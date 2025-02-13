// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/sch_aifo_stfq.c	AIFO queue with STFQ scheduling
 *
 *	Copyright 2022-2025 Hewlett Packard Enterprise Development LP.
 *	Author: Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 *
 * Some AIFO code from aifo_sfq :
 *	Author: Zhuolong Yu <yuzhuolong1993@gmail.com>
 *
 * ---------------------------------------------------------------- *
 *
 * Flow management (classification, gc...) based on sch_fq.c :
 *  Copyright (C) 2013-2015 Eric Dumazet <edumazet@google.com>
 *
 *  Flows are dynamically allocated and stored in a hash table of RB trees
 *
 *  enqueue() :
 *   - lookup one RB tree (out of 1024 or more) to find the flow.
 *     If non existent flow, create it, add it to the tree.
 *
 *  Note : When a flow becomes empty, we do not immediately remove it from
 *  rb trees, for performance reasons (its expected to send additional packets,
 *  or SLAB cache will reuse socket for another flow)
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/hash.h>
#include <linux/prefetch.h>
#include <linux/vmalloc.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/tcp.h>

//#define AIFO_DEBUG_CONFIG
//#define AIFO_DEBUG_FLOW_NEW
//#define AIFO_DEBUG_ADMIT
//#define AIFO_DEBUG_QUANTILE
//#define AIFO_DEBUG_STFQ_DEQUEUE
#define AIFO_DEBUG_QUANT_AVG
#define AIFO_DEBUG_STATS_PEAK

#define AIFO_PLIMIT_DEFLT		(10000)		/* packets */
#define AIFO_FLOW_PLIMIT_DEFLT		(100)		/* packets */
#define AIFO_HASH_NUM_DEFLT		(1024)		/* num tree roots */
#define AIFO_HASH_MASK_DEFLT		(1024 - 1)	/* bitmask */
#define AIFO_SAMPLE_SIZE_MAX		(1024)
#define AIFO_SAMPLE_SIZE_DEFLT		(20)		/* Save 20 ranks */
#define AIFO_SAMPLE_PERIOD_DEFLT	(15)		/* Every 15 packets */

enum {
	TCA_AIFO_UNSPEC,
	TCA_AIFO_PLIMIT,	/* limit of total number of packets in queue */
	TCA_AIFO_BURST,		/* AIFO headroom before dropping packets */
	TCA_AIFO_BUCKETS_LOG,	/* log2(number of buckets) */
	TCA_AIFO_HASH_MASK,	/* mask applied to skb hashes */
	TCA_AIFO_FLOW_PLIMIT,	/* limit of packets per flow */
	TCA_AIFO_SAMPLE_SIZE,
	TCA_AIFO_SAMPLE_PERIOD,
	TCA_AIFO_FLAGS,		/* Options */
	__TCA_AIFO_MAX
};
#define TCA_AIFO_MAX	(__TCA_AIFO_MAX - 1)

/* TCA_AIFO_FLAGS */
#define AIFF_PEAK_NORESET	0x0020	/* Don't reset peak statistics */
#define AIFF_QUANT_FIXED	0x0000	/* Quantile: fixed computations */
#define AIFF_QUANT_ADD1		0x0100	/* Quantile: add current packet */
#define AIFF_QUANT_ORIG		0x0200	/* Quantile: original computations */

#define AIFF_MASK_QUANT		(0x0F00)	/* Quantile mode */

/* statistics gathering */
struct tc_aifo_xstats {
	__u32	flows;		/* number of flows */
	__u64	flows_gc;	/* number of flows garbage collected */
	__u32	alloc_errors;	/* failed flow allocations */
	__u32	no_mark;	/* packet not dropped */
	__u32	drop_mark;	/* packet dropped */
	__u32	qlen_peak;	/* Maximum queue length */
	__u32	backlog_peak;	/* Maximum backlog */
	__u32	quant_avg_1k;	/* Average quantile * 1024 */
};

/*
 * Per flow structure, dynamically allocated.
 */
struct aifo_flow {
	unsigned long	age;	/* jiffies when flow was emptied, for gc */
	struct rb_node	hash_node;	/* anchor in hash_root[] trees */
	u64		virtual_finish;	/* Virtual of next incoming packet */
	u32		flow_idx;	/* Hash value for this flow */
} ____cacheline_aligned_in_smp;

static struct kmem_cache *aifo_flow_cachep __read_mostly;

/*
 * Private data for the Qdisc
 */
struct aifo_sched_data {
	/* Configuration */
	u32		hash_mask;	/* mask for orphaned skb */
	u8		hash_trees_log;	/* log(number buckets) */
	u32		flow_plimit;	/* max packets per flow */
	u32		burst;		/* headroom before dropping packets */
	u16		sample_size;
	u16		sample_period;
	u32		flags;		/* Bitmask of AIFF_XXX flags */

	/* Parameters */
	struct rb_root	*hash_root;		/* Hash of tree roots */
	u32		hash_buckets;
	u16		spl_tail;
	unsigned long	age_next_gc;
	u64		virtual_dequeue;	/* Virtual of last dequeue */
	u64	sample_ranks[AIFO_SAMPLE_SIZE_MAX];

	struct tc_aifo_xstats  stats;
};

/*
 * Packet Metadata
 */
struct aifo_skb_cb {
	u64	virtual_start;		/* Virtual start-time of packet */
};

static inline struct aifo_skb_cb *aifo_skb_cb(struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct aifo_skb_cb));
	return (struct aifo_skb_cb *)qdisc_skb_cb(skb)->data;
}

static inline struct aifo_flow *aifo_create_flow(struct aifo_sched_data *q,
						 uint32_t flow_idx)
{
	struct aifo_flow *flow_new;

	flow_new = kmem_cache_zalloc(aifo_flow_cachep, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(flow_new == NULL)) {
		q->stats.alloc_errors++;
		return NULL;
	}

	flow_new->flow_idx = flow_idx;

	/* Initialise virtual time of the flow. */
	flow_new->virtual_finish = q->virtual_dequeue;

	q->stats.flows++;

	return flow_new;
}

/* limit number of collected flows per round */
#define AIFO_GC_MAX 8
#define AIFO_GC_AGE (3*HZ)

static bool inline aifo_gc_candidate(const struct aifo_flow *f)
{
	return time_after(jiffies, f->age + AIFO_GC_AGE);
}

static void aifo_gc(struct aifo_sched_data *q,
		    struct rb_root *	root,
		    uint32_t		flow_idx)
{
	struct rb_node **p, *parent;
	void *tofree[AIFO_GC_MAX];
	struct aifo_flow *f;
	int i, fcnt = 0;

	p = &root->rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		f = rb_entry(parent, struct aifo_flow, hash_node);
		if (f->flow_idx == flow_idx)
			break;

		if (aifo_gc_candidate(f)) {
			tofree[fcnt++] = f;
			if (fcnt == AIFO_GC_MAX)
				break;
		}

		if (f->flow_idx > flow_idx)
			p = &parent->rb_right;
		else
			p = &parent->rb_left;
	}

	if (!fcnt)
		return;

	for (i = fcnt; i > 0; ) {
		f = tofree[--i];
		rb_erase(&f->hash_node, root);
	}
	q->stats.flows -= fcnt;
	q->stats.flows_gc += fcnt;
	q->age_next_gc = jiffies + AIFO_GC_AGE / 2;

	kmem_cache_free_bulk(aifo_flow_cachep, fcnt, tofree);
}

static struct aifo_flow *aifo_classify(struct sk_buff *skb,
				       struct Qdisc *sch)
{
	struct aifo_sched_data *q = qdisc_priv(sch);
	struct rb_node **	p;
	struct rb_node *	parent;
	uint32_t		flow_idx;
	struct rb_root *	root;
	struct aifo_flow *	flow_cur;

	/* Get hash value for the packet */
	flow_idx = (uint32_t) ( skb_get_hash(skb) & q->hash_mask );

	/* Get the root of the tree from the hash */
	root = &q->hash_root[ flow_idx & (q->hash_buckets - 1) ];

	/* I personally feel that the garbage collection policy is
	 * not aggressive enough. Also, garbage collection only scan
	 * a subset of the trees, so I think there might be flows never
	 * garbage collected. Unfortunately, I don't have time and
	 * inclination to play with it. Jean II */
	if ( (q->stats.flows >= (q->hash_buckets * 2))
	     && ( ( time_after(jiffies, q->age_next_gc) )
		  || (sch->q.qlen == 0) ) )
		aifo_gc(q, root, flow_idx);

	/* Find flow in that specific tree */
	p = &root->rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		flow_cur = rb_entry(parent, struct aifo_flow, hash_node);
		if (flow_cur->flow_idx == flow_idx) {
			/* Found ! */
			return flow_cur;
		}
		if (flow_cur->flow_idx > flow_idx)
			p = &parent->rb_right;
		else
			p = &parent->rb_left;
	}

	/* Create a new flow */
	flow_cur = aifo_create_flow(q, flow_idx);
	if (unlikely(flow_cur == NULL)) {
		return NULL;
	}

	/* Insert new flow into classifer */
	rb_link_node(&flow_cur->hash_node, parent, p);
	rb_insert_color(&flow_cur->hash_node, root);

#ifdef AIFO_DEBUG_FLOW_NEW
	{
		struct iphdr *ih;
		__be16 src_port;
		__be16 dest_port; 

		if (skb->protocol == htons(ETH_P_IP)) {
			ih = ip_hdr(skb);
			switch (ih->protocol) {
			case IPPROTO_TCP: {
				struct tcphdr *th = tcp_hdr(skb);
				src_port = th->source;
				dest_port = th->dest;
				break;
			}
			case IPPROTO_UDP: {
				struct udphdr *uh = udp_hdr(skb);
				src_port = uh->source;
				dest_port = uh->dest;
				break;
			}
			default:
				src_port = 0;
				dest_port = 0;
			}
			printk(KERN_DEBUG "AIFO: flow new: idx:%d, src_addr:%d, dst_addr:%d, src_port:%d, dst_port:%d\n", flow_idx, ntohl(ih->saddr), ntohl(ih->daddr), ntohs(src_port), ntohs(dest_port));
		} else {
			printk(KERN_DEBUG "AIFO: flow new: idx:%d\n", flow_idx);
		}
	}
#endif	/* AIFO_DEBUG_FLOW_NEW */

	return flow_cur;
}

static inline bool aifo_admit_packet(struct Qdisc *sch, struct sk_buff *skb)
{
	struct aifo_sched_data *q = qdisc_priv(sch);
	struct aifo_flow *flow_cur;
	u64	virtual_pkt;
	long	sample_num;
	long	flow_limit;
	long	lower_spl_num = 0;
	int	spl_idx;
	int	i;
	bool	drop;

	/* Get flow for this packet */
	flow_cur = aifo_classify(skb, sch);
	if (flow_cur == NULL)
		return true;
	/* Flow is in use - garbage collection */
	flow_cur->age = jiffies;

	/* STFQ : Get virtual time of the flow == start-time on this packet.
	 * Get the later of the finish-time of previous packet (flow was
	 * busy) and the current virtual time (flow was idle). Jean II */
	if ( time_after64(q->virtual_dequeue, flow_cur->virtual_finish) )
		virtual_pkt = q->virtual_dequeue;
	else
		virtual_pkt = flow_cur->virtual_finish;

	/* Quantile computation. Black magic. Jean II */
	switch (q->flags & AIFF_MASK_QUANT) {

	case AIFF_QUANT_ORIG:
		/* Quantile: original version */
		sample_num = (sch->q.qlen * q->sample_size) / sch->limit;
		if (sample_num > sch->q.qlen)
			sample_num = sch->q.qlen;
		lower_spl_num = 0;
		for (i = 0; i < sample_num; i++) {
			spl_idx = ( (q->spl_tail + q->sample_size - i)
				     % q->sample_size );
			if ( time_after64(virtual_pkt,
					  q->sample_ranks[spl_idx]) )
				lower_spl_num++;
		}
		break;

	default:
	case AIFF_QUANT_FIXED:
	case AIFF_QUANT_ADD1:
		/* We want to compare to packets that are currently in the
		 * queue, not past packets. Figure out how many samples are
		 * in the queue based on sampling rate. Jean II */
		sample_num = (sch->q.qlen / q->sample_period);
		/* If the number of flows is small, we don't need to check
		 * the whole set of samples to get an idea... Don't decrease
		 * too much because of bursts. Jean II */
		flow_limit = (q->sample_size + q->stats.flows) / 2;
		if (sample_num > flow_limit)
			sample_num = flow_limit;
		if (sample_num > q->sample_size)
			sample_num = q->sample_size;

		/* Compute quantile of this rank.
		 * We compute the percent of packets with lower rank in
		 * the sliding window of samples. */
		lower_spl_num = 0;
		for (i = 0; i < sample_num; i++) {
			/* '%' is remainder, not modulo. Jean II */
			spl_idx = ( (q->spl_tail + q->sample_size - i)
				     % q->sample_size );
			if ( time_after64(virtual_pkt,
					  q->sample_ranks[spl_idx]) )
				lower_spl_num++;
#ifdef AIFO_DEBUG_QUANTILE
			printk(KERN_DEBUG "AIFO: quantile: i:%d; vi:%lld; vp:%lld; lw:%ld\n", spl_idx, q->sample_ranks[spl_idx], virtual_pkt, lower_spl_num);
#endif	/* AIFO_DEBUG_QUANTILE */
		}

		/* Quantile: fudges original to get queue to grow... */
		if ( (q->flags & AIFF_MASK_QUANT) == AIFF_QUANT_ADD1) {
			/* Add the new packet to the population,
			 * i.e. do quantile with this packet included.
			 * This avoid degenerate cases with single flow
			 * or perfectly scheduled flows where it reaches 100%.
			 * Jean II */
			sample_num++;
		}
		break;
	}

#ifdef AIFO_DEBUG_QUANT_AVG
	if (sample_num > 1) {
	    if (q->stats.quant_avg_1k == 0)
	        q->stats.quant_avg_1k = ( lower_spl_num * 1024
					  / sample_num );
	    else
		q->stats.quant_avg_1k = ( ( q->stats.quant_avg_1k * 15
					    + ( lower_spl_num * 1024
						/ sample_num ) )
					  / 16 );
		}
#endif	/* AIFO_DEBUG_QUANT_AVG */

	/* Admission. More black magic. Jean II */
	/* Check if we need to admit or drop this packet
	 *
	 * Differences with AIFO paper :
	 * Queue.size is mapped to sch->limit
	 * Headroom is mapped to burst and is in packets
	 * k = burst / limit
	 *
	 * Optimisation of the test in paper...
	 * quantile = lower_spl_num / sample_num
	 * threshold = ( 1 / (1 - q->burst/sch->limit)
	 *		 * (sch->limit - sch->q.qlen) / sch->limit
	 * drop = quantile > threshold
	 * drop = ( lower_spl_num * (1 - q->burst/sch->limit)
	 *		* sch->limit
	 *	    > (sch->limit - sch->q.qlen) * sample_num )
	 * drop = ( lower_spl_num * (sch->limit - q->burst)
	 *	    > (sch->limit - sch->q.qlen) * sample_num )
	 *
	 * Computation range
	 * sample_num is lower than AIFO_SAMPLE_SIZE_MAX = 1024
	 * numbers can be negative - using signed long
	 *
	 * As noted in paper, we don't need to test explicitely
	 * for burst.
	 * lower_spl_num < sample_num, so if sch->q.qlen < q->burst
	 * the test is always false...
	 * Jean II */
	drop = ( lower_spl_num * (sch->limit - q->burst)
		 > (sch->limit - sch->q.qlen) * sample_num );

#ifdef AIFO_DEBUG_ADMIT
	printk(KERN_DEBUG "AIFO: admit: idx:%d; sn:%ld; lw:%ld; li:%d; ql:%d; vp:%lld; vdq:%lld; vf:%lld; d:%d\n", flow_cur->flow_idx, sample_num, lower_spl_num, sch->limit, sch->q.qlen, virtual_pkt, q->virtual_dequeue, virtual_pkt + qdisc_pkt_len(skb), drop);
#endif	/* AIFO_DEBUG_ADMIT */

	if (drop)
		return false;
	else {
		/* Check if we need to sample packet
		 * sample period = 1 / sample rate in AIFO paper. */
		if (prandom_u32_max(q->sample_period) == 0) {
			/* We are going to sample this packet */
			q->spl_tail += 1;
			q->spl_tail = q->spl_tail % q->sample_size;
			q->sample_ranks[q->spl_tail] = virtual_pkt; 
		}

		/* Save virtual time in packet to be used in dequeue */
		aifo_skb_cb(skb)->virtual_start = virtual_pkt;

		/* Update flow virtual time.
		 * STFQ : All flows have the same weight. Jean II */
		flow_cur->virtual_finish = virtual_pkt + qdisc_pkt_len(skb);

		return true;
	}
}

/* QDisc add a new packet to our queue - tail of queue. */
static int aifo_qdisc_enqueue(struct sk_buff *	skb,
			      struct Qdisc *	sch,
			      struct sk_buff **	to_free)
{
	struct aifo_sched_data *q = qdisc_priv(sch);
	bool enqueue;

	/* Tail-drop when queue is full - pfifo style limit */
	if (unlikely(sch->q.qlen >= sch->limit)) {
		qdisc_qstats_overlimit(sch);
		return qdisc_drop(skb, sch, to_free);
	}

#ifdef AIFO_DEBUG_STATS_PEAK
	{
		unsigned int backlog_new;

		/* Keep track of peak statistics */
		if (sch->q.qlen >= q->stats.qlen_peak)
			q->stats.qlen_peak = sch->q.qlen + 1;

		backlog_new = sch->qstats.backlog + qdisc_pkt_len(skb);
		if ( (backlog_new > q->stats.backlog_peak)
		     && (backlog_new < 2147483648) )
			q->stats.backlog_peak = backlog_new;
	}
#endif	/* AIFO_DEBUG_STATS_PEAK */

	/* Check if we need to queue this packet */
	enqueue = aifo_admit_packet(sch, skb);
	if (enqueue) {
		/* Enqueue packet */
		q->stats.no_mark++;
		return qdisc_enqueue_tail(skb, sch);
	} else {
		/* Drop packet */
		q->stats.drop_mark++;
		return qdisc_drop(skb, sch, to_free);
	}
}

/* QDisc remove a packet from our queue - head of queue. */
static struct sk_buff *aifo_qdisc_dequeue(struct Qdisc *sch)
{
	struct aifo_sched_data *q = qdisc_priv(sch);
	struct sk_buff *	skb;
	u64			virtual_pkt;

	skb = qdisc_dequeue_head(sch);
	if (!skb)
		return NULL;

	if ( (q->flags & AIFF_MASK_QUANT) == AIFF_QUANT_ORIG ) {
		/* Update the virtual time of STFQ */
		q->virtual_dequeue = q->virtual_dequeue + qdisc_pkt_len(skb);
	} else {
		/* Get virtual tag of this packet. */
		virtual_pkt = aifo_skb_cb(skb)->virtual_start;

#ifdef AIFO_DEBUG_STFQ_DEQUEUE
		printk(KERN_DEBUG "AIFO: vpkt:%lld; vdq:%lld; ql:%d\n", virtual_pkt, q->virtual_dequeue, sch->q.qlen);
#endif	/* AIFO_DEBUG_STFQ_DEQUEUE */

		/* Update virtual time - Check if queue is busy */
		if (sch->q.qlen == 0) {
			q->virtual_dequeue = virtual_pkt + qdisc_pkt_len(skb);
		} else {
			/* In AIFO, packets are dequeued out of order,
			 * so the virtual time of STFQ can not be tracked
			 * easily. We would need to find the smallest
			 * rank amongst all packets in the queue.
			 * Approximate by taking the time of this packet.
			 * But, prevent time going backwards. Jean II */
			if ( time_after64(virtual_pkt, q->virtual_dequeue) )
				q->virtual_dequeue = virtual_pkt;
		}
	}

	return skb;
}

static void aifo_rehash(struct aifo_sched_data *q,
		      struct rb_root *old_array, u32 old_log,
		      struct rb_root *new_array, u32 new_log)
{
	struct rb_node *op, **np, *parent;
	struct rb_root *oroot, *nroot;
	struct aifo_flow *of, *nf;
	int fcnt = 0;
	u32 idx;

	for (idx = 0; idx < (1U << old_log); idx++) {
		oroot = &old_array[idx];
		while ((op = rb_first(oroot)) != NULL) {
			rb_erase(op, oroot);
			of = rb_entry(op, struct aifo_flow, hash_node);
			if (aifo_gc_candidate(of)) {
				fcnt++;
				kmem_cache_free(aifo_flow_cachep, of);
				continue;
			}
			nroot = &new_array[hash_32(of->flow_idx, new_log)];

			np = &nroot->rb_node;
			parent = NULL;
			while (*np) {
				parent = *np;

				nf = rb_entry(parent, struct aifo_flow, hash_node);
				BUG_ON(nf->flow_idx == of->flow_idx);

				if (nf->flow_idx > of->flow_idx)
					np = &parent->rb_right;
				else
					np = &parent->rb_left;
			}

			rb_link_node(&of->hash_node, parent, np);
			rb_insert_color(&of->hash_node, nroot);
		}
	}
	q->stats.flows -= fcnt;
	q->stats.flows_gc += fcnt;
}

static void aifo_hash_free(void *addr)
{
	kvfree(addr);
}

static int aifo_hash_resize(struct Qdisc *sch, u32 log)
{
	struct aifo_sched_data *q = qdisc_priv(sch);
	struct rb_root *array;
	void *old_hash_root;
	u32 buckets;
	u32 idx;

	if (q->hash_root && log == q->hash_trees_log)
		return 0;

	buckets = 1U << log;

	/* If XPS was setup, we can allocate memory on right NUMA node */
	array = kvmalloc_node(sizeof(struct rb_root) << log, GFP_KERNEL | __GFP_RETRY_MAYFAIL,
			      netdev_queue_numa_node_read(sch->dev_queue));
	if (!array)
		return -ENOMEM;

	for (idx = 0; idx < buckets; idx++)
		array[idx] = RB_ROOT;

	sch_tree_lock(sch);

	old_hash_root = q->hash_root;
	if (old_hash_root)
		aifo_rehash(q, old_hash_root, q->hash_trees_log, array, log);

	q->hash_root = array;
	q->hash_trees_log = log;
	q->hash_buckets = buckets;

	sch_tree_unlock(sch);

	aifo_hash_free(old_hash_root);

	return 0;
}

static const struct nla_policy aifo_policy[TCA_AIFO_MAX + 1] = {
	[TCA_AIFO_PLIMIT]		= { .type = NLA_U32 },
	[TCA_AIFO_BURST]		= { .type = NLA_U32 },
	[TCA_AIFO_BUCKETS_LOG]		= { .type = NLA_U32 },
	[TCA_AIFO_HASH_MASK]		= { .type = NLA_U32 },
	[TCA_AIFO_FLOW_PLIMIT]		= { .type = NLA_U32 },
	[TCA_AIFO_SAMPLE_SIZE]		= { .type = NLA_U16 },
	[TCA_AIFO_SAMPLE_PERIOD]	= { .type = NLA_U16 },
	[TCA_AIFO_FLAGS]		= { .type = NLA_U32 },
};

static int aifo_qdisc_change(struct Qdisc *sch,
			     struct nlattr *opt,
			     struct netlink_ext_ack *extack)
{
	struct aifo_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_AIFO_MAX + 1];
	u32		plimit;
	u32		hash_log_new;
	int		err;
	int		drop_count = 0;
	unsigned	drop_len = 0;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_AIFO_MAX, opt, aifo_policy,
					  NULL);
	if (err < 0)
		return err;

	/* Check limit & target before locking */
	if (tb[TCA_AIFO_PLIMIT]) {
		plimit = nla_get_u32(tb[TCA_AIFO_PLIMIT]);
		/* Can't be negative... */
		if (plimit == 0)
			return -EINVAL;
	}

	sch_tree_lock(sch);

	if (tb[TCA_AIFO_PLIMIT])
		sch->limit = plimit;
	if (tb[TCA_AIFO_BURST]) {
		q->burst = nla_get_u32(tb[TCA_AIFO_BURST]);
	}

	hash_log_new = q->hash_trees_log;
	if (tb[TCA_AIFO_BUCKETS_LOG]) {
		u32 nval = nla_get_u32(tb[TCA_AIFO_BUCKETS_LOG]);

		if (nval >= 1 && nval <= ilog2(256*1024))
			hash_log_new = nval;
		else
			err = -EINVAL;
	}

	if (tb[TCA_AIFO_HASH_MASK])
		q->hash_mask = nla_get_u32(tb[TCA_AIFO_HASH_MASK]);

	if (tb[TCA_AIFO_FLOW_PLIMIT])
		q->flow_plimit = nla_get_u32(tb[TCA_AIFO_FLOW_PLIMIT]);

	if (tb[TCA_AIFO_SAMPLE_SIZE]) {
		u16 sample_size = nla_get_u16(tb[TCA_AIFO_SAMPLE_SIZE]);
		if (sample_size > AIFO_SAMPLE_SIZE_MAX)
			sample_size = AIFO_SAMPLE_SIZE_MAX;
		q->sample_size = sample_size;
	}
	if (tb[TCA_AIFO_SAMPLE_PERIOD]) {
		q->sample_period = nla_get_u16(tb[TCA_AIFO_SAMPLE_PERIOD]);
	}
	if (tb[TCA_AIFO_FLAGS])
                q->flags = nla_get_u32(tb[TCA_AIFO_FLAGS]);

	if (!err) {

		sch_tree_unlock(sch);
		/* Only done if hash_log_new != q->hash_trees_log */
		err = aifo_hash_resize(sch, hash_log_new);
		sch_tree_lock(sch);
	}
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = __qdisc_dequeue_head(&sch->q);

		if (!skb)
			break;
		drop_len += qdisc_pkt_len(skb);
		qdisc_qstats_backlog_dec(sch, skb);
		rtnl_kfree_skbs(skb, skb);
		drop_count++;
	}
	qdisc_tree_reduce_backlog(sch, drop_count, drop_len);

	sch_tree_unlock(sch);

#ifdef AIFO_DEBUG_CONFIG
	printk(KERN_DEBUG "AIFO: plimit %d; burst %u; logs %d; mask 0x%X; flow_plimit %d; sample_size %d; sample_period %d; flags 0x%X\n", sch->limit, q->burst, q->hash_trees_log, q->hash_mask, q->flow_plimit, q->sample_size, q->sample_period, q->flags);
#endif	/* AIFO_DEBUG_CONFIG */

	return err;
}

static int aifo_qdisc_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct aifo_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	/* Standard queue limit */
	if (nla_put_u32(skb, TCA_AIFO_PLIMIT, sch->limit))
		goto nla_put_failure;
	if (nla_put_u32(skb, TCA_AIFO_BURST, q->burst))
		goto nla_put_failure;

	/* Hashing attributes */
	if (nla_put_u32(skb, TCA_AIFO_BUCKETS_LOG, q->hash_trees_log))
		goto nla_put_failure;
	if (nla_put_u32(skb, TCA_AIFO_HASH_MASK, q->hash_mask))
		goto nla_put_failure;

	/* Other attributes */
	if (nla_put_u32(skb, TCA_AIFO_FLOW_PLIMIT, q->flow_plimit))
		goto nla_put_failure;
	if (nla_put_u16(skb, TCA_AIFO_SAMPLE_SIZE, q->sample_size))
		goto nla_put_failure;
	if (nla_put_u16(skb, TCA_AIFO_SAMPLE_PERIOD, q->sample_period))
		goto nla_put_failure;
	if (nla_put_u32(skb, TCA_AIFO_FLAGS, q->flags))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int aifo_qdisc_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct aifo_sched_data *q = qdisc_priv(sch);
	struct tc_aifo_xstats st;

	sch_tree_lock(sch);

	st.flows		= q->stats.flows;
	st.flows_gc		= q->stats.flows_gc;
	st.alloc_errors		= q->stats.alloc_errors;
	st.no_mark		= q->stats.no_mark;
	st.drop_mark		= q->stats.drop_mark;
	st.qlen_peak		= q->stats.qlen_peak;
	st.backlog_peak		= q->stats.backlog_peak;
	st.quant_avg_1k		= q->stats.quant_avg_1k;

	/* Reset some of the statistics, unless disabled */
	if ( ! (q->flags & AIFF_PEAK_NORESET) ) {
		q->stats.qlen_peak = 0;
		q->stats.backlog_peak = 0;
	}

	sch_tree_unlock(sch);

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static int aifo_qdisc_init(struct Qdisc *sch,
			   struct nlattr *opt,
			   struct netlink_ext_ack *extack)
{
	struct aifo_sched_data *q = qdisc_priv(sch);
	int i;
	int err;

#ifdef AIFO_DEBUG_CONFIG
	printk(KERN_DEBUG "AIFO: sizeof(aifo_flow) %lu\n", sizeof(struct aifo_flow));
#endif	/* AIFO_DEBUG_CONFIG */

	/* Configuration */
	sch->limit		= AIFO_PLIMIT_DEFLT;
	q->burst		= 1;			/* 1 packet */
	q->flow_plimit		= AIFO_FLOW_PLIMIT_DEFLT;
	q->hash_mask		= AIFO_HASH_MASK_DEFLT;
	q->sample_size		= AIFO_SAMPLE_SIZE_DEFLT;
	q->sample_period	= AIFO_SAMPLE_PERIOD_DEFLT;

	/* Parameters */
	q->hash_root		= NULL;
	q->hash_trees_log	= ilog2(AIFO_HASH_NUM_DEFLT);
	q->age_next_gc		= jiffies + AIFO_GC_AGE / 2;
	q->virtual_dequeue	= 0LL;
	q->stats.flows_gc	= 0;
	q->stats.alloc_errors	= 0;

	if (opt)
		err = aifo_qdisc_change(sch, opt, extack);
	else
		err = aifo_hash_resize(sch, q->hash_trees_log);

	for (i = 0; i < AIFO_SAMPLE_SIZE_MAX; i++)
		q->sample_ranks[i] = (u64)1 << 32;
	q->spl_tail		= 0;

	return err;
}

static void aifo_qdisc_reset(struct Qdisc *sch)
{
	struct aifo_sched_data *q = qdisc_priv(sch);
	struct rb_root *root;
	struct rb_node *p;
	struct aifo_flow *flow_cur;
	unsigned int idx;

	sch->q.qlen = 0;
	sch->qstats.backlog = 0;

	if (!q->hash_root)
		return;

	for (idx = 0; idx < (1U << q->hash_trees_log); idx++) {
		root = &q->hash_root[idx];
		while ((p = rb_first(root)) != NULL) {
			flow_cur = rb_entry(p, struct aifo_flow, hash_node);
			rb_erase(p, root);

			kmem_cache_free(aifo_flow_cachep, flow_cur);
		}
	}

	q->stats.flows		= 0;
	q->stats.no_mark	= 0;
	q->stats.drop_mark	= 0;
	q->stats.qlen_peak	= 0;
	q->stats.backlog_peak	= 0;
	q->stats.quant_avg_1k	= 0;
}

static void aifo_qdisc_destroy(struct Qdisc *sch)
{
	struct aifo_sched_data *q = qdisc_priv(sch);

	aifo_qdisc_reset(sch);
	aifo_hash_free(q->hash_root);
}

static struct Qdisc_ops aifo_qdisc_ops __read_mostly = {
	.id		=	"aifo_stfq",
	.priv_size	=	sizeof(struct aifo_sched_data),

	.enqueue	=	aifo_qdisc_enqueue,
	.dequeue	=	aifo_qdisc_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	aifo_qdisc_init,
	.reset		=	aifo_qdisc_reset,
	.destroy	=	aifo_qdisc_destroy,
	.change		=	aifo_qdisc_change,
	.dump		=	aifo_qdisc_dump,
	.dump_stats	=	aifo_qdisc_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init aifo_stfq_module_init(void)
{
	int ret;

	aifo_flow_cachep = kmem_cache_create("aifo_stfq_flow_cache",
					   sizeof(struct aifo_flow),
					   0, 0, NULL);
	if (!aifo_flow_cachep)
		return -ENOMEM;

	ret = register_qdisc(&aifo_qdisc_ops);
	if (ret)
		kmem_cache_destroy(aifo_flow_cachep);
	return ret;
}

static void __exit aifo_stfq_module_exit(void)
{
	unregister_qdisc(&aifo_qdisc_ops);
	kmem_cache_destroy(aifo_flow_cachep);
}

module_init(aifo_stfq_module_init)
module_exit(aifo_stfq_module_exit)
MODULE_AUTHOR("Jean Tourrilhes");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AIFO queue with STFQ Scheduler");
