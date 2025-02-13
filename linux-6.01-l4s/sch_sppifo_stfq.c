// SPDX-License-Identifier: GPL-2.0-only
/*
 * net/sched/sch_sppifo_stfq.c SP-PIFO Scheduler with Start Time Fair Queueing Prioritization
 *
 *	Copyright 2023-2025 Hewlett Packard Enterprise Development LP.
 *	Author: Erfan Sharafzadeh <e.sharafzadeh@jhu.edu>
 *	Author: Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 *
 * SP_PIFO is an approximation of PIFO packet scheduling for strict priority FIFO queues.
 * SP_PIFO decides to find the best priority level based on packet's virtual time by keeping
 * track of threshold values for each priority level.
 * If the packet was enqueued in a wong priority queue, the scheduler will update all the thresholds
 * to account for that mistake. 
 *
 * ---------------------------------------------------------------- *
 *
 * Flow management (classification, lists, gc...) based on sch_fq.c :
 *  Copyright (C) 2013-2015 Eric Dumazet <edumazet@google.com>
 *
 *  Flows are dynamically allocated and stored in a hash table of RB trees
 *
 *  enqueue() :
 *   - Calculate packets virtual time. Find the best priority level for the packet based on 
 * 		its (STFQ) virtual time. Insert packet	into that queue.
 *
 *  dequeue() : serves FIFO's in strict priority preference. Updates the global virtual time.
 * 		Higher indexed bands have higher priority.
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
#include <linux/skb_array.h>

// #define SPPIFO_DEBUG_CONFIG
// #define SPPIFO_DEBUG_FLOW_NEW
// #define SPPIFO_DEBUG_SPPIFO_ENQUEUE
// #define SPPIFO_DEBUG_SPPIFO_DEQUEUE
//#define SPPIFO_DEBUG_STATS_PEAK

#define SPPIFO_PLIMIT_DEFLT		(10000)		/* packets */
#define SPPIFO_BAND_PLIMIT_DEFLT	(1250)		/* packets */
#define SPPIFO_HASH_NUM_DEFLT		(1024)		/* num tree roots */
#define SPPIFO_HASH_MASK_DEFLT		(1024 - 1)	/* bitmask */

enum {
	TCA_SPPIFO_UNSPEC,
	TCA_SPPIFO_PLIMIT,	/* limit of total number of packets in queue */
	TCA_SPPIFO_BUCKETS_LOG,	/* log2(number of buckets) */
	TCA_SPPIFO_HASH_MASK,	/* mask applied to skb hashes */
	TCA_SPPIFO_BAND_PLIMIT,	/* limit of packets per band */
	TCA_SPPIFO_FLAGS,		/* Options */
	__TCA_SPPIFO_MAX
};
#define TCA_SPPIFO_MAX	(__TCA_SPPIFO_MAX - 1)

/* TCA_SPPIFO_FLAGS */
#define SCF_PEAK_NORESET	0x0020	/* Don't reset peak statistics */
#define SPPIFO_BANDS	8		/* Number of FIFO queues */

/* statistics gathering */
struct tc_sppifo_xstats {
	__u32	flows;		/* number of flows */
	__u64	flows_gc;	/* number of flows garbage collected */
	__u32	alloc_errors;	/* failed flow allocations */
	__u32	no_mark;	/* packet not dropped */
	__u32	drop_mark;	/* packet dropped */
	__u32	qlen_peak;	/* Maximum queue length */
	__u32	backlog_peak;	/* Maximum backlog */
	__u32	burst_peak;	/* Maximum burst size */
	__u32	burst_avg;	/* Average burst size */
	__u32	num_inversions;	/* Number of inversions on enqueue */
	__u32	num_reordering;	/* Number of re-ordering on dequeue */
	__u32	band_tx[SPPIFO_BANDS];	/* Number of SKBs sent from each band */
	__u32	band_qlen[SPPIFO_BANDS];	/* Number of SKBs queued in each band */
};

/*
 * Per flow structure, dynamically allocated.
 */
struct sppifo_flow {
	struct sk_buff	*head;		/* list of skbs for this flow : first skb */
	unsigned long  age;	/* (jiffies | 1UL) when flow was emptied, for gc */
	struct rb_node	hash_node;	/* anchor in hash_root[] trees */
	u64		virtual_tail;	/* Virtual of next incoming packet */
	u64		virtual_head;	/* Current virtual time */
	u32		flow_idx;	/* Hash value for this flow */
	int		pcount;		/* number of packets in fifos */

} ____cacheline_aligned_in_smp;

static struct kmem_cache *sppifo_flow_cachep __read_mostly;

/*
 * Private data for the Qdisc
 */
struct sppifo_sched_data {
	/* Configuration */
	u32		hash_mask;	/* mask for orphaned skb */
	u8		hash_trees_log;	/* log(number buckets) */
	u32		flags;		/* Bitmask of AIFF_XXX flags */
	u32 	band_plimit;	/* Limit on number of packets in each band */

	/* Classifier */
	struct rb_root	*hash_root;	/* Hash of tree roots */
	u32		hash_buckets;
	unsigned long	age_next_gc;


	/* Stats and instrumentation */
	struct tc_sppifo_xstats  stats;

	/* Scheduler */
	u64		sppifo_qbound[SPPIFO_BANDS];			/* SP-PIFO Queue bound */
	struct	skb_array	fifo[SPPIFO_BANDS];		/* FIFO queues holding packets */
	u64		virtual_dequeue;  /* Virtual of last dequeue */
};

/*
 * Packet Metadata
 */
struct sppifo_skb_cb {
	u64	virtual_start;		/* Virtual start-time of packet */
};

static inline struct sppifo_skb_cb *sppifo_skb_cb(struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct sppifo_skb_cb));
	return (struct sppifo_skb_cb *)qdisc_skb_cb(skb)->data;
}

static inline struct sppifo_flow *sppifo_create_flow(struct sppifo_sched_data *q,
						 uint32_t flow_idx)
{
	struct sppifo_flow *flow_new;

	flow_new = kmem_cache_zalloc(sppifo_flow_cachep, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(flow_new == NULL)) {
		q->stats.alloc_errors++;
		return NULL;
	}

	flow_new->flow_idx = flow_idx;

	/* Initialize virtual time of the flow. */
	flow_new->virtual_tail = q->virtual_dequeue;

	q->stats.flows++;

	return flow_new;
}

static inline void sppifo_flow_purge(struct sppifo_flow *flow,
				   struct sppifo_sched_data *q)
{
	flow->pcount = 0;
}

/* limit number of collected flows per round */
#define SPPIFO_GC_MAX 8
#define SPPIFO_GC_AGE (3*HZ)

static bool sppifo_gc_candidate(const struct sppifo_flow *f)
{
	return time_after(jiffies, f->age + SPPIFO_GC_AGE);
}

static void sppifo_gc(struct sppifo_sched_data *q,
		    struct rb_root *	root,
		    uint32_t		flow_idx)
{
	struct rb_node **p, *parent;
	void *tofree[SPPIFO_GC_MAX];
	struct sppifo_flow *f;
	int i, fcnt = 0;

	p = &root->rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		f = rb_entry(parent, struct sppifo_flow, hash_node);
		if (f->flow_idx == flow_idx)
			break;

		if (sppifo_gc_candidate(f)) {
			tofree[fcnt++] = f;
			if (fcnt == SPPIFO_GC_MAX)
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

	q->age_next_gc = jiffies + SPPIFO_GC_AGE / 2;
	kmem_cache_free_bulk(sppifo_flow_cachep, fcnt, tofree);
}

static struct sppifo_flow *sppifo_classify(struct sk_buff *skb,
				       struct Qdisc *sch)
{
	struct rb_node **	p;
	struct rb_node *	parent;
	uint32_t		flow_idx;
	struct rb_root *	root;
	struct sppifo_flow *	flow_cur;
	struct sppifo_sched_data *q = qdisc_priv(sch);

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
		sppifo_gc(q, root, flow_idx);

	/* Find flow in that specific tree */
	p = &root->rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		flow_cur = rb_entry(parent, struct sppifo_flow, hash_node);
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
	flow_cur = sppifo_create_flow(q, flow_idx);
	if (unlikely(flow_cur == NULL)) {
		return NULL;
	}

	/* Insert new flow into classifer */
	rb_link_node(&flow_cur->hash_node, parent, p);
	rb_insert_color(&flow_cur->hash_node, root);

#ifdef SPPIFO_DEBUG_FLOW_NEW
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
			printk(KERN_DEBUG "SP-PIFO: flow new: idx:%d, src_addr:%d, dst_addr:%d, src_port:%d, dst_port:%d\n", flow_idx, ntohl(ih->saddr), ntohl(ih->daddr), ntohs(src_port), ntohs(dest_port));
		} else {
			printk(KERN_DEBUG "SP-PIFO: flow new: idx:%d\n", flow_idx);
		}
	}
#endif	/* SPPIFO_DEBUG_FLOW_NEW */

	return flow_cur;
}


static inline u32 sppifo_select_band(struct sppifo_sched_data *q, struct sppifo_flow  *flow_cur, u64 virtual_pkt)
{
	int i;
	u64 cost;

	for(i = 0; i < SPPIFO_BANDS - 1; i++)
	{
		if(time_after_eq64(virtual_pkt, q->sppifo_qbound[i]))
			return i;
	}
	if(time_before64(virtual_pkt, q->sppifo_qbound[i]))
	{
		// inversion detected
		cost = q->sppifo_qbound[i] - virtual_pkt;
		for(i = 0; i < SPPIFO_BANDS - 1; i++)
			q->sppifo_qbound[i] -= cost;
		q->stats.num_inversions++;
	}
	// i is always the highest priority queue at this point
	return i;
}


static inline struct skb_array *sppifo_band2list(struct sppifo_sched_data *priv,
					     s32 band)
{
	return &priv->fifo[band];
}


/* QDisc add a new packet to our queue - tail of queue. */
static int sppifo_qdisc_enqueue(struct sk_buff *	skb,
			      struct Qdisc *	sch,
			      struct sk_buff **	to_free)
{
	struct sppifo_sched_data *q = qdisc_priv(sch);
	struct sppifo_flow *	flow_cur;
	struct skb_array *list;
	u64		virtual_pkt;
	u32		selected_band;
	int err;

	/* Tail-drop when queue is full - pfifo style limit */
	if (unlikely(sch->q.qlen >= sch->limit)) {
		qdisc_qstats_overlimit(sch);
		return qdisc_drop(skb, sch, to_free);
	}

	/* Find or create flow for this packet. */
	flow_cur = sppifo_classify(skb, sch);
	if (unlikely(flow_cur == NULL)) {
		/* Alt : enqueue packet on random flow, Jean II */
		return qdisc_drop(skb, sch, to_free);
	}



	/* STFQ : compute virtual time of packet. */
	if ( time_after64(q->virtual_dequeue, flow_cur->virtual_tail) )
		virtual_pkt = q->virtual_dequeue;
	else
		virtual_pkt = flow_cur->virtual_tail;

	/* Save virtual time in packet to be used in dequeue */
	sppifo_skb_cb(skb)->virtual_start = virtual_pkt;

	/* Update flow virtual time.
	 * STFQ : All flows have the same weight. Jean II */
	flow_cur->virtual_tail = virtual_pkt + qdisc_pkt_len(skb);

	selected_band = sppifo_select_band(q, flow_cur, virtual_pkt);

	if(unlikely(q->stats.band_qlen[selected_band] >= q->band_plimit))
	{
		q->stats.drop_mark++;
		return qdisc_drop(skb, sch, to_free);
	}
	q->sppifo_qbound[selected_band] = virtual_pkt;

	list = sppifo_band2list(q, selected_band);
	err = skb_array_produce(list, skb);

	if (unlikely(err)) {
		return qdisc_drop(skb, sch, to_free);
	}

	/* bstats->packets keep track of the number of actual Ethernet
	 * packets. Unfortunately, all other stats are in number of
	 * sbks. The packet count and skb count are different due
	 * to GSO. This counter allow to count skbs and therefore
	 * have something consistent with the other stats. Jean II */
	q->stats.no_mark++;
	
	q->stats.band_qlen[selected_band]++;
	sch->q.qlen++;
	flow_cur->age = jiffies;
	qdisc_qstats_backlog_inc(sch, skb);


#ifdef SPPIFO_DEBUG_SPPIFO_ENQUEUE
	printk(KERN_DEBUG "SP-PIFO: enqueue: idx:%d; vdq:%lld; vpkt:%lld; vtail:%lld; band:%u\n", flow_cur->flow_idx, q->virtual_dequeue, virtual_pkt, flow_cur->virtual_tail, selected_band);
#endif	/* SPPIFO_DEBUG_SPPIFO_ENQUEUE */

#ifdef SPPIFO_DEBUG_STATS_PEAK
	/* Keep track of peak statistics */
	if (sch->q.qlen >= q->stats.qlen_peak)
		q->stats.qlen_peak = sch->q.qlen;

	if ( (sch->qstats.backlog > q->stats.backlog_peak)
	     && (sch->qstats.backlog < 2147483648) )
		q->stats.backlog_peak = sch->qstats.backlog;
#endif	/* SPPIFO_DEBUG_STATS_PEAK */

	return NET_XMIT_SUCCESS;
}

/* QDisc remove a packet from the highest priority non-empty FIFO */
static struct sk_buff *sppifo_qdisc_dequeue(struct Qdisc *sch)
{
	struct sppifo_sched_data *q = qdisc_priv(sch);
	struct sk_buff *	skb = NULL;
	struct skb_array *list;
	u64			virtual_pkt;
	int b;

	/* If all sub-queues are empty, nothing to schedule. */
	if (unlikely(sch->q.qlen == 0))
		return NULL;

	for (b = SPPIFO_BANDS - 1; b >= 0; b--)
	{
		if (q->stats.band_qlen[b] > 0)
		{
			list = sppifo_band2list(q, b);

			if(list == NULL)
			{
				printk("SP_PIFO: BUG -> band cannot be null!\n");
				return NULL;
			}

			if (unlikely(skb_array_empty(list))) {
				printk("SP_PIFO: BUG -> Could not find a packet in non-empty band!\n");
				return NULL;
			}

#ifdef SPPIFO_DEBUG_SPPIFO_DEQUEUE
			printk(KERN_DEBUG "SP-PIFO: consuming band %d of length %u\n", b, q->stats.band_qlen[b] );
#endif	/* SPPIFO_DEBUG_SPPIFO_DEQUEUE */
			skb = skb_array_consume(list);
			q->stats.band_qlen[b]--;
			sch->q.qlen--;
			break;
		}
	}

	if(unlikely(skb == NULL))
	{
		printk("SP_PIFO: BUG -> Could not find a packet in bands!\n");
		return NULL;
	}

	/* Get virtual tag of this packet. */
	virtual_pkt = sppifo_skb_cb(skb)->virtual_start;


	/* SPPIFO: Update virtual time - Check if queue is busy */
	if (sch->q.qlen == 0) {
		q->virtual_dequeue = virtual_pkt + qdisc_pkt_len(skb);
	} else {
		// Dequeued packet might not have the most recent virtual time
		if ( time_after64(virtual_pkt, q->virtual_dequeue) )
			q->virtual_dequeue = virtual_pkt;
		else	// re-ordering in dequeue
			q->stats.num_reordering++;
	}

#ifdef SPPIFO_DEBUG_SPPIFO_DEQUEUE
	printk(KERN_DEBUG "SPPIFO: dequeue: vpkt:%lld; ql:%d; band:%d\n", q->virtual_dequeue, sch->q.qlen, b);
#endif	/* SPPIFO_DEBUG_SPPIFO_DEQUEUE */
	q->stats.band_tx[b]++;
	qdisc_qstats_backlog_dec(sch, skb);
	qdisc_bstats_update(sch, skb);
	return skb;
}

static void sppifo_rehash(struct sppifo_sched_data *q,
		      struct rb_root *old_array, u32 old_log,
		      struct rb_root *new_array, u32 new_log)
{
	struct rb_node *op, **np, *parent;
	struct rb_root *oroot, *nroot;
	struct sppifo_flow *of, *nf;
	int fcnt = 0;
	u32 idx;

	for (idx = 0; idx < (1U << old_log); idx++) {
		oroot = &old_array[idx];
		while ((op = rb_first(oroot)) != NULL) {
			rb_erase(op, oroot);
			of = rb_entry(op, struct sppifo_flow, hash_node);
			if (sppifo_gc_candidate(of)) {
				fcnt++;
				kmem_cache_free(sppifo_flow_cachep, of);
				continue;
			}
			nroot = &new_array[hash_32(of->flow_idx, new_log)];

			np = &nroot->rb_node;
			parent = NULL;
			while (*np) {
				parent = *np;

				nf = rb_entry(parent, struct sppifo_flow, hash_node);
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

static void sppifo_hash_free(void *addr)
{
	kvfree(addr);
}

static int sppifo_hash_resize(struct Qdisc *sch, u32 log)
{
	struct sppifo_sched_data *q = qdisc_priv(sch);
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
		sppifo_rehash(q, old_hash_root, q->hash_trees_log, array, log);

	q->hash_root = array;
	q->hash_trees_log = log;
	q->hash_buckets = buckets;

	sch_tree_unlock(sch);

	sppifo_hash_free(old_hash_root);

	return 0;
}

static const struct nla_policy sppifo_policy[TCA_SPPIFO_MAX + 1] = {
	[TCA_SPPIFO_PLIMIT]		= { .type = NLA_U32 },
	[TCA_SPPIFO_BUCKETS_LOG]		= { .type = NLA_U32 },
	[TCA_SPPIFO_HASH_MASK]		= { .type = NLA_U32 },
	[TCA_SPPIFO_BAND_PLIMIT]		= { .type = NLA_U32 },
	[TCA_SPPIFO_FLAGS]		= { .type = NLA_U32 },
};

static int sppifo_qdisc_change(struct Qdisc *sch,
			     struct nlattr *opt,
			     struct netlink_ext_ack *extack)
{
	struct sppifo_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_SPPIFO_MAX + 1];
	u32		plimit;
	u32		hash_log_new;
	int		err;
	int		drop_count = 0;
	unsigned	drop_len = 0;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_SPPIFO_MAX, opt, sppifo_policy,
					  NULL);
	if (err < 0)
		return err;

	/* Check limit before locking */
	if (tb[TCA_SPPIFO_PLIMIT]) {
		plimit = nla_get_u32(tb[TCA_SPPIFO_PLIMIT]);
		/* Can't be negative... */
		if (plimit == 0)
			return -EINVAL;
	}

	sch_tree_lock(sch);

	if (tb[TCA_SPPIFO_PLIMIT])
		sch->limit = plimit;

	hash_log_new = q->hash_trees_log;
	if (tb[TCA_SPPIFO_BUCKETS_LOG]) {
		u32 nval = nla_get_u32(tb[TCA_SPPIFO_BUCKETS_LOG]);

		if (nval >= 1 && nval <= ilog2(256*1024))
			hash_log_new = nval;
		else
			err = -EINVAL;
	}

	if (tb[TCA_SPPIFO_HASH_MASK])
		q->hash_mask = nla_get_u32(tb[TCA_SPPIFO_HASH_MASK]);

	if (tb[TCA_SPPIFO_BAND_PLIMIT])
		q->band_plimit = nla_get_u32(tb[TCA_SPPIFO_BAND_PLIMIT]);
	if (q->band_plimit == 0)
		q->band_plimit = SPPIFO_BAND_PLIMIT_DEFLT;

	if (tb[TCA_SPPIFO_FLAGS])
                q->flags = nla_get_u32(tb[TCA_SPPIFO_FLAGS]);

	if (!err) {

		sch_tree_unlock(sch);
		/* Only done if hash_log_new != q->hash_trees_log */
		err = sppifo_hash_resize(sch, hash_log_new);
		sch_tree_lock(sch);
	}
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = sppifo_qdisc_dequeue(sch);

		if (!skb)
			break;
		drop_len += qdisc_pkt_len(skb);
		rtnl_kfree_skbs(skb, skb);
		drop_count++;
	}
	qdisc_tree_reduce_backlog(sch, drop_count, drop_len);

	sch_tree_unlock(sch);

#ifdef SPPIFO_DEBUG_CONFIG
	printk(KERN_DEBUG "SPPIFO: plimit %d; logs %d; mask 0x%X; band_plimit %d; flags 0x%X\n", sch->limit, q->hash_trees_log, q->hash_mask, q->band_plimit, q->flags);
#endif	/* SPPIFO_DEBUG_CONFIG */

	return err;
}

static int sppifo_qdisc_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct sppifo_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	/* Standard queue limit */
	if (nla_put_u32(skb, TCA_SPPIFO_PLIMIT, sch->limit))
		goto nla_put_failure;

	/* Hashing attributes */
	if (nla_put_u32(skb, TCA_SPPIFO_BUCKETS_LOG, q->hash_trees_log))
		goto nla_put_failure;
	if (nla_put_u32(skb, TCA_SPPIFO_HASH_MASK, q->hash_mask))
		goto nla_put_failure;

	/* Other attributes */
	if (nla_put_u32(skb, TCA_SPPIFO_BAND_PLIMIT, q->band_plimit))
		goto nla_put_failure;
	if (nla_put_u32(skb, TCA_SPPIFO_FLAGS, q->flags))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int sppifo_qdisc_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct sppifo_sched_data *q = qdisc_priv(sch);
	struct tc_sppifo_xstats st;

	memcpy(&st, &q->stats, sizeof(st));

	/* Reset some of the statistics, unless disabled */
	if ( ! (q->flags & SCF_PEAK_NORESET) ) {
		q->stats.qlen_peak = 0;
		q->stats.backlog_peak = 0;
		q->stats.burst_peak = 0;
	}

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static int sppifo_qdisc_init(struct Qdisc *sch,
			   struct nlattr *opt,
			   struct netlink_ext_ack *extack)
{
	struct sppifo_sched_data *q = qdisc_priv(sch);
	int err, b;

	/* Configuration */
	sch->limit		= SPPIFO_PLIMIT_DEFLT;
	q->band_plimit		= 0;
	q->hash_mask		= SPPIFO_HASH_MASK_DEFLT;

	/* Parameters */
	q->hash_root		= NULL;
	q->hash_trees_log	= ilog2(SPPIFO_HASH_NUM_DEFLT);
	q->virtual_dequeue	= 0LL;
	q->age_next_gc		= jiffies + SPPIFO_GC_AGE / 2;

	/* Schedule */
	for(b = 0;b < SPPIFO_BANDS; b++){
		struct skb_array *list = sppifo_band2list(q, b);
		int err;

		err = skb_array_init(list, SPPIFO_PLIMIT_DEFLT, GFP_KERNEL);
		if (err)
			return -ENOMEM;

		q->stats.band_qlen[b] = 0;
		q->sppifo_qbound[b] = 0;
	}
		

	if (opt)
		err = sppifo_qdisc_change(sch, opt, extack);
	else
		err = sppifo_hash_resize(sch, q->hash_trees_log);

	return err;
}

static void sppifo_qdisc_reset(struct Qdisc *sch)
{
	struct sppifo_sched_data *q = qdisc_priv(sch);
	struct rb_root *root;
	struct rb_node *p;
	struct sppifo_flow *flow_cur;
	struct skb_array *list;
	struct sk_buff *	skb;
	unsigned int idx;
	int b;

	sch->q.qlen = 0;
	sch->qstats.backlog = 0;

	q->stats.flows		= 0;
	q->stats.no_mark	= 0;
	q->stats.drop_mark	= 0;
	q->stats.burst_peak	= 0;
	q->stats.burst_avg	= 0;
	q->stats.num_inversions	= 0;
	q->stats.num_reordering	= 0;


	if (!q->hash_root)
		return;

	for (idx = 0; idx < (1U << q->hash_trees_log); idx++) {
		root = &q->hash_root[idx];
		while ((p = rb_first(root)) != NULL) {
			flow_cur = rb_entry(p, struct sppifo_flow, hash_node);
			/* Remove from classifier */
			rb_erase(p, root);

			kmem_cache_free(sppifo_flow_cachep, flow_cur);
		}
	}

	for(b = 0;b < SPPIFO_BANDS; b++)
	{
		
		list = sppifo_band2list(q, b);

		if (!list->ring.queue)
			continue;

		while ((skb = __skb_array_consume(list)) != NULL)
			kfree_skb(skb);
		q->stats.band_qlen[b] = 0;
		q->sppifo_qbound[b] = 0;
	}


}

static void sppifo_qdisc_destroy(struct Qdisc *sch)
{
	int b;
	struct sppifo_sched_data *q = qdisc_priv(sch);

	sppifo_qdisc_reset(sch);


	for (b = 0; b < SPPIFO_BANDS; b++) {
		struct skb_array *list = sppifo_band2list(q, b);

		if (!list->ring.queue)
			continue;
		/* Destroy ring but no need to kfree_skb because a call to
		 * reset() has already done that work.
		 */
		ptr_ring_cleanup(&list->ring, NULL);
	}

	sppifo_hash_free(q->hash_root);
}

static struct Qdisc_ops sppifo_qdisc_ops __read_mostly = {
	.id		=	"sppifo_stfq",
	.priv_size	=	sizeof(struct sppifo_sched_data),

	.enqueue	=	sppifo_qdisc_enqueue,
	.dequeue	=	sppifo_qdisc_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	sppifo_qdisc_init,
	.reset		=	sppifo_qdisc_reset,
	.destroy	=	sppifo_qdisc_destroy,
	.change		=	sppifo_qdisc_change,
	.dump		=	sppifo_qdisc_dump,
	.dump_stats	=	sppifo_qdisc_dump_stats,
	.owner		=	THIS_MODULE,
};


static int __init sppifo_module_init(void)
{
	int ret;

	sppifo_flow_cachep = kmem_cache_create("sppifo_flow_cache",
					   sizeof(struct sppifo_flow),
					   0, 0, NULL);
	if (!sppifo_flow_cachep)
		return -ENOMEM;

	ret = register_qdisc(&sppifo_qdisc_ops);
	if (ret) {
		kmem_cache_destroy(sppifo_flow_cachep);
	}
	return ret;
}

static void __exit sppifo_module_exit(void)
{
	unregister_qdisc(&sppifo_qdisc_ops);
	kmem_cache_destroy(sppifo_flow_cachep);
}

module_init(sppifo_module_init)
module_exit(sppifo_module_exit)
MODULE_AUTHOR("Erfan Sharafzadeh");
MODULE_AUTHOR("Jean Tourrilhes");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Strict-Priority Push-In-First-Out Packet Scheduler");
