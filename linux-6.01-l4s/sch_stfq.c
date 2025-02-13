// SPDX-License-Identifier: GPL-2.0-only
/*
 * net/sched/sch_stfq.c Start Time Fair Queue Scheduler
 *
 *	Copyright 2023-2025 Hewlett Packard Enterprise Development LP.
 *	Author: Erfan Sharafzadeh <e.sharafzadeh@jhu.edu>
 *	Author: Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 *
 * STFQ usees the notion of virtual clocking to decide the departure of
 * packets in a multi-queue packet scheduler. Please refer to the paper
 * for more information.
 *
 * STFQ uses a RB-tree to store the ordered list of flows to schedule,
 * which is more scalable than a linked list. This is totally separate
 * from the RB-trees in the classifier.
 *
 * ---------------------------------------------------------------- *
 *
 * Flow management (classification, lists, gc...) based on sch_fq.c :
 *  Copyright (C) 2013-2015 Eric Dumazet <edumazet@google.com>
 *
 *  Flows are dynamically allocated and stored in a hash table of RB trees
 *
 *  enqueue() :
 *   - lookup one RB tree (out of 1024 or more) to find the flow.
 *     If non existent flow, create it, add it to the tree.
 *     Add skb to the per flow list of skb (fifo).
 *
 *  dequeue() : serves flows based on virtual time
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

//#define STFQ_DEBUG_CONFIG
//#define STFQ_DEBUG_FLOW_NEW
//#define STFQ_DEBUG_STFQ_ENQUEUE
//#define STFQ_DEBUG_STFQ_DEQUEUE
//#define STFQ_DEBUG_STATS_PEAK
#define STFQ_DEBUG_BURST_AVG

#define STFQ_PLIMIT_DEFLT		(10000)		/* packets */
#define STFQ_FLOW_PLIMIT_DEFLT		(100)		/* packets */
#define STFQ_HASH_NUM_DEFLT		(1024)		/* num tree roots */
#define STFQ_HASH_MASK_DEFLT		(1024 - 1)	/* bitmask */

enum {
	TCA_STFQ_UNSPEC,
	TCA_STFQ_PLIMIT,	/* limit of total number of packets in queue */
	TCA_STFQ_BUCKETS_LOG,	/* log2(number of buckets) */
	TCA_STFQ_HASH_MASK,	/* mask applied to skb hashes */
	TCA_STFQ_FLOW_PLIMIT,	/* limit of packets per flow */
	TCA_STFQ_FLAGS,		/* Options */
	__TCA_STFQ_MAX
};
#define TCA_STFQ_MAX	(__TCA_STFQ_MAX - 1)

/* TCA_STFQ_FLAGS */
#define SCF_PEAK_NORESET	0x0020	/* Don't reset peak statistics */

/* statistics gathering */
struct tc_stfq_xstats {
	__u32	flows;		/* number of flows */
	__u32	flows_inactive;	/* number of inactive flows */
	__u64	flows_gc;	/* number of flows garbage collected */
	__u32	alloc_errors;	/* failed flow allocations */
	__u32	no_mark;	/* packet not dropped */
	__u32	drop_mark;	/* packet dropped */
	__u32	qlen_peak;	/* Maximum queue length */
	__u32	backlog_peak;	/* Maximum backlog */
	__u32	burst_peak;	/* Maximum burst size */
	__u32	burst_avg;	/* Average burst size */
	__u32	sched_empty;	/* Schedule with no packet */
};

/*
 * Per flow structure, dynamically allocated.
 */
struct stfq_flow {
	struct sk_buff	*head;		/* list of skbs for this flow : first skb */
	union {
		struct sk_buff *tail;	/* last skb in the list */
		unsigned long  age;	/* (jiffies | 1UL) when flow was emptied, for gc */
	};
	struct rb_node	hash_node;	/* anchor in hash_root[] trees */
	struct rb_node	stfq_node;	/* flow pointer in the sorted flow tree */
	u64		virtual_tail;	/* Virtual of next incoming packet */
	u64		virtual_head;	/* Virtual where inserted in RB tree */
	u32		flow_idx;	/* Hash value for this flow */
	int		qlen;		/* number of packets in flow queue */

} ____cacheline_aligned_in_smp;

static struct kmem_cache *stfq_flow_cachep __read_mostly;

/*
 * Private data for the Qdisc
 */
struct stfq_sched_data {
	/* Configuration */
	u32		hash_mask;	/* mask for orphaned skb */
	u8		hash_trees_log;	/* log(number buckets) */
	u32		flow_plimit;	/* max packets per flow */
	u32		flags;		/* Bitmask of AIFF_XXX flags */

	/* Classifier */
	struct rb_root	*hash_root;	/* Hash of tree roots */
	u32		hash_buckets;

	/* Stats and instrumentation */
	struct tc_stfq_xstats  stats;
#ifdef STFQ_DEBUG_BURST_AVG
	u32		flow_sched_prev;	/* Previously active flow */
	u32		burst_cur;	/* Current burst size */
#endif	/* STFQ_DEBUG_BURST_AVG */

	/* Scheduler */
	struct rb_root_cached	scheduled_flows;	/* Sorted flow list */
	u64		virtual_dequeue;  /* Virtual of last dequeue */
};

/*
 * Packet Metadata
 */
struct stfq_skb_cb {
	u64	virtual_start;		/* Virtual start-time of packet */
};

static inline struct stfq_skb_cb *stfq_skb_cb(struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct stfq_skb_cb));
	return (struct stfq_skb_cb *)qdisc_skb_cb(skb)->data;
}

/*
 * flow->tail and flow->age share the same location.
 * We can use the low order bit to differentiate if this location points
 * to a sk_buff or contains a jiffies value, if we force this value to be odd.
 * This assumes flow->tail low order bit must be 0 since
 * alignof(struct sk_buff) >= 2
 */
static void stfq_flow_set_detached(struct stfq_flow *flow)
{
	flow->age = jiffies | 1UL;
}

static bool stfq_flow_is_detached(const struct stfq_flow *flow)
{
	return !!(flow->age & 1UL);
}

static inline struct stfq_flow *stfq_create_flow(struct stfq_sched_data *q,
						 uint32_t flow_idx)
{
	struct stfq_flow *flow_new;

	flow_new = kmem_cache_zalloc(stfq_flow_cachep, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(flow_new == NULL)) {
		q->stats.alloc_errors++;
		return NULL;
	}

	stfq_flow_set_detached(flow_new);
	flow_new->flow_idx = flow_idx;

	/* Initialise virtual time of the flow. */
	flow_new->virtual_tail = q->virtual_dequeue;

	q->stats.flows++;
	q->stats.flows_inactive++;

	return flow_new;
}

static inline void stfq_flow_purge(struct stfq_flow *flow,
				   struct stfq_sched_data *q)
{

	/* If flow is actively scheduled, remove from scheduler */
	if ( ! stfq_flow_is_detached(flow) ) {
		rb_erase_cached(&(flow->stfq_node), &(q->scheduled_flows));
	}

	/* Remove all SKBs attached to this flow */
	rtnl_kfree_skbs(flow->head, flow->tail);
	flow->head = NULL;
	flow->qlen = 0;
}

/* limit number of collected flows per round */
#define STFQ_GC_MAX 8
#define STFQ_GC_AGE (3*HZ)

static bool stfq_gc_candidate(const struct stfq_flow *f)
{
	return stfq_flow_is_detached(f) &&
	       time_after(jiffies, f->age + STFQ_GC_AGE);
}

static void stfq_gc(struct stfq_sched_data *q,
		    struct rb_root *	root,
		    uint32_t		flow_idx)
{
	struct rb_node **p, *parent;
	void *tofree[STFQ_GC_MAX];
	struct stfq_flow *f;
	int i, fcnt = 0;

	p = &root->rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		f = rb_entry(parent, struct stfq_flow, hash_node);
		if (f->flow_idx == flow_idx)
			break;

		if (stfq_gc_candidate(f)) {
			tofree[fcnt++] = f;
			if (fcnt == STFQ_GC_MAX)
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
		/* No need to call stfq_flow_purge(), flow was idle */
	}
	q->stats.flows -= fcnt;
	q->stats.flows_inactive -= fcnt;
	q->stats.flows_gc += fcnt;

	kmem_cache_free_bulk(stfq_flow_cachep, fcnt, tofree);
}

static struct stfq_flow *stfq_classify(struct sk_buff *skb,
				       struct stfq_sched_data *q)
{
	struct rb_node **	p;
	struct rb_node *	parent;
	uint32_t		flow_idx;
	struct rb_root *	root;
	struct stfq_flow *	flow_cur;

	/* Get hash value for the packet */
	flow_idx = (uint32_t) ( skb_get_hash(skb) & q->hash_mask );

	/* Get the root of the tree from the hash */
	root = &q->hash_root[ flow_idx & (q->hash_buckets - 1) ];

	/* I personally feel that the garbage collection policy is
	 * not aggressive enough. Also, garbage collection only scan
	 * a subset of the trees, so I think there might be flows never
	 * garbage collected. Unfortunately, I don't have time and
	 * inclination to play with it. Jean II */
	if (q->stats.flows >= (q->hash_buckets * 2) &&
	    q->stats.flows_inactive > q->stats.flows/2)
		stfq_gc(q, root, flow_idx);

	/* Find flow in that specific tree */
	p = &root->rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		flow_cur = rb_entry(parent, struct stfq_flow, hash_node);
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
	flow_cur = stfq_create_flow(q, flow_idx);
	if (unlikely(flow_cur == NULL)) {
		return NULL;
	}

	/* Insert new flow into classifer */
	rb_link_node(&flow_cur->hash_node, parent, p);
	rb_insert_color(&flow_cur->hash_node, root);

#ifdef STFQ_DEBUG_FLOW_NEW
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
			printk(KERN_DEBUG "STFQ: flow new: idx:%d, src_addr:%d, dst_addr:%d, src_port:%d, dst_port:%d\n", flow_idx, ntohl(ih->saddr), ntohl(ih->daddr), ntohs(src_port), ntohs(dest_port));
		} else {
			printk(KERN_DEBUG "STFQ: flow new: idx:%d\n", flow_idx);
		}
	}
#endif	/* STFQ_DEBUG_FLOW_NEW */

	return flow_cur;
}

/* Inserting flows into the sorted RB tree based on the virtual time */
static void stfq_schedule_insert_flow(struct stfq_sched_data *	q,
				      struct stfq_flow *	flow,
				      u64			virtual_head)
{
	struct rb_root_cached *root = &(q->scheduled_flows);
	struct rb_node **new = &root->rb_root.rb_node;
	struct rb_node *parent = NULL;
	bool leftmost = true;

	/* Update virtual head */
	flow->virtual_head = virtual_head;
	
	/* Find location in RB tree */
	while (*new) {
		struct stfq_flow* this = rb_entry(*new, struct stfq_flow, stfq_node);
		parent = *new;
		if time_before64(virtual_head, this->virtual_head)
			new = &(parent->rb_left);
		else {
			new = &(parent->rb_right);
			leftmost = false;
		}
	}

	/* Insert in RB tree, rebalance */
	rb_link_node(&flow->stfq_node, parent, new);
	rb_insert_color_cached(&flow->stfq_node, root, leftmost);
}

static inline struct sk_buff *stfq_peek_skb(struct stfq_flow *flow)
{
	struct sk_buff *head = flow->head;

	return head;
}

/* Add one skb to the flow queue. */
static inline void stfq_enqueue_skb(struct Qdisc *	sch,
				    struct stfq_flow *	flow,
				    struct sk_buff *	skb)
{
	if (flow->head == NULL)
		flow->head = skb;
	else
		flow->tail->next = skb;
	flow->tail = skb;
	skb->next = NULL;

	flow->qlen++;
	qdisc_qstats_backlog_inc(sch, skb);
	sch->q.qlen++;
}

/* Remove one skb from flow queue. */
static inline struct sk_buff *stfq_dequeue_skb(struct Qdisc *	sch,
					       struct stfq_flow *	flow)
{
	struct sk_buff *	skb;

	skb = flow->head;
	if (skb == NULL)
		return NULL;

	flow->head = skb->next;
	skb_mark_not_on_list(skb);

	flow->qlen--;
	qdisc_qstats_backlog_dec(sch, skb);
	sch->q.qlen--;

	return skb;
}

/* QDisc add a new packet to our queue - tail of queue. */
static int stfq_qdisc_enqueue(struct sk_buff *	skb,
			      struct Qdisc *	sch,
			      struct sk_buff **	to_free)
{
	struct stfq_sched_data *q = qdisc_priv(sch);
	struct stfq_flow *	flow_cur;
	u64			virtual_pkt;

	/* Tail-drop when queue is full - pfifo style limit */
	if (unlikely(sch->q.qlen >= sch->limit)) {
		qdisc_qstats_overlimit(sch);
		return qdisc_drop(skb, sch, to_free);
	}

	/* Find or create flow for this packet. */
	flow_cur = stfq_classify(skb, q);
	if (unlikely(flow_cur == NULL)) {
		/* Alt : enqueue packet on random flow, Jean II */
		return qdisc_drop(skb, sch, to_free);
	}

	/* Check sub-queue size. */
	if (unlikely(flow_cur->qlen >= q->flow_plimit)) {
		q->stats.drop_mark++;
		return qdisc_drop(skb, sch, to_free);
	}
	/* bstats->packets keep track of the number of actual Ethernet
	 * packets. Unfortunately, all other stats are in number of
	 * sbks. The packet count and skb count are different due
	 * to GSO. This counter allow to count skbs and therefore
	 * have something consistent with the other stats. Jean II */
	q->stats.no_mark++;

	/* STFQ : compute virtual time of packet. */
	if ( time_after64(q->virtual_dequeue, flow_cur->virtual_tail) )
		virtual_pkt = q->virtual_dequeue;
	else
		virtual_pkt = flow_cur->virtual_tail;

	/* Save virtual time in packet to be used in dequeue */
	stfq_skb_cb(skb)->virtual_start = virtual_pkt;

	/* Update flow virtual time.
	 * STFQ : All flows have the same weight. Jean II */
	flow_cur->virtual_tail = virtual_pkt + qdisc_pkt_len(skb);

	/* Check if flow was inactive, i.e. not scheduled. */
	if (stfq_flow_is_detached(flow_cur)) {

		q->stats.flows_inactive--;

		/* STFQ: Add flow to rb tree. The flow was empty, so it
		 * now has one packet, which is at the head. */
		stfq_schedule_insert_flow(q, flow_cur, virtual_pkt);
	}

	/* Note: this overwrites flow_cur->age */
	stfq_enqueue_skb(sch, flow_cur, skb);

#ifdef STFQ_DEBUG_STFQ_ENQUEUE
	printk(KERN_DEBUG "STFQ: enqueue:  idx:%d; vdq:%lld; vpkt:%lld; vtail:%lld; fl:%d; ql:%d\n", flow_cur->flow_idx, q->virtual_dequeue, virtual_pkt, flow_cur->virtual_tail, flow_cur->qlen, sch->q.qlen);
#endif	/* STFQ_DEBUG_STFQ_ENQUEUE */

#ifdef STFQ_DEBUG_STATS_PEAK
	/* Keep track of peak statistics */
	if (sch->q.qlen >= q->stats.qlen_peak)
		q->stats.qlen_peak = sch->q.qlen;

	if ( (sch->qstats.backlog > q->stats.backlog_peak)
	     && (sch->qstats.backlog < 2147483648) )
		q->stats.backlog_peak = sch->qstats.backlog;
#endif	/* STFQ_DEBUG_STATS_PEAK */

	return NET_XMIT_SUCCESS;
}

/* QDisc remove a packet from our queue - leftmost rb tree node. */
static struct sk_buff *stfq_qdisc_dequeue(struct Qdisc *sch)
{
	struct stfq_sched_data *q = qdisc_priv(sch);
	struct stfq_flow *flow_cur;
	struct rb_node *node_cur;
	struct sk_buff *	skb;
	u64			virtual_pkt;

	/* If all sub-queues are empty, nothing to schedule. */
	if (unlikely(sch->q.qlen == 0))
		return NULL;

retry_flow:

	/* Flows are always sorted by the virtual time of the head packet,
	 * so the leftmost flow should be scheduled first. */
	node_cur = rb_first_cached(&(q->scheduled_flows));

	if (unlikely(node_cur == NULL)) {
		printk_ratelimited(KERN_ERR "STFQ: no flow to schedule !\n");
		return NULL;
	}

	flow_cur = rb_entry(node_cur, struct stfq_flow, stfq_node);

	/* Remove flow from current list, advance to next flow. */
	rb_erase_cached(node_cur, &(q->scheduled_flows));

	/* Always dequeue a packet. Or try. Jean II */
	skb = stfq_dequeue_skb(sch, flow_cur);

	if (skb == NULL) {
		/* If the sub-queue was empty, that flow becomes inactive.
		 * It may be reactived in stfq_qdisc_enqueue(). Jean II */

		/* This is not supposed to happen, empty flows are supposed
		 * to always go inactive below. */
		printk_ratelimited(KERN_ERR "STFQ: flow with no SKB !\n");

		/* Flow goes inactive */
		stfq_flow_set_detached(flow_cur);
		q->stats.flows_inactive++;

#ifdef STFQ_DEBUG_BURST_AVG
		q->stats.sched_empty++;
#endif	/* STFQ_DEBUG_BURST_AVG */

		/* Pick another flow.
		 * This won't infinite loop because sch->q.qlen != 0
		 * and the list of flows will become empty. */
		goto retry_flow;
	}

	/* Get virtual tag of this packet. */
	virtual_pkt = stfq_skb_cb(skb)->virtual_start;

#ifdef STFQ_DEBUG_BURST_AVG
	/* Check if packet is part of the same burst.
	 * If there is only one active flow, burstiness does not make sense */
	if ( (flow_cur->flow_idx == q->flow_sched_prev)
	     && (q->stats.flows - q->stats.flows_inactive > 1) ) {
		/* Part of same burst, just add */
		q->burst_cur += qdisc_pkt_len(skb);
	} else {
		/* Add previous burst to average */
		if (q->burst_cur > q->stats.burst_peak)
			q->stats.burst_peak = q->burst_cur;
		if (q->stats.burst_avg == 0)
			q->stats.burst_avg = q->burst_cur;
		else
			q->stats.burst_avg = ( ( q->stats.burst_avg * 7
						 + q->burst_cur ) / 8 );
		/* Start new burst */
		q->burst_cur = qdisc_pkt_len(skb);
		q->flow_sched_prev = flow_cur->flow_idx;
	}
#endif	/* STFQ_DEBUG_BURST_AVG */

	/* STFQ: Update virtual time - Check if queue is busy */
	if (sch->q.qlen == 0) {
		q->virtual_dequeue = virtual_pkt + qdisc_pkt_len(skb);
	} else {
		q->virtual_dequeue = virtual_pkt;
	}

	/* Check if flow has more packets to send. */
	if(flow_cur->qlen > 0) {
		u64	virtual_next;

		/* Compute virtual tag of next packet in the sub-queue
		 * The finish time of the current packet is after
		 * virtual_dequeue.
		 * This time is the new head of this flow. */
		virtual_next = virtual_pkt + qdisc_pkt_len(skb);

		/* STFQ: Add the flow back to the rb tree at new position
		 * the virtual time of the new head packet. */
		stfq_schedule_insert_flow(q, flow_cur, virtual_next);
	} else {
		/* Flow goes inactive */
		stfq_flow_set_detached(flow_cur);
		q->stats.flows_inactive++;
	}

#ifdef STFQ_DEBUG_STFQ_DEQUEUE
	printk(KERN_DEBUG "STFQ: dequeue: idx:%d; vdq:%lld; vpkt:%lld; vnxt:%lld; fl:%d; ql:%d\n", flow_cur->flow_idx, q->virtual_dequeue, virtual_pkt, virtual_pkt + qdisc_pkt_len(skb), flow_cur->qlen, sch->q.qlen);
#endif	/* STFQ_DEBUG_STFQ_DEQUEUE */

	qdisc_bstats_update(sch, skb);
	return skb;
}

static void stfq_rehash(struct stfq_sched_data *q,
		      struct rb_root *old_array, u32 old_log,
		      struct rb_root *new_array, u32 new_log)
{
	struct rb_node *op, **np, *parent;
	struct rb_root *oroot, *nroot;
	struct stfq_flow *of, *nf;
	int fcnt = 0;
	u32 idx;

	for (idx = 0; idx < (1U << old_log); idx++) {
		oroot = &old_array[idx];
		while ((op = rb_first(oroot)) != NULL) {
			rb_erase(op, oroot);
			of = rb_entry(op, struct stfq_flow, hash_node);
			if (stfq_gc_candidate(of)) {
				fcnt++;
				kmem_cache_free(stfq_flow_cachep, of);
				continue;
			}
			nroot = &new_array[hash_32(of->flow_idx, new_log)];

			np = &nroot->rb_node;
			parent = NULL;
			while (*np) {
				parent = *np;

				nf = rb_entry(parent, struct stfq_flow, hash_node);
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
	q->stats.flows_inactive -= fcnt;
	q->stats.flows_gc += fcnt;
}

static void stfq_hash_free(void *addr)
{
	kvfree(addr);
}

static int stfq_hash_resize(struct Qdisc *sch, u32 log)
{
	struct stfq_sched_data *q = qdisc_priv(sch);
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
		stfq_rehash(q, old_hash_root, q->hash_trees_log, array, log);

	q->hash_root = array;
	q->hash_trees_log = log;
	q->hash_buckets = buckets;

	sch_tree_unlock(sch);

	stfq_hash_free(old_hash_root);

	return 0;
}

static const struct nla_policy stfq_policy[TCA_STFQ_MAX + 1] = {
	[TCA_STFQ_PLIMIT]		= { .type = NLA_U32 },
	[TCA_STFQ_BUCKETS_LOG]		= { .type = NLA_U32 },
	[TCA_STFQ_HASH_MASK]		= { .type = NLA_U32 },
	[TCA_STFQ_FLOW_PLIMIT]		= { .type = NLA_U32 },
	[TCA_STFQ_FLAGS]		= { .type = NLA_U32 },
};

static int stfq_qdisc_change(struct Qdisc *sch,
			     struct nlattr *opt,
			     struct netlink_ext_ack *extack)
{
	struct stfq_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_STFQ_MAX + 1];
	u32		plimit;
	u32		hash_log_new;
	int		err;
	int		drop_count = 0;
	unsigned	drop_len = 0;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_STFQ_MAX, opt, stfq_policy,
					  NULL);
	if (err < 0)
		return err;

	/* Check limit before locking */
	if (tb[TCA_STFQ_PLIMIT]) {
		plimit = nla_get_u32(tb[TCA_STFQ_PLIMIT]);
		/* Can't be negative... */
		if (plimit == 0)
			return -EINVAL;
	}

	sch_tree_lock(sch);

	if (tb[TCA_STFQ_PLIMIT])
		sch->limit = plimit;

	hash_log_new = q->hash_trees_log;
	if (tb[TCA_STFQ_BUCKETS_LOG]) {
		u32 nval = nla_get_u32(tb[TCA_STFQ_BUCKETS_LOG]);

		if (nval >= 1 && nval <= ilog2(256*1024))
			hash_log_new = nval;
		else
			err = -EINVAL;
	}

	if (tb[TCA_STFQ_HASH_MASK])
		q->hash_mask = nla_get_u32(tb[TCA_STFQ_HASH_MASK]);

	if (tb[TCA_STFQ_FLOW_PLIMIT])
		q->flow_plimit = nla_get_u32(tb[TCA_STFQ_FLOW_PLIMIT]);

	if (tb[TCA_STFQ_FLAGS])
                q->flags = nla_get_u32(tb[TCA_STFQ_FLAGS]);

	if (!err) {

		sch_tree_unlock(sch);
		/* Only done if hash_log_new != q->hash_trees_log */
		err = stfq_hash_resize(sch, hash_log_new);
		sch_tree_lock(sch);
	}
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = stfq_qdisc_dequeue(sch);

		if (!skb)
			break;
		drop_len += qdisc_pkt_len(skb);
		rtnl_kfree_skbs(skb, skb);
		drop_count++;
	}
	qdisc_tree_reduce_backlog(sch, drop_count, drop_len);

	sch_tree_unlock(sch);

#ifdef STFQ_DEBUG_CONFIG
	printk(KERN_DEBUG "STFQ: plimit %d; logs %d; mask 0x%X; flow_plimit %d; flags 0x%X\n", sch->limit, q->hash_trees_log, q->hash_mask, q->flow_plimit, q->flags);
#endif	/* STFQ_DEBUG_CONFIG */

	return err;
}

static int stfq_qdisc_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct stfq_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	/* Standard queue limit */
	if (nla_put_u32(skb, TCA_STFQ_PLIMIT, sch->limit))
		goto nla_put_failure;

	/* Hashing attributes */
	if (nla_put_u32(skb, TCA_STFQ_BUCKETS_LOG, q->hash_trees_log))
		goto nla_put_failure;
	if (nla_put_u32(skb, TCA_STFQ_HASH_MASK, q->hash_mask))
		goto nla_put_failure;

	/* Other attributes */
	if (nla_put_u32(skb, TCA_STFQ_FLOW_PLIMIT, q->flow_plimit))
		goto nla_put_failure;
	if (nla_put_u32(skb, TCA_STFQ_FLAGS, q->flags))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int stfq_qdisc_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct stfq_sched_data *q = qdisc_priv(sch);
	struct tc_stfq_xstats st;

	memcpy(&st, &q->stats, sizeof(st));

	/* Reset some of the statistics, unless disabled */
	if ( ! (q->flags & SCF_PEAK_NORESET) ) {
		q->stats.qlen_peak = 0;
		q->stats.backlog_peak = 0;
		q->stats.burst_peak = 0;
	}

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static int stfq_qdisc_init(struct Qdisc *sch,
			   struct nlattr *opt,
			   struct netlink_ext_ack *extack)
{
	struct stfq_sched_data *q = qdisc_priv(sch);
	int err;

#ifdef STFQ_DEBUG_CONFIG
	printk(KERN_DEBUG "STFQ: sizeof(stfq_flow) %lu\n", sizeof(struct stfq_flow));
#endif	/* STFQ_DEBUG_CONFIG */

	/* Configuration */
	sch->limit		= STFQ_PLIMIT_DEFLT;
	q->flow_plimit		= STFQ_FLOW_PLIMIT_DEFLT;
	q->hash_mask		= STFQ_HASH_MASK_DEFLT;

	/* Parameters */
	q->hash_root		= NULL;
	q->hash_trees_log	= ilog2(STFQ_HASH_NUM_DEFLT);
	q->scheduled_flows	= RB_ROOT_CACHED;
	q->virtual_dequeue	= 0LL;

	if (opt)
		err = stfq_qdisc_change(sch, opt, extack);
	else
		err = stfq_hash_resize(sch, q->hash_trees_log);

	return err;
}

static void stfq_qdisc_reset(struct Qdisc *sch)
{
	struct stfq_sched_data *q = qdisc_priv(sch);
	struct rb_root *root;
	struct rb_node *p;
	struct stfq_flow *flow_cur;
	unsigned int idx;

	sch->q.qlen = 0;
	sch->qstats.backlog = 0;

	q->stats.flows		= 0;
	q->stats.flows_inactive	= 0;
	q->stats.no_mark	= 0;
	q->stats.drop_mark	= 0;
	q->stats.burst_peak	= 0;
	q->stats.burst_avg	= 0;
	q->stats.sched_empty	= 0;

#ifdef STFQ_DEBUG_BURST_AVG
	q->flow_sched_prev	= 0;
	q->burst_cur		= 0;
#endif	/* STFQ_DEBUG_BURST_AVG */

	q->scheduled_flows	= RB_ROOT_CACHED;

	if (!q->hash_root)
		return;

	for (idx = 0; idx < (1U << q->hash_trees_log); idx++) {
		root = &q->hash_root[idx];
		while ((p = rb_first(root)) != NULL) {
			flow_cur = rb_entry(p, struct stfq_flow, hash_node);
			/* Remove from classifier */
			rb_erase(p, root);

			/* Remove from schedule, get rid of SKBs */
			stfq_flow_purge(flow_cur, q);

			kmem_cache_free(stfq_flow_cachep, flow_cur);
		}
	}
}

static void stfq_qdisc_destroy(struct Qdisc *sch)
{
	struct stfq_sched_data *q = qdisc_priv(sch);

	stfq_qdisc_reset(sch);
	stfq_hash_free(q->hash_root);
}

static struct Qdisc_ops stfq_qdisc_ops __read_mostly = {
	.id		=	"stfq",
	.priv_size	=	sizeof(struct stfq_sched_data),

	.enqueue	=	stfq_qdisc_enqueue,
	.dequeue	=	stfq_qdisc_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	stfq_qdisc_init,
	.reset		=	stfq_qdisc_reset,
	.destroy	=	stfq_qdisc_destroy,
	.change		=	stfq_qdisc_change,
	.dump		=	stfq_qdisc_dump,
	.dump_stats	=	stfq_qdisc_dump_stats,
	.owner		=	THIS_MODULE,
};


static int __init stfq_module_init(void)
{
	int ret;

	stfq_flow_cachep = kmem_cache_create("stfq_flow_cache",
					   sizeof(struct stfq_flow),
					   0, 0, NULL);
	if (!stfq_flow_cachep)
		return -ENOMEM;

	ret = register_qdisc(&stfq_qdisc_ops);
	if (ret) {
		kmem_cache_destroy(stfq_flow_cachep);
	}
	return ret;
}

static void __exit stfq_module_exit(void)
{
	unregister_qdisc(&stfq_qdisc_ops);
	kmem_cache_destroy(stfq_flow_cachep);
}

module_init(stfq_module_init)
module_exit(stfq_module_exit)
MODULE_AUTHOR("Erfan Sharafzadeh");
MODULE_AUTHOR("Jean Tourrilhes");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Start Time Fair Queueing Scheduler");
