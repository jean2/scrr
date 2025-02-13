// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Copyright (C) 2013-2015 Eric Dumazet <edumazet@google.com>
 *
 *  Meant to be mostly used for locally generated traffic :
 *  Fast classification depends on skb->sk being set before reaching us.
 *  If not, (router workload), we use rxhash as fallback, with 32 bits wide hash.
 *  All packets belonging to a socket are considered as a 'flow'.
 *
 *  Flows are dynamically allocated and stored in a hash table of RB trees
 *  They are also part of one Round Robin 'queues' (new or old flows)
 *
 *  Burst avoidance (aka pacing) capability :
 *
 *  Transport (eg TCP) can set in sk->sk_pacing_rate a rate, enqueue a
 *  bunch of packets, and this packet scheduler adds delay between
 *  packets to respect rate limitation.
 *
 *  enqueue() :
 *   - lookup one RB tree (out of 1024 or more) to find the flow.
 *     If non existent flow, create it, add it to the tree.
 *     Add skb to the per flow list of skb (fifo).
 *   - Use a special fifo for high prio packets
 *
 *  dequeue() : serves flows in Round Robin
 *  Note : When a flow becomes empty, we do not immediately remove it from
 *  rb trees, for performance reasons (its expected to send additional packets,
 *  or SLAB cache will reuse socket for another flow)
 */
/*
 * Remove all socket/pacing stuff to keep only the Deficit Round Robin.
 *	Copyright 2023-2025 Hewlett Packard Enterprise Development LP.
 *	Author: Jean Tourrilhes <tourrilhes.hpl@gmail.com>
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

//#define DRR_DEBUG_CONFIG
//#define DRR_DEBUG_GC
//#define DRR_DEBUG_CLASSIFIER
//#define DRR_DEBUG_REHASH
#define DRR_DEBUG_BURST_AVG

/*
 * Per flow structure, dynamically allocated.
 */
struct fq_flow {
	struct sk_buff	*head;		/* list of skbs for this flow : first skb */
	union {
		struct sk_buff *tail;	/* last skb in the list */
		unsigned long  age;	/* (jiffies | 1UL) when flow was emptied, for gc */
	};
	struct rb_node	hash_node;	/* anchor in hash_root[] trees */
	u32		flow_idx;	/* Hash value for this flow */
	int		qlen;		/* number of packets in flow queue */
	int		credit;		/* Deficit */

	struct fq_flow *next;		/* next flow in RR lists */
} ____cacheline_aligned_in_smp;

/*
 * Container for list of flows. Round Robin will go through those lists.
 */
struct fq_flow_head {
	struct fq_flow *first;
	struct fq_flow *last;
};

static struct kmem_cache *fq_flow_cachep __read_mostly;

/*
 * Private data for the Qdisc
 */
struct fq_sched_data {
	struct fq_flow_head new_flows;

	struct fq_flow_head old_flows;

	/* Configuration */
	u32		quantum;
	u32		initial_quantum;
	u32		flow_refill_delay;
	u32		flow_plimit;	/* max packets per flow */
	u64		ce_threshold;
	u32		orphan_mask;	/* mask for orphaned skb */
	/* Parameters */
	struct rb_root	*hash_root;
	u8		hash_trees_log;
	u32		hash_buckets;
	u32		flows;
	u32		inactive_flows;

	u64		stat_gc_flows;
	u64		stat_ce_mark;
	u64		stat_flows_plimit;
	u64		stat_allocation_errors;
#ifdef DRR_DEBUG_BURST_AVG
	u32		flow_sched_prev;	/* Previously active flow */
	u32		burst_cur;	/* Current burst size */
	u32		burst_peak;	/* Maximum burst size */
	u32		burst_avg;	/* Average burst size */
	u32		sched_empty;	/* Schedule with no packet */
	u32		sched_pkts;	/* Schedule with some packets */
#endif	/* DRR_DEBUG_BURST_AVG */
};

/*
 * flow->tail and flow->age share the same location.
 * We can use the low order bit to differentiate if this location points
 * to a sk_buff or contains a jiffies value, if we force this value to be odd.
 * This assumes flow->tail low order bit must be 0 since
 * alignof(struct sk_buff) >= 2
 */
static void fq_flow_set_detached(struct fq_flow *flow)
{
	flow->age = jiffies | 1UL;
}

static bool fq_flow_is_detached(const struct fq_flow *flow)
{
	return !!(flow->age & 1UL);
}

static inline struct fq_flow *fq_create_flow(struct fq_sched_data *q,
					     uint32_t flow_idx)
{
	struct fq_flow *flow_new;

	flow_new = kmem_cache_zalloc(fq_flow_cachep, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(flow_new == NULL)) {
		q->stat_allocation_errors++;
		return NULL;
	}

	fq_flow_set_detached(flow_new);
	flow_new->flow_idx = flow_idx;
	flow_new->credit = q->initial_quantum;

	q->flows++;
	q->inactive_flows++;

	return flow_new;
}

static inline void fq_flow_purge(struct fq_flow *flow)
{
	rtnl_kfree_skbs(flow->head, flow->tail);
	flow->head = NULL;
	flow->qlen = 0;
}

/* limit number of collected flows per round */
#define FQ_GC_MAX 8
#define FQ_GC_AGE (3*HZ)

static bool fq_gc_candidate(const struct fq_flow *f)
{
	return fq_flow_is_detached(f) &&
	       time_after(jiffies, f->age + FQ_GC_AGE);
}

static void fq_gc(struct fq_sched_data *q,
		  struct rb_root *	root,
		  uint32_t		flow_idx)
{
	struct rb_node **p, *parent;
	void *tofree[FQ_GC_MAX];
	struct fq_flow *f;
	int i, fcnt = 0;

	p = &root->rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		f = rb_entry(parent, struct fq_flow, hash_node);
		if (f->flow_idx == flow_idx)
			break;

		if (fq_gc_candidate(f)) {
			tofree[fcnt++] = f;
			if (fcnt == FQ_GC_MAX)
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
		/* No need to call fq_flow_purge(), flow was idle */
	}
	q->flows -= fcnt;
	q->inactive_flows -= fcnt;
	q->stat_gc_flows += fcnt;

#ifdef DRR_DEBUG_GC
	printk(KERN_DEBUG "DRR: flow gc: %d flows\n", fcnt);
#endif	/* DRR_DEBUG_GC */

	kmem_cache_free_bulk(fq_flow_cachep, fcnt, tofree);
}

static struct fq_flow *fq_classify(struct sk_buff *skb,
				   struct fq_sched_data *q)
{
	struct rb_node **	p;
	struct rb_node *	parent;
	uint32_t		flow_idx;
	struct rb_root *	root;
	struct fq_flow *	flow_cur;

	/* Get hash value for the packet */
	flow_idx = (uint32_t) ( skb_get_hash(skb) & q->orphan_mask );

	/* Get the root of the tree from the hash */
	root = &q->hash_root[ flow_idx & (q->hash_buckets - 1) ];

	if (q->flows >= (q->hash_buckets * 2) &&
	    q->inactive_flows > q->flows/2)
		fq_gc(q, root, flow_idx);

#ifdef DRR_DEBUG_CLASSIFIER
	printk(KERN_DEBUG "DRR: flow_idx 0x%X; buckets 0x%X; hash_32 0x%X; hash_root %p; root %p\n", flow_idx, q->hash_buckets - 1, flow_idx & (q->hash_buckets - 1), &q->hash_root[0], root);
#endif	/* DRR_DEBUG_CLASSIFIER */

	p = &root->rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		flow_cur = rb_entry(parent, struct fq_flow, hash_node);
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
	flow_cur = fq_create_flow(q, flow_idx);
	if (unlikely(flow_cur == NULL)) {
		return NULL;
	}

	/* Insert new flow into classifer */
	rb_link_node(&flow_cur->hash_node, parent, p);
	rb_insert_color(&flow_cur->hash_node, root);

	return flow_cur;
}

/* Add a flow at the end of the list used by Round Robin. */
static void fq_robin_add_tail(struct fq_flow_head *head,
			      struct fq_flow *flow)
{
	if (head->first)
		head->last->next = flow;
	else
		head->first = flow;
	head->last = flow;
	flow->next = NULL;
}

static inline struct sk_buff *fq_peek_skb(struct fq_flow *flow)
{
	struct sk_buff *head = flow->head;

	return head;
}

/* Add one skb to the flow queue. */
static inline void fq_enqueue_skb(struct Qdisc *	sch,
				  struct fq_flow *	flow,
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
static inline void fq_dequeue_skb(struct Qdisc *	sch,
				  struct fq_flow *	flow,
				  struct sk_buff *	skb)
{
	flow->head = skb->next;
	skb_mark_not_on_list(skb);

	flow->qlen--;
	qdisc_qstats_backlog_dec(sch, skb);
	sch->q.qlen--;
}

/* QDisc add a new packet to our queue - tail of queue. */
static int fq_qdisc_enqueue(struct sk_buff *	skb,
			    struct Qdisc *	sch,
			    struct sk_buff **	to_free)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct fq_flow *flow_cur;

	if (unlikely(sch->q.qlen >= sch->limit)) {
		qdisc_qstats_overlimit(sch);
		return qdisc_drop(skb, sch, to_free);
	}

	flow_cur = fq_classify(skb, q);
	if (flow_cur == NULL) {
		return qdisc_drop(skb, sch, to_free);
	}
	if (unlikely(flow_cur->qlen >= q->flow_plimit)) {
		q->stat_flows_plimit++;
		return qdisc_drop(skb, sch, to_free);
	}

	if (fq_flow_is_detached(flow_cur)) {
		fq_robin_add_tail(&q->new_flows, flow_cur);
		if (time_after(jiffies, flow_cur->age + q->flow_refill_delay))
			flow_cur->credit = max_t(u32,
						 flow_cur->credit,
						 q->quantum);
		q->inactive_flows--;
	}

	/* Note: this overwrites flow_cur->age */
	fq_enqueue_skb(sch, flow_cur, skb);

	return NET_XMIT_SUCCESS;
}

static struct sk_buff *fq_qdisc_dequeue(struct Qdisc *sch)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct fq_flow_head *head;
	struct sk_buff *skb;
	struct fq_flow *flow_cur;
	u32	plen;

	if (!sch->q.qlen)
		return NULL;

begin:
	head = &q->new_flows;
	if (!head->first) {
		head = &q->old_flows;
		if (!head->first) {
			printk_ratelimited(KERN_ERR "FQ: no flow to schedule !\n");
			return NULL;
		}
	}
	flow_cur = head->first;

	if (flow_cur->credit <= 0) {
		flow_cur->credit += q->quantum;
		head->first = flow_cur->next;
		fq_robin_add_tail(&q->old_flows, flow_cur);
#ifdef DRR_DEBUG_BURST_AVG
		/* If we are still on the same flow as the last packet,
		 * this count as normal scheduling, we just exhausted
		 * our quanta.
		 * If we are on a new flow, this is a wasted schedule.
		 * Jean II */
		if (flow_cur->flow_idx != q->flow_sched_prev)
			q->sched_empty++;
#endif	/* DRR_DEBUG_BURST_AVG */
		goto begin;
	}

	skb = fq_peek_skb(flow_cur);
	if (skb) {
		fq_dequeue_skb(sch, flow_cur, skb);
	} else {
		head->first = flow_cur->next;
		/* force a pass through old_flows to prevent starvation */
		if ((head == &q->new_flows) && q->old_flows.first) {
			fq_robin_add_tail(&q->old_flows, flow_cur);
		} else {
			fq_flow_set_detached(flow_cur);
			q->inactive_flows++;
		}
#ifdef DRR_DEBUG_BURST_AVG
		q->sched_empty++;
#endif	/* DRR_DEBUG_BURST_AVG */
		goto begin;
	}

	plen = qdisc_pkt_len(skb);
	flow_cur->credit -= plen;
#ifdef DRR_DEBUG_BURST_AVG
	/* Check if packet is part of the same burst.
	 * If there is only one active flow, burstiness does not make sense */
	if ( (flow_cur->flow_idx == q->flow_sched_prev)
	     && (q->flows - q->inactive_flows > 1) ) {
		/* Part of same burst, just add */
		q->burst_cur += qdisc_pkt_len(skb);
	} else {
		/* Add previous burst to average */
		if (q->burst_cur > q->burst_peak)
			q->burst_peak = q->burst_cur;
		if (q->burst_avg == 0)
			q->burst_avg = q->burst_cur;
		else
			q->burst_avg = ( ( q->burst_avg * 7
					   + q->burst_cur ) / 8 );
		/* Start new burst */
		q->burst_cur = qdisc_pkt_len(skb);
		q->flow_sched_prev = flow_cur->flow_idx;
	}
	q->sched_pkts++;
#endif	/* DRR_DEBUG_BURST_AVG */

	qdisc_bstats_update(sch, skb);
	return skb;
}

static struct sk_buff *fq_qdisc_basic_dequeue(struct Qdisc *sch)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct fq_flow_head *head;
	struct sk_buff *skb;
	struct fq_flow *flow_cur;
	u32	plen;

	if (!sch->q.qlen)
		return NULL;

begin:
	head = &q->new_flows;
	if (!head->first) {
		printk_ratelimited(KERN_ERR "FQ: no flow to schedule !\n");
		return NULL;
	}
	flow_cur = head->first;

	if (flow_cur->credit <= 0) {
		flow_cur->credit += q->quantum;
		head->first = flow_cur->next;
		/* In basic, we only use the new list. Jean II */
		fq_robin_add_tail(&q->new_flows, flow_cur);
#ifdef DRR_DEBUG_BURST_AVG
		/* If we are still on the same flow as the last packet,
		 * this count as normal scheduling, we just exhausted
		 * our quanta.
		 * If we are on a new flow, this is a wasted schedule.
		 * Jean II */
		if (flow_cur->flow_idx != q->flow_sched_prev)
			q->sched_empty++;
#endif	/* DRR_DEBUG_BURST_AVG */
		goto begin;
	}

	skb = fq_peek_skb(flow_cur);
	if (skb) {
		fq_dequeue_skb(sch, flow_cur, skb);
	} else {
		/* This is not supposed to happen, empty flows are supposed
		 * to always go inactive below. Jean II */
		printk_ratelimited(KERN_ERR "DRR: flow with no SKB !\n");
#ifdef DRR_DEBUG_BURST_AVG
		q->sched_empty++;
#endif	/* DRR_DEBUG_BURST_AVG */
		head->first = flow_cur->next;
		fq_flow_set_detached(flow_cur);
		q->inactive_flows++;
		goto begin;
	}
	/* Check if more packets after this one. Jean II */
	if (fq_peek_skb(flow_cur) == NULL) {
		/* If the sub-queue is now empty, that flow becomes inactive.
		 * It may be reactived in fq_qdisc_enqueue() and
		 * put back at the back of the list. Jean II */
		head->first = flow_cur->next;
		fq_flow_set_detached(flow_cur);
		q->inactive_flows++;
	}

	plen = qdisc_pkt_len(skb);
	flow_cur->credit -= plen;
#ifdef DRR_DEBUG_BURST_AVG
	/* Check if packet is part of the same burst.
	 * If there is only one active flow, burstiness does not make sense */
	if ( (flow_cur->flow_idx == q->flow_sched_prev)
	     && (q->flows - q->inactive_flows > 1) ) {
		/* Part of same burst, just add */
		q->burst_cur += qdisc_pkt_len(skb);
	} else {
		/* Add previous burst to average */
		if (q->burst_cur > q->burst_peak)
			q->burst_peak = q->burst_cur;
		if (q->burst_avg == 0)
			q->burst_avg = q->burst_cur;
		else
			q->burst_avg = ( ( q->burst_avg * 7
					   + q->burst_cur ) / 8 );
		/* Start new burst */
		q->burst_cur = qdisc_pkt_len(skb);
		q->flow_sched_prev = flow_cur->flow_idx;
	}
	q->sched_pkts++;
#endif	/* DRR_DEBUG_BURST_AVG */

	qdisc_bstats_update(sch, skb);
	return skb;
}

static void fq_rehash(struct fq_sched_data *q,
		      struct rb_root *old_array, u32 old_log,
		      struct rb_root *new_array, u32 new_log)
{
	struct rb_node *op, **np, *parent;
	struct rb_root *oroot, *nroot;
	struct fq_flow *of, *nf;
	int fcnt = 0;
	u32 idx;

	for (idx = 0; idx < (1U << old_log); idx++) {
		oroot = &old_array[idx];
		while ((op = rb_first(oroot)) != NULL) {
			rb_erase(op, oroot);
			of = rb_entry(op, struct fq_flow, hash_node);
			if (fq_gc_candidate(of)) {
				fcnt++;
				kmem_cache_free(fq_flow_cachep, of);
				continue;
			}
			nroot = &new_array[hash_32(of->flow_idx, new_log)];

			np = &nroot->rb_node;
			parent = NULL;
			while (*np) {
				parent = *np;

				nf = rb_entry(parent, struct fq_flow, hash_node);
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
	q->flows -= fcnt;
	q->inactive_flows -= fcnt;
	q->stat_gc_flows += fcnt;

#ifdef DRR_DEBUG_REHASH
	printk(KERN_DEBUG "DRR: flow rehash: %d flows\n", fcnt);
#endif	/* DRR_DEBUG_REHASH */
}

static void fq_hash_free(void *addr)
{
	kvfree(addr);
}

static int fq_hash_resize(struct Qdisc *sch, u32 log)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct rb_root *array;
	void *old_hash_root;
	u32 buckets;
	u32 idx;

	if (q->hash_root && log == q->hash_trees_log)
		return 0;

	buckets = 1U << log;

	/* If XPS was setup, we can allocate memory on right NUMA node */
	array = kvmalloc_node(sizeof(struct rb_root) * buckets, GFP_KERNEL | __GFP_RETRY_MAYFAIL,
			      netdev_queue_numa_node_read(sch->dev_queue));
	if (!array)
		return -ENOMEM;

	for (idx = 0; idx < buckets; idx++)
		array[idx] = RB_ROOT;

	sch_tree_lock(sch);

	old_hash_root = q->hash_root;
	if (old_hash_root)
		fq_rehash(q, old_hash_root, q->hash_trees_log, array, log);

	q->hash_root = array;
	q->hash_trees_log = log;
	q->hash_buckets = buckets;

	sch_tree_unlock(sch);

	fq_hash_free(old_hash_root);

	return 0;
}

static const struct nla_policy fq_policy[TCA_FQ_MAX + 1] = {
	[TCA_FQ_UNSPEC]			= { .strict_start_type = TCA_FQ_TIMER_SLACK },

	[TCA_FQ_PLIMIT]			= { .type = NLA_U32 },
	[TCA_FQ_FLOW_PLIMIT]		= { .type = NLA_U32 },
	[TCA_FQ_QUANTUM]		= { .type = NLA_U32 },
	[TCA_FQ_INITIAL_QUANTUM]	= { .type = NLA_U32 },
	[TCA_FQ_RATE_ENABLE]		= { .type = NLA_U32 },
	[TCA_FQ_FLOW_DEFAULT_RATE]	= { .type = NLA_U32 },
	[TCA_FQ_FLOW_MAX_RATE]		= { .type = NLA_U32 },
	[TCA_FQ_BUCKETS_LOG]		= { .type = NLA_U32 },
	[TCA_FQ_FLOW_REFILL_DELAY]	= { .type = NLA_U32 },
	[TCA_FQ_ORPHAN_MASK]		= { .type = NLA_U32 },
	[TCA_FQ_LOW_RATE_THRESHOLD]	= { .type = NLA_U32 },
	[TCA_FQ_CE_THRESHOLD]		= { .type = NLA_U32 },
	[TCA_FQ_TIMER_SLACK]		= { .type = NLA_U32 },
	[TCA_FQ_HORIZON]		= { .type = NLA_U32 },
	[TCA_FQ_HORIZON_DROP]		= { .type = NLA_U8 },
};

static int fq_qdisc_change(struct Qdisc *sch,
			     struct nlattr *opt,
			     struct netlink_ext_ack *extack)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_FQ_MAX + 1];
	int err, drop_count = 0;
	unsigned drop_len = 0;
	u32 fq_log;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_FQ_MAX, opt, fq_policy,
					  NULL);
	if (err < 0)
		return err;

	sch_tree_lock(sch);

	fq_log = q->hash_trees_log;

	if (tb[TCA_FQ_BUCKETS_LOG]) {
		u32 nval = nla_get_u32(tb[TCA_FQ_BUCKETS_LOG]);

		if (nval >= 1 && nval <= ilog2(256*1024))
			fq_log = nval;
		else
			err = -EINVAL;
	}
	if (tb[TCA_FQ_PLIMIT])
		sch->limit = nla_get_u32(tb[TCA_FQ_PLIMIT]);

	if (tb[TCA_FQ_FLOW_PLIMIT])
		q->flow_plimit = nla_get_u32(tb[TCA_FQ_FLOW_PLIMIT]);

	if (tb[TCA_FQ_QUANTUM]) {
		u32 quantum = nla_get_u32(tb[TCA_FQ_QUANTUM]);

		if (quantum > 0 && quantum <= (1 << 20)) {
			q->quantum = quantum;
		} else {
			NL_SET_ERR_MSG_MOD(extack, "invalid quantum");
			err = -EINVAL;
		}
	}

	if (tb[TCA_FQ_INITIAL_QUANTUM])
		q->initial_quantum = nla_get_u32(tb[TCA_FQ_INITIAL_QUANTUM]);

	if (tb[TCA_FQ_FLOW_REFILL_DELAY]) {
		u32 usecs_delay = nla_get_u32(tb[TCA_FQ_FLOW_REFILL_DELAY]) ;

		q->flow_refill_delay = usecs_to_jiffies(usecs_delay);
	}

	if (tb[TCA_FQ_ORPHAN_MASK])
		q->orphan_mask = nla_get_u32(tb[TCA_FQ_ORPHAN_MASK]);

	if (tb[TCA_FQ_CE_THRESHOLD])
		q->ce_threshold = (u64)NSEC_PER_USEC *
				  nla_get_u32(tb[TCA_FQ_CE_THRESHOLD]);

	if (!err) {

		sch_tree_unlock(sch);
		err = fq_hash_resize(sch, fq_log);
		sch_tree_lock(sch);
	}
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = fq_qdisc_dequeue(sch);

		if (!skb)
			break;
		drop_len += qdisc_pkt_len(skb);
		rtnl_kfree_skbs(skb, skb);
		drop_count++;
	}
	qdisc_tree_reduce_backlog(sch, drop_count, drop_len);

	sch_tree_unlock(sch);

#ifdef DRR_DEBUG_CONFIG
	printk(KERN_DEBUG "DRR: plimit %d; logs %d; mask 0x%X; flow_plimit %d; quantum %d\n", sch->limit, q->hash_trees_log, q->orphan_mask, q->flow_plimit, q->quantum);
#endif	/* DRR_DEBUG_CONFIG */

	return err;
}

static int fq_qdisc_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	u64 ce_threshold = q->ce_threshold;
	struct nlattr *opts;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	do_div(ce_threshold, NSEC_PER_USEC);

	if (nla_put_u32(skb, TCA_FQ_PLIMIT, sch->limit) ||
	    nla_put_u32(skb, TCA_FQ_FLOW_PLIMIT, q->flow_plimit) ||
	    nla_put_u32(skb, TCA_FQ_QUANTUM, q->quantum) ||
	    nla_put_u32(skb, TCA_FQ_INITIAL_QUANTUM, q->initial_quantum) ||
	    nla_put_u32(skb, TCA_FQ_FLOW_REFILL_DELAY,
			jiffies_to_usecs(q->flow_refill_delay)) ||
	    nla_put_u32(skb, TCA_FQ_ORPHAN_MASK, q->orphan_mask) ||
	    nla_put_u32(skb, TCA_FQ_CE_THRESHOLD, (u32)ce_threshold) ||
	    nla_put_u32(skb, TCA_FQ_BUCKETS_LOG, q->hash_trees_log))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int fq_qdisc_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct tc_fq_qd_stats st;

	st.gc_flows		  = q->stat_gc_flows;
#ifdef DRR_DEBUG_BURST_AVG
	st.highprio_packets	  = q->burst_avg;
	st.tcp_retrans		  = q->sched_empty;
	st.throttled		  = q->sched_pkts;
	st.pkts_too_long	  = q->burst_peak;
#else	/* DRR_DEBUG_BURST_AVG */
	st.highprio_packets	  = 0;
	st.tcp_retrans		  = 0;
	st.throttled		  = 0;
	st.pkts_too_long	  = 0;
#endif	/* DRR_DEBUG_BURST_AVG */
	st.flows_plimit		  = q->stat_flows_plimit;
	st.allocation_errors	  = q->stat_allocation_errors;
	st.time_next_delayed_flow = 0;
	st.flows		  = q->flows;
	st.inactive_flows	  = q->inactive_flows;
	st.throttled_flows	  = 0;
	st.unthrottle_latency_ns  = 0;
	st.ce_mark		  = q->stat_ce_mark;
	st.horizon_drops	  = 0;
	st.horizon_caps		  = 0;

	/* Reset some of the statistics */
	q->burst_peak = 0;

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static int fq_qdisc_init(struct Qdisc *sch,
			 struct nlattr *opt,
			 struct netlink_ext_ack *extack)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	int err;

#ifdef DRR_DEBUG_CONFIG
	printk(KERN_DEBUG "DRR: sizeof(fq_flow) %lu\n", sizeof(struct fq_flow));
#endif	/* DRR_DEBUG_CONFIG */

	sch->limit		= 10000;
	q->flow_plimit		= 100;
	q->quantum		= 2 * psched_mtu(qdisc_dev(sch));
	q->initial_quantum	= 10 * psched_mtu(qdisc_dev(sch));
	q->flow_refill_delay	= msecs_to_jiffies(40);
	q->new_flows.first	= NULL;
	q->old_flows.first	= NULL;
	q->hash_root		= NULL;
	q->hash_trees_log		= ilog2(1024);
	q->orphan_mask		= 1024 - 1;

	/* Default ce_threshold of 4294 seconds */
	q->ce_threshold		= (u64)NSEC_PER_USEC * ~0U;

	if (opt)
		err = fq_qdisc_change(sch, opt, extack);
	else
		err = fq_hash_resize(sch, q->hash_trees_log);

	return err;
}

static void fq_qdisc_reset(struct Qdisc *sch)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct rb_root *root;
	struct rb_node *p;
	struct fq_flow *flow_cur;
	unsigned int idx;

	sch->q.qlen = 0;
	sch->qstats.backlog = 0;

#ifdef DRR_DEBUG_BURST_AVG
	q->flow_sched_prev	= 0;
	q->burst_cur		= 0;
	q->burst_peak		= 0;
	q->burst_avg		= 0;
	q->sched_empty		= 0;
	q->sched_pkts		= 0;
#endif	/* DRR_DEBUG_BURST_AVG */

	q->new_flows.first	= NULL;
	q->old_flows.first	= NULL;
	q->flows		= 0;
	q->inactive_flows	= 0;

	if (!q->hash_root)
		return;

	for (idx = 0; idx < (1U << q->hash_trees_log); idx++) {
		root = &q->hash_root[idx];
		while ((p = rb_first(root)) != NULL) {
			flow_cur = rb_entry(p, struct fq_flow, hash_node);
			rb_erase(p, root);

			fq_flow_purge(flow_cur);

			kmem_cache_free(fq_flow_cachep, flow_cur);
		}
	}
}

static void fq_qdisc_destroy(struct Qdisc *sch)
{
	struct fq_sched_data *q = qdisc_priv(sch);

	fq_qdisc_reset(sch);
	fq_hash_free(q->hash_root);
}

static struct Qdisc_ops fq_qdisc_ops __read_mostly = {
	.id		=	"fq_drr",
	.priv_size	=	sizeof(struct fq_sched_data),

	.enqueue	=	fq_qdisc_enqueue,
	.dequeue	=	fq_qdisc_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	fq_qdisc_init,
	.reset		=	fq_qdisc_reset,
	.destroy	=	fq_qdisc_destroy,
	.change		=	fq_qdisc_change,
	.dump		=	fq_qdisc_dump,
	.dump_stats	=	fq_qdisc_dump_stats,
	.owner		=	THIS_MODULE,
};

static struct Qdisc_ops fq_basic_qdisc_ops __read_mostly = {
	.id		=	"fq_drr_basic",
	.priv_size	=	sizeof(struct fq_sched_data),

	.enqueue	=	fq_qdisc_enqueue,
	.dequeue	=	fq_qdisc_basic_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	fq_qdisc_init,
	.reset		=	fq_qdisc_reset,
	.destroy	=	fq_qdisc_destroy,
	.change		=	fq_qdisc_change,
	.dump		=	fq_qdisc_dump,
	.dump_stats	=	fq_qdisc_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init fq_module_init(void)
{
	int ret;

	fq_flow_cachep = kmem_cache_create("fq_flow_cache",
					   sizeof(struct fq_flow),
					   0, 0, NULL);
	if (!fq_flow_cachep)
		return -ENOMEM;

	ret = register_qdisc(&fq_qdisc_ops);
	if (!ret) {
		ret = register_qdisc(&fq_basic_qdisc_ops);
		if (ret)
			unregister_qdisc(&fq_qdisc_ops);
	}
	if (ret)
		kmem_cache_destroy(fq_flow_cachep);
	return ret;
}

static void __exit fq_module_exit(void)
{
	unregister_qdisc(&fq_basic_qdisc_ops);
	unregister_qdisc(&fq_qdisc_ops);
	kmem_cache_destroy(fq_flow_cachep);
}

module_init(fq_module_init)
module_exit(fq_module_exit)
MODULE_AUTHOR("Eric Dumazet");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Deficit Round Robin Packet Scheduler");
