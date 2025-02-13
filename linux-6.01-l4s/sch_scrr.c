// SPDX-License-Identifier: GPL-2.0-only
/*
 * net/sched/sch_scrr.c Self Clocked Round Robin Scheduler
 *
 *	Copyright 2023-2025 Hewlett Packard Enterprise Development LP.
 *	Author: Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 *
 * Self Clocked Round Robin (SCRR) is a packet scheduler trying to acheive
 * fairness between flows.
 *
 * It's pretty much a drop-in replacement for the very common
 * Deficit Round Robin (DRR) and has mostly the same properties :
 *	o Stochastic : flows are hashed, there may be collisions
 *	o Fairness : flows have the same bandwidth and latency
 *	o Burstiness : scheduling burst les than two max packet sizes
 *	o Efficient : computational complexity is O(1)
 *	o Only scheduling : should be combined with AQM or Tail-Drop
 * It has some big advantages over Deficit Round Robin :
 *	o No quantum - schedule advance adapts to packet sizes
 *	o Less CPU overhead for light flows (flow goes in-out schedule)
 *	o Lower latency for light flows - when using scrr-npme version
 *
 * SCRR is based on the concept of virtual time, which was introduced in
 * Self Clocked Fair Queuing (SCFQ), and improved in Start-Time Fair
 * queuing (STFQ). However, SCRR is not a true Fair Queuing scheduler.
 * Fair Queuing schedulers such as SCFQ and STFQ are more fair and
 * more complex (O(log(n)) than SCRR & DRR. SCRR uses the virtual clock of
 * STFQ, but schedule sub-queues in strict Round Robin. This gives it
 * lower CPU usage compared to true Fair Queuing scheduler.
 *
 * Note that the 'sch_fq' discipline in the Linux kernel currently
 * implements a Deficit Round Robin (DRR), and not any form of a true
 * Fair Queuing scheduler.
 *
 * ---------------------------------------------------------------- *
 *
 * Flow management (classification, lists, gc...) based on sch_fq.c :
 *  Copyright (C) 2013-2015 Eric Dumazet <edumazet@google.com>
 *
 *  Flows are dynamically allocated and stored in a hash table of RB trees
 *  They are also part of one Round Robin 'queues' (new or old flows)
 *
 *  enqueue() :
 *   - lookup one RB tree (out of 1024 or more) to find the flow.
 *     If non existent flow, create it, add it to the tree.
 *     Add skb to the per flow list of skb (fifo).
 *
 *  dequeue() : serves flows in Round Robin
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

//#define SCRR_DEBUG_CONFIG
//#define SCRR_DEBUG_FLOW_NEW
//#define SCRR_DEBUG_STFQ_ENQUEUE
//#define SCRR_DEBUG_STFQ_DEQUEUE
//#define SCRR_DEBUG_NOEMPTY_ENQUEUE
//#define SCRR_DEBUG_NOEMPTY_DEQUEUE
//#define SCRR_DEBUG_STATS_PEAK
#define SCRR_DEBUG_BURST_AVG

#define SCRR_PLIMIT_DEFLT		(10000)		/* packets */
#define SCRR_FLOW_PLIMIT_DEFLT		(100)		/* packets */
#define SCRR_HASH_NUM_DEFLT		(1024)		/* num tree roots */
#define SCRR_HASH_MASK_DEFLT		(1024 - 1)	/* bitmask */

enum {
	TCA_SCRR_UNSPEC,
	TCA_SCRR_PLIMIT,	/* limit of total number of packets in queue */
	TCA_SCRR_BUCKETS_LOG,	/* log2(number of buckets) */
	TCA_SCRR_HASH_MASK,	/* mask applied to skb hashes */
	TCA_SCRR_FLOW_PLIMIT,	/* limit of packets per flow */
	TCA_SCRR_FLAGS,		/* Options */
	__TCA_SCRR_MAX
};
#define TCA_SCRR_MAX	(__TCA_SCRR_MAX - 1)

/* TCA_SCRR_FLAGS */
#define SCF_PEAK_NORESET	0x0020	/* Don't reset peak statistics */

/* statistics gathering */
struct tc_scrr_xstats {
	__s32	flows;		/* number of flows */
	__s32	flows_inactive;	/* number of inactive flows */
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
struct scrr_flow {
	struct sk_buff	*head;		/* list of skbs for this flow : first skb */
	union {
		struct sk_buff *tail;	/* last skb in the list */
		unsigned long  age;	/* (jiffies | 1UL) when flow was emptied, for gc */
	};
	struct rb_node	hash_node;	/* anchor in hash_root[] trees */
	u64		virtual_finish;	/* Virtual of next incoming packet */
	u32		flow_idx;	/* Hash value for this flow */
	int		qlen;		/* number of packets in flow queue */

	struct scrr_flow *next;		/* next flow in RR lists */
} ____cacheline_aligned_in_smp;

/*
 * Container for list of flows. Round Robin will go through those lists.
 */
struct scrr_flow_head {
	struct scrr_flow *first;
	struct scrr_flow *last;
};

static struct kmem_cache *scrr_flow_cachep __read_mostly;

/*
 * Private data for the Qdisc
 */
struct scrr_sched_data {
	/* Configuration */
	u32		hash_mask;	/* mask for orphaned skb */
	u8		hash_trees_log;	/* log(number buckets) */
	u32		flow_plimit;	/* max packets per flow */
	u32		flags;		/* Bitmask of AIFF_XXX flags */

	/* Classifier */
	struct rb_root	*hash_root;	/* Hash of tree roots */
	u32		hash_buckets;

	/* Stats and instrumentation */
	struct tc_scrr_xstats  stats;
#ifdef SCRR_DEBUG_BURST_AVG
	u32		flow_sched_prev;	/* Previously active flow */
	u32		burst_cur;	/* Current burst size */
#endif	/* SCRR_DEBUG_BURST_AVG */

	/* Scheduler */
	struct scrr_flow_head new_flows;  /* Newly scheduled flows */
	struct scrr_flow_head old_flows;  /* Regular active flows */
	s32		rounds_advance;	  /* Until update virtual_advance */
	u64		virtual_dequeue;  /* Virtual of last dequeue */
	u64		virtual_advance;  /* Virtual where flows advance */
	u64		virtual_previous; /* Virtual of previous cycle */
};

/*
 * Packet Metadata
 */
struct scrr_skb_cb {
	u64	virtual_start;		/* Virtual start-time of packet */
};

static inline struct scrr_skb_cb *scrr_skb_cb(struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct scrr_skb_cb));
	return (struct scrr_skb_cb *)qdisc_skb_cb(skb)->data;
}

/*
 * flow->tail and flow->age share the same location.
 * We can use the low order bit to differentiate if this location points
 * to a sk_buff or contains a jiffies value, if we force this value to be odd.
 * This assumes flow->tail low order bit must be 0 since
 * alignof(struct sk_buff) >= 2
 */
static void scrr_flow_set_detached(struct scrr_flow *flow)
{
	flow->age = jiffies | 1UL;
}

static bool scrr_flow_is_detached(const struct scrr_flow *flow)
{
	return !!(flow->age & 1UL);
}

static inline struct scrr_flow *scrr_create_flow(struct scrr_sched_data *q,
						 uint32_t flow_idx)
{
	struct scrr_flow *flow_new;

	flow_new = kmem_cache_zalloc(scrr_flow_cachep, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(flow_new == NULL)) {
		q->stats.alloc_errors++;
		return NULL;
	}

	scrr_flow_set_detached(flow_new);
	flow_new->flow_idx = flow_idx;

	/* Initialise virtual time of the flow.
	 * Make sure it is before the current scheduling round. */
	flow_new->virtual_finish = q->virtual_previous;

	q->stats.flows++;
	q->stats.flows_inactive++;

	return flow_new;
}

static inline void scrr_flow_purge(struct scrr_flow *flow)
{
	rtnl_kfree_skbs(flow->head, flow->tail);
	flow->head = NULL;
	flow->qlen = 0;
}

/* limit number of collected flows per round */
#define SCRR_GC_MAX 8
#define SCRR_GC_AGE (3*HZ)

static bool scrr_gc_candidate(const struct scrr_flow *f)
{
	return scrr_flow_is_detached(f) &&
	       time_after(jiffies, f->age + SCRR_GC_AGE);
}

static void scrr_gc(struct scrr_sched_data *q,
		    struct rb_root *	root,
		    uint32_t		flow_idx)
{
	struct rb_node **p, *parent;
	void *tofree[SCRR_GC_MAX];
	struct scrr_flow *f;
	int i, fcnt = 0;

	p = &root->rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		f = rb_entry(parent, struct scrr_flow, hash_node);
		if (f->flow_idx == flow_idx)
			break;

		if (scrr_gc_candidate(f)) {
			tofree[fcnt++] = f;
			if (fcnt == SCRR_GC_MAX)
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
		/* No need to call scrr_flow_purge(), flow was idle */
	}
	q->stats.flows -= fcnt;
	q->stats.flows_inactive -= fcnt;
	q->stats.flows_gc += fcnt;

	kmem_cache_free_bulk(scrr_flow_cachep, fcnt, tofree);
}

static struct scrr_flow *scrr_classify(struct sk_buff *skb,
				       struct scrr_sched_data *q)
{
	struct rb_node **	p;
	struct rb_node *	parent;
	uint32_t		flow_idx;
	struct rb_root *	root;
	struct scrr_flow *	flow_cur;

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
		scrr_gc(q, root, flow_idx);

	/* Find flow in that specific tree */
	p = &root->rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		flow_cur = rb_entry(parent, struct scrr_flow, hash_node);
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
	flow_cur = scrr_create_flow(q, flow_idx);
	if (unlikely(flow_cur == NULL)) {
		return NULL;
	}

	/* Insert new flow into classifer */
	rb_link_node(&flow_cur->hash_node, parent, p);
	rb_insert_color(&flow_cur->hash_node, root);

#ifdef SCRR_DEBUG_FLOW_NEW
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
			printk(KERN_DEBUG "SCRR: flow new: idx:%d, src_addr:%d, dst_addr:%d, src_port:%d, dst_port:%d\n", flow_idx, ntohl(ih->saddr), ntohl(ih->daddr), ntohs(src_port), ntohs(dest_port));
		} else {
			printk(KERN_DEBUG "SCRR: flow new: idx:%d\n", flow_idx);
		}
	}
#endif	/* SCRR_DEBUG_FLOW_NEW */

	return flow_cur;
}

/* Add a flow at the end of the list used by Round Robin. */
static void scrr_robin_add_tail(struct scrr_flow_head *head,
				struct scrr_flow *flow)
{
	if (head->first)
		head->last->next = flow;
	else
		head->first = flow;
	head->last = flow;
	flow->next = NULL;
}

static inline struct sk_buff *scrr_peek_skb(struct scrr_flow *flow)
{
	struct sk_buff *head = flow->head;

	return head;
}

/* Add one skb to the flow queue. */
static inline void scrr_enqueue_skb(struct Qdisc *	sch,
				    struct scrr_flow *	flow,
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
static inline struct sk_buff *scrr_dequeue_skb(struct Qdisc *	sch,
					       struct scrr_flow *	flow)
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

/* QDisc add a new packet to our queue - tail of queue.
 * Basic version of SCRR, no enhancements. */
static int scrr_qdisc_enqueue(struct sk_buff *	skb,
			      struct Qdisc *	sch,
			      struct sk_buff **	to_free)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	struct scrr_flow *	flow_cur;
	u64			virtual_pkt;

	/* Tail-drop when queue is full - pfifo style limit */
	if (unlikely(sch->q.qlen >= sch->limit)) {
		qdisc_qstats_overlimit(sch);
		return qdisc_drop(skb, sch, to_free);
	}

	/* Find or create flow for this packet. */
	flow_cur = scrr_classify(skb, q);
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

	/* Check if flow was inactive, i.e. not scheduled. */
	if (scrr_flow_is_detached(flow_cur)) {

		q->stats.flows_inactive--;

		/* Put inactive flow into list of new flows for
		 * immediate scheduling. Jean II */
		scrr_robin_add_tail(&q->new_flows, flow_cur);

		/* One more flow in the current round robin cycle */
		q->rounds_advance++;
	}

	/* STFQ : Get virtual time of the flow == start-time on this packet.
	 * Get the later of the finish-time of previous packet (flow was
	 * busy) and the current virtual time (flow was idle). Jean II */
	if ( time_after64(q->virtual_advance, flow_cur->virtual_finish) )
		virtual_pkt = q->virtual_advance;
	else
		virtual_pkt = flow_cur->virtual_finish;

	/* Save virtual time in packet to be used in dequeue */
	scrr_skb_cb(skb)->virtual_start = virtual_pkt;

	/* Update flow virtual time.
	 * STFQ : All flows have the same weight. Jean II */
	flow_cur->virtual_finish = virtual_pkt + qdisc_pkt_len(skb);

	/* Note: this overwrites flow_cur->age */
	scrr_enqueue_skb(sch, flow_cur, skb);

#ifdef SCRR_DEBUG_STFQ_ENQUEUE
	printk(KERN_DEBUG "SCRR: enqueue: idx:%d; vadv:%lld; vpkt:%lld; vfin:%lld\n", flow_cur->flow_idx, q->virtual_advance, virtual_pkt, flow_cur->virtual_finish);
#endif	/* SCRR_DEBUG_STFQ_ENQUEUE */

#ifdef SCRR_DEBUG_STATS_PEAK
	/* Keep track of peak statistics */
	if (sch->q.qlen >= q->stats.qlen_peak)
		q->stats.qlen_peak = sch->q.qlen;

	if ( (sch->qstats.backlog > q->stats.backlog_peak)
	     && (sch->qstats.backlog < 2147483648) )
		q->stats.backlog_peak = sch->qstats.backlog;
#endif	/* SCRR_DEBUG_STATS_PEAK */

	return NET_XMIT_SUCCESS;
}

/* Update virtual clock at the end of a scheduling round.
 * Helper to remove code duplication. Jean II */
static inline void scrr_try_virtual_advance(struct scrr_sched_data *q)
{
	/* Check if it is time to update the virtual advance.
	 * We update it only once for every complete schedule through
	 * the active flows to minimise advance and guarantee the
	 * smallest burst size. Jean II */
	if (q->rounds_advance <= 0) {
		/* Scheduling round is done, start a new round.
		 * Make sure to not override previous if there is no advance
		 * to not disable initial advance. Jean II */
		if (q->virtual_dequeue != q->virtual_advance) {
			q->virtual_previous = q->virtual_advance;
			q->virtual_advance = q->virtual_dequeue;
		}

		/* The number of active flows may change.
		 * The current number of active flows is exactly how
		 * many there are in the round robin list. The next
		 * cycle may take longer if new flows become active,
		 * but it can't be shorter. Jean II */
		q->rounds_advance = q->stats.flows - q->stats.flows_inactive;
	}

	/* We are only called upon schedule, so update remaining number of
	 * schedules in this round.
	 * This is initialised at zero, which is why we test before
	 * decrement. Jean II */
	q->rounds_advance--;
}

/* QDisc remove a packet from our queue - head of queue.
 * Basic version of SCRR, no enhancements. */
static struct sk_buff *scrr_qdisc_dequeue(struct Qdisc *sch)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	struct scrr_flow_head *	head;
	struct scrr_flow *	flow_cur;
	struct sk_buff *	skb;
	u64			virtual_pkt;
	u64			virtual_next;

	/* If all sub-queues are empty, nothing to schedule. */
	if (unlikely(sch->q.qlen == 0))
		return NULL;

retry_flow:
	/* If there are flows in the new list (rare), use that list. */
	head = &q->new_flows;
	if (likely(head->first == NULL)) {
		/* Default case : use list of currently active flows. */
		head = &q->old_flows;
		if (unlikely(head->first == NULL)) {
			printk_ratelimited(KERN_ERR "SCRR: no flow to schedule !\n");
			return NULL;
		}
	}
	/* Pick first flow of the list. The list is rotated as needed. */
	flow_cur = head->first;

	/* Always dequeue a packet. Or try. Jean II */
	skb = scrr_dequeue_skb(sch, flow_cur);

	if (skb == NULL) {
		/* If the sub-queue was empty, that flow becomes inactive.
		 * It may be reactived in scrr_qdisc_enqueue(). Jean II */

		/* Remove flow from head of current list,
		 * advance to next sub-queue. */
		head->first = flow_cur->next;

		/* Flow goes inactive */
		scrr_flow_set_detached(flow_cur);
		q->stats.flows_inactive++;

#ifdef SCRR_DEBUG_BURST_AVG
		q->stats.sched_empty++;
#endif	/* SCRR_DEBUG_BURST_AVG */

		/* Advance the global clock as needed, but after
		 * updating the number of flows. Jean II */
		scrr_try_virtual_advance(q);

		/* Pick another flow.
		 * This won't infinite loop because sch->q.qlen != 0
		 * and the list of flows will become empty. */
		goto retry_flow;
	}

	/* Qdisc stats accounting */
	qdisc_bstats_update(sch, skb);

#ifdef SCRR_DEBUG_BURST_AVG
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
#endif	/* SCRR_DEBUG_BURST_AVG */

	/* Get virtual tag of this packet. */
	virtual_pkt = scrr_skb_cb(skb)->virtual_start;
	/* Compute virtual tag of next packet in the sub-queue (if any).
	 * The finish time of the current packet is after virtual_dequeue. */
	virtual_next = virtual_pkt + qdisc_pkt_len(skb);

#ifdef SCRR_DEBUG_STFQ_DEQUEUE
	printk(KERN_DEBUG "SCRR: dequeue: idx:%d; vpkt:%lld; vnxt:%lld; vadv:%lld (%d); vdq:%lld; ql:%d\n", flow_cur->flow_idx, virtual_pkt, virtual_next, q->virtual_advance, q->rounds_advance, q->virtual_dequeue, sch->q.qlen);
#endif	/* SCRR_DEBUG_STFQ_DEQUEUE */

	/* Update virtual time - Check if queue is busy */
	if (sch->q.qlen == 0) {
		q->virtual_dequeue = virtual_pkt + qdisc_pkt_len(skb);
		q->virtual_previous = q->virtual_advance;
		q->virtual_advance = q->virtual_dequeue;
	} else {
		/* In SCRR, packets are dequeued out of order,
		 * so the virtual time of STFQ can not be tracked
		 * easily. We would need to find the smallest
		 * rank amongst all packets in the queue.
		 * Approximate by taking the time of this packet.
		 * But, prevent time going backwards. Jean II */
		if ( time_after64(virtual_pkt, q->virtual_dequeue) )
			q->virtual_dequeue = virtual_pkt;
	}

	/* SCRR: Self Clocked Round Robin Scheduling. Jean II */
	/* If the sub-queue does not have a next packet,
	 * or if the next packet of the sub-queue is after the
	 * current virtual-time, we need to schedule another
	 * sub-queue. Jean II */
	if ( (scrr_peek_skb(flow_cur) == NULL)
	     || ( time_after64(virtual_next, q->virtual_advance) ) ) {

		/* Advance the global clock as needed */
		scrr_try_virtual_advance(q);

		/* We could make the flows without packets inactive here.
		 * The problem is that it would increase the chance of
		 * starvation for the old flows, though that flow coming
		 * back to the new list. This would happen if a flow drips
		 * packets without accumulating them in the sub-queue.
		 * We could always place inactive flows at the back of the
		 * old list, however light flows would loose their place
		 * in the schedule, impacting fairness. Jean II */

		/* Remove flow from head of current list,
		 * advance to next sub-queue. */
		head->first = flow_cur->next;

		/* Add current flow at end of list of active flows */
		scrr_robin_add_tail(&q->old_flows, flow_cur);
	}
	/* Else : if the next packet is older than the current virtual-time,
	 * remain on the same sub-queue, so it will be scheduled.
	 * next time. Jean II */

	return skb;
}

/* QDisc add a new packet to our queue - tail of queue.
 * Version No Packet Metadata, previously called Self Contained */
static int scrr_qdisc_npm_enqueue(struct sk_buff *	skb,
				  struct Qdisc *	sch,
				  struct sk_buff **	to_free)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	struct scrr_flow *	flow_cur;

	/* Tail-drop when queue is full - pfifo style limit */
	if (unlikely(sch->q.qlen >= sch->limit)) {
		qdisc_qstats_overlimit(sch);
		return qdisc_drop(skb, sch, to_free);
	}

	/* Find or create flow for this packet. */
	flow_cur = scrr_classify(skb, q);
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

	/* Check if flow was inactive, i.e. not scheduled. */
	if (scrr_flow_is_detached(flow_cur)) {

		q->stats.flows_inactive--;

		/* Put inactive flow into list of new flows for
		 * immediate scheduling. Jean II */
		scrr_robin_add_tail(&q->new_flows, flow_cur);

		/* One more flow in the current round robin cycle */
		q->rounds_advance++;
	}

	/* Note: this overwrites flow_cur->age */
	scrr_enqueue_skb(sch, flow_cur, skb);

#ifdef SCRR_DEBUG_STFQ_ENQUEUE
	printk(KERN_DEBUG "SCRR: enqueue: idx:%d; vadv:%lld; vpv:%lld; vfin:%lld\n", flow_cur->flow_idx, q->virtual_advance, q->virtual_previous, flow_cur->virtual_finish);
#endif	/* SCRR_DEBUG_STFQ_ENQUEUE */

#ifdef SCRR_DEBUG_STATS_PEAK
	/* Keep track of peak statistics */
	if (sch->q.qlen >= q->stats.qlen_peak)
		q->stats.qlen_peak = sch->q.qlen;

	if ( (sch->qstats.backlog > q->stats.backlog_peak)
	     && (sch->qstats.backlog < 2147483648) )
		q->stats.backlog_peak = sch->qstats.backlog;
#endif	/* SCRR_DEBUG_STATS_PEAK */

	return NET_XMIT_SUCCESS;
}

/* QDisc remove a packet from our queue - head of queue.
 * Version No Packet Metadata, previously called Self Contained */
static struct sk_buff *scrr_qdisc_npm_dequeue(struct Qdisc *sch)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	struct scrr_flow_head *	head;
	struct scrr_flow *	flow_cur;
	struct sk_buff *	skb;
	u64			virtual_pkt;
	u64			virtual_next;

	/* If all sub-queues are empty, nothing to schedule. */
	if (unlikely(sch->q.qlen == 0))
		return NULL;

retry_flow:
	/* If there are flows in the new list (rare), use that list. */
	head = &q->new_flows;
	if (likely(head->first == NULL)) {
		/* Default case : use list of currently active flows. */
		head = &q->old_flows;
		if (unlikely(head->first == NULL)) {
			printk_ratelimited(KERN_ERR "SCRR: no flow to schedule !\n");
			return NULL;
		}
	}
	/* Pick first flow of the list. The list is rotated as needed. */
	flow_cur = head->first;

	/* Always dequeue a packet. Or try. Jean II */
	skb = scrr_dequeue_skb(sch, flow_cur);

	if (skb == NULL) {
		/* If the sub-queue was empty, that flow becomes inactive.
		 * It may be reactived in scrr_qdisc_enqueue(). Jean II */

		/* Remove flow from head of current list,
		 * advance to next sub-queue. */
		head->first = flow_cur->next;

		/* Flow goes inactive */
		scrr_flow_set_detached(flow_cur);
		q->stats.flows_inactive++;

#ifdef SCRR_DEBUG_BURST_AVG
		q->stats.sched_empty++;
#endif	/* SCRR_DEBUG_BURST_AVG */

		/* Advance the global clock as needed, but after
		 * updating the number of flows. Jean II */
		scrr_try_virtual_advance(q);

		/* Pick another flow.
		 * This won't infinite loop because sch->q.qlen != 0
		 * and the list of flows will become empty. */
		goto retry_flow;
	}

	/* Qdisc stats accounting */
	qdisc_bstats_update(sch, skb);

#ifdef SCRR_DEBUG_BURST_AVG
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
#endif	/* SCRR_DEBUG_BURST_AVG */

	/* Figure out the virtual time of the packet. */
	/* STFQ : Get virtual time of the flow == start-time on this packet.
	 * Get the later of the finish-time of previous packet (flow was
	 * busy) and the current virtual time (flow was idle). Jean II */
	/* For the self contained version, we would need to compare to
	 * virtual_dequeue as it was when the flow was enqueued. Instead,
	 * we compare it to the virtual_advance of the previous cycle
	 * through the queues. It means that the sub-queue had no packet
	 * sent in the previous schedule, i.e. it was idle. Jean II */
	if ( time_after_eq64(q->virtual_previous, flow_cur->virtual_finish) )
		/* We don't have the exact time at enqueue, good enough. Jean */
		virtual_pkt = q->virtual_advance;
	else
		virtual_pkt = flow_cur->virtual_finish;

	/* Compute virtual tag of next packet in the sub-queue (if any).
	 * The finish time of the current packet is after virtual_dequeue. */
	virtual_next = virtual_pkt + qdisc_pkt_len(skb);

	/* Update flow virtual time.
	 * STFQ : All flows have the same weight. Jean II */
	flow_cur->virtual_finish = virtual_next;

#ifdef SCRR_DEBUG_STFQ_DEQUEUE
	printk(KERN_DEBUG "SCRR: dequeue: idx:%d; vpkt:%lld; vnxt:%lld; vadv:%lld (%d); vdq:%lld; ql:%d\n", flow_cur->flow_idx, virtual_pkt, virtual_next, q->virtual_advance, q->rounds_advance, q->virtual_dequeue, sch->q.qlen);
#endif	/* SCRR_DEBUG_STFQ_DEQUEUE */

	/* Update virtual time - Check if queue is busy */
	if (sch->q.qlen == 0) {
		q->virtual_dequeue = virtual_next;
		q->virtual_previous = q->virtual_advance;
		q->virtual_advance = q->virtual_dequeue;
	} else {
		/* In SCRR, packets are dequeued out of order,
		 * so the virtual time of STFQ can not be tracked
		 * easily. We would need to find the smallest
		 * rank amongst all packets in the queue.
		 * Approximate by taking the time of this packet.
		 * But, prevent time going backwards. Jean II */
		if ( time_after64(virtual_pkt, q->virtual_dequeue) )
			q->virtual_dequeue = virtual_pkt;
	}

	/* SCRR: Self Clocked Round Robin Scheduling. Jean II */
	/* If the sub-queue does not have a next packet,
	 * or if the next packet of the sub-queue is after the
	 * current virtual-time, we need to schedule another
	 * sub-queue. Jean II */
	if ( (scrr_peek_skb(flow_cur) == NULL)
	     || ( time_after64(virtual_next, q->virtual_advance) ) ) {

		/* Advance the global clock as needed */
		scrr_try_virtual_advance(q);

		/* We could make the flows without packets inactive here.
		 * The problem is that it would increase the chance of
		 * starvation for the old flows, though that flow coming
		 * back to the new list. This would happen if a flow drips
		 * packets without accumulating them in the sub-queue.
		 * We could always place inactive flows at the back of the
		 * old list, however light flows would loose their place
		 * in the schedule, impacting fairness. Jean II */

		/* Remove flow from head of current list,
		 * advance to next sub-queue. */
		head->first = flow_cur->next;

		/* Add current flow at end of list of active flows */
		scrr_robin_add_tail(&q->old_flows, flow_cur);
	}
	/* Else : if the next packet is older than the current virtual-time,
	 * remain on the same sub-queue, so it will be scheduled.
	 * next time. Jean II */

	return skb;
}

/* QDisc remove a packet from our queue - head of queue.
 * Version No Packet Metadata + Initial Advance */
static struct sk_buff *scrr_qdisc_nmia_dequeue(struct Qdisc *sch)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	struct scrr_flow_head *	head;
	struct scrr_flow *	flow_cur;
	struct sk_buff *	skb;
	u64			virtual_pkt;
	u64			virtual_next;

	/* If all sub-queues are empty, nothing to schedule. */
	if (unlikely(sch->q.qlen == 0))
		return NULL;

retry_flow:
	/* If there are flows in the new list (rare), use that list. */
	head = &q->new_flows;
	if (likely(head->first == NULL)) {
		/* Default case : use list of currently active flows. */
		head = &q->old_flows;
		if (unlikely(head->first == NULL)) {
			printk_ratelimited(KERN_ERR "SCRR: no flow to schedule !\n");
			return NULL;
		}
	}
	/* Pick first flow of the list. The list is rotated as needed. */
	flow_cur = head->first;

	/* Always dequeue a packet. Or try. Jean II */
	skb = scrr_dequeue_skb(sch, flow_cur);

	if (skb == NULL) {
		/* If the sub-queue was empty, that flow becomes inactive.
		 * It may be reactived in scrr_qdisc_enqueue(). Jean II */

		/* Remove flow from head of current list,
		 * advance to next sub-queue. */
		head->first = flow_cur->next;

		/* Flow goes inactive */
		scrr_flow_set_detached(flow_cur);
		q->stats.flows_inactive++;

#ifdef SCRR_DEBUG_BURST_AVG
		q->stats.sched_empty++;
#endif	/* SCRR_DEBUG_BURST_AVG */

		/* Advance the global clock as needed, but after
		 * updating the number of flows. Jean II */
		scrr_try_virtual_advance(q);

		/* Pick another flow.
		 * This won't infinite loop because sch->q.qlen != 0
		 * and the list of flows will become empty. */
		goto retry_flow;
	}

	/* Qdisc stats accounting */
	qdisc_bstats_update(sch, skb);

#ifdef SCRR_DEBUG_BURST_AVG
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
#endif	/* SCRR_DEBUG_BURST_AVG */

	/* Figure out the virtual time of the packet. */
	/* STFQ : Get virtual time of the flow == start-time on this packet.
	 * Get the later of the finish-time of previous packet (flow was
	 * busy) and the current virtual time (flow was idle). Jean II */
	/* For the No Packet Metadata version, we would need to compare to
	 * virtual_dequeue as it was when the flow was enqueued. Instead,
	 * we compare it to the virtual_advance of the previous cycle
	 * through the queues. It means that the sub-queue had no packet
	 * sent in the previous schedule, i.e. it was idle. Jean II */
	if ( time_after_eq64(q->virtual_previous, flow_cur->virtual_finish) )
		/* We don't have the exact time at enqueue.
		 * Try to give this new flow a full "quanta" at this round.
		 * The maximum advance is equal to the maximum packet size.
		 * We want the maximum burst for this new flow to be less
		 * than twice the max packet size, so we can only go back
		 * one advance minus 1 byte (as we can send 1 packet beyond
		 * the current advance). Deduct the current packet from the
		 * "quanta" to minimise average burstiness. Jean II */
		virtual_pkt = q->virtual_previous + qdisc_pkt_len(skb);
	else
		virtual_pkt = flow_cur->virtual_finish;

	/* Compute virtual tag of next packet in the sub-queue (if any).
	 * The finish time of the current packet is after virtual_dequeue. */
	virtual_next = virtual_pkt + qdisc_pkt_len(skb);

	/* Update flow virtual time.
	 * STFQ : All flows have the same weight. Jean II */
	flow_cur->virtual_finish = virtual_next;

#ifdef SCRR_DEBUG_STFQ_DEQUEUE
	printk(KERN_DEBUG "SCRR: dequeue: idx:%d; vpkt:%lld; vnxt:%lld; vadv:%lld (%d); vdq:%lld; ql:%d\n", flow_cur->flow_idx, virtual_pkt, virtual_next, q->virtual_advance, q->rounds_advance, q->virtual_dequeue, sch->q.qlen);
#endif	/* SCRR_DEBUG_STFQ_DEQUEUE */

	/* Update virtual time - Check if queue is busy */
	if (sch->q.qlen == 0) {
		q->virtual_dequeue = virtual_next;
		q->virtual_previous = q->virtual_advance;
		q->virtual_advance = q->virtual_dequeue;
	} else {
		/* In SCRR, packets are dequeued out of order,
		 * so the virtual time of STFQ can not be tracked
		 * easily. We would need to find the smallest
		 * rank amongst all packets in the queue.
		 * Approximate by taking the time of this packet.
		 * But, prevent time going backwards. Jean II */
		if ( time_after64(virtual_pkt, q->virtual_dequeue) )
			q->virtual_dequeue = virtual_pkt;
	}

	/* SCRR: Self Clocked Round Robin Scheduling. Jean II */
	/* If the sub-queue does not have a next packet,
	 * or if the next packet of the sub-queue is after the
	 * current virtual-time, we need to schedule another
	 * sub-queue. Jean II */
	if ( (scrr_peek_skb(flow_cur) == NULL)
	     || ( time_after64(virtual_next, q->virtual_advance) ) ) {

		/* Advance the global clock as needed */
		scrr_try_virtual_advance(q);

		/* We could make the flows without packets inactive here.
		 * The problem is that it would increase the chance of
		 * starvation for the old flows, though that flow coming
		 * back to the new list. This would happen if a flow drips
		 * packets without accumulating them in the sub-queue.
		 * We could always place inactive flows at the back of the
		 * old list, however light flows would loose their place
		 * in the schedule, impacting fairness. Jean II */

		/* Remove flow from head of current list,
		 * advance to next sub-queue. */
		head->first = flow_cur->next;

		/* Add current flow at end of list of active flows */
		scrr_robin_add_tail(&q->old_flows, flow_cur);
	}
	/* Else : if the next packet is older than the current virtual-time,
	 * remain on the same sub-queue, so it will be scheduled.
	 * next time. Jean II */

	return skb;
}

/* QDisc add a new packet to our queue - tail of queue.
 * Version No Packet Metadata + No Empty */
static int scrr_qdisc_nmne_enqueue(struct sk_buff *	skb,
				   struct Qdisc *	sch,
				   struct sk_buff **	to_free)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	struct scrr_flow *	flow_cur;

	/* Tail-drop when queue is full - pfifo style limit */
	if (unlikely(sch->q.qlen >= sch->limit)) {
		qdisc_qstats_overlimit(sch);
		return qdisc_drop(skb, sch, to_free);
	}

	/* Find or create flow for this packet. */
	flow_cur = scrr_classify(skb, q);
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

	/* Check if flow was inactive, i.e. not scheduled. */
	if (scrr_flow_is_detached(flow_cur)) {
		u32	flows_active = q->stats.flows - q->stats.flows_inactive;

		q->stats.flows_inactive--;

		/* Check how long that flow was inactive.
		 * We assume that the flow could have been active in
		 * the current scheduling round. So, the only way that
		 * flow could fit in the round is if the new packet
		 * can fit in the current round. In that case, we can
		 * schedule it in this round via the new list.
		 * If the scheduler was empty, the flow must go in
		 * the current round (a new round). Jean II */
		if ( ( time_after64(flow_cur->virtual_finish,
				    q->virtual_advance) )
		     && ( flows_active != 0 ) ) {
#ifdef SCRR_DEBUG_NOEMPTY_ENQUEUE
			printk(KERN_DEBUG "SCRR: flow add old: idx:%d; vfin:%lld; vadv:%lld (%d)\n", flow_cur->flow_idx, flow_cur->virtual_finish, q->virtual_advance, q->rounds_advance);
#endif	/* SCRR_DEBUG_NOEMPTY_ENQUEUE */

			/* That inactive flow was recently used, in the
			 * current scheduling round. Add it at end of
			 * the list of active flows. It will be scheduled
			 * in the next scheduling round. Jean II */
			scrr_robin_add_tail(&q->old_flows, flow_cur);

			/* We don't increase the number of flows in the
			 * current round robin cycle to make sure
			 * this flow in part of the next cycle. Jean II */
		} else {
#ifdef SCRR_DEBUG_NOEMPTY_ENQUEUE
			printk(KERN_DEBUG "SCRR: flow add new: idx:%d; vfin:%lld; vadv:%lld (%d)\n", flow_cur->flow_idx, flow_cur->virtual_finish, q->virtual_advance, q->rounds_advance);
#endif	/* SCRR_DEBUG_NOEMPTY_ENQUEUE */

			/* That inactive flow is old. Put it flow into list
			 * of new flows for immediate scheduling. Jean II */
			scrr_robin_add_tail(&q->new_flows, flow_cur);

			/* One more flow in the current round robin cycle */
			q->rounds_advance++;
		}
	}

	/* Note: this overwrites flow_cur->age */
	scrr_enqueue_skb(sch, flow_cur, skb);

#ifdef SCRR_DEBUG_STFQ_ENQUEUE
	printk(KERN_DEBUG "SCRR: enqueue: idx:%d; vadv:%lld; vpv:%lld; vfin:%lld\n", flow_cur->flow_idx, q->virtual_advance, q->virtual_previous, flow_cur->virtual_finish);
#endif	/* SCRR_DEBUG_STFQ_ENQUEUE */

#ifdef SCRR_DEBUG_STATS_PEAK
	/* Keep track of peak statistics */
	if (sch->q.qlen >= q->stats.qlen_peak)
		q->stats.qlen_peak = sch->q.qlen;

	if ( (sch->qstats.backlog > q->stats.backlog_peak)
	     && (sch->qstats.backlog < 2147483648) )
		q->stats.backlog_peak = sch->qstats.backlog;
#endif	/* SCRR_DEBUG_STATS_PEAK */

	return NET_XMIT_SUCCESS;
}

/* QDisc remove a packet from our queue - head of queue.
 * Version No Packet Metadata + No Empty */
static struct sk_buff *scrr_qdisc_nmne_dequeue(struct Qdisc *sch)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	struct scrr_flow_head *	head;
	struct scrr_flow *	flow_cur;
	struct sk_buff *	skb;
	u64			virtual_pkt;
	u64			virtual_next;

	/* If all sub-queues are empty, nothing to schedule. */
	if (unlikely(sch->q.qlen == 0))
		return NULL;

	/* If there are flows in the new list (rare), use that list. */
	head = &q->new_flows;
	if (likely(head->first == NULL)) {
		/* Default case : use list of currently active flows. */
		head = &q->old_flows;
		if (unlikely(head->first == NULL)) {
			printk_ratelimited(KERN_ERR "SCRR: no flow to schedule !\n");
			return NULL;
		}
	}
	/* Pick first flow of the list. The list is rotated as needed. */
	flow_cur = head->first;

	/* Always dequeue a packet. Or try. Jean II */
	skb = scrr_dequeue_skb(sch, flow_cur);

	if (unlikely(skb == NULL)) {
		/* This is not supposed to happen, empty flows are supposed
		 * to always go inactive below. Jean II */
		printk_ratelimited(KERN_ERR "SCRR: flow with no SKB !\n");

#ifdef SCRR_DEBUG_BURST_AVG
		q->stats.sched_empty++;
#endif	/* SCRR_DEBUG_BURST_AVG */

		/* Remove flow from head of current list,
		 * advance to next sub-queue, and bail out... */
		goto exit_empty;
	}

	/* Qdisc stats accounting */
	qdisc_bstats_update(sch, skb);

#ifdef SCRR_DEBUG_BURST_AVG
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
#endif	/* SCRR_DEBUG_BURST_AVG */

	/* Figure out the virtual time of the packet. */
	/* STFQ : Get virtual time of the flow == start-time on this packet.
	 * Get the later of the finish-time of previous packet (flow was
	 * busy) and the current virtual time (flow was idle). Jean II */
	/* For the No Packet Metadata version, we would need to compare to
	 * virtual_dequeue as it was when the flow was enqueued. Instead,
	 * we compare it to the virtual_advance of the previous cycle
	 * through the queues. It means that the sub-queue had no packet
	 * sent in the previous schedule, i.e. it was idle. Jean II */
	if ( time_after_eq64(q->virtual_previous, flow_cur->virtual_finish) )
		/* We don't have the exact time at enqueue, good enough. Jean */
		virtual_pkt = q->virtual_advance;
	else
		virtual_pkt = flow_cur->virtual_finish;

	/* Compute virtual tag of next packet in the sub-queue (if any).
	 * The finish time of the current packet is after virtual_dequeue. */
	virtual_next = virtual_pkt + qdisc_pkt_len(skb);

	/* Update flow virtual time.
	 * STFQ : All flows have the same weight. Jean II */
	flow_cur->virtual_finish = virtual_next;

#ifdef SCRR_DEBUG_STFQ_DEQUEUE
	printk(KERN_DEBUG "SCRR: dequeue: idx:%d; vpkt:%lld; vnxt:%lld; vadv:%lld (%d); vdq:%lld; vpv:%lld; ql:%d\n", flow_cur->flow_idx, virtual_pkt, virtual_next, q->virtual_advance, q->rounds_advance, q->virtual_dequeue, q->virtual_previous, sch->q.qlen);
#endif	/* SCRR_DEBUG_STFQ_DEQUEUE */

	/* Update virtual time - Check if queue is busy */
	if (unlikely(sch->q.qlen == 0)) {
		q->virtual_dequeue = virtual_next;
		q->virtual_previous = q->virtual_advance;
		q->virtual_advance = q->virtual_dequeue;
	} else {
		/* In SCRR, packets are dequeued out of order,
		 * so the virtual time of STFQ can not be tracked
		 * easily. We would need to find the smallest
		 * rank amongst all packets in the queue.
		 * Approximate by taking the time of this packet.
		 * But, prevent time going backwards. Jean II */
		if ( time_after64(virtual_pkt, q->virtual_dequeue) )
			q->virtual_dequeue = virtual_pkt;
	}

	/* skb may be NULL after this point. Jean II */

	/* SCRR: Self Clocked Round Robin Scheduling. Jean II */
	/* If the sub-queue does not have a next packet,
	 * or if the next packet of the sub-queue is after the
	 * current virtual-time, we need to schedule another
	 * sub-queue. Jean II */
	if (unlikely(scrr_peek_skb(flow_cur) == NULL)) {
		/* If the sub-queue is now empty, that flow becomes inactive.
		 * It may be reactived in scrr_qdisc_enqueue().
		 * In DRR and regular SCRR, we keep the queue in the
		 * round robin list to prevent starvation for the old
		 * flows, though that flow coming back to the new list.
		 * This would happen if a flow drips packets without
		 * accumulating them in the sub-queue.
		 * We prevent that from happening by checking the
		 * virtual clock of the flow before choosing to
		 * put it in the list of new or old flows. Jean II */

#ifdef SCRR_DEBUG_NOEMPTY_DEQUEUE
		printk(KERN_DEBUG "SCRR: dequeue empty: idx:%d; vpkt:%lld; vnxt:%lld; vadv:%lld (%d); vdq:%lld; vpv:%lld; ql:%d\n", flow_cur->flow_idx, virtual_pkt, virtual_next, q->virtual_advance, q->rounds_advance, q->virtual_dequeue, q->virtual_previous, sch->q.qlen);
#endif	/* SCRR_DEBUG_NOEMPTY_DEQUEUE */

exit_empty:
		/* Flow goes inactive */
		scrr_flow_set_detached(flow_cur);
		q->stats.flows_inactive++;

		/* Remove flow from head of current list,
		 * advance to next sub-queue. */
		head->first = flow_cur->next;

		/* Advance the global clock as needed, but after
		 * updating the number of flows. Jean II */
		goto exit_advance;

	} else if (likely( time_after64(virtual_next, q->virtual_advance) )) {

		/* If the next packet of the sub-queue is after the
		 * current virtual-time, it can't be sent in that 
		 * scheduling round. Jean II */

		/* Remove flow from head of current list,
		 * advance to next sub-queue. */
		head->first = flow_cur->next;

		/* Add current flow at end of the list of active flows */
		scrr_robin_add_tail(&q->old_flows, flow_cur);

exit_advance:
		/* Advance the global clock as needed */
		scrr_try_virtual_advance(q);

	}
	/* Else : if the next packet is older than the current virtual-time,
	 * remain on the same sub-queue, so it will be scheduled.
	 * next time in this scheduling round. Jean II */

	return skb;
}

/* QDisc remove a packet from our queue - head of queue.
 * Version No Packet Metadata + No Empty + Initial Advance */
static struct sk_buff *scrr_qdisc_neia_dequeue(struct Qdisc *sch)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	struct scrr_flow_head *	head;
	struct scrr_flow *	flow_cur;
	struct sk_buff *	skb;
	u64			virtual_pkt;
	u64			virtual_next;

	/* If all sub-queues are empty, nothing to schedule. */
	if (unlikely(sch->q.qlen == 0))
		return NULL;

	/* If there are flows in the new list (rare), use that list. */
	head = &q->new_flows;
	if (likely(head->first == NULL)) {
		/* Default case : use list of currently active flows. */
		head = &q->old_flows;
		if (unlikely(head->first == NULL)) {
			printk_ratelimited(KERN_ERR "SCRR: no flow to schedule !\n");
			return NULL;
		}
	}
	/* Pick first flow of the list. The list is rotated as needed. */
	flow_cur = head->first;

	/* Always dequeue a packet. Or try. Jean II */
	skb = scrr_dequeue_skb(sch, flow_cur);

	if (unlikely(skb == NULL)) {
		/* This is not supposed to happen, empty flows are supposed
		 * to always go inactive below. Jean II */
		printk_ratelimited(KERN_ERR "SCRR: flow with no SKB !\n");

#ifdef SCRR_DEBUG_BURST_AVG
		q->stats.sched_empty++;
#endif	/* SCRR_DEBUG_BURST_AVG */

		/* Remove flow from head of current list,
		 * advance to next sub-queue, and bail out... */
		goto exit_empty;
	}

	/* Qdisc stats accounting */
	qdisc_bstats_update(sch, skb);

#ifdef SCRR_DEBUG_BURST_AVG
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
#endif	/* SCRR_DEBUG_BURST_AVG */

	/* Figure out the virtual time of the packet. */
	/* STFQ : Get virtual time of the flow == start-time on this packet.
	 * Get the later of the finish-time of previous packet (flow was
	 * busy) and the current virtual time (flow was idle). Jean II */
	/* For the No Packet Metadata version, we would need to compare to
	 * virtual_dequeue as it was when the flow was enqueued. Instead,
	 * we compare it to the virtual_advance of the previous cycle
	 * through the queues. It means that the sub-queue had no packet
	 * sent in the previous schedule, i.e. it was idle. Jean II */
	if ( time_after_eq64(q->virtual_previous, flow_cur->virtual_finish) )
		/* We don't have the exact time at enqueue.
		 * Try to give this new flow a full "quanta" at this round.
		 * The maximum advance is equal to the maximum packet size.
		 * We want the maximum burst for this new flow to be less
		 * than twice the max packet size, so we can only go back
		 * one advance minus 1 byte (as we can send 1 packet beyond
		 * the current advance). Deduct the current packet from the
		 * "quanta" to minimise average burstiness. Jean II */
		virtual_pkt = q->virtual_previous + qdisc_pkt_len(skb);
	else
		virtual_pkt = flow_cur->virtual_finish;

	/* Compute virtual tag of next packet in the sub-queue (if any).
	 * The finish time of the current packet is after virtual_dequeue. */
	virtual_next = virtual_pkt + qdisc_pkt_len(skb);

	/* Update flow virtual time.
	 * STFQ : All flows have the same weight. Jean II */
	flow_cur->virtual_finish = virtual_next;

#ifdef SCRR_DEBUG_STFQ_DEQUEUE
	printk(KERN_DEBUG "SCRR: dequeue: idx:%d; vpkt:%lld; vnxt:%lld; vadv:%lld (%d); vdq:%lld; vpv:%lld; ql:%d\n", flow_cur->flow_idx, virtual_pkt, virtual_next, q->virtual_advance, q->rounds_advance, q->virtual_dequeue, q->virtual_previous, sch->q.qlen);
#endif	/* SCRR_DEBUG_STFQ_DEQUEUE */

	/* Update virtual time - Check if queue is busy */
	if (unlikely(sch->q.qlen == 0)) {
		q->virtual_dequeue = virtual_next;
		q->virtual_previous = q->virtual_advance;
		q->virtual_advance = q->virtual_dequeue;
	} else {
		/* In SCRR, packets are dequeued out of order,
		 * so the virtual time of STFQ can not be tracked
		 * easily. We would need to find the smallest
		 * rank amongst all packets in the queue.
		 * Approximate by taking the time of this packet.
		 * But, prevent time going backwards. Jean II */
		if ( time_after64(virtual_pkt, q->virtual_dequeue) )
			q->virtual_dequeue = virtual_pkt;
	}

	/* skb may be NULL after this point. Jean II */

	/* SCRR: Self Clocked Round Robin Scheduling. Jean II */
	/* If the sub-queue does not have a next packet,
	 * or if the next packet of the sub-queue is after the
	 * current virtual-time, we need to schedule another
	 * sub-queue. Jean II */
	if (unlikely(scrr_peek_skb(flow_cur) == NULL)) {
		/* If the sub-queue is now empty, that flow becomes inactive.
		 * It may be reactived in scrr_qdisc_enqueue().
		 * In DRR and regular SCRR, we keep the queue in the
		 * round robin list to prevent starvation for the old
		 * flows, though that flow coming back to the new list.
		 * This would happen if a flow drips packets without
		 * accumulating them in the sub-queue.
		 * We prevent that from happening by checking the
		 * virtual clock of the flow before choosing to
		 * put it in the list of new or old flows. Jean II */

#ifdef SCRR_DEBUG_NOEMPTY_DEQUEUE
		printk(KERN_DEBUG "SCRR: dequeue empty: idx:%d; vpkt:%lld; vnxt:%lld; vadv:%lld (%d); vdq:%lld; vpv:%lld; ql:%d\n", flow_cur->flow_idx, virtual_pkt, virtual_next, q->virtual_advance, q->rounds_advance, q->virtual_dequeue, q->virtual_previous, sch->q.qlen);
#endif	/* SCRR_DEBUG_NOEMPTY_DEQUEUE */

exit_empty:
		/* Flow goes inactive */
		scrr_flow_set_detached(flow_cur);
		q->stats.flows_inactive++;

		/* Remove flow from head of current list,
		 * advance to next sub-queue. */
		head->first = flow_cur->next;

		/* Advance the global clock as needed, but after
		 * updating the number of flows. Jean II */
		goto exit_advance;

	} else if (likely( time_after64(virtual_next, q->virtual_advance) )) {

		/* If the next packet of the sub-queue is after the
		 * current virtual-time, it can't be sent in that 
		 * scheduling round. Jean II */

		/* Remove flow from head of current list,
		 * advance to next sub-queue. */
		head->first = flow_cur->next;

		/* Add current flow at end of the list of active flows */
		scrr_robin_add_tail(&q->old_flows, flow_cur);

exit_advance:
		/* Advance the global clock as needed */
		scrr_try_virtual_advance(q);

	}
	/* Else : if the next packet is older than the current virtual-time,
	 * remain on the same sub-queue, so it will be scheduled.
	 * next time in this scheduling round. Jean II */

	return skb;
}

/* QDisc remove a packet from our queue - head of queue.
 * Basic version of SCRR, no enhancements. */
static struct sk_buff *scrr_qdisc_basic_dequeue(struct Qdisc *sch)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	struct scrr_flow_head *	head;
	struct scrr_flow *	flow_cur;
	struct sk_buff *	skb;
	u64			virtual_pkt;
	u64			virtual_next;

	/* If all sub-queues are empty, nothing to schedule. */
	if (unlikely(sch->q.qlen == 0))
		return NULL;

	/* Default case : use list of currently active flows. */
	head = &q->new_flows;
	if (unlikely(head->first == NULL)) {
		printk_ratelimited(KERN_ERR "SCRR: no flow to schedule !\n");
		return NULL;
	}
	/* Pick first flow of the list. The list is rotated as needed. */
	flow_cur = head->first;

	/* Always dequeue a packet. Or try. Jean II */
	skb = scrr_dequeue_skb(sch, flow_cur);

	if (unlikely(skb == NULL)) {
		/* This is not supposed to happen, empty flows are supposed
		 * to always go inactive below. Jean II */
		printk_ratelimited(KERN_ERR "SCRR: flow with no SKB !\n");

#ifdef SCRR_DEBUG_BURST_AVG
		q->stats.sched_empty++;
#endif	/* SCRR_DEBUG_BURST_AVG */

		/* Remove flow from head of current list,
		 * advance to next sub-queue, and bail out... */
		goto exit_empty;
	}

	/* Qdisc stats accounting */
	qdisc_bstats_update(sch, skb);

#ifdef SCRR_DEBUG_BURST_AVG
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
#endif	/* SCRR_DEBUG_BURST_AVG */

	/* Get virtual tag of this packet. */
	virtual_pkt = scrr_skb_cb(skb)->virtual_start;
	/* Compute virtual tag of next packet in the sub-queue (if any).
	 * The finish time of the current packet is after virtual_dequeue. */
	virtual_next = virtual_pkt + qdisc_pkt_len(skb);

#ifdef SCRR_DEBUG_STFQ_DEQUEUE
	printk(KERN_DEBUG "SCRR: dequeue: idx:%d; vpkt:%lld; vnxt:%lld; vadv:%lld (%d); vdq:%lld; ql:%d\n", flow_cur->flow_idx, virtual_pkt, virtual_next, q->virtual_advance, q->rounds_advance, q->virtual_dequeue, sch->q.qlen);
#endif	/* SCRR_DEBUG_STFQ_DEQUEUE */

	/* Update virtual time - Check if queue is busy */
	if (sch->q.qlen == 0) {
		q->virtual_dequeue = virtual_pkt + qdisc_pkt_len(skb);
		q->virtual_previous = q->virtual_advance;
		q->virtual_advance = q->virtual_dequeue;
	} else {
		/* In SCRR, packets are dequeued out of order,
		 * so the virtual time of STFQ can not be tracked
		 * easily. We would need to find the smallest
		 * rank amongst all packets in the queue.
		 * Approximate by taking the time of this packet.
		 * But, prevent time going backwards. Jean II */
		if ( time_after64(virtual_pkt, q->virtual_dequeue) )
			q->virtual_dequeue = virtual_pkt;
	}

	/* SCRR: Self Clocked Round Robin Scheduling. Jean II */
	/* If the sub-queue does not have a next packet,
	 * or if the next packet of the sub-queue is after the
	 * current virtual-time, we need to schedule another
	 * sub-queue. Jean II */
	if (unlikely(scrr_peek_skb(flow_cur) == NULL)) {
		/* If the sub-queue is now empty, that flow becomes inactive.
		 * It may be reactived in scrr_qdisc_enqueue() and
		 * put back at the back of the list. Jean II */

exit_empty:
		/* Flow goes inactive */
		scrr_flow_set_detached(flow_cur);
		q->stats.flows_inactive++;

		/* Remove flow from head of current list,
		 * advance to next sub-queue. */
		head->first = flow_cur->next;

		/* Advance the global clock as needed, but after
		 * updating the number of flows. Jean II */
		goto exit_advance;

	} else if (likely( time_after64(virtual_next, q->virtual_advance) )) {

		/* If the next packet of the sub-queue is after the
		 * current virtual-time, it can't be sent in that 
		 * scheduling round. Jean II */

		/* Remove flow from head of current list,
		 * advance to next sub-queue. */
		head->first = flow_cur->next;

		/* Add current flow at end of list of active flows */
		/* We only use the new list. Jean II */
		scrr_robin_add_tail(&q->new_flows, flow_cur);

exit_advance:
		/* Advance the global clock as needed */
		scrr_try_virtual_advance(q);

	}
	/* Else : if the next packet is older than the current virtual-time,
	 * remain on the same sub-queue, so it will be scheduled.
	 * next time. Jean II */

	return skb;
}

static void scrr_rehash(struct scrr_sched_data *q,
		      struct rb_root *old_array, u32 old_log,
		      struct rb_root *new_array, u32 new_log)
{
	struct rb_node *op, **np, *parent;
	struct rb_root *oroot, *nroot;
	struct scrr_flow *of, *nf;
	int fcnt = 0;
	u32 idx;

	for (idx = 0; idx < (1U << old_log); idx++) {
		oroot = &old_array[idx];
		while ((op = rb_first(oroot)) != NULL) {
			rb_erase(op, oroot);
			of = rb_entry(op, struct scrr_flow, hash_node);
			if (scrr_gc_candidate(of)) {
				fcnt++;
				kmem_cache_free(scrr_flow_cachep, of);
				continue;
			}
			nroot = &new_array[hash_32(of->flow_idx, new_log)];

			np = &nroot->rb_node;
			parent = NULL;
			while (*np) {
				parent = *np;

				nf = rb_entry(parent, struct scrr_flow, hash_node);
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

static void scrr_hash_free(void *addr)
{
	kvfree(addr);
}

static int scrr_hash_resize(struct Qdisc *sch, u32 log)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
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
		scrr_rehash(q, old_hash_root, q->hash_trees_log, array, log);

	q->hash_root = array;
	q->hash_trees_log = log;
	q->hash_buckets = buckets;

	sch_tree_unlock(sch);

	scrr_hash_free(old_hash_root);

	return 0;
}

static const struct nla_policy scrr_policy[TCA_SCRR_MAX + 1] = {
	[TCA_SCRR_PLIMIT]		= { .type = NLA_U32 },
	[TCA_SCRR_BUCKETS_LOG]		= { .type = NLA_U32 },
	[TCA_SCRR_HASH_MASK]		= { .type = NLA_U32 },
	[TCA_SCRR_FLOW_PLIMIT]		= { .type = NLA_U32 },
	[TCA_SCRR_FLAGS]		= { .type = NLA_U32 },
};

static int scrr_qdisc_change(struct Qdisc *sch,
			     struct nlattr *opt,
			     struct netlink_ext_ack *extack)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_SCRR_MAX + 1];
	u32		plimit;
	u32		hash_log_new;
	int		err;
	int		drop_count = 0;
	unsigned	drop_len = 0;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_SCRR_MAX, opt, scrr_policy,
					  NULL);
	if (err < 0)
		return err;

	/* Check limit before locking */
	if (tb[TCA_SCRR_PLIMIT]) {
		plimit = nla_get_u32(tb[TCA_SCRR_PLIMIT]);
		/* Can't be negative... */
		if (plimit == 0)
			return -EINVAL;
	}

	sch_tree_lock(sch);

	if (tb[TCA_SCRR_PLIMIT])
		sch->limit = plimit;

	hash_log_new = q->hash_trees_log;
	if (tb[TCA_SCRR_BUCKETS_LOG]) {
		u32 nval = nla_get_u32(tb[TCA_SCRR_BUCKETS_LOG]);

		if (nval >= 1 && nval <= ilog2(256*1024))
			hash_log_new = nval;
		else
			err = -EINVAL;
	}

	if (tb[TCA_SCRR_HASH_MASK])
		q->hash_mask = nla_get_u32(tb[TCA_SCRR_HASH_MASK]);

	if (tb[TCA_SCRR_FLOW_PLIMIT])
		q->flow_plimit = nla_get_u32(tb[TCA_SCRR_FLOW_PLIMIT]);

	if (tb[TCA_SCRR_FLAGS])
                q->flags = nla_get_u32(tb[TCA_SCRR_FLAGS]);

	if (!err) {

		sch_tree_unlock(sch);
		/* Only done if hash_log_new != q->hash_trees_log */
		err = scrr_hash_resize(sch, hash_log_new);
		sch_tree_lock(sch);
	}
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = scrr_qdisc_dequeue(sch);

		if (!skb)
			break;
		drop_len += qdisc_pkt_len(skb);
		rtnl_kfree_skbs(skb, skb);
		drop_count++;
	}
	qdisc_tree_reduce_backlog(sch, drop_count, drop_len);

	sch_tree_unlock(sch);

#ifdef SCRR_DEBUG_CONFIG
	printk(KERN_DEBUG "SCRR: plimit %d; logs %d; mask 0x%X; flow_plimit %d; flags 0x%X\n", sch->limit, q->hash_trees_log, q->hash_mask, q->flow_plimit, q->flags);
#endif	/* SCRR_DEBUG_CONFIG */

	return err;
}

static int scrr_qdisc_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	/* Standard queue limit */
	if (nla_put_u32(skb, TCA_SCRR_PLIMIT, sch->limit))
		goto nla_put_failure;

	/* Hashing attributes */
	if (nla_put_u32(skb, TCA_SCRR_BUCKETS_LOG, q->hash_trees_log))
		goto nla_put_failure;
	if (nla_put_u32(skb, TCA_SCRR_HASH_MASK, q->hash_mask))
		goto nla_put_failure;

	/* Other attributes */
	if (nla_put_u32(skb, TCA_SCRR_FLOW_PLIMIT, q->flow_plimit))
		goto nla_put_failure;
	if (nla_put_u32(skb, TCA_SCRR_FLAGS, q->flags))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int scrr_qdisc_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	struct tc_scrr_xstats st;

	memcpy(&st, &q->stats, sizeof(st));

	/* Reset some of the statistics, unless disabled */
	if ( ! (q->flags & SCF_PEAK_NORESET) ) {
		q->stats.qlen_peak = 0;
		q->stats.backlog_peak = 0;
		q->stats.burst_peak = 0;
	}

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static int scrr_qdisc_init(struct Qdisc *sch,
			   struct nlattr *opt,
			   struct netlink_ext_ack *extack)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	int err;

#ifdef SCRR_DEBUG_CONFIG
	printk(KERN_DEBUG "SCRR: sizeof(scrr_flow) %lu\n", sizeof(struct scrr_flow));
#endif	/* SCRR_DEBUG_CONFIG */

	/* Configuration */
	sch->limit		= SCRR_PLIMIT_DEFLT;
	q->flow_plimit		= SCRR_FLOW_PLIMIT_DEFLT;
	q->hash_mask		= SCRR_HASH_MASK_DEFLT;

	/* Parameters */
	q->hash_root		= NULL;
	q->hash_trees_log	= ilog2(SCRR_HASH_NUM_DEFLT);
	q->new_flows.first	= NULL;
	q->old_flows.first	= NULL;
	q->virtual_dequeue	= 0LL;
	q->virtual_advance	= 0LL;
	q->virtual_previous	= 0LL;
	q->rounds_advance	= -1;

	if (opt)
		err = scrr_qdisc_change(sch, opt, extack);
	else
		err = scrr_hash_resize(sch, q->hash_trees_log);

	return err;
}

static void scrr_qdisc_reset(struct Qdisc *sch)
{
	struct scrr_sched_data *q = qdisc_priv(sch);
	struct rb_root *root;
	struct rb_node *p;
	struct scrr_flow *flow_cur;
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

	q->new_flows.first	= NULL;
	q->old_flows.first	= NULL;

	if (!q->hash_root)
		return;

	for (idx = 0; idx < (1U << q->hash_trees_log); idx++) {
		root = &q->hash_root[idx];
		while ((p = rb_first(root)) != NULL) {
			flow_cur = rb_entry(p, struct scrr_flow, hash_node);
			rb_erase(p, root);

			scrr_flow_purge(flow_cur);

			kmem_cache_free(scrr_flow_cachep, flow_cur);
		}
	}
}

static void scrr_qdisc_destroy(struct Qdisc *sch)
{
	struct scrr_sched_data *q = qdisc_priv(sch);

	scrr_qdisc_reset(sch);
	scrr_hash_free(q->hash_root);
}

static struct Qdisc_ops scrr_qdisc_ops __read_mostly = {
	.id		=	"scrr",
	.priv_size	=	sizeof(struct scrr_sched_data),

	.enqueue	=	scrr_qdisc_enqueue,
	.dequeue	=	scrr_qdisc_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	scrr_qdisc_init,
	.reset		=	scrr_qdisc_reset,
	.destroy	=	scrr_qdisc_destroy,
	.change		=	scrr_qdisc_change,
	.dump		=	scrr_qdisc_dump,
	.dump_stats	=	scrr_qdisc_dump_stats,
	.owner		=	THIS_MODULE,
};

static struct Qdisc_ops scrr_npm_qdisc_ops __read_mostly = {
	.id		=	"scrr_npm",
	.priv_size	=	sizeof(struct scrr_sched_data),

	.enqueue	=	scrr_qdisc_npm_enqueue,
	.dequeue	=	scrr_qdisc_npm_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	scrr_qdisc_init,
	.reset		=	scrr_qdisc_reset,
	.destroy	=	scrr_qdisc_destroy,
	.change		=	scrr_qdisc_change,
	.dump		=	scrr_qdisc_dump,
	.dump_stats	=	scrr_qdisc_dump_stats,
	.owner		=	THIS_MODULE,
};

static struct Qdisc_ops scrr_nmia_qdisc_ops __read_mostly = {
	.id		=	"scrr_nmia",
	.priv_size	=	sizeof(struct scrr_sched_data),

	.enqueue	=	scrr_qdisc_npm_enqueue,
	.dequeue	=	scrr_qdisc_nmia_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	scrr_qdisc_init,
	.reset		=	scrr_qdisc_reset,
	.destroy	=	scrr_qdisc_destroy,
	.change		=	scrr_qdisc_change,
	.dump		=	scrr_qdisc_dump,
	.dump_stats	=	scrr_qdisc_dump_stats,
	.owner		=	THIS_MODULE,
};

static struct Qdisc_ops scrr_nmne_qdisc_ops __read_mostly = {
	.id		=	"scrr_nmne",
	.priv_size	=	sizeof(struct scrr_sched_data),

	.enqueue	=	scrr_qdisc_nmne_enqueue,
	.dequeue	=	scrr_qdisc_nmne_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	scrr_qdisc_init,
	.reset		=	scrr_qdisc_reset,
	.destroy	=	scrr_qdisc_destroy,
	.change		=	scrr_qdisc_change,
	.dump		=	scrr_qdisc_dump,
	.dump_stats	=	scrr_qdisc_dump_stats,
	.owner		=	THIS_MODULE,
};

static struct Qdisc_ops scrr_neia_qdisc_ops __read_mostly = {
	.id		=	"scrr_neia",
	.priv_size	=	sizeof(struct scrr_sched_data),

	.enqueue	=	scrr_qdisc_nmne_enqueue,
	.dequeue	=	scrr_qdisc_neia_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	scrr_qdisc_init,
	.reset		=	scrr_qdisc_reset,
	.destroy	=	scrr_qdisc_destroy,
	.change		=	scrr_qdisc_change,
	.dump		=	scrr_qdisc_dump,
	.dump_stats	=	scrr_qdisc_dump_stats,
	.owner		=	THIS_MODULE,
};

static struct Qdisc_ops scrr_basic_qdisc_ops __read_mostly = {
	.id		=	"scrr_basic",
	.priv_size	=	sizeof(struct scrr_sched_data),

	.enqueue	=	scrr_qdisc_enqueue,
	.dequeue	=	scrr_qdisc_basic_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	scrr_qdisc_init,
	.reset		=	scrr_qdisc_reset,
	.destroy	=	scrr_qdisc_destroy,
	.change		=	scrr_qdisc_change,
	.dump		=	scrr_qdisc_dump,
	.dump_stats	=	scrr_qdisc_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init scrr_module_init(void)
{
	int ret;

	scrr_flow_cachep = kmem_cache_create("scrr_flow_cache",
					     sizeof(struct scrr_flow),
					     0, 0, NULL);
	if (!scrr_flow_cachep)
		return -ENOMEM;

	ret = register_qdisc(&scrr_qdisc_ops);
	if (!ret) {
		ret = register_qdisc(&scrr_npm_qdisc_ops);
		if (!ret) {
			ret = register_qdisc(&scrr_nmia_qdisc_ops);
			if (!ret) {
				ret = register_qdisc(&scrr_nmne_qdisc_ops);
				if (!ret) {
					ret = register_qdisc(&scrr_neia_qdisc_ops);
					if (!ret) {
						ret = register_qdisc(&scrr_basic_qdisc_ops);
						if (ret)
							unregister_qdisc(&scrr_neia_qdisc_ops);
					}
					if (ret)
						unregister_qdisc(&scrr_nmne_qdisc_ops);
				}
				if (ret)
					unregister_qdisc(&scrr_nmia_qdisc_ops);
			}
			if (ret)
				unregister_qdisc(&scrr_npm_qdisc_ops);
		}
		if (ret)
			unregister_qdisc(&scrr_qdisc_ops);
	}
	if (ret)
		kmem_cache_destroy(scrr_flow_cachep);
	return ret;
}

static void __exit scrr_module_exit(void)
{
	unregister_qdisc(&scrr_qdisc_ops);
	unregister_qdisc(&scrr_npm_qdisc_ops);
	unregister_qdisc(&scrr_nmia_qdisc_ops);
	unregister_qdisc(&scrr_nmne_qdisc_ops);
	unregister_qdisc(&scrr_neia_qdisc_ops);
	unregister_qdisc(&scrr_basic_qdisc_ops);
	kmem_cache_destroy(scrr_flow_cachep);
}

module_init(scrr_module_init)
module_exit(scrr_module_exit)
MODULE_AUTHOR("Jean Tourrilhes");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Self Clocked Round Robin Packet Scheduler");
