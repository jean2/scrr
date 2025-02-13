// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/sch_bfifo_head.c	The FIFO queue in bytes that drop at the head.
 *
 *	Copyright 2022-2025 Hewlett Packard Enterprise Development LP.
 *	Author: Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 *
 * Based on fifo.c :
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>

//#define BFIFO_DEBUG

/* Stats exported to userspace */
struct tc_bfifo_head_xstats {
	__u32	skb_num;	/* Number of skbs */
	__u32	qlen_peak;	/* Maximum queue length */
	__u32	backlog_peak;	/* Maximum backlog */
};

/* private data for the Qdisc */
struct bfifo_head_sched_data {
	struct tc_bfifo_head_xstats	stats;
};

static int bfifo_head_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			      struct sk_buff **to_free)
{
	struct bfifo_head_sched_data *q = qdisc_priv(sch);
	unsigned int prev_backlog;
	unsigned int prev_qlen;
	unsigned int backlog_new;

	/* bstats->packets keep track of the number of actual Ethernet
	 * packets. Unfortunately, all other stats are in number of
	 * sbks. The packet count and skb count are different due
	 * to GSO. This counter allow to count skbs and therefore
	 * have something consistent with the other stats. Jean II */
	q->stats.skb_num++;

	/* Keep track of maximum queue size in this time interval. Jean II */
	if (sch->q.qlen >= q->stats.qlen_peak)
		q->stats.qlen_peak = sch->q.qlen + 1;
	backlog_new = sch->qstats.backlog + qdisc_pkt_len(skb);
	/* If it's greater than 2^31, it's negative */
	if ( (backlog_new > q->stats.backlog_peak)
	     && (backlog_new < 2147483648) )
		q->stats.backlog_peak = backlog_new;

	/* If there is space in the queue, easy peasy... */
	if (likely(sch->qstats.backlog + qdisc_pkt_len(skb) <= sch->limit))
		return qdisc_enqueue_tail(skb, sch);

	prev_qlen = sch->q.qlen;
	prev_backlog = sch->qstats.backlog;

	/* Remove as many skbs as necessary to make space.
	 * Check 'head' in case limit is lower than gso size... */
	while ( (sch->qstats.backlog + qdisc_pkt_len(skb) > sch->limit)
		&& (qdisc_peek_head(sch) != NULL) ) {
		/* Queue full, remove one skb, decrease backlog */
		__qdisc_queue_drop_head(sch, &sch->q, to_free);
		qdisc_qstats_drop(sch);
	}
	/* Now we can enqueue */
	qdisc_enqueue_tail(skb, sch);

	/* We can't call qdisc_tree_reduce_backlog() if our qlen is 0,
	 * or HTB crashes. Fortunately, that's not possible here. */
	/* Update stats of the parent qdisc and notify it if queue
	 * became empty. */
	qdisc_tree_reduce_backlog(sch, prev_qlen - sch->q.qlen,
				  prev_backlog - sch->qstats.backlog);

#ifdef BFIFO_DEBUG
	if (sch->q.qlen != prev_qlen) {
		printk_ratelimited(KERN_DEBUG "bfifo_head: qlen %u -> %u ; backlog %u -> %u ; skb %u\n",
				   prev_qlen, sch->q.qlen,
				   prev_backlog, sch->qstats.backlog,
				   qdisc_pkt_len(skb));
	}
#endif	/* BFIFO_DEBUG */

	return NET_XMIT_CN;
}

static int bfifo_tail_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			      struct sk_buff **to_free)
{
	struct bfifo_head_sched_data *q = qdisc_priv(sch);
	unsigned int backlog_new;

	/* bstats->packets keep track of the number of actual Ethernet
	 * packets. Unfortunately, all other stats are in number of
	 * sbks. The packet count and skb count are different due
	 * to GSO. This counter allow to count skbs and therefore
	 * have something consistent with the other stats. Jean II */
	q->stats.skb_num++;

	/* Keep track of maximum queue size in this time interval. Jean II */
	if (sch->q.qlen >= q->stats.qlen_peak)
		q->stats.qlen_peak = sch->q.qlen + 1;
	backlog_new = sch->qstats.backlog + qdisc_pkt_len(skb);
	/* If it's greater than 2^31, it's negative */
	if ( (backlog_new > q->stats.backlog_peak)
	     && (backlog_new < 2147483648) )
		q->stats.backlog_peak = backlog_new;

	/* Simple queuing */
	if (likely(sch->qstats.backlog + qdisc_pkt_len(skb) <= sch->limit))
		return qdisc_enqueue_tail(skb, sch);

	return qdisc_drop(skb, sch, to_free);
}

static int bfifo_head_init(struct Qdisc *sch, struct nlattr *opt,
			   struct netlink_ext_ack *extack)
{
	struct bfifo_head_sched_data *q = qdisc_priv(sch);
	bool bypass;
	bool is_bfifo = true;

	q->stats.skb_num = 0;

	if (opt == NULL) {
		u32 limit = qdisc_dev(sch)->tx_queue_len;

		if (is_bfifo)
			limit *= psched_mtu(qdisc_dev(sch));

		sch->limit = limit;
	} else {
		struct tc_fifo_qopt *ctl = nla_data(opt);

		if (nla_len(opt) < sizeof(*ctl))
			return -EINVAL;

		sch->limit = ctl->limit;
	}

	if (is_bfifo)
		bypass = sch->limit >= psched_mtu(qdisc_dev(sch));
	else
		bypass = sch->limit >= 1;

	if (bypass)
		sch->flags |= TCQ_F_CAN_BYPASS;
	else
		sch->flags &= ~TCQ_F_CAN_BYPASS;

	return 0;
}

static int bfifo_head_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct tc_fifo_qopt opt = { .limit = sch->limit };

	if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
		goto nla_put_failure;
	return skb->len;

nla_put_failure:
	return -1;
}

static int bfifo_head_dump_xstats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct bfifo_head_sched_data *q = qdisc_priv(sch);
	struct tc_bfifo_head_xstats st = {
		.skb_num	= q->stats.skb_num,
		.qlen_peak	= q->stats.qlen_peak,
		.backlog_peak	= q->stats.backlog_peak,
	};

	/* Reset some of the statistics */
	q->stats.qlen_peak = 0;
	q->stats.backlog_peak = 0;

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

struct Qdisc_ops bfifo_head_drop_qdisc_ops __read_mostly = {
	.id		=	"bfifo_head_drop",
	.priv_size	=	sizeof(struct bfifo_head_sched_data),
	.enqueue	=	bfifo_head_enqueue,
	.dequeue	=	qdisc_dequeue_head,
	.peek		=	qdisc_peek_head,
	.init		=	bfifo_head_init,
	.reset		=	qdisc_reset_queue,
	.change		=	bfifo_head_init,
	.dump		=	bfifo_head_dump,
	.dump_stats	=	bfifo_head_dump_xstats,
	.owner		=	THIS_MODULE,
};

struct Qdisc_ops bfifo_tail_drop_qdisc_ops __read_mostly = {
	.id		=	"bfifo_tail_drop",
	.priv_size	=	sizeof(struct bfifo_head_sched_data),
	.enqueue	=	bfifo_tail_enqueue,
	.dequeue	=	qdisc_dequeue_head,
	.peek		=	qdisc_peek_head,
	.init		=	bfifo_head_init,
	.reset		=	qdisc_reset_queue,
	.change		=	bfifo_head_init,
	.dump		=	bfifo_head_dump,
	.dump_stats	=	bfifo_head_dump_xstats,
	.owner		=	THIS_MODULE,
};

static int __init bfifo_head_module_init(void)
{
	int ret;

	ret = register_qdisc(&bfifo_head_drop_qdisc_ops);
	if (!ret) {
		ret = register_qdisc(&bfifo_tail_drop_qdisc_ops);
		if (ret)
			unregister_qdisc(&bfifo_head_drop_qdisc_ops);
	}

	return ret;
}

static void __exit bfifo_head_module_exit(void)
{
	unregister_qdisc(&bfifo_head_drop_qdisc_ops);
	unregister_qdisc(&bfifo_tail_drop_qdisc_ops);
}

module_init(bfifo_head_module_init);
module_exit(bfifo_head_module_exit);

MODULE_DESCRIPTION("Byte FIFO with head drop scheduler");
MODULE_AUTHOR("Jean Tourrilhes");
MODULE_LICENSE("GPL");
