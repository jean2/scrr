// SPDX-License-Identifier: GPL-2.0-only
/*
 * net/sched/sch_fq_pi2.c
 *
 * Authors:	Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 *
 * Integrate PI2 code (sch_pi2.c) into DRR qdisc (sch_fq.c) :
 *	Copyright 2024-2025 Hewlett Packard Enterprise Development LP.
 *	Author: Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 * Flow classifier and DRR scheduler based on sch_fq.c implementation :
 *	Copyright (C) 2013-2015 Eric Dumazet <edumazet@google.com>
 * Removing all socket/pacing code from DRR qdisc :
 *	Copyright 2023-2025 Hewlett Packard Enterprise Development LP.
 *	Author: Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 * PI2 optimisations & improvements :
 *	Copyright 2021-2025 Hewlett Packard Enterprise Development LP.
 *	Author: Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 * Based on the Dual PI2 qdisc implementation :
 *	Copyright (C) 2015 Alcatel-Lucent.
 *	Author: Koen De Schepper <koen.de_schepper@alcatel-lucent.com>
 *	Author: Olga Bondarenko <olgabo@simula.no>
 * Based on the PIE qdisc implementation :
 *	Copyright (C) 2013 Cisco Systems, Inc, 2013.
 *	Author: Vijay Subramanian <vijaynsu@cisco.com>
 *	Author: Mythili Prabhu <mysuryan@cisco.com>
 * Packet timestamping based on Codel qdisc implementation :
 *	Copyright (C) 2012 Michael D. Taht <dave.taht@bufferbloat.net>
 *	Copyright (C) 2012,2015 Eric Dumazet <edumazet@google.com>
 * Rapid signalling based on document from Bob Briscoe
 *
 * ---------------------------------------------------------------- *
 *
 * From sch_fq.c :
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
 *
 * ---------------------------------------------------------------- *
 *
 * From sch_pi2.c :
 *
 * ---- Parameters ----
 *
 * This implementation of PI2 is designed so that you only need to adjust
 * one parameter, 'target'. This represent the target delay of the queue
 * and should be approximately equal to the typical RTT.
 * The default is 15ms, like some other implementations (dualpi2.c),
 * and should be good enough for most deployments.
 * This implementation supports 'target' values between 100us and 1s.
 *
 * In other implementations (dualpi2.c), if 'target' is changed, other
 * parameters need to be changed, such as 'alpha', 'beta' and 'tupdate'.
 * In this implementation, they are scaled according to 'target', so
 * you don't really need to change them. But you can...
 *
 * The parameter 'tupdate' control how frequently the internal state
 * is updated. More frequent updates improves performance, but increase
 * overhead. It is safe to set very low values, even 0, the code guarantees
 * the updates are not done more frequently than once per packet.
 *
 * ---- QDisc combination, order and classfulness  ----
 *
 * This QDisc is *not* classful, which means it is terminal, no QDisc
 * can be attached after it. It does not matter, because the order
 * of QDisc often does not matter (NetEm is an exception).
 *
 * For example, a classic combination would be PI2 AQM + TBF shaper.
 * We want the AQM to be logically in front of the shaper, so that
 * the outgoing rate of the AQM is limited by the shaper. In practice,
 * attaching PI2 as a leaf of TBF produces the correct result.
 *
 * PI2-Head can not be combined with NetEm. NetEm will corrupt its statistics,
 * blocking the interface. Unfortunately, there is no workaround and
 * we can't warn the user.
 * For this reason, it's not the default QDisc. Use the normal PI2 instead.
 *
 * PI2 may have poor interactions with NetEm adding delay.
 * The reason is that PI2 measure the full delay of the queue, and in some
 * case this includes the emulated delay added by NetEm. In such case,
 * the delay will always be high, resulting in high loss/marking.
 * Most of the case, it works right for me, I hope you are as lucky...
 *
 * An earlier version of PI2 was classful. I decided to remove class
 * support for the following reasons :
 * 1) Not needed, most useful combinations of QDisc can be acheived
 *    with PI2 at the end of the QDisc chain (such as TBF+PI2).
 * 2) Prevent combining PI2 with CoDel. Both use the same area of the SKB
 *    to store timestamp, so the result would be unpredictable. Anyway,
 *    that combination does not make sense.
 * 3) Simpler, smaller, more efficient code.
 *
 * ---- GSO support ----
 *
 * I made the decision to not support GSO segmentation (see dualpi2.c).
 *
 * 1) It adds a lot of complexity to the code
 * 2) GSO is the main optimisation that allows Ethernet to go fast
 * 3) I feel that with short tupdate, Scalable-ECN and derandomisation, it's
 *	less needed
 * 4) Instead of having each qdisc implementing it's own version, we should
 * have a shim qdisc that implement GSO segmentation for everybody.
 * 5) At lower speed, large GSO frames should be segmented, but it's more
 * a question of TCP pacing, and therefore GSO segmentation may not be
 * the right tool.
 * 
 * GSO segmentation will improve AQM performance, especially at low rate.
 * If you really want GSO segmentation, please use TBF+PI2 (PI2 as a leaf
 * to the TBF qdisc), just set a low MTU (1500) and high rate on TBF.
 *
 * Jean II
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

#define PI2_ECN_IS_ECT1

//#define DRR_DEBUG_CONFIG
//#define DRR_DEBUG_GC
//#define DRR_DEBUG_CLASSIFIER
//#define DRR_DEBUG_FLOW_NEW
//#define DRR_DEBUG_REHASH
//#define DRR_DEBUG_NOFLOW
//#define PI2_DEBUG_CONFIG
//#define PI2_DEBUG_COMPUTE
//#define PI2_DEBUG_PROBA
//#define PI2_DEBUG_TUPDATE
//#define PI2_DEBUG_REDUCE
#define PI2_STATS_FLOW_QLEN
#define PI2_STATS_FLOW_QDELAY
#define PI2_STATS_FLOW_MARK
//#define PI2_UDP_TAILDROP_DELAY
#define PI2_UDP_TAILDROP_PACKETS
//#define DRR_STATS_BURST_AVG

#define PROBA_NORMA	0x100000000LL	/* Normalise : probability 1 is 2^32 */
#define PROBA_MAX	0xFFFFFFFFLL	/* Max probability : 2^32 - 1 */

/* We scale alpha and beta with the target delay, so the the reaction is always
 * the same with respect to the target delay. So, our alpha and beta are
 * quite different from other implementations (sch_pie.c, sch_dualpi2.c).
 * This is a list of *unscaled* alpha and beta to show typical scaling...
 * Our reference is       target= 1ms, tupdate= 1ms, alpha=2.250, beta=48.0
 * Same as dualpi2 implem target=15ms, tupdate=16ms, alpha=0.160, beta=3.2
 * Same as                target=20ms, tupdate=32ms, alpha=0.18,  beta=2.4
 * PI2 paper fig 6 is     target=20ms, tupdate=32ms, alpha=0.312, beta=3.125
 * PI2 paper fig 11 is    target=20ms, tupdate=32ms, alpha=0.625, beta=6.25
 * dualpi2 autoconfiguration (in tc/q_dualpi2.c) :
 * rtt typ 1ms max 6ms    target= 1ms, tupdate= 1ms, alpha=2.777, beta=50.0
 * rtt typ 15ms max 96ms  target=15ms, tupdate=15ms, alpha=0.163, beta=3.125
 * rtt typ 20ms max 240ms target=20ms, tupdate=20ms, alpha=0.034, beta=1.250
 * Jean II */
#define PI2_TUPDATE_REF	(1 * NSEC_PER_MSEC)	/* Reference tupdate */
#define PI2_TARGET_REF	(1 * NSEC_PER_MSEC)	/* Reference target */
#define PI2_ALPHA_DEFLT	(576)			/* 2.25 @ 1;1ms - see below */
#define PI2_BETA_DEFLT	(12288)			/* 48.0 @ 1;1ms - see below */
#define PI2_COUPL_DEFLT	(2 * ALPHA_BETA_SCALE)	/* Factor 2 - from PI2 paper */

/* Typical values of alpha and beta are floating point.
 * Typical value for coupling factor is 2.0.
 * We need to convert it to integer without loosing too much precision, so
 * encode in fixed point normalised at 256, in 1/256th increments.
 * We have for example :
 * alpha=2.250, beta=48.0 -> tca_alpha=576, tca_beta=12288
 * coupling 2.0 -> tca_coupling=512.
 * Jean II */
#define ALPHA_BETA_SCALE	(1 << 8)	/* Convert fraction-> integer */
#define ALPHA_BETA_MAX		((1 << 23) - 1)	/* s32, shifted by AB_SCALE */
#define ALPHA_BETA_INVALID	(~((uint32_t)0))

/* We shift our internal values of alpha and beta by 16 bits
 * to keep internal precision in fixed point computations.
 * In addition, we scale them using target.
 * Because alpha is divided by the square of target and needs to be multiplied
 * by tupdate in nanosecconds, we need to shift it by 24 extra bits. 
 * So, we have the following conversions :
 * tca_al=576, tca_be=12288, target= 1ms => al_nm40=10620380, be_nm16=13504512
 * tca_al=576, tca_be=12288, target=15ms => al_nm40=47201, be_nm16=900300
 * tca_al=576, tca_be=12288, target=20ms => al_nm40=26550, be_nm16=675225
 * tca_al=576, tca_be=12288, target= 1s  => al_nm40=10, be_nm16=13504
 * tca_al=576, tca_be=12288, tgt=100us => al_nm40=1062038038, be_nm16=135045120
 * Jean II */
#define NM16_SHIFT	16
#define NM16_SCALE	(1 << NM16_SHIFT)
#define NM24_SHIFT	24
#define NM24_SCALE	(1 << NM24_SHIFT)

#define PI2_LIMIT_DEFLT (1000000)		/* 1MB */

#ifndef TCA_FQ_PI2_MAX
/* FQ_PI2 */
enum {
	TCA_FQ_PI2_UNSPEC,
	TCA_FQ_PI2_PLIMIT,	/* limit of total number of packets in queue */
	TCA_FQ_PI2_FLOW_PLIMIT,	/* limit of packets per flow (packets) */
	TCA_FQ_PI2_QUANTUM,	/* RR quantum (bytes @ L2)*/
	TCA_FQ_PI2_INITIAL_QUANTUM,	/* RR quantum for new flow (bytes) */
	TCA_FQ_PI2_FLOW_REFILL_DELAY,	/* flow credit refill delay in usec */
	TCA_FQ_PI2_BUCKETS_LOG,	/* log2(number of buckets) */
	TCA_FQ_PI2_HASH_MASK,	/* mask applied to skb hashes (bitmask) */
	TCA_FQ_PI2_TARGET,	/* PI2 target queuing delay (us) */
	TCA_FQ_PI2_TUPDATE,	/* Time between proba updates (us) */
	TCA_FQ_PI2_ALPHA,	/* Integral coefficient */
	TCA_FQ_PI2_BETA,	/* Proportional coefficient */
	TCA_FQ_PI2_COUPLING,	/* Coupling between scalable and classical */
	TCA_FQ_PI2_FLAGS,	/* See flags below */
	TCA_FQ_PI2_MON_FL_PORT,	/* Transport port for flow instrumentation */
	TCA_FQ_PI2_UDP_PLIMIT,	/* Target backlog size for UDP (bytes) */
	__TCA_FQ_PI2_MAX
};
#define TCA_FQ_PI2_MAX   (__TCA_FQ_PI2_MAX - 1)

/* FQ_PI2_FLAGS */
#define PI2F_MARK_ECN		0x0001	/* Mark ECT_0 pkts with Classical ECN */
#define PI2F_MARK_SCE		0x0002	/* Mark ECT_1 pkts with Scalable-ECN */
#define PI2F_OVERLOAD_ECN	0x0004	/* Keep doing ECN/SCE on overload */
#define PI2F_RANDOM_MARK	0x0008	/* Randomise marking, like RED */
#define PI2F_BYTEMODE		0x0010	/* Bytemode - unimplemented */
#define PI2F_PEAK_NORESET	0x0020	/* Don't reset peak statistics */
#define PI2F_UDP_TAILDROP	0x0040	/* Tail-drop UDP packets */

#define PI2F_MASK_OVERLOAD	(~0x3)	/* Mask out two lowest bits */

#endif	/* TCA_FQ_PI2_MAX */

/* Stats exported to userspace */
struct tc_fq_pi2_xstats {
	__u32	flows;		/* number of flows */
	__u32	flows_inactive;	/* number of inactive flows */
	__u64	flows_gc;	/* number of flows garbage collected */
	__u32	alloc_errors;	/* failed flow allocations */
	__u32	no_mark;	/* Enqueue events (pkts / gso_segs) */
	__u32	drop_mark;	/* Packets dropped due to PI2 AQM */
	__u32	ecn_mark;	/* Packets marked with ECN, classic TCP */
	__u32	sce_mark;	/* Packets marked with ECN, scalable TCP */
	__u32	burst_peak;	/* Maximum burst size */
	__u32	burst_avg;	/* Average burst size */
	__u32	sched_empty;	/* Schedule with no packet */
	__u32	fl_qlen;	/* Sub-queue length */
	__u32	fl_backlog;	/* Sub-queue backlog */
	__u32	fl_qlen_peak;	/* Maximum sub-queue length */
	__u32	fl_backlog_peak;	/* Maximum sub-queue backlog */
	__u32	fl_proba;	/* Current raw probability for sub-queue */
	__u32	fl_proba_peak;	/* Maximum raw probability experienced */
	__u32	fl_qdelay_us;	/* Current estimated sub-queue delay */
	__u32	fl_qdelay_peak_us;	/* Maximum sub-queue delay */
	__u32	fl_no_mark;	/* Sub-Q enqueue events (pkts / gso_segs) */
	__u32	fl_drop_mark;	/* Sub-Q pkts dropped due to PI2 AQM */
	__u32	fl_ecn_mark;	/* Sub-Q pkts marked with ECN, classic TCP */
	__u32	fl_sce_mark;	/* Sub-Q pkts marked with ECN, scalable TCP */
};

/* PI2 Parameters configured from user space */
struct pi2_config {
	s64	target_ns;	/* Target queue delay (in ns) */
	u32	tupdate_ns;	/* Update timer frequency (in ns) */
	u32	alpha;		/* alpha and beta are between 0 and 32... */
	u32	beta;		/* ...and are used for shift relative to 1 */
	u32	coupling;	/* Coupling rate factor between
				 * Classic TCP and Scalable TCP */
	u32	flags;		/* Bitmask of PI2F_XXX flags */
};

/* PI2 Internal state and helpful variables */
struct pi2_param {
	s64	fl_qdelay_ns;	/* Last computed sub-queue delay */
	s64	fl_qdelay_peak_ns;	/* Maximum sub-queue delay */
	u32	alpha_nm40;	/* Scaled by target_ns, shifted 40 bits */
	u32	beta_nm16;	/* Scaled by target_ns, shifted 16 bits */
	u32	proba_max;	/* Maximum raw probability. */
	u32	reduce_qlen;	/* Pending qlen to be reduced on parent */
	u32	reduce_backlog;	/* Pending backlog to be reduced on parent */
};

/* Flow state for PI2 */
struct pi2_flow {
	s64	tupd_next_ns;	/* Next time to do a probability update */
	u64	overload_ns;	/* When overload condition will start */
	u64	head_ns;	/* When last head of queue was enqueue'd */
	s64	qdelay_ns;	/* Last computed queuing delay */
	u32	proba_2;	/* Probability for Classical TCP. */
	u32	proba_cpl;	/* Probability for Scalable TCP. */
	u32	proba;		/* Raw probability. */
	u32	flags_live;	/* Bitmask of PI2F_XXX flags */
	u32	recur_classic;	/* Mark counter for classical TCP */
	u32	recur_scalable;	/* Mark counter for scalable TCP */
};


/*
 * Per flow structure, dynamically allocated.
 */
struct fq_pi2_flow {
	struct sk_buff	*head;		/* list of skbs for this flow : first skb */
	union {
		struct sk_buff *tail;	/* last skb in the list */
		unsigned long  age;	/* (jiffies | 1UL) when flow was emptied, for gc */
	};
	struct rb_node	hash_node;	/* anchor in hash_root[] trees */
	u32		flow_idx;	/* Hash value for this flow */
	int		qlen;		/* number of packets in flow queue */
	int		credit;		/* Deficit */

	struct fq_pi2_flow *next;	/* next flow in RR lists */

	struct pi2_flow	pi2;		/* PI2 per flow data */
} ____cacheline_aligned_in_smp;

/*
 * Container for list of flows. Round Robin will go through those lists.
 */
struct fq_flow_head {
	struct fq_pi2_flow *first;
	struct fq_pi2_flow *last;
};

static struct kmem_cache *fq_pi2_flow_cachep __read_mostly;

/*
 * Private data for the Qdisc
 */
struct fq_pi2_sched_data {
	struct fq_flow_head new_flows;

	struct fq_flow_head old_flows;

	/* Configuration */
	u32		flow_plimit;	/* max packets per flow */
	u32		quantum;
	u32		initial_quantum;
	u32		flow_refill_delay;
	u32		hash_mask;	/* mask for limiting number hashes */
	struct pi2_config	pi2_config;

	/* Parameters */
	struct rb_root	*hash_root;
	u8		hash_trees_log;
	u32		hash_buckets;
	struct pi2_param	pi2_param;

	/* Stats and instrumentation */
	struct tc_fq_pi2_xstats  stats;

#ifdef DRR_STATS_BURST_AVG
	u32		flow_sched_prev;	/* Previously active flow */
	u32		burst_cur;	/* Current burst size */
#endif	/* DRR_STATS_BURST_AVG */
#if defined(PI2_STATS_FLOW_QLEN) || defined(PI2_STATS_FLOW_QDELAY) || defined(PI2_STATS_FLOW_MARK) || defined(DRR_DEBUG_FLOW_NEW)
	u16		mon_fl_port;	/* Port for flow monitoring */ 
	u32		mon_fl_idx;	/* Flow index for flow monitoring */
#endif	/* PI2_STATS_FLOW_QLEN || PI2_STATS_FLOW_QDELAY || PI2_STATS_FLOW_MARK || DRR_DEBUG_FLOW_NEW */
#ifdef PI2_UDP_TAILDROP_PACKETS
	u32	udp_plimit;	/* Target queue length for UDP (in packets) */
#endif	/* PI2_UDP_TAILDROP_PACKETS */
};

struct pi2_skb_cb {
	u64 ts;			/* Timestamp at enqueue */
};

/* ----------------------- PI2 COMPUTATIONS ----------------------- */

static struct pi2_skb_cb *pi2_skb_cb(struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct pi2_skb_cb));
	return (struct pi2_skb_cb *) qdisc_skb_cb(skb)->data;
}

#ifdef PI2_ECN_IS_ECT1
static inline int IP_ECN_is_ect1(struct iphdr *iph)
{
	return (iph->tos & INET_ECN_MASK) == INET_ECN_ECT_1;
}

static inline int IP6_ECN_is_ect1(struct ipv6hdr *iph)
{
	return (ipv6_get_dsfield(iph) & INET_ECN_MASK) == INET_ECN_ECT_1;
}

static inline int INET_ECN_is_ect1(struct sk_buff *skb)
{
	switch (skb_protocol(skb, true)) {
	case cpu_to_be16(ETH_P_IP):
		if (skb_network_header(skb) + sizeof(struct iphdr) <=
		    skb_tail_pointer(skb))
			return IP_ECN_is_ect1(ip_hdr(skb));
		break;

	case cpu_to_be16(ETH_P_IPV6):
		if (skb_network_header(skb) + sizeof(struct ipv6hdr) <=
		    skb_tail_pointer(skb))
			return IP6_ECN_is_ect1(ipv6_hdr(skb));
		break;
	}

	return 0;
}
#endif	/* PI2_ECN_IS_ECT1 */

#if defined(PI2_UDP_TAILDROP_DELAY) || defined(PI2_UDP_TAILDROP_PACKETS)
static inline int INET_is_UDP(struct sk_buff *skb)
{
	switch (skb_protocol(skb, true)) {
	case cpu_to_be16(ETH_P_IP):
		if (skb_network_header(skb) + sizeof(struct iphdr) <=
		    skb_tail_pointer(skb)) {
			return ip_hdr(skb)->protocol == IPPROTO_UDP;
		}
		break;

	case cpu_to_be16(ETH_P_IPV6):
		if (skb_network_header(skb) + sizeof(struct ipv6hdr) <=
		    skb_tail_pointer(skb)) {
			return ipv6_hdr(skb)->nexthdr == IPPROTO_UDP;
		}
		break;
	}

	return 0;
}
#endif	/* PI2_UDP_TAILDROP_DELAY || PI2_UDP_TAILDROP_PACKETS */

static inline bool udp_is_taildrop_config(struct Qdisc *sch,
					  struct sk_buff *skb)
{
#if defined(PI2_UDP_TAILDROP_DELAY) || defined(PI2_UDP_TAILDROP_PACKETS)
	struct fq_pi2_sched_data *q = qdisc_priv(sch);

	return (q->pi2_config.flags & PI2F_UDP_TAILDROP) && INET_is_UDP(skb);
#else	/* PI2_UDP_TAILDROP_DELAY || PI2_UDP_TAILDROP_PACKETS */
	return false;
#endif	/* PI2_UDP_TAILDROP_DELAY || PI2_UDP_TAILDROP_PACKETS */
}

/* Tail drop UDP packets at the target.
 * Most UDP applications don't support ECN, even if the underlying
 * IP header indicates support for ECN.
 * So, in most cases, UDP applications are not going to react
 * to ECN signals and just fill up the queue. This tail-drop
 * is a crude and effective way to solve this. Jean II */
static inline bool udp_try_drop_pkt(struct Qdisc *sch,
				    struct fq_pi2_flow *flow,
				    struct sk_buff *skb,
				    s64 now)
{
#if defined(PI2_UDP_TAILDROP_DELAY) || defined(PI2_UDP_TAILDROP_PACKETS)
	struct fq_pi2_sched_data *q = qdisc_priv(sch);

	/* Never mark/drop if we have a standing queue of less than 2 skbs. */
	if (flow->qlen > 2) {
#ifdef PI2_UDP_TAILDROP_DELAY
		s64	qdelay_ns;

		/* Estimate the current delay of the queue. */
		qdelay_ns = now - flow->pi2.head_ns;
		if ( qdelay_ns >= q->pi2_config.target_ns ) {
			q->stats.drop_mark++;
			return true;
		}
#else	/* PI2_UDP_TAILDROP_DELAY -> PI2_UDP_TAILDROP_PACKETS */
		if ( flow->qlen > q->udp_plimit ) {
			q->stats.drop_mark++;
			return true;
		}
#endif	/* PI2_UDP_TAILDROP_DELAY */
	}
	q->stats.no_mark++;
#endif	/* PI2_UDP_TAILDROP_DELAY || PI2_UDP_TAILDROP_PACKETS */
	return false;
}

static void pi2_calculate_proba(struct Qdisc *sch,
				struct fq_pi2_flow *flow,
				s64 qdelay_ns,
				s64 now,
				s64 elapsed_ns)
{
	struct fq_pi2_sched_data *q = qdisc_priv(sch);
	s64	qdelay_old_ns = flow->pi2.qdelay_ns;
        s64	delta;		/* Change +/- in probability */
        s64	delta_alpha;	/* Change +/- in probability from alpha */
        s64	delta_beta;	/* Change +/- in probability from beta */
	s64	proba;		/* New probability */
	s64	proba_cpl;	/* New probability, multiplied by coupling */
	s64	proba_2;	/* New probability, squared */

#ifdef PI2_STATS_FLOW_QDELAY
	if (flow->flow_idx == q->mon_fl_idx) {
		/* Save sub-queue delay for this flow */
		q->pi2_param.fl_qdelay_ns = qdelay_ns;
		/* Keep track of largest sub-queue delay */
		if (qdelay_ns > q->pi2_param.fl_qdelay_peak_ns)
			q->pi2_param.fl_qdelay_peak_ns = qdelay_ns;
	}
#endif	/* PI2_STATS_FLOW_QDELAY */

	/* Compute probability change +/- based on delay using the PI
	 * controller formula (proportional/integral).
	 * alpha is the integral weight, slowly react to absolute difference.
	 * beta is the proportional weight, quickly reacts to slope.
	 *
	 * delta and proba are encoded normalised at 2^32 (see PROBA_MAX).
	 * See earlier comments about alpha_nm40 and beta_nm16.
	 * Note that shift is undefined on signed integer, therefore
	 * use division that the compiler will optimise away.
	 *
	 * When we have multiple tupdate, we only need to scale the term alpha,
	 * because the difference of qdelays already represent the sum
	 * of each individual updates...
	 * Jean II
	 */
	delta_alpha = ( ( ( (qdelay_ns - q->pi2_config.target_ns)
			    * q->pi2_param.alpha_nm40 )
			  / NM24_SCALE )
			* elapsed_ns);
	delta_beta = ( (qdelay_ns - qdelay_old_ns) * q->pi2_param.beta_nm16 );
	delta = ( delta_alpha + delta_beta ) / NM16_SCALE;

	proba = (s64) flow->pi2.proba + delta;
#ifdef PI2_DEBUG_COMPUTE
        printk_ratelimited(KERN_DEBUG "PI2: qdelay %lld ; delta %lld (%lld + %lld); proba %lld\n", qdelay_ns, delta, delta_alpha / NM16_SCALE, delta_beta / NM16_SCALE, proba);
#endif	/* PI2_DEBUG_COMPUTE */

	/* PI2 limit the max marking probability to 100%
	 * This make the max dropping probability to 25%, assuming coupling=2,
	 * because only classic TCP drops packets (scalable does Scalable-ECN).
	 * This makes sure packets are still flowing and we don't shut down
	 * the queue entirely when it is full. This allows uncontrolled UDP
	 * traffic or unresponsive TCP to go throught the queue.
	 * I know that 25% is not the right maximum proba, and it depends on
	 * what the input rate is in relation to the output rate.
	 * High probability may be due to :
	 *	o Uncontrolled or poorly controlled UDP traffic
	 *	o Poor TCP congestion control implementation
	 *	o Connection storm, large number of synchronised connections
	 *	o Higher RTT than expected
	 *	o Target configured too small
	 * Such high probabilities are pathological cases, not really
	 * supported well by TCP and quite wasteful. We are already operating
	 * much outside the normal enveloppe of AQM, and we should not
	 * increase the dropping further. On the other hand, we should
	 * let this unexpected traffic take advantage of the larger queue,
	 * and let tail-drop takes over.
	 * For uncontroled UDP or unresponsive TCP, we may drop packets
	 * earlier than they would have been with pure tail drop, but as
	 * we don't prevent the queue from filling, the actual drop rate
	 * is the same.
	 * These tests work because we compare in signed 64bit.
	 * Jean II */
	if (proba >= q->pi2_param.proba_max) {
		proba = q->pi2_param.proba_max;

		/* Check how we handle overload conditions */
		if ( ! (q->pi2_config.flags & PI2F_OVERLOAD_ECN) ) {
		    if ( flow->pi2.overload_ns == 0LL)
			/* First time in overload, wait a few periods
			 * before doing anything...
			 * We want to wait for a duration greater than target
			 * before going in overload mode. TCP is bursty and can
			 * be expected to dump on us an amount of data at least
			 * equal to target all at once... Jean II */
			flow->pi2.overload_ns = now + (q->pi2_config.target_ns/4);
		    else {
			/* Declare overload condition if we have a few periods
			 * at max proba. TCP is bursty, waiting a bit enables
			 * ignore some transients. Jean II */
			if ( now > flow->pi2.overload_ns )
			    /* Overload condition, disable ECN & SCE markings */
			    flow->pi2.flags_live &= PI2F_MASK_OVERLOAD;
		    }
		}
	} else {
		/* We don't like negative probability either, especially
		 * that we will cast to unsigned... Jean II */
		if (proba < 0)
			proba = 0;

		/* No overload condition, re-enable ECN & SCE markings */
		flow->pi2.flags_live = q->pi2_config.flags;
		flow->pi2.overload_ns = 0LL;
	}

	/* Cast to 32 bits, save for next time */
	flow->pi2.proba = (u32) proba;

#ifdef PI2_STATS_FLOW_QDELAY
	if (flow->flow_idx == q->mon_fl_idx) {
		/* Keep track of current and maximum proba for the flow */
		q->stats.fl_proba = flow->pi2.proba;
		if (flow->pi2.proba > q->stats.fl_proba_peak)
			q->stats.fl_proba_peak = flow->pi2.proba;
	}
#endif	/* PI2_STATS_FLOW_QDELAY */

	/* Compute the probability for the Scalable TCP.
	 * Multiply by the raw probabiloty by coupling factor
	 * between scalable TCP and classic TCP. */
	proba_cpl = proba * q->pi2_config.coupling / ALPHA_BETA_SCALE;
	flow->pi2.proba_cpl = (u32) proba_cpl;

	/* Compute probability for classical TCP
	 * Do the square of the raw probability. Normalised at 2^32. */
	proba_2 = proba * proba / PROBA_NORMA;
	flow->pi2.proba_2 = (u32) proba_2;

#ifdef PI2_DEBUG_PROBA
        printk_ratelimited(KERN_DEBUG "PI2: proba*c %lld = 0.%03lld ; proba^2 %lld = 0.%03lld\n", proba_cpl, proba_cpl * 1000 / PROBA_NORMA, proba_2, proba_2 * 1000 / PROBA_NORMA);
#endif	/* PI2_DEBUG_PROBA */

	/* Save for next time as well */
	flow->pi2.qdelay_ns = qdelay_ns;
}

static void pi2_tupdate(struct Qdisc *sch,
			struct fq_pi2_flow *flow,
			s64 now)
{
	struct fq_pi2_sched_data *q = qdisc_priv(sch);
	s64	tupd_elapsed;
	s64	qdelay_ns;

	/* Figure out how many tupdate periods have elapsed. Jean II */
	tupd_elapsed = now - flow->pi2.tupd_next_ns + q->pi2_config.tupdate_ns;

	/* Keep track of next time tupdate will need to happen.
	 * This will drift over time, and won't tick at precisely tupdate
	 * period. It does not matter in practice because we use the exact
	 * time elapsed in computations. Jean II */
	flow->pi2.tupd_next_ns = now + ((s64) q->pi2_config.tupdate_ns);

#ifdef PI2_DEBUG_TUPDATE
        printk_ratelimited(KERN_DEBUG "PI2: tupd %lld (%d) ; now %lld ; next %lld\n", tupd_elapsed, q->pi2_config.tupdate_ns, now, flow->pi2.tupd_next_ns);
#endif	/* PI2_DEBUG_TUPDATE */

	/* Estimate the current delay of the queue.
	 * We compare when the packet at the head of the queue was enqueued
	 * to the time now. As we use the lastest head of the queue instead
	 * of the current head of the queue, we are a bit pessimistic.
	 * We need to make sure head_ns is always valid.
	 * Jean II */
	qdelay_ns = now - flow->pi2.head_ns;

	/* Compute new probability */
        pi2_calculate_proba(sch, flow, qdelay_ns, now, tupd_elapsed);
}

static bool pi2_try_drop_mark_pkt(struct Qdisc *sch,
				  struct fq_pi2_flow *flow,
				  struct sk_buff *skb)
{
	struct fq_pi2_sched_data *q = qdisc_priv(sch);
	u32 rnd_classic;
	u32 rnd_scalable;
	int is_ect1;

	/* Never mark/drop if we have a standing queue of less than 1 skbs. */
	if (flow->qlen <= 1) {
		q->stats.no_mark++;
#ifdef PI2_STATS_FLOW_MARK
		if (flow->flow_idx == q->mon_fl_idx) {
			q->stats.fl_no_mark++;
		}
#endif	/* PI2_STATS_FLOW_MARK */
		return false;
	}

	/* Figure out our random number */
	if (flow->pi2.flags_live & PI2F_RANDOM_MARK) {
		/* Pseudo random marking of packets based on current
		 * probability. */

		/* Use the fast, non-crypto random generator.
		 * Make sure we only use it only once to save CPU ! Jean II */
		rnd_classic = get_random_u32();
		rnd_scalable = rnd_classic;
	} else {
		/* Derandomised marking. This is what the latest PI2 spec
		 * suggest, and Bob Briscoe assure me it's better. Jean II */

		/* Increment our counters.
		 * They will roll over because they are only 32 bits.
		 * Rolling over is like reseting the counter, and it keeps
		 * the reminder of the probability from previous run.
		 * Also, updates to probability is handled properly.
		 * It's quite magical ! Jean II */
		flow->pi2.recur_classic += flow->pi2.proba_2;
		flow->pi2.recur_scalable += flow->pi2.proba_cpl;

		rnd_classic = flow->pi2.recur_classic;
		rnd_scalable = flow->pi2.recur_scalable;
	}

	/* Check if packet is Scalable TCP and if we can do Scalable-ECN. */
	is_ect1 = INET_ECN_is_ect1(skb);
	if ( is_ect1 && (flow->pi2.flags_live & PI2F_MARK_SCE) ) {
		/* Scalable TCP : Compare to raw probability multipled
		 * by coupling. */
		if ( (rnd_scalable < flow->pi2.proba_cpl)
		     && (INET_ECN_set_ce(skb)) ) {
			q->stats.sce_mark++;
#ifdef PI2_STATS_FLOW_MARK
			if (flow->flow_idx == q->mon_fl_idx) {
				q->stats.fl_sce_mark++;
			}
#endif	/* PI2_STATS_FLOW_MARK */
			/* Still need to be queued */
			return false;
		}
	} else {
		/* Classic TCP : Compare to square of probability. */
		if (rnd_classic < flow->pi2.proba_2) {
			/* Check if we can do ECN and packet is not Scalable */
			if ( (flow->pi2.flags_live & PI2F_MARK_ECN)
			     && (!is_ect1)
			     && (INET_ECN_set_ce(skb)) ) {
				q->stats.ecn_mark++;
#ifdef PI2_STATS_FLOW_MARK
				if (flow->flow_idx == q->mon_fl_idx) {
					q->stats.fl_ecn_mark++;
				}
#endif	/* PI2_STATS_FLOW_MARK */
				/* Still need to be queued */
				return false;
			} else {
				/* No ECN or packet is Scalable, drop it.
				 * In case of overload, flags are cleared
				 * and we end up here... Jean II */
				q->stats.drop_mark++;
#ifdef PI2_STATS_FLOW_MARK
				if (flow->flow_idx == q->mon_fl_idx) {
					q->stats.fl_drop_mark++;
				}
#endif	/* PI2_STATS_FLOW_MARK */
				return true;
			}
		}
	}

	/* bstats->packets keep track of the number of actual Ethernet
	 * packets. Unfortunately, all other stats are in number of
	 * sbks. The packet count and skb count are different due
	 * to GSO. This counter allow to count skbs and therefore
	 * have something consistent with the other stats. Jean II */
	q->stats.no_mark++;
#ifdef PI2_STATS_FLOW_MARK
	if (flow->flow_idx == q->mon_fl_idx) {
		q->stats.fl_no_mark++;
	}
#endif	/* PI2_STATS_FLOW_MARK */

	/* Lucky packet, not dropped, not marked... */
	return false;
}

/* ----------------------- FLOW MANAGEMENT ----------------------- */

/*
 * flow->tail and flow->age share the same location.
 * We can use the low order bit to differentiate if this location points
 * to a sk_buff or contains a jiffies value, if we force this value to be odd.
 * This assumes flow->tail low order bit must be 0 since
 * alignof(struct sk_buff) >= 2
 */
static void fq_flow_set_detached(struct fq_pi2_flow *flow)
{
	flow->age = jiffies | 1UL;
}

static bool fq_flow_is_detached(const struct fq_pi2_flow *flow)
{
	return !!(flow->age & 1UL);
}

static inline struct fq_pi2_flow *fq_create_flow(struct fq_pi2_sched_data *q,
						 uint32_t flow_idx)
{
	struct fq_pi2_flow *flow_new;

	flow_new = kmem_cache_zalloc(fq_pi2_flow_cachep,
				     GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(flow_new == NULL)) {
		q->stats.alloc_errors++;
		return NULL;
	}

	fq_flow_set_detached(flow_new);
	flow_new->flow_idx = flow_idx;
	flow_new->credit = q->initial_quantum;

	q->stats.flows++;
	q->stats.flows_inactive++;

	/* PI2 initialisation */
	flow_new->pi2.overload_ns = 0LL;
	flow_new->pi2.head_ns = 0LL;
	flow_new->pi2.qdelay_ns = 0;
	flow_new->pi2.proba_2 = 0;
	flow_new->pi2.proba_cpl = 0;
	flow_new->pi2.proba = 0;
	flow_new->pi2.recur_classic = 0;
	flow_new->pi2.recur_scalable = 0;

	/* When the first proba computation will happen. Jean II */
	flow_new->pi2.tupd_next_ns = ( ktime_get_ns()
				       + ((s64) q->pi2_config.tupdate_ns) );

	/* Overload mechanism.
	 * If probability goes through the roof, we assume that the queue
	 * is overloaded. This could be a badly implemented TCP, badly
	 * implemented ECN, or more likely a packet storm or unmanaged
	 * UDP traffic. In this case, we disable marking and only do drop
	 * to preserve low latency, unless PI2F_OVERLOAD_ECN is set.
	 * We do that by dropping ECN and SCE flags from the live flags.
	 * At init, we are not overloaded, so just copy the flags.
	 * Jean II */
	flow_new->pi2.flags_live = q->pi2_config.flags;

	return flow_new;
}

static inline void fq_flow_purge(struct fq_pi2_flow *flow)
{
	rtnl_kfree_skbs(flow->head, flow->tail);
	flow->head = NULL;
	flow->qlen = 0;
}

/* limit number of collected flows per round */
#define FQ_GC_MAX 8
#define FQ_GC_AGE (3*HZ)

static bool fq_gc_candidate(const struct fq_pi2_flow *f)
{
	return fq_flow_is_detached(f) &&
	       time_after(jiffies, f->age + FQ_GC_AGE);
}

static void fq_gc(struct fq_pi2_sched_data *q,
		  struct rb_root *	root,
		  uint32_t		flow_idx)
{
	struct rb_node **p, *parent;
	void *tofree[FQ_GC_MAX];
	struct fq_pi2_flow *f;
	int i, fcnt = 0;

	p = &root->rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		f = rb_entry(parent, struct fq_pi2_flow, hash_node);
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
	q->stats.flows -= fcnt;
	q->stats.flows_inactive -= fcnt;
	q->stats.flows_gc += fcnt;

#ifdef DRR_DEBUG_GC
	printk(KERN_DEBUG "DRR: flow gc: %d flows\n", fcnt);
#endif	/* DRR_DEBUG_GC */

	kmem_cache_free_bulk(fq_pi2_flow_cachep, fcnt, tofree);
}

static struct fq_pi2_flow *fq_classify(struct sk_buff *skb,
				       struct fq_pi2_sched_data *q)
{
	struct rb_node **	p;
	struct rb_node *	parent;
	uint32_t		flow_idx;
	struct rb_root *	root;
	struct fq_pi2_flow *	flow_cur;

	/* Get hash value for the packet */
	flow_idx = (uint32_t) ( skb_get_hash(skb) & q->hash_mask );

	/* Get the root of the tree from the hash */
	root = &q->hash_root[ flow_idx & (q->hash_buckets - 1) ];

	if (q->stats.flows >= (q->hash_buckets * 2) &&
	    q->stats.flows_inactive > q->stats.flows/2)
		fq_gc(q, root, flow_idx);

#ifdef DRR_DEBUG_CLASSIFIER
	printk(KERN_DEBUG "DRR: flow_idx 0x%X; buckets 0x%X; hash_32 0x%X; hash_root %p; root %p\n", flow_idx, q->hash_buckets - 1, flow_idx & (q->hash_buckets - 1), &q->hash_root[0], root);
#endif	/* DRR_DEBUG_CLASSIFIER */

	p = &root->rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		flow_cur = rb_entry(parent, struct fq_pi2_flow, hash_node);
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

#if defined(PI2_STATS_FLOW_QLEN) || defined(PI2_STATS_FLOW_QDELAY) || defined(PI2_STATS_FLOW_MARK) || defined(DRR_DEBUG_FLOW_NEW)
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
			/* Check if it's the flow we need to instrument */
			if ( (q->mon_fl_port == ntohs(dest_port))
			     ||  (q->mon_fl_port == ntohs(src_port)) ) {
				q->mon_fl_idx = flow_idx;
			}
#ifdef DRR_DEBUG_FLOW_NEW
			printk(KERN_DEBUG "DRR: flow new: idx:%d (mon %d), src_addr:%d, dst_addr:%d, src_port:%d, dst_port:%d\n", flow_idx, q->mon_fl_idx, ntohl(ih->saddr), ntohl(ih->daddr), ntohs(src_port), ntohs(dest_port));
#endif	/* DRR_DEBUG_FLOW_NEW */
		} else {
#ifdef DRR_DEBUG_FLOW_NEW
			printk(KERN_DEBUG "DRR: flow new: idx:%d\n", flow_idx);
#endif	/* DRR_DEBUG_FLOW_NEW */
		}
	}
#endif	/* PI2_STATS_FLOW_QLEN || PI2_STATS_FLOW_QDELAY || PI2_STATS_FLOW_MARK || DRR_DEBUG_FLOW_NEW */

	return flow_cur;
}

/* Add a flow at the end of the list used by Round Robin. */
static void fq_robin_add_tail(struct fq_flow_head *head,
			      struct fq_pi2_flow *flow)
{
	if (head->first)
		head->last->next = flow;
	else
		head->first = flow;
	head->last = flow;
	flow->next = NULL;
}

static inline struct sk_buff *fq_peek_skb(struct fq_pi2_flow *flow)
{
	struct sk_buff *head = flow->head;

	return head;
}

/* Add one skb to the flow queue. */
static inline void fq_enqueue_skb(struct Qdisc *	sch,
				  struct fq_pi2_flow *	flow,
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
#ifdef PI2_STATS_FLOW_QLEN
	{
		struct fq_pi2_sched_data *q = qdisc_priv(sch);
		if (flow->flow_idx == q->mon_fl_idx) {
			q->stats.fl_qlen++;
			q->stats.fl_backlog += qdisc_pkt_len(skb);
			/* Keep track of largest backlog */
			if (q->stats.fl_qlen > q->stats.fl_qlen_peak)
				q->stats.fl_qlen_peak = q->stats.fl_qlen;
			if (q->stats.fl_backlog > q->stats.fl_backlog_peak)
				q->stats.fl_backlog_peak = q->stats.fl_backlog;
		}
	}
#endif	/* PI2_STATS_FLOW_QLEN */
}

/* Remove one skb from flow queue. */
static inline void fq_dequeue_skb(struct Qdisc *	sch,
				  struct fq_pi2_flow *	flow,
				  struct sk_buff *	skb)
{
	flow->head = skb->next;
	skb_mark_not_on_list(skb);

	flow->qlen--;
	qdisc_qstats_backlog_dec(sch, skb);
	sch->q.qlen--;
#ifdef PI2_STATS_FLOW_QLEN
	{
		struct fq_pi2_sched_data *q = qdisc_priv(sch);
		if (flow->flow_idx == q->mon_fl_idx) {
			q->stats.fl_qlen--;
			q->stats.fl_backlog -= qdisc_pkt_len(skb);
		}
	}
#endif	/* PI2_STATS_FLOW_QLEN */
}

/* ----------------- ENQUEUE & DEQUEUE OPERATIONS ----------------- */

/* QDisc add a new packet to our queue - tail of queue.
 * Version with tail markings using PI2. */
static int fq_pi2_qdisc_enqueue_tail(struct sk_buff *	skb,
				     struct Qdisc *	sch,
				     struct sk_buff **	to_free)
{
	struct fq_pi2_sched_data *q = qdisc_priv(sch);
	struct fq_pi2_flow *flow_cur;
	struct pi2_skb_cb *cb;
	bool pi2_drop = true;
	s64 now;

	if (unlikely(sch->q.qlen >= sch->limit)) {
		qdisc_qstats_overlimit(sch);
		return qdisc_drop(skb, sch, to_free);
	}

	flow_cur = fq_classify(skb, q);
	if (flow_cur == NULL) {
		return qdisc_drop(skb, sch, to_free);
	}
	if (unlikely(flow_cur->qlen >= q->flow_plimit)) {
		qdisc_qstats_overlimit(sch);
		return qdisc_drop(skb, sch, to_free);
	}

	/* Fortunately, this is cheap on modern CPUs ;-) */
	now = ktime_get_ns();

	/* If sub-queue was empty, reset delay.
	 * This will make use underestimate the queuing delay, but
	 * the reverse is worse, because the last packet may have been
	 * enqueued a *long* time ago. When we are congested, which is
	 * when PI2 matters, this will be false. Jean II */
	if (flow_cur->qlen == 0)
		flow_cur->pi2.head_ns = now;

	if (udp_is_taildrop_config(sch, skb)) {
		if (udp_try_drop_pkt(sch, flow_cur, skb, now)) {
			/* Stats already updated */
			return qdisc_drop(skb, sch, to_free);
		}
		/* Skip PI2 processing.
		 * This would mess up computation of proba and we could
		 * have PI2 dropping more packets than we want. Jean II */
		goto skip_pi2;
	}

	/* PI2 tail processing */
	/* If more than an update period has elapsed,
	 * we need to recompute the probability. */
	if (now > flow_cur->pi2.tupd_next_ns) {
		pi2_tupdate(sch, flow_cur, now);
		/* tupd_last_ns updated in pi2_tupdate() */
	}

	/* Pseudo random marking of packets based on current
	 * probability. */
	pi2_drop = pi2_try_drop_mark_pkt(sch, flow_cur, skb);
	if (pi2_drop) {
		/* Stats already updated */
		return qdisc_drop(skb, sch, to_free);
	}

skip_pi2:
	/* Set timestamp on packet to measure avg queue delay */
	cb = pi2_skb_cb(skb);
	cb->ts = now;

	/* Schedule this sub-queue if not part of schedule */
	if (fq_flow_is_detached(flow_cur)) {
		fq_robin_add_tail(&q->new_flows, flow_cur);
		if (time_after(jiffies, flow_cur->age + q->flow_refill_delay))
			flow_cur->credit = max_t(u32,
						 flow_cur->credit,
						 q->quantum);
		q->stats.flows_inactive--;
	}

	/* Note: this overwrites flow_cur->age */
	fq_enqueue_skb(sch, flow_cur, skb);

	return NET_XMIT_SUCCESS;
}

/* QDisc want to forward a packet from the queue - head of queue.
 * Version with tail markings using PI2. */
static struct sk_buff *fq_pi2_qdisc_dequeue_tail(struct Qdisc *sch)
{
	struct fq_pi2_sched_data *q = qdisc_priv(sch);
	struct fq_flow_head *head;
	struct sk_buff *skb;
	struct fq_pi2_flow *flow_cur;
	u32	plen;

	if (!sch->q.qlen)
		return NULL;

begin:
	head = &q->new_flows;
	if (!head->first) {
		head = &q->old_flows;
		if (!head->first) {
#ifdef DRR_DEBUG_NOFLOW
			printk_ratelimited(KERN_ERR "FQ: no flow to schedule !\n");
#endif	/* DRR_DEBUG_NOFLOW */
			return NULL;
		}
	}
	flow_cur = head->first;

	if (flow_cur->credit <= 0) {
		flow_cur->credit += q->quantum;
		head->first = flow_cur->next;
		fq_robin_add_tail(&q->old_flows, flow_cur);
#ifdef DRR_STATS_BURST_AVG
		/* If we are still on the same flow as the last packet,
		 * this count as normal scheduling, we just exhausted
		 * our quanta.
		 * If we are on a new flow, this is a wasted schedule.
		 * Jean II */
		if (flow_cur->flow_idx != q->flow_sched_prev)
			q->stats.sched_empty++;
#endif	/* DRR_STATS_BURST_AVG */
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
			q->stats.flows_inactive++;
		}
#ifdef DRR_STATS_BURST_AVG
		q->stats.sched_empty++;
#endif	/* DRR_STATS_BURST_AVG */
		goto begin;
	}

	/* Compute new deficit */
	plen = qdisc_pkt_len(skb);
	flow_cur->credit -= plen;

	qdisc_bstats_update(sch, skb);

	/* Update timestamp of when packet at head was added to the queue.
	 * Because we use the last head instead of the new head, we
	 * are a bit pessimistic, but it simplifies processing. Jean II */
	flow_cur->pi2.head_ns = pi2_skb_cb(skb)->ts;

#ifdef DRR_STATS_BURST_AVG
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
#endif	/* DRR_STATS_BURST_AVG */

	return skb;
}

/* QDisc add a new packet to our queue - tail of queue.
 * Version with head markings using PI2. */
static int fq_pi2_qdisc_enqueue_head(struct sk_buff *	skb,
				     struct Qdisc *	sch,
				     struct sk_buff **	to_free)
{
	struct fq_pi2_sched_data *q = qdisc_priv(sch);
	struct fq_pi2_flow *flow_cur;
	struct pi2_skb_cb *cb;
	s64 now;

	if (unlikely(sch->q.qlen >= sch->limit)) {
		qdisc_qstats_overlimit(sch);
		return qdisc_drop(skb, sch, to_free);
	}

	flow_cur = fq_classify(skb, q);
	if (flow_cur == NULL) {
		return qdisc_drop(skb, sch, to_free);
	}
	if (unlikely(flow_cur->qlen >= q->flow_plimit)) {
		qdisc_qstats_overlimit(sch);
		return qdisc_drop(skb, sch, to_free);
	}

	/* Fortunately, this is cheap on modern CPUs ;-) */
	now = ktime_get_ns();

	if (udp_is_taildrop_config(sch, skb)) {
		if (flow_cur->qlen == 0)
			flow_cur->pi2.head_ns = now;
		if (udp_try_drop_pkt(sch, flow_cur, skb, now)) {
			/* Stats already updated */
			return qdisc_drop(skb, sch, to_free);
		}
	}

	/* Set timestamp on packet to measure avg queue delay */
	cb = pi2_skb_cb(skb);
	cb->ts = now;

	/* Schedule this sub-queue if not part of schedule */
	if (fq_flow_is_detached(flow_cur)) {
		fq_robin_add_tail(&q->new_flows, flow_cur);
		if (time_after(jiffies, flow_cur->age + q->flow_refill_delay))
			flow_cur->credit = max_t(u32,
						 flow_cur->credit,
						 q->quantum);
		q->stats.flows_inactive--;
	}

	/* Note: this overwrites flow_cur->age */
	fq_enqueue_skb(sch, flow_cur, skb);

	/* If we drop early, statistics are not updated when qlen = 0
	 * If packet are just dripping through one by one, the counters
	 * may go up, and are never reduced. Try to fix it here. Jean II */
	if ( (q->pi2_param.reduce_qlen > 0) && qdisc_qlen(sch)) {
#ifdef PI2_DEBUG_REDUCE
		printk_ratelimited(KERN_DEBUG "PI2: reduce qlen %u backlog %u - #late#\n", q->pi2_param.reduce_qlen, q->pi2_param.reduce_backlog);
#endif	/* PI2_DEBUG_REDUCE */

		/* Update statistics of our parents */
		qdisc_tree_reduce_backlog(sch,
					  q->pi2_param.reduce_qlen,
					  q->pi2_param.reduce_backlog);
		q->pi2_param.reduce_qlen = 0;
		q->pi2_param.reduce_backlog = 0;
	}

	return NET_XMIT_SUCCESS;
}

/* QDisc want to forward a packet from the queue - head of queue.
 * Version with tail markings using PI2. */
static struct sk_buff *fq_pi2_qdisc_dequeue_head(struct Qdisc *sch)
{
	struct fq_pi2_sched_data *q = qdisc_priv(sch);
	struct fq_flow_head *head;
	struct sk_buff *skb;
	struct fq_pi2_flow *flow_cur;
	u32	plen;
	bool pi2_drop;
	s64 now;

	if (!sch->q.qlen)
		return NULL;

	/* Fortunately, this is cheap on modern CPUs ;-) */
	now = ktime_get_ns();

begin:
	head = &q->new_flows;
	if (!head->first) {
		head = &q->old_flows;
		if (!head->first) {
#ifdef DRR_DEBUG_NOFLOW
			/* This can happen if we dropped the last packet.
			 * Jean II */
			printk_ratelimited(KERN_ERR "FQ: no flow to schedule !\n");
#endif	/* DRR_DEBUG_NOFLOW */
			return NULL;
		}
	}
	flow_cur = head->first;

	if (flow_cur->credit <= 0) {
		flow_cur->credit += q->quantum;
		head->first = flow_cur->next;
		fq_robin_add_tail(&q->old_flows, flow_cur);
#ifdef DRR_STATS_BURST_AVG
		/* If we are still on the same flow as the last packet,
		 * this count as normal scheduling, we just exhausted
		 * our quanta.
		 * If we are on a new flow, this is a wasted schedule.
		 * Jean II */
		if (flow_cur->flow_idx != q->flow_sched_prev)
			q->stats.sched_empty++;
#endif	/* DRR_STATS_BURST_AVG */
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
			q->stats.flows_inactive++;
		}
#ifdef DRR_STATS_BURST_AVG
		q->stats.sched_empty++;
#endif	/* DRR_STATS_BURST_AVG */
		goto begin;
	}

	if (udp_is_taildrop_config(sch, skb)) {
		/* Update timestamp of when packet at head was added to queue */
		flow_cur->pi2.head_ns = pi2_skb_cb(skb)->ts;
		/* Skip PI2 processing.
		 * This would mess up computation of proba and we could
		 * have PI2 dropping more packets than we want. Jean II */
		goto skip_pi2;
	}

	/* PI2 tail processing */
	/* If more than an update period has elapsed,
	 * we need to recompute the probability. */
	if (now > flow_cur->pi2.tupd_next_ns) {
		/* Update timestamp of when packet at head was added
		 * to the queue. In this version, we use the new head
		 * of queue, so we are exact. Jean II */
		flow_cur->pi2.head_ns = pi2_skb_cb(skb)->ts;

		pi2_tupdate(sch, flow_cur, now);
		/* tupd_last_ns updated in pi2_tupdate() */
	}

	/* Pseudo random marking of packets based on
	 * current probability. */
	pi2_drop = pi2_try_drop_mark_pkt(sch, flow_cur, skb);
	if (pi2_drop) {
		/* Keep track of how much to reduce backlog */
		q->pi2_param.reduce_qlen++;
		q->pi2_param.reduce_backlog += qdisc_pkt_len(skb);

		/* Packet must be dropped, so do it ! */
		qdisc_qstats_drop(sch);
		consume_skb(skb);		/* Same as kfree_skb(skb); */

		/* Get another packet */
		goto begin;
	}

skip_pi2:
	/* Compute new deficit */
	plen = qdisc_pkt_len(skb);
	flow_cur->credit -= plen;

	qdisc_bstats_update(sch, skb);

#ifdef DRR_STATS_BURST_AVG
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
#endif	/* DRR_STATS_BURST_AVG */

	/* First problem :
	 * We can't call qdisc_tree_reduce_backlog() if our qlen is 0,
	 * or HTB crashes. Defer it for next round by testing qlen.
	 * This is actually pretty bad. If packets are just dripping through
	 * one by one, the counters may go up, and are never reduced.
	 * We have an additional workaround in pi2_qdisc_enqueue_head().
	 * As an aside, most other qdisc use this call in enqueue(), so
	 * when qlen is guaranteed to be > 0, or when adding a hidden
	 * fifo, when the diff is zero, so it's not clear there is an
	 * example when notifications are used...
	 *
	 * Second problem :
	 * If NetEm is one of our parents, NetEm is guaranteed to corrupt
	 * its stats (even when qlen > 0). NetEm does not want to synchronise
	 * its stats with its child, so that stat update on NetEm is
	 * incorrect (and corrupt them). When the stats of NetEm are
	 * corrupted, is just blocks all traffic, effectively stopping
	 * the interface. I have not found a workaround for this issue.
	 * Jean II */
	if ( (q->pi2_param.reduce_qlen > 0) && qdisc_qlen(sch)) {
#ifdef PI2_DEBUG_REDUCE
		printk_ratelimited(KERN_DEBUG "PI2: reduce qlen %u backlog %u\n", q->pi2_param.reduce_qlen, q->pi2_param.reduce_backlog);
#endif	/* PI2_DEBUG_REDUCE */

		/* Update statistics of our parents */
		qdisc_tree_reduce_backlog(sch,
					  q->pi2_param.reduce_qlen,
					  q->pi2_param.reduce_backlog);
		q->pi2_param.reduce_qlen = 0;
		q->pi2_param.reduce_backlog = 0;
	}

	return skb;
}

/* ----------------------- QDISC MANAGEMENT ----------------------- */

static void fq_rehash(struct fq_pi2_sched_data *q,
		      struct rb_root *old_array, u32 old_log,
		      struct rb_root *new_array, u32 new_log)
{
	struct rb_node *op, **np, *parent;
	struct rb_root *oroot, *nroot;
	struct fq_pi2_flow *of, *nf;
	int fcnt = 0;
	u32 idx;

	for (idx = 0; idx < (1U << old_log); idx++) {
		oroot = &old_array[idx];
		while ((op = rb_first(oroot)) != NULL) {
			rb_erase(op, oroot);
			of = rb_entry(op, struct fq_pi2_flow, hash_node);
			if (fq_gc_candidate(of)) {
				fcnt++;
				kmem_cache_free(fq_pi2_flow_cachep, of);
				continue;
			}
			nroot = &new_array[hash_32(of->flow_idx, new_log)];

			np = &nroot->rb_node;
			parent = NULL;
			while (*np) {
				parent = *np;

				nf = rb_entry(parent, struct fq_pi2_flow,
					      hash_node);
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
	struct fq_pi2_sched_data *q = qdisc_priv(sch);
	struct rb_root *array;
	void *old_hash_root;
	u32 buckets;
	u32 idx;

	if (q->hash_root && log == q->hash_trees_log)
		return 0;

	buckets = 1U << log;

	/* If XPS was setup, we can allocate memory on right NUMA node */
	array = kvmalloc_node(sizeof(struct rb_root) * buckets,
			      GFP_KERNEL | __GFP_RETRY_MAYFAIL,
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

static const struct nla_policy fq_pi2_policy[TCA_FQ_PI2_MAX + 1] = {
	[TCA_FQ_PI2_PLIMIT]		= { .type = NLA_U32 },
	[TCA_FQ_PI2_FLOW_PLIMIT]	= { .type = NLA_U32 },
	[TCA_FQ_PI2_QUANTUM]		= { .type = NLA_U32 },
	[TCA_FQ_PI2_INITIAL_QUANTUM]	= { .type = NLA_U32 },
	[TCA_FQ_PI2_FLOW_REFILL_DELAY]	= { .type = NLA_U32 },
	[TCA_FQ_PI2_BUCKETS_LOG]	= { .type = NLA_U32 },
	[TCA_FQ_PI2_HASH_MASK]		= { .type = NLA_U32 },
	[TCA_FQ_PI2_TARGET]		= { .type = NLA_U32 },
	[TCA_FQ_PI2_TUPDATE]		= { .type = NLA_U32 },
	[TCA_FQ_PI2_ALPHA]		= { .type = NLA_U32 },
	[TCA_FQ_PI2_BETA]		= { .type = NLA_U32 },
	[TCA_FQ_PI2_COUPLING]		= { .type = NLA_U32 },
	[TCA_FQ_PI2_FLAGS]		= { .type = NLA_U32 },
	[TCA_FQ_PI2_MON_FL_PORT]	= { .type = NLA_U16 },
	[TCA_FQ_PI2_UDP_PLIMIT]		= { .type = NLA_U32 },
};

static void pi2_aqm_param_update(struct fq_pi2_sched_data *q)
{
	u64	alpha_nm40;
	u64	beta_nm16;
	u64	proba_max;

	/* Sanity checks */

	/* If target delay is invalid, stop now, to avoid divide by zero.
	 * In theory, there is no way this can happen... */
	if (q->pi2_config.target_ns < 0)
		q->pi2_config.target_ns = 0LL;
	if (!q->pi2_config.target_ns) {
		printk_ratelimited(KERN_ERR "FQ_PI2: target is 0 !\n");
		return;
	}
	if (!q->pi2_config.coupling) {
		printk_ratelimited(KERN_ERR "FQ_PI2: coupling is 0 !\n");
		return;
	}

	/* Help speed up/reduce computations in critical path */

	/* The original PI2 encode coupling as a simple integer, and
	 * the default value is 2. This does not allow much flexibility,
	 * and no values between 1 and 2 can be encoded. In this
	 * implementation, we use encoding to 1/256th for coupling,
	 * like it's done for alpha and beta.
	 *
	 * Compute the maximum raw probability.
	 * Because we want the probability for Scalable TCP to max out a 1.0,
	 * we divide 1.0 by the coupling factor.
	 * We can't have raw probability greater than 1.0 either, this would
	 * overflow 32bits, and that would make classical probability hit 0.5,
	 * so if coupling is lower than 1.0, then use max...
	 * Jean II */
	proba_max = ( ( PROBA_NORMA * ALPHA_BETA_SCALE
			/ (u64) q->pi2_config.coupling )
		      - 1 );
	if ( (q->pi2_config.coupling <= ALPHA_BETA_SCALE)
	     || (proba_max >= PROBA_MAX) )
		q->pi2_param.proba_max = (u32) PROBA_MAX;
	else {
		q->pi2_param.proba_max = (u32) proba_max;
	}

	/* In the algorithm, alpha and beta are between 0 and 10 with typical
	 * value for alpha as 0.3125 and beta as 3.125. Those values are higher
	 * that those for PIE, because they will be squared.
	 * Please see paper for details.
	 * In this implementation, like for PI2, we use values in fixed point
	 * passed from user space to represent this. Also, alpha and beta have
	 * unit of HZ and need to be scaled before they can used to update
	 * probability.
	 *
	 * With PI2, there is no need to have adjustements based on
	 * dropping mode due to the squaring of probability.
	 * So, we can precompute the proper values here, and save
	 * computation in the critical path.
	 *
	 * Computations are done in fixed point and renormalised.
	 * Original alpha and beta are encoded normalised at 256 (2^8),
	 * so should be between 0 and 2560, in multiples of 1/256th.
	 * We shift the precomputed values of alpha and beta by 16 bits
	 * (well, effective 16-8) to keep precision in computations
	 * (no bits left behind).
	 * The original formula uses timing/delay expressed in seconds,
	 * but we do out computations in nanoseconds. 
	 * The final probability is between 0 and 1 (duh), and encoded
	 * normalised at 2^32 (see PROBA_MAX).
	 *
	 * Compared to other implementations of PIE/PI2, we implement time
	 * normalisation so that the impact of alpha and beta are independant
	 * of the times target delay and tupdates.
	 * We use alpha and beta for target_delay=1ms and tupdate=1ms.
	 * We rescale them to the actual timing configured by user.
	 * For smaller target delay, we want faster reaction (higher slope),
	 * so we scale alpha and beta with the inverse of target_delay.
	 * For tupdate, only the integration is impacted by the computation
	 * interval, so we scale alpha with tupdate. We actually scale by
	 * the ratio of tupdate/target to make it time independant.
	 *
	 * The variable time normalisation constrain the range of target delay
	 * (and tupdate) we can use before we loose bits and precision on
	 * either side of 32 bits. Thanks to the order of operations and
	 * the shift by 16 bits, computations currently cover the range 100us
	 * to 1s for target, which should be appropriate/enough.
	 * Jean II
	 */
	alpha_nm40 = ( (u64) q->pi2_config.alpha
		       * ( PI2_TARGET_REF * PI2_TARGET_REF
			   / PI2_TUPDATE_REF
			   * ( (PROBA_NORMA * NM16_SCALE) / ALPHA_BETA_SCALE
			       / NSEC_PER_SEC ) )
		       / (u64) q->pi2_config.target_ns
		       * (u64) NM24_SCALE
		       / (u64) q->pi2_config.target_ns );
	beta_nm16 = ( (u64) q->pi2_config.beta
		      * ( PI2_TARGET_REF
			  * ( (PROBA_NORMA * NM16_SCALE) / ALPHA_BETA_SCALE
			      / NSEC_PER_SEC ) )
		      / (u64) q->pi2_config.target_ns );
	q->pi2_param.alpha_nm40 = (u32) alpha_nm40;
	q->pi2_param.beta_nm16 = (u32) beta_nm16;

#ifdef PI2_DEBUG_CONFIG
	printk(KERN_DEBUG "PI2: alpha_nm40 %u ; beta_nm16 %u ; proba_max %u\n", q->pi2_param.alpha_nm40, q->pi2_param.beta_nm16, q->pi2_param.proba_max);
#endif	/* PI2_DEBUG_CONFIG */
}

static int fq_pi2_qdisc_change(struct Qdisc *sch,
			       struct nlattr *opt,
			       struct netlink_ext_ack *extack)
{
	struct fq_pi2_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_FQ_PI2_MAX + 1];
	u32		target_us;
	int err, drop_count = 0;
	unsigned drop_len = 0;
	u32 fq_log;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_FQ_PI2_MAX, opt,
					  fq_pi2_policy, NULL);
	if (err < 0)
		return err;

	/* Check target before locking */
	if (tb[TCA_FQ_PI2_TARGET]) {
		target_us = nla_get_u32(tb[TCA_FQ_PI2_TARGET]);
		/* Can't be negative... */
		if (target_us == 0)
			return -EINVAL;
        }

	sch_tree_lock(sch);

	fq_log = q->hash_trees_log;

	if (tb[TCA_FQ_PI2_BUCKETS_LOG]) {
		u32 nval = nla_get_u32(tb[TCA_FQ_PI2_BUCKETS_LOG]);

		if (nval >= 1 && nval <= ilog2(256*1024))
			fq_log = nval;
		else
			err = -EINVAL;
	}
	if (tb[TCA_FQ_PI2_PLIMIT])
		sch->limit = nla_get_u32(tb[TCA_FQ_PI2_PLIMIT]);

	if (tb[TCA_FQ_PI2_FLOW_PLIMIT])
		q->flow_plimit = nla_get_u32(tb[TCA_FQ_PI2_FLOW_PLIMIT]);

	if (tb[TCA_FQ_PI2_QUANTUM]) {
		u32 quantum = nla_get_u32(tb[TCA_FQ_PI2_QUANTUM]);

		if (quantum > 0 && quantum <= (1 << 20)) {
			q->quantum = quantum;
		} else {
			NL_SET_ERR_MSG_MOD(extack, "invalid quantum");
			err = -EINVAL;
		}
	}

	if (tb[TCA_FQ_PI2_INITIAL_QUANTUM])
		q->initial_quantum = nla_get_u32(tb[TCA_FQ_PI2_INITIAL_QUANTUM]);

	if (tb[TCA_FQ_PI2_FLOW_REFILL_DELAY]) {
		u32 usecs_delay = nla_get_u32(tb[TCA_FQ_PI2_FLOW_REFILL_DELAY]) ;

		q->flow_refill_delay = usecs_to_jiffies(usecs_delay);
	}

	if (tb[TCA_FQ_PI2_HASH_MASK])
		q->hash_mask = nla_get_u32(tb[TCA_FQ_PI2_HASH_MASK]);

	if (!err) {

		sch_tree_unlock(sch);
		err = fq_hash_resize(sch, fq_log);
		sch_tree_lock(sch);
	}

	if (tb[TCA_FQ_PI2_TARGET]) {
		/* Extracted and checked above */
		q->pi2_config.target_ns = ((u64) target_us) * NSEC_PER_USEC;
        }

	if (tb[TCA_FQ_PI2_TUPDATE]) {
		u32 tupdate_us = nla_get_u32(tb[TCA_FQ_PI2_TUPDATE]);
		/* Clamp at 1s, which is plenty enough.
		 * This is needed to avoid overflowing 32 bits. */
		if (tupdate_us > 1000000)
			tupdate_us = 1000000;
		q->pi2_config.tupdate_ns = (u32) (tupdate_us * NSEC_PER_USEC);
	} else {
		if (tb[TCA_FQ_PI2_TARGET]) {
			u64 tupdate_ns;
			/* Use value of the target delay to get smooth enough
			 * reaction with minimised overhead. Clamp to 1s. */
			if (q->pi2_config.target_ns > 1000000000LL)
				tupdate_ns = 1000000000LL;
			else
				tupdate_ns = q->pi2_config.target_ns;
			q->pi2_config.tupdate_ns = (u32) tupdate_ns;
		}
	}

	if (tb[TCA_FQ_PI2_ALPHA])
                q->pi2_config.alpha = nla_get_u32(tb[TCA_FQ_PI2_ALPHA]);
	if (tb[TCA_FQ_PI2_BETA])
                q->pi2_config.beta = nla_get_u32(tb[TCA_FQ_PI2_BETA]);
	if (tb[TCA_FQ_PI2_COUPLING]) {
                q->pi2_config.coupling = nla_get_u32(tb[TCA_FQ_PI2_COUPLING]);
		/* Prevent divide by zero. Also, make sure it's sensible */
		if (q->pi2_config.coupling < (ALPHA_BETA_SCALE / 4))
		    q->pi2_config.coupling = (ALPHA_BETA_SCALE / 4);
		else if (q->pi2_config.coupling > (16 * ALPHA_BETA_SCALE))
		    q->pi2_config.coupling = (16 * ALPHA_BETA_SCALE);
	}
	if (tb[TCA_FQ_PI2_FLAGS])
                q->pi2_config.flags = nla_get_u32(tb[TCA_FQ_PI2_FLAGS]);

#if defined(PI2_STATS_FLOW_QLEN) || defined(PI2_STATS_FLOW_QDELAY) || defined(PI2_STATS_FLOW_MARK)
	if (tb[TCA_FQ_PI2_MON_FL_PORT])
		q->mon_fl_port = nla_get_u16(tb[TCA_FQ_PI2_MON_FL_PORT]);
#endif	/* PI2_STATS_FLOW_QLEN || PI2_STATS_FLOW_QDELAY || PI2_STATS_FLOW_MARK */
#ifdef PI2_UDP_TAILDROP_PACKETS
	if (tb[TCA_FQ_PI2_UDP_PLIMIT])
		q->udp_plimit = nla_get_u32(tb[TCA_FQ_PI2_UDP_PLIMIT]);
#endif	/* PI2_UDP_TAILDROP_PACKETS */

	/* Update internal parameters */
	pi2_aqm_param_update(q);

	/* Drop excess packets if new limit is lower */
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = fq_pi2_qdisc_dequeue_tail(sch);

		if (!skb)
			break;
		drop_len += qdisc_pkt_len(skb);
		rtnl_kfree_skbs(skb, skb);
		drop_count++;
	}
	qdisc_tree_reduce_backlog(sch, drop_count, drop_len);

	sch_tree_unlock(sch);

#ifdef DRR_DEBUG_CONFIG
	printk(KERN_DEBUG "DRR: plimit %d; logs %d; mask 0x%X; flow_plimit %d; quantum %d\n", sch->limit, q->hash_trees_log, q->hash_mask, q->flow_plimit, q->quantum);
#endif	/* DRR_DEBUG_CONFIG */

	return err;
}

static int fq_pi2_qdisc_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct fq_pi2_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;
	u32 target_us;
	u32 tupdate_us;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_FQ_PI2_PLIMIT, sch->limit) ||
	    nla_put_u32(skb, TCA_FQ_PI2_FLOW_PLIMIT, q->flow_plimit) ||
	    nla_put_u32(skb, TCA_FQ_PI2_QUANTUM, q->quantum) ||
	    nla_put_u32(skb, TCA_FQ_PI2_INITIAL_QUANTUM, q->initial_quantum) ||
	    nla_put_u32(skb, TCA_FQ_PI2_FLOW_REFILL_DELAY,
			jiffies_to_usecs(q->flow_refill_delay)) ||
	    nla_put_u32(skb, TCA_FQ_PI2_HASH_MASK, q->hash_mask) ||
	    nla_put_u32(skb, TCA_FQ_PI2_BUCKETS_LOG, q->hash_trees_log))
		goto nla_put_failure;

	/* PI2 attibutes */
	target_us =  (u32) (q->pi2_config.target_ns / NSEC_PER_USEC);
	if (nla_put_u32(skb, TCA_FQ_PI2_TARGET, target_us))
		goto nla_put_failure;
	tupdate_us = (u32) (q->pi2_config.tupdate_ns / NSEC_PER_USEC);
	/* Hide messy details unless needed. */
	if ( (tupdate_us != target_us)
	     || (q->pi2_config.alpha != PI2_ALPHA_DEFLT)
	     || (q->pi2_config.beta != PI2_BETA_DEFLT)
	     || (q->pi2_config.coupling != PI2_COUPL_DEFLT) ) {
		if (nla_put_u32(skb, TCA_FQ_PI2_TUPDATE, tupdate_us))
			goto nla_put_failure;
		if (nla_put_u32(skb, TCA_FQ_PI2_ALPHA, q->pi2_config.alpha))
			goto nla_put_failure;
		if (nla_put_u32(skb, TCA_FQ_PI2_BETA, q->pi2_config.beta))
			goto nla_put_failure;
		if (nla_put_u32(skb, TCA_FQ_PI2_COUPLING, q->pi2_config.coupling))
			goto nla_put_failure;
	}
	if (nla_put_u32(skb, TCA_FQ_PI2_FLAGS, q->pi2_config.flags))
		goto nla_put_failure;
#if defined(PI2_STATS_FLOW_QLEN) || defined(PI2_STATS_FLOW_QDELAY) || defined(PI2_STATS_FLOW_MARK)
	if ( q->mon_fl_port != 0 ) {
		if (nla_put_u16(skb, TCA_FQ_PI2_MON_FL_PORT, q->mon_fl_port))
			goto nla_put_failure;
	}
#endif	/* PI2_STATS_FLOW_QLEN || PI2_STATS_FLOW_QDELAY || PI2_STATS_FLOW_MARK */
#ifdef PI2_UDP_TAILDROP_PACKETS
	if ( q->udp_plimit != q->flow_plimit) {
		if (nla_put_u32(skb, TCA_FQ_PI2_UDP_PLIMIT, q->udp_plimit))
			goto nla_put_failure;
	}
#endif	/* PI2_UDP_TAILDROP_PACKETS */

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int fq_pi2_qdisc_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct fq_pi2_sched_data *q = qdisc_priv(sch);
	struct tc_fq_pi2_xstats st;

	/* Copy most stats */
	memcpy(&st, &q->stats, sizeof(st));
	/* Special stats */
	st.fl_qdelay_us		= (__u32) ( q->pi2_param.fl_qdelay_ns
					    / NSEC_PER_USEC );
	st.fl_qdelay_peak_us	= (__u32) ( q->pi2_param.fl_qdelay_peak_ns
					    / NSEC_PER_USEC );
  
	/* Reset some of the statistics, unless disabled */
	if ( ! (q->pi2_config.flags & PI2F_PEAK_NORESET) ) {
		q->stats.burst_peak = 0;
		q->stats.fl_qlen_peak = 0;
		q->stats.fl_backlog_peak = 0;
		q->stats.fl_proba_peak = 0;
		q->pi2_param.fl_qdelay_peak_ns = 0LL;
	}

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static int fq_pi2_qdisc_init(struct Qdisc *sch,
			     struct nlattr *opt,
			     struct netlink_ext_ack *extack)
{
	struct fq_pi2_sched_data *q = qdisc_priv(sch);
	int err;

#ifdef DRR_DEBUG_CONFIG
	printk(KERN_DEBUG "DRR: sizeof(fq_pi2_flow) %lu\n", sizeof(struct fq_pi2_flow));
#endif	/* DRR_DEBUG_CONFIG */

	sch->limit		= 10000;
	q->flow_plimit		= 100;
	q->quantum		= 2 * psched_mtu(qdisc_dev(sch));
	q->initial_quantum	= 10 * psched_mtu(qdisc_dev(sch));
	q->flow_refill_delay	= msecs_to_jiffies(40);
	q->new_flows.first	= NULL;
	q->old_flows.first	= NULL;
	q->hash_root		= NULL;
	q->hash_trees_log	= ilog2(1024);
	q->hash_mask		= 1024 - 1;

	/* PI2 config */
	q->pi2_config.alpha = PI2_ALPHA_DEFLT;
	q->pi2_config.beta = PI2_BETA_DEFLT;
	q->pi2_config.target_ns = 15 * NSEC_PER_MSEC;	/* 15 ms - from dualpi2 */
	q->pi2_config.tupdate_ns = q->pi2_config.target_ns;
	q->pi2_config.coupling = PI2_COUPL_DEFLT;	/* 2.0 - from dualpi2 */
	q->pi2_config.flags = 0x0;		/* Only drop */
	/* PI2 params */
	q->pi2_param.reduce_qlen = 0;
	q->pi2_param.reduce_backlog = 0;
	q->pi2_param.fl_qdelay_ns = 0LL;
	q->pi2_param.fl_qdelay_peak_ns = 0LL;
	pi2_aqm_param_update(q);

#if defined(PI2_STATS_FLOW_QLEN) || defined(PI2_STATS_FLOW_QDELAY) || defined(PI2_STATS_FLOW_MARK) || defined(DRR_DEBUG_FLOW_NEW)
	q->mon_fl_port = 0;
#endif	/* PI2_STATS_FLOW_QLEN || PI2_STATS_FLOW_QDELAY || PI2_STATS_FLOW_MARK || DRR_DEBUG_FLOW_NEW */
#ifdef PI2_UDP_TAILDROP_PACKETS
	q->udp_plimit = q->flow_plimit;
#endif	/* PI2_UDP_TAILDROP_PACKETS */

	if (opt)
		err = fq_pi2_qdisc_change(sch, opt, extack);
	else
		err = fq_hash_resize(sch, q->hash_trees_log);

	return err;
}

static void fq_pi2_qdisc_reset(struct Qdisc *sch)
{
	struct fq_pi2_sched_data *q = qdisc_priv(sch);
	struct rb_root *root;
	struct rb_node *p;
	struct fq_pi2_flow *flow_cur;
	unsigned int idx;

	sch->q.qlen = 0;
	sch->qstats.backlog = 0;

	/* PI2 params */
	q->pi2_param.reduce_qlen = 0;
	q->pi2_param.reduce_backlog = 0;
	q->pi2_param.fl_qdelay_ns = 0LL;
	q->pi2_param.fl_qdelay_peak_ns = 0LL;

	/* Stats */
	q->stats.flows		= 0;
	q->stats.flows_inactive	= 0;
	q->stats.no_mark	= 0;
	q->stats.drop_mark	= 0;
	q->stats.ecn_mark	= 0;
	q->stats.sce_mark	= 0;
	q->stats.burst_peak	= 0;
	q->stats.burst_avg	= 0;
	q->stats.sched_empty	= 0;
	q->stats.fl_qlen	= 0;
	q->stats.fl_backlog	= 0;
	q->stats.fl_qlen_peak	= 0;
	q->stats.fl_backlog_peak = 0;
	q->stats.fl_proba	= 0;
	q->stats.fl_proba_peak	= 0;
	q->stats.fl_qdelay_us	= 0;
	q->stats.fl_qdelay_peak_us = 0;
	q->stats.fl_no_mark	= 0;
	q->stats.fl_drop_mark	= 0;
	q->stats.fl_ecn_mark	= 0;
	q->stats.fl_sce_mark	= 0;

#ifdef STFQ_STATS_BURST_AVG
	q->flow_sched_prev	= 0;
	q->burst_cur		= 0;
#endif	/* STFQ_STATS_BURST_AVG */
#if defined(PI2_STATS_FLOW_QLEN) || defined(PI2_STATS_FLOW_QDELAY) || defined(PI2_STATS_FLOW_MARK) || defined(DRR_DEBUG_FLOW_NEW)
	q->mon_fl_idx		= 0xFFFFFFFF;
#endif	/* PI2_STATS_FLOW_QLEN || PI2_STATS_FLOW_QDELAY || PI2_STATS_FLOW_MARK || DRR_DEBUG_FLOW_NEW */

	q->new_flows.first	= NULL;
	q->old_flows.first	= NULL;

	if (!q->hash_root)
		return;

	for (idx = 0; idx < (1U << q->hash_trees_log); idx++) {
		root = &q->hash_root[idx];
		while ((p = rb_first(root)) != NULL) {
			flow_cur = rb_entry(p, struct fq_pi2_flow, hash_node);
			rb_erase(p, root);

			fq_flow_purge(flow_cur);

			kmem_cache_free(fq_pi2_flow_cachep, flow_cur);
		}
	}
}

static void fq_pi2_qdisc_destroy(struct Qdisc *sch)
{
	struct fq_pi2_sched_data *q = qdisc_priv(sch);

	fq_pi2_qdisc_reset(sch);
	fq_hash_free(q->hash_root);
}

static struct Qdisc_ops fq_pi2_tail_qdisc_ops __read_mostly = {
	.id		=	"fq_pi2",
	.priv_size	=	sizeof(struct fq_pi2_sched_data),

	.enqueue	=	fq_pi2_qdisc_enqueue_tail,
	.dequeue	=	fq_pi2_qdisc_dequeue_tail,
	.peek		=	qdisc_peek_dequeued,
	.init		=	fq_pi2_qdisc_init,
	.reset		=	fq_pi2_qdisc_reset,
	.destroy	=	fq_pi2_qdisc_destroy,
	.change		=	fq_pi2_qdisc_change,
	.dump		=	fq_pi2_qdisc_dump,
	.dump_stats	=	fq_pi2_qdisc_dump_stats,
	.owner		=	THIS_MODULE,
};

static struct Qdisc_ops fq_pi2_head_qdisc_ops __read_mostly = {
	.id		=	"fq_pi2_head",
	.priv_size	=	sizeof(struct fq_pi2_sched_data),

	.enqueue	=	fq_pi2_qdisc_enqueue_head,
	.dequeue	=	fq_pi2_qdisc_dequeue_head,
	.peek		=	qdisc_peek_dequeued,
	.init		=	fq_pi2_qdisc_init,
	.reset		=	fq_pi2_qdisc_reset,
	.destroy	=	fq_pi2_qdisc_destroy,
	.change		=	fq_pi2_qdisc_change,
	.dump		=	fq_pi2_qdisc_dump,
	.dump_stats	=	fq_pi2_qdisc_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init fq_module_init(void)
{
	int ret;

	fq_pi2_flow_cachep = kmem_cache_create("fq_pi2_flow_cache",
					       sizeof(struct fq_pi2_flow),
					       0, 0, NULL);
	if (!fq_pi2_flow_cachep)
		return -ENOMEM;

	ret = register_qdisc(&fq_pi2_tail_qdisc_ops);
	if (!ret) {
		ret = register_qdisc(&fq_pi2_head_qdisc_ops);
		if (ret)
			unregister_qdisc(&fq_pi2_tail_qdisc_ops);
	}
	if (ret)
		kmem_cache_destroy(fq_pi2_flow_cachep);
	return ret;
}

static void __exit fq_module_exit(void)
{
	unregister_qdisc(&fq_pi2_head_qdisc_ops);
	unregister_qdisc(&fq_pi2_tail_qdisc_ops);
	kmem_cache_destroy(fq_pi2_flow_cachep);
}

module_init(fq_module_init)
module_exit(fq_module_exit)

MODULE_DESCRIPTION("Deficit Round Robin (DRR) scheduler with PI2 AQM");
MODULE_AUTHOR("Jean Tourrilhes");
MODULE_LICENSE("GPL");
