// SPDX-License-Identifier: GPL-2.0-only
/*
 * net/sched/sch_pi2.c
 *
 * Authors:	Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 *
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
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>

/*
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
 * Jean II */

#define PI2_ECN_IS_ECT1
//#define PI2_DEBUG_CONFIG
//#define PI2_DEBUG_COMPUTE
//#define PI2_DEBUG_PROBA
//#define PI2_DEBUG_TUPDATE
#define PI2_DEBUG_REDUCE
//#define PI2_BOB_BRISCOE
//#define PI2_DEBUG_RAPID

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

#ifndef TCA_PI2_MAX
/* PI2 */
enum {
	TCA_PI2_UNSPEC,
	TCA_PI2_LIMIT,		/* limit of total number of packets in queue */
	TCA_PI2_TARGET,		/* PI2 target queuing delay (us) */
	TCA_PI2_TUPDATE,	/* Time between proba updates (us) */
	TCA_PI2_ALPHA,		/* Integral coefficient */
	TCA_PI2_BETA,		/* Proportional coefficient */
	TCA_PI2_COUPLING,	/* Coupling between scalable and classical */
	TCA_PI2_PI2_FLAGS,	/* See flags below */
	__TCA_PI2_MAX
};

#define TCA_PI2_MAX   (__TCA_PI2_MAX - 1)

/* PI2_FLAGS */
#define PI2F_MARK_ECN		0x0001	/* Mark ECT_0 pkts with Classical ECN */
#define PI2F_MARK_SCE		0x0002	/* Mark ECT_1 pkts with Scalable-ECN */
#define PI2F_OVERLOAD_ECN	0x0004	/* Keep doing ECN/SCE on overload */
#define PI2F_RANDOM_MARK	0x0008	/* Randomise marking, like RED */
#define PI2F_BYTEMODE		0x0010	/* Bytemode - unimplemented */
#define PI2F_PEAK_NORESET	0x0020	/* Don't reset peak statistics */
#define PI2F_RAPID_SOJOURN	0x0000	/* QDelay based on full sojourn */
#define PI2F_RAPID_SERVICE	0x0100	/* QDelay based on service time */
#define PI2F_RAPID_SCALED	0x0200	/* QDelay based on scaled sojourn */

#define PI2F_MASK_OVERLOAD	(~0x3)	/* Mask out two lowest bits */
#define PI2F_MASK_RAPID		(0x0300)	/* Rapid signalling */

#endif

/* Stats exported to userspace */
struct tc_pi2_xstats {
	__u32	no_mark;	/* Enqueue events (pkts / gso_segs) */
	__u32	drop_mark;	/* packets dropped due to PI2 AQM */
	__u32	ecn_mark;       /* Packets marked with ECN, classic TCP */
	__u32	sce_mark;       /* Packets marked with ECN, scalable TCP */
	__u32	proba;		/* Current raw probability */
	__u32	proba_peak;	/* Maximum raw probability experienced */
	__u32	delay_us;	/* Current estimated queue delay */
	__u32	delay_peak_us;	/* Maximum queuing delay experienced */
};

/* Parameters configured from user space */
struct pi2_config {
	s64	target_ns;	/* Target queue delay (in ns) */
	u32	tupdate_ns;	/* Update timer frequency (in ns) */
	u32	alpha;		/* alpha and beta are between 0 and 32... */
	u32	beta;		/* ...and are used for shift relative to 1 */
	u32	coupling;	/* Coupling rate factor between
				 * Classic TCP and Scalable TCP */
	u32	pi2_flags;	/* Bitmask of PI2F_XXX flags */
};

/* Internal state and helpful variables */
struct pi2_param {
	s64	tupd_next_ns;	/* Next time to do a probability update */
	u64	overload_ns;	/* When overload condition will start */
	u64	head_ns;	/* When last head of queue was enqueue'd */
	s64	qdelay_ns;	/* Last computed queuing delay */
	s64	qdelay_peak_ns;	/* Maximum queuing delay experienced */
	u32	alpha_nm40;	/* Scaled by target_ns, shifted 40 bits */
	u32	beta_nm16;	/* Scaled by target_ns, shifted 16 bits */
	u32	proba_2;	/* Probability for Classical TCP. */
	u32	proba_cpl;	/* Probability for Scalable TCP. */
	u32	proba_max;	/* Maximum raw probability. */
	u32	pi2_flags_live;	/* Bitmask of PI2F_XXX flags */
	u32	recur_classic;	/* Mark counter for classical TCP */
	u32	recur_scalable;	/* Mark counter for scalable TCP */
	u32	reduce_qlen;	/* Pending qlen to be reduced on parent */
	u32	reduce_backlog;	/* Pending backlog to be reduced on parent */
#ifdef PI2_BOB_BRISCOE
	u64	dequeue_last_ns; /* Last time we dequeued a packet */
	u64	service_avg_ns;	/* Average service time */
	u32	skb_len_avg;	/* Average packet length */
	u32	dequeue_qlen;	/* qlen last time we dequeued a packet */
#endif	/* PI2_BOB_BRISCOE */
};

/* private data for the Qdisc */
struct pi2_sched_data {
	struct pi2_config	config;
	struct pi2_param	param;
	struct tc_pi2_xstats	stats;
	struct Qdisc *		sch;		/* Back pointer to this qdisc */
};

struct pi2_skb_cb {
	u64 ts;			/* Timestamp at enqueue */
	u32 backlog;		/* Queue length (in bytes) at enqueue */
};

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

static void pi2_calculate_proba(struct Qdisc *sch, s64 qdelay_ns,
				s64 now, s64 elapsed_ns)
{
	struct pi2_sched_data * aqm = qdisc_priv(sch);
	s64	qdelay_old_ns = aqm->param.qdelay_ns;
        s64	delta;		/* Change +/- in probability */
        s64	delta_alpha;	/* Change +/- in probability from alpha */
        s64	delta_beta;	/* Change +/- in probability from beta */
	s64	proba;		/* New probability */
	s64	proba_cpl;	/* New probability, multiplied by coupling */
	s64	proba_2;	/* New probability, squared */

	/* Keep track of largest delay */
	if (qdelay_ns > aqm->param.qdelay_peak_ns)
		aqm->param.qdelay_peak_ns = qdelay_ns;
	//if (qdisc_qlen(sch) > q->stats.maxq)
	//	aqm->stats.maxq = qdisc_qlen(sch);

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
	delta_alpha = ( ( ( (qdelay_ns - aqm->config.target_ns)
			    * aqm->param.alpha_nm40 )
			  / NM24_SCALE )
			* elapsed_ns);
	delta_beta = ( (qdelay_ns - qdelay_old_ns) * aqm->param.beta_nm16 );
	delta = ( delta_alpha + delta_beta ) / NM16_SCALE;

	proba = (s64) aqm->stats.proba + delta;
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
	if (proba >= aqm->param.proba_max) {
		proba = aqm->param.proba_max;

		/* Check how we handle overload conditions */
		if ( ! (aqm->config.pi2_flags & PI2F_OVERLOAD_ECN) ) {
		    if ( aqm->param.overload_ns == 0LL)
			/* First time in overload, wait a few periods
			 * before doing anything...
			 * We want to wait for a duration greater than target
			 * before going in overload mode. TCP is bursty and can
			 * be expected to dump on us an amount of data at least
			 * equal to target all at once... Jean II */
			aqm->param.overload_ns = now + (aqm->config.target_ns/4);
		    else {
			/* Declare overload condition if we have a few periods
			 * at max proba. TCP is bursty, waiting a bit enables
			 * ignore some transients. Jean II */
			if ( now > aqm->param.overload_ns )
			    /* Overload condition, disable ECN & SCE markings */
			    aqm->param.pi2_flags_live &= PI2F_MASK_OVERLOAD;
		    }
		}
	} else {
		/* We don't like negative probability either, especially
		 * that we will cast to unsigned... Jean II */
		if (proba < 0)
			proba = 0;

		/* No overload condition, re-enable ECN & SCE markings */
		aqm->param.pi2_flags_live = aqm->config.pi2_flags;
		aqm->param.overload_ns = 0LL;
	}

	/* Cast to 32 bits, save for next time */
	aqm->stats.proba = (u32) proba;

	/* Keep track of maximum proba */
	if (aqm->stats.proba > aqm->stats.proba_peak)
		aqm->stats.proba_peak = aqm->stats.proba;

	/* Compute the probability for the Scalable TCP.
	 * Multiply by the raw probabiloty by coupling factor
	 * between scalable TCP and classic TCP. */
	proba_cpl = proba * aqm->config.coupling / ALPHA_BETA_SCALE;
	aqm->param.proba_cpl = (u32) proba_cpl;

	/* Compute probability for classical TCP
	 * Do the square of the raw probability. Normalised at 2^32. */
	proba_2 = proba * proba / PROBA_NORMA;
	aqm->param.proba_2 = (u32) proba_2;

#ifdef PI2_DEBUG_PROBA
        printk_ratelimited(KERN_DEBUG "PI2: proba*c %lld = 0.%03lld ; proba^2 %lld = 0.%03lld\n", proba_cpl, proba_cpl * 1000 / PROBA_NORMA, proba_2, proba_2 * 1000 / PROBA_NORMA);
#endif	/* PI2_DEBUG_PROBA */

	/* Save for next time as well */
	aqm->param.qdelay_ns = qdelay_ns;
}

static void pi2_tupdate(struct Qdisc *sch, s64 now)
{
	struct pi2_sched_data * aqm = qdisc_priv(sch);
	s64	tupd_elapsed;
	s64	qdelay_ns;

	/* Figure out how many tupdate periods have elapsed. Jean II */
	tupd_elapsed = now - aqm->param.tupd_next_ns + aqm->config.tupdate_ns;

	/* Keep track of next time tupdate will need to happen.
	 * This will drift over time, and won't tick at precisely tupdate
	 * period. It does not matter in practice because we use the exact
	 * time elapsed in computations. Jean II */
	aqm->param.tupd_next_ns = now + ((s64) aqm->config.tupdate_ns);

#ifdef PI2_DEBUG_TUPDATE
        printk_ratelimited(KERN_DEBUG "PI2: tupd %lld (%d) ; now %lld ; next %lld\n", tupd_elapsed, aqm->config.tupdate_ns, now, aqm->param.tupd_next_ns);
#endif	/* PI2_DEBUG_TUPDATE */

	/* Estimate the current delay of the queue.
	 * We compare when the packet at the head of the queue was enqueued
	 * to the time now. As we use the lastest head of the queue instead
	 * of the current head of the queue, we are a bit pessimistic.
	 * We need to make sure head_ns is always valid.
	 * Jean II */
	qdelay_ns = now - aqm->param.head_ns;

	/* Compute new probability */
        pi2_calculate_proba(sch, qdelay_ns, now, tupd_elapsed);
}

static bool pi2_try_drop_early(struct Qdisc *sch, struct sk_buff *skb)
{
	struct pi2_sched_data * aqm = qdisc_priv(sch);
	u32 rnd_classic;
	u32 rnd_scalable;
	int is_ect1;

	/* Never mark/drop if we have a standing queue of less than 2 skbs. */
	if (qdisc_qlen(sch) <= 2) {
		aqm->stats.no_mark++;
		return false;
	}

	/* Figure out our random number */
	if (aqm->param.pi2_flags_live & PI2F_RANDOM_MARK) {
		/* Pseudo random marking of packets based on current
		 * probability. */

		/* Use the fast, non-crypto random generator.
		 * Make sure we only use it only once to save CPU ! Jean II */
		rnd_classic = prandom_u32();
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
		aqm->param.recur_classic += aqm->param.proba_2;
		aqm->param.recur_scalable += aqm->param.proba_cpl;

		rnd_classic = aqm->param.recur_classic;
		rnd_scalable = aqm->param.recur_scalable;
	}

	/* Check if packet is Scalable TCP and if we can do Scalable-ECN. */
	is_ect1 = INET_ECN_is_ect1(skb);
	if ( is_ect1 && (aqm->param.pi2_flags_live & PI2F_MARK_SCE) ) {
		/* Scalable TCP : Compare to raw probability multipled
		 * by coupling. */
		if ( (rnd_scalable < aqm->param.proba_cpl)
		     && (INET_ECN_set_ce(skb)) ) {
			aqm->stats.sce_mark++;
			/* Still need to be queued */
			return false;
		}
	} else {
		/* Classic TCP : Compare to square of probability. */
		if (rnd_classic < aqm->param.proba_2) {
			/* Check if we can do ECN and packet is not Scalable */
			if ( (aqm->param.pi2_flags_live & PI2F_MARK_ECN)
			     && (!is_ect1)
			     && (INET_ECN_set_ce(skb)) ) {
				aqm->stats.ecn_mark++;
				/* Still need to be queued */
				return false;
			} else {
				/* No ECN or packet is Scalable, drop it.
				 * In case of overload, pi2_flags are cleared
				 * and we end up here... Jean II */
				aqm->stats.drop_mark++;
				return true;
			}
		}
	}

	/* bstats->packets keep track of the number of actual Ethernet
	 * packets. Unfortunately, all other stats are in number of
	 * sbks. The packet count and skb count are different due
	 * to GSO. This counter allow to count skbs and therefore
	 * have something consistent with the other stats. Jean II */
	aqm->stats.no_mark++;

	/* Lucky packet, not dropped, not marked... */
	return false;
}

/* Process new packet to be added to the queue.
 * Version for tail-dropping and tail-marking. */
static int pi2_qdisc_enqueue_tail(struct sk_buff *skb, struct Qdisc *sch,
				  struct sk_buff **to_free)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	struct pi2_skb_cb *cb;
	bool enqueue = true;
	s64 now;

	/* Tail-drop when queue is full - bfifo style limit */
	if (unlikely(sch->qstats.backlog + qdisc_pkt_len(skb) >= sch->limit)) {
		qdisc_qstats_overlimit(sch);
		goto out;
	}

	/* Fortunately, this is cheap on modern CPUs ;-) */
	now = ktime_get_ns();

	/* If sub-queue was empty, reset delay.
	 * This will make use underestimate the queuing delay, but
	 * the reverse is worse, because the last packet may have been
	 * enqueued a *long* time ago. When we are congested, which is
	 * when PI2 matters, this will be false. Jean II */
	if (qdisc_qlen(sch) == 0)
		q->param.head_ns = now;

	/* If more than an update period has elapsed,
	 * we need to recompute the probability. */
	if (now > q->param.tupd_next_ns) {
		pi2_tupdate(sch, now);
		/* tupd_last_ns updated in pi2_tupdate() */
	}

	/* Pseudo random marking of packets based on
	 * current probability.*/
	enqueue = ( ! pi2_try_drop_early(sch, skb) );

	/* we can enqueue the packet */
	if (enqueue) {
		/* Set timestamp on packet to measure avg queue delay */
		cb = pi2_skb_cb(skb);
		cb->ts = now;

		/* Add to queue, update stats, etc... */
		return qdisc_enqueue_tail(skb, sch);
	}

out:
	return qdisc_drop(skb, sch, to_free);
}

/* Process a transmit opportunity by removing a packet from the queue.
 * Version for tail-dropping and tail-marking. */
static struct sk_buff *pi2_qdisc_dequeue_tail(struct Qdisc *sch)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	/* Remove from queue, update stats. If no packet, done. */
	skb = qdisc_dequeue_head(sch);
	if (!skb)
		return NULL;

	/* Update timestamp of when packet at head was added to the queue.
	 * Because we use the last head instead of the new head, we
	 * are a bit pessimistic, but it simplifies processing. Jean II */
	q->param.head_ns = pi2_skb_cb(skb)->ts;

	return skb;
}

/* Process new packet to be added to the queue.
 * Version for head-dropping and head-marking. */
static int pi2_qdisc_enqueue_head(struct sk_buff *skb, struct Qdisc *sch,
				  struct sk_buff **to_free)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	struct pi2_skb_cb *cb;
	s64 now;
	int ret;

	/* Tail-drop when queue is full - bfifo style limit */
	if (unlikely(sch->qstats.backlog + qdisc_pkt_len(skb) >= sch->limit)) {
		qdisc_qstats_overlimit(sch);
		return qdisc_drop(skb, sch, to_free);
	}

	/* Fortunately, this is cheap on modern CPUs ;-) */
	now = ktime_get_ns();

	/* Set timestamp on packet to measure avg queue delay */
	cb = pi2_skb_cb(skb);
	cb->ts = now;
#ifdef PI2_BOB_BRISCOE
	cb->backlog = sch->qstats.backlog + qdisc_pkt_len(skb);
#endif	/* PI2_BOB_BRISCOE */
	/* If queue was empty, reset queuing delay to compute proba */
	if (qdisc_qlen(sch) == 0)
		q->param.head_ns = now;

	/* Add to queue, update stats, etc... */
	ret = qdisc_enqueue_tail(skb, sch);

	/* If we drop early, statistics are not updated when qlen = 0
	 * If packet are just dripping through one by one, the counters
	 * may go up, and are never reduced. Try to fix it here. Jean II */
	if ( (q->param.reduce_qlen > 0) && qdisc_qlen(sch)) {
#ifdef PI2_DEBUG_REDUCE
		printk_ratelimited(KERN_DEBUG "PI2: reduce qlen %u backlog %u - #late#\n", q->param.reduce_qlen, q->param.reduce_backlog);
#endif	/* PI2_DEBUG_REDUCE */

		/* Update statistics of our parents */
		qdisc_tree_reduce_backlog(sch,
					  q->param.reduce_qlen,
					  q->param.reduce_backlog);
		q->param.reduce_qlen = 0;
		q->param.reduce_backlog = 0;
	}

	return ret;
}

/* Process a transmit opportunity by removing a packet from the queue.
 * Version for head-dropping and head-marking. */
static struct sk_buff *pi2_qdisc_dequeue_head(struct Qdisc *sch)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	bool drop;
	s64 now;
	struct sk_buff *skb;

	/* Fortunately, this is cheap on modern CPUs ;-) */
	now = ktime_get_ns();

	/* Until we get a valid packet. The vast majority of times,
	 * we only iterate once, especially if ECN is enabled... Jean II */
	while (true) {

		/* Dequeue. If no packet, done. */
		skb = __qdisc_dequeue_head(&sch->q);
		if (!skb)
			/* No point in calling reduce_backlog(), qlen = 0.
			 * Just in case it's fixed later... Jean II */
			goto exit;

		/* Update our stats */
		qdisc_qstats_backlog_dec(sch, skb);

		/* If more than an update period has elapsed,
		 * we need to recompute the probability. */
		if (now > q->param.tupd_next_ns) {
			/* Update timestamp of when packet at head was added
			 * to the queue. In this version, we use the new head
			 * of queue, so we are exact. Jean II */
			q->param.head_ns = pi2_skb_cb(skb)->ts;

			pi2_tupdate(sch, now);
			/* tupd_last_ns updated in pi2_tupdate() */
		}

		/* Pseudo random marking of packets based on
		 * current probability. */
		drop = pi2_try_drop_early(sch, skb);

		/* If packet is not dropped, this is a valid packet. */
		if (! drop)
			break;

		/* Keep track of how much to reduce backlog */
		q->param.reduce_qlen++;
		q->param.reduce_backlog += qdisc_pkt_len(skb);

		/* Packet must be dropped, so do it ! */
		qdisc_qstats_drop(sch);
		consume_skb(skb);		/* Same as kfree_skb(skb); */
	}

	/* Update stats about valid packets */
	qdisc_bstats_update(sch, skb);

exit:
	/* Note : skb may be NULL here... */

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
	if ( (q->param.reduce_qlen > 0) && qdisc_qlen(sch)) {
#ifdef PI2_DEBUG_REDUCE
		printk_ratelimited(KERN_DEBUG "PI2: reduce qlen %u backlog %u\n", q->param.reduce_qlen, q->param.reduce_backlog);
#endif	/* PI2_DEBUG_REDUCE */

		/* Update statistics of our parents */
		qdisc_tree_reduce_backlog(sch,
					  q->param.reduce_qlen,
					  q->param.reduce_backlog);
		q->param.reduce_qlen = 0;
		q->param.reduce_backlog = 0;
	}

	return skb;
}

#ifdef PI2_BOB_BRISCOE
static void pi2_tupdate_rapid(struct Qdisc *sch, s64 now, struct sk_buff *skb)
{
	struct pi2_sched_data * aqm = qdisc_priv(sch);
	s64	tupd_elapsed;
	u64	service_ns;
	u32	skb_len;		/* Length of skb */
	u32	skb_backlog;		/* Queue length at enqueue */
	s64	qdelay_ns;

	/* Figure out how many tupdate periods have elapsed. Jean II */
	tupd_elapsed = now - aqm->param.tupd_next_ns + aqm->config.tupdate_ns;

	/* Keep track of next time tupdate will need to happen.
	 * This will drift over time, and won't tick at precisely tupdate
	 * period. It does not matter in practice because we use the exact
	 * time elapsed in computations. Jean II */
	aqm->param.tupd_next_ns = now + ((s64) aqm->config.tupdate_ns);

#ifdef PI2_DEBUG_TUPDATE
        printk_ratelimited(KERN_DEBUG "PI2: tupd %lld (%d) ; now %lld ; next %lld\n", tupd_elapsed, aqm->config.tupdate_ns, now, aqm->param.tupd_next_ns);
#endif	/* PI2_DEBUG_TUPDATE */

	/* Check how we estimate qdelay */
	switch (aqm->param.pi2_flags_live & PI2F_MASK_RAPID) {

	default :
	case PI2F_RAPID_SOJOURN :
		/* Estimate the current delay of the queue.
		 * Use regular sojourn time.
		 * We compare when the packet at the head of the queue was
		 * enqueued to the time now. Always exact in this version.
		 * Jean II */
		qdelay_ns = now - aqm->param.head_ns;
		break;

	case PI2F_RAPID_SERVICE :
		/* Compute the average service time, i.e. how much time
		 * it takes to send a packet. */
		service_ns = now - aqm->param.dequeue_last_ns;
		aqm->param.dequeue_last_ns = now;
		/* skb length */
		skb_len = qdisc_pkt_len(skb);

		/* If last time we ran out of packet, the service time
		 * would include some idle time, therefore is not
		 * reliable. Jean II */
		if (aqm->param.dequeue_qlen != 0) {
		    /* Average service time */
		    aqm->param.service_avg_ns = ( ( ( aqm->param.service_avg_ns
						      * 3 )
						    + service_ns ) / 4 );
		    /* Average packet length corresponding to service time. */
		    aqm->param.skb_len_avg = ( ( (3 * aqm->param.skb_len_avg)
						 + skb_len ) / 4 );
		}

		/* In theory it can never happens, but we *must* be
		 * paranoid with divisions ! */
		if (aqm->param.skb_len_avg > 0)
			/* Delay estimate is service time per byte * queue length */
			qdelay_ns = ( aqm->param.service_avg_ns
				      * sch->qstats.backlog
				      / aqm->param.skb_len_avg );
		else
			qdelay_ns = now - aqm->param.head_ns;
#ifdef PI2_DEBUG_RAPID
		printk_ratelimited(KERN_DEBUG "PI2: rapid service qdelay %lld sojourn %lld ; qlen %d->%d service %lld/%lld skb_len %d/%d\n", qdelay_ns, now - aqm->param.head_ns, aqm->param.dequeue_qlen, qdisc_qlen(sch), service_ns, aqm->param.service_avg_ns, skb_len, aqm->param.skb_len_avg);
#endif	/* PI2_DEBUG_RAPID */

		/* Current skb is already removed, so only count outstanding
		 * queue, which is what we want. Jean II */
		aqm->param.dequeue_qlen = qdisc_qlen(sch);
		break;

	case PI2F_RAPID_SCALED :
		/* Use scaled sojourn. Same as default, but scaled for
		 * queue size. Jean II */
		skb_backlog = pi2_skb_cb(skb)->backlog;
		/* In theory it can never happens, but we *must* be
		 * paranoid with divisions ! */
		if (skb_backlog > 0)
			qdelay_ns = ( (now - aqm->param.head_ns)
				      * sch->qstats.backlog / skb_backlog );
		else
			qdelay_ns = now - aqm->param.head_ns;
#ifdef PI2_DEBUG_RAPID
		printk_ratelimited(KERN_DEBUG "PI2: rapid scaled qdelay %lld sojourn %lld ; backlog %d -> %d\n", qdelay_ns, now - aqm->param.head_ns, skb_backlog, sch->qstats.backlog);
#endif	/* PI2_DEBUG_RAPID */
		break;
	}

	/* Compute new probability */
        pi2_calculate_proba(sch, qdelay_ns, now, tupd_elapsed);
}

/* Process a transmit opportunity by removing a packet from the queue.
 * Version for head-dropping and head-marking with rapid signalling. */
static struct sk_buff *pi2_qdisc_dequeue_rapid(struct Qdisc *sch)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	bool drop;
	s64 now;
	struct sk_buff *skb;

	/* Fortunately, this is cheap on modern CPUs ;-) */
	now = ktime_get_ns();

	/* Until we get a valid packet. The vast majority of times,
	 * we only iterate once, especially if ECN is enabled... Jean II */
	while (true) {

		/* Dequeue. If no packet, done. */
		skb = __qdisc_dequeue_head(&sch->q);
		if (!skb)
			/* No point in calling reduce_backlog(), qlen = 0.
			 * Just in case it's fixed later... Jean II */
			goto exit;

		/* Update backlog *before* computing qdelay */
		qdisc_qstats_backlog_dec(sch, skb);

		/* Update timestamp of when packet at head was added to the
		 * queue. In this version, we use the new head of queue,
		 * so we are *exact*. Jean II */
		q->param.head_ns = pi2_skb_cb(skb)->ts;

		/* Always recompute the probability, every packet. */
		pi2_tupdate_rapid(sch, now, skb);

		/* Pseudo random marking of packets based on
		 * current probability. */
		drop = pi2_try_drop_early(sch, skb);

		/* If packet is not dropped, this is a valid packet. */
		if (! drop)
			break;

		/* Keep track of how much to reduce backlog */
		q->param.reduce_qlen++;
		q->param.reduce_backlog += qdisc_pkt_len(skb);

		/* Packet must be dropped, so do it ! */
		qdisc_qstats_drop(sch);
		consume_skb(skb);		/* Same as kfree_skb(skb); */
	}

	/* Update stats about valid packets */
	qdisc_bstats_update(sch, skb);

exit:
	/* Note : skb may be NULL here... */

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
	if ( (q->param.reduce_qlen > 0) && qdisc_qlen(sch)) {
#ifdef PI2_DEBUG_REDUCE
		printk_ratelimited(KERN_DEBUG "PI2: reduce qlen %u backlog %u\n", q->param.reduce_qlen, q->param.reduce_backlog);
#endif	/* PI2_DEBUG_REDUCE */

		/* Update statistics of our parents */
		qdisc_tree_reduce_backlog(sch,
					  q->param.reduce_qlen,
					  q->param.reduce_backlog);
		q->param.reduce_qlen = 0;
		q->param.reduce_backlog = 0;
	}

	return skb;
}
#endif	/* PI2_BOB_BRISCOE */

static const struct nla_policy pi2_policy[TCA_PI2_MAX + 1] = {
	[TCA_PI2_LIMIT]		= { .type = NLA_U32 },
	[TCA_PI2_TARGET]	= { .type = NLA_U32 },
	[TCA_PI2_TUPDATE]	= { .type = NLA_U32 },
	[TCA_PI2_ALPHA]		= { .type = NLA_U32 },
	[TCA_PI2_BETA]		= { .type = NLA_U32 },
	[TCA_PI2_COUPLING]	= { .type = NLA_U32 },
	[TCA_PI2_PI2_FLAGS]	= { .type = NLA_U32 },
};

static void pi2_aqm_param_update(struct pi2_sched_data *aqm, u32 tupdate_ns_old)
{
	u64	alpha_nm40;
	u64	beta_nm16;
	u64	proba_max;

	/* Sanity checks */

	/* Update internal variables */
	aqm->param.tupd_next_ns -= (s64) tupdate_ns_old;
	aqm->param.tupd_next_ns += (s64) aqm->config.tupdate_ns;

	/* If target delay is invalid, stop now, to avoid divide by zero.
	 * In theory, there is no way this can happen... */
	if (aqm->config.target_ns < 0)
		aqm->config.target_ns = 0LL;
	if (!aqm->config.target_ns) {
		printk_ratelimited(KERN_ERR "PI2: target is 0 !\n");
		return;
	}
	if (!aqm->config.coupling) {
		printk_ratelimited(KERN_ERR "PI2: coupling is 0 !\n");
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
			/ (u64) aqm->config.coupling )
		      - 1 );
	if ( (aqm->config.coupling <= ALPHA_BETA_SCALE)
	     || (proba_max >= PROBA_MAX) )
		aqm->param.proba_max = (u32) PROBA_MAX;
	else {
		aqm->param.proba_max = (u32) proba_max;
	}

	/* Overload mechanism.
	 * If probability goes through the roof, we assume that the queue
	 * is overloaded. This could be a badly implemented TCP, badly
	 * implemented ECN, or more likely a packet storm or unmanaged
	 * UDP traffic. In this case, we disable marking and only do drop
	 * to preserve low latency, unless PI2F_OVERLOAD_ECN is set.
	 * We do that by dropping ECN and SCE flags from the live flags.
	 * At init, we are not overloaded, so just copy the flags.
	 * Jean II */
	aqm->param.pi2_flags_live = aqm->config.pi2_flags;

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
	alpha_nm40 = ( (u64) aqm->config.alpha
		       * ( PI2_TARGET_REF * PI2_TARGET_REF
			   / PI2_TUPDATE_REF
			   * ( (PROBA_NORMA * NM16_SCALE) / ALPHA_BETA_SCALE
			       / NSEC_PER_SEC ) )
		       / (u64) aqm->config.target_ns
		       * (u64) NM24_SCALE
		       / (u64) aqm->config.target_ns );
	beta_nm16 = ( (u64) aqm->config.beta
		      * ( PI2_TARGET_REF
			  * ( (PROBA_NORMA * NM16_SCALE) / ALPHA_BETA_SCALE
			      / NSEC_PER_SEC ) )
		      / (u64) aqm->config.target_ns );
	aqm->param.alpha_nm40 = (u32) alpha_nm40;
	aqm->param.beta_nm16 = (u32) beta_nm16;

#ifdef PI2_DEBUG_CONFIG
	printk(KERN_DEBUG "PI2: alpha_nm40 %u ; beta_nm16 %u ; proba_max %u\n", aqm->param.alpha_nm40, aqm->param.beta_nm16, aqm->param.proba_max);
#endif	/* PI2_DEBUG_CONFIG */
}

static int pi2_qdisc_change(struct Qdisc *sch, struct nlattr *opt,
			    struct netlink_ext_ack *extack)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_PI2_MAX + 1];
	u32		target_us;
	u32		tupdate_ns_old;
	unsigned int qlen, dropped = 0;
	int		err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_PI2_MAX, opt, pi2_policy,
					  NULL);
	if (err < 0)
		return err;

	/* Check target before locking */
	if (tb[TCA_PI2_TARGET]) {
		target_us = nla_get_u32(tb[TCA_PI2_TARGET]);
		/* Can't be negative... */
		if (target_us == 0)
			return -EINVAL;
        }

	sch_tree_lock(sch);

	/* Standard queue limit, in bytes like bfifo & tbf, max 4GB */
	if (tb[TCA_PI2_LIMIT]) {
		u32 limit = nla_get_u32(tb[TCA_PI2_LIMIT]);
		sch->limit = limit;
	}

	if (tb[TCA_PI2_TARGET]) {
		/* Extracted and checked above */
		q->config.target_ns = (u64) target_us * NSEC_PER_USEC;
        }

	tupdate_ns_old = q->config.tupdate_ns;
	if (tb[TCA_PI2_TUPDATE]) {
		u32 tupdate_us = nla_get_u32(tb[TCA_PI2_TUPDATE]);
		/* Clamp at 1s, which is plenty enough.
		 * This is needed to avoid overflowing 32 bits. */
		if (tupdate_us > 1000000)
			tupdate_us = 1000000;
		q->config.tupdate_ns = (u32) (tupdate_us * NSEC_PER_USEC);
	} else {
		if (tb[TCA_PI2_TARGET]) {
			u64 tupdate_ns;
			/* Use value of the target delay to get smooth enough
			 * reaction with minimised overhead. Clamp to 1s. */
			if (q->config.target_ns > 1000000000LL)
				tupdate_ns = 1000000000LL;
			else
				tupdate_ns = q->config.target_ns;
			q->config.tupdate_ns = (u32) tupdate_ns;
		}
	}

	if (tb[TCA_PI2_ALPHA])
                q->config.alpha = nla_get_u32(tb[TCA_PI2_ALPHA]);
	if (tb[TCA_PI2_BETA])
                q->config.beta = nla_get_u32(tb[TCA_PI2_BETA]);
	if (tb[TCA_PI2_COUPLING]) {
                q->config.coupling = nla_get_u32(tb[TCA_PI2_COUPLING]);
		/* Prevent divide by zero. Also, make sure it's sensible */
		if (q->config.coupling < (ALPHA_BETA_SCALE / 4))
		    q->config.coupling = (ALPHA_BETA_SCALE / 4);
		else if (q->config.coupling > (16 * ALPHA_BETA_SCALE))
		    q->config.coupling = (16 * ALPHA_BETA_SCALE);
	}
	if (tb[TCA_PI2_PI2_FLAGS])
                q->config.pi2_flags = nla_get_u32(tb[TCA_PI2_PI2_FLAGS]);

	/* Update internal parameters */
	pi2_aqm_param_update(q, tupdate_ns_old);

	/* Drop excess packets if new limit is lower */
	qlen = sch->q.qlen;
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = __qdisc_dequeue_head(&sch->q);

		dropped += qdisc_pkt_len(skb);
		qdisc_qstats_backlog_dec(sch, skb);
		rtnl_qdisc_drop(skb, sch);
	}
	qdisc_tree_reduce_backlog(sch, qlen - sch->q.qlen, dropped);

	sch_tree_unlock(sch);
	return 0;
}

static int pi2_qdisc_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;
	u32 target_us;
	u32 tupdate_us;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	/* Standard queue limit */
	if (nla_put_u32(skb, TCA_PI2_LIMIT, sch->limit))
		goto nla_put_failure;

	/* PI2 attibutes */
	target_us =  (u32) (q->config.target_ns / NSEC_PER_USEC);
	if (nla_put_u32(skb, TCA_PI2_TARGET, target_us))
		goto nla_put_failure;
	tupdate_us = (u32) (q->config.tupdate_ns / NSEC_PER_USEC);
	/* Hide messy details unless needed. */
	if ( (tupdate_us != target_us)
	     || (q->config.alpha != PI2_ALPHA_DEFLT)
	     || (q->config.beta != PI2_BETA_DEFLT)
	     || (q->config.coupling != PI2_COUPL_DEFLT) ) {
		if (nla_put_u32(skb, TCA_PI2_TUPDATE, tupdate_us))
			goto nla_put_failure;
		if (nla_put_u32(skb, TCA_PI2_ALPHA, q->config.alpha))
			goto nla_put_failure;
		if (nla_put_u32(skb, TCA_PI2_BETA, q->config.beta))
			goto nla_put_failure;
		if (nla_put_u32(skb, TCA_PI2_COUPLING, q->config.coupling))
			goto nla_put_failure;
	}
	if (nla_put_u32(skb, TCA_PI2_PI2_FLAGS, q->config.pi2_flags))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -1;

}

static int pi2_qdisc_dump_xstats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	struct tc_pi2_xstats st;
	s64 now;

	/* Copy most stats */
	memcpy(&st, &q->stats, sizeof(st));
	/* Special stats */
	now = ktime_get_ns();
	if (qdisc_qlen(sch) == 0)
		st.delay_us = 0;
	else
		st.delay_us = (__u32) ( (now - q->param.head_ns)
					/ NSEC_PER_USEC );
	st.delay_peak_us = (__u32) ( q->param.qdelay_peak_ns / NSEC_PER_USEC );

	/* Reset some of the statistics, unless disabled */
	if ( ! (q->config.pi2_flags & PI2F_PEAK_NORESET) ) {
		q->param.qdelay_peak_ns = 0LL;
		q->stats.proba_peak = 0;
	}

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static void pi2_config_init(struct pi2_config *config)
{
	config->alpha = PI2_ALPHA_DEFLT;
	config->beta = PI2_BETA_DEFLT;
	config->target_ns = 15 * NSEC_PER_MSEC;	/* 15 ms - from dualpi2 */
	config->tupdate_ns = config->target_ns;
	config->coupling = PI2_COUPL_DEFLT;	/* 2.0 - from dualpi2 */
	config->pi2_flags = 0x0;		/* Only drop */
}

static void pi2_param_init(struct pi2_param *param)
{
	/* This will be incremented to the future in pi2_aqm_param_update() */
	param->tupd_next_ns = ktime_get_ns();
        param->proba_cpl = 0;
        param->proba_2 = 0;
	param->qdelay_ns = 0LL;
	param->qdelay_peak_ns = 0LL;
	param->recur_classic = 0;
	param->recur_scalable = 0;
	param->overload_ns = 0LL;
	param->reduce_qlen = 0;
	param->reduce_backlog = 0;
#ifdef PI2_BOB_BRISCOE
	param->dequeue_last_ns = param->tupd_next_ns;
	param->service_avg_ns = 0LL;
	param->skb_len_avg = 40;	/* Don't initialise at zero ! */
	param->dequeue_qlen = 0;
#endif	/* PI2_BOB_BRISCOE */
}

static void pi2_stats_reset(struct tc_pi2_xstats *stats)
{
	stats->no_mark = 0;
	stats->drop_mark = 0;
	stats->ecn_mark = 0;
	stats->sce_mark = 0;
        stats->proba = 0;
	stats->proba_peak = 0;
}

static int pi2_qdisc_init(struct Qdisc *sch, struct nlattr *opt,
			  struct netlink_ext_ack *extack)
{
	struct pi2_sched_data *q = qdisc_priv(sch);

	/* Initialise all parameters */
	pi2_config_init(&q->config);
	pi2_param_init(&q->param);
	pi2_stats_reset(&q->stats);
	pi2_aqm_param_update(q, 0LL);
	sch->limit = PI2_LIMIT_DEFLT;	/* Default of 1MB */

	q->sch = sch;

	if (opt) {
		int err = pi2_qdisc_change(sch, opt, extack);

		if (err)
			return err;
	}

	return 0;
}

static void pi2_qdisc_reset(struct Qdisc *sch)
{
	struct pi2_sched_data *q = qdisc_priv(sch);
	qdisc_reset_queue(sch);
	pi2_param_init(&q->param);
}

static void pi2_qdisc_destroy(struct Qdisc *sch)
{
}

/* Regular qdisc description - tail drop/mark version */
static struct Qdisc_ops pi2_tail_qdisc_ops __read_mostly = {
	.id		= "pi2",
	.priv_size	= sizeof(struct pi2_sched_data),
	.enqueue	= pi2_qdisc_enqueue_tail,
	.dequeue	= pi2_qdisc_dequeue_tail,
	.peek		= qdisc_peek_dequeued,
	.init		= pi2_qdisc_init,
	.destroy	= pi2_qdisc_destroy,
	.reset		= pi2_qdisc_reset,
	.change		= pi2_qdisc_change,
	.dump		= pi2_qdisc_dump,
	.dump_stats	= pi2_qdisc_dump_xstats,
	.owner		= THIS_MODULE,
};

/* Regular qdisc description - head drop/mark version */
static struct Qdisc_ops pi2_head_qdisc_ops __read_mostly = {
	.id		= "pi2_head",
	.priv_size	= sizeof(struct pi2_sched_data),
	.enqueue	= pi2_qdisc_enqueue_head,
	.dequeue	= pi2_qdisc_dequeue_head,
	.peek		= qdisc_peek_dequeued,
	.init		= pi2_qdisc_init,
	.destroy	= pi2_qdisc_destroy,
	.reset		= pi2_qdisc_reset,
	.change		= pi2_qdisc_change,
	.dump		= pi2_qdisc_dump,
	.dump_stats	= pi2_qdisc_dump_xstats,
	.owner		= THIS_MODULE,
};

#ifdef PI2_BOB_BRISCOE
/* Experimental version */
static struct Qdisc_ops pi2_rapid_qdisc_ops __read_mostly = {
	.id		= "pi2_rapid",
	.priv_size	= sizeof(struct pi2_sched_data),
	.enqueue	= pi2_qdisc_enqueue_head,
	.dequeue	= pi2_qdisc_dequeue_rapid,
	.peek		= qdisc_peek_dequeued,
	.init		= pi2_qdisc_init,
	.destroy	= pi2_qdisc_destroy,
	.reset		= pi2_qdisc_reset,
	.change		= pi2_qdisc_change,
	.dump		= pi2_qdisc_dump,
	.dump_stats	= pi2_qdisc_dump_xstats,
	.owner		= THIS_MODULE,
};
#endif	/* PI2_BOB_BRISCOE */

static int __init pi2_module_init(void)
{
	int ret;

#ifdef PI2_BOB_BRISCOE
	ret = register_qdisc(&pi2_rapid_qdisc_ops);
#endif	/* PI2_BOB_BRISCOE */

	ret = register_qdisc(&pi2_tail_qdisc_ops);
	if (!ret) {
		ret = register_qdisc(&pi2_head_qdisc_ops);
		if (ret)
			unregister_qdisc(&pi2_tail_qdisc_ops);
	}

	return ret;
}

static void __exit pi2_module_exit(void)
{
	unregister_qdisc(&pi2_tail_qdisc_ops);
	unregister_qdisc(&pi2_head_qdisc_ops);
#ifdef PI2_BOB_BRISCOE
	unregister_qdisc(&pi2_rapid_qdisc_ops);
#endif	/* PI2_BOB_BRISCOE */
}

module_init(pi2_module_init);
module_exit(pi2_module_exit);

MODULE_DESCRIPTION("Proportional Integral controller Improved with a Square (PI2) scheduler");
MODULE_AUTHOR("Jean Tourrilhes");
MODULE_LICENSE("GPL");
