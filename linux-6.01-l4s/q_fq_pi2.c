/*
 * q_fq_pi2.c		Parse/print FQ-PI2 discipline module options.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Copyright 2024-2025 Hewlett Packard Enterprise Development LP.
 *	Author: Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>

#include "utils.h"
#include "tc_util.h"

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
	TCA_FQ_PI2_COUPLING,	/* Coupling between scalalble and classical */
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

#endif	/* TCA_FQ_PI2_MAX */

#define PROBA_NORMA	0x100000000LL	/* Normalise : probability 1 is 2^32 */
#define PROBA_MAX	0xFFFFFFFFLL	/* Max probability : 2^32 - 1 */

/* Typical values of alpha and beta are smaller than 1.0 (one).
 * Typical value for coupling factor is 2.0.
 * We need to convert it to integer without loosing too much precision, so
 * encode in fixed point normalised at 256, in 1/256th increments. */
#define ALPHA_BETA_SCALE	(1 << 8)	/* Convert fraction-> integer */
#define ALPHA_BETA_MAX		((1 << 16) - 1)	/* Up to 65535 */
#define ALPHA_BETA_INVALID	(~((uint32_t)0))

/* Stats exported to userspace */
struct tc_fq_pi2_xstats {
	__u32	flows;		/* number of flows */
	__u32	flows_inactive;	/* number of inactive flows */
	__u64	flows_gc;	/* number of flows garbage collected */
	__u32	alloc_errors;	/* failed flow allocations */
	__u32	no_mark;	/* Enqueue events (pkts / gso_segs) */
	__u32	drop_mark;	/* packets dropped due to PI2 AQM */
	__u32	ecn_mark;       /* Packets marked with ECN, classic TCP */
	__u32	sce_mark;       /* Packets marked with ECN, scalable TCP */
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


static void explain(void)
{
	fprintf(stderr,
		"Usage: ... fq_pi2 [ limit PACKETS ] [ buckets NUMBER ] [ hash_mask MASK ]\n"
		"                  [ flow_limit PACKETS ] [target TIME us] [ecn|noecn]\n"
		"                [tupdate TIME us] [alpha ALPHA] [beta BETA] [coupling COUPLING]\n");
}

static unsigned int ilog2(unsigned int val)
{
	unsigned int res = 0;

	val--;
	while (val) {
		res++;
		val >>= 1;
	}
	return res;
}

static int get_float(float *val, const char *arg, float min, float max)
{
        float res;
        char *ptr;

        if (!arg || !*arg)
                return -1;
        res = strtof(arg, &ptr);
        if (!ptr || ptr == arg || *ptr)
                return -1;
	if (res < min || res > max)
		return -1;
        *val = res;
        return 0;
}

static uint32_t parse_alpha_beta(const char *name, char *argv)
{

	float field_f;

	if (get_float(&field_f, argv, 0.0, ALPHA_BETA_MAX)) {
		fprintf(stderr, "Illegal \"%s\"\n", name);
		return ALPHA_BETA_INVALID;
	}
	else if (field_f < 1.0f / ALPHA_BETA_SCALE)
		fprintf(stderr, "Warning: \"%s\" is too small and will be "
			"rounded to zero.\n", name);
	return (uint32_t)(field_f * ALPHA_BETA_SCALE);
}

static int fq_pi2_parse_opt(struct qdisc_util *qu,
			  int argc,
			  char **argv,
			  struct nlmsghdr *n,
			  const char *dev)
{
	uint32_t	plimit = 0xFFFFFFFF;
	uint32_t	flow_plimit = 0xFFFFFFFF;
	uint32_t	quantum = 0xFFFFFFFF;
	uint32_t	initial_quantum = 0xFFFFFFFF;
	unsigned int	refill_delay = 0xFFFFFFFF;
	unsigned int	buckets = 0;
	uint32_t	hash_mask = 0x0;
	unsigned int	target = 0xFFFFFFFF;
	unsigned int	tupdate = 0xFFFFFFFF;
	uint32_t	alpha = ALPHA_BETA_INVALID;
	uint32_t	beta = ALPHA_BETA_INVALID;
	uint32_t	coupling = ALPHA_BETA_INVALID;
	uint32_t	flags = 0x0;
	bool		flags_upd = false;
	uint16_t	mon_fl_port = 0xFFFF;
	uint32_t	udp_plimit = 0xFFFFFFFF;
	struct rtattr *tail;

	while (argc > 0) {
		if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_u32(&plimit, *argv, 0)) {
				fprintf(stderr, "Illegal \"limit\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "flow_limit") == 0) {
			NEXT_ARG();
			if (get_u32(&flow_plimit, *argv, 0)) {
				fprintf(stderr, "Illegal \"flow_limit\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "quantum") == 0) {
			NEXT_ARG();
			if (get_u32(&quantum, *argv, 0)) {
				fprintf(stderr, "Illegal \"quantum\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "initial_quantum") == 0) {
			NEXT_ARG();
			if (get_u32(&initial_quantum, *argv, 0)) {
				fprintf(stderr, "Illegal \"initial_quantum\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "refill_delay") == 0) {
			NEXT_ARG();
			if (get_time(&refill_delay, *argv)) {
				fprintf(stderr, "Illegal \"refill_delay\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "buckets") == 0) {
			NEXT_ARG();
			if (get_unsigned(&buckets, *argv, 0)) {
				fprintf(stderr, "Illegal \"buckets\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "hash_mask") == 0) {
			NEXT_ARG();
			if (get_u32(&hash_mask, *argv, 0)) {
				fprintf(stderr, "Illegal \"hash_mask\"\n");
				return -1;
			}
		} else if (strcasecmp(*argv, "target") == 0) {
			NEXT_ARG();
			if (get_time(&target, *argv)) {
				fprintf(stderr, "Illegal \"target\"\n");
				return -1;
			}
		} else if (strcasecmp(*argv, "tupdate") == 0) {
			NEXT_ARG();
			if (get_time(&tupdate, *argv)) {
				fprintf(stderr, "Illegal \"tupdate\"\n");
				return -1;
			}
		} else if (strcasecmp(*argv, "alpha") == 0) {
			NEXT_ARG();
			alpha = parse_alpha_beta("alpha", *argv);
			if (alpha == ALPHA_BETA_INVALID)
				return -1;
		} else if (strcasecmp(*argv, "beta") == 0) {
			NEXT_ARG();
			beta = parse_alpha_beta("beta", *argv);
			if (beta == ALPHA_BETA_INVALID)
				return -1;
		} else if ( (strcasecmp(*argv, "coupling") == 0)
			    || (strcasecmp(*argv, "coupling_factor") == 0) ) {
			NEXT_ARG();
			coupling = parse_alpha_beta("coupling", *argv);
			if (coupling == ALPHA_BETA_INVALID)
				return -1;
		} else if (strcasecmp(*argv, "ecn") == 0) {
			flags |= PI2F_MARK_ECN;
			flags_upd = true;
		} else if (strcasecmp(*argv, "noecn") == 0) {
			flags &= ~PI2F_MARK_ECN;
			flags_upd = true;
		} else if ( (strcasecmp(*argv, "sce") == 0)
			    || (strcasecmp(*argv, "scaecn") == 0)
			    || (strcasecmp(*argv, "accecn") == 0) ) {
			flags |= PI2F_MARK_SCE;
			flags_upd = true;
		} else if ( (strcasecmp(*argv, "nosce") == 0)
			    || (strcasecmp(*argv, "noscaecn") == 0)
			    || (strcasecmp(*argv, "noaccecn") == 0) ) {
			flags &= ~PI2F_MARK_SCE;
			flags_upd = true;
		} else if (strcasecmp(*argv, "overload_ecn") == 0) {
			flags |= PI2F_OVERLOAD_ECN;
			flags_upd = true;
		} else if (strcasecmp(*argv, "nooverload_ecn") == 0) {
			flags &= ~PI2F_OVERLOAD_ECN;
			flags_upd = true;
		} else if (strcasecmp(*argv, "random") == 0) {
			flags |= PI2F_RANDOM_MARK;
			flags_upd = true;
		} else if (strcasecmp(*argv, "norandom") == 0) {
			flags &= ~PI2F_RANDOM_MARK;
			flags_upd = true;
		} else if (strcasecmp(*argv, "bytemode") == 0) {
			flags |= PI2F_BYTEMODE;
			flags_upd = true;
		} else if (strcasecmp(*argv, "nobytemode") == 0) {
			flags &= ~PI2F_BYTEMODE;
			flags_upd = true;
		} else if (strcasecmp(*argv, "peak_noreset") == 0) {
			flags |= PI2F_PEAK_NORESET;
			flags_upd = true;
		} else if (strcasecmp(*argv, "nopeak_noreset") == 0) {
			flags &= ~PI2F_PEAK_NORESET;
			flags_upd = true;
		} else if ( (strcasecmp(*argv, "udp_taildrop") == 0)
			    || (strcasecmp(*argv, "udp_nomark") == 0) ) {
			flags |= PI2F_UDP_TAILDROP;
			flags_upd = true;
		} else if ( (strcasecmp(*argv, "noudp_taildrop") == 0)
			    || (strcasecmp(*argv, "noudp_nomark") == 0) ) {
			flags &= ~PI2F_UDP_TAILDROP;
			flags_upd = true;
		} else if (strcasecmp(*argv, "flags") == 0) {
			NEXT_ARG();
			if (get_u32(&flags, *argv, 0)) {
				fprintf(stderr, "Illegal \"flags\"\n");
				return -1;
			}
			flags_upd = true;
		} else if (strcmp(*argv, "mon_fl_port") == 0) {
			NEXT_ARG();
			if (get_u16(&mon_fl_port, *argv, 0)) {
				fprintf(stderr, "Illegal \"mon_fl_port\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "udp_limit") == 0) {
			NEXT_ARG();
			if (get_u32(&udp_plimit, *argv, 0)) {
				fprintf(stderr, "Illegal \"udp_limit\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "%s: unknown parameter \"%s\"\n", qu->id, *argv);
			explain();
			return -1;
		}
		argc --;
		argv ++;
	}

	tail = addattr_nest(n, 1024, TCA_OPTIONS);
	// tail = NLMSG_TAIL(n);
	// addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);

	if (plimit != 0xFFFFFFFF)
		addattr32(n, 1024, TCA_FQ_PI2_PLIMIT, plimit);
	if (flow_plimit != 0xFFFFFFFF)
		addattr32(n, 1024, TCA_FQ_PI2_FLOW_PLIMIT, flow_plimit);
	if (quantum != 0xFFFFFFFF)
		addattr32(n, 1024, TCA_FQ_PI2_QUANTUM, quantum);
	if (initial_quantum != 0xFFFFFFFF)
		addattr32(n, 1024, TCA_FQ_PI2_INITIAL_QUANTUM, initial_quantum);
	if (refill_delay != 0xFFFFFFFF)
		addattr32(n, 1024, TCA_FQ_PI2_FLOW_REFILL_DELAY, refill_delay);
	if (buckets != 0) {
		unsigned int hash_log = ilog2(buckets);
		addattr32(n, 1024, TCA_FQ_PI2_BUCKETS_LOG, hash_log);
	}
	if (hash_mask != 0x0)
		addattr32(n, 1024, TCA_FQ_PI2_HASH_MASK, hash_mask);

	if (target != 0xFFFFFFFF)
		/* Zero will return an error. */
		addattr32(n, MAX_MSG, TCA_FQ_PI2_TARGET, target);
	if (tupdate != 0xFFFFFFFF)
		addattr32(n, MAX_MSG, TCA_FQ_PI2_TUPDATE, tupdate);
	if (alpha != ALPHA_BETA_INVALID)
		addattr32(n, MAX_MSG, TCA_FQ_PI2_ALPHA, alpha);
	if (beta != ALPHA_BETA_INVALID)
		addattr32(n, MAX_MSG, TCA_FQ_PI2_BETA, beta);
	if (coupling != ALPHA_BETA_INVALID)
		addattr32(n, MAX_MSG, TCA_FQ_PI2_COUPLING, coupling);
	if (flags_upd)
		addattr32(n, 1024, TCA_FQ_PI2_FLAGS, flags);
	if (mon_fl_port != 0xFFFF)
		addattr16(n, 1024, TCA_FQ_PI2_MON_FL_PORT, mon_fl_port);
	if (udp_plimit != 0xFFFFFFFF)
		addattr32(n, 1024, TCA_FQ_PI2_UDP_PLIMIT, udp_plimit);
	
	addattr_nest_end(n, tail);
	// tail->rta_len = (void *)NLMSG_TAIL(n) - (void *)tail;

	return 0;
}

static int fq_pi2_print_opt(struct qdisc_util *qu,
			  FILE *f,
			  struct rtattr *opt)
{
	struct rtattr *tb[TCA_FQ_PI2_MAX + 1];

	SPRINT_BUF(b1);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_FQ_PI2_MAX, opt);

	if (tb[TCA_FQ_PI2_PLIMIT] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PI2_PLIMIT]) >= sizeof(__u32)) {
		unsigned int plimit;
		plimit = rta_getattr_u32(tb[TCA_FQ_PI2_PLIMIT]);
		print_uint(PRINT_ANY, "limit", "limit %u ", plimit);
	}

	if (tb[TCA_FQ_PI2_FLOW_PLIMIT] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PI2_FLOW_PLIMIT]) >= sizeof(__u32)) {
		unsigned int flow_plimit;
		flow_plimit = rta_getattr_u32(tb[TCA_FQ_PI2_FLOW_PLIMIT]);
		print_uint(PRINT_ANY, "flow_limit", "flow_limit %up ",
			   flow_plimit);
	}

	if (tb[TCA_FQ_PI2_QUANTUM] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PI2_QUANTUM]) >= sizeof(__u32)) {
		unsigned int quantum;
		quantum = rta_getattr_u32(tb[TCA_FQ_PI2_QUANTUM]);
		print_size(PRINT_ANY, "quantum", "quantum %s ", quantum);
	}

	if (tb[TCA_FQ_PI2_INITIAL_QUANTUM] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PI2_INITIAL_QUANTUM]) >= sizeof(__u32)) {
		unsigned int quantum;
		quantum = rta_getattr_u32(tb[TCA_FQ_PI2_INITIAL_QUANTUM]);
		print_size(PRINT_ANY, "initial_quantum", "initial_quantum %s ",
			   quantum);
	}

	if (tb[TCA_FQ_PI2_FLOW_REFILL_DELAY] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PI2_FLOW_REFILL_DELAY]) >= sizeof(__u32)) {
		unsigned int refill_delay;
		refill_delay = rta_getattr_u32(tb[TCA_FQ_PI2_FLOW_REFILL_DELAY]);
		print_uint(PRINT_JSON, "refill_delay", NULL, refill_delay);
		print_string(PRINT_FP, NULL, "refill_delay %s ",
			     sprint_time(refill_delay, b1));
	}

	if (tb[TCA_FQ_PI2_BUCKETS_LOG] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PI2_BUCKETS_LOG]) >= sizeof(__u32)) {
		unsigned int buckets_log;
		buckets_log = rta_getattr_u32(tb[TCA_FQ_PI2_BUCKETS_LOG]);
		print_uint(PRINT_ANY, "buckets", "buckets %u ",
			   1U << buckets_log);
	}

	if (tb[TCA_FQ_PI2_HASH_MASK] &&
	    RTA_PAYLOAD(tb[TCA_FQ_PI2_HASH_MASK]) >= sizeof(__u32)) {
		unsigned int hash_mask;
		hash_mask = rta_getattr_u32(tb[TCA_FQ_PI2_HASH_MASK]);
		print_uint(PRINT_ANY, "hash_mask", "hash_mask %u ",
			   hash_mask);
	}

	if ( tb[TCA_FQ_PI2_TARGET] &&
	     RTA_PAYLOAD(tb[TCA_FQ_PI2_TARGET]) >= sizeof(__u32)) {
	    unsigned int target;

	    target = rta_getattr_u32(tb[TCA_FQ_PI2_TARGET]);
	    print_uint(PRINT_JSON, "target", NULL, target);
	    print_string(PRINT_FP, NULL, "\n\ttarget %s ",
			 sprint_time(target, b1));

	    if (tb[TCA_FQ_PI2_FLAGS] &&
		RTA_PAYLOAD(tb[TCA_FQ_PI2_FLAGS]) >= sizeof(__u32)) {
		    unsigned int pi2_flags;
		    pi2_flags = rta_getattr_u32(tb[TCA_FQ_PI2_FLAGS]);
		    if (pi2_flags & PI2F_MARK_ECN)
			print_bool(PRINT_ANY, "ecn", "ecn ", true);
		    if (pi2_flags & PI2F_MARK_SCE)
			print_bool(PRINT_ANY, "sce", "sce ", true);
		    if (pi2_flags & PI2F_OVERLOAD_ECN)
			print_bool(PRINT_ANY, "overload_ecn", "overload_ecn ", true);
		    if (pi2_flags & PI2F_RANDOM_MARK)
			print_bool(PRINT_ANY, "random", "random ", true);
		    if (pi2_flags & PI2F_BYTEMODE)
			print_bool(PRINT_ANY, "bytemode", "bytemode ", true);
		    if (pi2_flags & PI2F_PEAK_NORESET)
			print_bool(PRINT_ANY, "peak_noreset", "peak_noreset ", true);
		    if (pi2_flags & PI2F_UDP_TAILDROP)
			print_bool(PRINT_ANY, "udp_taildrop", "udp_taildrop ", true);
		}
	    if (tb[TCA_FQ_PI2_TUPDATE] &&
		RTA_PAYLOAD(tb[TCA_FQ_PI2_TUPDATE]) >= sizeof(__u32)) {
		    unsigned int tupdate;
		    tupdate = rta_getattr_u32(tb[TCA_FQ_PI2_TUPDATE]);
		    print_uint(PRINT_JSON, "tupdate", NULL, tupdate);
		    print_string(PRINT_FP, NULL, "\n\ttupdate %s ",
				 sprint_time(tupdate, b1));
	    }
	    if (tb[TCA_FQ_PI2_ALPHA] &&
		RTA_PAYLOAD(tb[TCA_FQ_PI2_ALPHA]) >= sizeof(__u32)) {
		    float alpha;
		    alpha = ( ((float) rta_getattr_u32(tb[TCA_FQ_PI2_ALPHA]))
			      / ALPHA_BETA_SCALE );
		    print_float(PRINT_ANY, "alpha", "alpha %.3f ", alpha);
	    }
	    if (tb[TCA_FQ_PI2_BETA] &&
		RTA_PAYLOAD(tb[TCA_FQ_PI2_BETA]) >= sizeof(__u32)) {
		    float beta;
		    beta = ( ((float) rta_getattr_u32(tb[TCA_FQ_PI2_BETA]))
			     / ALPHA_BETA_SCALE );
		    print_float(PRINT_ANY, "beta", "beta %.3f ", beta);
	    }
	    if (tb[TCA_FQ_PI2_COUPLING] &&
		RTA_PAYLOAD(tb[TCA_FQ_PI2_COUPLING]) >= sizeof(__u32)) {
		    float coupling;
		    coupling = ( ((float) rta_getattr_u32(tb[TCA_FQ_PI2_COUPLING]))
				 / ALPHA_BETA_SCALE );
		    print_float(PRINT_ANY, "coupling", "coupling %.1f ",
				coupling);
	    }
	    if (tb[TCA_FQ_PI2_MON_FL_PORT] &&
		RTA_PAYLOAD(tb[TCA_FQ_PI2_MON_FL_PORT]) >= sizeof(__u16)) {
		    unsigned int mon_fl_port;
		    mon_fl_port = rta_getattr_u16(tb[TCA_FQ_PI2_MON_FL_PORT]);
		    print_uint(PRINT_ANY, "mon_fl_port", "mon_fl_port %u ",
			       mon_fl_port);
	    }
	    if (tb[TCA_FQ_PI2_UDP_PLIMIT] &&
		RTA_PAYLOAD(tb[TCA_FQ_PI2_UDP_PLIMIT]) >= sizeof(__u32)) {
		    unsigned int udp_plimit;
		    udp_plimit = rta_getattr_u32(tb[TCA_FQ_PI2_UDP_PLIMIT]);
		    print_uint(PRINT_ANY, "udp_limit", "udp_limit %up ",
			       udp_plimit);
	    }
	}

	return 0;
}

static int fq_pi2_print_xstats(struct qdisc_util *qu, FILE *f,
			     struct rtattr *xstats)
{
	struct tc_fq_pi2_xstats *st;

	if (xstats == NULL)
		return 0;
	
	if (RTA_PAYLOAD(xstats) < sizeof(*st))
		return -1;

	st = RTA_DATA(xstats);
	print_uint(PRINT_ANY, "flows", "  flows %d", st->flows);
	print_uint(PRINT_ANY, "flows_inactive", " (inactive %d)",
		   st->flows_inactive);
	print_uint(PRINT_ANY, "flows_gc", " gc %u", st->flows_gc);
	print_uint(PRINT_ANY, "alloc_errors", " alloc_errors %u",
		   st->alloc_errors);
	if (st->burst_peak != 0 || st->burst_avg != 0 || st->sched_empty != 0) {
		print_uint(PRINT_ANY, "burst_peak", "\n  burst_peak %u", st->burst_peak);
		print_uint(PRINT_ANY, "burst_avg", " burst_avg %u", st->burst_avg);
		print_uint(PRINT_ANY, "sched_empty", " sched_empty %u", st->sched_empty);
	}
	if (st->fl_backlog_peak != 0 || st->fl_qlen_peak != 0) {
		print_uint(PRINT_ANY, "flow_backlog", "\n  flow_backlog %ub",
			   st->fl_backlog);
		print_uint(PRINT_ANY, "flow_qlen", " %up", st->fl_qlen);
		print_uint(PRINT_ANY, "flow_backlog_peak", " flow_peak %ub",
			   st->fl_backlog_peak);
		print_uint(PRINT_ANY, "flow_qlen_peak", " %up",
			   st->fl_qlen_peak);
	}
	if (st->fl_qdelay_peak_us != 0 || st->fl_proba_peak != 0) {
		/* proba is normalised with probability 1 <-> 2^32 */
		print_float(PRINT_ANY, "proba", "\n  proba %.3f",
			    (float) st->fl_proba / (float) PROBA_NORMA);
		print_float(PRINT_ANY, "proba_peak", " proba_peak %.3f",
			    (float) st->fl_proba_peak / (float) PROBA_NORMA);
		print_float(PRINT_ANY, "delay", " delay %.3fms",
			    (float) st->fl_qdelay_us / 1000.0);
		print_float(PRINT_ANY, "delay_peak", " delay_peak %.3fms",
			    (float) st->fl_qdelay_peak_us / 1000.0);
	}
	if (st->fl_no_mark != 0) {
		print_uint(PRINT_ANY, "no_fmark", "\n  no_fmark %u",
			   st->fl_no_mark);
		print_uint(PRINT_ANY, "drop_fmark", " drop_fmark %u",
			   st->fl_drop_mark);
		print_uint(PRINT_ANY, "ecn_fmark", " ecn_fmark %u",
			   st->fl_ecn_mark);
		print_uint(PRINT_ANY, "sce_fmark", " sce_fmark %u",
			   st->fl_sce_mark);
	}
	print_uint(PRINT_ANY, "no_mark", "\n  no_mark %u", st->no_mark);
	print_uint(PRINT_ANY, "drop_mark", " drop_mark %u", st->drop_mark);
	print_uint(PRINT_ANY, "ecn_mark", " ecn_mark %u", st->ecn_mark);
	print_uint(PRINT_ANY, "sce_mark", " sce_mark %u", st->sce_mark);

	return 0;
}

struct qdisc_util fq_pi2_qdisc_util = {
	.id = "fq_pi2",
	.parse_qopt = fq_pi2_parse_opt,
	.print_qopt = fq_pi2_print_opt,
	.print_xstats = fq_pi2_print_xstats,
};

struct qdisc_util fq_pi2_head_qdisc_util = {
	.id = "fq_pi2_head",
	.parse_qopt = fq_pi2_parse_opt,
	.print_qopt = fq_pi2_print_opt,
	.print_xstats = fq_pi2_print_xstats,
};
