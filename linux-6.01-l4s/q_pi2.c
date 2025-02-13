/*
 * q_pi2.c		Parse/print PI2 discipline module options.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 *
 * PI2 optimisations :
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

#ifndef TCA_PI2_MAX
/* PI2 */
enum {
	TCA_PI2_UNSPEC,
	TCA_PI2_LIMIT,
	TCA_PI2_TARGET,
	TCA_PI2_TUPDATE,
	TCA_PI2_ALPHA,
	TCA_PI2_BETA,
	TCA_PI2_COUPLING,
	TCA_PI2_PI2_FLAGS,
	__TCA_PI2_MAX
};

#define TCA_PI2_MAX   (__TCA_PI2_MAX - 1)

/* PI2_FLAGS */
#define PI2F_MARK_ECN		0x0001	/* Mark ECT_0 pkts with Classical ECN */
#define PI2F_MARK_SCE		0x0002	/* Mark ECT_1 pkts with Scalable ECN */
#define PI2F_OVERLOAD_ECN	0x0004	/* Keep doing ECN/SCE on overload */
#define PI2F_RANDOM_MARK	0x0008	/* Randomise marking, like RED */
#define PI2F_BYTEMODE		0x0010	/* Bytemode - unimplemented */
#define PI2F_PEAK_NORESET	0x0020	/* Don't reset peak statistics */

#endif	/* TCA_PI2_MAX */

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

static void explain(void)
{
	fprintf(stderr,
		"Usage: ... pi2 [limit BYTES] [target TIME us] [ecn|noecn] [sce|nosce]\n"
		"               [tupdate TIME us] [alpha ALPHA] [beta BETA] [coupling COUPLING]\n");
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

static int pi2_parse_opt(struct qdisc_util *qu, int argc, char **argv,
			 struct nlmsghdr *n, const char *dev)
{
	unsigned int	limit   = 0;
	unsigned int	target = 0xFFFFFFFF;
	unsigned int	tupdate = 0xFFFFFFFF;
	uint32_t	alpha = ALPHA_BETA_INVALID;
	uint32_t	beta = ALPHA_BETA_INVALID;
	uint32_t	coupling = ALPHA_BETA_INVALID;
	uint32_t	pi2_flags = 0x0;
	bool		flags_upd = false;
	struct rtattr *	tail;

	while (argc > 0) {
		if (strcasecmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_unsigned(&limit, *argv, 0)) {
				fprintf(stderr, "Illegal \"limit\"\n");
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
			pi2_flags |= PI2F_MARK_ECN;
			flags_upd = true;
		} else if (strcasecmp(*argv, "noecn") == 0) {
			pi2_flags &= ~PI2F_MARK_ECN;
			flags_upd = true;
		} else if ( (strcasecmp(*argv, "sce") == 0)
			    || (strcasecmp(*argv, "scaecn") == 0)
			    || (strcasecmp(*argv, "accecn") == 0) ) {
			pi2_flags |= PI2F_MARK_SCE;
			flags_upd = true;
		} else if ( (strcasecmp(*argv, "nosce") == 0)
			    || (strcasecmp(*argv, "noscaecn") == 0)
			    || (strcasecmp(*argv, "noaccecn") == 0) ) {
			pi2_flags &= ~PI2F_MARK_SCE;
			flags_upd = true;
		} else if (strcasecmp(*argv, "overload_ecn") == 0) {
			pi2_flags |= PI2F_OVERLOAD_ECN;
			flags_upd = true;
		} else if (strcasecmp(*argv, "nooverload_ecn") == 0) {
			pi2_flags &= ~PI2F_OVERLOAD_ECN;
			flags_upd = true;
		} else if (strcasecmp(*argv, "random") == 0) {
			pi2_flags |= PI2F_RANDOM_MARK;
			flags_upd = true;
		} else if (strcasecmp(*argv, "norandom") == 0) {
			pi2_flags &= ~PI2F_RANDOM_MARK;
			flags_upd = true;
		} else if (strcasecmp(*argv, "bytemode") == 0) {
			pi2_flags |= PI2F_BYTEMODE;
			flags_upd = true;
		} else if (strcasecmp(*argv, "nobytemode") == 0) {
			pi2_flags &= ~PI2F_BYTEMODE;
			flags_upd = true;
		} else if (strcasecmp(*argv, "peak_noreset") == 0) {
			pi2_flags |= PI2F_PEAK_NORESET;
			flags_upd = true;
		} else if (strcasecmp(*argv, "nopeak_noreset") == 0) {
			pi2_flags &= ~PI2F_PEAK_NORESET;
			flags_upd = true;
		} else if ( (strcasecmp(*argv, "pi2_flags") == 0)
			    || (strcasecmp(*argv, "ecn_flags") == 0) ) {
			NEXT_ARG();
			if (get_unsigned(&pi2_flags, *argv, 0)) {
				fprintf(stderr, "Illegal \"pi2_flags\"\n");
				return -1;
			}
			flags_upd = true;
		} else if (strcasecmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--;
		argv++;
	}

	tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
	if (limit)
		addattr_l(n, 1024, TCA_PI2_LIMIT, &limit, sizeof(limit));
	if (target != 0xFFFFFFFF)
		/* Zero will return an error. */
		addattr32(n, MAX_MSG, TCA_PI2_TARGET, target);
	if (tupdate != 0xFFFFFFFF)
		addattr32(n, MAX_MSG, TCA_PI2_TUPDATE, tupdate);
	if (alpha != ALPHA_BETA_INVALID)
		addattr32(n, MAX_MSG, TCA_PI2_ALPHA, alpha);
	if (beta != ALPHA_BETA_INVALID)
		addattr32(n, MAX_MSG, TCA_PI2_BETA, beta);
	if (coupling != ALPHA_BETA_INVALID)
		addattr32(n, MAX_MSG, TCA_PI2_COUPLING, coupling);
	if (flags_upd)
		addattr32(n, MAX_MSG, TCA_PI2_PI2_FLAGS, pi2_flags);

	tail->rta_len = (void *)NLMSG_TAIL(n) - (void *)tail;
	return 0;
}

static int pi2_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_PI2_MAX + 1];
	SPRINT_BUF(b1);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_PI2_MAX, opt);

	if (tb[TCA_PI2_LIMIT] &&
	    RTA_PAYLOAD(tb[TCA_PI2_LIMIT]) >= sizeof(__u32)) {
		unsigned int limit;
		limit = rta_getattr_u32(tb[TCA_PI2_LIMIT]);
		print_uint(PRINT_ANY, "limit", "limit %ub ", limit);
	}
	if ( tb[TCA_PI2_TARGET] &&
	     RTA_PAYLOAD(tb[TCA_PI2_TARGET]) >= sizeof(__u32)) {
	    unsigned int target;

	    target = rta_getattr_u32(tb[TCA_PI2_TARGET]);
	    print_uint(PRINT_JSON, "target", NULL, target);
	    print_string(PRINT_FP, NULL, "target %s ",
			 sprint_time(target, b1));

	    if (tb[TCA_PI2_PI2_FLAGS] &&
		RTA_PAYLOAD(tb[TCA_PI2_PI2_FLAGS]) >= sizeof(__u32)) {
		    unsigned int pi2_flags;
		    pi2_flags = rta_getattr_u32(tb[TCA_PI2_PI2_FLAGS]);
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
		}
	    if (tb[TCA_PI2_TUPDATE] &&
		RTA_PAYLOAD(tb[TCA_PI2_TUPDATE]) >= sizeof(__u32)) {
		    unsigned int tupdate;
		    tupdate = rta_getattr_u32(tb[TCA_PI2_TUPDATE]);
		    print_uint(PRINT_JSON, "tupdate", NULL, tupdate);
		    print_string(PRINT_FP, NULL, "\n\ttupdate %s ",
				 sprint_time(tupdate, b1));
	    }
	    if (tb[TCA_PI2_ALPHA] &&
		RTA_PAYLOAD(tb[TCA_PI2_ALPHA]) >= sizeof(__u32)) {
		    float alpha;
		    alpha = ( ((float) rta_getattr_u32(tb[TCA_PI2_ALPHA]))
			      / ALPHA_BETA_SCALE );
		    print_float(PRINT_ANY, "alpha", "alpha %.3f ", alpha);
	    }
	    if (tb[TCA_PI2_BETA] &&
		RTA_PAYLOAD(tb[TCA_PI2_BETA]) >= sizeof(__u32)) {
		    float beta;
		    beta = ( ((float) rta_getattr_u32(tb[TCA_PI2_BETA]))
			     / ALPHA_BETA_SCALE );
		    print_float(PRINT_ANY, "beta", "beta %.3f ", beta);
	    }
	    if (tb[TCA_PI2_COUPLING] &&
		RTA_PAYLOAD(tb[TCA_PI2_COUPLING]) >= sizeof(__u32)) {
		    float coupling;
		    coupling = ( ((float) rta_getattr_u32(tb[TCA_PI2_COUPLING]))
				 / ALPHA_BETA_SCALE );
		    print_float(PRINT_ANY, "coupling", "coupling %.1f ",
				coupling);
	    }
	}

	return 0;
}

static int pi2_print_xstats(struct qdisc_util *qu, FILE *f,
			    struct rtattr *xstats)
{
	struct tc_pi2_xstats *st;

	if (xstats == NULL)
		return 0;

	if (RTA_PAYLOAD(xstats) < sizeof(*st))
		return -1;

	st = RTA_DATA(xstats);
	print_uint(PRINT_ANY, "no_mark", "  no_mark %u", st->no_mark);
	print_uint(PRINT_ANY, "drop_mark", " drop_mark %u", st->drop_mark);
	print_uint(PRINT_ANY, "ecn_mark", " ecn_mark %u", st->ecn_mark);
	print_uint(PRINT_ANY, "sce_mark", " sce_mark %u", st->sce_mark);
	/* proba is normalised with probability 1 <-> 2^32 */
	print_float(PRINT_ANY, "proba", "\n  proba %.3f",
		    (float) st->proba / (float) PROBA_NORMA);
	print_float(PRINT_ANY, "proba_peak", " proba_peak %.3f",
		    (float) st->proba_peak / (float) PROBA_NORMA);
	print_float(PRINT_ANY, "delay", " delay %.3fms",
		    (float) st->delay_us / 1000.0);
	print_float(PRINT_ANY, "delay_peak", " delay_peak %.3fms",
		    (float) st->delay_peak_us / 1000.0);
	return 0;

}

struct qdisc_util pi2_qdisc_util = {
	.id = "pi2",
	.parse_qopt	= pi2_parse_opt,
	.print_qopt	= pi2_print_opt,
	.print_xstats	= pi2_print_xstats,
};

struct qdisc_util pi2_head_qdisc_util = {
	.id = "pi2_head",
	.parse_qopt	= pi2_parse_opt,
	.print_qopt	= pi2_print_opt,
	.print_xstats	= pi2_print_xstats,
};

struct qdisc_util pi2_rapid_qdisc_util = {
	.id = "pi2_rapid",
	.parse_qopt	= pi2_parse_opt,
	.print_qopt	= pi2_print_opt,
	.print_xstats	= pi2_print_xstats,
};
