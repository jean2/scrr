/*
 * q_sppifo_stfq.c		Parse/print SP-PIFO with STFQ discipline module options.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Copyright 2023-2025 Hewlett Packard Enterprise Development LP.
 *	Author: Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 *	Author: Erfan Sharafzadeh <e.sharafzadeh@jhu.edu>
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

enum {
	TCA_SPPIFO_UNSPEC,
	TCA_SPPIFO_PLIMIT,	/* limit of total number of packets in queue */
	TCA_SPPIFO_BUCKETS_LOG,	/* log2(number of buckets) */
	TCA_SPPIFO_HASH_MASK,	/* mask applied to skb hashes */
	TCA_SPPIFO_BAND_PLIMIT,	/* limit of packets per flow */
	TCA_SPPIFO_FLAGS,		/* Options */
	__TCA_SPPIFO_MAX
};
#define TCA_SPPIFO_MAX	(__TCA_SPPIFO_MAX - 1)

/* TCA_SPPIFO_FLAGS */
#define SCF_PEAK_NORESET	0x0020	/* Don't reset peak statistics */
#define SPPIFO_BANDS_XSTATS	8		/* Number of bands we report statistics for in the tc stats */

/* statistics exported to userspace */
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
	__u32	num_inversions;	/* Number of priority inversions (enqueue) */
	__u32	num_reordering;	/* Number of reordering (dequeue) */
	__u32	band_tx[SPPIFO_BANDS_XSTATS];	/* Number of SKBs sent from each band */
	__u32	band_qlen[SPPIFO_BANDS_XSTATS];	/* Number of SKBs queued in each band */
};


static void explain(void)
{
	fprintf(stderr,
		"Usage: ... sppifo_stfq [ limit PACKETS ] [ buckets NUMBER ] [ hash_mask MASK ]\n"
		"                [ band_limit PACKETS ]\n");
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

static int sppifo_parse_opt(struct qdisc_util *qu,
			  int argc,
			  char **argv,
			  struct nlmsghdr *n,
			  const char *dev)
{
	uint32_t	plimit = 0xFFFFFFFF;
	unsigned int	buckets = 0;
	uint32_t	hash_mask = 0x0;
	uint32_t	band_plimit = 0xFFFFFFFF;
	uint32_t	flags = 0x0;
	bool		flags_upd = false;
	struct rtattr *tail;

	while (argc > 0) {
		if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_u32(&plimit, *argv, 0)) {
				fprintf(stderr, "Illegal \"limit\"\n");
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
		} else if (strcmp(*argv, "band_limit") == 0) {
			NEXT_ARG();
			if (get_u32(&band_plimit, *argv, 0)) {
				fprintf(stderr, "Illegal \"band_limit\"\n");
				return -1;
			}
		} else if (strcasecmp(*argv, "flags") == 0) {
			NEXT_ARG();
			if (get_u32(&flags, *argv, 0)) {
				fprintf(stderr, "Illegal \"flags\"\n");
				return -1;
			}
			flags_upd = true;
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
		addattr32(n, 1024, TCA_SPPIFO_PLIMIT, plimit);
	if (buckets != 0) {
		unsigned int hash_log = ilog2(buckets);
		addattr32(n, 1024, TCA_SPPIFO_BUCKETS_LOG, hash_log);
	}
	if (hash_mask != 0x0)
		addattr32(n, 1024, TCA_SPPIFO_HASH_MASK, hash_mask);
	if (band_plimit != 0xFFFFFFFF)
		addattr32(n, 1024, TCA_SPPIFO_BAND_PLIMIT, band_plimit);
	if (flags_upd)
		addattr32(n, 1024, TCA_SPPIFO_FLAGS, flags);
	
	addattr_nest_end(n, tail);
	// tail->rta_len = (void *)NLMSG_TAIL(n) - (void *)tail;

	return 0;
}

static int sppifo_print_opt(struct qdisc_util *qu,
			  FILE *f,
			  struct rtattr *opt)
{
	struct rtattr *tb[TCA_SPPIFO_MAX + 1];

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_SPPIFO_MAX, opt);

	if (tb[TCA_SPPIFO_PLIMIT] &&
	    RTA_PAYLOAD(tb[TCA_SPPIFO_PLIMIT]) >= sizeof(__u32)) {
		unsigned int plimit;
		plimit = rta_getattr_u32(tb[TCA_SPPIFO_PLIMIT]);
		print_uint(PRINT_ANY, "limit", "limit %u ", plimit);
	}

	if (tb[TCA_SPPIFO_BUCKETS_LOG] &&
	    RTA_PAYLOAD(tb[TCA_SPPIFO_BUCKETS_LOG]) >= sizeof(__u32)) {
		unsigned int buckets_log;
		buckets_log = rta_getattr_u32(tb[TCA_SPPIFO_BUCKETS_LOG]);
		print_uint(PRINT_ANY, "buckets", "buckets %u ",
			   1U << buckets_log);
	}

	if (tb[TCA_SPPIFO_HASH_MASK] &&
	    RTA_PAYLOAD(tb[TCA_SPPIFO_HASH_MASK]) >= sizeof(__u32)) {
		unsigned int hash_mask;
		hash_mask = rta_getattr_u32(tb[TCA_SPPIFO_HASH_MASK]);
		print_uint(PRINT_ANY, "hash_mask", "hash_mask %u ",
			   hash_mask);
	}

	if (tb[TCA_SPPIFO_BAND_PLIMIT] &&
	    RTA_PAYLOAD(tb[TCA_SPPIFO_BAND_PLIMIT]) >= sizeof(__u32)) {
		unsigned int band_plimit;
		band_plimit = rta_getattr_u32(tb[TCA_SPPIFO_BAND_PLIMIT]);
		print_uint(PRINT_ANY, "band_limit", "band_limit %up ",
			   band_plimit);
	}

	if (tb[TCA_SPPIFO_FLAGS] &&
	    RTA_PAYLOAD(tb[TCA_SPPIFO_FLAGS]) >= sizeof(__u32)) {
		unsigned int flags;
		flags = rta_getattr_u32(tb[TCA_SPPIFO_FLAGS]);
		print_uint(PRINT_ANY, "flags", "flags 0x%X ", flags);
	}
	return 0;
}

static int sppifo_print_xstats(struct qdisc_util *qu, FILE *f,
			     struct rtattr *xstats)
{
	struct tc_sppifo_xstats *st;
	int i;

	if (xstats == NULL)
		return 0;
	
	if (RTA_PAYLOAD(xstats) < sizeof(*st))
		return -1;

	st = RTA_DATA(xstats);
	print_uint(PRINT_ANY, "flows", "  flows %u", st->flows);
	print_uint(PRINT_ANY, "flows_gc", " gc %u", st->flows_gc);
	print_uint(PRINT_ANY, "alloc_errors", " alloc_errors %u",
		   st->alloc_errors);
	print_uint(PRINT_ANY, "no_mark", " \n  no_mark %u", st->no_mark);
	print_uint(PRINT_ANY, "drop_mark", " drop_mark %u", st->drop_mark);
	if (st->burst_peak != 0) {
		print_uint(PRINT_ANY, "burst_peak", " burst_peak %u", st->burst_peak);
	}
	if (st->burst_avg != 0) {
		print_uint(PRINT_ANY, "burst_avg", " burst_avg %u", st->burst_avg);
	}
	if (st->backlog_peak != 0 || st->qlen_peak != 0) {
		print_uint(PRINT_ANY, "backlog_peak", "  backlog_peak %ub",
			   st->backlog_peak);
		print_uint(PRINT_ANY, "qlen_peak", " %up", st->qlen_peak);
	}
	print_uint(PRINT_ANY, "num_inversions", "\n  num_inversions %u", st->num_inversions);
	print_uint(PRINT_ANY, "num_reordering", " num_reordering %u\n  band_qlen", st->num_reordering);
	for(i = 0; i < SPPIFO_BANDS_XSTATS - 1 ; i++)
	{
		print_uint(PRINT_ANY, "band_qlen", " %u", st->band_qlen[i]);
	}
	print_uint(PRINT_ANY, "band_qlen", " %u \n  band_tx", st->band_qlen[i]);

	for(i = 0; i < SPPIFO_BANDS_XSTATS; i++)
	{
		print_uint(PRINT_ANY, "band_tx", " %u", st->band_tx[i]);
	}



	return 0;
}

struct qdisc_util sppifo_stfq_qdisc_util = {
	.id = "sppifo_stfq",
	.parse_qopt = sppifo_parse_opt,
	.print_qopt = sppifo_print_opt,
	.print_xstats = sppifo_print_xstats,
};
