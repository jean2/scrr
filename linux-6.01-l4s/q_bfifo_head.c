/*
 * q_fifo_head.c	The FIFO queue in bytes that drop at the head.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Copyright 2022-2025 Hewlett Packard Enterprise Development LP.
 *	Author: Jean Tourrilhes <tourrilhes.hpl@gmail.com>
 *
 * Based on fifo.c :
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"

/* Stats exported to userspace */
struct tc_bfifo_head_xstats {
	__u32	skb_num;	/* Number of skbs */
	__u32	qlen_peak;	/* Maximum queue length */
	__u32	backlog_peak;	/* Maximum backlog */
};

static void explain(void)
{
	fprintf(stderr, "Usage: ... <[p|b]fifo | pfifo_head_drop> [ limit NUMBER ]\n");
}

static int bfifo_head_parse_opt(struct qdisc_util *qu, int argc, char **argv,
				struct nlmsghdr *n, const char *dev)
{
	int ok = 0;
	struct tc_fifo_qopt opt = {};

	while (argc > 0) {
		if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_size(&opt.limit, *argv)) {
				fprintf(stderr, "%s: Illegal value for \"limit\": \"%s\"\n", qu->id, *argv);
				return -1;
			}
			ok++;
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "%s: unknown parameter \"%s\"\n", qu->id, *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}

	if (ok)
		addattr_l(n, 1024, TCA_OPTIONS, &opt, sizeof(opt));
	return 0;
}

static int bfifo_head_print_opt(struct qdisc_util *qu, FILE *f,
				struct rtattr *opt)
{
	struct tc_fifo_qopt *qopt;

	if (opt == NULL)
		return 0;

	if (RTA_PAYLOAD(opt)  < sizeof(*qopt))
		return -1;
	qopt = RTA_DATA(opt);
	if (strncmp(qu->id, "bfifo", 5) == 0) {
		print_size(PRINT_ANY, "limit", "limit %s", qopt->limit);
	} else {
		print_uint(PRINT_ANY, "limit", "limit %up", qopt->limit);
	}
	return 0;
}

static int bfifo_head_print_xstats(struct qdisc_util *qu, FILE *f,
				   struct rtattr *xstats)
{
	struct tc_bfifo_head_xstats *st;

	if (xstats == NULL)
		return 0;

	if (RTA_PAYLOAD(xstats) < sizeof(*st))
		return -1;

	st = RTA_DATA(xstats);
	print_uint(PRINT_ANY, "skb_num", "  skb_num %u", st->skb_num);
	print_uint(PRINT_ANY, "backlog_peak", " backlog_peak %ub", st->backlog_peak);
	print_uint(PRINT_ANY, "qlen_peak", " %up", st->qlen_peak);

	return 0;

}


struct qdisc_util bfifo_head_drop_qdisc_util = {
	.id = "bfifo_head_drop",
	.parse_qopt	= bfifo_head_parse_opt,
	.print_qopt	= bfifo_head_print_opt,
	.print_xstats	= bfifo_head_print_xstats,
};

struct qdisc_util bfifo_tail_drop_qdisc_util = {
	.id = "bfifo_tail_drop",
	.parse_qopt	= bfifo_head_parse_opt,
	.print_qopt	= bfifo_head_print_opt,
	.print_xstats	= bfifo_head_print_xstats,
};
