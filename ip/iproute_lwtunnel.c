/*
 * iproute_lwtunnel.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Roopa Prabhu, <roopa@cumulusnetworks.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <linux/lwtunnel.h>
#include <linux/mpls_iptunnel.h>
#include <errno.h>

#include "rt_names.h"
#include "utils.h"
#include "iproute_lwtunnel.h"

static int read_encap_type(const char *name)
{
	int type = LWTUNNEL_ENCAP_NONE;

	if (strcmp(name, "mpls") == 0)
		type = LWTUNNEL_ENCAP_MPLS;

	return type;
}

static const char *format_encap_type(int type)
{
	if (type == LWTUNNEL_ENCAP_MPLS)
		return "mpls";

	return "unknown";
}

static void print_encap_mpls(FILE *fp, struct rtattr *encap)
{
	struct rtattr *tb[MPLS_IPTUNNEL_MAX+1];
	char abuf[256];

	parse_rtattr_nested(tb, MPLS_IPTUNNEL_MAX, encap);

	if (tb[MPLS_IPTUNNEL_DST])
		fprintf(fp, " %s ", format_host(AF_MPLS,
			RTA_PAYLOAD(tb[MPLS_IPTUNNEL_DST]),
			RTA_DATA(tb[MPLS_IPTUNNEL_DST]),
			abuf, sizeof(abuf)));
}

void lwt_print_encap(FILE *fp, struct rtattr *encap_type,
			  struct rtattr *encap)
{
	int et;

	if (!encap_type)
		return;

	et = rta_getattr_u16(encap_type);

	switch (et) {
	case LWTUNNEL_ENCAP_MPLS:
		fprintf(fp, " encap %s", format_encap_type(et));
		print_encap_mpls(fp, encap);
		break;
	default:
		break;
	}
}

static int parse_encap_mpls(struct nlmsghdr *n, int *argcp, char ***argvp)
{
	inet_prefix addr;
	int argc = *argcp;
	char **argv = *argvp;

	if (get_addr(&addr, *argv, AF_MPLS)) {
		fprintf(stderr, "Error: an inet address is expected rather than \"%s\".\n", *argv);
		exit(1);
	}

	addattr_l(n, 1024, MPLS_IPTUNNEL_DST, &addr.data,
		  addr.bytelen);

	*argcp = argc;
	*argvp = argv;

	return 0;
}

int lwt_parse_encap(struct nlmsghdr *n, int *argcp, char ***argvp)
{
	struct rtattr *nest;
	int argc = *argcp;
	char **argv = *argvp;
	__u16 type;

	NEXT_ARG();
	type = read_encap_type(*argv);
	if (!type)
		invarg("\"encap type\" value is invalid\n", *argv);

	NEXT_ARG();
	if (argc <= 1) {
		fprintf(stderr, "Error: unexpected end of line after \"encap\"\n");
		exit(-1);
	}

	addattr16(n, 1024, RTA_ENCAP_TYPE, type);
	nest = addattr_nest(n, 1024, RTA_ENCAP);
	switch (type) {
	case LWTUNNEL_ENCAP_MPLS:
		parse_encap_mpls(n, &argc, &argv);
		break;
	default:
		fprintf(stderr, "Error: unsupported encap type\n");
		break;
	}
	addattr_nest_end(n, nest);

	*argcp = argc;
	*argvp = argv;

	return 0;
}

static int parse_nh_encap_mpls(struct rtattr *rta, int *argcp, char ***argvp)
{
	inet_prefix addr;
	int argc = *argcp;
	char **argv = *argvp;

	if (get_addr(&addr, *argv, AF_MPLS)) {
		fprintf(stderr, "Error: an inet address is expected rather than \"%s\".\n", *argv);
		exit(1);
	}

	rta_addattr_l(rta, 1024, MPLS_IPTUNNEL_DST, &addr.data,
		      addr.bytelen);

	*argcp = argc;
	*argvp = argv;

	return 0;
}

int lwt_parse_nh_encap(struct rtattr *rta, int *argcp, char ***argvp)
{
	struct rtattr *nest;
	int argc = *argcp;
	char **argv = *argvp;
	__u16 type;

	NEXT_ARG();
	type = read_encap_type(*argv);
	if (!type)
		invarg("\"encap type\" value is invalid\n", *argv);

	NEXT_ARG();
	if (argc <= 1) {
		fprintf(stderr, "Error: unexpected end of line after \"encap\"\n");
		exit(-1);
	}

	rta_addattr16(rta, 1024, RTA_ENCAP_TYPE, type);
	nest = rta_nest(rta, 1024, RTA_ENCAP);
	switch (type) {
	case LWTUNNEL_ENCAP_MPLS:
		parse_nh_encap_mpls(rta, &argc, &argv);
		break;
	default:
		fprintf(stderr, "Error: unsupported encap type\n");
		break;
	}
	rta_nest_end(rta, nest);

	*argcp = argc;
	*argvp = argv;

	return 0;
}
