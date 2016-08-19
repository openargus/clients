/*
 * Copyright (c) 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <unistd.h>
#include <stdlib.h>

#include <argus_compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <signal.h>
#include <ctype.h>
#include <argus/extract.h>

extern u_char *snapend;

#include "interface.h"

extern char ArgusBuf[];
extern void relts_print(char *, int);


/*
 * DVMRP message types and flag values shamelessly stolen from
 * mrouted/dvmrp.h.
 */
#define DVMRP_PROBE		1	/* for finding neighbors */
#define DVMRP_REPORT		2	/* for reporting some or all routes */
#define DVMRP_ASK_NEIGHBORS	3	/* sent by mapper, asking for a list */
					/* of this router's neighbors */
#define DVMRP_NEIGHBORS		4	/* response to such a request */
#define DVMRP_ASK_NEIGHBORS2	5	/* as above, want new format reply */
#define DVMRP_NEIGHBORS2	6
#define DVMRP_PRUNE		7	/* prune message */
#define DVMRP_GRAFT		8	/* graft message */
#define DVMRP_GRAFT_ACK		9	/* graft acknowledgement */

/*
 * 'flags' byte values in DVMRP_NEIGHBORS2 reply.
 */
#define DVMRP_NF_TUNNEL		0x01	/* neighbors reached via tunnel */
#define DVMRP_NF_SRCRT		0x02	/* tunnel uses IP source routing */
#define DVMRP_NF_DOWN		0x10	/* kernel state of interface */
#define DVMRP_NF_DISABLED	0x20	/* administratively disabled */
#define DVMRP_NF_QUERIER	0x40	/* I am the subnet's querier */

static int print_probe(const u_char *, const u_char *, u_int);
static int print_report(const u_char *, const u_char *, u_int);
static int print_neighbors(const u_char *, const u_char *, u_int);
static int print_neighbors2(const u_char *, const u_char *, u_int);
static int print_prune(const u_char *);
static int print_graft(const u_char *);
static int print_graft_ack(const u_char *);

static u_int32_t target_level;

char *
dvmrp_print(register const u_char *bp, register u_int len)
{
	register const u_char *ep;
	register u_char type;

	ep = (const u_char *)snapend;
	if (bp >= ep)
		return ArgusBuf;

	TCHECK(bp[1]);
	type = bp[1];

	/* Skip IGMP header */
	bp += 8;
	len -= 8;

	switch (type) {

	case DVMRP_PROBE:
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," Probe");
		if (ArgusParser->vflag) {
			if (print_probe(bp, ep, len) < 0)
				goto trunc;
		}
		break;

	case DVMRP_REPORT:
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," Report");
		if (ArgusParser->vflag > 1) {
			if (print_report(bp, ep, len) < 0)
				goto trunc;
		}
		break;

	case DVMRP_ASK_NEIGHBORS:
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," Ask-neighbors(old)");
		break;

	case DVMRP_NEIGHBORS:
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," Neighbors(old)");
		if (print_neighbors(bp, ep, len) < 0)
			goto trunc;
		break;

	case DVMRP_ASK_NEIGHBORS2:
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," Ask-neighbors2");
		break;

	case DVMRP_NEIGHBORS2:
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," Neighbors2");
		/*
		 * extract version and capabilities from IGMP group
		 * address field
		 */
		bp -= 4;
		TCHECK2(bp[0], 4);
		target_level = (bp[0] << 24) | (bp[1] << 16) |
		    (bp[2] << 8) | bp[3];
		bp += 4;
		if (print_neighbors2(bp, ep, len) < 0)
			goto trunc;
		break;

	case DVMRP_PRUNE:
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," Prune");
		if (print_prune(bp) < 0)
			goto trunc;
		break;

	case DVMRP_GRAFT:
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," Graft");
		if (print_graft(bp) < 0)
			goto trunc;
		break;

	case DVMRP_GRAFT_ACK:
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," Graft-ACK");
		if (print_graft_ack(bp) < 0)
			goto trunc;
		break;

	default:
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," [type %d]", type);
		break;
	}
	return ArgusBuf;

trunc:
	sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|dvmrp]");
	return ArgusBuf;
}

static int 
print_report(register const u_char *bp, register const u_char *ep,
    register u_int len)
{
	register u_int32_t mask, origin;
	register int metric, done;
	register u_int i, width;

	while (len > 0) {
		if (len < 3) {
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|]");
			return (0);
		}
		TCHECK2(bp[0], 3);
		mask = (u_int32_t)0xff << 24 | bp[0] << 16 | bp[1] << 8 | bp[2];
		width = 1;
		if (bp[0])
			width = 2;
		if (bp[1])
			width = 3;
		if (bp[2])
			width = 4;

		sprintf(&ArgusBuf[strlen(ArgusBuf)],"\n\tMask %s", intoa(htonl(mask)));
		bp += 3;
		len -= 3;
		do {
			if (bp + width + 1 > ep) {
				sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|]");
				return (0);
			}
			if (len < width + 1) {
				sprintf(&ArgusBuf[strlen(ArgusBuf)],"\n\t  [Truncated Report]");
				return (0);
			}
			origin = 0;
			for (i = 0; i < width; ++i) {
				TCHECK(*bp);
				origin = origin << 8 | *bp++;
			}
			for ( ; i < 4; ++i)
				origin <<= 8;

			TCHECK(*bp);
			metric = *bp++;
			done = metric & 0x80;
			metric &= 0x7f;
			sprintf(&ArgusBuf[strlen(ArgusBuf)],"\n\t  %s metric %d", intoa(htonl(origin)),
				metric);
			len -= width + 1;
		} while (!done);
	}
	return (0);
trunc:
	return (-1);
}

static int
print_probe(register const u_char *bp, register const u_char *ep,
    register u_int len)
{
	register u_int32_t genid;

	TCHECK2(bp[0], 4);
	if ((len < 4) || ((bp + 4) > ep)) {
		/* { (ctags) */
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|}");
		return (0);
	}
	genid = (bp[0] << 24) | (bp[1] << 16) | (bp[2] << 8) | bp[3];
	bp += 4;
	len -= 4;
	if (ArgusParser->vflag > 1)
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"\n\t");
	else
		sprintf(&ArgusBuf[strlen(ArgusBuf)]," ");
	sprintf(&ArgusBuf[strlen(ArgusBuf)],"genid %u", genid);
	if (ArgusParser->vflag < 2)
		return (0);

	while ((len > 0) && (bp < ep)) {
		TCHECK2(bp[0], 4);
		sprintf(&ArgusBuf[strlen(ArgusBuf)],"\n\tneighbor %s", ipaddr_string(bp));
		bp += 4; len -= 4;
	}
	return (0);
trunc:
	return (-1);
}

static int
print_neighbors(register const u_char *bp, register const u_char *ep,
    register u_int len)
{
	const u_char *laddr;
	register u_char metric;
	register u_char thresh;
	register int ncount;

	while (len > 0 && bp < ep) {
		TCHECK2(bp[0], 7);
		laddr = bp;
		bp += 4;
		metric = *bp++;
		thresh = *bp++;
		ncount = *bp++;
		len -= 7;
		while (--ncount >= 0) {
			TCHECK2(bp[0], 4);
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," [%s ->", ipaddr_string(laddr));
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s, (%d/%d)]",
				   ipaddr_string(bp), metric, thresh);
			bp += 4;
			len -= 4;
		}
	}
	return (0);
trunc:
	return (-1);
}

static int
print_neighbors2(register const u_char *bp, register const u_char *ep,
    register u_int len)
{
	const u_char *laddr;
	register u_char metric, thresh, flags;
	register int ncount;

	sprintf(&ArgusBuf[strlen(ArgusBuf)]," (v %d.%d):",
	       (int)target_level & 0xff,
	       (int)(target_level >> 8) & 0xff);

	while (len > 0 && bp < ep) {
		TCHECK2(bp[0], 8);
		laddr = bp;
		bp += 4;
		metric = *bp++;
		thresh = *bp++;
		flags = *bp++;
		ncount = *bp++;
		len -= 8;
		while (--ncount >= 0 && (len >= 4) && (bp + 4) <= ep) {
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," [%s -> ", ipaddr_string(laddr));
			sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s (%d/%d", ipaddr_string(bp),
				     metric, thresh);
			if (flags & DVMRP_NF_TUNNEL)
				sprintf(&ArgusBuf[strlen(ArgusBuf)],"/tunnel");
			if (flags & DVMRP_NF_SRCRT)
				sprintf(&ArgusBuf[strlen(ArgusBuf)],"/srcrt");
			if (flags & DVMRP_NF_QUERIER)
				sprintf(&ArgusBuf[strlen(ArgusBuf)],"/querier");
			if (flags & DVMRP_NF_DISABLED)
				sprintf(&ArgusBuf[strlen(ArgusBuf)],"/disabled");
			if (flags & DVMRP_NF_DOWN)
				sprintf(&ArgusBuf[strlen(ArgusBuf)],"/down");
			sprintf(&ArgusBuf[strlen(ArgusBuf)],")]");
			bp += 4;
			len -= 4;
		}
		if (ncount != -1) {
			sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|]");
			return (0);
		}
	}
	return (0);
trunc:
	return (-1);
}

static int
print_prune(register const u_char *bp)
{
	TCHECK2(bp[0], 12);
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," src %s grp %s", ipaddr_string(bp), ipaddr_string(bp + 4));
	bp += 8;
	(void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," timer ");
	relts_print(&ArgusBuf[strlen(ArgusBuf)],EXTRACT_32BITS(bp));
	return (0);
trunc:
	return (-1);
}

static int
print_graft(register const u_char *bp)
{
	TCHECK2(bp[0], 8);
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," src %s grp %s", ipaddr_string(bp), ipaddr_string(bp + 4));
	return (0);
trunc:
	return (-1);
}

static int
print_graft_ack(register const u_char *bp)
{
	TCHECK2(bp[0], 8);
	sprintf(&ArgusBuf[strlen(ArgusBuf)]," src %s grp %s", ipaddr_string(bp), ipaddr_string(bp + 4));
	return (0);
trunc:
	return (-1);
}
