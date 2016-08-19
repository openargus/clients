/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1993, 1994, 1995, 1996
 *  The Regents of the University of California.  All rights reserved.
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

#ifndef IN_CLASSD
#define IN_CLASSD(i) (((int32_t)(i) & 0xf0000000) == 0xe0000000)
#endif

/* (following from ipmulti/mrouted/prune.h) */

/*
 * The packet format for a traceroute request.
 */
struct tr_query {
    u_int32_t  tr_src;          /* traceroute source */
    u_int32_t  tr_dst;          /* traceroute destination */
    u_int32_t  tr_raddr;        /* traceroute response address */
    u_int32_t  tr_rttlqid;      /* response ttl and qid */
};

#define TR_GETTTL(x)        (int)(((x) >> 24) & 0xff)
#define TR_GETQID(x)        ((x) & 0x00ffffff)

/*
 * Traceroute response format.  A traceroute response has a tr_query at the
 * beginning, followed by one tr_resp for each hop taken.
 */
struct tr_resp {
    u_int32_t tr_qarr;          /* query arrival time */
    u_int32_t tr_inaddr;        /* incoming interface address */
    u_int32_t tr_outaddr;       /* outgoing interface address */
    u_int32_t tr_rmtaddr;       /* parent address in source tree */
    u_int32_t tr_vifin;         /* input packet count on interface */
    u_int32_t tr_vifout;        /* output packet count on interface */
    u_int32_t tr_pktcnt;        /* total incoming packets for src-grp */
    u_int8_t  tr_rproto;      /* routing proto deployed on router */
    u_int8_t  tr_fttl;        /* ttl required to forward on outvif */
    u_int8_t  tr_smask;       /* subnet mask for src addr */
    u_int8_t  tr_rflags;      /* forwarding error codes */
};

/* defs within mtrace */
#define TR_QUERY 1
#define TR_RESP 2

/* fields for tr_rflags (forwarding error codes) */
#define TR_NO_ERR   0
#define TR_WRONG_IF 1
#define TR_PRUNED   2
#define TR_OPRUNED  3
#define TR_SCOPED   4
#define TR_NO_RTE   5
#define TR_NO_FWD   7
#define TR_NO_SPACE 0x81
#define TR_OLD_ROUTER   0x82

/* fields for tr_rproto (routing protocol) */
#define TR_PROTO_DVMRP  1
#define TR_PROTO_MOSPF  2
#define TR_PROTO_PIM    3
#define TR_PROTO_CBT    4

/* igmpv3 report types */
static struct tok igmpv3report2str[] = {
	{ 1,	"is_in" },
	{ 2,	"is_ex" },
	{ 3,	"to_in" },
	{ 4,	"to_ex" },
	{ 5,	"allow" },
	{ 6,	"block" },
	{ 0,	NULL }
};

static void
print_mtrace(register const u_char *bp, register u_int len)
{
    struct tr_query *tr = (struct tr_query *)(bp + 8);

    TCHECK(*tr);
    if (len < 8 + sizeof (struct tr_query)) {
	(void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [invalid len %d]", len);
	return;
    }

    tr->tr_src   = EXTRACT_32BITS(&tr->tr_src);
    tr->tr_dst   = EXTRACT_32BITS(&tr->tr_dst);
    tr->tr_raddr = EXTRACT_32BITS(&tr->tr_raddr);

    sprintf(&ArgusBuf[strlen(ArgusBuf)],"mtrace %u: %s to %s reply-to %s",
        TR_GETQID(EXTRACT_32BITS(&tr->tr_rttlqid)),
        ipaddr_string(&tr->tr_src), ipaddr_string(&tr->tr_dst),
        ipaddr_string(&tr->tr_raddr));
    if (IN_CLASSD(EXTRACT_32BITS(&tr->tr_raddr)))
        sprintf(&ArgusBuf[strlen(ArgusBuf)]," with-ttl %d", TR_GETTTL(EXTRACT_32BITS(&tr->tr_rttlqid)));
    return;
trunc:
    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|igmp]");
    return;
}

static void
print_mresp(register const u_char *bp, register u_int len)
{
    register struct tr_query *tr = (struct tr_query *)(bp + 8);

    TCHECK(*tr);
    if (len < 8 + sizeof (struct tr_query)) {
	(void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [invalid len %d]", len);
	return;
    }

    tr->tr_src   = EXTRACT_32BITS(&tr->tr_src);
    tr->tr_dst   = EXTRACT_32BITS(&tr->tr_dst);
    tr->tr_raddr = EXTRACT_32BITS(&tr->tr_raddr);

    sprintf(&ArgusBuf[strlen(ArgusBuf)],"mresp %lu: %s to %s reply-to %s",
        (u_long)TR_GETQID(EXTRACT_32BITS(&tr->tr_rttlqid)),
        ipaddr_string(&tr->tr_src), ipaddr_string(&tr->tr_dst),
        ipaddr_string(&tr->tr_raddr));
    if (IN_CLASSD(EXTRACT_32BITS(&tr->tr_raddr)))
        sprintf(&ArgusBuf[strlen(ArgusBuf)]," with-ttl %d", TR_GETTTL(EXTRACT_32BITS(&tr->tr_rttlqid)));
    return;
trunc:
    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|igmp]");
    return;
}

static void
print_igmpv3_report(register const u_char *bp, register u_int len)
{
    u_int group, nsrcs, ngroups, haddr;
    register u_int i, j;

    /* Minimum len is 16, and should be a multiple of 4 */
    if (len < 16 || len & 0x03) {
	(void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [invalid len %d]", len);
	return;
    }
    TCHECK2(bp[6], 2);
    ngroups = EXTRACT_16BITS(&bp[6]);
    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],", %d group record(s)", ngroups);
    if (ArgusParser->vflag > 0) {
	/* Print the group records */
	group = 8;
        for (i=0; i<ngroups; i++) {
	    if (len < group+8) {
		(void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [invalid number of groups]");
		return;
	    }
	    TCHECK2(bp[group+4], 4);
	    haddr = EXTRACT_32BITS(&bp[group+4]);
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [gaddr %s", ipaddr_string(&haddr));
	    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", tok2str(igmpv3report2str, " [v3-report-#%d]",
								bp[group]));
            nsrcs = EXTRACT_16BITS(&bp[group+2]);
	    /* Check the number of sources and print them */
	    if (len < group+8+(nsrcs<<2)) {
		(void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [invalid number of sources %d]", nsrcs);
		return;
	    }
            if (ArgusParser->vflag == 1)
                (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],", %d source(s)", nsrcs);
            else {
		/* Print the sources */
                (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," {");
                for (j=0; j<nsrcs; j++) {
		    TCHECK2(bp[group+8+(j<<2)], 4);
	            haddr = EXTRACT_32BITS(&bp[group+8+(j<<2)]);
		    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", ipaddr_string(&haddr));
		}
                (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," }");
            }
	    /* Next group record */
            group += 8 + (nsrcs << 2);
	    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"]");
        }
    }
    return;
trunc:
    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|igmp]");
    return;
}

static void
print_igmpv3_query(register const u_char *bp, register u_int len)
{
    u_int mrc, haddr;
    int mrt;
    u_int nsrcs;
    register u_int i;

    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," v3");
    /* Minimum len is 12, and should be a multiple of 4 */
    if (len < 12 || len & 0x03) {
	(void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [invalid len %d]", len);
	return;
    }
    TCHECK(bp[1]);
    mrc = bp[1];
    if (mrc < 128) {
	mrt = mrc;
    } else {
        mrt = ((mrc & 0x0f) | 0x10) << (((mrc & 0x70) >> 4) + 3);
    }
    if (mrc != 100) {
	(void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [max resp time ");
	relts_print(&ArgusBuf[strlen(ArgusBuf)], mrt);
	(void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"]");
    }
    TCHECK2(bp[4], 4);
    if ((haddr = EXTRACT_32BITS(&bp[4])) == 0)
	return;
    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [gaddr %s", ipaddr_string(&haddr));
    TCHECK2(bp[10], 2);
    nsrcs = EXTRACT_16BITS(&bp[10]);
    if (nsrcs > 0) {
	if (len < 12 + (nsrcs << 2))
	    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [invalid number of sources]");
	else if (ArgusParser->vflag > 1) {
	    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," {");
	    for (i=0; i<nsrcs; i++) {
		TCHECK2(bp[12+(i<<2)], 4);
	        haddr = EXTRACT_32BITS(&bp[12+(i<<2)]);
		(void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", ipaddr_string(&haddr));
	    }
	    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," }");
	} else
	    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],", %d source(s)", nsrcs);
    }
    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"]");
    return;
trunc:
    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|igmp]");
    return;
}


char *
igmp_print(register const u_char *bp, register u_int len)
{
    unsigned int haddr;
    if (ArgusParser->qflag) {
        (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"igmp");
        return ArgusBuf;
    }

    TCHECK(bp[0]);
    switch (bp[0]) {
    case 0x11:
        (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"igmp query");
	if (len >= 12)
	    print_igmpv3_query(bp, len);
	else {
            TCHECK(bp[1]);
	    if (bp[1]) {
		(void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," v2");
		if (bp[1] != 100)
		    (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [max resp time %d]", bp[1]);
	    } else
		(void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," v1");
            TCHECK2(bp[4], 4);
	    haddr = EXTRACT_32BITS(&bp[4]);
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [gaddr %s]", ipaddr_string(&haddr));
            if (len != 8)
                (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [len %d]", len);
	}
        break;
    case 0x12:
        TCHECK2(bp[4], 4);
	haddr = EXTRACT_32BITS(&bp[4]);
        (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"igmp v1 report %s", ipaddr_string(&haddr));
        if (len != 8)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [len %d]", len);
        break;
    case 0x16:
        TCHECK2(bp[4], 4);
	haddr = EXTRACT_32BITS(&bp[4]);
        (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"igmp v2 report %s", ipaddr_string(&haddr));
        break;
    case 0x22:
        (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"igmp v3 report");
	print_igmpv3_report(bp, len);
        break;
    case 0x17:
        TCHECK2(bp[4], 4);
	haddr = EXTRACT_32BITS(&bp[4]);
        (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"igmp leave %s", ipaddr_string(&haddr));
        break;
    case 0x13:
        (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"igmp dvmrp");
        if (len < 8)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [len %d]", len);
        else
            dvmrp_print(bp, len);
        break;
    case 0x14:
        (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"igmp pimv1");
        pimv1_print(bp, len);
        break;
    case 0x1e:
        print_mresp(bp, len);
        break;
    case 0x1f:
        print_mtrace(bp, len);
        break;
    default:
        (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"igmp-%d", bp[0]);
        break;
    }

    if (ArgusParser->vflag && TTEST2(bp[0], len)) {
        /* Check the IGMP checksum 
        if (in_cksum((const u_short*)bp, len, 0))
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," bad igmp cksum %x!", EXTRACT_16BITS(&bp[2]));
        */
    }

    return ArgusBuf;

trunc:
    sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|igmp]");
    return ArgusBuf;
}
