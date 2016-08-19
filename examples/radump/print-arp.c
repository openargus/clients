/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *   The Regents of the University of California.  All rights reserved.
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

/*
 * Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  ARP packets are variable
 * in size; the arphdr structure defines the fixed-length portion.
 * Protocol type values are the same as those for 10 Mb/s Ethernet.
 * It is followed by the variable-sized fields ar_sha, arp_spa,
 * arp_tha and arp_tpa in that order, according to the lengths
 * specified.  Field names used correspond to RFC 826.
 */

#define ARPHRD_ETHER    1   /* ethernet hardware format */
#define ARPHRD_IEEE802   6   /* token-ring hardware format */
#define ARPHRD_ARCNET   7   /* arcnet hardware format */
#define ARPHRD_FRELAY    15   /* frame relay hardware format */
#define ARPHRD_STRIP    23   /* Ricochet Starmode Radio hardware format */
#define ARPHRD_IEEE1394   24   /* IEEE 1394 (FireWire) hardware format */

#define ARPOP_REQUEST   1   /* request to resolve address */
#define ARPOP_REPLY   2   /* response to previous request */
#define ARPOP_REVREQUEST 3   /* request protocol address given hardware */
#define ARPOP_REVREPLY   4   /* response giving protocol address */
#define ARPOP_INVREQUEST 8    /* request to identify peer */
#define ARPOP_INVREPLY   9   /* response identifying peer */

#if !defined(ar_sha)
#define ar_sha(ap)   (((const u_char *)((ap)+1))+0)
#endif
#if !defined(ar_spa)
#define ar_spa(ap)   (((const u_char *)((ap)+1))+  (ap)->ar_hln)
#endif
#if !defined(ar_tha)
#define ar_tha(ap)   (((const u_char *)((ap)+1))+  (ap)->ar_hln+(ap)->ar_pln)
#endif
#if !defined(ar_tpa)
#define ar_tpa(ap)   (((const u_char *)((ap)+1))+2*(ap)->ar_hln+(ap)->ar_pln)
#endif

struct   arp_pkthdr {
   u_short ar_hrd;      /* format of hardware address */
   u_short ar_pro;      /* format of protocol address */
   u_char  ar_hln;      /* length of hardware address */
   u_char  ar_pln;      /* length of protocol address */
   u_short ar_op;      /* one of: */

/*
 * The remaining fields are variable in size,
 * according to the sizes above.
 */
#ifdef COMMENT_ONLY
   u_char   ar_sha[];   /* sender hardware address */
   u_char   ar_spa[];   /* sender protocol address */
   u_char   ar_tha[];   /* target hardware address */
   u_char   ar_tpa[];   /* target protocol address */
#endif
};

#define ARP_HDRLEN   8

#define HRD(ap) EXTRACT_16BITS(&(ap)->ar_hrd)
#define HLN(ap) ((ap)->ar_hln)
#define PLN(ap) ((ap)->ar_pln)
#define OP(ap)  EXTRACT_16BITS(&(ap)->ar_op)
#define PRO(ap) EXTRACT_16BITS(&(ap)->ar_pro)
#define ARPSHA(ap) (ar_sha(ap))
#define ARPSPA(ap) (ar_spa(ap))
#define ARPTHA(ap) (ar_tha(ap))
#define ARPTPA(ap) (ar_tpa(ap))

/*
 * ATM Address Resolution Protocol.
 *
 * See RFC 2225 for protocol description.  ATMARP packets are similar
 * to ARP packets, except that there are no length fields for the
 * protocol address - instead, there are type/length fields for
 * the ATM number and subaddress - and the hardware addresses consist
 * of an ATM number and an ATM subaddress.
 */
struct   atmarp_pkthdr {
   u_short   aar_hrd;   /* format of hardware address */
#define ARPHRD_ATM2225   19   /* ATM (RFC 2225) */
   u_short   aar_pro;   /* format of protocol address */
   u_char   aar_shtl;   /* length of source ATM number */
   u_char   aar_sstl;   /* length of source ATM subaddress */
#define ATMARP_IS_E164   0x40   /* bit in type/length for E.164 format */
#define ATMARP_LEN_MASK   0x3F   /* length of {sub}address in type/length */
   u_short   aar_op;      /* same as regular ARP */
#define ATMARPOP_NAK   10   /* NAK */
   u_char   aar_spln;   /* length of source protocol address */
   u_char   aar_thtl;   /* length of target ATM number */
   u_char   aar_tstl;   /* length of target ATM subaddress */
   u_char   aar_tpln;   /* length of target protocol address */
/*
 * The remaining fields are variable in size,
 * according to the sizes above.
 */
#ifdef COMMENT_ONLY
   u_char   aar_sha[];   /* source ATM number */
   u_char   aar_ssa[];   /* source ATM subaddress */
   u_char   aar_spa[];   /* sender protocol address */
   u_char   aar_tha[];   /* target ATM number */
   u_char   aar_tsa[];   /* target ATM subaddress */
   u_char   aar_tpa[];   /* target protocol address */
#endif

#define ATMHRD(ap)  EXTRACT_16BITS(&(ap)->aar_hrd)
#define ATMSHLN(ap) ((ap)->aar_shtl & ATMARP_LEN_MASK)
#define ATMSSLN(ap) ((ap)->aar_sstl & ATMARP_LEN_MASK)
#define ATMSPLN(ap) ((ap)->aar_spln)
#define ATMOP(ap)   EXTRACT_16BITS(&(ap)->aar_op)
#define ATMPRO(ap)  EXTRACT_16BITS(&(ap)->aar_pro)
#define ATMTHLN(ap) ((ap)->aar_thtl & ATMARP_LEN_MASK)
#define ATMTSLN(ap) ((ap)->aar_tstl & ATMARP_LEN_MASK)
#define ATMTPLN(ap) ((ap)->aar_tpln)
#define aar_sha(ap)   ((const u_char *)((ap)+1))
#define aar_ssa(ap)   (aar_sha(ap) + ATMSHLN(ap))
#define aar_spa(ap)   (aar_ssa(ap) + ATMSSLN(ap))
#define aar_tha(ap)   (aar_spa(ap) + ATMSPLN(ap))
#define aar_tsa(ap)   (aar_tha(ap) + ATMTHLN(ap))
#define aar_tpa(ap)   (aar_tsa(ap) + ATMTSLN(ap))
};

#define ATMSHA(ap) (aar_sha(ap))
#define ATMSSA(ap) (aar_ssa(ap))
#define ATMSPA(ap) (aar_spa(ap))
#define ATMTHA(ap) (aar_tha(ap))
#define ATMTSA(ap) (aar_tsa(ap))
#define ATMTPA(ap) (aar_tpa(ap))

/*
static void
atmarp_addr_print(const u_char *ha, u_int ha_len, const u_char *srca, u_int srca_len)
{
   if (ha_len == 0)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"<No address>");
   else {
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", linkaddr_string(ArgusParser, ha, ha_len));
      if (srca_len != 0) 
         sprintf(&ArgusBuf[strlen(ArgusBuf)],",%s", linkaddr_string(ArgusParser, srca, srca_len));
   }
}

static void
atmarp_print(const u_char *bp, u_int length, u_int caplen)
{
   const struct atmarp_pkthdr *ap;
   u_short pro, hrd, op;

   ap = (const struct atmarp_pkthdr *)bp;
   TCHECK(*ap);

   hrd = ATMHRD(ap);
   pro = ATMPRO(ap);
   op = ATMOP(ap);

   if (!TTEST2(*aar_tpa(ap), ATMTPLN(ap))) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"truncated-atmarp");
      return;
   }

   if ((pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL) ||
       ATMSPLN(ap) != 4 || ATMTPLN(ap) != 4) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"atmarp-#%d for proto #%d (%d/%d) hardware #%d",
           op, pro, ATMSPLN(ap), ATMTPLN(ap), hrd);
      return;
   }
   if (pro == ETHERTYPE_TRAIL)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"trailer-");
   switch (op) {

   case ARPOP_REQUEST:
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"arp who-has %s", ipaddr_string(ATMTPA(ap)));
      if (ATMTHLN(ap) != 0) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," (");
         atmarp_addr_print(ATMTHA(ap), ATMTHLN(ap), ATMTSA(ap), ATMTSLN(ap));
         sprintf(&ArgusBuf[strlen(ArgusBuf)],")");
      }
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," tell %s", ipaddr_string(ATMSPA(ap)));
      break;

   case ARPOP_REPLY:
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"arp reply %s", ipaddr_string(ATMSPA(ap)));
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," is-at ");
      atmarp_addr_print(ATMSHA(ap), ATMSHLN(ap), ATMSSA(ap), ATMSSLN(ap));
      break;

   case ARPOP_INVREQUEST:
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"invarp who-is ");
      atmarp_addr_print(ATMTHA(ap), ATMTHLN(ap), ATMTSA(ap), ATMTSLN(ap));
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," tell ");
      atmarp_addr_print(ATMSHA(ap), ATMSHLN(ap), ATMSSA(ap), ATMSSLN(ap));
      break;

   case ARPOP_INVREPLY:
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"invarp reply ");
      atmarp_addr_print(ATMSHA(ap), ATMSHLN(ap), ATMSSA(ap), ATMSSLN(ap));
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," at %s", ipaddr_string(ATMSPA(ap)));
      break;

   case ATMARPOP_NAK:
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"nak reply for %s", ipaddr_string(ATMSPA(ap)));
      break;

   default:
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"atmarp-#%d", op);
      return;
   }
   return;
trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|atmarp]");
}
*/

#include <argus_def.h>
extern char ArgusBuf[];

char *
arp_src_print(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusMetricStruct *metric = (void *) argus->dsrs[ARGUS_METRIC_INDEX];
   struct ArgusArpFlow *arp = (struct ArgusArpFlow *) &flow->arp_flow;
 
   if ((metric != NULL) && metric->src.pkts) {
      switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
         case ARGUS_TYPE_ARP:
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"who-has %s tell %s", ArgusGetName(parser, (unsigned char *)&arp->arp_tpa),
                                         ArgusGetName(parser, (unsigned char *)&arp->arp_spa));
            break;
      }
   }

   return (ArgusBuf);
}

char *
arp_dst_print(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusMetricStruct *metric = (void *) argus->dsrs[ARGUS_METRIC_INDEX];
   struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) argus->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusArpFlow *arp = (struct ArgusArpFlow *) &flow->arp_flow;

   if (net && ((metric != NULL) && metric->dst.pkts)) {
      switch (net->hdr.subtype & 0x1F) {
         case ARGUS_NETWORK_SUBTYPE_ARP:
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s is-at %s", ArgusGetName(parser, (unsigned char *)&arp->arp_tpa), 
                        etheraddr_string(parser, (unsigned char *)&net->net_union.arp.respaddr));
            break;
      }
   }

   return (ArgusBuf);
}

/*
 * Local Variables:
 * c-style: bsd
 * End:
 */

