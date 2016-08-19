/*
 * Copyright (c) 1995, 1996
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
extern void relts_print(char *, int);

#include "interface.h"

extern char ArgusBuf[];

#define PIMV2_TYPE_HELLO         0
#define PIMV2_TYPE_REGISTER      1
#define PIMV2_TYPE_REGISTER_STOP 2
#define PIMV2_TYPE_JOIN_PRUNE    3
#define PIMV2_TYPE_BOOTSTRAP     4
#define PIMV2_TYPE_ASSERT        5
#define PIMV2_TYPE_GRAFT         6
#define PIMV2_TYPE_GRAFT_ACK     7
#define PIMV2_TYPE_CANDIDATE_RP  8
#define PIMV2_TYPE_PRUNE_REFRESH 9

static struct tok pimv2_type_values[] = {
    { PIMV2_TYPE_HELLO,         "Hello" },
    { PIMV2_TYPE_REGISTER,      "Register" },
    { PIMV2_TYPE_REGISTER_STOP, "Register Stop" },
    { PIMV2_TYPE_JOIN_PRUNE,    "Join / Prune" },
    { PIMV2_TYPE_BOOTSTRAP,     "Bootstrap" },
    { PIMV2_TYPE_ASSERT,        "Assert" },
    { PIMV2_TYPE_GRAFT,         "Graft" },
    { PIMV2_TYPE_GRAFT_ACK,     "Graft Acknowledgement" },
    { PIMV2_TYPE_CANDIDATE_RP,  "Candidate RP Advertisement" },
    { PIMV2_TYPE_PRUNE_REFRESH, "Prune Refresh" },
    { 0, NULL}
};

#define PIMV2_HELLO_OPTION_HOLDTIME             1
#define PIMV2_HELLO_OPTION_LANPRUNEDELAY        2
#define PIMV2_HELLO_OPTION_DR_PRIORITY_OLD     18
#define PIMV2_HELLO_OPTION_DR_PRIORITY         19
#define PIMV2_HELLO_OPTION_GENID               20
#define PIMV2_HELLO_OPTION_REFRESH_CAP         21
#define PIMV2_HELLO_OPTION_BIDIR_CAP           22
#define PIMV2_HELLO_OPTION_ADDRESS_LIST        24
#define PIMV2_HELLO_OPTION_ADDRESS_LIST_OLD 65001

static struct tok pimv2_hello_option_values[] = {
    { PIMV2_HELLO_OPTION_HOLDTIME,         "Hold Time" },
    { PIMV2_HELLO_OPTION_LANPRUNEDELAY,    "LAN Prune Delay" },
    { PIMV2_HELLO_OPTION_DR_PRIORITY_OLD,  "DR Priority (Old)" },
    { PIMV2_HELLO_OPTION_DR_PRIORITY,      "DR Priority" },
    { PIMV2_HELLO_OPTION_GENID,            "Generation ID" },
    { PIMV2_HELLO_OPTION_REFRESH_CAP,      "State Refresh Capability" },
    { PIMV2_HELLO_OPTION_BIDIR_CAP,        "Bi-Directional Capability" },
    { PIMV2_HELLO_OPTION_ADDRESS_LIST,     "Address List" },
    { PIMV2_HELLO_OPTION_ADDRESS_LIST_OLD, "Address List (Old)" },
    { 0, NULL}
};


/*
 * XXX: We consider a case where IPv6 is not ready yet for portability,
 * but PIM dependent defintions should be independent of IPv6...
 */

struct pim {
   u_int8_t pim_typever;
         /* upper 4bit: PIM version number; 2 for PIMv2 */
         /* lower 4bit: the PIM message type, currently they are:
          * Hello, Register, Register-Stop, Join/Prune,
          * Bootstrap, Assert, Graft (PIM-DM only),
          * Graft-Ack (PIM-DM only), C-RP-Adv
          */
#define PIM_VER(x)   (((x) & 0xf0) >> 4)
#define PIM_TYPE(x)   ((x) & 0x0f)
   u_char  pim_rsv;   /* Reserved */
   u_short   pim_cksum;   /* IP style check sum */
};


static void pimv2_print(register const u_char *bp, register u_int len);

static void
pimv1_join_prune_print(register const u_char *bp, register u_int len)
{
// int maddrlen, addrlen, ngroups, njoin, nprune, njp;
   int ngroups, njoin, nprune, njp;
   unsigned int haddr;

   /* If it's a single group and a single source, use 1-line output. */
   if (TTEST2(bp[0], 30) && bp[11] == 1 &&
       ((njoin = EXTRACT_16BITS(&bp[20])) + EXTRACT_16BITS(&bp[22])) == 1) {
      int hold;

      haddr = EXTRACT_32BITS(bp);
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," RPF %s ", ipaddr_string(&haddr));
      hold = EXTRACT_16BITS(&bp[6]);
      if (hold != 180) {
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"Hold ");
         relts_print(&ArgusBuf[strlen(ArgusBuf)],hold);
      }
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s (%s/%d, %s", njoin ? "Join" : "Prune",
      ipaddr_string(&bp[26]), bp[25] & 0x3f,
      ipaddr_string(&bp[12]));
      if ((haddr = EXTRACT_32BITS(&bp[16])) != 0xffffffff)
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"/%s", ipaddr_string(&haddr));
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],") %s%s %s",
          (bp[24] & 0x01) ? "Sparse" : "Dense",
          (bp[25] & 0x80) ? " WC" : "",
          (bp[25] & 0x40) ? "RP" : "SPT");
      return;
   }

   TCHECK2(bp[0], sizeof(struct in_addr));
   haddr = EXTRACT_32BITS(bp);
   (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Upstream Nbr: %s", ipaddr_string(&haddr));
   TCHECK2(bp[6], 2);
   (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Hold time: ");
   relts_print(&ArgusBuf[strlen(ArgusBuf)],EXTRACT_16BITS(&bp[6]));
   if (ArgusParser->vflag < 2)
      return;
   bp += 8;
   len -= 8;

   TCHECK2(bp[0], 4);
// maddrlen = bp[1];
// addrlen = bp[2];
   ngroups = bp[3];
   bp += 4;
   len -= 4;
   while (ngroups--) {
      /*
       * XXX - does the address have length "addrlen" and the
       * mask length "maddrlen"?
       */
      TCHECK2(bp[0], sizeof(struct in_addr));
      haddr = EXTRACT_32BITS(bp);
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Group: %s", ipaddr_string(&haddr));
      TCHECK2(bp[4], sizeof(struct in_addr));
      if ((haddr = EXTRACT_32BITS(&bp[4])) != 0xffffffff)
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"/%s", ipaddr_string(&haddr));
      TCHECK2(bp[8], 4);
      njoin = EXTRACT_16BITS(&bp[8]);
      nprune = EXTRACT_16BITS(&bp[10]);
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," joined: %d pruned: %d", njoin, nprune);
      bp += 12;
      len -= 12;
      for (njp = 0; njp < (njoin + nprune); njp++) {
         const char *type;

         if (njp < njoin)
            type = "Join ";
         else
            type = "Prune";
         TCHECK2(bp[0], 6);
         haddr = EXTRACT_32BITS(&bp[2]);
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s %s%s%s%s/%d", type,
             (bp[0] & 0x01) ? "Sparse " : "Dense ",
             (bp[1] & 0x80) ? "WC " : "",
             (bp[1] & 0x40) ? "RP " : "SPT ",
         ipaddr_string(&haddr), bp[1] & 0x3f);
         bp += 6;
         len -= 6;
      }
   }
   return;
trunc:
   (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|pim]");
   return;
}


char *
pimv1_print(register const u_char *bp, register u_int len)
{
   register const u_char *ep;
   unsigned int haddr, saddr, daddr;
   register u_char type;

   ep = (const u_char *)snapend;
   if (bp >= ep)
      return ArgusBuf;

   TCHECK(bp[1]);
   type = bp[1];

   switch (type) {
   case 0:
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Query");
      if (TTEST(bp[8])) {
         switch (bp[8] >> 4) {
         case 0:
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Dense-mode");
            break;
         case 1:
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Sparse-mode");
            break;
         case 2:
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Sparse-Dense-mode");
            break;
         default:
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," mode-%d", bp[8] >> 4);
            break;
         }
      }
      if (ArgusParser->vflag) {
         TCHECK2(bp[10],2);
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," (Hold-time ");
         relts_print(&ArgusBuf[strlen(ArgusBuf)],EXTRACT_16BITS(&bp[10]));
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],")");
      }
      break;

   case 1:
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Register");
      TCHECK2(bp[8], 20);         /* ip header */
      haddr = EXTRACT_32BITS(&bp[20]);
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," for %s > %s", ipaddr_string(&haddr),
          ipaddr_string(&bp[24]));
      break;
   case 2:
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Register-Stop");
      TCHECK2(bp[12], sizeof(struct in_addr));
      saddr = EXTRACT_32BITS(&bp[8]);
      daddr = EXTRACT_32BITS(&bp[12]);
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," for %s > %s", ipaddr_string(&saddr),
          ipaddr_string(&daddr));
      break;
   case 3:
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Join/Prune");
      if (ArgusParser->vflag)
         pimv1_join_prune_print(&bp[8], len - 8);
      break;
   case 4:
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," RP-reachable");
      if (ArgusParser->vflag) {
         TCHECK2(bp[22], 2);
         haddr = EXTRACT_32BITS(&bp[8]);
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," group %s", ipaddr_string(&haddr));
         if ((haddr = EXTRACT_32BITS(&bp[12])) != 0xffffffff)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"/%s", ipaddr_string(&haddr));
         haddr = EXTRACT_32BITS(&bp[16]);
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," RP %s hold ", ipaddr_string(&haddr));
         relts_print(&ArgusBuf[strlen(ArgusBuf)],EXTRACT_16BITS(&bp[22]));
      }
      break;
   case 5:
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Assert");
      TCHECK2(bp[16], sizeof(struct in_addr));
      saddr = EXTRACT_32BITS(&bp[16]);
      daddr = EXTRACT_32BITS(&bp[8]);
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," for %s > %s", ipaddr_string(&saddr), ipaddr_string(&daddr));
      if ((haddr = EXTRACT_32BITS(&bp[12])) != 0xffffffff)
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"/%s", ipaddr_string(&haddr));
      TCHECK2(bp[24], 4);
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s pref %d metric %d",
          (bp[20] & 0x80) ? "RP-tree" : "SPT",
      EXTRACT_32BITS(&bp[20]) & 0x7fffffff,
      EXTRACT_32BITS(&bp[24]));
      break;
   case 6:
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Graft");
      if (ArgusParser->vflag)
         pimv1_join_prune_print(&bp[8], len - 8);
      break;
   case 7:
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Graft-ACK");
      if (ArgusParser->vflag)
         pimv1_join_prune_print(&bp[8], len - 8);
      break;
   case 8:
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Mode");
      break;
   default:
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [type %d]", type);
      break;
   }
   if ((bp[4] >> 4) != 1)
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [v%d]", bp[4] >> 4);
   return ArgusBuf;

trunc:
   (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|pim]");
   return ArgusBuf;
}

/*
 * auto-RP is a cisco protocol, documented at
 * ftp://ftpeng.cisco.com/ipmulticast/specs/pim-autorp-spec01.txt
 *
 * This implements version 1+, dated Sept 9, 1998.
 */

void cisco_autorp_print(register const u_char *, register u_int);

void
cisco_autorp_print(register const u_char *bp, register u_int len)
{
   int type;
   int numrps;
   int hold;

   TCHECK(bp[0]);
   (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," auto-rp ");
   type = bp[0];
   switch (type) {
   case 0x11:
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"candidate-advert");
      break;
   case 0x12:
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"mapping");
      break;
   default:
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"type-0x%02x", type);
      break;
   }

   TCHECK(bp[1]);
   numrps = bp[1];

   TCHECK2(bp[2], 2);
   (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Hold ");
   hold = EXTRACT_16BITS(&bp[2]);
   if (hold)
      relts_print(&ArgusBuf[strlen(ArgusBuf)],EXTRACT_16BITS(&bp[2]));
   else
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"FOREVER");

   /* Next 4 bytes are reserved. */

   bp += 8; len -= 8;

   /*XXX skip unless -v? */

   /*
    * Rest of packet:
    * numrps entries of the form:
    * 32 bits: RP
    * 6 bits: reserved
    * 2 bits: PIM version supported, bit 0 is "supports v1", 1 is "v2".
    * 8 bits: # of entries for this RP
    * each entry: 7 bits: reserved, 1 bit: negative,
    *          8 bits: mask 32 bits: source
    * lather, rinse, repeat.
    */
   while (numrps--) {
      unsigned int haddr;
      int nentries;
      char s;

      TCHECK2(bp[0], 4);
      haddr = EXTRACT_32BITS(bp);
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," RP %s", ipaddr_string(&haddr));
      TCHECK(bp[4]);
      switch (bp[4] & 0x3) {
      case 0: sprintf(&ArgusBuf[strlen(ArgusBuf)]," PIMv?");
         break;
      case 1:   sprintf(&ArgusBuf[strlen(ArgusBuf)]," PIMv1");
         break;
      case 2:   sprintf(&ArgusBuf[strlen(ArgusBuf)]," PIMv2");
         break;
      case 3:   sprintf(&ArgusBuf[strlen(ArgusBuf)]," PIMv1+2");
         break;
      }
      if (bp[4] & 0xfc)
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [rsvd=0x%02x]", bp[4] & 0xfc);
      TCHECK(bp[5]);
      nentries = bp[5];
      bp += 6; len -= 6;
      s = ' ';
      for (; nentries; nentries--) {
         TCHECK2(bp[0], 6);
         haddr = EXTRACT_32BITS(bp);
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"%c%s%s/%d", s, bp[0] & 1 ? "!" : "",
             ipaddr_string(&haddr), bp[1]);
         if (bp[0] & 0xfe)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"[rsvd=0x%02x]", bp[0] & 0xfe);
         s = ',';
         bp += 6; len -= 6;
      }
   }
   return;

trunc:
   (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|autorp]");
   return;
}

char *
pim_print(register const u_char *bp, register u_int len)
{
   register const u_char *ep;
   register struct pim *pim = (struct pim *)bp;

   ep = (const u_char *)snapend;
   if (bp >= ep)
      return ArgusBuf;
#ifdef notyet         /* currently we see only version and type */
   TCHECK(pim->pim_rsv);
#endif

   switch (PIM_VER(pim->pim_typever)) {
      case 2:
         if (!ArgusParser->vflag) {
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"PIMv%u, %s, length: %u", PIM_VER(pim->pim_typever),
               tok2str(pimv2_type_values,"Unknown Type",PIM_TYPE(pim->pim_typever)),
               len);
            return ArgusBuf;
         } else {
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"PIMv%u, length: %u %s", PIM_VER(pim->pim_typever), len,
               tok2str(pimv2_type_values,"Unknown Type",PIM_TYPE(pim->pim_typever)));
            pimv2_print(bp, len);
         }
            break;
      default:
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"PIMv%u, length: %u", PIM_VER(pim->pim_typever), len);
         break;
   }
   return ArgusBuf;
}

/*
 * PIMv2 uses encoded address representations.
 *
 * The last PIM-SM I-D before RFC2117 was published specified the
 * following representation for unicast addresses.  However, RFC2117
 * specified no encoding for unicast addresses with the unicast
 * address length specified in the header.  Therefore, we have to
 * guess which encoding is being used (Cisco's PIMv2 implementation
 * uses the non-RFC encoding).  RFC2117 turns a previously "Reserved"
 * field into a 'unicast-address-length-in-bytes' field.  We guess
 * that it's the draft encoding if this reserved field is zero.
 *
 * RFC2362 goes back to the encoded format, and calls the addr length
 * field "reserved" again.
 *
 * The first byte is the address family, from:
 *
 *    0    Reserved
 *    1    IP (IP version 4)
 *    2    IP6 (IP version 6)
 *    3    NSAP
 *    4    HDLC (8-bit multidrop)
 *    5    BBN 1822
 *    6    802 (includes all 802 media plus Ethernet "canonical format")
 *    7    E.163
 *    8    E.164 (SMDS, Frame Relay, ATM)
 *    9    F.69 (Telex)
 *   10    X.121 (X.25, Frame Relay)
 *   11    IPX
 *   12    Appletalk
 *   13    Decnet IV
 *   14    Banyan Vines
 *   15    E.164 with NSAP format subaddress
 *
 * In addition, the second byte is an "Encoding".  0 is the default
 * encoding for the address family, and no other encodings are currently
 * specified.
 *
 */

static int pimv2_addr_len;

enum pimv2_addrtype {
   pimv2_unicast, pimv2_group, pimv2_source
};

/*  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Addr Family   | Encoding Type |     Unicast Address           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+++++++
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Addr Family   | Encoding Type |   Reserved    |  Mask Len     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Group multicast Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Addr Family   | Encoding Type | Rsrvd   |S|W|R|  Mask Len     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Source Address                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static int
pimv2_addr_print(const u_char *bp, enum pimv2_addrtype at, int silent)
{
   u_int haddr;
   int len, hdrlen;
   int af;

   TCHECK(bp[0]);

   if (pimv2_addr_len == 0) {
      TCHECK(bp[1]);
      switch (bp[0]) {
      case 1:
         af = AF_INET;
         len = sizeof(struct in_addr);
         break;
#ifdef INET6
      case 2:
         af = AF_INET6;
         len = sizeof(struct in6_addr);
         break;
#endif
      default:
         return -1;
      }
      if (bp[1] != 0)
         return -1;
      hdrlen = 2;
   } else {
      switch (pimv2_addr_len) {
      case sizeof(struct in_addr):
         af = AF_INET;
         break;
#ifdef INET6
      case sizeof(struct in6_addr):
         af = AF_INET6;
         break;
#endif
      default:
         return -1;
         break;
      }
      len = pimv2_addr_len;
      hdrlen = 0;
   }

   bp += hdrlen;
   switch (at) {
   case pimv2_unicast:
      TCHECK2(bp[0], len);
      haddr = EXTRACT_32BITS(bp);
      if (af == AF_INET) {
         if (!silent)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", ipaddr_string(&haddr));
      }
#ifdef INET6
      else if (af == AF_INET6) {
         if (!silent)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", ip6addr_string(bp));
      }
#endif
      return hdrlen + len;
   case pimv2_group:
   case pimv2_source:
      TCHECK2(bp[0], len + 2);
      haddr = EXTRACT_32BITS(bp + 2);
      if (af == AF_INET) {
         if (!silent) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", ipaddr_string(&haddr));
            if (bp[1] != 32)
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"/%u", bp[1]);
         }
      }
#ifdef INET6
      else if (af == AF_INET6) {
         if (!silent) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", ip6addr_string(bp + 2));
            if (bp[1] != 128)
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"/%u", bp[1]);
         }
      }
#endif
      if (bp[0] && !silent) {
         if (at == pimv2_group) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"(0x%02x)", bp[0]);
         } else {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"(%s%s%s",
               bp[0] & 0x04 ? "S" : "",
               bp[0] & 0x02 ? "W" : "",
               bp[0] & 0x01 ? "R" : "");
            if (bp[0] & 0xf8) {
               (void) sprintf(&ArgusBuf[strlen(ArgusBuf)],"+0x%02x", bp[0] & 0xf8);
            }
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],")");
         }
      }
      return hdrlen + 2 + len;
   default:
      return -1;
   }
trunc:
   return -1;
}

static void
pimv2_print(register const u_char *bp, register u_int len)
{
   register const u_char *ep;
   register struct pim *pim = (struct pim *)bp;
   int advance;

   ep = (const u_char *)snapend;
   if (bp >= ep)
      return;
   if (ep > bp + len)
      ep = bp + len;
   TCHECK(pim->pim_rsv);
   pimv2_addr_len = pim->pim_rsv;
   if (pimv2_addr_len != 0)
      (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],", RFC2117-encoding");

   switch (PIM_TYPE(pim->pim_typever)) {
      case PIMV2_TYPE_HELLO: {
         u_int16_t otype, olen;
         bp += 4;
         while (bp < ep) {
            TCHECK2(bp[0], 4);
            otype = EXTRACT_16BITS(&bp[0]);
            olen = EXTRACT_16BITS(&bp[2]);
            TCHECK2(bp[0], 4 + olen);

            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s Option (%u), length: %u, Value: ",
                 tok2str( pimv2_hello_option_values,"Unknown",otype),
                 otype, olen);
            bp += 4;

            switch (otype) {
               case PIMV2_HELLO_OPTION_HOLDTIME:
                  relts_print(&ArgusBuf[strlen(ArgusBuf)],EXTRACT_16BITS(bp));
                  break;

               case PIMV2_HELLO_OPTION_LANPRUNEDELAY:
                  if (olen != 4) {
                     (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"ERROR: Option Lenght != 4 Bytes (%u)", olen);
                  } else {
                     char t_bit;
                     u_int16_t lan_delay, override_interval;
                     lan_delay = EXTRACT_16BITS(bp);
                     override_interval = EXTRACT_16BITS(bp+2);
                     t_bit = (lan_delay & 0x8000)? 1 : 0;
                     lan_delay &= ~0x8000;
                     (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," T-bit=%d, LAN delay %dms, Override interval %dms",
                     t_bit, lan_delay, override_interval);
                  }
                  break;

               case PIMV2_HELLO_OPTION_DR_PRIORITY_OLD:
               case PIMV2_HELLO_OPTION_DR_PRIORITY:
                  switch (olen) {
                     case 0:
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],"Bi-Directional Capability (Old)");
                        break;
                     case 4:
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],"%u", EXTRACT_32BITS(bp));
                        break;
                     default:
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],"ERROR: Option Lenght != 4 Bytes (%u)", olen);
                        break;
                  }
                  break;

               case PIMV2_HELLO_OPTION_GENID:
                  (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"0x%08x", EXTRACT_32BITS(bp));
                  break;

               case PIMV2_HELLO_OPTION_REFRESH_CAP:
                  (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"v%d", *bp);
                  if (*(bp+1) != 0) {
                     (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],", interval ");
                     relts_print(&ArgusBuf[strlen(ArgusBuf)],*(bp+1));
                  }
                  if (EXTRACT_16BITS(bp+2) != 0) {
                     (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," ?0x%04x?", EXTRACT_16BITS(bp+2));
                  }
                  break;

               case  PIMV2_HELLO_OPTION_BIDIR_CAP:
                  break;

               case PIMV2_HELLO_OPTION_ADDRESS_LIST_OLD:
               case PIMV2_HELLO_OPTION_ADDRESS_LIST:
                  if (ArgusParser->vflag > 1) {
                     const u_char *ptr = bp;
                     while (ptr < (bp+olen)) {
                        int advance;
                        sprintf(&ArgusBuf[strlen(ArgusBuf)]," ");
                        advance = pimv2_addr_print(ptr, pimv2_unicast, 0);
                        if (advance < 0) {
                           sprintf(&ArgusBuf[strlen(ArgusBuf)],"...");
                           break;
                        }
                        ptr += advance;
                     }
                  }
                  break;

               default:
                  if (ArgusParser->vflag <= 1)
                     print_unknown_data(bp," ",olen);
                  break;
            }
            /* do we want to see an additionally hexdump ? */
            if (ArgusParser->vflag> 1)
               print_unknown_data(bp," ",olen);
            bp += olen;
         }
         break;
      }

      case PIMV2_TYPE_REGISTER: {
/*
         struct ip *ip;
*/
         if (ArgusParser->vflag && bp + 8 <= ep) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s%s", bp[4] & 0x80 ? "B" : "",
               bp[4] & 0x40 ? "N" : "");
         }
         bp += 8; len -= 8;

         /* encapsulated multicast packet */
         if (bp >= ep)
            break;
/*
         ip = (struct ip *)bp;
         switch (IP_V(ip)) {
            case 4:
               sprintf(&ArgusBuf[strlen(ArgusBuf)]," ");
               ip_print(bp, len);
               break;
#ifdef INET6
            case 6:
               sprintf(&ArgusBuf[strlen(ArgusBuf)]," ");
               ip6_print(bp, len);
               break;
#endif
            default:
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," IP ver %d", IP_V(ip));
               break;
         }
*/
         break;
      }

      case PIMV2_TYPE_REGISTER_STOP:
         bp += 4; len -= 4;
         if (bp >= ep)
            break;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," group=");
         if ((advance = pimv2_addr_print(bp, pimv2_group, 0)) < 0) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...");
            break;
         }
         bp += advance; len -= advance;
         if (bp >= ep)
            break;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," source=");
         if ((advance = pimv2_addr_print(bp, pimv2_unicast, 0)) < 0) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...");
            break;
         }
         bp += advance; len -= advance;
         break;

      case PIMV2_TYPE_JOIN_PRUNE:
      case PIMV2_TYPE_GRAFT:
      case PIMV2_TYPE_GRAFT_ACK: {


        /*
         * 0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |PIM Ver| Type  | Addr length   |           Checksum            |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |             Unicast-Upstream Neighbor Address                 |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |  Reserved     | Num groups    |          Holdtime             |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |            Encoded-Multicast Group Address-1                  |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |   Number of Joined  Sources   |   Number of Pruned Sources    |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |               Encoded-Joined Source Address-1                 |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                             .                                 |
         *  |                             .                                 |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |               Encoded-Joined Source Address-n                 |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |               Encoded-Pruned Source Address-1                 |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                             .                                 |
         *  |                             .                                 |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |               Encoded-Pruned Source Address-n                 |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                           .                                   |
         *  |                           .                                   |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                Encoded-Multicast Group Address-n              |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */

         u_int8_t ngroup;
         u_int16_t holdtime;
         u_int16_t njoin;
         u_int16_t nprune;
         int i, j;

         bp += 4; len -= 4;
         if (PIM_TYPE(pim->pim_typever) != 7) {   /*not for Graft-ACK*/
            if (bp >= ep)
               break;
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],", upstream-neighbor: ");
            if ((advance = pimv2_addr_print(bp, pimv2_unicast, 0)) < 0) {
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...");
               break;
            }
            bp += advance; len -= advance;
         }
         if (bp + 4 > ep)
            break;
         ngroup = bp[1];
         holdtime = EXTRACT_16BITS(&bp[2]);
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u group(s)", ngroup);
         if (PIM_TYPE(pim->pim_typever) != 7) {   /*not for Graft-ACK*/
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],", holdtime: ");
            if (holdtime == 0xffff)
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"infinite");
            else
               relts_print(&ArgusBuf[strlen(ArgusBuf)],holdtime);
         }
         bp += 4; len -= 4;
         for (i = 0; i < ngroup; i++) {
            if (bp >= ep)
               goto jp_done;
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," group #%u: ", i+1);
            if ((advance = pimv2_addr_print(bp, pimv2_group, 0)) < 0) {
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...)");
               goto jp_done;
            }
            bp += advance; len -= advance;
            if (bp + 4 > ep) {
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...)");
               goto jp_done;
            }
            njoin = EXTRACT_16BITS(&bp[0]);
            nprune = EXTRACT_16BITS(&bp[2]);
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],", joined sources: %u, pruned sources: %u", njoin,nprune);
            bp += 4; len -= 4;
            for (j = 0; j < njoin; j++) {
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," joined source #%u: ",j+1);
               if ((advance = pimv2_addr_print(bp, pimv2_source, 0)) < 0) {
                  (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...)");
                  goto jp_done;
               }
               bp += advance; len -= advance;
            }
            for (j = 0; j < nprune; j++) {
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," pruned source #%u: ",j+1);
               if ((advance = pimv2_addr_print(bp, pimv2_source, 0)) < 0) {
                  (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...)");
                  goto jp_done;
               }
               bp += advance; len -= advance;
            }
         }
         jp_done:
            break;
      }

      case PIMV2_TYPE_BOOTSTRAP: {
         int i, j, frpcnt;
         bp += 4;

         /* Fragment Tag, Hash Mask len, and BSR-priority */
         if (bp + sizeof(u_int16_t) >= ep) break;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," tag=%x", EXTRACT_16BITS(bp));
         bp += sizeof(u_int16_t);
         if (bp >= ep) break;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," hashmlen=%d", bp[0]);
         if (bp + 1 >= ep) break;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," BSRprio=%d", bp[1]);
         bp += 2;

         /* Encoded-Unicast-BSR-Address */
         if (bp >= ep) break;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," BSR=");
         if ((advance = pimv2_addr_print(bp, pimv2_unicast, 0)) < 0) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...");
            break;
         }
         bp += advance;

         for (i = 0; bp < ep; i++) {
            /* Encoded-Group Address */
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," (group%d: ", i);
            if ((advance = pimv2_addr_print(bp, pimv2_group, 0))
                < 0) {
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...)");
               goto bs_done;
            }
            bp += advance;

            /* RP-Count, Frag RP-Cnt, and rsvd */
            if (bp >= ep) {
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...)");
               goto bs_done;
            }
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," RPcnt=%d", bp[0]);
            if (bp + 1 >= ep) {
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...)");
               goto bs_done;
            }
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," FRPcnt=%d", frpcnt = bp[1]);
            bp += 4;

            for (j = 0; j < frpcnt && bp < ep; j++) {
               /* each RP info */
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," RP%d=", j);
               if ((advance = pimv2_addr_print(bp,
                           pimv2_unicast,
                           0)) < 0) {
                  (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...)");
                  goto bs_done;
               }
               bp += advance;

               if (bp + 1 >= ep) {
                  (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...)");
                  goto bs_done;
               }
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],",holdtime=");
               relts_print(&ArgusBuf[strlen(ArgusBuf)],EXTRACT_16BITS(bp));
               if (bp + 2 >= ep) {
                  (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...)");
                  goto bs_done;
               }
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],",prio=%d", bp[2]);
               bp += 4;
            }
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],")");
         }
         bs_done:
         break;
      }

      case PIMV2_TYPE_ASSERT:
         bp += 4; len -= 4;
         if (bp >= ep)
            break;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," group=");
         if ((advance = pimv2_addr_print(bp, pimv2_group, 0)) < 0) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...");
            break;
         }
         bp += advance; len -= advance;
         if (bp >= ep)
            break;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," src=");
         if ((advance = pimv2_addr_print(bp, pimv2_unicast, 0)) < 0) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...");
            break;
         }
         bp += advance; len -= advance;
         if (bp + 8 > ep)
            break;
         if (bp[0] & 0x80)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," RPT");
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," pref=%u", EXTRACT_32BITS(&bp[0]) & 0x7fffffff);
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," metric=%u", EXTRACT_32BITS(&bp[4]));
         break;

      case PIMV2_TYPE_CANDIDATE_RP: {
         int i, pfxcnt;
         bp += 4;

         /* Prefix-Cnt, Priority, and Holdtime */
         if (bp >= ep) break;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," prefix-cnt=%d", bp[0]);
         pfxcnt = bp[0];
         if (bp + 1 >= ep) break;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," prio=%d", bp[1]);
         if (bp + 3 >= ep) break;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," holdtime=");
         relts_print(&ArgusBuf[strlen(ArgusBuf)],EXTRACT_16BITS(&bp[2]));
         bp += 4;

         /* Encoded-Unicast-RP-Address */
         if (bp >= ep) break;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," RP=");
         if ((advance = pimv2_addr_print(bp, pimv2_unicast, 0)) < 0) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...");
            break;
         }
         bp += advance;

         /* Encoded-Group Addresses */
         for (i = 0; i < pfxcnt && bp < ep; i++) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Group%d=", i);
            if ((advance = pimv2_addr_print(bp, pimv2_group, 0))
                < 0) {
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...");
               break;
            }
            bp += advance;
         }
         break;
      }

      case PIMV2_TYPE_PRUNE_REFRESH:
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," src=");
         if ((advance = pimv2_addr_print(bp, pimv2_unicast, 0)) < 0) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...");
            break;
         }
         bp += advance;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," grp=");
         if ((advance = pimv2_addr_print(bp, pimv2_group, 0)) < 0) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...");
            break;
         }
         bp += advance;
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," forwarder=");
         if ((advance = pimv2_addr_print(bp, pimv2_unicast, 0)) < 0) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"...");
            break;
         }
         bp += advance;
         TCHECK2(bp[0], 2);
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," TUNR ");
         relts_print(&ArgusBuf[strlen(ArgusBuf)],EXTRACT_16BITS(bp));
         break;

      default:
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [type %d]", PIM_TYPE(pim->pim_typever));
         break;
   }
   return;

trunc:
   (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|pim]");
}

/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 8
 * End:
 */
