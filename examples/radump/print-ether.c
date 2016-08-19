/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000
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
#include <argus_ethertype.h>

#include <signal.h>
#include <ctype.h>
#include <argus/extract.h>

extern u_char *snapend;
extern const struct tok ethertype_values[];

int suppress_default_print = 1;

#include "interface.h"

extern char ArgusBuf[];

static inline void
ether_hdr_print(register const u_char *bp, u_int length)
{
   register const struct ether_header *ep;
   ep = (const struct ether_header *)bp;

   (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s > %s", etheraddr_string(ArgusParser, (u_char *)&ESRC(ep)),
                                                        etheraddr_string(ArgusParser, (u_char *)&EDST(ep)));

   if (!ArgusParser->qflag) {
           if (ntohs(ep->ether_type) <= ETHERMTU)
                (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],", 802.3");
                else 
                (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],", ethertype %s (0x%04x)",
                   tok2str(ethertype_values,"Unknown", ntohs(ep->ether_type)),
                                       ntohs(ep->ether_type));         
        } else {
                if (ntohs(ep->ether_type) <= ETHERMTU)
                          (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],", 802.3");
                else 
                          (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],", %s", tok2str(ethertype_values,"Unknown Ethertype (0x%04x)", ntohs(ep->ether_type)));  
        }

   (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],", length %u: ", length);
}

int ether_encap_print(u_short, const u_char *, u_int, u_int, u_short *);
char * ether_print(struct ArgusParserStruct *, struct ArgusRecordStruct *, const u_char *, u_int);

char *
ether_print(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, const u_char *p, u_int length)
{
   struct ArgusMacStruct *mac = (void *)argus->dsrs[ARGUS_MAC_INDEX];

   if (mac != NULL) {
      struct ether_header *ep = &mac->mac.mac_union.ether.ehdr;
      u_int caplen = length;
      u_short ether_type;
      u_short extracted_ether_type;

      if (caplen < ETHER_HDRLEN) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|ether]");
         return ArgusBuf;
      }

      if (ArgusParser->eflag)
         ether_hdr_print(p, length);

      length -= ETHER_HDRLEN;
      caplen -= ETHER_HDRLEN;
      ep = (struct ether_header *)p;
      p += ETHER_HDRLEN;

      ether_type = ntohs(ep->ether_type);

      /*
       * Is it (gag) an 802.3 encapsulation?
       */
      extracted_ether_type = 0;
      if (ether_type <= ETHERMTU) {
/*
         if (llc_print(p, length, caplen, ESRC(ep), EDST(ep),
             &extracted_ether_type) == 0) {
            if (!ArgusParser->eflag)
               ether_hdr_print((u_char *)ep, length + ETHER_HDRLEN);

            if (!suppress_default_print)
               default_print(p, caplen);
         }
*/
      } else if (ether_encap_print(ether_type, p, length, caplen,
          &extracted_ether_type) == 0) {
         /* ether_type not known, print raw packet */
         if (!ArgusParser->eflag)
            ether_hdr_print((u_char *)ep, length + ETHER_HDRLEN);
/*
         if (!suppress_default_print)
            default_print(p, caplen);
*/
      } 
   }

   return ArgusBuf;
}


/*
 * Prints the packet encapsulated in an Ethernet data segment
 * (or an equivalent encapsulation), given the Ethernet type code.
 *
 * Returns non-zero if it can do so, zero if the ethertype is unknown.
 *
 * The Ethernet type code is passed through a pointer; if it was
 * ETHERTYPE_8021Q, it gets updated to be the Ethernet type of
 * the 802.1Q payload, for the benefit of lower layers that might
 * want to know what it is.
 */

int
ether_encap_print(u_short ether_type, const u_char *p,
    u_int length, u_int caplen, u_short *extracted_ether_type)
{
 recurse:
   *extracted_ether_type = ether_type;

   switch (ether_type) {
/*
   case ETHERTYPE_DN:
      decnet_print(p, length, caplen);
      return (1);

   case ETHERTYPE_ATALK:
      if (ArgusParser->vflag)
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"et1 ");
      atalk_print(p, length);
      return (1);

   case ETHERTYPE_AARP:
      aarp_print(p, length);
      return (1);

   case ETHERTYPE_IPX:
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"(NOV-ETHII) ");
      ipx_print(p, length);
      return (1);

   case ETHERTYPE_8021Q:
           if (ArgusParser->eflag)
          sprintf(&ArgusBuf[strlen(ArgusBuf)],"vlan %u, p %u%s, ",
            ntohs(*(u_int16_t *)p) & 0xfff,
            ntohs(*(u_int16_t *)p) >> 13,
            (ntohs(*(u_int16_t *)p) & 0x1000) ? ", CFI" : "");

      ether_type = ntohs(*(u_int16_t *)(p + 2));
      p += 4;
      length -= 4;
      caplen -= 4;

      if (ether_type > ETHERMTU) {
              if (ArgusParser->eflag)
                 sprintf(&ArgusBuf[strlen(ArgusBuf)],"ethertype %s, ",
                   tok2str(ethertype_values,"0x%04x", ether_type));
         goto recurse;
      }

      *extracted_ether_type = 0;

      if (llc_print(p, length, caplen, p - 18, p - 12,
          extracted_ether_type) == 0) {
            ether_hdr_print(p - 18, length + 4);
      }

      if (!suppress_default_print)
              default_print(p - 18, caplen + 4);
      return (1);
*/
        case ETHERTYPE_JUMBO:
                ether_type = ntohs(*(u_int16_t *)(p));
                p += 2;
                length -= 2;      
                caplen -= 2;

                if (ether_type > ETHERMTU) {
                    if (ArgusParser->eflag)
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],"ethertype %s, ",
                               tok2str(ethertype_values,"0x%04x", ether_type));
                    goto recurse;
                }

                *extracted_ether_type = 0;

/*
                if (llc_print(p, length, caplen, p - 16, p - 10,
                              extracted_ether_type) == 0) {
                    ether_hdr_print(p - 16, length + 2);
                }
                if (!suppress_default_print)
                    default_print(p - 16, caplen + 2);
*/
                return (1);

        case ETHERTYPE_ISO:
                isoclns_print(p+1, length-1, length-1);
                return(1);
/*
   case ETHERTYPE_PPPOED:
   case ETHERTYPE_PPPOES:
      pppoe_print(p, length);
      return (1);

   case ETHERTYPE_EAPOL:
           eap_print(gndo, p, length);
      return (1);

   case ETHERTYPE_PPP:
      if (length) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],": ");
         ppp_print(p, length);
      }
      return (1);

   case ETHERTYPE_SLOW:
           slow_print(p, length);
      return (1);

        case ETHERTYPE_LOOPBACK:
                return (1);

   case ETHERTYPE_MPLS:
   case ETHERTYPE_MPLS_MULTI:
      mpls_print(p, length);
      return (1);

   case ETHERTYPE_LAT:
   case ETHERTYPE_SCA:
   case ETHERTYPE_MOPRC:
   case ETHERTYPE_MOPDL:
*/
      /* default_print for now */
   default:
      return (0);
   }
}


/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 8
 * End:
 */

