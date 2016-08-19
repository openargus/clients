/*
 * Argus Software
 * Copyright (c) 2000-2016 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/* 
 * $Id: //depot/argus/clients/examples/radump/radump.c#11 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

/*
 * radump.c  - dump payload as if its tcpdump data.
 */


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>

#include <argus_compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#ifndef IPPROTO_PIM
#define IPPROTO_PIM	103
#endif


#define RaDump	1
#include <oui.h>

#include <signal.h>
#include <ctype.h>

#include "interface.h"

const u_char *snapend = NULL;

char ArgusBuf[MAXSTRLEN];

/* draft-ietf-pwe3-iana-allocation-04 */
struct tok l2vpn_encaps_values[] = {
    { 0x00, "Reserved"},
    { 0x01, "Frame Relay"},
    { 0x02, "ATM AAL5 VCC transport"},
    { 0x03, "ATM transparent cell transport"},
    { 0x04, "Ethernet VLAN"},
    { 0x05, "Ethernet"},
    { 0x06, "Cisco-HDLC"},
    { 0x07, "PPP"},
    { 0x08, "SONET/SDH Circuit Emulation Service over MPLS"},
    { 0x09, "ATM n-to-one VCC cell transport"},
    { 0x0a, "ATM n-to-one VPC cell transport"},
    { 0x0b, "IP Layer2 Transport"},
    { 0x0c, "ATM one-to-one VCC Cell Mode"},
    { 0x0d, "ATM one-to-one VPC Cell Mode"},
    { 0x0e, "ATM AAL5 PDU VCC transport"},
    { 0x0f, "Frame-Relay Port mode"},
    { 0x10, "SONET/SDH Circuit Emulation over Packet"},
    { 0x11, "Structure-agnostic E1 over Packet"},
    { 0x12, "Structure-agnostic T1 (DS1) over Packet"},
    { 0x13, "Structure-agnostic E3 over Packet"},
    { 0x14, "Structure-agnostic T3 (DS3) over Packet"},
    { 0x15, "CESoPSN basic mode"},
    { 0x16, "TDMoIP basic mode"},
    { 0x17, "CESoPSN TDM with CAS"},
    { 0x18, "TDMoIP TDM with CAS"},
    { 0x40, "IP-interworking"},
    { 0, NULL}
};


int ArgusThisEflag = 0;

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   parser->RaWriteOut = 1;

   if (!(parser->RaInitialized)) {

/*
   the library sets signal handling routines for 
   SIGHUP, SIGTERM, SIGQUIT, SIGINT, SIGUSR1, and SIGUSR2.
   SIGHUP doesn't do anything, SIGTERM, SIGQUIT, and SIGINT
   call the user supplied RaParseComplete().  SIGUSR1 and
   SIGUSR2 modify the debug level so if compiled with
   ARGUS_DEBUG support, programs can start generating 
   debug information.  USR1 increments by 1, USR2 sets
   it back to zero.

*/
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      ArgusThisEflag = parser->eflag;
      parser->eflag = ARGUS_HEXDUMP;
      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input) {};

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      ArgusShutDown(sig);
      if ((sig == SIGINT) || (sig == SIGQUIT))
         exit(0);
   }
}


void
ArgusClientTimeout ()
{
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusClientTimeout()\n");
#endif
}

void
parse_arg (int argc, char**argv)
{}

void
usage ()
{
   extern char version[];

   fprintf (stdout, "Ratemplate Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] [ra-options]  [- filter-expression]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -v          print verbose protocol information.\n");
   fprintf (stdout, "         -s +suser   dump the source user data buffer.\n");
   fprintf (stdout, "            +duser   dump the destination user buffer.\n");
   fflush (stdout);
   exit(1);
}

char * RaDumpUserBuffer (struct ArgusParserStruct *, struct ArgusRecordStruct *, int, int);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   char buf[MAXSTRLEN];
   int i, srcdata = 0, dstdata = 0;

   if (parser->Lflag && !(parser->ArgusPrintXml)) {
      if (parser->RaLabel == NULL) {
         int eflag = parser->eflag;
         parser->eflag = ArgusThisEflag;
         parser->RaLabel = ArgusGenerateLabel(parser, argus);
         parser->eflag = eflag;
      }

      if (!(parser->RaLabelCounter++ % parser->Lflag))
         if (printf ("%s\n", parser->RaLabel) < 0)
            RaParseComplete (SIGQUIT);

      if (parser->Lflag < 0)
         parser->Lflag = 0;
   }

   if (argus->hdr.type & ARGUS_MAR) {
   } else {
      bzero (buf, MAXSTRLEN);
      ArgusPrintRecord(ArgusParser, buf, argus, MAXSTRLEN);

      fprintf (stdout, "%s", buf);

      bzero (ArgusBuf, MAXSTRLEN);
      for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
         if (parser->RaPrintAlgorithmList[i] != NULL) {
            if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcUserData)
               srcdata = parser->RaPrintAlgorithmList[i]->length;

            if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintDstUserData) {
               dstdata = parser->RaPrintAlgorithmList[i]->length;
            }
         }
      }

      if (srcdata || dstdata) {
         if ((parser->RaFieldDelimiter != ' ') && (parser->RaFieldDelimiter != '\0'))
            fprintf (stdout, "%c", parser->RaFieldDelimiter);
         else
            fprintf (stdout, "  ");
      }

      if (srcdata) {
         struct ArgusDataStruct *user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX];
         int slen;
         char *str;

         if (user != NULL) {
            slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
            slen = (user->count < slen) ? user->count : slen;
            slen = (slen > srcdata) ? srcdata : slen;
         }

         if ((str = RaDumpUserBuffer (parser, argus, ARGUS_SRCUSERDATA_INDEX, 8196)) != NULL) {
            int stlen = 0, blen = 0;
            char lbuf[64];
            sprintf (buf, "s[%d]=", srcdata);
            blen = strlen(buf);
            stlen = strlen(str);
            sprintf (lbuf, "s[%d]=", (stlen > srcdata) ? srcdata : stlen);
            sprintf (buf, "%*.*s", blen, blen, lbuf);
            sprintf (&buf[strlen(buf)], "\"%s", str);
            buf[srcdata - 1] = '\0';
#if defined(HAVE_STRLCAT)
            strlcat(buf, "\"", MAXSTRLEN - strlen(buf));
#else
            strcat(buf, "\"");
#endif
            fprintf (stdout, "%-*.*s", srcdata, srcdata, buf);
            bzero (ArgusBuf, MAXSTRLEN);
         
            if ((parser->RaFieldDelimiter != ' ') && (parser->RaFieldDelimiter != '\0'))
               fprintf (stdout, "%c", parser->RaFieldDelimiter);
            else
               fprintf (stdout, "  ");
         }
      }


      if (dstdata)  {
         struct ArgusDataStruct *user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX];
         int slen;
         char *str;

         if (user != NULL) {
            slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
            slen = (user->count < slen) ? user->count : slen;
            slen = (slen > dstdata) ? dstdata : slen;
         }

         if ((str = RaDumpUserBuffer (parser, argus, ARGUS_DSTUSERDATA_INDEX, 8196)) != NULL) {
            int stlen = 0, blen = 0;
            char lbuf[64];
            sprintf (buf, "d[%d]=", dstdata);
            blen = strlen(buf);
            stlen = strlen(str);
            sprintf (lbuf, "d[%d]=", (stlen > dstdata) ? dstdata : stlen);
            sprintf (buf, "%*.*s", blen, blen, lbuf);
            sprintf (&buf[strlen(buf)], "\"%s", str);
            buf[dstdata - 1] = '\0';
#if defined(HAVE_STRLCAT)
            strlcat(buf, "\"", MAXSTRLEN - strlen(buf));
#else
            strcat(buf, "\"");
#endif
            fprintf (stdout, "%-*.*s", dstdata, dstdata, buf);
            bzero (ArgusBuf, MAXSTRLEN);
         }
      }

      fprintf (stdout, "\n");
      fflush(stdout);
   }
}


char *
RaDumpUserBuffer (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, int ind, int len) 
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   unsigned short sport = 0, dport = 0;
   int type, proto, process = 0;
   struct ArgusDataStruct *user = NULL;
   u_char buf[MAXSTRLEN], *bp = NULL;
   int slen = 0, done = 0;

   if ((user = (struct ArgusDataStruct *)argus->dsrs[ind]) == NULL)
      return (ArgusBuf);

/*
   switch (ind) {
      case ARGUS_SRCUSERDATA_INDEX:
         dchr = 's';
         break;
      case ARGUS_DSTUSERDATA_INDEX:
         dchr = 'd';
         break;
   }
*/

   bp = (u_char *) &user->array;
   slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
   slen = (user->count < slen) ? user->count : slen;
   slen = (slen > len) ? len : slen;
   snapend = bp + slen;

   if (flow != NULL) {
      switch (flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch ((type = flow->hdr.argus_dsrvl8.qual & 0x1F)) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP: {
                        proto = flow->ip_flow.ip_p;
                        sport = flow->ip_flow.sport;
                        dport = flow->ip_flow.dport;
                        process++;
                        break;
                     }
                     case IPPROTO_IGMP: {
                        struct ArgusMetricStruct *metric = (void *)argus->dsrs[ARGUS_METRIC_INDEX];
                        if ((metric != NULL) && (((ind == ARGUS_SRCUSERDATA_INDEX) && metric->src.pkts) ||
                                                 ((ind == ARGUS_DSTUSERDATA_INDEX) && metric->dst.pkts))) {
                           igmp_print(bp, slen);
                           done++;
                           break;
                        }
                     }

                     case IPPROTO_PIM: {
                        struct ArgusMetricStruct *metric = (void *)argus->dsrs[ARGUS_METRIC_INDEX];
                        if ((metric != NULL) && (((ind == ARGUS_SRCUSERDATA_INDEX) && metric->src.pkts) ||
                                                 ((ind == ARGUS_DSTUSERDATA_INDEX) && metric->dst.pkts))) {
                           pim_print(bp, slen);
                           done++;
                           break;
                        }
                     }
                  }
                  break; 
               case ARGUS_TYPE_IPV6: {
                  switch (flow->ipv6_flow.ip_p) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP: {
                        proto = flow->ipv6_flow.ip_p;
                        sport = flow->ipv6_flow.sport;
                        dport = flow->ipv6_flow.dport;
                        process++;
                        break;
                     }

                     case IPPROTO_PIM: {
                        struct ArgusMetricStruct *metric = (void *)argus->dsrs[ARGUS_METRIC_INDEX];

                        if ((metric != NULL) && (((ind == ARGUS_SRCUSERDATA_INDEX) && metric->src.pkts) ||
                                                 ((ind == ARGUS_DSTUSERDATA_INDEX) && metric->dst.pkts))) {
                           pim_print(bp, slen);
                           done++;
                           break;
                        }
                     }
                  }
                  break;
               }
               case ARGUS_TYPE_ARP: {
                  if (ind == ARGUS_SRCUSERDATA_INDEX) {
                     arp_src_print(parser, argus);
                  }
                  if (ind == ARGUS_DSTUSERDATA_INDEX) {
                     arp_dst_print(parser, argus);
                  }
                  done++;
                  break;
               }
/*
struct ArgusMacFlow {
   struct ether_header ehdr;
   unsigned char dsap, ssap;
};

*/

               case ARGUS_TYPE_ETHER: {
                  if (flow != NULL)
                     if ((flow->mac_flow.mac_union.ether.ssap == LLCSAP_BPDU) &&
                         (flow->mac_flow.mac_union.ether.dsap == LLCSAP_BPDU))
                        stp_print (bp, slen);
                  done++;
                  break;
               }
            }
            break;
         }

         case ARGUS_FLOW_ARP: {
            switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
               case ARGUS_TYPE_RARP:
               case ARGUS_TYPE_ARP:
                  if (ind == ARGUS_SRCUSERDATA_INDEX) {
                     arp_src_print(parser, argus);
                  }
                  if (ind == ARGUS_DSTUSERDATA_INDEX) {
                     arp_dst_print(parser, argus);
                  }
                  done++;
                  break;
            }
         }
      }
   }

   if (process && bp) {
      *(int *)&buf = 0;

#define ISPORT(p) (dport == (p) || sport == (p))

      switch (proto) {
         case IPPROTO_TCP: {
            if (ISPORT(BGP_PORT))
               bgp_print(bp, slen); 
            else if (ISPORT(TELNET_PORT))
               telnet_print(bp, slen);
            else if (ISPORT(PPTP_PORT))
               pptp_print(bp, slen);
            else if (ISPORT(NETBIOS_SSN_PORT))
               nbt_tcp_print(bp, slen);
            else if (ISPORT(BEEP_PORT))
               beep_print(bp, slen);
            else if (ISPORT(NAMESERVER_PORT) || ISPORT(MULTICASTDNS_PORT)) 
                ns_print(bp + 2, slen - 2, 0);
            else if (ISPORT(MSDP_PORT))
               msdp_print(bp, slen);
            else if (ISPORT(LDP_PORT))
               ldp_print(bp, slen);
            else {
               parser->eflag = ArgusThisEflag;
               ArgusEncode (parser, (const char *)bp, NULL, slen, ArgusBuf, sizeof(ArgusBuf));
               parser->eflag = ARGUS_HEXDUMP;
            }
            break;
         }

         case IPPROTO_UDP: {
            if (ISPORT(NAMESERVER_PORT))
               ns_print(bp, slen, 0);
            else if (ISPORT(MULTICASTDNS_PORT))
               ns_print(bp, slen, 1);
            else if (ISPORT(NTP_PORT))
               ntp_print(bp, slen);
            else if (ISPORT(LDP_PORT))
               ldp_print(bp, slen);
            else if (ISPORT(RADIUS_PORT) || ISPORT(RADIUS_NEW_PORT) ||
                     ISPORT(RADIUS_ACCOUNTING_PORT) ||
                     ISPORT(RADIUS_NEW_ACCOUNTING_PORT) )
               radius_print(bp, slen);
            else if (ISPORT(KERBEROS_PORT) || ISPORT(KERBEROS_SEC_PORT))
               krb_print(bp, slen);
            else if (ISPORT(SNMP_PORT) || ISPORT(SNMPTRAP_PORT))
               snmp_print(bp, slen);
            else if (ISPORT(TIMED_PORT))
               timed_print(bp, slen);
            else if (ISPORT(TFTP_PORT))
               tftp_print(bp, slen);
            else if (ISPORT(IPPORT_BOOTPC) || ISPORT(IPPORT_BOOTPS))
               bootp_print(bp, slen);
            else if (ISPORT(RIP_PORT))
               rip_print(bp, slen);
            else if (ISPORT(AODV_PORT))
               aodv_print(bp, slen, 0);
            else if (ISPORT(L2TP_PORT))
               l2tp_print(bp, slen);
            else if (ISPORT(SYSLOG_PORT))
               syslog_print(bp, slen);
            else if (ISPORT(LMP_PORT))
               lmp_print(bp, slen);
            else if ((sport >= RX_PORT_LOW && sport <= RX_PORT_HIGH) ||
                     (dport >= RX_PORT_LOW && dport <= RX_PORT_HIGH))
               rx_print(bp, slen, sport, dport);
            else if (dport == BFD_CONTROL_PORT || dport == BFD_ECHO_PORT )
               bfd_print(bp, slen, dport);
            else if (ISPORT(NETBIOS_NS_PORT))
               nbt_udp137_print(bp, slen);
            else if (ISPORT(NETBIOS_DGRAM_PORT))
               nbt_udp138_print(bp, slen);
            else if (ISPORT(ISAKMP_PORT))
               isakmp_print(bp, slen);
            else if (ISPORT(ISAKMP_PORT_NATT))
               isakmp_rfc3948_print(bp, slen);
            else if (ISPORT(ISAKMP_PORT_USER1) || ISPORT(ISAKMP_PORT_USER2))
               isakmp_print(bp, slen);
            else {
               parser->eflag = ArgusThisEflag;
               ArgusEncode (parser, (const char *)bp, NULL, slen, ArgusBuf, sizeof(ArgusBuf));
               parser->eflag = ARGUS_HEXDUMP;
            }
/*
            else if (ISPORT(3456))
               vat_print(bp, slen);
            else if (ISPORT(ZEPHYR_SRV_PORT) || ISPORT(ZEPHYR_CLT_PORT))
               zephyr_print(bp, slen);
            else if (ISPORT(RIPNG_PORT))
               ripng_print(bp, slen);
            else if (ISPORT(DHCP6_SERV_PORT) || ISPORT(DHCP6_CLI_PORT))
               dhcp6_print(bp, slen);
            else if (dport == 4567)
               wb_print(bp, slen);
            else if (ISPORT(CISCO_AUTORP_PORT))
               cisco_autorp_print(bp, slen);
            else if (ISPORT(RADIUS_PORT) || ISPORT(RADIUS_NEW_PORT) ||
                     ISPORT(RADIUS_ACCOUNTING_PORT) || ISPORT(RADIUS_NEW_ACCOUNTING_PORT) )
               radius_print(bp, slen);
            else if (dport == HSRP_PORT)
               hsrp_print(bp, slen);
            else if (ISPORT(LWRES_PORT))
               lwres_print(bp, slen);
            else if (ISPORT(MPLS_LSP_PING_PORT))
               lspping_print(bp, slen);
*/
         }
      }
   }

   return (ArgusBuf);
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}

/*
 * Print out a null-terminated filename (or other ascii string).
 * If ep is NULL, assume no truncation check is needed.
 * Return true if truncated.
 */
int
fn_print(register const u_char *s, register const u_char *ep, char *buf)
{
   register int ret;
   register u_char c;

   ret = 1;                        /* assume truncated */
   while (ep == NULL || s < ep) {
      c = *s++;
      if (c == '\0') {
         ret = 0;
         break;
      }
      if (!isascii(c)) {
         c = toascii(c);
         sprintf(&buf[strlen(buf)], "%c", 'M');
         sprintf(&buf[strlen(buf)], "%c", '-');
      }
      if (!isprint(c)) {
         c ^= 0x40;      /* DEL to ?, others to alpha */
         sprintf(&buf[strlen(buf)], "%c", '^');
      }
      sprintf(&buf[strlen(buf)], "%c", c);
   }
   return(ret);
}

/*                      
 * Print out a counted filename (or other ascii string).
 * If ep is NULL, assume no truncation check is needed.
 * Return true if truncated.
 */                     
int                     
fn_printn(register const u_char *s, register u_int n,
          register const u_char *ep, char *buf)
{
        register u_char c;

        while (n > 0 && (ep == NULL || s < ep)) {
                n--;
                c = *s++;
                if (!isascii(c)) {
                        c = toascii(c);
                        sprintf(&buf[strlen(buf)], "%c", 'M');
                        sprintf(&buf[strlen(buf)], "%c", '-');
                }
                if (!isprint(c)) {
                        c ^= 0x40;      /* DEL to ?, others to alpha */
                        sprintf(&buf[strlen(buf)], "%c", '^');
                }
                sprintf(&buf[strlen(buf)], "%c", c);
        }
        return (n == 0) ? 0 : 1;
}

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


#include <argus/extract.h>

#include <stdio.h>
#include <string.h>


/*
 * Convert a token value to a string; use "fmt" if not found.
const char *
tok2str(const struct tok *lp, const char *fmt, int v)
{
   static char buf[128];

   while (lp->s != NULL) {
      if (lp->v == v)
         return (lp->s);
      ++lp;
   }
   if (fmt == NULL)
      fmt = "#%d";
   (void)snprintf(buf, sizeof(buf), fmt, v);
   return (buf);
}   
 */

/*
 * Convert a token value to a string; use "fmt" if not found.
 */

const char *
tok2strbuf(register const struct tok *lp, register const char *fmt,
           register int v, char *buf, size_t bufsize)
{
   if (lp != NULL) {
      while (lp->s != NULL) {
         if (lp->v == v)
            return (lp->s);
         ++lp;
      }
   }
   if (fmt == NULL)                
      fmt = "#%d"; 
                
   (void)snprintf(buf, bufsize, fmt, v);
   return (const char *)buf;
}  

/*
 * Convert a 32-bit netmask to prefixlen if possible
 * the function returns the prefix-len; if plen == -1
 * then conversion was not possible;
 */
int mask2plen (u_int32_t);

int
mask2plen (u_int32_t mask)
{
   u_int32_t bitmasks[33] = {
                0x00000000,
                0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
                0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
                0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
                0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
                0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
                0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
                0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
                0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff
   };
   int prefix_len = 32;

   /* let's see if we can transform the mask into a prefixlen */
   while (prefix_len >= 0) {
      if (bitmasks[prefix_len] == mask)
         break;
      prefix_len--;
   }
   return (prefix_len);
}

