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
 * $Id: //depot/argus/clients/clients/racount.c#45 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

/*
 *
 * racount  - Tally things about argus records
 *       
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>

#include <argus_compat.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>

#include <rabins.h>

#include <signal.h>
#include <ctype.h>


#ifndef IN6_IS_ADDR_UNSPECIFIED
#define IN6_IS_ADDR_UNSPECIFIED(a) \
	(((__const uint32_t *) (a))[0] == 0				      \
	 && ((__const uint32_t *) (a))[1] == 0				      \
	 && ((__const uint32_t *) (a))[2] == 0				      \
	 && ((__const uint32_t *) (a))[3] == 0)
#endif

#ifndef IN6_IS_ADDR_LOOPBACK
#define IN6_IS_ADDR_LOOPBACK(a) \
	(((__const uint32_t *) (a))[0] == 0				      \
	 && ((__const uint32_t *) (a))[1] == 0				      \
	 && ((__const uint32_t *) (a))[2] == 0				      \
	 && ((__const uint32_t *) (a))[3] == htonl (1))
#endif

#ifndef IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(a) (((__const uint8_t *) (a))[0] == 0xff)
#endif

#ifndef IN6_IS_ADDR_LINKLOCAL
#define IN6_IS_ADDR_LINKLOCAL(a) \
	((((__const uint32_t *) (a))[0] & htonl (0xffc00000))		      \
	 == htonl (0xfe800000))
#endif

#ifndef IN6_IS_ADDR_SITELOCAL
#define IN6_IS_ADDR_SITELOCAL(a) \
	((((__const uint32_t *) (a))[0] & htonl (0xffc00000))		      \
	 == htonl (0xfec00000))
#endif

#ifndef IN6_IS_ADDR_V4MAPPED
#define IN6_IS_ADDR_V4MAPPED(a) \
	((((__const uint32_t *) (a))[0] == 0)				      \
	 && (((__const uint32_t *) (a))[1] == 0)			      \
	 && (((__const uint32_t *) (a))[2] == htonl (0xffff)))
#endif

#ifndef IN6_IS_ADDR_V4COMPAT
#define IN6_IS_ADDR_V4COMPAT(a) \
	((((__const uint32_t *) (a))[0] == 0)				      \
	 && (((__const uint32_t *) (a))[1] == 0)			      \
	 && (((__const uint32_t *) (a))[2] == 0)			      \
	 && (ntohl (((__const uint32_t *) (a))[3]) > 1))
#endif

#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL(a,b) \
	((((__const uint32_t *) (a))[0] == ((__const uint32_t *) (b))[0])     \
	 && (((__const uint32_t *) (a))[1] == ((__const uint32_t *) (b))[1])  \
	 && (((__const uint32_t *) (a))[2] == ((__const uint32_t *) (b))[2])  \
	 && (((__const uint32_t *) (a))[3] == ((__const uint32_t *) (b))[3]))
#endif


#ifndef IN6_IS_ADDR_MC_NODELOCAL
#define IN6_IS_ADDR_MC_NODELOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a)					      \
	 && ((((__const uint8_t *) (a))[1] & 0xf) == 0x1))
#endif

#ifndef IN6_IS_ADDR_MC_LINKLOCAL
#define IN6_IS_ADDR_MC_LINKLOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a)					      \
	 && ((((__const uint8_t *) (a))[1] & 0xf) == 0x2))
#endif

#ifndef IN6_IS_ADDR_MC_SITELOCAL
#define IN6_IS_ADDR_MC_SITELOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a)					      \
	 && ((((__const uint8_t *) (a))[1] & 0xf) == 0x5))
#endif

#ifndef IN6_IS_ADDR_MC_ORGLOCAL
#define IN6_IS_ADDR_MC_ORGLOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a)					      \
	 && ((((__const uint8_t *) (a))[1] & 0xf) == 0x8))
#endif

#ifndef IN6_IS_ADDR_MC_GLOBAL
#define IN6_IS_ADDR_MC_GLOBAL(a) \
	(IN6_IS_ADDR_MULTICAST(a)					      \
	 && ((((__const uint8_t *) (a))[1] & 0xf) == 0xe))
#endif


int RaAddrMode = 0;
int RaProtoMode = 0;

int ArgusIPv4AddrUnicast[2]            = {0,0};
int ArgusIPv4AddrUnicastThisNet[2]     = {0,0};
int ArgusIPv4AddrUnicastReserved[2]    = {0,0};
int ArgusIPv4AddrUnicastLoopBack[2]    = {0,0};
int ArgusIPv4AddrUnicastLinkLocal[2]   = {0,0};
int ArgusIPv4AddrUnicastTestNet[2]     = {0,0};
int ArgusIPv4AddrUnicastPrivate[2]     = {0,0};

int ArgusIPv4AddrMulticastLocal[2]     = {0,0};
int ArgusIPv4AddrMulticastInternet[2]  = {0,0};
int ArgusIPv4AddrMulticastAdHoc[2]     = {0,0};
int ArgusIPv4AddrMulticastReserved[2]  = {0,0};
int ArgusIPv4AddrMulticastSdpSap[2]    = {0,0};
int ArgusIPv4AddrMulticastNasdaq[2]    = {0,0};
int ArgusIPv4AddrMulticastDisTrans[2]  = {0,0};
int ArgusIPv4AddrMulticastSrcSpec[2]   = {0,0};
int ArgusIPv4AddrMulticastGlop[2]      = {0,0};
int ArgusIPv4AddrMulticastAdmin[2]     = {0,0};
int ArgusIPv4AddrMulticastOrgLocal[2]  = {0,0};
int ArgusIPv4AddrMulticastSiteLocal[2] = {0,0};

int ArgusIPv6AddrUnspecified[2]        = {0,0};
int ArgusIPv6AddrLoopback[2]           = {0,0};
 
int ArgusIPv6AddrLinkLocal[2]          = {0,0};
int ArgusIPv6AddrSiteLocal[2]          = {0,0};
int ArgusIPv6AddrGlobal[2]             = {0,0};
 
int ArgusIPv6AddrV4Compat[2]           = {0,0};
int ArgusIPv6AddrV4Mapped[2]           = {0,0};
 
int ArgusIPv6AddrMulticastNodeLocal[2] = {0,0};
int ArgusIPv6AddrMulticastLinkLocal[2] = {0,0};
int ArgusIPv6AddrMulticastSiteLocal[2] = {0,0};
int ArgusIPv6AddrMulticastOrgLocal[2]  = {0,0};
int ArgusIPv6AddrMulticastGlobal[2]    = {0,0};

extern int ArgusTotalMarRecords;
extern int ArgusTotalFarRecords;

struct ArgusRecordStruct *ArgusIPProtoRecs[0x10000];
struct ArgusRecordStruct *ArgusEtherProtoRecs[0x10000];
struct ArgusRecordStruct *ArgusArpRecords;
struct ArgusRecordStruct *ArgusRarpRecords;
struct ArgusRecordStruct *ArgusUnknownRecords;

signed long long ArgusTotalFlowRecs = 1;

struct ArgusHashTable *ArgusSrcAddrTable, *ArgusDstAddrTable;

void RaPrintSrcAddressTally(void);
void RaPrintAddressTally(void);
void RaPrintProtoTally(void);

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;

   ArgusParser = parser;
   parser->RaWriteOut = 0;
   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "addr", 4)))
               RaAddrMode++;
            else
            if (!(strncasecmp (mode->mode, "proto", 4)))
               RaProtoMode++;
            else
            if (!(strncasecmp (mode->mode, "oui", 3)))
               parser->ArgusPrintEthernetVendors++;
            else
            if (!(strncasecmp (mode->mode, "poll", 4)))
               parser->RaPollMode++;
            else
            if (!(strncasecmp (mode->mode, "rmon", 4)))
               parser->RaMonMode++;
            else
            if (!(strncasecmp (mode->mode, "uni", 3)))
               parser->RaUniMode++;
            else
            if (!(strncasecmp (mode->mode, "oui", 3)))
               parser->ArgusPrintEthernetVendors++;
            else
            if (!(strncasecmp (mode->mode, "man", 3)))
               parser->ArgusPrintMan = 1;
            else
            if (!(strncasecmp (mode->mode, "noman", 5)))
               parser->ArgusPrintMan = 0;

            mode = mode->nxt;
         }
      }

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      bzero(ArgusIPProtoRecs, sizeof(ArgusIPProtoRecs));
      bzero(ArgusEtherProtoRecs, sizeof(ArgusEtherProtoRecs));

      ArgusArpRecords = NULL;
      ArgusRarpRecords = NULL;
      ArgusUnknownRecords = NULL;

      ArgusSrcAddrTable = ArgusNewHashTable(0x10000);
      ArgusDstAddrTable = ArgusNewHashTable(0x10000);

      parser->RaFieldWidth = RA_VARIABLE_WIDTH;
      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input) { return; }

void
RaParseComplete (int sig)
{
   int ArgusExitStatus = 0;

   if (sig >= 0) {
      if (!(ArgusParser->RaParseCompleting++)) {

         printf ("racount   records     total_pkts     src_pkts       dst_pkts       total_bytes        src_bytes          dst_bytes\n");
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__APPLE_CC__) || defined(__APPLE__) || defined(ARGUS_SOLARIS)
         printf ("    sum   %-11lld %-14lld %-14lld %-14lld %-18lld %-18lld %-18lld\n",
#else
         printf ("    sum   %-11Ld %-14Ld %-14Ld %-14Ld %-18Ld %-18Ld %-18Ld\n",
#endif
                       ArgusTotalFlowRecs,
                       ArgusParser->ArgusTotalPkts, ArgusParser->ArgusTotalSrcPkts, ArgusParser->ArgusTotalDstPkts,
                       ArgusParser->ArgusTotalBytes, ArgusParser->ArgusTotalSrcBytes, ArgusParser->ArgusTotalDstBytes);

         if (RaProtoMode) 
            RaPrintProtoTally();

         if (RaAddrMode) {
            if (ArgusParser->RaMonMode)
               RaPrintSrcAddressTally();
            else
               RaPrintAddressTally();
         }

         fflush (stdout);
         ArgusShutDown(sig);

#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(caught signal %d)\n", sig);
#endif
         switch (sig) {
            case SIGHUP:
            case SIGINT:
            case SIGTERM:
            case SIGQUIT: {
               struct ArgusWfileStruct *wfile = NULL;

               if (ArgusParser->ArgusWfileList != NULL) {
                  struct ArgusListObjectStruct *lobj = NULL;
                  int i, count = ArgusParser->ArgusWfileList->count;

                  if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
                     for (i = 0; i < count; i++) {
                        if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                           if (wfile->fd != NULL) {
#ifdef ARGUSDEBUG
                              ArgusDebug (2, "RaParseComplete: closing %s\n", wfile->filename);
#endif
                              fflush (wfile->fd);
                              fclose (wfile->fd);
                              wfile->fd = NULL;
                           }
                        }
                        lobj = lobj->nxt;
                     }
                  }
               }
               break;
            }
         }

         ArgusDeleteHashTable(ArgusSrcAddrTable);
         ArgusDeleteHashTable(ArgusDstAddrTable);

#if defined(ARGUS_THREADS)
         if (ArgusParser->Sflag) {
            struct ArgusInput *addr;
            void *retn = NULL;

            while ((addr = (void *)ArgusPopQueue(ArgusParser->ArgusRemoteHosts, ARGUS_LOCK)) != NULL) {
               if (addr->tid != (pthread_t) 0) {
                  pthread_join(addr->tid, &retn);
               }
               ArgusFree(addr);
            }

            while ((addr = (void *)ArgusPopQueue(ArgusParser->ArgusActiveHosts, ARGUS_LOCK)) != NULL) {
               if (addr->tid != (pthread_t) 0) {
                  pthread_join(addr->tid, &retn);
               }
               ArgusFree(addr);
            }
         }

         if (ArgusParser->timer != (pthread_t) 0)
            pthread_join(ArgusParser->timer, NULL);

         if (ArgusParser->dns != (pthread_t) 0)
            pthread_join(ArgusParser->dns, NULL);
#endif
         ArgusExitStatus = ArgusParser->ArgusExitStatus;
         ArgusCloseParser(ArgusParser);
         exit (ArgusExitStatus);
      }
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

   fprintf (stdout, "Racount Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [ra-options] -S remoteServer [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [ra-options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "\n");
   fprintf (stdout, "ra-options: -b                 dump packet-matching code.\n");
   fprintf (stdout, "            -C <[host]:<port>  specify remote Cisco Netflow source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stdout, "            -D <level>         specify debug level\n");
#endif
   fprintf (stdout, "            -F <conffile>      read configuration from <conffile>.\n");
   fprintf (stdout, "            -h                 print help.\n");
   fprintf (stdout, "            -M mode ...        specify run modes\n");
   fprintf (stdout, "              supported modes  \n");
   fprintf (stdout, "                 addr          print detailed address usage counts\n");
   fprintf (stdout, "                 proto         print detailed protocol usage stats\n");
   fprintf (stdout, "            -r <file>          read argus data <file>. '-' denotes stdin.\n");
   fprintf (stdout, "            -s [-][+[#]]field  specify fields to print.\n");
   fprintf (stdout, "            -S <host[:port]>   specify remote argus <host> and optional port\n");
   fprintf (stdout, "                               number.\n");
   fprintf (stdout, "            -t <timerange>     specify <timerange> for reading records.\n");
   fprintf (stdout, "                      format:  timeSpecification[-timeSpecification]\n");
   fprintf (stdout, "                               timeSpecification: [mm/dd[/yy].]hh[:mm[:ss]]\n");
   fprintf (stdout, "                                                   mm/dd[/yy]\n");
   fprintf (stdout, "                                                   -%%d{yMhdms}\n");
   fprintf (stdout, "            -T <secs>          attach to remote server for T seconds.\n");
#ifdef ARGUS_SASL
   fprintf (stdout, "            -U <user/auth>     specify <user/auth> authentication information.\n");
#endif
   fprintf (stdout, "            -w <file>          write output to <file>. '-' denotes stdout.\n");
   fflush (stdout);
   exit(1);
}

int RaLabelCounter = 0;


#include <netinet/in.h>


#define ARGUS_THIS_SRC_ADDR	0
#define ARGUS_THIS_DST_ADDR	1

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaTallyIPv4AddressType(struct ArgusParserStruct *, unsigned int, int);
void RaTallyIPv6AddressType(struct ArgusParserStruct *, struct in6_addr *, int);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (parser->RaMonMode) {
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(argus);
            struct ArgusFlow *flow;

            if ((flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, argus);
            ArgusReverseRecord(tns);

            if ((flow = (void *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);

         } else
            RaProcessThisRecord(parser, argus);
      }
   }
}

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow = (struct ArgusFlow *)argus->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusMetricStruct *metric = (void *)argus->dsrs[ARGUS_METRIC_INDEX];

   ArgusTotalFlowRecs++;
   argus->dsrs[ARGUS_AGR_INDEX] = NULL;

   if (metric != NULL) {
      parser->ArgusTotalPkts     += metric->src.pkts;
      parser->ArgusTotalPkts     += metric->dst.pkts;
      parser->ArgusTotalSrcPkts  += metric->src.pkts;
      parser->ArgusTotalDstPkts  += metric->dst.pkts;
      parser->ArgusTotalBytes    += metric->src.bytes;
      parser->ArgusTotalBytes    += metric->dst.bytes;
      parser->ArgusTotalSrcBytes += metric->src.bytes;
      parser->ArgusTotalDstBytes += metric->dst.bytes;
   }

   if (flow != NULL) {
      if (RaProtoMode) {
         struct ArgusRecordStruct *tns = NULL;

         switch(flow->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_LAYER_3_MATRIX:
            case ARGUS_FLOW_CLASSIC5TUPLE: {

               switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4: {
                     struct ArgusRecordStruct *tns;

                     if ((tns = ArgusIPProtoRecs[flow->ip_flow.ip_p]) == NULL)
                        ArgusIPProtoRecs[flow->ip_flow.ip_p] = ArgusCopyRecordStruct(argus); 
                     else
                        ArgusMergeRecords (parser->ArgusAggregator, tns, argus);
                     break;
                  }
                  case ARGUS_TYPE_IPV6: {
                     struct ArgusRecordStruct *tns;

                     if ((tns = ArgusIPProtoRecs[flow->ipv6_flow.ip_p]) == NULL)
                        ArgusIPProtoRecs[flow->ipv6_flow.ip_p] = ArgusCopyRecordStruct(argus); 
                     else
                        ArgusMergeRecords (parser->ArgusAggregator, tns, argus);
                     break;
                  }

                  case ARGUS_TYPE_ARP: {
                     if ((tns = ArgusArpRecords) == NULL)
                        ArgusArpRecords = ArgusCopyRecordStruct(argus);
                     else
                        ArgusMergeRecords (parser->ArgusAggregator, tns, argus);
                     break;
                  }
                  case ARGUS_TYPE_RARP: {
                     if ((tns = ArgusRarpRecords) == NULL)
                        ArgusRarpRecords = ArgusCopyRecordStruct(argus);
                     else
                        ArgusMergeRecords (parser->ArgusAggregator, tns, argus);
                     break;
                  }

                  case ARGUS_TYPE_WLAN: 
                  case ARGUS_TYPE_ETHER: {
                     unsigned short proto = flow->mac_flow.mac_union.ether.ehdr.ether_type;

                     if ((tns = ArgusEtherProtoRecs[proto]) == NULL)
                        ArgusEtherProtoRecs[proto] = ArgusCopyRecordStruct(argus);
                     else
                        ArgusMergeRecords (parser->ArgusAggregator, tns, argus);
                     break;
                  }

                  default: {
                     if ((tns = ArgusUnknownRecords) == NULL)
                        ArgusUnknownRecords = ArgusCopyRecordStruct(argus);
                     else
                        ArgusMergeRecords (parser->ArgusAggregator, tns, argus);
                     break;
                  }
               }
            }

            case ARGUS_FLOW_ARP: {
               switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_RARP: {
                     if ((tns = ArgusRarpRecords) == NULL)
                        ArgusRarpRecords = ArgusCopyRecordStruct(argus);
                     else
                        ArgusMergeRecords (parser->ArgusAggregator, tns, argus);
                     break;
                  }
 
                  case ARGUS_TYPE_ARP: {
                     if ((tns = ArgusArpRecords) == NULL)
                        ArgusArpRecords = ArgusCopyRecordStruct(argus);
                     else
                        ArgusMergeRecords (parser->ArgusAggregator, tns, argus);
                     break;
                  }
               }
               break;
            }

            default: {
               if ((tns = ArgusUnknownRecords) == NULL)
                  ArgusUnknownRecords = ArgusCopyRecordStruct(argus);
               else
                  ArgusMergeRecords (parser->ArgusAggregator, tns, argus);
               break;
            }
         }
      }

      if (RaAddrMode) {
         switch(flow->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_LAYER_3_MATRIX:
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4: {
                     int i, len, s = sizeof(unsigned short);
                     struct ArgusHashTableHdr *htbl = NULL;
                     struct ArgusHashStruct ArgusHash;
                     unsigned short *sptr;
                     unsigned int *addr;

                     bzero(&ArgusHash, sizeof(ArgusHash));
                     ArgusHash.len = 4;
                     ArgusHash.buf = &flow->ip_flow.ip_src;

                     sptr = (unsigned short *) ArgusHash.buf;
                     for (i = 0, len = ArgusHash.len / s; i < len; i++)
                        ArgusHash.hash += *sptr++;

                     if ((htbl = ArgusFindHashEntry(ArgusSrcAddrTable, &ArgusHash)) == NULL) {
                        if ((addr = (unsigned int *) ArgusMalloc(sizeof(*addr))) == NULL)
                           ArgusLog (LOG_ERR, "RaProcessRecord: ArgusMalloc error %s\n", strerror(errno));

                        *addr = flow->ip_flow.ip_src;
                        ArgusAddHashEntry(ArgusSrcAddrTable, (void *)addr, &ArgusHash);
                        RaTallyIPv4AddressType(parser, flow->ip_flow.ip_src, ARGUS_THIS_SRC_ADDR);
                     }

                     if (!(parser->RaMonMode)) {
                        bzero(&ArgusHash, sizeof(ArgusHash));
                        ArgusHash.len = 4;
                        ArgusHash.buf = &flow->ip_flow.ip_dst;

                        sptr = (unsigned short *) ArgusHash.buf;
                        for (i = 0, len = ArgusHash.len / s; i < len; i++)
                           ArgusHash.hash += *sptr++;

                        if ((htbl = ArgusFindHashEntry(ArgusDstAddrTable, &ArgusHash)) == NULL) {
                           if ((addr = (unsigned int *) ArgusMalloc(sizeof(*addr))) == NULL)
                              ArgusLog (LOG_ERR, "RaProcessRecord: ArgusMalloc error %s\n", strerror(errno));

                           *addr = flow->ip_flow.ip_dst;
                           ArgusAddHashEntry(ArgusDstAddrTable, (void *)addr, &ArgusHash);
                           RaTallyIPv4AddressType(parser, flow->ip_flow.ip_dst, ARGUS_THIS_DST_ADDR);
                        }
                     }
                     break;
                  }

                  case ARGUS_TYPE_IPV6: {
                     RaTallyIPv6AddressType(parser, (struct in6_addr *)&flow->ipv6_flow.ip_src, ARGUS_THIS_SRC_ADDR);
                     RaTallyIPv6AddressType(parser, (struct in6_addr *)&flow->ipv6_flow.ip_dst, ARGUS_THIS_DST_ADDR);
                     break;
                  }

                  default:
                     break;
               }
            }
         }
      }
   }
}


void
RaTallyIPv4AddressType(struct ArgusParserStruct *parser, unsigned int addr, int type)
{
   if (IN_MULTICAST(addr)) {
      if ((addr & 0xFF000000) == 0xE0000000) {
         if ((addr & 0x00FFFFFF) <  0x00000100) ArgusIPv4AddrMulticastLocal[type]++; else
         if ((addr & 0x00FFFFFF) <  0x00000200) ArgusIPv4AddrMulticastInternet[type]++; else
         if ((addr & 0x00FFFFFF) <  0x0000FF00) ArgusIPv4AddrMulticastAdHoc[type]++; else
         if ((addr & 0x00FFFFFF) <  0x00020000) ArgusIPv4AddrMulticastReserved[type]++; else
         if ((addr & 0x00FFFFFF) <  0x00030000) ArgusIPv4AddrMulticastSdpSap[type]++; else
         if ((addr & 0x00FFFFFF) <  0x00030040) ArgusIPv4AddrMulticastNasdaq[type]++; else
         if ((addr & 0x00FFFFFF) <  0x00FD0000) ArgusIPv4AddrMulticastReserved[type]++; else
         if ((addr & 0x00FFFFFF) <= 0x00FD0000) ArgusIPv4AddrMulticastDisTrans[type]++;
      }
      if (((addr & 0xFF000000) > 0xE0000000) && ((addr & 0xFF000000) < 0xE8000000)) {
         ArgusIPv4AddrMulticastReserved[type]++;
      }
      if ((addr & 0xFF000000) == 0xE8000000) {
         ArgusIPv4AddrMulticastSrcSpec[type]++;
      }
      if ((addr & 0xFF000000) == 0xE9000000) {
         ArgusIPv4AddrMulticastGlop[type]++;
      }
      if (((addr & 0xFF000000) >= 0xE9000000) && ((addr & 0xFF000000) <= 0xEE000000)) {
         ArgusIPv4AddrMulticastReserved[type]++;
      }
      if ((addr & 0xFF000000) == 0xEF000000) {
         ArgusIPv4AddrMulticastAdmin[type]++;
         if (((addr & 0x00FF0000) >  0x00000000) && ((addr & 0x00FF0000) <  0x00C00000)) {
            ArgusIPv4AddrMulticastReserved[type]++;
         }
         if (((addr & 0x00FF0000) >= 0x00C00000) && ((addr & 0x00FF0000) <  0x00FC0000)) {
            ArgusIPv4AddrMulticastOrgLocal[type]++;
         }
         if (((addr & 0x00FF0000) >= 0x00FC0000) && ((addr & 0x00FF0000) <= 0x00FF0000)) {
            ArgusIPv4AddrMulticastSiteLocal[type]++;
         }
      }

   } else {
      if (((addr & 0xFF000000) == 0x00000000)) {
         ArgusIPv4AddrUnicastThisNet[type]++;
      } else 
      if (((addr & 0xFF000000) > 0x00000000) && ((addr & 0xFF000000) <  0x03000000)) {
         ArgusIPv4AddrUnicastReserved[type]++;
      } else 
      if ((addr & 0xFF000000) == 0x05000000) {
         ArgusIPv4AddrUnicastReserved[type]++;
      } else
      if ((addr & 0xFF000000) == 0x17000000) {
         ArgusIPv4AddrUnicastReserved[type]++;
      } else
      if ((addr & 0xFF000000) == 0x1B000000) {
         ArgusIPv4AddrUnicastReserved[type]++;
      } else
      if (((addr & 0xFF000000) == 0x24000000) || ((addr & 0xFF000000) == 0x25000000)) {
         ArgusIPv4AddrUnicastReserved[type]++;
      } else
      if (((addr & 0xFF000000) == 0x29000000) || ((addr & 0xFF000000) == 0x30000000)) {
         ArgusIPv4AddrUnicastReserved[type]++;
      } else
      if (((addr & 0xFF000000) >= 0x49000000) && ((addr & 0xFF000000) <  0x50000000)) {
         ArgusIPv4AddrUnicastReserved[type]++;
      } else
      if (((addr & 0xFF000000) >= 0x59000000) && ((addr & 0xFF000000) <  0x7F000000)) {
         ArgusIPv4AddrUnicastReserved[type]++;
      } else
      if ((addr & 0xFF000000) == 0x7F000000) {
         ArgusIPv4AddrUnicastLoopBack[type]++;
      } else
      if ((addr & 0xFFFF0000) == 0xAC100000) {
         ArgusIPv4AddrUnicastPrivate[type]++;
      } else
      if (((addr & 0xFF000000) >= 0xAD000000) && ((addr & 0xFF000000) <  0xBC000000)) {
         if ((addr & 0xFFFF0000) == 0xA9FE0000)
            ArgusIPv4AddrUnicastLinkLocal[type]++;
         else
            ArgusIPv4AddrUnicastReserved[type]++;
      } else
      if (((addr & 0xFF000000) >= 0xBE000000) && ((addr & 0xFF000000) <  0xC0000000)) {
         ArgusIPv4AddrUnicastReserved[type]++;
      } else
      if ((addr & 0xFF000000) == 0xC0000000) {
         if ((addr & 0xFFFFFF00) == 0xC0000200)
            ArgusIPv4AddrUnicastTestNet[type]++;
         else
         if ((addr & 0xFFFF0000) == 0xC0A80000)
            ArgusIPv4AddrUnicastPrivate[type]++;
         else
            ArgusIPv4AddrUnicast[type]++;
      } else
      if ((addr & 0xFF000000) == 0xC5000000) {
         ArgusIPv4AddrUnicastReserved[type]++;
      } else
      if ((addr & 0xFF000000) == 0xDF000000) {
         ArgusIPv4AddrUnicastReserved[type]++;
      } else
      if (((addr & 0xFF000000) >= 0xBE000000) && ((addr & 0xFF000000) <  0xC0000000)) {
         ArgusIPv4AddrUnicastReserved[type]++;
      } else
      if (((addr & 0xFF000000) >= 0xF0000000) && ((addr & 0xFF000000) <= 0xFF000000)) {
         ArgusIPv4AddrUnicastReserved[type]++;
      } else
      if ((addr & 0xFF000000) == 0x0A000000) {
         ArgusIPv4AddrUnicastPrivate[type]++;
      } else
         ArgusIPv4AddrUnicast[type]++;
   }
}

void
RaTallyIPv6AddressType(struct ArgusParserStruct *parser, struct in6_addr *addr, int type)
{
   if (IN6_IS_ADDR_UNSPECIFIED(addr))  ArgusIPv6AddrUnspecified[type]++; else
   if (IN6_IS_ADDR_LOOPBACK(addr))     ArgusIPv6AddrLoopback[type]++; else
   if (IN6_IS_ADDR_V4COMPAT(addr))     ArgusIPv6AddrV4Compat[type]++; else
   if (IN6_IS_ADDR_V4MAPPED(addr))     ArgusIPv6AddrV4Mapped[type]++; else
 
   if (IN6_IS_ADDR_LINKLOCAL(addr))    ArgusIPv6AddrLinkLocal[type]++; else
   if (IN6_IS_ADDR_SITELOCAL(addr))    ArgusIPv6AddrSiteLocal[type]++; else
 
   if (IN6_IS_ADDR_MC_NODELOCAL(addr)) ArgusIPv6AddrMulticastNodeLocal[type]++; else
   if (IN6_IS_ADDR_MC_LINKLOCAL(addr)) ArgusIPv6AddrMulticastLinkLocal[type]++; else
   if (IN6_IS_ADDR_MC_SITELOCAL(addr)) ArgusIPv6AddrMulticastSiteLocal[type]++; else
   if (IN6_IS_ADDR_MC_ORGLOCAL(addr))  ArgusIPv6AddrMulticastOrgLocal[type]++; else
   if (IN6_IS_ADDR_MC_GLOBAL(addr))    ArgusIPv6AddrMulticastGlobal[type]++;
}


void
RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}


void
RaPrintAddressTally(void)
{
   printf ("Address Summary\n");
   if (ArgusIPv4AddrUnicast[0] || ArgusIPv4AddrUnicast[1])
      printf ("  IPv4 Unicast              src %-10d  dst %-10d\n", ArgusIPv4AddrUnicast[0], ArgusIPv4AddrUnicast[1]);
   if (ArgusIPv4AddrUnicastThisNet[0] || ArgusIPv4AddrUnicastThisNet[1])
      printf ("  IPv4 Unicast This Network src %-10d  dst %-10d\n", ArgusIPv4AddrUnicastThisNet[0], ArgusIPv4AddrUnicastThisNet[1]);
   if (ArgusIPv4AddrUnicastPrivate[0] || ArgusIPv4AddrUnicastPrivate[1])
      printf ("  IPv4 Unicast Private      src %-10d  dst %-10d\n", ArgusIPv4AddrUnicastPrivate[0], ArgusIPv4AddrUnicastPrivate[1]);
   if (ArgusIPv4AddrUnicastLoopBack[0] || ArgusIPv4AddrUnicastLoopBack[1])
      printf ("  IPv4 Unicast LoopBack     src %-10d  dst %-10d\n", ArgusIPv4AddrUnicastLoopBack[0], ArgusIPv4AddrUnicastLoopBack[1]);
   if (ArgusIPv4AddrUnicastLinkLocal[0] || ArgusIPv4AddrUnicastLinkLocal[1])
      printf ("  IPv4 Unicast Link Local   src %-10d  dst %-10d\n", ArgusIPv4AddrUnicastLinkLocal[0], ArgusIPv4AddrUnicastLinkLocal[1]);
   if (ArgusIPv4AddrUnicastLinkLocal[0] || ArgusIPv4AddrUnicastLinkLocal[1])
      printf ("  IPv4 Unicast Test Net     src %-10d  dst %-10d\n", ArgusIPv4AddrUnicastTestNet[0], ArgusIPv4AddrUnicastTestNet[1]);
   if (ArgusIPv4AddrUnicastReserved[0] || ArgusIPv4AddrUnicastReserved[1])
      printf ("  IPv4 Unicast Reserved     src %-10d  dst %-10d\n", ArgusIPv4AddrUnicastReserved[0], ArgusIPv4AddrUnicastReserved[1]);
   if (ArgusIPv4AddrMulticastLocal[0] || ArgusIPv4AddrMulticastLocal[1])
      printf ("  IPv4 Multicast Local      src %-10d  dst %-10d\n", ArgusIPv4AddrMulticastLocal[0], ArgusIPv4AddrMulticastLocal[1]);
   if (ArgusIPv4AddrMulticastInternet[0] || ArgusIPv4AddrMulticastInternet[1])
      printf ("  IPv4 Multicast Internet   src %-10d  dst %-10d\n", ArgusIPv4AddrMulticastInternet[0], ArgusIPv4AddrMulticastInternet[1]);
   if (ArgusIPv4AddrMulticastAdHoc[0] || ArgusIPv4AddrMulticastAdHoc[1])
      printf ("  IPv4 Multicast AdHoc      src %-10d  dst %-10d\n", ArgusIPv4AddrMulticastAdHoc[0], ArgusIPv4AddrMulticastAdHoc[1]);
   if (ArgusIPv4AddrMulticastReserved[0] || ArgusIPv4AddrMulticastReserved[1])
      printf ("  IPv4 Multicast Reserved   src %-10d  dst %-10d\n", ArgusIPv4AddrMulticastReserved[0], ArgusIPv4AddrMulticastReserved[1]);
   if (ArgusIPv4AddrMulticastSdpSap[0] || ArgusIPv4AddrMulticastSdpSap[1])
      printf ("  IPv4 Multicast SdpSap     src %-10d  dst %-10d\n", ArgusIPv4AddrMulticastSdpSap[0], ArgusIPv4AddrMulticastSdpSap[1]);
   if (ArgusIPv4AddrMulticastNasdaq[0] || ArgusIPv4AddrMulticastNasdaq[1])
      printf ("  IPv4 Multicast Nasdaq     src %-10d  dst %-10d\n", ArgusIPv4AddrMulticastNasdaq[0], ArgusIPv4AddrMulticastNasdaq[1]);
   if (ArgusIPv4AddrMulticastDisTrans[0] || ArgusIPv4AddrMulticastDisTrans[1])
      printf ("  IPv4 Multicast DisTrans   src %-10d  dst %-10d\n", ArgusIPv4AddrMulticastDisTrans[0], ArgusIPv4AddrMulticastDisTrans[1]);
   if (ArgusIPv4AddrMulticastSrcSpec[0] || ArgusIPv4AddrMulticastSrcSpec[1])
      printf ("  IPv4 Multicast Src Spec   src %-10d  dst %-10d\n", ArgusIPv4AddrMulticastSrcSpec[0], ArgusIPv4AddrMulticastSrcSpec[1]);
   if (ArgusIPv4AddrMulticastGlop[0] || ArgusIPv4AddrMulticastGlop[1])
      printf ("  IPv4 Multicast GLOP Blk   src %-10d  dst %-10d\n", ArgusIPv4AddrMulticastGlop[0], ArgusIPv4AddrMulticastGlop[1]);
   if (ArgusIPv4AddrMulticastOrgLocal[0] || ArgusIPv4AddrMulticastOrgLocal[1])
      printf ("  IPv4 Multicast OrgLocal   src %-10d  dst %-10d\n", ArgusIPv4AddrMulticastOrgLocal[0], ArgusIPv4AddrMulticastOrgLocal[1]);
   if (ArgusIPv4AddrMulticastSiteLocal[0] || ArgusIPv4AddrMulticastSiteLocal[1])
      printf ("  IPv4 Multicast SiteLocal  src %-10d  dst %-10d\n", ArgusIPv4AddrMulticastSiteLocal[0], ArgusIPv4AddrMulticastSiteLocal[1]);
   if (ArgusIPv6AddrUnspecified[0] || ArgusIPv6AddrUnspecified[1])
      printf ("  IPv6 Unspecified          src %-10d  dst %-10d\n", ArgusIPv6AddrUnspecified[0], ArgusIPv6AddrUnspecified[1]);
   if (ArgusIPv6AddrLoopback[0] || ArgusIPv6AddrLoopback[1])
      printf ("  IPv6 Loopback             src %-10d  dst %-10d\n", ArgusIPv6AddrLoopback[0], ArgusIPv6AddrLoopback[1]);
   if (ArgusIPv6AddrLinkLocal[0] || ArgusIPv6AddrLinkLocal[1])
      printf ("  IPv6 LinkLocal            src %-10d  dst %-10d\n", ArgusIPv6AddrLinkLocal[0], ArgusIPv6AddrLinkLocal[1]);
   if (ArgusIPv6AddrSiteLocal[0] || ArgusIPv6AddrSiteLocal[1])
      printf ("  IPv6 SiteLocal            src %-10d  dst %-10d\n", ArgusIPv6AddrSiteLocal[0], ArgusIPv6AddrSiteLocal[1]);
   if (ArgusIPv6AddrGlobal[0] || ArgusIPv6AddrGlobal[1])
      printf ("  IPv6 Global               src %-10d  dst %-10d\n", ArgusIPv6AddrGlobal[0], ArgusIPv6AddrGlobal[1]);
   if (ArgusIPv6AddrMulticastNodeLocal[0] || ArgusIPv6AddrMulticastNodeLocal[1])
      printf ("  IPv6 Multicast Node Local src %-10d  dst %-10d\n", ArgusIPv6AddrMulticastNodeLocal[0], ArgusIPv6AddrMulticastNodeLocal[1]);
   if (ArgusIPv6AddrMulticastLinkLocal[0] || ArgusIPv6AddrMulticastLinkLocal[1])
      printf ("  IPv6 Multicast Link Local src %-10d  dst %-10d\n", ArgusIPv6AddrMulticastLinkLocal[0], ArgusIPv6AddrMulticastLinkLocal[1]);
   if (ArgusIPv6AddrMulticastSiteLocal[0] || ArgusIPv6AddrMulticastSiteLocal[1])
      printf ("  IPv6 Multicast Site Local src %-10d  dst %-10d\n", ArgusIPv6AddrMulticastSiteLocal[0], ArgusIPv6AddrMulticastSiteLocal[1]);
   if (ArgusIPv6AddrMulticastOrgLocal[0] || ArgusIPv6AddrMulticastOrgLocal[1])
      printf ("  IPv6 Multicast Org  Local src %-10d  dst %-10d\n", ArgusIPv6AddrMulticastOrgLocal[0], ArgusIPv6AddrMulticastOrgLocal[1]);
   if (ArgusIPv6AddrMulticastGlobal[0] || ArgusIPv6AddrMulticastGlobal[1])
      printf ("  IPv6 Multicast Global     src %-10d  dst %-10d\n", ArgusIPv6AddrMulticastGlobal[0], ArgusIPv6AddrMulticastGlobal[1]);
}

void
RaPrintSrcAddressTally(void)
{
   printf ("Address Summary\n");
   if (ArgusIPv4AddrUnicast[0])
      printf ("  IPv4 Unicast              %-10d\n", ArgusIPv4AddrUnicast[0]);
   if (ArgusIPv4AddrUnicastThisNet[0])
      printf ("  IPv4 Unicast This Network %-10d\n", ArgusIPv4AddrUnicastThisNet[0]);
   if (ArgusIPv4AddrUnicastPrivate[0])
      printf ("  IPv4 Unicast Private      %-10d\n", ArgusIPv4AddrUnicastPrivate[0]);
   if (ArgusIPv4AddrUnicastLoopBack[0])
      printf ("  IPv4 Unicast LoopBack     %-10d\n", ArgusIPv4AddrUnicastLoopBack[0]);
   if (ArgusIPv4AddrUnicastLinkLocal[0])
      printf ("  IPv4 Unicast Link Local   %-10d\n", ArgusIPv4AddrUnicastLinkLocal[0]);
   if (ArgusIPv4AddrUnicastLinkLocal[0])
      printf ("  IPv4 Unicast Test Net     %-10d\n", ArgusIPv4AddrUnicastTestNet[0]);
   if (ArgusIPv4AddrUnicastReserved[0])
      printf ("  IPv4 Unicast Reserved     %-10d\n", ArgusIPv4AddrUnicastReserved[0]);
   if (ArgusIPv4AddrMulticastLocal[0])
      printf ("  IPv4 Multicast Local      %-10d\n", ArgusIPv4AddrMulticastLocal[0]);
   if (ArgusIPv4AddrMulticastInternet[0])
      printf ("  IPv4 Multicast Internet   %-10d\n", ArgusIPv4AddrMulticastInternet[0]);
   if (ArgusIPv4AddrMulticastAdHoc[0])
      printf ("  IPv4 Multicast AdHoc      %-10d\n", ArgusIPv4AddrMulticastAdHoc[0]);
   if (ArgusIPv4AddrMulticastReserved[0])
      printf ("  IPv4 Multicast Reserved   %-10d\n", ArgusIPv4AddrMulticastReserved[0]);
   if (ArgusIPv4AddrMulticastSdpSap[0])
      printf ("  IPv4 Multicast SdpSap     %-10d\n", ArgusIPv4AddrMulticastSdpSap[0]);
   if (ArgusIPv4AddrMulticastNasdaq[0])
      printf ("  IPv4 Multicast Nasdaq     %-10d\n", ArgusIPv4AddrMulticastNasdaq[0]);
   if (ArgusIPv4AddrMulticastDisTrans[0])
      printf ("  IPv4 Multicast DisTrans   %-10d\n", ArgusIPv4AddrMulticastDisTrans[0]);
   if (ArgusIPv4AddrMulticastSrcSpec[0])
      printf ("  IPv4 Multicast Src Spec   %-10d\n", ArgusIPv4AddrMulticastSrcSpec[0]);
   if (ArgusIPv4AddrMulticastGlop[0])
      printf ("  IPv4 Multicast GLOP Blk   %-10d\n", ArgusIPv4AddrMulticastGlop[0]);
   if (ArgusIPv4AddrMulticastOrgLocal[0])
      printf ("  IPv4 Multicast OrgLocal   %-10d\n", ArgusIPv4AddrMulticastOrgLocal[0]);
   if (ArgusIPv4AddrMulticastSiteLocal[0])
      printf ("  IPv4 Multicast SiteLocal  %-10d\n", ArgusIPv4AddrMulticastSiteLocal[0]);
   if (ArgusIPv6AddrUnspecified[0])
      printf ("  IPv6 Unspecified          %-10d\n", ArgusIPv6AddrUnspecified[0]);
   if (ArgusIPv6AddrLoopback[0])
      printf ("  IPv6 Loopback             %-10d\n", ArgusIPv6AddrLoopback[0]);
   if (ArgusIPv6AddrLinkLocal[0])
      printf ("  IPv6 LinkLocal            %-10d\n", ArgusIPv6AddrLinkLocal[0]);
   if (ArgusIPv6AddrSiteLocal[0])
      printf ("  IPv6 SiteLocal            %-10d\n", ArgusIPv6AddrSiteLocal[0]);
   if (ArgusIPv6AddrGlobal[0])
      printf ("  IPv6 Global               %-10d\n", ArgusIPv6AddrGlobal[0]);
   if (ArgusIPv6AddrMulticastNodeLocal[0])
      printf ("  IPv6 Multicast Node Local %-10d\n", ArgusIPv6AddrMulticastNodeLocal[0]);
   if (ArgusIPv6AddrMulticastLinkLocal[0])
      printf ("  IPv6 Multicast Link Local %-10d\n", ArgusIPv6AddrMulticastLinkLocal[0]);
   if (ArgusIPv6AddrMulticastSiteLocal[0])
      printf ("  IPv6 Multicast Site Local %-10d\n", ArgusIPv6AddrMulticastSiteLocal[0]);
   if (ArgusIPv6AddrMulticastOrgLocal[0])
      printf ("  IPv6 Multicast Org  Local %-10d\n", ArgusIPv6AddrMulticastOrgLocal[0]);
   if (ArgusIPv6AddrMulticastGlobal[0])
      printf ("  IPv6 Multicast Global     %-10d\n", ArgusIPv6AddrMulticastGlobal[0]);
}

void
RaPrintProtoTally(void)
{
   struct ArgusRecordStruct *ns;
   char buf[1024];
   int i;

   printf ("Protocol Summary\n");
   for (i = 0; i < 0x1000; i++) {
      buf[0] = '\0';
      if ((ns = ArgusIPProtoRecs[i]) != NULL) {
         double value;
         long long recs,  pkts, spkts, dpkts;
         long long bytes, sbytes, dbytes;

         ArgusPrintProto (ArgusParser, buf, ns, 32);
         value  = ArgusFetchTransactions (ns);
         recs   = value;
         value  = ArgusFetchPktsCount (ns);
         pkts   = value;
         value  = ArgusFetchSrcPktsCount (ns);
         spkts  = value;
         value  = ArgusFetchDstPktsCount (ns);
         dpkts  = value;
         value  = ArgusFetchByteCount (ns);
         bytes  = value;
         value  = ArgusFetchSrcByteCount (ns);
         sbytes = value;
         value  = ArgusFetchDstByteCount (ns);
         dbytes = value;

#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__APPLE_CC__) || defined(__APPLE__) || defined(ARGUS_SOLARIS)
         printf ("%8.8s  %-11lld %-14lld %-14lld %-14lld %-18lld %-18lld %-18lld\n",
#else
         printf ("%8.8s  %-11Ld %-14Ld %-14Ld %-14Ld %-18Ld %-18Ld %-18Ld\n",
#endif
            buf, recs, pkts, spkts, dpkts, bytes, sbytes, dbytes);
      }
   }
   for (i = 0; i < 0x1000; i++) {
      buf[0] = '\0';
      if ((ns = ArgusEtherProtoRecs[i]) != NULL) {
         double value;
         long long recs,  pkts, spkts, dpkts;
         long long bytes, sbytes, dbytes;

         ArgusPrintProto (ArgusParser, buf, ns, 32);
         value  = ArgusFetchTransactions (ns);
         recs   = value;
         value  = ArgusFetchPktsCount (ns);
         pkts   = value;
         value  = ArgusFetchSrcPktsCount (ns);
         spkts  = value;
         value  = ArgusFetchDstPktsCount (ns);
         dpkts  = value;
         value  = ArgusFetchByteCount (ns);
         bytes  = value;
         value  = ArgusFetchSrcByteCount (ns);
         sbytes = value;
         value  = ArgusFetchDstByteCount (ns);
         dbytes = value;

#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__APPLE_CC__) || defined(__APPLE__) || defined(ARGUS_SOLARIS)
         printf ("%8.8s  %-11lld %-14lld %-14lld %-14lld %-18lld %-18lld %-18lld\n",
#else
         printf ("%8.8s  %-11Ld %-14Ld %-14Ld %-14Ld %-18Ld %-18Ld %-18Ld\n",
#endif
            buf, recs, pkts, spkts, dpkts, bytes, sbytes, dbytes);
      }
   }

   if ((ns = ArgusArpRecords) != NULL) {
      double value;
      long long recs,  pkts, spkts, dpkts;
      long long bytes, sbytes, dbytes;
 
      sprintf (buf, "arp ");
      value  = ArgusFetchTransactions (ns);
      recs   = value;
      value  = ArgusFetchPktsCount (ns);
      pkts   = value;
      value  = ArgusFetchSrcPktsCount (ns);
      spkts  = value;
      value  = ArgusFetchDstPktsCount (ns);
      dpkts  = value;
      value  = ArgusFetchByteCount (ns);
      bytes  = value;
      value  = ArgusFetchSrcByteCount (ns);
      sbytes = value;
      value  = ArgusFetchDstByteCount (ns);
      dbytes = value;
 
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__APPLE_CC__) || defined(__APPLE__) || defined(ARGUS_SOLARIS)
      printf ("%8.8s  %-11lld %-14lld %-14lld %-14lld %-18lld %-18lld %-18lld\n",
#else
      printf ("%8.8s  %-11Ld %-14Ld %-14Ld %-14Ld %-18Ld %-18Ld %-18Ld\n",
#endif
      buf, recs, pkts, spkts, dpkts, bytes, sbytes, dbytes);
   }

   if ((ns = ArgusRarpRecords) != NULL) {
      double value;
      long long recs,  pkts, spkts, dpkts;
      long long bytes, sbytes, dbytes;
 
      sprintf (buf, "rarp ");
      value  = ArgusFetchTransactions (ns);
      recs   = value;
      value  = ArgusFetchPktsCount (ns);
      pkts   = value;
      value  = ArgusFetchSrcPktsCount (ns);
      spkts  = value;
      value  = ArgusFetchDstPktsCount (ns);
      dpkts  = value;
      value  = ArgusFetchByteCount (ns);
      bytes  = value;
      value  = ArgusFetchSrcByteCount (ns);
      sbytes = value;
      value  = ArgusFetchDstByteCount (ns);
      dbytes = value;
 
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__APPLE_CC__) || defined(__APPLE__) || defined(ARGUS_SOLARIS)
      printf ("%8.8s  %-11lld %-14lld %-14lld %-14lld %-18lld %-18lld %-18lld\n",
#else
      printf ("%8.8s  %-11Ld %-14Ld %-14Ld %-14Ld %-18Ld %-18Ld %-18Ld\n",
#endif
      buf, recs, pkts, spkts, dpkts, bytes, sbytes, dbytes);
   }

   if ((ns = ArgusUnknownRecords) != NULL) {
      double value;
      long long recs,  pkts, spkts, dpkts;
      long long bytes, sbytes, dbytes;
 
      sprintf (buf, "unkwn ");
      value  = ArgusFetchTransactions (ns);
      recs   = value;
      value  = ArgusFetchPktsCount (ns);
      pkts   = value;
      value  = ArgusFetchSrcPktsCount (ns);
      spkts  = value;
      value  = ArgusFetchDstPktsCount (ns);
      dpkts  = value;
      value  = ArgusFetchByteCount (ns);
      bytes  = value;
      value  = ArgusFetchSrcByteCount (ns);
      sbytes = value;
      value  = ArgusFetchDstByteCount (ns);
      dbytes = value;
 
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__APPLE_CC__) || defined(__APPLE__) || defined(ARGUS_SOLARIS)
      printf ("%8.8s  %-11lld %-14lld %-14lld %-14lld %-18lld %-18lld %-18lld\n",
#else
      printf ("%8.8s  %-11Ld %-14Ld %-14Ld %-14Ld %-18Ld %-18Ld %-18Ld\n",
#endif
      buf, recs, pkts, spkts, dpkts, bytes, sbytes, dbytes);
   }
}
