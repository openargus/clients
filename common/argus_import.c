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
 * argus import modules for other flow data - cisco, juniper and inmon
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/argus/clients/common/argus_import.c#30 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#ifndef ArgusNetflow
#define ArgusNetflow
#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <math.h>
#include <argus_compat.h>
#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>

#include <argus/extract.h>

#include <netinet/tcp.h>


struct ArgusRecord *ArgusNetFlowCallRecord (struct ArgusParserStruct *, struct ArgusInput *, u_char **, int *);
struct ArgusRecord *ArgusNetFlowDetailInt  (struct ArgusParserStruct *, struct ArgusInput *, u_char **, int *);
struct ArgusRecord *ArgusParseCiscoRecord (struct ArgusParserStruct *, struct ArgusInput *, u_char **, int *);

struct ArgusRecord *ArgusParseCiscoRecordV1 (struct ArgusParserStruct *, struct ArgusInput *, u_char **, int *);
struct ArgusRecord *ArgusParseCiscoRecordV5 (struct ArgusParserStruct *, struct ArgusInput *, u_char **, int *);
struct ArgusRecord *ArgusParseCiscoRecordV6 (struct ArgusParserStruct *, struct ArgusInput *, u_char **, int *);
struct ArgusRecord *ArgusParseCiscoRecordV7 (struct ArgusParserStruct *, struct ArgusInput *, u_char **, int *);
struct ArgusRecord *ArgusParseCiscoRecordV8 (struct ArgusParserStruct *, struct ArgusInput *, u_char **, int *);
struct ArgusRecord *ArgusParseCiscoRecordV9 (struct ArgusParserStruct *, struct ArgusInput *, u_char **, int *);

struct ArgusRecord *ArgusParseCiscoRecordV9Data (struct ArgusParserStruct *, struct ArgusInput *, struct ArgusQueueStruct *, u_char *, int *);

unsigned char *ArgusNetFlowRecordHeader = NULL;
unsigned char ArgusNetFlowArgusRecordBuf[4098];

struct ArgusRecord *ArgusNetFlowArgusRecord = (struct ArgusRecord *) ArgusNetFlowArgusRecordBuf;

#define ARGUSCISCOTEMPLATEIPV4		0x04
#define ARGUSCISCOTEMPLATEIPV6		0x06

struct ArgusCiscoTemplateStruct {
   struct timeval lasttime;
   int status, length, count;
   CiscoFlowTemplateFlowEntryV9_t **tHdr;
};

struct ArgusCiscoSourceStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusHashTableHdr htblbuf, *htblhdr;
   unsigned int srcid, saddr;
   struct timeval startime, lasttime;
   struct ArgusCiscoTemplateStruct templates[0x10000];
};

unsigned int ArgusFlowSeq = 0, ArgusCounter;
unsigned int ArgusCiscoSrcId = 0;
unsigned int ArgusCiscoSrcAddr = 0;
unsigned int ArgusSysUptime = 0;
struct timeval ArgusCiscoTvpBuf, *ArgusCiscoTvp = &ArgusCiscoTvpBuf;
struct ArgusQueueStruct *ArgusTemplateQueue = NULL;

struct ArgusRecord * 
ArgusParseCiscoRecordV1 (struct ArgusParserStruct *parser, struct ArgusInput *input, u_char **ptr, int *count)
{
   CiscoFlowEntryV1_t  *entryPtrV1 = (CiscoFlowEntryV1_t *) *ptr;
   CiscoFlowHeaderV1_t *hdrPtrV1   = (CiscoFlowHeaderV1_t *) ArgusNetFlowRecordHeader;
   struct ArgusRecord *argus = ArgusNetFlowArgusRecord;
   struct ArgusDSRHeader *dsr = (struct ArgusDSRHeader *) &ArgusNetFlowArgusRecordBuf[4];
   int i;

   *ptr += sizeof(CiscoFlowEntryV1_t);
   bzero ((char *) argus, sizeof(ArgusNetFlowArgusRecordBuf));
   argus->hdr.type    = ARGUS_NETFLOW | ARGUS_VERSION;
   argus->hdr.cause   = ARGUS_STATUS;
   argus->hdr.len     = 1;

   if (hdrPtrV1) {
      for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
         int ind = (1 << i);
         switch (ind) {
            case ARGUS_FLOW_INDEX: {
               struct ArgusFlow *flow = (struct ArgusFlow *) dsr;
               flow->hdr.type              = ARGUS_FLOW_DSR;
               flow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
               flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
               flow->hdr.argus_dsrvl8.len  = 5;
               flow->ip_flow.ip_src = ntohl(entryPtrV1->srcaddr);
               flow->ip_flow.ip_dst = ntohl(entryPtrV1->dstaddr);

               switch (flow->ip_flow.ip_p = entryPtrV1->prot) {
                  case IPPROTO_TCP:
                  case IPPROTO_UDP:
                     flow->ip_flow.sport  = ntohs(entryPtrV1->srcport);
                     flow->ip_flow.dport  = ntohs(entryPtrV1->dstport);
                  break;
         
                  case IPPROTO_ICMP:
                     flow->icmp_flow.type  = ((char *)&entryPtrV1->dstport)[0];
                     flow->icmp_flow.code  = ((char *)&entryPtrV1->dstport)[1];
                  break;
               }
               dsr += flow->hdr.argus_dsrvl8.len;
               argus->hdr.len += flow->hdr.argus_dsrvl8.len;
               break;
            }
            case ARGUS_TIME_INDEX: {
               struct ArgusTimeObject *time = (struct ArgusTimeObject *) dsr;
               long timeval;

               time->hdr.type               = ARGUS_TIME_DSR;
               time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
               time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
               time->hdr.argus_dsrvl8.len   = 5;               

               timeval = ntohl(entryPtrV1->first);
               time->src.start.tv_sec   = (timeval - (long)hdrPtrV1->sysUptime)/1000; 
               time->src.start.tv_sec  += hdrPtrV1->unix_secs;

               time->src.start.tv_usec  = ((timeval - (long)hdrPtrV1->sysUptime)%1000) * 1000; 
               time->src.start.tv_usec += hdrPtrV1->unix_nsecs/1000;

               if (time->src.start.tv_usec >= 1000000) {
                  time->src.start.tv_sec++;
                  time->src.start.tv_usec -= 1000000;
               }
               if (time->src.start.tv_usec < 0) {
                  time->src.start.tv_sec--;
                  time->src.start.tv_usec += 1000000;
               }

               timeval = ntohl(entryPtrV1->last);
               time->src.end.tv_sec   = (timeval - (long)hdrPtrV1->sysUptime)/1000;
               time->src.end.tv_sec  += hdrPtrV1->unix_secs;

               time->src.end.tv_usec  = ((timeval - (long)hdrPtrV1->sysUptime)%1000) * 1000;
               time->src.end.tv_usec += hdrPtrV1->unix_nsecs/1000;

               if (time->src.end.tv_usec >= 1000000) {
                  time->src.end.tv_sec++;
                  time->src.end.tv_usec -= 1000000;
               }
               if (time->src.end.tv_usec < 0) {
                  time->src.end.tv_sec--;
                  time->src.end.tv_usec += 1000000;
               }

               time->src.start.tv_usec = (time->src.start.tv_usec / 1000) * 1000;
               time->src.end.tv_usec  = (time->src.end.tv_usec / 1000) * 1000;
               dsr += time->hdr.argus_dsrvl8.len;
               argus->hdr.len += time->hdr.argus_dsrvl8.len;
               break;
            }
            case ARGUS_TRANSPORT_INDEX: {
               if (input->addr.s_addr != 0) {
                  struct ArgusTransportStruct *trans = (struct ArgusTransportStruct *) dsr;
                  trans->hdr.type               = ARGUS_TRANSPORT_DSR;
                  trans->hdr.subtype            = ARGUS_SRC;
                  trans->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4;
                  trans->hdr.argus_dsrvl8.len   = 2;
                  trans->srcid.a_un.ipv4        = input->addr.s_addr;

                  dsr += trans->hdr.argus_dsrvl8.len;
                  argus->hdr.len += trans->hdr.argus_dsrvl8.len;
               }
               break;
            }
            case ARGUS_IPATTR_INDEX: {
               struct ArgusIPAttrStruct *attr = (struct ArgusIPAttrStruct *) dsr;
               attr->hdr.type               = ARGUS_IPATTR_DSR;
               attr->hdr.subtype            = 0;
               attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
               attr->hdr.argus_dsrvl8.len   = 2;
               attr->src.tos                = entryPtrV1->tos; 
               attr->src.ttl                = 0;
               attr->src.ip_id              = 0;
               dsr += attr->hdr.argus_dsrvl8.len;
               argus->hdr.len += attr->hdr.argus_dsrvl8.len;
               break;
            }
            case ARGUS_METRIC_INDEX: {
               struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *) dsr;
               long long *ptr;
                                    
               metric->hdr.type              = ARGUS_METER_DSR;
               metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
               metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_LONGLONG;
               metric->hdr.argus_dsrvl8.len  = 5;
               ptr    = &metric->src.pkts;
               *ptr++ = ntohl(entryPtrV1->pkts);
               *ptr++ = ntohl(entryPtrV1->bytes);
               dsr += metric->hdr.argus_dsrvl8.len;
               argus->hdr.len += metric->hdr.argus_dsrvl8.len;
               break;
            }
            case ARGUS_MAC_INDEX: {
               struct ArgusMacStruct *mac = (struct ArgusMacStruct *) dsr;
               mac->hdr.type              = ARGUS_MAC_DSR;
               mac->hdr.subtype           = 0;
               mac->hdr.argus_dsrvl8.qual = ARGUS_PORT_INDEX;
               mac->hdr.argus_dsrvl8.len  = 5;
//             entryPtrV1->input = ntohs(entryPtrV1->input);
//             entryPtrV1->output = ntohs(entryPtrV1->output);
#if defined(ARGUS_SOLARIS)
               bcopy((char *)&entryPtrV1->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost.ether_addr_octet[4], 2);
               bcopy((char *)&entryPtrV1->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost.ether_addr_octet[4], 2);
#else
               bcopy((char *)&entryPtrV1->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost[4], 2);
               bcopy((char *)&entryPtrV1->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost[4], 2);
#endif

               dsr += mac->hdr.argus_dsrvl8.len;
               argus->hdr.len += mac->hdr.argus_dsrvl8.len;
               break;
            }

            case ARGUS_NETWORK_INDEX: {
               if (entryPtrV1->prot == IPPROTO_TCP) {
                  struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) dsr;
                  net->hdr.type              = ARGUS_NETWORK_DSR;
                  net->hdr.subtype           = ARGUS_TCP_STATUS;
                  net->hdr.argus_dsrvl8.len  = 3;
                  net->net_union.tcpstatus.src = entryPtrV1->flags;

                  dsr += net->hdr.argus_dsrvl8.len;
                  argus->hdr.len += net->hdr.argus_dsrvl8.len;
               }
            }
         }
      }
   }

#ifdef _LITTLE_ENDIAN
   ArgusHtoN(argus);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV1 (0x%x) returning 0x%x\n", *ptr, argus);
#endif

   return(argus);
}


struct ArgusRecord * 
ArgusParseCiscoRecordV5 (struct ArgusParserStruct *parser, struct ArgusInput *input, u_char **ptr, int *count)
{
   CiscoFlowEntryV5_t  *entryPtrV5 = (CiscoFlowEntryV5_t *) *ptr;
   CiscoFlowHeaderV5_t *hdrPtrV5   = (CiscoFlowHeaderV5_t *) ArgusNetFlowRecordHeader;
   struct ArgusRecord *argus = ArgusNetFlowArgusRecord;
   struct ArgusDSRHeader *dsr = (struct ArgusDSRHeader *) &ArgusNetFlowArgusRecordBuf[4];
   int i;

   *ptr += sizeof(CiscoFlowEntryV5_t);
   bzero ((char *) argus, sizeof(ArgusNetFlowArgusRecordBuf));
   argus->hdr.type    = ARGUS_NETFLOW | ARGUS_VERSION;
   argus->hdr.cause   = ARGUS_STATUS;
   argus->hdr.len     = 1;

   if (hdrPtrV5) {
      for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
         switch (i) {
            case ARGUS_FLOW_INDEX: {
               struct ArgusFlow *flow = (struct ArgusFlow *) dsr;
               flow->hdr.type              = ARGUS_FLOW_DSR;
               flow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
               flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
               flow->hdr.argus_dsrvl8.len  = 5;
               flow->ip_flow.ip_src = ntohl(entryPtrV5->srcaddr);
               flow->ip_flow.ip_dst = ntohl(entryPtrV5->dstaddr);

               switch (flow->ip_flow.ip_p = entryPtrV5->prot) {
                  case IPPROTO_TCP:
                  case IPPROTO_UDP:
                     flow->ip_flow.sport  = ntohs(entryPtrV5->srcport);
                     flow->ip_flow.dport  = ntohs(entryPtrV5->dstport);
                  break;
         
                  case IPPROTO_ICMP:
                     flow->icmp_flow.type  = ((char *)&entryPtrV5->dstport)[0];
                     flow->icmp_flow.code  = ((char *)&entryPtrV5->dstport)[1];
                  break;
               }
               dsr += flow->hdr.argus_dsrvl8.len;
               argus->hdr.len += flow->hdr.argus_dsrvl8.len;
               break;
            }
            case ARGUS_TIME_INDEX: {
               struct ArgusTimeObject *time = (struct ArgusTimeObject *) dsr;
               int timeval, secs, usecs;

               time->hdr.type               = ARGUS_TIME_DSR;
               time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
               time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
               time->hdr.argus_dsrvl8.len   = 5;               

               timeval = ntohl(entryPtrV5->first);

               secs  = hdrPtrV5->unix_secs       + ((timeval - (int)hdrPtrV5->sysUptime) / 1000);
               usecs = hdrPtrV5->unix_nsecs/1000 + ((timeval - (int)hdrPtrV5->sysUptime) % 1000) * 1000;
               time->src.start.tv_sec  = secs;

               if (usecs < 0) {
                  time->src.start.tv_sec--;
                  usecs += 1000000;
               } else
               if (usecs > 1000000) {
                  time->src.start.tv_sec++;
                  usecs -= 1000000;
               }
               time->src.start.tv_usec = usecs;

               timeval = ntohl(entryPtrV5->last);
               secs  = hdrPtrV5->unix_secs       + ((timeval - (int)hdrPtrV5->sysUptime) / 1000);
               usecs = hdrPtrV5->unix_nsecs/1000 + ((timeval - (int)hdrPtrV5->sysUptime) % 1000) * 1000;
               time->src.end.tv_sec  = secs;

               if (usecs < 0) {
                  time->src.start.tv_sec--;
                  usecs += 1000000;
               } else
               if (usecs > 1000000) {
                  time->src.start.tv_sec++;
                  usecs -= 1000000;
               }
               time->src.end.tv_usec = usecs;

               dsr += time->hdr.argus_dsrvl8.len;
               argus->hdr.len += time->hdr.argus_dsrvl8.len;
               break;
            }

            case ARGUS_TRANSPORT_INDEX: {
               if (input->addr.s_addr != 0) {
                  struct ArgusTransportStruct *trans = (struct ArgusTransportStruct *) dsr;
                  trans->hdr.type               = ARGUS_TRANSPORT_DSR;
                  trans->hdr.subtype            = ARGUS_SRC;
                  trans->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4;
                  trans->hdr.argus_dsrvl8.len   = 2;
                  trans->srcid.a_un.ipv4        = input->addr.s_addr;

                  dsr += trans->hdr.argus_dsrvl8.len;
                  argus->hdr.len += trans->hdr.argus_dsrvl8.len;
               }
               break;
            }
            case ARGUS_IPATTR_INDEX: {
               struct ArgusIPAttrStruct *attr = (struct ArgusIPAttrStruct *) dsr;
               attr->hdr.type               = ARGUS_IPATTR_DSR;
               attr->hdr.subtype            = 0;
               attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
               attr->hdr.argus_dsrvl8.len   = 2;
               attr->src.tos                = entryPtrV5->tos; 
               attr->src.ttl                = 0;
               attr->src.ip_id              = 0;
               dsr += attr->hdr.argus_dsrvl8.len;
               argus->hdr.len += attr->hdr.argus_dsrvl8.len;
               break;
            }
            case ARGUS_ASN_INDEX: {
               struct ArgusAsnStruct *asn  = (struct ArgusAsnStruct *) dsr;
               asn->hdr.type               = ARGUS_ASN_DSR;
               asn->hdr.subtype            = 0;
               asn->hdr.argus_dsrvl8.qual  = 0;
               asn->hdr.argus_dsrvl8.len   = 3;
               asn->src_as                 = entryPtrV5->src_as;
               asn->dst_as                 = entryPtrV5->dst_as;
               dsr += asn->hdr.argus_dsrvl8.len;
               argus->hdr.len += asn->hdr.argus_dsrvl8.len;
               break;
            }
            case ARGUS_METRIC_INDEX: {
               struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *) dsr;
               uint32_t val;

               metric->hdr.type              = ARGUS_METER_DSR;
               metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
               metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
               metric->hdr.argus_dsrvl8.len  = 3;

               dsr++;
               val = ntohl(entryPtrV5->pkts);
               *(int *)dsr++ = val;
               val = ntohl(entryPtrV5->bytes);
               *(int *)dsr++ = val;
               argus->hdr.len += metric->hdr.argus_dsrvl8.len;
               break;
            }
            case ARGUS_MAC_INDEX: {
               struct ArgusMacStruct *mac = (struct ArgusMacStruct *) dsr;
               mac->hdr.type              = ARGUS_MAC_DSR;
               mac->hdr.subtype           = 0;
               mac->hdr.argus_dsrvl8.qual = ARGUS_PORT_INDEX;
               mac->hdr.argus_dsrvl8.len  = 5;
//             entryPtrV5->input = ntohs(entryPtrV5->input);
//             entryPtrV5->output = ntohs(entryPtrV5->output);
#if defined(ARGUS_SOLARIS)
               bcopy((char *)&entryPtrV5->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost.ether_addr_octet[4], 2);
               bcopy((char *)&entryPtrV5->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost.ether_addr_octet[4], 2);
#else
               bcopy((char *)&entryPtrV5->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost[4], 2);
               bcopy((char *)&entryPtrV5->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost[4], 2);
#endif

               dsr += mac->hdr.argus_dsrvl8.len;
               argus->hdr.len += mac->hdr.argus_dsrvl8.len;
               break;
            }

            case ARGUS_NETWORK_INDEX: {
               if (entryPtrV5->prot == IPPROTO_TCP) {
                  struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) dsr;
                  struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;

                  net->hdr.type              = ARGUS_NETWORK_DSR;
                  net->hdr.subtype           = ARGUS_TCP_STATUS;
                  net->hdr.argus_dsrvl8.len  = 3;
                  net->net_union.tcpstatus.src = entryPtrV5->tcp_flags;

                  if (entryPtrV5->tcp_flags & TH_RST) 
                     tcp->status |= ARGUS_RESET;
          
                  if (entryPtrV5->tcp_flags & TH_FIN)
                     tcp->status |= ARGUS_FIN;
          
                  if ((entryPtrV5->tcp_flags & TH_ACK) || (entryPtrV5->tcp_flags & TH_PUSH) || (entryPtrV5->tcp_flags & TH_URG))
                     tcp->status |= ARGUS_CON_ESTABLISHED;
          
                  switch (entryPtrV5->tcp_flags & (TH_SYN|TH_ACK)) {
                     case (TH_SYN):  
                        tcp->status |= ARGUS_SAW_SYN;
                        break;
             
                     case (TH_SYN|TH_ACK): 
                        tcp->status |= ARGUS_SAW_SYN_SENT;  
                        if (ntohl(entryPtrV5->pkts) > 1)
                           tcp->status &= ~(ARGUS_CON_ESTABLISHED);
                        break;
                  }

                  dsr += net->hdr.argus_dsrvl8.len;
                  argus->hdr.len += net->hdr.argus_dsrvl8.len;
               }
            }
         }
      }
   }

#ifdef _LITTLE_ENDIAN
   ArgusHtoN(argus);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV5 (0x%x) returning 0x%x\n", *ptr, argus);
#endif

   return(argus);
}



struct ArgusRecord * 
ArgusParseCiscoRecordV6 (struct ArgusParserStruct *parser, struct ArgusInput *input, u_char **ptr, int *count)
{
   struct ArgusRecord *argus = ArgusNetFlowArgusRecord;
   CiscoFlowEntryV6_t  *entryPtrV6 = (CiscoFlowEntryV6_t *) *ptr;
   CiscoFlowHeaderV6_t *hdrPtrV6   = (CiscoFlowHeaderV6_t *) ArgusNetFlowRecordHeader;
   struct ArgusDSRHeader *dsr = (struct ArgusDSRHeader *) &ArgusNetFlowArgusRecordBuf[4];
   int i;

   *ptr += sizeof(CiscoFlowEntryV6_t);
   bzero ((char *) argus, sizeof (*argus));
   argus->hdr.type    = ARGUS_NETFLOW | ARGUS_VERSION;
   argus->hdr.cause   = ARGUS_STATUS;
   argus->hdr.len     = sizeof(argus->hdr) + sizeof(argus->argus_far);

   if (hdrPtrV6) {
      for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
         switch (i) {
            case ARGUS_FLOW_INDEX: {
               struct ArgusFlow *flow = (struct ArgusFlow *) dsr;
               flow->hdr.type              = ARGUS_FLOW_DSR;
               flow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
               flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
               flow->hdr.argus_dsrvl8.len  = 5;
               flow->ip_flow.ip_src = ntohl(entryPtrV6->srcaddr);
               flow->ip_flow.ip_dst = ntohl(entryPtrV6->dstaddr);

               flow->ip_flow.smask = entryPtrV6->src_mask;
               flow->ip_flow.dmask = entryPtrV6->src_mask;

               switch (flow->ip_flow.ip_p = entryPtrV6->prot) {
                  case IPPROTO_TCP:
                  case IPPROTO_UDP:
                     flow->ip_flow.sport  = ntohs(entryPtrV6->srcport);
                     flow->ip_flow.dport  = ntohs(entryPtrV6->dstport);
                  break;

                  case IPPROTO_ICMP:
                     flow->icmp_flow.type  = ((char *)&entryPtrV6->dstport)[0];
                     flow->icmp_flow.code  = ((char *)&entryPtrV6->dstport)[1];
                  break;
               }
               dsr += flow->hdr.argus_dsrvl8.len;
               argus->hdr.len += flow->hdr.argus_dsrvl8.len;
               break;
            }

            case ARGUS_TIME_INDEX: {
               struct ArgusTimeObject *time = (struct ArgusTimeObject *) dsr;
               long timeval;

               time->hdr.type               = ARGUS_TIME_DSR;
               time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
               time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
               time->hdr.argus_dsrvl8.len   = 5;               

               timeval = ntohl(entryPtrV6->first);
               time->src.start.tv_sec   = (timeval - (long)hdrPtrV6->sysUptime)/1000; 
               time->src.start.tv_sec  += hdrPtrV6->unix_secs;

               time->src.start.tv_usec  = ((timeval - (long)hdrPtrV6->sysUptime)%1000) * 1000; 
               time->src.start.tv_usec += hdrPtrV6->unix_nsecs/1000;

               if (time->src.start.tv_usec >= 1000000) {
                  time->src.start.tv_sec++;
                  time->src.start.tv_usec -= 1000000;
               }
               if (time->src.start.tv_usec < 0) {
                  time->src.start.tv_sec--;
                  time->src.start.tv_usec += 1000000;
               }

               timeval = ntohl(entryPtrV6->last);
               time->src.end.tv_sec   = (timeval - (long)hdrPtrV6->sysUptime)/1000;
               time->src.end.tv_sec  += hdrPtrV6->unix_secs;

               time->src.end.tv_usec  = ((timeval - (long)hdrPtrV6->sysUptime)%1000) * 1000;
               time->src.end.tv_usec += hdrPtrV6->unix_nsecs/1000;

               if (time->src.end.tv_usec >= 1000000) {
                  time->src.end.tv_sec++;
                  time->src.end.tv_usec -= 1000000;
               }
               if (time->src.end.tv_usec < 0) {
                  time->src.end.tv_sec--;
                  time->src.end.tv_usec += 1000000;
               }

               time->src.start.tv_usec = (time->src.start.tv_usec / 1000) * 1000;
               time->src.end.tv_usec  = (time->src.end.tv_usec / 1000) * 1000;
               dsr += time->hdr.argus_dsrvl8.len;
               argus->hdr.len += time->hdr.argus_dsrvl8.len;
               break;
            }

            case ARGUS_ASN_INDEX: {
               struct ArgusAsnStruct *asn  = (struct ArgusAsnStruct *) dsr;
               asn->hdr.type               = ARGUS_ASN_DSR;
               asn->hdr.subtype            = 0;
               asn->hdr.argus_dsrvl8.qual  = 0;
               asn->hdr.argus_dsrvl8.len   = 3;
               asn->src_as                 = entryPtrV6->src_as;
               asn->dst_as                 = entryPtrV6->dst_as;
               dsr += asn->hdr.argus_dsrvl8.len;
               argus->hdr.len += asn->hdr.argus_dsrvl8.len;
               break;
            }
            case ARGUS_METRIC_INDEX: {
               struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *) dsr;
               uint32_t val;

               metric->hdr.type              = ARGUS_METER_DSR;
               metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
               metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
               metric->hdr.argus_dsrvl8.len  = 3;

               dsr++;
               val = ntohl(entryPtrV6->pkts);
               *(int *)dsr++ = val;
               val = ntohl(entryPtrV6->bytes);
               *(int *)dsr++ = val;
               argus->hdr.len += metric->hdr.argus_dsrvl8.len;
               break;
            }

            case ARGUS_MAC_INDEX: {
               struct ArgusMacStruct *mac = (struct ArgusMacStruct *) dsr;
               mac->hdr.type              = ARGUS_MAC_DSR;
               mac->hdr.subtype           = 0;
               mac->hdr.argus_dsrvl8.qual = ARGUS_PORT_INDEX;
               mac->hdr.argus_dsrvl8.len  = 5;
//             entryPtrV6->input = ntohs(entryPtrV6->input);
//             entryPtrV6->output = ntohs(entryPtrV6->output);
#if defined(ARGUS_SOLARIS)
               bcopy((char *)&entryPtrV6->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost.ether_addr_octet[4], 2);
               bcopy((char *)&entryPtrV6->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost.ether_addr_octet[4], 2);
#else
               bcopy((char *)&entryPtrV6->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost[4], 2);
               bcopy((char *)&entryPtrV6->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost[4], 2);
#endif

               dsr += mac->hdr.argus_dsrvl8.len;
               argus->hdr.len += mac->hdr.argus_dsrvl8.len;
               break;
            }

            case ARGUS_NETWORK_INDEX: {
               if (entryPtrV6->prot == IPPROTO_TCP) {
                  struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) dsr;
                  struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;

                  net->hdr.type              = ARGUS_NETWORK_DSR;
                  net->hdr.subtype           = ARGUS_TCP_STATUS;
                  net->hdr.argus_dsrvl8.len  = 3;
                  net->net_union.tcpstatus.src = entryPtrV6->tcp_flags;

                  if (entryPtrV6->tcp_flags & TH_RST) 
                     tcp->status |= ARGUS_RESET;
          
                  if (entryPtrV6->tcp_flags & TH_FIN)
                     tcp->status |= ARGUS_FIN;
          
                  if ((entryPtrV6->tcp_flags & TH_ACK) || (entryPtrV6->tcp_flags & TH_PUSH) || (entryPtrV6->tcp_flags & TH_URG))
                     tcp->status |= ARGUS_CON_ESTABLISHED;
          
                  switch (entryPtrV6->tcp_flags & (TH_SYN|TH_ACK)) {
                     case (TH_SYN):  
                        tcp->status |= ARGUS_SAW_SYN;
                        break;
             
                     case (TH_SYN|TH_ACK): 
                        tcp->status |= ARGUS_SAW_SYN_SENT;  
                        if (ntohl(entryPtrV6->pkts) > 1)
                           tcp->status &= ~(ARGUS_CON_ESTABLISHED);
                        break;
                  }

                  dsr += net->hdr.argus_dsrvl8.len;
                  argus->hdr.len += net->hdr.argus_dsrvl8.len;
               }
               break;
            }
            case ARGUS_TRANSPORT_INDEX: {
               if (input->addr.s_addr != 0) {
                  struct ArgusTransportStruct *trans = (struct ArgusTransportStruct *) dsr;
                  trans->hdr.type               = ARGUS_TRANSPORT_DSR;
                  trans->hdr.subtype            = ARGUS_SRC;
                  trans->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4;
                  trans->hdr.argus_dsrvl8.len   = 2;
                  trans->srcid.a_un.ipv4        = input->addr.s_addr;

                  dsr += trans->hdr.argus_dsrvl8.len;
                  argus->hdr.len += trans->hdr.argus_dsrvl8.len;
               }
               break;
            }
            case ARGUS_IPATTR_INDEX: {
               struct ArgusIPAttrStruct *attr = (struct ArgusIPAttrStruct *) dsr;
               attr->hdr.type               = ARGUS_IPATTR_DSR;
               attr->hdr.subtype            = 0;
               attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
               attr->hdr.argus_dsrvl8.len   = 2;
               attr->src.tos                = entryPtrV6->tos;
               attr->src.ttl                = 0;
               attr->src.ip_id              = 0;
               dsr += attr->hdr.argus_dsrvl8.len;
               argus->hdr.len += attr->hdr.argus_dsrvl8.len;
               break;
            }

         }
      }
   }

#ifdef _LITTLE_ENDIAN
   ArgusHtoN(argus);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV6 (0x%x) returning 0x%x\n", *ptr, argus);
#endif

   return(argus);
}


struct ArgusRecord * 
ArgusParseCiscoRecordV7 (struct ArgusParserStruct *parser, struct ArgusInput *input, u_char **ptr, int *count)
{
   struct ArgusRecord *argus = ArgusNetFlowArgusRecord;
   CiscoFlowEntryV7_t  *entryPtrV7 = (CiscoFlowEntryV7_t *) *ptr;
   CiscoFlowHeaderV7_t *hdrPtrV7   = (CiscoFlowHeaderV7_t *) ArgusNetFlowRecordHeader;
   struct ArgusDSRHeader *dsr = (struct ArgusDSRHeader *) &ArgusNetFlowArgusRecordBuf[4];
   int i;

   *ptr += sizeof(CiscoFlowEntryV7_t);
   bzero ((char *) argus, sizeof (*argus));
   argus->hdr.type    = ARGUS_NETFLOW | ARGUS_VERSION;
   argus->hdr.cause   = ARGUS_STATUS;
   argus->hdr.len     = sizeof(argus->hdr) + sizeof(argus->argus_far);

   if (hdrPtrV7) {
      for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
         switch (i) {
            case ARGUS_FLOW_INDEX: {
               struct ArgusFlow *flow = (struct ArgusFlow *) dsr;
               flow->hdr.type              = ARGUS_FLOW_DSR;
               flow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
               flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
               flow->hdr.argus_dsrvl8.len  = 5;
               flow->ip_flow.ip_src = ntohl(entryPtrV7->srcaddr);
               flow->ip_flow.ip_dst = ntohl(entryPtrV7->dstaddr);

               flow->ip_flow.smask = entryPtrV7->src_mask;
               flow->ip_flow.dmask = entryPtrV7->src_mask;

               switch (flow->ip_flow.ip_p = entryPtrV7->prot) {
                  case IPPROTO_TCP:
                  case IPPROTO_UDP:
                     flow->ip_flow.sport  = ntohs(entryPtrV7->srcport);
                     flow->ip_flow.dport  = ntohs(entryPtrV7->dstport);
                  break;

                  case IPPROTO_ICMP:
                     flow->icmp_flow.type  = ((char *)&entryPtrV7->dstport)[0];
                     flow->icmp_flow.code  = ((char *)&entryPtrV7->dstport)[1];
                  break;
               }
               dsr += flow->hdr.argus_dsrvl8.len;
               argus->hdr.len += flow->hdr.argus_dsrvl8.len;
               break;
            }

            case ARGUS_TIME_INDEX: {
               struct ArgusTimeObject *time = (struct ArgusTimeObject *) dsr;
               long timeval;

               time->hdr.type               = ARGUS_TIME_DSR;
               time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
               time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
               time->hdr.argus_dsrvl8.len   = 5;               

               timeval = ntohl(entryPtrV7->first);
               time->src.start.tv_sec   = (timeval - (long)hdrPtrV7->sysUptime)/1000; 
               time->src.start.tv_sec  += hdrPtrV7->unix_secs;

               time->src.start.tv_usec  = ((timeval - (long)hdrPtrV7->sysUptime)%1000) * 1000; 
               time->src.start.tv_usec += hdrPtrV7->unix_nsecs/1000;

               if (time->src.start.tv_usec >= 1000000) {
                  time->src.start.tv_sec++;
                  time->src.start.tv_usec -= 1000000;
               }
               if (time->src.start.tv_usec < 0) {
                  time->src.start.tv_sec--;
                  time->src.start.tv_usec += 1000000;
               }

               timeval = ntohl(entryPtrV7->last);
               time->src.end.tv_sec   = (timeval - (long)hdrPtrV7->sysUptime)/1000;
               time->src.end.tv_sec  += hdrPtrV7->unix_secs;

               time->src.end.tv_usec  = ((timeval - (long)hdrPtrV7->sysUptime)%1000) * 1000;
               time->src.end.tv_usec += hdrPtrV7->unix_nsecs/1000;

               if (time->src.end.tv_usec >= 1000000) {
                  time->src.end.tv_sec++;
                  time->src.end.tv_usec -= 1000000;
               }
               if (time->src.end.tv_usec < 0) {
                  time->src.end.tv_sec--;
                  time->src.end.tv_usec += 1000000;
               }

               time->src.start.tv_usec = (time->src.start.tv_usec / 1000) * 1000;
               time->src.end.tv_usec  = (time->src.end.tv_usec / 1000) * 1000;
               dsr += time->hdr.argus_dsrvl8.len;
               argus->hdr.len += time->hdr.argus_dsrvl8.len;
               break;
            }

            case ARGUS_ASN_INDEX: {
               struct ArgusAsnStruct *asn  = (struct ArgusAsnStruct *) dsr;
               asn->hdr.type               = ARGUS_ASN_DSR;
               asn->hdr.subtype            = 0;
               asn->hdr.argus_dsrvl8.qual  = 0;
               asn->hdr.argus_dsrvl8.len   = 3;
               asn->src_as                 = entryPtrV7->src_as;
               asn->dst_as                 = entryPtrV7->dst_as;
               dsr += asn->hdr.argus_dsrvl8.len;
               argus->hdr.len += asn->hdr.argus_dsrvl8.len;
               break;
            }
            case ARGUS_METRIC_INDEX: {
               struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *) dsr;
               uint32_t val;

               metric->hdr.type              = ARGUS_METER_DSR;
               metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
               metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
               metric->hdr.argus_dsrvl8.len  = 3;

               dsr++;
               val = ntohl(entryPtrV7->pkts);
               *(int *)dsr++ = val;
               val = ntohl(entryPtrV7->bytes);
               *(int *)dsr++ = val;
               argus->hdr.len += metric->hdr.argus_dsrvl8.len;
               break;
            }

            case ARGUS_MAC_INDEX: {
               struct ArgusMacStruct *mac = (struct ArgusMacStruct *) dsr;
               mac->hdr.type              = ARGUS_MAC_DSR;
               mac->hdr.subtype           = 0;
               mac->hdr.argus_dsrvl8.qual = ARGUS_PORT_INDEX;
               mac->hdr.argus_dsrvl8.len  = 5;
//             entryPtrV7->input = ntohs(entryPtrV7->input);
//             entryPtrV7->output = ntohs(entryPtrV7->output);
#if defined(ARGUS_SOLARIS)
               bcopy((char *)&entryPtrV7->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost.ether_addr_octet[4], 2);
               bcopy((char *)&entryPtrV7->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost.ether_addr_octet[4], 2);
#else
               bcopy((char *)&entryPtrV7->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost[4], 2);
               bcopy((char *)&entryPtrV7->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost[4], 2);
#endif

               dsr += mac->hdr.argus_dsrvl8.len;
               argus->hdr.len += mac->hdr.argus_dsrvl8.len;
               break;
            }

            case ARGUS_NETWORK_INDEX: {
               if (entryPtrV7->prot == IPPROTO_TCP) {
                  struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) dsr;
                  struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;

                  net->hdr.type              = ARGUS_NETWORK_DSR;
                  net->hdr.subtype           = ARGUS_TCP_STATUS;
                  net->hdr.argus_dsrvl8.len  = 3;
                  net->net_union.tcpstatus.src = entryPtrV7->tcp_flags;

                  if (entryPtrV7->tcp_flags & TH_RST) 
                     tcp->status |= ARGUS_RESET;
          
                  if (entryPtrV7->tcp_flags & TH_FIN)
                     tcp->status |= ARGUS_FIN;
          
                  if ((entryPtrV7->tcp_flags & TH_ACK) || (entryPtrV7->tcp_flags & TH_PUSH) || (entryPtrV7->tcp_flags & TH_URG))
                     tcp->status |= ARGUS_CON_ESTABLISHED;
          
                  switch (entryPtrV7->tcp_flags & (TH_SYN|TH_ACK)) {
                     case (TH_SYN):  
                        tcp->status |= ARGUS_SAW_SYN;
                        break;
             
                     case (TH_SYN|TH_ACK): 
                        tcp->status |= ARGUS_SAW_SYN_SENT;  
                        if (ntohl(entryPtrV7->pkts) > 1)
                           tcp->status &= ~(ARGUS_CON_ESTABLISHED);
                        break;
                  }

                  dsr += net->hdr.argus_dsrvl8.len;
                  argus->hdr.len += net->hdr.argus_dsrvl8.len;
               }
               break;
            }
            case ARGUS_TRANSPORT_INDEX: {
               if (input->addr.s_addr != 0) {
                  struct ArgusTransportStruct *trans = (struct ArgusTransportStruct *) dsr;
                  trans->hdr.type               = ARGUS_TRANSPORT_DSR;
                  trans->hdr.subtype            = ARGUS_SRC;
                  trans->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4;
                  trans->hdr.argus_dsrvl8.len   = 2;
                  trans->srcid.a_un.ipv4        = input->addr.s_addr;

                  dsr += trans->hdr.argus_dsrvl8.len;
                  argus->hdr.len += trans->hdr.argus_dsrvl8.len;
               }
               break;
            }
            case ARGUS_IPATTR_INDEX: {
               struct ArgusIPAttrStruct *attr = (struct ArgusIPAttrStruct *) dsr;
               attr->hdr.type               = ARGUS_IPATTR_DSR;
               attr->hdr.subtype            = 0;
               attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
               attr->hdr.argus_dsrvl8.len   = 2;
               attr->src.tos                = entryPtrV7->tos;
               attr->src.ttl                = 0;
               attr->src.ip_id              = 0;
               dsr += attr->hdr.argus_dsrvl8.len;
               argus->hdr.len += attr->hdr.argus_dsrvl8.len;
               break;
            }
         }
      }
   }

#ifdef _LITTLE_ENDIAN
   ArgusHtoN(argus);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV7 (0x%x) returning 0x%x\n", *ptr, argus);
#endif

   return(argus);
}


struct ArgusRecord *
ArgusParseCiscoRecordV8 (struct ArgusParserStruct *parser, struct ArgusInput *input, u_char **ptr, int *count)
{
   struct ArgusRecord *retn = NULL;

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV8 (%p, %p) returning %p\n", input, ptr, retn);
#endif
   return(retn);
}



typedef struct value {
   union {
      uint8_t   val8[16];
      uint16_t  val16[8];
      uint32_t  val32[4];
      uint64_t  val64[2];
      uint64_t val128[2];
   };
} value_t;


struct ArgusRecord *
ArgusParseCiscoRecordV9Data (struct ArgusParserStruct *parser, struct ArgusInput *input, struct ArgusQueueStruct *tqueue, u_char *ptr, int *cnt)
{
   struct ArgusCiscoTemplateStruct *templates = NULL;
   struct ArgusCiscoSourceStruct *src;
   struct ArgusRecord *retn = NULL;
   int ArgusParsingIPv6 = 0;

   u_char *tptr = ptr;

   if (tqueue != NULL) {
      int i, cnt = tqueue->count;
      for (i = 0; (i < cnt) && (templates == NULL); i++) {
         src = (struct ArgusCiscoSourceStruct *)ArgusPopQueue (tqueue, ARGUS_LOCK);
         if ((src->srcid == ArgusCiscoSrcId) && (src->saddr == ArgusCiscoSrcAddr))
            templates = src->templates;
         ArgusAddToQueue(tqueue, &src->qhdr, ARGUS_LOCK);
      }
   }

   if (templates == NULL)
      return(retn);

//  using the matching template, parse out a single record.  we need to update ptr and
//  len so that they represent marching through the buffer, parsing out the records.
//  

   {
      CiscoFlowEntryV9_t *cflow = (CiscoFlowEntryV9_t *) tptr;
      CiscoFlowTemplateHeaderV9_t *tHdr = NULL;
      CiscoFlowTemplateFlowEntryV9_t *tData;
      int flowset_id, length;

      flowset_id = ntohs(cflow->flowset_id);
      length = ntohs(cflow->length);

      if (length) {
#define ARGUS_TEMPLATE_TIMEOUT	1800

         if ((tHdr = (CiscoFlowTemplateHeaderV9_t *) templates[flowset_id].tHdr) != NULL) {
            if ((templates[flowset_id].lasttime.tv_sec + ARGUS_TEMPLATE_TIMEOUT) > parser->ArgusGlobalTime.tv_sec) {
               int i, count = tHdr->count, nflowPad = 3;
               struct ArgusRecordStruct *ns = &parser->argus;
               struct ArgusCanonRecord *canon = &parser->canon;
               u_char *sptr = (u_char *)(cflow + 1);
               u_char *eptr = sptr + (length - sizeof(*cflow));

// process an entire flow set

               while ((*cnt > 0) && (sptr < (eptr - nflowPad))) {
                  struct ArgusRecord *argus = ArgusNetFlowArgusRecord;
                  struct ArgusDSRHeader *dsr = (struct ArgusDSRHeader *) &ArgusNetFlowArgusRecordBuf[4];

                  bzero(canon, sizeof(*canon));
                  bzero(ns, sizeof(*ns));

                  tData = (CiscoFlowTemplateFlowEntryV9_t *)(tHdr + 1);

                  for (i = 0; i < count; i++) {
                     value_t value;

                     bzero(&value, sizeof(value));
                     
                     switch (tData->length) {
                        case  1: value.val8[0] = *sptr; break;
                        case  2: value.val16[0] = EXTRACT_16BITS(sptr); break;
                        case  4: value.val32[0] = EXTRACT_32BITS(sptr); break;
                        case  8: value.val64[0] = EXTRACT_64BITS(sptr); break;
                        case 16: bcopy(sptr, &value.val128, 16); break;
                     }
                     sptr += tData->length;

                     switch (tData->type) {
                        case k_CiscoV9InBytes: {
                           canon->metric.src.bytes = value.val32[0];
                           ns->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           ns->dsrs[ARGUS_METRIC_INDEX] = &canon->metric.hdr;
                           break;
                        }
                        case k_CiscoV9InPackets: {
                           canon->metric.src.pkts = value.val32[0];
                           ns->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           ns->dsrs[ARGUS_METRIC_INDEX] = &canon->metric.hdr;
                           break;
                        }
                        case k_CiscoV9Flows: {
                           break;
                        }
                        case k_CiscoV9InProtocol: {
                           canon->flow.flow_un.ipv6.ip_p = value.val8[0];
                           ns->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           ns->dsrs[ARGUS_FLOW_INDEX] = &canon->flow.hdr;
                           break;
                        }
                        case k_CiscoV9SrcTos: {
                           canon->attr.src.tos = (tData->length == 2) ? value.val16[0] : value.val8[0];
                           ns->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           ns->dsrs[ARGUS_IPATTR_INDEX] = &canon->attr.hdr;
                           break;
                        }
                        case k_CiscoV9TcpFlags: {
                           struct ArgusNetworkStruct *net = &canon->net;
                           struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;
                           unsigned char flags =  value.val8[0];

                           net->hdr.type                = ARGUS_NETWORK_DSR;
                           net->hdr.subtype             = ARGUS_TCP_STATUS;
                           net->hdr.argus_dsrvl8.len    = 3;
                           net->net_union.tcpstatus.src = flags;

                           if (flags & TH_RST)
                              tcp->status |= ARGUS_RESET;

                           if (flags & TH_FIN)
                              tcp->status |= ARGUS_FIN;

                           if ((flags & TH_ACK) || (flags & TH_PUSH) || (flags & TH_URG))
                              tcp->status |= ARGUS_CON_ESTABLISHED;

                           switch (flags & (TH_SYN|TH_ACK)) {
                              case (TH_SYN):
                                 tcp->status |= ARGUS_SAW_SYN;
                                 break;

                              case (TH_SYN|TH_ACK):
                                 break;
                           }
                           ns->dsrindex |= 1 << ARGUS_NETWORK_INDEX;
                           ns->dsrs[ARGUS_NETWORK_INDEX] = (void *)net;
                           break;
                        }
                        case k_CiscoV9L4SrcPort: {
                           canon->flow.flow_un.ipv6.sport = value.val16[0];
                           ns->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           ns->dsrs[ARGUS_FLOW_INDEX] = &canon->flow.hdr;
                           break;
                        }
                        case k_CiscoV9IpV4SrcAddr: {
                           canon->flow.flow_un.ipv6.ip_src[0] = value.val32[0];
                           ns->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           ns->dsrs[ARGUS_FLOW_INDEX] = &canon->flow.hdr;
                           break;
                        }
                        case k_CiscoV9SrcMask: {
                           uint32_t mask = 0xffffffff << (32 - value.val8[0]);
                           canon->flow.flow_un.ipv6.ip_src[3] = mask;
                           ns->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           ns->dsrs[ARGUS_FLOW_INDEX] = &canon->flow.hdr;
                           break;
                        }
                        case k_CiscoV9InputSnmp: {
                           break;
                        }
                        case k_CiscoV9L4DstPort: {
                           canon->flow.flow_un.ipv6.dport = value.val16[0];
                           ns->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           ns->dsrs[ARGUS_FLOW_INDEX] = &canon->flow.hdr;
                           break;
                        }
                        case k_CiscoV9IpV4DstAddr: {
                           canon->flow.flow_un.ipv6.ip_dst[0] = value.val32[0];
                           ns->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           ns->dsrs[ARGUS_FLOW_INDEX] = &canon->flow.hdr;
                           break;
                        }
                        case k_CiscoV9DstMask: {
                           uint32_t mask = 0xffffffff << (32 - value.val8[0]);
                           canon->flow.flow_un.ipv6.ip_dst[3] = mask;
                           ns->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           ns->dsrs[ARGUS_FLOW_INDEX] = &canon->flow.hdr;
                           break;
                        }
                        case k_CiscoV9OutputSnmp: {
                           break;
                        }
                        case k_CiscoV9IpV4NextHop: {
                           break;
                        }
                        case k_CiscoV9SrcAS: {
                           canon->asn.src_as = (tData->length == 2) ? value.val16[0] : value.val32[0];
                           ns->dsrindex |= 1 << ARGUS_ASN_INDEX;
                           ns->dsrs[ARGUS_ASN_INDEX] = &canon->asn.hdr;
                           break;
                        }
                        case k_CiscoV9DstAS: {
                           canon->asn.dst_as = (tData->length == 2) ? value.val16[0] : value.val32[0];
                           ns->dsrindex |= 1 << ARGUS_ASN_INDEX;
                           ns->dsrs[ARGUS_ASN_INDEX] = &canon->asn.hdr;
                           break;
                        }
                        case k_CiscoV9BgpIpV4NextHop: {
                           break;
                        }
                        case k_CiscoV9MulDstPkts: {
                           break;
                        }
                        case k_CiscoV9MulDstBytes: {
                           break;
                        }
                        case k_CiscoV9LastSwitched: {
                           CiscoFlowHeaderV9_t *ArgusNetFlow = (CiscoFlowHeaderV9_t *) ArgusNetFlowRecordHeader;
                           long timeval = (tData->length == 2) ? value.val16[0] : value.val32[0];
                           int secs, usecs;

                           secs  = ((timeval - ArgusNetFlow->sysUptime) / 1000);
                           usecs = ((timeval - ArgusNetFlow->sysUptime) % 1000) * 1000;

                           canon->time.src.end.tv_sec   = ArgusCiscoTvp->tv_sec  + secs;
                           if (usecs < 0) {
                              canon->time.src.end.tv_sec--;
                              usecs += 1000000;
                           }
                           canon->time.src.end.tv_usec  = ArgusCiscoTvp->tv_usec + usecs;

                           ns->dsrindex |= 1 << ARGUS_TIME_INDEX;
                           ns->dsrs[ARGUS_TIME_INDEX] = &canon->time.hdr;
                           break;
                        }
                        case k_CiscoV9FirstSwitched: {
                           CiscoFlowHeaderV9_t *ArgusNetFlow = (CiscoFlowHeaderV9_t *) ArgusNetFlowRecordHeader;
                           long timeval = (tData->length == 2) ? value.val16[0] : value.val32[0];
                           int secs, usecs;

                           secs  = ((timeval - ArgusNetFlow->sysUptime) / 1000);
                           usecs = ((timeval - ArgusNetFlow->sysUptime) % 1000) * 1000;

                           canon->time.src.start.tv_sec   = ArgusCiscoTvp->tv_sec  + secs;
                           if (usecs < 0) {
                              canon->time.src.start.tv_sec--;
                              usecs += 1000000;
                           }
                           canon->time.src.start.tv_usec  = ArgusCiscoTvp->tv_usec + usecs;

                           ns->dsrindex |= 1 << ARGUS_TIME_INDEX;
                           ns->dsrs[ARGUS_TIME_INDEX] = &canon->time.hdr;
                           break;
                        }
                        case k_CiscoV9OutBytes: {
/*
                           canon->metric.dst.bytes = value.val32[0];
                           ns->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           ns->dsrs[ARGUS_METRIC_INDEX] = &canon->metric.hdr;
*/
                           break;
                        }
                        case k_CiscoV9OutPkts: {
/*
                           canon->metric.dst.pkts = value.val32[0];
                           ns->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           ns->dsrs[ARGUS_METRIC_INDEX] = &canon->metric.hdr;
*/
                           break;
                        }
                        case k_CiscoV9MinPktLen: {
                           canon->psize.src.psizemin = value.val16[0];
                           ns->dsrindex |= 1 << ARGUS_PSIZE_INDEX;
                           ns->dsrs[ARGUS_PSIZE_INDEX] = &canon->psize.hdr;
                           break;
                        }
                        case k_CiscoV9MaxPktLen: {
                           canon->psize.src.psizemax = value.val16[0];
                           ns->dsrindex |= 1 << ARGUS_PSIZE_INDEX;
                           ns->dsrs[ARGUS_PSIZE_INDEX] = &canon->psize.hdr;
                           break;
                        }
                        case k_CiscoV9IpV6SrcAddr: {
                           bcopy (&value, &canon->flow.flow_un.ipv6.ip_src, 16);
                           ns->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           ns->dsrs[ARGUS_FLOW_INDEX] = &canon->flow.hdr;
                           ArgusParsingIPv6 = 1;
                           break;
                        }
                        case k_CiscoV9IpV6DstAddr: {
                           bcopy (&value, &canon->flow.flow_un.ipv6.ip_dst, 16);
                           ns->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           ns->dsrs[ARGUS_FLOW_INDEX] = &canon->flow.hdr;
                           ArgusParsingIPv6 = 1;
                           break;
                        }
                        case k_CiscoV9IPV6SrcMask: {
                           canon->flow.flow_un.ipv6.smask = value.val8[0];
                           break;
                        }
                        case k_CiscoV9IpV6DstMask: {
                           canon->flow.flow_un.ipv6.dmask = value.val8[0];
                           break;
                        }
                        case k_CiscoV9IpV6FlowLabel: {
                           break;
                        }
                        case k_CiscoV9IpV6IcmpType: {
                           canon->icmp.icmp_type = value.val8[0];
                           ns->dsrindex |= 1 << ARGUS_ICMP_INDEX;
                           ns->dsrs[ARGUS_ICMP_INDEX] = &canon->icmp.hdr;
                           break;
                        }
                        case k_CiscoV9IpV6MulIgmpType: {
                           break;
                        }
                        case k_CiscoV9IpV6SamplingInterval: {
                           break;
                        }
                        case k_CiscoV9IpV6SamplingAlgorithm: {
                           break;
                        }
                        case k_CiscoV9FlowActiveTimeout: {
                           break;
                        }
                        case k_CiscoV9FlowInactiveTimeout: {
                           break;
                        }
                        case k_CiscoV9EngineType: {
                           break;
                        }
                        case k_CiscoV9EngineID: {
                           break;
                        }
                        case k_CiscoV9TotalBytesExp: {
                           break;
                        }
                        case k_CiscoV9TotalPktsExp: {
                           break;
                        }
                        case k_CiscoV9TotalFlowsExp: {
                           break;
                        }
                        case k_CiscoV9MplsTopLabelType: {
                           break;
                        }
                        case k_CiscoV9MplsTopLabelIPAddr: {
                           break;
                        }
                        case k_CiscoV9FlowSamplerID: {
                           break;
                        }
                        case k_CiscoV9FlowSamplerMode: {
                           break;
                        }
                        case k_CiscoV9FlowSamplerRandomInt: {
                           break;
                        }

                        case k_CiscoV9MinTtl: {
                           canon->attr.src.ttl = value.val8[0];
                           ns->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           ns->dsrs[ARGUS_IPATTR_INDEX] = &canon->attr.hdr;
                           break;
                        }
                        case k_CiscoV9MaxTtl: {
                           canon->attr.src.ttl = value.val8[0];
                           ns->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           ns->dsrs[ARGUS_IPATTR_INDEX] = &canon->attr.hdr;
                           break;
                        }
                        case k_CiscoV9IPv4IpId: {
                           canon->attr.src.ip_id = value.val16[0];
                           ns->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           ns->dsrs[ARGUS_IPATTR_INDEX] = &canon->attr.hdr;
                           break;
                        }
                        case k_CiscoV9DstTos: {
                           canon->attr.dst.tos = (tData->length == 2) ? value.val16[0] : value.val8[0];
                           ns->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           ns->dsrs[ARGUS_IPATTR_INDEX] = &canon->attr.hdr;
                           break;
                        }
                        case k_CiscoV9SrcMac: {
                           ns->dsrindex |= 1 << ARGUS_MAC_INDEX;
                           ns->dsrs[ARGUS_MAC_INDEX] = &canon->mac.hdr;
                           break;
                        }
                        case k_CiscoV9DstMac: {
                           ns->dsrindex |= 1 << ARGUS_MAC_INDEX;
                           ns->dsrs[ARGUS_MAC_INDEX] = &canon->mac.hdr;
                           break;
                        }
                        case k_CiscoV9SrcVlan: {
                           canon->vlan.sid = value.val16[0];
                           ns->dsrindex |= 1 << ARGUS_VLAN_INDEX;
                           ns->dsrs[ARGUS_VLAN_INDEX] = &canon->vlan.hdr;
                           break;
                        }
                        case k_CiscoV9DstVlan: {
                           canon->vlan.did = value.val16[0];
                           ns->dsrindex |= 1 << ARGUS_VLAN_INDEX;
                           ns->dsrs[ARGUS_VLAN_INDEX] = &canon->vlan.hdr;
                           break;
                        }
                        case k_CiscoV9IpProtocolVersion: {
                           break;
                        }
                        case k_CiscoV9Direction: {
                           break;
                        }
                        case k_CiscoV9IpV6NextHop: {
                           break;
                        }
                        case k_CiscoV9BgpIpV6NextHop: {
                           break;
                        }
                        case k_CiscoV9IpV6OptionHeaders: {
                           break;
                        }
                        case k_CiscoV9MplsLabel1: {
                           break;
                        }
                        case k_CiscoV9MplsLabel2: {
                           break;
                        }
                        case k_CiscoV9MplsLabel3: {
                           break;
                        }
                        case k_CiscoV9MplsLabel4: {
                           break;
                        }
                        case k_CiscoV9MplsLabel5: {
                           break;
                        }
                        case k_CiscoV9MplsLabel6: {
                           break;
                        }
                        case k_CiscoV9MplsLabel7: {
                           break;
                        }
                        case k_CiscoV9MplsLabel8: {
                           break;
                        }
                        case k_CiscoV9MplsLabel9: {
                           break;
                        }
                        case k_CiscoV9MplsLabel10: {
                           break;
                        }
                        case k_CiscoV9InDstMac: {
                           ns->dsrindex |= 1 << ARGUS_MAC_INDEX;
                           ns->dsrs[ARGUS_MAC_INDEX] = &canon->mac.hdr;
                           break;
                        }
                        case k_CiscoV9OutSrcMac: {
                           ns->dsrindex |= 1 << ARGUS_MAC_INDEX;
                           ns->dsrs[ARGUS_MAC_INDEX] = &canon->mac.hdr;
                           break;
                        }
                        case k_CiscoV9IfName: {
                           break;
                        }
                        case k_CiscoV9IfDesc: {
                           break;
                        }
                        case k_CiscoV9SampleName: {
                           break;
                        }
                        case k_CiscoV9InPermanentBytes: {
                           canon->metric.src.bytes = value.val32[0];
                           ns->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           ns->dsrs[ARGUS_METRIC_INDEX] = &canon->metric.hdr;
                           break;
                        }
                        case k_CiscoV9InPermanentPkts: {
                           break;
                        }
                        case k_CiscoV9FragmentOffset: {
                           break;
                        }
                        case k_CiscoV9ForwardingStatus: {
                           break;
                        }
                        case k_CiscoV9PostDSCP: {
                           break;
                        }
                        case k_CiscoV9NatInsideGlobalAddr: {
                           break;
                        }
                        case k_CiscoV9NatOutsideGlobalAddr: {
                           break;
                        }
                        case k_CiscoV9postNatL4SrcPort: {
                           break;
                        }
                        case k_CiscoV9postNatL4DstPort: {
                           break;
                        }
                        case k_CiscoV9postNatEvent: {
                           break;
                        }
                        case k_CiscoV9IngressVRFID: {
                           break;
                        }
                        case k_CiscoV9ConnId: {
                           break;
                        }
                        case k_CiscoV9IcmpType: {
                           break;
                        }
                        case k_CiscoV9IcmpCode: {
                           break;
                        }
                       case k_CiscoV9IcmpTypeV6: {
                           struct ArgusICMPv6Flow *icmpv6Flow = &canon->flow.icmpv6_flow;
                           icmpv6Flow->type = value.val8[0];
                           ns->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           ns->dsrs[ARGUS_FLOW_INDEX] = &canon->flow.hdr;
                           break;
                        }
                        case k_CiscoV9IcmpCodeV6: {
                           struct ArgusICMPv6Flow *icmpv6Flow = &canon->flow.icmpv6_flow;
                           icmpv6Flow->code = value.val8[0];
                           ns->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           ns->dsrs[ARGUS_FLOW_INDEX] = &canon->flow.hdr;
                           break;
                        }
                        case k_CiscoEventTimeMilliSec: {
                           break;
                        }
                        case k_CiscoEventTimeMicroSec: {
                           break;
                        }
                        case k_CiscoEventTimeNanoSec:  {
                           break;
                        }
                     }
                     tData++;
                  }

                  {
                     struct timeval tdiffbuf, *tdiff = &tdiffbuf;
                     canon->hdr.type    = ARGUS_FAR | ARGUS_NETFLOW | ARGUS_VERSION;
                     canon->hdr.cause   = ARGUS_STATUS;
                     canon->hdr.len     = 1;

                     if (!(ns->dsrindex & (1 << ARGUS_TIME_INDEX))) {
                        struct ArgusTimeObject *time = &canon->time;
                        time->src.start.tv_sec   = ArgusCiscoTvp->tv_sec;
                        time->src.start.tv_usec  = ((long)(ArgusSysUptime)%1000) * 1000;
 
                        if (time->src.start.tv_usec >= 1000000) {
                           time->src.start.tv_sec++;
                           time->src.start.tv_usec -= 1000000;
                        }
                        time->src.end = time->src.start;
                        ns->dsrindex |= 1 << ARGUS_TIME_INDEX;
                        ns->dsrs[ARGUS_TIME_INDEX] = (void *)time;
                     }

                     if (ArgusDiffTime(&canon->time.src.end, &canon->time.src.start, tdiff) == 0) {
                        struct ArgusMetricStruct *metric = &canon->metric;

#define ARGUS_DEFAULT_RATE      1000000.0f
                        if (metric->src.pkts > 1) {
                           double dtime = (metric->src.pkts * 1.0) / ARGUS_DEFAULT_RATE;
                           double itime;
                           double ftime = modf(dtime, &itime);
                           canon->time.src.end.tv_sec  = canon->time.src.start.tv_sec  + (itime);
                           canon->time.src.end.tv_usec = canon->time.src.start.tv_usec + (ftime * 1000000);
                           if (canon->time.src.end.tv_usec >= 1000000) {
                              canon->time.src.end.tv_usec  -= 1000000;
                              canon->time.src.end.tv_sec++;
                           }
                        }
                     }

                     for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
                        if (ns->dsrindex & (1 << i)) {
                           switch(i) {
                              case ARGUS_FLOW_INDEX: {
                                 canon->flow.hdr.type              = ARGUS_FLOW_DSR;
                                 canon->flow.hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;

                                 if (ArgusParsingIPv6) {
                                    canon->flow.hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV6;
                                    canon->flow.hdr.argus_dsrvl8.len  = 11;
                                    ArgusParsingIPv6 = 0;

                                 } else {
                                    struct ArgusFlow tflow;
                                    bzero(&tflow, sizeof(tflow));
                                    tflow.flow_un.ip.ip_src = canon->flow.flow_un.ipv6.ip_src[0];
                                    tflow.flow_un.ip.ip_dst = canon->flow.flow_un.ipv6.ip_dst[0];
                                    tflow.flow_un.ip.ip_p   = canon->flow.flow_un.ipv6.ip_p;
                                    tflow.flow_un.ip.sport  = canon->flow.flow_un.ipv6.sport;
                                    tflow.flow_un.ip.dport  = canon->flow.flow_un.ipv6.dport;
                                    tflow.flow_un.ip.smask  = canon->flow.flow_un.ipv6.ip_src[3];
                                    tflow.flow_un.ip.dmask  = canon->flow.flow_un.ipv6.ip_dst[3];

                                    canon->flow.hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                                    canon->flow.hdr.argus_dsrvl8.len  = 5;
                                    bcopy(&tflow.flow_un.ip, &canon->flow.flow_un.ip, sizeof(tflow.flow_un.ip));
                                 }

                                 bcopy(&canon->flow, dsr, canon->flow.hdr.argus_dsrvl8.len * 4);
                                 dsr += canon->flow.hdr.argus_dsrvl8.len;
                                 canon->hdr.len += canon->flow.hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_TIME_INDEX: {
                                 struct ArgusTimeObject *time = &canon->time;
                                 time->hdr.type               = ARGUS_TIME_DSR;
                                 time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
                                 time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
                                 time->hdr.argus_dsrvl8.len   = 5;
                                 bcopy(time, dsr, time->hdr.argus_dsrvl8.len * 4);
                                 dsr += time->hdr.argus_dsrvl8.len;
                                 canon->hdr.len += time->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_ASN_INDEX: {
                                 struct ArgusAsnStruct *asn  = &canon->asn;
                                 asn->hdr.type               = ARGUS_ASN_DSR;
                                 asn->hdr.subtype            = 0;
                                 asn->hdr.argus_dsrvl8.qual  = 0;
                                 asn->hdr.argus_dsrvl8.len   = 3;
                                 bcopy(asn, dsr, asn->hdr.argus_dsrvl8.len * 4);
                                 dsr += asn->hdr.argus_dsrvl8.len;
                                 canon->hdr.len += asn->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_METRIC_INDEX: {
                                 struct ArgusMetricStruct *metric = &canon->metric;
                                 int pkts, bytes;

                                 metric->hdr.type              = ARGUS_METER_DSR;
                                 metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
                                 metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
                                 metric->hdr.argus_dsrvl8.len  = 3;

                                 pkts  = metric->src.pkts;
                                 bytes = metric->src.bytes;

                                 bcopy(&metric->hdr, dsr, 4);
                                 bcopy(&pkts,  dsr+1, 4);
                                 bcopy(&bytes, dsr+2, 4);

                                 dsr += metric->hdr.argus_dsrvl8.len;
                                 canon->hdr.len += metric->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_NETWORK_INDEX: {
                                 struct ArgusNetworkStruct *net = &canon->net;
                                 bcopy(net, dsr, net->hdr.argus_dsrvl8.len * 4);
                                 dsr += net->hdr.argus_dsrvl8.len;
                                 canon->hdr.len += net->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_MAC_INDEX: {
                                 struct ArgusMacStruct *mac = &canon->mac;
                                 mac->hdr.type              = ARGUS_MAC_DSR;
                                 mac->hdr.subtype           = 0;
                                 mac->hdr.argus_dsrvl8.len  = 5;
                                 bcopy(mac, dsr, mac->hdr.argus_dsrvl8.len * 4);
                                 dsr += mac->hdr.argus_dsrvl8.len;
                                 canon->hdr.len += mac->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_IPATTR_INDEX: {
                                 struct ArgusIPAttrStruct *attr = &canon->attr;
                                 attr->hdr.type               = ARGUS_IPATTR_DSR;
                                 attr->hdr.subtype            = 0;
                                 attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
                                 attr->hdr.argus_dsrvl8.len   = 2;
                                 bcopy(attr, dsr, attr->hdr.argus_dsrvl8.len * 4);
                                 dsr += attr->hdr.argus_dsrvl8.len;
                                 canon->hdr.len += attr->hdr.argus_dsrvl8.len;
                              }
                           }
                        }
                     }

                     bzero ((char *) dsr, 4); // clear out byte padding
                     bcopy(&canon->hdr, &argus->hdr, sizeof(canon->hdr));
#ifdef _LITTLE_ENDIAN
                     ArgusHtoN(argus);
#endif
                     ArgusHandleRecord (parser, input, argus, &ArgusParser->ArgusFilterCode);
#ifdef ARGUSDEBUG
                     ArgusDebug (3, "ArgusParseCiscoRecordV9Data (%p, %p, %p, %p, %d) new flow\n", parser, input, templates, sptr, *cnt);
#endif
                  }

                  ArgusParsingIPv6 = 0;
                  *cnt = *cnt - 1;
               }
               src->lasttime = parser->ArgusGlobalTime;

            } else {
               if (templates[flowset_id].tHdr != NULL) {
                  ArgusFree(templates[flowset_id].tHdr);
                  bzero(&templates[flowset_id], sizeof(struct ArgusCiscoTemplateStruct));
                  templates[flowset_id].tHdr = NULL;
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV9Data (%p, %p, %p, %p, %d) returning %p\n", parser, input, tqueue, ptr, *cnt, retn);
#endif
   return(retn);
}


struct ArgusRecord *ArgusParseCiscoRecordV9Template (struct ArgusParserStruct *, struct ArgusQueueStruct *, u_char *, int);
struct ArgusRecord *ArgusParseCiscoRecordV9OptionTemplate (struct ArgusParserStruct *, struct ArgusQueueStruct *, u_char *, int);


struct ArgusRecord *
ArgusParseCiscoRecordV9Template (struct ArgusParserStruct *parser, struct ArgusQueueStruct *tqueue, u_char *ptr, int len)
{
   struct ArgusCiscoTemplateStruct *templates = NULL;
   struct ArgusRecord *retn = NULL;
   struct ArgusCiscoSourceStruct *src;
   int i, done = 0;

   if (tqueue != NULL) {
      int cnt = tqueue->count;
      for (i = 0; (i < cnt) && (templates == NULL); i++) {
         src = (struct ArgusCiscoSourceStruct *)ArgusPopQueue (tqueue, ARGUS_LOCK);
         if ((src->srcid == ArgusCiscoSrcId) && (src->saddr == ArgusCiscoSrcAddr))
            templates = src->templates;
         ArgusAddToQueue(tqueue, &src->qhdr, ARGUS_LOCK);
      }
   }

   if (templates == NULL) {
      if ((src = (struct ArgusCiscoSourceStruct *)ArgusCalloc (1, sizeof(*src))) == NULL)
         ArgusLog(LOG_ERR, "ArgusParseCiscoRecordV9Template: ArgusCalloc(%d, %d) error %s\n", 1, sizeof(*src), strerror(errno));

      src->srcid = ArgusCiscoSrcId;
      src->saddr = ArgusCiscoSrcAddr;
      src->startime = parser->ArgusGlobalTime;
      src->lasttime = parser->ArgusGlobalTime;
      templates = src->templates;
      ArgusAddToQueue (tqueue, &src->qhdr, ARGUS_LOCK);
   }

   if (templates) {
      while (!done) {
         CiscoFlowTemplateHeaderV9_t *tHdr = (CiscoFlowTemplateHeaderV9_t *) ptr;
         CiscoFlowTemplateFlowEntryV9_t *tData = (CiscoFlowTemplateFlowEntryV9_t *)(tHdr + 1);
         CiscoFlowTemplateFlowEntryV9_t **dArray = NULL;
         short count = ntohs(tHdr->count);
         int slen = 0, protocol = 0;

         slen = (sizeof(*tData) * count) + sizeof(*tHdr);

         if ((slen > len) || (slen <= 0))
            break;

         tHdr->template_id = ntohs(tHdr->template_id);
         tHdr->count = count;

         if (templates[tHdr->template_id].tHdr != NULL) {
            ArgusFree(templates[tHdr->template_id].tHdr);
            templates[tHdr->template_id].tHdr =  NULL;
         }

         if ((dArray = ArgusCalloc(1, slen)) == NULL)
            ArgusLog(LOG_ERR, "ArgusCalloc(%d, %d) error %s\n", tHdr->count, sizeof(*tData), strerror(errno));

         for (i = 0; i < tHdr->count; i++) {
            tData->type   = ntohs(tData->type);
            tData->length = ntohs(tData->length);
            switch (tData->type) {
               case k_CiscoV9IpV4SrcAddr:
               case k_CiscoV9IpV4DstAddr:
                  protocol = 4;
                  break;
                  
               case k_CiscoV9IpV6SrcAddr: 
               case k_CiscoV9IpV6DstAddr: 
               case k_CiscoV9IPV6SrcMask: 
               case k_CiscoV9IpV6DstMask: 
               case k_CiscoV9IpV6FlowLabel: 
               case k_CiscoV9IpV6IcmpType: 
               case k_CiscoV9IpV6MulIgmpType: 
                  protocol = 6;
                  break;
            }
            tData++;
         }

         bcopy(tHdr, dArray, slen);
         templates[tHdr->template_id].tHdr = dArray;
         templates[tHdr->template_id].lasttime = parser->ArgusGlobalTime;
         templates[tHdr->template_id].status = protocol;

#ifdef ARGUSDEBUG
         ArgusDebug (5, "ArgusParseCiscoRecordV9Template (%p, %p, %p, %d) tHdr template id %d len %d\n", parser, templates, ptr, len, tHdr->template_id, tHdr->count);
#endif
         if ((len - slen) > (sizeof(*tData) + sizeof(*tHdr))) {
            ptr += slen;
            len -= slen;
         } else
            done = 1;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV9Template (%p, %p, %p, %d) returning %p\n", parser, templates, ptr, len, retn);
#endif
   return(retn);
}

struct ArgusRecord *
ArgusParseCiscoRecordV9OptionTemplate (struct ArgusParserStruct *parser, struct ArgusQueueStruct *tqueue, u_char *ptr, int len)
{
   struct ArgusCiscoTemplateStruct *templates = NULL;
   struct ArgusRecord *retn = NULL;
   struct ArgusCiscoSourceStruct *src;
   int i;

   if (tqueue != NULL) {
      int cnt = tqueue->count;
      for (i = 0; (i < cnt) && (templates == NULL); i++) {
         src = (struct ArgusCiscoSourceStruct *)ArgusPopQueue (tqueue, ARGUS_LOCK);
         if ((src->srcid == ArgusCiscoSrcId) && (src->saddr == ArgusCiscoSrcAddr))
            templates = src->templates;
         ArgusAddToQueue(tqueue, &src->qhdr, ARGUS_LOCK);
      }
   }

   if (templates) {
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV9OptionTemplate (%p, %p) returning %p\n", parser, ptr, retn);
#endif
   return(retn);
}



struct ArgusRecord *
ArgusParseCiscoRecordV9 (struct ArgusParserStruct *parser, struct ArgusInput *input, u_char **ptr, int *count)
{
   CiscoFlowEntryV9_t  *entryPtrV9 = (CiscoFlowEntryV9_t *) *ptr;
   struct ArgusRecord *retn = NULL;
   int flowset_id, flowset_len;

// OK, so we've got a pointer to a v9 record.  parse it and move on.
// with the ArgusParseCisco... routine moving the ptr.

   flowset_id  = ntohs(entryPtrV9->flowset_id);
   flowset_len = ntohs(entryPtrV9->length);

   if (flowset_len > 0) {
      switch (flowset_id) {
         case k_CiscoV9TemplateFlowsetId: {
            ArgusParseCiscoRecordV9Template(parser, ArgusTemplateQueue, (u_char *)(entryPtrV9 + 1), (flowset_len - sizeof(*entryPtrV9)));
            break;
         }

         case k_CiscoV9OptionsFlowsetId: {
            ArgusParseCiscoRecordV9OptionTemplate(parser, ArgusTemplateQueue, (u_char *)(entryPtrV9 + 1), (flowset_len - sizeof(*entryPtrV9)));
            break;
         }

         default: {
            if (flowset_id >= k_CiscoV9MinRecordFlowsetId) {
               retn = ArgusParseCiscoRecordV9Data(parser, input, ArgusTemplateQueue, *ptr, count);
               break;
            }
         }
      }

      *ptr += flowset_len;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV9 (%p, %p) returning %p\n", input, ptr, retn);
#endif
   return(retn);
}


struct ArgusRecord *
ArgusParseCiscoRecord (struct ArgusParserStruct *parser, struct ArgusInput *input, u_char **ptr, int *count)
{
   struct ArgusRecord *argus = ArgusNetFlowArgusRecord;
   unsigned short *sptr = (unsigned short *) *ptr;

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecord (0x%x) version %h\n", *ptr, *sptr);
#endif

   switch (*sptr) {
      case Version1: {
/*
         CiscoFlowHeaderV1_t *hdrPtrV1   = (CiscoFlowHeaderV1_t *) *ptr;
         CiscoFlowEntryV1_t  *entryPtrV1 = (CiscoFlowEntryV1_t *) (hdrPtrV1 + 1);
*/

         bzero ((char *) argus, sizeof (*argus));
         argus->hdr.type    = ARGUS_NETFLOW | ARGUS_VERSION;
         argus->hdr.cause   = ARGUS_STATUS;
         argus->hdr.len     = sizeof(argus->hdr) + sizeof(argus->argus_far);
/*
         argus->ahdr.status |= ETHERTYPE_IP;

         argus->argus_far.type   = ARGUS_FAR;
         argus->argus_far.length = sizeof(argus->argus_far);

         if (hdrPtrV1) {
            long time; 
            time = ntohl(entryPtrV1->first);
            argus->argus_far.time.start.tv_sec  = (time - (long)hdrPtrV1->sysUptime)/1000;
            argus->argus_far.time.start.tv_sec += hdrPtrV1->unix_secs;
      
            argus->argus_far.time.start.tv_usec = ((time - (long)hdrPtrV1->sysUptime)%1000) * 1000;
            argus->argus_far.time.start.tv_usec += hdrPtrV1->unix_nsecs/1000;

            if (argus->argus_far.time.start.tv_usec >= 1000000) {
               argus->argus_far.time.start.tv_sec++;
               argus->argus_far.time.start.tv_usec -= 1000000;
            }
            if (argus->argus_far.time.start.tv_usec < 0) {
               argus->argus_far.time.start.tv_sec--;
               argus->argus_far.time.start.tv_usec += 1000000;
            }

            time = ntohl(entryPtrV1->last);
            argus->argus_far.time.last.tv_sec  = (time - (long)hdrPtrV1->sysUptime)/1000;
            argus->argus_far.time.last.tv_sec += hdrPtrV1->unix_secs;
      
            argus->argus_far.time.last.tv_usec = ((time - (long)hdrPtrV1->sysUptime)%1000) * 1000;
            argus->argus_far.time.last.tv_usec += hdrPtrV1->unix_nsecs/1000;

            if (argus->argus_far.time.last.tv_usec >= 1000000) {
               argus->argus_far.time.last.tv_sec++;
               argus->argus_far.time.last.tv_usec -= 1000000;
            }
            if (argus->argus_far.time.last.tv_usec < 0) {
               argus->argus_far.time.last.tv_sec--;
               argus->argus_far.time.last.tv_usec += 1000000;
            }

            argus->argus_far.time.start.tv_usec = (argus->argus_far.time.start.tv_usec / 1000) * 1000;
            argus->argus_far.time.last.tv_usec  = (argus->argus_far.time.last.tv_usec / 1000) * 1000;
         }

         argus->argus_far.flow.ip_flow.ip_src = ntohl(entryPtrV1->srcaddr);
         argus->argus_far.flow.ip_flow.ip_dst = ntohl(entryPtrV1->dstaddr);
         argus->argus_far.flow.ip_flow.sport  = ntohs(entryPtrV1->srcport);
         argus->argus_far.flow.ip_flow.dport  = ntohs(entryPtrV1->dstport);
         argus->argus_far.flow.ip_flow.ip_p   = entryPtrV1->prot;
         argus->argus_far.attr_ip.stos        = entryPtrV1->tos;
         argus->argus_far.src.count    = ntohl(entryPtrV1->pkts);
         argus->argus_far.src.bytes    = ntohl(entryPtrV1->bytes);
*/

#ifdef _LITTLE_ENDIAN
         ArgusHtoN(argus);
#endif
         break;
      }

      case Version5: {
/*
         CiscoFlowHeaderV5_t *hdrPtrV5   = (CiscoFlowHeaderV5_t *) ptr;
         CiscoFlowEntryV5_t  *entryPtrV5 = (CiscoFlowEntryV5_t *) (hdrPtrV5 + 1);
*/

         bzero ((char *) argus, sizeof (*argus));
         argus->hdr.type    = ARGUS_NETFLOW | ARGUS_VERSION;
         argus->hdr.cause   = ARGUS_STATUS;
         argus->hdr.len     = sizeof(argus->hdr) + sizeof(argus->argus_far);
/*
         argus->ahdr.status |= ETHERTYPE_IP; 
   
         argus->argus_far.type   = ARGUS_FAR;
         argus->argus_far.length = sizeof(argus->argus_far);

         if (hdrPtrV5) {
            long time;
            time = ntohl(entryPtrV5->first);
            argus->argus_far.time.start.tv_sec  = (time - (long)hdrPtrV5->sysUptime)/1000;
            argus->argus_far.time.start.tv_sec += hdrPtrV5->unix_secs;
      
            argus->argus_far.time.start.tv_usec = ((time - (long)hdrPtrV5->sysUptime)%1000) * 1000;
            argus->argus_far.time.start.tv_usec += hdrPtrV5->unix_nsecs/1000;

            if (argus->argus_far.time.start.tv_usec >= 1000000) {
               argus->argus_far.time.start.tv_sec++;
               argus->argus_far.time.start.tv_usec -= 1000000;
            }
            if (argus->argus_far.time.start.tv_usec < 0) {
               argus->argus_far.time.start.tv_sec--;
               argus->argus_far.time.start.tv_usec += 1000000;
            }
      
            time = ntohl(entryPtrV5->last);
            argus->argus_far.time.last.tv_sec  = (time - (long)hdrPtrV5->sysUptime)/1000;
            argus->argus_far.time.last.tv_sec += hdrPtrV5->unix_secs;
      
            argus->argus_far.time.last.tv_usec = ((time - (long)hdrPtrV5->sysUptime)%1000) * 1000;
            argus->argus_far.time.last.tv_usec += hdrPtrV5->unix_nsecs/1000;

            if (argus->argus_far.time.last.tv_usec >= 1000000) {
               argus->argus_far.time.last.tv_sec++;
               argus->argus_far.time.last.tv_usec -= 1000000;
            }
            if (argus->argus_far.time.last.tv_usec < 0) {
               argus->argus_far.time.last.tv_sec--;
               argus->argus_far.time.last.tv_usec += 1000000;
            }

            argus->argus_far.time.start.tv_usec = (argus->argus_far.time.start.tv_usec / 1000) * 1000;
            argus->argus_far.time.last.tv_usec  = (argus->argus_far.time.last.tv_usec / 1000) * 1000;
         }

         argus->argus_far.flow.ip_flow.ip_src = ntohl(entryPtrV5->srcaddr);
         argus->argus_far.flow.ip_flow.ip_dst = ntohl(entryPtrV5->dstaddr);
         argus->argus_far.flow.ip_flow.sport  = ntohs(entryPtrV5->srcport);
         argus->argus_far.flow.ip_flow.dport  = ntohs(entryPtrV5->dstport);
         argus->argus_far.flow.ip_flow.ip_p   = entryPtrV5->prot;
         argus->argus_far.attr_ip.stos        = entryPtrV5->tos;
         argus->argus_far.src.count    = ntohl(entryPtrV5->pkts);
         argus->argus_far.src.bytes    = ntohl(entryPtrV5->bytes);
         argus->argus_far.src.appbytes = 0;
*/

#ifdef _LITTLE_ENDIAN
         ArgusHtoN(argus);
#endif
         break;
      }

      case Version6: {
/*
         CiscoFlowHeaderV6_t *hdrPtrV6   = (CiscoFlowHeaderV6_t *) ptr;
         CiscoFlowEntryV6_t  *entryPtrV6 = (CiscoFlowEntryV6_t *) (hdrPtrV6 + 1);
*/

         bzero ((char *) argus, sizeof (*argus));
         argus->hdr.type    = ARGUS_NETFLOW | ARGUS_VERSION;
         argus->hdr.cause   = ARGUS_STATUS;
         argus->hdr.len     = sizeof(argus->hdr) + sizeof(argus->argus_far);
/*
         argus->ahdr.status |= ETHERTYPE_IP; 
   
         argus->argus_far.type   = ARGUS_FAR;
         argus->argus_far.length = sizeof(argus->argus_far);

         if (hdrPtrV6) {
            long time;
            time = ntohl(entryPtrV6->first);
            argus->argus_far.time.start.tv_sec  = (time - (long)hdrPtrV6->sysUptime)/1000;
            argus->argus_far.time.start.tv_sec += hdrPtrV6->unix_secs;
      
            argus->argus_far.time.start.tv_usec = ((time - (long)hdrPtrV6->sysUptime)%1000) * 1000;
            argus->argus_far.time.start.tv_usec += hdrPtrV6->unix_nsecs/1000;
      
            if (argus->argus_far.time.start.tv_usec >= 1000000) {
               argus->argus_far.time.start.tv_sec++;
               argus->argus_far.time.start.tv_usec -= 1000000;
            }
            if (argus->argus_far.time.start.tv_usec < 0) {
               argus->argus_far.time.start.tv_sec--;
               argus->argus_far.time.start.tv_usec += 1000000;
            }

            time = ntohl(entryPtrV6->last);
            argus->argus_far.time.last.tv_sec  = (time - (long)hdrPtrV6->sysUptime)/1000;
            argus->argus_far.time.last.tv_sec += hdrPtrV6->unix_secs;
      
            argus->argus_far.time.last.tv_usec = ((time - (long)hdrPtrV6->sysUptime)%1000) * 1000;
            argus->argus_far.time.last.tv_usec += hdrPtrV6->unix_nsecs/1000;

            if (argus->argus_far.time.last.tv_usec >= 1000000) {
               argus->argus_far.time.last.tv_sec++;
               argus->argus_far.time.last.tv_usec -= 1000000;
            }
            if (argus->argus_far.time.last.tv_usec < 0) {
               argus->argus_far.time.last.tv_sec--;
               argus->argus_far.time.last.tv_usec += 1000000;
            }

            argus->argus_far.time.start.tv_usec = (argus->argus_far.time.start.tv_usec / 1000) * 1000;
            argus->argus_far.time.last.tv_usec  = (argus->argus_far.time.last.tv_usec / 1000) * 1000;
         }

         argus->argus_far.flow.ip_flow.ip_src = ntohl(entryPtrV6->srcaddr);
         argus->argus_far.flow.ip_flow.ip_dst = ntohl(entryPtrV6->dstaddr);
         argus->argus_far.flow.ip_flow.sport  = ntohs(entryPtrV6->srcport);
         argus->argus_far.flow.ip_flow.dport  = ntohs(entryPtrV6->dstport);
         argus->argus_far.flow.ip_flow.ip_p   = entryPtrV6->prot;
         argus->argus_far.attr_ip.stos        = entryPtrV6->tos;
         argus->argus_far.src.count    = ntohl(entryPtrV6->pkts);
         argus->argus_far.src.bytes    = ntohl(entryPtrV6->bytes);
         argus->argus_far.src.appbytes = 0;
*/

#ifdef _LITTLE_ENDIAN
         ArgusHtoN(argus);
#endif
         break;
      }

      case Version8: {
         break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecord (0x%x) returning 0x%x\n", *ptr, argus);
#endif

   return (argus);
}


struct ArgusRecord *
ArgusNetFlowCallRecord (struct ArgusParserStruct *parser, struct ArgusInput *input, u_char **ptr, int *count)
{
   struct ArgusRecord *argus = ArgusNetFlowArgusRecord;
   BinaryRecord_CallRecord_V1 *call = (BinaryRecord_CallRecord_V1 *) *ptr;
   struct ArgusDSRHeader *dsr = (struct ArgusDSRHeader *) &ArgusNetFlowArgusRecordBuf[4];
   int i;

   if (*ptr) {
      bzero ((char *) argus, sizeof (*argus));
      argus->hdr.type    = ARGUS_NETFLOW | ARGUS_VERSION;
      argus->hdr.cause   = ARGUS_STATUS;
      argus->hdr.len     = 1;

      for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
         switch (i) {
            case ARGUS_FLOW_INDEX: {
               struct ArgusFlow *flow = (struct ArgusFlow *) dsr;
               flow->hdr.type              = ARGUS_FLOW_DSR;
               flow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
               flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
               flow->hdr.argus_dsrvl8.len  = 5;
               flow->ip_flow.ip_src = ntohl(call->srcaddr);
               flow->ip_flow.ip_dst = ntohl(call->dstaddr);

               switch (flow->ip_flow.ip_p = call->prot) {
                  case IPPROTO_TCP:
                  case IPPROTO_UDP:
                     flow->ip_flow.sport  = ntohs(call->srcport);
                     flow->ip_flow.dport  = ntohs(call->dstport);
                  break;
         
                  case IPPROTO_ICMP:
                     flow->icmp_flow.type  = ((char *)&call->dstport)[0];
                     flow->icmp_flow.code  = ((char *)&call->dstport)[1];
                  break;
               }
               dsr += flow->hdr.argus_dsrvl8.len;
               argus->hdr.len += flow->hdr.argus_dsrvl8.len;
               break;
            }
            case ARGUS_TIME_INDEX: {
               struct ArgusTimeObject *time = (struct ArgusTimeObject *) dsr;

               time->hdr.type               = ARGUS_TIME_DSR;
               time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
               time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
               time->hdr.argus_dsrvl8.len   = 5;               

               time->src.start.tv_sec  = ntohl(call->starttime);
               time->src.end.tv_sec  = ntohl(call->endtime);

               time->src.end.tv_usec = ntohl(call->activetime) % 1000000;
               time->src.end.tv_sec += ntohl(call->activetime) / 1000000;

               time->src.start.tv_usec = (time->src.start.tv_usec / 1000) * 1000;
               time->src.end.tv_usec  = (time->src.end.tv_usec / 1000) * 1000;
               dsr += time->hdr.argus_dsrvl8.len;
               argus->hdr.len += time->hdr.argus_dsrvl8.len;
               break;
            }
            case ARGUS_TRANSPORT_INDEX: {
               if (input->addr.s_addr != 0) {
                  struct ArgusTransportStruct *trans = (struct ArgusTransportStruct *) dsr;
                  trans->hdr.type               = ARGUS_TRANSPORT_DSR;
                  trans->hdr.subtype            = ARGUS_SRC;
                  trans->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4;
                  trans->hdr.argus_dsrvl8.len   = 2;
                  trans->srcid.a_un.ipv4        = input->addr.s_addr;

                  dsr += trans->hdr.argus_dsrvl8.len;
                  argus->hdr.len += trans->hdr.argus_dsrvl8.len;
               }
               break;
            }
            case ARGUS_IPATTR_INDEX: {
               struct ArgusIPAttrStruct *attr = (struct ArgusIPAttrStruct *) dsr;
               attr->hdr.type               = ARGUS_IPATTR_DSR;
               attr->hdr.subtype            = 0;
               attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
               attr->hdr.argus_dsrvl8.len   = 2;
               attr->src.tos                = call->tos; 
               attr->src.ttl                = 0;
               attr->src.ip_id              = 0;
               dsr += attr->hdr.argus_dsrvl8.len;
               argus->hdr.len += attr->hdr.argus_dsrvl8.len;
               break;
            }
            case ARGUS_METRIC_INDEX: {
               struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *) dsr;
               uint32_t val;
                                    
               metric->hdr.type              = ARGUS_METER_DSR;
               metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
               metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_LONGLONG;
               metric->hdr.argus_dsrvl8.len  = 5;
               val = ntohl(call->pkts);
               metric->src.pkts = val;
               val = ntohl(call->octets);
               metric->src.bytes = val;
               dsr += metric->hdr.argus_dsrvl8.len;
               argus->hdr.len += metric->hdr.argus_dsrvl8.len;
               break;
            }
         }
      }

#ifdef _LITTLE_ENDIAN
      ArgusHtoN(argus);
#endif
   }
   
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusNetFlowCallRecord (0x%x) returns 0x%x\n", *ptr, argus);
#endif

   return (argus);
}


struct ArgusRecord *
ArgusNetFlowDetailInt (struct ArgusParserStruct *parser, struct ArgusInput *input, u_char **ptr, int *count)
{
   struct ArgusRecord *argus = ArgusNetFlowArgusRecord;
// BinaryRecord_DetailInterface_V1  *dint = (BinaryRecord_DetailInterface_V1 *) *ptr;

   if (*ptr) {
//    dint = NULL;
      bzero ((char *) argus, sizeof (*argus));
   }


#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusNetFlowDetailInt (0x%x) returns 0x%x\n", *ptr, argus);
#endif

   return (argus);
}


ArgusNetFlowHandler ArgusLookUpNetFlow(struct ArgusInput *, int);


struct ArgusNetFlowParsers {
   int type, size;
   ArgusNetFlowHandler proc;
};

struct ArgusNetFlowParsers ArgusNetFlowParsers [] = {
   { NetflowSourceNode, 0, NULL },
   { NetflowDestNode, 0, NULL },
   { NetflowHostMatrix, 0, NULL },
   { NetflowSourcePort, 0, NULL },
   { NetflowDestPort, 0, NULL },
   { NetflowProtocol, 0, NULL },
   { NetflowDetailDestNode, 0, NULL },
   { NetflowDetailHostMatrix, 0, NULL },
   { NetflowDetailInterface, sizeof(BinaryRecord_DetailInterface_V1), ArgusNetFlowDetailInt },
   { NetflowCallRecord, sizeof(BinaryRecord_CallRecord_V1), ArgusNetFlowCallRecord },
   { NetflowASMatrix, 0, NULL },
   { NetflowNetMatrix, 0, NULL },
   { NetflowDetailSourceNode, 0, NULL },
   { NetflowDetailASMatrix, 0, NULL },
   { NetflowASHostMatrix, 0, NULL },
   { NetflowHostMatrixInterface, 0, NULL },
   { NetflowDetailCallRecord, 0, NULL },
   { NetflowRouterAS, 0, NULL },
   { NetflowRouterProtoPort, 0, NULL },
   { NetflowRouterSrcPrefix, 0, NULL },
   { NetflowRouterDstPrefix, 0, NULL },
   { NetflowRouterPrefix, 0, NULL },
   { -1, 0, NULL },
};
   

ArgusNetFlowHandler 
ArgusLookUpNetFlow(struct ArgusInput *input, int type)
{
   ArgusNetFlowHandler retn = NULL;
   struct ArgusNetFlowParsers *p = ArgusNetFlowParsers;

   do {
      if (type == p->type) {
         retn = p->proc;
         input->ArgusReadSize = p->size;
         input->ArgusReadSocketSize = p->size;
         break;
      }
      p++;
   } while (p->type != -1);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusLookUpNetFlow (0x%x, %d) returning 0x%x\n", input, type, retn);
#endif

   return (retn);
}

#if defined(ARGUS_FLOWTOOLS)

#include "ftlib.h"
struct ArgusRecord *ArgusParseFlowToolsRecord (struct ArgusParserStruct *, struct ArgusInput *, struct fts3rec_all *);

struct ArgusRecord *
ArgusParseFlowToolsRecord (struct ArgusParserStruct *parser, struct ArgusInput *input, struct fts3rec_all *cur)
{
   struct ArgusRecord *argus = ArgusNetFlowArgusRecord;
   struct ArgusDSRHeader *dsr = (struct ArgusDSRHeader *) &ArgusNetFlowArgusRecordBuf[4];
   int i;

   bzero ((char *) argus, sizeof(ArgusNetFlowArgusRecordBuf));
   argus->hdr.type    = ARGUS_NETFLOW | ARGUS_VERSION;
   argus->hdr.cause   = ARGUS_STATUS;
   argus->hdr.len     = 1;

   for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
      switch (i) {
         case ARGUS_FLOW_INDEX: {
            if ((cur->srcaddr != NULL) && (cur->dstaddr != NULL)) {
               struct ArgusFlow *flow = (struct ArgusFlow *) dsr;
               flow->hdr.type              = ARGUS_FLOW_DSR;
               flow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
               flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
               flow->hdr.argus_dsrvl8.len  = 5;
               flow->ip_flow.ip_src = *cur->srcaddr;
               flow->ip_flow.ip_dst = *cur->dstaddr;

               if (cur->src_mask != NULL) {
                  flow->hdr.argus_dsrvl8.qual |= ARGUS_MASKLEN;
                  flow->ip_flow.smask = *cur->src_mask;
               }
               if (cur->dst_mask != NULL) {
                  flow->hdr.argus_dsrvl8.qual |= ARGUS_MASKLEN;
                  flow->ip_flow.dmask = *cur->dst_mask;
               }

               if (cur->prot != NULL) {
                  switch (flow->ip_flow.ip_p = *cur->prot) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP:
                        flow->ip_flow.sport  = *cur->srcport;
                        flow->ip_flow.dport  = *cur->dstport;
                        break;
         
                     case IPPROTO_ICMP:
                        flow->icmp_flow.type  = *cur->srcport;
                        flow->icmp_flow.code  = *cur->dstport;
                        break;
                  }
               }
               dsr += flow->hdr.argus_dsrvl8.len;
               argus->hdr.len += flow->hdr.argus_dsrvl8.len;
               break;
            }
         }

         case ARGUS_TIME_INDEX: {
            struct ArgusTimeObject *time = (struct ArgusTimeObject *) dsr;

            if (cur->unix_secs != NULL) {
               time->hdr.type               = ARGUS_TIME_DSR;
               time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE | ARGUS_TIME_SRC_START | ARGUS_TIME_SRC_END;
               time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_NANOSECONDS;
               time->hdr.argus_dsrvl8.len   = 5;               

               time->src.start.tv_sec  = *cur->unix_secs;
               time->src.start.tv_usec = *cur->unix_nsecs;

               if ((cur->Last != NULL) && (cur->First != NULL)) {
                  int   dur = *cur->Last - *cur->First;
                  int  secs = dur / 1000;
                  int msecs = dur % 1000;

                  time->src.end = time->src.start;
                  time->src.end.tv_sec  += secs;
                  time->src.end.tv_usec += (msecs * 1000000);
                  if (time->src.end.tv_usec > 1000000000) {
                     time->src.end.tv_sec++;
                     time->src.end.tv_usec -= 1000000000;
                  }
               }

               dsr += time->hdr.argus_dsrvl8.len;
               argus->hdr.len += time->hdr.argus_dsrvl8.len;
            }
            break;
         }

         case ARGUS_TRANSPORT_INDEX: {
            if (cur->exaddr != NULL) {
               struct ArgusTransportStruct *trans = (struct ArgusTransportStruct *) dsr;
               trans->hdr.type               = ARGUS_TRANSPORT_DSR;
               trans->hdr.subtype            = ARGUS_SRC;
               trans->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4;
               trans->hdr.argus_dsrvl8.len   = 2;
               trans->srcid.a_un.ipv4        = *cur->exaddr;

               dsr += trans->hdr.argus_dsrvl8.len;
               argus->hdr.len += trans->hdr.argus_dsrvl8.len;
            }
            break;
         }

         case ARGUS_IPATTR_INDEX: {
            if (cur->tos != NULL) {
               struct ArgusIPAttrStruct *attr = (struct ArgusIPAttrStruct *) dsr;
               attr->hdr.type               = ARGUS_IPATTR_DSR;
               attr->hdr.subtype            = 0;
               attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
               attr->hdr.argus_dsrvl8.len   = 2;
               attr->src.tos                = *cur->tos; 
               attr->src.ttl                = 0;
               attr->src.ip_id              = 0;
               dsr += attr->hdr.argus_dsrvl8.len;
               argus->hdr.len += attr->hdr.argus_dsrvl8.len;
               break;
            }
         }

         case ARGUS_ASN_INDEX: {
            if ((cur->src_as != NULL) || (cur->dst_as != NULL)) {
               struct ArgusAsnStruct *asn  = (struct ArgusAsnStruct *) dsr;
               asn->hdr.type               = ARGUS_ASN_DSR;
               asn->hdr.subtype            = 0;
               asn->hdr.argus_dsrvl8.qual  = 0;
               asn->hdr.argus_dsrvl8.len   = 3;
               if (cur->src_as != NULL)
                  asn->src_as              = *cur->src_as;
               if (cur->dst_as != NULL)
                  asn->dst_as              = *cur->dst_as;
               dsr += asn->hdr.argus_dsrvl8.len;
               argus->hdr.len += asn->hdr.argus_dsrvl8.len;
               break;
            }
         }

            case ARGUS_METRIC_INDEX: {
               if ((cur->dPkts != NULL) && (cur->dOctets != NULL)) {
               struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *) dsr;
               uint32_t val;
                                    
               metric->hdr.type              = ARGUS_METER_DSR;
               metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
               metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_LONGLONG;
               metric->hdr.argus_dsrvl8.len  = 5;
               val = *cur->dPkts;
               metric->src.pkts = val;
               val = *cur->dOctets;
               metric->src.bytes = val;
               dsr += metric->hdr.argus_dsrvl8.len;
               argus->hdr.len += metric->hdr.argus_dsrvl8.len;
               break;
            }

            case ARGUS_NETWORK_INDEX: {
               if ((cur->prot != NULL) && (*cur->prot == IPPROTO_TCP)) {
                  if ((cur->tcp_flags != NULL) && (*cur->tcp_flags != 0)) {
                     struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) dsr;
                     net->hdr.type              = ARGUS_NETWORK_DSR;
                     net->hdr.subtype           = ARGUS_TCP_STATUS;
                     net->hdr.argus_dsrvl8.len  = 3;
                     net->net_union.tcpstatus.src = *cur->tcp_flags;
                     dsr += net->hdr.argus_dsrvl8.len;
                     argus->hdr.len += net->hdr.argus_dsrvl8.len;
                  }
               }
            }
         }
      }
   }

#ifdef _LITTLE_ENDIAN
   ArgusHtoN(argus);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusParseFlowToolsRecord (%p, %p, %p) returning %p\n", parser, input, cur, argus);
#endif
   return (argus);
}
#endif



#include <argus/sflow.h>

static void SFLengthCheck(SFSample *, u_char *, int);

void SFParseFlowSample_header(SFSample *);
void SFParseFlowSample_ethernet(SFSample *);
void SFParseFlowSample_IPv4(SFSample *);
void SFParseFlowSample_IPv6(SFSample *);
void SFParseFlowSample_memcache(SFSample *);
void SFParseFlowSample_http(SFSample *);
void SFParseFlowSample_CAL(SFSample *);
void SFParseExtendedSwitch(SFSample *);
void SFParseExtendedRouter(SFSample *);
void SFParseExtendedGateway(SFSample *);
void SFParseExtendedUser(SFSample *);
void SFParseExtendedUrl(SFSample *);
void SFParseExtendedMpls(SFSample *);
void SFParseExtendedNat(SFSample *);
void SFParseExtendedMplsTunnel(SFSample *);
void SFParseExtendedMplsVC(SFSample *);
void SFParseExtendedMplsFTN(SFSample *);
void SFParseExtendedMplsLDP_FEC(SFSample *);
void SFParseExtendedVlanTunnel(SFSample *);
void SFParseExtendedWifiPayload(SFSample *);
void SFParseExtendedWifiRx(SFSample *);
void SFParseExtendedWifiTx(SFSample *);
void SFParseExtendedSocket4(SFSample *);
void SFParseExtendedSocket6(SFSample *);

void SFParseCounters_generic (SFSample *sptr);
void SFParseCounters_ethernet (SFSample *sptr);
void SFParseCounters_tokenring (SFSample *sptr);
void SFParseCounters_vg (SFSample *sptr);
void SFParseCounters_vlan (SFSample *sptr);
void SFParseCounters_80211 (SFSample *sptr);
void SFParseCounters_processor (SFSample *sptr);
void SFParseCounters_radio (SFSample *sptr);
void SFParseCounters_host_hid (SFSample *sptr);
void SFParseCounters_adaptors (SFSample *sptr);
void SFParseCounters_host_parent (SFSample *sptr);
void SFParseCounters_host_cpu (SFSample *sptr);
void SFParseCounters_host_mem (SFSample *sptr);
void SFParseCounters_host_dsk (SFSample *sptr);
void SFParseCounters_host_nio (SFSample *sptr);
void SFParseCounters_host_vnode (SFSample *sptr);
void SFParseCounters_host_vcpu (SFSample *sptr);
void SFParseCounters_host_vmem (SFSample *sptr);
void SFParseCounters_host_vdsk (SFSample *sptr);
void SFParseCounters_host_vnio (SFSample *sptr);
void SFParseCounters_memcache (SFSample *sptr);
void SFParseCounters_http (SFSample *sptr);
void SFParseCounters_CAL (SFSample *sptr);

static void SFDecodeLinkLayer(SFSample *);
static void SFDecode80211MAC(SFSample *);

static void SFDecodeIPV4(SFSample *);
static void SFDecodeIPV6(SFSample *);
static void SFDecodeIPLayer4(SFSample *, u_char *);


#define ARGUS_FALSE   0
#define ARGUS_TRUE   1

int ArgusProcessSflowDatagram (struct ArgusParserStruct *, struct ArgusInput *, int);

static void ArgusParseSFFlowSample(SFSample *, int);
static void ArgusParseSFCountersSample(SFSample *, int);

static void 
ArgusParseSFFlowSample(SFSample *sptr, int state)
{
   if (sptr->datagramVersion >= 5) {
      int i, len, num;
      u_char *start;
//    int cnt;
  
      start = (u_char *)sptr->datap;
      len = SFGetData32 (sptr);
//    cnt = SFGetData32 (sptr);

      SFGetData32 (sptr);

      if (state) {
         sptr->ds_class = SFGetData32 (sptr);
         sptr->ds_index = SFGetData32 (sptr);
      } else {
         uint32_t sid = SFGetData32 (sptr);
         sptr->ds_class = sid >> 24;
         sptr->ds_index = sid & 0x00FFFFFF;
      }
      sptr->meanSkipCount = SFGetData32 (sptr);
      sptr->samplePool    = SFGetData32 (sptr);
      sptr->dropEvents    = SFGetData32 (sptr);
      if (state) {
         sptr->inputPortFormat  = SFGetData32 (sptr);
         sptr->inputPort        = SFGetData32 (sptr);
         sptr->outputPortFormat = SFGetData32 (sptr);
         sptr->outputPort       = SFGetData32 (sptr);
      } else {
         uint32_t inp  = SFGetData32 (sptr);
         uint32_t outp = SFGetData32 (sptr);
         sptr->inputPortFormat  = inp >> 30;
         sptr->inputPort        = inp & 0x3FFFFFFF;
         sptr->outputPortFormat = outp >> 30;
         sptr->outputPort       = outp & 0x3FFFFFFF;
      }

      num = SFGetData32 (sptr);
      for (i = 0; i < num; i++) {
         uint32_t stag, slen;
//       u_char *sdp;
         stag = SFGetData32 (sptr);
         slen = SFGetData32 (sptr);
//       sdp  = (u_char *)sptr->datap;

         switch (stag) {
            case SFLFLOW_HEADER:           SFParseFlowSample_header(sptr); break;
            case SFLFLOW_ETHERNET:         SFParseFlowSample_ethernet(sptr); break;
            case SFLFLOW_IPV4:             SFParseFlowSample_IPv4(sptr); break;
            case SFLFLOW_IPV6:             SFParseFlowSample_IPv6(sptr); break;
            case SFLFLOW_MEMCACHE:         SFParseFlowSample_memcache(sptr); break;
            case SFLFLOW_HTTP:             SFParseFlowSample_http(sptr); break;
            case SFLFLOW_CAL:              SFParseFlowSample_CAL(sptr); break;
            case SFLFLOW_EX_SWITCH:        SFParseExtendedSwitch(sptr); break;
            case SFLFLOW_EX_ROUTER:        SFParseExtendedRouter(sptr); break;
            case SFLFLOW_EX_GATEWAY:       SFParseExtendedGateway(sptr); break;
            case SFLFLOW_EX_USER:          SFParseExtendedUser(sptr); break;
            case SFLFLOW_EX_URL:           SFParseExtendedUrl(sptr); break;
            case SFLFLOW_EX_MPLS:          SFParseExtendedMpls(sptr); break;
            case SFLFLOW_EX_NAT:           SFParseExtendedNat(sptr); break;
            case SFLFLOW_EX_MPLS_TUNNEL:   SFParseExtendedMplsTunnel(sptr); break;
            case SFLFLOW_EX_MPLS_VC:       SFParseExtendedMplsVC(sptr); break;
            case SFLFLOW_EX_MPLS_FTN:      SFParseExtendedMplsFTN(sptr); break;
            case SFLFLOW_EX_MPLS_LDP_FEC:  SFParseExtendedMplsLDP_FEC(sptr); break;
            case SFLFLOW_EX_VLAN_TUNNEL:   SFParseExtendedVlanTunnel(sptr); break;
            case SFLFLOW_EX_80211_PAYLOAD: SFParseExtendedWifiPayload(sptr); break;
            case SFLFLOW_EX_80211_RX:      SFParseExtendedWifiRx(sptr); break;
            case SFLFLOW_EX_80211_TX:      SFParseExtendedWifiTx(sptr); break;
         /* case SFLFLOW_EX_AGGREGATION:   SFParseExtendedAggregation(sptr); break; */
            case SFLFLOW_EX_SOCKET4:       SFParseExtendedSocket4(sptr); break;
            case SFLFLOW_EX_SOCKET6:       SFParseExtendedSocket6(sptr); break;
            default:                       SFSkipBytes(sptr, slen); break;
         }
         SFLengthCheck(sptr, start, slen);
      }
      SFLengthCheck(sptr, start, len);
   }
}

static void
ArgusParseSFCountersSample(SFSample *sptr, int state)
{
   if (sptr->datagramVersion >= 5) {
      uint32_t slen, num;
      u_char *sdp, *start;
      int i;

      slen = SFGetData32 (sptr);
      sdp = (u_char *)sptr->datap;
      sptr->samplesGenerated = SFGetData32 (sptr);
      
      if (state) {
         sptr->ds_class = SFGetData32 (sptr);
         sptr->ds_index = SFGetData32 (sptr);
      } else {
         uint32_t sptrrId = SFGetData32 (sptr);
         sptr->ds_class = sptrrId >> 24;
         sptr->ds_index = sptrrId & 0x00ffffff;
      }
      
      num = SFGetData32 (sptr);
         
      for (i = 0; i < num; i++) {
         uint32_t tag, length;
         tag    = SFGetData32 (sptr);
         length = SFGetData32 (sptr);
         start  = (u_char *)sptr->datap;
         
         switch (tag) {
            case SFLCOUNTERS_GENERIC:       SFParseCounters_generic(sptr); break;
            case SFLCOUNTERS_ETHERNET:      SFParseCounters_ethernet(sptr); break;
            case SFLCOUNTERS_TOKENRING:     SFParseCounters_tokenring(sptr); break;
            case SFLCOUNTERS_VG:            SFParseCounters_vg(sptr); break;
            case SFLCOUNTERS_VLAN:          SFParseCounters_vlan(sptr); break;
            case SFLCOUNTERS_80211:         SFParseCounters_80211(sptr); break;
            case SFLCOUNTERS_PROCESSOR:     SFParseCounters_processor(sptr); break;
            case SFLCOUNTERS_RADIO:         SFParseCounters_radio(sptr); break;
            case SFLCOUNTERS_HOST_HID:      SFParseCounters_host_hid(sptr); break;
            case SFLCOUNTERS_ADAPTORS:      SFParseCounters_adaptors(sptr); break;
            case SFLCOUNTERS_HOST_PAR:      SFParseCounters_host_parent(sptr); break;
            case SFLCOUNTERS_HOST_CPU:      SFParseCounters_host_cpu(sptr); break;
            case SFLCOUNTERS_HOST_MEM:      SFParseCounters_host_mem(sptr); break;
            case SFLCOUNTERS_HOST_DSK:      SFParseCounters_host_dsk(sptr); break;
            case SFLCOUNTERS_HOST_NIO:      SFParseCounters_host_nio(sptr); break;
            case SFLCOUNTERS_HOST_VRT_NODE: SFParseCounters_host_vnode(sptr); break;
            case SFLCOUNTERS_HOST_VRT_CPU:  SFParseCounters_host_vcpu(sptr); break;
            case SFLCOUNTERS_HOST_VRT_MEM:  SFParseCounters_host_vmem(sptr); break;
            case SFLCOUNTERS_HOST_VRT_DSK:  SFParseCounters_host_vdsk(sptr); break;
            case SFLCOUNTERS_HOST_VRT_NIO:  SFParseCounters_host_vnio(sptr); break;
            case SFLCOUNTERS_MEMCACHE:      SFParseCounters_memcache(sptr); break;
            case SFLCOUNTERS_HTTP:          SFParseCounters_http(sptr); break;
            case SFLCOUNTERS_CAL:           SFParseCounters_CAL(sptr); break;
            default:                        SFSkipBytes(sptr, length); break;
         }
         SFLengthCheck(sptr, start, length);
      }
      SFLengthCheck(sptr, sdp, slen);
   }
}

int
ArgusProcessSflowDatagram (struct ArgusParserStruct *parser, struct ArgusInput *input, int cnt)
{
   SFSample sample, *sptr = &sample;
   uint32_t count;
   int retn = 0, i;

   bzero(sptr, sizeof (sample));
   sptr->rawSample = input->ArgusReadPtr;
   sptr->rawSampleLen = cnt;
   sptr->sourceIP = input->addr;

   sptr->datap = (uint32_t *)input->ArgusReadPtr;
   sptr->endp  = ((u_char *)input->ArgusReadPtr) + cnt;

   sptr->datagramVersion = SFGetData32 (sptr);

   switch (sptr->datagramVersion) {
      case 2:
      case 4:
      case 5:
         break;
      default: {
#ifdef ARGUSDEBUG
         ArgusDebug (5, "ArgusReadSflowStreamSocket (%p, %p) bad version  %d\n", parser, input, sptr->datagramVersion);
#endif

         return (1);
      }
   }

   SFGetAddress(sptr, &sptr->agent_addr);
   if (sptr->datagramVersion >= 5) {
      sptr->agentSubId = SFGetData32 (sptr);
   }

   sptr->sequenceNo = SFGetData32 (sptr);
   sptr->sysUpTime = SFGetData32 (sptr);
   count = SFGetData32 (sptr);

   for (i = 0; i < count; i++) {
      if ((u_char *)sptr->datap < sptr->endp) {
         sptr->sampleType = SFGetData32 (sptr);
         if (sptr->datagramVersion >= 5) {
            switch (sptr->sampleType) {
               case SFLFLOW_SAMPLE:
                  ArgusParseSFFlowSample(sptr, ARGUS_FALSE);
                  break;
               case SFLCOUNTERS_SAMPLE:
                  ArgusParseSFCountersSample(sptr, ARGUS_FALSE);
                  break;
               case SFLFLOW_SAMPLE_EXPANDED:
                  ArgusParseSFFlowSample(sptr, ARGUS_TRUE);
                  break;
               case SFLCOUNTERS_SAMPLE_EXPANDED:
                  ArgusParseSFCountersSample(sptr, ARGUS_TRUE);
                  break;
               default:
                  SFSkipBytes(sptr, SFGetData32 (sptr));
                  break;
            }
         } else {
/*
            switch (sptr->sampleType) {
               case FLOWSAMPLE:
                  ArgusParseSFFlowSample(sptr, ARGUS_FALSE);
                  break;
               case COUNTERSSAMPLE:
                  ArgusParseSFCountersSample(sptr, ARGUS_FALSE);
                  break;
            }
*/
         }

      } else
         break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusProcessSflowDatagram (%p, %p, %d) returning %d\n", parser, input, cnt, retn);
#endif

   return (retn);
}

int
ArgusReadSflowStreamSocket (struct ArgusParserStruct *parser, struct ArgusInput *input)
{
   int retn = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusReadSflowStreamSocket (%p, %p) returning %d\n", parser, input, retn);
#endif

   return (retn);
}

int
ArgusReadSflowDatagramSocket (struct ArgusParserStruct *parser, struct ArgusInput *input)
{
   int retn = 0, cnt = 0;
   struct sockaddr from;
   socklen_t fromlen = sizeof(from);
   struct sockaddr_in *sin = (struct sockaddr_in *)&from;

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusReadSflowDatagramSocket (0x%x) starting\n", input);
#endif

   if ((cnt = recvfrom (input->fd, input->ArgusReadPtr, input->ArgusReadSocketSize, 0L, &from, &fromlen)) > 0) {
      input->ArgusReadSocketCnt = cnt;

      if (from.sa_family == AF_INET)
         input->addr.s_addr = ntohl(sin->sin_addr.s_addr);
      else
         input->addr.s_addr = 0;

#ifdef ARGUSDEBUG
      ArgusDebug (8, "ArgusReadSflowDatagramSocket (0x%x) read %d bytes, capacity %d\n",
                      input, cnt, input->ArgusReadSocketCnt, input->ArgusReadSocketSize);
#endif

      if (ArgusProcessSflowDatagram(parser, input, cnt))
         retn = 1;

   } else {
#ifdef ARGUSDEBUG
     ArgusDebug (3, "ArgusReadSflowDatagramSocket (0x%x) read returned %d error %s\n", input, cnt, strerror(errno));
#endif
      if ((cnt < 0) && ((errno == EAGAIN) || (errno == EINTR))) {
         retn = 0;
      } else
         retn = 1;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusReadSflowDatagramSocket (%p, %p) returning %d\n", parser, input, retn);
#endif

   return (retn);
}


#define CISCO_VERSION_1      1
#define CISCO_VERSION_5      5
#define CISCO_VERSION_6      6
#define CISCO_VERSION_7      7
#define CISCO_VERSION_8      8
#define CISCO_VERSION_9      9

int
ArgusReadCiscoStreamSocket (struct ArgusParserStruct *parser, struct ArgusInput *input)
{
   int retn = 0, cnt = 0, bytes = 0, done = 0;

   if (!(input))
      return (retn);

   bytes = (input->ArgusBufferLen - input->ArgusReadSocketCnt);
   bytes = (bytes > ARGUS_MAX_BUFFER_READ) ? ARGUS_MAX_BUFFER_READ : bytes;

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusReadCiscoStreamSocket (0x%x) starting\n", input);
#endif

   if (input->file != NULL) {
      if (input->file == stdin) {
         int sretn;
         fd_set readmask;
         struct timeval wait;

         FD_ZERO (&readmask);
         FD_SET (fileno(stdin), &readmask);
         wait.tv_sec = 0;
         wait.tv_usec = 150000;

         if (!((sretn = select (fileno(stdin)+1, &readmask, NULL, NULL, &wait)) > 0))
            return (sretn);
          else
            cnt = fread (input->ArgusReadPtr + input->ArgusReadSocketCnt, 1, bytes, input->file);
      } else
         cnt = fread (input->ArgusReadPtr + input->ArgusReadSocketCnt, 1, bytes, input->file);
   } else
      cnt = read (input->fd, input->ArgusReadPtr + input->ArgusReadSocketCnt, bytes);

   if (cnt > 0) {
      input->ArgusReadSocketCnt += cnt;

#ifdef ARGUSDEBUG
      ArgusDebug (8, "ArgusReadCiscoStreamSocket (0x%x) read %d bytes, total %d need %d\n",
                      input, cnt, input->ArgusReadSocketCnt, input->ArgusReadSocketSize);
#endif

      while ((input->ArgusReadSocketCnt >= input->ArgusReadSocketSize) && !done) {
         unsigned int size = input->ArgusReadSocketSize;

         switch (input->ArgusReadSocketState) {
            case ARGUS_READINGPREHDR: {
               unsigned short *sptr = (unsigned short *) input->ArgusReadPtr;

               input->ArgusReadCiscoVersion = ntohs(*sptr++);
               input->ArgusReadSocketNum  = ntohs(*sptr);

               switch (input->ArgusReadCiscoVersion) {
                  case CISCO_VERSION_1:
                     input->ArgusReadSocketSize  = sizeof(CiscoFlowHeaderV1_t) - 4;
                     input->ArgusReadPtr = &input->ArgusReadBuffer[size];
                     break;

                  case CISCO_VERSION_5:
                     input->ArgusReadSocketSize  = sizeof(CiscoFlowHeaderV5_t) - 4;
                     input->ArgusReadPtr = &input->ArgusReadBuffer[size];
                     break;

                  default: {
#ifdef ARGUSDEBUG
                     ArgusDebug (8, "ArgusReadCiscoStreamSocket (0x%x) read version %d preheader num %d\n",
                                       input, input->ArgusReadCiscoVersion, input->ArgusReadSocketNum);
#endif
                  }
               }

               input->ArgusReadSocketState = ARGUS_READINGHDR;
               input->ArgusReadSocketCnt  -= size;
               break;
            }

            case ARGUS_READINGHDR: {
#ifdef ARGUSDEBUG
               ArgusDebug (7, "ArgusReadCiscoStreamSocket (0x%x) read record header\n", input);
#endif
               switch (input->ArgusReadCiscoVersion) {
                  case CISCO_VERSION_1: {
                     CiscoFlowHeaderV1_t *ArgusNetFlow = (CiscoFlowHeaderV1_t *) input->ArgusReadBuffer;

                     input->ArgusCiscoNetFlowParse = ArgusParseCiscoRecordV1;
                     input->ArgusReadSocketSize  = sizeof(CiscoFlowEntryV1_t);
                     input->ArgusReadPtr = &input->ArgusReadBuffer[sizeof(CiscoFlowHeaderV1_t)];

                     ArgusNetFlow->version    = ntohs(ArgusNetFlow->version);
                     ArgusNetFlow->count      = ntohs(ArgusNetFlow->count);
                     ArgusNetFlow->sysUptime  = ntohl(ArgusNetFlow->sysUptime);
                     ArgusNetFlow->unix_secs  = ntohl(ArgusNetFlow->unix_secs);
                     ArgusNetFlow->unix_nsecs = ntohl(ArgusNetFlow->unix_nsecs);
                     ArgusNetFlowRecordHeader = (u_char *)ArgusNetFlow;
                     break;
                  }

                  case CISCO_VERSION_5: {
                     CiscoFlowHeaderV5_t *ArgusNetFlow = (CiscoFlowHeaderV5_t *) input->ArgusReadBuffer;
 
                     input->ArgusCiscoNetFlowParse = ArgusParseCiscoRecordV5;
                     input->ArgusReadSocketSize  = sizeof(CiscoFlowEntryV5_t);
                     input->ArgusReadPtr = &input->ArgusReadBuffer[sizeof(CiscoFlowHeaderV5_t)];

                     ArgusNetFlow->version       = ntohs(ArgusNetFlow->version);
                     ArgusNetFlow->count         = ntohs(ArgusNetFlow->count);
                     ArgusNetFlow->sysUptime     = ntohl(ArgusNetFlow->sysUptime);
                     ArgusNetFlow->unix_secs     = ntohl(ArgusNetFlow->unix_secs);
                     ArgusNetFlow->unix_nsecs    = ntohl(ArgusNetFlow->unix_nsecs);
                     ArgusNetFlow->flow_sequence = ntohl(ArgusNetFlow->flow_sequence);
                     ArgusNetFlowRecordHeader = (u_char *)ArgusNetFlow;
                     break;
                  }

                  default: {
#ifdef ARGUSDEBUG
                     ArgusDebug (7, "ArgusReadCiscoStreamSocket (0x%x) read header\n", input);
#endif
                  }
               }
               
               input->ArgusReadSocketState = ARGUS_READINGBLOCK;
               input->ArgusReadBlockPtr = input->ArgusReadPtr;
               input->ArgusReadSocketCnt -= size;
               break;
            }

            default: {
#ifdef ARGUSDEBUG
               ArgusDebug (7, "ArgusReadCiscoStreamSocket (0x%x) read record complete\n", input);
#endif
               switch (input->ArgusReadCiscoVersion) {
                  case CISCO_VERSION_1:
                  case CISCO_VERSION_5:
                  case CISCO_VERSION_6:
                  case CISCO_VERSION_7:
                  case CISCO_VERSION_8:
                  case CISCO_VERSION_9: {
                     struct ArgusRecord *argus = input->ArgusCiscoNetFlowParse (ArgusParser, input, &input->ArgusReadPtr, NULL);
                     if  (argus != NULL)
                        if (ArgusHandleRecord (ArgusParser, input, argus, &ArgusParser->ArgusFilterCode) < 0)
                           return(1);
                     break;
                  }
               }

               input->ArgusReadSocketCnt -= size;

               switch (input->ArgusReadCiscoVersion) {
                  case CISCO_VERSION_1:
                     input->ArgusReadPtr += sizeof(CiscoFlowHeaderV1_t);
                     input->ArgusReadSocketCnt -= sizeof(CiscoFlowHeaderV1_t);
                     break;

                  case CISCO_VERSION_5:
                     input->ArgusReadPtr += sizeof(CiscoFlowHeaderV5_t);
                     input->ArgusReadSocketCnt -= sizeof(CiscoFlowHeaderV5_t);
                     break;

                  default: {
                     input->ArgusReadPtr += size;
#ifdef ARGUSDEBUG
                     ArgusDebug (7, "ArgusReadCiscoStreamSocket (0x%x) read header\n", input);
#endif
                  }
               }
               break;
            }
         }
      }

      if (input->ArgusReadPtr != input->ArgusReadBuffer) {
         if (input->ArgusReadSocketCnt > 0)
            memmove(input->ArgusReadBuffer, input->ArgusReadPtr, input->ArgusReadSocketCnt);
         input->ArgusReadPtr = input->ArgusReadBuffer;
      }

   } else {
#ifdef ARGUSDEBUG
     if (cnt < 0)
        ArgusDebug (3, "ArgusReadCiscoStreamSocket (%p) read returned %d error %s\n", input, cnt, strerror(errno));
     else
        ArgusDebug (6, "ArgusReadCiscoStreamSocket (%p) read returned %d\n", input, cnt);
#endif

      retn = 1;

      if ((cnt < 0) && ((errno == EAGAIN) || (errno == EINTR))) {
         retn = 0;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusReadCiscoStreamSocket (%p, %p) returning %d\n", parser, input, retn);
#endif

   return (retn);
}

int ArgusCiscoDatagramSocketStart = 1;

int
ArgusReadCiscoDatagramSocket (struct ArgusParserStruct *parser, struct ArgusInput *input)
{
   int retn = 0, cnt = 0, count = 0;
   struct sockaddr from;
   socklen_t fromlen = sizeof(from);
   struct sockaddr_in *sin = (struct sockaddr_in *)&from;
   unsigned char *ptr = NULL, *end = NULL;
   unsigned short *sptr = NULL;

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusReadCiscoDatagramSocket (0x%x) starting\n", input);
#endif

   if (ArgusTemplateQueue == NULL)
      if ((ArgusTemplateQueue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "ArgusReadCiscoDatagramSocket: ArgusNewQueue error %s", strerror(errno));

   if ((cnt = recvfrom (input->fd, input->ArgusReadPtr, input->ArgusReadSocketSize, 0L, &from, &fromlen)) > 0) {
      int ArgusReadSocketState = ARGUS_READINGPREHDR;
//    int ArgusReadSocketSize = 0;

      input->ArgusReadSocketCnt = cnt;
      ptr = (unsigned char *) input->ArgusReadPtr;
      sptr = (unsigned short *) ptr;
      end = ptr + cnt;

      if (from.sa_family == AF_INET)
         input->addr.s_addr = ntohl(sin->sin_addr.s_addr);
      else
         input->addr.s_addr = 0;

#ifdef ARGUSDEBUG
      ArgusDebug (8, "ArgusReadCiscoDatagramSocket (%p) read %d bytes, capacity %d\n",
                      input, cnt, input->ArgusReadSocketCnt, input->ArgusReadSocketSize);
#endif

      while ((char *)ptr < (char *) end) {
         switch (ArgusReadSocketState) {
            case ARGUS_READINGPREHDR: {
               sptr = (unsigned short *) ptr;
               input->ArgusReadCiscoVersion = ntohs(*sptr++);
//             ArgusReadSocketNum  = ntohs(*sptr);
               ArgusReadSocketState = ARGUS_READINGHDR;
               break;
            }

            case ARGUS_READINGHDR: {
#ifdef ARGUSDEBUG
               ArgusDebug (7, "ArgusReadCiscoDatagramSocket (%p, %p) read record header\n", parser, input);
#endif
               switch (input->ArgusReadCiscoVersion) {
                  case CISCO_VERSION_1: {
                     CiscoFlowHeaderV1_t *ArgusNetFlow = (CiscoFlowHeaderV1_t *) ptr;
//                   ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                     input->ArgusCiscoNetFlowParse = ArgusParseCiscoRecordV1;
                     ArgusNetFlow->count           = ntohs(ArgusNetFlow->count);
                     ArgusNetFlow->sysUptime       = ntohl(ArgusNetFlow->sysUptime);
                     ArgusNetFlow->unix_secs       = ntohl(ArgusNetFlow->unix_secs);
                     ArgusNetFlow->unix_nsecs      = ntohl(ArgusNetFlow->unix_nsecs);
                     ArgusNetFlowRecordHeader      = ptr;

                     ptr = (unsigned char *) (ArgusNetFlow + 1);
                     count = ArgusNetFlow->count;
                     break;
                  }

                  case CISCO_VERSION_5: {
                     CiscoFlowHeaderV5_t *ArgusNetFlow = (CiscoFlowHeaderV5_t *) ptr;
//                   ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                     input->ArgusCiscoNetFlowParse = ArgusParseCiscoRecordV5;
                     ArgusNetFlow->version         = ntohs(ArgusNetFlow->version);
                     ArgusNetFlow->count           = ntohs(ArgusNetFlow->count);
                     ArgusNetFlow->sysUptime       = ntohl(ArgusNetFlow->sysUptime);
                     ArgusNetFlow->unix_secs       = ntohl(ArgusNetFlow->unix_secs);
                     ArgusNetFlow->unix_nsecs      = ntohl(ArgusNetFlow->unix_nsecs);
                     ArgusNetFlow->flow_sequence   = ntohl(ArgusNetFlow->flow_sequence);
                     ArgusNetFlowRecordHeader      = ptr;

                     ptr = (unsigned char *) (ArgusNetFlow + 1);
                     count = ArgusNetFlow->count;
                     break;
                  }

                  case CISCO_VERSION_6: {
                     CiscoFlowHeaderV6_t *ArgusNetFlow = (CiscoFlowHeaderV6_t *) ptr;
//                   ArgusReadSocketSize  = sizeof(*ArgusNetFlow);
          
                     input->ArgusCiscoNetFlowParse = ArgusParseCiscoRecordV6;
                     ArgusNetFlow->version         = ntohs(ArgusNetFlow->version);
                     ArgusNetFlow->count           = ntohs(ArgusNetFlow->count);
                     ArgusNetFlow->sysUptime       = ntohl(ArgusNetFlow->sysUptime);
                     ArgusNetFlow->unix_secs       = ntohl(ArgusNetFlow->unix_secs);
                     ArgusNetFlow->unix_nsecs      = ntohl(ArgusNetFlow->unix_nsecs);
                     ArgusNetFlow->flow_sequence   = ntohl(ArgusNetFlow->flow_sequence);

                     ArgusNetFlowRecordHeader = ptr;
                     ptr = (unsigned char *) (ArgusNetFlow + 1);
                     count = ArgusNetFlow->count;
                     break;
                  }

                  case CISCO_VERSION_7: {
                     CiscoFlowHeaderV7_t *ArgusNetFlow = (CiscoFlowHeaderV7_t *) ptr;
//                   ArgusReadSocketSize  = sizeof(*ArgusNetFlow);
          
                     input->ArgusCiscoNetFlowParse = ArgusParseCiscoRecordV7;
                     ArgusNetFlow->version         = ntohs(ArgusNetFlow->version);
                     ArgusNetFlow->count           = ntohs(ArgusNetFlow->count);
                     ArgusNetFlow->sysUptime       = ntohl(ArgusNetFlow->sysUptime);
                     ArgusNetFlow->unix_secs       = ntohl(ArgusNetFlow->unix_secs);
                     ArgusNetFlow->unix_nsecs      = ntohl(ArgusNetFlow->unix_nsecs);
                     ArgusNetFlow->flow_sequence   = ntohl(ArgusNetFlow->flow_sequence);

                     ArgusNetFlowRecordHeader = ptr;
                     ptr = (unsigned char *) (ArgusNetFlow + 1);
                     count = ArgusNetFlow->count;
                     break;
                  }

                  case CISCO_VERSION_8: {
                     CiscoFlowHeaderV8_t *ArgusNetFlow = (CiscoFlowHeaderV8_t *) ptr;
//                   ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                     input->ArgusCiscoNetFlowParse = ArgusParseCiscoRecordV8;
                     ArgusNetFlow->version         = ntohs(ArgusNetFlow->version);
                     ArgusNetFlow->count           = ntohs(ArgusNetFlow->count);
                     ArgusNetFlow->sysUptime       = ntohl(ArgusNetFlow->sysUptime);
                     ArgusNetFlow->unix_secs       = ntohl(ArgusNetFlow->unix_secs);
                     ArgusNetFlow->unix_nsecs      = ntohl(ArgusNetFlow->unix_nsecs);
                     ArgusNetFlow->flow_sequence   = ntohl(ArgusNetFlow->flow_sequence);

                     ArgusNetFlowRecordHeader = ptr;
                     ptr = (unsigned char *) (ArgusNetFlow + 1);
                     count = ArgusNetFlow->count;

                     if ((input->ArgusCiscoNetFlowParse =
                            ArgusLookUpNetFlow(input, ArgusNetFlow->agg_method)) != NULL) {
                     }
                     break;
                  }

                  case CISCO_VERSION_9: {
                     CiscoFlowHeaderV9_t *ArgusNetFlow = (CiscoFlowHeaderV9_t *) ptr;
//                   ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                     input->ArgusCiscoNetFlowParse  = ArgusParseCiscoRecordV9;
                     ArgusNetFlow->version          = ntohs(ArgusNetFlow->version);
                     ArgusNetFlow->count            = ntohs(ArgusNetFlow->count);
                     ArgusNetFlow->sysUptime        = ntohl(ArgusNetFlow->sysUptime);
                     ArgusNetFlow->unix_secs        = ntohl(ArgusNetFlow->unix_secs);
                     ArgusNetFlow->package_sequence = ntohl(ArgusNetFlow->package_sequence);
                     ArgusNetFlow->source_id        = ntohl(ArgusNetFlow->source_id);
                     ArgusCiscoTvp->tv_sec          = ArgusNetFlow->unix_secs;
                     ArgusCiscoTvp->tv_usec         = 0;
                     ArgusCiscoSrcId                = ArgusNetFlow->source_id;
                     ArgusCiscoSrcAddr              = input->addr.s_addr;

                     ArgusNetFlowRecordHeader = ptr;
                     ptr = (unsigned char *) (ArgusNetFlow + 1);
                     count = ArgusNetFlow->count;
                     break;
                  }

                  default: {
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusReadCiscoStreamSocket (%p) unknown header version %d\n", ptr, input->ArgusReadCiscoVersion);
#endif
                  }
               }

               ArgusReadSocketState = ARGUS_READINGBLOCK;
               break;
            }

            case ARGUS_READINGBLOCK: {
               if (ArgusHandleRecord (parser, input, input->ArgusCiscoNetFlowParse (parser, input, &ptr, &count), &ArgusParser->ArgusFilterCode) < 0)
                  return(1);

               break;
            }
         }
      }

   } else {
#ifdef ARGUSDEBUG
     ArgusDebug (3, "ArgusReadCiscoDatagramSocket (0x%x) read returned %d error %s\n", input, cnt, strerror(errno));
#endif

      if ((cnt < 0) && ((errno == EAGAIN) || (errno == EINTR))) {
         retn = 0;
      } else
         retn = 1;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusReadCiscoDatagramSocket (0x%x) returning %d\n", input, retn);
#endif

   return (retn);
}


void 
SFParseFlowSample_header(SFSample *sptr)
{
   sptr->headerProtocol    = SFGetData32 (sptr);
   sptr->sampledPacketSize = SFGetData32 (sptr);

   if (sptr->datagramVersion > 4)
      sptr->stripped = SFGetData32 (sptr);
  
   sptr->headerLen  = SFGetData32 (sptr);
   sptr->header     = (u_char *)sptr->datap;
   SFSkipBytes(sptr, sptr->headerLen);
   
   switch(sptr->headerProtocol) {
      case SFLHEADER_ETHERNET_ISO8023:
        SFDecodeLinkLayer(sptr);
        break;
      case SFLHEADER_IPv4: 
        sptr->gotIPV4 = ARGUS_TRUE;
        sptr->offsetToIPV4 = 0;
        break;
      case SFLHEADER_IPv6: 
        sptr->gotIPV6 = ARGUS_TRUE;
        sptr->offsetToIPV6 = 0;
        break;
      case SFLHEADER_IEEE80211MAC:
        SFDecode80211MAC(sptr);
        break;
      case SFLHEADER_ISO88024_TOKENBUS:
      case SFLHEADER_ISO88025_TOKENRING:
      case SFLHEADER_FDDI:
      case SFLHEADER_FRAME_RELAY:
      case SFLHEADER_X25:
      case SFLHEADER_PPP:
      case SFLHEADER_SMDS:
      case SFLHEADER_AAL5:
      case SFLHEADER_AAL5_IP:
      case SFLHEADER_MPLS:
      case SFLHEADER_POS:
      case SFLHEADER_IEEE80211_AMPDU:
      case SFLHEADER_IEEE80211_AMSDU_SUBFRAME:
      default:
        break;
    }
   
   if (sptr->gotIPV4)
     SFDecodeIPV4 (sptr);
   else
   if (sptr->gotIPV6) 
     SFDecodeIPV6 (sptr);
}

void
SFParseFlowSample_ethernet(SFSample *sptr)
{
   sptr->eth_len = SFGetData32 (sptr);
   memcpy(sptr->eth_src, sptr->datap, 6);
   SFSkipBytes(sptr, 6);
   memcpy(sptr->eth_dst, sptr->datap, 6);
   SFSkipBytes(sptr, 6);
   sptr->eth_type = SFGetData32 (sptr);
}

void
SFParseFlowSample_IPv4 (SFSample *sptr)
{
   SFLSampled_ipv4 nfKey;

   sptr->headerLen = sizeof(SFLSampled_ipv4);
   sptr->header = (u_char *)sptr->datap; /* just point at the header */
   SFSkipBytes(sptr, sptr->headerLen);
   
   memcpy(&nfKey, sptr->header, sizeof(nfKey));
   sptr->sampledPacketSize = ntohl(nfKey.length);
   sptr->ipsrc.type = SFLADDRESSTYPE_IP_V4;
   sptr->ipsrc.address.ip_v4 = nfKey.src_ip;
   sptr->ipdst.type = SFLADDRESSTYPE_IP_V4;
   sptr->ipdst.address.ip_v4 = nfKey.dst_ip;
   sptr->dcd_ipProtocol = ntohl(nfKey.protocol);
   sptr->dcd_ipTos = ntohl(nfKey.tos);
   sptr->dcd_sport = ntohl(nfKey.src_port);
   sptr->dcd_dport = ntohl(nfKey.dst_port);

   switch(sptr->dcd_ipProtocol) {
      case IPPROTO_TCP:
         sptr->dcd_tcpFlags = ntohl(nfKey.tcp_flags);
         break;

      default: /* some other protcol */
         break;
   }
}

void
SFParseFlowSample_IPv6(SFSample *sptr)
{
   SFLSampled_ipv6 nfKey6;

   sptr->header = (u_char *)sptr->datap; /* just point at the header */
   sptr->headerLen = sizeof(SFLSampled_ipv6);
   SFSkipBytes(sptr, sptr->headerLen);
   memcpy(&nfKey6, sptr->header, sizeof(nfKey6));
   sptr->sampledPacketSize = ntohl(nfKey6.length);
   sptr->ipsrc.type = SFLADDRESSTYPE_IP_V6;
   memcpy(&sptr->ipsrc.address.ip_v6, &nfKey6.src_ip, 16);
   sptr->ipdst.type = SFLADDRESSTYPE_IP_V6;
   memcpy(&sptr->ipdst.address.ip_v6, &nfKey6.dst_ip, 16);
   sptr->dcd_ipProtocol = ntohl(nfKey6.protocol);
   sptr->dcd_sport = ntohl(nfKey6.src_port);
   sptr->dcd_dport = ntohl(nfKey6.dst_port);
   switch(sptr->dcd_ipProtocol) {
      case IPPROTO_TCP:
         sptr->dcd_tcpFlags = ntohl(nfKey6.tcp_flags);
         break;

      default: /* some other protcol */
         break;
   }
}

#define ENC_KEY_BYTES (SFL_MAX_MEMCACHE_KEY * 3) + 1

void
SFParseFlowSample_memcache (SFSample *sptr)
{
  char key[SFL_MAX_MEMCACHE_KEY+1];

   SFGetData32 (sptr); // memchache_op_protocol
   SFGetData32 (sptr); // memchache_op_cmd

   SFGetString(sptr, key, SFL_MAX_MEMCACHE_KEY);

   SFGetData32 (sptr); // memchache_op_nkeys
   SFGetData32 (sptr); // memchache_op_value_bytes
   SFGetData32 (sptr); // memchache_op_duration_uS
   SFGetData32 (sptr); // memchache_op_status
}

void
SFParseFlowSample_http(SFSample *sptr)
{
   char uri[SFL_MAX_HTTP_URI+1];
   char host[SFL_MAX_HTTP_HOST+1];
   char referrer[SFL_MAX_HTTP_REFERRER+1];
   char useragent[SFL_MAX_HTTP_USERAGENT+1];
   char authuser[SFL_MAX_HTTP_AUTHUSER+1];
   char mimetype[SFL_MAX_HTTP_MIMETYPE+1];
// uint32_t method, protocol, status, duration;
// uint64_t bytes;

// method   = SFGetData32 (sptr);
// protocol = SFGetData32 (sptr);

   SFGetData32 (sptr);
   SFGetData32 (sptr);

   SFGetString(sptr, uri, SFL_MAX_HTTP_URI);
   SFGetString(sptr, host, SFL_MAX_HTTP_HOST);
   SFGetString(sptr, referrer, SFL_MAX_HTTP_REFERRER);
   SFGetString(sptr, useragent, SFL_MAX_HTTP_USERAGENT);
   SFGetString(sptr, authuser, SFL_MAX_HTTP_AUTHUSER);
   SFGetString(sptr, mimetype, SFL_MAX_HTTP_MIMETYPE);

// bytes    = SFGetData64 (sptr);
// duration = SFGetData32 (sptr);
// status   = SFGetData32 (sptr);

   SFGetData64 (sptr);
   SFGetData32 (sptr);
   SFGetData32 (sptr);
}

void
SFParseFlowSample_CAL(SFSample *sptr)
{
   char pool[SFLCAL_MAX_POOL_LEN];
   char transaction[SFLCAL_MAX_TRANSACTION_LEN];
   char operation[SFLCAL_MAX_OPERATION_LEN];
   char status[SFLCAL_MAX_STATUS_LEN];

   SFGetData32 (sptr); // ttype
   SFGetData32 (sptr); // depth

   SFGetString(sptr, pool, SFLCAL_MAX_POOL_LEN);
   SFGetString(sptr, transaction, SFLCAL_MAX_TRANSACTION_LEN);
   SFGetString(sptr, operation, SFLCAL_MAX_OPERATION_LEN);
   SFGetString(sptr, status, SFLCAL_MAX_STATUS_LEN);

   SFGetData64 (sptr); // duration_uS
}

void
SFParseExtendedSwitch(SFSample *sptr)
{
   sptr->in_vlan            = SFGetData32 (sptr);
   sptr->in_priority        = SFGetData32 (sptr);
   sptr->out_vlan           = SFGetData32 (sptr);
   sptr->out_priority       = SFGetData32 (sptr);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_SWITCH;
}

void
SFParseExtendedRouter(SFSample *sptr)
{
   SFGetAddress(sptr, &sptr->nextHop);
   sptr->srcMask            = SFGetData32 (sptr);
   sptr->dstMask            = SFGetData32 (sptr);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_ROUTER;
}

void
SFParseExtendedGateway(SFSample *sptr)
{
   uint32_t segments;
   uint32_t seg;

   if(sptr->datagramVersion >= 5)
      SFGetAddress(sptr, &sptr->bgp_nextHop);

   sptr->my_as       = SFGetData32 (sptr);
   sptr->src_as      = SFGetData32 (sptr);
   sptr->src_peer_as = SFGetData32 (sptr);
   segments          = SFGetData32 (sptr);

   // clear dst_peer_as and dst_as to make sure we are not
   // remembering values from a previous sptr - (thanks Marc Lavine)
   sptr->dst_peer_as = 0;
   sptr->dst_as = 0;

   if (segments > 0) {
      for (seg = 0; seg < segments; seg++) {
//       uint32_t i, seg_type, seg_len;
         uint32_t i, seg_len;

//       seg_type = SFGetData32 (sptr);
         SFGetData32 (sptr);
         seg_len  = SFGetData32 (sptr);
         for (i = 0; i < seg_len; i++) {
            uint32_t asNumber;
            asNumber = SFGetData32 (sptr);
            /* mark the first one as the dst_peer_as */
            if (i == 0 && seg == 0)
               sptr->dst_peer_as = asNumber;

            /* mark the last one as the dst_as */
            if (seg == (segments - 1) && i == (seg_len - 1))
               sptr->dst_as = asNumber;
         }
      }
   }

   sptr->communities_len = SFGetData32 (sptr);
   /* just point at the communities array */
   if (sptr->communities_len > 0)
      sptr->communities = sptr->datap;
   /* and skip over it in the input */
   SFSkipBytes(sptr, sptr->communities_len * 4);
 
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
   sptr->localpref = SFGetData32 (sptr);
}

void
SFParseExtendedUser(SFSample *sptr)
{
   if (sptr->datagramVersion >= 5)
      sptr->src_user_charset = SFGetData32 (sptr);

   sptr->src_user_len = SFGetString(sptr, sptr->src_user, SA_MAX_EXTENDED_USER_LEN);

   if (sptr->datagramVersion >= 5)
      sptr->dst_user_charset = SFGetData32 (sptr);

   sptr->dst_user_len = SFGetString(sptr, sptr->dst_user, SA_MAX_EXTENDED_USER_LEN);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_USER;
}

void
SFParseExtendedUrl(SFSample *sptr)
{
   sptr->url_direction = SFGetData32 (sptr);
   sptr->url_len = SFGetString(sptr, sptr->url, SA_MAX_EXTENDED_URL_LEN);

   if(sptr->datagramVersion >= 5)
      sptr->host_len = SFGetString(sptr, sptr->host, SA_MAX_EXTENDED_HOST_LEN);

   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_URL;
}

void SFMplsLabelStack(SFSample *, char *);

void
SFMplsLabelStack(SFSample *sptr, char *fieldName)
{
   SFLLabelStack lstk;

   lstk.depth = SFGetData32 (sptr);
   /* just point at the lablelstack array */
   if(lstk.depth > 0)
      lstk.stack = (uint32_t *)sptr->datap;
   /* and skip over it in the input */
   SFSkipBytes(sptr, lstk.depth * 4);
}

void
SFParseExtendedMpls(SFSample *sptr)
{
   SFGetAddress(sptr, &sptr->mpls_nextHop);
  SFMplsLabelStack(sptr, "mpls_input_stack");
  SFMplsLabelStack(sptr, "mpls_output_stack");

  sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS;
}

void
SFParseExtendedNat(SFSample *sptr)
{
   SFGetAddress(sptr, &sptr->nat_src);
   SFGetAddress(sptr, &sptr->nat_dst);
  sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT;
}


#define SA_MAX_TUNNELNAME_LEN 100

void
SFParseExtendedMplsTunnel(SFSample *sptr)
{
   char tunnel_name[SA_MAX_TUNNELNAME_LEN+1];
// uint32_t tunnel_id, tunnel_cos;

   SFGetString(sptr, tunnel_name, SA_MAX_TUNNELNAME_LEN);
// tunnel_id = SFGetData32 (sptr);
// tunnel_cos = SFGetData32 (sptr);
   SFGetData32 (sptr);
   SFGetData32 (sptr);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL;
}


#define SA_MAX_VCNAME_LEN 100

void
SFParseExtendedMplsVC (SFSample *sptr)
{
   char vc_name[SA_MAX_VCNAME_LEN+1];
// uint32_t vll_vc_id, vc_cos;

   SFGetString(sptr, vc_name, SA_MAX_VCNAME_LEN);
// vll_vc_id = SFGetData32 (sptr);
// vc_cos = SFGetData32 (sptr);

   SFGetData32 (sptr);
   SFGetData32 (sptr);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_VC;
}


#define SA_MAX_FTN_LEN 100

void
SFParseExtendedMplsFTN (SFSample *sptr)
{
   char ftn_descr[SA_MAX_FTN_LEN+1];
// uint32_t ftn_mask;
   SFGetString(sptr, ftn_descr, SA_MAX_FTN_LEN);
// ftn_mask = SFGetData32 (sptr);
   SFGetData32 (sptr);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_FTN;
}

void
SFParseExtendedMplsLDP_FEC(SFSample *sptr)
{
   SFGetData32 (sptr); // fec_addr_prefix_len
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC;
}

void
SFParseExtendedVlanTunnel(SFSample *sptr)
{
   SFLLabelStack lstk;
   lstk.depth = SFGetData32 (sptr);

   /* just point at the lablelstack array */
   if(lstk.depth > 0)
      lstk.stack = (uint32_t *)sptr->datap;

   /* and skip over it in the input */
   SFSkipBytes(sptr, lstk.depth * 4);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL;
}

void
SFParseExtendedWifiPayload(SFSample *sptr)
{
   SFGetData32 (sptr);  // "cipher_suite"
   SFParseFlowSample_header(sptr);
}

void
SFParseExtendedWifiRx(SFSample *sptr)
{
   char ssid[SFL_MAX_SSID_LEN+1];

   SFGetString(sptr, ssid, SFL_MAX_SSID_LEN);
   SFSkipBytes(sptr, 6);

   SFGetData32 (sptr); // "rx_version");
   SFGetData32 (sptr); // "rx_channel");
   SFGetData64 (sptr); // "rx_speed");
   SFGetData32 (sptr); // "rx_rsni");
   SFGetData32 (sptr); // "rx_rcpi");
   SFGetData32 (sptr); // "rx_packet_uS");
}

void
SFParseExtendedWifiTx(SFSample *sptr)
{
   char ssid[SFL_MAX_SSID_LEN+1];
   SFGetString(sptr, ssid, SFL_MAX_SSID_LEN);
   SFSkipBytes(sptr, 6);

   SFGetData32 (sptr); // "tx_version"
   SFGetData32 (sptr); // "tx_transmissions"
   SFGetData32 (sptr); // "tx_packet_uS"
   SFGetData32 (sptr); // "tx_retrans_uS"
   SFGetData32 (sptr); // "tx_channel"
   SFGetData64 (sptr); // "tx_speed"
   SFGetData32 (sptr); // "tx_power_mW"
}

void
SFParseExtendedSocket4(SFSample *sptr)
{
   SFGetData32 (sptr); //   "socket4_ip_protocol"
   sptr->ipsrc.type                      = SFLADDRESSTYPE_IP_V4;
   sptr->ipsrc.address.ip_v4.addr = SFGetData32_nobswap(sptr);
   sptr->ipdst.type                      = SFLADDRESSTYPE_IP_V4;
   sptr->ipdst.address.ip_v4.addr = SFGetData32_nobswap(sptr);

   SFGetData32 (sptr); //   "socket4_local_port"
   SFGetData32 (sptr); //   "socket4_remote_port"
}

void
SFParseExtendedSocket6(SFSample *sptr)
{
   SFGetData32 (sptr);   // "socket6_ip_protocol"
   sptr->ipsrc.type = SFLADDRESSTYPE_IP_V6;
   memcpy(&sptr->ipsrc.address.ip_v6, sptr->datap, 16);
   SFSkipBytes(sptr, 16);
   sptr->ipdst.type = SFLADDRESSTYPE_IP_V6;
   memcpy(&sptr->ipdst.address.ip_v6, sptr->datap, 16);
   SFSkipBytes(sptr, 16);
   SFGetData32 (sptr);   // "socket6_local_port"
   SFGetData32 (sptr);   // "socket6_remote_port"
}


void
SFParseCounters_generic (SFSample *sptr)
{
  /* the first part of the generic counters block is really just more info about the interface. */
  sptr->ifCounters.ifIndex            = SFGetData32 (sptr);  // "ifIndex"
  sptr->ifCounters.ifType             = SFGetData32 (sptr);  // "networkType"
  sptr->ifCounters.ifSpeed            = SFGetData64 (sptr);  // "ifSpeed"
  sptr->ifCounters.ifDirection        = SFGetData32 (sptr);  // "ifDirection"
  sptr->ifCounters.ifStatus           = SFGetData32 (sptr);  // "ifStatus"

  /* the generic counters always come first */
  sptr->ifCounters.ifInOctets         = SFGetData64 (sptr);  // "ifInOctets"
  sptr->ifCounters.ifInUcastPkts      = SFGetData32 (sptr);  // "ifInUcastPkts"
  sptr->ifCounters.ifInMulticastPkts  = SFGetData32 (sptr);  // "ifInMulticastPkts"
  sptr->ifCounters.ifInBroadcastPkts  = SFGetData32 (sptr);  // "ifInBroadcastPkts"
  sptr->ifCounters.ifInDiscards       = SFGetData32 (sptr);  // "ifInDiscards"
  sptr->ifCounters.ifInErrors         = SFGetData32 (sptr);  // "ifInErrors"
  sptr->ifCounters.ifInUnknownProtos  = SFGetData32 (sptr);  // "ifInUnknownProtos"
  sptr->ifCounters.ifOutOctets        = SFGetData64 (sptr);  // "ifOutOctets"
  sptr->ifCounters.ifOutUcastPkts     = SFGetData32 (sptr);  // "ifOutUcastPkts"
  sptr->ifCounters.ifOutMulticastPkts = SFGetData32 (sptr);  // "ifOutMulticastPkts"
  sptr->ifCounters.ifOutBroadcastPkts = SFGetData32 (sptr);  // "ifOutBroadcastPkts"
  sptr->ifCounters.ifOutDiscards      = SFGetData32 (sptr);  // "ifOutDiscards"
  sptr->ifCounters.ifOutErrors        = SFGetData32 (sptr);  // "ifOutErrors"
  sptr->ifCounters.ifPromiscuousMode  = SFGetData32 (sptr);  // "ifPromiscuousMode"
}

void
SFParseCounters_ethernet (SFSample *sptr)
{
   SFGetData32 (sptr);  // "dot3StatsAlignmentErrors"
   SFGetData32 (sptr);  // "dot3StatsFCSErrors"
   SFGetData32 (sptr);  // "dot3StatsSingleCollisionFrames"
   SFGetData32 (sptr);  // "dot3StatsMultipleCollisionFrames"
   SFGetData32 (sptr);  // "dot3StatsSQETestErrors"
   SFGetData32 (sptr);  // "dot3StatsDeferredTransmissions"
   SFGetData32 (sptr);  // "dot3StatsLateCollisions"
   SFGetData32 (sptr);  // "dot3StatsExcessiveCollisions"
   SFGetData32 (sptr);  // "dot3StatsInternalMacTransmitErrors"
   SFGetData32 (sptr);  // "dot3StatsCarrierSenseErrors"
   SFGetData32 (sptr);  // "dot3StatsFrameTooLongs"
   SFGetData32 (sptr);  // "dot3StatsInternalMacReceiveErrors"
   SFGetData32 (sptr);  // "dot3StatsSymbolErrors"
}

void
SFParseCounters_tokenring (SFSample *sptr)
{
   SFGetData32 (sptr);  // "dot5StatsLineErrors"
   SFGetData32 (sptr);  // "dot5StatsBurstErrors"
   SFGetData32 (sptr);  // "dot5StatsACErrors"
   SFGetData32 (sptr);  // "dot5StatsAbortTransErrors"
   SFGetData32 (sptr);  // "dot5StatsInternalErrors"
   SFGetData32 (sptr);  // "dot5StatsLostFrameErrors"
   SFGetData32 (sptr);  // "dot5StatsReceiveCongestions"
   SFGetData32 (sptr);  // "dot5StatsFrameCopiedErrors"
   SFGetData32 (sptr);  // "dot5StatsTokenErrors"
   SFGetData32 (sptr);  // "dot5StatsSoftErrors"
   SFGetData32 (sptr);  // "dot5StatsHardErrors"
   SFGetData32 (sptr);  // "dot5StatsSignalLoss"
   SFGetData32 (sptr);  // "dot5StatsTransmitBeacons"
   SFGetData32 (sptr);  // "dot5StatsRecoverys"
   SFGetData32 (sptr);  // "dot5StatsLobeWires"
   SFGetData32 (sptr);  // "dot5StatsRemoves"
   SFGetData32 (sptr);  // "dot5StatsSingles"
   SFGetData32 (sptr);  // "dot5StatsFreqErrors"
}

void
SFParseCounters_vg (SFSample *sptr)
{
   SFGetData32 (sptr);  // "dot12InHighPriorityFrames"
   SFGetData64 (sptr);  // "dot12InHighPriorityOctets"
   SFGetData32 (sptr);  // "dot12InNormPriorityFrames"
   SFGetData64 (sptr);  // "dot12InNormPriorityOctets"
   SFGetData32 (sptr);  // "dot12InIPMErrors"
   SFGetData32 (sptr);  // "dot12InOversizeFrameErrors"
   SFGetData32 (sptr);  // "dot12InDataErrors"
   SFGetData32 (sptr);  // "dot12InNullAddressedFrames"
   SFGetData32 (sptr);  // "dot12OutHighPriorityFrames"
   SFGetData64 (sptr);  // "dot12OutHighPriorityOctets"
   SFGetData32 (sptr);  // "dot12TransitionIntoTrainings"
   SFGetData64 (sptr);  // "dot12HCInHighPriorityOctets"
   SFGetData64 (sptr);  // "dot12HCInNormPriorityOctets"
   SFGetData64 (sptr);  // "dot12HCOutHighPriorityOctets"
}

void
SFParseCounters_vlan (SFSample *sptr)
{
  sptr->in_vlan = SFGetData32 (sptr);

   SFGetData64 (sptr);  // "octets"
   SFGetData32 (sptr);  // "ucastPkts"
   SFGetData32 (sptr);  // "multicastPkts"
   SFGetData32 (sptr);  // "broadcastPkts"
   SFGetData32 (sptr);  // "discards"
}

void
SFParseCounters_80211 (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "dot11TransmittedFragmentCount"
   SFGetData32 (sptr);  //  "dot11MulticastTransmittedFrameCount"
   SFGetData32 (sptr);  //  "dot11FailedCount"
   SFGetData32 (sptr);  //  "dot11RetryCount"
   SFGetData32 (sptr);  //  "dot11MultipleRetryCount"
   SFGetData32 (sptr);  //  "dot11FrameDuplicateCount"
   SFGetData32 (sptr);  //  "dot11RTSSuccessCount"
   SFGetData32 (sptr);  //  "dot11RTSFailureCount"
   SFGetData32 (sptr);  //  "dot11ACKFailureCount"
   SFGetData32 (sptr);  //  "dot11ReceivedFragmentCount"
   SFGetData32 (sptr);  //  "dot11MulticastReceivedFrameCount"
   SFGetData32 (sptr);  //  "dot11FCSErrorCount"
   SFGetData32 (sptr);  //  "dot11TransmittedFrameCount"
   SFGetData32 (sptr);  //  "dot11WEPUndecryptableCount"
   SFGetData32 (sptr);  //  "dot11QoSDiscardedFragmentCount"
   SFGetData32 (sptr);  //  "dot11AssociatedStationCount"
   SFGetData32 (sptr);  //  "dot11QoSCFPollsReceivedCount"
   SFGetData32 (sptr);  //  "dot11QoSCFPollsUnusedCount"
   SFGetData32 (sptr);  //  "dot11QoSCFPollsUnusableCount"
   SFGetData32 (sptr);  //  "dot11QoSCFPollsLostCount"
}

void
SFParseCounters_processor (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "5s_cpu"
   SFGetData32 (sptr);  //  "1m_cpu"
   SFGetData32 (sptr);  //  "5m_cpu"
   SFGetData64(sptr);  //  "total_memory_bytes"
   SFGetData64(sptr);  //  "free_memory_bytes"
}

void
SFParseCounters_radio (SFSample *sptr)
{
   SFGetData32 (sptr);  // "radio_elapsed_time"
   SFGetData32 (sptr);  // "radio_on_channel_time"
   SFGetData32 (sptr);  // "radio_on_channel_busy_time"
}

void
SFParseCounters_host_hid (SFSample *sptr)
{
   char hostname[SFL_MAX_HOSTNAME_LEN+1];
   char os_release[SFL_MAX_OSRELEASE_LEN+1];

   SFGetString(sptr, hostname, SFL_MAX_HOSTNAME_LEN);
   SFSkipBytes(sptr, 16);
   SFGetData32 (sptr);  //  "machine_type");
   SFGetData32 (sptr);  //  "os_name");
   SFGetString(sptr, os_release, SFL_MAX_OSRELEASE_LEN);
}

void
SFParseCounters_adaptors (SFSample *sptr)
{
// uint32_t i, j, ifindex, num_macs;
   uint32_t i, j, num_macs;
   uint32_t num = SFGetData32 (sptr);

   for (i = 0; i < num; i++) {
//    ifindex  = SFGetData32 (sptr);
      SFGetData32 (sptr);
      num_macs = SFGetData32 (sptr);
      for (j = 0; j < num_macs; j++) 
         SFSkipBytes(sptr, 8);
   }
}

void
SFParseCounters_host_parent (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "parent_dsClass"
   SFGetData32 (sptr);  //  "parent_dsIndex"
}

void
SFParseCounters_host_cpu (SFSample *sptr)
{
   SFGetFloat (sptr);   // "cpu_load_one");
   SFGetFloat (sptr);   // "cpu_load_five");
   SFGetFloat (sptr);   // "cpu_load_fifteen");
   SFGetData32 (sptr);  // "cpu_proc_run");
   SFGetData32 (sptr);  // "cpu_proc_total");
   SFGetData32 (sptr);  // "cpu_num");
   SFGetData32 (sptr);  // "cpu_speed");
   SFGetData32 (sptr);  // "cpu_uptime");
   SFGetData32 (sptr);  // "cpu_user");
   SFGetData32 (sptr);  // "cpu_nice");
   SFGetData32 (sptr);  // "cpu_system");
   SFGetData32 (sptr);  // "cpu_idle");
   SFGetData32 (sptr);  // "cpu_wio");
   SFGetData32 (sptr);  // "cpuintr");
   SFGetData32 (sptr);  // "cpu_sintr");
   SFGetData32 (sptr);  // "cpuinterrupts");
   SFGetData32 (sptr);  // "cpu_contexts");
}

void
SFParseCounters_host_mem (SFSample *sptr)
{
   SFGetData64 (sptr);  //  "mem_total"
   SFGetData64 (sptr);  //  "mem_free"
   SFGetData64 (sptr);  //  "mem_shared"
   SFGetData64 (sptr);  //  "mem_buffers"
   SFGetData64 (sptr);  //  "mem_cached"
   SFGetData64 (sptr);  //  "swap_total"
   SFGetData64 (sptr);  //  "swap_free"
   SFGetData32 (sptr);  //  "page_in"
   SFGetData32 (sptr);  //  "page_out"
   SFGetData32 (sptr);  //  "swap_in"
   SFGetData32 (sptr);  //  "swap_out"
}

void
SFParseCounters_host_dsk (SFSample *sptr)
{
   SFGetData64 (sptr);  //  "disk_total"
   SFGetData64 (sptr);  //  "disk_free"
   SFGetData32 (sptr);  //  "disk_partition_max_used"
   SFGetData32 (sptr);  //  "disk_reads"
   SFGetData64 (sptr);  //  "disk_bytes_read"
   SFGetData32 (sptr);  //  "disk_read_time"
   SFGetData32 (sptr);  //  "disk_writes"
   SFGetData64 (sptr);  //  "disk_bytes_written"
   SFGetData32 (sptr);  //  "disk_write_time"
}

void
SFParseCounters_host_nio (SFSample *sptr)
{
   SFGetData64 (sptr);  //  "nio_bytes_in"
   SFGetData32 (sptr);  //  "nio_pkts_in"
   SFGetData32 (sptr);  //  "nio_errs_in"
   SFGetData32 (sptr);  //  "nio_drops_in"
   SFGetData64 (sptr);  //  "nio_bytes_out"
   SFGetData32 (sptr);  //  "nio_pkts_out"
   SFGetData32 (sptr);  //  "nio_errs_out"
   SFGetData32 (sptr);  //  "nio_drops_out"
}

void
SFParseCounters_host_vnode (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "vnode_mhz"
   SFGetData32 (sptr);  //  "vnode_cpus"
   SFGetData64 (sptr);  //  "vnode_memory"
   SFGetData64 (sptr);  //  "vnode_memory_free"
   SFGetData32 (sptr);  //  "vnode_num_domains"
}

void
SFParseCounters_host_vcpu (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "vcpu_state"
   SFGetData32 (sptr);  //  "vcpu_cpu_mS"
   SFGetData32 (sptr);  //  "vcpu_cpuCount"
}

void
SFParseCounters_host_vmem (SFSample *sptr)
{
   SFGetData64 (sptr);  //  "vmem_memory"
   SFGetData64 (sptr);  //  "vmem_maxMemory"
}

void
SFParseCounters_host_vdsk (SFSample *sptr)
{
   SFGetData64 (sptr);  //  "vdsk_capacity"
   SFGetData64 (sptr);  //  "vdsk_allocation"
   SFGetData64 (sptr);  //  "vdsk_available"
   SFGetData32 (sptr);  //  "vdsk_rd_req"
   SFGetData64 (sptr);  //  "vdsk_rd_bytes"
   SFGetData32 (sptr);  //  "vdsk_wr_req"
   SFGetData64 (sptr);  //  "vdsk_wr_bytes"
   SFGetData32 (sptr);  //  "vdsk_errs"
}

void
SFParseCounters_host_vnio (SFSample *sptr)
{
   SFGetData64 (sptr);  //  "vnio_bytes_in"
   SFGetData32 (sptr);  //  "vnio_pkts_in"
   SFGetData32 (sptr);  //  "vnio_errs_in"
   SFGetData32 (sptr);  //  "vnio_drops_in"
   SFGetData64 (sptr);  //  "vnio_bytes_out"
   SFGetData32 (sptr);  //  "vnio_pkts_out"
   SFGetData32 (sptr);  //  "vnio_errs_out"
   SFGetData32 (sptr);  //  "vnio_drops_out"
}

void
SFParseCounters_memcache (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "memcache_uptime"
   SFGetData32 (sptr);  //  "memcache_rusage_user"
   SFGetData32 (sptr);  //  "memcache_rusage_system"
   SFGetData32 (sptr);  //  "memcache_curr_connections"
   SFGetData32 (sptr);  //  "memcache_total_connections"
   SFGetData32 (sptr);  //  "memcache_connection_structures"
   SFGetData32 (sptr);  //  "memcache_cmd_get"
   SFGetData32 (sptr);  //  "memcache_cmd_set"
   SFGetData32 (sptr);  //  "memcache_cmd_flush"
   SFGetData32 (sptr);  //  "memcache_get_hits"
   SFGetData32 (sptr);  //  "memcache_get_misses"
   SFGetData32 (sptr);  //  "memcache_delete_misses"
   SFGetData32 (sptr);  //  "memcache_delete_hits"
   SFGetData32 (sptr);  //  "memcache_incr_misses"
   SFGetData32 (sptr);  //  "memcache_incr_hits"
   SFGetData32 (sptr);  //  "memcache_decr_misses"
   SFGetData32 (sptr);  //  "memcache_decr_hits"
   SFGetData32 (sptr);  //  "memcache_cas_misses"
   SFGetData32 (sptr);  //  "memcache_cas_hits"
   SFGetData32 (sptr);  //  "memcache_cas_badval"
   SFGetData32 (sptr);  //  "memcache_auth_cmds"
   SFGetData32 (sptr);  //  "memcache_auth_errors"
   SFGetData64 (sptr);  //  "memcache_bytes_read"
   SFGetData64 (sptr);  //  "memcache_bytes_written"
   SFGetData32 (sptr);  //  "memcache_limit_maxbytes"
   SFGetData32 (sptr);  //  "memcache_accepting_conns"
   SFGetData32 (sptr);  //  "memcache_listen_disabled_num"
   SFGetData32 (sptr);  //  "memcache_threads"
   SFGetData32 (sptr);  //  "memcache_conn_yields"
   SFGetData64 (sptr);  //  "memcache_bytes"
   SFGetData32 (sptr);  //  "memcache_curr_items"
   SFGetData32 (sptr);  //  "memcache_total_items"
   SFGetData32 (sptr);  //  "memcache_evictions"
}

void
SFParseCounters_http (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "http_method_option_count"
   SFGetData32 (sptr);  //  "http_method_get_count"
   SFGetData32 (sptr);  //  "http_method_head_count"
   SFGetData32 (sptr);  //  "http_method_post_count"
   SFGetData32 (sptr);  //  "http_method_put_count"
   SFGetData32 (sptr);  //  "http_method_delete_count"
   SFGetData32 (sptr);  //  "http_method_trace_count"
   SFGetData32 (sptr);  //  "http_methd_connect_count"
   SFGetData32 (sptr);  //  "http_method_other_count"
   SFGetData32 (sptr);  //  "http_status_1XX_count"
   SFGetData32 (sptr);  //  "http_status_2XX_count"
   SFGetData32 (sptr);  //  "http_status_3XX_count"
   SFGetData32 (sptr);  //  "http_status_4XX_count"
   SFGetData32 (sptr);  //  "http_status_5XX_count"
   SFGetData32 (sptr);  //  "http_status_other_count"
}

void
SFParseCounters_CAL (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "transactions"
   SFGetData32 (sptr);  //  "errors"
   SFGetData64 (sptr);  //  "duration_uS"
}


static void
SFLengthCheck(SFSample *sample, u_char *start, int len) 
{
  uint32_t actualLen = (u_char *)sample->datap - start;
  uint32_t adjustedLen = ((len + 3) >> 2) << 2;
  if(actualLen != adjustedLen) {
    SFABORT(sample, SF_ABORT_LENGTH_ERROR);
  }
}

/* define my own IP header struct - to ease portability */
struct SFmyiphdr {
    uint8_t version_and_headerLen;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

/* same for tcp */
struct SFmytcphdr
  {
    uint16_t th_sport;          /* source port */
    uint16_t th_dport;          /* destination port */
    uint32_t th_seq;            /* sequence number */
    uint32_t th_ack;            /* acknowledgement number */
    uint8_t th_off_and_unused;
    uint8_t th_flags;
    uint16_t th_win;            /* window */
    uint16_t th_sum;            /* checksum */
    uint16_t th_urp;            /* urgent pointer */
};

/* and UDP */
struct SFmyudphdr {
  uint16_t uh_sport;           /* source port */
  uint16_t uh_dport;           /* destination port */
  uint16_t uh_ulen;            /* udp length */
  uint16_t uh_sum;             /* udp checksum */
};

/* and ICMP */
struct SFmyicmphdr
{
  uint8_t type;         /* message type */
  uint8_t code;         /* type sub-code */
  /* ignore the rest */
};


static void 
SFDecodeIPV4(SFSample *sptr)
{
   if (sptr->gotIPV4) {
      u_char *ptr = sptr->header + sptr->offsetToIPV4;
      /* Create a local copy of the IP header (cannot overlay structure in case it is not quad-aligned...some
          platforms would core-dump if we tried that).   It's OK coz this probably performs just as well anyway. */
      struct SFmyiphdr ip;
      memcpy(&ip, ptr, sizeof(ip));
      /* Value copy all ip elements into sptr */
      sptr->ipsrc.type = SFLADDRESSTYPE_IP_V4;
      sptr->ipsrc.address.ip_v4.addr = ip.saddr;
      sptr->ipdst.type = SFLADDRESSTYPE_IP_V4;
      sptr->ipdst.address.ip_v4.addr = ip.daddr;
      sptr->dcd_ipProtocol = ip.protocol;
      sptr->dcd_ipTos = ip.tos;
      sptr->dcd_ipTTL = ip.ttl;
      sptr->ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
      if(sptr->ip_fragmentOffset > 0) {
      } else {
         /* advance the pointer to the next protocol layer */
         /* ip headerLen is expressed as a number of quads */
         ptr += (ip.version_and_headerLen & 0x0f) * 4;
         SFDecodeIPLayer4(sptr, ptr);
      }
   }
}


static void 
SFDecodeIPV6(SFSample *sptr)
{
// uint16_t payloadLen;
   uint32_t label;
   uint32_t nextHeader;
   u_char *end = sptr->header + sptr->headerLen;

   if(sptr->gotIPV6) {
      u_char *ptr = sptr->header + sptr->offsetToIPV6;
      int ipVersion = (*ptr >> 4);
      
      if(ipVersion != 6)
         return;

      // get the tos (priority)
      sptr->dcd_ipTos = *ptr++ & 15;
      // 24-bit label
      label = *ptr++;
      label <<= 8;
      label += *ptr++;
      label <<= 8;
      label += *ptr++;
      // payload
      // payloadLen = (ptr[0] << 8) + ptr[1];
      ptr += 2;
      // next header
      nextHeader = *ptr++;

      // TTL
      sptr->dcd_ipTTL = *ptr++;

      sptr->ipsrc.type = SFLADDRESSTYPE_IP_V6;
      memcpy(&sptr->ipsrc.address, ptr, 16);
      ptr +=16;
      sptr->ipdst.type = SFLADDRESSTYPE_IP_V6;
      memcpy(&sptr->ipdst.address, ptr, 16);
      ptr +=16;

      // skip over some common header extensions...
      // http://searchnetworking.techtarget.com/originalContent/0,289142,sid7_gci870277,00.html
      while(nextHeader == 0 ||   // hop
      nextHeader == 43 || // routing
      nextHeader == 44 || // fragment
      // nextHeader == 50 || // encryption - don't bother coz we'll not be able to read any further
      nextHeader == 51 || // auth
      nextHeader == 60) { // destination options
         uint32_t optionLen, skip;
         nextHeader = ptr[0];
         optionLen = 8 * (ptr[1] + 1);   // second byte gives option len in 8-byte chunks, not counting first 8
         skip = optionLen - 2;
         ptr += skip;
         if(ptr > end) return; // ran off the end of the header
      }
      
      // now that we have eliminated the extension headers, nextHeader should have what we want to
      // remember as the ip protocol...
      sptr->dcd_ipProtocol = nextHeader;
      SFDecodeIPLayer4(sptr, ptr);
   }
}

static void 
SFDecodeIPLayer4(SFSample *sptr, u_char *ptr)
{
   u_char *end = sptr->header + sptr->headerLen;
   if (ptr > (end - 8)) {
      // not enough header bytes left
      return;
   }
   switch (sptr->dcd_ipProtocol) {
      case IPPROTO_ICMP: { /* ICMP */
         struct SFmyicmphdr icmp;
         memcpy(&icmp, ptr, sizeof(icmp));
         sptr->dcd_sport = icmp.type;
         sptr->dcd_dport = icmp.code;
         sptr->offsetToPayload = ptr + sizeof(icmp) - sptr->header;
         break;
      }
      case IPPROTO_TCP: { /* TCP */
         struct SFmytcphdr tcp;
         int headerBytes;
         memcpy(&tcp, ptr, sizeof(tcp));
         sptr->dcd_sport = ntohs(tcp.th_sport);
         sptr->dcd_dport = ntohs(tcp.th_dport);
         sptr->dcd_tcpFlags = tcp.th_flags;
         headerBytes = (tcp.th_off_and_unused >> 4) * 4;
         ptr += headerBytes;
         sptr->offsetToPayload = ptr - sptr->header;
         break;
      }
      case IPPROTO_UDP: { /* UDP */
         struct SFmyudphdr udp;
         memcpy(&udp, ptr, sizeof(udp));
         sptr->dcd_sport = ntohs(udp.uh_sport);
         sptr->dcd_dport = ntohs(udp.uh_dport);
         sptr->udp_pduLen = ntohs(udp.uh_ulen);
         sptr->offsetToPayload = ptr + sizeof(udp) - sptr->header;
         break;
      }

      default: /* some other protcol */
         sptr->offsetToPayload = ptr - sptr->header;
         break;
   }
}



#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500
 
#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct SFmyiphdr))


static void
SFDecodeLinkLayer(SFSample *sample)
{
   u_char *start = (u_char *)sample->header;
   u_char *end = start + sample->headerLen;
   u_char *ptr = start;
   uint16_t type_len;

   /* assume not found */
   sample->gotIPV4 = ARGUS_FALSE;
   sample->gotIPV6 = ARGUS_FALSE;

   if (sample->headerLen < NFT_ETHHDR_SIZ) return; /* not enough for an Ethernet header */

   memcpy(sample->eth_dst, ptr, 6);
   ptr += 6;

   memcpy(sample->eth_src, ptr, 6);
   ptr += 6;
   type_len = (ptr[0] << 8) + ptr[1];
   ptr += 2;

   if (type_len == 0x8100) {
      /* VLAN   - next two bytes */
      uint32_t vlanData = (ptr[0] << 8) + ptr[1];
      uint32_t vlan = vlanData & 0x0fff;
      ptr += 2;
      /*   _____________________________________ */
      /* |    pri   | c |             vlan-id            | */
      /*   ------------------------------------- */
      /* [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] */
      sample->in_vlan = vlan;
      /* now get the type_len again (next two bytes) */
      type_len = (ptr[0] << 8) + ptr[1];
      ptr += 2;
   }

   /* now we're just looking for IP */
   if (sample->headerLen < NFT_MIN_SIZ) return; /* not enough for an IPv4 header */
   
   /* peek for IPX */
   if(type_len == 0x0200 || type_len == 0x0201 || type_len == 0x0600) {
#define IPX_HDR_LEN 30
#define IPX_MAX_DATA 546
      int ipxChecksum = (ptr[0] == 0xff && ptr[1] == 0xff);
      int ipxLen = (ptr[2] << 8) + ptr[3];
      if (ipxChecksum &&
          ipxLen >= IPX_HDR_LEN &&
          ipxLen <= (IPX_HDR_LEN + IPX_MAX_DATA))
         /* we don't do anything with IPX here */
         return;
   } 
   
   if (type_len <= NFT_MAX_8023_LEN) {
      /* assume 802.3+802.2 header */
      /* check for SNAP */
      if (ptr[0] == 0xAA && ptr[1] == 0xAA && ptr[2] == 0x03) {
         ptr += 3;
         if (ptr[0] != 0 || ptr[1] != 0 || ptr[2] != 0) {
            return; /* no further decode for vendor-specific protocol */
         }
         ptr += 3;
         /* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
         type_len = (ptr[0] << 8) + ptr[1];
         ptr += 2;
      }
      else {
         if (ptr[0] == 0x06 &&
       ptr[1] == 0x06 &&
       (ptr[2] & 0x01)) {
    /* IP over 8022 */
    ptr += 3;
    /* force the type_len to be IP so we can inline the IP decode below */
    type_len = 0x0800;
         }
         else return;
      }
   }
   
   /* assume type_len is an ethernet-type now */
   sample->eth_type = type_len;

   if (type_len == 0x0800) {
      /* IPV4 */
      if((end - ptr) < sizeof(struct SFmyiphdr)) return;
      /* look at first byte of header.... */
      /*   ___________________________ */
      /* |    version    |      hdrlen    | */
      /*   --------------------------- */
      if((*ptr >> 4) != 4) return; /* not version 4 */
      if((*ptr & 15) < 5) return; /* not IP (hdr len must be 5 quads or more) */
      /* survived all the tests - store the offset to the start of the ip header */
      sample->gotIPV4 = ARGUS_TRUE;
      sample->offsetToIPV4 = (ptr - start);
   }

   if (type_len == 0x86DD) {
      /* IPV6 */
      /* look at first byte of header.... */
      if((*ptr >> 4) != 6) return; /* not version 6 */
      /* survived all the tests - store the offset to the start of the ip6 header */
      sample->gotIPV6 = ARGUS_TRUE;
      sample->offsetToIPV6 = (ptr - start);
   }
}


#define WIFI_MIN_HDR_SIZ 24

static void
SFDecode80211MAC(SFSample *sample)
{
   u_char *start = (u_char *)sample->header;
// u_char *end = start + sample->headerLen;
   u_char *ptr = start;

   /* assume not found */
   sample->gotIPV4 = ARGUS_FALSE;
   sample->gotIPV6 = ARGUS_FALSE;

   if(sample->headerLen < WIFI_MIN_HDR_SIZ) return; /* not enough for an 80211 MAC header */

   uint32_t fc = (ptr[1] << 8) + ptr[0];   // [b7..b0][b15..b8]
// uint32_t protocolVersion = fc & 3;
   uint32_t control = (fc >> 2) & 3;
// uint32_t subType = (fc >> 4) & 15;
   uint32_t toDS = (fc >> 8) & 1;
   uint32_t fromDS = (fc >> 9) & 1;
// uint32_t moreFrag = (fc >> 10) & 1;
// uint32_t retry = (fc >> 11) & 1;
// uint32_t pwrMgt = (fc >> 12) & 1;
// uint32_t moreData = (fc >> 13) & 1;
// uint32_t encrypted = (fc >> 14) & 1;
// uint32_t order = fc >> 15;

   ptr += 2;

// uint32_t duration_id = (ptr[1] << 8) + ptr[0]; // not in network byte order either?
   ptr += 2;

   switch (control) {
      case 0: // mgmt
      case 1: // ctrl
      case 3: // rsvd
         break;

      case 2: {    // data
         u_char *macAddr1 = ptr;
         ptr += 6;
         u_char *macAddr2 = ptr;
         ptr += 6;
         u_char *macAddr3 = ptr;
         ptr += 6;
//       uint32_t sequence = (ptr[0] << 8) + ptr[1];
         ptr += 2;

         // ToDS    FromDS    Addr1    Addr2   Addr3    Addr4
         // 0         0            DA         SA       BSSID    N/A (ad-hoc)
         // 0         1            DA         BSSID   SA         N/A
         // 1         0            BSSID    SA       DA         N/A
         // 1         1            RA         TA       DA         SA   (wireless bridge)

         u_char *srcMAC = NULL;
         u_char *dstMAC = NULL;

         if(toDS) {
            dstMAC = macAddr3;
            if(fromDS) {
               srcMAC = ptr; // macAddr4.   1,1 => (wireless bridge)
               ptr += 6;
            } else
               srcMAC = macAddr2;   // 1,0
         } else {
            dstMAC = macAddr1;
            if (fromDS)
               srcMAC = macAddr3; // 0,1
            else
               srcMAC = macAddr2; // 0,0
         }

         if(srcMAC)
            memcpy(sample->eth_src, srcMAC, 6);
         if(dstMAC) 
            memcpy(sample->eth_dst, srcMAC, 6);
         break;
      }
   }
}
