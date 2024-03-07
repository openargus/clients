/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/include/argus_cluster.h#17 $
 * $DateTime: 2016/10/10 23:14:45 $
 * $Change: 3219 $
 */

#ifndef ArgusCluster_h
#define ArgusCluster_h

#ifdef __cplusplus
extern "C" {
#endif

#if defined(ARGUS_PCRE)
#include "pcreposix.h"
#else
#include <regex.h>
#endif

struct RaFlowModelStruct {
   char *desc;  
   int pindex, mindex; 
   int preserve, report, autocorrect;
   int *histotimevalues;
   int histostart, histoend, histobins;
   int histotimeseries;
    
   struct RaPolicyStruct **policy; 
   struct RaPolicyStruct **model; 
};
 
struct RaPolicyStruct {
   u_int RaEntryType, RaPolicyId;
   u_int RaModelId, ArgusTimeout, ArgusIdleTimeout;
   struct ArgusFlow flow;
   char *str; 
};  

struct ArgusIPAddrStruct {
   union {
      u_int ipv4;
      u_int ipv6[4];
   } addr_un;
};

#define ARGUS_AGGREGATOR_DIRTY	1
#define ARGUS_CREATE_AUTOID	2

#define ARGUS_RECORD_AGGREGATOR	1
#define ARGUS_OBJ_AGGREGATOR	2
 
struct ArgusAggregatorStruct {
   struct ArgusAggregatorStruct *nxt;
   char *name, *pres, *report, *correct;
   int status, statusint, idleint;
   int AbsoluteValue;

   char *modeStr;

   long long ArgusTotalNewFlows;
   long long ArgusTotalClosedFlows;
   long long ArgusTotalSends;
   long long ArgusTotalBadSends;
   long long ArgusTotalUpdates;
   long long ArgusTotalCacheHits;

   struct ArgusRecordStruct *argus;

   long long mask, cont;
   int saddrlen, daddrlen, iaddrlen;
   struct ArgusIPAddrStruct smask, dmask, imask;

   struct RaPolicyStruct *drap, *rap;
   struct RaFlowModelStruct *fmodel;
   struct ArgusModeStruct *ArgusModeList, *ArgusMaskList;
   struct ArgusMaskStruct *ArgusMaskDefs;
   struct ArgusQueueStruct *queue, *timeout;
   struct ArgusHashTable *htable;
   struct ArgusHashStruct hstruct;
   struct ArgusSystemFlow fstruct;

   char *filterstr;
   struct nff_program filter;

   char *modelstr;
   char *grepstr;
   char *labelstr;
   regex_t lpreg;

   char *estr;
   regex_t upreg;

   double (*RaMetricFetchAlgorithm)(struct ArgusRecordStruct *);
   unsigned char ArgusMetricIndex, ArgusMatrixMode, ArgusRmonMode, ArgusAgMode;
};


#define NLI			-1

#define ARGUS_MAX_MASK_LIST	41

#define ARGUS_MASK_SRCID	0
#define ARGUS_MASK_SID      	1
#define ARGUS_MASK_SRCID_INF	2
 
#define ARGUS_MASK_SMPLS	3
#define ARGUS_MASK_DMPLS	4
#define ARGUS_MASK_SVLAN	5
#define ARGUS_MASK_DVLAN	6
 
#define ARGUS_MASK_PROTO	7
#define ARGUS_MASK_SADDR	8
#define ARGUS_MASK_SPORT	9
#define ARGUS_MASK_DADDR	10
#define ARGUS_MASK_DPORT	11
 
#define ARGUS_MASK_SNET		12
#define ARGUS_MASK_DNET		13
 
#define ARGUS_MASK_STOS		14
#define ARGUS_MASK_DTOS		15
#define ARGUS_MASK_STTL		16
#define ARGUS_MASK_DTTL		17
#define ARGUS_MASK_SIPID	18
#define ARGUS_MASK_DIPID	19
 
#define ARGUS_MASK_STCPB	20
#define ARGUS_MASK_DTCPB	21

#define ARGUS_MASK_SMAC		22
#define ARGUS_MASK_DMAC		23

#define ARGUS_MASK_SVID		24
#define ARGUS_MASK_DVID		25
#define ARGUS_MASK_SVPRI	26
#define ARGUS_MASK_DVPRI	27
#define ARGUS_MASK_SVC		28
 
#define ARGUS_MASK_INODE	29

#define ARGUS_MASK_SDSB		30
#define ARGUS_MASK_DDSB		31
#define ARGUS_MASK_SCO 		32
#define ARGUS_MASK_DCO 		33
#define ARGUS_MASK_SAS 		34
#define ARGUS_MASK_DAS 		35
#define ARGUS_MASK_IAS 		36
#define ARGUS_MASK_SOUI		37
#define ARGUS_MASK_DOUI		38
#define ARGUS_MASK_ETYPE	39

#define ARGUS_MASK_STIME	40


#define ARGUS_MASK_SRCID_INDEX	(0x1 << ARGUS_MASK_SRCID)
#define ARGUS_MASK_INF_INDEX	(0x1 << ARGUS_MASK_SRCID_INF)
 
#define ARGUS_MASK_SMPLS_INDEX	(0x1 << ARGUS_MASK_SMPLS)
#define ARGUS_MASK_DMPLS_INDEX	(0x1 << ARGUS_MASK_DMPLS)
#define ARGUS_MASK_SVLAN_INDEX	(0x1 << ARGUS_MASK_SVLAN)
#define ARGUS_MASK_DVLAN_INDEX	(0x1 << ARGUS_MASK_DVLAN)
 
#define ARGUS_MASK_PROTO_INDEX	(0x1 << ARGUS_MASK_PROTO)
#define ARGUS_MASK_SADDR_INDEX	(0x1 << ARGUS_MASK_SADDR)
#define ARGUS_MASK_SPORT_INDEX	(0x1 << ARGUS_MASK_SPORT)
#define ARGUS_MASK_DADDR_INDEX	(0x1 << ARGUS_MASK_DADDR)
#define ARGUS_MASK_DPORT_INDEX	(0x1 << ARGUS_MASK_DPORT)
 
#define ARGUS_MASK_SNET_INDEX	(0x1 << ARGUS_MASK_SNET)
#define ARGUS_MASK_DNET_INDEX	(0x1 << ARGUS_MASK_DNET)
 
#define ARGUS_MASK_STOS_INDEX	(0x1 << ARGUS_MASK_STOS)
#define ARGUS_MASK_DTOS_INDEX	(0x1 << ARGUS_MASK_DTOS)
#define ARGUS_MASK_STTL_INDEX	(0x1 << ARGUS_MASK_STTL)
#define ARGUS_MASK_DTTL_INDEX	(0x1 << ARGUS_MASK_DTTL)
#define ARGUS_MASK_SIPID_INDEX	(0x1 << ARGUS_MASK_SIPID)
#define ARGUS_MASK_DIPID_INDEX	(0x1 << ARGUS_MASK_DIPID)
 
#define ARGUS_MASK_STCPB_INDEX	(0x1 << ARGUS_MASK_STCPB)
#define ARGUS_MASK_DTCPB_INDEX	(0x1 << ARGUS_MASK_DTCPB)

#define ARGUS_MASK_SDSB_INDEX	(0x1 << ARGUS_MASK_SDSB)
#define ARGUS_MASK_DDSB_INDEX	(0x1 << ARGUS_MASK_DDSB)

#define ARGUS_MASK_SVC_INDEX	(0x1 << ARGUS_MASK_SVC)
#define ARGUS_MASK_INODE_INDEX	(0x1 << ARGUS_MASK_INODE)

#define ARGUS_MASK_SCO_INDEX	(0x1 << ARGUS_MASK_SCO)
#define ARGUS_MASK_DCO_INDEX	(0x1 << ARGUS_MASK_DCO)

#define ARGUS_MASK_SAS_INDEX	(0x1 << ARGUS_MASK_SAS)
#define ARGUS_MASK_DAS_INDEX	(0x1 << ARGUS_MASK_DAS)

#define ARGUS_MASK_SOUI_INDEX	(0x1 << ARGUS_MASK_SOUI)
#define ARGUS_MASK_DOUI_INDEX	(0x1 << ARGUS_MASK_DOUI)

#define ARGUS_MASK_ETYPE_INDEX	(0x1 << ARGUS_MASK_ETYPE)

#define ARGUS_MASK_STIME_INDEX	(0x1 << ARGUS_MASK_STIME)

struct ArgusMaskStruct {
   char *name, slen;
   int dsr, offset, len, index;
};

#if defined(ARGUS_MAIN)
struct ArgusMaskStruct ArgusSrcIdMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL},
   {NULL}
};
struct ArgusMaskStruct ArgusIpV4MaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      14,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      16,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  4, ARGUS_MAC_INDEX,       10,  3, 1},
   {"doui",  4, ARGUS_MAC_INDEX,        4,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};

struct ArgusMaskStruct ArgusIpV4RevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      16,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      14,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  2, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  4, ARGUS_MAC_INDEX,        4,  3, 1},
   {"doui",  4, ARGUS_MAC_INDEX,       10,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};

struct ArgusMaskStruct ArgusIpV6MaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       4, 16, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      40,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      20, 16, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      42,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  4, ARGUS_MAC_INDEX,       10,  3, 1},
   {"doui",  4, ARGUS_MAC_INDEX,        4,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};
 
struct ArgusMaskStruct ArgusIpV6RevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       4, 16, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      40,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      20, 16, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      42,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  4, ARGUS_MAC_INDEX,        4,  3, 1},
   {"doui",  4, ARGUS_MAC_INDEX,       10,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};


struct ArgusMaskStruct ArgusIBLocalMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      14,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      16,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {NULL},
   {NULL},
   {NULL},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};


struct ArgusMaskStruct ArgusIBGlobalMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      14,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      16,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {NULL},
   {NULL},
   {NULL},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};


struct ArgusMaskStruct ArgusIBGlobalRevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,      12,  1, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      14,  2, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      16,  2, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {NULL},
   {NULL},
   {NULL},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};


struct ArgusMaskStruct ArgusArpMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       2,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,       8,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};



struct ArgusMaskStruct ArgusArpRevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       2,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  2, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};


struct ArgusMaskStruct ArgusRarpMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};


struct ArgusMaskStruct ArgusRarpRevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};


struct ArgusMaskStruct ArgusEtherMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  6, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  6, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  6, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  6, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};

struct ArgusMaskStruct ArgusEtherRevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  6, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  6, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};


struct ArgusMaskStruct ArgusWlanMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  6, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      32, 32, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  6, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,      24,  6, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};

struct ArgusMaskStruct ArgusWlanRevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,      32, 32, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};

struct ArgusMaskStruct ArgusIsisMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};


struct ArgusMaskStruct ArgusIsisRevMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};


struct ArgusMaskStruct ArgusIsisHelloMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};

struct ArgusMaskStruct ArgusIsisLspMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};


struct ArgusMaskStruct ArgusIsisCsnpMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};


struct ArgusMaskStruct ArgusIsisPsnpMaskDefs[ARGUS_MAX_MASK_LIST] = {
   {"srcid", 5, ARGUS_TRANSPORT_INDEX,  4, 20, 1},
   {"sid",   5, ARGUS_TRANSPORT_INDEX,  4, 16, 1},
   {"inf",   3, ARGUS_TRANSPORT_INDEX,  20, 4, 1},
   {"smpls", 5, ARGUS_MPLS_INDEX,       8,  4, 1},
   {"dmpls", 5, ARGUS_MPLS_INDEX,       4,  4, 1},
   {"svlan", 5, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvlan", 5, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"proto", 5, ARGUS_FLOW_INDEX,       4,  2, 1},
   {"saddr", 5, ARGUS_FLOW_INDEX,      12,  4, 1},
   {"sport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"daddr", 5, ARGUS_FLOW_INDEX,      16,  4, 1},
   {"dport", 5, ARGUS_FLOW_INDEX,       0,  0, 1},
   {"snet",  4, ARGUS_FLOW_INDEX,       8,  4, 1},
   {"dnet",  4, ARGUS_FLOW_INDEX,       4,  4, 1},
   {"stos",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"dtos",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sttl",  4, ARGUS_IPATTR_INDEX,    12,  1, 1},
   {"dttl",  4, ARGUS_IPATTR_INDEX,     4,  1, 1},
   {"sipid", 4, ARGUS_IPATTR_INDEX,    14,  2, 1},
   {"dipid", 4, ARGUS_IPATTR_INDEX,     6,  2, 1},
   {"stcpb", 5, ARGUS_NETWORK_INDEX,  252,  4, 1},
   {"dtcpb", 5, ARGUS_NETWORK_INDEX,  300,  4, 1},
   {"smac",  4, ARGUS_MAC_INDEX,       10,  6, 1},
   {"dmac",  4, ARGUS_MAC_INDEX,        4,  6, 1},
   {"svid",  4, ARGUS_VLAN_INDEX,       6,  2, 1},
   {"dvid",  4, ARGUS_VLAN_INDEX,       4,  2, 1},
   {"svpri", 5, ARGUS_VLAN_INDEX,       6,  1, 1},
   {"dvpri", 5, ARGUS_VLAN_INDEX,       4,  1, 1},
   {"svc",   3, ARGUS_LABEL_INDEX,      4, 16, 1},
   {"inode", 5, ARGUS_ICMP_INDEX,      24,  4, 1},
   {"sdsb",  4, ARGUS_IPATTR_INDEX,    13,  1, 1},
   {"ddsb",  4, ARGUS_IPATTR_INDEX,     5,  1, 1},
   {"sco",   3, ARGUS_COCODE_INDEX,     6,  2, 1},
   {"dco",   3, ARGUS_COCODE_INDEX,     4,  2, 1},
   {"sas",   3, ARGUS_ASN_INDEX,        8,  4, 1},
   {"das",   3, ARGUS_ASN_INDEX,        4,  4, 1},
   {"ias",   3, ARGUS_ASN_INDEX,       12,  4, 1},
   {"soui",  3, ARGUS_MAC_INDEX,       10,  3, 1},
   {"doui",  3, ARGUS_MAC_INDEX,        4,  3, 1},
   {"etype", 5, ARGUS_MAC_INDEX,       16,  2, 1},
   {"stime", 5, ARGUS_TIME_INDEX,       4,  8, 1},
};

struct ArgusAggregatorStruct *ArgusNewAggregator (struct ArgusParserStruct *, char *, int type);
struct ArgusAggregatorStruct *ArgusCopyAggregator (struct ArgusAggregatorStruct *);
void ArgusDeleteAggregator (struct ArgusParserStruct *, struct ArgusAggregatorStruct *);
struct RaPolicyStruct *RaFlowModelOverRides(struct ArgusAggregatorStruct *, struct ArgusRecordStruct *);
void ArgusGenerateNewFlow(struct ArgusAggregatorStruct *, struct ArgusRecordStruct *);

void RaMatrixNormalizeEtherAddrs (struct ArgusRecordStruct *ns);
 
unsigned int ArgusMergeAddress(unsigned int *, unsigned int *, int, int, unsigned char *);
void ArgusMergeRecords (const struct ArgusAggregatorStruct * const,
                        struct ArgusRecordStruct *, struct ArgusRecordStruct *);
void ArgusReplaceRecords (struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);
void ArgusIntersectRecords (struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);

#else
extern struct ArgusMaskStruct ArgusIpV4MaskDefs[ARGUS_MAX_MASK_LIST];
extern struct ArgusMaskStruct ArgusIpV6MaskDefs[ARGUS_MAX_MASK_LIST];
extern struct ArgusMaskStruct ArgusEtherMaskDefs[ARGUS_MAX_MASK_LIST];
extern struct ArgusMaskStruct ArgusArpMaskDefs[ARGUS_MAX_MASK_LIST];

extern struct ArgusMaskStruct ArgusIpV4RevMaskDefs[ARGUS_MAX_MASK_LIST];
extern struct ArgusMaskStruct ArgusIpV6RevMaskDefs[ARGUS_MAX_MASK_LIST];
extern struct ArgusMaskStruct ArgusEtherRevMaskDefs[ARGUS_MAX_MASK_LIST];
extern struct ArgusMaskStruct ArgusArpRevMaskDefs[ARGUS_MAX_MASK_LIST];

extern struct ArgusAggregatorStruct *ArgusNewAggregator (struct ArgusParserStruct *, char *, int type);
extern struct ArgusAggregatorStruct *ArgusCopyAggregator (struct ArgusAggregatorStruct *);
extern void ArgusDeleteAggregator (struct ArgusParserStruct *, struct ArgusAggregatorStruct *);
extern struct RaPolicyStruct *RaFlowModelOverRides(struct ArgusAggregatorStruct *, struct ArgusRecordStruct *);
extern void ArgusGenerateNewFlow(struct ArgusAggregatorStruct *, struct ArgusRecordStruct *);

extern void RaMatrixNormalizeEtherAddrs (struct ArgusRecordStruct *ns);
 
extern unsigned int ArgusMergeAddress(unsigned int *, unsigned int *, int, int, unsigned char *);
extern void ArgusMergeRecords (const struct ArgusAggregatorStruct * const,
                               struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern void ArgusReplaceRecords (struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern void ArgusIntersectRecords (struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);

#endif
#ifdef __cplusplus
}
#endif
#endif


