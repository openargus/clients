/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/include/argus_util.h#41 $
 * $DateTime: 2016/11/30 00:54:11 $
 * $Change: 3245 $
 */

#ifndef ArgusUtil_h
#define ArgusUtil_h

#ifdef __cplusplus
extern "C" {
#endif

#include <argus_os.h>
#include <argus_compat.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>

#if defined(ARGUS_THREADS)
#include <pthread.h>
#endif

#include <argus_def.h>
#include <argus_out.h>

#include <argus/cons_out.h>
#include <argus/cflowd.h>

#define ARGUS_MAX_PRINT_ALG     	255
#define MAX_PRINT_ALG_TYPES     	255


#include <argus/CflowdFlowPdu.h>

typedef void (*proc)(void);
typedef char *(*strproc)(void);

struct ArgusQueueHeader {
   struct ArgusQueueHeader *nxt;
   struct ArgusQueueHeader *prv;
   struct ArgusQueueStruct *queue;
   struct timeval lasttime, logtime;
};

struct ArgusMemoryHeader {
   struct ArgusMemoryHeader *nxt, *prv;
#if defined(__GNUC__)
   void *frame[3];
#endif
   unsigned int tag;
   unsigned short len;
   unsigned short offset;
};

struct ArgusMemoryList {
   struct ArgusMemoryHeader *start, *end;
#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
#endif
   int total, count, size;
   int out, in, freed;
};

struct ArgusQueueStruct {
   unsigned int count, status, arraylen;
#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
#endif
   struct ArgusQueueHeader *start, *end;
   struct ArgusQueueHeader **array;
};

struct anamemem {
   struct anamemem *n_nxt;
   unsigned int status, hashval, secs, ref;
   char *name, *alias;
};

struct gnamemem {
   struct gnamemem *g_nxt;
   unsigned int status, hashval, secs, ref;
   char *name;
   void *group;
};

struct snamemem {
   struct snamemem *s_nxt;
   unsigned int status, hashval, secs, ref;
   char *name;
   void *service;
};

struct dbtblmem {
   struct dbtblmem *p_nxt;
   unsigned int hashval;
   char *name;
};

struct cnamemem {
   struct cnamemem *n_nxt;
   unsigned int status, hashval, secs, ref;
   char *name;
   unsigned int type;
   struct ArgusAddrStruct addr;
   struct RaAddressStruct *node;
};

struct nnamemem {
   struct nnamemem *n_nxt;
   unsigned int status, hashval, ref, index;
   struct timeval stime, rtime, ltime;

   char *n_name, *d_name, *tld_name;
   struct ArgusListStruct *refers;
   struct ArgusListStruct *cidrs;
   struct ArgusListStruct *cnames;
   struct ArgusListStruct *aliases;
   struct ArgusListStruct *ptrs;
   struct ArgusListStruct *mxs;
   struct ArgusListStruct *servers;
   struct ArgusListStruct *clients;
};

#define e_bs e_nsap        /* for byestringtable */

struct enamemem {
   struct enamemem *e_nxt;
   int category, rank, loc;

   u_int16_t e_addr[3];
   u_int16_t masklen;

   char *e_oui;
   char *e_name;
   char *e_numeric;
   char *e_ouiname;
   u_char *e_nsap;         /* used only for nsaptable[] */

   struct RaAddressStruct *addrs;
};

struct protoidmem {
   struct protoidmem *p_nxt;
   u_int p_oui;
   arg_uint16 p_proto;
   char *p_name;
};

#include <argus_parser.h>
#include <argus_cluster.h>

#if defined(__OpenBSD__)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

#include <netinet/ip_icmp.h>
#undef ICMP_MAXTYPE
#define ICMP_MAXTYPE	46

 
struct ArgusFileEntry {
   struct ArgusFileEntry *nxt;
   char *str;
};

 
#define ARGUS_NOLOCK            0x00
#define ARGUS_LOCK              0x01
#define ARGUS_NOSORT            0x02

#define ARGUS_RFILE_LIST        1
#define ARGUS_WFILE_LIST        2
#define ARGUS_DEVICE_LIST       3
#define ARGUS_OUTPUT_LIST       4
#define ARGUS_MODE_LIST         5
#define ARGUS_STRING_LIST       6
#define ARGUS_RR_LIST           7
#define ARGUS_EVENT_LIST        8
#define ARGUS_OBJECT_LIST       9

struct ArgusListObjectStruct {
   struct ArgusListObjectStruct *nxt, *prv;
   unsigned int status;
   union {
      void *obj;
      unsigned int val;
   } list_union;
};

#define list_obj	list_union.obj
#define list_val	list_union.val
 
struct ArgusListRecord {
   struct ArgusListObjectStruct *nxt, *prv;
   struct ArgusRecordHeader argus;
};
 
struct ArgusListStruct {
   struct ArgusListObjectStruct *start;
   struct ArgusListObjectStruct *end;
#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
   pthread_cond_t cond;
#endif
   struct timeval outputTime, reportTime;
   unsigned int count;
};

struct ArgusPrintFieldStruct {
   char *field, *format;
   int length, index, type, value;
   void (*print)(struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
   void (*label)(struct ArgusParserStruct *, char *, int);
   char *dbformat, *pformat;
   int offset, pair, attr;
};


#define ARGUS_DNS_REQUEST_NAME		0x01
#define ARGUS_DNS_REQUEST_ADDR_V4	0x02
#define ARGUS_DNS_REQUEST_ADDR_V6	0x04

struct ArgusDNSRequest {
   int status, type;
   union {
      char *name;
      u_int ipv4;
      struct in6_addr ipv6;
   } request;
};

#define reqName	request.name
#define reqIPv4	request.ipv4
#define reqIPv6	request.ipv6

/*
 * hash tables for whatever-to-name translations
 */

struct h6namemem {
   struct h6namemem *nxt;
   int sec;
   struct in6_addr addr;
   char *name;
};

struct hnamemem {
   struct hnamemem *nxt;
   int sec;
   char *name, *nname;
   u_int addr, status;
};

struct evendmem {
   struct evendmem *nxt;
   u_int addr;
   char *name;
};

enum argus_file_sort_e {
   ARGUS_FILES_NOSORT = 0,
   ARGUS_FILES_SORT = 1,
};


struct ArgusRecord *ArgusNetFlowCallRecord (struct ArgusParserStruct *, struct ArgusInput *, u_char **, int *);
struct ArgusRecord *ArgusNetFlowDetailInt  (struct ArgusParserStruct *, struct ArgusInput *, u_char **, int *);
struct ArgusRecord *ArgusParseCiscoRecord (struct ArgusParserStruct *, struct ArgusInput *, u_char **, int *);

#ifdef ARGUS_SASL
#include <sasl/sasl.h>
#endif

#include <sys/stat.h>
#include <stdio.h>

#define ARGUS_DATA_TYPE			0x3FF

#define ARGUS_DATA_SOURCE		0x01
#define ARGUS_V2_DATA_SOURCE		0x02
#define ARGUS_SFLOW_DATA_SOURCE		0x04
#define ARGUS_JFLOW_DATA_SOURCE		0x08
#define ARGUS_CISCO_DATA_SOURCE		0x10
#define ARGUS_DATAGRAM_SOURCE           0x20
#define ARGUS_IPFIX_DATA_SOURCE		0x40
#define ARGUS_FLOW_TOOLS_SOURCE		0x80

#define ARGUS_DOMAIN_SOURCE             0x100
#define ARGUS_NAMED_PIPE_SOURCE		0x200

#define ARGUS_BASELINE_SOURCE		0x800

#if defined(ARGUS_MYSQL)
#define ARGUS_DBASE_SOURCE		0x1000
#endif

#define ARGUS_MY_ADDRESS        	5
#define ARGUS_MY_NETWORK        	4


#define ARGUS_IPV4_UNICAST                      0x00010000
#define ARGUS_IPV4_UNICAST_THIS_NET             0x00010001
#define ARGUS_IPV4_UNICAST_PRIVATE              0x00010004
#define ARGUS_IPV4_UNICAST_LINK_LOCAL           0x00010006
#define ARGUS_IPV4_UNICAST_LOOPBACK             0x00010008
#define ARGUS_IPV4_UNICAST_TESTNET              0x00010010
#define ARGUS_IPV4_UNICAST_RESERVED             0x00010020

#define ARGUS_IPV4_MULTICAST                    0x00020000
#define ARGUS_IPV4_MULTICAST_LOCAL              0x00020001
#define ARGUS_IPV4_MULTICAST_INTERNETWORK       0x00020002

#define ARGUS_IPV4_MULTICAST_RESERVED           0x00020003
#define ARGUS_IPV4_MULTICAST_SDPSAP             0x00020004
#define ARGUS_IPV4_MULTICAST_NASDAQ             0x00020005
#define ARGUS_IPV4_MULTICAST_DIS                0x00020006
#define ARGUS_IPV4_MULTICAST_SRCSPEC            0x00020007
#define ARGUS_IPV4_MULTICAST_GLOP               0x00020008
#define ARGUS_IPV4_MULTICAST_ADMIN              0x00021000
#define ARGUS_IPV4_MULTICAST_SCOPED             0x00021100
#define ARGUS_IPV4_MULTICAST_SCOPED_ORG_LOCAL   0x00021101
#define ARGUS_IPV4_MULTICAST_SCOPED_SITE_LOCAL  0x00021104
#define ARGUS_IPV4_MULTICAST_SCOPED_REL         0x00021110

#define ARGUS_IPV4_MULTICAST_ADHOC              0x00020100
#define ARGUS_IPV4_MULTICAST_ADHOC_BLK1         0x00020101
#define ARGUS_IPV4_MULTICAST_ADHOC_BLK2         0x00020102
#define ARGUS_IPV4_MULTICAST_ADHOC_BLK3         0x00020103

#define ARGUS_IPV6_UNICAST                      0x00040000
#define ARGUS_IPV6_UNICAST_UNSPECIFIED          0x00040001
#define ARGUS_IPV6_UNICAST_LOOPBACK             0x00040002
#define ARGUS_IPV6_UNICAST_V4COMPAT             0x00040004
#define ARGUS_IPV6_UNICAST_V4MAPPED             0x00040008

#define ARGUS_IPV6_UNICAST_LINKLOCAL            0x00040010
#define ARGUS_IPV6_UNICAST_SITELOCAL            0x00040011

#define ARGUS_IPV6_MULTICAST                    0x00080000
#define ARGUS_IPV6_MULTICAST_NODELOCAL          0x00080001
#define ARGUS_IPV6_MULTICAST_LINKLOCAL          0x00080002
#define ARGUS_IPV6_MULTICAST_SITELOCAL          0x00080004
#define ARGUS_IPV6_MULTICAST_ORGLOCAL           0x00080008
#define ARGUS_IPV6_MULTICAST_GLOBAL             0x00080010


unsigned int RaIPv4AddressType(struct ArgusParserStruct *, unsigned int);
unsigned int RaIPv6AddressType(struct ArgusParserStruct *, struct in6_addr *);


#define ipaddr_string(p) ArgusGetName(ArgusParser, (u_char *)(p))

#include <stdarg.h>
static inline int
snprintf_append(char *str, size_t *len, size_t *remain, const char *fmt, ...)
{
   va_list ap;
   unsigned int c;

   va_start(ap, fmt);
   c = vsnprintf(str+(*len), *remain, fmt, ap);
   if (c > 0) {
      if (c <= *remain) {
         *remain -= c;
         *len += c;
      } else {
         *len += *remain;
         *remain = 0;
      }
   }
   va_end(ap);
   return c;
}

typedef int (*ResourceCallback)(struct ArgusParserStruct *, int, char *, int, int);

#define ARGUS_SOPTIONS_IGNORE	0
#define ARGUS_SOPTIONS_PROCESS	1

int RaParseOptHStr(const char * const);

#ifdef ArgusUtil

void ArgusHandleSig (int);

char *chroot_dir = NULL;
uid_t new_uid;
gid_t new_gid;


extern int ArgusDeletePIDFile (struct ArgusParserStruct *);
extern char *ArgusCreatePIDFile (struct ArgusParserStruct *, char *);

void ArgusMainInit (struct ArgusParserStruct *, int, char **);
int RaParseResourceFile (struct ArgusParserStruct *parser, char *file,
                         int enable_soptions, char *directives[], size_t items,
                         ResourceCallback cb);



int ArgusMkdirPath(const char * const);
int RaProcessRecursiveFiles (char *, int);

#define RAENVITEMS      2

char *RaResourceEnvStr [] = {
   "HOME",
   "ARGUSHOME",
};

char *RaOutputFilter = NULL;
char *RaHomePath = NULL;

int RaWriteOut = 1;
int ArgusSOptionRecord = 1;

long thiszone;

char *ArgusTrimString (char *str);
char *ArgusGetString (struct ArgusParserStruct *, u_char *, int);
char *ArgusGetUuidString (struct ArgusParserStruct *, u_char *, int);

void setArgusHashTableSize (struct ArgusParserStruct *, int);
void setArgusID(struct ArgusAddrStruct *, void *, int, unsigned int);
void setTransportArgusID(struct ArgusTransportStruct *, void *, int, unsigned int);
void setParserArgusID(struct ArgusParserStruct *, void *, int, unsigned int);

void setArgusManInf (struct ArgusParserStruct *, char *);
char *getArgusManInf (struct ArgusParserStruct *);

int getParserArgusID(struct ArgusParserStruct *, struct ArgusAddrStruct *);
unsigned int getArgusIDType(struct ArgusParserStruct *);
int ArgusCommonParseSourceID (struct ArgusAddrStruct *,
                              struct ArgusParserStruct *, char *);
void ArgusParseSourceID (struct ArgusParserStruct *, char *);

void ArgusPrintType (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintBssid (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSsid (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintCause (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintStartDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintLastDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcStartDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcLastDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstStartDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstLastDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintRelativeDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSourceID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintNode (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintInf (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintStatus (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintScore (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintFlags (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintMacAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcMacAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstMacAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcMacOuiAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstMacOuiAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintMacOuiAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcMacClass (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstMacClass (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintEtherType (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintProto (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintGreProto (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintGeneveProto (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintAddr (struct ArgusParserStruct *, char *, int, void *, int, unsigned char, int, int);
void ArgusPrintSrcNet (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintGreSrcAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintGeneveSrcAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcName (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcGroup (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstNet (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintGreDstAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintGeneveDstAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstName (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstGroup (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintLocalNet (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintLocalAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintRemoteNet (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintRemoteAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPort (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int, unsigned char, unsigned int, int, int);
void ArgusPrintSrcPort (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstPort (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDirection (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPackets (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcPackets (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstPackets (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintAppBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcAppBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstAppBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintProducerConsumerRatio (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintAppByteRatio (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintTransEfficiency (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcTransEfficiency (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstTransEfficiency (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintSrcIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveSrcIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveSrcIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveDstIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveDstIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleSrcIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleSrcIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleDstIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleDstIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveSrcIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveSrcIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveDstIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveDstIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleSrcIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleSrcIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleDstIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleDstIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintIntFlow (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIntFlowDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIntFlowStdDev (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIntFlowMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIntFlowMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintSrcJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveSrcJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintActiveDstJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleSrcJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleDstJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintState (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaStartTime (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaLastTime (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaSrcPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaDstPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaSrcBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDeltaDstBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDeltaSrcPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDeltaDstPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDeltaSrcBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDeltaDstBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcUserData (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstUserData (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintUserData (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPOptions (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPExtensions (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcLoad (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstLoad (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintLoad (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentSrcLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDstLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcRetrans (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstRetrans (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintRetrans (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentSrcRetrans (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDstRetrans (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentRetrans (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcNacks (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstNacks (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintNacks (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentSrcNacks (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDstNacks (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentNacks (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintSrcSolo (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstSolo (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSolo (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentSrcSolo (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDstSolo (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentSolo (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcFirst (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstFirst (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintFirst (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentSrcFirst (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentDstFirst (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintPercentFirst (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintAutoId (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintSrcRate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstRate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintRate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcTos (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstTos (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcDSByte (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstDSByte (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcIpId (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstIpId (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcTtl (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstTtl (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcVlan (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstVlan (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcVID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstVID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcVPRI (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstVPRI (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcMpls (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstMpls (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcWindow (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstWindow (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcMaxSeg (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstMaxSeg (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintJoinDelay (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintLeaveDelay (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintMean (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintStdDeviation (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleMean (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleStdDeviation (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintStartRange (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintEndRange (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTransactions (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSequenceNumber (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintHashRef (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintHashIndex (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintRank (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintBinNumber (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintBins (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPSrcBase (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPDstBase (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPRTT (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPSynAck (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPAckDat (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPSrcMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintTCPDstMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcGap (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstGap (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintManStatus (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintICMPStatus (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIGMPStatus (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIPStatus (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintInode (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintByteOffset (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcEncaps (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstEncaps (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcEncapsBuffer (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstEncapsBuffer (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcMaxPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcMinPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcMeanPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstMaxPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstMinPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstMeanPktSize (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcCountryCode (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstCountryCode (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintInodeCountryCode (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintSrcLatitude (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstLatitude (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintInodeLatitude (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcLongitude (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstLongitude (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintInodeLongitude (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintLocal (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcLocal (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstLocal (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintSrcHopCount (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstHopCount (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIcmpId (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcAsn (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstAsn (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintInodeAsn (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintKeyStrokeSrcNStroke (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintKeyStrokeDstNStroke (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintKeyStrokeNStroke (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSum (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintRunTime (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintIdleTime (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintResponse (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintSrcOui (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstOui (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintCor (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintProducerConsumerRatio (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintSrcVirtualNID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void ArgusPrintDstVirtualNID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

void ArgusPrintTypeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintBssidLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSsidLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintCauseLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintStartDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintLastDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcStartDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcLastDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstStartDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstLastDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintRelativeDateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSourceIDLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSIDLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintNodeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintInfLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintStatusLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintScoreLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintFlagsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcMacAddressLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstMacAddressLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintMacAddressLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcMacOuiAddressLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstMacOuiAddressLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintMacOuiAddressLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcMacClassLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstMacClassLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintEtherTypeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintProtoLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintGreProtoLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintGeneveProtoLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintAddrLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcNetLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcAddrLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintGreSrcAddrLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintGeneveSrcAddrLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcNameLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcGroupLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstNetLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstAddrLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintGreDstAddrLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintGeneveDstAddrLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstNameLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstGroupLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintLocalNetLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintLocalAddrLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintRemoteNetLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintRemoteAddrLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcPortLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstPortLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcIpIdLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstIpIdLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIpIdLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcTtlLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstTtlLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTtlLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDirectionLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPacketsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcPacketsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstPacketsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstBytesLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintAppBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcAppBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstAppBytesLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintProducerConsumerRatioLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintAppByteRatioLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintTransEfficiencyLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcTransEfficiencyLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstTransEfficiencyLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintSrcIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcIntPktDistLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstIntPktDistLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveIntPktDistLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveSrcIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveSrcIntPktDistLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveDstIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveDstIntPktDistLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleIntPktDistLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleSrcIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleSrcIntPktDistLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleDstIntPktLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleDstIntPktDistLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcIntPktMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstIntPktMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveSrcIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveSrcIntPktMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveDstIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveDstIntPktMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleSrcIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleSrcIntPktMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleDstIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleDstIntPktMinLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintIntFlowLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIntFlowDistLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIntFlowStdDevLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIntFlowMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIntFlowMinLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintSrcJitterLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstJitterLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveSrcJitterLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintActiveDstJitterLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleSrcJitterLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleDstJitterLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintStateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaDurationLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaStartTimeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaLastTimeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaSrcPktsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaDstPktsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaSrcBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDeltaDstBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDeltaSrcPktsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDeltaDstPktsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDeltaSrcBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDeltaDstBytesLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcUserDataLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstUserDataLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintUserDataLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPOptionsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPExtensionsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcLoadLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstLoadLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintLoadLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcLossLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstLossLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintLossLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcRetransLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstRetransLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintRetransLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentSrcRetransLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDstRetransLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentRetransLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcNacksLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstNacksLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintNacksLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentSrcNacksLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDstNacksLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentNacksLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcSoloLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstSoloLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSoloLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentSrcSoloLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDstSoloLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentSoloLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcFirstLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstFirstLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintFirstLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentSrcFirstLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDstFirstLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentFirstLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentSrcLossLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentDstLossLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintPercentLossLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcRateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstRateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintRateLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcTosLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstTosLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcDSByteLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstDSByteLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcVlanLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstVlanLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcVIDLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstVIDLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcVPRILabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstVPRILabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcMplsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstMplsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintWindowLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintSrcWindowLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstWindowLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintSrcMaxSegLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstMaxSegLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintJoinDelayLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintLeaveDelayLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintMeanLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintStdDeviationLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintIdleMeanLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleMinLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleSumLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleStdDeviationLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintStartRangeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintEndRangeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcDurationLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstDurationLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDurationLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTransactionsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSequenceNumberLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintHashRefLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintHashIndexLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintRankLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintBinNumberLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintBinsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPSrcBaseLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPDstBaseLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPRTTLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPSynAckLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPAckDatLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPSrcMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintTCPDstMaxLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcGapLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstGapLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintInodeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintByteOffsetLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcEncapsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstEncapsBufferLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcEncapsBufferLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstEncapsLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintMaxPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcMaxPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcMinPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcMeanPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstMaxPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstMinPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstMeanPktSizeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcCountryCodeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstCountryCodeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintInodeCountryCodeLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintSrcLatitudeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstLatitudeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintInodeLatitudeLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintSrcLongitudeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstLongitudeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintInodeLongitudeLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintLocalLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcLocalLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstLocalLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintSrcHopCountLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstHopCountLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIcmpIdLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintAutoIdLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintLabelLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcAsnLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstAsnLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintInodeAsnLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintKeyStrokeSrcNStrokeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintKeyStrokeDstNStrokeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintKeyStrokeNStrokeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSumLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintRunTimeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintIdleTimeLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintResponseLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintSrcOuiLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstOuiLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintCorLabel (struct ArgusParserStruct *, char *, int);

void ArgusPrintSrcVirtualNIDLabel (struct ArgusParserStruct *, char *, int);
void ArgusPrintDstVirtualNIDLabel (struct ArgusParserStruct *, char *, int);

#define ARGUS_PTYPE_INT         0
#define ARGUS_PTYPE_UINT        1
#define ARGUS_PTYPE_DOUBLE      2
#define ARGUS_PTYPE_STRING      4


struct ArgusPrintFieldStruct 
RaPrintAlgorithmTable[MAX_PRINT_ALG_TYPES] = {
#define ARGUSPRINTSTARTDATE		0
   { "stime", "%T.%f", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSTARTDATE, ArgusPrintStartDate, ArgusPrintStartDateLabel, "double(18,6) unsigned not null", 0},
#define ARGUSPRINTLASTDATE		1
   { "ltime", "%T.%f", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTLASTDATE, ArgusPrintLastDate, ArgusPrintLastDateLabel, "double(18,6) unsigned not null", 0},
#define ARGUSPRINTTRANSACTIONS		2
   { "trans", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTTRANSACTIONS, ArgusPrintTransactions, ArgusPrintTransactionsLabel, "int unsigned", 0},
#define ARGUSPRINTDURATION		3
   { "dur", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDURATION, ArgusPrintDuration, ArgusPrintDurationLabel, "double(18,6) not null", 0},
#define ARGUSPRINTMEAN		        4
   { "mean", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTMEAN, ArgusPrintMean, ArgusPrintMeanLabel, "double", 0},
#define ARGUSPRINTMIN			5
   { "min", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTMIN, ArgusPrintMin, ArgusPrintMinLabel, "double", 0},
#define ARGUSPRINTMAX			6
   { "max", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTMAX, ArgusPrintMax, ArgusPrintMaxLabel, "double", 0},
#define ARGUSPRINTSRCADDR		7
   { "saddr", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCADDR, ArgusPrintSrcAddr, ArgusPrintSrcAddrLabel, "varchar(64) not null", 0},
#define ARGUSPRINTDSTADDR		8
   { "daddr", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTADDR, ArgusPrintDstAddr, ArgusPrintDstAddrLabel, "varchar(64) not null", 0},
#define ARGUSPRINTPROTO			9
   { "proto", "", 6 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTPROTO, ArgusPrintProto, ArgusPrintProtoLabel, "varchar(16) not null", 0},
#define ARGUSPRINTSRCPORT		10
   { "sport", "", 6 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCPORT, ArgusPrintSrcPort, ArgusPrintSrcPortLabel, "varchar(10) not null", 0},
#define ARGUSPRINTDSTPORT		11
   { "dport", "", 6 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTPORT, ArgusPrintDstPort, ArgusPrintDstPortLabel, "varchar(10) not null", 0},
#define ARGUSPRINTSRCTOS		12
   { "stos", "", 5 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCTOS, ArgusPrintSrcTos, ArgusPrintSrcTosLabel, "tinyint unsigned", 0},
#define ARGUSPRINTDSTTOS		13
   { "dtos", "", 5 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTTOS, ArgusPrintDstTos, ArgusPrintDstTosLabel, "tinyint unsigned", 0},
#define ARGUSPRINTSRCDSBYTE		14
   { "sdsb", "", 5 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCDSBYTE, ArgusPrintSrcDSByte, ArgusPrintSrcDSByteLabel, "varchar(4) not null", 0},
#define ARGUSPRINTDSTDSBYTE		15
   { "ddsb", "", 5 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTDSBYTE, ArgusPrintDstDSByte, ArgusPrintDstDSByteLabel, "varchar(4) not null", 0},
#define ARGUSPRINTSRCTTL		16
   { "sttl", "", 4 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCTTL, ArgusPrintSrcTtl, ArgusPrintSrcTtlLabel, "tinyint unsigned", 0},
#define ARGUSPRINTDSTTTL		17
   { "dttl", "", 4 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTTTL, ArgusPrintDstTtl, ArgusPrintDstTtlLabel, "tinyint unsigned", 0},
#define ARGUSPRINTBYTES			18
   { "bytes", "", 10 , 1, ARGUS_PTYPE_INT, ARGUSPRINTBYTES, ArgusPrintBytes, ArgusPrintBytesLabel, "bigint", 0},
#define ARGUSPRINTSRCBYTES		19
   { "sbytes", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCBYTES, ArgusPrintSrcBytes, ArgusPrintSrcBytesLabel, "bigint", 0},
#define ARGUSPRINTDSTBYTES		20
   { "dbytes", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTBYTES, ArgusPrintDstBytes, ArgusPrintDstBytesLabel, "bigint", 0},
#define ARGUSPRINTAPPBYTES              21
   { "appbytes", "", 10 , 1, ARGUS_PTYPE_INT, ARGUSPRINTAPPBYTES, ArgusPrintAppBytes, ArgusPrintAppBytesLabel, "bigint", 0},
#define ARGUSPRINTSRCAPPBYTES           22
   { "sappbytes", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCAPPBYTES, ArgusPrintSrcAppBytes, ArgusPrintSrcAppBytesLabel, "bigint", 0},
#define ARGUSPRINTDSTAPPBYTES           23
   { "dappbytes", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTAPPBYTES, ArgusPrintDstAppBytes, ArgusPrintDstAppBytesLabel, "bigint", 0},
#define ARGUSPRINTPACKETS		24
   { "pkts", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPRINTPACKETS, ArgusPrintPackets, ArgusPrintPacketsLabel, "bigint", 0},
#define ARGUSPRINTSRCPACKETS		25
   { "spkts", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCPACKETS, ArgusPrintSrcPackets, ArgusPrintSrcPacketsLabel, "bigint", 0},
#define ARGUSPRINTDSTPACKETS		26
   { "dpkts", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTPACKETS, ArgusPrintDstPackets, ArgusPrintDstPacketsLabel, "bigint", 0},
#define ARGUSPRINTLOAD			27
   { "load", "", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTLOAD, ArgusPrintLoad, ArgusPrintLoadLabel, "double", 0},
#define ARGUSPRINTSRCLOAD		28
   { "sload", "", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSRCLOAD, ArgusPrintSrcLoad, ArgusPrintSrcLoadLabel, "double", 0},
#define ARGUSPRINTDSTLOAD		29
   { "dload", "", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDSTLOAD, ArgusPrintDstLoad, ArgusPrintDstLoadLabel, "double", 0},
#define ARGUSPRINTLOSS			30
   { "loss", "", 10 , 1, ARGUS_PTYPE_INT, ARGUSPRINTLOSS, ArgusPrintLoss, ArgusPrintLossLabel, "int", 0},
#define ARGUSPRINTSRCLOSS		31
   { "sloss", "", 10 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCLOSS, ArgusPrintSrcLoss, ArgusPrintSrcLossLabel, "int", 0},
#define ARGUSPRINTDSTLOSS		32
   { "dloss", "", 10 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTLOSS, ArgusPrintDstLoss, ArgusPrintDstLossLabel, "int", 0},
#define ARGUSPRINTPERCENTLOSS		33
   { "ploss", "", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTLOSS, ArgusPrintPercentLoss, ArgusPrintPercentLossLabel, "double", 0},
#define ARGUSPRINTSRCPERCENTLOSS	34
   { "sploss", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSRCPERCENTLOSS, ArgusPrintPercentSrcLoss, ArgusPrintPercentSrcLossLabel, "double", 0},
#define ARGUSPRINTDSTPERCENTLOSS	35
   { "dploss", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDSTPERCENTLOSS, ArgusPrintPercentDstLoss, ArgusPrintPercentDstLossLabel, "double", 0},
#define ARGUSPRINTRATE			36
   { "rate", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTRATE, ArgusPrintRate, ArgusPrintRateLabel, "double", 0},
#define ARGUSPRINTSRCRATE		37
   { "srate", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSRCRATE, ArgusPrintSrcRate, ArgusPrintSrcRateLabel, "double", 0},
#define ARGUSPRINTDSTRATE		38
   { "drate", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDSTRATE, ArgusPrintDstRate, ArgusPrintDstRateLabel, "double", 0},
#define ARGUSPRINTSOURCEID		39
   { "srcid", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSOURCEID, ArgusPrintSourceID, ArgusPrintSourceIDLabel, "varchar(64)", 0},
#define ARGUSPRINTFLAGS			40
   { "flgs", "", 9 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTFLAGS, ArgusPrintFlags, ArgusPrintFlagsLabel, "varchar(32)", 0},
#define ARGUSPRINTSRCMACADDRESS		41
   { "smac", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCMACADDRESS, ArgusPrintSrcMacAddress, ArgusPrintSrcMacAddressLabel, "varchar(24)", 0},
#define ARGUSPRINTDSTMACADDRESS		42
   { "dmac", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTMACADDRESS, ArgusPrintDstMacAddress, ArgusPrintDstMacAddressLabel, "varchar(24)", 0},
#define ARGUSPRINTDIR			43
   { "dir", "", 5 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDIR, ArgusPrintDirection, ArgusPrintDirectionLabel, "varchar(3)", 0},
#define ARGUSPRINTSRCINTPKT		44
   { "sintpkt", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSRCINTPKT, ArgusPrintSrcIntPkt, ArgusPrintSrcIntPktLabel, "double", 0},
#define ARGUSPRINTDSTINTPKT		45
   { "dintpkt", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDSTINTPKT, ArgusPrintDstIntPkt, ArgusPrintDstIntPktLabel, "double", 0},
#define ARGUSPRINTACTSRCINTPKT		46
   { "sintpktact", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTACTSRCINTPKT, ArgusPrintActiveSrcIntPkt, ArgusPrintActiveSrcIntPktLabel, "double", 0},
#define ARGUSPRINTACTDSTINTPKT		47
   { "dintpktact", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTACTDSTINTPKT, ArgusPrintActiveDstIntPkt, ArgusPrintActiveDstIntPktLabel, "double", 0},
#define ARGUSPRINTIDLESRCINTPKT		48
   { "sintpktidl", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTIDLESRCINTPKT, ArgusPrintIdleSrcIntPkt, ArgusPrintIdleSrcIntPktLabel, "double", 0},
#define ARGUSPRINTIDLEDSTINTPKT		49
   { "dintpktidl", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTIDLEDSTINTPKT, ArgusPrintIdleDstIntPkt, ArgusPrintIdleDstIntPktLabel, "double", 0},
#define ARGUSPRINTSRCINTPKTMAX		50
   { "sintpktmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSRCINTPKTMAX, ArgusPrintSrcIntPktMax, ArgusPrintSrcIntPktMaxLabel, "double", 0},
#define ARGUSPRINTSRCINTPKTMIN		51
   { "sintpktmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSRCINTPKTMIN, ArgusPrintSrcIntPktMin, ArgusPrintSrcIntPktMinLabel, "double", 0},
#define ARGUSPRINTDSTINTPKTMAX		52
   { "dintpktmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDSTINTPKTMAX, ArgusPrintDstIntPktMax, ArgusPrintDstIntPktMaxLabel, "double", 0},
#define ARGUSPRINTDSTINTPKTMIN		53
   { "dintpktmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDSTINTPKTMIN, ArgusPrintDstIntPktMin, ArgusPrintDstIntPktMinLabel, "double", 0},
#define ARGUSPRINTACTSRCINTPKTMAX	54
   { "sintpktactmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTACTSRCINTPKTMAX, ArgusPrintActiveSrcIntPktMax, ArgusPrintActiveSrcIntPktMaxLabel, "double", 0},
#define ARGUSPRINTACTSRCINTPKTMIN	55
   { "sintpktactmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTACTSRCINTPKTMIN, ArgusPrintActiveSrcIntPktMin, ArgusPrintActiveSrcIntPktMinLabel, "double", 0},
#define ARGUSPRINTACTDSTINTPKTMAX	56
   { "dintpktactmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTACTDSTINTPKTMAX, ArgusPrintActiveDstIntPktMax, ArgusPrintActiveDstIntPktMaxLabel, "double", 0},
#define ARGUSPRINTACTDSTINTPKTMIN	57
   { "dintpktactmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTACTDSTINTPKTMIN, ArgusPrintActiveDstIntPktMin, ArgusPrintActiveDstIntPktMinLabel, "double", 0},
#define ARGUSPRINTIDLESRCINTPKTMAX	58
   { "sintpktidlmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTIDLESRCINTPKTMAX, ArgusPrintIdleSrcIntPktMax, ArgusPrintIdleSrcIntPktMaxLabel, "double", 0},
#define ARGUSPRINTIDLESRCINTPKTMIN	59
   { "sintpktidlmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTIDLESRCINTPKTMIN, ArgusPrintIdleSrcIntPktMin, ArgusPrintIdleSrcIntPktMinLabel, "double", 0},
#define ARGUSPRINTIDLEDSTINTPKTMAX	60
   { "dintpktidlmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTIDLEDSTINTPKTMAX, ArgusPrintIdleDstIntPktMax, ArgusPrintIdleDstIntPktMaxLabel, "double", 0},
#define ARGUSPRINTIDLEDSTINTPKTMIN	61
   { "dintpktidlmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTIDLEDSTINTPKTMIN, ArgusPrintIdleDstIntPktMin, ArgusPrintIdleDstIntPktMinLabel, "double", 0},
#define ARGUSPRINTSPACER		62
   { "xxx", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSPACER, NULL, NULL, "varchar(3)", 0},
#define ARGUSPRINTSRCJITTER		63
   { "sjit", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSRCJITTER, ArgusPrintSrcJitter, ArgusPrintSrcJitterLabel, "double", 0},
#define ARGUSPRINTDSTJITTER		64
   { "djit", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDSTJITTER, ArgusPrintDstJitter, ArgusPrintDstJitterLabel, "double", 0},
#define ARGUSPRINTACTSRCJITTER		65
   { "sjitact", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTACTSRCJITTER, ArgusPrintActiveSrcJitter, ArgusPrintActiveSrcJitterLabel, "double", 0},
#define ARGUSPRINTACTDSTJITTER		66
   { "djitact", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTACTDSTJITTER, ArgusPrintActiveDstJitter, ArgusPrintActiveDstJitterLabel, "double", 0},
#define ARGUSPRINTIDLESRCJITTER		67
   { "sjitidl", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTIDLESRCJITTER, ArgusPrintIdleSrcJitter, ArgusPrintIdleSrcJitterLabel, "double", 0},
#define ARGUSPRINTIDLEDSTJITTER		68
   { "djitidl", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTIDLEDSTJITTER, ArgusPrintIdleDstJitter, ArgusPrintIdleDstJitterLabel, "double", 0},
#define ARGUSPRINTSTATE			69
   { "state", "", 5 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSTATE, ArgusPrintState, ArgusPrintStateLabel, "varchar(32)", 0},
#define ARGUSPRINTDELTADURATION		70
   { "dldur", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDELTADURATION, ArgusPrintDeltaDuration, ArgusPrintDeltaDurationLabel, "double", 0},
#define ARGUSPRINTDELTASTARTTIME	71
   { "dlstime", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDELTASTARTTIME, ArgusPrintDeltaStartTime, ArgusPrintDeltaStartTimeLabel, "double(18,6)", 0},
#define ARGUSPRINTDELTALASTTIME		72
   { "dlltime", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDELTALASTTIME, ArgusPrintDeltaLastTime, ArgusPrintDeltaLastTimeLabel, "double(18,6)", 0},
#define ARGUSPRINTDELTASPKTS		73
   { "dlspkt", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDELTASPKTS, ArgusPrintDeltaSrcPkts, ArgusPrintDeltaSrcPktsLabel, "int", 0},
#define ARGUSPRINTDELTADPKTS		74
   { "dldpkt", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDELTADPKTS, ArgusPrintDeltaDstPkts, ArgusPrintDeltaDstPktsLabel, "int", 0},
#define ARGUSPRINTDELTASRCPKTS		75
   { "dspkts", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDELTASRCPKTS, ArgusPrintDeltaSrcPkts, ArgusPrintDeltaSrcPktsLabel, "int", 0},
#define ARGUSPRINTDELTADSTPKTS		76
   { "ddpkts", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDELTADSTPKTS, ArgusPrintDeltaDstPkts, ArgusPrintDeltaDstPktsLabel, "int", 0},
#define ARGUSPRINTDELTASRCBYTES		77
   { "dsbytes", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDELTASRCBYTES, ArgusPrintDeltaSrcBytes, ArgusPrintDeltaSrcBytesLabel, "int", 0},
#define ARGUSPRINTDELTADSTBYTES		78
   { "ddbytes", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDELTADSTBYTES, ArgusPrintDeltaDstBytes, ArgusPrintDeltaDstBytesLabel, "int", 0},
#define ARGUSPRINTPERCENTDELTASRCPKTS	79
   { "pdspkts", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTDELTASRCPKTS, ArgusPrintPercentDeltaSrcPkts, ArgusPrintPercentDeltaSrcPktsLabel, "double", 0},
#define ARGUSPRINTPERCENTDELTADSTPKTS	80
   { "pddpkts", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTDELTADSTPKTS, ArgusPrintPercentDeltaDstPkts, ArgusPrintPercentDeltaDstPktsLabel, "double", 0},
#define ARGUSPRINTPERCENTDELTASRCBYTES	81
   { "pdsbytes", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTDELTASRCBYTES, ArgusPrintPercentDeltaSrcBytes, ArgusPrintPercentDeltaSrcBytesLabel, "double", 0},
#define ARGUSPRINTPERCENTDELTADSTBYTES	82
   { "pddbytes", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTDELTADSTBYTES, ArgusPrintPercentDeltaDstBytes, ArgusPrintPercentDeltaDstBytesLabel, "double", 0},
#define ARGUSPRINTSRCUSERDATA		83
   { "suser", "", 16 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCUSERDATA, ArgusPrintSrcUserData, ArgusPrintSrcUserDataLabel, "varbinary(2048)", 0},
#define ARGUSPRINTDSTUSERDATA		84
   { "duser", "", 16 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTUSERDATA, ArgusPrintDstUserData, ArgusPrintDstUserDataLabel, "varbinary(2048)", 0},
#define ARGUSPRINTTCPEXTENSIONS		85
   { "tcpext", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTTCPEXTENSIONS, ArgusPrintTCPExtensions, ArgusPrintTCPExtensionsLabel, "varchar(64)", 0},
#define ARGUSPRINTSRCWINDOW		86
   { "swin", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCWINDOW, ArgusPrintSrcWindow, ArgusPrintSrcWindowLabel, "tinyint unsigned", 0},
#define ARGUSPRINTDSTWINDOW		87
   { "dwin", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTWINDOW, ArgusPrintDstWindow, ArgusPrintDstWindowLabel, "tinyint unsigned", 0},
#define ARGUSPRINTJOINDELAY		88
   { "jdelay", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTJOINDELAY, ArgusPrintJoinDelay, ArgusPrintJoinDelayLabel, "double", 0},
#define ARGUSPRINTLEAVEDELAY		89
   { "ldelay", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTLEAVEDELAY, ArgusPrintLeaveDelay, ArgusPrintLeaveDelayLabel, "double", 0},
#define ARGUSPRINTSEQUENCENUMBER	90
   { "seq", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSEQUENCENUMBER, ArgusPrintSequenceNumber, ArgusPrintSequenceNumberLabel, "int unsigned", 0},
#define ARGUSPRINTBINS			91
   { "bins", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTBINS, ArgusPrintBins, ArgusPrintBinsLabel, "int unsigned", 0},
#define ARGUSPRINTBINNUMBER		92
   { "binnum", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTBINNUMBER, ArgusPrintBinNumber, ArgusPrintBinNumberLabel, "int unsigned", 0},
#define ARGUSPRINTSRCMPLS		93
   { "smpls", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCMPLS, ArgusPrintSrcMpls, ArgusPrintSrcMplsLabel, "int unsigned", 0},
#define ARGUSPRINTDSTMPLS		94
   { "dmpls", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTMPLS, ArgusPrintDstMpls, ArgusPrintDstMplsLabel, "int unsigned", 0},
#define ARGUSPRINTSRCVLAN		95
   { "svlan", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCVLAN, ArgusPrintSrcVlan, ArgusPrintSrcVlanLabel, "smallint unsigned", 0},
#define ARGUSPRINTDSTVLAN		96
   { "dvlan", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTVLAN, ArgusPrintDstVlan, ArgusPrintDstVlanLabel, "smallint unsigned", 0},
#define ARGUSPRINTSRCVID		97
   { "svid", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCVID, ArgusPrintSrcVID, ArgusPrintSrcVIDLabel, "smallint unsigned", 0},
#define ARGUSPRINTDSTVID		98
   { "dvid", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTVID, ArgusPrintDstVID, ArgusPrintDstVIDLabel, "smallint unsigned", 0},
#define ARGUSPRINTSRCVPRI		99
   { "svpri", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCVPRI, ArgusPrintSrcVPRI, ArgusPrintSrcVPRILabel, "smallint unsigned", 0},
#define ARGUSPRINTDSTVPRI		100
   { "dvpri", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTVPRI, ArgusPrintDstVPRI, ArgusPrintDstVPRILabel, "smallint unsigned", 0},
#define ARGUSPRINTSRCIPID		101
   { "sipid", "", 7 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCIPID, ArgusPrintSrcIpId, ArgusPrintSrcIpIdLabel, "smallint unsigned", 0},
#define ARGUSPRINTDSTIPID		102
   { "dipid", "", 7 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTIPID, ArgusPrintDstIpId, ArgusPrintDstIpIdLabel, "smallint unsigned", 0},
#define ARGUSPRINTSTARTRANGE		103
   { "srng", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSTARTRANGE, ArgusPrintStartRange, ArgusPrintStartRangeLabel, "int unsigned", 0},
#define ARGUSPRINTENDRANGE		104
   { "erng", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTENDRANGE, ArgusPrintEndRange, ArgusPrintEndRangeLabel, "int unsigned", 0},
#define ARGUSPRINTTCPSRCBASE		105
   { "stcpb", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTTCPSRCBASE, ArgusPrintTCPSrcBase, ArgusPrintTCPSrcBaseLabel, "int unsigned", 0},
#define ARGUSPRINTTCPDSTBASE		106
   { "dtcpb", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTTCPDSTBASE, ArgusPrintTCPDstBase, ArgusPrintTCPDstBaseLabel, "int unsigned", 0},
#define ARGUSPRINTTCPRTT		107
   { "tcprtt", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTTCPRTT, ArgusPrintTCPRTT, ArgusPrintTCPRTTLabel, "double", 0},
#define ARGUSPRINTINODE   		108
   { "inode", "", 18, 1, ARGUS_PTYPE_STRING, ARGUSPRINTINODE, ArgusPrintInode, ArgusPrintInodeLabel, "varchar(64)", 0},
#define ARGUSPRINTSTDDEV  		109
   { "stddev", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSTDDEV, ArgusPrintStdDeviation, ArgusPrintStdDeviationLabel, "double unsigned", 0},
#define ARGUSPRINTRELDATE		110
   { "rtime", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTRELDATE, ArgusPrintRelativeDate, ArgusPrintRelativeDateLabel, "double(18,6)", 0},
#define ARGUSPRINTBYTEOFFSET		111
   { "offset", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTBYTEOFFSET, ArgusPrintByteOffset, ArgusPrintByteOffsetLabel, "bigint", 0},
#define ARGUSPRINTSRCNET		112
   { "snet", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCNET, ArgusPrintSrcNet, ArgusPrintSrcNetLabel, "varchar(64)", 0},
#define ARGUSPRINTDSTNET		113
   { "dnet", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTNET, ArgusPrintDstNet, ArgusPrintDstNetLabel, "varchar(64)", 0},
#define ARGUSPRINTSRCDURATION		114
   { "sdur", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSRCDURATION, ArgusPrintSrcDuration, ArgusPrintSrcDurationLabel, "double", 0},
#define ARGUSPRINTDSTDURATION		115
   { "ddur", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDSTDURATION, ArgusPrintDstDuration, ArgusPrintDstDurationLabel, "double", 0},
#define ARGUSPRINTTCPSRCMAX		116
   { "stcpmax", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTTCPSRCMAX, ArgusPrintTCPSrcMax, ArgusPrintTCPSrcMaxLabel, "double", 0},
#define ARGUSPRINTTCPDSTMAX		117
   { "dtcpmax", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTTCPDSTMAX, ArgusPrintTCPDstMax, ArgusPrintTCPDstMaxLabel, "double", 0},
#define ARGUSPRINTTCPSYNACK		118
   { "synack", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTTCPSYNACK, ArgusPrintTCPSynAck, ArgusPrintTCPSynAckLabel, "double", 0},
#define ARGUSPRINTTCPACKDAT		119
   { "ackdat", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTTCPACKDAT, ArgusPrintTCPAckDat, ArgusPrintTCPAckDatLabel, "double", 0},
#define ARGUSPRINTSRCSTARTDATE		120
   { "sstime", "%T.%f", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCSTARTDATE, ArgusPrintSrcStartDate, ArgusPrintSrcStartDateLabel, "double(18,6) unsigned not null", 0},
#define ARGUSPRINTSRCLASTDATE		121
   { "sltime", "%T.%f", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCLASTDATE, ArgusPrintSrcLastDate, ArgusPrintSrcLastDateLabel, "double(18,6) unsigned not null", 0},
#define ARGUSPRINTDSTSTARTDATE		122
   { "dstime", "%T.%f", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTSTARTDATE, ArgusPrintDstStartDate, ArgusPrintDstStartDateLabel, "double(18,6) unsigned not null", 0},
#define ARGUSPRINTDSTLASTDATE		123
   { "dltime", "%T.%f", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTLASTDATE, ArgusPrintDstLastDate, ArgusPrintDstLastDateLabel, "double(18,6) unsigned not null", 0},
#define ARGUSPRINTSRCENCAPS		124
   { "senc", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCENCAPS, ArgusPrintSrcEncaps, ArgusPrintSrcEncapsLabel, "varchar(32)", 0},
#define ARGUSPRINTDSTENCAPS		125
   { "denc", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTENCAPS, ArgusPrintDstEncaps, ArgusPrintDstEncapsLabel, "varchar(32)", 0},
#define ARGUSPRINTSRCPKTSIZE		126
   { "spktsz", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCPKTSIZE, ArgusPrintSrcPktSize, ArgusPrintSrcPktSizeLabel, "varchar(32)", 0},
#define ARGUSPRINTSRCMAXPKTSIZE		127
   { "smaxsz", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCMAXPKTSIZE, ArgusPrintSrcMaxPktSize, ArgusPrintSrcMaxPktSizeLabel, "smallint unsigned", 0},
#define ARGUSPRINTSRCMINPKTSIZE		128
   { "sminsz", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCMINPKTSIZE, ArgusPrintSrcMinPktSize, ArgusPrintSrcMinPktSizeLabel, "smallint unsigned", 0},
#define ARGUSPRINTDSTPKTSIZE		129
   { "dpktsz", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTPKTSIZE, ArgusPrintDstPktSize, ArgusPrintDstPktSizeLabel, "varchar(32)", 0},
#define ARGUSPRINTDSTMAXPKTSIZE		130
   { "dmaxsz", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTMAXPKTSIZE, ArgusPrintDstMaxPktSize, ArgusPrintDstMaxPktSizeLabel, "smallint unsigned", 0},
#define ARGUSPRINTDSTMINPKTSIZE		131
   { "dminsz", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTMINPKTSIZE, ArgusPrintDstMinPktSize, ArgusPrintDstMinPktSizeLabel, "smallint unsigned", 0},
#define ARGUSPRINTSRCCOUNTRYCODE	132
   { "sco", "", 3 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCCOUNTRYCODE, ArgusPrintSrcCountryCode, ArgusPrintSrcCountryCodeLabel, "varchar(2)", 0},
#define ARGUSPRINTDSTCOUNTRYCODE	133
   { "dco", "", 3 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTCOUNTRYCODE, ArgusPrintDstCountryCode, ArgusPrintDstCountryCodeLabel, "varchar(2)", 0},
#define ARGUSPRINTSRCHOPCOUNT		134
   { "shops", "", 5 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCHOPCOUNT, ArgusPrintSrcHopCount, ArgusPrintSrcHopCountLabel, "smallint", 0},
#define ARGUSPRINTDSTHOPCOUNT		135
   { "dhops", "", 5 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTHOPCOUNT, ArgusPrintDstHopCount, ArgusPrintDstHopCountLabel, "smallint", 0},
#define ARGUSPRINTICMPID		136
   { "icmpid", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTICMPID, ArgusPrintIcmpId, ArgusPrintIcmpIdLabel, "smallint unsigned", 0},
#define ARGUSPRINTLABEL			137
   { "label", "", 5 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTLABEL, ArgusPrintLabel, ArgusPrintLabelLabel, "varchar(4098)", 0},
#define ARGUSPRINTSRCINTPKTDIST		138
   { "sintdist", "", 8, 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCINTPKTDIST, ArgusPrintSrcIntPktDist, ArgusPrintSrcIntPktDistLabel, "varchar(8)", 0},
#define ARGUSPRINTDSTINTPKTDIST		139
   { "dintdist", "", 8, 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTINTPKTDIST, ArgusPrintDstIntPktDist, ArgusPrintDstIntPktDistLabel, "varchar(8)", 0},
#define ARGUSPRINTACTSRCINTPKTDIST	140
   { "sintdistact", "", 11, 1, ARGUS_PTYPE_STRING, ARGUSPRINTACTSRCINTPKTDIST, ArgusPrintActiveSrcIntPktDist, ArgusPrintActiveSrcIntPktDistLabel, "varchar(8)", 0},
#define ARGUSPRINTACTDSTINTPKTDIST	141
   { "dintdistact", "", 11, 1, ARGUS_PTYPE_STRING, ARGUSPRINTACTDSTINTPKTDIST, ArgusPrintActiveDstIntPktDist, ArgusPrintActiveDstIntPktDistLabel, "varchar(8)", 0},
#define ARGUSPRINTIDLESRCINTPKTDIST	142
   { "sintdistidl", "", 11, 1, ARGUS_PTYPE_STRING, ARGUSPRINTIDLESRCINTPKTDIST, ArgusPrintIdleSrcIntPktDist, ArgusPrintIdleSrcIntPktDistLabel, "varchar(8)", 0},
#define ARGUSPRINTIDLEDSTINTPKTDIST	143
   { "dintdistidl", "", 11, 1, ARGUS_PTYPE_STRING, ARGUSPRINTIDLEDSTINTPKTDIST, ArgusPrintIdleDstIntPktDist, ArgusPrintIdleDstIntPktDistLabel, "varchar(8)", 0},
#define ARGUSPRINTRETRANS          	144
   { "retrans", "", 7, 1, ARGUS_PTYPE_INT, ARGUSPRINTRETRANS, ArgusPrintRetrans, ArgusPrintRetransLabel, "int", 0},
#define ARGUSPRINTSRCRETRANS          	145
   { "sretrans", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCRETRANS, ArgusPrintSrcRetrans, ArgusPrintSrcRetransLabel, "int", 0},
#define ARGUSPRINTDSTRETRANS          	146
   { "dretrans", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTRETRANS, ArgusPrintDstRetrans, ArgusPrintDstRetransLabel, "int", 0},
#define ARGUSPRINTPERCENTRETRANS        147
   { "pretrans", "", 7, 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTRETRANS, ArgusPrintPercentRetrans, ArgusPrintPercentRetransLabel, "double", 0},
#define ARGUSPRINTPERCENTSRCRETRANS     148
   { "spretrans", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTSRCRETRANS, ArgusPrintPercentSrcRetrans, ArgusPrintPercentSrcRetransLabel, "double", 0},
#define ARGUSPRINTPERCENTDSTRETRANS     149
   { "dpretrans", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTDSTRETRANS, ArgusPrintPercentDstRetrans, ArgusPrintPercentDstRetransLabel, "double", 0},
#define ARGUSPRINTNACKS          	150
   { "nacks", "", 7, 1, ARGUS_PTYPE_INT, ARGUSPRINTNACKS, ArgusPrintNacks, ArgusPrintNacksLabel, "int", 0},
#define ARGUSPRINTSRCNACKS          	151
   { "snacks", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCNACKS, ArgusPrintSrcNacks, ArgusPrintSrcNacksLabel, "int", 0},
#define ARGUSPRINTDSTNACKS          	152
   { "dnacks", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTNACKS, ArgusPrintDstNacks, ArgusPrintDstNacksLabel, "int", 0},
#define ARGUSPRINTPERCENTNACKS		153
   { "pnacks", "", 7, 1, ARGUS_PTYPE_INT, ARGUSPRINTPERCENTNACKS, ArgusPrintPercentNacks, ArgusPrintPercentNacksLabel, "double", 0},
#define ARGUSPRINTPERCENTSRCNACKS	154
   { "spnacks", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTSRCNACKS, ArgusPrintPercentSrcNacks, ArgusPrintPercentSrcNacksLabel, "double", 0},
#define ARGUSPRINTPERCENTDSTNACKS	155
   { "dpnacks", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTDSTNACKS, ArgusPrintPercentDstNacks, ArgusPrintPercentDstNacksLabel, "double", 0},
#define ARGUSPRINTSOLO          	156
   { "solo", "", 7, 1, ARGUS_PTYPE_INT, ARGUSPRINTSOLO, ArgusPrintSolo, ArgusPrintSoloLabel, "int", 0},
#define ARGUSPRINTSRCSOLO          	157
   { "ssolo", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCSOLO, ArgusPrintSrcSolo, ArgusPrintSrcSoloLabel, "int", 0},
#define ARGUSPRINTDSTSOLO          	158
   { "dsolo", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTSOLO, ArgusPrintDstSolo, ArgusPrintDstSoloLabel, "int", 0},
#define ARGUSPRINTPERCENTSOLO		159
   { "psolo", "", 7, 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTSOLO, ArgusPrintPercentSolo, ArgusPrintPercentSoloLabel, "double", 0},
#define ARGUSPRINTPERCENTSRCSOLO	160
   { "spsolo", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTSRCSOLO, ArgusPrintPercentSrcSolo, ArgusPrintPercentSrcSoloLabel, "double", 0},
#define ARGUSPRINTPERCENTDSTSOLO	161
   { "dpsolo", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTDSTSOLO, ArgusPrintPercentDstSolo, ArgusPrintPercentDstSoloLabel, "double", 0},
#define ARGUSPRINTFIRST          	162
   { "first", "", 7, 1, ARGUS_PTYPE_INT, ARGUSPRINTFIRST, ArgusPrintFirst, ArgusPrintFirstLabel, "int", 0},
#define ARGUSPRINTSRCFIRST          	163
   { "sfirst", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCFIRST, ArgusPrintSrcFirst, ArgusPrintSrcFirstLabel, "int", 0},
#define ARGUSPRINTDSTFIRST          	164
   { "dfirst", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTFIRST, ArgusPrintDstFirst, ArgusPrintDstFirstLabel, "int", 0},
#define ARGUSPRINTPERCENTFIRST		165
   { "pfirst", "", 7, 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTFIRST, ArgusPrintPercentFirst, ArgusPrintPercentFirstLabel, "double", 0},
#define ARGUSPRINTPERCENTSRCFIRST	166
   { "spfirst", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTSRCFIRST, ArgusPrintPercentSrcFirst, ArgusPrintPercentSrcFirstLabel, "double", 0},
#define ARGUSPRINTPERCENTDSTFIRST	167
   { "dpfirst", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPERCENTDSTFIRST, ArgusPrintPercentDstFirst, ArgusPrintPercentDstFirstLabel, "double", 0},
#define ARGUSPRINTAUTOID		168
   { "autoid", "", 6, 1, ARGUS_PTYPE_INT, ARGUSPRINTAUTOID, ArgusPrintAutoId, ArgusPrintAutoIdLabel, "int not null auto_increment", 0},
#define ARGUSPRINTSRCASN		169
   { "sas", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCASN, ArgusPrintSrcAsn, ArgusPrintSrcAsnLabel, "int unsigned", 0},
#define ARGUSPRINTDSTASN		170
   { "das", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTASN, ArgusPrintDstAsn, ArgusPrintDstAsnLabel, "int unsigned", 0},
#define ARGUSPRINTINODEASN		171
   { "ias", "", 5 , 1, ARGUS_PTYPE_INT, ARGUSPRINTINODEASN, ArgusPrintInodeAsn, ArgusPrintInodeAsnLabel, "int unsigned", 0},
#define ARGUSPRINTCAUSE			172
   { "cause", "", 7 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTCAUSE, ArgusPrintCause, ArgusPrintCauseLabel, "varchar(8)", 0},
#define ARGUSPRINTBSSID			173
   { "bssid", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTBSSID, ArgusPrintBssid, ArgusPrintBssidLabel, "varchar(24)", 0},
#define ARGUSPRINTSSID			174
   { "ssid", "", 9 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSSID, ArgusPrintSsid, ArgusPrintSsidLabel, "varchar(32)", 0},
#define ARGUSPRINTKEYSTROKENSTROKE      175
   { "nstroke", "", 9 , 1, ARGUS_PTYPE_INT, ARGUSPRINTKEYSTROKENSTROKE, ArgusPrintKeyStrokeNStroke, ArgusPrintKeyStrokeNStrokeLabel, "int unsigned", 0},
#define ARGUSPRINTKEYSTROKESRCNSTROKE   176
   { "snstroke", "", 9 , 1, ARGUS_PTYPE_INT, ARGUSPRINTKEYSTROKESRCNSTROKE, ArgusPrintKeyStrokeSrcNStroke, ArgusPrintKeyStrokeSrcNStrokeLabel, "int unsigned", 0},
#define ARGUSPRINTKEYSTROKEDSTNSTROKE   177
   { "dnstroke", "", 9 , 1, ARGUS_PTYPE_INT, ARGUSPRINTKEYSTROKEDSTNSTROKE, ArgusPrintKeyStrokeDstNStroke, ArgusPrintKeyStrokeDstNStrokeLabel, "int unsigned", 0},
#define ARGUSPRINTSRCMEANPKTSIZE        178
   { "smeansz", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCMEANPKTSIZE, ArgusPrintSrcMeanPktSize, ArgusPrintSrcMeanPktSizeLabel, "smallint unsigned", 0},
#define ARGUSPRINTDSTMEANPKTSIZE        179
   { "dmeansz", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTMEANPKTSIZE, ArgusPrintDstMeanPktSize, ArgusPrintDstMeanPktSizeLabel, "smallint unsigned", 0},
#define ARGUSPRINTRANK			180
   { "rank", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTRANK, ArgusPrintRank, ArgusPrintRankLabel, "int unsigned", 0},
#define ARGUSPRINTSUM                   181
   { "sum", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSUM, ArgusPrintSum, ArgusPrintSumLabel, "double", 0},
#define ARGUSPRINTRUN                   182
   { "runtime", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTRUN, ArgusPrintRunTime, ArgusPrintRunTimeLabel, "double", 0},
#define ARGUSPRINTIDLETIME              183
   { "idle", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTIDLETIME, ArgusPrintIdleTime, ArgusPrintIdleTimeLabel, "double", 0},
#define ARGUSPRINTTCPOPTIONS            184
   { "tcpopt", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTTCPOPTIONS, ArgusPrintTCPOptions, ArgusPrintTCPOptionsLabel, "varchar(12)", 0},
#define ARGUSPRINTRESPONSE              185
   { "resp", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTRESPONSE, ArgusPrintResponse, ArgusPrintResponseLabel, "varchar(12)", 0},
#define ARGUSPRINTTCPSRCGAP		186
   { "sgap", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPRINTTCPSRCGAP, ArgusPrintSrcGap, ArgusPrintSrcGapLabel, "int unsigned", 0},
#define ARGUSPRINTTCPDSTGAP		187
   { "dgap", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPRINTTCPDSTGAP, ArgusPrintDstGap, ArgusPrintDstGapLabel, "int unsigned", 0},
#define ARGUSPRINTSRCOUI   		188
   { "soui", "", 9 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCOUI, ArgusPrintSrcOui, ArgusPrintSrcOuiLabel, "varchar(9)", 0},
#define ARGUSPRINTDSTOUI   		189
   { "doui", "", 9 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTOUI, ArgusPrintDstOui, ArgusPrintDstOuiLabel, "varchar(9)", 0},
#define ARGUSPRINTCOR   		190
   { "cor", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTCOR, ArgusPrintCor, ArgusPrintCorLabel, "varchar(12)", 0},
#define ARGUSPRINTLOCALADDR             191
   { "laddr", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTLOCALADDR, ArgusPrintLocalAddr, ArgusPrintLocalAddrLabel, "varchar(64) not null", 0},
#define ARGUSPRINTREMOTEADDR            192
   { "raddr", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTREMOTEADDR, ArgusPrintRemoteAddr, ArgusPrintRemoteAddrLabel, "varchar(64) not null", 0},
#define ARGUSPRINTLOCALNET              193
   { "lnet", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTLOCALADDR, ArgusPrintLocalNet, ArgusPrintLocalNetLabel, "varchar(64) not null", 0},
#define ARGUSPRINTREMOTENET             194
   { "rnet", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTREMOTEADDR, ArgusPrintRemoteNet, ArgusPrintRemoteNetLabel, "varchar(64) not null", 0},
#define ARGUSPRINTAPPBYTERATIO          195
   { "abr", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTAPPBYTERATIO, ArgusPrintAppByteRatio, ArgusPrintAppByteRatioLabel, "double", 0},
#define ARGUSPRINTPRODUCERCONSUMERRATIO 196
   { "pcr", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTPRODUCERCONSUMERRATIO, ArgusPrintProducerConsumerRatio, ArgusPrintProducerConsumerRatioLabel, "double", 0},
#define ARGUSPRINTTRANSEFFICIENCY       197
   { "tf", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTTRANSEFFICIENCY, ArgusPrintTransEfficiency, ArgusPrintTransEfficiencyLabel, "double", 0},
#define ARGUSPRINTSRCTRANSEFFICIENCY    198
   { "stf", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSRCTRANSEFFICIENCY, ArgusPrintSrcTransEfficiency, ArgusPrintSrcTransEfficiencyLabel, "double", 0},
#define ARGUSPRINTDSTTRANSEFFICIENCY    199
   { "dtf", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDSTTRANSEFFICIENCY, ArgusPrintDstTransEfficiency, ArgusPrintDstTransEfficiencyLabel, "double", 0},
#define ARGUSPRINTINODECOUNTRYCODE	200
   { "ico", "", 3 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTINODECOUNTRYCODE, ArgusPrintInodeCountryCode, ArgusPrintInodeCountryCodeLabel, "varchar(2)", 0},
#define ARGUSPRINTSRCLATITUDE		201
   { "slat", "", 3 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSRCLATITUDE, ArgusPrintSrcLatitude, ArgusPrintSrcLatitudeLabel, "double", 0},
#define ARGUSPRINTSRCLONGITUDE		202
   { "slon", "", 3 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSRCLONGITUDE, ArgusPrintSrcLongitude, ArgusPrintSrcLongitudeLabel, "double", 0},
#define ARGUSPRINTDSTLATITUDE		203
   { "dlat", "", 3 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDSTLATITUDE, ArgusPrintDstLatitude, ArgusPrintDstLatitudeLabel, "double", 0},
#define ARGUSPRINTDSTLONGITUDE		204
   { "dlon", "", 3 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTDSTLONGITUDE, ArgusPrintDstLongitude, ArgusPrintDstLongitudeLabel, "double", 0},
#define ARGUSPRINTINODELATITUDE		205
   { "ilat", "", 3 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTINODELATITUDE, ArgusPrintInodeLatitude, ArgusPrintInodeLatitudeLabel, "double", 0},
#define ARGUSPRINTINODELONGITUDE	206
   { "ilon", "", 3 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTINODELONGITUDE, ArgusPrintInodeLongitude, ArgusPrintInodeLongitudeLabel, "double", 0},
#define ARGUSPRINTSRCLOCAL		207
   { "sloc", "", 3 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCLOCAL, ArgusPrintSrcLocal, ArgusPrintSrcLocalLabel, "tinyint unsigned", 0},
#define ARGUSPRINTDSTLOCAL		208
   { "dloc", "", 3 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTLOCAL, ArgusPrintDstLocal, ArgusPrintDstLocalLabel, "tinyint unsigned", 0},
#define ARGUSPRINTLOCAL			209
   { "loc", "", 3 , 1, ARGUS_PTYPE_INT, ARGUSPRINTLOCAL, ArgusPrintLocal, ArgusPrintLocalLabel, "tinyint unsigned", 0},
#define ARGUSPRINTSID			210
   { "sid", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSID, ArgusPrintSID, ArgusPrintSIDLabel, "varchar(64)", 0},
#define ARGUSPRINTNODE			211
   { "node", "", 8 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTNODE, ArgusPrintNode, ArgusPrintNodeLabel, "varchar(64)", 0},
#define ARGUSPRINTINF			212
   { "inf", "", 4 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTINF, ArgusPrintInf, ArgusPrintInfLabel, "varchar(4)", 0},
#define ARGUSPRINTSTATUS		213
   { "status", "", 4 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSTATUS, ArgusPrintStatus, ArgusPrintStatusLabel, "varchar(8)", 0},
#define ARGUSPRINTSRCGROUP		214
   { "sgrp", "", 4 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCGROUP, ArgusPrintSrcGroup, ArgusPrintSrcGroupLabel, "varchar(64)", 0},
#define ARGUSPRINTDSTGROUP		215
   { "dgrp", "", 4 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTGROUP, ArgusPrintDstGroup, ArgusPrintDstGroupLabel, "varchar(64)", 0},
#define ARGUSPRINTHASHREF		216
   { "hash", "", 4 , 1, ARGUS_PTYPE_UINT, ARGUSPRINTHASHREF, ArgusPrintHashRef, ArgusPrintHashRefLabel, "int unsigned", 0},
#define ARGUSPRINTHASHINDEX		217
   { "ind", "", 4 , 1, ARGUS_PTYPE_UINT, ARGUSPRINTHASHINDEX, ArgusPrintHashIndex, ArgusPrintHashIndexLabel, "int unsigned", 0},
#define ARGUSPRINTSCORE			218
   { "score", "%d", 5 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSCORE, ArgusPrintScore, ArgusPrintScoreLabel, "tinyint", 0},
#define ARGUSPRINTSRCNAME		219
   { "sname", "%s", 16 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCNAME, ArgusPrintSrcName, ArgusPrintSrcNameLabel, "varchar(64)", 0},
#define ARGUSPRINTDSTNAME		220
   { "dname", "%s", 16 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTNAME, ArgusPrintDstName, ArgusPrintDstNameLabel, "varchar(64)", 0},
#define ARGUSPRINTETHERTYPE		221
   { "etype", "%u", 8 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTETHERTYPE, ArgusPrintEtherType, ArgusPrintEtherTypeLabel, "varchar(32)", 0},
#define ARGUSPRINTMEANIDLE		222
   { "idlemean", "%u", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTMEANIDLE, ArgusPrintIdleMean, ArgusPrintIdleMeanLabel, "double unsigned", 0},
#define ARGUSPRINTMINIDLE		223
   { "idlemin", "%u", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTMINIDLE, ArgusPrintIdleMin, ArgusPrintIdleMinLabel, "double unsigned", 0},
#define ARGUSPRINTMAXIDLE		224
   { "idlemax", "%u", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTMAXIDLE, ArgusPrintIdleMax, ArgusPrintIdleMaxLabel, "double unsigned", 0},
#define ARGUSPRINTSTDDEVIDLE  		225
   { "idlestddev", "%u", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTSTDDEVIDLE, ArgusPrintIdleStdDeviation, ArgusPrintIdleStdDeviationLabel, "double unsigned", 0},
#define ARGUSPRINTSRCMAXSEG  		226
   { "smss", "%d", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCMAXSEG, ArgusPrintSrcMaxSeg, ArgusPrintSrcMaxSegLabel, "tinyint unsigned", 0},
#define ARGUSPRINTDSTMAXSEG  		227
   { "dmss", "%d", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTMAXSEG, ArgusPrintDstMaxSeg, ArgusPrintDstMaxSegLabel, "tinyint unsigned", 0},
#define ARGUSPRINTINTFLOW		228
   { "intflow", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTINTFLOW, ArgusPrintIntFlow, ArgusPrintIntFlowLabel, "double", 0},
#define ARGUSPRINTACTINTFLOW            229
   { "actintflow", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTACTINTFLOW, NULL, NULL, "double", 0},
#define ARGUSPRINTIDLEINTFLOW           230
   { "idleintflow", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTIDLEINTFLOW, NULL, NULL, "double", 0},
#define ARGUSPRINTINTFLOWMAX		231
   { "intflowmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTINTFLOWMAX, ArgusPrintIntFlowMax, ArgusPrintIntFlowMaxLabel, "double", 0},
#define ARGUSPRINTINTFLOWMIN		232
   { "intflowmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTINTFLOWMIN, ArgusPrintIntFlowMin, ArgusPrintIntFlowMinLabel, "double", 0},
#define ARGUSPRINTINTFLOWSDEV		233
   { "intflowsdev", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTINTFLOWSDEV, ArgusPrintIntFlowStdDev, ArgusPrintIntFlowStdDevLabel, "double", 0},
#define ARGUSPRINTACTINTFLOWMAX         234
   { "actintflowmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTACTINTFLOWMAX, NULL, NULL, "double", 0},
#define ARGUSPRINTACTINTFLOWMIN         235
   { "actintflowmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTACTINTFLOWMIN, NULL, NULL, "double", 0},
#define ARGUSPRINTACTINTFLOWSDEV        236
   { "actintflowsdev", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTACTINTFLOWSDEV, NULL, NULL, "double", 0},
#define ARGUSPRINTIDLEINTFLOWMAX        237
   { "idleintflowmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTIDLEINTFLOWMAX, NULL, NULL, "double", 0},
#define ARGUSPRINTIDLEINTFLOWMIN        238
   { "idleintflowmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTIDLEINTFLOWMIN, NULL, NULL, "double", 0},
#define ARGUSPRINTIDLEINTFLOWSDEV       239
   { "idleintflowsdev", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPRINTIDLEINTFLOWSDEV, NULL, NULL, "double", 0},
#define ARGUSPRINTSRCVNID		240
   { "svnid", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTSRCVNID, ArgusPrintSrcVirtualNID, ArgusPrintSrcVirtualNIDLabel, "int", 0},
#define ARGUSPRINTDSTVNID		241
   { "dvnid", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPRINTDSTVNID, ArgusPrintDstVirtualNID, ArgusPrintDstVirtualNIDLabel, "int", 0},
#define ARGUSPRINTTYPE			242
   { "type", "", 4 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTTYPE, ArgusPrintType, ArgusPrintTypeLabel, "varchar(4)", 0},
#define ARGUSPRINTSRCMACOUI    		243
   { "smacoui", "", 7 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCMACOUI, ArgusPrintSrcMacOuiAddress, ArgusPrintSrcMacOuiAddressLabel, "varchar(24)", 0},
#define ARGUSPRINTDSTOUINAME		244
   { "dmacoui", "", 7 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCMACOUI, ArgusPrintDstMacOuiAddress, ArgusPrintDstMacOuiAddressLabel, "varchar(24)", 0},
#define ARGUSPRINTSRCMACCLASS		245
   { "smacclass", "%s", 5 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCMACCLASS, ArgusPrintSrcMacClass, ArgusPrintSrcMacClassLabel, "varchar(4)", 0},
#define ARGUSPRINTDSTMACCLASS		246
   { "dmacclass", "%s", 5 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTMACCLASS, ArgusPrintDstMacClass, ArgusPrintDstMacClassLabel, "varchar(4)", 0},
#define ARGUSPRINTGRESRCADDR		247
   { "sgreaddr", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTGRESRCADDR, ArgusPrintGreSrcAddr, ArgusPrintGreSrcAddrLabel, "varchar(64) not null", 0},
#define ARGUSPRINTGREDSTADDR		248
   { "dgreaddr", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTGREDSTADDR, ArgusPrintGreDstAddr, ArgusPrintGreDstAddrLabel, "varchar(64) not null", 0},
#define ARGUSPRINTGREPROTO		249
   { "greproto", "", 6 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTGREPROTO, ArgusPrintGreProto, ArgusPrintGreProtoLabel, "varchar(16) not null", 0},
#define ARGUSPRINTGENSRCADDR		250
   { "sgenaddr", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTGENSRCADDR, ArgusPrintGeneveSrcAddr, ArgusPrintGeneveSrcAddrLabel, "varchar(64) not null", 0},
#define ARGUSPRINTGENDSTADDR		251
   { "dgenaddr", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTGENDSTADDR, ArgusPrintGeneveDstAddr, ArgusPrintGeneveDstAddrLabel, "varchar(64) not null", 0},
#define ARGUSPRINTGENPROTO		252
   { "genproto", "", 6 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTGENPROTO, ArgusPrintGeneveProto, ArgusPrintGeneveProtoLabel, "varchar(16) not null", 0},
#define ARGUSPRINTSRCENCAPSBUFFER	253
   { "sencbuf", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTSRCENCAPSBUFFER, ArgusPrintSrcEncapsBuffer, ArgusPrintSrcEncapsBufferLabel, "varchar(32)", 0},
#define ARGUSPRINTDSTENCAPSBUFFER	254
   { "dencbuf", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPRINTDSTENCAPSBUFFER, ArgusPrintDstEncapsBuffer, ArgusPrintDstEncapsBufferLabel, "varchar(32)", 0},
};


#define IPPROTOSTR              256

char *ip_proto_string [IPPROTOSTR] = {"ip", "icmp", "igmp", "ggp",
   "ipnip", "st2", "tcp", "cbt", "egp", "igp", "bbn-rcc", "nvp",
   "pup", "argus", "emcon", "xnet", "chaos", "udp", "mux", "dcn",
   "hmp", "prm", "xns-idp", "trunk-1", "trunk-2", "leaf-1", "leaf-2",
   "rdp", "irtp", "iso-tp4", "netblt", "mfe-nsp", "merit-inp", "sep",
   "3pc", "idpr", "xtp", "ddp", "idpr-cmtp", "tp++", "il", "ipv6",
   "sdrp", "ipv6-route", "ipv6-frag", "idrp", "rsvp", "gre", "mhrp", "bna",
   "esp", "ah", "i-nlsp", "swipe", "narp", "mobile", "tlsp", "skip",
   "ipv6-icmp", "ipv6-no", "ipv6-opts", "any", "cftp", "any", "sat-expak", "kryptolan",
   "rvd", "ippc", "any", "sat-mon", "visa", "ipcv", "cpnx", "cphb", "wsn",
   "pvp", "br-sat-mon", "sun-nd", "wb-mon", "wb-expak", "iso-ip", "vmtp",
   "secure-vmtp", "vines", "ttp", "nsfnet-igp", "dgp", "tcf", "eigrp",
   "ospf", "sprite-rpc", "larp", "mtp", "ax.25", "ipip", "micp",
   "aes-sp3-d", "etherip", "encap", "pri-enc", "gmtp", "ifmp", "pnni",
   "pim", "aris", "scps", "qnx", "a/n", "ipcomp", "snp", "compaq-peer",
   "ipx-n-ip", "vrrp", "pgm", "zero", "l2tp", "ddx", "iatp", "stp", "srp",
   "uti", "smp", "sm", "ptp", "isis", "fire", "crtp", "crudp", "sccopmce", "iplt",
   "sps", "pipe", "sctp", "fc", "rsvp", NULL, NULL, NULL, NULL, NULL, NULL,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*141-150*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*151-160*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*161-170*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*171-180*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*181-190*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*191-200*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*201-210*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*211-220*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*221-230*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*231-240*/
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /*241-250*/
   NULL, NULL, "ib", NULL, NULL,                                /*251-255*/
};

char *icmptypestr[ICMP_MAXTYPE + 1] = {
   "ECR", "   ", "   ", "UR" , "SRC", "RED",
   "AHA", "   ", "ECO", "RTA", "RTS", "TXD",
   "PAR", "TST", "TSR", "IRQ", "IRR", "MAS",
   "MSR", "SEC", "ROB", "ROB", "ROB", "ROB",
   "ROB", "ROB", "ROB", "ROB", "ROB", "ROB",
   "TRC", "DCE", "MHR", "WAY", "IAH", "MRQ",
   "MRP", "DNQ", "DNP", "SKP", "PHO", "EXM",
   "EEO", "EER",
};

char *icmptypelongstr[ICMP_MAXTYPE + 1] = {
   "echoreply", "unas", "unassigned", "dstunreach", "srcquench",
   "redirect", "althostaddr", "unassigned", "echo", "rtrad",
   "rtrsel", "timeexceed", "param", "tstamp", "tstreply",
   "inforeq", "inforeply", "maskreq", "maskreply", "security",

   "robust", "robust", "robust", "robust", "robust",
   "robust", "robust", "robust", "robust", "robust",
   "trace", "datconverr", "mobhostred", "ipv6way", "ipv6iah",
   "mrreq", "mrreply", "dnsreq", "dnsreply", "skip",
   "photuris", "expmobile", "extecho", "extechoreply",
};

struct ArgusTokenStruct llcsap_db[] = {
   { LLCSAP_NULL,   "null" },
   { LLCSAP_8021B_I,   "gsap" },
   { LLCSAP_8021B_G,   "isap" },
   { LLCSAP_SNAPATH,   "snapath" },
   { LLCSAP_IP,      "ipsap" },
   { LLCSAP_SNA1,   "sna1" },
   { LLCSAP_SNA2,   "sna2" },
   { LLCSAP_PROWAYNM,   "p-nm" },
   { LLCSAP_TI,      "ti" },
   { LLCSAP_BPDU,   "stp" },
   { LLCSAP_RS511,   "eia" },
   { LLCSAP_ISO8208,   "x25" },
   { LLCSAP_XNS,   "xns" },
   { LLCSAP_NESTAR,   "nestar" },
   { LLCSAP_PROWAYASLM,   "p-aslm" },
   { LLCSAP_ARP,   "arp" },
   { LLCSAP_SNAP,   "snap" },
   { LLCSAP_VINES1,   "vine1" },
   { LLCSAP_VINES2,   "vine2" },
   { LLCSAP_NETWARE,   "netware" },
   { LLCSAP_NETBIOS,   "netbios" },
   { LLCSAP_IBMNM,   "ibmnm" },
   { LLCSAP_RPL1,   "rpl1" },
   { LLCSAP_UB,      "ub" },
   { LLCSAP_RPL2,   "rpl2" },
   { LLCSAP_ISONS,   "clns" },
   { LLCSAP_GLOBAL,   "gbl" },
   { 0,             NULL }
};

void ArgusLoadList(struct ArgusListStruct *, struct ArgusListStruct *);

void ArgusInitServarray(struct ArgusParserStruct *);
void ArgusInitEprotoarray(void);
void ArgusInitProtoidarray(void);
void ArgusInitEtherarray(void);
void ArgusInitLlcsaparray(void);

void ArgusFreeServarray(struct ArgusParserStruct *);
void ArgusFreeProtoidarray(void);
void ArgusFreeHostarray(void);
void ArgusFreeEtherarray(void);
void ArgusFreeLlcsaparray(void);
void ArgusSetLocalNet(u_int localnet, u_int mask);
void ArgusInitAddrtoname(struct ArgusParserStruct *);

unsigned int ArgusIndexRecord (struct ArgusRecordStruct *);

void ArgusFree (void *buf);
void *ArgusMalloc (int);
void *ArgusCalloc (int, int);
void *ArgusMallocAligned(int, size_t);
void *ArgusRealloc(void *, size_t);
void *ArgusMallocListRecord (struct ArgusParserStruct *, int);
void ArgusFreeListRecord (struct ArgusParserStruct *, void *buf);
int ArgusParserWiresharkManufFile (struct ArgusParserStruct *, char *);

void ArgusAdjustGlobalTime (struct ArgusParserStruct *parser, struct timeval *now);
void ArgusReverseRecordWithFlag (struct ArgusRecordStruct *, int); 
void ArgusReverseRecord (struct ArgusRecordStruct *); 
void ArgusReverseDataRecord (struct ArgusRecordStruct *); 
void ArgusZeroRecord (struct ArgusRecordStruct *); 
void ArgusZeroRecordWithFlag (struct ArgusRecordStruct *, int); 
struct ArgusRecordStruct *ArgusSubtractRecord (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

void ArgusProcessDirection (struct ArgusParserStruct *, struct ArgusRecordStruct *);
struct RaAddressStruct *RaProcessAddress (struct ArgusParserStruct *, struct ArgusLabelerStruct *, unsigned int *, int, int, int); 

int RaProcessAddressLabel (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct ArgusRecordStruct *, unsigned int *, int, int, int); 
int RaProcessAddressLocality (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct ArgusRecordStruct *, unsigned int *, int, int, int); 
char *RaFetchAddressLocalityLabel (struct ArgusParserStruct *, struct ArgusLabelerStruct *, unsigned int *, int, int, int);
char *RaFetchAddressLocalityGroup (struct ArgusParserStruct *, struct ArgusLabelerStruct *, unsigned int *, int, int, int);
int RaFetchAddressLocality (struct ArgusParserStruct *, struct ArgusLabelerStruct *, unsigned int *, int, int, int);

struct ArgusQueueStruct *ArgusNewQueue (void);
void ArgusDeleteQueue (struct ArgusQueueStruct *);
int ArgusGetQueueCount(struct ArgusQueueStruct *);
void ArgusPushQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);
struct ArgusQueueHeader *ArgusPopQueue (struct ArgusQueueStruct *queue, int);
int ArgusAddToQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);
struct ArgusQueueHeader *ArgusRemoveFromQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);

int ArgusConvertInitialWriteStruct (struct WriteStruct *, struct ArgusRecordStruct *);
int ArgusConvertWriteStruct (struct WriteStruct *, struct ArgusRecordStruct *);

struct timeval *RaMinTime (struct timeval *, struct timeval *);
struct timeval *RaMaxTime (struct timeval *, struct timeval *);

struct timeval RaAddTime (struct timeval *, struct timeval *);
struct timeval RaSubTime (struct timeval *, struct timeval *);

long long ArgusDiffTime (struct ArgusTime *, struct ArgusTime *, struct timeval *);
int RaDiffTime (struct timeval *, struct timeval *, struct timeval *);
float RaDeltaFloatTime (struct timeval *, struct timeval *);

int ArgusPrintTime(struct ArgusParserStruct *, char *, size_t, struct timeval *);
char *ArgusGenerateLabel(struct ArgusParserStruct *, struct ArgusRecordStruct *);

void ArgusPrintRecord (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *ptr, int);
void ArgusDump (const u_char *, int, char *, char *);


char *RaGetUserDataString (struct ArgusRecordStruct *);

int ArgusEncode (struct ArgusParserStruct *, const char *, const char *, int, char *, int);
int ArgusEncode32 (struct ArgusParserStruct *, const char *, int , char *, int );

int ArgusEncode64 (struct ArgusParserStruct *, const char *, int, char *, int);
int ArgusEncodeAscii (struct ArgusParserStruct *, const char *, int, char *, int);

void clearArgusWfile(struct ArgusParserStruct *);
extern unsigned int thisnet, localaddr, localnet, netmask;

void ArgusProcessLabelOptions(struct ArgusParserStruct *, char *);
void ArgusProcessGroupOptions(struct ArgusParserStruct *, char *);

void (*RaPrintAlgorithms[ARGUS_MAX_PRINT_ALG])(struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int) = {
   ArgusPrintStartDate,
   ArgusPrintFlags,
   ArgusPrintProto,
   ArgusPrintSrcAddr,
   ArgusPrintSrcPort,
   ArgusPrintDirection,
   ArgusPrintDstAddr,
   ArgusPrintDstPort,
   ArgusPrintSrcPackets,
   ArgusPrintDstPackets,
   ArgusPrintSrcBytes,
   ArgusPrintDstBytes,
   ArgusPrintState,
   NULL,
};


int argus_nametoeproto(char *);
unsigned int __argus_atoin(char *, unsigned int *);

void ArgusNtoH (struct ArgusRecord *);
void ArgusHtoN (struct ArgusRecord *);

void ArgusV2NtoH (struct ArgusV2Record *);
void ArgusV2HtoN (struct ArgusV2Record *);

extern unsigned int getnamehash(const u_char *);
extern struct cnamemem *check_cmem(struct cnamemem *, const u_char *);
extern struct cnamemem *lookup_cmem(struct cnamemem *, const u_char *);
extern struct nnamemem *lookup_nmem(struct nnamemem *, const u_char *);
extern struct nnamemem *check_nmem(struct nnamemem *, const u_char *);
extern struct dbtblmem *lookup_dbtbl(struct dbtblmem *, const u_char *);
extern struct dbtblmem *check_dbtbl(struct dbtblmem *, const u_char *);
extern struct gnamemem *check_group(struct gnamemem *, const u_char *);
extern struct gnamemem *lookup_group(struct gnamemem *, const u_char *);
extern struct snamemem *check_service(struct snamemem *, const u_char *);
extern struct snamemem *lookup_service(struct snamemem *, const u_char *);

extern char *lookup_srcid(const u_char *, struct anamemem *);
extern char *lookup_alias(const u_char *, struct anamemem *);

void ArgusFileFree(struct ArgusFileInput *afi);
void ArgusInputFromFile(struct ArgusInput *input, struct ArgusFileInput *afi);

#else
#define ARGUSPRINTSTARTDATE		0
#define ARGUSPRINTLASTDATE		1
#define ARGUSPRINTTRANSACTIONS		2
#define ARGUSPRINTDURATION		3
#define ARGUSPRINTMEAN		        4
#define ARGUSPRINTMIN			5
#define ARGUSPRINTMAX			6
#define ARGUSPRINTSRCADDR		7
#define ARGUSPRINTDSTADDR		8
#define ARGUSPRINTPROTO			9
#define ARGUSPRINTSRCPORT		10
#define ARGUSPRINTDSTPORT		11
#define ARGUSPRINTSRCTOS		12
#define ARGUSPRINTDSTTOS		13
#define ARGUSPRINTSRCDSBYTE		14
#define ARGUSPRINTDSTDSBYTE		15
#define ARGUSPRINTSRCTTL		16
#define ARGUSPRINTDSTTTL		17
#define ARGUSPRINTBYTES			18
#define ARGUSPRINTSRCBYTES		19
#define ARGUSPRINTDSTBYTES		20
#define ARGUSPRINTAPPBYTES              21
#define ARGUSPRINTSRCAPPBYTES           22
#define ARGUSPRINTDSTAPPBYTES           23
#define ARGUSPRINTPACKETS		24
#define ARGUSPRINTSRCPACKETS		25
#define ARGUSPRINTDSTPACKETS		26
#define ARGUSPRINTLOAD			27
#define ARGUSPRINTSRCLOAD		28
#define ARGUSPRINTDSTLOAD		29
#define ARGUSPRINTLOSS			30
#define ARGUSPRINTSRCLOSS		31
#define ARGUSPRINTDSTLOSS		32
#define ARGUSPRINTPERCENTLOSS		33
#define ARGUSPRINTSRCPERCENTLOSS	34
#define ARGUSPRINTDSTPERCENTLOSS	35
#define ARGUSPRINTRATE			36
#define ARGUSPRINTSRCRATE		37
#define ARGUSPRINTDSTRATE		38
#define ARGUSPRINTSOURCEID		39
#define ARGUSPRINTFLAGS			40
#define ARGUSPRINTSRCMACADDRESS		41
#define ARGUSPRINTDSTMACADDRESS		42
#define ARGUSPRINTDIR			43
#define ARGUSPRINTSRCINTPKT		44
#define ARGUSPRINTDSTINTPKT		45
#define ARGUSPRINTACTSRCINTPKT		46
#define ARGUSPRINTACTDSTINTPKT		47
#define ARGUSPRINTIDLESRCINTPKT		48
#define ARGUSPRINTIDLEDSTINTPKT		49
#define ARGUSPRINTSRCINTPKTMAX		50
#define ARGUSPRINTSRCINTPKTMIN		51
#define ARGUSPRINTDSTINTPKTMAX		52
#define ARGUSPRINTDSTINTPKTMIN		53
#define ARGUSPRINTACTSRCINTPKTMAX	54
#define ARGUSPRINTACTSRCINTPKTMIN	55
#define ARGUSPRINTACTDSTINTPKTMAX	56
#define ARGUSPRINTACTDSTINTPKTMIN	57
#define ARGUSPRINTIDLESRCINTPKTMAX	58
#define ARGUSPRINTIDLESRCINTPKTMIN	59
#define ARGUSPRINTIDLEDSTINTPKTMAX	60
#define ARGUSPRINTIDLEDSTINTPKTMIN	61
#define ARGUSPRINTSPACER		62
#define ARGUSPRINTSRCJITTER		63
#define ARGUSPRINTDSTJITTER		64
#define ARGUSPRINTACTSRCJITTER		65
#define ARGUSPRINTACTDSTJITTER		66
#define ARGUSPRINTIDLESRCJITTER		67
#define ARGUSPRINTIDLEDSTJITTER		68
#define ARGUSPRINTSTATE			69
#define ARGUSPRINTDELTADURATION		70
#define ARGUSPRINTDELTASTARTTIME	71
#define ARGUSPRINTDELTALASTTIME		72
#define ARGUSPRINTDELTASPKTS		73
#define ARGUSPRINTDELTADPKTS		74
#define ARGUSPRINTDELTASRCPKTS		75
#define ARGUSPRINTDELTADSTPKTS		76
#define ARGUSPRINTDELTASRCBYTES		77
#define ARGUSPRINTDELTADSTBYTES		78
#define ARGUSPRINTPERCENTDELTASRCPKTS	79
#define ARGUSPRINTPERCENTDELTADSTPKTS	80
#define ARGUSPRINTPERCENTDELTASRCBYTES	81
#define ARGUSPRINTPERCENTDELTADSTBYTES	82
#define ARGUSPRINTSRCUSERDATA		83
#define ARGUSPRINTDSTUSERDATA		84
#define ARGUSPRINTTCPEXTENSIONS		85
#define ARGUSPRINTSRCWINDOW		86
#define ARGUSPRINTDSTWINDOW		87
#define ARGUSPRINTJOINDELAY		88
#define ARGUSPRINTLEAVEDELAY		89
#define ARGUSPRINTSEQUENCENUMBER	90
#define ARGUSPRINTBINS			91
#define ARGUSPRINTBINNUMBER		92
#define ARGUSPRINTSRCMPLS		93
#define ARGUSPRINTDSTMPLS		94
#define ARGUSPRINTSRCVLAN		95
#define ARGUSPRINTDSTVLAN		96
#define ARGUSPRINTSRCVID		97
#define ARGUSPRINTDSTVID		98
#define ARGUSPRINTSRCVPRI		99
#define ARGUSPRINTDSTVPRI		100
#define ARGUSPRINTSRCIPID		101
#define ARGUSPRINTDSTIPID		102
#define ARGUSPRINTSTARTRANGE		103
#define ARGUSPRINTENDRANGE		104
#define ARGUSPRINTTCPSRCBASE		105
#define ARGUSPRINTTCPDSTBASE		106
#define ARGUSPRINTTCPRTT		107
#define ARGUSPRINTINODE   		108
#define ARGUSPRINTSTDDEV  		109
#define ARGUSPRINTRELDATE		110
#define ARGUSPRINTBYTEOFFSET		111
#define ARGUSPRINTSRCNET		112
#define ARGUSPRINTDSTNET		113
#define ARGUSPRINTSRCDURATION		114
#define ARGUSPRINTDSTDURATION		115
#define ARGUSPRINTTCPSRCMAX		116
#define ARGUSPRINTTCPDSTMAX		117
#define ARGUSPRINTTCPSYNACK		118
#define ARGUSPRINTTCPACKDAT		119
#define ARGUSPRINTSRCSTARTDATE		120
#define ARGUSPRINTSRCLASTDATE		121
#define ARGUSPRINTDSTSTARTDATE		122
#define ARGUSPRINTDSTLASTDATE		123
#define ARGUSPRINTSRCENCAPS		124
#define ARGUSPRINTDSTENCAPS		125
#define ARGUSPRINTSRCPKTSIZE		126
#define ARGUSPRINTSRCMAXPKTSIZE		127
#define ARGUSPRINTSRCMINPKTSIZE		128
#define ARGUSPRINTDSTPKTSIZE		129
#define ARGUSPRINTDSTMAXPKTSIZE		130
#define ARGUSPRINTDSTMINPKTSIZE		131
#define ARGUSPRINTSRCCOUNTRYCODE	132
#define ARGUSPRINTDSTCOUNTRYCODE	133
#define ARGUSPRINTSRCHOPCOUNT		134
#define ARGUSPRINTDSTHOPCOUNT		135
#define ARGUSPRINTICMPID		136
#define ARGUSPRINTLABEL			137
#define ARGUSPRINTSRCINTPKTDIST		138
#define ARGUSPRINTDSTINTPKTDIST		139
#define ARGUSPRINTACTSRCINTPKTDIST	140
#define ARGUSPRINTACTDSTINTPKTDIST	141
#define ARGUSPRINTIDLESRCINTPKTDIST	142
#define ARGUSPRINTIDLEDSTINTPKTDIST	143
#define ARGUSPRINTRETRANS          	144
#define ARGUSPRINTSRCRETRANS          	145
#define ARGUSPRINTDSTRETRANS          	146
#define ARGUSPRINTPERCENTRETRANS        147
#define ARGUSPRINTPERCENTSRCRETRANS     148
#define ARGUSPRINTPERCENTDSTRETRANS     149
#define ARGUSPRINTNACKS          	150
#define ARGUSPRINTSRCNACKS          	151
#define ARGUSPRINTDSTNACKS          	152
#define ARGUSPRINTPERCENTNACKS		153
#define ARGUSPRINTPERCENTSRCNACKS	154
#define ARGUSPRINTPERCENTDSTNACKS	155
#define ARGUSPRINTSOLO          	156
#define ARGUSPRINTSRCSOLO          	157
#define ARGUSPRINTDSTSOLO          	158
#define ARGUSPRINTPERCENTSOLO		159
#define ARGUSPRINTPERCENTSRCSOLO	160
#define ARGUSPRINTPERCENTDSTSOLO	161
#define ARGUSPRINTFIRST          	162
#define ARGUSPRINTSRCFIRST          	163
#define ARGUSPRINTDSTFIRST          	164
#define ARGUSPRINTPERCENTFIRST		165
#define ARGUSPRINTPERCENTSRCFIRST	166
#define ARGUSPRINTPERCENTDSTFIRST	167
#define ARGUSPRINTAUTOID		168
#define ARGUSPRINTSRCASN		169
#define ARGUSPRINTDSTASN		170
#define ARGUSPRINTINODEASN		171
#define ARGUSPRINTCAUSE			172
#define ARGUSPRINTBSSID			173
#define ARGUSPRINTSSID			174
#define ARGUSPRINTKEYSTROKENSTROKE      175
#define ARGUSPRINTKEYSTROKESRCNSTROKE   176
#define ARGUSPRINTKEYSTROKEDSTNSTROKE   177
#define ARGUSPRINTSRCMEANPKTSIZE        178
#define ARGUSPRINTDSTMEANPKTSIZE        179
#define ARGUSPRINTRANK			180
#define ARGUSPRINTSUM                   181
#define ARGUSPRINTRUN                   182
#define ARGUSPRINTIDLETIME              183
#define ARGUSPRINTTCPOPTIONS            184
#define ARGUSPRINTRESPONSE              185
#define ARGUSPRINTTCPSRCGAP		186
#define ARGUSPRINTTCPDSTGAP		187
#define ARGUSPRINTSRCOUI   		188
#define ARGUSPRINTDSTOUI   		189
#define ARGUSPRINTCOR   		190
#define ARGUSPRINTLOCALADDR             191
#define ARGUSPRINTREMOTEADDR            192
#define ARGUSPRINTLOCALNET              193
#define ARGUSPRINTREMOTENET             194
#define ARGUSPRINTAPPBYTERATIO          195
#define ARGUSPRINTPRODUCERCONSUMERRATIO 196
#define ARGUSPRINTTRANSEFFICIENCY       197
#define ARGUSPRINTSRCTRANSEFFICIENCY    198
#define ARGUSPRINTDSTTRANSEFFICIENCY    199
#define ARGUSPRINTINODECOUNTRYCODE	200
#define ARGUSPRINTSRCLATITUDE		201
#define ARGUSPRINTSRCLONGITUDE		202
#define ARGUSPRINTDSTLATITUDE		203
#define ARGUSPRINTDSTLONGITUDE		204
#define ARGUSPRINTINODELATITUDE		205
#define ARGUSPRINTINODELONGITUDE	206
#define ARGUSPRINTSRCLOCAL		207
#define ARGUSPRINTDSTLOCAL		208
#define ARGUSPRINTLOCAL			209
#define ARGUSPRINTSID			210
#define ARGUSPRINTNODE			211
#define ARGUSPRINTINF			212
#define ARGUSPRINTSTATUS		213
#define ARGUSPRINTSRCGROUP		214
#define ARGUSPRINTDSTGROUP		215
#define ARGUSPRINTHASHREF		216
#define ARGUSPRINTHASHINDEX		217
#define ARGUSPRINTSCORE			218
#define ARGUSPRINTSRCNAME		219
#define ARGUSPRINTDSTNAME		220
#define ARGUSPRINTETHERTYPE		221
#define ARGUSPRINTMEANIDLE		222
#define ARGUSPRINTMINIDLE		223
#define ARGUSPRINTMAXIDLE		224
#define ARGUSPRINTSTDDEVIDLE  		225
#define ARGUSPRINTSRCMAXSEG  		226
#define ARGUSPRINTDSTMAXSEG  		227
#define ARGUSPRINTINTFLOW		228
#define ARGUSPRINTACTINTFLOW		229
#define ARGUSPRINTIDLEINTFLOW		230
#define ARGUSPRINTINTFLOWMAX		231
#define ARGUSPRINTINTFLOWMIN		232
#define ARGUSPRINTINTFLOWSDEV		233
#define ARGUSPRINTACTINTFLOWMAX		234
#define ARGUSPRINTACTINTFLOWMIN		235
#define ARGUSPRINTACTINTFLOWSDEV	236
#define ARGUSPRINTIDLEINTFLOWMAX	237
#define ARGUSPRINTIDLEINTFLOWMIN	238
#define ARGUSPRINTIDLEINTFLOWSDEV	239
#define ARGUSPRINTSRCVNID		240
#define ARGUSPRINTDSTVNID		241


extern struct ArgusPrintFieldStruct RaPrintAlgorithmTable[MAX_PRINT_ALG_TYPES];
extern void (*RaPrintAlgorithms[ARGUS_MAX_PRINT_ALG])(struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusProcessLabelOptions(struct ArgusParserStruct *, char *);
extern void ArgusProcessGroupOptions(struct ArgusParserStruct *, char *);

extern void ArgusLoadList(struct ArgusListStruct *, struct ArgusListStruct *);

extern void ArgusInitServarray(struct ArgusParserStruct *);
extern void ArgusInitEprotoarray(void);
extern void ArgusInitProtoidarray(void);
extern void ArgusInitEtherarray(void);
extern void ArgusInitLlcsaparray(void);

extern void ArgusFreeServarray(struct ArgusParserStruct *);
extern void ArgusFreeProtoidarray(void);
extern void ArgusFreeEtherarray(void);
extern void ArgusFreeHostarray(void);
extern void ArgusFreeLlcsaparray(void);
extern void ArgusSetLocalNet(u_int localnet, u_int mask);
extern void ArgusInitAddrtoname(struct ArgusParserStruct *);

extern char *ip_proto_string [];
extern char *icmptypestr[];
extern char *icmptypelongstr[];

extern unsigned int getnamehash(const u_char *);
extern struct cnamemem *lookup_cmem(struct cnamemem *, const u_char *);
extern struct cnamemem *check_cmem(struct cnamemem *, const u_char *);
extern struct nnamemem *lookup_nmem(struct nnamemem *, const u_char *);
extern struct nnamemem *check_nmem(struct nnamemem *, const u_char *);
extern struct dbtblmem *lookup_dbtbl(struct dbtblmem *, const u_char *);
extern struct dbtblmem *check_dbtbl(struct dbtblmem *, const u_char *);
extern struct enamemem *lookup_emem(struct enamemem *, const u_char *);
extern struct enamemem *check_emem(struct enamemem *, const u_char *);

extern struct gnamemem *lookup_group(struct gnamemem *, const u_char *);
extern struct gnamemem *check_group(struct gnamemem *, const u_char *);

extern struct snamemem *lookup_service(struct snamemem *, const u_char *);
extern struct snamemem *check_service(struct snamemem *, const u_char *);

extern char *lookup_srcid(const u_char *, struct anamemem *);
extern char *lookup_alias(const u_char *, struct anamemem *);

extern unsigned int ArgusIndexRecord (struct ArgusRecordStruct *);

extern void *
ArgusRealloc(void *buf, size_t size)
#if defined(__GNUC__)
__attribute__ ((warn_unused_result))
#endif
;

extern int ArgusMkdirPath(const char * const);

extern void ArgusFree (void *buf);
extern void *ArgusMalloc (int);
extern void *ArgusCalloc (int, int);
extern void *ArgusMallocAligned(int, size_t);
extern void *ArgusRealloc(void *, size_t);
extern void *ArgusMallocListRecord (struct ArgusParserStruct *, int);
extern void ArgusFreeListRecord (struct ArgusParserStruct *, void *buf);
extern int ArgusParserWiresharkManufFile (struct ArgusParserStruct *, char *);

extern char *ArgusTrimString (char *str);

extern void ArgusAdjustGlobalTime (struct ArgusParserStruct *parser, struct timeval *now);
extern void ArgusReverseRecordWithFlag (struct ArgusRecordStruct *, int);
extern void ArgusReverseRecord (struct ArgusRecordStruct *); 
extern void ArgusReverseDataRecord (struct ArgusRecordStruct *); 
extern void ArgusZeroRecord (struct ArgusRecordStruct *);  
extern void ArgusZeroRecordWithFlag (struct ArgusRecordStruct *, int); 
extern struct ArgusRecordStruct *ArgusSubtractRecord (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

extern void ArgusProcessDirection (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern struct RaAddressStruct *RaProcessAddress (struct ArgusParserStruct *, struct ArgusLabelerStruct *, unsigned int *, int, int, int); 
extern int RaProcessAddressLabel (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct ArgusRecordStruct *, unsigned int *, int, int, int); 
extern int RaProcessAddressLocality (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct ArgusRecordStruct *, unsigned int *, int, int, int); 
extern char *RaFetchAddressLocalityLabel (struct ArgusParserStruct *, struct ArgusLabelerStruct *, unsigned int *, int, int, int);
extern char *RaFetchAddressLocalityGroup (struct ArgusParserStruct *, struct ArgusLabelerStruct *, unsigned int *, int, int, int);
extern int RaFetchAddressLocality (struct ArgusParserStruct *, struct ArgusLabelerStruct *, unsigned int *, int, int, int);

extern struct ArgusQueueStruct *ArgusNewQueue (void);
extern void ArgusDeleteQueue (struct ArgusQueueStruct *);
extern int ArgusGetQueueCount(struct ArgusQueueStruct *);
extern void ArgusPushQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);
extern struct ArgusQueueHeader *ArgusPopQueue (struct ArgusQueueStruct *queue, int);
extern int ArgusAddToQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);
extern struct ArgusQueueHeader *ArgusRemoveFromQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);

extern void setArgusID(struct ArgusAddrStruct *, void *, int, unsigned int);
extern void setTransportArgusID(struct ArgusTransportStruct *, void *, int, unsigned int);
extern void setParserArgusID(struct ArgusParserStruct *, void *, int, unsigned int);

extern int getParserArgusID(struct ArgusParserStruct *, struct ArgusAddrStruct *);
extern unsigned int getArgusIDType(struct ArgusParserStruct *);
extern int ArgusCommonParseSourceID (struct ArgusAddrStruct *,
                                     struct ArgusParserStruct *, char *);

extern void setArgusManInf (struct ArgusParserStruct *, char *);
extern char *getArgusManInf (struct ArgusParserStruct *);

extern int ArgusConvertInitialWriteStruct (struct WriteStruct *, struct ArgusRecordStruct *);
extern int ArgusConvertWriteStruct (struct WriteStruct *, struct ArgusRecordStruct *);

extern struct timeval *RaMinTime (struct timeval *, struct timeval *);
extern struct timeval *RaMaxTime (struct timeval *, struct timeval *);

extern struct timeval RaAddTime (struct timeval *, struct timeval *);
extern struct timeval RaSubTime (struct timeval *, struct timeval *);

extern long long ArgusDiffTime (struct ArgusTime *, struct ArgusTime *, struct timeval *);
extern int RaDiffTime (struct timeval *, struct timeval *, struct timeval *);
extern float RaDeltaFloatTime (struct timeval *, struct timeval *);

extern char *ArgusGetString (struct ArgusParserStruct *, u_char *, int);
extern char *ArgusGetUuidString (struct ArgusParserStruct *, u_char *, int);

extern int ArgusPrintTime(struct ArgusParserStruct *, char *, size_t, struct timeval *);
extern char *ArgusGenerateLabel(struct ArgusParserStruct *, struct ArgusRecordStruct *);

extern void ArgusPrintRecord (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *ptr, int);
extern void ArgusDump (const u_char *, int, char *, char *);

extern void ArgusMainInit (struct ArgusParserStruct *, int, char **);
extern int RaParseResourceFile (struct ArgusParserStruct *parser, char *file,
                                int enable_soptions, char *directives[],
                                size_t items, ResourceCallback cb);


extern void ArgusPrintCause (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int, int);
extern void ArgusPrintDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int, int);
extern void ArgusPrintStartDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintLastDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcStartDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcLastDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstStartDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstLastDate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSourceID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintNode (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintInf (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintStatus (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintScore (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintFlags (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintMacAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcMacAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstMacAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcMacOuiAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstMacOuiAddress (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintMacOuiAddressLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcMacClass (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstMacClass (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintEtherType (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintProto (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintGreProto (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintGeneveProto (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintAddr (struct ArgusParserStruct *, char *, int, void *, int, char, int, int);
extern void ArgusPrintSrcNet (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintGreSrcAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintGeneveSrcAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcName (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcGroup (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstNet (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintGreDstAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintGeneveDstAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstName (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstGroup (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintLocalNet (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintLocalAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintRemoteNet (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintRemoteAddr (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPort (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int, unsigned char, unsigned int, int, int);
extern void ArgusPrintSrcPort (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstPort (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDirection (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPackets (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcPackets (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstPackets (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintAppBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcAppBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstAppBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintSrcIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveSrcIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveSrcIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveDstIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveDstIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleSrcIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleSrcIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleDstIntPkt (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleDstIntPktDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveSrcIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveSrcIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveDstIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveDstIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleSrcIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleSrcIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleDstIntPktMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleDstIntPktMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintIntFlow (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIntFlowDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveIntFlow (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveIntFlowDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleIntFlow (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleIntFlowDist (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIntFlowStdDev (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIntFlowMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIntFlowMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveIntFlowStdDev (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveIntFlowMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveIntFlowMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleIntFlowStdDev (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleIntFlowMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleIntFlowMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstJitter (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintState (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaStartTime (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaLastTime (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaSrcPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaDstPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaSrcBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDeltaDstBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPercentDeltaSrcPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPercentDeltaDstPkts (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPercentDeltaSrcBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPercentDeltaDstBytes (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcUserData (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstUserData (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTCPExtensions (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcLoad (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstLoad (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintLoad (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintPercentLoss (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcRate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstRate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintRate (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcTos (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstTos (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcDSByte (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstDSByte (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcIpId (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstIpId (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcTtl (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcVlan (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstVlan (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcVID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstVID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcVPRI (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstVPRI (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcMpls (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstMpls (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcWindow (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstWindow (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcMaxSeg (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstMaxSeg (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintJoinDelay (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintLeaveDelay (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintMean (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleMean (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleStdDeviation (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintStartRange (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintEndRange (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSrcDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDuration (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTransactions (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintSequenceNumber (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintHashRef (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintHashIndex (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintRank (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintBinNumber (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintBins (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTCPSrcBase (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTCPDstBase (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTCPRTT (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTCPSrcMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTCPDstMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTCPSrcGap (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintTCPDstGap (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintInode (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintMin (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintMax (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintStdDeviation (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintRunTime (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleTime (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintSrcVirtualNID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstVirtualNID (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintLabelLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintCauseLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDateLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintStartDateLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintLastDateLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSourceIDLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSIDLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintNodeLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintInfLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintStatusLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintScoreLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintFlagsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcMacAddressLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstMacAddressLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcMacOuiAddressLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstMacOuiAddressLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintEtherTypeLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintProtoLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintGreProtoLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintGeneveProtoLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcAddrLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcNameLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcGroupLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstAddrLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstNameLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintLocalAddrLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintRemoteAddrLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcPortLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstPortLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcIpIdLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstIpIdLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcTtlLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstTtlLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDirectionLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintPacketsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcPacketsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstPacketsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintAppBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcAppBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstAppBytesLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcIntPktLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcIntPktDistLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstIntPktLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstIntPktDistLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintActiveIntPktLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintActiveIntPktLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintActiveIntPktDistLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintActiveSrcIntPktLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintActiveSrcIntPktDistLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintActiveDstIntPktLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintActiveDstIntPktDistLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintIdleIntPktLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintIdleIntPktDistLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintIdleSrcIntPktLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintIdleSrcIntPktDistLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintIdleDstIntPktLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintIdleDstIntPktDistLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcIntPktMinLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstIntPktMinLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintActiveSrcIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintActiveSrcIntPktMinLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintActiveDstIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintActiveDstIntPktMinLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintIdleSrcIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintIdleSrcIntPktMinLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintIdleDstIntPktMaxLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintIdleDstIntPktMinLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintIntFlowLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIntFlowDistLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveIntFlowLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveIntFlowDistLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleIntFlowLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleIntFlowDistLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIntFlowStdDevLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIntFlowMaxLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIntFlowMinLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveIntFlowStdDevLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveIntFlowMaxLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintActiveIntFlowMinLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleIntFlowStdDevLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleIntFlowMaxLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintIdleIntFlowMinLabel (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintJitterLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcJitterLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstJitterLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintStateLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaDurationLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaStartTimeLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaLastTimeLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaSrcPktsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaDstPktsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaSrcBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDeltaDstBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintPercentDeltaSrcPktsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintPercentDeltaDstPktsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintPercentDeltaSrcBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintPercentDeltaDstBytesLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcUserDataLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstUserDataLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintTCPExtensionsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcLoadLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstLoadLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcLoadLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstLoadLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintLoadLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcLossLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstLossLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintLossLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintPercentLossLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcRateLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstRateLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintRateLabel (struct ArgusParserStruct *, char *, int);


extern void ArgusPrintSrcTosLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstTosLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcDSByteLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstDSByteLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcVlanLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstVlanLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcVIDLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstVIDLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcVPRILabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstVPRILabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcMplsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstMplsLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintWindowLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcWindowLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstWindowLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcMaxSegLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDstMaxSegLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintJoinDelayLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintLeaveDelayLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintMeanLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintStartRangeLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintEndRangeLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcDurationLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSrcDurationLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintDurationLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTransactionsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintSequenceNumberLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintHashRefLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintHashIndexLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintRankLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintBinNumberLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintBinsLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTCPSrcBaseLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTCPDstBaseLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTCPRTTLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTCPSrcMaxLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTCPDstMaxLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTCPSrcGapLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintTCPDstGapLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintInodeLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintMinLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintMaxLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintStdDeviationLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintRunTimeLabel (struct ArgusParserStruct *, char *, int);
extern void ArgusPrintIdleTimeLabel (struct ArgusParserStruct *, char *, int);

extern void ArgusPrintSrcOui (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstOui (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintProducerConsumerRatio (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

extern void ArgusPrintAutoId (struct ArgusParserStruct *, char *, int);

extern char *RaGetUserDataString (struct ArgusRecordStruct *);

extern int ArgusEncode (struct ArgusParserStruct *, const char *, const char *, int, char *, int);
extern int ArgusEncode32 (struct ArgusParserStruct *, const char *, int , char *, int );
extern int ArgusEncode64 (const char *, int, char *, int);
extern int ArgusEncodeAscii (const char *, int, char *, int);

extern int argus_nametoeproto(char *);
extern unsigned int __argus_atoin(char *, unsigned int *);


extern void ArgusNtoH (struct ArgusRecord *);
extern void ArgusHtoN (struct ArgusRecord *);

extern void ArgusV2NtoH (struct ArgusV2Record *);
extern void ArgusV2HtoN (struct ArgusV2Record *);

void ArgusFileFree(struct ArgusFileInput *afi);
void ArgusInputFromFile(struct ArgusInput *input, struct ArgusFileInput *afi);
#endif 
#ifdef __cplusplus
}
#endif
#endif /* ArgusUtil_h */
