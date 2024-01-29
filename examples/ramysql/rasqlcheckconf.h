/*
 * Argus-5.0 Software.  Argus files - Modeler includes
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
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
 
#include <argus_compat.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>

#include <argus_namedb.h>
#include <argus_filter.h>


/*
 * Argus-5.0 Software.  Argus files - Modeler includes
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
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */

#ifndef ArgusModeler_h
#define ArgusModeler_h

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pwd.h>

#if defined(ARGUS_THREADS)
#include <pthread.h>
#endif
 
#include <argus_encapsulations.h>
 
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <netinet/in.h>
#include <grp.h>

#if defined(HAVE_UUID_UUID_H)
#include <uuid/uuid.h>
#else
#if defined(HAVE_LINUX_UUID_H)
#include <linux/uuid.h>
#else
#if defined(HAVE_UUID_H)
#include <uuid.h>
#endif
#endif
#endif

#define RA_NUMTABLES            1
#define RA_NUMTABLES_MASK       0x0001
#define RA_MAXTABLES            0x100

char *RaTableValues[256];
char *RaExistsTableNames[RA_MAXTABLES];
char *RaRoleString = NULL;

int RaProjectExists = 0;

char *RaCreateTableNames[RA_NUMTABLES] = {
   "ArgusConf",
};

char *RaTableCreationString[RA_NUMTABLES] = {
   "CREATE TABLE %s (label varchar(255) not null, value varchar(255) not null)",
};

#define RA_MAXSQLQUERY          1
char *RaTableQueryString[RA_MAXSQLQUERY] = {
   "SELECT * from %s",
};


#define ARGUS_MARSTATUSTIMER	"60"
#define ARGUS_FARSTATUSTIMER	"5"

#define ARGUS_INITIMEOUT	5
#define ARGUS_IPTIMEOUT		30 
#define ARGUS_ARPTIMEOUT	5 
#define ARGUS_TCPTIMEOUT	60
#define ARGUS_ICMPTIMEOUT	5
#define ARGUS_IGMPTIMEOUT	30
#define ARGUS_OTHERTIMEOUT	30
#define ARGUS_FRAGTIMEOUT	5

#define ARGUS_MINSNAPLEN	96
#define ARGUS_MINIPHDRLEN	20
#define ARGUS_HASHTABLESIZE	0x10000

#define ARGUS_REQUEST		0x01
#define ARGUS_REPLY		0x02

#define ARGUS_RTP_PCMU		0
#define ARGUS_RTP_1016		1
#define ARGUS_RTP_G726		2
#define ARGUS_RTP_GSM		3
#define ARGUS_RTP_G723		4
#define ARGUS_RTP_DVI4_8K	5
#define ARGUS_RTP_DVI4_16K	6
#define ARGUS_RTP_PCMA		8
#define ARGUS_RTP_G722		9
#define ARGUS_RTP_L16_STEREO	10
#define ARGUS_RTP_L16_MONO	11
#define ARGUS_RTP_QCELP		12
#define ARGUS_RTP_MPA		14
#define ARGUS_RTP_G728		15
#define ARGUS_RTP_DVI4_11K	16
#define ARGUS_RTP_DVI4_22K	17
#define ARGUS_RTP_G729		18
#define ARGUS_RTP_CELB		25
#define ARGUS_RTP_JPEG		26
#define ARGUS_RTP_NV		28
#define ARGUS_RTP_H261		31
#define ARGUS_RTP_MPV		32
#define ARGUS_RTP_MP2T		33
#define ARGUS_RTP_H263		34

#define ARGUS_SSH_MONITOR       0x20000

#define ARGUS_ETHER_HDR		1
#define ARGUS_802_11_HDR	2

#define ARGUS_DEBUG		0xFF

#define ARGUSTIMEOUTQS		65534

#define ARGUS_CLNS    129
#define ARGUS_ESIS    130
#define ARGUS_ISIS    131
#define ARGUS_NULLNS  132


/* True if  "l" bytes of "var" were captured */
#define BYTESCAPTURED(m, var, l) ((u_char *)&(var) <= m->ArgusThisSnapEnd - (l))

/* True if "var" was captured */
#define STRUCTCAPTURED(m, var) BYTESCAPTURED(m, var, sizeof(var))

/* Bail if "l" bytes of "var" were not captured */
#define BYTESCHECK(m, var, l) if (!BYTESCAPTURED(m, var, l)) goto trunc

/* Bail if "var" was not captured */
#define STRUCTCHECK(m, var) BYTESCHECK(m, var, sizeof(var))

#define LENCHECK(m, l) { if ((l) > len) goto bad; BYTESCHECK(m, *cp, l); }



#if defined(HAVE_SOLARIS) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/socket.h>

#if !defined(__OpenBSD__) || (defined(__OpenBSD__) && !defined(_NET_IF_H_))
#include <net/if.h>
#define _NET_IF_H_
#endif
#endif

#if !defined(__OpenBSD__) || (defined(__OpenBSD__) && !defined(_NETINET_IF_SYSTEM_H_))
#include <netinet/in_systm.h>
#define _NETINET_IF_SYSTEM_H_
#endif

#if !defined(__OpenBSD__)
#include <netinet/if_ether.h>
#endif

#ifndef _NETINET_IP_H_
#include <netinet/ip.h>
#define _NETINET_IP_H_
#endif

#ifndef _NETINET_IPV6_H_
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#define _NETINET_IPV6_H_
#endif

#ifndef _NETINET_UDP_H_
#include <netinet/udp.h>
#define _NETINET_UDP_H_
#endif

#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/rtp.h>

#include <argus_def.h>
#include <argus_out.h>

struct AHHeader {
   unsigned char  nxt, len;
   unsigned short pad;
   unsigned int   spi, replay, data;
};

struct ArgusHashTableHeader {
   struct ArgusHashTableHeader *nxt, *prv;
   struct ArgusHashTable *htbl;
   struct ArgusHashStruct hstruct;
   void *object;
};


#define ARGUS_MAXSNAPLEN	65535
#define ARGUS_MAX_MPLS_LABELS	4


struct ArgusKeyStrokeConf {
   int status, state, n_min;
   int dc_min, dc_max, gs_max;
   int ds_min, ds_max, gpc_max;
   int ic_min, lcs_max;
   float icr_min, icr_max;
};

struct ArgusControlProtocols {
   char tcpport[0x10000];
   char udpport[0x10000];
};


struct ArgusModelerStruct {
   int state, status;
#if defined(ARGUS_THREADS)
   pthread_t thread;
   pthread_mutex_t lock;
#endif

   struct ArgusSourceStruct *ArgusSrc;
   struct ArgusQueueStruct *ArgusStatusQueue;
   struct ArgusQueueStruct *ArgusTimeOutQueues;
   struct ArgusQueueStruct *ArgusTimeOutQueue[ARGUSTIMEOUTQS];
   struct ArgusListStruct *ArgusOutputList;
   struct ArgusHashTable *ArgusHashTable;
   struct ArgusSystemFlow  *ArgusThisFlow;
   struct ArgusHashStruct *hstruct;

   unsigned int ArgusTransactionNum;
   unsigned int ArgusSeqNum;
   unsigned int ArgusPcapBufSize;

   int ArgusStatusQueueTimeout;
   int ArgusDaemon;

   long long ival;

   unsigned int ArgusThisInterface;
   unsigned int ArgusThisEncaps;
   unsigned int ArgusThisNetworkFlowType;
   struct llc *ArgusThisLLC;
   unsigned int ArgusThisAppFlowType;
   int ArgusThisMplsLabelIndex;
   unsigned int ArgusThisMplsLabel;
   unsigned int ArgusThisVxLanVni;
   unsigned int ArgusThisPacket8021QEncaps;
   unsigned char ArgusFlowType, ArgusFlowKey;
   unsigned short ArgusOptionIndicator;

   int ArgusInProtocol, ArgusThisDir, ArgusTrackDuplicates;

   struct ArgusKeyStrokeConf ArgusKeyStroke;
   struct ArgusUniStats *ArgusThisStats;
 
   int ArgusControlMonitor;
   struct ArgusControlProtocols *cps;

   int ArgusSnapLength;
   int ArgusGenerateTime;
   int ArgusGeneratePacketSize;

   struct timeval ArgusGlobalTime;
   struct timeval ArgusStartTime;
   struct timeval ArgusNowTime;
   struct timeval ArgusUpdateInterval;
   struct timeval ArgusUpdateTimer;

   int ArgusMajorVersion;
   int ArgusMinorVersion;
   int ArgusSnapLen;
 
   int ArgusTunnelDiscovery;
   int ArgusOSFingerPrinting;
   int ArgusUserDataLen;
   int ArgusSelfSynchronize;

   int ArgusAflag, ArgusTCPflag, Argusmflag;
   int Argusvflag, ArgusOflag;

   int ArgusIPTimeout;
   int ArgusTCPTimeout;
   int ArgusICMPTimeout;
   int ArgusIGMPTimeout;
   int ArgusFRAGTimeout;
   int ArgusARPTimeout;
   int ArgusOtherTimeout;

   int ArgusReportAllTime;
   int ArgusResponseStatus;

   struct timeval ArgusFarReportInterval;
   struct timeval ArgusQueueInterval;
   struct timeval ArgusListenInterval;

   char *ArgusBindAddr;
   char *ArgusChrootDir;

   uid_t ArgusNewUid;
   gid_t ArgusNewGid;

   unsigned int ArgusFilterOptimizer;
   unsigned int ArgusCaptureFullControlData;
   unsigned int ArgusDumpPacket;
   unsigned int ArgusDumpPacketOnError;

   char *ArgusWriteOutPacketFile;
   char *ArgusInputFilter;
};

#define ARGUS_EVENT_OS_STATUS   0x00000001
#define ARGUS_ZLIB_COMPRESS     0x00000001
#define ARGUS_ZLIB_COMPRESS2    0x00000002

struct ArgusTimeStats {
   unsigned int n;
   float minval, maxval, sum;
   long long sumsqrd;
};

struct ArgusTimeStat {
   struct timeval lasttime;
   struct ArgusTimeStats act, idle;
};


#define ARGUS_NUM_KEYSTROKE_PKTS	8
#define ARGUS_KEYSTROKE_NONE		0
#define ARGUS_KEYSTROKE_TENTATIVE	1
#define ARGUS_KEYSTROKE_KNOWN		2

struct ArgusKeyStrokePacket {
   int status, n_pno;
   struct ArgusTime ts;
   unsigned int seq;
   long long intpkt;
};

struct ArgusKeyStrokeData {
   struct ArgusKeyStrokePacket pkts[ARGUS_NUM_KEYSTROKE_PKTS];
};

struct ArgusKeyStrokeState {
   int status, n_pkts, n_strokes, prev_pno;
   struct ArgusKeyStrokeData data;
   struct ArgusTime prev_c_ts, prev_s_ts;
};

struct ArgusFlowStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusHashTableHeader htblbuf, *htblhdr;
   struct ArgusDSRHeader *dsrs[ARGUSMAXDSRTYPE];
   struct ArgusQueueStruct frag;

   unsigned int state, status, dsrindex;
   unsigned int ArgusEncaps;

   unsigned short trans, timeout;
   unsigned short userlen;
   signed char srcint, dstint;
   unsigned short sipid, dipid;


   struct ArgusTimeStat stime, dtime;
   struct ArgusKeyStrokeState skey;
   struct ArgusCanonRecord canon;
};


#if defined(ArgusModeler)

#if defined(LBL_ALIGN)
#define ARGUS_MAXALIGNBUF  65536
unsigned char ArgusAlignBuffer[ARGUS_MAXALIGNBUF], *ArgusAlignBuf = ArgusAlignBuffer;
#endif

struct ArgusModelerStruct *ArgusModel = NULL;

struct llc ArgusThisLLCBuffer;

unsigned char argusDSRTypes [ARGUSMAXDSRTYPE] = {
   ARGUS_TRANSPORT_DSR, ARGUS_FLOW_DSR, ARGUS_TIME_DSR,
   ARGUS_METER_DSR, ARGUS_AGR_DSR,
};


struct ArgusEventsStruct *ArgusEventsTask = NULL;

struct timeval ArgusQueueTime = {0, 0};
struct timeval ArgusQueueInterval = {0, 50000};
struct timeval ArgusListenTime = {0, 0};
struct timeval ArgusListenInterval = {0, 250000};

typedef unsigned short (*pproc)(struct ArgusModelerStruct *, void *ptr);
pproc ArgusTransportParseRoutines [0x10000];
void ArgusInitTunnelPortNumbers (void);

struct ArgusModelerStruct *ArgusNewModeler(void);
struct ArgusModelerStruct *ArgusCloneModeler(struct ArgusModelerStruct *);

void ArgusInitModeler(struct ArgusModelerStruct *);
void ArgusCloseModeler(struct ArgusModelerStruct *);

int ArgusProcessEtherPacket (struct ArgusModelerStruct *, struct ether_header *, int, struct timeval *);
int ArgusProcessIpPacket (struct ArgusModelerStruct *, struct ip *, int, struct timeval *);
extern int ArgusProcessEtherHdr (struct ArgusModelerStruct *, struct ether_header *, int);

unsigned short ArgusDiscoverNetworkProtocol (unsigned char *);
void ArgusParseMPLSLabel (unsigned int, unsigned int *, unsigned char *, unsigned char *, unsigned char *);

void ArgusSendFlowRecord (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char);

struct ArgusFlowStruct *ArgusNewFlow (struct ArgusModelerStruct *, struct ArgusSystemFlow *, struct ArgusHashStruct *, struct ArgusQueueStruct *);
extern struct ArgusFlowStruct *ArgusNewFragFlow (void);

void ArgusTallyStats (struct ArgusModelerStruct *, struct ArgusFlowStruct *);
void ArgusTallyTime (struct ArgusFlowStruct *, unsigned char);

unsigned short ArgusParseIPOptions (unsigned char *, int);

void setArgusIpTimeout (struct ArgusModelerStruct *model, int value);
void setArgusTcpTimeout (struct ArgusModelerStruct *model, int value);
void setArgusIcmpTimeout (struct ArgusModelerStruct *model, int value);
void setArgusIgmpTimeout (struct ArgusModelerStruct *model, int value);
void setArgusFragTimeout (struct ArgusModelerStruct *model, int value);
void setArgusArpTimeout (struct ArgusModelerStruct *model, int value);
void setArgusOtherTimeout (struct ArgusModelerStruct *model, int value);

void setArgusSynchronize (struct ArgusModelerStruct *, int);

int getArgusKeystroke(struct ArgusModelerStruct *);
void setArgusKeystroke(struct ArgusModelerStruct *, int);
void setArgusKeystrokeVariable(struct ArgusModelerStruct *, char *);

int getArgusOSFingerPrinting (struct ArgusModelerStruct *);
void setArgusOSFingerPrinting (struct ArgusModelerStruct *, int);

void setArgusControlPlaneProtocols(struct ArgusModelerStruct *, char *);

int getArgusTunnelDiscovery (struct ArgusModelerStruct *);
void setArgusTunnelDiscovery (struct ArgusModelerStruct *, int);

int getArgusTrackDuplicates (struct ArgusModelerStruct *);
void setArgusTrackDuplicates (struct ArgusModelerStruct *, int);

void setArgusFlowKey(struct ArgusModelerStruct *, int);
void setArgusFlowType(struct ArgusModelerStruct *, int);

int getArgusAflag(struct ArgusModelerStruct *);
void setArgusAflag(struct ArgusModelerStruct *, int);
int getArgusTCPflag(struct ArgusModelerStruct *);
void setArgusTCPflag(struct ArgusModelerStruct *, int);
int getArgusmflag(struct ArgusModelerStruct *);
void setArgusmflag(struct ArgusModelerStruct *, int);
int getArgusUserDataLen(struct ArgusModelerStruct *);
void setArgusUserDataLen(struct ArgusModelerStruct *, int);
int getArgusControlMonitor(struct ArgusModelerStruct *);
void setArgusControlMonitor(struct ArgusModelerStruct *);

int getArgusGenerateTime(struct ArgusModelerStruct *);
void setArgusGenerateTime(struct ArgusModelerStruct *, int);
int getArgusGeneratePacketSize(struct ArgusModelerStruct *);
void setArgusGeneratePacketSize(struct ArgusModelerStruct *, int);
void setArgusTimeReport(struct ArgusModelerStruct *, int);

struct timeval *getArgusQueueInterval(struct ArgusModelerStruct *);
struct timeval *getArgusListenInterval(struct ArgusModelerStruct *);


extern struct udt_control_handshake *ArgusThisUdtHshake;
extern int ArgusParseUDTHeader (struct ArgusModelerStruct *, struct udt_header *, unsigned int *);

int getArgusdflag(struct ArgusModelerStruct *);
void setArgusdflag(struct ArgusModelerStruct *, int);

void setArgusLink(struct ArgusModelerStruct *, unsigned int);
void ArgusModelerCleanUp (struct ArgusModelerStruct *);

void *ArgusQueueManager(void *); 

int ArgusCreateFlowKey (struct ArgusModelerStruct *, struct ArgusSystemFlow *, struct ArgusHashStruct *);
struct ArgusFlowStruct *ArgusFindFlow (struct ArgusModelerStruct *, struct ArgusHashStruct *);

void ArgusICMPMappedFlowRecord (struct ArgusFlowStruct *, struct ArgusRecord *, unsigned char);

struct ArgusFlowStruct *ArgusUpdateState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char, unsigned char);
struct ArgusFlowStruct *ArgusUpdateFlow (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char, unsigned char);
void ArgusUpdateAppState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char);

void ArgusModelTransmit (void);

int ArgusUpdateTime (struct ArgusModelerStruct *);
void ArgusTimeOut(struct ArgusFlowStruct *);

int getArgusMajorVersion(struct ArgusModelerStruct *);
void setArgusMajorVersion(struct ArgusModelerStruct *, int);

int getArgusMinorVersion(struct ArgusModelerStruct *);
void setArgusMinorVersion(struct ArgusModelerStruct *, int);

int getArgusManReportInterval(struct ArgusModelerStruct *);
void setArgusManReportInterval(struct ArgusModelerStruct *, int);

struct timeval *getArgusFarReportInterval(struct ArgusModelerStruct *);
void setArgusFarReportInterval(struct ArgusModelerStruct *, char *);

int getArgusResponseStatus(struct ArgusModelerStruct *);
void setArgusResponseStatus(struct ArgusModelerStruct *, int value);

int getArgusIpTimeout(struct ArgusModelerStruct *);
void setArgusIpTimeout(struct ArgusModelerStruct *, int);

int getArgusTcpTimeout(struct ArgusModelerStruct *);
void setArgusTcpTimeout(struct ArgusModelerStruct *, int);

int getArgusIcmpTimeout(struct ArgusModelerStruct *);
void setArgusIcmpTimeout(struct ArgusModelerStruct *, int);

int getArgusIgmpTimeout(struct ArgusModelerStruct *);
void setArgusIgmpTimeout(struct ArgusModelerStruct *, int);

int getArgusFragTimeout(struct ArgusModelerStruct *);
void setArgusFragTimeout(struct ArgusModelerStruct *, int);

int getArgusArpTimeout(struct ArgusModelerStruct *);
void setArgusArpTimeout(struct ArgusModelerStruct *, int);

int getArgusOtherTimeout(struct ArgusModelerStruct *);
void setArgusOtherTimeout(struct ArgusModelerStruct *, int);


unsigned int getArgusLocalNet(struct ArgusModelerStruct *);
void setArgusLocalNet(struct ArgusModelerStruct *, unsigned int);

unsigned int getArgusNetMask(struct ArgusModelerStruct *);
void setArgusNetMask(struct ArgusModelerStruct *, unsigned int);


void ArgusSystemTimeout (struct ArgusModelerStruct *);

#else /* #if defined(ArgusModeler) */

extern struct ArgusModelerStruct *ArgusModel;
extern struct llc ArgusThisLLCBuffer;

#if defined(LBL_ALIGN)
extern unsigned char *ArgusAlignBuf;
#endif

#if defined(Argus)
void clearArgusConfiguration (struct ArgusModelerStruct *);
#endif

typedef unsigned short (*pproc)(void *ptr);
extern pproc ArgusTransportParseRoutines [];

extern struct ArgusModelerStruct *ArgusNewModeler(void);
extern struct ArgusModelerStruct *ArgusCloneModeler(struct ArgusModelerStruct *);

extern void ArgusInitModeler(struct ArgusModelerStruct *);
extern void ArgusCloseModeler(struct ArgusModelerStruct *);

extern int ArgusProcessEtherPacket (struct ArgusModelerStruct *, struct ether_header *, int, struct timeval *);
extern int ArgusProcessIpPacket (struct ArgusModelerStruct *, struct ip *, int, struct timeval *);
extern int ArgusProcessEtherHdr (struct ArgusModelerStruct *, struct ether_header *, int);

extern unsigned short ArgusDiscoverNetworkProtocol (unsigned char *);
extern void ArgusParseMPLSLabel (unsigned int, unsigned int *, unsigned char *, unsigned char *, unsigned char *);

extern void ArgusSendFlowRecord (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char);

extern struct ArgusFlowStruct *ArgusNewFlow (struct ArgusModelerStruct *, struct ArgusSystemFlow *, struct ArgusHashStruct *, struct ArgusQueueStruct *);
extern struct ArgusFlowStruct *ArgusNewFragFlow (void);

extern void ArgusTallyStats (struct ArgusModelerStruct *, struct ArgusFlowStruct *);
extern void ArgusTallyTime (struct ArgusFlowStruct *, unsigned char);

extern unsigned short ArgusParseIPOptions (unsigned char *, int);

extern void setArgusIpTimeout (struct ArgusModelerStruct *model, int value);
extern void setArgusTcpTimeout (struct ArgusModelerStruct *model, int value);
extern void setArgusIcmpTimeout (struct ArgusModelerStruct *model, int value);
extern void setArgusIgmpTimeout (struct ArgusModelerStruct *model, int value);
extern void setArgusFragTimeout (struct ArgusModelerStruct *model, int value);
extern void setArgusArpTimeout (struct ArgusModelerStruct *model, int value);
extern void setArgusOtherTimeout (struct ArgusModelerStruct *model, int value);

extern void setArgusSynchronize (struct ArgusModelerStruct *, int);

extern int getArgusKeystroke(struct ArgusModelerStruct *);
extern void setArgusKeystroke(struct ArgusModelerStruct *, int);
extern void setArgusKeystrokeVariable(struct ArgusModelerStruct *, char *);

extern int getArgusOSFingerPrinting (struct ArgusModelerStruct *);
extern void setArgusOSFingerPrinting (struct ArgusModelerStruct *, int);

extern void setArgusControlPlaneProtocols(struct ArgusModelerStruct *, char *);

extern int getArgusTunnelDiscovery(struct ArgusModelerStruct *);
extern void setArgusTunnelDiscovery(struct ArgusModelerStruct *, int);

extern int getArgusTrackDuplicates (struct ArgusModelerStruct *);
extern void setArgusTrackDuplicates (struct ArgusModelerStruct *, int);

extern void setArgusFlowKey(struct ArgusModelerStruct *, int);
extern void setArgusFlowType(struct ArgusModelerStruct *, int);

extern void setArgusCollector(struct ArgusModelerStruct *, int);

extern int getArgusAflag(struct ArgusModelerStruct *);
extern void setArgusAflag(struct ArgusModelerStruct *, int);
extern int getArgusTCPflag(struct ArgusModelerStruct *);
extern void setArgusTCPflag(struct ArgusModelerStruct *, int);
extern int getArgusmflag(struct ArgusModelerStruct *);
extern void setArgusmflag(struct ArgusModelerStruct *, int);
extern int getArgusUserDataLen(struct ArgusModelerStruct *);
extern void setArgusUserDataLen(struct ArgusModelerStruct *, int);
extern int getArgusControlMonitor(struct ArgusModelerStruct *);
extern void setArgusControlMonitor(struct ArgusModelerStruct *);

extern struct timeval ArgusQueueInterval;
extern struct timeval *getArgusQueueInterval(void);

extern struct timeval ArgusListenInterval;
extern struct timeval *getArgusListenInterval(void);

extern struct udt_control_handshake *ArgusThisUdtHshake;
extern int ArgusParseUDTHeader (struct ArgusModelerStruct *, struct udt_header *, unsigned int *);

extern int getArgusGenerateTime(struct ArgusModelerStruct *);
extern void setArgusGenerateTime(struct ArgusModelerStruct *, int);

extern int getArgusGeneratePacketSize(struct ArgusModelerStruct *);
extern void setArgusGeneratePacketSize(struct ArgusModelerStruct *, int);

extern void setArgusTimeReport(struct ArgusModelerStruct *, int);

extern int getArgusKeystroke(struct ArgusModelerStruct *);
extern void setArgusKeystroke(struct ArgusModelerStruct *, int);

extern int getArgusdflag(struct ArgusModelerStruct *);
extern struct timeval *getArgusFarReportInterval(struct ArgusModelerStruct *);

extern void setArgusdflag(struct ArgusModelerStruct *, int);
extern void setArgusFarReportInterval(struct ArgusModelerStruct *, char *);

extern void setArgusLink(struct ArgusModelerStruct *, unsigned int);
extern void ArgusModelerCleanUp (struct ArgusModelerStruct *);

extern void ArgusUpdateBasicFlow (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char);

extern void *ArgusQueueManager(void *); 

extern struct ArgusFlowStruct *ArgusFindFlow (struct ArgusModelerStruct *, struct ArgusHashStruct *);
extern int ArgusCreateFlowKey (struct ArgusModelerStruct *, struct ArgusSystemFlow *, struct ArgusHashStruct *);

extern void ArgusICMPMappedFlowRecord (struct ArgusFlowStruct *, struct ArgusRecord *, unsigned char);

extern struct ArgusFlowStruct *ArgusUpdateState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char, unsigned char);
extern struct ArgusFlowStruct *ArgusUpdateFlow (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char, unsigned char);
extern void ArgusUpdateAppState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char);

extern void ArgusModelTransmit (void);

extern int ArgusUpdateTime (struct ArgusModelerStruct *);
extern void ArgusTimeOut(struct ArgusFlowStruct *);

extern int getArgusMajorVersion(struct ArgusModelerStruct *);
extern void setArgusMajorVersion(struct ArgusModelerStruct *, int);

extern int getArgusMinorVersion(struct ArgusModelerStruct *);
extern void setArgusMinorVersion(struct ArgusModelerStruct *, int);

extern int getArgusManReportInterval(struct ArgusModelerStruct *);
extern void setArgusManReportInterval(struct ArgusModelerStruct *, int);

extern int getArgusStatusReportInterval(struct ArgusModelerStruct *);
extern void setArgusStatusReportInterval(struct ArgusModelerStruct *, int);

extern int getArgusResponseStatus(struct ArgusModelerStruct *);
extern void setArgusResponseStatus(struct ArgusModelerStruct *, int value);

extern int getArgusIPTimeout(struct ArgusModelerStruct *);
extern void setArgusIPTimeout(struct ArgusModelerStruct *, int);

extern int getArgusTCPTimeout(struct ArgusModelerStruct *);
extern void setArgusTCPTimeout(struct ArgusModelerStruct *, int);

extern int getArgusICMPTimeout(struct ArgusModelerStruct *);
extern void setArgusICMPTimeout(struct ArgusModelerStruct *, int);

extern int getArgusIGMPTimeout(struct ArgusModelerStruct *);
extern void setArgusIGMPTimeout(struct ArgusModelerStruct *, int);

extern int getArgusFRAGTimeout(struct ArgusModelerStruct *);
extern void setArgusFRAGTimeout(struct ArgusModelerStruct *, int);

extern unsigned int getArgusLocalNet(struct ArgusModelerStruct *);
extern void setArgusLocalNet(struct ArgusModelerStruct *, unsigned int);

extern unsigned int getArgusNetMask(struct ArgusModelerStruct *);
extern void setArgusNetMask(struct ArgusModelerStruct *, unsigned int);

extern void ArgusSystemTimeout (struct ArgusModelerStruct *);

#endif /* #if defined(ArgusModeler) else */
#endif /* #ifndef ArgusModeler_h */
