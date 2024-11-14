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
 * $Id: //depot/gargoyle/clients/include/argus_out.h#15 $
 * $DateTime: 2016/09/13 16:02:42 $
 * $Change: 3182 $
 */


#ifndef Argus_out_h
#define Argus_out_h

#ifdef __cplusplus
extern "C" {
#endif

#if defined(ARGUS_SOLARIS) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#endif

#if defined(__OpenBSD__)
#include <netinet/in.h>
#endif


struct tok {
   int v;                  /* value */
   const char *s;          /* string */
};

#include <netinet/if_ether.h>
#include <netinet/rtp.h>
#include <argus_gre.h>
#include <argus_geneve.h>
#include <argus_llc.h>
#include <argus_isis.h>
#include <argus_udt.h>

#include <sys/time.h>

#pragma pack(2)

struct ArgusDSRfixLen {
   unsigned short data;
};

struct ArgusDSRvar8bitLen {
   unsigned char qual;
   unsigned char len;
};

struct ArgusDSRvar16bitLen {
   unsigned short len;
};

struct ArgusDSRHeader {
   unsigned char type;
   unsigned char subtype;
   union {
      struct ArgusDSRfixLen fl;
      struct ArgusDSRvar8bitLen  vl8;
      struct ArgusDSRvar16bitLen vl16;
   } dsr_un;
};

struct ArgusSystemDSRHeader {
   unsigned char type;
   unsigned char subtype;
   union {
      struct ArgusDSRfixLen      fl;
      struct ArgusDSRvar8bitLen  vl8;
      struct ArgusDSRvar16bitLen vl16;
   } dsr_un;
#if defined(ALIGN_64BIT)
   int pad[3];
#endif
};

struct ArgusTime {
   int tv_sec, tv_usec;
};

#define argus_dsrfl	dsr_un.fl
#define argus_dsrvl8     dsr_un.vl8
#define argus_dsrvl16    dsr_un.vl16

/** access functions, use those instead of accessing data structure encoding directly
    since the encoding has many things to remember */
static inline unsigned char ArgusDSRType(struct ArgusDSRHeader *dsr,
					int argus_major_version,
					int argus_minor_version) 
{
  if (!dsr) return 0;
  
  return ((argus_major_version == MAJOR_VERSION_4) &&
	  (argus_minor_version >= MINOR_VERSION_1)) ? (dsr->type & 0x7f) : dsr->type;
}

static inline unsigned char ArgusDSRSubType(struct ArgusDSRHeader *dsr,
					   int argus_major_version,
					   int argus_minor_version) 
{ 
  if (!dsr) return 0;

  switch (ArgusDSRType(dsr,argus_major_version,argus_minor_version)) { 
  case ARGUS_DATA_DSR:
    return dsr->subtype; 
  default: 
    return (dsr->subtype & 0x3F);
  }
}

static inline unsigned char ArgusDSRQual(struct ArgusDSRHeader *dsr,
					int argus_major_version,
					int argus_minor_version) 
{
  if (!dsr) return 0;

  switch (ArgusDSRType(dsr,argus_major_version,argus_minor_version)) { 

  case ARGUS_FLOW_LAYER_3_MATRIX:
  case ARGUS_FLOW_CLASSIC5TUPLE:
  case ARGUS_METER_DSR: 
  case ARGUS_MPLS_DSR:
  case ARGUS_JITTER_DSR:
  case ARGUS_IPATTR_DSR:
    return dsr->argus_dsrvl8.qual; 
    break;

  case ARGUS_DATA_DSR:
    /** argus data DSR only posseses a qualifier below version 4.1 */
    if ((argus_major_version == MAJOR_VERSION_4) && 
	(argus_minor_version >= MINOR_VERSION_1)) {
      return dsr->argus_dsrvl8.qual; 
    }
    break;
    
  default:
    return 0;
    break;
  }
  return 0;
}

static inline unsigned int ArgusDSRLen(struct ArgusDSRHeader *dsr,
				      int argus_major_version,
				      int argus_minor_version) 
{
  if (!dsr) return 0; 

  switch (ArgusDSRType(dsr,argus_major_version,argus_minor_version)) { 
  case ARGUS_DATA_DSR:
    return dsr->argus_dsrvl16.len * 4;
    break;
  default:
    return dsr->argus_dsrvl8.len; 
    break;
  }
}

struct ArgusIdStruct {
   int status;
   char name[64];
};

struct ArgusInputStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusIdStruct id;
};


/*
   Argus V5 changes the ArgusMarStruct to accomodate extensions to argus data representation.

   Argus V5 extends the srcid to include ethernet addresses, longer strings (16 byte), and UUID's.
   These srcid's are ArgusAddrStructs, and to convey them in management records, we need to change
   the ArgusMarStruct, or we need to provide additional management record types, to pass on the
   extended ids.

   The concept, for backward compatibility, is that the initial argus record is a fixed length
   128 byte struct. It has a 4 byte ArgusRecord header, followed by a 124 byte management
   record buffer, the format identified by the major_version number, which is an 8-bit value.

   Up until the major_version, minor_version identifiers that identify the ArgusMarStruct type,
   i.e. the first 36 bytes of the ArgusMarStruct, the structure needs to be consistent. For
   backward compatibility, the major and minor version numbers need to be in the same place, so
   that earlier versions can find the 8 bit values that indicate if it can read the data.

   After the major_version, minor_verions identifiers, the structure can be completely different.
*/

struct ArgusMarStruct {
   unsigned int status, argusid;
   unsigned int localnet, netmask;
   unsigned int nextMrSequenceNum; 
   struct ArgusTime startime, now;

   unsigned char  major_version, minor_version; 
   unsigned char interfaceType, interfaceStatus;

   unsigned short reportInterval, argusMrInterval;
   unsigned long long pktsRcvd, bytesRcvd;
   long long drift;

   unsigned int records, flows, dropped;
   unsigned int queue, output, clients;
   unsigned int bufs, bytes;
   unsigned short suserlen, duserlen;

   union {
      unsigned int value;
      unsigned int ipv4;
      unsigned char ethersrc[6];
      unsigned char str[4];
      unsigned char uuid[16];
      unsigned int ipv6[4];

      struct {
         unsigned int pad[3];
         unsigned int thisid;
      };
   };

   unsigned int record_len;
};

struct ArgusMarSupStruct {
   unsigned int status, argusid;
   struct ArgusTime startime, now;
   struct ArgusInputStruct input;
};

struct ArgusICMPObject {
   unsigned char icmp_type, icmp_code;
   unsigned short iseq;
   unsigned int osrcaddr, odstaddr;
   unsigned int isrcaddr, idstaddr;
   unsigned int igwaddr;
};

struct ArgusICMPv6Object {
   unsigned char icmp_type, icmp_code;
   unsigned short cksum;
};

struct ArgusTCPInitStatusV1 {
   unsigned int status, seqbase;
   unsigned int options;
   unsigned short win;
   unsigned char flags, winshift;
};  

struct ArgusTCPInitStatus {
   unsigned int status, seqbase;
   unsigned int options;
   unsigned short win;
   unsigned char flags, winshift;
   unsigned short maxseg, pad;
};
  
struct ArgusTCPStatus {
   unsigned int status;
   unsigned char src, dst, pad[2];
};

struct ArgusTCPObjectMetricsV1 {
   struct ArgusTime lasttime;
   unsigned int status, seqbase, seq, ack, winnum;
   unsigned int bytes, retrans, ackbytes, winbytes;
   unsigned short win;
   unsigned char flags, winshift;
};

struct ArgusTCPObjectMetrics {
   struct ArgusTime lasttime;
   unsigned int status, seqbase, seq, ack, winnum;
   unsigned int bytes, retrans, ackbytes, winbytes;
   unsigned short win;
   unsigned char flags, winshift;
   unsigned short maxseg, pad;
};

struct ArgusTCPObjectV1 {
   unsigned int status, state, options;
   unsigned int synAckuSecs, ackDatauSecs;
   struct ArgusTCPObjectMetricsV1 src, dst;
};

struct ArgusTCPObject {
   unsigned int status, state, options;
   unsigned int synAckuSecs, ackDatauSecs;
   struct ArgusTCPObjectMetrics src, dst;
};

struct ArgusUDTObjectMetrics {
   struct ArgusTime lasttime;
   unsigned int seq, tstamp, ack, rtt, var, bsize, rate, lcap;
   int solo, first, middle, last, drops, retrans, nacked;
};

struct ArgusUDTObject {
   unsigned int state, status;
   struct udt_control_handshake hshake;
   struct ArgusUDTObjectMetrics src;
};

struct ArgusRTPObject {
   unsigned int state;
   struct rtphdr  src, dst;
   unsigned short sdrop, ddrop;
   unsigned short ssdev, dsdev;
};
 
struct ArgusRTCPObject {
   struct rtcphdr src, dst;
   unsigned short sdrop, ddrop;
};

struct ArgusIGMPObjectV1 {
   unsigned char igmp_type, igmp_code;
   unsigned int igmp_group;
};

struct ArgusIGMPObject {
   unsigned char igmp_type, igmp_code;
   unsigned int igmp_group;
   struct ArgusTime jdelay;
   struct ArgusTime ldelay;
};

struct ArgusFragObject {
   unsigned int fragnum, frag_id;
   unsigned short totlen, currlen, maxfraglen, pad;
};

struct ArgusIsisLspFlow {
   unsigned char lspid[LSP_ID_LEN];
   unsigned int seqnum;
};

struct ArgusIsisHelloFlow {
   unsigned char srcid[SYSTEM_ID_LEN];
   unsigned char lanid[NODE_ID_LEN];
   unsigned char circuit_id;
};

struct ArgusIsisCsnpFlow {
   unsigned char srcid[NODE_ID_LEN];
};

struct ArgusIsisPsnpFlow {
   unsigned char srcid[NODE_ID_LEN];
};

struct ArgusIsisFlow {
   int pdu_type;
   char esrc[ETHER_ADDR_LEN], edst[ETHER_ADDR_LEN];
   char proto_version, pad[3];
   union {
      struct ArgusIsisHelloFlow hello;
      struct ArgusIsisLspFlow   lsp;
      struct ArgusIsisCsnpFlow  csnp;
      struct ArgusIsisPsnpFlow  psnp;
   } isis_un;
   int chksum;
};

struct ArgusESPObject {
   unsigned int status, spi, lastseq, lostseq;
};

struct ArgusARPObject { 
   unsigned char respaddr[6];    
   unsigned short pad; 
};  
 
struct ArgusDHCPObject {     
   unsigned int respaddr;   
};  

struct ArgusAHObject {
   unsigned int src_spi, dst_spi;
   unsigned int src_replay, dst_replay;
};

struct ArgusLcpFlow {
   struct ether_header ehdr;
   unsigned char code, id;
};

struct ArgusEtherMacFlow {
   struct ether_header ehdr;
   unsigned char dsap, ssap;
};

struct Argus80211MacFlow {
   struct ether_header ehdr;
   unsigned char dsap, ssap;
};

struct ArgusMacFlow {
   union {
      struct ArgusEtherMacFlow ether;
      struct Argus80211MacFlow wlan;
   } mac_union;
};

struct ArgusWlanFlow {
   unsigned char dhost[ETHER_ADDR_LEN];
   unsigned char shost[ETHER_ADDR_LEN];
   unsigned char bssid[ETHER_ADDR_LEN];
   char ssid[32];
};

struct ArgusIPAttrObject {
   unsigned char ttl, tos;   
   unsigned short ip_id;
   unsigned int options;
};

struct ArgusIsisObject {
   struct isis_common_header common;
   union {
      struct isis_iih_lan_header iih_lan;
      struct isis_iih_ptp_header iih_ptp;
      struct isis_lsp_header lsp;
      struct isis_csnp_header csnp;
      struct isis_psnp_header psnp;
   } isis_un;
};


struct ArgusAsnStruct {
   struct ArgusDSRHeader hdr;
   uint32_t src_as;        /* originating AS of source address */
   uint32_t dst_as;        /* originating AS of destination address */
   uint32_t inode_as;      /* originating AS of intermediate node address, if present */
};

struct ArgusNetworkStruct {
   struct ArgusDSRHeader hdr;
   union {
      struct ArgusTCPInitStatus tcpinit;
      struct ArgusTCPStatus     tcpstatus;
      struct ArgusTCPObject     tcp;
      struct ArgusICMPObject    icmp;
      struct ArgusICMPv6Object  icmpv6;
      struct ArgusUDTObject     udt;
      struct ArgusRTPObject     rtp;
      struct ArgusRTCPObject    rtcp;
      struct ArgusIGMPObject    igmp;
      struct ArgusDHCPObject    dhcp;
      struct ArgusESPObject     esp;
      struct ArgusARPObject     arp;
      struct ArgusAHObject      ah;
      struct ArgusFragObject    frag;
      struct ArgusIsisObject    isis;
   } net_union;  
};

struct ArgusESPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned short pad;
   unsigned int spi;
};

 
struct ArgusESPv6Flow {
   unsigned int ip_src[4], ip_dst[4];
#if defined(_LITTLE_ENDIAN) 
   unsigned int flow:20; 
   unsigned int blank:4; 
   unsigned int ip_p:8; 
#else
   unsigned int ip_p:8;
   unsigned int blank:4;
   unsigned int flow:20; 
#endif 
   unsigned int spi; 
};  

struct ArgusHAddr {
   union {
      unsigned char ethernet[6];
      unsigned char ib[32];
      unsigned char ieee1394[16];
      unsigned char framerelay[4];
      unsigned char tokenring[6];
      unsigned char arcnet[1];
      unsigned char fiberchannel[12];
      unsigned char atm[20];
   } h_un;
};

struct ArgusInterimArpFlow {
   unsigned short pro;
   unsigned char  hln;
   unsigned char  pln;
   unsigned int   arp_spa;
   unsigned int   arp_tpa;
   struct ArgusHAddr haddr;
};

struct ArgusArpFlow {
   unsigned short    hrd;
   unsigned short    pro; 
   unsigned char     hln;
   unsigned char     pln;
   unsigned short    op;
   unsigned int      arp_spa;
   unsigned int      arp_tpa;
   struct ArgusHAddr haddr;
};
 
struct ArgusRarpFlow {
   unsigned short    hrd;
   unsigned short    pro;
   unsigned char     hln;
   unsigned char     pln;
   unsigned short    op;
   unsigned int      arp_tpa;
   struct ArgusHAddr shaddr;
   struct ArgusHAddr dhaddr; 
};

 
struct ArgusLegacyArpFlow {
   unsigned int arp_spa;
   unsigned int arp_tpa;
   unsigned char etheraddr[6];
   unsigned short pad;
};
 
struct ArgusLegacyRarpFlow {
   unsigned int arp_tpa;
   unsigned char srceaddr[6];
   unsigned char tareaddr[6];
};

struct ArgusICMPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned char type, code;
   unsigned short id, ip_id;
};
 
struct ArgusICMPv6Flow {
   unsigned int ip_src[4], ip_dst[4];
#if defined(_LITTLE_ENDIAN)
   unsigned int flow:20;
   unsigned int blank:4;
   unsigned int ip_p:8;
#else
   unsigned int ip_p:8;
   unsigned int blank:4;
   unsigned int flow:20;
#endif
   unsigned char type, code;
   unsigned short id;
};


struct ArgusIPFragFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned short pad[2];
   unsigned short ip_id;
};

struct ArgusIPv6FragFlow {
   unsigned int ip_src[4], ip_dst[4];
#if defined(_LITTLE_ENDIAN)
   unsigned int flow:20;
   unsigned int resv:4;
   unsigned int ip_p:8;
#else
   unsigned int ip_p:8;
   unsigned int resv:4;
   unsigned int flow:20;
#endif
   unsigned int ip_id;
};

 
struct ArgusIGMPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned char type, code;
   unsigned short pad, ip_id;
};

struct ArgusIGMPv6Flow {
   unsigned int ip_src[4], ip_dst[4];
#if defined(_LITTLE_ENDIAN)
   unsigned int flow:20;
   unsigned int blank:4;
   unsigned int ip_p:8;
#else
   unsigned int ip_p:8;
   unsigned int blank:4;
   unsigned int flow:20;
#endif
   unsigned char type, code;
   unsigned short pad;
};

struct ArgusIPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned short sport, dport;
   unsigned char smask, dmask;
};

struct ArgusIPv6Flow {
   unsigned int ip_src[4], ip_dst[4];
#if defined(_LITTLE_ENDIAN)
   unsigned int flow:20;
   unsigned int blank:4;
   unsigned int ip_p:8;
#else
   unsigned int ip_p:8;
   unsigned int blank:4;
   unsigned int flow:20;
#endif
   unsigned short sport, dport;
   unsigned short smask, dmask;
};

struct ArgusFlow {
   struct ArgusDSRHeader hdr;
   union {
      struct ArgusIPv6Flow        ipv6;
      struct ArgusIPFlow            ip;
      struct ArgusMacFlow          mac;
      struct ArgusICMPv6Flow    icmpv6;
      struct ArgusICMPFlow        icmp;
      struct ArgusIGMPv6Flow    igmpv6;
      struct ArgusIGMPFlow        igmp;
      struct ArgusESPv6Flow      espv6;
      struct ArgusESPFlow          esp;
      struct ArgusArpFlow          arp;
      struct ArgusRarpFlow        rarp;
      struct ArgusInterimArpFlow  iarp;
      struct ArgusLegacyArpFlow   larp;
      struct ArgusLegacyRarpFlow lrarp;
      struct ArgusIPv6FragFlow  fragv6;
      struct ArgusIPFragFlow      frag;
      struct ArgusIsisFlow        isis;
      struct ArgusWlanFlow        wlan;
  } flow_un;
};

struct ArgusSystemFlow {
   struct ArgusSystemDSRHeader hdr;
   union {
      struct ArgusIPv6Flow        ipv6;
      struct ArgusIPFlow            ip;
      struct ArgusMacFlow          mac;
      struct ArgusICMPv6Flow    icmpv6;
      struct ArgusICMPFlow        icmp;
      struct ArgusIGMPv6Flow    igmpv6;
      struct ArgusIGMPFlow        igmp;
      struct ArgusESPv6Flow      espv6;
      struct ArgusESPFlow          esp;
      struct ArgusArpFlow          arp;
      struct ArgusRarpFlow        rarp;
      struct ArgusInterimArpFlow  iarp;
      struct ArgusLegacyArpFlow   larp;
      struct ArgusLegacyRarpFlow lrarp;
      struct ArgusIPv6FragFlow  fragv6;
      struct ArgusIPFragFlow      frag;
      struct ArgusIsisFlow        isis;
      struct ArgusWlanFlow        wlan;
  } flow_un;
#if defined(ALIGN_64BIT)
   int tail[1];
#endif
};

#define   ipv6_flow flow_un.ipv6
#define     ip_flow flow_un.ip
#define icmpv6_flow flow_un.icmpv6
#define   icmp_flow flow_un.icmp
#define   igmp_flow flow_un.igmp
#define igmpv6_flow flow_un.igmpv6
#define    mac_flow flow_un.mac
#define    arp_flow flow_un.arp
#define   rarp_flow flow_un.rarp
#define   iarp_flow flow_un.iarp
#define   larp_flow flow_un.larp
#define  lrarp_flow flow_un.lrarp
#define   esp6_flow flow_un.espv6
#define    esp_flow flow_un.esp
#define   frag_flow flow_un.frag
#define fragv6_flow flow_un.fragv6
#define     lcp_flow flow_un.lcp
#define    isis_flow flow_un.isis
#define    wlan_flow flow_un.wlan


struct ArgusFlowHashStruct {
   struct ArgusDSRHeader hdr;
   unsigned int hash;
   unsigned int ind;
};

struct ArgusAddrStruct {
   union {
      unsigned int value;
      unsigned int ipv4;
      unsigned char str[4];
      unsigned char ethersrc[6];
      unsigned int ipv6[4];
      unsigned char uuid[16];
   } a_un;
   unsigned char inf[4];
};

struct ArgusTransportStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusAddrStruct srcid;
   unsigned int seqnum;
};

struct ArgusTimeStruct {
   struct ArgusTime start, end;
};


struct ArgusTimeObject {
   struct ArgusDSRHeader hdr;
   struct ArgusTimeStruct src, dst;
};


struct ArgusEventTimeStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusTime start;
   unsigned int duration;
};


struct ArgusEncapsStruct {
   struct ArgusDSRHeader hdr;
   unsigned int src, dst;
   unsigned short slen, dlen;
   unsigned char *sbuf, *dbuf;
};

struct ArgusUniStats {
   long long pkts, bytes, appbytes;
};

struct ArgusStatObject {
   int n;
   float minval;
   float meanval;
   float stdev;
   float maxval;
   unsigned char fdist[8];
};

struct ArgusAgrStruct {
   struct ArgusDSRHeader hdr;
   unsigned int count;
   struct ArgusTime laststartime, lasttime;
   struct ArgusStatObject act, idle;
};

/*
   ARGUS_HISTO_LINEAR       size:bins:start
   ARGUS_HISTO_EXPONENTIAL  size:bins:start:base
   ARGUS_HISTO_SCALED
   ARGUS_HISTO_OUTLAYER_LOWER     
   ARGUS_HISTO_OUTLAYER_UPPER     
*/
 
struct ArgusHistoObject {
   struct ArgusDSRHeader hdr;
   float size;
   char bins, bits;
   short start;
   unsigned char *data;
};

/*
struct ArgusOutputStatObject {
   int n;
   float minval;
   float meanval;
   float stdev;
   float maxval;
   union {
      unsigned char fdist[8];
      struct ArgusHistoObject linear;
   } dist_union;
};
*/

struct ArgusStatsObject {
   int n;
   float minval;
   float meanval;
   float stdev;
   float maxval;
   union {
      unsigned int exp;
      unsigned int *linear;
   } dist_union;
};


struct ArgusOutputAgrStruct {
   struct ArgusDSRHeader hdr;
   unsigned int count;
   struct ArgusTime laststartime, lasttime;
   struct ArgusStatObject act, idle;
};

struct ArgusStatIntObject {
   int n;
   unsigned int minval;
   unsigned int meanval;
   unsigned int stdev;
   unsigned int maxval;
};

struct ArgusPacketSizeObject {
   unsigned short psizemin, psizemax;
   unsigned char psize[8];
};

struct ArgusPacketSizeStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusPacketSizeObject src, dst;
};

struct ArgusKeyStrokeMetrics {
   int n_strokes;
};
 
struct ArgusKeyStrokeStruct {
   struct ArgusKeyStrokeMetrics src, dst;
};

struct ArgusScoreObject {
   u_char values[8];
};
 
struct ArgusBehaviorStruct {
   struct ArgusDSRHeader hdr;
   union {
      struct ArgusKeyStrokeStruct keyStroke;
   } behavior_union;
};

struct ArgusScoreStruct {
   struct ArgusDSRHeader hdr;
   union {
      struct ArgusScoreObject score;
   } score_union;
};
 
#define keyStroke behavior_union.keyStroke
#define behvScore score_union.score

struct ArgusJitterObject {
   struct ArgusStatObject act, idle;
};

struct ArgusJitterStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusJitterObject src, dst;
};

struct ArgusMacStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusMacFlow mac;
};

struct ArgusVxLanStruct {
   struct ArgusDSRHeader hdr;
   unsigned int svnid, dvnid;
   struct ArgusFlow tflow;
};

struct ArgusVlanStruct {
   struct ArgusDSRHeader hdr;
   unsigned short sid, did;
};

struct ArgusMplsStruct {
   struct ArgusDSRHeader hdr;
   unsigned int slabel;
   unsigned int dlabel;
};

struct ArgusGreStruct {
   struct ArgusDSRHeader hdr;
   unsigned short flags, proto;
   struct ArgusFlow tflow;
};

struct ArgusGeneveStruct {
   struct ArgusDSRHeader hdr;
   unsigned char ver_opt, flags;
   unsigned short ptype;
   unsigned int vni;
   struct ArgusFlow tflow;
};

struct ArgusIPAttrStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusIPAttrObject src, dst;
};

struct ArgusMetricStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusUniStats src, dst;
};

struct ArgusDataStruct {
   struct ArgusDSRHeader hdr;
   unsigned short size, count;
   char array[8];
};  

struct ArgusIcmpv6Struct {
   struct ArgusDSRHeader hdr;
   unsigned char icmp_type, icmp_code;
   unsigned short cksum;
};

struct ArgusIcmpStruct {
   struct ArgusDSRHeader hdr;
   unsigned char icmp_type, icmp_code;
   unsigned short iseq;
   unsigned int osrcaddr, odstaddr;
   unsigned int isrcaddr, idstaddr;
   unsigned int igwaddr;
};

struct ArgusCorMetrics {
   struct ArgusAddrStruct srcid;
   int deltaDur, deltaStart, deltaLast;
   int deltaSrcPkts, deltaDstPkts;
};

struct ArgusCorrelateStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusCorMetrics metrics;
};

struct ArgusCountryCodeStruct {
   struct ArgusDSRHeader hdr;
   char src[2], dst[2];
};

struct ArgusCoordinates {
   float lat, lon;
};

struct ArgusCoordinateRange {
   struct ArgusCoordinates max, min;
};

struct ArgusSiteLocation {
   union {
      struct ArgusCoordinates cor;
      struct ArgusCoordinateRange range;
   } dist_union;
};

struct ArgusGeoLocationStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusCoordinates src, dst, inode;
};

struct ArgusNetspatialStruct {
   struct ArgusDSRHeader hdr;
   unsigned short status;
   signed char sloc, dloc; 
};

struct ArgusLabelStruct {
   struct ArgusDSRHeader hdr;
   union {
      char *svc;
      char *label;
   }l_un;
};

/*
   The ArgusRecordHeader is composed of 4 4-bit fields, the
   type, version, cause and options fields.  For the purpose
   of portability, we define them as two char values, so that
   little endian machines don't mess up the order, and
   to avoid compiler problems with using bit fields.
 
   unsigned char type:4;
   unsigned char vers:4;
   unsigned char cause:4;
   unsigned char opt:4;
*/
 
struct ArgusRecordHeader {
   unsigned char type;
   unsigned char cause;
   unsigned short len;
};


struct ArgusCanonRecord {
   struct ArgusRecordHeader      hdr;
   struct ArgusFlow              flow;
   struct ArgusFlowHashStruct    hash;
   struct ArgusTransportStruct   trans;
   struct ArgusTimeObject        time;
   struct ArgusEncapsStruct      encaps;
   struct ArgusAsnStruct         asn;
   struct ArgusIPAttrStruct      attr;
   struct ArgusMetricStruct      metric;
   struct ArgusNetworkStruct     net;
   struct ArgusMacStruct         mac;
   struct ArgusVlanStruct        vlan;
   struct ArgusVxLanStruct       vxlan;
   struct ArgusGeneveStruct      gen;
   struct ArgusGreStruct         gre;
   struct ArgusMplsStruct        mpls;
   struct ArgusIcmpStruct        icmp;
   struct ArgusAgrStruct         agr;
   struct ArgusCorrelateStruct   cor;
   struct ArgusJitterStruct      jitter;
   struct ArgusPacketSizeStruct  psize;
   struct ArgusBehaviorStruct    actor;
   struct ArgusCountryCodeStruct cocode;
   struct ArgusGeoLocationStruct geo;
   struct ArgusNetspatialStruct  local;
   struct ArgusLabelStruct       label;
   struct ArgusDataStruct        data;
   struct ArgusScoreStruct       score;
};

struct ArgusEventStruct {
   struct ArgusDSRHeader       event;   /* immediate data */
   struct ArgusTransportStruct trans;
   struct ArgusEventTimeStruct  time;
   struct ArgusDataStruct       data;
};

#if defined ARGUS_PLURIBUS

#include <nvc_client.h>

struct ArgusVflowStruct {
   struct ArgusDSRHeader         hdr;   /* immediate data */
   struct ArgusTransportStruct trans;
   struct ArgusEventTimeStruct  time;
   nvc_vflow_stat_t            vflow;
};
#endif


struct ArgusFarStruct {
   struct ArgusFlow flow;
};


struct ArgusRecord {
   struct ArgusRecordHeader hdr;
   union {
      struct ArgusMarStruct     mar;
      struct ArgusMarSupStruct  sup;
      struct ArgusFarStruct     far;
      struct ArgusEventStruct event;
//#if defined ARGUS_PLURIBUS
//    struct ArgusVflowStruct vflow;
//#endif
   } ar_un;
};

#define argus_mar	ar_un.mar
#define argus_far	ar_un.far
#define argus_event	ar_un.event

#pragma pack()

#ifdef __cplusplus
}
#endif


#include <argus_legacy_out.h>

#endif /*  Argus_out_h  */
