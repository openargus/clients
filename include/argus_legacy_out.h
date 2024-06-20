/*
 * Argus Software
 * Copyright (c) 2000-2024 QoSient, LLC
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
 * $Id: //depot/argus/clients/include/argus_legacy_out.h#57 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */


#ifndef Argus_legacy_out_h
#define Argus_legacy_out_h

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(2)

struct ArgusV3MarStruct {
   unsigned int status, argusid;
   unsigned int localnet, netmask, nextMrSequenceNum; 
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
   unsigned int pad[3];
   unsigned int thisid, record_len;
};


struct ArgusV3AddrStruct {
   union {
      unsigned int value;
      unsigned int ipv4;
      unsigned char str[4];
/*
      unsigned int ipv6[4];
      unsigned char ethersrc[6];
*/
   } a_un;
};

struct ArgusV3TransportStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusV3AddrStruct srcid;
   unsigned int seqnum;
};


struct ArgusV3CorMetrics {
   struct ArgusV3AddrStruct srcid;
   int deltaDur, deltaStart, deltaLast;
   int deltaSrcPkts, deltaDstPkts;
};

struct ArgusV3CorrelateStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusV3CorMetrics metrics;
};


struct ArgusV3GeoLocationStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusSiteLocation src, dst;
};


struct ArgusV3EventStruct {
   struct ArgusDSRHeader         event;   /* immediate data */
   struct ArgusV3TransportStruct trans;
   struct ArgusEventTimeStruct    time;
   struct ArgusDataStruct         data;
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
 

struct ArgusV3Record {
   struct ArgusRecordHeader hdr;
   union {
      struct ArgusV3MarStruct     mar;
      struct ArgusMarSupStruct    sup;
      struct ArgusFarStruct       far;
      struct ArgusV3EventStruct event;
   } ar_un;
};

#define argus_mar	ar_un.mar
#define argus_far	ar_un.far
#define argus_event	ar_un.event



struct ArgusV2ETHERObject {
   unsigned char ethersrc[6];
   unsigned char etherdst[6];
};

struct ArgusV2MACFlow {
   struct ether_header ehdr;
   unsigned char dsap, ssap;
};

struct ArgusV2ESPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned short pad;
   unsigned int spi;
};

struct ArgusV2ArpFlow {
   unsigned int arp_spa;
   unsigned int arp_tpa;
   unsigned char etheraddr[6];
   unsigned short pad;
};

struct ArgusV2RarpFlow {
   unsigned int arp_tpa;
   unsigned char srceaddr[6];
   unsigned char tareaddr[6];
};

struct ArgusV2ICMPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned char type, code;
   unsigned short id, ip_id;
};

struct ArgusV2IGMPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned char type, code;
   unsigned short pad, ip_id;
};

struct ArgusV2IPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned short sport, dport;
   unsigned short ip_id;
};

struct ArgusV2LoadObject {
   int n;
   float minval;
   float meanval;
   float stdev;
   float maxval;
};

struct ArgusV2LoadStruct {
   struct ArgusV2LoadObject pktsPerSec, bytesPerSec;
};

struct ArgusV2TimeObject {
   int n;
   unsigned int minval;
   unsigned int meanval;
   unsigned int stdev;
   unsigned int maxval;
};

struct ArgusV2TimeEntity {
   struct ArgusV2TimeObject act, idle;
};

struct ArgusV2AHObject {
   unsigned int src_spi, dst_spi;
   unsigned int src_replay, dst_replay;
};


struct ArgusV2ARPObject {
   unsigned char respaddr[6];
   unsigned short pad;
};

struct ArgusV2DHCPObject {
   unsigned int respaddr;
};

struct ArgusV2FragObject {
   unsigned char type, length;
   unsigned short status;
   int fragnum, frag_id;
   unsigned short ip_id, totlen, currlen, maxfraglen;
};

struct ArgusV2ICMPObject {
   unsigned char type, length;
   unsigned short status;
   unsigned char icmp_type, icmp_code;
   unsigned short iseq;
   unsigned int osrcaddr, odstaddr;
   unsigned int isrcaddr, idstaddr;
   unsigned int igwaddr;
};

struct ArgusV2TCPObjectMetrics {
   unsigned int seqbase, ackbytes;
   unsigned int bytes, rpkts;
   unsigned short win;
   unsigned char flags, pad;
};

struct ArgusV2TCPObject {
   unsigned char type, length;
   unsigned short status;
   unsigned int state;
   unsigned int options;
   unsigned int synAckuSecs, ackDatauSecs;
   struct ArgusV2TCPObjectMetrics src, dst;
};

struct ArgusV2RTPObject {
   unsigned char type, length;
   unsigned short status;
   unsigned int state;
   struct rtphdr  src, dst;
   unsigned short sdrop, ddrop;
   unsigned short ssdev, dsdev;
};
 
struct ArgusV2RTCPObject {
   unsigned char type, length;
   unsigned short status;
   struct rtcphdr src, dst;
   unsigned short src_pkt_drop, dst_pkt_drop;
};

struct ArgusV2IGMPObjectV1 {
   unsigned char type, length;
   unsigned short status;
   unsigned char igmp_type, igmp_code;
   unsigned int igmp_group;
};

struct ArgusV2IGMPObject {
   unsigned char type, length;
   unsigned short status;
   unsigned char igmp_type, igmp_code;
   unsigned int igmp_group;
   struct ArgusTime jdelay;
   struct ArgusTime ldelay;
};

struct ArgusV2FRAGObject {
   unsigned char type, length;
   unsigned short status;
   int fragnum, frag_id;
   unsigned short totlen, currlen, maxfraglen;
};

struct ArgusV2ESPObject {
   unsigned int spi, lastseq, lostseq;
};

struct ArgusV2ESPStruct {
   unsigned char type, length;
   u_short status;
   struct ArgusV2ESPObject src, dst;
};

struct ArgusV2AGRStruct {
   unsigned char type, length;
   u_short status;
   unsigned int count;
   struct ArgusTime laststartime, lasttime;
   struct ArgusV2TimeObject act, idle;
   unsigned int startrange, endrange;
};

struct ArgusV2PerfStruct {
   unsigned char type, length;
   u_short status;

   int count;
   struct ArgusV2LoadStruct src, dst;
};

struct ArgusV2TimeStruct {
   unsigned char type, length;
   u_short status;
   struct ArgusV2TimeEntity src, dst;
};

struct ArgusV2MacStruct {
   unsigned char type, length;
   unsigned short status;
   union {
      struct ArgusV2ETHERObject ether;
   } phys_union;
};

#define ether_mac	phys_union.ether

struct ArgusV2VlanStruct {
   unsigned char type, length;
   unsigned short status;
   unsigned short sid, did;
};

struct ArgusV2MplsStruct {
   unsigned char type, length;
   unsigned short status;
   unsigned int slabel;
   unsigned int dlabel;
};



struct ArgusV2MarStruct {
   struct ArgusTime startime, now;
   unsigned char  major_version, minor_version; 
   unsigned char interfaceType, interfaceStatus;
   unsigned short reportInterval, argusMrInterval;
   unsigned int argusid, localnet, netmask, nextMrSequenceNum; 
   unsigned long long pktsRcvd, bytesRcvd;
   unsigned int  pktsDrop, flows, flowsClosed;
   unsigned int actIPcons,  cloIPcons;
   unsigned int actICMPcons,  cloICMPcons;
   unsigned int actIGMPcons,  cloIGMPcons;
   unsigned int inputs, outputs;
   unsigned int qcount,  qtime;
   int record_len;
};


struct ArgusV2TimeDesc {
   struct ArgusTime start;
   struct ArgusTime last;
};

struct ArgusV2Flow {
   union {
      struct ArgusV2IPFlow     ip;
      struct ArgusV2ICMPFlow icmp;
      struct ArgusV2IGMPFlow igmp;
      struct ArgusV2MACFlow   mac;
      struct ArgusV2ArpFlow   arp;
      struct ArgusV2RarpFlow rarp;
      struct ArgusV2ESPFlow   esp;
  } flow_union;
};

struct ArgusV2UniAttributes {
   unsigned short options;
   unsigned char ttl, tos;
};

struct ArgusV2IPAttributes {
   unsigned short soptions, doptions;
   unsigned char sttl, dttl;
   unsigned char stos, dtos;
};

struct ArgusV2ARPAttributes {
   unsigned char response[8]; 
};

struct ArgusV2Attributes {
   union {
      struct ArgusV2IPAttributes   ip;
      struct ArgusV2ARPAttributes arp;
   } attr_union;
};

#define attr_ip   attr.attr_union.ip
#define attr_arp  attr.attr_union.arp

struct ArgusV2ArchiveMeter {
   unsigned int count, bytes;
};

struct ArgusV2Meter {
   unsigned int count, bytes, appbytes;
};

struct ArgusV2FarHeaderStruct {
   unsigned char type, length;
   unsigned short status;
};

struct ArgusV2FarStruct {
   unsigned char type, length;
   unsigned short status;

   unsigned int ArgusV2TransRefNum;
   struct ArgusV2TimeDesc time;
   struct ArgusV2Flow flow;
   struct ArgusV2Attributes attr;
   struct ArgusV2Meter src, dst;
};

struct ArgusV2CorrelateStruct {
   unsigned char type, length;
   unsigned short status;
   unsigned int argusid;
   int deltaDur, deltaStart, deltaLast;
   char deltaSrcToS, deltaSrcTTL;
   char deltaDstToS, deltaDstTTL;
   unsigned short deltaSrcIpId, deltaDstIpId;
   struct ArgusV2Meter deltaSrc, deltaDst;
};

struct ArgusV2ServiceStruct {
   unsigned char type, length;
   u_short status;
   char name[16];
};


struct ArgusV2RecordArchiveHeader {
   unsigned char type, cause;
   unsigned short length;
   unsigned int status;
};

struct ArgusV2RecordHeader {
   unsigned char type, cause;
   unsigned short length;
   unsigned int status;
   unsigned int argusid;
   unsigned int seqNumber;
};

struct ArgusV2Record {
   struct ArgusV2RecordHeader ahdr;
   union {
      struct ArgusV2MarStruct  mar;
      struct ArgusV2FarStruct  far;
   } ar_un;
};

struct ArgusV2CanonicalRecord {
   struct ArgusV2RecordHeader ahdr;
   struct ArgusV2FarStruct    far;
   struct ArgusV2MacStruct    mac;
   union {
      struct ArgusV2TCPObject     tcp;
      struct ArgusV2ESPStruct     esp;
      struct ArgusV2IGMPObject   igmp;
      struct ArgusV2DHCPObject   dhcp;
      struct ArgusV2RTPObject     rtp;
      struct ArgusV2RTCPObject   rtcp;
      struct ArgusV2ARPObject     arp;
      struct ArgusV2AHObject       ah;
      struct ArgusV2FRAGObject   frag;
   } acr_union;
 
   struct ArgusV2AGRStruct        agr;
   struct ArgusV2TimeStruct      time;
   struct ArgusV2VlanStruct      vlan;
   struct ArgusV2MplsStruct      mpls;
   struct ArgusV2CorrelateStruct  cor;
   struct ArgusV2ICMPObject      icmp;
   struct ArgusV2ServiceStruct    svc;
};


struct ArgusV2ArchiveUniRecord {
   struct ArgusV2RecordArchiveHeader ahdr;
   unsigned int status;
   struct ArgusTime startime;
   unsigned int duration;
   struct ArgusV2Flow flow;
   struct ArgusV2UniAttributes attr;
   struct ArgusV2ArchiveMeter src;
};

struct ArgusV2ArchiveRecord {
   struct ArgusV2RecordArchiveHeader ahdr;
   unsigned int status;
   struct ArgusTime startime;
   unsigned int duration;
   struct ArgusV2Flow flow;
   struct ArgusV2Attributes attr;
   struct ArgusV2ArchiveMeter src, dst;
};


struct ArgusV2UserStruct {
   unsigned char type, length;
   u_short status;
   char data;
};

#pragma pack()

#ifdef __cplusplus
}
#endif
#endif /*  Argus_out_h  */
