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
 * Copyright (c) 1993, 1994 Carnegie Mellon University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and
 * that both that copyright notice and this permission notice appear
 * in supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/include/argus/cons_out.h#4 $
 * $DateTime: 2014/05/14 00:30:13 $
 * $Change: 2825 $
 */

#if !defined(__OpenBSD__)
#include <net/if.h>
#include <netinet/if_ether.h>
#endif

#include <netinet/in.h>

struct THA_OBJECT {
   int size;
   unsigned char *buffer;
};

struct tha {
   struct in_addr src;
   struct in_addr dst;
   u_short sport;
   u_short dport;
};

struct icmptha {
   struct in_addr src;
   struct in_addr dst;
   u_int port;
   u_int addr;
};


struct writeStruct {
   u_int status;
   struct timeval startime, lasttime;
   struct ether_addr ethersrc;
   struct ether_addr etherdst;
   struct tha addr;
   int src_count, dst_count;
   int src_bytes, dst_bytes;
};


struct inittcpWriteStruct {
   int src_count, dst_count;
   u_int addr, seq;
};

struct tcpWriteStruct {
   int src_count, dst_count;
   int src_bytes, dst_bytes;
};

struct udpWriteStruct {
   int src_count, dst_count;
   int src_bytes, dst_bytes;
};

struct icmpWriteStruct {
   u_char type, code;
   u_short data;
   struct in_addr srcaddr, dstaddr, gwaddr;
};

struct fragWriteStruct {
   int fragnum, frag_id;
   unsigned short status, totlen, currlen, maxfraglen;
};

struct physWriteStruct {
   struct ether_addr ethersrc;
   struct ether_addr etherdst;
};

struct arpWriteStruct {
   struct timeval time;
   struct physWriteStruct phys;
   struct ether_arp arp;
};

struct  ipWriteStruct {
   struct timeval startime, lasttime;
   struct physWriteStruct ws_phys;
   struct in_addr src;
   struct in_addr dst;
   u_short sport;
   u_short dport;
   union {
      struct inittcpWriteStruct inittcp;
      struct  tcpWriteStruct  tcp;
      struct  udpWriteStruct  udp;
      struct icmpWriteStruct icmp;
      struct fragWriteStruct frag;
   } ipws_trans_union;
};

struct manInitStruct {
   struct timeval startime, now;
   char initString[20];
   u_int localnet, netmask; 
   u_short reportInterval, dflagInterval; 
   u_char interfaceType, interfaceStatus;
};

struct manStatStruct {
   struct timeval startime, now;
   u_short reportInterval, dflagInterval;
   u_char interfaceType, interfaceStatus;
   u_int pktsRcvd, bytesRcvd, pktsDrop;
   u_short actTCPcons, cloTCPcons;
   u_short actUDPcons, cloUDPcons;
   u_short actIPcons,  cloIPcons;
   u_short actICMPcons,  cloICMPcons;
   u_short actFRAGcons,  cloFRAGcons;
};

struct WriteStruct {
   u_int status;
   union {
      struct    ipWriteStruct ip;
      struct   arpWriteStruct arp;
      struct   manInitStruct man_init;
      struct   manStatStruct man_stat;
   } ws_trans_union;
};

#define ws_ip   ws_trans_union.ip
#define ws_arp  ws_trans_union.arp
#define ws_init ws_trans_union.man_init
#define ws_stat ws_trans_union.man_stat

#define ws_ip_phys     ws_trans_union.ip.ws_phys
#define ws_ip_src      ws_trans_union.ip.src
#define ws_ip_dst      ws_trans_union.ip.dst
#define ws_ip_port     ws_trans_union.ip.port
#define ws_ip_inittcp  ws_trans_union.ip.ipws_trans_union.inittcp
#define ws_ip_tcp      ws_trans_union.ip.ipws_trans_union.tcp
#define ws_ip_udp      ws_trans_union.ip.ipws_trans_union.udp
#define ws_ip_icmp     ws_trans_union.ip.ipws_trans_union.icmp
#define ws_ip_frag     ws_trans_union.ip.ipws_trans_union.frag




