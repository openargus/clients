/*
 * Argus Software
 * Copyright (c) 2000-2022 QoSient, LLC
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
 * $Id: //depot/gargoyle/clients/include/argus_udt.h#4 $
 * $DateTime: 2014/05/14 00:30:13 $
 * $Change: 2825 $
 */

#ifndef ArgusUdt_h
#define ArgusUdt_h

#ifdef __cplusplus
extern "C" {
#endif

#define UDT_SEQNUMBER_MASK	0xEFFFFFFF
#define UDT_MSGNUMBER_MASK	0x1FFFFFFF

#define UDT_PACKET_MASK		0x8000
#define UDT_CONTROL_PACKET      0x8000
#define UDT_DATA_PACKET         0x0000

#define UDT_CONTROL_TYPE_MASK	0x7FFF

#define UDT_CONTROL_HANDSHAKE	0x0000
#define UDT_CONTROL_KEEPALIVE	0x0001
#define UDT_CONTROL_ACK		0x0002
#define UDT_CONTROL_NAK		0x0003
#define UDT_CONTROL_SHUTDOWN	0x0005
#define UDT_CONTROL_ACKACK	0x0006
#define UDT_CONTROL_DROPREQ	0x0007

struct udt_control_hdr {
   unsigned short type, resv;
   unsigned int info;
   unsigned int tstamp;
   unsigned int sockid;
};

struct udt_control_handshake {
   unsigned int version;
   unsigned int socktype;
   unsigned int initseq;
   unsigned int psize;
   unsigned int wsize;
   unsigned int conntype;
   unsigned int sockid;
};

struct udt_control_ack {
   unsigned int ackseqnum;
   unsigned int rtt;
   unsigned int var;
   unsigned int bsize;
   unsigned int rate;
   unsigned int lcap;
};

struct udt_control_nak {
   unsigned int seqnum;
};

struct udt_control_dropreq {
   unsigned int firstseqnum;
   unsigned int lastseqnum;
};

struct udt_data_hdr {
   unsigned int seqnum;
   unsigned int msgnum;
   unsigned int tstamp;
   unsigned int sockid;
};


struct udt_header {
   union {
      struct udt_control_hdr cntl;
      struct udt_data_hdr    data;
   } un_udt;
};
 
#define udt_control    un_udt.cntl
#define udt_data       un_udt.data

#ifdef __cplusplus
}
#endif
#endif /* ArgusUdt_h */

