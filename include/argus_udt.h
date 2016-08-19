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
 * $Id: //depot/argus/clients/include/argus_udt.h#9 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
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

