/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2016 QoSient, LLC
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
 */
 
/*
 * $Id: //depot/gargoyle/clients/examples/radhcp/rabootp.h#3 $
 * $DateTime: 2016/08/22 00:32:32 $
 * $Change: 3173 $
 */
 
/*
 *     rabootp.h  - support for parsing DHCP transactions from argus data
 *
 */

#ifndef _RABOOTP_H_
#define	_RABOOTP_H_

#include <sys/types.h>


struct ArgusDhcpQueryStruct {
   unsigned char opcode, rcode, status, pad;
   unsigned char flags[2];
   unsigned short seqnum;
   unsigned short qdcount, ancount, nscount, arcount;
   unsigned short qtype, qclass;

   char *name;
   struct ArgusListStruct *domains;
   struct ArgusListStruct *ans;
   struct ArgusListStruct *cname;
   struct ArgusListStruct *ns;
};

struct ArgusDhcpStruct {
   char opcode, rcode, status, pad;
   unsigned char flags[2];
   unsigned short seqnum;
   unsigned short qdcount, ancount, nscount, arcount;
   unsigned short qtype, qclass;
   struct ArgusDhcpQueryStruct *request;
   struct ArgusDhcpQueryStruct *response;
};

struct ArgusDhcpStruct *ArgusParseDhcpRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusDhcpStruct *);

/*
 * Vendor magic cookie (v_magic) for RFC1048
 */
#define VM_RFC1048   { 99, 130, 83, 99 }

#endif
