/*
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *   The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Format and print bootp packets.
 */

#include <unistd.h>
#include <stdlib.h>

#include <argus_compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <signal.h>
#include <ctype.h>
#include <argus/extract.h>

#include "interface.h"
#include "rabootp.h"
#include "dhcp.h"

extern char ArgusBuf[];

static void rfc1048_print(const u_char *, const u_char *);
static void cmu_print(const u_char *);

static char tstr[] = " [|bootp]";

static const struct tok bootp_flag_values[] = {
    { 0x8000, "Broadcast" },
    { 0, NULL}
};

static const struct tok bootp_op_values[] = {
    { BOOTREQUEST, "Request" },
    { BOOTREPLY,   "Reply" },
    { 0, NULL}
};



struct ArgusDhcpStruct *ArgusParseDhcpRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusDhcpStruct *);


struct ArgusDhcpStruct *
ArgusParseDhcpRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, struct ArgusDhcpStruct *dhcp)
{
   struct ArgusDhcpStruct *retn = NULL;

   if (argus != NULL) {
      struct ArgusDataStruct *suser = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX];
      struct ArgusDataStruct *duser = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX];

      if (suser != NULL) {
      }

      if (duser != NULL) {
      }

      retn = dhcp;
   }

   return (retn);
}

/*
 * Print bootp requests
 */

char *
bootp_print(register const u_char *cp, u_int length)
{
   register const struct dhcp_packet *bp;
   static const u_char vm_rfc1048[4] = VM_RFC1048;
   const u_char *snapend = cp + length;

   unsigned int iaddr;

   bp = (struct dhcp_packet *)cp;
   TCHECK(bp->op);

   sprintf(&ArgusBuf[strlen(ArgusBuf)],"BOOTP/DHCP, %s",
          tok2str(bootp_op_values, "unknown (0x%02x)", bp->op));

   if (bp->htype == HTYPE_ETHER && bp->hlen == 6 && bp->op == BOOTREQUEST) {
      TCHECK2(bp->chaddr[0], 6);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," from %s", etheraddr_string(ArgusParser, (u_char *)bp->chaddr));
   }

   sprintf(&ArgusBuf[strlen(ArgusBuf)],", length: %u", length);

   if (!ArgusParser->vflag)
      return ArgusBuf;

   TCHECK(bp->secs);

   /* The usual hardware address type is 1 (10Mb Ethernet) */
   if (bp->htype != HTYPE_ETHER)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", htype-#%d", bp->htype);

   /* The usual length for 10Mb Ethernet address is 6 bytes */
   if (bp->htype != HTYPE_ETHER || bp->hlen != 6)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", hlen:%d", bp->hlen);

   /* Only print interesting fields */
   if (bp->hops)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", hops:%d", bp->hops);
   if (bp->xid)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", xid:0x%x", EXTRACT_32BITS(&bp->xid));
   if (bp->secs)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", secs:%d", EXTRACT_16BITS(&bp->secs));

   sprintf(&ArgusBuf[strlen(ArgusBuf)],", flags: [%s]",
          bittok2str(bootp_flag_values, "none", EXTRACT_16BITS(&bp->flags)));
   if (ArgusParser->vflag>1)
     sprintf(&ArgusBuf[strlen(ArgusBuf)], " (0x%04x)", EXTRACT_16BITS(&bp->flags));

   /* Client's ip address */
   TCHECK(bp->ciaddr);
   if (bp->ciaddr.s_addr) {
      iaddr = ntohl(bp->ciaddr.s_addr);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Client IP: %s", ipaddr_string(&iaddr));
   }

   /* 'your' ip address (bootp client) */
   TCHECK(bp->yiaddr);
   if (bp->yiaddr.s_addr) {
      iaddr = ntohl(bp->yiaddr.s_addr);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Your IP: %s", ipaddr_string(&iaddr));
   }

   /* Server's ip address */
   TCHECK(bp->siaddr);
   if (bp->siaddr.s_addr) {
      iaddr = ntohl(bp->siaddr.s_addr);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Server IP: %s", ipaddr_string(&iaddr));
   }

   /* Gateway's ip address */
   TCHECK(bp->giaddr);
   if (bp->giaddr.s_addr) {
      iaddr = ntohl(bp->giaddr.s_addr);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Gateway IP: %s", ipaddr_string(&iaddr));
   }

   /* Client's Ethernet address */
   if (bp->htype == HTYPE_ETHER && bp->hlen == 6) {
      TCHECK2(bp->chaddr[0], 6);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Client Ethernet Address: %s", etheraddr_string(ArgusParser, (u_char *)bp->chaddr));
   }

   TCHECK2(bp->sname[0], 1);      /* check first char only */
   if (bp->sname[0]) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," sname \"");
      if (fn_print(bp->sname, snapend, ArgusBuf)) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tstr + 1);
         return ArgusBuf;
      }
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
   }
   TCHECK2(bp->file[0], 1);      /* check first char only */
   if (bp->file[0]) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," file \"");
      if (fn_print(bp->file, snapend, ArgusBuf)) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tstr + 1);
         return ArgusBuf;
      }
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
   }

   /* Decode the vendor buffer */
   TCHECK(bp->options[0]);
   if (memcmp((const char *)&bp->options[0], vm_rfc1048,
       sizeof(u_int32_t)) == 0)
      rfc1048_print(bp->options, (const u_char *)cp+length);
   else {
      u_int32_t ul;

      ul = EXTRACT_32BITS(&bp->options[0]);
      if (ul != 0)
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," Vendor-#0x%x", ul);
   }

   return ArgusBuf;
trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tstr);

   return ArgusBuf;
}

/*
 * The first character specifies the format to print:
 *     i - ip address (32 bits)
 *     p - ip address pairs (32 bits + 32 bits)
 *     l - long (32 bits)
 *     L - unsigned long (32 bits)
 *     s - short (16 bits)
 *     b - period-seperated decimal bytes (variable length)
 *     x - colon-seperated hex bytes (variable length)
 *     a - ascii string (variable length)
 *     B - on/off (8 bits)
 *     $ - special (explicit code to handle)
 */
static struct tok tag2str[] = {
	{ DHO_PAD, "pad" },
	{ DHO_SUBNET_MASK, "isubnet_mask" },
	{ DHO_TIME_OFFSET, "Ltime_offset" },
	{ DHO_ROUTERS, "irouters" },
	{ DHO_TIME_SERVERS, "itime_servers" },
	{ DHO_NAME_SERVERS, "iname_servers" },
	{ DHO_DOMAIN_NAME_SERVERS, "idomain_name_servers" },
	{ DHO_LOG_SERVERS, "ilog_servers" },
	{ DHO_COOKIE_SERVERS, "icookie_servers" },
	{ DHO_LPR_SERVERS, "ilpr_servers" },
	{ DHO_IMPRESS_SERVERS, "iimpress_servers" },
	{ DHO_RESOURCE_LOCATION_SERVERS, "iresource_location_servers" },
	{ DHO_HOST_NAME, "ahost_name" },
	{ DHO_BOOT_SIZE, "sboot_size" },
	{ DHO_MERIT_DUMP, "amerit_dump" },
	{ DHO_DOMAIN_NAME, "adomain_name" },
	{ DHO_SWAP_SERVER, "iswap_server" },
	{ DHO_ROOT_PATH, "aroot_path" },
	{ DHO_EXTENSIONS_PATH, "aextensions_path" },
	{ DHO_IP_FORWARDING, "Bip_forwarding" },
	{ DHO_NON_LOCAL_SOURCE_ROUTING, "Bnon_local_source_routing" },
	{ DHO_POLICY_FILTER, "ppolicy_filter" },
	{ DHO_MAX_DGRAM_REASSEMBLY, "smax_dgram_reassembly" },
	{ DHO_DEFAULT_IP_TTL, "bdefault_ip_ttl" },
	{ DHO_PATH_MTU_AGING_TIMEOUT, "lpath_mtu_aging_timeout" },
	{ DHO_PATH_MTU_PLATEAU_TABLE, "spath_mtu_plateau_table" },
	{ DHO_INTERFACE_MTU, "sinterface_mtu" },
	{ DHO_ALL_SUBNETS_LOCAL, "Ball_subnets_local" },
	{ DHO_BROADCAST_ADDRESS, "ibroadcast_address" },
	{ DHO_PERFORM_MASK_DISCOVERY, "Bperform_mask_discovery" },
	{ DHO_MASK_SUPPLIER, "Bmask_supplier" },
	{ DHO_ROUTER_DISCOVERY, "Brouter_discovery" },
	{ DHO_ROUTER_SOLICITATION_ADDRESS, "irouter_solicitation_address" },
	{ DHO_STATIC_ROUTES, "pstatic_routes" },
	{ DHO_TRAILER_ENCAPSULATION, "Btrailer_encapsulation" },
	{ DHO_ARP_CACHE_TIMEOUT, "larp_cache_timeout" },
	{ DHO_IEEE802_3_ENCAPSULATION, "Bieee802_3_encapsulation" },
	{ DHO_DEFAULT_TCP_TTL, "bdefault_tcp_ttl" },
	{ DHO_TCP_KEEPALIVE_INTERVAL, "ltcp_keepalive_interval" },
	{ DHO_TCP_KEEPALIVE_GARBAGE, "Btcp_keepalive_garbage" },
	{ DHO_NIS_DOMAIN, "anis_domain" },
	{ DHO_NIS_SERVERS, "inis_servers" },
	{ DHO_NTP_SERVERS, "intp_servers" },
	{ DHO_VENDOR_ENCAPSULATED_OPTIONS, "bvendor_encapsulated_options" },
	{ DHO_NETBIOS_NAME_SERVERS, "inetbios_name_servers" },
	{ DHO_NETBIOS_DD_SERVER, "inetbios_dd_server" },
	{ DHO_NETBIOS_NODE_TYPE, "$netbios_node_type" },
	{ DHO_NETBIOS_SCOPE, "anetbios_scope" },
	{ DHO_FONT_SERVERS, "ifont_servers" },
	{ DHO_X_DISPLAY_MANAGER, "ix_display_manager" },
	{ DHO_DHCP_REQUESTED_ADDRESS, "idhcp_requested_address" },
	{ DHO_DHCP_LEASE_TIME, "ldhcp_lease_time" },
	{ DHO_DHCP_OPTION_OVERLOAD, "$dhcp_option_overload" },
	{ DHO_DHCP_MESSAGE_TYPE, "Ddhcp_message_type" },
	{ DHO_DHCP_SERVER_IDENTIFIER, "idhcp_server_identifier" },
	{ DHO_DHCP_PARAMETER_REQUEST_LIST, "bdhcp_parameter_request_list" },
	{ DHO_DHCP_MESSAGE, "adhcp_message" },
	{ DHO_DHCP_MAX_MESSAGE_SIZE, "sdhcp_max_message_size" },
	{ DHO_DHCP_RENEWAL_TIME, "ldhcp_renewal_time" },
	{ DHO_DHCP_REBINDING_TIME, "ldhcp_rebinding_time" },
	{ DHO_VENDOR_CLASS_IDENTIFIER, "avendor_class_identifier" },
	{ DHO_DHCP_CLIENT_IDENTIFIER, "$dhcp_client_identifier" },
/*	{ DHO_NWIP_DOMAIN_NAME, "nwip_domain_name" }, */
/*	{ DHO_NWIP_SUBOPTIONS, "nwip_suboptions" }, */
	{ DHO_USER_CLASS, "auser_class" },
	{ DHO_FQDN, "$fqdn" },
/*	{ DHO_DHCP_AGENT_OPTIONS, "dhcp_agent_options" }, */
	{ DHO_AUTHENTICATE, "bauthenticate" },
/*	{ DHO_CLIENT_LAST_TRANSACTION_TIME, "client_last_transaction_time" }, */
	{ DHO_ASSOCIATED_IP, "associated_ip" },
	{ DHO_SUBNET_SELECTION, "subnet_selection" },
	{ DHO_DOMAIN_SEARCH, "sdomain_search" }, /* RFC 3397 */
	{ DHO_VIVCO_SUBOPTIONS, "Lvivco_suboptions" }, /* RFC 3925 - first four bytes are Vendor ID */
	{ DHO_VIVSO_SUBOPTIONS, "svivso_suboptions" }, /* RFC 3925 - first 2 bytes are sub-option code */
	{ DHO_END, "end" },
	{ 0, NULL },
};

/* 2-byte extended tags */
static struct tok xtag2str[] = {
   { 0, NULL }
};

/* DHCP "options overload" types */
static struct tok oo2str[] = {
   { 1,   "file" },
   { 2,   "sname" },
   { 3,   "file+sname" },
   { 0, NULL }
};

/* NETBIOS over TCP/IP node type options */
static struct tok nbo2str[] = {
   { 0x1, "b-node" },
   { 0x2, "p-node" },
   { 0x4, "m-node" },
   { 0x8, "h-node" },
   { 0, NULL }
};

/* ARP Hardware types, for Client-ID option */
static struct tok arp2str[] = {
   { 0x1,  "ether" },
   { 0x6,  "ieee802" },
   { 0x7,  "arcnet" },
   { 0xf,  "frelay" },
   { 0x17, "strip" },
   { 0x18, "ieee1394" },
   { 0, NULL }
};

static void
rfc1048_print(register const u_char *bp, const u_char *endp)
{
   register u_int16_t tag;
   register u_int len, size;
   register const char *cp;
   register char c;
   int first;
   u_int32_t ul;
   u_int16_t us;
   u_int8_t uc;
   size_t off;

   sprintf(&ArgusBuf[strlen(ArgusBuf)]," Vendor-rfc1048:");

   /* Step over magic cookie */
   sprintf(&ArgusBuf[strlen(ArgusBuf)], " MAGIC:0x%08x", EXTRACT_32BITS(bp));
   bp += sizeof(int32_t);

   /* Loop while we there is a tag left in the buffer */
   while (bp + 1 < endp) {
      tag = *bp++;
      if (tag == DHO_PAD)
         continue;
      if (tag == DHO_END)
         return;

         cp = tok2str(tag2str, "?T%u", tag);
      c = *cp++;
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s:", cp);

      /* Get the length; check for truncation */
      if (bp + 1 >= endp) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tstr);
         return;
      }
      len = *bp++;
      if (bp + len >= endp) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|bootp %u]", len);
         return;
      }

      if (tag == DHO_DHCP_MESSAGE && len == 1) {
         uc = *bp++;
         switch (uc) {
         case DHCPDISCOVER:   sprintf(&ArgusBuf[strlen(ArgusBuf)],"DISCOVER");   break;
         case DHCPOFFER:      sprintf(&ArgusBuf[strlen(ArgusBuf)],"OFFER");   break;
         case DHCPREQUEST:   sprintf(&ArgusBuf[strlen(ArgusBuf)],"REQUEST");   break;
         case DHCPDECLINE:   sprintf(&ArgusBuf[strlen(ArgusBuf)],"DECLINE");   break;
         case DHCPACK:      sprintf(&ArgusBuf[strlen(ArgusBuf)],"ACK");      break;
         case DHCPNAK:      sprintf(&ArgusBuf[strlen(ArgusBuf)],"NACK");      break;
         case DHCPRELEASE:   sprintf(&ArgusBuf[strlen(ArgusBuf)],"RELEASE");   break;
         case DHCPINFORM:   sprintf(&ArgusBuf[strlen(ArgusBuf)],"INFORM");   break;
         default:      sprintf(&ArgusBuf[strlen(ArgusBuf)],"%u", uc);   break;
         }
         continue;
      }

      if (tag == DHO_DHCP_PARAMETER_REQUEST_LIST) {
         first = 1;
         while (len-- > 0) {
            uc = *bp++;
            cp = tok2str(tag2str, "?T%u", uc);
            if (!first)
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '+');
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", cp + 1);
            first = 0;
         }
         continue;
      }

      /* Print data */
      size = len;
      if (c == '?') {
         /* Base default formats for unknown tags on data size */
         if (size & 1)
            c = 'b';
         else if (size & 2)
            c = 's';
         else
            c = 'l';
      }
      first = 1;
      switch (c) {

      case 'a':
         /* ascii strings */
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
         off = strlen(ArgusBuf);
         if (fn_printn(bp, size, endp, &ArgusBuf[strlen(ArgusBuf)]) == NULL) {
            sprintf(&ArgusBuf[off], "%c", '"');
            goto trunc;
         }
         sprintf(&ArgusBuf[off+size], "%c", '"');
         bp += size;
         size = 0;
         break;

      case 'i':
      case 'l':
      case 'L':
         /* ip addresses/32-bit words */
         while (size >= sizeof(ul)) {
            if (!first)
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ',');
            ul = EXTRACT_32BITS(bp);
            if (c == 'i') {
//             ul = htonl(ul);
               sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", ipaddr_string(&ul));
            } else if (c == 'L')
               sprintf(&ArgusBuf[strlen(ArgusBuf)],"%d", ul);
            else
               sprintf(&ArgusBuf[strlen(ArgusBuf)],"%u", ul);
            bp += sizeof(ul);
            size -= sizeof(ul);
            first = 0;
         }
         break;

      case 'p':
         /* IP address pairs */
         while (size >= 2*sizeof(ul)) {
            if (!first)
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ',');
            memcpy((char *)&ul, (const char *)bp, sizeof(ul));
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"(%s:", ipaddr_string(&ul));
            bp += sizeof(ul);
            memcpy((char *)&ul, (const char *)bp, sizeof(ul));
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s)", ipaddr_string(&ul));
            bp += sizeof(ul);
            size -= 2*sizeof(ul);
            first = 0;
         }
         break;

      case 's':
         /* shorts */
         while (size >= sizeof(us)) {
            if (!first)
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ',');
            us = EXTRACT_16BITS(bp);
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"%u", us);
            bp += sizeof(us);
            size -= sizeof(us);
            first = 0;
         }
         break;

      case 'B':
         /* boolean */
         while (size > 0) {
            if (!first)
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ',');
            switch (*bp) {
            case 0:
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", 'N');
               break;
            case 1:
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", 'Y');
               break;
            default:
               sprintf(&ArgusBuf[strlen(ArgusBuf)],"%u?", *bp);
               break;
            }
            ++bp;
            --size;
            first = 0;
         }
         break;

      case 'b':
      case 'x':
      default:
         /* Bytes */
         while (size > 0) {
            if (!first)
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", c == 'x' ? ':' : '.');
            if (c == 'x')
               sprintf(&ArgusBuf[strlen(ArgusBuf)],"%02x", *bp);
            else
               sprintf(&ArgusBuf[strlen(ArgusBuf)],"%u", *bp);
            ++bp;
            --size;
            first = 0;
         }
         break;

      case '$':
         /* Guys we can't handle with one of the usual cases */
         switch (tag) {

         case DHO_NETBIOS_NODE_TYPE:
            tag = *bp++;
            --size;
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tok2str(nbo2str, NULL, tag));
            break;

         case DHO_DHCP_OPTION_OVERLOAD:
            tag = *bp++;
            --size;
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tok2str(oo2str, NULL, tag));
            break;

         case DHO_FQDN:
            /* option 81 should be at least 4 bytes long */
            if (len < 4)  {
                                        sprintf(&ArgusBuf[strlen(ArgusBuf)],"ERROR: options 81 len %u < 4 bytes", len);
               break;
            }
            if (*bp++)
               sprintf(&ArgusBuf[strlen(ArgusBuf)],"[svrreg]");
            if (*bp)
               sprintf(&ArgusBuf[strlen(ArgusBuf)],"%u/%u/", *bp, *(bp+1));
            bp += 2;
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
            if (fn_printn(bp, size - 3, endp, &ArgusBuf[strlen(ArgusBuf)]) == NULL) {
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
               goto trunc;
            }
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
            bp += size - 3;
            size = 0;
            break;

         case DHO_DHCP_CLIENT_IDENTIFIER:
             {   int type = *bp++;
            size--;
            if (type == 0) {
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
               if (fn_printn(bp, size, endp, &ArgusBuf[strlen(ArgusBuf)]) == NULL) {
                  sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
                  goto trunc;
               }
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
               bp += size;
               size = 0;
               break;
            } else {
               sprintf(&ArgusBuf[strlen(ArgusBuf)],"[%s]", tok2str(arp2str, "type-%d", type));
            }
            while (size > 0) {
               if (!first)
                  sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ':');
               sprintf(&ArgusBuf[strlen(ArgusBuf)],"%02x", *bp);
               ++bp;
               --size;
               first = 0;
            }
            break;
             }

         default:
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"[unknown special tag %u, size %u]",
                tag, size);
            bp += size;
            size = 0;
            break;
         }
         break;
      }
      /* Data left over? */
      if (size) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"[len %u]", len);
         bp += size;
      }
   }
   return;
trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"|[rfc1048]");
   return;
}

