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
#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

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
#include <arpa/inet.h>

#include "interface.h"
#include "rabootp.h"
#include "dhcp.h"
#include "argus_threads.h"
#include "argus_label.h"
#include "rabootp_client_tree.h"
#include "rabootp_interval_tree.h"
#include "rabootp_memory.h"
#include "rabootp_fsa.h"
#include "rabootp_update.h"
#include "rabootp_callback.h"
#include "rabootp_timer.h"
#include "rabootp_patricia_tree.h"

#if defined(ARGUS_MYSQL)
extern char RaSQLSaveTable[];
char *ArgusCreateSQLSaveTableName(struct ArgusParserStruct *,
                                  struct ArgusRecordStruct *, char *);
#endif

static struct {
   struct rabootp_cblist state_change; /* called when dhcp FSA state changes */
   struct rabootp_cblist xid_new;      /* called when new transaction added */
   struct rabootp_cblist xid_update;   /* called when transaction updated */
   struct rabootp_cblist xid_delete;   /* called when transaction deleted */
} callback;

extern char ArgusBuf[];

#if defined(ARGUSDEBUG)
static char *bootp_print(register const u_char *, u_int);
#endif
static void rfc1048_print(const u_char *, const u_char *);
static void rfc1048_parse(const u_char *, const u_char *,
                          struct ArgusDhcpStruct *, u_char);

static char tstr[] = " [|bootp]";
static const u_char vm_rfc1048[4] = VM_RFC1048;

static const struct tok bootp_flag_values[] = {
    { 0x8000, "Broadcast" },
    { 0, NULL}
};

static const struct tok bootp_op_values[] = {
    { BOOTREQUEST, "Request" },
    { BOOTREPLY,   "Reply" },
    { 0, NULL}
};

static struct ArgusDhcpClientTree client_tree = {
   .lock = PTHREAD_MUTEX_INITIALIZER,
};
static struct ArgusDhcpIntvlTree interval_tree = {
   .lock = PTHREAD_MUTEX_INITIALIZER,
};


/* The TCHECK* macros are not safe to use since we are checking
 * multiple buffers
 */
static inline int
__tcheck(const unsigned char * const target, size_t targetsize,
         const struct ArgusDataStruct * const data)
{
   if ((target + targetsize) <= ((unsigned char *)&data->array[0] + data->count))
      return 1;
   return 0;
}

static struct ArgusDhcpStruct *
__parse_one_dhcp_record(const struct ether_header * const ehdr,
                        const struct ArgusDataStruct * const user,
                        const struct ArgusTimeStruct * const time)
{
   int newads = 0;
   uint32_t xid;
   struct ArgusDhcpStruct *ads = NULL;
   struct ArgusDhcpStruct parsed;
   register const struct dhcp_packet *bp;
   enum ArgusDhcpState newstate;

   bp = (struct dhcp_packet *)&user->array;

   /* first make sure we've got the op, htype and hlen */
   if (!__tcheck(&bp->hlen, sizeof(bp->hlen), user))
      goto nouser;

   if (bp->hlen > sizeof(bp->chaddr)) {
      /* malformed.  increment a counter? */
      goto nouser;
   }

   /* Then check to see that everything thru the client address
    * is present.
    */
   if (!__tcheck(&bp->chaddr[0], bp->hlen, user))
      goto nouser;

   /* make sure we have everything up to the options data */
   if (!__tcheck(&bp->options[0], sizeof(bp->options[0]), user))
      goto nouser;

   xid = EXTRACT_32BITS(&bp->xid);
   ads = ClientTreeFind(&client_tree, &bp->chaddr[0], bp->hlen, xid);
   if (!ads) {
      /* don't have a cached entry, so allocate a new one to insert. */
      ads = ArgusDhcpStructAlloc(); /* refcount = 1 already */
      ads->xid = xid;
      ads->hlen = bp->hlen;
      memcpy(&ads->chaddr[0], &bp->chaddr[0], bp->hlen);
      if (ArgusDhcpClientTreeInsert(&client_tree, ads) < 0) {
         ArgusDhcpStructFree(ads);
         ads = NULL;
         goto nouser;
      }

      newads = 1;
      DEBUGLOG(2, "%s(): added new dhcp structure to tree\n", __func__);
   } else {
      DEBUGLOG(2, "%s(): found dhcp structure in tree\n", __func__);
   }

   memset(&parsed, 0, sizeof(parsed));

   MUTEX_LOCK(ads->lock);

   if (bp->op == BOOTREQUEST) {
      if (ads->first_req.tv_sec == 0) {
         ads->first_req.tv_sec = time->start.tv_sec;
         ads->first_req.tv_usec = time->start.tv_usec;
      }
   } else if (bp->op == BOOTREPLY) {
      /* extract some data from the non-options portion of the packet */
      parsed.rep.yiaddr.s_addr = EXTRACT_32BITS(&bp->yiaddr.s_addr);
      parsed.rep.ciaddr.s_addr = EXTRACT_32BITS(&bp->ciaddr.s_addr);
      parsed.rep.siaddr.s_addr = EXTRACT_32BITS(&bp->siaddr.s_addr);
      if (ehdr)
         memcpy(&parsed.rep.shaddr[0], &ehdr->ether_shost[0],
                sizeof(ehdr->ether_shost));
   }

   if (memcmp((const char *)&bp->options[0], vm_rfc1048,
       sizeof(u_int32_t)) == 0)
      rfc1048_parse(bp->options, (const u_char *)(user->array+user->count),
                    &parsed, bp->op);

   if (newads) {
      newstate = fsa_choose_initial_state(&parsed);
   } else {
      newstate = fsa_advance_state(&parsed, ads);
      if (ads->state != newstate) {
         if (newstate == BOUND) {
            if (ads->first_bind.tv_sec == 0) {
               ads->first_bind.tv_sec = time->end.tv_sec;
               ads->first_bind.tv_usec = time->end.tv_usec;
            }
            ads->last_bind.tv_sec = time->end.tv_sec;
            ads->last_bind.tv_usec = time->end.tv_usec;
         }
         parsed.state = newstate;
         rabootp_cb_exec(&callback.state_change, &parsed, ads);
      }
   }
   ads->state = newstate;

   /* merge/update */
   ArgusDhcpStructUpdate(&parsed, ads);

   if (newads)
      rabootp_cb_exec(&callback.xid_new, &parsed, ads);
   else
      rabootp_cb_exec(&callback.xid_update, &parsed, ads);

   if (bp->op == BOOTREQUEST)
      ads->total_requests++;
   else if (bp->op == BOOTREPLY)
      ads->total_responses++;
   else
      ads->total_unknownops++;

   MUTEX_UNLOCK(ads->lock);

   ArgusDhcpStructFreeReplies(&parsed);
   ArgusDhcpStructFreeRequest(&parsed);

   if (!newads) {
      /* ClientTreeFind() ups the refcount.  We're done making changes,
       * so call the "free" function to decrement the refcount.
       */
      ArgusDhcpStructFree(ads);
   }

nouser:
   return ads;
}

static struct ArgusDhcpStruct *
__parse_one_dhcp_record_direction(const struct ether_header * const ehdr,
                                  const struct ArgusDataStruct * const user,
                                  const struct ArgusTimeStruct * const time,
                                  struct RabootpTimerStruct *timer)
{
   struct ArgusDhcpStruct *retn;

   /* THIS HAS TO CHANGE.  Lock timer first to preserve lock
    * ordering.  The problem is the timer lock may be aquired
    * for quite some time.  Per-timer-slot locks?
    */
   RabootpTimerLock(timer);
   retn = __parse_one_dhcp_record(ehdr, user, time);
   RabootpTimerUnlock(timer);

#if defined(ARGUSDEBUG)
   bootp_print((u_char *)&(user->array[0]), user->count);
   strncat(ArgusBuf, "\n", MAXSTRLEN);
#endif

   return retn;
}

static void
__set_sql_table_name(struct ArgusParserStruct *parser,
                     struct ArgusRecordStruct *argus,
                     struct ArgusDhcpStruct *ads)
{
#if defined(ARGUS_MYSQL)
         MUTEX_LOCK(&parser->lock);
         if (parser->writeDbstr && ads->sql_table_name == NULL) {
            ads->sql_table_name =
             strdup(ArgusCreateSQLSaveTableName(parser, argus, RaSQLSaveTable));
         }
         MUTEX_UNLOCK(&parser->lock);
#endif
}

struct ArgusDhcpStruct *
ArgusParseDhcpRecord(struct ArgusParserStruct *parser,
                     struct ArgusRecordStruct *argus,
                     struct RabootpTimerStruct *timer)
{
   struct ArgusDhcpStruct *retn = NULL;

   if (argus != NULL) {
      struct ArgusDataStruct *suser = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX];
      struct ArgusDataStruct *duser = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX];
      struct ArgusTimeObject *time = (struct ArgusTimeObject *)argus->dsrs[ARGUS_TIME_INDEX];
      struct ArgusMacStruct *mac = (struct ArgusMacStruct *) argus->dsrs[ARGUS_MAC_INDEX];
      struct ether_header *ehdr = NULL;

      if (mac != NULL) {
         switch (mac->hdr.subtype & 0x3F) {
            default:
            case ARGUS_TYPE_ETHER:
               ehdr = &(mac->mac.mac_union.ether.ehdr);
               break;
         }
      }

      if (suser != NULL) {
         retn = __parse_one_dhcp_record_direction(ehdr, suser, &time->src,
                                                  timer);
         __set_sql_table_name(parser, argus, retn);
      }

      if (duser != NULL) {
         retn = __parse_one_dhcp_record_direction(ehdr, duser, &time->dst,
                                                  timer);
         __set_sql_table_name(parser, argus, retn);
      }
   }

   return (retn);
}

/*
 * Print bootp requests
 */

#if defined(ARGUSDEBUG)
static char *
bootp_print(register const u_char *cp, u_int length)
{
   register const struct dhcp_packet *bp;
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
      if (fn_print((u_char *)&(bp->sname[0]), snapend, ArgusBuf)) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tstr + 1);
         return ArgusBuf;
      }
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
   }
   TCHECK2(bp->file[0], 1);      /* check first char only */
   if (bp->file[0]) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," file \"");
      if (fn_print((u_char *)&(bp->file[0]), snapend, ArgusBuf)) {
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
      u_int32_t options;

      memcpy(&options, bp->options, sizeof(options));

      ul = EXTRACT_32BITS(&options);
      if (ul != 0)
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," Vendor-#0x%x", ul);
   }

   return ArgusBuf;
trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tstr);

   return ArgusBuf;
}
#endif

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

static inline char *
__extract_string(const u_char * const bp, u_char len)
{
   u_char *s;

   s = malloc(len+1);
   if (s) {
      memcpy(s, bp, len);
      *(s+len) = '\0';
   }
   return (char *)s;
}

/* __extract_ipv4array:
 * extracts an option containing multiple ipv4 addresses into an
 * array of struct in_addr.  The length of the array is specified
 * in nelems.
 *
 * Returns the number of ipv4 addresses in the DHCP option, even if
 * this is more than the number copied into the array.
 */
static u_char
__extract_ipv4array(const u_char * const bp, u_char len,
                    struct in_addr arr[], u_char nelems)
{
   u_char tmplen = len;
   const u_char *tmpbp = bp;
   u_char count = 0;

   while (tmplen >= 4) {
      if (count < nelems)
         arr[count].s_addr = EXTRACT_32BITS(tmpbp);

      count++;
      tmpbp += 4;
      tmplen -= 4;
   }
   return count;
}

/* use with qsort */
static int
__uchar_compar(const void *a, const void *b)
{
   const unsigned char *uca, *ucb;

   uca = a;
   ucb = b;
   if (*uca < *ucb)
      return -1;
   if (*uca == *ucb)
      return 0;
   return 1;
}


static void
rfc1048_parse(const u_char *bp, const u_char *endp,
              struct ArgusDhcpStruct *ads, u_char op)
{
   register u_int16_t tag;
   register u_int len, size;
   u_int8_t uc;

   /* Step over magic cookie */
   bp += sizeof(int32_t);

   /* Loop while we there is a tag left in the buffer */
   while (bp + 1 < endp) {
      tag = *bp++;

      if (op == BOOTREPLY)
          __options_mask_set(ads->rep.options, tag);
      else if (op == BOOTREQUEST)
          __options_mask_set(ads->req.options, tag);

      if (tag == DHO_PAD)
         continue;
      if (tag == DHO_END)
         return;

      /* Get the length; check for truncation */
      if (bp + 1 >= endp)
         return;

      len = *bp++;
      if (bp + len >= endp)
         return;

      /* 53 */
      if (tag == DHO_DHCP_MESSAGE_TYPE && len == 1) {
         uc = *bp++;
         switch (uc) {
         case DHCPDISCOVER:
         case DHCPOFFER:
         case DHCPREQUEST:
         case DHCPDECLINE:
         case DHCPACK:
         case DHCPNAK:
         case DHCPRELEASE:
         case DHCPINFORM:
         case DHCPFORCERENEW:
         case DHCPLEASEQUERY:
         case DHCPLEASEUNASSIGNED:
         case DHCPLEASEUNKNOWN:
         case DHCPLEASEACTIVE:

            ads->msgtypemask |= __type2mask(uc);
            break;
         default:
            break;
         }
         continue;
      }

      /* 1 */
      if (tag == DHO_SUBNET_MASK && op == BOOTREPLY) {
         if (len == 4) {
            ads->rep.netmask.s_addr = EXTRACT_32BITS(bp);
         }
         bp += len;
         continue;
      }

      /* 3 */
      if (tag == DHO_ROUTERS && op == BOOTREPLY) {
         u_char tmplen = len;
         const u_char *tmpbp = bp;
         u_char count = 0;

         while (tmplen >= 4) {
            if (count == 0)
               ads->rep.router.s_addr = EXTRACT_32BITS(tmpbp);

            count++;
            tmpbp += 4;
            tmplen -= 4;
         }

         ads->rep.router_count = count;
         bp += len;
         continue;
      }

      /* 6 */
      if (tag == DHO_DOMAIN_NAME_SERVERS && op == BOOTREPLY) {
         u_char nelems;

         nelems = sizeof(ads->rep.nameserver)/sizeof(ads->rep.nameserver[0]);
         ads->rep.nameserver_count =
            __extract_ipv4array(bp, len, ads->rep.nameserver, nelems);
         bp += len;
         continue;
      }

      /* 12 */
      if (tag == DHO_HOST_NAME) {
         u_char lenchar = (u_char)(len & 0xff);

         if (len > 0) {
            if (op == BOOTREPLY) {
               if (ads->rep.hostname)
                  free(ads->rep.hostname);
               ads->rep.hostname = __extract_string(bp, lenchar);
            } else if (op == BOOTREQUEST) {
               if (ads->req.requested_hostname)
                  free(ads->req.requested_hostname);
               ads->req.requested_hostname = __extract_string(bp, lenchar);
            }
            bp += len;
         }
         continue;
      }

      /* 15 */
      if (tag == DHO_DOMAIN_NAME && op == BOOTREPLY) {
         if (len > 0) {
            ads->rep.domainname = __extract_string(bp, (u_char)(len & 0xff));
            bp += len;
         }
         continue;
      }

      /* 26 */
      if (tag == DHO_INTERFACE_MTU && op == BOOTREPLY) {
         if (len == 2)
            ads->rep.mtu = EXTRACT_16BITS(bp);
         bp += len;
         continue;
      }

      /* 28 */
      if (tag == DHO_BROADCAST_ADDRESS && op == BOOTREPLY) {
         if (len == 4)
            ads->rep.broadcast.s_addr = EXTRACT_32BITS(bp);
         bp += len;
         continue;
      }

      /* 42 */
      if (tag == DHO_NTP_SERVERS && op == BOOTREPLY) {
         u_char nelems;

         nelems = sizeof(ads->rep.timeserver)/sizeof(ads->rep.timeserver[0]);
         ads->rep.timeserver_count =
            __extract_ipv4array(bp, len, ads->rep.timeserver, nelems);
         bp += len;
         continue;
      }

      /* 50 */
      if (tag == DHO_DHCP_REQUESTED_ADDRESS && op == BOOTREQUEST) {
         if (len == 4)
            ads->req.requested_addr.s_addr = EXTRACT_32BITS(bp);
         bp += len;
         continue;
      }

      /* 51 */
      if (tag == DHO_DHCP_LEASE_TIME && op == BOOTREPLY) {
         if (len == 4)
            ads->rep.leasetime = EXTRACT_32BITS(bp);
         bp += len;
         continue;
      }

      /* 54 */
      if (tag == DHO_DHCP_SERVER_IDENTIFIER && len == 4) {
         if (op == BOOTREPLY)
            ads->rep.server_id.s_addr = EXTRACT_32BITS(bp);
         else if (op == BOOTREQUEST)
            ads->req.requested_server_id.s_addr = EXTRACT_32BITS(bp);
         bp += len;
         continue;
      }

      /* 55 */
      if (tag == DHO_DHCP_PARAMETER_REQUEST_LIST && op == BOOTREQUEST) {
         if (len > 0) {
            if (len > ads->req.requested_options_count) {
               if (ads->req.requested_opts) {
                  free(ads->req.requested_opts);
                  ads->req.requested_opts = malloc(len);
               }
            }
            if (ads->req.requested_opts) {
               memcpy(ads->req.requested_opts, bp, len);
               ads->req.requested_options_count = len;
               qsort(ads->req.requested_opts, len,
                     sizeof(*ads->req.requested_opts), __uchar_compar);
            } else {
               ads->req.requested_options_count = 0;
            }
         }
         bp += len;
         continue;
      }

      /* 61 */
      if (tag == DHO_DHCP_CLIENT_IDENTIFIER && op == BOOTREQUEST) {
         if (len >= 2) {
            if (len <= 8) {
               ads->req.client_id.ptr = NULL;
               memcpy(&ads->req.client_id.bytes[0], bp, len);
            } else {
               ads->req.client_id.ptr = malloc(len);
               if (ads->req.client_id.ptr)
                  memcpy(ads->req.client_id.ptr, bp, len);
            }
         }
         bp += len;
         continue;
      }

      size = len;

      /* If this is an option we care about, keep going and parse.
       * Otherwise, just note that the option was present and go
       * back to top of loop.
       */

      switch (tag) {
      }

      /* Data left over? */
      if (size) {
         bp += size;
      }
   }

   return;
}

struct string {
   char *str;
   size_t len;
   size_t remain;
};

static int
__raboot_dump_node_req(void *arg0,
                       const struct ArgusDhcpClientNode * const node)
{
   int i;
   size_t optarrlen;
   struct in_addr msb;
   struct string *s = arg0;

   if (node == NULL)
      return -1;

   snprintf_append(s->str, &s->len, &s->remain, "  REQUEST ");

   optarrlen = sizeof(node->data->req.options)/sizeof(node->data->req.options[0]);

   snprintf_append(s->str, &s->len, &s->remain, "options ");
   for (i = 0; i < optarrlen; i++)
      snprintf_append(s->str, &s->len, &s->remain, "%016llx ",
                      node->data->req.options[i]);

   msb.s_addr = htonl(node->data->req.requested_addr.s_addr);
   snprintf_append(s->str, &s->len, &s->remain, "req-address %s ",
                   inet_ntoa(msb));
   msb.s_addr = htonl(node->data->req.requested_server_id.s_addr);
   snprintf_append(s->str, &s->len, &s->remain, "req-server %s ",
                   inet_ntoa(msb));

   snprintf_append(s->str, &s->len, &s->remain,
            "req-options-count %u client-id-len %u",
            node->data->req.requested_options_count,
            node->data->req.client_id_len);
   return 0;
}

static int
__raboot_dump_node_reps(void *arg0,
                        const struct ArgusDhcpClientNode * const node)
{
   struct ArgusDhcpV4LeaseOptsStruct *rep = &(node->data->rep);
   unsigned count;
   struct in_addr in;
   size_t optarrlen;
   struct string *s = arg0;

   if (node->data->num_responders == 0)
      return 0;

   snprintf_append(s->str, &s->len, &s->remain, "  REPLY ");

   while(rep) {
      for (count = 0; count < node->data->hlen; count++)
         snprintf_append(s->str, &s->len, &s->remain, "%02x%s",
                         rep->shaddr[count],
                         count == node->data->hlen-1 ? " " : ":");

      optarrlen = sizeof(rep->options)/sizeof(rep->options[0]);
      snprintf_append(s->str, &s->len, &s->remain, "options ");
      for (count = 0; count < optarrlen; count++)
         snprintf_append(s->str, &s->len, &s->remain, "%016llx ", rep->options[count]);

      snprintf_append(s->str, &s->len, &s->remain, "leasetime %u ", rep->leasetime);
      in.s_addr = htonl(rep->router.s_addr);
      snprintf_append(s->str, &s->len, &s->remain, "router %s ", inet_ntoa(in));
      in.s_addr = htonl(rep->yiaddr.s_addr);
      snprintf_append(s->str, &s->len, &s->remain, "yiaddr %s ", inet_ntoa(in));
      in.s_addr = htonl(rep->ciaddr.s_addr);
      snprintf_append(s->str, &s->len, &s->remain, "ciaddr %s ", inet_ntoa(in));

      in.s_addr = htonl(rep->netmask.s_addr);
      snprintf_append(s->str, &s->len, &s->remain, "netmask %s ", inet_ntoa(in));
      in.s_addr = htonl(rep->broadcast.s_addr);
      snprintf_append(s->str, &s->len, &s->remain, "broadcast %s ", inet_ntoa(in));
      for (count = 0; count < rep->timeserver_count; count++) {
         in.s_addr = htonl(rep->timeserver[count].s_addr);
         snprintf_append(s->str, &s->len, &s->remain, "timeserver-%u %s ",
                         count, inet_ntoa(in));
      }
      for (count = 0; count < rep->nameserver_count; count++) {
         in.s_addr = htonl(rep->nameserver[count].s_addr);
         snprintf_append(s->str, &s->len, &s->remain, "nameserver-%u %s ",
                         count, inet_ntoa(in));
      }
      if (rep->hostname)
         snprintf_append(s->str, &s->len, &s->remain, "hostname %s ", rep->hostname);
      if (rep->domainname)
         snprintf_append(s->str, &s->len, &s->remain, "domainname %s ", rep->domainname);
      in.s_addr = htonl(rep->server_id.s_addr);
      snprintf_append(s->str, &s->len, &s->remain, "server_id %s ", inet_ntoa(in));
      if (rep->option_overload)
         snprintf_append(s->str, &s->len, &s->remain, "option-overload ");
      in.s_addr = htonl(rep->siaddr.s_addr);
      snprintf_append(s->str, &s->len, &s->remain, "siaddr %s ", inet_ntoa(in));
      snprintf_append(s->str, &s->len, &s->remain, "mtu %u", rep->mtu);

      rep = rep->next;
   }
   return 0;
}

static int
__rabootp_dump_node(void *arg0, struct ArgusDhcpClientNode *node)
{
   struct ArgusDhcpStruct *data;
   int i;
   struct string *s = arg0;

   if (node == NULL)
      return -1;

   snprintf_append(s->str, &s->len, &s->remain, "NODE mac ");

   data = node->data;
   MUTEX_LOCK(data->lock);
   for (i = 0; i < data->hlen; i++) {
      snprintf_append(s->str, &s->len, &s->remain, "%02x%c", data->chaddr[i],
                      i == (data->hlen-1) ? ' ' : ':');
   }
   snprintf_append(s->str, &s->len, &s->remain,
            "XID %08x msgtypemask %04x %u/%u/%u/%u state %u flags %02x\n",
            data->xid, data->msgtypemask, data->total_responses,
            data->num_responders, data->total_requests,
            data->total_unknownops, (unsigned)data->state, data->flags);
   MUTEX_UNLOCK(data->lock);
   return 0;
}

static int
__rabootp_dump_node_verbose(void *arg0, struct ArgusDhcpClientNode *node)
{
   struct string *s = arg0;

   __rabootp_dump_node(arg0, node);
   MUTEX_LOCK(node->data->lock);
   __raboot_dump_node_req(arg0, node);
   snprintf_append(s->str, &s->len, &s->remain, "\n");
   __raboot_dump_node_reps(arg0, node);
   MUTEX_UNLOCK(node->data->lock);
   snprintf_append(s->str, &s->len, &s->remain, "\n");
   return 0;
}

/* Caller is responsible for freeing returned string */
char *RabootpDumpTreeStr(int verbose)
{
   struct string s;

   s.str = ArgusMalloc(4096);
   if (s.str == NULL)
      return NULL;

   s.len = 0;
   s.remain = 4096-1;
   *s.str = '\0';
   if (verbose)
      ClientTreeForEach(&client_tree, __rabootp_dump_node_verbose, &s);
   else
      ClientTreeForEach(&client_tree, __rabootp_dump_node, &s);

   return s.str;
}

void RabootpDumpTree(void)
{
   char *str = RabootpDumpTreeStr(1);

   if (str) {
      ArgusLog(LOG_INFO, "%s", str);
      ArgusFree(str);
   }
}

void RabootpIntvlTreeDump(void)
{
   IntvlTreeDump(&interval_tree);
}


ssize_t
RabootpIntvlTreeOverlapsRange(const struct timeval * const start,
                              const struct timeval * const stop,
                              struct ArgusDhcpIntvlNode *invec, size_t nitems)
{
   return IntvlTreeOverlapsRange(&interval_tree, start, stop, invec, nitems);
}

/* cached lock must be held by caller.
 * Caller must also have a reference (incremented refcount) to cached.
 */
static int
__rabootp_update_interval_tree(const void * const v_parsed,
                               void *v_cached,
                               void *v_arg)
{
   const struct ArgusDhcpStruct * const parsed = v_parsed;
   struct ArgusDhcpStruct *cached = v_cached;

   /* did we just transition to the BOUND state? */
   if (parsed->state == BOUND && cached->state != BOUND) {
      if (parsed->rep.leasetime) {
         struct ArgusDhcpIntvlTree *head = v_arg;

         ArgusDhcpStructUpRef(cached);
         if (ArgusDhcpIntvlTreeInsert(head,
                                      &cached->first_bind,
                                      parsed->rep.leasetime,
                                      cached) != 0)
            /* interval found for this transaction and was updated.
             * Do not increment the refcount again.
             */
            ArgusDhcpStructFree(cached);
      }
   }
   return 0;
}

/* cached lock must be held by caller.
 * Caller must also have a reference (incremented refcount) to cached.
 */
static int
__rabootp_update_patricia_tree(const void * const v_parsed,
                               void *v_cached,
                               void *v_arg)
{
   const struct ArgusDhcpStruct * const parsed = v_parsed;
   struct ArgusDhcpStruct *cached = v_cached;
   struct ArgusParserStruct *parser = v_arg;
   int rv = -1;

   /* did we just transition to the BOUND state? */
   if (parsed->state == BOUND && cached->state != BOUND) {
      MUTEX_LOCK(&parser->lock);
      rv = RabootpPatriciaTreeUpdate(v_parsed, v_cached, v_arg);
      MUTEX_UNLOCK(&parser->lock);
   }

   return rv;
}

int
RabootpCallbackRegister(enum rabootp_callback_trigger trigger,
                        rabootp_cb cb, void *arg)
{
   int rv;

   switch (trigger) {
      case CALLBACK_STATECHANGE:
         rv = rabootp_cb_register(&callback.state_change, cb, arg);
         break;
      case CALLBACK_XIDNEW:
         rv = rabootp_cb_register(&callback.xid_new, cb, arg);
         break;
      case CALLBACK_XIDUPDATE:
         rv = rabootp_cb_register(&callback.xid_update, cb, arg);
         break;
      case CALLBACK_XIDDELETE:
         rv = rabootp_cb_register(&callback.xid_delete, cb, arg);
         break;
      default:
         rv = -1;
   }
   return  rv;
}

int
RabootpCallbackUnregister(enum rabootp_callback_trigger trigger,
                          rabootp_cb cb)
{
   int rv;

   switch (trigger) {
      case CALLBACK_STATECHANGE:
         rv = rabootp_cb_unregister(&callback.state_change, cb);
         break;
      case CALLBACK_XIDNEW:
         rv = rabootp_cb_unregister(&callback.xid_new, cb);
         break;
      case CALLBACK_XIDUPDATE:
         rv = rabootp_cb_unregister(&callback.xid_update, cb);
         break;
      case CALLBACK_XIDDELETE:
         rv = rabootp_cb_unregister(&callback.xid_delete, cb);
         break;
      default:
         rv = -1;
   }
   return  rv;
}

int RabootpClientRemove(struct ArgusDhcpStruct *ads)
{
   return ArgusDhcpClientTreeRemove(&client_tree, ads);
}

int RabootpIntvlRemove(const struct timeval * const intlo)
{
   return ArgusDhcpIntvlTreeRemove(&interval_tree, intlo);
}

size_t RabootpIntvlTreeCount(void)
{
   return IntvlTreeCount(&interval_tree);
}

void
RabootpCallbacksInit(struct ArgusParserStruct *parser)
{
   memset(&callback, 0, sizeof(callback));
   RabootpCallbackRegister(CALLBACK_STATECHANGE, __rabootp_update_interval_tree,
                           &interval_tree);
   RabootpCallbackRegister(CALLBACK_STATECHANGE, __rabootp_update_patricia_tree,
                           parser);
}

void
RabootpCallbacksCleanup(void)
{
   rabootp_cb_cleanup(&callback.state_change);
   rabootp_cb_cleanup(&callback.xid_new);
   rabootp_cb_cleanup(&callback.xid_update);
   rabootp_cb_cleanup(&callback.xid_delete);
}

void
RabootpCleanup(void)
{
   /* only after all processing has stopped */
   ArgusDhcpClientTreeFree(&client_tree);
   ArgusDhcpIntvlTreeFree(&interval_tree);
}
