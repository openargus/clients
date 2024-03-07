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

extern u_char *snapend;

#include "interface.h"
#include "rabootp.h"

extern char ArgusBuf[];

static void rfc1048_print(const u_char *);
static void cmu_print(const u_char *);

static char tstr[] = " [|bootp]";

static const struct tok bootp_flag_values[] = {
    { 0x8000, "Broadcast" },
    { 0, NULL}
};

static const struct tok bootp_op_values[] = {
    { BOOTPREQUEST, "Request" },
    { BOOTPREPLY,   "Reply" },
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
   register const struct bootp *bp;
   static const u_char vm_cmu[4] = VM_CMU;
   static const u_char vm_rfc1048[4] = VM_RFC1048;

   unsigned int iaddr;

   bp = (struct bootp *)cp;
   TCHECK(bp->bp_op);

   sprintf(&ArgusBuf[strlen(ArgusBuf)],"BOOTP/DHCP, %s",
          tok2str(bootp_op_values, "unknown (0x%02x)", bp->bp_op));

   if (bp->bp_htype == 1 && bp->bp_hlen == 6 && bp->bp_op == BOOTPREQUEST) {
      TCHECK2(bp->bp_chaddr[0], 6);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," from %s", etheraddr_string(ArgusParser, (u_char *)bp->bp_chaddr));
   }

   sprintf(&ArgusBuf[strlen(ArgusBuf)],", length: %u", length);

   if (!ArgusParser->vflag)
      return ArgusBuf;

   TCHECK(bp->bp_secs);

   /* The usual hardware address type is 1 (10Mb Ethernet) */
   if (bp->bp_htype != 1)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", htype-#%d", bp->bp_htype);

   /* The usual length for 10Mb Ethernet address is 6 bytes */
   if (bp->bp_htype != 1 || bp->bp_hlen != 6)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", hlen:%d", bp->bp_hlen);

   /* Only print interesting fields */
   if (bp->bp_hops)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", hops:%d", bp->bp_hops);
   if (bp->bp_xid)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", xid:0x%x", EXTRACT_32BITS(&bp->bp_xid));
   if (bp->bp_secs)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", secs:%d", EXTRACT_16BITS(&bp->bp_secs));

   sprintf(&ArgusBuf[strlen(ArgusBuf)],", flags: [%s]",
          bittok2str(bootp_flag_values, "none", EXTRACT_16BITS(&bp->bp_flags)));
   if (ArgusParser->vflag>1)
     sprintf(&ArgusBuf[strlen(ArgusBuf)], " (0x%04x)", EXTRACT_16BITS(&bp->bp_flags));

   /* Client's ip address */
   TCHECK(bp->bp_ciaddr);
   if (bp->bp_ciaddr.s_addr) {
      iaddr = ntohl(bp->bp_ciaddr.s_addr);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Client IP: %s", ipaddr_string(&iaddr));
   }

   /* 'your' ip address (bootp client) */
   TCHECK(bp->bp_yiaddr);
   if (bp->bp_yiaddr.s_addr) {
      iaddr = ntohl(bp->bp_yiaddr.s_addr);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Your IP: %s", ipaddr_string(&iaddr));
   }

   /* Server's ip address */
   TCHECK(bp->bp_siaddr);
   if (bp->bp_siaddr.s_addr) {
      iaddr = ntohl(bp->bp_siaddr.s_addr);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Server IP: %s", ipaddr_string(&iaddr));
   }

   /* Gateway's ip address */
   TCHECK(bp->bp_giaddr);
   if (bp->bp_giaddr.s_addr) {
      iaddr = ntohl(bp->bp_giaddr.s_addr);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Gateway IP: %s", ipaddr_string(&iaddr));
   }

   /* Client's Ethernet address */
   if (bp->bp_htype == 1 && bp->bp_hlen == 6) {
      TCHECK2(bp->bp_chaddr[0], 6);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Client Ethernet Address: %s", etheraddr_string(ArgusParser, (u_char *)bp->bp_chaddr));
   }

   TCHECK2(bp->bp_sname[0], 1);      /* check first char only */
   if (*bp->bp_sname) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," sname \"");
      if (fn_print(bp->bp_sname, snapend, ArgusBuf)) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tstr + 1);
         return ArgusBuf;
      }
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
   }
   TCHECK2(bp->bp_file[0], 1);      /* check first char only */
   if (*bp->bp_file) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," file \"");
      if (fn_print(bp->bp_file, snapend, ArgusBuf)) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tstr + 1);
         return ArgusBuf;
      }
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
   }

   /* Decode the vendor buffer */
   TCHECK(bp->bp_vend[0]);
   if (memcmp((const char *)bp->bp_vend, vm_rfc1048,
       sizeof(u_int32_t)) == 0)
      rfc1048_print(bp->bp_vend);
   else if (memcmp((const char *)bp->bp_vend, vm_cmu,
            sizeof(u_int32_t)) == 0)
      cmu_print(bp->bp_vend);
   else {
      u_int32_t ul;

      ul = EXTRACT_32BITS(&bp->bp_vend);
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
/* RFC1048 tags */
   { TAG_PAD,                "PAD" },
   { TAG_SUBNET_MASK,        "iSM" },   /* subnet mask (RFC950) */
   { TAG_TIME_OFFSET,        "LTZ" },   /* seconds from UTC */
   { TAG_GATEWAY,            "iDG" },   /* default gateway */
   { TAG_TIME_SERVER,        "iTS" },   /* time servers (RFC868) */
   { TAG_NAME_SERVER,        "iIEN" },  /* IEN name servers (IEN116) */
   { TAG_DOMAIN_SERVER,      "iNS" },   /* domain name (RFC1035) */
   { TAG_LOG_SERVER,         "iLOG" },  /* MIT log servers */
   { TAG_COOKIE_SERVER,      "iCS" },   /* cookie servers (RFC865) */
   { TAG_LPR_SERVER,         "iLPR" },  /* lpr server (RFC1179) */
   { TAG_IMPRESS_SERVER,     "iIM" },   /* impress servers (Imagen) */
   { TAG_RLP_SERVER,         "iRL" },   /* resource location (RFC887) */
   { TAG_HOSTNAME,           "aHN" },   /* ascii hostname */
   { TAG_BOOTSIZE,           "sBS" },   /* 512 byte blocks */
   { TAG_END,                "END" },

/* RFC1497 tags */
   { TAG_DUMPPATH,           "aDP" },
   { TAG_DOMAINNAME,         "aDN" },
   { TAG_SWAP_SERVER,        "iSS" },
   { TAG_ROOTPATH,           "aRP" },
   { TAG_EXTPATH,            "aEP" },

/* RFC2132 tags */
   { TAG_IP_FORWARD,         "BIPF" },
   { TAG_NL_SRCRT,           "BSRT" },
   { TAG_PFILTERS,           "pPF" },
   { TAG_REASS_SIZE,         "sRSZ" },
   { TAG_DEF_TTL,            "bTTL" },
   { TAG_MTU_TIMEOUT,        "lMA" },
   { TAG_MTU_TABLE,          "sMT" },
   { TAG_INT_MTU,            "sMTU" },
   { TAG_LOCAL_SUBNETS,      "BLSN" },
   { TAG_BROAD_ADDR,         "iBR" },
   { TAG_DO_MASK_DISC,       "BMD" },
   { TAG_SUPPLY_MASK,        "BMS" },
   { TAG_DO_RDISC,           "BRD" },
   { TAG_RTR_SOL_ADDR,       "iRSA" },
   { TAG_STATIC_ROUTE,       "pSR" },
   { TAG_USE_TRAILERS,       "BUT" },
   { TAG_ARP_TIMEOUT,        "lAT" },
   { TAG_ETH_ENCAP,          "BIE" },
   { TAG_TCP_TTL,            "bTT" },
   { TAG_TCP_KEEPALIVE,      "lKI" },
   { TAG_KEEPALIVE_GO,       "BKG" },
   { TAG_NIS_DOMAIN,         "aYD" },
   { TAG_NIS_SERVERS,        "iYS" },
   { TAG_NTP_SERVERS,        "iNTP" },
   { TAG_VENDOR_OPTS,        "bVO" },
   { TAG_NETBIOS_NS,         "iWNS" },
   { TAG_NETBIOS_DDS,        "iWDD" },
   { TAG_NETBIOS_NODE,       "$WNT" },
   { TAG_NETBIOS_SCOPE,      "aWSC" },
   { TAG_XWIN_FS,            "iXFS" },
   { TAG_XWIN_DM,            "iXDM" },
   { TAG_NIS_P_DOMAIN,       "sN+D" },
   { TAG_NIS_P_SERVERS,      "iN+S" },
   { TAG_MOBILE_HOME,        "iMH" },
   { TAG_SMPT_SERVER,        "iSMTP" },
   { TAG_POP3_SERVER,        "iPOP3" },
   { TAG_NNTP_SERVER,        "iNNTP" },
   { TAG_WWW_SERVER,         "iWWW" },
   { TAG_FINGER_SERVER,      "iFG" },
   { TAG_IRC_SERVER,         "iIRC" },
   { TAG_STREETTALK_SRVR,    "iSTS" },
   { TAG_STREETTALK_STDA,    "iSTDA" },
   { TAG_REQUESTED_IP,       "iRQ" },
   { TAG_IP_LEASE,           "lLT" },
   { TAG_OPT_OVERLOAD,       "$OO" },
   { TAG_TFTP_SERVER,        "aTFTP" },
   { TAG_BOOTFILENAME,       "aBF" },
   { TAG_DHCP_MESSAGE,       "DHCP" },
   { TAG_SERVER_ID,          "iSID" },
   { TAG_PARM_REQUEST,       "bPR" },
   { TAG_MESSAGE,            "aMSG" },
   { TAG_MAX_MSG_SIZE,       "sMSZ" },
   { TAG_RENEWAL_TIME,       "lRN" },
   { TAG_REBIND_TIME,        "lRB" },
   { TAG_VENDOR_CLASS,       "aVC" },
   { TAG_CLIENT_ID,          "$CID" },

/* RFC 2485 */
   { TAG_OPEN_GROUP_UAP,     "aUAP" },

/* RFC 2563 */
   { TAG_DISABLE_AUTOCONF,   "BNOAUTO" },

/* RFC 2610 */
   { TAG_SLP_DA,             "bSLP-DA" },   
   { TAG_SLP_SCOPE,          "bSLP-SCOPE" },

/* RFC 2937 */
   { TAG_NS_SEARCH,          "sNSSEARCH" },

/* RFC 3011 */
   { TAG_IP4_SUBNET_SELECT,  "iSUBNET" },

/* http://www.iana.org/assignments/bootp-dhcp-extensions/index.htm */
   { TAG_USER_CLASS,         "aCLASS" },
   { TAG_SLP_NAMING_AUTH,    "aSLP-NA" },
   { TAG_CLIENT_FQDN,        "$FQDN" },
   { TAG_AGENT_CIRCUIT,      "bACKT" },
   { TAG_AGENT_REMOTE,       "bARMT" },
   { TAG_AGENT_MASK,         "bAMSK" },
   { TAG_TZ_STRING,          "aTZSTR" },
   { TAG_FQDN_OPTION,        "bFQDNS" },
   { TAG_AUTH,               "bAUTH" },
   { TAG_VINES_SERVERS,      "iVINES" },
   { TAG_SERVER_RANK,        "sRANK" },
   { TAG_CLIENT_ARCH,        "sARCH" },
   { TAG_CLIENT_NDI,         "bNDI" },
   { TAG_CLIENT_GUID,        "bGUID" },
   { TAG_LDAP_URL,           "aLDAP" },
   { TAG_6OVER4,             "i6o4" },
   { TAG_PRINTER_NAME,       "aPRTR" },
   { TAG_MDHCP_SERVER,       "bMDHCP" },
   { TAG_IPX_COMPAT,         "bIPX" },
   { TAG_NETINFO_PARENT,     "iNI" },
   { TAG_NETINFO_PARENT_TAG, "aNITAG" },
   { TAG_URL,                "aURL" },
   { TAG_FAILOVER,           "bFAIL" },
   { 0, NULL }
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
rfc1048_print(register const u_char *bp)
{
   register u_int16_t tag;
   register u_int len, size;
   register const char *cp;
   register char c;
   int first;
   u_int32_t ul;
   u_int16_t us;
   u_int8_t uc;

   sprintf(&ArgusBuf[strlen(ArgusBuf)]," Vendor-rfc1048:");

   /* Step over magic cookie */
   sprintf(&ArgusBuf[strlen(ArgusBuf)], " MAGIC:0x%08x", EXTRACT_32BITS(bp));
   bp += sizeof(int32_t);

   /* Loop while we there is a tag left in the buffer */
   while (bp + 1 < snapend) {
      tag = *bp++;
      if (tag == TAG_PAD)
         continue;
      if (tag == TAG_END)
         return;
      if (tag == TAG_EXTENDED_OPTION) {
         TCHECK2(*(bp + 1), 2);
         tag = EXTRACT_16BITS(bp + 1);
         /* XXX we don't know yet if the IANA will
          * preclude overlap of 1-byte and 2-byte spaces.
          * If not, we need to offset tag after this step.
          */
         cp = tok2str(xtag2str, "?xT%u", tag);
      } else
         cp = tok2str(tag2str, "?T%u", tag);
      c = *cp++;
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s:", cp);

      /* Get the length; check for truncation */
      if (bp + 1 >= snapend) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tstr);
         return;
      }
      len = *bp++;
      if (bp + len >= snapend) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|bootp %u]", len);
         return;
      }

      if (tag == TAG_DHCP_MESSAGE && len == 1) {
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

      if (tag == TAG_PARM_REQUEST) {
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
      if (tag == TAG_EXTENDED_REQUEST) {
         first = 1;
         while (len > 1) {
            len -= 2;
            us = EXTRACT_16BITS(bp);
            bp += 2;
            cp = tok2str(xtag2str, "?xT%u", us);
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
         if (fn_printn(bp, size, snapend, &ArgusBuf[strlen(ArgusBuf)]) == NULL) {
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
            goto trunc;
         }
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
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

         case TAG_NETBIOS_NODE:
            tag = *bp++;
            --size;
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tok2str(nbo2str, NULL, tag));
            break;

         case TAG_OPT_OVERLOAD:
            tag = *bp++;
            --size;
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tok2str(oo2str, NULL, tag));
            break;

         case TAG_CLIENT_FQDN:
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
            if (fn_printn(bp, size - 3, snapend, &ArgusBuf[strlen(ArgusBuf)]) == NULL) {
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
               goto trunc;
            }
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
            bp += size - 3;
            size = 0;
            break;

         case TAG_CLIENT_ID:
             {   int type = *bp++;
            size--;
            if (type == 0) {
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
               if (fn_printn(bp, size, snapend, &ArgusBuf[strlen(ArgusBuf)]) == NULL) {
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

static void
cmu_print(register const u_char *bp)
{
   register const struct cmu_vend *cmu;

#define PRINTCMUADDR(m, s) { TCHECK(cmu->m); \
    if (cmu->m.s_addr != 0) \
   sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s:%s", s, ipaddr_string(&cmu->m.s_addr)); }

   sprintf(&ArgusBuf[strlen(ArgusBuf)]," vend-cmu");
   cmu = (const struct cmu_vend *)bp;

   /* Only print if there are unknown bits */
   TCHECK(cmu->v_flags);
   if ((cmu->v_flags & ~(VF_SMASK)) != 0)
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," F:0x%x", cmu->v_flags);
   PRINTCMUADDR(v_dgate, "DG");
   PRINTCMUADDR(v_smask, cmu->v_flags & VF_SMASK ? "SM" : "SM*");
   PRINTCMUADDR(v_dns1, "NS1");
   PRINTCMUADDR(v_dns2, "NS2");
   PRINTCMUADDR(v_ins1, "IEN1");
   PRINTCMUADDR(v_ins2, "IEN2");
   PRINTCMUADDR(v_ts1, "TS1");
   PRINTCMUADDR(v_ts2, "TS2");
   return;

trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "%s", tstr);
#undef PRINTCMUADDR
}
