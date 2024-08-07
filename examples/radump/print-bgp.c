/*
 *  (C) 1999 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Extensively modified by Hannes Gredler (hannes@juniper.net) for more
 * complete BGP support.
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>

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
#include "bgp.h"
#include "l2vpn.h"

extern char ArgusBuf[];

#if !defined(MAXHOSTNAMELEN)
#define MAXHOSTNAMELEN 256
#endif

#define TOKBUFSIZE        128
    
struct bgp {
   u_int8_t bgp_marker[16];
   u_int16_t bgp_len;
   u_int8_t bgp_type;
};
#define BGP_SIZE      19   /* unaligned */

#define BGP_OPEN      1
#define BGP_UPDATE      2
#define BGP_NOTIFICATION   3
#define BGP_KEEPALIVE      4
#define BGP_ROUTE_REFRESH       5

static struct tok bgp_msg_values[] = {
    { BGP_OPEN,                 "Open"},
    { BGP_UPDATE,               "Update"},
    { BGP_NOTIFICATION,         "Notification"},
    { BGP_KEEPALIVE,            "Keepalive"},
    { BGP_ROUTE_REFRESH,        "Route Refresh"},
    { 0, NULL}
};

struct bgp_open {
   u_int8_t bgpo_marker[16];
   u_int16_t bgpo_len;
   u_int8_t bgpo_type;
   u_int8_t bgpo_version;
   u_int16_t bgpo_myas;
   u_int16_t bgpo_holdtime;
   u_int32_t bgpo_id;
   u_int8_t bgpo_optlen;
   /* options should follow */
};
#define BGP_OPEN_SIZE      29   /* unaligned */

struct bgp_opt {
   u_int8_t bgpopt_type;
   u_int8_t bgpopt_len;
   /* variable length */
};
#define BGP_OPT_SIZE      2   /* some compilers may pad to 4 bytes */

#define BGP_UPDATE_MINSIZE      23

struct bgp_notification {
   u_int8_t bgpn_marker[16];
   u_int16_t bgpn_len;
   u_int8_t bgpn_type;
   u_int8_t bgpn_major;
   u_int8_t bgpn_minor;
};
#define BGP_NOTIFICATION_SIZE      21   /* unaligned */

struct bgp_route_refresh {
    u_int8_t  bgp_marker[16];
    u_int16_t len;
    u_int8_t  type;
    u_int8_t  afi[2]; /* the compiler messes this structure up               */
    u_int8_t  res;    /* when doing misaligned sequences of int8 and int16   */
    u_int8_t  safi;   /* afi should be int16 - so we have to access it using */
};                    /* EXTRACT_16BITS(&bgp_route_refresh->afi) (sigh)      */ 
#define BGP_ROUTE_REFRESH_SIZE          23

struct bgp_attr {
   u_int8_t bgpa_flags;
   u_int8_t bgpa_type;
   union {
      u_int8_t len;
      u_int16_t elen;
   } bgpa_len;
#define bgp_attr_len(p) \
   (((p)->bgpa_flags & 0x10) ? \
      EXTRACT_16BITS(&(p)->bgpa_len.elen) : (p)->bgpa_len.len)
#define bgp_attr_off(p) \
   (((p)->bgpa_flags & 0x10) ? 4 : 3)
};

#define BGPTYPE_ORIGIN         1
#define BGPTYPE_AS_PATH         2
#define BGPTYPE_NEXT_HOP      3
#define BGPTYPE_MULTI_EXIT_DISC      4
#define BGPTYPE_LOCAL_PREF      5
#define BGPTYPE_ATOMIC_AGGREGATE   6
#define BGPTYPE_AGGREGATOR      7
#define   BGPTYPE_COMMUNITIES      8   /* RFC1997 */
#define   BGPTYPE_ORIGINATOR_ID      9   /* RFC1998 */
#define   BGPTYPE_CLUSTER_LIST      10   /* RFC1998 */
#define   BGPTYPE_DPA         11   /* draft-ietf-idr-bgp-dpa */
#define   BGPTYPE_ADVERTISERS      12   /* RFC1863 */
#define   BGPTYPE_RCID_PATH      13   /* RFC1863 */
#define BGPTYPE_MP_REACH_NLRI      14   /* RFC2283 */
#define BGPTYPE_MP_UNREACH_NLRI      15   /* RFC2283 */
#define BGPTYPE_EXTD_COMMUNITIES        16      /* draft-ietf-idr-bgp-ext-communities */
#define BGPTYPE_ATTR_SET               128      /* draft-marques-ppvpn-ibgp */

#define BGP_MP_NLRI_MINSIZE              3       /* End of RIB Marker detection */

static struct tok bgp_attr_values[] = {
    { BGPTYPE_ORIGIN,           "Origin"},
    { BGPTYPE_AS_PATH,          "AS Path"},
    { BGPTYPE_NEXT_HOP,         "Next Hop"},
    { BGPTYPE_MULTI_EXIT_DISC,  "Multi Exit Discriminator"},
    { BGPTYPE_LOCAL_PREF,       "Local Preference"},
    { BGPTYPE_ATOMIC_AGGREGATE, "Atomic Aggregate"},
    { BGPTYPE_AGGREGATOR,       "Aggregator"},
    { BGPTYPE_COMMUNITIES,      "Community"},
    { BGPTYPE_ORIGINATOR_ID,    "Originator ID"},
    { BGPTYPE_CLUSTER_LIST,     "Cluster List"},
    { BGPTYPE_DPA,              "DPA"},
    { BGPTYPE_ADVERTISERS,      "Advertisers"},
    { BGPTYPE_RCID_PATH,        "RCID Path / Cluster ID"},
    { BGPTYPE_MP_REACH_NLRI,    "Multi-Protocol Reach NLRI"},
    { BGPTYPE_MP_UNREACH_NLRI,  "Multi-Protocol Unreach NLRI"},
    { BGPTYPE_EXTD_COMMUNITIES, "Extended Community"},
    { BGPTYPE_ATTR_SET,         "Attribute Set"},
    { 255,                      "Reserved for development"},
    { 0, NULL}
};

#define BGP_AS_SET             1
#define BGP_AS_SEQUENCE        2
#define BGP_CONFED_AS_SEQUENCE 3 /* draft-ietf-idr-rfc3065bis-01 */
#define BGP_CONFED_AS_SET      4 /* draft-ietf-idr-rfc3065bis-01  */

static struct tok bgp_as_path_segment_open_values[] = {
    { BGP_AS_SEQUENCE,         ""},
    { BGP_AS_SET,              "{ "},
    { BGP_CONFED_AS_SEQUENCE,  "( "},
    { BGP_CONFED_AS_SET,       "({ "},
    { 0, NULL}
};

static struct tok bgp_as_path_segment_close_values[] = {
    { BGP_AS_SEQUENCE,         ""},
    { BGP_AS_SET,              "}"},
    { BGP_CONFED_AS_SEQUENCE,  ")"},
    { BGP_CONFED_AS_SET,       "})"},
    { 0, NULL}
};

#define BGP_OPT_AUTH                    1
#define BGP_OPT_CAP                     2


static struct tok bgp_opt_values[] = {
    { BGP_OPT_AUTH,             "Authentication Information"},
    { BGP_OPT_CAP,              "Capabilities Advertisement"},
    { 0, NULL}
};

#define BGP_CAPCODE_MP                  1
#define BGP_CAPCODE_RR                  2
#define BGP_CAPCODE_ORF                 3 /* XXX */
#define BGP_CAPCODE_RESTART            64 /* draft-ietf-idr-restart-05  */
#define BGP_CAPCODE_AS_NEW             65 /* XXX */
#define BGP_CAPCODE_DYN_CAP            67 /* XXX */
#define BGP_CAPCODE_RR_CISCO          128

static struct tok bgp_capcode_values[] = {
    { BGP_CAPCODE_MP,           "Multiprotocol Extensions"},
    { BGP_CAPCODE_RR,           "Route Refresh"},
    { BGP_CAPCODE_ORF,          "Cooperative Route Filtering"},
    { BGP_CAPCODE_RESTART,      "Graceful Restart"},
    { BGP_CAPCODE_AS_NEW,       "32-Bit AS Number"},
    { BGP_CAPCODE_DYN_CAP,      "Dynamic Capability"},
    { BGP_CAPCODE_RR_CISCO,     "Route Refresh (Cisco)"},
    { 0, NULL}
};

#define BGP_NOTIFY_MAJOR_MSG            1
#define BGP_NOTIFY_MAJOR_OPEN           2
#define BGP_NOTIFY_MAJOR_UPDATE         3
#define BGP_NOTIFY_MAJOR_HOLDTIME       4
#define BGP_NOTIFY_MAJOR_FSM            5
#define BGP_NOTIFY_MAJOR_CEASE          6
#define BGP_NOTIFY_MAJOR_CAP            7

static struct tok bgp_notify_major_values[] = {
    { BGP_NOTIFY_MAJOR_MSG,     "Message Header Error"},
    { BGP_NOTIFY_MAJOR_OPEN,    "OPEN Message Error"},
    { BGP_NOTIFY_MAJOR_UPDATE,  "UPDATE Message Error"},
    { BGP_NOTIFY_MAJOR_HOLDTIME,"Hold Timer Expired"},
    { BGP_NOTIFY_MAJOR_FSM,     "Finite State Machine Error"},
    { BGP_NOTIFY_MAJOR_CEASE,   "Cease"},
    { BGP_NOTIFY_MAJOR_CAP,     "Capability Message Error"},
    { 0, NULL}
};

/* draft-ietf-idr-cease-subcode-02 */
#define BGP_NOTIFY_MINOR_CEASE_MAXPRFX  1
static struct tok bgp_notify_minor_cease_values[] = {
    { BGP_NOTIFY_MINOR_CEASE_MAXPRFX, "Maximum Number of Prefixes Reached"},
    { 2,                        "Administratively Shutdown"},
    { 3,                        "Peer Unconfigured"},
    { 4,                        "Administratively Reset"},
    { 5,                        "Connection Rejected"},
    { 6,                        "Other Configuration Change"},
    { 7,                        "Connection Collision Resolution"},
    { 0, NULL}
};

static struct tok bgp_notify_minor_msg_values[] = {
    { 1,                        "Connection Not Synchronized"},
    { 2,                        "Bad Message Length"},
    { 3,                        "Bad Message Type"},
    { 0, NULL}
};

static struct tok bgp_notify_minor_open_values[] = {
    { 1,                        "Unsupported Version Number"},
    { 2,                        "Bad Peer AS"},
    { 3,                        "Bad BGP Identifier"},
    { 4,                        "Unsupported Optional Parameter"},
    { 5,                        "Authentication Failure"},
    { 6,                        "Unacceptable Hold Time"},
    { 0, NULL}
};

static struct tok bgp_notify_minor_update_values[] = {
    { 1,                        "Malformed Attribute List"},
    { 2,                        "Unrecognized Well-known Attribute"},
    { 3,                        "Missing Well-known Attribute"},
    { 4,                        "Attribute Flags Error"},
    { 5,                        "Attribute Length Error"},
    { 6,                        "Invalid ORIGIN Attribute"},
    { 7,                        "AS Routing Loop"},
    { 8,                        "Invalid NEXT_HOP Attribute"},
    { 9,                        "Optional Attribute Error"},
    { 10,                       "Invalid Network Field"},
    { 11,                       "Malformed AS_PATH"},
    { 0, NULL}
};

static struct tok bgp_notify_minor_cap_values[] = {
    { 1,                        "Invalid Action Value" },
    { 2,                        "Invalid Capability Length" },
    { 3,                        "Malformed Capability Value" },
    { 4,                        "Unsupported Capability Code" },
    { 0, NULL }
};

static struct tok bgp_origin_values[] = {
    { 0,                        "IGP"},
    { 1,                        "EGP"},
    { 2,                        "Incomplete"},
    { 0, NULL}
};

/* Subsequent address family identifier, RFC2283 section 7 */
#define SAFNUM_RES                      0
#define SAFNUM_UNICAST                  1
#define SAFNUM_MULTICAST                2
#define SAFNUM_UNIMULTICAST             3
/* labeled BGP RFC3107 */
#define SAFNUM_LABUNICAST               4
#define SAFNUM_TUNNEL                   64 /* XXX */
#define SAFNUM_VPLS                     65 /* XXX */
#define SAFNUM_MDT                      66 /* XXX */
/* Section 4.3.4 of draft-rosen-rfc2547bis-03.txt  */
#define SAFNUM_VPNUNICAST               128
#define SAFNUM_VPNMULTICAST             129
#define SAFNUM_VPNUNIMULTICAST          130
/* draft-marques-ppvpn-rt-constrain-01.txt */
#define SAFNUM_RT_ROUTING_INFO          132

#define BGP_VPN_RD_LEN                  8

static struct tok bgp_safi_values[] = {
    { SAFNUM_RES,               "Reserved"},
    { SAFNUM_UNICAST,           "Unicast"},
    { SAFNUM_MULTICAST,         "Multicast"},
    { SAFNUM_UNIMULTICAST,      "Unicast+Multicast"},
    { SAFNUM_LABUNICAST,        "labeled Unicast"},
    { SAFNUM_TUNNEL,            "Tunnel"},
    { SAFNUM_VPLS,              "VPLS"},
    { SAFNUM_MDT,               "MDT"},
    { SAFNUM_VPNUNICAST,        "labeled VPN Unicast"},
    { SAFNUM_VPNMULTICAST,      "labeled VPN Multicast"},
    { SAFNUM_VPNUNIMULTICAST,   "labeled VPN Unicast+Multicast"},
    { SAFNUM_RT_ROUTING_INFO,   "Route Target Routing Information"}, /* draft-marques-ppvpn-rt-constrain-01.txt */
    { 0, NULL }
};

/* well-known community */
#define BGP_COMMUNITY_NO_EXPORT         0xffffff01
#define BGP_COMMUNITY_NO_ADVERT         0xffffff02
#define BGP_COMMUNITY_NO_EXPORT_SUBCONFED   0xffffff03

/* RFC1700 address family numbers */
#define AFNUM_INET   1
#define AFNUM_INET6   2
#define AFNUM_NSAP   3
#define AFNUM_HDLC   4
#define AFNUM_BBN1822   5
#define AFNUM_802   6
#define AFNUM_E163   7
#define AFNUM_E164   8
#define AFNUM_F69   9
#define AFNUM_X121   10
#define AFNUM_IPX   11
#define AFNUM_ATALK   12
#define AFNUM_DECNET   13
#define AFNUM_BANYAN   14
#define AFNUM_E164NSAP   15
/* draft-kompella-ppvpn-l2vpn */
#define AFNUM_L2VPN     196 /* still to be approved by IANA */

static struct tok bgp_afi_values[] = {
    { 0,                      "Reserved"},
    { AFNUM_INET,             "IPv4"},
    { AFNUM_INET6,            "IPv6"},
    { AFNUM_NSAP,             "NSAP"},
    { AFNUM_HDLC,             "HDLC"},
    { AFNUM_BBN1822,          "BBN 1822"},
    { AFNUM_802,              "802"},
    { AFNUM_E163,             "E.163"},
    { AFNUM_E164,             "E.164"},
    { AFNUM_F69,              "F.69"},
    { AFNUM_X121,             "X.121"},
    { AFNUM_IPX,              "Novell IPX"},
    { AFNUM_ATALK,            "Appletalk"},
    { AFNUM_DECNET,           "Decnet IV"},
    { AFNUM_BANYAN,           "Banyan Vines"},
    { AFNUM_E164NSAP,         "E.164 with NSAP subaddress"},
    { AFNUM_L2VPN,            "Layer-2 VPN"},
    { 0, NULL},
};

/* Extended community type - draft-ietf-idr-bgp-ext-communities-05 */
#define BGP_EXT_COM_RT_0        0x0002  /* Route Target,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_RT_1        0x0102  /* Route Target,Format IP address:AN(2bytes) */
#define BGP_EXT_COM_RT_2        0x0202  /* Route Target,Format AN(4bytes):local(2bytes) */
#define BGP_EXT_COM_RO_0        0x0003  /* Route Origin,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_RO_1        0x0103  /* Route Origin,Format IP address:AN(2bytes) */
#define BGP_EXT_COM_RO_2        0x0203  /* Route Origin,Format AN(4bytes):local(2bytes) */
#define BGP_EXT_COM_LINKBAND    0x4004  /* Link Bandwidth,Format AS(2B):Bandwidth(4B) */
                                        /* rfc2547 bgp-mpls-vpns */
#define BGP_EXT_COM_CISCO_MCAST 0x0009  /* cisco proprietary */

#define BGP_EXT_COM_VPN_ORIGIN  0x0005  /* OSPF Domain ID / VPN of Origin  - draft-rosen-vpns-ospf-bgp-mpls */
#define BGP_EXT_COM_VPN_ORIGIN2 0x0105  /* duplicate - keep for backwards compatability */
#define BGP_EXT_COM_VPN_ORIGIN3 0x0205  /* duplicate - keep for backwards compatability */
#define BGP_EXT_COM_VPN_ORIGIN4 0x8005  /* duplicate - keep for backwards compatability */

#define BGP_EXT_COM_OSPF_RTYPE  0x0306  /* OSPF Route Type,Format Area(4B):RouteType(1B):Options(1B) */
#define BGP_EXT_COM_OSPF_RTYPE2 0x8000  /* duplicate - keep for backwards compatability */

#define BGP_EXT_COM_OSPF_RID    0x0107  /* OSPF Router ID,Format RouterID(4B):Unused(2B) */
#define BGP_EXT_COM_OSPF_RID2   0x8001  /* duplicate - keep for backwards compatability */ 

#define BGP_EXT_COM_L2INFO      0x800a  /* draft-kompella-ppvpn-l2vpn */

static struct tok bgp_extd_comm_flag_values[] = {
    { 0x8000,                  "vendor-specific"},
    { 0x4000,                  "non-transitive"},
    { 0, NULL},
};

static struct tok bgp_extd_comm_subtype_values[] = {
    { BGP_EXT_COM_RT_0,        "target"},
    { BGP_EXT_COM_RT_1,        "target"},
    { BGP_EXT_COM_RT_2,        "target"},
    { BGP_EXT_COM_RO_0,        "origin"},
    { BGP_EXT_COM_RO_1,        "origin"},
    { BGP_EXT_COM_RO_2,        "origin"},
    { BGP_EXT_COM_LINKBAND,    "link-BW"},
    { BGP_EXT_COM_CISCO_MCAST, "mdt-group"},
    { BGP_EXT_COM_VPN_ORIGIN,  "ospf-domain"},
    { BGP_EXT_COM_VPN_ORIGIN2, "ospf-domain"},
    { BGP_EXT_COM_VPN_ORIGIN3, "ospf-domain"},
    { BGP_EXT_COM_VPN_ORIGIN4, "ospf-domain"},
    { BGP_EXT_COM_OSPF_RTYPE,  "ospf-route-type"},
    { BGP_EXT_COM_OSPF_RTYPE2, "ospf-route-type"},
    { BGP_EXT_COM_OSPF_RID,    "ospf-router-id"},
    { BGP_EXT_COM_OSPF_RID2,   "ospf-router-id"},
    { BGP_EXT_COM_L2INFO,      "layer2-info"}, 
    { 0, NULL},
};

/* OSPF codes for  BGP_EXT_COM_OSPF_RTYPE draft-rosen-vpns-ospf-bgp-mpls  */
#define BGP_OSPF_RTYPE_RTR      1 /* OSPF Router LSA */
#define BGP_OSPF_RTYPE_NET      2 /* OSPF Network LSA */
#define BGP_OSPF_RTYPE_SUM      3 /* OSPF Summary LSA */
#define BGP_OSPF_RTYPE_EXT      5 /* OSPF External LSA, note that ASBR doesn't apply to MPLS-VPN */
#define BGP_OSPF_RTYPE_NSSA     7 /* OSPF NSSA External*/
#define BGP_OSPF_RTYPE_SHAM     129 /* OSPF-MPLS-VPN Sham link */
#define BGP_OSPF_RTYPE_METRIC_TYPE 0x1 /* LSB of RTYPE Options Field */

static struct tok bgp_extd_comm_ospf_rtype_values[] = {
  { BGP_OSPF_RTYPE_RTR, "Router" },  
  { BGP_OSPF_RTYPE_NET, "Network" },  
  { BGP_OSPF_RTYPE_SUM, "Summary" },  
  { BGP_OSPF_RTYPE_EXT, "External" },  
  { BGP_OSPF_RTYPE_NSSA,"NSSA External" },
  { BGP_OSPF_RTYPE_SHAM,"MPLS-VPN Sham" },  
  { 0, NULL },
};

int
decode_prefix4(const u_char *pptr, char *buf, u_int buflen)
{
   struct in_addr addr;
   u_int plen;

   TCHECK(pptr[0]);
   plen = pptr[0];
   if (32 < plen)
      return -1;

   memset(&addr, 0, sizeof(addr));
   TCHECK2(pptr[1], (plen + 7) / 8);
   memcpy(&addr, &pptr[1], (plen + 7) / 8);
   if (plen % 8) {
      ((u_char *)&addr)[(plen + 7) / 8 - 1] &=
         ((0xff00 >> (plen % 8)) & 0xff);
   }
   snprintf(buf, buflen, "%s/%d", ArgusGetName(ArgusParser, (u_char *)&addr), plen);
   return 1 + (plen + 7) / 8;

trunc:
   return -2;
}

static int
decode_labeled_prefix4(const u_char *pptr, char *buf, u_int buflen)
{
   struct in_addr addr;
   u_int plen;

   TCHECK(pptr[0]);
   plen = pptr[0];   /* get prefix length */

        /* this is one of the weirdnesses of rfc3107
           the label length (actually the label + COS bits)
           is added to the prefix length;
           we also do only read out just one label -
           there is no real application for advertisement of
           stacked labels in a a single BGP message
        */

        plen-=24; /* adjust prefixlen - labellength */

   if (32 < plen)
      return -1;

   memset(&addr, 0, sizeof(addr));
   TCHECK2(pptr[4], (plen + 7) / 8);
   memcpy(&addr, &pptr[4], (plen + 7) / 8);
   if (plen % 8) {
      ((u_char *)&addr)[(plen + 7) / 8 - 1] &=
         ((0xff00 >> (plen % 8)) & 0xff);
   }
        /* the label may get offsetted by 4 bits so lets shift it right */
   snprintf(buf, buflen, "%s/%d, label:%u %s",
                 ArgusGetName(ArgusParser, (u_char *)&addr),
                 plen,
                 EXTRACT_24BITS(pptr+1)>>4,
                 ((pptr[3]&1)==0) ? "(BOGUS: Bottom of Stack NOT set!)" : "(bottom)" );

   return 4 + (plen + 7) / 8;

trunc:
   return -2;
}

/* RDs and RTs share the same semantics
 * we use bgp_vpn_rd_print for
 * printing route targets inside a NLRI */
char *
bgp_vpn_rd_print (const u_char *pptr) {

   /* allocate space for the largest possible string */
    static char rd[sizeof("xxxxxxxxxx:xxxxx (xxx.xxx.xxx.xxx:xxxxx)")];
    char *pos = rd;

    /* ok lets load the RD format */
    switch (EXTRACT_16BITS(pptr)) {

        /* AS:IP-address fmt*/
    case 0:
        snprintf(pos, sizeof(rd) - (pos - rd), "%u:%u.%u.%u.%u",
            EXTRACT_16BITS(pptr+2), *(pptr+4), *(pptr+5), *(pptr+6), *(pptr+7));
        break;
        /* IP-address:AS fmt*/

    case 1:
        snprintf(pos, sizeof(rd) - (pos - rd), "%u.%u.%u.%u:%u",
            *(pptr+2), *(pptr+3), *(pptr+4), *(pptr+5), EXTRACT_16BITS(pptr+6));
        break;

        /* 4-byte-AS:number fmt*/
    case 2:
        snprintf(pos, sizeof(rd) - (pos - rd), "%u:%u (%u.%u.%u.%u:%u)",
            EXTRACT_32BITS(pptr+2), EXTRACT_16BITS(pptr+6),
            *(pptr+2), *(pptr+3), *(pptr+4), *(pptr+5), EXTRACT_16BITS(pptr+6));
        break;
    default:
        snprintf(pos, sizeof(rd) - (pos - rd), "unknown RD format");
        break;
    }
    pos += strlen(pos);
    *(pos) = '\0';
    return (rd);
}

static int
decode_rt_routing_info(const u_char *pptr, char *buf, u_int buflen)
{
   u_int8_t route_target[8];
   u_int plen;

   TCHECK(pptr[0]);
   plen = pptr[0];   /* get prefix length */

        plen-=32; /* adjust prefix length */

   if (0 < plen)
      return -1;

   memset(&route_target, 0, sizeof(route_target));
   TCHECK2(pptr[1], (plen + 7) / 8);
   memcpy(&route_target, &pptr[1], (plen + 7) / 8);
   if (plen % 8) {
      ((u_char *)&route_target)[(plen + 7) / 8 - 1] &=
         ((0xff00 >> (plen % 8)) & 0xff);
   }
   snprintf(buf, buflen, "origin AS: %u, route target %s",
                 EXTRACT_32BITS(pptr+1),
                 bgp_vpn_rd_print((u_char *)&route_target));

   return 5 + (plen + 7) / 8;

trunc:
   return -2;
}

static int
decode_labeled_vpn_prefix4(const u_char *pptr, char *buf, u_int buflen)
{
   struct in_addr addr;
   u_int plen;

   TCHECK(pptr[0]);
   plen = pptr[0];   /* get prefix length */

        plen-=(24+64); /* adjust prefixlen - labellength - RD len*/

   if (32 < plen)
      return -1;

   memset(&addr, 0, sizeof(addr));
   TCHECK2(pptr[12], (plen + 7) / 8);
   memcpy(&addr, &pptr[12], (plen + 7) / 8);
   if (plen % 8) {
      ((u_char *)&addr)[(plen + 7) / 8 - 1] &=
         ((0xff00 >> (plen % 8)) & 0xff);
   }
        /* the label may get offsetted by 4 bits so lets shift it right */
   snprintf(buf, buflen, "RD: %s, %s/%d, label:%u %s",
                 bgp_vpn_rd_print(pptr+4),
                 ArgusGetName(ArgusParser, (u_char *)&addr),
                 plen,
                 EXTRACT_24BITS(pptr+1)>>4,
                 ((pptr[3]&1)==0) ? "(BOGUS: Bottom of Stack NOT set!)" : "(bottom)" );

   return 12 + (plen + 7) / 8;

trunc:
   return -2;
}

static int
decode_labeled_vpn_l2(const u_char *pptr, char *buf, u_int buflen)
{
        int plen,tlen,strlen,tlv_type,tlv_len,ttlv_len;

   TCHECK2(pptr[0], 2);
        plen=EXTRACT_16BITS(pptr);
        tlen=plen;
        pptr+=2;
   TCHECK2(pptr[0],15);
        strlen=snprintf(buf, buflen, "RD: %s, CE-ID: %u, Label-Block Offset: %u, Label Base %u",
                        bgp_vpn_rd_print(pptr),
                        EXTRACT_16BITS(pptr+8),
                        EXTRACT_16BITS(pptr+10),
                        EXTRACT_24BITS(pptr+12)>>4); /* the label is offsetted by 4 bits so lets shift it right */
        pptr+=15;
        tlen-=15;

        /* ok now the variable part - lets read out TLVs*/
        while (tlen>0) {
            if (tlen < 3)
                return -1;
            TCHECK2(pptr[0], 3);
            tlv_type=*pptr++;
            tlv_len=EXTRACT_16BITS(pptr);
            ttlv_len=tlv_len;
            pptr+=2;

            switch(tlv_type) {
            case 1:
                strlen+=snprintf(buf+strlen,buflen-strlen, " circuit status vector (%u) length: %u: 0x",
                                 tlv_type,
                                 tlv_len);
                ttlv_len=ttlv_len/8+1; /* how many bytes do we need to read ? */
                while (ttlv_len>0) {
                    TCHECK(pptr[0]);
                    strlen+=snprintf(buf+strlen,buflen-strlen, "%02x",*pptr++);
                    ttlv_len--;
                }
                break;
            default:
                snprintf(buf+strlen,buflen-strlen, " unknown TLV #%u, length: %u",
                         tlv_type,
                         tlv_len);
                break;
            }
            tlen-=(tlv_len<<3); /* the tlv-length is expressed in bits so lets shift it tright */
        }
        return plen+2;

trunc:
        return -2;
}

#ifdef INET6
int
decode_prefix6(const u_char *pd, char *buf, u_int buflen)
{
   struct in6_addr addr;
   u_int plen;

   TCHECK(pd[0]);
   plen = pd[0];
   if (128 < plen)
      return -1;

   memset(&addr, 0, sizeof(addr));
   TCHECK2(pd[1], (plen + 7) / 8);
   memcpy(&addr, &pd[1], (plen + 7) / 8);
   if (plen % 8) {
      addr.s6_addr[(plen + 7) / 8 - 1] &=
         ((0xff00 >> (plen % 8)) & 0xff);
   }
   ssprintf(buf, buflen, "%s/%d", ArgusGetName(ArgusParser, (u_char *)&addr), plen);
   return 1 + (plen + 7) / 8;

trunc:
   return -2;
}

static int
decode_labeled_prefix6(const u_char *pptr, char *buf, u_int buflen)
{
   struct in6_addr addr;
   u_int plen;

   TCHECK(pptr[0]);
   plen = pptr[0]; /* get prefix length */
        plen-=24; /* adjust prefixlen - labellength */

   if (128 < plen)
      return -1;

   memset(&addr, 0, sizeof(addr));
   TCHECK2(pptr[4], (plen + 7) / 8);
   memcpy(&addr, &pptr[4], (plen + 7) / 8);
   if (plen % 8) {
      addr.s6_addr[(plen + 7) / 8 - 1] &=
         ((0xff00 >> (plen % 8)) & 0xff);
   }
        /* the label may get offsetted by 4 bits so lets shift it right */
   snprintf(buf, buflen, "%s/%d, label:%u %s",
                 ArgusGetName(ArgusParser, (u_char *)&addr),
                 plen,
                 EXTRACT_24BITS(pptr+1)>>4,
                 ((pptr[3]&1)==0) ? "(BOGUS: Bottom of Stack NOT set!)" : "(bottom)" );

   return 4 + (plen + 7) / 8;

trunc:
   return -2;
}

static int
decode_labeled_vpn_prefix6(const u_char *pptr, char *buf, u_int buflen)
{
   struct in6_addr addr;
   u_int plen;

   TCHECK(pptr[0]);
   plen = pptr[0];   /* get prefix length */

        plen-=(24+64); /* adjust prefixlen - labellength - RD len*/

   if (128 < plen)
      return -1;

   memset(&addr, 0, sizeof(addr));
   TCHECK2(pptr[12], (plen + 7) / 8);
   memcpy(&addr, &pptr[12], (plen + 7) / 8);
   if (plen % 8) {
      addr.s6_addr[(plen + 7) / 8 - 1] &=
         ((0xff00 >> (plen % 8)) & 0xff);
   }
        /* the label may get offsetted by 4 bits so lets shift it right */
   ssprintf(buf, buflen, "RD: %s, %s/%d, label:%u %s",
                 bgp_vpn_rd_print(pptr+4),
                 ArgusGetName(ArgusParser, (u_char *)&addr),
                 plen,
                 EXTRACT_24BITS(pptr+1)>>4,
                 ((pptr[3]&1)==0) ? "(BOGUS: Bottom of Stack NOT set!)" : "(bottom)" );

   return 12 + (plen + 7) / 8;

trunc:
   return -2;
}
#endif

static int
decode_clnp_prefix(const u_char *pptr, char *buf, u_int buflen)
{
        u_int8_t addr[19];
   u_int plen;

   TCHECK(pptr[0]);
   plen = pptr[0]; /* get prefix length */

   if (152 < plen)
      return -1;

   memset(&addr, 0, sizeof(addr));
   TCHECK2(pptr[4], (plen + 7) / 8);
   memcpy(&addr, &pptr[4], (plen + 7) / 8);
   if (plen % 8) {
      addr[(plen + 7) / 8 - 1] &=
         ((0xff00 >> (plen % 8)) & 0xff);
   }
   snprintf(buf, buflen, "%s/%d", isonsap_string(addr,(plen + 7) / 8), plen);

   return 1 + (plen + 7) / 8;

trunc:
   return -2;
}

static int
decode_labeled_vpn_clnp_prefix(const u_char *pptr, char *buf, u_int buflen)
{
        u_int8_t addr[19];
   u_int plen;

   TCHECK(pptr[0]);
   plen = pptr[0];   /* get prefix length */

        plen-=(24+64); /* adjust prefixlen - labellength - RD len*/

   if (152 < plen)
      return -1;

   memset(&addr, 0, sizeof(addr));
   TCHECK2(pptr[12], (plen + 7) / 8);
   memcpy(&addr, &pptr[12], (plen + 7) / 8);
   if (plen % 8) {
      addr[(plen + 7) / 8 - 1] &=
         ((0xff00 >> (plen % 8)) & 0xff);
   }
        /* the label may get offsetted by 4 bits so lets shift it right */
   snprintf(buf, buflen, "RD: %s, %s/%d, label:%u %s",
                 bgp_vpn_rd_print(pptr+4),
                 isonsap_string(addr,(plen + 7) / 8),
                 plen,
                 EXTRACT_24BITS(pptr+1)>>4,
                 ((pptr[3]&1)==0) ? "(BOGUS: Bottom of Stack NOT set!)" : "(bottom)" );

   return 12 + (plen + 7) / 8;

trunc:
   return -2;
}

static int
bgp_attr_print(const struct bgp_attr *attr, const u_char *pptr, int len)
{
   int i;
   u_int16_t af;
   u_int8_t safi, snpa, nhlen;
        union { /* copy buffer for bandwidth values */
            float f; 
            u_int32_t i;
        } bw;
   int advance;
   int tlen;
   const u_char *tptr;
   char buf[MAXHOSTNAMELEN + 100];
   char tokbuf[TOKBUFSIZE];

        tptr = pptr;
        tlen=len;

   switch (attr->bgpa_type) {
   case BGPTYPE_ORIGIN:
      if (len != 1)
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
      else {
         TCHECK(*tptr);
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", tok2strbuf(bgp_origin_values,
                  "Unknown Origin Typecode",
                  tptr[0],
                  tokbuf, sizeof(tokbuf)));
      }
      break;

   case BGPTYPE_AS_PATH:
      if (len % 2) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
         break;
      }
                if (!len) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"empty");
         break;
                }

      while (tptr < pptr + len) {
         TCHECK(tptr[0]);
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", tok2strbuf(bgp_as_path_segment_open_values,
                  "?", tptr[0],
                  tokbuf, sizeof(tokbuf)));
                        for (i = 0; i < tptr[1] * 2; i += 2) {
                            TCHECK2(tptr[2 + i], 2);
                            sprintf(&ArgusBuf[strlen(ArgusBuf)],"%u ", EXTRACT_16BITS(&tptr[2 + i]));
                        }
         TCHECK(tptr[0]);
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", tok2strbuf(bgp_as_path_segment_close_values,
                  "?", tptr[0],
                  tokbuf, sizeof(tokbuf)));
                        TCHECK(tptr[1]);
                        tptr += 2 + tptr[1] * 2;
      }
      break;
   case BGPTYPE_NEXT_HOP:
      if (len != 4)
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
      else {
         TCHECK2(tptr[0], 4);
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", ArgusGetName(ArgusParser, (u_char *)tptr));
      }
      break;
   case BGPTYPE_MULTI_EXIT_DISC:
   case BGPTYPE_LOCAL_PREF:
      if (len != 4)
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
      else {
         TCHECK2(tptr[0], 4);
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"%u", EXTRACT_32BITS(tptr));
      }
      break;
   case BGPTYPE_ATOMIC_AGGREGATE:
      if (len != 0)
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
      break;
   case BGPTYPE_AGGREGATOR:
      if (len != 6) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
         break;
      }
      TCHECK2(tptr[0], 6);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," AS #%u, origin %s", EXTRACT_16BITS(tptr),
         ArgusGetName(ArgusParser, (u_char *)tptr + 2));
      break;
   case BGPTYPE_COMMUNITIES:
      if (len % 4) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
         break;
      }
      while (tlen>0) {
         u_int32_t comm;
         TCHECK2(tptr[0], 4);
         comm = EXTRACT_32BITS(tptr);
         switch (comm) {
         case BGP_COMMUNITY_NO_EXPORT:
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," NO_EXPORT");
            break;
         case BGP_COMMUNITY_NO_ADVERT:
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," NO_ADVERTISE");
            break;
         case BGP_COMMUNITY_NO_EXPORT_SUBCONFED:
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," NO_EXPORT_SUBCONFED");
            break;
         default:
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"%u:%u%s",
                                       (comm >> 16) & 0xffff,
                                       comm & 0xffff,
                                       (tlen>4) ? ", " : "");
            break;
         }
                        tlen -=4;
                        tptr +=4;
      }
      break;
        case BGPTYPE_ORIGINATOR_ID:
      if (len != 4) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
         break;
      }
      TCHECK2(tptr[0], 4);
                sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s",ArgusGetName(ArgusParser, (u_char *)tptr));
                break;
        case BGPTYPE_CLUSTER_LIST:
      if (len % 4) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
         break;
      }
                while (tlen>0) {
         TCHECK2(tptr[0], 4);
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s%s",
                               ArgusGetName(ArgusParser, (u_char *)tptr),
                                (tlen>4) ? ", " : "");
                        tlen -=4;
                        tptr +=4;
                }
                break;
   case BGPTYPE_MP_REACH_NLRI:
      TCHECK2(tptr[0], 3);
      af = EXTRACT_16BITS(tptr);
      safi = tptr[2];
   
                sprintf(&ArgusBuf[strlen(ArgusBuf)]," AFI: %s (%u), %sSAFI: %s (%u)",
                       tok2strbuf(bgp_afi_values, "Unknown AFI", af,
              tokbuf, sizeof(tokbuf)),
                       af,
                       (safi>128) ? "vendor specific " : "", /* 128 is meanwhile wellknown */
                       tok2strbuf(bgp_safi_values, "Unknown SAFI", safi,
              tokbuf, sizeof(tokbuf)),
                       safi);

                switch(af<<8 | safi) {
                case (AFNUM_INET<<8 | SAFNUM_UNICAST):
                case (AFNUM_INET<<8 | SAFNUM_MULTICAST):
                case (AFNUM_INET<<8 | SAFNUM_UNIMULTICAST):
                case (AFNUM_INET<<8 | SAFNUM_LABUNICAST):
                case (AFNUM_INET<<8 | SAFNUM_RT_ROUTING_INFO):
                case (AFNUM_INET<<8 | SAFNUM_VPNUNICAST):
                case (AFNUM_INET<<8 | SAFNUM_VPNMULTICAST):
                case (AFNUM_INET<<8 | SAFNUM_VPNUNIMULTICAST):
#ifdef INET6
                case (AFNUM_INET6<<8 | SAFNUM_UNICAST):
                case (AFNUM_INET6<<8 | SAFNUM_MULTICAST):
                case (AFNUM_INET6<<8 | SAFNUM_UNIMULTICAST):
                case (AFNUM_INET6<<8 | SAFNUM_LABUNICAST):
                case (AFNUM_INET6<<8 | SAFNUM_RT_ROUTING_INFO):
                case (AFNUM_INET6<<8 | SAFNUM_VPNUNICAST):
                case (AFNUM_INET6<<8 | SAFNUM_VPNMULTICAST):
                case (AFNUM_INET6<<8 | SAFNUM_VPNUNIMULTICAST):
#endif
                case (AFNUM_NSAP<<8 | SAFNUM_UNICAST):
                case (AFNUM_NSAP<<8 | SAFNUM_MULTICAST):
                case (AFNUM_NSAP<<8 | SAFNUM_UNIMULTICAST):
                case (AFNUM_NSAP<<8 | SAFNUM_VPNUNICAST):
                case (AFNUM_NSAP<<8 | SAFNUM_VPNMULTICAST):
                case (AFNUM_NSAP<<8 | SAFNUM_VPNUNIMULTICAST):
                case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNICAST):
                case (AFNUM_L2VPN<<8 | SAFNUM_VPNMULTICAST):
                case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNIMULTICAST):
                    break;
                default:
                    TCHECK2(tptr[0], tlen);
                    sprintf(&ArgusBuf[strlen(ArgusBuf)]," no AFI %u / SAFI %u decoder",af,safi);
                    if (ArgusParser->vflag <= 1)
                        print_unknown_data(tptr," ",tlen);
                    goto done;
                    break;
                }

                tptr +=3;

      TCHECK(tptr[0]);
      nhlen = tptr[0];
                tlen = nhlen;
                tptr++;

      if (tlen) {
                    sprintf(&ArgusBuf[strlen(ArgusBuf)]," nexthop: ");
                    while (tlen > 0) {
                        switch(af<<8 | safi) {
                        case (AFNUM_INET<<8 | SAFNUM_UNICAST):
                        case (AFNUM_INET<<8 | SAFNUM_MULTICAST):
                        case (AFNUM_INET<<8 | SAFNUM_UNIMULTICAST):
                        case (AFNUM_INET<<8 | SAFNUM_LABUNICAST):
                        case (AFNUM_INET<<8 | SAFNUM_RT_ROUTING_INFO):
                            if (tlen < (int)sizeof(struct in_addr)) {
                                sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
                                tlen = 0;
                            } else {
                                TCHECK2(tptr[0], sizeof(struct in_addr));
                                sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s",ArgusGetName(ArgusParser, (u_char *)tptr));
                                tlen -= sizeof(struct in_addr);
                                tptr += sizeof(struct in_addr);
                            }
                            break;
                        case (AFNUM_INET<<8 | SAFNUM_VPNUNICAST):
                        case (AFNUM_INET<<8 | SAFNUM_VPNMULTICAST):
                        case (AFNUM_INET<<8 | SAFNUM_VPNUNIMULTICAST):
                            if (tlen < (int)(sizeof(struct in_addr)+BGP_VPN_RD_LEN)) {
                                sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
                                tlen = 0;
                            } else {
                                TCHECK2(tptr[0], sizeof(struct in_addr)+BGP_VPN_RD_LEN);
                                sprintf(&ArgusBuf[strlen(ArgusBuf)],"RD: %s, %s",
                                       bgp_vpn_rd_print(tptr),
                                       ArgusGetName(ArgusParser, (u_char *)tptr+BGP_VPN_RD_LEN));
                                tlen -= (sizeof(struct in_addr)+BGP_VPN_RD_LEN);
                                tptr += (sizeof(struct in_addr)+BGP_VPN_RD_LEN);
                            }
                            break;
#ifdef INET6
                        case (AFNUM_INET6<<8 | SAFNUM_UNICAST):
                        case (AFNUM_INET6<<8 | SAFNUM_MULTICAST):
                        case (AFNUM_INET6<<8 | SAFNUM_UNIMULTICAST):
                        case (AFNUM_INET6<<8 | SAFNUM_LABUNICAST):
                        case (AFNUM_INET6<<8 | SAFNUM_RT_ROUTING_INFO):
                            if (tlen < (int)sizeof(struct in6_addr)) {
                                sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
                                tlen = 0;
                            } else {
                                TCHECK2(tptr[0], sizeof(struct in6_addr));
                                sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", ArgusGetName(ArgusParser, (u_char *)tptr));
                                tlen -= sizeof(struct in6_addr);
                                tptr += sizeof(struct in6_addr);
                            }
                            break;
                        case (AFNUM_INET6<<8 | SAFNUM_VPNUNICAST):
                        case (AFNUM_INET6<<8 | SAFNUM_VPNMULTICAST):
                        case (AFNUM_INET6<<8 | SAFNUM_VPNUNIMULTICAST):
                            if (tlen < (int)(sizeof(struct in6_addr)+BGP_VPN_RD_LEN)) {
                                sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
                                tlen = 0;
                            } else {
                                TCHECK2(tptr[0], sizeof(struct in6_addr)+BGP_VPN_RD_LEN);
                                sprintf(&ArgusBuf[strlen(ArgusBuf)],"RD: %s, %s",
                                       bgp_vpn_rd_print(tptr),
                                       ArgusGetName(ArgusParser, (u_char *)tptr+BGP_VPN_RD_LEN));
                                tlen -= (sizeof(struct in6_addr)+BGP_VPN_RD_LEN);
                                tptr += (sizeof(struct in6_addr)+BGP_VPN_RD_LEN);
                            }
                            break;
#endif
                        case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNICAST):
                        case (AFNUM_L2VPN<<8 | SAFNUM_VPNMULTICAST):
                        case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNIMULTICAST):
                            if (tlen < (int)sizeof(struct in_addr)) {
                                sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
                                tlen = 0;
                            } else {
                                TCHECK2(tptr[0], sizeof(struct in_addr));
                                sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", ArgusGetName(ArgusParser, (u_char *)tptr));
                                tlen -= (sizeof(struct in_addr));
                                tptr += (sizeof(struct in_addr));
                            }
                            break;
                        case (AFNUM_NSAP<<8 | SAFNUM_UNICAST):
                        case (AFNUM_NSAP<<8 | SAFNUM_MULTICAST):
                        case (AFNUM_NSAP<<8 | SAFNUM_UNIMULTICAST):
                            TCHECK2(tptr[0], tlen);
                            sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s",isonsap_string(tptr,tlen));
                            tptr += tlen;
                            tlen = 0;
                            break;

                        case (AFNUM_NSAP<<8 | SAFNUM_VPNUNICAST):
                        case (AFNUM_NSAP<<8 | SAFNUM_VPNMULTICAST):
                        case (AFNUM_NSAP<<8 | SAFNUM_VPNUNIMULTICAST):
                            if (tlen < BGP_VPN_RD_LEN+1) {
                                sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
                                tlen = 0;
                            } else {
                                TCHECK2(tptr[0], tlen);
                                sprintf(&ArgusBuf[strlen(ArgusBuf)],"RD: %s, %s",
                                       bgp_vpn_rd_print(tptr),
                                       isonsap_string(tptr+BGP_VPN_RD_LEN,tlen-BGP_VPN_RD_LEN));
                                /* rfc986 mapped IPv4 address ? */
                                if (EXTRACT_32BITS(tptr+BGP_VPN_RD_LEN) ==  0x47000601)
                                    sprintf(&ArgusBuf[strlen(ArgusBuf)]," = %s", ArgusGetName(ArgusParser, (u_char *)tptr+BGP_VPN_RD_LEN+4));
#ifdef INET6
                                /* rfc1888 mapped IPv6 address ? */
                                else if (EXTRACT_24BITS(tptr+BGP_VPN_RD_LEN) ==  0x350000)
                                    sprintf(&ArgusBuf[strlen(ArgusBuf)]," = %s", ArgusGetName(ArgusParser, (u_char *)tptr+BGP_VPN_RD_LEN+3));
#endif
                                tptr += tlen;
                                tlen = 0;
                            }
                            break;
                        default:
                            TCHECK2(tptr[0], tlen);
                            sprintf(&ArgusBuf[strlen(ArgusBuf)],"no AFI %u/SAFI %u decoder",af,safi);
                            if (ArgusParser->vflag <= 1)
                                print_unknown_data(tptr," ",tlen);
                            tptr += tlen;
                            tlen = 0;
                            goto done;
                            break;
                        }
                    }
      }
                sprintf(&ArgusBuf[strlen(ArgusBuf)],", nh-length: %u", nhlen);
      tptr += tlen;

      TCHECK(tptr[0]);
      snpa = tptr[0];
      tptr++;

      if (snpa) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u SNPA", snpa);
         for (/*nothing*/; snpa > 0; snpa--) {
            TCHECK(tptr[0]);
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %d bytes", tptr[0]);
            tptr += tptr[0] + 1;
         }
      } else {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],", no SNPA");
                }

      while (len - (tptr - pptr) > 0) {
                    switch (af<<8 | safi) {
                    case (AFNUM_INET<<8 | SAFNUM_UNICAST):
                    case (AFNUM_INET<<8 | SAFNUM_MULTICAST):
                    case (AFNUM_INET<<8 | SAFNUM_UNIMULTICAST):
                        advance = decode_prefix4(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
                    case (AFNUM_INET<<8 | SAFNUM_LABUNICAST):
                        advance = decode_labeled_prefix4(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
                    case (AFNUM_INET<<8 | SAFNUM_VPNUNICAST):
                    case (AFNUM_INET<<8 | SAFNUM_VPNMULTICAST):
                    case (AFNUM_INET<<8 | SAFNUM_VPNUNIMULTICAST):
                        advance = decode_labeled_vpn_prefix4(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
                    case (AFNUM_INET<<8 | SAFNUM_RT_ROUTING_INFO):
                        advance = decode_rt_routing_info(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
#ifdef INET6
                    case (AFNUM_INET6<<8 | SAFNUM_UNICAST):
                    case (AFNUM_INET6<<8 | SAFNUM_MULTICAST):
                    case (AFNUM_INET6<<8 | SAFNUM_UNIMULTICAST):
                        advance = decode_prefix6(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
                    case (AFNUM_INET6<<8 | SAFNUM_LABUNICAST):
                        advance = decode_labeled_prefix6(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
                    case (AFNUM_INET6<<8 | SAFNUM_VPNUNICAST):
                    case (AFNUM_INET6<<8 | SAFNUM_VPNMULTICAST):
                    case (AFNUM_INET6<<8 | SAFNUM_VPNUNIMULTICAST):
                        advance = decode_labeled_vpn_prefix6(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
                    case (AFNUM_INET6<<8 | SAFNUM_RT_ROUTING_INFO):
                        advance = decode_rt_routing_info(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
#endif
                    case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNICAST):
                    case (AFNUM_L2VPN<<8 | SAFNUM_VPNMULTICAST):
                    case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNIMULTICAST):
                        advance = decode_labeled_vpn_l2(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);         
                        break;
                    case (AFNUM_NSAP<<8 | SAFNUM_UNICAST):
                    case (AFNUM_NSAP<<8 | SAFNUM_MULTICAST):
                    case (AFNUM_NSAP<<8 | SAFNUM_UNIMULTICAST):
                        advance = decode_clnp_prefix(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
                    case (AFNUM_NSAP<<8 | SAFNUM_VPNUNICAST):
                    case (AFNUM_NSAP<<8 | SAFNUM_VPNMULTICAST):
                    case (AFNUM_NSAP<<8 | SAFNUM_VPNUNIMULTICAST):
                        advance = decode_labeled_vpn_clnp_prefix(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;                                   
                    default:
                        TCHECK2(*tptr,tlen);
                        sprintf(&ArgusBuf[strlen(ArgusBuf)]," no AFI %u / SAFI %u decoder",af,safi);
                        if (ArgusParser->vflag <= 1)
                            print_unknown_data(tptr," ",tlen);
                        advance = 0;
                        tptr = pptr + len;
                        break;
                    }
                    if (advance < 0)
                        break;
                    tptr += advance;
      }
        done:
      break;

   case BGPTYPE_MP_UNREACH_NLRI:
      TCHECK2(tptr[0], BGP_MP_NLRI_MINSIZE);
      af = EXTRACT_16BITS(tptr);
      safi = tptr[2];

                sprintf(&ArgusBuf[strlen(ArgusBuf)]," AFI: %s (%u), %sSAFI: %s (%u)",
                       tok2strbuf(bgp_afi_values, "Unknown AFI", af,
              tokbuf, sizeof(tokbuf)),
                       af,
                       (safi>128) ? "vendor specific " : "", /* 128 is meanwhile wellknown */
                       tok2strbuf(bgp_safi_values, "Unknown SAFI", safi,
              tokbuf, sizeof(tokbuf)),
                       safi);

                if (len == BGP_MP_NLRI_MINSIZE)
                    sprintf(&ArgusBuf[strlen(ArgusBuf)]," End-of-Rib Marker (empty NLRI)");

      tptr += 3;
                
      while (len - (tptr - pptr) > 0) {
                    switch (af<<8 | safi) {
                    case (AFNUM_INET<<8 | SAFNUM_UNICAST):
                    case (AFNUM_INET<<8 | SAFNUM_MULTICAST):
                    case (AFNUM_INET<<8 | SAFNUM_UNIMULTICAST):
                        advance = decode_prefix4(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
                    case (AFNUM_INET<<8 | SAFNUM_LABUNICAST):
                        advance = decode_labeled_prefix4(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
                    case (AFNUM_INET<<8 | SAFNUM_VPNUNICAST):
                    case (AFNUM_INET<<8 | SAFNUM_VPNMULTICAST):
                    case (AFNUM_INET<<8 | SAFNUM_VPNUNIMULTICAST):
                        advance = decode_labeled_vpn_prefix4(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
#ifdef INET6
                    case (AFNUM_INET6<<8 | SAFNUM_UNICAST):
                    case (AFNUM_INET6<<8 | SAFNUM_MULTICAST):
                    case (AFNUM_INET6<<8 | SAFNUM_UNIMULTICAST):
                        advance = decode_prefix6(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
                    case (AFNUM_INET6<<8 | SAFNUM_LABUNICAST):
                        advance = decode_labeled_prefix6(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
                    case (AFNUM_INET6<<8 | SAFNUM_VPNUNICAST):
                    case (AFNUM_INET6<<8 | SAFNUM_VPNMULTICAST):
                    case (AFNUM_INET6<<8 | SAFNUM_VPNUNIMULTICAST):
                        advance = decode_labeled_vpn_prefix6(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
#endif
                    case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNICAST):
                    case (AFNUM_L2VPN<<8 | SAFNUM_VPNMULTICAST):
                    case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNIMULTICAST):
                        advance = decode_labeled_vpn_l2(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);         
                        break;
                    case (AFNUM_NSAP<<8 | SAFNUM_UNICAST):
                    case (AFNUM_NSAP<<8 | SAFNUM_MULTICAST):
                    case (AFNUM_NSAP<<8 | SAFNUM_UNIMULTICAST):
                        advance = decode_clnp_prefix(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;
                    case (AFNUM_NSAP<<8 | SAFNUM_VPNUNICAST):
                    case (AFNUM_NSAP<<8 | SAFNUM_VPNMULTICAST):
                    case (AFNUM_NSAP<<8 | SAFNUM_VPNUNIMULTICAST):
                        advance = decode_labeled_vpn_clnp_prefix(tptr, buf, sizeof(buf));
                        if (advance == -1)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
                        else if (advance == -2)
                            goto trunc;
                        else
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
                        break;                                   
                    default:
                        TCHECK2(*(tptr-3),tlen);
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],"no AFI %u / SAFI %u decoder",af,safi);
                        if (ArgusParser->vflag <= 1)
                            print_unknown_data(tptr-3," ",tlen);                                        
                        advance = 0;
                        tptr = pptr + len;
                        break;
                    }
                    if (advance < 0)
                        break;
                    tptr += advance;
      }
      break;
        case BGPTYPE_EXTD_COMMUNITIES:
      if (len % 8) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"invalid len");
         break;
      }
                while (tlen>0) {
                    u_int16_t extd_comm;

                    TCHECK2(tptr[0], 2);
                    extd_comm=EXTRACT_16BITS(tptr);

          sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s (0x%04x), Flags [%s]",
            tok2strbuf(bgp_extd_comm_subtype_values,
                  "unknown extd community typecode",
                  extd_comm, tokbuf, sizeof(tokbuf)),
            extd_comm,
            bittok2str(bgp_extd_comm_flag_values, "none", extd_comm));

                    TCHECK2(*(tptr+2), 6);
                    switch(extd_comm) {
                    case BGP_EXT_COM_RT_0:
                    case BGP_EXT_COM_RO_0:
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],": %u:%s",
                               EXTRACT_16BITS(tptr+2),
                               ArgusGetName(ArgusParser, (u_char *)tptr+4));
                        break;
                    case BGP_EXT_COM_RT_1:
                    case BGP_EXT_COM_RO_1:
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],": %s:%u",
                               ArgusGetName(ArgusParser, (u_char *)tptr+2),
                               EXTRACT_16BITS(tptr+6));
                        break;
                    case BGP_EXT_COM_RT_2:
                    case BGP_EXT_COM_RO_2:
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],": %u:%u",
                               EXTRACT_32BITS(tptr+2),
                               EXTRACT_16BITS(tptr+6));
                        break;
                    case BGP_EXT_COM_LINKBAND:
              bw.i = EXTRACT_32BITS(tptr+2);
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],": bandwidth: %.3f Mbps",
                               bw.f*8/1000000);
                        break;
                    case BGP_EXT_COM_CISCO_MCAST:
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],": AS %u, group %s",
                               EXTRACT_16BITS(tptr+2),
                               ArgusGetName(ArgusParser, (u_char *)tptr+4));
                        break;
                    case BGP_EXT_COM_VPN_ORIGIN:
                    case BGP_EXT_COM_VPN_ORIGIN2:
                    case BGP_EXT_COM_VPN_ORIGIN3:
                    case BGP_EXT_COM_VPN_ORIGIN4:
                    case BGP_EXT_COM_OSPF_RID:
                    case BGP_EXT_COM_OSPF_RID2:
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", ArgusGetName(ArgusParser, (u_char *)tptr+2));
                        break;
                    case BGP_EXT_COM_OSPF_RTYPE:
                    case BGP_EXT_COM_OSPF_RTYPE2: 
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],": area:%s, router-type:%s, metric-type:%s%s",
                               ArgusGetName(ArgusParser, (u_char *)tptr+2),
                               tok2strbuf(bgp_extd_comm_ospf_rtype_values,
                 "unknown (0x%02x)",
                 *(tptr+6),
                 tokbuf, sizeof(tokbuf)),
                               (*(tptr+7) &  BGP_OSPF_RTYPE_METRIC_TYPE) ? "E2" : "",
                               (*(tptr+6) == (BGP_OSPF_RTYPE_EXT ||BGP_OSPF_RTYPE_NSSA )) ? "E1" : "");
                        break;
                    case BGP_EXT_COM_L2INFO:
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],": %s Control Flags [0x%02x]:MTU %u",
                               tok2strbuf(l2vpn_encaps_values,
                 "unknown encaps",
                 *(tptr+2),
                 tokbuf, sizeof(tokbuf)),
                                       *(tptr+3),
                               EXTRACT_16BITS(tptr+4));
                        break;
                    default:
                        TCHECK2(*tptr,8);
                        print_unknown_data(tptr," ",8);
                        break;
                    }
                    tlen -=8;
                    tptr +=8;
                }
                break;

        case BGPTYPE_ATTR_SET:
                TCHECK2(tptr[0], 4);
                sprintf(&ArgusBuf[strlen(ArgusBuf)]," Origin AS: %u", EXTRACT_32BITS(tptr));
                tptr+=4;
                len -=4;

                while (len >= 2 ) {
                    int alen;
                    struct bgp_attr bgpa;
                    
                    TCHECK2(tptr[0], sizeof(bgpa));
                    memcpy(&bgpa, tptr, sizeof(bgpa));
                    alen = bgp_attr_len(&bgpa);
                    tptr += bgp_attr_off(&bgpa);
                    len -= bgp_attr_off(&bgpa);
                    
                    sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s (%u), length: %u",
                           tok2strbuf(bgp_attr_values,
                  "Unknown Attribute", bgpa.bgpa_type,
                  tokbuf, sizeof(tokbuf)),
                           bgpa.bgpa_type,
                           alen);
                    
                    if (bgpa.bgpa_flags) {
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],", Flags [%s%s%s%s",
                               bgpa.bgpa_flags & 0x80 ? "O" : "",
                               bgpa.bgpa_flags & 0x40 ? "T" : "",
                               bgpa.bgpa_flags & 0x20 ? "P" : "",
                               bgpa.bgpa_flags & 0x10 ? "E" : "");
                        if (bgpa.bgpa_flags & 0xf)
                            sprintf(&ArgusBuf[strlen(ArgusBuf)],"+%x", bgpa.bgpa_flags & 0xf);
                        sprintf(&ArgusBuf[strlen(ArgusBuf)],"]: ");
                    }
                    /* FIXME check for recursion */
                    if (!bgp_attr_print(&bgpa, tptr, alen))
                        return 0;
                    tptr += alen;
                    len -= alen;
      }
                break;
           

   default:
       TCHECK2(*pptr,len);
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," no Attribute %u decoder",attr->bgpa_type); /* we have no decoder for the attribute */
            if (ArgusParser->vflag <= 1)
                print_unknown_data(pptr," ",len);
            break;
   }
        if (ArgusParser->vflag > 1 && len) { /* omit zero length attributes*/
            TCHECK2(*pptr,len);
            print_unknown_data(pptr," ",len);
        }
        return 1;

trunc:
        return 0;
}

static void
bgp_open_print(const u_char *dat, int length)
{
   struct bgp_open bgpo;
   struct bgp_opt bgpopt;
   const u_char *opt;
   int i,cap_type,cap_len,tcap_len,cap_offset;
   char tokbuf[TOKBUFSIZE];
   char tokbuf2[TOKBUFSIZE];

   TCHECK2(dat[0], BGP_OPEN_SIZE);
   memcpy(&bgpo, dat, BGP_OPEN_SIZE);

   sprintf(&ArgusBuf[strlen(ArgusBuf)]," Version %d, ", bgpo.bgpo_version);
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"my AS %u, ", ntohs(bgpo.bgpo_myas));
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"Holdtime %us, ", ntohs(bgpo.bgpo_holdtime));
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"ID %s", ArgusGetName(ArgusParser, (u_char *)&bgpo.bgpo_id));
   sprintf(&ArgusBuf[strlen(ArgusBuf)]," Optional parameters, length: %u", bgpo.bgpo_optlen);

        /* some little sanity checking */
        if (length < bgpo.bgpo_optlen+BGP_OPEN_SIZE) 
            return;

   /* ugly! */
   opt = &((const struct bgp_open *)dat)->bgpo_optlen;
   opt++;

   i = 0;
   while (i < bgpo.bgpo_optlen) {
      TCHECK2(opt[i], BGP_OPT_SIZE);
      memcpy(&bgpopt, &opt[i], BGP_OPT_SIZE);
      if (i + 2 + bgpopt.bgpopt_len > bgpo.bgpo_optlen) {
                        sprintf(&ArgusBuf[strlen(ArgusBuf)]," Option %d, length: %u", bgpopt.bgpopt_type, bgpopt.bgpopt_len);
         break;
      }

      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Option %s (%u), length: %u",
                       tok2strbuf(bgp_opt_values,"Unknown",
              bgpopt.bgpopt_type,
              tokbuf, sizeof(tokbuf)),
                       bgpopt.bgpopt_type,
                       bgpopt.bgpopt_len);

                /* now lets decode the options we know*/
                switch(bgpopt.bgpopt_type) {
                case BGP_OPT_CAP:
                    cap_type=opt[i+BGP_OPT_SIZE];
                    cap_len=opt[i+BGP_OPT_SIZE+1];
                    tcap_len=cap_len;
                    sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s (%u), length: %u",
                           tok2strbuf(bgp_capcode_values, "Unknown",
                  cap_type, tokbuf, sizeof(tokbuf)),
                           cap_type,
                           cap_len);
                    switch(cap_type) {
                    case BGP_CAPCODE_MP:
                        sprintf(&ArgusBuf[strlen(ArgusBuf)]," AFI %s (%u), SAFI %s (%u)",
                               tok2strbuf(bgp_afi_values, "Unknown",
                 EXTRACT_16BITS(opt+i+BGP_OPT_SIZE+2),
                 tokbuf, sizeof(tokbuf)),
                               EXTRACT_16BITS(opt+i+BGP_OPT_SIZE+2),
                               tok2strbuf(bgp_safi_values, "Unknown",
                 opt[i+BGP_OPT_SIZE+5],
                 tokbuf, sizeof(tokbuf)),
                               opt[i+BGP_OPT_SIZE+5]);
                        break;
                    case BGP_CAPCODE_RESTART:
                        sprintf(&ArgusBuf[strlen(ArgusBuf)]," Restart Flags: [%s], Restart Time %us",
                               ((opt[i+BGP_OPT_SIZE+2])&0x80) ? "R" : "none",
                               EXTRACT_16BITS(opt+i+BGP_OPT_SIZE+2)&0xfff);
                        tcap_len-=2;
                        cap_offset=4;
                        while(tcap_len>=4) {
                            sprintf(&ArgusBuf[strlen(ArgusBuf)]," AFI %s (%u), SAFI %s (%u), Forwarding state preserved: %s",
                                   tok2strbuf(bgp_afi_values,"Unknown",
                     EXTRACT_16BITS(opt+i+BGP_OPT_SIZE+cap_offset),
                     tokbuf, sizeof(tokbuf)),
                                   EXTRACT_16BITS(opt+i+BGP_OPT_SIZE+cap_offset),
                                   tok2strbuf(bgp_safi_values,"Unknown",
                     opt[i+BGP_OPT_SIZE+cap_offset+2],
                     tokbuf2, sizeof(tokbuf2)),
                                   opt[i+BGP_OPT_SIZE+cap_offset+2],
                                   ((opt[i+BGP_OPT_SIZE+cap_offset+3])&0x80) ? "yes" : "no" );
                            tcap_len-=4;
                            cap_offset+=4;
                        }
                        break;
                    case BGP_CAPCODE_RR:
                    case BGP_CAPCODE_RR_CISCO:
                        break;
                    default:
                        TCHECK2(opt[i+BGP_OPT_SIZE+2],cap_len);
                        sprintf(&ArgusBuf[strlen(ArgusBuf)]," no decoder for Capability %u",
                               cap_type);
                        if (ArgusParser->vflag <= 1)
                            print_unknown_data(&opt[i+BGP_OPT_SIZE+2]," ",cap_len);
                        break;
                    }
                    if (ArgusParser->vflag > 1) {
                        TCHECK2(opt[i+BGP_OPT_SIZE+2],cap_len);
                        print_unknown_data(&opt[i+BGP_OPT_SIZE+2]," ",cap_len);
                    }
                    break;
                case BGP_OPT_AUTH:
                default:
                       sprintf(&ArgusBuf[strlen(ArgusBuf)]," no decoder for option %u",
                           bgpopt.bgpopt_type);
                       break;
                }

      i += BGP_OPT_SIZE + bgpopt.bgpopt_len;
   }
   return;
trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|BGP]");
}

static void
bgp_update_print(const u_char *dat, int length)
{
   struct bgp bgp;
   struct bgp_attr bgpa;
   const u_char *p;
   int len;
   int i;
   char tokbuf[TOKBUFSIZE];

   TCHECK2(dat[0], BGP_SIZE);
   memcpy(&bgp, dat, BGP_SIZE);
   p = dat + BGP_SIZE;   /*XXX*/

   /* Unfeasible routes */
   len = EXTRACT_16BITS(p);
   if (len) {
      /*
       * Without keeping state from the original NLRI message,
       * it's not possible to tell if this a v4 or v6 route,
       * so only try to decode it if we're not v6 enabled.
            */
#ifdef INET6
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Withdrawn routes: %d bytes", len);
#else
      char buf[MAXHOSTNAMELEN + 100];
      int wpfx;

      TCHECK2(p[2], len);
      i = 2;

      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Withdrawn routes:");

      while(i < 2 + len) {
         wpfx = decode_prefix4(&p[i], buf, sizeof(buf));
         if (wpfx == -1) {
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
            break;
         } else if (wpfx == -2)
            goto trunc;
         else {
            i += wpfx;
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
         }
      }
#endif
   }
   p += 2 + len;

   TCHECK2(p[0], 2);
   len = EXTRACT_16BITS(p);

        if (len == 0 && length == BGP_UPDATE_MINSIZE) {
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," End-of-Rib Marker (empty NLRI)");
            return;
        }

   if (len) {
      /* do something more useful!*/
      i = 2;
      while (i < 2 + len) {
         int alen, aoff;

         TCHECK2(p[i], sizeof(bgpa));
         memcpy(&bgpa, &p[i], sizeof(bgpa));
         alen = bgp_attr_len(&bgpa);
         aoff = bgp_attr_off(&bgpa);

             sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s (%u), length: %u",
                              tok2strbuf(bgp_attr_values, "Unknown Attribute",
                bgpa.bgpa_type,
                tokbuf, sizeof(tokbuf)),
                              bgpa.bgpa_type,
                              alen);

         if (bgpa.bgpa_flags) {
            sprintf(&ArgusBuf[strlen(ArgusBuf)],", Flags [%s%s%s%s",
               bgpa.bgpa_flags & 0x80 ? "O" : "",
               bgpa.bgpa_flags & 0x40 ? "T" : "",
               bgpa.bgpa_flags & 0x20 ? "P" : "",
               bgpa.bgpa_flags & 0x10 ? "E" : "");
            if (bgpa.bgpa_flags & 0xf)
               sprintf(&ArgusBuf[strlen(ArgusBuf)],"+%x", bgpa.bgpa_flags & 0xf);
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"]: ");
         }
         if (!bgp_attr_print(&bgpa, &p[i + aoff], alen))
            goto trunc;
         i += aoff + alen;
      }
   } 
   p += 2 + len;

   if (dat + length > p) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Updated routes:");
      while (dat + length > p) {
         char buf[MAXHOSTNAMELEN + 100];
         i = decode_prefix4(p, buf, sizeof(buf));
         if (i == -1) {
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," (illegal prefix length)");
            break;
         } else if (i == -2)
            goto trunc;
         else {
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", buf);
            p += i;
         }
      }
   }
   return;
trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|BGP]");
}

static void
bgp_notification_print(const u_char *dat, int length)
{
   struct bgp_notification bgpn;
   const u_char *tptr;
   char tokbuf[TOKBUFSIZE];
   char tokbuf2[TOKBUFSIZE];

   TCHECK2(dat[0], BGP_NOTIFICATION_SIZE);
   memcpy(&bgpn, dat, BGP_NOTIFICATION_SIZE);

        /* some little sanity checking */
        if (length<BGP_NOTIFICATION_SIZE)
            return;

   sprintf(&ArgusBuf[strlen(ArgusBuf)],", %s (%u)",
          tok2strbuf(bgp_notify_major_values, "Unknown Error",
           bgpn.bgpn_major, tokbuf, sizeof(tokbuf)),
          bgpn.bgpn_major);

        switch (bgpn.bgpn_major) {

        case BGP_NOTIFY_MAJOR_MSG:
            sprintf(&ArgusBuf[strlen(ArgusBuf)],", subcode %s (%u)",
         tok2strbuf(bgp_notify_minor_msg_values, "Unknown",
               bgpn.bgpn_minor, tokbuf, sizeof(tokbuf)),
         bgpn.bgpn_minor);
            break;
        case BGP_NOTIFY_MAJOR_OPEN:
            sprintf(&ArgusBuf[strlen(ArgusBuf)],", subcode %s (%u)",
         tok2strbuf(bgp_notify_minor_open_values, "Unknown",
               bgpn.bgpn_minor, tokbuf, sizeof(tokbuf)),
         bgpn.bgpn_minor);
            break;
        case BGP_NOTIFY_MAJOR_UPDATE:
            sprintf(&ArgusBuf[strlen(ArgusBuf)],", subcode %s (%u)",
         tok2strbuf(bgp_notify_minor_update_values, "Unknown",
               bgpn.bgpn_minor, tokbuf, sizeof(tokbuf)),
         bgpn.bgpn_minor);
            break;
        case BGP_NOTIFY_MAJOR_CAP:
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," subcode %s (%u)",
         tok2strbuf(bgp_notify_minor_cap_values, "Unknown",
               bgpn.bgpn_minor, tokbuf, sizeof(tokbuf)),
         bgpn.bgpn_minor);
        case BGP_NOTIFY_MAJOR_CEASE:
            sprintf(&ArgusBuf[strlen(ArgusBuf)],", subcode %s (%u)",
         tok2strbuf(bgp_notify_minor_cease_values, "Unknown",
               bgpn.bgpn_minor, tokbuf, sizeof(tokbuf)),
         bgpn.bgpn_minor);

       /* draft-ietf-idr-cease-subcode-02 mentions optionally 7 bytes
             * for the maxprefix subtype, which may contain AFI, SAFI and MAXPREFIXES
             */
       if(bgpn.bgpn_minor == BGP_NOTIFY_MINOR_CEASE_MAXPRFX && length >= BGP_NOTIFICATION_SIZE + 7) {
      tptr = dat + BGP_NOTIFICATION_SIZE;
      TCHECK2(*tptr, 7);
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", AFI %s (%u), SAFI %s (%u), Max Prefixes: %u",
             tok2strbuf(bgp_afi_values, "Unknown",
              EXTRACT_16BITS(tptr), tokbuf, sizeof(tokbuf)),
             EXTRACT_16BITS(tptr),
             tok2strbuf(bgp_safi_values, "Unknown", *(tptr+2),
              tokbuf2, sizeof(tokbuf)),
             *(tptr+2),
             EXTRACT_32BITS(tptr+3));
       }
            break;
        default:
            break;
        }

   return;
trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|BGP]");
}

static void
bgp_route_refresh_print(const u_char *pptr, int len) {

        const struct bgp_route_refresh *bgp_route_refresh_header;
   char tokbuf[TOKBUFSIZE];
   char tokbuf2[TOKBUFSIZE];

   TCHECK2(pptr[0], BGP_ROUTE_REFRESH_SIZE);

        /* some little sanity checking */
        if (len<BGP_ROUTE_REFRESH_SIZE)
            return;

        bgp_route_refresh_header = (const struct bgp_route_refresh *)pptr;

        sprintf(&ArgusBuf[strlen(ArgusBuf)]," AFI %s (%u), SAFI %s (%u)",
               tok2strbuf(bgp_afi_values,"Unknown",
           /* this stinks but the compiler pads the structure
            * weird */
           EXTRACT_16BITS(&bgp_route_refresh_header->afi),
           tokbuf, sizeof(tokbuf)), 
               EXTRACT_16BITS(&bgp_route_refresh_header->afi),
               tok2strbuf(bgp_safi_values,"Unknown",
           bgp_route_refresh_header->safi,
           tokbuf2, sizeof(tokbuf2)),
               bgp_route_refresh_header->safi);

        if (ArgusParser->vflag > 1) {
            TCHECK2(*pptr, len);
            print_unknown_data(pptr," ", len);
        }
        
        return;
trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|BGP]");
}

static int
bgp_header_print(const u_char *dat, int length)
{
   struct bgp bgp;
   char tokbuf[TOKBUFSIZE];

   TCHECK2(dat[0], BGP_SIZE);
   memcpy(&bgp, dat, BGP_SIZE);
   sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s Message (%u), length: %u",
               tok2strbuf(bgp_msg_values, "Unknown", bgp.bgp_type,
           tokbuf, sizeof(tokbuf)),
               bgp.bgp_type,
               length);

   switch (bgp.bgp_type) {
   case BGP_OPEN:
      bgp_open_print(dat, length);
      break;
   case BGP_UPDATE:
      bgp_update_print(dat, length);
      break;
   case BGP_NOTIFICATION:
      bgp_notification_print(dat, length);
      break;
        case BGP_KEEPALIVE:
                break;
        case BGP_ROUTE_REFRESH:
                bgp_route_refresh_print(dat, length);
                break;
        default:
                /* we have no decoder for the BGP message */
                TCHECK2(*dat, length);
                sprintf(&ArgusBuf[strlen(ArgusBuf)]," no Message %u decoder",bgp.bgp_type);
                print_unknown_data(dat," ",length);
                break;
   }
   return 1;
trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|BGP]");
   return 0;
}

char *
bgp_print(const u_char *dat, int length)
{
   const u_char *p;
   const u_char *ep;
   const u_char *start;
   const u_char marker[] = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   };
   struct bgp bgp;
   u_int16_t hlen;
   char tokbuf[TOKBUFSIZE];

   ep = dat + length;
   if (snapend < dat + length)
      ep = snapend;

   sprintf(&ArgusBuf[strlen(ArgusBuf)],": BGP, length: %u",length);

        if (ArgusParser->vflag < 1) /* lets be less chatty */
                return ArgusBuf;

   p = dat;
   start = p;
   while (p < ep) {
      if (!TTEST2(p[0], 1))
         break;
      if (p[0] != 0xff) {
         p++;
         continue;
      }

      if (!TTEST2(p[0], sizeof(marker)))
         break;
      if (memcmp(p, marker, sizeof(marker)) != 0) {
         p++;
         continue;
      }

      /* found BGP header */
      TCHECK2(p[0], BGP_SIZE);   /*XXX*/
      memcpy(&bgp, p, BGP_SIZE);

      if (start != p)
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|BGP]");

      hlen = ntohs(bgp.bgp_len);
      if (hlen < BGP_SIZE) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|BGP Bogus header length %u < %u]", hlen, BGP_SIZE);
         break;
      }

      if (TTEST2(p[0], hlen)) {
         if (!bgp_header_print(p, hlen))
            return ArgusBuf;
         p += hlen;
         start = p;
      } else {
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|BGP %s]", tok2strbuf(bgp_msg_values,
                 "Unknown Message Type", bgp.bgp_type,
                 tokbuf, sizeof(tokbuf)));
         break;
      }
   }

   return ArgusBuf;

trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|BGP]");

   return ArgusBuf;
}
