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

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include "argus_util.h"
#include "argus_parser.h"
#include "argus_debug.h"
#include "dhcp.h"
#include "rabootp_callback.h"
#include "rabootp_timer.h"
#include "rabootp_interval_tree.h" /* for RabootpIntvlTreeOverlapsRange */

# if defined(ARGUS_MYSQL)
#  include "argus_mysql.h"

#  define RASQL_MAX_COLUMNS     64
#  define RASQL_MAX_VARCHAR     128

/* excessive? */
#  define ARGUS_MAX_TABLE_LIST_SIZE	0x10000

void RaSQLResultBindFreeOne(MYSQL_BIND *);
void RaSQLResultBindFree(MYSQL_BIND *, int);
int RaSQLResultBindOne(MYSQL_BIND *, const MYSQL_FIELD * const);
int RaSQLResultBind(MYSQL_BIND *, const MYSQL_FIELD * const, int);

# endif /* ARGUS_MYSQL */

#ifdef ARGUSDEBUG
# define DEBUGLOG(lvl, fmt...) ArgusDebug(lvl, fmt)
#else
# define DEBUGLOG(lvl, fmt...)
#endif

/* message type missing from dhcp.h */
#define DHCPFORCERENEW 9           /* RFC 3203 */

static int
#ifdef __GNUC__
__attribute__((always_inline))
#endif
inline
__ether_aton(const char * const etherstr, unsigned char *addr)
{
   int i;
   unsigned int o0, o1, o2, o3, o4, o5;

   i = sscanf(etherstr, "%x:%x:%x:%x:%x:%x", &o0, &o1, &o2, &o3, &o4, &o5);
   if (i != 6)
      return -1;

   addr[0] = o0;
   addr[1] = o1;
   addr[2] = o2;
   addr[3] = o3;
   addr[4] = o4;
   addr[5] = o5;

   return 0;
}

static inline uint16_t
__type2mask(const uint8_t t)
{
	return (1 << t);
}

static inline uint8_t
__mask2type(uint16_t mask)
{
   uint8_t msgtype = 0;

   for (mask >>= 1; mask; msgtype++, mask >>= 1);
   return msgtype;
}

static inline void
__options_mask_set(uint64_t mask[], uint8_t opt)
{
   uint8_t idx = opt/64;
   uint8_t shift = opt % 64;

   mask[idx] |= (1ULL << shift);
}

static inline void
__options_mask_clr(uint64_t mask[], uint8_t opt)
{
   uint8_t idx = opt/64;
   uint8_t shift = opt % 64;

   mask[idx] &= ~(1ULL << shift);
}


static inline uint8_t
__options_mask_isset(const uint64_t mask[], uint8_t opt)
{
   uint8_t idx = opt/64;
   uint8_t shift = opt % 64;

   if (mask[idx] & (1ULL << shift))
      return opt;

   return 0;
}

enum ArgusDhcpState {
   __INVALID__  = 0,
   INITREBOOT   = 1,
   REBOOTING    = 2,
   REQUESTING   = 3,
   BOUND        = 4,
   RENEWING     = 5,
   REBINDING    = 6,
   SELECTING    = 7,
   INIT         = 8,
};

struct ArgusDhcpV6DUID {
   uint8_t *value;
   uint16_t len;
};

/* either accepted lease or offer */
/* IP addresses are in network byte order */
struct ArgusDhcpV4LeaseOptsStruct {

   /* first cacheline */
   unsigned char shaddr[16];       /* server's L2 address */
   uint64_t options[4];            /* bitmask - 256 possible options */
   uint32_t leasetime;             /* option 51 */
   struct in_addr router;          /* option 3 first router */
   struct in_addr yiaddr;          /* yiaddr from non-options payload */
   struct in_addr ciaddr;          /* ciaddr from non-options payload */

   /* second cacheline */
   struct in_addr netmask;         /* option 1 */
   struct in_addr broadcast;       /* option 28 */
   struct in_addr timeserver[2];   /* option 42 first 2 timeservers */
   struct in_addr nameserver[2];   /* option 6 first 2 nameservers */
   char *hostname;                 /* option 12 */
   char *domainname;               /* option 15 */
   struct in_addr server_id;       /* option 54 */
   uint8_t router_count;           /* option 3 */
   uint8_t timeserver_count;       /* option 42 */
   uint8_t nameserver_count;       /* option 6 */
   uint8_t option_overload;        /* option 52 */
   struct in_addr siaddr;          /* siaddr from non-options payload */
   uint16_t mtu;                   /* option 26 */
   uint8_t hops;                   /* hop count from header */
   uint8_t pad0;                   /* PAD */
   struct ArgusDhcpV4LeaseOptsStruct *next;
};

/* IP addresses are in network byte order */
struct ArgusDhcpV4RequstOptsStruct {
   uint64_t options[4];            /* bitmask - 256 possible options */
   uint8_t *requested_opts;        /* option 55 */
   union {
      /* use bytes array if length <= 8 */
      uint8_t *ptr;
      uint8_t bytes[8];
   } client_id;                    /* option 61 */
   struct in_addr requested_addr;  /* option 50 */
   struct in_addr requested_server_id; /* option 54 */
   char *requested_hostname;       /* option 12 */

   /* second cacheline */
   uint8_t requested_options_count;
   uint8_t client_id_len;
   uint8_t pad[6];
};

struct ArgusDhcpV4Timers {
   void *lease;                    /* protocol lease expiry */
   void *non_lease;                /* out-of-lease timer */
   void *intvl;                    /* when to remove from interval tree */
};

enum ArgusDhcpStructFlags {
   ARGUS_DHCP_LEASEEXP = 0x1,
   ARGUS_DHCP_LEASEREL = 0x2,
};

/* chaddr + xid uniquely identifies host state */
/* IP addresses are in network byte order */
struct ArgusDhcpStruct {
   /* first x86_64 cacheline */
   unsigned char chaddr[16];       /* client L2 address */
   unsigned char shaddr[16];       /* accepted server's L2 address */
   pthread_mutex_t *lock;
   enum ArgusDhcpState state;      /* 4 bytes on x86_64 with llvm & gcc */
   uint8_t pad0[3];
   uint8_t flags;
   struct in_addr server_id_v4;

   uint32_t xid;                   /* transaction ID from dhcp packet */
   uint16_t msgtypemask;           /* mask of option-53 message types */
   uint8_t hlen;
   uint8_t refcount;
   uint8_t pad1[4];

   /* second + third cachelines */
   struct ArgusDhcpV4RequstOptsStruct req;
   char *sql_table_name;
   struct ArgusDhcpV6DUID server_id_v6;
   unsigned short total_responses; /* how many replies received with this xid */
   unsigned short num_responders;  /* how many unique servers replied */
   unsigned short total_requests;  /* request packets with this chaddr+xid */
   unsigned short total_unknownops;/* unknown opcodes received */

   /* do not put ArgusDhcpV4Timers here - shared with timer thread */
   uint8_t pad3[24];

   /* fourth + fifth cachelines */
   struct ArgusDhcpV4LeaseOptsStruct rep; /* This is a linked list of replies */

   /* sixth cacheline */
   struct timeval first_req;       /* this client transaction was first seen */
   struct timeval first_bind;      /* first time we entered the BOUND state */
   struct timeval last_mod;        /* last time transaction modified */
   struct timeval last_bind;       /* last time we entered the BOUND state */

   /* seventh cacheline */
   struct ArgusDhcpV4Timers timers;

};

void RabootpCleanup(void);
struct ArgusDhcpStruct *
ArgusParseDhcpRecord(struct ArgusParserStruct *, struct ArgusRecordStruct *,
                     struct RabootpTimerStruct *);

int RabootpClientRemove(struct ArgusDhcpStruct *);
int RabootpIntvlRemove(const struct timeval * const,
                       struct ArgusDhcpStruct *);
char *RabootpDumpTreeStr(int, char *, size_t);
void RabootpIntvlTreeDump(char *, size_t);

struct ArgusDhcpIntvlNode;
ssize_t RabootpIntvlTreeOverlapsRange(const struct timeval * const,
                                      const struct timeval * const,
                                      struct ArgusDhcpIntvlNode *, size_t,
                                      const unsigned char * const, uint8_t);


enum rabootp_callback_trigger {
   CALLBACK_STATECHANGE = 0,
   CALLBACK_XIDNEW,
   CALLBACK_XIDUPDATE,
   CALLBACK_XIDDELETE,
};

size_t RabootpIntvlTreeCount(void);

void RabootpCallbacksInit(struct ArgusParserStruct *);
int RabootpCallbackRegister(enum rabootp_callback_trigger trigger,
                            rabootp_cb cb, void *arg);
int RabootpCallbackUnregister(enum rabootp_callback_trigger trigger,
                              rabootp_cb cb);
void RabootpCallbacksCleanup(void);

/*
 * Vendor magic cookie (v_magic) for RFC1048
 */
#define VM_RFC1048   { 99, 130, 83, 99 }

#endif
