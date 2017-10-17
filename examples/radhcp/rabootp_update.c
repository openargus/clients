#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#include <stdlib.h>
#include <syslog.h>
#include "argus_util.h"
#include "argus_client.h"
#include "rabootp_update.h"

/*
 *
 * Local helper functions
 *
 */

/* TODO: this macro should update an event/alert log and do so with more
 * information
 */
#define SET_CHANGE_NOTIFY(target, val, unsetval)			\
do {									\
   if ((target) != (val)) {						\
      if ((val) != (unsetval)) {					\
         if ((target) != (unsetval)) {					\
            ArgusLog(LOG_INFO, "%s: %s changed from original value\n",	\
                     __func__, #target);				\
         }								\
         (target) = (val);						\
      }									\
   }									\
} while (0)

#define STRDUP_CHANGE_NOTIFY(target, val)				\
do {									\
   if ((target) != (val)) {						\
      if ((val) != NULL) {						\
         if ((target) != NULL) {					\
            if (strcmp(target, val)) {					\
               ArgusLog(LOG_INFO, "%s: %s changed from original value\n", \
                        __func__, #target);				\
               free(target);						\
               (target) = strdup(val);					\
            }								\
         } else {							\
            (target) = strdup(val);					\
         }								\
      }									\
   }									\
} while (0)

static int
__client_id_compare(const struct ArgusDhcpStruct * const parsed,
                    const struct ArgusDhcpStruct * const cached)
{
   if (parsed->req.client_id_len <= 8)
      return memcmp(&parsed->req.client_id.bytes[0], &cached->req.client_id.bytes[0],
                    parsed->req.client_id_len);

   return memcmp(parsed->req.client_id.ptr, cached->req.client_id.ptr,
                 parsed->req.client_id_len);
}

static int
__client_id_copy(const struct ArgusDhcpStruct * const parsed,
                 struct ArgusDhcpStruct *cached)
{
   cached->req.client_id_len = parsed->req.client_id_len;
   if (parsed->req.client_id_len <= 8)
      cached->req.client_id = parsed->req.client_id;
   else {
      if (cached->req.client_id.ptr) {
         if (cached->req.client_id_len < parsed->req.client_id_len) {
            ArgusFree(cached->req.client_id.ptr);
            cached->req.client_id.ptr = NULL;
         }
      }

      if (cached->req.client_id.ptr == NULL)
         cached->req.client_id.ptr = ArgusMalloc(parsed->req.client_id_len);

      if (cached->req.client_id.ptr == NULL)
         return -1;

      memcpy(cached->req.client_id.ptr, parsed->req.client_id.ptr,
             parsed->req.client_id_len);
   }
   return 0;
}

static struct ArgusDhcpV4LeaseOptsStruct *
__find_v4_server_by_id(struct ArgusDhcpV4LeaseOptsStruct * head,
                       const struct in_addr * const server_id)
{
   for (; head; head = head->next)
      if (head->server_id.s_addr == server_id->s_addr)
         return head;
   return NULL;
}

static void
__update_selected_server_id(const struct ArgusDhcpStruct * const parsed,
                            struct ArgusDhcpStruct *cached)
{
   if (parsed->req.requested_server_id.s_addr !=
       cached->req.requested_server_id.s_addr) {
      /* ALERT: selected DHCP server changed */
      cached->req.requested_server_id = parsed->req.requested_server_id;
   }
}

/* given two sorted char arrays, a and b, store a list that
 * contains the sorted contents of (a U b) in dst.  dst must
 * be large enough to hold (alen+blen) chars.
 *
 * returns the actual length of dst.  If the two input lists overlap
 * this will be less than their combined lengths.
 */
static size_t
__uchar_array_union(const uint8_t *a, const uint8_t *b, uint8_t *dst,
                    size_t alen, size_t blen)
{
   uint8_t dstlen = 0;
   size_t apos = 0, bpos = 0;

   while (!(apos == alen && bpos == blen)) {

      if (apos < alen) {
         /* skip duplicates in a */
         if (apos > 0 && a[apos] == a[apos-1]) {
            apos++;
            continue;
         }
         if (bpos < blen) {
            /* skip duplicates in b */
            if (bpos > 0 && b[bpos] == b[bpos-1]) {
               bpos++;
               continue;
            }
            if (a[apos] < b[bpos])
               dst[dstlen++] = a[apos++];
            else if (b[bpos] < a[apos])
               dst[dstlen++] = b[bpos++];
            else /* equal */
               dst[dstlen++] = a[apos++], bpos++;
            continue;
         }
         dst[dstlen++] = a[apos++];
      } else if (bpos < blen) {
         /* skip duplicates in b */
         if (bpos > 0 && b[bpos] == b[bpos-1]) {
            bpos++;
            continue;
         }
         dst[dstlen++] = b[bpos++];
      }
   }
   return dstlen;
}



/*
 *
 * Per-message update functions
 *
 */

static int
__update_dhcpdiscover(const struct ArgusDhcpStruct * const parsed,
                      struct ArgusDhcpStruct *cached)
{
   /* TODO: validate presence of provided options and bootp
    * (non-options) fields.  See "Table 5:  Fields and options used
    * by DHCP clients" in RFC2131.
    */

   unsigned count;
   int res = 0;

   /* combine the options masks */
   count = sizeof(parsed->req.options)/sizeof(parsed->req.options[0]);
   while (--count)
      cached->req.options[count] |= parsed->req.options[count];
   cached->req.options[0] |= parsed->req.options[0];

   if (cached->req.client_id_len > 0 && parsed->req.client_id_len > 0) {
      if (cached->req.client_id_len != parsed->req.client_id_len)
         /* ALERT: client ID length changed!!! */
         ;
      else if (__client_id_compare(parsed, cached))
         /* ALERT: client ID changed!!! */
         ;
   } else if (parsed->req.client_id_len > 0) {
      /* new client ID */
      res = __client_id_copy(parsed, cached);
   }

   return res;
}

static int
__update_dhcprequest(const struct ArgusDhcpStruct * const parsed,
                     struct ArgusDhcpStruct *cached)
{
   /* TODO: validate presence of provided options and bootp
    * (non-options) fields.  See "Table 5:  Fields and options used
    * by DHCP clients" in RFC2131.
    */

   struct ArgusDhcpV4LeaseOptsStruct *rep;
   int res = __update_dhcpdiscover(parsed, cached);

   /* RFC 2131 Section 3.1 list item (3) - client must include server ID
    * in DHCPREQUEST.  Not many do.
    */
   if (__options_mask_isset(parsed->req.options, DHO_DHCP_SERVER_IDENTIFIER)) {
      rep = __find_v4_server_by_id(&cached->rep,
                                   &parsed->req.requested_server_id);
      __update_selected_server_id(parsed, cached);
   } else {
      /* No server ID in DHCPREQUEST.  ALERT?  just take note? */
   }

   if (__options_mask_isset(parsed->req.options, DHO_DHCP_REQUESTED_ADDRESS))
      cached->req.requested_addr = parsed->req.requested_addr;

   if (__options_mask_isset(parsed->req.options, DHO_HOST_NAME)) {
      STRDUP_CHANGE_NOTIFY(cached->req.requested_hostname,
                           parsed->req.requested_hostname);
   }

   if (parsed->req.requested_options_count) {
      uint8_t *un;
      size_t unlen;
      unsigned alloclen = parsed->req.requested_options_count
                          + cached->req.requested_options_count;

      un = ArgusMalloc(alloclen);
      if (un) {
         unlen = __uchar_array_union(parsed->req.requested_opts,
                                     cached->req.requested_opts, un,
                                     parsed->req.requested_options_count,
                                     cached->req.requested_options_count);
         if (cached->req.requested_opts)
            ArgusFree(cached->req.requested_opts);
         cached->req.requested_opts = un;
         cached->req.requested_options_count = (uint8_t)(unlen & 0xff);
      }
   }

   return res;
}

static int
__update_common_reply(const struct ArgusDhcpStruct * const parsed,
                      struct ArgusDhcpStruct *cached)
{
   struct ArgusDhcpV4LeaseOptsStruct *rep;
   unsigned count;

   if (parsed->rep.server_id.s_addr == 0) {
      /* ALERT: can't do much with this */
      return -1;
   }

   rep = __find_v4_server_by_id(&cached->rep, &parsed->rep.server_id);
   if (rep == NULL) {

      cached->num_responders++;

      if (cached->rep.server_id.s_addr == 0) {
         /* no replies yet, use the reply struct in 'cached' */
         rep = &cached->rep;
      } else {
         /* need to chain a new reply onto the list */
         ArgusLog(LOG_INFO, "%s: allocating a new reply struct \n", __func__);
         rep = ArgusMallocAligned(sizeof(*rep), 64);
         memset(rep, 0, sizeof(*rep));
      }

      if (rep) {
         memcpy(rep, &parsed->rep, sizeof(*rep));
         if (rep->hostname)
            rep->hostname = strdup(rep->hostname);
         if (rep->domainname)
            rep->domainname = strdup(rep->domainname);
         if (rep != &cached->rep) {
            rep->next = cached->rep.next;
            cached->rep.next = rep;
         }

         /* only needed to copy, so get out here */
         return 0;
      }
   }

   if (rep == NULL) {
      ArgusLog(LOG_WARNING,
               "%s: unable to find a place to store the DHCP reply\n",
               __func__);
      return -1;
   }

   /* combine the options masks */
   count = sizeof(parsed->rep.options)/sizeof(parsed->rep.options[0]);
   while (--count)
      rep->options[count] |= parsed->rep.options[count];
   rep->options[0] |= parsed->rep.options[0];

   SET_CHANGE_NOTIFY(rep->yiaddr.s_addr, parsed->rep.yiaddr.s_addr, 0UL);
   SET_CHANGE_NOTIFY(rep->ciaddr.s_addr, parsed->rep.ciaddr.s_addr, 0UL);
   SET_CHANGE_NOTIFY(rep->siaddr.s_addr, parsed->rep.siaddr.s_addr, 0UL);
   memcpy(&rep->shaddr[0], &parsed->rep.shaddr[0],
          sizeof(rep->shaddr));
   SET_CHANGE_NOTIFY(rep->leasetime, parsed->rep.leasetime, 0);

   SET_CHANGE_NOTIFY(rep->netmask.s_addr, parsed->rep.netmask.s_addr, 0UL);
   SET_CHANGE_NOTIFY(rep->broadcast.s_addr, parsed->rep.broadcast.s_addr, 0UL);
   SET_CHANGE_NOTIFY(rep->timeserver[0].s_addr,
                     parsed->rep.timeserver[0].s_addr, 0UL);
   SET_CHANGE_NOTIFY(rep->timeserver[1].s_addr,
                     parsed->rep.timeserver[1].s_addr, 0UL);
   SET_CHANGE_NOTIFY(rep->nameserver[0].s_addr,
                     parsed->rep.nameserver[0].s_addr, 0UL);
   SET_CHANGE_NOTIFY(rep->nameserver[1].s_addr,
                     parsed->rep.nameserver[1].s_addr, 0UL);
   SET_CHANGE_NOTIFY(rep->router_count, parsed->rep.router_count, 0);
   SET_CHANGE_NOTIFY(rep->nameserver_count, parsed->rep.nameserver_count, 0);
   SET_CHANGE_NOTIFY(rep->timeserver_count, parsed->rep.timeserver_count, 0);
   SET_CHANGE_NOTIFY(rep->option_overload, parsed->rep.option_overload, 0);
   SET_CHANGE_NOTIFY(rep->mtu, parsed->rep.mtu, 0);
   STRDUP_CHANGE_NOTIFY(rep->hostname, parsed->rep.hostname);
   STRDUP_CHANGE_NOTIFY(rep->domainname, parsed->rep.domainname);

   return 0;
}

static inline int
__update_dhcpoffer(const struct ArgusDhcpStruct * const parsed,
                   struct ArgusDhcpStruct *cached)
{
   /* TODO: validate presence of provided options and bootp
    * (non-options) fields.  See "Table 3:  Fields and options used
    * by DHCP servers" in RFC2131.
    */
   return __update_common_reply(parsed, cached);
}

static inline int
__update_dhcpack(const struct ArgusDhcpStruct * const parsed,
                 struct ArgusDhcpStruct *cached)
{
   /* TODO: validate presence of provided options and bootp
    * (non-options) fields.  See "Table 3:  Fields and options used
    * by DHCP servers" in RFC2131.
    */
   return __update_common_reply(parsed, cached);
}

/* ArgusDhcpStructUpdate:
 *   Caller must ensure that the XIDs, hlens and host addresses
 *   (chaddr)  of the parsed DHCP message matches the cached message.
 */
int
ArgusDhcpStructUpdate(const struct ArgusDhcpStruct * const parsed,
                      struct ArgusDhcpStruct *cached)
{
   /* combine the message type masks */
   cached->msgtypemask |= parsed->msgtypemask;

   /* everything from here depends on what type of message was recieved. */

   if (parsed->msgtypemask & (1U << DHCPDISCOVER)) {
      __update_dhcpdiscover(parsed, cached);
   } else if (parsed->msgtypemask & (1U << DHCPOFFER)) {
      __update_dhcpoffer(parsed, cached);
   } else if (parsed->msgtypemask & (1U << DHCPREQUEST)) {
      __update_dhcprequest(parsed, cached);
   } else if (parsed->msgtypemask & (1U << DHCPDECLINE)) {
   } else if (parsed->msgtypemask & (1U << DHCPACK)) {
      __update_dhcpack(parsed, cached);
   } else if (parsed->msgtypemask & (1U << DHCPNAK)) {
   } else if (parsed->msgtypemask & (1U << DHCPRELEASE)) {
   } else {
      /* DHCPINFORM
       * DHCPLEASEQUERY
       * DHCPLEASEUNASSIGNED
       * DHCPLEASEUNKNOWN
       * DHCPLEASEACTIVE
       */
   }

   return 0;
}
