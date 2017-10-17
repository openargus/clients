/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2017 QoSient, LLC
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

/* rabootp_lease_pullup.c: Functions to convert an array of interval
 * tree nodes, each node representing a single lease sorted by start
 * time, to an array of interval tree nodes with overlapping leases
 * for the same address to the same host combined.  This provides
 * a "logical" view of address assignments for hosts that do not
 * renew leases, but instead always aquire a new lease (different
 * transaction ID).
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#include <stdlib.h>
#include "rabootp_interval_tree.h"
#include "rabootp_memory.h"

static int
__chaddr_same(const unsigned char * const a,
              const unsigned char * const b,
              unsigned char hlen)
{
   unsigned i;
   int same = 1;

   for (i = 0; i < hlen && same; i++) {
      if (a[i] != b[i])
         same = 0;
   }
   return same;
}

static const unsigned char *
__chaddr(const struct ArgusDhcpIntvlNode * const n)
{
   const struct ArgusDhcpStruct * const ads = n->data;

   return &ads->chaddr[0];
}

static int
__overlap(const struct ArgusDhcpIntvlNode * const a,
          const struct ArgusDhcpIntvlNode * const b)
{
   /* assume a->intlo < b->intlo */
   if (timercmp(&a->inthi, &b->intlo, >=))
      return 1;
   return 0;
}

static int
__compare_addr_intvl(const void *a, const void *b)
{
   const struct ArgusDhcpIntvlNode *ina = a;
   const struct ArgusDhcpIntvlNode *inb = b;
   int res;
 
   res = memcmp(&ina->data->rep.yiaddr, &inb->data->rep.yiaddr,
                sizeof(ina->data->rep.yiaddr));
   if (res)
      return res;

   if (timercmp(&ina->intlo, &inb->intlo, <))
      return -1;
   if (timercmp(&ina->intlo, &inb->intlo, >))
      return 1;
   return 0;
}

void
RabootpLeasePullupSort(struct ArgusDhcpIntvlNode *src_invec,
                       size_t src_nitems)
{
   /* src_invec[] must be sorted by (yiaddr, starttime) such that all records
    * with the same IP address are contiguous and all records for a given IP
    * address are in ascending order by time.
    */
   qsort(src_invec, src_nitems, sizeof(*src_invec), __compare_addr_intvl);
}

/* caller must hold references to all of the dhcp structures pointed to by
 * the interval nodes.  RabootpLeasePullup increments the refcount for every
 * ArgusDhcpStruct referenced by the output vector, dst_invec.
 */
int
RabootpLeasePullup(const struct ArgusDhcpIntvlNode * const src_invec,
                   size_t src_nitems,
                   struct ArgusDhcpIntvlNode * const dst_invec,
                   size_t dst_nitems)
{
   size_t in_idx = 0;
   size_t out_idx = 0;
   size_t range_start_idx = 0;
   const unsigned char *chaddr_a;
   const unsigned char *chaddr_b;
   int chaddr_changed;
   int ipaddr_changed;

   if (src_nitems == 0)
      return 0;

   if (dst_nitems == 0)
      return -1;

   if (src_nitems == 1) {
      *dst_invec = *src_invec;
      return 1;
   }

   while (in_idx < (src_nitems-1) && out_idx < dst_nitems) {
      chaddr_a = __chaddr(&src_invec[in_idx]);
      chaddr_b = __chaddr(&src_invec[in_idx+1]);

      /* TODO: also check the leased IP addresses and only continue if
       * they are also the same.
       */
      if (src_invec[in_idx].data->hlen == src_invec[in_idx+1].data->hlen &&
          __chaddr_same(chaddr_a, chaddr_b, src_invec[in_idx].data->hlen))
         chaddr_changed = 0;
      else
         chaddr_changed = 1;

      if (memcmp(&src_invec[in_idx].data->rep.yiaddr,
                 &src_invec[in_idx+1].data->rep.yiaddr,
                 sizeof(src_invec[in_idx].data->rep.yiaddr)) == 0)
         ipaddr_changed = 0;
      else
         ipaddr_changed = 1;

      if (chaddr_changed == 0 && ipaddr_changed == 0 &&
          __overlap(&src_invec[in_idx], &src_invec[in_idx+1])) {
         in_idx++;
         continue;
      }

      /* found a node that either doesn't overlap or has a different hw addr
       * so output a node for the current lease.
       */

      /* combine the time ranges */
      dst_invec[out_idx].intlo = src_invec[range_start_idx].intlo;

      /* If the mac address for this IP address changed, it might have
       * done so before the original lease was over (relenquished).  If so
       * use the start time of the next host's lease as the end time.
       */
      if (ipaddr_changed == 0 &&
          timercmp(&src_invec[in_idx].inthi, &src_invec[in_idx+1].intlo, >))
         dst_invec[out_idx].inthi = src_invec[in_idx+1].intlo;
      else
         dst_invec[out_idx].inthi = src_invec[in_idx].inthi;

      dst_invec[out_idx].subtreehi.tv_sec = 0;
      dst_invec[out_idx].subtreehi.tv_usec = 0;
      dst_invec[out_idx].data = src_invec[in_idx].data;

      ArgusDhcpStructUpRef(dst_invec[out_idx].data);

      in_idx++;
      range_start_idx = in_idx;
      out_idx++;
   }

   /* If we've hit the end of the input, generate an output record */
   dst_invec[out_idx].intlo = src_invec[range_start_idx].intlo;
   dst_invec[out_idx].inthi = src_invec[in_idx].inthi;
   dst_invec[out_idx].subtreehi.tv_sec = 0;
   dst_invec[out_idx].subtreehi.tv_usec = 0;
   dst_invec[out_idx].data = src_invec[in_idx].data;

   ArgusDhcpStructUpRef(dst_invec[out_idx].data);
   out_idx++;

   /* return the number of nodes output */
   return (int)out_idx;
}
