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

#include "argus_util.h"
#include "argus_threads.h"
#include "rabootp_l2addr_list.h"

int
rabootp_l2addr_list_empty(const struct rabootp_l2addr_list_head * const list)
{
   return SLIST_EMPTY(&list->head);
}

struct rabootp_l2addr_entry *
rabootp_l2addr_list_insert(struct rabootp_l2addr_list_head *list,
                           const unsigned char * const addr, size_t addrlen,
                           void *datum)
{
   struct rabootp_l2addr_entry *entry;

   entry = ArgusMalloc(sizeof(*entry));
   if (entry == NULL)
      return NULL;

   memset(&entry->list, 0, sizeof(entry->list));
   memcpy(entry->l2addr, addr, addrlen);
   entry->addrlen = addrlen;
   entry->datum = datum;

   SLIST_INSERT_HEAD(&list->head, entry, list);

   return entry;
}

struct rabootp_l2addr_entry *
rabootp_l2addr_list_remove(struct rabootp_l2addr_list_head *list,
                           const unsigned char * const addr, size_t addrlen)
{
   struct rabootp_l2addr_entry *target, *tmp;

   SLIST_FOREACH_SAFE(target, &list->head, list, tmp) {
      if (target->addrlen == addrlen &&
          (memcmp(target->l2addr, addr, addrlen) == 0)) {
         SLIST_REMOVE(&list->head, target, rabootp_l2addr_entry, list);
         break;
      }
   }

   return target;
}

int
rabootp_l2addr_list_foreach(struct rabootp_l2addr_list_head *list,
                            raboot_l2addr_list_cb cb, void *arg)
{
   int rv = 0;
   struct rabootp_l2addr_entry *cur, *tmp;

   SLIST_FOREACH_SAFE(cur, &list->head, list, tmp) {
      rv = cb(cur, arg);
      if (rv)
         break;
   }
   return rv;
}

struct rabootp_l2addr_entry *
rabootp_l2addr_list_search(struct rabootp_l2addr_list_head *list,
                           const unsigned char * const addr, size_t addrlen)
{
   struct rabootp_l2addr_entry *target;

   SLIST_FOREACH(target, &list->head, list) {
      if (target->addrlen == addrlen &&
          (memcmp(target->l2addr, addr, addrlen) == 0)) {
         break;
      }
   }

   return target;
}

struct rabootp_l2addr_list_head *
rabootp_l2addr_list_alloc(void)
{
   struct rabootp_l2addr_list_head *tmp;

   tmp = ArgusCalloc(1, sizeof(*tmp));
   if (tmp == NULL)
      return NULL;

   MUTEX_INIT(&tmp->lock, NULL);
   SLIST_INIT(&tmp->head);
   return tmp;
}

void
rabootp_l2addr_list_free(struct rabootp_l2addr_list_head *list)
{
   MUTEX_DESTROY(&list->lock);
   ArgusFree(list);
}
