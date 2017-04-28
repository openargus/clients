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

/* List of Layer-2 addresses */

#ifndef __RABOOTP_L2ADDR_LIST_H
# define __RABOOTP_L2ADDR_LIST_H

# include <sys/types.h>
# include "bsd/sys/queue.h"

struct rabootp_l2addr_entry {
   void *datum;
   unsigned char l2addr[16];
   size_t addrlen;
   SLIST_ENTRY(rabootp_l2addr_entry) list;
};

SLIST_HEAD(rabootp_l2addr_list, rabootp_l2addr_entry);

struct rabootp_l2addr_list_head {
   pthread_mutex_t lock;
   struct rabootp_l2addr_list head;
};

typedef int (*raboot_l2addr_list_cb)(struct rabootp_l2addr_entry *, void *);

int
rabootp_l2addr_list_empty(const struct rabootp_l2addr_list_head * const);

struct rabootp_l2addr_entry *
rabootp_l2addr_list_insert(struct rabootp_l2addr_list_head *,
                           const unsigned char * const, size_t, void *);

struct rabootp_l2addr_entry *
rabootp_l2addr_list_remove(struct rabootp_l2addr_list_head *,
                           const unsigned char * const, size_t);

int
rabootp_l2addr_list_foreach(struct rabootp_l2addr_list_head *,
                            raboot_l2addr_list_cb, void *);

struct rabootp_l2addr_entry *
rabootp_l2addr_list_search(struct rabootp_l2addr_list_head *,
                           const unsigned char * const, size_t);

struct rabootp_l2addr_list_head *
rabootp_l2addr_list_alloc(void);

void
rabootp_l2addr_list_free(struct rabootp_l2addr_list_head *);

#endif
