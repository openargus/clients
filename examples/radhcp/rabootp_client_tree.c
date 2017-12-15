#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#include <pthread.h>
#include <string.h>
#include "argus_config.h"
#include "argus_util.h"
#include "argus_threads.h"
#include "bsd/sys/tree.h"
#include "rabootp.h"
#include "rabootp_client_tree.h"
#include "rabootp_memory.h"

static int
__dhcp_client_compare(struct ArgusDhcpClientNode *aa,
                      struct ArgusDhcpClientNode *bb)
{
   int res;
   struct ArgusDhcpStruct *a = aa->data;
   struct ArgusDhcpStruct *b = bb->data;

   if (a->hlen == b->hlen) {
      res = memcmp(&a->chaddr[0], &b->chaddr[0], a->hlen);
      if (res)
         return res;
      else if (a->xid < b->xid)
         return -1;
      else if (a->xid > b->xid)
         return 1;
   } else if (a->hlen < b->hlen) {
      return -1;
   } else if (a->hlen > b->hlen) {
      return 1;
   }

   return 0;
}

static int
__dhcp_client_compare_hwaddr(struct ArgusDhcpClientNode *aa,
                             struct ArgusDhcpClientNode *bb)
{
   struct ArgusDhcpStruct *a = aa->data;
   struct ArgusDhcpStruct *b = bb->data;

   if (a->hlen == b->hlen) {
      return memcmp(&a->chaddr[0], &b->chaddr[0], a->hlen);
   } else if (a->hlen < b->hlen) {
      return -1;
   } else if (a->hlen > b->hlen) {
      return 1;
   }

   return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
RB_GENERATE_STATIC(dhcp_client_tree, ArgusDhcpClientNode, tree, __dhcp_client_compare);
#pragma GCC diagnostic pop

/* Search ONLY by client hardware address and return the first node
 * found.  All entries for a particular mac address can then be iterated
 * with the RB_NEXT macro.  Nodes are indexed in the tree by client
 * host address + XID.  ArgusDhcpClientTree->lock should be held by the
 * caller.
 */
static inline struct ArgusDhcpStruct *
__argus_find_dhcp_client__locked(struct dhcp_client_tree *head,
                                 struct ArgusDhcpStruct *elm)
{
        struct ArgusDhcpClientNode *tmp = RB_ROOT(head);
        struct ArgusDhcpClientNode node;
        int comp;

        node.data = elm;
        while (tmp) {
                comp = __dhcp_client_compare_hwaddr(&node, tmp);
                if (comp < 0)
                        tmp = RB_LEFT(tmp, tree);
                else if (comp > 0)
                        tmp = RB_RIGHT(tmp, tree);
                else
                        return (tmp->data);
        }
        return (NULL);
}

struct ArgusDhcpClientTree *
ArgusDhcpClientTreeAlloc(void)
{
   struct ArgusDhcpClientTree *res;

   res = ArgusMalloc(sizeof(*res));
   if (res) {
      RB_INIT(&res->tree);
      pthread_mutex_init(&res->lock, NULL);
   }

   return res;
}

void
ArgusDhcpClientTreeFree(struct ArgusDhcpClientTree *head)
{
   struct ArgusDhcpClientNode *node;

   while (!RB_EMPTY(&head->tree)) {
      node = RB_ROOT(&head->tree);
      RB_REMOVE(dhcp_client_tree, &head->tree, node);
      ArgusDhcpStructFree(node->data);
      ArgusFree(node);
   }
}

/* increment ads->refcount BEFORE calling */
int
ArgusDhcpClientTreeInsert(struct ArgusDhcpClientTree *head,
                          struct ArgusDhcpStruct *ads)
{
   struct ArgusDhcpClientNode *node;
   struct ArgusDhcpClientNode *exist;

   node = ArgusCalloc(1, sizeof(*node));
   if (node) {
      node->data = ads;

      MUTEX_LOCK(&head->lock);
      exist = RB_INSERT(dhcp_client_tree, &head->tree, node);
      MUTEX_UNLOCK(&head->lock);

      if (exist) {
          DEBUGLOG(6, "%s: Node already exists in client tree.\n", __func__);
          ArgusFree(node);
          node = NULL;
      }
   }

   return -(node == NULL);
}

int
ArgusDhcpClientTreeRemove(struct ArgusDhcpClientTree *head,
                          struct ArgusDhcpStruct *ads)
{
   struct ArgusDhcpClientNode *node;
   struct ArgusDhcpClientNode search;

   search.data = ads;
   MUTEX_LOCK(&head->lock);
   node = RB_FIND(dhcp_client_tree, &head->tree, &search);
   if (node)
      RB_REMOVE(dhcp_client_tree, &head->tree, node);
   MUTEX_UNLOCK(&head->lock);

   if (node)
      ArgusFree(node);

   DEBUGLOG(4, "%s returned %d\n", __func__, -(node == NULL));
   return -(node == NULL);
}

struct ArgusDhcpStruct *
ClientTreeFind(struct ArgusDhcpClientTree *head,
               const unsigned char * const chaddr,
               unsigned char hlen, unsigned xid)
{
   struct ArgusDhcpStruct client;
   struct ArgusDhcpClientNode node = {
      .data = &client,
   };
   struct ArgusDhcpClientNode *res;

   memcpy(&(client.chaddr[0]), chaddr, hlen);
   client.hlen = hlen;
   client.xid = xid;

   MUTEX_LOCK(&head->lock);
   res = RB_FIND(dhcp_client_tree, &head->tree, &node);
   if (res)
      ArgusDhcpStructUpRef(res->data);
   MUTEX_UNLOCK(&head->lock);

   if (res)
      return res->data;
   return NULL;
}

struct ArgusDhcpStruct *
ClientTreeFindByStruct(struct ArgusDhcpClientTree *head,
                       struct ArgusDhcpStruct *exemplar)
{
   struct ArgusDhcpClientNode node;
   struct ArgusDhcpClientNode *res;

   node.data = exemplar;
   MUTEX_LOCK(&head->lock);
   res = RB_FIND(dhcp_client_tree, &head->tree, &node);
   if (res)
      ArgusDhcpStructUpRef(res->data);
   MUTEX_UNLOCK(&head->lock);

   if (res)
      return res->data;
   return NULL;
}

int
ClientTreeForEach(struct ArgusDhcpClientTree * const head,
                  ClientTreeCallback cb, void *cp_arg0)
{
   int rv = 0;
   struct ArgusDhcpClientNode *node;

   MUTEX_LOCK(&head->lock);
   RB_FOREACH(node, dhcp_client_tree, &head->tree) {
      rv = cb(cp_arg0, node);
      if (rv < 0)
         goto unlock;
   }

unlock:
   MUTEX_UNLOCK(&head->lock);
   return rv;
}
