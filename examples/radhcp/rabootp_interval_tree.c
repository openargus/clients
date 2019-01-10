#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include "argus_config.h"
#include "argus_util.h"
#include "argus_filter.h" /* etheraddr_string */
#include "argus_threads.h"
static void __dhcp_intvl_node_update(void *);
#define RB_AUGMENT(ent) __dhcp_intvl_node_update(ent)
#include "bsd/sys/tree.h"
#include "rabootp.h"
#include "rabootp_interval_tree.h"
#include "rabootp_memory.h"

#pragma GCC diagnostic ignored "-Wunused-function"

/* called every time a pointer is changed in the RB tree? */
static void
__dhcp_intvl_node_update(void *arg)
{
   struct ArgusDhcpIntvlNode *ent = arg;
   struct ArgusDhcpIntvlNode *left = RB_LEFT(ent, inttree);
   struct ArgusDhcpIntvlNode *right = RB_RIGHT(ent, inttree);

   if (left) {
      /* If the left node has a longer duration than the right node,
       * the left node's end time may exceed that of the right node.
       * Check both sides against this node's subtreehi.
       */

       if ((right && timercmp(&right->subtreehi, &left->subtreehi, <)) || !right)
          ent->subtreehi = left->subtreehi;
       else if (right)
          ent->subtreehi = right->subtreehi;
       else {
          ent->subtreehi.tv_sec = -1;
          ent->subtreehi.tv_usec = 0;
       }
   } else if (right) {
      ent->subtreehi = right->subtreehi;
   } else {
      ent->subtreehi = ent->inthi;
   }

   /* Now compare this to our own high value and choose the larger */
   if (timercmp(&ent->inthi, &ent->subtreehi, >))
      ent->subtreehi = ent->inthi;

   if (RB_PARENT(ent,inttree))
     __dhcp_intvl_node_update(RB_PARENT(ent,inttree));
}

static int
__dhcp_client_compare(struct ArgusDhcpIntvlNode *aa,
                      struct ArgusDhcpIntvlNode *bb)
{
   if (timercmp(&aa->intlo, &bb->intlo, <))
      return -1;

   if (timercmp(&aa->intlo, &bb->intlo, >))
      return 1;

   if (aa->data < bb->data)
      return -1;

   if (aa->data > bb->data)
      return 1;

   return 0;
}

RB_GENERATE_STATIC(dhcp_intvl_tree, ArgusDhcpIntvlNode, inttree, __dhcp_client_compare);

struct ArgusDhcpIntvlTree *
ArgusDhcpIntvlTreeAlloc(void)
{
   struct ArgusDhcpIntvlTree *res;

   res = ArgusMalloc(sizeof(*res));
   if (res) {
      RB_INIT(&res->inttree);
      res->count = 0;
      pthread_mutex_init(&res->lock, NULL);
   }

   return res;
}

void
ArgusDhcpIntvlTreeFree(struct ArgusDhcpIntvlTree *head)
{
   struct ArgusDhcpIntvlNode *node;

   while (!RB_EMPTY(&head->inttree)) {
      node = RB_ROOT(&head->inttree);
      RB_REMOVE(dhcp_intvl_tree, &head->inttree, node);
      ArgusDhcpStructFree(node->data);
      ArgusFree(node);
   }
}

int
ArgusDhcpIntvlTreeEmpty(const struct ArgusDhcpIntvlTree * const head)
{
   return RB_EMPTY(&head->inttree);
}

/* increment ads->refcount BEFORE calling */
int
ArgusDhcpIntvlTreeInsert(struct ArgusDhcpIntvlTree *head,
                         const struct timeval * const start,
                         uint32_t seconds,
                         struct ArgusDhcpStruct *ads)
{
   struct ArgusDhcpIntvlNode *node;

   node = ArgusCalloc(1, sizeof(*node));
   if (node) {
      struct ArgusDhcpIntvlNode *exist;

      node->data = ads;
      node->intlo = *start;
      node->inthi = *start;
      node->inthi.tv_sec += seconds; /* unlikely to overflow */
      node->subtreehi = node->inthi;

      MUTEX_LOCK(&head->lock);
      exist = RB_INSERT(dhcp_intvl_tree, &head->inttree, node);
      if (exist != NULL) {
         /* extend this node's interval */
         exist->inthi.tv_sec = ads->last_bind.tv_sec + seconds;
         if (timercmp(&exist->subtreehi, &exist->inthi, <))
            __dhcp_intvl_node_update(exist);

         /* clean up the node we allocated but don't need */
         ArgusFree(node);
         node = NULL;
      } else {
         if (head->count < -1U)
            head->count++;
      }
      MUTEX_UNLOCK(&head->lock);
   }

   return -(node == NULL);
}

int
ArgusDhcpIntvlTreeReduce(struct ArgusDhcpIntvlTree *head,
                         const struct timeval * const intlo,
                         const struct timeval * const end,
                         struct ArgusDhcpStruct * const ads)
{
   struct ArgusDhcpIntvlNode *exist;
   struct ArgusDhcpIntvlNode search;

   search.intlo = *intlo;
   search.data = ads;
   MUTEX_LOCK(&head->lock);
   exist = RB_FIND(dhcp_intvl_tree, &head->inttree, &search);
   if (exist) {
      if (timercmp(end, &exist->inthi, <)) {
         /* only apply reduce/truncate logic if the new end time is
          * earlier than the interval upper bound
          */

         exist->inthi = *end;
         __dhcp_intvl_node_update(exist);
      }
   }
   MUTEX_UNLOCK(&head->lock);

   return -(exist == NULL);
}

int
ArgusDhcpIntvlTreeRemove(struct ArgusDhcpIntvlTree *head,
                         const struct timeval * const intlo,
                         struct ArgusDhcpStruct * const ads)
{
   struct ArgusDhcpIntvlNode *node;
   struct ArgusDhcpIntvlNode search;

   search.intlo = *intlo;
   search.data = ads;
   MUTEX_LOCK(&head->lock);
   node = RB_FIND(dhcp_intvl_tree, &head->inttree, &search);
   if (node) {
      if (node->data == ads) {
         RB_REMOVE(dhcp_intvl_tree, &head->inttree, node);
         if (head->count > 0)
            head->count--;
      } else {
         DEBUGLOG(1, "%s: FOUND WRONG ArgusDhcpStruct\n", __func__);
      }
   }
   MUTEX_UNLOCK(&head->lock);

   if (node)
      ArgusFree(node);

   DEBUGLOG(4, "%s() returned %d\n", __func__, -(node == NULL));
   return -(node == NULL);
}

struct ArgusDhcpIntvlNode *
IntvlTreeFind(struct ArgusDhcpIntvlTree *head,
               struct timeval *intlo,
               struct ArgusDhcpStruct *ads)
{
   struct ArgusDhcpIntvlNode node = {
      .intlo = *intlo,
      .data = ads,
   };
   struct ArgusDhcpIntvlNode *res;

   MUTEX_LOCK(&head->lock);
   res = RB_FIND(dhcp_intvl_tree, &head->inttree, &node);
   if (res)
      ArgusDhcpStructUpRef(res->data);
   MUTEX_UNLOCK(&head->lock);

   return res;
}

int
IntvlTreeForEach(struct ArgusDhcpIntvlTree * const head,
                  IntvlTreeCallback cb, void *cp_arg0)
{
   int rv = 0;
   struct ArgusDhcpIntvlNode *node;

   MUTEX_LOCK(&head->lock);
   RB_FOREACH(node, dhcp_intvl_tree, &head->inttree) {
      rv = cb(cp_arg0, node);
      if (rv < 0)
         goto unlock;
   }

unlock:
   MUTEX_UNLOCK(&head->lock);
   return rv;
}

/* returns 1 if overlap, 0 if not */
static int
__test_overlap(struct ArgusDhcpIntvlNode *node,
               const struct timeval * const start,
               const struct timeval * const end)
{
   if ((timercmp(&node->intlo, start, <=)
        && timercmp(&node->inthi, start, >=))
       || (timercmp(&node->intlo, start, >=)
           && timercmp(&node->intlo, end, <=)))
      return 1;
   return 0;
}

/* IntvlTreeForEachOverlaps()
 * Run supplied callback for each node in the inteval tree with
 * time range that overlaps in the supplied range.  Returns zero on
 * success and passes along the return value of the callback if
 * that function ever fails.  The refcount for each node passed
 * to the callback is first incremented.  It is the responsibility
 * of the caller to decrement the refcount(s) when finished with the
 * dhcp structure(s).
 */
int
IntvlTreeForEachOverlaps(struct ArgusDhcpIntvlTree * const head,
                         IntvlTreeCallback cb, void *cp_arg0,
                         const struct timeval * const start,
                         const struct timeval * const end)
{
   struct ArgusDhcpIntvlNode *node;
   int rv = 0;

   MUTEX_LOCK(&head->lock);
   RB_FOREACH(node, dhcp_intvl_tree, &head->inttree) {
      if (timercmp(&node->intlo, end, >))
         /* tree is ordered by intlo, so if the start times are now
          * past the range end time we can quit.
          */
         break;
      if (__test_overlap(node, start, end)) {
         ArgusDhcpStructUpRef(node->data);
         rv = cb(cp_arg0, node);
         if (rv < 0)
            break;
      }
   }

   MUTEX_UNLOCK(&head->lock);
   return rv;
}

struct string {
   char *str;
   size_t len;
   size_t remain;
};

extern struct ArgusParserStruct *ArgusParser;

static int
__dump_tree_structure_cb(void *arg, struct ArgusDhcpIntvlNode *node)
{
   struct string *s = arg;
   char stime[64] = {0,}, etime[64] = {0,};
   char subtreehi[64] = {0,};
   char *macstr;
   char *ipstr;

   /* Take a chance on not locking the ArgusDhcpStruct lock (node->data->lock)
    * since the xid and chaddr fields never change after the "ads" is created.
    * The ads will not disappear from underneath us since the tree is locked
    * and the tree holds a reference to the ads.
    */

   ArgusPrintTime(ArgusParser, stime, sizeof(stime), &node->intlo);
   ArgusPrintTime(ArgusParser, etime, sizeof(etime), &node->inthi);
   ArgusPrintTime(ArgusParser, subtreehi, sizeof(subtreehi), &node->subtreehi);
   macstr = strdup(etheraddr_string(ArgusParser, (u_char *)&node->data->chaddr[0]));
   if (!macstr)
      return -1;

   /* not always right -- find accepted reply */
   ipstr = strdup(ipaddr_string(&node->data->rep.yiaddr.s_addr));
   if (!ipstr) {
      free(macstr);
      return -1;
   }

   snprintf_append(s->str, &s->len, &s->remain, "\"0x%08x_%lu\"",
                   node->data->xid, node->intlo.tv_sec);

   snprintf_append(s->str, &s->len, &s->remain,
                   " [label=\"%s -> %s\\n[%s, %s)\\n|%s|\"]\n",
                   macstr, ipstr, stime, etime, subtreehi);

   if (RB_LEFT(node,inttree))
      snprintf_append(s->str, &s->len, &s->remain,
                      "\"0x%08x_%lu\" -> \"0x%08x_%lu\" [label=\"L\"]\n",
                      node->data->xid, node->intlo.tv_sec,
                      RB_LEFT(node,inttree)->data->xid,
                      RB_LEFT(node,inttree)->intlo.tv_sec);

   if (RB_RIGHT(node,inttree))
      snprintf_append(s->str, &s->len, &s->remain,
                      "\"0x%08x_%lu\" -> \"0x%08x_%lu\" [label=\"R\"]\n",
                      node->data->xid, node->intlo.tv_sec,
                      RB_RIGHT(node,inttree)->data->xid,
                      RB_RIGHT(node,inttree)->intlo.tv_sec);

   free(ipstr);
   free(macstr);

   return 0;
}

int
IntvlTreeDump(struct ArgusDhcpIntvlTree *it, char *str, size_t strlen)
{
   struct string s;

   s.str = str;
   s.len = 0;
   s.remain = strlen-1;

   if (s.str == NULL)
      return -1;

   *s.str = '\0';
   snprintf_append(s.str, &s.len, &s.remain, "digraph \"intervaltree\" {\n");
   IntvlTreeForEach(it, __dump_tree_structure_cb, &s);
   snprintf_append(s.str, &s.len, &s.remain, "}");

   return 0;
}

struct invecAddrFilterStruct {
   unsigned char chaddr[16];
   struct invecStruct x;
   uint8_t hlen;
};

static int
__cb_intvl_tree_build_array(void *arg, struct ArgusDhcpIntvlNode *node)
{
   struct invecAddrFilterStruct *filt = arg;

   if (filt->x.used == filt->x.nitems)
      return 0;

   if (filt->hlen > 0) {
      if (node->data->hlen != filt->hlen)
         /* hardware address lengths are different - no match */
         return 0;

      if (memcmp(filt->chaddr, node->data->chaddr, filt->hlen))
         /* hardware address contents differ - no match */
         return 0;
   }

   filt->x.invec[filt->x.used].data = node->data;
   filt->x.invec[filt->x.used].intlo = node->intlo;
   filt->x.invec[filt->x.used].inthi = node->inthi;
   filt->x.used++;
   return 0;
}

/* RabootpIntvlTreeOverlapsRange() returns the number of elements
 * in xvec that were set.  The refcount for every ArgusDhcpStruct
 * returned in the array is incremented; it is necessary for the
 * caller to decrement the refcounts when finished with the array.
 */
ssize_t
IntvlTreeOverlapsRangeWithFilter(struct ArgusDhcpIntvlTree *in,
                                 const struct timeval * const start,
                                 const struct timeval * const stop,
                                 struct ArgusDhcpIntvlNode *invec,
                                 size_t nitems,
                                 const unsigned char * const chaddr,
                                 uint8_t hlen)
{
   int rv;
   struct invecAddrFilterStruct filt = {
      .x = {
         .nitems = nitems,
         .used = 0,
         .invec = invec,
      },
      .hlen = hlen,
   };

   if (hlen)
      memcpy(filt.chaddr, chaddr, hlen);

   rv =  IntvlTreeForEachOverlaps(in, __cb_intvl_tree_build_array, &filt,
                                  start, stop);

   if (rv < 0)
      return rv;

   return filt.x.used;
}

ssize_t
IntvlTreeOverlapsRange(struct ArgusDhcpIntvlTree *in,
                       const struct timeval * const start,
                       const struct timeval * const stop,
                       struct ArgusDhcpIntvlNode *invec, size_t nitems)
{
   return IntvlTreeOverlapsRangeWithFilter(in, start, stop, invec, nitems,
                                           NULL, 0);
}

size_t
IntvlTreeCount(struct ArgusDhcpIntvlTree *head)
{
   size_t count = 0;
   if (MUTEX_LOCK(&head->lock) == 0) {
      count = head->count;
      MUTEX_UNLOCK(&head->lock);
   }
   return count;
}
