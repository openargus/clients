#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "argus_util.h"
#include "argus_threads.h"
#include "rabootp.h"

static pthread_mutex_t __memlock = PTHREAD_MUTEX_INITIALIZER;

struct ArgusDhcpStruct *
ArgusDhcpStructAlloc(void)
{
   struct ArgusDhcpStruct *res;

   res = ArgusMallocAligned(sizeof(struct ArgusDhcpStruct), 64);
   if (res) {
      memset(res, 0, sizeof(struct ArgusDhcpStruct));
      res->refcount = 1;
      res->lock = ArgusMalloc(sizeof(*res->lock));
      if (res->lock == NULL) {
         ArgusFree(res);
         return NULL;
      }
      MUTEX_INIT(res->lock, NULL);
   }
   return res;
}

void
ArgusDhcpStructFreeReplies(void *v)
{
   struct ArgusDhcpStruct *a = v;
   struct ArgusDhcpV4LeaseOptsStruct *rep = &a->rep;

   while (rep) {
      if (rep->hostname)
         free(rep->hostname);
      if (rep->domainname)
         free(rep->domainname);
      rep = rep->next;
   }
}

void
ArgusDhcpStructFreeClientID(void *v)
{
   struct ArgusDhcpStruct *a = v;

   if (a->req.client_id_len > 8 && a->req.client_id.ptr)
      ArgusFree(a->req.client_id.ptr);
}

void
ArgusDhcpStructFree(void *v)
{
   struct ArgusDhcpStruct *a = v;

   if (MUTEX_LOCK(&__memlock) == 0) {
      if (--(a->refcount) == 0) {
         ArgusDhcpStructFreeClientID(v);
         ArgusDhcpStructFreeReplies(v);
         MUTEX_DESTROY(a->lock);
         ArgusFree(a->lock);
         ArgusFree(a);
      }
      MUTEX_UNLOCK(&__memlock);
   }
}

void
ArgusDhcpStructUpRef(struct ArgusDhcpStruct *a)
{
   if (MUTEX_LOCK(&__memlock) == 0) {
      a->refcount++;
      MUTEX_UNLOCK(&__memlock);
   }
}
