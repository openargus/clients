#include "argus_util.h"
#include "argus_client.h"
#include "rabootp_callback.h"

int rabootp_cb_register(struct rabootp_cblist *l, rabootp_cb cb,
                        void *arg)
{
   struct rabootp_cbentry *elm;

   elm = ArgusMalloc(sizeof(*elm));
   if (elm == NULL)
      return -1;

   elm->func = cb;
   elm->arg = arg;
   memset(&elm->list, 0 , sizeof(elm->list));
   SLIST_INSERT_HEAD(l, elm, list);
   return 0;
}

int rabootp_cb_unregister(struct rabootp_cblist *l, rabootp_cb cb)
{
   struct rabootp_cbentry *elm = SLIST_FIRST(l);

   if (elm == NULL)
      return -1;

   if (elm->func == cb) {
      SLIST_REMOVE_HEAD(l, list);
      ArgusFree(elm);
   } else {
      while (SLIST_NEXT(elm, list)->func != cb)
         elm = SLIST_NEXT(elm, list);
      SLIST_REMOVE_AFTER(elm, list);
   }
   return 0;
}

int rabootp_cb_exec(struct rabootp_cblist *l,
                    const void * const parsed,
                    void *cached)
{
   /* step through the list and run each of the callbacks */

   struct rabootp_cbentry *elm;
   int failed = 0;

   SLIST_FOREACH(elm, l, list) {
      if (elm->func(parsed, cached, elm->arg) < 0)
         failed--;
   }
   return failed;
}

void rabootp_cb_init(struct rabootp_cblist *l)
{
   SLIST_INIT(l);
}

void rabootp_cb_cleanup(struct rabootp_cblist *l)
{
   struct rabootp_cbentry *elm;

   while ((elm = SLIST_FIRST(l))) {
      SLIST_REMOVE_HEAD(l, list);
      ArgusFree(elm);
   }
}
