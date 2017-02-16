#ifndef __RABOOTP_CALLBACK_H
# define __RABOOTP_CALLBACK_H

# include "bsd/sys/queue.h"

typedef int (*rabootp_cb)(const void * const, /* parsed */
                          void *,             /* cached */
                          void *);

struct rabootp_cbentry {
   rabootp_cb func;
   void *arg;
   SLIST_ENTRY(rabootp_cbentry) list;
};

SLIST_HEAD(rabootp_cblist, rabootp_cbentry);

int rabootp_cb_register(struct rabootp_cblist *, rabootp_cb, void *);
int rabootp_cb_unregister(struct rabootp_cblist *, rabootp_cb);
int rabootp_cb_exec(struct rabootp_cblist *,
                    const void * const, /* parsed */
                    void *);            /* cached */
void rabootp_cb_cleanup(struct rabootp_cblist *);

#endif
