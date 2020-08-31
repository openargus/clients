#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "racontext.h"

/* Maintain a tree of per-(sid,inf) context trees. */

#pragma GCC diagnostic ignored "-Wunused-function"

static int
__RacontextTree_compare(struct RacontextTree *a, struct RacontextTree *b)
{
   return strcmp(a->srcidstr, b->srcidstr);
}

RB_GENERATE_STATIC(sid_tree, RacontextTree, entry, __RacontextTree_compare);

struct sid_tree *
SidtreeAlloc(void)
{
   struct sid_tree *t = ArgusMalloc(sizeof(*t));

   if (t == NULL)
      return NULL;

   RB_INIT(t);
   return t;
}

int
SidtreeInsert(struct sid_tree *t, struct RacontextTree *e)
{
   struct RacontextTree *exist;

   exist = RB_INSERT(sid_tree, t, e);
   if (exist)
      return -EEXIST;

   return 0;
}

int
SidtreeFind(struct sid_tree *t, const char * const srcidstr,
            struct RacontextTree **target)
{
   struct RacontextTree exemplar;

   exemplar.srcidstr = strdup(srcidstr);
   if (exemplar.srcidstr == NULL)
      return -ENOMEM;

   *target = RB_FIND(sid_tree, t, &exemplar);
   free(exemplar.srcidstr);

   return 0;
}

int
SidtreeFindByRecordStruct(struct sid_tree *t, struct RacontextTree **target,
                          struct ArgusParserStruct *parser,
                          struct ArgusRecordStruct *argus)
{
   char *srcidstr = ArgusMalloc(RCT_SIDINF_LEN_MAX + 16);
   int rv;

   if (srcidstr == NULL)
      return -ENOMEM;

   ArgusPrintSourceID(parser, srcidstr, argus, RCT_SIDINF_LEN_MAX);
   rv = SidtreeFind(t, srcidstr, target);
   ArgusFree(srcidstr);
   return rv;
}

int
SidtreeRemove(struct sid_tree *t, struct RacontextTree *e)
{
   RB_REMOVE(sid_tree, t, e);
   return 0;
}

void
SidtreeFree(struct sid_tree *t)
{
   if (t == NULL)
      return;

   while(!RB_EMPTY(t)) {
      struct RacontextTree *e = RB_ROOT(t);

      RB_REMOVE(sid_tree, t, e);
      RacontextTreeFree(e);
   }

   ArgusFree(t);
}

int
SidtreeForeach(struct sid_tree * t, sid_tree_callback cb, void *arg)
{
   struct RacontextTree *e;
   int rv = 0;

   RB_FOREACH(e, sid_tree, t) {
      rv = cb(e, arg);
      if (rv < 0)
         break;
   }
   return rv;
}

void
SidtreeDump(struct sid_tree *t)
{
   struct RacontextTree *e;

   RB_FOREACH(e, sid_tree, t) {
      RacontextTreeDump(e);
   }
}

#include "argus_mysql.h"
#include "argus_util.h"
#include "argus_client.h"

int
SidtreeScore(const struct ArgusParserStruct * const parser,
             MYSQL *mysql, struct sid_tree *t)
{
   struct RacontextTree *e;
   int rv;
   int res = 0;

   RB_FOREACH(e, sid_tree, t) {
      rv = RacontextTreeScore(parser, mysql, e);
      if (rv < 0)
         res = -1;
   }
   return res;
}
