#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif
#include <stdio.h>
#include <sys/syslog.h>
#include <errno.h>
#include "argus_compat.h"
#include "argus_util.h"
#include "argus_client.h"
#include "argus_parser.h"
#include "racontext.h"

/* Context Tree
 *
 * This tree holds, for a particular Argus SourceID, nodes that
 * represent a particular range of times during which network
 * activity was observed.  Periods of silence on the network are
 * implicit; there are no nodes in the tree to represent times
 * during which there was an absence of network activity.  Each
 * node has a start time and a last time.  The duration is determined
 * by the ltime of the most recent flow record.  If the start time
 * of the next flow record processed is greater than the start time
 * of the most recent node and is less than the (node last time +
 * MIN_SILENCE), the context-tree node is extended to the ltime of
 * the current flow record.  If the flow record stime is greater
 * than the (node last time + MIN_SILENCE) then a new node is added
 * to the context tree with the start and last times taken from the
 * flow record.
 *
 * --> A prerequisite of the input flow data is that it MUST BE
 * sorted in argus record start time order.
 *
 * --> A property of the resulting context tree is that contexts
 * DO NOT overlap in time.  This avoids the complexity of an "interval
 * tree".
 */

#pragma GCC diagnostic ignored "-Wunused-function"

static int
__racontext_node_compare(struct racontext *a, struct racontext *b)
{
   if (a->stime.tv_sec == b->stime.tv_sec
       && a->stime.tv_usec == b->stime.tv_usec)
      return 0;

   if (timercmp(&a->stime, &b->stime, <))
      return -1;

   return 1;
}

RB_GENERATE_STATIC(racontext_tree, racontext, tree, __racontext_node_compare);

struct RacontextTree *
RacontextTreeAlloc(struct ArgusParserStruct *parser,
                   struct ArgusRecordStruct *argus)
{
   struct RacontextTree *rct = ArgusMalloc(sizeof(*rct));

   if (rct == NULL) {
      ArgusLog(LOG_WARNING, "%s unable to allocate tree\n", __func__);
      return NULL;
   }

   rct->srcidstr = ArgusMalloc(RCT_SIDINF_LEN_MAX + 16);

   if (rct->srcidstr == NULL) {
      ArgusLog(LOG_WARNING, "%s unable to allocate srcid string\n", __func__);
      ArgusFree(rct);
      return NULL;
   }

   memset(&rct->entry, 0, sizeof(rct->entry));

   ArgusPrintSourceID(parser, rct->srcidstr, argus, RCT_SIDINF_LEN_MAX);
   RB_INIT(&rct->head);
   return rct;
}

/* RacontextTreeInsert() will always create a new node in the list unless
 * an existing node has exactly the same start time.  The lasttime
 * of the previous node (if any) will be truncated if necessary to
 * avoid overlapping the new node.  The lasttime of the new node will
 * be truncated to the value of the next node's startime to avoid
 * overlapping.
 *
 * No assumptions are made about the order of start times for
 * successive calls to this function.
 */
int
RacontextTreeInsert(struct RacontextTree *rct,
                    const struct timeval * const startime,
                    const struct timeval * const lasttime,
                    const configuration_t * const config,
                    struct racontext **newctx)
{
   struct racontext *exist;
   struct racontext *next;
   struct racontext *prev;
   struct racontext *ctx = RacontextAlloc();

   if (ctx == NULL)
      return -ENOMEM;

   ctx->stime = *startime;
   ctx->ltime = *lasttime;
ctx->source = 1;
   exist = RB_INSERT(racontext_tree, &rct->head, ctx);
   if (exist) {
      RacontextFree(ctx);
      return -EEXIST;
   }

   /* provide the caller with a pointer to the new context, if requested */
   if (newctx)
      *newctx = ctx;

   prev = RB_PREV(racontext_tree, NULL, ctx);
   next = RB_NEXT(racontext_tree, NULL, ctx);

   if (prev && timercmp(&prev->ltime, &ctx->stime, >))
      prev->ltime = ctx->stime;
   if (next && timercmp(&ctx->ltime, &next->stime, >))
      ctx->ltime = next->stime;
   return 0;
}

/* RacontextTreeAppend() will either extend the range of times in
 * an existing context node or it will create a new context node
 * with a start time greater than the last time of the, currently,
 * most recent node.  Times are taken from the flow record, struct
 * ArgusRecordStruct *argus.  The configuration_t structure has
 * the threshold that must be met to create a new node.
 *
 * See note at the top of this file about sorting the input flow
 * records.
 */
int
RacontextTreeAppend(struct RacontextTree *rct,
                    struct ArgusRecordStruct *argus,
                    const configuration_t * const config,
                    struct racontext **newctx)
{
   struct racontext *exist;
   struct racontext *most_recent;
   int add_node = 0;

   if (RB_EMPTY(&rct->head))
      add_node = 1;
   else {
      struct timeval ltime;
      struct timeval recstime;
      struct timeval silence = {
         .tv_sec = config->silence_duration_sec,
      };

      most_recent = RB_MAX(racontext_tree, &rct->head);
      timeradd(&most_recent->ltime, &silence, &ltime);
      RaGetStartTime(argus, &recstime);
      if timercmp(&recstime, &ltime, >=)
         add_node = 1;
   }

   if (!add_node) { /* the most likely case */
      /* extend the time range of the newest node */
      RaGetLastTime(argus, &most_recent->ltime);
      if (newctx)
         *newctx = most_recent;
      return 0;
   } else {
      struct racontext *ctx = RacontextAlloc();

      RaGetStartTime(argus, &ctx->stime);
      RaGetLastTime(argus, &ctx->ltime);
      exist = RB_INSERT(racontext_tree, &rct->head, ctx);
      if (exist) {
         RacontextFree(ctx);
         return -EEXIST;
      }
      if (newctx)
         *newctx = ctx;
   }

   return 0;
}

int
RacontextTreeRemove(struct RacontextTree *rct,
                    struct racontext *ctx)
{
   RB_REMOVE(racontext_tree, &rct->head, ctx);
   return 0;
}

struct racontext *
RacontextTreeFind(struct RacontextTree *rct, struct timeval *when)
{
   struct racontext exemplar;
   struct racontext *target;

   exemplar.stime = *when;
   target = RB_NFIND(racontext_tree, &rct->head, &exemplar);
   if (target)
      target = RB_PREV(racontext_tree, NULL, target);
   else
      target = RB_MAX(racontext_tree, &rct->head);

#ifdef ARGUSDEBUG
 /* TODO: add some sanity checking here to make sure *when falls in the
  * range of times for the target context we found */
#endif

   return target;
}

void
RacontextTreeFree(struct RacontextTree *rct)
{
   if (rct == NULL)
      return;

   if (rct->srcidstr)
      ArgusFree(rct->srcidstr);

   while (!RB_EMPTY(&rct->head)) {
      struct racontext *ctx = RB_ROOT(&rct->head);

      RB_REMOVE(racontext_tree, &rct->head, ctx);
      KnownContextTreeFree(&ctx->known_contexts);
      RacontextFree(ctx);
   }

   ArgusFree(rct);
}

void
RacontextTreeDump(struct RacontextTree *rct)
{
   struct racontext *ctx;

   printf("\n\n=== SID %s ===\n", rct->srcidstr);
   RB_FOREACH(ctx, racontext_tree, &rct->head) {
      printf("context start %12ld.%06d end %12ld.%06d source %d\n",
             ctx->stime.tv_sec, (int)ctx->stime.tv_usec,
             ctx->ltime.tv_sec, (int)ctx->ltime.tv_usec, ctx->source);
      RacontextAttrTreeDump(ctx->attrs);
      KnownContextTreeDump(&ctx->known_contexts);
      if (ctx->match) {
         printf("matched context:  ");
         KnownContextMatchDump(ctx->match);
      }
   }
}

int
RacontextTreePullup(struct RacontextTree *rct, void *arg /* unused */)
{
   struct racontext *ctx;
   struct racontext *nxt;

   ctx = RB_MIN(racontext_tree, &rct->head);
   while (ctx) {
      nxt = RB_NEXT(racontext_tree, NULL, ctx);
      if (nxt == NULL)
         break;

      if ((!ctx->match && !nxt->match) ||
          (ctx->match && nxt->match &&
           memcmp(ctx->match->cid, nxt->match->cid, sizeof(uuid_t)) == 0)) {
         ctx->ltime = nxt->ltime;
         RB_REMOVE(racontext_tree, &rct->head, nxt);
         RacontextFree(nxt);
         continue;
      }

      ctx = nxt;
   }
   return 0;
}

#include <math.h>
#include "racontext_query_known_context.h"
#include "racontext_insert_known_context.h"
#include "argus_mysql.h"

int
RacontextTreeScore(const struct ArgusParserStruct * const parser,
                   MYSQL *mysql, struct RacontextTree *rct)
{
   struct racontext *ctx;
   int rv[3];
   int res = 0;
   unsigned distinct;
   unsigned int *counts;
   unsigned total_weight;
   uuid_t nid;
#ifdef ARGUSDEBUG
   char nidstr[37];
#endif

   counts = ArgusMallocAligned(sizeof(*counts) * NUM_CTX_ATTRIB_MULT4, 64);

   RB_FOREACH(ctx, racontext_tree, &rct->head) {
      rv[0] = RacontextQueryKnownContext(mysql, ctx);
      rv[1] = RacontextQueryIndex(mysql, ctx);
      rv[2] = RacontextKnownContextCalc(ctx);
      if (rv[0] < 0 || rv[1] < 0 || rv[2] < 0) {
         res = -1;
         continue;
      }

      /* After RacontextKnownContextCalc(), ctx->match is set if a match was
       * found.  If match is still NULL, consider defining a new context.
       */

      if (ctx->match)
         continue;

      /* First step, normalize the attribute occurance counts for time */
      memset(counts, 0, sizeof(*counts) * NUM_CTX_ATTRIB_MULT4);
      distinct = RacontextNormalizeAttributeOccurences(ctx, counts);
      total_weight = RacontextTotalWeightCalc(counts);

      /* if enough attribute meet the threshold for frequency and of
       * those that did, if there are enough distinct attribute types,
       * add a new definition to the database.
       */
      if (distinct < RACONTEXT_DISTINCT_TYPES_THRESHOLD)
         continue;

      uuid_generate(nid);

      /* allocate a match structure for this context, give it the NID
       * of the new context and set the score to +inf.
       */
      KnownContextTreeInsert(&ctx->known_contexts, nid, &ctx->match);
      if (ctx->match == NULL) {
#ifdef ARGUSDEBUG
         ArgusDebug(1, "%s failed to create new known context structure\n",
                    __func__);
#endif
         continue;
      }

      ctx->match->score = HUGE_VAL;
      ctx->match->total_weight = total_weight > UINT_MAX
                                 ? UINT_MAX : total_weight;
      rv[0] = RacontextInsertKnownContext(parser, ctx, nid, mysql,
                                          contexts_table_name);
#ifdef ARGUSDEBUG
      uuid_unparse_lower(nid, nidstr);
      ArgusDebug(2, "%s insert new known context for NID %s returned %d\n",
                 __func__, nidstr, rv[0]);
#endif
   }

   ArgusFree(counts);
   return res;
}
