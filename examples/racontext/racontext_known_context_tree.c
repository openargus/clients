#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif
#include <stdio.h>
#include <sys/syslog.h>
#include <errno.h>
#include <string.h>		/* memcmp */
#include "argus_compat.h"
#include "argus_util.h"
#include "argus_client.h"
#include "argus_parser.h"
#include "racontext.h"

/*
 * Known Context Tree
 *
 * This tree holds information about known contexts for which a candidate
 * context has matching attributes.  Among other details, it has the known
 * context's identifier (UUID) and an array of counters to track how many
 * times each attribute type was matched.
 */

#pragma GCC diagnostic ignored "-Wunused-function"

static int
__known_context_match_compare(struct known_context_match *a,
                              struct known_context_match *b)
{
   return memcmp(a->cid, b->cid, sizeof(uuid_t));
}

RB_GENERATE_STATIC(known_context_tree, known_context_match, tree, \
                   __known_context_match_compare);

/* we don't allocate these separately since the tree head is included
 * directly in the racontext structure.  Just initialize here.
 */
void
KnownContextTreeInit(struct known_context_tree *kct)
{
   RB_INIT(kct);
}

struct known_context_match *
KnownContextMatchAlloc(void)
{
   struct known_context_match *tmp;

   /* allocate on 16-byte boundary for SIMD purposes */
   tmp = ArgusMallocAligned(sizeof(struct known_context_match), 16);
   memset(tmp, 0, sizeof(struct known_context_match));
   return tmp;
}

void
KnownContextMatchFree(struct known_context_match *kcm)
{
   ArgusFree(kcm);
}

char ArgusDebugOutputBuffer[MAXSTRLEN];

void
KnownContextDump(const struct known_context_match * const kcm)
{
   char uuidstr[37];
   char *buf = ArgusDebugOutputBuffer;
   int i;

   uuid_unparse_lower(kcm->cid, uuidstr);

#ifdef ARGUSDEBUG
   sprintf(buf, "known context : CID %s : SCORE %f : COUNTS [", uuidstr, kcm->score);
   for (i = 0; i < NUM_CTX_ATTRIB; i++)
      sprintf(&buf[strlen(buf)], "%u%s", kcm->attr_match_counts[i], i < (NUM_CTX_ATTRIB-1) ? "," : "");
   ArgusDebug (0, "%s]\n", buf);
#endif
}

void
KnownContextMatchDump(const struct known_context_match * const kcm)
{
   char uuidstr[37];
   char *buf = ArgusDebugOutputBuffer;
   int i;

   uuid_unparse_lower(kcm->cid, uuidstr);

#ifdef ARGUSDEBUG
   sprintf(buf, "match context : CID %s : SCORE %f : COUNTS [", uuidstr, kcm->score);
   for (i = 0; i < NUM_CTX_ATTRIB; i++)
      sprintf(&buf[strlen(buf)], "%u%s", kcm->attr_match_counts[i], i < (NUM_CTX_ATTRIB-1) ? "," : "");
   ArgusDebug (0, "%s]\n", buf);
#endif
}

int
KnownContextTreeInsert(struct known_context_tree *kct, uuid_t cid,
                        struct known_context_match **kcm_out)
{
   struct known_context_match *tmp = KnownContextMatchAlloc();
   struct known_context_match *exist;

   if (tmp == NULL)
      return -ENOMEM;

   memcpy(tmp->cid, cid, sizeof(uuid_t));
   exist = RB_INSERT(known_context_tree, kct, tmp);
   if (exist) {
      KnownContextMatchFree(tmp);
      if (kcm_out)
         *kcm_out = exist;
      return -EEXIST;
   }

   if (kcm_out)
      *kcm_out = tmp;
   return 0;
}

int
KnownContextTreeFind(struct known_context_tree *kct, uuid_t cid,
                     struct known_context_match **kcm_out)
{
   struct known_context_match tmp;
   struct known_context_match *target;

   memcpy(tmp.cid, cid, sizeof(uuid_t));
   target = RB_FIND(known_context_tree, kct, &tmp);
   if (target == NULL)
      return -ENOENT;

   if (kcm_out)
      *kcm_out = target;
   return 0;
}

/* Empties the tree and frees the contents, but does NOT free *kct. */
void
KnownContextTreeFree(struct known_context_tree *kct)
{
   while (!RB_EMPTY(kct)) {
      struct known_context_match *kcm = RB_ROOT(kct);

      RB_REMOVE(known_context_tree, kct, kcm);
      KnownContextMatchFree(kcm);
   }
}

/* Maybe cursor-like functions are better than a foreach function? */
struct known_context_match *
KnownContextTreeFirst(struct known_context_tree *kcm)
{
   return RB_MIN(known_context_tree, kcm);
}

struct known_context_match *
KnownContextTreeNext(struct known_context_match *kcm)
{
   return RB_NEXT(known_context_tree, NULL, kcm);
}

void
KnownContextTreeDump(struct known_context_tree *kct)
{
   struct known_context_match *kcm;

   RB_FOREACH(kcm, known_context_tree, kct) {
      KnownContextDump(kcm);
   }
}
