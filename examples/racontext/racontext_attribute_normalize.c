#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif
#include <stdio.h>
#include <sys/syslog.h>
#include <errno.h>
#include <arpa/inet.h>
#include "argus_compat.h"
#include "argus_util.h"
#include "argus_client.h"
#include "argus_parser.h"
#include "racontext.h"

static unsigned int
__count_distinct(unsigned int *counts)
{
   int i;
   unsigned int distinct = 0;

   for (i = 0; i < NUM_CTX_ATTRIB; i++)
      if (counts[i])
         distinct++;

   return distinct;
}

/* RacontextNormalizeAttributeOccurances:
 * Step through the tree of attributes and divide each occurance counter
 * by the duration of the context.  For each attribute type, count the
 * number of attributes with a normalized value that meets the threshold
 * for creating a new context definition.
 *
 * Counts is an array of at least NUM_CTX_ATTRIB elements and must first
 * be initialized by caller.  RacontextNormalizeAttributeOccurences()
 * will increment the values in the array.
 *
 * Returns the number of distinct attribute types in the *counts array
 * on success.
 */

unsigned int
RacontextNormalizeAttributeOccurences(struct racontext *ctx,
                                      unsigned int *counts)
{
   struct racontext_attribute *attr;
   struct timeval diff;
   float norm;

   for (attr = RacontextAttrTreeFirst(ctx->attrs);
        attr;
        attr = RacontextAttrTreeNext(attr)) {
      timersub(&ctx->ltime, &ctx->stime, &diff);

      if (diff.tv_sec < 1)
         /* less than a second or negative; ignore */
         continue;

      norm = (float)attr->occurrences / diff.tv_sec;
      if (attr->attrib_num >= CTX_ATTRIB_MCAST_SOURCE_MAC &&
          norm <= RACONTEXT_OCCURRENCES_NORM_THRESHOLD)
         continue;

      attr->occurrences_norm = norm;
      counts[attr->attrib_num]++;
   }

   return __count_distinct(counts);
}
