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
 * Known Context Calcuations
 *
 * Calculate a context matching score as described in the Trac page
 * "ContextDevelopment".  Find a weighted percentage of matching
 * attribute counts and scale by the disctinct number of attribute
 * types that matched.
 *
 * If building with GCC, or compatible, and SSE2 is enabled (-msse2)
 * RacontextKnownContextCalcOne() will use vector multiplies
 * (pmuludq on x86_64).  If SSE2 is not enabled, the same code
 * will result in individual imul instructions.
 */

static unsigned int weights[NUM_CTX_ATTRIB_MULT4]
#ifdef __GNUC__
__attribute__((aligned(16)))
#endif
= {
   /* CTX_ATTRIB_BSSID */                       10,
   /* CTX_ATTRIB_DHCP_SERVER_MAC */             10,
   /* CTX_ATTRIB_NEXT_HOP_MAC */                10,
   /* CTX_ATTRIB_SLAAC_PREFIX */                9,
   /* CTX_ATTRIB_DHCP_DNS_SERVER */             8,
   /* CTX_ATTRIB_DHCP_DNS_DOMAIN */             8,
   /* CTX_ATTRIB_DHCP_NEXTHOP */                6,
   /* CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME */     1,
   /* CTX_ATTRIB_IGMP_QUERIER_MAC */            6,
   /* CTX_ATTRIB_IGMP_QUERIER_ADDRESS */        6,
   /* CTX_ATTRIB_MCAST_SOURCE_MAC */            3,
   /* CTX_ATTRIB_BCAST_SOURCE_MAC */            3,
   /* CTX_ATTRIB_MCAST_DEST_MAC */              1,
};

#ifdef __GNUC__
typedef unsigned int v4ui __attribute__ ((vector_size (16)));
#endif

/* counts MUST be aligned to 16 bytes */
static inline unsigned long long
__calc_total_weight(unsigned int *counts)
{
   int i;
   unsigned long long total = 0;
#ifdef __GNUC__
   static const size_t arraylen = NUM_CTX_ATTRIB_MULT4;
   int vcount;

   for (vcount = 0; vcount < arraylen; vcount += 4) {
      v4ui w = *(v4ui *)&weights[vcount];
      v4ui c = *(v4ui *)&counts[vcount];
      v4ui prod = w * c;

      for (i = 0; i < 4; i++)
         total += prod[i];
   }

#else
   for (i = 0; i < NUM_CTX_ATTRIB; i++)
      total += weights[i] * match->attr_match_counts[i];
#endif

   return total;
}

static int
RacontextKnownContextCalcOne(struct racontext *ctx,
                             struct known_context_match *match)
{
   unsigned long long total;

   total = __calc_total_weight(&match->attr_match_counts[0]);
   if (match->total_weight) {
      match->score = (double)total / match->total_weight
                     * match->distict_attr_types;
      return 0;
   }
   return -EINVAL;
}

unsigned long long
RacontextTotalWeightCalc(unsigned int *counts)
{
   return __calc_total_weight(counts);
}

int
RacontextKnownContextCalc(struct racontext *ctx)
{
   struct known_context_match *match;
   double max_score = 0.;
   int rv = 0;

   for (match = KnownContextTreeFirst(&ctx->known_contexts);
        (rv == 0) && match;
        match = KnownContextTreeNext(match)) {
      rv = RacontextKnownContextCalcOne(ctx, match);
      if (rv == 0) {
         if (match->score > max_score) {
            max_score = match->score;
            if (max_score > RACONTEXT_MIN_MATCHING_SCORE)
               ctx->match = match;
         }
      }
   }
   return rv;
}
