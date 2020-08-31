#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif

#include <ctype.h>
#include <stdlib.h>
#include "racontext_process_dhcp.h"
#include "racontext_query_dhcp.h"
#include "racontext_attribute_dhcp.h"
#include "../radhcp/rabootp_memory.h"

struct callback_args {
   const struct ArgusParserStruct * const parser;
   struct RaBinProcessStruct *rbps;
   const configuration_t * const config;
   MYSQL *RaMySQL;
};

/* RacontextExtractSid:
 *
 * Provided the srcidstr from a RacontextTree, return pointers to SID and
 * interface strings with extraneous whitespace removed.
 *
 * Caller is responsible for free()ing the pointer returned by this
 * function.  However, the (char *)sid and (char *)inf pointers should NOT
 * be freed.
 */
static char *
RacontextExtractSid(const char * const srcidstr, char **sid, char **inf)
{
   char *srcidstr_origptr;
   char *tmp;

   srcidstr_origptr = strdup(srcidstr);
   if (srcidstr_origptr == NULL)
      return NULL;

   /* remove trailing spaces put there by ArgusPrintSourceID */
   *sid = strrchr(srcidstr_origptr, ' ');
   if (*sid) {
      while (**sid == ' ' && *sid > srcidstr_origptr) {
         **sid = 0;
         (*sid)--;
      }
   }

   /* remove leading spaces put there by ArgusPrintSourceID() */
   *sid = srcidstr_origptr;
   while (**sid == ' ')
      (*sid)++;

   *inf = strchr(*sid, '/');
   if (*inf) {
      **inf = 0;	/* cover up the slash with a NULL */
      (*inf)++;		/* the interface name should start with the next char */
   } else {
      *inf = NULL;
   }

   /* now convert everything to lowercase */
   for (tmp = *sid; tmp && *tmp; tmp++)
      if (*tmp >= 'A' && *tmp <= 'Z')
         *tmp = tolower(*tmp);

   for (tmp = *inf; tmp && *tmp; tmp++)
      if (*tmp >= 'A' && *tmp <= 'Z')
         *tmp = tolower(*tmp);

   return srcidstr_origptr;
}

static int
RacontextProcessDhcpLeases(struct RacontextTree *t,
                           struct ArgusDhcpIntvlNode *nodes, size_t nleases,
                           const configuration_t * const config)
{
   int rv;
   size_t i;
   struct racontext *ctx = NULL;

   for (i = 0; i < nleases; i++) {
      rv = RacontextTreeInsert(t, &nodes[i].intlo, &nodes[i].inthi, config,
                               &ctx);
      if (rv < 0)
         continue;

      if (ctx)
         RacontextAttributeDhcpUpdate(ctx, &nodes[i]);
   }
   return 0;
}

static int
RacontextProcessDhcpUseDatabase(MYSQL *mysql, const char * const dbname)
{
   return 0;
}

static int
RacontextProcessDhcpOne(struct RacontextTree *t, void *args)
{
   struct ArgusDhcpIntvlNode *nodes = NULL;
   size_t nleases = 1024;
   struct callback_args *callback_args = args;
   char *srcidstr_origptr;
   char *srcidstr; /* local copy of t->srcidstr with whitespace cruft and
                    * interface name trimmed */
   char *inf;      /* interface name from t->srcidstr */
   int used;
   int rv;
   int i;

   srcidstr_origptr = RacontextExtractSid(t->srcidstr, &srcidstr, &inf);
   if (srcidstr_origptr == NULL)
      return -ENOMEM;

   /* Tell mysql to switch to a per-SID database */
   rv = RacontextProcessDhcpUseDatabase(callback_args->RaMySQL, srcidstr);
   if (rv < 0) {
      free(srcidstr_origptr);
      return rv;
   }

   used = RacontextQueryDhcp(callback_args->parser, callback_args->rbps,
                             (const unsigned char * const)callback_args->config->clientmac,
                             /* inf, */ &nodes, nleases);
   if (used > 0) {
      rv = RacontextProcessDhcpLeases(t, nodes, used, callback_args->config);
      for (i = 0; i < used; i++)
         ArgusDhcpStructFree(nodes[i].data);
   }

   if (nodes)
      ArgusFree(nodes);
   free(srcidstr_origptr);
   return rv;
}

/* For each sid+inf tree, query the per-sid database for information
 * pertaining to the client.  The client mac address can come from
 * configuration or from a supplemental management record.
 */

int
RacontextProcessDhcp(const struct ArgusParserStruct * const parser,
                      const configuration_t * const config,
                      struct RaBinProcessStruct *rbps,
                      struct sid_tree *RacontextSidtree, MYSQL *RaMySQL)
{
   int rv;
   struct callback_args callback_args = {
      .parser = parser,
      .config = config,
      .RaMySQL = RaMySQL,
      .rbps = rbps,
   };

   rv = SidtreeForeach(RacontextSidtree, RacontextProcessDhcpOne,
                       &callback_args);

   return rv;
}
