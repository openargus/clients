#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <limits.h>
#include <arpa/inet.h>
#include <sys/syslog.h>
#include <uuid/uuid.h>
#include "argus_util.h"
#include "argus_client.h"
#include "argus_main.h"
#include "argus_dhcp.h"

#include "../radhcp/argus_print.h"
#include "racontext.h"
#include "racontext_sql_scan.h"
#include "racontext_query_known_context.h"

#if defined(CYGWIN)
# include <sys/cygwin.h>
# define USE_IPV6
#endif

#ifdef ARGUSDEBUG
# define DEBUGLOG(lvl, fmt...) ArgusDebug(lvl, fmt)
#else
# define DEBUGLOG(lvl, fmt...)
#endif

#include "argus_mysql.h"
#include "ramysqlinit.h"
#include <mysqld_error.h>

static const size_t context_query_columns = 3;
struct context_row {
    uuid_t cid;		/* binary */
    int64_t count;	/* MYSQL_TYPE_LONGLONG (bigint) */
    int32_t attrib_num;	/* MYSQL_TYPE_LONG (int) */
};

static ssize_t
RabootpPrintUuid(const struct ArgusParserStruct * const parser,
                 const void * const datum, char *str, size_t len)
{
   if (len < (sizeof(uuid_t)*2 +1))
      return -1;

   uuid_unparse_lower(*(uuid_t *)datum, str);
   return 36;
}

/* The order of SQL columns in this array must match the order
 * of columns in the SELECT statement.
 */
static const struct ArgusPrinterTable ContextPrinterTablep[] = {
   ARGUS_PRINT_INITIALIZER(context_row, attrib_num, "idx", \
                           NULL /* print */, "int", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           NULL /* bind */, \
                           RacontextSQLScanInt32),
   ARGUS_PRINT_INITIALIZER(context_row, count, "count", \
                           RabootpPrintUuid, "bigint", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           NULL /* bind */, \
                           RacontextSQLScanInt64),
   ARGUS_PRINT_INITIALIZER(context_row, cid, "cid", \
                           NULL /* print */, "binary(16)", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           NULL /* bind */, \
                           RacontextSQLScanUuid),
};

static int
RacontextQueryKnownContextScanSQL(
   const struct ArgusParserStruct * const parser,
   struct racontext *ctx, const MYSQL_BIND * const bindvec, size_t nitems)
{
   int max;
   int t;
   int res = 0;
   int idx = 0;
   struct context_row ctxrow;
   struct known_context_match *kcm;

   max = sizeof(ContextPrinterTablep)/sizeof(ContextPrinterTablep[0]);
   for (t = 0; t < max && idx < nitems; t++) {
      res = ArgusScanFieldSQL(parser, ContextPrinterTablep, &ctxrow,
                              t, &bindvec[idx]);
      if (res <= 0) {
          ArgusLog(
#ifdef ARGUSDEBUG
                   LOG_ERR,
#else
                   LOG_WARNING,
#endif
                   "%s: failed to scan SQL field in ContextPrinterTablep\n",
                   __func__);
          return res;
      }
      idx++;
   }

   /* KnownContextTreeInsert() will return either a pointer to a new
    * known context structure, or an existing.  We don't care which
    * in this case, so ignore the -EEXIST return value.
    */
   res = KnownContextTreeInsert(&ctx->known_contexts, ctxrow.cid, &kcm);
   if (res == -EEXIST)
      res = 0;

   if (res < 0)
      return res;

   if (ctxrow.attrib_num >= NUM_CTX_ATTRIB)
      return -EINVAL;

   /* The COUNT() function in SQL returns a BIGINT so make sure that,
    * in the unlikely event the count value is larger than what can be
    * stored in the context structure, we don't overflow.
    */
   if (ctxrow.count >= UINT_MAX)
      ctxrow.count = UINT_MAX;

   /* Since we are getting DISTINCT combinations of (cid,idx), each
    * attribute number (idx) should appear only once for each context
    * identifier (cid).  No need to accumulate and check for overflow
    * here - just assign.
    */
   kcm->attr_match_counts[ctxrow.attrib_num] = ctxrow.count;
   kcm->distict_attr_types++;

   return 0;
}


int
RacontextQueryKnownContext(MYSQL *mysql, struct racontext *ctx)
{
   char *query;
   size_t used = 0;
   size_t remain = RaMySQLGetMaxPacketSize();
   int rv;
   int count = 0;
   MYSQL_STMT *stmt;
   MYSQL_BIND resbind[context_query_columns];
   bool have_resbind = false;

   /* this will later need to be a list of tables queried from the index */
   static const char * const table = "testdata.contexts";

   if (RacontextAttrTreeEmpty(ctx->attrs))
      return 0;  /* no error, just nothing to do */

   stmt = mysql_stmt_init(mysql);
   if (stmt == NULL)
      return -ENOMEM;

   query = ArgusMalloc(remain);
   if (query == NULL)
      return -ENOMEM;

   snprintf_append(query, &used, &remain,
                   "SELECT idx,COUNT(idx) as count,cid FROM %s ",
                   table);

   rv = RacontextAttrTreeSqlWhere(ctx->attrs, query, &used, &remain);
   if (rv < 0)
      goto out;

   snprintf_append(query, &used, &remain, " GROUP BY idx, cid");
   snprintf_append(query, &used, &remain, " ORDER BY cid");
   DEBUGLOG(4, "%s QUERY: %s\n", __func__, query);

   memset(resbind, 0, sizeof(resbind));
   /* need an api change - we pass in a MYSQL*, but ArgusDhcpSqlQueryOneTable
    * uses the global RaMySQL
    */
   rv = ArgusDhcpSqlQueryOneTable(stmt, resbind, query, used, &have_resbind,
                                  context_query_columns);
   if (rv < 0)
      goto out;

   while (rv == 0 && !mysql_stmt_fetch(stmt)) {
      rv = RacontextQueryKnownContextScanSQL(NULL /* parser */, ctx, resbind,
                                             context_query_columns);
      count++;
   }
   DEBUGLOG(1, "%s found %d results\n", __func__, count);

out:
   RaSQLResultBindFree(resbind, context_query_columns);
   mysql_stmt_close(stmt);
   ArgusFree(query);
   return rv;
}
