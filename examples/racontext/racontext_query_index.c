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
#include "rabootp.h"

#include "../radhcp/argus_print.h"
#include "../radhcp/rabootp_sql_scan.h"
#include "racontext.h"
#include "racontext_sql_scan.h"

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

/*
 * create table context_index (cid binary(16), tablename varchar(64), \
 * sid varbinary(16), inf char(4), alias varchar(64), \
 * total_weight integer unsigned, primary key (cid));
 *
 * +--------------+------------------+------+-----+---------+-------+
 * | Field        | Type             | Null | Key | Default | Extra |
 * +--------------+------------------+------+-----+---------+-------+
 * | cid          | binary(16)       | NO   | PRI | NULL    |       |
 * | tablename    | varchar(64)      | YES  |     | NULL    |       |
 * | sid          | varbinary(16)    | YES  |     | NULL    |       |
 * | inf          | char(4)          | YES  |     | NULL    |       |
 * | alias        | varchar(64)      | YES  |     | NULL    |       |
 * | total_weight | int(10) unsigned | YES  |     | NULL    |       |
 * +--------------+------------------+------+-----+---------+-------+
 */

/* Only query cid and weight for now.  Include cid in the query because
 * the table will be indexed by cid (primary key) and the index is only
 * used if the keys appear in the query.
 */
static const size_t index_query_columns = 2;
struct index_row {
    uuid_t cid;
#if 0 /* future */
    char *tablename;
    char *sid;
    char *inf;
    char *alias;
#endif
    uint32_t total_weight;
};

/* The order of SQL columns in this array must match the order
 * of columns in the SELECT statement.
 */
static const struct ArgusPrinterTable IndexPrinterTablep[] = {
   ARGUS_PRINT_INITIALIZER(index_row, cid, "cid", \
                           NULL /* print */, "binary(16)", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           NULL /* bind */, \
                           RacontextSQLScanUuid),
   ARGUS_PRINT_INITIALIZER(index_row, total_weight, "total_weight", \
                           NULL /* print */, "int unsigned", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           NULL /* bind */, \
                           RabootpSQLScanUint32),
};


static void
__to_hex(char *query, size_t *used, size_t *remain, uuid_t cid)
{
   int i;
   static const char hex[] = {
      '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
   };

   for(i = 0; i < sizeof(uuid_t) && *remain > 1; i++) {
      *(query+*used+2*i) = hex[(cid[i] & 0xf0) >> 4];
      *(query+*used+2*i+1) = hex[(cid[i] & 0xf)];
   }
   *(query+*used+2*i) = 0;
   *used += 2*i;
   *remain -= 2*i;
}

static int
RacontextQueryIndexScanSQL(
   const struct ArgusParserStruct * const parser,
   struct known_context_match *kcm, const MYSQL_BIND * const bindvec,
   size_t nitems)
{
   int max;
   int t;
   int res = 0;
   int idx = 0;
   struct index_row indexrow;

   max = sizeof(IndexPrinterTablep)/sizeof(IndexPrinterTablep[0]);
   for (t = 0; t < max && idx < nitems; t++) {
      res = ArgusScanFieldSQL(parser, IndexPrinterTablep, &indexrow,
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

   kcm->total_weight = indexrow.total_weight;
   return 0;
}


static int
RacontextQueryIndexOne(MYSQL *mysql, struct racontext *ctx,
                       struct known_context_match *kcm)
{
   char *query;
   size_t used = 0;
   size_t remain = RaMySQLGetMaxPacketSize();
   int rv;
   MYSQL_STMT *stmt = mysql_stmt_init(mysql);
   MYSQL_BIND resbind[index_query_columns];
   bool have_resbind = false;

   /* this will later need to be a list of tables queried from the index */
   static const char * const table = "testdata.context_index";

   if (RacontextAttrTreeEmpty(ctx->attrs))
      return 0;  /* no error, just nothing to do */

   if (stmt == NULL)
      return -ENOMEM;

   query = ArgusMalloc(remain);
   if (query == NULL)
      return -ENOMEM;

   snprintf_append(query, &used, &remain, "SELECT cid, total_weight FROM %s",
                   table);
   snprintf_append(query, &used, &remain, " WHERE cid=UNHEX('");
   __to_hex(query, &used, &remain, kcm->cid);
   snprintf_append(query, &used, &remain, "')");

   DEBUGLOG(4, "%s QUERY: %s\n", __func__, query);

   memset(resbind, 0, sizeof(resbind));
   /* need an api change - we pass in a MYSQL*, but ArgusDhcpSqlQueryOneTable
    * uses the global RaMySQL
    */
   rv = ArgusDhcpSqlQueryOneTable(stmt, resbind, query, used, &have_resbind,
                                  index_query_columns);

   while (rv == 0 && !mysql_stmt_fetch(stmt)) {
      rv = RacontextQueryIndexScanSQL(NULL /* parser */, kcm, resbind,
                                             index_query_columns);
   }

   mysql_stmt_close(stmt);
   RaSQLResultBindFree(resbind, index_query_columns);
   ArgusFree(query);
   return rv;
}

int
RacontextQueryIndex(MYSQL *mysql, struct racontext *ctx)
{
   struct known_context_match *kcm;
   int rv = 0;

   /* should instead build a query string with all CIDs in tree */
   for (kcm = KnownContextTreeFirst(&ctx->known_contexts);
        rv == 0 && kcm;
        kcm = KnownContextTreeNext(kcm)) {
      rv = RacontextQueryIndexOne(mysql, ctx, kcm);
   }
   return rv;
}
