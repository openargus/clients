#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#define _GNU_SOURCE
#include <stdio.h> /* asprintf */
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

#include "racontext.h"
#include "racontext_sql_bind.h"
#include "racontext_index_known_context.h"

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
 * +-----------+---------------------+------+-----+---------+-------+
 * | Field     | Type                | Null | Key | Default | Extra |
 * +-----------+---------------------+------+-----+---------+-------+
 * | cid       | binary(16)          | YES  |     | NULL    |       |
 * | val       | varbinary(64)       | YES  |     | NULL    |       |
 * | idx       | int(11)             | YES  |     | NULL    |       |
 * | prefixlen | tinyint(3) unsigned | YES  |     | NULL    |       |
 * +-----------+---------------------+------+-----+---------+-------+
 */

static const size_t context_insert_columns = 4;
struct context_insert_row {
    uuid_t cid;						/* column 1 */
    const struct racontext_attribute * const attr;	/* columns 2-4 */
};

/* The order of SQL columns in this array must match the order
 * of columns in the SELECT statement.  The "val" column calls
 * a bind function that expects an entire struct racontext_attribute
 * so use the offset of the zero length element at the beginning
 * of the structure.
 */
static const struct ArgusPrinterTable ContextInsertTablep[] = {
   ARGUS_PRINT_INITIALIZER(context_insert_row, cid, "cid", \
                           NULL /* print */, "binary(16)", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           RacontextSQLBindUuid,
                           NULL /* scan */),
   ARGUS_PRINT_INITIALIZER(context_insert_row, attr, "idx", \
                           NULL /* print */, "int", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           RacontextSQLBindIdx,
                           NULL /* scan */),
   ARGUS_PRINT_INITIALIZER(context_insert_row, attr, "val", \
                           NULL /* print */, "varbinary(64)", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           RacontextSQLBindValue,
                           NULL /* scan */),
   ARGUS_PRINT_INITIALIZER(context_insert_row, attr, "prefixlen", \
                           NULL /* print */, "tinyint unsigned", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           RacontextSQLBindPrefixlen,
                           NULL /* scan */),
};

static char *
__create_columns_str(size_t ncols, const char **namevec)
{
   size_t nchars = 0;
   size_t tmpcol;
   char *str;
   char *tmpstr;

   if (ncols == 0)
      return NULL;

   for (tmpcol = 0; tmpcol < ncols; tmpcol++)
      nchars += strlen(namevec[tmpcol]);
   nchars += ncols; /* comma between each, null term */
   nchars += 2;     /* parens */

   str = ArgusMalloc(nchars);
   if (str == NULL)
      return NULL;

   tmpstr = str;
   *tmpstr++ = '(';
   for (tmpcol = 0; tmpcol < ncols; tmpcol++) {
      tmpstr = stpcpy(tmpstr, namevec[tmpcol]);
      if (tmpcol < (ncols-1))
         *tmpstr++ = ',';
   }
   *tmpstr++ = ')';
   *tmpstr = '\0';

   return str;
}

static char *
__create_values_str(size_t ncols)
{
   size_t nchars = 0;
   size_t tmpcol;
   char *str;
   char *tmpstr;

   nchars = 2 + 2*ncols; /* parens + quesion marks + commas + null */
   str = ArgusMalloc(nchars);
   if (str == NULL)
      return NULL;

   tmpstr = str;
   *tmpstr++ = '(';
   for (tmpcol = 0; tmpcol < ncols; tmpcol++) {
      *tmpstr++ = '?';
      if (tmpcol < (ncols-1))
         *tmpstr++ = ',';
   }
   *tmpstr++ = ')';
   *tmpstr = '\0';

   return str;
}

static int
RacontextInsertKnownContextPrintLabelSQL
 (const struct ArgusParserStruct * const parser,
  const char **namevec, size_t nitems)
{
   int tmax, t;
   int out_idx = 0;

   tmax = sizeof(ContextInsertTablep)/sizeof(ContextInsertTablep[0]);
   for (t = 0; t < tmax && out_idx < nitems; t++) {
      if (ContextInsertTablep[t].enabled > ENA_DISPLAY) {
         namevec[out_idx] = ContextInsertTablep[t].label;
         out_idx++;
      }
   }
   return out_idx;
}

static int
RacontextInsertKnownContextPrintTypeSQL
 (const struct ArgusParserStruct * const parser,
  const char **typevec, size_t nitems)
{
   int tmax, t;
   int out_idx = 0;

   tmax = sizeof(ContextInsertTablep)/sizeof(ContextInsertTablep[0]);
   for (t = 0; t < tmax && out_idx < nitems; t++) {
      if (ContextInsertTablep[t].enabled > ENA_DISPLAY) {
         typevec[out_idx] = ContextInsertTablep[t].sqltype;
         out_idx++;
      }
   }
   return out_idx;
}

static int
RacontextInsertKnownContextPrintSQL(const struct ArgusParserStruct * const parser,
                                    const struct racontext_attribute * const attr,
                                    const uuid_t nid, MYSQL_BIND *bindvec, size_t nitems)

{
   int t;
   int tmax;
   int res;
   int out_idx = 0;
   struct context_insert_row row = {
      .cid = {
         nid[0],  nid[1],  nid[2],  nid[3],
         nid[4],  nid[5],  nid[6],  nid[7],
         nid[8],  nid[9],  nid[10], nid[11],
         nid[12], nid[13], nid[14], nid[15],
      },
      .attr = attr,
   };

   tmax = sizeof(ContextInsertTablep)/sizeof(ContextInsertTablep[0]);
   for (t = 0; t < tmax && out_idx < nitems; t++) {
      res = ArgusPrintFieldSQL(parser, ContextInsertTablep, &row, t,
                               &bindvec[out_idx]);
      if (res > 0)
         out_idx++;
   }

   return out_idx;
}

/* bindvecp is set on success and is the caller's responsibility to
 * clean up.
 */
static int
RacontextSQLBindStatement(const struct ArgusParserStruct * const parser,
                          const struct racontext_attribute * const attr,
                          const uuid_t nid,
                          MYSQL_STMT *statement,
                          MYSQL_BIND **bindvecp)
{
   MYSQL_BIND *bindvec;         /* used by RacontextInsertKnownContextPrintSQL */
   size_t max_columns;          /* number of defined printer fields/columns */
   int rv = 0;
   int ncols = 0;
   my_bool boolrv;

   max_columns = context_insert_columns;
   bindvec = ArgusCalloc((int)max_columns, sizeof(*bindvec));
   if (bindvec == NULL)
      return -1;

   ncols = rv = RacontextInsertKnownContextPrintSQL(parser, attr, nid, bindvec,
                                                    max_columns);
   if (rv != max_columns)
      goto err;

   boolrv = mysql_stmt_bind_param(statement, bindvec);
   if (boolrv) {
      ArgusLog(LOG_INFO, "%s: mysql_stmt_bind_param error", __func__);
      rv = -1;
      goto err;
   }

   return 0;

err:
   RaSQLResultBindFree(bindvec, ncols);
   ArgusFree(bindvec);
   return rv;
}

static int
RacontextSQLFreeStatement(MYSQL *mysql, MYSQL_STMT *statement)
{
   my_bool boolrv;

   boolrv = mysql_stmt_close(statement);
   if (boolrv) {
      ArgusLog(LOG_INFO, "%s: mysql_stmt_close error %s", __func__,
               mysql_error(mysql));
      return -1;
   }

   return 0;
}

int
RacontextInsertKnownContextAttr(const struct ArgusParserStruct * const parser,
                                const struct racontext_attribute * const attr,
                                const uuid_t nid, MYSQL *mysql,
                                MYSQL_STMT *statement)

{
   int rv = 0;
   int ncols = 0;
   MYSQL_BIND *bindvec = NULL;

   rv = RacontextSQLBindStatement(parser, attr, nid, statement, &bindvec);
   if (rv < 0)
      goto out;
   ncols = rv;

   rv = mysql_stmt_execute(statement);
   if (rv) {
      ArgusLog(LOG_INFO, "%s: mysql_stmt_execute error %s\n", __func__,
               mysql_error(mysql));
      goto out;
   }

out:
   RaSQLResultBindFree(bindvec, ncols);
   ArgusFree(bindvec);
   return rv;
}

static int
RacontextSQLNewInsert(const struct ArgusParserStruct * const parser,
                      const char * const table,
                      MYSQL *mysql,
                      MYSQL_STMT **statement)
{
   char **namevec;              /* array of column names */
   char *querystr;              /* DO NOT FREE.  allocated on stack */
   char *columns;               /* (column1, column2, ..., columnn) */
   char *values;                /* (?, ?, ..., ?) */
   size_t max_columns;          /* number of defined printer fields/columns */
   int rv = 0;
   int ncols;
   int len;

   max_columns = context_insert_columns;
   namevec = ArgusCalloc((int)max_columns, sizeof(*namevec));
   if (namevec == NULL) {
      return -1;
   }

   columns = NULL;
   values = NULL;

   rv = RacontextInsertKnownContextPrintLabelSQL(parser,
                                                 (const char **)namevec,
                                                 max_columns);
   if (rv < 0)
      goto out;

   ncols = rv;
   columns = __create_columns_str(ncols, (const char **)namevec);
   if (columns == NULL) {
      rv = -1;
      goto out;
   }

   values = __create_values_str(ncols);
   if (values == NULL) {
      rv = -1;
      goto out;
   }

   len = asprintf(&querystr, "INSERT INTO %s %s VALUES %s", table, columns,
                  values);
   if (len < 0 || querystr == NULL) {
      rv = -1;
      goto out;
   }
   DEBUGLOG(2, "%s: query string '%s'\n", __func__, querystr);

   *statement = mysql_stmt_init(mysql);
   if (*statement == NULL)
      goto out;

   rv = mysql_stmt_prepare(*statement, querystr, len);
   if (rv) {
      ArgusLog(LOG_INFO, "%s: mysql_stmt_prepare error %s", __func__,
               mysql_error(mysql));
      mysql_stmt_close(*statement);
      if (rv > 0)
         rv = -1;
   }

out:
   ArgusFree(namevec);
   if (columns)
      ArgusFree(columns);
   if (values)
      ArgusFree(values);

   return rv;
}


int
RacontextInsertKnownContext(const struct ArgusParserStruct * const parser,
                            const struct racontext * const ctx,
                            const uuid_t nid, MYSQL *mysql,
                            const char * const table)
{
   int rv;
   struct racontext_attribute *attr;
   MYSQL_STMT *statement = NULL;

   rv = RacontextSQLNewInsert(parser, table, mysql, &statement);
   if (rv)
      return rv;

   for (attr = RacontextAttrTreeFirst(ctx->attrs);
        !rv && attr;
        attr = RacontextAttrTreeNext(attr)) {

      /* skip attributes that didn't make the grade */
      if (attr->attrib_num >= CTX_ATTRIB_MCAST_SOURCE_MAC &&
          attr->occurrences_norm == 0.)
         continue;

      rv = RacontextInsertKnownContextAttr(parser, attr, nid, mysql, statement);
   }

   RacontextSQLFreeStatement(mysql, statement);

   if (rv < 0)
      goto out;

   rv = RacontextIndexKnownContext(parser, nid, table, ctx->match->total_weight,
                                   index_table_name, mysql);

out:
   return rv;
}

int
KnownContextSQLCreateTable(const struct ArgusParserStruct * const parser,
                           MYSQL *mysql, const char * const table)
{
   static const int querymax = 1024;
   char **namevec;
   char **typevec;
   char *query;
   size_t max_columns;
   int ncols;
   int tmpcol;
   int rv = 0;

   size_t slen = 0, sremain = querymax;

   max_columns = context_insert_columns;
   namevec = ArgusCalloc((int)max_columns, sizeof(*namevec));
   if (namevec == NULL) {
      return -1;
   }

   typevec = ArgusCalloc((int)max_columns, sizeof(*namevec));
   if (typevec == NULL) {
      ArgusFree(namevec);
      return -1;
   }

   query = ArgusMalloc(querymax);
   if (query == NULL)
      goto out;

   ncols = RacontextInsertKnownContextPrintLabelSQL(parser,
                                                   (const char **)namevec,
                                                   max_columns);
   if (ncols < max_columns)
      goto out;

   if (RacontextInsertKnownContextPrintTypeSQL(parser, (const char **)typevec,
                                               max_columns) != ncols)
      goto out;

   snprintf_append(query, &slen, &sremain, "CREATE TABLE IF NOT EXISTS %s (",
                   table);

   for (tmpcol = 0; tmpcol < ncols && sremain > 0; tmpcol++) {
      snprintf_append(query, &slen, &sremain, "%s %s%s",
                      namevec[tmpcol], typevec[tmpcol],
                      (tmpcol < (ncols-1)) ? ", " : ")");
   }

   DEBUGLOG(1, "%s: %s\n", __func__, query);
   if (mysql_real_query(mysql, query, slen)) {
      ArgusLog(LOG_INFO, "%s: mysql_query error %s", __func__,
               mysql_error(mysql));
   }

out:
   ArgusFree(namevec);
   ArgusFree(typevec);
   ArgusFree(query);
   return rv;
}
