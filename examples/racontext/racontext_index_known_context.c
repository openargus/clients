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

#include "../radhcp/rabootp_sql_bind.h"
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

static const size_t index_columns = 3;
static const size_t unused_index_columns = 3;
struct index_row {
    uuid_t cid;
    const char * const tablename;
    uuid_t sid;
    const char * const inf;
    const char * const alias;
    uint32_t total_weight;
};

/* The order of SQL columns in this array must match the order
 * of columns in the SELECT statement.  The "val" column calls
 * a bind function that expects an entire struct racontext_attribute
 * so use the offset of the zero length element at the beginning
 * of the structure.
 */
static const struct ArgusPrinterTable ContextIndexTablep[] = {
   ARGUS_PRINT_INITIALIZER(index_row, cid, "cid", \
                           NULL /* print */, "binary(16)", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           RacontextSQLBindUuid,
                           NULL /* scan */),
   ARGUS_PRINT_INITIALIZER(index_row, tablename, "tablename", \
                           NULL /* print */, "varchar(64)", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           RacontextSQLBindString,
                           NULL /* scan */),
   ARGUS_PRINT_INITIALIZER(index_row, total_weight, "total_weight", \
                           NULL /* print */, "int(10) unsigned", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           RabootpSQLBindUnsigned,
                           NULL /* scan */),
};

/* Currently unused columns */
static const struct ArgusPrinterTable ContextUnusedTablep[] = {
   ARGUS_PRINT_INITIALIZER(index_row, sid, "sid", \
                           NULL /* print */, "binary(16)", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           RacontextSQLBindUuid,
                           NULL /* scan */),
   ARGUS_PRINT_INITIALIZER(index_row, inf, "inf", \
                           NULL /* print */, "char(4)", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           RacontextSQLBindString,
                           NULL /* scan */),
   ARGUS_PRINT_INITIALIZER(index_row, alias, "alias", \
                           NULL /* print */, "varchar(64)", \
                           ENA_DISPLAY|ENA_SQL_LEASE_SUMMARY, \
                           RacontextSQLBindString,
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
RacontextIndexKnownContextPrintLabelSQL
 (const struct ArgusParserStruct * const parser,
  const char **namevec, size_t nitems)
{
   int tmax, t;
   int out_idx = 0;

   tmax = sizeof(ContextIndexTablep)/sizeof(ContextIndexTablep[0]);
   for (t = 0; t < tmax && out_idx < nitems; t++) {
      if (ContextIndexTablep[t].enabled > ENA_DISPLAY) {
         namevec[out_idx] = ContextIndexTablep[t].label;
         out_idx++;
      }
   }

   tmax = sizeof(ContextUnusedTablep)/sizeof(ContextUnusedTablep[0]);
   for (t = 0; t < tmax && out_idx < nitems; t++) {
      if (ContextUnusedTablep[t].enabled > ENA_DISPLAY) {
         namevec[out_idx] = ContextUnusedTablep[t].label;
         out_idx++;
      }
   }

   return out_idx;
}

static int
RacontextIndexKnownContextPrintTypeSQL
 (const struct ArgusParserStruct * const parser,
  const char **typevec, size_t nitems)
{
   int tmax, t;
   int out_idx = 0;

   tmax = sizeof(ContextIndexTablep)/sizeof(ContextIndexTablep[0]);
   for (t = 0; t < tmax && out_idx < nitems; t++) {
      if (ContextIndexTablep[t].enabled > ENA_DISPLAY) {
         typevec[out_idx] = ContextIndexTablep[t].sqltype;
         out_idx++;
      }
   }

   tmax = sizeof(ContextUnusedTablep)/sizeof(ContextUnusedTablep[0]);
   for (t = 0; t < tmax && out_idx < nitems; t++) {
      if (ContextUnusedTablep[t].enabled > ENA_DISPLAY) {
         typevec[out_idx] = ContextUnusedTablep[t].sqltype;
         out_idx++;
      }
   }

   return out_idx;
}

static int
RacontextIndexKnownContextPrintSQL(const struct ArgusParserStruct * const parser,
                                   const uuid_t nid,
                                   const char * const tablename,
                                   unsigned long long total_weight,
                                   MYSQL_BIND *bindvec, size_t nitems)

{
   int t;
   int tmax;
   int res;
   int out_idx = 0;
   struct index_row row = {
      .cid = {
         nid[0],  nid[1],  nid[2],  nid[3],
         nid[4],  nid[5],  nid[6],  nid[7],
         nid[8],  nid[9],  nid[10], nid[11],
         nid[12], nid[13], nid[14], nid[15],
      },
      .tablename = tablename,
      .total_weight = total_weight,
   };



   tmax = sizeof(ContextIndexTablep)/sizeof(ContextIndexTablep[0]);
   for (t = 0; t < tmax && out_idx < nitems; t++) {
      res = ArgusPrintFieldSQL(parser, ContextIndexTablep, &row, t,
                               &bindvec[out_idx]);
      if (res <= 0)
         return -1;

      out_idx++;
   }

   tmax = sizeof(ContextUnusedTablep)/sizeof(ContextUnusedTablep[0]);
   for (t = 0; t < tmax && out_idx < nitems; t++) {
      res = ArgusPrintFieldSQL(parser, ContextUnusedTablep, &row, t,
                               &bindvec[out_idx]);
      if (res <= 0)
         return -1;

      out_idx++;
   }

   return out_idx;
}

/* bindvecp is set on success and is the caller's responsibility to
 * clean up.
 */
static int
RacontextIndexSQLBindStatement(const struct ArgusParserStruct * const parser,
                              const uuid_t nid,
                              const char * const tablename,
                              unsigned total_weight,
                              MYSQL_STMT *statement,
                              MYSQL_BIND **bindvecp)
{
   MYSQL_BIND *bindvec;         /* used by RacontextInsertKnownContextPrintSQL */
   size_t max_columns;          /* number of defined printer fields/columns */
   int rv = 0;
   int ncols = 0;
   my_bool boolrv;

   max_columns = index_columns;
   bindvec = ArgusCalloc((int)max_columns, sizeof(*bindvec));
   if (bindvec == NULL)
      return -1;

   ncols = rv = RacontextIndexKnownContextPrintSQL(parser, nid, tablename,
                                                   total_weight, bindvec,
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
RacontextIndexKnownContextOne(const struct ArgusParserStruct * const parser,
                              const uuid_t nid,
                              const char * const tablename,
                              unsigned total_weight,
                              MYSQL *mysql,
                              MYSQL_STMT *statement)

{
   int rv = 0;
   int ncols = 0;
   MYSQL_BIND *bindvec = NULL;

   rv = RacontextIndexSQLBindStatement(parser, nid, tablename, total_weight,
                                       statement, &bindvec);
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
RacontextIndexSQLNewInsert(const struct ArgusParserStruct * const parser,
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

   max_columns = index_columns;
   namevec = ArgusCalloc((int)max_columns, sizeof(*namevec));
   if (namevec == NULL) {
      return -1;
   }

   columns = NULL;
   values = NULL;

   rv = RacontextIndexKnownContextPrintLabelSQL(parser,
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
RacontextIndexKnownContext(const struct ArgusParserStruct * const parser,
                           const uuid_t nid,
                           const char * const tablename,
                           unsigned total_weight,
                           const char * const indextable,
                           MYSQL *mysql)
{
   int rv;
   MYSQL_STMT *statement = NULL;

   rv = RacontextIndexSQLNewInsert(parser, indextable, mysql, &statement);
   if (rv)
      return rv;

   rv = RacontextIndexKnownContextOne(parser, nid, tablename, total_weight,
                                      mysql, statement);
   if (rv)
      return rv;

   RacontextSQLFreeStatement(mysql, statement);
   return rv;
}

int
RacontextIndexSQLCreateTable(const struct ArgusParserStruct * const parser,
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

   max_columns = index_columns + unused_index_columns;
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

   ncols = RacontextIndexKnownContextPrintLabelSQL(parser,
                                                   (const char **)namevec,
                                                   max_columns);
   if (ncols < max_columns)
      goto out;

   if (RacontextIndexKnownContextPrintTypeSQL(parser, (const char **)typevec,
                                              max_columns) != ncols)
      goto out;

   snprintf_append(query, &slen, &sremain, "CREATE TABLE IF NOT EXISTS %s (",
                   table);

   for (tmpcol = 0; tmpcol < ncols && sremain > 0; tmpcol++) {
      snprintf_append(query, &slen, &sremain, "%s %s, ",
                      namevec[tmpcol], typevec[tmpcol]);
   }
   snprintf_append(query, &slen, &sremain, "PRIMARY KEY (`%s`))", 
                   ContextIndexTablep[0].label);

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
