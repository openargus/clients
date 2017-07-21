#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif

#define _GNU_SOURCE
#include <stdio.h> /* asprintf */
#undef _GNU_SOURCE

#include <string.h>
#include <sys/syslog.h>
#include "argus_util.h"
#include "argus_parser.h"
#include "argus_print.h"
#include "argus_client.h"
#include "rabootp.h" /* DEBUGLOG */
#include "rabootp_interval_tree.h"
#include "rabootp_sql_bind.h"

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

#if defined(ARGUS_MYSQL)
extern MYSQL *RaMySQL;

int
RabootpSQLCreateTable(const struct ArgusParserStruct * const parser,
                      const char * const table)
{
   static const int querymax = 1024;
   char **namevec;
   char **typevec;
   char *query;
   size_t max_columns;
   int ncols;
   int tmpcol;
   int querylen;
   int rv = 0;

   size_t slen = 0, sremain = querymax;

   max_columns = RabootpPrintMaxFields();
   if (max_columns == 0) {
      DEBUGLOG(4, "%s: no fields to insert into database\n", __func__);
      return -1;
   }

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

   ncols = RabootpPrintLabelSQL(parser, (const char **)namevec, max_columns);
   if (ncols <= 0)
      goto out;

   if (RabootpPrintTypeSQL(parser, (const char **)typevec,
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
   /* if (mysql_real_query(RaMySQL, query, querylen)) { */
   if (mysql_query(RaMySQL, query)) {
      ArgusLog(LOG_INFO, "%s: mysql_query error %s", __func__,
               mysql_error(RaMySQL));
   }
   
out:
   ArgusFree(namevec);
   ArgusFree(typevec);
   ArgusFree(query);
   return rv;
}

int
RabootpSQLNewInsert(const struct ArgusParserStruct * const parser,
                    const char * const table,
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

   max_columns = RabootpPrintMaxFields();
   if (max_columns == 0) {
      DEBUGLOG(4, "%s: no fields to insert into database\n", __func__);
      return -1;
   }

   namevec = ArgusCalloc((int)max_columns, sizeof(*namevec));
   if (namevec == NULL) {
      return -1;
   }

   columns = NULL;
   values = NULL;

   rv = RabootpPrintLabelSQL(parser, (const char **)namevec, max_columns);
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

   *statement = mysql_stmt_init(RaMySQL);
   if (*statement == NULL)
      goto out;

   rv = mysql_stmt_prepare(*statement, querystr, len);
   if (rv) {
      ArgusLog(LOG_INFO, "%s: mysql_stmt_prepare error %s", __func__,
               mysql_error(RaMySQL));
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

/* bindvecp is set on success and is the caller's responsibility to
 * clean up.
 */
int
RabootpSQLBindStatement(const struct ArgusParserStruct * const parser,
                        const struct ArgusDhcpIntvlNode *node,
                        const char * const table,
                        MYSQL_STMT *statement,
                        MYSQL_BIND **bindvecp)
{
   MYSQL_BIND *bindvec;         /* storage used by RabootpPrintSQL() */
   size_t max_columns;          /* number of defined printer fields/columns */
   int rv = 0;
   int ncols = 0;
   int i;
   my_bool boolrv;

   max_columns = RabootpPrintMaxFields();
   if (max_columns == 0) {
      DEBUGLOG(4, "%s: no fields to insert into database\n", __func__);
      return -1;
   }

   bindvec = ArgusCalloc((int)max_columns, sizeof(*bindvec));
   if (bindvec == NULL)
      return -1;

   ncols = rv = RabootpPrintSQL(parser, node, bindvec, max_columns);
   if (rv < 0)
      goto err;

   boolrv = mysql_stmt_bind_param(statement, bindvec);
   if (boolrv) {
      ArgusLog(LOG_INFO, "%s: mysql_stmt_bind_param error %s", __func__,
               mysql_error(RaMySQL));
      rv = -1;
      goto err;
   }

   return 0;

err:
   for (i = 0; i < ncols; i++)
      RabootpSQLBindFree(&bindvec[i]);
   ArgusFree(bindvec);
   return rv;
}

int
RabootpSQLFreeStatement(MYSQL_STMT *statement)
{
   my_bool boolrv;

   boolrv = mysql_stmt_close(statement);
   if (boolrv) {
      ArgusLog(LOG_INFO, "%s: mysql_stmt_close error %s", __func__,
               mysql_error(RaMySQL));
      return -1;
   }

   return 0;
}

int
RabootpSQLInsertOne(const struct ArgusParserStruct * const parser,
                    const struct ArgusDhcpIntvlNode *node,
                    const char * const table)
{
   int rv = 0;
   int ncols = 0;
   int i;
   MYSQL_STMT *statement;
   MYSQL_BIND *bindvec = NULL;

   rv = RabootpSQLNewInsert(parser, table, &statement);
   if (rv)
      return rv;

   rv = RabootpSQLBindStatement(parser, node, table, statement, &bindvec);
   if (rv < 0)
      goto out;
   ncols = rv;

   rv = mysql_stmt_execute(statement);
   if (rv) {
      ArgusLog(LOG_INFO, "%s: mysql_stmt_execute error %s\n", __func__,
               mysql_error(RaMySQL));
      goto out;
   }

out:
   for (i = 0; i < ncols; i++)
      RabootpSQLBindFree(&bindvec[i]);
   ArgusFree(bindvec);
   RabootpSQLFreeStatement(statement);
   return rv;
}

int
RabootpSQLInsert(const struct ArgusParserStruct * const parser,
                 const struct ArgusDhcpIntvlNode *invec, size_t invec_nitems)
{
   int rv = 0;
   int ncols = 0;
   int i;
   size_t idx;
   char *lasttable;
   MYSQL_STMT *statement;
   MYSQL_BIND *bindvec = NULL;

   if (invec_nitems == 0)
      return 0;

   lasttable = ArgusMalloc(MAXSTRLEN);
   if (lasttable == NULL) {
      ArgusLog(LOG_WARNING, "%s: Unable to allocate memory for table name\n",
               __func__);
      return -1;
   }
   strcpy(lasttable, invec->data->sql_table_name);

   rv = RabootpSQLNewInsert(parser, lasttable, &statement);
   if (rv) {
      ArgusFree(lasttable);
      return rv;
   }

   mysql_query(RaMySQL, "START TRANSACTION");
   statement = NULL;

   for (idx = 0; idx < invec_nitems; idx++) {
      if (strcmp(lasttable, invec[idx].data->sql_table_name)) {
         RabootpSQLFreeStatement(statement);
         strcpy(lasttable, invec[idx].data->sql_table_name);
fprintf(stderr, "switching to table %s\n", lasttable);

         statement = NULL;
         rv = RabootpSQLNewInsert(parser, lasttable, &statement);
         if (rv)
            goto out;

         rv = RabootpSQLBindStatement(parser, &invec[idx], lasttable, statement,
                                      &bindvec);
         if (rv < 0) {
            ncols = 0;
            goto out;
         }
         ncols = rv;
      }

      rv = mysql_stmt_execute(statement);
      if (rv) {
         ArgusLog(LOG_INFO, "%s: mysql_stmt_execute error %s\n", __func__,
                  mysql_error(RaMySQL));
         goto out;
      }
      for (i = 0; i < ncols; i++)
         RabootpSQLBindFree(&bindvec[i]);
      ArgusFree(bindvec);
      bindvec = NULL;
   }

out:
   ArgusFree(lasttable);
   for (i = 0; i < ncols; i++)
      RabootpSQLBindFree(&bindvec[i]);
   if (bindvec)
      ArgusFree(bindvec);
   if (statement)
      RabootpSQLFreeStatement(statement);

   if (rv < 0)
      mysql_query(RaMySQL, "ROLLBACK");
   else
      mysql_query(RaMySQL, "COMMIT");

   return rv;
}

#endif
