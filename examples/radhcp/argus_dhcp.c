/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2019 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 */

/*
 * libargus_dhcp: routines for querying the dhcp database
 */

#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif

#if defined(ARGUS_MYSQL)

#define _GNU_SOURCE
#include <stdio.h> /* asprintf */
#undef _GNU_SOURCE

#include <string.h>
#include <sys/syslog.h>
#include <stdbool.h>
#include "argus_util.h"
#include "argus_parser.h"
#include "argus_print.h"
#include "argus_client.h"
#include "argus_mysql.h"
#include "../ramysql/rasql_common.h"

#include "rabootp.h" /* DEBUGLOG */
#include "rabootp_print.h"
#include "rabootp_lease_pullup.h"
#include "rabootp_memory.h"

#include "argus_dhcp.h"

void RaSQLQueryDatabaseTable (char *, unsigned int, unsigned int);
extern MYSQL *RaMySQL;

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

   str = ArgusMalloc(nchars);
   if (str == NULL)
      return NULL;

   tmpstr = str;
   for (tmpcol = 0; tmpcol < ncols; tmpcol++) {
      tmpstr = stpcpy(tmpstr, namevec[tmpcol]);
      if (tmpcol < (ncols-1))
         *tmpstr++ = ',';
   }
   *tmpstr = '\0';

   return str;
}

static int
__format_query(char *query, size_t maxstrlen, const char * const columns,
               const char * const table,
               const char * const where,
               size_t limit)
{
   int slen;
   size_t qlen = 0;
   size_t qremain = maxstrlen;

   slen = snprintf_append(query, &qlen, &qremain, "SELECT %s from %s",
                             columns, table);
   if (slen < 0) {
      DEBUGLOG(1, "%s: failed to format query string\n", __func__);
      return -1;
   }

   if (where) {
      slen = snprintf_append(query, &qlen, &qremain, " WHERE %s", where);
      if (slen < 0) {
         DEBUGLOG(1, "%s: failed to format when clause\n", __func__);
         return -1;
      }
   }

   if (limit) {
      slen = snprintf_append(query, &qlen, &qremain, " LIMIT %zd", limit);
      if (slen < 0) {
         DEBUGLOG(1, "%s: failed to format limit clause\n", __func__);
         return -1;
      }
   }

   if (qlen == maxstrlen) {
      DEBUGLOG(1, "%s: query string too long\n", __func__);
      return -1;
   }

   return (int)qlen;
}

void RaSQLQueryDatabaseTable (char *table, unsigned int start, unsigned int stop) { };

int
ArgusDhcpSqlQueryOneTable(MYSQL_STMT *stmt, MYSQL_BIND *resbind,
                          const char * const query, int querylen,
                          bool *have_resbind, size_t ncols)
{
      MYSQL_FIELD *fields;
      MYSQL_RES *prepare_meta_result;
      int nfields;
      int rv = 0;

      /* make query here */
      if (mysql_stmt_prepare(stmt, query, querylen)) {
         if (mysql_stmt_errno(stmt) != ER_NO_SUCH_TABLE) {
            ArgusLog(LOG_INFO, "%s: %s\n", __func__, mysql_error(RaMySQL));
            rv = -1;
         }
         goto out;
      }

      /* Fetch result set meta information */
      prepare_meta_result = mysql_stmt_result_metadata(stmt);
      if (!prepare_meta_result) {
         DEBUGLOG(1, "%s: mysql_stmt_result_metadata(): %s\n", __func__,
                  mysql_stmt_error(stmt));
         rv = -1;
         goto out;
      }

      /* Get total columns in the query */
      nfields = mysql_num_fields(prepare_meta_result);
      if (nfields != ncols) {
         DEBUGLOG(1, "%s: wrong number of fields\n", __func__);
         rv = -1;
         goto out;
      }

      /* do this once since all tables should have the same schema */
      if (!*have_resbind) {
         fields = mysql_fetch_fields(prepare_meta_result);
         if (RaSQLResultBind(resbind, fields, nfields) < 0) {
            DEBUGLOG(1, "%s: unable to bind results\n", __func__);
            rv = -1;
            goto out;
         }
         *have_resbind = true;
      }

      if (mysql_stmt_execute(stmt)) {
         DEBUGLOG(1, "%s: mysql_stmt_execute: %s\n", __func__,
                  mysql_stmt_error(stmt));
         rv = -1;
         goto out;
      }

      if (mysql_stmt_bind_result(stmt, resbind)) {
         DEBUGLOG(1, "%s: mysql_stmt_bind_result() failed: %s\n", __func__,
                  mysql_stmt_error(stmt));
         rv = -1;
         goto out;
      }

      mysql_free_result(prepare_meta_result);

out:
      return rv;
}

/* Use the parser->startime_t and parser->lasttime_t values to
 * format a WHERE clause limiting the search for DHCP leases to
 * the relevant times.  len is the number of bytes allocated for
 * the when_clause buffer.  This mimics the __test_overlap()
 * function in rabootp_interval_tree.c.
 */
static int
ArgusDhcpSqlQueryTimes(const struct ArgusParserStruct * const parser,
                       char *where_clause, size_t *len, size_t *rem)
{
   if (parser->startime_t.tv_sec == 0 ||
       parser->lasttime_t.tv_sec == 0)
      return 0;

   snprintf_append(where_clause, len, rem,
                   "((stime <= %ld.%06ld AND ltime >= %d.%06ld) OR ",
                   parser->startime_t.tv_sec, parser->startime_t.tv_usec,
                   parser->startime_t.tv_sec, parser->startime_t.tv_usec);
   snprintf_append(where_clause, len, rem,
                   "(stime >= %ld.%06ld AND stime <= %d.%06ld))",
                   parser->startime_t.tv_sec, parser->startime_t.tv_usec,
                   parser->lasttime_t.tv_sec, parser->lasttime_t.tv_usec);

   if (*rem == 0)
      return -1;

   return 0;
}

/* Format a WHERE clause to compare the client MAC address.  Only OUI-48
 * addresses supported for now.
 */
static int
ArgusDhcpSqlQueryClientAddr(const unsigned char * const clientmac,
                            char *where_clause, size_t *len, size_t *rem)
{
   return snprintf_append(where_clause, len, rem,
                   "(clientmac = '%02x:%02x:%02x:%02x:%02x:%02x')",
                   clientmac[0], clientmac[1], clientmac[2],
                   clientmac[3], clientmac[4], clientmac[5]);
}

/* Reconsitute an array of dhcp lease structures from the database.
 * Note that not all fields will have valid data after this since
 * not every field from the structures makes its way into the database.
 *
 * Returns the number of leases that were added to the **leases array.
 */

static int
ArgusDhcpSqlQueryTables(const struct ArgusParserStruct * const parser,
                        const char ** const tablevec, const char * const where,
                        struct ArgusDhcpIntvlNode *nodes, ssize_t nleases)
{
   size_t max_columns = RabootpPrintMaxFields();
   int i;
   int rv = 0;
   int count = 0;
   int slen;
   size_t ncols;
   char **namevec;
   char *columns = NULL;
   char *query = NULL;
   MYSQL_BIND *resbind = NULL;
   bool have_resbind = false;

   if (max_columns == 0) {
      DEBUGLOG(4, "%s: no fields to query from database\n", __func__);
      return -1;
   }

   namevec = ArgusCalloc((int)max_columns, sizeof(*namevec));
   if (namevec == NULL) {
      return -1;
   }

   /* fill in the list of column names */
   rv = RabootpPrintLabelSQL(parser, (const char **)namevec, max_columns);
   if (rv < 0)
      goto out;

   /* create a comma-delimited string of column names */
   ncols = rv;
   columns = __create_columns_str(ncols, (const char **)namevec);
   if (columns == NULL) {
      rv = -1;
      goto out;
   }

   query = ArgusMalloc(MAXSTRLEN);
   if (query == NULL) {
      rv = -1;
      goto out;
   }

   resbind = ArgusCalloc(ncols, sizeof(*resbind));
   if (resbind == NULL) {
      rv = -1;
      goto out;
   }

   /* check each table dhcp leases */
   for (i = 0; tablevec[i] && count < nleases; i++) {
      MYSQL_STMT *stmt = mysql_stmt_init(RaMySQL);

      if (stmt == NULL) {
         DEBUGLOG(1, "%s: mysql_stmt_init() out of memory\n");
         rv = -1;
         goto out;
      }

      slen = __format_query(query, MAXSTRLEN, columns, tablevec[i], where,
                            nleases);
      if (slen < 0) {
         rv = -1;
         goto out;
      }
      DEBUGLOG(4, "%s: SQL: %s\n", __func__, query);

      rv = ArgusDhcpSqlQueryOneTable(stmt, resbind, query, slen, &have_resbind,
                                     ncols);
      if (rv < 0)
         goto out;

      while (count < nleases && !mysql_stmt_fetch(stmt)) {
         nodes[count].data = ArgusDhcpStructAlloc();
         if (nodes[count].data == NULL) {
            ArgusLog(LOG_WARNING,
                     "unable to allocate dhcp structure for SQL results\n");
            break;
         }

         rv = RabootpScanSQL(parser, &nodes[count], resbind, ncols);
         count++;
      }

      DEBUGLOG(4, "finished table %s lease count now %u\n", tablevec[i], count);

      if (stmt)
         mysql_stmt_close(stmt);
   }

   rv = count;

out:
   if (columns)
      ArgusFree(columns);
   if (namevec)
      ArgusFree(namevec);
   if (query)
      ArgusFree(query);
   if (resbind) {
      RaSQLResultBindFree(resbind, ncols);
      ArgusFree(resbind);
   }

   return rv;
}


int
ArgusDhcpSqlQuery(const struct ArgusParserStruct * const parser,
                  const struct ArgusAdjustStruct * const nadp,
                  const unsigned char * const clientmac,
                  const char * const table, bool pullup,
                  struct ArgusDhcpIntvlNode *nodes, ssize_t nleases)
{
   int i;
   int rv;
   time_t ArgusTableStartSecs; /* ignored */
   time_t ArgusTableEndSecs;   /* ignored */
   char **tablevec;
   size_t where_len = 0;
   size_t where_rem = 256;
   char *where;
   struct ArgusDhcpIntvlNode *tmp_invec;
   size_t tmp_invec_used = 0;
   static const int argus_seconds_table = 0;

   tmp_invec = ArgusMalloc(nleases * sizeof(*tmp_invec));
   if (tmp_invec == NULL) {
      DEBUGLOG(1, "%s: unable to allocate temp array of interval nodes\n",
               __func__);
      return -1;
   }

   where = ArgusMalloc(where_rem);
   if (where == NULL) {
      DEBUGLOG(1, "%s: unable to allocate time range string\n", __func__);
      ArgusFree(tmp_invec);
      return -1;
   }

   rv = ArgusDhcpSqlQueryTimes(parser, where, &where_len, &where_rem);
   if (rv < 0) {
      DEBUGLOG(1, "%s: unable to format where clause for times\n", __func__);
      ArgusFree(tmp_invec);
      ArgusFree(where);
      return -1;
   }

   if (*where != 0 && clientmac)
      snprintf_append(where, &where_len, &where_rem, " AND ");

   if (clientmac) {
      ArgusDhcpSqlQueryClientAddr(clientmac, where, &where_len, &where_rem);
   }

   tablevec = ArgusCreateSQLTimeTableNames((struct ArgusParserStruct *)parser, &ArgusTableStartSecs,
                                           &ArgusTableEndSecs,
                                           argus_seconds_table,
                                           nadp, table);

   if (tablevec == NULL) {
      DEBUGLOG(1, "%s: unable to generate list of tables\n");
      ArgusFree(tmp_invec);
      ArgusFree(where);
      return -1;
   }

   if (*tablevec == NULL) {
      DEBUGLOG(1, "%s: generated empty list of tables\n");
      goto out;
   }

   rv = ArgusDhcpSqlQueryTables(parser, (const char **)tablevec,
                                where_len > 0 ? where : NULL, tmp_invec, nleases);

   if (rv < 0)
      goto out;

   tmp_invec_used = rv;

   if (pullup) {
      RabootpLeasePullupSort(tmp_invec, tmp_invec_used);
      rv = RabootpLeasePullup(tmp_invec, rv, nodes, nleases);
   } else {
      memcpy(nodes, tmp_invec, tmp_invec_used * sizeof(*nodes));
   }

out:
   if (pullup) {
      /* Decrement the refcount for each lease structure.  Those that do not
       * also appear in the nodes[] array will be freed.
       */
      for (i = 0; i < tmp_invec_used; i++)
         ArgusDhcpStructFree(tmp_invec[i].data);
   }

   for (i = 0; i < ARGUS_MAX_TABLE_LIST_SIZE; i++) {
      if (tablevec[i] == NULL)
         break;

      free(tablevec[i]); /* allocated with strdup() */
   }
   ArgusFree(tmp_invec);
   ArgusFree(tablevec);
   ArgusFree(where);

   return rv;
}

#endif
