/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
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
 * rasql_prepared_query.c:
 *   routines for SQL queries with prepared statements

 * These functions require the use of bound query parameters.
 * See rasql_result_bind.c.
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
#include "argus_client.h"
#include "argus_mysql.h"
#include "rasql_common.h"
#include "rasql_result_bind.h"
#include "rasql_prepared_query.h"

#ifdef ARGUSDEBUG
# define DEBUGLOG(lvl, fmt...) ArgusDebug(lvl, fmt)
#else
# define DEBUGLOG(lvl, fmt...)
#endif

/* yech.  Make this a function argument. */
extern MYSQL *RaMySQL;

/* RaSqlPreparedQuery:
 *   stmt:         mysql statement structure allocated with mysql_stmt_init()
 *   resbind:      array of bind structures.  This function will initialize
 *                 the array with RaSQLResultBind() if have_resbind is FALSE.
 *   query:        SQL "SELECT" query string without terminating semicolon
 *   querylen:     query string length excluding terminating NULL
 *   have_resbind: this function will initialize the resbind array if
 *                 have_resbind == false.  If true, the array is used as-is.
 *   ncols:        the number of columns referenced in the query (SELECT) string.
 *
 * Returns 0 on success, some value less than zero on failure.  On success, the
 * resbind array will be initialized and the query results can be retrieved with
 * mysql_stmt_fetch(stmt).  The resbind array will be filled in with the results
 * for one row each time mysql_stmt_fetch() is called.
 */

int
RaSqlPreparedQuery(MYSQL_STMT *stmt, MYSQL_BIND *resbind,
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
#endif
