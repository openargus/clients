#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/syslog.h>

#include <mysql.h>
#include <mysqld_error.h>

#include "argus_util.h"
#include "argus_parser.h"
#include "argus_client.h"
#include "rasql_common.h"
#include "rasplit.h"

#define ARGUS_MAX_TABLE_LIST_SIZE	0x10000

extern int RaDaysInAMonth[12];
extern void RaSQLQuerySecondsTable (unsigned int, unsigned int); /* temporary */

char **
ArgusCreateSQLTimeTableNames (struct ArgusParserStruct *parser,
                              time_t *ArgusTableStartSecs,
                              time_t *ArgusTableEndSecs,
                              int ArgusSQLSecondsTable,
                              const struct ArgusAdjustStruct * const nadp,
                              const char * const table)
{
   char **retn = NULL, *fileStr = NULL;
   char *ArgusSQLTableNameBuf;
   int retnIndex = 0;

   if ((retn = ArgusCalloc(sizeof(void *), ARGUS_MAX_TABLE_LIST_SIZE)) == NULL)
      ArgusLog(LOG_ERR, "%s ArgusCalloc %s", __func__, strerror(errno));

   ArgusSQLTableNameBuf = ArgusMalloc(MAXSTRLEN);
   if (ArgusSQLTableNameBuf == NULL)
      ArgusLog(LOG_ERR, "%s failed to allocate memory for table name %s",
               __func__, strerror(errno));

   retnIndex = 0;

   if (table && (strchr(table, '%') || strchr(table, '$'))) {
      if (nadp->size > 0) {
         int size = nadp->size / 1000000;
         long long start;
         time_t tableSecs;
         struct tm tmval;

         if (parser->startime_t.tv_sec > 0) {
            start = parser->startime_t.tv_sec * 1000000LL;
         } else
            start = parser->ArgusRealTime.tv_sec * 1000000LL + parser->ArgusRealTime.tv_usec;

         if (parser->lasttime_t.tv_sec > parser->ArgusRealTime.tv_sec)
            parser->lasttime_t = parser->ArgusRealTime;

         *ArgusTableEndSecs = start / 1000000;

         while (*ArgusTableEndSecs < parser->lasttime_t.tv_sec) {
               fileStr = NULL;
               tableSecs = *ArgusTableEndSecs;

               switch (nadp->qual) {
                  case ARGUSSPLITYEAR:
                  case ARGUSSPLITMONTH:
                  case ARGUSSPLITWEEK: 
                     gmtime_r(&tableSecs, &tmval);
                     break;
               }

               switch (nadp->qual) {
                  case ARGUSSPLITYEAR:
                     tmval.tm_mon = 0;
                  case ARGUSSPLITMONTH:
                     tmval.tm_mday = 1;

                  case ARGUSSPLITWEEK: 
                     if (nadp->qual == ARGUSSPLITWEEK) {
                        if ((tmval.tm_mday - tmval.tm_wday) < 0) {
                           if (tmval.tm_mon == 0) {
                              if (tmval.tm_year != 0)
                                 tmval.tm_year--;
                              tmval.tm_mon = 11;
                           } else {
                              tmval.tm_mon--;
                           }
                           tmval.tm_mday = RaDaysInAMonth[tmval.tm_mon];
                        }
                        tmval.tm_mday -= tmval.tm_wday;
                     }

                     tmval.tm_hour = 0;
                     tmval.tm_min  = 0;
                     tmval.tm_sec  = 0;
                     tableSecs = timegm(&tmval);
                     localtime_r(&tableSecs, &tmval);
#if defined(HAVE_TM_GMTOFF)
                     tableSecs -= tmval.tm_gmtoff;
#endif
                     break;

                  case ARGUSSPLITDAY:
                  case ARGUSSPLITHOUR:
                  case ARGUSSPLITMINUTE:
                  case ARGUSSPLITSECOND: {
                     localtime_r(&tableSecs, &tmval);
#if defined(HAVE_TM_GMTOFF)
                     tableSecs += tmval.tm_gmtoff;
#endif
                     tableSecs = tableSecs / size;
                     tableSecs = tableSecs * size;
#if defined(HAVE_TM_GMTOFF)
                     tableSecs -= tmval.tm_gmtoff;
#endif
                     break;
                  }
               }

               localtime_r(&tableSecs, &tmval);

               if (strftime(ArgusSQLTableNameBuf, MAXSTRLEN, table, &tmval) <= 0)
                  ArgusLog (LOG_ERR, "RaSendArgusRecord () ArgusCalloc %s\n", strerror(errno));

               *ArgusTableStartSecs = tableSecs;

               switch (nadp->qual) {
                  case ARGUSSPLITYEAR:  
                     tmval.tm_year++;
                     *ArgusTableEndSecs = mktime(&tmval);
                     break;
                  case ARGUSSPLITMONTH:
                     tmval.tm_mon++;
                     *ArgusTableEndSecs = mktime(&tmval);
                     break;
                  case ARGUSSPLITWEEK: 
                  case ARGUSSPLITDAY: 
                  case ARGUSSPLITHOUR: 
                  case ARGUSSPLITMINUTE: 
                  case ARGUSSPLITSECOND: 
                     *ArgusTableEndSecs = tableSecs + size;
                     break;
               }

               fileStr = ArgusSQLTableNameBuf;

               if (fileStr != NULL) {
                  retn[retnIndex++] = strdup(fileStr);
               }
            }

            /* when looking at explicit table expansion, we shouldn't
             * go to the Seconds table
             */

         } else
            ArgusLog(LOG_ERR, "ArgusCreateSQLTimeTableNames no time mode (-M time xx) specified");

      } else {
         if (table) {
            bcopy(table, ArgusSQLTableNameBuf, strlen(table));
            fileStr = ArgusSQLTableNameBuf;

            if (retn == NULL) {
               if ((retn = ArgusCalloc(sizeof(void *), 16)) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCreateSQLTimeTableNames ArgusCalloc %s", strerror(errno));
               retnIndex = 0;
            }

            retn[retnIndex++] = strdup(fileStr);

         } else
            if (ArgusSQLSecondsTable)
               retn[retnIndex++] = strdup("Seconds");
      }

   ArgusFree(ArgusSQLTableNameBuf);
   return (retn);
}

void
RaSQLQueryTable (MYSQL *RaMySQL, const char **tables,
                 int ArgusAutoId, int argus_version,
                 const char **ArgusTableColumnName)
{
   char *ArgusSQLStatement;
   char *buf, *sbuf;
   const char *table;
   MYSQL_ROW row;
   MYSQL_RES *mysqlRes;
   struct timeval now;
   int retn, x, i;

   if ((ArgusInput = (struct ArgusInput *) ArgusCalloc (1, sizeof(struct ArgusInput))) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

   ArgusSQLStatement = ArgusMalloc(MAXSTRLEN);
   if (ArgusSQLStatement == NULL)
      ArgusLog(LOG_ERR, "unable to allocate ArgusSQLStatement: %s", strerror(errno));
   *ArgusSQLStatement = 0;

   buf = ArgusMalloc(MAXARGUSRECORD);
   if (buf == NULL)
      ArgusLog(LOG_ERR, "unable to allocate buf: %s", strerror(errno));
   *buf = 0;

   sbuf = ArgusMalloc(MAXARGUSRECORD);
   if (sbuf == NULL)
      ArgusLog(LOG_ERR, "unable to allocate sbuf: %s", strerror(errno));

   ArgusInput->fd            = -1;
   ArgusInput->ArgusOriginal = (struct ArgusRecord *)&ArgusInput->ArgusOriginalBuffer;
   ArgusInput->mode          = ARGUS_DATA_SOURCE;
   ArgusInput->status       |= ARGUS_DATA_SOURCE;
   ArgusInput->index         = -1;
   ArgusInput->ostart        = -1;
   ArgusInput->ostop         = -1;

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&ArgusInput->lock, NULL);
#endif

   ArgusInput->ArgusInitCon.hdr.type  = ARGUS_MAR | argus_version;
   ArgusInput->ArgusInitCon.hdr.cause = ARGUS_START;
   ArgusInput->ArgusInitCon.hdr.len   = htons((unsigned short) sizeof(struct ArgusRecord)/4);

   ArgusInput->ArgusInitCon.argus_mar.argusid = (argus_version == ARGUS_VERSION_3)
                                                ? htonl(ARGUS_V3_COOKIE) : htonl(ARGUS_COOKIE);

   gettimeofday (&now, 0L);

   ArgusInput->ArgusInitCon.argus_mar.now.tv_sec  = now.tv_sec;
   ArgusInput->ArgusInitCon.argus_mar.now.tv_usec = now.tv_usec;

   ArgusInput->ArgusInitCon.argus_mar.major_version = VERSION_MAJOR;
   ArgusInput->ArgusInitCon.argus_mar.minor_version = VERSION_MINOR;

   bcopy((char *)&ArgusInput->ArgusInitCon, (char *)&ArgusParser->ArgusInitCon, sizeof (ArgusParser->ArgusInitCon));

   if (ArgusParser->ArgusSQLStatement != NULL)
      strcpy(ArgusSQLStatement, ArgusParser->ArgusSQLStatement);

   if (ArgusParser->tflag) {
      char *timeField = NULL;
      int i, slen = 0;

      for (i = 0; (ArgusTableColumnName[i] != NULL) && (i < ARGUSSQLMAXCOLUMNS); i++) {
         if (!(strcmp("ltime", ArgusTableColumnName[i]))) {
            timeField = "ltime";
            break;
         }
         if (!(strcmp("stime", ArgusTableColumnName[i])))
            timeField = "stime";
      }

      if (timeField == NULL) 
         timeField = "second";

      if ((slen = strlen(ArgusSQLStatement)) > 0) {
         snprintf (&ArgusSQLStatement[strlen(ArgusSQLStatement)], MAXSTRLEN - slen, " and ");
         slen = strlen(ArgusSQLStatement);
      }

      snprintf (&ArgusSQLStatement[slen], MAXSTRLEN - slen, "%s >= %d and %s <= %d", timeField, (int)ArgusParser->startime_t.tv_sec, timeField, (int)ArgusParser->lasttime_t.tv_sec);
   }

   for (i = 0; ((table = tables[i]) != NULL); i++) {
      if (!(strcmp ("Seconds", table))) {
         RaSQLQuerySecondsTable (ArgusParser->startime_t.tv_sec, ArgusParser->lasttime_t.tv_sec);

      } else {
         if (ArgusAutoId)
            sprintf (buf, "SELECT autoid,record from %s", table);
         else
            sprintf (buf, "SELECT record from %s", table);

         if (strlen(ArgusSQLStatement) > 0)
            sprintf (&buf[strlen(buf)], " WHERE %s", ArgusSQLStatement);

#ifdef ARGUSDEBUG
         ArgusDebug (1, "SQL Query %s\n", buf);
#endif
         if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) == 0) {
            if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
               if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                  while ((row = mysql_fetch_row(mysqlRes))) {
                     unsigned long *lengths = mysql_fetch_lengths(mysqlRes);
                     int autoid = 0;

                     bzero(sbuf, MAXARGUSRECORD);
                     if (ArgusAutoId && (retn > 1)) {
                        char *endptr;
                        autoid = strtol(row[0], &endptr, 10);
                        if (row[0] == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: autoid returned %s", row[0]);
                        x = 1;
                     } else
                        x = 0;

                     ArgusParser->ArgusAutoId = autoid;
                     bcopy (row[x], sbuf, (int) lengths[x]);

                     ArgusHandleRecord (ArgusParser, ArgusInput, (struct ArgusRecord *)sbuf, lengths[x], &ArgusParser->ArgusFilterCode);
                  }
               }

               mysql_free_result(mysqlRes);
            }

         } else {
            if (mysql_errno(RaMySQL) != ER_NO_SUCH_TABLE) {
               ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
#ifdef ARGUSDEBUG
            } else {
               ArgusDebug (4, "%s: skip missing table %s", __func__, table);
#endif
            }
         }
      }
   }

   ArgusFree(buf);
   ArgusFree(sbuf);
   ArgusFree(ArgusSQLStatement);
}

/* The array *columns[] must be allocated to hold ncolumns number of
 * char *pointers, but the char* elements should not be allocated before
 * calling RasqlManageGetColumns().  On return, the first *keylen elements
 * in the array are primary keys according to SQL.  The element following
 * the last column name is always NULL, so really only ncolumns-1 column
 * names can be recorded.
 */
int
RasqlManageGetColumns(MYSQL *RaMySQL, const char * const table, char **columns,
                      size_t ncolumns, size_t *keylen)
{
   unsigned int num_fields;
   unsigned int i;
   unsigned int pricount;	/* primary key columns */
   unsigned int other;		/* non-key column index */
   int retn = -1;
   int slen;
   char *query;
   MYSQL_RES *result;
   MYSQL_FIELD *fields;


   query = ArgusMalloc(MAXSTRLEN);
   if (query == NULL)
      ArgusLog(LOG_ERR, "%s unable to allocate query buffer\n", __func__);

   slen = snprintf(query, MAXSTRLEN, "SELECT * from %s LIMIT 1", table);
   if (slen >= MAXSTRLEN) {
#ifdef ARGUSDEBUG
      ArgusDebug(4, "%s query string too long\n", __func__);
#endif
   }

   retn = mysql_real_query(RaMySQL, query, slen);
   if (retn) {
      if (mysql_errno(RaMySQL) == ER_NO_SUCH_TABLE)
         retn = 0;
#ifdef ARGUSDEBUG
      ArgusDebug(4, "mysql_real_query error %s", mysql_error(RaMySQL));
#endif
      goto out;
   }

   result = mysql_store_result(RaMySQL);
   if (result == NULL)
      goto out;

   num_fields = mysql_num_fields(result);
   if (num_fields > ncolumns) {
#ifdef ARGUSDEBUG
      ArgusDebug(4, "%s not enough space to store column names\n", __func__);
#endif
      goto out;
   }

   fields = mysql_fetch_fields(result);
   pricount = 0;
   other = num_fields;

   /* Build the array of column names from both ends -- primary key
    * columns have the lowest numbered indices, non-key columns have
    * the largest indices.
    */

   for (i = 0; i < num_fields && pricount < other; i++) {
      if (fields[i].flags & PRI_KEY_FLAG) {
         columns[pricount] = strdup(fields[i].name);
         pricount++;
      } else {
         other--;
         columns[other] = strdup(fields[i].name);
      }
   }
   if (num_fields < ncolumns)
      columns[num_fields] = NULL;

   retn = (int)num_fields;
   *keylen = pricount;

out:
   ArgusFree(query);
   return retn;
}

/* caller is responsible for preventing concurrent accesses
 * to MYSQL *RaMySQL.
 */
void
RaSQLOptimizeTables (MYSQL *RaMySQL, const char **tables)
{
   int i;
   int len;
   char *query;
   MYSQL_RES *result;

#ifdef ARGUSDEBUG
      ArgusDebug(2, "%s\n", __func__);
#endif

   query = ArgusMalloc(MAXSTRLEN);
   if (query == NULL)
      ArgusLog(LOG_ERR, "%s unable to allocate query string\n");

   for (i = 0; tables[i]; i++) {
      len = snprintf(query, MAXSTRLEN, "OPTIMIZE TABLE %s", tables[i]);
      if (len >= MAXSTRLEN) {
         ArgusLog(LOG_WARNING, "%s table name too long?\n", __func__);
         continue;
      }

      /* If the table doesn't support optimization, keep going and
       * don't complain.
       */
      if (mysql_real_query(RaMySQL, query, len))
         continue;

      result = mysql_store_result(RaMySQL);
      if (result)
         mysql_free_result(result);
   }
   ArgusFree(query);
}
