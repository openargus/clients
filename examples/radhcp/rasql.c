/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2016 QoSient, LLC
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
 *
 *  rasql.c - this module provides basic sql operations for radhcp.1
 *
 *  Author: Carter Bullard carter@qosient.com
 */

/* 
 * $Id: //depot/gargoyle/clients/examples/radhcp/rasql.c#7 $
 * $DateTime: 2016/11/30 12:35:01 $
 * $Change: 3247 $
 */


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <argus_threads.h>
#include <argus_compat.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <rasplit.h>

static int ArgusCloseDown = 0;

#if defined(ARGUS_MYSQL)
#include "rabootp_sql.h"

#if defined(CYGWIN)
#define USE_IPV6
#endif

#define RA_CURSES_MAIN

#if defined(ARGUS_THREADS)
pthread_t RaMySQLThread = 0;
pthread_mutex_t RaMySQLlock;
#endif

#if defined(ARGUS_MYSQL)
#include <netdb.h>
#include <sys/socket.h>

#include <mysql.h>

char *RaDatabase = NULL;
char **RaTables = NULL;

long long ArgusTotalSQLSearches = 0;
long long ArgusTotalSQLUpdates  = 0;
long long ArgusTotalSQLWrites = 0;
 
int ArgusSQLBulkInsertSize = 0;
int ArgusSQLMaxPacketSize = 0;
int ArgusSQLBulkBufferSize = 0;
int ArgusSQLBulkBufferIndex = 0;
int ArgusSQLBulkBufferCount = 0;
char *ArgusSQLBulkLastTable = NULL;
char *ArgusSQLBulkBuffer = NULL;
char *ArgusSQLVersion = NULL;
int MySQLVersionMajor = 0;
int MySQLVersionMinor = 0;
int MySQLVersionSub = 0;

extern int ArgusSOptionRecord;

int ArgusDropTable = 0;
int ArgusCreateTable = 0;
int ArgusAutoId = 0;

struct timeval ArgusLastRealTime     = {0, 0};
struct timeval ArgusLastTime         = {0, 0};
struct timeval ArgusThisTime         = {0, 0};
struct timeval ArgusCurrentTime      = {0, 0};

static char ArgusSQLSaveTableNameBuf[1024];
int ArgusCreateSQLSaveTable(char *, char *);
char *ArgusCreateSQLSaveTableName (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);
extern struct RaBinProcessStruct *RaBinProcess;

int RaInitialized = 0;
char *RaSQLCurrentTable = NULL;
char RaSQLSaveTable[MAXSTRLEN];

#define RA_MAXTABLES            0x100000

char *RaTableExistsNames[RA_MAXTABLES];
char *RaTableCreateNames[RA_MAXTABLES];
char *RaTableCreateString[RA_MAXTABLES];
char *RaTableDeleteString[RA_MAXTABLES];

char *RaSource       = NULL;
char *RaArchive      = NULL;
char *RaLocalArchive = NULL;
char *RaFormat       = NULL;
char *RaTable        = NULL;
int   RaPeriod       = 1;
int   RaStatus       = 1;

char ArgusArchiveBuf[MAXPATHNAMELEN];
char RaLocalArchiveBuf[MAXSTRLEN];

char *RaHost = NULL, *RaUser = NULL, *RaPass = NULL;
int RaPort = 0;

struct ArgusInput *ArgusInput = NULL;

MYSQL_ROW row;
MYSQL *RaMySQL = NULL;

int
ArgusMySQLProcess(int argc, char **argv)
{
   struct ArgusParserStruct *parser = NULL;
   int i, cc;

   for (i = 0, cc = 0; i < argc; i++)
      cc += strlen(argv[i]);

   if (strchr (argv[0], '/'))
      argv[0] = strrchr(argv[0], '/') + 1;

   if ((parser = ArgusNewParser(argv[0])) != NULL) {
      ArgusParser = parser;
      ArgusMainInit (parser, argc, argv);
      ArgusClientInit (parser);

#if defined(ARGUS_THREADS)
      sigset_t blocked_signals;

      sigfillset(&blocked_signals);
      sigdelset(&blocked_signals, SIGTERM);
      sigdelset(&blocked_signals, SIGINT);
      sigdelset(&blocked_signals, SIGWINCH);

      pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

      if (parser->writeDbstr != NULL) {
         if (parser->readDbstr != NULL)
            free(parser->readDbstr);
         parser->readDbstr = NULL; //if writing we'll need to read the same db
      }

#if defined(ARGUS_MYSQL)

      if (RaDatabase && RaTable)
         parser->RaTasksToDo = 1;

      {
         sigset_t blocked_signals;
         sigset_t sigs_to_catch;

         sigfillset(&blocked_signals);
         pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

         sigemptyset(&sigs_to_catch);
         sigaddset(&sigs_to_catch, SIGHUP);
         sigaddset(&sigs_to_catch, SIGTERM);
         sigaddset(&sigs_to_catch, SIGQUIT);
         sigaddset(&sigs_to_catch, SIGINT);
         pthread_sigmask(SIG_UNBLOCK, &sigs_to_catch, NULL);
      }
#endif

      ArgusCloseDown = 1;
      mysql_close(RaMySQL);
#endif
   }

#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#else
   return (NULL);
#endif
}

int
RaProcessSplitOptions(struct ArgusParserStruct *parser, char *str, int len, struct ArgusRecordStruct *ns)
{
   char resultbuf[MAXSTRLEN], tmpbuf[MAXSTRLEN];
   char *ptr = NULL, *tptr = str;
   int retn = 0, i, x;

   bzero (resultbuf, len);

   while ((ptr = strchr (tptr, '$')) != NULL) {
      *ptr++ = '\0';
      sprintf (&resultbuf[strlen(resultbuf)], "%s", tptr);

      for (i = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (!strncmp (RaPrintAlgorithmTable[x].field, ptr, strlen(RaPrintAlgorithmTable[x].field))) {
            bzero (tmpbuf, MAXSTRLEN);
            RaPrintAlgorithmTable[x].print(parser, tmpbuf, ns, RaPrintAlgorithmTable[x].length);

            while (isspace((int)tmpbuf[strlen(tmpbuf) - 1]))
               tmpbuf[strlen(tmpbuf) - 1] = '\0';

            while (isspace((int)tmpbuf[i])) i++;
            sprintf (&resultbuf[strlen(resultbuf)], "%s", &tmpbuf[i]);

            ptr += strlen(RaPrintAlgorithmTable[x].field);
            while (*ptr && (*ptr != '$'))
               bcopy (ptr++, &resultbuf[strlen(resultbuf)], 1);
            break;
         }
      }

      tptr = ptr;
      retn++;
   }

   if (retn) {
      bzero (str, len);
      bcopy (resultbuf, str, strlen(resultbuf));
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessSplitOptions(%s, %d, 0x%x): returns %d", str, len, ns, retn);
#endif

   return (retn);
}

#if defined(ARGUS_MYSQL)


/*
   Mysql URL that we will respond to is:
      mysql://[username[:password]@]hostname[:port]/database/tablename
*/

void
RaMySQLInit ()
{
   my_bool reconnectbuf = 1, *reconnect = &reconnectbuf;
   char *sptr = NULL, *ptr;
   char userbuf[1024], sbuf[1024], db[1024], *dbptr = NULL;
   MYSQL_RES *mysqlRes;
   int retn = 0, x;

   bzero((char *)RaTableExistsNames,  sizeof(RaTableExistsNames));
   bzero((char *)RaTableCreateNames,  sizeof(RaTableCreateNames));
   bzero((char *)RaTableCreateString, sizeof(RaTableCreateString));
   bzero((char *)RaTableDeleteString, sizeof(RaTableDeleteString));

   if (ArgusParser->MySQLDBEngine == NULL)
      ArgusParser->MySQLDBEngine = strdup("MyISAM");

   if ((RaUser == NULL) && (ArgusParser->dbuserstr != NULL)) {
      bzero(userbuf, sizeof(userbuf));
      strncpy (userbuf, ArgusParser->dbuserstr, sizeof(userbuf));
      if ((sptr = strchr (userbuf, ':')) != NULL) {
         *sptr++ = '\0';
         RaPass = strdup(sptr);
      }
      RaUser = strdup(userbuf);
   }

   if ((RaPass == NULL) && (ArgusParser->dbpassstr != NULL))
      RaPass = ArgusParser->dbpassstr;

   if (RaDatabase == NULL) {
      if (ArgusParser->writeDbstr != NULL)
         RaDatabase = strdup(ArgusParser->writeDbstr);

      else if (ArgusParser->readDbstr != NULL)
         RaDatabase = strdup(ArgusParser->readDbstr);

      if (RaDatabase != NULL)
         if (!(strncmp("mysql:", RaDatabase, 6))) {
            char *tmp = RaDatabase;
            RaDatabase = strdup(&RaDatabase[6]);
            free(tmp);
         }
   }

   if (RaDatabase == NULL) {
#ifdef ARGUSDEBUG
      ArgusDebug(1, "no database specified"); 
#endif
   } else {
      sprintf(db, "%s", RaDatabase);
      dbptr = db;
/*
      //[[username[:password]@]hostname[:port]]/database/tablename
*/
      if (!(strncmp ("//", dbptr, 2))) {
         char *rhost = NULL, *ruser = NULL, *rpass = NULL;
         if ((strncmp ("///", dbptr, 3))) {
            dbptr = &dbptr[2];
            rhost = dbptr;
            if ((ptr = strchr (dbptr, '/')) != NULL) {
               *ptr++ = '\0';
               dbptr = ptr;

               if ((ptr = strchr (rhost, '@')) != NULL) {
                  ruser = rhost;
                  *ptr++ = '\0';
                  rhost = ptr;
                  if ((ptr = strchr (ruser, ':')) != NULL) {
                     *ptr++ = '\0';
                     rpass = ptr;
                  } else {
                     rpass = NULL;
                  }
               }

               if ((ptr = strchr (rhost, ':')) != NULL) {
                  *ptr++ = '\0';
                  RaPort = atoi(ptr);
               }
            } else
               dbptr = NULL;

         } else {
            dbptr = &dbptr[3];
         }

         if (ruser != NULL) {
            if (RaUser != NULL) free(RaUser);
            RaUser = strdup(ruser);
         }
         if (rpass != NULL) {
            if (RaPass != NULL) free(RaPass);
            RaPass = strdup(rpass);
         }
         if (rhost != NULL) {
            if (RaHost != NULL) free(RaHost);
            RaHost = strdup(rhost);
         }
         free(RaDatabase);
         RaDatabase = strdup(dbptr);
      }
 
      if ((ptr = strchr (RaDatabase, '/')) != NULL) {
         *ptr++ = '\0';
         RaTable = ptr;

         if (ArgusParser->writeDbstr != NULL)
            snprintf (RaSQLSaveTable, MAXSTRLEN, "%s", RaTable);
      }

      if (!(ArgusParser->status & ARGUS_REAL_TIME_PROCESS))
         ArgusLastTime = ArgusParser->ArgusRealTime;

      MUTEX_INIT(&RaMySQLlock, NULL);
      if (MUTEX_LOCK(&RaMySQLlock) == 0) {
         if (RaMySQL == NULL)
            if ((RaMySQL = (void *) ArgusCalloc(1, sizeof(*RaMySQL))) == NULL)
               ArgusLog(LOG_ERR, "RaMySQLInit: ArgusCalloc error %s", strerror(errno));
       
         if ((mysql_init(RaMySQL)) == NULL)
            ArgusLog(LOG_ERR, "mysql_init error %s");

         if (!mysql_thread_safe())
            ArgusLog(LOG_INFO, "mysql not thread-safe");

         mysql_options(RaMySQL, MYSQL_READ_DEFAULT_GROUP, ArgusParser->ArgusProgramName);
         mysql_options(RaMySQL, MYSQL_OPT_RECONNECT, reconnect);

#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaMySQLInit: connect %s %s %d\n", RaHost, RaUser, RaPort);
#endif

         if ((mysql_real_connect(RaMySQL, RaHost, RaUser, RaPass, NULL, RaPort, NULL, 0)) == NULL) {
#ifdef ARGUSDEBUG
            ArgusDebug(1, "mysql_connect error %s", mysql_error(RaMySQL));
#endif
         } else {
            bzero(sbuf, sizeof(sbuf));
            sprintf (sbuf, "SHOW VARIABLES LIKE 'version'");

            if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
               ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

            if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
               if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                  while ((row = mysql_fetch_row(mysqlRes))) {
                     int matches = 0;
                     unsigned long *lengths;
                     lengths = mysql_fetch_lengths(mysqlRes);
                     sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");

                    ArgusSQLVersion = strdup(sbuf);
                    if ((matches = sscanf(ArgusSQLVersion,"%d.%d.%d", &MySQLVersionMajor, &MySQLVersionMinor, &MySQLVersionSub)) > 0) {
                     }
                  }
               }
               mysql_free_result(mysqlRes);
            }

            bzero(sbuf, sizeof(sbuf));
            sprintf (sbuf, "SHOW VARIABLES LIKE 'bulk_insert_buffer_size'");

            if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
               ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

            if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
               if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                  while ((row = mysql_fetch_row(mysqlRes))) {
                     unsigned long *lengths;
                     lengths = mysql_fetch_lengths(mysqlRes);
                     sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");

                    ArgusSQLBulkBufferSize = (int)strtol(sbuf, (char **)NULL, 10);
                  }
               }
               mysql_free_result(mysqlRes);
            }

            bzero(sbuf, sizeof(sbuf));
            sprintf (sbuf, "SHOW VARIABLES LIKE 'max_allowed_packet'");

            if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
               ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

            if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
               if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                  while ((row = mysql_fetch_row(mysqlRes))) {
                     unsigned long *lengths;
                     lengths = mysql_fetch_lengths(mysqlRes);
                     sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");
                     
                    ArgusSQLMaxPacketSize = (int)strtol(sbuf, (char **)NULL, 10);
                  }
               }
               mysql_free_result(mysqlRes);
            }

            ArgusSQLBulkInsertSize = (ArgusSQLMaxPacketSize < ArgusSQLBulkBufferSize) ? ArgusSQLMaxPacketSize : ArgusSQLBulkBufferSize;

            if ((ArgusSQLBulkBuffer = calloc(1, ArgusSQLBulkInsertSize)) == NULL)
               ArgusLog(LOG_WARNING, "ArgusMySQLInit: cannot alloc bulk buffer size %d\n", ArgusSQLBulkInsertSize);

            bzero(sbuf, sizeof(sbuf));
            sprintf (sbuf, "CREATE DATABASE IF NOT EXISTS %s", RaDatabase);

            if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)  
               ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

            sprintf (sbuf, "USE %s", RaDatabase);

            if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
               ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

            if ((mysqlRes = mysql_list_tables(RaMySQL, NULL)) != NULL) {
               char sbuf[MAXSTRLEN];

               if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                  int thisIndex = 0;

                  while ((thisIndex < RA_MAXTABLES) && (row = mysql_fetch_row(mysqlRes))) {
                     unsigned long *lengths;
                     lengths = mysql_fetch_lengths(mysqlRes);
                     bzero(sbuf, sizeof(sbuf));

                     for (x = 0; x < retn; x++)
                        sprintf(&sbuf[strlen(sbuf)], "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

                     RaTableExistsNames[thisIndex++] = strdup (sbuf);
                  }

               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (2, "mysql_num_fields() returned zero.\n");
#endif
               }
               mysql_free_result(mysqlRes);
            }

            if (ArgusParser->writeDbstr != NULL) {
               char *ptr;
               sprintf (ArgusParser->RaDBString, "-w %s", ArgusParser->writeDbstr);
               if ((ptr = strrchr(ArgusParser->writeDbstr, '/')) != NULL)
                  *ptr = '\0';

            } else 
            if (ArgusParser->readDbstr != NULL) {
               char *ptr;
               sprintf (ArgusParser->RaDBString, "-r %s", ArgusParser->readDbstr);
               if ((ptr = strrchr(ArgusParser->readDbstr, '/')) != NULL)
                  *ptr = '\0';
            } else  {
               sprintf (ArgusParser->RaDBString, "db %s", RaDatabase);

               if (RaHost)
                  sprintf (&ArgusParser->RaDBString[strlen(ArgusParser->RaDBString)], "@%s", RaHost);

               sprintf (&ArgusParser->RaDBString[strlen(ArgusParser->RaDBString)], " user %s", RaUser);
            }
         }
         MUTEX_UNLOCK(&RaMySQLlock);
      }

      if ((ArgusParser->ArgusInputFileList != NULL)  ||
           (ArgusParser->ArgusRemoteHosts && (ArgusParser->ArgusRemoteHosts->count > 0))) {

         if (strlen(RaSQLSaveTable) > 0) {
            if (!((strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$'))))
               if (ArgusCreateSQLSaveTable(RaDatabase, RaSQLSaveTable))
                  ArgusLog(LOG_ERR, "mysql create %s.%s returned error", RaDatabase, RaSQLSaveTable);
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaMySQLInit () RaSource %s RaArchive %s RaFormat %s", RaSource, RaArchive, RaFormat);
#endif
}

/*
   So first look to see if the table already exists.
   If so and we're suppose to delete, then delete it.
   Then look to see if the name is in our list of default
   RaTableCreateNames[] to see if we need to remove it
   from that list, if we didn't catch the table in the
   other list.  At the end of this routine cindex is pointing 
   at the right place.
*/

extern int RaDaysInAMonth[12];

time_t ArgusTableStartSecs = 0;
time_t ArgusTableEndSecs = 0;



char *
ArgusCreateSQLSaveTableName (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, char *table)
{
   struct ArgusAdjustStruct *nadp = &RaBinProcess->nadp;
   int timeLabel = 0, objectLabel = 0;
   char *retn = NULL;

   if (strchr(table, '%')) timeLabel = 1;
   if (strchr(table, '$')) objectLabel = 1;

   if (timeLabel || objectLabel) {
      int size = nadp->size / 1000000;
      long long start;
      time_t tableSecs;
      struct tm tmval;

      if (ns != NULL) 
         start = ArgusFetchStartuSecTime(ns);
      else 
         start = parser->ArgusRealTime.tv_sec * 1000000LL + parser->ArgusRealTime.tv_usec;
      
      if (timeLabel && (start == 0)) 
         return retn;

      tableSecs = start / 1000000;

      if (!(ArgusTableStartSecs) || !((tableSecs >= ArgusTableStartSecs) && (tableSecs < ArgusTableEndSecs))) {
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

         if (strftime(ArgusSQLSaveTableNameBuf, MAXSTRLEN, table, &tmval) <= 0)
            ArgusLog (LOG_ERR, "ArgusCreateSQLSaveTableName () strftime %s\n", strerror(errno));

         RaProcessSplitOptions(ArgusParser, ArgusSQLSaveTableNameBuf, MAXSTRLEN, ns);

         ArgusTableStartSecs = tableSecs;

         switch (nadp->qual) {
            case ARGUSSPLITYEAR:  
               tmval.tm_year++;
               ArgusTableEndSecs = mktime(&tmval);
               break;
            case ARGUSSPLITMONTH:
               tmval.tm_mon++;
               ArgusTableEndSecs = mktime(&tmval);
               break;
            case ARGUSSPLITWEEK: 
            case ARGUSSPLITDAY: 
            case ARGUSSPLITHOUR: 
            case ARGUSSPLITMINUTE: 
            case ARGUSSPLITSECOND: 
               ArgusTableEndSecs = tableSecs + size;
               break;
         }
      }

      retn = ArgusSQLSaveTableNameBuf;

   } else {
      bcopy(ArgusSQLSaveTableNameBuf, table, strlen(table));
      retn = ArgusSQLSaveTableNameBuf;
   }

   return (retn);
}

char *ArgusGetSQLSaveTable(void);

char *
ArgusGetSQLSaveTable()
{
   char *retn = NULL;

   if (MUTEX_LOCK(&RaMySQLlock) == 0) {
      if (RaSQLCurrentTable && (strlen(RaSQLCurrentTable) > 0))
         retn = strdup(RaSQLCurrentTable);

      MUTEX_UNLOCK(&RaMySQLlock);
   }

   return retn;
}

int
ArgusCreateSQLSaveTable(char *db, char *table)
{
   int retn = 0, cindex = 0, ind = 0, i, x, exists = 0;
   struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
   char stable[1024], sbuf[MAXSTRLEN], kbuf[MAXSTRLEN];
   MYSQL_RES *mysqlRes;

   MUTEX_LOCK(&RaMySQLlock);

   if ((db != NULL) && (table != NULL)) {
      sprintf (stable, "%s.%s", db, table);
      bzero(sbuf, sizeof(sbuf));
      bzero(kbuf, sizeof(kbuf));

      sprintf (sbuf, "SHOW TABLES LIKE '%s'", table);
      if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
         ArgusLog(LOG_INFO, "ArgusCreateSQLSaveTable: mysql_real_query %s error %s", sbuf, mysql_error(RaMySQL));

      if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
         exists = mysql_num_rows(mysqlRes);
         mysql_free_result(mysqlRes);
      }

      if (ArgusDropTable) {
         if (exists) {
#ifdef ARGUSDEBUG
            ArgusDebug (2, "ArgusCreateSQLSaveTable: drop table %s\n", table);
#endif
            sprintf (sbuf, "DROP TABLE %s", table);
            if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
               ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));
            exists = 0;
         }
      }

      if (!exists) {
         RaTableCreateNames[cindex] = strdup(stable);
         RabootpSQLCreateTable(ArgusParser, stable);
      } else {
         if (RaSQLCurrentTable == NULL)
            RaSQLCurrentTable = strdup(stable);
         retn = 0;
      }
   } else {
      char *tbl = RaSQLCurrentTable;
      RaSQLCurrentTable = NULL;
      free(tbl);
   }

   MUTEX_UNLOCK(&RaMySQLlock);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCreateSQLSaveTable (%s, %s) returning", db, table, retn);
#endif
   return (retn);
}


#endif
#endif
#endif
