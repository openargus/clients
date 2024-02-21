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
 *
 *  rastatus - read various status data sources and put values into
 *             a database.
 *
 *  Author: Carter Bullard carter@qosient.com
 */

/* 
 * $Id: //depot/gargoyle/clients/examples/ramysql/rasqlinsert.c#40 $
 * $DateTime: 2016/12/05 10:32:59 $
 * $Change: 3255 $
 */


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#define ArgusEvents

#include <argus_threads.h>
#include "rasql_common.h"
#include "rastatus.h"
#include <time.h>


#if defined(ARGUS_THREADS)
#include <pthread.h>
void *ArgusEventsProcess(void *);
#endif

#define ARGUS_RECORD_MODIFIED   0x0100
#define ARGUS_RECORD_CLEARED    0x0200

#define ARGUS_SQL_INSERT        0x0100000
#define ARGUS_SQL_SELECT        0x0200000
#define ARGUS_SQL_UPDATE        0x0400000
#define ARGUS_SQL_DELETE        0x0800000
#define ARGUS_SQL_REWRITE       0x1000000

#define ARGUS_SQL_STATUS        (ARGUS_SQL_INSERT | ARGUS_SQL_SELECT | ARGUS_SQL_UPDATE | ARGUS_SQL_DELETE)

#define ARGUS_MAX_OS_BUF	65536
#define ARGUS_MAX_OS_BUF	65536

#if defined(CYGWIN)
#define USE_IPV6
#endif

#define RA_CURSES_MAIN
#include <rasqlinsert.h>

#if defined(ARGUS_THREADS)
pthread_attr_t RaTopAttr;
pthread_t RaMySQLThread = 0;
pthread_t RaMySQLUpdateThread = 0;
pthread_mutex_t RaMySQLlock;
#endif

#if defined(ARGUS_MYSQL)
long long ArgusTotalInsertSQLStatements = 0;
long long ArgusTotalUpdateSQLStatements = 0;
long long ArgusTotalSelectSQLStatements = 0;
long long ArgusTotalDeleteSQLStatements = 0;

unsigned long long ArgusTotalCommitSQLStatements = 0ULL;

#include <netdb.h>
#include <sys/socket.h>

#include "argus_mysql.h"

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
char *ArgusTableColumnName[ARGUSSQLMAXCOLUMNS];
size_t ArgusTableColumnKeys;
int MySQLVersionMajor = 0;
int MySQLVersionMinor = 0;
int MySQLVersionSub = 0;

extern int ArgusSOptionRecord;
int ArgusDeleteTable = 0;

int ArgusDropTable = 0;
int ArgusCreateTable = 0;
int ArgusAutoId = 0;
int ArgusSQLSecondsTable = 0;
time_t ArgusTableStartSecs = 0;
time_t ArgusTableEndSecs = 0;

struct timeval ArgusLastRealTime     = {0, 0};
struct timeval ArgusLastTime         = {0, 0};
struct timeval ArgusThisTime         = {0, 0};
struct timeval ArgusCurrentTime      = {0, 0};

struct tm ArgusSaveTableTmStruct;
time_t ArgusSaveTableSeconds = 0;

int ArgusCreateSQLSaveTable(char *, char *);
int ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, int);
struct ArgusRecordStruct *ArgusCheckSQLCache(struct ArgusParserStruct *, struct RaBinStruct *, struct ArgusRecordStruct *);

struct ArgusSQLQueryStruct *ArgusGenerateSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, int);
void ArgusDeleteSQLQuery (struct ArgusSQLQueryStruct *);

void RaMySQLDeleteRecords(struct ArgusParserStruct *, struct ArgusRecordStruct *);

void RaSQLQueryNetworksTable (unsigned int, unsigned int, unsigned int);
void RaSQLQueryProbes (void);
void RaSQLQuerySecondsTable (unsigned int, unsigned int);
void RaSQLQueryDatabaseTable (char *, unsigned int, unsigned int);

char *ArgusCreateSQLSaveTableName (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *, char *, int);
struct RaBinProcessStruct *ArgusNewRateBins (struct ArgusParserStruct *, struct ArgusRecordStruct *);

char *RaFetchStatusData (struct ArgusEventsStruct *, struct ArgusEventRecordStruct *, unsigned char);
void RaClearArgusEventRecord(void);
void ArgusProcessSqlData(struct RaBinStruct *);
int RaStatusProcessSQLStatement(struct ArgusEventRecordStruct *, char *);
int RaParseDiskStatus(struct ArgusEventRecordStruct *, char *);

int RaInitialized = 0;
int RaSQLMcastMode = 0;

char *RaProbeString = NULL;
char *RaSQLCurrentTable = NULL;

char RaSQLSaveTable[MAXSTRLEN];

unsigned int RaTableFlags = 0;

char *RaTableValues[256];
char *RaTableCreateNames[RA_MAXTABLES];
char *RaTableCreateString[RA_MAXTABLES];
char *RaTableDeleteString[RA_MAXTABLES];
char ArgusSQLTableNameBuf[MAXSTRLEN];

char *RaSource       = NULL;
char *RaArchive      = NULL;
char *RaLocalArchive = NULL;
char *RaFormat       = NULL;
char *RaTable        = NULL;
int   RaPeriod       = 1;
int   RaStatus       = 1;

int   RaSQLMaxSecs   = 0;
int   RaSQLUpdateDB  = 1;
int   RaSQLCacheDB   = 0;
int   RaSQLRewrite   = 0;
int   RaSQLDBInserts = 0;
int   RaSQLDBUpdates = 0;
int   RaSQLDBDeletes = 1;
int   RaFirstManRec  = 1;

char ArgusArchiveBuf[MAXPATHNAMELEN];
char RaLocalArchiveBuf[MAXSTRLEN];

extern char *RaRemoteFilter;
extern char *RaLocalFilter;

extern char RaFilterSQLStatement[];
extern int argus_version;

char *RaHost = NULL, *RaUser = NULL, *RaPass = NULL;
int RaPort = 0;

struct ArgusInput *ArgusInput = NULL;
void RaMySQLInit (int);

MYSQL_ROW row;
MYSQL *RaMySQL = NULL;

#endif


int
main(int argc, char **argv)
{
   struct ArgusParserStruct *parser = NULL;
   int i, cc;
   pthread_attr_t attr;

   for (i = 0, cc = 0; i < argc; i++)
      cc += strlen(argv[i]);

   if (strchr (argv[0], '/'))
      argv[0] = strrchr(argv[0], '/') + 1;

   ArgusThreadsInit(&attr);

   if ((parser = ArgusNewParser(argv[0])) != NULL) {
      struct ArgusEventsStruct *events = NULL;
      ArgusParser = parser;
      ArgusMainInit (parser, argc, argv);

      ArgusClientInit (parser);

      if (parser->writeDbstr != NULL) {
         if (parser->readDbstr != NULL)
            free(parser->readDbstr);
         parser->readDbstr = NULL; //if writing we'll need to read the same db
      }

#if defined(ARGUS_MYSQL)
      RaMySQLInit(RaSQLRewrite ? 2 : 1);
      ArgusParseInit(parser, NULL);

      for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
         if (parser->RaPrintAlgorithmList[i] != NULL) {
            parser->RaPrintAlgorithm = parser->RaPrintAlgorithmList[i];
            if (!strncmp(parser->RaPrintAlgorithm->field, "autoid", 6)) {
               ArgusAutoId = 1;
               break;
            }
         }
      }

      if (RaDatabase && RaTable)
         parser->RaTasksToDo = 1;
#endif
      ArgusInitEvents (parser->ArgusEventsTask);

#if defined(ARGUS_THREADS)
      if ((events = parser->ArgusEventsTask) != NULL) {
         pthread_join(events->thread, NULL);
         ArgusCloseEvents (events);
      } else {
         ArgusLog (LOG_ERR, "No events\n");
      }
#endif /* ARGUS_THREADS */
      mysql_close(RaMySQL);
   }

   exit (0);
}


void
RaClearArgusEventRecord(void)
{
   ArgusDeleteList (ArgusEventsTask->ArgusEventsList, ARGUS_EVENT_LIST);
   ArgusEventsTask->ArgusEventsList = NULL;
}

void ArgusWindowClose(void) { };
void RaSQLQuerySecondsTable (unsigned int start, unsigned int stop) { };
void RaSQLQueryDatabaseTable (char *table, unsigned int start, unsigned int stop) { };

void
ArgusProcessSqlData(struct RaBinStruct *bin)
{
   if (bin && bin->agg) {
      struct ArgusQueueStruct *queue = bin->agg->queue;

      if (MUTEX_LOCK(&queue->lock) == 0) {
#if defined(ARGUS_MYSQL)
         struct ArgusQueueHeader *qhdr = queue->start;
         int i = 0;
         struct ArgusRecordStruct *ns;

         for (i = 0; qhdr && (i < queue->count); i++, qhdr = qhdr->nxt) {
            ns = (struct ArgusRecordStruct *)qhdr;
            if (ns && (ns->status & ARGUS_RECORD_MODIFIED)) {
               ns->status &= ~ARGUS_RECORD_MODIFIED;
               ArgusScheduleSQLQuery (ArgusParser, ArgusParser->ArgusAggregator, ns, bin->table, ARGUS_SQL_UPDATE);
            }
         }
#endif
         MUTEX_UNLOCK(&queue->lock);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (7, "ArgusProcessSqlData(%p)\n", bin);
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

int RaCheckedTables = 0;

void
RaMySQLInit (int ncons)
{
   char *sptr = NULL, *ptr;
   char userbuf[1024], sbuf[1024], db[1024], *dbptr = NULL;
   MYSQL_RES *mysqlRes;
   int retn = 0;

   bzero((char *)RaTableCreateNames,  sizeof(RaTableCreateNames));
   bzero((char *)RaTableCreateString, sizeof(RaTableCreateString));
   bzero((char *)RaTableDeleteString, sizeof(RaTableDeleteString));

   if (ArgusParser->MySQLDBEngine == NULL)
      ArgusParser->MySQLDBEngine = strdup("InnoDB");

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
      ArgusLog(LOG_ERR, "must specify database"); 

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
      int con;

      if (RaMySQL == NULL)
         if ((RaMySQL = (void *) ArgusCalloc(ncons, sizeof(*RaMySQL))) == NULL)
            ArgusLog(LOG_ERR, "RaMySQLInit: ArgusCalloc error %s", strerror(errno));
    
      for (con = 0; con < ncons; con++)
         if ((mysql_init(RaMySQL+con)) == NULL)
            ArgusLog(LOG_ERR, "mysql_init error %s");

      if (!mysql_thread_safe())
         ArgusLog(LOG_INFO, "mysql not thread-safe");

      mysql_options(RaMySQL, MYSQL_READ_DEFAULT_GROUP, ArgusParser->ArgusProgramName);

#ifdef ARGUSDEBUG
      ArgusDebug (2, "RaMySQLInit: connect %s %s %d\n", RaHost, RaUser, RaPort);
#endif

      for (con = 0; con < ncons; con++)
         if ((mysql_real_connect(RaMySQL+con, RaHost, RaUser, RaPass, NULL, RaPort, NULL, 0)) == NULL)
            ArgusLog(LOG_ERR, "mysql_connect error %s", mysql_error(RaMySQL));

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

#ifdef ARGUSDEBUG
      ArgusDebug (6, "RaMySQLInit () mysql_real_query: %s\n", sbuf);
#endif

      if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)  
         ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

      sprintf (sbuf, "USE %s", RaDatabase);

      if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)  
         ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));


      if (!RaCheckedTables) {
         if ((mysqlRes = mysql_list_tables(RaMySQL, NULL)) != NULL) {
            int x;
            if ((retn = mysql_num_fields(mysqlRes)) > 0) {
               char sbuf[MAXSTRLEN];
               int thisIndex = 0;
 
               while ((row = mysql_fetch_row(mysqlRes))) {
                  unsigned long *lengths;
                  lengths = mysql_fetch_lengths(mysqlRes);
                  bzero(sbuf, sizeof(sbuf));
                  for (x = 0; x < retn; x++)
                     sprintf(&sbuf[strlen(sbuf)], "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

                  RaExistsTableNames[thisIndex++] = strdup (sbuf);
               }
 
            } else {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "mysql_num_fields() returned zero.\n");
#endif
            }
 
            mysql_free_result(mysqlRes);

            for (x = 0; x < RA_MAXTABLES; x++) {
               if (RaExistsTableNames[x]) {
                  char sbuf[1024];
                  int i;

                  bzero (sbuf, 1024);
                  for (i = 0; i < RA_NUMTABLES; i++) {
                     if (RaCreateTableNames[i] != NULL) {
                        sprintf (sbuf, "%s", RaCreateTableNames[i]);
                        if (!(strcmp(RaExistsTableNames[x], sbuf))) {
#ifdef ARGUSDEBUG
                           ArgusDebug (4, "RaMySQLInit: table %s matches %s.\n", RaExistsTableNames[x], sbuf);
#endif
                           RaTableFlags |= (0x01 << i);
                           break;
                        }
                     }
                  }
                  free (RaExistsTableNames[x]);
                  RaExistsTableNames[x] = NULL;

               } else
                  break;
            }
         }

         if (RaTableFlags != RA_NUMTABLES_MASK) {
            int i;
            for (i = 0; i < RA_NUMTABLES; i++) {
               if (RaTableCreationString[i] != NULL) {
                  if (!(RaTableFlags & (0x01 << i))) {
                     char sbuf[1024];
                     bzero (sbuf, 1024);
                     sprintf (sbuf, "%s", RaTableCreationString[i]);
                     if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0) {
                        ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
                     }
                  }
               }
            }
         }
   
         RaCheckedTables = 1;
      }

      for (con = 0; con < ncons; con++)
         if ((retn = mysql_real_query(RaMySQL+con, sbuf, strlen(sbuf))) != 0)
            ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

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
      MUTEX_UNLOCK(&RaMySQLlock);
   }

   if ((ArgusParser->ArgusInputFileList != NULL)  ||
        (ArgusParser->ArgusRemoteHosts && (ArgusParser->ArgusRemoteHosts->count > 0))) {

      if (strlen(RaSQLSaveTable) > 0) {
         if (strchr(RaSQLSaveTable, '%')) {
            int err = 1;
            if (RaBinProcess != NULL) {
               struct ArgusAdjustStruct *nadp = &RaBinProcess->nadp;
               if (nadp->mode == ARGUSSPLITTIME) 
                  err = 0;
            }
            if (err)
               ArgusLog (LOG_ERR, "RaMySQLInit: mysql save table time subsitution, but time mode not set\n", strerror(errno));

         } else
            if (ArgusCreateSQLSaveTable(RaDatabase, RaSQLSaveTable))
               ArgusLog(LOG_ERR, "mysql create %s.%s returned error", RaDatabase, RaSQLSaveTable);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaMySQLInit () RaSource %s RaArchive %s RaFormat %s", RaSource, RaArchive, RaFormat);
#endif
}


struct ArgusSQLQueryObjectStruct {
   char *obj, *value;
};

int
RaStatusProcessSQLStatement(struct ArgusEventRecordStruct *evt, char *str)
{
   int retn = 0, i, slen, valIndex = 0, inc = 0;
   char sbuf[512], *sptr, *tptr, *cptr, *xptr;
   struct ArgusSQLQueryObjectStruct values[64];
   char *scptr = strdup(str);
   char *stptr = scptr;

   if ((evt->db != NULL) && (evt->table != NULL)) {

      if (strcmp(evt->db, RaDatabase)) {
         sprintf (sbuf, "USE %s", evt->db);

         if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
            ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

         RaDatabase = evt->db;
      }


      if ((cptr = strstr(scptr, "[{")) != NULL) {
         cptr += 2;
         while ((sptr = strsep(&cptr, "{}")) != NULL) {
            char sval[32], *aptr;
            if (*sptr == ']')
               break;

            if (*sptr != ',') {
               memset(values, 0, sizeof(values));
               memset(sbuf, 0, 512);
               valIndex = 0;

               sptr = strdup(sptr);
               aptr = sptr;

               while (((scptr = strsep(&aptr, ",")) != NULL) && (valIndex < 64)) {
                  if ((tptr = strchr(scptr, ':')) != NULL) {
                     *tptr++ = '\0';
                     slen = strlen(scptr) - 1;
                     while (ispunct(scptr[slen])) scptr[slen--] =  '\0';
                     while (ispunct(*scptr) || isspace(*scptr)) scptr++;
                     slen = strlen(tptr) - 1;
                     while (ispunct(tptr[slen])) tptr[slen--] =  '\0';
                     while (ispunct(*tptr) || isspace(*tptr)) tptr++;

                     values[valIndex].obj   = strdup(scptr);
                     if ((xptr = strstr(tptr, "kB")) != NULL) {
                        unsigned long long val;
                        *xptr = '\0';
                        val = strtoll(tptr, NULL, 0);
                        val *= 1024;
                        sprintf(sval, "%lld", val);
                        tptr = sval;
                     }
                     values[valIndex].value = strdup(tptr);
                  }
                  valIndex++;
               }
               free(sptr);

               inc = 0;
               sprintf (sbuf, "INSERT INTO %s (", evt->table);
               slen = strlen(sbuf);

               for (i = 0; i < valIndex; i++) {
                  slen = strlen(sbuf);
                  if (i > 0) sprintf (&sbuf[slen++], ",");
                  sprintf (&sbuf[slen], "`%s`", values[i].obj);
               }
               slen = strlen(sbuf);
               sprintf (&sbuf[slen], ") VALUES (");

               for (i = 0; i < valIndex; i++) {
                  slen = strlen(sbuf);
                  if (i > 0) sprintf (&sbuf[slen++], ",");
                  if ((strcmp("name", values[i].obj)) &&
                      (strcmp("procs", values[i].obj)))
                     sprintf (&sbuf[slen], "%s", values[i].value);
                  else
                     sprintf (&sbuf[slen], "\"%s\"", values[i].value);
               }
               slen = strlen(sbuf);
               sprintf (&sbuf[slen], ") ON DUPLICATE KEY UPDATE ");

               for (i = 0; i < valIndex; i++) {
                  slen = strlen(sbuf);

                  if (values[i].obj && ((strcmp("stime", values[i].obj)) &&
                                        (strcmp("name", values[i].obj)) &&
                                        (strcmp("procs", values[i].obj)))) {
                     if (inc++ > 0) sprintf (&sbuf[slen++], ",");
                     sprintf (&sbuf[slen], "`%s`=\"%s\"", values[i].obj, values[i].value);
                  }
               }
               slen = strlen(sbuf);
               sprintf (&sbuf[slen], ";");

               if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
                  ArgusLog(LOG_INFO, "ArgusCreateSQLSaveTable: mysql_real_query %s error %s", sbuf, mysql_error(RaMySQL));
            }
         }
         for (i = 0; i < valIndex; i++) {
            free(values[i].obj);
            free(values[i].value);
         }
      }
   }

   if (stptr != NULL) free(stptr);

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaStatusProcessSQLStatement (%p,'%s') returns %d", evt, str, retn);
#endif
   return (retn);
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

char *
ArgusCreateSQLSaveTableName (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, char *table, char *tbuf, int len)
{
   struct ArgusAdjustStruct *nadp = &RaBinProcess->nadp;
   int timeLabel = 0, objectLabel = 0;
   char *retn = NULL;

   if (strchr(table, '%')) {
      if (nadp->mode != ARGUSSPLITTIME) 
         return retn;
      timeLabel = 1;
   }
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

         if (strftime(tbuf, len, table, &tmval) <= 0)
            ArgusLog (LOG_ERR, "ArgusCreateSQLSaveTableName () strftime %s\n", strerror(errno));

         RaProcessSplitOptions(ArgusParser, tbuf, len, ns);

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

      retn = tbuf;

   } else {
      sprintf(tbuf, "%s", table);
      retn = tbuf;
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
      else
         retn = strdup(RaSQLSaveTable);
      MUTEX_UNLOCK(&RaMySQLlock);
   }

   return retn;
}

extern struct dbtblmem dbtables[];

int
ArgusCreateSQLSaveTable(char *db, char *table)
{
   int retn = 0, cindex = 0, ind = 0, i, x, exists = 0;
   struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
   char stable[1024], sbuf[MAXSTRLEN], kbuf[1024];
   MYSQL_RES *mysqlRes;

   MUTEX_LOCK(&RaMySQLlock);

   if ((db != NULL) && (table != NULL)) {
      sprintf (stable, "%s.%s", db, table);
 
      if (check_dbtbl(dbtables, (u_char *)stable) == NULL) {
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
            if (RaTableCreateNames[cindex])
               free(RaTableCreateNames[cindex]);

            RaTableCreateNames[cindex] = strdup(stable);

            sprintf (sbuf, "CREATE table %s (", RaTableCreateNames[cindex]);
            ind = 0;

            for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
               if (ArgusParser->RaPrintAlgorithmList[i] != NULL) {
                  ArgusParser->RaPrintAlgorithm = ArgusParser->RaPrintAlgorithmList[i];

                  if ((ArgusAutoId == 0) && !strncmp(ArgusParser->RaPrintAlgorithm->field, "autoid", 6))
                     ArgusAutoId = 1;

                  for (x = 0; x < ARGUS_MAX_PRINT_ALG; x++) {
                     if (!strcmp(ArgusParser->RaPrintAlgorithm->field, RaPrintAlgorithmTable[x].field)) {
                        if (ind++ > 0)
                           sprintf (&sbuf[strlen(sbuf)], ",");

                        sprintf (&sbuf[strlen(sbuf)], "%s %s", RaPrintAlgorithmTable[x].field, RaPrintAlgorithmTable[x].dbformat);
                        break;
                     }
                  }
               }
            }

            if ((ArgusParser->ArgusAggregator != NULL) || ArgusAutoId) {
               struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;

               long long mask = 0;

               while (agg != NULL) {
                  mask |= agg->mask;
                  agg = agg->nxt;
               }

               if (mask || ArgusAutoId) {
                  ind = 0;
                  sprintf (kbuf, "primary key (");

                  if (ArgusAutoId) {
                     sprintf (&kbuf[strlen(kbuf)], "autoid");
                     ind++;
                  }

                  if (mask) {
                     for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                        int found; 
                        if (mask & (0x01LL << i)) {
                           for (found = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                              if (ArgusParser->RaPrintAlgorithmList[x] != NULL) {
                                 ArgusParser->RaPrintAlgorithm = ArgusParser->RaPrintAlgorithmList[x];
                                 if (!strcmp(ArgusParser->RaPrintAlgorithm->field, ArgusMaskDefs[i].name)) {
                                    found = 1;
                                    break;
                                 }
                              }
                           }

                           if (!found)
                              ArgusLog(LOG_ERR, "key field '%s' not in schema (-s option)",  ArgusMaskDefs[i].name);

                           for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                              if (!(strcasecmp (ArgusMaskDefs[i].name, RaPrintAlgorithmTable[x].field))) {
                                 if (ind++ > 0)
                                    sprintf (&kbuf[strlen(kbuf)], ",");

                                 sprintf (&kbuf[strlen(kbuf)], "%s", RaPrintAlgorithmTable[x].field);
                                 break;
                              }
                           }
                        }
                     }
                  }
                  sprintf (&kbuf[strlen(kbuf)], ")");
               }
            }

            if (strlen(kbuf))
               snprintf (&sbuf[strlen(sbuf)], sizeof(sbuf), ", %s", kbuf);

            if (ArgusSOptionRecord)
               sprintf (&sbuf[strlen(sbuf)], ", record blob");

            if ((MySQLVersionMajor > 4) || ((MySQLVersionMajor == 4) &&
                                            (MySQLVersionMinor >= 1)))
               sprintf (&sbuf[strlen(sbuf)], ") ENGINE=%s", ArgusParser->MySQLDBEngine);
            else
               sprintf (&sbuf[strlen(sbuf)], ") TYPE=%s", ArgusParser->MySQLDBEngine);

            if (RaTableCreateString[cindex])
               free(RaTableCreateString[cindex]);
            RaTableCreateString[cindex] = strdup(sbuf);

            cindex++;

            for (i = 0; i < cindex; i++) {
               char *str = NULL;
               if (RaTableCreateNames[i] != NULL) {
                  if ((str = RaTableCreateString[i]) != NULL) {
#ifdef ARGUSDEBUG
                     ArgusDebug (2, "ArgusCreateSQLSaveTable: %s\n", str);
#endif
                     if ((retn = mysql_real_query(RaMySQL, str, strlen(str))) != 0)
                        ArgusLog(LOG_INFO, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

                     ArgusCreateTable = 1;
                  }
               }
            }

            lookup_dbtbl(dbtables, (u_char *)stable);
         }
      }

   } else {
      char *tbl = RaSQLCurrentTable;
      RaSQLCurrentTable = NULL;
      free(tbl);

      for (i = 0; i < RA_MAXTABLES; i++) {
         if (RaTableCreateNames[i] != NULL){free (RaTableCreateNames[i]); RaTableCreateNames[i] = NULL;}
         if (RaTableCreateString[i] != NULL){free (RaTableCreateString[i]); RaTableCreateString[i] = NULL;}
      }
   }

   MUTEX_UNLOCK(&RaMySQLlock);

#ifdef ARGUSDEBUG
   if (retn)
      ArgusDebug (1, "ArgusCreateSQLSaveTable (%s, %s) created", db, table);
#endif
   return (retn);
}


void
RaMySQLDeleteRecords(struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   if (RaSQLUpdateDB && strlen(RaSQLSaveTable)) {
      if (ns->htblhdr != NULL) {
         ArgusRemoveHashEntry(&ns->htblhdr);
         ns->htblhdr = NULL;
      }

      if (ns->hinthdr != NULL) {
         ArgusRemoveHashEntry(&ns->hinthdr);
         ns->hinthdr = NULL;
      }

      if (RaSQLDBDeletes)
         if (ArgusScheduleSQLQuery (ArgusParser, ArgusParser->ArgusAggregator, ns, RaSQLSaveTable, ARGUS_SQL_DELETE) != 0)
            ArgusLog(LOG_ERR, "RaMySQLDeleteRecords: ArgusScheduleSQLQuery error %s", strerror(errno));
   }

   ArgusDeleteRecordStruct (parser, ns);

#ifdef ARGUSDEBUG
      ArgusDebug (4, "RaMySQLDeleteRecords (0x%x, 0x%x) done", parser, ns);
#endif
}


// We construct the mysql query here.
// Query can get big, so we have a real query, and a debug string representing the query.
// The structure of the query is 

// If we are inserting the record, ArgusSOptionRecord == 1, we need to generate a mysql escaped record.




struct ArgusSQLQueryStruct *
ArgusGenerateSQLQuery (struct ArgusParserStruct *parser, struct ArgusAggregatorStruct *agg, struct ArgusRecordStruct *ns, char *tbl, int state)
{
   struct ArgusSQLQueryStruct *sqry = NULL;

   if (tbl != NULL) {
      if ((sqry = (void *) ArgusCalloc(1, sizeof(*sqry))) != NULL) {
         char *tmpbuf = ArgusMalloc(MAXBUFFERLEN);
         char   *sbuf = ArgusMalloc(MAXBUFFERLEN);
         char   *mbuf = ArgusMalloc((ARGUS_MAXRECORDSIZE * 2) + 1);
#ifdef ARGUSDEBUG
         char   *dbuf = ArgusMalloc(MAXSTRLEN);
#endif
         char tbuf[1024], fbuf[1024], ubuf[1024], *ptr, *tptr;
         char vbuf[1024], ibuf[1024];
         char *rbuf = NULL;

         struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs;
         struct ArgusRecord *argus = NULL;

         int y, len, ind = 0, mind = 0, iind = 0;
         int  nflag, keyField, uflag;

         nflag = parser->nflag;
         parser->nflag = 2;

         bzero(sbuf, 8);
         tbuf[0] = '\0';
         fbuf[0] = '\0';
         ubuf[0] = '\0';
         vbuf[0] = '\0';
         ibuf[0] = '\0';

         if (ArgusSOptionRecord)
           rbuf = ArgusCalloc(1, ARGUS_MAXRECORDSIZE);

         MUTEX_LOCK(&parser->lock);

         uflag = ArgusParser->uflag;
         ArgusParser->uflag++;

         for (parser->RaPrintIndex = 0; parser->RaPrintIndex < MAX_PRINT_ALG_TYPES; parser->RaPrintIndex++) {
            if (parser->RaPrintAlgorithmList[parser->RaPrintIndex] != NULL) {
               int process = 1;

               parser->RaPrintAlgorithm = parser->RaPrintAlgorithmList[parser->RaPrintIndex];

               if (strncmp(parser->RaPrintAlgorithm->field, "autoid", 6)) {
                  int len = parser->RaPrintAlgorithm->length;
                  len = (len > 256) ? len : 256;

                  keyField = 0;
                  *tmpbuf = '\0';

                  if (agg && agg->mask) {
                     for (y = 0; y < ARGUS_MAX_MASK_LIST; y++) {
                        if (agg->mask & (0x01LL << y)) {
                           if (!strcmp(parser->RaPrintAlgorithm->field, ArgusMaskDefs[y].name)) {
                              keyField = 1;
                           }
                        }
                     }
                  }

                  switch (state) {
                      case ARGUS_SQL_SELECT: 
                      case ARGUS_SQL_DELETE: 
                         if (keyField == 0) process = 0;
                         break;
                  }

                  if (ind++ > 0) {
                     sprintf (&fbuf[strlen(fbuf)], ",");
                     sprintf (&vbuf[strlen(vbuf)], ",");
                  }

                  if (keyField) {
                     if (mind++ > 0)
                        sprintf (&ubuf[strlen(ubuf)], " and ");
                  } else {
                     if (process) {
                        if (iind++ > 0)
                           sprintf (&ibuf[strlen(ibuf)], ",");
                     }
                  }

                  if (process) {
                     parser->RaPrintAlgorithm->print(parser, tmpbuf, ns, len);

                     if ((ptr = ArgusTrimString(tmpbuf)) != NULL) {
                        snprintf (tbuf, 1024, "\"%s\"", ptr);
                        tptr = &fbuf[strlen(fbuf)];
                        sprintf (tptr, "%s", tbuf);

                        snprintf (&vbuf[strlen(vbuf)], 1024, "%s", parser->RaPrintAlgorithm->field);
                        snprintf (tbuf, 1024, "%s=\"%s\"", parser->RaPrintAlgorithm->field, ptr);

                        if (keyField) {
                           tptr = &ubuf[strlen(ubuf)];
                           sprintf (tptr, "%s", tbuf);
                        } else {
                           tptr = &ibuf[strlen(ibuf)];
                           sprintf (tptr, "%s", tbuf);
                        }
                     }
                  }
               }
            }
         }
         ArgusParser->uflag = uflag;
         MUTEX_UNLOCK(&parser->lock);

         parser->nflag   = nflag;

         switch (state) {
            case ARGUS_SQL_SELECT: {
               ns->status &= ~(ARGUS_SQL_STATUS);
               ns->status |= ARGUS_SQL_SELECT;

               snprintf (sbuf, MAXBUFFERLEN, "SELECT record FROM %s WHERE %s", tbl, ubuf);
#ifdef ARGUSDEBUG
               snprintf (dbuf, MAXSTRLEN, "%s", sbuf);
               ArgusDebug (3, "ArgusGenerateSQLQuery (0x%x, 0x%x, 0x%x, %s, %s, %d) done\n", parser, agg, ns, tbl, dbuf, state);
#endif
               break;
            }

            case ARGUS_SQL_DELETE: {
               ns->status &= ~(ARGUS_SQL_STATUS);
               ns->status |= ARGUS_SQL_DELETE;
 
               snprintf (sbuf, MAXBUFFERLEN, "DELETE FROM %s WHERE %s", tbl, ubuf);
#ifdef ARGUSDEBUG
               snprintf (dbuf, MAXSTRLEN, "%s", sbuf);
               ArgusDebug (3, "ArgusGenerateSQLQuery (0x%x, 0x%x, 0x%x, %s, %s, %d) done\n", parser, agg, ns, tbl, dbuf, state);
#endif
               break;
            }

            default: {
               len = 0;
               if (ArgusSOptionRecord || RaSQLRewrite) {
                  int tlen;

                  if ((argus = ArgusGenerateRecord (ns, 0L, rbuf, argus_version)) == NULL)
                     ArgusLog(LOG_ERR, "ArgusGenerateSQLQuery: ArgusGenerateRecord error %s", strerror(errno));
#ifdef _LITTLE_ENDIAN
                  ArgusHtoN(argus);
#endif

                  if ((tlen = ntohs(argus->hdr.len) * 4) < ARGUS_MAXRECORDSIZE) {
                     if (MUTEX_LOCK(&RaMySQLlock) == 0) {
                        if ((len = mysql_real_escape_string(RaMySQL, mbuf, (char *)argus, tlen)) <= 0)
                           ArgusLog(LOG_ERR, "mysql_real_escape_string error %s", mysql_error(RaMySQL));
                        MUTEX_UNLOCK(&RaMySQLlock);
                     }
                  }
               }

               if (len < (MAXBUFFERLEN - (strlen(ibuf) + strlen(ubuf)))) {
                  if (!(ns->status & ARGUS_SQL_INSERT)) {
                     if (ArgusSOptionRecord || RaSQLRewrite) {
                        if (strlen(ibuf)) {
                           snprintf (sbuf, MAXBUFFERLEN, "UPDATE %s SET %s,record=\"%s\" WHERE %s", tbl, ibuf, mbuf, ubuf);
#ifdef ARGUSDEBUG
                           snprintf (dbuf, MAXSTRLEN, "UPDATE %s SET %s,record=\"...\" WHERE %s", tbl, ibuf, ubuf);
#endif
                        } else {
                           snprintf (sbuf, MAXBUFFERLEN, "UPDATE %s SET record=\"%s\" WHERE %s", tbl, mbuf, ubuf);
#ifdef ARGUSDEBUG
                           snprintf (dbuf, MAXSTRLEN, "UPDATE %s SET record=\"...\" WHERE %s", tbl, ubuf);
#endif
                        }
                     } else {
                        snprintf (sbuf, MAXBUFFERLEN, "UPDATE %s SET %s WHERE %s", tbl, ibuf, ubuf);
#ifdef ARGUSDEBUG
                        snprintf (dbuf, MAXSTRLEN, "%s", sbuf);
#endif
                     }
                     ns->status &= ~(ARGUS_SQL_STATUS);
                     ns->status |= ARGUS_SQL_UPDATE;

                  } else {
                     if (ArgusSOptionRecord) {
                        int slen, tlen;

                        snprintf (sbuf, MAXBUFFERLEN, "INSERT INTO %s (%s,record) VALUES (%s,\"", tbl, vbuf, fbuf);
#ifdef ARGUSDEBUG
                        snprintf (dbuf, MAXSTRLEN, "INSERT INTO %s (%s,record) VALUES (%s,...)", tbl, vbuf, fbuf);
#endif
                        slen = strlen(sbuf);

                        if ((tlen = (slen + len)) < (MAXBUFFERLEN - 3))  {
                           bcopy(mbuf, &sbuf[slen], len + 1);
                           snprintf (&sbuf[tlen], MAXBUFFERLEN - tlen, "\")");
                        } else {
                           snprintf (&sbuf[slen], MAXBUFFERLEN - slen, "\")");
                        }

                     } else {
                        snprintf (sbuf, MAXBUFFERLEN, "INSERT INTO %s (%s) VALUES (%s)", tbl, vbuf, fbuf);
#ifdef ARGUSDEBUG
                        snprintf (dbuf, MAXSTRLEN, "%s", sbuf);
#endif
                     }

                     ns->status &= ~(ARGUS_SQL_STATUS);
                     ns->status |= ARGUS_SQL_INSERT;
#ifdef ARGUSDEBUG
                     ArgusDebug (3, "ArgusGenerateSQLQuery (0x%x, 0x%x, 0x%x, %s, %s, %d) done\n", parser, agg, ns, tbl, dbuf, state);
#endif
                  }

               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (3, "ArgusGenerateSQLQuery: query too large for allocated buffer\n", len);
#endif
               }
               break;
            }
         }

         ns->qhdr.logtime = ArgusParser->ArgusRealTime;

         sqry->tbl  = strdup(tbl);
         sqry->sptr = strdup(sbuf);
#ifdef ARGUSDEBUG
         if (dbuf) {
            sqry->dptr = strdup(dbuf);
            ArgusFree(dbuf);
         }
#endif
         if (tmpbuf) ArgusFree(tmpbuf);
         if (  mbuf) ArgusFree(mbuf);
         if (  sbuf) ArgusFree(sbuf);
         if (  rbuf) ArgusFree(rbuf);

      } else
         ArgusLog(LOG_ERR, "ArgusGenerateSQLQuery: ArgusCalloc error %s", strerror(errno));
   }

   return (sqry);
}

void
ArgusDeleteSQLQuery (struct ArgusSQLQueryStruct *sqry)
{
   if (sqry != NULL) {
      if (sqry->tbl  != NULL) free(sqry->tbl);
      if (sqry->sptr != NULL) free(sqry->sptr);

#ifdef ARGUSDEBUG
      if (sqry->dptr != NULL) free(sqry->dptr);
#endif
      ArgusFree(sqry);
   }
#ifdef ARGUSDEBUG
   ArgusDebug (7, "ArgusDeleteSQLQuery(%p) complete\n", sqry);
#endif
}

int
ArgusScheduleSQLQuery (struct ArgusParserStruct *parser, struct ArgusAggregatorStruct *agg, struct ArgusRecordStruct *ns, char *tbl, int state)
{
   struct ArgusSQLQueryStruct *sqry = NULL;
   int retn = 0;

   if ((agg == NULL) || (agg->mask == 0))
      if (!(ns->status & (ARGUS_SQL_INSERT|ARGUS_SQL_REWRITE)))
         return retn;

   if ((sqry = ArgusGenerateSQLQuery(parser, agg, ns,tbl, state)) != NULL) {
      ns->qhdr.logtime = ArgusParser->ArgusRealTime;

      switch (ns->status & ARGUS_SQL_STATUS) {
         case ARGUS_SQL_INSERT:
            ArgusPushBackList (ArgusSQLInsertQueryList, (struct ArgusListRecord *)&sqry->nxt, ARGUS_LOCK);
            COND_SIGNAL(&ArgusSQLInsertQueryList->cond);
            break;
         case ARGUS_SQL_SELECT:
            ArgusPushBackList (ArgusSQLSelectQueryList, (struct ArgusListRecord *)&sqry->nxt, ARGUS_LOCK);
            COND_SIGNAL(&ArgusSQLSelectQueryList->cond);
            break;
         case ARGUS_SQL_REWRITE:
         case ARGUS_SQL_UPDATE:
            ArgusPushBackList (ArgusSQLUpdateQueryList, (struct ArgusListRecord *)&sqry->nxt, ARGUS_LOCK);
            COND_SIGNAL(&ArgusSQLUpdateQueryList->cond);
            break;
         case ARGUS_SQL_DELETE:
            ArgusPushBackList (ArgusSQLDeleteQueryList, (struct ArgusListRecord *)&sqry->nxt, ARGUS_LOCK);
            COND_SIGNAL(&ArgusSQLDeleteQueryList->cond);
            break;
      }
      ns->status &= ~(ARGUS_SQL_STATUS);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (7, "ArgusScheduleSQLQuery(%p, %p, %p, %s, %d) complete\n", parser, agg, ns, tbl, state);
#endif

   return (retn);
}



struct ArgusRecordStruct *
ArgusCheckSQLCache(struct ArgusParserStruct *parser, struct RaBinStruct *bin, struct ArgusRecordStruct *ns)
{
   struct ArgusRecordStruct *argus = NULL;
   struct ArgusSQLQueryStruct *sqry;

   if ((sqry = ArgusGenerateSQLQuery(parser, bin->agg, ns, bin->table, ARGUS_SQL_SELECT)) != NULL) {
      extern long long ArgusTotalSelectSQLStatements;
      int retn;

      MUTEX_LOCK(&RaMySQLlock);

      if ((retn = mysql_real_query(RaMySQL, sqry->sptr, strlen(sqry->sptr))) != 0) {
         ArgusLog(LOG_INFO, "ArgusProcessSQLQueryList(Update): %s mysql_real_query error %s", sqry->dptr, mysql_error(RaMySQL));
      } else {
         MYSQL_RES *mysqlRes;
         struct ArgusRecord *buf;

         buf = ArgusMalloc(MAXBUFFERLEN);

         if (buf && ((mysqlRes = mysql_store_result(RaMySQL)) != NULL)) {
            if ((retn = mysql_num_fields(mysqlRes)) > 0) {
               MYSQL_ROW row;
               while ((row = mysql_fetch_row(mysqlRes))) {
                  unsigned long *lengths;
                  int x;

                  lengths = mysql_fetch_lengths(mysqlRes);
                  bzero(buf, MAXBUFFERLEN);

                  for (x = 0; x < retn; x++) {
                     bcopy (row[x], buf, (int) lengths[x]);
#ifdef ARGUSDEBUG
                     ArgusDebug (2, "ArgusCheckSQLCache: sql query returned buffer[%d] length %d\n", x, lengths[x]);
#endif


                     if ((buf->hdr.type & ARGUS_FAR) || (buf->hdr.type & ARGUS_AFLOW) || (buf->hdr.type & ARGUS_NETFLOW)) {
#ifdef _LITTLE_ENDIAN
                        ArgusNtoH(buf);
#endif
                        if ((argus = ArgusGenerateRecordStruct (ArgusParser, ArgusInput, buf)) == NULL)
                           ArgusLog(LOG_INFO, "mysql_real_query recieved record could not parse");
                     }
                  }
               }
            }
            mysql_free_result(mysqlRes);
            ArgusFree(buf);
         }
      }
      MUTEX_UNLOCK(&RaMySQLlock);

      ArgusTotalSQLSearches++;
      ArgusTotalSelectSQLStatements++;
      ArgusDeleteSQLQuery(sqry);
   }

   return (argus);
}

#endif


int
RaParseDiskStatus(struct ArgusEventRecordStruct *evt, char *str)
{
   int retn = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaParseDiskStatus(%p, %s) return %d\n", evt, str, retn);
#endif
   return (retn);
}

void
ArgusInitEvents (struct ArgusEventsStruct *events)
{
   if (events == NULL)
      return;

#if defined(ARGUS_THREADS)
   if ((events->ArgusEventsList != NULL) && (!(ArgusListEmpty(events->ArgusEventsList)))) {
      if (!(ArgusListEmpty(events->ArgusEventsList))) {
         struct ArgusEventRecordStruct *evt;
         int i, cnt = ArgusGetListCount(events->ArgusEventsList);

         for (i = 0; i < cnt; i++) {
            if ((evt = (void *)ArgusPopFrontList(events->ArgusEventsList, ARGUS_LOCK)) != NULL) {
               if (evt->db != NULL) {
                  char *dbstr = strdup(evt->db), *dbptr = dbstr, *ptr;

                  if (!(strncmp("mysql:", dbptr, 6))) {
                     dbptr += 6;

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
                        if ((ptr = strchr (dbptr, '/')) != NULL) {
                           *ptr++ = '\0';
                           evt->table = strdup(ptr);
                        }
                        free(evt->db);
                        evt->db = strdup(dbptr);
                     }
                  }

                  free(dbstr);
               }

               ArgusPushBackList(events->ArgusEventsList, (struct ArgusListRecord *) evt, ARGUS_LOCK);
            }
         }

         if ((pthread_create(&events->thread, NULL, ArgusEventsProcess, (void *) events)) != 0)
            ArgusLog (LOG_ERR, "ArgusNewEventProcessor() pthread_create error %s\n", strerror(errno));
      }
   }
#endif /* ARGUS_THREADS */

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusInitEvents() done\n");
#endif
}

void
ArgusCloseEvents (struct ArgusEventsStruct *events)
{
   if (events != NULL) {
      events->status |= ARGUS_SHUTDOWN;

#if defined(ARGUS_THREADS)
      if (events->thread)
         pthread_cancel(events->thread);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCloseEvents() done\n");
#endif
}

#if defined(ARGUS_THREADS)

int
ArgusSortEventList (const void *item1, const void *item2)
{
   struct ArgusEventRecordStruct *event1 = *(struct ArgusEventRecordStruct **) item1;
   struct ArgusEventRecordStruct *event2 = *(struct ArgusEventRecordStruct **) item2;
   int retn = 0;

   if ((retn = (event1->poptime.tv_sec - event2->poptime.tv_sec)) == 0)
      retn = (event1->poptime.tv_nsec - event2->poptime.tv_nsec);

   return (retn);
}


#if !defined(TIMEVAL_TO_TIMESPEC)
void TIMEVAL_TO_TIMESPEC (struct timeval *, struct timespec *);
void
TIMEVAL_TO_TIMESPEC (struct timeval *tvp, struct timespec *ts)
{
   ts->tv_sec  = tvp->tv_sec;
   ts->tv_nsec = tvp->tv_usec * 1000;
}
#endif

void *
ArgusEventsProcess(void *arg)
{
   struct ArgusEventsStruct *events = (struct ArgusEventsStruct *) arg;
   struct ArgusEventRecordStruct *evtarray[1024];
   struct ArgusEventRecordStruct *evt;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   void *retn = NULL;
   int cnt, i;

   do {
      struct timespec tsbuf, *ts = &tsbuf;
      struct timespec rmtpb, *rmtp = &rmtpb;

      if (events->status & ARGUS_SHUTDOWN)
         break;

      if (!(ArgusListEmpty(events->ArgusEventsList))) {
         cnt = ArgusGetListCount(events->ArgusEventsList);
         memset(evtarray, 0, sizeof(evtarray));

         for (i = 0; i < cnt; i++) {
            if ((evt = (void *)ArgusPopFrontList(events->ArgusEventsList, ARGUS_LOCK)) != NULL) {
               evtarray[i] = evt;
               if (evt->poptime.tv_sec > 0) {
                  struct timeval tvpbuf, *tvp = &tvpbuf;
                  gettimeofday(tvp, 0L);
                  TIMEVAL_TO_TIMESPEC(tvp, ts);
                  evt->remaining.tv_sec  = evt->poptime.tv_sec - ts->tv_sec;
                  evt->remaining.tv_nsec = evt->poptime.tv_nsec - ts->tv_nsec;

                  while ((evt->remaining.tv_nsec < 0) && (evt->remaining.tv_sec > 0)) {
                     evt->remaining.tv_sec  -= 1;
                     evt->remaining.tv_nsec += 1000000000;
                  }
               }
               ArgusPushBackList(events->ArgusEventsList, (struct ArgusListRecord *) evt, ARGUS_LOCK);
            }
         }

         qsort (evtarray, cnt, sizeof(evt), ArgusSortEventList);

         evt = evtarray[0];
         *ts = evt->remaining;

         if (events->status & ARGUS_SHUTDOWN)
            break;

         if ((ts->tv_sec > 0) || ((ts->tv_sec == 0) && (ts->tv_nsec > 100))) {
            while (nanosleep (ts, rmtp)) {
               *ts = *rmtp;
               if ((rmtp->tv_sec == 0) && (rmtp->tv_nsec == 0))
                  break;
               if (events->status & ARGUS_SHUTDOWN)
                  break;
            }
         }

         if (events->status & ARGUS_SHUTDOWN)
            break;

#ifdef ARGUSDEBUG
         {
            char *str;
            if ((str = RaFetchStatusData(events, evt, ARGUS_STATUS)) != NULL) {
               switch (evt->status & (RA_STATUS_RETURN | RA_STATUS_DELTA)) {
                  case RA_STATUS_RETURN:
                  case RA_STATUS_DELTA:
                     break;
               }

               if (evt->db && evt->table)
                  RaStatusProcessSQLStatement(evt, str);
               else
                  ArgusDebug (3, "ArgusEventsProcess: %s\n", str);
               free(str);
            }
         }
#endif
            
         if (evt->interval > 0) {
            gettimeofday(tvp, 0L);
            TIMEVAL_TO_TIMESPEC(tvp, &evt->poptime);
            evt->poptime.tv_sec   += evt->interval;
            evt->remaining.tv_sec  = evt->interval;

         } else {
            evtarray[0] = NULL;
            if (evt->entry)
               free(evt->entry);
            if (evt->method)
               free(evt->method);
            if (evt->filename)
               free(evt->filename);
            ArgusFree(evt);
         }
      }
   } while (!(events->status & ARGUS_SHUTDOWN));

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusEventsProcess() exiting\n");
#endif

   pthread_exit(retn);
   return(retn);
}

char *
RaFetchStatusData (struct ArgusEventsStruct *events, struct ArgusEventRecordStruct *evt, unsigned char status)
{
   int tcnt = 0, len = ARGUS_MAX_OS_BUF;
   char *retn = NULL, *buf = NULL;
   struct timeval now, then;

   if ((buf = (char *) ArgusMalloc(ARGUS_MAX_OS_BUF)) == NULL)
      ArgusLog (LOG_ERR, "ArgusMalloc returned NULL\n");

   memset(buf, 0, ARGUS_MAX_OS_BUF);

   gettimeofday(&then, 0L);

   if (strncmp(evt->method, "file", 4) == 0)  {
      int fd = 0, cnt;
      if ((fd = open(evt->filename, O_RDONLY)) > 0) {
         snprintf(buf, ARGUS_MAX_OS_BUF - 1, "file=%s result='", evt->filename);
         tcnt = strlen(buf);
         if ((cnt = read(fd, &buf[tcnt], len - tcnt)) >= 0) {
            close(fd);
            tcnt = strlen(buf);
            if (isspace(buf[tcnt - 1]) || (buf[tcnt - 1] == '\n')) buf[tcnt-- - 1] = '\0';
            snprintf(&buf[tcnt], ARGUS_MAX_OS_BUF - (tcnt + 1), "'");
         }

      } else {
         snprintf(buf, ARGUS_MAX_OS_BUF - 1, "file=%s:result='not found'\n", evt->filename);
      }

   } else 
   if (strncmp(evt->method, "prog", 4) == 0)  {
      int terror = 0, len = ARGUS_MAX_OS_BUF;
      struct stat statbuf;
      FILE *fd = NULL;
      char *ptr = NULL;

      if (stat (evt->filename, &statbuf) == 0) {
         snprintf(buf, ARGUS_MAX_OS_BUF - 1, "prog=%s result='", evt->filename);
         tcnt = strlen(buf);

         if ((fd = popen(evt->filename, "r")) != NULL) {
            clearerr(fd);
            while ((!(feof(fd))) && (!(ferror(fd))) && (len > tcnt)) {
               if ((ptr = fgets(&buf[tcnt], len - tcnt, fd)) == NULL) {
                  if (ferror(fd)) {
                     terror++;
                     break;
                  }
               } else {
                  tcnt += strlen(ptr);
                  if (strlen(ptr) == 0)
                     break;
               }
            }
            tcnt = strlen(buf);
            if (isspace(buf[tcnt - 1]) || (buf[tcnt - 1] == '\n')) buf[tcnt-- - 1] = '\0';
            snprintf(&buf[tcnt], ARGUS_MAX_OS_BUF - (tcnt + 1), "'");
            if (terror == 0)
               ptr = buf;
            else
               ptr = NULL;
            pclose(fd);

         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (1, "RaFetchStatusData: System error: popen(%s) %s\n", evt->filename, strerror(errno));
#endif
         }
      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "RaFetchStatusData: prog %s stat error: %s\n", evt->filename, strerror(errno));
#endif
      }
   }

   gettimeofday(&now, 0L);

   if (strlen(buf) > 0)
      retn = strdup(buf);

   ArgusFree(buf);

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaFetchStatusData(0x%x, %d) returning 0x%x", events, status, retn);
#endif
   return (retn);
}

#endif
