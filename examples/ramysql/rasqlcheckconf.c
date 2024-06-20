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
 * rasqlcheckconf.c - compare argus.conf with database table values.
 *
 * Author: Carter Bullard carter@qosient.com
 */

/* 
 * $Id: //depot/gargoyle/clients/examples/ramysql/rasqlcheckconf.c#7 $
 * $DateTime: 2016/11/30 12:35:01 $
 * $Change: 3247 $
 */


#define ArgusModeler

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <argus_threads.h>
#include <time.h>

#define ARGUS_RECORD_MODIFIED   0x0100
#define ARGUS_RECORD_CLEARED    0x0200

#define ARGUS_SQL_INSERT        0x0100000
#define ARGUS_SQL_UPDATE        0x0200000
#define ARGUS_SQL_DELETE        0x0400000

#define ARGUS_SQL_STATUS        (ARGUS_SQL_INSERT | ARGUS_SQL_UPDATE | ARGUS_SQL_DELETE)

#define ARGUSTIMEOUTQS          65534


#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <argus_def.h>
#include <argus_util.h>
#include <rasqlcheckconf.h>

int ArgusParseErrors = 0;
int ArgusCloseDown = 0;
int RaSQLArgusConfTable = 0;

#if defined(ARGUS_THREADS)
pthread_attr_t RaTopAttr;
pthread_t RaMySQLThread = 0;
pthread_t RaMySQLSelectThread = 0;
pthread_t RaMySQLUpdateThread = 0;
pthread_t RaMySQLInsertThread = 0;
pthread_mutex_t RaMySQLlock;

void *ArgusMySQLInsertProcess (void *);
void *ArgusMySQLUpdateProcess (void *);
void *ArgusMySQLSelectProcess (void *);
#endif

void clearArgusConfiguration (struct ArgusModelerStruct *);
struct ArgusQueueStruct *ArgusTimeOutQueues;
struct ArgusQueueStruct *ArgusTimeOutQueue[ARGUSTIMEOUTQS];

#if defined(ARGUS_MYSQL)
int ArgusTotalInsertSQLStatements = 0;
int ArgusTotalUpdateSQLStatements = 0;
int ArgusTotalSelectSQLStatements = 0;


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
int MySQLVersionMajor = 0;
int MySQLVersionMinor = 0;
int MySQLVersionSub = 0;

extern int ArgusSOptionRecord;
int ArgusDeleteTable = 0;

int Argusdflag = 0;

int ArgusDropTable = 0;
int ArgusCreateTable = 0;
int ArgusAutoId = 0;

struct timeval ArgusLastRealTime     = {0, 0};
struct timeval ArgusLastTime         = {0, 0};
struct timeval ArgusThisTime         = {0, 0};
struct timeval ArgusCurrentTime      = {0, 0};

char ArgusSQLSaveTableNameBuf[1024];
struct tm ArgusSaveTableTmStruct;
time_t ArgusSaveTableSeconds = 0;

int ArgusCreateSQLSaveTable(char *, char *);
char *ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, char*, int, int);


void RaMySQLDeleteRecords(struct ArgusParserStruct *, struct ArgusRecordStruct *);

void RaSQLQueryNetworksTable (unsigned int, unsigned int, unsigned int);
void RaSQLQueryProbes (void);
void RaSQLQuerySecondsTable (unsigned int, unsigned int);

int RaInitialized = 0;
int RaSQLMcastMode = 0;

char *RaSQLCurrentTable = NULL;

char *RaSQLSaveTable = NULL;

unsigned int RaTableFlags = 0;

char *RaTableValues[256];
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

int   RaSQLMaxSecs   = 0;
int   RaSQLUpdateDB  = 1;
int   RaSQLCacheDB   = 0;
int   RaSQLDBInserts = 0;
int   RaSQLDBUpdates = 0;
int   RaSQLDBDeletes = 1;
int   RaFirstManRec  = 1;

char ArgusArchiveBuf[MAXPATHNAMELEN];
char RaLocalArchiveBuf[MAXSTRLEN];

extern char *RaRemoteFilter;
extern char *RaLocalFilter;

extern char RaFilterSQLStatement[];

char *RaHost = NULL, *RaUser = NULL, *RaPass = NULL;
int RaPort = 0;

struct ArgusInput *ArgusInput = NULL;
void RaMySQLInit (void);

MYSQL_ROW row;
MYSQL *RaMySQL = NULL;

struct ArgusSQLQueryStruct {
   struct ArgusListObjectStruct *nxt;
   char *tbl, *sptr, *dptr;
};


#define ARGUS_RCITEMS			53

struct ArgusResourceItemStruct {
   struct ArgusResourceItemStruct *nxt;
   int status;
   char *value;
};

struct ArgusResourceStruct {
   int status;
   char *label, *type;
   struct ArgusListStruct *values;
};

struct ArgusResourceStruct RaArgusResourceFileStr[ARGUS_RCITEMS];
int ArgusCopyResourceFileStruct (struct ArgusResourceStruct *, struct ArgusResourceStruct **, int);
void RaParseArgusResourceFile (struct ArgusResourceStruct *, char *);
int RaReadMySQLTable(MYSQL *, char *, struct ArgusResourceStruct *);
int RaCompareArgusConfiguration (struct ArgusResourceStruct *, struct ArgusResourceStruct *, int);
int RaMySQLWriteArgusConfiguration (MYSQL *, struct ArgusResourceStruct *);

void RaMySQLInit (void);

#endif

void ArgusClientTimeout (void) { };
void ArgusWindowClose(void) { };
void RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus) { };
int RaSendArgusRecord(struct ArgusRecordStruct *argus) { return 0; };

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      fflush(stdout);
      mysql_close(RaMySQL);
      exit(0);
   }
}

int
main(int argc, char **argv)
{
   struct ArgusModelerStruct *ArgusModel = NULL;
   struct ArgusParserStruct *parser = NULL;
   int ArgusExitStatus = 0;
   int i, cc, dodebug = 0;

   for (i = 0, cc = 0; i < argc; i++)
      cc += strlen(argv[i]);

   if (strchr (argv[0], '/'))
      argv[0] = strrchr(argv[0], '/') + 1;

   if ((ArgusModel = ArgusNewModeler()) == NULL)
      ArgusLog (LOG_ERR, "Error Creating Modeler: Exiting.\n");

   for (i = 1; (i < argc); i++) {
      char *ptr = argv[i]; 
      if (ptr != NULL) {
         if (*ptr == '-') {
            ptr++;
            if ((*ptr == 0) || (isspace((int)*ptr)))
               break;
            do {
               switch (*ptr) {
                  case 'D': 
                     if (isdigit((int)*++ptr)) {
                        setArgusdflag (ArgusModel, atoi (ptr));
                     } else {
                        if (isdigit((int)*argv[i + 1]))
                           setArgusdflag (ArgusModel, atoi (argv[++i]));
                        else
                           break;
                     }
                     break;

                  default: {
                     if (dodebug) {
                        if (isdigit((int)*ptr)) {
                           setArgusdflag (ArgusModel, atoi (ptr));
                           dodebug = 0;
                        }
                     }
                  }
               }

            } while (isalpha((int)*++ptr));
         }
      }
   }

   if ((parser = ArgusNewParser(argv[0])) != NULL) {
      struct ArgusResourceStruct *RaSQLResourceFileStr = NULL;
      struct ArgusModeStruct *mode;

      ArgusParser = parser;
      ArgusMainInit (parser, argc, argv);

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "replace", 7)))
               parser->ArgusReplaceMode++;
            mode = mode->nxt;
         }
      }

      ArgusCopyResourceFileStruct (&RaArgusResourceFileStr[0], &RaSQLResourceFileStr, ARGUS_RCITEMS);

#if defined(ARGUS_THREADS)
      sigset_t blocked_signals;

      sigfillset(&blocked_signals);
      sigdelset(&blocked_signals, SIGTERM);
      sigdelset(&blocked_signals, SIGINT);
      sigdelset(&blocked_signals, SIGWINCH);

      pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

      if (parser->ArgusFlowModelFile == NULL)
         parser->ArgusFlowModelFile = "/etc/argus.conf";

      RaParseArgusResourceFile (&RaArgusResourceFileStr[0], parser->ArgusFlowModelFile);

      if (parser->writeDbstr != NULL) {
         if (parser->readDbstr != NULL)
            free(parser->readDbstr);
         parser->readDbstr = NULL; //if writing we'll need to read the same db
      }

#if defined(ARGUS_MYSQL)
      RaMySQLInit();

      if (RaDatabase && RaSQLSaveTable) {
         parser->RaTasksToDo = 1;
         if (RaReadMySQLTable(RaMySQL, RaSQLSaveTable, RaSQLResourceFileStr)) {
            if (RaCompareArgusConfiguration (&RaArgusResourceFileStr[0], RaSQLResourceFileStr, ARGUS_RCITEMS)) {
#ifdef ARGUSDEBUG
               ArgusDebug (1, "Argus configurations differ");
#endif
               ArgusExitStatus = 1;

               if (parser->ArgusReplaceMode) {
                  char sbuf[2048];
#ifdef ARGUSDEBUG
                  ArgusDebug (1, "Replacing argus configuration");
#endif
                  sprintf (sbuf, "TRUNCATE TABLE %s", RaSQLSaveTable);
                  if (mysql_real_query(RaMySQL, sbuf, strlen(sbuf)) != 0)
                     ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

                  RaMySQLWriteArgusConfiguration (RaMySQL, &RaArgusResourceFileStr[0]);
               }
            } else {
#ifdef ARGUSDEBUG
               ArgusDebug (1, "Argus configurations are equal");
#endif
            }
               
         } else {
            ArgusExitStatus = 2;
            if (parser->ArgusReplaceMode)
               RaMySQLWriteArgusConfiguration (RaMySQL, &RaArgusResourceFileStr[0]);
         }
      }

      ArgusCloseDown = 1;
      mysql_close(RaMySQL);
#endif
#endif
   }

   exit (ArgusExitStatus);
}



#define ARGUS_DEFAULT_DATABASE		"argus"
#define ARGUS_DEFAULT_TABLE		"argusConf"

void
RaMySQLInit ()
{
   char userbuf[1024], sbuf[1024], db[1024], *dbptr = NULL;
   char *sptr = NULL, *ptr;
   MYSQL_RES *mysqlRes;
   int retn = 0, x;

   bzero((char *)RaTableExistsNames,  sizeof(RaTableExistsNames));
   bzero((char *)RaTableCreateNames,  sizeof(RaTableCreateNames));
   bzero((char *)RaTableCreateString, sizeof(RaTableCreateString));
   bzero((char *)RaTableDeleteString, sizeof(RaTableDeleteString));

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

      if (RaDatabase) {
         if (!(strncmp("mysql:", RaDatabase, 6))) {
            char *tmp = RaDatabase;
            RaDatabase = strdup(&RaDatabase[6]);
            free(tmp);
         }
      } else {
         RaDatabase = strdup(ARGUS_DEFAULT_DATABASE);
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
            } else
               dbptr = NULL;

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
         RaDatabase = NULL;

         if (dbptr != NULL)
            RaDatabase = strdup(dbptr);
         else
            RaDatabase = strdup(ARGUS_DEFAULT_DATABASE);
      }
   }

   if ((ptr = strchr (RaDatabase, '/')) != NULL) {
      *ptr++ = '\0';
      RaTable = ptr;

      if (ArgusParser->readDbstr != NULL)
         if (ArgusParser->writeDbstr == NULL)
            ArgusParser->writeDbstr = strdup(ArgusParser->readDbstr);

      if (ArgusParser->writeDbstr != NULL)
         RaSQLSaveTable = strdup(RaTable);
   }

   if (!(ArgusParser->status & ARGUS_REAL_TIME_PROCESS))
      ArgusLastTime = ArgusParser->ArgusRealTime;

   if (RaMySQL == NULL)
      if ((RaMySQL = (void *) ArgusCalloc(1, sizeof(*RaMySQL))) == NULL)
         ArgusLog(LOG_ERR, "RaMySQLInit: ArgusCalloc error %s", strerror(errno));

   if ((mysql_init(RaMySQL)) == NULL)
      ArgusLog(LOG_ERR, "mysql_init error %s");

   if (!mysql_thread_safe())
      ArgusLog(LOG_INFO, "mysql not thread-safe");

   mysql_options(RaMySQL, MYSQL_READ_DEFAULT_GROUP, ArgusParser->ArgusProgramName);

   if ((mysql_real_connect(RaMySQL, RaHost, RaUser, RaPass, NULL, RaPort, NULL, 0)) == NULL)
      ArgusLog(LOG_ERR, "mysql_connect error %s", mysql_error(RaMySQL));

   bzero(sbuf, sizeof(sbuf));
   sprintf (sbuf, "SHOW VARIABLES LIKE 'version'");

   if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

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
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

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
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

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
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   sprintf (sbuf, "USE %s", RaDatabase);

   if (RaSQLSaveTable == NULL)
      RaSQLSaveTable = strdup(ARGUS_DEFAULT_TABLE);

   if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   if ((mysqlRes = mysql_list_tables(RaMySQL, NULL)) != NULL) {
      char sbuf[MAXSTRLEN];

      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         int thisIndex = 0;

         while (!RaSQLArgusConfTable && (row = mysql_fetch_row(mysqlRes))) {
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            bzero(sbuf, sizeof(sbuf));
               for (x = 0; x < retn; x++)
               sprintf(&sbuf[strlen(sbuf)], "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

            RaTableExistsNames[thisIndex++] = strdup (sbuf);

            if (RaSQLSaveTable)
               if (!(strncmp(sbuf, RaSQLSaveTable, strlen(RaSQLSaveTable)))) {
                  RaSQLArgusConfTable = 1;
            }
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

   if ((RaSQLArgusConfTable == 0) && (RaSQLSaveTable != NULL)) {
      if (RaTableFlags != RA_NUMTABLES_MASK) {
         int i;
         for (i = 0; i < RA_NUMTABLES; i++) {
            if (RaTableCreationString[i] != NULL) {
               if (!(RaTableFlags & (0x01 << i))) {
                  char sbuf[1024];
                  bzero (sbuf, 1024);
                  sprintf (sbuf, RaTableCreationString[i], RaSQLSaveTable);
                  if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0) {
                     ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
                  }
               }
            }
         }
      }
   }

   if (ArgusParser->MySQLDBEngine == NULL)
      ArgusParser->MySQLDBEngine = strdup("InnoDB");

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaMySQLInit () RaSource %s RaArchive %s RaFormat %s", RaSource, RaArchive, RaFormat);
#endif
}

int
ArgusCopyResourceFileStruct (struct ArgusResourceStruct *src, struct ArgusResourceStruct **dst, int num)
{
   int retn = 0, i;
   struct ArgusResourceStruct *array = NULL;

   if ((array = (void *) ArgusCalloc(sizeof (struct ArgusResourceStruct), num)) != NULL) {
      retn = 1;
      for (i = 0; i < num; i++)
         bcopy(&src[i], &array[i], sizeof(struct ArgusResourceStruct));

      *dst = array;
   }
   return (retn);
}




int
RaReadMySQLTable(MYSQL *sql, char *table, struct ArgusResourceStruct *recs) 
{
   char *label = NULL, *value = NULL;
   int retn = 0, cnt = 0;
   MYSQL_RES *mysqlRes;
   char buf[2048];

   sprintf (buf, "SELECT * from %s", RaSQLSaveTable);

#ifdef ARGUSDEBUG
   ArgusDebug (4, "SQL Query %s\n", buf);
#endif

   if (mysql_real_query(sql, buf, strlen(buf)) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(sql));

   else {
      if ((mysqlRes = mysql_store_result(sql)) != NULL) {
         if (mysql_num_fields(mysqlRes) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               struct ArgusResourceItemStruct *res = NULL;
               int i, x, found = 0, quoted = 0;
               unsigned long *lengths;
               char *bptr = buf, *qptr;

               lengths = mysql_fetch_lengths(mysqlRes);
               bzero(buf, sizeof(buf));

               for (x = 0; x < 2; x++) {
                  snprintf(buf, 2048, "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

                  if (*bptr == '\"') {
                     bptr++;
                     if ((qptr = strchr(bptr, '"')) != NULL)
                        *qptr++ = '\0';
                     quoted = 1;
                  }

// deal with potential embedded comments
                  if (!quoted) {
                     if (((qptr = strstr(bptr, " //")) != NULL) ||
                         ((qptr = strstr(bptr, "\t//")) != NULL))
                        *qptr++ = '\0';
                  }

                  switch (x) {
                     case 0:
                       label = strdup(bptr);
                       break;
                     case 1: {
                       value = strdup(bptr);
                       break;
                     }
                  }
               }

               for (i = 0; i < ARGUS_RCITEMS; i++) {
                  if (!(strcmp(recs[i].label, label))) {
                     found = 1;
                     break;
                  }
               }
               if (found) {
                  struct ArgusListStruct *list;
                  if ((list = recs[i].values) == NULL)
                     list = recs[i].values = ArgusNewList();

                  if ((res = (struct ArgusResourceItemStruct *) ArgusCalloc(1, sizeof(*res))) != NULL) {
                     res->value = strdup(value);
                     if (quoted) res->status |= ARGUS_ITEM_QUOTED;
                     ArgusPushBackList(list, (struct ArgusListRecord *)res, ARGUS_LOCK);
                     cnt++;
                  }
               }
               free(label);
               free(value);
            }
         }
      }
   }

   if (cnt > 0)
      retn = 1;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaReadMySQLTable(%p, %p, %p) read %d items\n", sql, table, recs, cnt);
#endif

   return(retn);
}

int 
RaMySQLWriteArgusConfiguration (MYSQL *sql, struct ArgusResourceStruct *recs)
{
   struct ArgusListStruct *list;
   int retn = 0, i;

   for (i = 0; i < ARGUS_RCITEMS; i++) {
      if ((list = RaArgusResourceFileStr[i].values) != NULL) {
         struct ArgusListObjectStruct *obj = list->start;

         char *label = RaArgusResourceFileStr[i].label;
         int x, cnt = list->count, slen;
         
         for (x = 0; x < cnt; x++) {
            char *value = ((struct ArgusResourceItemStruct *)obj)->value;
            int status  = ((struct ArgusResourceItemStruct *)obj)->status;
            char sbuf[2048];

            if ( status & ARGUS_ITEM_QUOTED)
               sprintf (sbuf, "INSERT INTO %s (label, value) VALUES (\"%s\",\"\\\"%s\\\"\")", RaSQLSaveTable, label, value);
            else
               sprintf (sbuf, "INSERT INTO %s (label, value) VALUES (\"%s\",\"%s\")", RaSQLSaveTable, label, value);

#ifdef ARGUSDEBUG
            ArgusDebug (2, "RaMySQLWriteArgusConfiguration: SQL statement \"%s\"\n", sbuf);
#endif
            if ((slen = strlen(sbuf)) > 0) {
               if ((retn = mysql_real_query(sql, sbuf, slen)) != 0) {
                  ArgusLog(LOG_INFO, "RaMySQLWriteArgusConfiguration: mysql_real_query error %s", mysql_error(sql));
               }
            }

            obj = obj->nxt;
         }
      }
   }

   return (retn);
}

int
RaCompareArgusConfiguration (struct ArgusResourceStruct *src, struct ArgusResourceStruct *dst, int cnt)
{
   int retn = 0, i;

   for (i = 0; i < cnt; i++) {
      if (src[i].values && dst[i].values) {
         if (src[i].values->count == dst[i].values->count) {
            int x = src[i].values->count, z, y;
            struct ArgusListObjectStruct *sobj = src[i].values->start;
            struct ArgusListObjectStruct *dobj = dst[i].values->start;

            if (x == 1) {
               if (strcmp(((struct ArgusResourceItemStruct *)sobj)->value, ((struct ArgusResourceItemStruct *)dobj)->value)) {
                  retn = 1;
                  break;
               }
            } else {
               for (z = 0; z < src[i].values->count; z++) {
                  int found = 0;
                  for (y = 0; y < dst[i].values->count; y++) {
                     if (!(strcmp(((struct ArgusResourceItemStruct *)sobj)->value, ((struct ArgusResourceItemStruct *)dobj)->value))) {
                        found = 1;
                        break;
                     }
                     dobj = dobj->nxt;
                  }
                  if (!found) {
                     retn = 1;
                     break;
                  }
                  sobj = sobj->nxt;
               }
            }

         } else
            retn = 1;
      } else {
         if (src[i].values || dst[i].values) 
            retn = 1;
      }
   }
   
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
                  RaSQLCurrentTable = strdup(stable);
               }
            }
         }

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
   ArgusDebug (2, "ArgusCreateSQLSaveTable (%s, %s) returning", db, table, retn);
#endif
   return (retn);
}


struct ArgusModelerStruct *
ArgusNewModeler()
{
   struct ArgusModelerStruct *retn = NULL;

   if ((retn = (struct ArgusModelerStruct *) ArgusCalloc (1, sizeof (struct ArgusModelerStruct))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewModeler () ArgusCalloc error %s\n", strerror(errno));

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusNewModeler() returning %p\n", retn);
#endif 

   return (retn);
}



void *ArgusQueueManager(void *);

void
ArgusInitModeler(struct ArgusModelerStruct *model)
{
   struct timeval *tvp = NULL;

   bzero (model->ArgusTimeOutQueue, sizeof(model->ArgusTimeOutQueue));
   model->ArgusInProtocol = 1;
   model->ArgusMajorVersion = VERSION_MAJOR;
   model->ArgusMinorVersion = VERSION_MINOR;
   model->ArgusSnapLen = ARGUS_MINSNAPLEN;

   model->ArgusUpdateInterval.tv_usec = 200000;
   model->ival = ((model->ArgusUpdateInterval.tv_sec * 1000000LL) + model->ArgusUpdateInterval.tv_usec);

   if ((model->ArgusHashTable = ArgusNewHashTable(ARGUS_HASHTABLESIZE)) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewModeler () ArgusNewHashTable error %s\n", strerror(errno));

   if ((model->hstruct = (struct ArgusHashStruct *) ArgusCalloc (1, sizeof (struct ArgusHashStruct))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewModeler () ArgusCalloc error %s\n", strerror(errno));

   if ((model->ArgusStatusQueue = ArgusNewQueue()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewModeler () ArgusNewQueue error %s\n", strerror(errno));

   if ((model->ArgusTimeOutQueues = ArgusNewQueue()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewModeler () ArgusNewQueue error %s\n", strerror(errno));

/* align the ArgusThisFlow buffer */

   if ((model->ArgusThisFlow = (struct ArgusSystemFlow *) ArgusCalloc (1, sizeof (struct ArgusSystemFlow) + 32)) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewModeler () ArgusCalloc error %s\n", strerror(errno));

   gettimeofday (&model->ArgusGlobalTime, 0L);

   if ((model->ArgusThisLLC = (struct llc  *) ArgusCalloc (1, sizeof (struct llc ) + 32)) == NULL)
      ArgusLog (LOG_ERR, "ArgusInitModeler () ArgusCalloc error %s\n", strerror(errno));

   model->ArgusSeqNum = 1;
   model->ArgusReportAllTime = 1;

   if (!(model->ArgusFlowKey))
      model->ArgusFlowKey = ARGUS_FLOW_CLASSIC5TUPLE;

   if (!(model->ArgusFlowType)) {
      if (model->ArgusFlowKey == ARGUS_FLOW_CLASSIC5TUPLE)
         model->ArgusFlowType = ARGUS_BIDIRECTIONAL;
      else
         model->ArgusFlowType = ARGUS_UNIDIRECTIONAL;
   }

   model->ArgusQueueInterval.tv_usec  = 50000;
   model->ArgusListenInterval.tv_usec = 250000;

   model->ArgusIPTimeout    = (model->ArgusIPTimeout == 0) ? ARGUS_IPTIMEOUT : model->ArgusIPTimeout;
   model->ArgusTCPTimeout   = (model->ArgusTCPTimeout == 0) ? ARGUS_TCPTIMEOUT : model->ArgusTCPTimeout;
   model->ArgusICMPTimeout  = (model->ArgusICMPTimeout == 0) ? ARGUS_ICMPTIMEOUT : model->ArgusICMPTimeout;
   model->ArgusIGMPTimeout  = (model->ArgusIGMPTimeout == 0) ? ARGUS_IGMPTIMEOUT : model->ArgusIGMPTimeout;
   model->ArgusFRAGTimeout  = (model->ArgusFRAGTimeout == 0) ? ARGUS_FRAGTIMEOUT : model->ArgusFRAGTimeout;
   model->ArgusARPTimeout   = (model->ArgusARPTimeout == 0) ? ARGUS_ARPTIMEOUT : model->ArgusARPTimeout;
   model->ArgusOtherTimeout = (model->ArgusOtherTimeout == 0) ? ARGUS_OTHERTIMEOUT : model->ArgusOtherTimeout;

   if ((tvp = getArgusFarReportInterval(model)) != NULL)
      model->ArgusStatusQueueTimeout = tvp->tv_sec;

   model->ArgusTCPflag = 1;

   model->ArgusThisDir = 0;

/*
   if (getArgusTunnelDiscovery(model))
      ArgusInitTunnelPortNumbers ();
*/

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusInitModeler(%p) done\n", model);
#endif 
}

struct timeval *
getArgusFarReportInterval(struct ArgusModelerStruct *model) {
   return (&model->ArgusFarReportInterval);
}

int
getArgusdflag(struct ArgusModelerStruct *model) {
   return (Argusdflag);
}

void
setArgusdflag(struct ArgusModelerStruct *model, int value)
{
   if (Argusdflag && !(value)) {
   }

   if (value) {
   }

   Argusdflag = value;
}


#define ARGUS_DAEMON				0
#define ARGUS_MONITOR_ID			1
#define ARGUS_ACCESS_PORT			2
#define ARGUS_INTERFACE				3
#define ARGUS_OUTPUT_FILE			4
#define ARGUS_SET_PID 				5
#define ARGUS_PID_PATH				6
#define ARGUS_GO_PROMISCUOUS			7
#define ARGUS_FLOW_STATUS_INTERVAL		8
#define ARGUS_MAR_STATUS_INTERVAL		9
#define ARGUS_CAPTURE_DATA_LEN			10
#define ARGUS_GENERATE_START_RECORDS		11
#define ARGUS_GENERATE_RESPONSE_TIME_DATA	12
#define ARGUS_GENERATE_JITTER_DATA		13
#define ARGUS_GENERATE_MAC_DATA			14
#define ARGUS_DEBUG_LEVEL			15
#define ARGUS_FILTER_OPTIMIZER			16
#define ARGUS_FILTER				17
#define ARGUS_PACKET_CAPTURE_FILE		18
#define ARGUS_PACKET_CAPTURE_ON_ERROR		19
#define ARGUS_BIND_IP				20
#define ARGUS_MIN_SSF				21
#define ARGUS_MAX_SSF				22
#define ARGUS_COLLECTOR				23
#define ARGUS_FLOW_TYPE				24
#define ARGUS_FLOW_KEY				25
#define ARGUS_GENERATE_APPBYTE_METRIC		26
#define ARGUS_CHROOT_DIR			27
#define ARGUS_SETUSER_ID			28
#define ARGUS_SETGROUP_ID			29
#define ARGUS_GENERATE_TCP_PERF_METRIC		30
#define ARGUS_GENERATE_BIDIRECTIONAL_TIMESTAMPS 31
#define ARGUS_GENERATE_PACKET_SIZE		32
#define ARGUS_ENV				33
#define ARGUS_CAPTURE_FULL_CONTROL_DATA         34
#define ARGUS_SELF_SYNCHRONIZE                  35
#define ARGUS_EVENT_DATA                        36
#define ARGUS_JITTER_HISTOGRAM                  37
#define ARGUS_OUTPUT_STREAM                     38
#define ARGUS_KEYSTROKE				39
#define ARGUS_KEYSTROKE_CONF			40
#define ARGUS_TUNNEL_DISCOVERY			41
#define ARGUS_IP_TIMEOUT			42
#define ARGUS_TCP_TIMEOUT			43
#define ARGUS_ICMP_TIMEOUT			44
#define ARGUS_IGMP_TIMEOUT			45
#define ARGUS_FRAG_TIMEOUT			46
#define ARGUS_ARP_TIMEOUT			47
#define ARGUS_OTHER_TIMEOUT			48
#define ARGUS_TRACK_DUPLICATES			49
#define ARGUS_PCAP_BUF_SIZE			50
#define ARGUS_OS_FINGERPRINTING			51
#define ARGUS_CONTROLPLANE_PROTO		52



struct ArgusResourceStruct RaArgusResourceFileStr [ARGUS_RCITEMS] = {
   {0, "ARGUS_DAEMON=", NULL,},
   {0, "ARGUS_MONITOR_ID=", NULL,},
   {0, "ARGUS_ACCESS_PORT=", NULL,},
   {0, "ARGUS_INTERFACE=", NULL,},
   {0, "ARGUS_OUTPUT_FILE=", NULL,},
   {0, "ARGUS_SET_PID=", NULL,},
   {0, "ARGUS_PID_PATH=", NULL,},
   {0, "ARGUS_GO_PROMISCUOUS=", NULL,},
   {0, "ARGUS_FLOW_STATUS_INTERVAL=", NULL,},
   {0, "ARGUS_MAR_STATUS_INTERVAL=", NULL,},
   {0, "ARGUS_CAPTURE_DATA_LEN=", NULL,},
   {0, "ARGUS_GENERATE_START_RECORDS=", NULL,},
   {0, "ARGUS_GENERATE_RESPONSE_TIME_DATA=", NULL,},
   {0, "ARGUS_GENERATE_JITTER_DATA=", NULL,},
   {0, "ARGUS_GENERATE_MAC_DATA=", NULL,},
   {0, "ARGUS_DEBUG_LEVEL=", NULL,},
   {0, "ARGUS_FILTER_OPTIMIZER=", NULL,},
   {0, "ARGUS_FILTER=", NULL,},
   {0, "ARGUS_PACKET_CAPTURE_FILE=", NULL,},
   {0, "ARGUS_PACKET_CAPTURE_ON_ERROR=", NULL,},
   {0, "ARGUS_BIND_IP=", NULL,},
   {0, "ARGUS_MIN_SSF=", NULL,},
   {0, "ARGUS_MAX_SSF=", NULL,},
   {0, "ARGUS_COLLECTOR=", NULL,},
   {0, "ARGUS_FLOW_TYPE=", NULL,},
   {0, "ARGUS_FLOW_KEY=", NULL,},
   {0, "ARGUS_GENERATE_APPBYTE_METRIC=", NULL,},
   {0, "ARGUS_CHROOT_DIR=", NULL,},
   {0, "ARGUS_SETUSER_ID=", NULL,},
   {0, "ARGUS_SETGROUP_ID=", NULL,},
   {0, "ARGUS_GENERATE_TCP_PERF_METRIC=", NULL,},
   {0, "ARGUS_GENERATE_BIDIRECTIONAL_TIMESTAMPS=", NULL,},
   {0, "ARGUS_GENERATE_PACKET_SIZE=", NULL,},
   {0, "ARGUS_ENV=", NULL,},
   {0, "ARGUS_CAPTURE_FULL_CONTROL_DATA=", NULL,},
   {0, "ARGUS_SELF_SYNCHRONIZE=", NULL,},
   {0, "ARGUS_EVENT_DATA=", NULL,},
   {0, "ARGUS_JITTER_HISTOGRAM=", NULL,},
   {0, "ARGUS_OUTPUT_STREAM=", NULL,},
   {0, "ARGUS_KEYSTROKE=", NULL,},
   {0, "ARGUS_KEYSTROKE_CONF=", NULL,},
   {0, "ARGUS_TUNNEL_DISCOVERY=", NULL,},
   {0, "ARGUS_IP_TIMEOUT=", NULL,},
   {0, "ARGUS_TCP_TIMEOUT=", NULL,},
   {0, "ARGUS_ICMP_TIMEOUT=", NULL,},
   {0, "ARGUS_IGMP_TIMEOUT=", NULL,},
   {0, "ARGUS_FRAG_TIMEOUT=", NULL,},
   {0, "ARGUS_ARP_TIMEOUT=", NULL,},
   {0, "ARGUS_OTHER_TIMEOUT=", NULL,},
   {0, "ARGUS_TRACK_DUPLICATES=", NULL,},
   {0, "ARGUS_PCAP_BUF_SIZE=", NULL,},
   {0, "ARGUS_OS_FINGERPRINTING=", NULL,},
   {0, "ARGUS_CONTROLPLANE_PROTO=", NULL,},
};



extern char *ArgusPcapOutFile;
extern char *ArgusWriteOutPacketFile;

void
RaParseArgusResourceFile (struct ArgusResourceStruct *recs , char *file)
{
   FILE *fd;
   char strbuf[MAXSTRLEN], *str = strbuf, *optarg;
   char *qptr = NULL;
   int i, len, done = 0, linenum = 0, cnt = 0;

   if (file) {
      if ((fd = fopen (file, "r")) != NULL) {
         while ((fgets(str, MAXSTRLEN, fd)) != NULL)  {
            done = 0;
            linenum++;
            while (*str && isspace((int)*str))
                str++;
 
            if (*str && (*str != '#') && (*str != '\n') && (*str != '!')) {
               for (i = 0; i < ARGUS_RCITEMS && !done; i++) {
                  len = strlen(RaArgusResourceFileStr[i].label);
                  if (!(strncmp (str, RaArgusResourceFileStr[i].label, len))) {
                     struct ArgusResourceItemStruct *res = NULL;
                     int quoted = 0, parseOk = 0;

                     optarg = &str[len];
                     if (*optarg == '\"') {
                        optarg++; 
                        if ((qptr = strchr(optarg, '"')) != NULL)
                           *qptr++ = '\0';
                        else
                           ArgusLog (LOG_ERR, "RaParseArgusResourceFile(%s) string unterminated at line %d\n", file, linenum);
                        quoted = 1; 
                     }
// deal with potential embedded comments
                     if (!quoted) {
                        if (((qptr = strstr(optarg, " //")) != NULL) ||
                            ((qptr = strstr(optarg, "\t//")) != NULL))
                           *qptr++ = '\0';
                     }

                     while (optarg[strlen(optarg) - 1] == '\n')
                        optarg[strlen(optarg) - 1] = '\0';

                     optarg = ArgusTrimString(optarg);
                     cnt++;

// Perform range and type checking for configuration values.

                     parseOk = 1;
                     switch (i) {
                        case ARGUS_DAEMON:
                        case ARGUS_SET_PID:
                        case ARGUS_GO_PROMISCUOUS:
                        case ARGUS_GENERATE_START_RECORDS:
                        case ARGUS_GENERATE_RESPONSE_TIME_DATA:
                        case ARGUS_GENERATE_JITTER_DATA:
                        case ARGUS_GENERATE_MAC_DATA:
                        case ARGUS_FILTER_OPTIMIZER:
                        case ARGUS_PACKET_CAPTURE_ON_ERROR:
                        case ARGUS_GENERATE_APPBYTE_METRIC:
                        case ARGUS_GENERATE_TCP_PERF_METRIC:
                        case ARGUS_GENERATE_BIDIRECTIONAL_TIMESTAMPS:
                        case ARGUS_GENERATE_PACKET_SIZE:
                        case ARGUS_CAPTURE_FULL_CONTROL_DATA:
                        case ARGUS_SELF_SYNCHRONIZE:
                        case ARGUS_TUNNEL_DISCOVERY:
                        case ARGUS_TRACK_DUPLICATES:
                        case ARGUS_OS_FINGERPRINTING:
                           if (!((strcmp("yes", optarg) == 0) || (strcmp("no", optarg) == 0))) {
                              parseOk = 0;
                           }
                           break;

                        case ARGUS_MONITOR_ID:
                           break;

                        case ARGUS_ACCESS_PORT: 
                        case ARGUS_CAPTURE_DATA_LEN: 
                        case ARGUS_DEBUG_LEVEL:
                        case ARGUS_MIN_SSF:
                        case ARGUS_MAX_SSF:
                        case ARGUS_IP_TIMEOUT:
                        case ARGUS_TCP_TIMEOUT:
                        case ARGUS_ICMP_TIMEOUT:
                        case ARGUS_IGMP_TIMEOUT:
                        case ARGUS_FRAG_TIMEOUT:
                        case ARGUS_ARP_TIMEOUT:
                        case ARGUS_OTHER_TIMEOUT: {
                           int value, matches;
                           if ((matches = sscanf(optarg,"%d", &value)) == 0) {
                              parseOk = 0;
                           }
                           break;
                        }

                        case ARGUS_INTERFACE:
                        case ARGUS_OUTPUT_FILE:
                        case ARGUS_PID_PATH:
                           break;

                        case ARGUS_FLOW_STATUS_INTERVAL: 
                        case ARGUS_MAR_STATUS_INTERVAL: {
                           int matches;
                           float value;
                           if ((matches = sscanf(optarg,"%f", &value)) == 0) {
                              parseOk = 0;
                           }
                           break;
                        }

                        case ARGUS_FILTER:
                        case ARGUS_PACKET_CAPTURE_FILE:
                        case ARGUS_BIND_IP:
                        case ARGUS_COLLECTOR:
                        case ARGUS_FLOW_TYPE:
                        case ARGUS_FLOW_KEY:
                        case ARGUS_CHROOT_DIR:
                           break;

                        case ARGUS_SETUSER_ID: {
#ifdef ARGUSDEBUG
                           struct passwd *pw;
                           if ((pw = getpwnam(optarg)) == NULL) {
                              ArgusDebug (1, "RaParseArgusResourceFile: ARGUS_SETUSER_ID user %s unknown\n", optarg);
                           }
                           endpwent();
#endif 
                           break;
                        }

                        case ARGUS_SETGROUP_ID: {
#ifdef ARGUSDEBUG
                           struct group *gr;
                           if ((gr = getgrnam(optarg)) == NULL)
                              ArgusDebug (1, "RaParseArgusResourceFile: ARGUS_SETGROUP_ID group %s unknown\n", optarg);
                           endgrent();
#endif 
                           break;
                        }

                        case ARGUS_ENV:
                        case ARGUS_EVENT_DATA:
                        case ARGUS_JITTER_HISTOGRAM:
                        case ARGUS_OUTPUT_STREAM:
                           break;

                        case ARGUS_KEYSTROKE:
                           if (!((strcmp("yes", optarg) == 0) || (strcmp("no", optarg) == 0) ||
                                 (strcmp("ssh", optarg) == 0) || (strcmp("tcp", optarg) == 0))) {
                              parseOk = 0;
                           }
                           break;

                        case ARGUS_KEYSTROKE_CONF:
                        case ARGUS_PCAP_BUF_SIZE:
                        case ARGUS_CONTROLPLANE_PROTO:
                           break;
                     }

                     if (recs[i].values == NULL)
                        recs[i].values = ArgusNewList();
 
                     if ((res = (struct ArgusResourceItemStruct *) ArgusCalloc(1, sizeof(*res))) != NULL) {
                        if (quoted) res->status |=  ARGUS_ITEM_QUOTED;
                        res->value = strdup(optarg);
                        ArgusPushBackList(recs[i].values, (struct ArgusListRecord *)res, ARGUS_LOCK);
                     }

                     if (parseOk == 0) {
                        ArgusParseErrors++;
#ifdef ARGUSDEBUG
                        if (quoted)
                           ArgusDebug (1, "RaParseArgusResourceFile: format error: entry %s\"%s\"", RaArgusResourceFileStr[i].label, optarg);
                        else
                           ArgusDebug (1, "RaParseArgusResourceFile: format error: entry %s%s", RaArgusResourceFileStr[i].label, optarg);
#endif
                     }
                     done = 1;
                     break;
                  }
               }
            }
         }

         fclose (fd);

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "RaParseArgusResourceFile: open %s %s\n", file, strerror(errno));
#endif 
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaParseArgusResourceFile (%s) parsed %d items\n", file, cnt);
#endif 
}

void
clearArgusConfiguration (struct ArgusModelerStruct *model)
{
   int i;
   for (i = 0; i < ARGUS_RCITEMS; i++) {
   }

   bzero (model, sizeof(*model));
   
   model->ArgusOflag = 1;

/*
   setArgusFarReportInterval (model, ARGUS_FARSTATUSTIMER);

   daemonflag = 0;
   setArgusID (ArgusSourceTask, 0, 0, 0);
   clearArgusWfile ();
   clearArgusDevice (ArgusSourceTask);
   setArgusPortNum(ArgusOutputTask, 0);
   setArgusBindAddr (ArgusOutputTask, NULL);
   setArguspidflag  (0);
   setArguspflag  (ArgusSourceTask, 0);
   setArgusFarReportInterval (model, ARGUS_FARSTATUSTIMER);
   setArgusMarReportInterval (ArgusOutputTask, ARGUS_MARSTATUSTIMER);
   setArgusUserDataLen (model, 0);
   setArgusSnapLen (ArgusSourceTask, ARGUS_MINSNAPLEN);
   setArgusResponseStatus (model, 0);
   setArgusGenerateTime (model, 0);
   setArgusmflag (model, 0);
   setArgusOflag (ArgusSourceTask, 1);
   setArgusCaptureFlag (ArgusSourceTask, 0);
   setArgusAflag(model, 0);
   setArgusTimeReport(model, 0);

   if (ArgusSourceTask->ArgusWriteOutPacketFile) {
      if (ArgusSourceTask->ArgusPcapOutFile != NULL) {
         pcap_dump_close(ArgusSourceTask->ArgusPcapOutFile);
         ArgusSourceTask->ArgusPcapOutFile = NULL;
      }
      ArgusSourceTask->ArgusWriteOutPacketFile = NULL;
   }

   if (ArgusSourceTask->ArgusInputFilter) {
      ArgusFree(ArgusSourceTask->ArgusInputFilter);
      ArgusSourceTask->ArgusInputFilter = NULL;
   }
*/

#ifdef ARGUSDEBUG
   ArgusDebug (2, "clearArgusConfiguration () returning\n");
#endif 
}

/* 
   Syntax is: "method:pathname:interval:postprocessor"
       Where:  method = [ "file" | "prog" ]
             pathname = %s
             interval = %d
             postproc = [ "compress" | "encrypt" | "none" ]
*/


void
usage ()
{
   extern char version[];

   fprintf (stdout, "RaSqlCheckConf Version %s\n", version);
   fprintf (stdout, "usage: %s -r mysql://[user[:pass]@]host[:port]/db/table\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s -t timerange -r mysql://[user[:pass]@]host[:port]/db\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [ra-options] [rasql-options] [- filter-expression]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -M sql='where clause'  pass where clause to database engine.\n");
   fprintf (stdout, "         -r <dbUrl>             read argus data from mysql database.\n");
   fprintf (stdout, "             Format:            mysql://[user[:pass]@]host[:port]/db/table\n");
   fflush (stdout);

   exit(1);
}
