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
 *
 * rasql  - Read Argus data using time offset indexs from mysql database.
 *          This program reads argus output streams from a database query,
 *          filters and optionally writes the output to a file, its
 *          stdout or prints the binary records to stdout in ASCII.
 */

/* 
 * $Id: //depot/gargoyle/clients/examples/ramysql/rasql.c#17 $
 * $DateTime: 2016/12/05 11:55:57 $
 * $Change: 3256 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
  
#include <netdb.h>
#include <sys/socket.h>

#include <rabins.h>
#include <rasplit.h>
#include "rasql_common.h"
 
#include "argus_mysql.h"
#include <mysqld_error.h>

char *RaDatabase = NULL;
char **RaTables = NULL;

int ArgusCreateSQLSaveTable(char *);
char *ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, int);
void RaMySQLDeleteRecords(struct ArgusParserStruct *, struct ArgusRecordStruct *);

void RaSQLQueryNetworksTable (unsigned int, unsigned int, unsigned int);
void RaSQLQueryProbes (void);
void RaSQLQuerySecondsTable (unsigned int, unsigned int);
void RaSQLQueryDatabaseTable (char *, unsigned int, unsigned int);

char *ArgusCreateSQLSaveTableName (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);

int RaInitialized = 0;
int ArgusAutoId = 0;
int ArgusDropTable = 0;
int ArgusCreateTable = 0;

char *RaProgramPath = RABINPATH;
char *RaRoleString = NULL;
char *RaProbeString = NULL;
char *RaSQLSaveTable = NULL;
char *RaSQLCurrentTable = NULL;

struct timeval RaStartTime = {0x7FFFFFFF, 0x7FFFFFFF};
struct timeval RaEndTime = {0, 0};
 
struct timeval ArgusLastRealTime     = {0, 0};
struct timeval ArgusLastTime         = {0, 0};
struct timeval ArgusThisTime         = {0, 0};
struct timeval ArgusCurrentTime      = {0, 0};
 
char ArgusSQLSaveTableNameBuf[MAXSTRLEN];
struct tm ArgusSaveTableTmStruct;
time_t ArgusSaveTableSeconds = 0;
 
struct timeval dLastTime = {0, 0};
struct timeval dRealTime = {0, 0};
struct timeval dThisTime = {0, 0};
struct timeval dTime     = {0, 0};
 
long long thisUsec = 0;
long long lastUsec = 0;
 
struct ArgusQueueStruct *ArgusModelerQueue;
struct ArgusQueueStruct *ArgusFileQueue;
struct ArgusQueueStruct *ArgusProbeQueue;
 
char ArgusArchiveBuf[4098];
 
#define RAMON_NETS_CLASSA	0
#define RAMON_NETS_CLASSB	1
#define RAMON_NETS_CLASSC	2
#define RAMON_NETS_CLASS	3

#define RA_MINTABLES            128
#define RA_MAXTABLES            0x10000
unsigned int RaTableFlags = 0;
 
char       *RaTableValues[256];
char  *RaTableExistsNames[RA_MAXTABLES];
char  *RaTableCreateNames[RA_MINTABLES];
char *RaTableCreateString[RA_MINTABLES];
char *RaTableDeleteString[RA_MINTABLES];

#define ARGUSSQLMAXQUERYTIMESPAN	300
#define ARGUSSQLMAXCOLUMNS		256
#define ARGUSSQLMAXROWNUMBER		0x80000

char *ArgusTableColumnName[ARGUSSQLMAXCOLUMNS];

char ArgusSQLTableNameBuf[MAXSTRLEN];

char *RaSource         = NULL;
char *RaArchive        = NULL;
char *RaLocalArchive   = NULL;
char *RaFormat         = NULL;
char *RaTable          = NULL;

int   RaStatus         = 1;
int   RaPeriod         = 1;
int   RaSQLMaxSeconds  = 0;

int ArgusSQLSecondsTable = 0;
int ArgusSQLBulkInsertSize = 0;
int ArgusSQLMaxPacketSize = 0;
int ArgusSQLBulkBufferSize = 0;
int ArgusSQLBulkBufferIndex = 0;
char *ArgusSQLBulkLastTable = NULL;
char *ArgusSQLBulkBuffer = NULL;
char *ArgusSQLVersion = NULL;
int MySQLVersionMajor = 0;
int MySQLVersionMinor = 0;
int MySQLVersionSub = 0;

time_t ArgusTableStartSecs = 0;
time_t ArgusTableEndSecs = 0;

extern int ArgusSOptionRecord;
int ArgusDeleteTable = 0;

char RaLocalArchBuf[MAXSTRLEN];

extern char *RaRemoteFilter;
extern char RaFilterSQLStatement[];
  
char *RaHost = NULL, *RaUser = NULL, *RaPass = NULL;
int RaPort = 0;
struct ArgusInput *ArgusInput = NULL;
void RaMySQLInit (void);

/* Do not try to create a database.  Allows read-only operations
 * with fewer database permissions.
 */
static int RaSQLNoCreate = 0;

MYSQL_ROW row;
MYSQL mysql, *RaMySQL = NULL;

struct RaMySQLFileStruct {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   unsigned int fileindex;
   unsigned int second;
   char *filename;
   int ostart, ostop;
};

#define RAMYSQL_SECONDTABLE_PROBE       0
#define RAMYSQL_SECONDTABLE_SECOND      1
#define RAMYSQL_SECONDTABLE_FILEINDEX   2
#define RAMYSQL_SECONDTABLE_OSTART      3
#define RAMYSQL_SECONDTABLE_OSTOP       4

struct RaMySQLSecondsTable {
   struct ArgusQueueHeader qhdr;
   unsigned int fileindex;
   char *filename;
   unsigned int probe;
   unsigned int second;
   int ostart, ostop;
};

#define RAMYSQL_PROBETABLE_PROBE        0
#define RAMYSQL_PROBETABLE_NAME         1

struct RaMySQLProbeTable {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   char *name;
};

static int argus_version = ARGUS_VERSION;

extern int ArgusTotalMarRecords;
extern int ArgusTotalFarRecords;

extern struct ArgusParserStruct *ArgusParser;
struct RaBinProcessStruct *RaBinProcess = NULL;

void RaArgusInputComplete (struct ArgusInput *input) {};

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
         mysql_close(RaMySQL);
         ArgusShutDown(sig);
         if ((sig >= 0) && ArgusParser->aflag) {
            printf (" Totalrecords %-8lld  TotalManRecords %-8lld  TotalFarRecords %-8lld TotalPkts %-8lld TotalBytes %-8lld\n",
                          ArgusParser->ArgusTotalRecords,
                          ArgusParser->ArgusTotalMarRecords, ArgusParser->ArgusTotalFarRecords,
                          ArgusParser->ArgusTotalPkts, ArgusParser->ArgusTotalBytes);
         }
      }
      fflush(stdout);
      exit(0);
   }
}


void
ArgusClientTimeout ()
{
#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusClientTimeout()\n");
#endif
}

void
parse_arg (int argc, char**argv)
{}

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
         RaProcessThisRecord (parser, argus);
         break;

      case ARGUS_EVENT:
         RaProcessThisRecord (parser, argus);
         break;

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusMetricStruct *metric = (void *)argus->dsrs[ARGUS_METRIC_INDEX];
         if (metric != NULL) {
            parser->ArgusTotalPkts  += metric->src.pkts;
            parser->ArgusTotalPkts  += metric->dst.pkts;
            parser->ArgusTotalBytes += metric->src.bytes;
            parser->ArgusTotalBytes += metric->dst.bytes;
         }

         if (parser->RaMonMode) {
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(argus);
            struct ArgusFlow *flow;

            if ((flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, argus);
            ArgusReverseRecord(tns);

            if ((flow = (void *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);

         } else {
            RaProcessThisRecord(parser, argus);
         }
      }
   }
}

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   char *buf;

   if ((buf = (void *) ArgusCalloc(1, MAXARGUSRECORD)) == NULL)
      ArgusLog(LOG_ERR, "RaProcessThisRecord: ArgusCalloc error %s", strerror(errno));

   if (parser->ArgusWfileList != NULL) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = parser->ArgusWfileList->count;

      if ((lobj = parser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               int retn = 1;
               if (wfile->filterstr) {
                  struct nff_insn *wfcode = wfile->filter.bf_insns;
                  retn = ArgusFilterRecord (wfcode, argus);
               }

               if (retn != 0) {
                  if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                     struct ArgusRecord *argusrec = NULL;
                     char *sbuf;
                     int rv;

                     if ((sbuf = (void *) ArgusCalloc(1, MAXARGUSRECORD)) == NULL)
                        ArgusLog(LOG_ERR, "RaProcessThisRecord: ArgusCalloc error %s", strerror(errno));

                     if ((argusrec = ArgusGenerateRecord (argus, 0L, sbuf, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        rv = ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                        if (rv < 0) {
                           ArgusLog(LOG_ERR, "%s unable to open file\n", __func__);
                        }
                     }
                     ArgusFree(sbuf);
                  }
               }
            }

            lobj = lobj->nxt;
         }
      }

   } else {
      if (!parser->qflag) {
         if (parser->Lflag && (!(parser->ArgusPrintXml) && !(ArgusParser->ArgusPrintJson))) {
            if (parser->RaLabel == NULL)
               parser->RaLabel = ArgusGenerateLabel(parser, argus);

            if (!(parser->RaLabelCounter++ % parser->Lflag))
               printf ("%s\n", parser->RaLabel);

            if (parser->Lflag < 0)
               parser->Lflag = 0;
         }

         ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);

         fprintf (stdout, "%s", buf);

         if (parser->eflag == ARGUS_HEXDUMP) {
            char *sbuf;
            int i;

            if ((sbuf = ArgusCalloc(1, 65536)) == NULL)
               ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusCalloc error");

            for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
               if (ArgusParser->RaPrintAlgorithmList[i] != NULL) {
                  struct ArgusDataStruct *user = NULL;
                  if (ArgusParser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcUserData) {
                     int slen = 0, len = ArgusParser->RaPrintAlgorithmList[i]->length;
                     if (len > 0) {
                        if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) != NULL) {
                           if (user->hdr.type == ARGUS_DATA_DSR) {
                              slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                           } else
                              slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

                           slen = (user->count < slen) ? user->count : slen;
                           slen = (slen > len) ? len : slen;
                           ArgusDump ((const u_char *) &user->array, slen, "      ", sbuf);
                           printf ("%s\n", sbuf);
                        }
                     }
                  }
                  if (ArgusParser->RaPrintAlgorithmList[i]->print == ArgusPrintDstUserData) {
                     int slen = 0, len = ArgusParser->RaPrintAlgorithmList[i]->length;
                     if (len > 0) {
                        if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) != NULL) {
                           if (user->hdr.type == ARGUS_DATA_DSR) {
                              slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                           } else
                              slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

                           slen = (user->count < slen) ? user->count : slen;
                           slen = (slen > len) ? len : slen;
                           ArgusDump ((const u_char *) &user->array, slen, "      ", sbuf);
                           printf ("%s\n", sbuf);
                        }
                     }
                  }
               } else
                  break;
            }
            ArgusFree(sbuf);
         }

         if (strlen(buf) && !(parser->ArgusPrintJson))
            fprintf (stdout, "\n");
         fflush (stdout);
      }
   }
   ArgusFree(buf);
}


int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}

/*
   Mysql URL that we will respond to is:
      mysql://[username[:password]@]hostname[:port]/database/tablename
*/

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

      if (RaDatabase) 
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

   sprintf (sbuf, "USE argus");

   if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) == 0) {
      if ((mysqlRes = mysql_list_tables(RaMySQL, NULL)) != NULL) {
         char sbuf[MAXSTRLEN];

         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               unsigned long *lengths;
               lengths = mysql_fetch_lengths(mysqlRes);
               bzero(sbuf, sizeof(sbuf));
                  for (x = 0; x < retn; x++)
                  sprintf(&sbuf[strlen(sbuf)], "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

               if (!(strncmp(sbuf, "Seconds", 8))) {
                  ArgusSQLSecondsTable = 1;
               }
            }

         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (2, "list argus database returned no tables.\n");
#endif
         }
         mysql_free_result(mysqlRes);
      }
   }

   if (!RaSQLNoCreate) {
      bzero(sbuf, sizeof(sbuf));
      sprintf (sbuf, "CREATE DATABASE IF NOT EXISTS %s", RaDatabase);

      if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
         ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
   }

   sprintf (sbuf, "USE %s", RaDatabase);

   if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   if ((mysqlRes = mysql_list_tables(RaMySQL, NULL)) != NULL) {
      char sbuf[MAXSTRLEN];

      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         int thisIndex = 0;

         while ((row = mysql_fetch_row(mysqlRes))) {
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

   if (RaTable != NULL) {
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

   if ((ArgusParser->ArgusInputFileList != NULL)  ||
        (ArgusParser->ArgusRemoteHosts && (ArgusParser->ArgusRemoteHosts->count > 0))) {

      if (RaSQLSaveTable != NULL) {
         if (!((strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$'))))
            if (ArgusCreateSQLSaveTable(RaSQLSaveTable))
               ArgusLog(LOG_ERR, "mysql create %s returned error", RaSQLSaveTable);
      }
   }

   if (ArgusParser->MySQLDBEngine == NULL)
      ArgusParser->MySQLDBEngine = strdup("InnoDB");

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaMySQLInit () RaSource %s RaArchive %s RaFormat %s", RaSource, RaArchive, RaFormat);
#endif
}


void
RaSQLQuerySecondsTable (unsigned int start, unsigned int stop)
{
   struct RaMySQLSecondsTable *sqry = NULL;
   MYSQL_RES *mysqlRes;
   char *endptr, *str;
   char *buf, *sbuf;

   unsigned int t1, t2;
   int retn, x;

   if ((buf = (char *)ArgusCalloc (1, MAXSTRLEN)) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

   if ((sbuf = (char *)ArgusCalloc (1, MAXSTRLEN)) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

   for (t1 = start; t1 <= stop; t1 += ARGUSSQLMAXQUERYTIMESPAN) {
      t2 = ((t1 + ARGUSSQLMAXQUERYTIMESPAN) > stop) ? stop : (t1 + ARGUSSQLMAXQUERYTIMESPAN);

      str = "SELECT * from %s.Seconds WHERE second >= %u and second <= %u";
      sprintf (buf, str, RaDatabase, t1, t2);

#ifdef ARGUSDEBUG
      ArgusDebug (2, "SQL Query %s\n", buf);
#endif

      if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
         ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

      else {
         if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
            if ((retn = mysql_num_fields(mysqlRes)) > 0) {
               while ((row = mysql_fetch_row(mysqlRes))) {
                  unsigned long *lengths;
       
                  lengths = mysql_fetch_lengths(mysqlRes);
                  bzero(sbuf, MAXSTRLEN);

                  if ((sqry = (void *) ArgusCalloc (1, sizeof(*sqry))) == NULL)
                     ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

                  for (x = 0; x < retn; x++) {
                     int y = x;
                     snprintf(sbuf, MAXSTRLEN, "%.*s ", (int) lengths[x], row[x] ? row[x] : "NULL");
                     
                     switch (y) {
                        case RAMYSQL_SECONDTABLE_PROBE:
                           sqry->probe = strtol(sbuf, &endptr, 10);
                           if (sbuf == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                           break;

                        case RAMYSQL_SECONDTABLE_SECOND:
                           sqry->second = strtol(sbuf, &endptr, 10);
                           if (sbuf == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                           break;

                        case RAMYSQL_SECONDTABLE_FILEINDEX:
                           sqry->fileindex = strtol(sbuf, &endptr, 10);
                           if (sbuf == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                           break;

                        case RAMYSQL_SECONDTABLE_OSTART:
                           sqry->ostart = strtol(sbuf, &endptr, 10);
                           if (sbuf == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                           break;

                        case RAMYSQL_SECONDTABLE_OSTOP:
                           sqry->ostop = strtol(sbuf, &endptr, 10);
                           if (sbuf == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                           break;
                     }
                  }

                  ArgusAddToQueue (ArgusModelerQueue, &sqry->qhdr, ARGUS_LOCK);
               }
            }

            mysql_free_result(mysqlRes);
         }
      }
   }
   ArgusFree(sbuf);
   ArgusFree(buf);
}

void
RaSQLQueryDatabaseTable (char *table, unsigned int start, unsigned int stop)
{
   MYSQL_RES *mysqlRes;
   char *timeField = "stime";
   char *buf, *sbuf;
   int i, slen = 0;
   int retn, x, count = 0;

   if ((buf = (char *)ArgusCalloc (1, MAXSTRLEN)) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

   if ((sbuf = (char *)ArgusCalloc (1, MAXARGUSRECORD)) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

   for (i = 0; (ArgusTableColumnName[i] != NULL) && (i < ARGUSSQLMAXCOLUMNS); i++) {
      if (!(strcmp("ltime", ArgusTableColumnName[i]))) {
//       timeField = "ltime";
      }
      if (!(strcmp("stime", ArgusTableColumnName[i]))) {
         timeField = "stime";
         break;
      }
   }

   if (timeField == NULL)
      timeField = "second";

   {
      char *ArgusSQLStatement;
      unsigned int t1, t2;

      if ((ArgusSQLStatement = ArgusCalloc(1, MAXSTRLEN)) == NULL)
         ArgusLog(LOG_ERR, "unable to allocate ArgusSQLStatement: %s", strerror(errno));

      sprintf (buf, "SELECT count(*) from %s", table);
      if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) == 0) {
         if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
            if ((retn = mysql_num_fields(mysqlRes)) > 0) {
               while ((row = mysql_fetch_row(mysqlRes))) {
                  count = atoi(row[0]);
               }
            }
         }
      }

      if (count > ARGUSSQLMAXROWNUMBER) {
         if (timeField && (ArgusParser->tflag == 0)) {
            sprintf (buf, "SELECT min(%s) start, max(%s) stop from %s", timeField, timeField, table);
            if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) == 0) {
               if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
                  if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                     while ((row = mysql_fetch_row(mysqlRes))) {
                        start = atoi(row[0]);
                        stop  = atoi(row[1]) + 1;
                     }
                  }
               }
            }
         }

         for (t1 = start; t1 <= stop; t1 += ARGUSSQLMAXQUERYTIMESPAN) {
            t2 = ((t1 + ARGUSSQLMAXQUERYTIMESPAN) > stop) ? stop : (t1 + ARGUSSQLMAXQUERYTIMESPAN);

            *ArgusSQLStatement = '\0';
         
            if (ArgusParser->ArgusSQLStatement != NULL)
               strcpy(ArgusSQLStatement, ArgusParser->ArgusSQLStatement);

            if (ArgusAutoId)
               sprintf (buf, "SELECT autoid,record from %s", table);
            else
               sprintf (buf, "SELECT record from %s", table);

            if ((slen = strlen(ArgusSQLStatement)) > 0) {
               snprintf (&ArgusSQLStatement[strlen(ArgusSQLStatement)], MAXSTRLEN - slen, " and ");
               slen = strlen(ArgusSQLStatement);
            }

            snprintf (&ArgusSQLStatement[slen], MAXSTRLEN - slen, "%s >= %d and %s < %d", timeField, t1, timeField, t2);

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

      } else {
         *ArgusSQLStatement = '\0';
         
         if (ArgusParser->ArgusSQLStatement != NULL)
            strcpy(ArgusSQLStatement, ArgusParser->ArgusSQLStatement);

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

   ArgusFree(sbuf);
   ArgusFree(buf);
}

void RaSQLProcessQueue (struct ArgusQueueStruct *);

void 
RaSQLProcessQueue (struct ArgusQueueStruct *queue)
{
   struct RaMySQLFileStruct *fstruct = NULL;
   struct RaMySQLSecondsTable *sqry = NULL, *tsqry = NULL;

   if (queue == NULL)
      return;

   while (queue->count) {
      if ((sqry = (struct RaMySQLSecondsTable *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
         int i, cnt = queue->count;

         if ((fstruct = (void *) ArgusCalloc (1, sizeof(*fstruct))) == NULL)
            ArgusLog(LOG_ERR, "RaSQLProcessQueue: ArgusCalloc error %s", strerror(errno));

         fstruct->fileindex = sqry->fileindex;
         fstruct->probe  = sqry->probe;
         fstruct->second = sqry->second;
         fstruct->ostart = sqry->ostart;
         fstruct->ostop  = sqry->ostop;
         ArgusAddToQueue (ArgusFileQueue, &fstruct->qhdr, ARGUS_LOCK);

         if (cnt > 0) {
            for (i = 0; i < cnt; i++) {
               if ((tsqry = (void *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
                  if (sqry->fileindex == tsqry->fileindex) {
                     if (fstruct->second > tsqry->second)
                        fstruct->second = tsqry->second;
                     if (fstruct->ostart > tsqry->ostart)
                        fstruct->ostart = tsqry->ostart;
                     if (fstruct->ostop < tsqry->ostop)
                        fstruct->ostop = tsqry->ostop;

                     ArgusFree(tsqry);

                  } else {
                     ArgusAddToQueue(queue, &tsqry->qhdr, ARGUS_LOCK);
                  }
               }
            }
         }

         ArgusFree(sqry);
      }
   }

   if (ArgusFileQueue->count) {
      int i, cnt = ArgusFileQueue->count;
      char *buf, *sbuf;
      MYSQL_RES *mysqlRes;
      struct stat statbuf;
      int retn, x;

      if ((buf = ArgusMalloc(1024)) == NULL)
         ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

      if ((sbuf = ArgusMalloc(1024)) == NULL)
         ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

      for (i = 0; i < cnt; i++) {
         if ((fstruct = (struct RaMySQLFileStruct *) ArgusPopQueue(ArgusFileQueue, ARGUS_LOCK)) !=  NULL) {
            char *str = NULL;

            str = "SELECT filename from %s.Filename WHERE id = %d",
            sprintf (buf, str, RaDatabase, fstruct->fileindex);

            if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
               ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

            else {
               if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
                  if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                     while ((row = mysql_fetch_row(mysqlRes))) {
                        char *file, *filenamebuf, *directorypath;
                        char *ptr = NULL;
                        unsigned long *lengths;

                        if ((file = ArgusMalloc(MAXSTRLEN)) == NULL)
                           ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

                        if ((filenamebuf = ArgusMalloc(MAXSTRLEN)) == NULL)
                           ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

                        if ((directorypath = ArgusMalloc(MAXSTRLEN)) == NULL)
                           ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));
          
                        lengths = mysql_fetch_lengths(mysqlRes);
                        if (RaFormat) {
                           char fbuf[1024];
                           time_t secs;
                           bzero (fbuf, sizeof(fbuf));
                           if ((ptr = strstr(RaFormat, "$srcid")) != NULL) {
                              struct RaMySQLProbeTable *psqry = (void *)ArgusProbeQueue->start;
                              RaProbeString = NULL;
                              bcopy (RaFormat, fbuf, (ptr - RaFormat));
                              if (psqry) {
                                 for (x = 0; x < ArgusProbeQueue->count; x++) {
                                    if ((psqry->probe == fstruct->probe) || (fstruct->probe == 0)) {
                                       RaProbeString = psqry->name;
                                       break;
                                    }
                                    psqry = (void *)psqry->qhdr.nxt;
                                 }
                                 if (RaProbeString)
                                    sprintf (&fbuf[strlen(fbuf)], "%s", RaProbeString);
                              }
                              
                              bcopy (&ptr[6], &fbuf[strlen(fbuf)], strlen(&ptr[6]));

                           } else {
                              bcopy (RaFormat, fbuf, strlen(RaFormat));
                           }

                           secs = (fstruct->second/RaPeriod) * RaPeriod;
                           strftime (directorypath, MAXSTRLEN, fbuf, localtime(&secs));
                        }

                        for (x = 0; x < retn; x++)
                           snprintf(sbuf, MAXSTRLEN, "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

                        if ((ptr = strchr(sbuf, '.')) == NULL)
                           ArgusLog(LOG_ERR, "RaSQLProcessQueue: Filename format error %s", sbuf);

                        if (RaFormat) 
                           sprintf (file, "%s/%s", directorypath, sbuf);
                        else
                           sprintf (file, "%s", sbuf);

                        while (file[strlen(file) - 1] == ' ')
                           file[strlen(file) - 1] = '\0';

                        if (!(strncmp(&file[strlen(file) - 3], ".gz", 3))) 
                           file[strlen(file) - 3] = '\0';

                        if (RaRoleString) {
                           sprintf (filenamebuf, "%s/%s/%s", ArgusArchiveBuf, RaRoleString, file);
                        } else {
                           sprintf (filenamebuf, "%s/%s", ArgusArchiveBuf, file);
                        }

                        if ((stat (filenamebuf, &statbuf)) != 0) {   // does file exist
                           char *compressbuf = NULL;
                           char *filepath =  NULL;

                           if ((filepath = ArgusMalloc(MAXSTRLEN)) == NULL)
                              ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

                           if (ArgusParser->RaTempFilePath != NULL)
                              sprintf(filepath, "%s/%s", ArgusParser->RaTempFilePath, filenamebuf);

                           if ((stat (filepath, &statbuf)) != 0) {  // is file in temporary cache 

                              if ((compressbuf = ArgusMalloc(MAXSTRLEN)) == NULL)
                                 ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

                              sprintf (compressbuf, "%s.gz", filenamebuf);

                              if ((stat (compressbuf, &statbuf)) == 0) {
                                 if ((fstruct->ostart >= 0) || (fstruct->ostop > 0)) {
                                    char *command =  NULL;

                                    if ((command = ArgusMalloc(MAXSTRLEN)) == NULL)
                                       ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

                                    ArgusMkdirPath(filepath);

                                    sprintf (command, "gunzip -c \"%s\" > \"%s\"", compressbuf, filepath);
#ifdef ARGUSDEBUG
                                    ArgusDebug (2, "RaSQLProcessQueue: local decomression command %s\n", command);
#endif
                                    if (system(command) < 0)
                                       ArgusLog(LOG_ERR, "RaSQLProcessQueue: system error", strerror(errno));

                                    sprintf (filenamebuf, "%s", filepath);
                                    ArgusFree(command);

                                 } else {
                                    sprintf (filenamebuf, "%s", compressbuf);
                                 }

                              } else {
/*
                                 if (RaHost) {
                                    int RaPort = ArgusParser->ArgusPortNum ?  ArgusParser->ArgusPortNum : ARGUS_DEFAULTPORT;
                                    char *command =  NULL;

                                    if ((command = ArgusMalloc(MAXSTRLEN)) == NULL)
                                       ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

                                    if (RaRoleString != NULL)
                                       sprintf (command, "\"%s/ra\" -S %s:%d%s/%s/%s -w %s", RaProgramPath, RaHost, RaPort, RaArchive, RaRoleString, file, filenamebuf);
                                    else
                                       sprintf (command, "\"%s/ra\" -S %s:%d%s/%s -w %s", RaProgramPath, RaHost, RaPort, RaArchive, file, filenamebuf);
#ifdef ARGUSDEBUG
                                    ArgusDebug (2, "RaSQLProcessQueue: remote file caching command  %s\n", command);
#endif
                                    if (system(command) < 0)
                                       ArgusLog(LOG_ERR, "RaSQLProcessQueue: system error", strerror(errno));

                                    ArgusFree(command);
                                 }
*/
                              }

                           } else {
                              sprintf (filenamebuf, "%s", filepath);
                           }
                           ArgusFree(filepath);
                        }

                        fstruct->filename = strdup (filenamebuf);
                        ArgusFree(file);
                        ArgusFree(filenamebuf);
                        ArgusFree(directorypath);
                     }
                  }

                  mysql_free_result(mysqlRes);
               }
            }
            ArgusAddToQueue(ArgusFileQueue, &fstruct->qhdr, ARGUS_LOCK);
         }
      }

      ArgusFree(buf);
      ArgusFree(sbuf);
   }

   if (ArgusFileQueue->count) {
      struct RaMySQLFileStruct *fptr = NULL;
      int x;

      while ((fstruct = (struct RaMySQLFileStruct *) ArgusPopQueue(ArgusFileQueue, ARGUS_LOCK)) != NULL) {
         fptr = (struct RaMySQLFileStruct *) ArgusFileQueue->start;

         for (x = 0; x < ArgusFileQueue->count; x++) {
            if (fstruct->fileindex == fptr->fileindex) {
               if (fstruct->ostart < fptr->ostart)
                  fptr->ostart = fstruct->ostart;
               if (fstruct->ostop > fptr->ostop)
                  fptr->ostop = fstruct->ostop;

               ArgusFree(fstruct);
               fstruct = NULL;
               break;
            }

            fptr = (struct RaMySQLFileStruct *) fptr->qhdr.nxt;
         }

         if (fstruct != NULL) {
            ArgusAddFileList(ArgusParser, fstruct->filename, ARGUS_DATA_SOURCE,
                       fstruct->ostart, fstruct->ostop);
#ifdef ARGUSDEBUG
            ArgusDebug (2, "RaSQLProcessQueue: filename %s ostart %d  ostop %d\n",
                              fstruct->filename, fstruct->ostart, fstruct->ostop);
#endif
         }
      }

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (2, "RaSQLProcessQueue: query return NULL");
#endif
      RaParseComplete(SIGINT);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaSQLProcessQueue(0x%x)", queue);
#endif
}

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusAdjustStruct *nadp = NULL;
   int x, retn = 0, found = 0, tableIndex;
   struct ArgusModeStruct *mode;
   char *table = NULL;

   if (!(parser->RaInitialized)) {
      char ArgusSQLStatement[MAXSTRLEN];
      MYSQL_RES *mysqlRes;

      parser->RaInitialized++;
      parser->RaWriteOut = 0;

      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      ArgusParseInit(ArgusParser, NULL);

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      if (ArgusParser->Sflag)
         usage();

      for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (parser->RaPrintAlgorithmList[x] != NULL) {
            if (!(strncmp(parser->RaPrintAlgorithmList[x]->field, "autoid", 6))) {
               ArgusAutoId = 1;
               break;
            }
         } else
            break;
      }

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if (parser->ArgusAggregator->correct != NULL) { free(parser->ArgusAggregator->correct); parser->ArgusAggregator->correct = NULL; }

      if ((ArgusModelerQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

      if ((ArgusProbeQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

      if ((ArgusFileQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

      if ((RaBinProcess = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*RaBinProcess))) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

#if defined(ARGUS_THREADS)
      pthread_mutex_init(&RaBinProcess->lock, NULL);
#endif

      nadp = &RaBinProcess->nadp;

      nadp->mode   = -1;
      nadp->modify =  0;
      nadp->slen   =  2;
 
      if (parser->aflag)
         nadp->slen = parser->aflag;

      if ((mode = parser->ArgusModeList) != NULL) {
         int i, ind;
         while (mode) {
            for (i = 0, ind = -1; i < ARGUSSPLITMODENUM; i++) {
               if (!(strncasecmp (mode->mode, RaSplitModes[i], strlen(RaSplitModes[i])))) {
                  ind = i;
                  break;
               }
            }

            if (ind >= 0) {
               char *mptr = NULL;
               switch (ind) {
                  case ARGUSSPLITRATE:  {   /* "%d:%d[yMwdhms]" */
                     struct ArgusModeStruct *tmode = NULL; 
                     nadp->mode = ind;
                     if ((tmode = mode->nxt) != NULL) {
                        mptr = tmode->mode;
                        if (isdigit((int)*tmode->mode)) {
                           char *ptr = NULL;
                           nadp->count = strtol(tmode->mode, (char **)&ptr, 10);
                           if (*ptr++ != ':') 
                              usage();
                           tmode->mode = ptr;
                        }
                     }
                  }

                  case ARGUSSPLITTIME: /* "%d[yMwdhms] */
                     nadp->mode = ind;
                     if ((mode = mode->nxt) != NULL) {
                        if (isdigit((int)*mode->mode)) {
                           char *ptr = NULL;
                           nadp->value = strtol(mode->mode, (char **)&ptr, 10);
                           if (ptr == mode->mode)
                              usage();
                           else {
                              switch (*ptr) {
                                 case 'y':
                                    nadp->qual = ARGUSSPLITYEAR;  
                                    nadp->size = nadp->value * 31556926 * 1000000LL;
                                    break;
                                 case 'M':
                                    nadp->qual = ARGUSSPLITMONTH; 
                                    nadp->size = nadp->value * 2629744 * 1000000LL;
                                    break;
                                 case 'w':
                                    nadp->qual = ARGUSSPLITWEEK;  
                                    nadp->size = nadp->value * 604800 * 1000000LL;
                                    break;
                                 case 'd':
                                    nadp->qual = ARGUSSPLITDAY;   
                                    nadp->size = nadp->value * 86400 * 1000000LL;
                                    break;
                                 case 'h':
                                    nadp->qual = ARGUSSPLITHOUR;  
                                    nadp->size = nadp->value * 3600 * 1000000LL;
                                    break;
                                 case 'm':
                                    nadp->qual = ARGUSSPLITMINUTE;
                                    nadp->size = nadp->value * 60 * 1000000LL;
                                    break;
                                  default:
                                    nadp->qual = ARGUSSPLITSECOND;
                                    nadp->size = nadp->value * 1000000LL;
                                    break;
                              }
                           }
                        }
                        if (mptr != NULL)
                            mode->mode = mptr;
                     }

                     nadp->modify = 1;

                     if (ind == ARGUSSPLITRATE) {
                        /* need to set the flow idle timeout value to be equal to or
                           just a bit bigger than (nadp->count * nadp->size) */

                        ArgusParser->timeout.tv_sec  = (nadp->count * (nadp->size / 1000000));
                        ArgusParser->timeout.tv_usec = 0;
                     }
                     break;

                  case ARGUSSPLITSIZE:
                  case ARGUSSPLITCOUNT:
                     nadp->mode = ind;
                     nadp->count = 1;

                     if ((mode = mode->nxt) != NULL) {
                        if (isdigit((int)*mode->mode)) {
                           char *ptr = NULL;
                           nadp->value = strtol(mode->mode, (char **)&ptr, 10);
                           if (ptr == mode->mode)
                              usage();
                           else {
                              switch (*ptr) {
                                 case 'B':   
                                 case 'b':  nadp->value *= 1000000000; break;
                                  
                                 case 'M':   
                                 case 'm':  nadp->value *= 1000000; break;
                                  
                                 case 'K':   
                                 case 'k':  nadp->value *= 1000; break;
                              }
                           }
                        }
                     }
                     break;

                  case ARGUSSPLITNOMODIFY:
                     nadp->modify = 0;
                     break;

                  case ARGUSSPLITHARD:
                     nadp->hard++;
                     break;

                  case ARGUSSPLITZERO:
                     nadp->zero++;
                     break;
               }

            } else {
               if (!(strncasecmp (mode->mode, "nocorrect", 9))) {
                  if (parser->ArgusAggregator->correct != NULL) {
                     free(parser->ArgusAggregator->correct);
                     parser->ArgusAggregator->correct = NULL;
                  }
                  parser->ArgusPerformCorrection = 0;
               } else
               if (!(strncasecmp (mode->mode, "rtime", 5)) ||
                  (!(strncasecmp (mode->mode, "realtime", 8)))) {
                  ArgusParser->status |= ARGUS_REAL_TIME_PROCESS;
               } else
               if (!(strncasecmp (mode->mode, "oui", 3))) {
                  parser->ArgusPrintEthernetVendors++;
               } else
               if (!strncasecmp (mode->mode, "nocreate", 8)) {
                  RaSQLNoCreate = 1;
               } else
               if (!strncasecmp (mode->mode, "noprune", 7)) {
                  if (parser->ArgusLabeler != NULL) {
                     parser->ArgusLabeler->prune = 0;
                  }
                  if (parser->ArgusLocalLabeler != NULL) {
                     parser->ArgusLocalLabeler->prune = 0;
                  }
               } else
               if (!(strncasecmp (mode->mode, "debug.local", 10))) {
                  if (parser->ArgusLocalLabeler != NULL) {
                     parser->ArgusLocalLabeler->RaPrintLabelTreeMode = ARGUS_TREE;
                     if (!(strncasecmp (mode->mode, "debug.localnode", 14))) {
                        parser->ArgusLocalLabeler->status |= ARGUS_LABELER_DEBUG_NODE;
                     } else
                        parser->ArgusLocalLabeler->status |= ARGUS_LABELER_DEBUG_LOCAL;
                  }
               }
            }

            mode = mode->nxt;
         }
      }

      RaBinProcess->size = nadp->size;

      if (nadp->mode < 0) {
         nadp->mode = ARGUSSPLITCOUNT;
         nadp->value = 10000;
         nadp->count = 1;
      }

      if (parser->ArgusLocalLabeler && ((parser->ArgusLocalLabeler->status & ARGUS_LABELER_DEBUG_LOCAL) ||
                                        (parser->ArgusLocalLabeler->status & ARGUS_LABELER_DEBUG_NODE))) {
         if (parser->ArgusLocalLabeler &&  parser->ArgusLocalLabeler->ArgusAddrTree) {
            extern int RaPrintLabelTreeLevel;
            if (parser->Lflag > 0) {
               RaPrintLabelTreeLevel = parser->Lflag;
            }
            RaPrintLabelTree (parser->ArgusLocalLabeler, parser->ArgusLocalLabeler->ArgusAddrTree[AF_INET], 0, 0);
         }
         exit(0);
      }

      RaMySQLInit();

      if (parser->tflag) {

// so we've been given a time filter, so we have a start and end time
// stored in parser->startime_t && parser->lasttime_t, and we support
// wildcard options, so ..., the idea is that we need at some point to
// calculate the set of tables that we'll search for records.  We
// should do that here.
//
// So the actual table, datatbase, etc..., were set in the RaMySQLInit()
// call so we can test some values here.
// 
         RaTables = ArgusCreateSQLTimeTableNames(parser, &ArgusTableStartSecs,
                                                 &ArgusTableEndSecs,
                                                 ArgusSQLSecondsTable,
                                                 &RaBinProcess->nadp, RaTable);
      }

      if ((RaTables == NULL) && (RaTable != NULL)) {
         sprintf (ArgusSQLTableNameBuf, "%s", RaTable);

         if ((RaTables = ArgusCalloc(sizeof(void *), 2)) == NULL)
            ArgusLog(LOG_ERR, "mysql_init error %s", strerror(errno));

         RaTables[0] = strdup(ArgusSQLTableNameBuf);
      }

      if (RaTables != NULL) {
         bzero(&ArgusTableColumnName, sizeof (ArgusTableColumnName));

         tableIndex = 0;
         retn = -1;
         while ((table = RaTables[tableIndex]) != NULL) {
            if (strcmp("Seconds", table)) {
               sprintf (ArgusSQLStatement, "desc %s", table);
               if ((retn = mysql_real_query(RaMySQL, ArgusSQLStatement , strlen(ArgusSQLStatement))) != 0) {
                  if (mysql_errno(RaMySQL) != ER_NO_SUCH_TABLE) {
                     ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
#ifdef ARGUSDEBUG
                  } else {
                     ArgusDebug (4, "%s: skip missing table %s", __func__, table);
#endif
                  }
               } else {
                  found++;
                  break;
               }
            } else
               retn = 0;
            tableIndex++;
         }
      }

      if (retn == 0) {
         if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
            if ((retn = mysql_num_fields(mysqlRes)) > 0) {
               int ind = 0;
               while ((row = mysql_fetch_row(mysqlRes)))
                  ArgusTableColumnName[ind++] = strdup(row[0]);

               mysql_free_result(mysqlRes);
            }
         }

      if (retn > 0) {
         int x, i = 0;

         while (parser->RaPrintAlgorithmList[i] != NULL) {
           ArgusFree(parser->RaPrintAlgorithmList[i]);
           parser->RaPrintAlgorithmList[i] = NULL;
           i++;
         }

         for (x = 0; (ArgusTableColumnName[x] != NULL) && (x < ARGUSSQLMAXCOLUMNS); x++) {
            for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
               if (!strcmp(RaPrintAlgorithmTable[i].field, ArgusTableColumnName[x])) {
                  if ((parser->RaPrintAlgorithmList[x] = ArgusCalloc(1, sizeof(*parser->RaPrintAlgorithm))) == NULL)
                     ArgusLog (LOG_ERR, "ArgusCalloc error %s", strerror(errno));

                  bcopy(&RaPrintAlgorithmTable[i], parser->RaPrintAlgorithmList[x], sizeof(*parser->RaPrintAlgorithm));
               }
            }
         }

         ArgusProcessSOptions(parser);
      }

      if (RaTables) {
         RaSQLQueryTable (RaMySQL, (const char **)RaTables, ArgusAutoId,
                          argus_version,
                          (const char **)&ArgusTableColumnName[0]);

         if (ArgusModelerQueue->count > 0)
            RaSQLProcessQueue (ArgusModelerQueue);
         else
            RaParseComplete (SIGINT);
      }
      } else {
         if (!found) {
#ifdef ARGUSDEBUG
            ArgusDebug (1, "No SQL tables found\n");
#endif
            RaParseComplete (SIGINT);
         }
      }
   }
}

void
usage ()
{
   extern char version[];

   fprintf (stdout, "RaSql Version %s\n", version);
   fprintf (stdout, "usage: %s -r mysql://[user[:pass]@]host[:port]/db/table\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s -t timerange -r mysql://[user[:pass]@]host[:port]/db\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [ra-options] [rasql-options] [- filter-expression]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -M sql='where clause'  pass where clause to database engine.\n");
   fprintf (stdout, "         -r <dbUrl>             read argus data from mysql database.\n");
   fprintf (stdout, "             Format:            mysql://[user[:pass]@]host[:port]/db/table\n");
   fflush (stdout);

   exit(1);
}


/*
 *  Convert host name to internet address.
 *  Return 0 upon failure.
 */

unsigned int **
argus_nametoaddr(char *name)
{
#ifndef h_addr
   static unsigned int *hlist[2];
#endif
   struct hostent *hp;

   if ((hp = gethostbyname(name)) != NULL) {
#ifndef h_addr
      hlist[0] = (unsigned int *)hp->h_addr;
#if defined(_LITTLE_ENDIAN)
      *hp->h_addr = ntohl(*hp->h_addr);
#endif
      return hlist;
#else
#if defined(_LITTLE_ENDIAN)
      {
         unsigned int **p;
          for (p = (unsigned int **)hp->h_addr_list; *p; ++p)
             **p = ntohl(**p);
      }
#endif
      return (unsigned int **)hp->h_addr_list;
#endif
   }
   else
      return 0;
}



int
RaProcessSplitOptions(struct ArgusParserStruct *parser, char *str, int len, struct ArgusRecordStruct *ns)
{
   char resultbuf[MAXSTRLEN], tmpbuf[MAXSTRLEN];
   char *ptr = NULL, *tptr = str;
   int retn = 0, i, x;

   len = len > MAXSTRLEN ? MAXSTRLEN : len;
   bzero (resultbuf, len);

   if (ns == NULL)
      return (1);

   while ((ptr = strchr (tptr, '$')) != NULL) {
      *ptr++ = '\0';
      sprintf (&resultbuf[strlen(resultbuf)], "%s", tptr);

      for (i = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (!strncmp (RaPrintAlgorithmTable[x].field, ptr, strlen(RaPrintAlgorithmTable[x].field))) {
            bzero (tmpbuf, sizeof(tmpbuf));
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
   ArgusDebug (1, "RaProcessSplitOptions(%s, %d, 0x%x): returns %d", str, len, ns, retn);
#endif

   return (retn);
}


extern int RaDaysInAMonth[12];


/*
    So first look to see if the table already exists.
    If so and we're suppose to delete, then delete it.
    Then look to see if the name is in our list of default
    RaTableCreateNames[] to see if we need to remove it
    from that list, if we didn't catch the table in the
    other list.  At the end of this routine cindex is pointing 
    at the right place.
*/


char *
ArgusCreateSQLSaveTableName (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, char *table)
{
   char *retn = NULL;
   struct ArgusAdjustStruct *nadp = &RaBinProcess->nadp;

   if (strchr(table, '%') || strchr(table, '$')) {
      int size = nadp->size / 1000000;
      long long start;
      time_t tableSecs;
      struct tm tmval;

      if (ns != NULL) 
         start = ArgusFetchStartuSecTime(ns);
      else 
         start = parser->ArgusRealTime.tv_sec * 1000000LL + parser->ArgusRealTime.tv_usec;
      
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
            ArgusLog (LOG_ERR, "RaSendArgusRecord () ArgusCalloc %s\n", strerror(errno));

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


int
ArgusCreateSQLSaveTable(char *table)
{
   int retn = 0, cindex = 0, ind = 0, i, x, exists = 0;
   struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
   char stable[256], sbuf[MAXSTRLEN], kbuf[MAXSTRLEN];

   sprintf (stable, "%s", table);

   bzero(sbuf, sizeof(sbuf));
   bzero(kbuf, sizeof(kbuf));

   for (i = 0; i < RA_MAXTABLES && !exists; i++) {
      if (RaTableExistsNames[i] != NULL) {
         if (!strcmp(RaTableExistsNames[i], stable))
            exists++;
      } else
         break;
   }

   if (!exists) {
      RaTableCreateNames[cindex] = strdup(stable);

      sprintf (sbuf, "CREATE table %s (", RaTableCreateNames[cindex]);
      ind = 0;

      for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
         if (ArgusParser->RaPrintAlgorithmList[i] != NULL) {
            ArgusParser->RaPrintAlgorithm = ArgusParser->RaPrintAlgorithmList[i];

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
            sprintf (&kbuf[strlen(kbuf)], ")");
         }
      }

      if (strlen(kbuf))
         sprintf (&sbuf[strlen(sbuf)], ", %s", kbuf);

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
               ArgusDebug (2, "generating table %s\n", str);
#endif
               if ((retn = mysql_real_query(RaMySQL, str, strlen(str))) != 0)
                  ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));

               ArgusCreateTable = 1;
               RaSQLCurrentTable = strdup(table);
            }
         }
      }

   } else {
      if (RaSQLCurrentTable == NULL)
         RaSQLCurrentTable = strdup(table);
      retn = 0;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCreateSQLSaveTable (%s) returning", table, retn);
#endif
   return (retn);
}
