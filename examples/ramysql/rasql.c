/*
 * Argus Software
 * Copyright (c) 2000-2016 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/*
 *
 * rasql  - Read Argus data using time offset indexs from mysql database.
 *         This program reads argus output streams from a database query,
 *         filters and optionally writes the output to a file, its
 *         stdout or prints the binary records to stdout in ASCII.
 */

/* 
 * $Id: //depot/argus/clients/examples/ramysql/rasql.c#22 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
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
 
#include <mysql.h>

char *RaDatabase = NULL;
char **RaTables = NULL;

char **ArgusCreateSQLTimeTableNames (struct ArgusParserStruct *, char *);
void RaSQLQueryTable (char **);

int ArgusCreateSQLSaveTable(char *);
char *ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, int);
void RaMySQLDeleteRecords(struct ArgusParserStruct *, struct ArgusRecordStruct *);

void RaSQLQueryNetworksTable (unsigned int, unsigned int, unsigned int);
void RaSQLQueryProbes (void);
void RaSQLQuerySecondsTable (unsigned int, unsigned int);

char *ArgusCreateSQLSaveTableName (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);

int RaInitialized = 0;
int ArgusAutoId = 0;
int ArgusDropTable = 0;
int ArgusCreateTable = 0;

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

#define ARGUSSQLMAXCOLUMNS	256
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

extern int ArgusSOptionRecord;
int ArgusDeleteTable = 0;

char RaLocalArchBuf[MAXSTRLEN];

extern char *RaRemoteFilter;
extern char RaFilterSQLStatement[];
  
char *RaHost = NULL, *RaUser = NULL, *RaPass = NULL;
int RaPort = 0;
struct ArgusInput *ArgusInput = NULL;
void RaMySQLInit (void);

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
         ArgusShutDown(sig);
         if ((sig >= 0) && ArgusParser->aflag) {
            printf (" Totalrecords %-8lld  TotalManRecords %-8lld  TotalFarRecords %-8lld TotalPkts %-8lld TotalBytes %-8lld\n",
                          ArgusParser->ArgusTotalRecords,
                          ArgusParser->ArgusTotalMarRecords, ArgusParser->ArgusTotalFarRecords,
                          ArgusParser->ArgusTotalPkts, ArgusParser->ArgusTotalBytes);
         }
      }
      fflush(stdout);
      mysql_close(RaMySQL);
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
         RaProcessManRecord (parser, argus);
         break;

      case ARGUS_EVENT:
         RaProcessEventRecord (parser, argus);
         break;

      case ARGUS_NETFLOW:
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
   static char buf[MAXARGUSRECORD];

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
                     static char sbuf[MAXARGUSRECORD];
                     if ((argusrec = ArgusGenerateRecord (argus, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                     }
                  }
               }
            }

            lobj = lobj->nxt;
         }
      }

   } else {
      if (!parser->qflag) {
         if (parser->Lflag && !(parser->ArgusPrintXml)) {
            if (parser->RaLabel == NULL)
               parser->RaLabel = ArgusGenerateLabel(parser, argus);

            if (!(parser->RaLabelCounter++ % parser->Lflag))
               printf ("%s\n", parser->RaLabel);

            if (parser->Lflag < 0)
               parser->Lflag = 0;
         }

         bzero (buf, sizeof(buf));
         ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);

         fprintf (stdout, "%s", buf);

         if (parser->eflag == ARGUS_HEXDUMP) {
            int i;
            for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
               struct ArgusDataStruct *user = NULL;
               if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcUserData) {
                  int slen = 0, len = parser->RaPrintAlgorithmList[i]->length;
                  if (len > 0) {
                     if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) != NULL) {
                        if (user->hdr.type == ARGUS_DATA_DSR) {
                           slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                        } else
                           slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

                        slen = (user->count < slen) ? user->count : slen;
                        slen = (slen > len) ? len : slen;
                        ArgusDump ((const u_char *) &user->array, slen, "      ");
                     }
                  }
               }
               if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintDstUserData) {
                  int slen = 0, len = parser->RaPrintAlgorithmList[i]->length;
                  if (len > 0) {
                     if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) != NULL) {
                        if (user->hdr.type == ARGUS_DATA_DSR) {
                           slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                        } else
                           slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

                        slen = (user->count < slen) ? user->count : slen;
                        slen = (slen > len) ? len : slen;
                        ArgusDump ((const u_char *) &user->array, slen, "      ");
                     }
                  }
               }
            }
         }

         fprintf (stdout, "\n");
         fflush (stdout);
      }
   }
}


void RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns) {};
void RaProcessEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns) {};
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
   my_bool reconnectbuf = 1, *reconnect = &reconnectbuf;
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
   mysql_options(RaMySQL, MYSQL_OPT_RECONNECT, reconnect);

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
            if (!(strncmp(sbuf, "Seconds", 8))) {
               ArgusSQLSecondsTable = 1;
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

   if ((ArgusParser->ArgusInputFileList != NULL)  ||
        (ArgusParser->ArgusRemoteHosts && (ArgusParser->ArgusRemoteHosts->count > 0))) {

      if (RaSQLSaveTable != NULL) {
         if (!((strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$'))))
            if (ArgusCreateSQLSaveTable(RaSQLSaveTable))
               ArgusLog(LOG_ERR, "mysql create %s returned error", RaSQLSaveTable);
      }
   }

   if (ArgusParser->MySQLDBEngine == NULL)
      ArgusParser->MySQLDBEngine = strdup("MyISAM");

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaMySQLInit () RaSource %s RaArchive %s RaFormat %s", RaSource, RaArchive, RaFormat);
#endif
}


void
RaSQLQueryTable (char **tables)
{
   char ArgusSQLStatement[MAXSTRLEN];
   char buf[MAXARGUSRECORD], sbuf[MAXARGUSRECORD], *table;
   MYSQL_RES *mysqlRes;
   struct timeval now;
   int retn, x, i;

   if ((ArgusInput = (struct ArgusInput *) ArgusCalloc (1, sizeof(struct ArgusInput))) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

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

   ArgusInput->ArgusInitCon.hdr.type  = ARGUS_MAR | ARGUS_VERSION;
   ArgusInput->ArgusInitCon.hdr.cause = ARGUS_START;
   ArgusInput->ArgusInitCon.hdr.len   = htons((unsigned short) sizeof(struct ArgusRecord)/4);

   ArgusInput->ArgusInitCon.argus_mar.argusid = htonl(ARGUS_COOKIE);

   gettimeofday (&now, 0L);

   ArgusInput->ArgusInitCon.argus_mar.now.tv_sec  = now.tv_sec;
   ArgusInput->ArgusInitCon.argus_mar.now.tv_usec = now.tv_usec;

   ArgusInput->ArgusInitCon.argus_mar.major_version = VERSION_MAJOR;
   ArgusInput->ArgusInitCon.argus_mar.minor_version = VERSION_MINOR;

   bcopy((char *)&ArgusInput->ArgusInitCon, (char *)&ArgusParser->ArgusInitCon, sizeof (ArgusParser->ArgusInitCon));

   if (ArgusParser->tflag) {
      char *timeField = NULL;
      int i;

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

      if (ArgusParser->ArgusSQLStatement != NULL) {
      } else {
         snprintf (ArgusSQLStatement, MAXSTRLEN, "%s >= %d and %s <= %d", timeField, (int)ArgusParser->startime_t.tv_sec, timeField, (int)ArgusParser->lasttime_t.tv_sec);
         ArgusParser->ArgusSQLStatement = strdup(ArgusSQLStatement);
      }
   }

   for (i = 0; ((table = tables[i]) != NULL); i++) {
      if (!(strcmp ("Seconds", table))) {
         RaSQLQuerySecondsTable (ArgusParser->startime_t.tv_sec, ArgusParser->lasttime_t.tv_sec);

      } else {
         if (ArgusAutoId)
            sprintf (buf, "SELECT autoid,record from %s", table);
         else
            sprintf (buf, "SELECT record from %s", table);

         if (ArgusParser->ArgusSQLStatement != NULL)
            sprintf (&buf[strlen(buf)], " WHERE %s", ArgusParser->ArgusSQLStatement);

#ifdef ARGUSDEBUG
         ArgusDebug (1, "SQL Query %s\n", buf);
#endif
         if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) == 0) {
            if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
               if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                  while ((row = mysql_fetch_row(mysqlRes))) {
                     unsigned long *lengths = mysql_fetch_lengths(mysqlRes);
                     int autoid = 0;

                     bzero(sbuf, sizeof(sbuf));
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

                     if (((struct ArgusRecord *)sbuf)->hdr.type & ARGUS_MAR) {
                        bcopy ((char *) &sbuf, (char *)&ArgusInput->ArgusInitCon, sizeof (struct ArgusRecord));
                     } else {
                        ArgusHandleRecord (ArgusParser, ArgusInput, (struct ArgusRecord *)&sbuf, &ArgusParser->ArgusFilterCode);
                     }
                  }
               }

               mysql_free_result(mysqlRes);
            }
         }
      }
   }
}

void
RaSQLQuerySecondsTable (unsigned int start, unsigned int stop)
{
   struct RaMySQLSecondsTable *sqry = NULL;
   char buf[2048], sbuf[2048];
   MYSQL_RES *mysqlRes;
   char *endptr, *str;
   int retn, x;

   str = "SELECT * from Seconds WHERE second >= %u and second <= %u",
   sprintf (buf, str, start, stop);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "SQL Query %s\n", buf);
#endif

   if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   else {
      if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               unsigned long *lengths;
    
               lengths = mysql_fetch_lengths(mysqlRes);
               bzero(sbuf, sizeof(sbuf));

               if ((sqry = (void *) ArgusCalloc (1, sizeof(*sqry))) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

               for (x = 0; x < retn; x++) {
                  int y = x;
                  snprintf(sbuf, 2048, "%.*s ", (int) lengths[x], row[x] ? row[x] : "NULL");
                  
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

void RaSQLProcessQueue (struct ArgusQueueStruct *);

void 
RaSQLProcessQueue (struct ArgusQueueStruct *queue)
{
   struct RaMySQLFileStruct *fstruct = NULL;
   struct RaMySQLSecondsTable *sqry = NULL, *tsqry = NULL;

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
      char buf[2048], sbuf[2048];
      MYSQL_RES *mysqlRes;
      struct stat statbuf;
      int retn, x;

      for (i = 0; i < cnt; i++) {
         if ((fstruct = (struct RaMySQLFileStruct *) ArgusPopQueue(ArgusFileQueue, ARGUS_LOCK)) !=  NULL) {
            char *str = NULL;
            bzero (buf, sizeof(buf));

            str = "SELECT filename from Filename WHERE id = %d",
            sprintf (buf, str, fstruct->fileindex);

            if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
               ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

            else {
               if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
                  if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                     while ((row = mysql_fetch_row(mysqlRes))) {
                        char file[MAXSTRLEN];
                        char filenamebuf[MAXSTRLEN];
                        char directorypath[MAXSTRLEN];
                        char *ptr = NULL;
                        unsigned long *lengths;
          
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
                           snprintf(sbuf, 2048, "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

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

                        if ((stat (filenamebuf, &statbuf)) != 0) {
                           char compressbuf[MAXSTRLEN];
                           sprintf (compressbuf, "%s.gz", filenamebuf);
                           if ((stat (compressbuf, &statbuf)) == 0) {
                              if ((fstruct->ostart >= 0) || (fstruct->ostop > 0)) {
                                 char command[MAXSTRLEN];
                                 sprintf (command, "gunzip %s", compressbuf);
#ifdef ARGUSDEBUG
                                 ArgusDebug (2, "RaSQLProcessQueue: local decomression command %s\n", command);
#endif
                                 if (system(command) < 0)
                                    ArgusLog(LOG_ERR, "RaSQLProcessQueue: system error", strerror(errno));
                              } else {
                                 sprintf (filenamebuf, "%s", compressbuf);
                              }

                           } else {
                              if (RaHost) {
                                 char command[MAXSTRLEN];
                                 int RaPort = ArgusParser->ArgusPortNum ?  ArgusParser->ArgusPortNum : ARGUS_DEFAULTPORT;

                                 if (RaRoleString != NULL)
                                    sprintf (command, "/usr/local/bin/ra -nnS %s:%d%s/%s/%s -w %s", RaHost, RaPort, RaArchive, RaRoleString, file, filenamebuf);
                                 else
                                    sprintf (command, "/usr/local/bin/ra -nnS %s:%d%s/%s -w %s", RaHost, RaPort, RaArchive, file, filenamebuf);
#ifdef ARGUSDEBUG
                                 ArgusDebug (2, "RaSQLProcessQueue: remote file caching command  %s\n", command);
#endif
                                 if (system(command) < 0)
                                    ArgusLog(LOG_ERR, "RaSQLProcessQueue: system error", strerror(errno));
                              }
                           }
                        }

                        fstruct->filename = strdup (filenamebuf);
                     }
                  }

                  mysql_free_result(mysqlRes);
               }
            }

            ArgusAddToQueue(ArgusFileQueue, &fstruct->qhdr, ARGUS_LOCK);
         }
      }
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
   struct ArgusModeStruct *mode;
   int x, retn, tableIndex;

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
               } else
               if (!(strncasecmp (mode->mode, "rtime", 5)) ||
                  (!(strncasecmp (mode->mode, "realtime", 8)))) {
                  char *ptr = NULL;
                  ArgusParser->status |= ARGUS_REAL_TIME_PROCESS;
                  if ((ptr = strchr(mode->mode, ':')) != NULL) {
                     double value = 0.0;
                     char *endptr = NULL;
                     ptr++;
                     value = strtod(ptr, &endptr);
                     if (ptr != endptr)
                        parser->ArgusTimeMultiplier = value;
                  }
               } else
               if (!(strncasecmp (mode->mode, "oui", 3)))
                  parser->ArgusPrintEthernetVendors++;
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
         RaTables = ArgusCreateSQLTimeTableNames(parser, RaTable);
/*
         if (strchr(RaTable, '%') || strchr(RaTable, '$')) {
            RaTables = ArgusCreateSQLTimeTableNames(parser, RaTable);
         }
*/
      }

      if (RaTables == NULL) {
         sprintf (ArgusSQLTableNameBuf, "%s", RaTable);

         if ((RaTables = ArgusCalloc(sizeof(void *), 2)) == NULL)
            ArgusLog(LOG_ERR, "mysql_init error %s", strerror(errno));

         RaTables[0] = strdup(ArgusSQLTableNameBuf);
      }

      bzero(&ArgusTableColumnName, sizeof (ArgusTableColumnName));

      tableIndex = 0;
      retn = -1;
      while (RaTables[tableIndex] != NULL) {
         if (strcmp("Seconds", RaTables[tableIndex])) {
            sprintf (ArgusSQLStatement, "desc %s", RaTables[tableIndex]);
            if ((retn = mysql_real_query(RaMySQL, ArgusSQLStatement , strlen(ArgusSQLStatement))) == 0)
               break;
         }
         tableIndex++;
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
         RaSQLQueryTable (RaTables);

         if (ArgusModelerQueue->count > 0)
            RaSQLProcessQueue (ArgusModelerQueue);
         else
            RaParseComplete (SIGINT);
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

time_t ArgusTableStartSecs = 0;
time_t ArgusTableEndSecs = 0;

#define ARGUS_MAX_TABLE_LIST_SIZE	0x10000

char **
ArgusCreateSQLTimeTableNames (struct ArgusParserStruct *parser, char *table)
{
   char **retn = NULL, *fileStr = NULL;
   struct ArgusAdjustStruct *nadp = &RaBinProcess->nadp;
   int retnIndex = 0;

   if ((retn = ArgusCalloc(sizeof(void *), ARGUS_MAX_TABLE_LIST_SIZE)) == NULL)
      ArgusLog(LOG_ERR, "ArgusCreateSQLTimeTableNames ArgusCalloc %s", strerror(errno));
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

         ArgusTableEndSecs = start / 1000000;

         while (ArgusTableEndSecs < parser->lasttime_t.tv_sec) {
               fileStr = NULL;
               tableSecs = ArgusTableEndSecs;

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

               fileStr = ArgusSQLTableNameBuf;

               if (fileStr != NULL) {
                  retn[retnIndex++] = strdup(fileStr);
               }
            }

// when looking at explicit table expansion, we shouldn't go to the Seconds table
//          if (ArgusSQLSecondsTable)
//             retn[retnIndex++] = strdup("Seconds");

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
         }

         if (ArgusSQLSecondsTable)
            retn[retnIndex++] = strdup("Seconds");
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
         int status = 0;

         while (agg != NULL) {
            mask |= agg->mask;
            status |= agg->status;
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
