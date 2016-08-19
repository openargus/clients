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
 * rasqltimeindex  - Read Argus data and build a time index suitable for
 *                   inserting into a database schema.
 *
 */

/* 
 * $Id: //depot/argus/clients/examples/ramysql/rasqltimeindex.c#18 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <argus_cluster.h>

#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
  
#include <netdb.h>
#include <sys/socket.h>
 
#include <mysql.h>

#include <rasqltimeindex.h>

void RaTimeSortQueue (struct ArgusQueueStruct *);
int RaTimeSortRoutine (const void *, const void *);
void RaTimeCleanHashTable (struct RaTimeHashTableStruct *);

struct RaTimeStore {
   struct ArgusQueueHeader qhdr;
   struct RaTimeHashTableStruct *htable;
   void *object;
};

char *RaDatabase = NULL;
char **RaTables = NULL;

char *RaProbeString = NULL;
char *RaSQLSaveTable = NULL;
char *RaSQLCurrentTable = NULL;

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

void RaMySQLInit (void);

struct ArgusQueueStruct *ArgusFileQueue = NULL;
struct ArgusQueueStruct *ArgusProbeQueue = NULL;

#define RAMON_NETS_CLASSA       0
#define RAMON_NETS_CLASSB       1
#define RAMON_NETS_CLASSC       2
#define RAMON_NETS_CLASS        3

char *RaTableValues[256];
char *RaTableExistsNames[RA_MAXTABLES];
char *RaTableCreateNames[RA_MAXTABLES];
char *RaTableCreateString[RA_MAXTABLES];
char *RaTableDeleteString[RA_MAXTABLES];

char *RaSource       = NULL;
char *RaArchive      = NULL;
char *RaLocalArchive = NULL;
char *RaTable        = NULL;
int   RaPeriod       = 1;

int ArgusDropTable = 0;
int ArgusCreateTable = 0;
int ArgusAutoId = 0;

struct timeval ArgusLastRealTime     = {0, 0};
struct timeval ArgusLastTime         = {0, 0};
struct timeval ArgusThisTime         = {0, 0};
struct timeval ArgusCurrentTime      = {0, 0};


char RaLocalArchBuf[MAXSTRLEN];

extern char *RaRemoteFilter;
extern char RaFilterSQLStatement[];
  
char *RaHost = NULL, *RaUser = NULL, *RaPass = NULL;
int RaPort = 0;
struct ArgusInput *ArgusInput = NULL;
void RaMySQLInit (void);


MYSQL_ROW row;
MYSQL *RaMySQL = NULL;
MYSQL_RES *mysqlRes;

int RaParseCompleteInd = 0;

extern int ArgusTotalMarRecords;
extern int ArgusTotalFarRecords;

extern struct ArgusParserStruct *ArgusParser;
int RaCheckedTables = 0;


void RaArgusInputComplete (struct ArgusInput *input) {
   int cnt, retn, fileindex, filestatus;
   char buf[MAXSTRLEN], *endptr = NULL;
   char sbuf[MAXSTRLEN], *sptr = NULL;
   char *pathptr, filename[MAXSTRLEN];
   struct ArgusInput *ArgusInput = input;
   struct RaTimeProbesStruct *probe = NULL;

   if ((input != NULL) && ((ArgusProbes) && (ArgusProbes->queue) && (ArgusProbes->queue->count > 0))) {
      if ((probe = (struct RaTimeProbesStruct *) ArgusProbes->queue->start) == NULL)
         ArgusLog(LOG_ERR, "RaArgusInputComplete: queue is empty");

      do {
         int found = 0, error = 0;

         bzero(sbuf, sizeof(sbuf));
         sptr = sbuf;
         ArgusPrintSourceID(ArgusParser, sbuf, probe->tn, 64);
         while (isspace(*sptr)) sptr++;
         while (sptr[strlen(sptr) - 1] == ' ') sptr[strlen(sptr) - 1] = '\0';

         do {
            sprintf (buf, RaTableQueryString[6], sptr);
            if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0) 
               ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
            else {
               if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
                  if ((retn = mysql_num_fields(mysqlRes)) == 1) {
                     while ((row = mysql_fetch_row(mysqlRes))) {
                        if (row[0] != NULL) {
                           probe->probeid = strtol(row[0], &endptr, 10);
                           if (row[0] == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: id returned %s", row[0]);
                           found++;
                        }
                     } 
                  }
                  mysql_free_result(mysqlRes);
               }   
               if (!found) {
                  if (ArgusParser->vflag)
                     ArgusLog(LOG_ALERT, "Probe %s not found: installing", sptr);
                  sprintf (buf, RaTableQueryString[7], sptr);
                  if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
                     ArgusLog(LOG_ERR, "mysql_real_query error %s: %s", buf, mysql_error(RaMySQL));
               }
            }
         } while (!found && !error++);
      } while ((probe = (struct RaTimeProbesStruct *) probe->qhdr.nxt) != (void *) ArgusProbes->queue->start);

      bzero (buf, sizeof(buf));
      bzero (filename, sizeof(filename));
      fileindex = -1, filestatus = -1;

     if ((pathptr = realpath(input->filename, filename)) != NULL) {
         free (input->filename);
         input->filename = strdup(filename);
     }

      sprintf (buf, RaTableQueryString[0], filename);
      if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
         ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

      else {
         if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
            if ((retn = mysql_num_fields(mysqlRes)) == 2) {
               while ((row = mysql_fetch_row(mysqlRes))) {
                  if (row[0] != NULL) {
                     fileindex = strtol(row[0], &endptr, 10);
                     if (row[0] == endptr)
                        ArgusLog(LOG_ERR, "mysql database error: id returned %s", row[0]);
                  }
                  if (row[1] != NULL) {
                     filestatus = strtol(row[1], &endptr, 10);
                     if (row[1] == endptr)
                        ArgusLog(LOG_ERR, "mysql database error: id returned %s", row[1]);
                  }
               }
            }

            mysql_free_result(mysqlRes);
         }
      }

      if (filestatus == 1)
         ArgusLog(LOG_ERR, "file %s index %d is locked", ArgusInput->filename, fileindex);

      if (filestatus == 2) {
         if (ArgusParser->vflag)
            ArgusLog(LOG_INFO, "file %s index %d has already been processed", ArgusInput->filename, fileindex);
         goto RaArgusInputCompleteDone;
      }

      if (filestatus == 0) {
         sprintf (buf, RaTableQueryString[4], fileindex);

         if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
            ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

         if (mysql_affected_rows(RaMySQL) == 0)
            ArgusLog(LOG_ERR, "file %s is locked", ArgusInput->filename);

      } else {
         int size, mtime;
         size = ArgusInput->statbuf.st_size;
         mtime = ArgusInput->statbuf.st_mtime;

         sprintf (buf, RaTableQueryString[1], filename, size, 
                       mtime, MDFile(ArgusInput->filename), RaStartTime, RaEndTime);

         if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0) 
            ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
      }

      sprintf (buf, RaTableQueryString[2], filename);

      if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
         ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
      else {
         if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
            if ((retn = mysql_num_fields(mysqlRes)) == 2) {
               while ((row = mysql_fetch_row(mysqlRes))) {
                  if (row[0] != NULL) {
                     fileindex  = strtol(row[0], &endptr, 10);
                     if (row[0] == endptr)
                        ArgusLog(LOG_ERR, "mysql database error: id returned %s", row[0]);
                  }
                  if (row[1] != NULL) {
                     filestatus  = strtol(row[1], &endptr, 10);
                     if (row[1] == endptr)
                        ArgusLog(LOG_ERR, "mysql database error: id returned %s", row[1]);
                  }
               }
            } else {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "mysql_num_fields() returned %d should be 2.\n", retn);
#endif
            }
    
            mysql_free_result(mysqlRes);

         } else
            ArgusLog(LOG_ERR, "mysql_store_result error %s", mysql_error(RaMySQL));
      }

      if ((probe = (struct RaTimeProbesStruct *) ArgusProbes->queue->start) == NULL) 
         ArgusLog(LOG_ERR, "RaArgusInputComplete: queue is empty");
 
      do {
         if ((cnt = probe->queue->count) != 0) {
            int i;
            RaTimeSortQueue (probe->queue);

            bzero (buf, MAXSTRLEN);
            sprintf (buf, "%s", RaTableQueryString[3]);

// gang up as many insert statements as possible mysql specific?

            for (i = 0; i < cnt; i++) {
               struct RaTimeStore *tstore = (struct RaTimeStore *) probe->queue->array[i];
               struct RaTimeHashTableHeader *hdr = (struct RaTimeHashTableHeader *) tstore->object;

               if ((strlen(buf) + 128) > MAXSTRLEN) {
                  if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
                     ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

                  sprintf (buf, "%s", RaTableQueryString[3]);
               }
               if (buf[strlen(buf) - 1] == ')')
                  strcat(buf, ",");

               sprintf (&buf[strlen(buf)], "(%d, %u, %u, %u, %u)", probe->probeid, (u_int) hdr->time.tv_sec, fileindex, hdr->minoffset, hdr->maxoffset);

               RaTimeRemoveHashEntry (probe->rtable, hdr);
            }

            if (buf[strlen(buf) - 1] == ')')
               if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
                  ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

            sprintf (buf, RaTableQueryString[5], fileindex);

            if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
               ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
         }

         bzero (buf, sizeof(buf));

      } while ((probe = (struct RaTimeProbesStruct *) probe->qhdr.nxt) != (void *) ArgusProbes->queue->start);

      if (ArgusParser->vflag)
         ArgusLog(LOG_INFO, "file %s complete", filename);
   }

RaArgusInputCompleteDone:

   if (ArgusProbes) {
#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&ArgusProbes->queue->lock);
#endif
      while ((probe = (struct RaTimeProbesStruct *) ArgusPopQueue(ArgusProbes->queue, ARGUS_NOLOCK))) {
         ArgusDeleteHashTable (probe->htable);
         if (probe->rtable) {
            RaTimeCleanHashTable (probe->rtable);
            if (probe->rtable->array)
               ArgusFree(probe->rtable->array);
            ArgusFree(probe->rtable);
         }
         ArgusDeleteQueue (probe->queue);
         ArgusDeleteRecordStruct(ArgusParser, probe->tn);
         ArgusFree(probe);
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&ArgusProbes->queue->lock);
#endif
      ArgusDeleteQueue(ArgusProbes->queue);
      if ((ArgusProbes->queue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewQueue error %s\n", strerror(errno));

      ArgusEmptyHashTable  (ArgusProbes->htable);
      RaTimeCleanHashTable (ArgusProbes->rtable);
   }

   if (ArgusTimeQueue) {
      ArgusDeleteQueue(ArgusTimeQueue);
         if ((ArgusTimeQueue = ArgusNewQueue()) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewQueue error %s\n", strerror(errno));

      if (RaTimeHashTable != NULL)
         RaTimeCleanHashTable (RaTimeHashTable);
   }

   RaStartTime = 0xFFFFFFFF;
   RaEndTime   = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaArgusInputComplete (0x%x): returning\n", input);
#endif
}

void
RaParseComplete (int sig)
{
   if ((sig >= 0) && ArgusParser->aflag) {

      ArgusShutDown(sig);

      if (!(RaParseCompleteInd++)) {
      printf (" Totalrecords %-8lld  TotalManRecords %-8lld  TotalFarRecords %-8lld TotalPkts %-8lld TotalBytes %-8lld\n",
                       ArgusParser->ArgusTotalRecords,
                       ArgusParser->ArgusTotalMarRecords, ArgusParser->ArgusTotalFarRecords,
                       ArgusParser->ArgusTotalPkts, ArgusParser->ArgusTotalBytes);
      }
   }
   fflush(stdout);
   mysql_close(RaMySQL);

   if (sig == SIGINT)
      exit(0);
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

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   int RaHashSize = 0x10000;

   if (argus->hdr.type & ARGUS_MAR)
      RaProcessManRecord (parser, argus);

   else {
      struct RaTimeHashTableHeader *hdr;
      struct ArgusHashStruct ArgusHash;
      struct ArgusTransportStruct *trans = (void *)argus->dsrs[ARGUS_TRANSPORT_INDEX];
      struct ArgusTimeObject *time = (void *)argus->dsrs[ARGUS_TIME_INDEX];
      struct timeval stvbuf, etvbuf, *stvp = &stvbuf, *etvp = &etvbuf;

      if ((time != NULL) && (trans != NULL)) {
         struct RaTimeProbesStruct *probe;
         unsigned int secs, key = trans->srcid.a_un.value;
         struct ArgusHashTableHdr *htablehdr;
         struct RaTimeStore *tstore = NULL;

         int len, i;

         if (RaGetStartTime(argus, stvp) == NULL)
            ArgusLog (LOG_ERR, "RaGetStartTime returned NULL: error\n");

         if (RaGetLastTime(argus, etvp) == NULL)
            ArgusLog (LOG_ERR, "RaGetStartTime returned NULL: error\n");

         secs = stvp->tv_sec;
             
         if (RaStartTime > stvp->tv_sec)
            RaStartTime = stvp->tv_sec;
         if (RaEndTime < etvp->tv_sec)
            RaEndTime = etvp->tv_sec;

         bzero ((char *)&ArgusHash, sizeof(ArgusHash));
         ArgusHash.len = 4;
         ArgusHash.hash = 0;
         ArgusHash.buf = &key;
         for (i = 0; i < ArgusHash.len/2; i++) {
            unsigned short value = ((unsigned short *)&key)[i];
            ArgusHash.hash += value;
         }

         if ((htablehdr = ArgusFindHashEntry(ArgusProbes->htable, &ArgusHash)) == NULL) {
            if ((probe = (struct RaTimeProbesStruct *) ArgusCalloc (RaHashSize, sizeof (struct RaTimeProbesStruct))) == NULL)
               ArgusLog (LOG_ERR, "RaTimeInit: ArgusCalloc error %s\n", strerror(errno));

            if ((probe->htable = ArgusNewHashTable(RaHashSize)) == NULL)
               ArgusLog (LOG_ERR, "RaProcessRecord: ArgusNewHashTable error %s\n", strerror(errno));

            if ((probe->rtable = (struct RaTimeHashTableStruct *) ArgusCalloc (1, sizeof (*probe->rtable))) == NULL)
               ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s\n", strerror(errno));

            probe->rtable->size =  RaHashSize;
            if ((probe->rtable->array = (struct RaTimeHashTableHeader **)
                        ArgusCalloc (RaHashSize, sizeof (struct RaTimeHashTableHeader))) == NULL)
               ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s\n", strerror(errno));

            if ((probe->queue = ArgusNewQueue()) == NULL)
               ArgusLog (LOG_ERR, "RaProcessRecord: ArgusNewQueue error %s\n", strerror(errno));

            if ((probe->tn = ArgusCopyRecordStruct(argus)) == NULL)
               ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCopyRecordStruct error %s\n", strerror(errno));

            ArgusAddHashEntry (ArgusProbes->htable, (void *)probe, &ArgusHash);
            ArgusAddToQueue(ArgusProbes->queue, &probe->qhdr, ARGUS_LOCK);

         } else
            probe = htablehdr->object;

         if ((hdr = RaTimeFindHashObject (probe->rtable, &secs, RATIME_TIMEVAL_SEC, &len)) != NULL) {
            if (secs < hdr->time.tv_sec) {
               hdr->time.tv_sec  = stvp->tv_sec;
               hdr->time.tv_usec = stvp->tv_usec;
            }
            hdr->maxoffset = argus->input->offset;

         } else {
            len = 4;
            if (!(hdr = RaTimeAddHashEntry (probe->rtable, &secs, RATIME_TIMEVAL_SEC, &len)))
               ArgusLog (LOG_ERR, "RaProcessRecord: RaTimeAddHashEntry error %s\n", strerror(errno));

            hdr->time.tv_sec  = stvp->tv_sec;
            hdr->time.tv_usec = stvp->tv_usec;

            hdr->minoffset = argus->input->offset;
            hdr->maxoffset = argus->input->offset;

            if ((tstore = (struct RaTimeStore *) ArgusCalloc (1, sizeof(*tstore))) == NULL)
               ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s\n", strerror(errno));

            tstore->htable = probe->rtable;
            tstore->object = hdr;
            ArgusAddToQueue(probe->queue, &tstore->qhdr, ARGUS_LOCK);
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessRecord (0x%x) returning\n", argus);
#endif
}

void RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns) {};
int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}

/*
void
RaMySQLInit ()
{
   my_bool reconnectbuf = 1, *reconnect = &reconnectbuf;
   char *sptr = NULL, *ptr;
   char userbuf[1024], sbuf[1024], db[1024], *dbptr = NULL;
   MYSQL_RES *mysqlRes;
   int retn = 0;

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

//    //[[username[:password]@]hostname[:port]]/database/tablename

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
         int x, thisIndex = 0;

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

   if (ArgusParser->MySQLDBEngine == NULL)
      ArgusParser->MySQLDBEngine = strdup("MyISAM");

      RaCheckedTables = 1;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaMySQLInit ()");
#endif
}
*/

void
RaMySQLInit ()
{
   my_bool reconnectbuf = 1, *reconnect = &reconnectbuf;
   unsigned int RaTableFlags = 0;
   int retn = 0, x;
   char *sptr = NULL, *ptr;
   char userbuf[1024], sbuf[1024];
   MYSQL_RES *mysqlRes;

   bzero((char *)RaTableValues, sizeof(RaTableValues));
   bzero((char *)RaExistsTableNames, sizeof(RaExistsTableNames));

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
         if (!(strncmp("mysql:", RaDatabase, 6)))
            RaDatabase = &RaDatabase[6];
   }

   if (RaDatabase == NULL)
      ArgusLog(LOG_ERR, "must specify database, use '-r mysql://user@host/db' or specify in .rarc");

//    //[[username[:password]@]hostname[:port]]/database/tablename

   if (!(strncmp ("//", RaDatabase, 2))) {
      if ((strncmp ("///", RaDatabase, 3))) {
         RaDatabase = &RaDatabase[2];
         RaHost = RaDatabase;
         if ((ptr = strchr (RaDatabase, '/')) != NULL) {
            *ptr++ = '\0';
            RaDatabase = ptr;

            if ((ptr = strchr (RaHost, '@')) != NULL) {
               RaUser = RaHost;
               *ptr++ = '\0';
               RaHost = ptr;
               if ((ptr = strchr (RaUser, ':')) != NULL) {
                  *ptr++ = '\0';
                  RaPass = ptr;
               } else {
                  RaPass = NULL;
               }
            }

            if ((ptr = strchr (RaHost, ':')) != NULL) {
               *ptr++ = '\0';
               RaPort = atoi(ptr);
            }
         } else
            RaDatabase = NULL;

      } else {
         RaDatabase = &RaDatabase[3];
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

   if (!RaCheckedTables) {
      if ((mysqlRes = mysql_list_tables(RaMySQL, NULL)) != NULL) {
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
                        ArgusDebug (4, "ArgusClientInit: table %s matches %s.\n", RaExistsTableNames[x], sbuf);
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
 
#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaMySQLInit () RaSource %s RaArchive %s", RaSource, RaArchive);
#endif
}

struct RaMySQLFileStruct {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   unsigned int fileindex;
   char *filename;
   unsigned int ostart, ostop;
};

#define RAMYSQL_SECONDTABLE_PROBE	0
#define RAMYSQL_SECONDTABLE_SECOND	1
#define RAMYSQL_SECONDTABLE_FILEINDEX	2
#define RAMYSQL_SECONDTABLE_OSTART	3
#define RAMYSQL_SECONDTABLE_OSTOP 	4

struct RaMySQLSecondsTable {
   struct ArgusQueueHeader qhdr;
   unsigned int fileindex;
   char *filename;
   unsigned int probe;
   unsigned int second;
   unsigned int ostart, ostop;
};

#define RAMYSQL_PROBETABLE_PROBE	0
#define RAMYSQL_PROBETABLE_NAME		1

struct RaMySQLProbeTable {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   char *name;
};
 

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = parser->ArgusModeList;
   unsigned int RaThisNet = 0, RaThisHost = 0;
   int RaHashSize = 0x10000;
   char buf[2048];
   int oldpflag;

   if (!(parser->RaInitialized)) {
      parser->RaInitialized++;
      parser->RaWriteOut = 0;

      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      if (ArgusParser->Sflag)
         usage();

      while (mode && mode->mode) {
         if (!(strcasecmp (mode->mode, "host"))) {
            mode = mode->nxt;
            RaThisHost = **argus_nametoaddr(mode->mode);
            RaThisNet = RaThisHost & ipaddrtonetmask(RaThisHost);
         } else
         if (!(strcasecmp (mode->mode, "net"))) {
            mode = mode->nxt;
            RaThisNet = **argus_nametoaddr(mode->mode);
         }

         mode = mode->nxt;
      }

      if ((ArgusTimeQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: ArgusNewQueue error %s", strerror(errno));

      if ((ArgusProbeQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: ArgusNewQueue error %s", strerror(errno));

      if ((ArgusFileQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: ArgusNewQueue error %s", strerror(errno));

      RaMySQLInit();

      if ((RaHost != NULL) && strcmp(RaHost, "localhost")) {
         if (ArgusParser->ais == NULL)
            ArgusParser->ais = strdup("/tmp/archive");
         sprintf (RaLocalArchBuf, "%s/%s/%s", ArgusParser->ais, RaArchive, RaHost);
         RaLocalArchive = RaLocalArchBuf;
      } else {
         RaLocalArchive = RaArchive;
      }

      if (RaLocalArchive != NULL) {
         snprintf (ArgusArchiveBuf, MAXPATHNAMELEN - 1, "%s", RaLocalArchive);
      }

      bzero(buf, sizeof(buf));

      RaStartTime = 0xFFFFFFFF;
      RaEndTime = 0;

      if (ArgusParser->tflag) {
         RaStartTime = parser->startime_t.tv_sec;
         if (parser->startime_t.tv_sec != parser->lasttime_t.tv_sec)
            RaEndTime = parser->lasttime_t.tv_sec - 1;
         else
            RaEndTime = parser->lasttime_t.tv_sec;
      }

      ArgusParser->uflag++;
      oldpflag = ArgusParser->pflag;
      ArgusParser->pflag = 0;

      ArgusParser->pflag = oldpflag;
      ArgusParser->uflag--;

      if ((ArgusProbes = (struct RaTimeProbesStruct *) ArgusCalloc (RaHashSize, sizeof (struct RaTimeProbesStruct))) == NULL)
         ArgusLog (LOG_ERR, "RaTimeInit: ArgusCalloc error %s\n", strerror(errno));

      if ((ArgusProbes->htable = ArgusNewHashTable(RaHashSize)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewHashTable error %s\n", strerror(errno));

      if ((ArgusProbes->rtable = (struct RaTimeHashTableStruct *) ArgusCalloc (1, sizeof (*ArgusProbes->rtable))) == NULL)
         ArgusLog (LOG_ERR, "RaTimeInit: ArgusCalloc error %s\n", strerror(errno));

      ArgusProbes->rtable->size =  RaHashSize;
      if ((ArgusProbes->rtable->array = (struct RaTimeHashTableHeader **)
                  ArgusCalloc (RaHashSize, sizeof (struct RaTimeHashTableHeader))) == NULL)
         ArgusLog (LOG_ERR, "RaTimeInit: ArgusCalloc error %s\n", strerror(errno));

      if ((ArgusProbes->queue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewQueue error %s\n", strerror(errno));

      if (parser->ArgusInputFileList != NULL) {
         struct ArgusInput *input = NULL, *nxtinput = NULL;

         input = parser->ArgusInputFileList;
         parser->ArgusInputFileList = NULL;

         do {
            int retn, fileindex = -1, filestatus = -1;
            char filename[2048], *endptr = NULL;

            nxtinput = (struct ArgusInput *) input->qhdr.nxt;
            input->qhdr.nxt = NULL;

            bzero (filename, sizeof(filename));

            if (realpath(input->filename, filename) != NULL) {
               free (input->filename);
               input->filename =  strdup(filename);
            }

            sprintf (buf, RaTableQueryString[0], input->filename);
            if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
               ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
            else {
               if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
                  if ((retn = mysql_num_fields(mysqlRes)) == 2) {
                     while ((row = mysql_fetch_row(mysqlRes))) {
                        if (row[0] != NULL) {
                           fileindex = strtol(row[0], &endptr, 10);
                           if (row[0] == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: id returned %s", row[0]);
                        }
                        if (row[1] != NULL) {
                           filestatus = strtol(row[1], &endptr, 10);
                           if (row[1] == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: id returned %s", row[1]);
                        }
                     }
                  }

                  mysql_free_result(mysqlRes);
               }
            }

            if (!((filestatus == 1) || (filestatus == 2))) {
               struct ArgusInput *list;
               if ((list = parser->ArgusInputFileList) != NULL) {
                  while (list->qhdr.nxt)
                     list = (struct ArgusInput *)list->qhdr.nxt;
                  list->qhdr.nxt = &input->qhdr;
               } else
                  parser->ArgusInputFileList = input;

            } else {
               ArgusLog(LOG_INFO, "file %s index %d has already been processed", input->filename, fileindex);
               if (input->filename != NULL)
                  free (input->filename);
               ArgusFree(input);
            }

            input = nxtinput;

         } while (input);
      }

      if (parser->ArgusInputFileList == NULL) 
         ArgusShutDown(SIGQUIT);
   }
}

void
usage ()
{
   extern char version[];

   fprintf (stdout, "Rasqltimeindex Version %s\n", version);
   fprintf (stdout, "usage: %s -r filename -w mysql://[user[:pass]@]host[:port]/db\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s -R directory -w mysql://[user[:pass]@]host[:port]/db\n", ArgusParser->ArgusProgramName);

#ifdef ARGUSDEBUG
   fprintf (stdout, "options: -D debuglevel                            print debug information.\n");
   fprintf (stdout, "         -r filename                              read from file.\n");
#else
   fprintf (stdout, "options: -r filename                              read from file.\n");
#endif
   fprintf (stdout, "         -R directory                             read files from complete directory tree.\n");
   fprintf (stdout, "         -v                                       verbose mode\n");
   fprintf (stdout, "         -w mysql://[user[:pass]@]host[:port]/db  write indexes to db database\n");
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
RaTimeSortRoutine (const void *void1, const void *void2)
{
   int retn = 0;
   struct RaTimeStore *store1 = *(struct RaTimeStore **)void1;
   struct RaTimeStore *store2 = *(struct RaTimeStore **)void2;
   struct RaTimeHashTableHeader *hdr1, *hdr2;

   if (store1 && store2) {
      hdr1 = (struct RaTimeHashTableHeader *)store1->object;
      hdr2 = (struct RaTimeHashTableHeader *)store2->object;
      retn = hdr1->time.tv_sec - hdr2->time.tv_sec;
   }

   return (retn);
}


void
RaTimeSortQueue (struct ArgusQueueStruct *queue)
{
   int i = 0, cnt = queue->count;
   struct ArgusQueueHeader *qhdr;

   if (queue->array != NULL) {
      ArgusFree(queue->array);
      queue->array = NULL;
   }

   if (cnt > 0) {
      if ((queue->array = (struct ArgusQueueHeader **)
                  ArgusCalloc(sizeof(struct ArgusQueueHeader *), cnt + 1)) != NULL) {
         qhdr = queue->start;
         do {
            queue->array[i] = qhdr;
            qhdr = qhdr->nxt;
            i++;
         } while (qhdr != queue->start);

         qsort ((char *) queue->array, i, sizeof (struct ArgusQueueHeader *), RaTimeSortRoutine);

      } else
         ArgusLog (LOG_ERR, "RaSortQueue: ArgusCalloc(%d, %d) %s\n", sizeof(struct ArgusRecord *),
                                                                     cnt, strerror(errno));
   }
#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaSortQueue(0x%x) returned\n", queue);
#endif
}


unsigned int
RaTimeCalcHash (struct RaTimeHashTableStruct *table, void *obj, int type, int *len)
{
   u_char buf[MAX_OBJ_SIZE];
   unsigned int retn = 0;

   *len = 0;
   switch (type) {
      case RATIME_PROBE:
          *len = 4;
          break;

      case RATIME_TIMEVAL:
          *len = 8;
          break;

      case RATIME_TIMEVAL_SEC:
      case RATIME_TIMEVAL_USEC:
          *len = 4;
          break;

      default:
          break;
   }

   if (table && *len) {
      bzero (buf, sizeof buf);

      if (table->size <= 0x100) {
         unsigned char hash = 0, *ptr = (unsigned char *) buf;
         int i, nitems = *len;

         bcopy ((char *) obj, &buf, *len);

         for (i = 0; i < nitems; i++)
            hash += *ptr++;

         retn = hash;

      } else
      if (table->size <= 0x10000) {
         unsigned short hash = 0, *ptr = (unsigned short *) buf;
         int i, nitems = (*len / sizeof(unsigned short)) + 2;

         bcopy ((char *) obj, &buf[1], *len);

         for (i = 0; i < nitems; i++)
            hash += *ptr++;

         retn = hash;

      } else {
         unsigned int hash = 0, *ptr = (unsigned int *) buf;
         int i, nitems = (*len /sizeof(unsigned int)) + 2;

         bcopy ((char *) obj, &buf[3], *len);

         for (i = 0; i < nitems; i++)
            hash += *ptr++;

         retn = hash;
      }

      retn %= table->size;
   }

   return (retn);
}



struct RaTimeHashTableHeader *
RaTimeFindHashObject (struct RaTimeHashTableStruct *table, void *obj, int type, int *len)
{
   struct RaTimeHashTableHeader *retn = NULL, *head = NULL, *target;
   int RaTimeHash = 0;

   RaTimeHash = RaTimeCalcHash (table, obj, type, len);

   if ((target = table->array[RaTimeHash]) != NULL) {
      head = target;
      do {
         if ((type == target->type) && (*len == target->len)) {
            if (!(bcmp ((char *) obj, (char *) target->obj, *len))) {
               retn = target;
               break;
            }
         }

         target = target->nxt;
      } while (target != head);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaTimeFindHashEntry () returning 0x%x RaTimeHash %d\n", retn, RaTimeHash);
#endif
 
   return (retn);
}


struct RaTimeHashTableHeader *
RaTimeAddHashEntry (struct RaTimeHashTableStruct *table, void *oid, int type, int *len)
{
   struct RaTimeHashTableHeader *retn = NULL, *start = NULL;
   int RaTimeHash = 0;

   if ((retn = (struct RaTimeHashTableHeader *) ArgusCalloc (1, sizeof (struct RaTimeHashTableHeader))) != NULL) {
      RaTimeHash = RaTimeCalcHash (table, oid, type, len);

      retn->hash = RaTimeHash;
      retn->type = type;
      retn->len  = *len;

      if ((retn->obj = (void *) ArgusCalloc (1, *len)) == NULL)
         ArgusLog (LOG_ERR, "RaTimeAddHashEntry: ArgusCalloc error %s\n", strerror(errno));
      else
         bcopy ((char *) oid, (char *)retn->obj, *len);
      
      if ((start = table->array[RaTimeHash % table->size]) != NULL) {
         retn->nxt = start;
         retn->prv = start->prv;
         retn->prv->nxt = retn;
         retn->nxt->prv = retn;
      } else
         retn->prv = retn->nxt = retn;

      table->array[RaTimeHash % table->size] = retn;
      table->count++;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaTimeAddHashEntry (0x%x, 0x%x, %d, %d) returning 0x%x\n", table, oid, type, *len, retn);
#endif

   return (retn);
}

 
void
RaTimeRemoveHashEntry (struct RaTimeHashTableStruct *table, struct RaTimeHashTableHeader *htblhdr)
{
   unsigned short hash = htblhdr->hash;

   htblhdr->prv->nxt = htblhdr->nxt;
   htblhdr->nxt->prv = htblhdr->prv;

   if (htblhdr == table->array[hash % table->size]) {
      if (htblhdr == htblhdr->nxt)
         table->array[hash % table->size] = NULL;
      else
         table->array[hash % table->size] = htblhdr->nxt;
   }

   ArgusFree (htblhdr);
   table->count--;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaTimeRemoveHashEntry (0x%x) returning\n", htblhdr);
#endif
}


void
RaTimeCleanHashTable (struct RaTimeHashTableStruct *thisHashTable)
{
   struct RaTimeHashTableHeader *hdr = NULL;
   int i;

   for (i = 0; i < thisHashTable->size; i++)
      while ((hdr = (struct RaTimeHashTableHeader *) thisHashTable->array[i]) != NULL)
         RaTimeRemoveHashEntry (thisHashTable, hdr);

#ifdef ARGUSDEBUG
   ArgusDebug (4, "RaCleanHashTable (0x%x) returning\n", thisHashTable);
#endif
}


/* MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#include <argus/global.h>
#include <argus/md5.h>

/* Constants for MD5Transform routine.
 */

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5Transform (UINT4 [4], unsigned char [64]);
static void Encode (unsigned char *, UINT4 *, unsigned int);
static void Decode (UINT4 *, unsigned char *, unsigned int);
static void MD5_memcpy (POINTER, POINTER, unsigned int);
static void MD5_memset (POINTER, int, unsigned int);

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void MD5Init (context)
MD5_CTX *context;                                        /* context */
{
  context->count[0] = context->count[1] = 0;
  /* Load magic initialization constants.
*/
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */
void MD5Update (context, input, inputLen)
MD5_CTX *context;                                        /* context */
unsigned char *input;                                /* input block */
unsigned int inputLen;                     /* length of input block */
{
  unsigned int i, index, partLen;

  /* Compute number of bytes mod 64 */
  index = (unsigned int)((context->count[0] >> 3) & 0x3F);

  /* Update number of bits */
  if ((context->count[0] += ((UINT4)inputLen << 3))
   < ((UINT4)inputLen << 3))
 context->count[1]++;
  context->count[1] += ((UINT4)inputLen >> 29);

  partLen = 64 - index;

  /* Transform as many times as possible.
*/
  if (inputLen >= partLen) {
 MD5_memcpy
   ((POINTER)&context->buffer[index], (POINTER)input, partLen);
 MD5Transform (context->state, context->buffer);

 for (i = partLen; i + 63 < inputLen; i += 64)
   MD5Transform (context->state, &input[i]);

 index = 0;
  }
  else
 i = 0;

  /* Buffer remaining input */
  MD5_memcpy
 ((POINTER)&context->buffer[index], (POINTER)&input[i],
  inputLen-i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
void MD5Final (digest, context)
unsigned char digest[16];                         /* message digest */
MD5_CTX *context;                                       /* context */
{
  unsigned char bits[8];
  unsigned int index, padLen;

  /* Save number of bits */
  Encode (bits, context->count, 8);

  /* Pad out to 56 mod 64.
*/
  index = (unsigned int)((context->count[0] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  MD5Update (context, PADDING, padLen);

  /* Append length (before padding) */
  MD5Update (context, bits, 8);

  /* Store state in digest */
  Encode (digest, context->state, 16);

  /* Zeroize sensitive information.
*/
  MD5_memset ((POINTER)context, 0, sizeof (*context));
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void MD5Transform (state, block)
UINT4 state[4];
unsigned char block[64];
{
  UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  Decode (x, block, 64);

  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
  FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
  FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
  FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
  FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
  FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
  FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
  FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
  FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
  FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
  FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
  FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
  FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
  FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
  FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
  FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

 /* Round 2 */
  GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
  GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
  GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
  GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
  GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
  GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
  GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
  GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
  GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
  GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
  GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
  GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
  GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
  GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
  GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
  GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

  /* Round 3 */
  HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
  HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
  HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
  HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
  HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
  HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
  HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
  HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
  HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
  HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
  HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
  HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
  HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
  HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
  HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
  HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

  /* Round 4 */
  II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
  II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
  II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
  II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
  II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
  II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
  II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
  II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
  II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
  II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
  II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
  II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
  II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
  II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
  II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
  II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

  /* Zeroize sensitive information.
 */
  MD5_memset ((POINTER)x, 0, sizeof (x));
}

/* Encodes input (UINT4) into output (unsigned char). Assumes len is
  a multiple of 4.
 */
static void Encode (output, input, len)
unsigned char *output;
UINT4 *input;
unsigned int len;
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4) {
 output[j] = (unsigned char)(input[i] & 0xff);
 output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
 output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
 output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
  }
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
  a multiple of 4.
 */
static void Decode (output, input, len)
UINT4 *output;
unsigned char *input;
unsigned int len;
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
 output[i] = ((UINT4)input[j]) | (((UINT4)input[j+1]) << 8) |
   (((UINT4)input[j+2]) << 16) | (((UINT4)input[j+3]) << 24);
}

/* Note: Replace "for loop" with standard memcpy if possible.
 */

static void MD5_memcpy (output, input, len)
POINTER output;
POINTER input;
unsigned int len;
{
  unsigned int i;

  for (i = 0; i < len; i++)
 output[i] = input[i];
}

/* Note: Replace "for loop" with standard memset if possible.
 */
static void MD5_memset (output, value, len)
POINTER output;
int value;
unsigned int len;
{
  unsigned int i;

  for (i = 0; i < len; i++)
 ((char *)output)[i] = (char)value;
}


/* MDDRIVER.C - test driver for MD2, MD4 and MD5
 */

/* Copyright (C) 1990-2, RSA Data Security, Inc. Created 1990. All
rights reserved.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/* The following makes MD default to MD5 if it has not already been
  defined with C compiler flags.
 */

#ifndef MD
#define MD 5
#endif

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#if MD == 2
#include "md2.h"
#endif
#if MD == 4
#include "md4.h"
#endif
#if MD == 5
#endif


#if MD == 2
#define MD_CTX MD2_CTX
#define MDInit MD2Init
#define MDUpdate MD2Update
#define MDFinal MD2Final
#endif
#if MD == 4
#define MD_CTX MD4_CTX
#define MDInit MD4Init
#define MDUpdate MD4Update
#define MDFinal MD4Final
#endif
#if MD == 5
#define MD_CTX MD5_CTX
#define MDInit MD5Init
#define MDUpdate MD5Update
#define MDFinal MD5Final
#endif

/* 
   Digests a file and prints the result.
 */


char MDFileBuf[128];

char *
MDFile (char *filename)
{
  unsigned char buffer[1024], digest[16];
  FILE *file;
  MD_CTX context;
  int len, i;

  bzero (MDFileBuf, sizeof(MDFileBuf));

  if ((file = fopen (filename, "rb")) == NULL)
     printf ("%s can't be opened\n", filename);

  else {
     MDInit (&context);
     while ((len = fread (buffer, 1, 1024, file)) > 0)
       MDUpdate (&context, buffer, len);
     MDFinal (digest, &context);

     fclose (file);

     for (i = 0; i < 16; i++)
        sprintf (&MDFileBuf[strlen(MDFileBuf)], "%02x", digest[i]);
  }

  return(MDFileBuf);
}


