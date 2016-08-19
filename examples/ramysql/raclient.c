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
 *  rasqlinsert  -  mysql database table management system.  uses ratop's
 *                  raclient.c based record processing engine.
 *
 *                  ramysql.c handles the database routines needed to
 *                  maintain the current data view in the database.
 *
 *  Author: Carter Bullard carter@qosient.com
 */

#define ARGUS_HISTORY
#define ARGUS_READLINE

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <argus_compat.h>
#include <sys/wait.h>

#define ARGUS_PROCESS_NOW	0x01

#define ARGUS_RECORD_MODIFIED   0x0100
#define ARGUS_RECORD_CLEARED    0x0200

#define ARGUS_SQL_INSERT        0x0100000
#define ARGUS_SQL_UPDATE        0x0200000
#define ARGUS_SQL_DELETE        0x0400000

#define ARGUS_SQL_STATUS        (ARGUS_SQL_INSERT | ARGUS_SQL_UPDATE | ARGUS_SQL_DELETE)

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <rasqlinsert.h>
#include <rabins.h>

#if defined(HAVE_ZLIB_H)
#include <zlib.h>
#endif

#if defined(ARGUS_MYSQL)
#include <mysql.h>

char *ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, int, int);

extern char RaSQLSaveTable[];
extern char *RaSQLCurrentTable;

extern int RaSQLDBDeletes;
extern int ArgusDropTable;
extern int ArgusCreateTable;
extern int RaSQLCacheDB;

extern int ArgusTotalSQLSearches;
extern int ArgusTotalSQLUpdates;
extern int ArgusTotalSQLWrites;

extern int ArgusSOptionRecord;

extern pthread_mutex_t RaMySQLlock;
extern MYSQL *RaMySQL;


#endif

int ArgusCreateSQLSaveTable(char *, char *);
char *ArgusCreateSQLSaveTableName (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);

void ArgusThreadsInit(pthread_attr_t *);

struct RaAddressStruct *RaFindAddress (struct ArgusParserStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);
void RaInsertAddressTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *);

extern int ArgusCloseDown;

int ArgusProcessQueue (struct ArgusQueueStruct *, int status);
void ArgusGetInterfaceAddresses(struct ArgusParserStruct *);
int ArgusCorrelateRecord (struct ArgusRecordStruct *);
int ArgusCorrelateQueue (struct ArgusQueueStruct *);

 
void
ArgusThreadsInit(pthread_attr_t *attr)
{
#if defined(ARGUS_THREADS)
#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN)
   int thread_policy;
   struct sched_param thread_param;
#if defined(HAVE_SCHED_GET_PRIORITY_MIN)
   int rr_min_priority, rr_max_priority;
#endif
#endif
   int status;
   size_t stacksize;
#endif

#if defined(ARGUS_THREADS)
   if ((status = pthread_attr_init(attr)) != 0)
      ArgusLog (LOG_ERR, "pthreads init error");

#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN)
   if ((status = pthread_attr_getschedpolicy(attr, &thread_policy)) != 0)
      ArgusLog (LOG_ERR, "pthreads get policy error");
   if ((status = pthread_attr_getschedparam(attr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads get sched params error");
   if ((status = pthread_attr_setschedpolicy(attr, SCHED_RR)) != 0)
      ArgusLog (LOG_ERR, "pthreads set SCHED_RR error");

#if defined(HAVE_SCHED_GET_PRIORITY_MIN)
   if ((rr_min_priority = sched_get_priority_min(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority min error");
   if ((rr_max_priority = sched_get_priority_max(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority max error");

   thread_param.sched_priority = (rr_max_priority + rr_min_priority)/2 + 1;

   if (thread_param.sched_priority > rr_max_priority)
      thread_param.sched_priority = rr_max_priority;
   if (thread_param.sched_priority < (rr_max_priority - 8))
      thread_param.sched_priority = rr_max_priority - 8;

   if ((status = pthread_attr_setschedparam(attr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads set sched param error");
#endif
#else
   pthread_attr_setschedpolicy(attr, SCHED_RR);
#endif

#if defined(_POSIX_THREAD_ATTR_STACKSIZE)
#define ARGUS_MIN_STACKSIZE     0x1000000

   if (pthread_attr_getstacksize(attr, &stacksize))
      ArgusLog (LOG_ERR, "pthreads get stacksize error");

   if (stacksize < ARGUS_MIN_STACKSIZE) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "setting stacksize from %d to %d", stacksize, ARGUS_MIN_STACKSIZE);
#endif
      if (pthread_attr_setstacksize(attr, ARGUS_MIN_STACKSIZE))
         ArgusLog (LOG_ERR, "pthreads set stacksize error");
   }
#endif

   pthread_attr_setdetachstate(attr, PTHREAD_CREATE_JOINABLE);
#endif
}


void *
ArgusProcessData (void *arg)
{
#if defined(ARGUS_THREADS)
   int done = 0;
#endif
   struct ArgusParserStruct *parser = ArgusParser;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusProcessData() starting");
#endif

#if defined(ARGUS_THREADS)
   while (!ArgusCloseDown && !done) {
      if (parser->RaTasksToDo) {
         struct ArgusInput *input = NULL, *file =  NULL;
         int hosts = 0;
         char sbuf[1024];

         sprintf (sbuf, "RaCursesLoop() Processing.");
         ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);

         RaCursesStartTime.tv_sec  = 0;
         RaCursesStartTime.tv_usec = 0;
         RaCursesStopTime.tv_sec   = 0;
         RaCursesStopTime.tv_usec  = 0;

// Process the input files first

         if ((!(parser->status & ARGUS_FILE_LIST_PROCESSED)) && ((file = parser->ArgusInputFileList) != NULL)) {
            while (file && parser->eNflag) {
               if (strcmp (file->filename, "-")) {
                  if (file->fd < 0) {
                     if ((file->file = fopen(file->filename, "r")) == NULL) {
                        sprintf (sbuf, "open '%s': %s", file->filename, strerror(errno));
                        ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);
                     }

                  } else {
                     fseek(file->file, 0, SEEK_SET);
                  }

                  if ((file->file != NULL) && ((ArgusReadConnection (parser, file, ARGUS_FILE)) >= 0)) {
                     parser->ArgusTotalMarRecords++;
                     parser->ArgusTotalRecords++;

                     if (parser->RaPollMode) {
                         ArgusHandleRecord (parser, file, &file->ArgusInitCon, &parser->ArgusFilterCode);
                     } else {
                        if (file->ostart != -1) {
                           file->offset = file->ostart;
                           if (fseek(file->file, file->offset, SEEK_SET) >= 0)
                              ArgusReadFileStream(parser, file);
                        } else
                           ArgusReadFileStream(parser, file);
                     }

                     sprintf (sbuf, "RaCursesLoop() Processing Input File %s done.", file->filename);
                     ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);

                  } else {
                     file->fd = -1;
                     sprintf (sbuf, "ArgusReadConnection '%s': %s", file->filename, strerror(errno));
                     ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
                  }

                  if (file->file != NULL)
                     ArgusCloseInput(parser, file);

               } else {
                  file->file = stdin;
                  file->ostart = -1;
                  file->ostop = -1;

                  if (((ArgusReadConnection (parser, file, ARGUS_FILE)) >= 0)) {
                     parser->ArgusTotalMarRecords++;
                     parser->ArgusTotalRecords++;
                     fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);
                     ArgusReadFileStream(parser, file);
                  }
               }

               RaArgusInputComplete(file);
               file = (struct ArgusInput *)file->qhdr.nxt;
            }

            parser->status |= ARGUS_FILE_LIST_PROCESSED;
         }

// Then process the realtime stream input, if any

         if (parser->Sflag) {
            if (parser->ArgusRemoteHosts && (parser->ArgusRemoteHosts->count > 0)) {
               struct ArgusQueueStruct *tqueue = ArgusNewQueue();
               int flags;

#if defined(ARGUS_THREADS)
               if (parser->ArgusReliableConnection) {
                  if (parser->ArgusRemoteHosts && (hosts = parser->ArgusRemoteHosts->count)) {
                     if ((pthread_create(&parser->remote, NULL, ArgusConnectRemotes, parser->ArgusRemoteHosts)) != 0)
                        ArgusLog (LOG_ERR, "ArgusNewOutput() pthread_create error %s\n", strerror(errno));
                  }

               } else {
#else
                  {
#endif
                  while ((input = (void *)ArgusPopQueue(parser->ArgusRemoteHosts, ARGUS_LOCK)) != NULL) {
                     if ((input->fd = ArgusGetServerSocket (input, 5)) >= 0) {
                        if ((ArgusReadConnection (parser, input, ARGUS_SOCKET)) >= 0) {
                           parser->ArgusTotalMarRecords++;
                           parser->ArgusTotalRecords++;

                           if ((flags = fcntl(input->fd, F_GETFL, 0L)) < 0)
                              ArgusLog (LOG_ERR, "ArgusConnectRemote: fcntl error %s", strerror(errno));

                           if (fcntl(input->fd, F_SETFL, flags | O_NONBLOCK) < 0)
                              ArgusLog (LOG_ERR, "ArgusConnectRemote: fcntl error %s", strerror(errno));

                           if (parser->RaPollMode)
                              ArgusHandleRecord (parser, input, &input->ArgusInitCon, &parser->ArgusFilterCode);

                           ArgusAddToQueue(parser->ArgusActiveHosts, &input->qhdr, ARGUS_LOCK);
                           parser->RaTasksToDo++;
                        } else
                           ArgusAddToQueue(tqueue, &input->qhdr, ARGUS_LOCK);
                     } else
                        ArgusAddToQueue(tqueue, &input->qhdr, ARGUS_LOCK);
#if !defined(ARGUS_THREADS)
                  }
#else
                  }
#endif
               }

               while ((input = (void *)ArgusPopQueue(tqueue, ARGUS_LOCK)) != NULL)
                  ArgusAddToQueue(parser->ArgusRemoteHosts, &input->qhdr, ARGUS_LOCK);

               ArgusDeleteQueue(tqueue);
            }

         } else {
#if defined(ARGUS_THREADS)
            parser->RaDonePending++;
            done++;
#endif
         }

         if (parser->ArgusReliableConnection || parser->ArgusActiveHosts)
            if (parser->ArgusActiveHosts->count)
               ArgusReadStream(parser, parser->ArgusActiveHosts);

         parser->RaTasksToDo = 0;

      } else {
         struct timespec ts = {0, 25000000};
         gettimeofday (&parser->ArgusCurrentTime, 0L);
         nanosleep (&ts, NULL);

         if (parser->ArgusActiveHosts && parser->ArgusActiveHosts->count)
            parser->RaTasksToDo = 1;
      }

      ArgusClientTimeout ();
   }

   {
      int flushCnt = 0, queueCnt = 0;
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessData: flushing sql queues\n");
#endif
      struct ArgusQueueStruct *queue = RaOutputProcess->queue;
      extern int   RaSQLUpdateDB;

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock);
#endif
#if defined(ARGUS_MYSQL)

      if (ArgusParser->RaCursesMode)
         RaClientSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);
      else
         RaClientSortQueue(ArgusSorter, queue, ARGUS_NOLOCK | ARGUS_NOSORT);

      if (RaSQLUpdateDB && RaSQLCurrentTable) {
         char *sbuf = calloc(1, MAXBUFFERLEN);
         int i;

         if (queue->array != NULL) {
            queueCnt = queue->count;
            for (i = 0; i < queueCnt; i++) {
               struct ArgusRecordStruct *ns = (struct ArgusRecordStruct *)queue->array[i];

               if (ns && (ns->status & ARGUS_RECORD_MODIFIED)) {
                  ArgusScheduleSQLQuery (parser, parser->ArgusAggregator, ns, sbuf, MAXBUFFERLEN, ARGUS_STATUS);
                  ns->status &= ~ARGUS_RECORD_MODIFIED;
                  flushCnt++;
               }
            }
         }
         free(sbuf);
      }
#endif
#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock);
#endif
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusProcessData: flushed %d records\n", flushCnt);
#endif
   }

   RaParseComplete(0);
   pthread_exit(NULL);
#endif

   return (arg);
}


extern pthread_mutex_t RaCursesLock;


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   time_t tsec = ArgusParser->ArgusRealTime.tv_sec;
   struct ArgusAdjustStruct *nadp = NULL;
   struct ArgusInput *input = NULL;
   struct ArgusModeStruct *mode;
   char outputfile[MAXSTRLEN];
   int i = 0, size = 1;

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&RaCursesLock, NULL);
#endif

   if (parser != NULL) {
      outputfile[0] = '\0';
      parser->RaWriteOut = 1;

      if (!(parser->RaInitialized)) {

/*
      the library sets signal handling routines for 
      SIGHUP, SIGTERM, SIGQUIT, SIGINT, SIGUSR1, and SIGUSR2.
      SIGHUP doesn't do anything, SIGTERM, SIGQUIT, and SIGINT
      call the user supplied RaParseComplete().  SIGUSR1 and
      SIGUSR2 modify the debug level so if compiled with
      ARGUS_DEBUG support, programs can start generating 
      debug information.  USR1 increments by 1, USR2 sets
      it back to zero.
   
*/
         (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
         (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
         (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
         (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

         (void) signal (SIGWINCH,SIG_IGN);
         (void) signal (SIGPIPE, SIG_IGN);
         (void) signal (SIGALRM, SIG_IGN);

         parser->timeout.tv_sec  = 60;
         parser->timeout.tv_usec = 0;

         parser->RaClientTimeout.tv_sec  = 0;
         parser->RaClientTimeout.tv_usec = 10000;

         parser->RaInitialized++;
         parser->ArgusPrintXml = 0;

         parser->NonBlockingDNS = 1;
         parser->RaCumulativeMerge = 1;

         if ((parser->timeout.tv_sec == -1) && (parser->timeout.tv_sec == 0)) {
            parser->timeout.tv_sec  = 60;
            parser->timeout.tv_usec = 0;
         }

         if (parser->ArgusInputFileList != NULL) {
            parser->RaTasksToDo = 1;
            if (parser->ArgusRemoteHosts) {
               if ((input = (void *)parser->ArgusRemoteHosts->start) == NULL) {
                  parser->timeout.tv_sec  = 0;
                  parser->timeout.tv_usec = 0;
               }
            }
         }

         if (parser->ArgusFlowModelFile) {
            if ((parser->ArgusAggregator = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL)) == NULL)
               ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseAggregator error");
         } else
            parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR);

         if (parser->ArgusRemoteHosts)
            if ((input = (void *)parser->ArgusRemoteHosts->start) != NULL)
               parser->RaTasksToDo = 1;

         ArgusEventAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR);

         if ((ArgusInput = (struct ArgusInput *) ArgusCalloc (1, sizeof(struct ArgusInput))) != NULL) {
            ArgusInput->ArgusOriginal = (struct ArgusRecord *)&ArgusInput->ArgusOriginalBuffer;
            ArgusInput->fd = -1;
         }

         if (parser->Hstr != NULL)
            ArgusHistoMetricParse(parser, parser->ArgusAggregator);

         if ((ArgusModelerQueue = ArgusNewQueue()) == NULL)
            ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

         if ((ArgusProbeQueue = ArgusNewQueue()) == NULL)
            ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

         if ((ArgusFileQueue = ArgusNewQueue()) == NULL)
            ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

         if ((ArgusSQLQueryList = ArgusNewList()) == NULL)
            ArgusLog(LOG_ERR, "ArgusClientInit: ArgusNewList error %s", strerror(errno));

         if ((ArgusSQLInsertQueryList = ArgusNewList()) == NULL)
            ArgusLog(LOG_ERR, "ArgusClientInit: ArgusNewList error %s", strerror(errno));

         if ((ArgusSQLSelectQueryList = ArgusNewList()) == NULL)
            ArgusLog(LOG_ERR, "ArgusClientInit: ArgusNewList error %s", strerror(errno));

         if ((ArgusSQLUpdateQueryList = ArgusNewList()) == NULL)
            ArgusLog(LOG_ERR, "ArgusClientInit: ArgusNewList error %s", strerror(errno));

         if ((RaOutputProcess = RaCursesNewProcess(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: RaCursesNewProcess error");

         if ((RaEventProcess = RaCursesNewProcess(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: RaCursesNewProcess error");

         if ((RaHistoryProcess = RaCursesNewProcess(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: RaCursesNewProcess error");

         if (parser->vflag)
            ArgusReverseSortDir++;

         if ((ArgusSorter = ArgusNewSorter(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewSorter error %s", strerror(errno));

         ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortAlgorithmTable[ARGUSSORTPKTSCOUNT];

         if ((parser->RaBinProcess = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*parser->RaBinProcess))) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

#if defined(ARGUS_THREADS)
         pthread_mutex_init(&parser->RaBinProcess->lock, NULL);
#endif
         nadp = &parser->RaBinProcess->nadp;

         nadp->mode   = -1;
         nadp->modify =  0;
         nadp->slen   =  2;
    
         if (parser->aflag)
            nadp->slen = parser->aflag;

         if ((mode = parser->ArgusModeList) != NULL) {
            int i, x, ind;

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
                        // purposefully drop through
                     }

                     case ARGUSSPLITTIME: /* "%d[yMwdhms] */
                        if (ArgusParser->tflag)
                           tsec = ArgusParser->startime_t.tv_sec;

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
                                       localtime_r(&tsec, &nadp->RaStartTmStruct);
                                       nadp->RaStartTmStruct.tm_sec = 0;
                                       nadp->RaStartTmStruct.tm_min = 0;
                                       nadp->RaStartTmStruct.tm_hour = 0;
                                       nadp->RaStartTmStruct.tm_mday = 1;
                                       nadp->RaStartTmStruct.tm_mon = 0;
//                                     nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
                                       nadp->size = nadp->value*3600.0*24.0*7.0*52.0*1000000LL;
                                       break;

                                    case 'M':
                                       nadp->qual = ARGUSSPLITMONTH; 
                                       localtime_r(&tsec, &nadp->RaStartTmStruct);
                                       nadp->RaStartTmStruct.tm_sec = 0;
                                       nadp->RaStartTmStruct.tm_min = 0;
                                       nadp->RaStartTmStruct.tm_hour = 0;
                                       nadp->RaStartTmStruct.tm_mday = 1;
                                       nadp->RaStartTmStruct.tm_mon = 0;
//                                     nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
                                       nadp->size = nadp->value*3600.0*24.0*7.0*4.0*1000000LL;
                                       break;

                                    case 'w':
                                       nadp->qual = ARGUSSPLITWEEK;  
                                       localtime_r(&tsec, &nadp->RaStartTmStruct);
                                       nadp->RaStartTmStruct.tm_sec = 0;
                                       nadp->RaStartTmStruct.tm_min = 0;
                                       nadp->RaStartTmStruct.tm_hour = 0;
                                       nadp->RaStartTmStruct.tm_mday = 1;
                                       nadp->RaStartTmStruct.tm_mon = 0;
//                                     nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
                                       nadp->size = nadp->value*3600.0*24.0*7.0*1000000LL;
                                       break;

                                    case 'd':
                                       nadp->qual = ARGUSSPLITDAY;   
                                       localtime_r(&tsec, &nadp->RaStartTmStruct);
                                       nadp->RaStartTmStruct.tm_sec = 0;
                                       nadp->RaStartTmStruct.tm_min = 0;
                                       nadp->RaStartTmStruct.tm_hour = 0;
//                                     nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
                                       nadp->size = nadp->value*3600.0*24.0*1000000LL;
                                       break;

                                    case 'h':
                                       nadp->qual = ARGUSSPLITHOUR;  
                                       localtime_r(&tsec, &nadp->RaStartTmStruct);
                                       nadp->RaStartTmStruct.tm_sec = 0;
                                       nadp->RaStartTmStruct.tm_min = 0;
//                                     nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
                                       nadp->size = nadp->value*3600.0*1000000LL;
                                       break;

                                    case 'm': {
                                       nadp->qual = ARGUSSPLITMINUTE;
                                       localtime_r(&tsec, &nadp->RaStartTmStruct);
                                       nadp->RaStartTmStruct.tm_sec = 0;
//                                     nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
                                       nadp->size = nadp->value*60.0*1000000LL;
                                       break;
                                    }

                                     default: 
                                    case 's': {
                                       long long val = tsec / nadp->value;
                                       nadp->qual = ARGUSSPLITSECOND;
                                       tsec = val * nadp->value;
                                       localtime_r(&tsec, &nadp->RaStartTmStruct);
//                                     nadp->start.tv_sec = tsec;
                                       nadp->size = nadp->value * 1000000LL;
                                       break;
                                    }
                                 }
                              }
                           }
                           if (mptr != NULL)
                               mode->mode = mptr;
                        }

                        nadp->modify = 1;

                        if (ind == ARGUSSPLITRATE) {
                           /* need to set the flow idle timeout value to be equal to or
                              just a bit bigger than (nadp->count * size) */

                           ArgusParser->timeout.tv_sec  = (nadp->count * size);
                           ArgusParser->timeout.tv_usec = 0;
                        }

                        parser->RaBinProcess->rtime.tv_sec = tsec;

                        if (RaCursesRealTime)
                           nadp->start.tv_sec = 0;

                        if (ArgusSorter->ArgusSortAlgorithms[0] == NULL) {
                           ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;
                           ArgusSorter->ArgusSortAlgorithms[1] = NULL;
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
                        ArgusSorter->ArgusSortAlgorithms[0] = NULL;
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
                  if (!(strncasecmp (mode->mode, "oui", 3)))
                     parser->ArgusPrintEthernetVendors++;
                  else
                  if (!(strncasecmp (mode->mode, "nocorrect", 9))) {
                     if (parser->ArgusAggregator && (parser->ArgusAggregator->correct != NULL)) {
                        free(parser->ArgusAggregator->correct);
                        parser->ArgusAggregator->correct = NULL;
                     }
                  } else
                  if (!(strncasecmp (mode->mode, "correct", 7))) {
                     if (parser->ArgusAggregator && (parser->ArgusAggregator->correct != NULL))
                        parser->ArgusAggregator->correct = strdup("yes");;
                  } else
                  if (!(strncasecmp (mode->mode, "preserve", 8))) {
                     if (parser->ArgusAggregator && (parser->ArgusAggregator->pres != NULL))
                        free(parser->ArgusAggregator->pres);
                     parser->ArgusAggregator->pres = strdup("yes");
                  } else
                  if (!(strncasecmp (mode->mode, "nopreserve", 10))) {
                     if (parser->ArgusAggregator && (parser->ArgusAggregator->pres != NULL))
                        free(parser->ArgusAggregator->pres);
                     parser->ArgusAggregator->pres = NULL;
                  } else
                  if (!(strncasecmp (mode->mode, "curses", 6))) {
                     ArgusCursesEnabled = 1;
                  } else
                  if (!(strncasecmp (mode->mode, "nocurses", 8))) {
                     ArgusCursesEnabled = 0;
                  } else
                  if (!(strncasecmp (mode->mode, "cache", 5))) {
                     RaSQLCacheDB = 1;
                     RaSQLDBDeletes = 0;
                  } else
                  if (!(strncasecmp (mode->mode, "drop", 6))) {
                     ArgusDropTable = 1;
                  } else
                  if (!(strncasecmp (mode->mode, "mysql_engine=", 13))) {
                     if (parser->MySQLDBEngine != NULL)
                        free (parser->MySQLDBEngine);
                     parser->MySQLDBEngine = strdup(&mode->mode[13]);
                  } else
                  if (!(strncasecmp (mode->mode, "rmon", 4))) {
                     parser->RaMonMode++;
                     if (parser->ArgusAggregator && (parser->ArgusAggregator->correct != NULL)) {
                        free(parser->ArgusAggregator->correct);
                        parser->ArgusAggregator->correct = NULL;
                     }
                  } else
                  if (!(strncasecmp (mode->mode, "nomerge", 7))) {
                     parser->RaCumulativeMerge = 0;
                  } else
                  if (!(strncasecmp (mode->mode, "net", 3))) {
                     parser->RaMpcNetMode++;
                     parser->RaMpcProbeMode = 0;
                  } else
                  if (!(strncasecmp (mode->mode, "probe", 5))) {
                     parser->RaMpcProbeMode++;
                     parser->RaMpcNetMode = 0;
                  } else
                  if (!(strncasecmp (mode->mode, "merge", 5))) {
                     parser->RaCumulativeMerge = 1;
                  } else {
                     for (x = 0, i = 0; x < MAX_SORT_ALG_TYPES; x++) {
                        if (!strncmp (ArgusSortKeyWords[x], mode->mode, strlen(ArgusSortKeyWords[x]))) {
                           ArgusSorter->ArgusSortAlgorithms[i++] = ArgusSortAlgorithmTable[x];
                           break;
                        }
                     }
                  }
               }

               mode = mode->nxt;
            }
         }

         parser->RaBinProcess->size = nadp->size;

         if (nadp->mode < 0) {
            nadp->mode = ARGUSSPLITCOUNT;
            nadp->value = 10000;
            nadp->count = 1;
         }

         /* if content substitution, either time or any field, is used,
            size and count modes will not work properly.  If using
            the default count, set the value so that we generate only
            one filename.

            if no substitution, then we need to add "aa" suffix to the
            output file for count and size modes.
         */

         if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList)))) {
            struct ArgusWfileStruct *wfile = NULL;
            int count = parser->ArgusWfileList->count;

            if (count > 1)
               usage();

            if ((wfile = (struct ArgusWfileStruct *) ArgusPopFrontList(parser->ArgusWfileList, ARGUS_LOCK)) != NULL) {
               strncpy (outputfile, wfile->filename, MAXSTRLEN);
    
               if ((strchr(outputfile, '%')) || (strchr(outputfile, '$'))) {
                  switch (nadp->mode) {
                     case ARGUSSPLITCOUNT:
                        nadp->count = -1;
                        break;

                     case ARGUSSPLITSIZE:
                        for (i = 0; i < nadp->slen; i++) 
                           strcat(outputfile, "a");
                        break;
                  }

               } else {
                  switch (nadp->mode) {
                     case ARGUSSPLITSIZE:
                     case ARGUSSPLITCOUNT:
                        for (i = 0; i < nadp->slen; i++) 
                           strcat(outputfile, "a");
                        break;
                  }
               }

               if (!(strchr(outputfile, '%'))) {
                  switch (nadp->mode) {
                     case ARGUSSPLITTIME:
                       break;
                  }
               }

               nadp->filename = strdup(outputfile);
               setArgusWfile (parser, outputfile, NULL);
            }
         }

         for (i = 0; i < MAX_PRINT_ALG_TYPES; i++)
            if (parser->RaPrintAlgorithmList[i] != NULL)
               if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintIdleTime)
                  ArgusAlwaysUpdate++;

         if (parser->RaTasksToDo == 0) {
            RaCursesUpdateInterval.tv_sec  = 1;
            RaCursesUpdateInterval.tv_usec = 0;
         } else {
            RaCursesUpdateInterval.tv_sec  = 1;
            RaCursesUpdateInterval.tv_usec = 153613;
         }

         if (ArgusCursesEnabled)
            parser->RaCursesMode = 1;

         parser->RaInitialized++;
      
         if (!(parser->Sflag)) {
            if (parser->ArgusInputFileList == NULL) {
               if (!(ArgusAddFileList (parser, "-", ARGUS_DATA_SOURCE, -1, -1))) {
                  ArgusLog(LOG_ERR, "error: file arg %s", "-");
               }
            }
         }

         ArgusGetInterfaceAddresses(parser);
         parser->ArgusReliableConnection = 1;


         if (parser->dflag) {
            int pid;
    
            if (parser->Sflag)
               parser->ArgusReliableConnection++;
    
            ArgusLog(LOG_INFO, "started");
    
            if (chdir ("/") < 0)
               ArgusLog (LOG_ERR, "Can't chdir to / %s", strerror(errno));

            if ((pid = fork ()) < 0) {
               ArgusLog (LOG_ERR, "Can't fork daemon %s", strerror(errno));
            } else {
               if (pid) {
                  struct timespec ts = {0, 20000000};
                  int status;
                  nanosleep(&ts, NULL);
                  waitpid(pid, &status, WNOHANG);
                  if (kill(pid, 0) < 0) {
                     exit (1);
                  } else
                     exit (0);
               } else {
                  FILE *tmpfile;
    
                  parser->ArgusSessionId = setsid();
    
                  if ((tmpfile = freopen ("/dev/null", "r", stdin)) == NULL)
                     ArgusLog (LOG_ERR, "Cannot map stdout to /dev/null");
    
                  if ((tmpfile = freopen ("/dev/null", "a+", stdout)) == NULL)
                     ArgusLog (LOG_ERR, "Cannot map stdout to /dev/null");
    
                  if ((tmpfile = freopen ("/dev/null", "a+", stderr)) == NULL)
                     ArgusLog (LOG_ERR, "Cannot map stderr to /dev/null");
               }
            }
         }
      }
   }
}


void RaArgusInputComplete (struct ArgusInput *input) {
#if !defined(ARGUS_THREADS)
   RaRefreshDisplay();
#endif
}

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (ArgusParser && !ArgusParser->RaParseCompleting++) {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "RaParseComplete(caught signal %d)\n", sig);
#endif
         switch (sig) {
            case SIGHUP:
            case SIGINT:
            case SIGTERM:
            case SIGQUIT: {
               struct ArgusWfileStruct *wfile = NULL;

               ArgusParser->RaParseDone = 1;
               ArgusCloseDown = 1;
               ArgusShutDown(sig);

               if (ArgusParser->ArgusWfileList != NULL) {
                  struct ArgusListObjectStruct *lobj = NULL;
                  int i, count = ArgusParser->ArgusWfileList->count;

                  if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
                     for (i = 0; i < count; i++) {
                        if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                           if (wfile->fd != NULL) {
#ifdef ARGUSDEBUG
                              ArgusDebug (2, "RaParseComplete: closing %s\n", wfile->filename);
#endif
                              fflush (wfile->fd);
                              fclose (wfile->fd);
                              wfile->fd = NULL;
                           }
                           lobj = lobj->nxt;
                        }
                     }
                  }
               }
               break;
            }

            default:
               ArgusParser->RaParseDone = 1;
               break;
         }
      }
   }
}


struct timeval RaProcessQueueTimer = {0, 250000};
struct timeval RaProcessDebugTimer = {0,      0};

void
ArgusClientTimeout ()
{
   struct ArgusQueueStruct *queue = RaOutputProcess->queue;
   struct timeval tvbuf, *tvp = &tvbuf;

   if (!(ArgusParser->Pauseflag)) {
      gettimeofday(&ArgusParser->ArgusRealTime, 0);
      ArgusAdjustGlobalTime (ArgusParser, NULL);
   }

   *tvp = ArgusParser->ArgusGlobalTime;

   if (RaProcessDebugTimer.tv_sec != 0) {
      if (RaProcessDebugTimer.tv_sec == tvp->tv_sec) {
#if defined(ARGUSDEBUG)
         ArgusDebug (2, "ArgusClientTimeout RaCursesQueue %d ArgusTotalSearches %d ArgusTotalSQLUpdates %d written %d bytes\n", queue->count, ArgusTotalSQLSearches, ArgusTotalSQLUpdates, ArgusTotalSQLWrites);
#endif
         RaProcessDebugTimer.tv_sec++;
      } else
      if (RaProcessDebugTimer.tv_sec < tvp->tv_sec)
         RaProcessDebugTimer.tv_sec = tvp->tv_sec + 1;
         
   } else
      RaProcessDebugTimer.tv_sec = tvp->tv_sec + 1;


   if (ArgusParser->RaClientUpdate.tv_sec != 0) {
      int last = 0;
      if (((ArgusParser->RaClientUpdate.tv_sec < tvp->tv_sec) ||
          ((ArgusParser->RaClientUpdate.tv_sec == tvp->tv_sec) &&
           (ArgusParser->RaClientUpdate.tv_usec < tvp->tv_usec)))) {

         ArgusProcessQueue(queue, 0);

         ArgusParser->RaClientUpdate.tv_sec  += RaProcessQueueTimer.tv_sec;
         ArgusParser->RaClientUpdate.tv_usec += RaProcessQueueTimer.tv_usec;

         while (ArgusParser->RaClientUpdate.tv_usec > 1000000) {
            if (!last++)
               ArgusGetInterfaceAddresses(ArgusParser);

            ArgusParser->RaClientUpdate.tv_sec++;
            ArgusParser->RaClientUpdate.tv_usec -= 1000000;
         }
      }

   } else
      ArgusParser->RaClientUpdate.tv_sec = ArgusParser->ArgusGlobalTime.tv_sec;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusClientTimeout()\n");
#endif
}

void
parse_arg (int argc, char**argv)
{}

void
usage ()
{
   extern char version[];

   fprintf (stdout, "Rasqlinsert Version %s\n", version);

   fprintf (stdout, "usage: %s -w mysql://[user[:pass]@]host[:port]/db/table\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [-M mode] -w mysql://[user[:pass]@]host[:port]/db/table\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [-M mode] -r mysql://[user[:pass]@]host[:port]/db/table\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [ra-options] [rasqlinsert-options] [- filter-expression]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -f <racluster.conf>    read aggregation rules from <racluster.conf>.\n");
   fprintf (stdout, "         -m flow key fields     specify fields to be used as flow keys.\n");
   fprintf (stdout, "         -M modes               modify mode of operation.\n");
   fprintf (stdout, "            Available modes:    \n");
   fprintf (stdout, "               cache            maintain flow caches in database table\n");
   fprintf (stdout, "               drop             drop target table before using\n");
   fprintf (stdout, "               mysql_engine=    use specific mysql storage engines\n");
   fprintf (stdout, "                  MyISAM        default\n");
   fprintf (stdout, "                  InnoDB        \n");
   fprintf (stdout, "                  Memory        \n");
   fprintf (stdout, "                  Merge         \n");
   fprintf (stdout, "                  Archive       \n");
   fprintf (stdout, "                  Federated     \n");
   fprintf (stdout, "                  NDB           \n");
   fprintf (stdout, "                  CSV           \n");
   fprintf (stdout, "                  Blackhole     \n");
   fprintf (stdout, "               curses           turn on curses based interface\n");
   fprintf (stdout, "               nocurses         turn off curses based interface (default)\n");
   fprintf (stdout, "               correct          turn on direction correction (default)\n");
   fprintf (stdout, "               nocorrect        turn off direction correction\n");
   fprintf (stdout, "               preserve         turn on field preservation during aggregation (default)\n");
   fprintf (stdout, "               nopreserve       turn off field preservation during aggregation\n");
   fprintf (stdout, "               merge            turn on accumulation aggregation (default)\n");
   fprintf (stdout, "               nomerge          update table with only the last record \n");
   fprintf (stdout, "               ind              aggregate multiple files independently\n");
   fprintf (stdout, "               norep            do not report aggregation statistics\n");
   fprintf (stdout, "               rmon             convert bi-directional data into rmon in/out data\n");
   fprintf (stdout, "                                \n");
   fprintf (stdout, "         -r <dbUrl>             read argus data from mysql database.\n");
   fprintf (stdout, "         -w <dbUrl>             write argus data to mysql database.\n");
   fprintf (stdout, "             Format:            mysql://[user[:pass]@]host[:port]/db/table\n");
   fflush (stdout);
   exit(1);
}

/*
   RaProcessRecord - this routine will take a non-managment record and
   process it as if it were a SBP.  This basically means, transform the
   flow descriptor to whatever model is appropriate, find the flow
   cache.  Then we carve the new record into the appropriate size for
   the SBP operation, and then proceed to merge the fragments into the
   appropriate record for this ns.

   If the ns cache is a sticky ns, it may not be in the RaOutputProcess
   queue, so we need to check and put it in if necessary.

   And because we had a record, we'll indicate that the window needs
   to be updated.

   All screen operations, queue timeouts etc, are done in 
   ArgusClientTimeout, so we're done here.

*/

void RaProcessThisEventRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_EVENT:
         RaProcessEventRecord(parser, ns);
         break;

      case ARGUS_MAR:
         RaProcessManRecord(parser, ns);
         break;

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];

         if (parser->RaMonMode) {
            struct ArgusRecordStruct *tns;

            if (flow != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, ns);

            tns = ArgusCopyRecordStruct(ns);
            ArgusReverseRecord(tns);

            if ((flow = (void *) tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);

         } else {
            struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;

            if (flow && agg && agg->ArgusMatrixMode) {
               if (agg->mask & ((0x01LL << ARGUS_MASK_SADDR) | (0x01LL << ARGUS_MASK_DADDR))) {
                  switch (flow->hdr.subtype & 0x3F) {
                     case ARGUS_FLOW_LAYER_3_MATRIX:
                     case ARGUS_FLOW_CLASSIC5TUPLE: {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: {
                              if (flow->ip_flow.ip_src > flow->ip_flow.ip_dst)
                                 ArgusReverseRecord(ns);
                           }
                           break;

                           case ARGUS_TYPE_IPV6: {
                              int i;
                              for (i = 0; i < 4; i++) {
                                 if (flow->ipv6_flow.ip_src[i] < flow->ipv6_flow.ip_dst[i])
                                    break;

                                 if (flow->ipv6_flow.ip_src[i] > flow->ipv6_flow.ip_dst[i]) {
                                    ArgusReverseRecord(ns);
                                    break;
                                 }
                              }
                           }
                           break;
                        }
                        break;
                     }

                     default:
                        break;
                  }

               } else
               if (agg->mask & ((0x01LL << ARGUS_MASK_SMAC) | (0x01LL << ARGUS_MASK_DMAC))) {

                  struct ArgusMacStruct *m1 = NULL;
                  if ((m1 = (struct ArgusMacStruct *) ns->dsrs[ARGUS_MAC_INDEX]) != NULL) {
                     switch (m1->hdr.subtype) {
                        case ARGUS_TYPE_ETHER: {
                           struct ether_header *e1 = &m1->mac.mac_union.ether.ehdr;
                           int i;

                           for (i = 0; i < 6; i++) {
#if defined(ARGUS_SOLARIS)
                              if (e1->ether_shost.ether_addr_octet[i] < e1->ether_dhost.ether_addr_octet[i])
                                 break;
                              if (e1->ether_shost.ether_addr_octet[i] > e1->ether_dhost.ether_addr_octet[i]) {
                                 ArgusReverseRecord(ns);
                                 break;
                              }
#else
                              if (e1->ether_shost[i] < e1->ether_dhost[i])
                                 break;
                              if (e1->ether_shost[i] > e1->ether_dhost[i]) {
                                 ArgusReverseRecord(ns);
                                 break;
                              }
#endif
                           }
                           break;
                        }
                     }
                  }
               }
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, ns);
         }
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "RaProcessRecord (0x%x, 0x%x)\n", parser, ns);
#endif
}

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusRecordStruct *tns = NULL, *pns = NULL, *cns = NULL;
   struct ArgusAggregatorStruct *tagg, *agg = parser->ArgusAggregator;
   struct RaBinProcessStruct *RaBinProcess = parser->RaBinProcess;
   struct ArgusHashStruct *hstruct = NULL;
   struct ArgusFlow *flow = NULL;
   int found = 0;

   while (ArgusParser->Pauseflag) {
      struct timespec ts = {0, 25000000};
      nanosleep (&ts, NULL);
      ArgusClientTimeout ();
   }

   RaCursesStopTime = parser->ArgusRealTime;
   if (ArgusParser->RaClientUpdate.tv_sec == 0) {
      ArgusParser->RaClientUpdate.tv_sec = parser->ArgusGlobalTime.tv_sec;
      ArgusParser->RaClientUpdate.tv_usec = 0;
   }
   if (RaCursesStartTime.tv_sec == 0)
      RaCursesStartTime = parser->ArgusRealTime;

#if defined(ARGUS_MYSQL)
   {
      char *table;

         if ((strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$'))) {
            char stable[MAXSTRLEN];
            table = ArgusCreateSQLSaveTableName(parser, ns, RaSQLSaveTable);

            sprintf (stable, "%s.%s", RaDatabase, table);

            if (RaSQLCurrentTable) {
               if (strncmp(RaSQLCurrentTable, stable, strlen(stable))) {
                  if ((ArgusLastTime.tv_sec   > ArgusThisTime.tv_sec) || 
                     ((ArgusLastTime.tv_sec  == ArgusThisTime.tv_sec) && 
                      (ArgusLastTime.tv_usec  > ArgusThisTime.tv_usec))) {

                     int flushCnt = 0, queueCnt = 0;
#ifdef ARGUSDEBUG
                  ArgusDebug (1, "ArgusProcessData: flushing sql queues\n");
#endif
                     struct ArgusQueueStruct *queue = RaOutputProcess->queue;
                     extern int   RaSQLUpdateDB;

#if defined(ARGUS_THREADS)
                     pthread_mutex_unlock(&queue->lock);
#endif
#if defined(ARGUS_MYSQL)

                     if (ArgusParser->RaCursesMode)
                        RaClientSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);
                     else
                        RaClientSortQueue(ArgusSorter, queue, ARGUS_NOLOCK | ARGUS_NOSORT);

                     if (RaSQLUpdateDB && RaSQLCurrentTable) {
                        char *sbuf = calloc(1, MAXBUFFERLEN);
                        int i;

                        if (queue->array != NULL) {
                           queueCnt = queue->count;
                           for (i = 0; i < queueCnt; i++) {
                              struct ArgusRecordStruct *ns = (struct ArgusRecordStruct *)queue->array[i];

                              if (ns && (ns->status & ARGUS_RECORD_MODIFIED)) {
                                 ArgusScheduleSQLQuery (parser, parser->ArgusAggregator, ns, sbuf, MAXBUFFERLEN, ARGUS_STATUS);
                                 ns->status &= ~ARGUS_RECORD_MODIFIED;
                                 flushCnt++;
                              }
                           }
                        }
                        free(sbuf);
                     }
#endif
#if defined(ARGUS_THREADS)
                     pthread_mutex_unlock(&queue->lock);
#endif
#ifdef ARGUSDEBUG
                     ArgusDebug (1, "ArgusProcessData: flushed %d records\n", flushCnt);
#endif
                     free (RaSQLCurrentTable);
                     RaSQLCurrentTable = NULL;
                  }
               }
            }

            if (RaSQLCurrentTable == NULL) {
               struct ArgusQueueStruct *queue = RaOutputProcess->queue;
               struct ArgusRecordStruct *argus;
               int x, z, count;

               count = queue->count;

               for (x = 0, z = count; x < z; x++) {
                  if ((argus = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL)
                     ArgusDeleteRecordStruct(ArgusParser, argus);
               }
               ArgusCreateSQLSaveTable(RaDatabase, table);
            }
         }
   }
#endif

   ArgusProcessDirection(parser, ns);

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&RaOutputProcess->queue->lock);
#endif

   while (agg && !found) {
      int retn = 0, fretn = -1, lretn = -1;

      if (agg->filterstr) {
         struct nff_insn *fcode = agg->filter.bf_insns;
         fretn = ArgusFilterRecord (fcode, ns);
      }

      if (agg->grepstr) {
         struct ArgusLabelStruct *label;
         if (((label = (void *)ns->dsrs[ARGUS_LABEL_INDEX]) != NULL)) {
            if (regexec(&agg->lpreg, label->l_un.label, 0, NULL, 0))
               lretn = 0;
            else
               lretn = 1;
         } else
            lretn = 0;
      }

      retn = (lretn < 0) ? ((fretn < 0) ? 1 : fretn) : ((fretn < 0) ? lretn : (lretn && fretn));

      if (retn != 0) {
         cns = ArgusCopyRecordStruct(ns);
         flow = (struct ArgusFlow *) cns->dsrs[ARGUS_FLOW_INDEX];

         if (agg->mask) {
         if (flow != NULL) {
            if ((agg->rap = RaFlowModelOverRides(agg, cns)) == NULL)
               agg->rap = agg->drap;

            ArgusGenerateNewFlow(agg, cns);

            if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
               ArgusLog (LOG_ERR, "RaProcessRecord: ArgusGenerateHashStruct error %s", strerror(errno));

            if ((pns = ArgusFindRecord(RaOutputProcess->htable, hstruct)) == NULL) {
               int tryreverse = 1;

               switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4: {
                     switch (flow->ip_flow.ip_p) {
                        case IPPROTO_ESP:
                           tryreverse = 0;
                           break;
                     }
                  }
               }

               if (!parser->RaMonMode && tryreverse) {
                  struct ArgusRecordStruct *dns = ArgusCopyRecordStruct(cns);

                  ArgusReverseRecord (dns);

                  ArgusGenerateNewFlow(agg, dns);
                  flow = (struct ArgusFlow *) dns->dsrs[ARGUS_FLOW_INDEX];

                  if ((hstruct = ArgusGenerateHashStruct(agg, dns, flow)) == NULL)
                     ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                  if ((pns = ArgusFindRecord(RaOutputProcess->htable, hstruct)) != NULL) {
                     ArgusDeleteRecordStruct(ArgusParser, cns);
                     cns = dns;

                  } else {
                     ArgusDeleteRecordStruct(ArgusParser, dns);
                     flow = (struct ArgusFlow *) cns->dsrs[ARGUS_FLOW_INDEX];
                     if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
                        ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));
                  }
               }
            }
         }

         if ((pns) && pns->qhdr.queue) {
            if (pns->qhdr.queue != RaOutputProcess->queue)
               ArgusRemoveFromQueue (pns->qhdr.queue, &pns->qhdr, ARGUS_LOCK);
            else
               ArgusRemoveFromQueue (pns->qhdr.queue, &pns->qhdr, ARGUS_NOLOCK);

            ArgusAddToQueue (RaOutputProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
            pns->status |= ARGUS_RECORD_MODIFIED;
         } else {
            tagg = agg;
            agg = agg->nxt;
         }
         }
         found++;

      } else
         agg = agg->nxt;
   }

   if (agg == NULL)
      agg = tagg;

   if (cns) {
      if (!found) 
         if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
            ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

      if (pns == NULL) {   // didn't find a cache, so ...
                           // go ahead and insert the record, and schedule a select to
                           // fetch from database... First marked as insert, but the return
                           // from the select could convert that to update.

         if (RaSQLCacheDB) {
            struct ArgusMaskStruct *ArgusMaskDefs =  ArgusSelectMaskDefs(cns);
            char sbuf[MAXBUFFERLEN], buf[MAXBUFFERLEN];
            char tmpbuf[MAXSTRLEN], *ptr, *tptr;
            char ubuf[1024], tbuf[1024];
            int uflag, nflag = parser->nflag;
            int retn, y, mind = 0;
            MYSQL_RES *mysqlRes;

            parser->nflag = 2;

            bzero(ubuf, sizeof(ubuf));
            bzero(sbuf, sizeof(sbuf));

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&parser->lock);
#endif
            for (parser->RaPrintIndex = 0; parser->RaPrintIndex < MAX_PRINT_ALG_TYPES; parser->RaPrintIndex++) {

               if (parser->RaPrintAlgorithmList[parser->RaPrintIndex] != NULL) {
                  parser->RaPrintAlgorithm = parser->RaPrintAlgorithmList[parser->RaPrintIndex];

                  found = 0;
                  bzero (tmpbuf, sizeof(tmpbuf));

                  if (agg && agg->mask) {
                     for (y = 0; y < ARGUS_MAX_MASK_LIST; y++) {
                        if (agg->mask & (0x01LL << y)) {
                           if (!strcmp(parser->RaPrintAlgorithm->field, ArgusMaskDefs[y].name)) {
                              found++;
                           }
                        }
                     }
                  }

                  if (found) {
                     int len = parser->RaPrintAlgorithm->length;
                     len = (len > 256) ? len : 256;

                     if (mind++ > 0)
                        sprintf (&ubuf[strlen(ubuf)], " and ");

                     uflag = ArgusParser->uflag;
                     ArgusParser->uflag++;

                     parser->RaPrintAlgorithm->print(parser, tmpbuf, cns, len);

                     ArgusParser->uflag = uflag;

                     if ((ptr = ArgusTrimString(tmpbuf)) != NULL) {
                        sprintf (tbuf, "%s=\"%s\"", parser->RaPrintAlgorithm->field, ptr);
                        tptr = &ubuf[strlen(ubuf)];
                        sprintf (tptr, "%s", tbuf);
                     }
                  }
               }
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&parser->lock);
#endif
            sprintf (sbuf, "SELECT record FROM %s WHERE %s", RaSQLCurrentTable, ubuf);
            parser->nflag   = nflag;

#if defined(ARGUSDEBUG)
            ArgusDebug (3, "ArgusProcessThisRecord () sql query %s\n", sbuf); 
#endif
            ArgusTotalSQLSearches++;

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaMySQLlock);
#endif
            if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
               ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));
            else {
               if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
                  if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                     MYSQL_ROW row;
                     while ((row = mysql_fetch_row(mysqlRes))) {
                        unsigned long *lengths;
                        int x;

                        lengths = mysql_fetch_lengths(mysqlRes);
                        bzero(buf, sizeof(buf));

                        for (x = 0; x < retn; x++) {
                           bcopy (row[x], buf, (int) lengths[x]);
                           if ((((struct ArgusRecord *)buf)->hdr.type & ARGUS_FAR) ||
                               (((struct ArgusRecord *)buf)->hdr.type & ARGUS_NETFLOW)) {
#ifdef _LITTLE_ENDIAN
                              ArgusNtoH((struct ArgusRecord *) buf);
#endif
                              if ((tns = ArgusGenerateRecordStruct (ArgusParser, ArgusInput, (struct ArgusRecord *) buf)) != NULL) {
#if defined(ARGUSDEBUG)
                                 char buf[MAXSTRLEN];
                                 bzero(buf, MAXSTRLEN);
                                 ArgusPrintRecord(parser, buf, tns, MAXSTRLEN);
                                 ArgusDebug (3, "returned %s\n", buf); 
#endif
                                 if ((pns = ArgusCopyRecordStruct(tns)) != NULL) {
                                    pns->htblhdr = ArgusAddHashEntry (RaOutputProcess->htable, pns, hstruct);
                                    ArgusAddToQueue (RaOutputProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
                                    gettimeofday (&pns->qhdr.logtime, 0L);
                                 }

                              } else {
                                 ArgusLog(LOG_INFO, "mysql_real_query recieved record could not parse");
                              }
                           }
                        }
                     }
                  }
                  mysql_free_result(mysqlRes);
               }
            }
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaMySQLlock);
#endif
         }
      }

      ArgusAlignInit(parser, cns, &RaBinProcess->nadp);

      while ((tns = ArgusAlignRecord(parser, cns, &RaBinProcess->nadp)) != NULL) {
         int offset = 0;

         if (pns) {
            if (pns->bins) {
//             offset = (parser->Bflag * 1000000LL) / pns->bins->size;
               pns->bins->nadp.RaStartTmStruct = RaBinProcess->nadp.RaStartTmStruct;
               pns->bins->nadp.RaEndTmStruct   = RaBinProcess->nadp.RaEndTmStruct;

               if (!(ArgusInsertRecord (parser, pns->bins, tns, offset)))
                  ArgusDeleteRecordStruct(ArgusParser, tns);

               pns->bins->status |= RA_DIRTYBINS;

            } else {
               if (parser->RaCumulativeMerge)
                  ArgusMergeRecords (ArgusParser->ArgusAggregator, pns, tns);
               else {
                  int i;
                  for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
                     if (tns->dsrs[i] != NULL) {
                        if (pns->dsrs[i] != NULL)
                           ArgusFree(pns->dsrs[i]);
                        pns->dsrs[i] = tns->dsrs[i];
                        tns->dsrs[i] = NULL;
                     }
                  }
               }

               ArgusDeleteRecordStruct(ArgusParser, tns);
               pns->status |= ARGUS_RECORD_MODIFIED;
            }

            ArgusRemoveFromQueue(RaOutputProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
            ArgusAddToQueue (RaOutputProcess->queue, &pns->qhdr, ARGUS_NOLOCK);

         } else {
            if ((pns =  ArgusCopyRecordStruct(tns)) != NULL) { /* new record */
               pns->htblhdr = ArgusAddHashEntry (RaOutputProcess->htable, pns, hstruct);
               ArgusAddToQueue (RaOutputProcess->queue, &pns->qhdr, ARGUS_NOLOCK);

               if (RaBinProcess->nadp.mode == ARGUSSPLITRATE) {
                  if ((pns->bins = (struct RaBinProcessStruct *)ArgusNewRateBins(parser, pns)) == NULL)
                     ArgusLog (LOG_ERR, "ArgusProcessThisRecord: ArgusNewRateBins error %s", strerror(errno));

//             offset = (parser->Bflag * 1000000LL) / pns->bins->size;

                  if (!(ArgusInsertRecord (parser, pns->bins, tns, offset))) 
                     ArgusDeleteRecordStruct(ArgusParser, tns);

                  pns->bins->status |= RA_DIRTYBINS;

               } else
                  ArgusDeleteRecordStruct(ArgusParser, tns);

               pns->status |= ARGUS_RECORD_NEW | ARGUS_RECORD_MODIFIED;
#if defined(ARGUS_MYSQL)
               pns->status |= ARGUS_SQL_INSERT;
#endif
            }
         }

//    for (i = 0; i < ArgusTotalAnalytics; i++) {
            if (pns->status & ARGUS_RECORD_NEW)
               ArgusCorrelateRecord(pns);
//    }

         pns->status &= ~ARGUS_RECORD_NEW;
         RaWindowModified = RA_MODIFIED;
      }
      ArgusDeleteRecordStruct(ArgusParser, cns);

   } else {

/* no key, so we're just inserting the record at the end of the table */

      char sbuf[MAXBUFFERLEN];
      ns->status |= ARGUS_SQL_INSERT;
      ArgusScheduleSQLQuery (ArgusParser, ArgusParser->ArgusAggregator, ns, sbuf, sizeof(sbuf), ARGUS_STATUS);
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&RaOutputProcess->queue->lock);
#endif

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessThisRecord () returning\n"); 
#endif
}



void
RaProcessThisEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusRecordStruct *tns = NULL, *pns = NULL, *cns = NULL;
   struct ArgusAggregatorStruct *agg = ArgusEventAggregator;
   struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusHashStruct *hstruct = NULL;
   int found = 0;

   RaCursesStopTime = parser->ArgusRealTime;
   if (ArgusParser->RaClientUpdate.tv_sec == 0) {
      ArgusParser->RaClientUpdate.tv_sec = parser->ArgusGlobalTime.tv_sec;
      ArgusParser->RaClientUpdate.tv_usec = 0;
   }
   if (RaCursesStartTime.tv_sec == 0)
      RaCursesStartTime = parser->ArgusRealTime;

   while (agg && !found) {
      struct nff_insn *fcode = agg->filter.bf_insns;

      if (ArgusFilterRecord (fcode, ns) != 0) {
         cns = ArgusCopyRecordStruct(ns);
         if (flow != NULL) {
            if ((agg->rap = RaFlowModelOverRides(agg, cns)) == NULL)
               agg->rap = agg->drap;

            ArgusGenerateNewFlow(agg, cns);

            if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
               ArgusLog (LOG_ERR, "RaProcessRecord: ArgusGenerateHashStruct error %s", strerror(errno));

            if ((pns = ArgusFindRecord(RaEventProcess->htable, hstruct)) == NULL) {
               int tryreverse = 1;

               switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4: {
                     switch (flow->ip_flow.ip_p) {
                        case IPPROTO_ESP:
                           tryreverse = 0;
                           break;
                     }
                  }
               }

               if (!parser->RaMonMode && tryreverse) {
                  struct ArgusRecordStruct *dns = ArgusCopyRecordStruct(ns);

                  ArgusReverseRecord (dns);

                  ArgusGenerateNewFlow(agg, dns);

                  if ((hstruct = ArgusGenerateHashStruct(agg, dns, flow)) == NULL)
                     ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                  if ((pns = ArgusFindRecord(RaEventProcess->htable, hstruct)) != NULL) {
                     ArgusDeleteRecordStruct(ArgusParser, cns);
                     cns = dns;

                  } else {
                     ArgusDeleteRecordStruct(ArgusParser, dns);
                     if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
                        ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));
                  }
               }
            }
         }

         if ((pns) && pns->qhdr.queue) {
            if (pns->qhdr.queue != RaEventProcess->queue)
               ArgusRemoveFromQueue (pns->qhdr.queue, &pns->qhdr, ARGUS_LOCK);
            else
               ArgusRemoveFromQueue (pns->qhdr.queue, &pns->qhdr, ARGUS_NOLOCK);

            ArgusAddToQueue (RaEventProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
            pns->status |= ARGUS_RECORD_MODIFIED;
         }
         found++;

      } else
         agg = agg->nxt;
   }

   if (cns) {
   if (!found)
      if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
         ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         tns = ArgusCopyRecordStruct(cns);
         if (pns) {
            if (parser->RaCumulativeMerge)
               ArgusMergeRecords (ArgusParser->ArgusAggregator, pns, tns);
            else {
               int i;
               for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
                  if (tns->dsrs[i] != NULL) {
                     if (pns->dsrs[i] != NULL)
                        ArgusFree(pns->dsrs[i]);
                     pns->dsrs[i] = tns->dsrs[i];
                     tns->dsrs[i] = NULL;
                  }
               }
            }

            ArgusDeleteRecordStruct(ArgusParser, tns);
            pns->status |= ARGUS_RECORD_MODIFIED;

            ArgusRemoveFromQueue(RaEventProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
            ArgusAddToQueue (RaEventProcess->queue, &pns->qhdr, ARGUS_NOLOCK);

         } else {
            pns = tns;
            pns->status |= ARGUS_RECORD_MODIFIED;
            pns->htblhdr = ArgusAddHashEntry (RaEventProcess->htable, pns, hstruct);
            ArgusAddToQueue (RaEventProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
         }
         RaWindowModified = RA_MODIFIED;
      }
   }

   ArgusDeleteRecordStruct(ArgusParser, cns);
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessThisEventRecord () returning\n"); 
#endif
}


void
RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
 
#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessManRecord () returning\n"); 
#endif
}


void
RaProcessEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   if (parser->ArgusCorrelateEvents) {
      struct ArgusTimeObject *time = (void *)argus->dsrs[ARGUS_TIME_INDEX];
      struct ArgusDataStruct *data = NULL;
      struct timeval tvpbuf, *tvp = &tvpbuf;
      char buf[0x10000], *ptr = buf;
      char tbuf[129], sbuf[129], *sptr = sbuf;
      char *dptr, *str;
      unsigned long len = 0x10000;
      int title = 0;;

      if ((data = (void *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) == NULL)
         return;

      if (data->hdr.subtype & ARGUS_DATA_COMPRESS) {
         bzero (ptr, sizeof(buf));
         uncompress((Bytef *)ptr, (uLongf *)&len, (Bytef *)&data->array, data->count);
         dptr = ptr;
      } else {
         dptr = data->array;
      }

      if (strstr(dptr, "argus-lsof")) {
         bzero (tbuf, sizeof(tbuf));
         bzero (sptr, sizeof(sbuf));
         tvp->tv_sec  = time->src.start.tv_sec;
         tvp->tv_usec = time->src.start.tv_usec;

         ArgusPrintTime(parser, tbuf, tvp);
         ArgusPrintSourceID(parser, sptr, argus, 24);

         while (isspace((int)sbuf[strlen(sbuf) - 1]))
            sbuf[strlen(sbuf) - 1] = '\0';

         while (isspace((int)*sptr)) sptr++;

// COMMAND     PID           USER   FD   TYPE     DEVICE SIZE/OFF   NODE NAME

         while ((str = strsep(&dptr, "\n")) != NULL) {
            if (title) {
               char *tok, *app = NULL, *pid = NULL, *user = NULL;
               char *node = NULL, *name = NULL, *state = NULL;
               int field = 0;
               while ((tok = strsep(&str, " ")) != NULL) {
                  if (*tok != '\0') {
                     switch (field++) {
                        case 0: app  = tok; break;
                        case 1: pid  = tok; break;
                        case 2: user = tok; break;
                        case 7: node = tok; break;
                        case 8: name = tok; break;
                        case 9: state = tok; break;
                     }
                  }
               }
               if (name != NULL) {
                  short proto = 0;

                  if (!(strcmp("TCP", node))) proto = IPPROTO_TCP;
                  else if (!(strcmp("UDP", node))) proto = IPPROTO_UDP;

                  if ((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {
                     struct ArgusFlow flowbuf, *flow = &flowbuf;
                     char *saddr = NULL, *daddr = NULL;
                     char *sport = NULL, *dport = NULL;
                     field = 0;

                     if (strstr(name, "->") != NULL) {
                        struct ArgusCIDRAddr *cidr = NULL, scidr, dcidr;
                        int sPort, dPort;

                        if (strchr(name, '[')) {
                           while ((tok = strsep(&name, "[]->")) != NULL) {
                              if (*tok != '\0') {
                                 switch (field++) {
                                    case 0: saddr  = tok; break;
                                    case 1: sport  = tok+1; break;
                                    case 2: daddr = tok; break;
                                    case 3: dport = tok+1; break;
                                 }
                              }
                           }
                        } else {
                           while ((tok = strsep(&name, ":->")) != NULL) {
                              if (*tok != '\0') {
                                 switch (field++) {
                                    case 0: saddr  = tok; break;
                                    case 1: sport  = tok; break;
                                    case 2: daddr = tok; break;
                                    case 3: dport = tok; break;
                                 }
                              }
                           }
                        }

                        if (daddr && ((cidr = RaParseCIDRAddr (parser, saddr)) != NULL))
                           bcopy ((char *)cidr, (char *)&scidr, sizeof (*cidr));

                        if (daddr && ((cidr = RaParseCIDRAddr (parser, daddr)) != NULL))
                           bcopy ((char *)cidr, (char *)&dcidr, sizeof (*cidr));
    
                        sPort = strtol(sport, NULL, 10);
                        dPort = strtol(dport, NULL, 10);

                        if ((sPort != 0) && (dPort != 0)) {

                           switch (scidr.type) {
                              case AF_INET: {
                                 bzero((char *)flow, sizeof(*flow));
                                 flow->hdr.type              = ARGUS_FLOW_DSR;
                                 flow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                                 flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                                 flow->hdr.argus_dsrvl8.len    = 5;

                                 bcopy(&scidr.addr, &flow->ip_flow.ip_src, scidr.len);
                                 bcopy(&dcidr.addr, &flow->ip_flow.ip_dst, dcidr.len);
                                 flow->ip_flow.ip_p  = proto;
                                 flow->ip_flow.sport = sPort;
                                 flow->ip_flow.dport = dPort;
                                 flow->ip_flow.smask = 32;
                                 flow->ip_flow.dmask = 32;
                                 break;
                              }

                              case AF_INET6: {
                                 bzero((char *)flow, sizeof(*flow));
                                 flow->hdr.type              = ARGUS_FLOW_DSR;
                                 flow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                                 flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV6;
                                 flow->hdr.argus_dsrvl8.len    = 12;

                                 bcopy(&scidr.addr, &flow->ipv6_flow.ip_src, scidr.len);
                                 bcopy(&dcidr.addr, &flow->ipv6_flow.ip_dst, dcidr.len);
                                 flow->ipv6_flow.ip_p  = proto;
                                 flow->ipv6_flow.sport = sPort;
                                 flow->ipv6_flow.dport = dPort;
                                 break;
                              }
                           }

                           {
                              struct ArgusRecordStruct *ns = NULL;
                              struct ArgusTransportStruct *atrans, *btrans;
                              struct ArgusLabelStruct *label;
                              struct ArgusTimeObject *btime;
                              struct ArgusFlow *bflow;
                              extern char ArgusCanonLabelBuffer[];
                              char *lptr = ArgusCanonLabelBuffer;

#if defined(ARGUSDEBUG)
                           ArgusDebug (2, "RaProcessEventRecord: %s:srcid=%s:%s: %s %s.%s -> %s.%s %s\n", tbuf, sptr, app, node, 
                                               saddr, sport, daddr, dport, state);
#endif
                              if ((ns = ArgusGenerateRecordStruct(NULL, NULL, NULL)) != NULL) {
                                 extern struct ArgusCanonRecord ArgusGenerateCanonBuffer;
                                 struct ArgusCanonRecord *canon = &ArgusGenerateCanonBuffer;

                                 ns->status = argus->status;

                                 if ((atrans = (struct ArgusTransportStruct *)argus->dsrs[ARGUS_TRANSPORT_INDEX]) != NULL)
                                    if ((btrans = (struct ArgusTransportStruct *)ns->dsrs[ARGUS_TRANSPORT_INDEX]) != NULL)
                                       bcopy ((char *)atrans, (char *)btrans, sizeof(*atrans));
                                 ns->dsrindex |= (0x1 << ARGUS_TRANSPORT_INDEX);

                                 if ((btime = (struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX]) != NULL)
                                    bcopy ((char *)time, (char *)btime, sizeof(*btime));
                                 ns->dsrindex |= (0x1 << ARGUS_TIME_INDEX);

                                 if ((bflow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX]) == NULL) {
                                    ns->dsrs[ARGUS_FLOW_INDEX] = (struct ArgusDSRHeader*) &canon->flow;
                                    bflow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];
                                 }
                                 bcopy ((char *)flow, (char *)bflow, sizeof(*flow));
                                 ns->dsrindex |= (0x1 << ARGUS_FLOW_INDEX);

                                 if (state && (proto == IPPROTO_TCP)) {
                                    struct ArgusNetworkStruct *bnet;
                                    struct ArgusTCPObject *tcp;

                                    if ((bnet = (struct ArgusNetworkStruct *)ns->dsrs[ARGUS_NETWORK_INDEX]) == NULL) {
                                       ns->dsrs[ARGUS_NETWORK_INDEX] = (struct ArgusDSRHeader*) &canon->net;
                                       bnet = (struct ArgusNetworkStruct *)ns->dsrs[ARGUS_NETWORK_INDEX];
                                    }

                                    bnet->hdr.type    = ARGUS_NETWORK_DSR;
                                    bnet->hdr.subtype = ARGUS_TCP_STATUS;
                                    bnet->hdr.argus_dsrvl8.len  = 3;
                                    tcp = (struct ArgusTCPObject *)&bnet->net_union.tcp;

                                    if (!(strcmp(state, "(ESTABLISHED)")))     tcp->status = ARGUS_CON_ESTABLISHED;
                                    else if (!(strcmp(state, "(CLOSED)")))     tcp->status = ARGUS_NORMAL_CLOSE;
                                    else if (!(strcmp(state, "(CLOSE_WAIT)"))) tcp->status = ARGUS_CLOSE_WAITING;
                                    else if (!(strcmp(state, "(TIME_WAIT)")))  tcp->status = ARGUS_CLOSE_WAITING;

                                    ns->dsrindex |= (0x01 << ARGUS_NETWORK_INDEX);
                                 }

                                 if ((label = (struct ArgusLabelStruct *)ns->dsrs[ARGUS_LABEL_INDEX]) == NULL) {
                                    ns->dsrs[ARGUS_LABEL_INDEX] = (struct ArgusDSRHeader*) &canon->label;
                                    label = (struct ArgusLabelStruct *)ns->dsrs[ARGUS_LABEL_INDEX];
                                 }

                                 bzero(lptr, MAXBUFFERLEN);
                                 sprintf (lptr, "pid=%s:usr=%s:app=%s", pid, user, app);

                                 label->hdr.type    = ARGUS_LABEL_DSR;
                                 label->hdr.subtype = ARGUS_PROC_LABEL;
                                 label->hdr.argus_dsrvl8.len  = 1 + ((strlen(lptr) + 3)/4);
                                 label->l_un.label = lptr;
                                 ns->dsrindex |= (0x01 << ARGUS_LABEL_INDEX);

                                 RaProcessThisEventRecord (parser, ns);
                              }
                           }
                        }
                     }
                  }
               }

            } else
            if (strstr (str, "COMMAND"))
               title++;
         }
      }

      ArgusCorrelateQueue (RaOutputProcess->queue);
   }
}


int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}


int ArgusProcessBins (struct ArgusRecordStruct *, struct RaBinProcessStruct *);

struct RaBinProcessStruct *
ArgusNewRateBins (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct RaBinProcessStruct *retn = NULL;
   struct RaBinProcessStruct *RaBinProcess = NULL;

   if ((RaBinProcess = parser->RaBinProcess) != NULL) {
      if ((retn = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*retn))) == NULL)
         ArgusLog (LOG_ERR, "ArgusNewRateBins: ArgusCalloc error %s", strerror(errno));

      bcopy ((char *)RaBinProcess, (char *)retn, sizeof (*retn));

#if defined(ARGUS_THREADS)
      pthread_mutex_init(&retn->lock, NULL);
#endif

      retn->nadp.RaStartTmStruct = RaBinProcess->nadp.RaStartTmStruct;
      retn->nadp.RaEndTmStruct   = RaBinProcess->nadp.RaEndTmStruct;

      retn->startpt.tv_sec = mktime(&RaBinProcess->nadp.RaStartTmStruct);
      retn->endpt.tv_sec   = mktime(&RaBinProcess->nadp.RaEndTmStruct);
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusNewRateBins (0x%x, 0x%x) returning %d", parser, ns, retn);
#endif

   return(retn);
}

void ArgusShiftArray (struct ArgusParserStruct *, struct RaBinProcessStruct *, int, int);

int
ArgusProcessBins (struct ArgusRecordStruct *ns, struct RaBinProcessStruct *rbps)
{
   int retn = 0, count = 0;
   int cnt   = (rbps->arraylen - rbps->index);
   int dtime = cnt * rbps->size;
   int rtime = ((((ArgusParser->ArgusGlobalTime.tv_sec * 1000000LL) /rbps->size)) * rbps->size)/1000000LL;;

   if (rbps && (rbps->size != 0)) {
      count = (rbps->end - rbps->start)/rbps->size;

      if ((rbps->startpt.tv_sec + dtime) < rtime) {
         ArgusShiftArray(ArgusParser, rbps, count, ARGUS_LOCK);
         ArgusUpdateScreen();

         rbps->status |= RA_DIRTYBINS;
         retn = 1;
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (2, "ArgusProcessBins (0x%x, 0x%x) count %d, dtime %d, rtime %d returning %d", ns, rbps, cnt, dtime, rtime, retn); 
#endif

   return (retn);
}

#if defined(HAVE_NET_IF_DL_H) && HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif

void
ArgusGetInterfaceAddresses(struct ArgusParserStruct *parser)
{
#if defined(HAVE_IFADDRS_H) && HAVE_IFADDRS_H
   struct ArgusLabelerStruct *labeler = NULL;
   struct ifaddrs *ifa = NULL, *p;
   
   if ((labeler = parser->ArgusLocalLabeler) != NULL) {
      if (getifaddrs(&ifa) != 0) 
         ArgusLog (LOG_ERR, "ArgusGetInterfaceAddrs: getifaddrs error %s", strerror(errno));

      for (p = ifa; p != NULL; p = p->ifa_next) {
         if (p->ifa_addr != NULL) {

#if defined(ARGUS_SOLARIS)
            int s, family = p->ifa_addr->ss_family;
#else
            int s, family = p->ifa_addr->sa_family;
#endif

            switch (family) {
               case AF_INET: {
                  char ip_addr[NI_MAXHOST];
                  uint32_t tmask, mask = ((struct sockaddr_in *)(p->ifa_netmask))->sin_addr.s_addr;
                  int i, cidrlen = 0;

                  if ((s = getnameinfo((void *)p->ifa_addr, sizeof(struct sockaddr_in), ip_addr, sizeof(ip_addr), NULL, 0, NI_NUMERICHOST)) != 0)
                     ArgusLog (LOG_ERR, "ArgusGetInerfaceAddresses: error %s\n", strerror(errno));

                  mask = ntohl(mask);
                  for (i = 0, tmask = 0xffffffff; i < 32; i++) {
                     if ((tmask << i) == mask) {
                        cidrlen = 32 - i;
                     }
                  }

                  RaInsertAddressTree (parser, labeler, ip_addr);
                  sprintf(&ip_addr[strlen(ip_addr)], "/%d", cidrlen);
                  RaInsertAddressTree (parser, labeler, ip_addr);
#if defined(ARGUSDEBUG)
                  ArgusDebug (7, "ArgusGetInterfaceAddresses: %-7s: %s", p->ifa_name, ip_addr);
#endif
                  break;
               }


               case AF_INET6: {
#if defined(ARGUSDEBUG)
                  ArgusDebug (7, "ArgusGetInterfaceAddresses: %-7s: family AF_INET6", p->ifa_name);
#endif
                  break;
               }

#if defined(AF_LINK)
               case AF_LINK: {
                  extern struct enamemem elabeltable[HASHNAMESIZE];
                  struct sockaddr_dl *sdp = (struct sockaddr_dl *) p->ifa_addr; 
                  static struct argus_etherent e;
                  struct enamemem *tp;

                  char *macstr = NULL;

                  bzero((char *)&e, sizeof(e));
                  bcopy((unsigned char *)(sdp->sdl_data + sdp->sdl_nlen), e.addr, 6);

                  tp = lookup_emem(elabeltable, e.addr);
                  if (tp->e_name == NULL) {
                     macstr = etheraddr_string (parser, e.addr);
                     tp->e_name = savestr(macstr);
                  }
#if defined(ARGUSDEBUG)
                  ArgusDebug (7, "ArgusGetInterfaceAddresses: %-7s: family AF_LINK: %s", p->ifa_name, macstr);
#endif
                  break;
               }
#endif

               default: {
#if defined(ARGUSDEBUG)
#if defined(ARGUS_SOLARIS)
                  ArgusDebug (7, "ArgusGetInterfaceAddresses: %-7s: family %d", p->ifa_name, p->ifa_addr->ss_family);
#else
                  ArgusDebug (7, "ArgusGetInterfaceAddresses: %-7s: family %d", p->ifa_name, p->ifa_addr->sa_family);
#endif
#endif
                  break;
               }
            }
         }
      }
      freeifaddrs(ifa);
   }
#endif

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusGetInterfaceAddresses () done"); 
#endif
}


extern struct ArgusRecordStruct *ArgusSearchHitRecord;

int
ArgusProcessQueue (struct ArgusQueueStruct *queue, int status)
{
   struct timeval tbuf, *tvp = &tbuf;
   int retn = 0, x, z;

   if (status || ((ArgusParser->timeout.tv_sec > 0) || (ArgusParser->timeout.tv_usec > 0))) {
      struct ArgusRecordStruct *ns;
      struct timeval lasttime;
      int count, deleted = 0;

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&queue->lock);
#endif
      count = queue->count;
      for (x = 0, z = count; x < z; x++) {
         if ((ns = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
            lasttime = ns->qhdr.lasttime;
            *tvp = lasttime;

            tvp->tv_sec  += ArgusParser->timeout.tv_sec;
            tvp->tv_usec += ArgusParser->timeout.tv_usec;
            if (tvp->tv_usec > 1000000) {
               tvp->tv_sec++;
               tvp->tv_usec -= 1000000;
            }

            if ((tvp->tv_sec  < ArgusParser->ArgusRealTime.tv_sec) ||
               ((tvp->tv_sec == ArgusParser->ArgusRealTime.tv_sec) &&
                (tvp->tv_usec < ArgusParser->ArgusRealTime.tv_usec))) {

               retn++;

               if (!(ns->status & ARGUS_NSR_STICKY)) {
                  if (ns->htblhdr != NULL)
                     ArgusRemoveHashEntry(&ns->htblhdr);

                  if (ArgusSearchHitRecord == ns)
                     ArgusResetSearch();

                  ArgusDeleteRecordStruct (ArgusParser, ns);
                  deleted++;

               } else {
                  ArgusZeroRecord (ns);
                  ArgusAddToQueue (queue, &ns->qhdr, ARGUS_NOLOCK);
                  ns->qhdr.lasttime = lasttime;
               }

            } else {
               struct RaBinProcessStruct *rbps;
               int i, y;

               if ((rbps = ns->bins) != NULL) {
                  ArgusProcessBins (ns, rbps);
                  if (rbps->status & RA_DIRTYBINS) {
                     ArgusZeroRecord (ns);
                     for (i = rbps->index; i < rbps->arraylen; i++) {
                        struct RaBinStruct *bin;
                        if (((bin = rbps->array[i]) != NULL) && (bin->agg->queue != NULL)) {
                           struct ArgusRecordStruct *tns  = (struct ArgusRecordStruct *)bin->agg->queue->start;
                           for (y = 0; y < bin->agg->queue->count; y++) {
                              ArgusMergeRecords (ArgusParser->ArgusAggregator, ns, tns);
                              tns = (struct ArgusRecordStruct *)tns->qhdr.nxt;
                           }
                        }
                     }

                     ns->status |= ARGUS_RECORD_MODIFIED;
                     rbps->status &= ~RA_DIRTYBINS;
                     retn++;
                  }
               }
               ArgusAddToQueue (queue, &ns->qhdr, ARGUS_NOLOCK);
               ns->qhdr.lasttime = lasttime;
            }
         }
      }

      if (deleted) {
         if (ArgusParser->RaCursesMode)
            RaClientSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);
         else
            RaClientSortQueue(ArgusSorter, queue, ARGUS_NOLOCK | ARGUS_NOSORT);
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock);
#endif
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (5, "ArgusProcessQueue (%p, %d) returning %d", queue, status, retn); 
#endif

   return (retn);
}

int
ArgusCorrelateQueue (struct ArgusQueueStruct *queue)
{
   struct timeval tbuf, *tvp = &tbuf;
   struct ArgusRecordStruct *ns;
   int retn = 0, x, z, count;
   struct timeval lasttime;

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&queue->lock);
#endif
   count = queue->count;
   for (x = 0, z = count; x < z; x++) {
      if ((ns = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
         lasttime = ns->qhdr.lasttime;
         *tvp = lasttime;
         ArgusCorrelateRecord(ns);
         ArgusAddToQueue (queue, &ns->qhdr, ARGUS_NOLOCK);
         ns->qhdr.lasttime = lasttime;
      }
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&queue->lock);
#endif

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "ArgusCorrelateQueue (0x%x) returning %d", queue, retn); 
#endif

   return (retn);
}


int
ArgusCorrelateRecord (struct ArgusRecordStruct *ns)
{
   int retn = 0;

   if (ns != NULL) {
      struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;
      struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
      struct ArgusRecordStruct *cns = ArgusCopyRecordStruct(ns);
      struct ArgusRecordStruct *pns = NULL;
      struct ArgusHashStruct *hstruct = NULL;

      int found = 0;

      while (agg && !found) {
         struct nff_insn *fcode = agg->filter.bf_insns;

         if (ArgusFilterRecord (fcode, ns) != 0) {
            if (flow != NULL) {
               if ((agg->rap = RaFlowModelOverRides(agg, cns)) == NULL)
                  agg->rap = agg->drap;

               ArgusGenerateNewFlow(agg, cns);

               if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
                  ArgusLog (LOG_ERR, "RaProcessRecord: ArgusGenerateHashStruct error %s", strerror(errno));

               if ((pns = ArgusFindRecord(RaEventProcess->htable, hstruct)) == NULL) {
                  int tryreverse = 1;

                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_ESP:
                              tryreverse = 0;
                              break;
                        }
                     }
                  }

                  if (!ArgusParser->RaMonMode && tryreverse) {
                     struct ArgusRecordStruct *dns = ArgusCopyRecordStruct(ns);

                     ArgusReverseRecord (dns);

                     ArgusGenerateNewFlow(agg, dns);

                     if ((hstruct = ArgusGenerateHashStruct(agg, dns, flow)) == NULL)
                        ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                     if ((pns = ArgusFindRecord(RaEventProcess->htable, hstruct)) != NULL) {
                        ArgusDeleteRecordStruct(ArgusParser, cns);
                        cns = dns;
                        found++;

                     } else {
                        ArgusDeleteRecordStruct(ArgusParser, dns);
                        if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
                           ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));
                     }
                  }

               } else
                  found++;
            }
         }
         agg = agg->nxt;
      }

      if (found && (pns != NULL)) {
         struct ArgusLabelStruct *l1 = (void *) ns->dsrs[ARGUS_LABEL_INDEX];
         struct ArgusLabelStruct *l2 = (void *) pns->dsrs[ARGUS_LABEL_INDEX];

         if (l1 && l2) {
            if (strcmp(l1->l_un.label, l2->l_un.label)) {
               char buf[MAXSTRLEN], *label = NULL;
               bzero(buf, sizeof(buf));

               if ((label = ArgusMergeLabel(l1, l2, buf, MAXSTRLEN, ARGUS_UNION)) != NULL) {
                  int slen = strlen(label);
                  int len = 4 * ((slen + 3)/4);

                  if (l1->l_un.label != NULL)
                     free(l1->l_un.label);

                  if ((l1->l_un.label = calloc(1, len)) == NULL)
                     ArgusLog (LOG_ERR, "RaProcessRecord: calloc error %s", strerror(errno));

                  l1->hdr.argus_dsrvl8.len = 1 + ((len + 3)/4);
                  bcopy (label, l1->l_un.label, strlen(label));
               }
            }
#if defined(ARGUSDEBUG)
            ArgusDebug (4, "ArgusCorrelateRecord (0x%x) merged label", pns); 
#endif

         } else {
            if (l2 && (l1 == NULL)) {
               ns->dsrs[ARGUS_LABEL_INDEX] = calloc(1, sizeof(struct ArgusLabelStruct));
               l1 = (void *) ns->dsrs[ARGUS_LABEL_INDEX];

               bcopy(l2, l1, sizeof(*l2));

               if (l2->l_un.label)
                  l1->l_un.label = strdup(l2->l_un.label);
#if defined(ARGUSDEBUG)
               ArgusDebug (4, "ArgusCorrelateRecord (0x%x) added label", pns); 
#endif
            }
         }

         pns->status |= ARGUS_RECORD_MODIFIED;
      }

      ArgusDeleteRecordStruct(ArgusParser, cns);
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "ArgusCorrelateRecord (0x%x) returning %d", ns, retn); 
#endif

   return (retn);
}


struct RaOutputProcessStruct *
RaCursesNewProcess(struct ArgusParserStruct *parser)
{
   struct RaOutputProcessStruct *retn = NULL;

   if ((retn = (struct RaOutputProcessStruct *) ArgusCalloc (1, sizeof(*retn))) != NULL) {
      if ((retn->queue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "RaCursesNewProcess: ArgusNewQueue error %s\n", strerror(errno));

      if ((retn->delqueue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "RaCursesNewProcess: ArgusNewQueue error %s\n", strerror(errno));

      if ((retn->htable = ArgusNewHashTable(0x100000)) == NULL)
         ArgusLog (LOG_ERR, "RaCursesNewProcess: ArgusCalloc error %s\n", strerror(errno));

   } else
      ArgusLog (LOG_ERR, "RaCursesNewProcess: ArgusCalloc error %s\n", strerror(errno));

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaCursesNewProcess(0x%x) returns 0x%x\n", parser, retn);
#endif
   return (retn);
}


 
void
RaClientSortQueue (struct ArgusSorterStruct *sorter, struct ArgusQueueStruct *queue, int type)
{
   struct nff_insn *fcode = NULL;
   int cnt, x = 0;

#if defined(ARGUS_THREADS)
   if (type & ARGUS_LOCK)
      pthread_mutex_lock(&queue->lock);
#endif

   cnt = queue->count;

   if (queue->array != NULL) {
      ArgusFree(queue->array);
      queue->array = NULL;
   }

   if (cnt > 0) {
      fcode = sorter->filter.bf_insns;
      if ((queue->array = (struct ArgusQueueHeader **) ArgusCalloc(1, sizeof(struct ArgusQueueHeader *) * (cnt + 1))) != NULL) {
         struct ArgusQueueHeader *qhdr = queue->start;
         int i = 0;

         for (i = 0; i < cnt; i++) {
            int keep = 1;
            if (fcode) {
               if (ArgusFilterRecord (fcode, (struct ArgusRecordStruct *)qhdr) == 0)
                  keep = 0;
            }
      
            if (keep)
               queue->array[x++] = qhdr;
            qhdr = qhdr->nxt;
         }

         queue->array[i] = NULL;

         if (!(type & ARGUS_NOSORT)) {
            qsort ((char *) queue->array, x, sizeof (struct ArgusQueueHeader *), ArgusSortRoutine);

            for (i = 0; i < x; i++) {
               struct ArgusRecordStruct *ns = (struct ArgusRecordStruct *) queue->array[i];
               if (ns->rank != (i + 1)) {
                  ns->rank = i + 1;
                  ns->status |= ARGUS_RECORD_MODIFIED;
               }
            }
         }

      } else 
         ArgusLog (LOG_ERR, "RaClientSortQueue: ArgusMalloc(%d) %s\n", sizeof(struct ArgusRecord *), cnt, strerror(errno));
   }

   RaSortItems = x;
   bzero (&ArgusParser->ArgusStartTimeVal, sizeof(ArgusParser->ArgusStartTimeVal));

#if defined(ARGUS_THREADS)
   if (type & ARGUS_LOCK)
      pthread_mutex_unlock(&queue->lock);
#endif

#ifdef ARGUSDEBUG 
   ArgusDebug (5, "RaClientSortQueue(0x%x, 0x%x, %d) returned\n", sorter, queue, type);
#endif
}

