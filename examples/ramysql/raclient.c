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
 *  rasqlinsert  -  mysql database table management system.  this is ratop's
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

#include <argus_threads.h>
#include <argus_compat.h>
#include <sys/wait.h>

#include <rasqlinsert.h>
#include <argus_output.h>

#define RA_IDLE                 0
#define RA_ACTIVE               1
#define RA_SORTING              2

#define ARGUS_PROCESS_NOW	0x01

#define ARGUS_RECORD_MODIFIED   0x0100
#define ARGUS_RECORD_CLEARED    0x0200

#define ARGUS_SQL_INSERT        0x0100000
#define ARGUS_SQL_SELECT        0x0200000
#define ARGUS_SQL_UPDATE        0x0400000
#define ARGUS_SQL_DELETE        0x0800000
#define ARGUS_SQL_REWRITE       0x1000000

#define ARGUS_SQL_STATUS        (ARGUS_SQL_INSERT | ARGUS_SQL_SELECT | \
                                 ARGUS_SQL_UPDATE | ARGUS_SQL_DELETE | \
                                 ARGUS_SQL_REWRITE)

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <rasqlinsert.h>
#include <rabins.h>

#if defined(HAVE_ZLIB_H)
#include <zlib.h>
#endif

void RaClientSortQueue (struct ArgusSorterStruct *, struct ArgusQueueStruct *, int);
void ArgusShiftArray (struct ArgusParserStruct *, struct RaBinProcessStruct *, int, int);

#if defined(ARGUS_MYSQL)
# include "argus_mysql.h"

int ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, int);
struct ArgusRecordStruct *RaLookupDBCache (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, struct ArgusHashStruct *);

extern char RaSQLSaveTable[];
extern char *ArgusGetSQLSaveTable();

extern int RaSQLDBDeletes;
extern int ArgusDropTable;
extern int ArgusCreateTable;
extern int RaSQLCacheDB;
extern int RaSQLRewrite;

extern long long ArgusTotalSQLSearches;
extern long long ArgusTotalSQLUpdates;
extern long long ArgusTotalSQLWrites;

extern int ArgusSOptionRecord;

extern pthread_mutex_t RaMySQLlock;
extern MYSQL *RaMySQL;


#endif

int ArgusCreateSQLSaveTable(char *, char *);
char *ArgusCreateSQLSaveTableName (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *, char *, int);

void ArgusThreadsInit(pthread_attr_t *);

extern int ArgusCloseDown;

int ArgusProcessQueue (struct RaBinStruct *, struct ArgusQueueStruct *, int status);
void ArgusGetInterfaceAddresses(struct ArgusParserStruct *);
int ArgusCorrelateRecord (struct ArgusRecordStruct *);
int ArgusCorrelateQueue (struct ArgusQueueStruct *);

int RaCloseBinProcess(struct ArgusParserStruct *, struct RaBinProcessStruct *);

extern struct ArgusRecordStruct *ArgusCheckSQLCache(struct ArgusParserStruct *, struct RaBinStruct *, struct ArgusRecordStruct *);

struct timeval RaCursesUpdateInterval = {5, 0};

int argus_version = ARGUS_VERSION;

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
   struct ArgusParserStruct *parser = ArgusParser;

   while (parser == NULL) {
      struct timespec ts = {0, 250000000};
      nanosleep (&ts, NULL);
      parser = ArgusParser;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusProcessData() starting");
#endif

#if defined(ARGUS_THREADS)

   if (parser->ArgusInputFileList == NULL)
      parser->status |= ARGUS_FILE_LIST_PROCESSED;

   while (!ArgusCloseDown && !parser->RaParseDone) {
      if (parser->RaTasksToDo) {
         struct ArgusInput *input = NULL;
         struct ArgusFileInput *file = NULL;
         int hosts = 0;
         char sbuf[1024];

         sprintf (sbuf, "ArgusProcessData() Processing.");
         ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);

         RaCursesStartTime.tv_sec  = 0;
         RaCursesStartTime.tv_usec = 0;
         RaCursesStopTime.tv_sec   = 0;
         RaCursesStopTime.tv_usec  = 0;

         /* Process the input files first */

         if ((!(parser->status & ARGUS_FILE_LIST_PROCESSED)) && ((file = parser->ArgusInputFileList) != NULL)) {
            while (file && parser->eNflag) {
               if ((input = ArgusMalloc(sizeof(*input))) == NULL)
                  ArgusLog(LOG_ERR, "unable to allocate input structure\n");

               ArgusInputFromFile(input, file);
               ArgusParser->ArgusCurrentInput = input;

               if (strcmp (input->filename, "-")) {
                  if (file->fd < 0) {
                     if ((input->file = fopen(input->filename, "r")) == NULL) {
                        sprintf (sbuf, "open '%s': %s", input->filename, strerror(errno));
                        ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);
                     }

                  } else {
                     fseek(input->file, 0, SEEK_SET);
                  }

                  if ((input->file != NULL) && ((ArgusReadConnection (parser, input, ARGUS_FILE)) >= 0)) {
                     parser->ArgusTotalMarRecords++;
                     parser->ArgusTotalRecords++;

                     if (parser->RaPollMode) {
                         ArgusHandleRecord (parser, input, &input->ArgusInitCon, 0, &parser->ArgusFilterCode);
                     } else {
                        if (input->ostart != -1) {
                           input->offset = input->ostart;
                           if (fseek(input->file, input->offset, SEEK_SET) >= 0)
                              ArgusReadFileStream(parser, input);
                        } else
                           ArgusReadFileStream(parser, input);
                     }

                     sprintf (sbuf, "RaCursesLoop() Processing Input File %s done.", input->filename);
                     ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);

                  } else {
                     input->fd = -1;
                     sprintf (sbuf, "ArgusReadConnection '%s': %s", input->filename, strerror(errno));
                     ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
                  }

                  if (input->file != NULL)
                     ArgusCloseInput(parser, input);

               } else {
                  input->file = stdin;
                  input->ostart = -1;
                  input->ostop = -1;

                  if (((ArgusReadConnection (parser, input, ARGUS_FILE)) >= 0)) {
                     parser->ArgusTotalMarRecords++;
                     parser->ArgusTotalRecords++;
                     fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);
                     ArgusReadFileStream(parser, input);
                  }
               }

               RaArgusInputComplete(input);
               ArgusParser->ArgusCurrentInput = NULL;
               ArgusDeleteInput(ArgusParser, input);
               file = (struct ArgusFileInput *)file->qhdr.nxt;
            }

            parser->ArgusCurrentInput = NULL;
            parser->status |= ARGUS_FILE_LIST_PROCESSED;
         }

         input = NULL;

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
                              ArgusHandleRecord (parser, input, &input->ArgusInitCon, 0, &parser->ArgusFilterCode);

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
            parser->RaParseDone++;
#else
            parser->RaParseDone++;
#endif
         }

         if (parser->ArgusReliableConnection || parser->ArgusActiveHosts) {
            unsigned int count = 0;
            if (MUTEX_LOCK(&parser->ArgusActiveHosts->lock) == 0) {
               count = parser->ArgusActiveHosts->count;
               MUTEX_UNLOCK(&parser->ArgusActiveHosts->lock);
            }

            if (count)
               ArgusReadStream(parser, parser->ArgusActiveHosts);
         }

         parser->RaTasksToDo = RA_IDLE;

      } else {
         struct timespec ts = {0, 200000000};
         gettimeofday (&parser->ArgusCurrentTime, 0L);
         nanosleep (&ts, NULL);

         if (parser->ArgusActiveHosts) {
            unsigned int count = 0;
            if (MUTEX_LOCK(&parser->ArgusActiveHosts->lock) == 0) {
               count = parser->ArgusActiveHosts->count;
               MUTEX_UNLOCK(&parser->ArgusActiveHosts->lock);
            }
            if (count)
              parser->RaTasksToDo = RA_ACTIVE;
         }
      }

      ArgusClientTimeout ();
   }


   {
      struct RaBinProcessStruct *rbps = RaBinProcess;

      if (rbps != NULL) {
         if (MUTEX_LOCK(&rbps->lock) == 0) {
            int i, max = ((parser->tflag && !parser->RaWildCardDate) ? rbps->nadp.count : rbps->max) + 1;
            struct RaBinStruct *bin = NULL;

#ifdef ARGUSDEBUG
            ArgusDebug (1, "ArgusProcessData: flushing sql queues\n");
#endif

            for (i = rbps->index; i < max; i++) {
               if ((rbps->array != NULL) && ((bin = rbps->array[i]) != NULL)) {
                  ArgusProcessQueue(bin, bin->agg->queue, ARGUS_STATUS);
               }
            }
            MUTEX_UNLOCK(&rbps->lock);
         }
      }
   }

   ArgusCloseDown = 1;
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
   int correct = -1, preserve = 1;
   int i = 0, size = 1;

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&RaCursesLock, NULL);
#endif

   if (parser != NULL) {
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

         if (parser->ver3flag)
            argus_version = ARGUS_VERSION_3;

         if ((parser->ArgusMaskList) == NULL)
            parser->ArgusReverse = 1;
         else
            parser->ArgusReverse = 0;

         parser->timeout.tv_sec  = 60;
         parser->timeout.tv_usec = 0;

         parser->RaClientTimeout.tv_sec  = 1;
         parser->RaClientTimeout.tv_usec = 0;

         parser->RaInitialized++;
         parser->ArgusPrintXml = 0;

         parser->NonBlockingDNS = 1;
         parser->RaCumulativeMerge = 1;

         if (parser->timeout.tv_sec == -1) {
            parser->timeout.tv_sec  = 60;
            parser->timeout.tv_usec = 0;
         }

         if (parser->ArgusInputFileList != NULL) {
            parser->RaTasksToDo = RA_ACTIVE;
            if (parser->ArgusRemoteHosts) {
               if ((input = (void *)parser->ArgusRemoteHosts->start) == NULL) {
                  parser->timeout.tv_sec  = 0;
                  parser->timeout.tv_usec = 0;
               }
            }
         }

         if (parser->vflag)
            ArgusReverseSortDir++;

         if ((ArgusSorter = ArgusNewSorter(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewSorter error %s", strerror(errno));

         ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortAlgorithmTable[ARGUSSORTPKTSCOUNT];
         if (RaBinProcess == NULL) {
            if ((RaBinProcess = RaNewBinProcess(parser, 256)) == NULL)
               ArgusLog (LOG_ERR, "ArgusClientInit: RaNewBinProcess error %s", strerror(errno));
         }

         if ((mode = parser->ArgusModeList) != NULL) {
            int i, x, ind;

            while (mode) {
               for (i = 0, ind = -1; i < ARGUSSPLITMODENUM; i++) {
                  if (!(strncasecmp (mode->mode, RaSplitModes[i], strlen(RaSplitModes[i])))) {
                     nadp = &RaBinProcess->nadp;

                     nadp->mode   = -1;
                     nadp->modify =  1;
                     nadp->slen   =  2;
   
                     if (parser->aflag)
                        nadp->slen = parser->aflag;

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

                        RaBinProcess->rtime.tv_sec = tsec;

                        if (RaCursesRealTime)
                           nadp->start.tv_sec = 0;
/*
                        if (ArgusSorter->ArgusSortAlgorithms[0] == NULL) {
                           ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;
                           ArgusSorter->ArgusSortAlgorithms[1] = NULL;
                        }
*/
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

                  RaBinProcess->size = nadp->size;

                  if (nadp->mode < 0) {
                     nadp->mode = ARGUSSPLITCOUNT;
                     nadp->value = 10000;
                     nadp->count = 1;
                  }

               } else {
                  if (!strncasecmp (mode->mode, "rewrite", 7)) {
                     parser->RaCumulativeMerge = 0;
                     RaSQLRewrite = 1;
                     RaSQLDBDeletes = 0;
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
                     correct = 0;
                     if (parser->ArgusAggregator && (parser->ArgusAggregator->correct != NULL)) {
                        free(parser->ArgusAggregator->correct);
                        parser->ArgusAggregator->correct = NULL;
                     }
                  }
                  if (!(strncasecmp (mode->mode, "oui", 3)))
                     parser->ArgusPrintEthernetVendors++;
                  else
                  if (!(strncasecmp (mode->mode, "nocorrect", 9))) {
                     correct = 0;
                     parser->ArgusPerformCorrection = 0;
                  } else
                  if (!(strncasecmp (mode->mode, "correct", 7))) {
                     correct = 1;
                     parser->ArgusPerformCorrection = 1;
                  } else
                  if (!(strncasecmp (mode->mode, "preserve", 8))) {
                     preserve = 1;
                  } else
                  if (!(strncasecmp (mode->mode, "nocolor", 7))) {
                     parser->ArgusColorSupport = 0;
                  } else
                  if (!(strncasecmp (mode->mode, "nopreserve", 10))) {
                     preserve = 0;
                  } else
                  if (!(strncasecmp (mode->mode, "nocurses", 4))) {
                    ArgusCursesEnabled = 0;
                  } else
                  if (!(strncasecmp (mode->mode, "control:", 8))) {
                     char *ptr = &mode->mode[8];
                     double value = 0.0;
                     char *endptr = NULL;
                     value = strtod(ptr, &endptr);
                     if (ptr != endptr) {
                        parser->ArgusControlPort = value;
                     }
                  } else
                  if (!(strncasecmp (mode->mode, "nocontrol", 9))) {
                     parser->ArgusControlPort = 0;
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
                  } else
                     if ((!(strncasecmp (mode->mode, "debug.tree", 10))) ||
                         (!(strncasecmp (mode->mode, "debug", 5)))) {

                        extern int RaPrintLabelTreeLevel;

                        if (parser->ArgusLocalLabeler &&  parser->ArgusLocalLabeler->ArgusAddrTree) {
                           parser->ArgusLocalLabeler->RaPrintLabelTreeMode = ARGUS_TREE;
                           parser->ArgusLocalLabeler->status |= ARGUS_TREE_DEBUG;

                           if (parser->Lflag > 0)
                              RaPrintLabelTreeLevel = parser->Lflag;
                        }
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

         if (RaSQLRewrite) {
            /* If rewriting tables, make sure there are no contradictory
             * cmdline parameters.
             */
            if (RaSQLCacheDB)
               ArgusLog(LOG_ERR, "cache and rewrite modes are mutually exclusive\n");
            if (ArgusDropTable)
               ArgusLog(LOG_ERR, "drop and rewrite modes are mutually exclusive\n");
            if (parser->ArgusRemoteHosts) {
               MUTEX_LOCK(&parser->ArgusRemoteHosts->lock);
               if (parser->ArgusRemoteHosts->count > 0)
                  ArgusLog(LOG_ERR, "cannot rewrite records from remote host\n");
               MUTEX_UNLOCK(&parser->ArgusRemoteHosts->lock);
            }
            if (parser->ArgusInputFileCount > 0)
               ArgusLog(LOG_ERR, "cannot rewrite records from file.\n");

            if (parser->sflag)
               ArgusLog(LOG_WARNING, "Fields specified with -s ignored during rewrite\n");

            /* Read and write from the same table(s) */
            if (parser->readDbstr)
               free(parser->readDbstr);
            parser->readDbstr = strdup(parser->writeDbstr);
            ArgusAddFileList (parser, parser->readDbstr, ARGUS_DATA_SOURCE, -1, -1);

            if (parser->ArgusFlowModelFile)
               ArgusLog(LOG_WARNING, "Aggregation config using -f option ignored during rewrite\n");

            if (parser->ArgusMaskList != NULL)
               ArgusLog(LOG_WARNING, "Fields specified with -m ignored during rewrite\n");
         }

         if (parser->ArgusFlowModelFile)
            parser->ArgusAggregator = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL);
         else {
            if (parser->ArgusMaskList != NULL)
               parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR);
            else
               parser->ArgusAggregator = ArgusNewAggregator(parser, "sid saddr daddr proto sport dport", ARGUS_RECORD_AGGREGATOR);
         }

         if (parser->ArgusAggregator != NULL) {
            if (correct >= 0) {
               if (correct == 0) {
                  if (parser->ArgusAggregator->correct != NULL)
                     free(parser->ArgusAggregator->correct);
                  parser->ArgusAggregator->correct = NULL;
                  parser->ArgusPerformCorrection = 0;
               } else {
                  if (parser->ArgusAggregator->correct != NULL)
                     free(parser->ArgusAggregator->correct);
                  parser->ArgusAggregator->correct = strdup("yes");
                  parser->ArgusPerformCorrection = 1;
               }
            }

            if (preserve == 0) {
               if (parser->ArgusAggregator->pres != NULL)
                  free(parser->ArgusAggregator->pres);
               parser->ArgusAggregator->pres = NULL;
            } else {
               if (parser->ArgusAggregator->pres != NULL)
                  free(parser->ArgusAggregator->pres);
               parser->ArgusAggregator->pres = strdup("yes");
            }

         } else {
            parser->RaCumulativeMerge = 0;
            bzero(parser->RaSortOptionStrings, sizeof(parser->RaSortOptionStrings));
            parser->RaSortOptionIndex = 0;
//          parser->RaSortOptionStrings[parser->RaSortOptionIndex++] = "stime";
         }

         if (parser->ArgusRemoteHosts)
            if ((input = (void *)parser->ArgusRemoteHosts->start) != NULL)
               parser->RaTasksToDo = RA_ACTIVE;

         if ((ArgusEventAggregator = ArgusNewAggregator(parser, "sid saddr daddr proto sport dport", ARGUS_RECORD_AGGREGATOR)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

         if ((ArgusInput = (struct ArgusInput *) ArgusCalloc (1, sizeof(struct ArgusInput))) != NULL) {
            ArgusInput->ArgusOriginal = (struct ArgusRecord *)&ArgusInput->ArgusOriginalBuffer;
            ArgusInput->fd = -1;
         }

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

         if (parser->ArgusAggregator != NULL)
            if (ArgusSorter->ArgusSortAlgorithms[0] == NULL)
               ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortAlgorithmTable[ARGUSSORTPKTSCOUNT];

         /* if content substitution, either time or any field, is used,
            size and count modes will not work properly.  If using
            the default count, set the value so that we generate only
            one filename.

            if no substitution, then we need to add "aa" suffix to the
            output file for count and size modes.
         */

         if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList))))
            ArgusLog(LOG_ERR, "-w option not supported.");

         for (i = 0; i < MAX_PRINT_ALG_TYPES; i++)
            if (parser->RaPrintAlgorithmList[i] != NULL)
               if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintIdleTime)
                  ArgusAlwaysUpdate++;

         if ((parser->ArgusUpdateInterval.tv_sec > 0) || (parser->ArgusUpdateInterval.tv_usec > 0)) {
            RaCursesUpdateInterval.tv_sec  = parser->ArgusUpdateInterval.tv_sec;
            RaCursesUpdateInterval.tv_usec = parser->ArgusUpdateInterval.tv_usec;
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

         if (parser->ArgusLocalLabeler && (parser->ArgusLocalLabeler->status & ARGUS_TREE_DEBUG)) {
            RaPrintLabelTree (parser->ArgusLocalLabeler, parser->ArgusLocalLabeler->ArgusAddrTree[AF_INET], 0, 0);
            exit(0);
         }

/*
         if (parser->ArgusControlPort != 0) {
            if ((parser->ArgusControlChannel = ArgusNewControlChannel (parser)) == NULL)
               ArgusLog (LOG_ERR, "could not create control channel: %s\n", strerror(errno));

            if (ArgusEstablishListen (parser, parser->ArgusControlChannel,
                                      parser->ArgusControlPort, "127.0.0.1",
                                      ARGUS_VERSION) < 0)
               ArgusLog (LOG_ERR, "setArgusPortNum: ArgusEstablishListen returned %s", strerror(errno));

            tvp = getArgusMarReportInterval(ArgusParser);
            if ((tvp->tv_sec == 0) && (tvp->tv_usec == 0)) {
               setArgusMarReportInterval (ArgusParser, "60s");
            }

            ArgusControlCommands[CONTROL_DISPLAY].handler = ArgusHandleDisplayCommand;
            ArgusControlCommands[CONTROL_HIGHLIGHT].handler = ArgusHandleHighlightCommand;
            ArgusControlCommands[CONTROL_SEARCH].handler = ArgusHandleControllerCommand;
            ArgusControlCommands[CONTROL_FILTER].handler = ArgusHandleControllerCommand;
         }
*/
         parser->ArgusReliableConnection = 1;
         parser->ArgusPrintJson = 0;

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
                  int status;
                  struct timespec ts = {0, 20000000};

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


void RaArgusInputComplete (struct ArgusInput *input) { }



int
RaCloseBinProcess(struct ArgusParserStruct *parser, struct RaBinProcessStruct *rbps)
{
   int retn = 0;

   if (rbps != NULL) {
      struct RaBinStruct *bin = NULL;
      int max = 0, i;

      MUTEX_LOCK(&rbps->lock);

      max = ((parser->tflag && !parser->RaWildCardDate) ? rbps->nadp.count : rbps->max) + 1;

      for (i = rbps->index; i < max; i++) {
         if ((rbps->array != NULL) && ((bin = rbps->array[i]) != NULL)) {
            ArgusProcessQueue(bin, bin->agg->queue, ARGUS_STOP);
            RaDeleteBin(parser, rbps, i);
         }
      }
/*
      if (!(parser->Sflag)) {
         sprintf (sbuf, "UNLOCK TABLES");
         if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
            ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));
      }
*/
      MUTEX_UNLOCK(&rbps->lock);
   }

   return (retn);
}



void
RaParseComplete (int sig)
{

   if (sig >= 0) {
      if (ArgusParser && !ArgusParser->RaParseCompleting++) {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "RaParseComplete(caught signal %d)\n", sig);
#endif

         ArgusProcessSqlData(RaCurrentWindow);

         if (RaBinProcess != NULL) {
            RaCloseBinProcess(ArgusParser, RaBinProcess);
            RaDeleteBinProcess(ArgusParser, RaBinProcess);
            RaBinProcess = NULL;
         }

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


struct timeval RaProcessQueueTimer = {2, 0};
struct timeval RaProcessDebugTimer = {0, 0};

void
ArgusClientTimeout ()
{
   struct timeval tvbuf, *tvp = &tvbuf;

   if (!(ArgusParser->Pauseflag)) {
      gettimeofday(&ArgusParser->ArgusRealTime, 0);
      ArgusAdjustGlobalTime (ArgusParser, NULL);
   }

   *tvp = ArgusParser->ArgusGlobalTime;

   if (ArgusParser->Sflag) {
      if (RaProcessDebugTimer.tv_sec != 0) {
         if (RaProcessDebugTimer.tv_sec == tvp->tv_sec) {
#if defined(ARGUSDEBUG)
            ArgusDebug (4, "%s: ArgusTotalSQLUpdates %lld written %lld bytes\n", __func__, ArgusTotalSQLUpdates, ArgusTotalSQLWrites);
#endif
            RaProcessDebugTimer.tv_sec += 5;
         } else
         if (RaProcessDebugTimer.tv_sec < tvp->tv_sec)
            RaProcessDebugTimer.tv_sec = tvp->tv_sec + 5;
      } else
         RaProcessDebugTimer.tv_sec = tvp->tv_sec + 5;

      if (ArgusParser->RaClientUpdate.tv_sec != 0) {
         int last = 0;
         if (((ArgusParser->RaClientUpdate.tv_sec < tvp->tv_sec) ||
             ((ArgusParser->RaClientUpdate.tv_sec == tvp->tv_sec) &&
              (ArgusParser->RaClientUpdate.tv_usec < tvp->tv_usec)))) {

            
            if ((RaBinProcess != NULL) && (RaBinProcess->array != NULL)) {
               struct RaBinProcessStruct *rbps = RaBinProcess;
               if (MUTEX_LOCK(&rbps->lock) == 0) {
                  int max = ((ArgusParser->tflag && !ArgusParser->RaWildCardDate) ? rbps->nadp.count : rbps->max) + 1;
                  struct RaBinStruct *bin = NULL;
                  int i, deleted = 0;


                  for (i = RaBinProcess->index; i < max; i++) {
                     if ((RaBinProcess->array != NULL) && ((bin = RaBinProcess->array[i]) != NULL)) {
                        ArgusProcessQueue(bin, bin->agg->queue, ARGUS_STATUS);
                        if (ArgusParser->Bflag > 0) {
                           if ((bin->etime.tv_sec + ArgusParser->Bflag) < tvp->tv_sec) {
#ifdef ARGUSDEBUG
                              ArgusDebug (2, "ArgusClientTimeout: deleting time bin %p\n", bin);
#endif
                              RaDeleteBin(ArgusParser, RaBinProcess, i);
                              deleted++;
                           }
                        }
                     }
                  }

                  if (deleted)
                     ArgusShiftArray(ArgusParser, rbps, 1, ARGUS_NOLOCK);

                 MUTEX_UNLOCK(&RaBinProcess->lock);
               }
            }

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
   }

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
   fprintf (stdout, "                  InnoDB        default\n");
   fprintf (stdout, "                  MyISAM        \n");
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
      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
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
            ArgusDeleteRecordStruct(parser, tns), tns = NULL;

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
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
   struct ArgusDataStruct *data = NULL;
   int found = 0, offset;

   extern int ArgusTimeRangeStrategy;

   if (ArgusParser->RaClientUpdate.tv_sec == 0) {
      ArgusParser->RaClientUpdate.tv_sec = parser->ArgusGlobalTime.tv_sec;
      ArgusParser->RaClientUpdate.tv_usec = 0;
   }

   if (RaCursesStartTime.tv_sec == 0)
      gettimeofday (&RaCursesStartTime, 0L);

   gettimeofday (&RaCursesStopTime, 0L);
   argus->status |= ARGUS_RECORD_MODIFIED;

   if (argus->dsrs[ARGUS_SRCUSERDATA_INDEX] || argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) {
      if ((data = (void *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) != NULL) {
         if (data->size > 2048) {
            data->size  = (data->size > 2048) ? 2048 : data->size;
            data->count = (data->count > 2048) ? 2048 : data->count;
            data->hdr.argus_dsrvl16.len = ((data->size + 3)/4) + 2;
            argus->status |= ARGUS_RECORD_MODIFIED;
         }
      }
      if ((data = (void *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) != NULL) {
         if (data->size > 2048) {
            data->size  = (data->size > 2048) ? 2048 : data->size;
            data->count = (data->count > 2048) ? 2048 : data->count;
            data->hdr.argus_dsrvl16.len = ((data->size + 3)/4) + 2;
            argus->status |= ARGUS_RECORD_MODIFIED;
         }
      }
   }

   if ((agg != NULL) && (parser->RaCumulativeMerge)) {
      while (agg && !found) {
         int tretn = 0, fretn = -1, lretn = -1;

         if (ArgusParser->tflag) {
            ArgusTimeRangeStrategy = 1;
         }

         if (agg->filterstr) {
            struct nff_insn *fcode = agg->filter.bf_insns;
            fretn = ArgusFilterRecord (fcode, argus);
         }

         switch (argus->hdr.type & 0xF0) {
            default:
            case ARGUS_EVENT:
            case ARGUS_MAR:
            case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
            case ARGUS_FAR: {
               if (agg->grepstr) {
                  struct ArgusLabelStruct *label;
                  if (((label = (void *)argus->dsrs[ARGUS_LABEL_INDEX]) != NULL)) {
                     if (regexec(&agg->lpreg, label->l_un.label, 0, NULL, 0))
                        lretn = 0;
                     else
                        lretn = 1;
                  } else
                     lretn = 0;
               }
               break;
            }
         }

         tretn = (lretn < 0) ? ((fretn < 0) ? 1 : fretn) : ((fretn < 0) ? lretn : (lretn && fretn));

         if (tretn != 0) {
            struct ArgusRecordStruct *tns = NULL, *ns = NULL;

            ns = ArgusCopyRecordStruct(argus);

            if (agg->labelstr)
               ArgusAddToRecordLabel(parser, ns, agg->labelstr);

            ArgusAlignInit(parser, ns, &RaBinProcess->nadp);

            offset = (ArgusParser->Bflag * 1000000)/RaBinProcess->nadp.size;

            while ((!(ns->status & ARGUS_RECORD_PROCESSED)) && ((tns = ArgusAlignRecord(parser, ns, &RaBinProcess->nadp)) != NULL)) {
               if ((tretn = ArgusCheckTime (parser, tns, ArgusTimeRangeStrategy)) != 0) {
                  struct ArgusRecordStruct *rec = NULL;

                  switch (ns->hdr.type & 0xF0) {
                     case ARGUS_EVENT:
                     case ARGUS_MAR:
                        break;

/*
   The concept is that we track database records within a bin that
   maps to a database table, based on the name, wildcards, etc ...

   We manage the records within the bin, and let someone else, do
   the bin to database table cache concurrency.
*/
                     case ARGUS_NETFLOW:
                     case ARGUS_AFLOW:
                     case ARGUS_FAR: {
                        struct ArgusMetricStruct *metric = (void *)tns->dsrs[ARGUS_METRIC_INDEX];

                        if ((metric != NULL) && ((metric->src.pkts + metric->dst.pkts) > 0)) {
                           if (ArgusInsertRecord(parser, RaBinProcess, tns, offset, &rec) > 0) {
#if defined(ARGUS_MYSQL)
                              if (rec != NULL) {
                                 struct RaBinStruct *bin = rec->bin;
                                 struct ArgusRecordStruct *cns = NULL;

                                 if (bin->table == NULL) {
                                    char *table;
                                    if ((strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$'))) {
                                       char tbuf[1024], stable[MAXSTRLEN];
                                       if ((table = ArgusCreateSQLSaveTableName(ArgusParser, ns, RaSQLSaveTable, tbuf, 1024)) != NULL) {
                                          ArgusCreateSQLSaveTable(RaDatabase, table);
                                          sprintf (stable, "%s.%s", RaDatabase, table);
                                          bin->table = strdup(stable);

                                       } else
                                          ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCreateSQLSaveTableName error", strerror(errno));

                                    } else {
                                       bin->table = strdup(RaSQLSaveTable);
                                    }
/*                                  
                                    if (!(parser->Sflag)) {
                                       sprintf (sbuf, "LOCK TABLE %s WRITE", bin->table);
                                       if ((mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
                                          ArgusLog(LOG_INFO, "mysql_real_query LOCK TABLE error %s", mysql_error(RaMySQL));
                                    }
*/
                                 }
                                 if (RaSQLCacheDB) {
                                    if ((cns = ArgusCheckSQLCache(parser, rec->bin, rec)) != NULL) {
                                       ArgusMergeRecords (ArgusParser->ArgusAggregator, rec, cns);
                                       rec->status &= ~ARGUS_SQL_STATUS;
                                    } else
                                       rec->status |= ARGUS_SQL_INSERT;
                                 } else
                                    rec->status |= ARGUS_SQL_INSERT;
                              }
#endif
                           }
                        }
                        break;
                     }
                  }
               }

               if (tns)
                  ArgusDeleteRecordStruct(parser, tns);
            }
            ArgusDeleteRecordStruct(parser, ns);
            found++;
         }
         agg = agg->nxt;
      }

   } else {
      char tbuf[1024], *tbl = NULL;

// no key, so we're just inserting the record at the end of the table 

      if ((strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$'))) {
         if ((tbl = ArgusCreateSQLSaveTableName(ArgusParser, argus, RaSQLSaveTable, tbuf, 1024)) != NULL)
            ArgusCreateSQLSaveTable(RaDatabase, tbl);

      } else 
         tbl = RaSQLSaveTable;
      
      if (tbl != NULL) {
         if (RaSQLRewrite)
            argus->status |= ARGUS_SQL_REWRITE;
         else
            argus->status |= ARGUS_SQL_INSERT;
         ArgusScheduleSQLQuery (ArgusParser, ArgusParser->ArgusAggregator, argus, tbl, ARGUS_STATUS);
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (3, "ArgusProcessThisRecord () returning\n"); 
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
            agg->ArgusMaskDefs = NULL;

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
      case ARGUS_AFLOW:
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
      unsigned long len = 0x10000;
      char *dptr, *str;
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
         tbuf[0] = '\0';
         bzero (sptr, sizeof(sbuf));
         tvp->tv_sec  = time->src.start.tv_sec;
         tvp->tv_usec = time->src.start.tv_usec;

         ArgusPrintTime(parser, tbuf, sizeof(tbuf), tvp);
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


struct ArgusRecordStruct *
RaLookupDBCache (struct ArgusParserStruct *parser, struct ArgusAggregatorStruct *agg, struct ArgusRecordStruct *cns, struct ArgusHashStruct *hstruct)
{
   struct ArgusRecordStruct *pns = NULL;
   struct ArgusRecordStruct *sns = NULL;

   if (RaSQLCacheDB) {
      struct ArgusMaskStruct *ArgusMaskDefs =  ArgusSelectMaskDefs(cns);
      char *sbuf   = calloc(1, MAXBUFFERLEN);
      char *tmpbuf = calloc(1, MAXBUFFERLEN);

      int uflag, nflag = parser->nflag;
      char *ptr, *tptr;
      int retn, y, mind = 0;
      MYSQL_RES *mysqlRes;
      char tbuf[1024], *tbl;
      char ubuf[1024];

      parser->nflag = 2;

      bzero(ubuf, sizeof(ubuf));

      if (MUTEX_LOCK(&parser->lock) == 0) {
         int found = 0;
         for (parser->RaPrintIndex = 0; parser->RaPrintIndex < MAX_PRINT_ALG_TYPES; parser->RaPrintIndex++) {

            if (parser->RaPrintAlgorithmList[parser->RaPrintIndex] != NULL) {
               parser->RaPrintAlgorithm = parser->RaPrintAlgorithmList[parser->RaPrintIndex];

               found = 0;

               if (agg && agg->mask) {
                  for (y = 0; y < ARGUS_MAX_MASK_LIST; y++) {
                     if ((agg->mask & (0x01LL << y)) && ArgusMaskDefs[y].name) {
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
         MUTEX_UNLOCK(&parser->lock);
      }

      if ((tbl = ArgusCreateSQLSaveTableName(ArgusParser, cns, RaSQLSaveTable, tbuf, 1024)) != NULL) {
           char stbl[MAXSTRLEN];
           sprintf (stbl, "%s.%s", RaDatabase, tbl);

            sprintf (sbuf, "SELECT record FROM %s WHERE %s", stbl, ubuf);
            parser->nflag   = nflag;

#if defined(ARGUSDEBUG)
            ArgusDebug (3, "RaProcessThisRecord () sql query %s\n", sbuf); 
#endif
            ArgusTotalSQLSearches++;

            if (MUTEX_LOCK(&RaMySQLlock) == 0) {
               if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
                  ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));
               else {
                  if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
                     if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                        char *buf = malloc(MAXBUFFERLEN);
                        MYSQL_ROW row;
                        while ((row = mysql_fetch_row(mysqlRes))) {
                           unsigned long *lengths;
                           int x;

                           lengths = mysql_fetch_lengths(mysqlRes);
                           bzero(buf, MAXBUFFERLEN);

                           for (x = 0; x < retn; x++) {
                              bcopy (row[x], buf, (int) lengths[x]);
                              if ((((struct ArgusRecord *)buf)->hdr.type & ARGUS_FAR) ||
                                  (((struct ArgusRecord *)buf)->hdr.type & ARGUS_AFLOW) || 
                                  (((struct ArgusRecord *)buf)->hdr.type & ARGUS_NETFLOW)) {
#ifdef _LITTLE_ENDIAN
                                 ArgusNtoH((struct ArgusRecord *) buf);
#endif
                                 if ((sns = ArgusGenerateRecordStruct (ArgusParser, ArgusInput, (struct ArgusRecord *) buf)) != NULL) {
                                    if ((pns = ArgusCopyRecordStruct(sns)) != NULL) {
                                       pns->htblhdr = ArgusAddHashEntry (RaOutputProcess->htable, pns, hstruct);
                                       ArgusAddToQueue (RaOutputProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
                                       gettimeofday (&pns->qhdr.logtime, 0L);
                                    }

                                 }
                              }
                           }
                        }
                        if ( buf != NULL)   free(buf);
                     }
                     mysql_free_result(mysqlRes);
                  }
#if defined(ARGUSDEBUG)
                  ArgusDebug (3, "RaProcessThisRecord () done with sql query\n"); 
#endif
               }
               MUTEX_UNLOCK(&RaMySQLlock);
            }
            free(tbl);
      }
      if (sbuf != NULL)   free(sbuf);
      if (tmpbuf != NULL) free(tmpbuf);
   }
   return (pns);
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


int
ArgusProcessBins (struct ArgusRecordStruct *ns, struct RaBinProcessStruct *rbps)
{
   int retn = 0, count = 0;
   int cnt   = (rbps->arraylen - rbps->index);
   int dtime = cnt * rbps->size;
   int rtime = 0;

   if (rbps && (rbps->size != 0)) {
      rtime = ((((ArgusParser->ArgusGlobalTime.tv_sec * 1000000LL) /rbps->size)) * rbps->size)/1000000LL;;
      count = (rbps->end - rbps->start)/rbps->size;

      if ((rbps->startpt.tv_sec + dtime) < rtime) {
         ArgusShiftArray(ArgusParser, rbps, count, ARGUS_LOCK);
         rbps->status |= RA_DIRTYBINS;
         retn = 1;
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (2, "ArgusProcessBins (0x%x, 0x%x) count %d, dtime %d, rtime %d returning %d", ns, rbps, cnt, dtime, rtime, retn); 
#endif

   return (retn);
}

extern struct ArgusRecordStruct *ArgusSearchHitRecord;

int
ArgusProcessQueue (struct RaBinStruct *bin, struct ArgusQueueStruct *queue, int status)
{
   int retn = 0, x, z;

   if (status || ((ArgusParser->timeout.tv_sec > 0) || (ArgusParser->timeout.tv_usec > 0))) {
      struct ArgusRecordStruct *ns;
      int count;

      if (MUTEX_LOCK(&queue->lock) == 0) {
         count = queue->count;
         for (x = 0, z = count; x < z; x++) {
            if ((ns = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
#if defined(ARGUS_MYSQL)
               if (bin->table == NULL) {
                  char *table;

                  if ((strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$'))) {
                     char tbuf[1024], stable[MAXSTRLEN];
                     if ((table = ArgusCreateSQLSaveTableName(ArgusParser, ns, RaSQLSaveTable, tbuf, 1024)) == NULL)
                        return retn;

                     ArgusCreateSQLSaveTable(RaDatabase, table);
                     sprintf (stable, "%s.%s", RaDatabase, table);
                     bin->table = strdup(stable);
                  } else {
                     bin->table = strdup(RaSQLSaveTable);
                  }
               }

               if (ns && (ns->status & ARGUS_RECORD_MODIFIED)) {
                  ArgusScheduleSQLQuery (ArgusParser, bin->agg, ns, bin->table, ARGUS_STATUS);
                  ns->status &= ~ARGUS_RECORD_MODIFIED;
               }

               ArgusAddToQueue(queue, &ns->qhdr, ARGUS_NOLOCK);
#endif

/*
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
*/
            }
         }

         MUTEX_UNLOCK(&queue->lock);
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (5, "ArgusProcessQueue (%p, %p, %d) returning %d", bin, queue, status, retn); 
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

   if (queue == NULL)
      return (retn);

   if (MUTEX_LOCK(&queue->lock) == 0) {
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

      MUTEX_UNLOCK(&queue->lock);
   }

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
               agg->ArgusMaskDefs = NULL;

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

               if ((label = ArgusMergeLabel(l1->l_un.label, l2->l_un.label, buf, MAXSTRLEN, ARGUS_UNION)) != NULL) {
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

   if (type & ARGUS_LOCK)
      MUTEX_LOCK(&queue->lock);

   cnt = queue->count;

   if (queue->array != NULL) {
      ArgusFree(queue->array);
      queue->array = NULL;
   }

   if (cnt > 0) {
      fcode = sorter->filter.bf_insns;
      if ((queue->array = (struct ArgusQueueHeader **) ArgusMalloc(sizeof(struct ArgusQueueHeader *) * (cnt + 1))) != NULL) {
         struct ArgusQueueHeader *qhdr = queue->start;
         int i = 0;

         for (i = 0; qhdr && (i < cnt); i++) {
            int keep = 1;
            if (fcode) {
               if (ArgusFilterRecord (fcode, (struct ArgusRecordStruct *)qhdr) == 0)
                  keep = 0;
            }
      
            if (keep)
               queue->array[x++] = qhdr;
            qhdr = qhdr->nxt;
         }

         queue->array[x] = NULL;

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

   if (type & ARGUS_LOCK)
      MUTEX_UNLOCK(&queue->lock);

#ifdef ARGUSDEBUG 
   ArgusDebug (5, "RaClientSortQueue(0x%x, 0x%x, %d) returned\n", sorter, queue, type);
#endif
}

