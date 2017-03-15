/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2014 QoSient, LLC
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
 *  rampc - ra multi-probe correlator.
 *
 *  raclient.c - this routine handles the argus data processing.
 *
 *  Author: Carter Bullard carter@qosient.com
 */

/*
 * $Id: //depot/gargoyle/clients/examples/rampc/raclient.c#19 $
 * $DateTime: 2016/11/30 12:38:04 $
 * $Change: 3249 $
 */

#define ARGUS_HISTORY
#define ARGUS_READLINE

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <racurses.h>
#include <rabins.h>
#include <rampcd.h>

#if defined(HAVE_ZLIB_H)
#include <zlib.h>
#endif

int RaRealTime = 0;

struct timeval ArgusLastRealTime = {0, 0};
struct timeval ArgusLastTime     = {0, 0};
struct timeval ArgusThisTime     = {0, 0};


struct timeval dLastTime = {0, 0};
struct timeval dRealTime = {0, 0};
struct timeval dThisTime = {0, 0};
struct timeval dTime     = {0, 0};

long long thisUsec = 0;

void ArgusThreadsInit(pthread_attr_t *);

void RaInsertAddressTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *);

/*
int RaProcessAddress (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *, unsigned int *, int, int);
void ArgusProcessDirection (struct ArgusParserStruct *, struct ArgusRecordStruct *);
*/

extern int ArgusCloseDown;

int ArgusProcessQueue (struct ArgusQueueStruct *);
void ArgusGetInterfaceAddresses(struct ArgusParserStruct *);

int ArgusProcessQueue (struct ArgusQueueStruct *);
int ArgusCorrelateRecord (struct ArgusRecordStruct *);
int ArgusCorrelateQueue (struct ArgusQueueStruct *);
void RaCursesSortQueue (struct ArgusSorterStruct *, struct ArgusQueueStruct *, int);

 
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
#define ARGUS_MIN_STACKSIZE     524288

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
            pthread_cond_signal(&parser->ArgusOutputList->cond);
#else
            parser->RaParseDone++;
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

   ArgusCloseDown = 1;
#endif
#if defined(ARGUS_THREADS)
   pthread_exit(NULL);
#endif
   return(NULL);
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
            if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
               ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

         if (parser->ArgusRemoteHosts)
            if ((input = (void *)parser->ArgusRemoteHosts->start) != NULL)
               parser->RaTasksToDo = 1;

         if ((ArgusEventAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

         if (parser->Hstr != NULL)
            ArgusHistoMetricParse(parser, parser->ArgusAggregator);

         if ((ArgusModelerQueue = ArgusNewQueue()) == NULL)
            ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

         if ((ArgusProbeQueue = ArgusNewQueue()) == NULL)
            ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

         ArgusProbeTable.size  = 1024;
         if ((ArgusProbeTable.array = (struct ArgusHashTableHdr **) ArgusCalloc (1024, sizeof (struct ArgusHashTableHdr))) == NULL)
            ArgusLog (LOG_ERR, "RaTimeInit: ArgusCalloc error %s\n", strerror(errno));

         if ((ArgusFileQueue = ArgusNewQueue()) == NULL)
            ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

         if ((RaCursesProcess = RaCursesNewProcess(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: RaCursesNewProcess error");

         if ((RaEventProcess = RaCursesNewProcess(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: RaCursesNewProcess error");

         if ((RaHistoryProcess = RaCursesNewProcess(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: RaCursesNewProcess error");

         if (parser->vflag)
            ArgusReverseSortDir++;

         if ((ArgusSorter = ArgusNewSorter(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewSorter error %s", strerror(errno));

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
                     if (parser->ArgusAggregator->correct != NULL) {
                        free(parser->ArgusAggregator->correct);
                        parser->ArgusAggregator->correct = NULL;
                     }
                  } else
                  if (!(strncasecmp (mode->mode, "correct", 7))) {
                     if (parser->ArgusAggregator->correct != NULL)
                        parser->ArgusAggregator->correct = strdup("yes");;
                  } else
                  if (!(strncasecmp (mode->mode, "preserve", 8))) {
                     if (parser->ArgusAggregator->pres != NULL)
                        free(parser->ArgusAggregator->pres);
                     parser->ArgusAggregator->pres = strdup("yes");
                  } else
                  if (!(strncasecmp (mode->mode, "nopreserve", 10))) {
                     if (parser->ArgusAggregator->pres != NULL)
                        free(parser->ArgusAggregator->pres);
                     parser->ArgusAggregator->pres = NULL;
                  } else
                  if (!(strncasecmp (mode->mode, "nocurses", 4))) {
                    ArgusCursesEnabled = 0;
                  } else
                  if (!(strncasecmp (mode->mode, "rmon", 4))) {
                     parser->RaMonMode++;
                     if (parser->ArgusAggregator->correct != NULL) {
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
            RaCursesUpdateInterval.tv_sec  = 0;
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
         parser->ArgusPrintJson = 0;
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
         }
      }
   }
}


struct timeval RaProcessQueueTimer = {0, 250000};

void
ArgusClientTimeout ()
{
   struct ArgusQueueStruct *queue = RaCursesProcess->queue;
   struct timeval tvbuf, *tvp = &tvbuf;

   if (!(ArgusParser->Pauseflag)) {
      gettimeofday(&ArgusParser->ArgusRealTime, 0);
      ArgusAdjustGlobalTime (ArgusParser, NULL);
   }

   *tvp = ArgusParser->ArgusGlobalTime;

   if (ArgusParser->RaClientUpdate.tv_sec != 0) {
      int last = 0;
      if (((ArgusParser->RaClientUpdate.tv_sec < tvp->tv_sec) ||
          ((ArgusParser->RaClientUpdate.tv_sec == tvp->tv_sec) &&
           (ArgusParser->RaClientUpdate.tv_usec < tvp->tv_usec)))) {

         ArgusProcessQueue(queue);

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

   fprintf (stdout, "RaCurses Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] -S remoteServer  [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -A                 print record summaries on termination.\n");
   fprintf (stdout, "         -b                 dump packet-matching code.\n");
   fprintf (stdout, "         -c <char>          specify a delimiter <char> for output columns.\n");
   fprintf (stdout, "         -C <[host]:port>   specify remote Cisco Netflow source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stdout, "         -D <level>         specify debug level\n");
#endif
   fprintf (stdout, "         -e <encode>        convert user data using <encode> method.\n");
   fprintf (stdout, "                            Supported types are <Ascii> and <Encode64>.\n");
   fprintf (stdout, "         -E <file>          write records that are rejected by the filter\n");
   fprintf (stdout, "                            into <file>\n");
   fprintf (stdout, "         -F <conffile>      read configuration from <conffile>.\n");
   fprintf (stdout, "         -h                 print help.\n");
   fprintf (stdout, "         -n                 don't convert numbers to names.\n");
   fprintf (stdout, "         -p <digits>        print fractional time with <digits> precision.\n");
   fprintf (stdout, "         -q                 quiet mode. don't print record outputs.\n");
   fprintf (stdout, "         -r <file>          read argus data <file>. '-' denotes stdin.\n");
   fprintf (stdout, "         -R <dir>           recursively process files in directory\n");
   fprintf (stdout, "         -s [-][+[#]]field  specify fields to print.\n");
   fprintf (stdout, "                   fields:  srcid, stime, ltime, trans, seq, flgs, dur, avgdur,\n");
   fprintf (stdout, "                            stddev, mindur, maxdur, saddr, daddr, proto, sport,\n");
   fprintf (stdout, "                            dport, stos, dtos, sdsb, ddsb, sttl, dttl, sipid,\n");
   fprintf (stdout, "                            dipid, smpls, dmpls, [s|d]pkts, [s|d]bytes,\n");
   fprintf (stdout, "                            [s||d]appbytes, [s|d]load, [s|d]loss, [s|d]ploss,\n");
   fprintf (stdout, "                            [s|d]rate, smac, dmac, dir, [s|d]intpkt, [s|d]jit,\n");
   fprintf (stdout, "                            status, suser, duser, swin, dwin, svlan, dvlan,\n");
   fprintf (stdout, "                            svid, dvid, svpri, dvpri, srng, drng, stcpb, dtcpb,\n");
   fprintf (stdout, "                            tcprtt, inode\n");
   fprintf (stdout, "         -S <host[:port]>   specify remote argus <host> and optional port\n");
   fprintf (stdout, "                            number.\n");
   fprintf (stdout, "         -t <timerange>     specify <timerange> for reading records.\n");
   fprintf (stdout, "                   format:  timeSpecification[-timeSpecification]\n");
   fprintf (stdout, "                            timeSpecification: [[[yyyy/]mm/]dd.]hh[:mm[:ss]]\n");
   fprintf (stdout, "                                                 [yyyy/]mm/dd\n");
   fprintf (stdout, "                                                 -%%d{yMdhms}\n");
   fprintf (stdout, "         -T <secs>          attach to remote server for T seconds.\n");
   fprintf (stdout, "         -u                 print time in Unix time format.\n");
#ifdef ARGUS_SASL
   fprintf (stdout, "         -U <user/auth>     specify <user/auth> authentication information.\n");
#endif
   fprintf (stdout, "         -w <file>          write output to <file>. '-' denotes stdout.\n");
   fprintf (stdout, "         -z                 print Argus TCP state changes.\n");
   fprintf (stdout, "         -Z <s|d|b>         print actual TCP flag values.\n");
   fprintf (stdout, "                            <'s'rc | 'd'st | 'b'oth>\n");
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

   If the ns cache is a sticky ns, it may not be in the RaCursesProcess
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
         if (parser->RaMonMode) {
            struct ArgusFlow *flow;
            struct ArgusRecordStruct *tns;

            if ((flow = (void *) ns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
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

            if (agg->ArgusMatrixMode) {
               struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];

               if (agg->mask & ((0x01LL << ARGUS_MASK_SADDR) | (0x01LL << ARGUS_MASK_DADDR))) {
                  if (flow != NULL) {
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
#if defined(ARGUS_SOLARIS) || defined(ARGUS_PLURIBUS)
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
   struct RaBinProcessStruct *RaBinProcess = parser->RaBinProcess;
   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
   struct ArgusHashStruct *hstruct = NULL;
   struct ArgusProbeStruct *probe = NULL, *mpc = NULL;
   int count, i, found = 0, mpccachemiss = 0;
   struct ArgusFlow *flow = NULL;

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

   if ((probe = ArgusProcessProbe (parser, ns)) != NULL) {
      if ((count = ArgusProbeQueue->count) > 1) {
         for (i = 0; (i < count) && !found; i++) {
            if ((mpc = (void *) ArgusPopQueue(ArgusProbeQueue, ARGUS_LOCK)) != NULL) {
               if (probe != mpc) {
/*
                  if ((rec = RaFindMpcStream(parser, mpc, ns)) != NULL) {
                     double recst = ArgusFetchStartTime(rec);
                     double  nsst = ArgusFetchStartTime(ns);
                     double  diff, tdiff;

                     tdiff = (parser->timeout.tv_sec * 1.0) + (parser->timeout.tv_usec / 1000000.0);
                     diff = fabs(recst - nsst);

                     if (diff > (tdiff * 2.0)) {
                        RaSendArgusRecord(rec);
                        ArgusZeroRecord(rec);
                     }

                     if ((trec = RaMpcCorrelate(mpc, ns, rec)) != NULL) {
                        if (trec == ns) {
                           RaFreeMpcStream (parser, rec);
                           if ((rec = RaMpcEstablishMpcStream(probe, ns)) != NULL)
                              RaMpcAdvertiseHints(probe, rec);
                        }
                     }
                     found++;
                  }
*/
                  mpccachemiss++;
               }

               ArgusAddToQueue (ArgusProbeQueue, &mpc->qhdr, ARGUS_LOCK);
            }
         }
      }

   } else
      ArgusLog (LOG_INFO, "RaProcessThisRecord: ArgusProcessProbe returned NULL");

   ArgusProcessDirection(parser, ns);
   cns = ArgusCopyRecordStruct(ns);

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&RaCursesProcess->queue->lock);
#endif

   flow = (struct ArgusFlow *) cns->dsrs[ARGUS_FLOW_INDEX];

   while (agg && !found) {
      struct nff_insn *fcode = agg->filter.bf_insns;

      if (ArgusFilterRecord (fcode, cns) != 0) {
         if (agg->mask) {
         if (flow != NULL) {
            if ((agg->rap = RaFlowModelOverRides(agg, cns)) == NULL)
               agg->rap = agg->drap;

            ArgusGenerateNewFlow(agg, cns);
            agg->ArgusMaskDefs = NULL;

            if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
               ArgusLog (LOG_ERR, "RaProcessRecord: ArgusGenerateHashStruct error %s", strerror(errno));

            if ((pns = ArgusFindRecord(RaCursesProcess->htable, hstruct)) == NULL) {
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

                  if ((pns = ArgusFindRecord(RaCursesProcess->htable, hstruct)) != NULL) {
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
            struct timeval startime = pns->qhdr.logtime;
            if (pns->qhdr.queue != RaCursesProcess->queue)
               ArgusRemoveFromQueue (pns->qhdr.queue, &pns->qhdr, ARGUS_LOCK);
            else
               ArgusRemoveFromQueue (pns->qhdr.queue, &pns->qhdr, ARGUS_NOLOCK);

            ArgusAddToQueue (RaCursesProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
            pns->status |= ARGUS_RECORD_MODIFIED;
            pns->qhdr.logtime = startime;
         }
         }
         found++;

      } else
         agg = agg->nxt;
   }

   if (!found)
      if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
         ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

   ArgusAlignInit(parser, cns, &RaBinProcess->nadp);

   while ((tns = ArgusAlignRecord(parser, cns, &RaBinProcess->nadp)) != NULL) {
      struct ArgusRecordStruct *rec = NULL;
      int offset = 0;

      if (pns) {
         struct timeval startime = pns->qhdr.logtime;
         if (pns->bins) {
            pns->bins->nadp.RaStartTmStruct = RaBinProcess->nadp.RaStartTmStruct;
            pns->bins->nadp.RaEndTmStruct   = RaBinProcess->nadp.RaEndTmStruct;

            if (ArgusInsertRecord (parser, pns->bins, tns, offset, &rec) <= 0)
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

         ArgusRemoveFromQueue(RaCursesProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
         ArgusAddToQueue (RaCursesProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
         pns->qhdr.logtime = startime;

      } else {
         if ((pns =  ArgusCopyRecordStruct(tns)) != NULL) { /* new record */
            pns->htblhdr = ArgusAddHashEntry (RaCursesProcess->htable, pns, hstruct);
            ArgusAddToQueue (RaCursesProcess->queue, &pns->qhdr, ARGUS_NOLOCK);

            if (RaBinProcess->nadp.mode == ARGUSSPLITRATE) {
               if ((pns->bins = (struct RaBinProcessStruct *)ArgusNewRateBins(parser, pns)) == NULL)
                  ArgusLog (LOG_ERR, "ArgusProcessThisRecord: ArgusNewRateBins error %s", strerror(errno));

//             offset = (parser->Bflag * 1000000LL) / pns->bins->size;

               if (ArgusInsertRecord (parser, pns->bins, tns, offset, &rec) <= 0)
                  ArgusDeleteRecordStruct(ArgusParser, tns);

               pns->bins->status |= RA_DIRTYBINS;

            } else
               ArgusDeleteRecordStruct(ArgusParser, tns);

            pns->status |= ARGUS_RECORD_NEW | ARGUS_RECORD_MODIFIED;
         }
      }

//    for (i = 0; i < ArgusTotalAnalytics; i++) {
         if (pns->status & ARGUS_RECORD_NEW)
            ArgusCorrelateRecord(pns);
//    }

      pns->status &= ~ARGUS_RECORD_NEW;
      RaWindowModified = RA_MODIFIED;
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&RaCursesProcess->queue->lock);
#endif

   ArgusDeleteRecordStruct(ArgusParser, cns);

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessThisRecord () returning\n"); 
#endif
}


void
RaProcessThisEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusRecordStruct *tns = NULL, *pns = NULL;
   struct ArgusRecordStruct *cns = ArgusCopyRecordStruct(ns);
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
      char *dptr = data->array, *str;
      unsigned long len = 0x10000;
      int title = 0;;

      data = (void *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX];

      if (data->hdr.subtype & ARGUS_DATA_COMPRESS) {
         bzero (ptr, sizeof(buf));
 #if defined(HAVE_ZLIB_H)
         uncompress((Bytef *)ptr, (uLongf *)&len, (Bytef *)&data->array, data->count);
#else
 #if defined(ARGUSDEBUG)
         ArgusDebug (3, "RaProcessEventRecord: unable to decompress payload\n");
 #endif
#endif
         dptr = ptr;
      }

      if (strstr(dptr, "argus-lsof")) {
         bzero (tbuf, 129);
         bzero (sptr, 129);
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
                           ArgusDebug (1, "RaProcessEventRecord: %s:srcid=%s:%s: %s %s.%s -> %s.%s %s\n", tbuf, sptr, app, node, 
                                               saddr, sport, daddr, dport, state);
#endif
                              if ((ns = ArgusGenerateRecordStruct(NULL, NULL, NULL)) != NULL) {
                                 extern struct ArgusCanonRecord ArgusGenerateCanonBuffer;
                                 struct ArgusCanonRecord  *canon = &ArgusGenerateCanonBuffer;

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

                                 bzero(lptr, MAXSTRLEN);
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

      ArgusCorrelateQueue (RaCursesProcess->queue);
   }
}

/*
void
ArgusProcessDirection (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusLabelerStruct *labeler = NULL;
// char dbuf[16];

   if (parser->RaMonMode)
      return;

// bzero(dbuf, sizeof(dbuf));
// ArgusPrintDir(parser, dbuf, ns, sizeof(dbuf) - 1);
//
// if (strchr(dbuf, '?')) {
      switch (ns->hdr.type & 0xF0) {
         case ARGUS_NETFLOW:
         case ARGUS_FAR: {
            struct ArgusMacStruct *mac = (struct ArgusMacStruct *) ns->dsrs[ARGUS_MAC_INDEX];
            struct ArgusFlow *flow     = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
            int src = 0, dst = 0;

            if (mac) {
               switch (mac->hdr.subtype & 0x3F) {
                  default:
                  case ARGUS_TYPE_ETHER: {
                     struct ether_header *e = &mac->mac.mac_union.ether.ehdr;
                     extern struct enamemem elabeltable[HASHNAMESIZE];
                     unsigned char *ep = e->ether_shost;
                     u_int i = 0, j = 0, k = 0;
                     struct enamemem *tp, *et = NULL;

#if defined(ARGUS_SOLARIS)
#else
                     k = (ep[0] << 8) | ep[1];
                     j = (ep[2] << 8) | ep[3];
                     i = (ep[4] << 8) | ep[5];

                     tp = &elabeltable[(i ^ j) % (HASHNAMESIZE-1)];
                     while (tp->e_nxt)
                        if ((tp->e_addr0 == i) && (tp->e_addr1 == j) && (tp->e_addr2 == k)) {
                           et = tp;
                           break;
                        } else
                           tp = tp->e_nxt;
                     if (et != NULL)
                        src = 1;

                     ep = e->ether_dhost;
                     k = 0, j = 0, i = 0;

                     k = (ep[0] << 8) | ep[1];
                     j = (ep[2] << 8) | ep[3];
                     i = (ep[4] << 8) | ep[5];

                     tp = &elabeltable[(i ^ j) % (HASHNAMESIZE-1)];
                     while (tp->e_nxt)
                        if ((tp->e_addr0 == i) && (tp->e_addr1 == j) && (tp->e_addr2 == k)) {
                           et = tp;
                           break;
                        } else
                           tp = tp->e_nxt;
                     if (et != NULL)
                        dst = 1;
#endif
                     break;
                  }
               }
            }

            if (((src == 0) && (dst == 0)) && flow) {
               switch (flow->hdr.subtype & 0x3F) {
                  case ARGUS_FLOW_CLASSIC5TUPLE:
                  case ARGUS_FLOW_LAYER_3_MATRIX: {
                     switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                        case ARGUS_TYPE_IPV4: {
                           if ((labeler = parser->ArgusLocalLabeler) != NULL) {
                              dst = RaProcessAddress (parser, labeler, &flow->ip_flow.ip_dst, flow->ip_flow.dmask, ARGUS_TYPE_IPV4);
                              src = RaProcessAddress (parser, labeler, &flow->ip_flow.ip_src, flow->ip_flow.smask, ARGUS_TYPE_IPV4);
                              break;
                           }
                        }
                     }
                  }
               }
            }

            switch (parser->ArgusDirectionFunction) {
               case ARGUS_SUGGEST_LOCAL_SRC: if ((dst > 0) && (src == 0)) ArgusReverseRecord (ns); break;
               case ARGUS_SUGGEST_LOCAL_DST: if ((dst > 0) && (src == 0)) ArgusReverseRecord (ns); break;
               case ARGUS_FORCE_LOCAL_SRC: if ((dst > 0) && (src == 0)) ArgusReverseRecord (ns); break;
               case ARGUS_FORCE_LOCAL_DST: if ((src > 0) && (dst == 0)) ArgusReverseRecord (ns); break;
            }
         }
//    }
   }
}
*/


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



void ArgusShiftArray (struct ArgusParserStruct *, struct RaBinProcessStruct *);

int
ArgusProcessBins (struct ArgusRecordStruct *ns, struct RaBinProcessStruct *rbps)
{
   int retn = 0;
   int cnt   = (rbps->arraylen - rbps->index);
   int dtime = cnt * rbps->size;
   int rtime = 0;

   if (rbps && (rbps->size != 0)) {
      rtime = ((((ArgusParser->ArgusGlobalTime.tv_sec * 1000000LL) /rbps->size)) * rbps->size)/1000000LL;;

      if ((rbps->startpt.tv_sec + dtime) < rtime) {
         ArgusShiftArray(ArgusParser, rbps);
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

extern struct ArgusRecordStruct *ArgusSearchHitRecord;

int
ArgusProcessQueue (struct ArgusQueueStruct *queue)
{
   struct timeval tbuf, *tvp = &tbuf;
   int retn = 0, x, z;

   if ((ArgusParser->timeout.tv_sec > 0) || (ArgusParser->timeout.tv_usec > 0)) {
      struct ArgusRecordStruct *ns;
      struct timeval startime, lasttime;
      int count, deleted = 0;

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&queue->lock);
#endif
      count = queue->count;
      for (x = 0, z = count; x < z; x++) {
         if ((ns = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
            startime = ns->qhdr.logtime;
            lasttime = ns->qhdr.lasttime;
            *tvp = startime;

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
                  ns->qhdr.logtime = startime;
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
               ns->qhdr.logtime = startime;
               ns->qhdr.lasttime = lasttime;
            }
         }
      }

      if (deleted)
         RaCursesSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock);
#endif
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (5, "ArgusProcessQueue (0x%x) returning %d", queue, retn); 
#endif

   return (retn);
}

int
ArgusCorrelateQueue (struct ArgusQueueStruct *queue)
{
   struct timeval tbuf, *tvp = &tbuf;
   struct ArgusRecordStruct *ns;
   int retn = 0, x, z, count;
   struct timeval startime, lasttime;

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&queue->lock);
#endif
   count = queue->count;
   for (x = 0, z = count; x < z; x++) {
      if ((ns = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
         startime = ns->qhdr.logtime;
         lasttime = ns->qhdr.lasttime;
         *tvp = lasttime;
         ArgusCorrelateRecord(ns);
         ArgusAddToQueue (queue, &ns->qhdr, ARGUS_NOLOCK);
         ns->qhdr.logtime = startime;
         ns->qhdr.lasttime = lasttime;
      }
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&queue->lock);
#endif

#if defined(ARGUSDEBUG)
   ArgusDebug (1, "ArgusCorrelateQueue (0x%x) returning %d", queue, retn); 
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
               char buf[MAXSTRLEN];
               bzero(buf, sizeof(buf));

               if ((ArgusMergeLabel(l1, l2, buf, MAXSTRLEN, ARGUS_UNION)) != NULL) {
                  free(l1->l_un.label);
                  l1->l_un.label = strdup(buf);
               }
            }
#if defined(ARGUSDEBUG)
            ArgusDebug (1, "ArgusCorrelateRecord (0x%x) merged label", pns); 
#endif

         } else {
            if (l2 && (l1 == NULL)) {
               ns->dsrs[ARGUS_LABEL_INDEX] = calloc(1, sizeof(struct ArgusLabelStruct));
               l1 = (void *) ns->dsrs[ARGUS_LABEL_INDEX];

               bcopy(l2, l1, sizeof(*l2));

               if (l2->l_un.label)
                  l1->l_un.label = strdup(l2->l_un.label);
#if defined(ARGUSDEBUG)
               ArgusDebug (1, "ArgusCorrelateRecord (0x%x) added label", pns); 
#endif
            }
         }

         pns->status |= ARGUS_RECORD_MODIFIED;
      }

      ArgusDeleteRecordStruct(ArgusParser, cns);
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (2, "ArgusCorrelateRecord (0x%x) returning %d", ns, retn); 
#endif

   return (retn);
}


struct RaCursesProcessStruct *
RaCursesNewProcess(struct ArgusParserStruct *parser)
{
   struct RaCursesProcessStruct *retn = NULL;

   if ((retn = (struct RaCursesProcessStruct *) ArgusCalloc (1, sizeof(*retn))) != NULL) {
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
RaCursesSortQueue (struct ArgusSorterStruct *sorter, struct ArgusQueueStruct *queue, int type)
{
   struct nff_insn *fcode = NULL;
   int cnt, x = 0;

#if defined(ARGUS_THREADS)
   if (type == ARGUS_LOCK)
      pthread_mutex_lock(&queue->lock);
#endif

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
         qsort ((char *) queue->array, x, sizeof (struct ArgusQueueHeader *), ArgusSortRoutine);

         for (i = 0; i < x; i++) {
            struct ArgusRecordStruct *ns = (struct ArgusRecordStruct *) queue->array[i];
            if (ns->rank != i) {
               ns->rank = i;
               ns->status |= ARGUS_RECORD_MODIFIED;
            }
         }

      } else 
         ArgusLog (LOG_ERR, "ArgusSortQueue: ArgusMalloc(%d) %s\n", sizeof(struct ArgusRecord *), cnt, strerror(errno));
   }

   RaSortItems = x;
   bzero (&ArgusParser->ArgusStartTimeVal, sizeof(ArgusParser->ArgusStartTimeVal));

#if defined(ARGUS_THREADS)
   if (type == ARGUS_LOCK)
      pthread_mutex_unlock(&queue->lock);
#endif

#ifdef ARGUSDEBUG 
   ArgusDebug (5, "ArgusSortQueue(0x%x, 0x%x, %d) returned\n", sorter, queue, type);
#endif
}


struct ArgusProbeStruct *
ArgusProcessProbe (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusProbeStruct *retn = NULL;
   struct ArgusTransportStruct *trans = NULL;
   struct ArgusHashTableHdr *htbl = NULL;
   struct ArgusHashStruct ArgusHash;
   unsigned short *sptr;
   int i, len, s = sizeof(short);
   unsigned int key;

   if ((trans = (void *)ns->dsrs[ARGUS_TRANSPORT_INDEX]) != NULL) {
      struct ArgusTimeObject *time = (void *)ns->dsrs[ARGUS_TIME_INDEX];;
      key = trans->srcid.a_un.value;

      if (RaRealTime) {
         if (time != NULL) {
            ArgusThisTime.tv_sec  = time->src.start.tv_sec;
            ArgusThisTime.tv_usec = time->src.start.tv_usec;

            if (ArgusLastTime.tv_sec == 0)
               ArgusLastTime = ArgusThisTime;

            if (!((ArgusLastTime.tv_sec  > ArgusThisTime.tv_sec) ||
               ((ArgusLastTime.tv_sec == ArgusThisTime.tv_sec) &&
                (ArgusLastTime.tv_usec > ArgusThisTime.tv_usec)))) {

               while ((ArgusThisTime.tv_sec  > ArgusLastTime.tv_sec) ||
                     ((ArgusThisTime.tv_sec == ArgusLastTime.tv_sec) &&
                      (ArgusThisTime.tv_usec > ArgusLastTime.tv_usec))) {
                  struct timespec ts = {0, 0};
                  int thisRate;

                  RaDiffTime(&ArgusThisTime, &ArgusLastTime, &dThisTime);
                  thisRate = ((dThisTime.tv_sec * 1000000) + dThisTime.tv_usec)/RaUpdateRate;
                  thisRate = (thisRate > 100000) ? 100000 : thisRate;

                  ts.tv_nsec = thisRate * 1000;
                  nanosleep (&ts, NULL);

                  ArgusClientTimeout ();

                  gettimeofday(&parser->ArgusRealTime, 0);

                  if (ArgusLastRealTime.tv_sec > 0) {
                     RaDiffTime(&parser->ArgusRealTime, &ArgusLastRealTime, &dRealTime);
                     thisUsec = ((dRealTime.tv_sec * 1000000) + dRealTime.tv_usec) * RaUpdateRate;
                     dRealTime.tv_sec  = thisUsec / 1000000;
                     dRealTime.tv_usec = thisUsec % 1000000;

                     ArgusLastTime.tv_sec  += dRealTime.tv_sec;
                     ArgusLastTime.tv_usec += dRealTime.tv_usec;
                     if (ArgusLastTime.tv_usec > 1000000) {
                        ArgusLastTime.tv_sec++;
                        ArgusLastTime.tv_usec -= 1000000;
                     }
                  }
                  ArgusLastRealTime = parser->ArgusRealTime;
               }
            }
         }

      } else
         ArgusLastTime = parser->ArgusRealTime;
 
      bzero ((char *)&ArgusHash, sizeof(ArgusHash));
      ArgusHash.len = 4;
      ArgusHash.buf = &key;

      sptr = (unsigned short *) ArgusHash.buf;
      for (i = 0, len = ArgusHash.len / s; i < len; i++)
         ArgusHash.hash += *sptr++;

      if ((htbl = ArgusFindHashEntry(&ArgusProbeTable, &ArgusHash)) == NULL) {
         if ((retn = (struct ArgusProbeStruct *) ArgusCalloc (1, sizeof(*retn))) != NULL) {
            retn->htblhdr = ArgusAddHashEntry (&ArgusProbeTable, (void *)retn, &ArgusHash);
            ArgusAddToQueue(ArgusProbeQueue, &retn->qhdr, ARGUS_LOCK);

            bcopy ((char *)trans, (char *)&retn->trans, sizeof(retn->trans)); 

            if ((retn->agg = ArgusParseAggregator(parser, NULL, ArgusMpcAggregatorConfig)) == NULL)
               ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

#ifdef ARGUSDEBUG
            ArgusDebug (2, "RaProcessRecord(0x%x, 0x%x) New Probe %s", parser, ns,
                 ArgusGetName (parser, (unsigned char *)&key));
#endif
         } else
            ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s\n", strerror(errno));
      } else
         retn = htbl->object;

      if (retn->start.tv_sec == 0)
         retn->start = ArgusParser->ArgusRealTime;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusProcessProbe (0x%x, 0x%x) returns 0x%x\n", parser, ns, retn);
#endif
   return(retn);
}

void
RaClientSortQueue (struct ArgusSorterStruct *sorter, struct ArgusQueueStruct *queue, int type)
{
   struct nff_insn *fcode = NULL;
   int cnt, x = 0;

#if defined(ARGUS_THREADS)
   if (type == ARGUS_LOCK)
      pthread_mutex_lock(&queue->lock);
#endif

   cnt = queue->count;

   if (queue->array != NULL) {
      ArgusFree(queue->array);
      queue->array = NULL;
      queue->arraylen = 0;
   }

   if (cnt > 0) {
      fcode = sorter->filter.bf_insns;
      if ((queue->array = (struct ArgusQueueHeader **) ArgusCalloc(1, sizeof(struct ArgusQueueHeader *) * (cnt + 1))) != NULL) {
         struct ArgusQueueHeader *qhdr = queue->start;
         int i = 0;

         queue->arraylen = cnt;
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

         queue->array[x] = NULL;
         qsort ((char *) queue->array, x, sizeof (struct ArgusQueueHeader *), ArgusSortRoutine);

         for (i = 0; i < x; i++) {
            struct ArgusRecordStruct *ns = (struct ArgusRecordStruct *) queue->array[i];
            if (ns->rank != i) {
               ns->rank = i;
               ns->status |= ARGUS_RECORD_MODIFIED;
            }
         }

      } else 
         ArgusLog (LOG_ERR, "RaClientSortQueue: ArgusMalloc(%d) %s\n", sizeof(struct ArgusRecord *), cnt, strerror(errno));
   }

   RaSortItems = x;
   bzero (&ArgusParser->ArgusStartTimeVal, sizeof(ArgusParser->ArgusStartTimeVal));

   queue->status &= ~RA_MODIFIED;

#if defined(ARGUS_THREADS)
   if (type == ARGUS_LOCK)
      pthread_mutex_unlock(&queue->lock);
#endif

#ifdef ARGUSDEBUG 
   ArgusDebug (5, "RaClientSortQueue(0x%x, 0x%x, %d) returned\n", sorter, queue, type);
#endif
}
