/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2019 QoSient, LLC
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
 *  raclient.c - this routine handles the argus data processing.
 *
 *  Author: Carter Bullard carter@qosient.com
 */

/*
 * $Id: //depot/gargoyle/clients/examples/ratop/raclient.c#40 $
 * $DateTime: 2016/12/02 00:09:45 $
 * $Change: 3254 $
 */


#define ARGUS_HISTORY
#define ARGUS_READLINE
#define ARGUS_OUTPUT

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <argus_output.h>
#include <racurses.h>
#include <rabins.h>

#if defined(HAVE_ZLIB_H)
#include <zlib.h>
#endif

#include <wordexp.h>

struct ArgusAggregatorStruct *ArgusBaselineAggregator;
struct ArgusAggregatorStruct *ArgusSampleAggregator;

struct RaCursesProcessStruct *RaBaselineProcess = NULL;
struct RaCursesProcessStruct *RaSampleProcess = NULL;

void ArgusThreadsInit(pthread_attr_t *);

extern int ArgusCloseDown;
extern char ArgusRecordBuffer[];

int RaTopReplace = 0;

void ArgusGetInterfaceAddresses(struct ArgusParserStruct *);

int ArgusProcessQueue (struct ArgusQueueStruct *, int);
int ArgusCorrelateRecord (struct ArgusRecordStruct *);
int ArgusCorrelateQueue (struct ArgusQueueStruct *);

int ArgusMergeRecordToProcess (struct ArgusParserStruct *, struct RaCursesProcessStruct *, struct ArgusRecordStruct *);

char **ArgusHandleControllerCommand (struct ArgusOutputStruct *, char *);
char **ArgusHandleHighlightCommand (struct ArgusOutputStruct *, char *);
char **ArgusHandleDisplayCommand (struct ArgusOutputStruct *, char *);
char **ArgusHandleFilterCommand (struct ArgusOutputStruct *, char *);
char **ArgusHandleSearchCommand (struct ArgusOutputStruct *, char *);


struct ArgusWirelessStruct ArgusWirelessBuf, *ArgusWireless = &ArgusWirelessBuf;

#define MAX_AIRPORT_PARSE_TOKENS	15
 
char *ArgusParseAirportTokens[MAX_AIRPORT_PARSE_TOKENS] = {
#define ARGUSWSAGRCTLRSSI	0
   "agrCtlRSSI",
#define ARGUSWSAGREXTRSSI	1
   "agrExtRSSI",
#define ARGUSWSAGRCTLNOISE	2
   "agrCtlNoise",
#define ARGUSWSAGREXTNOISE	3
   "agrExtNoise",
#define ARGUSWSSTATE		4
   "state",
#define ARGUSWSOPSTATE		5
   "opMode",
#define ARGUSWSLASTTXRATE	6
   "lastTxRate",
#define ARGUSWSMAXRATE		7
   "maxRate",
#define ARGUSWSLASTASSOC	8
   "lastAssocStatus",
#define ARGUSWSAUTH		9
   "802.11.auth",
#define ARGUSWSLINKAUTH		10
   "linkAuth",
#define ARGUSWSBSSID		11
   "BSSID",
#define ARGUSWSSSID		12
   "SSID",
#define ARGUSWSMCS		13
   "MCS",
#define ARGUSWSCHANNEL		14
   "channel"
};
 

#define ARGUS_PROCESS_BASELINE	0
#define ARGUS_PROCESS_SAMPLE	1
#define ARGUS_PROCESS_COMPLETE	2
#define ARGUS_PROCESS_DONE	3

int argus_version = ARGUS_VERSION;

int ArgusProcessingBaseline   = 0;
int ArgusProcessingSample     = 0;
int ArgusProcessingComplete   = 0;

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
      ArgusDebug (5, "setting stacksize from %d to %d", stacksize, ARGUS_MIN_STACKSIZE);
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

   /* Process the baseline file first */
   ArgusProcessingBaseline = 1;
   ArgusProcessingSample = 0;

   while (!ArgusCloseDown && !done) {
      if (parser->RaTasksToDo) {
         struct ArgusInput *input = NULL;
         struct ArgusFileInput *file = NULL;
         int hosts = 0;
         char sbuf[1024];

         sprintf (sbuf, "RaCursesLoop() Processing.");
         ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);

         RaCursesStartTime.tv_sec  = 0;
         RaCursesStartTime.tv_usec = 0;
         RaCursesStopTime.tv_sec   = 0;
         RaCursesStopTime.tv_usec  = 0;

         input = ArgusMalloc(sizeof(*input));
         if (input == NULL)
            ArgusLog(LOG_ERR, "unable to allocate input structure\n");

         if ((!(parser->status & ARGUS_FILE_LIST_PROCESSED)) && ((file = parser->ArgusInputFileList) != NULL)) {
            while (file && parser->eNflag) {
               ArgusInputFromFile(input, file);
               parser->ArgusCurrentInput = input;

               if (strcmp (input->filename, "-")) {
                  if (input->fd < 0) {
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
               ArgusCloseInput(ArgusParser, input);
               file = (struct ArgusFileInput *)file->qhdr.nxt;
            }

            parser->ArgusCurrentInput = NULL;
            parser->status |= ARGUS_FILE_LIST_PROCESSED;
         }
         ArgusFree(input);
         input = NULL;

         ArgusProcessingSample = 0;
         ArgusProcessingComplete = 1;

// Then process the realtime stream input, if any

         if (parser->Sflag) {
            if (parser->ArgusRemoteHosts && (parser->ArgusRemoteHosts->count > 0)) {
               struct ArgusQueueStruct *tqueue = ArgusNewQueue();
               int flags;

#if defined(ARGUS_THREADS)
               if (parser->ArgusReliableConnection) {
                  if (parser->ArgusRemoteHosts && (hosts = parser->ArgusRemoteHosts->count)) {
                     if ((pthread_create(&parser->remote, NULL, ArgusConnectRemotes, parser->ArgusRemoteHosts)) != 0)
                        ArgusLog (LOG_ERR, "ArgusConnectRemotes() pthread_create error %s\n", strerror(errno));
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
                           parser->RaTasksToDo = RA_ACTIVE;
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

         if (parser->ArgusReliableConnection || parser->ArgusActiveHosts)
            if (parser->ArgusActiveHosts->count)
               ArgusReadStream(parser, parser->ArgusActiveHosts);

         if (ArgusCursesEnabled)
            parser->RaTasksToDo = RA_IDLE;
         else
            done = 1;

      } else {
         struct timespec ts = {0, 150000000};
         gettimeofday (&parser->ArgusCurrentTime, 0L);
         nanosleep (&ts, NULL);

         if (parser->ArgusActiveHosts && parser->ArgusActiveHosts->count)
            parser->RaTasksToDo = RA_ACTIVE;
      }

      if (ArgusCursesEnabled)
         ArgusClientTimeout ();
   }

   ArgusCloseDown = 1;
   pthread_exit(NULL);
#endif

   return (arg);
}


extern pthread_mutex_t RaCursesLock;

char **
ArgusHandleControllerCommand (struct ArgusOutputStruct *output, char *command)
{
   char **retn = NULL;

#if defined(ARGUS_CURSES)
   
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusHandleControllerCommand(%s)", command);
#endif
   return retn;
}

char **
ArgusHandleHighlightCommand (struct ArgusOutputStruct *output, char *command)
{
   extern int RaHighlightDisplay (struct ArgusParserStruct *, struct ArgusQueueStruct *, char *);
   char *string = &command[11], *sptr;
   int slen = strlen(string);
   char **retn = NULL;

   sptr = &string[slen - 1];
   while (isspace((int)*sptr)) {*sptr-- = '\0';}

#if defined(ARGUS_CURSES)
   ArgusParser->ArgusSearchString = strdup(string);
   RaHighlightDisplay(ArgusParser, RaCursesProcess->queue, ArgusParser->ArgusSearchString);
#endif
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusHandleHighlight(%s)", command);
#endif
   return retn;
}


char **
ArgusHandleDisplayCommand (struct ArgusOutputStruct *output, char *command)
{
   char *string = &command[10], *sptr;
   struct nff_program lfilter;
   int fretn, slen = strlen(string);
   char **retn = NULL;

#ifdef ARGUSDEBUG
   char *result = NULL;
#endif

   sptr = &string[slen - 1];
   while (isspace((int)*sptr)) {*sptr-- = '\0';}
   fretn = ArgusFilterCompile (&lfilter, string, 1);

   if (fretn < 0) {
#ifdef ARGUSDEBUG
      result = "syntax error";
#endif
   } else {
#ifdef ARGUSDEBUG
      result = "accepted";
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusHandleDisplay(%s) filter %s", string, result);
#endif

   return retn;
}

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   time_t tsec = ArgusParser->ArgusRealTime.tv_sec;
   struct ArgusAdjustStruct *nadp = NULL;
   struct ArgusInput *input = NULL;
   struct ArgusModeStruct *mode;
   int correct = -1, preserve = 1;
   int i = 0, size = 1;
   struct timeval *tvp;

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&RaCursesLock, NULL);
#endif

   if (parser != NULL) {
      parser->RaWriteOut = 0;

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

         parser->RaClientTimeout.tv_sec  = 0;
         parser->RaClientTimeout.tv_usec = 500000;

         parser->RaInitialized++;
         parser->ArgusPrintXml = 0;

         parser->NonBlockingDNS = 1;
         parser->RaCumulativeMerge = 1;

         if ((parser->timeout.tv_sec == -1) && (parser->timeout.tv_sec == 0)) {
            parser->timeout.tv_sec  = 60;
            parser->timeout.tv_usec = 0;
         }

         if (parser->ArgusInputFileList != NULL) {
            parser->RaTasksToDo = RA_ACTIVE;
            if (parser->ProcessRealTime == 0) {
               if (parser->ArgusRemoteHosts) {
                  if ((input = (void *)parser->ArgusRemoteHosts->start) == NULL) {
                     parser->timeout.tv_sec  = 0;
                     parser->timeout.tv_usec = 0;
                  }
               }
            }
         }

         if (parser->vflag)
            ArgusReverseSortDir++;

         if ((ArgusSorter = ArgusNewSorter(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewSorter error %s", strerror(errno));

         ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortAlgorithmTable[ARGUSSORTCOMPARE];
         ArgusSorter->ArgusSortAlgorithms[1] = ArgusSortAlgorithmTable[ARGUSSORTPKTSCOUNT];

         if ((parser->RaBinProcess = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*parser->RaBinProcess))) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));


         if ((mode = parser->ArgusModeList) != NULL) {
            int i, x, ind;

            while (mode) {
               for (i = 0, ind = -1; i < ARGUSSPLITMODENUM; i++) {
                  if (!(strncasecmp (mode->mode, RaSplitModes[i], strlen(RaSplitModes[i])))) {

#if defined(ARGUS_THREADS)
                     pthread_mutex_init(&parser->RaBinProcess->lock, NULL);
#endif
                     nadp = &parser->RaBinProcess->nadp;

                     nadp->mode   = -1;
                     nadp->modify =  0;
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

                        parser->RaBinProcess->rtime.tv_sec = tsec;

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


                  parser->RaBinProcess->size = nadp->size;

                  if (nadp->mode < 0) {
                     nadp->mode = ARGUSSPLITCOUNT;
                     nadp->value = 10000;
                     nadp->count = 1;
                  }

               } else {
                  if (!(strncasecmp (mode->mode, "replace", 9))) {
                     RaTopReplace = 1;
                  } else
                  if (!(strncasecmp (mode->mode, "oui", 3)))
                     parser->ArgusPrintEthernetVendors++;
                  else
                  if (!(strncasecmp (mode->mode, "nocorrect", 9))) {
                     correct = 0;
                  } else
                  if (!(strncasecmp (mode->mode, "correct", 7))) {
                     correct = 1;
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
                  if (!(strncasecmp (mode->mode, "rmon", 4))) {
                     parser->RaMonMode++;
                     correct = 0;
                  } else
                  if (!(strncasecmp (mode->mode, "baseline:", 9))) {
                     if (strlen(mode->mode) > 9) {
                        char *ptr = &mode->mode[9];
                        wordexp_t p;
                        if (wordexp (ptr, &p, 0) == 0) {
                            char *str = p.we_wordv[0];
                            if (str != NULL)
                               parser->ArgusBaseLineFile = strdup(str);
                           wordfree (&p);
                        }
                     }
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
                     ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortAlgorithmTable[ARGUSSORTCOMPARE];
                     for (x = 0, i = 1; x < MAX_SORT_ALG_TYPES; x++) {
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

         if (parser->ArgusBaseLineFile != NULL) {
            if (!(ArgusPushFileList (parser, parser->ArgusBaseLineFile, ARGUS_DATA_SOURCE, -1, -1))) {
               ArgusLog(LOG_ERR, "ArgusClientInit: ArgusPushBaseLineFile  error: file %s", parser->ArgusBaseLineFile);
            }
            free(parser->ArgusBaseLineFile);
            parser->ArgusBaseLineFile = NULL;
         }

         if (parser->ArgusFlowModelFile) {
            parser->ArgusAggregator = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL);
            ArgusBaselineAggregator = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL);
            ArgusSampleAggregator   = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL);
         } else {
            char *mask = NULL;
            if (parser->ArgusMaskList == NULL) mask = "sid saddr daddr proto sport dport";

            parser->ArgusAggregator = ArgusNewAggregator(parser, mask, ARGUS_RECORD_AGGREGATOR);
            ArgusBaselineAggregator = ArgusNewAggregator(parser, mask, ARGUS_RECORD_AGGREGATOR);
            ArgusSampleAggregator   = ArgusNewAggregator(parser, mask, ARGUS_RECORD_AGGREGATOR);
         }

         if (parser->ArgusAggregator != NULL) {
            if (correct >= 0) {
               if (parser->ArgusAggregator->correct != NULL) { free(parser->ArgusAggregator->correct); parser->ArgusAggregator->correct = NULL; }
               if (ArgusBaselineAggregator->correct != NULL) { free(ArgusBaselineAggregator->correct); ArgusBaselineAggregator->correct = NULL; }
               if (ArgusSampleAggregator->correct   != NULL) { free(ArgusSampleAggregator->correct);   ArgusSampleAggregator->correct = NULL; }

               if (correct > 0) {
                  parser->ArgusPerformCorrection = 1;
                  parser->ArgusAggregator->correct = strdup("yes");
                  ArgusBaselineAggregator->correct = strdup("yes");
                  ArgusSampleAggregator->correct   = strdup("yes");
               }
            }

            if (parser->ArgusAggregator->pres != NULL) { free(parser->ArgusAggregator->pres); parser->ArgusAggregator->pres = NULL; }
            if (ArgusBaselineAggregator->pres != NULL) { free(ArgusBaselineAggregator->pres); ArgusBaselineAggregator->pres = NULL; }
            if (ArgusSampleAggregator->pres != NULL)   { free(ArgusSampleAggregator->pres); ArgusSampleAggregator->pres = NULL; }

            if (preserve > 0) {
               parser->ArgusAggregator->pres = strdup("yes");
               ArgusBaselineAggregator->pres = strdup("yes");
               ArgusSampleAggregator->pres   = strdup("yes");
            }

         } else {
            parser->RaCumulativeMerge = 0;
            bzero(parser->RaSortOptionStrings, sizeof(parser->RaSortOptionStrings));
            parser->RaSortOptionIndex = 0;
            parser->RaSortOptionStrings[parser->RaSortOptionIndex++] = "compare";
            parser->RaSortOptionStrings[parser->RaSortOptionIndex++] = "stime";
         }

         if (parser->ArgusBaseLineFile) {
#ifdef ARGUSDEBUG
            ArgusDebug (1, "ArgusClientInit baseline file %s\n", parser->ArgusBaseLineFile);
#endif
         }

         if (parser->ArgusRemoteHosts)
            if ((input = (void *)parser->ArgusRemoteHosts->start) != NULL)
               parser->RaTasksToDo = RA_ACTIVE;

         if ((ArgusEventAggregator = ArgusNewAggregator(parser, "sid saddr daddr proto sport dport", ARGUS_RECORD_AGGREGATOR)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

         if ((ArgusModelerQueue = ArgusNewQueue()) == NULL)
            ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

         if ((ArgusProbeQueue = ArgusNewQueue()) == NULL)
            ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

         if ((ArgusFileQueue = ArgusNewQueue()) == NULL)
            ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

         if ((RaBaselineProcess = RaCursesNewProcess(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: RaCursesNewProcess error");

         if ((RaSampleProcess = RaCursesNewProcess(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: RaCursesNewProcess error");

         if ((RaCursesProcess = RaCursesNewProcess(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: RaCursesNewProcess error");

         if ((RaEventProcess = RaCursesNewProcess(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: RaCursesNewProcess error");

         if ((RaHistoryProcess = RaCursesNewProcess(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: RaCursesNewProcess error");

         if (parser->ArgusAggregator != NULL)
            if (ArgusSorter->ArgusSortAlgorithms[0] == NULL) {
               ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortAlgorithmTable[ARGUSSORTCOMPARE];
               ArgusSorter->ArgusSortAlgorithms[1] = ArgusSortAlgorithmTable[ARGUSSORTPKTSCOUNT];
            }

         /* if content substitution, either time or any field, is used,
            size and count modes will not work properly.  If using
            the default count, set the value so that we generate only
            one filename.

            if no substitution, then we need to add "aa" suffix to the
            output file for count and size modes.
         */

         if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList)))) {
            if (parser->Sflag) {
               ArgusLog(LOG_ERR, "-w option not supported.");
            }
            ArgusCursesEnabled = 0;
         }
         
         for (i = 0; i < MAX_PRINT_ALG_TYPES; i++)
            if (parser->RaPrintAlgorithmList[i] != NULL)
               if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintIdleTime)
                  ArgusAlwaysUpdate++;

         if (parser->RaTasksToDo == RA_IDLE) {
            RaCursesUpdateInterval.tv_sec  = 1;
            RaCursesUpdateInterval.tv_usec = 0;


         } else {
            if ((parser->ArgusUpdateInterval.tv_sec > 0) || (parser->ArgusUpdateInterval.tv_usec > 0)) {
               RaCursesUpdateInterval.tv_sec  = parser->ArgusUpdateInterval.tv_sec;
               RaCursesUpdateInterval.tv_usec = parser->ArgusUpdateInterval.tv_usec;
            } else {
               RaCursesUpdateInterval.tv_sec  = 1;
               RaCursesUpdateInterval.tv_usec = 153613;
            }
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

         parser->ArgusReliableConnection = 1;
         parser->ArgusPrintJson = 0;

         if (ArgusWireless != NULL)
            bzero(ArgusWireless, sizeof(*ArgusWireless));
      }
   }
}


void RaArgusInputComplete (struct ArgusInput *input) {
   if (ArgusProcessingBaseline) {
      struct ArgusQueueStruct *queue = RaBaselineProcess->queue;
      ArgusProcessingBaseline = 0;
      if (queue != NULL) {
         ArgusProcessQueue(queue, ARGUS_PROCESS_BASELINE);
      }
      ArgusProcessingSample = 1;

   } else 
   if (ArgusProcessingSample) {
      struct ArgusQueueStruct *queue = RaSampleProcess->queue;
      if (queue != NULL) {
         ArgusProcessQueue(queue, ARGUS_PROCESS_SAMPLE);
         ArgusProcessingSample   = 0;
         ArgusProcessingComplete = 1;
         ArgusProcessQueue(queue, ARGUS_PROCESS_COMPLETE);
      }
   }

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
            case      0:
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

                  ArgusProcessQueue(RaCursesProcess->queue, ARGUS_PROCESS_DONE);

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

         ArgusProcessQueue(queue, ARGUS_TIMEOUT);

         ArgusParser->RaClientUpdate.tv_sec  =  tvp->tv_sec + RaProcessQueueTimer.tv_sec;
         ArgusParser->RaClientUpdate.tv_usec = tvp->tv_usec + RaProcessQueueTimer.tv_usec;

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

   fprintf (stdout, "RaTop Version %s\n", version);
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

void RaProcessThisLsOfEventRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessThisAirportEventRecord (struct ArgusParserStruct *, struct ArgusWirelessStruct *);

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
   struct RaCursesProcessStruct *RaProcess = NULL;

   struct ArgusRecordStruct *tns = NULL, *pns = NULL, *cns = NULL;
   struct ArgusAggregatorStruct *tagg, *agg = parser->ArgusAggregator;
   struct RaBinProcessStruct *RaBinProcess = parser->RaBinProcess;
   struct ArgusHashStruct *hstruct = NULL;
   int found = 0;

   /* terminal aggregator -- The aggregators form a singly-linked list
    * so we have to find this value along the way.  Initialize to the
    * first element for the case where there is only one.
    */
   tagg = parser->ArgusAggregator;

   while (ArgusParser->Pauseflag) {
      struct timespec ts = {0, 15000000};
      nanosleep (&ts, NULL);
      ArgusClientTimeout ();
   }

   if (ArgusParser->RaClientUpdate.tv_sec == 0) {
      ArgusParser->RaClientUpdate.tv_sec = parser->ArgusGlobalTime.tv_sec;
      ArgusParser->RaClientUpdate.tv_usec = 0;
   }
   if (RaCursesStartTime.tv_sec == 0)
      gettimeofday (&RaCursesStartTime, 0L);

   gettimeofday (&RaCursesStopTime, 0L);

   if (ArgusProcessingBaseline) {
      RaProcess = RaBaselineProcess;
   } else
   if (ArgusProcessingSample) {
      RaProcess = RaSampleProcess;
   } else
   if (ArgusProcessingComplete) {
      RaProcess = RaCursesProcess;
   }

   if ((agg != NULL) && (parser->RaCumulativeMerge)) {
      struct ArgusFlow *flow = NULL;
#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&RaProcess->queue->lock);
#endif

      while (agg && !found) {                     // lets find this flow in the cache with this aggregation
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

            if (agg->mask) {
               if ((agg->rap = RaFlowModelOverRides(agg, cns)) == NULL)
                  agg->rap = agg->drap;

               ArgusGenerateNewFlow(agg, cns);
               agg->ArgusMaskDefs = NULL;

               if ((hstruct = ArgusGenerateHashStruct(agg, cns, (struct ArgusFlow *)&agg->fstruct)) != NULL) {
                  if ((pns = ArgusFindRecord(RaProcess->htable, hstruct)) == NULL) {
                     flow = (struct ArgusFlow *) cns->dsrs[ARGUS_FLOW_INDEX];
                     int tryreverse = 0;

                     if (flow != NULL) {
                        if (agg->correct != NULL)
                           tryreverse = 1;

                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: {
                              switch (flow->ip_flow.ip_p) {
                                 case IPPROTO_ESP:
                                    tryreverse = 0;
                                    break;
                              }
                              break;
                           }
                           case ARGUS_TYPE_IPV6: {
                              switch (flow->ipv6_flow.ip_p) {
                                 case IPPROTO_ESP:
                                    tryreverse = 0;
                                    break;
                              }
                              break;
                           }
                        }

                        if (!parser->RaMonMode && tryreverse) {
                           struct ArgusRecordStruct *dns = ArgusCopyRecordStruct(cns);

                           ArgusReverseRecord (dns);

                           ArgusGenerateNewFlow(agg, dns);
                           flow = (struct ArgusFlow *) dns->dsrs[ARGUS_FLOW_INDEX];

                           if ((hstruct = ArgusGenerateHashStruct(agg, dns, flow)) == NULL)
                              ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                           if ((pns = ArgusFindRecord(RaProcess->htable, hstruct)) != NULL) {
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

                  if (pns) {
                     if (pns->qhdr.queue) {
                        if (pns->qhdr.queue != RaProcess->queue)
                           ArgusRemoveFromQueue (pns->qhdr.queue, &pns->qhdr, ARGUS_LOCK);
                        else
                           ArgusRemoveFromQueue (pns->qhdr.queue, &pns->qhdr, ARGUS_NOLOCK);
                     }
                     pns->status |= ARGUS_RECORD_MODIFIED;

                  } else {
                     tagg = agg;
                     agg = agg->nxt;
                  }
               }
            }
            found++;

         } else
            agg = agg->nxt;
      }

      if (agg == NULL)                 // if didn't find the aggregation model, 
         agg = tagg;                   // then use the terminal agg (tagg)

//
//     ns - original ns record
//
//    cns - copy of original ns record, this is what we'll work with in this routine
//          If we're chopping this record up, we'll do it with the cns
//
//    pns - cached ns record matching the working cns.  this is what we'll merge into


      if (cns) {        // OK we're processing something from the ns, and we've got a copy

         if (!(RaBinProcess && (RaBinProcess->nadp.mode == ARGUSSPLITRATE))) {   //  Are we not processing bins ???  
            if (ArgusProcessingBaseline) {
               if (pns) {                                                           //  We found a match ...
                  if (RaTopReplace) {
                     ArgusReplaceRecords (ArgusParser->ArgusAggregator, pns, cns);
                     ArgusDeleteRecordStruct(ArgusParser, pns);
                     pns = cns;
                  } else {
                     ArgusMergeRecords (ArgusParser->ArgusAggregator, pns, cns);
                     ArgusDeleteRecordStruct(ArgusParser, cns);
                  }
                  pns->status |= ARGUS_RECORD_MODIFIED | ARGUS_RECORD_BASELINE | ARGUS_NSR_STICKY;

               } else {
                  pns = cns;
       
                  if (!found)    // If we didn't find a pns, we'll need to setup to insert the cns
                     if ((hstruct = ArgusGenerateHashStruct(agg, pns, flow)) == NULL)
                        ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));
       
                  pns->htblhdr = ArgusAddHashEntry (RaProcess->htable, pns, hstruct);
                  pns->status |= ARGUS_RECORD_NEW | ARGUS_RECORD_MODIFIED | ARGUS_RECORD_BASELINE | ARGUS_NSR_STICKY;
               }

            } else {
               if (pns) {
                  //  We found a match ...
                  if (pns->status & ARGUS_RECORD_MATCH) {
                     ArgusMergeRecords (ArgusParser->ArgusAggregator, pns, cns);
                     ArgusDeleteRecordStruct(ArgusParser, cns);
                  } else {
                     ArgusReplaceRecords (ArgusParser->ArgusAggregator, pns, cns);
                     if (pns->status & ARGUS_RECORD_BASELINE) {
                        cns->status |= (ARGUS_RECORD_BASELINE | ARGUS_NSR_STICKY);
                     }
                     ArgusDeleteRecordStruct(ArgusParser, pns);
                     pns = cns;
                     pns->status |= ARGUS_RECORD_MATCH;
                  }
               } else {
                  pns = cns;

                  if (!found)    // If we didn't find a pns, we'll need to setup to insert the cns
                     if ((hstruct = ArgusGenerateHashStruct(agg, pns, flow)) == NULL)
                        ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                  pns->htblhdr = ArgusAddHashEntry (RaProcess->htable, pns, hstruct);
                  pns->status |= ARGUS_RECORD_NEW;
               }
               pns->status |= ARGUS_RECORD_MODIFIED;
            }

            ArgusAddToQueue (RaProcess->queue, &pns->qhdr, ARGUS_NOLOCK);

         } else {
            ArgusAlignInit(parser, cns, &RaBinProcess->nadp);
      
            while ((tns = ArgusAlignRecord(parser, cns, &RaBinProcess->nadp)) != NULL) {
               struct ArgusRecordStruct *rec = NULL;
               int offset = 0;
         
               if (pns) {
                  if (pns->bins) {
                     pns->bins->nadp.RaStartTmStruct = RaBinProcess->nadp.RaStartTmStruct;
                     pns->bins->nadp.RaEndTmStruct   = RaBinProcess->nadp.RaEndTmStruct;
         
                     if (ArgusInsertRecord (parser, pns->bins, tns, offset, &rec) <= 0) {
                        ArgusDeleteRecordStruct(ArgusParser, tns);
                        tns = NULL;
                     }
         
                     pns->bins->status |= RA_DIRTYBINS;
         
                  } else {
                     if (RaTopReplace) {
                       ArgusDeleteRecordStruct(ArgusParser, pns);
                       pns = tns;
                     } else {
                       ArgusMergeRecords (ArgusParser->ArgusAggregator, pns, tns);
                       ArgusDeleteRecordStruct(ArgusParser, tns);
                     }
                     pns->status |= ARGUS_RECORD_MODIFIED;
                  }
         
                  ArgusRemoveFromQueue(RaProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
                  ArgusAddToQueue (RaProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
         
               } else {
                  if ((pns =  ArgusCopyRecordStruct(tns)) != NULL) { /* new record */
                     if (!found)    // If we didn't find a pns, we'll need to setup to insert the cns
                        if ((hstruct = ArgusGenerateHashStruct(agg, pns, flow)) == NULL)
                           ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                     pns->htblhdr = ArgusAddHashEntry (RaProcess->htable, pns, hstruct);
                     ArgusAddToQueue (RaProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
         
                     if ((pns->bins = (struct RaBinProcessStruct *)ArgusNewRateBins(parser, pns)) == NULL)
                        ArgusLog (LOG_ERR, "ArgusProcessThisRecord: ArgusNewRateBins error %s", strerror(errno));

//                offset = (parser->Bflag * 1000000LL) / pns->bins->size;
         
                     if (ArgusInsertRecord (parser, pns->bins, tns, offset, &rec) <= 0)
                        ArgusDeleteRecordStruct(ArgusParser, tns);
      
                     pns->bins->status |= RA_DIRTYBINS;
                     pns->status |= ARGUS_RECORD_NEW | ARGUS_RECORD_MODIFIED;
                  }
               }
            }

            ArgusDeleteRecordStruct(ArgusParser, cns);
         }

         if (pns) {
//          for (i = 0; i < ArgusTotalAnalytics; i++) {
               if (pns->status & ARGUS_RECORD_NEW) {
                  if (parser->ArgusCorrelateEvents)
                     ArgusCorrelateRecord(pns);

                  pns->status &= ~ARGUS_RECORD_NEW;
               }
//          }
         }
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&RaProcess->queue->lock);
#endif

   } else {
      cns = ArgusCopyRecordStruct(ns);
      ArgusAddToQueue (RaProcess->queue, &cns->qhdr, ARGUS_LOCK);
      cns->status |= ARGUS_RECORD_MODIFIED;
   }

   RaProcess->queue->status |= RA_MODIFIED;

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessThisRecord () returning\n"); 
#endif
}


void
RaProcessThisLsOfEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusRecordStruct *tns = NULL, *pns = NULL, *cns = NULL;
   struct ArgusAggregatorStruct *agg = ArgusEventAggregator;
   struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusHashStruct *hstruct = NULL;
   int found = 0;

   if (ArgusParser->RaClientUpdate.tv_sec == 0) {
      ArgusParser->RaClientUpdate.tv_sec = parser->ArgusGlobalTime.tv_sec;
      ArgusParser->RaClientUpdate.tv_usec = 0;
   }

   if (RaCursesStartTime.tv_sec == 0)
      gettimeofday (&RaCursesStartTime, 0L);

   gettimeofday (&RaCursesStopTime, 0L);

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
               struct ArgusFlow *cflow = (struct ArgusFlow *) cns->dsrs[ARGUS_FLOW_INDEX];
               int tryreverse = 0;

               if (cflow->hdr.subtype & ARGUS_FLOW_KEY_ATTRIBUTE)
                  tryreverse = 1;

               if (agg->correct == NULL)
                  tryreverse = 0;

               switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4: {
                     switch (flow->ip_flow.ip_p) {
                        case IPPROTO_ESP:
                           tryreverse = 0;
                           break;
                     }
                     break;
                  }
                  case ARGUS_TYPE_IPV6: {
                     switch (flow->ipv6_flow.ip_p) {
                        case IPPROTO_ESP:
                           tryreverse = 0;
                           break;
                     }
                     break;
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
   ArgusDebug (4, "RaProcessThisLsOfEventRecord () returning\n");
#endif
}

void
RaProcessThisAirportEventRecord (struct ArgusParserStruct *parser, struct ArgusWirelessStruct *ws)
{

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&RaCursesLock);
#endif

   ArgusWireless->agrCtlRSSI  = ws->agrCtlRSSI;
   ArgusWireless->agrExtNoise = ws->agrExtRSSI;
   ArgusWireless->agrCtlNoise = ws->agrCtlNoise;
   ArgusWireless->agrExtNoise = ws->agrExtNoise;

   if (ArgusWireless->state != NULL) {
      free(ArgusWireless->state);
      ArgusWireless->state = NULL;
   }

   if (ws->state)
      ArgusWireless->state = strdup(ws->state);

   if (ArgusWireless->opMode != NULL) {
      free(ArgusWireless->opMode);
      ArgusWireless->opMode = NULL;
   }

   if (ws->opMode)
      ArgusWireless->opMode = strdup(ws->opMode);

   ArgusWireless->lastTxRate = ws->lastTxRate;
   ArgusWireless->maxRate = ws->maxRate;
   ArgusWireless->lastAssocStatus = ws->lastAssocStatus;

   if (ArgusWireless->auth != NULL) {
      free(ArgusWireless->auth);
      ArgusWireless->auth = NULL;
   }

   if (ws->auth)
      ArgusWireless->auth = strdup(ws->auth);

   if (ArgusWireless->linkAuth != NULL) {
      free(ArgusWireless->linkAuth);
      ArgusWireless->linkAuth = NULL;
   }
      
   if (ws->linkAuth)
      ArgusWireless->linkAuth = strdup(ws->linkAuth);

   if (ArgusWireless->bssid != NULL) {
      free(ArgusWireless->bssid);
      ArgusWireless->bssid = NULL;
   }

   if (ws->bssid)
      if (strcmp(ws->bssid, "0:0:0:0:0:0"))
         ArgusWireless->bssid = strdup(ws->bssid);

   if (ArgusWireless->ssid != NULL) {
      free(ArgusWireless->ssid);
      ArgusWireless->ssid = NULL;
   }

   if (ws->ssid)
      ArgusWireless->ssid = strdup(ws->ssid);

   ArgusWireless->mcs = ws->mcs;
   ArgusWireless->channel = ws->channel;

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&RaCursesLock);
#endif

#if defined(ARGUSDEBUG)
   ArgusDebug (1, "RaProcessThisAirportEventRecord () returning\n"); 
#endif
}

void
RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
 
#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessManRecord () returning\n"); 
#endif
}

void RaParseAirportEventRecord (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void RaParseLsOfEventRecord (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void RaParseStumblerEventRecord (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void RaParseExtIPEventRecord (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void RaParseNetstatEventRecord (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
void RaParseSnmpEventRecord (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);

struct ArgusParseEventFieldStruct {
   char *field;
   int index, type, value;
   void (*parse)(struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
};

#define MAX_PARSE_ALG_TYPES		6

struct ArgusParseEventFieldStruct 
RaParseEventAlgorithmTable[MAX_PARSE_ALG_TYPES] = {
#define ARGUSPARSEAIRPORT		0
   { "argus-airport", 1, 0, ARGUSPARSEAIRPORT, RaParseAirportEventRecord},
#define ARGUSPARSELSOF			1
   { "argus-lsof", 1, 0, ARGUSPARSELSOF, RaParseLsOfEventRecord},
#define ARGUSPARSESTUMBLER		2
   { "argus-stumble", 1, 0, ARGUSPARSESTUMBLER, RaParseStumblerEventRecord},
#define ARGUSPARSEEXTIP			3
   { "argus-extip", 1, 0, ARGUSPARSEEXTIP, RaParseExtIPEventRecord},
#define ARGUSPARSENETSTAT		4
   { "argus-netstat", 1, 0, ARGUSPARSESTUMBLER, RaParseNetstatEventRecord},
#define ARGUSPARSESNMP			5
   { "argus-snmp", 1, 0, ARGUSPARSESTUMBLER, RaParseSnmpEventRecord}
};


void
RaProcessEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   if (parser->ArgusCorrelateEvents) {
      struct ArgusDataStruct *data = NULL;
      char buf[0x10000], *ptr = buf;
      unsigned long len = 0x10000;
      char *dptr = NULL;
      int i;

      if ((data = (void *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) == NULL)
         return;

      if (data->hdr.subtype & ARGUS_DATA_COMPRESS) {
#if defined(HAVE_ZLIB_H)
         bzero (ptr, sizeof(buf));
         uncompress((Bytef *)ptr, (uLongf *)&len, (Bytef *)&data->array, data->count);
         dptr = ptr;
#else
#if defined(ARGUSDEBUG)
         ArgusDebug (5, "RaProcessEventRecord: unable to decompress payload\n");
#endif
         return;
#endif
      } else {
         dptr = data->array;
      }

      for (i = 0; i < MAX_PARSE_ALG_TYPES; i++) {
         if (strstr(dptr, RaParseEventAlgorithmTable[i].field))
            if (RaParseEventAlgorithmTable[i].parse != NULL)
               RaParseEventAlgorithmTable[i].parse(parser, dptr, argus, 0);
      }

      ArgusCorrelateQueue (RaCursesProcess->queue);
   }
#if defined(ARGUSDEBUG)
   ArgusDebug (6, "RaProcessEventRecord (%p, %p)\n", parser, argus);
#endif
}


void
RaParseAirportEventRecord (struct ArgusParserStruct *parser, char *dptr, struct ArgusRecordStruct *argus, int status)
{
   struct ArgusWirelessStruct wsbuf, *ws = &wsbuf;

   struct ArgusTimeObject *time = (void *)argus->dsrs[ARGUS_TIME_INDEX];
   struct timeval tvpbuf, *tvp = &tvpbuf;
   char tbuf[129], sbuf[129], *sptr = sbuf;
   char *str;
   int i;

   tbuf[0] = '\0';
   bzero (sptr, sizeof(sbuf));
   bzero (ws, sizeof(wsbuf));

   tvp->tv_sec  = time->src.start.tv_sec;
   tvp->tv_usec = time->src.start.tv_usec;

   ArgusPrintTime(parser, tbuf, sizeof(tbuf), tvp);
   ArgusPrintSID(parser, sptr, argus, 24);

   while (isspace((int)sbuf[strlen(sbuf) - 1]))
      sbuf[strlen(sbuf) - 1] = '\0';

   while (isspace((int)*sptr)) sptr++;

   while ((str = strsep(&dptr, "\n")) != NULL) {
      for (i = 0; i < MAX_AIRPORT_PARSE_TOKENS; i++) {
         if (strstr(str, ArgusParseAirportTokens[i])) {
            char *ptr, *sptr;
            if ((ptr = strchr(str, '\"')) != NULL) {
               ptr++;
               if ((sptr = strchr(ptr, '\"')) != NULL) {
                  *sptr = '\0';
               }

               switch (i) {
                  case ARGUSWSAGRCTLRSSI:     ws->agrCtlRSSI = strtol(ptr, NULL, 10); break;
                  case ARGUSWSAGREXTRSSI:     ws->agrExtRSSI = strtol(ptr, NULL, 10); break;
                  case ARGUSWSAGRCTLNOISE:   ws->agrCtlNoise = strtol(ptr, NULL, 10); break;
                  case ARGUSWSAGREXTNOISE:   ws->agrExtNoise = strtol(ptr, NULL, 10); break;
                  case ARGUSWSSTATE:               ws->state = strdup(ptr); break;
                  case ARGUSWSOPSTATE:            ws->opMode = strdup(ptr); break;
                  case ARGUSWSLASTTXRATE:     ws->lastTxRate = strtol(ptr, NULL, 10); break;
                  case ARGUSWSMAXRATE:           ws->maxRate = strtol(ptr, NULL, 10); break;
                  case ARGUSWSLASTASSOC: ws->lastAssocStatus = strtol(ptr, NULL, 10); break;
                  case ARGUSWSAUTH:                 ws->auth = strdup(ptr); break;
                  case ARGUSWSLINKAUTH:         ws->linkAuth = strdup(ptr); break;
                  case ARGUSWSBSSID:               ws->bssid = strdup(ptr); break;
                  case ARGUSWSSSID:                 ws->ssid = strdup(ptr); break;
                  case ARGUSWSMCS:                   ws->mcs = strtol(ptr, NULL, 10); break;
                  case ARGUSWSCHANNEL:           ws->channel = strtol(ptr, NULL, 10); break;
               }
            }
            break;
         }
      }
   }

   RaProcessThisAirportEventRecord (parser, ws);

   if (ws->state != NULL) free (ws->state);
   if (ws->opMode != NULL) free (ws->opMode);
   if (ws->auth != NULL) free (ws->auth);
   if (ws->linkAuth != NULL) free (ws->linkAuth);
   if (ws->bssid != NULL) free (ws->bssid);
   if (ws->ssid != NULL) free (ws->ssid);

#if defined(ARGUSDEBUG)
   ArgusDebug (1, "RaParseAirportEventRecord (%p, %p)\n", parser, argus);
#endif
}


void
RaParseStumblerEventRecord (struct ArgusParserStruct *parser, char *dptr, struct ArgusRecordStruct *argus, int status)
{
 
#if defined(ARGUSDEBUG)
   ArgusDebug (1, "RaParseStumblerEventRecord (%p, %p)\n", parser, argus);
#endif
}

void
RaParseExtIPEventRecord (struct ArgusParserStruct *parser, char *dptr, struct ArgusRecordStruct *argus, int status)
{
 
#if defined(ARGUSDEBUG)
   ArgusDebug (1, "RaParseExtIPEventRecord (%p, %p)\n", parser, argus);
#endif
}

void
RaParseNetstatEventRecord (struct ArgusParserStruct *parser, char *dptr, struct ArgusRecordStruct *argus, int status)
{
 
#if defined(ARGUSDEBUG)
   ArgusDebug (1, "RaParseNetstatEventRecord (%p, %p)\n", parser, argus);
#endif
}

void
RaParseSnmpEventRecord (struct ArgusParserStruct *parser, char *dptr, struct ArgusRecordStruct *argus, int status)
{
 
#if defined(ARGUSDEBUG)
   ArgusDebug (1, "RaParseSnmpEventRecord (%p, %p)\n", parser, argus);
#endif
}


void
RaParseLsOfEventRecord (struct ArgusParserStruct *parser, char *dptr, struct ArgusRecordStruct *argus, int status)
{
   struct ArgusTimeObject *time = (void *)argus->dsrs[ARGUS_TIME_INDEX];
   struct timeval tvpbuf, *tvp = &tvpbuf;
   char tbuf[129], sbuf[129], *sptr = sbuf;
   char *str;
   int title = 0;

   tbuf[0] = '\0';
   bzero (sptr, sizeof(sbuf));
   tvp->tv_sec  = time->src.start.tv_sec;
   tvp->tv_usec = time->src.start.tv_usec;
 
   ArgusPrintTime(parser, tbuf, sizeof(tbuf), tvp);
   ArgusPrintSID(parser, sptr, argus, 48);

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
                           flow->ipv6_flow.smask = 128;
                           flow->ipv6_flow.dmask = 128;
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
                     ArgusDebug (3, "RaProcessEventRecord: %s:srcid=%s:%s: %s %s.%s -> %s.%s %s\n", tbuf, sptr, app, node, 
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

                           bzero(lptr, MAXBUFFERLEN);
                           sprintf (lptr, "pid=%s:usr=%s:app=%s", pid, user, app);

                           label->hdr.type    = ARGUS_LABEL_DSR;
                           label->hdr.subtype = ARGUS_PROC_LABEL;
                           label->hdr.argus_dsrvl8.len  = 1 + ((strlen(lptr) + 3)/4);
                           label->l_un.label = lptr;
                           ns->dsrindex |= (0x01 << ARGUS_LABEL_INDEX);

                           RaProcessThisLsOfEventRecord (parser, ns);
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

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "RaParseLsOfEventRecord (%p, %p)\n", parser, argus);
#endif
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
   int rtime = 0;

   if (rbps && (rbps->size != 0)) {
      rtime = ((((ArgusParser->ArgusGlobalTime.tv_sec * 1000000LL) /rbps->size)) * rbps->size)/1000000LL;;

      if ((rbps->startpt.tv_sec + dtime) < rtime) {
         count = (rbps->end - rbps->start)/rbps->size;

         if ((rbps->startpt.tv_sec + dtime) < rtime) {
            ArgusShiftArray(ArgusParser, rbps, count, ARGUS_LOCK);
#if defined(ARGUS_CURSES)
            ArgusUpdateScreen();
#endif
            rbps->status |= RA_DIRTYBINS;
            retn = 1;
         }
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (2, "ArgusProcessBins (0x%x, 0x%x) count %d, dtime %d, rtime %d returning %d", ns, rbps, cnt, dtime, rtime, retn); 
#endif

   return (retn);
}


extern struct ArgusRecordStruct *ArgusSearchHitRecord;
struct ArgusQueueStruct *ArgusTimeoutQueue = NULL;

int
ArgusProcessQueue (struct ArgusQueueStruct *queue, int type)
{
   struct timeval tbuf, *tvp = &tbuf;
   int retn = 0, x, z;
   int process = 1;

   if (type == ARGUS_TIMEOUT) {
      if (ArgusParser->timeout.tv_sec == 0) {
         process = 0;
      }
   }
   
   if (process) {
      struct ArgusRecordStruct *ns;
      struct timeval lasttime;
      int count, modified = 0;
      unsigned int status = 0;

      if (ArgusTimeoutQueue == NULL)
         if ((ArgusTimeoutQueue = ArgusNewQueue()) == NULL)
            ArgusLog (LOG_ERR, "RaProcessQueue: ArgusNewQueue()error %s", strerror(errno));

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&queue->lock);
#endif
      status = queue->status;
      count = queue->count;

      for (x = 0, z = count; x < z; x++) {
         if ((ns = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
            switch (type) {
               case ARGUS_TIMEOUT: {
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

#if defined(ARGUS_CURSES)
                        if (ArgusSearchHitRecord == ns)
                           ArgusResetSearch();
#endif
                        ArgusDeleteRecordStruct (ArgusParser, ns);
                        modified++;

                     } else {
                        struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;
                        struct ArgusHashStruct *hstruct = NULL;
                        struct ArgusRecordStruct *pns = NULL;
                        struct ArgusFlow *flow;

                        if (ns->status & ARGUS_RECORD_BASELINE) {
                           if (ns->status & ARGUS_RECORD_MATCH) {
                              if ((flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
                                 agg->ArgusMaskDefs = NULL;

                                 if ((hstruct = ArgusGenerateHashStruct(agg, ns, flow)) == NULL)
                                    ArgusLog (LOG_ERR, "RaProcessRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                                 if ((pns = ArgusFindRecord(RaBaselineProcess->htable, hstruct)) != NULL) {
                                    struct ArgusRecordStruct *cns = ArgusCopyRecordStruct(pns);
                                    ArgusReplaceRecords (ArgusParser->ArgusAggregator, ns, cns);
                                    if (ns->status & ARGUS_RECORD_BASELINE) {
                                       cns->status |= (ARGUS_RECORD_BASELINE | ARGUS_NSR_STICKY);
                                    }
                                    ArgusDeleteRecordStruct(ArgusParser, ns);
                                    ns = cns;
                                    cns = NULL;
                                 }
                              }
                           }
                           if (ns != NULL) {
                              ArgusAddToQueue (queue, &ns->qhdr, ARGUS_NOLOCK);
                              ns->qhdr.lasttime = lasttime;
                           }
                           ns->status &= ~ARGUS_RECORD_MATCH;

                        } else
                           ArgusDeleteRecordStruct (ArgusParser, ns);

                        modified++;
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
                     modified++;
                  }
                  break;
               }

               case ARGUS_PROCESS_BASELINE: {
                  struct ArgusRecordStruct *cns = ArgusCopyRecordStruct(ns);

                  ArgusAddToQueue (queue, &ns->qhdr, ARGUS_NOLOCK);
                  cns->status |= ARGUS_RECORD_BASELINE | ARGUS_NSR_STICKY;

                  ArgusProcessingComplete = 1;
                  RaProcessThisRecord (ArgusParser, cns);
                  ArgusProcessingComplete = 0;
                  modified++;
                  break;
               }

               case ARGUS_PROCESS_SAMPLE: {
                  ArgusAddToQueue (queue, &ns->qhdr, ARGUS_NOLOCK);
                  break;
               }

               case ARGUS_PROCESS_COMPLETE: {
                  RaProcessThisRecord (ArgusParser, ns);
                  ArgusAddToQueue (queue, &ns->qhdr, ARGUS_NOLOCK);
                  modified++;
                  break;
               }

               case ARGUS_PROCESS_DONE: {
                  if (!(ArgusParser->RaCursesMode)) {
                     if (queue == RaCursesProcess->queue) {
                        if (ArgusParser->ArgusWfileList != NULL) {
                           struct ArgusWfileStruct *wfile = NULL;
                           struct ArgusRecord *argusrec = NULL;
                           struct ArgusListObjectStruct *lobj = NULL;
                           int i, count = ArgusParser->ArgusWfileList->count;

                           if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
                              for (i = 0; i < count; i++) {
                                 if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                                    if ((argusrec = ArgusGenerateRecord (ns, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
                                       int rv;
#ifdef _LITTLE_ENDIAN
                                       ArgusHtoN(argusrec);
#endif
                                       if ((rv = ArgusWriteNewLogfile (ArgusParser, ns->input, wfile, argusrec)) < 0)
                                          ArgusLog(LOG_ERR, "%s unable to open file\n", __func__);
                                    }
                                 }
                              }
                           }
                        }
                     }
                  }
                  break;
               }
            }
         }
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock);
#endif

      if (modified)
         RaClientSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);

      queue->status = status;
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
   ArgusDebug (5, "ArgusCorrelateQueue (0x%x) returning %d", queue, retn);
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
                     case ARGUS_TYPE_IPV6: {
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
            ArgusDebug (3, "ArgusCorrelateRecord (0x%x) merged label", pns); 
#endif

         } else {
            if (l2 && (l1 == NULL)) {
               ns->dsrs[ARGUS_LABEL_INDEX] = calloc(1, sizeof(struct ArgusLabelStruct));
               l1 = (void *) ns->dsrs[ARGUS_LABEL_INDEX];

               bcopy(l2, l1, sizeof(*l2));

               if (l2->l_un.label)
                  l1->l_un.label = strdup(l2->l_un.label);

               ns->dsrindex |= (0x1 << ARGUS_LABEL_INDEX);
#if defined(ARGUSDEBUG)
               ArgusDebug (3, "ArgusCorrelateRecord (0x%x) added label", pns); 
#endif
            }
         }

         pns->status |= ARGUS_RECORD_MODIFIED;
      }

      ArgusDeleteRecordStruct(ArgusParser, cns);
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (5, "ArgusCorrelateRecord (0x%x) returning %d", ns, retn); 
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
   ArgusDebug (5, "RaCursesNewProcess(0x%x) returns 0x%x\n", parser, retn);
#endif
   return (retn);
}


 
int
RaClientSortQueue (struct ArgusSorterStruct *sorter, struct ArgusQueueStruct *queue, int type)
{
   struct nff_insn *fcode = NULL;
   int cnt, x = 0;

   ArgusParser->RaTasksToDo |= RA_SORTING;
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
            if (ns->rank != (i + 1)) {
               ns->rank = i + 1;
               ns->status |= ARGUS_RECORD_MODIFIED;
            }
         }

      } else 
         ArgusLog (LOG_ERR, "RaClientSortQueue: ArgusMalloc(%d) %s\n", sizeof(struct ArgusRecord *), cnt, strerror(errno));
   }

   bzero (&ArgusParser->ArgusStartTimeVal, sizeof(ArgusParser->ArgusStartTimeVal));
   queue->status &= ~RA_MODIFIED;

#if defined(ARGUS_THREADS)
   if (type == ARGUS_LOCK)
      pthread_mutex_unlock(&queue->lock);
#endif
   ArgusParser->RaTasksToDo &= ~RA_SORTING;

#ifdef ARGUSDEBUG 
   ArgusDebug (5, "RaClientSortQueue(0x%x, 0x%x, %d) returns %d\n", sorter, queue, type, x);
#endif

   return(x);
}

