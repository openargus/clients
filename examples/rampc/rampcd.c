/*
 * Gargoyle Client Software.  Tools to read, analyze and manage Argus data.
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
 */

/*
 * rampcd.c  - this is the daemon form of the multi-probe correlator.
 *    Acting just like a ra* program, supporting all the options
 *    and functions of ra(), and providing access to data, like
 *    argus, supporting remote filtering, and MAR record generation.
 *    
 *    This is an important workhorse for the argus architecture,
 *    as multi-probe correlation is an enabler for so much stuff.
 *    
 */

/* 
 * $Id: //depot/gargoyle/clients/examples/rampc/rampcd.c#17 $
 * $DateTime: 2016/09/20 14:24:49 $
 * $Change: 3195 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <grp.h>
#include <pwd.h>

#include <signal.h>
#include <ctype.h>

#if defined(HAVE_ZLIB_H)
#include <zlib.h>
#endif

#if defined(HAVE_SYS_VFS_H)
#include <sys/vfs.h>
#else
#include <sys/param.h>
#include <sys/mount.h>
#endif

#include <argus_compat.h>
#include <argus_output.h>

#include <rabins.h>

#include <rasplit.h>
#include <rampcd.h>
#include <argus_sort.h>
#include <argus_cluster.h>
#include <argus_metric.h>


int RaRealTime = 0;
float RaUpdateRate = 1.0;
                                                                                                                           
struct timeval ArgusLastRealTime = {0, 0};
struct timeval ArgusLastTime     = {0, 0};
struct timeval ArgusThisTime     = {0, 0};
                                                                                                                           
struct timeval dLastTime = {0, 0};
struct timeval dRealTime = {0, 0};
struct timeval dThisTime = {0, 0};
struct timeval dTime     = {0, 0};
                                                                                                                           
long long thisUsec = 0;
                                                                                                                           
void RadiumSendFile (struct ArgusOutputStruct *, struct ArgusClientData *, char *, int);

extern char *chroot_dir;
extern uid_t new_uid;
extern gid_t new_gid;

void ArgusSetChroot(char *);


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode;
   FILE *tmpfile = NULL;
   struct timeval *tvp;
   int pid, dflag, correct = 1;
   int size = 5000000;
#if defined(ARGUS_THREADS)
   sigset_t blocked_signals;
   int thread = 0;

   thread++;
#endif /* ARGUS_THREADS */
 
/*
   if (thread == 0)
      ArgusLog (LOG_ERR, "not compiled with pthread support.  exiting");
*/
   parser->RaWriteOut = 1;
   parser->ArgusReverse = 1;

   if (!(parser->RaInitialized)) {

      if (!(strncmp(parser->ArgusProgramName, "rampc", 5)))
         parser->RaCorrelate = 1;

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "correct", 7)))
               correct = 1;
            else
            if (!(strncasecmp (mode->mode, "nocorrect", 9)))
               correct = 0;
            else
            if (!(strncasecmp (mode->mode, "ind", 3)))
               ArgusProcessFileIndependantly = 1;
            else
            if (!(strncasecmp (mode->mode, "replace", 7))) {
               ArgusProcessFileIndependantly = 1;
               parser->ArgusReplaceMode++;
               if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList)))) {
                  ArgusLog (LOG_ERR, "replace mode and -w option are incompatible\n");
               }
            } else
            if (!(strncasecmp (mode->mode, "net", 3))) {
               RaMpcNetMode++;
               RaMpcProbeMode = 0;
            } else
            if (!(strncasecmp (mode->mode, "probe", 5))) {
               RaMpcProbeMode++;
               RaMpcNetMode = 0;
            }
            mode = mode->nxt;
         }
      }

      dflag = parser->dflag;
      parser->dflag = 0;

      if (parser->ArgusFlowModelFile != NULL) {
         RadiumParseResourceFile (parser, parser->ArgusFlowModelFile);
      } else {
         if (!(parser->Xflag)) {
            RadiumParseResourceFile (parser, "/etc/radium.conf");
         }
      }

      parser->dflag = (parser->dflag) ? (dflag ? 0 : 1) : dflag;

      if (parser->RaCorrelate) {
         struct ArgusAdjustStruct *nadp;

         parser->RaCumulativeMerge = 1;
         parser->timeout.tv_sec  = 0;
         parser->timeout.tv_usec = 750000;

         if ((parser->RaBinProcess = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*parser->RaBinProcess))) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

#if defined(ARGUS_THREADS)
         pthread_mutex_init(&parser->RaBinProcess->lock, NULL);
#endif

         nadp = &parser->RaBinProcess->nadp;
         bzero((char *)nadp, sizeof(*nadp));

         nadp->mode   = ARGUSSPLITTIME;
         nadp->qual   = ARGUSSPLITSECOND;
         nadp->size   = 5000000;
         nadp->modify = 1;
         nadp->slen   = 2;
         nadp->value  = 1;

         if ((ArgusSorter = ArgusNewSorter(parser)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewSorter error %s", strerror(errno));

         ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;

         parser->RaBinProcess->size  = nadp->size;

         parser->RaClientTimeout.tv_sec  = 0;
         parser->RaClientTimeout.tv_usec = 274895;
         parser->RaInitialized++;

         if (ArgusParser->Bflag == 0)
            ArgusParser->Bflag = 3000000LL;

         parser->RaBinProcess->rtime.tv_sec = ArgusParser->ArgusRealTime.tv_sec;

         if (ArgusParser->startime_t.tv_sec && ArgusParser->lasttime_t.tv_sec) {
            nadp->count = ((ArgusParser->lasttime_t.tv_sec - ArgusParser->startime_t.tv_sec)/size) + 1;
         } else {
            int cnt = (parser->Bflag / nadp->size);
            nadp->count = ((size > cnt) ? size : cnt);
            nadp->count += 2;
         }
      }

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if ((ArgusBinProcess = RaNewBinProcess(parser, size)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

      ArgusBinProcess->size  = size;

      if ((ArgusProbeQueue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewQueue error");

      ArgusProbeTable.size  = 1024;
      if ((ArgusProbeTable.array = (struct ArgusHashTableHdr **)
            ArgusCalloc (1024, sizeof (struct ArgusHashTableHdr))) == NULL)
         ArgusLog (LOG_ERR, "RaTimeInit: ArgusCalloc error %s\n", strerror(errno));

      if (parser->dflag) {
         pid_t parent = getppid();

         if (parent != 1) {
            if ((pid = fork ()) < 0) {
               ArgusLog (LOG_ERR, "Can't fork daemon %s", strerror(errno));
            } else {
               if (pid) {
                  struct timespec ts = {0, 500000000};
                  int status;

                  nanosleep(&ts, NULL);
                  waitpid(pid, &status, WNOHANG);
                  if (kill(pid, 0) < 0) {
                     exit (1);
                  } else
                     exit (0);

               } else {
                  if (chdir ("/") < 0)
                     ArgusLog (LOG_ERR, "Can't chdir to / %s", strerror(errno));

                  if ((parser->ArgusSessionId = setsid()) < 0)
                     ArgusLog (LOG_ERR, "setsid error %s", strerror(errno));

                  umask(0);
    
                  ArgusLog(LOG_WARNING, "started");

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

      if (parser->ArgusPortNum != 0) {
         if (ArgusEstablishListen (parser, parser->ArgusPortNum, parser->ArgusBindAddr) < 0)
            ArgusLog (LOG_ERR, "setArgusPortNum: ArgusEstablishListen returned %s", strerror(errno));
      }

      if (chroot_dir != NULL)
         ArgusSetChroot(chroot_dir);
 
      if (new_gid > 0) {
         if (setgid(new_gid) < 0)
            ArgusLog (LOG_ERR, "ArgusClientInit: setgid error %s", strerror(errno));
      }

      if (new_uid > 0) {
         if (setuid(new_uid) < 0)
            ArgusLog (LOG_ERR, "ArgusClientInit: setuid error %s", strerror(errno));
      }
/*
   This is the basic new argus() strategy for processing output
   records.  The thread will do two basic things: 
      1) it will grab stuff off the queue, and then do the basic
         processing that this radium will do, such as time
         adjustment, aggregation, correction, and anonymization, etc...

      2) it will manage the listen, to deal without remote client
         requests.  radium() can write its records to a file, and
         any number of remote clients, so ......

   The ArgusClientTimeout() routine will drive all the maintenance
   and so it should be run, probably 4x a second, just for good
   measure.
*/

      parser->ArgusReliableConnection++;
      parser->RaInitialized++;

      if ((parser->ArgusOutput = ArgusNewOutput (parser)) == NULL)
         ArgusLog (LOG_ERR, "could not generate output: %s.\n", strerror(errno));

      tvp = getArgusMarReportInterval(ArgusParser);
      if ((tvp->tv_sec == 0) && (tvp->tv_usec == 0)) {
         setArgusMarReportInterval (ArgusParser, "60s");
      }

#if defined(ARGUS_THREADS)
      sigemptyset(&blocked_signals);
      pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);
#endif

      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);
 
      (void) signal (SIGPIPE, SIG_IGN);
      (void) signal (SIGTSTP, SIG_IGN);
      (void) signal (SIGTTOU, SIG_IGN);
      (void) signal (SIGTTIN, SIG_IGN);
   }
}

void RaArgusInputComplete (struct ArgusInput *input) { return; };
int RaDeleteBinProcess(struct ArgusParserStruct *, struct RaBinProcessStruct *);


void
RaParseComplete (int sig)
{
   struct ArgusRecordStruct *rec = NULL;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaParseComplete(%d) Starting\n", sig);
#endif

   if (!ArgusParser->RaParseCompleting) {
      ArgusParser->RaParseCompleting++;
      ArgusParser->RaParseDone++;

      if (ArgusParser->ArgusActiveHosts != NULL) {
         struct ArgusQueueStruct *queue =  ArgusParser->ArgusActiveHosts;
         struct ArgusInput *input = NULL;

         while (queue->count > 0) {
            if ((input = (struct ArgusInput *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
               ArgusCloseInput(ArgusParser, input);
               if (input->hostname != NULL)
                  free (input->hostname);
               if (input->filename != NULL)
                  free (input->filename);
#if defined(HAVE_GETADDRINFO)
               if (input->host != NULL)
                  freeaddrinfo (input->host);
#endif
               ArgusFree(input);
            }
         }
         ArgusDeleteQueue(queue);
         ArgusParser->ArgusActiveHosts = NULL;
      }

      if (ArgusParser->RaCorrelate) {
         struct ArgusRecordStruct *argus = NULL;
         struct RaBinProcessStruct *rbps = ArgusParser->RaBinProcess;
         struct RaBinStruct *bin = NULL;
         int count, i;
#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(%d) processing RaBinProcess\n");
#endif

         if (rbps && (rbps->array != NULL)) {
            for (i = 0; i < rbps->arraylen; i++) {
               if ((bin = rbps->array[i]) != NULL) {
                  struct ArgusAggregatorStruct *agg = bin->agg;
                  while (agg) {
                     if (agg->queue && agg->queue->count) {
                        int x, cnt = 0;
                        ArgusSortQueue(ArgusSorter, agg->queue, ARGUS_LOCK);
                        argus = ArgusCopyRecordStruct((struct ArgusRecordStruct *) agg->queue->array[0]);

                        cnt = agg->queue->count;

                        for (x = 1; x < cnt; x++)
                           ArgusMergeRecords (agg, argus, (struct ArgusRecordStruct *)agg->queue->array[x]);

                        ArgusParser->ns = argus;

                        for (x = 0; x < cnt; x++)
                           RaProcessThisRecord (ArgusParser, (struct ArgusRecordStruct *) agg->queue->array[x]);

                        ArgusDeleteRecordStruct(ArgusParser, ArgusParser->ns);
                        ArgusParser->ns = NULL;
                     }

                     agg = agg->nxt;
                  }
                  RaDeleteBin(ArgusParser, bin);
                  rbps->array[i] = NULL;
               }
            }
         }

         if (rbps) {
            RaDeleteBinProcess(ArgusParser, rbps);
            ArgusParser->RaBinProcess = NULL;
         }

#ifdef ARGUSDEBUG
      ArgusDebug (2, "RaParseComplete(%d) Processing Probes\n");
#endif

         if ((count = ArgusProbeQueue->count) > 1) {
            struct ArgusProbeStruct *mpc;
    
            for (i = 0; i < count; i++) {
               if ((mpc = (void *) ArgusPopQueue(ArgusProbeQueue, ARGUS_LOCK)) != NULL) {
                  struct ArgusAggregatorStruct *agg = mpc->agg;
                  while (agg) {
                     if (agg->queue && agg->queue->count)
                        ArgusProcessQueue (agg->queue);
                     agg = agg->nxt;
                  }
                  ArgusAddToQueue (ArgusProbeQueue, &mpc->qhdr, ARGUS_LOCK);
               }
            }
         }
      }

      if (ArgusParser->ArgusOutput) {
         if ((rec = ArgusGenerateStatusMarRecord(ArgusParser->ArgusOutput, ARGUS_SHUTDOWN)) != NULL)
            ArgusPushBackList(ArgusParser->ArgusOutput->ArgusOutputList, (struct ArgusListRecord *)rec, ARGUS_LOCK);
      
         ArgusCloseOutput(ArgusParser->ArgusOutput);
         ArgusDeleteOutput(ArgusParser, ArgusParser->ArgusOutput);
         ArgusParser->ArgusOutput = NULL;
      }

      if (sig >= 0) {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(caught signal $d)\n", sig);
#endif

         switch (sig) {
            case SIGHUP:
            case SIGINT:
            case SIGTERM:
            case SIGQUIT: {
               struct ArgusWfileStruct *wfile = NULL;

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
                        }
                        lobj = lobj->nxt;
                     }
                  }
               }
#if defined(ARGUS_THREADS)
               pthread_exit(0);
#else
               exit(0);
#endif /* ARGUS_THREADS */
               break;
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaParseComplete(%d) returning\n", sig);
#endif
}


void
ArgusClientTimeout ()
{
   gettimeofday(&ArgusParser->ArgusRealTime, 0);

   if (RaRealTime) {  /* establish value for time comparison */
      if (ArgusLastTime.tv_sec != 0) {
         if (ArgusLastRealTime.tv_sec > 0) {
            RaDiffTime(&ArgusParser->ArgusRealTime, &ArgusLastRealTime, &dRealTime);
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

         ArgusLastRealTime = ArgusParser->ArgusRealTime;
      }
   }

   if (ArgusParser->RaCorrelate) {
      struct ArgusRecordStruct *ns = NULL, *argus = NULL;
      struct RaBinProcessStruct *rbps = ArgusParser->RaBinProcess;
      struct RaBinStruct *bin = NULL;
      int i = 0, count, size = (rbps->size / 1000000);

      if ((ArgusParser->Bflag > 0) && rbps->rtime.tv_sec) {
         struct timeval tvalbuf, *tval = &tvalbuf;

         RaDiffTime(&ArgusParser->ArgusRealTime, &rbps->rtime, tval);

#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusClientTimeout() RaBinProcess: Bflag %f rtime %d.%06d tval %d.%06d\n", ArgusParser->Bflag, 
                               rbps->rtime.tv_sec, rbps->rtime.tv_usec, tval->tv_sec,  tval->tv_usec);
#endif
         if (tval->tv_sec >= ArgusParser->Bflag) {

            count = (rbps->endpt.tv_sec - rbps->startpt.tv_sec)/size;

            if (rbps->array != NULL) {
               if ((bin = rbps->array[rbps->index]) != NULL) {
                  struct ArgusAggregatorStruct *agg = bin->agg;
                  while (agg) {
                     if (agg->queue->count) {
                        int cnt = 0;
                        ArgusSortQueue(ArgusSorter, agg->queue, ARGUS_LOCK);
                        argus = ArgusCopyRecordStruct((struct ArgusRecordStruct *) agg->queue->array[0]);

                        cnt = agg->queue->count;

                        for (i = 1; i < cnt; i++)
                           ArgusMergeRecords (agg, argus, (struct ArgusRecordStruct *)agg->queue->array[i]);

                        ArgusParser->ns = argus;

                        for (i = 0; i < cnt; i++)
                           RaProcessThisRecord (ArgusParser, (struct ArgusRecordStruct *) agg->queue->array[i]);

                        ArgusDeleteRecordStruct(ArgusParser, ArgusParser->ns);
                        ArgusParser->ns = NULL;
                     }

                     agg = agg->nxt;
                  }

                  rbps->array[rbps->index] = NULL;
                  RaDeleteBin(ArgusParser, bin);
#ifdef ARGUSDEBUG
                  ArgusDebug (2, "ArgusClientTimeout() RaBinProcess: process bin\n");
#endif

               } else {
                  if (rbps->nadp.zero && ((i >= rbps->index) && (((i - rbps->index) * rbps->size) < rbps->scalesecs))) {
                     ns = ArgusGenerateRecordStruct(NULL, NULL, NULL);
                     ((struct ArgusTimeStruct *)ns->dsrs[ARGUS_TIME_INDEX])->start.tv_sec  = rbps->start + (rbps->size * (i - rbps->index));
                     ((struct ArgusTimeStruct *)ns->dsrs[ARGUS_TIME_INDEX])->start.tv_usec = 0;
                     ((struct ArgusTimeStruct *)ns->dsrs[ARGUS_TIME_INDEX])->end.tv_sec    = rbps->start + (rbps->size * ((i + 1) - rbps->index));
                     ((struct ArgusTimeStruct *)ns->dsrs[ARGUS_TIME_INDEX])->end.tv_usec   = 0;
                     RaSendArgusRecord (ns);
                     ArgusDeleteRecordStruct(ArgusParser, ns);
#ifdef ARGUSDEBUG
                     ArgusDebug (2, "ArgusClientTimeout() RaBinProcess: creating zero record\n");
#endif
                  }
               }

               for (i = 0; i < rbps->arraylen; i++)
                  rbps->array[i] = rbps->array[(i + 1)];

               rbps->start += rbps->size;
               rbps->end   += rbps->size;
               rbps->startpt.tv_sec += size;
               rbps->endpt.tv_sec   += size;

               if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
                  struct ArgusWfileStruct *wfile = NULL;
                  struct ArgusListObjectStruct *lobj = NULL;
                  int i, cnt = ArgusParser->ArgusWfileList->count;

                  if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
                     for (i = 0; i < cnt; i++) {
                        if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                           if (wfile->fd != NULL)
                              fflush(wfile->fd);
                        }
                        lobj = lobj->nxt;
                     }
                  }
               }
            }

#ifdef ARGUSDEBUG
            ArgusDebug (6, "ArgusClientTimeout() RaBinProcess: Bflag %d rtime %d start %d end %d size %d arraylen %d count %d index %d\n",
               ArgusParser->Bflag, rbps->rtime.tv_sec, rbps->startpt.tv_sec, rbps->endpt.tv_sec,
               rbps->size, rbps->arraylen, rbps->count, rbps->index);
#endif
            rbps->rtime.tv_sec += size;
         }

      } else {
#ifdef ARGUSDEBUG
            ArgusDebug (2, "ArgusClientTimeout() RaBinProcess: Bflag %d rtime %d\n", ArgusParser->Bflag, rbps->rtime.tv_sec);
#endif
      }

      if (rbps->rtime.tv_sec == 0)
         rbps->rtime.tv_sec = ArgusParser->ArgusRealTime.tv_sec;

      if ((count = ArgusProbeQueue->count) > 1) {
         struct ArgusProbeStruct *mpc;
            
         for (i = 0; i < count; i++) {
            if ((mpc = (void *) ArgusPopQueue(ArgusProbeQueue, ARGUS_LOCK)) != NULL) {
               struct ArgusAggregatorStruct *agg = mpc->agg;
               while (agg) { 
                  if (agg->queue && agg->queue->count)
                     ArgusProcessQueue (agg->queue);
                  agg = agg->nxt;
               }
               ArgusAddToQueue (ArgusProbeQueue, &mpc->qhdr, ARGUS_LOCK);
            }
         }
      }
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

   fprintf (stdout, "Radium Version %s\n", version);
   fprintf (stdout, "usage: %s [radiumoptions] [raoptions]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -c <dir>       daemon chroot directory.\n");
   fprintf (stdout, "         -d             run as a daemon.\n");
   fprintf (stdout, "         -f conf.file   read %s configure file.\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "         -u <userid>    specify user id for daemon.\n");
   fprintf (stdout, "         -g <groupid>   specify group id for daemon.\n");
#if defined (ARGUSDEBUG)
   fprintf (stdout, "         -D <level>     specify debug level\n");
#endif
#ifdef ARGUS_SASL
   fprintf (stdout, "         -U <user/auth> specify <user/auth> authentication information.\n");
#endif
   fflush (stdout);
   exit(1);
}


void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusRecordStruct *ns = NULL;

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR: {
         struct ArgusRecord *rec = (struct ArgusRecord *)argus->dsrs[0];
         if (rec && parser->ArgusAdjustTime) {
            struct timeval drift;

            drift.tv_sec  = parser->ArgusRealTime.tv_sec  - ntohl(rec->argus_mar.now.tv_sec);
            drift.tv_usec = parser->ArgusRealTime.tv_usec - ntohl(rec->argus_mar.now.tv_usec);
            argus->input->ArgusTimeDrift  = drift.tv_sec * 1000000;
            argus->input->ArgusTimeDrift += drift.tv_usec;
            rec->argus_mar.drift = argus->input->ArgusTimeDrift;
#ifdef ARGUSDEBUG
#if defined(__APPLE_CC__) || defined(__APPLE__)
            ArgusDebug (3, "RaProcessRecord: ArgusInput 0x%x drift %lld\n", 
                             argus->input, argus->input->ArgusTimeDrift);
#else
            ArgusDebug (3, "RaProcessRecord: ArgusInput 0x%x drift %Ld\n",
                             argus->input, argus->input->ArgusTimeDrift);
#endif
#endif
         }
         break;
      }

      case ARGUS_EVENT:
         break;

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         struct ArgusTimeObject *time = (void *)argus->dsrs[ARGUS_TIME_INDEX];

         if (time != NULL) {
            if (parser->ArgusAdjustTime) {
               long long ArgusDriftLevel = parser->ArgusAdjustTime * 1000000;

               if (time && ((argus->input->ArgusTimeDrift >  ArgusDriftLevel) || 
                            (argus->input->ArgusTimeDrift < -ArgusDriftLevel))) {
                  int secs  = argus->input->ArgusTimeDrift / 1000000;
                  int usecs = argus->input->ArgusTimeDrift % 1000000;

                  struct timeval startbuf, *start = &startbuf;
                  struct timeval endbuf, *end = &endbuf;

                  start->tv_sec  = time->src.start.tv_sec;
                  start->tv_usec = time->src.start.tv_usec;

                  end->tv_sec    = time->src.end.tv_sec;
                  end->tv_usec   = time->src.end.tv_usec;

#ifdef ARGUSDEBUG
                  ArgusDebug (4, "RaProcessRecord() ArgusInput 0x%x adjusting timestamps by %d secs and %d usecs\n", argus->input, secs, usecs);
#endif
                  time->hdr.argus_dsrvl8.qual |= ARGUS_TIMEADJUST;
                  start->tv_sec  +=  secs;
                  start->tv_usec += usecs;
                  if (start->tv_usec < 0) {
                     start->tv_sec--; start->tv_usec += 1000000;
                  }
                  if (start->tv_usec > 1000000) {
                     start->tv_sec++; start->tv_usec -= 1000000;
                  }

                  end->tv_sec  +=  secs;
                  end->tv_usec += usecs;
                  if (end->tv_usec < 0) {
                     end->tv_sec--; end->tv_usec += 1000000;
                  }
                  if (end->tv_usec > 1000000) {
                     end->tv_sec++; end->tv_usec -= 1000000;
                  }
               }
            }
         }
         break;
      }
   }

   if ((ns = ArgusCopyRecordStruct(argus)) != NULL)
      if (parser->ArgusLabeler != NULL) 
         ArgusLabelRecord(parser, ns);

   if (!(parser->RaCorrelate)) {
      ArgusPushBackList(parser->ArgusOutput->ArgusOutputList, (struct ArgusListRecord *)ns, ARGUS_LOCK);

#if defined(ARGUS_THREADS)
      pthread_cond_signal(&parser->ArgusOutput->ArgusOutputList->cond); 

      if (parser->ArgusOutput->ArgusOutputList->count > 10000) {
         struct timespec tsbuf = {0, 10000000}, *ts = &tsbuf;
         nanosleep (ts, NULL);
      }

#else
      ArgusOutputProcess(parser->ArgusOutput);
#endif
   } else {
      struct RaBinProcessStruct *RaBinProcess = parser->RaBinProcess;
      struct ArgusRecordStruct *tns = NULL;
      int retn = 0, offset = 0;
 
      offset = (ArgusParser->Bflag + (RaBinProcess->nadp.size - 1))/RaBinProcess->nadp.size;
      RaBinProcess->nadp.stperiod = 0.0;
      RaBinProcess->nadp.dtperiod = 0.0;
  
      while ((tns = ArgusAlignRecord(parser, ns, &RaBinProcess->nadp)) != NULL) {
         if ((retn = ArgusCheckTime (parser, tns)) != 0) {
            struct ArgusMetricStruct *metric = (void *)tns->dsrs[ARGUS_METRIC_INDEX];
  
            if ((metric != NULL) && ((metric->src.pkts + metric->dst.pkts) > 0)) {
               if (!(ArgusInsertRecord(parser, RaBinProcess, tns, offset)))
                  ArgusDeleteRecordStruct(parser, tns);
            } else
               ArgusDeleteRecordStruct(parser, tns);
         } else
            ArgusDeleteRecordStruct(parser, tns);
      }
      ArgusDeleteRecordStruct(parser, ns);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "RaProcessRecord (0x%x, 0x%x) returning", parser, argus); 
#endif
}

int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{
   int retn = 0;

   if (ArgusParser->RaCorrelate) {
      if (argus->status & ARGUS_RECORD_WRITTEN)
         return (retn);

      if (!(retn = ArgusCheckTime (ArgusParser, argus)))
         return (retn);

      if (ArgusParser->RaBinProcess->nadp.hard) {
         struct ArgusTimeObject *time = (void *)argus->dsrs[ARGUS_TIME_INDEX];
         struct ArgusAdjustStruct *nadp = &ArgusParser->RaBinProcess->nadp;
         long long dsecs, stime = ArgusFetchStartuSecTime(argus);

         dsecs = ((stime - nadp->startuSecs) / nadp->size);
         dsecs *= nadp->size;
         dsecs += nadp->startuSecs;

         time->src.start.tv_sec  = dsecs / 1000000;
         time->src.start.tv_usec = dsecs % 1000000;

         dsecs += nadp->size;
         time->src.end.tv_sec   = dsecs / 1000000;
         time->src.end.tv_usec  = dsecs % 1000000;
      }

      ArgusPushBackList(ArgusParser->ArgusOutput->ArgusOutputList,
                 (struct ArgusListRecord *)ArgusCopyRecordStruct(argus), ARGUS_LOCK);

#if defined(ARGUS_THREADS)
      pthread_cond_signal(&ArgusParser->ArgusOutput->ArgusOutputList->cond);

      if (ArgusParser->ArgusOutput->ArgusOutputList->count > 10000) {
         struct timespec tsbuf = {0, 10000000}, *ts = &tsbuf;
         nanosleep (ts, NULL);
      }

#else
      ArgusOutputProcess(ArgusParser->ArgusOutput);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaSendArgusRecord(0x%x) retn 0x%x\n", argus, retn);
#endif

   return (retn);
}



void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusRecordStruct *rec = NULL, *trec;
   struct ArgusProbeStruct *probe, *mpc;
   int i, count, found = 0;

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_MAR:
         break;

      case ARGUS_EVENT:
      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if ((probe = ArgusProcessProbe (parser, ns)) != NULL) {
            if ((count = ArgusProbeQueue->count) > 1) {
               for (i = 0; (i < count) && !found; i++) {
                  if ((mpc = (void *) ArgusPopQueue(ArgusProbeQueue, ARGUS_LOCK)) != NULL) {
                     if (probe != mpc) {
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
                     }

                     ArgusAddToQueue (ArgusProbeQueue, &mpc->qhdr, ARGUS_LOCK);
                  }
               }
            }

            if (!found) {
               if ((rec = RaMpcEstablishMpcStream(probe, ns)) != NULL)
                  RaMpcAdvertiseHints(probe, rec);
            }
         }

         break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaProcessThisRecord (0x%x, 0x%x) returning\n", parser, ns);
#endif
}


void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
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


struct RaBinProcessStruct *
RaNewBinProcess (struct ArgusParserStruct *parser, int size)
{
   struct RaBinProcessStruct *retn = NULL;
   struct ArgusAdjustStruct *tnadp;

   if ((retn = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "RaNewBinProcess: ArgusCalloc error %s", strerror(errno));

   tnadp = &retn->nadp;
   bcopy((char *)&RaStreamDefaultNadp, (char *)tnadp, sizeof(*tnadp));

   tnadp->mode    = -1;
   tnadp->modify  =  1;
   tnadp->slen    =  2;
   tnadp->count   = 1;
   tnadp->value   = 1;

   return (retn);
}


struct ArgusRecordStruct *
RaMpcEstablishMpcStream(struct ArgusProbeStruct *mpc, struct ArgusRecordStruct *argus)
{
   struct ArgusRecordStruct *retn = NULL;
   struct ArgusAggregatorStruct *agg = mpc->agg;
   struct ArgusHashStruct *hstruct = NULL;
   int found = 0;

   while (agg && !found) {
      struct nff_insn *fcode = agg->filter.bf_insns;

      if (ArgusFilterRecord (fcode, argus)) {
         struct ArgusRecordStruct *ns = ArgusCopyRecordStruct(argus);
         struct ArgusRecordStruct *tns = NULL;

         if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
            agg->rap = agg->drap;

         ArgusGenerateNewFlow(agg, ns);
         agg->ArgusMaskDefs = NULL;

         if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
            ArgusLog (LOG_ERR, "RaMpcEstablishMpcStream: ArgusGenerateHashStruct error %s", strerror(errno));

         if ((retn = ArgusFindRecord(agg->htable, hstruct)) != NULL) {
            struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
            if (!ArgusParser->RaMonMode && ArgusParser->ArgusReverse) {
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
               } else
                  tryreverse = 0;

               if (tryreverse) {
                  if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                     ArgusLog (LOG_ERR, "RaMpcEstablishMpcStream: ArgusGenerateHashStruct error %s", strerror(errno));

                  if ((tns = ArgusFindRecord(agg->htable, hstruct)) == NULL) {
                     switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                        case ARGUS_TYPE_IPV4: {
                           switch (flow->ip_flow.ip_p) {
                              case IPPROTO_ICMP: {
                                 struct ArgusICMPFlow *icmpFlow = &flow->flow_un.icmp;

                                 if (ICMP_INFOTYPE(icmpFlow->type)) {
                                    switch (icmpFlow->type) {
                                       case ICMP_ECHO:
                                       case ICMP_ECHOREPLY:
                                          icmpFlow->type = (icmpFlow->type == ICMP_ECHO) ? ICMP_ECHOREPLY : ICMP_ECHO;
                                          if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                             tns = ArgusFindRecord(agg->htable, hstruct);
                                          icmpFlow->type = (icmpFlow->type == ICMP_ECHO) ? ICMP_ECHOREPLY : ICMP_ECHO;
                                          if (tns)
                                             ArgusReverseRecord (ns);
                                          break;

                                       case ICMP_ROUTERADVERT:
                                       case ICMP_ROUTERSOLICIT:
                                          icmpFlow->type = (icmpFlow->type == ICMP_ROUTERADVERT) ? ICMP_ROUTERSOLICIT : ICMP_ROUTERADVERT;
                                          if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                             tns = ArgusFindRecord(agg->htable, hstruct);
                                          icmpFlow->type = (icmpFlow->type == ICMP_ROUTERADVERT) ? ICMP_ROUTERSOLICIT : ICMP_ROUTERADVERT;
                                          if (tns)
                                             ArgusReverseRecord (ns);
                                          break;

                                       case ICMP_TSTAMP:
                                       case ICMP_TSTAMPREPLY:
                                          icmpFlow->type = (icmpFlow->type == ICMP_TSTAMP) ? ICMP_TSTAMPREPLY : ICMP_TSTAMP;
                                          if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                             tns = ArgusFindRecord(agg->htable, hstruct);
                                          icmpFlow->type = (icmpFlow->type == ICMP_TSTAMP) ? ICMP_TSTAMPREPLY : ICMP_TSTAMP;
                                          if (tns)
                                             ArgusReverseRecord (ns);
                                          break;

                                       case ICMP_IREQ:
                                       case ICMP_IREQREPLY:
                                          icmpFlow->type = (icmpFlow->type == ICMP_IREQ) ? ICMP_IREQREPLY : ICMP_IREQ;
                                          if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                             tns = ArgusFindRecord(agg->htable, hstruct);
                                          icmpFlow->type = (icmpFlow->type == ICMP_IREQ) ? ICMP_IREQREPLY : ICMP_IREQ;
                                          if (tns)
                                             ArgusReverseRecord (ns);
                                          break;

                                       case ICMP_MASKREQ:
                                       case ICMP_MASKREPLY:
                                          icmpFlow->type = (icmpFlow->type == ICMP_MASKREQ) ? ICMP_MASKREPLY : ICMP_MASKREQ;
                                          if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                             tns = ArgusFindRecord(agg->htable, hstruct);
                                          icmpFlow->type = (icmpFlow->type == ICMP_MASKREQ) ? ICMP_MASKREPLY : ICMP_MASKREQ;
                                          if (tns)
                                             ArgusReverseRecord (ns);
                                          break;
                                    }
                                 }
                                 break;
                              }
                           }
                        }
                     }

                     if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                        ArgusLog (LOG_ERR, "RaMpcEstablishMpcStream: ArgusGenerateHashStruct error %s", strerror(errno));

                  } else {
                     switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                        case ARGUS_TYPE_IPV4: {
                           switch (flow->ip_flow.ip_p) {
                              case IPPROTO_TCP: {
                                 struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)ns->dsrs[ARGUS_NETWORK_INDEX];
                                 if (tcp != NULL) {
                                    struct ArgusTCPObject *ttcp = (struct ArgusTCPObject *)tns->dsrs[ARGUS_NETWORK_INDEX];
                                    if (ttcp != NULL) {
                                       if ((tcp->status & ARGUS_SAW_SYN) && !(ttcp->status & ARGUS_SAW_SYN)) {
                                          ArgusReverseRecord (tns);
                                       } else
                                          ArgusReverseRecord (ns);
                                    } else
                                       ArgusReverseRecord (ns);
                                 } else
                                    ArgusReverseRecord (ns);
                                 break;
                              }

                              default:
                                 ArgusReverseRecord (ns);
                                 break;
                           }
                        }
                        break;

                        case ARGUS_TYPE_IPV6: {
                           switch (flow->ipv6_flow.ip_p) {
                              case IPPROTO_TCP: {
                                 struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)ns->dsrs[ARGUS_NETWORK_INDEX];
                                 if (tcp != NULL) {
                                    struct ArgusTCPObject *ttcp = (struct ArgusTCPObject *)tns->dsrs[ARGUS_NETWORK_INDEX];
                                    if (ttcp != NULL) {
                                       if ((tcp->status & ARGUS_SAW_SYN) && !(ttcp->status & ARGUS_SAW_SYN)) {
                                          ArgusReverseRecord (tns);
                                       } else
                                          ArgusReverseRecord (ns);
                                    } else
                                       ArgusReverseRecord (ns);
                                 } else
                                    ArgusReverseRecord (ns);
                                 break;
                              }

                              default:
                                 ArgusReverseRecord (ns);
                                 break;
                           }
                        }
                        break;

                        default:
                           ArgusReverseRecord (ns);
                     }
                  }
               }
            }

            if (tns != NULL)
               retn = tns;
         }

         if (retn != NULL) {
            RaSendArgusRecord (retn);
            ArgusDeleteRecordStruct(ArgusParser, retn);
         }

         retn = ns;
         ns->htblhdr = ArgusAddHashEntry (agg->htable, ns, hstruct);
         ArgusAddToQueue (agg->queue, &ns->qhdr, ARGUS_NOLOCK);

         if (agg->cont)
            agg = agg->nxt;
         else
            found++;
      } else
         agg = agg->nxt;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaMpcEstablishMpcStream(0x%x, 0x%x) returns 0x%x\n", mpc, argus, retn);
#endif
   return(retn);
}


int
RaMpcAdvertiseHints(struct ArgusProbeStruct *mpc, struct ArgusRecordStruct *argus)
{
   struct ArgusAggregatorStruct *agg = mpc->agg;
   struct ArgusRecordStruct *rec = NULL;
   struct ArgusHashStruct *hstruct = NULL;
   int retn = 0, found = 0;

   if (argus->hinthdr != NULL)
      ArgusRemoveHashEntry(&argus->hinthdr);

   while (agg && !found) {
      struct nff_insn *fcode = agg->filter.bf_insns;

      if (ArgusFilterRecord (fcode, argus)) {
         if ((hstruct = ArgusGenerateHintStruct(agg, argus)) != NULL) {
            if ((rec = ArgusFindRecord(agg->htable, hstruct)) == NULL) 
               argus->hinthdr = ArgusAddHashEntry (agg->htable, argus, hstruct);
            found++;
         }
      }

      agg = agg->nxt;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaMpcAdvertiseHints(0x%x, 0x%x) returns %d\n", mpc, argus, retn);
#endif
   return(retn);
}


void
RaFreeMpcStream(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   if (argus->hinthdr)
      ArgusRemoveHashEntry (&argus->hinthdr);

   if (argus->htblhdr)
      ArgusRemoveHashEntry (&argus->htblhdr);

   ArgusRemoveFromQueue (argus->qhdr.queue, &argus->qhdr, ARGUS_NOLOCK);
   ArgusDeleteRecordStruct(ArgusParser, argus);

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaFreeMpcStream(0x%x, 0x%x) done\n", parser, argus);
#endif
   return;
}


struct ArgusRecordStruct *
RaFindMpcStream(struct ArgusParserStruct *parser, struct ArgusProbeStruct *mpc, struct ArgusRecordStruct *argus)
{
   struct ArgusRecordStruct *retn = NULL;
   struct ArgusAggregatorStruct *agg = mpc->agg;
   struct ArgusHashStruct *hstruct = NULL;
   int found = 0;

   while (agg && !found) {
      int tretn = 0, fretn = -1, lretn = -1;
      if (agg->filterstr) {
         struct nff_insn *fcode = agg->filter.bf_insns;
         fretn = ArgusFilterRecord (fcode, argus);
      }

      if (agg->labelstr) {
         struct ArgusLabelStruct *label;
         if (((label = (void *)argus->dsrs[ARGUS_LABEL_INDEX]) != NULL)) {
            if (regexec(&agg->lpreg, label->l_un.label, 0, NULL, 0))
               lretn = 0;
            else
               lretn = 1;
         } else
            lretn = 0;
      }

      tretn = (lretn < 0) ? ((fretn < 0) ? 1 : fretn) : ((fretn < 0) ? lretn : (lretn && fretn));

      if (tretn != 0) {
         if ((agg->rap = RaFlowModelOverRides(agg, argus)) == NULL)
            agg->rap = agg->drap;

         ArgusGenerateNewFlow(agg, argus);
         agg->ArgusMaskDefs = NULL;

         if ((hstruct = ArgusGenerateHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) == NULL)
            ArgusLog (LOG_ERR, "RaFindMpcStream: ArgusGenerateHashStruct error %s", strerror(errno));

         if ((retn = ArgusFindRecord(agg->htable, hstruct)) == NULL) {
            struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
            if (!parser->RaMonMode && parser->ArgusReverse) {
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
               } else
                  tryreverse = 0;

               if (tryreverse) {
                  if ((hstruct = ArgusGenerateReverseHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                     ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                  if ((retn = ArgusFindRecord(agg->htable, hstruct)) == NULL) {
                     switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                        case ARGUS_TYPE_IPV4: {
                           switch (flow->ip_flow.ip_p) {
                              case IPPROTO_ICMP: {
                                 struct ArgusICMPFlow *icmpFlow = &flow->flow_un.icmp;

                                 if (ICMP_INFOTYPE(icmpFlow->type)) {
                                    switch (icmpFlow->type) {
                                       case ICMP_ECHO:
                                       case ICMP_ECHOREPLY:
                                          icmpFlow->type = (icmpFlow->type == ICMP_ECHO) ? ICMP_ECHOREPLY : ICMP_ECHO;
                                          if ((hstruct = ArgusGenerateReverseHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                             retn = ArgusFindRecord(agg->htable, hstruct);
                                          icmpFlow->type = (icmpFlow->type == ICMP_ECHO) ? ICMP_ECHOREPLY : ICMP_ECHO;
                                          if (retn)
                                             ArgusReverseRecord (argus);
                                          break;

                                       case ICMP_ROUTERADVERT:
                                       case ICMP_ROUTERSOLICIT:
                                          icmpFlow->type = (icmpFlow->type == ICMP_ROUTERADVERT) ? ICMP_ROUTERSOLICIT : ICMP_ROUTERADVERT;
                                          if ((hstruct = ArgusGenerateReverseHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                             retn = ArgusFindRecord(agg->htable, hstruct);
                                          icmpFlow->type = (icmpFlow->type == ICMP_ROUTERADVERT) ? ICMP_ROUTERSOLICIT : ICMP_ROUTERADVERT;
                                          if (retn)
                                             ArgusReverseRecord (argus);
                                          break;

                                       case ICMP_TSTAMP:
                                       case ICMP_TSTAMPREPLY:
                                          icmpFlow->type = (icmpFlow->type == ICMP_TSTAMP) ? ICMP_TSTAMPREPLY : ICMP_TSTAMP;
                                          if ((hstruct = ArgusGenerateReverseHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                             retn = ArgusFindRecord(agg->htable, hstruct);
                                          icmpFlow->type = (icmpFlow->type == ICMP_TSTAMP) ? ICMP_TSTAMPREPLY : ICMP_TSTAMP;
                                          if (retn)
                                             ArgusReverseRecord (argus);
                                          break;

                                       case ICMP_IREQ:
                                       case ICMP_IREQREPLY:
                                          icmpFlow->type = (icmpFlow->type == ICMP_IREQ) ? ICMP_IREQREPLY : ICMP_IREQ;
                                          if ((hstruct = ArgusGenerateReverseHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                             retn = ArgusFindRecord(agg->htable, hstruct);
                                          icmpFlow->type = (icmpFlow->type == ICMP_IREQ) ? ICMP_IREQREPLY : ICMP_IREQ;
                                          if (retn)
                                             ArgusReverseRecord (argus);
                                          break;

                                       case ICMP_MASKREQ:
                                       case ICMP_MASKREPLY:
                                          icmpFlow->type = (icmpFlow->type == ICMP_MASKREQ) ? ICMP_MASKREPLY : ICMP_MASKREQ;
                                          if ((hstruct = ArgusGenerateReverseHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                             retn = ArgusFindRecord(agg->htable, hstruct);
                                          icmpFlow->type = (icmpFlow->type == ICMP_MASKREQ) ? ICMP_MASKREPLY : ICMP_MASKREQ;
                                          if (retn)
                                             ArgusReverseRecord (argus);
                                          break;
                                    }
                                 }
                                 break;
                              }
                           }
                        }
                     }
                     if ((hstruct = ArgusGenerateHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                        ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                  } else {
                     found++;
                     switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                        case ARGUS_TYPE_IPV4: {
                           switch (flow->ip_flow.ip_p) {
                              case IPPROTO_TCP: {
                                 struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)argus->dsrs[ARGUS_NETWORK_INDEX];
                                 if (tcp != NULL) {
                                    struct ArgusTCPObject *ttcp = (struct ArgusTCPObject *)retn->dsrs[ARGUS_NETWORK_INDEX];
                                    if (ttcp != NULL) {
                                       if ((tcp->status & ARGUS_SAW_SYN) && !(ttcp->status & ARGUS_SAW_SYN)) {
                                          ArgusReverseRecord (retn);
                                       } else
                                          ArgusReverseRecord (argus);
                                    } else
                                       ArgusReverseRecord (argus);
                                 } else
                                    ArgusReverseRecord (argus);
                                 break;
                              }

                              default:
                                 ArgusReverseRecord (argus);
                                 break;
                           }
                        }
                        break;

                        case ARGUS_TYPE_IPV6: {
                           switch (flow->ipv6_flow.ip_p) {
                              case IPPROTO_TCP: {
                                 struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)argus->dsrs[ARGUS_NETWORK_INDEX];
                                 if (tcp != NULL) {
                                    struct ArgusTCPObject *ttcp = (struct ArgusTCPObject *)retn->dsrs[ARGUS_NETWORK_INDEX];
                                    if (ttcp != NULL) {
                                       if ((tcp->status & ARGUS_SAW_SYN) && !(ttcp->status & ARGUS_SAW_SYN)) {
                                          ArgusReverseRecord (retn);
                                       } else
                                          ArgusReverseRecord (argus);
                                    } else
                                       ArgusReverseRecord (argus);
                                 } else
                                    ArgusReverseRecord (argus);
                                 break;
                              }

                              default:
                                 ArgusReverseRecord (argus);
                                 break;
                           }
                        }
                        break;

                        default:
                           ArgusReverseRecord (argus);
                     }
                  }
               }

               if (!found && ((hstruct = ArgusGenerateHintStruct(agg, argus)) != NULL)) {
                  if ((retn = ArgusFindRecord(agg->htable, hstruct)) != NULL)
                  found++;
               }
            }

         } else 
            found++;
      }
      agg = agg->nxt;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaFindMpcStream(0x%x, 0x%x, 0x%x) returns 0x%x\n", parser, mpc, argus, retn);
#endif

   return (retn);
}


struct ArgusRecordStruct *
RaMpcCorrelate (struct ArgusProbeStruct *mpc, struct ArgusRecordStruct *ns, struct ArgusRecordStruct *rec)
{
   struct ArgusRecordStruct *retn = rec, *cs = NULL;
   struct ArgusAggregatorStruct *agg = mpc->agg;
   struct ArgusRecordStruct **pcor = NULL;
   struct ArgusRecordStruct *targus = NULL;;
   struct ArgusCorStruct *cor = NULL;
   int i;

   if ((cor = ns->correlates) != NULL) {
#ifdef ARGUSDEBUG
      ArgusDebug (2, "RaMpcCorrelate (0x%x, 0x%x) ns has correlates\n", rec, ns);
#endif
   }

   if ((cor = rec->correlates) != NULL) {
      for (i = 0; i < cor->count; i++) {
         struct ArgusTransportStruct *trans1 = NULL, *trans2 = NULL;
         trans1 = (void *)ns->dsrs[ARGUS_TRANSPORT_INDEX];
         trans2 = (void *)cor->array[i]->dsrs[ARGUS_TRANSPORT_INDEX];

         if (trans1->srcid.a_un.value == trans2->srcid.a_un.value) {
            cs = cor->array[i];
            break;
         }
      }

   } else {
      struct ArgusTimeObject *time = (void *)rec->dsrs[ARGUS_TIME_INDEX];
      if (time != NULL) {
         if ((time->src.start.tv_sec == 0) && (time->dst.start.tv_sec == 0))
            return (ns);
      }
   }

   if (cs != NULL) {
      ArgusMergeRecords(agg, cs, ns);
   } else {
      if ((targus = ArgusCopyRecordStruct(ns)) != NULL) {

         if (cor != NULL) {
            if (!(cor->size > cor->count)) {
               struct ArgusRecordStruct **array;
               if ((array = (void *) ArgusCalloc (cor->size + 5, sizeof(ns))) == NULL) 
                  ArgusLog (LOG_ERR, "RaMpcCorrelate: ArgusCalloc %s", strerror(errno));
               for (i = 0; i < cor->count; i++)
                  array[i] = cor->array[i];
               ArgusFree(cor->array);
               cor->array = array;
            }

            pcor = &cor->array[cor->count];
            cor->count++;
         } else {
            if ((rec->correlates = (void *) ArgusCalloc (1, sizeof(*ns->correlates))) == NULL)
               ArgusLog (LOG_ERR, "RaMpcCorrelate: ArgusCalloc %s", strerror(errno));

            if ((rec->correlates->array = (void *) ArgusCalloc (5, sizeof(ns))) == NULL)
               ArgusLog (LOG_ERR, "RaMpcCorrelate: ArgusCalloc %s", strerror(errno));

            cor = rec->correlates;
            cor->size = 5;
            pcor = &cor->array[cor->count];
            cor->count++;
         }

         *pcor = targus;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaMpcCorrelate (0x%x, 0x%x) returning 0x%x\n", rec, ns, retn);
#endif

   return (retn);
}



int
ArgusProcessQueue (struct ArgusQueueStruct *queue)
{
   struct timeval tbuf, *tvp = &tbuf;
   int retn = 0, x, z;

   if (ArgusParser->RaParseDone || ((ArgusParser->timeout.tv_sec > 0) || (ArgusParser->timeout.tv_usec > 0))) {
      struct ArgusRecordStruct *ns, *nxt = NULL;
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

            nxt = (struct ArgusRecordStruct *) ns->qhdr.nxt;

            if (ArgusParser->RaParseDone ||
               ((tvp->tv_sec  < ArgusParser->ArgusRealTime.tv_sec) ||
               ((tvp->tv_sec == ArgusParser->ArgusRealTime.tv_sec) &&
                (tvp->tv_usec < ArgusParser->ArgusRealTime.tv_usec)))) {

               RaSendArgusRecord (ns);

               if (!(ns->status & ARGUS_NSR_STICKY)) {
                  ArgusDeleteRecordStruct (ArgusParser, ns);
                  deleted++;
               } else 
                  ArgusAddToQueue (queue, &ns->qhdr, ARGUS_NOLOCK);

            } else {
               ArgusAddToQueue (queue, &ns->qhdr, ARGUS_NOLOCK);
               ns->qhdr.lasttime = lasttime;
            }
         }
      }

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
RaDeleteBinProcess(struct ArgusParserStruct *parser, struct RaBinProcessStruct *rbps)
{
   struct RaBinStruct *bin = NULL;
   struct ArgusRecordStruct *ns = NULL;
   int max = ((parser->tflag && parser->RaExplicitDate) ? rbps->nadp.count : rbps->max) + 1;
   int startsecs = 0, endsecs = 0, i;
   int retn = 0;

   char stimebuf[128], dtimebuf[128], etimebuf[128];
   int bins;

   if (rbps->array != NULL) {
      if (!(parser->tflag)) {
         for (i = 0; i < max; i++) {
            if ((bin = rbps->array[i]) != NULL) {
               if (startsecs == 0)
                  startsecs = bin->stime.tv_sec;
               endsecs = bin->etime.tv_sec;
            }
         }

         rbps->startpt.tv_sec = startsecs;
         rbps->scalesecs      = (endsecs - startsecs) + (rbps->size / 1000000);

         if ((parser->RaEndTime.tv_sec >  rbps->endpt.tv_sec) ||
                  ((parser->RaEndTime.tv_sec == rbps->endpt.tv_sec) &&
                   (parser->RaEndTime.tv_usec > rbps->endpt.tv_usec)))
            parser->RaEndTime = rbps->endpt;

      } else {
         rbps->startpt.tv_sec  = parser->startime_t.tv_sec;
         rbps->startpt.tv_usec = parser->startime_t.tv_usec;
         rbps->endpt.tv_sec    = parser->lasttime_t.tv_sec;
         rbps->endpt.tv_usec   = parser->lasttime_t.tv_usec;
         rbps->scalesecs       = parser->lasttime_t.tv_sec - parser->startime_t.tv_sec;
         rbps->start           = parser->startime_t.tv_sec * 1000000LL;
      }

      if ((parser->ArgusWfileList == NULL) && (parser->Gflag)) {
         if (parser->Hstr != NULL) {

         } else {

            ArgusPrintTime(parser, stimebuf, &rbps->startpt);
            ArgusPrintTime(parser, dtimebuf, &rbps->endpt);
            ArgusPrintTime(parser, etimebuf, &parser->RaEndTime);

            stimebuf[strlen(stimebuf) - 1] = '\0';
            dtimebuf[strlen(dtimebuf) - 1] = '\0';
            etimebuf[strlen(etimebuf) - 1] = '\0';

            printf ("StartTime=%s\n", stimebuf);
            printf ("StopTime=%s\n",  dtimebuf);
            printf ("LastTime=%s\n",  etimebuf);
            printf ("Seconds=%d\n", rbps->scalesecs);
            printf ("BinSize=%1.*f\n", parser->pflag, (rbps->size * 1.0)/1000000);
            bins = ((rbps->scalesecs + (rbps->size/1000000 - 1))/(rbps->size / 1000000));
            printf ("Bins=%d\n", bins);
         }
      }
   }

   for (i = rbps->index; i < max; i++) {
      if ((rbps->array != NULL) && ((bin = rbps->array[i]) != NULL)) {
         struct ArgusAggregatorStruct *agg = bin->agg;
         while (agg) {
            int rank = 1;
            ArgusSortQueue(ArgusSorter, agg->queue, ARGUS_LOCK);
            while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(agg->queue, ARGUS_NOLOCK)) != NULL) {
               ns->rank = rank++;
               if ((parser->eNoflag == 0 ) || ((parser->eNoflag >= ns->rank) && (parser->sNoflag <= ns->rank)))
                  RaSendArgusRecord (ns);
               ArgusDeleteRecordStruct(parser, ns);
            }
            agg = agg->nxt;
         }

      } else {
         if (rbps->nadp.zero && ((i >= rbps->index) && 
                 ((((i - rbps->index) * 1.0) * rbps->size) < (rbps->scalesecs * 1000000LL)))) {
            long long tval = rbps->start + (rbps->size * (i - rbps->index));

            ns = ArgusGenerateRecordStruct(NULL, NULL, NULL);

            ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.start.tv_sec  = tval / 1000000;
            ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.start.tv_usec = tval % 1000000;

            tval += rbps->size;
            ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.end.tv_sec    = tval / 1000000;;
            ((struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX])->src.end.tv_usec   = tval % 1000000;

            RaSendArgusRecord (ns);
         }
      }
   }

   for (i = rbps->index; i < max; i++) {
      if ((rbps->array != NULL) && ((bin = rbps->array[i]) != NULL)) {
         RaDeleteBin(parser, bin);
      }
   }

   if (rbps->array != NULL) ArgusFree(rbps->array);
   ArgusFree(rbps);
   return (retn);
}



#define RADIUM_RCITEMS                          22

#define RADIUM_DAEMON                           0
#define RADIUM_MONITOR_ID                       1
#define RADIUM_ARGUS_SERVER                     2
#define RADIUM_CISCONETFLOW_PORT                3
#define RADIUM_ACCESS_PORT                      4
#define RADIUM_INPUT_FILE                       5
#define RADIUM_USER_AUTH                        6
#define RADIUM_AUTH_PASS                        7
#define RADIUM_OUTPUT_FILE                      8
#define RADIUM_OUTPUT_STREAM                    9
#define RADIUM_MAR_STATUS_INTERVAL              10
#define RADIUM_DEBUG_LEVEL                      11
#define RADIUM_FILTER_OPTIMIZER                 12
#define RADIUM_FILTER_TAG                       13
#define RADIUM_BIND_IP                          14
#define RADIUM_MIN_SSF                          15
#define RADIUM_MAX_SSF                          16
#define RADIUM_ADJUST_TIME                      17
#define RADIUM_CHROOT_DIR                       18
#define RADIUM_SETUSER_ID                       19
#define RADIUM_SETGROUP_ID                      20
#define RADIUM_CLASSIFIER_FILE                  21

char *RadiumResourceFileStr [] = {
   "RADIUM_DAEMON=",
   "RADIUM_MONITOR_ID=",
   "RADIUM_ARGUS_SERVER=",
   "RADIUM_CISCONETFLOW_PORT=",
   "RADIUM_ACCESS_PORT=",
   "RADIUM_INPUT_FILE=",
   "RADIUM_USER_AUTH=",
   "RADIUM_AUTH_PASS=",
   "RADIUM_OUTPUT_FILE=",
   "RADIUM_OUTPUT_STREAM=",
   "RADIUM_MAR_STATUS_INTERVAL=",
   "RADIUM_DEBUG_LEVEL=",
   "RADIUM_FILTER_OPTIMIZER=",
   "RADIUM_FILTER=",
   "RADIUM_BIND_IP=",
   "RADIUM_MIN_SSF=",
   "RADIUM_MAX_SSF=",
   "RADIUM_ADJUST_TIME=",
   "RADIUM_CHROOT_DIR=",
   "RADIUM_SETUSER_ID=",
   "RADIUM_SETGROUP_ID=",
   "RADIUM_CLASSIFIER_FILE=",
};

int
RadiumParseResourceFile (struct ArgusParserStruct *parser, char *file)
{
   int retn = 0;
   int i, len, done = 0, linenum = 0, Soption = 0, roption = 0, quoted = 0;
   char strbuf[MAXSTRLEN], *str = strbuf, *optarg;
   char result[MAXSTRLEN], *ptr;
   FILE *fd;

   if (file) {
      if ((fd = fopen (file, "r")) != NULL) {
         while ((fgets(str, MAXSTRLEN, fd)) != NULL)  {
            done = 0; quoted = 0; linenum++;
            while (*str && isspace((int)*str))
                str++;

            if (*str && (*str != '#') && (*str != '\n') && (*str != '!')) {
               for (i = 0; i < RADIUM_RCITEMS && !done; i++) {
                  len = strlen(RadiumResourceFileStr[i]);
                  if (!(strncmp (str, RadiumResourceFileStr[i], len))) {
                     optarg = &str[len];
                     if (*optarg == '\"') { optarg++; quoted = 1; }
                     if (optarg[strlen(optarg) - 1] == '\n')
                        optarg[strlen(optarg) - 1] = '\0';
                     if (optarg[strlen(optarg) - 1] == '\"')
                        optarg[strlen(optarg) - 1] = '\0';

                     switch (i) {
                        case RADIUM_DAEMON: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              parser->dflag = 1;
                           else
                           if (!(strncasecmp(optarg, "no", 2)))
                              parser->dflag = 0;

                           break;
                        }

                        case RADIUM_MONITOR_ID: 
                           if (optarg && quoted) {   // Argus ID is a string.  Limit to date is 4 characters.
                              int slen = strlen(optarg);
                              if (slen > 4) optarg[4] = '\0';
                              setArgusID (parser, optarg, 4, ARGUS_IDIS_STRING);
 
                           } else {
                           if (optarg && (*optarg == '`')) {
                              if (optarg[strlen(optarg) - 1] == '`') {
                                 FILE *tfd;

                                 optarg++;
                                 optarg[strlen(optarg) - 1] = '\0';
                                 if (!(strcmp (optarg, "hostname"))) {
                                    if ((tfd = popen("hostname", "r")) != NULL) {
                                       if ((ptr = fgets(result, MAXSTRLEN, tfd)) != NULL) {
                                          optarg = ptr;
                                          optarg[strlen(optarg) - 1] = '\0';

                                          if ((ptr = strstr(optarg, ".local")) != NULL) {
                                             if (strlen(ptr) == strlen(".local"))
                                                *ptr = '\0';
                                          }

                                       } else
                                          ArgusLog (LOG_ERR, "RadiumParseResourceFile(%s) `hostname` failed %s.\n", file, strerror(errno));

                                       pclose(tfd);
                                    } else
                                       ArgusLog (LOG_ERR, "RadiumParseResourceFile(%s) System error: popen() %s\n", file, strerror(errno));
                                 } else
                                    ArgusLog (LOG_ERR, "RadiumParseResourceFile(%s) unsupported command `%s` at line %d.\n", file, optarg, linenum);
                              } else
                                 ArgusLog (LOG_ERR, "RadiumParseResourceFile(%s) syntax error line %d\n", file, linenum);
                           }
                           if (optarg && isalnum((int)*optarg)) {
#if defined(HAVE_GETADDRINFO)
                              struct addrinfo *host;
                              int retn;

                              if ((retn = getaddrinfo(optarg, NULL, NULL, &host)) == 0) {
                                 struct addrinfo *hptr = host;
                                 switch (host->ai_family) {
                                    case AF_INET:  {
                                       struct sockaddr_in *sa = (struct sockaddr_in *) host->ai_addr;
                                       unsigned int addr;
                                       bcopy ((char *)&sa->sin_addr, (char *)&addr, 4);
                                       setArgusID (ArgusParser, &addr, 4, ARGUS_IDIS_IPV4);
                                       break;
                                    }
                                    default:
                                       ArgusLog (LOG_ERR, "Probe ID %s not in address family\n", optarg);
                                       break;
                                 }
                                 freeaddrinfo(hptr);

                              } else {
                                 switch (retn) {
                                    case EAI_AGAIN:
                                       ArgusLog(LOG_ERR, "dns server not available");
                                       break;
                                    case EAI_NONAME:
                                       ArgusLog(LOG_ERR, "srcid %s unknown", optarg);
                                       break;
#if defined(EAI_ADDRFAMILY)
                                    case EAI_ADDRFAMILY:
                                       ArgusLog(LOG_ERR, "srcid %s has no IP address", optarg);
                                       break;
#endif
                                    case EAI_SYSTEM:
                                       ArgusLog(LOG_ERR, "srcid %s name server error %s", optarg, strerror(errno));
                                       break;
                                 }
                              }
#else
                              struct hostent *host;

                              if ((host = gethostbyname(optarg)) != NULL) {
                                 if ((host->h_addrtype == 2) && (host->h_length == 4)) {
                                    unsigned int addr;
                                    bcopy ((char *) *host->h_addr_list, (char *)&addr, host->h_length);
                                    setArgusID (parser, &addr, 4, ARGUS_IDIS_IPV4);
                                 } else
                                    ArgusLog (LOG_ERR, "RadiumParseResourceFile(%s) host '%s' error %s\n", file, optarg, strerror(errno));
                              } else
                                 if (optarg && isdigit((int)*optarg)) {
                                    setArgusID (parser, optarg, 4, ARGUS_IDIS_INT);
                                 } else
                                    ArgusLog (LOG_ERR, "RadiumParseResourceFile(%s) syntax error line %d\n", file, linenum);

#endif
                           } else
                              ArgusLog (LOG_ERR, "RadiumParseResourceFile(%s) syntax error line %d\n", file, linenum);
                           }

                           break;

                        case RADIUM_ARGUS_SERVER:
                           ++parser->Sflag;
                           if (!Soption++ && (parser->ArgusRemoteHostList != NULL))
                              ArgusDeleteHostList(parser);

                           if (!(ArgusAddHostList (parser, optarg, ARGUS_DATA_SOURCE, IPPROTO_TCP)))
                              ArgusLog (LOG_ERR, "%s: host %s unknown\n", optarg);
                           break;

                        case RADIUM_CISCONETFLOW_PORT: {
                           ++parser->Sflag; ++parser->Cflag;
                           if (!Soption++ && (parser->ArgusRemoteHostList != NULL))
                              ArgusDeleteHostList(parser);

                           if (!(ArgusAddHostList (parser, optarg, ARGUS_CISCO_DATA_SOURCE, IPPROTO_UDP)))
                              ArgusLog (LOG_ERR, "%s: host %s unknown\n", optarg);

                           break;
                        }

                        case RADIUM_INPUT_FILE:
                           if ((!roption++) && (parser->ArgusInputFileList != NULL))
                              ArgusDeleteFileList(parser);

                           if (!(ArgusAddFileList (parser, optarg, (parser->Cflag ? ARGUS_CISCO_DATA_SOURCE : ARGUS_DATA_SOURCE), -1, -1))) {
                              ArgusLog (LOG_ERR, "%s: error: file arg %s\n", optarg);
                           }
                           break;
                           
                        case RADIUM_ACCESS_PORT:
                           parser->ArgusPortNum = atoi(optarg);
                           break;
/*
                        case RADIUM_USER_AUTH:
                           ustr = strdup(optarg);
                           break;

                        case RADIUM_AUTH_PASS:
                           pstr = strdup(optarg);
                           break;
*/
                        case RADIUM_OUTPUT_FILE: 
                        case RADIUM_OUTPUT_STREAM: {
                           char *filter = NULL, *fptr;

                           if ((filter = strchr (optarg, ' ')) != NULL) {
                              *filter++ = '\0';

                              if ((fptr = strchr (filter, '"')) != NULL) {
                                 *fptr++ = '\0';
                                 filter = fptr;
                              }
                           }

                           setArgusWfile (parser, optarg, filter);
                           break;
                        }

                        case RADIUM_MAR_STATUS_INTERVAL:
                           setArgusMarReportInterval (parser, optarg);
                           break;

                        case RADIUM_DEBUG_LEVEL:
                           parser->debugflag = atoi(optarg);
                           break;
                        
                        case RADIUM_FILTER_OPTIMIZER:
                           if ((strncasecmp(optarg, "yes", 3)))
                              setArgusOflag  (parser, 1);
                           else
                              setArgusOflag  (parser, 0);
                           break;

                        case RADIUM_FILTER_TAG:
                           if ((parser->ArgusRemoteFilter = ArgusCalloc (1, MAXSTRLEN)) != NULL) {
                              ptr = parser->ArgusRemoteFilter;
                              str = optarg;
                              while (*str) {
                                 if ((*str == '\\') && (str[1] == '\n')) {
                                    if (fgets(str, MAXSTRLEN, fd) != NULL)
                                    while (*str && (isspace((int)*str) && (str[1] && isspace((int)str[1]))))
                                       str++;
                                 }
                                 
                                 if ((*str != '\n') && (*str != '"'))
                                    *ptr++ = *str++;
                                 else
                                    str++;
                              }
#ifdef ARGUSDEBUG
                              ArgusDebug (1, "RadiumParseResourceFile: ArgusFilter \"%s\" \n", parser->ArgusRemoteFilter);
#endif 
                           }
                           break;

                        case RADIUM_BIND_IP:
                           if (*optarg != '\0')
                              setArgusBindAddr (parser, optarg);
#ifdef ARGUSDEBUG
                           ArgusDebug (1, "RadiumParseResourceFile: ArgusBindAddr \"%s\" \n", parser->ArgusBindAddr);
#endif 
                           break;

                        case RADIUM_MIN_SSF:
                           if (*optarg != '\0') {
#ifdef ARGUS_SASL
                              ArgusMinSsf = atoi(optarg);
#ifdef ARGUSDEBUG
                           ArgusDebug (1, "RadiumParseResourceFile: ArgusMinSsf \"%s\" \n", ArgusMinSsf);
#endif
#endif
                           }
                           break;

                        case RADIUM_MAX_SSF:
                           if (*optarg != '\0') {
#ifdef ARGUS_SASL
                              ArgusMaxSsf = atoi(optarg);
#ifdef ARGUSDEBUG
                              ArgusDebug (1, "RadiumParseResourceFile: ArgusMaxSsf \"%s\" \n", ArgusMaxSsf);
#endif
#endif
                           }
                           break;

                        case RADIUM_ADJUST_TIME: {
                           char *ptr;
                           parser->ArgusAdjustTime = strtol(optarg, (char **)&ptr, 10);
                           if (ptr == optarg)
                              ArgusLog (LOG_ERR, "%s syntax error: line %d", file, linenum);
                           
                           if (isalpha((int) *ptr)) {
                              switch (*ptr) {
                                 case 's': break;
                                 case 'm': parser->ArgusAdjustTime *= 60; break;
                                 case 'h': parser->ArgusAdjustTime *= 3600; break;
                              }
                           }
#ifdef ARGUSDEBUG
                           ArgusDebug (1, "RadiumParseResourceFile: ArgusAdjustTime is %d secs\n", parser->ArgusAdjustTime);
#endif
                           break;
                        }

                        case RADIUM_CHROOT_DIR: {
                           if (chroot_dir != NULL)
                              free(chroot_dir);
                           chroot_dir = strdup(optarg);
                           break;
                        }
                        case RADIUM_SETUSER_ID: {
                           struct passwd *pw;
                           if ((pw = getpwnam(optarg)) == NULL)
                              ArgusLog (LOG_ERR, "unknown user \"%s\"\n", optarg);
                           new_uid = pw->pw_uid;
                           endpwent();
                           break;
                        }
                        case RADIUM_SETGROUP_ID: {
                           struct group *gr;
                           if ((gr = getgrnam(optarg)) == NULL)
                               ArgusLog (LOG_ERR, "unknown group \"%s\"\n", optarg);
                           new_gid = gr->gr_gid;
                           endgrent();
                           break;
                        }


                        case RADIUM_CLASSIFIER_FILE: {
                           if (parser->ArgusLabeler == NULL) {
                              if ((parser->ArgusLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
                                 ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");
                           }

                           if (RaLabelParseResourceFile (parser, parser->ArgusLabeler, optarg) != 0)
                              ArgusLog (LOG_ERR, "ArgusClientInit: label conf file error %s", strerror(errno));

                           break;
                        }
                     }

                     done = 1;
                     break;
                  }
               }
            }
         }

         fclose(fd);

      } else {
         retn++;
#ifdef ARGUSDEBUG
         ArgusDebug (1, "RadiumParseResourceFile: open %s %s\n", file, strerror(errno));
#endif 
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RadiumParseResourceFile (%s) returning %d\n", file, retn);
#endif 

   return (retn);
}

void
clearRadiumConfiguration (void)
{
   ArgusParser->dflag = 0;
   setArgusID (ArgusParser, 0, 0, 0);

   ArgusParser->ArgusPortNum = 0;

   clearArgusWfile (ArgusParser);
   setArgusBindAddr (ArgusParser, NULL);
   setArgusOflag (ArgusParser, 1);

   ArgusParser->dflag = 0;

   if (ArgusParser->ArgusRemoteHostList != NULL)
      ArgusDeleteHostList(ArgusParser);

   if (ArgusParser->ArgusInputFileList) {
      ArgusDeleteFileList(ArgusParser);
   }
 
   if (ArgusParser->ArgusRemoteFilter) {
      ArgusFree(ArgusParser->ArgusRemoteFilter);
      ArgusParser->ArgusRemoteFilter = NULL;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "clearRadiumConfiguration () returning\n");
#endif 
}