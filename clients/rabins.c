/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/*
 * rabins - time based bin processor. 
 *    this routine will take in an argus stream and align it to
 *    to a time array, and hold it for a hold period, and then
 *    output the bin countents as an argus stream.
 *
 *    this is the basis for all stream block processors.
 *    used by ragraph() to structure the data into graphing
 *    regions.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/clients/rabins.c#29 $
 * $DateTime: 2016/11/14 01:30:37 $
 * $Change: 3244 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>

#include <math.h>

#include <argus_compat.h>
#include <argus_threads.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <argus_output.h>

#include <rabins.h>
#include <rasplit.h>
#include <argus_sort.h>
#include <argus_cluster.h>

#include <signal.h>
#include <ctype.h>

extern int ArgusTimeRangeStrategy;

int RaPrintCounter = 0;
int RaRealTime = 0;
float RaUpdateRate = 1.0;

/* index into rbps->array of oldest location with data */
static int RabinsOldestIndex;

static struct timeval RabinsTimeoutB;	/* -B option as timeval */
static struct timeval RabinsTimeoutAbs;	/* time of next expiry */
struct timeval ArgusLastRealTime = {0, 0};
struct timeval ArgusLastTime     = {0, 0};
struct timeval ArgusThisTime     = {0, 0};


struct timeval dLastTime = {0, 0};
struct timeval dRealTime = {0, 0};
struct timeval dThisTime = {0, 0};
struct timeval dTime     = {0, 0};

long long thisUsec = 0;

struct RaBinProcessStruct *RaBinProcess = NULL;

#define ARGUS_JSON_OUTPUT		1

int RaOutputFormat = 0;
int ArgusRmonMode = 0;

int RaCloseBinProcess(struct ArgusParserStruct *, struct RaBinProcessStruct *);
int ArgusPrintFormat(struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int, int);

static int argus_version = ARGUS_VERSION;

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   time_t tsec = ArgusParser->ArgusRealTime.tv_sec;
   struct ArgusAdjustStruct *nadp;
   struct ArgusModeStruct *mode = NULL;
   int i = 0, ind = 0, size = 1;
   char outputfile[MAXSTRLEN];
   char *nocorrect = NULL;
   char *correct = NULL;

   parser->RaWriteOut = 0;
   *outputfile = '\0';

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      if ((RaBinProcess = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*RaBinProcess))) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

#if defined(ARGUS_THREADS)
      pthread_mutex_init(&RaBinProcess->lock, NULL);
#endif

      RaBinProcess->scalesecs = 0;

      nadp = &RaBinProcess->nadp;
      bzero((char *)nadp, sizeof(*nadp));

      nadp->mode      = -1;
      nadp->modify    =  1;
      nadp->slen      =  2;

      if (parser->aflag)
         nadp->slen = parser->aflag;

      if (parser->vflag)
         ArgusReverseSortDir++;

      parser->RaCumulativeMerge = 1;

      if ((ArgusSorter = ArgusNewSorter(parser)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewSorter error %s", strerror(errno));
 
      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (isdigit((int) *mode->mode)) {
               ind = 0;
            } else {
               if (!(strncasecmp (mode->mode, "nomerge", 4)))
                  parser->RaCumulativeMerge = 0;
               else
               if (!(strncasecmp (mode->mode, "rmon", 4)))
                  parser->RaMonMode++;
               else
               if (!(strncasecmp (mode->mode, "nocorrect", 5)))
                  nocorrect = strdup(mode->mode);
               else
               if (!(strncasecmp (mode->mode, "correct", 5)))
                  correct = strdup(mode->mode);
               else
               if (!(strncasecmp (mode->mode, "norep", 5)))
                  parser->RaAgMode++;
               else
               if (!(strncasecmp (mode->mode, "oui", 3)))
                  parser->ArgusPrintEthernetVendors++;
               else
               if (!(strncasecmp (mode->mode, "poll", 4)))
                  parser->RaPollMode++;
               else
               if (!(strncasecmp (mode->mode, "uni", 3)))
                  parser->RaUniMode++;
               else
               if (!(strncasecmp (mode->mode, "man", 3)))
                  parser->ArgusPrintMan = 1;
               else
               if (!(strncasecmp (mode->mode, "noman", 5)))
                  parser->ArgusPrintMan = 0;
               else
               if (!(strcmp (mode->mode, "lock")));
               else {
                  int done = 0;
                  for (i = 0, ind = -1; !(done) && (i < ARGUSSPLITMODENUM); i++) {
                     if (!(strncasecmp (mode->mode, RaSplitModes[i], 3))) {
                        ind = i;
                        switch (ind) {
                           case ARGUSSPLITTIME:
                           case ARGUSSPLITSIZE:
                           case ARGUSSPLITCOUNT: {
                              if ((mode = mode->nxt) == NULL)
                                 usage();
                              done++;
                           }
                        }
                     }
                  }
               }
            }

            if (ind < 0)
               usage();

            switch (ind) {
               case ARGUSSPLITTIME:
                  if (ArgusParser->tflag)
                     tsec = ArgusParser->startime_t.tv_sec;

                  nadp->mode = ind;
                  if (isdigit((int)*mode->mode)) {
                     char *ptr = NULL;
                     nadp->value = strtod(mode->mode, (char **)&ptr);
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
                              tsec= mktime(&nadp->RaStartTmStruct);
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
                              tsec = mktime(&nadp->RaStartTmStruct);
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
                              tsec = mktime(&nadp->RaStartTmStruct);
                              nadp->size = nadp->value*3600.0*24.0*7.0*1000000LL;
                              break;

                           case 'd':
                              nadp->qual = ARGUSSPLITDAY;   
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->RaStartTmStruct.tm_min = 0;
                              nadp->RaStartTmStruct.tm_hour = 0;
                              tsec = mktime(&nadp->RaStartTmStruct);
                              nadp->size = nadp->value*3600.0*24.0*1000000LL;
                              break;

                           case 'h':
                              nadp->qual = ARGUSSPLITHOUR;  
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->RaStartTmStruct.tm_min = 0;
                              tsec = mktime(&nadp->RaStartTmStruct);
                              nadp->size = nadp->value*3600.0*1000000LL;
                              break;

                           case 'm': {
                              nadp->qual = ARGUSSPLITMINUTE;
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              tsec = nadp->value*60.0*1000000LL;
                              nadp->size = tsec;
                              break;
                           }

                            default: 
                           case 's': {
                              long long val = tsec / nadp->value;
                              nadp->qual = ARGUSSPLITSECOND;
                              tsec = val * nadp->value;
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
//                            nadp->start.tv_sec = tsec;
                              nadp->size = nadp->value * 1000000LL;
                              break;
                           }
                        }
                     }
                  }

                  RaBinProcess->rtime.tv_sec = tsec;

                  if (RaRealTime) 
                     nadp->start.tv_sec = 0;

                  if (ArgusSorter->ArgusSortAlgorithms[0] == NULL)
                     ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;
                  break;

               case ARGUSSPLITSIZE:
               case ARGUSSPLITCOUNT:
                  nadp->mode = ind;
                  nadp->count = 1;

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
                  ArgusSorter->ArgusSortAlgorithms[0] = NULL;
                  break;

               case ARGUSSPLITNOMODIFY:
                  nadp->modify = 0;
                  break;

               case ARGUSSPLITSOFT:
               case ARGUSSPLITHARD:
                  nadp->hard++;
                  break;

               case ARGUSSPLITZERO:
                  nadp->zero++;
                  break;
            }

            mode = mode->nxt;
         }
      }

      if ((RaBinProcess->size  = nadp->size) == 0) {
//       ArgusLog (LOG_ERR, "ArgusClientInit: no bin size specified");
         nadp->value = 0xEFFFFFFF;
         nadp->size = nadp->value * 1000000LL;
         RaBinProcess->size  = nadp->size;
      }

      if (!(nadp->value))
         nadp->value = 1;

      if (nadp->mode < 0) {
         nadp->value = 1;
         nadp->count = 1;
      }

      /* if content substitution, either time or any field, is used,
         size and count modes will not work properly.  If using
         the default count, set the value so that we generate only
         one filename.

         if no substitution, then we need to add "aa" suffix to the
         output file for count and size modes.
      */

      if (parser->ArgusWfileList != NULL) {
         struct ArgusWfileStruct *wfile = NULL;

         if ((wfile = (struct ArgusWfileStruct *)ArgusPopFrontList(parser->ArgusWfileList, ARGUS_NOLOCK)) != NULL) {
            if (strcmp(wfile->filename, "-")) {
               strncpy (outputfile, wfile->filename, MAXSTRLEN);
               if ((strchr(outputfile, '%')) || (strchr(outputfile, '$'))) {
                  switch (nadp->mode) {
                     case ARGUSSPLITCOUNT:
                        nadp->count = -1;
                        break;

                     case ARGUSSPLITSIZE:
                        for (i = 0; i < nadp->slen; i++) {
#if defined(HAVE_STRLCAT)
                           strlcat(outputfile, "a", MAXSTRLEN - strlen(outputfile));
#else
                           strcat(outputfile, "a");
#endif
                        }
                        break;
                  }

               } else {
                  switch (nadp->mode) {
                     case ARGUSSPLITSIZE:
                     case ARGUSSPLITCOUNT:
                        for (i = 0; i < nadp->slen; i++) {
#if defined(HAVE_STRLCAT)
                           strlcat(outputfile, "a", MAXSTRLEN - strlen(outputfile));
#else
                           strcat(outputfile, "a");
#endif
                        }
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
               setArgusWfile (parser, outputfile, wfile->filterstr);
            } else
               setArgusWfile (parser, "-", NULL);
         }
      }

      parser->RaClientTimeout.tv_sec  = 0;
      parser->RaClientTimeout.tv_usec = 100000;
      parser->RaInitialized++;


      if (ArgusParser->startime_t.tv_sec && ArgusParser->lasttime_t.tv_sec) {
         nadp->count = (((ArgusParser->lasttime_t.tv_sec - ArgusParser->startime_t.tv_sec) * 1000000LL)/nadp->size);
      } else {
         int cnt = (parser->Bflag * 1000000) / nadp->size;
         nadp->count = ((size > cnt) ? size : cnt);
         if (parser->Bflag) {
            nadp->count += 2;
         } else {
            nadp->count += 10000;
         }
      }

      RabinsTimeoutB.tv_sec = parser->Bflag;

      if (parser->Gflag) {
         parser->uflag++;
         parser->RaFieldDelimiter = ',';
      }

      for (i = 0; parser->RaPrintAlgorithmList[i] != NULL; i++) {
         if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintProto) {
            parser->RaPrintMode |= RA_PRINTPROTO;
            break;
         }
         if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcPort) {
            break;
         }
         if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintDstPort) {
            break;
         }
         if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintSourceID) {
            parser->RaPrintMode |= RA_PRINTSRCID;
            break;
         }
      }

      if (parser->ArgusFlowModelFile) {
         if ((parser->ArgusAggregator = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseAggregator error");

         if (parser->ArgusAggregatorFile != NULL) 
            free(parser->ArgusAggregatorFile);

         parser->ArgusAggregatorFile = strdup(parser->ArgusFlowModelFile);

      } else
         if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if (RaBinProcess->size == 0)
         usage ();

      if (nocorrect != NULL) {
         if (parser->ArgusAggregator->correct != NULL) {
            free (parser->ArgusAggregator->correct);
            parser->ArgusAggregator->correct = NULL;
            free (nocorrect);
         }
      } else
      if (correct != NULL) {
         if (parser->ArgusAggregator->correct == NULL) {
            parser->ArgusAggregator->correct = correct;
         }
      }

      parser->ArgusReverse = 1;
      if (parser->ArgusAggregator->correct == NULL) 
            parser->ArgusReverse = 0;

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

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusClientInit()\n");
#endif
}


void RaArgusInputComplete (struct ArgusInput *input) { return; }
int RaDeleteBinProcess(struct ArgusParserStruct *, struct RaBinProcessStruct *);

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      switch (sig) {
         case SIGINT:
            exit(0);
            break;
      }
      if (!(ArgusParser->RaParseCompleting++)) {
         if (RaBinProcess != NULL) {
            RaCloseBinProcess(ArgusParser, RaBinProcess);
            RaDeleteBinProcess(ArgusParser, RaBinProcess);
            RaBinProcess = NULL;
         }

         if (ArgusSorter != NULL)
            ArgusDeleteSorter(ArgusSorter);

#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(caught signal %d)\n", sig);
#endif
         switch (sig) {
            case SIGHUP:
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

               exit(0);
               break;
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaParseComplete(%d)\n", sig);
#endif
}

/* timeout functions:
 *
 * If the source of argus data is a socket, then ArgusCurrentInput is
 * always non-null.  If it's a file, then ArgusCurrentInput _might_
 * be non-null; a compressed file causes the ArgusCurrentInput to be
 * cleared because the records come from a child process via popen().
 *
 * Try to take into account that we could read some files first and
 * then connect to a socket.
 */
static void
RabinsSetTimeout(struct RaBinProcessStruct *rbps, struct timeval *timer,
                 const struct timeval * const interval)
{
   int ind = RabinsOldestIndex ? RabinsOldestIndex : rbps->index;

   if (rbps->array && rbps->array[ind])
      timeradd(&rbps->array[ind]->etime, interval, timer);
   else {
      timer->tv_sec = 0;
      timer->tv_usec = 0;
   }
}

static int
RabinsCheckTimeout(const struct ArgusParserStruct * const parser,
                   const struct timeval * const timer)
{
   if (timer->tv_sec == 0)
      return 0;

   if (parser->Sflag && parser->ArgusCurrentInput)
      return !!timercmp(&parser->ArgusRealTime, timer, >);

   return !!timercmp(&parser->ArgusCurrentTime, timer, >);
}

/* return the next index into rbps->array that is non-null */
static int
RabinsAdvanceIndex(struct RaBinProcessStruct *rbps, int curindex)
{
   if (rbps->array[curindex] == NULL) {
      /* advance rbps->index to the next usable entry */
      if (rbps->count > 0) {
         int i = curindex+1;
         int found = 0;

         while (i != curindex && i < rbps->arraylen && !found) {
            if (rbps->array[i] != NULL)
               found = i;
            i++;
         }
         if (found)
            curindex = found;
      }
   }
   return curindex;
}

void
ArgusClientTimeout ()
{
   struct ArgusRecordStruct *ns = NULL, *argus = NULL;
   struct RaBinProcessStruct *rbps = RaBinProcess;
   struct RaBinStruct *bin = NULL;
   int i = 0, nflag = 0;

   if ((ArgusParser->Bflag > 0) && RabinsTimeoutAbs.tv_sec > 0) {
      int ind = RabinsOldestIndex ? RabinsOldestIndex : rbps->index;

     /* track the previous value of the array index.
      * The last call to RabinsAdvanceIndex will
      * (almost) always push the index past the range
      * of times we're ready to flush.
      */

      if (RabinsCheckTimeout(ArgusParser, &RabinsTimeoutAbs)) {
         RabinsSetTimeout(rbps, &RabinsTimeoutAbs, &RabinsTimeoutB);

         if (rbps->array != NULL) {

            ind = RabinsAdvanceIndex(rbps, ind);
            bin = rbps->array[ind];
            RabinsOldestIndex = ind;

            while (bin && timercmp(&bin->etime, &RabinsTimeoutAbs, <)) {
               struct ArgusAggregatorStruct *agg = bin->agg;
               int tcnt = 0;

               if (ArgusParser->ArgusGenerateManRecords) {
                  struct ArgusRecordStruct *man =
                     ArgusGenerateStatusMarRecord (NULL, ARGUS_START, argus_version);
                  struct ArgusRecord *rec = (struct ArgusRecord *)man->dsrs[0];
                  rec->argus_mar.startime.tv_sec  = bin->stime.tv_sec;
                  rec->argus_mar.startime.tv_usec = bin->stime.tv_usec;
                  rec->argus_mar.now.tv_sec       = bin->stime.tv_sec;
                  rec->argus_mar.now.tv_usec      = bin->stime.tv_usec;

                  RaSendArgusRecord (man);
                  ArgusDeleteRecordStruct(ArgusParser, man);
               }

               while (agg) {
                  int cnt = 0;
                  if ((cnt = agg->queue->count) > 0) {
                     ArgusSortQueue(ArgusSorter, agg->queue, ARGUS_LOCK);

                     for (i = 0; i < cnt; i++) {
                        if ((ns = (struct ArgusRecordStruct *)ArgusPopQueue(agg->queue, ARGUS_LOCK)) != NULL) {
                           if (i == 0) {
                              argus = ArgusCopyRecordStruct(ns);
			   } else {
                              ArgusMergeRecords (agg, argus, ns);
			   }
                           ArgusAddToQueue (agg->queue, &ns->qhdr, ARGUS_LOCK);
                        }
                     }

                     ArgusParser->ns = argus;

                     if (nflag != 0)
                        cnt = nflag > agg->queue->count ? agg->queue->count : nflag;

                     for (i = 0; i < cnt; i++) {
                        if ((ns = (struct ArgusRecordStruct *)ArgusPopQueue(agg->queue, ARGUS_LOCK)) != NULL) {
                           ns->rank = i;
                           RaSendArgusRecord ((struct ArgusRecordStruct *) ns);
                        }
                        ArgusDeleteRecordStruct(ArgusParser, ns);
                     }

                     ArgusDeleteRecordStruct(ArgusParser, ArgusParser->ns);
                     ArgusParser->ns = NULL;
                     tcnt += cnt;
                  }
                  agg = agg->nxt;
               }

               if (ArgusParser->ArgusGenerateManRecords) {
                  struct ArgusRecordStruct *man =
                     ArgusGenerateStatusMarRecord (NULL, ARGUS_STOP, argus_version);
                  struct ArgusRecord *rec = (struct ArgusRecord *)man->dsrs[0];
                  rec->argus_mar.startime.tv_sec  = bin->etime.tv_sec;
                  rec->argus_mar.startime.tv_usec = bin->etime.tv_usec;
                  rec->argus_mar.now.tv_sec       = bin->etime.tv_sec;
                  rec->argus_mar.now.tv_usec      = bin->etime.tv_usec;
                  RaSendArgusRecord (man);
                  ArgusDeleteRecordStruct(ArgusParser, man);
               }

#ifdef ARGUSDEBUG
               ArgusDebug (2, "ArgusClientTimeout() RaBinProcess: Bflag %f start %d.%06d size %.06f arraylen %d count %d index %d\n",
                  ArgusParser->Bflag, bin->stime.tv_sec, bin->stime.tv_usec, bin->size/1000000.0, rbps->arraylen, tcnt, rbps->index);
#endif
               RaDeleteBin(ArgusParser, rbps, ind);
               ind = RabinsAdvanceIndex(rbps, ind);
               bin = rbps->array[ind];
            }
            if (bin == NULL) {
               if (RaBinProcess->nadp.zero) {
                  long long tval = RaBinProcess->start + (RaBinProcess->size * RaBinProcess->index);
                  struct ArgusTimeObject *btime = NULL;

                  ns = ArgusGenerateRecordStruct(NULL, NULL, NULL);

                  btime = (struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX];
                  btime->src.start.tv_sec  = tval / 1000000;
                  btime->src.start.tv_usec = tval % 1000000;

                  tval += RaBinProcess->size;
                  btime->src.end.tv_sec    = tval / 1000000;;
                  btime->src.end.tv_usec   = tval % 1000000;

                  RaSendArgusRecord (ns);

#ifdef ARGUSDEBUG
               ArgusDebug (2, "ArgusClientTimeout() RaBinProcess: Bflag %f start %d.%06d size %.06f arraylen %d count %d index %d\n",
                  ArgusParser->Bflag, btime->src.start.tv_sec, btime->src.start.tv_usec, rbps->size/1000000.0, rbps->arraylen, 0, rbps->index);
#endif

/*
                  ArgusDeleteRecordStruct(ArgusParser, ns);
*/
#ifdef ARGUSDEBUG
                  ArgusDebug (2, "ArgusClientTimeout() RaBinProcess: creating zero record\n");
#endif
               }
            }
         }
      }

      /* shift the array to the left */
      if (RabinsOldestIndex > rbps->index) {
         ArgusShiftArray(ArgusParser, rbps, RabinsOldestIndex-rbps->index, 0);
         RabinsOldestIndex = rbps->index;
      }

   } else {
      RabinsSetTimeout(rbps, &RabinsTimeoutAbs, &RabinsTimeoutB);
   }

   if ((rbps->size > 0) && (rbps->rtime.tv_sec == 0)) {
      long long rtime = (ArgusParser->ArgusRealTime.tv_sec * 1000000LL) / rbps->size;
      rbps->rtime.tv_sec = (rtime + 1) * rbps->size;
   }
}

void parse_arg (int argc, char**argv) {}

void
usage ()
{
   extern char version[];

   fprintf (stdout, "Rabins Version %s\n", version);

   fprintf (stdout, "usage: %s -M splitmode [splitmode options] [raoptions]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -B <secs>            holding time period for processing input data\n");
#if defined (ARGUSDEBUG)
   fprintf (stdout, "         -D <level>           specify debug level\n");
#endif
   fprintf (stdout, "         -M <mode>            supported modes of operation:\n");
   fprintf (stdout, "             time N[smhdwmy]  split output into time series bins of N size\n");
   fprintf (stdout, "                              s[econds], m[inutes], h[ours], d[ays], w[eeks], m[onths], y[ears].\n");
   fprintf (stdout, "             nomodify         don't modify/split the input records when placing into bins\n");
   fprintf (stdout, "             hard             set start and ending timestamps to bin time boundary values\n");
   fprintf (stdout, "             zero             generate zero records when there are gaps in the series\n\n");

   fprintf (stdout, "         -m <mode>            supported aggregation objects:\n");
   fprintf (stdout, "             none             no flow key\n");
   fprintf (stdout, "             saddr            include the source address\n");
   fprintf (stdout, "             daddr            include the destination address\n");
   fprintf (stdout, "             proto            include the destination proto\n");
   fprintf (stdout, "             sport            include the source port\n");
   fprintf (stdout, "             dport            include the destination port\n");
   fprintf (stdout, "             srcid            include the source identifier\n");

   fprintf (stdout, "         -P <sortfield>       specify the fields to sort records on.\n\n");

   fflush (stdout);
   exit(1);
}

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   switch (ns->hdr.type & 0xF0) {
      case ARGUS_EVENT:
         RaProcessThisRecord(parser, ns);
         break;

      case ARGUS_MAR:
         if (parser->ArgusTotalRecords != 1)
            RaProcessThisRecord(parser, ns);
         break;

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {

         if (parser->Vflag || parser->Aflag) {
            ArgusProcessServiceAvailability(parser, ns);
            if (parser->xflag) {
               if ((parser->vflag && (ns->status & RA_SVCPASSED)) ||
                  (!parser->vflag && (ns->status & RA_SVCFAILED))) {
#ifdef ARGUSDEBUG
                  ArgusDebug (3, "RaProcessRecord (0x%x, 0x%x) service test failed", parser, ns);
#endif
                  return;
               }
            }
         }

         if (parser->RaMonMode) {
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(ns);
            struct ArgusFlow *flow;

            if ((flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, ns);

            ArgusReverseRecord(tns);

            if ((flow = (struct ArgusFlow *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }
    
            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);

         } else {
            struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;

            if (agg && agg->ArgusMatrixMode) {
               struct ArgusFlow *flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];

               if (flow != NULL) {
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
            }
            RaProcessThisRecord(parser, ns);
         }
      }
   }
}

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   extern struct RaBinProcessStruct *RaBinProcess;
   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
   int found = 0, offset, tstrat;

   tstrat = ArgusTimeRangeStrategy;
   while (agg && !found) {
      int tretn = -1, fretn = -1, lretn = -1;

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

         while (!(ns->status & ARGUS_RECORD_PROCESSED) && ((tns = ArgusAlignRecord(parser, ns, &RaBinProcess->nadp)) != NULL)) {
            if ((tretn = ArgusCheckTime (parser, tns, ArgusTimeRangeStrategy)) != 0) {
               struct ArgusRecordStruct *rec = NULL;

               switch (ns->hdr.type & 0xF0) {
                  case ARGUS_EVENT:
                  case ARGUS_MAR:
                     if (ArgusInsertRecord(parser, RaBinProcess, tns, offset, &rec) <= 0)
#ifdef ARGUSDEBUG
                        ArgusDebug(2, "%s: failed to insert EVENT or MAR\n")
#endif
                        ;
                     break;

                  case ARGUS_NETFLOW:
                  case ARGUS_AFLOW:
                  case ARGUS_FAR: {
                     struct ArgusMetricStruct *metric = (void *)tns->dsrs[ARGUS_METRIC_INDEX];

                     if ((metric != NULL) && ((metric->src.pkts + metric->dst.pkts) > 0)) {
                        if (ArgusInsertRecord(parser, RaBinProcess, tns, offset, &rec) <= 0)
#ifdef ARGUSDEBUG
                        ArgusDebug(2, "%s: failed to insert FAR\n")
#endif
                           ;
                     }
                     break;
                  }
               }

            }
            /* ArgusInsertRecord() makes a copy of the source record so we
             * should always free tns here.
             */
            ArgusDeleteRecordStruct(parser, tns);
         }

         ArgusDeleteRecordStruct(parser, ns);
         found++;
      }
      agg = agg->nxt;
   }

   if (ArgusParser->tflag)
      ArgusTimeRangeStrategy = tstrat;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessThisRecord (0x%x) done\n", argus); 
#endif
}


void ArgusPrintTCPSynAck (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];


int
ArgusPrintFormat(struct ArgusParserStruct *parser, char *buf, struct ArgusRecordStruct *argus, int format, int len)
{
   int retn = 0;

   if (argus != NULL) {
      switch (format) {
         case ARGUS_JSON_OUTPUT: {
            double stime = ArgusFetchStartuSecTime(argus)/1000;
            double ltime = ArgusFetchLastuSecTime(argus)/1000;
            long long sdate = stime, ldate = ltime;
            char *rank, *node, *proto, *saddr, *daddr, *dport, *synack;
            char buf[1024], str[256];

            ArgusPrintRank(parser, str, argus, 32);
            rank = strdup(ArgusTrimString(str));

            ArgusPrintProto(parser, str, argus, 256);
            proto = strdup(ArgusTrimString(str));

            ArgusPrintSrcAddr(parser, str, argus, 256);
            saddr = strdup(ArgusTrimString(str));

            ArgusPrintDstAddr(parser, str, argus, 256);
            daddr = strdup(ArgusTrimString(str));

            ArgusPrintDstPort(parser, str, argus, 256);
            dport = strdup(ArgusTrimString(str));

            ArgusPrintTCPSynAck(parser, str, argus, 256);
            synack = strdup(ArgusTrimString(str));

            ArgusPrintSourceID(parser, str, argus, 256);
            node = strdup(ArgusTrimString(str));

            sprintf(buf, "{\"rank\":\"%s\",\"node\":\"%s\",\"stime\":new Date(%lld),\"ltime\":new Date(%lld),\"proto\":\"%s\",\"saddr\":\"%s\",\"daddr\":\"%s\",\"dport\":\"%s\",\"synack\":\"%s\"},", rank, node, sdate, ldate, proto, saddr, daddr, dport, synack);
            fprintf(stdout, "%s", buf);
            fflush(stdout);
            break;

         default:
            break;
         }
      }
   }
#ifdef ARGUSDEBUG 
   ArgusDebug (6, "ArgusPrintFormat (%p, %p, %p, %d, %d) returning\n", parser, buf, argus, format, len);

#endif
   return (retn);
}


int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{
   int retn = 1;

   if (argus->status & ARGUS_RECORD_WRITTEN)
      return (retn);

   argus->rank = RaPrintCounter++;

   if (!(retn = ArgusCheckTime (ArgusParser, argus, ArgusTimeRangeStrategy)))
      return (retn);

   if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = ArgusParser->ArgusWfileList->count;

      if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               int retn = 1;
               if (wfile->filterstr) {
                  struct nff_insn *wfcode = wfile->filter.bf_insns;
                  retn = ArgusFilterRecord (wfcode, argus);
               }

               if (retn != 0) {
                  if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
                     struct ArgusRecord *argusrec = NULL;

                     if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
                        int rv;

#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        rv = ArgusWriteNewLogfile (ArgusParser, argus->input,
                                                   wfile, argusrec);
                        if (rv < 0)
                           ArgusLog(LOG_ERR, "%s unable to open file\n", __func__);
                     }
                  }
               }
            }
            lobj = lobj->nxt;
         }
      }

   } else {
      if (!ArgusParser->qflag) {
         switch (argus->hdr.type & 0xF0) {
            case ARGUS_MAR:
               if (!(ArgusParser->ArgusPrintMan))
                break;

            default: {
               char buf[MAXSTRLEN];
               if (!(ArgusParser->ArgusPrintJson) && (ArgusParser->Lflag)) {
                  int printReturn = 0;

                  if (ArgusParser->RaLabel == NULL)
                     ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, argus);

                  if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag)) {
                     if (ArgusParser->Gflag) {
                        printf ("Columns=%s\n", ArgusParser->RaLabel);
                     } else
                        printf ("%s", ArgusParser->RaLabel);
                     printReturn = 1;
                  }

                  if (ArgusParser->Lflag < 0)
                     ArgusParser->Lflag = 0;

                  if (ArgusParser->Gflag) {
                     switch (ArgusParser->RaPrintMode) {
                        case RA_PRINTSRCID:
                           printf ("Probes=\n");
                           break;

                        case RA_PRINTPROTO: {
                           printf ("Protos=\n");
                           break;
                        }

                        default: {
                           printf ("Objects=\n");
                           break;
                        }
                     }
                     printReturn = 1;
                  }

                  if (printReturn)
                     printf ("\n");
               }

               buf[0] = 0;

               ArgusPrintRecord(ArgusParser, buf, argus, MAXSTRLEN);

               if (fprintf (stdout, "%s\n", buf) < 0)
                  RaParseComplete (SIGQUIT);

               fflush(stdout);
               break;
            }
         }
      }
   }

   argus->status |= ARGUS_RECORD_WRITTEN;
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusSendArgusRecord (%p) returning\n", argus); 
#endif
   return (retn);
}


void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}


char *
RaSplitFilename (struct ArgusAdjustStruct *nadp)
{
   char *retn = NULL, tmpbuf[MAXSTRLEN];
   char *filename = nadp->filename;
   int len, i = 1, carry = 0;

   if (filename != NULL) {
      len = strlen(filename);

      for (i = 0; i < nadp->slen; i++)
         if (filename[len - (i + 1)] == 'z')
            carry++;

      if ((carry == (nadp->slen - 1)) && (filename[len - nadp->slen] == 'y')) {
         strncpy(tmpbuf, filename, MAXSTRLEN);
         tmpbuf[strlen(tmpbuf) - nadp->slen] = 'z';
         for (i = 0; i < nadp->slen; i++) {
#if defined(HAVE_STRLCAT)
            strlcat(tmpbuf, "a", MAXSTRLEN - strlen(tmpbuf));
#else
            strcat(tmpbuf, "a");
#endif
         }
         nadp->slen++;

      } else {
         for (i = 0, carry = 0; i < nadp->slen; i++) {
            if (filename[len - (i + 1)] == 'z') {
               filename[len - (i + 1)] = 'a';
            } else {
               filename[len - (i + 1)]++;
               break;
            }
         }
         strncpy (tmpbuf, filename, MAXSTRLEN);
      }

      if (nadp->filename)
         free(nadp->filename);

      nadp->filename = strdup(tmpbuf);
      retn = nadp->filename;
   }


#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaSplitFilename (0x%x) returning %s\n", nadp, retn); 
#endif

   return (retn);
}

int
RaProcessSplitOptions(struct ArgusParserStruct *parser, char *str, int len, struct ArgusRecordStruct *ns)
{
   char resultbuf[MAXSTRLEN], tmpbuf[MAXSTRLEN];
   char *ptr = NULL, *tptr = str;
   int retn = 0, i, x, slen = 0;

   bzero (resultbuf, len);

   while ((ptr = strchr (tptr, '$')) != NULL) {
      *ptr++ = '\0';
      slen = strlen(resultbuf);
      snprintf (&resultbuf[slen], MAXSTRLEN - slen, "%s", tptr);

      for (i = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (!strncmp (RaPrintAlgorithmTable[x].field, ptr, strlen(RaPrintAlgorithmTable[x].field))) {
            bzero (tmpbuf, MAXSTRLEN);
            RaPrintAlgorithmTable[x].print(parser, tmpbuf, ns, RaPrintAlgorithmTable[x].length);

            while (isspace((int)tmpbuf[strlen(tmpbuf) - 1]))
               tmpbuf[strlen(tmpbuf) - 1] = '\0';

            while (isspace((int)tmpbuf[i])) i++;
            slen = strlen(resultbuf);
            snprintf (&resultbuf[slen], MAXSTRLEN - slen, "%s", &tmpbuf[i]);

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


int
RaCloseBinProcess(struct ArgusParserStruct *parser, struct RaBinProcessStruct *rbps)
{
   int retn = 0;
   if (rbps != NULL) {
      struct RaBinStruct *bin = NULL;
      struct ArgusRecordStruct *ns = NULL;
      int max = 0, startsecs = 0, endsecs = 0, i;

      char stimebuf[128], dtimebuf[128], etimebuf[128];
      int bins;

      MUTEX_LOCK(&rbps->lock);

      max = ((parser->tflag && !parser->RaWildCardDate) ? rbps->nadp.count : rbps->max) + 1;

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
            if (parser->Hflag == 0) {
               int slen, dlen, elen;

               slen = ArgusPrintTime(parser, stimebuf, sizeof(stimebuf), &rbps->startpt);
               dlen = ArgusPrintTime(parser, dtimebuf, sizeof(dtimebuf), &rbps->endpt);
               elen = ArgusPrintTime(parser, etimebuf, sizeof(etimebuf), &parser->RaEndTime);

               stimebuf[slen - 1] = '\0';
               dtimebuf[dlen - 1] = '\0';
               etimebuf[elen - 1] = '\0';

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

            if (ArgusParser->ArgusGenerateManRecords) {
               struct ArgusRecordStruct *man =
                  ArgusGenerateStatusMarRecord (NULL, ARGUS_START, argus_version);
               struct ArgusRecord *rec = (struct ArgusRecord *)man->dsrs[0];
               rec->argus_mar.startime.tv_sec  = bin->stime.tv_sec;
               rec->argus_mar.startime.tv_usec = bin->stime.tv_usec;
               rec->argus_mar.now.tv_sec       = bin->stime.tv_sec;
               rec->argus_mar.now.tv_usec      = bin->stime.tv_usec;

               RaSendArgusRecord (man);
               ArgusDeleteRecordStruct(ArgusParser, man);
            }

            while (agg) {
               int rank = 0;
               ArgusSortQueue(ArgusSorter, agg->queue, ARGUS_LOCK);
               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(agg->queue, ARGUS_NOLOCK)) != NULL) {
                  ns->rank = rank++;
                  if ((parser->eNoflag == 0 ) || ((parser->eNoflag >= (ns->rank + 1)) && (parser->sNoflag <= (ns->rank + 1))))
                     RaSendArgusRecord (ns);
                  ArgusDeleteRecordStruct(parser, ns);
               }
               agg = agg->nxt;
            }

            if (ArgusParser->ArgusGenerateManRecords) {
               struct ArgusRecordStruct *man =
                  ArgusGenerateStatusMarRecord (NULL, ARGUS_STOP, argus_version);
               struct ArgusRecord *rec = (struct ArgusRecord *)man->dsrs[0];
               rec->argus_mar.startime.tv_sec  = bin->etime.tv_sec;
               rec->argus_mar.startime.tv_usec = bin->etime.tv_usec;
               rec->argus_mar.now.tv_sec       = bin->etime.tv_sec;
               rec->argus_mar.now.tv_usec      = bin->etime.tv_usec;

               RaSendArgusRecord (man);
               ArgusDeleteRecordStruct(ArgusParser, man);
            }

            RaDeleteBin(parser, rbps, i);

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
      MUTEX_UNLOCK(&rbps->lock);
   }

   return (retn);
}
