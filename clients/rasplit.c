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
 * 
 * $Id: //depot/argus/clients/clients/rasplit.c#70 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(CYGWIN)
#define USE_IPV6
#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <argus_compat.h>
#include <sys/wait.h>

#include <rabins.h>
#include <rasplit.h>
#include <math.h>


struct ArgusObjectStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusHashTableHdr *htblhdr;
   unsigned int status;

   time_t ArgusFileStartSecs;
   time_t ArgusFileEndSecs;

   struct timeval lasttime;
   struct ArgusWfileStruct wfile;
};


struct ArgusHashTable ArgusProbeTable;
struct ArgusQueueStruct *ArgusProbeQueue = NULL;
struct ArgusProbeStruct *ArgusThisProbe = NULL;

struct ArgusAdjustStruct adata, *ArgusNadp = &adata;
int RaProcessSplitOptionSrcId = 0;


int ArgusInitNewFilename(struct ArgusParserStruct *, struct ArgusWfileStruct *, char *);
struct ArgusObjectStruct *ArgusFindObject (struct ArgusHashTable *, struct ArgusHashStruct *);

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


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusWfileStruct *wfile = NULL;
   struct ArgusModeStruct *mode = NULL;
   char outputfile[MAXSTRLEN];
   int i = 0, ind = 0, count = 0;

   parser->RaWriteOut = 0;
   bzero(outputfile, sizeof(outputfile));

   if (!(parser->RaInitialized)) {
      char *ptr = NULL;

      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      if (parser->dflag) {
         int pid;

         if (parser->Sflag)
            parser->ArgusReliableConnection++;

         ArgusLog(LOG_WARNING, "started");
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

      bzero((char *)ArgusNadp, sizeof(*ArgusNadp));

      ArgusNadp->mode      = -1;
      ArgusNadp->modify    =  1;
      ArgusNadp->slen =  2;

      if (parser->aflag)
         ArgusNadp->slen = parser->aflag;

      if (ArgusParser->ArgusWfileList && (ArgusParser->ArgusWfileList->start != NULL)) {
         count = ArgusParser->ArgusWfileList->count;
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) ArgusPopFrontList(parser->ArgusWfileList, ARGUS_LOCK)) != NULL) {
               if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
                  strncpy (outputfile, wfile->filename, MAXSTRLEN);
                  count++;
                  break;
               } else
                  ArgusPushBackList(ArgusParser->ArgusWfileList, (struct ArgusListRecord *) wfile, ARGUS_LOCK);
            }
         }
      } else {
         bzero (outputfile, MAXSTRLEN);
         *outputfile = 'x';
      }

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "rtime", 5)) ||
               (!(strncasecmp (mode->mode, "realtime", 8)))) {
               char *ptr = NULL;
               RaRealTime++;
               if ((ptr = strchr(mode->mode, ':')) != NULL) {
                  double value = 0.0;
                  char *endptr = NULL;
                  ptr++;
                  value = strtod(ptr, &endptr);
                  if (ptr != endptr) {
                     RaUpdateRate = value;
                  }
               }
            } else
            if (!(strncasecmp (mode->mode, "poll", 4)))
               parser->RaPollMode++;
            else
            if (!(strncasecmp (mode->mode, "rmon", 4)))
               parser->RaMonMode++;
            else
            if (!(strncasecmp (mode->mode, "uni", 3)))
               parser->RaUniMode++;
            else
            if (!(strncasecmp (mode->mode, "oui", 3)))
               parser->ArgusPrintEthernetVendors++;
            else
            if (!(strncasecmp (mode->mode, "man", 3)))
               parser->ArgusPrintMan = 1;
            else
            if (!(strncasecmp (mode->mode, "noman", 5)))
               parser->ArgusPrintMan = 0;
            else
            if (isdigit((int) *mode->mode)) {
               ind = 0;
            } else {
                  int done = 0;
                  for (i = 0, ind = -1; (i < ARGUSSPLITMODENUM) && !done; i++) {
                     if (!(strncasecmp (mode->mode, RaSplitModes[i], 3))) {
                        ind = i;
                        switch (ind) {
                           case ARGUSSPLITTIME:
                           case ARGUSSPLITSIZE:
                           case ARGUSSPLITCOUNT:
                              if ((mode = mode->nxt) == NULL)
                                 usage();
                              done = 1;
                              break;
                        }
                     }
                  }
            }

            if (ind < 0)
               usage();

            switch (ind) {
               case ARGUSSPLITTIME:
                  ArgusNadp->mode = ind;
                  if (isdigit((int)*mode->mode)) {
                     ptr = NULL;
                     ArgusNadp->value = strtod(mode->mode, (char **)&ptr);
                     if (ptr == mode->mode)
                        usage();
                     else {
                        time_t tsec = ArgusParser->ArgusRealTime.tv_sec;

                        switch (*ptr) {
                           case 'y':
                              ArgusNadp->qual = ARGUSSPLITYEAR;  
                              localtime_r(&tsec, &ArgusNadp->RaStartTmStruct);
                              ArgusNadp->RaStartTmStruct.tm_sec = 0;
                              ArgusNadp->RaStartTmStruct.tm_min = 0;
                              ArgusNadp->RaStartTmStruct.tm_hour = 0;
                              ArgusNadp->RaStartTmStruct.tm_mday = 1;
                              ArgusNadp->RaStartTmStruct.tm_mon = 0;
                              ArgusNadp->start.tv_sec = mktime(&ArgusNadp->RaStartTmStruct);
                              ArgusNadp->size = ArgusNadp->value*31556926*1000000LL;
                              break;

                           case 'M':
                              ArgusNadp->qual = ARGUSSPLITMONTH; 
                              localtime_r(&tsec, &ArgusNadp->RaStartTmStruct);
                              ArgusNadp->RaStartTmStruct.tm_sec = 0;
                              ArgusNadp->RaStartTmStruct.tm_min = 0;
                              ArgusNadp->RaStartTmStruct.tm_hour = 0;
                              ArgusNadp->RaStartTmStruct.tm_mday = 1;
                              ArgusNadp->RaStartTmStruct.tm_mon = 0;
                              ArgusNadp->start.tv_sec = mktime(&ArgusNadp->RaStartTmStruct);

                              ArgusNadp->size = ArgusNadp->value*3600.0*24.0*7.0*4.0*1000000LL;
                              break;

                           case 'w':
                              ArgusNadp->qual = ARGUSSPLITWEEK;  
                              localtime_r(&tsec, &ArgusNadp->RaStartTmStruct);
                              ArgusNadp->RaStartTmStruct.tm_sec = 0;
                              ArgusNadp->RaStartTmStruct.tm_min = 0;
                              ArgusNadp->RaStartTmStruct.tm_hour = 0;
                              ArgusNadp->RaStartTmStruct.tm_mday = 1;
                              ArgusNadp->RaStartTmStruct.tm_mon = 0;
                              ArgusNadp->start.tv_sec = mktime(&ArgusNadp->RaStartTmStruct);

                              ArgusNadp->size = ArgusNadp->value*3600.0*24.0*7.0*1000000LL;
                              break;

                           case 'd':
                              ArgusNadp->qual = ARGUSSPLITDAY;   
                              localtime_r(&tsec, &ArgusNadp->RaStartTmStruct);
                              ArgusNadp->RaStartTmStruct.tm_sec = 0;
                              ArgusNadp->RaStartTmStruct.tm_min = 0;
                              ArgusNadp->RaStartTmStruct.tm_hour = 0;
                              ArgusNadp->start.tv_sec = mktime(&ArgusNadp->RaStartTmStruct);

                              ArgusNadp->size = ArgusNadp->value*3600.0*24.0*1000000LL;
                              break;

                           case 'h':
                              ArgusNadp->qual = ARGUSSPLITHOUR;  
                              localtime_r(&tsec, &ArgusNadp->RaStartTmStruct);
                              ArgusNadp->RaStartTmStruct.tm_sec = 0;
                              ArgusNadp->RaStartTmStruct.tm_min = 0;
                              ArgusNadp->start.tv_sec = mktime(&ArgusNadp->RaStartTmStruct);
                              ArgusNadp->size = ArgusNadp->value*3600.0*1000000LL;
                              break;

                           case 'm': {
                              ArgusNadp->qual = ARGUSSPLITMINUTE;
                              localtime_r(&tsec, &ArgusNadp->RaStartTmStruct);
                              ArgusNadp->RaStartTmStruct.tm_sec = 0;
                              ArgusNadp->start.tv_sec = mktime(&ArgusNadp->RaStartTmStruct);
                              ArgusNadp->size = ArgusNadp->value*60.0*1000000LL;
                              break;
                           }

                            default: 
                           case 's': {
                              long long val = tsec / ArgusNadp->value;
                              ArgusNadp->qual = ARGUSSPLITSECOND;
                              tsec = val * ArgusNadp->value;

                              localtime_r(&tsec, &ArgusNadp->RaStartTmStruct);
                              ArgusNadp->start.tv_sec = tsec;
                              ArgusNadp->size = ArgusNadp->value * 1000000LL;

                              if (ArgusNadp->size < 1000000LL)
                                 usage();
                              break;
                           }
                        }
                     }
                  }
                  break;

               case ARGUSSPLITSIZE:
               case ARGUSSPLITCOUNT:
                  ArgusNadp->mode = ind;
                  ArgusNadp->count = 1;

                  if (mode != NULL) {
                     if (isdigit((int)*mode->mode)) {
                        ptr = NULL;
                        ArgusNadp->value = strtol(mode->mode, (char **)&ptr, 10);
                        if (ptr == mode->mode)
                           usage();
                        else {
                           switch (*ptr) {
                              case 'B':   
                              case 'b':  ArgusNadp->value *= 1000000000; break;
                               
                              case 'M':   
                              case 'm':  ArgusNadp->value *= 1000000; break;
                               
                              case 'K':   
                              case 'k':  ArgusNadp->value *= 1000; break;
                           }
                        }
                     }
                  }
                  break;

               case ARGUSSPLITFLOW: {
                  ArgusNadp->mode = ind;
                  if ((mode = mode->nxt) != NULL) {
                     ArgusNadp->filterstr = strdup(mode->mode);

                     if (ArgusFilterCompile (&ArgusNadp->filter, ArgusNadp->filterstr, ArgusParser->Oflag) < 0)
                        ArgusLog (LOG_ERR, "flow filter parse error");

                     if (ArgusParser->bflag) {
                        nff_dump(&ArgusNadp->filter, ArgusParser->bflag);
                        exit (0);
                     }
                  }
                  break;
               }

               case ARGUSSPLITPATTERN:
                  break;

               case ARGUSSPLITNOMODIFY:
                  ArgusNadp->modify = 0;
            }

            mode = mode->nxt;
         }
      }

      if (ArgusNadp->mode < 0) {
         ArgusNadp->mode = ARGUSSPLITCOUNT;
         ArgusNadp->value = 10000;
         ArgusNadp->count = 1;
      }

      /* if content substitution, either time or any field, is used,
         size and count modes will not work properly.  If using
         the default count, set the value so that we generate only
         one filename.

         if no substitution, then we need to add "aa" suffix to the
         output file for count and size modes.
      */
 
      if ((strchr(outputfile, '%')) || (strchr(outputfile, '$'))) {
         switch (ArgusNadp->mode) {
            case ARGUSSPLITCOUNT:
               ArgusNadp->count = -1;
               break;

            case ARGUSSPLITSIZE:
            case ARGUSSPLITFLOW:
               for (i = 0; i < ArgusNadp->slen; i++) 
#if defined(HAVE_STRLCAT)
                  strlcat(outputfile, "a", MAXSTRLEN - strlen(outputfile));
#else
                  strcat(outputfile, "a");
#endif
               break;
         }

      } else {
         switch (ArgusNadp->mode) {
            case ARGUSSPLITSIZE:
            case ARGUSSPLITCOUNT:
            case ARGUSSPLITFLOW:
               for (i = 0; i < ArgusNadp->slen; i++) 
#if defined(HAVE_STRLCAT)
                  strlcat(outputfile, "a", MAXSTRLEN - strlen(outputfile));
#else
                  strcat(outputfile, "a");
#endif
               break;
         }
      }

      if (!(strchr(outputfile, '%'))) {
         switch (ArgusNadp->mode) {
            case ARGUSSPLITTIME:
            /* if strftime() labels are not in use, need to add suffix */
              if (outputfile[strlen(outputfile) - 1] != '.')
#if defined(HAVE_STRLCAT)
                  strlcat(outputfile, ".", MAXSTRLEN - strlen(outputfile));
#else
                  strcat(outputfile, ".");
#endif

#if defined(HAVE_STRLCAT)
              strlcat(outputfile, "%Y.%m.%d.%H.%M.%S", MAXSTRLEN - strlen(outputfile));
#else
              strcat(outputfile, "%Y.%m.%d.%H.%M.%S");
#endif
              break;
         }
      }

#define ARGUS_MAX_MASK		32

      if ((ptr = strchr(outputfile, '$')) != NULL) {
         char **ap, *mask[ARGUS_MAX_MASK];
         char *file = strdup(ptr);
         char *sptr = file;

         bzero (mask, sizeof(mask));
/*
   ptr = l1buf;
   while ((obj = strtok(ptr, ":")) != NULL) {
      if (l1labsindex < 256) {
         l1labs[l1labsindex].object = obj;
         l1labsindex++;
      }
      ptr = NULL;
   }
*/

         for (ap = mask; (*ap = strtok(sptr, "$")) != NULL;) {
            sptr = NULL;
            if (**ap != '\0')
               if (++ap >= &mask[ARGUS_MAX_MASK])
                  break;
         }

         for (i = 0; i < ARGUS_MAX_MASK; i++) {
            char *word;
            if (mask[i] != NULL) {
               if ((word = strtok((char *)mask[i], " ,./_\t\n")) != NULL) {
                  if (!(ArgusAddMaskList (parser, word)))
                     ArgusLog(LOG_ERR, "%s: error: mask arg %s", file, word);
               }
            } else
               break;
         }

         if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_OBJ_AGGREGATOR)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

         free(file);
      }

      ArgusNadp->filename = strdup(outputfile);
      setArgusWfile (parser, outputfile, NULL);

      parser->RaClientTimeout.tv_sec  = 0;
      parser->RaClientTimeout.tv_usec = 330000;
      parser->RaInitialized++;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusClientInit()\n");
#endif
}


void RaArgusInputComplete (struct ArgusInput *input) { return; }


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(caught signal %d)\n", sig);
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

                  ArgusDeleteList(ArgusParser->ArgusWfileList, ARGUS_WFILE_LIST);
               }

               if (ArgusNadp->filename != NULL)
                  free (ArgusNadp->filename);
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


#define ARGUS_OBJ_IDLE_TIME	120

void
ArgusClientTimeout ()
{
   struct ArgusAggregatorStruct *agg;

   if ((agg = ArgusParser->ArgusAggregator) != NULL) {
      struct ArgusQueueStruct *queue = agg->queue;
      struct ArgusObjectStruct *obj = NULL;
      int i, cnt;

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&queue->lock);
#endif
      cnt = queue->count;

      for (i = 0; i < cnt; i++) {
         if ((obj = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
            if (ArgusParser->ArgusRealTime.tv_sec > (obj->lasttime.tv_sec  + ARGUS_OBJ_IDLE_TIME)) {
#ifdef ARGUSDEBUG
               ArgusDebug (1, "ArgusClientTimeout() closing file: %s\n", obj->wfile.filename);
#endif
               free(obj->wfile.filename);
               if (obj->htblhdr != NULL)
                  ArgusRemoveHashEntry(&obj->htblhdr);
               if (obj->wfile.fd) {
                  fflush (obj->wfile.fd);
                  fclose (obj->wfile.fd);
                  obj->wfile.fd = NULL;
               }
               ArgusFree(obj);
            } else
               ArgusAddToQueue (queue, &obj->qhdr, ARGUS_NOLOCK);
         }
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusClientTimeout()\n");
#endif
}

void parse_arg (int argc, char**argv) {}

void
usage ()
{
   extern char version[];

   fprintf (stdout, "Rasplit Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] -S remoteServer  [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -b                  dump packet-matching code.\n");
   fprintf (stdout, "         -C <[host]:port>    specify remote Cisco Netflow source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stdout, "         -D <level>          specify debug level\n");
#endif
   fprintf (stdout, "         -E <file>           write records that are rejected by the filter\n");
   fprintf (stdout, "                             into <file>\n");
   fprintf (stdout, "         -F <conffile>       read configuration from <conffile>.\n");
   fprintf (stdout, "         -h                  print help.\n");

   fprintf (stdout, "         -M <mode>           supported modes of operation:\n");
   fprintf (stdout, "            time n[smhdwmy]  n must be a integral value\n");
   fprintf (stdout, "           count n[kmb]\n");
   fprintf (stdout, "            size n[kmb]\n");
   fprintf (stdout, "            nomodify\n");

   fprintf (stdout, "         -r <file>           read argus data <file>. '-' denotes stdin.\n");
   fprintf (stdout, "         -S <host[:port]>    specify remote argus <host> and optional port\n");
   fprintf (stdout, "                             number.\n");
   fprintf (stdout, "         -t <timerange>      specify <timerange> for reading records.\n");
   fprintf (stdout, "                   format:   timeSpecification[-timeSpecification]\n");
   fprintf (stdout, "                             timeSpecification: [[[yyyy/]mm/]dd.]hh[:mm[:ss]]\n");
   fprintf (stdout, "                                                  [yyyy/]mm/dd\n");
   fprintf (stdout, "                                                  -%%d{yMdhms}\n");
   fprintf (stdout, "         -T <secs>           attach to remote server for T seconds.\n");
#ifdef ARGUS_SASL
   fprintf (stdout, "         -U <user/auth>      specify <user/auth> authentication information.\n");
#endif
   fprintf (stdout, "         -w <file>           write output to <file>. '-' denotes stdout.\n");
   fflush (stdout);
   exit(1);
}


int RaFirstRecord = 1;

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   switch (ns->hdr.type & 0xF0) {
      case ARGUS_MAR: {
         if (!(RaFirstRecord)) {
            struct ArgusRecord *rec = (struct ArgusRecord *)ns->dsrs[0];
            if (rec && parser->ArgusAdjustTime) {
               struct timeval drift;

               drift.tv_sec  = parser->ArgusRealTime.tv_sec  - ntohl(rec->argus_mar.now.tv_sec);
               drift.tv_usec = parser->ArgusRealTime.tv_usec - ntohl(rec->argus_mar.now.tv_usec);
               ns->input->ArgusTimeDrift  = drift.tv_sec * 1000000;
               ns->input->ArgusTimeDrift += drift.tv_usec;
               rec->argus_mar.drift = ns->input->ArgusTimeDrift;
#ifdef ARGUSDEBUG
#if defined(__APPLE_CC__) || defined(__APPLE__)
               ArgusDebug (3, "RaProcessRecord: ArgusInput 0x%x drift %lld\n",
                                ns->input, ns->input->ArgusTimeDrift);
#else
               ArgusDebug (3, "RaProcessRecord: ArgusInput 0x%x drift %Ld\n",
                                ns->input, ns->input->ArgusTimeDrift);
#endif
#endif
            }
            RaSendArgusRecord (ns);

         } else
            RaFirstRecord = 0;
         break;
      }

      case ARGUS_EVENT: {
         RaSendArgusRecord (ns);
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         struct ArgusTimeObject *time = (void *)ns->dsrs[ARGUS_TIME_INDEX];
         struct ArgusRecordStruct *tns = NULL;

         if (time == NULL)
            return;

         ArgusThisTime.tv_sec  = time->src.start.tv_sec;
         ArgusThisTime.tv_usec = time->src.start.tv_usec;

         if (RaRealTime) {
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

                  ts.tv_nsec =  thisRate * 1000;
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
         } else
            ArgusLastTime = parser->ArgusRealTime;

         switch (ArgusNadp->mode) {
            case ARGUSSPLITTIME: {
               ArgusAlignInit(parser, ns, &adata);
               while ((tns = ArgusAlignRecord(parser, ns, &adata)) != NULL) {
                  RaSendArgusRecord (tns);
                  ArgusDeleteRecordStruct (parser, tns);
               }
               break;
            }

            case ARGUSSPLITCOUNT:
            case ARGUSSPLITSIZE: 
            case ARGUSSPLITFLOW: {
               RaSendArgusRecord (ns);
               break;
            }
         }
         break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessRecord (0x%x) done\n", ns); 
#endif
}


int
ArgusInitNewFilename(struct ArgusParserStruct *parser, struct ArgusWfileStruct *wfile, char *filename)
{
   char *tptr = NULL, *pptr = NULL;
   char tmpbuf[MAXSTRLEN]; 
   int retn = 0;

   if (wfile->fd != NULL) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusInitNewFilename(0x%x, 0x%x, %s) closing file: %s\n", parser, wfile, filename, wfile->filename); 
#endif
      fclose (wfile->fd);
      wfile->fd = NULL;
   }

   if (wfile->filename != NULL) {
      free(wfile->filename);
      wfile->filename = NULL;
   } 

   if (filename == NULL)
      if ((filename = RaSplitFilename(ArgusNadp)) == NULL)
         ArgusLog(LOG_ERR, "RaProcessRecord filename beyond space");

   wfile->filename = strdup(filename);

   /* got new filename, need to check the
      path to be sure that all the directories exist */

   bzero (tmpbuf, sizeof(tmpbuf));
   strncpy (tmpbuf, wfile->filename, MAXSTRLEN);
   if ((tptr = strrchr(tmpbuf, (int) '/')) != NULL) {   /* if there is a path */
      *tptr = '\0';
      pptr = tptr;

      while ((pptr != NULL) && ((stat(tmpbuf, &wfile->statbuf)) < 0)) {
         switch (errno) {
            case ENOENT:
               if ((pptr = strrchr(tmpbuf, (int) '/')) != NULL) {
                  if (pptr != tmpbuf) {
                     *pptr = '\0';
                  } else {
                     pptr = NULL;
                  }
               }
               break;

            default:
               ArgusLog (LOG_ERR, "stat: %s %s\n", tmpbuf, strerror(errno));
         }
      }

      while (&tmpbuf[strlen(tmpbuf)] <= tptr) {
         if ((mkdir(tmpbuf, 0777)) < 0) {
            if (errno != EEXIST)
               ArgusLog (LOG_ERR, "mkdir: %s %s\n", tmpbuf, strerror(errno));
         }
         tmpbuf[strlen(tmpbuf)] = '/';
      }
      *tptr = '/';
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusInitNewFilename(0x%x, 0x%x, %s) done\n", parser, wfile, filename); 
#endif

   return (retn);
}

extern int RaDaysInAMonth[12];

time_t ArgusFileStartSecs = 0;
time_t ArgusFileEndSecs = 0;
char ArgusCurrentFileName[MAXSTRLEN];

int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{
   struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;
   struct ArgusWfileStruct *wfile = NULL;
   struct ArgusObjectStruct *obj = NULL;
   int retn = 1;

   if (argus->status & ARGUS_RECORD_WRITTEN)
      return (retn);

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR: 
      case ARGUS_EVENT:
      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (agg != NULL) {
            struct ArgusRecordStruct *ns = ArgusCopyRecordStruct(argus);
            struct ArgusHashStruct *hstruct = NULL;

            if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
               agg->rap = agg->drap;

            ArgusGenerateNewFlow(agg, ns);

            if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
               ArgusLog (LOG_ERR, "RaSendArgusRecord: ArgusGenerateHashStruct error %s", strerror(errno));

            if ((obj = ArgusFindObject(agg->htable, hstruct)) == NULL) {
               if ((obj = (struct ArgusObjectStruct *) ArgusCalloc(1, sizeof(*obj))) == NULL)
                  ArgusLog (LOG_ERR, "RaSendArgusRecord: ArgusCalloc error");

               obj->htblhdr = ArgusAddHashEntry(agg->htable, (void *)obj, hstruct);
               ArgusAddToQueue (agg->queue, &obj->qhdr, ARGUS_LOCK);

               if ((wfile = (struct ArgusWfileStruct *)ArgusFrontList(ArgusParser->ArgusWfileList)) == NULL)
                  ArgusLog (LOG_ERR, "RaSendArgusRecord: no output file specified");

               bcopy(wfile, &obj->wfile, sizeof(*wfile));
               obj->wfile.filename = NULL;
            }

            ArgusFileStartSecs = obj->ArgusFileStartSecs;
            ArgusFileEndSecs   = obj->ArgusFileEndSecs;
            wfile = &obj->wfile;

            ArgusDeleteRecordStruct(ArgusParser, ns);

         } else {
            if ((wfile = (struct ArgusWfileStruct *)ArgusFrontList(ArgusParser->ArgusWfileList)) == NULL)
               ArgusLog (LOG_ERR, "RaSendArgusRecord: no output file specified");
         }
         break;
      }
   }

   switch (ArgusNadp->mode) {
      case ARGUSSPLITTIME: {
         long long start = ArgusFetchStartuSecTime(argus);
         time_t fileSecs = start / 1000000;
         int size = ArgusNadp->size / 1000000;
         struct tm tmval;

         if (!(ArgusFileStartSecs) || !((fileSecs >= ArgusFileStartSecs) && (fileSecs < ArgusFileEndSecs))) {
            switch (ArgusNadp->qual) {
               case ARGUSSPLITYEAR:
               case ARGUSSPLITMONTH:
               case ARGUSSPLITWEEK: 
                  gmtime_r(&fileSecs, &tmval);
                  break;
            }

            switch (ArgusNadp->qual) {
               case ARGUSSPLITYEAR:
                  tmval.tm_mon = 0;
               case ARGUSSPLITMONTH:
                  tmval.tm_mday = 1;

               case ARGUSSPLITWEEK: 
                  if (ArgusNadp->qual == ARGUSSPLITWEEK) {
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
                  fileSecs = timegm(&tmval);
                  localtime_r(&fileSecs, &tmval);

#if defined(HAVE_TM_GMTOFF)
                  fileSecs -= tmval.tm_gmtoff;
#endif
                  break;

               case ARGUSSPLITDAY:
               case ARGUSSPLITHOUR:
               case ARGUSSPLITMINUTE:
               case ARGUSSPLITSECOND: {
                  localtime_r(&fileSecs, &tmval);
#if defined(HAVE_TM_GMTOFF)
                  fileSecs += tmval.tm_gmtoff;
#endif
                  fileSecs = fileSecs / size;
                  fileSecs = fileSecs * size;
#if defined(HAVE_TM_GMTOFF)
                  fileSecs -= tmval.tm_gmtoff;
#endif
                  break;
               }
            }

            localtime_r(&fileSecs, &tmval);

            if (strftime(ArgusCurrentFileName, MAXSTRLEN, ArgusNadp->filename, &tmval) <= 0)
               ArgusLog (LOG_ERR, "RaSendArgusRecord () ArgusCalloc %s\n", strerror(errno));

            RaProcessSplitOptions(ArgusParser, ArgusCurrentFileName, MAXSTRLEN, argus);
        
            if ((wfile->filename == NULL) || (strcmp(wfile->filename, ArgusCurrentFileName)))
               ArgusInitNewFilename(ArgusParser, wfile, ArgusCurrentFileName);

            ArgusFileStartSecs = fileSecs;

            switch (ArgusNadp->qual) {
               case ARGUSSPLITYEAR:  
                  tmval.tm_year++;
                  ArgusFileEndSecs = mktime(&tmval);
                  break;
               case ARGUSSPLITMONTH:
                  tmval.tm_mon++;
                  ArgusFileEndSecs = mktime(&tmval);
                  break;
               case ARGUSSPLITWEEK: 
               case ARGUSSPLITDAY: 
               case ARGUSSPLITHOUR: 
               case ARGUSSPLITMINUTE: 
               case ARGUSSPLITSECOND: 
                  ArgusFileEndSecs = fileSecs + size;
                  break;
            }
         }
         break;
      }

      case ARGUSSPLITCOUNT: {
         char *filename = NULL;
         int newfilename = 0;
         int value = ArgusNadp->value;

         sprintf (ArgusCurrentFileName, "%s", ArgusNadp->filename);
         RaProcessSplitOptions(ArgusParser, ArgusCurrentFileName, MAXSTRLEN, argus);

         if (strcmp(wfile->filename, ArgusCurrentFileName)) {
            filename = ArgusCurrentFileName;
            newfilename++;
         }

         if ((value == 1) || ((value > 1) && (!(ArgusNadp->count % value))))
            newfilename++;

         if (ArgusNadp->count > 0)
            ArgusNadp->count++;

         if (newfilename)
            ArgusInitNewFilename(ArgusParser, wfile, filename);
         break;
      }


      case ARGUSSPLITSIZE: {
         char *filename = NULL;
         int newfilename = 0;

         sprintf (ArgusCurrentFileName, "%s", ArgusNadp->filename);
         RaProcessSplitOptions(ArgusParser, ArgusCurrentFileName, MAXSTRLEN, argus);

         if (strcmp(wfile->filename, ArgusCurrentFileName)) {
            filename = ArgusCurrentFileName;
            newfilename++;
         }

         if ((ArgusNadp->value > 0) && (stat (wfile->filename, &wfile->statbuf) == 0))
            if ((wfile->statbuf.st_size + (argus->hdr.len * 4)) > ArgusNadp->value)
               newfilename++;

         if (newfilename)
            ArgusInitNewFilename(ArgusParser, wfile, filename);
         break;
      }


      case ARGUSSPLITFLOW: {
         struct nff_insn *fcode = ArgusNadp->filter.bf_insns;
         char *filename = NULL;
         int newfilename = 0;

         sprintf (ArgusCurrentFileName, "%s", ArgusNadp->filename);
         RaProcessSplitOptions(ArgusParser, ArgusCurrentFileName, MAXSTRLEN, argus);

         if (strcmp(wfile->filename, ArgusCurrentFileName)) {
            filename = ArgusCurrentFileName;
            newfilename++;
         }

         if (ArgusFilterRecord (fcode, argus) != 0)
            newfilename++;

         if (newfilename)
            ArgusInitNewFilename(ArgusParser, wfile, filename);
         break;
      }
   }
 
   if (wfile != NULL) {
      int pass = 1;
      if (wfile->filterstr) {
         struct nff_insn *wfcode = wfile->filter.bf_insns;
         pass = ArgusFilterRecord (wfcode, argus);
      }

      if (pass != 0) {
         if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
            struct ArgusRecord *argusrec = NULL;
            char buf[0x10000];
            if ((argusrec = ArgusGenerateRecord (argus, 0L, buf)) != NULL) {
#ifdef _LITTLE_ENDIAN
               ArgusHtoN(argusrec);
#endif
               ArgusWriteNewLogfile (ArgusParser, argus->input, wfile, argusrec);
            }
         }
      }
   }

   if ((agg != NULL) && (obj != NULL)) {
      obj->ArgusFileStartSecs = ArgusFileStartSecs;
      obj->ArgusFileEndSecs   = ArgusFileEndSecs;
      obj->lasttime           = ArgusParser->ArgusRealTime;
   }

   argus->status |= ARGUS_RECORD_WRITTEN;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaSendArgusRecord () returning %d\n", retn);
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
   int len, i = 1;

   if (filename != NULL) {
      len = strlen(filename);

      for (i = 0; i < nadp->slen; i++) {
         if (filename[len - (i + 1)] == 'z') {
            filename[len - (i + 1)] = 'a';
         } else {
            filename[len - (i + 1)]++;
            break;
         }
      }

      if (filename[len - nadp->slen] == 'z') {
         snprintf(tmpbuf, MAXSTRLEN, "%sa", filename);

         if (nadp->filename)
            free(nadp->filename);

         nadp->filename = strdup(tmpbuf);
      }

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
   char *ptr = NULL, *cptr = NULL, *tptr = str;
   int retn = 0, i, x, slen = 0;

   bzero(resultbuf, MAXSTRLEN);
   bzero(tmpbuf, MAXSTRLEN);

   while ((ptr = strchr (tptr, '$')) != NULL) {
      *ptr++ = '\0';
      slen = strlen(resultbuf);
      snprintf (&resultbuf[slen], MAXSTRLEN - slen, "%s", tptr);

      for (i = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (!strncmp (RaPrintAlgorithmTable[x].field, ptr, strlen(RaPrintAlgorithmTable[x].field))) {
            RaPrintAlgorithmTable[x].print(parser, tmpbuf, ns, RaPrintAlgorithmTable[x].length);

            while (isspace((int)tmpbuf[strlen(tmpbuf) - 1]))
               tmpbuf[strlen(tmpbuf) - 1] = '\0';

            while (isspace((int)tmpbuf[i])) i++;
            slen = strlen(resultbuf);
            snprintf (&resultbuf[slen], MAXSTRLEN - slen, "%s", &tmpbuf[i]);

            ptr += strlen(RaPrintAlgorithmTable[x].field);
            cptr = &resultbuf[strlen(resultbuf)];

            while (*ptr && (*ptr != '$')) {
               *cptr++ = *ptr++;
            }
            *cptr = '\0';
            break;
         }
      }

      tptr = ptr;
      retn++;
   }

   if (retn) {
      int len = strlen(resultbuf);
      bcopy (resultbuf, str, strlen(resultbuf));
      str[len] = '\0';
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaProcessSplitOptions(%s, %d, 0x%x): returns %d", str, len, ns, retn);
#endif

   return (retn);
}

struct ArgusObjectStruct *
ArgusFindObject (struct ArgusHashTable *htable, struct ArgusHashStruct *hstruct)
{
   struct ArgusObjectStruct *retn = NULL;
   struct ArgusHashTableHdr *hashEntry = NULL, *target, *head;
   unsigned int ind = (hstruct->hash % htable->size), i, len;

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&htable->lock);
#endif
   if ((target = htable->array[ind]) != NULL) {
      head = target;
      do {
         unsigned short *ptr1 = (unsigned short *) hstruct->buf;
         unsigned short *ptr2 = (unsigned short *) target->hstruct.buf;

         if (ptr1 && ptr2) {
            for (i = 0, len = hstruct->len/sizeof(unsigned short); i < len; i++)
               if (*ptr1++ != *ptr2++)
                  break;
            if (i == len) {
               hashEntry = target;
               break;
            }

         } else
           if (!(ptr1 || ptr2) || ((hstruct->len == 0) && (target->hstruct.len == 0))) {
               hashEntry = target;
               break;
           }

         target = target->nxt;
      } while (target != head);

      if (hashEntry != NULL) {
         if (hashEntry != head)
            htable->array[ind] = hashEntry;
         retn = hashEntry->object;
      }
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&htable->lock);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusFindObject () returning 0x%x\n", retn);
#endif

   return (retn);
}

