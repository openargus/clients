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
 * $Id: //depot/gargoyle/clients/clients/radium.c#20 $
 * $DateTime: 2016/11/30 00:54:11 $
 * $Change: 3245 $
 */

/*
 * radium.c  - this is the argus record distribtion node.
 *    Acting just like a ra* program, supporting all the options
 *    and functions of ra(), and providing access to data, like
 *    argus, supporting remote filtering, and MAR record generation.
 *    This is an important workhorse for the argus architecture.
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <grp.h>
#include <pwd.h>

#if defined(HAVE_SYS_VFS_H)
#include <sys/vfs.h>
#else
#include <sys/param.h>
#include <sys/mount.h>
#endif

#include <argus_compat.h>
#include <argus_util.h>
#include <argus_output.h>
#include "argus_clientconfig.h"

#include <rabins.h>

#if defined(HAVE_UUID_UUID_H)
#include <uuid/uuid.h>
#else
#if defined(HAVE_UUID_H)
#include <uuid.h>
#else
#if defined(HAVE_LINUX_UUID_H)
#include <linux/uuid.h>
#endif
#endif
#endif


#define RADIUM_MAX_ANALYTICS    128
struct ArgusRecordStruct *(*RadiumAnalyticAlgorithmTable[RADIUM_MAX_ANALYTICS])(struct ArgusParserStruct *, struct ArgusRecordStruct *) = {
   NULL, NULL, NULL
};


struct timeval ArgusLastRealTime = {0, 0};
                                                                                                                           
struct timeval dLastTime = {0, 0};
struct timeval dRealTime = {0, 0};
struct timeval dThisTime = {0, 0};
struct timeval dTime     = {0, 0};
                                                                                                                           
long long thisUsec = 0;
                                                                                                                           
void RadiumSendFile (struct ArgusOutputStruct *, struct ArgusClientData *, char *, int);
int RadiumParseSourceID (struct ArgusAddrStruct *, char *);
int RadiumParseSrcidConversionFile (char *);

static int RadiumMinSsf = 0;
static int RadiumMaxSsf = 0;
static int RadiumAuthLocalhost = 1;
static int RadiumParseResourceLine (struct ArgusParserStruct *parser,
                                    int linenum, char *optarg, int quoted,
                                    int idx);

const static unsigned int ArgusClientMaxQueueDepth = 500000;

extern char *chroot_dir;
extern uid_t new_uid;
extern gid_t new_gid;

void ArgusSetChroot(char *);

#define RADIUM_RCITEMS                          28

#define RADIUM_MONITOR_ID                       0
#define RADIUM_MONITOR_ID_INCLUDE_INF		1
#define RADIUM_ARGUS_SERVER                     2
#define RADIUM_ARGUS_CLIENT			3
#define RADIUM_DAEMON                           4
#define RADIUM_CISCONETFLOW_PORT                5
#define RADIUM_ACCESS_PORT                      6
#define RADIUM_INPUT_FILE                       7
#define RADIUM_USER_AUTH                        8
#define RADIUM_AUTH_PASS                        9
#define RADIUM_OUTPUT_FILE                      10
#define RADIUM_OUTPUT_STREAM                    11
#define RADIUM_MAR_STATUS_INTERVAL              12
#define RADIUM_DEBUG_LEVEL                      13
#define RADIUM_FILTER_OPTIMIZER                 14
#define RADIUM_FILTER_TAG                       15
#define RADIUM_BIND_IP                          16
#define RADIUM_MIN_SSF                          17
#define RADIUM_MAX_SSF                          18
#define RADIUM_ADJUST_TIME                      19
#define RADIUM_CHROOT_DIR                       20
#define RADIUM_SETUSER_ID                       21
#define RADIUM_SETGROUP_ID                      22
#define RADIUM_CLASSIFIER_FILE                  23
#define RADIUM_ZEROCONF_REGISTER                24
#define RADIUM_V3_ACCESS_PORT                   25
#define RADIUM_SRCID_CONVERSION_FILE            26
#define RADIUM_AUTH_LOCALHOST                   27

char *RadiumResourceFileStr [] = {
   "RADIUM_MONITOR_ID=",
   "RADIUM_MONITOR_ID_INCLUDE_INF=",
   "RADIUM_ARGUS_SERVER=",
   "RADIUM_ARGUS_CLIENT=",
   "RADIUM_DAEMON=",
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
   "RADIUM_ZEROCONF_REGISTER=",
   "RADIUM_V3_ACCESS_PORT=",
   "RADIUM_SRCID_CONVERSION_FILE=",
   "RADIUM_AUTH_LOCALHOST=",
};


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode;
   FILE *tmpfile = NULL;
   struct timeval *tvp;
   int pid, dflag;
#if defined(ARGUS_THREADS)
   sigset_t blocked_signals;
#endif /* ARGUS_THREADS */

   parser->RaWriteOut = 1;
   parser->ArgusReverse = 1;

   if (!(parser->RaInitialized)) {
      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "zeroconf", 8)))
               parser->ArgusZeroConf = 1;
            mode = mode->nxt;
         }
      }

      dflag = parser->dflag;
      parser->dflag = 0;

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if (parser->ArgusFlowModelFile != NULL) {
         RaParseResourceFile (parser, parser->ArgusFlowModelFile,
                              ARGUS_SOPTIONS_IGNORE, RadiumResourceFileStr,
                              RADIUM_RCITEMS, RadiumParseResourceLine);
      } else {
         if (!(parser->Xflag)) {
            RaParseResourceFile (parser, "/etc/radium.conf",
                                 ARGUS_SOPTIONS_IGNORE, RadiumResourceFileStr,
                                 RADIUM_RCITEMS, RadiumParseResourceLine);
         }
      }

      parser->dflag = (parser->dflag) ? (dflag ? 0 : 1) : dflag;

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
    
                  ArgusLog(LOG_INFO, "started");

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

      if (chroot_dir != NULL)
         ArgusSetChroot(chroot_dir);
 
      if (new_gid > 0) {
         if (setgid(new_gid) < 0)
            ArgusLog (LOG_ERR, "ArgusInitOutput: setgid error %s", strerror(errno));
      }

      if (new_uid > 0) {
         if (setuid(new_uid) < 0)
            ArgusLog (LOG_ERR, "ArgusInitOutput: setuid error %s", strerror(errno));
      }

/*
   This is the basic new argus() strategy for processing output
   records.  The thread will do two basic things: 
      1) it will grab stuff off the queue, and then do the basic
         processing that this radium will do, such as time
         adjustment, aggregation, correction, and anonymization, etc...

      2) it will establish the permanent and non-argus outputs
         from the configuration file.

      3) it will manage the listen, to deal without remote argus
         requests.  radium() can write its records to a file, and
         any number of remote clients, so ......

   The ArgusClientTimeout() routine will drive all the maintenance
   and so it should be run, probably 4x a second, just for good
   measure.
*/
      parser->ArgusReliableConnection++;

      tvp = getArgusMarReportInterval(ArgusParser);
      if ((tvp->tv_sec == 0) && (tvp->tv_usec == 0)) {
         setArgusMarReportInterval (ArgusParser, "5s");
      }

      if ((parser->ArgusOutput = ArgusNewOutput(parser, RadiumMinSsf,
                                                RadiumMaxSsf,
                                                RadiumAuthLocalhost)) == NULL)
         ArgusLog (LOG_ERR, "could not create output: %s\n", strerror(errno));

      /* Need valid parser->ArgusOutput before starting listener */
      if (parser->ArgusPortNum != 0) {
         if (ArgusEstablishListen (parser, parser->ArgusOutput,
                                   parser->ArgusPortNum, parser->ArgusBindAddr,
                                   ARGUS_VERSION) < 0)
            ArgusLog (LOG_ERR, "setArgusPortNum: ArgusEstablishListen returned %s", strerror(errno));
      }
      if (parser->ArgusV3Port != 0) {
         if (ArgusEstablishListen (parser, parser->ArgusOutput,
                                   parser->ArgusV3Port, parser->ArgusBindAddr,
                                   ARGUS_VERSION_3) < 0)
            ArgusLog (LOG_ERR, "%s: ArgusEstablishListen returned %s",
                      __func__, strerror(errno));
      }

#if defined(ARGUS_THREADS)
      sigemptyset(&blocked_signals);
      pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);
#endif
      (void) signal (SIGHUP,  (void (*)(int)) ArgusShutDown);
      (void) signal (SIGTERM, (void (*)(int)) ArgusShutDown);
      (void) signal (SIGQUIT, (void (*)(int)) ArgusShutDown);
      (void) signal (SIGINT,  (void (*)(int)) ArgusShutDown);

      (void) signal (SIGPIPE, SIG_IGN);
      (void) signal (SIGTSTP, SIG_IGN);
      (void) signal (SIGTTOU, SIG_IGN);
      (void) signal (SIGTTIN, SIG_IGN);

      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input)
{

};

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
               ArgusDeleteInput(ArgusParser, input);
            }
         }
         ArgusDeleteQueue(queue);
         ArgusParser->ArgusActiveHosts = NULL;
      }

      if (ArgusParser->ArgusOutput) {
         if ((rec = ArgusGenerateStatusMarRecord(ArgusParser->ArgusOutput, ARGUS_SHUTDOWN, ARGUS_VERSION)) != NULL)
            ArgusPushBackList(ArgusParser->ArgusOutput->ArgusOutputList, (struct ArgusListRecord *)rec, ARGUS_LOCK);
      
         ArgusCloseListen(ArgusParser);
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
   ArgusParser->ArgusGlobalTime = ArgusParser->ArgusRealTime;

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
      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusTimeObject *time = (void *)argus->dsrs[ARGUS_TIME_INDEX];

         if (time != NULL) {
            if (parser->ArgusAdjustTime) {
               int secs = 0, usecs = 0;

               if (parser->ProcessRealTime) {
                  struct timeval tvpbuf, *now = &tvpbuf;
                  double lastTime = ArgusFetchLastTime(argus);

                  gettimeofday(now, NULL);
                  secs  = now->tv_sec - (int)lastTime;
                  usecs = now->tv_usec - ((lastTime - (int)lastTime) * 1000000);
                  if (usecs < 0) { usecs += 1000000; secs--; }

               } else {
                  long long ArgusDriftLevel = parser->ArgusAdjustTime * 1000000;
                  if (time && ((argus->input->ArgusTimeDrift >  ArgusDriftLevel) || 
                               (argus->input->ArgusTimeDrift < -ArgusDriftLevel))) {
                        secs  = argus->input->ArgusTimeDrift / 1000000;
                        usecs = argus->input->ArgusTimeDrift % 1000000;
                     }
               }

               if ((secs > 0) || (usecs > 0)) {
                  if (time->hdr.subtype & (ARGUS_TIME_SRC_START | ARGUS_TIME_DST_START)) {
                     time->hdr.argus_dsrvl8.qual |= ARGUS_TIMEADJUST;
                     if (time->hdr.subtype & ARGUS_TIME_SRC_START) {
                        if (time->src.start.tv_sec > 0) {
                           time->src.start.tv_sec  += secs;
                           time->src.start.tv_usec += usecs;
                           if (time->src.start.tv_usec > 1000000) {
                              time->src.start.tv_sec++;
                              time->src.start.tv_usec -= 1000000;
                           }
                        }
                        if (time->src.end.tv_sec > 0) {
                           time->src.end.tv_sec  += secs;
                           time->src.end.tv_usec += usecs;
                           if (time->src.end.tv_usec > 1000000) {
                              time->src.end.tv_sec++;
                              time->src.end.tv_usec -= 1000000;
                           }
                        }
                     }

                     if (time->hdr.subtype & ARGUS_TIME_DST_START) {
                        if (time->dst.start.tv_sec > 0) {
                           time->dst.start.tv_sec  += secs;
                           time->dst.start.tv_usec += usecs;
                           if (time->dst.start.tv_usec > 1000000) {
                              time->dst.start.tv_sec++;
                              time->dst.start.tv_usec -= 1000000;
                           }
                        }
                        if (time->dst.end.tv_sec > 0) {
                           time->dst.end.tv_sec  += secs;
                           time->dst.end.tv_usec += usecs;
                           if (time->dst.end.tv_usec > 1000000) {
                              time->dst.end.tv_sec++;
                              time->dst.end.tv_usec -= 1000000;
                           }
                        }
                     }
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "RaProcessRecord() ArgusInput 0x%x adjusting timestamps by %d secs and %d usecs\n", argus->input, secs, usecs);
#endif
                  }
               }
            }
         }
         break;
      }
   }

   if ((ns = ArgusCopyRecordStruct(argus)) != NULL) {
      int i;
      for (i = 0; i < RADIUM_MAX_ANALYTICS; i++) {
         if (RadiumAnalyticAlgorithmTable[i] != NULL) {
            if ((ns = RadiumAnalyticAlgorithmTable[i](parser, ns)) == NULL)
               break;

         } else
            break;
      }

      if (ns != NULL)
         ArgusPushBackList(parser->ArgusOutput->ArgusOutputList, (struct ArgusListRecord *) ns, ARGUS_LOCK);
   }

#if defined(ARGUS_THREADS)
   if (parser->ArgusOutput && parser->ArgusOutput->ArgusOutputList) {
      unsigned int cnt;

      pthread_mutex_lock(&parser->ArgusOutput->ArgusOutputList->lock);
      pthread_cond_signal(&parser->ArgusOutput->ArgusOutputList->cond);
      cnt = parser->ArgusOutput->ArgusOutputList->count;
      pthread_mutex_unlock(&parser->ArgusOutput->ArgusOutputList->lock);

      if (cnt > ArgusClientMaxQueueDepth) {
         struct timespec tsbuf = {0, 10000000}, *ts = &tsbuf;
         nanosleep (ts, NULL);
      }
   }

#else
   ArgusListenProcess(parser);
   ArgusOutputProcess(parser->ArgusOutput);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (4, "RaProcessRecord (0x%x, 0x%x) returning", parser, argus); 
#endif
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}

/* used by RadiumParseResourceLine */
static int roption = 0;

static int
RadiumParseResourceLine (struct ArgusParserStruct *parser, int linenum,
                         char *optarg, int quoted, int idx)
{
   int retn = 0;
   char *ptr;

   switch (idx) {
      case RADIUM_MONITOR_ID: {
         if (optarg && quoted) {   // Argus ID is a string.  Limit to date is 4 characters.
            int slen = strlen(optarg);
            if (slen > 4) optarg[4] = '\0';
            if (optarg[3] == '\"') optarg[3] = '\0';
            setParserArgusID (parser, optarg, 4, ARGUS_TYPE_STRING);

         } else {
            if (optarg && (*optarg == '`')) {
               if (strrchr(optarg, (int) '`') != optarg) {
                  char *val = ArgusExpandBackticks(optarg);

#ifdef ARGUSDEBUG
                  ArgusDebug(1, "expanded %s to %s\n", optarg, val);
#endif
                  ArgusParseSourceID(parser, val);
                  free(val);
               } else {
                  ArgusLog (LOG_ERR, "%s: syntax error line %d\n", __func__, linenum);
               }
            } else {
               ArgusParseSourceID(parser, optarg);
            }
         }
         break;
      }

      case RADIUM_MONITOR_ID_INCLUDE_INF:
         setArgusManInf(parser, optarg);
         break;

      case RADIUM_ARGUS_CLIENT:
         break;

      case RADIUM_ARGUS_SERVER:
         if (!parser->Sflag++ && (parser->ArgusRemoteServerList != NULL))
            ArgusDeleteServerList(parser);

         if (!(ArgusAddServerList (parser, optarg, ARGUS_DATA_SOURCE, IPPROTO_TCP)))
            ArgusLog (LOG_ERR, "%s: host %s unknown\n", optarg);
         break;

      case RADIUM_CISCONETFLOW_PORT: {
         ++parser->Cflag;
         if (!parser->Sflag++ && (parser->ArgusRemoteServerList != NULL))
            ArgusDeleteServerList(parser);

         if (!(ArgusAddServerList (parser, optarg, ARGUS_CISCO_DATA_SOURCE, IPPROTO_UDP)))
            ArgusLog (LOG_ERR, "%s: host %s unknown\n", optarg);

         break;
      }

      case RADIUM_DAEMON: {
         if (!(strncasecmp(optarg, "yes", 3)))
            parser->dflag = 1;
         else
         if (!(strncasecmp(optarg, "no", 2)))
            parser->dflag = 0;
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

      case RADIUM_V3_ACCESS_PORT:
         parser->ArgusV3Port = atoi(optarg);
         break;

      case RADIUM_SRCID_CONVERSION_FILE:
         parser->RadiumSrcidConvertFile = strdup(optarg);
         RadiumParseSrcidConversionFile (parser->RadiumSrcidConvertFile);
         break;

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
            char *str = optarg;
            ptr = parser->ArgusRemoteFilter;
            while (*str) {
               if ((*str != '\n') && (*str != '"'))
                  *ptr++ = *str++;
               else
                  str++;
            }
#ifdef ARGUSDEBUG
            ArgusDebug (1, "%s: ArgusFilter \"%s\" \n", __func__, parser->ArgusRemoteFilter);
#endif
         }
         break;

      case RADIUM_BIND_IP:
         if (*optarg != '\0')
            setArgusBindAddr (parser, optarg);
#ifdef ARGUSDEBUG
         ArgusDebug (1, "%s: ArgusBindAddr \"%s\" \n", __func__, parser->ArgusBindAddr);
#endif
         break;

      case RADIUM_MIN_SSF:
         if (*optarg != '\0') {
#ifdef ARGUS_SASL
            RadiumMinSsf = atoi(optarg);
#ifdef ARGUSDEBUG
         ArgusDebug (1, "%s: RadiumMinSsf \"%d\" \n", __func__, RadiumMinSsf);
#endif
#endif
         }
         break;

      case RADIUM_MAX_SSF:
         if (*optarg != '\0') {
#ifdef ARGUS_SASL
            RadiumMaxSsf = atoi(optarg);
#ifdef ARGUSDEBUG
            ArgusDebug (1, "%s: RadiumMaxSsf \"%d\" \n", __func__, RadiumMaxSsf);
#endif
#endif
         }
         break;

      case RADIUM_ADJUST_TIME: {
         char *ptr;
         parser->ArgusAdjustTime = strtol(optarg, (char **)&ptr, 10);
         if (ptr == optarg)
            ArgusLog (LOG_ERR, "%s: syntax error: line %d", __func__, linenum);

         if (isalpha((int) *ptr)) {
            switch (*ptr) {
               case 's': break;
               case 'm': parser->ArgusAdjustTime *= 60; break;
               case 'h': parser->ArgusAdjustTime *= 3600; break;
            }
         }
#ifdef ARGUSDEBUG
         ArgusDebug (1, "%s: ArgusAdjustTime is %d secs\n", __func__, parser->ArgusAdjustTime);
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
               ArgusLog (LOG_ERR, "%s: ArgusNewLabeler error", __func__);
         }

         if (RaLabelParseResourceFile (parser, parser->ArgusLabeler, optarg) != 0)
            ArgusLog (LOG_ERR, "%s: label conf file error %s", __func__, strerror(errno));

         RadiumAnalyticAlgorithmTable[0] = ArgusLabelRecord;
         break;
      }

      case RADIUM_ZEROCONF_REGISTER: {
         if ((strncasecmp(optarg, "yes", 3)))
            setArgusZeroConf (parser, 0);
         else
            setArgusZeroConf (parser, 1);
         break;

         break;
      }

      case RADIUM_AUTH_LOCALHOST:
         if (strncasecmp(optarg, "no", 2) == 0)
            RadiumAuthLocalhost = 0;
         break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s(%d,%s%s,%d) returning %d\n", __func__, linenum,
               RadiumResourceFileStr[idx], optarg, idx, retn);
#endif

   return (retn);
}


void
clearRadiumConfiguration (void)
{
   ArgusParser->dflag = 0;
   setParserArgusID (ArgusParser, 0, 0, 0);

   ArgusParser->ArgusPortNum = 0;

   clearArgusWfile (ArgusParser);
   setArgusBindAddr (ArgusParser, NULL);
   setArgusOflag (ArgusParser, 1);

   ArgusParser->dflag = 0;

   if (ArgusParser->ArgusRemoteServerList != NULL)
      ArgusDeleteServerList(ArgusParser);

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


int
RadiumParseSourceID (struct ArgusAddrStruct *srcid, char *optarg)
{
   return ArgusCommonParseSourceID(srcid, NULL, optarg);
}


/*
   RadiumParseSrcidConversionFile (char *file)
      srcid 	conversionValue
*/

extern struct cnamemem converttable[HASHNAMESIZE];

int 
RadiumParseSrcidConversionFile (char *file)
{
   struct stat statbuf;
   FILE *fd = NULL;
   int retn = 0;

   if (file != NULL) {
      if (stat(file, &statbuf) >= 0) {
         if ((fd = fopen(file, "r")) != NULL) {
            char strbuf[MAXSTRLEN], *str = strbuf, *optarg = NULL;
            char *srcid = NULL, *convert = NULL;

            retn = 1;

            while ((fgets(strbuf, MAXSTRLEN, fd)) != NULL)  {
               str = strbuf;
               while (*str && isspace((int)*str))
                   str++;

#define RA_READING_SRCID                0
#define RA_READING_ALIAS                1

               if (*str && (*str != '#') && (*str != '\n') && (*str != '!')) {
                  int state = RA_READING_SRCID;
                  struct cnamemem  *ap;
                  int done = 0;
                  u_int hash;

                  while ((optarg = strtok(str, " \t\n")) != NULL) {
                     switch (state) {
                        case RA_READING_SRCID: {
                           int i, len = strlen(optarg);
                           for (i = 0; i < len; i++)
                              optarg[i] = tolower(optarg[i]);
                           srcid = optarg;
                           state = RA_READING_ALIAS;
                           break;
                        }

                        case RA_READING_ALIAS: {
                           convert = optarg;
                           done = 1;
                           break;
                        }
                     }
                     str = NULL;
                    
                     if (done)
                        break;
                  }

                  hash = getnamehash((const u_char *)srcid);
                  ap = &converttable[hash % (HASHNAMESIZE-1)];
                  while (ap->n_nxt)
                     ap = ap->n_nxt;
     
                  ap->hashval = hash;
                  ap->name = strdup((char *) srcid);

                  ap->type = RadiumParseSourceID(&ap->addr, convert);
                  ap->n_nxt = (struct cnamemem *)calloc(1, sizeof(*ap));
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RadiumParseSrcidConversionFile (%s) returning %d\n", file, retn);
#endif

   return (retn);
}
