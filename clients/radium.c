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
 * $Id: //depot/argus/clients/clients/radium.c#16 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
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
#include <argus_output.h>

#include <rabins.h>

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
   int pid, dflag;
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
               if (isdigit(*optarg))
                  setArgusMarReportInterval (ArgusParser, optarg);

            mode = mode->nxt;
         }
      }

      dflag = parser->dflag;
      parser->dflag = 0;

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if (parser->ArgusFlowModelFile != NULL) {
         RadiumParseResourceFile (parser, parser->ArgusFlowModelFile);
      } else {
         if (!(parser->Xflag)) {
            RadiumParseResourceFile (parser, "/etc/radium.conf");
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

      2) it will manage the listen, to deal without remote client
         requests.  radium() can write its records to a file, and
         any number of remote clients, so ......

   The ArgusClientTimeout() routine will drive all the maintenance
   and so it should be run, probably 4x a second, just for good
   measure.
*/

      parser->ArgusReliableConnection++;
      parser->RaInitialized++;

      parser->ArgusOutput = ArgusNewOutput (parser);
      ArgusInitOutput (parser->ArgusOutput);

      tvp = getArgusMarReportInterval(ArgusParser);
      if ((tvp->tv_sec == 0) && (tvp->tv_usec == 0)) {
         setArgusMarReportInterval (ArgusParser, "60s");
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


#define RADIUM_MAX_ANALYTICS	128
struct ArgusRecordStruct *(*RadiumAnalyticAlgorithmTable[RADIUM_MAX_ANALYTICS])(struct ArgusParserStruct *, struct ArgusRecordStruct *) = {
   NULL, NULL, NULL
};



void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusRecordStruct *ns;

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

            } else
               ArgusLastTime = parser->ArgusRealTime;

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
   pthread_cond_signal(&parser->ArgusOutput->ArgusOutputList->cond); 

   if (parser->ArgusOutput->ArgusOutputList->count > 10000) {
      struct timespec tsbuf = {0, 10000000}, *ts = &tsbuf;
      nanosleep (ts, NULL);
   }

#else
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
                              setArgusID (parser, optarg, ARGUS_IDIS_STRING);
 
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
                                       setArgusID (ArgusParser, &addr, ARGUS_IDIS_IPV4);
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
                                    setArgusID (parser, &addr, ARGUS_IDIS_IPV4);
                                 } else
                                    ArgusLog (LOG_ERR, "RadiumParseResourceFile(%s) host '%s' error %s\n", file, optarg, strerror(errno));
                              } else
                                 if (optarg && isdigit((int)*optarg)) {
                                    setArgusID (parser, optarg, ARGUS_IDIS_INT);
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
                              struct nff_program filter;

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

                              if (ArgusFilterCompile (&filter, parser->ArgusRemoteFilter, 0) < 0)
                                 ArgusLog (LOG_ERR, "RaParseResourceFile: remote filter syntax error");
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

                           RadiumAnalyticAlgorithmTable[0] = ArgusLabelRecord;
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
   setArgusID (ArgusParser, 0, 0);

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
