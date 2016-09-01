/*
 * Argus Software
 * Copyright (c) 2000-2012 QoSient, LLC
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
 * $Id: //depot/gargoyle/clients/examples/ratop.orig/ratop.c#1 $
 * $DateTime: 2013/03/26 15:23:14 $
 * $Change: 2563 $
 */

/*
 * ratop.c  - top program for argus data.  
 * 
*/

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#define ARGUS_RECORD_MODIFIED     0x0100

#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include <argus_compat.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <rabins.h>
#include <rasplit.h>
#include <ratop.h>

#include <signal.h>
#include <ctype.h>

#include <argus_sort.h>
#include <argus_cluster.h>

#include <glob.h>

void RaProcessRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

#if defined(ARGUS_CURSES)

char RaOutputBuffer[MAXSTRLEN];

//#define ARGUS_COLOR_SUPPORT

void * ArgusCursesProcess (void *);

#if defined(ARGUS_READLINE) || defined(ARGUS_EDITLINE)
#include <readline/readline.h>

void argus_redisplay_function(void);
int argus_readline_timeout(void);
int argus_getch_function(FILE *);
void argus_getsearch_string(int);
void argus_command_string(void);

int argus_process_command (struct ArgusParserStruct *, int);

#if defined(ARGUS_HISTORY)
#include <readline/history.h>

void argus_enable_history(void);
void argus_disable_history(void);
void argus_recall_history(void);
void argus_save_history(void);

int argus_history_is_enabled(void);
#endif

#endif

int ArgusTerminalColors = 0;
int ArgusDisplayStatus = 0;
#endif

int ArgusCursesEnabled = 1;
char *RaDatabase = NULL;
char **RaTables = NULL;

void ArgusUpdateScreen(void);

#define ARGUS_FORWARD           1
#define ARGUS_BACKWARD          2

int ArgusSearchDirection = ARGUS_FORWARD;
int ArgusAlwaysUpdate    = 0;

struct timeval RaStartTime = {0x7FFFFFFF, 0x7FFFFFFF};
struct timeval RaEndTime   = {0, 0};

#define ARGUS_REMOTE_FILTER     1
#define ARGUS_LOCAL_FILTER      2
#define ARGUS_DISPLAY_FILTER    3


#define RAMON_NETS_CLASSA       0
#define RAMON_NETS_CLASSB       1
#define RAMON_NETS_CLASSC       2
#define RAMON_NETS_CLASS        3

#define RA_DIRTYBINS            0x20

extern void ArgusInitAggregatorStructs(struct ArgusAggregatorStruct *);

void RaTopLoop (struct ArgusParserStruct *);
void RaRefreshDisplay(struct ArgusParserStruct *);
void RaOutputModifyScreen (void);
void RaOutputHelpScreen (void);
int RaSearchDisplay (struct ArgusParserStruct *, struct ArgusQueueStruct *, int, int *, int *, char *);

// struct RaBinProcessStruct *RaBinProcess = NULL;

struct RaTopProcessStruct *RaTopNewProcess(struct ArgusParserStruct *parser);


#if defined(ARGUS_THREADS)
pthread_attr_t RaTopAttr;
pthread_t RaCursesThread = 0;
#endif

#define RATOPSTARTINGINDEX       2

struct RaTopProcessStruct {
   int status, timeout; 
   int value, size;
   struct ArgusRecordStruct *ns;
   struct ArgusQueueStruct *queue, *delqueue;
   struct ArgusHashTable *htable;
   struct nff_program filter;
};

struct RaTopProcessStruct *RaTopProcess = NULL;

int ArgusWindowClosing = 0;

float RaUpdateRate = 1.0;
int RaTopRealTime = 0;
int RaCursorOffset = 0;
int RaCursorX = 0;
int RaCursorY = 0;

struct timeval ArgusLastRealTime = {0, 0};
struct timeval ArgusLastTime     = {0, 0};
struct timeval ArgusThisTime     = {0, 0};
struct timeval ArgusCurrentTime  = {0, 0};

struct timeval dLastTime = {0, 0};
struct timeval dRealTime = {0, 0};
struct timeval dThisTime = {0, 0};
struct timeval dTime     = {0, 0};

long long thisUsec = 0;
long long lastUsec = 0;

char *RaTable = NULL;

struct ArgusQueueStruct *ArgusModelerQueue;
struct ArgusQueueStruct *ArgusFileQueue;
struct ArgusQueueStruct *ArgusProbeQueue;

void RaResizeHandler (int);


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusAdjustStruct *nadp = NULL;
   struct ArgusInput *input = NULL;
   struct ArgusModeStruct *mode; 
   char outputfile[MAXSTRLEN];
   int i = 0, size = 1;
#if defined(ARGUS_CURSES) && (defined(ARGUS_READLINE) || defined(ARGUS_EDITLINE))
#if defined(ARGUS_READLINE)
   int keytimeout;
#endif

   rl_initialize();
#if defined(ARGUS_HISTORY)
   using_history();
#endif
   rl_redisplay_function = argus_redisplay_function;
   rl_getc_function = argus_getch_function;

#if defined(HAVE_DECL_RL_EVENT_HOOK) && HAVE_DECL_RL_EVENT_HOOK
   rl_event_hook = argus_readline_timeout;
#endif

#if defined(ARGUS_READLINE)
   keytimeout = RaTopUpdateInterval.tv_sec * 1000000 + RaTopUpdateInterval.tv_usec;
   keytimeout = (keytimeout == 1000000) ? keytimeout - 1 : keytimeout;
#if defined(HAVE_DECL_RL_SET_KEYBOARD_INPUT_TIMEOUT) && HAVE_DECL_RL_SET_KEYBOARD_INPUT_TIMEOUT
   rl_set_keyboard_input_timeout (keytimeout);
#endif
#endif

   rl_outstream = NULL;

#if defined(HAVE_DECL_RL_CATCH_SIGNALS) && HAVE_DECL_RL_CATCH_SIGNALS
   rl_catch_signals = 0;
   rl_catch_sigwinch = 0;
#endif
#endif

   outputfile[0] = '\0';
   parser->RaWriteOut = 1;

   if (!(parser->RaInitialized)) {
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

      if (parser->ArgusRemoteHosts)
         if ((input = (void *)parser->ArgusRemoteHosts->start) != NULL) 
            parser->RaTasksToDo = 1;

      if (parser->ArgusFlowModelFile) {
         if ((parser->ArgusAggregator = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseAggregator error");

      } else
         if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if (parser->Hstr != NULL)
         ArgusHistoMetricParse(parser, parser->ArgusAggregator);

      if ((ArgusModelerQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

      if ((ArgusProbeQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

      if ((ArgusFileQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

      if ((RaTopProcess = RaTopNewProcess(parser)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: RaTopNewProcess error");

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
                  }

                  case ARGUSSPLITTIME: /* "%d[yMwdhms] */
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
                                    size = nadp->value * 31556926;
                                    break;
                                 case 'M':
                                    nadp->qual = ARGUSSPLITMONTH; 
                                    size = nadp->value * 2629744;
                                    break;
                                 case 'w':
                                    nadp->qual = ARGUSSPLITWEEK;  
                                    size = nadp->value * 604800;
                                    break;
                                 case 'd':
                                    nadp->qual = ARGUSSPLITDAY;   
                                    size = nadp->value * 86400;
                                    break;
                                 case 'h':
                                    nadp->qual = ARGUSSPLITHOUR;  
                                    size = nadp->value * 3600;
                                    break;
                                 case 'm':
                                    nadp->qual = ARGUSSPLITMINUTE;
                                    size = nadp->value * 60;
                                    break;
                                  default:
                                    nadp->qual = ARGUSSPLITSECOND;
                                    size = nadp->value;
                                    break;
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

                     ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;
                     ArgusSorter->ArgusSortAlgorithms[1] = NULL;
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
               if (!(strncasecmp (mode->mode, "nocurses", 4))) {
                 ArgusCursesEnabled = 0;
               } else
               if (!(strncasecmp (mode->mode, "rmon", 4))) {
                  parser->RaMonMode++;
               } else
               if (!(strncasecmp (mode->mode, "nomerge", 7))) {
                  parser->RaCumulativeMerge = 0;
               } else
               if (!(strncasecmp (mode->mode, "merge", 5))) {
                  parser->RaCumulativeMerge = 1;
               } else
               if (!(strncasecmp (mode->mode, "rtime", 5)) ||
                  (!(strncasecmp (mode->mode, "realtime", 8)))) {
                  char *ptr = NULL;
                  RaTopRealTime++;
                  if ((ptr = strchr(mode->mode, ':')) != NULL) {
                     double value = 0.0;
                     char *endptr = NULL;
                     ptr++;
                     value = strtod(ptr, &endptr);
                     if (ptr != endptr) {
                        RaUpdateRate = value;
                     }
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

#if defined(ARGUS_CURSES)
      if (ArgusCursesEnabled)
         RaInitCurses(parser);
#else
      if (ArgusCursesEnabled)
         ArgusLog (LOG_ERR, "ratop not compiled with curses support.  install ncurses and rebuild.");
      
#endif
      parser->RaBinProcess->size = size;

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
         RaTopUpdateInterval.tv_sec  = 1;
         RaTopUpdateInterval.tv_usec = 0;
      } else {
         RaTopUpdateInterval.tv_sec  = 0;
         RaTopUpdateInterval.tv_usec = 453613;
      }

#ifdef ARGUS_CURSES
#if defined(ARGUS_THREADS)
      sigset_t blocked_signals;

      if ((pthread_create(&RaCursesThread, NULL, ArgusCursesProcess, NULL)) != 0)
         ArgusLog (LOG_ERR, "ArgusCursesProcess() pthread_create error %s\n", strerror(errno));
      sigfillset(&blocked_signals);
      sigdelset(&blocked_signals, SIGTERM);
      sigdelset(&blocked_signals, SIGINT);
      sigdelset(&blocked_signals, SIGTSTP);

      pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);
#endif
#endif
      RaTopLoop (parser);
   }
}


#define ARGUS_FILE_LIST_PROCESSED     0x1000

void
RaTopLoop (struct ArgusParserStruct *parser)
{
   parser->RaParseDone = 0;
   sprintf (parser->RaDebugString, "RaTopLoop() Idle.");
   ArgusParser->RaDebugStatus = 0;

   while (1) {
      if (parser->RaTasksToDo) {
         struct ArgusInput *input = NULL, *file =  NULL;
#if defined(ARGUS_THREADS)
         int hosts = 0;
#endif

         sprintf (parser->RaDebugString, "RaTopLoop() Processing.");
         ArgusParser->RaDebugStatus = 0;

         RaTopStartTime.tv_sec  = 0;
         RaTopStartTime.tv_usec = 0;
         RaTopStopTime.tv_sec   = 0;
         RaTopStopTime.tv_usec  = 0;

         if ((!(parser->status & ARGUS_FILE_LIST_PROCESSED)) && ((file = parser->ArgusInputFileList) != NULL)) {
            while (file && ArgusParser->eNflag) {
               if (strcmp (file->filename, "-")) {
                  if (file->fd < 0) {
                     if ((file->file = fopen(file->filename, "r")) == NULL) {
                        sprintf (parser->RaDebugString, "open '%s': %s", file->filename, strerror(errno));
                        ArgusParser->RaDebugStatus = 0;
                     }

                  } else {
                     fseek(file->file, 0, SEEK_SET);
                  }

                  if ((file->file != NULL) && ((ArgusReadConnection (ArgusParser, file, ARGUS_FILE)) >= 0)) {
                     ArgusParser->ArgusTotalMarRecords++;
                     ArgusParser->ArgusTotalRecords++;

                     if (ArgusParser->RaPollMode) {
                         ArgusHandleDatum (ArgusParser, file, &file->ArgusInitCon, &ArgusParser->ArgusFilterCode);
                     } else {
                        if (file->ostart != -1) {
                           file->offset = file->ostart;
                           if (fseek(file->file, file->offset, SEEK_SET) >= 0)
                              ArgusReadFileStream(ArgusParser, file);
                        } else
                           ArgusReadFileStream(ArgusParser, file);
                     }

                     sprintf (parser->RaDebugString, "RaTopLoop() Processing Input File %s done.", file->filename);
                     ArgusParser->RaDebugStatus = 0;

                  } else {
                     file->fd = -1;
                     sprintf (parser->RaDebugString, "ArgusReadConnection '%s': %s", file->filename, strerror(errno));
                     ArgusParser->RaDebugStatus = LOG_ERR;
                  }

                  if (file->file != NULL)
                     ArgusCloseInput(ArgusParser, file);

               } else {
                  file->file = stdin;
                  file->ostart = -1;
                  file->ostop = -1;

                  if (((ArgusReadConnection (ArgusParser, file, ARGUS_FILE)) >= 0)) {
                     ArgusParser->ArgusTotalMarRecords++;
                     ArgusParser->ArgusTotalRecords++;
                     fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);
                     ArgusReadFileStream(ArgusParser, file);
                  }
               }

               RaArgusInputComplete(file);
               file = (struct ArgusInput *)file->qhdr.nxt;
            }

            parser->status |= ARGUS_FILE_LIST_PROCESSED;
         }

         if (ArgusParser->Sflag) {
            if (ArgusParser->ArgusRemoteHosts && (ArgusParser->ArgusRemoteHosts->count > 0)) {
               struct ArgusQueueStruct *tqueue = ArgusNewQueue();
               int flags;

#if defined(ARGUS_THREADS)
               if (ArgusParser->ArgusReliableConnection) {
                  if (ArgusParser->ArgusRemoteHosts && (hosts = ArgusParser->ArgusRemoteHosts->count)) {
                     if ((pthread_create(&ArgusParser->remote, NULL, ArgusConnectRemotes, ArgusParser->ArgusRemoteHosts)) != 0)
                        ArgusLog (LOG_ERR, "ArgusNewOutput() pthread_create error %s\n", strerror(errno));
                  }

               } else {
#else
               {
#endif
                  while ((input = (void *)ArgusPopQueue(ArgusParser->ArgusRemoteHosts, ARGUS_LOCK)) != NULL) {
                     if ((input->fd = ArgusGetServerSocket (input, 5)) >= 0) {
                        if ((ArgusReadConnection (ArgusParser, input, ARGUS_SOCKET)) >= 0) {
                           ArgusParser->ArgusTotalMarRecords++;
                           ArgusParser->ArgusTotalRecords++;

                           if ((flags = fcntl(input->fd, F_GETFL, 0L)) < 0)
                              ArgusLog (LOG_ERR, "ArgusConnectRemote: fcntl error %s", strerror(errno));

                           if (fcntl(input->fd, F_SETFL, flags | O_NONBLOCK) < 0)
                              ArgusLog (LOG_ERR, "ArgusConnectRemote: fcntl error %s", strerror(errno));

                           if (ArgusParser->RaPollMode)
                              ArgusHandleDatum (ArgusParser, input, &input->ArgusInitCon, &ArgusParser->ArgusFilterCode);

                           ArgusAddToQueue(ArgusParser->ArgusActiveHosts, &input->qhdr, ARGUS_LOCK);
                           ArgusParser->RaTasksToDo++;
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
                  ArgusAddToQueue(ArgusParser->ArgusRemoteHosts, &input->qhdr, ARGUS_LOCK);

               ArgusDeleteQueue(tqueue);
            }

         } else {
#if defined(ARGUS_THREADS)
            ArgusParser->RaDonePending++;
            pthread_cond_signal(&ArgusParser->ArgusOutputList->cond);
#else
            ArgusParser->RaParseDone++;
#endif
         }

         if (ArgusParser->ArgusReliableConnection || ArgusParser->ArgusActiveHosts)
            if (ArgusParser->ArgusActiveHosts->count)
               ArgusReadStream(ArgusParser, ArgusParser->ArgusActiveHosts);

         parser->RaTasksToDo = 0;

      } else {
         struct timespec ts = {0, 25000000};
         gettimeofday (&ArgusCurrentTime, 0L);
         nanosleep (&ts, NULL);

         if (ArgusParser->ArgusActiveHosts && ArgusParser->ArgusActiveHosts->count)
            parser->RaTasksToDo = 1;
      }

      ArgusClientTimeout ();
   }
}

void RaArgusInputComplete (struct ArgusInput *input) {
   ArgusUpdateScreen();
#if !defined(ARGUS_THREADS)
   RaRefreshDisplay(ArgusParser);
#endif
}

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (sig == SIGINT) {
         ArgusShutDown(0);
         exit(0);
      }
   }
}

#if defined(ARGUS_CURSES)
void
RaResizeHandler (int sig)
{
   RaScreenResize = TRUE;

#ifdef ARGUSDEBUG 
   ArgusDebug (1, "RaResizeHandler(%d)\n", sig);
#endif
}
#endif


char *ArgusGenerateProgramArgs(struct ArgusParserStruct *);
char RaProgramArgs[MAXSTRLEN];

char *
ArgusGenerateProgramArgs(struct ArgusParserStruct *parser)
{
   char *retn = RaProgramArgs;
   struct ArgusModeStruct *mode = NULL;
   struct ArgusInput *input = NULL;
   
   sprintf (retn, "%s ", parser->ArgusProgramName);

   if (parser->ArgusActiveHosts) {
      if (parser->Sflag) {
         sprintf (&retn[strlen(retn)], "-S ");
         if ((input = (void *)parser->ArgusActiveHosts->start) != NULL) {
            do {
                  sprintf (&retn[strlen(retn)], "%s:%d ", input->hostname, input->portnum);
               input = (void *)input->qhdr.nxt;
            } while (input != (void *)parser->ArgusActiveHosts->start);
         }
      } else {
         sprintf (&retn[strlen(retn)], "-r ");
         if ((input = (void *)parser->ArgusInputFileList) != NULL) {
            while (input != NULL) {
               sprintf (&retn[strlen(retn)], "%s ", input->filename);
               input = (void *)input->qhdr.nxt;
            }
         }
      }


   } else {
      if (RaDatabase && RaTable) {
         sprintf (&retn[strlen(retn)], "-P %s:%s ", RaDatabase, RaTable);
      }
   }

   if ((mode = parser->ArgusModeList) != NULL) { 
      sprintf (&retn[strlen(retn)], "-M ");
      while (mode) { 
         sprintf (&retn[strlen(retn)], "%s ", mode->mode);
         mode = mode->nxt;
      }
   }

   if (((mode = parser->ArgusMaskList) != NULL) || (parser->ArgusAggregator->mask == 0)) {
      sprintf (&retn[strlen(retn)], "-m ");
      while (mode) {
         sprintf (&retn[strlen(retn)], "%s ", mode->mode);
         mode = mode->nxt;
      }
   }

   if (parser->Hstr)
      sprintf (&retn[strlen(retn)], "-H %s ", parser->Hstr);

   if ((parser->ArgusDisplayFilter) || parser->ArgusLocalFilter || parser->ArgusRemoteFilter) {
      sprintf (&retn[strlen(retn)], "- ");
      if (parser->ArgusDisplayFilter)
         sprintf (&retn[strlen(retn)], "display '%s' ", parser->ArgusDisplayFilter);
      if (parser->ArgusLocalFilter)
         sprintf (&retn[strlen(retn)], "local '%s' ", parser->ArgusLocalFilter);
      if (parser->ArgusRemoteFilter) 
         sprintf (&retn[strlen(retn)], "remote '%s' ", parser->ArgusRemoteFilter);
   }
   return (retn);
}


void RaTopSortQueue (struct ArgusSorterStruct *, struct ArgusQueueStruct *, int);
int RaSortItems = 0;
 
void
RaTopSortQueue (struct ArgusSorterStruct *sorter, struct ArgusQueueStruct *queue, int type)
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
         qsort ((char *) queue->array, x, sizeof (struct ArgusQueueHeader *), ArgusSortRoutine);

         for (i = 0; i < x; i++) {
            struct ArgusRecordStruct *ns = (struct ArgusRecordStruct *) queue->array[i];
            if (ns->rank != (i + 1)) {
               ns->rank = i + 1;
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


#if defined(ARGUS_CURSES)
void RaUpdateWindow (struct ArgusParserStruct *, WINDOW *, struct ArgusQueueStruct *);

void
RaUpdateWindow (struct ArgusParserStruct *parser, WINDOW *window, struct ArgusQueueStruct *queue)
#else
void RaUpdateWindow (struct ArgusParserStruct *, struct ArgusQueueStruct *);

void
RaUpdateWindow (struct ArgusParserStruct *parser, struct ArgusQueueStruct *queue)
#endif
{
#if defined(ARGUS_CURSES)
   struct ArgusRecordStruct *ns = NULL;
   char tbuf[MAXSTRLEN];
   int x, cnt;
#endif
   int i;

   if ((RaWindowModified == RA_MODIFIED) || ArgusAlwaysUpdate) {
      parser->RaLabel = NULL;
      if (RaWindowStatus) {
#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&queue->lock);
#endif
         if (queue->count) {
            RaTopSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);

            if (RaSortItems) {
               if (queue == RaTopProcess->queue) {
                  if (ArgusParser->ns) {
                     ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                     ArgusParser->ns = NULL;
                  }
                  for (i = 0; i < queue->count; i++) {
                     struct ArgusRecordStruct *ns;
                     if ((ns = (struct ArgusRecordStruct *)queue->array[i]) == NULL)
                        break;
                     if (ArgusParser->ns)
                        ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
                     else
                        ArgusParser->ns = ArgusCopyRecordStruct (ns);
                  }
               }
            }
         }

#ifdef ARGUS_CURSES
         wclear(RaAvailableWindow);

         if (queue->array != NULL) {
            if (parser->ns != NULL) {
               if (parser->RaLabel == NULL)
                  parser->RaLabel = ArgusGenerateLabel(parser, parser->ns);
               snprintf (tbuf, RaScreenColumns, "%s", parser->RaLabel);
               mvwaddnstr (window, 0, 0, tbuf, RaScreenColumns);
               wclrtoeol(window);
            }

            if (queue->count < RaWindowStartLine) {
               RaWindowStartLine = queue->count - RaDisplayLines;
               RaWindowStartLine = (RaWindowStartLine > 0) ? RaWindowStartLine : 0;
            }

            cnt = ((RaDisplayLines > 0) ? RaDisplayLines : RaWindowLines);
            cnt = (cnt > (queue->count - RaWindowStartLine)) ? (queue->count - RaWindowStartLine) : cnt;

            for (x = 0, i = RaWindowStartLine; x < cnt; x++, i++) {
#if defined(ARGUS_COLOR_SUPPORT)
               int attrs = 0;
#endif
               if ((ns = (struct ArgusRecordStruct *) queue->array[i]) != NULL) {
                  if (parser->Aflag) {
                     ArgusProcessServiceAvailability(parser, ns);
#if defined(ARGUS_COLOR_SUPPORT)
                     if (ArgusTerminalColors) {
                        if (ns->status & RA_SVCFAILED) {
                           attrs = (COLOR_PAIR(3));
                        } else
                           attrs = COLOR_PAIR(1);
                     }
#endif
                  }

                  if (ArgusAlwaysUpdate || (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != (i + 1)))) {
                     char buf[MAXSTRLEN];
                     buf[0] = '\0';

                     if (ns->disp.str != NULL)
                        free(ns->disp.str);

                     ns->rank =  i + 1;
                     ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                     ns->disp.str = strdup(buf);
                     ns->status &= ~ARGUS_RECORD_MODIFIED;
                  }
                  snprintf (tbuf, RaScreenColumns, "%s", ns->disp.str);
                  wmove(window, x + 1, 0);

#if defined(ARGUS_COLOR_SUPPORT)
                  wattron(window, attrs);
#endif
                  wprintw (window, "%s", tbuf);
#if defined(ARGUS_COLOR_SUPPORT)
                  wattroff(window, attrs);
#endif
                  wclrtoeol(window);
               } else
                  break;
            }

         } else {
            mvwaddstr (window, 1, 0, " ");
            wclrtoeol(window);
         }

         wclrtobot(window);
#endif

#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&queue->lock);
#endif
      }
#if defined(ARGUS_CURSES)
      wnoutrefresh(window);
#endif
   }
   RaWindowModified  = 0;
   RaWindowImmediate = FALSE;
}

int ArgusSourceConnected = 0;

void
RaRefreshDisplay(struct ArgusParserStruct *parser)
{
   struct timeval tvp;
#if defined(ARGUS_CURSES)
   char stimebuf[128], tbuf[MAXSTRLEN];
   char strbuf[128];  
   struct tm *tm, tmbuf;
   float secs, rate;
#endif

   tvp = parser->ArgusRealTime;

   if (RaTopUpdateTime.tv_sec == 0)
      RaTopUpdateTime = tvp;
   
   if (RaWindowImmediate ||
      ((RaTopUpdateTime.tv_sec < tvp.tv_sec) ||
      ((RaTopUpdateTime.tv_sec == tvp.tv_sec) &&
       (RaTopUpdateTime.tv_usec <= tvp.tv_usec)))) {

#if defined(ARGUS_CURSES)
      RaUpdateWindow(parser, RaAvailableWindow, RaTopProcess->queue);
#endif
      RaTopUpdateTime = tvp;

      RaTopUpdateTime.tv_sec  += RaTopUpdateInterval.tv_sec;
      RaTopUpdateTime.tv_usec += RaTopUpdateInterval.tv_usec;

      if (RaTopUpdateTime.tv_usec >= 1000000) {
         RaTopUpdateTime.tv_sec  += 1;
         RaTopUpdateTime.tv_usec -= 1000000;
      }

#if defined(ARGUS_CURSES)
      RaWindowImmediate = FALSE;

      if (parser->ArgusRealTime.tv_sec > 0) {
         time_t tsec =  parser->ArgusRealTime.tv_sec;
         tm = localtime_r(&tsec, &tmbuf);
         strftime ((char *) stimebuf, 32, "%Y/%m/%d.%T", tm);
         sprintf ((char *)&stimebuf[strlen(stimebuf)], " ");
         strftime(&stimebuf[strlen(stimebuf)], 32, "%Z ", tm);

      } else 
         sprintf (stimebuf, " ");

      mvwaddnstr (RaHeaderWindow, 0, 0, ArgusGenerateProgramArgs(ArgusParser), RaScreenColumns - 5);
      wclrtoeol(RaHeaderWindow);
      mvwaddnstr (RaHeaderWindow, 0, RaScreenColumns - strlen(stimebuf) , stimebuf, strlen(stimebuf));

      if (ArgusPrintTotals) {
         struct ArgusRecordStruct *ns = NULL;
         if ((ns = parser->ns) != NULL) {
            if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != RaTopProcess->queue->count)) {
               char buf[MAXSTRLEN];

               if (ns->disp.str != NULL)
                  free(ns->disp.str);

               buf[0] = '\0';
               if (ns != NULL) {
                  ns->rank = RaTopProcess->queue->count;
                  ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                  ns->disp.str = strdup(buf);
                  ns->status &= ~ARGUS_RECORD_MODIFIED;
               }
            }
            snprintf (tbuf, RaScreenColumns, "%s", ns->disp.str);
         } else
            sprintf (tbuf, " ");

         mvwaddnstr (RaHeaderWindow, 1, 0, tbuf, RaScreenColumns);
         wclrtoeol(RaHeaderWindow);
      }

      if (ArgusDisplayStatus && (ArgusParser->debugflag == 0)) {
         struct timeval dtime;

         dtime.tv_sec   = RaTopStopTime.tv_sec  - RaTopStartTime.tv_sec;
         dtime.tv_usec  = RaTopStopTime.tv_usec - RaTopStartTime.tv_usec;

         if (dtime.tv_usec < 0) {
            dtime.tv_sec--;
            dtime.tv_usec += 1000000;
         }

         secs = (dtime.tv_sec * 1.0) + ((dtime.tv_usec * 1.0)/1000000.0);
         rate = (parser->ArgusTotalRecords * 1.0); 

         sprintf (tbuf, "ProcessQueue %6d DisplayQueue %6d TotalRecords %8lld  Rate %11.4f rps",
                             RaTopProcess->queue->count, RaSortItems,
                             parser->ArgusTotalRecords, rate/secs);

         sprintf (parser->RaDebugString, "%s", tbuf);
         ArgusParser->RaDebugStatus = 0;
      }
#endif
   }

#if defined(ARGUS_CURSES)
   if (RaWindowStatus) {
      wnoutrefresh(RaWindow);
      wnoutrefresh(RaHeaderWindow);

      wclrtoeol(RaAvailableWindow);
      wnoutrefresh(RaAvailableWindow);
   }

   if (RaCursorWindow == NULL)
      RaCursorWindow = RaHeaderWindow;

   switch (RaInputStatus) {
      case RAGETTINGcolon:
      case RAGETTINGslash:
         wmove(RaWindow, RaScreenLines - 1, RaCommandIndex + 1);
         break;

      default: {
         int len = strlen(RaInputString);
#if defined(ARGUS_COLOR_SUPPORT)
         int attrs = 0;
#endif
         if (len > 0)
            wmove(RaWindow, RaScreenLines - 1, (RaCommandIndex - RaCursorOffset) + len);
         break;
      }

      case RAGOTslash:
      case RAGOTcolon: {
#if defined(ARGUS_COLOR_SUPPORT)
         int attrs = 0;

         if (ArgusTerminalColors) {
            if (parser->RaDebugStatus == LOG_ERR)
               attrs = COLOR_PAIR(3);
            else
               attrs = COLOR_PAIR(1) | A_BOLD;
         }
         wattron(RaWindow, attrs);
#endif
         wmove(RaWindow, RaScreenLines - 1, 0);

         sprintf (strbuf, "%s", parser->RaDebugString);
         wprintw (RaWindow, "%s", strbuf);
 
#if defined(ARGUS_COLOR_SUPPORT)
         wattroff(RaWindow, attrs);
#endif
         wclrtoeol(RaWindow);
         if (RaWindowCursorY > 0) {
            int offset = (RaWindowCursorY % (RaDisplayLines + 1));
            if (offset > (RaSortItems - RaWindowStartLine)) {
               RaWindowCursorY = (RaSortItems - RaWindowStartLine);
               offset = (RaSortItems - RaWindowStartLine);
            }
            offset += RaHeaderWinSize;
            wmove (RaWindow, offset, RaWindowCursorX);
         }
         break;
      }
   }
   wrefresh(RaWindow);   /* Linux needs this */
#endif
}

#if defined(ARGUS_CURSES)

int RaHighlightDisplay (struct ArgusParserStruct *, struct ArgusQueueStruct *, char *);

int
RaHighlightDisplay (struct ArgusParserStruct *parser, struct ArgusQueueStruct *queue, char *pattern)
{
   int retn = -1, x = 0, cursy = 1;
   struct ArgusRecordStruct *ns = NULL;
   regex_t pregbuf, *preg = &pregbuf;
   regmatch_t pm[1];

   if (regcomp(preg, pattern, REG_EXTENDED | REG_NEWLINE)) {
      sprintf (ArgusParser->RaDebugString, "RaSearchDisplay bad regular expression %s", pattern);
      ArgusParser->RaDebugStatus = LOG_ERR;
      return retn;
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&queue->lock);
#endif
   if (queue->array != NULL) {
      char buf[MAXSTRLEN];

      for (x = RaWindowStartLine; x < (RaWindowStartLine + RaDisplayLines); x++) {
         cursy++;
         if ((ns = (struct ArgusRecordStruct *) queue->array[x]) != NULL) {
            bcopy(ns->disp.str, buf, strlen(ns->disp.str) + 1);

            if ((retn = regexec(preg, buf, 1, pm, 0)) == 0) {
               int cursx = pm[0].rm_so + 1;
               wmove (RaWindow, cursy, cursx);
               wchgat(RaWindow, pm[0].rm_eo - pm[0].rm_so, A_REVERSE, 0, NULL);
            }
         }
      }
   }
#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&queue->lock);
#endif
   regfree(preg);
   return (retn);
}

int
RaSearchDisplay (struct ArgusParserStruct *parser, struct ArgusQueueStruct *queue, 
                                 int dir, int *cursx, int *cursy, char *pattern)
{
   int retn = -1, x = 0, startline = *cursy;
   regmatch_t pm[1];
   struct ArgusRecordStruct *ns = NULL;
   regex_t pregbuf, *preg = &pregbuf;
   char buf[MAXSTRLEN], *ptr;

   if (regcomp(preg, pattern, REG_EXTENDED | REG_NEWLINE)) {
      sprintf (ArgusParser->RaDebugString, "RaSearchDisplay bad regular expression %s", pattern);
      ArgusParser->RaDebugStatus = LOG_ERR;
      return retn;
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&queue->lock);
#endif
   if (queue->array != NULL) {
      if (startline == 0) {
         *cursy = 1; startline = 1;
      }
  
      startline = (startline == 0) ? 1 : startline;
      if (queue->count >= startline) {
         if ((ns = (struct ArgusRecordStruct *) queue->array[startline - 1]) != NULL) {
            int offset = *cursx, found = 0;

            if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != startline)) {
               char buf[MAXSTRLEN];

               if (ns->disp.str != NULL)
                  free(ns->disp.str);

               buf[0] = '\0';
               ns->rank = startline;
               ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
               ns->disp.str = strdup(buf);
               ns->status &= ~ARGUS_RECORD_MODIFIED;
            }

            bcopy(ns->disp.str, buf, strlen(ns->disp.str) + 1);

            switch (dir) {
               case ARGUS_FORWARD:
                  if (regexec(preg, &buf[offset], 1, pm, 0) == 0) {
                     if (pm[0].rm_so == 0) {
                        if (regexec(preg, &buf[offset + 1], 1, pm, 0) == 0) {
                           offset += pm[0].rm_so + 1;
                           found++;
                        }
                     } else {
                        offset += pm[0].rm_so;
                        found++;
                     }
                     if (found) {
                        retn = *cursy;
                        *cursx = offset;
#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&queue->lock);
#endif
                        return (retn);
                     }
                  }
                  break;

               case ARGUS_BACKWARD: {
                  char *lastmatch = NULL;
                  buf[offset] = '\0';
                  ptr = buf;
                  while ((ptr = strstr(ptr, pattern)) != NULL)
                     lastmatch = ptr++;

                  if (lastmatch) {
                     retn = *cursy;
                     *cursx = (lastmatch - buf);
#if defined(ARGUS_THREADS)
                     pthread_mutex_unlock(&queue->lock);
#endif
                     return (retn);
                  }
                  break;
               }
            }
         }

         switch (dir) {
            case ARGUS_FORWARD:
               for (x = startline; x < queue->count; x++) {
                  if ((ns = (struct ArgusRecordStruct *) queue->array[x]) != NULL) {

                     if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != (x + 1))) {
                        char buf[MAXSTRLEN];

                        if (ns->disp.str != NULL)
                           free(ns->disp.str);

                        buf[0] = '\0';
                        ns->rank = (x + 1);
                        ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                        ns->disp.str = strdup(buf);
                        ns->status &= ~ARGUS_RECORD_MODIFIED;
                     }

                     bcopy(ns->disp.str, buf, strlen(ns->disp.str) + 1);
      
                     if ((retn = regexec(preg, buf, 1, pm, 0)) == 0) {
                        retn = x + 1;
                        *cursx = pm[0].rm_so;
                        *cursy = retn;
#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&queue->lock);
#endif
                        return (retn);
                        break;
                     }
                  }
               }
               break;

            case ARGUS_BACKWARD: {
               for (x = (startline - 2); x >= 0; x--) {
                  if ((ns = (struct ArgusRecordStruct *) queue->array[x]) != NULL) {
                     char *lastmatch = NULL;

                     if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != (x + 1))) {
                        char buf[MAXSTRLEN];

                        if (ns->disp.str != NULL)
                           free(ns->disp.str);

                        buf[0] = '\0';
                        ns->rank = x + 1;
                        ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                        ns->disp.str = strdup(buf);
                        ns->status &= ~ARGUS_RECORD_MODIFIED;
                     }

                     bcopy(ns->disp.str, buf, strlen(ns->disp.str) + 1);

                     ptr = buf;
                     while ((ptr = strstr(ptr, pattern)) != NULL)
                        lastmatch = ptr++;

                     if (lastmatch) {
                        retn = x + 1;
                        *cursx = (lastmatch - buf);
                        *cursy = retn;
#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&queue->lock);
#endif
                        return (retn);
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

   regfree(preg);
   return (-1);
}
#endif

int ArgusProcessQueue (struct ArgusQueueStruct *);
int ArgusProcessBins (struct ArgusRecordStruct *, struct RaBinProcessStruct *);
struct RaBinProcessStruct *ArgusNewRateBins (struct ArgusParserStruct *, struct ArgusRecordStruct *);


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
   int rtime = (((ArgusParser->ArgusGlobalTime.tv_sec/rbps->size)) * rbps->size);

   if ((rbps->startpt.tv_sec + dtime) < rtime) {
      ArgusShiftArray(ArgusParser, rbps);
      ArgusUpdateScreen();

      rbps->status |= RA_DIRTYBINS;
      retn = 1;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessBins (0x%x, 0x%x) returning %d", ns, rbps, retn); 
#endif

   return (retn);
}


int
ArgusProcessQueue (struct ArgusQueueStruct *queue)
{
   struct timeval tbuf, *tvp = &tbuf;
   int retn = 0, x, z;

   if ((ArgusParser->timeout.tv_sec > 0) || (ArgusParser->timeout.tv_usec > 0)) {
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

      if (deleted)
         RaTopSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock);
#endif
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (5, "ArgusProcessQueue (0x%x) returning %d", queue, retn); 
#endif

   return (retn);
}


extern void ArgusCloseInput(struct ArgusParserStruct *parser, struct ArgusInput *);
struct timeval RaProcessQueueTimer = {0, 250000};
void RaResizeScreen(void);

void
ArgusClientTimeout ()
{
   struct ArgusQueueStruct *queue = RaTopProcess->queue;
   struct timeval tvbuf, *tvp = &tvbuf;

   gettimeofday(&ArgusParser->ArgusRealTime, 0);
   ArgusAdjustGlobalTime (ArgusParser, &ArgusParser->ArgusRealTime);
   *tvp = ArgusParser->ArgusGlobalTime;

   if (ArgusParser->RaClientUpdate.tv_sec != 0) {
      if (((ArgusParser->RaClientUpdate.tv_sec < tvp->tv_sec) ||
          ((ArgusParser->RaClientUpdate.tv_sec == tvp->tv_sec) &&
           (ArgusParser->RaClientUpdate.tv_usec < tvp->tv_usec)))) {

         ArgusProcessQueue(queue);

         ArgusParser->RaClientUpdate.tv_sec  += RaProcessQueueTimer.tv_sec;
         ArgusParser->RaClientUpdate.tv_usec += RaProcessQueueTimer.tv_usec;

         while (ArgusParser->RaClientUpdate.tv_usec > 1000000) {
            ArgusParser->RaClientUpdate.tv_sec++;
            ArgusParser->RaClientUpdate.tv_usec -= 1000000;
         }
      }

#if defined(ARGUS_THREADS)
#else
#if defined(ARGUS_CURSES)
      ArgusCursesProcess(NULL);
#endif
#endif

   } else
      ArgusParser->RaClientUpdate.tv_sec = ArgusParser->ArgusGlobalTime.tv_sec;

#if defined(ARGUSDEBUG)
   ArgusDebug (12, "ArgusClientTimeout () returning\n"); 
#endif
}

void
ArgusUpdateScreen(void)
{
   struct ArgusQueueStruct *queue = RaTopProcess->queue;
   RaWindowModified  = RA_MODIFIED;
   RaWindowImmediate = TRUE;

   if (queue == RaTopProcess->queue) {
      int i;
      if (ArgusParser->ns) {
         ArgusParser->ns->status |= ARGUS_RECORD_MODIFIED;
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&queue->lock);
#endif

      if (queue->array) {
         for (i = 0; i < queue->count; i++) {
            struct ArgusRecordStruct *ns;
            if ((ns = (struct ArgusRecordStruct *)queue->array[i]) == NULL)
               break;
            ns->status |= ARGUS_RECORD_MODIFIED;
         }
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock);
#endif
   }
}

char RaLastSearchBuf[MAXSTRLEN], *RaLastSearch = RaLastSearchBuf;
char RaLastCommandBuf[MAXSTRLEN], *RaLastCommand = RaLastCommandBuf;
int RaIter = 1, RaDigitPtr = 0;
char RaDigitBuffer[16];

int ArgusProcessCommand (struct ArgusParserStruct *, int, int);

#if defined(ARGUS_CURSES)

void *
ArgusCursesProcess (void *arg)
{
   struct ArgusQueueStruct *queue = RaTopProcess->queue;
   struct timeval tvbuf, *tvp = &tvbuf;
   int i = 0, ch;
   fd_set in;
#if defined(ARGUS_THREADS)
   sigset_t blocked_signals;
   int done = 0;
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusCursesProcess() starting");
#endif
   bzero(RaDigitBuffer, sizeof(RaDigitBuffer));
   bzero(RaLastSearchBuf, sizeof(RaLastSearchBuf));

#if defined(ARGUS_THREADS)
   sigfillset(&blocked_signals);
   sigdelset(&blocked_signals, SIGWINCH);

   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

   (void) signal (SIGWINCH,(void (*)(int)) RaResizeHandler);

   while (!done) {
#endif
      if ((RaScreenResize == TRUE) || ((RaScreenLines != RaScreenLines) || (RaScreenColumns != RaScreenColumns))) {
         RaResizeScreen();
         ArgusUpdateScreen();

#if defined(ARGUS_READLINE)
         rl_set_screen_size(RaScreenLines - 1, RaScreenColumns);
#endif
      }

      if (ArgusAlwaysUpdate || (RaWindowModified == RA_MODIFIED)) {
#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&queue->lock);
#endif
         RaTopSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);
         if (RaSortItems) {
            if (ArgusParser->ns) {
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->ns = NULL;
            }
            for (i = 0; i < queue->count; i++) {
               struct ArgusRecordStruct *ns;
               if ((ns = (struct ArgusRecordStruct *)queue->array[i]) == NULL)
                  break;
               if (ArgusParser->ns) 
                  ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
               else
                  ArgusParser->ns = ArgusCopyRecordStruct (ns);
            }
         }
#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&queue->lock);
#endif
      }

      if (!(ArgusParser->RaTasksToDo)) {
         gettimeofday(&ArgusLastTime, 0);
         ArgusLastTime.tv_usec = 0;

      } else {
         if (ArgusCurrentTime.tv_sec != 0) {
            long long tUsec = 0;
            gettimeofday(&ArgusParser->ArgusRealTime, 0);

            if (ArgusLastRealTime.tv_sec > 0) {
               struct timeval dTime;

               RaDiffTime(&ArgusParser->ArgusRealTime, &ArgusLastRealTime, &dTime);
               tUsec = ((dTime.tv_sec * 1000000) + dTime.tv_usec) * RaUpdateRate;
               dTime.tv_sec  = tUsec / 1000000;
               dTime.tv_usec = tUsec % 1000000;

               ArgusCurrentTime.tv_sec  = ArgusLastTime.tv_sec  + dTime.tv_sec;
               ArgusCurrentTime.tv_usec = ArgusLastTime.tv_usec + dTime.tv_usec;

               if (ArgusCurrentTime.tv_usec > 1000000) {
                  ArgusCurrentTime.tv_sec++;
                  ArgusCurrentTime.tv_usec -= 1000000;
               }
            }
         }
      }

      tvp->tv_sec = 0; tvp->tv_usec = 75000;
      FD_ZERO(&in); FD_SET(0, &in);

      while (!ArgusWindowClosing && (select(1, &in, 0, 0, tvp) > 0)) {
         if ((ch = wgetch(RaWindow)) != ERR) {
            ArgusUpdateScreen();
            RaInputStatus = ArgusProcessCommand(ArgusParser, RaInputStatus, ch);
         }
      }

      switch (RaInputStatus) {
         default:
         case RAGOTslash:
         case RAGETTINGslash:
         case RAGETTINGcolon: {
            sprintf (RaOutputBuffer, "%s%s%s", RaInputString, RaCommandInputStr, RaCommandError);
            mvwaddnstr (RaWindow, RaScreenLines - 1, 0, RaOutputBuffer, RaScreenColumns);
            wclrtoeol(RaWindow);
            break;
         }

 
         case RANEWCOMMAND: 
         case RAGOTcolon: {
            wmove (RaWindow, RaScreenLines - 1, 0);
            break;
         }
      }
 
      getyx(RaHeaderWindow,RaCursorY,RaCursorX);
      wclrtoeol(RaHeaderWindow);

      if (RaCursesInit)
         if (ArgusParser)
            RaRefreshDisplay(ArgusParser);

#if defined(ARGUS_THREADS)
   }
#endif
 
   return (NULL);
}


int
ArgusProcessCommand (struct ArgusParserStruct *parser, int status, int ch)
{
   int retn = status, x;

   if (status == RAGETTINGh) {
      RaWindowStatus = 1;
      wclear(RaWindow);

      RaInputString = RANEWCOMMANDSTR;
      bzero(RaCommandInputStr, MAXSTRLEN);
      RaCommandIndex = 0;
      RaCursorOffset = 0;
      RaWindowCursorY = 0;
      RaWindowCursorX = 0;
      mvwaddnstr (RaWindow, RaScreenLines - 1, 0, " ", RaScreenColumns);
      wclrtoeol(RaWindow);

      ArgusUpdateScreen();
      RaRefreshDisplay(ArgusParser);
      return (RAGOTslash);
   }

   if ((ch == '\n') || (ch == '\r')) {
      bzero (ArgusParser->RaDebugString, sizeof(ArgusParser->RaDebugString));
      ArgusParser->RaDebugStatus = 0;

      RaCursorOffset = 0;
      RaCommandInputStr[RaCommandIndex] = '\0';
      switch (retn) {
         case RAGETTINGN: {
            char *ptr = NULL;
            int value = strtol(RaCommandInputStr, (char **)&ptr, 10);

            if (ptr != RaCommandInputStr) {
               RaDisplayLines = ((value < (RaScreenLines - (RaHeaderWinSize + 1)) - 1) ?
                                  value : (RaScreenLines - (RaHeaderWinSize + 1)) - 1);
               ArgusUpdateScreen();
            }
      
            break;
         }

         case RAGETTINGS: {
            if (!(ArgusAddHostList (ArgusParser, RaCommandInputStr, (ArgusParser->Cflag ? ARGUS_CISCO_DATA_SOURCE : ARGUS_DATA_SOURCE), 0))) {
               ArgusLog (LOG_ALERT, "%s%s host not found", RaInputString, RaCommandInputStr);
            } else {
               ArgusDeleteHostList(ArgusParser);
               ArgusAddHostList (ArgusParser, RaCommandInputStr, (ArgusParser->Cflag ? ARGUS_CISCO_DATA_SOURCE : ARGUS_DATA_SOURCE), 0);
               ArgusParser->Sflag = 1;
               ArgusParser->RaParseDone = 0;
            }
            break;
         }

         case RAGETTINGa: {
            if (!(strncasecmp(RaCommandInputStr, "Totals", 6))) {
               RaScreenResize = TRUE;
               if (ArgusPrintTotals == 0) {
                  ArgusPrintTotals = 1;
                  RaHeaderWinSize++;
                  RaScreenMove = TRUE;
               }
               ArgusUpdateScreen();
            }
            if (!(strncasecmp(RaCommandInputStr, "-Totals", 6))) {
               RaScreenResize = TRUE;
               if (ArgusPrintTotals > 0) {
                  ArgusPrintTotals = 0;
                  RaHeaderWinSize--;
                  RaScreenMove = FALSE;
                  getbegyx(RaAvailableWindow, RaScreenStartY, RaScreenStartX);
                  if (mvwin(RaAvailableWindow, RaScreenStartY - 1, RaScreenStartX) == ERR)
                     ArgusLog (LOG_ERR, "RaResizeScreen: mvwin %d, %d returned ERR\n", RaScreenStartY - 1, RaScreenStartX);
               }
               ArgusUpdateScreen();
            }
         }
         break;

         case RAGETTINGd: {
            struct ArgusInput *input;
            char strbuf[MAXSTRLEN];

            if ((input = (void *)ArgusParser->ArgusActiveHosts->start) != NULL) {
               do {
                  sprintf (strbuf, " %s:%d", input->hostname, input->portnum);
                  if ((strstr (RaCommandInputStr, strbuf))) {
                     ArgusRemoveFromQueue (ArgusParser->ArgusActiveHosts, &input->qhdr, ARGUS_LOCK);
                     ArgusCloseInput(ArgusParser, input);
                     break;
                  }
                  input = (void *)input->qhdr.nxt;
               } while (input != (void *)ArgusParser->ArgusActiveHosts->start);
            }
         }
         break;

         case RAGETTINGD: {
            char *ptr = NULL;
            int value = strtol(RaCommandInputStr, (char **)&ptr, 10);

            if (ptr != RaCommandInputStr)
               ArgusParser->debugflag = value;
            break;
         }

         case RAGETTINGc: {
            break;
         }

         case RAGETTINGe: {
            char *ptr = NULL;

            ptr = RaCommandInputStr;
            while (isspace((int)*ptr)) ptr++;
            if (ArgusParser->estr != NULL)
               free(ArgusParser->estr);
            ArgusParser->estr = strdup(RaCommandInputStr);
            break;
         }

         case RAGETTINGf: {
            struct nff_program lfilter;
            char *ptr = NULL, *str = NULL;
            int ind = ARGUS_REMOTE_FILTER;
            int retn, i;

            bzero ((char *) &lfilter, sizeof (lfilter));
            ptr = RaCommandInputStr;
            while (isspace((int)*ptr)) ptr++;

            if ((str = strstr (ptr, "local")) != NULL) {
               ptr = strdup(&str[strlen("local ")]);
               ind = ARGUS_LOCAL_FILTER;
            } else 
            if ((str = strstr (ptr, "display")) != NULL) {
               ptr = strdup(&str[strlen("display ")]);
               ind = ARGUS_DISPLAY_FILTER;
            } else 
            if ((str = strstr (ptr, "remote")) != NULL) {
               ptr = strdup(&str[strlen("remote ")]);
               ind = ARGUS_REMOTE_FILTER;
            } else 
            if ((str = strstr (ptr, "none")) != NULL) {
               ptr = NULL;
               ind = RaFilterIndex;
            } else
               ptr = NULL;

            if ((retn = ArgusFilterCompile (&lfilter, ptr, 1)) < 0) {
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGfSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = LOG_ERR;
            } else {
               sprintf (ArgusParser->RaDebugString, "%s %s filter accepted", RAGETTINGfSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = 0;
               if ((str = ptr) != NULL)
                  while (isspace((int)*str)) str++;
               
               switch (ind) {
                  case ARGUS_LOCAL_FILTER:
                     if (ArgusParser->ArgusFilterCode.bf_insns != NULL)
                        free (ArgusParser->ArgusFilterCode.bf_insns);

                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusFilterCode, sizeof(lfilter));
                     if (ArgusParser->ArgusLocalFilter !=  NULL) {
                        free(ArgusParser->ArgusLocalFilter);
                        ArgusParser->ArgusLocalFilter = NULL;
                     }
                     if (str && (strlen(str) > 0))
                        ArgusParser->ArgusLocalFilter = ptr;
                     else
                        if (ptr != NULL) free(ptr);
                     break;

                  case ARGUS_DISPLAY_FILTER:
                     if (ArgusParser->ArgusDisplayCode.bf_insns != NULL)
                        free (ArgusParser->ArgusDisplayCode.bf_insns);

                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusDisplayCode, sizeof(lfilter));
                     bcopy((char *)&lfilter, (char *)&ArgusSorter->filter, sizeof(lfilter));

                     if (ArgusParser->ArgusDisplayFilter !=  NULL) {
                        free(ArgusParser->ArgusDisplayFilter);
                        ArgusParser->ArgusDisplayFilter = NULL;
                     }
                     if (str && (strlen(str) > 0))
                        ArgusParser->ArgusDisplayFilter = ptr;
                     else
                        if (ptr != NULL) free(ptr);
                     break;

                  case ARGUS_REMOTE_FILTER:
                     if (ArgusParser->ArgusFilterCode.bf_insns != NULL)
                        free (ArgusParser->ArgusFilterCode.bf_insns);
                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusFilterCode, sizeof(lfilter));
                     if (ArgusParser->ArgusRemoteFilter !=  NULL) {
                        free(ArgusParser->ArgusRemoteFilter);
                        ArgusParser->ArgusRemoteFilter = NULL;
                     }
                     if (str && (strlen(str) > 0))
                        ArgusParser->ArgusRemoteFilter = ptr;
                     else
                        if (ptr != NULL) free(ptr);
                     break;
               }
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
            RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);
            if (ArgusParser->ns) {
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->ns = NULL;
            }
            for (i = 0; i < RaTopProcess->queue->count; i++) {
               struct ArgusRecordStruct *ns;
               if ((ns = (struct ArgusRecordStruct *)RaTopProcess->queue->array[i]) == NULL)
                  break;
               if (ArgusParser->ns)
                  ArgusMergeRecords (parser->ArgusAggregator, ArgusParser->ns, ns);
               else
                  ArgusParser->ns = ArgusCopyRecordStruct (ns);
            }
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
            RaWindowStatus = 1;
            ArgusUpdateScreen();
            RaRefreshDisplay(ArgusParser);
            break;
         }
                      
         case RAGETTINGm: {
            struct ArgusRecordStruct *ns = NULL;
            char strbuf[MAXSTRLEN], *tok = NULL, *ptr;
            struct ArgusModeStruct *mode = NULL, *modelist = NULL, *list; 
            struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
            int i;                                  

            ArgusParser->RaMonMode = 0;

            if ((agg->modeStr == NULL) || strcmp(agg->modeStr, RaCommandInputStr)) {
               if (agg->modeStr != NULL)
                  free(agg->modeStr);
               agg->modeStr = strdup(RaCommandInputStr);
               strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

               if ((mode = ArgusParser->ArgusMaskList) != NULL)
                  ArgusDeleteMaskList(ArgusParser);

               agg->mask = 0;
               agg->saddrlen = 0;
               agg->daddrlen = 0;

               if ((ptr = strbuf) != NULL) {
                  while ((tok = strtok (ptr, " \t")) != NULL) {
                     if ((mode = (struct ArgusModeStruct *) ArgusCalloc (1, sizeof(struct ArgusModeStruct))) != NULL) {
                        if ((list = modelist) != NULL) {
                           while (list->nxt)
                              list = list->nxt;
                           list->nxt = mode;
                        } else
                           modelist = mode;
                        mode->mode = strdup(tok);
                     }
                     ptr = NULL;
                  }
               } else {
                  if ((modelist = ArgusParser->ArgusMaskList) == NULL)
                     agg->mask  = ( ARGUS_MASK_SRCID_INDEX | ARGUS_MASK_PROTO_INDEX |
                                    ARGUS_MASK_SADDR_INDEX | ARGUS_MASK_SPORT_INDEX |
                                    ARGUS_MASK_DADDR_INDEX | ARGUS_MASK_DPORT_INDEX );
               }

               ArgusInitAggregatorStructs(agg);

               if ((mode = modelist) != NULL) {
                  while (mode) {
                     char *ptr = NULL, **endptr = NULL;
                     int value = 0;

                     if ((ptr = strchr(mode->mode, '/')) != NULL) {
                        ptr++;
                        if ((value = strtol(ptr, endptr, 10)) == 0)
                           if (*endptr == ptr)
                              usage();
                     }
                     if (!(strncasecmp (mode->mode, "none", 4))) {
                        agg->mask  = 0;
                     } else
                     if (!(strncasecmp (mode->mode, "macmatrix", 9))) {
                        agg->ArgusMatrixMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SMAC);
                        agg->mask |= (0x01LL << ARGUS_MASK_DMAC);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "mac", 3))) {
                        ArgusParser->RaMonMode++;
                        if (agg->correct != NULL) {
                           free(agg->correct);
                           agg->correct = NULL;
                        }
                        agg->mask |= (0x01LL << ARGUS_MASK_SMAC);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "addr", 4))) {
                        ArgusParser->RaMonMode++;
                        if (agg->correct != NULL) {
                           free(agg->correct);
                           agg->correct = NULL;
                        }
                        agg->mask |= (0x01LL << ARGUS_MASK_SADDR);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "matrix", 6))) {
                        agg->ArgusMatrixMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SADDR);
                        agg->mask |= (0x01LL << ARGUS_MASK_DADDR);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else {
                        struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs;

                        for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                           if (!(strncasecmp (mode->mode, ArgusMaskDefs[i].name, ArgusMaskDefs[i].slen))) {
                              agg->mask |= (0x01LL << i);
                              switch (i) {
                                 case ARGUS_MASK_SADDR:
                                    if (value > 0) {
                                       agg->saddrlen = value;
                                       if (value <= 32)
                                          agg->smask.addr_un.ipv4 = (0xFFFFFFFF << (32 - value));
                                    }
                                    break;

                                 case ARGUS_MASK_DADDR:
                                    if (value > 0) {
                                       agg->daddrlen = value;
                                       if (value <= 32)
                                          agg->dmask.addr_un.ipv4 = (0xFFFFFFFF << (32 - value));
                                    }
                                    break;

                                case ARGUS_MASK_SMPLS:
                                case ARGUS_MASK_DMPLS: {
                                   int x, RaNewIndex = 0;
                                   char *ptr;

                                   if ((ptr = strchr(mode->mode, '[')) != NULL) {
                                      char *cptr = NULL;
                                      int sind = -1, dind = -1;
                                      *ptr++ = '\0';
                                      while (*ptr != ']') {
                                         if (isdigit((int)*ptr)) {
                                            dind = strtol(ptr, (char **)&cptr, 10);
                                            if (cptr == ptr)
                                               usage ();
     
                                            if (sind < 0)
                                               sind = dind;

                                            for (x = sind; x <= dind; x++)
                                               RaNewIndex |= 0x01 << x;

                                            ptr = cptr;
                                            if (*ptr != ']')
                                               ptr++;
                                            if (*cptr != '-')
                                               sind = -1;
                                         } else
                                            usage ();
                                      }
                                      ArgusIpV4MaskDefs[i].index = RaNewIndex;
                                      ArgusIpV6MaskDefs[i].index = RaNewIndex;
                                      ArgusEtherMaskDefs[i].index = RaNewIndex;
                                   }
                                   break;
                                }
                             }
                             break;
                          }
                       }
                    }
                    mode = mode->nxt;
                 }
              }

               ArgusParser->ArgusMaskList = modelist;

               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaTopProcess->queue, ARGUS_LOCK)) != NULL)
                  ArgusDeleteRecordStruct (ArgusParser, ns);

               ArgusEmptyHashTable(RaTopProcess->htable);
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->RaClientUpdate.tv_sec = 0;
               ArgusParser->ns = NULL;

               werase(RaWindow);
               ArgusUpdateScreen();
            }

            break;
         }

         case RAGETTINGM: {
            struct ArgusModeStruct *mode = NULL;
            char strbuf[MAXSTRLEN], *str = strbuf, *tok = NULL;
            char *tzptr;
            int retn = 0;

            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if ((tzptr = strstr(strbuf, "TZ=")) != NULL) {
               if (ArgusParser->RaTimeZone)
                  free (ArgusParser->RaTimeZone);
               ArgusParser->RaTimeZone = strdup(tzptr);
               tzptr = getenv("TZ");
#if defined(HAVE_SETENV)
               if ((retn = setenv("TZ", (ArgusParser->RaTimeZone + 3), 1)) < 0) {
                  sprintf (ArgusParser->RaDebugString, "setenv(TZ, %s, 1) error %s", 
                     ArgusParser->RaTimeZone + 3, strerror(errno));
                  ArgusParser->RaDebugStatus = LOG_ERR;
               }
#else
               if ((retn = putenv(ArgusParser->RaTimeZone)) < 0) {
                  sprintf (ArgusParser->RaDebugString, "setenv(TZ, %s, 1) error %s", 
                     ArgusParser->RaTimeZone + 3, strerror(errno));
                  ArgusParser->RaDebugStatus = LOG_ERR;
               }
#endif
               if (retn == 0) {
                  tzset();
                  sprintf (ArgusParser->RaDebugString, "Timezone changed from %s to %s", 
                             tzptr, getenv("TZ"));
                  ArgusParser->RaDebugStatus = 0;
               }

               ArgusUpdateScreen();
               break;
            }

            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               ArgusDeleteModeList(ArgusParser);
               ArgusParser->RaCumulativeMerge = 1;
            }

            if (strlen(strbuf) > 0) {
               while ((tok = strtok(str, " \t\n")) != NULL) {
                  if (!(strncasecmp (tok, "none", 4)))
                     ArgusDeleteModeList(ArgusParser);
                  else if (!(strncasecmp (tok, "default", 7))) {
                     ArgusDeleteModeList(ArgusParser);
                  } else
                     ArgusAddModeList (ArgusParser, tok);
                  str = NULL;
               }
            }

            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               struct ArgusAdjustStruct *nadp = NULL;
               struct RaBinProcessStruct *RaBinProcess = parser->RaBinProcess;
               int i, ind;

               while (mode) {
                  for (i = 0, ind = -1; i < ARGUSSPLITMODENUM; i++) {
                     if (!(strncasecmp (mode->mode, RaSplitModes[i], strlen(RaSplitModes[i])))) {
                        ind = i;
                        break;
                     }
                  }

                  if (ind >= 0) {
                     char *mptr = NULL;
                     int size = -1;
                     nadp = &RaBinProcess->nadp;

                     nadp = &RaBinProcess->nadp;

                     switch (ind) {
                        case ARGUSSPLITRATE:  {   /* "%d:%d[yMwdhms]" */
                           struct ArgusModeStruct *tmode = NULL; 
                           nadp->mode = ind;
                           if ((tmode = mode->nxt) != NULL) {
                              mptr = tmode->mode;
                              if (isdigit((int)*tmode->mode)) {
                                 char *ptr = NULL;
                                 nadp->len = strtol(tmode->mode, (char **)&ptr, 10);
                                 if (*ptr++ != ':') 
                                    usage();
                                 tmode->mode = ptr;
                              }
                           }
                        }

                        case ARGUSSPLITTIME: /* "%d[yMwdhms] */
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
                                          size = nadp->value * 31556926;
                                          break;
                                       case 'M':
                                          nadp->qual = ARGUSSPLITMONTH; 
                                          size = nadp->value * 2629744;
                                          break;
                                       case 'w':
                                          nadp->qual = ARGUSSPLITWEEK;  
                                          size = nadp->value * 604800;
                                          break;
                                       case 'd':
                                          nadp->qual = ARGUSSPLITDAY;   
                                          size = nadp->value * 86400;
                                          break;
                                       case 'h':
                                          nadp->qual = ARGUSSPLITHOUR;  
                                          size = nadp->value * 3600;
                                          break;
                                       case 'm':
                                          nadp->qual = ARGUSSPLITMINUTE;
                                          size = nadp->value * 60;
                                          break;
                                        default:
                                          nadp->qual = ARGUSSPLITSECOND;
                                          size = nadp->value;
                                          break;
                                    }
                                 }
                              }
                              if (mptr != NULL)
                                  mode->mode = mptr;
                           }

                           nadp->modify = 1;

                           if (ind == ARGUSSPLITRATE) {
                              /* need to set the flow idle timeout value to be equal to or
                                 just a bit bigger than (nadp->len * size) */

                              ArgusParser->timeout.tv_sec  = (nadp->len * size);
                              ArgusParser->timeout.tv_usec = 0;
                           }

                           ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;
                           ArgusSorter->ArgusSortAlgorithms[1] = NULL;
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
                     if (!(strncasecmp (mode->mode, "nomerge", 7))) {
                        ArgusParser->RaCumulativeMerge = 0;
                     } else
                     if (!(strncasecmp (mode->mode, "merge", 5))) {
                        ArgusParser->RaCumulativeMerge = 1;
                     } else
                     if (!(strncasecmp (mode->mode, "rtime", 5)) ||
                        (!(strncasecmp (mode->mode, "realtime", 8)))) {
                        char *ptr = NULL;
                        RaTopRealTime++;
                        if ((ptr = strchr(mode->mode, ':')) != NULL) {
                           double value = 0.0;
                           char *endptr = NULL;
                           ptr++;
                           value = strtod(ptr, &endptr);
                           if (ptr != endptr) {
                              RaUpdateRate = value;
                           }
                        }

                     }
                  }

                  mode = mode->nxt;
               }
            }

            break;
         }

         case RAGETTINGp: {
            int value = 0;
            char *endptr = NULL;

            value = strtod(RaCommandInputStr, &endptr);

            if (RaCommandInputStr != endptr) {
               ArgusParser->pflag = value;
            } else {
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGuSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = LOG_ERR;
            }

            ArgusUpdateScreen();
            break;
         }

         case RAGETTINGR: {
            char strbuf[MAXSTRLEN], *str = strbuf, *ptr = NULL;
            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if (strlen(strbuf) > 0) {
               ArgusDeleteFileList(ArgusParser);
               while ((ptr = strtok(str, " ")) != NULL) {
                  RaProcessRecursiveFiles (ptr);
                  str = NULL;
               }
            }
            break;
         }

         case RAGETTINGr: {
            char strbuf[MAXSTRLEN], *str = strbuf, *ptr = NULL;
            glob_t globbuf;

            bzero (strbuf, MAXSTRLEN);
            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if (strlen(strbuf) > 0) {
               struct ArgusRecordStruct *ns = NULL;

               ArgusDeleteFileList(ArgusParser);
               while ((ptr = strtok(str, " ")) != NULL) {
                  glob (ptr, 0, NULL, &globbuf);
                  if (globbuf.gl_pathc > 0) {
                     int i;
                     for (i = 0; i < globbuf.gl_pathc; i++)
                        ArgusAddFileList (ArgusParser, globbuf.gl_pathv[i], ARGUS_DATA_SOURCE, -1, -1);
                  } else {
                     sprintf (ArgusParser->RaDebugString, "%s no files found for %s", RAGETTINGrSTR, ptr);
                     ArgusParser->RaDebugStatus = LOG_ERR;
                  }
                  str = NULL;
               }
               ArgusParser->RaTasksToDo = 1;
               ArgusParser->Sflag = 0;
               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaTopProcess->queue, ARGUS_LOCK)) != NULL) 
                  ArgusDeleteRecordStruct (ArgusParser, ns);
               ArgusEmptyHashTable(RaTopProcess->htable);
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->RaClientUpdate.tv_sec = 0;
               ArgusParser->status &= ~ARGUS_FILE_LIST_PROCESSED;
               ArgusParser->ns = NULL;
               ArgusLastTime.tv_sec  = 0;
               ArgusLastTime.tv_usec = 0;
            }
            break;
         }

         case RAGETTINGs: {
            char strbuf[MAXSTRLEN], *ptr = strbuf, *tok;
            int (*srtalg[ARGUS_MAX_SORT_ALG])(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
            int i, x, ind = 0;
            strncpy (strbuf, RaCommandInputStr, MAXSTRLEN);
            bzero(srtalg, sizeof(srtalg));
            while ((tok = strtok(ptr, " ")) != NULL) {
               for (x = 0; x < ARGUS_MAX_SORT_ALG; x++) {
                  if (!strncmp (ArgusSortKeyWords[x], tok, strlen(ArgusSortKeyWords[x]))) {
                     srtalg[ind++] = ArgusSortAlgorithmTable[x];
                     break;
                  }
               }
               if (x == ARGUS_MAX_SORT_ALG) {
                  bzero(srtalg, sizeof(srtalg));
                  ArgusLog (LOG_ALERT, "sort keyword %s not valid", tok);
                  break;
               }
               ptr = NULL;
            }

            if (srtalg[0] != NULL) {
               for (x = 0; x < ARGUS_MAX_SORT_ALG; x++)
                  ArgusSorter->ArgusSortAlgorithms[x] = srtalg[x];
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
            RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);
            if (ArgusParser->ns) {
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->ns = NULL;
            }
            for (i = 0; i < RaTopProcess->queue->count; i++) {
               struct ArgusRecordStruct *ns;
               if ((ns = (struct ArgusRecordStruct *)RaTopProcess->queue->array[i]) == NULL)
                  break;
               if (ArgusParser->ns)
                  ArgusMergeRecords (parser->ArgusAggregator, ArgusParser->ns, ns);
               else
                  ArgusParser->ns = ArgusCopyRecordStruct (ns);
            }
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
            ArgusUpdateScreen();
            break;
         }

         case RAGETTINGT: {
            double sec, usec, value;
            char *ptr = NULL;

            value = strtod(RaCommandInputStr, (char **)&ptr);
            if (ptr != RaCommandInputStr) {
               usec = modf(value, &sec);
               ArgusParser->timeout.tv_sec  = sec;
               ArgusParser->timeout.tv_usec = usec;
            }
            break;
         }

         case RAGETTINGt: {
            if (ArgusParser->timearg) {
               free (ArgusParser->timearg);
               ArgusParser->timearg = NULL;
            }

            if (strlen(RaCommandInputStr))
               ArgusParser->timearg = strdup(RaCommandInputStr);

            ArgusCheckTimeFormat (&ArgusParser->RaTmStruct, ArgusParser->timearg);
            break;
         }

         case RAGETTINGu: {
            double value = 0.0, ivalue, fvalue;
            char *endptr = NULL;
#if defined(ARGUS_READLINE)
            int keytimeout;
#endif
 
            value = strtod(RaCommandInputStr, &endptr);
 
            if (RaCommandInputStr != endptr) {
               fvalue = modf(value, &ivalue);
 
               RaTopUpdateInterval.tv_sec  = (int) ivalue;
               RaTopUpdateInterval.tv_usec = (int) (fvalue * 1000000.0);

#if defined(ARGUS_READLINE)
               keytimeout = (RaTopUpdateInterval.tv_sec * 1000000) + RaTopUpdateInterval.tv_usec;
               keytimeout = (keytimeout == 1000000) ? keytimeout - 1 : keytimeout;
#if defined(HAVE_DECL_RL_SET_KEYBOARD_INPUT_TIMEOUT) && HAVE_DECL_RL_SET_KEYBOARD_INPUT_TIMEOUT
               rl_set_keyboard_input_timeout (keytimeout);
#endif
#endif
               sprintf (ArgusParser->RaDebugString, "%s %s interval accepted", RAGETTINGuSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = 0;
               RaTopUpdateTime = ArgusParser->ArgusRealTime;
 
            } else {
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGuSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = LOG_ERR;
            }

            break;
         }

         case RAGETTINGU: {
            double value = 0.0;
            char *endptr = NULL;
 
            value = strtod(RaCommandInputStr, &endptr);
 
            if (RaCommandInputStr != endptr) {
               RaUpdateRate = value;
               sprintf (ArgusParser->RaDebugString, "%s %s accepted", RAGETTINGUSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = 0;
 
            } else {
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGUSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = LOG_ERR;
            }

            break;
         }

         
         case RAGETTINGw: {
            struct ArgusListStruct *wlist = ArgusParser->ArgusWfileList;
            struct ArgusWfileStruct *wfile = NULL;
            struct ArgusRecord *argusrec = NULL;
            struct ArgusRecordStruct *ns;
            static char sbuf[0x10000];
            int i;

            if (strlen(RaCommandInputStr)) {
               if (RaTopProcess->queue->count > 0) {
                  ArgusParser->ArgusWfileList = NULL;
                  setArgusWfile (ArgusParser, RaCommandInputStr, NULL);
                  wfile = (struct ArgusWfileStruct *) ArgusParser->ArgusWfileList->start;

                  for (i = 0; i < RaTopProcess->queue->count; i++) {
                     int pass = 1;

                     if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[i]) == NULL)
                        break;

                     if (wfile->filterstr) {
                        struct nff_insn *wfcode = wfile->filter.bf_insns;
                        pass = ArgusFilterRecord (wfcode, ns);
                     }

                     if (pass != 0) {
                        if ((argusrec = ArgusGenerateRecord (ns, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                           ArgusHtoN(argusrec);
#endif
                           ArgusWriteNewLogfile (ArgusParser, ns->input, wfile, argusrec);

                        }
                     }
                  }
            
                  fflush(wfile->fd);
                  fclose(wfile->fd);
                  clearArgusWfile(ArgusParser);
                  ArgusParser->ArgusWfileList = wlist;
               }
            }

            break;   
         }

         case RAGETTINGF: {
            struct ArgusQueueStruct *queue = RaTopProcess->queue;
            char strbuf[MAXSTRLEN], *ptr = strbuf, *tok;
            int x;

            strncpy (strbuf, RaCommandInputStr, MAXSTRLEN);
            bzero ((char *)ArgusParser->RaPrintOptionStrings, sizeof(ArgusParser->RaPrintOptionStrings));
            ArgusParser->RaPrintOptionIndex = 0;
            while ((tok = strtok(ptr, " ")) != NULL) {
               if (ArgusParser->RaPrintOptionIndex <  ARGUS_MAX_S_OPTIONS)
                  ArgusParser->RaPrintOptionStrings[ArgusParser->RaPrintOptionIndex++] = tok;
               ptr = NULL;
            }

            if (ArgusParser->RaPrintOptionIndex > 0) {
               ArgusProcessSOptions(ArgusParser);
               for (x = 0; x < ArgusParser->RaPrintOptionIndex; x++) 
                  if (ArgusParser->RaPrintOptionStrings[x] != NULL) 
                     ArgusParser->RaPrintOptionStrings[x] = NULL;
               ArgusParser->RaPrintOptionIndex = 0;
            }

            for (x = 0, ArgusAlwaysUpdate = 0; x < MAX_PRINT_ALG_TYPES; x++)
               if (parser->RaPrintAlgorithmList[x] != NULL)
                  if (parser->RaPrintAlgorithmList[x]->print == ArgusPrintIdleTime)
                     ArgusAlwaysUpdate++;

            if (queue == RaTopProcess->queue) {
               int i;
               if (ArgusParser->ns) {
                  ArgusParser->ns->status |= ARGUS_RECORD_MODIFIED;
               }
               for (i = 0; i < queue->count; i++) {
                  struct ArgusRecordStruct *ns;
                  if ((ns = (struct ArgusRecordStruct *)queue->array[i]) == NULL)
                     break;
                  ns->status |= ARGUS_RECORD_MODIFIED;
               }
            }
            retn = RAGOTcolon;
            ArgusUpdateScreen();
            break;
         }

         case RAGETTINGcolon: {
            char *endptr = NULL;
            int linenum, startline;

            linenum = (int)strtol(RaCommandInputStr, &endptr, 10);
            if (RaCommandInputStr == endptr) {
               switch (*RaCommandInputStr) {
                  case 'q': {
                     bzero (RaCommandInputStr, MAXSTRLEN);
                     ArgusUpdateScreen();
                     RaParseComplete(SIGINT);
                     break;
                  }
               }
            } else {
               if ((linenum >= RaWindowStartLine) && (linenum <= (RaWindowStartLine + RaDisplayLines)))
                  RaWindowCursorY = linenum - RaWindowStartLine;
               else {
                  startline = ((linenum - 1)/ RaDisplayLines) * RaDisplayLines;
                  startline = (RaTopProcess->queue->count > startline) ? startline : RaTopProcess->queue->count - RaDisplayLines;
                  startline = (startline > 0) ? startline : 0;
                  RaWindowStartLine = startline;
                  if ((RaWindowCursorY = linenum % RaDisplayLines) == 0)
                     RaWindowCursorY = RaDisplayLines;
               }
               retn = RAGOTcolon;
               ArgusUpdateScreen();
            }
            break;
         }

         case RAGETTINGslash: {
            int linenum = RaWindowCursorY;
            int cursx = RaWindowCursorX, cursy = RaWindowCursorY + RaWindowStartLine;


//          RaHighlightDisplay(ArgusParser, RaTopProcess->queue, RaCommandInputStr);
            if ((linenum = RaSearchDisplay(ArgusParser, RaTopProcess->queue, ArgusSearchDirection,
                     &cursx, &cursy, RaCommandInputStr)) < 0) {
               if (ArgusSearchDirection == ARGUS_FORWARD) {
                  sprintf (ArgusParser->RaDebugString, "search hit BOTTOM, continuing at TOP");
                  cursx = 0; cursy = 0;
               } else {
                  sprintf (ArgusParser->RaDebugString, "search hit TOP, continuing at BOTTOM");
                  cursx = RaScreenColumns; cursy = RaTopProcess->queue->count;
               }
               linenum = RaSearchDisplay(ArgusParser, RaTopProcess->queue, ArgusSearchDirection,
                     &cursx, &cursy, RaCommandInputStr);
            }

            if (linenum >= 0) {
               int startline = ((cursy - 1)/ RaDisplayLines) * RaDisplayLines;
               startline = (RaTopProcess->queue->count > startline) ? startline : RaTopProcess->queue->count - RaDisplayLines;
               startline = (startline > 0) ? startline : 0;
               retn = RAGOTslash;
               RaWindowStartLine = startline;
               if ((RaWindowCursorY = cursy % RaDisplayLines) == 0)
                  RaWindowCursorY = RaDisplayLines;
               RaWindowCursorX = cursx;
               ArgusUpdateScreen();
            } else {
               sprintf (ArgusParser->RaDebugString, "Pattern not found: %s", RaCommandInputStr);
               ArgusParser->RaDebugStatus = LOG_ERR;
               retn = RAGOTslash;
               RaInputString = RANEWCOMMANDSTR;
               bzero(RaCommandInputStr, MAXSTRLEN);
               RaCommandIndex = 0;
               RaCursorOffset = 0;
               RaWindowCursorY = 0;
               RaWindowCursorX = 0;
               mvwaddnstr (RaWindow, RaScreenLines - 1, 0, " ", RaScreenColumns);
               wclrtoeol(RaWindow);
            }

            retn = RAGOTslash;
            RaInputString = "/";
            break;
         }
      }

      if ((retn != RAGOTslash) && (retn != RAGOTcolon)) {
         retn = RAGOTslash;
         RaInputString = RANEWCOMMANDSTR;
         RaCommandInputStr[0] = '\0';
      }

   } else {
      switch (ch) {
         case 0x0C: {
            bzero(&RaTopUpdateTime, sizeof(RaTopUpdateTime));
            wclear(RaWindow);
            RaWindowStatus = 1;
            ArgusUpdateScreen();
            RaRefreshDisplay(ArgusParser);
            ArgusUpdateScreen();
            break;
         }

         case 0x12: {
            int startline = RaWindowCursorY + RaWindowStartLine;
            struct ArgusRecordStruct *ns;

            if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[startline - 1]) != NULL) {

               ArgusRemoveFromQueue(RaTopProcess->queue, &ns->qhdr, ARGUS_LOCK);
               ArgusReverseRecord(ns);

               if (ns->htblhdr != NULL)
                  ArgusRemoveHashEntry(&ns->htblhdr);

               RaProcessThisRecord (ArgusParser, ns);

               RaWindowCursorY++;
               if ((RaTopProcess->queue->count - RaWindowStartLine) < RaDisplayLines) {
                  int maxwincount = RaTopProcess->queue->count - RaWindowStartLine;
                  if (RaWindowCursorY > maxwincount) {
                     RaWindowCursorY = maxwincount;
                     beep();
                  }

               } else {
                  if (RaWindowCursorY > RaDisplayLines) {
                     if ((RaTopProcess->queue->count - RaWindowStartLine) > RaDisplayLines) {
                        RaWindowStartLine++;
                        wscrl(RaAvailableWindow, 1);
                        ArgusUpdateScreen();
                     } else
                        beep();

                     RaWindowCursorY = RaDisplayLines;
                  }
               }
               ArgusUpdateScreen();
            }
            break;
         }

#if defined(ARGUS_READLINE)
         case 0x1B: { /* process ESC */
            struct timeval tvbuf, *tvp = &tvbuf;
            int eindex = 0;
            int escbuf[16];
            fd_set in;

            bzero(escbuf, sizeof(escbuf));
            tvp->tv_sec = 0; tvp->tv_usec = 10000;
            FD_ZERO(&in); FD_SET(0, &in);
            while ((select(1, &in, 0, 0, tvp) > 0) && (eindex < 2)) {
               if ((ch = wgetch(RaWindow)) != ERR) {
                  escbuf[eindex++] = ch;
               }
               FD_ZERO(&in); FD_SET(0, &in);
            }

            if (eindex == 2) {
               int offset;
               switch (escbuf[0]) {
                  case '[': /* process ESC */
                     switch (escbuf[1]) {
                        case 'A': /* cursor up */
                           RaWindowCursorY--;
                           if (RaWindowCursorY < 1) {
                              RaWindowCursorY = 1;
                              if (RaWindowStartLine > 0) {
                                 RaWindowStartLine--;
                                 wscrl(RaAvailableWindow, -1);
                                 ArgusUpdateScreen();
                              } else
                                 beep();
                           }
                           break;
                        case 'B': /* cursor down */
                           RaWindowCursorY++;
                           if ((RaTopProcess->queue->count - RaWindowStartLine) < RaDisplayLines) {
                              int maxwincount = RaTopProcess->queue->count - RaWindowStartLine;
                              if (RaWindowCursorY > maxwincount) {
                                 RaWindowCursorY = maxwincount;
                                 beep();
                              }

                           } else {
                              if (RaWindowCursorY > RaDisplayLines) {
                                 if ((RaTopProcess->queue->count - RaWindowStartLine) > RaDisplayLines) {
                                    RaWindowStartLine++;
                                    wscrl(RaAvailableWindow, 1);
                                    ArgusUpdateScreen();
                                 } else
                                    beep();

                                 RaWindowCursorY = RaDisplayLines;
                              }
                           }
                           break;
                        case 'C': { /* cursor forward */
                           int startline = RaWindowCursorY + RaWindowStartLine;
                           struct ArgusRecordStruct *ns;
                           int len;

                           if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[startline - 1]) != NULL) {
                              char buf[MAXSTRLEN];

                              if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != startline)) {
                                 char buf[MAXSTRLEN];

                                 if (ns->disp.str != NULL)
                                    free(ns->disp.str);

                                 buf[0] = '\0';
                                 ns->rank = startline;
                                 ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                                 ns->disp.str = strdup(buf);
                                 ns->status &= ~ARGUS_RECORD_MODIFIED;
                              }

                              len = strlen(ns->disp.str);

                              bcopy(ns->disp.str, buf, len + 1);
                              RaWindowCursorX++;
                              if (RaWindowCursorX >= len) {
                                 RaWindowCursorX = len - 1;
                                 beep();
                              }
                           }
                           ArgusUpdateScreen();
                           break;
                        }

                        case 'D': /* cursor backward */
                           RaWindowCursorX--;
                           if (RaWindowCursorX < 0) {
                              RaWindowCursorX = 0;
                              beep();
                           }
                           ArgusUpdateScreen();
                           break;
                     }
                     break;
                  default:
                     break;
               }
               offset = (RaWindowCursorY % (RaDisplayLines + 1));
               if (offset > (RaSortItems - RaWindowStartLine)) {
                  RaWindowCursorY = (RaSortItems - RaWindowStartLine);
                  offset = (RaSortItems - RaWindowStartLine);
               }
               offset += RaHeaderWinSize;
               wmove (RaWindow, offset, RaWindowCursorX);
            }
            break;
         }
#endif

         case 0x04: {
            bzero (RaCommandInputStr, MAXSTRLEN);
            RaCommandIndex = 0;
            RaCursorOffset = 0;
            break;
         }

         case KEY_UP: {
            int done = 0, start = RaFilterIndex;
            switch (retn) {
               case RAGETTINGf: {
                  do {
                     RaFilterIndex = ((RaFilterIndex + 1) > ARGUS_DISPLAY_FILTER) ? ARGUS_REMOTE_FILTER : RaFilterIndex + 1;
                     switch (RaFilterIndex) {
                        case ARGUS_REMOTE_FILTER:
                           if (ArgusParser->ArgusRemoteFilter) {
                              sprintf (RaCommandInputStr, "remote %s ", ArgusParser->ArgusRemoteFilter);
                              RaCommandIndex = strlen(RaCommandInputStr);
                              RaFilterIndex = ARGUS_REMOTE_FILTER;
                              RaWindowImmediate = TRUE;
                              done++;
                              break;
                           }

                        case ARGUS_LOCAL_FILTER:
                           if (ArgusParser->ArgusLocalFilter) {
                              sprintf (RaCommandInputStr, "local %s ", ArgusParser->ArgusLocalFilter);
                              RaCommandIndex = strlen(RaCommandInputStr);
                              RaFilterIndex = ARGUS_LOCAL_FILTER;
                              RaWindowImmediate = TRUE;
                              done++;
                              break;
                           }
                        case ARGUS_DISPLAY_FILTER:
                           if (ArgusParser->ArgusDisplayFilter) {
                              sprintf (RaCommandInputStr, "display %s ", ArgusParser->ArgusDisplayFilter);
                              RaCommandIndex = strlen(RaCommandInputStr);
                              RaFilterIndex = ARGUS_DISPLAY_FILTER;
                              RaWindowImmediate = TRUE;
                              done++;
                              break;
                           }
                     }
                  } while ((start != RaFilterIndex) && !done);
                  break;
               }

               default: {
                  RaWindowCursorY--;
                  if (RaWindowCursorY < 1) {
                     RaWindowCursorY = 1;
                     if (RaWindowStartLine > 0) {
                        RaWindowStartLine--;
                        wscrl(RaAvailableWindow, -1);
                        ArgusUpdateScreen();
                     } else
                        beep();
                  }
                  break;
               }
            }
            break;
         }

         case KEY_DOWN: {
            int trips = 0, done = 0, start = RaFilterIndex;
            switch (retn) {
               case RAGETTINGf: {
                  do {
                     RaFilterIndex = ((RaFilterIndex - 1) < ARGUS_REMOTE_FILTER) ? ARGUS_DISPLAY_FILTER : RaFilterIndex - 1;
                     switch (RaFilterIndex) {
                        case ARGUS_DISPLAY_FILTER:
                           if (ArgusParser->ArgusDisplayFilter) {
                              sprintf (RaCommandInputStr, " display %s", ArgusParser->ArgusDisplayFilter);
                              RaCommandIndex = strlen(RaCommandInputStr);
                              RaFilterIndex = ARGUS_DISPLAY_FILTER;
                              RaWindowImmediate = TRUE;
                              done++;
                              break;
                           }

                        case ARGUS_LOCAL_FILTER:
                           if (ArgusParser->ArgusLocalFilter) {
                              sprintf (RaCommandInputStr, " local %s", ArgusParser->ArgusLocalFilter);
                              RaCommandIndex = strlen(RaCommandInputStr);
                              RaFilterIndex = ARGUS_LOCAL_FILTER;
                              RaWindowImmediate = TRUE;
                              done++;
                              break;
                           }

                        case ARGUS_REMOTE_FILTER:
                           if (ArgusParser->ArgusRemoteFilter) {
                              sprintf (RaCommandInputStr, " remote %s", ArgusParser->ArgusRemoteFilter);
                              RaCommandIndex = strlen(RaCommandInputStr);
                              RaFilterIndex = ARGUS_REMOTE_FILTER;
                              RaWindowImmediate = TRUE;
                              done++;
                              break;
                           }
                     }
                     trips++;
                  } while ((start != RaFilterIndex) && !done && (trips < 3));
                  break;
               }
               default: {
                  RaWindowCursorY++;
                  if ((RaTopProcess->queue->count - RaWindowStartLine) < RaDisplayLines) {
                     int maxwincount = RaTopProcess->queue->count - RaWindowStartLine;
                     if (RaWindowCursorY > maxwincount) {
                        RaWindowCursorY = maxwincount;
                        beep();
                     }

                  } else {
                     if (RaWindowCursorY > RaDisplayLines) {
                        if ((RaTopProcess->queue->count - RaWindowStartLine) > RaDisplayLines) {
                           RaWindowStartLine++;
                           wscrl(RaAvailableWindow, 1);
                           ArgusUpdateScreen();
                        } else
                           beep();

                        RaWindowCursorY = RaDisplayLines;
                     }
                  }
                  break;
               }
            }
            break;
         }

         case KEY_LEFT:
            if (++RaCursorOffset > RaCommandIndex)
              RaCursorOffset = RaCommandIndex;
            break;

         case KEY_RIGHT:
            if (--RaCursorOffset < 0)
               RaCursorOffset = 0;
            break;

         case 0x07: {
            ArgusDisplayStatus = (ArgusDisplayStatus ? 0 : 1);
            bzero (parser->RaDebugString, 4);
            ArgusUpdateScreen();
            break;
         }

         default: {
            switch (ch) {
               case '\b':
               case 0x7F:
               case KEY_DC:
               case KEY_BACKSPACE: {
                  if (RaCursorOffset == 0) {
                     RaCommandInputStr[RaCommandIndex--] = '\0';
                     RaCommandInputStr[RaCommandIndex] = '\0';
                  } else {
                     if (RaCursorOffset < RaCommandIndex) {
                        int z, start; 
                        start = RaCommandIndex - (RaCursorOffset + 1);
                        if (start < 0)
                           start = 0;
                        for (z = start; z < (RaCommandIndex - 1); z++)
                           RaCommandInputStr[z] = RaCommandInputStr[z + 1];
                        RaCommandInputStr[RaCommandIndex--] = '\0';
                        RaCommandInputStr[RaCommandIndex] = '\0';
                        if (RaCursorOffset > RaCommandIndex)
                           RaCursorOffset = RaCommandIndex;
                     }
                  }

                  if (RaCommandIndex < 0) {
                     if ((retn == RAGETTINGslash) || (retn == RAGETTINGcolon)) {
                        mvwaddstr (RaWindow, RaScreenLines - 1, 0, " ");
                        retn = RAGOTslash;
                        RaInputString = RANEWCOMMANDSTR;
                        RaCommandIndex = 0;
                        RaCursorOffset = 0;
                     }
                     RaCommandIndex = 0;
                  }
                  break;
               }

               case 0x15:
               case KEY_DL: {
                  bzero (RaCommandInputStr, MAXSTRLEN);
                  RaCommandIndex = 0;
                  RaCursorOffset = 0;
                  break;
               }
    
               default: {
                  int iter;
                  if (retn == RAGOTslash) {
                     if (isdigit(ch) && (ch != '0')) {
                        if (RaDigitPtr < 16)
                           RaDigitBuffer[RaDigitPtr++] = ch;
                     } else {
                        if (RaDigitPtr) {
                           char *ptr;
                           RaIter= strtol(RaDigitBuffer, (char **)&ptr, 10);
                           if (ptr == RaDigitBuffer)
                              RaIter = 1;
                           bzero(RaDigitBuffer, sizeof(RaDigitBuffer));
                           RaDigitPtr = 0;
                        } else
                           RaIter = 1;

#if defined(ARGUSDEBUG)
                        ArgusDebug (6, "ArgusProcessCommand: calling with %d iterations", RaIter);
#endif
                     }
                  } else
                     RaIter = 1;

                  for (iter = 0; iter < RaIter; iter++) {
                     int olddir = -1;

                     switch (retn) {
                        case RAGOTcolon:
                        case RAGOTslash: {
                           bzero (ArgusParser->RaDebugString, sizeof(ArgusParser->RaDebugString));
                           ArgusParser->RaDebugStatus = 0;
                           switch (ch) {
                              case 0x07: {
                                 ArgusDisplayStatus = (ArgusDisplayStatus ? 0 : 1);
                                 bzero (parser->RaDebugString, 4);
                                 ArgusUpdateScreen();
                                 break;
                              }
                              case '%': {
                                 ArgusParser->Pctflag = (ArgusParser->Pctflag == 1) ? 0 : 1;
                                 if (ArgusParser->Pctflag)
                                    RaInputString = "Toggle percent on";
                                 else
                                    RaInputString = "Toggle percent off";
                                 break;
                              }
                              case 'H':
                                 ArgusParser->Hflag = ArgusParser->Hflag ? 0 : 1;
                                 break;
                              case 'P': {
                                 double pause = ArgusParser->Pauseflag;

                                 ArgusParser->Pauseflag = (pause > 0.0) ? 0.0 : 1.0;

                                 if (ArgusParser->Pauseflag)
                                    RaInputString = "Paused";
                                 else
                                    RaInputString = "";
                                 break;
                              }
                              case 'v':
                                 if (ArgusParser->vflag) {
                                    ArgusParser->vflag = 0;
                                    ArgusReverseSortDir = 0;
                                 } else {
                                    ArgusParser->vflag = 1;
                                    ArgusReverseSortDir++;
                                 }
#if defined(ARGUS_THREADS)
                                 pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
                                 RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);
#if defined(ARGUS_THREADS)
                                 pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
                                 break;

                              case 'N': 
                                 olddir = ArgusSearchDirection;
                                 ArgusSearchDirection = (ArgusSearchDirection == ARGUS_FORWARD) ?  ARGUS_BACKWARD : ARGUS_FORWARD;
                              case 'n': {
                                 if ((retn == RAGOTslash) && strlen(RaCommandInputStr)) {
                                    int linenum;
                                    int cursx = RaWindowCursorX, cursy = RaWindowCursorY + RaWindowStartLine;
                                    if ((linenum = RaSearchDisplay(ArgusParser, RaTopProcess->queue,
                                          ArgusSearchDirection, &cursx, &cursy, RaCommandInputStr)) < 0) {

                                       if (ArgusSearchDirection == ARGUS_FORWARD) {
                                          sprintf (ArgusParser->RaDebugString, "search hit BOTTOM, continuing at TOP");
                                          cursx = 0; cursy = 0;
                                       } else {
                                          sprintf (ArgusParser->RaDebugString, "search hit TOP, continuing at BOTTOM");
                                          cursx = RaScreenColumns; cursy = RaTopProcess->queue->count;
                                       }
                                       linenum = RaSearchDisplay(ArgusParser, RaTopProcess->queue,
                                          ArgusSearchDirection, &cursx, &cursy, RaCommandInputStr);
                                    }
                                    if (linenum >= 0) {
                                       if ((linenum < RaWindowStartLine) || ((linenum > RaWindowStartLine + RaDisplayLines))) {
                                          int startline = ((cursy - 1)/ RaDisplayLines) * RaDisplayLines;
                                          startline = (RaTopProcess->queue->count > startline) ? startline : RaTopProcess->queue->count - RaDisplayLines;
                                          startline = (startline > 0) ? startline : 0;
                                          RaWindowStartLine = startline;

                                          if ((RaWindowCursorY = cursy % RaDisplayLines) == 0)
                                             RaWindowCursorY = RaDisplayLines;

                                       } else
                                          RaWindowCursorY = cursy - RaWindowStartLine;

                                       RaWindowCursorX = cursx;
                                       ArgusUpdateScreen();
                                    } 
                                 }
                                 if (olddir != -1)
                                    ArgusSearchDirection = olddir;
                                 break;
                              }

                              case KEY_LEFT:
                              case 'h': {
                                 RaWindowCursorX--;
                                 if (RaWindowCursorX < 0) {
                                    RaWindowCursorX = 0;
                                    beep();
                                 }
                                 break;
                              }
                              case 'j': 
                              case 0x05:
                              case 0x0E:
                              case KEY_DOWN: {
                                 RaWindowCursorY++;
                                 if ((RaTopProcess->queue->count - RaWindowStartLine) < RaDisplayLines) {
                                    int maxwincount = RaTopProcess->queue->count - RaWindowStartLine;
                                    if (RaWindowCursorY > maxwincount) {
                                       RaWindowCursorY = maxwincount;
                                       beep();
                                    }

                                 } else {
                                    if (RaWindowCursorY > RaDisplayLines) {
                                       if ((RaTopProcess->queue->count - RaWindowStartLine) > RaDisplayLines) {
                                          RaWindowStartLine++;
                                          wscrl(RaAvailableWindow, 1);
                                          ArgusUpdateScreen();
                                       } else
                                          beep();

                                       RaWindowCursorY = RaDisplayLines;
                                    }
                                 }
                                 break;
                              }

                              case 0x19:
                              case KEY_UP:
                              case 'k': {
                                 RaWindowCursorY--;
                                 if (RaWindowCursorY < 1) {
                                    RaWindowCursorY = 1;
                                    if (RaWindowStartLine > 0) {
                                       RaWindowStartLine--;
                                       wscrl(RaAvailableWindow, -1);
                                       ArgusUpdateScreen();
                                    } else
                                       beep();
                                 }
                                 break;
                              }

                              case KEY_RIGHT:
                              case 'l': {
                                 int startline = RaWindowCursorY + RaWindowStartLine;
                                 struct ArgusRecordStruct *ns;

                                 if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[startline - 1]) != NULL) {
                                    char buf[MAXSTRLEN];
                                    int len;

                                    if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != startline)) {
                                       char buf[MAXSTRLEN];

                                       if (ns->disp.str != NULL)
                                          free(ns->disp.str);

                                       buf[0] = '\0';
                                       ns->rank = startline;
                                       ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                                       ns->disp.str = strdup(buf);
                                       ns->status &= ~ARGUS_RECORD_MODIFIED;
                                    }

                                    len = strlen(ns->disp.str);
                                    bcopy(ns->disp.str, buf, len + 1);

                                    len = strlen(buf);
                                    RaWindowCursorX++;
                                    if (RaWindowCursorX >= len) {
                                       RaWindowCursorX = len - 1;
                                       beep();
                                    }
                                 }
                                 break;
                              }

                              case 'g':
                              case KEY_HOME:
                                 if (RaWindowStartLine != 0) {
                                    RaWindowStartLine = 0;
                                    RaWindowModified = RA_MODIFIED;
                                 } else
                                    beep();
                                 break;

                              case 'G':
                              case KEY_END:
                                 if (RaWindowStartLine != (RaTopProcess->queue->count - RaDisplayLines)) {
                                    RaWindowStartLine = RaTopProcess->queue->count - RaDisplayLines;
                                    if (RaWindowStartLine < 0)
                                       RaWindowStartLine = 0;
                                    RaWindowModified = RA_MODIFIED;
                                 } else
                                    beep();
                                 break;
                              case 0x06:
                              case 0x04:
                              case ' ':
                              case KEY_NPAGE: {
                                 int count = (RaSortItems - RaWindowStartLine) - 1;
                                 if (count > RaDisplayLines) {
                                    RaWindowStartLine += RaDisplayLines;
                                    wscrl(RaWindow, RaDisplayLines);
                                    RaWindowModified = RA_MODIFIED;
                                 } else {
                                    if (count) {
                                       RaWindowStartLine += count;
                                       wscrl(RaWindow, count);
                                       RaWindowModified = RA_MODIFIED;
                                    } else
                                       beep();
                                 }
                                 break;
                              }

                              case 0x02:
                              case 0x15:
                              case KEY_PPAGE:
                                 if (RaWindowStartLine > 0) { 
                                    wscrl(RaWindow, (RaDisplayLines > RaWindowStartLine) ? -RaWindowStartLine : -RaDisplayLines);
                                    RaWindowStartLine -= RaDisplayLines;
                                    if (RaWindowStartLine < 0)
                                       RaWindowStartLine = 0;
                                    RaWindowModified = RA_MODIFIED;
                                 } else
                                    beep();
                                 break;

                              case 'b': {
                                 int startline = RaWindowCursorY + RaWindowStartLine;
                                 struct ArgusRecordStruct *ns;

                                 if ((RaWindowCursorX == 0)) {
                                    if (RaWindowCursorY > 1) {
                                          RaWindowCursorY--;
                                    } else {
                                       if (RaWindowStartLine > 0) {
                                          RaWindowStartLine--;
                                          ArgusUpdateScreen();
                                       } else {
                                          beep();
                                          break;
                                       }
                                    }

                                    startline = RaWindowCursorY + RaWindowStartLine;
                                    if (startline == 0) {
                                       startline = 1;
                                    }
                                 }

                                 if (RaSortItems >= startline) {
                                    if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[startline - 1]) != NULL) {
                                       char buf[MAXSTRLEN], *ptr;

                                       if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != startline)) {
                                          char buf[MAXSTRLEN];

                                          if (ns->disp.str != NULL)
                                             free(ns->disp.str);

                                          buf[0] = '\0';
                                          ns->rank = startline;
                                          ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                                          ns->disp.str = strdup(buf);
                                          ns->status &= ~ARGUS_RECORD_MODIFIED;
                                       }

                                       bcopy(ns->disp.str, buf, strlen(ns->disp.str) + 1);

                                       if (RaWindowCursorX == 0)
                                          RaWindowCursorX = strlen(buf) - 1;

                                       if ((ptr = &buf[RaWindowCursorX]) != NULL) {
                                          while ((ptr > buf) && isspace((int)*(ptr - 1)))
                                             ptr--;

                                          if (ispunct((int)*(--ptr))) {
                                             while ((ptr > buf) && ispunct((int)*(ptr - 1)))
                                                ptr--;
                                          } else {
                                             while ((ptr > buf) && !(isspace((int)*(ptr - 1)) || ispunct((int)*(ptr - 1))))
                                                ptr--;
                                          }
                                          RaWindowCursorX = ptr - buf;
                                       }
                                    }
                                 }
                                 break;
                              }

                              case 'w': {
                                 int startline = RaWindowCursorY + RaWindowStartLine;
                                 struct ArgusRecordStruct *ns;

                                 if (startline == 0)
                                    startline = 1;

                                 if (RaSortItems >= startline) {
                                    int done = 0;
                                    int shifted = 0;

                                    while (!done) {
                                       if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[startline - 1]) != NULL) {
                                          char buf[MAXSTRLEN], *ptr;
                                          int cursor, passpunct = 0;

                                          if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != startline)) {
                                             char buf[MAXSTRLEN];

                                             if (ns->disp.str != NULL)
                                                free(ns->disp.str);

                                             buf[0] = '\0';
                                             ns->rank = startline;
                                             ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                                             ns->disp.str = strdup(buf);
                                             ns->status &= ~ARGUS_RECORD_MODIFIED;
                                          }

                                          bcopy(ns->disp.str, buf, strlen(ns->disp.str) + 1);

                                          if (!shifted) {
                                             cursor = RaWindowCursorX + 1;
                                             if (ispunct((int)buf[RaWindowCursorX]))
                                                passpunct = 1;
                                          } else
                                             cursor = RaWindowCursorX;

                                          if ((ptr = &buf[cursor]) != NULL) {
                                             if (!shifted)
                                                while ((*ptr != '\0') && !(isspace((int)*ptr)) && (passpunct ? ispunct((int)*ptr) : !(ispunct((int)*ptr))))
                                                   ptr++;
                                             while (isspace((int)*ptr) && (*ptr != '\0'))
                                                ptr++;
                                             if (*ptr != '\0') {
                                                RaWindowCursorX = ptr - buf;
                                                done++;
                                             } else {
                                                if (RaWindowCursorY == RaDisplayLines) {
                                                   if (RaTopProcess->queue->array[startline] != NULL) {
                                                      shifted++;
                                                      startline++;
                                                      RaWindowStartLine++;
                                                      ArgusUpdateScreen();
                                                      RaWindowCursorX = 0;
                                                   }
                                                } else {
                                                   shifted++;
                                                   startline++;
                                                   RaWindowCursorY++;
                                                   RaWindowCursorX = 0;
                                                }
                                             }
                                          }
                                       }
                                    }
                                 }
                                 break;
                              }

                              case '0':
                              case '^': {
                                 RaWindowCursorX = 0;
                                 break;
                              }
                              case '$': {
                                 int startline = RaWindowCursorY + RaWindowStartLine;
                                 struct ArgusRecordStruct *ns;

                                 if (startline == 0)
                                    startline = 1;

                                 if (RaSortItems >= startline) {
                                    if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[startline - 1]) != NULL) {
                                       char buf[MAXSTRLEN];
                                       int len = strlen(ns->disp.str);

                                       if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != startline)) {
                                          char buf[MAXSTRLEN];

                                          if (ns->disp.str != NULL)
                                             free(ns->disp.str);

                                          buf[0] = '\0';
                                          ns->rank = startline;
                                          ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                                          ns->disp.str = strdup(buf);
                                          ns->status &= ~ARGUS_RECORD_MODIFIED;
                                       }

                                       len = strlen(ns->disp.str);
                                       bcopy(ns->disp.str, buf, len + 1);
                                       if ((RaWindowCursorX = len - 1) < 0)
                                          RaWindowCursorX = 0;
                                    }
                                 }
                                 break;
                              }

                              case '?':
                                 bzero (ArgusParser->RaDebugString, sizeof(ArgusParser->RaDebugString));
                                 ArgusParser->RaDebugStatus = 0;
#if defined(ARGUS_READLINE)
                                 argus_getsearch_string(ARGUS_BACKWARD);
#else
                                 retn = RAGETTINGslash;
                                 RaInputString = "?";
                                 ArgusSearchDirection = ARGUS_BACKWARD;
                                 bzero(RaCommandInputStr, MAXSTRLEN);
                                 RaCommandIndex = 0;
                                 RaWindowCursorX = 0;
#endif
                                 break;

                              case '/':
                                 bzero (ArgusParser->RaDebugString, sizeof(ArgusParser->RaDebugString));
                                 ArgusParser->RaDebugStatus = 0;
#if defined(ARGUS_READLINE)
                                 argus_getsearch_string(ARGUS_FORWARD);
#else
                                 retn = RAGETTINGslash;
                                 RaInputString = "/";
                                 ArgusSearchDirection = ARGUS_FORWARD;
                                 bzero(RaCommandInputStr, MAXSTRLEN);
                                 RaCommandIndex = 0;
                                 RaWindowCursorX = 0;
#endif
                                 break;

                              case ':': {
                                 bzero (ArgusParser->RaDebugString, sizeof(ArgusParser->RaDebugString));
                                 ArgusParser->RaDebugStatus = 0;
#if defined(ARGUS_READLINE)
                                 argus_command_string();
#else
                                 retn = RAGETTINGcolon;
                                 RaInputString = ":";
                                 bzero(RaCommandInputStr, MAXSTRLEN);
                                 RaCommandIndex = 0;
                                 RaWindowCursorX = 0;
#endif
                                 break;
                              }
                           }
                           break;
                        }

                        case RAGETTINGq:
                           if (*RaCommandInputStr == 'y') {
                              RaParseComplete(SIGINT);
                           } else {
                              retn = RAGOTslash;
                              RaInputString = RANEWCOMMANDSTR;
                              RaCommandInputStr[0] = '\0';
                              RaCommandIndex = 0;
                           }
                           break;


                        case RAGETTINGcolon: {
                           if (RaCommandIndex == 0) {
                              switch (ch) {
                                 case '%': {
                                    ArgusParser->Pctflag = (ArgusParser->Pctflag == 1) ? 0 : 1;
                                    if (ArgusParser->Pctflag)
                                       RaInputString = "Toggle percent on";
                                    else
                                       RaInputString = "Toggle percent off";
                                    break;
                                 }

                                 case 'a': {
                                    retn = RAGETTINGa;
                                    RaInputString = RAGETTINGaSTR;
                                    break;
                                 }

                                 case 'c': {
                                    break;
                                 }

                                 case 'd': {
                                    retn = RAGETTINGd;
                                    RaInputString = RAGETTINGdSTR;

                                    if (ArgusParser->ArgusRemoteHostList) {
                                       struct ArgusInput *input = (void *)ArgusParser->ArgusActiveHosts->start;
                                       do {
                                          sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s:%d", input->hostname, input->portnum);
                                          RaCommandIndex = strlen(RaCommandInputStr); 
                                          input = (void *)input->qhdr.nxt;
                                       } while (input != (void *)ArgusParser->ArgusActiveHosts->start);
                                    }

                                    break;
                                 }
                   
                                 case 'D': {
                                    retn = RAGETTINGD;
                                    RaInputString = RAGETTINGDSTR;
                                    sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d", ArgusParser->debugflag);
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;
                                 }

                                 case 'e': {
                                    retn = RAGETTINGe;
                                    RaInputString = RAGETTINGeSTR;
                                    if (ArgusParser->estr) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", ArgusParser->estr);
                                    } 
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;
                                 }

                                 case 'f': {
                                    retn = RAGETTINGf;
                                    RaInputString = RAGETTINGfSTR;
                                    RaFilterIndex = 3;
                                    if (ArgusParser->ArgusRemoteFilter) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " remote %s", ArgusParser->ArgusRemoteFilter);
                                       RaFilterIndex = ARGUS_REMOTE_FILTER;
                                    } else
                                    if (ArgusParser->ArgusLocalFilter) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " local %s", ArgusParser->ArgusLocalFilter);
                                       RaFilterIndex = ARGUS_LOCAL_FILTER;
                                    } else
                                    if (ArgusParser->ArgusDisplayFilter) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " display %s", ArgusParser->ArgusDisplayFilter);
                                       RaFilterIndex = ARGUS_DISPLAY_FILTER;
                                    }
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;
                                 }

                                 case 'm': {
                                    struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
                                    struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
                                    int i;

                                    retn = RAGETTINGm;
                                    RaInputString = RAGETTINGmSTR;

                                    if (agg->modeStr != NULL) {
                                       sprintf (RaCommandInputStr, "%s", agg->modeStr);
                                    } else {
                                       for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                                          if (agg->mask & (0x01LL << i)) {
                                             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", ArgusMaskDefs[i].name);

                                             switch (i) {
                                                case ARGUS_MASK_SADDR:
                                                   if (agg->saddrlen > 0)
                                                      sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "/%d", agg->saddrlen);
                                                   break;
                                                case ARGUS_MASK_DADDR:
                                                   if (agg->daddrlen > 0)
                                                      sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "/%d", agg->daddrlen);
                                                   break;
                                             }
                                          }
                                       }

                                       agg->modeStr = strdup(RaCommandInputStr);
                                    }

                                    RaCommandIndex = strlen(RaCommandInputStr);
                                    break;
                                 }

                                 case 'M': {
                                    struct ArgusModeStruct *mode;
                                    retn = RAGETTINGM;
                                    RaInputString = RAGETTINGMSTR;
                           
                                    if ((mode = ArgusParser->ArgusModeList) != NULL) {
                                       while (mode) {
                                          sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", mode->mode);
                                          mode = mode->nxt;
                                       }
                                    }
                                    RaCommandIndex = strlen(RaCommandInputStr);
                                    break;
                                 }

                                 case 'N':
                                    retn = RAGETTINGN;
                                    RaInputString = RAGETTINGNSTR;
                                    break;

                                 case 'p': {
                                    retn = RAGETTINGp;
                                    RaInputString = RAGETTINGpSTR;
                                    sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d", ArgusParser->pflag);
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;
                                 }

                                 case 'P': {
                                    double pause = ArgusParser->Pauseflag;

                                    ArgusParser->Pauseflag = (pause > 0.0) ? 0.0 : 1.0;

                                    if (ArgusParser->Pauseflag)
                                       RaInputString = "Paused";
                                    else
                                       RaInputString = "";
                                    break;
                                 }

                                 case 't':
                                    retn = RAGETTINGt;
                                    RaInputString = RAGETTINGtSTR;
                                    if (ArgusParser->timearg) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", ArgusParser->timearg);
                                    }
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;

                                 case 'T':
                                    retn = RAGETTINGT;
                                    RaInputString = RAGETTINGTSTR;
                                    sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d.%06d",
                                       (int)ArgusParser->timeout.tv_sec, (int)ArgusParser->timeout.tv_usec);
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;

                                 case 'R': {
                                    struct ArgusInput *input = ArgusParser->ArgusInputFileList;
                                    retn = RAGETTINGR;
                                    RaInputString = RAGETTINGRSTR;
                                    while (input) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", input->filename);
                                       RaCommandIndex = strlen(RaCommandInputStr); 
                                       input = (void *)input->qhdr.nxt;
                                    }
                                    break;
                                 }

                                 case 'r': {
                                    struct ArgusInput *input = ArgusParser->ArgusInputFileList;
                                    retn = RAGETTINGr;
                                    RaInputString = RAGETTINGrSTR;
                                    while (input) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", input->filename);
                                       RaCommandIndex = strlen(RaCommandInputStr); 
                                       input = (void *)input->qhdr.nxt;
                                    }
                                    break;
                                 }

                                 case 'S': {
                                    struct ArgusInput *input = ArgusParser->ArgusRemoteHostList;
                                    retn = RAGETTINGS;
                                    RaInputString = RAGETTINGSSTR;
                                    while (input) {
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s:%d", input->hostname, input->portnum);
                                       RaCommandIndex = strlen(RaCommandInputStr); 
                                       input = (void *)input->qhdr.nxt;
                                    }
                                    break;
                                 }

                                 case 's': {
                                    int x, y;
                                    retn = RAGETTINGs;
                                    RaInputString = RAGETTINGsSTR;
                                    for (x = 0; x < ARGUS_MAX_SORT_ALG; x++) {
                                       if (ArgusSorter->ArgusSortAlgorithms[x]) {
                                          for (y = 0; y < ARGUS_MAX_SORT_ALG; y++) {
                                             if (ArgusSorter->ArgusSortAlgorithms[x] == ArgusSortAlgorithmTable[y]) {
                                                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", 
                                                      ArgusSortKeyWords[y]);
                                                break;
                                             }
                                          }
                                       }
                                    }
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;
                                 }

                                 case 'u':
                                    retn = RAGETTINGu;
                                    RaInputString = RAGETTINGuSTR;
                                    sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d.", (int) RaTopUpdateInterval.tv_sec);
                                    sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%06d",(int) RaTopUpdateInterval.tv_usec);
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;

                                 case 'U':
                                    retn = RAGETTINGU;
                                    RaInputString = RAGETTINGUSTR;
                                    sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%2.2f", RaUpdateRate);
                                    RaCommandIndex = strlen(RaCommandInputStr); 
                                    break;

                                 case 'w':
                                    retn = RAGETTINGw;
                                    RaInputString = RAGETTINGwSTR;
                                    break;

                                 case 'F': {
                                    retn = RAGETTINGF;
                                    RaInputString = RAGETTINGFSTR;

                                    for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                                       int y;
                                       if (parser->RaPrintAlgorithmList[x] != NULL) {
                                          for (y = 0; y < MAX_PRINT_ALG_TYPES; y++) {
                                             if ((void *) parser->RaPrintAlgorithmList[x]->print == (void *) RaPrintAlgorithmTable[y].print) {
                                                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s:%d ",
                                                   RaPrintAlgorithmTable[y].field, RaPrintAlgorithmTable[y].length);
                                                break;
                                             }
                                          }
                                       } else
                                          break;
                                    }
                                    RaCommandIndex = strlen(RaCommandInputStr);
                                    break;
                                 }

                                 case 'Q':
                                    retn = RAGETTINGq;
                                    RaInputString = RAGETTINGqSTR;
                                    break;

                                 case 'H':
                                    ArgusParser->Hflag = ArgusParser->Hflag ? 0 : 1;
                                    break;

                                 case 'h':
                                    retn = RAGETTINGh;
                                    RaInputString = RAGETTINGhSTR;
                                    RaWindowStatus = 0;
                                    RaOutputHelpScreen();
                                    break;

                                 case 'n':
                                    if (++ArgusParser->nflag > 3) {
                                       ArgusParser->nflag = 0;
                                    }
                                    break;

                                 case 'v': 
                                    if (ArgusParser->vflag) {
                                       ArgusParser->vflag = 0;
                                       ArgusReverseSortDir = 0;
                                    } else {
                                       ArgusParser->vflag = 1;
                                       ArgusReverseSortDir++;
                                    }
#if defined(ARGUS_THREADS)
                                    pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
                                    RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);
#if defined(ARGUS_THREADS)
                                    pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
                                    break;

                                 case '=':  {
                                    struct ArgusRecordStruct *ns = NULL;

                                    werase(RaWindow);
                                    ArgusUpdateScreen();
#if defined(ARGUS_THREADS)
                                    pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
                                    while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaTopProcess->queue, ARGUS_NOLOCK)) != NULL) 
                                       ArgusDeleteRecordStruct (ArgusParser, ns);

                                    ArgusEmptyHashTable(RaTopProcess->htable);
                                    ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                                    ArgusParser->RaClientUpdate.tv_sec = 0;
                                    ArgusParser->ArgusTotalRecords = 0;
                                    RaTopStartTime.tv_sec = 0;
                                    RaTopStartTime.tv_usec = 0;
                                    RaTopStopTime.tv_sec = 0;
                                    RaTopStopTime.tv_usec = 0;
                                    ArgusParser->ns = NULL;
#if defined(ARGUS_THREADS)
                                    pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
                                    break;
                                 }

                                 case 'z':  
                                    if (++ArgusParser->zflag > 1) {
                                       ArgusParser->zflag = 0;
                                    }
                                    break;

                                 case 'Z':  
                                    switch (ArgusParser->Zflag) {
                                       case '\0': ArgusParser->Zflag = 'b'; break;
                                       case  'b': ArgusParser->Zflag = 's'; break;
                                       case  's': ArgusParser->Zflag = 'd'; break;
                                       case  'd': ArgusParser->Zflag = '\0'; break;
                                    }
                                    break;

                                 default:
                                    RaCommandInputStr[RaCommandIndex++] = ch;
                                    break;

                              }
                              break;
                           }

                        }

                        default: {
                           switch (ch) {
                              case KEY_RIGHT:
                                 if (--RaCursorOffset < 0)
                                    RaCursorOffset = 0;
                                 break;
                              case KEY_LEFT:
                                 if (++RaCursorOffset > RaCommandIndex)
                                    RaCursorOffset = RaCommandIndex;
                                 break;
        
                              default:
                                 if (isascii(ch)) {
                                    if (RaCursorOffset == 0) 
                                       RaCommandInputStr[RaCommandIndex++] = ch;
                                    else {
                                       int z, start; 
                                       start = RaCommandIndex - RaCursorOffset;
                                       for (z = RaCommandIndex; z > start; z--)
                                          RaCommandInputStr[z] = RaCommandInputStr[z-1];

                                       RaCommandInputStr[start] = ch;
                                       RaCommandIndex++;
                                    }
                                 }
                           }
                           break;
                        }
                     }
                  }
                  break;
               }
            }
         }
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (2, "ArgusProcessCommand (0x%x, %d, %d)", parser, status, ch);
#endif

   return (retn);
}
#endif



void
parse_arg (int argc, char**argv)
{}

void
usage ()
{
   extern char version[];

#if defined(ARGUS_CURSES)
   ArgusWindowClose();
#endif

   fprintf (stdout, "Ratop Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [ra-options] [- filter-expression]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -C <[host]:port>   specify remote Cisco Netflow source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stdout, "         -D <level>         specify debug level\n");
#endif
   fprintf (stdout, "         -M nocurses        run without curses window (useful for debugging)\n");
   fprintf (stdout, "         -R <directory>     recursively process argus data files in directory.\n");
   fprintf (stdout, "         -r <filename>      read argus data filename.\n");
   fprintf (stdout, "         -S <host[:port]>   specify remote argus <host> and optional port\n");
   fprintf (stdout, "                            number.\n");
#if defined(ARGUS_SASL)
   fprintf (stdout, "         -U <user/auth>     specify <user/auth> authentication information.\n");
#endif
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

   If the ns cache is a sticky ns, it may not be in the RaTopProcess
   queue, so we need to check and put it in if necessary.

   And because we had a record, we'll indicate that the window needs
   to be updated.

   All screen operations, queue timeouts etc, are done in 
   ArgusClientTimeout, so we're done here.

*/

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_EVENT:
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
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
            RaProcessThisRecord(parser, ns);

#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
         }
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessRecord (0x%x, 0x%x)\n", parser, ns);
#endif
}

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusRecordStruct *tns = NULL, *pns = NULL;
   struct ArgusRecordStruct *cns = ArgusCopyRecordStruct(ns);
   struct RaBinProcessStruct *RaBinProcess = parser->RaBinProcess;
   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
   struct ArgusTimeObject *time = (void *) ns->dsrs[ARGUS_TIME_INDEX];
   struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusHashStruct *hstruct = NULL;
   int found = 0;

   if (time != NULL) {
      ArgusThisTime.tv_sec  = time->src.start.tv_sec;
      ArgusThisTime.tv_usec = time->src.start.tv_usec;
   }

   if (ArgusLastTime.tv_sec == 0) {
      ArgusLastTime    = ArgusThisTime;
      ArgusCurrentTime = ArgusThisTime;
   }

   if (!((ArgusLastTime.tv_sec  > ArgusThisTime.tv_sec) ||
      ((ArgusLastTime.tv_sec == ArgusThisTime.tv_sec) &&
       (ArgusLastTime.tv_usec > ArgusThisTime.tv_usec)))) {

      while (ArgusParser->Pauseflag) {
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
         struct timespec ts = {0, 25000000};
         nanosleep (&ts, NULL);
         ArgusClientTimeout ();
#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
      }

/* ok so lets deal with realtime processing */
      if (!(parser->Sflag) && (RaTopRealTime)) {
         if ((ArgusThisTime.tv_sec  > ArgusLastTime.tv_sec) ||
            ((ArgusThisTime.tv_sec == ArgusLastTime.tv_sec) &&
             (ArgusThisTime.tv_usec > ArgusLastTime.tv_usec))) {
            int thisRate;
            int deltausec;

/* this record is some period of time after the last record, so 
lets calculate the difference, and then sleep to deal with
time that needs to lapse */

            RaDiffTime(&ArgusThisTime, &ArgusLastTime, &dRealTime);
            thisUsec  = ((dRealTime.tv_sec * 1000000) + dRealTime.tv_usec)/RaUpdateRate;

            RaDiffTime(&parser->ArgusRealTime, &ArgusLastRealTime, &dRealTime);
            lastUsec  = ((dRealTime.tv_sec * 1000000) + dRealTime.tv_usec)/RaUpdateRate;

            while ((deltausec = (thisUsec - lastUsec)) > 0) {
               struct timespec ts;
               thisRate = (deltausec > 50000) ? 50000 : deltausec;
#if defined(ARGUSDEBUG)
               ArgusDebug (6, "ArgusProcessThisRecord () idling needed for %d usecs\n", deltausec); 
#endif
               ts.tv_sec  = 0;
               ts.tv_nsec = thisRate * 1000;
               nanosleep (&ts, NULL);
               ArgusClientTimeout ();

               RaDiffTime(&parser->ArgusRealTime, &ArgusLastRealTime, &dRealTime);
               lastUsec  = ((dRealTime.tv_sec * 1000000) + dRealTime.tv_usec)/RaUpdateRate;
            }
         }
      }

      ArgusLastRealTime = parser->ArgusRealTime;
      ArgusLastTime     = ArgusThisTime;
      ArgusCurrentTime  = ArgusThisTime;
   }

   RaTopStopTime = parser->ArgusRealTime;
   if (ArgusParser->RaClientUpdate.tv_sec == 0) {
      ArgusParser->RaClientUpdate.tv_sec = parser->ArgusGlobalTime.tv_sec;
      ArgusParser->RaClientUpdate.tv_usec = 0;
   }
   if (RaTopStartTime.tv_sec == 0)
      RaTopStartTime = parser->ArgusRealTime;

   while (agg && !found) {
      struct nff_insn *fcode = agg->filter.bf_insns;

      if (ArgusFilterRecord (fcode, ns) != 0) {
         if (flow != NULL) {
            if ((agg->rap = RaFlowModelOverRides(agg, cns)) == NULL)
               agg->rap = agg->drap;

            ArgusGenerateNewFlow(agg, cns);

            if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
               ArgusLog (LOG_ERR, "RaProcessRecord: ArgusGenerateHashStruct error %s", strerror(errno));

            if ((pns = ArgusFindRecord(RaTopProcess->htable, hstruct)) == NULL) {
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

                  if ((pns = ArgusFindRecord(RaTopProcess->htable, hstruct)) != NULL) {
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
            if (pns->qhdr.queue != RaTopProcess->queue)
               ArgusRemoveFromQueue (pns->qhdr.queue, &pns->qhdr, ARGUS_LOCK);
            else
               ArgusRemoveFromQueue (pns->qhdr.queue, &pns->qhdr, ARGUS_NOLOCK);

            ArgusAddToQueue (RaTopProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
            pns->status |= ARGUS_RECORD_MODIFIED;
         }
         found++;

      } else
         agg = agg->nxt;
   }

   if (!found)
      if ((hstruct = ArgusGenerateHashStruct(agg, cns, flow)) == NULL)
         ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

   ArgusAlignInit(parser, ns, &RaBinProcess->nadp);

   while ((tns = ArgusAlignRecord(parser, cns, &RaBinProcess->nadp)) != NULL) {
      int offset = 0;

      if (pns) {
         if (pns->bins) {
            offset = parser->Bflag / pns->bins->size;
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

         ArgusRemoveFromQueue(RaTopProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
         ArgusAddToQueue (RaTopProcess->queue, &pns->qhdr, ARGUS_NOLOCK);

      } else {
         if ((pns =  ArgusCopyRecordStruct(tns)) != NULL) { /* new record */
            if (RaBinProcess->nadp.mode == ARGUSSPLITRATE) {
               if ((pns->bins = (struct RaBinProcessStruct *)ArgusNewRateBins(parser, pns)) == NULL)
                  ArgusLog (LOG_ERR, "ArgusProcessThisRecord: ArgusNewRateBins error %s", strerror(errno));

               offset = parser->Bflag / pns->bins->size;

               if (!(ArgusInsertRecord (parser, pns->bins, tns, offset))) 
                  ArgusDeleteRecordStruct(ArgusParser, tns);

               pns->bins->status |= RA_DIRTYBINS;

            } else
               ArgusDeleteRecordStruct(ArgusParser, tns);

            pns->status |= ARGUS_RECORD_MODIFIED;

            pns->htblhdr = ArgusAddHashEntry (RaTopProcess->htable, pns, hstruct);
            ArgusAddToQueue (RaTopProcess->queue, &pns->qhdr, ARGUS_NOLOCK);
         }
      }

      RaWindowModified = RA_MODIFIED;
   }

   ArgusDeleteRecordStruct(ArgusParser, cns);

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessThisRecord () returning\n"); 
#endif
}

void
RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
 
#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessManRecord () returning\n"); 
#endif
}

int RaSendArgusRecord(struct ArgusRecordStruct *ns) {return 0;}

void ArgusWindowClose(void);

void
ArgusWindowClose(void)
{ 
   if (!(ArgusWindowClosing++)) {
#if defined(ARGUS_CURSES)
      struct timeval tvbuf, *tvp = &tvbuf;
      fd_set in;
      int ch;

      if (RaCursesInit && (!(isendwin()))) {
         tvp->tv_sec = 0; tvp->tv_usec = 0;
         FD_ZERO(&in); FD_SET(0, &in);

         while (select(1, &in, 0, 0, tvp) > 0)
            if ((ch = wgetch(RaWindow)) == ERR)
               break;

         endwin();
         printf("\n");
      }
#endif
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}


#if defined(ARGUS_CURSES)
int 
RaInitCurses (struct ArgusParserStruct *parser)
{
#if defined(ARGUS_COLOR_SUPPORT)
   chtype ch;
#endif

   RaCursesInit++;

   srandom(parser->ArgusRealTime.tv_usec);
   parser->RaCursesMode = 1;

#if defined(HAVE_SETENV)
   if (setenv("ESCDELAY", "0", 1) < 0)
      sprintf (ArgusParser->RaDebugString, "setenv(ESCDELAY, 0, 1) error %s", strerror(errno));
      ArgusParser->RaDebugStatus = LOG_ERR;
#else
   {
      char buf[16];
      sprintf (buf, "ESCDELAY=0");
      if (putenv(buf) < 0) {
         sprintf (ArgusParser->RaDebugString, "putenv(%s) error %s", buf, strerror(errno));
         ArgusParser->RaDebugStatus = LOG_ERR;
      }
   }
#endif

   RaWindow = initscr();

#if defined(ARGUS_COLOR_SUPPORT)
   if (has_colors() == TRUE) {
      ArgusTerminalColors++;
      start_color();

      ch = getbkgd(RaWindow);

      if (can_change_color()) {
         init_color(COLOR_GREEN, 0, 200, 0);
      }

      init_pair(1, COLOR_WHITE, COLOR_BLACK);
      init_pair(2, COLOR_GREEN, COLOR_BLACK);
      init_pair(3, COLOR_RED,   COLOR_BLACK);

      wbkgdset(RaWindow, ch | COLOR_PAIR(1));
      wattrset(RaWindow, COLOR_PAIR(1));
   }
#endif

   cbreak();

#if defined(ARGUS_READLINE)
   keypad(stdscr, FALSE);
#else
   keypad(stdscr, TRUE);
#endif
   meta(stdscr, TRUE);
   nodelay(RaWindow, TRUE);
   noecho();
   nonl();
   intrflush(stdscr, FALSE);

   clearok(RaWindow, TRUE);
   werase(RaWindow);
   wrefresh(RaWindow);

   getmaxyx(RaWindow, RaScreenLines, RaScreenColumns);
 
   RaHeaderWindow = newwin (RaHeaderWinSize, RaScreenColumns, 0, 0);
   RaWindowLines  = RaScreenLines - RaHeaderWinSize;
   RaWindowStartLine = 0;
   RaDisplayLines = RaWindowLines - 2;

   RaAvailableWindow = newwin (RaWindowLines, RaScreenColumns, RaHeaderWinSize, 0);

   idlok (RaAvailableWindow, TRUE);
   notimeout(RaAvailableWindow, TRUE);

#if defined(ARGUS_COLOR_SUPPORT)
   if (ArgusTerminalColors) {
      wattrset(RaHeaderWindow, COLOR_PAIR(1) | A_BOLD);
      wattrset(RaAvailableWindow, COLOR_PAIR(1));
   }
#endif

   nodelay(RaWindow, TRUE);
   intrflush(RaWindow, FALSE);
   refresh();

#if defined(ARGUS_READLINE)
#if defined(HAVE_DECL_RL_RESIZE_TERMINAL) && HAVE_DECL_RL_RESIZE_TERMINAL
   rl_resize_terminal();
#endif
#endif

   return (1);
}


void
RaResizeScreen(void)
{
   struct winsize size;

   if (ioctl(fileno(stdout), TIOCGWINSZ, &size) == 0) {
#if defined(__FreeBSD__) || (__NetBSD__) || (__OpenBSD__)
      resizeterm(size.ws_row, size.ws_col);
#else
#if defined(ARGUS_SOLARIS)
#else
      resize_term(size.ws_row, size.ws_col);
#endif
#endif
      wrefresh(RaWindow);   /* Linux needs this */
   }

   getmaxyx(RaWindow, RaScreenLines, RaScreenColumns);

   RaWindowLines = RaScreenLines - RaHeaderWinSize;
   RaDisplayLines = RaWindowLines - 2;

#if !defined(ARGUS_SOLARIS)
   wresize(RaWindow, RaScreenLines, RaScreenColumns);
   wresize(RaHeaderWindow, RaHeaderWinSize, RaScreenColumns);

   if (RaScreenMove == TRUE) {
      wresize(RaAvailableWindow, RaDisplayLines + 1, RaScreenColumns);
      getbegyx(RaAvailableWindow, RaScreenStartY, RaScreenStartX);
      if (mvwin(RaAvailableWindow, RaScreenStartY + 1, RaScreenStartX) == ERR)
         ArgusLog (LOG_ERR, "RaResizeScreen: mvwin %d, %d returned ERR\n", RaScreenStartY + 5, RaScreenStartX);

      RaScreenMove = FALSE;
   } else
      wresize(RaAvailableWindow, RaDisplayLines + 1, RaScreenColumns);


#else
   delwin(RaHeaderWindow);
   RaHeaderWindow = newwin (RaHeaderWinSize, RaScreenColumns, 0, 0);
   idlok (RaHeaderWindow, TRUE);
   notimeout(RaHeaderWindow, TRUE);
 
   delwin(RaAvailableWindow);
   RaAvailableWindow = newwin (RaWindowLines, RaScreenColumns, RaHeaderWinSize, 0);
   idlok (RaAvailableWindow, TRUE);
   notimeout(RaAvailableWindow, TRUE);
#endif/* ARGUS_SOLARIS */

   idlok (RaWindow, TRUE);
   notimeout(RaWindow, TRUE);
   nodelay(RaWindow, TRUE);
   intrflush(RaWindow, FALSE);

   RaWindow = initscr();
   wclear(RaWindow);

   ArgusParser->RaLabel = NULL;
   ArgusUpdateScreen();
   RaRefreshDisplay(ArgusParser);

   RaScreenResize = FALSE;
}


void
RaOutputModifyScreen ()
{
   int i = 0;
   werase(RaAvailableWindow);
   for (i = RaMinCommandLines; i < (RaMaxCommandLines + 1); i++) {
      mvwprintw (RaAvailableWindow, i, 1, RaCommandArray[i - RaMinCommandLines]);
      if (i == RaMinCommandLines)
         wstandout(RaAvailableWindow);
      wprintw (RaAvailableWindow, "%s", RaCommandValueArray[i - RaMinCommandLines]());
      if (i == RaMinCommandLines)
         wstandend(RaAvailableWindow);
   }
}

void
RaOutputHelpScreen ()
{
   extern char version[];
   werase(RaAvailableWindow);
   mvwprintw (RaAvailableWindow, 0, 1, "RaTop Version %s\n", version);
   mvwprintw (RaAvailableWindow, 1, 1, "Key Commands: c,d,D,f,F,h,m,n,N,p,P,q,r,R,s,S,t,T,u,U,v,w,z,Z,=");
   mvwprintw (RaAvailableWindow, 3, 1, "  ^D - Clear command line. Reset input (also ESC).");
   mvwprintw (RaAvailableWindow, 4, 1, "   c - Connect to remote Argus Source");
   mvwprintw (RaAvailableWindow, 5, 1, "   d - Drop connection from remote argus source");
   mvwprintw (RaAvailableWindow, 6, 1, "   D - Set debug printing level");
   mvwprintw (RaAvailableWindow, 7, 1, "   f - Specify filter expression");
   mvwprintw (RaAvailableWindow, 8, 1, "   F - Specify fields to print (use arrow keys to navigate).");
   mvwprintw (RaAvailableWindow, 9, 1, "         +[#]field - add field to optional column # or end of line");
   mvwprintw (RaAvailableWindow,10, 1, "         -field    - remove field from display");
   mvwprintw (RaAvailableWindow,11, 1, "          field    - reset fields and add to display");
   mvwprintw (RaAvailableWindow,12, 1, "             available fields are:");
   mvwprintw (RaAvailableWindow,13, 1, "               srcid, stime, ltime, dur, avgdur, trans, flgs, dir, state, seq, bins, binnum");
   mvwprintw (RaAvailableWindow,14, 1, "               mac, smac, dmac, mpls, smpls, dmpls, vlan, svlan, dvlan, svid, dvid, svpri, dvpri");
   mvwprintw (RaAvailableWindow,15, 1, "               saddr, daddr, snet, dnet, proto, sport, dport, stos, dtos, sttl, dttl, sipid, dipid");
   mvwprintw (RaAvailableWindow,16, 1, "               tcpext, tcprtt, stcpb, dtcpb, swin, dwin, srng, drng, spksz, dpksz, smaxsz, sminsz, dmaxsz, dminsz");
   mvwprintw (RaAvailableWindow,17, 1, "               suser, duser, svc, pkts, spkts, dpkts, load,sload, dload, bytes, sbytes, dbytes, rate, srate, drate");
   mvwprintw (RaAvailableWindow,18, 1, "               sloss, dloss, sintpkt, dintpkt, sjit, djit, sintpktact, dintpktact, sintpktidl, dintpktidl");
   mvwprintw (RaAvailableWindow,19, 1, "               sjitidl, djitidl, ddur, dstime, dltime, dspkts, ddpkts, dsbytes, ddbytes");
   mvwprintw (RaAvailableWindow,20, 1, "               djitact, jitidl, sjitidl, djitidl, state, ddur, dstime, dltime, dspkts, ddpkts");
   mvwprintw (RaAvailableWindow,21, 1, "   H - Toggle number abbreviations.");
   mvwprintw (RaAvailableWindow,21, 1, "   m - Specify the flow model objects.");
   mvwprintw (RaAvailableWindow,22, 1, "   n - Toggle name to number conversion(cycle through).");
   mvwprintw (RaAvailableWindow,23, 1, "   N - Specify the number of items to print.");
   mvwprintw (RaAvailableWindow,24, 1, "   %% - Show percent values.");
   mvwprintw (RaAvailableWindow,25, 1, "   p - Specify precision.");
   mvwprintw (RaAvailableWindow,26, 1, "   P - Pause the program");
   mvwprintw (RaAvailableWindow,27, 1, "   q - Quit the program.");
   mvwprintw (RaAvailableWindow,28, 1, "   r - Read argus data file(s)");
   mvwprintw (RaAvailableWindow,29, 1, "   R - Recursively open argus data files(s)");
   mvwprintw (RaAvailableWindow,30, 1, "   s - Specify sort fields.");
   mvwprintw (RaAvailableWindow,31, 1, "   t - Specify time range. same as -t command line option. ");
   mvwprintw (RaAvailableWindow,32, 1, "   T - Specify idle timeout (float) value [60.0s].");
   mvwprintw (RaAvailableWindow,33, 1, "   u - Specify the window update timer, in seconds [0.1s]");
   mvwprintw (RaAvailableWindow,34, 1, "   U - Specify the playback rate, in seconds per second [1.0]");
   mvwprintw (RaAvailableWindow,35, 1, "   v - reverse the sort order");
   mvwprintw (RaAvailableWindow,36, 1, "   w - Write display to file");
   mvwprintw (RaAvailableWindow,37, 1, "   z - Toggle State field output formats");
   mvwprintw (RaAvailableWindow,38, 1, "   Z - Toggle TCP State field output");
   mvwprintw (RaAvailableWindow,39, 1, "   = - Clear Flow List");
   mvwprintw (RaAvailableWindow,40, 1, "   h - Print help screen.");
   mvwprintw (RaAvailableWindow,42, 1, "Navigation Keys (vi): g,G,h,j,k,l,i,w,$,^,^F,^D,^B,^U");

   wnoutrefresh(RaAvailableWindow);
   doupdate();
}


#endif/* ARGUS_CURSES */


struct RaTopProcessStruct *
RaTopNewProcess(struct ArgusParserStruct *parser)
{
   struct RaTopProcessStruct *retn = NULL;
 
   if ((retn = (struct RaTopProcessStruct *) ArgusCalloc (1, sizeof(*retn))) != NULL) {
      if ((retn->queue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "RaTopNewProcess: ArgusNewQueue error %s\n", strerror(errno));

      if ((retn->delqueue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "RaTopNewProcess: ArgusNewQueue error %s\n", strerror(errno));
 
      if ((retn->htable = ArgusNewHashTable(0x100000)) == NULL)
         ArgusLog (LOG_ERR, "RaTopNewProcess: ArgusCalloc error %s\n", strerror(errno));

   } else
      ArgusLog (LOG_ERR, "RaTopNewProcess: ArgusCalloc error %s\n", strerror(errno));
 
#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaTopNewProcess(0x%x) returns 0x%x\n", parser, retn);
#endif
   return (retn);
}



char RaGetStrBuf[MAXSTRLEN];

char *
RaGetCiscoServers(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", (ArgusParser->Cflag ? "yes" : "no"));
   return(retn);
}

char *
RaGetNoOutputStatus(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", (ArgusParser->qflag ? "yes" : "no"));
   return(retn);
}

char *
RaGetUserAuth(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", ArgusParser->ustr);
   return(retn);
}

char *
RaGetUserPass(void)
{
   char *retn = RaGetStrBuf;
   int i;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", ArgusParser->pstr);
   for (i = 0; i < strlen(RaGetStrBuf); i++)
      RaGetStrBuf[i] = 'x';
   return(retn);
}

char *
RaGetOutputFile(void)
{
   char *retn = RaGetStrBuf;
   struct ArgusWfileStruct *wfile = NULL, *start;

   bzero(RaGetStrBuf, MAXSTRLEN);

   if (ArgusParser->ArgusWfileList != NULL) {
      if ((wfile = (struct ArgusWfileStruct *) ArgusFrontList(ArgusParser->ArgusWfileList)) != NULL) {
         start = wfile;
         do {
            sprintf(&RaGetStrBuf[strlen(RaGetStrBuf)], "%s ", wfile->filename);
            ArgusPopFrontList(ArgusParser->ArgusWfileList, ARGUS_LOCK);
            ArgusPushBackList(ArgusParser->ArgusWfileList, (struct ArgusListRecord *)wfile, ARGUS_LOCK);
            wfile = (struct ArgusWfileStruct *)ArgusFrontList(ArgusParser->ArgusWfileList);
         } while (wfile != start);
      }
      sprintf(RaGetStrBuf, "%s", RaGetStrBuf);
   }
   return(retn);
}

char *
RaGetExceptionOutputFile(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", ArgusParser->exceptfile);
   return(retn);
}

char *
RaGetTimeRange(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", ArgusParser->timearg);
   return(retn);
}

char *
RaGetRunTime(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%d", ArgusParser->Tflag);
   return(retn);
}

char *
RaGetFieldDelimiter(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   if (ArgusParser->RaFieldDelimiter == '\0')
      sprintf(RaGetStrBuf, "'\\0'");
   else
      sprintf(RaGetStrBuf, "'%c'", ArgusParser->RaFieldDelimiter);
   return(retn);
}

char *
RaGetTimeFormat(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", ArgusParser->RaTimeFormat);
   return(retn);
}

char *
RaGetPrecision(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%d", ArgusParser->pflag);
   return(retn);
}

char *
RaGetTimeSeries(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", (ArgusParser->Hstr ? "yes" : "no"));
   return(retn);
}

char *
RaGetValidateStatus(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%s", (ArgusParser->Vflag ? "yes" : "no"));
   return(retn);
}

char *
RaGetNumber(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%d", ArgusParser->eNflag);
   return(retn);
}

char *
RaGetDebugLevel(void)
{
   char *retn = RaGetStrBuf;

   bzero(RaGetStrBuf, MAXSTRLEN);
   sprintf(RaGetStrBuf, "%d", ArgusParser->debugflag);
   return(retn);
}

char *
RaGetUserDataEncode(void)
{
   char *retn = RaGetStrBuf, *str = NULL;

   bzero(RaGetStrBuf, MAXSTRLEN);
   switch (ArgusParser->eflag) {
      case ARGUS_ENCODE_ASCII:
         str = "ascii"; break;
      case ARGUS_ENCODE_32:
         str = "encode32"; break;
      case ARGUS_ENCODE_64:
         str = "encode64"; break;
   }

   sprintf(RaGetStrBuf, "%s", str);
   return(retn);
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
         bzero (tmpbuf, MAXSTRLEN);
         strncpy(tmpbuf, filename, MAXSTRLEN);
         tmpbuf[strlen(tmpbuf) - nadp->slen] = 'z';
         for (i = 0; i < nadp->slen; i++)
            strcat(tmpbuf, "a");
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
   int retn = 0, i, x;

   bzero (resultbuf, len);

   while ((ptr = strchr (tptr, '$')) != NULL) {
      *ptr++ = '\0';
      sprintf (&resultbuf[strlen(resultbuf)], "%s", tptr);

      for (i = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (!strncmp (RaPrintAlgorithmTable[x].field, ptr, strlen(RaPrintAlgorithmTable[x].field))) {
            bzero (tmpbuf, MAXSTRLEN);
            RaPrintAlgorithmTable[x].print(parser, tmpbuf, ns, RaPrintAlgorithmTable[x].length);

            while (isspace((int)tmpbuf[strlen(tmpbuf) - 1]))
               tmpbuf[strlen(tmpbuf) - 1] = '\0';

            while (isspace((int)tmpbuf[i])) i++;
            sprintf (&resultbuf[strlen(resultbuf)], "%s", &tmpbuf[i]);

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

#if defined(ARGUS_CURSES) && (defined(ARGUS_READLINE) || defined(ARGUS_EDITLINE))
int
argus_getch_function(FILE *file)
{
   int retn = wgetch(RaWindow);
   if (retn  != ERR) {
      return retn;
   } else
      return -1;
}


int
argus_readline_timeout(void)
{
   struct ArgusQueueStruct *queue = RaTopProcess->queue;
   int retn = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "argus_readline_timeout()");
#endif

   if (RaWindowModified == RA_MODIFIED) {
      int i;

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&queue->lock);
#endif
      RaTopSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);
      if (ArgusParser->ns) {
         ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
         ArgusParser->ns = NULL;
      }
      for (i = 0; i < queue->count; i++) {
         struct ArgusRecordStruct *ns;
         if ((ns = (struct ArgusRecordStruct *)queue->array[i]) == NULL)
            break;
         if (ArgusParser->ns)
            ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
         else
            ArgusParser->ns = ArgusCopyRecordStruct (ns);
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock);
#endif

      switch (RaInputStatus) {
         case RAGETTINGh:
            break;
         default:
            argus_redisplay_function();
            break;
      }

      RaWindowModified  = 0;
      RaWindowImmediate = FALSE;
   }

   return (retn);
}


int ArgusReadlinePoint = 0;
void
argus_redisplay_function()
{
   int offset = 0, plen, sw = RaScreenColumns - 1;

   if (RaInputStatus == RAGETTINGh) {
      RaWindowStatus = 1;

      RaInputStatus = RAGOTslash;
      RaInputString = RANEWCOMMANDSTR;
      RaCommandInputStr[0] = '\0';
      RaWindowModified = RA_MODIFIED;
#if defined(HAVE_DECL_RL_DONE) && HAVE_DECL_RL_DONE
      rl_done = 1;
#endif
   }

   if (RaInputStatus == RAGETTINGcolon)
      RaInputStatus = argus_process_command (ArgusParser, RaInputStatus);

   sprintf (RaOutputBuffer, "%s", RaInputString);
   plen = strlen(RaOutputBuffer);

   if ((rl_point + 1) > (sw - plen)) {
      offset = (rl_point + 1) - (sw - plen);
      RaOutputBuffer[plen - 1] = '<';
      sprintf (&RaOutputBuffer[plen], "%s", &rl_line_buffer[offset]);
   } else {
      sprintf (&RaOutputBuffer[plen], "%s", rl_line_buffer);
   }

   if (strlen(RaOutputBuffer) > sw)
      RaOutputBuffer[sw] = '>';

#ifdef ARGUSDEBUG
   ArgusDebug (1, "argus_redisplay_function: sw %d plen %d rl_point %d offset %d", sw, plen, rl_point, offset);
#endif

   ArgusUpdateScreen();
   RaRefreshDisplay(ArgusParser);

   mvwaddnstr (RaWindow, RaScreenLines - 1, 0, RaOutputBuffer, sw + 1);
   wclrtoeol(RaWindow);
   if (offset > 0)
      wmove(RaWindow, RaScreenLines - 1, plen + (rl_point - offset));
   else
      wmove(RaWindow, RaScreenLines - 1, plen + rl_point);

   wnoutrefresh(RaWindow);
   doupdate();
}

void
argus_getsearch_string(int dir)
{
   int linenum = RaWindowCursorY;
   int cursx = RaWindowCursorX, cursy = RaWindowCursorY + RaWindowStartLine;
   struct ArgusQueueStruct *queue = RaTopProcess->queue;
   char *line;

#if defined(ARGUS_HISTORY)
   if (!(argus_history_is_enabled()))
      argus_enable_history();
#endif

   ArgusSearchDirection = dir;

   RaInputStatus = RAGETTINGslash;
   RaInputString = (dir == ARGUS_FORWARD) ? "/" : "?";
   ArgusSearchDirection = dir;
   bzero(RaCommandInputStr, MAXSTRLEN);
   RaCommandIndex = 0;

   rl_redisplay_function = argus_redisplay_function;
   ArgusReadlinePoint = 0;

   if ((line = readline("")) != NULL) {
      if (strlen(line) > 0) {
         strcpy (RaCommandInputStr, line);
#if defined(ARGUS_HISTORY)
         if (*line && argus_history_is_enabled()) {
            add_history (line);
         }
#endif
         free(line);
         sprintf(RaLastSearch, "%s", RaCommandInputStr);
      } else {
         if (strlen(RaLastSearch) > 0) 
            sprintf(RaCommandInputStr, "%s", RaLastSearch);
      }

//    RaHighlightDisplay(ArgusParser, RaTopProcess->queue, RaCommandInputStr);
      if ((linenum = RaSearchDisplay(ArgusParser, queue, ArgusSearchDirection, 
               &cursx, &cursy, RaCommandInputStr)) < 0) {
         if (ArgusSearchDirection == ARGUS_FORWARD) {
            sprintf (ArgusParser->RaDebugString, "search hit BOTTOM, continuing at TOP");
            cursx = 0; cursy = 0;
         } else {
            sprintf (ArgusParser->RaDebugString, "search hit TOP, continuing at BOTTOM");
            cursx = RaScreenColumns; cursy = RaSortItems;
         }
         linenum = RaSearchDisplay(ArgusParser, queue, ArgusSearchDirection, &cursx, &cursy, RaCommandInputStr);
      }

      if (linenum >= 0) {
         if ((linenum < RaWindowStartLine) || ((linenum > RaWindowStartLine + RaDisplayLines))) {
            int startline = ((cursy - 1)/ RaDisplayLines) * RaDisplayLines;
            startline = (RaSortItems > startline) ? startline : RaSortItems - RaDisplayLines;
            startline = (startline > 0) ? startline : 0;
            RaWindowStartLine = startline;

            if ((RaWindowCursorY = cursy % RaDisplayLines) == 0)
               RaWindowCursorY = RaDisplayLines;

         } else
            RaWindowCursorY = cursy - RaWindowStartLine;

         RaInputStatus = RAGOTslash;

         RaWindowCursorX = cursx;
         ArgusUpdateScreen();
      } else {
         sprintf (ArgusParser->RaDebugString, "Pattern not found: %s", RaCommandInputStr);
         RaInputStatus = RAGOTslash;
         RaInputString = RANEWCOMMANDSTR;
         bzero(RaCommandInputStr, MAXSTRLEN);
         RaCommandIndex = 0;
      }

      RaInputStatus = RAGOTslash;
      RaInputString = (dir == ARGUS_FORWARD) ? "/" : "?";
   }
}


void
argus_command_string(void)
{
   char *line;

#if defined(ARGUS_HISTORY)
   argus_disable_history();
#endif

   RaInputStatus = RAGETTINGcolon;
   RaInputString = ":";
   bzero(RaCommandInputStr, MAXSTRLEN);
   RaCommandIndex = 0;

   ArgusReadlinePoint = 0;

   if ((line = readline("")) != NULL) {
      if (strlen(line) > 0) {
         strcpy (RaCommandInputStr, line);
         free(line);
         sprintf(RaLastCommand, "%s", RaCommandInputStr);
      } else {
         if (strlen(RaLastCommand) > 0) 
            sprintf(RaCommandInputStr, "%s", RaLastCommand);
      }
   }

   if (*RaCommandInputStr == 'q') {
      bzero (RaCommandInputStr, MAXSTRLEN);
      ArgusUpdateScreen();
      RaParseComplete(SIGINT);
   }

   if (strlen(RaCommandInputStr)) {
      switch(RaInputStatus) {
         case RAGETTINGh: {
            RaWindowStatus = 1;
            RaInputStatus = RAGOTcolon;
            wclear(RaWindow);
            ArgusUpdateScreen();
            RaRefreshDisplay(ArgusParser);
            break;
         }

         case RAGETTINGN: {
            char *ptr = NULL;
            int value = strtol(RaCommandInputStr, (char **)&ptr, 10);

            RaDisplayLinesSet = 1;

            if (ptr != RaCommandInputStr) {
               RaDisplayLines = ((value < (RaScreenLines - (RaHeaderWinSize + 1)) - 1) ?
                                  value : (RaScreenLines - (RaHeaderWinSize + 1)) - 1);
               ArgusUpdateScreen();

            } else
               RaDisplayLinesSet = 0;

            break;
         }

         case RAGETTINGS: {
            if (!(ArgusAddHostList (ArgusParser, RaCommandInputStr, (ArgusParser->Cflag ? ARGUS_CISCO_DATA_SOURCE : ARGUS_DATA_SOURCE), 0))) {
               ArgusLog (LOG_ALERT, "%s%s host not found", RaInputString, RaCommandInputStr);
            } else {
               ArgusParser->Sflag = 1;
               ArgusParser->RaParseDone = 0;
            }
            break;
         }

         case RAGETTINGa: {
            if (!(strncasecmp(RaCommandInputStr, "Totals", 6))) {
               RaScreenResize = TRUE;
               if (ArgusPrintTotals == 0) {
                  ArgusPrintTotals = 1;
                  RaHeaderWinSize++;
                  RaScreenMove = TRUE;
               }
               ArgusUpdateScreen();
            }
            if (!(strncasecmp(RaCommandInputStr, "-Totals", 6))) {
               RaScreenResize = TRUE;
               if (ArgusPrintTotals > 0) {
                  ArgusPrintTotals = 0;
                  RaHeaderWinSize--;
                  RaScreenMove = FALSE;
                  getbegyx(RaAvailableWindow, RaScreenStartY, RaScreenStartX);
                  if (mvwin(RaAvailableWindow, RaScreenStartY - 1, RaScreenStartX) == ERR)
                     ArgusLog (LOG_ERR, "RaResizeScreen: mvwin %d, %d returned ERR\n", RaScreenStartY - 1, RaScreenStartX);
               }
               ArgusUpdateScreen();
            }
         }
         break;

         case RAGETTINGd: {
            struct ArgusInput *input;
            char strbuf[MAXSTRLEN];

            if ((input = (void *)ArgusParser->ArgusActiveHosts->start) != NULL) {
               do {
                  sprintf (strbuf, " %s:%d", input->hostname, input->portnum);
                  if ((strstr (RaCommandInputStr, strbuf))) {
                     ArgusRemoveFromQueue (ArgusParser->ArgusActiveHosts, &input->qhdr, ARGUS_LOCK);
                     ArgusCloseInput(ArgusParser, input);
                     break;
                  }
                  input = (void *)input->qhdr.nxt;
               } while (input != (void *)ArgusParser->ArgusActiveHosts->start);
            }
         }
         break;

         case RAGETTINGD: {
            char *ptr = NULL;
            int value = strtol(RaCommandInputStr, (char **)&ptr, 10);

            if (ptr != RaCommandInputStr)
               ArgusParser->debugflag = value;
            break;
         }

         case RAGETTINGc: {
            break;
         }

         case RAGETTINGe: {
            char *ptr = NULL;

            ptr = RaCommandInputStr;
            while (isspace((int)*ptr)) ptr++;

            ArgusParser->ArgusGrepSource = 1;
            ArgusParser->ArgusGrepDestination = 1;

            if (ArgusParser->estr != NULL)
               free(ArgusParser->estr);
            ArgusParser->estr = strdup(RaCommandInputStr);

            if ((ArgusParser->estr[0] == 's') && (ArgusParser->estr[1] == ':')) {
                  ArgusParser->ArgusGrepDestination = 0;
                  ArgusParser->estr = &ArgusParser->estr[2];
            }
            if ((ArgusParser->estr[0] == 'd') && (ArgusParser->estr[1] == ':')) {
                  ArgusParser->ArgusGrepSource = 0;
                  ArgusParser->estr = &ArgusParser->estr[2];
            }

            break;
         }

         case RAGETTINGf: {
            struct nff_program lfilter;
            char *ptr = NULL, *str = NULL;
            int ind = ARGUS_REMOTE_FILTER;
            int i, retn;

            bzero ((char *) &lfilter, sizeof (lfilter));
            ptr = RaCommandInputStr;
            while (isspace((int)*ptr)) ptr++;

            if ((str = strstr (ptr, "local")) != NULL) {
               ptr = strdup(&str[strlen("local ")]);
               ind = ARGUS_LOCAL_FILTER;
            } else 
            if ((str = strstr (ptr, "display")) != NULL) {
               ptr = strdup(&str[strlen("display ")]);
               ind = ARGUS_DISPLAY_FILTER;
            } else 
            if ((str = strstr (ptr, "remote")) != NULL) {
               ptr = strdup(&str[strlen("remote ")]);
               ind = ARGUS_REMOTE_FILTER;
            } else 
            if ((str = strstr (ptr, "none")) != NULL) {
               ind = RaFilterIndex;
            }

            if ((retn = ArgusFilterCompile (&lfilter, ptr, 1)) < 0) {
               sprintf (ArgusParser->RaDebugString, "%s%s syntax error", RAGETTINGfSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = LOG_ERR;

           } else {
               sprintf (ArgusParser->RaDebugString, "%s%s filter accepted", RAGETTINGfSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = 0;
               if ((str = ptr) != NULL)
                  while (isspace((int)*str)) str++;
               
               switch (ind) {
                  case ARGUS_LOCAL_FILTER:
                     if (ArgusParser->ArgusFilterCode.bf_insns != NULL)
                        free (ArgusParser->ArgusFilterCode.bf_insns);

                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusFilterCode, sizeof(lfilter));
                     if (ArgusParser->ArgusLocalFilter !=  NULL) {
                        free(ArgusParser->ArgusLocalFilter);
                        ArgusParser->ArgusLocalFilter = NULL;
                     }
                     if (strlen(str) > 0)
                        ArgusParser->ArgusLocalFilter = ptr;
                     else
                        if (ptr != NULL) free(ptr);
                     break;

                  case ARGUS_DISPLAY_FILTER:
                     if (ArgusParser->ArgusDisplayCode.bf_insns != NULL)
                        free (ArgusParser->ArgusDisplayCode.bf_insns);

                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusDisplayCode, sizeof(lfilter));
                     bcopy((char *)&lfilter, (char *)&ArgusSorter->filter, sizeof(lfilter));

                     if (ArgusParser->ArgusDisplayFilter !=  NULL) {
                        free(ArgusParser->ArgusDisplayFilter);
                        ArgusParser->ArgusDisplayFilter = NULL;
                     }
                     if (strlen(str) > 0)
                        ArgusParser->ArgusDisplayFilter = ptr;
                     else
                        if (ptr != NULL) free(ptr);
                     break;

                  case ARGUS_REMOTE_FILTER:
                     if (ArgusParser->ArgusFilterCode.bf_insns != NULL)
                        free (ArgusParser->ArgusFilterCode.bf_insns);
                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusFilterCode, sizeof(lfilter));
                     if (ArgusParser->ArgusRemoteFilter !=  NULL) {
                        free(ArgusParser->ArgusRemoteFilter);
                        ArgusParser->ArgusRemoteFilter = NULL;
                     }
                     if (strlen(str) > 0)
                        ArgusParser->ArgusRemoteFilter = ptr;
                     else
                        if (ptr != NULL) free(ptr);
                     break;
               }

#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
               RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);

               if (RaSortItems) {
                  if (ArgusParser->ns) {
                     ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                     ArgusParser->ns = NULL;
                  }
                  for (i = 0; i < RaSortItems; i++) {
                     struct ArgusRecordStruct *ns;
                     if ((ns = (struct ArgusRecordStruct *)RaTopProcess->queue->array[i]) == NULL)
                        break;
                     if (ArgusParser->ns)
                        ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
                     else
                        ArgusParser->ns = ArgusCopyRecordStruct (ns);
                  }
               }
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
               RaWindowStatus = 1;
               ArgusUpdateScreen();
               RaRefreshDisplay(ArgusParser);
            }
            break;
         }
                      
         case RAGETTINGm: {
            struct ArgusRecordStruct *ns = NULL;
            char strbuf[MAXSTRLEN], *tok = NULL, *ptr;
            struct ArgusModeStruct *mode = NULL, *modelist = NULL, *list; 
            struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;
            int i;                                  

            if ((agg->modeStr == NULL) || strcmp(agg->modeStr, RaCommandInputStr)) {
               if (agg->modeStr != NULL)
                  free(agg->modeStr);
               agg->modeStr = strdup(RaCommandInputStr);
               ArgusParser->RaMonMode = 0;
               strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

               if ((mode = ArgusParser->ArgusMaskList) != NULL)
                  ArgusDeleteMaskList(ArgusParser);

               agg->mask = 0;
               agg->saddrlen = 0;
               agg->daddrlen = 0;

               if ((ptr = strbuf) != NULL) {
                  while ((tok = strtok (ptr, " \t")) != NULL) {
                     if ((mode = (struct ArgusModeStruct *) ArgusCalloc (1, sizeof(struct ArgusModeStruct))) != NULL) {
                        if ((list = modelist) != NULL) {
                           while (list->nxt)
                              list = list->nxt;
                           list->nxt = mode;
                        } else
                           modelist = mode;
                        mode->mode = strdup(tok);
                     }
                     ptr = NULL;
                  }
               } else {
                  if ((modelist = ArgusParser->ArgusMaskList) == NULL)
                     agg->mask  = ( ARGUS_MASK_SRCID_INDEX | ARGUS_MASK_PROTO_INDEX |
                                    ARGUS_MASK_SADDR_INDEX | ARGUS_MASK_SPORT_INDEX |
                                    ARGUS_MASK_DADDR_INDEX | ARGUS_MASK_DPORT_INDEX );
               }

               ArgusInitAggregatorStructs(agg);

               if ((mode = modelist) != NULL) {
                  while (mode) {
                     char *ptr = NULL, **endptr = NULL;
                     int value = 0;

                     if ((ptr = strchr(mode->mode, '/')) != NULL) {
                        ptr++;
                        if ((value = strtol(ptr, endptr, 10)) == 0)
                           if (*endptr == ptr)
                              usage();
                     }
                     if (!(strncasecmp (mode->mode, "none", 4))) {
                        agg->mask  = 0;
                     } else
                     if (!(strncasecmp (mode->mode, "mac", 3))) {
                        ArgusParser->RaMonMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SMAC);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "addr", 4))) {
                        ArgusParser->RaMonMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SADDR);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "matrix", 6))) {
                        agg->ArgusMatrixMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SADDR);
                        agg->mask |= (0x01LL << ARGUS_MASK_DADDR);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else {
                        struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs;

                        for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                           if (!(strncasecmp (mode->mode, ArgusMaskDefs[i].name, ArgusMaskDefs[i].slen))) {
                              agg->mask |= (0x01LL << i);
                              switch (i) {
                                 case ARGUS_MASK_SADDR:
                                    if (value > 0) {
                                       agg->saddrlen = value;
                                       if (value <= 32)
                                          agg->smask.addr_un.ipv4 = (0xFFFFFFFF << (32 - value));
                                    }
                                    break;
                                 case ARGUS_MASK_DADDR:
                                    if (value > 0) {
                                       agg->daddrlen = value;
                                       if (value <= 32)
                                          agg->dmask.addr_un.ipv4 = (0xFFFFFFFF << (32 - value));
                                    }
                                    break;

                                 case ARGUS_MASK_SMPLS:
                                 case ARGUS_MASK_DMPLS: {
                                    int x, RaNewIndex = 0;
                                    char *ptr;

                                    if ((ptr = strchr(mode->mode, '[')) != NULL) {
                                       char *cptr = NULL;
                                       int sind = -1, dind = -1;
                                       *ptr++ = '\0';
                                       while (*ptr != ']') {
                                          if (isdigit((int)*ptr)) {
                                             dind = strtol(ptr, (char **)&cptr, 10);
                                             if (cptr == ptr)
                                                usage ();
            
                                             if (sind < 0)
                                                sind = dind;

                                             for (x = sind; x <= dind; x++)
                                                RaNewIndex |= 0x01 << x;

                                             ptr = cptr;
                                             if (*ptr != ']')
                                                ptr++;
                                             if (*cptr != '-')
                                                sind = -1;
                                          } else
                                             usage ();
                                       }
                                       ArgusIpV4MaskDefs[i].index = RaNewIndex;
                                       ArgusIpV6MaskDefs[i].index = RaNewIndex;
                                       ArgusEtherMaskDefs[i].index = RaNewIndex;
                                    }
                                    break;
                                 }
                              }
                              break;
                           }
                        }
                     }
                     mode = mode->nxt;
                  }
               }

               ArgusParser->ArgusMaskList = modelist;

#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaTopProcess->queue, ARGUS_NOLOCK)) != NULL)
                  ArgusDeleteRecordStruct (ArgusParser, ns);

               ArgusEmptyHashTable(RaTopProcess->htable);
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->RaClientUpdate.tv_sec = 0;
               ArgusParser->ns = NULL;
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
               werase(RaWindow);
               ArgusUpdateScreen();
            }

            break;
         }

         case RAGETTINGM: {
            struct ArgusModeStruct *mode = NULL;
            char strbuf[MAXSTRLEN], *str = strbuf, *tok = NULL;
            char *tzptr;
            int retn = 0;

            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if ((tzptr = strstr(strbuf, "TZ=")) != NULL) {
               if (ArgusParser->RaTimeZone)
                  free (ArgusParser->RaTimeZone);
               ArgusParser->RaTimeZone = strdup(tzptr);
               tzptr = getenv("TZ");
#if defined(HAVE_SETENV)
               if ((retn = setenv("TZ", (ArgusParser->RaTimeZone + 3), 1)) < 0) {
                  sprintf (ArgusParser->RaDebugString, "setenv(TZ, %s, 1) error %s", 
                     ArgusParser->RaTimeZone + 3, strerror(errno));
                  ArgusParser->RaDebugStatus = LOG_ERR;
               }
#else
               if ((retn = putenv(ArgusParser->RaTimeZone)) < 0) {
                  sprintf (ArgusParser->RaDebugString, "setenv(TZ, %s, 1) error %s", 
                     ArgusParser->RaTimeZone + 3, strerror(errno));
                  ArgusParser->RaDebugStatus = LOG_ERR;
               }
#endif
               if (retn == 0) {
                  tzset();
                  sprintf (ArgusParser->RaDebugString, "Timezone changed from %s to %s", 
                             tzptr, getenv("TZ"));
                  ArgusParser->RaDebugStatus = 0;
               }

               ArgusUpdateScreen();
               break;
            }

            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               ArgusDeleteModeList(ArgusParser);
               ArgusParser->RaCumulativeMerge = 1;
            }

            if (strlen(strbuf) > 0) {
               while ((tok = strtok(str, " \t\n")) != NULL) {
                  if (!(strncasecmp (tok, "none", 4)))
                     ArgusDeleteModeList(ArgusParser);
                  else if (!(strncasecmp (tok, "default", 7))) {
                     ArgusDeleteModeList(ArgusParser);
                  } else
                     ArgusAddModeList (ArgusParser, tok);
                  str = NULL;
               }
            }

            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               struct RaBinProcessStruct *RaBinProcess = ArgusParser->RaBinProcess;
               struct ArgusAdjustStruct *nadp = NULL;
               int i, ind;

               while (mode) {
                  for (i = 0, ind = -1; i < ARGUSSPLITMODENUM; i++) {
                     if (!(strncasecmp (mode->mode, RaSplitModes[i], strlen(RaSplitModes[i])))) {
                        ind = i;
                        break;
                     }
                  }

                  if (ind >= 0) {
                     char *mptr = NULL;
                     int size = -1;
                     nadp = &RaBinProcess->nadp;

                     nadp = &RaBinProcess->nadp;

                     switch (ind) {
                        case ARGUSSPLITRATE:  {   /* "%d:%d[yMwdhms]" */
                           struct ArgusModeStruct *tmode = NULL; 
                           nadp->mode = ind;
                           if ((tmode = mode->nxt) != NULL) {
                              mptr = tmode->mode;
                              if (isdigit((int)*tmode->mode)) {
                                 char *ptr = NULL;
                                 nadp->len = strtol(tmode->mode, (char **)&ptr, 10);
                                 if (*ptr++ != ':') 
                                    usage();
                                 tmode->mode = ptr;
                              }
                           }
                        }

                        case ARGUSSPLITTIME: /* "%d[yMwdhms] */
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
                                          size = nadp->value * 31556926;
                                          break;
                                       case 'M':
                                          nadp->qual = ARGUSSPLITMONTH; 
                                          size = nadp->value * 2629744;
                                          break;
                                       case 'w':
                                          nadp->qual = ARGUSSPLITWEEK;  
                                          size = nadp->value * 604800;
                                          break;
                                       case 'd':
                                          nadp->qual = ARGUSSPLITDAY;   
                                          size = nadp->value * 86400;
                                          break;
                                       case 'h':
                                          nadp->qual = ARGUSSPLITHOUR;  
                                          size = nadp->value * 3600;
                                          break;
                                       case 'm':
                                          nadp->qual = ARGUSSPLITMINUTE;
                                          size = nadp->value * 60;
                                          break;
                                        default:
                                          nadp->qual = ARGUSSPLITSECOND;
                                          size = nadp->value;
                                          break;
                                    }
                                 }
                              }
                              if (mptr != NULL)
                                  mode->mode = mptr;
                           }

                           nadp->modify = 1;

                           if (ind == ARGUSSPLITRATE) {
                              /* need to set the flow idle timeout value to be equal to or
                                 just a bit bigger than (nadp->len * size) */

                              ArgusParser->timeout.tv_sec  = (nadp->len * size);
                              ArgusParser->timeout.tv_usec = 0;
                           }

                           ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;
                           ArgusSorter->ArgusSortAlgorithms[1] = NULL;
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
                     if (!(strncasecmp (mode->mode, "nomerge", 7))) {
                        ArgusParser->RaCumulativeMerge = 0;
                     } else
                     if (!(strncasecmp (mode->mode, "merge", 5))) {
                        ArgusParser->RaCumulativeMerge = 1;
                     } else
                     if (!(strncasecmp (mode->mode, "rtime", 5)) ||
                        (!(strncasecmp (mode->mode, "realtime", 8)))) {
                        char *ptr = NULL;
                        RaTopRealTime++;
                        if ((ptr = strchr(mode->mode, ':')) != NULL) {
                           double value = 0.0;
                           char *endptr = NULL;
                           ptr++;
                           value = strtod(ptr, &endptr);
                           if (ptr != endptr) {
                              RaUpdateRate = value;
                           }
                        }

                     }
                  }

                  mode = mode->nxt;
               }
            }

            break;
         }

         case RAGETTINGp: {
            int value = 0;
            char *endptr = NULL;

            value = strtod(RaCommandInputStr, &endptr);

            if (RaCommandInputStr != endptr) {
               ArgusParser->pflag = value;
               sprintf (ArgusParser->RaDebugString, "%s %s precision accepted", RAGETTINGpSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = 0;
            } else {
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGuSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = LOG_ERR;
            }

            ArgusUpdateScreen();
            break;
         }

         case RAGETTINGR: {
            char strbuf[MAXSTRLEN], *str = strbuf, *ptr = NULL;
            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if (strlen(strbuf) > 0) {
               ArgusDeleteFileList(ArgusParser);
               while ((ptr = strtok(str, " ")) != NULL) {
                  RaProcessRecursiveFiles (ptr);
                  str = NULL;
               }
            }
            break;
         }

         case RAGETTINGr: {
            char strbuf[MAXSTRLEN], *str = strbuf, *ptr = NULL;
            glob_t globbuf;

            bzero (strbuf, MAXSTRLEN);
            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if (strlen(strbuf) > 0) {
               struct ArgusRecordStruct *ns = NULL;

               ArgusDeleteFileList(ArgusParser);
               while ((ptr = strtok(str, " ")) != NULL) {
                  glob (ptr, 0, NULL, &globbuf);
                  if (globbuf.gl_pathc > 0) {
                     int i;
                     for (i = 0; i < globbuf.gl_pathc; i++)
                        ArgusAddFileList (ArgusParser, globbuf.gl_pathv[i], ARGUS_DATA_SOURCE, -1, -1);
                  } else {
                     sprintf (ArgusParser->RaDebugString, "%s no files found for %s", RAGETTINGrSTR, ptr);
                     ArgusParser->RaDebugStatus = LOG_ERR;
                  }
                  str = NULL;
               }
               ArgusParser->RaTasksToDo = 1;
               ArgusParser->Sflag = 0;

#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaTopProcess->queue, ARGUS_NOLOCK)) != NULL) 
                  ArgusDeleteRecordStruct (ArgusParser, ns);

               ArgusEmptyHashTable(RaTopProcess->htable);
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->RaClientUpdate.tv_sec = 0;
               ArgusParser->status &= ~ARGUS_FILE_LIST_PROCESSED;
               ArgusParser->ns = NULL;
               ArgusLastTime.tv_sec  = 0;
               ArgusLastTime.tv_usec = 0;
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
            }
            break;
         }

         case RAGETTINGs: {
            char strbuf[MAXSTRLEN], *ptr = strbuf, *tok;
            int (*srtalg[ARGUS_MAX_SORT_ALG])(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
            int i, x, ind = 0;
            strncpy (strbuf, RaCommandInputStr, MAXSTRLEN);
            bzero(srtalg, sizeof(srtalg));
            while ((tok = strtok(ptr, " ")) != NULL) {
               for (x = 0; x < ARGUS_MAX_SORT_ALG; x++) {
                  if (!strncmp (ArgusSortKeyWords[x], tok, strlen(ArgusSortKeyWords[x]))) {
                     srtalg[ind++] = ArgusSortAlgorithmTable[x];
                     break;
                  }
               }
               if (x == ARGUS_MAX_SORT_ALG) {
                  bzero(srtalg, sizeof(srtalg));
                  ArgusLog (LOG_ALERT, "sort keyword %s not valid", tok);
                  break;
               }
               ptr = NULL;
            }

            if (srtalg[0] != NULL) {
               for (x = 0; x < ARGUS_MAX_SORT_ALG; x++)
                  ArgusSorter->ArgusSortAlgorithms[x] = srtalg[x];
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
            RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);
            if (ArgusParser->ns) {
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->ns = NULL;
            }
            for (i = 0; i < RaTopProcess->queue->count; i++) {
               struct ArgusRecordStruct *ns;
               if ((ns = (struct ArgusRecordStruct *)RaTopProcess->queue->array[i]) == NULL)
                  break;
               if (ArgusParser->ns)
                  ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
               else
                  ArgusParser->ns = ArgusCopyRecordStruct (ns);
            }
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
            ArgusUpdateScreen();
            break;
         }

         case RAGETTINGT: {
            double sec, usec, value;
            char *ptr = NULL;

            value = strtod(RaCommandInputStr, (char **)&ptr);
            if (ptr != RaCommandInputStr) {
               usec = modf(value, &sec);
               ArgusParser->timeout.tv_sec  = sec;
               ArgusParser->timeout.tv_usec = usec;
            }
            break;
         }

         case RAGETTINGt: {
            if (ArgusParser->timearg) {
               free (ArgusParser->timearg);
               ArgusParser->timearg = NULL;
            }

            if (strlen(RaCommandInputStr))
               ArgusParser->timearg = strdup(RaCommandInputStr);

            ArgusCheckTimeFormat (&ArgusParser->RaTmStruct, ArgusParser->timearg);
            break;
         }

         case RAGETTINGu: {
            double value = 0.0, ivalue, fvalue;
            char *endptr = NULL;
       
            value = strtod(RaCommandInputStr, &endptr);
       
            if (RaCommandInputStr != endptr) {
               fvalue = modf(value, &ivalue);
       
               RaTopUpdateInterval.tv_sec  = (int) ivalue;
               RaTopUpdateInterval.tv_usec = (int) (fvalue * 1000000.0);
       
               sprintf (ArgusParser->RaDebugString, "%s %s interval accepted", RAGETTINGuSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = 0;
               RaTopUpdateTime = ArgusParser->ArgusRealTime;
       
            } else {
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGuSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = LOG_ERR;
            }

            break;
         }


         case RAGETTINGU: {
            double value = 0.0;
            char *endptr = NULL;
       
            value = strtod(RaCommandInputStr, &endptr);
       
            if (RaCommandInputStr != endptr) {
               RaUpdateRate = value;
               sprintf (ArgusParser->RaDebugString, "%s %s accepted", RAGETTINGUSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = 0;
       
            } else {
               sprintf (ArgusParser->RaDebugString, "%s %s syntax error", RAGETTINGUSTR, RaCommandInputStr);
               ArgusParser->RaDebugStatus = LOG_ERR;
            }

            break;
         }

         
         case RAGETTINGw: {
            struct ArgusListStruct *wlist = ArgusParser->ArgusWfileList;
            struct ArgusWfileStruct *wfile = NULL;
            struct ArgusRecord *argusrec = NULL;
            struct ArgusRecordStruct *ns;
            static char sbuf[0x10000];
            int i;

            if (strlen(RaCommandInputStr)) {
               if (RaSortItems > 0) {
                  ArgusParser->ArgusWfileList = NULL;
                  setArgusWfile (ArgusParser, RaCommandInputStr, NULL);
                  wfile = (struct ArgusWfileStruct *) ArgusParser->ArgusWfileList->start;

#if defined(ARGUS_THREADS)
                  pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
                  for (i = 0; i < RaSortItems; i++) {
                     int pass = 1;

                     if ((ns = (struct ArgusRecordStruct *) RaTopProcess->queue->array[i]) == NULL)
                        break;

                     if (wfile->filterstr) {
                        struct nff_insn *wfcode = wfile->filter.bf_insns;
                        pass = ArgusFilterRecord (wfcode, ns);
                     }

                     if (pass != 0) {
                        if ((argusrec = ArgusGenerateRecord (ns, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                           ArgusHtoN(argusrec);
#endif
                           ArgusWriteNewLogfile (ArgusParser, ns->input, wfile, argusrec);

                        }
                     }
                  }
#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
                  fflush(wfile->fd);
                  fclose(wfile->fd);
                  clearArgusWfile(ArgusParser);
                  ArgusParser->ArgusWfileList = wlist;
               }
            }

            break;   
         }

         case RAGETTINGF: {
            struct ArgusQueueStruct *queue = RaTopProcess->queue;
            char strbuf[MAXSTRLEN], *ptr = strbuf, *tok;
            int x;

            strncpy (strbuf, RaCommandInputStr, MAXSTRLEN);
            bzero ((char *)ArgusParser->RaPrintOptionStrings, sizeof(ArgusParser->RaPrintOptionStrings));
            ArgusParser->RaPrintOptionIndex = 0;
            while ((tok = strtok(ptr, " ")) != NULL) {
               if (ArgusParser->RaPrintOptionIndex <  ARGUS_MAX_S_OPTIONS)
                  ArgusParser->RaPrintOptionStrings[ArgusParser->RaPrintOptionIndex++] = tok;
               ptr = NULL;
            }

            if (ArgusParser->RaPrintOptionIndex > 0) {
               ArgusProcessSOptions(ArgusParser);
               for (x = 0; x < ArgusParser->RaPrintOptionIndex; x++) 
                  if (ArgusParser->RaPrintOptionStrings[x] != NULL) 
                     ArgusParser->RaPrintOptionStrings[x] = NULL;
               ArgusParser->RaPrintOptionIndex = 0;
            }

            for (x = 0, ArgusAlwaysUpdate = 0; x < MAX_PRINT_ALG_TYPES; x++)
               if (ArgusParser->RaPrintAlgorithmList[x] != NULL)
                  if (ArgusParser->RaPrintAlgorithmList[x]->print == ArgusPrintIdleTime)
                     ArgusAlwaysUpdate++;

            if (queue == RaTopProcess->queue) {
               int i;
               if (ArgusParser->ns) {
                  ArgusParser->ns->status |= ARGUS_RECORD_MODIFIED;
               }
               for (i = 0; i < queue->count; i++) {
                  struct ArgusRecordStruct *ns;
                  if ((ns = (struct ArgusRecordStruct *)queue->array[i]) == NULL)
                     break;
                  ns->status |= ARGUS_RECORD_MODIFIED;
               }
            }
            ArgusUpdateScreen();
            break;
         }

         case RAGETTINGcolon: {
            char *endptr = NULL;
            int linenum, startline;

            linenum = (int)strtol(RaCommandInputStr, &endptr, 10);
            if (RaCommandInputStr == endptr) {
               switch (*RaCommandInputStr) {
                  case 'q': {
                     bzero (RaCommandInputStr, MAXSTRLEN);
                     ArgusUpdateScreen();
                     RaParseComplete(SIGINT);
                     break;
                  }
               }
            } else {
               if ((linenum >= RaWindowStartLine) && (linenum <= (RaWindowStartLine + RaDisplayLines)))
                  RaWindowCursorY = linenum - RaWindowStartLine;
               else {
                  startline = ((linenum - 1)/ RaDisplayLines) * RaDisplayLines;
                  startline = (RaSortItems > startline) ? startline : RaSortItems - RaDisplayLines;
                  startline = (startline > 0) ? startline : 0;
                  RaWindowStartLine = startline;
                  if ((RaWindowCursorY = linenum % RaDisplayLines) == 0)
                     RaWindowCursorY = RaDisplayLines;
               }
               RaCursorOffset = 0;
               RaWindowCursorX = 0;
               ArgusUpdateScreen();
            }
            break;
         }
      }
   }

   RaInputStatus = RAGOTcolon;
   RaInputString = RANEWCOMMANDSTR;
   bzero(RaCommandInputStr, MAXSTRLEN);
   RaCommandIndex = 0;

#if defined(ARGUS_HISTORY)
   argus_enable_history();
#endif
}


int
argus_process_command (struct ArgusParserStruct *parser, int status)
{
   char promptbuf[256], *prompt = promptbuf;
   int retn = status;

   if (strlen(rl_line_buffer) == 1) {

      switch (*rl_line_buffer) {
          case 'a': {
             retn = RAGETTINGa;
             RaInputString = RAGETTINGaSTR;
             break;
          }

          case 'c': {
             break;
          }

          case 'd': {
             struct ArgusInput *input;
             retn = RAGETTINGd;

             RaInputString = RAGETTINGdSTR;

            if ((input = (void *)ArgusParser->ArgusActiveHosts->start) != NULL) {
               do {
                  sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s:%d ", input->hostname, input->portnum);
                  input = (void *)input->qhdr.nxt;
               } while (input != (void *)ArgusParser->ArgusActiveHosts->start);
            }
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }
                   
          case 'D': {
             retn = RAGETTINGD;
             RaInputString = RAGETTINGDSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d", ArgusParser->debugflag);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }

          case 'e': {
             retn = RAGETTINGe;
             RaInputString = RAGETTINGeSTR;
             if (ArgusParser->estr)
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", ArgusParser->estr);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }

          case 'f': 
             retn = RAGETTINGf;
             RaInputString = RAGETTINGfSTR;
             RaFilterIndex = 3;
             if (ArgusParser->ArgusRemoteFilter) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "remote %s ", ArgusParser->ArgusRemoteFilter);
                RaCommandIndex = strlen(RaCommandInputStr); 
                RaFilterIndex = ARGUS_REMOTE_FILTER;
             } else
             if (ArgusParser->ArgusLocalFilter) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "local %s ", ArgusParser->ArgusLocalFilter);
                RaCommandIndex = strlen(RaCommandInputStr); 
                RaFilterIndex = ARGUS_LOCAL_FILTER;
             } else
             if (ArgusParser->ArgusDisplayFilter) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "display %s ", ArgusParser->ArgusDisplayFilter);
                RaCommandIndex = strlen(RaCommandInputStr); 
                RaFilterIndex = ARGUS_DISPLAY_FILTER;
             }
             break;

         case 'm': {
            struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;
            struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
            int i;

            retn = RAGETTINGm;
            RaInputString = RAGETTINGmSTR;
            if (agg->modeStr != NULL) {
               sprintf (RaCommandInputStr, "%s", agg->modeStr);
            } else {
               for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                  if (agg->mask & (0x01LL << i)) {
                     sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", ArgusMaskDefs[i].name);

                     switch (i) {
                        case ARGUS_MASK_SADDR:
                           if (agg->saddrlen > 0)
                              sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "/%d", agg->saddrlen);
                           break;
                        case ARGUS_MASK_DADDR:
                           if (agg->daddrlen > 0)
                              sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "/%d", agg->daddrlen);
                           break;
                     }

                     sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " ");
                  }
               }

               agg->modeStr = strdup(RaCommandInputStr);
            }
            RaCommandIndex = strlen(RaCommandInputStr);
            break;
         }

         case 'M': {
            struct ArgusModeStruct *mode;
            retn = RAGETTINGM;
            RaInputString = RAGETTINGMSTR;
    
            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               while (mode) {
                  sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", mode->mode);
                  mode = mode->nxt;
               }
            }
            RaCommandIndex = strlen(RaCommandInputStr);
            break;
         }

          case 'N':
             retn = RAGETTINGN;
             RaInputString = RAGETTINGNSTR;
             break;

          case 'p': {
             retn = RAGETTINGp;
             RaInputString = RAGETTINGpSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d", ArgusParser->pflag);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }

          case 'P': {
             double pause = ArgusParser->Pauseflag;
             ArgusParser->Pauseflag = (pause > 0.0) ? 0.0 : 1.0;

             if (ArgusParser->Pauseflag)
                RaInputString = "Paused";
             else
                RaInputString = "";
             break;
          }

          case 't':
             retn = RAGETTINGt;
             RaInputString = RAGETTINGtSTR;
             if (ArgusParser->timearg) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", ArgusParser->timearg);
                RaCommandIndex = strlen(RaCommandInputStr); 
             } else {
             }
             break;

          case 'T':
             retn = RAGETTINGT;
             RaInputString = RAGETTINGTSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d.%06d", 
                       (int)ArgusParser->timeout.tv_sec, (int)ArgusParser->timeout.tv_usec);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;

          case 'R': {
             struct ArgusInput *input = ArgusParser->ArgusInputFileList;
             retn = RAGETTINGR;
             RaInputString = RAGETTINGRSTR;
             while (input) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", input->filename);
                RaCommandIndex = strlen(RaCommandInputStr); 
                input = (void *) input->qhdr.nxt;
             }
             break;
          }

          case 'r': {
             struct ArgusInput *input = ArgusParser->ArgusInputFileList;
             retn = RAGETTINGr;
             RaInputString = RAGETTINGrSTR;
             while (input) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", input->filename);
                RaCommandIndex = strlen(RaCommandInputStr); 
                input = (void *) input->qhdr.nxt;
             }
             break;
          }

          case 'S': {
             struct ArgusInput *input;
             retn = RAGETTINGS;
             RaInputString = RAGETTINGSSTR;

            if ((input = (void *)ArgusParser->ArgusActiveHosts->start) != NULL) {
               do {
                  sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s:%d ", input->hostname, input->portnum);
                  input = (void *)input->qhdr.nxt;
               } while (input != (void *)ArgusParser->ArgusActiveHosts->start);

               RaCommandIndex = strlen(RaCommandInputStr); 
            }
            break;
         }

          case 's': {
             int x, y;
             retn = RAGETTINGs;
             RaInputString = RAGETTINGsSTR;
             for (x = 0; x < ARGUS_MAX_SORT_ALG; x++) {
                if (ArgusSorter->ArgusSortAlgorithms[x]) {
                   for (y = 0; y < ARGUS_MAX_SORT_ALG; y++) {
                      if (ArgusSorter->ArgusSortAlgorithms[x] == ArgusSortAlgorithmTable[y]) {
                         sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", 
                               ArgusSortKeyWords[y]);
                         break;
                      }
                   }
                }
             }
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }

          case 'u':
             retn = RAGETTINGu;
             RaInputString = RAGETTINGuSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d.", (int) RaTopUpdateInterval.tv_sec);
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%06d",(int) RaTopUpdateInterval.tv_usec);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;

          case 'U':
             retn = RAGETTINGU;
             RaInputString = RAGETTINGUSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%2.2f", RaUpdateRate);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;

          case 'w':
             retn = RAGETTINGw;
             RaInputString = RAGETTINGwSTR;
             break;

          case 'F': {
             int x, y;

             RaInputString = RAGETTINGFSTR;
             retn = RAGETTINGF;

             for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                if (parser->RaPrintAlgorithmList[x] != NULL) {
                   for (y = 0; y < MAX_PRINT_ALG_TYPES; y++) {
                      if ((void *) parser->RaPrintAlgorithmList[x]->print == (void *) RaPrintAlgorithmTable[y].print) {
                         sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s:%d ",
                            RaPrintAlgorithmTable[y].field, RaPrintAlgorithmTable[y].length);
                         break;
                      }
                   }
                } else
                   break;
             }
             RaCommandIndex = strlen(RaCommandInputStr);
             break;
          }

          case 'Q':
             retn = RAGETTINGq;
             RaInputString = RAGETTINGqSTR;
             break;

          case 'h':
             retn = RAGETTINGh;
             RaInputString = RAGETTINGhSTR;
             RaWindowStatus = 0;
             RaOutputHelpScreen();
             break;

          case 'n':
             if (++ArgusParser->nflag > 3) {
                ArgusParser->nflag = 0;
             }
#if defined(HAVE_DECL_RL_DONE) && HAVE_DECL_RL_DONE
             rl_done = 1;
#endif
             break;

          case 'v': 
             if (ArgusParser->vflag) {
                ArgusParser->vflag = 0;
                ArgusReverseSortDir = 0;
             } else {
                ArgusParser->vflag = 1;
                ArgusReverseSortDir++;
             }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
             RaTopSortQueue(ArgusSorter, RaTopProcess->queue, ARGUS_NOLOCK);

#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
#if defined(HAVE_DECL_RL_DONE) && HAVE_DECL_RL_DONE
             rl_done = 1;
#endif
             break;

          case '=':  {
             struct ArgusRecordStruct *ns = NULL;

             werase(RaWindow);
             ArgusUpdateScreen();

#if defined(ARGUS_THREADS)
             pthread_mutex_lock(&RaTopProcess->queue->lock);
#endif
             while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaTopProcess->queue, ARGUS_NOLOCK)) != NULL) 
                ArgusDeleteRecordStruct (ArgusParser, ns);

             ArgusEmptyHashTable(RaTopProcess->htable);
             ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
             ArgusParser->RaClientUpdate.tv_sec = 0;
             ArgusParser->ArgusTotalRecords = 0;
             RaTopStartTime.tv_sec = 0;
             RaTopStartTime.tv_usec = 0;
             RaTopStopTime.tv_sec = 0;
             RaTopStopTime.tv_usec = 0;
             ArgusParser->ns = NULL;
#if defined(ARGUS_THREADS)
             pthread_mutex_unlock(&RaTopProcess->queue->lock);
#endif
#if defined(HAVE_DECL_RL_DONE) && HAVE_DECL_RL_DONE
             rl_done = 1;
#endif
             break;
          }

          case 'z':  
             if (++ArgusParser->zflag > 1) {
                ArgusParser->zflag = 0;
             }
#if defined(HAVE_DECL_RL_DONE) && HAVE_DECL_RL_DONE
             rl_done = 1;
#endif
             break;

          case 'Z':  
             switch (ArgusParser->Zflag) {
                case '\0': ArgusParser->Zflag = 'b'; break;
                case  'b': ArgusParser->Zflag = 's'; break;
                case  's': ArgusParser->Zflag = 'd'; break;
                case  'd': ArgusParser->Zflag = '\0'; break;
             }
#if defined(HAVE_DECL_RL_DONE) && HAVE_DECL_RL_DONE
             rl_done = 1;
#endif
             break;

          default:
             break;
      }

      if (retn != status) {
         sprintf (prompt, ":%s ", RaInputString);

         rl_set_prompt(prompt);

#if defined(ARGUS_READLINE_SAVE_PROMPT)
         rl_save_prompt();
#endif

#if defined(ARGUS_READLINE)
#if defined(HAVE_DECL_RL_REPLACE_LINE) && HAVE_DECL_RL_REPLACE_LINE
         rl_replace_line(RaCommandInputStr, 1);
#else
#if defined(HAVE_DECL_RL_DELETE_TEXT) && HAVE_DECL_RL_DELETE_TEXT
         rl_delete_text(0, rl_point);
#endif
         sprintf(rl_line_buffer, "%s", RaCommandInputStr);
#endif
         rl_point = strlen(rl_line_buffer);
         rl_end = rl_point;
#else
#if defined(ARGUS_EDITLINE)

#endif
#endif
      }

   } else {
   }

   return (retn);
}

#if defined(ARGUS_HISTORY)

char ratop_historybuf[MAXSTRLEN];
char *ratop_history = NULL;

int argus_history_enabled = 1;

void
argus_recall_history(void)
{
   if (ratop_history != NULL)
      read_history(ratop_history);
}

void
argus_save_history(void)
{
   if (ratop_history == NULL) {
      char *home;

      if ((home = getenv("HOME")) != NULL) {
         sprintf (ratop_historybuf, "%s/.ratop_history", home);
         ratop_history = ratop_historybuf;
      }
   }

   if (ratop_history != NULL)
      write_history(ratop_history);
}

void
argus_enable_history(void)
{
   argus_recall_history();
   argus_history_enabled = 1;
}


void
argus_disable_history(void)
{
   argus_save_history();
   clear_history();
   argus_history_enabled = 0;
}

int
argus_history_is_enabled(void)
{
   return (argus_history_enabled);
}
#endif
#endif
