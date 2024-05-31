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
 * $Id: //depot/gargoyle/clients/examples/rastream/rastream.c#14 $
 * $DateTime: 2016/10/24 19:39:51 $
 * $Change: 3228 $
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

#include "argus_threads.h"
#include <argus_compat.h>
#include <sys/wait.h>

#include <rabins.h>
#include <rasplit.h>
#include <math.h>

#define ARGUS_SCHEDULE_SCRIPT		1
#define ARGUS_RUN_SCRIPT		2

#define ARGUS_SCRIPT_TIMEOUT            30

struct ArgusScriptStruct {
   struct ArgusListObjectStruct *nxt;
   struct ArgusWfileStruct *file;
   char *script, *filename, *cmd;
   char *args[8];
   struct timeval startime;
   int timeout;
   pid_t pid;
};

struct ArgusFileCacheStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusHashTableHdr *htblhdr;
   unsigned int status;

   time_t ArgusFileStartSecs;
   time_t ArgusFileEndSecs;

   struct timeval lasttime;
   struct ArgusWfileStruct wfile;
   struct ArgusListStruct *files;
   struct ArgusHashTable htable;
   struct ArgusHashStruct hstruct;
};

struct RastreamFileMap {
   struct ArgusQueueHeader qhdr;
   char *filename;
   char *filename_orig;
   int nodelete;
};

void *ArgusScriptProcess (void *);

#ifdef HAVE_FCNTL_H
# include <limits.h>
static struct RastreamFileMap *RastreamRetryListHead;
static struct RastreamFileMap *RastreamRetryListTail;

/* list of files we couldn't lock without blocking */
static int RastreamWriteNewLogfile(struct ArgusParserStruct *,
                                   struct ArgusInput *,
                                   struct ArgusWfileStruct *,
                                   struct ArgusRecord *);
#endif
static struct ArgusFileCacheStruct *ArgusThisFileCache = NULL;
static struct timeval ArgusLastFileTime = {0, 0};

static struct ArgusAdjustStruct adata, *ArgusNadp = &adata;

static int ArgusInitNewFilename(struct ArgusParserStruct *,
                                struct ArgusWfileStruct *, char *);
static struct ArgusFileCacheStruct *
   ArgusFindFileCache(struct ArgusHashTable *, struct ArgusHashStruct *);

static void ArgusProcessFileCache(struct ArgusFileCacheStruct *);
static struct ArgusFileCacheStruct *ArgusNewFileCache(void);
static void ArgusDeleteFileCache(struct ArgusFileCacheStruct *);
static void RastreamProcessAllFileCaches(struct ArgusQueueStruct *);

static struct ArgusWfileStruct *
   ArgusFindTimeInFileCache(struct ArgusFileCacheStruct *, time_t);

static int RaRealTime = 0;
static float RaUpdateRate = 1.0;

static struct timeval ArgusLastRealTime = {0, 0};
static struct timeval ArgusLastTime     = {0, 0};
static struct timeval ArgusThisTime     = {0, 0};
static struct timeval dRealTime = {0, 0};
static struct timeval dThisTime = {0, 0};

static long long thisUsec = 0;

static int argus_version = ARGUS_VERSION;

static int ArgusRunFileScript(struct ArgusParserStruct *,
                              struct ArgusWfileStruct *, int);
static int ArgusRunScript(struct ArgusParserStruct *,
                          struct ArgusScriptStruct *, int);

static struct ArgusHashTable ArgusFileTable;

static struct ArgusListStruct *ArgusScriptList = NULL;

static struct ArgusWfileStruct *ArgusFindFilename(struct ArgusParserStruct *,
                                                  struct ArgusFileCacheStruct *,
                                                  char *);
static struct ArgusHashStruct *ArgusGenerateFileHash(struct ArgusParserStruct *,
                                                     char *);

static struct ArgusWfileStruct *ArgusAddFilename(struct ArgusParserStruct *,
                                                 struct ArgusFileCacheStruct *,
                                                 char *);
static void RastreamCloseAllWfiles(void);

static int
RastreamAddFileRetryList(const char * const filename,
                         const char * const filename_orig)
{
   struct RastreamFileMap *file;

   file = ArgusCalloc(1, sizeof(*file));
   if (file == NULL)
      return 0;

   file->filename = strdup(filename);
   if (file->filename == NULL) {
      ArgusFree(file);
      return 0;
   }

   file->filename_orig = strdup(filename_orig);
   if (file->filename_orig == NULL) {
      free(file->filename);
      ArgusFree(file);
      return 0;
   }

   if (RastreamRetryListTail != NULL) {
      RastreamRetryListTail->qhdr.nxt = (struct ArgusQueueHeader *)file;
      RastreamRetryListTail = file;
   } else {
      RastreamRetryListHead = file;
      RastreamRetryListTail = file;
   }
   return 1;
}

static void
RastreamFreeFileRetryList(void)
{
   struct RastreamFileMap *file = RastreamRetryListHead;

   while (file) {
      RastreamRetryListHead = (struct RastreamFileMap *)
                              RastreamRetryListHead->qhdr.nxt;
      if (file->filename)
         free(file->filename);
      if (file->filename_orig)
         free(file->filename_orig);
      ArgusFree(file);
      file = RastreamRetryListHead;
   }

   RastreamRetryListTail = NULL;
}

/* use ra(1) to append temporary output to intended target file with
 * locking.  Could just open the files ourselves . . .
 */
static int
RastreamProcessFileRetryList(void)
{
   FILE *pipe;
   struct RastreamFileMap *file = RastreamRetryListHead;
   char *cmd, path[PATH_MAX];
   static const char * const fmt = "ra -X -Mlock -r %s -w %s";
   int rv = 1;

   cmd = ArgusMalloc(2*PATH_MAX);
   if (cmd == NULL)
      return 0;

   while (file) {
      int slen;
      int pres;

      if (file->filename == NULL)
         goto next;

      slen = snprintf(cmd, 2*PATH_MAX, fmt, file->filename, file->filename_orig);
      if (slen >= 2*PATH_MAX) {
         ArgusLog(LOG_WARNING, "%s command too long: skipping %s\n",
                  file->filename);
         file->nodelete = 1;
      }

#ifdef ARGUSDEBUG
      ArgusDebug(2, "%s running command: %s\n", __func__, cmd);
#endif
      pipe = popen(cmd, "r");
      if (pipe == NULL) {
         ArgusLog(LOG_WARNING, "%s unable to run command: %s\n", __func__, cmd);
         goto next;
      }

#ifdef ARGUSDEBUG
      while (fgets(path, PATH_MAX, pipe) != NULL)
          ArgusDebug(1, "cmd returns: %s", path);
#endif

      pres = pclose(pipe);
      if (pres == 0) {
         /* we are done with the temporary file.  clean up. */
#ifdef ARGUSDEBUG
         ArgusDebug(2, "%s removing temporary file %s\n", __func__,
                    file->filename);
#endif
         unlink(file->filename);
      }

next:
      file = (struct RastreamFileMap *)RastreamRetryListHead->qhdr.nxt;
   }

   ArgusFree(cmd);
   return rv;
}

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusWfileStruct *wfile = NULL;
   struct ArgusModeStruct *mode = NULL;
   char outputfile[MAXSTRLEN];
   char *outputfilter = NULL;
   int i = 0, ind = 0, count = 0;

#if defined(ARGUS_THREADS)
   pthread_attr_t attr;
#endif

   parser->RaWriteOut = 0;
   bzero(outputfile,   sizeof(outputfile));

   if (!(parser->RaInitialized)) {
      char *ptr = NULL;

      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      if (parser->dflag) {
         int pid;

         if (parser->Sflag)
            parser->ArgusReliableConnection++;

         ArgusLog(LOG_INFO, "started");
         if (chdir ("/") < 0)
            ArgusLog (LOG_ERR, "Can't chdir to / %s", strerror(errno));

         if ((pid = fork ()) < 0) 
            ArgusLog (LOG_ERR, "Can't fork daemon %s", strerror(errno));

         if (pid > 0) {
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
                  outputfilter = wfile->filterstr;
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
            if (isdigit((int) *mode->mode)) {
               ind = 0;
            } else if (!strncmp(mode->mode, "lock", 4)) {
               /* This is handled in ArgusParseArgs() but check for
               "lock" here so rastream doesn't exit if it's specified */
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

         parser->RaFieldWidth = RA_VARIABLE_WIDTH;
         bzero (mask, sizeof(mask));

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

      bzero(&ArgusFileTable, sizeof(ArgusFileTable));

      ArgusFileTable.size  = parser->ArgusHashTableSize;

      if ((ArgusFileTable.array = (struct ArgusHashTableHdr **)
                  ArgusCalloc (parser->ArgusHashTableSize, sizeof (struct ArgusHashTableHdr))) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s\n", strerror(errno));

      ArgusNadp->filename = strdup(outputfile);
      setArgusWfile (parser, outputfile, outputfilter);

      parser->RaClientTimeout.tv_sec  = 0;
      parser->RaClientTimeout.tv_usec = 330000;
      parser->RaInitialized++;

#if defined(ARGUS_THREADS)
extern void * ArgusScriptProcess (void *);

      if (pthread_attr_init(&attr) != 0)
         ArgusLog (LOG_ERR, "pthreads init error");
      if ((pthread_create(&ArgusParser->script, &attr, ArgusScriptProcess, ArgusParser)) != 0)
         ArgusLog (LOG_ERR, "ArgusSciptProcessor() pthread_create error %s\n", strerror(errno));
#endif
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
         struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;

         RastreamProcessFileRetryList();
         RastreamFreeFileRetryList();

#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(caught signal %d)\n", sig);
#endif
         RastreamProcessAllFileCaches(agg ? agg->queue : NULL);
         RastreamCloseAllWfiles();
         ArgusParser->RaParseDone = 1;
         if (ArgusParser->script != (pthread_t) 0) {
            pthread_join(ArgusParser->script, NULL);
            ArgusParser->script = (pthread_t) 0;
         }

         switch (sig) {
            case SIGHUP:
            case SIGINT:
            case SIGTERM:
            case SIGQUIT: {
               ArgusShutDown(sig);
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

   if (ArgusParser->Bflag > 0) {
      struct ArgusFileCacheStruct *fcache = NULL;

      if ((agg = ArgusParser->ArgusAggregator) != NULL) {
         struct ArgusQueueStruct *queue = agg->queue;
         int x, cnt;

#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&queue->lock);
#endif
         cnt = queue->count;
         for (x = 0; x < cnt; x++) {
            if ((fcache = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
               int i, count;
               if ((count = fcache->files->count) != 0) {
                  for (i = 0; i < count; i++) {
                     struct ArgusWfileStruct *wfile = (struct ArgusWfileStruct *)ArgusPopFrontList(fcache->files, ARGUS_NOLOCK);
                     if ((wfile->etime.tv_sec + ArgusParser->Bflag) <= ArgusParser->ArgusRealTime.tv_sec) {
                        ArgusLastFileTime = wfile->etime;
                        if (wfile->fd != NULL) {
                           fclose (wfile->fd);
                           wfile->fd = NULL;
                        }
                        ArgusRunFileScript(ArgusParser, wfile, ARGUS_SCHEDULE_SCRIPT);
                     } else {
                        ArgusPushBackList(fcache->files, (struct ArgusListRecord *)wfile, ARGUS_NOLOCK);
                     }
                  }
               }
               ArgusAddToQueue (queue, &fcache->qhdr, ARGUS_NOLOCK);
            }
         }

#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&queue->lock);
#endif
      } else {
         if ((fcache = ArgusThisFileCache) != NULL) {
            int i, count;
            if ((count = fcache->files->count) != 0) {
               for (i = 0; i < count; i++) {
                  struct ArgusWfileStruct *wfile = (struct ArgusWfileStruct *)ArgusPopFrontList(fcache->files, ARGUS_NOLOCK);
                  if ((wfile->etime.tv_sec + ArgusParser->Bflag) <= ArgusParser->ArgusRealTime.tv_sec) {
                     ArgusLastFileTime = wfile->etime;
                     if (wfile->fd != NULL) {
                        fclose (wfile->fd);
                        wfile->fd = NULL;
                     }
                     ArgusRunFileScript(ArgusParser, wfile, ARGUS_SCHEDULE_SCRIPT);
                  } else
                     ArgusPushBackList(fcache->files, (struct ArgusListRecord *)wfile, ARGUS_NOLOCK);
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (9, "ArgusClientTimeout()\n");
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

// The concept of operation here is a single record comes in, we need to split
// it based on the splitting logic (split to time boundary, or split based on
// file size, etc...).  Once we've split the record, we send it on its way using
// the standard RaSendArgusRecord (ns)
//
// For this client, RaSendArgusRecord (ns) will formulate the filename
// if there are any content specifiers in the outpout filename, and then
// we do some range checking formulate the filename
//

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
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusTimeObject *time = (void *)ns->dsrs[ARGUS_TIME_INDEX];
         struct ArgusRecordStruct *tns = NULL;

         if (time == NULL)
            return;

         RaGetStartTime(ns, &ArgusThisTime);

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


static
int
ArgusInitNewFilename(struct ArgusParserStruct *parser, struct ArgusWfileStruct *tfile, char *filename)
{
   int retn = 0;

   if (tfile->fd != NULL) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusInitNewFilename(0x%x, 0x%x, %s) closing file: %s\n", parser, tfile, filename, tfile->filename); 
#endif
      fclose (tfile->fd);
      tfile->fd = NULL;
   }

   if (tfile->filename != NULL) {
      free(tfile->filename);
      tfile->filename = NULL;
   } 

   if (filename == NULL)
      if ((filename = RaSplitFilename(ArgusNadp)) == NULL)
         ArgusLog(LOG_ERR, "RaProcessRecord filename beyond space");

   tfile->filename = strdup(filename);

   /* got new filename, need to check the
      path to be sure that all the directories exist */

   ArgusMkdirPath(tfile->filename);

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusInitNewFilename(0x%x, 0x%x, %s) done\n", parser, tfile, filename); 
#endif

   return (retn);
}

extern int RaDaysInAMonth[12];

time_t ArgusFileStartSecs = 0;
time_t ArgusFileEndSecs = 0;
char ArgusCurrentFileName[MAXSTRLEN];

//
// For this client, RaSendArgusRecord (ns) needs to decide which file to
// write data into, based on content, or time, or whatever.  To do this
// we need to formulate the filename if there are any content specifiers
// in the outpout filename.  If there are content specifiers, we're going
// to track filenames based on those specifiers, so we'll hash and cache
// based on the specifiers, and then grab a set of filenames that match
// the set of specifiers, like srcid, saddr, daddr, matrix, etc....

// So, we find the set of filenames based on content specifiers ( or null),
// and then do a range check to see if the target file for this record
// is in our cache. If not we create a new filenae, add it to the cache,
// and write the record into it.
//
//


char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];


int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{
   struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;
   struct ArgusWfileStruct *wfile = NULL, *tfile = NULL;
   struct ArgusFileCacheStruct *fcache = NULL;
   int retn = 1;

   if (argus->status & ARGUS_RECORD_WRITTEN)
      return (retn);

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR: 
      case ARGUS_EVENT:
      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         if (agg != NULL) {
            struct ArgusRecordStruct *ns = ArgusCopyRecordStruct(argus);
            struct ArgusHashStruct *hstruct = NULL;

            if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
               agg->rap = agg->drap;

            ArgusGenerateNewFlow(agg, ns);
            agg->ArgusMaskDefs = NULL;

            if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
               ArgusLog (LOG_ERR, "RaSendArgusRecord: ArgusGenerateHashStruct error %s", strerror(errno));

            if ((fcache = ArgusFindFileCache(agg->htable, hstruct)) == NULL) {
               if ((fcache = ArgusNewFileCache()) == NULL)
                  ArgusLog (LOG_ERR, "RaSendArgusRecord: ArgusNewFileCache: error");

               fcache->htblhdr = ArgusAddHashEntry(agg->htable, (void *)fcache, hstruct);
               ArgusAddToQueue (agg->queue, &fcache->qhdr, ARGUS_LOCK);

               if ((wfile = (struct ArgusWfileStruct *)ArgusFrontList(ArgusParser->ArgusWfileList)) == NULL)
                  ArgusLog (LOG_ERR, "RaSendArgusRecord: no output file specified");

               bcopy(wfile, &fcache->wfile, sizeof(*wfile));
            }

            ArgusFileStartSecs = fcache->ArgusFileStartSecs;
            ArgusFileEndSecs   = fcache->ArgusFileEndSecs;
            wfile = &fcache->wfile;

            ArgusDeleteRecordStruct(ArgusParser, ns);

         } else {
            if (ArgusThisFileCache == NULL) {
               if ((ArgusThisFileCache = ArgusNewFileCache()) == NULL)
                  ArgusLog (LOG_ERR, "RaSendArgusRecord: ArgusCalloc error");
               if ((wfile = (struct ArgusWfileStruct *)ArgusFrontList(ArgusParser->ArgusWfileList)) == NULL)
                  ArgusLog (LOG_ERR, "RaSendArgusRecord: no output file specified");

               bcopy(wfile, &ArgusThisFileCache->wfile, sizeof(*wfile));
            }
            fcache = ArgusThisFileCache;
            wfile = &fcache->wfile;
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

// so we've got the fcache, and we have a time.  before we go through the painful
// process of generating a filename, lets look to see if we have a file that can
// handle our startime.  If so just write into that file, if not, do the painful thing.
   
// First, if we've closed a file after this record, we're done.....

         if (ArgusLastFileTime.tv_sec > 0)
            if (ArgusLastFileTime.tv_sec >= fileSecs) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "RaSendArgusRecord () rejecting late record secs %d done file secs\n",
                    fileSecs, ArgusLastFileTime.tv_sec);
#endif
               return (retn);
            }


         if ((tfile = ArgusFindTimeInFileCache(fcache, fileSecs)) == NULL) {
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
            ArgusFileStartSecs = fileSecs;

            if (strftime(ArgusCurrentFileName, MAXSTRLEN, ArgusNadp->filename, &tmval) <= 0)
               ArgusLog (LOG_ERR, "RaSendArgusRecord () strftime %s\n", strerror(errno));

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

            if (agg != NULL)
               RaProcessSplitOptions(ArgusParser, ArgusCurrentFileName, MAXSTRLEN, argus);

            if ((tfile = ArgusFindFilename(ArgusParser, fcache, ArgusCurrentFileName)) == NULL) {
               if ((tfile = ArgusAddFilename(ArgusParser, fcache, ArgusCurrentFileName)) != NULL) {
                  ArgusInitNewFilename(ArgusParser, tfile, ArgusCurrentFileName);
                  tfile->stime.tv_sec = ArgusFileStartSecs;
                  tfile->etime.tv_sec = ArgusFileEndSecs;
               }
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
 
   if (tfile != NULL) {
      int pass = 1;
      if (tfile->filterstr) {
         struct nff_insn *wfcode = tfile->filter.bf_insns;
         pass = ArgusFilterRecord (wfcode, argus);
      }

      if (pass != 0) {
         if ((ArgusParser->exceptfile == NULL) || strcmp(tfile->filename, ArgusParser->exceptfile)) {
            struct ArgusRecord *argusrec = NULL;
            int rv;

            if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
               ArgusHtoN(argusrec);
#endif
               rv = RastreamWriteNewLogfile (ArgusParser, argus->input, tfile,
                                             argusrec);
               if (rv < 0)
                  ArgusLog(LOG_ERR, "%s unable to open file\n", __func__);
            }
         }
      }
   }

   if ((agg != NULL) && (fcache != NULL)) {
      fcache->ArgusFileStartSecs = ArgusFileStartSecs;
      fcache->ArgusFileEndSecs   = ArgusFileEndSecs;
      fcache->lasttime           = ArgusParser->ArgusRealTime;
   }

   argus->status |= ARGUS_RECORD_WRITTEN;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaSendArgusRecord () returning %d\n", retn);
#endif
   return (retn);
}

static int
RastreamWriteNewLogfile(struct ArgusParserStruct *parser,
                        struct ArgusInput *input,
                        struct ArgusWfileStruct *wfile,
                        struct ArgusRecord *argusrec)
{
   int retn = 0;
   int rv;

   rv = ArgusWriteNewLogfile(ArgusParser, input, wfile, argusrec);

   if (rv == 0)
      return 0;

#ifdef HAVE_FCNTL_H
   if (rv != -EAGAIN && rv != -EACCES)
      return rv * -1;

   /* A non-blocking lock failed because the file is already locked.
    * Generate a temporary name and open that file.
    */
   char *template;
   int slen;
   int fd;

   template = ArgusMalloc(PATH_MAX);
   if (template == NULL) {
      ArgusLog(LOG_WARNING,
               "%s: unable to allocate memory for filename template\n",
               __func__);
      retn = -1;
      goto out;
   }

   slen = snprintf(template, PATH_MAX, "%s.XXXXXX", wfile->filename);
   if (slen >= PATH_MAX) {
      retn = -1;
      ArgusLog(LOG_WARNING, "%s: filename template too long\n", __func__);
      goto out;
   }

   fd = mkstemp(template);
   if (fd < 0) {
      retn = -1;
      ArgusLog(LOG_WARNING, "%s: unable to open temp file: %s\n",
               __func__, strerror(errno));
      goto out;
   }

#ifdef ARGUSDEBUG
   ArgusDebug(2, "%s opening temporary file %s\n", __func__, template);
#endif
   wfile->fd = fdopen(fd, "a+");
   if (wfile->fd == NULL) {
      retn = -1;
      ArgusLog(LOG_WARNING, "%s: unable to open temporary file\n",
               __func__);
      goto out;
   }
   wfile->firstWrite = 1;

   if (RastreamAddFileRetryList(template, wfile->filename) != 1) {
      retn = -1;
      ArgusLog(LOG_WARNING,
               "%s: unable to add temporary file to retry list\n",
               __func__);
      goto out;
   }

out:
   if (template)
      ArgusFree(template);

#endif
   return retn;
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

static
struct ArgusFileCacheStruct *
ArgusFindFileCache (struct ArgusHashTable *htable, struct ArgusHashStruct *hstruct)
{
   struct ArgusFileCacheStruct *retn = NULL;
   struct ArgusHashTableHdr *hashEntry = NULL, *target, *head;
   unsigned int ind = (hstruct->hash % htable->size), i, len;

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

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusFindFileCache () returning 0x%x\n", retn);
#endif

   return (retn);
}


struct ArgusHashStruct ArgusFileHash;
unsigned int ArgusFileHashBuf[(MAXSTRLEN + 1)/4];

static
struct ArgusHashStruct *
ArgusGenerateFileHash(struct ArgusParserStruct *parser, char *filename)
{
   struct ArgusHashStruct *retn = NULL;

   if (filename != NULL) {
      u_short *sptr = NULL;
      int i, len, s = sizeof(*sptr);

      retn = &ArgusFileHash;
      retn->len  = s * ((strlen(filename) + (s - 1))/s);
      retn->len  = (retn->len >= MAXSTRLEN) ? (MAXSTRLEN - 1) : retn->len;
      retn->buf  = ArgusFileHashBuf;
      bzero(ArgusFileHashBuf, retn->len + 1);
      bcopy(filename, ArgusFileHashBuf, retn->len);

      retn->hash = 0;
      sptr = (unsigned short *)&retn->buf[0];
      for (i = 0, len = retn->len / s; i < len; i++)
         retn->hash += *sptr++;
   }

   return (retn);
}

static
struct ArgusWfileStruct *
ArgusFindFilename(struct ArgusParserStruct *parser, struct ArgusFileCacheStruct *fcache, char *filename)
{
   struct ArgusWfileStruct *retn = NULL;
   struct ArgusHashStruct *hash = ArgusGenerateFileHash(parser, filename);
   struct ArgusHashTableHdr *tblhdr = NULL;

   if (hash != NULL)
      if ((tblhdr = ArgusFindHashEntry (&ArgusFileTable, hash)) != NULL)
         retn = (struct ArgusWfileStruct *) tblhdr->object;
   
#ifdef ARGUSDEBUG
   ArgusDebug (7, "ArgusFindFilename (%p, %p, %s) return %p", parser, fcache, filename, retn);
#endif
   return(retn);
}

static
struct ArgusWfileStruct *
ArgusAddFilename(struct ArgusParserStruct *parser, struct ArgusFileCacheStruct *fcache, char *filename)
{
   struct ArgusWfileStruct *retn = NULL;
   struct ArgusHashStruct *hash = ArgusGenerateFileHash(parser, filename);

   if (hash != NULL) {
      if ((retn = (struct ArgusWfileStruct *) ArgusCalloc(1, sizeof(*retn))) != NULL) {
         if ((retn->htblhdr = ArgusAddHashEntry (&ArgusFileTable, (void *)retn, hash)) != NULL) {
            ArgusPushBackList(fcache->files, (struct ArgusListRecord *)retn, ARGUS_NOLOCK);
         } else {
            ArgusFree(retn);
            retn = NULL;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusAddFilename (%p, %p, %s) return %p", parser, fcache, filename, retn);
#endif
   return(retn);
}

static
struct ArgusFileCacheStruct *
ArgusNewFileCache(void)
{
   struct ArgusFileCacheStruct *retn = NULL;

   if ((retn = (struct ArgusFileCacheStruct *) ArgusCalloc(1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewFileCache: ArgusCalloc error");

   if ((retn->files = ArgusNewList()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewFileCache: ArgusNewList error %s\n", strerror(errno));

   if ((retn->htable.array = (struct ArgusHashTableHdr **) ArgusCalloc (ArgusParser->ArgusHashTableSize, sizeof(void *))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewLabeler: ArgusCalloc error %s", strerror(errno));

   retn->htable.size = ArgusParser->ArgusHashTableSize;

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusNewFileCache () return %p", retn);
#endif
   return(retn);
}

static
void 
ArgusProcessFileCache(struct ArgusFileCacheStruct *fcache)
{
   struct ArgusWfileStruct *tfile;

   while ((tfile = (struct ArgusWfileStruct *) ArgusPopFrontList(fcache->files, ARGUS_NOLOCK)) != NULL) {
#ifdef ARGUSDEBUG
      ArgusDebug (3, "ArgusProcessFileCache: removing file %s", tfile->filename);
#endif
      if (tfile->htblhdr != NULL) ArgusRemoveHashEntry (&tfile->htblhdr);

      if (tfile->fd != NULL) {
         fclose (tfile->fd);
         tfile->fd = NULL;
      }

      if (!(ArgusParser->Sflag)) 
         ArgusRunFileScript(ArgusParser, tfile, ARGUS_SCHEDULE_SCRIPT);

      if (tfile->filename)
         free(tfile->filename);

      ArgusFree(tfile);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusProcessFileCache (%p)", fcache);
#endif
}

static void
RastreamProcessAllFileCaches(struct ArgusQueueStruct *queue)
{
   struct ArgusFileCacheStruct *fcache;

   if (queue) {
      MUTEX_LOCK(&queue->lock);
      while ((fcache = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "%s: processing file cache: %s\n", __func__,
                     fcache->wfile.filename);
#endif
         ArgusProcessFileCache(fcache);
         ArgusDeleteFileCache(fcache);
      }
      MUTEX_UNLOCK(&queue->lock);
   } else {
      if ((fcache = ArgusThisFileCache) != NULL) {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "%s: processing file cache: %s\n", __func__,
                     fcache->wfile.filename);
#endif
         ArgusProcessFileCache(fcache);
         ArgusDeleteFileCache(fcache);
         ArgusThisFileCache = NULL;
      }
   }
}

static
void
ArgusDeleteFileCache(struct ArgusFileCacheStruct *fcache)
{
   ArgusDeleteList(fcache->files, ARGUS_WFILE_LIST);
   ArgusFree(fcache->htable.array);
   ArgusFree(fcache);

#ifdef ARGUSDEBUG
   ArgusDebug (7, "ArgusDeleteFileCache (%p) done", fcache);
#endif
   return;
}

static
struct ArgusWfileStruct * 
ArgusFindTimeInFileCache(struct ArgusFileCacheStruct *fcache, time_t secs)
{
   struct ArgusWfileStruct *retn = NULL, *wfile;
   int i, count;

   wfile = (struct ArgusWfileStruct *)fcache->files->start;
   count = fcache->files->count;

   for (i = 0; (i < count) && (retn == NULL); i++) {
      if ((wfile->stime.tv_sec <= secs) && (wfile->etime.tv_sec > secs))
         retn = wfile;
      wfile = (struct ArgusWfileStruct *)wfile->nxt;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusFindTimeInFileCache (%p, %d) retn %p", fcache, secs, retn);
#endif
   return (retn);
}

static
int
ArgusRunFileScript (struct ArgusParserStruct *parser, struct ArgusWfileStruct *file, int status)
{
   struct ArgusScriptStruct *script = NULL;
   int retn = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusRunFileScript(0x%x, %x) filename %s", parser, file, file->filename);
#endif

   if (file && parser->ArgusFlowModelFile) {
      char sbuf[1024];
      int i;

      if ((script = (struct ArgusScriptStruct *) ArgusCalloc (1, sizeof(*script))) == NULL)
         ArgusLog (LOG_ERR, "ArgusRunScript (%s) ArgusCalloc() error %s\n", file->filename, strerror(errno));

      script->file = file;
      script->filename = strdup(file->filename);
      script->script = strdup(parser->ArgusFlowModelFile);
      script->startime = parser->ArgusRealTime;
      script->timeout = ARGUS_SCRIPT_TIMEOUT;

      bzero(script->args, sizeof(script->args));
      bzero(sbuf, sizeof(sbuf));

      script->args[0] = script->script;         
      script->args[1] = "-r";         
      script->args[2] = script->filename;

      for (i = 0; i < 4; i++) {
         if (script->args[i] != NULL) {
            int slen = strlen(sbuf);
            snprintf (&sbuf[slen], 1024 - slen, " %s", script->args[i]);
         }
      }

      script->cmd = strdup(sbuf);
      ArgusRunScript(parser, script, status);

   } else
      retn = 1;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusRunFileScript(%p, %p) done", parser, file);
#endif
   return (retn);
}

static
int
ArgusRunScript (struct ArgusParserStruct *parser, struct ArgusScriptStruct *script, int status)
{
   int retn = 0;

   if (ArgusParser->RaParseDone) {
      if (parser->Sflag)
         return (retn);
   }

   switch (status) {
      case ARGUS_SCHEDULE_SCRIPT: {
         if (ArgusScriptList == NULL)
            if ((ArgusScriptList = ArgusNewList()) == NULL)
               ArgusLog (LOG_ERR, "ArgusRunScript (%s) ArgusNewList() error %s\n", script->filename, strerror(errno));

#ifdef ARGUSDEBUG
         ArgusDebug (1, "ArgusRunScript(%p, %p) scheduling %s", parser, script, script->cmd);
#endif
         ArgusPushBackList(ArgusScriptList, (struct ArgusListRecord *) script, ARGUS_LOCK);

         break;
      }

      case ARGUS_RUN_SCRIPT: {
         if ((retn = system(script->cmd)) < 0)
            ArgusLog(LOG_WARNING, "'%s' command failed\n", script->cmd);

         if (script->cmd != NULL) free (script->cmd);
         if (script->script != NULL) free (script->script);
         if (script->filename != NULL) free (script->filename);
         break;
      }
   }

   return (retn);
}

static void
RastreamCloseAllWfiles(void) {
   struct ArgusWfileStruct *wfile = NULL;
   struct ArgusListObjectStruct *lobj = NULL;
   int i, count = ArgusParser->ArgusWfileList->count;

   if (ArgusParser->ArgusWfileList == NULL)
      return;

   if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
      for (i = 0; i < count; i++) {
         if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
            if (wfile->fd != NULL) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "%s: closing %s\n", __func__, wfile->filename);
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
void *
ArgusScriptProcess (void *args) {
   struct timespec tsbuf = {1, 0}, *ts = &tsbuf;
   struct ArgusScriptStruct *script;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusScriptProcess() starting");
#endif

   while (!(ArgusParser->RaParseDone)) {
      if (ArgusScriptList != NULL) {
         if (!ArgusListEmpty(ArgusScriptList)) {
            while ((script = (struct ArgusScriptStruct *) ArgusPopFrontList(ArgusScriptList, ARGUS_LOCK)) != NULL)
               ArgusRunScript(ArgusParser, script, ARGUS_RUN_SCRIPT);
         }
      }
      if (!ArgusParser->RaParseDone)
         nanosleep(ts, NULL);
   }

   if (ArgusScriptList != NULL) {
      if (!ArgusListEmpty(ArgusScriptList)) {
         while ((script = (struct ArgusScriptStruct *) ArgusPopFrontList(ArgusScriptList, ARGUS_LOCK)) != NULL)
            ArgusRunScript(ArgusParser, script, ARGUS_RUN_SCRIPT);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusScriptProcess() done!");
#endif

   pthread_exit (NULL);
}
#endif
