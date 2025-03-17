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
 * argus_main - main routine for parsing argus output.
 *       this module performs all the argus(1) related connection parsing,
 *       selects datum from a set of criteria, and then calls specific
 *       protocol dependant routines, depending on the selected datum.
 *       at the end of processing, argus_parse calls an application
 *       specific finish routine, RaParseComplete(), and when
 *       connected to a remote data source, it supplies a periodic
 *       timeout routine;
 *
 *       this module defines all things, except:
 *
 *   (void) usage ((char *) argv[0]);
 *                    this routine should print the standard usage message
 *                    for the specific application.
 *
 *   (void) ArgusClientInit ();  this is the application specific init
 *                    routine, which is called after all parsing
 *                    initialization is done, prior to reading the
 *                    first monitor(1) datum.
 *
 *   (void) ArgusClientTimeout ();
 *                    this routine is called every ArgusParser->RaClientTimeout
 *                    period, after reading files and connecting to a remote
 *                    data source.
 *
 *   (void) RaParseComplete (0);
 *                    this routine will be called after all the
 *                    monitor data has been read.
 *
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/common/argus_main.c#13 $
 * $DateTime: 2016/10/13 07:13:10 $
 * $Change: 3222 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <sys/types.h>
#include <unistd.h>

#if defined(ARGUS_THREADS) 
#include <pthread.h>
#endif

#define ArgusMain

#include <argus_compat.h>

#include <argus_def.h>
#include <argus_out.h>

#include <signal.h>

#include <argus_util.h>

#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <argus_grep.h>
#include <argus_dscodepoints.h>

#include <ctype.h>
#include <strings.h>

#if defined(ARGUS_SOLARIS)
#include <string.h>
#endif

#include <sys/wait.h>

#if defined(__NetBSD__)
#include <sys/sched.h>
#else
#include <sched.h>
#endif

#ifdef __sun
# pragma weak RaOnePassComplete
#endif
int RaOnePassComplete(void)
#ifdef __GNUC__
 __attribute__((weak));
#endif

int RaOnePassComplete(void)
{
    return 1;
}


int
main (int argc, char **argv)
{
   struct ArgusInput *addr;
   int ArgusExitStatus;
   int i, cc;

#if defined(ARGUS_THREADS)
   int hosts = 0;
   pthread_attr_t attr;
#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN)
   int thread_policy;
   struct sched_param thread_param;
#if HAVE_SCHED_GET_PRIORITY_MIN
   int rr_min_priority, rr_max_priority;
#endif
#endif
   int status;
   size_t stacksize;
#endif

   for (i = 0, cc = 0; i < argc; i++)
      cc += strlen(argv[i]);

   if (strchr (argv[0], '/'))
      argv[0] = strrchr(argv[0], '/') + 1;

   if ((ArgusParser = ArgusNewParser(argv[0])) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewParser failed %s", strerror(errno));

#if defined(ARGUS_THREADS)
   if ((status = pthread_attr_init(&attr)) != 0)
      ArgusLog (LOG_ERR, "pthreads init error");
 
#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN)
   if ((status = pthread_attr_getschedpolicy(&attr, &thread_policy)) != 0)
      ArgusLog (LOG_ERR, "pthreads get policy error");
   if ((status = pthread_attr_getschedparam(&attr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads get sched params error");
   if ((status = pthread_attr_setschedpolicy(&attr, SCHED_RR)) != 0)
      ArgusLog (LOG_ERR, "pthreads set SCHED_RR error");

#if HAVE_SCHED_GET_PRIORITY_MIN
   if ((rr_min_priority = sched_get_priority_min(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority min error");
   if ((rr_max_priority = sched_get_priority_max(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority max error");

   thread_param.sched_priority = (rr_max_priority + rr_min_priority)/2 + 1;

   if (thread_param.sched_priority > rr_max_priority)
      thread_param.sched_priority = rr_max_priority;
   if (thread_param.sched_priority < (rr_max_priority - 8))
      thread_param.sched_priority = rr_max_priority - 8;

   if ((status = pthread_attr_setschedparam(&attr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads set sched param error");
#endif
#else
   pthread_attr_setschedpolicy(&attr, SCHED_RR);
#endif

#if defined(_POSIX_THREAD_ATTR_STACKSIZE)
#define ARGUS_MIN_STACKSIZE	0x10000000

   if (pthread_attr_getstacksize(&attr, &stacksize))
      ArgusLog (LOG_ERR, "pthreads get stacksize error");

   if (stacksize < ARGUS_MIN_STACKSIZE) {
      size_t nstacksize;

      if (pthread_attr_setstacksize(&attr, ARGUS_MIN_STACKSIZE))
         ArgusLog (LOG_ERR, "pthreads set stacksize error");

      if (pthread_attr_getstacksize(&attr, &nstacksize))
         ArgusLog (LOG_ERR, "pthreads get stacksize error");

#ifdef ARGUSDEBUG
      ArgusDebug (1, "stacksize from %d to %d", stacksize, nstacksize);
#endif
   }
#endif
 
   pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
#endif

   ArgusMainInit (ArgusParser, argc, argv);
   ArgusClientInit (ArgusParser);

   if (ArgusParser->ArgusLocalLabeler != NULL) {
      struct ArgusLabelerStruct *labeler = ArgusParser->ArgusLocalLabeler;
      if (labeler->RaLabelLocalityInterfaceIsMe == 1) {
         ArgusGetInterfaceAddresses(ArgusParser);
      }
   }

   if (ArgusParser->pidflag)
      ArgusCreatePIDFile (ArgusParser, ArgusParser->ArgusProgramName);
 
   if (!(ArgusParser->Sflag)) {
      if (ArgusParser->ArgusInputFileList == NULL) {
         if (!(ArgusAddFileList (ArgusParser, "-", ARGUS_DATA_SOURCE, -1, -1)))
            ArgusLog(LOG_ERR, "%s: error: file arg %s", *argv, optarg);
      }
   }

/*
   OK now we're ready.  Read in all the files, for as many passes as
   needed, and then attach to any remote sources as a group until
   they close, then we're done.
*/

   ArgusParser->ArgusCurrentInput = NULL;

   if (ArgusParser->ArgusInputFileList != NULL) {
      struct ArgusInput *input;
      struct ArgusFileInput *file;

      while (ArgusParser->ArgusPassNum) {
         if ((input = ArgusMalloc(sizeof(*input))) == NULL)
            ArgusLog(LOG_ERR, "unable to allocate input structure\n");

         file = ArgusParser->ArgusInputFileList;

         while (file && ArgusParser->eNflag) {
            if (strcmp (file->filename, "-")) {
               if (strlen(file->filename)) {
                  if (file->file == NULL) {
                     if ((file->file = fopen(file->filename, "r")) == NULL) {
#ifdef ARGUSDEBUG
                        ArgusDebug (1, "open '%s': %s", file->filename, strerror(errno));
#endif
                     }

                  } else {
                     fseek(file->file, 0, SEEK_SET);
                  }

                  ArgusInputFromFile(input, file);

                  /* input->file now "owns" this pointer.  Setting it
                   * to NULL prevents ArgusFileFree() from closing the
                   * file a second time.
                   */
                  file->file = NULL;

                  ArgusParser->ArgusCurrentInput = input;

                  if ((input->file != NULL) && ((ArgusReadConnection (ArgusParser, input, ARGUS_FILE)) >= 0)) {
#if defined(ARGUS_THREADS)
                     pthread_mutex_lock(&ArgusParser->lock);
#endif
                     ArgusParser->ArgusTotalMarRecords++;
                     ArgusParser->ArgusTotalRecords++;
#if defined(ARGUS_THREADS)
                     pthread_mutex_unlock(&ArgusParser->lock);
#endif
                     if (ArgusParser->RaPollMode) {
                         ArgusHandleRecord (ArgusParser, input, &input->ArgusInitCon, 0, &ArgusParser->ArgusFilterCode);
                     } else {
                        if (file->ostart != -1) {
                           input->offset = file->ostart;
                           if (fseek(input->file, input->offset, SEEK_SET) >= 0)
                              ArgusReadFileStream(ArgusParser, input);
                        } else {
                           ArgusHandleRecord (ArgusParser, input, &input->ArgusInitCon, 0, &ArgusParser->ArgusFilterCode);
                           ArgusReadFileStream(ArgusParser, input);
                        }
                     }

                  } else
                     file->fd = -1;
               }

            } else {
               int flags;
               file->file = stdin;
               file->ostart = -1;
               file->ostop = -1;

               ArgusInputFromFile(input, file);
               ArgusParser->ArgusCurrentInput = input;

               if (((ArgusReadConnection (ArgusParser, input, ARGUS_FILE)) >= 0)) {
#if defined(ARGUS_THREADS)
                  pthread_mutex_lock(&ArgusParser->lock);
#endif
                  ArgusParser->ArgusTotalMarRecords++;
                  ArgusParser->ArgusTotalRecords++;
#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&ArgusParser->lock);
#endif
                  if ((flags = fcntl(fileno(stdin), F_GETFL, 0L)) < 0)
                     ArgusLog (LOG_ERR, "ArgusReadFile: fcntl error %s", strerror(errno));

                  if (fcntl(fileno(stdin), F_SETFL, flags | O_NONBLOCK) < 0)
                     ArgusLog (LOG_ERR, "ArgusReadFile: fcntl error %s", strerror(errno));

                  ArgusReadFileStream(ArgusParser, input);
               }
            }

#ifdef ARGUSDEBUG
            ArgusDebug (1, "main: ArgusReadFileStream (%s) done", file->filename);
#endif
            RaArgusInputComplete(input);
            ArgusParser->ArgusCurrentInput = NULL;
            ArgusCloseInput(ArgusParser, input);

            file = (struct ArgusFileInput *)file->qhdr.nxt;

            /* Only free items from the file list during the last pass over
             * the data. */
            if (ArgusParser->ArgusPassNum <= 1) {
               ArgusFileFree(ArgusParser->ArgusInputFileList);
               ArgusParser->ArgusInputFileList = file;
            }
         }

         ArgusParser->ArgusPassNum--;
         RaOnePassComplete(); /* let this particular client know we're done
                               * with this pass
                               */
      }

      ArgusSetLocalNet(input->ArgusLocalNet, input->ArgusNetMask);
      ArgusDeleteInput(ArgusParser, input);
      input = NULL;
   }

   ArgusParser->ArgusCurrentInput = NULL;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "main: reading files completed");
#endif

/*
   Now we're going to deal with remote data sources.  To implement
   reliable connections effeciently, we need to put the input blocks
   in a data structure so that our reliable thread can do the right
   thing with them.
   
   The idea is that if they are in the queue we need to get a connection
   with the input.  If they are not in the queue, we have a connection or
   we are going to delete/forget them  because of massive errors.

   So, if we are reliably connected, first we put them all on the queue.
   If not we just connect to them sequentially.
*/

   if (ArgusParser->Sflag) {

      if (ArgusParser->tflag)
         ArgusParser->tflag = 0;

      ArgusParser->ArgusPassNum = 1;

#if defined(ARGUS_THREADS)
extern void * ArgusTimeoutProcess (void *);
 
   if (ArgusParser->ArgusTimeoutThread)
      if ((pthread_create(&ArgusParser->timer, &attr, ArgusTimeoutProcess, ArgusParser)) != 0)
         ArgusLog (LOG_ERR, "ArgusNewOutput() pthread_create error %s\n", strerror(errno));
#endif

      if (ArgusParser->ArgusRemoteHosts && (ArgusParser->ArgusRemoteHosts->count > 0)) {
         struct ArgusQueueStruct *tqueue = ArgusNewQueue();
         int flags;

         ArgusParser->ArgusRemotes = ArgusParser->ArgusRemoteHosts->count;

#if defined(ARGUS_THREADS)
         if (ArgusParser->ArgusReliableConnection) {
            if (ArgusParser->ArgusRemoteHosts && (hosts = ArgusParser->ArgusRemoteHosts->count)) {
               if ((pthread_create(&ArgusParser->remote, &attr, ArgusConnectRemotes, ArgusParser->ArgusRemoteHosts)) != 0)
                  ArgusLog (LOG_ERR, "ArgusNewOutput() pthread_create error %s\n", strerror(errno));
            }

         } else {
#else
         {
#endif
            while ((addr = (void *)ArgusPopQueue(ArgusParser->ArgusRemoteHosts, ARGUS_LOCK)) != NULL) {
               if ((addr->fd = ArgusGetServerSocket (addr, 5)) >= 0) {
                  if ((ArgusReadConnection (ArgusParser, addr, ARGUS_SOCKET)) >= 0) {
#if defined(ARGUS_THREADS)
                     pthread_mutex_lock(&ArgusParser->lock);
#endif
                     ArgusParser->ArgusTotalMarRecords++;
                     ArgusParser->ArgusTotalRecords++;
#if defined(ARGUS_THREADS)
                     pthread_mutex_unlock(&ArgusParser->lock);
#endif
                     if ((flags = fcntl(addr->fd, F_GETFL, 0L)) < 0)
                        ArgusLog (LOG_ERR, "ArgusConnectRemote: fcntl error %s", strerror(errno));

                     if (fcntl(addr->fd, F_SETFL, flags | O_NONBLOCK) < 0)
                        ArgusLog (LOG_ERR, "ArgusConnectRemote: fcntl error %s", strerror(errno));

                     ArgusHandleRecord (ArgusParser, addr, &addr->ArgusInitCon, 0, &ArgusParser->ArgusFilterCode);

                     if (ArgusParser->RaPollMode) {
                        ArgusDeleteInput (ArgusParser, addr);
                     } else {
                        ArgusAddToQueue(ArgusParser->ArgusActiveHosts, &addr->qhdr, ARGUS_LOCK);
                        ArgusParser->ArgusHostsActive++;
                     }
                  } else
                     ArgusAddToQueue(tqueue, &addr->qhdr, ARGUS_NOLOCK);
               } else
                  ArgusAddToQueue(tqueue, &addr->qhdr, ARGUS_NOLOCK);

#if !defined(ARGUS_THREADS)
            }
#else
         }
#endif
         }

         while ((addr = (void *)ArgusPopQueue(tqueue, ARGUS_NOLOCK)) != NULL)
            ArgusAddToQueue(ArgusParser->ArgusRemoteHosts, &addr->qhdr, ARGUS_LOCK);

         ArgusDeleteQueue(tqueue);
      }

#if defined(ARGUS_THREADS) 
      if (ArgusParser->ArgusReliableConnection || ArgusParser->ArgusActiveHosts->count)
#else
      if (ArgusParser->ArgusActiveHosts->count)
#endif
         ArgusReadStream(ArgusParser, ArgusParser->ArgusActiveHosts);

   } else {
#if defined(ARGUS_THREADS) 
      ArgusParser->RaDonePending++;
#else
      ArgusParser->RaParseDone++;
#endif
   }

   RaParseComplete(0);
   ArgusShutDown (0);

#if defined(ARGUS_THREADS) 
   if (ArgusParser->Sflag) {
      void *retn = NULL;

      if (ArgusParser->ArgusReliableConnection)
         pthread_attr_destroy(&attr);

      while ((addr = (void *)ArgusPopQueue(ArgusParser->ArgusRemoteHosts, ARGUS_LOCK)) != NULL) {
         if (addr->tid != (pthread_t) 0) {
            pthread_join(addr->tid, &retn);
         }
         if (addr->hostname != NULL)
            free (addr->hostname);
         ArgusFree(addr);
      }

      while ((addr = (void *)ArgusPopQueue(ArgusParser->ArgusActiveHosts, ARGUS_LOCK)) != NULL) {
         if (addr->tid != (pthread_t) 0) {
            pthread_join(addr->tid, &retn);
         }
         if (addr->hostname != NULL)
            free (addr->hostname);
         ArgusFree(addr);
      }
   }

   if (ArgusParser->timer != (pthread_t) 0)
      pthread_join(ArgusParser->timer, NULL);

   if (ArgusParser->dns != (pthread_t) 0)
      pthread_join(ArgusParser->dns, NULL);

   if (ArgusParser->remote != (pthread_t) 0)
      pthread_join(ArgusParser->remote, NULL);
#endif

   ArgusExitStatus = ArgusParser->ArgusExitStatus;
   ArgusCloseParser(ArgusParser);
   exit (ArgusExitStatus);
}

