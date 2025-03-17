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
 * Argus-5.0 Client Library
 * 
 * written by Carter Bullard
 * QoSient, LLC
 * 
 */

/* 
 * $Id: //depot/gargoyle/clients/common/argus_client.c#87 $
 * $DateTime: 2016/12/05 10:32:59 $
 * $Change: 3255 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#ifndef ArgusClient
#define ArgusClient
#endif

#ifndef ArgusSort
#define ArgusSort
#endif

#ifndef ArgusMetric
#define ArgusMetric
#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <stdlib.h>
#include <syslog.h>
#include <errno.h>

#include <math.h>
#include <ctype.h>

#include <sys/types.h>
#include <argus_compat.h>

#define ARGUS_MAIN

#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_sort.h>
#include <argus_metric.h>
#include <argus_histo.h>
#include <argus_label.h>

#include <rasplit.h>

#if defined(__OpenBSD__)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif
 
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/tcp.h>

#include <argus_main.h>

#define RA_HASHSIZE		256

#if defined(HAVE_XDR)
#include <rpc/types.h>
#if defined(HAVE_RPC_XDR_H)
#include <rpc/xdr.h>
#endif
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef ETH_ALEN
#define ETH_ALEN  6
#endif

#ifndef AF_INET6
#define AF_INET6	23
#endif


#ifndef ArgusOutputC
#define ArgusOutputC
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
 

#if defined(ARGUS_THREADS)
#include <pthread.h>
#endif

#include <argus_output.h>

int ArgusConnect(int, const struct sockaddr *, socklen_t, int);

extern struct ArgusRecord *ArgusGenerateRecord (struct ArgusRecordStruct *, unsigned char, char *, int);

void ArgusGenerateV3CorrelateStruct(struct ArgusRecordStruct *);
void ArgusGenerateCorrelateStruct(struct ArgusRecordStruct *);

struct ArgusRecordStruct *ArgusCopyRecordStruct (struct ArgusRecordStruct *);
void ArgusDeleteRecordStruct (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int ArgusSortSrvSignatures (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

static void
ArgusGenerateTransportStruct(const struct ArgusTransportStruct * const,
                             int, struct ArgusTransportStruct *, int);
static int
ArgusSortTransportStruct(const struct ArgusTransportStruct * const,
                         const struct ArgusTransportStruct * const, int);


void
ArgusSetTimeout(struct ArgusParserStruct *parser, struct ArgusInput *input)
{
   if (input == NULL)
      return;
   if (input->file || input->pipe)
      timeradd(&parser->ArgusCurrentTime, &parser->RaClientTimeout,
               &parser->RaClientTimeoutAbs);
   else
      timeradd(&parser->ArgusRealTime, &parser->RaClientTimeout,
               &parser->RaClientTimeoutAbs);
}

int
ArgusCheckTimeout(struct ArgusParserStruct *parser, struct ArgusInput *input)
{
   if (input == NULL)
      return 0;
   if (input->file || input->pipe)
      return !!timercmp(&parser->ArgusCurrentTime, &parser->RaClientTimeoutAbs, >);
   return !!timercmp(&parser->ArgusRealTime, &parser->RaClientTimeoutAbs, >);
}


#ifdef ARGUS_SASL
#include <argus/saslint.h>

// ArgusReadSaslStreamSocket() - this routine needs to keep reading data from the
//                               socket, decrypt it and then copy it into the
//                               standard ArgusReadBuffer, and then use the standard
//                               processing logic to read records.


int ArgusReadSaslStreamSocket (struct ArgusParserStruct *parser, struct ArgusInput *);

int
ArgusReadSaslStreamSocket (struct ArgusParserStruct *parser, struct ArgusInput *input)
{
   int retn = 0, fd = input->fd, cnt = 0;
   u_int val = 0, *pval = &val;
   char *output = NULL, *ptr = NULL;
   u_int outputlen = 0;
   const int *ssfp;
   int result;

   if ((retn = sasl_getprop(input->sasl_conn, SASL_MAXOUTBUF, (const void **) &pval)) != SASL_OK)
      ArgusLog (LOG_ERR, "ArgusReadSaslStreamSocket: sasl_getprop %s", strerror(errno));

   if (val == 0) 
      val = ARGUS_MAX_BUFFER_READ;

   cnt = (input->ArgusBufferLen - input->ArgusSaslBufCnt);
   val = (cnt > val) ? val : cnt;

   if ((cnt = read (fd, input->ArgusSaslBuffer + input->ArgusSaslBufCnt, val)) > 0) {
      ptr = (char *) input->ArgusSaslBuffer + input->ArgusSaslBufCnt;
      input->ArgusSaslBufCnt += cnt;

#ifdef ARGUSDEBUG
      ArgusDebug (5, "ArgusReadSaslStreamSocket (%p) read returned %d bytes\n", input, cnt);
#endif

      if ((result = sasl_getprop(input->sasl_conn, SASL_SSF, (const void **) &ssfp)) != SASL_OK)
         ArgusLog (LOG_ERR, "sasl_getprop: error %s\n", sasl_errdetail(input->sasl_conn));

      if (ssfp && (*ssfp > 0)) {
         if ((retn = sasl_decode (input->sasl_conn, ptr, cnt, (const char **) &output, &outputlen)) == SASL_OK) {
#ifdef ARGUSDEBUG
            ArgusDebug (5, "ArgusReadSaslStreamSocket (%p) sasl_decoded %d bytes\n", input, outputlen);
#endif

         } else
            ArgusLog (LOG_ERR, "ArgusReadSaslStreamSocket: sasl_decode (%p, %p, %d, %p, %p) failed %d",
                input->sasl_conn, ptr, cnt, &output, &outputlen, retn);
      } else {
         output = ptr;
         outputlen = input->ArgusSaslBufCnt;
      }

      if (outputlen) {
         while (input->ArgusSaslBufCnt) {
            int bytes, done = 0;
            bytes = (input->ArgusBufferLen - input->ArgusReadSocketCnt);
            bytes = (bytes > outputlen) ? outputlen : bytes;

            bcopy (output, input->ArgusReadPtr + input->ArgusReadSocketCnt, bytes);

            cnt = (input->ArgusBufferLen - input->ArgusSaslBufCnt);

            if (bytes > 0) {
               struct ArgusRecord *rec = NULL;
               input->ArgusReadSocketCnt += bytes;
               retn = 0;
               
               while (!retn && !done && !parser->RaParseDone) {
                  unsigned short length = 0;

                  switch (input->type & ARGUS_DATA_TYPE) {
                     case ARGUS_V2_DATA_SOURCE: {
                        struct ArgusV2Record *recv2 = (struct ArgusV2Record *)input->ArgusReadPtr;
                        if (input->ArgusReadSocketCnt >= sizeof(recv2->ahdr)) {
                           if ((length = ntohs(recv2->ahdr.length)) > 0) {
                              if (input->ArgusReadSocketCnt >= length)
                                 rec = (struct ArgusRecord *) ArgusConvertRecord (input, (char *)input->ArgusReadPtr);
                           } else {
                              ArgusLog (LOG_INFO,
                                        "ArgusReadSaslStreamSocket (%p) record length is zero",
                                        input);
                              retn = 1;
                           }
                        }
                        break;
                     }
                     case ARGUS_DATA_SOURCE: {
                        struct ArgusRecordHeader *recv3 = (struct ArgusRecordHeader *) input->ArgusReadPtr;
                        if (input->ArgusReadSocketCnt >= sizeof(*recv3)) {
                           if ((length = ntohs(recv3->len) * 4) > 0) {
                              if (input->ArgusReadSocketCnt >= length) {
                                 rec = (struct ArgusRecord *) input->ArgusReadPtr;
                              }

                           } else {
                              ArgusLog (LOG_INFO,
                                        "ArgusReadSaslStreamSocket (%p) record length is zero",
                                        input);
                              retn = 1;
                           }
                        }
                        break;
                     }
                  }

                  if (rec) {
                     int len;
                     if ((len = ArgusHandleRecord (ArgusParser, input, rec, 0, &ArgusParser->ArgusFilterCode)) < 0) {
                        retn = 1;
                     } else {
                        input->offset += len;
                        input->ArgusReadPtr += len;
                        input->ArgusReadSocketCnt -= len;

                        if (input->ostop != -1)
                           if (input->offset > input->ostop)
                              retn = 1;
                     }
                     rec = NULL;

                  } else
                     done = 1;
               }

               if (input->ArgusReadPtr != input->ArgusReadBuffer) {
                  if (input->ArgusReadSocketCnt > 0)
                     memmove(input->ArgusReadBuffer, input->ArgusReadPtr, input->ArgusReadSocketCnt);
                  input->ArgusReadPtr = input->ArgusReadBuffer;
               }
            }
            input->ArgusSaslBufCnt = 0;
         }
      }

   } else {
      retn = 1;

      if ((cnt < 0) && ((errno == EAGAIN) || (errno == EINTR))) {
         retn = 0;
      } else
         ArgusLog (LOG_ERR, "ArgusReadSaslStreamSocket: read (%d, %p, %d) failed '%s'",
                       fd, input->ArgusSaslBuffer, val, strerror(errno));
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusReadSaslStreamSocket (%p) returning %d\n", input, retn);
#endif

   return (retn);
}

#endif // ARGUS_SASL 


int
ArgusReadStreamSocket (struct ArgusParserStruct *parser, struct ArgusInput *input)
{
   int retn = 0, cnt = 0, done = 0;
   int bytes = 0, rbytes = 0;

   if (!(input) || parser->RaParseDone)
      return (1);

   bytes = (input->ArgusBufferLen - input->ArgusReadSocketCnt);
   bytes = (bytes > ARGUS_MAX_BUFFER_READ) ? ARGUS_MAX_BUFFER_READ : bytes;
   if (input->ostop != -1) {
      if ((rbytes = (input->ostop - input->ostart)) > 0) {
         bytes = (bytes > rbytes) ? rbytes : bytes;
      }
   }

   if ((input->type != ARGUS_DOMAIN_SOURCE) && (input->file != NULL)) {
      clearerr(input->file);

      if (input->file == stdin) {
         int sretn;
         fd_set readmask;
         struct timeval wait;

         parser->status &= ~(ARGUS_READING_FILES | ARGUS_READING_STDIN | ARGUS_READING_REMOTE);
         parser->status |=   ARGUS_READING_STDIN;

         FD_ZERO (&readmask);
         FD_SET (fileno(stdin), &readmask);
         wait.tv_sec  = 0;
         wait.tv_usec = 250000;

         if (!((sretn = select (fileno(stdin)+1, &readmask, NULL, NULL, &wait)) > 0)) {
#ifdef ARGUSDEBUG
            ArgusDebug (4, "ArgusReadStreamSocket (%p) select returned %d\n", input, sretn);
#endif
            return (sretn);
         } else {
            if ((cnt = fread (input->ArgusReadPtr + input->ArgusReadSocketCnt, 1, bytes, input->file)) == 0) {
               if ((retn = ferror(input->file))) {
                  if ((retn == EAGAIN) || (retn == EINTR))
                     retn = 0;
                  else
                     retn = 1;
               } else {
               if (parser->fflag) {
                  struct timespec tsbuf = {0, 250000000}, *ts = &tsbuf;
#ifdef ARGUSDEBUG
                  ArgusDebug (2, "ArgusReadStreamSocket () -fflag set ...sleeping", retn);
#endif
                  nanosleep(ts, NULL);
                  gettimeofday (&parser->ArgusGlobalTime, NULL);
               } else {
                  if ((retn = feof(input->file))) {
                     done++;
                     retn = 1;
                  }
               }

               }
            }
         }
      } else {
         parser->status &= ~(ARGUS_READING_FILES | ARGUS_READING_STDIN | ARGUS_READING_REMOTE);
         parser->status |=   ARGUS_READING_REMOTE;

         if ((cnt = fread (input->ArgusReadPtr + input->ArgusReadSocketCnt, 1, bytes, input->file)) == 0) {
            if ((retn = ferror(input->file))) {
               if ((retn == EAGAIN) || (retn == EINTR))
                  retn = 0;
               else
                  retn = 1;
            } else {
               if ((retn = feof(input->file))) {
                  done++;
                  retn = 1;
               }
            }
         }
      }

   } else {
      switch (input->type & ARGUS_DATA_TYPE) {
         default:
         if ((cnt = read (input->fd, input->ArgusReadPtr + input->ArgusReadSocketCnt, bytes)) < 0) {
            switch (errno) {
               case EINTR:
               case EAGAIN:
                  retn = 0;

               default:
                  ArgusLog (LOG_WARNING, "ArgusReadStreamSocket (%p) read error %s\n", input, strerror(errno));
                  retn = 1;
            }
         } else {
            if (cnt == 0) {
               retn = 1;
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusReadStreamSocket (%p) read %d bytes\n", input, cnt);
#endif

   if (cnt > 0) {
      struct ArgusRecord *rec = NULL;
      input->ArgusReadSocketCnt += cnt;
      
      while (!done) {
         int length = 0;

         rec = NULL;
         switch (input->type & ARGUS_DATA_TYPE) {
            case ARGUS_DOMAIN_SOURCE:
            case ARGUS_DATA_SOURCE: {
               struct ArgusRecordHeader *recv3 = (struct ArgusRecordHeader *) input->ArgusReadPtr;
 
               while ((ntohs(recv3->len) == 0) && (input->ArgusReadSocketCnt >= sizeof(*recv3))) {
                  recv3++;
                  input->ArgusReadSocketCnt -= sizeof(*recv3);
                  input->ArgusReadPtr += sizeof(*recv3);
               }
 
               if (input->ArgusReadSocketCnt >= sizeof(*recv3)) {
                  if ((length = ntohs(recv3->len) * 4) > 0) {
                     if (input->ArgusReadSocketCnt >= length) {
                        rec = (struct ArgusRecord *) input->ArgusReadPtr;
                     } else {
#ifdef ARGUSDEBUG
                        ArgusDebug (4, "ArgusReadStreamSocket (%p) ArgusReadSocketCnt %d lt %d length\n", input, input->ArgusReadSocketCnt, length);
#endif
                     }
                  } else {
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusReadStreamSocket (%p) record length is zero\n", input);
#endif
                     retn = 1;
                  }
               } else {
#ifdef ARGUSDEBUG
                  if (cnt > 0) {
                     ArgusDebug (4, "ArgusReadStreamSocket (%p) searched to the end of the buffer\n", input);
                  }
#endif
               }
               break;
            }

            case ARGUS_V2_DATA_SOURCE: {
               if (input->ArgusReadSocketCnt >= sizeof(void *)) {
                  struct ArgusV2Record *recv2 = (struct ArgusV2Record *)input->ArgusReadPtr;
                  length = ntohs(recv2->ahdr.length);

                  if ((length < 1) || (length > 4098)) {
                     unsigned int pattern = 0xa4000801;
                     do {
                        if (input->ArgusReadSocketCnt >= sizeof(recv2->ahdr)) {
                           input->ArgusReadPtr += 4;
                           input->ArgusReadSocketCnt -= 4;
                           recv2 = (struct ArgusV2Record *)input->ArgusReadPtr;
                        } else
                           break;
                     } while (bcmp(&recv2->ahdr, &pattern, 4));
                     length = ntohs(recv2->ahdr.length);
                  }

                  if (input->ArgusReadSocketCnt >= length)
                     if ((rec = (struct ArgusRecord *) ArgusConvertRecord (input, (char *)input->ArgusReadPtr)) != NULL)
                        break;
               }
               break;
            }
         }

         if (rec && !done && !parser->RaParseDone) {
            int len = 0;

            if ((len = ArgusHandleRecord (parser, input, rec, 0, &parser->ArgusFilterCode)) < 0) {
               switch (len) {
                  case -1: {
                     input->offset += length;
                     input->ArgusReadPtr += length;
                     input->ArgusReadSocketCnt -= length;

                     if (input->ArgusReadSocketCnt < 4) {
#ifdef ARGUSDEBUG
                        ArgusDebug (4, "ArgusReadStreamSocket (%p) not enough bytes to parser header\n", input);
#endif
                        retn = 1;
                        done = 1;
                     }
                     break;
                  }
                  case -2: {
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusReadStreamSocket (%p) ArgusHandleRecord returned %d\n", input, len);
#endif
                     retn = 1;
                     done = 1;
                     break;
                  }
               }

            } else {
               if ((input->type  & ARGUS_DATA_TYPE) == ARGUS_V2_DATA_SOURCE)
                  len = length;

               input->offset += len;
               input->ArgusReadPtr += len;
               input->ArgusReadSocketCnt -= len;

               cnt -= len;
               if (cnt > 0) {
#ifdef ARGUSDEBUG
                  ArgusDebug (6, "ArgusReadStreamSocket (%p) ArgusHandleRecord returned %d left %d\n", input, len, cnt);
#endif
               }

               if (input->ostop != -1) {
                  if (input->offset >= input->ostop) {
#ifdef ARGUSDEBUG
                     ArgusDebug (6, "ArgusReadStreamSocket (%p) ArgusHandleRecord reached end of read offset\n", input);
#endif
                     retn = 1;
                     done++;
                  }
               }
            }

         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (4, "ArgusReadStreamSocket (%p) DONE rec %p flag %d signal %d\n", input, rec, done, parser->RaParseDone);
#endif
            done = 1;
         }
      }

      if (input->ArgusReadPtr != input->ArgusReadBuffer) {
         if (input->ArgusReadSocketCnt > 0)
            memmove(input->ArgusReadBuffer, input->ArgusReadPtr, input->ArgusReadSocketCnt);
         input->ArgusReadPtr = input->ArgusReadBuffer;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (7, "ArgusReadStreamSocket (%p) returning %d\n", input, retn);
#endif

   return (retn);
}

void
ArgusReadFileStream (struct ArgusParserStruct *parser, struct ArgusInput *input)
{
   int retn = 0, done = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusReadFileStream() starting\n");
#endif
   parser->status &= ~(ARGUS_READING_FILES | ARGUS_READING_STDIN | ARGUS_READING_REMOTE);
   parser->status |=   ARGUS_READING_FILES;
      
   while (input && !done && !parser->RaParseDone) {
      switch (input->type & ARGUS_DATA_TYPE) {
         case ARGUS_DATA_SOURCE:
         case ARGUS_V2_DATA_SOURCE:
            if ((retn = ArgusReadStreamSocket (parser, input)) > 0) {
               done++;
            }
            break;

         case ARGUS_CISCO_DATA_SOURCE:
            if ((retn = ArgusReadCiscoStreamSocket (parser, input)) > 0) {
               done++;
            }
            break;

      }

      if (parser->RaClientTimeoutAbs.tv_sec > 0 && ArgusCheckTimeout(parser, input)) {
         ArgusClientTimeout ();
         ArgusSetTimeout(parser, input);
      }

      if (parser->Tflag) {
         struct timeval rtime, diff;
         rtime = parser->ArgusRealTime;
         RaDiffTime (&rtime, &input->ArgusStartTime, &diff);
         if (diff.tv_sec >= parser->Tflag)
            ArgusShutDown(0);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusReadFileStream() returning\n");
#endif
}


void *
ArgusConnectRemotes (void *arg)
{
#if defined(ARGUS_THREADS)
   struct ArgusQueueStruct *queue = arg;
   struct ArgusInput *addr = NULL;
   struct timespec tsbuf = {0, 250000000};
   struct timespec *ts = &tsbuf;
   int status, retn, done = 0;
   pthread_attr_t attr;

   if ((status = pthread_attr_init(&attr)) != 0)
      ArgusLog (LOG_ERR, "pthreads init error");

   while (!done && !ArgusParser->RaParseDone) {
      if ((addr = (struct ArgusInput *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
         if ((retn = pthread_create(&addr->tid, &attr, ArgusConnectRemote, addr)) != 0) {
            switch (retn) {
               case EAGAIN:
                  ArgusLog (LOG_ERR, "main: pthread_create ArgusConnectRemotes: EAGAIN \n");
                  break;
               case EINVAL:
                  ArgusLog (LOG_ERR, "main: pthread_create ArgusConnectRemotes, EINVAL\n");
                  break;
            }
         }
      }

      nanosleep(ts, NULL);
   }
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusConnectRemotes() done!");
#endif

#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#endif
   return (NULL);
}


// This routine basically runs until it connects to the remote
// site and then it exists.  If it is run in a threaded environment,
// it will run forever until it connects, then it will exit.


void *
ArgusConnectRemote (void *arg)
{
   struct ArgusInput *addr = (struct ArgusInput *)arg;
   struct timespec tsbuf = {5, 0};
   struct timespec *ts = &tsbuf;
   int done = 0;

#if defined(ARGUS_THREADS)
   sigset_t blocked_signals;
   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);
#endif

   if (ArgusParser->ArgusConnectTime == 0)
      ArgusParser->ArgusConnectTime = 10;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusConnectRemote(%p) starting", arg);
#endif

   while (!done && !ArgusParser->RaParseDone) {
#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&addr->lock);
#endif

      addr->status &= ~ARGUS_CLOSED;

      if (addr->fd < 0) {
         if ((addr->fd = ArgusGetServerSocket (addr, ArgusParser->ArgusConnectTime)) >= 0) {
            if ((ArgusReadConnection (ArgusParser, addr, ARGUS_SOCKET)) >= 0) {
               int flags;
               if ((flags = fcntl(addr->fd, F_GETFL, 0L)) < 0)
                  ArgusLog (LOG_INFO, "ArgusConnectRemote: fcntl error %s", strerror(errno));

               if (fcntl (addr->fd, F_SETFL, flags | O_NONBLOCK) < 0)
                  ArgusLog (LOG_INFO, "ArgusConnectRemote: fcntl error %s", strerror(errno));

#ifdef ARGUSDEBUG
               if (addr->hostname != NULL)
                  ArgusDebug (2, "ArgusConnectRemote(%p) connected to %s", arg, addr->hostname);
               else
                  ArgusDebug (2, "ArgusConnectRemote(%p) connected to %p", arg, addr);
#endif
               if (addr->qhdr.queue != NULL) {
                  if (addr->qhdr.queue != ArgusParser->ArgusActiveHosts) {
                     ArgusRemoveFromQueue(addr->qhdr.queue, &addr->qhdr, ARGUS_LOCK);
                     ArgusAddToQueue(ArgusParser->ArgusActiveHosts, &addr->qhdr, ARGUS_LOCK);
                  }
               } else
                  ArgusAddToQueue(ArgusParser->ArgusActiveHosts, &addr->qhdr, ARGUS_LOCK);

#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&ArgusParser->lock);
#endif
               ArgusParser->ArgusTotalMarRecords++;
               ArgusParser->ArgusTotalRecords++;
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&ArgusParser->lock);
#endif
               done++;
            } else {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "ArgusConnectRemote() ArgusReadConnection(%s) failed", addr->hostname);
#endif
            }

         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (2, "ArgusConnectRemote() ArgusGetServerSocket failed errno %d: %s", errno, strerror(errno));
#endif
            switch (errno) {
               case EHOSTDOWN:
               case EHOSTUNREACH:
               case ENETUNREACH: {
                  break;
               }
            }
         }
      }
#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&addr->lock);
#endif

      if (!done && ArgusParser->ArgusReliableConnection)
         nanosleep(ts, NULL);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusConnectRemote() done!");
#endif

#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#endif
   return (NULL);
}


void
ArgusReadStream (struct ArgusParserStruct *parser, struct ArgusQueueStruct *queue)
{
   struct ArgusInput *input = NULL;
   struct timeval wait;
   int retn = 0, started = 0;
   struct timeval rtime;

#if defined(ARGUS_THREADS)
   struct timespec tsbuf = {0, 50000000};
   struct timespec *ts = &tsbuf;
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusReadStream(%p) starting", parser);
#endif
      
   while (!(parser->RaParseDone)) {
      int width = -1, i;
      fd_set readmask;

      FD_ZERO (&readmask);

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&queue->lock);
#endif
      if ((input = (struct ArgusInput *) queue->start) != NULL) {
         for (i = 0; i < queue->count; i++) {
            if (input->fd >= 0) {
               FD_SET (input->fd, &readmask);
               width = (width < input->fd) ? input->fd : width;
            } else {
               if (!(parser->RaShutDown) && (parser->ArgusReliableConnection)) {
                  if (input->qhdr.queue != NULL) {
                     ArgusRemoveFromQueue(input->qhdr.queue, &input->qhdr, ARGUS_NOLOCK);
                     ArgusAddToQueue(parser->ArgusRemoteHosts, &input->qhdr, ARGUS_LOCK);
                  }
               }
            }
            input = (void *)input->qhdr.nxt;
         }
      }
#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock);
#endif
      if (width >= 0) {
         width++;
         wait.tv_sec = 0;
         wait.tv_usec = 500000;

         started = 1;

         if (input->ArgusStartTime.tv_sec == 0)
            gettimeofday (&input->ArgusStartTime, 0L);

         if ((retn = select (width, &readmask, NULL, NULL, &wait)) >= 0) {
#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&parser->lock);
#endif
            gettimeofday (&parser->ArgusRealTime, NULL);
            ArgusAdjustGlobalTime(ArgusParser, &ArgusParser->ArgusRealTime);
            rtime = parser->ArgusRealTime;
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&parser->lock);
#endif

            for (input = (struct ArgusInput *) queue->start, i = 0; i < queue->count; i++) {
               if ((input->fd >= 0) && FD_ISSET (input->fd, &readmask)) {
                  input->ArgusLastTime = parser->ArgusRealTime;

                  switch (input->type & ARGUS_DATA_TYPE) {
                     case ARGUS_DATA_SOURCE:
                     case ARGUS_DOMAIN_SOURCE:
                     case ARGUS_V2_DATA_SOURCE:
#ifdef ARGUS_SASL
                        if (input->sasl_conn) {
                           if (ArgusReadSaslStreamSocket (parser, input))
                              ArgusCloseInput(parser, input);
                        } else
#endif // ARGUS_SASL 
                           if (ArgusReadStreamSocket (parser, input))
                              ArgusCloseInput(parser, input);
                        break;

                     case ARGUS_JFLOW_DATA_SOURCE:
                     case ARGUS_CISCO_DATA_SOURCE:
                        if (parser->Sflag) {
                           if (ArgusReadCiscoDatagramSocket (parser, input))
                              ArgusCloseInput(parser, input);
                        } else {
                           if (ArgusReadCiscoStreamSocket (parser, input))
                              ArgusCloseInput(parser, input);
                        }
                        break;

                     case ARGUS_SFLOW_DATA_SOURCE:
                        if (parser->Sflag) {
                           if (ArgusReadSflowDatagramSocket (parser, input))
                              ArgusCloseInput(parser, input);
                        } else {
                           if (ArgusReadSflowStreamSocket (parser, input))
                              ArgusCloseInput(parser, input);
                        }
                        break;
                  }

               }
               input = (void *)input->qhdr.nxt;
            }
         } else {
#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&parser->lock);
#endif
            gettimeofday (&parser->ArgusRealTime, NULL);
            ArgusAdjustGlobalTime(ArgusParser, &ArgusParser->ArgusRealTime);
            rtime = parser->ArgusRealTime;
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&parser->lock);
#endif
         }

      } else {
         if (started) {
            if (!(parser->ArgusReliableConnection)) {
               parser->RaParseDone++;
            }
         }

#if defined(ARGUS_THREADS)
         if ((!parser->RaParseDone && !retn) || (width < 0))
            if (parser->ArgusReliableConnection)
               nanosleep(ts, NULL);
#endif

#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&parser->lock);
#endif
         gettimeofday (&parser->ArgusRealTime, NULL);
         ArgusAdjustGlobalTime(ArgusParser, &ArgusParser->ArgusRealTime);
         rtime = parser->ArgusRealTime;
#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&parser->lock);
#endif
      }

      if (input != NULL) {
         if (parser->RaClientTimeoutAbs.tv_sec == 0) {
#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&parser->lock);
#endif
            gettimeofday (&ArgusParser->ArgusRealTime, NULL);
            rtime = parser->ArgusRealTime;
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&parser->lock);
#endif
            ArgusSetTimeout(parser, input);
         }

         if (ArgusCheckTimeout(parser, input)) {
            ArgusClientTimeout ();
            ArgusSetTimeout(parser, input);

#if !defined(ARGUS_THREADS)
            if (parser->ArgusReliableConnection) {
               struct ArgusInput *addr;
               int flags;

               if ((addr = (void *)ArgusPopQueue(ArgusParser->ArgusRemoteHosts, ARGUS_LOCK)) != NULL) {
                  if (addr->fd != -1) close(addr->fd);
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
                           ArgusLog (LOG_WARNING, "ArgusConnectRemote: fcntl error %s", strerror(errno));
            
                        if (fcntl(addr->fd, F_SETFL, flags | O_NONBLOCK) < 0)
                           ArgusLog (LOG_WARNING, "ArgusConnectRemote: fcntl error %s", strerror(errno));
         
                        if (ArgusParser->RaPollMode)
                           ArgusHandleRecord (ArgusParser, addr, &addr->ArgusInitCon, 0, &ArgusParser->ArgusFilterCode);
         
                        ArgusAddToQueue(ArgusParser->ArgusActiveHosts, &addr->qhdr, ARGUS_LOCK);
#if defined(ARGUS_THREADS)
                        pthread_mutex_lock(&ArgusParser->lock);
#endif
                        ArgusParser->ArgusHostsActive++;
#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&ArgusParser->lock);
#endif
          
                     } else {
                        close(addr->fd);
                        addr->fd = -1;
                        ArgusAddToQueue(ArgusParser->ArgusRemoteHosts, &addr->qhdr, ARGUS_LOCK);
                     }
                  } else
                     ArgusAddToQueue(ArgusParser->ArgusRemoteHosts, &addr->qhdr, ARGUS_LOCK);
               }
            }
#endif
         }

         if (ArgusParser->Tflag) {
            struct timeval diff;
            RaDiffTime (&rtime, &input->ArgusStartTime, &diff);
            if (diff.tv_sec >= ArgusParser->Tflag)
               ArgusShutDown(0);
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusReadStream(%p, %p) returning", parser, queue);
#endif
}


#include <netdb.h>
#include <sys/un.h>

extern void ArgusLog (int, char *, ...);

#define ARGUS_DEFAULTCISCOPORT      9995

char *ArgusRecordType = NULL;

extern int ArgusInitializeAuthentication(void);

#include <netinet/in.h>
#include <arpa/inet.h>



int
ArgusGetServerSocket (struct ArgusInput *input, int timeout)
{
#if HAVE_GETADDRINFO
   struct addrinfo *hp = input->host;
#else
   struct hostent *hp = input->host;
   int type = SOCK_DGRAM;
#endif
   struct servent *sp;
   int s, retn = -1;
   u_short portnum = 0;

#if HAVE_GETADDRINFO
   char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
   int optval = 1;
#endif

   switch (input->type & ARGUS_DATA_TYPE) {
      case ARGUS_DATA_SOURCE:
      case ARGUS_V2_DATA_SOURCE: {
         char *protoStr;
         ArgusRecordType = "Argus";
         if (input->mode == IPPROTO_UDP) {
            input->mode = ARGUS_DATAGRAM_SOURCE;
            protoStr = "udp";
         } else {
            protoStr = "tcp";
#if !HAVE_GETADDRINFO
            type = SOCK_STREAM;
#endif
         }
         if (!input->portnum) {
            if (!ArgusParser->ArgusPortNum) {
               if ((sp = getservbyname ("monitor", protoStr)) != NULL)
                  portnum = sp->s_port;
               else
                  portnum = htons(ARGUS_DEFAULTPORT);
            } else
               portnum = htons(ArgusParser->ArgusPortNum);

            input->portnum = ntohs(portnum);

         } else {
            if (!ArgusParser->ArgusPortNum)
               ArgusParser->ArgusPortNum = input->portnum;

            portnum = htons(input->portnum);
         }

         break;
      }

      case ARGUS_DOMAIN_SOURCE: {
         ArgusRecordType = "Argus";
         input->mode = ARGUS_DOMAIN_SOURCE;
         break;
      }

      case ARGUS_JFLOW_DATA_SOURCE: {
         ArgusRecordType = "Jflow";
         input->mode = ARGUS_DATAGRAM_SOURCE;
         break;
      }

      case ARGUS_SFLOW_DATA_SOURCE: {
         ArgusRecordType = "Sflow";
         input->mode = ARGUS_DATAGRAM_SOURCE;
         break;
      }

      case ARGUS_CISCO_DATA_SOURCE: {
         struct ArgusRecord argus;

         ArgusRecordType = "Netflow";
         if (!input->portnum) {
            if (!ArgusParser->ArgusPortNum) {
               if ((sp = getservbyname ("monitor", "udp")) != NULL)
                  portnum = sp->s_port;
               else
                  portnum = htons(ARGUS_DEFAULTCISCOPORT);
            } else
               portnum = htons(ArgusParser->ArgusPortNum);
         } else {
            ArgusParser->ArgusPortNum = input->portnum;
            portnum = htons(input->portnum);
         } 

         bzero ((char *)&argus, sizeof(argus));
         argus.hdr.type          = ARGUS_MAR | ARGUS_NETFLOW | ARGUS_VERSION;
         argus.hdr.cause         = ARGUS_START;
         argus.hdr.len           = sizeof (argus) / 4;
         argus.argus_mar.argusid = ARGUS_COOKIE;

         if (input->addr.s_addr != 0)
            argus.argus_mar.thisid = input->addr.s_addr;

         argus.argus_mar.startime.tv_sec = ArgusParser->ArgusGlobalTime.tv_sec;
         argus.argus_mar.now.tv_sec      = ArgusParser->ArgusGlobalTime.tv_sec;
         argus.argus_mar.major_version   = VERSION_MAJOR;
         argus.argus_mar.minor_version   = VERSION_MINOR;
         argus.argus_mar.record_len      = -1;

         input->major_version = argus.argus_mar.major_version;
         input->minor_version = argus.argus_mar.minor_version;

#if defined(_LITTLE_ENDIAN)
         ArgusHtoN(&argus);
#endif
         bcopy ((char *) &argus, (char *)&input->ArgusInitCon, sizeof (argus));
         break;
      }

      case ARGUS_IPFIX_DATA_SOURCE: {
         ArgusRecordType = "Ipfix";
         break;
      }

      default:
         ArgusLog (LOG_ERR, "ArgusGetServerSocket(%p) unknown type", input);
   }

   switch (input->type & ARGUS_DATA_TYPE) {
      case ARGUS_DATA_SOURCE:
      case ARGUS_V2_DATA_SOURCE: {

         if (hp == NULL) {
            char *hptr = input->hostname;
#if HAVE_GETADDRINFO
            struct addrinfo hints;
#endif
            if ((hptr != NULL) && (strlen(hptr) > 0)) {
               char msgbuf[1024];
               int rval;
#if HAVE_GETADDRINFO
               memset(&hints, 0, sizeof(hints));
//       hints.ai_family   = AF_INET;
               if ((input->type == ARGUS_CISCO_DATA_SOURCE) || (input->mode == ARGUS_DATAGRAM_SOURCE)) {
                  hints.ai_socktype = SOCK_DGRAM;
                  hints.ai_protocol = IPPROTO_UDP;
                  hints.ai_family   = AF_INET;
               } else
                  hints.ai_socktype = SOCK_STREAM;
       
               if (!(strncasecmp("any", hptr, 3))) {
                  hptr = NULL;
                  hints.ai_flags = AI_PASSIVE;
               }

               if ((rval = getaddrinfo(hptr, input->servname, &hints, &hp)) != 0) {
                  switch (rval) {
                     case EAI_AGAIN: 
                        sprintf (msgbuf, "dns server not available");
                        break;
                     case EAI_NONAME:
                        sprintf (msgbuf, "host %s unknown", hptr);
                        break;
#if defined(EAI_ADDRFAMILY)
                     case EAI_ADDRFAMILY:
                        sprintf (msgbuf, "host %s has no IP address", hptr);
                        break;
#endif
                     case EAI_SYSTEM:
                     default:
                        sprintf (msgbuf, "host '%s' %s", hptr, gai_strerror(rval));
                        break;
                  }
               }
#else
               if ((hp = gethostbyname(hptr)) != NULL) {
                  u_int **p;
                  for (p = (u_int **)hp->h_addr_list; *p; ++p)
                     **p = ntohl(**p);
               } else {
                  switch (h_errno) {
                     case TRY_AGAIN:
                        sprintf (msgbuf, "dns server not available");
                        break;
                     case HOST_NOT_FOUND:
                        sprintf (msgbuf, "host %s unknown", hptr);
                        break;
                     case NO_ADDRESS:
                        sprintf (msgbuf, "host %s has no IP address", hptr);
                        break;
                     case NO_RECOVERY:
                        sprintf (msgbuf, "host %s name server error", hptr);
                        break;
                  }
               }
#endif
            }
         }

         if (hp != NULL) {
#if HAVE_GETADDRINFO
            do {
               if (getnameinfo(hp->ai_addr, hp->ai_addrlen, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV))
                  ArgusLog(LOG_ERR, "could not get numeric hostname");
               
               if (hp->ai_canonname) {
                  if (input->hostname)
                     free(input->hostname);
                  input->hostname = strdup(hp->ai_canonname);
               } else {
                  if (input->hostname)
                     free(input->hostname);
                  input->hostname = strdup(hbuf);
               }

               if ((s = socket (hp->ai_family, hp->ai_socktype, hp->ai_protocol)) >= 0) {
                  if (hp->ai_socktype == SOCK_DGRAM) {
                     if (hp->ai_addr->sa_family == PF_INET) {
                        struct sockaddr_in *sinaddr = (struct sockaddr_in *)hp->ai_addr;
                        struct in_addr ia;

                        bcopy(&sinaddr->sin_addr, &ia, sizeof(ia));

                        if (IN_MULTICAST(ntohl(ia.s_addr))) {
                           struct ip_mreq mreq;
                           bcopy(&ia, &mreq.imr_multiaddr.s_addr, sizeof(struct in_addr));
  // set interface
                           mreq.imr_interface.s_addr = htonl(INADDR_ANY);

  // do membership call
                           if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(struct ip_mreq)) == -1)
                              ArgusLog (LOG_ERR, "ArgusGetServerSocket: setsockopt() join multicast failed. %s", strerror(errno));

//                         if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) == -1)
//                            ArgusLog (LOG_ERR, "ArgusGetServerSocket: setsockopt() reuse port failed. %s", strerror(errno));
                        }

                     } else if (hp->ai_addr->sa_family == PF_INET6) {
//                      if (IN6_IS_ADDR_MULTICAST(hp->ai_addr->sa_data)) {
//                      }
                     }

#ifdef ARGUSDEBUG
                     ArgusDebug (1, "Binding %s:%s Expecting %s records", input->hostname, sbuf, ArgusRecordType); 
#endif
                     if ((retn = bind (s, hp->ai_addr, hp->ai_addrlen)) < 0) {
#ifdef ARGUSDEBUG
                        ArgusDebug(1, "connect to %s:%s failed '%s'", input->hostname, sbuf, strerror(errno));
#endif
                        hp = hp->ai_next;
                     } else {
                        retn = s;
                        input->fd = s;
                     }

                  } else {
                     if (ArgusParser->ArgusSourcePort) {
                        struct sockaddr_in server;
                        bzero(&server, sizeof(server));
                        server.sin_family = AF_INET;
                        server.sin_addr.s_addr = INADDR_ANY;
                        server.sin_port = htons(ArgusParser->ArgusSourcePort);
#ifdef ARGUSDEBUG
                        ArgusDebug (1, "Binding TCP to source INADDR_ANY:%d Expecting %s records", ArgusParser->ArgusSourcePort, ArgusRecordType);
#endif
                        if ((bind (s, (struct sockaddr *)&server, sizeof(server))) < 0)
                           ArgusLog (LOG_ERR, "bind (%d, %s:%hu, %d) failed '%s'", s, "INADDR_ANY",
                                                          ntohs(server.sin_port), sizeof(server), strerror(errno));

                        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(int)) < 0) {
#ifdef ARGUSDEBUG
                           ArgusDebug (1, "setsockopt(%d, SOL_SOCKET, SO_REUSEADDR, x%x, %d) failed:", s, optval, sizeof(int));
#endif
                        }
                     }

                     if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval, sizeof(int)) < 0) {
#ifdef ARGUSDEBUG
                        ArgusDebug (1, "setsockopt(%d, SOL_SOCKET, SO_KEEPALIVE, 0x%x, %d) failed:", s, optval, sizeof(int));
#endif
                     }
#ifdef ARGUSDEBUG
                     ArgusDebug (1, "Trying %s port %s Expecting %s records\n", input->hostname, sbuf, ArgusRecordType); 
#endif
                     if ((retn = ArgusConnect (s, hp->ai_addr, hp->ai_addrlen, timeout)) < 0) {
#ifdef ARGUSDEBUG
                        ArgusDebug(1, "connect to %s:%s failed '%s'", input->hostname, sbuf, strerror(errno));
#endif
                        hp = hp->ai_next;
                     } else {
                        retn = s;
                        input->fd = s;
                     }
                  }

                  if (retn < 0)
                     close(s);
#ifdef ARGUSDEBUG
                  else {
                     if (hp->ai_socktype == SOCK_DGRAM)
                        ArgusDebug (1, "receiving\n");
                     else
                        ArgusDebug (1, "connected\n");

                     input->status &= ~ARGUS_CLOSED;
                  }
#endif
               } else
                  ArgusLog (LOG_ERR, "ArgusGetServerSocket: socket() failed. errno %d: %s", errno, strerror(errno));

            } while (hp && (retn < 0));
#endif
         } else {
#if !HAVE_GETADDRINFO
            struct sockaddr_in server;

            bzero ((char *) &server, sizeof (server));

            if ((s = socket (PF_INET, type, 0)) >= 0) {
               if (type == SOCK_DGRAM) {
                  if (input->addr.s_addr != 0)
                     server.sin_addr.s_addr = htonl(input->addr.s_addr);
                  else
                     server.sin_addr.s_addr = INADDR_ANY;

                  server.sin_family = AF_INET;
                  server.sin_port = portnum;

#ifdef ARGUSDEBUG
                  ArgusLog (1, "Binding %s:%d Expecting %s records", 
                       ArgusGetName(ArgusParser, (unsigned char *)&input->addr.s_addr), ntohs(portnum), ArgusRecordType); 
#endif
                  if ((bind (s, (struct sockaddr *)&server, sizeof(server))) < 0)
                     ArgusLog (LOG_ERR, "bind (%d, %s:%hu, %d) failed '%s'", s, inet_ntoa(server.sin_addr),
                                                    server.sin_port, sizeof(server), strerror(errno));
                  retn = s;
                  input->fd = s;

               } else {
                  in_addr_t saddr;
                  int optval = 1;

                  if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval, sizeof(int)) < 0) {
#ifdef ARGUSDEBUG
                     ArgusDebug (1, "setsockopt(%d, SOL_SOCKET, SO_KEEPALIVE, 0x%x, %d) failed:", s, optval, sizeof(int));
#endif
                  }

                  if (ArgusParser->ArgusSourcePort) {
                     server.sin_family = AF_INET;
                     server.sin_addr.s_addr = INADDR_ANY;
                     server.sin_port = htons(ArgusParser->ArgusSourcePort);

#ifdef ARGUSDEBUG
                     ArgusDebug (1, "Binding TCP to source INADDR_ANY:%d Expecting %s records",
                          ArgusGetName(ArgusParser, ArgusParser->ArgusSourcePort, ArgusRecordType));
#endif
                     if ((bind (s, (struct sockaddr *)&server, sizeof(server))) < 0)
                        ArgusLog (LOG_ERR, "bind (%d, %s:%hu, %d) failed '%s'", s, "INADDR_ANY",
                                                       ntohs(server.sin_port), sizeof(server), strerror(errno));
                  }

                  saddr = htonl(input->addr.s_addr);
                  if ((hp = gethostbyaddr ((char *)&saddr, sizeof (saddr), AF_INET)) != NULL) {
                     input->hostname = strdup(hp->h_name);
                     bcopy ((char *) hp->h_addr, (char *)&server.sin_addr, hp->h_length);
                     server.sin_family = hp->h_addrtype;
                     server.sin_port = portnum;
#ifdef ARGUSDEBUG
                     ArgusDebug (1, "Trying %s port %d Expecting %s records\n", (hp->h_name) ?
                                 (hp->h_name) : intoa (saddr), ntohs(portnum), ArgusRecordType); 
#endif
                 } else {
                     server.sin_addr.s_addr = saddr;
                     server.sin_family = AF_INET;
                     server.sin_port = portnum;
#ifdef ARGUSDEBUG
                     ArgusDebug (1, "Trying %s port %d Expecting %s records\n", 
                                   intoa (saddr), ntohs(portnum), ArgusRecordType); 
#endif
                  }

                  if ((retn = ArgusConnect (s, (struct sockaddr *)&server, sizeof(server), timeout)) < 0) {
#ifdef ARGUSDEBUG
                     ArgusDebug(1, "connect to %s:%hu failed '%s'", inet_ntoa(server.sin_addr), 
                         ntohs(server.sin_port), strerror(errno));
#endif
                     close(s);

                  } else {
                     retn = s;
                     input->fd = s;

#ifdef ARGUSDEBUG
                     if (type == SOCK_DGRAM)
                        ArgusDebug (1, "receiving\n");
                     else
                        ArgusDebug (1, "connected\n");
#endif
                  }
               }

            } else {
               ArgusLog (LOG_ERR, "ArgusGetServerSocket: socket() failed. errno %d: %s", errno, strerror(errno));
            }
#endif
         }
         break;
      }

#define ARGUS_SOCKET_PATH  "/tmp/argus.sock"

      case ARGUS_DOMAIN_SOURCE: {
         struct sockaddr_un server;

         bzero ((char *) &server, sizeof (server));

         if ((s = socket (AF_UNIX, SOCK_STREAM, 0)) >= 0) {
            server.sun_family = AF_UNIX;
           
            if (input->filename != NULL) 
               strcpy(server.sun_path, input->filename);
            else
               strcpy(server.sun_path, ARGUS_SOCKET_PATH);

            if ((retn = connect (s, (struct sockaddr *)&server, sizeof(struct sockaddr_un))) < 0) {
               close(s);
            } else {
               retn = s;
#ifdef ARGUSDEBUG
               ArgusDebug (1, "connected\n");
#endif
            }
         } else {
         }
         break;
      }

      case ARGUS_SFLOW_DATA_SOURCE: 
      case ARGUS_JFLOW_DATA_SOURCE: 
      case ARGUS_CISCO_DATA_SOURCE: {
#if HAVE_GETADDRINFO
         if (hp != NULL)
            s = socket (hp->ai_family, hp->ai_socktype, hp->ai_protocol);
         else
#endif
            s = socket (AF_INET, SOCK_DGRAM, 0);

         if (s >= 0) {
            if (hp != NULL) {
#if HAVE_GETADDRINFO
               if (getnameinfo(hp->ai_addr, hp->ai_addrlen, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV))
                  ArgusLog(LOG_ERR, "could not get numeric hostname");

               if (hp->ai_canonname) {
                  if (input->hostname)
                     free(input->hostname);
                  input->hostname = strdup(hp->ai_canonname);
               } else {
                  if (input->hostname)
                     free(input->hostname);
                  input->hostname = strdup(hbuf);
               }

               if (hp->ai_socktype == SOCK_DGRAM) {
#ifdef ARGUSDEBUG
                  char *name = input->hostname;
                  if (!(strncmp(name, "0.0.0.0", 7))) name = "AF_ANY";
                  ArgusLog (1, "Binding %s:%s Expecting %s records", name, sbuf, ArgusRecordType);
#endif
                  if ((retn = bind (s, hp->ai_addr, hp->ai_addrlen)) < 0) {
#ifdef ARGUSDEBUG
                        ArgusDebug(1, "connect to %s:%s failed '%s'", input->hostname, sbuf, strerror(errno));
#endif
                     hp = hp->ai_next;
                  } else {
                     retn = s;
                     input->fd = s;
                  }

               } else {
                  if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&optval, sizeof(int)) < 0) {
#ifdef ARGUSDEBUG
                     ArgusDebug (1, "setsockopt(%d, SOL_SOCKET, SO_KEEPALIVE, 0x%x, %d) failed:", s, optval, sizeof(int));
#endif
                  }
#ifdef ARGUSDEBUG
                  ArgusDebug (1, "Trying %s port %s Expecting %s records\n", input->hostname, sbuf, ArgusRecordType);
#endif
                  if ((retn = ArgusConnect (s, hp->ai_addr, hp->ai_addrlen, timeout)) < 0) {
                     ArgusLog(LOG_WARNING, "connect to %s:%s failed '%s'", input->hostname, sbuf, strerror(errno));
                     hp = hp->ai_next;
                  } else {
                     retn = s;
                     input->fd = s;
                  }
               }

               if (retn < 0)
                  close(s);
#ifdef ARGUSDEBUG
               else {
                  if (hp->ai_socktype == SOCK_DGRAM)
                     ArgusDebug (1, "receiving\n");
                  else
                     ArgusDebug (1, "connected\n");
               }
#endif
#endif
            } else {
               struct sockaddr_in server;
               bzero(&server, sizeof(server));

               if (input->addr.s_addr != 0)
                  server.sin_addr.s_addr = htonl(input->addr.s_addr);
               else
                  server.sin_addr.s_addr = INADDR_ANY;

               server.sin_family = AF_INET;
               server.sin_port   = htons(input->portnum);
#ifdef ARGUSDEBUG
               if ((server.sin_addr.s_addr == INADDR_ANY) || (!(strncmp((char *)&input->addr.s_addr, "0.0.0.0", 7)))) 
                  ArgusLog (1, "Binding %s:%d Expecting %s records", "AF_ANY", input->portnum, ArgusRecordType);
               else {
                  ArgusLog (1, "Binding %s:%d Expecting %s records", (unsigned char *)&input->addr.s_addr, input->portnum, ArgusRecordType);
               }
#endif
               if ((retn = bind (s, (struct sockaddr *)&server, sizeof(server))) < 0) {
                  ArgusLog(LOG_WARNING, "connect to %s:%d failed '%s'", inet_ntoa(server.sin_addr),
                                              ntohs(server.sin_port), strerror(errno)); 
                  close(s);

               } else {
                  retn = s;
                  input->fd = s;
               }
            }
         } else
            ArgusLog (LOG_ERR, "ArgusGetServerSocket: socket() failed. errno %d: %s", errno, strerror(errno));
         break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusGetServerSocket (%p) returning %d", input, retn);
#endif

   return (retn);
}


int
ArgusConnect(int s, const struct sockaddr *name, socklen_t namelen, int timeout)
{
   int retn = 0, flags, width = (s + 1);
   struct timeval tbuf;
   fd_set rset, wset;

   if ((flags = fcntl(s, F_GETFL, 0)) < 0)
      ArgusLog (LOG_ERR, "ArgusConnect: fcntl error %s", strerror(errno));

   if ((fcntl(s, F_SETFL, flags | O_NONBLOCK)) < 0)
      ArgusLog (LOG_ERR, "ArgusConnect: fcntl error %s", strerror(errno));

   if ((retn = connect(s, name, namelen)) < 0)
      if (errno != EINPROGRESS)
         return(retn);

   if (retn) {
      FD_ZERO(&rset); FD_SET(s, &rset);
      FD_ZERO(&wset); FD_SET(s, &wset);
      tbuf.tv_sec  = timeout;
      tbuf.tv_usec = 0;

      if ((retn = select (width, &rset, &wset, NULL, &tbuf)) == 0) {
         errno = ETIMEDOUT;
         return(-1);

      } else {
         if (FD_ISSET(s, &rset) || FD_ISSET(s, &wset)) {
            int error;
            socklen_t len = sizeof(error);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
               return(-1);
            }
            if (error) {
               errno = error;
               return(-1);
            }
         }
      }
   }

   if ((fcntl(s, F_SETFL, flags)) < 0)
      ArgusLog (LOG_ERR, "ArgusConnect: fcntl error %s", strerror(errno));

   return(0);
}

struct ArgusRecordStruct ArgusGenerateRecordBuffer;
struct ArgusCanonRecord  ArgusGenerateCanonBuffer;
char ArgusCanonLabelBuffer[MAXBUFFERLEN];
unsigned char ArgusCanonSrcEncapsBuffer[MAXBUFFERLEN];
unsigned char ArgusCanonDstEncapsBuffer[MAXBUFFERLEN];

struct ArgusRecordStruct *
ArgusGenerateRecordStruct (struct ArgusParserStruct *parser, struct ArgusInput *input, struct ArgusRecord *argus)
{
   unsigned int ArgusReverse = 0, status = 0;
   struct ArgusRecordStruct *retn = NULL;
   struct ArgusCanonRecord  *canon = NULL;
   char *label = NULL;

   if (input != NULL) {
      retn  = &input->ArgusGenerateRecordStructBuf;
      canon = &input->ArgusGenerateRecordCanonBuf;
      label = input->ArgusGenerateRecordLabelBuf;
   } else {
      retn  = &ArgusGenerateRecordBuffer;
      canon = &ArgusGenerateCanonBuffer;
      label = ArgusCanonLabelBuffer;
   }

   if (argus == NULL) {
      bzero ((char *)retn, sizeof(*retn));
      bzero ((char *)canon, sizeof(*canon));

      retn->input = input;
      retn->hdr.type = ARGUS_FAR | ARGUS_VERSION;
      retn->hdr.cause = ARGUS_STATUS;
      retn->hdr.len = 8;
      retn->dsrs[ARGUS_TRANSPORT_INDEX] = &canon->trans.hdr;

      retn->dsrs[ARGUS_TIME_INDEX] = &canon->time.hdr;
      canon->time.hdr.type = ARGUS_TIME_DSR;
      canon->time.hdr.subtype =  ARGUS_TIME_ABSOLUTE_RANGE;
      canon->time.hdr.argus_dsrvl8.qual = ARGUS_TYPE_UTC_MICROSECONDS;
      canon->time.hdr.argus_dsrvl8.len = (sizeof(canon->time) + 3)/4;
      retn->dsrindex |= (0x01 << ARGUS_TIME_INDEX);

      retn->score =  0;
      retn->sload =  0.0;
      retn->dload =  0.0;
      retn->srate =  0.0;
      retn->drate =  0.0;
      retn->pcr   =  0.0;
      retn->dur   =  0.0;

   } else {
      struct ArgusRecordHeader *hdr = &argus->hdr;

      bzero ((char *)retn->dsrs, sizeof(retn->dsrs));
      bzero ((char *)&retn->qhdr, sizeof(retn->qhdr));

      retn->status   = 0;
      retn->dsrindex = 0;
      retn->score    = 0;
      retn->input = input;

      retn->sload =  0.0;
      retn->dload =  0.0;
      retn->srate =  0.0;
      retn->drate =  0.0;
      retn->pcr   =  0.0;
      retn->dur   =  0.0;

      retn->bins = NULL;
      retn->htblhdr = NULL;
      retn->nsq = NULL;

      switch (hdr->type & 0xF0) {
         case ARGUS_MAR: {
            struct ArgusRecord *ns = NULL;

            if (argus->hdr.len > 1) {
               retn->dsrs[0] = (void *) canon;
               bcopy ((char *)argus, (char *)retn->dsrs[0], (argus->hdr.len * 4));
               retn->dsrindex |= (0x01 << ARGUS_MAR_INDEX);
            }
            bcopy((char *)hdr, (char *)&retn->hdr, sizeof(*hdr));

            if (argus == &input->ArgusInitCon) {
               retn->status |= ARGUS_INIT_MAR;
            }
            if ((ns = (struct ArgusRecord *)retn->dsrs[0]) != NULL) {
               if (ns->argus_mar.status & (ARGUS_IDIS_INT | ARGUS_IDIS_IPV4)) {
                  switch (ns->argus_mar.status) {
                     case ARGUS_IDIS_INT:
                     case ARGUS_IDIS_IPV4: {
                        if (ns->argus_mar.value == 0) {
                           ns->argus_mar.value = ns->argus_mar.thisid;
                           ns->argus_mar.thisid = 0;
                        }
                     }
                  }
               }
            }
            break;
         }

         case ARGUS_EVENT:
         case ARGUS_AFLOW:
         case ARGUS_NETFLOW:
         case ARGUS_FAR: {
            struct ArgusDSRHeader *dsr = (struct ArgusDSRHeader *) (hdr + 1);
            int dsrlen = hdr->len * 4;
            char *argusend = (char *)argus + dsrlen;
            double seconds = 0.0;

            bcopy((char *)hdr, (char *)&retn->hdr, sizeof(*hdr));

            while (retn && ((char *) dsr < argusend)) {
               unsigned char type = dsr->type;
               unsigned char subtype = dsr->subtype;
               unsigned char qual = 0;
               int cnt;

               if ((cnt = (((type & ARGUS_IMMEDIATE_DATA) ? 1 :
                           ((subtype & ARGUS_LEN_16BITS)  ? dsr->argus_dsrvl16.len :
                                                            dsr->argus_dsrvl8.len))) * 4) > 0) {

                  if (!(subtype & ARGUS_LEN_16BITS))  qual = dsr->argus_dsrvl8.qual;
                  if (argusend < ((char *)dsr + cnt))
                     break;

                  switch (type & 0x7F) {
                     case ARGUS_FLOW_DSR: {
                        struct ArgusFlow *flow = (struct ArgusFlow *) dsr;

                        bzero ((char *)&canon->flow, sizeof(canon->flow));
                        switch (subtype & 0x3F) {
                           case ARGUS_FLOW_LAYER_3_MATRIX:
                           case ARGUS_FLOW_CLASSIC5TUPLE: {
                              status = flow->hdr.argus_dsrvl8.qual & ARGUS_DIRECTION;

                              switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                 case ARGUS_TYPE_IPV4: {
                                    if (flow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT) {

                                       if ((flow->hdr.subtype & 0x3F) == ARGUS_FLOW_CLASSIC5TUPLE) {  // lets modify the flow direction
                                                                                                      // if needs reversing, to get things right.
                                          if (!(flow->hdr.subtype & ARGUS_REVERSE)) {
                                             canon->flow.frag_flow.ip_src = flow->frag_flow.ip_src;
                                             canon->flow.frag_flow.ip_dst = flow->frag_flow.ip_dst;
                                          } else {
                                             canon->flow.frag_flow.ip_src = flow->frag_flow.ip_dst;
                                             canon->flow.frag_flow.ip_dst = flow->frag_flow.ip_src;
                                          }
                                          canon->flow.frag_flow.ip_p   = flow->frag_flow.ip_p;
                                          canon->flow.frag_flow.pad[0] = 0;
                                          canon->flow.frag_flow.pad[1] = 0;
                                       }
                                    } else {
                                       if (!(flow->hdr.subtype & ARGUS_REVERSE)) {
                                          canon->flow.ip_flow.ip_src = flow->ip_flow.ip_src;
                                          canon->flow.ip_flow.ip_dst = flow->ip_flow.ip_dst;
                                       } else {
                                          canon->flow.ip_flow.ip_src = flow->ip_flow.ip_dst;
                                          canon->flow.ip_flow.ip_dst = flow->ip_flow.ip_src;
                                       }
                                       if ((flow->hdr.subtype & 0x3F) == ARGUS_FLOW_CLASSIC5TUPLE) {
                                          canon->flow.ip_flow.ip_p   = flow->ip_flow.ip_p;
                                          switch (flow->ip_flow.ip_p) {
                                             case IPPROTO_UDP:
                                                if (flow->ip_flow.tp_p == ARGUS_V2_RTCP_FLOWTAG) {
                                                   retn->dsrs[ARGUS_NETWORK_INDEX] = &canon->net.hdr;
                                                   canon->net.hdr.type = ARGUS_NETWORK_DSR;
                                                   canon->net.hdr.subtype = ARGUS_RTCP_FLOW;
                                                   canon->net.hdr.argus_dsrvl8.qual = 0;
                                                   canon->net.hdr.argus_dsrvl8.len = ((sizeof(struct ArgusRTCPObject)+3/4) + 1);
                                                   retn->dsrindex |= (0x01 << ARGUS_NETWORK_INDEX);
                                                }

                                             case IPPROTO_TCP:
                                                if (!(flow->hdr.subtype & ARGUS_REVERSE)) {
                                                   canon->flow.ip_flow.sport = flow->ip_flow.sport;
                                                   canon->flow.ip_flow.dport = flow->ip_flow.dport;
                                                } else {
                                                   canon->flow.ip_flow.sport = flow->ip_flow.dport;
                                                   canon->flow.ip_flow.dport = flow->ip_flow.sport;
                                                }
                                                break;

                                             case IPPROTO_ICMP: 
                                                canon->flow.icmp_flow.type  = flow->icmp_flow.type;
                                                canon->flow.icmp_flow.code  = flow->icmp_flow.code;
                                                canon->flow.icmp_flow.id    = flow->icmp_flow.id;
                                                canon->flow.icmp_flow.ip_id = flow->icmp_flow.ip_id;
                                                break;

                                             case IPPROTO_ESP:
                                                canon->flow.esp_flow.spi = flow->esp_flow.spi;
                                                break;
                                          }
                                       }
                                       if (flow->hdr.argus_dsrvl8.qual & ARGUS_MASKLEN) {
                                          if (!(flow->hdr.subtype & ARGUS_REVERSE)) {
                                             canon->flow.ip_flow.smask = flow->ip_flow.smask;
                                             canon->flow.ip_flow.dmask = flow->ip_flow.dmask;
                                          } else {
                                             canon->flow.ip_flow.smask = flow->ip_flow.dmask;
                                             canon->flow.ip_flow.dmask = flow->ip_flow.smask;
                                          }
                                          if (canon->flow.ip_flow.smask == 0) 
                                             canon->flow.ip_flow.smask = 32;
                                          
                                          if (canon->flow.ip_flow.dmask == 0) 
                                             canon->flow.ip_flow.dmask = 32;
                                       } else {
                                          flow->hdr.argus_dsrvl8.qual |= ARGUS_MASKLEN;
                                          canon->flow.ip_flow.smask = 32;
                                          canon->flow.ip_flow.dmask = 32;
                                       }
                                    }
                                    break; 
                                 }

                                 case ARGUS_TYPE_IPV6: {
                                    int i;

                                    for (i = 0; i < 4; i++) {
                                       if (!(flow->hdr.subtype & ARGUS_REVERSE)) {
                                          canon->flow.ipv6_flow.ip_src[i] = flow->ipv6_flow.ip_src[i];
                                          canon->flow.ipv6_flow.ip_dst[i] = flow->ipv6_flow.ip_dst[i];
                                       } else {
                                          canon->flow.ipv6_flow.ip_dst[i] = flow->ipv6_flow.ip_src[i];
                                          canon->flow.ipv6_flow.ip_src[i] = flow->ipv6_flow.ip_dst[i];
                                       }
                                    }

                                    if ((flow->hdr.subtype & 0x3F) == ARGUS_FLOW_CLASSIC5TUPLE) {
                                       canon->flow.ipv6_flow.flow = flow->ipv6_flow.flow;
                                       switch (canon->flow.ipv6_flow.ip_p = flow->ipv6_flow.ip_p) {
                                          case IPPROTO_TCP:
                                          case IPPROTO_UDP:
                                             if (!(flow->hdr.subtype & ARGUS_REVERSE)) {
                                                canon->flow.ipv6_flow.sport = flow->ipv6_flow.sport;
                                                canon->flow.ipv6_flow.dport = flow->ipv6_flow.dport;
                                             } else {
                                                canon->flow.ipv6_flow.sport = flow->ipv6_flow.dport;
                                                canon->flow.ipv6_flow.dport = flow->ipv6_flow.sport;
                                             }
                                             break;

                                          case IPPROTO_ICMPV6:
                                             canon->flow.icmpv6_flow.type = flow->icmpv6_flow.type;
                                             canon->flow.icmpv6_flow.code = flow->icmpv6_flow.code;
                                             canon->flow.icmpv6_flow.id   = ntohs(flow->icmpv6_flow.id);
                                             break;

                                          case IPPROTO_ESP:
                                             canon->flow.esp_flow.spi = flow->esp_flow.spi;
                                             break;
                                       }
                                    }

                                    if (flow->hdr.argus_dsrvl8.qual & ARGUS_MASKLEN) {
                                       if (!(flow->hdr.subtype & ARGUS_REVERSE)) {
                                          canon->flow.ipv6_flow.smask = flow->ipv6_flow.smask;
                                          canon->flow.ipv6_flow.dmask = flow->ipv6_flow.dmask;
                                       } else {
                                          canon->flow.ipv6_flow.smask = flow->ipv6_flow.dmask;
                                          canon->flow.ipv6_flow.dmask = flow->ipv6_flow.smask;
                                       }
                                       if (canon->flow.ipv6_flow.smask > 128)
                                          canon->flow.ipv6_flow.smask = 128;

                                       if (canon->flow.ipv6_flow.dmask > 128)
                                          canon->flow.ipv6_flow.dmask = 128;

                                       if (canon->flow.ipv6_flow.smask == 0)
                                          canon->flow.ipv6_flow.smask = 128;

                                       if (canon->flow.ipv6_flow.dmask == 0)
                                          canon->flow.ipv6_flow.dmask = 128;

                                    } else {
                                       flow->hdr.argus_dsrvl8.qual |= ARGUS_MASKLEN;
                                       flow->hdr.argus_dsrvl8.len++; 
                                       canon->flow.ipv6_flow.smask = 128;
                                       canon->flow.ipv6_flow.dmask = 128;
                                    }
                                    break; 
                                 }

                                 case ARGUS_TYPE_RARP: {
                                    struct ArgusLegacyRarpFlow *trarp = &flow->lrarp_flow;
                                    struct ArgusRarpFlow        *rarp = &canon->flow.rarp_flow;

                                    flow->hdr.subtype           = ARGUS_FLOW_ARP;
                                    flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_RARP;
                                    flow->hdr.argus_dsrvl8.len  = 1 + sizeof(*rarp)/4;
                                    rarp->hrd     = 1;
                                    rarp->pro     = 2048;
                                    rarp->hln     = 6;
                                    rarp->pln     = 4;
                                    rarp->op      = 3;

                                    rarp->arp_tpa = trarp->arp_tpa;
                                    bcopy((char *)&trarp->srceaddr, (char *)&rarp->shaddr, 6);
                                    bcopy((char *)&trarp->tareaddr, (char *)&rarp->dhaddr, 6);
                                    break;
                                 }

                                 case ARGUS_TYPE_ARP: {
                                    struct ArgusLegacyArpFlow *tarp = &flow->larp_flow;
                                    struct ArgusArpFlow        *arp = &canon->flow.arp_flow;

                                    flow->hdr.subtype           = ARGUS_FLOW_ARP;
                                    flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_ARP;
                                    flow->hdr.argus_dsrvl8.len  = 1 + sizeof(*arp)/4;
                                    arp->hrd     = 1;
                                    arp->pro     = 2048;
                                    arp->hln     = 6;
                                    arp->pln     = 4;
                                    arp->op      = 1;

                                    arp->arp_spa = (tarp->arp_spa);
                                    arp->arp_tpa = (tarp->arp_tpa);
                                    bcopy((char *)&tarp->etheraddr, (char *)&arp->haddr, 6);
                                    break;
                                 }
                                 case ARGUS_TYPE_ETHER: 
                                    if (!(flow->hdr.subtype & ARGUS_REVERSE)) 
                                       bcopy (&flow->mac_flow, &canon->flow.mac_flow, sizeof(canon->flow.mac_flow));
                                    else {
                                       struct ArgusEtherMacFlow *fether = &flow->mac_flow.mac_union.ether;
                                       struct ether_header *fehdr = &fether->ehdr;

                                       struct ArgusEtherMacFlow *cether = &canon->flow.mac_flow.mac_union.ether;
                                       struct ether_header *cehdr = &cether->ehdr;

                                       bcopy((u_char *)&fehdr->ether_dhost, (u_char *)&cehdr->ether_shost, ETHER_ADDR_LEN);
                                       bcopy((u_char *)&fehdr->ether_shost, (u_char *)&cehdr->ether_dhost, ETHER_ADDR_LEN);
                                       cehdr->ether_type =  fehdr->ether_type;
                                       cether->dsap =  fether->dsap;
                                       cether->ssap =  fether->ssap;
                                    }
                                    break;

                                 case ARGUS_TYPE_WLAN:
                                    bcopy (&flow->wlan_flow, &canon->flow.wlan_flow, sizeof(canon->flow.wlan_flow));
                                    break;

                                 case ARGUS_TYPE_MPLS:
                                 case ARGUS_TYPE_VLAN:
                                    bcopy ((char *)flow, &canon->flow, cnt);
                                    break; 

                                 case ARGUS_TYPE_ISIS:
                                    bcopy (&flow->isis_flow, &canon->flow.isis_flow, sizeof(canon->flow.isis_flow));
                                    break;
                              }
                              break;
                           }

                           case ARGUS_FLOW_ARP: {
                              canon->flow.hdr = flow->hdr;

                              switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                 case ARGUS_TYPE_RARP: {
                                    struct ArgusRarpFlow *trarp = &flow->flow_un.rarp;
                                    struct ArgusRarpFlow *rarp  = &canon->flow.flow_un.rarp;

                                    canon->flow.hdr = flow->hdr;
                                    rarp->hrd     = trarp->hrd;
                                    rarp->pro     = trarp->pro;
                                    rarp->hln     = trarp->hln;
                                    rarp->pln     = trarp->pln;
                                    rarp->op      = trarp->op;
                                    rarp->arp_tpa = trarp->arp_tpa;
                                    bcopy (&((char *)&trarp->shaddr)[0],         &rarp->shaddr, rarp->hln);
                                    bcopy (&((char *)&trarp->shaddr)[rarp->hln], &rarp->dhaddr, rarp->hln);
                                    break;
                                 }

                                 case ARGUS_TYPE_ARP: {
                                    struct ArgusArpFlow *tarp = &flow->flow_un.arp;
                                    struct ArgusArpFlow *arp  = &canon->flow.flow_un.arp;

                                    flow->hdr.argus_dsrvl8.len = sizeof(*arp)/4 + 1;
                                    canon->flow.hdr = flow->hdr;

                                    if ((arp->hrd = tarp->hrd) == 0)
                                       arp->hrd     = 1;
                                    if ((arp->pro = tarp->pro) == 0)
                                       arp->pro     = 2048;
                                    if ((arp->hln = tarp->hln) == 0)
                                       arp->hln     = 6;
                                    if ((arp->pln = tarp->pln) == 0)
                                       arp->pln     = 4;

                                    arp->op      = tarp->op;
                                    arp->arp_spa = tarp->arp_spa;
                                    arp->arp_tpa = tarp->arp_tpa;
                                    bcopy ((char *)&arp->haddr, &arp->haddr, arp->hln);
                                    break;
                                 }

                                 default: {
                                    struct ArgusInterimArpFlow *tarp = &flow->flow_un.iarp;
                                    struct ArgusArpFlow         *arp = &canon->flow.flow_un.arp;
    
                                    flow->hdr.subtype = ARGUS_FLOW_ARP;
                                    flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_ARP;
                                    flow->hdr.argus_dsrvl8.len  = sizeof(*arp)/4 + 1;
                                    arp->hrd     = 1;
                                    arp->pro     = tarp->pro;
                                    arp->hln     = tarp->hln;
                                    arp->pln     = tarp->pln;
                                    arp->op      = 0;
                                    arp->arp_spa = tarp->arp_spa;
                                    arp->arp_tpa = tarp->arp_tpa;
                                    bcopy ((char *)&arp->haddr, &arp->haddr, arp->hln);
                                 }
                              }
                              break; 
                           }

                           default:
                              break; 
                        }

                        bcopy((char *)&flow->hdr, (char *)&canon->flow.hdr, sizeof(flow->hdr));

                        retn->dsrs[ARGUS_FLOW_INDEX] = (struct ArgusDSRHeader*) &canon->flow;
                        retn->dsrindex |= (0x01 << ARGUS_FLOW_INDEX);
                        break;
                     }

                     case ARGUS_FLOW_HASH_DSR: {
                        struct ArgusFlowHashStruct *hash = (struct ArgusFlowHashStruct *) dsr;

                        bcopy(hash, (char *)&canon->hash, sizeof(*hash));
                        retn->dsrs[ARGUS_FLOW_HASH_INDEX] = (struct ArgusDSRHeader*) &canon->hash;
                        retn->dsrindex |= (0x01 << ARGUS_FLOW_HASH_INDEX);
                        break;
                     }
        
                     case ARGUS_TRANSPORT_DSR: {
                        struct ArgusTransportStruct *trans = (struct ArgusTransportStruct *) dsr;

                        ArgusGenerateTransportStruct(trans, cnt, &canon->trans,
                                                     input->major_version);
                        retn->dsrs[ARGUS_TRANSPORT_INDEX] = (struct ArgusDSRHeader*) &canon->trans;
                        retn->dsrindex |= (0x01 << ARGUS_TRANSPORT_INDEX);
                        break;
                     }

                     case ARGUS_ENCAPS_DSR: {
                        struct ArgusEncapsStruct *encaps  = (struct ArgusEncapsStruct *) dsr;
                        struct ArgusEncapsStruct *cncaps = &canon->encaps;
                        int len = encaps->hdr.argus_dsrvl8.len;
                        int tlen = (len > 3) ? 4 : 3;
// the structure for encaps is 3 ints of basic data, and if there is an encapsulation
// header buffer, then the 4th int holds the sbuf and dbuf lengths. 
// if these lengths are > 0, then allocate buffers and copy into sbuf, and dbuf ...

                        memcpy((char *) cncaps, (char *) encaps, tlen * 4);
                        if (len > 3) {
                           unsigned char *cptr = (void *) &encaps->sbuf;
                           if (encaps->slen > 0) {
                              int clen = encaps->slen;
                              cncaps->sbuf = ArgusCanonSrcEncapsBuffer;
                              memcpy(cncaps->sbuf, cptr, clen);
                              cptr += clen;
			   }
			   if (encaps->dlen > 0) {
                              int clen = encaps->dlen;
                              cncaps->dbuf = ArgusCanonDstEncapsBuffer;
                              memcpy(cncaps->dbuf, cptr, clen);
			   }
			}

                        retn->dsrs[ARGUS_ENCAPS_INDEX] = &cncaps->hdr;
                        retn->dsrindex |= (0x01 << ARGUS_ENCAPS_INDEX);
                        break;
                     }

                     case ARGUS_TIME_DSR: {
                        struct ArgusTimeObject *time  = (struct ArgusTimeObject *) dsr;
                        struct ArgusTimeObject *ctime = (struct ArgusTimeObject *) &canon->time;
                        int i, num = (time->hdr.argus_dsrvl8.len - 1)/2;

                        if (subtype & (ARGUS_TIME_SRC_START | ARGUS_TIME_DST_START)) {  // 3.0 time bi-directional dsr subtype
                           unsigned int *tptr = (unsigned int *) (dsr + 1);
                           int tlen = 2, sindex = -1, tind = 0, cnt = 0;
                           struct ArgusTime *tstart = NULL;
                           unsigned int *tval = NULL;

                           bzero ((char *)ctime, sizeof(*ctime));
                           ctime->hdr = time->hdr;

                           for (i = 0; i < 4; i++) {
                              int stype = (ARGUS_TIME_SRC_START << i);
                              if (subtype & stype) {
                                 tind |= (ARGUS_TIME_SRC_START << i);
                                 cnt++;
                                 switch(stype) {
                                    case ARGUS_TIME_SRC_START: {
                                       if (tstart == NULL) tstart = &ctime->src.start;
                                       break;
                                    }
                                    case ARGUS_TIME_DST_START: {
                                       if (tstart == NULL) tstart = &ctime->dst.start;
                                       break;
                                    }
                                 }
                              }
                           }

                           if (!(tind & ARGUS_TIME_SRC_START) && (tind & ARGUS_TIME_SRC_END)) {
                              tind &= ~ARGUS_TIME_SRC_END;
                              cnt--;
                           }
                           if (!(tind & ARGUS_TIME_DST_START) && (tind & ARGUS_TIME_DST_END)) {
                              tind &= ~ARGUS_TIME_DST_END;
                              cnt--;
                           }

// test length against number of objects in the dsr, and correct
// subtype so that it refects use of absolute vs relative.
                           subtype &= ~(0x07);

                           if (cnt == num) {  // this is an absolute timestamp. each timestamp uses 2 ints.
                              if (cnt == 1)
                                 subtype |= ARGUS_TIME_ABSOLUTE_TIMESTAMP;
                              else
                                 subtype |= ARGUS_TIME_ABSOLUTE_RANGE;
                           } else {
                              if (cnt < num) 
                                 subtype |= ARGUS_TIME_ABSOLUTE_RANGE;
                              else {
                                 if (cnt == 1)
                                    subtype |= ARGUS_TIME_RELATIVE_TIMESTAMP;
                                 else {
                                    if (time->hdr.argus_dsrvl8.len == (1 + (cnt + 1))) 
                                       subtype |= ARGUS_TIME_RELATIVE_RANGE;
                                    else
                                       subtype |= ARGUS_TIME_ABSOLUTE_TIMESTAMP;
                                 }
                              }
                           }
                              
                           time->hdr.subtype = subtype;
                           ctime->hdr = time->hdr;

                           sindex = (subtype & ARGUS_TIME_SRC_START) ? 0 : 2;

                           for (i = 0; i < 4; i++) {
                              if (subtype & (ARGUS_TIME_SRC_START << i)) {
                                 switch (ARGUS_TIME_SRC_START << i) {
                                    case ARGUS_TIME_SRC_START: {
                                       tval = (unsigned int *)&ctime->src.start;
                                       break;
                                    }
                                    case ARGUS_TIME_SRC_END: {
                                       tval = (unsigned int *)&ctime->src.end;
                                       break;
                                    }
                                    case ARGUS_TIME_DST_START: {
                                       tval = (unsigned int *)&ctime->dst.start;
                                       break;
                                    }
                                    case ARGUS_TIME_DST_END: {
                                       tval = (unsigned int *)&ctime->dst.end;
                                       break;
                                    }
                                 }

                                 if (tval && tlen) {
                                    switch (subtype & 0x07) {
                                       case ARGUS_TIME_ABSOLUTE_RANGE:
                                       case ARGUS_TIME_ABSOLUTE_TIMESTAMP: {
                                          int y;
                                          for (y = 0; y < tlen; y++)
                                             *tval++ = (*(unsigned int *)tptr++);
                                          break;
                                       }

                                       case ARGUS_TIME_RELATIVE_TIMESTAMP:
                                       case ARGUS_TIME_RELATIVE_RANGE:
                                       case ARGUS_TIME_ABSOLUTE_RELATIVE_RANGE: {
                                          int y;
                                          if (i == sindex) {
                                             for (y = 0; y < tlen; y++)
                                                *tval++ = (*(unsigned int *)tptr++);

                                          } else {
                                             struct ArgusTime tbuf, *tvp = &tbuf; 
                                             long long stime, secs, usecs;
                                             int rtime = *(int *)tptr++;

                                             stime = (tstart->tv_sec * 1000000LL) + tstart->tv_usec;

                                             stime += rtime;
                                             secs = stime / 1000000LL;
                                             usecs = stime - (secs * 1000000LL);
                                             tvp->tv_sec  = secs;
                                             tvp->tv_usec = usecs;

                                             bcopy(tvp, tval, sizeof(*tvp));
                                          }
                                          break;
                                       }
                                    }
                                 }
                              }
                           }

                           if (ctime->src.end.tv_sec == 0) {
                              ctime->src.end = ctime->src.start;
                           } else {
                              long long svalue = (ctime->src.start.tv_sec * 1000000LL);
                              long long evalue = (ctime->src.end.tv_sec * 1000000LL);
                              if (ctime->hdr.argus_dsrvl8.qual == ARGUS_TYPE_UTC_NANOSECONDS) {
                                 svalue += (ctime->src.start.tv_usec)/1000;
                                 evalue += (ctime->src.end.tv_usec)/1000;
                              } else {
                                 svalue += (ctime->src.start.tv_usec);
                                 evalue += (ctime->src.end.tv_usec);
                              }

                              if (svalue > evalue) {
                                 struct ArgusTime tbuf, *tvp = &tbuf; 
                                 *tvp = ctime->src.start;
                                 ctime->src.start = ctime->src.end;
                                 ctime->src.end = *tvp;
                              }
                           }
                           if (ctime->dst.end.tv_sec == 0) {
                              if (ctime->dst.start.tv_sec != 0) {
                                 ctime->dst.end = ctime->dst.start;
                              }
                           } else {
                              long long svalue = (ctime->dst.start.tv_sec * 1000000LL);
                              long long evalue = (ctime->dst.end.tv_sec * 1000000LL);
                              if (ctime->hdr.argus_dsrvl8.qual == ARGUS_TYPE_UTC_NANOSECONDS) {
                                 svalue += (ctime->dst.start.tv_usec)/1000;
                                 evalue += (ctime->dst.end.tv_usec)/1000;
                              } else {
                                 svalue += (ctime->dst.start.tv_usec);
                                 evalue += (ctime->dst.end.tv_usec);
                              } 
                              if (svalue > evalue) {
                                 struct ArgusTime tbuf, *tvp = &tbuf;
                                 *tvp = ctime->dst.start;
                                 ctime->dst.start = ctime->dst.end;
                                 ctime->dst.end = *tvp;
                              }
                           }

                        } else {
                           bcopy((char *)dsr, (char *)&canon->time, cnt);

                           switch (subtype & 0x3F) {                 // subtype set at top of loop
                              case ARGUS_TIME_ABSOLUTE_TIMESTAMP:
                              case ARGUS_TIME_ABSOLUTE_RANGE:
                                 break;
                              case ARGUS_TIME_ABSOLUTE_RELATIVE_RANGE:  // end.tv_sec is delta uSec 
                                 ctime->src.end.tv_sec  = ctime->src.start.tv_sec  + (time->src.end.tv_sec / 1000000);
                                 ctime->src.end.tv_usec = ctime->src.start.tv_usec + (time->src.end.tv_sec % 1000000);
                                 if (ctime->src.end.tv_usec > 1000000) {
                                    ctime->src.end.tv_sec++;
                                    ctime->src.end.tv_usec -= 1000000;
                                 }
                                 break;
                              case ARGUS_TIME_RELATIVE_TIMESTAMP:
                                 break;
                              case ARGUS_TIME_RELATIVE_RANGE:
                                 break;
                           }

                           if (cnt < sizeof(struct ArgusTimeObject))
                              bzero (&((char *)&canon->time)[cnt], sizeof(struct ArgusTimeObject) - cnt);

                           canon->time.hdr.subtype &= ~(ARGUS_TIME_MASK);

                           if (canon->time.src.start.tv_sec)
                              canon->time.hdr.subtype |= ARGUS_TIME_SRC_START;
                           if (canon->time.src.end.tv_sec)
                              canon->time.hdr.subtype |= ARGUS_TIME_SRC_END;

                           switch (subtype & 0x3F) {
                              case ARGUS_TIME_ABSOLUTE_TIMESTAMP:
                              case ARGUS_TIME_ABSOLUTE_RANGE:
                              case ARGUS_TIME_ABSOLUTE_RELATIVE_RANGE:
                                 if (!(ctime->src.start.tv_sec))
                                    ctime->src.start = ctime->src.end;
                                 if (!(ctime->src.end.tv_sec))
                                    ctime->src.end = ctime->src.start;
                                 break;
                           }
                        }

                        if (ctime->hdr.argus_dsrvl8.qual == ARGUS_TYPE_UTC_NANOSECONDS) {
                           ctime->hdr.argus_dsrvl8.qual = ARGUS_TYPE_UTC_MICROSECONDS;
                           ctime->src.start.tv_usec /= 1000;
                           ctime->src.end.tv_usec   /= 1000;
                           ctime->dst.start.tv_usec /= 1000;
                           ctime->dst.end.tv_usec   /= 1000;
                        }

                        if (ctime->src.start.tv_usec > 1000000)
                           ctime->src.start.tv_usec = 999999;
                        if (ctime->src.end.tv_usec > 1000000)
                           ctime->src.end.tv_usec = 999999;

                        ctime->hdr.argus_dsrvl8.len = (sizeof(*time) + 3)/4;
                        retn->dsrs[ARGUS_TIME_INDEX] = (struct ArgusDSRHeader*) &ctime->hdr;
                        retn->dsrindex |= (0x01 << ARGUS_TIME_INDEX);
                        break;
                     }

                     case ARGUS_METER_DSR: {
                        if (subtype & ARGUS_METER_PKTS_BYTES) {
                           canon->metric.src.appbytes = 0;
                           canon->metric.dst.appbytes = 0;

                           switch (dsr->argus_dsrvl8.qual & 0x0F) {
                              case ARGUS_SRCDST_BYTE:
                                 canon->metric.src.pkts  = ((unsigned char *)(dsr + 1))[0];
                                 canon->metric.src.bytes = ((unsigned char *)(dsr + 1))[1];
                                 canon->metric.dst.pkts  = ((unsigned char *)(dsr + 1))[2];
                                 canon->metric.dst.bytes = ((unsigned char *)(dsr + 1))[3];
                                 break;
                              case ARGUS_SRCDST_SHORT:
                                 canon->metric.src.pkts  = (((unsigned short *)(dsr + 1))[0]);
                                 canon->metric.src.bytes = (((unsigned short *)(dsr + 1))[1]);
                                 canon->metric.dst.pkts  = (((unsigned short *)(dsr + 1))[2]);
                                 canon->metric.dst.bytes = (((unsigned short *)(dsr + 1))[3]);
                                 break;
                              case ARGUS_SRCDST_INT:
                                 canon->metric.src.pkts  = (((unsigned int *)(dsr + 1))[0]);
                                 canon->metric.src.bytes = (((unsigned int *)(dsr + 1))[1]);
                                 canon->metric.dst.pkts  = (((unsigned int *)(dsr + 1))[2]);
                                 canon->metric.dst.bytes = (((unsigned int *)(dsr + 1))[3]);
                                 break;
                              case ARGUS_SRCDST_LONGLONG:
                                 canon->metric.src.pkts  = (((unsigned long long *)(dsr + 1))[0]);
                                 canon->metric.src.bytes = (((unsigned long long *)(dsr + 1))[1]);
                                 canon->metric.dst.pkts  = (((unsigned long long *)(dsr + 1))[2]);
                                 canon->metric.dst.bytes = (((unsigned long long *)(dsr + 1))[3]);
                                 break;
                              case ARGUS_SRC_SHORT:
                                 canon->metric.src.pkts  = (((unsigned short *)(dsr + 1))[0]);
                                 canon->metric.src.bytes = (((unsigned short *)(dsr + 1))[1]);
                                 canon->metric.dst.pkts  = 0;
                                 canon->metric.dst.bytes = 0;
                                 break;
                              case ARGUS_SRC_INT:
                                 canon->metric.src.pkts  = (((unsigned int *)(dsr + 1))[0]);
                                 canon->metric.src.bytes = (((unsigned int *)(dsr + 1))[1]);
                                 canon->metric.dst.pkts  = 0;
                                 canon->metric.dst.bytes = 0;
                                 break;
                              case ARGUS_SRC_LONGLONG:
                                 bcopy((char *)(dsr + 1), (char *)&canon->metric.src, 16);
                                 canon->metric.dst.pkts  = 0;
                                 canon->metric.dst.bytes = 0;
                                 break;
                              case ARGUS_DST_SHORT:
                                 canon->metric.src.pkts  = 0;
                                 canon->metric.src.bytes = 0;
                                 canon->metric.dst.pkts  = (((unsigned short *)(dsr + 1))[0]);
                                 canon->metric.dst.bytes = (((unsigned short *)(dsr + 1))[1]);
                                 break;
                              case ARGUS_DST_INT:
                                 canon->metric.src.pkts  = 0;
                                 canon->metric.src.bytes = 0;
                                 canon->metric.dst.pkts  = (((unsigned int *)(dsr + 1))[0]);
                                 canon->metric.dst.bytes = (((unsigned int *)(dsr + 1))[1]);
                                 break;
                              case ARGUS_DST_LONGLONG:
                                 canon->metric.src.pkts  = 0;
                                 canon->metric.src.bytes = 0;
                                 bcopy((char *)(dsr + 1), (char *)&canon->metric.dst, 16);
                                 break;
                           }

                        } else
                        if (subtype & ARGUS_METER_PKTS_BYTES_APP) {
                           switch (dsr->argus_dsrvl8.qual & 0x0F) {
                              case ARGUS_SRCDST_BYTE:
                                 canon->metric.src.pkts     = ((unsigned char *)(dsr + 1))[0];
                                 canon->metric.src.bytes    = ((unsigned char *)(dsr + 1))[1];
                                 canon->metric.src.appbytes = ((unsigned char *)(dsr + 1))[2];
                                 canon->metric.dst.pkts     = ((unsigned char *)(dsr + 1))[3];
                                 canon->metric.dst.bytes    = ((unsigned char *)(dsr + 1))[4];
                                 canon->metric.dst.appbytes = ((unsigned char *)(dsr + 1))[5];
                                 break;
                              case ARGUS_SRCDST_SHORT:
                                 canon->metric.src.pkts     = (((unsigned short *)(dsr + 1))[0]);
                                 canon->metric.src.bytes    = (((unsigned short *)(dsr + 1))[1]);
                                 canon->metric.src.appbytes = (((unsigned short *)(dsr + 1))[2]);
                                 canon->metric.dst.pkts     = (((unsigned short *)(dsr + 1))[3]);
                                 canon->metric.dst.bytes    = (((unsigned short *)(dsr + 1))[4]);
                                 canon->metric.dst.appbytes = (((unsigned short *)(dsr + 1))[5]);
                                 break;
                              case ARGUS_SRCDST_INT:
                                 canon->metric.src.pkts     = (((unsigned int *)(dsr + 1))[0]);
                                 canon->metric.src.bytes    = (((unsigned int *)(dsr + 1))[1]);
                                 canon->metric.src.appbytes = (((unsigned int *)(dsr + 1))[2]);
                                 canon->metric.dst.pkts     = (((unsigned int *)(dsr + 1))[3]);
                                 canon->metric.dst.bytes    = (((unsigned int *)(dsr + 1))[4]);
                                 canon->metric.dst.appbytes = (((unsigned int *)(dsr + 1))[5]);
                                 break;
                              case ARGUS_SRCDST_LONGLONG:
                                 canon->metric.src.pkts     = (((long long *)(dsr + 1))[0]);
                                 canon->metric.src.bytes    = (((long long *)(dsr + 1))[1]);
                                 canon->metric.src.appbytes = (((long long *)(dsr + 1))[2]);
                                 canon->metric.dst.pkts     = (((long long *)(dsr + 1))[3]);
                                 canon->metric.dst.bytes    = (((long long *)(dsr + 1))[4]);
                                 canon->metric.dst.appbytes = (((long long *)(dsr + 1))[5]);
                                 break;
                              case ARGUS_SRC_BYTE:
                                 canon->metric.src.pkts     = (((unsigned char *)(dsr + 1))[0]);
                                 canon->metric.src.bytes    = (((unsigned char *)(dsr + 1))[1]);
                                 canon->metric.src.appbytes = (((unsigned char *)(dsr + 1))[2]);
                                 canon->metric.dst.pkts     = 0;
                                 canon->metric.dst.bytes    = 0;
                                 canon->metric.dst.appbytes = 0;
                                 break;
                              case ARGUS_SRC_SHORT:
                                 canon->metric.src.pkts     = (((unsigned short *)(dsr + 1))[0]);
                                 canon->metric.src.bytes    = (((unsigned short *)(dsr + 1))[1]);
                                 canon->metric.src.appbytes = (((unsigned short *)(dsr + 1))[2]);
                                 canon->metric.dst.pkts     = 0;
                                 canon->metric.dst.bytes    = 0;
                                 canon->metric.dst.appbytes = 0;
                                 break;
                              case ARGUS_SRC_INT:
                                 canon->metric.src.pkts     = (((unsigned int *)(dsr + 1))[0]);
                                 canon->metric.src.bytes    = (((unsigned int *)(dsr + 1))[1]);
                                 canon->metric.src.appbytes = (((unsigned int *)(dsr + 1))[2]);
                                 canon->metric.dst.pkts     = 0;
                                 canon->metric.dst.bytes    = 0;
                                 canon->metric.dst.appbytes = 0;
                                 break;
                              case ARGUS_SRC_LONGLONG:
                                 bcopy((char *)(dsr + 1), (char *)&canon->metric.src, 24);
                                 canon->metric.dst.pkts     = 0;
                                 canon->metric.dst.bytes    = 0;
                                 canon->metric.dst.appbytes = 0;
                                 break;
                              case ARGUS_DST_BYTE:
                                 canon->metric.src.pkts     = 0;
                                 canon->metric.src.bytes    = 0;
                                 canon->metric.src.appbytes = 0;
                                 canon->metric.dst.pkts     = (((unsigned char *)(dsr + 1))[0]);
                                 canon->metric.dst.bytes    = (((unsigned char *)(dsr + 1))[1]);
                                 canon->metric.dst.appbytes = (((unsigned char *)(dsr + 1))[2]);
                                 break;
                              case ARGUS_DST_SHORT:
                                 canon->metric.src.pkts     = 0;
                                 canon->metric.src.bytes    = 0;
                                 canon->metric.src.appbytes = 0;
                                 canon->metric.dst.pkts     = (((unsigned short *)(dsr + 1))[0]);
                                 canon->metric.dst.bytes    = (((unsigned short *)(dsr + 1))[1]);
                                 canon->metric.dst.appbytes = (((unsigned short *)(dsr + 1))[2]);
                                 break;
                              case ARGUS_DST_INT:
                                 canon->metric.src.pkts     = 0;
                                 canon->metric.src.bytes    = 0;
                                 canon->metric.src.appbytes = 0;
                                 canon->metric.dst.pkts     = (((unsigned int *)(dsr + 1))[0]);
                                 canon->metric.dst.bytes    = (((unsigned int *)(dsr + 1))[1]);
                                 canon->metric.dst.appbytes = (((unsigned int *)(dsr + 1))[2]);
                                 break;
                              case ARGUS_DST_LONGLONG:
                                 canon->metric.src.pkts     = 0;
                                 canon->metric.src.bytes    = 0;
                                 canon->metric.src.appbytes = 0;
                                 bcopy((char *)(dsr + 1), (char *)&canon->metric.dst, 24);
                                 break;
                           }
                        }

                        bcopy((char *)dsr, (char *)&canon->metric.hdr, sizeof(*dsr));
                        canon->metric.hdr.argus_dsrvl8.len  = sizeof(canon->metric)/4;

                        retn->dsrs[ARGUS_METRIC_INDEX] = (struct ArgusDSRHeader*) &canon->metric;
                        retn->dsrindex |= (0x01 << ARGUS_METRIC_INDEX);
                        break;
                     }

                     case ARGUS_PSIZE_DSR: {
                        int i, offset = 0;
                        switch (dsr->argus_dsrvl8.qual & 0x0F) {
                           case ARGUS_SRCDST_SHORT:
                              dsr->subtype |= ARGUS_PSIZE_SRC_MAX_MIN | ARGUS_PSIZE_DST_MAX_MIN;
                              canon->psize.src.psizemin = (((unsigned short *)(dsr + 1))[0]);
                              canon->psize.src.psizemax = (((unsigned short *)(dsr + 1))[1]);
                              canon->psize.dst.psizemin = (((unsigned short *)(dsr + 1))[2]);
                              canon->psize.dst.psizemax = (((unsigned short *)(dsr + 1))[3]);
                              offset = 3;
                              break;

                           case ARGUS_SRC_SHORT:
                              dsr->subtype |= ARGUS_PSIZE_SRC_MAX_MIN;
                              canon->psize.src.psizemin = (((unsigned short *)(dsr + 1))[0]);
                              canon->psize.src.psizemax = (((unsigned short *)(dsr + 1))[1]);
                              canon->psize.dst.psizemin = 0;
                              canon->psize.dst.psizemax = 0;
                              offset = 2;
                              break;

                           case ARGUS_DST_SHORT:
                              dsr->subtype |= ARGUS_PSIZE_DST_MAX_MIN;
                              canon->psize.src.psizemin = 0;
                              canon->psize.src.psizemax = 0;
                              canon->psize.dst.psizemin = (((unsigned short *)(dsr + 1))[0]);
                              canon->psize.dst.psizemax = (((unsigned short *)(dsr + 1))[1]);
                              offset = 2;
                              break;
                        }

                        if (dsr->subtype & ARGUS_PSIZE_HISTO) {
                           if (dsr->subtype & ARGUS_PSIZE_SRC_MAX_MIN) {
                              unsigned char *ptr = (unsigned char *)(dsr + offset);
                              for (i = 0; i < 4; i++) {
                                 unsigned char value = *ptr++;
                                 canon->psize.src.psize[(i*2)]   = (value & 0xF0) >> 4;
                                 canon->psize.src.psize[(i*2)+1] = (value & 0x0F);
                              }
                              offset++;
                           } else
                              bzero(&canon->psize.src.psize, sizeof(canon->psize.src.psize));

                           if (dsr->subtype & ARGUS_PSIZE_DST_MAX_MIN) {
                              unsigned char *ptr = (unsigned char *)(dsr + offset);
                              for (i = 0; i < 4; i++) {
                                 unsigned char value = *ptr++;
                                 canon->psize.dst.psize[(i*2)]   = (value & 0xF0) >> 4;
                                 canon->psize.dst.psize[(i*2)+1] = (value & 0x0F);
                              }
                           } else
                              bzero(&canon->psize.dst.psize, sizeof(canon->psize.dst.psize));
                        }

                        bcopy((char *)dsr, (char *)&canon->psize.hdr, sizeof(*dsr));
                        canon->psize.hdr.argus_dsrvl8.len  = sizeof(canon->psize)/4;
                        retn->dsrs[ARGUS_PSIZE_INDEX] = (struct ArgusDSRHeader*) &canon->psize;
                        retn->dsrindex |= (0x01 << ARGUS_PSIZE_INDEX);
                        break;
                     }

                     case ARGUS_NETWORK_DSR: {
                        struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) dsr;
                        retn->dsrs[ARGUS_NETWORK_INDEX] = (struct ArgusDSRHeader*) &canon->net;
                        retn->dsrindex |= (0x01 << ARGUS_NETWORK_INDEX);

                        switch (subtype) {
                           case 0:
                              retn->dsrs[ARGUS_NETWORK_INDEX] = NULL;
                              retn->dsrindex &= ~(0x01 << ARGUS_NETWORK_INDEX);
                              break;

                           case ARGUS_RTP_FLOW: {
                              struct ArgusRTPObject *rtp = (void *) &net->net_union.rtp;
                              if (cnt == (sizeof(*rtp) + 4))
                                 bcopy((char *)net, (char *)&canon->net, cnt);
                              else {
                                 retn->dsrs[ARGUS_NETWORK_INDEX] = NULL;
                                 retn->dsrindex &= ~(0x01 << ARGUS_NETWORK_INDEX);
                              }
                              break;
                           }
                           case ARGUS_RTCP_FLOW: {
                              struct ArgusRTCPObject *rtcp = (void *) &net->net_union.rtcp;
                              if (cnt == (sizeof(*rtcp) + 4))
                                 bcopy((char *)net, (char *)&canon->net, cnt);
                              else {
                                 retn->dsrs[ARGUS_NETWORK_INDEX] = NULL;
                                 retn->dsrindex &= ~(0x01 << ARGUS_NETWORK_INDEX);
                              }
                              break;
                           }

                           default:
                           case ARGUS_NETWORK_SUBTYPE_FRAG: {
                              bcopy((char *)net, (char *)&canon->net, cnt);
                              break;
                           }

                           case ARGUS_TCP_INIT: {
                              if (qual == 0) {   // Version 1
                                 struct ArgusTCPInitStatusV1 *tcpinit = (void *) &net->net_union.tcpinit;
                                 struct ArgusTCPObject *tcp = (void *) &canon->net.net_union.tcp;
                                 bcopy((char *)&net->hdr, (char *)&canon->net.hdr, sizeof(net->hdr));
                                 memset(tcp, 0, sizeof(*tcp));
                                 tcp->status = tcpinit->status;
                                 tcp->src.seqbase = tcpinit->seqbase;
                                 tcp->options = tcpinit->options;
                                 tcp->src.win = tcpinit->win;
                                 tcp->src.flags = tcpinit->flags;
                                 tcp->src.winshift = tcpinit->winshift;
                                 tcp->src.maxseg = 0;
                                 canon->net.hdr.argus_dsrvl8.qual = ARGUS_TCP_INIT_V2;
                                 canon->net.hdr.argus_dsrvl8.len  = ((sizeof(*tcp) + 3)/4) + 1;
                              } else {
                                 struct ArgusTCPInitStatus *tcpinit = (void *) &net->net_union.tcpinit;
                                 struct ArgusTCPObject *tcp = (void *) &canon->net.net_union.tcp;
                                 bcopy((char *)&net->hdr, (char *)&canon->net.hdr, sizeof(net->hdr));
                                 memset(tcp, 0, sizeof(*tcp));
                                 tcp->status = tcpinit->status;
                                 tcp->src.seqbase = tcpinit->seqbase;
                                 tcp->options = tcpinit->options;
                                 tcp->src.win = tcpinit->win;
                                 tcp->src.flags = tcpinit->flags;
                                 tcp->src.winshift = tcpinit->winshift;
                                 tcp->src.maxseg = tcpinit->maxseg;
                                 canon->net.hdr.argus_dsrvl8.len  = ((sizeof(*tcp) + 3)/4) + 1;
                              }
                              break;
                           }
                           case ARGUS_TCP_STATUS: {
                              struct ArgusTCPStatus *tcpstatus = (void *) &net->net_union.tcpstatus;
                              struct ArgusTCPObject *tcp = (void *) &canon->net.net_union.tcp;
                              bcopy((char *)&net->hdr, (char *)&canon->net.hdr, sizeof(net->hdr));

                              memset(tcp, 0, sizeof(*tcp));
                              tcp->status = tcpstatus->status;
                              tcp->src.flags = tcpstatus->src;
                              tcp->dst.flags = tcpstatus->dst;

                              if (!canon->metric.src.pkts) {
                                 tcp->src.flags = 0;
                              }
                              if (!canon->metric.dst.pkts) {
                                 tcp->dst.flags = 0;
                              }
                              canon->net.hdr.argus_dsrvl8.qual = ARGUS_TCP_INIT_V2;
                              canon->net.hdr.argus_dsrvl8.len  = ((sizeof(*tcp) + 3)/4) + 1;
                              break;
                           }
                           case ARGUS_TCP_PERF: {
                              if (qual == 0) {   // Version 1
                                 struct ArgusTCPObjectV1 *tcpperf = (void *) &net->net_union.tcp;
                                 struct ArgusTCPObject *tcp = (void *) &canon->net.net_union.tcp;

                                 bcopy((char *)&net->hdr, (char *)&canon->net.hdr, sizeof(net->hdr));
                                 memset(tcp, 0, sizeof(*tcp));
                                 tcp->status = tcpperf->status;
                                 tcp->state = tcpperf->state;
                                 tcp->options = tcpperf->options;
                                 tcp->synAckuSecs = tcpperf->synAckuSecs;
                                 tcp->ackDatauSecs = tcpperf->ackDatauSecs;
                                 bcopy((char *)&tcpperf->src, (char *)&tcp->src, sizeof(tcpperf->src));
                                 bcopy((char *)&tcpperf->dst, (char *)&tcp->dst, sizeof(tcpperf->dst));
                                 tcp->src.maxseg = 0;
                                 tcp->dst.maxseg = 0;

                                 canon->net.hdr.argus_dsrvl8.qual = ARGUS_TCP_INIT_V2;
                                 canon->net.hdr.argus_dsrvl8.len  = ((sizeof(*tcp) + 3)/4) + 1;

                              } else {
                                 struct ArgusTCPObject *tcp = (struct ArgusTCPObject *) &canon->net.net_union.tcp;

                                 bcopy((char *)net, (char *)&canon->net, cnt);
                                 if (!canon->metric.src.pkts) {
                                    tcp->src.win = 0;
                                    tcp->src.flags = 0;
                                 }
                                 if (!canon->metric.dst.pkts) {
                                    tcp->dst.win = 0;
                                    tcp->dst.flags = 0;
                                 }
                              }
                              break;
                           }
                        }
                        break;
                     }

                     case ARGUS_MAC_DSR: {
                        struct ArgusMacStruct *mac = (struct ArgusMacStruct *) dsr;

                        switch (mac->hdr.subtype & 0x3F) {
                           default:
                           case ARGUS_TYPE_ETHER: {
                              bcopy((char *)mac, (char *)&canon->mac, cnt);
                              break;
                           }
                        }
                        retn->dsrs[ARGUS_MAC_INDEX] = (struct ArgusDSRHeader*) &canon->mac;
                        retn->dsrindex |= (0x01 << ARGUS_MAC_INDEX);
                        break;
                     }

                     case ARGUS_VLAN_DSR: {
                        struct ArgusVlanStruct *vlan = (struct ArgusVlanStruct *) dsr;
                 
                        bcopy((char *)vlan, (char *)&canon->vlan, cnt);
                        retn->dsrs[ARGUS_VLAN_INDEX] = (struct ArgusDSRHeader*) &canon->vlan;
                        retn->dsrindex |= (0x01 << ARGUS_VLAN_INDEX);
                        break;
                     }

                     case ARGUS_VXLAN_DSR: {
                        struct ArgusVxLanStruct *vxlan = (struct ArgusVxLanStruct *) dsr;

                        bcopy((char *)vxlan, (char *)&canon->vxlan, cnt);
                        retn->dsrs[ARGUS_VXLAN_INDEX] = (struct ArgusDSRHeader*) &canon->vxlan;
                        retn->dsrindex |= (0x01 << ARGUS_VXLAN_INDEX);
                        break;
                     }

                     case ARGUS_GENEVE_DSR: {
                        struct ArgusGeneveStruct *gen = (struct ArgusGeneveStruct *) dsr;

                        bcopy((char *)gen, (char *)&canon->gen, cnt);
                        retn->dsrs[ARGUS_GENEVE_INDEX] = (struct ArgusDSRHeader*) &canon->gen;
                        retn->dsrindex |= (0x01 << ARGUS_GENEVE_INDEX);
                        break;
                     }

                     case ARGUS_GRE_DSR: {
                        struct ArgusGreStruct *gre = (struct ArgusGreStruct *) dsr;

                        bcopy((char *)gre, (char *)&canon->gre, cnt);
                        retn->dsrs[ARGUS_GRE_INDEX] = (struct ArgusDSRHeader*) &canon->gre;
                        retn->dsrindex |= (0x01 << ARGUS_GRE_INDEX);
                        break;
                     }

                     case ARGUS_MPLS_DSR: {
                        struct ArgusMplsStruct *mpls = (struct ArgusMplsStruct *) dsr;
                        unsigned int *mlabel = (unsigned int *)(dsr + 1);

//                      bzero((char *)&canon->mpls, sizeof(*mpls));
                        bcopy((char *)&mpls->hdr, (char *)&canon->mpls.hdr, 4);
                        canon->mpls.slabel = *mlabel++;
                        canon->mpls.dlabel = *mlabel++;
                        retn->dsrs[ARGUS_MPLS_INDEX] = (struct ArgusDSRHeader*) &canon->mpls;
                        retn->dsrindex |= (0x01 << ARGUS_MPLS_INDEX);
                        break;
                     }

                     case ARGUS_ICMP_DSR: {
                        struct ArgusIcmpStruct *icmp = (struct ArgusIcmpStruct *) dsr;
                        int icmpLen = sizeof(*icmp);
                
                        bcopy((char *)icmp, (char *)&canon->icmp, (cnt > icmpLen) ? icmpLen : cnt);
                        retn->dsrs[ARGUS_ICMP_INDEX] = (struct ArgusDSRHeader*) &canon->icmp;
                        retn->dsrindex |= (0x01 << ARGUS_ICMP_INDEX);
                        break;
                     }

                     case ARGUS_COR_DSR: {
                        struct ArgusCorrelateStruct *cor = (struct ArgusCorrelateStruct *) dsr;
                        int corLen = sizeof(*cor);

                        bcopy((char *)cor, (char *)&canon->cor, (cnt > corLen) ? corLen : cnt);
                        retn->dsrs[ARGUS_COR_INDEX] = (struct ArgusDSRHeader*) &canon->cor;
                        retn->dsrindex |= (0x01 << ARGUS_COR_INDEX);
                        break;
                     }

                     case ARGUS_AGR_DSR: {
#if defined(HAVE_XDR)
                        struct ArgusAgrStruct *agr = (struct ArgusAgrStruct *) dsr;

                        if (cnt != sizeof(*agr)) {
/* 
   This is legacy ArgusOutputAgrStruct kind of input (V3 ?).
                           struct ArgusOutputAgrStruct *oagr = (struct ArgusOutputAgrStruct *) dsr;
                           struct ArgusStatsObject *tstat = (struct ArgusStatsObject *) &agr->act;
                           int agrlen = sizeof(*oagr);
*/

                        } else {
                           bcopy(agr, &canon->agr, sizeof(*agr));
                          
/* 
                           struct ArgusStatObject *stat, *tstat;
                           XDR xdrbuf, *xdrs = &xdrbuf;

   We haven't been using XDR for this struct, but when we do ... next version ...

                           canon->agr.hdr = agr->hdr;
                           canon->agr.count = agr->count;
                           canon->agr.laststartime = agr->laststartime;
                           canon->agr.lasttime = agr->lasttime;

                           stat  = &canon->agr.act;
                           tstat = &agr->act;
                           xdrmem_create(xdrs, (char *)tstat, sizeof(*stat), XDR_DECODE);
                           xdr_int(xdrs,   &stat->n);
                           xdr_float(xdrs, &stat->minval);
                           xdr_float(xdrs, &stat->meanval);
                           xdr_float(xdrs, &stat->stdev);
                           xdr_float(xdrs, &stat->maxval);
                           
                           bcopy(tstat->fdist, stat->fdist, sizeof (stat->fdist));

                           stat = &canon->agr.idle;
                           tstat = &agr->idle;
                           xdrmem_create(xdrs, (char *)tstat, sizeof(*stat), XDR_DECODE);
                           xdr_int(xdrs,   &stat->n);
                           xdr_float(xdrs, &stat->minval);
                           xdr_float(xdrs, &stat->meanval);
                           xdr_float(xdrs, &stat->stdev);
                           xdr_float(xdrs, &stat->maxval);

                           bcopy(tstat->fdist, stat->fdist, sizeof (stat->fdist));
*/
                           retn->dsrs[ARGUS_AGR_INDEX] = (struct ArgusDSRHeader*) &canon->agr;
                           retn->dsrindex |= (0x01 << ARGUS_AGR_INDEX);
                        }
#endif
                        break;
                     }

                     case ARGUS_JITTER_DSR: {
#if defined(HAVE_XDR)
                        struct ArgusJitterStruct *jitter = &canon->jitter;
                        struct ArgusStatsObject *tjit = (struct ArgusStatsObject *) (dsr + 1);
                        struct ArgusStatObject *stat;
                        XDR xdrbuf, *xdrs = &xdrbuf;
                        unsigned int fdist, i;

                        jitter->hdr = *dsr;

                        if (dsr->argus_dsrvl8.qual & ARGUS_SRC_ACTIVE_JITTER) {
                           stat = &jitter->src.act;
                           xdrmem_create(xdrs, (char *)tjit, sizeof(*stat), XDR_DECODE);
                           xdr_int(xdrs, &stat->n);
                           xdr_float(xdrs, &stat->minval);
                           xdr_float(xdrs, &stat->meanval);
                           xdr_float(xdrs, &stat->stdev);
                           xdr_float(xdrs, &stat->maxval);

                           switch (jitter->hdr.subtype & (ARGUS_HISTO_EXP | ARGUS_HISTO_LINEAR)) {
                              case ARGUS_HISTO_EXP: {
                                 unsigned char *ptr = (unsigned char *)&fdist;

                                 xdr_u_int(xdrs, &fdist);
                                 for (i = 0; i < 4; i++) {
                                    unsigned char value = *ptr++;
                                    stat->fdist[(i*2)]   = (value & 0xF0) >> 4;
                                    stat->fdist[(i*2)+1] = (value & 0x0F);
                                 }
                                 tjit = (struct ArgusStatsObject *)((char *)tjit + 6*4);
                                 break;
                              }
                              case ARGUS_HISTO_LINEAR: {
                                 break;
                              }

                              default:
                                 tjit++;
                                 break;
                           }
                        } else
                           bzero((char *)&jitter->src.act, sizeof(jitter->src.act));

                        if (dsr->argus_dsrvl8.qual & ARGUS_SRC_IDLE_JITTER) {
                           stat = &jitter->src.idle;
                           xdrmem_create(xdrs, (char *)tjit, sizeof(*stat), XDR_DECODE);
                           xdr_int(xdrs, &stat->n);
                           xdr_float(xdrs, &stat->minval);
                           xdr_float(xdrs, &stat->meanval);
                           xdr_float(xdrs, &stat->stdev);
                           xdr_float(xdrs, &stat->maxval);

                           switch (jitter->hdr.subtype & (ARGUS_HISTO_EXP | ARGUS_HISTO_LINEAR)) {
                              case ARGUS_HISTO_EXP: {
                                 unsigned char *ptr = (unsigned char *)&fdist;
                                 xdr_u_int(xdrs, &fdist);
                                 for (i = 0; i < 4; i++) {
                                    unsigned char value = *ptr++;
                                    stat->fdist[(i*2)]   = (value & 0xF0) >> 4;
                                    stat->fdist[(i*2)+1] = (value & 0x0F);
                                 }
                                 tjit = (struct ArgusStatsObject *)((char *)tjit + 6*4);
                                 break;
                              }
                              case ARGUS_HISTO_LINEAR: {
                                 break;
                              }

                              default:
                                 tjit++;
                                 break;
                           }
                        } else
                           bzero((char *)&jitter->src.idle, sizeof(jitter->src.idle));

                        if (dsr->argus_dsrvl8.qual & ARGUS_DST_ACTIVE_JITTER) {
                           stat = &jitter->dst.act;
                           xdrmem_create(xdrs, (char *)tjit, sizeof(*stat), XDR_DECODE);
                           xdr_int(xdrs, &stat->n);
                           xdr_float(xdrs, &stat->minval);
                           xdr_float(xdrs, &stat->meanval);
                           xdr_float(xdrs, &stat->stdev);
                           xdr_float(xdrs, &stat->maxval);

                           switch (jitter->hdr.subtype & (ARGUS_HISTO_EXP | ARGUS_HISTO_LINEAR)) {
                              case ARGUS_HISTO_EXP: {
                                 unsigned char *ptr = (unsigned char *)&fdist;
                                 xdr_u_int(xdrs, &fdist);
                                 for (i = 0; i < 4; i++) {
                                    unsigned char value = *ptr++;
                                    stat->fdist[(i*2)]   = (value & 0xF0) >> 4;
                                    stat->fdist[(i*2)+1] = (value & 0x0F);
                                 }
                                 tjit = (struct ArgusStatsObject *)((char *)tjit + 6*4);
                                 break;
                              }
                              case ARGUS_HISTO_LINEAR: {
                                 break;
                              }

                              default:
                                 tjit++;
                                 break;
                           }
                        } else
                           bzero((char *)&jitter->dst.act, sizeof(jitter->dst.act));

                        if (dsr->argus_dsrvl8.qual & ARGUS_DST_IDLE_JITTER) {
                           stat = &jitter->dst.idle;
                           xdrmem_create(xdrs, (char *)tjit, sizeof(*stat), XDR_DECODE);
                           xdr_int(xdrs, &stat->n);
                           xdr_float(xdrs, &stat->minval);
                           xdr_float(xdrs, &stat->meanval);
                           xdr_float(xdrs, &stat->stdev);
                           xdr_float(xdrs, &stat->maxval);

                           switch (jitter->hdr.subtype & (ARGUS_HISTO_EXP | ARGUS_HISTO_LINEAR)) {
                              case ARGUS_HISTO_EXP: {
                                 unsigned char *ptr = (unsigned char *)&fdist;
                                 xdr_u_int(xdrs, &fdist);
                                 for (i = 0; i < 4; i++) {
                                    unsigned char value = *ptr++;
                                    stat->fdist[(i*2)]   = (value & 0xF0) >> 4;
                                    stat->fdist[(i*2)+1] = (value & 0x0F);
                                 }
                                 tjit = (struct ArgusStatsObject *)((char *)tjit + 6*4);
                                 break;
                              }
                              case ARGUS_HISTO_LINEAR: {
                                 break;
                              }

                              default:
                                 tjit++;
                                 break;
                           }
                        } else
                           bzero((char *)&jitter->dst.idle, sizeof(jitter->dst.idle));

                        canon->jitter.hdr.argus_dsrvl8.len = (sizeof(struct ArgusJitterStruct) + 3)/4;
                        retn->dsrs[ARGUS_JITTER_INDEX] = (struct ArgusDSRHeader*) &canon->jitter;
                        retn->dsrindex |= (0x01 << ARGUS_JITTER_INDEX);
#endif
                        break;
                     }

                     case ARGUS_IPATTR_DSR: {
                        struct ArgusIPAttrStruct *attr = (struct ArgusIPAttrStruct *) dsr;
                        unsigned int *ptr = (unsigned int *)(dsr + 1);

                        bzero((char *)&canon->attr, sizeof(*attr));
                        bcopy((char *)&attr->hdr, (char *)&canon->attr.hdr, 4);

                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC)
                           *(unsigned int *)&canon->attr.src = *ptr++;

                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC_OPTIONS)
                           canon->attr.src.options = *ptr++;

                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST)
                           *(unsigned int *)&canon->attr.dst = *ptr++;

                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST_OPTIONS)
                           canon->attr.dst.options = *ptr++;

                        canon->attr.hdr.argus_dsrvl8.len = (sizeof(struct ArgusIPAttrStruct) + 3)/4;
                        retn->dsrs[ARGUS_IPATTR_INDEX] = (struct ArgusDSRHeader*) &canon->attr;
                        retn->dsrindex |= (0x01 << ARGUS_IPATTR_INDEX);
                        break;
                     }

                     case ARGUS_ASN_DSR: {
                        struct ArgusAsnStruct *asn = (struct ArgusAsnStruct *) dsr;
                        bcopy((char *)asn, (char *)&canon->asn, cnt);
                        canon->asn.hdr.argus_dsrvl8.len = (sizeof(struct ArgusAsnStruct) + 3)/4;
                        retn->dsrs[ARGUS_ASN_INDEX] = (struct ArgusDSRHeader*) &canon->asn;
                        retn->dsrindex |= (0x01 << ARGUS_ASN_INDEX);
                        break;
                     }

                     case ARGUS_BEHAVIOR_DSR: {
                        struct ArgusBehaviorStruct *actor = (struct ArgusBehaviorStruct *) dsr;
                        bcopy((char *)actor, (char *)&canon->actor, sizeof(*actor));
                        retn->dsrs[ARGUS_BEHAVIOR_INDEX] = (struct ArgusDSRHeader*) &canon->actor;
                        retn->dsrindex |= (0x01 << ARGUS_BEHAVIOR_INDEX);
                        break;
                     }

                     case ARGUS_SCORE_DSR: {
                        struct ArgusScoreStruct *score = (struct ArgusScoreStruct *) dsr;
                        bcopy((char *)score, (char *)&canon->score, sizeof(*score));
                        retn->dsrs[ARGUS_SCORE_INDEX] = (struct ArgusDSRHeader*) &canon->score;
                        retn->dsrindex |= (0x01 << ARGUS_SCORE_INDEX);
                        break;
                     }

                     case ARGUS_COCODE_DSR: {
                        struct ArgusCountryCodeStruct *cocode = (struct ArgusCountryCodeStruct *) dsr;
                        bcopy((char *)cocode, (char *)&canon->cocode, sizeof(*cocode));
                        retn->dsrs[ARGUS_COCODE_INDEX] = (struct ArgusDSRHeader*) &canon->cocode;
                        retn->dsrindex |= (0x01 << ARGUS_COCODE_INDEX);
                        break;
                     }

                     case ARGUS_LABEL_DSR: {
                        struct ArgusLabelStruct *tlabel = (struct ArgusLabelStruct *) dsr;
                        int llen = ((tlabel->hdr.argus_dsrvl8.len - 1) * 4);
                        if (tlabel->hdr.argus_dsrvl8.len <= 0) {
                           retn = NULL;
                           break;
                        }
//                      bzero((char *)&canon->label, sizeof(*tlabel));
                        bzero((char *)label, llen + 1);
                        bcopy((char *)&tlabel->hdr, (char *)&canon->label.hdr, 4);
                        bcopy((char *)&tlabel->l_un.label, label, llen);
                        canon->label.l_un.label = ArgusCanonLabelBuffer;
                        bcopy(label, (char *)ArgusCanonLabelBuffer, llen);
                        ArgusCanonLabelBuffer[llen] = '\0';
                        retn->dsrs[ARGUS_LABEL_INDEX] = (struct ArgusDSRHeader*) &canon->label;
                        retn->dsrindex |= (0x01 << ARGUS_LABEL_INDEX);
                        break;
                     }

                     case ARGUS_DATA_DSR: {
                        struct ArgusDataStruct *user = (struct ArgusDataStruct *) dsr;

                        if (subtype & ARGUS_LEN_16BITS) {
                           int usersz = sizeof(input->ArgusSrcUserData);
                           int datasz = sizeof(input->ArgusSrcUserData) - 8;

                           if (user->hdr.argus_dsrvl16.len == 0)
                              ArgusLog (LOG_ERR, "ArgusGenerateRecordStruct: pre ARGUS_DATA_DSR len is zero");

                           if (subtype & ARGUS_SRC_DATA) {
//                            bzero(input->ArgusSrcUserData, sizeof(input->ArgusSrcUserData));
                              retn->dsrs[ARGUS_SRCUSERDATA_INDEX] = (struct ArgusDSRHeader *)input->ArgusSrcUserData;

                              if (user->size > datasz)   user->size = datasz; 
                              if (user->count > datasz) user->count = datasz; 

                              bcopy (user, retn->dsrs[ARGUS_SRCUSERDATA_INDEX], (cnt > usersz) ? usersz : cnt);

                              if ((usersz - cnt) > 0)
                                 bzero (&input->ArgusSrcUserData[cnt], ((usersz - cnt) > 32) ? 32 : (usersz - cnt));

                              retn->dsrindex |= (0x01 << ARGUS_SRCUSERDATA_INDEX);
                           } else {
//                            bzero(input->ArgusDstUserData, sizeof(input->ArgusDstUserData));
                              retn->dsrs[ARGUS_DSTUSERDATA_INDEX] = (struct ArgusDSRHeader *)input->ArgusDstUserData;
                              if (user->size > datasz)   user->size = datasz; 
                              if (user->count > datasz) user->count = datasz; 

                              bcopy (user, retn->dsrs[ARGUS_DSTUSERDATA_INDEX], (cnt > usersz) ? usersz : cnt);

                              if ((usersz - cnt) > 0)
                                 bzero (&input->ArgusDstUserData[cnt], ((usersz - cnt) > 32) ? 32 : (usersz - cnt));

                              retn->dsrindex |= (0x01 << ARGUS_DSTUSERDATA_INDEX);
                           }

                        } else {
                           if (user->hdr.argus_dsrvl8.len == 0)
                              ArgusLog (LOG_ERR, "ArgusGenerateRecordStruct: pre ARGUS_DATA_DSR len is zero");

                           if (user->hdr.argus_dsrvl8.qual & ARGUS_SRC_DATA) {
//                            bzero(input->ArgusSrcUserData, sizeof(input->ArgusSrcUserData));
                              retn->dsrs[ARGUS_SRCUSERDATA_INDEX] = (struct ArgusDSRHeader *)input->ArgusSrcUserData;
                              retn->dsrindex |= (0x01 << ARGUS_SRCUSERDATA_INDEX);
                              user->hdr.subtype  = ARGUS_LEN_16BITS;
                              user->hdr.subtype |= ARGUS_SRC_DATA;
                              user->hdr.argus_dsrvl16.len = cnt / 4;
                              bcopy (user, retn->dsrs[ARGUS_SRCUSERDATA_INDEX], cnt);
                              bzero (&input->ArgusSrcUserData[cnt], 32);
                           } else {
//                            bzero(input->ArgusDstUserData, sizeof(input->ArgusDstUserData));
                              retn->dsrs[ARGUS_DSTUSERDATA_INDEX] = (struct ArgusDSRHeader *)input->ArgusDstUserData;
                              retn->dsrindex |= (0x01 << ARGUS_DSTUSERDATA_INDEX);
                              user->hdr.subtype  = ARGUS_LEN_16BITS;
                              user->hdr.subtype |= ARGUS_DST_DATA;
                              user->hdr.argus_dsrvl16.len = cnt / 4;
                              bcopy (user, retn->dsrs[ARGUS_DSTUSERDATA_INDEX], cnt);
                              bzero (&input->ArgusDstUserData[cnt], 32);
                           }
                        }

                        if (subtype & ARGUS_LEN_16BITS) {
                           if (user->hdr.argus_dsrvl16.len == 0)
                              ArgusLog (LOG_INFO, "ArgusGenerateRecordStruct: post ARGUS_DATA_DSR len is zero");

                        } else {
                           if (user->hdr.argus_dsrvl8.len == 0)
                              ArgusLog (LOG_INFO, "ArgusGenerateRecordStruct: post ARGUS_DATA_DSR len is zero");
                        }
                        break;
                     }

                     case ARGUS_GEO_DSR: {
#if defined(HAVE_XDR)
                        struct ArgusGeoLocationStruct *geo = &canon->geo;
                        struct ArgusCoordinates *tcoord = (struct ArgusCoordinates *) (dsr + 1);
                        struct ArgusCoordinates *coord;
                        XDR xdrbuf, *xdrs = &xdrbuf;

                        geo->hdr = *dsr;

                        if (dsr->argus_dsrvl8.qual & ARGUS_SRC_GEO) {
                           coord = &geo->src;
                           xdrmem_create(xdrs, (char *)tcoord, sizeof(*coord), XDR_DECODE);
                           xdr_float(xdrs, &coord->lat);
                           xdr_float(xdrs, &coord->lon);
                           tcoord++;
                        } else
                           bzero((char *)&geo->src, sizeof(geo->src));

                        if (dsr->argus_dsrvl8.qual & ARGUS_DST_GEO) {
                           coord = &geo->dst;
                           xdrmem_create(xdrs, (char *)tcoord, sizeof(*coord), XDR_DECODE);
                           xdr_float(xdrs, &coord->lat);
                           xdr_float(xdrs, &coord->lon);
                           tcoord++;
                        } else
                           bzero((char *)&geo->dst, sizeof(geo->dst));

                        if (dsr->argus_dsrvl8.qual & ARGUS_INODE_GEO) {
                           coord = &geo->inode;
                           xdrmem_create(xdrs, (char *)tcoord, sizeof(*coord), XDR_DECODE);
                           xdr_float(xdrs, &coord->lat);
                           xdr_float(xdrs, &coord->lon);
                           tcoord++;
                        } else
                           bzero((char *)&geo->inode, sizeof(geo->inode));

                        canon->geo.hdr.argus_dsrvl8.len = (sizeof(struct ArgusGeoLocationStruct) + 3)/4;
                        retn->dsrs[ARGUS_GEO_INDEX] = (struct ArgusDSRHeader*) &canon->geo;
                        retn->dsrindex |= (0x01 << ARGUS_GEO_INDEX);
#endif
                        break;
                     }

                     case ARGUS_LOCAL_DSR: {
                        struct ArgusNetspatialStruct *local = (struct ArgusNetspatialStruct *) dsr;
                        bcopy((char *)local, (char *)&canon->local, cnt);
                        canon->local.hdr.argus_dsrvl8.len = (sizeof(struct ArgusNetspatialStruct) + 3)/4;
                        retn->dsrs[ARGUS_LOCAL_INDEX] = (struct ArgusDSRHeader*) &canon->local;
                        retn->dsrindex |= (0x01 << ARGUS_LOCAL_INDEX);
                        break;
                     }

                     default:
                        break;
                  }

                  dsr = (struct ArgusDSRHeader *)((char *)dsr + cnt); 

               } else {
                  if (retn->dsrs[ARGUS_TIME_INDEX] == NULL) {
                     retn = NULL;
#ifdef ARGUSDEBUG
                     ArgusDebug (6, "ArgusGenerateRecordStruct (%p, %p, %p) retn %p\n", parser, input, argus, retn);
#endif 
                  }
                  break;
               }
            }

            if (retn != NULL && parser->ArgusStripFields) {
               int x;
               for (x = 0; x < ARGUSMAXDSRTYPE; x++) {
                  if (!(parser->ArgusDSRFields[x])) {
                     retn->dsrs[x] = NULL;
                     retn->dsrindex &= ~(0x01 << x);
                     retn->status |= ARGUS_RECORD_MODIFIED;
                  } else {
                     switch (x) {
                        case ARGUS_JITTER_INDEX: {
                           if (parser->ArgusDSRFields[x] > 1) {
                              struct ArgusJitterStruct *jitter = &canon->jitter;

                              jitter->hdr.type             = ARGUS_JITTER_DSR;
                              jitter->hdr.subtype          = 0;
                              jitter->hdr.argus_dsrvl8.qual  = (ARGUS_SRC_ACTIVE_JITTER | ARGUS_DST_ACTIVE_JITTER |
                                                                ARGUS_SRC_IDLE_JITTER   | ARGUS_DST_IDLE_JITTER );
                              jitter->hdr.argus_dsrvl8.len   = sizeof(*jitter) >> 2;

                              retn->dsrs[ARGUS_JITTER_INDEX] = (struct ArgusDSRHeader*) &canon->jitter;
                              retn->dsrindex |= (0x01 << ARGUS_JITTER_INDEX);
                           }
                           break;
                        }
                     }
                  }
               }
            }

            if (retn != NULL) {
               struct ArgusFlow *flow = (struct ArgusFlow *) retn->dsrs[ARGUS_FLOW_INDEX];
               struct ArgusMacStruct *mac = (struct ArgusMacStruct *) retn->dsrs[ARGUS_MAC_INDEX];

               if (!(retn->dsrindex & (0x01 << ARGUS_METRIC_INDEX))) {
                  canon->metric.src.pkts     = 0;
                  canon->metric.src.bytes    = 0;
                  canon->metric.src.appbytes = 0;
                  canon->metric.dst.pkts     = 0;
                  canon->metric.dst.bytes    = 0;
                  canon->metric.dst.appbytes = 0;
               }

// correct for time problems.
// adjust subtype when time values are zero.
// or adjust time where there is not packet activity.
// adjust start and stop times if they are negative.

               {
                  float stime = 0, ltime = 0;
                  struct ArgusTimeObject *dtime = (struct ArgusTimeObject *)retn->dsrs[ARGUS_TIME_INDEX];

                  if (dtime != NULL) {
                     if ((canon->metric.src.pkts > 0) && (canon->metric.dst.pkts > 0)) {

// ok both sides have activity, so the start and end timestamps or src and dst should have a value
// the assumption here is that a seconds time of 0 is incorrect.

                        if ((canon->metric.src.pkts == 1) && (canon->metric.dst.pkts == 1)) {
                           if ((dtime->src.start.tv_sec == 0) && (dtime->dst.start.tv_sec != 0)) {
                              dtime->src.start = dtime->dst.end;
                              dtime->src.end   = dtime->dst.end;
                              dtime->dst.end   = dtime->dst.start;
                           } else 
                           if ((dtime->src.start.tv_sec != 0) && (dtime->dst.start.tv_sec == 0)) {
                              dtime->dst.start = dtime->src.end;
                              dtime->dst.end   = dtime->src.end;
                              dtime->src.end   = dtime->src.start;
                           }

                        } else {
                           if ((dtime->src.start.tv_sec == 0) && (dtime->dst.start.tv_sec != 0)) {
                              dtime->src = dtime->dst;
                           } else
                           if ((dtime->src.start.tv_sec != 0) && (dtime->dst.start.tv_sec == 0)) {
                                 dtime->dst = dtime->src;
                           }
    
                           if (canon->metric.src.pkts == 1) {
                              if ((dtime->src.start.tv_sec != dtime->src.end.tv_sec) ||
                                  (dtime->src.start.tv_sec != dtime->src.end.tv_sec)) {
                                 if ((dtime->src.end.tv_sec == 0) && (dtime->src.start.tv_sec != 0))
                                    dtime->src.end = dtime->src.start;
                                 else 
                                 if ((dtime->src.start.tv_sec == 0) && (dtime->src.end.tv_sec != 0))
                                    dtime->src.start = dtime->src.end;
                                 else 
                                    dtime->src.end = dtime->src.start;
                              }
                           }

                           if (canon->metric.dst.pkts == 1) {
                              if ((dtime->dst.start.tv_sec != dtime->dst.end.tv_sec) ||
                                  (dtime->dst.start.tv_sec != dtime->dst.end.tv_sec)) {
                                 if ((dtime->dst.end.tv_sec == 0) && (dtime->dst.start.tv_sec != 0))
                                    dtime->dst.end = dtime->dst.start;
                                 else 
                                 if ((dtime->dst.start.tv_sec == 0) && (dtime->dst.end.tv_sec != 0))
                                    dtime->dst.start = dtime->dst.end;
                                 else
                                    dtime->dst.end = dtime->dst.start;
                              }
                           }
                        }
                        dtime->hdr.subtype |= ARGUS_TIME_MASK;

                     } else {
                        if (canon->metric.src.pkts > 0) {
                           if (dtime->src.start.tv_sec == 0) {
                              if (dtime->dst.start.tv_sec != 0) {
                                 dtime->src = dtime->dst;
                              }
                           }
                           bzero ((char *)&dtime->dst, sizeof(dtime->dst));
                        } else
                        if (canon->metric.dst.pkts > 0) {
                           if (dtime->dst.start.tv_sec == 0) {
                              if (dtime->src.start.tv_sec != 0) {
                                 dtime->dst = dtime->src;
                              }
                           }
                           bzero ((char *)&dtime->src, sizeof(dtime->src));
                        }
                     }

                     if ((dtime->src.start.tv_sec != 0) && (dtime->src.end.tv_sec == 0))
                        dtime->src.end = dtime->src.start;
                     if ((dtime->dst.start.tv_sec != 0) && (dtime->dst.end.tv_sec == 0))
                        dtime->dst.end = dtime->dst.start;

                     dtime->hdr.subtype &= ~(ARGUS_TIME_MASK);
                     if (dtime->src.start.tv_sec)
                        dtime->hdr.subtype |= ARGUS_TIME_SRC_START;
                     if (dtime->src.end.tv_sec)
                        dtime->hdr.subtype |= ARGUS_TIME_SRC_END;
                     if (dtime->dst.start.tv_sec)
                        dtime->hdr.subtype |= ARGUS_TIME_DST_START;
                     if (dtime->dst.end.tv_sec)
                        dtime->hdr.subtype |= ARGUS_TIME_DST_END;

                     stime = RaGetFloatSrcDuration(retn);
                     ltime = RaGetFloatDstDuration(retn);

                     if (!(stime >= 0) || (!(ltime >= 0))) {
                        struct timeval tvbuf, *tvp = &tvbuf;
                        if (stime < 0) {
                           tvp->tv_sec  = dtime->src.start.tv_sec;
                           tvp->tv_usec = dtime->src.start.tv_usec;
                           dtime->src.start = dtime->src.end;
                           dtime->src.end.tv_sec  = tvp->tv_sec;
                           dtime->src.end.tv_usec = tvp->tv_usec;
                           stime = RaGetFloatSrcDuration(retn);
                        }
                        if (ltime < 0) {
                           tvp->tv_sec  = dtime->dst.start.tv_sec;
                           tvp->tv_usec = dtime->dst.start.tv_usec;
                           dtime->dst.start = dtime->src.end;
                           dtime->dst.end.tv_sec  = tvp->tv_sec;
                           dtime->dst.end.tv_usec = tvp->tv_usec;
                           ltime = RaGetFloatSrcDuration(retn);
                        }
                     }

                     if ((stime > 0) && (canon->metric.src.pkts == 0)) {
                        if ((ltime == 0) && (canon->metric.dst.pkts > 0)) {
                           dtime->dst = dtime->src;
//                         bzero(&dtime->src, sizeof(dtime->src));
                           dtime->hdr.subtype &= ~(ARGUS_TIME_SRC_START | ARGUS_TIME_SRC_END);
                        }
                     }
                     if ((ltime > 0) && (canon->metric.dst.pkts == 0)) {
                        if ((stime == 0) && (canon->metric.src.pkts > 0)) {
                           dtime->src = dtime->dst;
//                         bzero(&dtime->dst, sizeof(dtime->dst));
                           dtime->hdr.subtype &= ~(ARGUS_TIME_DST_START | ARGUS_TIME_DST_END);
                        }
                     }
                     if ((canon->metric.src.pkts + canon->metric.dst.pkts) == 1) {
                        if ((canon->metric.src.pkts == 1) && ((stime = RaGetFloatSrcDuration(retn)) != 0)) {
                           if (retn->dsrs[ARGUS_ICMP_INDEX] == NULL)
                              dtime->src.start  = dtime->src.end;
                        } else
                        if ((canon->metric.dst.pkts == 1) && ((ltime = RaGetFloatDstDuration(retn)) != 0)) {
                           dtime->dst.start  = dtime->dst.end;
                        }
                     }
                  }
               }

               retn->dur = RaGetFloatDuration(retn);

               if (!((seconds = RaGetFloatSrcDuration(retn)) > 0))
                  seconds = retn->dur;

               if (seconds > 0) {
                  long long pkts = canon->metric.src.pkts;
                  long long bytes = (canon->metric.src.bytes + (pkts * parser->ArgusEtherFrameCnt));
                  if (pkts > 1) {
                     long long bppkts = bytes / pkts;
                     retn->srate = (float)((pkts - 1) * 1.0) / seconds;
                     retn->sload = (float)((bytes - bppkts) * 8.0) / seconds;
                  }
               }

               if (!((seconds = RaGetFloatDstDuration(retn)) > 0)) 
                  seconds = retn->dur;

               if (seconds > 0) {
                  long long pkts = canon->metric.dst.pkts; 
                  long long bytes = (canon->metric.dst.bytes + (pkts * parser->ArgusEtherFrameCnt));
                  if (pkts > 1) {
                     long long bppkts = bytes / pkts;
                     retn->drate = (float)((pkts - 1) * 1.0) / seconds;
                     retn->dload = (float)((bytes - bppkts) * 8.0) / seconds;
                  }
               }

               retn->offset   = input->offset;

               if (mac != NULL) {
                  unsigned short retn = mac->mac.mac_union.ether.ehdr.ether_type;
                  if (retn == ETHERTYPE_8021Q) {
                     if (flow) {
                        switch (flow->hdr.subtype & 0x3F) {
                           case ARGUS_FLOW_LAYER_3_MATRIX:
                           case ARGUS_FLOW_CLASSIC5TUPLE: {
                              switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                 case ARGUS_TYPE_IPV4: {
                                    mac->mac.mac_union.ether.ehdr.ether_type = ETHERTYPE_IP;
                                    break;
                                 }
                                 case ARGUS_TYPE_IPV6: {
                                    mac->mac.mac_union.ether.ehdr.ether_type = ETHERTYPE_IPV6;
                                    break;
                                 }
                                 case ARGUS_TYPE_ARP: {
                                    mac->mac.mac_union.ether.ehdr.ether_type = ETHERTYPE_ARP;
                                    break;
                                 }
                              }
                              break;
                           }
                           case ARGUS_FLOW_ARP: {
                              mac->mac.mac_union.ether.ehdr.ether_type = ETHERTYPE_ARP;
                              break;
                           }
                        }
                     }
                  }
               }

               if (flow != NULL) {
                  switch (canon->flow.hdr.subtype & 0x3F) {
                     case ARGUS_FLOW_LAYER_3_MATRIX:
                     case ARGUS_FLOW_CLASSIC5TUPLE: {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: {
                              if (parser->ArgusPerformCorrection) {
                              switch (canon->flow.ip_flow.ip_p) {
                                 case IPPROTO_TCP: {
                                    struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *) &canon->net.net_union.tcpstatus;
                                    char TcpShouldReverse = 0;

//                                  if (!(status & ARGUS_DIRECTION)) {
                                    if ((tcp->status & ARGUS_SAW_SYN) || (tcp->status & ARGUS_SAW_SYN_SENT)) {
                                       if (!(tcp->status & ARGUS_SAW_SYN) && (tcp->status & ARGUS_SAW_SYN_SENT)) {
                                          switch (canon->net.hdr.subtype) {
                                             case ARGUS_TCP_INIT: {
                                                struct ArgusTCPInitStatus *tcp = (struct ArgusTCPInitStatus *) &canon->net.net_union.tcp;
                                                if (tcp->flags & TH_SYN)
                                                   TcpShouldReverse = 1;
                                                break;
                                             }
                                             case ARGUS_TCP_STATUS: {
                                                struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *) &canon->net.net_union.tcp;

                                                if ((tcp->status & ARGUS_SAW_SYN_SENT) && ((tcp->status & ARGUS_CON_ESTABLISHED) || (tcp->status & ARGUS_NORMAL_CLOSE) || (tcp->status & ARGUS_FIN) || (tcp->status & ARGUS_FIN_ACK))) 
                                                   TcpShouldReverse = 1;

                                                if ((tcp->src & TH_SYN) && !(tcp->dst & TH_RST)) {
                                                   if ((canon->metric.src.pkts > 5) && (canon->metric.dst.pkts > 5)) {
                                                      TcpShouldReverse = 1;
                                                   } else {
                                                      if (canon->metric.src.pkts && (canon->metric.dst.pkts == 0))
                                                         if ((tcp->src & TH_SYN) && (tcp->src & TH_FIN)) 
                                                            if ((canon->metric.src.bytes / canon->metric.src.pkts) > 60) 
                                                               TcpShouldReverse = 1;
                                                   }
                                                }
                                                break;
                                             }
                                             case ARGUS_TCP_PERF: {
                                                struct ArgusTCPObject *tcp = (struct ArgusTCPObject *) &canon->net.net_union.tcp;
                                                if ((tcp->status & ARGUS_SAW_SYN_SENT) && 
                                                   ((tcp->status & ARGUS_CON_ESTABLISHED) || 
                                                    (tcp->status & ARGUS_NORMAL_CLOSE) || 
                                                    (tcp->status & ARGUS_FIN) || 
                                                    (tcp->status & ARGUS_FIN_ACK)))
                                                   TcpShouldReverse = 1;

                                                if ((tcp->src.flags & TH_SYN) && !(tcp->dst.flags & TH_RST)) {
                                                   if ((canon->metric.src.pkts > 5) && (canon->metric.dst.pkts > 5)) {
                                                      TcpShouldReverse = 1;
                                                   } else {
                                                      if (canon->metric.src.pkts && (canon->metric.dst.pkts == 0))
                                                         if ((tcp->src.flags & TH_SYN) && (tcp->src.flags & TH_FIN))
                                                            if ((canon->metric.src.bytes / canon->metric.src.pkts) > 60)
                                                               TcpShouldReverse = 1;
                                                   }
                                                }
                                                break;
                                             }
                                          }

                                       } else {
                                          switch (canon->net.hdr.subtype) {
                                             case ARGUS_TCP_INIT: {
                                                break;
                                             }
                                             case ARGUS_TCP_PERF: {
                                                struct ArgusTCPObject *tcp = (struct ArgusTCPObject *) &canon->net.net_union.tcp;

                                                if ((tcp->src.status & ARGUS_SAW_SYN_SENT) || (tcp->dst.status & ARGUS_SAW_SYN)) 
                                                   TcpShouldReverse = 1;
                                                break;
                                             }
                                          }
                                       }
#define TCPPORT_FTP_DATA   20
                                    } else {
                                       if ((((flow->ip_flow.sport <= IPPORT_RESERVED) && 
                                             (flow->ip_flow.dport  > IPPORT_RESERVED)) && 
                                             (flow->ip_flow.sport != TCPPORT_FTP_DATA)) && !(parser->nflag)) {
                                          u_int sfnd = 0, i;
                                          extern struct hnamemem tporttable[];
                                          struct hnamemem *tp;

                                          if (parser->ArgusSrvInit == 0)
                                             ArgusInitServarray(parser);

                                          i  = flow->ip_flow.sport;
                                          for (tp = &tporttable[i % (HASHNAMESIZE-1)]; tp->nxt; tp = tp->nxt)
                                             if (tp->addr == i)
                                                sfnd = 1;

                                          if (sfnd)
                                             TcpShouldReverse = 1;
                                       }
                                    }
//                                  }

                                    if (TcpShouldReverse) {
                                       ArgusReverseRecord (retn);
                                       tcp->status ^= ARGUS_DIRECTION;
                                       flow->hdr.argus_dsrvl8.qual ^= ARGUS_DIRECTION;
                                    }
                                    break;
                                 }

                                 case IPPROTO_ICMP: {
                                    if (status & ARGUS_DIRECTION) {
                                       if (canon->metric.src.pkts && !canon->metric.dst.pkts) {
                                          struct ArgusICMPObject *icmp = &canon->net.net_union.icmp;
                                          canon->flow.icmp_flow.type = icmp->icmp_type;
                                          canon->flow.icmp_flow.code = icmp->icmp_code;

                                          switch (icmp->icmp_type) {
                                             case ICMP_MASKREPLY:
                                             case ICMP_ECHOREPLY:
                                             case ICMP_TSTAMPREPLY:
                                             case ICMP_IREQREPLY: {
                                                ArgusReverseRecord (retn);
                                                break;
                                             }
                                          }
                                       }
                                    }
                                    break;
                                 }
                                 case IPPROTO_UDP: {
                                    struct ArgusNetworkStruct *net;
                                    if ((net = (struct ArgusNetworkStruct *) retn->dsrs[ARGUS_NETWORK_INDEX]) != NULL) {
                                       switch (net->hdr.subtype) {
                                          case ARGUS_RTP_FLOW: {
                                             break;
                                          }
                                          case ARGUS_RTCP_FLOW: 
                                             break;
                                       }
                                    }

//                                  if (!(IN_MULTICAST(flow->ip_flow.ip_dst) || (INADDR_BROADCAST == flow->ip_flow.ip_dst))) {
//                                     if ((flow->ip_flow.sport <= IPPORT_RESERVED) || (flow->ip_flow.dport <= IPPORT_RESERVED)) {
//                                        if ((flow->ip_flow.sport <= IPPORT_RESERVED) && (flow->ip_flow.dport <= IPPORT_RESERVED)) {
//                                           if (flow->ip_flow.sport < flow->ip_flow.dport) {
//                                              ArgusReverseRecord (retn);
//                                           }
//                                        } else {
//                                           if (flow->ip_flow.sport <= IPPORT_RESERVED)
//                                              ArgusReverseRecord (retn);
//                                        }
//                                     }
//                                  }

                                    break;
                                 }
                              }
                              }
                              break;
                           }

                           case ARGUS_TYPE_IPV6: {
                              if (parser->ArgusPerformCorrection) {
                              switch (canon->flow.ipv6_flow.ip_p) {
                                 case IPPROTO_ICMP: {
                                    struct ArgusICMPv6Flow *icmpv6 = (struct ArgusICMPv6Flow *) &canon->flow;
                                    if (!(icmpv6->type) && !(icmpv6->type)) {
                                       struct ArgusICMPObject *icmp = &canon->net.net_union.icmp;
                                       icmpv6->type = icmp->icmp_type;
                                       icmpv6->code = icmp->icmp_code;
                                    }
                                    break;
                                 }
                                 case IPPROTO_UDP: {
                                    struct ArgusNetworkStruct *net;
                                    if ((net = (struct ArgusNetworkStruct *) retn->dsrs[ARGUS_NETWORK_INDEX]) != NULL) {
                                       switch (net->hdr.subtype) {
                                          case ARGUS_RTP_FLOW: {
                                             break;
                                          }

                                          case ARGUS_RTCP_FLOW: {
                                             if (flow->ipv6_flow.sport > flow->ipv6_flow.dport) {
                                                ArgusReverse = 1;
                                                status |= ARGUS_DIRECTION;
                                             }
                                             break;
                                          }
                                       }
                                    }
                                    break;
                                 }
                              }
                              }
                              break;
                           }

                           case ARGUS_TYPE_RARP:
                           case ARGUS_TYPE_ARP: {
                              if (flow->hdr.subtype & ARGUS_REVERSE) {
                                 struct ArgusFlow flowbuf;
                                 bcopy(flow, &flowbuf, sizeof(flowbuf));
                                 ArgusReverseRecord (retn);
                                 bcopy(&flowbuf, flow, sizeof(flowbuf));
                              }
                              break;
                           }
                        }
                        break;
                     }
                  
                     case ARGUS_FLOW_ARP: {
                        struct ArgusFlow *flow = (struct ArgusFlow *) retn->dsrs[ARGUS_FLOW_INDEX];

                        if (flow->hdr.subtype & ARGUS_REVERSE) {
                           struct ArgusFlow flowbuf;
                           bcopy(flow, &flowbuf, sizeof(flowbuf));
                           ArgusReverseRecord (retn);
                           bcopy(&flowbuf, flow, sizeof(flowbuf));
                        }
                        break;
                     }
                  }

                  if (flow->hdr.subtype & ARGUS_REVERSE)
                     flow->hdr.subtype &= ~ARGUS_REVERSE;
               }
            }
   
            if (retn != NULL) {
               if ((ArgusFetchPktsCount(retn) > 100000000.0) && (ArgusFetchDuration(retn) == 0.0)) {
                  retn->hdr.cause           &= 0x0F;
                  retn->hdr.cause           |= ARGUS_ERROR;
                  canon->metric.src.pkts     = 0;
                  canon->metric.src.bytes    = 0;
                  canon->metric.src.appbytes = 0;
                  canon->metric.dst.pkts     = 0;
                  canon->metric.dst.bytes    = 0;
                  canon->metric.dst.appbytes = 0;
               } else {
                  if (retn->hdr.len < 1) {
                     retn = NULL;
#ifdef ARGUSDEBUG
                     ArgusDebug (6, "ArgusGenerateRecordStruct (%p, %p, %p) retn->hdr len < 1\n", parser, input, argus);
#endif 
                  }
               }
            }

            if ((parser != NULL) && (retn != NULL)) {
               struct ArgusNetworkStruct *net = &canon->net;

               switch (net->hdr.subtype) {
                  case ARGUS_TCP_INIT:
                     break;

                  case ARGUS_TCP_STATUS:
                     break;

                  case ARGUS_TCP_PERF: 
                     break;

                  case ARGUS_RTP_FLOW: {
                     if ((canon->flow.ip_flow.ip_p != IPPROTO_UDP) ||
                         (((canon->metric.src.pkts < 5)) && ((canon->metric.dst.pkts < 5))))
                        retn->dsrs[ARGUS_NETWORK_INDEX] = NULL;
                     break;
                  }
               }

               if (ArgusReverse && (status & ARGUS_DIRECTION))
                  ArgusReverseRecord (retn);

               retn->pcr = ArgusFetchAppByteRatio(retn);
            }

            if ((parser != NULL) && (retn != NULL)) {
               if (!retn->dsrs[ARGUS_AGR_INDEX]) {
                  if ((canon->metric.src.pkts + canon->metric.dst.pkts) > 0) {
                     struct ArgusAgrStruct *agr = &canon->agr;
                     double value;

//                   bzero(agr, sizeof(*agr));
                     agr->hdr.type               = ARGUS_AGR_DSR;
                     agr->hdr.argus_dsrvl8.qual  = 0x01;
                     agr->hdr.argus_dsrvl8.len   = (sizeof(*agr) + 3)/4;
                     agr->count                  = 1;
                     agr->act.minval             = 10000000000.0;
                     agr->idle.minval            = 10000000000.0;

                     if ((parser->ArgusAggregator != NULL) && (parser->ArgusAggregator->RaMetricFetchAlgorithm != NULL)) {
                        value = parser->ArgusAggregator->RaMetricFetchAlgorithm(retn);
                        agr->hdr.subtype         = parser->ArgusAggregator->ArgusMetricIndex;
                     } else {
                        value = ArgusFetchDuration(retn);
                        agr->hdr.subtype         = ARGUSMETRICDURATION;
                     }

                     agr->act.maxval          = value;
                     agr->act.minval          = value;
                     agr->act.meanval         = value;
                     agr->act.stdev           = 0;
                     agr->act.n               = 1;
//                   bzero ((char *)&agr->idle, sizeof(agr->idle));

                     retn->dsrs[ARGUS_AGR_INDEX] = (struct ArgusDSRHeader *) agr;
                     retn->dsrindex |= (0x01 << ARGUS_AGR_INDEX);
                  }
               }

               if (retn->dsrs[ARGUS_SCORE_INDEX]) {
                  struct ArgusScoreStruct *score = (struct ArgusScoreStruct *) retn->dsrs[ARGUS_SCORE_INDEX];
                  if (score && (score->hdr.subtype == ARGUS_BEHAVIOR_SCORE)) {
                     retn->score = score->behvScore.values[0];
                  }
               }

               retn->sloss   = ArgusFetchSrcLoss(retn);
               retn->dloss   = ArgusFetchDstLoss(retn);
               retn->sploss  = ArgusFetchPercentSrcLoss(retn);
               retn->dploss  = ArgusFetchPercentDstLoss(retn);
            }
            break;
         }
         
         default:
            retn = NULL;
            break;
      }
   }

   return (retn);
}

static void
ArgusGenerateTransportStruct(const struct ArgusTransportStruct * const src,
                             int srclen, struct ArgusTransportStruct *dst,
                             int major_version)
{
   unsigned char subtype = src->hdr.subtype;
   char *iptr = (char *)&src->hdr + 4;

   if (major_version < MAJOR_VERSION_5)
      if (srclen >= 12)
         subtype = src->hdr.subtype | (ARGUS_SRCID | ARGUS_SEQ);

   bzero ((char *)dst, sizeof(struct ArgusTransportStruct));
   bcopy((char *)&src->hdr, (char *)&dst->hdr, 4);
   dst->hdr.argus_dsrvl8.len = (sizeof(struct ArgusTransportStruct) + 3) / 4;

   if (src->hdr.subtype & ARGUS_SRCID) {
      switch (src->hdr.argus_dsrvl8.qual & ~ARGUS_TYPE_INTERFACE) {
         case ARGUS_TYPE_INT: {
            dst->srcid.a_un.value = src->srcid.a_un.value;
            iptr = (char *)&src->srcid.a_un.value + 4;
            break;
         }

         default:
         case ARGUS_TYPE_IPV4: {
            dst->srcid.a_un.ipv4 = src->srcid.a_un.ipv4;
            iptr = (char *)&src->srcid.a_un.value + 4;
            break;
         }
         case ARGUS_TYPE_IPV6: {
            bcopy(src->srcid.a_un.ipv6,
                  dst->srcid.a_un.ipv6,
                  sizeof(src->srcid.a_un.ipv6));
            iptr = (char *)&src->srcid.a_un.value + 16;
            break;
         }
         case ARGUS_TYPE_ETHER: {
            iptr = (char *)&src->srcid.a_un.value + 8;
            break;
         }
         case ARGUS_TYPE_STRING: {
            bcopy(src->srcid.a_un.str, dst->srcid.a_un.str, 4);
            iptr = (char *)&src->srcid.a_un.value + 4;
            break;
         }
         case ARGUS_TYPE_UUID: {
            bcopy(src->srcid.a_un.uuid, dst->srcid.a_un.uuid, 16);
            iptr = (char *)&src->srcid.a_un.value + 16;
            break;
         }
      }
      if (src->hdr.argus_dsrvl8.qual & ARGUS_TYPE_INTERFACE) {
         bcopy (iptr, &dst->srcid.inf, 4);
         iptr += 4;
      }
   }

   if (subtype & ARGUS_SEQ)
      bcopy (iptr, &dst->seqnum, 4);
}

struct ArgusRecordStruct *
ArgusCopyRecordStruct (struct ArgusRecordStruct *rec)
{
   struct ArgusRecordStruct *retn = NULL;

   if (rec) {
      if ((retn = (struct ArgusRecordStruct *) ArgusCalloc (1, sizeof(*retn))) != NULL) {
         retn->status  = rec->status;
         retn->input   = rec->input;
         retn->autoid  = rec->autoid;

         bcopy ((char *)&rec->hdr, (char *)&retn->hdr, sizeof (rec->hdr));

         switch (rec->hdr.type & 0xF0) {
            case ARGUS_MAR: {
               struct ArgusRecord *ns = (struct ArgusRecord *) rec->dsrs[0];
               int len = ns->hdr.len * 4;

               if ((retn->dsrs[0] = ArgusCalloc(1, len)) != NULL) {
                  bcopy((char *)ns, (char *)retn->dsrs[0], len);
               } else {
                  ArgusFree(retn);
                  retn = NULL;
               }
               break;
            }

            case ARGUS_EVENT:
            case ARGUS_NETFLOW:
            case ARGUS_AFLOW:
            case ARGUS_FAR: {
               if ((retn->dsrindex = rec->dsrindex)) {
                  int i;
                  for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
                     struct ArgusDSRHeader *dsr;
                     if ((dsr = rec->dsrs[i]) != NULL) {
                        if (dsr->type) {
                           int len = (((dsr->type & ARGUS_IMMEDIATE_DATA) ? 1 :
                                      ((dsr->subtype & ARGUS_LEN_16BITS)  ? dsr->argus_dsrvl16.len :
                                                                            dsr->argus_dsrvl8.len)));
                           if (len > 0) {
                              switch (i) {
                                 case ARGUS_TRANSPORT_INDEX:
                                 case ARGUS_FLOW_HASH_INDEX:
                                 case ARGUS_TIME_INDEX:
                                 case ARGUS_METRIC_INDEX:
                                 case ARGUS_PSIZE_INDEX:
                                 case ARGUS_IPATTR_INDEX:
                                 case ARGUS_ICMP_INDEX:
                                 case ARGUS_MAC_INDEX:
                                 case ARGUS_VLAN_INDEX:
                                 case ARGUS_VXLAN_INDEX:
                                 case ARGUS_MPLS_INDEX:
                                 case ARGUS_GRE_INDEX:
                                 case ARGUS_GENEVE_INDEX:
                                 case ARGUS_ASN_INDEX:
                                 case ARGUS_AGR_INDEX:
                                 case ARGUS_BEHAVIOR_INDEX:
                                 case ARGUS_SCORE_INDEX:
                                 case ARGUS_COCODE_INDEX:
                                 case ARGUS_COR_INDEX: 
                                 case ARGUS_GEO_INDEX: 
                                 case ARGUS_JITTER_INDEX: 
                                 case ARGUS_LOCAL_INDEX: {
                                    if ((retn->dsrs[i] = ArgusCalloc(1, len * 4)) == NULL)
                                       ArgusLog (LOG_ERR, "ArgusCopyRecordStruct: ArgusCalloc error %s\n", strerror(errno));
                                    bcopy((char *)rec->dsrs[i], (char *)retn->dsrs[i], len * 4);
                                    break;
                                 }

                                 case ARGUS_FLOW_INDEX: {
                                    if ((retn->dsrs[i] = ArgusCalloc(1, sizeof(struct ArgusFlow))) == NULL)
                                       ArgusLog (LOG_ERR, "ArgusCopyRecordStruct: ArgusCalloc error %s\n", strerror(errno));
                                    bcopy((char *)rec->dsrs[i], (char *)retn->dsrs[i], len * 4);
                                    break;
                                 }

                                 case ARGUS_NETWORK_INDEX: {
                                    struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) dsr;
                                    switch (net->hdr.subtype) {
                                       case ARGUS_TCP_INIT:
                                       case ARGUS_TCP_STATUS:
                                       case ARGUS_TCP_PERF: {
                                          if ((retn->dsrs[i] = ArgusCalloc(1, sizeof(struct ArgusTCPObject) + 4)) == NULL)
                                             ArgusLog (LOG_ERR, "ArgusCopyRecordStruct: ArgusCalloc error %s\n", strerror(errno));
                                          break;
                                       }
                                       default: {
                                          if ((retn->dsrs[i] = ArgusCalloc(1, len * 4)) == NULL)
                                             ArgusLog (LOG_ERR, "ArgusCopyRecordStruct: ArgusCalloc error %s\n", strerror(errno));
                                          break;
                                       }
                                    }
                                    bcopy((char *)rec->dsrs[i], (char *)retn->dsrs[i], len * 4);
                                    break;
                                 }

                                 case ARGUS_LABEL_INDEX: {
                                    struct ArgusLabelStruct *label = (void *)rec->dsrs[i];
                                    int slen;

                                    if ((retn->dsrs[i] = ArgusCalloc(1, sizeof(struct ArgusLabelStruct))) == NULL)
                                       ArgusLog (LOG_ERR, "ArgusCopyRecordStruct: ArgusCalloc error %s\n", strerror(errno));

                                    bcopy((char *)rec->dsrs[i], (char *)retn->dsrs[i], sizeof(struct ArgusLabelStruct));

                                    if (label->l_un.label != NULL) {
                                       struct ArgusLabelStruct *tlabel = (void *)retn->dsrs[i];

                                       tlabel->l_un.label = NULL;
                                       if ((slen = strlen(label->l_un.label)) > 0) {
                                          int blen = (label->hdr.argus_dsrvl8.len - 1) * 4;

                                          tlabel->l_un.label = calloc(1, blen + 1);
                                          bcopy((char *)label->l_un.label, tlabel->l_un.label, (blen > slen) ? slen : blen);
                                       }
                                    }
                                    break;
                                 }

                                 case ARGUS_ENCAPS_INDEX: {
                                    struct ArgusEncapsStruct *enc  = (struct ArgusEncapsStruct *) rec->dsrs[i];
                                    struct ArgusEncapsStruct *renc = NULL;

                                    if ((retn->dsrs[i] = ArgusCalloc(1, sizeof(struct ArgusEncapsStruct))) == NULL)
                                       ArgusLog (LOG_ERR, "ArgusCopyRecordStruct: ArgusCalloc error %s\n", strerror(errno));

                                    renc  = (struct ArgusEncapsStruct *) retn->dsrs[i];

                                    bcopy((char *)enc, (char *)renc, sizeof(struct ArgusEncapsStruct));
                                    renc->sbuf = NULL; renc->dbuf = NULL;

                                    if ((enc->slen > 0) && (enc->sbuf != NULL)) {
                                       if ((renc->sbuf = ArgusCalloc(1, enc->slen)) == NULL)
                                          ArgusLog (LOG_ERR, "ArgusCopyRecordStruct: ArgusCalloc error %s\n", strerror(errno));
                                       bcopy((char *)enc->sbuf, (char *)renc->sbuf, enc->slen);
                                    }
                                    if ((enc->dlen > 0) && (enc->dbuf != NULL)) {
                                       if ((renc->dbuf = ArgusCalloc(1, enc->dlen)) == NULL)
                                          ArgusLog (LOG_ERR, "ArgusCopyRecordStruct: ArgusCalloc error %s\n", strerror(errno));
                                       bcopy((char *)enc->dbuf, (char *)renc->dbuf, enc->dlen);
                                    }
                                    break;
                                 }

                                 case ARGUS_SRCUSERDATA_INDEX: 
                                 case ARGUS_DSTUSERDATA_INDEX: {
                                    struct ArgusDataStruct *user = (struct ArgusDataStruct *) rec->dsrs[i];
                                    len = ((user->size + 8) + 3) / 4;
                                    if ((retn->dsrs[i] = (struct ArgusDSRHeader *) ArgusCalloc(1, len * 4)) == NULL)
                                       ArgusLog (LOG_ERR, "ArgusCopyRecordStruct: ArgusCalloc error %s\n", strerror(errno));

                                    bcopy (rec->dsrs[i], retn->dsrs[i], len * 4);
                                    break;
                                 }
                              }
                           }
                        }
                     }
                  }
               }

               retn->score   = rec->score;
               retn->dur     = rec->dur;
               retn->srate   = rec->srate;
               retn->drate   = rec->drate;
               retn->sload   = rec->sload;
               retn->dload   = rec->dload;
               retn->sloss   = ArgusFetchSrcLoss(retn);
               retn->dloss   = ArgusFetchDstLoss(retn);
               retn->sploss  = ArgusFetchPercentSrcLoss(retn);
               retn->dploss  = ArgusFetchPercentDstLoss(retn);
               retn->pcr     = ArgusFetchAppByteRatio(retn);
               retn->bins    = NULL;
               retn->htblhdr = NULL;
               retn->nsq     = NULL;
               break;
            }
         }

         if (retn->hdr.type & (ARGUS_FAR | ARGUS_NETFLOW | ARGUS_AFLOW))
            retn->rank = rec->rank;

         if (rec->correlates) {
            int i;

            if ((retn->correlates = (void *) ArgusCalloc (1, sizeof(*rec->correlates))) == NULL)
               ArgusLog (LOG_ERR, "ArgusCopyRecordStruct: ArgusCalloc error %s\n", strerror(errno));
            if ((retn->correlates->array = (void *) ArgusCalloc (rec->correlates->size, sizeof(rec))) == NULL)
               ArgusLog (LOG_ERR, "ArgusCopyRecordStruct: ArgusCalloc error %s\n", strerror(errno));

            retn->correlates->count = rec->correlates->count;
            retn->correlates->size  = rec->correlates->size;

            for (i = 0; i < rec->correlates->count; i++)
               if (rec->correlates->array[i] != NULL)
                  retn->correlates->array[i] = ArgusCopyRecordStruct(rec->correlates->array[i]);
         }

         retn->timeout = rec->timeout;

      } else
         ArgusLog (LOG_ERR, "ArgusCopyRecordStruct: ArgusCalloc error %s\n", strerror(errno));

#ifdef ARGUSDEBUG
      ArgusDebug (9, "ArgusCopyRecordStruct (%p) retn %p\n", rec, retn);
#endif 
   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (9, "ArgusCopyRecordStruct (%p) retn %p\n", rec, retn);
#endif 
   }

   return (retn);
}


void
ArgusDeleteRecordStruct (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusRecordStruct *tsns = NULL;
   int i;

   if (ns != NULL) {
      if (ns->qhdr.queue != NULL)
         ArgusRemoveFromQueue(ns->qhdr.queue, &ns->qhdr, ARGUS_LOCK);

      if (ns->bins) {
         int i;
         if (ns->bins->array != NULL) {
            for (i = 0; i < ns->bins->len; i++)
               if (ns->bins->array[i] != NULL) {
                  RaDeleteBin (parser, ns->bins, i);
                  ns->bins->array[i] = NULL;
               }

            ArgusFree (ns->bins->array);
            ns->bins->array = NULL;
         }

         ArgusFree (ns->bins);
         ns->bins = NULL;
      }

      if (ns->htblhdr != NULL)
         ArgusRemoveHashEntry(&ns->htblhdr);

      if (ns->hinthdr != NULL)
         ArgusRemoveHashEntry(&ns->hinthdr);

      if (ns->disp.str != NULL)
         free(ns->disp.str);
 
      if (ns->nsq != NULL) {
         while ((tsns = (struct ArgusRecordStruct *) ArgusPopQueue(ns->nsq, ARGUS_LOCK)) != NULL)
            ArgusDeleteRecordStruct (parser, tsns);
         ArgusDeleteQueue (ns->nsq);
         ns->nsq = NULL;
      }

      for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
         switch (i) {
            case ARGUS_LABEL_INDEX: {
               struct ArgusLabelStruct *label = (void *)ns->dsrs[i];
               extern char ArgusCanonLabelBuffer[];

               if (label != NULL) {
                  if (label->l_un.label != ArgusCanonLabelBuffer) {
                     free(label->l_un.label);
                  }
                  label->l_un.label = NULL;
               }
               break;
            }

            case ARGUS_JITTER_INDEX: {
               struct ArgusJitterStruct *jitter = (void *)ns->dsrs[i];

               if (jitter != NULL) {
                  if (jitter->hdr.subtype & ARGUS_HISTO_LINEAR) {
                  }
               }
               break;
            }

            case ARGUS_ENCAPS_INDEX: {
               struct ArgusEncapsStruct *encaps  = (struct ArgusEncapsStruct *) ns->dsrs[i];
               if (encaps != NULL) {
                  if ((encaps->sbuf != NULL) && (encaps->slen > 0)) {
                     ArgusFree(encaps->sbuf);
                     encaps->sbuf = NULL;
                  }
                  if ((encaps->dbuf != NULL) && (encaps->dlen > 0)) {
                     ArgusFree(encaps->dbuf);
                     encaps->dbuf = NULL;
                  }
               }
               break;
            }
         }

         if (ns->dsrs[i] != NULL) {
            ArgusFree (ns->dsrs[i]);
            ns->dsrs[i] = NULL;
         }
      }

      if (ns->correlates) {
         for (i = 0; i < ns->correlates->count; i++)
            ArgusDeleteRecordStruct(parser, ns->correlates->array[i]);
 
         ArgusFree(ns->correlates->array);
         ns->correlates->array = NULL;
         ArgusFree(ns->correlates);
      }

      if (ns->agg != NULL) {
         ArgusDeleteAggregator(parser, ns->agg);
         ns->agg = NULL;
      }

      ArgusFree(ns);
   }
#ifdef ARGUSDEBUG
   ArgusDebug (9, "ArgusDeleteRecordStruct (%p, %p)", parser, ns);
#endif 
}


int
ArgusGenerateCiscoRecord (struct ArgusRecordStruct *rec, unsigned char state, char *buf)
{
   int retn = 0;
#ifdef ARGUSDEBUG
   int len = 0;
#endif

   if (rec) {
      switch (rec->hdr.type & 0xF0) {
         case ARGUS_EVENT:
         case ARGUS_MAR: 
         default:
            break;

         case ARGUS_AFLOW:
         case ARGUS_NETFLOW:
         case ARGUS_FAR: {
            struct ArgusDSRHeader *dsr;
            int y, ind, dsrindex = 0;
            retn = 1;

            dsrindex = rec->dsrindex;
            for (y = 0, ind = 1; (dsrindex && (y < ARGUSMAXDSRTYPE)); y++, ind <<= 1) {
               if ((dsr = rec->dsrs[y]) != NULL) {
#ifdef ARGUDEBUG
                  len = ((dsr->type & ARGUS_IMMEDIATE_DATA) ? 1 :
                        ((dsr->subtype & ARGUS_LEN_16BITS)  ? dsr->argus_dsrvl16.len :
                                                              dsr->argus_dsrvl8.len));
#endif
                  switch (y) {
                     case ARGUS_NETWORK_INDEX: {
                        struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) dsr;
                        switch (net->hdr.subtype) {
                           case ARGUS_TCP_INIT: {
                              break;
                           }
                           case ARGUS_TCP_STATUS: {
                              break;
                           }
                           case ARGUS_TCP_PERF:
                           default: {
                              break;
                           }
                        }
                        break;
                     }

                     case ARGUS_SRCUSERDATA_INDEX:
                     case ARGUS_DSTUSERDATA_INDEX:
                     case ARGUS_AGR_INDEX: 
                     case ARGUS_PSIZE_INDEX:
                     case ARGUS_MPLS_INDEX:
                     case ARGUS_JITTER_INDEX:
                     case ARGUS_IPATTR_INDEX:
                     case ARGUS_LABEL_INDEX:
                     default: {
                        break;
                     }

                     case ARGUS_TIME_INDEX: {
                        break;
                     }

                     case ARGUS_METRIC_INDEX: {
                        break;
                     }
                  }
               }
            }
            break;
         }
      }
   }
         
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusGenerateCiscoRecord (%p, %d) len %d\n", rec, state, len);
#endif 
   return (retn);
}


// Generating an ArgusV3CorellateStruct from an Argus V5 ArgusRecordStruct
// involves modification of the transport struct that is in the ArgusCorrelateStruct.
// V3 is shorter than V5, but the appropriate values are the same.


void
ArgusGenerateV3CorrelateStruct(struct ArgusRecordStruct *ns)
{
   struct ArgusCorStruct *cor;
   int i;

   if ((cor = ns->correlates) != NULL) {
      struct ArgusV3CorrelateStruct *scor = NULL;
      struct ArgusV3CorMetrics *met = NULL;
      struct ArgusRecordStruct *sns;
      int clen = 0;

      clen  = sizeof(struct ArgusDSRHeader)/4 + (cor->count * sizeof(struct ArgusV3CorMetrics)/4);
      if ((scor = ArgusCalloc(4, clen)) == NULL)
         ArgusLog (LOG_ERR, "ArgusGenerateV3CorrelateStruct ArgusCalloc error %s", strerror(errno));

      scor->hdr.type    = ARGUS_COR_DSR;
      scor->hdr.subtype = 0;
      scor->hdr.argus_dsrvl8.qual = 0;
      scor->hdr.argus_dsrvl8.len  = clen;

      ns->dsrs[ARGUS_COR_INDEX] = &scor->hdr;
      ns->dsrindex |= 0x01 << ARGUS_COR_INDEX;

      met = &scor->metrics;

      for (i = 0; i < ns->correlates->count; i++) {
         if ((sns = ns->correlates->array[i]) != NULL) {
            struct ArgusTransportStruct *trans = (void *)sns->dsrs[ARGUS_TRANSPORT_INDEX];
            long long stime, ltime;

            if (trans != NULL)
               met->srcid.a_un.value = trans->srcid.a_un.value;

            stime = RaGetuSecDuration (sns);
            ltime = RaGetuSecDuration (ns);

            met->deltaDur     = stime - ltime;
            met->deltaStart   = (ArgusFetchStartuSecTime(sns) - ArgusFetchStartuSecTime(ns));
            met->deltaLast    =  (ArgusFetchLastuSecTime(sns) - ArgusFetchLastuSecTime(ns));
            met->deltaSrcPkts =  (ArgusFetchSrcPktsCount(sns) - ArgusFetchSrcPktsCount(ns));
            met->deltaDstPkts =  (ArgusFetchDstPktsCount(sns) - ArgusFetchDstPktsCount(ns));
            met++;
         }
      }
   }
}

void
ArgusGenerateCorrelateStruct(struct ArgusRecordStruct *ns)
{
   int i, clen = 0;
   struct ArgusCorStruct *cor;

   if ((cor = ns->correlates) != NULL) {
      struct ArgusCorrelateStruct *scor = NULL;
      struct ArgusCorMetrics *met = NULL;
      struct ArgusRecordStruct *sns;

      clen  = sizeof(struct ArgusDSRHeader)/4 + (cor->count * sizeof(struct ArgusCorMetrics)/4);
      if ((scor = ArgusCalloc(4, clen)) == NULL)
         ArgusLog (LOG_ERR, "ArgusGenerateCorrelateStruct ArgusCalloc error %s", strerror(errno));

      scor->hdr.type    = ARGUS_COR_DSR;
      scor->hdr.subtype = 0;
      scor->hdr.argus_dsrvl8.qual = 0;
      scor->hdr.argus_dsrvl8.len  = clen;

      ns->dsrs[ARGUS_COR_INDEX] = &scor->hdr;
      ns->dsrindex |= 0x01 << ARGUS_COR_INDEX;

      met = &scor->metrics;

      for (i = 0; i < ns->correlates->count; i++) {
         if ((sns = ns->correlates->array[i]) != NULL) {
            struct ArgusTransportStruct *trans = (void *)sns->dsrs[ARGUS_TRANSPORT_INDEX];
            long long stime, ltime;

            if (trans != NULL)
               met->srcid.a_un.value = trans->srcid.a_un.value;

            stime = RaGetuSecDuration (sns);
            ltime = RaGetuSecDuration (ns);

            met->deltaDur     = stime - ltime;
            met->deltaStart   = (ArgusFetchStartuSecTime(sns) - ArgusFetchStartuSecTime(ns));
            met->deltaLast    = (ArgusFetchLastuSecTime(sns) - ArgusFetchLastuSecTime(ns));
            met->deltaSrcPkts = (ArgusFetchSrcPktsCount(sns) - ArgusFetchSrcPktsCount(ns));
            met->deltaDstPkts = (ArgusFetchDstPktsCount(sns) - ArgusFetchDstPktsCount(ns));
            met++;
         }
      }
   }
}



struct ArgusHashTableHdr *ArgusFindHashEntry (struct ArgusHashTable *, struct ArgusHashStruct *);
struct ArgusHashTable *ArgusNewHashTable (size_t);
void ArgusDeleteHashTable (struct ArgusHashTable *);


struct RaBinProcessStruct * 
RaNewBinProcess (struct ArgusParserStruct *parser, int size)
{ 
   struct RaBinProcessStruct *retn = NULL;
   struct ArgusAdjustStruct *tnadp;
  
   parser->ArgusReverse = 0;
 
   if ((retn = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewBinProcess: ArgusCalloc error %s", strerror(errno));

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&retn->lock, NULL);
#endif
  
   tnadp = &retn->nadp;
   tnadp->mode    = -1;
   tnadp->modify  =  1;
   tnadp->slen    =  2;
   tnadp->count   = 1;
   tnadp->value   = 1;

   if ((retn->array = (struct RaBinStruct **)ArgusCalloc(size, sizeof(struct RaBinStruct *))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewBinProcess: ArgusCalloc error %s", strerror(errno));

   retn->arraylen = size;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaNewBinProcess(%p, %d) returns %p\n", parser, size, retn);
#endif
   return (retn);
}


int
RaDeleteBinProcess(struct ArgusParserStruct *parser, struct RaBinProcessStruct *rbps)
{
   int retn = 0;

   if (rbps != NULL) {
      struct RaBinStruct *bin = NULL;
      int i, max = ((parser->tflag && !parser->RaWildCardDate) ? rbps->nadp.count : rbps->max) + 1;

      for (i = rbps->index; i < max; i++) {
         if ((rbps->array != NULL) && ((bin = rbps->array[i]) != NULL)) {
            RaDeleteBin(parser, rbps, i);
         }
      }

      if (rbps->array != NULL) ArgusFree(rbps->array);

#if defined(ARGUS_THREADS)
      pthread_mutex_destroy(&rbps->lock);
#endif

      ArgusFree(rbps);
   }
   return (retn);
}


struct RaBinStruct *
RaNewBin (struct ArgusParserStruct *parser, struct RaBinProcessStruct *rbps, struct ArgusRecordStruct *ns, long long startpt, int sindex)
{
   struct RaBinStruct *retn = NULL;

   if ((retn = (struct RaBinStruct *) ArgusCalloc (1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "RaNewBin: ArgusCalloc error %s\n", strerror(errno));

   if ((retn->agg = ArgusCopyAggregator(parser->ArgusAggregator)) == NULL)
      ArgusLog (LOG_ERR, "RaNewBin: ArgusCopyAggregator error");

   switch (rbps->nadp.mode) {
      default:
      case ARGUSSPLITTIME: {
         retn->value         = startpt;
         retn->stime.tv_sec  = startpt / 1000000;
         retn->stime.tv_usec = startpt % 1000000;

         startpt += rbps->size;

         retn->etime.tv_sec  = startpt / 1000000;
         retn->etime.tv_usec = startpt % 1000000;
         break;
      }

      case ARGUSSPLITSIZE:
      case ARGUSSPLITCOUNT:
         retn->value = rbps->start + (rbps->size * (rbps->index - sindex));
         break;
   }

   retn->size  = rbps->size;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaNewBin(%p, %p, %p, %lld, %d) returns %p\n", parser, rbps, ns, startpt, sindex, retn);
#endif
   return (retn);
}

void
RaDeleteBin (struct ArgusParserStruct *parser, struct RaBinProcessStruct *rbps,
             int index)
{
   struct RaBinStruct *bin;

   if (rbps == NULL) {
#ifdef ARGUSDEBUG
   ArgusDebug (2, "%s: rbps is NULL\n", __func__);
#endif
      return;
   }

   if (rbps->array == NULL) {
#ifdef ARGUSDEBUG
   ArgusDebug (2, "%s: rbps array is NULL\n", __func__);
#endif
      return;
   }

   bin = rbps->array[index];
   if (bin != NULL) {
      rbps->array[index] = NULL;
      rbps->count--;
      if (bin->agg != NULL)
         ArgusDeleteAggregator (parser, bin->agg);
      if (bin->table != NULL)
         free(bin->table);

      ArgusFree(bin);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "%s(%p, %p, %d)\n", __func__, parser, rbps, index);
#endif
   return;
}

struct ArgusMaskStruct *
ArgusSelectMaskDefs(struct ArgusRecordStruct *ns)
{
   struct ArgusMaskStruct *mask = NULL;

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_MAR: 
      case ARGUS_EVENT: {
         mask = ArgusSrcIdMaskDefs;
         break;
      }

      default: {
         struct ArgusNetworkStruct *net = NULL;
         struct ArgusFlow *flow = NULL;

         if ((flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
            if (flow->hdr.subtype == ARGUS_FLOW_ARP) {
               mask = ArgusArpMaskDefs;
            } else {
               net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
               switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV6: {
                     if (net != NULL) {
                        switch (net->hdr.argus_dsrvl8.qual) {
                           default:
                              mask = ArgusIpV6MaskDefs;
                              break;
                        }

                     } else
                        mask = ArgusIpV6MaskDefs;
                     break;
                  }

                  case ARGUS_TYPE_IPV4: {
                     if (net != NULL) {
                        switch (net->hdr.argus_dsrvl8.qual) {
                           default:
                              mask = ArgusIpV4MaskDefs;
                              break;
                        }
                     } else
                        mask = ArgusIpV4MaskDefs;
                     break;
                  }

                  case ARGUS_TYPE_ISIS: {
                     struct ArgusIsisFlow *isis = (struct ArgusIsisFlow *) &flow->isis_flow;

                     switch (isis->pdu_type) {
                        default:
                        case L1_LAN_IIH:
                        case L2_LAN_IIH: mask = ArgusIsisHelloMaskDefs; break;
                        case L1_LSP:
                        case L2_LSP:     mask = ArgusIsisLspMaskDefs;   break;
                        case L1_CSNP:
                        case L2_CSNP:    mask = ArgusIsisCsnpMaskDefs;  break;
                        case L1_PSNP:
                        case L2_PSNP:    mask = ArgusIsisPsnpMaskDefs;  break;
                     }

                     break;
                  }

                  case ARGUS_TYPE_RARP:
                  case ARGUS_TYPE_ARP:
                     mask = ArgusArpMaskDefs;
                     break;

                  case ARGUS_TYPE_WLAN:
                     mask = ArgusWlanMaskDefs;
                     break;

                  default:
                  case ARGUS_TYPE_ETHER:
                     mask = ArgusEtherMaskDefs;
                     break;
               }
            }
         }
      }
   }

   return mask;
}


struct ArgusMaskStruct *
ArgusSelectRevMaskDefs(struct ArgusRecordStruct *ns)
{
   struct ArgusMaskStruct *mask = NULL;
   struct ArgusNetworkStruct *net;
   struct ArgusFlow *flow;

   flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];
   net  = (struct ArgusNetworkStruct *)ns->dsrs[ARGUS_NETWORK_INDEX];

   if (flow != NULL) {
      switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
         case ARGUS_TYPE_IPV6: {
            mask = ArgusIpV6RevMaskDefs;
            if (net != NULL) {
               switch (net->hdr.argus_dsrvl8.qual) {
                  default:
                     break;
               }
            }
            break;
         }

         case ARGUS_TYPE_IPV4: {
            mask = ArgusIpV4RevMaskDefs;
            if (net != NULL) {
               switch (net->hdr.argus_dsrvl8.qual) {
                  default:
                    break;
               }
            }
            break;
         }

         case ARGUS_TYPE_RARP:
         case ARGUS_TYPE_ARP:
            mask = ArgusArpRevMaskDefs;
            break;

         case ARGUS_TYPE_WLAN:
            mask = ArgusWlanRevMaskDefs;
            break;

         default:
         case ARGUS_TYPE_ETHER:
            mask = ArgusEtherRevMaskDefs;
            break;
      }
   }
   return mask;
}


struct ArgusHashStruct *
ArgusGenerateHashStruct (struct ArgusAggregatorStruct *na,  struct ArgusRecordStruct *ns, struct ArgusFlow *flow)
{
   struct ArgusHashStruct *retn = NULL;
   char *ptr = NULL;

   if (na != NULL) {
      if (na->hstruct.buf == NULL) {
         if ((na->hstruct.buf = (unsigned int *) ArgusCalloc(1, RA_HASHSIZE)) == NULL)
            ArgusLog (LOG_ERR, "ArgusGenerateHashStruct(%p, %p, %p) ArgusCalloc returned error %s\n", na, ns, flow, strerror(errno));
      } else
         bzero(na->hstruct.buf, RA_HASHSIZE);

      ptr = (char *) na->hstruct.buf;

      switch (ns->hdr.type & 0xF0) {
         case ARGUS_MAR: {
            if ((na->mask == -1) || (na->mask & ARGUS_MASK_SRCID_INDEX)) {
               struct ArgusRecord *rec = (struct ArgusRecord *) ns->dsrs[0];
               int i, len, s = sizeof(unsigned short);
               struct ArgusAddrStruct thisid;
               unsigned short *sptr;

               bzero (&thisid, sizeof(thisid));
               len = sizeof(thisid.a_un);
               switch (rec->argus_mar.status & (ARGUS_IDIS_STRING | ARGUS_IDIS_INT | ARGUS_IDIS_IPV4)) {
                  case ARGUS_IDIS_STRING: {
                     bcopy (&rec->ar_un.mar.str, &thisid.a_un.str, 4);
                     break;
                  }

                  case ARGUS_IDIS_INT: {
                     bcopy (&rec->ar_un.mar.value, &thisid.a_un.value, 4);
                     break;
                  }

                  case ARGUS_IDIS_IPV4: {
                     thisid.a_un.ipv4 = rec->ar_un.mar.ipv4;
                     break;
                  }

                  case ARGUS_IDIS_IPV6: {
                     bcopy (&rec->ar_un.mar.ipv6, &thisid.a_un.ipv6, sizeof(thisid.a_un.ipv6));
                     break;
                  }

                  case ARGUS_IDIS_UUID: {
                     bcopy (&rec->ar_un.mar.uuid, &thisid.a_un.uuid, sizeof(thisid.a_un.uuid));
                     break;
                  }
               }

               if (rec->argus_mar.status & ARGUS_ID_INC_INF) {
                  if (rec->hdr.cause & ARGUS_SRC_RADIUM) 
                     bcopy ("rad0", &thisid.inf, sizeof(thisid.inf));
                  else
                     bcopy ("man0", &thisid.inf, sizeof(thisid.inf));
                  len += sizeof(thisid.inf);
               }
               
               retn = &na->hstruct;

               retn->hash = 0; 
               retn->len  = len; 

               bcopy(&thisid, ptr, len);

               sptr = (unsigned short *)&thisid;

               for (i = 0, len = retn->len / s; i < len; i++)
                  retn->hash += *sptr++;
            }
            break;
         }

         case ARGUS_EVENT:
         case ARGUS_AFLOW:
         case ARGUS_NETFLOW: 
         case ARGUS_FAR: {
            struct ArgusFlow *tflow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
            int i, len, tlen = 0, s = sizeof(unsigned short);
            unsigned short *sptr;

            retn = &na->hstruct;

            retn->hash = 0; 
            retn->len  = 0;

            if (na->mask != -1) {
               if (flow == NULL)
                  flow = tflow;

               if (na->ArgusMaskDefs == NULL)
                  if ((na->ArgusMaskDefs = ArgusSelectMaskDefs(ns)) == NULL) 
                     return(retn);

               if ((flow != NULL)) {
                  if (na->mask & ((0x01LL << ARGUS_MASK_SADDR) | (0x01LL << ARGUS_MASK_DADDR))) {
                     bcopy ((char *)&flow->hdr, ptr, sizeof(flow->hdr));
                     ((struct ArgusFlow *)ptr)->hdr.subtype           &= 0x3F;
                     ((struct ArgusFlow *)ptr)->hdr.argus_dsrvl8.qual &= 0x1F;
                     ((struct ArgusFlow *)ptr)->hdr.argus_dsrvl8.len   = 0;
                     ptr += sizeof(flow->hdr);
                     tlen += sizeof(flow->hdr);
                  }
               }
                   
               for (i = 0; ((i < ARGUS_MAX_MASK_LIST) && (tlen < RA_HASHSIZE)); i++) {
                  if (na->mask < (0x01LL << i)) 
                     break;
                  if (na->mask & (0x01LL << i)) {
                     if (na->ArgusMaskDefs[i].name != NULL) {
                     char *p = (char *)ns->dsrs[na->ArgusMaskDefs[i].dsr];

                     if (p != NULL) {
                        int offset = 0, slen = 0;

                        switch (i) {
                           case ARGUS_MASK_STIME:
                              break;

                           case ARGUS_MASK_SMPLS:
                           case ARGUS_MASK_DMPLS: {
                              unsigned int label  = (*(unsigned int *)&((char *) p)[na->ArgusMaskDefs[i].offset]) >> 12;
                              bcopy ((char *)&label, ptr, na->ArgusMaskDefs[i].len);
                              ptr  += na->ArgusMaskDefs[i].len;
                              tlen += na->ArgusMaskDefs[i].len;
                              break;
                           }

                           case ARGUS_MASK_SPORT:
                           case ARGUS_MASK_DPORT: {
                              if (flow != NULL) {
                                 switch (flow->hdr.subtype & 0x3F) {
                                    case ARGUS_FLOW_CLASSIC5TUPLE: {
                                       switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                          case ARGUS_TYPE_IPV4:
                                             switch (flow->ip_flow.ip_p) {
                                                case IPPROTO_ESP: {
                                                   slen   = (i == ARGUS_MASK_SPORT) ? -1 : 4;
                                                   offset = (i == ARGUS_MASK_SPORT) ? -1 : na->ArgusMaskDefs[i].offset;
                                                   break;
                                                }

                                                case IPPROTO_ICMP: {
                                                   if (i == ARGUS_MASK_SPORT) {
                                                      slen = 1;
                                                      offset = na->ArgusMaskDefs[i].offset;
                                                   } else {
                                                      switch (flow->icmp_flow.type) {
                                                         case ICMP_ECHO:
                                                         case ICMP_ECHOREPLY:
                                                            slen = -1;
                                                            break;

                                                         case ICMP_MASKREQ:
                                                         case ICMP_TSTAMP:
                                                         case ICMP_IREQ: 
                                                         case ICMP_MASKREPLY:
                                                         case ICMP_TSTAMPREPLY:
                                                         case ICMP_IREQREPLY:
                                                            offset = na->ArgusMaskDefs[i].offset - 1;
                                                            slen = 5;
                                                            break;
  
                                                         default:
                                                            offset = na->ArgusMaskDefs[i].offset - 1;
                                                            slen = 1;
                                                      }
                                                   }
                                                   break;
                                                }
                                             }
                                             break;  
                                       }
                                    }
                                 }
                              }
                           }

                           default: {
                              if (slen < 0) {
                                 slen = 0;
                                 break;
                              }

                              if (na->ArgusMaskDefs[i].len > 0) {
                                 if (!slen) {
                                    slen = na->ArgusMaskDefs[i].len;
                                    offset = na->ArgusMaskDefs[i].offset;
                                 }

                                 if (offset == NLI) {
                                    unsigned char *cptr = NULL, cbuf;
                                    unsigned short sbuf;
                                    switch (slen) {
                                       case 0: cbuf = na->ArgusMaskDefs[i].index; cptr = &cbuf; break;
                                       case 1: cbuf = na->ArgusMaskDefs[i].index; cptr = &cbuf; break;
                                       case 2: sbuf = na->ArgusMaskDefs[i].index; cptr = (unsigned char *)&sbuf; break;
                                       case 4:
                                       default:
                                          cptr = (unsigned char *)&na->ArgusMaskDefs[i].index;
                                          break;
                                    }

                                    bcopy (cptr, ptr, slen);

                                 } else {
                                    bcopy (&((char *) p)[offset], ptr, slen);

                                    if (ARGUS_MASK_ETYPE == i) {
                                       u_short etype = *(u_short *)ptr;
                                       if (etype < 1500) {
                                          *(u_short *)ptr = 0;
                                       }
                                    }
                                 }
                              }
                              break;
                           }


                           case ARGUS_MASK_INODE: {
                              if (na->ArgusMaskDefs[i].len > 0) {
                                 unsigned int iaddr[4];
                                 slen = na->ArgusMaskDefs[i].len;
                                 offset = na->ArgusMaskDefs[i].offset;
                                 bcopy (&((char *) p)[offset], iaddr, slen);

                                 if (na->iaddrlen > 0)
                                    iaddr[0] &= na->imask.addr_un.ipv4;

                                 bcopy (iaddr, ptr, slen);
                              }
                              break;
                           }
                        }

                        ptr  += slen;
                        tlen += slen;
                     }
                     }
                  }
               }

               retn->len = s * ((tlen + (s - 1))/ s); 
               if (retn->len > RA_HASHSIZE)
                  retn->len = RA_HASHSIZE;
               sptr = (unsigned short *)&retn->buf[0];

               for (i = 0, len = retn->len / s; i < len; i++)
                  retn->hash += *sptr++;

               na->ArgusMaskDefs = NULL;
            }
            break;
         }
      }
   }

   return (retn);
}


struct ArgusHashStruct *
ArgusGenerateReverseHashStruct (struct ArgusAggregatorStruct *na,  struct ArgusRecordStruct *ns, struct ArgusFlow *flow)
{
   struct ArgusHashStruct *retn = &na->hstruct;
   struct ArgusFlow *tflow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
   char *ptr = (char *) na->hstruct.buf; 
   int i, len, tlen = 0, s = sizeof(unsigned short);
   unsigned short *sptr;

   if (ptr == NULL) {
      if ((na->hstruct.buf = (unsigned int *) ArgusCalloc(1, RA_HASHSIZE)) == NULL)
         ArgusLog (LOG_ERR, "ArgusGenerateHashStruct(%p, %p, %p) ArgusCalloc returned error %s\n", na, ns, flow, strerror(errno));

      ptr = (char *) na->hstruct.buf;

   } else
      bzero ((char *)ptr, retn->len);

   retn->hash = 0; 
   retn->len  = 0;

   if (na->mask && (tflow != NULL)) {
      if (flow == NULL)
         flow = tflow;

      if ((flow != NULL)) {
//       if (na->ArgusMaskDefs == NULL)
            na->ArgusMaskDefs = ArgusSelectRevMaskDefs(ns);

         if (na->mask & ((0x01LL << ARGUS_MASK_SADDR) | (0x01LL << ARGUS_MASK_DADDR))) {
            bcopy ((char *)&flow->hdr, ptr, sizeof(flow->hdr));
            ((struct ArgusFlow *)ptr)->hdr.subtype           &= 0x3F;
            ((struct ArgusFlow *)ptr)->hdr.argus_dsrvl8.qual &= 0x1F;
            ((struct ArgusFlow *)ptr)->hdr.argus_dsrvl8.len   = 0;
            ptr += sizeof(flow->hdr);
            tlen += sizeof(flow->hdr);
         }
          
         for (i = 0; ((i < ARGUS_MAX_MASK_LIST) && (tlen < RA_HASHSIZE)); i++) {
            if (na->mask < (0x01LL << i))
               break;

            if (na->mask & (0x01LL << i)) {
               int offset = 0, slen = 0;
               char *p = (char *)ns->dsrs[na->ArgusMaskDefs[i].dsr];

               if (p != NULL) {
                  switch (i) {
                     case ARGUS_MASK_SMPLS:
                     case ARGUS_MASK_DMPLS: {
                        unsigned int label  = (*(unsigned int *)&((char *) p)[na->ArgusMaskDefs[i].offset]) >> 12;
                        bcopy ((char *)&label, ptr, na->ArgusMaskDefs[i].len);
                        ptr  += na->ArgusMaskDefs[i].len;
                        tlen += na->ArgusMaskDefs[i].len;
                        break;
                     }

                     case ARGUS_MASK_SPORT:
                     case ARGUS_MASK_DPORT:
                        switch (flow->hdr.subtype & 0x3F) {
                           case ARGUS_FLOW_CLASSIC5TUPLE: {
                              switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                 case ARGUS_TYPE_IPV4:
                                    switch (flow->ip_flow.ip_p) {
                                       case IPPROTO_ESP: { 
                                          slen   = (i == ARGUS_MASK_SPORT) ? -1 : 4;
                                          offset = (i == ARGUS_MASK_SPORT) ? -1 : na->ArgusMaskDefs[i].offset;
                                          break;
                                       }

                                       case IPPROTO_ICMP: { 
                                          slen = 1;
                                          offset = (i == ARGUS_MASK_SPORT) ? na->ArgusMaskDefs[i].offset :
                                                                             na->ArgusMaskDefs[i].offset - 1;
                                          break;
                                       }
                                    }
                                    break;  
                              }
                           }
                        }

                     default: {
                        if (slen < 0) {
                           slen = 0;
                           break;
                        }

                        if (na->ArgusMaskDefs[i].len > 0) {
                           if (!slen) {
                              slen = na->ArgusMaskDefs[i].len;
                              offset = na->ArgusMaskDefs[i].offset;
                           }

                           if (offset == NLI) {
                              unsigned char *cptr = NULL, cbuf;
                              unsigned short sbuf;
                              switch (slen) {
                                 case 0: cbuf = na->ArgusMaskDefs[i].index; cptr = &cbuf; break;
                                 case 1: cbuf = na->ArgusMaskDefs[i].index; cptr = &cbuf; break;
                                 case 2: sbuf = na->ArgusMaskDefs[i].index; cptr = (unsigned char *)&sbuf; break;
                                 case 4:
                                 default:
                                    cptr = (unsigned char *)&na->ArgusMaskDefs[i].index;
                                    break;
                              }

                              bcopy (cptr, ptr, slen);

                           } else {
                              bcopy (&((char *) p)[offset], ptr, slen);
                           }
                        }
                        break;
                     }
                  }

                  ptr  += slen;
                  tlen += slen;
               }
            }
         }

         retn->len = s * ((tlen + (s - 1))/ s); 
         if (retn->len > RA_HASHSIZE)
            retn->len = RA_HASHSIZE;
         sptr = (unsigned short *)&retn->buf[0];

         for (i = 0, len = retn->len / s; i < len; i++)
            retn->hash += *sptr++;

         na->ArgusMaskDefs = NULL;
      }
   }

   return (retn);
}


struct ArgusHashStruct *
ArgusGenerateHintStruct (struct ArgusAggregatorStruct *na,  struct ArgusRecordStruct *ns)
{
   struct ArgusHashStruct *retn = NULL;

   if (na != NULL) {
      struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
      int i, len = 0, s = sizeof(unsigned short);
      char *ptr = (char *) na->hstruct.buf; 
      unsigned short *sptr;

      retn = &na->hstruct;

      if (ptr == NULL) {
         if ((na->hstruct.buf = (unsigned int *) ArgusCalloc(1, RA_HASHSIZE)) == NULL)
            ArgusLog (LOG_ERR, "ArgusGenerateHashStruct(%p, %p, %p) ArgusCalloc returned error %s\n", na, ns, flow, strerror(errno));

         ptr = (char *) na->hstruct.buf;

      } else
         bzero ((char *)ptr, retn->len);

      retn->hash = 0; 
      retn->len  = 0;

      if (na->mask && (flow != NULL)) {
         switch (flow->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4: {
                     switch (flow->ip_flow.ip_p) {
                        case IPPROTO_TCP: {
                           struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];

                           if (net != NULL) {
                              switch (net->hdr.subtype) {
                                 case ARGUS_TCP_INIT:
                                 case ARGUS_TCP_STATUS:
                                 case ARGUS_TCP_PERF: {
                                    struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                                    if (tcp->src.seqbase != 0) {
                                       bcopy((char *)&tcp->src.seqbase, ptr, sizeof(tcp->src.seqbase));
                                       ptr += sizeof(tcp->src.seqbase);
                                       len += sizeof(tcp->src.seqbase);

                                       bcopy((char *)&flow->ip_flow.ip_p, ptr, 1);
                                       ptr += sizeof(flow->ip_flow.ip_p);
                                       len += sizeof(flow->ip_flow.ip_p);
                                    }
                                    break;
                                 }
                              }
                              break;
                           }
                        }

                        case IPPROTO_UDP: {
                           struct ArgusIPAttrStruct *attr = (void *) ns->dsrs[ARGUS_IPATTR_INDEX];

                           if ((attr != NULL) && (attr->src.ip_id != 0)) {
                              bcopy((char *)&attr->src.ip_id, ptr, sizeof(attr->src.ip_id));
                              ptr += sizeof(attr->src.ip_id);
                              len += sizeof(attr->src.ip_id);

                              bcopy((char *)&flow->ip_flow.dport, ptr, sizeof(flow->ip_flow.dport));
                              len += sizeof(flow->ip_flow.dport);
                              ptr += sizeof(flow->ip_flow.dport);
                           }
                           break;
                        }

                        case IPPROTO_ICMP: {
                           bcopy((char *)&flow->icmp_flow.ip_p, ptr++, 1); len++;
                           bcopy((char *)&flow->icmp_flow.tp_p, ptr++, 1); len++;
                           bcopy((char *)&flow->icmp_flow.type, ptr++, 1); len++;
                           bcopy((char *)&flow->icmp_flow.code, ptr++, 1); len++;

                           bcopy((char *)&flow->icmp_flow.id, ptr, sizeof(flow->icmp_flow.id));
                           ptr += sizeof(flow->icmp_flow.id);
                           len += sizeof(flow->icmp_flow.id);
                           bcopy((char *)&flow->icmp_flow.ip_id, ptr, sizeof(flow->icmp_flow.ip_id));
                           ptr += sizeof(flow->icmp_flow.ip_id);
                           len += sizeof(flow->icmp_flow.id);
                           break;
                        }
                     }
                     break;  
                  }
               }
            }
         }
      }

      if (len > 0) {
         retn->len = s * ((len + (s - 1))/ s); 
         sptr = (unsigned short *)&retn->buf[0];

         for (i = 0, len = retn->len / s; i < len; i++)
            retn->hash += *sptr++;

      } else 
         retn = NULL;
   }

   return (retn);
}


struct ArgusRecordStruct *
ArgusFindRecord (struct ArgusHashTable *htable, struct ArgusHashStruct *hstruct)
{
   struct ArgusRecordStruct *retn = NULL;
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
   ArgusDebug (6, "ArgusFindRecord () returning %p\n", retn);
#endif
  
   return (retn);
}


void ArgusEmptyHashTable (struct ArgusHashTable *htbl);

struct ArgusHashTable *
ArgusNewHashTable (size_t size)
{
   struct ArgusHashTable *retn = NULL;

   if ((retn = (struct ArgusHashTable *) ArgusCalloc (1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewHashTable: ArgusCalloc(1, %d) error %s\n", size, strerror(errno));

   if ((retn->array = (struct ArgusHashTableHdr **) ArgusCalloc (size, sizeof (struct ArgusHashTableHdr *))) == NULL)
      ArgusLog (LOG_ERR, "RaMergeQueue: ArgusCalloc error %s\n", strerror(errno));

   retn->size = size;

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&retn->lock, NULL);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusNewHashTable (%d) returning %p\n", size, retn);
#endif

   return (retn);
}


void
ArgusDeleteHashTable (struct ArgusHashTable *htbl)
{

   if (htbl != NULL) {
      ArgusEmptyHashTable (htbl);

      if (htbl->array != NULL)
         ArgusFree(htbl->array);

      ArgusFree(htbl);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusDeleteHashTable (%p)\n", htbl);
#endif
}

void
ArgusEmptyHashTable2 (struct ArgusHashTable *htbl, ArgusEmptyHashCallback dcb)
{
   struct ArgusHashTableHdr *htblhdr = NULL, *tmp;
   int i;
 
#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&htbl->lock);
#endif
   for (i = 0; i < htbl->size; i++) {
      if ((htblhdr = htbl->array[i]) != NULL) {
         if (htblhdr->prv && htblhdr->nxt) {
            htblhdr->prv->nxt = NULL;
            while ((tmp = htblhdr) != NULL) {
               htblhdr = htblhdr->nxt;
               if (dcb)
                  dcb(tmp->object);
               if (tmp->hstruct.buf != NULL)
                  ArgusFree (tmp->hstruct.buf);
               ArgusFree (tmp);
            }
         }
         htbl->array[i] = NULL;
      }
   }
#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&htbl->lock);
#endif
 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusEmptyHashTable (%p) returning\n", htbl);
#endif
}

void
ArgusEmptyHashTable (struct ArgusHashTable *htbl)
{
   ArgusEmptyHashTable2(htbl, NULL);
}

void
ArgusHashForEach(struct ArgusHashTable *htbl, ArgusHashForEachCallback fcb,
                 void *user)
{
   struct ArgusHashTableHdr *htblhdr;
   struct ArgusHashTableHdr *first;
   int i;

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&htbl->lock);
#endif
   for (i = 0; i < htbl->size; i++) {
      if ((htblhdr = htbl->array[i]) != NULL) {
         first = htblhdr;
         do {
            fcb(htblhdr->object, user);
            htblhdr = htblhdr->nxt;
         } while (htblhdr != first);
      }
   }
#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&htbl->lock);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (6, "%s (%p, %p) returning\n", __func__, htbl, fcb);
#endif
}

struct ArgusHashTableHdr *
ArgusFindHashEntry (struct ArgusHashTable *htable, struct ArgusHashStruct *hstruct)
{
   struct ArgusHashTableHdr *retn = NULL, *target, *head;
   unsigned int ind = (hstruct->hash % htable->size), i, len;

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&htable->lock);
#endif 

   if ((target = htable->array[ind]) != NULL) {
      head = target;
      do {
         unsigned short *ptr1 = (unsigned short *) hstruct->buf;
         unsigned short *ptr2 = (unsigned short *) target->hstruct.buf;

         for (i = 0, len = hstruct->len/sizeof(unsigned short); i < len; i++)
            if (*ptr1++ != *ptr2++)
               break;
         if (i == len) {
            retn = target;
            break;
         }
         target = target->nxt;
      } while (target != head);
 
      if (retn != NULL) {
         if (retn != head)
            htable->array[ind] = retn;
      }
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&htable->lock);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusFindHashEntry () returning %p\n", retn);
#endif
  
   return (retn);
}


struct ArgusHashTableHdr *
ArgusAddHashEntry (struct ArgusHashTable *table, void *ns, struct ArgusHashStruct *hstruct)
{
   struct ArgusHashTableHdr *retn = NULL, *start = NULL;
   int ind;

   if (hstruct != NULL) {
      if ((retn = (struct ArgusHashTableHdr *) ArgusCalloc (1, sizeof (struct ArgusHashTableHdr))) == NULL)
         ArgusLog (LOG_ERR, "ArgusAddHashEntry(%p, %p, %d) ArgusCalloc returned error %s\n", table, ns, hstruct, strerror(errno));

      retn->object = ns;

      if (hstruct->len > 0) {
         retn->hstruct = *hstruct;
         if ((retn->hstruct.buf = (unsigned int *) ArgusCalloc (1, hstruct->len)) == NULL)
            ArgusLog (LOG_ERR, "ArgusAddHashEntry(%p, %p, %d) ArgusCalloc returned error %s\n", table, ns, hstruct, strerror(errno));

         bcopy (hstruct->buf, retn->hstruct.buf, hstruct->len);
      }

      ind = (hstruct->hash % table->size);
      
#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&table->lock);
#endif

      if ((start = table->array[ind]) != NULL) {
         retn->nxt = start;
         retn->prv = start->prv;
         retn->prv->nxt = retn;
         retn->nxt->prv = retn;
      } else
         retn->prv = retn->nxt = retn;

      table->array[ind] = retn;
      table->count++;

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&table->lock);
#endif
      retn->htbl = table;

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (6, "ArgusAddHashEntry (%p) no hash struct: returning %p\n", ns, retn);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusAddHashEntry (%p) returning %p\n", ns, retn);
#endif

   return (retn);
}

void
ArgusRemoveHashEntry (struct ArgusHashTableHdr **htblhdr)
{
   unsigned int hash = (*htblhdr)->hstruct.hash;
   struct ArgusHashTable *table = (*htblhdr)->htbl;
   int ind = hash % table->size;

   if (htblhdr && *htblhdr) {
#ifdef ARGUSDEBUG
      ArgusDebug (6, "ArgusRemoveHashEntry (%p)\n", *htblhdr);
#endif

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&table->lock);
#endif
      if ((*htblhdr)->nxt == *htblhdr) {
         (*htblhdr)->nxt = NULL;
         (*htblhdr)->prv = NULL;
         if (*htblhdr == table->array[ind])
            table->array[ind] = NULL;

      } else {
         (*htblhdr)->prv->nxt = (*htblhdr)->nxt;
         (*htblhdr)->nxt->prv = (*htblhdr)->prv;

         if (*htblhdr == table->array[ind])
            table->array[ind] = (*htblhdr)->nxt;
      }

      if ((*htblhdr)->hstruct.buf != NULL)
         ArgusFree ((*htblhdr)->hstruct.buf);
      ArgusFree (*htblhdr);
      *htblhdr = NULL;

      table->count--;
#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&table->lock);
#endif
   } else {
#ifdef ARGUSDEBUG
      if (htblhdr == NULL)
         ArgusDebug (6, "ArgusRemoveHashEntry (NULL)\n");
      else
         ArgusDebug (6, "ArgusRemoveHashEntry (%p) passes NULL\n", htblhdr);
#endif
   }
}


int ArgusProcessServiceAvailability (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int ArgusProcessTCPAvailability (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int ArgusProcessUDPAvailability (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int ArgusProcessESPAvailability (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int ArgusProcessICMPAvailability (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int ArgusProcessIPAvailability (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int ArgusProcessARPAvailability (struct ArgusParserStruct *, struct ArgusRecordStruct *);

int
ArgusProcessServiceAvailability (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow = (struct ArgusFlow *)argus->dsrs[ARGUS_FLOW_INDEX];
   int retn = 1;

   argus->status &= ~RA_SVCTEST;
   if (flow == NULL)
      return retn;

   switch (flow->hdr.subtype & 0x3F) {
      case ARGUS_FLOW_CLASSIC5TUPLE: {
         switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
            case ARGUS_TYPE_IPV4: {
               switch (flow->ip_flow.ip_p) {
                  case IPPROTO_TCP: 
                     argus->status |= ArgusProcessTCPAvailability (parser, argus);
                     break;
                  case IPPROTO_ICMP: 
                     argus->status |= ArgusProcessICMPAvailability (parser, argus);
                     break;
                  case IPPROTO_UDP:
                     argus->status |= ArgusProcessUDPAvailability (parser, argus);
                     break;
                  case IPPROTO_ESP:
                     argus->status |= ArgusProcessESPAvailability (parser, argus);
                     break;
                  default:
                     argus->status |= ArgusProcessIPAvailability (parser, argus);
                     break;
               }
               break;
            }
            case ARGUS_TYPE_IPV6: {
               switch (flow->ipv6_flow.ip_p) {
                  case IPPROTO_TCP:
                     argus->status |= ArgusProcessTCPAvailability (parser, argus);
                     break;
                  case IPPROTO_ICMP: 
                     argus->status |= ArgusProcessICMPAvailability (parser, argus);
                     break;
                  case IPPROTO_UDP:
                     argus->status |= ArgusProcessUDPAvailability (parser, argus);
                     break;
                  default:
                     argus->status |= ArgusProcessIPAvailability (parser, argus);
                     break;
               }
               break;
            }
            case ARGUS_TYPE_RARP:
            case ARGUS_TYPE_ARP:
               argus->status |= ArgusProcessARPAvailability (parser, argus);
               break;

            case ARGUS_TYPE_ETHER:
               break;
         }
         break;
      }
                                                                                                                                  
      case ARGUS_FLOW_ARP: {
         argus->status |= ArgusProcessARPAvailability (parser, argus);
         break;
      }

      default:
         break;
   }


#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessServiceAvailability: returning %d \n", retn);
#endif

   return (retn);
}


int
ArgusProcessTCPAvailability (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *)argus->dsrs[ARGUS_METRIC_INDEX];
   struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX];
   int retn = RA_SVCPASSED, status = 0;

   if (net == NULL)
      return retn;

   switch (net->hdr.subtype) {
      case ARGUS_TCP_INIT:
      case ARGUS_TCP_STATUS:
      case ARGUS_TCP_PERF: {
         struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
         status = tcp->status;
         break;
      }

      default:
         return(retn);
   }

   if (status & ARGUS_SAW_SYN) {
      if (status & ARGUS_RESET) {
         if (status & ARGUS_DST_RESET) {
            if (!(status & ARGUS_SAW_SYN_SENT))
               retn = RA_SVCFAILED;
         } else {
            if (metric->src.pkts && !(metric->dst.pkts))
               retn = RA_SVCFAILED;
         }
      } else {
         if (!(status & (ARGUS_SAW_SYN_SENT | ARGUS_CON_ESTABLISHED)))
            retn = RA_SVCFAILED;
      }

   } else {
      if (status & (ARGUS_SAW_SYN | ARGUS_SAW_SYN_SENT)) {
         if (metric->src.pkts && !(metric->dst.pkts))
            retn = RA_SVCFAILED;
      }
   }

   if (status & ARGUS_TIMEOUT)
      if (metric->src.pkts && !(metric->dst.pkts))
         retn = RA_SVCFAILED;

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessTCPAvailability: returning %d \n", retn);
#endif

   return (retn);
}

int ArgusTestMulticast( struct ArgusInput *input, unsigned int);

int
ArgusTestMulticast( struct ArgusInput *input, unsigned int addr)
{
   int retn = 0;

   if (input != NULL) {
      if (input->ArgusLocalNet || input->ArgusNetMask) {
         u_int netaddr = 0xffffffffL;

         netaddr = input->ArgusLocalNet & input->ArgusNetMask;

         if (netaddr)
            if ((addr & netaddr) == netaddr)
               retn = ((addr & ~input->ArgusNetMask) == (INADDR_BROADCAST & ~input->ArgusNetMask)); 
      }
   }

   if (retn)
      return (retn);

   if (IN_MULTICAST(addr))
      return 1;

   if (INADDR_BROADCAST == addr)
      return 1;

   if (IN_CLASSA(addr))
      return ((addr & IN_CLASSA_HOST) == (INADDR_BROADCAST & IN_CLASSA_HOST)); 

   if (IN_CLASSB(addr))
      return ((addr & IN_CLASSB_HOST) == (INADDR_BROADCAST & IN_CLASSB_HOST)); 

   if (IN_CLASSC(addr))
      return ((addr & IN_CLASSC_HOST) == (INADDR_BROADCAST & IN_CLASSC_HOST)); 

#if defined(IN_CLASSD) && defined(IN_CLASSD_HOST)
   if (IN_CLASSD(addr))
      return ((addr & IN_CLASSD_HOST) == (INADDR_BROADCAST & IN_CLASSD_HOST)); 
#endif

   return 0;
}

int
ArgusProcessESPAvailability (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   return RA_SVCPASSED;
}

#define UDP_PORT_BOOTPS      67
#define UDP_PORT_BOOTPC      68

int
ArgusProcessUDPAvailability (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *)argus->dsrs[ARGUS_METRIC_INDEX];
   struct ArgusFlow *flow = (struct ArgusFlow *)argus->dsrs[ARGUS_FLOW_INDEX];
   int retn = RA_SVCPASSED;

   switch (flow->hdr.subtype & 0x3F) {
      case ARGUS_FLOW_CLASSIC5TUPLE: {
         switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
            case ARGUS_TYPE_IPV4: {
               if (!(ArgusTestMulticast(argus->input, flow->ip_flow.ip_dst))) {
                  switch (flow->ip_flow.dport) {
                      case UDP_PORT_BOOTPS:
                         if (flow->ip_flow.sport == UDP_PORT_BOOTPC)
                            return retn;
                      case UDP_PORT_BOOTPC:
                         if (flow->ip_flow.sport == UDP_PORT_BOOTPS)
                            return retn;
                  }

                  if (!metric->src.pkts || !metric->dst.pkts) {
                     retn = RA_SVCFAILED;
                  }
               }
               break;
            }

            case ARGUS_TYPE_IPV6: {
               break;
            }
        }
     }
  }



#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessUDPAvailability: returning %d \n", retn);
#endif

   return (retn);
}

int
ArgusProcessICMPAvailability (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *)argus->dsrs[ARGUS_METRIC_INDEX];
   struct ArgusFlow *flow = (struct ArgusFlow *)argus->dsrs[ARGUS_FLOW_INDEX];
   int retn = RA_SVCPASSED;
                                                                                                                                                                           
   switch (flow->hdr.subtype & 0x3F) {
      case ARGUS_FLOW_CLASSIC5TUPLE: {
         switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
            case ARGUS_TYPE_IPV4: {
               struct ArgusICMPFlow *icmp = (struct ArgusICMPFlow *) &flow->icmp_flow;
               switch (icmp->type) {
                  case ICMP_UNREACH:
                  case ICMP_REDIRECT:
                  case ICMP_ROUTERADVERT:
                  case ICMP_TIMXCEED:
                  case ICMP_PARAMETERPROB:
                     break;

                  default:
                     if (!metric->src.pkts || !metric->dst.pkts)
                        retn = RA_SVCFAILED;

                     if (parser->vflag && (metric->src.pkts != metric->dst.pkts))
                        retn = RA_SVCFAILED;
                     break;
               }
               break;
            }

            case ARGUS_TYPE_IPV6: {
//             struct ArgusICMPv6Flow *icmpv6 = (struct ArgusICMPv6Flow *) flow;
               break;
            }
        }
     }
  }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessICMPAvailability: returning %d \n", retn);
#endif

   return (retn);
}

int
ArgusProcessIPAvailability (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *)argus->dsrs[ARGUS_METRIC_INDEX];
   int retn = RA_SVCPASSED;

   if (metric->src.pkts && !metric->dst.pkts)
      retn = RA_SVCFAILED;

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessIPAvailability: returning %d \n", retn);
#endif

   return (retn);
}

int
ArgusProcessARPAvailability (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *)argus->dsrs[ARGUS_METRIC_INDEX];
   int retn = RA_SVCPASSED;

   if (!metric->src.pkts || !metric->dst.pkts)
      retn = RA_SVCFAILED;

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessARPAvailability: returning %d \n", retn);
#endif

   return (retn);
}

struct timeval *
RaGetStartTime (struct ArgusRecordStruct *argus, struct timeval *tvp)
{
   if ((argus != NULL)  && (tvp != NULL)) {
      double retn = ArgusFetchStartuSecTime(argus);
      tvp->tv_sec  = retn / 1000000;
      tvp->tv_usec = retn - (tvp->tv_sec * 1000000LL);
      return (tvp);
   } else
      return (NULL);
}

struct timeval *
RaGetLastTime (struct ArgusRecordStruct *argus, struct timeval *tvp)
{
   if ((argus != NULL)  && (tvp != NULL)) {
      double retn = ArgusFetchLastuSecTime(argus);
      tvp->tv_sec  = retn / 1000000;
      tvp->tv_usec = retn - (tvp->tv_sec * 1000000LL);
      return (tvp);
   } else
      return (NULL);
}

long long RaGetuSecMean (struct ArgusRecordStruct *);
long long RaGetuSecDeltaDuration (struct ArgusRecordStruct *);

long long
RaGetActiveDuration (struct ArgusRecordStruct *argus)
{
   long long retn = 0;

   return (retn);
}


long long
RaGetuSecMean (struct ArgusRecordStruct *argus)
{
   long long retn = 0;

   return (retn);
}


long long
RaGetuSecDeltaDuration (struct ArgusRecordStruct *argus)
{
   long long retn = 0;

   return (retn);
}

long long
RaGetuSecDuration (struct ArgusRecordStruct *argus)
{
   long long ltime = ArgusFetchLastuSecTime(argus); 
   long long stime = ArgusFetchStartuSecTime(argus);
   return (ltime - stime);
}

char RaUserDataStr[MAXBUFFERLEN];

char *
RaGetUserDataString (struct ArgusRecordStruct *argus)
{
   char *retn = RaUserDataStr;
   return (retn);
}

void
RaMatrixNormalizeEtherAddrs (struct ArgusRecordStruct *ns)
{
   struct ArgusMacStruct *m1 = NULL;

   if ((m1 = (struct ArgusMacStruct *) ns->dsrs[ARGUS_MAC_INDEX]) != NULL) {
      int i;

      switch (m1->hdr.subtype) {
         default:
         case ARGUS_TYPE_ETHER: {
            struct ether_header *e1 = &m1->mac.mac_union.ether.ehdr;
#if defined(ARGUS_SOLARIS)
            if ((e1->ether_shost.ether_addr_octet[0] == 0x33) &&
                (e1->ether_shost.ether_addr_octet[1] == 0x33)) {
               for (i = 2; i < 6; i++)
                  e1->ether_shost.ether_addr_octet[i] = 0x00;
            } else 
            if ((e1->ether_shost.ether_addr_octet[0] == 0x01) &&
                (e1->ether_shost.ether_addr_octet[1] == 0x00) &&
                (e1->ether_shost.ether_addr_octet[2] == 0x5e)) {
               for (i = 3; i < 6; i++)
                  e1->ether_shost.ether_addr_octet[i] = 0x00;
            }

            if ((e1->ether_dhost.ether_addr_octet[0] == 0x33) &&
                (e1->ether_dhost.ether_addr_octet[1] == 0x33)) {

               for (i = 2; i < 6; i++) 
                  e1->ether_dhost.ether_addr_octet[i] = 0x00;
            } else
            if ((e1->ether_dhost.ether_addr_octet[0] == 0x01) &&
                (e1->ether_dhost.ether_addr_octet[1] == 0x00) &&
                (e1->ether_dhost.ether_addr_octet[2] == 0x5e)) {
               for (i = 3; i < 6; i++)
                  e1->ether_dhost.ether_addr_octet[i] = 0x00;
            } 
#else
            if ((e1->ether_shost[0] == 0x33) && (e1->ether_shost[1] == 0x33)) {
               for (i = 2; i < 6; i++)
                  e1->ether_shost[i] = 0x00;
            } else {
               if ((e1->ether_shost[0] == 0x01) && (e1->ether_shost[1] == 0x00) && (e1->ether_shost[2] == 0x5e)) {
                  for (i = 3; i < 6; i++)
                     e1->ether_shost[i] = 0x00;
               }
            }

            if ((e1->ether_dhost[0] == 0x33) && (e1->ether_dhost[1] == 0x33)) {
               for (i = 2; i < 6; i++)
                  e1->ether_dhost[i] = 0x00;
            } else {
               if ((e1->ether_dhost[0] == 0x01) && (e1->ether_dhost[1] == 0x00) && (e1->ether_dhost[2] == 0x5e)) {
                  for (i = 3; i < 6; i++)
                     e1->ether_dhost[i] = 0x00;
               }
            }
#endif
            break;
         }
      }
   }
}

struct RaPolicyStruct *
RaFlowModelOverRides(struct ArgusAggregatorStruct *na, struct ArgusRecordStruct *ns)
{
   struct RaPolicyStruct *retn = NULL;

   return (retn);
}


void
ArgusGenerateNewFlow(struct ArgusAggregatorStruct *na, struct ArgusRecordStruct *ns)
{
   struct ArgusFlow tflow, *flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];
   int i = 0, x = 0, len = 0;

   bzero ((char *)&tflow, sizeof(tflow));

   na->ArgusMaskDefs = ArgusSelectMaskDefs(ns);

   if (na->mask && (flow != NULL)) {
      len = flow->hdr.argus_dsrvl8.len * 4;

      if (na->pres == NULL)
         bcopy ((char *)&flow->hdr, (char *)&tflow.hdr, sizeof(flow->hdr));
      else
         bcopy ((char *)&flow->hdr, (char *)&tflow.hdr, len);

      if (!(na->mask & (ARGUS_MASK_SADDR_INDEX | ARGUS_MASK_DADDR_INDEX | ARGUS_MASK_PROTO_INDEX | ARGUS_MASK_SPORT_INDEX | ARGUS_MASK_DPORT_INDEX))) {
         tflow.hdr.subtype &= 0x3F;
         tflow.hdr.argus_dsrvl8.qual &= 0x1F;
      }
      for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
         if (na->mask < (0x01LL << i))
            break;
         if (na->mask & (0x01LL << i)) {
            switch(i) {
               case ARGUS_MASK_SADDR:
                  switch(flow->hdr.subtype & 0x3F) {
                     case ARGUS_FLOW_LAYER_3_MATRIX:
                     case ARGUS_FLOW_CLASSIC5TUPLE:  {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: {
                              if (sizeof(tflow.ip_flow) > len)
                                 ArgusLog (LOG_ERR, "ArgusGenerateNewFlow: buf %d not big enough %d\n", len, sizeof(tflow.ip_flow));

                              tflow.ip_flow.ip_src = flow->ip_flow.ip_src;

                              if (!(na->mask & (ARGUS_MASK_PROTO_INDEX | ARGUS_MASK_SPORT_INDEX | ARGUS_MASK_DPORT_INDEX))) {
                                 struct ArgusIPAttrStruct *attr = (void *)ns->dsrs[ARGUS_IPATTR_INDEX];
                                 if ((attr != NULL) && ((attr->hdr.argus_dsrvl8.qual &
                                                   (ARGUS_IPATTR_SRC_FRAGMENTS | ARGUS_IPATTR_DST_FRAGMENTS)) ||
                                                   (flow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT))) {
                                    tflow.hdr.subtype &= 0x3F;
                                    tflow.hdr.argus_dsrvl8.qual &= 0x1F;
                                    tflow.ip_flow.smask = 32;
                                 } else {
                                    tflow.ip_flow.smask  = flow->ip_flow.smask;
                                 }
                              } else {
                                 tflow.ip_flow.smask  = flow->ip_flow.smask;
                              }

                              if ((na->saddrlen > 0) && (na->saddrlen < tflow.ip_flow.smask)) {
                                 tflow.ip_flow.ip_src &= na->smask.addr_un.ipv4;
                                 tflow.ip_flow.smask = na->saddrlen;
                                 tflow.hdr.argus_dsrvl8.qual |= ARGUS_MASKLEN;
                              }
                              break;
                           }

                           case ARGUS_TYPE_IPV6:  {
                              if (sizeof(tflow.ipv6_flow) > len)
                                 ArgusLog (LOG_ERR, "ArgusGenerateNewFlow: buf %d not big enough %d\n", len, sizeof(tflow.ipv6_flow));
                              for (x = 0; x < 4; x++)
                                 tflow.ipv6_flow.ip_src[x] = flow->ipv6_flow.ip_src[x];
                              
                              tflow.ipv6_flow.smask  = flow->ipv6_flow.smask;
                              if ((na->saddrlen > 0) && (na->saddrlen < tflow.ipv6_flow.smask)) {
                                 for (x = 0; x < 4; x++)
                                    tflow.ipv6_flow.ip_src[x] &= ntohl(na->smask.addr_un.ipv6[x]);
                                 tflow.ipv6_flow.smask = na->saddrlen;
                              }
                              break;
                           }

                           case ARGUS_TYPE_RARP: {
                              if (sizeof(tflow.rarp_flow) > len)
                                 ArgusLog (LOG_ERR, "ArgusGenerateNewFlow: buf %d not big enough %d\n", len, sizeof(tflow.rarp_flow));
                              bcopy (&flow->rarp_flow.shaddr, &tflow.rarp_flow.shaddr, tflow.rarp_flow.hln);
                              break;
                           }

                           case ARGUS_TYPE_ETHER: {
                              if (sizeof(tflow.mac_flow) > len)
                                 ArgusLog (LOG_ERR, "ArgusGenerateNewFlow: buf %d not big enough %d\n", len, sizeof(tflow.mac_flow));
                              bcopy (&flow->mac_flow.mac_union.ether.ehdr.ether_shost,
                                     &tflow.mac_flow.mac_union.ether.ehdr.ether_shost,
                                     sizeof(tflow.mac_flow.mac_union.ether.ehdr.ether_shost));
                              break;
                           }

                           case ARGUS_TYPE_WLAN: {
                              if (sizeof(tflow.wlan_flow) > len)
                                 ArgusLog (LOG_ERR, "ArgusGenerateNewFlow: buf %d not big enough %d\n", len, sizeof(tflow.wlan_flow));
                              bcopy (&flow->wlan_flow.shost, &tflow.wlan_flow.shost, sizeof(tflow.wlan_flow.shost));
                              break;
                           }

                           case ARGUS_TYPE_ISIS: {
                              struct ArgusIsisFlow *isis = (struct ArgusIsisFlow *) &flow->isis_flow;
                              bcopy (flow->isis_flow.esrc, tflow.isis_flow.esrc, ETHER_ADDR_LEN);
                              switch (isis->pdu_type) {
                                 case L1_LAN_IIH:
                                 case L2_LAN_IIH:
                                    bcopy (flow->isis_flow.isis_un.hello.srcid,
                                           tflow.isis_flow.isis_un.hello.srcid, SYSTEM_ID_LEN);
                                    break;
                                 case L1_CSNP:
                                 case L2_CSNP:
                                    bcopy (flow->isis_flow.isis_un.csnp.srcid,
                                           tflow.isis_flow.isis_un.csnp.srcid, NODE_ID_LEN);
                                    break;
                                 case L1_PSNP:
                                 case L2_PSNP:
                                    bcopy (flow->isis_flow.isis_un.psnp.srcid,
                                           tflow.isis_flow.isis_un.psnp.srcid, NODE_ID_LEN);
                                    break;

                                 case L1_LSP:
                                 case L2_LSP:
                                    bcopy (flow->isis_flow.isis_un.lsp.lspid,
                                           tflow.isis_flow.isis_un.lsp.lspid, LSP_ID_LEN);
                                    break;
                              }
                              break;
                           }
                        }
                        break;
                     }
                     case ARGUS_FLOW_ARP:  {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_RARP: {
                              bcopy (&flow->rarp_flow.shaddr, &tflow.rarp_flow.shaddr, tflow.rarp_flow.hln);
                              break;
                           }

                           case ARGUS_TYPE_ARP: {
                              tflow.arp_flow.pln = flow->arp_flow.pln;
                              tflow.arp_flow.arp_spa = flow->arp_flow.arp_spa;
                              break;
                           }
                        }
                        break;
                     }
                  }
                  break;

               case ARGUS_MASK_DADDR:
                  switch(flow->hdr.subtype & 0x3F) {
                     case ARGUS_FLOW_LAYER_3_MATRIX:
                     case ARGUS_FLOW_CLASSIC5TUPLE: {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4:
                              tflow.ip_flow.ip_dst = flow->ip_flow.ip_dst;

                              if (!(na->mask & (ARGUS_MASK_PROTO_INDEX | ARGUS_MASK_SPORT_INDEX | ARGUS_MASK_DPORT_INDEX))) {
                                 if (flow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT) {
                                    tflow.hdr.subtype &= 0x3F;
                                    tflow.hdr.argus_dsrvl8.qual &= 0x1F;
                                    tflow.ip_flow.dmask = 32;
                                 } else {
                                    tflow.ip_flow.dmask  = flow->ip_flow.dmask;
                                 }
                              } else {
                                 tflow.ip_flow.dmask  = flow->ip_flow.dmask;
                              }

                              if ((na->daddrlen > 0) && (na->daddrlen < tflow.ip_flow.dmask)) {
                                 tflow.ip_flow.ip_dst &= na->dmask.addr_un.ipv4;
                                 tflow.ip_flow.dmask = na->daddrlen;
                                 tflow.hdr.argus_dsrvl8.qual |= ARGUS_MASKLEN;
                              }

                              break;

                           case ARGUS_TYPE_IPV6:
                              if (sizeof(tflow.ipv6_flow) > len)
                                 ArgusLog (LOG_ERR, "ArgusGenerateNewFlow: buf %d not big enough %d\n", len, sizeof(tflow.ipv6_flow));
                              for (x = 0; x < 4; x++)
                                 tflow.ipv6_flow.ip_dst[x] = flow->ipv6_flow.ip_dst[x];

                              tflow.ipv6_flow.dmask  = flow->ipv6_flow.dmask;
                              if ((na->daddrlen > 0) && (na->daddrlen < tflow.ipv6_flow.dmask)) {
                                 for (x = 0; x < 4; x++)
                                    tflow.ipv6_flow.ip_dst[x] &= ntohl(na->dmask.addr_un.ipv6[x]);
                                 tflow.ipv6_flow.dmask = na->daddrlen;
                              }
                              break;

                           case ARGUS_TYPE_RARP:
                              bcopy (&flow->rarp_flow.dhaddr, &tflow.rarp_flow.dhaddr, tflow.rarp_flow.hln);
                              break;
                           case ARGUS_TYPE_ARP: 
                              tflow.arp_flow.arp_tpa = flow->arp_flow.arp_tpa;
                              break;

                           case ARGUS_TYPE_ETHER:
                              bcopy (&flow->mac_flow.mac_union.ether.ehdr.ether_dhost,
                                     &tflow.mac_flow.mac_union.ether.ehdr.ether_dhost,
                                     sizeof(tflow.mac_flow.mac_union.ether.ehdr.ether_dhost));
                              break;

                           case ARGUS_TYPE_WLAN: {
                              if (sizeof(tflow.wlan_flow) > len)
                                 ArgusLog (LOG_ERR, "ArgusGenerateNewFlow: buf %d not big enough %d\n", len, sizeof(tflow.wlan_flow));
                              bcopy (&flow->wlan_flow.dhost, &tflow.wlan_flow.dhost, sizeof(tflow.wlan_flow.dhost));
                              break;
                           }

                           case ARGUS_TYPE_ISIS: {
                              struct ArgusIsisFlow *isis = (struct ArgusIsisFlow *) &flow->isis_flow;
                              bcopy (flow->isis_flow.edst, tflow.isis_flow.edst, ETHER_ADDR_LEN);
                              switch (isis->pdu_type) {
                                 case L1_LAN_IIH:
                                 case L2_LAN_IIH:
                                    bcopy (flow->isis_flow.isis_un.hello.lanid,
                                           tflow.isis_flow.isis_un.hello.lanid, NODE_ID_LEN);
                                    break;

                                 case L1_CSNP:
                                 case L2_CSNP:
                                 case L1_PSNP:
                                 case L2_PSNP:
                                    break;

                                 case L1_LSP:
                                 case L2_LSP:
                                    tflow.isis_flow.isis_un.lsp.seqnum = flow->isis_flow.isis_un.lsp.seqnum;
                                    break;
                              }
                              break;
                           }
                        }
                        break;
                     }

                     case ARGUS_FLOW_ARP:  {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_RARP: {
                              bcopy (&flow->rarp_flow.dhaddr, &tflow.rarp_flow.dhaddr, tflow.rarp_flow.hln);
                              break;
                           }

                           case ARGUS_TYPE_ARP: {
                              tflow.arp_flow.arp_tpa = flow->arp_flow.arp_tpa;
                              break;
                           }
                        }
                        break;

                     }
                  }
                  break;

               case ARGUS_MASK_PROTO:
                  switch(flow->hdr.subtype & 0x3F) {
                     case ARGUS_FLOW_CLASSIC5TUPLE: {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: 
                              tflow.ip_flow.ip_p   = flow->ip_flow.ip_p; 
                              break;
                           case ARGUS_TYPE_IPV6: {
                              tflow.ipv6_flow.ip_p = flow->ipv6_flow.ip_p;
                              break;
                           }
                           case ARGUS_TYPE_ETHER:
                              tflow.mac_flow.mac_union.ether.ehdr.ether_type = flow->mac_flow.mac_union.ether.ehdr.ether_type;
                              break;

                           case ARGUS_TYPE_ISIS:
                              tflow.isis_flow.pdu_type = flow->isis_flow.pdu_type;
                              break;
                        }
                        break;
                     }
                     case ARGUS_FLOW_ARP:  {
                        tflow.arp_flow.pro = flow->arp_flow.pro;
                        break;
                     }
                     break;
                  }
                  break;

               case ARGUS_MASK_SPORT:
                  switch(flow->hdr.subtype & 0x3F) {
                     case ARGUS_FLOW_CLASSIC5TUPLE: {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: 
                              switch (flow->ip_flow.ip_p) {
                                 case IPPROTO_ESP: {
                                    break;
                                 }
                                 default:
                                    tflow.ip_flow.sport = flow->ip_flow.sport;
                                    break;
                              }
                              break;
                           case ARGUS_TYPE_IPV6: tflow.ipv6_flow.sport = flow->ipv6_flow.sport; break;
                           case ARGUS_TYPE_ETHER:
                              tflow.mac_flow.mac_union.ether.ssap = flow->mac_flow.mac_union.ether.ssap;
                              break;

                           case ARGUS_TYPE_WLAN:
                              bcopy(flow->wlan_flow.ssid, tflow.wlan_flow.ssid, sizeof(flow->wlan_flow.ssid));
                              break;

                           case ARGUS_TYPE_ISIS:
                              tflow.isis_flow.chksum = flow->isis_flow.chksum;
                              break;
                        }
                        break;
                     }
                     case ARGUS_FLOW_ARP:  {
                        break;
                     }
                     break;
                  }
                  break;

               case ARGUS_MASK_DPORT:
                  switch(flow->hdr.subtype & 0x3F) {
                     case ARGUS_FLOW_CLASSIC5TUPLE: {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: 
                              switch (flow->ip_flow.ip_p) {
                                 case IPPROTO_ESP: {
                                    tflow.esp_flow.spi = flow->esp_flow.spi;
                                    break;
                                 }
                                 default:
                                    tflow.ip_flow.dport = flow->ip_flow.dport;
                                    break;
                              }
                              break;

                           case ARGUS_TYPE_IPV6: tflow.ipv6_flow.dport = flow->ipv6_flow.dport; break;
                           case ARGUS_TYPE_ETHER:
                              tflow.mac_flow.mac_union.ether.dsap = flow->mac_flow.mac_union.ether.dsap;
                              break;

                           case ARGUS_TYPE_WLAN:
                              bcopy (flow->wlan_flow.bssid, tflow.wlan_flow.bssid, sizeof(flow->wlan_flow.bssid));
                              break;
                        }
                        break;
                     }
                     case ARGUS_FLOW_ARP:  {
                        int hln = flow->arp_flow.hln;
                        
                        if (hln > sizeof(flow->arp_flow.haddr))
                           hln = sizeof(flow->arp_flow.haddr);
                        tflow.arp_flow.hln = hln;
                        bcopy((char *)&flow->arp_flow.haddr, (char *)&tflow.arp_flow.haddr, hln);
                        break;
                     }
                     break;
                  }
                  break;

               case ARGUS_MASK_SRCID:
               case ARGUS_MASK_SRCID_INF:
                  break;

               default:
                  break;
            }
         }
      }

      bcopy ((char *)flow, (char *)&na->fstruct, len);
      bcopy ((char *)&tflow, (char *)flow, len);
   }
}


//  ArgusMergeRecords
//     This routine takes 2 ArgusRecordStructs and merges each DSR,
//     leaving the resultant in ns1.
//
//  ArgusMergeAddress
//     Given two non-equal addresses, ArgusMergeAddress() will do a MSB
//     run length compare, leaving the result in the first address passed.
//     If either the addrs are the broadcast address (0xFFFFFFFF) the
//     the result will be the other address.
//
//     The masklen is the length of the CIDR mask, which is used to limit the
//     MSB test, and will be updated with the new CIDR mask length.


unsigned int
ArgusMergeAddress(unsigned int *a1, unsigned int *a2, int type, int dir, unsigned char *masklen)
{
   unsigned int retn = 0;

   switch (type) {
      case ARGUS_TYPE_IPV4: {
         if (*a1 != *a2) {
            unsigned int i = 32, value = 0, ind;
            ind = 0x80000000;

            while (ind && ((*a1 & ind) == (*a2 & ind)) && (i > (32 - *masklen))) {
               value |= (*a1 & ind);
               ind >>= 1;
               i--;
            }
            *a1 = value;
            *masklen = (32 - i);
         }
         break;
      }

      case ARGUS_TYPE_IPV6: {
         int z;
         for (z = 0; z < 4; z++) {
            if (a1[z] != a2[z]) {
               unsigned int i = 32, value = 0, ind;
               unsigned int na1 = ntohl(a1[z]);
               unsigned int na2 = ntohl(a2[z]);
               ind = 0x80000000;

               while (ind && ((na1 & ind) == (na2 & ind))) {
                  value |= (na1 & ind);
                  ind >>= 1;
                  i--;
               }
               *masklen = (z * 32) + (32 - i);
               a1[z] = htonl(value);
               while ((z + 1) < 4) {
                  a1[z + 1] = 0;
                  z++;
               }
               break;
            }
         }
         break;
      }

      case ARGUS_TYPE_WLAN:
      case ARGUS_TYPE_ETHER: {
         break;
      }

      case ARGUS_TYPE_RARP:
      case ARGUS_TYPE_ARP: {
         break;
      }
   }

   switch (dir) {
      case ARGUS_SRC:
      case ARGUS_DST:
         break;
   }

   return (retn);
}


void
ArgusMergeRecords (const struct ArgusAggregatorStruct * const na,
                   struct ArgusRecordStruct *ns1, struct ArgusRecordStruct *ns2)
{
   struct ArgusAgrStruct *agr = NULL;
   double seconds;
   int i;

   if (ns1 && ns2) {
      if ((ns1->hdr.type & 0xF0) == (ns2->hdr.type & 0xF0)) {
         switch (ns1->hdr.type & 0xF0) {
            case ARGUS_MAR: {
               struct ArgusMarStruct *man1 = (struct ArgusMarStruct *) &((struct ArgusRecord *) ns1->dsrs[0])->ar_un.mar;
               struct ArgusMarStruct *man2 = (struct ArgusMarStruct *) &((struct ArgusRecord *) ns2->dsrs[0])->ar_un.mar;

               if ((ns1->hdr.cause & 0xF0) == ARGUS_START) {
               } else
               if ((ns1->hdr.cause & 0xF0) == ARGUS_STATUS) {
                  double stime1 = ArgusFetchStartuSecTime(ns1);
                  double stime2 = ArgusFetchStartuSecTime(ns2);
                  double ltime1 = ArgusFetchLastuSecTime(ns1);
                  double ltime2 = ArgusFetchLastuSecTime(ns2);

                  if ((stime2 < stime1) || (stime1 == 0)) {
                     man1->startime          = man2->startime;
                     man1->nextMrSequenceNum = man2->nextMrSequenceNum;
                     man1->interfaceStatus   = man2->interfaceStatus;
                     man1->drift             = man2->drift;
                     man1->clients           = man2->clients;
                  }

                  if ((ltime2 > ltime1) || (ltime1 == 0))
                     man1->now = man2->now;

                  man1->pktsRcvd  += man2->pktsRcvd;
                  man1->bytesRcvd += man2->bytesRcvd;
                  man1->drift      = man2->drift;
                  man1->records   += man2->records;
                  man1->queue      = man2->queue;
                  man1->output    += man2->output;
                  man1->flows     += man2->flows;
                  man1->dropped   += man2->dropped;
                  man1->bytes     += man2->bytes;
                  man1->bufs       = man2->bufs;
                  man1->suserlen   = man2->suserlen;
                  man1->duserlen   = man2->duserlen;

                  man1->status |= ARGUS_RECORD_MODIFIED;
               }
               break;
            }

            case ARGUS_NETFLOW:
            case ARGUS_AFLOW:
            case ARGUS_FAR: {
               struct ArgusTimeObject *ns1time = (void *)ns1->dsrs[ARGUS_TIME_INDEX];
               struct ArgusTimeObject *ns2time = (void *)ns2->dsrs[ARGUS_TIME_INDEX];
               struct ArgusMetricStruct *ns1metric = (void *)ns1->dsrs[ARGUS_METRIC_INDEX];
               struct ArgusMetricStruct *ns2metric = (void *)ns2->dsrs[ARGUS_METRIC_INDEX];

               double deltaSrcFlowTime = 0.0;
               double deltaDstFlowTime = 0.0;

               if ((ns1time && ns2time) && (ns1metric && ns2metric)) {
                  double senst1 = (ns1time->src.end.tv_sec * 1000000LL) + ns1time->src.end.tv_usec;
                  double denst1 = (ns1time->dst.end.tv_sec * 1000000LL) + ns1time->dst.end.tv_usec;

                  double ssnst2 = (ns2time->src.start.tv_sec * 1000000LL) + ns2time->src.start.tv_usec;
                  double dsnst2 = (ns2time->dst.start.tv_sec * 1000000LL) + ns2time->dst.start.tv_usec;

                  double slstime = (ns1->lastSrcStartTime.tv_sec * 1000000LL) + ns1->lastSrcStartTime.tv_usec;

                  if (ns1metric->src.pkts && ns2metric->src.pkts) {
                     if (slstime) {
                     } else {
                     }
                     deltaSrcFlowTime = fabs(ssnst2 - senst1)/1000000.0;
                  }

                  if (ns1metric->dst.pkts && ns2metric->dst.pkts) {
                     deltaDstFlowTime = fabs(dsnst2 - denst1)/1000000.0;
                  }
               }

               ns1->status &= ~ARGUS_RECORD_WRITTEN; 
           
               if ((agr = (struct ArgusAgrStruct *) ns1->dsrs[ARGUS_AGR_INDEX]) == NULL) {
                  struct ArgusMetricStruct *metric = (void *)ns1->dsrs[ARGUS_METRIC_INDEX];
                  if ((metric != NULL) && ((metric->src.pkts + metric->dst.pkts) > 0)) {
                     double value = na->RaMetricFetchAlgorithm(ns1);

                     if ((agr = ArgusCalloc(1, sizeof(*agr))) == NULL)
                        ArgusLog (LOG_ERR, "ArgusMergeRecords: ArgusCalloc error: %s", strerror(errno));

                     agr->hdr.type              = ARGUS_AGR_DSR;
                     agr->hdr.subtype           = na->ArgusMetricIndex;
                     agr->hdr.argus_dsrvl8.qual = 0x01;
                     agr->hdr.argus_dsrvl8.len  = (sizeof(*agr) + 3)/4;
                     agr->count                 = 1;
                     agr->act.maxval            = value;
                     agr->act.minval            = value;
                     agr->act.meanval           = value;
                     agr->act.n                 = 1;
                     bzero ((char *)&agr->idle, sizeof(agr->idle));
                     agr->idle.minval           = 1000000000.0;

                     ns1->dsrs[ARGUS_AGR_INDEX] = (struct ArgusDSRHeader *) agr;
                     ns1->dsrindex |= (0x01 << ARGUS_AGR_INDEX);
                  }
               }

               for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
                  switch (i) {

// Merging Flow records is a matter of testing each field and
// transforming values that are not equal to either run length
// and'ing or zeroing out the value.  When a value is zero'ed
// we need to indicate it in the status field of the flow
// descriptor so that values resulting from merging are not
// confused with values actually off the wire.
//
// run length and'ing is an attempt to preserve CIDR addresses.
// any other value should be either preserved or invalidated.

                     case ARGUS_FLOW_INDEX: {
                        struct ArgusFlow *f1 = (struct ArgusFlow *) ns1->dsrs[ARGUS_FLOW_INDEX];
                        struct ArgusFlow *f2 = (struct ArgusFlow *) ns2->dsrs[ARGUS_FLOW_INDEX];

                        if (f1 && f2) {
                           unsigned char masklen = 0;
                           if ((f1->hdr.subtype & 0x3F) == (f2->hdr.subtype & 0x3F)) {
                              char f1qual = f1->hdr.argus_dsrvl8.qual & 0x1F;
                              char f2qual = f2->hdr.argus_dsrvl8.qual & 0x1F;

                              if (f1->hdr.subtype != f2->hdr.subtype) {
                                 if ((f1->hdr.subtype & ARGUS_REVERSE) || (f2->hdr.subtype & ARGUS_REVERSE)) {
                                    long long v1 = ArgusFetchStartTime(ns1);
                                    long long v2 = ArgusFetchStartTime(ns2);
                                    if (v1 > v2) {
                                       f1->hdr.subtype = f2->hdr.subtype;
                                    }
                                 }
                              }

                              switch (f1->hdr.subtype & 0x3F) {
                                 case ARGUS_FLOW_LAYER_3_MATRIX: {
                                    if (f1qual == f2qual) {
                                       switch (f1qual) {
                                          case ARGUS_TYPE_IPV4: {
                                             masklen = (f1->ip_flow.smask > f2->ip_flow.smask) ? f2->ip_flow.smask : f1->ip_flow.smask;
                                             f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->ip_flow.ip_src, &f2->ip_flow.ip_src, ARGUS_TYPE_IPV4, ARGUS_SRC, &masklen);
                                             f1->ip_flow.smask = masklen;
                                             masklen = (f1->ip_flow.dmask > f2->ip_flow.dmask) ? f2->ip_flow.dmask : f1->ip_flow.dmask;
                                             f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->ip_flow.ip_dst, &f2->ip_flow.ip_dst, ARGUS_TYPE_IPV4, ARGUS_DST, &masklen);
                                             f1->ip_flow.dmask = masklen;
                                             f1->hdr.argus_dsrvl8.qual |= ARGUS_MASKLEN;
                                             break;

                                          case ARGUS_TYPE_IPV6:  
                                             masklen = (f1->ipv6_flow.smask > f2->ipv6_flow.smask) ? f2->ipv6_flow.smask : f1->ipv6_flow.smask;
                                             f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->ipv6_flow.ip_src[0], &f2->ipv6_flow.ip_src[0], ARGUS_TYPE_IPV6, ARGUS_SRC, &masklen);
                                             f1->ip_flow.smask = masklen;
                                             masklen = (f1->ipv6_flow.dmask > f2->ipv6_flow.dmask) ? f2->ipv6_flow.dmask : f1->ipv6_flow.dmask;
                                             f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->ipv6_flow.ip_dst[0], &f2->ipv6_flow.ip_dst[0], ARGUS_TYPE_IPV6, ARGUS_DST, &masklen);
                                             f1->ip_flow.dmask = masklen;
                                             f1->hdr.argus_dsrvl8.qual |= ARGUS_MASKLEN;
                                             break;

                                          }
                                       }
                                    }
                                    break;
                                 }

                                 case ARGUS_FLOW_CLASSIC5TUPLE: {
                                       switch (f1qual) {
                                          case ARGUS_TYPE_IPV4:
                                             if (f1qual == f2qual) {
                                                masklen = (f1->ip_flow.smask > f2->ip_flow.smask) ? f2->ip_flow.smask : f1->ip_flow.smask;
                                                ArgusMergeAddress(&f1->ip_flow.ip_src, &f2->ip_flow.ip_src, ARGUS_TYPE_IPV4, ARGUS_SRC, &masklen);
                                                f1->ip_flow.smask = masklen;

                                                masklen = (f1->ip_flow.dmask > f2->ip_flow.dmask) ? f2->ip_flow.dmask : f1->ip_flow.dmask;
                                                ArgusMergeAddress(&f1->ip_flow.ip_dst, &f2->ip_flow.ip_dst, ARGUS_TYPE_IPV4, ARGUS_DST, &masklen);
                                                f1->ip_flow.dmask = masklen;

                                                f1->hdr.argus_dsrvl8.qual |= ARGUS_MASKLEN;

                                                if (f1->ip_flow.ip_p  != f2->ip_flow.ip_p)
                                                   f1->ip_flow.ip_p = 0;
                                                else {
                                                   switch (f1->ip_flow.ip_p) {
                                                      case IPPROTO_ESP: {
                                                         if (f1->esp_flow.spi != f2->esp_flow.spi)
                                                            f1->esp_flow.spi = 0;
                                                         break;
                                                      }

                                                      default: {
                                                         if (f1->ip_flow.sport != f2->ip_flow.sport)
                                                            f1->ip_flow.sport = 0;
                                                         if (f1->ip_flow.dport != f2->ip_flow.dport)
                                                            f1->ip_flow.dport = 0;
                                                         break;
                                                      }
                                                   }
                                                }

                                             } else {
                                                f1->ip_flow.ip_src = 0;
                                                f1->ip_flow.ip_dst = 0;
                                             
                                                switch (f2qual) {
                                                   case ARGUS_TYPE_IPV6:
                                                      if (f1->ip_flow.ip_p  != f2->ipv6_flow.ip_p)
                                                         f1->ip_flow.ip_p = 0;
                                                      if (f1->ip_flow.sport != f2->ipv6_flow.sport)
                                                         f1->ip_flow.sport = 0;
                                                      if (f1->ip_flow.dport != f2->ipv6_flow.dport)
                                                         f1->ip_flow.dport = 0;
                                                      break;
                       
                                                   default:
                                                      f1->ip_flow.ip_p = 0;
                                                      f1->ip_flow.sport = 0;
                                                      f1->ip_flow.dport = 0;
                                                      break;
                                                }
                                             }
                                             break;

                                          case ARGUS_TYPE_IPV6:  
                                             if (f1qual == f2qual) {
                                                masklen = (f1->ipv6_flow.smask > f2->ipv6_flow.smask) ? f2->ipv6_flow.smask : f1->ipv6_flow.smask;
                                                f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->ipv6_flow.ip_src[0], &f2->ipv6_flow.ip_src[0], ARGUS_TYPE_IPV6, ARGUS_SRC, &masklen);
                                                f1->ipv6_flow.smask = masklen;
                                                masklen = (f1->ipv6_flow.dmask > f2->ipv6_flow.dmask) ? f2->ipv6_flow.dmask : f1->ipv6_flow.dmask;
                                                f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->ipv6_flow.ip_dst[0], &f2->ipv6_flow.ip_dst[0], ARGUS_TYPE_IPV6, ARGUS_DST, &masklen);
                                                f1->ipv6_flow.dmask = masklen;

                                                f1->hdr.argus_dsrvl8.qual |= ARGUS_MASKLEN;

                                                if (f1->ipv6_flow.ip_p  != f2->ipv6_flow.ip_p)  f1->ipv6_flow.ip_p = 0;
                                                if (f1->ipv6_flow.sport != f2->ipv6_flow.sport) f1->ipv6_flow.sport = 0;
                                                if (f1->ipv6_flow.dport != f2->ipv6_flow.dport) f1->ipv6_flow.dport = 0;

                                             } else {
                                                bzero ((char *)&f1->ipv6_flow.ip_src[0], sizeof(f1->ipv6_flow.ip_src));
                                                bzero ((char *)&f1->ipv6_flow.ip_dst[0], sizeof(f1->ipv6_flow.ip_dst));
                                                if (f1->ipv6_flow.ip_p  != f2->ip_flow.ip_p)  f1->ipv6_flow.ip_p = 0;
                                                if (f1->ipv6_flow.sport != f2->ip_flow.sport) f1->ipv6_flow.sport = 0;
                                                if (f1->ipv6_flow.dport != f2->ip_flow.dport) f1->ipv6_flow.dport = 0;
                                             }
                                             break;

                                        case ARGUS_TYPE_RARP:
                                           if (bcmp(&f1->rarp_flow.shaddr, &f2->rarp_flow.shaddr, 6))
                                              bzero(&f1->rarp_flow.shaddr, 6);
                                           if (bcmp(&f1->rarp_flow.dhaddr, &f2->rarp_flow.dhaddr, 6))
                                              bzero(&f1->rarp_flow.dhaddr, 6);
                                           break;
                                        case ARGUS_TYPE_ARP:
                                           f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->arp_flow.arp_spa, &f2->arp_flow.arp_spa, ARGUS_TYPE_ARP, ARGUS_SRC, &masklen);
                                           f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->arp_flow.arp_tpa, &f2->arp_flow.arp_tpa, ARGUS_TYPE_ARP, ARGUS_DST, &masklen);
                                           break;
                                    }
                                    break;
                                 }

                                 case ARGUS_FLOW_ARP: {
                                    switch (f1qual) {
                                        case ARGUS_TYPE_RARP: {
                                           if (bcmp(&f1->rarp_flow.shaddr, &f2->rarp_flow.shaddr, 6))
                                                   bzero(&f1->rarp_flow.shaddr, 6);
                                           if (bcmp(&f1->rarp_flow.dhaddr, &f2->rarp_flow.dhaddr, 6))
                                                   bzero(&f1->rarp_flow.dhaddr, 6);

                                           if (f1->arp_flow.pln == 4) {
                                              ArgusMergeAddress(&f1->arp_flow.arp_tpa, &f2->arp_flow.arp_tpa, ARGUS_TYPE_IPV4, ARGUS_DST, &masklen);
                                           }
                                           break;
                                       }

                                        case ARGUS_TYPE_ARP: {
                                           if (bcmp(&f1->arp_flow.haddr, &f2->arp_flow.haddr, 6))
                                              bzero(&f1->arp_flow.haddr, 6);

                                           if (f1->arp_flow.pln == 4) {
                                              ArgusMergeAddress(&f1->arp_flow.arp_spa, &f2->arp_flow.arp_spa, ARGUS_TYPE_IPV4, ARGUS_SRC, &masklen);
                                              ArgusMergeAddress(&f1->arp_flow.arp_tpa, &f2->arp_flow.arp_tpa, ARGUS_TYPE_IPV4, ARGUS_DST, &masklen);
                                           }
                                           break;
                                       }
                                    }
                                    break;
                                 }
                              }
                           }
                        }
                     }
                     break;

// Merging Transport objects involves simply checking that the source
// id and seqnum are the same, and if not, removing the fields until
// we're actually removing the struct.
//
// struct ArgusTransportStruct {
//    struct ArgusDSRHeader hdr;
//    struct ArgusAddrStruct srcid;
//    unsigned int seqnum;
// };

                     case ARGUS_TRANSPORT_INDEX: {
                        struct ArgusTransportStruct *t1 = (struct ArgusTransportStruct *) ns1->dsrs[ARGUS_TRANSPORT_INDEX];
                        struct ArgusTransportStruct *t2 = (struct ArgusTransportStruct *) ns2->dsrs[ARGUS_TRANSPORT_INDEX];
                        int match = 0;

                        if (t1 && t2) {
                           if ((t1->hdr.subtype & ARGUS_SRCID) && (t2->hdr.subtype & ARGUS_SRCID)) {
                              switch (t1->hdr.argus_dsrvl8.qual & ~ARGUS_TYPE_INTERFACE) {
                                 case ARGUS_TYPE_INT:
                                 case ARGUS_TYPE_IPV4:
                                 case ARGUS_TYPE_STRING:
                                    if (t1->srcid.a_un.ipv4 == t2->srcid.a_un.ipv4)
                                       match = 1;
                                    break;

                                 case ARGUS_TYPE_IPV6:
                                 case ARGUS_TYPE_UUID: {
                                    int x;
                                    match = 1;
                                    for (x = 0; x < 16; x++) {
                                       if (t1->srcid.a_un.uuid[x] != t2->srcid.a_un.uuid[x]) {
                                          match = 1;
                                          break;
                                       }
                                    }
                                    break;
                                 }

                                 case ARGUS_TYPE_ETHER:
                                    break;
                              }
                              if (match && (t1->hdr.argus_dsrvl8.qual & ARGUS_TYPE_INTERFACE)) {
                                 if (bcmp(t1->srcid.inf, t2->srcid.inf, 4))
                                    bzero(t1->srcid.inf, 4);
                              }
                           }
                        }
                        if (match == 0) {
                           if (t1) {
                              ArgusFree(ns1->dsrs[ARGUS_TRANSPORT_INDEX]);
                              ns1->dsrs[ARGUS_TRANSPORT_INDEX] = NULL;
                              ns1->dsrindex &= ~(0x1 << ARGUS_TRANSPORT_INDEX);
                           }
                        }
                        break;
                     }

// Merging Time objects may result in a change in the storage
// type of the time structure, from an ABSOLUTE_TIMESTAMP
// to an ABSOLUTE_RANGE, to hold the new ending time.

                     case ARGUS_TIME_INDEX: {
                        struct ArgusTimeObject *t1 = (struct ArgusTimeObject *) ns1->dsrs[ARGUS_TIME_INDEX];
                        struct ArgusTimeObject *t2 = (struct ArgusTimeObject *) ns2->dsrs[ARGUS_TIME_INDEX];

                        if (t1 && t2) {
                           unsigned int st1, st2;

                           if (t1->hdr.argus_dsrvl8.len == 0) {
                              bcopy ((char *) t2, (char *) t1, sizeof (*t1));
                              break;
                           }

                           st1 = t1->hdr.subtype & (ARGUS_TIME_SRC_START | ARGUS_TIME_DST_START |
                                                    ARGUS_TIME_SRC_END   | ARGUS_TIME_DST_END);

                           st2 = t2->hdr.subtype & (ARGUS_TIME_SRC_START | ARGUS_TIME_DST_START |
                                                    ARGUS_TIME_SRC_END   | ARGUS_TIME_DST_END);

                           if (st2) {
                              if (st2 & ARGUS_TIME_SRC_START) {
                                 if (st1 & ARGUS_TIME_SRC_START) {
                                    if ((t1->src.start.tv_sec  >  t2->src.start.tv_sec) ||
                                       ((t1->src.start.tv_sec  == t2->src.start.tv_sec) &&
                                        (t1->src.start.tv_usec >  t2->src.start.tv_usec))) {
                                       t1->src.start = t2->src.start;
                                       t1->hdr.subtype |= ARGUS_TIME_SRC_START;
                                    } else {
                                       if ((t1->src.end.tv_sec  <  t2->src.start.tv_sec) ||
                                          ((t1->src.end.tv_sec  == t2->src.start.tv_sec) &&
                                           (t1->src.end.tv_usec >  t2->src.start.tv_usec))) {
                                          t1->src.end = t2->src.start;
                                          t1->hdr.subtype |= ARGUS_TIME_SRC_END;
                                       }
                                    }
                                 } else {
                                    t1->src = t2->src;
                                    t1->hdr.subtype |= st2 & (ARGUS_TIME_SRC_START |
                                                              ARGUS_TIME_SRC_END);
                                 }
                              }
                              if (st2 & (ARGUS_TIME_SRC_START | ARGUS_TIME_SRC_END)) {
                                 if (st1 & (ARGUS_TIME_SRC_START | ARGUS_TIME_SRC_END)) {
                                    if (t2->src.end.tv_sec) {
                                       if ((t1->src.end.tv_sec  <  t2->src.end.tv_sec) ||
                                          ((t1->src.end.tv_sec  == t2->src.end.tv_sec) &&
                                           (t1->src.end.tv_usec <  t2->src.end.tv_usec))) {
                                          t1->src.end = t2->src.end;
                                          t1->hdr.subtype |= ARGUS_TIME_SRC_END;
                                       }
                                    } else {
                                       if ((t1->src.end.tv_sec  <  t2->src.start.tv_sec) ||
                                          ((t1->src.end.tv_sec  == t2->src.start.tv_sec) &&
                                           (t1->src.end.tv_usec <  t2->src.start.tv_usec))) {
                                          t1->src.end = t2->src.end;
                                          t1->hdr.subtype |= ARGUS_TIME_SRC_END;
                                       }
                                    }

                                 } else {
                                    t1->src.end = t2->src.end;
                                    t1->hdr.subtype |= st2 & (ARGUS_TIME_SRC_START |
                                                              ARGUS_TIME_SRC_END);
                                 }
                              }
                              if (st2 & ARGUS_TIME_DST_START) {
                                 if (st1 & ARGUS_TIME_DST_START) {
                                    if ((t1->dst.start.tv_sec  >  t2->dst.start.tv_sec) ||
                                       ((t1->dst.start.tv_sec  == t2->dst.start.tv_sec) &&
                                        (t1->dst.start.tv_usec >  t2->dst.start.tv_usec))) {
                                       t1->dst.start = t2->dst.start;
                                       t1->hdr.subtype |= ARGUS_TIME_DST_START;
                                    }
                                 } else {
                                    t1->dst = t2->dst;
                                    t1->hdr.subtype |= st2 & (ARGUS_TIME_DST_START |
                                                              ARGUS_TIME_DST_END);
                                 }
                              }
                              if (st2 & (ARGUS_TIME_DST_START | ARGUS_TIME_DST_END)) {
                                 if (st1 & (ARGUS_TIME_DST_START | ARGUS_TIME_DST_END)) {
                                    if ((t1->dst.end.tv_sec  <  t2->dst.end.tv_sec) ||
                                       ((t1->dst.end.tv_sec  == t2->dst.end.tv_sec) &&
                                        (t1->dst.end.tv_usec <  t2->dst.end.tv_usec))) {
                                       t1->dst.end = t2->dst.end;
                                       t1->hdr.subtype |= ARGUS_TIME_DST_END;
                                    }
                                 } else {
                                    t1->dst = t2->dst;
                                    t1->hdr.subtype |= st2 & (ARGUS_TIME_DST_START |
                                                              ARGUS_TIME_DST_END);
                                 }
                              }

                           } else {

                              if (t1->src.start.tv_sec == 0) {
                                 bcopy ((char *)t2, (char *)t1, sizeof (*t1));
                              } else {
                                 struct ArgusTimeObject t2cpy = *t2;

                                 if ((t1->src.start.tv_sec  >  t2->src.start.tv_sec) ||
                                    ((t1->src.start.tv_sec  == t2->src.start.tv_sec) &&
                                     (t1->src.start.tv_usec >  t2->src.start.tv_usec)))
                                    t1->src.start = t2->src.start;

                                 if ((t1->src.end.tv_sec == 0) || (t1->hdr.subtype == ARGUS_TIME_ABSOLUTE_TIMESTAMP)) {
                                    t1->src.end = t1->src.start;
                                    t1->hdr.subtype         = ARGUS_TIME_ABSOLUTE_RANGE;
                                    t1->hdr.argus_dsrvl8.len = sizeof(*t1);
                                 }
                                 if ((t2->src.end.tv_sec == 0) || (t2->hdr.subtype == ARGUS_TIME_ABSOLUTE_TIMESTAMP)) {
                                    t2cpy.src.end = t2->src.start;
                                    t2cpy.hdr.subtype         = ARGUS_TIME_ABSOLUTE_RANGE;
                                    t2cpy.hdr.argus_dsrvl8.len = sizeof(*t1);
                                 }
                                 if ((t1->src.end.tv_sec  <  t2cpy.src.end.tv_sec) ||
                                    ((t1->src.end.tv_sec  == t2cpy.src.end.tv_sec) &&
                                     (t1->src.end.tv_usec <  t2cpy.src.end.tv_usec)))
                                    t1->src.end = t2cpy.src.end;
                              }
                           }
                        }
                        break;
                     }

                     case ARGUS_TIME_ADJ_INDEX: {
                        break;
                     }

// Merging networks objects involve copying and masking
// various protocol specific network structs together.
// First test for the protocols, and if they are the same,
// then merge, if not, just remove the dsrs[] pointers;

                     case ARGUS_NETWORK_INDEX: {
                        struct ArgusNetworkStruct *n1 = (void *)ns1->dsrs[ARGUS_NETWORK_INDEX];
                        struct ArgusNetworkStruct *n2 = (void *)ns2->dsrs[ARGUS_NETWORK_INDEX];

                        if ((n1 != NULL) && (n2 != NULL)) {
                           if (n1->hdr.subtype != n2->hdr.subtype) {
                              if (!(((n1->hdr.subtype == ARGUS_TCP_INIT) || (n1->hdr.subtype == ARGUS_TCP_STATUS) || (n1->hdr.subtype == ARGUS_TCP_PERF)) &&
                                    ((n2->hdr.subtype == ARGUS_TCP_INIT) || (n2->hdr.subtype == ARGUS_TCP_STATUS) || (n2->hdr.subtype == ARGUS_TCP_PERF)))) {
                                 ArgusFree(ns1->dsrs[i]);
                                 ns1->dsrs[i] = NULL;
                                 ns1->dsrindex &= ~(0x01 << i);
                                 n1 = NULL;
                                 break;
                              }
                           }

                           if ((n1 != NULL) && (n2 != NULL)) {
                              switch (n1->hdr.subtype) {
                                 case ARGUS_TCP_INIT: {
                                    struct ArgusTCPObject *t1 = (struct ArgusTCPObject *)&n1->net_union.tcp;
                                    struct ArgusTCPObject *t2 = (struct ArgusTCPObject *)&n2->net_union.tcp;

                                    switch (n2->hdr.subtype) {
                                       case ARGUS_TCP_INIT: {
                                          t1->status    |= t2->status;
                                          t1->options   |= t2->options;
                                          t1->src.flags |= t2->src.flags;

                                          break;
                                       }
                                       case ARGUS_TCP_STATUS: {
                                          n1->hdr.subtype          = ARGUS_TCP_PERF;
                                          n1->hdr.argus_dsrvl8.len = 1 + sizeof(*t1)/4; 
                                          t1->status             = t2->status;
                                          t1->options            = t2->options;
                                          t1->src.status         = t2->src.status;
                                          t1->src.seqbase        = t2->src.seqbase;
                                          t1->src.win            = t2->src.win;
                                          t1->src.flags          = t2->src.flags;
                                          t1->src.winshift       = t2->src.winshift;
                                          t1->dst.flags          = t2->dst.flags;
                                          break;
                                       }
                                       case ARGUS_TCP_PERF: {
                                          struct ArgusTCPObject *t2 = (struct ArgusTCPObject *)&n2->net_union.tcp;
                                          struct ArgusTCPObject *tobj = (struct ArgusTCPObject *)&n1->net_union.tcp;

                                          bcopy(t2, tobj, sizeof(*t2));
                                          t1->status       |= t2->status;
                                          t1->options      |= t2->options;
                                          t1->src.status   |= t2->src.status;
                                          t1->src.seqbase   = t2->src.seqbase;
                                          t1->src.win       = t2->src.win;
                                          t1->src.flags    |= t2->src.flags;
                                          t1->src.winshift  = t2->src.winshift;
                                          break;
                                       }
                                    }
                                    break;
                                 }

                                 case ARGUS_TCP_STATUS: {
                                    struct ArgusTCPStatus *t1 = (struct ArgusTCPStatus *)&n1->net_union.tcp;
                                    struct ArgusTCPStatus tcpstatusbuf, *tcps = &tcpstatusbuf;
                                    bcopy(t1, tcps, sizeof(*t1));
                                    switch (n2->hdr.subtype) {
                                       case ARGUS_TCP_INIT: {
                                          struct ArgusTCPInitStatus *t2 = (struct ArgusTCPInitStatus *)&n2->net_union.tcp;
                                          struct ArgusTCPObject *tobj = (struct ArgusTCPObject *)&n1->net_union.tcp;

                                          bzero(tobj, sizeof(*tobj));
                                          n1->hdr.subtype          = ARGUS_TCP_PERF;
                                          n1->hdr.argus_dsrvl8.len = 1 + sizeof(*tobj)/4; 
                                          tobj->status       = tcps->status | t2->status;
                                          tobj->options      = t2->options;
                                          tobj->src.status   = t2->status;
                                          tobj->src.seqbase  = t2->seqbase;
                                          tobj->src.win      = t2->win;
                                          tobj->src.flags    = t2->flags | tcps->src;
                                          tobj->src.winshift = t2->winshift;
                                          tobj->dst.flags    = tcps->dst;

                                          break;
                                       }
                                       case ARGUS_TCP_STATUS: {
                                          struct ArgusTCPStatus *t2 = (struct ArgusTCPStatus *)&n2->net_union.tcp;
                                          t1->status |= t2->status;
                                          break;
                                       }
                                       case ARGUS_TCP_PERF: {
                                          struct ArgusTCPObject *t2 = (struct ArgusTCPObject *)&n2->net_union.tcp;
                                          struct ArgusTCPObject *tobj = (struct ArgusTCPObject *)&n1->net_union.tcp;

                                          bcopy(t2, tobj, sizeof(*t2));
                                          tobj->status       |= tcps->status;
                                          tobj->src.status   |= tcps->status;
                                          tobj->src.flags    |= tcps->src;
                                          tobj->dst.flags    |= tcps->dst;
                                          break;
                                       }
                                    }
                                    break;
                                 }

                                 case ARGUS_TCP_PERF: {
                                    struct ArgusTCPObject *t1 = (struct ArgusTCPObject *)&n1->net_union.tcp;
                                    switch (n2->hdr.subtype) {
                                       case ARGUS_TCP_INIT: 
                                       case ARGUS_TCP_STATUS: {
                                          struct ArgusTCPObject *t2 = (struct ArgusTCPObject *)&n2->net_union.tcp;

                                          t1->status    |= t2->status;
                                          t1->options   |= t2->options;
                                          t1->src.flags |= t2->src.flags;

                                          break;
                                       }

                                       case ARGUS_TCP_PERF: {
                                          struct ArgusTCPObject *t2 = (struct ArgusTCPObject *)&n2->net_union.tcp;

                                          if (n1->hdr.argus_dsrvl8.len == 0) {
                                             bcopy ((char *) n2, (char *) n1, sizeof (*n1));
                                          } else {
                                             t1->status  |= t2->status;
                                             t1->state   |= t2->state;
                                             t1->options |= t2->options;

                                             if (t1->synAckuSecs == 0)
                                                t1->synAckuSecs  = t2->synAckuSecs;
                                             if (t1->ackDatauSecs == 0)
                                                t1->ackDatauSecs = t2->ackDatauSecs;

                                             t1->src.status   |= t2->src.status;
                                             t1->src.ack       = t2->src.ack;

                                             if (t1->src.seqbase > t2->src.seqbase) {  // potential roll over

#define TCP_MAX_WINDOWSIZE	65536
                                                if ((t1->src.seqbase - t2->src.seqbase) > TCP_MAX_WINDOWSIZE) {  // roll over
                                                   t1->src.ackbytes += (t2->src.seq + (0xffffffff - t1->src.seqbase));
                                                } else
                                                   t1->src.seqbase = t2->src.seqbase;
                                             } else
                                                t1->src.seq       = t2->src.seq;

                                             t1->src.winnum   += t2->src.winnum;
                                             t1->src.bytes    += t2->src.bytes;
                                             t1->src.retrans  += t2->src.retrans;

                                             t1->src.win       = t2->src.win;
                                             t1->src.winbytes  = t2->src.winbytes;
                                             t1->src.flags    |= t2->src.flags;

                                             t1->dst.status   |= t2->dst.status;
                                             t1->dst.ack       = t2->dst.ack;

                                             if (t1->dst.seqbase > t2->dst.seqbase) {  // potential roll over
                                                if ((t1->dst.seqbase - t2->dst.seqbase) > TCP_MAX_WINDOWSIZE) {  // roll over
                                                   t1->dst.ackbytes += (t2->dst.seq + (0xffffffff - t1->dst.seqbase));
                                                } else
                                                   t1->dst.seqbase = t2->dst.seqbase;
                                             } else
                                                t1->dst.seq       = t2->dst.seq;

                                             t1->dst.winnum   += t2->dst.winnum;
                                             t1->dst.bytes    += t2->dst.bytes;
                                             t1->dst.retrans  += t2->dst.retrans;

                                             t1->dst.win       = t2->dst.win;
                                             t1->dst.winbytes  = t2->dst.winbytes;
                                             t1->dst.flags    |= t2->dst.flags;

                                             if (n1->hdr.subtype != n2->hdr.subtype) {
                                                if (n1->hdr.subtype == ARGUS_TCP_INIT) {
                                                   n1->hdr.subtype = ARGUS_TCP_PERF;
                                                   n1->hdr.argus_dsrvl8.len = (sizeof(*t1) + 3) / 4;
                                                }
                                             }
                                          }
                                          break;
                                       }
                                       break;
                                    }
                                    break;
                                 }

                                 case ARGUS_RTP_FLOW: {
                                    struct ArgusRTPObject *r1 = &n1->net_union.rtp;
                                    struct ArgusRTPObject *r2 = &n2->net_union.rtp;
                                    r1->sdrop += r2->sdrop;
                                    r1->ddrop += r2->ddrop;
                                    r1->src = r2->src;
                                    r1->dst = r2->dst;
                                    break;
                                 }

                                 case ARGUS_UDT_FLOW: {
                                    struct ArgusUDTObject *u1 = &n1->net_union.udt;
                                    struct ArgusUDTObject *u2 = &n2->net_union.udt;

                                    if (u1->hshake.version != u2->hshake.version)
                                       u1->hshake.version = 0;
                                    if (u1->hshake.socktype != u2->hshake.socktype)
                                       u1->hshake.version = 0;
                                    if (u1->hshake.conntype != u2->hshake.conntype)
                                       u1->hshake.conntype = 0;
                                    if (u1->hshake.sockid != u2->hshake.sockid)
                                       u1->hshake.sockid = 0;

                                    u1->src.solo    += u2->src.solo;
                                    u1->src.first   += u2->src.first;
                                    u1->src.middle  += u2->src.middle;
                                    u1->src.last    += u2->src.last;
                                    u1->src.drops   += u2->src.drops;
                                    u1->src.retrans += u2->src.retrans;
                                    u1->src.nacked  += u2->src.nacked;
                                    break;
                                 }

                                 case ARGUS_ESP_DSR: {
                                    struct ArgusESPObject *e1 = &n1->net_union.esp;
                                    struct ArgusESPObject *e2 = &n2->net_union.esp;

                                    n1->hdr.argus_dsrvl8.qual |= n2->hdr.argus_dsrvl8.qual;

                                    e1->lastseq = e2->lastseq;
                                    e1->lostseq += e2->lostseq;
                                    if (e1->spi != e2->spi) {
                                       e1->spi = 0;
                                    }
                                 }
                              }

                           }
                        }
                        break;
                     }

// Merging IP Attribute objects involves
// of rollover any time soon, as we're working with 64 bit
// ints with the canonical DSR.  We should test for rollover
// but lets do that later - cb

                     case ARGUS_IPATTR_INDEX: {
                        struct ArgusIPAttrStruct *attr1 = (struct ArgusIPAttrStruct *)ns1->dsrs[ARGUS_IPATTR_INDEX];
                        struct ArgusIPAttrStruct *attr2 = (struct ArgusIPAttrStruct *)ns2->dsrs[ARGUS_IPATTR_INDEX]; 

                        if (attr1 && attr2) {
                           if (attr1->hdr.argus_dsrvl8.len == 0) {
                              bcopy ((char *) attr2, (char *) attr1, sizeof (*attr1));
                              break;
                           }

                           if ((attr1->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC) &&
                               (attr2->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC)) {
                              if (attr1->src.tos != attr2->src.tos)
                                 attr1->src.tos = 0;

                              if (attr1->src.ttl != attr2->src.ttl)
                                 if ((attr2->src.ttl > 0) && (attr1->src.ttl > attr2->src.ttl)) 
                                    attr1->src.ttl = attr2->src.ttl;

                              attr1->src.options ^= attr2->src.options;
                              if (attr2->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC_FRAGMENTS)
                                 attr1->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_SRC_FRAGMENTS;

                           } else 
                           if (!(attr1->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC) &&
                                (attr2->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC)) {
                              bcopy ((char *)&attr2->src, (char *)&attr1->src, sizeof(attr1->src));
                              attr1->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_SRC;
                              if (attr2->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC_OPTIONS)
                                 attr1->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_SRC_OPTIONS;
                              if (attr2->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC_FRAGMENTS)
                                 attr1->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_SRC_FRAGMENTS;
                           }

                           if ((attr1->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST) &&
                               (attr2->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST)) {
                              if (attr1->dst.tos != attr2->dst.tos)
                                 attr1->dst.tos = 0;

                              if (attr1->dst.ttl != attr2->dst.ttl)
                                 if ((attr2->dst.ttl > 0) && (attr1->dst.ttl > attr2->dst.ttl)) 
                                    attr1->dst.ttl = attr2->dst.ttl;

                              attr1->dst.options ^= attr2->dst.options;
                              if (attr2->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST_FRAGMENTS)
                                 attr1->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_DST_FRAGMENTS;

                           } else
                           if (!(attr1->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST) &&
                                (attr2->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST)) {
                              bcopy ((char *)&attr2->dst, (char *)&attr1->dst, sizeof(attr1->dst));
                              attr1->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_DST;
                              if (attr2->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST_OPTIONS)
                                 attr1->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_DST_OPTIONS;
                              if (attr2->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST_FRAGMENTS)
                                 attr1->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_DST_FRAGMENTS;
                           }
                        }
                        break;
                     }

// Merging metrics data  involves accumulating counters.

                     case ARGUS_METRIC_INDEX: {
                        struct ArgusMetricStruct *m1 = (struct ArgusMetricStruct *) ns1->dsrs[ARGUS_METRIC_INDEX];
                        struct ArgusMetricStruct *m2 = (struct ArgusMetricStruct *) ns2->dsrs[ARGUS_METRIC_INDEX];
                        if (m1 && m2) {
                           if (m1->hdr.argus_dsrvl8.len == 0) {
                              bcopy ((char *) m2, (char *) m1, sizeof (*m1));
                              break;
                           }

                           m1->src.pkts     += m2->src.pkts;
                           m1->src.bytes    += m2->src.bytes;
                           m1->src.appbytes += m2->src.appbytes;
                           m1->dst.pkts     += m2->dst.pkts;
                           m1->dst.bytes    += m2->dst.bytes;
                           m1->dst.appbytes += m2->dst.appbytes;
                        }
                        break;
                     }


// Merging packet size data involves max min comparisons
// as well as a reformulation of the histogram if being used.

                     case ARGUS_PSIZE_INDEX: {
                        struct ArgusPacketSizeStruct *p1 = (struct ArgusPacketSizeStruct *) ns1->dsrs[ARGUS_PSIZE_INDEX];
                        struct ArgusPacketSizeStruct *p2 = (struct ArgusPacketSizeStruct *) ns2->dsrs[ARGUS_PSIZE_INDEX];

                        if (p1 && p2) {
                           if (p1->hdr.argus_dsrvl8.len == 0) {
                              bcopy ((char *) p2, (char *) p1, sizeof (*p1));
                           } else {
                              if ((p1->hdr.subtype & ARGUS_PSIZE_SRC_MAX_MIN) && 
                                  (p2->hdr.subtype & ARGUS_PSIZE_SRC_MAX_MIN))  {
                                 if (p1->src.psizemax < p2->src.psizemax)
                                    p1->src.psizemax = p2->src.psizemax;
                                 if (p1->src.psizemin > p2->src.psizemin)
                                    p1->src.psizemin = p2->src.psizemin;

                                 if (p1->hdr.subtype & ARGUS_PSIZE_HISTO) {
                                    int x, max, tot, val[8];
                                    for (x = 0, max = 0, tot = 0; x < 8; x++) {
                                       val[x] = (p1->src.psize[x] + p2->src.psize[x]);
                                       tot += val[x];
                                       if (max < val[x])
                                          max = val[x];
                                    }
                                    for (x = 0; x < 8; x++) {
                                       if (val[x]) {
                                          if (max > 255)
                                             val[x] = (val[x] * 255)/max;
                                          if (val[x] == 0)
                                             val[x] = 1;
                                       }
                                       p1->src.psize[x] = val[x];
                                    }
                                 }

                              } else {
                                 if (p2->hdr.subtype & ARGUS_PSIZE_SRC_MAX_MIN) {
                                    p1->hdr.subtype |= ARGUS_PSIZE_SRC_MAX_MIN;
                                    bcopy (&p2->src, &p1->src, sizeof(p1->src));
                                 }
                              }
                              if ((p1->hdr.subtype & ARGUS_PSIZE_DST_MAX_MIN) && 
                                  (p2->hdr.subtype & ARGUS_PSIZE_DST_MAX_MIN))  {
                                 if (p1->dst.psizemax < p2->dst.psizemax)
                                    p1->dst.psizemax = p2->dst.psizemax;
                                 if (p1->dst.psizemin > p2->dst.psizemin)
                                    p1->dst.psizemin = p2->dst.psizemin;

                                 if (p1->hdr.subtype & ARGUS_PSIZE_HISTO) {
                                    int x, max, tot, val[8];
                                    for (x = 0, max = 0, tot = 0; x < 8; x++) {
                                       val[x] = (p1->dst.psize[x] + p2->dst.psize[x]);
                                       tot += val[x];
                                       if (max < val[x])
                                          max = val[x];
                                    }
                                    for (x = 0; x < 8; x++) {
                                       if (val[x]) {
                                          if (max > 255) 
                                             val[x] = (val[x] * 255)/max;
                                          if (val[x] == 0)
                                             val[x] = 1; 
                                       }  
                                       p1->dst.psize[x] = val[x];
                                    }
                                 }
                              } else {
                                 if (p2->hdr.subtype & ARGUS_PSIZE_DST_MAX_MIN) {
                                    p1->hdr.subtype |= ARGUS_PSIZE_DST_MAX_MIN;
                                    bcopy (&p2->dst, &p1->dst, sizeof(p1->dst));
                                 }
                              }
                           }
                        } else {
                           if (!(p1) && p2) {
                              if ((p1 = ArgusCalloc(1, sizeof(*p1))) == NULL)
                                 ArgusLog (LOG_ERR, "ArgusMergeRecords: ArgusCalloc error %s", strerror(errno));
                              bcopy ((char *)p2, (char *)p1, sizeof(*p2));
                              ns1->dsrs[ARGUS_PSIZE_INDEX] = (struct ArgusDSRHeader *) p1;
                              ns1->dsrindex |= (0x01 << ARGUS_PSIZE_INDEX);
                           }
                        }
                        break;
                     }

// Merging the aggregation object results in ns1 having
// a valid aggregation object, with updates to the various
// aggregation metrics.  So, ns1 should have a valid agr, 
// as prior merging of the metrics fields will have
// generated it if ns1 did not have an agr.  If ns2 does
// not have an agr, then merge into ns1's agr the values
// for ns2's metrics.  If ns2 does exist, then just merge
// the two agr's.

                     case ARGUS_AGR_INDEX: {
                        struct ArgusAgrStruct *a1 = (struct ArgusAgrStruct *) ns1->dsrs[ARGUS_AGR_INDEX];
                        struct ArgusAgrStruct *a2 = (struct ArgusAgrStruct *) ns2->dsrs[ARGUS_AGR_INDEX];
                        struct ArgusAgrStruct databuf, *data = &databuf;
                        double ss1 = 0, ss2 = 0, sum1 = 0, sum2 = 0, value = 0;
                        int x = 0, n = 0, items = 0;

                        if (a1 && a2) {
                           if ((a1->hdr.subtype == a2->hdr.subtype) ||
                             (((a1->hdr.subtype == ARGUSMETRICDURATION) || (a1->hdr.subtype == 0x01)) &&
                              ((a2->hdr.subtype == ARGUSMETRICDURATION) || (a2->hdr.subtype == 0x01)))) {

                              double tvalstd = 0, tvalmean = 0, meansqrd = 0;

                              bzero(data, sizeof(*data));

                              if (a1->hdr.argus_dsrvl8.len == 0) {
                                 bcopy ((char *) a2, (char *) a1, sizeof (*a1));
                                 break;
                              }

                              bcopy ((char *)&a1->hdr, (char *)&data->hdr, sizeof(data->hdr));

                              data->count = a1->count + a2->count;

                              if (data->count) {
                                 data->act.maxval   = (a1->act.maxval > a2->act.maxval) ? a1->act.maxval : a2->act.maxval;
                                 data->act.minval   = (a1->act.minval < a2->act.minval) ? a1->act.minval : a2->act.minval;
                                 data->act.n        = a1->act.n + a2->act.n;

                                 sum1               = (a1->act.n > 1) ? (a1->act.meanval * a1->act.n) : a1->act.meanval;
                                 sum2               = (a2->act.n > 1) ? (a2->act.meanval * a2->act.n) : a2->act.meanval;

                                 if (a1->act.n > 1) {
                                    tvalstd  = pow(a1->act.stdev, 2.0);
                                    tvalmean = pow(a1->act.meanval, 2.0);

                                    ss1 = a1->act.n * (tvalstd + tvalmean);
                                 } else {
                                    ss1 = pow(a1->act.meanval, 2.0);
                                 }
                                 if (a2->act.n > 1) {
                                    tvalstd  = pow(a2->act.stdev, 2.0);
                                    tvalmean = pow(a2->act.meanval, 2.0);
                                    ss2 = a2->act.n * (tvalstd + tvalmean);

                                 } else {
                                    ss2 = pow(a2->act.meanval, 2.0);
                                 }

                                 if (data->act.n > 0) {
                                    data->act.meanval  = (sum1 + sum2) / data->act.n;
                                    meansqrd = pow(data->act.meanval, 2.0);
                                    data->act.stdev    = sqrt(fabs(((ss1 + ss2)/(data->act.n)) - meansqrd));
                                 }

                                 value = 0.0;
                                 ss1 = 0.0;

                                 sum1  = (a1->idle.n > 1) ? (a1->idle.meanval * a1->idle.n) : a1->idle.meanval;
                                 sum2  = (a2->idle.n > 1) ? (a2->idle.meanval * a2->idle.n) : a2->idle.meanval;

                                 if (a1->idle.stdev != 0) {
                                    tvalstd  = pow(a1->idle.stdev, 2.0);
                                    ss1 = a1->idle.n * (tvalstd + pow(a1->idle.meanval, 2.0));

                                 } else
                                    ss1 = pow(a1->idle.meanval, 2.0);

                                 if (a2->idle.stdev != 0) {
                                    tvalstd  = pow(a2->idle.stdev, 2.0);
                                    ss2 = a2->idle.n * (tvalstd + pow(a2->idle.meanval, 2.0));

                                 } else
                                    ss2 = pow(a2->idle.meanval, 2.0);

                                 if ((items = (a1->idle.n + a2->idle.n)) > 0) {
                                    for (n = 0; n < 8; n++) {
                                       int val = ((a1->idle.fdist[n] * a1->idle.n) + (a2->idle.fdist[n] * a2->idle.n)) / items;
                                       data->idle.fdist[n] = (val > 0xFF) ? 0xFF : val;
                                       if (data->idle.fdist[n] == 0) {
                                          if (a1->idle.fdist[n] || a2->idle.fdist[n])
                                             data->idle.fdist[n] = 1;
                                       }
                                    }
                                 }
                              }

                              if (deltaSrcFlowTime) {
                                 value += deltaSrcFlowTime;
                                 if (deltaSrcFlowTime > a1->idle.maxval)  a1->idle.maxval = deltaSrcFlowTime;
                                 if (deltaSrcFlowTime < a1->idle.minval)  a1->idle.minval = deltaSrcFlowTime;
                              } else 
                              if (deltaDstFlowTime) {
                                 value += deltaDstFlowTime;
                                 if (deltaDstFlowTime > a1->idle.maxval)  a1->idle.maxval = deltaDstFlowTime;
                                 if (deltaDstFlowTime < a1->idle.minval)  a1->idle.minval = deltaDstFlowTime;
                              }
                              a1->idle.n++;

                              sum1 += value;
                              ss1  += pow(value, 2.0);

                              data->idle.maxval  = (a1->idle.maxval > a2->idle.maxval) ? a1->idle.maxval : a2->idle.maxval;
                              data->idle.minval  = (a1->idle.minval < a2->idle.minval) ? a1->idle.minval : a2->idle.minval;

                              if ((data->idle.n = a1->idle.n + a2->idle.n) > 0) {
                                    data->idle.meanval = (sum1 + sum2) / data->idle.n;

                                    if (data->idle.n > 1)
                                       data->idle.stdev = sqrt (fabs(((ss1 + ss2)/(data->idle.n)) - pow(data->idle.meanval, 2.0)));
                                 }

                                 for (n = 0, x = 10; (n < 8) && (deltaSrcFlowTime || deltaDstFlowTime); n++) {
                                    if (deltaSrcFlowTime && (deltaSrcFlowTime < x)) {
                                       if (data->idle.fdist[n] < 0xFF)
                                          data->idle.fdist[n]++;
                                       deltaSrcFlowTime = 0;
                                    } 
                                    if (deltaDstFlowTime && (deltaDstFlowTime < x)) {
                                       if (data->idle.fdist[n] < 0xFF)
                                          data->idle.fdist[n]++;
                                       deltaDstFlowTime = 0;
                                    }
                                    x *= 10;
                                 }

                                 data->laststartime = ((a1->laststartime.tv_sec  > a2->laststartime.tv_sec) ||
                                                      ((a1->laststartime.tv_sec == a2->laststartime.tv_sec) &&
                                                       (a1->laststartime.tv_usec > a2->laststartime.tv_usec))) ?
                                                        a1->laststartime : a2->laststartime;

                                 data->lasttime     = ((a1->lasttime.tv_sec  > a2->lasttime.tv_sec) ||
                                                      ((a1->lasttime.tv_sec == a2->lasttime.tv_sec) &&
                                                       (a1->lasttime.tv_usec > a2->lasttime.tv_usec))) ?
                                                        a1->lasttime : a2->lasttime;

                              bcopy ((char *)data, (char *) a1, sizeof (databuf));
                           }

                        } else {
                           if (a1 && !(a2)) {
                              double value = na->RaMetricFetchAlgorithm(ns2);
                              double tvalstd = 0, meansqrd = 0;

                              a1->count++;

                              if (a1->act.maxval < value) a1->act.maxval = value;

                              if (value != 0)
                                 if (a1->act.minval > value)
                                    a1->act.minval = value;

                              sum1  = a1->act.meanval * a1->act.n;
                              sum1 += value;

                              if (a1->act.stdev != 0) {
                                 tvalstd  = pow(a1->act.stdev, 2.0);
                                 ss1 = a1->act.n * (tvalstd + pow(a1->act.meanval, 2.0));

                              } else
                                 ss1 = pow(a1->act.meanval, 2.0);
                             
                              ss1 += pow(value, 2.0);

                              a1->act.n++;
                              a1->act.meanval  = sum1 / a1->act.n;
                              meansqrd = pow(a1->act.meanval, 2.0);

                              a1->act.stdev    = sqrt(fabs((ss1/(a1->act.n)) - meansqrd));

                           } else {
                              if (!(a1) && a2) {
                                 if ((a1 = ArgusCalloc(1, sizeof(*a1))) == NULL)
                                    ArgusLog (LOG_ERR, "ArgusMergeRecords: ArgusCalloc error %s", strerror(errno));
                                 bcopy ((char *)a2, (char *)a1, sizeof(*a2));
                                 ns1->dsrs[ARGUS_AGR_INDEX] = (struct ArgusDSRHeader *) a1;
                                 ns1->dsrindex |= (0x01 << ARGUS_AGR_INDEX);
                              }
                           }
                        }
                        break;
                     }

// Merging the jitter object involves both records having
// a valid jitter object.  If they don't just drop the dsr;


                     case ARGUS_JITTER_INDEX: {
                        struct ArgusJitterStruct *j1 = (struct ArgusJitterStruct *) ns1->dsrs[ARGUS_JITTER_INDEX];
                        struct ArgusJitterStruct *j2 = (struct ArgusJitterStruct *) ns2->dsrs[ARGUS_JITTER_INDEX];

                        if (j1 && j2) {
                           if (j1->hdr.argus_dsrvl8.len == 0) {
                              bcopy ((char *) j2, (char *) j1, sizeof (*j1));
                              break;
                           }

                           if (j2->src.act.n > 0) {
                              unsigned int n, stdev = 0;
                              double meanval, sumsqrd = 0.0;
                              
                              n = (j1->src.act.n + j2->src.act.n);
                              meanval = (((double)j1->src.act.meanval * (double)j1->src.act.n) +
                                         ((double)j2->src.act.meanval * (double)j2->src.act.n)) / n;

                              if (j1->src.act.n) {
                                 double sum = (double)j1->src.act.meanval * (double)j1->src.act.n;
                                 sumsqrd += (j1->src.act.n * ((double)j1->src.act.stdev * (double)j1->src.act.stdev)) +
                                            (sum * sum)/j1->src.act.n;
                              }

                              if (j2->src.act.n) {
                                 double sum  =  (double)j2->src.act.meanval * (double)j2->src.act.n;
                                 sumsqrd += (j2->src.act.n * ((double)j2->src.act.stdev * (double)j2->src.act.stdev)) +
                                            (sum * sum)/j2->src.act.n;
                              }
                              stdev = (int) sqrt (fabs((sumsqrd/n) - ((double)meanval * (double)meanval)));

                              j1->src.act.n       = n;
                              j1->src.act.meanval = (unsigned int) meanval;
                              j1->src.act.stdev   = stdev;
                              if (j1->src.act.minval > j2->src.act.minval)
                                 j1->src.act.minval = j2->src.act.minval;
                              if (j1->src.act.maxval < j2->src.act.maxval)
                                 j1->src.act.maxval = j2->src.act.maxval;

                              switch (j1->hdr.subtype & (ARGUS_HISTO_EXP | ARGUS_HISTO_LINEAR)) {
                                 case ARGUS_HISTO_EXP: {
                                    int x, max, tot, val[8];

                                    for (x = 0, max = 0, tot = 0; x < 8; x++) {
                                       val[x] = (j1->src.act.fdist[x] + j2->src.act.fdist[x]);
                                       tot += val[x];
                                       if (max < val[x])
                                          max = val[x];
                                    }
                                    for (x = 0; x < 8; x++) {
                                       if (val[x]) {
                                          if (max > 255)
                                             val[x] = (val[x] * 255)/max;
                                          if (val[x] == 0)
                                             val[x] = 1;
                                       }
                                       j1->src.act.fdist[x] = val[x];
                                    }
                                    break;
                                 }
                                 case ARGUS_HISTO_LINEAR: {
                                    break;
                                 }
                              }
                           }

                           if (j2->src.idle.n > 0) {
                              unsigned int n, stdev = 0;
                              double meanval, sumsqrd = 0.0;
                              
                              n = (j1->src.idle.n + j2->src.idle.n);
                              meanval  = (((double) j1->src.idle.meanval * (double) j1->src.idle.n) +
                                          ((double) j2->src.idle.meanval * (double) j2->src.idle.n)) / n;

                              if (j1->src.idle.n) {
                                 double sum  =  (double) j1->src.idle.meanval * (double) j1->src.idle.n;
                                 sumsqrd += (j1->src.idle.n * ((double)j1->src.idle.stdev * (double)j1->src.idle.stdev)) +
                                            ((double)sum *(double)sum)/j1->src.idle.n;
                              }

                              if (j2->src.idle.n) {
                                 double sum  =  (double) j2->src.idle.meanval * (double) j2->src.idle.n;
                                 sumsqrd += (j2->src.idle.n * ((double)j2->src.idle.stdev * (double)j2->src.idle.stdev)) +
                                            ((double)sum *(double)sum)/j2->src.idle.n;
                              }
                              stdev = (int) sqrt (fabs((sumsqrd/n) - ((double)meanval * (double)meanval)));

                              j1->src.idle.n       = n;
                              j1->src.idle.meanval = (unsigned int) meanval;
                              j1->src.idle.stdev   = stdev;
                              if (j1->src.idle.minval > j2->src.idle.minval)
                                 j1->src.idle.minval = j2->src.idle.minval;
                              if (j1->src.idle.maxval < j2->src.idle.maxval)
                                 j1->src.idle.maxval = j2->src.idle.maxval;

                              switch (j1->hdr.subtype & (ARGUS_HISTO_EXP | ARGUS_HISTO_LINEAR)) {
                                 case ARGUS_HISTO_EXP: {
                                    int x, max, tot, val[8];

                                    for (x = 0, max = 0, tot = 0; x < 8; x++) {
                                       val[x] = (j1->src.idle.fdist[x] + j2->src.idle.fdist[x]);
                                       tot += val[x];
                                       if (max < val[x])
                                          max = val[x];
                                    }
                                    for (x = 0; x < 8; x++) {
                                       if (val[x]) {
                                          if (max > 255)
                                             val[x] = (val[x] * 255)/max;
                                          if (val[x] == 0)
                                             val[x] = 1;
                                       }
                                       j1->src.idle.fdist[x] = val[x];
                                    }
                                    break;
                                 }
                                 case ARGUS_HISTO_LINEAR: {
                                    break;
                                 }
                              }  
                           }

                           if (j2->dst.act.n > 0) {
                              unsigned int n, stdev = 0;
                              double meanval, sumsqrd = 0.0;
                              
                              n = (j1->dst.act.n + j2->dst.act.n);
                              meanval  = (((double) j1->dst.act.meanval * (double) j1->dst.act.n) +
                                          ((double) j2->dst.act.meanval * (double) j2->dst.act.n)) / n;

                              if (j1->dst.act.n) {
                                 double sum  =  j1->dst.act.meanval * j1->dst.act.n;
                                 sumsqrd += (j1->dst.act.n * ((double)j1->dst.act.stdev * (double)j1->dst.act.stdev)) +
                                            (sum * sum)/j1->dst.act.n;
                              }

                              if (j2->dst.act.n) {
                                 double sum  =  (double) j2->dst.act.meanval * (double) j2->dst.act.n;
                                 sumsqrd += (j2->dst.act.n * ((double)j2->dst.act.stdev * (double)j2->dst.act.stdev)) +
                                            ((double)sum *(double)sum)/j2->dst.act.n;
                              }
                              stdev = (int) sqrt (fabs((sumsqrd/n) - ((double)meanval * (double)meanval)));

                              j1->dst.act.n       = n;
                              j1->dst.act.meanval = (unsigned int) meanval;
                              j1->dst.act.stdev   = stdev;
                              if (j1->dst.act.minval > j2->dst.act.minval)
                                 j1->dst.act.minval = j2->dst.act.minval;
                              if (j1->dst.act.maxval < j2->dst.act.maxval)
                                 j1->dst.act.maxval = j2->dst.act.maxval;

                              switch (j1->hdr.subtype & (ARGUS_HISTO_EXP | ARGUS_HISTO_LINEAR)) {
                                 case ARGUS_HISTO_EXP: {
                                    int x, max, tot, val[8];

                                    for (x = 0, max = 0, tot = 0; x < 8; x++) {
                                       val[x] = (j1->dst.act.fdist[x] + j2->dst.act.fdist[x]);
                                       tot += val[x];
                                       if (max < val[x])
                                          max = val[x];
                                    }
                                    for (x = 0; x < 8; x++) {
                                       if (val[x]) {
                                          if (max > 255)
                                             val[x] = (val[x] * 255)/max;
                                          if (val[x] == 0)
                                             val[x] = 1;
                                       }
                                       j1->dst.act.fdist[x] = val[x];
                                    }
                                    break;
                                 }
                                 case ARGUS_HISTO_LINEAR: {
                                    break;
                                 }
                              }  
                           }

                           if (j2->dst.idle.n > 0) {
                              unsigned int n, stdev = 0;
                              double meanval, sumsqrd = 0.0;
                              
                              n = (j1->dst.idle.n + j2->dst.idle.n);
                              meanval  = (((double) j1->dst.idle.meanval * (double) j1->dst.idle.n) +
                                          ((double) j2->dst.idle.meanval * (double) j2->dst.idle.n)) / n;

                              if (j1->dst.idle.n) {
                                 int sum  =  (double) j1->dst.idle.meanval * (double) j1->dst.idle.n;
                                 sumsqrd += (j1->dst.idle.n * ((double)j1->dst.idle.stdev * (double)j1->dst.idle.stdev)) +
                                            ((double)sum *(double)sum)/j1->dst.idle.n;
                              }

                              if (j2->dst.idle.n) {
                                 double sum  =  (double) j2->dst.idle.meanval * (double) j2->dst.idle.n;
                                 sumsqrd += (j2->dst.idle.n * ((double)j2->dst.idle.stdev * (double)j2->dst.idle.stdev)) +
                                            ((double)sum *(double)sum)/j2->dst.idle.n;
                              }
                              stdev = (int) sqrt (fabs((sumsqrd/n) - ((double)meanval * (double)meanval)));

                              j1->dst.idle.n       = n;
                              j1->dst.idle.meanval = (unsigned int) meanval;
                              j1->dst.idle.stdev   = stdev;
                              if (j1->dst.idle.minval > j2->dst.idle.minval)
                                 j1->dst.idle.minval = j2->dst.idle.minval;
                              if (j1->dst.idle.maxval < j2->dst.idle.maxval)
                                 j1->dst.idle.maxval = j2->dst.idle.maxval;

                              switch (j1->hdr.subtype & (ARGUS_HISTO_EXP | ARGUS_HISTO_LINEAR)) {
                                 case ARGUS_HISTO_EXP: {
                                    int x, max, tot, val[8];

                                    for (x = 0, max = 0, tot = 0; x < 8; x++) {
                                       val[x] = (j1->dst.idle.fdist[x] + j2->dst.idle.fdist[x]);
                                       tot += val[x];
                                       if (max < val[x])
                                          max = val[x];
                                    }
                                    for (x = 0; x < 8; x++) {
                                       if (val[x]) {
                                          if (max > 255)
                                             val[x] = (val[x] * 255)/max;
                                          if (val[x] == 0)
                                             val[x] = 1;
                                       }
                                       j1->dst.idle.fdist[x] = val[x];
                                    }
                                    break;
                                 }
                                 case ARGUS_HISTO_LINEAR: {
                                    break;
                                 }
                              }  
                           }

                        } else {
                           if (!j1 && j2) {
                              if ((j1 = (void *) ArgusCalloc (1, sizeof(*j1))) == NULL)
                                 ArgusLog (LOG_ERR, "ArgusMergeRecords: ArgusCalloc error %s", strerror(errno));
                              bcopy ((char *) j2, (char *)j1, sizeof (*j1));
                              ns1->dsrs[i] = (struct ArgusDSRHeader *) j1;
                              ns1->dsrindex |= (0x01 << i);
                           }
                        }
                        break;
                     }

// Merging the user data object involves leaving the ns1 buffer,
// or making the ns2 buffer, ns1's.  Since these are allocated
// objects, make sure you deal with them as such.


                     case ARGUS_SRCUSERDATA_INDEX: 
                     case ARGUS_DSTUSERDATA_INDEX: {
                        struct ArgusDataStruct *d1 = (struct ArgusDataStruct *) ns1->dsrs[i];
                        struct ArgusDataStruct *d2 = (struct ArgusDataStruct *) ns2->dsrs[i];

                        if (d1 && d2) {
                           unsigned short d2count = d2->count;
                           int t1len = d1->size - d1->count;
                           int t2len = d2->size - d2->count;

                           if (t1len < 0) { d1->count = d1->size; t1len = 0; }
                           if (t2len < 0) { d2count = d2->size; t2len = 0; }

                           t1len = (t1len > d2count) ? d2count : t1len;

                           if (t1len > 0) {
                              bcopy(d2->array, &d1->array[d1->count], t1len);
                              d1->count += t1len;
                           }

                        } else
                        if (!d1 && d2) {
                           struct ArgusDataStruct *t2;
                           int len = (((d2->hdr.type & ARGUS_IMMEDIATE_DATA) ? 1 :
                                      ((d2->hdr.subtype & ARGUS_LEN_16BITS)  ? d2->hdr.argus_dsrvl16.len :
                                                                               d2->hdr.argus_dsrvl8.len)));
                           if ((t2 = (struct ArgusDataStruct *) ArgusCalloc((2 + len), 4)) == NULL)
                              ArgusLog (LOG_ERR, "ArgusMergeRecords: ArgusCalloc error %s", strerror(errno));

                           bcopy ((char *)d2, (char *)t2, len * 4);
                           t2->size  = (len - 2) * 4;
                           t2->count  = (len - 2) * 4;
                           ns1->dsrs[i] = (struct ArgusDSRHeader *) t2;
                           ns1->dsrindex |= (0x01 << i);
                        }
                        break;
                     }


// Merging the MAC data object involves comparing the ns1 buffer,
// leaving them if they are equal and blowing away the value if they
// are different.

                     case ARGUS_ENCAPS_INDEX: {
                        struct ArgusEncapsStruct *e1  = (struct ArgusEncapsStruct *) ns1->dsrs[ARGUS_ENCAPS_INDEX];
                        struct ArgusEncapsStruct *e2  = (struct ArgusEncapsStruct *) ns2->dsrs[ARGUS_ENCAPS_INDEX];

                        if (e1 && e2) {
                           if (e1->src != e2->src) {
                              e1->hdr.argus_dsrvl8.qual |= ARGUS_SRC_CHANGED;
                              e1->src |= e2->src;
                           }
                           if (e1->dst != e2->dst) {
                              e1->hdr.argus_dsrvl8.qual |= ARGUS_DST_CHANGED;
                              e1->dst |= e2->dst;
                           }
                        }
                        break;
                     }

                     case ARGUS_MAC_INDEX: {
                        struct ArgusMacStruct *m1 = (struct ArgusMacStruct *) ns1->dsrs[ARGUS_MAC_INDEX];
                        struct ArgusMacStruct *m2 = (struct ArgusMacStruct *) ns2->dsrs[ARGUS_MAC_INDEX];

                        if (m1 && m2) {
                           if (m1->hdr.subtype == m2->hdr.subtype) {
                              switch (m1->hdr.subtype) {
                                 default:
                                 case ARGUS_TYPE_ETHER: {
                                    struct ether_header *e1 = &m1->mac.mac_union.ether.ehdr;
                                    struct ether_header *e2 = &m2->mac.mac_union.ether.ehdr;

                                    if (bcmp(&e1->ether_shost, &e2->ether_shost, sizeof(e1->ether_shost)))
                                       bzero ((char *)&e1->ether_shost, sizeof(e1->ether_shost));
                          
                                    if (bcmp(&e1->ether_dhost, &e2->ether_dhost, sizeof(e1->ether_dhost)))
                                       bzero ((char *)&e1->ether_dhost, sizeof(e1->ether_dhost));

                                    if (e1->ether_type != e2->ether_type) 
                                       e1->ether_type = 0;
                                    break;
                                 }
                              }

                           } else {
                              ArgusFree(ns1->dsrs[ARGUS_MAC_INDEX]);
                              ns1->dsrs[ARGUS_MAC_INDEX] = NULL;
                              ns1->dsrindex &= ~(0x01 << i);
                           }

                        } else {
                           if (ns1->dsrs[ARGUS_MAC_INDEX] != NULL) {
                              ArgusFree(ns1->dsrs[ARGUS_MAC_INDEX]);
                              ns1->dsrs[ARGUS_MAC_INDEX] = NULL;
                              ns1->dsrindex &= ~(0x01 << i);
                           }
                        }
                        break;
                     }

// Merging vlan and mpls tags needs a bit of work.

                     case ARGUS_VLAN_INDEX:
                     case ARGUS_MPLS_INDEX: {
                        break;
                     }

                     case ARGUS_ICMP_INDEX: {
                        struct ArgusIcmpStruct *i1 = (struct ArgusIcmpStruct *) ns1->dsrs[ARGUS_ICMP_INDEX];
                        struct ArgusIcmpStruct *i2 = (struct ArgusIcmpStruct *) ns2->dsrs[ARGUS_ICMP_INDEX];

                        if (i1 && i2) {
                           if ((i1->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED) &&
                               (i2->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED)) {
                              struct ArgusFlow *flow = (void *)ns1->dsrs[ARGUS_FLOW_INDEX];
                              int type = 0;

                              if (flow != NULL) {
                                 switch (flow->hdr.subtype & 0x3F) {
                                    case ARGUS_FLOW_CLASSIC5TUPLE:
                                    case ARGUS_FLOW_LAYER_3_MATRIX: {
                                       switch (type = (flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                                          case ARGUS_TYPE_IPV4: {
                                             unsigned char masklen = 32;
                                             ArgusMergeAddress(&i1->osrcaddr, &i2->osrcaddr, ARGUS_TYPE_IPV4, ARGUS_SRC, &masklen);
                                             break;
                                          }

                                          case ARGUS_TYPE_IPV6:
                                             break;
                                       }
                                       break;
                                    }
                                 }
                              }
                           }
                        }

                        if (!i1 && i2) {
                           int len = i2->hdr.argus_dsrvl8.len;

                           if (len > 0) {
                              if ((i1 = ArgusCalloc(1, len * 4)) == NULL)
                                 ArgusLog (LOG_ERR, "ArgusMergeRecords: ArgusCalloc error %s", strerror(errno));
                              bcopy ((char *)i2, (char *)i1, len * 4);

                              ns1->dsrs[ARGUS_ICMP_INDEX] = (struct ArgusDSRHeader *) i1;
                              ns1->dsrindex |= (0x01 << ARGUS_ICMP_INDEX);
                           }
                        }
                        break;
                     }

                     case ARGUS_COCODE_INDEX: {
                        struct ArgusCountryCodeStruct *c1 = (void *) ns1->dsrs[ARGUS_COCODE_INDEX];
                        struct ArgusCountryCodeStruct *c2 = (void *) ns2->dsrs[ARGUS_COCODE_INDEX];
                        
                        if (c1 && c2) {
                           if (bcmp(c1->src, c2->src, sizeof(c1->src)))
                              bzero(&c1->src, sizeof(c1->src));
                           if (bcmp(c1->dst, c2->dst, sizeof(c1->dst)))
                              bzero(&c1->dst, sizeof(c1->dst));
                           
                        } else
                        if (c2) {
                           int len = c2->hdr.argus_dsrvl8.len;

                           if (len > 0) {
                              if ((c1 = ArgusCalloc(1, len * 4)) == NULL)
                                 ArgusLog (LOG_ERR, "ArgusMergeRecords: ArgusCalloc error %s", strerror(errno));
                              bcopy ((char *)c2, (char *)c2, len * 4);

                              ns1->dsrs[ARGUS_COCODE_INDEX] = (struct ArgusDSRHeader *) c1;
                              ns1->dsrindex |= (0x01 << ARGUS_COCODE_INDEX);
                           }
                        }
                        break;
                     }

                     case ARGUS_LABEL_INDEX: {
                        struct ArgusLabelStruct *l1 = (void *) ns1->dsrs[ARGUS_LABEL_INDEX];
                        struct ArgusLabelStruct *l2 = (void *) ns2->dsrs[ARGUS_LABEL_INDEX];

                        if (l1 && l2) {
                           if ((l1->l_un.label != NULL) && (l2->l_un.label != NULL)) {
                              if (strcmp(l1->l_un.label, l2->l_un.label)) {
                                 char *buf = calloc(1, MAXBUFFERLEN);
                                 int len;

                                 if ((ArgusMergeLabel(l1->l_un.label, l2->l_un.label, buf, MAXBUFFERLEN, ARGUS_UNION)) != NULL) {
                                    free(l1->l_un.label);
                                    l1->l_un.label = strdup(buf);
                                    len = 1 + ((strlen(buf) + 3)/4);
                                    l1->hdr.argus_dsrvl8.len  = len;
                                 }
                                 free(buf);
                              }
                           } else {
                              if (l2->l_un.label != NULL) {
                                 if (l1->l_un.label != NULL) free (l1->l_un.label);
                                 l1->l_un.label = strdup(l2->l_un.label);
                              }
                           }

                        } else {
                           if (l2 && (l1 == NULL)) {
                              ns1->dsrs[ARGUS_LABEL_INDEX] = calloc(1, sizeof(struct ArgusLabelStruct));
                              l1 = (void *) ns1->dsrs[ARGUS_LABEL_INDEX];

                              bcopy(l2, l1, sizeof(*l2));
                              l1->l_un.label = NULL;

                              if (l2->l_un.label != NULL)
                                 l1->l_un.label = strdup(l2->l_un.label);
                           }
                        }
                        break;
                     }

// Merging the behavioral dsr's currently involve accumulating the counters for keystrokes.
// and taking the greatest of the scores.

                     case ARGUS_BEHAVIOR_INDEX: {
                        struct ArgusBehaviorStruct *a1 = (void *) ns1->dsrs[ARGUS_BEHAVIOR_INDEX];
                        struct ArgusBehaviorStruct *a2 = (void *) ns2->dsrs[ARGUS_BEHAVIOR_INDEX];

                        if (a1 && a2) {
                           if (a1->hdr.subtype == a2->hdr.subtype) {
                              switch (a1->hdr.subtype) {
                                 case ARGUS_TCP_KEYSTROKE: 
                                 case ARGUS_SSH_KEYSTROKE: 
                                 case ARGUS_BEHAVIOR_KEYSTROKE: {
                                    a1->keyStroke.src.n_strokes += a2->keyStroke.src.n_strokes;
                                    a1->keyStroke.dst.n_strokes += a2->keyStroke.dst.n_strokes;
                                    break;
                                 }
                              }
                           }

                        } else {
                           if (a2 && (a1 == NULL)) {
                              ns1->dsrs[ARGUS_BEHAVIOR_INDEX] = calloc(1, sizeof(struct ArgusBehaviorStruct));
                              ns1->dsrindex |= (0x01 << ARGUS_BEHAVIOR_INDEX);

                              a1 = (void *) ns1->dsrs[ARGUS_BEHAVIOR_INDEX];
                              bcopy(a2, a1, sizeof(*a2));
                           }
                        }
                        break;
                     }

                     case ARGUS_SCORE_INDEX: {
                        struct ArgusScoreStruct *s1 = (void *) ns1->dsrs[ARGUS_SCORE_INDEX];
                        struct ArgusScoreStruct *s2 = (void *) ns2->dsrs[ARGUS_SCORE_INDEX];
                        
                        if (s1 || s2) {
                           if (s1 && s2) {
                              if (s1->hdr.subtype == s2->hdr.subtype) {
                                 switch (s1->hdr.subtype) {
                                    case ARGUS_BEHAVIOR_SCORE: {
                                       int i;
                                       for (i = 0; i < 8; i++) {
                                          if (s2->behvScore.values[i] > s1->behvScore.values[i])
                                             s1->behvScore.values[i] = s2->behvScore.values[i];
                                       }
                                    }
                                 }
                              }
                           } else 
                           if (!s1 && s2) {
                              ns1->dsrs[ARGUS_SCORE_INDEX] = calloc(1, sizeof(struct ArgusScoreStruct));
                              ns1->dsrindex |= (0x01 << ARGUS_SCORE_INDEX);

                              s1 = (void *) ns1->dsrs[ARGUS_SCORE_INDEX];
                              bcopy(s2, s1, sizeof(*s2));
                           }
                        }
                        break;
                     }

                     case ARGUS_GEO_INDEX: {
                        struct ArgusGeoLocationStruct *g1 = (void *) ns1->dsrs[ARGUS_GEO_INDEX];
                        struct ArgusGeoLocationStruct *g2 = (void *) ns2->dsrs[ARGUS_GEO_INDEX];

                        if (g1 && g2) {

                        } else {
                           if (g2 && (g1 == NULL)) {
                              ns1->dsrs[ARGUS_GEO_INDEX] = calloc(1, sizeof(struct ArgusGeoLocationStruct));
                              g1 = (void *) ns1->dsrs[ARGUS_GEO_INDEX];
                              bcopy(g2, g1, sizeof(*g2));
                           }
                        }
                        break;
                     }

                     case ARGUS_LOCAL_INDEX: {
                        struct ArgusNetspatialStruct *l1 = (void *) ns1->dsrs[ARGUS_LOCAL_INDEX];
                        struct ArgusNetspatialStruct *l2 = (void *) ns2->dsrs[ARGUS_LOCAL_INDEX];

                        if (l1 && l2) {
                           if (l1->sloc > l2->sloc) l1->sloc = l2->sloc;
                           if (l1->dloc > l2->dloc) l1->dloc = l2->dloc;

                        } else {
                           if (l2 && (l1 == NULL)) {
                              ns1->dsrs[ARGUS_LOCAL_INDEX] = calloc(1, sizeof(struct ArgusNetspatialStruct));
                              l1 = (void *) ns1->dsrs[ARGUS_LOCAL_INDEX];
                              bcopy(l2, l1, sizeof(*l2));
                           }
                        }
                        break;
                     }
                  }
               }

               if ((seconds = RaGetFloatDuration(ns1)) > 0) {
                  struct ArgusMetricStruct *metric = (void *)ns1->dsrs[ARGUS_METRIC_INDEX];
                  if (metric != NULL) {
                     int eframe = ArgusParser->ArgusEtherFrameCnt;
                     ns1->srate = (float) (metric->src.pkts * 1.0)/seconds;
                     ns1->drate = (float) (metric->dst.pkts * 1.0)/seconds;
                     ns1->sload = (float) ((metric->src.bytes + (metric->src.pkts * eframe)) * 8.0)/seconds;
                     ns1->dload = (float) ((metric->dst.bytes + (metric->dst.pkts * eframe)) * 8.0)/seconds;
                     ns1->pcr   = (float) ArgusFetchAppByteRatio(ns1);
                     ns1->dur   = seconds;
                  }
               }

               if (ns2->score > ns1->score)
                  ns1->score = ns2->score;

               if (ns1time && ns2time) {
                  if (ns2time->src.start.tv_sec > 0) {
                     ns1->lastSrcStartTime.tv_sec  = ns2time->src.start.tv_sec;
                     ns1->lastSrcStartTime.tv_usec = ns2time->src.start.tv_usec;
                  } else {
                  }
                  if (ns2time->dst.start.tv_sec > 0) {
                     ns1->lastDstStartTime.tv_sec  = ns2time->dst.start.tv_sec;
                     ns1->lastDstStartTime.tv_usec = ns2time->dst.start.tv_usec;
                  } else {
                  }
               }

               ns1->status |= ARGUS_RECORD_MODIFIED;
               break;
            }
         }
      }
   }

   return;
}

void
ArgusReplaceRecords (struct ArgusAggregatorStruct *na, struct ArgusRecordStruct *ns1, struct ArgusRecordStruct *ns2)
{
   ns2->htblhdr = ns1->htblhdr;
   if (ns2->htblhdr != NULL)
      ns2->htblhdr->object = ns2;

   ns1->htblhdr = NULL;
   ns1->status |= ARGUS_RECORD_MODIFIED;
   return;
}


void
ArgusIntersectRecords (struct ArgusAggregatorStruct *na, struct ArgusRecordStruct *ns1, struct ArgusRecordStruct *ns2)
{
   struct ArgusAgrStruct *agr = NULL;
   int i;

   if ((ns1 && ns2) && ((ns1->hdr.type & ARGUS_FAR) && (ns2->hdr.type & ARGUS_FAR))) {
      if ((agr = (struct ArgusAgrStruct *) ns1->dsrs[ARGUS_AGR_INDEX]) == NULL) {
         double value = na->RaMetricFetchAlgorithm(ns1);

         if ((agr = ArgusCalloc(1, sizeof(*agr))) == NULL)
            ArgusLog (LOG_ERR, "ArgusIntersectRecords: ArgusCalloc error %s", strerror(errno));

         agr->hdr.type              = ARGUS_AGR_DSR;
         agr->hdr.subtype           = na->ArgusMetricIndex;
         agr->hdr.argus_dsrvl8.qual = 0x01;
         agr->hdr.argus_dsrvl8.len  = (sizeof(*agr) + 3)/4;
         agr->count                 = 1;
         agr->act.maxval            = value;
         agr->act.minval            = value;
         agr->act.meanval           = value;
         agr->act.n                 = 1;
         ns1->dsrs[ARGUS_AGR_INDEX] = (struct ArgusDSRHeader *) agr;
         ns1->dsrindex |= (0x01 << ARGUS_AGR_INDEX);
      }

      for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
         switch (i) {
            case ARGUS_FLOW_INDEX: {

// Intersecting Flow records is a matter of testing each field and
// transforming values that are not equal to either run length
// and'ing or zeroing out the value.  When a value is zero'ed
// we need to indicate it in the status field of the flow
// descriptor so that values resulting from merging are not
// confused with values actually off the wire.
 
// run length and'ing is an attempt to preserve CIDR addresses.
// any other value should be either preserved or invalidated.

               struct ArgusFlow *f1 = (struct ArgusFlow *) ns1->dsrs[ARGUS_FLOW_INDEX];
               struct ArgusFlow *f2 = (struct ArgusFlow *) ns2->dsrs[ARGUS_FLOW_INDEX];

               if (f1 && f2) {
                  unsigned char masklen = 0;
                  if (f1->hdr.subtype == f2->hdr.subtype) {
                     switch (f1->hdr.subtype & 0x3F) {
                        case ARGUS_FLOW_LAYER_3_MATRIX: {
                           if ((f1->hdr.argus_dsrvl8.qual & 0x1F) == (f2->hdr.argus_dsrvl8.qual & 0x1F)) {
                              switch (f1->hdr.argus_dsrvl8.qual & 0x1F) {
                                 case ARGUS_TYPE_IPV4:
                                    masklen = (f1->ip_flow.smask > f2->ip_flow.smask) ? f2->ip_flow.smask : f1->ip_flow.smask;
                                    f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->ip_flow.ip_src, &f2->ip_flow.ip_src, ARGUS_TYPE_IPV4, ARGUS_SRC, &masklen);
                                    f1->ip_flow.smask = masklen;

                                    masklen = (f1->ip_flow.dmask > f2->ip_flow.dmask) ? f2->ip_flow.dmask : f1->ip_flow.dmask;
                                    f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->ip_flow.ip_dst, &f2->ip_flow.ip_dst, ARGUS_TYPE_IPV4, ARGUS_DST, &masklen);
                                    f1->ip_flow.dmask = masklen;
                                    break;

                                 case ARGUS_TYPE_IPV6:  
                                    masklen = (f1->ipv6_flow.smask > f2->ipv6_flow.smask) ? f2->ipv6_flow.smask : f1->ipv6_flow.smask;
                                    f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->ipv6_flow.ip_src[0], &f2->ipv6_flow.ip_src[0], ARGUS_TYPE_IPV6, ARGUS_SRC, &masklen);
                                    f1->ipv6_flow.smask = masklen;

                                    masklen = (f1->ipv6_flow.dmask > f2->ipv6_flow.dmask) ? f2->ipv6_flow.dmask : f1->ipv6_flow.dmask;
                                    f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->ipv6_flow.ip_dst[0], &f2->ipv6_flow.ip_dst[0], ARGUS_TYPE_IPV6, ARGUS_DST, &masklen);
                                    f1->ipv6_flow.dmask = masklen;
                                    break;

                                 case ARGUS_TYPE_RARP:
                                    if (bcmp(&f1->rarp_flow.shaddr, &f2->rarp_flow.shaddr, 6))
                                       bzero(&f1->rarp_flow.shaddr, 6);
                                    if (bcmp(&f1->rarp_flow.dhaddr, &f2->rarp_flow.dhaddr, 6))
                                       bzero(&f1->rarp_flow.dhaddr, 6);
                                    break;
                                 case ARGUS_TYPE_ARP:
                                    f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->arp_flow.arp_spa, &f2->arp_flow.arp_spa, ARGUS_TYPE_ARP, ARGUS_SRC, &masklen);
                                    f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->arp_flow.arp_tpa, &f2->arp_flow.arp_tpa, ARGUS_TYPE_ARP, ARGUS_DST, &masklen);
                                    break;
                              }
                           }
                           break;
                        }

                        case ARGUS_FLOW_CLASSIC5TUPLE: {
                              switch (f1->hdr.argus_dsrvl8.qual & 0x1F) {
                                 case ARGUS_TYPE_IPV4:
                                    if ((f1->hdr.argus_dsrvl8.qual & 0x1F) == (f2->hdr.argus_dsrvl8.qual & 0x1F)) {
                                       ArgusMergeAddress(&f1->ip_flow.ip_src, &f2->ip_flow.ip_src, ARGUS_TYPE_IPV4, ARGUS_SRC, &masklen);
                                       ArgusMergeAddress(&f1->ip_flow.ip_dst, &f2->ip_flow.ip_dst, ARGUS_TYPE_IPV4, ARGUS_DST, &masklen);
                                       if (f1->ip_flow.ip_p  != f2->ip_flow.ip_p)
                                          f1->ip_flow.ip_p = 0;
                                       if (f1->ip_flow.sport != f2->ip_flow.sport)
                                          f1->ip_flow.sport = 0;
                                       if (f1->ip_flow.dport != f2->ip_flow.dport)
                                          f1->ip_flow.dport = 0;

                                    } else {
                                       f1->ip_flow.ip_src = 0;
                                       f1->ip_flow.ip_dst = 0;
                                    
                                       switch (f2->hdr.argus_dsrvl8.qual & 0x1F) {
                                          case ARGUS_TYPE_IPV6:
                                             if (f1->ip_flow.ip_p  != f2->ipv6_flow.ip_p)
                                                f1->ip_flow.ip_p = 0;
                                             if (f1->ip_flow.sport != f2->ipv6_flow.sport)
                                                f1->ip_flow.sport = 0;
                                             if (f1->ip_flow.dport != f2->ipv6_flow.dport)
                                                f1->ip_flow.dport = 0;
                                             break;
              
                                          default:
                                             f1->ip_flow.ip_p = 0;
                                             f1->ip_flow.sport = 0;
                                             f1->ip_flow.dport = 0;
                                             break;
                                       }
                                    }
                                    break;

                                 case ARGUS_TYPE_IPV6:  
                                    if ((f1->hdr.argus_dsrvl8.qual & 0x1F) == (f2->hdr.argus_dsrvl8.qual & 0x1F)) {
                                       f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->ipv6_flow.ip_src[0],
                                               &f2->ipv6_flow.ip_src[0], ARGUS_TYPE_IPV6, ARGUS_SRC, &masklen);
                                       f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->ipv6_flow.ip_dst[0],
                                               &f2->ipv6_flow.ip_dst[0], ARGUS_TYPE_IPV6, ARGUS_DST, &masklen);

                                       if (f1->ipv6_flow.ip_p  != f2->ipv6_flow.ip_p)  f1->ipv6_flow.ip_p = 0;
                                       if (f1->ipv6_flow.sport != f2->ipv6_flow.sport) f1->ipv6_flow.sport = 0;
                                       if (f1->ipv6_flow.dport != f2->ipv6_flow.dport) f1->ipv6_flow.dport = 0;

                                    } else {
                                       bzero ((char *)&f1->ipv6_flow.ip_src[0], sizeof(f1->ipv6_flow.ip_src));
                                       bzero ((char *)&f1->ipv6_flow.ip_dst[0], sizeof(f1->ipv6_flow.ip_dst));
                                       if (f1->ipv6_flow.ip_p  != f2->ip_flow.ip_p)  f1->ipv6_flow.ip_p = 0;
                                       if (f1->ipv6_flow.sport != f2->ip_flow.sport) f1->ipv6_flow.sport = 0;
                                       if (f1->ipv6_flow.dport != f2->ip_flow.dport) f1->ipv6_flow.dport = 0;
                                    }
                                    break;

                                 case ARGUS_TYPE_RARP:
                                    if (bcmp(&f1->rarp_flow.shaddr, &f2->rarp_flow.shaddr, 6))
                                       bzero(&f1->rarp_flow.shaddr, 6);
                                    if (bcmp(&f1->rarp_flow.dhaddr, &f2->rarp_flow.dhaddr, 6))
                                       bzero(&f1->rarp_flow.dhaddr, 6);
                                 case ARGUS_TYPE_ARP:
                                    f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->arp_flow.arp_spa, &f2->arp_flow.arp_spa, ARGUS_TYPE_ARP, ARGUS_SRC, &masklen);
                                    f1->hdr.argus_dsrvl8.qual |= ArgusMergeAddress(&f1->arp_flow.arp_tpa, &f2->arp_flow.arp_tpa, ARGUS_TYPE_ARP, ARGUS_DST, &masklen);
                                    break;
                              }
                              break;
                           }

                           case ARGUS_FLOW_ARP: {
                              break;
                           }
                        }
                     }
                  }
               }
               break;

// Intersecting Transport objects involves simply checking that the source
// id and seqnum are the same, and if not, removing the fields until
// we're actually removing the struct.

// struct ArgusTransportStruct {
//    struct ArgusDSRHeader hdr;
//    struct ArgusAddrStruct srcid;
//    unsigned int seqnum;
// };

            case ARGUS_TRANSPORT_INDEX: {
               struct ArgusTransportStruct *t1 = (struct ArgusTransportStruct *) ns1->dsrs[ARGUS_TRANSPORT_INDEX];
               struct ArgusTransportStruct *t2 = (struct ArgusTransportStruct *) ns2->dsrs[ARGUS_TRANSPORT_INDEX];

               if ((t1 && t2) && (t1->hdr.argus_dsrvl8.qual == t2->hdr.argus_dsrvl8.qual)) {
                  if (t1->hdr.argus_dsrvl8.qual == t2->hdr.argus_dsrvl8.qual) {
                     if ((t1->hdr.subtype & ARGUS_SRCID) && (t2->hdr.subtype & ARGUS_SRCID)) {
                        switch (t1->hdr.argus_dsrvl8.qual & ~ARGUS_TYPE_INTERFACE) {
                           case ARGUS_TYPE_INT:
                           case ARGUS_TYPE_IPV4:
                           case ARGUS_TYPE_STRING:
                              if (t1->srcid.a_un.ipv4 != t2->srcid.a_un.ipv4) {
                                 ns1->dsrs[ARGUS_TRANSPORT_INDEX] = NULL;
                                 ns1->dsrindex &= ~(0x1 << ARGUS_TRANSPORT_INDEX);
                              }
                              break;

                           case ARGUS_TYPE_IPV6:
                           case ARGUS_TYPE_ETHER:
                              break;

                        }
                     }

                  } else {
                     ns1->dsrs[ARGUS_TRANSPORT_INDEX] = NULL;
                     ns1->dsrindex &= ~(0x1 << ARGUS_TRANSPORT_INDEX);
                  }
               }

               break;
            }

// Intersecting Time objects may result in a change in the storage
// type of the time structure, from an ABSOLUTE_TIMESTAMP
// to an ABSOLUTE_RANGE, to hold the new ending time.

            case ARGUS_TIME_INDEX: {
               struct ArgusTimeObject *t1 = (struct ArgusTimeObject *) ns1->dsrs[ARGUS_TIME_INDEX];
               struct ArgusTimeObject *t2 = (struct ArgusTimeObject *) ns2->dsrs[ARGUS_TIME_INDEX];

               if (t1 && t2) {
                  if ((t1->hdr.argus_dsrvl8.len = 0) || (t1->src.start.tv_sec == 0)) {
                     bcopy ((char *)t2, (char *)t1, sizeof (*t1));
                  } else {
                     if ((t1->src.start.tv_sec  >  t2->src.start.tv_sec) ||
                        ((t1->src.start.tv_sec  == t2->src.start.tv_sec) &&
                         (t1->src.start.tv_usec >  t2->src.start.tv_usec)))
                        t1->src.start = t2->src.start;

                     if ((t1->src.end.tv_sec == 0) || (t1->hdr.subtype == ARGUS_TIME_ABSOLUTE_TIMESTAMP)) {
                        t1->src.end = t1->src.start;
                        t1->hdr.subtype         = ARGUS_TIME_ABSOLUTE_RANGE;
                        t1->hdr.argus_dsrvl8.len  = 5;
                     }
                     if ((t2->src.end.tv_sec == 0) || (t2->hdr.subtype == ARGUS_TIME_ABSOLUTE_TIMESTAMP)) {
                        t2->src.end = t2->src.start;
                        t2->hdr.subtype         = ARGUS_TIME_ABSOLUTE_RANGE;
                        t2->hdr.argus_dsrvl8.len  = 5;
                     }
                     if ((t1->src.end.tv_sec  <  t2->src.end.tv_sec) ||
                        ((t1->src.end.tv_sec  == t2->src.end.tv_sec) &&
                         (t1->src.end.tv_usec <  t2->src.end.tv_usec)))
                        t1->src.end = t2->src.end;
                  }
               }
               break;
            }

// Intersecting metric objects should not result in any type
// of rollover any time soon, as we're working with 64 bit
// ints with the canonical DSR.  We should test for rollover
// but lets do that later - cb

            case ARGUS_METRIC_INDEX: {
               struct ArgusMetricStruct *m1 = (struct ArgusMetricStruct *) ns1->dsrs[ARGUS_METRIC_INDEX];
               struct ArgusMetricStruct *m2 = (struct ArgusMetricStruct *) ns2->dsrs[ARGUS_METRIC_INDEX];

               if (m1 && m2) {
                  if (m1->hdr.type == 0) {
                     bcopy ((char *) m2, (char *) m1, sizeof (*m1));
                     break;
                  }

                  m1->src.pkts     -= m2->src.pkts;
                  m1->src.bytes    -= m2->src.bytes;
                  m1->src.appbytes -= m2->src.appbytes;
                  m1->dst.pkts     -= m2->dst.pkts;
                  m1->dst.bytes    -= m2->dst.bytes;
                  m1->dst.appbytes -= m2->dst.appbytes;
               }
               break;
            }


// Intersecting packet size object choses the smaller of the
// two values for psizemax and psizemin. opposite of merge - cb

            case ARGUS_PSIZE_INDEX: {
               struct ArgusPacketSizeStruct *p1 = (struct ArgusPacketSizeStruct *) ns1->dsrs[ARGUS_PSIZE_INDEX];
               struct ArgusPacketSizeStruct *p2 = (struct ArgusPacketSizeStruct *) ns2->dsrs[ARGUS_PSIZE_INDEX];

               if (p1 && p2) {
                  if (p1->src.psizemax > p2->src.psizemax)
                     p1->src.psizemax = p2->src.psizemax;

                  if (p1->src.psizemin < p2->src.psizemin)
                     p1->src.psizemin = p2->src.psizemin;
               }
               break;
            }

// Intersecting the aggregation object results in ns1 having
// a valid aggregation object, but without the updates
// from this merger.  So, if ns1 and ns2 have valid
// agr's, then just update ns1 fields.  If ns2 has an
// agr, but ns1 does not, then move ns2's agr to ns1.
// Do this by updating the canonical agr struct and
// then putting the pointer into the dsrs[].
   
// if neither, then add one to ns1 with a count of 1.

            case ARGUS_AGR_INDEX: {
               struct ArgusAgrStruct *a1 = (struct ArgusAgrStruct *) ns1->dsrs[ARGUS_AGR_INDEX];
               struct ArgusAgrStruct *a2 = (struct ArgusAgrStruct *) ns2->dsrs[ARGUS_AGR_INDEX];

               if (a1 && a2) {
                  a1->count += a2->count;
               } else {
                  if (!(a1 || a2)) {
                     if ((a1 = ArgusCalloc(1, sizeof(*a1))) == NULL)
                        ArgusLog (LOG_ERR, "ArgusIntersectRecords: ArgusCalloc error %s", strerror(errno));

                     a1->hdr.type            = ARGUS_AGR_DSR;
                     a1->hdr.subtype         = 0x01;
                     a1->hdr.argus_dsrvl8.qual = 0x01;
                     a1->hdr.argus_dsrvl8.len  = (sizeof(*agr) + 3)/4;
                     a1->count = 1;
                     ns1->dsrs[ARGUS_AGR_INDEX] = (struct ArgusDSRHeader *) a1;
                  } else
                  if (a2) {
                     if ((a1 = ArgusCalloc(1, sizeof(*a1))) == NULL)
                        ArgusLog (LOG_ERR, "ArgusIntersectRecords: ArgusCalloc error %s", strerror(errno));

                     bcopy((char *)a2, (char *)a1, sizeof(*a1));
                     a1->count++;
                  }
               }
               break;
            }

            case ARGUS_JITTER_INDEX: {
               struct ArgusJitterStruct *j1 = (struct ArgusJitterStruct *) ns1->dsrs[ARGUS_JITTER_INDEX];
               struct ArgusJitterStruct *j2 = (struct ArgusJitterStruct *) ns2->dsrs[ARGUS_JITTER_INDEX];

               if (j1 && j2) {
                  if (j2->src.act.n > 0) {
                     unsigned int n, stdev = 0;
                     double meanval, sumsqrd = 0.0;
                     
                     n = (j1->src.act.n + j2->src.act.n);
                     meanval  = (((double)j1->src.act.meanval * (double)j1->src.act.n) +
                                 ((double)j2->src.act.meanval * (double)j2->src.act.n)) / n;

                     if (j1->src.act.n) {
                        double sum  =  (double)j1->src.act.meanval * (double)j1->src.act.n;
                        sumsqrd += (j1->src.act.n * ((double)j1->src.act.stdev * (double)j1->src.act.stdev)) +
                                   (sum * sum)/j1->src.act.n;
                     }

                     if (j2->src.act.n) {
                        double sum  =  (double)j2->src.act.meanval * (double)j2->src.act.n;
                        sumsqrd += (j2->src.act.n * ((double)j2->src.act.stdev * (double)j2->src.act.stdev)) +
                                   (sum * sum)/j2->src.act.n;
                     }
                     stdev = (int) sqrt (fabs((sumsqrd/n) - ((double)meanval * (double)meanval)));

                     j1->src.act.n       = n;
                     j1->src.act.meanval = (unsigned int) meanval;
                     j1->src.act.stdev   = stdev;
                     if (j1->src.act.minval > j2->src.act.minval)
                        j1->src.act.minval = j2->src.act.minval;
                     if (j1->src.act.maxval < j2->src.act.maxval)
                        j1->src.act.maxval = j2->src.act.maxval;
                  }

                  if (j2->src.idle.n > 0) {
                     unsigned int n, stdev = 0;
                     double meanval, sumsqrd = 0.0;
                     
                     n = (j1->src.idle.n + j2->src.idle.n);
                     meanval  = (((double) j1->src.idle.meanval * (double) j1->src.idle.n) +
                                 ((double) j2->src.idle.meanval * (double) j2->src.idle.n)) / n;

                     if (j1->src.idle.n) {
                        double sum  =  (double) j1->src.idle.meanval * (double) j1->src.idle.n;
                        sumsqrd += (j1->src.idle.n * ((double)j1->src.idle.stdev * (double)j1->src.idle.stdev)) +
                                   ((double)sum *(double)sum)/j1->src.idle.n;
                     }

                     if (j2->src.idle.n) {
                        double sum  =  (double) j2->src.idle.meanval * (double) j2->src.idle.n;
                        sumsqrd += (j2->src.idle.n * ((double)j2->src.idle.stdev * (double)j2->src.idle.stdev)) +
                                   ((double)sum *(double)sum)/j2->src.idle.n;
                     }
                     stdev = (int) sqrt (fabs((sumsqrd/n) - ((double)meanval * (double)meanval)));

                     j1->src.idle.n       = n;
                     j1->src.idle.meanval = (unsigned int) meanval;
                     j1->src.idle.stdev   = stdev;
                     if (j1->src.idle.minval > j2->src.idle.minval)
                        j1->src.idle.minval = j2->src.idle.minval;
                     if (j1->src.idle.maxval < j2->src.idle.maxval)
                        j1->src.idle.maxval = j2->src.idle.maxval;
                  }

                  if (j2->dst.act.n > 0) {
                     unsigned int n, stdev = 0;
                     double meanval, sumsqrd = 0.0;
                     
                     n = (j1->dst.act.n + j2->dst.act.n);
                     meanval  = (((double) j1->dst.act.meanval * (double) j1->dst.act.n) +
                                 ((double) j2->dst.act.meanval * (double) j2->dst.act.n)) / n;

                     if (j1->dst.act.n) {
                        double sum  =  j1->dst.act.meanval * j1->dst.act.n;
                        sumsqrd += (j1->dst.act.n * ((double)j1->dst.act.stdev * (double)j1->dst.act.stdev)) +
                                   (sum * sum)/j1->dst.act.n;
                     }

                     if (j2->dst.act.n) {
                        double sum  =  (double) j2->dst.act.meanval * (double) j2->dst.act.n;
                        sumsqrd += (j2->dst.act.n * ((double)j2->dst.act.stdev * (double)j2->dst.act.stdev)) +
                                   ((double)sum *(double)sum)/j2->dst.act.n;
                     }
                     stdev = (int) sqrt (fabs((sumsqrd/n) - ((double)meanval * (double)meanval)));

                     j1->dst.act.n       = n;
                     j1->dst.act.meanval = (unsigned int) meanval;
                     j1->dst.act.stdev   = stdev;
                     if (j1->dst.act.minval > j2->dst.act.minval)
                        j1->dst.act.minval = j2->dst.act.minval;
                     if (j1->dst.act.maxval < j2->dst.act.maxval)
                        j1->dst.act.maxval = j2->dst.act.maxval;
                  }

                  if (j2->dst.idle.n > 0) {
                     unsigned int n, stdev = 0;
                     double meanval, sumsqrd = 0.0;
                     
                     n = (j1->dst.idle.n + j2->dst.idle.n);
                     meanval  = (((double) j1->dst.idle.meanval * (double) j1->dst.idle.n) +
                                 ((double) j2->dst.idle.meanval * (double) j2->dst.idle.n)) / n;

                     if (j1->dst.idle.n) {
                        int sum  =  (double) j1->dst.idle.meanval * (double) j1->dst.idle.n;
                        sumsqrd += (j1->dst.idle.n * ((double)j1->dst.idle.stdev * (double)j1->dst.idle.stdev)) +
                                   ((double)sum *(double)sum)/j1->dst.idle.n;
                     }

                     if (j2->dst.idle.n) {
                        double sum  =  (double) j2->dst.idle.meanval * (double) j2->dst.idle.n;
                        sumsqrd += (j2->dst.idle.n * ((double)j2->dst.idle.stdev * (double)j2->dst.idle.stdev)) +
                                   ((double)sum *(double)sum)/j2->dst.idle.n;
                     }
                     stdev = (int) sqrt (fabs((sumsqrd/n) - ((double)meanval * (double)meanval)));

                     j1->dst.idle.n       = n;
                     j1->dst.idle.meanval = (unsigned int) meanval;
                     j1->dst.idle.stdev   = stdev;
                     if (j1->dst.idle.minval > j2->dst.idle.minval)
                        j1->dst.idle.minval = j2->dst.idle.minval;
                     if (j1->dst.idle.maxval < j2->dst.idle.maxval)
                        j1->dst.idle.maxval = j2->dst.idle.maxval;
                  }

               } else
                  ns1->dsrs[ARGUS_JITTER_INDEX] = NULL;

               break;
            }

            case ARGUS_MAC_INDEX: {
               struct ArgusMacStruct *m1 = (struct ArgusMacStruct *) ns1->dsrs[ARGUS_MAC_INDEX];
               struct ArgusMacStruct *m2 = (struct ArgusMacStruct *) ns2->dsrs[ARGUS_MAC_INDEX];

               if (m1 && m2) {
                  struct ether_header *e1 = &m1->mac.mac_union.ether.ehdr;
                  struct ether_header *e2 = &m2->mac.mac_union.ether.ehdr;

                  if (bcmp(&e1->ether_shost, &e2->ether_shost, sizeof(e1->ether_shost)))
                     bzero ((char *)&e1->ether_shost, sizeof(e1->ether_shost));
                 
                  if (bcmp(&e1->ether_dhost, &e2->ether_dhost, sizeof(e1->ether_dhost)))
                     bzero ((char *)&e1->ether_dhost, sizeof(e1->ether_dhost));

               } else {
                  ns1->dsrs[ARGUS_MAC_INDEX] = NULL;
               }
               break;
            }
         }
      }
      ns1->status |= ARGUS_RECORD_MODIFIED;
   }

   return;
}

struct ArgusRecordStruct *ArgusSubtractRecord (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

struct ArgusRecordStruct *
ArgusSubtractRecord (struct ArgusRecordStruct *ns1, struct ArgusRecordStruct *ns2)
{
   struct ArgusRecordStruct *retn = ns1;

   if ((ns1 && ns2) && ((ns1->hdr.type & ARGUS_FAR) && (ns2->hdr.type & ARGUS_FAR))) {
      int i;
      for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
         switch (i) {

// Subtracting Flow records is a matter of testing each field and
// providing delta values where appropriate.  These apply to time,
// attributes, and metrics. but not things like flows.
//
// Subtracting Transport objects is tricky, since we normally subtract
// records from different probes.  So just leave this alone.

            case ARGUS_FLOW_INDEX:
            case ARGUS_TRANSPORT_INDEX: 
               break;

// Subtracing time objects may result in a change in the storage
// type of the time structure, from an ABSOLUTE_TIMESTAMP
// to an ABSOLUTE_RANGE, to hold the new ending time.

            case ARGUS_TIME_INDEX: {
               struct ArgusTimeObject *t1 = (struct ArgusTimeObject *) ns1->dsrs[ARGUS_TIME_INDEX];
               struct ArgusTimeObject *t2 = (struct ArgusTimeObject *) ns2->dsrs[ARGUS_TIME_INDEX];

               if (t1 && t2) {
                  t1->src.start.tv_sec  -= t2->src.start.tv_sec;
                  t1->src.start.tv_usec -= t2->src.start.tv_usec;
                  t1->src.end.tv_sec    -= t2->src.end.tv_sec;
                  t1->src.end.tv_usec   -= t2->src.end.tv_usec;
                  t1->dst.start.tv_sec  -= t2->dst.start.tv_sec;
                  t1->dst.start.tv_usec -= t2->dst.start.tv_usec;
                  t1->dst.end.tv_sec    -= t2->dst.end.tv_sec;
                  t1->dst.end.tv_usec   -= t2->dst.end.tv_usec;
               }
               break;
            }

// Subtracting metric objects is straight forward for all values.

            case ARGUS_METRIC_INDEX: {
               struct ArgusMetricStruct *m1 = (struct ArgusMetricStruct *) ns1->dsrs[ARGUS_METRIC_INDEX];
               struct ArgusMetricStruct *m2 = (struct ArgusMetricStruct *) ns2->dsrs[ARGUS_METRIC_INDEX];

               if (m1 && m2) {
                  m1->src.pkts     -= m2->src.pkts;
                  m1->src.bytes    -= m2->src.bytes;
                  m1->src.appbytes -= m2->src.appbytes;
                  m1->dst.pkts     -= m2->dst.pkts;
                  m1->dst.bytes    -= m2->dst.bytes;
                  m1->dst.appbytes -= m2->dst.appbytes;
               }
               break;
            }


// Subtracting networks objects involve subtracting the metrics
// that are embedded in the network dsrs.


            case ARGUS_NETWORK_INDEX: {
               struct ArgusNetworkStruct *n1 = (void *)ns1->dsrs[ARGUS_NETWORK_INDEX];
               struct ArgusNetworkStruct *n2 = (void *)ns2->dsrs[ARGUS_NETWORK_INDEX];

               if ((n1 != NULL) && (n2 != NULL)) {
                  if (n1->hdr.subtype == n2->hdr.subtype)
                  switch (n1->hdr.subtype) {
                     case ARGUS_TCP_INIT:
                     case ARGUS_TCP_STATUS:
                     case ARGUS_TCP_PERF: {
                        struct ArgusTCPObject *t1 = (struct ArgusTCPObject *)&n1->net_union.tcp;
                        struct ArgusTCPObject *t2 = (struct ArgusTCPObject *)&n2->net_union.tcp;

                        if (n1->hdr.argus_dsrvl8.len == 0) {
                           bcopy ((char *) n2, (char *) n1, sizeof (*n1));
                           break;
                        }

                        t1->src.ack      -= t2->src.ack;
                        t1->src.seq      -= t2->src.seq;

                        t1->src.winnum   -= t2->src.winnum;
                        t1->src.bytes    -= t2->src.bytes;
                        t1->src.retrans  -= t2->src.retrans;

                        t1->src.ackbytes -= t2->src.ackbytes;
                        t1->src.win      -= t2->src.win;
                        t1->src.winbytes -= t2->src.winbytes;

                        t1->dst.winnum   -= t2->dst.winnum;
                        t1->dst.bytes    -= t2->dst.bytes;
                        t1->dst.retrans  -= t2->dst.retrans;
                        t1->dst.ackbytes -= t2->dst.ackbytes;
                        t1->dst.win      -= t2->dst.win;
                        t1->dst.winbytes -= t2->dst.winbytes;

                        if (n1->hdr.subtype != n2->hdr.subtype) {
                           n1->hdr.subtype = ARGUS_TCP_PERF;
                           n1->hdr.argus_dsrvl8.len = (sizeof(*t1) + 3) / 4;
                        }
                        break;
                     }

                     case ARGUS_RTP_FLOW: {
                        struct ArgusRTPObject *r1 = &n1->net_union.rtp;
                        struct ArgusRTPObject *r2 = &n2->net_union.rtp;
                        r1->sdrop -= r2->sdrop;
                        r1->ddrop -= r2->ddrop;
                        break;
                     }

                     case ARGUS_ESP_DSR: {
                        struct ArgusESPObject *e1 = &n1->net_union.esp;
                        struct ArgusESPObject *e2 = &n2->net_union.esp;

                        e1->lastseq -= e2->lastseq;
                        e1->lostseq -= e2->lostseq;
                        if (e1->spi != e2->spi) {
                           e1->spi = 0;
                        }
                     }
                  }
               }
               break;
            }

// Subtracting packet size object is straightforward for each value.

            case ARGUS_PSIZE_INDEX: {
               struct ArgusPacketSizeStruct *p1 = (struct ArgusPacketSizeStruct *) ns1->dsrs[ARGUS_PSIZE_INDEX];
               struct ArgusPacketSizeStruct *p2 = (struct ArgusPacketSizeStruct *) ns2->dsrs[ARGUS_PSIZE_INDEX];

               if (p1 && p2) {
                  p1->src.psizemax -= p2->src.psizemax;
                  p1->src.psizemin -= p2->src.psizemin;
               }
               break;
            }

            case ARGUS_IPATTR_INDEX: {
               struct ArgusIPAttrStruct *attr1 = (struct ArgusIPAttrStruct *)ns1->dsrs[ARGUS_IPATTR_INDEX];
               struct ArgusIPAttrStruct *attr2 = (struct ArgusIPAttrStruct *)ns2->dsrs[ARGUS_IPATTR_INDEX];

               if (attr1 && attr2) {
                  attr1->src.tos -= attr2->src.tos;
                  attr1->src.ttl -= attr2->src.ttl;
                  attr1->dst.tos -= attr2->dst.tos;
                  attr1->dst.ttl -= attr2->dst.ttl;
               }
               break;
            }

// Subtracting the aggregation object seems interesting,
// but don't know what this means yet.

            case ARGUS_AGR_INDEX: {
               struct ArgusAgrStruct *a1 = (struct ArgusAgrStruct *) ns1->dsrs[ARGUS_AGR_INDEX];
               struct ArgusAgrStruct *a2 = (struct ArgusAgrStruct *) ns2->dsrs[ARGUS_AGR_INDEX];

               if (a1 && a2) {
               }
               ns1->dsrs[ARGUS_AGR_INDEX] = NULL;
               break;
            }

            case ARGUS_JITTER_INDEX: {
               struct ArgusJitterStruct *j1 = (struct ArgusJitterStruct *) ns1->dsrs[ARGUS_JITTER_INDEX];
               struct ArgusJitterStruct *j2 = (struct ArgusJitterStruct *) ns2->dsrs[ARGUS_JITTER_INDEX];

               if (j1 && j2) {
               }
               ns1->dsrs[ARGUS_JITTER_INDEX] = NULL;
               break;
            }

            case ARGUS_MAC_INDEX:
               break;
         }
      }
      ns1->status |= ARGUS_RECORD_MODIFIED;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "ArgusSubtractRecord (%p, %p) returning %p", ns1, ns2, retn);
#endif

   return (retn);
}

#define RATOPSTARTINGINDEX     0

void
ArgusCalculatePeriod (struct ArgusRecordStruct *ns, struct ArgusAdjustStruct *nadp)
{
   struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
   struct ArgusTimeObject *time = (void *)ns->dsrs[ARGUS_TIME_INDEX];

   if ((nadp->stperiod == 0.0) && (nadp->dtperiod == 0.0)) {
      if ((metric != NULL) && (time != NULL)) {
         long long sstime = (time->src.start.tv_sec * 1000000LL) + time->src.start.tv_usec;
         long long dstime = (time->dst.start.tv_sec * 1000000LL) + time->dst.start.tv_usec;
         long long setime = (time->src.end.tv_sec * 1000000LL) + time->src.end.tv_usec;
         long long detime = (time->dst.end.tv_sec * 1000000LL) + time->dst.end.tv_usec;

         nadp->stperiod = ((setime - sstime) * 1.0) / (nadp->size * 1.0);
         nadp->dtperiod = ((detime - dstime) * 1.0) / (nadp->size * 1.0);

// linear model 
         if (nadp->stperiod < 1.0) nadp->stperiod = 1.0;
         if (nadp->dtperiod < 1.0) nadp->dtperiod = 1.0;

         nadp->spkts     = (metric->src.pkts     / nadp->stperiod);
         nadp->sbytes    = (metric->src.bytes    / nadp->stperiod);
         nadp->sappbytes = (metric->src.appbytes / nadp->stperiod);

         nadp->dpkts     = (metric->dst.pkts     / nadp->dtperiod);
         nadp->dbytes    = (metric->dst.bytes    / nadp->dtperiod);
         nadp->dappbytes = (metric->dst.appbytes / nadp->dtperiod);
      }
   }
}


// ArgusAlignRecord is designed to snip records on hard time boundaries.
// What those time boundary's are, are specified in the ArgusAdjustStruct.
// The idea is that one specifies a time interval, and we try to find
// a time boundary to snip the records to.  If the bin size is 60s, we
// will clip on 1 minute boundaries.  
//
// A problem arises, when the boundary does not coincide with minute boundaries,
// as we have to decide where the starting boundary is, and then clip accordingly.
// So, as an example, if we are aligning on 90s boundaries (1.5m).  What is
// the correct starting point for the clipping?  Can't be on the hour, as 90s
// boundaries don't conincide with hourly boundaries.
//
// As a convention, if the boundary does not align well on minutes, we shall
// start on the yearly boundary, and adjust accordingly, so we find our
// current time, and adjust it so that the alignment bin is aligned with the
// beginning of the year.
//
// For intervals that are a fraction of a second, if the fraction is not
// an integral fraction, we need to do the same thing.


struct ArgusRecordStruct *ArgusAlignRecord(struct ArgusParserStruct *parser, struct ArgusRecordStruct *, struct ArgusAdjustStruct *);

void
ArgusAlignConfig(struct ArgusParserStruct *parser, struct ArgusAdjustStruct *nadp)
{

}


// Load up the ArgusAdjustStruct to deal with this specific record.


void
ArgusAlignInit(struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, struct ArgusAdjustStruct *nadp)
{
   struct timeval *start = &nadp->start;
   long long startusec = 0;
   struct timeval *end = &nadp->end;
   time_t tsec = 0;

   nadp->stperiod = 0.0;
   nadp->dtperiod = 0.0;
   nadp->trperiod = 0.0;

   nadp->startuSecs = ArgusFetchStartuSecTime(ns);
   nadp->enduSecs   = ArgusFetchLastuSecTime(ns);

   nadp->sploss = ArgusFetchPercentSrcLoss(ns);
   nadp->dploss = ArgusFetchPercentDstLoss(ns);

   startusec = nadp->startuSecs;

   if (start->tv_sec == 0) {
      if (parser->tflag) {
         start->tv_sec  = parser->startime_t.tv_sec;
         start->tv_usec = parser->startime_t.tv_usec;

         end->tv_sec    = parser->lasttime_t.tv_sec;
         end->tv_usec   = parser->lasttime_t.tv_usec;

         startusec = (start->tv_sec * 1000000LL) + start->tv_usec;

      } else {
         start->tv_sec  = nadp->startuSecs / 1000000;
         start->tv_usec = nadp->startuSecs % 1000000;

         end->tv_sec    = nadp->enduSecs / 1000000;
         end->tv_usec   = nadp->enduSecs % 1000000;

         startusec = nadp->startuSecs;
      }
   }

   tsec = start->tv_sec;

   if (nadp->value != 0) {
      switch (nadp->qual) {
         case ARGUSSPLITSECOND: {
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
            nadp->size = nadp->value * 1000000LL;
            break;
         }
         case ARGUSSPLITMINUTE: {
            long long val = tsec / (nadp->value * 60);
            tsec = val * (nadp->value * 60.0);
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

            nadp->size = nadp->value*60.0*1000000;
            break;
         }
         case ARGUSSPLITHOUR: {
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->RaStartTmStruct.tm_sec = 0;
            nadp->RaStartTmStruct.tm_min = 0;
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

            nadp->size = nadp->value*3600.0*1000000LL;
            break;
         }
         case ARGUSSPLITDAY: {
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->RaStartTmStruct.tm_sec = 0;
            nadp->RaStartTmStruct.tm_min = 0;
            nadp->RaStartTmStruct.tm_hour = 0;
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

            nadp->size = nadp->value*3600.0*24.0*1000000LL;
            break;
         }

         case ARGUSSPLITWEEK:   {
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->RaStartTmStruct.tm_sec = 0;
            nadp->RaStartTmStruct.tm_min = 0;
            nadp->RaStartTmStruct.tm_hour = 0;
            nadp->RaStartTmStruct.tm_mday = 1;
            nadp->RaStartTmStruct.tm_mon = 0;
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

            nadp->size = nadp->value*3600.0*24.0*7.0*1000000LL;
            break;
         }

         case ARGUSSPLITMONTH:  {
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->RaStartTmStruct.tm_sec = 0;
            nadp->RaStartTmStruct.tm_min = 0;
            nadp->RaStartTmStruct.tm_hour = 0;
            nadp->RaStartTmStruct.tm_mday = 1;
            nadp->RaStartTmStruct.tm_mon = 0;
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

            nadp->size = nadp->value*3600.0*24.0*7.0*4.0*1000000LL;
            break;
         }

         case ARGUSSPLITYEAR:   
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->RaStartTmStruct.tm_sec = 0;
            nadp->RaStartTmStruct.tm_min = 0;
            nadp->RaStartTmStruct.tm_hour = 0;
            nadp->RaStartTmStruct.tm_mday = 1;
            nadp->RaStartTmStruct.tm_mon = 0;
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

            nadp->size = nadp->value*3600.0*24.0*7.0*52.0*1000000LL;
            break;
      }
   }

   if (nadp->size > 0) {
      switch (nadp->qual) {
         case ARGUSSPLITDAY: {
            time_t fileSecs = startusec / 1000000;
            struct tm tmval;

            localtime_r(&fileSecs, &tmval);

#if defined(HAVE_TM_GMTOFF)
            fileSecs += tmval.tm_gmtoff;
#endif
            fileSecs = fileSecs / (nadp->size / 1000000);
            fileSecs = fileSecs * (nadp->size / 1000000);
#if defined(HAVE_TM_GMTOFF)
            fileSecs -= tmval.tm_gmtoff;
#endif

            nadp->startuSecs = fileSecs * 1000000LL;
            nadp->start.tv_sec  = fileSecs;
            nadp->start.tv_usec = 0;
            break;
         }

         case ARGUSSPLITHOUR:
         case ARGUSSPLITMINUTE:
         case ARGUSSPLITSECOND: {
            nadp->startuSecs = (startusec / nadp->size) * nadp->size;
            nadp->start.tv_sec  = nadp->startuSecs / 1000000;
            nadp->start.tv_usec = nadp->startuSecs % 1000000;
            break;
         }
      }
   }
}

int
ArgusAlignTime(struct ArgusParserStruct *parser, struct ArgusAdjustStruct *nadp, time_t *sec)
{
   int retn = 0;
   time_t tsec = *sec;

   if (nadp->value != 0) {
      switch (nadp->qual) {
         case ARGUSSPLITSECOND: {
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);
            nadp->size = nadp->value * 1000000LL;
            break;
         }
         case ARGUSSPLITMINUTE: {
            long long val = tsec / (nadp->value * 60);
            tsec = val * (nadp->value * 60.0);
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

            nadp->size = nadp->value*60.0*1000000;
            break;
         }
         case ARGUSSPLITHOUR: {
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->RaStartTmStruct.tm_sec = 0;
            nadp->RaStartTmStruct.tm_min = 0;
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

            nadp->size = nadp->value*3600.0*1000000LL;
            break;
         }
         case ARGUSSPLITDAY: {
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->RaStartTmStruct.tm_sec = 0;
            nadp->RaStartTmStruct.tm_min = 0;
            nadp->RaStartTmStruct.tm_hour = 0;
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

            nadp->size = nadp->value*3600.0*24.0*1000000LL;
            break;
         }

         case ARGUSSPLITWEEK:   {
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->RaStartTmStruct.tm_sec = 0;
            nadp->RaStartTmStruct.tm_min = 0;
            nadp->RaStartTmStruct.tm_hour = 0;
            nadp->RaStartTmStruct.tm_mday = 1;
            nadp->RaStartTmStruct.tm_mon = 0;
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

            nadp->size = nadp->value*3600.0*24.0*7.0*1000000LL;
            break;
         }

         case ARGUSSPLITMONTH:  {
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->RaStartTmStruct.tm_sec = 0;
            nadp->RaStartTmStruct.tm_min = 0;
            nadp->RaStartTmStruct.tm_hour = 0;
            nadp->RaStartTmStruct.tm_mday = 1;
            nadp->RaStartTmStruct.tm_mon = 0;
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

            nadp->size = nadp->value*3600.0*24.0*7.0*4.0*1000000LL;
            break;
         }

         case ARGUSSPLITYEAR:   
            localtime_r(&tsec, &nadp->RaStartTmStruct);
            nadp->RaStartTmStruct.tm_sec = 0;
            nadp->RaStartTmStruct.tm_min = 0;
            nadp->RaStartTmStruct.tm_hour = 0;
            nadp->RaStartTmStruct.tm_mday = 1;
            nadp->RaStartTmStruct.tm_mon = 0;
            nadp->start.tv_sec = mktime(&nadp->RaStartTmStruct);

            nadp->size = nadp->value*3600.0*24.0*7.0*52.0*1000000LL;
            break;
      }
   }
   return (retn);
}

struct ArgusRecordStruct *
ArgusAlignRecord(struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, struct ArgusAdjustStruct *nadp)
{
   struct ArgusRecordStruct *retn = NULL;
   struct ArgusMetricStruct *metric;
   struct ArgusTimeObject *time;
   struct ArgusAgrStruct *agr;
   long long startusec = 0, endusec = 0;

   if (nadp->size != 0) {
      startusec = ArgusFetchStartuSecTime(ns);
        endusec = ArgusFetchLastuSecTime(ns);

      if (nadp->startuSecs == 0) {
         if (nadp->size > 0) {
            switch (nadp->qual) {
               case ARGUSSPLITDAY: {
                  time_t fileSecs = startusec / 1000000;
                  struct tm tmval;

                  localtime_r(&fileSecs, &tmval);

#if defined(HAVE_TM_GMTOFF)
                  fileSecs += tmval.tm_gmtoff;
#endif
                  fileSecs = fileSecs / (nadp->size / 1000000);
                  fileSecs = fileSecs * (nadp->size / 1000000);
#if defined(HAVE_TM_GMTOFF)
                  fileSecs -= tmval.tm_gmtoff;
#endif

                  nadp->startuSecs = fileSecs * 1000000LL;
                  nadp->start.tv_sec  = fileSecs;
                  nadp->start.tv_usec = 0;
                  break;
               }

               case ARGUSSPLITHOUR:
               case ARGUSSPLITMINUTE:
               case ARGUSSPLITSECOND: {
                  nadp->startuSecs = (startusec / nadp->size) * nadp->size;
                  nadp->start.tv_sec  = nadp->startuSecs / 1000000;
                  nadp->start.tv_usec = nadp->startuSecs % 1000000;
                  break;
               }
            }
         }
      }

      switch (ns->hdr.type & 0xF0) {
         case ARGUS_MAR: {
            struct ArgusRecord *ar1 = (struct ArgusRecord *) ns->dsrs[0];

            if (!(nadp->modify)) {
               ns->status |= ARGUS_RECORD_PROCESSED;
               retn = ArgusCopyRecordStruct (ns);

            } else {
               if (nadp->size) {
                  struct ArgusRecord *ar2 = NULL;
                  struct ArgusTime  sSecs, eSecs;
                  long long ssecs = 0, esecs = 0;

                  long long value = (startusec - nadp->startuSecs) / nadp->size;

                  ssecs = (nadp->startuSecs + (value * nadp->size));
                  sSecs.tv_sec  = ssecs / 1000000;
                  sSecs.tv_usec = ssecs % 1000000;

                  esecs = (nadp->startuSecs + ((value + 1) * nadp->size));
                  eSecs.tv_sec  = esecs / 1000000;
                  eSecs.tv_usec = esecs % 1000000;

                  nadp->turns++;

                  if ((retn = ArgusCopyRecordStruct (ns)) == NULL)
                     return(retn);

                  ar2 = (struct ArgusRecord *) retn->dsrs[0];

// if this record doesn't extend beyound the boundary, then we're done.
                  if (endusec > esecs) {
                     long long tduration;
                     double ratio;

// OK, so we simply split to align the records in time, regardless of the metrics. We'll want to
// distribute some stats between all the resulting records.  Here its all based on the timestamps
                     if ((tduration = (endusec - startusec)) > nadp->size)
                        tduration = nadp->size;

                     ratio = ((tduration * 1.0) / (endusec - startusec) * 1.0);

                     ar2->argus_mar.pktsRcvd  *= ratio;
                     ar2->argus_mar.bytesRcvd *= ratio;
                     ar2->argus_mar.records   *= ratio;
                     ar2->argus_mar.flows     *= ratio;
                     ar2->argus_mar.dropped   *= ratio;

                     ar1->argus_mar.pktsRcvd  -= ar2->argus_mar.pktsRcvd;
                     ar1->argus_mar.bytesRcvd -= ar2->argus_mar.bytesRcvd;
                     ar1->argus_mar.records   -= ar2->argus_mar.records;
                     ar1->argus_mar.flows     -= ar2->argus_mar.flows;
                     ar1->argus_mar.dropped   -= ar2->argus_mar.dropped;

                     ar2->argus_mar.now        = eSecs;
                     ar1->argus_mar.startime   = eSecs;
                     retn->status |= ARGUS_RECORD_MODIFIED;

                  } else {
                     ns->status |= ARGUS_RECORD_PROCESSED;
                  }

                  if (nadp->hard) {
                     ar2->argus_mar.startime  = sSecs;
                     ar2->argus_mar.now       = eSecs;
                  }
               }
            }
            break;
         }

         case ARGUS_EVENT: {
            ns->status |= ARGUS_RECORD_PROCESSED;
            retn = ArgusCopyRecordStruct(ns);
            break;
         }

         case ARGUS_NETFLOW:
         case ARGUS_AFLOW:
         case ARGUS_FAR: {
            agr = (void *)ns->dsrs[ARGUS_AGR_INDEX];

            if ((time = (void *)ns->dsrs[ARGUS_TIME_INDEX]) != NULL) {
               if ((metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX]) != NULL) {
                  if ((metric->src.pkts + metric->dst.pkts) > 0) {
                     if (!(nadp->modify)) {
                        retn =  ArgusCopyRecordStruct(ns);
                        metric->src.pkts = 0;
                        metric->dst.pkts = 0;

                     } else {
                        struct ArgusMetricStruct *rmetric = NULL;
                        struct ArgusTimeObject *rtime = NULL;
                        struct ArgusAgrStruct *ragr = NULL;
                        struct timeval sSecs, eSecs;
                        long long ssecs = 0, esecs = 0;

                        long long value = (startusec - nadp->startuSecs) / nadp->size;

                        ssecs = (nadp->startuSecs + (value * nadp->size));
                        sSecs.tv_sec  = ssecs / 1000000;
                        sSecs.tv_usec = ssecs % 1000000;

                        esecs = (nadp->startuSecs + ((value + 1) * nadp->size));
                        eSecs.tv_sec  = esecs / 1000000;
                        eSecs.tv_usec = esecs % 1000000;

                        if ((metric->src.pkts + metric->dst.pkts) > 1) {
                           int count = 0, bytes = 0;

                           nadp->turns++;

                           if (nadp->size) {
                              if ((retn = ArgusCopyRecordStruct (ns)) == NULL)
                                 return(retn);

                              rmetric = (void *)retn->dsrs[ARGUS_METRIC_INDEX];
                              rtime = (void *)retn->dsrs[ARGUS_TIME_INDEX];
                              ragr = (void *)retn->dsrs[ARGUS_AGR_INDEX];

// if this record doesn't extend beyound the boundary, then we're done.
                              if (endusec > esecs) {
                                 if ((rmetric != NULL) && (rtime != NULL)) {

// if pkt count is 2, we split record into 2, with start and end time
// coming from the original packet so rtime get startime, and time
// gets endtime.  Need to adjust for whether packets are in the src or dst

                                    if ((count = (metric->src.pkts + metric->dst.pkts)) == 2) {
                                       if (metric->src.pkts == 1) {

// in this record, we will end up with two records, each with one packet each.  we don't
// worry which one is first, so just prepare the src flow, and leave the dst flow record for
// the next pass.  the rtime->src.start has the correct timestamp. just need to zero out
// the other values.  leave the time->dst intact, as that is what is needed for the next record

                                          rtime->hdr.subtype &= ~(ARGUS_TIME_MASK);
                                          rtime->hdr.subtype |= ARGUS_TIME_SRC_START;

                                          rtime->dst.start.tv_sec  = 0;
                                          rtime->dst.start.tv_usec = 0;
                                          rtime->dst.end.tv_sec    = 0;
                                          rtime->dst.end.tv_usec   = 0;

                                           time->hdr.subtype &= ~(ARGUS_TIME_MASK);
                                           time->hdr.subtype |= ARGUS_TIME_DST_START;

                                           time->src.start.tv_sec  = 0;
                                           time->src.start.tv_usec = 0;
                                           time->src.end.tv_sec    = 0;
                                           time->src.end.tv_usec   = 0;

                                          rmetric->dst.pkts        = 0;
                                          rmetric->dst.bytes       = 0;
                                          rmetric->dst.appbytes    = 0;

                                       } else {
// in this record, we have either 2 src pkts or 2 dst pkts.
                                          rtime->hdr.subtype &= ~(ARGUS_TIME_MASK);
                                           time->hdr.subtype &= ~(ARGUS_TIME_MASK);

                                          if (rmetric->src.pkts) {
                                             rtime->hdr.subtype |= ARGUS_TIME_SRC_START;
                                              time->hdr.subtype |= ARGUS_TIME_SRC_START;
                                             rmetric->src.pkts = 1;
                                             bytes = rmetric->src.bytes;
                                             rmetric->src.bytes /= 2;
                                             if (bytes & 0x01)
                                                rmetric->src.bytes += 1;
                                             bytes = rmetric->src.appbytes;
                                             rmetric->src.appbytes /= 2;

                                             if (bytes & 0x01)
                                                rmetric->src.appbytes += 1;
                                             rmetric->dst.pkts  = 0;
                                             rmetric->dst.bytes = 0;
                                             rmetric->dst.appbytes = 0;

                                             rtime->src.end  = rtime->src.start;
                                             time->src.start = time->src.end;

                                          } else {
                                             rtime->hdr.subtype |= ARGUS_TIME_DST_START;
                                              time->hdr.subtype |= ARGUS_TIME_DST_START;
                                             rmetric->dst.pkts = 1;
                                             bytes = rmetric->dst.bytes;
                                             rmetric->dst.bytes /= 2;
                                             if (bytes & 0x01)
                                                rmetric->dst.bytes += 1;
                                             bytes = rmetric->dst.appbytes;
                                             rmetric->dst.appbytes /= 2;

                                             if (bytes & 0x01)
                                                rmetric->dst.appbytes += 1;
                                             rmetric->src.bytes = 0;
                                             rmetric->src.appbytes = 0;

                                             rtime->dst.end  = rtime->dst.start;
                                             time->dst.start = time->dst.end;
                                          }
                                       }

                                       metric->src.pkts     -= rmetric->src.pkts;
                                       metric->src.bytes    -= rmetric->src.bytes;
                                       metric->src.appbytes -= rmetric->src.appbytes;
                                       metric->dst.pkts     -= rmetric->dst.pkts;
                                       metric->dst.bytes    -= rmetric->dst.bytes;
                                       metric->dst.appbytes -= rmetric->dst.appbytes;

                                       if ((ragr != NULL) && (ragr->count >= 1)) {
                                          ragr->count = 1;
                                          agr->count = 1;
                                       }

                                    } else {

// OK, so this isn't a simple split, so we'll need to distributed stats between
// the two resulting records.  Here we need to pay a lot of attention to the timestamps

                                       long long sstime = (rtime->src.start.tv_sec * 1000000LL) + rtime->src.start.tv_usec;
                                       long long dstime = (rtime->dst.start.tv_sec* 1000000LL)  + rtime->dst.start.tv_usec;
                                       long long setime = (rtime->src.end.tv_sec* 1000000LL)  + rtime->src.end.tv_usec;
                                       long long detime = (rtime->dst.end.tv_sec* 1000000LL)  + rtime->dst.end.tv_usec;
                                       double agrRatio;

                                       if ((nadp->stperiod == 0.0) && (nadp->dtperiod == 0.0)) {
                                          ArgusCalculatePeriod (ns, nadp);
                                          if (metric->src.pkts > 1)
                                             nadp->stduration = (nadp->stperiod)/(metric->src.pkts - 1);
                                          else
                                             nadp->stduration = 0.0;

                                          if (metric->dst.pkts > 1) 
                                             nadp->dtduration = (nadp->dtperiod)/(metric->dst.pkts - 1);
                                          else
                                             nadp->stduration = 0.0;

                                          nadp->scpkts = 0.0;
                                          nadp->dcpkts = 0.0;
                                       }

// first does this direction need adjustment, if xstime > esecs then we need to pass.
                                       if (sstime > esecs) {
                                          rtime->src.start.tv_sec  = 0;
                                          rtime->src.start.tv_usec = 0;
                                          rtime->src.end.tv_sec    = 0;
                                          rtime->src.end.tv_usec   = 0;
                                          rmetric->src.pkts        = 0;
                                          rmetric->src.bytes       = 0;
                                          rmetric->src.appbytes    = 0;
                                          rtime->hdr.subtype &= ~(ARGUS_TIME_SRC_START | ARGUS_TIME_SRC_END);
                                       } else {
                                          if (setime > esecs) {
                                             rtime->src.end.tv_sec   = eSecs.tv_sec;
                                             rtime->src.end.tv_usec  = eSecs.tv_usec;
                                             rtime->hdr.subtype     |= (ARGUS_TIME_SRC_START | ARGUS_TIME_SRC_END);
                                             time->src.start         = rtime->src.end;
                                             time->hdr.subtype      |= (ARGUS_TIME_SRC_START | ARGUS_TIME_SRC_END);
                                          } else {
                                             time->src.start.tv_sec  = 0;
                                             time->src.start.tv_usec = 0;
                                             time->src.end.tv_sec    = 0;
                                             time->src.end.tv_usec   = 0;
                                             time->hdr.subtype &=  ~(ARGUS_TIME_SRC_START | ARGUS_TIME_SRC_END);
                                             nadp->stduration = 0;
                                          }
                                       }

                                       if (dstime > esecs) {
                                          rtime->dst.start.tv_sec  = 0;
                                          rtime->dst.start.tv_usec = 0;
                                          rtime->dst.end.tv_sec    = 0;
                                          rtime->dst.end.tv_usec   = 0;
                                          rmetric->dst.pkts        = 0;
                                          rmetric->dst.bytes       = 0;
                                          rmetric->dst.appbytes    = 0;
                                          rtime->hdr.subtype &= ~(ARGUS_TIME_DST_START | ARGUS_TIME_DST_END);

                                       } else {
                                          if (detime > esecs) {
                                             rtime->dst.end.tv_sec   = eSecs.tv_sec;
                                             rtime->dst.end.tv_usec  = eSecs.tv_usec;
                                             rtime->hdr.subtype     |= (ARGUS_TIME_DST_START | ARGUS_TIME_DST_END);
                                             time->dst.start         = rtime->dst.end;
                                             time->hdr.subtype      |= (ARGUS_TIME_DST_START | ARGUS_TIME_DST_END);

                                          } else {
                                             time->dst.start.tv_sec  = 0;
                                             time->dst.start.tv_usec = 0;
                                             time->dst.end = time->dst.start;
                                             time->hdr.subtype &=  ~(ARGUS_TIME_DST_START | ARGUS_TIME_DST_END);
                                             nadp->dtduration = 0;
                                          }
                                       }

                                       if (rtime->src.start.tv_sec && rmetric->src.pkts) {
                                          long long thisBytes = 0, thisAppBytes = 0, thisCount = 0;
                                          long long tduration, rduration;
                                          long long tsstime, tsetime;
                                          double pkts, ratio;
                                          double iptr;

                                          tsstime = (rtime->src.start.tv_sec * 1000000LL) + rtime->src.start.tv_usec;
                                          tsetime = (rtime->src.end.tv_sec * 1000000LL) + rtime->src.end.tv_usec;

                                          if ((tduration = (tsetime - tsstime)) > nadp->size)
                                             tduration = nadp->size;

                                          if ((rduration = (setime - sstime)) > nadp->size)
                                             rduration = nadp->size;

                                          pkts = ((nadp->spkts + nadp->scpkts) * (tduration * 1.0))/(rduration * 1.0);

// add carry from last accumluation 
                                          modf(pkts, &iptr);
                                       
                                          thisCount = iptr;

                                          if (thisCount > rmetric->src.pkts)
                                             thisCount = rmetric->src.pkts;

                                          if (thisCount < 1)
                                             thisCount = 1;

                                          if (thisCount == 0) {
                                             if (nadp->turns == 1) {
                                                thisCount = 1;
                                                nadp->scpkts += (thisCount * 1.0) - nadp->spkts;
                                             } else {
                                                nadp->scpkts += nadp->spkts;
                                             }

                                          } else 
                                             nadp->scpkts += ((nadp->spkts * (tduration * 1.0))/(rduration * 1.0)) - (thisCount * 1.0);

                                          ratio        = ((thisCount * 1.0)/nadp->spkts);
                                          thisBytes    = nadp->sbytes    * ratio;
                                          thisAppBytes = nadp->sappbytes * ratio;

                                          rmetric->src.pkts     = thisCount;
                                          rmetric->src.bytes    = thisBytes;
                                          rmetric->src.appbytes = thisAppBytes;
                                       }

                                       if (rtime->dst.start.tv_sec && rmetric->dst.pkts) {
                                          long long thisBytes = 0, thisAppBytes = 0, thisCount = 0;
                                          long long tduration, rduration;
                                          long long tdstime, tdetime;
                                          double ratio, pkts;
                                          double iptr;

                                          tdstime = (rtime->dst.start.tv_sec * 1000000LL) + rtime->dst.start.tv_usec;
                                          tdetime = (rtime->dst.end.tv_sec * 1000000LL) + rtime->dst.end.tv_usec;

                                          if ((tduration = (tdetime - tdstime)) > nadp->size)
                                             tduration = nadp->size;

                                          if ((rduration = (detime - dstime)) > nadp->size)
                                             rduration = nadp->size;


                                          pkts = ((nadp->dpkts + nadp->dcpkts) * (tduration * 1.0))/(rduration * 1.0);
// add carry from last accumluation 
                                          modf(pkts, &iptr);

                                          thisCount = iptr;

                                          if (thisCount > rmetric->dst.pkts)
                                             thisCount = rmetric->dst.pkts;

                                          if ((thisCount < 1))
                                             thisCount = 1;

                                          if (thisCount == 0) {
                                             if (nadp->turns == 1) {
                                                thisCount = 1;
                                                nadp->dcpkts += (thisCount * 1.0) - nadp->dpkts;
                                             } else {
                                                nadp->dcpkts += nadp->dpkts;
                                             }

                                          } else
                                             nadp->dcpkts += ((nadp->dpkts * (tduration * 1.0))/(rduration * 1.0)) - (thisCount * 1.0);

                                          ratio        = ((thisCount * 1.0)/nadp->dpkts);
                                          thisBytes    = nadp->dbytes * ratio;
                                          thisAppBytes = nadp->dappbytes * ratio;

                                          rmetric->dst.pkts     = thisCount;
                                          rmetric->dst.bytes    = thisBytes;
                                          rmetric->dst.appbytes = thisAppBytes;
                                       }

                                       agrRatio = ((rmetric->src.pkts + rmetric->dst.pkts) * 1.0)/((metric->src.pkts + metric->dst.pkts) * 1.0);

                                       if ((ragr != NULL) && (agr != NULL)) {
                                          if (agr->count > 1) {
                                             ragr->count = agr->count * agrRatio;
                                             if (ragr->count == 0) {
                                                if ((rmetric->src.pkts + rmetric->dst.pkts) > 0)
                                                   ragr->count = 1;
                                             }
                                             agr->count -= ragr->count;
                                          } else {
                                             ragr->count = agr->count;
                                          }
                                       }

                                       metric->src.pkts  -= rmetric->src.pkts;
                                       metric->src.bytes -= rmetric->src.bytes;
                                       metric->src.appbytes -= rmetric->src.appbytes;

                                       metric->dst.pkts  -= rmetric->dst.pkts;
                                       metric->dst.bytes -= rmetric->dst.bytes;
                                       metric->dst.appbytes -= rmetric->dst.appbytes;

                                       if ((metric->src.pkts == 0) && (metric->src.bytes > 0)) {
                                          if (rmetric->src.pkts > 1) {
                                             rmetric->src.pkts--;
                                             metric->src.pkts++;
                                          } else {
                                             rmetric->src.bytes += metric->src.bytes;
                                             rmetric->src.appbytes += metric->src.appbytes;
                                          }
                                       }

                                       if ((metric->dst.pkts == 0) && (metric->dst.bytes > 0)) {
                                          if (rmetric->dst.pkts > 1) {
                                             rmetric->dst.pkts--;
                                             metric->dst.pkts++;
                                          } else {
                                             rmetric->dst.bytes += metric->dst.bytes;
                                             rmetric->dst.appbytes += metric->dst.appbytes;
                                          }
                                       }

                                       if ((rmetric->src.pkts + rmetric->dst.pkts) == 1)  {
                                          rtime->src.end = rtime->src.start;
                                          rtime->dst.end = rtime->dst.start;
                                       }

                                       if ((metric->src.pkts > 1) && nadp->stduration) {
                                          struct timeval dtime, diff;
                                          long long tratio, useconds;

                                          tratio = (nadp->stduration * rmetric->src.pkts) * nadp->size;
                                          sstime += tratio;
                                          dtime.tv_sec  = sstime / 1000000;
                                          dtime.tv_usec = sstime % 1000000;

                                          RaDiffTime(&dtime, (struct timeval *)&time->src.start, &diff);
                                          useconds = (diff.tv_sec * 1000000) + diff.tv_usec;

                                          if (useconds >= nadp->size) {
                                             time->src.start.tv_sec  = dtime.tv_sec;
                                             time->src.start.tv_usec = dtime.tv_usec;
                                          }

                                       } else {
                                          if (metric->src.pkts == 1) {
                                             time->src.start.tv_sec  = time->src.end.tv_sec;
                                             time->src.start.tv_usec = time->src.end.tv_usec;
                                          }
                                       }
                                       if ((metric->dst.pkts > 1) && nadp->dtduration) {
                                          struct timeval dtime, diff;
                                          long long tratio, useconds;

                                          tratio = (nadp->dtduration * rmetric->dst.pkts) * nadp->size;
                                          dstime += tratio;
                                          dtime.tv_sec  = dstime / 1000000;
                                          dtime.tv_usec = dstime % 1000000;

                                          RaDiffTime(&dtime, (struct timeval *)&time->dst.start, &diff);
                                          useconds = diff.tv_sec * 1000000 + diff.tv_usec;
                                          if (useconds >= nadp->size) {
                                             time->dst.start.tv_sec  = dtime.tv_sec;
                                             time->dst.start.tv_usec = dtime.tv_usec;
                                          }
                                       } else {
                                          if (metric->dst.pkts == 1) {
                                             time->dst.start.tv_sec  = time->dst.end.tv_sec;
                                             time->dst.start.tv_usec = time->dst.end.tv_usec;
                                          }
                                       }
                                    }
                                    retn->status |= ARGUS_RECORD_MODIFIED;
                                 }

                              } else {
                                 metric->src.pkts = 0;
                                 metric->dst.pkts = 0;
                                 retn->status |= ARGUS_RECORD_MODIFIED;
                              }
                           }

                        } else {
                           if ((metric->src.pkts + metric->dst.pkts) == 1) {
                              if ((retn = ArgusCopyRecordStruct (ns)) == NULL)
                                 return(retn);

                              rmetric = (void *)retn->dsrs[ARGUS_METRIC_INDEX];
                              rtime = (void *)retn->dsrs[ARGUS_TIME_INDEX];
                              ragr = (void *)retn->dsrs[ARGUS_AGR_INDEX];

                              nadp->turns++;
                              metric->src.pkts = 0;
                              metric->dst.pkts = 0;
                              retn->status |= ARGUS_RECORD_MODIFIED;
                           }
                        }

                        if (nadp->hard) {
                           rtime->src.start.tv_sec  = sSecs.tv_sec;
                           rtime->src.start.tv_usec = sSecs.tv_usec;
                           rtime->dst.start         = rtime->src.start;

                           rtime->src.end.tv_sec    = eSecs.tv_sec;
                           rtime->src.end.tv_usec   = eSecs.tv_usec;
                           rtime->dst.end           = rtime->src.end;
                           rtime->hdr.argus_dsrvl8.len = (sizeof(*rtime) + 3)/4; 

                           rtime->hdr.subtype |= (ARGUS_TIME_SRC_START | ARGUS_TIME_SRC_END);
                           retn->status |= ARGUS_RECORD_MODIFIED;
                        }
                     }
                     if (nadp->sploss > 0)
                        ArgusAdjustSrcLoss(ns, retn, nadp->sploss);
                     if (nadp->dploss > 0)
                        ArgusAdjustDstLoss(ns, retn, nadp->dploss);

                  } else
                     nadp->turns = 0;
               } else
                  nadp->turns = 0;
            }
         }
      }

   } else {
      if (!(ns->status & ARGUS_RECORD_PROCESSED)) {
         ns->status |= ARGUS_RECORD_PROCESSED;
         retn = ArgusCopyRecordStruct (ns);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusAlignRecord () returning %p\n", retn); 
#endif
   return(retn);
}


// ArgusInsertRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
//    This routine takes an ArgusRecordStruct and inserts it into the current
//    array structure that is held in the RaBinProcessStruct *RaBinProcess.
//
//    If the structure has not been initialized, this routines initializes
//    the RaBinProcess by allocating an array of sufficient size in order
//    to accomodate a number of insertions, ARGUSMINARRAYSIZE.  If the mode
//    is ARGUSSPLITTIME, then the start value will be the start time in seconds
//    of the first record seen.  If any adjustments need to be made, they
//    need to be done prior to calling ArgusInsertRecord().
//
//    The array strategy is to assume that records will not come in order,
//    so we'll allocate a number of slots for a negative index insertion.
//    If the array is not large enough, we'll allocate more space as we go.
//
// struct RaBinStruct {
//    int status, timeout; 
//    double value, size;
//    struct ArgusQueueStruct *queue;
//    struct ArgusHashTable hashtable;
// };
// 
// struct RaBinProcessStruct {
//    unsigned int status, start, end, size;
//    int arraylen, len, count, index;  
//    struct RaBinStruct **array;
// 
//    struct ArgusAdjustStruct *nadp;
// };
//
// The concept here is to insert a record into an array, based on an aggregation
// strategy.  There are two strategies, one where a bin is defined by mode
// specifiers on the command line, and the other is where there is no
// definition, and you want to insert the record into a one second bin
// specified by the starting seconds in the record.
//
// So the issues are to create the array using the rbps to provide hints.
// Indicate the starting and ending points for the array, and then insert
// the record so that it is in the 'bin' it belongs.
// 
// Depending on the mode of operation, use either the rbps->nadp to tell
// us which time bin were in (nadp.RaStartTmStruct and nadp.RaEndTmStruct),
// or use the ns->canon.time.src.start.tv_sec to determine the bin.
//
// Usually the TmStructs do the right thing, as the program has called
// routines like ArgusAlignRecord() which sets up the TmStructs to
// be the bounding regions for the bin the record should go in.
//


#define ARGUSMINARRAYSIZE      0x400
void ArgusShiftArray (struct ArgusParserStruct *, struct RaBinProcessStruct *, int, int);

void
ArgusShiftArray (struct ArgusParserStruct *parser, struct RaBinProcessStruct *rbps, int num, int lock)
{
   if (num > 0) {
      struct RaBinStruct *bin;
      int i, step;

#if defined(ARGUS_THREADS)
      if (lock == ARGUS_LOCK)
         pthread_mutex_lock(&rbps->lock);
#endif

      for (i = 0; i < num; i++)
         if ((bin = rbps->array[rbps->index + i]) != NULL)
            RaDeleteBin(parser, rbps, rbps->index);
 
      for (i = rbps->index, step = (rbps->arraylen - num); i < step; i++)
         rbps->array[i] = rbps->array[i + num];

      for (i = rbps->arraylen - num; i < rbps->arraylen; i++)
         rbps->array[i] = NULL;

      rbps->start  += rbps->size * num;
      rbps->end    += rbps->size * num;

      rbps->startpt.tv_sec  = rbps->start / 1000000;
      rbps->startpt.tv_usec = rbps->start % 1000000;

      rbps->endpt.tv_sec    = rbps->end / 1000000;
      rbps->endpt.tv_usec   = rbps->end % 1000000;

      rbps->max -= num;

#if defined(ARGUS_THREADS)
      if (lock == ARGUS_LOCK)
         pthread_mutex_unlock(&rbps->lock);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusShiftArray (%p, %p) shifted array %d slot(s)\n", parser, rbps, num); 
#endif
}


// ArgusInsertRecord - this routine takes an rbps structure with an argus record and an offset
//                     and inserts it into a time based array.  The rbps holds the notion of the
//                     start and end range of the array, and the size of the bins.  From this
//                     you should be able to figure out if there is an index to put the 
//                     record in, or if we need to adjust the array to accept the record.
//                     
//                     ArgusInsertRecord returns 1 for an insertion, 0 for an update, -1 for an error.

int
ArgusInsertRecord (struct ArgusParserStruct *parser, struct RaBinProcessStruct *rbps, struct ArgusRecordStruct *argus, int offset,  struct ArgusRecordStruct **rec)
{
   struct ArgusAggregatorStruct *agg = NULL;
   struct RaBinStruct *bin = NULL;
   long long val = 0;
   int retn = -1, ind = 0;

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&rbps->lock);
#endif

   if (rbps && argus) {
      if (rbps->array == NULL) {
         if ((rbps->arraylen = rbps->nadp.count + offset + RATOPSTARTINGINDEX + 1) == 0)
            rbps->arraylen = ARGUSMINARRAYSIZE;

         rbps->len      = rbps->arraylen;
         rbps->index    = offset;
         rbps->max      = 0;

         if ((rbps->array = (struct RaBinStruct **) ArgusCalloc(sizeof(void *), rbps->len + 1)) == NULL)
            ArgusLog (LOG_ERR, "ArgusInsertRecord: ArgusCalloc error %s", strerror(errno));
      }

      if (rbps->startpt.tv_sec == 0) {
         if (rbps->nadp.start.tv_sec == 0) {
            if (rbps->nadp.RaStartTmStruct.tm_year == 0) {
               time_t tsec = parser->ArgusGlobalTime.tv_sec;

               localtime_r(&tsec, &rbps->nadp.RaStartTmStruct);
            }

            rbps->startpt.tv_sec = mktime(&rbps->nadp.RaStartTmStruct);
            rbps->endpt.tv_sec = rbps->startpt.tv_sec + (rbps->nadp.count * rbps->nadp.size)/1000000;

         } else {
            rbps->startpt = rbps->nadp.start;
            if ((rbps->nadp.end.tv_sec) == 0) {
               rbps->endpt.tv_sec = rbps->startpt.tv_sec + (rbps->nadp.count * rbps->nadp.size)/1000000;
            } else {
               rbps->endpt = rbps->nadp.end;
            }
         }

#ifdef ARGUSDEBUG
         ArgusDebug (3, "ArgusInsertRecord (%p, %p) initializing array\n", rbps, argus); 
#endif
      }

      if (rbps->start == 0.0) {
         long long tval = 0;
         if (rbps->nadp.qual) {
            switch (rbps->nadp.qual) {
               case ARGUSSPLITDAY: {
                  time_t fileSecs = rbps->startpt.tv_sec;
                  struct tm tmval;

                  localtime_r(&fileSecs, &tmval);
#if defined(HAVE_TM_GMTOFF)
                  fileSecs += tmval.tm_gmtoff;
#endif
                  fileSecs = fileSecs / (rbps->nadp.size / 1000000);
                  fileSecs = fileSecs * (rbps->nadp.size / 1000000);
#if defined(HAVE_TM_GMTOFF)
                  fileSecs -= tmval.tm_gmtoff;
#endif
                  rbps->start = fileSecs * 1000000LL;
                  rbps->end   = rbps->start + rbps->nadp.size;
                  break;
               }

               case ARGUSSPLITHOUR:
               case ARGUSSPLITMINUTE:
               case ARGUSSPLITSECOND: {
                  tval = ((rbps->startpt.tv_sec * 1000000LL) + rbps->startpt.tv_usec) / rbps->nadp.size;
                  rbps->start = tval * rbps->nadp.size;
                  tval = ((rbps->endpt.tv_sec * 1000000LL) + rbps->endpt.tv_usec) / rbps->nadp.size;
                  rbps->end   = tval * rbps->nadp.size;
                  break;
               }
            }

         } else {
            rbps->start = ((rbps->startpt.tv_sec * 1000000LL) + rbps->startpt.tv_usec);
         }
      }

/*
      if (parser->tflag) {
         if (rbps->array[0] == NULL) {
            int i;
            for (i = 0; i < rbps->arraylen; i++) {
               if ((rbps->array[i] = RaNewBin(parser, rbps, NULL, (rbps->start + (i * rbps->size)), RATOPSTARTINGINDEX)) == NULL)
                  ArgusLog (LOG_ERR, "ArgusInsertRecord: RaNewBin error %s", strerror(errno));
            }
         }
      }
*/

// set the current records value and index for insertion into array.

      switch (rbps->nadp.mode) {
         default: 
         case ARGUSSPLITRATE:
         case ARGUSSPLITTIME: {
            if (parser->RaWildCardDate) {
               struct tm stmbuf,  *stm;
               time_t tsec;
               int i = 0;

               val = ArgusFetchStartTime(argus);
               tsec = val;
               stm  = localtime_r (&tsec, &stmbuf);

               for (i = 0; i < RAMAXWILDCARDFIELDS; i++) {
                  if (parser->RaWildCardDate & (1 << i)) {
                     switch (i) {
                        case RAWILDCARDYEAR: {
                           stm->tm_year = 70;
                           break;
                        }
                        case RAWILDCARDMONTH: {
                           stm->tm_mon = 0;
                           break;
                        }
                        case RAWILDCARDDAY: {
                           stm->tm_mday = 1;
                           break;
                        }
                        case RAWILDCARDHOUR: {
                           stm->tm_hour = 0;
                           break;
                        }
                        case RAWILDCARDMIN: {
                           stm->tm_min = 0;
                           break;
                        }
                        case RAWILDCARDSEC: {
                           stm->tm_sec = 0;
                           break;
                        }
                     }
                  }
               }

               tsec = mktime (stm);
               val = (tsec * 1000000LL);

            } else 
               val = ArgusFetchStartuSecTime(argus);

            break;
         }

         case ARGUSSPLITSIZE:
         case ARGUSSPLITCOUNT: {
            val = rbps->start + (rbps->size * (rbps->index - RATOPSTARTINGINDEX));
            break;
         }
      }

// using val, calculate the index offset for this record 

      switch (rbps->nadp.mode) {
         default:
         case ARGUSSPLITRATE:
         case ARGUSSPLITTIME:
         case ARGUSSPLITSIZE: {
            if (rbps->size > 0) {
               if ((rbps->size > 0) && ((val - rbps->start) >= 0)) {
                  int i = ((val - rbps->start)/rbps->size);
                  ind = rbps->index + i;
               } else
                  ind = -1;
            }
            break;
         }
         case ARGUSSPLITCOUNT: {
            if (rbps->size > 0) {
               double frac, iptr, val = ((rbps->count + 1) / rbps->size);

               frac = modf(val, &iptr);

               if (!(frac))
                  rbps->index++;

               ind = rbps->index + ((val - rbps->start) / rbps->size);
            }
            break;
         }
      }

      if (ind < 0) {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusInsertRecord (%p, %p) array too short ind %d index %d", rbps, argus, ind, rbps->index); 
#endif
      } else {

// here is where we do a lot of array and queue management.  we want
// to get the rbps->array set up right, as it is our time series
// buffer, so we want to shift the record so that it represents
// now, and however many seconds back is needed to cover the period
// of the "-M rate %d:%d[smhdwMy]" needed.
//
// So in ArgusProcessQueue(), we will manage the arrays but that is
// in a periodic fashion.  Here, we have data, and so it is also
// a driver for correcting the array series.  We need to shift array
// members, and delete bins to get the current time correct.
//
// We could use this as a hint to correct the array to current time,
// but because ArgusGlobalTime and ArgusLastTime are not necessarily
// in sync, go ahead and let the actual data drive the array corrections,
// and let ArgusProcessQueue, do its thing to get the array aligned with
// ArgusGlobalTime.
//
// at this point we're ready to add the record to the array.
// test if the array has a bin struct, if not add one, then
// add the record to the bin struct, based on the split mode.

         if (ind >= rbps->arraylen) {
            struct RaBinStruct **newarray;
            int i, cnt = ((ind + ARGUSMINARRAYSIZE)/ARGUSMINARRAYSIZE) * ARGUSMINARRAYSIZE;

            if ((newarray = (void *) ArgusCalloc (sizeof(struct RaBinStruct *), cnt)) == NULL)
               ArgusLog (LOG_ERR, "ArgusInsertRecord: ArgusCalloc error %s", strerror(errno));

            for (i = 0; i < rbps->arraylen; i++)
               newarray[i] = rbps->array[i];

            ArgusFree(rbps->array);
            rbps->array = newarray;
            rbps->arraylen = cnt;
            rbps->len = cnt;
         }

         if ((bin = rbps->array[ind]) == NULL) {
            if (ind > rbps->max)
               rbps->max = ind;

            if ((rbps->array[ind] = RaNewBin(parser, rbps, argus,
                                             /* knock rbps->index off of ind so that the record
                                              * falls within the bin boundaries. */
                                             (rbps->start + ((ind - rbps->index) * rbps->size)),
                                             RATOPSTARTINGINDEX)) == NULL)
               ArgusLog (LOG_ERR, "ArgusInsertRecord: RaNewBin error %s", strerror(errno));

            rbps->count++; /* the number of used array entries */
            bin = rbps->array[ind];

            if (rbps->end < bin->value) {
               rbps->end = bin->value;

               if ((rbps->endpt.tv_sec  < bin->etime.tv_sec) || 
                  ((rbps->endpt.tv_sec == bin->etime.tv_sec) && 
                   (rbps->endpt.tv_usec < bin->etime.tv_usec)))
                  rbps->endpt = bin->etime;
            }
         }

         if ((agg = bin->agg) != NULL) {
            int found = 0;

            while (agg && !found) {
               int tretn = 0, fretn = -1, lretn = -1;
               if (agg->filterstr) {
                  struct nff_insn *fcode = agg->filter.bf_insns;
                  fretn = ArgusFilterRecord (fcode, argus);
               }

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

               tretn = (lretn < 0) ? ((fretn < 0) ? 1 : fretn) : ((fretn < 0) ? lretn : (lretn && fretn));

               if (tretn != 0) {
                  struct ArgusRecordStruct *tns, *ns;
                  struct ArgusHashStruct *hstruct = NULL;

                  ns = ArgusCopyRecordStruct(argus);

                  if (agg->labelstr)
                     ArgusAddToRecordLabel(parser, ns, agg->labelstr);

                  if (agg->mask) {
                     if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
                        agg->rap = agg->drap;

                     ArgusGenerateNewFlow(agg, ns);
                     agg->ArgusMaskDefs = NULL;

                     if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL) {
                        if ((tns = ArgusFindRecord(agg->htable, hstruct)) == NULL) {
                           struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
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
                                 if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL) {
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

                                       hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct);

                                    } else {    // OK, so we have a match (tns) that is the reverse of the current flow (ns)
                                                // Need to decide which direction wins.

                                       struct ArgusNetworkStruct *nnet = (struct ArgusNetworkStruct *)ns->dsrs[ARGUS_NETWORK_INDEX];
                                       struct ArgusNetworkStruct *tnet = (struct ArgusNetworkStruct *)tns->dsrs[ARGUS_NETWORK_INDEX];

                                       switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                          case ARGUS_TYPE_IPV4: {
                                             switch (flow->ip_flow.ip_p) {
                                                case IPPROTO_TCP: {
                                                   if ((nnet != NULL) && (tnet != NULL)) {
                                                      struct ArgusTCPObject *ntcp = &nnet->net_union.tcp;
                                                      struct ArgusTCPObject *ttcp = &tnet->net_union.tcp;

// first if both flows have syn, then don't merge;
                                                      if ((ntcp->status & ARGUS_SAW_SYN) && (ttcp->status & ARGUS_SAW_SYN)) {
                                                         tns = NULL;
                                                      } else {
                                                         if ((ntcp->status & ARGUS_SAW_SYN) ||
                                                            ((ntcp->status & ARGUS_SAW_SYN_SENT) && (ntcp->status & ARGUS_CON_ESTABLISHED))) {
                                                            struct ArgusFlow *tflow = (struct ArgusFlow *) tns->dsrs[ARGUS_FLOW_INDEX];
                                                            ArgusRemoveHashEntry(&tns->htblhdr);
                                                            ArgusReverseRecord (tns);
                                                            hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                                            tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                                            tflow->hdr.subtype &= ~ARGUS_REVERSE;
                                                            tflow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
                                                         } else
                                                            ArgusReverseRecord (ns);
                                                      }
                                                   }
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
                                                   if ((nnet != NULL) && (tnet != NULL)) {
                                                      struct ArgusTCPObject *ntcp = &nnet->net_union.tcp;
                                                      struct ArgusTCPObject *ttcp = &tnet->net_union.tcp;

// first if both flows have syn, then don't merge;
                                                      if ((ntcp->status & ARGUS_SAW_SYN) && (ttcp->status & ARGUS_SAW_SYN)) {
                                                         tns = NULL;
                                                      } else {
                                                         if ((ntcp->status & ARGUS_SAW_SYN) ||
                                                            ((ntcp->status & ARGUS_SAW_SYN_SENT) && (ntcp->status & ARGUS_CON_ESTABLISHED))) {
                                                            struct ArgusFlow *tflow = (struct ArgusFlow *) tns->dsrs[ARGUS_FLOW_INDEX];
                                                            ArgusRemoveHashEntry(&tns->htblhdr);
                                                            ArgusReverseRecord (tns);
                                                            hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                                            tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                                            tflow->hdr.subtype &= ~ARGUS_REVERSE;
                                                            tflow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
                                                         } else
                                                            ArgusReverseRecord (ns);
                                                      }
                                                   }
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
                           }
                        }

                        if (tns != NULL) {                            // found record in queue
                           if (parser->Aflag) {
                              if ((tns->status & RA_SVCTEST) != (ns->status & RA_SVCTEST)) {
                                 struct ArgusRecordStruct *sns;
                                 sns = ArgusCopyRecordStruct(tns);
                                 ArgusAddToQueue (agg->queue, &sns->qhdr, ARGUS_LOCK);         // use the agg queue as an idle timeout queue
                                 tns->status &= ~(RA_SVCTEST);
                                 tns->status |= (ns->status & RA_SVCTEST);
                              }
                           }

                           if (tns->status & ARGUS_RECORD_WRITTEN) {
                              ArgusZeroRecord (tns);

                           } else {
                              if ((agg->statusint > 0) || (agg->idleint > 0)) {   // if any timers, need to flush if needed
                                 double dur, nsst, tnsst, nslt, tnslt;

                                 nsst  = ArgusFetchStartTime(ns);
                                 tnsst = ArgusFetchStartTime(tns);
                                 nslt  = ArgusFetchLastTime(ns);
                                 tnslt = ArgusFetchLastTime(tns);

                                 dur = ((tnslt > nslt) ? tnslt : nslt) - ((nsst < tnsst) ? nsst : tnsst); 
                              
                                 if ((agg->statusint > 0) && (dur >= agg->statusint)) {
                                    struct ArgusRecordStruct *sns;
                                    sns = ArgusCopyRecordStruct(tns);
                                    ArgusAddToQueue (agg->queue, &sns->qhdr, ARGUS_LOCK);         // use the agg queue as an idle timeout queue
                                    ArgusZeroRecord(tns);
                                 } else {
                                    dur = ((nslt < tnsst) ? (tnsst - nslt) : ((tnslt < nsst) ? (nsst - tnslt) : 0.0));
                                    if (agg->idleint && (dur >= agg->idleint)) {
                                       struct ArgusRecordStruct *sns;
                                       sns = ArgusCopyRecordStruct(tns);
                                       ArgusAddToQueue (agg->queue, &sns->qhdr, ARGUS_LOCK);         // use the agg queue as an idle timeout queue
                                       ArgusZeroRecord(tns);
                                    }
                                 }
                              }
                           }

                           ArgusMergeRecords (agg, tns, ns);

                           ArgusRemoveFromQueue (agg->queue, &tns->qhdr, ARGUS_LOCK);
                           ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_LOCK);         // use the agg queue as an idle timeout queue

                           ArgusDeleteRecordStruct(parser, ns);
                           agg->status |= ARGUS_AGGREGATOR_DIRTY;
                           tns->bin = bin;
                           *rec = tns;
                           retn = 0;

                        } else {
                           tns = ns;
                           if ((hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct)) != NULL) {
                              tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                              ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_NOLOCK);
                              agg->status |= ARGUS_AGGREGATOR_DIRTY;
                              tns->bin = bin;
                              *rec = tns;
                              retn = 1;
                           }
                        }
                     }

                  } else {
                     if (agg->statusint < 0)
                        RaSendArgusRecord(argus);
                     else {
                        ArgusAddToQueue (agg->queue, &ns->qhdr, ARGUS_NOLOCK);
                        agg->status |= ARGUS_AGGREGATOR_DIRTY;
                        ns->bin = bin;
                        *rec = ns;
                        retn = 1;
                     }
                  }

                  if (agg->cont)
                     agg = agg->nxt;
                  else
                     found++;

               } else
                  agg = agg->nxt;
            }
         }

         rbps->scalesecs = rbps->endpt.tv_sec - rbps->startpt.tv_sec;
      }
   }

#ifdef ARGUSDEBUG
   {
      int vSec  = val / 1000000;
      int vuSec = val % 1000000;
      int sSec  = rbps->startpt.tv_sec;
      int suSec = rbps->startpt.tv_usec;
      int eSec  = rbps->endpt.tv_sec;
      int euSec = rbps->endpt.tv_usec;

   ArgusDebug (5, "ArgusInsertRecord (%p, %p, %p, %d) ind %d val %d.%6.6d bin start %d.%6.6d end %d.%6.6d", parser, rbps, argus, offset,
                    ind, vSec, vuSec, sSec, suSec, eSec, euSec); 
   }
#endif

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&rbps->lock);
#endif

   return (retn);
}


void ArgusInitAggregatorStructs(struct ArgusAggregatorStruct *);

void
ArgusInitAggregatorStructs(struct ArgusAggregatorStruct *nag)
{
   struct ArgusFlow flowbuf, *flow = &flowbuf;
   int i;

   for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
      switch (i) {
         case ARGUS_MASK_PROTO:
            ArgusIpV4MaskDefs[i].offset      = ((char *)&flow->ip_flow.ip_p - (char *)flow);
            ArgusIpV4RevMaskDefs[i].offset   = ((char *)&flow->ip_flow.ip_p - (char *)flow);

#if defined(_LITTLE_ENDIAN)
            ArgusIpV6MaskDefs[i].offset      = 39;
            ArgusIpV6RevMaskDefs[i].offset   = 39;
#else
            ArgusIpV6MaskDefs[i].offset      = 36;
            ArgusIpV6RevMaskDefs[i].offset   = 36;
#endif
            ArgusIsisHelloMaskDefs[i].offset = ((char *)&flow->isis_flow.pdu_type - (char *)flow);
            ArgusIsisLspMaskDefs[i].offset   = ((char *)&flow->isis_flow.pdu_type - (char *)flow);
            ArgusIsisCsnpMaskDefs[i].offset  = ((char *)&flow->isis_flow.pdu_type - (char *)flow);
            ArgusIsisPsnpMaskDefs[i].offset  = ((char *)&flow->isis_flow.pdu_type - (char *)flow);
            ArgusIsisRevMaskDefs[i].offset   = ((char *)&flow->isis_flow.pdu_type - (char *)flow);

            ArgusEtherMaskDefs[i].offset     = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_type - (char *)flow);
            ArgusEtherRevMaskDefs[i].offset  = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_type - (char *)flow);
            ArgusArpMaskDefs[i].len          = 2;
            ArgusArpRevMaskDefs[i].len       = 2;
            break;

         case ARGUS_MASK_SNET:
         case ARGUS_MASK_SADDR:
            ArgusIpV4MaskDefs[i].offset      = ((char *)&flow->ip_flow.ip_src - (char *)flow);
            ArgusIpV4RevMaskDefs[i].offset   = ((char *)&flow->ip_flow.ip_dst - (char *)flow);
            ArgusIpV6MaskDefs[i].offset      = ((char *)&flow->ipv6_flow.ip_src - (char *)flow);
            ArgusIpV6RevMaskDefs[i].offset   = ((char *)&flow->ipv6_flow.ip_dst - (char *)flow);
            ArgusIsisHelloMaskDefs[i].offset = ((char *)&flow->isis_flow.isis_un.hello.srcid - (char *)flow);
            ArgusIsisLspMaskDefs[i].offset   = ((char *)&flow->isis_flow.isis_un.lsp.lspid - (char *)flow);
            ArgusIsisCsnpMaskDefs[i].offset  = ((char *)&flow->isis_flow.isis_un.csnp.srcid - (char *)flow);
            ArgusIsisPsnpMaskDefs[i].offset  = ((char *)&flow->isis_flow.isis_un.psnp.srcid - (char *)flow);
            ArgusEtherMaskDefs[i].offset     = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_shost - (char *)flow);
            ArgusEtherRevMaskDefs[i].offset  = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_dhost - (char *)flow);
            ArgusWlanMaskDefs[i].offset      = ((char *)&flow->wlan_flow.shost - (char *)flow);
            ArgusWlanRevMaskDefs[i].offset   = ((char *)&flow->wlan_flow.dhost - (char *)flow);
            break;

         case ARGUS_MASK_DNET:
         case ARGUS_MASK_DADDR:
            ArgusIpV4MaskDefs[i].offset      = ((char *)&flow->ip_flow.ip_dst - (char *)flow);
            ArgusIpV4RevMaskDefs[i].offset   = ((char *)&flow->ip_flow.ip_src - (char *)flow);
            ArgusIpV6MaskDefs[i].offset      = ((char *)&flow->ipv6_flow.ip_dst - (char *)flow);
            ArgusIpV6RevMaskDefs[i].offset   = ((char *)&flow->ipv6_flow.ip_src - (char *)flow);
            ArgusIsisHelloMaskDefs[i].offset = ((char *)&flow->isis_flow.isis_un.hello.lanid - (char *)flow);
            ArgusIsisLspMaskDefs[i].offset   = ((char *)&flow->isis_flow.isis_un.lsp.seqnum  - (char *)flow);
            ArgusIsisCsnpMaskDefs[i].len     = 0;
            ArgusIsisPsnpMaskDefs[i].len     = 0;

            ArgusEtherMaskDefs[i].offset     = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_dhost - (char *)flow);
            ArgusEtherRevMaskDefs[i].offset  = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_shost - (char *)flow);
            ArgusWlanMaskDefs[i].offset      = ((char *)&flow->wlan_flow.shost - (char *)flow);
            ArgusWlanRevMaskDefs[i].offset   = ((char *)&flow->wlan_flow.dhost - (char *)flow);
            break;

         case ARGUS_MASK_SPORT:
            ArgusIpV4MaskDefs[i].offset      = ((char *)&flow->ip_flow.sport - (char *)flow);
            ArgusIpV4RevMaskDefs[i].offset   = ((char *)&flow->ip_flow.dport - (char *)flow);
            ArgusIpV6MaskDefs[i].offset      = ((char *)&flow->ipv6_flow.sport - (char *)flow);
            ArgusIpV6RevMaskDefs[i].offset   = ((char *)&flow->ipv6_flow.dport - (char *)flow);

            ArgusIsisHelloMaskDefs[i].offset = ((char *)&flow->isis_flow.chksum - (char *)flow);
            ArgusIsisLspMaskDefs[i].offset   = ((char *)&flow->isis_flow.chksum - (char *)flow);
            ArgusIsisCsnpMaskDefs[i].offset  = ((char *)&flow->isis_flow.chksum - (char *)flow);
            ArgusIsisPsnpMaskDefs[i].offset  = ((char *)&flow->isis_flow.chksum - (char *)flow);
            ArgusIsisRevMaskDefs[i].offset   = ((char *)&flow->isis_flow.chksum - (char *)flow);

            ArgusEtherMaskDefs[i].offset     = ((char *)&flow->mac_flow.mac_union.ether.ssap - (char *)flow);
            ArgusEtherRevMaskDefs[i].offset  = ((char *)&flow->mac_flow.mac_union.ether.dsap - (char *)flow);
            ArgusWlanMaskDefs[i].offset      = ((char *)&flow->wlan_flow.ssid - (char *)flow);
            ArgusWlanRevMaskDefs[i].offset   = ((char *)&flow->wlan_flow.ssid - (char *)flow);
            break;

         case ARGUS_MASK_DPORT:
            ArgusIpV4MaskDefs[i].offset     = ((char *)&flow->ip_flow.dport - (char *)flow);
            ArgusIpV4RevMaskDefs[i].offset  = ((char *)&flow->ip_flow.sport - (char *)flow);
            ArgusIpV6MaskDefs[i].offset     = ((char *)&flow->ipv6_flow.dport - (char *)flow);
            ArgusIpV6RevMaskDefs[i].offset  = ((char *)&flow->ipv6_flow.sport - (char *)flow);
            ArgusEtherMaskDefs[i].offset    = ((char *)&flow->mac_flow.mac_union.ether.dsap - (char *)flow);
            ArgusEtherRevMaskDefs[i].offset = ((char *)&flow->mac_flow.mac_union.ether.ssap - (char *)flow);
            ArgusWlanMaskDefs[i].offset      = ((char *)&flow->wlan_flow.bssid - (char *)flow);
            ArgusWlanRevMaskDefs[i].offset   = ((char *)&flow->wlan_flow.bssid - (char *)flow);
            break;

         case ARGUS_MASK_SMAC:
            ArgusIpV4MaskDefs[i].offset     = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_shost - (char *)flow);
            ArgusIpV4RevMaskDefs[i].offset  = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_dhost - (char *)flow);
            ArgusIpV6MaskDefs[i].offset     = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_shost - (char *)flow);
            ArgusIpV6RevMaskDefs[i].offset  = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_dhost - (char *)flow);

            ArgusIsisHelloMaskDefs[i].offset = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_shost - (char *)flow);
            ArgusIsisLspMaskDefs[i].offset   = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_shost - (char *)flow);
            ArgusIsisCsnpMaskDefs[i].offset  = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_shost - (char *)flow);
            ArgusIsisPsnpMaskDefs[i].offset  = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_shost - (char *)flow);
            ArgusIsisRevMaskDefs[i].offset   = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_dhost - (char *)flow);

            ArgusEtherMaskDefs[i].offset    = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_shost - (char *)flow);
            ArgusEtherRevMaskDefs[i].offset = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_dhost - (char *)flow);
            break;

         case ARGUS_MASK_DMAC:
            ArgusIpV4MaskDefs[i].offset     = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_dhost - (char *)flow);
            ArgusIpV4RevMaskDefs[i].offset  = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_shost - (char *)flow);
            ArgusIpV6MaskDefs[i].offset     = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_dhost - (char *)flow);
            ArgusIpV6RevMaskDefs[i].offset  = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_shost - (char *)flow);

            ArgusIsisHelloMaskDefs[i].offset = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_dhost - (char *)flow);
            ArgusIsisLspMaskDefs[i].offset   = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_dhost - (char *)flow);
            ArgusIsisCsnpMaskDefs[i].offset  = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_dhost - (char *)flow);
            ArgusIsisPsnpMaskDefs[i].offset  = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_dhost - (char *)flow);
            ArgusIsisRevMaskDefs[i].offset   = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_shost - (char *)flow);

            ArgusEtherMaskDefs[i].offset    = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_dhost - (char *)flow);
            ArgusEtherRevMaskDefs[i].offset = ((char *)&flow->mac_flow.mac_union.ether.ehdr.ether_shost - (char *)flow);
            break;
      }
   }
}


struct ArgusAggregatorStruct *
ArgusNewAggregator (struct ArgusParserStruct *parser, char *masklist, int type)
{
   struct ArgusAggregatorStruct *retn = NULL;
   struct ArgusModeStruct *mode = NULL, *modelist = NULL, *list;
   char *mptr, *ptr, *tok;
   int i;

   if ((retn = (struct ArgusAggregatorStruct *) ArgusCalloc (1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewAggregator: ArgusCalloc error %s", strerror(errno));

   if (masklist != NULL) {
      mptr = strdup(masklist);
      ptr = mptr;
      while ((tok = strtok (ptr, " ,\t")) != NULL) {
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
      free(mptr);

   } else {
      int ArgusSetDefaultMask = 0;

      if (parser->ArgusMaskList == NULL) {
         ArgusSetDefaultMask = 1;
      } else {
         if ((mode = parser->ArgusMaskList) != NULL) 
           if ((*mode->mode == '-') || (*mode->mode == '+'))
              ArgusSetDefaultMask = 1;
      }

      if (ArgusSetDefaultMask) {
         if (parser->RaMonMode) {
            retn->mask  = ( ARGUS_MASK_SRCID_INDEX | ARGUS_MASK_PROTO_INDEX |
                            ARGUS_MASK_SADDR_INDEX | ARGUS_MASK_SPORT_INDEX );
         } else {
            retn->mask  = ( ARGUS_MASK_SRCID_INDEX | 
                            ARGUS_MASK_PROTO_INDEX | ARGUS_MASK_SADDR_INDEX | 
                            ARGUS_MASK_DADDR_INDEX | ARGUS_MASK_SPORT_INDEX | ARGUS_MASK_DPORT_INDEX );
         }
      }

      modelist = parser->ArgusMaskList;
   }

   if ((mode = modelist) != NULL) {
      while (mode) {
         char *ptr = NULL, *endptr = NULL;
         struct ArgusIPAddrStruct mask;
         char *tptr = strdup(mode->mode), *sptr = tptr;
         int len = 0, x = 0, maskset = 0;
         int action = 1;

         bzero((char *)&mask, sizeof(mask));

         if (*sptr == '-') { action = -1; sptr++; };
         if (*sptr == '+') { action =  1; sptr++; };

         if ((ptr = strchr(sptr, '/')) != NULL) {
            *ptr++ = '\0';
            if (strchr(ptr, ':')) {
               if (!(inet_pton(AF_INET6, (const char *) ptr, &mask.addr_un.ipv6) > 0))
                  ArgusLog (LOG_ERR, "syntax error: %s %s", ptr, strerror(errno));
#if defined(_LITTLE_ENDIAN)
               for (x = 0 ; x < 4 ; x++)
                  mask.addr_un.ipv6[x] = htonl(mask.addr_un.ipv6[x]);
#endif
               len = 128;
            } else
            if (strchr(ptr, '.')) {
               if (!(inet_pton(AF_INET, (const char *) ptr, &mask.addr_un.ipv4) > 0))
                  ArgusLog (LOG_ERR, "syntax error: %s %s", ptr, strerror(errno));
#if defined(_LITTLE_ENDIAN)
               mask.addr_un.ipv4 = htonl(mask.addr_un.ipv4);
#endif
               len = 32;
            } else {
               if ((len = strtol(ptr, &endptr, 10)) == 0)
                  if (endptr == ptr)
                     ArgusLog (LOG_ERR, "syntax error: %s %s", ptr, strerror(errno));

               if (len <= 32)
                  mask.addr_un.ipv4 = (0xFFFFFFFF << (32 - len));
               else {
                  int tlen = len;
                  x = 0;
                  while (tlen) {
                     if (tlen > 32) {
                        mask.addr_un.ipv6[x] = 0xFFFFFFFF;
                        tlen -= 32;
                     } else {
                        mask.addr_un.ipv6[x] = htonl(0xFFFFFFFF << (32 - tlen));
                        tlen = 0;
                     }
                     x++;
                  }
               }
            }
            maskset = 1;
         }
         
         if (!(strncasecmp (sptr, "none", 4))) {
            retn->mask  = 0;
            ArgusParser->RaCumulativeMerge = 0;
            if (retn->correct) free(retn->correct);
            retn->correct = NULL;
         } else
         if (!(strncasecmp (sptr, "all", 3))) {
            retn->mask  = -1;
            ArgusParser->RaCumulativeMerge = 1;
            retn->correct = NULL;
         } else
         if (!(strncasecmp (sptr, "matrix", 6))) {
            retn->ArgusMatrixMode++;
            retn->mask |= (0x01LL << ARGUS_MASK_SADDR);
            retn->mask |= (0x01LL << ARGUS_MASK_DADDR);
            if (len > 0) {
               retn->saddrlen = len;
               retn->daddrlen = len;
               bcopy((char *)&mask, (char *)&retn->smask, sizeof(mask));
               bcopy((char *)&mask, (char *)&retn->dmask, sizeof(mask));
            }
            if (retn->correct) free(retn->correct);
            retn->correct = NULL;
         } else
         if (!(strncasecmp (sptr, "macmatrix", 9))) {
            retn->ArgusMatrixMode++;
            retn->mask |= (0x01LL << ARGUS_MASK_SMAC);
            retn->mask |= (0x01LL << ARGUS_MASK_DMAC);
            if (len > 0) {
               retn->saddrlen = len;
               retn->daddrlen = len;
            }
            if (retn->correct) free(retn->correct);
            retn->correct = NULL;
         } else 
         if (!(strncasecmp (sptr, "mac", 3))) {
            parser->RaMonMode++;
            retn->mask |= (0x01LL << ARGUS_MASK_SMAC);
            if (len > 0) {
               retn->saddrlen = len;
            }
            if (retn->correct) free(retn->correct);
            retn->correct = NULL;
         } else
         if (!(strncasecmp (sptr, "addr", 4))) {
            parser->RaMonMode++;
            retn->mask |= (0x01LL << ARGUS_MASK_SADDR);
            if (len > 0) {
               retn->saddrlen = len;
               bcopy((char *)&mask, (char *)&retn->smask, sizeof(mask));
            }
            if (retn->correct) free(retn->correct);
            retn->correct = NULL;
         } else
         if (!(strncasecmp (sptr, "port", 4))) {
            parser->RaMonMode++;
            retn->mask |= (0x01LL << ARGUS_MASK_SPORT);
            retn->mask |= (0x01LL << ARGUS_MASK_PROTO);
            if (retn->correct) free(retn->correct);
            retn->correct = NULL;

         } else {

            struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs;

            for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
               if (!(strncasecmp (sptr, ArgusMaskDefs[i].name, ArgusMaskDefs[i].slen))) {
                  if (action > 0) retn->mask |= (0x01LL << i); else retn->mask &= ~(0x1LL << i);
                  switch (i) {
                     case ARGUS_MASK_SRCID:
                        if (action > 0) retn->mask |= (0x01LL << ARGUS_MASK_SRCID); else retn->mask &= ~(0x01LL << ARGUS_MASK_SRCID); 
                     case ARGUS_MASK_SRCID_INF:
                        if (action > 0) retn->mask |= (0x01LL << ARGUS_MASK_SRCID_INF); else retn->mask &= ~(0x01LL << ARGUS_MASK_SRCID_INF); 
                        break;

                     case ARGUS_MASK_SADDR:
                        if ((action > 0) && (len > 0)) {
                           retn->saddrlen = len;
                           if (!maskset)
                              mask.addr_un.ipv4 = (0xFFFFFFFF << (32 - len));
                           bcopy((char *)&mask, (char *)&retn->smask, sizeof(mask));
                        }
                        break;
                     case ARGUS_MASK_DADDR:
                        if ((action > 0) && (len > 0)) {
                           retn->daddrlen = len;
                           if (!maskset)
                              mask.addr_un.ipv4 = (0xFFFFFFFF << (32 - len));
                           bcopy((char *)&mask, (char *)&retn->dmask, sizeof(mask));
                        }
                        break;

                     case ARGUS_MASK_INODE:
                        if ((action > 0) && (len > 0)) {
                           retn->iaddrlen = len;
                           if (!maskset)
                              mask.addr_un.ipv4 = (0xFFFFFFFF << (32 - len));
                           bcopy((char *)&mask, (char *)&retn->imask, sizeof(mask));
                        }
                        break;

                     case ARGUS_MASK_SMPLS:
                     case ARGUS_MASK_DMPLS: {
                        int x, RaNewIndex = 0;
                        char *ptr;

                        if ((action > 0) && ((ptr = strchr(sptr, '[')) != NULL)) {
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

                     case ARGUS_MASK_SPORT:
                     case ARGUS_MASK_DPORT:
                        if (action > 0) 
                           retn->mask |= (0x01LL << ARGUS_MASK_PROTO); 
                        break;
                  }
                  break;
               }
            }
         }
         free(tptr);
         mode = mode->nxt;
      }

      retn->ArgusModeList = modelist;
   }

   retn->status   = type;
   retn->correct  = strdup("yes");
   retn->pres     = strdup("yes");

   if (retn->mask == 0) {
      if ((retn->queue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "ArgusNewAggregator: ArgusNewQueue error %s", strerror(errno));

      if (retn->correct != NULL) {
         free (retn->correct);
         retn->correct = NULL;
      }

      parser->ArgusPerformCorrection = 0;

   } else {

      ArgusInitAggregatorStructs(retn);

      if ((retn->drap = (struct RaPolicyStruct *) ArgusCalloc(1, sizeof(*retn->drap))) == NULL)
         ArgusLog (LOG_ERR, "ArgusNewAggregator: ArgusCalloc error %s", strerror(errno));

      if ((retn->queue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "ArgusNewAggregator: ArgusNewQueue error %s", strerror(errno));

      if ((retn->timeout = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "ArgusNewAggregator: ArgusNewQueue error %s", strerror(errno));

      if ((retn->htable = ArgusNewHashTable (ArgusParser->ArgusHashTableSize)) == NULL)
         ArgusLog (LOG_ERR, "ArgusNewAggregator: ArgusNewHashTable error %s", strerror(errno));

      retn->RaMetricFetchAlgorithm = ArgusFetchDuration;
      retn->ArgusMetricIndex = ARGUSMETRICDURATION;
   }

   return (retn);
}


struct ArgusAggregatorStruct *
ArgusCopyAggregator (struct ArgusAggregatorStruct *agg) 
{
   struct ArgusAggregatorStruct *retn = NULL, *tagg = NULL, *pagg = NULL;
 
   while (agg != NULL) {
      if ((tagg = (struct ArgusAggregatorStruct *) ArgusMalloc (sizeof(*tagg))) == NULL)
         ArgusLog (LOG_ERR, "ArgusCopyAggregator: ArgusMalloc error %s", strerror(errno));

      bcopy(agg, tagg, sizeof(*agg));
      tagg->nxt = NULL;

      if (agg->name != NULL)    tagg->name    = strdup(agg->name);
      if (agg->pres != NULL)    tagg->pres    = strdup(agg->pres);
      if (agg->report != NULL)  tagg->report  = strdup(agg->report);
      if (agg->correct != NULL) tagg->correct = strdup(agg->correct);
      if (agg->modeStr != NULL) tagg->modeStr = strdup(agg->modeStr);

      if (agg->argus != NULL) tagg->argus = NULL;

      bzero(&agg->hstruct, sizeof(agg->hstruct));

      if (agg->drap != NULL) {
         if ((tagg->drap = (void *) ArgusCalloc (1, sizeof(*tagg->drap))) == NULL)
            ArgusLog (LOG_ERR, "ArgusCopyAggregator: ArgusCalloc error %s", strerror(errno));
         bcopy(agg->drap, tagg->drap, sizeof(*agg->drap));
      }

      if (agg->rap != NULL) {
         if ((tagg->rap = (void *) ArgusCalloc (1, sizeof(*tagg->rap))) == NULL)
            ArgusLog (LOG_ERR, "ArgusCopyAggregator: ArgusCalloc error %s", strerror(errno));
         bcopy(agg->rap, tagg->rap, sizeof(*agg->rap));
      }

      tagg->ArgusModeList = NULL;
      {
         struct ArgusModeStruct *mode = NULL;

         if ((mode = agg->ArgusModeList) != NULL) {
            struct ArgusModeStruct *tmode, *prv = NULL;
            while (mode) {
               if ((tmode = (struct ArgusModeStruct *) ArgusCalloc (1, sizeof(struct ArgusModeStruct))) == NULL)
                  ArgusLog (LOG_ERR, "ArgusCopyAggregator: ArgusCalloc error %s", strerror(errno));

               if (tagg->ArgusModeList == NULL)
                  tagg->ArgusModeList = tmode;

               tmode->mode = strdup(mode->mode);
               if (prv != NULL) prv->nxt = tmode;
               prv = tmode;

               mode = mode->nxt;
            }
         }
      }

      tagg->ArgusMaskList = NULL;
      {
         struct ArgusModeStruct *mode = NULL;

         if ((mode = agg->ArgusMaskList) != NULL) {
            struct ArgusModeStruct *tmode, *prv = NULL;
            while (mode) {
               if ((tmode = (struct ArgusModeStruct *) ArgusCalloc (1, sizeof(struct ArgusModeStruct))) == NULL)
                  ArgusLog (LOG_ERR, "ArgusCopyAggregator: ArgusCalloc error %s", strerror(errno));

               if (tagg->ArgusMaskList == NULL)
                  tagg->ArgusMaskList = tmode;

               tmode->mode = strdup(mode->mode);
               if (prv != NULL) prv->nxt = tmode;
               prv = tmode;

               mode = mode->nxt;
            }
         }
      }

      if ((tagg->queue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "ArgusNewAggregator: ArgusNewQueue error %s", strerror(errno));

      if ((tagg->timeout = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "ArgusNewAggregator: ArgusNewQueue error %s", strerror(errno));

      if ((tagg->htable = ArgusNewHashTable (ArgusParser->ArgusHashTableSize)) == NULL)
         ArgusLog (LOG_ERR, "ArgusNewAggregator: ArgusNewHashTable error %s", strerror(errno));

      if (agg->filterstr != NULL) {
         tagg->filterstr = strdup(agg->filterstr);
     	 if (agg->filter.bf_insns != NULL) {
     	    tagg->filter.bf_insns = calloc(sizeof(*agg->filter.bf_insns), agg->filter.bf_len);
     	    bcopy(agg->filter.bf_insns, tagg->filter.bf_insns, sizeof(*agg->filter.bf_insns) * agg->filter.bf_len);
         }
      }

      if (agg->modelstr != NULL) tagg->modelstr = strdup(agg->modelstr);
      if (agg->grepstr != NULL) tagg->grepstr = strdup(agg->grepstr);
      if (agg->labelstr != NULL) tagg->labelstr = strdup(agg->labelstr);
      if (agg->estr != NULL) tagg->estr = strdup(agg->estr);

      tagg->RaMetricFetchAlgorithm = agg->RaMetricFetchAlgorithm;

      if (retn == NULL)
         retn = tagg;

      if (pagg != NULL)
         pagg->nxt = tagg;

      agg = agg->nxt;
      pagg = tagg;
   }
   return retn;
}


void
ArgusDeleteAggregator (struct ArgusParserStruct *parser, struct ArgusAggregatorStruct *agg)
{
   struct ArgusModeStruct *mode = NULL, *prv;

   if (agg->nxt != NULL) {
      ArgusDeleteAggregator (parser, agg->nxt);
      agg->nxt = NULL;
   }

   if (agg->correct != NULL)
      free(agg->correct);

   if (agg->pres != NULL)
      free(agg->pres);

   if (agg->hstruct.buf != NULL)
      ArgusFree(agg->hstruct.buf);

   if (agg->drap != NULL)
      ArgusFree(agg->drap);

   if (agg->queue && agg->queue->count) {
      switch (agg->status & ( ARGUS_RECORD_AGGREGATOR | ARGUS_OBJ_AGGREGATOR)) {
         default:
         case ARGUS_RECORD_AGGREGATOR: {
            struct ArgusRecordStruct *argus;
            while ((argus = (struct ArgusRecordStruct *) ArgusPopQueue (agg->queue, ARGUS_LOCK)) != NULL)
               ArgusDeleteRecordStruct(ArgusParser, argus);
            break;
         }

         case ARGUS_OBJ_AGGREGATOR: {
            struct ArgusObjectStruct *obj;
            while ((obj = (struct ArgusObjectStruct *) ArgusPopQueue (agg->queue, ARGUS_LOCK)) != NULL)
               ArgusFree(obj);
            break;
         }
      }
   }

   if (agg->timeout && agg->timeout->count) {
      switch (agg->status & ( ARGUS_RECORD_AGGREGATOR | ARGUS_OBJ_AGGREGATOR)) {
         default:
         case ARGUS_RECORD_AGGREGATOR: {
            struct ArgusRecordStruct *argus;
            while ((argus = (struct ArgusRecordStruct *) ArgusPopQueue (agg->timeout, ARGUS_LOCK)) != NULL)
               ArgusDeleteRecordStruct(ArgusParser, argus);
            break;
         }

         case ARGUS_OBJ_AGGREGATOR: {
            struct ArgusObjectStruct *obj;
            while ((obj = (struct ArgusObjectStruct *) ArgusPopQueue (agg->timeout, ARGUS_LOCK)) != NULL)
               ArgusFree(obj);
            break;
         }
      }
   }

   if ((mode = agg->ArgusModeList) != NULL) {
     if (mode != parser->ArgusMaskList) {
        while ((prv = mode) != NULL) {
           if (mode->mode != NULL)
              free (mode->mode);
           mode = mode->nxt;
           ArgusFree(prv);
        }
      }
   }

   if (agg->queue != NULL)
      ArgusDeleteQueue(agg->queue);

   if (agg->timeout != NULL)
      ArgusDeleteQueue(agg->timeout);

   if (agg->htable != NULL)
      ArgusDeleteHashTable(agg->htable);

   if (agg->modelstr)
      free(agg->modelstr);

   if (agg->filterstr) {
      free(agg->filterstr);
      if (agg->filter.bf_insns != NULL)
         free(agg->filter.bf_insns);
   }

   if (parser->ArgusAggregator == agg)
      parser->ArgusAggregator = NULL;

   ArgusFree(agg);

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusDeleteAggregator(%p, %p) returned\n", parser, agg);
#endif
}


#define ARGUS_RCITEMS    7

#define ARGUS_RC_FILTER  0
#define ARGUS_RC_GREP    1
#define ARGUS_RC_MODEL   2
#define ARGUS_RC_STATUS  3
#define ARGUS_RC_IDLE    4
#define ARGUS_RC_LABEL   5
#define ARGUS_RC_CONT    6

char *ArgusAggregatorFields[ARGUS_RCITEMS] = {
   "filter", "grep", "model", "status", "idle", "label", "cont",
};

struct ArgusAggregatorStruct *
ArgusParseAggregator (struct ArgusParserStruct *parser, char *file, char *buf[])
{
   struct ArgusAggregatorStruct *retn = NULL, *agg;
   char strbuf[MAXSTRLEN], *sptr = strbuf;
   char *name = NULL, *pres = NULL;
   char *report = NULL, *correct = NULL;
   char *histo = NULL, *metric = NULL;
   char *ptr, *end, tmp;
   int i, tlines = 0;
   FILE *fd = NULL;

   if ((buf == NULL) && (file == NULL)) 
      return NULL;

   if (buf == NULL) {
      if ((fd = fopen (file, "r")) == NULL)
         ArgusLog (LOG_ERR, "%s: %s", file, strerror(errno));
   }

// Here we're either reading from a file or a buffer. Treat the strings the same.
// Because we modify the strings, lets get a copy to work with, and free it up later.

   while ((fd ? (sptr = fgets(strbuf, MAXSTRLEN, fd)) : (sptr = ((*buf != NULL) ? *buf++ : *buf))) != NULL)  {
      char *pstr = strdup(sptr), *str = pstr;
      int done = 0, defined = 0;
      tlines++;

      while (*str && isspace((int)*str)) str++;
      ptr = str; 

      if (*str && (*str != '#') && (*str != '\n') && (*str != '"') && (*str != '!')) {
         char *filter = NULL, *grep = NULL, *model = NULL, *label = NULL;
         char *status = NULL, *idle = NULL, *cptr = NULL;
         int cont = 0;
         while (!done) {
            if (!(strncmp(str, RA_MODELNAMETAGSTR, strlen(RA_MODELNAMETAGSTR)))) {
               name = strdup(&str[strlen(RA_MODELNAMETAGSTR)]);
               done++;
            } else
            if (!(strncmp(str, RA_PRESERVETAGSTR, strlen(RA_PRESERVETAGSTR)))) {
               if (pres != NULL) free(pres);
               pres = strdup(&str[strlen(RA_PRESERVETAGSTR)]);
               done++;
            } else
            if (!(strncmp(str, RA_REPORTTAGSTR, strlen(RA_REPORTTAGSTR)))) {
               if (report != NULL) free(report);
               report = strdup(&str[strlen(RA_REPORTTAGSTR)]);
               done++;
            } else
            if (!(strncmp(str, RA_AUTOCORRECTSTR, strlen(RA_AUTOCORRECTSTR)))) {
               if (correct != NULL) free(correct);
               correct = strdup(&str[strlen(RA_AUTOCORRECTSTR)]);
               if (!(strstr(correct, "yes"))) {
                  free(correct);
                  correct = NULL;
               }
               done++;
            } else
            if (!(strncmp(str, RA_HISTOGRAM, strlen(RA_HISTOGRAM)))) {
               if (histo != NULL) free(histo);
               histo = strdup(&str[strlen(RA_HISTOGRAM)]);
               done++;
            } else
            if (!(strncmp(str, RA_AGGMETRIC, strlen(RA_AGGMETRIC)))) {
               ptr = str + strlen(RA_AGGMETRIC); 
               while (*ptr && (isspace((int)*ptr) || ispunct((int)*ptr))) ptr++;
               str = &ptr[strlen(ptr) - 1]; 
               while (*str && (isspace((int)*str) || ispunct((int)*str))) { *str = '\0'; str--;}
               metric = strdup(ptr);
               done++;
            } else
            for (i = 0; i < ARGUS_RCITEMS; i++) {
               if (!(strncmp(str, ArgusAggregatorFields[i], strlen(ArgusAggregatorFields[i])))) {
                  char *value = NULL;
                  ptr = str + strlen(ArgusAggregatorFields[i]); 
                  while (*ptr && isspace((int)*ptr)) ptr++;

                  if (!(*ptr == '=') && (i != ARGUS_RC_CONT))
                     ArgusLog (LOG_ERR, "ArgusParseAggregator: syntax error line %d %s", tlines, str);

                  defined++;

                  ptr++;
                  while (*ptr && isspace((int)*ptr)) ptr++;

                  switch (i) {
                     case ARGUS_RC_FILTER:
                     case ARGUS_RC_GREP:
                     case ARGUS_RC_LABEL:
                     case ARGUS_RC_MODEL: {
                        if (*ptr == '\"') {
                          ptr++;
                          end = ptr;
                          while (*end != '\"') end++;
                          *end++ = '\0';
                  
                           value = strdup(ptr);
                           ptr = end;
                        }
                        break;
                     }

                     case ARGUS_RC_STATUS:
                     case ARGUS_RC_IDLE: {
                        strtol(ptr, (char **)&end, 10);
                        if (end == ptr)
                           ArgusLog (LOG_ERR, "ArgusParseAggregator: syntax error line %d %s", tlines, str);

                        switch (*end) {
                           case 's': 
                           case 'm': 
                           case 'h': 
                           case 'd':
                              end++; break;
                        }
                        tmp = *end;
                        *end = '\0';
                        value = strdup(ptr);
                        ptr = end;
                        *ptr = tmp;
                        break;
                     }
                  }

                  switch (i) {
                     case ARGUS_RC_FILTER: filter = value; value = NULL; break;
                     case ARGUS_RC_GREP:   grep   = value; value = NULL; break;
                     case ARGUS_RC_MODEL:  model  = value; value = NULL; break;
                     case ARGUS_RC_STATUS: status = value; value = NULL; break;
                     case ARGUS_RC_IDLE:   idle   = value; value = NULL; break;
                     case ARGUS_RC_LABEL:  label  = value; value = NULL; break;
                     case ARGUS_RC_CONT: {
                       cont++;
                       done++;
                     }
                     default:
                       if (value != NULL) {
                          free (value);
                          value = NULL;
                       }
                       break;
                  }

                  while (*ptr && isspace((int)*ptr)) ptr++;
                  str = ptr;
               }
            }

            if (!(done || defined))
               ArgusLog (LOG_ERR, "ArgusParseAggregator: syntax error line %d: %s", tlines, str);

            if (ptr && ((*ptr == '\n') || (*ptr == '\0')))
               done++;
         }

         if (defined) {
            if ((agg = ArgusNewAggregator(parser, model, ARGUS_RECORD_AGGREGATOR)) == NULL)
               ArgusLog (LOG_ERR, "ArgusParseAggregator: ArgusNewAggregator returned NULL");

            if (cont)
               agg->cont++;

            if (name)
               agg->name = name;

            if (pres) {
               if (!(strncasecmp(pres, "no", 2)))
                  agg->pres = NULL;
               else
                  agg->pres = strdup("yes");
               pres = NULL;
            }

            if (histo) {
               free (histo);
               histo = NULL;
            }

            if (report)
               agg->report = report;

            if (correct)
               agg->correct = strdup(correct);

            if (metric) {
               int x, found = 0;
               for (x = 0; (x < MAX_METRIC_ALG_TYPES) && (!(found)); x++) {
                  struct ArgusFetchValueStruct *fetch = &RaFetchAlgorithmTable[x];

                  if (!strncmp (fetch->field, metric, strlen(metric))) {
                     agg->RaMetricFetchAlgorithm = fetch->fetch;
                     agg->ArgusMetricIndex = x;
                     found++;
                     break;
                  }
               }
               if (!found)
                  ArgusLog (LOG_ERR, "ArgusNewAggregator RA_AGG_METRIC %s not found", metric);
            }

            if (filter) {
               if (strlen(filter)) {
                  agg->filterstr = filter;
                  filter = NULL;
                  if (ArgusFilterCompile (&agg->filter, agg->filterstr, ArgusParser->Oflag) < 0)
                     ArgusLog (LOG_ERR, "ArgusNewAggregator ArgusFilterCompile returned error");
               }
            }

            if (model) {
               if (strlen(model)) {
                  agg->modelstr = model;
                  model = NULL;
               }
            }

            if (grep) {
               int options;
               int rege;

#if defined(ARGUS_PCRE)
               options = 0;
#else
               options = REG_EXTENDED | REG_NOSUB;
#if defined(REG_ENHANCED)
               options |= REG_ENHANCED;
#endif
#endif
               if (parser->iflag)
                  options |= REG_ICASE;

               agg->grepstr = grep;

               if ((rege = regcomp(&agg->lpreg, grep, options)) != 0) {
                  char errbuf[MAXSTRLEN];
                  if (regerror(rege, &parser->lpreg, errbuf, MAXSTRLEN))
                     ArgusLog (LOG_ERR, "ArgusProcessLabelOption: grep regex error %s", errbuf);
               }
            }

            if (status) {
               agg->statusint = strtol(status, (char **)&cptr, 10);
               switch(*cptr) {
                  case 'm': agg->statusint *= 60; break;
                  case 'h': agg->statusint *= 3600; break;
                  case 'd': agg->statusint *= 86400; break;
               }
            }
            if (idle) {
               agg->idleint = strtol(idle, (char **)&cptr, 10);
               switch(*cptr) {
                  case 'm': agg->idleint *= 60; break;
                  case 'h': agg->idleint *= 3600; break;
                  case 'd': agg->idleint *= 86400; break;
               }
            }

            if (label) {
               if (strlen(label)) {
                  agg->labelstr = label;
                  label = NULL;
               }
            }

            if (retn != NULL) {
               struct ArgusAggregatorStruct *tagg = retn;
                while (tagg->nxt != NULL)
                   tagg = tagg->nxt;
                tagg->nxt = agg;
            } else
               retn = agg;

         } else {
            if (!done)
               ArgusLog (LOG_ERR, "ArgusNewAggregator: line %d, syntax error %s", tlines, str);
         }

         if (filter != NULL) { free (filter); filter = NULL; }
         if (grep != NULL)   { free (grep); grep = NULL; }
         if (model != NULL)  { free (model); model = NULL; }
         if (status != NULL) { free (status); status = NULL; }
         if (idle != NULL)   { free (idle); idle = NULL; }
      }

      if (pstr != NULL) {
         free(pstr);
         pstr = NULL;
      }
   }

   if (fd != NULL) fclose(fd);

   if ((agg = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
      ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

   if (name)
      agg->name = name;

   if (pres) {
      if (!(strncasecmp(pres, "no", 2)))
         agg->pres = NULL;
      else
         agg->pres = strdup("yes");
   }

   if (report)
      agg->report = report;

   if (correct) {
      agg->correct = strdup(correct);
      free(correct);
      correct = NULL;
   }

   if (metric) {
      int x, found = 0;
      for (x = 0; (x < MAX_METRIC_ALG_TYPES) && (!(found)); x++) {
         struct ArgusFetchValueStruct *fetch = &RaFetchAlgorithmTable[x];

         if (!strncmp (fetch->field, metric, strlen(metric))) {
            agg->RaMetricFetchAlgorithm = fetch->fetch;
            agg->ArgusMetricIndex = x;
            found++;
            break;
         }
      }
      if (!found)
         ArgusLog (LOG_ERR, "ArgusNewAggregator RA_AGG_METRIC %s not found", metric);
   }

   if (retn != NULL) {
      struct ArgusAggregatorStruct *tagg = retn;
      while (tagg->nxt != NULL)
         tagg = tagg->nxt;
      tagg->nxt = agg;
   } else
      retn = agg;

   if (pres) free (pres);
   if (histo) free (histo);
   if (report) free (report);
   if (correct) free (correct);

   return (retn);
}


int
RaParseType (char *str)
{
   return(argus_nametoeproto(str));
}

double
ArgusFetchSrcId (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   struct ArgusTransportStruct *t = (struct ArgusTransportStruct *)ns->dsrs[ARGUS_TRANSPORT_INDEX];

   if (t) {
      if (t->hdr.subtype & ARGUS_SRCID) {
         if (t->hdr.argus_dsrvl8.qual & ARGUS_TYPE_INTERFACE) {
            long long value = t->srcid.a_un.value;
            value <<= 32;
            bcopy(t->srcid.inf, &((char *)&value)[4], 4);
            retn = (double) value;

         } else
            retn = t->srcid.a_un.value;
/*
         switch (t->hdr.argus_dsrvl8.qual) {
            case ARGUS_TYPE_INT:    len = 1; break;
            case ARGUS_TYPE_IPV4:   len = 1; break;
            case ARGUS_TYPE_IPV6:   len = 4; break;
            case ARGUS_TYPE_ETHER:  len = 6; break;
            case ARGUS_TYPE_STRING: len = t->hdr.argus_dsrvl8.len - 2;
         }
*/
      }
   }

   return (retn);
}

double
ArgusFetchSID (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   struct ArgusTransportStruct *t = (struct ArgusTransportStruct *)ns->dsrs[ARGUS_TRANSPORT_INDEX];
   if (t) {
      if (t->hdr.subtype & ARGUS_SRCID) {
         long long value = t->srcid.a_un.value;
         retn = (double) value;
      }
   }
   return (retn);
}

double
ArgusFetchInf (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   struct ArgusTransportStruct *t = (struct ArgusTransportStruct *)ns->dsrs[ARGUS_TRANSPORT_INDEX];
   if (t) {
      if (t->hdr.subtype & ARGUS_SRCID) {
         if (t->hdr.argus_dsrvl8.qual & ARGUS_TYPE_INTERFACE) {
            int value = 0;
            bcopy(t->srcid.inf, (char *)&value, 4);
            retn = (double) value;
         } else
            retn = 0;
      }
   }
   return (retn);
}

long long
ArgusFetchStartuSecTime (struct ArgusRecordStruct *ns)
{
   long long retn = 0;
   long long sec = 0, usec = 0;

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_MAR: {
         struct ArgusRecord *rec = (struct ArgusRecord *) ns->dsrs[0];

         if (rec != NULL) {
            if ((ns->hdr.cause & 0xF0) == ARGUS_START) {
               sec  = rec->argus_mar.now.tv_sec;
               usec = rec->argus_mar.now.tv_usec;

            } else {
               sec  = rec->argus_mar.startime.tv_sec;
               usec = rec->argus_mar.startime.tv_usec;
            }
         }
         break;
      }

      case ARGUS_EVENT: {
         struct ArgusTimeObject *time = (void *)ns->dsrs[ARGUS_TIME_INDEX];
         if (time != NULL) {
             sec = time->src.start.tv_sec;
            usec = time->src.start.tv_usec;
         }
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusTimeObject *dtime = (void *)ns->dsrs[ARGUS_TIME_INDEX];

         if (dtime != NULL) {
            unsigned int subtype = dtime->hdr.subtype & (ARGUS_TIME_SRC_START | ARGUS_TIME_DST_START);
            struct timeval stimebuf, *st = &stimebuf;
            struct timeval etimebuf, *et = &etimebuf;
            struct timeval *stime = NULL;

            if (subtype) {
               switch (subtype) {
                  case ARGUS_TIME_SRC_START | ARGUS_TIME_DST_START: {
                     st->tv_sec  = dtime->src.start.tv_sec;
                     st->tv_usec = dtime->src.start.tv_usec;
                     et->tv_sec  = dtime->dst.start.tv_sec;
                     et->tv_usec = dtime->dst.start.tv_usec;

                     if ((st->tv_sec > 0) && (et->tv_sec > 0)) {
                        stime = RaMinTime(st, et);
                     } else {
                        stime = (st->tv_sec > 0) ? st : et;
                     }
                     break;
                  }

                  case ARGUS_TIME_SRC_START: {
                     st->tv_sec  = dtime->src.start.tv_sec;
                     st->tv_usec = dtime->src.start.tv_usec;
                     stime = st;
                     break;
                  }

                  case ARGUS_TIME_DST_START: {
                     st->tv_sec  = dtime->dst.start.tv_sec;
                     st->tv_usec = dtime->dst.start.tv_usec;
                     stime = st;
                     break;
                  }
               }

            } else {
               st->tv_sec  = dtime->src.start.tv_sec;
               st->tv_usec = dtime->src.start.tv_usec;
               et->tv_sec  = dtime->dst.start.tv_sec;
               et->tv_usec = dtime->dst.start.tv_usec;

               if ((st->tv_sec > 0) && (et->tv_sec > 0)) {
                  stime = RaMinTime(st, et);
               } else {
                  stime = (st->tv_sec > 0) ? st : et;
               } 
            }

            sec  = stime->tv_sec;
            usec = stime->tv_usec;
         }
         break;
      }
   }

   retn = (sec * 1000000LL) + usec;
   return(retn);
}

double
ArgusFetchSrcStartTime (struct ArgusRecordStruct *ns)
{
   double sec = 0, usec = 0;
   double retn = 0;

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusTimeObject *dtime = (void *)ns->dsrs[ARGUS_TIME_INDEX];
         struct timeval stimebuf, *st = &stimebuf;

         if (dtime != NULL) {
            unsigned int subtype = dtime->hdr.subtype & ARGUS_TIME_SRC_START;

            if (subtype) {
               st->tv_sec  = dtime->src.start.tv_sec;
               st->tv_usec = dtime->src.start.tv_usec;
               sec  = st->tv_sec;
               usec = st->tv_usec;
            }
         }
      }
   }

   retn = ((sec * 1000000.0) + usec) / 1000000.0;
   return(retn);
}

double
ArgusFetchDstStartTime (struct ArgusRecordStruct *ns)
{
   double sec = 0, usec = 0;
   double retn = 0;

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusTimeObject *dtime = (void *)ns->dsrs[ARGUS_TIME_INDEX];
         struct timeval stimebuf, *st = &stimebuf;

         if (dtime != NULL) {
            unsigned int subtype = dtime->hdr.subtype & ARGUS_TIME_DST_START;
            if (subtype) {
               st->tv_sec  = dtime->dst.start.tv_sec;
               st->tv_usec = dtime->dst.start.tv_usec;
               sec  = st->tv_sec;
               usec = st->tv_usec;
            }
         }
      }
   }
   retn = ((sec * 1000000.0) + usec) / 1000000.0;
   return(retn);
}

double
ArgusFetchStartTime (struct ArgusRecordStruct *ns)
{
   double retn = ArgusFetchStartuSecTime(ns) / 1000000.0;
   return (retn);
}


long long
ArgusFetchLastuSecTime (struct ArgusRecordStruct *ns)
{
   long long retn = 0;
   long long sec = 0, usec = 0;

   if (ns->hdr.type & ARGUS_MAR) {
      struct ArgusRecord *rec = (struct ArgusRecord *) ns->dsrs[0];
      if (rec != NULL) {
         sec  = rec->argus_mar.now.tv_sec;
         usec = rec->argus_mar.now.tv_usec;
      }

   } else {
      struct ArgusTimeObject *dtime = (void *)ns->dsrs[ARGUS_TIME_INDEX];

      if (dtime != NULL) {
         struct timeval stimebuf, *st = &stimebuf;
         struct timeval etimebuf, *et = &etimebuf;
         struct timeval *stime = NULL;

         st->tv_sec  = dtime->src.end.tv_sec;
         st->tv_usec = dtime->src.end.tv_usec;
         et->tv_sec  = dtime->dst.end.tv_sec;
         et->tv_usec = dtime->dst.end.tv_usec;

         stime = RaMaxTime(st, et);

         sec  = stime->tv_sec;
         usec = stime->tv_usec;
      }
   }

   retn = (sec * 1000000LL) + usec;
   return(retn);
}

double
ArgusFetchLastTime (struct ArgusRecordStruct *ns)
{
   double retn = ArgusFetchLastuSecTime(ns) / 1000000.0;
   return (retn);
}

double
ArgusFetchMean (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   if (ns->hdr.type & ARGUS_MAR) {
   } else {
      struct ArgusAgrStruct *agr;

      if ((agr = (struct ArgusAgrStruct *) ns->dsrs[ARGUS_AGR_INDEX]) != NULL)
         retn = agr->act.meanval;
   }
   return retn;
}

double
ArgusFetchIdleMean (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   if (ns->hdr.type & ARGUS_MAR) {
   } else {
      struct ArgusAgrStruct *agr;

      if ((agr = (struct ArgusAgrStruct *) ns->dsrs[ARGUS_AGR_INDEX]) != NULL)
         retn = agr->idle.meanval;
   }
   return retn;
}

double
ArgusFetchMin (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   if (ns->hdr.type & ARGUS_MAR) {
   } else {
      struct ArgusAgrStruct *agr;

      if ((agr = (struct ArgusAgrStruct *) ns->dsrs[ARGUS_AGR_INDEX]) != NULL)
         retn = agr->act.minval;
   }
   return retn;
}

double
ArgusFetchIdleMin (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   if (ns->hdr.type & ARGUS_MAR) {
   } else {
      struct ArgusAgrStruct *agr;

      if ((agr = (struct ArgusAgrStruct *) ns->dsrs[ARGUS_AGR_INDEX]) != NULL)
         retn = agr->idle.minval;
   }
   return retn;
}

double
ArgusFetchMax (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   if (ns->hdr.type & ARGUS_MAR) {
   } else {
      struct ArgusAgrStruct *agr;

      if ((agr = (struct ArgusAgrStruct *) ns->dsrs[ARGUS_AGR_INDEX]) != NULL)
         retn = agr->act.maxval;
   }
   return (retn);
}

double
ArgusFetchIdleMax (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   if (ns->hdr.type & ARGUS_MAR) {
   } else {
      struct ArgusAgrStruct *agr;

      if ((agr = (struct ArgusAgrStruct *) ns->dsrs[ARGUS_AGR_INDEX]) != NULL)
         retn = agr->idle.maxval;
   }
   return (retn);
}


double
ArgusFetchAvgDuration (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   if (ns->hdr.type & ARGUS_MAR) {
   } else {
      struct ArgusAgrStruct *agr;

      if ((agr = (struct ArgusAgrStruct *) ns->dsrs[ARGUS_AGR_INDEX]) != NULL)
         retn = agr->act.meanval;
      else
         retn = RaGetFloatDuration (ns);
   }
   return retn;
}

double
ArgusFetchMinDuration (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   if (ns->hdr.type & ARGUS_MAR) {
   } else {
      struct ArgusAgrStruct *agr;

      if ((agr = (struct ArgusAgrStruct *) ns->dsrs[ARGUS_AGR_INDEX]) != NULL)
         retn = agr->act.minval;
      else
         retn = RaGetFloatDuration (ns);
   }
   return retn;
}

double
ArgusFetchMaxDuration (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   if (ns->hdr.type & ARGUS_MAR) {
   } else {
      struct ArgusAgrStruct *agr;

      if ((agr = (struct ArgusAgrStruct *) ns->dsrs[ARGUS_AGR_INDEX]) != NULL)
         retn = agr->act.maxval;
      else
         retn = RaGetFloatDuration (ns);
   }
   return (retn);
}

double
ArgusFetchuSecDuration (struct ArgusRecordStruct *ns)
{
   float dur = RaGetuSecDuration(ns);
   double retn = dur;
   return (retn);
}


double
ArgusFetchDuration (struct ArgusRecordStruct *ns)
{
   float dur = RaGetFloatDuration(ns);
   double retn = dur;
   return (retn);
}

double
ArgusFetchSrcDuration (struct ArgusRecordStruct *ns)
{
   float dur = RaGetFloatDuration(ns);
   double retn = dur;
   return (retn);
}

double
ArgusFetchDstDuration (struct ArgusRecordStruct *ns)
{
   float dur = RaGetFloatDuration(ns);
   double retn = dur;
   return (retn);
}

#if !defined(ntohll)
  #if defined(_LITTLE_ENDIAN)
    #if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__sun__)
      #include <argus/extract.h>
      #define ntohll(x) EXTRACT_64BITS(&x)
      #define htonll(x) EXTRACT_64BITS(&x)
    #else
      #include <byteswap.h>
      #define ntohll(x) bswap_64(x)
      #define htonll(x) bswap_64(x)
    #endif
  #else
    #define ntohll(x) x
    #define htonll(x) x
  #endif
#endif

double
ArgusFetchSrcMac (struct ArgusRecordStruct *ns)
{
   struct ArgusMacStruct *m = (struct ArgusMacStruct *) ns->dsrs[ARGUS_MAC_INDEX];
   unsigned long long value  = 0;
   double retn = 0;

   if (m != NULL) {
      bcopy ((char *)&m->mac.mac_union.ether.ehdr.ether_shost, (char *)&value, ETH_ALEN);
      retn = ntohll(value);
   }
   return(retn);
}

double
ArgusFetchDstMac (struct ArgusRecordStruct *ns)
{
   struct ArgusMacStruct *m = (struct ArgusMacStruct *) ns->dsrs[ARGUS_MAC_INDEX];
   unsigned long long value  = 0;
   double retn = 0;

   if (m != NULL) {
      bcopy ((char *)&m->mac.mac_union.ether.ehdr.ether_dhost, (char *)&value, ETH_ALEN);
      retn = ntohll(value);
   }
   return(retn);
}


double
ArgusFetchSrcMacOui (struct ArgusRecordStruct *ns)
{
   struct ArgusMacStruct *m = (struct ArgusMacStruct *) ns->dsrs[ARGUS_MAC_INDEX];
   double retn = 0;

   if (m !=  NULL) {
      char *oui = etheraddr_oui(ArgusParser, (unsigned char *)&m->mac.mac_union.ether.ehdr.ether_shost);

      if (oui != NULL) {
         int slen = strlen(oui);
         slen = (slen > 8) ? 8 : slen;
         bcopy (oui, (char *)&retn, slen);
      }
   }
   return(retn);
}

double
ArgusFetchDstMacOui (struct ArgusRecordStruct *ns)
{
   struct ArgusMacStruct *m = (struct ArgusMacStruct *) ns->dsrs[ARGUS_MAC_INDEX];
   double retn = 0;

   if (m !=  NULL) {
      char *oui = etheraddr_oui(ArgusParser, (unsigned char *)&m->mac.mac_union.ether.ehdr.ether_dhost);

      if (oui != NULL) {
         int slen = strlen(oui);
         slen = (slen > 8) ? 8 : slen;
         bcopy (oui, (char *)&retn, slen);
      }
   }
   return(retn);
}

double
ArgusFetchSrcAddr (struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow;
   void *addr = NULL;
   int objlen = 0, type = 0;
   double retn = 0;

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR: {
         struct ArgusRecord *rec = (struct ArgusRecord *) argus->dsrs[0];

         if (rec != NULL)
            retn = rec->argus_mar.queue;

         break;
      }

      case ARGUS_EVENT: {
         struct ArgusTransportStruct *trans = (void *) argus->dsrs[ARGUS_TRANSPORT_INDEX];

         if (trans != NULL) {
            switch (trans->hdr.argus_dsrvl8.qual) {
               case ARGUS_TYPE_INT:
                  retn = trans->srcid.a_un.value;
                  break;

               case ARGUS_TYPE_IPV4:
                  retn = trans->srcid.a_un.ipv4;
                  break;

//             case ARGUS_TYPE_IPV6:   value = ArgusGetV6Name(parser, (u_char *)&trans->srcid.ipv6); break;
//             case ARGUS_TYPE_ETHER:  value = ArgusGetEtherName(parser, (u_char *)&trans->srcid.ether); break;
//             case ARGUS_TYPE_STRING: value = ArgusGetString(parser, (u_char *)&trans->srcid.string); break;
            }
         }
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         if ((flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: 
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (type = (flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_IPV4:
                        addr = &flow->ip_flow.ip_src;
                        objlen = 4;
                        break;
                     case ARGUS_TYPE_IPV6:
                        addr = &flow->ipv6_flow.ip_src;
                        objlen = 16;
                        break;

                     case ARGUS_TYPE_RARP:
                        type = ARGUS_TYPE_ETHER;
                        addr = &flow->lrarp_flow.tareaddr;
                        objlen = 6;
                        break;
                     case ARGUS_TYPE_ARP:
                        type = ARGUS_TYPE_IPV4;
                        addr = &flow->larp_flow.arp_spa;
                        objlen = 4;
                        break;

                     case ARGUS_TYPE_ETHER:
                        addr = &flow->mac_flow.mac_union.ether.ehdr.ether_shost;
                        objlen = 6;
                        break;

                     case ARGUS_TYPE_WLAN:
                        addr = &flow->wlan_flow.shost;
                        objlen = 6;
                        break;
                  }
                  break;
               }

               case ARGUS_FLOW_ARP: {
                  switch (type = (flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_RARP:
                        type = ARGUS_TYPE_ETHER;
                        addr = &flow->rarp_flow.dhaddr;
                        objlen = 6;
                        break;

                     case ARGUS_TYPE_ARP:
                        type = ARGUS_TYPE_IPV4;
                        addr = &flow->arp_flow.arp_spa;
                        objlen = 4;
                        break;
                  }
                  break;
               }

               default:
                  break;
            }
         } 

         switch (objlen) {
            case 4:
               retn = *(unsigned int *)addr;
               break;

            default:
               break;
         }
         break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "ArgusFetchSrcAddr (%p) returns %p", argus, retn);
#endif

   return(retn);
}

double
ArgusFetchDstAddr (struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow;
   void *addr = NULL;
   int objlen = 0, type = 0;
   double retn = 0;

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR: {
         struct ArgusRecord *rec = (struct ArgusRecord *) argus->dsrs[0];

         if (rec != NULL)
            retn = rec->argus_mar.queue;

         break;
      }

      case ARGUS_EVENT: {
         struct ArgusTransportStruct *trans = (void *) argus->dsrs[ARGUS_TRANSPORT_INDEX];

         if (trans != NULL) {
            switch (trans->hdr.argus_dsrvl8.qual) {
               case ARGUS_TYPE_INT:
                  retn = trans->srcid.a_un.value;
                  break;

               case ARGUS_TYPE_IPV4:
                  retn = trans->srcid.a_un.ipv4;
                  break;

//             case ARGUS_TYPE_IPV6:   value = ArgusGetV6Name(parser, (u_char *)&trans->srcid.ipv6); break;
//             case ARGUS_TYPE_ETHER:  value = ArgusGetEtherName(parser, (u_char *)&trans->srcid.ether); break;
//             case ARGUS_TYPE_STRING: value = ArgusGetString(parser, (u_char *)&trans->srcid.string); break;
            }
         }
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         if ((flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
            switch (flow->hdr.subtype & 0x3F) {

               case ARGUS_FLOW_CLASSIC5TUPLE: 
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (type = (flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_IPV4:
                        addr = &flow->ip_flow.ip_dst;
                        objlen = 4;
                        break;
                     case ARGUS_TYPE_IPV6:
                        addr = &flow->ipv6_flow.ip_dst;
                        objlen = 16;
                        break;

                     case ARGUS_TYPE_RARP:
                        type = ARGUS_TYPE_ETHER;
                        addr = &flow->lrarp_flow.srceaddr;
                        objlen = 6;
                        break;
                     case ARGUS_TYPE_ARP:
                        type = ARGUS_TYPE_IPV4;
                        addr = &flow->larp_flow.arp_tpa;
                        objlen = 4;
                        break;

                     case ARGUS_TYPE_ETHER:
                        addr = &flow->mac_flow.mac_union.ether.ehdr.ether_dhost;
                        objlen = 6;
                        break;

                     case ARGUS_TYPE_WLAN:
                        addr = &flow->wlan_flow.dhost;
                        objlen = 6;
                        break;
                  }
                  break;
               }

               case ARGUS_FLOW_ARP: {
                  switch (type = (flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_RARP:
                        type = ARGUS_TYPE_ETHER;
                        addr = &flow->rarp_flow.dhaddr;
                        objlen = 6;
                        break;

                     case ARGUS_TYPE_ARP:
                        type = ARGUS_TYPE_IPV4;
                        addr = &flow->arp_flow.arp_tpa;
                        objlen = 4;
                        break;
                  }
                  break;
               }

               default:
                  break;
            }
         }

         switch (objlen) {
            case 4:
               retn = *(unsigned int *)addr;
               break;

            default:
               break;
         }
         break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "ArgusFetchSrcAddr (%p) returns %p", argus, retn);
#endif

   return(retn);
}


double
ArgusFetchEtherType (struct ArgusRecordStruct *ns)
{
   struct ArgusMacStruct *m1 = (struct ArgusMacStruct *) ns->dsrs[ARGUS_MAC_INDEX];
   double retn = 0;

   if (m1) {
      retn = m1->mac.mac_union.ether.ehdr.ether_type;
      if (retn == ETHERTYPE_8021Q) {
         struct ArgusFlow *f1 = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
         if (f1) {
            switch (f1->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch (f1->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4:
                        retn = ETHERTYPE_IP;
                        break;
                     case ARGUS_TYPE_IPV6:
                        retn = ETHERTYPE_IPV6;
                        break;
                  }
                  break;
               }

               default:
                  break;
            }
         }
      }
   }

   return(retn);
}

double
ArgusFetchProtocol (struct ArgusRecordStruct *ns)
{
   double retn = 0;
   struct ArgusFlow *f1 = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];

   if (f1) {
      switch (f1->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (f1->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4:
                  retn = f1->ip_flow.ip_p;
                  break;
               case ARGUS_TYPE_IPV6:
                  retn = f1->ipv6_flow.ip_p;
                  break;
            }
            break;
         }
 
         default:
            break;
      }
   }
 
   return(retn);
}

double
ArgusFetchSrcPort (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];

   switch (flow->hdr.subtype & 0x3F) {
      case ARGUS_FLOW_CLASSIC5TUPLE: {
         switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
            case ARGUS_TYPE_IPV4:
               if ((flow->ip_flow.ip_p == IPPROTO_TCP) || (flow->ip_flow.ip_p == IPPROTO_UDP))
                  retn = (flow->hdr.subtype & ARGUS_REVERSE) ? flow->ip_flow.dport : flow->ip_flow.sport;
               break;
            case ARGUS_TYPE_IPV6:
               switch (flow->ipv6_flow.ip_p) {
                  case IPPROTO_TCP:
                  case IPPROTO_UDP: {
                     retn = (flow->hdr.subtype & ARGUS_REVERSE) ? flow->ipv6_flow.dport : flow->ipv6_flow.sport;
                     break;
                  }
               }

               break;
         }
         break;
      }

      default:
         break;
   }

   return(retn);
}

double
ArgusFetchDstPort (struct ArgusRecordStruct *ns)
{
   double retn = 0;

   struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
 
   switch (flow->hdr.subtype & 0x3F) {
      case ARGUS_FLOW_CLASSIC5TUPLE: {
         switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
            case ARGUS_TYPE_IPV4:
               if ((flow->ip_flow.ip_p == IPPROTO_TCP) || (flow->ip_flow.ip_p == IPPROTO_UDP))
                  retn = (flow->hdr.subtype & ARGUS_REVERSE) ? flow->ip_flow.sport : flow->ip_flow.dport;
               break;
            case ARGUS_TYPE_IPV6:
               switch (flow->ipv6_flow.ip_p) {
                  case IPPROTO_TCP:
                  case IPPROTO_UDP: {
                     retn = (flow->hdr.subtype & ARGUS_REVERSE) ? flow->ipv6_flow.sport : flow->ipv6_flow.dport;
                     break;
                  }
               }

               break;
         }
         break;
      }
 
      default:
         break;
   }

   return(retn);
}


double
ArgusFetchSrcMpls (struct ArgusRecordStruct *ns)
{
   struct ArgusMplsStruct *m1 = (struct ArgusMplsStruct *)ns->dsrs[ARGUS_MPLS_INDEX];
   double retn = 0;

   if (m1 && (m1->hdr.subtype & ARGUS_MPLS_SRC_LABEL)) {
      unsigned char *p1 = (unsigned char *)&m1->slabel;

#if defined(_LITTLE_ENDIAN)
      retn = (p1[0] << 12) | (p1[1] << 4) | ((p1[2] >> 4) & 0xff);
#else
      retn = (p1[3] << 12) | (p1[2] << 4) | ((p1[1] >> 4) & 0xff);
#endif
   }

   return (retn);
}

double
ArgusFetchDstMpls (struct ArgusRecordStruct *ns)
{
   struct ArgusMplsStruct *m1 = (struct ArgusMplsStruct *)ns->dsrs[ARGUS_MPLS_INDEX];
   double retn = 0;

   if (m1 && (m1->hdr.subtype & ARGUS_MPLS_DST_LABEL)) {
      unsigned char *p1 = (unsigned char *)&m1->dlabel;

#if defined(_LITTLE_ENDIAN)
      retn = (p1[0] << 12) | (p1[1] << 4) | ((p1[2] >> 4) & 0xff);
#else
      retn = (p1[3] << 12) | (p1[2] << 4) | ((p1[1] >> 4) & 0xff);
#endif
   }

   return (retn);
}

double
ArgusFetchSrcVlan (struct ArgusRecordStruct *ns)
{
   struct ArgusVlanStruct *v1 = (struct ArgusVlanStruct *)ns->dsrs[ARGUS_VLAN_INDEX];
   double retn = 0;

   if (v1 && (v1->hdr.argus_dsrvl8.qual & ARGUS_SRC_VLAN))
      retn = v1->sid & 0x0FFF;

   return (retn);
}

double
ArgusFetchDstVlan (struct ArgusRecordStruct *ns)
{
   struct ArgusVlanStruct *v1 = (struct ArgusVlanStruct *)ns->dsrs[ARGUS_VLAN_INDEX];
   double retn = 0;

   if (v1 && (v1->hdr.argus_dsrvl8.qual & ARGUS_DST_VLAN))
      retn = (v1->did & 0x0FFF);

   return (retn);
}

double
ArgusFetchSrcIpId (struct ArgusRecordStruct *ns)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)ns->dsrs[ARGUS_IPATTR_INDEX];
   double retn = 0;
 
   if (ip1)
      retn = ip1->src.ip_id;
 
   return (retn);
}


double
ArgusFetchDstIpId (struct ArgusRecordStruct *ns)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)ns->dsrs[ARGUS_IPATTR_INDEX];
   double retn = 0;
 
   if (ip1)  
      retn = ip1->dst.ip_id;
 
   return (retn);
}

double
ArgusFetchSrcTos (struct ArgusRecordStruct *ns)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)ns->dsrs[ARGUS_IPATTR_INDEX];
   double retn = 0;

   if (ip1)
      retn = ip1->src.tos;

   return (retn);
}

double
ArgusFetchDstTos (struct ArgusRecordStruct *ns)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)ns->dsrs[ARGUS_IPATTR_INDEX];
   double retn = 0;

   if (ip1)
      retn = ip1->dst.tos;

   return (retn);
}

double
ArgusFetchSrcTtl (struct ArgusRecordStruct *ns)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)ns->dsrs[ARGUS_IPATTR_INDEX];
   double retn = 0;
 
   if (ip1 && (ip1->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC))
      retn = (ip1->src.ttl * 1.0);

   return (retn);
}

double
ArgusFetchDstTtl (struct ArgusRecordStruct *ns)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)ns->dsrs[ARGUS_IPATTR_INDEX];
   double retn = 0;
 
   if (ip1  && (ip1->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST))
      retn = (ip1->dst.ttl * 1.0);

   return (retn);
}

double
ArgusFetchSrcHopCount (struct ArgusRecordStruct *ns)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)ns->dsrs[ARGUS_IPATTR_INDEX];
   int esthops = 1;
   double retn = 0;

   if (ip1 && (ip1->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC)) {
      while (esthops < ip1->src.ttl)
         esthops = esthops * 2;
      
      retn = ((esthops - ip1->src.ttl) * 1.0);
   }

   return (retn);
}

double
ArgusFetchDstHopCount (struct ArgusRecordStruct *ns)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)ns->dsrs[ARGUS_IPATTR_INDEX];
   int esthops = 1;
   double retn = 0;
 
   if (ip1  && (ip1->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST)) {
      while (esthops < ip1->dst.ttl)
         esthops = esthops * 2;
      
      retn = ((esthops - ip1->dst.ttl) * 1.0);
   }

   return (retn);
}

double
ArgusFetchTransactions (struct ArgusRecordStruct *ns)
{
   struct ArgusAgrStruct *a1 = (struct ArgusAgrStruct *)ns->dsrs[ARGUS_AGR_INDEX];
   double retn = 1.0;

   if (a1)
      retn = (a1->count * 1.0);

   return (retn);
}

double
ArgusFetchSrcLoad (struct ArgusRecordStruct *ns)
{
   double retn = ns->sload;
   return (retn);
}

double
ArgusFetchDstLoad (struct ArgusRecordStruct *ns)
{
   double retn = ns->dload;
   return (retn);
}


double
ArgusFetchLoad (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      float sdur = RaGetFloatSrcDuration(ns);
      float ddur = RaGetFloatDstDuration(ns);

      if (!(sdur > 0)) sdur = ns->dur;
      if (!(ddur > 0)) ddur = ns->dur;

      if (ns->dur > 0.0)
         retn = ((ns->sload * sdur) + (ns->dload * ddur)) / ns->dur;
   }

   return (retn);
}

double
ArgusFetchLoss (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {
          struct ArgusRecord *rec = (void *)ns->dsrs[0];

          if (rec != NULL)
             retn = rec->argus_mar.dropped * 1.0;
      } else {
         struct ArgusFlow *flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];
         struct ArgusMetricStruct *metric = (void *) ns->dsrs[ARGUS_METRIC_INDEX];

         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_IPV4: {
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_UDP: {
                              if ((net != NULL) && (net->hdr.subtype == ARGUS_RTP_FLOW)) {
                                 struct ArgusRTPObject *rtp = (void *)&net->net_union.rtp;
                                 retn = (rtp->sdrop + rtp->ddrop) * 1.0;
                              } else 
                              if ((net != NULL) && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
                                 struct ArgusUDTObject *udt = (void *)&net->net_union.udt;
                                 retn = (udt->src.drops) * 1.0;
                              }
                              break;
                           }

                           case IPPROTO_ICMP: {
                              break;
                           }
                           case IPPROTO_TCP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusTCPObject *tcp = (void *)&net->net_union.tcp;

                                 if ((tcp != NULL) && (tcp->state != 0)) {
                                    if (metric->src.pkts)
                                       retn = (tcp->src.retrans + tcp->dst.retrans) * 1.0;
                                 }
                              }
                              break;
                           }
                           case IPPROTO_ESP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusESPObject *esp = (void *)&net->net_union.esp;
                                 if (esp != NULL) {
                                    if (metric->src.pkts)
                                       retn = esp->lostseq * 1.0;
                                 }
                              }
                              break;
                           }
                        }
                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        switch (flow->ipv6_flow.ip_p) {
                           case IPPROTO_UDP: {
                              if (net != NULL) {
                                 if (net->hdr.subtype == ARGUS_RTP_FLOW) {
                                    struct ArgusRTPObject *rtp = (void *)&net->net_union.rtp;
                                    retn = (rtp->sdrop + rtp->ddrop) * 1.0;
                                 } else 
                                 if (net->hdr.subtype == ARGUS_UDT_FLOW) {
                                    struct ArgusUDTObject *udt = (void *)&net->net_union.udt;
                                    retn = (udt->src.drops) * 1.0;
                                 }
                              }
                              break;
                           }

                           case IPPROTO_ICMP: {
                              break;
                           }

                           case IPPROTO_TCP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusTCPObject *tcp = (void *)&net->net_union.tcp;

                                 if ((tcp != NULL) && (tcp->state != 0)) {
                                    if (metric->src.pkts)
                                       retn = (tcp->src.retrans + tcp->dst.retrans) * 1.0;
                                 }
                              }
                              break;
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

   return (retn);
}

double
ArgusFetchSrcLoss (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {
      } else {
         struct ArgusFlow *flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];
         struct ArgusMetricStruct *metric = (void *) ns->dsrs[ARGUS_METRIC_INDEX];

         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_IPV4: {
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_UDP: {
                              if (net != NULL) {
                                 if (net->hdr.subtype == ARGUS_RTP_FLOW) {
                                    struct ArgusRTPObject *rtp = (void *)&net->net_union.rtp;
                                    retn = rtp->sdrop;
                                 } else 
                                 if (net->hdr.subtype == ARGUS_UDT_FLOW) {
                                    struct ArgusUDTObject *udt = (void *)&net->net_union.udt;
                                    retn = (udt->src.drops);
                                 }
                              }
                              break;
                           }

                           case IPPROTO_ICMP: {
                              break;
                           }
                           case IPPROTO_TCP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusTCPObject *tcp = (void *)&net->net_union.tcp;

                                 if (tcp->state != 0) {
                                    if (metric->src.pkts)
                                       retn = tcp->src.retrans;
                                 }
                              }
                              break;
                           }
                           case IPPROTO_ESP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusESPObject *esp = (void *)&net->net_union.esp;
                                 if (metric->src.pkts)
                                    retn = esp->lostseq;
                              }
                              break;
                           }
                        }
                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        switch (flow->ipv6_flow.ip_p) {
                           case IPPROTO_UDP: {
                              if (net != NULL) {
                                 if (net->hdr.subtype == ARGUS_RTP_FLOW) {
                                    struct ArgusRTPObject *rtp = (void *)&net->net_union.rtp;
                                    retn = rtp->sdrop;
                                 } else 
                                 if (net->hdr.subtype == ARGUS_UDT_FLOW) {
                                    struct ArgusUDTObject *udt = (void *)&net->net_union.udt;
                                    retn = (udt->src.drops);
                                 }
                              }
                              break;
                           }

                           case IPPROTO_ICMP: {
                              break;
                           }

                           case IPPROTO_TCP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusTCPObject *tcp = (void *)&net->net_union.tcp;

                                 if ((tcp != NULL) && (tcp->state != 0)) {
                                    if (metric->src.pkts)
                                       retn = tcp->src.retrans;
                                 }
                              }
                              break;
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

   return (retn);
}

double
ArgusFetchDstLoss (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {
      } else {
         struct ArgusFlow *flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];
         struct ArgusMetricStruct *metric = (void *) ns->dsrs[ARGUS_METRIC_INDEX];

         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_IPV4: {
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_UDP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 if (net->hdr.subtype == ARGUS_RTP_FLOW) {
                                    struct ArgusRTPObject *rtp = (void *)&net->net_union.rtp;
                                    retn = rtp->ddrop;
                                 }
                              }
                           }

                           case IPPROTO_ICMP: {
                              break;
                           }
                           case IPPROTO_TCP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusTCPObject *tcp = (void *)&net->net_union.tcp;
                                 unsigned int status;

                                 if ((tcp != NULL) && ((status = tcp->state) != 0)) {
                                    if (metric->dst.pkts)
                                       retn = tcp->dst.retrans;
                                 }
                              }
                              break;
                           }
                           case IPPROTO_ESP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusESPObject *esp = (void *)&net->net_union.esp;
                                 if (metric->dst.pkts)
                                    retn = esp->lostseq;
                              }
                           }
                        }
                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        switch (flow->ipv6_flow.ip_p) {
                           case IPPROTO_UDP: {
                              if (net != NULL) {
                                 if (net->hdr.subtype == ARGUS_RTP_FLOW) {
                                    struct ArgusRTPObject *rtp = (void *)&net->net_union.rtp;
                                    retn = rtp->ddrop;
                                 }
                              }
                              break;
                           }

                           case IPPROTO_ICMP: {
                              break;
                           }

                           case IPPROTO_TCP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusTCPObject *tcp = (void *)&net->net_union.tcp;
                                 unsigned int status;

                                 if ((status = tcp->state) != 0) {
                                    if (metric->dst.pkts)
                                       retn = tcp->dst.retrans;
                                 }
                              }
                              break;
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

   return (retn);
}


void
ArgusAdjustTransactions (struct ArgusRecordStruct *ns, double ptrans, double ppkts)
{
   switch (ns->hdr.type & 0xF0) {
      case ARGUS_EVENT:
      case ARGUS_MAR: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusAgrStruct *agr = (void *)ns->dsrs[ARGUS_AGR_INDEX];
         double tpkts = ArgusFetchPktsCount(ns);

         if (agr != NULL) {
            double trans =  floor(ptrans * (tpkts/ppkts));
            agr->count = trans;
         }
         break;
      }
   }
}

// the idea here is to use the percentage loss value to tweak the new record, so
// that its source and dest loss counters represent what should be a good value.
// rounding up, should get us there. and tracking the value to maintain the raminader
// is very important.

void
ArgusAdjustSrcLoss (struct ArgusRecordStruct *ns, struct ArgusRecordStruct *retn, double percent)
{
   if (ns && retn) {
      if (ns->hdr.type & ARGUS_MAR) {
      } else {
         struct ArgusFlow *flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];
         struct ArgusMetricStruct *metric = (void *) ns->dsrs[ARGUS_METRIC_INDEX];
         double pkts = metric->src.pkts * 1.0;

         struct ArgusNetworkStruct *rnet = (void *) retn->dsrs[ARGUS_NETWORK_INDEX];
         struct ArgusMetricStruct *rmetric = (void *) retn->dsrs[ARGUS_METRIC_INDEX];
         double rpkts = rmetric->src.pkts * 1.0;
         double tpkts = pkts + rpkts;

         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_IPV4: {
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_UDP: {
                              if (net != NULL) {
                                 if (net->hdr.subtype == ARGUS_RTP_FLOW) {
                                    struct ArgusRTPObject *nrtp = (void *)&net->net_union.rtp;
                                    struct ArgusRTPObject *rrtp = (void *)&rnet->net_union.rtp;

                                    double drop = rint(rrtp->sdrop * (rpkts / tpkts));

                                    if ((rrtp->sdrop = (unsigned short) drop) == 0) {
                                    } else {
                                       nrtp->sdrop -= rrtp->sdrop;
                                    }

                                 } else 
                                 if (net->hdr.subtype == ARGUS_UDT_FLOW) {
                                    struct ArgusUDTObject *nudt = (void *)&net->net_union.udt;
                                    struct ArgusUDTObject *rudt = (void *)&rnet->net_union.udt;
                                    double drop = rint(rudt->src.drops * (rpkts / tpkts));

                                    if ((rudt->src.drops = (unsigned short) drop) == 0)
                                       rudt->status = ~(ARGUS_PKTS_RETRANS | ARGUS_PKTS_DROP);
                                    else
                                       nudt->src.drops -= rudt->src.drops;
                                 }
                              }
                              break;
                           }

                           case IPPROTO_ICMP: {
                              break;
                           }
                           case IPPROTO_TCP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusTCPObject *tcp  = (void *)&net->net_union.tcp;

                                 if (tcp->state != 0) {
                                    struct ArgusTCPObject *rtcp = (void *)&rnet->net_union.tcp;

                                    double drop = rint(tcp->src.retrans * (rpkts / tpkts));
                                    if ((rtcp->src.retrans = (unsigned int) drop) == 0) {
                                       rtcp->src.status &= ~(ARGUS_PKTS_RETRANS | ARGUS_PKTS_DROP);
                                       rtcp->status &= ~(ARGUS_SRC_PKTS_RETRANS | ARGUS_SRC_PKTS_DROP);

                                    } else
                                       tcp->src.retrans -= rtcp->src.retrans;
                                 }
                              }
                              break;
                           }
                           case IPPROTO_ESP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusESPObject *nesp = (void *)&net->net_union.esp;
                                 struct ArgusESPObject *resp = (void *)&rnet->net_union.esp;

                                 double drop = rint(resp->lostseq * (rpkts / tpkts));
                                 if ((resp->lostseq = (unsigned int) drop) == 0)
                                    resp->status &= ~ARGUS_SRC_PKTS_DROP;
                                 else
                                    nesp->lostseq -= resp->lostseq;
                              }
                              break;
                           }
                        }
                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        switch (flow->ipv6_flow.ip_p) {
                           case IPPROTO_UDP: {
                              if (net != NULL) {
                                 if (net->hdr.subtype == ARGUS_RTP_FLOW) {
                                    struct ArgusRTPObject *nrtp = (void *)&net->net_union.rtp;
                                    struct ArgusRTPObject *rrtp = (void *)&rnet->net_union.rtp;

                                    double drop = rint(rrtp->sdrop * (rpkts / tpkts));

                                    if ((rrtp->sdrop = (unsigned short) drop) == 0) {
                                    } else {
                                       nrtp->sdrop -= rrtp->sdrop;
                                    }

                                 } else
                                 if (net->hdr.subtype == ARGUS_UDT_FLOW) {
                                    struct ArgusUDTObject *nudt = (void *)&net->net_union.udt;
                                    struct ArgusUDTObject *rudt = (void *)&rnet->net_union.udt;
                                    double drop = rint(rudt->src.drops * (rpkts / tpkts));

                                    if ((rudt->src.drops = (unsigned short) drop) == 0)
                                       rudt->status = ~(ARGUS_PKTS_RETRANS | ARGUS_PKTS_DROP);
                                    else
                                       nudt->src.drops -= rudt->src.drops;
                                 }
                              }
                              break;
                           }

                           case IPPROTO_ICMP: {
                              break;
                           }

                           case IPPROTO_TCP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusTCPObject *tcp  = (void *)&net->net_union.tcp;

                                 if (tcp->state != 0) {
                                    struct ArgusTCPObject *rtcp = (void *)&rnet->net_union.tcp;

                                    double drop = rint(tcp->src.retrans * (rpkts / tpkts));
                                    if ((rtcp->src.retrans = (unsigned int) drop) == 0) {
                                       rtcp->src.status &= ~(ARGUS_PKTS_RETRANS | ARGUS_PKTS_DROP);
                                       rtcp->status &= ~(ARGUS_SRC_PKTS_RETRANS | ARGUS_SRC_PKTS_DROP);

                                    } else
                                       tcp->src.retrans -= rtcp->src.retrans;
                                 }
                              }
                              break;
                           }

                           case IPPROTO_ESP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusESPObject *nesp = (void *)&net->net_union.esp;
                                 struct ArgusESPObject *resp = (void *)&rnet->net_union.esp;

                                 double drop = rint(resp->lostseq * (rpkts / tpkts));
                                 if ((resp->lostseq = (unsigned int) drop) == 0)
                                    resp->status &= ~ARGUS_SRC_PKTS_DROP;
                                 else
                                    nesp->lostseq -= resp->lostseq;
                              }
                              break;
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
}


void
ArgusAdjustDstLoss (struct ArgusRecordStruct *ns, struct ArgusRecordStruct *retn, double percent)
{
   if (ns && retn) {
      if (ns->hdr.type & ARGUS_MAR) {
      } else {
         struct ArgusFlow *flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];
         struct ArgusMetricStruct *metric = (void *) ns->dsrs[ARGUS_METRIC_INDEX];
         double pkts = metric->dst.pkts * 1.0;

         struct ArgusNetworkStruct *rnet = (void *) retn->dsrs[ARGUS_NETWORK_INDEX];
         struct ArgusMetricStruct *rmetric = (void *) retn->dsrs[ARGUS_METRIC_INDEX];
         double rpkts = rmetric->dst.pkts * 1.0;
         double tpkts = pkts + rpkts;

         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_IPV4: {
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_UDP: {
                              if (net != NULL) {
                                 if (net->hdr.subtype == ARGUS_RTP_FLOW) {
                                    struct ArgusRTPObject *nrtp = (void *)&net->net_union.rtp;
                                    struct ArgusRTPObject *rrtp = (void *)&rnet->net_union.rtp;

                                    double drop = rint(rrtp->ddrop * (rpkts / tpkts));

                                    if ((rrtp->ddrop = (unsigned short) drop) == 0) {
                                    } else {
                                       nrtp->ddrop -= rrtp->ddrop;
                                    }

                                 } 
                              }
                              break;
                           }

                           case IPPROTO_ICMP: {
                              break;
                           }
                           case IPPROTO_TCP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusTCPObject *tcp  = (void *)&net->net_union.tcp;

                                 if (tcp->state != 0) {
                                    struct ArgusTCPObject *rtcp = (void *)&rnet->net_union.tcp;

                                    double drop = rint(tcp->dst.retrans * (rpkts / tpkts));
                                    if ((rtcp->dst.retrans = (unsigned int) drop) == 0) {
                                       rtcp->dst.status &= ~(ARGUS_PKTS_RETRANS | ARGUS_PKTS_DROP);
                                       rtcp->status &= ~(ARGUS_DST_PKTS_RETRANS | ARGUS_DST_PKTS_DROP);

                                    } else
                                       tcp->dst.retrans -= rtcp->dst.retrans;
                                 }
                              }
                              break;
                           }
                        }
                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        switch (flow->ipv6_flow.ip_p) {
                           case IPPROTO_UDP: {
                              if (net != NULL) {
                                 if (net->hdr.subtype == ARGUS_RTP_FLOW) {
                                    struct ArgusRTPObject *nrtp = (void *)&net->net_union.rtp;
                                    struct ArgusRTPObject *rrtp = (void *)&rnet->net_union.rtp;

                                    double drop = rint(rrtp->ddrop * (rpkts / tpkts));

                                    if ((rrtp->ddrop = (unsigned short) drop) == 0) {
                                    } else {
                                       nrtp->ddrop -= rrtp->ddrop;
                                    }

                                 } else
                                 if (net->hdr.subtype == ARGUS_UDT_FLOW) {
                                 }
                              }
                              break;
                           }

                           case IPPROTO_ICMP: {
                              break;
                           }

                           case IPPROTO_TCP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusTCPObject *tcp  = (void *)&net->net_union.tcp;

                                 if (tcp->state != 0) {
                                    struct ArgusTCPObject *rtcp = (void *)&rnet->net_union.tcp;

                                    double drop = rint(tcp->dst.retrans * (rpkts / tpkts));
                                    if ((rtcp->dst.retrans = (unsigned int) drop) == 0) {
                                       rtcp->dst.status &= ~(ARGUS_PKTS_RETRANS | ARGUS_PKTS_DROP);
                                       rtcp->status &= ~(ARGUS_DST_PKTS_RETRANS | ARGUS_DST_PKTS_DROP);

                                    } else
                                       tcp->dst.retrans -= rtcp->dst.retrans;
                                 }
                              }
                              break;
                           }

                           case IPPROTO_ESP: {
                              if ((net != NULL) && (metric != NULL)) {
                                 struct ArgusESPObject *nesp = (void *)&net->net_union.esp;
                                 struct ArgusESPObject *resp = (void *)&rnet->net_union.esp;

                                 double drop = rint(resp->lostseq * (rpkts / tpkts));
                                 if ((resp->lostseq = (unsigned int) drop) == 0)
                                    resp->status &= ~ARGUS_SRC_PKTS_DROP;
                                 else
                                    nesp->lostseq -= resp->lostseq;
                              }
                              break;
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
}


double
ArgusFetchRetrans (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {

      } else {
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];

         if ((net != NULL) && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
            struct ArgusUDTObject *udt = (void *)&net->net_union.udt;
            retn = (udt->src.retrans) * 1.0;
         }
      }
   }

   return (retn);
}

double
ArgusFetchSrcRetrans (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {

      } else {
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];

         if ((net != NULL) && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
            struct ArgusUDTObject *udt = (void *)&net->net_union.udt;
            retn = (udt->src.retrans) * 1.0;
         }                    
      }
   }

   return (retn);
}

double
ArgusFetchDstRetrans (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {

      } else {
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];

         if ((net != NULL) && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
         }                    
      }
   }

   return (retn);
}


double
ArgusFetchPercentRetrans (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchRetrans(ns);
         pkts = metric->src.pkts + metric->dst.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/(pkts * 1.0);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}

double
ArgusFetchPercentSrcRetrans (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchSrcRetrans(ns);
         pkts = metric->src.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/(pkts * 1.0);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}

double
ArgusFetchPercentDstRetrans (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchDstRetrans(ns);
         pkts = metric->dst.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/(pkts * 1.0);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}


double
ArgusFetchNacks (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {

      } else {
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];

         if ((net != NULL) && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
            struct ArgusUDTObject *udt = (void *)&net->net_union.udt;
            retn = (udt->src.nacked) * 1.0;
         }
      }
   }

   return (retn);
}

double
ArgusFetchSrcNacks (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {

      } else {
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];

         if ((net != NULL) && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
            struct ArgusUDTObject *udt = (void *)&net->net_union.udt;
            retn = (udt->src.nacked) * 1.0;
         }                    
      }
   }

   return (retn);
}

double
ArgusFetchDstNacks (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {

      } else {
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];

         if ((net != NULL) && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
         }                    
      }
   }

   return (retn);
}


double
ArgusFetchPercentNacks (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchNacks(ns);
         pkts = metric->src.pkts + metric->dst.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/(pkts * 1.0);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}

double
ArgusFetchPercentSrcNacks (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchSrcNacks(ns);
         pkts = metric->src.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/(pkts * 1.0);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}

double
ArgusFetchPercentDstNacks (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchDstNacks(ns);
         pkts = metric->dst.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/(pkts * 1.0);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}


double
ArgusFetchSolo (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {

      } else {
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];

         if ((net != NULL) && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
            struct ArgusUDTObject *udt = (void *)&net->net_union.udt;
            retn = (udt->src.solo) * 1.0;
         }
      }
   }

   return (retn);
}

double
ArgusFetchSrcSolo (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {

      } else {
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];

         if ((net != NULL) && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
            struct ArgusUDTObject *udt = (void *)&net->net_union.udt;
            retn = (udt->src.solo) * 1.0;
         }                    
      }
   }

   return (retn);
}

double
ArgusFetchDstSolo (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {

      } else {
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];

         if ((net != NULL) && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
         }                    
      }
   }

   return (retn);
}


double
ArgusFetchPercentSolo (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchSolo(ns);
         pkts = metric->src.pkts + metric->dst.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/(pkts * 1.0);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}

double
ArgusFetchPercentSrcSolo (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchSrcSolo(ns);
         pkts = metric->src.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/(pkts * 1.0);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}

double
ArgusFetchPercentDstSolo (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchDstSolo(ns);
         pkts = metric->dst.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/(pkts * 1.0);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}


double
ArgusFetchFirst (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {

      } else {
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];

         if ((net != NULL) && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
            struct ArgusUDTObject *udt = (void *)&net->net_union.udt;
            retn = (udt->src.first) * 1.0;
         }
      }
   }

   return (retn);
}

double
ArgusFetchSrcFirst (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {

      } else {
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];

         if ((net != NULL) && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
            struct ArgusUDTObject *udt = (void *)&net->net_union.udt;
            retn = (udt->src.first) * 1.0;
         }                    
      }
   }

   return (retn);
}

double
ArgusFetchDstFirst (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {

      } else {
         struct ArgusNetworkStruct *net = (void *) ns->dsrs[ARGUS_NETWORK_INDEX];

         if ((net != NULL) && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
         }                    
      }
   }

   return (retn);
}


double
ArgusFetchPercentFirst (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchFirst(ns);
         pkts = metric->src.pkts + metric->dst.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/(pkts * 1.0);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}

double
ArgusFetchPercentSrcFirst (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchSrcFirst(ns);
         pkts = metric->src.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/(pkts * 1.0);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}

double
ArgusFetchPercentDstFirst (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchDstFirst(ns);
         pkts = metric->dst.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/(pkts * 1.0);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}

double
ArgusFetchPercentLoss (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchLoss(ns);
         pkts = metric->src.pkts + metric->dst.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/((pkts * 1.0 )+ retn);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}

double
ArgusFetchPercentSrcLoss (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchSrcLoss(ns);
         pkts = metric->src.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/((pkts * 1.0) + retn);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}

double
ArgusFetchPercentDstLoss (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      if (metric != NULL) {
         retn = ArgusFetchDstLoss(ns);
         pkts = metric->dst.pkts;
         if (pkts > 0) {
            retn = (retn * 100.0)/((pkts * 1.0) + retn);
         } else
            retn = 0.0;
      }
   }

   return (retn);
}

double
ArgusFetchSrcRate (struct ArgusRecordStruct *ns)
{
   double retn = ns->srate;
   return (retn);
}

double
ArgusFetchDstRate (struct ArgusRecordStruct *ns)
{
   double retn = ns->drate;
   return (retn);
}

double
ArgusFetchRate (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   float d1 = RaGetFloatDuration(ns);
   long long cnt1 = 0;
   double retn = 0.0;

   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = (m1->src.pkts + m1->dst.pkts);

   if ((cnt1 > 0) && (d1 > 0.0))
      retn = (cnt1 * 1.0)/d1;

   return (retn);

}

double
ArgusFetchSrcMeanPktSize (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   long long pkts = 0, bytes = 0;
   double retn = 0.0;

   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL) {
      pkts  = m1->src.pkts;
      bytes = m1->src.bytes;
   }

   if (pkts > 0) 
      retn = (bytes * 1.0)/(pkts * 1.0);

   return (retn);
}

double
ArgusFetchDstMeanPktSize (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   long long pkts = 0, bytes = 0;
   double retn = 0.0;

   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL) {
      pkts  = m1->dst.pkts;
      bytes = m1->dst.bytes;
   }
   
   if (pkts > 0) 
      retn = (bytes * 1.0)/(pkts * 1.0);

   return (retn);
}


double
ArgusFetchTranRef (struct ArgusRecordStruct *ns)
{
   double retn = 0;
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

double
ArgusFetchSeq (struct ArgusRecordStruct *ns)
{
   struct ArgusTransportStruct *t1 = (struct ArgusTransportStruct *)ns->dsrs[ARGUS_TRANSPORT_INDEX];
   double retn = 0;

   if (t1->hdr.subtype & ARGUS_SEQ)
      retn = t1->seqnum;
   return (retn);
}


double
ArgusFetchByteCount (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   double retn = 0;
     
   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      retn = m1->src.bytes + m1->dst.bytes;
   return (retn); 
}

double
ArgusFetchSrcByteCount (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   double retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      retn = m1->src.bytes;
   return (retn);
}

double
ArgusFetchDstByteCount (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   double retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      retn = m1->dst.bytes;
 
   return (retn);
}


double
ArgusFetchPktsCount (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   double retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      retn = m1->src.pkts + m1->dst.pkts;
   return (retn);
}

double
ArgusFetchSrcPktsCount (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   double retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      retn = m1->src.pkts;
   return (retn);
}

double
ArgusFetchDstPktsCount (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   double retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      retn = m1->dst.pkts;
   return (retn);
}

double
ArgusFetchAppByteCount (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   double retn = 0;
   
   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      retn = m1->src.appbytes + m1->dst.appbytes;
   return (retn); 
}
 
double
ArgusFetchSrcAppByteCount (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   double retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      retn = m1->src.appbytes;
   return (retn);
}

double
ArgusFetchDstAppByteCount (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   double retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      retn = m1->dst.appbytes;
 
   return (retn);
}

double
ArgusFetchAppByteRatio (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   double retn =  0.0;

   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL) {
      double nvalue = (m1->src.appbytes - m1->dst.appbytes) * 1.0;
      double dvalue = (m1->src.appbytes + m1->dst.appbytes) * 1.0;

      if (dvalue > 0)
         retn = nvalue / dvalue;
      else
         retn = -0.0;
   }
   return (retn);
}

double
ArgusFetchSrcTcpBase (struct ArgusRecordStruct *ns)
{
   struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
   unsigned int seq = 0;
   double retn = 0;

   if ((flow != NULL) && (net != NULL)) {
      struct ArgusTCPObject *tcp = &net->net_union.tcp;

      switch (flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case  IPPROTO_TCP:
                        seq = tcp->src.seqbase;
                        break;
                  }
                  break;

               case ARGUS_TYPE_IPV6:
                  switch (flow->ipv6_flow.ip_p) {
                     case  IPPROTO_TCP:
                        seq = tcp->src.seqbase;
                        break;
                  }
                  break;
            }
            break;
         }
      }
   }

   retn = seq;
   return (retn);
}


double
ArgusFetchDstTcpBase (struct ArgusRecordStruct *ns)
{
   struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
   unsigned int seq = 0;
   double retn = 0;

   if ((flow != NULL) && (net != NULL)) {
      struct ArgusTCPObject *tcp = &net->net_union.tcp;

      switch (flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case  IPPROTO_TCP:
                        seq = tcp->dst.seqbase;
                        break;
                  }
                  break;

               case ARGUS_TYPE_IPV6:
                  switch (flow->ipv6_flow.ip_p) {
                     case  IPPROTO_TCP:
                        seq = tcp->dst.seqbase;
                        break;
                  }
                  break;
            }
            break;
         }
      }
   }

   retn = seq;
   return (retn);
}

double
ArgusFetchTcpRtt (struct ArgusRecordStruct *ns)
{
   struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
   unsigned int rtt = 0;
   double retn = 0;

   if ((flow != NULL) && (net != NULL)) {
      struct ArgusTCPObject *tcp = &net->net_union.tcp;

      switch (flow->hdr.subtype & 0x3F) {


         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case  IPPROTO_TCP:
                        rtt = tcp->synAckuSecs + tcp->ackDatauSecs;
                        break;
                  }
                  break;

               case ARGUS_TYPE_IPV6:
                  switch (flow->ipv6_flow.ip_p) {
                     case  IPPROTO_TCP:
                        rtt = tcp->synAckuSecs + tcp->ackDatauSecs;
                        break;
                  }
                  break;
            }
            break;
         }
      }
   }

   retn = (rtt * 1.0)/1000000.0;
   return (retn);
}


double
ArgusFetchTcpSynAck (struct ArgusRecordStruct *ns)
{
   struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
   unsigned int value = 0;
   double retn = 0;

   if ((flow != NULL) && (net != NULL)) {
      struct ArgusTCPObject *tcp = &net->net_union.tcp;

      switch (flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case  IPPROTO_TCP:
                        value = tcp->synAckuSecs;
                        break;
                  }
                  break;

               case ARGUS_TYPE_IPV6:
                  switch (flow->ipv6_flow.ip_p) {
                     case  IPPROTO_TCP:
                        value = tcp->synAckuSecs;
                        break;
                  }
                  break;
            }
            break;
         }
      }
   }

   retn = (value * 1.0)/1000000.0;
   return (retn);
}

double
ArgusFetchTcpAckDat (struct ArgusRecordStruct *ns)
{
   struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
   unsigned int value = 0;
   double retn = 0;

   if ((flow != NULL) && (net != NULL)) {
      struct ArgusTCPObject *tcp = &net->net_union.tcp;

      switch (flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case  IPPROTO_TCP:
                        value = tcp->ackDatauSecs;
                        break;
                  }
                  break;

               case ARGUS_TYPE_IPV6:
                  switch (flow->ipv6_flow.ip_p) {
                     case  IPPROTO_TCP:
                        value = tcp->ackDatauSecs;
                        break;
                  }
                  break;
            }
            break;
         }
      }
   }

   retn = (value * 1.0)/1000000.0;
   return (retn);
}

double
ArgusFetchSrcTcpMax (struct ArgusRecordStruct *ns)
{
   struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
   double rtt = 0.0, retn = 0.0;

   if ((flow != NULL) && (net != NULL)) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      struct ArgusTCPObject *tcp = &net->net_union.tcp;

      switch (flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case  IPPROTO_TCP: {
                        if ((rtt = ArgusFetchTcpRtt(ns)) > 0.0) {
                           double synack, ackdat;
                           synack = ArgusFetchTcpSynAck(ns);
                           ackdat = ArgusFetchTcpAckDat(ns);
                           if (ackdat < 0.000100) {
                              rtt = synack;
                           } else
                           if (synack < 0.000100) {
                              rtt = ackdat;
                           }

                           if ((metric != NULL) && (metric->dst.pkts > 0)) {
                              unsigned int win = tcp->dst.win << tcp->dst.winshift;
                              retn = (win * 8.0) / (rtt * 1000);
                           }
                           break;
                        }
                     }
                     default:
                        break;
                  }
                  break;

               case ARGUS_TYPE_IPV6:
                  switch (flow->ipv6_flow.ip_p) {
                     case  IPPROTO_TCP: {
                        if ((rtt = ArgusFetchTcpRtt(ns)) > 0.0) {
                           double synack, ackdat;
                           synack = ArgusFetchTcpSynAck(ns);
                           ackdat = ArgusFetchTcpAckDat(ns);
                           if (ackdat < 0.000100) {
                              rtt = synack;
                           } else 
                           if (synack < 0.000100) {
                              rtt = ackdat;
                           }
                           if ((metric != NULL) && (metric->dst.pkts > 0)) {
                              unsigned int win = tcp->dst.win << tcp->dst.winshift;
                              retn = (win * 8.0) / (rtt * 1000);
                           }
                           break;
                        }
                     }
                     default:
                        break;
                  }
                  break;
            }
            break;
         }

         default:
            break;
      }
   }
   return (retn);
}


double
ArgusFetchDstTcpMax (struct ArgusRecordStruct *ns)
{
   struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
   double rtt = 0.0, retn = 0.0;

   if ((flow != NULL) && (net != NULL)) {
      struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
      struct ArgusTCPObject *tcp = &net->net_union.tcp;

      switch (flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case  IPPROTO_TCP: {
                        if ((rtt = ArgusFetchTcpRtt(ns)) > 0.0) {
                           double synack, ackdat;
                           synack = ArgusFetchTcpSynAck(ns);
                           ackdat = ArgusFetchTcpAckDat(ns);
                           if (ackdat < 0.000100) {
                              rtt = synack;
                           } else
                           if (synack < 0.000100) {
                              rtt = ackdat;
                           }

                           if ((metric != NULL) && (metric->src.pkts > 0)) {
                              unsigned int win = tcp->src.win << tcp->src.winshift;
                              retn = (win * 8.0) / rtt;
                           }
                        }
                        break;
                     }
                     default:
                        break;
                  }
                  break;

               case ARGUS_TYPE_IPV6:
                  switch (flow->ipv6_flow.ip_p) {
                     case  IPPROTO_TCP: {
                        if ((rtt = ArgusFetchTcpRtt(ns)) > 0.0) {
                           double synack, ackdat;
                           synack = ArgusFetchTcpSynAck(ns);
                           ackdat = ArgusFetchTcpAckDat(ns);
                           if (ackdat < 0.000100) {
                              rtt = synack;
                           } else
                           if (synack < 0.000100) {
                              rtt = ackdat;
                           }

                           if ((metric != NULL) && (metric->src.pkts > 0)) {
                              unsigned int win = tcp->src.win << tcp->src.winshift;
                              retn = (win * 8.0) / rtt;
                           }
                        }
                        break;
                     }
                     default:
                        break;
                  }
                  break;
            }
            break;
         }

         default:
            break;
      }
   }
   return (retn);
}


double
ArgusFetchSrcGap (struct ArgusRecordStruct *ns)
{
   struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
   double retn = -1;

   if ((flow != NULL) && (net != NULL)) {
      switch (flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case  IPPROTO_TCP: {
                        retn = 0;
                        switch (net->hdr.subtype) {
                           case ARGUS_TCP_INIT:
                           case ARGUS_TCP_STATUS:
                              break;
                           
                           case ARGUS_TCP_PERF: {
                              struct ArgusTCPObject *tcp = (struct ArgusTCPObject *) &net->net_union.tcp;
                              if ((tcp->src.seqbase == tcp->src.ackbytes) || (tcp->src.seq == 0))            // prior version of argus
                                 break;

                              if (!tcp->src.retrans) {
                                 retn = (tcp->src.seq - tcp->src.seqbase);
                                 if ((retn == tcp->src.bytes) || (retn == (tcp->src.bytes - tcp->src.winbytes)))
                                    retn = 0;
                                 else {
                                    if ((retn -= tcp->src.bytes) < 0)
                                       retn = 0;
                                    if (retn > 0) retn--;
                                 }
                              }
                              break;
                           }
                        }
                        break;
                     }
                     default:
                        break;
                  }
                  break;

               case ARGUS_TYPE_IPV6:
                  switch (flow->ipv6_flow.ip_p) {
                     case  IPPROTO_TCP: {
                        retn = 0;
                        switch (net->hdr.subtype) {
                           case ARGUS_TCP_INIT: 
                           case ARGUS_TCP_STATUS: 
                              break;
                           
                           case ARGUS_TCP_PERF: {
                              struct ArgusTCPObject *tcp = (struct ArgusTCPObject *) &net->net_union.tcp;
                              if ((tcp->src.seqbase == tcp->src.ackbytes) || (tcp->src.seq == 0))            // prior version of argus
                                 break;

                              if (!tcp->src.retrans) {
                                 retn = (tcp->src.seq - tcp->src.seqbase);
                                 if ((retn == tcp->src.bytes) || (retn == (tcp->src.bytes - tcp->src.winbytes)))
                                    retn = 0;
                                 else {
                                    if ((retn -= tcp->src.bytes) < 0)
                                       retn = 0;
                                    if (retn > 0) retn--;
                                 }
                              }
                              break;
                           }
                        }
                        break;
                     }
                     default:
                        break;
                  }
                  break;
            }
            break;
         }

         default:
            break;
      }
   }
   return (retn);
}

double
ArgusFetchDstGap (struct ArgusRecordStruct *ns)
{
   struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
   double retn = -1;

   if ((flow != NULL) && (net != NULL)) {
      switch (flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case  IPPROTO_TCP: {
                        retn = 0;
                        switch (net->hdr.subtype) {
                           case ARGUS_TCP_INIT:
                           case ARGUS_TCP_STATUS:
                              break;

                           case ARGUS_TCP_PERF: {
                              struct ArgusTCPObject *tcp = (struct ArgusTCPObject *) &net->net_union.tcp;
                              if ((tcp->dst.seqbase == tcp->dst.ackbytes) || (tcp->dst.seq == 0))            // prior version of argus
                                 break;

                              if (!tcp->dst.retrans) {
                                 retn = (tcp->dst.seq - tcp->dst.seqbase);
                                 if ((retn == tcp->dst.bytes) || (retn == (tcp->dst.bytes - tcp->dst.winbytes)))
                                    retn = 0;
                                 else {
                                    if ((retn -= tcp->dst.bytes) < 0)
                                       retn = 0;
                                    if (retn > 0) retn--;
                                 }
                              }
                              break;
                           }
                        }
                        break;
                     }
                     default:
                        break;
                  }
                  break;

               case ARGUS_TYPE_IPV6:
                  switch (flow->ipv6_flow.ip_p) {
                     case  IPPROTO_TCP: {
                        retn = 0;
                        switch (net->hdr.subtype) {
                           case ARGUS_TCP_INIT:
                           case ARGUS_TCP_STATUS:
                              break;

                           case ARGUS_TCP_PERF: {
                              struct ArgusTCPObject *tcp = (struct ArgusTCPObject *) &net->net_union.tcp;
                              if ((tcp->dst.seqbase == tcp->dst.ackbytes) || (tcp->dst.seq == 0))            // prior version of argus
                                 break;

                              if (!tcp->dst.retrans) {
                                 retn = (tcp->dst.seq - tcp->dst.seqbase);
                                 if ((retn == tcp->dst.bytes) || (retn == (tcp->dst.bytes - tcp->dst.winbytes)))
                                    retn = 0;
                                 else {
                                    if ((retn -= tcp->dst.bytes) < 0)
                                       retn = 0;
                                    if (retn > 0) retn--;
                                 }
                              }
                              break;
                           }
                        }
                        break;
                     }
                     default:
                        break;
                  }
                  break;
            }
            break;
         }

         default:
            break;
      }
   }
   return (retn);
}

double
ArgusFetchSrcDup (struct ArgusRecordStruct *ns)
{
   struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
   double retn = -1;

   if ((flow != NULL) && (net != NULL)) {
      switch (flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case  IPPROTO_TCP: {
                        retn = 0;
                        switch (net->hdr.subtype) {
                           case ARGUS_TCP_INIT:
                           case ARGUS_TCP_STATUS:
                              break;
                           
                           case ARGUS_TCP_PERF: {
//                            struct ArgusTCPObject *tcp = (struct ArgusTCPObject *) &net->net_union.tcp;
//                            retn = tcp->sdups;
                              retn = 0;
                              break;
                           }
                        }
                        break;
                     }
                     default:
                        break;
                  }
                  break;

               case ARGUS_TYPE_IPV6:
                  switch (flow->ipv6_flow.ip_p) {
                     case  IPPROTO_TCP: {
                        retn = 0;
                        switch (net->hdr.subtype) {
                           case ARGUS_TCP_INIT: 
                           case ARGUS_TCP_STATUS: 
                              break;
                           
                           case ARGUS_TCP_PERF: {
//                            struct ArgusTCPObject *tcp = (struct ArgusTCPObject *) &net->net_union.tcp;
//                            retn = tcp->sdups;
                              retn = 0;
                              break;
                           }
                        }
                        break;
                     }
                     default:
                        break;
                  }
                  break;
            }
            break;
         }

         default:
            break;
      }
   }
   return (retn);
}

double
ArgusFetchDstDup (struct ArgusRecordStruct *ns)
{
   struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
   double retn = -1;

   if ((flow != NULL) && (net != NULL)) {
      switch (flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case  IPPROTO_TCP: {
                        retn = 0;
                        switch (net->hdr.subtype) {
                           case ARGUS_TCP_INIT:
                           case ARGUS_TCP_STATUS:
                              break;

                           case ARGUS_TCP_PERF: {
//                            struct ArgusTCPObject *tcp = (struct ArgusTCPObject *) &net->net_union.tcp;
//                            retn = tcp->ddups;
                              retn = 0;
                              break;
                           }
                        }
                        break;
                     }
                     default:
                        break;
                  }
                  break;

               case ARGUS_TYPE_IPV6:
                  switch (flow->ipv6_flow.ip_p) {
                     case  IPPROTO_TCP: {
                        retn = 0;
                        switch (net->hdr.subtype) {
                           case ARGUS_TCP_INIT:
                           case ARGUS_TCP_STATUS:
                              break;

                           case ARGUS_TCP_PERF: {
//                            struct ArgusTCPObject *tcp = (struct ArgusTCPObject *) &net->net_union.tcp;
//                            retn = tcp->ddups;
                              retn = 0;
                              break;
                           }
                        }
                        break;
                     }
                     default:
                        break;
                  }
                  break;
            }
            break;
         }

         default:
            break;
      }
   }
   return (retn);
}

double
ArgusFetchIntFlow (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusAgrStruct *agr;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      unsigned int n;

      if ((agr = (struct ArgusAgrStruct *)ns->dsrs[ARGUS_AGR_INDEX]) != NULL) {
         if ((n = agr->idle.n) > 0) {
            retn = agr->idle.meanval;
         }
      }
   }
   return (retn);
}

double
ArgusFetchIntFlowStdDev (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusAgrStruct *agr;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if ((agr = (struct ArgusAgrStruct *)ns->dsrs[ARGUS_AGR_INDEX]) != NULL)
         if (agr->act.n > 0)
            retn = agr->act.stdev;
   }

   return (retn/1000.0);
   return (retn);
}

double
ArgusFetchIntFlowMax (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusAgrStruct *agr;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if ((agr = (struct ArgusAgrStruct *)ns->dsrs[ARGUS_AGR_INDEX]) != NULL) {
         retn = agr->idle.maxval;
      }
   }
   return (retn);
}

double
ArgusFetchIntFlowMin (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusAgrStruct *agr;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if ((agr = (struct ArgusAgrStruct *)ns->dsrs[ARGUS_AGR_INDEX]) != NULL) {
         retn = agr->idle.minval;
      }
   }
   return (retn);
}

double
ArgusFetchSrcIntPkt (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      unsigned int n;

      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL) {
         if ((n = (jitter->src.act.n + jitter->src.idle.n)) > 0) {
            if (jitter->src.act.n && jitter->src.idle.n) {
               retn  = ((jitter->src.act.meanval * jitter->src.act.n) +
                        (jitter->src.idle.meanval * jitter->src.idle.n)) / n;
            } else {
               retn = (jitter->src.act.n) ? jitter->src.act.meanval : jitter->src.idle.meanval;
            }
         }
      }
   }

   return (retn/1000.0);
}

double
ArgusFetchSrcIntPktAct (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)
         if (jitter->src.act.n > 0)
            retn = jitter->src.act.meanval;
   }

   return (retn/1000.0);
}

double
ArgusFetchSrcIntPktActMin (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)
         if (jitter->src.act.n > 0)
            retn = jitter->src.act.minval;
   }

   return (retn/1000.0);
}

double
ArgusFetchSrcIntPktActMax (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)
         if (jitter->src.act.n > 0)
            retn = jitter->src.act.maxval;
   }

   return (retn/1000.0);
}

double
ArgusFetchSrcIntPktIdl (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {
   
   } else {
      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL) 
         if (jitter->src.idle.n > 0)
            retn = jitter->src.idle.meanval;
   }        
         
   return (retn/1000.0);
} 


double
ArgusFetchSrcIntPktIdlMin (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)
         if (jitter->src.idle.n > 0)
            retn = jitter->src.idle.minval;
   }

   return (retn/1000.0);
}

double
ArgusFetchSrcIntPktIdlMax (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)
         if (jitter->src.idle.n > 0)
            retn = jitter->src.idle.maxval;
   }

   return (retn/1000.0);
}

double
ArgusFetchDstIntPkt (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      unsigned int n;

      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL) {
         if ((n = (jitter->src.act.n + jitter->src.idle.n)) > 0) {
            if (jitter->src.act.n && jitter->src.idle.n) {
               retn  = ((jitter->src.act.meanval * jitter->src.act.n) +
                        (jitter->src.idle.meanval * jitter->src.idle.n)) / n;
            } else {
               retn = (jitter->src.act.n) ? jitter->src.act.meanval : jitter->src.idle.meanval;
            }
         }
      }
   }

   return (retn/1000.0);
}

double
ArgusFetchDstIntPktAct (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {
   
   } else {
      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL) 
         if (jitter->dst.act.n > 0)
            retn = jitter->dst.act.meanval;
   }        
         
   return (retn/1000.0);
}  

double
ArgusFetchDstIntPktActMin (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)
         if (jitter->dst.act.n > 0)
            retn = jitter->dst.act.minval;
   }

   return (retn/1000.0);
}

double
ArgusFetchDstIntPktActMax (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)
         if (jitter->dst.act.n > 0)
            retn = jitter->dst.act.maxval;
   }

   return (retn/1000.0);
}


double
ArgusFetchDstIntPktIdl (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)
         if (jitter->dst.idle.n > 0)
            retn = jitter->dst.idle.meanval;
   }

   return (retn/1000.0);
}

double
ArgusFetchDstIntPktIdlMin (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)
         if (jitter->dst.idle.n > 0)
            retn = jitter->dst.idle.minval;
   }

   return (retn/1000.0);
}

double
ArgusFetchDstIntPktIdlMax (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if ((jitter = (struct ArgusJitterStruct *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)
         if (jitter->dst.idle.n > 0)
            retn = jitter->dst.idle.maxval;
   }

   return (retn/1000.0);
}


double
ArgusFetchSrcJitter (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if (ns && ((jitter = (void *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)) {
         double stdev = 0.0, sumsqrd1 = 0.0, sumsqrd2 = 0.0, sumsqrd;
         unsigned int n;
         float meanval;

         if ((n = (jitter->src.act.n + jitter->src.idle.n)) > 0) {
            if (jitter->src.act.n && jitter->src.idle.n) {
               meanval  = ((jitter->src.act.meanval * jitter->src.act.n) +
                          (jitter->src.idle.meanval * jitter->src.idle.n)) / n;

               if (jitter->src.act.n) {
                  stdev = jitter->src.act.stdev;
                  sumsqrd1 = (jitter->src.act.n * pow(stdev, 2.0)) +
                              pow((jitter->src.act.meanval * jitter->src.act.n), 2.0)/jitter->src.act.n;
               }

               if (jitter->src.idle.n) {
                  stdev = jitter->src.idle.stdev;
                  sumsqrd2 = (jitter->src.idle.n * pow(stdev, 2.0)) +
                              pow((jitter->src.idle.meanval * jitter->src.idle.n), 2.0)/jitter->src.idle.n;
               }

               sumsqrd = sumsqrd1 + sumsqrd2;
               sumsqrd = sumsqrd / 1000;
               meanval = meanval / 1000.0;
               retn    = ((sqrt ((sumsqrd/n) - pow (meanval, 2.0))) * 1);

            } else {
               retn = (jitter->src.act.n) ? jitter->src.act.stdev : jitter->src.idle.stdev;
               retn = retn / 1000.0;
            }
         }
      }
   }

   return (retn);
}

double
ArgusFetchSrcJitterAct (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if (ns && ((jitter = (void *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)) {
         if (jitter->src.act.n) {
            retn = jitter->src.act.stdev;
            retn = retn / 1000.0;
         }
      }
   }

   return (retn);
}

double
ArgusFetchSrcJitterIdl (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if (ns && ((jitter = (void *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)) {
         if (jitter->src.idle.n) {
            retn = jitter->src.idle.stdev;
            retn = retn / 1000.0;
         }
      }
   }

   return (retn);
} 


double
ArgusFetchDstJitter (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if (ns && ((jitter = (void *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)) {
         double stdev = 0.0, sumsqrd1 = 0.0, sumsqrd2 = 0.0, sumsqrd;
         unsigned int n;
         float meanval;

         if ((n = (jitter->dst.act.n + jitter->dst.idle.n)) > 0) {
            if (jitter->dst.act.n && jitter->dst.idle.n) {
               meanval  = ((jitter->dst.act.meanval * jitter->dst.act.n) +
                          (jitter->dst.idle.meanval * jitter->dst.idle.n)) / n;

               if (jitter->dst.act.n) {
                  stdev = jitter->dst.act.stdev;
                  sumsqrd1 = (jitter->dst.act.n * pow(stdev, 2.0)) +
                              pow((jitter->dst.act.meanval * jitter->dst.act.n), 2.0)/jitter->dst.act.n;
               }

               if (jitter->dst.idle.n) {
                  stdev = jitter->dst.idle.stdev;
                  sumsqrd2 = (jitter->dst.idle.n * pow(stdev, 2.0)) +
                              pow((jitter->dst.idle.meanval * jitter->dst.idle.n), 2.0)/jitter->dst.idle.n;
               }

               sumsqrd = sumsqrd1 + sumsqrd2;
               sumsqrd = sumsqrd / 1000;
               meanval = meanval / 1000.0;
               retn    = ((sqrt ((sumsqrd/n) - pow (meanval, 2.0))) * 1);

            } else {
               retn = (jitter->dst.act.n) ? jitter->dst.act.stdev : jitter->dst.idle.stdev;
               retn = retn / 1000.0;
            }
         }
      }
   }

   return (retn);
}


double
ArgusFetchDstJitterAct (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if (ns && ((jitter = (void *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)) {
         if (jitter->dst.act.n) {
            retn = jitter->dst.act.stdev;
            retn = retn / 1000.0;
         }
      }
   }

   return (retn);
}  

double
ArgusFetchDstJitterIdl (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   struct ArgusJitterStruct *jitter;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      if (ns && ((jitter = (void *)ns->dsrs[ARGUS_JITTER_INDEX]) != NULL)) {
         if (jitter->dst.idle.n) {
            retn = jitter->dst.idle.stdev;
            retn = retn / 1000.0;
         }
      }
   }

   return (retn);
}
   
double
ArgusFetchSrcWindow (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns->hdr.type & ARGUS_MAR) {
  
   } else {
      struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
      struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
      unsigned int win = 0;

      if (net && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
         retn = net->net_union.udt.src.bsize; 

      } else {
         if ((flow != NULL) && (net != NULL)) {
            struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
            struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];

            if ((metric != NULL) && (metric->src.pkts > 0)) {
               switch (flow->hdr.subtype & 0x3F) {
                  case ARGUS_FLOW_CLASSIC5TUPLE: {
                     switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                        case ARGUS_TYPE_IPV4:
                           switch (flow->ip_flow.ip_p) {
                              case  IPPROTO_TCP: {
                                 win = tcp->src.win << tcp->src.winshift;
                                 break;
                              }
                              default:
                                 break;
                           }
                           break;
         
                        case ARGUS_TYPE_IPV6:
                           switch (flow->ipv6_flow.ip_p) {
                              case  IPPROTO_TCP: {
                                 win = tcp->src.win << tcp->src.winshift;
                                 break;
                              }
                              default:
                                 break;
                           }
                           break;
                     }
                     break;
                  }
         
                  default:
                     break;
               }

               retn = win;
            }
         }
      }
   }

   return (retn);
}


double
ArgusFetchDstWindow (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns->hdr.type & ARGUS_MAR) {
 
   } else {
      struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
      struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
      unsigned int win = 0;

      if (net && (net->hdr.subtype == ARGUS_UDT_FLOW)) {

      } else {
         if ((flow != NULL) && (net != NULL)) {
            struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
            struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;

            if ((metric != NULL) && (metric->dst.pkts > 0)) {
               switch (flow->hdr.subtype & 0x3F) {
                  case ARGUS_FLOW_CLASSIC5TUPLE: {
                     switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                        case ARGUS_TYPE_IPV4:
                           switch (flow->ip_flow.ip_p) {
                              case  IPPROTO_TCP: {
                                 win = tcp->dst.win << tcp->dst.winshift;
                                 break;
                              }
                              default:
                                 break;
                           }
                           break;
        
                        case ARGUS_TYPE_IPV6:
                           switch (flow->ipv6_flow.ip_p) {
                              case  IPPROTO_TCP: {
                                 win = tcp->dst.win << tcp->dst.winshift;
                                 break;
                              }
                              default:
                                 break;
                           }
                           break;
                     }
                     break;
                  }
        
                  default:
                     break;
               }

               retn = win;
            }
         }
      }
   }
   return (retn);
}

double
ArgusFetchSrcMaxSeg (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns->hdr.type & ARGUS_MAR) {
  
   } else {
      struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
      struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
      unsigned int mss = 0;

      if (net && (net->hdr.subtype == ARGUS_UDT_FLOW)) {
         retn = net->net_union.udt.src.bsize; 

      } else {
         if ((flow != NULL) && (net != NULL)) {
            struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
            struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];

            if ((metric != NULL) && (metric->src.pkts > 0)) {
               switch (flow->hdr.subtype & 0x3F) {
                  case ARGUS_FLOW_CLASSIC5TUPLE: {
                     switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                        case ARGUS_TYPE_IPV4:
                           switch (flow->ip_flow.ip_p) {
                              case  IPPROTO_TCP: {
                                 mss = tcp->src.maxseg;
                                 break;
                              }
                              default:
                                 break;
                           }
                           break;
         
                        case ARGUS_TYPE_IPV6:
                           switch (flow->ipv6_flow.ip_p) {
                              case  IPPROTO_TCP: {
                                 mss = tcp->src.maxseg;
                                 break;
                              }
                              default:
                                 break;
                           }
                           break;
                     }
                     break;
                  }
         
                  default:
                     break;
               }

               retn = mss;
            }
         }
      }
   }

   return (retn);
}


double
ArgusFetchDstMaxSeg (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns->hdr.type & ARGUS_MAR) {
 
   } else {
      struct ArgusNetworkStruct *net = (void *)ns->dsrs[ARGUS_NETWORK_INDEX];
      struct ArgusFlow *flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX];
      unsigned int mss = 0;

      if (net && (net->hdr.subtype == ARGUS_UDT_FLOW)) {

      } else {
         if ((flow != NULL) && (net != NULL)) {
            struct ArgusMetricStruct *metric = (void *)ns->dsrs[ARGUS_METRIC_INDEX];
            struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;

            if ((metric != NULL) && (metric->dst.pkts > 0)) {
               switch (flow->hdr.subtype & 0x3F) {
                  case ARGUS_FLOW_CLASSIC5TUPLE: {
                     switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                        case ARGUS_TYPE_IPV4:
                           switch (flow->ip_flow.ip_p) {
                              case  IPPROTO_TCP: {
                                 mss = tcp->dst.maxseg;
                                 break;
                              }
                              default:
                                 break;
                           }
                           break;
        
                        case ARGUS_TYPE_IPV6:
                           switch (flow->ipv6_flow.ip_p) {
                              case  IPPROTO_TCP: {
                                 mss = tcp->dst.maxseg;
                                 break;
                              }
                              default:
                                 break;
                           }
                           break;
                     }
                     break;
                  }
        
                  default:
                     break;
               }

               retn = mss;
            }
         }
      }
   }
   return (retn);
}

double
ArgusFetchDeltaDuration (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
 
   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      struct ArgusCorrelateStruct *cor = (void *)ns->dsrs[ARGUS_COR_INDEX];
      if (cor != NULL)
         retn = cor->metrics.deltaDur / 1000000.0;
   }
   return (retn);
}

double
ArgusFetchDeltaStartTime (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
 
   if (ns->hdr.type & ARGUS_MAR) {
   
   } else {
      struct ArgusCorrelateStruct *cor = (void *)ns->dsrs[ARGUS_COR_INDEX];
      if (cor != NULL) 
         retn = cor->metrics.deltaStart / 1000000.0;
   }
   return (retn);
}

double
ArgusFetchDeltaLastTime (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
 
   if (ns->hdr.type & ARGUS_MAR) {
   
   } else {
      struct ArgusCorrelateStruct *cor = (void *)ns->dsrs[ARGUS_COR_INDEX];
      if (cor != NULL) 
         retn = cor->metrics.deltaLast / 1000000.0;
   }
   return (retn);
}

double
ArgusFetchDeltaSrcPkts (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      struct ArgusCorrelateStruct *cor = (void *)ns->dsrs[ARGUS_COR_INDEX];
      if (cor != NULL)
         retn = cor->metrics.deltaSrcPkts * 1.0;
   }
   return (retn);
}

double
ArgusFetchDeltaDstPkts (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns->hdr.type & ARGUS_MAR) {

   } else {
      struct ArgusCorrelateStruct *cor = (void *)ns->dsrs[ARGUS_COR_INDEX];
      if (cor != NULL)
         retn = cor->metrics.deltaDstPkts * 1.0;
   }
   return (retn);
}


double
ArgusFetchIpId (struct ArgusRecordStruct *ns)
{
   double retn = 0;
   return (retn);
}


double
ArgusFetchLocality (struct ArgusRecordStruct *ns)
{
   double retn = 0;
   return (retn);
}

double
ArgusFetchSrcLocality (struct ArgusRecordStruct *ns)
{
   struct ArgusNetspatialStruct *local = (struct ArgusNetspatialStruct *) ns->dsrs[ARGUS_LOCAL_INDEX];
   struct ArgusLabelerStruct *labeler;
   double retn = 0;

   if (ns->hdr.type & ARGUS_MAR) {
   } else {
      int locValue = -1;

      if (local != NULL) {
         locValue = local->sloc;
      } else {
         struct ArgusFlow *flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];
         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        if ((labeler = ArgusParser->ArgusLocalLabeler) != NULL) {
                           locValue = RaFetchAddressLocality (ArgusParser, labeler, &flow->ip_flow.ip_src, flow->ip_flow.smask, ARGUS_TYPE_IPV4, ARGUS_NODE_MATCH);
                           break;
                        }
                     }
                  }
               }
            }
         }
      }
      retn = locValue;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "ArgusFetchSrcLocality (%p, %p)", ns);
#endif
   return (retn);
}

double
ArgusFetchDstLocality (struct ArgusRecordStruct *ns)
{
   struct ArgusNetspatialStruct *local = (struct ArgusNetspatialStruct *) ns->dsrs[ARGUS_LOCAL_INDEX];
   struct ArgusLabelerStruct *labeler;
   double retn = 0;

   if (ns->hdr.type & ARGUS_MAR) {
   } else {
      int locValue = -1;

      if (local != NULL) {
         locValue = local->dloc;
      } else {
         struct ArgusFlow *flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];
         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        if ((labeler = ArgusParser->ArgusLocalLabeler) != NULL) {
                           locValue = RaFetchAddressLocality (ArgusParser, labeler, &flow->ip_flow.ip_dst, flow->ip_flow.smask, ARGUS_TYPE_IPV4, ARGUS_NODE_MATCH);
                           break;
                        }
                     }
                  }
               }
            }
         }
      }
      retn = locValue;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "ArgusFetchSrcLocality (%p, %p)", ns);
#endif
   return (retn);
}


struct ArgusSorterStruct *ArgusNewSorter (struct ArgusParserStruct *parser);

struct ArgusSorterStruct *
ArgusNewSorter (struct ArgusParserStruct *parser)
{
   struct ArgusSorterStruct *retn = NULL;
   
   if ((retn = (struct ArgusSorterStruct *) ArgusCalloc (1, sizeof (*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewSorter ArgusCalloc error %s", strerror(errno));
  
   if ((retn->ArgusRecordQueue = ArgusNewQueue()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewSorter ArgusNewQueue error %s", strerror(errno));

   if (parser && (parser->RaSortOptionIndex > 0)) {
      int i, x, s = 0;

      for (i = 0; i < parser->RaSortOptionIndex; i++) {
         char *ptr, *str = parser->RaSortOptionStrings[i];
         for (x = 0; x < MAX_SORT_ALG_TYPES; x++) {
            if (!strncmp (ArgusSortKeyWords[x], str, strlen(ArgusSortKeyWords[x]))) {
               retn->ArgusSortAlgorithms[s++] = ArgusSortAlgorithmTable[x];
               if (ArgusSortAlgorithmTable[x] == ArgusSortSrcAddr) {
                  if ((ptr = strchr(str, '/')) != NULL) {
                     int cidr = 0;
                     ptr++;
                     cidr = atoi(ptr);
                     ArgusSorter->ArgusSrcAddrCIDR = cidr;
                  }
               }
               if (ArgusSortAlgorithmTable[x] == ArgusSortDstAddr) {
                  if ((ptr = strchr(str, '/')) != NULL) {
                     int cidr = 0;
                     ptr++;
                     cidr = atoi(ptr);
                     retn->ArgusSrcAddrCIDR = cidr;
                  }
               }
               break;
            }
         }

         if (x == MAX_SORT_ALG_TYPES)
            ArgusLog (LOG_ERR, "sort syntax error. \'%s\' not supported", str);
      }
   }

   return (retn);
}

void
ArgusDeleteSorter (struct ArgusSorterStruct *sort)
{
   if (sort != NULL) {
      if (sort->ArgusRecordQueue != NULL)
         ArgusDeleteQueue(sort->ArgusRecordQueue);
   
      ArgusFree (sort);
      ArgusSorter = NULL;
   }
}



void
ArgusSortQueue (struct ArgusSorterStruct *sorter, struct ArgusQueueStruct *queue, int type)
{
   int i = 0, cnt;

   if (ArgusSorter->ArgusSortAlgorithms[0] != NULL) {
#if defined(ARGUS_THREADS)
      if (type == ARGUS_LOCK)
         pthread_mutex_lock(&queue->lock);
#endif

      if (queue->array != NULL) {
         ArgusFree(queue->array);
         queue->array = NULL;
         queue->arraylen = 0;
      }

      cnt = queue->count;

      if ((queue->array = (struct ArgusQueueHeader **) ArgusMalloc(sizeof(struct ArgusQueueHeader *) * (cnt + 1))) != NULL) {
         struct ArgusQueueHeader *qhdr;

         for (i = 0; i < cnt; i++)
            if ((qhdr = ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL)
               queue->array[i] = qhdr;

         queue->array[i] = NULL;

         if (cnt > 1)
            qsort ((char *) queue->array, cnt, sizeof (struct ArgusQueueHeader *), ArgusSortRoutine);

         for (i = 0; i < cnt; i++)
            ArgusAddToQueue(queue, queue->array[i], ARGUS_NOLOCK);

         queue->arraylen = cnt;
      } else
         ArgusLog (LOG_ERR, "ArgusSortQueue: ArgusMalloc %s\n", strerror(errno));

#if defined(ARGUS_THREADS)
      if (type == ARGUS_LOCK)
         pthread_mutex_unlock(&queue->lock);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusSortQueue(%p, %p, %d) returned\n", sorter, queue, type);
#endif
}



int
ArgusSortRoutine (const void *void1, const void *void2)
{
   int retn = 0, i = 0;
   struct ArgusRecordStruct *ns1 = *(struct ArgusRecordStruct **)void1;
   struct ArgusRecordStruct *ns2 = *(struct ArgusRecordStruct **)void2;

   if (ns1 && ns2) {
      for (i = 0; i < ARGUS_MAX_SORT_ALG; i++)
         if (ArgusSorter->ArgusSortAlgorithms[i] != NULL) {
            if ((retn = ArgusSorter->ArgusSortAlgorithms[i](ns2, ns1)) != 0)
               break;
         } else
            break;
   }

   return (retn);
}


static int
ArgusSortTransportStruct(const struct ArgusTransportStruct * const t1,
                         const struct ArgusTransportStruct * const t2,
                         int include_inf)
{
   unsigned int *sid1 = NULL, *sid2 = NULL;
   int retn = 0, len = 0, i;

   if (t1 && !t2)
      return 1;

   if (!t1 && t2)
      return -1;

   if (t1 && t2) {
      if ((t1->hdr.subtype & ARGUS_SRCID) && (t2->hdr.subtype & ARGUS_SRCID)) {
         sid1 = (unsigned int *)&t1->srcid.a_un;
         sid2 = (unsigned int *)&t2->srcid.a_un;

         if (include_inf
             && ((t1->hdr.argus_dsrvl8.qual & ARGUS_TYPE_INTERFACE)
                  || (t2->hdr.argus_dsrvl8.qual & ARGUS_TYPE_INTERFACE))) {
            len = 5;
         } else 
         if ((t1->hdr.argus_dsrvl8.qual & ~ARGUS_TYPE_INTERFACE) == (t2->hdr.argus_dsrvl8.qual & ~ARGUS_TYPE_INTERFACE)) {
            switch (t1->hdr.argus_dsrvl8.qual & ~ARGUS_TYPE_INTERFACE) {
               case ARGUS_TYPE_INT:
               case ARGUS_TYPE_IPV4:
               case ARGUS_TYPE_STRING:
                  len = 1;
                  break;

               case ARGUS_TYPE_IPV6:
               case ARGUS_TYPE_UUID:
                  len = 4;
                  break;
            }
         }
      }

      if (sid1 && sid2) {
         for (i = 0; i < len; i++, sid1++, sid2++) {
            if (*sid2 != *sid1) {
               retn = sid2[i] - sid1[i];
               break;
            }
         }
      }
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortSrcId (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusTransportStruct *t1 = (struct ArgusTransportStruct *)n1->dsrs[ARGUS_TRANSPORT_INDEX];
   struct ArgusTransportStruct *t2 = (struct ArgusTransportStruct *)n2->dsrs[ARGUS_TRANSPORT_INDEX];

   if (t1 && t2)
      return ArgusSortTransportStruct(t1, t2, 1 /* include interface */ );

   return 0;
}


int
ArgusSortSID (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusTransportStruct *t1 = (struct ArgusTransportStruct *)n1->dsrs[ARGUS_TRANSPORT_INDEX];
   struct ArgusTransportStruct *t2 = (struct ArgusTransportStruct *)n2->dsrs[ARGUS_TRANSPORT_INDEX];

   if (t1 && t2)
      return ArgusSortTransportStruct(t1, t2, 0 /* don't include interface */ );

   return 0;
}


int
ArgusSortInf (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusTransportStruct *t1 = (struct ArgusTransportStruct *)n1->dsrs[ARGUS_TRANSPORT_INDEX];
   struct ArgusTransportStruct *t2 = (struct ArgusTransportStruct *)n2->dsrs[ARGUS_TRANSPORT_INDEX];
   int retn = 0;

   if (t1 && t2) {
      if ((t1->hdr.subtype & ARGUS_SRCID) && (t2->hdr.subtype & ARGUS_SRCID))
         if ((t1->hdr.argus_dsrvl8.qual & ARGUS_TYPE_INTERFACE) && (t2->hdr.argus_dsrvl8.qual & ARGUS_TYPE_INTERFACE))
            retn = strcmp((const char *)t2->srcid.inf, (const char *)t1->srcid.inf);
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortCompare (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   int retn = 0;

// The concept is that you want row sorted in this order
//       [baseline, nomatch]
//       [baseline, match]
//       [new]

   if (n1 && n2) {
      int s1 = 0, s2 = 0; // baseline, nomatch

      if (n1->status & ARGUS_RECORD_MATCH) s1 += 1;
      if (n2->status & ARGUS_RECORD_MATCH) s2 += 1;

      if (!(n1->status & ARGUS_RECORD_BASELINE)) s1 += 8; // not baseline, then new
      if (!(n2->status & ARGUS_RECORD_BASELINE)) s2 += 8; // not baseline, then new

   // baseline, match, new is the scale for sorting ... gives you missing, matches, 
   // and new in that order
      retn = (s2 > s1) ? 1 : (s2 == s1) ? 0 : -1;
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortMacClass (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   return (ArgusSortSrcMacClass(n1, n2));
}

int
ArgusSortSrcMacClass (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusMacStruct *m1 = NULL, *m2 = NULL;
   int s1 = 0, s2 = 0, retn = 0;

// The concept is that you want to sort based on the class of the mac address.
// This is primarily for ramatrix, which wants the list sorted by,
// Broadcast, Multicast, Addresses in reverse order based on sort algorithm ...
//
// So we'll make anything with 'cas_' in the oui a cast class ...
// they get first up ...

   if ((m1 = (struct ArgusMacStruct *) n1->dsrs[ARGUS_MAC_INDEX]) != NULL) {
      switch (m1->hdr.subtype) {
         default:
         case ARGUS_TYPE_ETHER: {
            s1 = etheraddr_class(ArgusParser, (u_char *)&m1->mac.mac_union.ether.ehdr.ether_shost);
            break;
         }
      }
   }
   if ((m2 = (struct ArgusMacStruct *) n2->dsrs[ARGUS_MAC_INDEX]) != NULL) {
      switch (m2->hdr.subtype) {
         default:
         case ARGUS_TYPE_ETHER: {
            s2 = etheraddr_class(ArgusParser, (u_char *)&m2->mac.mac_union.ether.ehdr.ether_shost);
            break;
         }
      }
   }

   retn = (s2 > s1) ? 1 : (s2 == s1) ? 0 : -1;
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortDstMacClass (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusMacStruct *m1 = NULL, *m2 = NULL;
   int s1 = 0, s2 = 0, retn = 0;

// The concept is that you want to sort based on the class of the mac address.
// This is primarily for ramatrix, which wants the list sorted by,
// Broadcast, Multicast, Addresses in reverse order based on sort algorithm ...
//
// So we'll make anything with 'cas_' in the oui a cast class ...
// they get first up ...

   m1 = (struct ArgusMacStruct *) n1->dsrs[ARGUS_MAC_INDEX];
   m2 = (struct ArgusMacStruct *) n2->dsrs[ARGUS_MAC_INDEX];

   if ((m1 != NULL) && (m2 != NULL)) {
      switch (m1->hdr.subtype) {
         default:
         case ARGUS_TYPE_ETHER: {
            s1 += etheraddr_class(ArgusParser, (u_char *)&m1->mac.mac_union.ether.ehdr.ether_dhost);
            s2 += etheraddr_class(ArgusParser, (u_char *)&m2->mac.mac_union.ether.ehdr.ether_dhost);
            break;
         }
      }

      retn = (s2 > s1) ? 1 : (s2 == s1) ? 0 : -1;
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortScore (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   int retn = 0;

   if (n1 && n2) {
      retn = (n2->score > n1->score) ? 1 : 0;
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int
ArgusSortNStroke (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   int stroke1 = 0, stroke2 = 0;
   int retn = 0;

   if ((n1->hdr.type & 0xF0) != (n2->hdr.type & 0xF0))
      return retn;

   switch (n1->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT:
      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
         break;
         
      case ARGUS_FAR: {
         struct ArgusBehaviorStruct *actor1 = (void *)n1->dsrs[ARGUS_BEHAVIOR_INDEX];
         struct ArgusBehaviorStruct *actor2 = (void *)n2->dsrs[ARGUS_BEHAVIOR_INDEX];
         
         if (actor1 != NULL) 
            stroke1 = actor1->keyStroke.src.n_strokes + actor1->keyStroke.dst.n_strokes;

         if (actor2 != NULL) 
            stroke2 = actor2->keyStroke.src.n_strokes + actor2->keyStroke.dst.n_strokes;

         if (actor1 && actor2) {
            retn = (stroke2 - stroke1);
         } else
         if (n1) {
            retn = -1;
         } else
            retn = 1;
      }
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortSrcNStroke (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   int stroke1 = 0, stroke2 = 0;
   int retn = 0;
   
   if ((n1->hdr.type & 0xF0) != (n2->hdr.type & 0xF0))
      return retn;

   switch (n1->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT:
      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
         break;
         
      case ARGUS_FAR: {
         struct ArgusBehaviorStruct *actor1 = (void *)n1->dsrs[ARGUS_BEHAVIOR_INDEX];
         struct ArgusBehaviorStruct *actor2 = (void *)n2->dsrs[ARGUS_BEHAVIOR_INDEX];
         
         if (actor1 != NULL) 
            stroke1 = actor1->keyStroke.src.n_strokes;
         
         if (actor2 != NULL) 
            stroke2 = actor2->keyStroke.src.n_strokes;
         break;
      }
   }
   
   if (n1 && n2) {
      retn = (stroke2 > stroke1) ? 1 : 0;
   }
   
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int
ArgusSortDstNStroke (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   int stroke1 = 0, stroke2 = 0;
   int retn = 0;
  
   if ((n1->hdr.type & 0xF0) != (n2->hdr.type & 0xF0))
      return retn;

   switch (n1->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT:
      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
         break;

      case ARGUS_FAR: {
         struct ArgusBehaviorStruct *actor1 = (void *)n1->dsrs[ARGUS_BEHAVIOR_INDEX];
         struct ArgusBehaviorStruct *actor2 = (void *)n2->dsrs[ARGUS_BEHAVIOR_INDEX];
 
         if (actor1 != NULL)
            stroke1 = actor1->keyStroke.dst.n_strokes;

         if (actor2 != NULL)
            stroke2 = actor2->keyStroke.dst.n_strokes;
         break;
      }
   }
  
   if (n1 && n2) {
      retn = (stroke2 > stroke1) ? 1 : 0;
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}



int
ArgusSortStartTime (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double t1 = 0.0, t2 = 0.0;
   int retn = 0;

   if (n1)
      t1 = ArgusFetchStartTime(n1);

   if (n2)
      t2 = ArgusFetchStartTime(n2);

   retn = (t2 > t1) ? 1 : ((t1 == t2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortLastTime (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double t1 = 0.0, t2 = 0.0;
   int retn = 0;

   if (n1)
      t1 = ArgusFetchLastTime(n1);

   if (n2)
      t2 = ArgusFetchLastTime(n2);

   retn = (t2 > t1) ? 1 : ((t1 == t2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int ArgusSortIdleTime (struct ArgusRecordStruct *n2, struct ArgusRecordStruct *n1)
{
   float ad1 = 0.0, ad2 = 0.0;
   int retn = 0;

   if (n1 && n2) {
      ad1 = RaGetFloatIdleTime(n1);
      ad2 = RaGetFloatIdleTime(n2);
      retn = (ad1 > ad2) ? 1 : ((ad1 == ad2) ? 0 : -1);
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int ArgusSortMean (struct ArgusRecordStruct *n2, struct ArgusRecordStruct *n1)
{
   float ad1 = 0.0, ad2 = 0.0;
   int retn = 0;
 
   if (n1 && n2) {
      ad1 = RaGetFloatMean(n1);
      ad2 = RaGetFloatMean(n2);
      retn = (ad1 > ad2) ? 1 : ((ad1 == ad2) ? 0 : -1);
   }
 
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortSum (struct ArgusRecordStruct *n2, struct ArgusRecordStruct *n1)
{
   float ad1 = 0.0, ad2 = 0.0;
   int retn = 0;

   if (n1 && n2) {
      ad1 = RaGetFloatSum(n1);
      ad2 = RaGetFloatSum(n2);
      retn = (ad1 > ad2) ? 1 : ((ad1 == ad2) ? 0 : -1);
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int ArgusSortMin (struct ArgusRecordStruct *n2, struct ArgusRecordStruct *n1)
{
   float ad1 = 0.0, ad2 = 0.0;
   int retn = 0;
 
   if (n1 && n2) {
      ad1 = RaGetFloatMin(n1);
      ad2 = RaGetFloatMin(n2);
      retn = (ad1 > ad2) ? 1 : ((ad1 == ad2) ? 0 : -1);
   }
 
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortMax (struct ArgusRecordStruct *n2, struct ArgusRecordStruct *n1)
{
   float ad1 = 0.0, ad2 = 0.0;
   int retn = 0;
 
   if (n1 && n2) {
      ad1 = RaGetFloatMax(n1);
      ad2 = RaGetFloatMax(n2);
      retn = (ad1 > ad2) ? 1 : ((ad1 == ad2) ? 0 : -1);
   }
 
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortDuration (struct ArgusRecordStruct *n2, struct ArgusRecordStruct *n1)
{
   double d1 = 0.0, d2 = 0.0;
   int retn = 0;

   if (n1)
      d1 = ArgusFetchDuration(n1);

   if (n2)
      d2 = ArgusFetchDuration(n2);

   retn = (d1 > d2) ? 1 : ((d1 == d2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortSrcMac (struct ArgusRecordStruct *n2, struct ArgusRecordStruct *n1)
{
   struct ArgusMacStruct *m1 = (struct ArgusMacStruct *) n1->dsrs[ARGUS_MAC_INDEX];
   struct ArgusMacStruct *m2 = (struct ArgusMacStruct *) n2->dsrs[ARGUS_MAC_INDEX];
   int retn = 0;

   if (m1 && m2) {
      retn = bcmp ((unsigned char *)&m1->mac.mac_union.ether.ehdr.ether_shost,
                   (unsigned char *)&m2->mac.mac_union.ether.ehdr.ether_shost, 6);
   }
 
 
   return(ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortDstMac (struct ArgusRecordStruct *n2, struct ArgusRecordStruct *n1)
{
   struct ArgusMacStruct *m1 = (struct ArgusMacStruct *) n1->dsrs[ARGUS_MAC_INDEX];
   struct ArgusMacStruct *m2 = (struct ArgusMacStruct *) n2->dsrs[ARGUS_MAC_INDEX];
   int retn = 0;

   if (m1 && m2) {
      retn = bcmp ((unsigned char *)&m1->mac.mac_union.ether.ehdr.ether_dhost,
                   (unsigned char *)&m2->mac.mac_union.ether.ehdr.ether_dhost, 6);
   }
 
   return(ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortSrcOui (struct ArgusRecordStruct *n2, struct ArgusRecordStruct *n1)
{
   struct ArgusMacStruct *m1 = (struct ArgusMacStruct *) n1->dsrs[ARGUS_MAC_INDEX];
   struct ArgusMacStruct *m2 = (struct ArgusMacStruct *) n2->dsrs[ARGUS_MAC_INDEX];
   int retn = 0;

   if (m1 && m2) {
      char *m1oui = etheraddr_oui(ArgusParser, (unsigned char *)&m1->mac.mac_union.ether.ehdr.ether_shost);
      char *m2oui = etheraddr_oui(ArgusParser, (unsigned char *)&m2->mac.mac_union.ether.ehdr.ether_shost);

      if (m1oui && m2oui) {
         retn = strcmp (m1oui, m2oui);
      }
   }

   return(ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortDstOui (struct ArgusRecordStruct *n2, struct ArgusRecordStruct *n1)
{
   struct ArgusMacStruct *m1 = (struct ArgusMacStruct *) n1->dsrs[ARGUS_MAC_INDEX];
   struct ArgusMacStruct *m2 = (struct ArgusMacStruct *) n2->dsrs[ARGUS_MAC_INDEX];
   int retn = 0;

   if (m1 && m2) {
      char *m1oui = etheraddr_oui(ArgusParser, (unsigned char *)&m1->mac.mac_union.ether.ehdr.ether_dhost);
      char *m2oui = etheraddr_oui(ArgusParser, (unsigned char *)&m2->mac.mac_union.ether.ehdr.ether_dhost);
      
      if (m1oui && m2oui) {
         retn = strcmp (m1oui, m2oui);
      }
   }

   return(ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortSrcAddr (struct ArgusRecordStruct *n2, struct ArgusRecordStruct *n1)
{
   struct ArgusFlow *f1 = (struct ArgusFlow *) n1->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusFlow *f2 = (struct ArgusFlow *) n2->dsrs[ARGUS_FLOW_INDEX];
   int retn = 0;

   if (f1 && f2) {
      char scidr =  32 - ((ArgusSorter->ArgusSrcAddrCIDR > 0) ? ArgusSorter->ArgusSrcAddrCIDR : 32);
      int len = 0, i = 0;
      u_char f1qual, f2qual;

      if ((f1->hdr.subtype & 0x3F) != (f2->hdr.subtype & 0x3F))
         return((f1->hdr.subtype & 0x3F) - (f2->hdr.subtype & 0x3F));

      f1qual = f1->hdr.argus_dsrvl8.qual & 0x1F;
      f2qual = f2->hdr.argus_dsrvl8.qual & 0x1F;

      if (f1qual != f2qual)
         return (f1qual - f2qual);

      switch (f1->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (f1qual) {
               case ARGUS_TYPE_IPV4: {
                  unsigned int *a1, *a2;
                  unsigned int va1, va2;

                  a1 = (unsigned int *)&f1->ip_flow.ip_src;
                  a2 = (unsigned int *)&f2->ip_flow.ip_src;

                  if (scidr) {
                     va1 = (*a1 >> scidr) << scidr;
                     va2 = (*a2 >> scidr) << scidr;
                  } else {
                     va1 = *a1;
                     va2 = *a2;
                  }
                  
                  retn = (va1 > va2) ? 1 : ((va1 < va2) ? -1 : 0);
                  break;
               }
               case ARGUS_TYPE_IPV6: {
                  unsigned int *a1, *a2;
                  a1 = (unsigned int *)&f1->ipv6_flow.ip_src;
                  a2 = (unsigned int *)&f2->ipv6_flow.ip_src;
                  len = 4;
                  for (i = 0; i < len; i++)
                     if (a1[i] != a2[i])
                        break;
                  if (i != len)
                     retn = (a1[i] > a2[i]) ? 1 : ((a1[i] < a2[i]) ? -1 : 0);
                  break;
               }
               case ARGUS_TYPE_RARP: 
                  retn = bcmp (&f1->rarp_flow.shaddr, &f2->rarp_flow.shaddr, 6);
                  break;
               case ARGUS_TYPE_ARP: {
                  unsigned int *a1, *a2;
                  a1 = (unsigned int *)&f1->arp_flow.arp_spa;
                  a2 = (unsigned int *)&f2->arp_flow.arp_spa;
                  retn = (*a1 > *a2) ? 1 : ((*a1 < *a2) ? -1 : 0);
                  break;
               }
               case ARGUS_TYPE_ETHER: {
                  unsigned char *a1, *a2;
                  a1 = (unsigned char *)&f1->mac_flow.mac_union.ether.ehdr.ether_shost;
                  a2 = (unsigned char *)&f2->mac_flow.mac_union.ether.ehdr.ether_shost;
                  len = 6;
                  for (i = 0; i < len; i++)
                     if (a1[i] != a2[i])
                        break;
                  if (i != len)
                     retn = (a1[i] > a2[i]) ? 1 : ((a1[i] < a2[i]) ? -1 : 0);
                  break;
               }
               case ARGUS_TYPE_WLAN: {
                  unsigned char *a1, *a2;
                  a1 = (unsigned char *)&f1->wlan_flow.shost;
                  a2 = (unsigned char *)&f2->wlan_flow.shost;
                  len = 6;
                  for (i = 0; i < len; i++)
                     if (a1[i] != a2[i])
                        break;
                  if (i != len)
                     retn = (a1[i] > a2[i]) ? 1 : ((a1[i] < a2[i]) ? -1 : 0);
                  break;
               }
            }
            break;
         }

         case ARGUS_FLOW_ARP: {
            switch (f1qual) {
               case ARGUS_TYPE_RARP: {
                  break;
               }

               case ARGUS_TYPE_ARP: {
                  unsigned int *a1, *a2;
                  a1 = (unsigned int *)&f1->arp_flow.arp_spa;
                  a2 = (unsigned int *)&f2->arp_flow.arp_spa;
                  retn = (*a1 > *a2) ? 1 : ((*a1 < *a2) ? -1 : 0);
                  break;
               }

               default: {
                  unsigned int *a1, *a2;
                  a1 = (unsigned int *)&f1->iarp_flow.arp_spa;
                  a2 = (unsigned int *)&f2->iarp_flow.arp_spa;
                  retn = (*a1 > *a2) ? 1 : ((*a1 < *a2) ? -1 : 0);
               }
            }
            break; 
         }

         default:
            break;
      }
   }
 
   return(ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int ArgusSortDstAddr (struct ArgusRecordStruct *n2, struct ArgusRecordStruct *n1)
{
   struct ArgusFlow *f1 = (struct ArgusFlow *) n1->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusFlow *f2 = (struct ArgusFlow *) n2->dsrs[ARGUS_FLOW_INDEX];
   int retn = 0;

   if (f1 && f2) {
      char scidr =  32 - ((ArgusSorter->ArgusSrcAddrCIDR > 0) ? ArgusSorter->ArgusSrcAddrCIDR : 32);
      int len = 0, i = 0;
      u_char f1qual, f2qual;

      if ((f1->hdr.subtype & 0x3F) != (f2->hdr.subtype & 0x3F))
         return((f1->hdr.subtype & 0x3F) - (f2->hdr.subtype & 0x3F));

      f1qual = f1->hdr.argus_dsrvl8.qual & 0x1F;
      f2qual = f2->hdr.argus_dsrvl8.qual & 0x1F;

      if (f1qual != f2qual)
         return (f1qual - f2qual);

      switch (f1->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (f1qual) {
               case ARGUS_TYPE_IPV4: {
                  unsigned int *a1, *a2;
                  unsigned int va1, va2;

                  a1 = (unsigned int *)&f1->ip_flow.ip_dst;
                  a2 = (unsigned int *)&f2->ip_flow.ip_dst;

                  if (scidr) {
                     va1 = (*a1 >> scidr) << scidr;
                     va2 = (*a2 >> scidr) << scidr;
                  } else {
                     va1 = *a1;
                     va2 = *a2;
                  }

                  retn = (va1 > va2) ? 1 : ((va1 < va2) ? -1 : 0);
                  break;
               }
               case ARGUS_TYPE_IPV6: {
                  unsigned int *a1, *a2;
                  a1 = (unsigned int *)&f1->ipv6_flow.ip_dst;
                  a2 = (unsigned int *)&f2->ipv6_flow.ip_dst;
                  len = 4;
                  for (i = 0; i < len; i++)
                     if (a1[i] != a2[i])
                        break;
                  if (i != len)
                     retn = (a1[i] > a2[i]) ? 1 : ((a1[i] < a2[i]) ? -1 : 0);
                  break;
               }
               case ARGUS_TYPE_RARP: 
                  retn = bcmp (&f1->rarp_flow.dhaddr, &f2->rarp_flow.dhaddr, 6);
                  break;
               case ARGUS_TYPE_ARP: {
                  unsigned int *a1, *a2;
                  a1 = (unsigned int *)&f1->arp_flow.arp_tpa;
                  a2 = (unsigned int *)&f2->arp_flow.arp_tpa;
                  retn = (*a1 > *a2) ? 1 : ((*a1 < *a2) ? -1 : 0);
                  break;
               }
               case ARGUS_TYPE_ETHER: {
                  unsigned char *a1, *a2;
                  a1 = (unsigned char *)&f1->mac_flow.mac_union.ether.ehdr.ether_shost;
                  a2 = (unsigned char *)&f2->mac_flow.mac_union.ether.ehdr.ether_shost;
                  len = 6;
                  for (i = 0; i < len; i++)
                     if (a1[i] != a2[i])
                        break;
                  if (i != len)
                     retn = (a1[i] > a2[i]) ? 1 : ((a1[i] < a2[i]) ? -1 : 0);
                  break;
               }
               case ARGUS_TYPE_WLAN: {
                  unsigned char *a1, *a2;
                  a1 = (unsigned char *)&f1->wlan_flow.dhost;
                  a2 = (unsigned char *)&f2->wlan_flow.dhost;
                  len = 6;
                  for (i = 0; i < len; i++)
                     if (a1[i] != a2[i])
                        break;
                  if (i != len)
                     retn = (a1[i] > a2[i]) ? 1 : ((a1[i] < a2[i]) ? -1 : 0);
                  break;
               }
            }
            break;
         }

         case ARGUS_FLOW_ARP: {
            switch (f1qual) {
               case ARGUS_TYPE_RARP: {
                  break;
               }

               case ARGUS_TYPE_ARP: {
                  unsigned int *a1, *a2;
                  a1 = (unsigned int *)&f1->arp_flow.arp_tpa;
                  a2 = (unsigned int *)&f2->arp_flow.arp_tpa;
                  retn = (*a1 > *a2) ? 1 : ((*a1 < *a2) ? -1 : 0);
                  break;
               }

               default: {
                  unsigned int *a1, *a2;
                  a1 = (unsigned int *)&f1->iarp_flow.arp_tpa;
                  a2 = (unsigned int *)&f2->iarp_flow.arp_tpa;
                  retn = (*a1 > *a2) ? 1 : ((*a1 < *a2) ? -1 : 0);
               }
            }
            break;
         }

         default:
            break;
      }
   }
 
   return(ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int                       
ArgusSortInode (struct ArgusRecordStruct *n2, struct ArgusRecordStruct *n1)
{
   struct ArgusIcmpStruct *i1 = (struct ArgusIcmpStruct *) n1->dsrs[ARGUS_ICMP_INDEX];
   struct ArgusIcmpStruct *i2 = (struct ArgusIcmpStruct *) n2->dsrs[ARGUS_ICMP_INDEX];
   int retn = 0;
 
   if (i1 && i2) {
      unsigned int *a1, *a2;

      if ((i1->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED) &&
          (i2->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED)) {

         a1 = &i1->osrcaddr;
         a2 = &i2->osrcaddr;
         retn = (*a1 > *a2) ? 1 : ((*a1 < *a2) ? -1 : 0);
      }
   }

   return(ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int ArgusSortProtocol (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusFlow *f1 = (struct ArgusFlow *) n1->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusFlow *f2 = (struct ArgusFlow *) n2->dsrs[ARGUS_FLOW_INDEX];
   unsigned char p1 = 0, p2 = 0;
   int retn = 0;

   if (f1 && f2) {
      switch (f1->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (f1->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4:
                  p1 = f1->ip_flow.ip_p;
                  break;
               case ARGUS_TYPE_IPV6:
                  p1 = f1->ipv6_flow.ip_p;
                  break;
            }
            break;
         }
 
         default:
            break;
      }
      switch (f2->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (f2->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4:
                  p2 = f2->ip_flow.ip_p;
                  break;
               case ARGUS_TYPE_IPV6:
                  p2 = f2->ipv6_flow.ip_p;
                  break;
            }
            break;
         }
 
         default:
            break;
      }
   }
 
   retn = p1 - p2;
   return(ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortSrcPort (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusFlow *f1 = (struct ArgusFlow *) n1->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusFlow *f2 = (struct ArgusFlow *) n2->dsrs[ARGUS_FLOW_INDEX];
   int retn = 0;

   if (f1 && f2) {
      unsigned short p1 = 0, p2 = 0;
    
      switch (f1->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (f1->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4:
                  if ((f1->ip_flow.ip_p == IPPROTO_TCP) || (f1->ip_flow.ip_p == IPPROTO_UDP))
                     p1 = (f1->hdr.subtype & ARGUS_REVERSE) ? f1->ip_flow.dport : f1->ip_flow.sport;
                  break;
               case ARGUS_TYPE_IPV6:
                  switch (f1->ipv6_flow.ip_p) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP: {
                        p1 = (f1->hdr.subtype & ARGUS_REVERSE) ? f1->ipv6_flow.dport : f1->ipv6_flow.sport;
                        break;
                     }
                  }
                  break;
            }
            break;
         }
    
         default:
            break;
      }
      switch (f2->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (f2->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4:
                  if ((f2->ip_flow.ip_p == IPPROTO_TCP) || (f2->ip_flow.ip_p == IPPROTO_UDP))
                     p2 = (f2->hdr.subtype & ARGUS_REVERSE) ? f2->ip_flow.dport : f2->ip_flow.sport;
                  break;
               case ARGUS_TYPE_IPV6:
                  switch (f2->ipv6_flow.ip_p) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP: {
                        p2 = (f2->hdr.subtype & ARGUS_REVERSE) ? f2->ipv6_flow.dport : f2->ipv6_flow.sport;
                        break;
                     }
                  }
            }
            break;
         }
         default:
            break;
      }
    
      retn = p2 - p1;
   }
   return(ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortDstPort (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusFlow *f1 = (struct ArgusFlow *) n1->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusFlow *f2 = (struct ArgusFlow *) n2->dsrs[ARGUS_FLOW_INDEX];
   int retn = 0;

   if (f1 && f2) {
      unsigned short p1 = 0, p2 = 0;
    
      switch (f1->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (f1->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4:
                  if ((f1->ip_flow.ip_p == IPPROTO_TCP) || (f1->ip_flow.ip_p == IPPROTO_UDP))
                     p1 = (f1->hdr.subtype & ARGUS_REVERSE) ? f1->ip_flow.sport : f1->ip_flow.dport;
                  break;
               case ARGUS_TYPE_IPV6:
                  switch (f1->ipv6_flow.ip_p) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP: {
                        p1 = (f1->hdr.subtype & ARGUS_REVERSE) ? f1->ipv6_flow.sport : f1->ipv6_flow.dport;
                        break;
                     }
                  }

                  break;
            }
            break;
         }
    
         default:
            break;
      }
      switch (f2->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (f2->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4:
                  if ((f2->ip_flow.ip_p == IPPROTO_TCP) || (f2->ip_flow.ip_p == IPPROTO_UDP))
                     p2 = (f2->hdr.subtype & ARGUS_REVERSE) ? f2->ip_flow.sport : f2->ip_flow.dport;
                  break;
               case ARGUS_TYPE_IPV6:
                  switch (f1->ipv6_flow.ip_p) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP: {
                        p2 = (f2->hdr.subtype & ARGUS_REVERSE) ? f2->ipv6_flow.sport : f2->ipv6_flow.dport;
                        break;
                     }
                  }
                  break;
            }
            break;
         }
    
         default:
            break;
      }
    
      retn = p2 - p1;
   }
   return(ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int ArgusSortSrcMasklen (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusFlow *f1 = (struct ArgusFlow *) n1->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusFlow *f2 = (struct ArgusFlow *) n2->dsrs[ARGUS_FLOW_INDEX];
   int retn = 0;

   if (f1 && f2) {
      unsigned short ml1 = 0, ml2 = 0;
    
      if (f1->hdr.argus_dsrvl8.qual & ARGUS_MASKLEN) {
         switch (f1->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_LAYER_3_MATRIX:
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch (f1->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4:
                     ml1 = f1->ip_flow.smask;
                     break;
                  case ARGUS_TYPE_IPV6:
                     ml1 = f1->ipv6_flow.smask;
                     break;
               }
               break;
            }
    
            default:
               break;
         }
      }
      if (f2->hdr.argus_dsrvl8.qual & ARGUS_MASKLEN) {
         switch (f2->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_LAYER_3_MATRIX:
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch (f2->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4:
                     ml2 = f2->ip_flow.smask;
                     break;
                  case ARGUS_TYPE_IPV6:
                     ml2 = f2->ipv6_flow.smask;
                     break;
               }
               break;
            }
            default:
               break;
         }
      }
    
      retn = ml2 - ml1;
   }
   return(ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortDstMasklen (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusFlow *f1 = (struct ArgusFlow *) n1->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusFlow *f2 = (struct ArgusFlow *) n2->dsrs[ARGUS_FLOW_INDEX];
   int retn = 0;

   if (f1 && f2) {
      unsigned short ml1 = 0, ml2 = 0;
    
      if (f1->hdr.argus_dsrvl8.qual & ARGUS_MASKLEN) {
         switch (f1->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_LAYER_3_MATRIX:
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch (f1->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4:
                     ml1 = f1->ip_flow.dmask;
                     break;
                  case ARGUS_TYPE_IPV6:
                     ml1 = f1->ipv6_flow.dmask;
                     break;
               }
               break;
            }
   
            default:
               break;
         }
      }  
      if (f2->hdr.argus_dsrvl8.qual & ARGUS_MASKLEN) {
         switch (f2->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_LAYER_3_MATRIX:
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch (f2->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4:
                     ml2 = f2->ip_flow.dmask;
                     break;
                  case ARGUS_TYPE_IPV6:
                     ml2 = f2->ipv6_flow.dmask;
                     break;
               }
               break;
            }
            default:
               break;
         }
      }
    
      retn = ml2 - ml1;
   }
   return(ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int ArgusSortSrcMpls (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusMplsStruct *m1 = (struct ArgusMplsStruct *)n1->dsrs[ARGUS_MPLS_INDEX];
   struct ArgusMplsStruct *m2 = (struct ArgusMplsStruct *)n2->dsrs[ARGUS_MPLS_INDEX];
   int retn = 0;

   if (m1 && m2) {
      unsigned int l1, l2;
      if ((m1->hdr.subtype & ARGUS_MPLS_SRC_LABEL) && (m2->hdr.subtype & ARGUS_MPLS_SRC_LABEL)) {
         unsigned char *p1 = (unsigned char *)&m1->slabel;
         unsigned char *p2 = (unsigned char *)&m2->slabel;

#if defined(_LITTLE_ENDIAN)
         l1 = (p1[0] << 12) | (p1[1] << 4) | ((p1[2] >> 4) & 0xff);
         l2 = (p2[0] << 12) | (p2[1] << 4) | ((p2[2] >> 4) & 0xff);
#else
         l1 = (p1[3] << 12) | (p1[2] << 4) | ((p1[1] >> 4) & 0xff);
         l2 = (p2[3] << 12) | (p2[2] << 4) | ((p2[1] >> 4) & 0xff);
#endif
         retn = l1 - l2;

      } else
         retn = (m1->hdr.subtype & ARGUS_MPLS_SRC_LABEL) ? 1 :
               ((m2->hdr.subtype & ARGUS_MPLS_SRC_LABEL) ? -1 : 0);
   } else
      retn = (m1) ? 1 : ((m2) ? -1 : 0);

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortDstMpls (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusMplsStruct *m1 = (struct ArgusMplsStruct *)n1->dsrs[ARGUS_MPLS_INDEX];
   struct ArgusMplsStruct *m2 = (struct ArgusMplsStruct *)n2->dsrs[ARGUS_MPLS_INDEX];
   int retn = 0;

   if (m1 && m2) {
      unsigned int l1, l2;
      if ((m1->hdr.subtype & ARGUS_MPLS_DST_LABEL) && (m2->hdr.subtype & ARGUS_MPLS_DST_LABEL)) {
         unsigned char *p1 = (unsigned char *)&m1->dlabel;
         unsigned char *p2 = (unsigned char *)&m2->dlabel;

#if defined(_LITTLE_ENDIAN)
         l1 = (p1[0] << 12) | (p1[1] << 4) | ((p1[2] >> 4) & 0xff);
         l2 = (p2[0] << 12) | (p2[1] << 4) | ((p2[2] >> 4) & 0xff);
#else
         l1 = (p1[3] << 12) | (p1[2] << 4) | ((p1[1] >> 4) & 0xff);
         l2 = (p2[3] << 12) | (p2[2] << 4) | ((p2[1] >> 4) & 0xff);
#endif
         retn = l1 - l2;

      } else
         retn = (m1->hdr.subtype & ARGUS_MPLS_DST_LABEL) ? 1 :
               ((m2->hdr.subtype & ARGUS_MPLS_DST_LABEL) ? -1 : 0);
   } else
      retn = (m1) ? 1 : ((m2) ? -1 : 0);

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortSrcVlan (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusVlanStruct *v1 = (struct ArgusVlanStruct *)n1->dsrs[ARGUS_VLAN_INDEX];
   struct ArgusVlanStruct *v2 = (struct ArgusVlanStruct *)n2->dsrs[ARGUS_VLAN_INDEX];
   int retn = 0;

   if (v1 && v2) {
      if ((v1->hdr.argus_dsrvl8.qual & ARGUS_SRC_VLAN) && (v2->hdr.argus_dsrvl8.qual & ARGUS_SRC_VLAN)) {
         retn = (v1->sid & 0x0FFF) - (v2->sid & 0x0FFF);
      } else {
         retn = (v1->hdr.argus_dsrvl8.qual & ARGUS_SRC_VLAN) ? 1 :
               ((v2->hdr.argus_dsrvl8.qual & ARGUS_SRC_VLAN) ? -1 : 0);
      }
   } else
      retn = (v1) ? 1 : ((v2) ? -1 : 0);

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortDstVlan (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusVlanStruct *v1 = (struct ArgusVlanStruct *)n1->dsrs[ARGUS_VLAN_INDEX];
   struct ArgusVlanStruct *v2 = (struct ArgusVlanStruct *)n2->dsrs[ARGUS_VLAN_INDEX];
   int retn = 0;

   if (v1 && v2) {
      if ((v1->hdr.argus_dsrvl8.qual & ARGUS_DST_VLAN) && (v2->hdr.argus_dsrvl8.qual & ARGUS_DST_VLAN)) {
         retn = (v1->did & 0x0FFF) - (v2->did & 0x0FFF);
      } else {
         retn = (v1->hdr.argus_dsrvl8.qual & ARGUS_DST_VLAN) ? 1 :
               ((v2->hdr.argus_dsrvl8.qual & ARGUS_DST_VLAN) ? -1 : 0);
      }

   } else
      retn = (v1) ? 1 : ((v2) ? -1 : 0);

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortSrcIpId (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)n1->dsrs[ARGUS_IPATTR_INDEX];
   struct ArgusIPAttrStruct *ip2 = (struct ArgusIPAttrStruct *)n2->dsrs[ARGUS_IPATTR_INDEX];
   unsigned short ipid1, ipid2;
   int retn = 0;

   if (ip1 && ip2) {
      ipid1 = ip1->src.ip_id;
      ipid2 = ip2->src.ip_id;
      retn = ipid1 - ipid2;
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortDstIpId (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)n1->dsrs[ARGUS_IPATTR_INDEX];
   struct ArgusIPAttrStruct *ip2 = (struct ArgusIPAttrStruct *)n2->dsrs[ARGUS_IPATTR_INDEX];
   int retn = 0;

   if (ip1 && ip2) {
      unsigned char ipid1, ipid2;

      ipid1 = ip1->src.ip_id;
      ipid2 = ip2->src.ip_id;
      retn = ipid1 - ipid2;
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortSrcTos (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)n1->dsrs[ARGUS_IPATTR_INDEX];
   struct ArgusIPAttrStruct *ip2 = (struct ArgusIPAttrStruct *)n2->dsrs[ARGUS_IPATTR_INDEX];
   int retn = 0;

   if (ip1 && ip2) {
      unsigned char tos1, tos2;

      tos1 = ip1->src.tos;
      tos2 = ip2->src.tos;
      retn = tos1 - tos2;
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortDstTos (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)n1->dsrs[ARGUS_IPATTR_INDEX];
   struct ArgusIPAttrStruct *ip2 = (struct ArgusIPAttrStruct *)n2->dsrs[ARGUS_IPATTR_INDEX];
   int retn = 0;

   if (ip1 && ip2) {
      unsigned char tos1, tos2;

      tos1 = ip1->dst.tos;
      tos2 = ip2->dst.tos;
      retn = tos1 - tos2;
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortSrcDSByte (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)n1->dsrs[ARGUS_IPATTR_INDEX];
   struct ArgusIPAttrStruct *ip2 = (struct ArgusIPAttrStruct *)n2->dsrs[ARGUS_IPATTR_INDEX];
   int retn = 0;

   if (ip1 && ip2) {
      unsigned char dsb1, dsb2;

      dsb1 = (ip1->src.tos >> 2);
      dsb2 = (ip2->src.tos >> 2);
      retn = dsb1 - dsb2;
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortDstDSByte (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)n1->dsrs[ARGUS_IPATTR_INDEX];
   struct ArgusIPAttrStruct *ip2 = (struct ArgusIPAttrStruct *)n2->dsrs[ARGUS_IPATTR_INDEX];
   int retn = 0;

   if (ip1 && ip2) {
      unsigned char dsb1, dsb2;
      dsb1 = (ip1->dst.tos >> 2);
      dsb2 = (ip2->dst.tos >> 2);
      retn =  dsb1 - dsb2;
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortSrcTtl (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)n1->dsrs[ARGUS_IPATTR_INDEX];
   struct ArgusIPAttrStruct *ip2 = (struct ArgusIPAttrStruct *)n2->dsrs[ARGUS_IPATTR_INDEX];
   int retn = 0;
 
   if (ip1 && ip2) {
      if ((ip1->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC) &&
          (ip2->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC)) {
         unsigned char ttl1, ttl2;

         ttl1 = ip1->src.ttl;
         ttl2 = ip2->src.ttl;
         retn = (ttl1 < ttl2) ? 1 : ((ttl1 == ttl2) ? 0 : -1);
      }
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortDstTtl (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusIPAttrStruct *ip1 = (struct ArgusIPAttrStruct *)n1->dsrs[ARGUS_IPATTR_INDEX];
   struct ArgusIPAttrStruct *ip2 = (struct ArgusIPAttrStruct *)n2->dsrs[ARGUS_IPATTR_INDEX];
   int retn = 0;
 
   if (ip1 && ip2) {
      if ((ip1->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST) &&
          (ip2->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST)) {
         unsigned char ttl1, ttl2;

         ttl1 = ip1->dst.ttl;
         ttl2 = ip2->dst.ttl;
         retn = (ttl1 < ttl2) ? 1 : ((ttl1 == ttl2) ? 0 : -1);
      }
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortTransactions (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusAgrStruct *a1 = (struct ArgusAgrStruct *)n1->dsrs[ARGUS_AGR_INDEX];
   struct ArgusAgrStruct *a2 = (struct ArgusAgrStruct *)n2->dsrs[ARGUS_AGR_INDEX];
   int retn = 0;

   if (a1 && a2)
      retn = (a1->count > a2->count) ? 1 : ((a1->count < a2->count) ? -1 : 0);

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortSrcLoad (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double r1 = 0.0, r2 = 0.0;
   int retn = 0;

   if (n1)
      r1 = ArgusFetchSrcLoad(n1);
   if (n2)
      r2 = ArgusFetchSrcLoad(n2);
   retn = (r1 > r2) ? 1 : ((r1 == r2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortDstLoad (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double r1 = 0.0, r2 = 0.0;
   int retn = 0;

   if (n1)
      r1 = ArgusFetchDstLoad(n1);
   if (n2)
      r2 = ArgusFetchDstLoad(n2);
   retn = (r1 > r2) ? 1 : ((r1 == r2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int
ArgusSortLoad (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double r1 = 0.0, r2 = 0.0;
   int retn = 0;

   if (n1)
      r1 = ArgusFetchLoad(n1);
   if (n2)
      r2 = ArgusFetchLoad(n2);
   retn = (r1 > r2) ? 1 : ((r1 == r2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int
ArgusSortLoss (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double l1 = 0.0, l2 = 0.0;
   int retn = 0;

   if (n1) 
      l1 = ArgusFetchLoss(n1);

   if (n2) 
      l2 = ArgusFetchLoss(n2);
   
   retn = (l1 > l2) ? 1 : ((l1 == l2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int
ArgusSortSrcLoss (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double l1 = 0.0, l2 = 0.0;
   int retn = 0;

   if (n1)
      l1 = ArgusFetchSrcLoss(n1);

   if (n2)
      l2 = ArgusFetchSrcLoss(n2);
   
   retn = (l1 > l2) ? 1 : ((l1 == l2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortDstLoss (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double l1 = 0.0, l2 = 0.0;
   int retn = 0;

   if (n1) 
      l1 = ArgusFetchDstLoss(n1);
   if (n2) 
      l2 = ArgusFetchDstLoss(n2);
   retn = (l1 > l2) ? 1 : ((l1 == l2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortPercentLoss (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double l1 = 0.0, l2 = 0.0;
   int retn = 0;

   if (n1) 
      l1 = ArgusFetchPercentLoss(n1);

   if (n2) 
      l2 = ArgusFetchPercentLoss(n2);
   
   retn = (l1 > l2) ? 1 : ((l1 == l2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


int
ArgusSortPercentSrcLoss (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double l1 = 0.0, l2 = 0.0;
   int retn = 0;

   if (n1)
      l1 = ArgusFetchPercentSrcLoss(n1);

   if (n2)
      l2 = ArgusFetchPercentSrcLoss(n2);
   
   retn = (l1 > l2) ? 1 : ((l1 == l2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortPercentDstLoss (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double l1 = 0.0, l2 = 0.0;
   int retn = 0;

   if (n1) 
      l1 = ArgusFetchPercentDstLoss(n1);
   if (n2) 
      l2 = ArgusFetchPercentDstLoss(n2);
   retn = (l1 > l2) ? 1 : ((l1 == l2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortSrcRate (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double r1 = 0.0, r2 = 0.0;
   int retn = 0;

   if (n1) 
      r1 = ArgusFetchSrcRate(n1);
   if (n2) 
      r2 = ArgusFetchSrcRate(n2);
   retn = (r1 > r2) ? 1 : ((r1 == r2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortDstRate (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double r1 = 0.0, r2 = 0.0;
   int retn = 0;

   if (n1)
      r1 = ArgusFetchSrcRate(n1);
   if (n2)
      r2 = ArgusFetchSrcRate(n2);
   retn = (r1 > r2) ? 1 : ((r1 == r2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortRate (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double r1 = 0.0, r2 = 0.0;
   int retn = 0;

   if (n1)
      r1 = ArgusFetchRate(n1);
   if (n2)
      r2 = ArgusFetchRate(n2);
   retn = (r1 > r2) ? 1 : ((r1 == r2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortTranRef (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   int retn = 0;
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortSeq (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusTransportStruct *t1 = (struct ArgusTransportStruct *)n1->dsrs[ARGUS_TRANSPORT_INDEX];
   struct ArgusTransportStruct *t2 = (struct ArgusTransportStruct *)n2->dsrs[ARGUS_TRANSPORT_INDEX];
   int retn = 0;

   if (t1 && t2) {
      unsigned int seq1 = 0, seq2 = 0;

      if (t1->hdr.subtype & ARGUS_SEQ)
         seq1 = t1->seqnum;

      if (t2->hdr.subtype & ARGUS_SEQ)
         seq2 = t2->seqnum;

      retn = seq2 - seq1; 
   }
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}


/*
int
ArgusSortSrcGap (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double l1 = 0.0, l2 = 0.0;
   int retn = 0;

   if (n1)
      l1 = ArgusFetchSrcGap(n1);

   if (n2)
      l2 = ArgusFetchSrcGap(n2);

   retn = (l1 > l2) ? 1 : ((l1 == l2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortDstGap (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double l1 = 0.0, l2 = 0.0;
   int retn = 0;

   if (n1)
      l1 = ArgusFetchDstGap(n1);
   if (n2)
      l2 = ArgusFetchDstGap(n2);
   retn = (l1 > l2) ? 1 : ((l1 == l2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortSrcDup (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double l1 = 0.0, l2 = 0.0;
   int retn = 0;

   if (n1)
      l1 = ArgusFetchSrcDup(n1);

   if (n2)
      l2 = ArgusFetchSrcDup(n2);

   retn = (l1 > l2) ? 1 : ((l1 == l2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int ArgusSortDstDup (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double l1 = 0.0, l2 = 0.0;
   int retn = 0;

   if (n1)
      l1 = ArgusFetchDstDup(n1);
   if (n2)
      l2 = ArgusFetchDstDup(n2);
   retn = (l1 > l2) ? 1 : ((l1 == l2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}
*/



int
ArgusSortByteCount (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusMetricStruct *m1 = NULL, *m2 = NULL;
   long long cnt1 = 0, cnt2 = 0; 
   int retn = 0;
     
   if ((m1 = (struct ArgusMetricStruct *) n1->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = m1->src.bytes + m1->dst.bytes;
 
   if ((m2 = (struct ArgusMetricStruct *) n2->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt2 = m2->src.bytes + m2->dst.bytes;
    
   retn = ArgusReverseSortDir ? ((cnt1 < cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) :
                                ((cnt1 > cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) ; 
   return (retn); 
}

int
ArgusSortSrcByteCount (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusMetricStruct *m1 = NULL, *m2 = NULL;
   long long cnt1 = 0, cnt2 = 0;
   int retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) n1->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = m1->src.bytes;
 
   if ((m2 = (struct ArgusMetricStruct *) n2->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt2 = m2->src.bytes;
 
   retn = ArgusReverseSortDir ? ((cnt1 < cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) :
                                ((cnt1 > cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) ;
   return (retn);
}

int
ArgusSortDstByteCount (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusMetricStruct *m1 = NULL, *m2 = NULL;
   long long cnt1 = 0, cnt2 = 0;
   int retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) n1->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = m1->dst.bytes;
 
   if ((m2 = (struct ArgusMetricStruct *) n2->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt2 = m2->dst.bytes;
 
   retn = ArgusReverseSortDir ? ((cnt1 < cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) :
                                ((cnt1 > cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) ;
   return (retn);
}

int
ArgusSortAppByteRatio (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double r1 = 0.0, r2 = 0.0;
   int retn = 0;

   if (n1)
      r1 = ArgusFetchAppByteRatio(n1);
   if (n2)
      r2 = ArgusFetchAppByteRatio(n2);

   retn = (r1 > r2) ? 1 : ((r1 == r2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

int
ArgusSortPktsCount (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusMetricStruct *m1 = NULL, *m2 = NULL;
   long long cnt1 = 0, cnt2 = 0;
   int retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) n1->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = m1->src.pkts + m1->dst.pkts;
 
   if ((m2 = (struct ArgusMetricStruct *) n2->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt2 = m2->src.pkts + m2->dst.pkts;
 
   retn = ArgusReverseSortDir ? ((cnt1 < cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) :
                                ((cnt1 > cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) ;
   return (retn);
}

int
ArgusSortSrcPktsCount (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusMetricStruct *m1 = NULL, *m2 = NULL;
   long long cnt1 = 0, cnt2 = 0;
   int retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) n1->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = m1->src.pkts;
 
   if ((m2 = (struct ArgusMetricStruct *) n2->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt2 = m2->src.pkts;
 
   retn = ArgusReverseSortDir ? ((cnt1 < cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) :
                                ((cnt1 > cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) ;
   return (retn);
}

int
ArgusSortDstPktsCount (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusMetricStruct *m1 = NULL, *m2 = NULL;
   long long cnt1 = 0, cnt2 = 0;
   int retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) n1->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = m1->dst.pkts;
 
   if ((m2 = (struct ArgusMetricStruct *) n2->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt2 = m2->dst.pkts;
 
   retn = ArgusReverseSortDir ? ((cnt1 < cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) :
                                ((cnt1 > cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) ;
   return (retn);
}

int
ArgusSortAppByteCount (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusMetricStruct *m1 = NULL, *m2 = NULL;
   long long cnt1 = 0, cnt2 = 0; 
   int retn = 0;
     
   if ((m1 = (struct ArgusMetricStruct *) n1->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = m1->src.appbytes + m1->dst.appbytes;
 
   if ((m2 = (struct ArgusMetricStruct *) n2->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt2 = m2->src.appbytes + m2->dst.appbytes;
    
   retn = ArgusReverseSortDir ? ((cnt1 < cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) :
                                ((cnt1 > cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) ; 
   return (retn); 
}

int
ArgusSortSrcAppByteCount (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusMetricStruct *m1 = NULL, *m2 = NULL;
   long long cnt1 = 0, cnt2 = 0;
   int retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) n1->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = m1->src.appbytes;
 
   if ((m2 = (struct ArgusMetricStruct *) n2->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt2 = m2->src.appbytes;
 
   retn = ArgusReverseSortDir ? ((cnt1 < cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) :
                                ((cnt1 > cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) ;
   return (retn);
}

int
ArgusSortDstAppByteCount (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   struct ArgusMetricStruct *m1 = NULL, *m2 = NULL;
   long long cnt1 = 0, cnt2 = 0;
   int retn = 0;
 
   if ((m1 = (struct ArgusMetricStruct *) n1->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = m1->dst.appbytes;
 
   if ((m2 = (struct ArgusMetricStruct *) n2->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt2 = m2->dst.appbytes;
 
   retn = ArgusReverseSortDir ? ((cnt1 < cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) :
                                ((cnt1 > cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) ;
   return (retn);
}

int
ArgusSortSrvSignatures (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct RaSrvSignature *data1 = *(struct RaSrvSignature **)argus1;
   struct RaSrvSignature *data2 = *(struct RaSrvSignature **)argus2;
   int cnt1 = data1->count;
   int cnt2 = data2->count;
   int retn = 0;

   retn = ArgusReverseSortDir ? ((cnt1 < cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) :
                                ((cnt1 > cnt2) ? 1 : ((cnt1 == cnt2) ? 0 : -1)) ;
   return (retn);
}


int
ArgusSortSrcTcpBase (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusNetworkStruct *net1 = (void *)argus1->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusNetworkStruct *net2 = (void *)argus2->dsrs[ARGUS_NETWORK_INDEX];
   int retn = 0;

   if (net1 && net2) {
      struct ArgusTCPObject *tcp1 = &net1->net_union.tcp;
      struct ArgusTCPObject *tcp2 = &net2->net_union.tcp;
      struct ArgusFlow *flow1 = (void *)argus1->dsrs[ARGUS_FLOW_INDEX];
      struct ArgusFlow *flow2 = (void *)argus2->dsrs[ARGUS_FLOW_INDEX];

      unsigned int seq1 = 0;
      unsigned int seq2 = 0;

      if (flow1 != NULL) {
         switch (flow1->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch (flow1->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4:
                     switch (flow1->ip_flow.ip_p) {
                        case  IPPROTO_TCP:
                           seq1 = tcp1->src.seqbase;
                           break;
                     }
                     break;

                  case ARGUS_TYPE_IPV6:
                     switch (flow1->ipv6_flow.ip_p) {
                        case  IPPROTO_TCP:
                           seq1 = tcp1->src.seqbase;
                           break;
                     }
                     break;
               }
               break;
            }
         }
      }

      if (flow2 != NULL) {
         switch (flow2->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch (flow2->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4:
                     switch (flow2->ip_flow.ip_p) {
                        case  IPPROTO_TCP:
                           seq2 = tcp2->src.seqbase;
                           break;
                     }
                     break;

                  case ARGUS_TYPE_IPV6:
                     switch (flow2->ipv6_flow.ip_p) {
                        case  IPPROTO_TCP:
                           seq2 = tcp2->src.seqbase;
                           break;
                     }
                     break;
               }
               break;
            }
         }
      }

      retn = ArgusReverseSortDir ? ((seq1 < seq2) ? 1 : ((seq1 == seq2) ? 0 : -1)) :
                                   ((seq1 > seq2) ? 1 : ((seq1 == seq2) ? 0 : -1)) ;
   }

   return (retn);
}


int
ArgusSortDstTcpBase (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusNetworkStruct *net1 = (void *)argus1->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusNetworkStruct *net2 = (void *)argus2->dsrs[ARGUS_NETWORK_INDEX];
   int retn = 0;

   if (net1 && net2) {
      struct ArgusTCPObject *tcp1 = &net1->net_union.tcp;
      struct ArgusTCPObject *tcp2 = &net2->net_union.tcp;

      struct ArgusFlow *flow1 = (void *)argus1->dsrs[ARGUS_FLOW_INDEX];
      struct ArgusFlow *flow2 = (void *)argus2->dsrs[ARGUS_FLOW_INDEX];

      unsigned int seq1 = 0;
      unsigned int seq2 = 0;

      if (flow1 != NULL) {
         switch (flow1->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch (flow1->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4:
                     switch (flow1->ip_flow.ip_p) {
                        case  IPPROTO_TCP:
                           seq1 = tcp1->dst.seqbase;
                           break;
                     }
                     break;

                  case ARGUS_TYPE_IPV6:
                     switch (flow1->ipv6_flow.ip_p) {
                        case  IPPROTO_TCP:
                           seq1 = tcp1->dst.seqbase;
                           break;
                     }
                     break;
               }
               break;
            }
         }
      }

      if (flow2 != NULL) {
         switch (flow2->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch (flow2->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4:
                     switch (flow2->ip_flow.ip_p) {
                        case  IPPROTO_TCP:
                           seq2 = tcp2->dst.seqbase;
                           break;
                     }
                     break;

                  case ARGUS_TYPE_IPV6:
                     switch (flow2->ipv6_flow.ip_p) {
                        case  IPPROTO_TCP:
                           seq2 = tcp2->dst.seqbase;
                           break;
                     }
                     break;
               }
               break;
            }
         }
      }

      retn = ArgusReverseSortDir ? ((seq1 < seq2) ? 1 : ((seq1 == seq2) ? 0 : -1)) :
                                   ((seq1 > seq2) ? 1 : ((seq1 == seq2) ? 0 : -1)) ;
   }
   return (retn);
}

int
ArgusSortTcpRtt (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusNetworkStruct *net1 = (void *)argus1->dsrs[ARGUS_NETWORK_INDEX];
   struct ArgusNetworkStruct *net2 = (void *)argus2->dsrs[ARGUS_NETWORK_INDEX];
   int retn = 0;

   if (net1 && net2) {
      struct ArgusFlow *flow1 = (void *)argus1->dsrs[ARGUS_FLOW_INDEX];
      struct ArgusFlow *flow2 = (void *)argus2->dsrs[ARGUS_FLOW_INDEX];
      unsigned int rtt1 = 0;
      unsigned int rtt2 = 0;

      struct ArgusTCPObject *tcp1 = &net1->net_union.tcp;
      struct ArgusTCPObject *tcp2 = &net2->net_union.tcp;

      if (flow1 != NULL) {
         switch (flow1->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch (flow1->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4:
                     switch (flow1->ip_flow.ip_p) {
                        case  IPPROTO_TCP:
                           rtt1 = tcp1->synAckuSecs + tcp1->ackDatauSecs;
                           break;
                     }
                     break;

                  case ARGUS_TYPE_IPV6:
                     switch (flow1->ipv6_flow.ip_p) {
                        case  IPPROTO_TCP:
                           rtt1 = tcp1->synAckuSecs + tcp1->ackDatauSecs;
                           break;
                     }
                     break;
               }
               break;
            }
         }
      }

      if (flow2 != NULL) {
         switch (flow2->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch (flow2->hdr.argus_dsrvl8.qual & 0x1F) {
                  case ARGUS_TYPE_IPV4:
                     switch (flow2->ip_flow.ip_p) {
                        case  IPPROTO_TCP:
                           rtt2 = tcp2->synAckuSecs + tcp2->ackDatauSecs;
                           break;
                     }
                     break;

                  case ARGUS_TYPE_IPV6:
                     switch (flow2->ipv6_flow.ip_p) {
                        case  IPPROTO_TCP:
                           rtt2 = tcp2->synAckuSecs + tcp2->ackDatauSecs;
                           break;
                     }
                     break;
               }
               break;
            }
         }
      }

      retn = ArgusReverseSortDir ? ((rtt1 < rtt2) ? 1 : ((rtt1 == rtt2) ? 0 : -1)) :
                                   ((rtt1 > rtt2) ? 1 : ((rtt1 == rtt2) ? 0 : -1)) ;
   }
   return (retn);
}


int
ArgusSortSrcMaxPktSize (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusPacketSizeStruct *ps1 = (void *)argus1->dsrs[ARGUS_PSIZE_INDEX];
   struct ArgusPacketSizeStruct *ps2 = (void *)argus2->dsrs[ARGUS_PSIZE_INDEX];
   int retn = 0;

   if (ps1 && ps2) {
      unsigned short smaxsz1 = 0, smaxsz2 = 0;

      smaxsz1 = ps1->src.psizemax;
      smaxsz2 = ps2->src.psizemax;

      retn = ArgusReverseSortDir ? ((smaxsz1 < smaxsz2) ? 1 : ((smaxsz1 == smaxsz2) ? 0 : -1)) :
                                   ((smaxsz1 > smaxsz2) ? 1 : ((smaxsz1 == smaxsz2) ? 0 : -1)) ;
   }
   return (retn);
}


int
ArgusSortSrcMinPktSize (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusPacketSizeStruct *ps1 = (void *)argus1->dsrs[ARGUS_PSIZE_INDEX];
   struct ArgusPacketSizeStruct *ps2 = (void *)argus2->dsrs[ARGUS_PSIZE_INDEX];
   int retn = 0;

   if (ps1 && ps2) {
      unsigned short smiargusz1 = 0, smiargusz2 = 0;

      smiargusz1 = ps1->src.psizemin;
      smiargusz2 = ps2->src.psizemin;

      retn = ArgusReverseSortDir ? ((smiargusz1 > smiargusz2) ? 1 : ((smiargusz1 == smiargusz2) ? 0 : -1)) :
                                   ((smiargusz1 < smiargusz2) ? 1 : ((smiargusz1 == smiargusz2) ? 0 : -1)) ;
   }
   return (retn);
}

int
ArgusSortSrcMeanPktSize (struct ArgusRecordStruct *n1, struct ArgusRecordStruct *n2)
{
   double r1 = 0.0, r2 = 0.0;
   int retn = 0;

   if (n1)
      r1 = ArgusFetchSrcMeanPktSize(n1);
   if (n2)
      r2 = ArgusFetchSrcMeanPktSize(n2);
   retn = (r1 > r2) ? 1 : ((r1 == r2) ? 0 : -1);
   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}



int
ArgusSortDstMaxPktSize (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusPacketSizeStruct *ps1 = (void *)argus1->dsrs[ARGUS_PSIZE_INDEX];
   struct ArgusPacketSizeStruct *ps2 = (void *)argus2->dsrs[ARGUS_PSIZE_INDEX];
   int retn = 0;

   if (ps1 && ps2) {
      unsigned short dmaxsz1 = 0, dmaxsz2 = 0;

      dmaxsz1 = ps1->dst.psizemax;
      dmaxsz2 = ps2->dst.psizemax;

      retn = ArgusReverseSortDir ? ((dmaxsz1 < dmaxsz2) ? 1 : ((dmaxsz1 == dmaxsz2) ? 0 : -1)) :
                                   ((dmaxsz1 > dmaxsz2) ? 1 : ((dmaxsz1 == dmaxsz2) ? 0 : -1)) ;
   }
   return (retn);
}

int
ArgusSortDstMinPktSize (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusPacketSizeStruct *ps1 = (void *)argus1->dsrs[ARGUS_PSIZE_INDEX];
   struct ArgusPacketSizeStruct *ps2 = (void *)argus2->dsrs[ARGUS_PSIZE_INDEX];
   int retn = 0;

   if (ps1 && ps2) {
      unsigned short dmiargusz1 = 0, dmiargusz2 = 0;

      dmiargusz1 = ps1->dst.psizemin;
      dmiargusz2 = ps2->dst.psizemin;

      retn = ArgusReverseSortDir ? ((dmiargusz1 > dmiargusz2) ? 1 : ((dmiargusz1 == dmiargusz2) ? 0 : -1)) :
                                   ((dmiargusz1 < dmiargusz2) ? 1 : ((dmiargusz1 == dmiargusz2) ? 0 : -1)) ;
   }
   return (retn);
}

int
ArgusSortSrcCountryCode (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusCountryCodeStruct *sco1 = (void *)argus1->dsrs[ARGUS_COCODE_INDEX];
   struct ArgusCountryCodeStruct *sco2 = (void *)argus2->dsrs[ARGUS_COCODE_INDEX];
   int retn = 0;

   if (sco1 && sco2) {
      retn = strcmp(sco1->src, sco2->src);
      retn = ArgusReverseSortDir ? ((retn < 0) ? 1 : ((retn == 0) ? 0 : -1)) : retn;
   }
   return (retn);
}  

int
ArgusSortDstCountryCode (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusCountryCodeStruct *sco1 = (void *)argus1->dsrs[ARGUS_COCODE_INDEX];
   struct ArgusCountryCodeStruct *sco2 = (void *)argus2->dsrs[ARGUS_COCODE_INDEX];
   int retn = 0;

   if (sco1 && sco2) {
      retn = strcmp(sco1->dst, sco2->dst);
      retn = ArgusReverseSortDir ? ((retn < 0) ? 1 : ((retn == 0) ? 0 : -1)) : retn;
   }
   return (retn);
}

int
ArgusSortSrcASNum (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusAsnStruct *asn1 = (void *)argus1->dsrs[ARGUS_ASN_INDEX];
   struct ArgusAsnStruct *asn2 = (void *)argus2->dsrs[ARGUS_ASN_INDEX];
   int retn = 0;

   if (asn1 && asn2) {
      int value = (asn1->src_as - asn2->src_as);
      retn = (value < 0) ? 1 : ((value == 0) ? 0 : -1);
      retn = ArgusReverseSortDir ? ((retn < 0) ? 1 : ((retn == 0) ? 0 : -1)) : retn;
   }

   return (retn);
}

int
ArgusSortDstASNum (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusAsnStruct *asn1 = (void *)argus1->dsrs[ARGUS_ASN_INDEX];
   struct ArgusAsnStruct *asn2 = (void *)argus2->dsrs[ARGUS_ASN_INDEX];
   int retn = 0;

   if (asn1 && asn2) {
      int value = (asn1->dst_as - asn2->dst_as);
      retn = (value < 0) ? 1 : ((value == 0) ? 0 : -1);
      retn = ArgusReverseSortDir ? ((retn < 0) ? 1 : ((retn == 0) ? 0 : -1)) : retn;
   }

   return (retn);
}

int
ArgusSortLocality (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusNetspatialStruct *nss1 = (void *)argus1->dsrs[ARGUS_LOCAL_INDEX];
   struct ArgusNetspatialStruct *nss2 = (void *)argus2->dsrs[ARGUS_LOCAL_INDEX];
   int retn = 0, sloc1 = 0, sloc2 = 0, dloc1 = 0, dloc2 = 0, value;

   if (nss1 && (nss1->hdr.argus_dsrvl8.qual & ARGUS_SRC_LOCAL)) sloc1 = nss1->sloc;
   if (nss1 && (nss1->hdr.argus_dsrvl8.qual & ARGUS_DST_LOCAL)) dloc1 = nss1->dloc;
   if (nss2 && (nss2->hdr.argus_dsrvl8.qual & ARGUS_SRC_LOCAL)) sloc2 = nss2->sloc;
   if (nss2 && (nss2->hdr.argus_dsrvl8.qual & ARGUS_DST_LOCAL)) dloc2 = nss2->dloc;

   value = ((sloc1 > dloc1) ? sloc1 : dloc1) - ((sloc2 > dloc2) ? sloc2 : dloc2);
   retn = (value < 0) ? 1 : ((value == 0) ? 0 : -1);
   retn = ArgusReverseSortDir ? ((retn < 0) ? 1 : ((retn == 0) ? 0 : -1)) : retn;

   return (retn);
}

int
ArgusSortSrcLocality (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusNetspatialStruct *nss1 = (void *)argus1->dsrs[ARGUS_LOCAL_INDEX];
   struct ArgusNetspatialStruct *nss2 = (void *)argus2->dsrs[ARGUS_LOCAL_INDEX];
   int retn = 0, sloc1 = 0, sloc2 = 0, value;

   if (nss1 && (nss1->hdr.argus_dsrvl8.qual & ARGUS_SRC_LOCAL)) sloc1 = nss1->sloc;
   if (nss2 && (nss2->hdr.argus_dsrvl8.qual & ARGUS_SRC_LOCAL)) sloc2 = nss2->sloc;

   value = (sloc1 - sloc2);
   retn = (value < 0) ? 1 : ((value == 0) ? 0 : -1);
   retn = ArgusReverseSortDir ? ((retn < 0) ? 1 : ((retn == 0) ? 0 : -1)) : retn;
   
   return (retn);
}

int
ArgusSortDstLocality (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   struct ArgusNetspatialStruct *nss1 = (void *)argus1->dsrs[ARGUS_LOCAL_INDEX];
   struct ArgusNetspatialStruct *nss2 = (void *)argus2->dsrs[ARGUS_LOCAL_INDEX];
   int retn = 0, dloc1 = 0, dloc2 = 0, value;

   if (nss1 && (nss1->hdr.argus_dsrvl8.qual & ARGUS_DST_LOCAL)) dloc1 = nss1->dloc;
   if (nss2 && (nss2->hdr.argus_dsrvl8.qual & ARGUS_DST_LOCAL)) dloc2 = nss2->dloc;

   value = (dloc1 - dloc2);
   retn = (value < 0) ? 1 : ((value == 0) ? 0 : -1);
   retn = ArgusReverseSortDir ? ((retn < 0) ? 1 : ((retn == 0) ? 0 : -1)) : retn;
   
   return (retn);
}

int
ArgusSortSrcHops (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   double shops1 = ArgusFetchSrcHopCount(argus1);
   double shops2 = ArgusFetchSrcHopCount(argus2);
   int retn, value = (shops1 - shops2);

   retn = (value < 0) ? 1 : ((value == 0) ? 0 : -1);
   retn = ArgusReverseSortDir ? ((retn < 0) ? 1 : ((retn == 0) ? 0 : -1)) : retn;
   return (retn);
}

int
ArgusSortDstHops (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   double dhops1 = ArgusFetchDstHopCount(argus1);
   double dhops2 = ArgusFetchDstHopCount(argus2);
   int retn, value = (dhops1 - dhops2);

   retn = (value < 0) ? 1 : ((value == 0) ? 0 : -1);
   retn = ArgusReverseSortDir ? ((retn < 0) ? 1 : ((retn == 0) ? 0 : -1)) : retn;
   return (retn);
}

int
ArgusSortIntFlow (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   double intf1 = ArgusFetchIntFlow(argus1);
   double intf2 = ArgusFetchIntFlow(argus2);
   double value = (intf1 - intf2);
   int retn;

   retn = (value < 0) ? 1 : ((value == 0) ? 0 : -1);
   retn = ArgusReverseSortDir ? ((retn < 0) ? 1 : ((retn == 0) ? 0 : -1)) : retn;

   return (retn);
}

int
ArgusSortIntFlowStdDev (struct ArgusRecordStruct *argus1, struct ArgusRecordStruct *argus2)
{
   double intf1 = ArgusFetchIntFlowStdDev(argus1);
   double intf2 = ArgusFetchIntFlowStdDev(argus2);
   double value = (intf1 - intf2);
   int retn;

   retn = (value < 0) ? 1 : ((value == 0) ? 0 : -1);
   retn = ArgusReverseSortDir ? ((retn < 0) ? 1 : ((retn == 0) ? 0 : -1)) : retn;

   return (retn);
}
