/*
 * Argus Software
 * Copyright (c) 2000-2022 QoSient, LLC
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
 * $Id: //depot/argus/clients/common/argus_output.c#7 $
 * $DateTime: 2012/12/13 11:07:52 $
 * $Change: 2514 $
 */

/*
 * argus_output.c  - this is the argus output manager.
 *    If a client, like radium, wants all the output strategies,
 *    ports, compression, encryption, etc.... its here.
 *    This is an important workhorse for the argus architecture.
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <grp.h>
#include <pwd.h>

#if defined(HAVE_DNS_SD_H)
#include <dns_sd.h>
#endif

#if defined(HAVE_SYS_VFS_H)
#include <sys/vfs.h>
#else
#include <sys/param.h>
#include <sys/mount.h>
#endif

#include <argus_compat.h>
#include <argus_util.h>
#include <argus_output.h>


void ArgusSendFile (struct ArgusOutputStruct *, struct ArgusClientData *, char *, int);

extern char *chroot_dir;
extern uid_t new_uid;
extern gid_t new_gid;

void ArgusSetChroot(char *);


#include <ctype.h>
#include <math.h>

static void ArgusWriteSocket(struct ArgusOutputStruct *,
                             struct ArgusClientData *,
                             struct ArgusRecordStruct *,
                             unsigned char *);
static int ArgusWriteOutSocket(struct ArgusOutputStruct *,
                               struct ArgusClientData *,
                               unsigned char *);

void
setArgusMarReportInterval (struct ArgusParserStruct *parser, char *value)
{
   struct timeval *tvp = getArgusMarReportInterval(parser);

   struct timeval ovalue;
   double thisvalue = 0.0, iptr, fptr;
   int ivalue = 0;
   char *ptr = NULL;

   gettimeofday (&parser->ArgusRealTime, 0L);

   if (tvp != NULL) {
      ovalue = *tvp;
      tvp->tv_sec  = 0;
      tvp->tv_usec = 0;
   } else {
      ovalue.tv_sec  = 0;
      ovalue.tv_usec = 0;
   }

   if (((ptr = strchr (value, '.')) != NULL) || isdigit((int)*value)) {
      if (ptr != NULL) {
         thisvalue = atof(value);
      } else {
         if (isdigit((int)*value)) {
            ivalue = atoi(value);
            thisvalue = ivalue * 1.0;
         }
      }

      fptr =  modf(thisvalue, &iptr);

      tvp->tv_sec = iptr;
      tvp->tv_usec =  fptr * 1000000;

      parser->ArgusReportTime.tv_sec  = parser->ArgusRealTime.tv_sec  + tvp->tv_sec;
      parser->ArgusReportTime.tv_usec = parser->ArgusRealTime.tv_usec + tvp->tv_usec;

      if (parser->ArgusReportTime.tv_usec > 1000000) {
         parser->ArgusReportTime.tv_sec++;
         parser->ArgusReportTime.tv_usec -= 1000000;
      }

   } else
      *tvp = ovalue;

#ifdef ARGUSDEBUG
   ArgusDebug (4, "setArgusMarReportInterval(%s) returning\n", value);
#endif
}

void
setArgusBindAddr (struct ArgusParserStruct *parser, char *value)
{
   if (parser->ArgusBindAddr != NULL)
      free(parser->ArgusBindAddr);

   if (value != NULL)
      parser->ArgusBindAddr = strdup(value);
   else
      parser->ArgusBindAddr = NULL;
}


struct timeval *
getArgusMarReportInterval(struct ArgusParserStruct *parser) {
   return (&parser->ArgusMarReportInterval);
}


#include <netdb.h>

#if defined(HAVE_DNS_SD_H)
void RadiumDNSServiceCallback (DNSServiceRef, DNSServiceFlags, DNSServiceErrorType, const char *, const char *, const char *, void *);

void
RadiumDNSServiceCallback (DNSServiceRef sdRef, DNSServiceFlags flags, DNSServiceErrorType errorCode, const char *name, const char *regtype, const char *domain, void *context)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "RadiumDNSServiceCallback(%s, %c, %s, %p) returned %d\n", name, regtype, domain, errorCode);
#endif
}
#endif

int
ArgusEstablishListen (struct ArgusParserStruct *parser, int port, char *baddr)
{
   int s = -1;

   if (port) {
#if HAVE_GETADDRINFO
      struct addrinfo hints, *host, *hp;
      char portbuf[32];
      int retn = 0;

      memset(&hints, 0, sizeof(hints));
      hints.ai_family   = PF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags    = AI_PASSIVE;

      snprintf(portbuf, 32, "%d", port);

      if ((retn = getaddrinfo(baddr, portbuf, &hints, &host)) != 0) {
         switch (retn) {
            case EAI_AGAIN:
               ArgusLog(LOG_ERR, "dns server not available");
               break;
            case EAI_NONAME:
               ArgusLog(LOG_ERR, "bind address %s unknown", optarg);
               break;
#if defined(EAI_ADDRFAMILY)
            case EAI_ADDRFAMILY:
               ArgusLog(LOG_ERR, "bind address %s has no IP address", optarg);
               break;
#endif
            case EAI_SYSTEM:
               ArgusLog(LOG_ERR, "bind address %s name server error %s", optarg, strerror(errno));
               break;
         }
      }

#ifdef ARGUSDEBUG
      if (baddr) {
         ArgusDebug (1, "ArgusEstablishListen(0x%x, %d, %s) binding: %s:%d\n", parser, port, baddr, baddr, port);
      } else {
         ArgusDebug (1, "ArgusEstablishListen(0x%x, %d, null) binding: any:%d\n", parser, port, port);
      }
#endif

      if ((hp = host) != NULL) {
         do {
            retn = -1;
            if ((s = socket (host->ai_family, host->ai_socktype, host->ai_protocol)) >= 0) {
               int flags = fcntl (s, F_GETFL, 0L);
               if ((fcntl (s, F_SETFL, flags | O_NONBLOCK)) >= 0) {
                  int on = 1;
                  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                  if (!(bind (s, host->ai_addr, host->ai_addrlen))) {
                     if ((retn = listen (s, ARGUS_MAXLISTEN)) >= 0) {
                        parser->ArgusLfd[parser->ArgusListens++] = s;
                     } else {
                        ArgusLog(LOG_ERR, "ArgusEstablishListen: listen() error %s", strerror(errno));
                     }
                  } else {
                     ArgusLog(LOG_ERR, "ArgusEstablishListen: bind() error %s", strerror(errno));
                  }
               } else
                  ArgusLog(LOG_ERR, "ArgusEstablishListen: fcntl() error %s", strerror(errno));

               if (retn == -1) {
                  close (s);
                  s = -1;
               }
            }
            host = host->ai_next;

         } while ((host != NULL) && (retn == -1));

         freeaddrinfo(hp);
      }
#else
      struct sockaddr_in sin;
      struct hostent *host;

      sin.sin_addr.s_addr = INADDR_ANY;
      if (parser->ArgusBindAddr != NULL) {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "ArgusEstablishListen(%d, %s)\n", port, parser->ArgusBindAddr);
#endif
         if ((host = gethostbyname (parser->ArgusBindAddr)) != NULL) {
            if ((host->h_addrtype == AF_INET) && (host->h_length == 4)) {
               bcopy ((char *) *host->h_addr_list, (char *)&sin.sin_addr.s_addr, host->h_length);
            } else
               ArgusLog (LOG_ERR, "ArgusEstablishListen() unsupported bind address %s", parser->ArgusBindAddr);
         } else
            ArgusLog (LOG_ERR, "ArgusEstablishListen() bind address %s error %s", parser->ArgusBindAddr, strerror(errno));
      }

      sin.sin_port = htons((u_short) port);
      sin.sin_family = AF_INET;

      if ((s = socket (AF_INET, SOCK_STREAM, 0)) != -1) {
         int flags = fcntl (s, F_GETFL, 0L);
         if ((fcntl (s, F_SETFL, flags | O_NONBLOCK)) >= 0) {
            int on = 1;
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
            if (!(bind (s, (struct sockaddr *)&sin, sizeof(sin)))) {
               if ((listen (s, ARGUS_MAXLISTEN)) >= 0) {
                  parser->ArgusLfd[parser->ArgusListens++] = s;
               } else {
                  close (s);
                  s = -1;
                  ArgusLog(LOG_ERR, "ArgusEstablishListen: listen() failure");
               }
            } else {
               close (s);
               s = -1;
               ArgusLog(LOG_ERR, "ArgusEstablishListen: bind() error");
            }
         } else
            ArgusLog(LOG_ERR, "ArgusEstablishListen: fcntl() error");
      } else
         ArgusLog(LOG_ERR, " ArgusEstablishListen: socket() error");
#endif

#if defined(HAVE_DNS_SD_H)
      if (parser->ArgusZeroConf > 0) {
         if (parser->ArgusListens > 0) {
            DNSServiceRef *ssr = &parser->dnsSrvRef;
            int err = 0;

            DNSServiceFlags flags   = kDNSServiceFlagsNoAutoRename;
            const char *name        = NULL;
            const char *regtype     = "_argus._tcp";
            const char *domain      = NULL; // default domain
            const char *host        = NULL; // default host

            if ((err = DNSServiceRegister(ssr, flags, 0, name, regtype, domain, host, htons(port), 0, NULL, RadiumDNSServiceCallback, NULL)) != kDNSServiceErr_NoError) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "DNSServiceRegister(%p, %p, %d, 0, %s, %s, %d) returned error %d\n", parser, ssr, flags, name, regtype, port, err);
#endif
            } else {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "DNSServiceRegister(%p, %p, %d, 0, %s, %s, %d) returned OK\n", parser, ssr, flags, name, regtype, port);
#endif
            }
         }
      }
#endif

   }
     
#ifdef ARGUSDEBUG
   if (baddr)
      ArgusDebug (2, "ArgusEstablishListen(0x%x, %d, %s) returning %d\n", parser, port, baddr, s);
   else
      ArgusDebug (2, "ArgusEstablishListen(0x%x, %d, null) returning %d\n", parser, port, s);
#endif

   return (s);
}


#ifndef ArgusOutputC
#define ArgusOutputC
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
 

#if defined(ARGUS_THREADS)
#include <pthread.h>
#endif


struct ArgusOutputStruct *
ArgusNewOutput (struct ArgusParserStruct *parser)
{
   struct ArgusOutputStruct *retn = NULL;
   int i;

   if ((retn = (struct ArgusOutputStruct *) ArgusCalloc (1, sizeof (struct ArgusOutputStruct))) == NULL)
     ArgusLog (LOG_ERR, "ArgusNewOutput() ArgusCalloc error %s\n", strerror(errno));

   if ((retn->ArgusClients = ArgusNewQueue()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewOutput: clients queue %s", strerror(errno));

   retn->ArgusParser    = parser;

   retn->ArgusPortNum   = parser->ArgusPortNum;
   retn->ArgusBindAddr  = parser->ArgusBindAddr;
   retn->ArgusWfileList = parser->ArgusWfileList;

   for (i = 0; i < parser->ArgusListens; i++)
      retn->ArgusLfd[i] = parser->ArgusLfd[i];

   retn->ArgusListens = parser->ArgusListens;

   retn->ArgusInputList   = parser->ArgusOutputList;
   parser->ArgusWfileList = NULL;

   retn->ArgusMarReportInterval   = parser->ArgusMarReportInterval;

   gettimeofday (&retn->ArgusGlobalTime, 0L);
   retn->ArgusStartTime = retn->ArgusGlobalTime;

   retn->ArgusReportTime.tv_sec   = retn->ArgusStartTime.tv_sec  + parser->ArgusMarReportInterval.tv_sec;
   retn->ArgusReportTime.tv_usec  = retn->ArgusStartTime.tv_usec + parser->ArgusMarReportInterval.tv_usec;

   if (retn->ArgusReportTime.tv_usec  > 1000000) {
      retn->ArgusReportTime.tv_sec++;
      retn->ArgusReportTime.tv_usec -= 1000000;
   }

   retn->ArgusLastMarUpdateTime   = retn->ArgusGlobalTime;

   ArgusInitOutput(retn);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusNewOutput() returning retn 0x%x\n", retn);
#endif

   return (retn);
}


void
ArgusDeleteOutput (struct ArgusParserStruct *parser, struct ArgusOutputStruct *output)
{
#if defined(ARGUS_THREADS)
   pthread_mutex_destroy(&output->lock);
#endif

   ArgusDeleteList(output->ArgusInputList, ARGUS_OUTPUT_LIST);
   ArgusDeleteList(output->ArgusOutputList, ARGUS_OUTPUT_LIST);
   ArgusDeleteQueue(output->ArgusClients);

   if (output->ArgusInitMar != NULL)
      ArgusFree(output->ArgusInitMar);

   parser->ArgusOutputList = NULL;
   ArgusFree(output);


#if defined(HAVE_DNS_SD_H)
   if (parser->ArgusZeroConf > 0) {
      DNSServiceRefDeallocate(parser->dnsSrvRef);
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusDeleteOutput(0x%x, 0x%x) DNSServiceRefDeallocate\n", parser, output);
#endif
   }
#endif


#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusDeleteOutput(0x%x, 0x%x)\n", parser, output);
#endif
}


struct ArgusOutputStruct *
ArgusNewControlChannel (struct ArgusParserStruct *parser)
{
   struct ArgusOutputStruct *retn = NULL;
   int i;

   if ((retn = (struct ArgusOutputStruct *) ArgusCalloc (1, sizeof (struct ArgusOutputStruct))) == NULL)
     ArgusLog (LOG_ERR, "ArgusNewControlChannel() ArgusCalloc error %s\n", strerror(errno));

   if ((retn->ArgusClients = ArgusNewQueue()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewControlChannel: clients queue %s", strerror(errno));

   retn->ArgusParser      = parser;
   retn->ArgusControlPort = parser->ArgusControlPort;
   retn->ArgusBindAddr    = parser->ArgusBindAddr;
   retn->ArgusWfileList   = parser->ArgusWfileList;

   for (i = 0; i < parser->ArgusListens; i++)
      retn->ArgusLfd[i] = parser->ArgusLfd[i];

   retn->ArgusListens = parser->ArgusListens;

   retn->ArgusInputList   = parser->ArgusOutputList;
   parser->ArgusWfileList = NULL;

   retn->ArgusMarReportInterval   = parser->ArgusMarReportInterval;

   gettimeofday (&retn->ArgusStartTime, 0L);
   retn->ArgusLastMarUpdateTime = retn->ArgusStartTime;

   retn->ArgusReportTime.tv_sec   = retn->ArgusStartTime.tv_sec + parser->ArgusMarReportInterval.tv_sec;
   retn->ArgusReportTime.tv_usec  = retn->ArgusStartTime.tv_usec + parser->ArgusMarReportInterval.tv_usec;

   if (retn->ArgusReportTime.tv_usec > 1000000) {
      retn->ArgusReportTime.tv_sec++;
      retn->ArgusReportTime.tv_usec -= 1000000;
   }

   ArgusInitControlChannel(retn);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusNewControlChannel() returning retn 0x%x\n", retn);
#endif

   return (retn);
}


void
ArgusDeleteControlChannel (struct ArgusParserStruct *parser, struct ArgusOutputStruct *output)
{
#if defined(ARGUS_THREADS)
   pthread_mutex_destroy(&output->lock);
#endif

   ArgusDeleteList(output->ArgusInputList, ARGUS_OUTPUT_LIST);
   ArgusDeleteList(output->ArgusOutputList, ARGUS_OUTPUT_LIST);
   ArgusDeleteQueue(output->ArgusClients);

   if (output->ArgusInitMar != NULL)
      ArgusFree(output->ArgusInitMar);
   parser->ArgusOutputList = NULL;
   ArgusFree(output);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusDeleteOutput(0x%x, 0x%x)\n", parser, output);
#endif
}


int iptostring(const struct sockaddr *, socklen_t, char *, unsigned);

#ifdef ARGUS_SASL

extern int ArgusSaslLog (void *context __attribute__((unused)), int, const char *);

typedef int (*funcptr)();

static const struct sasl_callback argus_cb[] = {
    { SASL_CB_LOG,     (funcptr)&ArgusSaslLog, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};
#endif


void
ArgusInitOutput (struct ArgusOutputStruct *output)
{
   if (output != NULL) {
      struct ArgusWfileStruct *wfile;
      int len = 0;

#if defined(ARGUS_SASL)
      int retn = 0;
#endif /* ARGUS_SASL */

#if defined(ARGUS_THREADS)
      pthread_attr_t attrbuf, *attr = &attrbuf;

      pthread_mutex_init(&output->lock, NULL);
#endif

      if ((output->ArgusOutputList = ArgusNewList()) == NULL)
         ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusList %s", strerror(errno));

      if (output->ArgusInitMar != NULL)
         ArgusFree (output->ArgusInitMar);

      if ((output->ArgusInitMar = ArgusGenerateInitialMar(output)) == NULL)
         ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusGenerateInitialMar error %s", strerror(errno));

      len = ntohs(output->ArgusInitMar->hdr.len) * 4;

      if (output->ArgusWfileList != NULL) {
         int i, retn, count = output->ArgusWfileList->count;

         if (setuid(getuid()) < 0)
            ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusCalloc %s", strerror(errno));

         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) ArgusPopFrontList(output->ArgusWfileList, ARGUS_LOCK)) != NULL) {
               struct ArgusClientData *client = (void *) ArgusCalloc (1, sizeof(struct ArgusClientData));

               if (client == NULL)
                  ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusCalloc %s", strerror(errno));

               if (strcmp (wfile->filename, "-")) {
                  if ((!(strncmp (wfile->filename, "argus-udp://", 12))) ||
                      (!(strncmp (wfile->filename, "argus-tcp://", 12))) ||
                      (!(strncmp (wfile->filename, "udp://", 6))) ||
                      (!(strncmp (wfile->filename, "tcp://", 6))) ||
                      (!(strncmp (wfile->filename, "nfv5-udp://", 7))) ||
                      (!(strncmp (wfile->filename, "nfv9-udp://", 11))) ||
                      (!(strncmp (wfile->filename, "nfv9-tcp://", 11))) ||
                      (!(strncmp (wfile->filename, "ipfix-udp://", 12))) ||
                      (!(strncmp (wfile->filename, "ipfix-tcp://", 12)))) {

                     char *baddr = strstr (wfile->filename, "udp://");
                     baddr = &baddr[6];

#if HAVE_GETADDRINFO
                     struct addrinfo hints, *hp;
                     int retn = 0;
                     char *port;

                     if ((port = strchr(baddr, ':')) != NULL) {
                        *port++ = '\0';
                     } else {
                        port = "561";
                     }

                     memset(&hints, 0, sizeof(hints));
                     hints.ai_family   = PF_INET;
                     hints.ai_socktype = SOCK_DGRAM;

                     if ((retn = getaddrinfo(baddr, port, &hints, &client->host)) != 0) {
                        switch (retn) {
                           case EAI_AGAIN:
                              ArgusLog(LOG_ERR, "dns server not available");
                              break;
                           case EAI_NONAME:
                              ArgusLog(LOG_ERR, "bind address %s unknown", optarg);
                              break;
#if defined(EAI_ADDRFAMILY)
                           case EAI_ADDRFAMILY:
                              ArgusLog(LOG_ERR, "bind address %s has no IP address", optarg);
                              break;
#endif
                           case EAI_SYSTEM:
                              ArgusLog(LOG_ERR, "bind address %s name server error %s", optarg, strerror(errno));
                              break;
                        }
                     }

                     hp = client->host;

                     do {
                        if ((client->fd = socket (hp->ai_family, hp->ai_socktype, hp->ai_protocol)) >= 0) {
                           unsigned char ttl = 128;
                           int ttl_size = sizeof(ttl);
                           if (setsockopt(client->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, ttl_size) < 0)
                              ArgusLog (LOG_ERR, "ArgusInitOutput: setsockopt set multicast TTL: %s", strerror(errno));
                        } else
                           ArgusLog (LOG_ERR, "ArgusInitOutput: socket %s: %s", wfile->filename, strerror(errno));
                        hp = hp->ai_next;
                     } while (hp != NULL);
#endif

                     wfile->format = ARGUS_DATA;

                     if (strstr (wfile->filename, "nfv5"))  wfile->format = ARGUS_CISCO_V5_DATA;
                     if (strstr (wfile->filename, "nfv9"))  wfile->format = ARGUS_CISCO_V9_DATA;
                     if (strstr (wfile->filename, "ipfix")) wfile->format = ARGUS_IPFIX_DATA;

                     client->format = wfile->format;

                  } else {
                     if ((client->fd = open (wfile->filename, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0x1a4)) < 0)
                        ArgusLog (LOG_ERR, "ArgusInitOutput: open %s: %s", wfile->filename, strerror(errno));

                     wfile->format = ARGUS_DATA;
                     client->format = wfile->format;
                  }

               } else {
                  client->fd = 1;
                  output->ArgusWriteStdOut++;
               }

               if (wfile->filterstr != NULL) {
                  if (ArgusFilterCompile (&client->ArgusNFFcode, wfile->filterstr, 1) < 0)
                     ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusFilter syntax error: %s", wfile->filter);
                  client->ArgusFilterInitialized++;
               }

               if ((client->sock = ArgusNewSocket(client->fd)) == NULL)
                  ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusNewSocket error %s", strerror(errno));

               if (client->host != NULL) {
                  switch (client->format) {
                     case ARGUS_DATA:
                     if ((retn = sendto(client->fd, (char *) output->ArgusInitMar, len, 0, client->host->ai_addr, client->host->ai_addrlen)) < 0)
                        ArgusLog (LOG_ERR, "ArgusInitOutput: sendto(): retn %d %s", retn, strerror(errno));
                     break;
                  }

               } else {
                  struct ArgusClientData *oc = (struct ArgusClientData *)output->ArgusClients->start;
                  int x, count = output->ArgusClients->count;

                  stat (wfile->filename, &client->sock->statbuf);

                  for (x = 0; x < count; x++) {
                     if ((oc->sock->statbuf.st_dev == client->sock->statbuf.st_dev) &&
                         (oc->sock->statbuf.st_ino == client->sock->statbuf.st_ino))
                        ArgusLog (LOG_ERR, "ArgusInitOutput: writing to same file multiple times.");
                     oc = (struct ArgusClientData *)oc->qhdr.nxt;
                  }

                  if ((retn = write (client->fd, (char *) output->ArgusInitMar, len)) != len) {
                     if (!output->ArgusWriteStdOut) {
                        close (client->fd);
                        unlink (wfile->filename);
                     }
                     ArgusLog (LOG_ERR, "ArgusInitOutput: write(): %s", strerror(errno));
                  }
               }

               if (strcmp(wfile->filename, "/dev/null"))
                  client->sock->filename = strdup(wfile->filename);

               ArgusAddToQueue(output->ArgusClients, &client->qhdr, ARGUS_LOCK);

               client->ArgusClientStart++;
               ArgusPushBackList (output->ArgusWfileList, (struct ArgusListRecord *) wfile, ARGUS_LOCK);
            }
         }
      }

#ifdef ARGUS_SASL
      if ((retn = sasl_server_init(argus_cb, ArgusParser->ArgusProgramName)) != SASL_OK)
         ArgusLog (LOG_ERR, "ArgusInitOutput() sasl_server_init failed %d\n", retn);
#endif /* ARGUS_SASL */

#if defined(ARGUS_THREADS)
      pthread_attr_init(attr); 

      if (getuid() == 0)
         pthread_attr_setschedpolicy(attr, SCHED_RR);
      else
         attr = NULL;

      if ((pthread_create(&output->thread, attr, ArgusOutputProcess, (void *) output)) != 0)
         ArgusLog (LOG_ERR, "ArgusNewOutput() pthread_create error %s\n", strerror(errno));

#endif /* ARGUS_THREADS */
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusInitOutput() done\n");
#endif
}


void
ArgusInitControlChannel (struct ArgusOutputStruct *output)
{
   if (output != NULL) {
      struct ArgusWfileStruct *wfile;
      int len = 0;

#if defined(ARGUS_SASL)
      int retn = 0;
#endif /* ARGUS_SASL */

#if defined(ARGUS_THREADS)
      pthread_attr_t attrbuf, *attr = &attrbuf;

      pthread_mutex_init(&output->lock, NULL);
#endif

      if ((output->ArgusOutputList = ArgusNewList()) == NULL)
         ArgusLog (LOG_ERR, "ArgusInitControlChannel: ArgusList %s", strerror(errno));

      if (output->ArgusInitMar != NULL)
         ArgusFree (output->ArgusInitMar);

      if ((output->ArgusInitMar = ArgusGenerateInitialMar(output)) == NULL)
         ArgusLog (LOG_ERR, "ArgusInitControlChannel: ArgusGenerateInitialMar error %s", strerror(errno));

      len = ntohs(output->ArgusInitMar->hdr.len) * 4;

      if (output->ArgusWfileList != NULL) {
         int i, retn, count = output->ArgusWfileList->count;

         if (setuid(getuid()) < 0)
            ArgusLog (LOG_ERR, "ArgusInitControlChannel: ArgusCalloc %s", strerror(errno));

         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) ArgusPopFrontList(output->ArgusWfileList, ARGUS_LOCK)) != NULL) {
               struct ArgusClientData *client = (void *) ArgusCalloc (1, sizeof(struct ArgusClientData));

               if (client == NULL)
                  ArgusLog (LOG_ERR, "ArgusInitControlChannel: ArgusCalloc %s", strerror(errno));

               if (strcmp (wfile->filename, "-")) {
                  if ((!(strncmp (wfile->filename, "argus-udp://", 12))) ||
                      (!(strncmp (wfile->filename, "argus-tcp://", 12))) ||
                      (!(strncmp (wfile->filename, "udp://", 6))) ||
                      (!(strncmp (wfile->filename, "tcp://", 6))) ||
                      (!(strncmp (wfile->filename, "nfv5-udp://", 7))) ||
                      (!(strncmp (wfile->filename, "nfv9-udp://", 11))) ||
                      (!(strncmp (wfile->filename, "nfv9-tcp://", 11))) ||
                      (!(strncmp (wfile->filename, "ipfix-udp://", 12))) ||
                      (!(strncmp (wfile->filename, "ipfix-tcp://", 12)))) {

                     char *baddr = strstr (wfile->filename, "udp://");
                     baddr = &baddr[6];

#if HAVE_GETADDRINFO
                     struct addrinfo hints, *hp;
                     int retn = 0;
                     char *port;

                     if ((port = strchr(baddr, ':')) != NULL) {
                        *port++ = '\0';
                     } else {
                        port = "561";
                     }

                     memset(&hints, 0, sizeof(hints));
                     hints.ai_family   = PF_INET;
                     hints.ai_socktype = SOCK_DGRAM;

                     if ((retn = getaddrinfo(baddr, port, &hints, &client->host)) != 0) {
                        switch (retn) {
                           case EAI_AGAIN:
                              ArgusLog(LOG_ERR, "dns server not available");
                              break;
                           case EAI_NONAME:
                              ArgusLog(LOG_ERR, "bind address %s unknown", optarg);
                              break;
#if defined(EAI_ADDRFAMILY)
                           case EAI_ADDRFAMILY:
                              ArgusLog(LOG_ERR, "bind address %s has no IP address", optarg);
                              break;
#endif
                           case EAI_SYSTEM:
                              ArgusLog(LOG_ERR, "bind address %s name server error %s", optarg, strerror(errno));
                              break;
                        }
                     }

                     hp = client->host;

                     do {
                        if ((client->fd = socket (hp->ai_family, hp->ai_socktype, hp->ai_protocol)) >= 0) {
                           unsigned char ttl = 128;
                           int ttl_size = sizeof(ttl);
                           if (setsockopt(client->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, ttl_size) < 0)
                              ArgusLog (LOG_ERR, "ArgusInitControlChannel: setsockopt set multicast TTL: %s", strerror(errno));
                        } else
                           ArgusLog (LOG_ERR, "ArgusInitControlChannel: socket %s: %s", wfile->filename, strerror(errno));
                        hp = hp->ai_next;
                     } while (hp != NULL);
#endif

                     wfile->format = ARGUS_DATA;

                     if (strstr (wfile->filename, "nfv5"))  wfile->format = ARGUS_CISCO_V5_DATA;
                     if (strstr (wfile->filename, "nfv9"))  wfile->format = ARGUS_CISCO_V9_DATA;
                     if (strstr (wfile->filename, "ipfix")) wfile->format = ARGUS_IPFIX_DATA;

                     client->format = wfile->format;

                  } else 
                     if ((client->fd = open (wfile->filename, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0x1a4)) < 0)
                        ArgusLog (LOG_ERR, "ArgusInitControlChannel: open %s: %s", wfile->filename, strerror(errno));

               } else {
                  client->fd = 1;
                  output->ArgusWriteStdOut++;
               }

               if (wfile->filterstr != NULL) {
                  if (ArgusFilterCompile (&client->ArgusNFFcode, wfile->filterstr, 1) < 0)
                     ArgusLog (LOG_ERR, "ArgusInitControlChannel: ArgusFilter syntax error: %s", wfile->filter);
                  client->ArgusFilterInitialized++;
               }

               if ((client->sock = ArgusNewSocket(client->fd)) == NULL)
                  ArgusLog (LOG_ERR, "ArgusInitControlChannel: ArgusNewSocket error %s", strerror(errno));

               if (client->host != NULL) {
                  switch (client->format) {
                     case ARGUS_DATA:
                     if ((retn = sendto(client->fd, (char *) output->ArgusInitMar, len, 0, client->host->ai_addr, client->host->ai_addrlen)) < 0)
                        ArgusLog (LOG_ERR, "ArgusInitControlChannel: sendto(): retn %d %s", retn, strerror(errno));
                     break;
                  }

               } else {
                  struct ArgusClientData *oc = (struct ArgusClientData *)output->ArgusClients->start;
                  int x, count = output->ArgusClients->count;

                  stat (wfile->filename, &client->sock->statbuf);

                  for (x = 0; x < count; x++) {
                     if ((oc->sock->statbuf.st_dev == client->sock->statbuf.st_dev) &&
                         (oc->sock->statbuf.st_ino == client->sock->statbuf.st_ino))
                        ArgusLog (LOG_ERR, "ArgusInitControlChannel: writing to same file multiple times.");
                     oc = (struct ArgusClientData *)oc->qhdr.nxt;
                  }

                  if ((retn = write (client->fd, (char *) output->ArgusInitMar, len)) != len) {
                     if (!output->ArgusWriteStdOut) {
                        close (client->fd);
                        unlink (wfile->filename);
                     }
                     ArgusLog (LOG_ERR, "ArgusInitControlChannel: write(): %s", strerror(errno));
                  }
               }

               if (strcmp(wfile->filename, "/dev/null"))
                  client->sock->filename = strdup(wfile->filename);

               ArgusAddToQueue(output->ArgusClients, &client->qhdr, ARGUS_LOCK);

               client->ArgusClientStart++;
               ArgusPushBackList (output->ArgusWfileList, (struct ArgusListRecord *) wfile, ARGUS_LOCK);
            }
         }
      }

#ifdef ARGUS_SASL
      if ((retn = sasl_server_init(argus_cb, ArgusParser->ArgusProgramName)) != SASL_OK)
         ArgusLog (LOG_ERR, "ArgusInitControlChannel() sasl_server_init failed %d\n", retn);
#endif /* ARGUS_SASL */

#if defined(ARGUS_THREADS)
      pthread_attr_init(attr); 

      if (getuid() == 0)
         pthread_attr_setschedpolicy(attr, SCHED_RR);
      else
         attr = NULL;

      if ((pthread_create(&output->thread, attr, ArgusControlChannelProcess, (void *) output)) != 0)
         ArgusLog (LOG_ERR, "ArgusNewOutput() pthread_create error %s\n", strerror(errno));

#endif /* ARGUS_THREADS */
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusInitControlChannel() done\n");
#endif
}


void
ArgusCloseOutput(struct ArgusOutputStruct *output)
{
#if defined(ARGUS_THREADS)
   void *retn = NULL;

#ifdef ARGUSDEBUG
   if (output->ArgusOutputList != NULL)
      ArgusDebug (1, "ArgusCloseOutput() scheduling closure after %d records", output->ArgusInputList->count + output->ArgusOutputList->count);
   else
      ArgusDebug (1, "ArgusCloseOutput() closing", output->ArgusOutputList->count);
#endif

   output->status |= ARGUS_SHUTDOWN;
   if (output != NULL) 
      pthread_join(output->thread, &retn);
#else
   if (output != NULL) {
      output->status |= ARGUS_SHUTDOWN;
      ArgusOutputProcess(output);
   }
#endif /* ARGUS_THREADS */

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCloseOutput() done\n");
#endif
}


void ArgusCheckClientStatus (struct ArgusOutputStruct *, int);
int ArgusCheckClientMessage (struct ArgusOutputStruct *, struct ArgusClientData *);
int ArgusCheckControlMessage (struct ArgusOutputStruct *, struct ArgusClientData *);
int ArgusCongested = 0;

struct timeval *getArgusMarReportInterval(struct ArgusParserStruct *);
int ArgusOutputStatusTime(struct ArgusOutputStruct *);

int
ArgusOutputStatusTime(struct ArgusOutputStruct *output)
{
   int retn = 0;

   gettimeofday (&output->ArgusGlobalTime, 0L);
   if ((output->ArgusReportTime.tv_sec  < output->ArgusGlobalTime.tv_sec) ||
      ((output->ArgusReportTime.tv_sec == output->ArgusGlobalTime.tv_sec) &&
       (output->ArgusReportTime.tv_usec <= output->ArgusGlobalTime.tv_usec))) {

      output->ArgusReportTime.tv_sec  = output->ArgusGlobalTime.tv_sec  + getArgusMarReportInterval(output->ArgusParser)->tv_sec;
      output->ArgusReportTime.tv_usec = output->ArgusGlobalTime.tv_usec + getArgusMarReportInterval(output->ArgusParser)->tv_usec;

      if (output->ArgusReportTime.tv_usec > 1000000) {
         output->ArgusReportTime.tv_sec++;
         output->ArgusReportTime.tv_usec -= 1000000;
      }

      retn++;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (7, "ArgusOutputStatusTime(0x%x) done", output);
#endif
   return (retn);
}


#define ARGUS_MAXPROCESS		0x10000

void *
ArgusOutputProcess(void *arg)
{
   struct ArgusOutputStruct *output = (struct ArgusOutputStruct *) arg;
   struct timeval ArgusUpDate = {0, 50000}, ArgusNextUpdate = {0,0};
   int val, count;
   void *retn = NULL;
   unsigned char *buf;

#if defined(ARGUS_THREADS)
   sigset_t blocked_signals;
#endif /* ARGUS_THREADS */

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusOutputProcess(0x%x) starting\n", output);
#endif

   buf = ArgusMalloc(ARGUS_MAXRECORD);
   if (buf == NULL)
      ArgusLog(LOG_ERR, "%s: Unable to allocate packet buffer memory\n",
               __func__);

#if defined(ARGUS_THREADS)
   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

   while (!(output->status & ARGUS_STOP)) {
#else
   {
#endif
      struct ArgusListStruct *list = NULL;
      struct ArgusRecordStruct *rec = NULL;

      if (output && ((list = output->ArgusOutputList) != NULL)) {
         gettimeofday (&output->ArgusGlobalTime, 0L);

         if ((output->ArgusPortNum != 0) &&
            ((output->ArgusGlobalTime.tv_sec >  ArgusNextUpdate.tv_sec) ||
            ((output->ArgusGlobalTime.tv_sec == ArgusNextUpdate.tv_sec) &&
             (output->ArgusGlobalTime.tv_usec > ArgusNextUpdate.tv_usec)))) {

            if (output->ArgusListens) {
               struct timeval wait = {0, 0};
               fd_set readmask;
               int i, width = 0;

               /* Build new fd_set of listening sockets */

               FD_ZERO(&readmask);

               for (i = 0; i < output->ArgusListens; i++) {
                  if (output->ArgusLfd[i] != -1) {
                     FD_SET(output->ArgusLfd[i], &readmask);
                     width = (output->ArgusLfd[i] > width) ? output->ArgusLfd[i] : width;
                  }
               }

               if (output->ArgusClients) {
#if defined(ARGUS_THREADS)
                  pthread_mutex_lock(&output->ArgusClients->lock);
#endif

                  /* Build new fd_set of client sockets */

                  if ((count = output->ArgusClients->count) > 0) {
                     struct ArgusClientData *client = (void *)output->ArgusClients->start;
                     int i;

                     for (i = 0; i < count && client; i++) {
                        if (client->sock &&
                            client->sock->filename == NULL &&
                            client->fd != -1) {
                           FD_SET(client->fd, &readmask);
                           width = (client->fd > width) ? client->fd : width;
                        }
                        client = (void *) client->qhdr.nxt;
                     }
                  }

                  if (width) {
                     if ((val = select (width + 1, &readmask, NULL, NULL, &wait)) >= 0) {
                        if (val > 0) {
                           struct ArgusClientData *client = (void *)output->ArgusClients->start;

#ifdef ARGUSDEBUG
                           ArgusDebug (3, "ArgusOutputProcess() select returned with tasks\n");
#endif
                           for (i = 0; i < output->ArgusListens; i++)
                              if (FD_ISSET(output->ArgusLfd[i], &readmask))
                                 ArgusCheckClientStatus(output, output->ArgusLfd[i]);

                           if (client != NULL)  {
                              do {
                                 if (client->fd != -1 &&
                                     FD_ISSET(client->fd, &readmask)) {
                                    if (ArgusCheckClientMessage(output, client) < 0) {
                                       ArgusDeleteSocket(output, client);
                                    }
                                 }
                                 client = (void *) client->qhdr.nxt;
                              } while (client != (void *)output->ArgusClients->start);
                           }
                        }
                     }
                  }

#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&output->ArgusClients->lock);
#endif
               }

               ArgusNextUpdate.tv_sec  += ArgusUpDate.tv_sec;
               ArgusNextUpdate.tv_usec += ArgusUpDate.tv_usec;

               if (ArgusNextUpdate.tv_usec > 1000000) {
                  ArgusNextUpdate.tv_sec++;
                  ArgusNextUpdate.tv_usec -= 1000000;
               }
            }
         }

         if (ArgusOutputStatusTime(output) &&
             (rec = ArgusGenerateStatusMarRecord(output, ARGUS_STATUS)) != NULL) {
            ArgusPushBackList(list, (struct ArgusListRecord *)rec, ARGUS_LOCK);
         }

         while (output->ArgusOutputList && !(ArgusListEmpty(output->ArgusOutputList))) {
            ArgusLoadList(output->ArgusOutputList, output->ArgusInputList);

            while ((rec = (struct ArgusRecordStruct *) ArgusPopFrontList(output->ArgusInputList, ARGUS_LOCK)) != NULL) {
               u_int seqnum = 0;
               output->ArgusTotalRecords++;
               switch (rec->hdr.type & 0xF0) {
                  case ARGUS_MAR:
                  case ARGUS_EVENT:
                     break;

                  case ARGUS_NETFLOW:
                  case ARGUS_FAR: {
                     struct ArgusTransportStruct *trans = (void *)rec->dsrs[ARGUS_TRANSPORT_INDEX];
                     if (trans != NULL) {
                        seqnum = trans->seqnum;
                     }
                     break;
                  }
               }
               output->ArgusOutputSequence = seqnum;
#ifdef ARGUSDEBUG
               if (seqnum == 0)
                  ArgusDebug (3, "ArgusOutputProcess() received mar 0x%x totals %lld count %d remaining %d\n",
                            rec, output->ArgusTotalRecords, output->ArgusInputList->count, output->ArgusOutputList->count);
#endif
               count = 0;

               if (output->ArgusClients) {
#if defined(ARGUS_THREADS)
                  pthread_mutex_lock(&output->ArgusClients->lock);
#endif
                  if (output->ArgusClients->count) {
                     struct ArgusClientData *client = (void *)output->ArgusClients->start;
                     int i, ArgusWriteRecord = 0;
#ifdef ARGUSDEBUG
                  ArgusDebug (5, "ArgusOutputProcess() %d client(s) for record 0x%x\n", output->ArgusClients->count, rec);
#endif
                     for (i = 0; i < output->ArgusClients->count; i++) {
                        if ((client->fd != -1) && (client->sock != NULL) && client->ArgusClientStart) {
#ifdef ARGUSDEBUG
                           ArgusDebug (5, "ArgusOutputProcess() client 0x%x ready fd %d sock 0x%x start %d", client, client->fd, client->sock, client->ArgusClientStart);
#endif
                           ArgusWriteRecord = 1;
                           if (client->ArgusFilterInitialized)
                              if (!(ArgusFilterRecord ((struct nff_insn *)client->ArgusNFFcode.bf_insns, rec)))
                                 ArgusWriteRecord = 0;

                           if (ArgusWriteRecord) {
                              ArgusWriteSocket (output, client, rec, buf);           // post record for transmit
                              if (ArgusWriteOutSocket (output, client, buf) < 0) {   // transmit the record
                                 ArgusDeleteSocket(output, client);
                              }

                           } else {
#ifdef ARGUSDEBUG
                              ArgusDebug (5, "ArgusOutputProcess() client 0x%x filter blocks fd %d sock 0x%x start %d", client, client->fd, client->sock, client->ArgusClientStart);
#endif
                           }

                        } else {
                           struct timeval tvbuf, *tvp = &tvbuf;
#ifdef ARGUSDEBUG
                           ArgusDebug (5, "ArgusOutputProcess() %d client(s) not ready fd %d sock 0x%x start %d", output->ArgusClients->count, client->fd, client->sock, client->ArgusClientStart);
#endif
                           RaDiffTime (&output->ArgusGlobalTime, &client->startime, tvp);
                           if (tvp->tv_sec >= ARGUS_CLIENT_STARTUP_TIMEOUT) {
                              if (client->sock != NULL) {
                                 ArgusDeleteSocket(output, client);
                                 ArgusLog (LOG_WARNING, "ArgusCheckClientMessage: client %s never started: timed out", client->hostname);
                              }
                              client->ArgusClientStart = 1;
                           }
                        }
                        client = (void *) client->qhdr.nxt;
                     }
                  }
#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&output->ArgusClients->lock);
#endif
               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (5, "ArgusOutputProcess() no client for record 0x%x\n", rec);
#endif
               }
               ArgusDeleteRecordStruct(ArgusParser, rec);
            }

            if (output->ArgusWriteStdOut)
               fflush (stdout);
         }

#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&output->ArgusClients->lock);
#endif
         if ((output->ArgusPortNum != 0) && (output->ArgusClients->count)) {
            struct ArgusClientData *client = (void *)output->ArgusClients->start;
            int i, status;

            for (i = 0; i < output->ArgusClients->count; i++) {
               if ((client->fd != -1) && (client->sock != NULL)) {
                  if ((output->status & ARGUS_STOP) || (output->status & ARGUS_SHUTDOWN)) {
#ifdef ARGUSDEBUG
                     ArgusDebug (1, "ArgusOutputProcess() draining queue\n");
#endif
                     ArgusWriteOutSocket (output, client, buf);
                     ArgusDeleteSocket(output, client);
                  } else {
                     if (ArgusWriteOutSocket (output, client, buf) < 0) {
                        ArgusDeleteSocket(output, client);
                     } else {
                        if (client->pid > 0) {
                           if (waitpid(client->pid, &status, WNOHANG) == client->pid) {
                              client->ArgusClientStart++;
                              ArgusDeleteSocket(output, client);
                           }
                        }
                     }
                  }
               }
               client = (void *) client->qhdr.nxt;
            }

            for (i = 0, count = output->ArgusClients->count; (i < count) && output->ArgusClients->count; i++) {
               if ((client->fd == -1) && (client->sock == NULL) && client->ArgusClientStart) {
                  ArgusRemoveFromQueue(output->ArgusClients, &client->qhdr, ARGUS_NOLOCK);
#ifdef ARGUSDEBUG
                  ArgusDebug (1, "ArgusCheckClientMessage: client %s removed", client->hostname);
#endif
                  ArgusFree(client);
                  i = 0; count = output->ArgusClients->count;
                  client = (void *)output->ArgusClients->start;
               } else
                  client = (void *)client->qhdr.nxt;
            }
         }

#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&output->ArgusClients->lock);
#endif

#if defined(ARGUS_THREADS)
         if (ArgusListEmpty(list)) {
            struct timeval tvp;
            struct timespec tsbuf, *ts = &tsbuf;

            gettimeofday (&tvp, 0L);
            ts->tv_sec = tvp.tv_sec;
            ts->tv_nsec = tvp.tv_usec * 1000;
            ts->tv_nsec += 20000000;
            if (ts->tv_nsec > 1000000000) {
               ts->tv_sec++;
               ts->tv_nsec -= 1000000000;
            }
            pthread_mutex_lock(&list->lock);
            pthread_cond_timedwait(&list->cond, &list->lock, ts);
            pthread_mutex_unlock(&list->lock);
         }
#endif

      } else {
#if defined(ARGUS_THREADS)
         struct timespec tsbuf = {0, 100000000}, *ts = &tsbuf;
#ifdef ARGUSDEBUG
         ArgusDebug (1, "ArgusOutputProcess() waiting for ArgusOutputList 0x%x\n", output);
#endif
         nanosleep (ts, NULL);
#endif
      }
#if !defined(ARGUS_THREADS)
   }
#else
   }
#endif /* ARGUS_THREADS */

   if (output->status & ARGUS_SHUTDOWN) {
      struct ArgusClientData *client;
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusOutputProcess() shuting down\n");
#endif
      while ((client = (void *) output->ArgusClients->start) != NULL) {
         if ((client->fd != -1) && (client->sock != NULL)) {
             ArgusWriteOutSocket (output, client, buf);
             ArgusDeleteSocket(output, client);
          }
          ArgusRemoveFromQueue(output->ArgusClients, &client->qhdr, ARGUS_LOCK);
          ArgusFree(client);
       }
    }

    ArgusFree(buf);

#if defined(ARGUS_THREADS)
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusOutputProcess() exiting\n");
#endif
   RaParseComplete(1);
   pthread_exit(retn);
#endif /* ARGUS_THREADS */

   return (retn);
}



void *
ArgusControlChannelProcess(void *arg)
{
   struct ArgusOutputStruct *output = (struct ArgusOutputStruct *) arg;
   struct timeval ArgusUpDate = {0, 50000}, ArgusNextUpdate = {0,0};
   int val, count;
   void *retn = NULL;
   unsigned char *buf;

#if defined(ARGUS_THREADS)
   sigset_t blocked_signals;
#endif /* ARGUS_THREADS */

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusControlChannelProcess(0x%x) starting\n", output);
#endif

   buf = ArgusMalloc(ARGUS_MAXRECORD);
   if (buf == NULL)
      ArgusLog(LOG_ERR, "%s: Unable to allocate packet buffer memory\n",
               __func__);

#if defined(ARGUS_THREADS)
   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

   while (!(output->status & ARGUS_STOP)) {
#else
   {
#endif
      struct ArgusListStruct *list = NULL;
      struct ArgusRecordStruct *rec = NULL;

      if (output && ((list = output->ArgusOutputList) != NULL)) {
         gettimeofday (&output->ArgusGlobalTime, 0L);

    /* check to see if there are any new clients */
         
         if ((output->ArgusControlPort != 0) &&
            ((output->ArgusGlobalTime.tv_sec >  ArgusNextUpdate.tv_sec) ||
            ((output->ArgusGlobalTime.tv_sec == ArgusNextUpdate.tv_sec) &&
             (output->ArgusGlobalTime.tv_usec > ArgusNextUpdate.tv_usec)))) {
         
            if (output->ArgusListens) {
               struct timeval wait = {0, 0}; 
               fd_set readmask;
               int i, width = 0;
 
               FD_ZERO(&readmask);

               for (i = 0; i < output->ArgusListens; i++) {
                  if (output->ArgusLfd[i] != -1) {
                     FD_SET(output->ArgusLfd[i], &readmask);
                     width = (output->ArgusLfd[i] > width) ? output->ArgusLfd[i] : width;
                  }  
               }

               if (output->ArgusClients) {
#if defined(ARGUS_THREADS)
                  pthread_mutex_lock(&output->ArgusClients->lock);
#endif
                  if ((count = output->ArgusClients->count) > 0) {
                     struct ArgusClientData *client = (void *)output->ArgusClients->start;
                     int i;

                     for (i = 0; i < count && client; i++) {
                        if (client->sock && !(client->sock->filename)) {
                           if (client->fd != -1) {
                              FD_SET(client->fd, &readmask);
                              width = (client->fd > width) ? client->fd : width;
                           }
                        } 
                        client = (void *) client->qhdr.nxt;
                     }
                  }

                  if (width) {
                     if ((val = select (width + 1, &readmask, NULL, NULL, &wait)) >= 0) {
                        if (val > 0) {
                           struct ArgusClientData *client = (void *)output->ArgusClients->start;
#ifdef ARGUSDEBUG
                           ArgusDebug (1, "ArgusControlChannelProcess() select returned with tasks\n");
#endif
                           for (i = 0; i < output->ArgusListens; i++)
                              if (FD_ISSET(output->ArgusLfd[i], &readmask))
                                 ArgusCheckClientStatus(output, output->ArgusLfd[i]);

                           if (client != NULL)  {
                              do {
                                 if (client->fd != -1) {
                                    if (FD_ISSET(client->fd, &readmask)) {
                                       if (ArgusCheckControlMessage(output, client) < 0) {
                                          ArgusDeleteSocket(output, client);
                                       }
                                    }
                                 }
                                 client = (void *) client->qhdr.nxt;
                              } while (client != (void *)output->ArgusClients->start);
                           }
                        }
                     }
                  }
#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&output->ArgusClients->lock);
#endif
               }

               ArgusNextUpdate.tv_sec  = (output->ArgusGlobalTime.tv_sec  +  ArgusUpDate.tv_sec);
               ArgusNextUpdate.tv_usec = (output->ArgusGlobalTime.tv_usec +  ArgusUpDate.tv_usec);

               if (ArgusNextUpdate.tv_usec > 1000000) {
                  ArgusNextUpdate.tv_sec++;
                  ArgusNextUpdate.tv_usec -= 1000000;
               }
            }
         }

         if (ArgusOutputStatusTime(output)) {
            if ((rec = ArgusGenerateStatusMarRecord(output, ARGUS_STATUS)) != NULL)
               ArgusPushBackList(list, (struct ArgusListRecord *)rec, ARGUS_LOCK);
         }

         while (output->ArgusOutputList && !(ArgusListEmpty(output->ArgusOutputList))) {
            int done = 0;
            ArgusLoadList(output->ArgusOutputList, output->ArgusInputList);

            while (!done && ((rec = (struct ArgusRecordStruct *) ArgusPopFrontList(output->ArgusInputList, ARGUS_LOCK)) != NULL)) {
               u_int seqnum = 0;
               output->ArgusTotalRecords++;
               switch (rec->hdr.type & 0xF0) {
                  case ARGUS_MAR:
                  case ARGUS_EVENT:
                     break;

                  case ARGUS_NETFLOW:
                  case ARGUS_AFLOW:
                  case ARGUS_FAR: {
                     struct ArgusTransportStruct *trans = (void *)rec->dsrs[ARGUS_TRANSPORT_INDEX];
                     if (trans != NULL) {
                        seqnum = trans->seqnum;
                     }
                     break;
                  }
               }
               output->ArgusOutputSequence = seqnum;
#ifdef ARGUSDEBUG
               if (seqnum == 0)
                  ArgusDebug (1, "ArgusControlChannelProcess() received mar 0x%x totals %lld count %d remaining %d\n",
                            rec, output->ArgusTotalRecords, output->ArgusInputList->count, output->ArgusOutputList->count);
#endif
               count = 0;

               if (output->ArgusClients) {
#if defined(ARGUS_THREADS)
                  pthread_mutex_lock(&output->ArgusClients->lock);
#endif
                  if (output->ArgusClients->count) {
                     struct ArgusClientData *client = (void *)output->ArgusClients->start;
                     int i, ArgusWriteRecord = 0;
#ifdef ARGUSDEBUG
                  ArgusDebug (5, "ArgusControlChannelProcess() %d client(s) for record 0x%x\n", output->ArgusClients->count, rec);
#endif
                     for (i = 0; i < output->ArgusClients->count; i++) {
                        if ((client->fd != -1) && (client->sock != NULL) && client->ArgusClientStart) {
#ifdef ARGUSDEBUG
                           ArgusDebug (5, "ArgusControlChannelProcess() client 0x%x ready fd %d sock 0x%x start %d", client, client->fd, client->sock, client->ArgusClientStart);
#endif
                           ArgusWriteRecord = 1;
                           if (client->ArgusFilterInitialized)
                              if (!(ArgusFilterRecord ((struct nff_insn *)client->ArgusNFFcode.bf_insns, rec)))
                                 ArgusWriteRecord = 0;

                           if (ArgusWriteRecord) {
                              ArgusWriteSocket (output, client, rec, buf);           // post record for transmit
                              if (ArgusWriteOutSocket (output, client, buf) < 0) {   // transmit the record
                                    ArgusDeleteSocket(output, client);
                              }

                           } else {
#ifdef ARGUSDEBUG
                              ArgusDebug (5, "ArgusControlChannelProcess() client 0x%x filter blocks fd %d sock 0x%x start %d", client, client->fd, client->sock, client->ArgusClientStart);
#endif
                           }

                        } else {
                           struct timeval tvbuf, *tvp = &tvbuf;
#ifdef ARGUSDEBUG
                           ArgusDebug (5, "ArgusControlChannelProcess() %d client(s) not ready fd %d sock 0x%x start %d", output->ArgusClients->count, client->fd, client->sock, client->ArgusClientStart);
#endif
                           RaDiffTime (&output->ArgusGlobalTime, &client->startime, tvp);
                           if (tvp->tv_sec >= ARGUS_CLIENT_STARTUP_TIMEOUT) {
                              if (client->sock != NULL) {
                                 ArgusDeleteSocket(output, client);
                                 ArgusLog (LOG_WARNING, "ArgusControlChannelProcess: client %s never started: timed out", client->hostname);
                              }
                              client->ArgusClientStart = 1;
                           }
                        }
                        client = (void *) client->qhdr.nxt;
                     }
                  }
#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&output->ArgusClients->lock);
#endif
               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (5, "ArgusControlChannelProcess() no client for record 0x%x\n", rec);
#endif
               }
               ArgusDeleteRecordStruct(ArgusParser, rec);
            }

            if (output->ArgusWriteStdOut)
               fflush (stdout);
         }

#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&output->ArgusClients->lock);
#endif
         if ((output->ArgusControlPort != 0) && (output->ArgusClients->count)) {
            struct ArgusClientData *client = (void *)output->ArgusClients->start;
            int i, status;

            for (i = 0; i < output->ArgusClients->count; i++) {
               if ((client->fd != -1) && (client->sock != NULL)) {
                  if ((output->status & ARGUS_STOP) || (output->status & ARGUS_SHUTDOWN)) {
#ifdef ARGUSDEBUG
                     ArgusDebug (1, "ArgusControlChannelProcess() draining queue\n");
#endif
                     ArgusWriteOutSocket (output, client, buf);
                     ArgusDeleteSocket(output, client);
                  } else {
                     if (ArgusWriteOutSocket (output, client, buf) < 0) {
                        ArgusDeleteSocket(output, client);
                     } else {
                        if (client->pid > 0) {
                           if (waitpid(client->pid, &status, WNOHANG) == client->pid) {
                              client->ArgusClientStart++;
                              ArgusDeleteSocket(output, client);
                           }
                        }
                     }
                  }
               }
               client = (void *) client->qhdr.nxt;
            }

            for (i = 0, count = output->ArgusClients->count; (i < count) && output->ArgusClients->count; i++) {
               if ((client->fd == -1) && (client->sock == NULL) && client->ArgusClientStart) {
                  ArgusRemoveFromQueue(output->ArgusClients, &client->qhdr, ARGUS_NOLOCK);
#ifdef ARGUSDEBUG
                  ArgusDebug (1, "ArgusControlChannelProcess: client %s removed", client->hostname);
#endif
                  ArgusFree(client);
                  i = 0; count = output->ArgusClients->count;
                  client = (void *)output->ArgusClients->start;
               } else
                  client = (void *)client->qhdr.nxt;
            }
         }

#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&output->ArgusClients->lock);
#endif

#if defined(ARGUS_THREADS)
         if (ArgusListEmpty(list)) {
            struct timeval tvp;
            struct timespec tsbuf, *ts = &tsbuf;
 
            gettimeofday (&tvp, 0L);
            ts->tv_sec = tvp.tv_sec;
            ts->tv_nsec = tvp.tv_usec * 1000;
            ts->tv_nsec += 20000000;
            if (ts->tv_nsec > 1000000000) {
               ts->tv_sec++; 
               ts->tv_nsec -= 1000000000;
            }
            pthread_mutex_lock(&list->lock);
            pthread_cond_timedwait(&list->cond, &list->lock, ts);
            pthread_mutex_unlock(&list->lock);
         }
#endif

      } else {
#if defined(ARGUS_THREADS)
         struct timespec tsbuf = {0, 100000000}, *ts = &tsbuf;
#ifdef ARGUSDEBUG
         ArgusDebug (4, "ArgusControlChannelProcess() waiting for ArgusOutputList 0x%x\n", output);
#endif
         nanosleep (ts, NULL);
#endif
      }
#if !defined(ARGUS_THREADS)
   }
#else
   }
#endif /* ARGUS_THREADS */

   if (output->status & ARGUS_SHUTDOWN) {
      struct ArgusClientData *client;
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusControlChannelProcess() shuting down\n");
#endif
      while ((client = (void *) output->ArgusClients->start) != NULL) {
         if ((client->fd != -1) && (client->sock != NULL)) {
             ArgusWriteOutSocket (output, client, buf);
             ArgusDeleteSocket(output, client);
          }
          ArgusRemoveFromQueue(output->ArgusClients, &client->qhdr, ARGUS_LOCK);
          ArgusFree(client);
       }
    }

   ArgusFree(buf);

#if defined(ARGUS_THREADS)
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusControlChannelProcess() exiting\n");
#endif
   pthread_exit(retn);
#endif /* ARGUS_THREADS */
   return (retn);
}

int ArgusAuthenticateClient (struct ArgusClientData *);
static char clienthost[NI_MAXHOST*2+1] = "[local]";

#ifdef ARGUS_SASL
static sasl_ssf_t extprops_ssf = 0;
sasl_security_properties_t *mysasl_secprops(int);
#endif



void
ArgusCheckClientStatus (struct ArgusOutputStruct *output, int s)
{
   struct sockaddr from;
   int len = sizeof (from);
   int fd;

#ifdef ARGUS_SASL
#define SASL_SEC_MASK   0x0fff
   struct sockaddr_storage localaddr, remoteaddr;
   int retn, argus_have_addr = 0;
   char localhostname[1024];
   sasl_conn_t *conn = NULL;

   socklen_t salen;
   sasl_security_properties_t *secprops = NULL;
   char localip[60], remoteip[60];
#endif

   if ((fd = accept (s, (struct sockaddr *)&from, (socklen_t *)&len)) > 0) {
      int flags = fcntl (fd, F_GETFL, 0L);
      if ((fcntl (fd, F_SETFL, flags | O_NONBLOCK)) >= 0) {
         bzero(clienthost, sizeof(clienthost));
         if (ArgusTcpWrapper (output, fd, &from, clienthost) >= 0) {
            if (output->ArgusClients->count < ARGUS_MAXLISTEN) {
               struct ArgusClientData *client = (void *) ArgusCalloc (1, sizeof(struct ArgusClientData));

               if (client == NULL)
                  ArgusLog (LOG_ERR, "ArgusCheckClientStatus: ArgusCalloc %s", strerror(errno));

               gettimeofday (&client->startime, 0L);
               client->fd = fd;
               client->format = ARGUS_DATA;

               if (strlen(clienthost) > 0)
                  client->hostname = strdup(clienthost);
#ifdef ARGUSDEBUG
               ArgusDebug (6, "ArgusCheckClientStatus() new client %s\n", client->hostname);
#endif
               if ((client->sock = ArgusNewSocket(fd)) == NULL)
                  ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusNewSocket error %s", strerror(errno));

               if (output->ArgusInitMar != NULL)
                  ArgusFree(output->ArgusInitMar);

               if ((output->ArgusInitMar = ArgusGenerateInitialMar(output)) == NULL)
                  ArgusLog (LOG_ERR, "ArgusCheckClientStatus: ArgusGenerateInitialMar error %s", strerror(errno));

#ifdef ARGUS_SASL
               if (ArgusMaxSsf == 0)
                  goto no_auth;
#ifdef ARGUSDEBUG
               ArgusDebug (2, "ArgusCheckClientStatus: SASL enabled\n");
#endif
    /* Find out name of client host */
               {
                  char hbuf[NI_MAXHOST];
                  int niflags;
                  salen = sizeof(remoteaddr);

                  bzero(hbuf, sizeof(hbuf));

                  if (getpeername(fd, (struct sockaddr *)&remoteaddr, &salen) == 0 &&
                      (remoteaddr.ss_family == AF_INET || remoteaddr.ss_family == AF_INET6)) {
                      if (getnameinfo((struct sockaddr *)&remoteaddr, salen, hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) == 0) {
                          strncpy(clienthost, hbuf, sizeof(hbuf));
                      } else {
                          clienthost[0] = '\0';
                      }
                      niflags = NI_NUMERICHOST;
#ifdef NI_WITHSCOPEID
                      if (((struct sockaddr *)&remoteaddr)->sa_family == AF_INET6)
                          niflags |= NI_WITHSCOPEID;
#endif
                      if (getnameinfo((struct sockaddr *)&remoteaddr, salen, hbuf, sizeof(hbuf), NULL, 0, niflags) != 0)
                          strncpy(hbuf, "unknown", sizeof(hbuf));

                      sprintf(&clienthost[strlen(clienthost)], "[%s]", hbuf);

                      salen = sizeof(localaddr);
                      if (getsockname(fd, (struct sockaddr *)&localaddr, &salen) == 0) {
                          if(iptostring((struct sockaddr *)&remoteaddr, salen,
                                        remoteip, sizeof(remoteip)) == 0
                             && iptostring((struct sockaddr *)&localaddr, salen,
                                           localip, sizeof(localip)) == 0) {
                             argus_have_addr = 1;
                          }
                      }
                  }
               }

               gethostname(localhostname, 1024);
               if (!strchr (localhostname, '.')) {
                  char domainname[256];
                  strcat (localhostname, ".");
                  if (getdomainname (domainname, 256)) {
                     snprintf (&localhostname[strlen(localhostname)], 1024 - strlen(localhostname), "%s", domainname);
                  }
               }

               if ((retn = sasl_server_new("argus", NULL, NULL, localip, remoteip, NULL, 0,
                               &client->sasl_conn)) != SASL_OK)
                  ArgusLog (LOG_ERR, "ArgusCheckClientStatus: sasl_server_new failed %d", retn);

               conn = client->sasl_conn;

              /* set required security properties here */

               if (extprops_ssf)
                  sasl_setprop(conn, SASL_SSF_EXTERNAL, &extprops_ssf);

               secprops = mysasl_secprops(0);
               sasl_setprop(conn, SASL_SEC_PROPS, secprops);


              /* set ip addresses */
               if (argus_have_addr) {
                  sasl_setprop(conn, SASL_IPREMOTEPORT, remoteip);
                  if (client->saslprops.ipremoteport != NULL)
                     free(client->saslprops.ipremoteport);
                  client->saslprops.ipremoteport = strdup(remoteip);

                  sasl_setprop(conn, SASL_IPLOCALPORT, localip);
                  if (client->saslprops.iplocalport != NULL)
                     free(client->saslprops.iplocalport);
                  client->saslprops.iplocalport = strdup(localip);
               }

               output->ArgusInitMar->argus_mar.status |= htonl(ARGUS_SASL_AUTHENTICATE);
no_auth:
#endif
               len = ntohs(output->ArgusInitMar->hdr.len) * 4;

               if (write (client->fd, (char *) output->ArgusInitMar, len) != len) {
                  close (client->fd);
                  ArgusLog (LOG_ERR, "ArgusInitOutput: write(): %s", strerror(errno));
               }

#ifdef ARGUS_SASL
               if (ArgusMaxSsf > 0) {
                  int flags = fcntl (fd, F_GETFL, 0);

                  fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
                  if (ArgusAuthenticateClient (client)) {
                     ArgusDeleteSocket(output, client);
                     ArgusLog (LOG_ALERT, "ArgusCheckClientStatus: ArgusAuthenticateClient failed\n");
                  } else {
                     ArgusAddToQueue(output->ArgusClients, &client->qhdr, ARGUS_NOLOCK);
                     fcntl (fd, F_SETFL, flags);
                  }

               } else {
                     ArgusAddToQueue(output->ArgusClients, &client->qhdr, ARGUS_NOLOCK);
               }
#else
               ArgusAddToQueue(output->ArgusClients, &client->qhdr, ARGUS_NOLOCK);
#endif
            } else {
               char buf[4];
               struct ArgusRecord *argus = (struct ArgusRecord *) &buf;

               argus->hdr.type   = ARGUS_MAR | ARGUS_VERSION;
               argus->hdr.cause  = (ARGUS_ERROR & 0xF0) | ARGUS_SRC_RADIUM;
               argus->hdr.cause |= ARGUS_MAXLISTENEXCD;
               argus->hdr.len    = ntohs(1); 
               len = 4;

               if (write (fd, (char *) argus, len) != len)
                  ArgusLog (LOG_ERR, "ArgusInitOutput: write(): %s", strerror(errno));
               close(fd);
            }

         } else {
            ArgusLog (LOG_WARNING, "ArgusCheckClientStatus: ArgusTcpWrapper rejects");
            close (fd);
         }
         
      } else {
         ArgusLog (LOG_WARNING, "ArgusCheckClientStatus: fcntl: %s", strerror(errno));
         close (fd);
      }
   } else {
      ArgusLog (LOG_WARNING, "ArgusCheckClientStatus: accept: %s", strerror(errno));
      close (fd);
   }
     
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusCheckClientStatus() returning\n");
#endif
}

 
#define ARGUSMAXCLIENTCOMMANDS          6
#define RADIUM_START                    0
#define RADIUM_DONE                     1
#define RADIUM_FILTER                   2
#define RADIUM_MODEL                    3
#define RADIUM_PROJECT                  4
#define RADIUM_FILE                     5
 
char *ArgusClientCommands[ARGUSMAXCLIENTCOMMANDS] =
{
   "START:",
   "DONE:",
   "FILTER:",
   "MODEL:",
   "PROJECT:",
   "FILE:",
};


int
ArgusCheckClientMessage (struct ArgusOutputStruct *output, struct ArgusClientData *client)
{
   int retn = 0, cnt = 0, i, found, fd = client->fd;
   char buf[MAXSTRLEN], *ptr = buf;
   unsigned int value = 0;
    
#ifdef ARGUS_SASL
   const char *outputbuf = NULL;
   unsigned int outputlen = 0;
#endif /* ARGUS_SASL */

   bzero(buf, MAXSTRLEN);

   if (value == 0)
      value = MAXSTRLEN;

   if ((cnt = recv (fd, buf, value, 0)) <= 0) {
      if (cnt == 0) {
#ifdef ARGUSDEBUG
         ArgusDebug (3, "%s (0x%x, %d) recv() found no connection\n", __func__, client, fd);
#endif
         return -1;
      }
      switch(errno) {
         default:
         case EBADF:
         case EINVAL:
         case EIO:
         case ENOMEM:
         case ECONNREFUSED:
#ifdef ARGUSDEBUG
            ArgusDebug (3, "ArgusCheckClientMessage (0x%x, %d) recv() returned error %s\n", client, fd, strerror(errno));
#endif
            break;

         case EINTR:
         case ENOTSOCK:
         case EWOULDBLOCK:
            break;
      }
      return (-1);

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (3, "ArgusCheckClientMessage (0x%x, %d) recv() returned %d bytes\n", client, fd, cnt);
#endif
   }

#ifdef ARGUS_SASL
   if ((client->sasl_conn)) {
      const int *ssfp;
      int result;

      if ((result = sasl_getprop(client->sasl_conn, SASL_SSF, (const void **) &ssfp)) != SASL_OK)
         ArgusLog (LOG_ERR, "sasl_getprop: error %s\n", sasl_errdetail(client->sasl_conn));

      if (ssfp && (*ssfp > 0)) {
         if (sasl_decode (client->sasl_conn, buf, cnt, &outputbuf, &outputlen) != SASL_OK) {
            ArgusLog (LOG_WARNING, "ArgusCheckClientMessage(0x%x, %d) sasl_decode (0x%x, 0x%x, %d, 0x%x, %d) failed",
                       client, fd, client->sasl_conn, buf, cnt, &outputbuf, outputlen);
            return(-1);
         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (3, "ArgusCheckClientMessage (0x%x, %d) sasl_decode() returned %d bytes\n", client, fd, outputlen);
#endif
         }
         if (outputlen > 0) {
            if (outputlen < MAXSTRLEN) {
               bzero (buf, MAXSTRLEN);
               bcopy (outputbuf, buf, outputlen);
               cnt = outputlen;
            } else
               ArgusLog (LOG_ERR, "ArgusCheckClientMessage(0x%x, %d) sasl_decode returned %d bytes\n", client, fd, outputlen);
        
         } else {
            return (0);
         }
      }
   }
#endif /* ARGUS_SASL */

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusCheckClientMessage (0x%x, %d) read '%s' from remote\n", client, fd, ptr);
#endif

   for (i = 0, found = 0; i < ARGUSMAXCLIENTCOMMANDS; i++) {
      if (!(strncmp (ptr, ArgusClientCommands[i], strlen(ArgusClientCommands[i])))) {
         found++;
         switch (i) {
            case RADIUM_START: client->ArgusClientStart++; retn = 0; break;
            case RADIUM_DONE:  {
               if (client->hostname != NULL)
                  ArgusLog (LOG_WARNING, "ArgusCheckClientMessage: client %s sent DONE", client->hostname);
               else
                  ArgusLog (LOG_WARNING, "ArgusCheckClientMessage: received DONE");
               retn = -4;
               break; 
            }
            case RADIUM_FILTER: {
               if (ArgusFilterCompile (&client->ArgusNFFcode, &ptr[7], 1) < 0) {
                  retn = -2;
#ifdef ARGUSDEBUG
                  ArgusDebug (3, "ArgusCheckClientMessage: ArgusFilter syntax error: %s\n", &ptr[7]);
#endif
               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (3, "ArgusCheckClientMessage: ArgusFilter %s\n", &ptr[7]);
#endif
                  client->ArgusFilterInitialized++;
                  if ((cnt = send (fd, "OK", 2, 0)) != 2) {
                     retn = -3;
#ifdef ARGUSDEBUG
                     ArgusDebug (3, "ArgusCheckClientMessage: send error %s\n", strerror(errno));
#endif
                  } else {
                     retn = 0;
#ifdef ARGUSDEBUG
                     ArgusDebug (3, "ArgusCheckClientMessage: ArgusFilter %s initialized.\n", &ptr[7]);
#endif
                  }
               }
               break;
            }

            case RADIUM_PROJECT: 
            case RADIUM_MODEL: 
               break;

            case RADIUM_FILE: {
               char *file = &ptr[6];
#ifdef ARGUSDEBUG
               ArgusDebug (3, "ArgusCheckClientMessage: ArgusFile %s requested.\n", file);
#endif
               ArgusSendFile (output, client, file, 0);
               retn = 5;
               break;
            }

            default:
               if (client->hostname)
                  ArgusLog (LOG_WARNING, "ArgusCheckClientMessage: client %s sent %s",  client->hostname, ptr);
               else
                  ArgusLog (LOG_WARNING, "ArgusCheckClientMessage: received %s",  ptr);
               break;
         }

         break;
      }
   }

   if (!found) {
      if (client->hostname)
         ArgusLog (LOG_WARNING, "ArgusCheckClientMessage: client %s sent %s",  client->hostname, ptr);
      else
         ArgusLog (LOG_WARNING, "ArgusCheckClientMessage: received %s",  ptr);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusCheckClientMessage: returning %d\n", retn);
#endif

   return (retn);
}

struct ArgusControlHandlerStruct ArgusControlCommands[ARGUSMAXCONTROLCOMMANDS] = {
   { "START: ", NULL},
   { "DONE: ", NULL},
   { "DISPLAY: ", NULL},
   { "HIGHLIGHT: ", NULL},
   { "SEARCH: ", NULL},
   { "FILTER: ", NULL},
   { "TREE: ", NULL}
};

int
ArgusCheckControlMessage (struct ArgusOutputStruct *output, struct ArgusClientData *client)
{
   int retn = 0, cnt = 0, i, found, fd = client->fd;
   char buf[MAXSTRLEN], *ptr = buf;
   unsigned int value = 0;
    
#ifdef ARGUS_SASL
   const char *outputbuf = NULL;
   unsigned int outputlen = 0;
#endif /* ARGUS_SASL */

   bzero(buf, MAXSTRLEN);

   if (value == 0)
      value = MAXSTRLEN;

   if ((cnt = recv (fd, buf, value, 0)) <= 0) {
      switch(errno) {
         default:
         case EBADF:
         case EINVAL:
         case EIO:
         case ENOMEM:
         case ECONNREFUSED:
#ifdef ARGUSDEBUG
            ArgusDebug (3, "ArgusCheckControlMessage (0x%x, %d) recv() returned error %s\n", client, fd, strerror(errno));
#endif
            break;

         case EINTR:
         case ENOTSOCK:
         case EWOULDBLOCK:
            break;
      }
      return (-1);

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (3, "ArgusCheckControlMessage (0x%x, %d) recv() returned %d bytes\n", client, fd, cnt);
#endif
   }

#ifdef ARGUS_SASL
   if ((client->sasl_conn)) {
      const int *ssfp;
      int result;

      if ((result = sasl_getprop(client->sasl_conn, SASL_SSF, (const void **) &ssfp)) != SASL_OK)
         ArgusLog (LOG_ERR, "sasl_getprop: error %s\n", sasl_errdetail(client->sasl_conn));

      if (ssfp && (*ssfp > 0)) {
         if (sasl_decode (client->sasl_conn, buf, cnt, &outputbuf, &outputlen) != SASL_OK) {
            ArgusLog (LOG_WARNING, "ArgusCheckControlMessage(0x%x, %d) sasl_decode (0x%x, 0x%x, %d, 0x%x, %d) failed",
                       client, fd, client->sasl_conn, buf, cnt, &outputbuf, outputlen);
            return(-1);
         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (3, "ArgusCheckControlMessage (0x%x, %d) sasl_decode() returned %d bytes\n", client, fd, outputlen);
#endif
         }
         if (outputlen > 0) {
            if (outputlen < MAXSTRLEN) {
               bzero (buf, MAXSTRLEN);
               bcopy (outputbuf, buf, outputlen);
               cnt = outputlen;
            } else
               ArgusLog (LOG_ERR, "ArgusCheckControlMessage(0x%x, %d) sasl_decode returned %d bytes\n", client, fd, outputlen);
        
         } else {
            return (0);
         }
      }
   }
#endif /* ARGUS_SASL */

   ptr[strcspn(ptr, "\r\n")] = '\0';

#ifdef ARGUSDEBUG
   if (strlen(ptr))
      ArgusDebug (1, "ArgusCheckControlMessage (0x%x, %d) read %s", client, fd, ptr);
#endif

   for (i = 0, found = 0; i < ARGUSMAXCONTROLCOMMANDS; i++) {
      if (!(strncmp (ptr, ArgusControlCommands[i].command, strlen(ArgusControlCommands[i].command)))) {
         if (ArgusControlCommands[i].handler != NULL) {
            char **result;
            if ((result = ArgusControlCommands[i].handler(ptr)) != NULL) {
               int sindex = 0;
               char *rstr = NULL;

               while ((rstr = result[sindex++]) != NULL) {
                  int slen = strlen(rstr);
                  if ((cnt = send (fd, rstr, slen, 0)) != slen) {
                     retn = -3;
#ifdef ARGUSDEBUG
                     ArgusDebug (3, "ArgusCheckControlMessage: send error %s\n", strerror(errno));
#endif
                  }
               }
               if (retn != -3) {
                  if ((cnt = send (fd, "OK\n", 3, 0)) != 3) {
                     retn = -3;
#ifdef ARGUSDEBUG
                     ArgusDebug (3, "ArgusCheckControlMessage: send error %s\n", strerror(errno));
#endif
                  } else {
                     retn = 0;
                  }
               }
            }

         } else {
            found++;
            switch (i) {
               case CONTROL_START: client->ArgusClientStart++; retn = 0; break;
               case CONTROL_DONE:  {
#ifdef ARGUSDEBUG
                  if (client->hostname != NULL)
                     ArgusDebug (2, "ArgusCheckControlMessage: client %s sent DONE", client->hostname);
                  else
                     ArgusDebug (2, "ArgusCheckControlMessage: received DONE");
#endif
                  retn = -4;
                  break; 
               }

               case CONTROL_DISPLAY: 
               case CONTROL_HIGHLIGHT: 
               case CONTROL_SEARCH: 
               case CONTROL_FILTER:
               default:
#ifdef ARGUSDEBUG
                  if (client->hostname)
                     ArgusDebug (2, "ArgusCheckControlMessage: client %s sent %s",  client->hostname, ptr);
                  else
                     ArgusDebug (2, "ArgusCheckControlMessage: received %s",  ptr);
#endif
                  break;
            }

            break;
         }
         break;
      }
   }

   if (!found) {
#ifdef ARGUSDEBUG
      if (client->hostname)
         ArgusDebug (2, "ArgusCheckControlMessage: client %s sent %s",  client->hostname, ptr);
      else
         ArgusDebug (2, "ArgusCheckControlMessage: received %s",  ptr);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusCheckControlMessage: returning %d\n", retn);
#endif

   return (retn);
}

struct ArgusRecord *
ArgusGenerateInitialMar (struct ArgusOutputStruct *output)
{
   struct ArgusAddrStruct asbuf, *asptr = &asbuf;
   struct timeval tbuf, *tptr = &tbuf;
   struct ArgusRecord *retn;

   if ((retn = (struct ArgusRecord *) ArgusCalloc (1, sizeof(struct ArgusRecord))) == NULL)
     ArgusLog (LOG_ERR, "ArgusGenerateInitialMar(0x%x) ArgusCalloc error %s\n", output, strerror(errno));
   
   retn->hdr.type  = ARGUS_MAR | ARGUS_VERSION;
   retn->hdr.cause = ARGUS_START | ARGUS_SRC_RADIUM;
   retn->hdr.len   = htons((unsigned short) sizeof(struct ArgusRecord)/4);

   retn->argus_mar.argusid = htonl(ARGUS_COOKIE);

   if (output) {
      retn->argus_mar.startime.tv_sec  = htonl(output->ArgusStartTime.tv_sec);
      retn->argus_mar.startime.tv_usec = htonl(output->ArgusStartTime.tv_usec);

      retn->argus_mar.argusMrInterval = htonl(output->ArgusMarReportInterval.tv_sec);
      retn->argus_mar.localnet = htonl(output->ArgusLocalNet);
      retn->argus_mar.netmask = htonl(output->ArgusNetMask);

      retn->argus_mar.nextMrSequenceNum = htonl(output->ArgusOutputSequence);
   }

   gettimeofday (tptr, 0L);

   retn->argus_mar.now.tv_sec  = htonl(tptr->tv_sec);
   retn->argus_mar.now.tv_usec = htonl(tptr->tv_usec);

   output->ArgusLastMarUpdateTime = *tptr;

   retn->argus_mar.major_version = VERSION_MAJOR;
   retn->argus_mar.minor_version = VERSION_MINOR;
   retn->argus_mar.reportInterval = 0;

   if (getParserArgusID(ArgusParser, asptr)) {
         struct cnamemem *cp;
         extern struct cnamemem converttable[HASHNAMESIZE];

         cp = check_cmem(converttable, (const u_char *) ArgusParser->ArgusSourceIDString);
         retn->argus_mar.status &= ~(ARGUS_IDIS_UUID | ARGUS_IDIS_IPV6 | ARGUS_IDIS_STRING | ARGUS_IDIS_INT | ARGUS_IDIS_IPV4);

         if (cp != NULL) {
            retn->argus_mar.thisid = cp->addr.a_un.value;
            retn->argus_mar.status |= cp->type;
         } else {
            retn->argus_mar.thisid = asptr->a_un.value;
         }
   }
   retn->argus_mar.record_len = htonl(-1);

   output->ArgusLastMarUpdateTime = now;

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusGenerateInitialMar() returning\n");
#endif

   return (retn);
}

struct ArgusRecordStruct *
ArgusGenerateStatusMarRecord (struct ArgusOutputStruct *output, unsigned char status)
{
   extern int ArgusAllocTotal, ArgusFreeTotal, ArgusAllocBytes;
   struct ArgusAddrStruct asbuf, *asptr = &asbuf;
   struct ArgusRecordStruct *retn;
   struct ArgusRecord *rec;
   struct timeval now;

   if ((retn = (struct ArgusRecordStruct *) ArgusCalloc (1, sizeof(*retn))) == NULL)
     ArgusLog (LOG_ERR, "ArgusGenerateStatusMarRecord(0x%x) ArgusCalloc error %s\n", output, strerror(errno));

   retn->hdr.type  = ARGUS_MAR | ARGUS_VERSION;
   retn->hdr.cause = status | ARGUS_SRC_RADIUM;
   retn->hdr.len   = ((unsigned short) sizeof(struct ArgusRecord)/4);

   if ((rec = (struct ArgusRecord *) ArgusCalloc(1, sizeof(*rec))) == NULL)
      ArgusLog (LOG_ERR, "ArgusGenerateStatusMarRecord: ArgusCalloc error %s", strerror(errno));

   retn->dsrs[0] = (void *)rec;

   rec->hdr = retn->hdr;

   if (getParserArgusID(ArgusParser, asptr)) {
            switch (getArgusIDType(ArgusParser) & ~ARGUS_TYPE_INTERFACE) {
               case ARGUS_TYPE_STRING: {
                  rec->argus_mar.status |= ARGUS_IDIS_STRING;
                  bcopy (&asptr->a_un.str, &rec->argus_mar.str, 4);
                  break;
               }
               case ARGUS_TYPE_INT: {
                  rec->argus_mar.status |= ARGUS_IDIS_INT;
                  bcopy (&asptr->a_un.value, &rec->argus_mar.value, sizeof(rec->argus_mar.value));
                  break;
               }
               case ARGUS_TYPE_IPV4: {
                  rec->argus_mar.status |= ARGUS_IDIS_IPV4;
                  bcopy (&asptr->a_un.ipv4, &rec->argus_mar.ipv4, sizeof(rec->argus_mar.ipv4));
                  break;
               }
               case ARGUS_TYPE_IPV6: {
//                rec->argus_mar.status |= ARGUS_IDIS_IPV6;
//                bcopy (&asptr->a_un.ipv6, &rec->argus_mar.ipv6, sizeof(rec->argus_mar.ipv6));
                  break;
               }
               case ARGUS_TYPE_UUID: {
//                rec->argus_mar.status |= ARGUS_IDIS_UUID;
//                bcopy (&asptr->a_un.uuid, &rec->argus_mar.uuid, sizeof(rec->argus_mar.uuid));
                  break;
               }
            }
            if (getArgusManInf(ArgusParser) != NULL)
               rec->argus_mar.status |=  ARGUS_ID_INC_INF;

            rec->argus_mar.status  |= getArgusIDType(ArgusParser);
   }

   gettimeofday (&now, 0L);

   if (output) {
      rec->argus_mar.startime.tv_sec  = output->ArgusLastMarUpdateTime.tv_sec;
      rec->argus_mar.startime.tv_usec = output->ArgusLastMarUpdateTime.tv_usec;

      rec->argus_mar.now.tv_sec  = now.tv_sec;
      rec->argus_mar.now.tv_usec = now.tv_usec;

      output->ArgusLastMarUpdateTime = now;

      rec->argus_mar.major_version = VERSION_MAJOR;
      rec->argus_mar.minor_version = VERSION_MINOR;
      rec->argus_mar.reportInterval = 0;


      rec->argus_mar.argusMrInterval = output->ArgusMarReportInterval.tv_sec;

      rec->argus_mar.localnet = output->ArgusLocalNet;
      rec->argus_mar.netmask = output->ArgusNetMask;

      rec->argus_mar.nextMrSequenceNum = output->ArgusOutputSequence;
      rec->argus_mar.record_len = -1;
   }

/*
   if ((ArgusSrc = output->ArgusSrc) != NULL) {
      int i;
      rec->argus_mar.interfaceType = ArgusSrc->ArgusInterface[0].ArgusInterfaceType;
      rec->argus_mar.interfaceStatus = getArgusInterfaceStatus(ArgusSrc);

      rec->argus_mar.pktsRcvd  = 0;
      rec->argus_mar.bytesRcvd = 0;
      rec->argus_mar.dropped   = 0;

      for (i = 0; i < ARGUS_MAXINTERFACE; i++) {
         rec->argus_mar.pktsRcvd  += ArgusSrc->ArgusInterface[i].ArgusStat.ps_recv - 
                                    ArgusSrc->ArgusInterface[i].ArgusLastPkts;
         rec->argus_mar.bytesRcvd += ArgusSrc->ArgusInterface[i].ArgusTotalBytes -
                                    ArgusSrc->ArgusInterface[i].ArgusLastBytes;
         rec->argus_mar.dropped   += ArgusSrc->ArgusInterface[i].ArgusStat.ps_drop - 
                                    ArgusSrc->ArgusInterface[i].ArgusLastDrop;

         ArgusSrc->ArgusInterface[i].ArgusLastPkts  = ArgusSrc->ArgusInterface[i].ArgusStat.ps_recv;
         ArgusSrc->ArgusInterface[i].ArgusLastDrop  = ArgusSrc->ArgusInterface[i].ArgusStat.ps_drop;
         ArgusSrc->ArgusInterface[i].ArgusLastBytes = ArgusSrc->ArgusInterface[i].ArgusTotalBytes;
      }
   }
*/

   if (output) {
      rec->argus_mar.records = output->ArgusTotalRecords - output->ArgusLastRecords;
      output->ArgusLastRecords = output->ArgusTotalRecords;

      if (output->ArgusOutputList)
         rec->argus_mar.output  = output->ArgusOutputList->count;
      else
         rec->argus_mar.output  = 0;

      rec->argus_mar.clients = output->ArgusClients->count;

      rec->argus_mar.bufs  = ArgusAllocTotal - ArgusFreeTotal;
      rec->argus_mar.bytes = ArgusAllocBytes;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusGenerateStatusMarRecord(0x%x, %d) returning 0x%x", output, status, retn);
#endif
   return (retn);
}



void
setArgusPortNum (struct ArgusParserStruct *parser, int value, char *addr)
{
   parser->ArgusPortNum = value;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "setArgusPortNum(%d) returning\n", value);
#endif
}

int
getArgusPortNum(struct ArgusParserStruct *parser)
{
   return(parser->ArgusPortNum);
}

void
setArgusOflag(struct ArgusParserStruct *parser, unsigned int value)
{
   parser->Oflag = value;
}


#if defined HAVE_TCP_WRAPPER

#include <syslog.h>
#include <tcpd.h>

#ifndef MAXPATHNAMELEN
#define MAXPATHNAMELEN   BUFSIZ
#endif

#define PARANOID		1
#define KILL_IP_OPTIONS		1
#define HOSTS_ACCESS		1

void fix_options(struct request_info *);

#endif

int allow_severity = LOG_INFO;     /* run-time adjustable */
int deny_severity  = LOG_WARNING;   /* ditto */


int
ArgusTcpWrapper (struct ArgusOutputStruct *output, int fd, struct sockaddr *from, char *clienthost)
{
   int retn = 0;

   if (output->ArgusUseWrapper) {

#if defined(HAVE_TCP_WRAPPER)
      struct request_info request;

      /*
       * Find out the endpoint addresses of this conversation. Host name
       * lookups and double checks will be done on demand.
       */
    
      request_init(&request, RQ_DAEMON, ArgusParser->ArgusProgramName, RQ_FILE, STDIN_FILENO, 0);
      request.fd = fd;
      fromhost(&request);

      /*
       * Optionally look up and double check the remote host name. Sites
       * concerned with security may choose to refuse connections from hosts
       * that pretend to have someone elses host name.
       */
    
#ifdef PARANOID
      if (STR_EQ(eval_hostname(request.client), paranoid)) {
         ArgusLog (deny_severity, "refused connect from %s", eval_client(&request)); 
         if (request.sink)
            request.sink(request.fd);
         return -1;
      }
#endif

       /*
        * The BSD rlogin and rsh daemons that came out after 4.3 BSD disallow
        * socket options at the IP level. They do so for a good reason.
        * Unfortunately, we cannot use this with SunOS 4.1.x because the
        * getsockopt() system call can panic the system.
        */  

#if defined(KILL_IP_OPTIONS)
      fix_options(&request);
#endif /* KILL_IP_OPTIONS */

       /*
        * Find out and verify the remote host name. Sites concerned with
        * security may choose to refuse connections from hosts that pretend to
        * have someone elses host name.
        */  

#ifdef HOSTS_ACCESS
      if (!hosts_access(&request)) {
         ArgusLog  (deny_severity, "refused connect from %s", eval_client(&request));
         if (request.sink)
            request.sink(request.fd);
         return -1;
      } else
#endif

       /* Report remote client */
      sprintf (clienthost, "%s", eval_client(&request));
      ArgusLog  (allow_severity, "connect from %s", clienthost);
      return (retn);

#else
       /* Report remote client */

#if HAVE_GETADDRINFO
   struct sockaddr_storage remoteaddr, localaddr;
   char localip[60], remoteip[60];
   char hbuf[NI_MAXHOST];
   unsigned int salen, niflags;

   salen = sizeof(remoteaddr);
   bzero(hbuf, sizeof(hbuf));

   if ((getpeername(fd, (struct sockaddr *)&remoteaddr, &salen) == 0) &&
                      (remoteaddr.ss_family == AF_INET || remoteaddr.ss_family == AF_INET6)) {
      if (getnameinfo((struct sockaddr *)&remoteaddr, salen, hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) == 0) {
         strncpy(clienthost, hbuf, sizeof(hbuf) - 1);
      } else {
         clienthost[0] = '\0';
      }
      niflags = NI_NUMERICHOST;
#ifdef NI_WITHSCOPEID
         if (((struct sockaddr *)&remoteaddr)->sa_family == AF_INET6)
            niflags |= NI_WITHSCOPEID;
#endif
         if (getnameinfo((struct sockaddr *)&remoteaddr, salen, hbuf, sizeof(hbuf), NULL, 0, niflags) != 0)
            strncpy(hbuf, "unknown", sizeof(hbuf));

         sprintf(&clienthost[strlen(clienthost)], "[%s]", hbuf);

         salen = sizeof(localaddr);
         if (getsockname(fd, (struct sockaddr *)&localaddr, &salen) == 0) {
            if ((iptostring((struct sockaddr *)&remoteaddr, salen, remoteip, sizeof(remoteip)) == 0) && 
                 iptostring((struct sockaddr *)&localaddr, salen, localip, sizeof(localip)) == 0) {
               retn = 1;
            }
         }
      }

      ArgusLog  (allow_severity, "connect from %s", clienthost);
#endif
#endif /* HAVE_TCP_WRAPPER */
   }

   return (retn);
}


struct ArgusSocketStruct *
ArgusNewSocket (int fd)
{
   struct ArgusSocketStruct *retn = NULL;

   if ((retn = ((struct ArgusSocketStruct *) ArgusCalloc (1, sizeof (struct ArgusSocketStruct)))) != NULL) {
      if ((retn->ArgusOutputList = ArgusNewList()) != NULL) {
         int flags = fcntl (fd, F_GETFL, 0L);
         fcntl (fd, F_SETFL, flags | O_NONBLOCK);
         retn->fd = fd;

      } else {
         ArgusFree(retn);   
         retn = NULL;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusNewSocket (%d) returning 0x%x\n", fd, retn);
#endif

   return (retn);
}


void
ArgusDeleteSocket (struct ArgusOutputStruct *output, struct ArgusClientData *client)
{
   struct ArgusSocketStruct *asock = client->sock;

   if (asock != NULL) {
      struct ArgusListStruct *list = asock->ArgusOutputList;
      struct ArgusRecordStruct *rec;

      while ((rec = (struct ArgusRecordStruct *)
                    ArgusPopFrontList(list, ARGUS_LOCK)) != NULL)
         ArgusDeleteRecordStruct(ArgusParser, rec);
   
      ArgusDeleteList(asock->ArgusOutputList, ARGUS_OUTPUT_LIST);

      close(asock->fd);
      asock->fd = -1;
      client->fd = -1;
      
      if (asock->filename) {
         free(asock->filename);
         asock->filename = NULL;
      }
   
      ArgusFree (asock);
      client->sock = NULL;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusDeleteSocket (0x%x) returning\n", asock);
#endif
}  


#include <sys/stat.h>
#include <fcntl.h>

#define ARGUS_MAXERROR		500000
#define ARGUS_MAXWRITENUM	50000

int ArgusMaxListLength = 500000;
int ArgusCloseFile = 0;


extern struct ArgusRecord *ArgusGenerateInitialMar (struct ArgusOutputStruct *);


static
void
ArgusWriteSocket(struct ArgusOutputStruct *output,
                 struct ArgusClientData *client,
                 struct ArgusRecordStruct *rec,
                 unsigned char *buf)
{
   struct ArgusSocketStruct *asock = client->sock;
   struct ArgusListStruct *list = asock->ArgusOutputList;

   if (list->count >= ArgusMaxListLength) {
      if (ArgusWriteOutSocket(output, client, buf) < 0) {
#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&list->lock);
#endif
         if (list->count >= ArgusMaxListLength) {
            struct ArgusRecordStruct *trec;
            int i;
#define ARGUS_MAX_TOSS_RECORD	128
            ArgusLog (LOG_WARNING, "ArgusWriteSocket: tossing records to %s\n", client->hostname);

            for (i = 0; i < ARGUS_MAX_TOSS_RECORD; i++)
               if ((trec = (struct ArgusRecordStruct *) ArgusPopFrontList(list, ARGUS_NOLOCK)) != NULL)
                  ArgusDeleteRecordStruct(ArgusParser, trec);
         }
#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&list->lock);
#endif
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWriteSocket (0x%x, 0x%x, 0x%x) schedule record\n", output, asock, rec);
#endif
   ArgusPushBackList (list, (struct ArgusListRecord *) ArgusCopyRecordStruct(rec), ARGUS_LOCK);
}


static
int
ArgusWriteOutSocket(struct ArgusOutputStruct *output,
                    struct ArgusClientData *client,
                    unsigned char *buf)
{
   struct ArgusSocketStruct *asock = client->sock;
   struct ArgusListStruct *list = NULL;
   struct ArgusRecordStruct *rec = NULL;
   int retn = 0, count = 0, len, ocnt;
   struct stat statbuf;
   unsigned char *ptr;

   if ((list = asock->ArgusOutputList) != NULL) {
      if (asock->rec != NULL)
         count++;

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&list->lock);
#endif
      if ((count += ArgusGetListCount(list)) > 0) {
         if (count > ARGUS_MAXWRITENUM)
            count = ARGUS_MAXWRITENUM;

         while ((asock->fd != -1 ) && count--) {
            if ((rec = asock->rec) == NULL) {
               asock->writen = 0;
               asock->length = 0;

               if ((rec = (struct ArgusRecordStruct *) ArgusPopFrontList(list, ARGUS_NOLOCK)) != NULL) {

                     switch (client->format) {
                        case ARGUS_DATA: {
                           if (ArgusGenerateRecord (rec, 0, (char *)&buf[0])) {
                              int cnt = ((struct ArgusRecord *)&buf[0])->hdr.len * 4;
#if defined(_LITTLE_ENDIAN)
                              ArgusHtoN((struct ArgusRecord *)&buf[0]);
#endif
#ifdef ARGUS_SASL
                              if (client->sasl_conn) {
                                 unsigned int outputlen = 0;
                                 const char *output =  NULL;
#ifdef ARGUSDEBUG
                                 ArgusDebug (7, "ArgusHandleClientData: sasl_encode(0x%x, 0x%x, %d, 0x%x, 0x%x)\n",
                                                            client->sasl_conn, rec, cnt, &output, &outputlen);
#endif
                                 if ((retn = sasl_encode(client->sasl_conn, (const char *)&buf[0], (unsigned int) cnt,
                                                            &output, &outputlen)) == SASL_OK) {
#ifdef ARGUSDEBUG
                                    ArgusDebug (7, "ArgusHandleClientData: sasl_encode returned %d bytes\n", outputlen);
#endif
                                    if (outputlen < ARGUS_MAXRECORD) {
                                       bcopy(output, &buf[0], outputlen);
                                       cnt = outputlen;

                                    } else
                                       ArgusLog (LOG_ERR, "sasl_encode: returned too many bytes %d\n", outputlen);

                                 } else
                                    ArgusLog (LOG_ERR, "sasl_encode: failed returned %d\n", retn);
                              }
#endif
                              asock->length = cnt;
                              asock->rec = rec;

                           } else {
#ifdef ARGUSDEBUG
                              ArgusDebug (1, "ArgusHandleClientData: ArgusGenerateRecord error deleting record");
#endif
                              ArgusDeleteRecordStruct(ArgusParser, rec);
                           }
                           break;
                        }

                        case ARGUS_CISCO_V5_DATA: {
                           if (ArgusGenerateCiscoRecord(rec, 0, (char *)&buf[0])) {
                              asock->length = sizeof(CiscoFlowHeaderV5_t) + sizeof(CiscoFlowEntryV5_t);
                              asock->rec = rec;
                           }
                        }
                     }
               }
            }

            if (asock->rec != NULL) {
               ptr = (unsigned char *)&buf[0];
               if ((client->host == NULL) && (!(asock->writen))) {
                  if (!(output->ArgusWriteStdOut) && (asock->filename)) {
                     if (asock->lastwrite.tv_sec < output->ArgusGlobalTime.tv_sec) {
                        int retn = stat (asock->filename, &statbuf);

                        if ((retn < 0) || (ArgusCloseFile || ((statbuf.st_dev != asock->statbuf.st_dev) || 
                                                              (statbuf.st_ino != asock->statbuf.st_ino)))) {
                           close(asock->fd);
                           if ((asock->fd = open (asock->filename, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0x1a4)) < 0)
                              ArgusLog (LOG_ERR, "ArgusWriteSocket: open(%s, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0x1a4) failed %s\n",
                                         asock->filename, strerror(errno));
#ifdef ARGUSDEBUG
                           ArgusDebug (3, "ArgusWriteOutSocket: created outfile %s\n", asock->filename);
#endif
                        }

                        if ((stat (asock->filename, &statbuf)) == 0) {
                           if (statbuf.st_size == 0) {
                              if (output->format == ARGUS_DATA) {
                                 if (output->ArgusInitMar != NULL)
                                    ArgusFree(output->ArgusInitMar);
                                 output->ArgusInitMar = ArgusGenerateInitialMar(output);
                                 ocnt = sizeof(struct ArgusRecord);
                                 if (((retn = write (asock->fd, output->ArgusInitMar, ocnt))) < ocnt)
                                    ArgusLog (LOG_ERR, "ArgusWriteSocket: write %s failed %s\n", asock->filename, strerror(errno));
                                 ArgusFree(output->ArgusInitMar);
                                 output->ArgusInitMar = NULL;
                              }
                           }
                           bcopy (&statbuf, &asock->statbuf, sizeof(statbuf));
                        }
                        asock->lastwrite = output->ArgusGlobalTime;
                     }
                  }
               }
               
               if ((len = (asock->length - asock->writen)) > 0) {
                  if (client->host != NULL) {
                     if ((retn = sendto (asock->fd, &buf[0], len, 0, client->host->ai_addr, client->host->ai_addrlen)) < 0)
                        ArgusLog (LOG_ERR, "ArgusInitOutput: sendto(): retn %d %s", retn, strerror(errno));
#ifdef ARGUSDEBUG
                        ArgusDebug (3, "ArgusWriteSocket: sendto (%d, %x, %d, ...) %d\n", asock->fd, &buf[0], len, retn);
#endif
                     asock->errornum = 0;
                     asock->writen += len;

                  } else 
                  if ((retn = write(asock->fd, (unsigned char *)&ptr[asock->writen], len)) > 0) {
                     asock->errornum = 0;
                     asock->writen += retn;
#ifdef ARGUSDEBUG
                     ArgusDebug (8, "ArgusWriteOutSocket(0x%x, 0x%x) wrote %d bytes\n", output, client, retn);
#endif
                  } else {
                     if (retn == 0) {
                        if (client->hostname)
                           ArgusLog (LOG_WARNING, "ArgusWriteOutSocket(0x%x, 0x%x) client %s write 0: disconnecting\n", output, client, client->hostname, asock->errornum);
                        else
                           ArgusLog (LOG_WARNING, "ArgusWriteOutSocket(0x%x, 0x%x) write 0: disconnecting\n", output, client, asock->errornum);
                        close(asock->fd);
                        asock->fd = -1;
                        asock->writen = 0;
                        asock->length = 0;

                        if (asock->rec != NULL) {
                           ArgusDeleteRecordStruct(ArgusParser, rec);
                           asock->rec = NULL;
                        }
                        while ((rec = (struct ArgusRecordStruct *) ArgusPopFrontList(list, ARGUS_NOLOCK)) != NULL)
                           ArgusDeleteRecordStruct(ArgusParser, rec);

                     } else {
                        switch (errno) {
                           case 0:
                           case EAGAIN:
                              asock->errornum++;
#ifdef ARGUSDEBUG
                              if (client->hostname)
                                 ArgusDebug (6, "ArgusWriteOutSocket: client %s count %d write error %s\n", client->hostname, count, strerror(errno));
                              else
                                 ArgusDebug (6, "ArgusWriteOutSocket: client %s count %d write error %s\n", count, strerror(errno));
#endif
                              count = 0;

                           case EINTR: 
                              retn = 0;
                              break;

                           default:
                           case EPIPE:
                           case ENOSPC: {
                              if (asock->filename != NULL)
                                 ArgusLog (LOG_WARNING, "ArgusWriteOutSocket(0x%x, 0x%x) closing %s, %s\n", output, client, client->filename, strerror(errno));
                              else
                              if (client->hostname != NULL)
                                 ArgusLog (LOG_WARNING, "ArgusWriteOutSocket(0x%x, 0x%x) %s disconnecting %s\n", output, client, client->hostname, strerror(errno));
                              else
                                 ArgusLog (LOG_WARNING, "ArgusWriteOutSocket(0x%x, 0x%x) disconnecting %s\n", output, client, strerror(errno));

                              close(asock->fd);
                              asock->fd = -1;
                              asock->rec = NULL;
                              asock->writen = 0;
                              asock->length = 0;
                              ArgusDeleteRecordStruct(ArgusParser, rec);
                              while ((rec = (struct ArgusRecordStruct *) ArgusPopFrontList(list, ARGUS_NOLOCK)) != NULL)
                                 ArgusDeleteRecordStruct(ArgusParser, rec);

                              count = 0;
                              retn = -1;
                              break;
                           }
                        }
                     }
                  }
               }
               
               if ((asock->writen > 0) && (asock->writen >= asock->length)) {
                  gettimeofday(&list->outputTime, 0L);
                  ArgusDeleteRecordStruct(ArgusParser, rec);
                  asock->rec = NULL;

               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (6, "ArgusWriteOutSocket: still work to be done for 0x%x, len %d writen %d turns %d", rec, asock->length, asock->writen, count);
#endif
               }

            } else {
               count = 0;
#ifdef ARGUSDEBUG
               ArgusDebug (6, "ArgusWriteOutSocket: nothing to be done for 0x%x, len %d writen %d", rec, asock->length, asock->writen);
#endif
            }
         }

         if (asock->errornum >= ARGUS_MAXERROR) {
            ArgusLog (LOG_WARNING, "ArgusWriteOutSocket(0x%x) client not processing: disconnecting\n", asock, asock->errornum);
            close(asock->fd);
            asock->fd = -1;
            if (asock->rec != NULL) {
               ArgusDeleteRecordStruct(ArgusParser, rec);
               asock->rec = NULL;
               asock->writen = 0;
               asock->length = 0;
            }
            while ((rec = (struct ArgusRecordStruct *) ArgusPopFrontList(list, ARGUS_NOLOCK)) != NULL)
               ArgusDeleteRecordStruct(ArgusParser, rec);

            asock->errornum = 0;
            retn = -1;
         }

         if ((count = ArgusGetListCount(list)) > ArgusMaxListLength) {
            ArgusLog (LOG_WARNING, "ArgusWriteOutSocket(0x%x) max queue exceeded %d\n", asock, count);
            retn = -1;
         }

#ifdef ARGUSDEBUG
         if (list) {
            ArgusDebug (4, "ArgusWriteOutSocket (0x%x, 0x%x) %d records waiting. returning %d\n", output, client, list->count, retn);
         } else {
            ArgusDebug (4, "ArgusWriteOutSocket (0x%x, 0x%x) no list.  returning %d\n", output, client, retn);
         }
#endif
      }
#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&list->lock);
#endif
   }

   return retn;
}


void
ArgusSendFile (struct ArgusOutputStruct *output, struct ArgusClientData *client, char *file, int status)
{
   int retn = 0, pid = 0, cnt, fd = client->fd, flags, error = 0;
   unsigned int filesize;
   char sbuf[MAXBUFFERLEN];
   struct stat statbuf;
   FILE *ffd = NULL;

   flags = fcntl (fd, F_GETFL, 0L);
   fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);

   switch ((retn = stat (file, &statbuf))) {
      case 0:
         if (statbuf.st_mode & S_IFREG)
            break;

      case -1:
         error++;
         break;
   }

   if (error) {
      if ((cnt = send (fd, "KO", 2, 0)) != 2) {
#ifdef ARGUSDEBUG
         ArgusDebug (3, "ArgusSendFile: send error %s\n", strerror(errno));
#endif
      }
      ArgusLog (LOG_INFO, "ArgusSendFile: file %s error %s", file, strerror(errno));
      client->pid = 0;
      return;
   }

   filesize = statbuf.st_size;
#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusSendFile: %s size is %d", file, filesize);
#endif

   if ((pid = fork ()) < 0)
      ArgusLog (LOG_ERR, "Can't fork file processor %s", strerror(errno));

   if (!(pid)) {
#if defined(_LITTLE_ENDIAN)
         filesize = htonl(filesize);
#endif

         if ((cnt = send (fd, &filesize, sizeof(filesize), 0)) != sizeof(filesize)) {
            ArgusLog (LOG_NOTICE, "ArgusSendFile: file %s error %s", file, strerror(errno));
         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (3, "ArgusSendFile: sent %d bytes");
#endif
         }

         if ((cnt = recv (fd, sbuf, MAXBUFFERLEN, 0)) <= 0) {
            if (cnt < 0) {
               ArgusLog (LOG_ERR, "ArgusSendFile (0x%x, %d) recv() returned error %s\n", client, fd, strerror(errno));

            } else {
               ArgusLog (LOG_ERR, "ArgusSendFile (0x%x, %d) recv() returned %d bytes\n", client, fd, cnt);
            }
         }

         if (strstr (sbuf, "START")) {
#ifdef ARGUSDEBUG
            ArgusDebug (3, "ArgusSendFile: received START from requestor");
#endif
            client->ArgusClientStart++;
            if ((ffd = fopen (file, "r")) != NULL) {
               char sbuf[MAXBUFFERLEN];
               int cnt = 0, bytes = 0;
               while ((cnt = fread (sbuf, 1, MAXBUFFERLEN, ffd)) > 0) {
                  if (write (fd, sbuf, cnt) < cnt) {
                     ArgusLog (LOG_ERR, "remote file transfer write error", strerror(errno));
                  }
                  bytes += cnt;
               }

               if (ferror(ffd))
                  ArgusLog (LOG_ERR, "local file transfer read error", strerror(errno));

               ArgusLog (LOG_INFO, "ArgusSendFile: file %s sent %d bytes\n", file, bytes);

               fclose(ffd);
            }

         } else
            ArgusLog (LOG_ERR, "ArgusSendFile: client responded with %s\n", sbuf);

#ifdef ARGUSDEBUG
      ArgusDebug (3, "ArgusSendFile: file %s done.\n", file);
#endif

      exit (0);

   } else {
      client->pid = pid;
#ifdef ARGUSDEBUG
      ArgusDebug (3, "ArgusSendFile (0x%x, %s): forked file processor\n", client, file);
#endif
   }
}


void
ArgusSetChroot(char *dir)
{
   if (chdir(dir) < 0)
      ArgusLog(LOG_ERR, "ArgusSetChroot: failed to chdir to \"%s\": %s", dir, strerror(errno));
  
   if (chroot(dir) < 0)
      ArgusLog(LOG_ERR, "ArgusSetChroot: failed to chroot to \"%s\": %s", dir, strerror(errno));
 
   if (chdir("/") < 0)
      ArgusLog(LOG_ERR, "ArgusSetChroot: failed to chdir to \"/\" after chroot: %s", dir, strerror(errno));
 
#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusSetChroot (0x%x) returning\n", dir);
#endif
} 



#if defined(ARGUS_SASL)
/* This creates a structure that defines the allowable
 *   security properties 
 */
#define PROT_BUFSIZE 4096
sasl_security_properties_t *
mysasl_secprops(int flags)
{
    static sasl_security_properties_t ret;

    bzero((char *)&ret, sizeof(ret));

    ret.maxbufsize = PROT_BUFSIZE;
    ret.min_ssf = ArgusMinSsf; /* minimum allowable security strength */
    ret.max_ssf = ArgusMaxSsf; /* maximum allowable security strength */

    ret.security_flags = flags;
    
    ret.property_names = NULL;
    ret.property_values = NULL;

    return &ret;
}
#endif


/*
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 *
 * modified by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/argus/clients/clients/radium.c#7 $
 * $DateTime: 2012/12/13 11:07:52 $
 * $Change: 2514 $
 */


#if !defined(ArgusSasl)
#define ArgusSasl
#endif
 

int ArgusAuthenticateClient (struct ArgusClientData *);
int ArgusGetSaslString(FILE *, char *, int);
int ArgusSendSaslString(FILE *, const char *, int, int);

int
ArgusAuthenticateClient (struct ArgusClientData *client)
{
   int retn = 1;

#ifdef ARGUS_SASL
   unsigned int rlen = 0;
   int len, mechnum = 0;
   char buf[8192], chosenmech[512];
   const char *data;
   sasl_conn_t *conn = NULL;

// int SASLOpts = (SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS);
   FILE *in, *out;

   if (ArgusMaxSsf == 0)
       goto no_auth;

   conn = client->sasl_conn;

   if ((retn = sasl_listmech(conn, NULL, "{", ", ", "}", &data, &rlen, &mechnum)) != SASL_OK)
      ArgusLog (LOG_ERR, "ArgusAuthenticateClient: Error generating mechanism list");

   if ((in  = fdopen (client->fd, "r")) < 0)
      ArgusLog (LOG_ERR, "ArgusAuthenticateClient: fdopen() error %s", strerror(errno));

   if ((out = fdopen (client->fd, "w")) < 0)
      ArgusLog (LOG_ERR, "ArgusAuthenticateClient: fdopen() error %s", strerror(errno));

   ArgusSendSaslString (out, data, rlen, SASL_OK);

   if ((len = ArgusGetSaslString (in, chosenmech, sizeof(chosenmech))) <= 0)  {
#ifdef ARGUSDEBUG
      ArgusDebug (2, "ArgusAuthenticateClient: Error ArgusGetSaslString returned %d\n", len);
#endif
      return 0;
   }

   if ((len = ArgusGetSaslString (in, buf, sizeof(buf))) <= 0)  {
#ifdef ARGUSDEBUG
      ArgusDebug (2, "ArgusAuthenticateClient: Error ArgusGetSaslString returned %d\n", len);
#endif
      return 0;
   }

   if (*buf == 'Y') {
      if ((len = ArgusGetSaslString (in, buf, sizeof(buf))) <= 0)  {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusAuthenticateClient: Error ArgusGetSaslString returned %d\n", len);
#endif
         return 0;
      }
      retn = sasl_server_start(conn, chosenmech, buf, len, &data, &rlen);

   } else {
      retn = sasl_server_start(conn, chosenmech, NULL, 0, &data, &rlen);
   }

   if ((retn != SASL_OK) && (retn != SASL_CONTINUE)) {
      sprintf (buf, "%s", sasl_errstring(retn, NULL, NULL));
#ifdef ARGUSDEBUG
      ArgusDebug (2, "ArgusAuthenticateClient: Error starting SASL negotiation");
#endif
      ArgusSendSaslString(out, buf, strlen(buf), retn);
      return 0;
   }

   while (retn == SASL_CONTINUE) {
      if (data) {
#ifdef ARGUSDEBUG
         ArgusDebug(2, "sending response length %d...\n", rlen);
#endif
         ArgusSendSaslString(out, data, rlen, retn);
      } else {
#ifdef ARGUSDEBUG
         ArgusDebug(2, "no data to send? ...\n");
#endif
      }

#ifdef ARGUSDEBUG
      ArgusDebug(2, "waiting for client reply...\n");
#endif
      len = ArgusGetSaslString(in, buf, sizeof(buf));

      if (len < 0) {
#ifdef ARGUSDEBUG
         ArgusDebug(2, "client disconnected ...\n");
#endif
         return 0;
      }

      retn = sasl_server_step(conn, buf, len, &data, &rlen);
      if ((retn != SASL_OK) && (retn != SASL_CONTINUE)) {
         sprintf (buf, "%s", sasl_errstring(retn, NULL, NULL));
#ifdef ARGUSDEBUG
         ArgusDebug(2, "Authentication failed %s\n", sasl_errstring(retn, NULL, NULL));
#endif
         ArgusSendSaslString(out, buf, strlen(buf), retn);
         return 0;
      }
   }

   if (retn == SASL_OK)
      ArgusSendSaslString(out, NULL, 0, SASL_OK);

no_auth:
#endif
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAuthenticateClient() returning %d\n", retn);
#endif

   return (retn);
}


#ifdef ARGUS_SASL

#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <sysexits.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

/* send/recv library for IMAP4 style literals. */

int
ArgusSendSaslString(FILE *f, const char *s, int l, int mode)
{
   char *buf = NULL, *ptr = NULL, error[128];
   unsigned int al, len;
   int result, size, tsize;

   switch (mode) {
      case SASL_OK: {
         if ((s == NULL) || (l == 0)) {
            ptr = "D: ";
            tsize = 3;
            break;
         }
      }
      case SASL_CONTINUE: {
         ptr = "S: ";
         tsize = 3;
         break;
      }
      default: {
         sprintf (error, "E: [%d]", mode);
         ptr = error;
         tsize = strlen(error);
         break;
      }
   }

   if (ferror(f))
      clearerr(f);

   while ((size = fwrite(ptr, 1, tsize, f)) != tsize) {
      if (size >= 0) {
         tsize -= size;
         ptr += size;
      } else {
         if (ferror(f))
            ArgusLog (LOG_ERR, "ArgusSendSaslString: error %d", ferror(f));
      }
   }

   if (l > 0) {
      al = (((l / 3) + 1) * 4) + 1;

      if ((buf = malloc(al)) == NULL)
         ArgusLog (LOG_ERR, "malloc: error %s", strerror(errno));

      if ((ptr = buf) != NULL) {
         result = sasl_encode64(s, l, buf, al, &len);

         if (result == SASL_OK) {
            tsize = len;
            while ((size = fwrite(ptr, 1, tsize, f)) != tsize) {
               if (size >= 0) {
                  tsize -= size;
                  ptr += size;
               } else {
                  if (ferror(f))
                     ArgusLog (LOG_ERR, "ArgusSendSaslString: error %d", ferror(f));
               }
            }
         }
      }

      free(buf);
   }

   ptr = "\n";
   tsize = 1;
   while ((size = fwrite(ptr, 1, tsize, f)) != tsize) {
      if (size >= 0) {
         tsize -= size;
         ptr += size;
      } else {
         if (ferror(f))
            ArgusLog (LOG_ERR, "ArgusSendSaslString: error %d", ferror(f));
      }
   }

   fflush(f);

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusSendSaslString(0x%x, 0x%x, %d) %s", f, s, l, s);
#endif
   return len;
}

int
ArgusGetSaslString(FILE *f, char *buf, int buflen)
{
   unsigned int len = -1;
   char *s = NULL;
   int result;

   if (ferror(f))
      clearerr(f);

   if ((s = fgets(buf, buflen, f)) != NULL) {
      switch (*buf) {
         case 'C': {
            if (!(strncmp(buf, "C: ", 3))) {
               buf[strlen(buf) - 1] = '\0';

               result = sasl_decode64(buf + 3, (unsigned) strlen(buf + 3), buf, buflen, &len);

               if (result != SASL_OK)
                  ArgusLog (LOG_ERR, "ArgusGetSaslString: sasl_decode64 error");

               buf[len] = '\0';
            } else
               ArgusLog (LOG_ERR, "ArgusGetSaslString: error %s", strerror(errno));

            break;
         }

         default:
         case 'N': 
            len = -1;
            break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusGetSaslString(0x%x, 0x%x, %d) %s", f, buf, buflen, buf);
#endif 
   return len;
}

#endif 
