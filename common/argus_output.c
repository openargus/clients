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

#if defined(HAVE_XDR)
#include <rpc/types.h>
#if defined(HAVE_RPC_XDR_H)
#include <rpc/xdr.h>
#endif
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
#include "argus_threads.h"
#include "ring.h"

static void *ArgusControlChannelProcess(void *);

struct ArgusRecord *ArgusGenerateRecord (struct ArgusRecordStruct *, unsigned char, char *, int);
struct ArgusV3Record *ArgusGenerateV3Record (struct ArgusRecordStruct *, unsigned char, char *);
struct ArgusRecord *ArgusGenerateV5Record (struct ArgusRecordStruct *, unsigned char, char *);
unsigned int ArgusGenerateV5SrcId(struct ArgusTransportStruct *, unsigned int *);
static struct ArgusRecord *ArgusGenerateInitialMar (struct ArgusOutputStruct *, char);

#ifdef ARGUS_SASL
static int ArgusAuthenticateClient (struct ArgusClientData *, int);
#endif

extern char *chroot_dir;
extern uid_t new_uid;
extern gid_t new_gid;

void ArgusSetChroot(char *);


#include <ctype.h>
#include <math.h>

struct ArgusQueueNode {
   struct ArgusQueueHeader qhdr;
   void *datum;
};

struct ArgusWireFmtBuffer {
   uint32_t refcount;
   uint32_t len;
   union {
       struct ArgusRecord rec;
       unsigned char buf[ARGUS_MAXRECORD]; /* 256 KB */
   } data;
};

static void ArgusWriteSocket(struct ArgusOutputStruct *,
                             struct ArgusClientData *,
                             struct ArgusWireFmtBuffer *);
static int ArgusWriteOutSocket(struct ArgusOutputStruct *,
                               struct ArgusClientData *);
static char ** ArgusHandleMARCommand(struct ArgusOutputStruct *, char *);

static struct ArgusQueueNode *
NewArgusQueueNode(void *datum)
{
   struct ArgusQueueNode *n = ArgusMalloc(sizeof(*n));

   if (n == NULL)
      return NULL;

   memset(n, 0, sizeof(struct ArgusQueueHeader));
   n->datum = datum;
   return n;
}

static void
FreeArgusQueueNode(struct ArgusQueueNode *n)
{
   ArgusFree(n);
}

static struct ArgusWireFmtBuffer *
NewArgusWireFmtBuffer(struct ArgusRecordStruct *rec, int format, char version)
{
   struct ArgusWireFmtBuffer *awf;

   awf = ArgusMallocAligned(sizeof(*awf), 64);
   if (awf == NULL)
      return NULL;

   memset(awf, 0, sizeof(*awf) - ARGUS_MAXRECORD);
   awf->refcount = 1;
   awf->len = 0;
   if (rec == NULL)
      /* no record to munge, just return allocated buffer */
      return awf;

   if (format == ARGUS_DATA) {
      if (ArgusGenerateRecord (rec, 0, (char *)&awf->data.buf[0], version)) {
         awf->len = awf->data.rec.hdr.len * 4;
         ArgusHtoN(&awf->data.rec);
      }
   } else if (format == ARGUS_CISCO_V5_DATA) {
      if (ArgusGenerateCiscoRecord(rec, 0, (char *)&awf->data.buf[0])) {
         awf->len = sizeof(CiscoFlowHeaderV5_t) + sizeof(CiscoFlowEntryV5_t);
      }
   }

   if (awf->len == 0) {
      ArgusFree(awf);
      return NULL;
   }

   if (awf->len < sizeof(*awf)/2)
      awf = ArgusRealloc(awf, sizeof(*awf) - sizeof(awf->data.buf) + awf->len);

   return awf;
}

static void
FreeArgusWireFmtBuffer(struct ArgusWireFmtBuffer *awf)
{
   awf->refcount--;
   if (awf->refcount == 0) {
      ArgusFree(awf);
   }
}

static void
DrainArgusSocketQueue(struct ArgusClientData *client)
{
   struct ArgusSocketStruct *asock = client->sock;
   struct ArgusListStruct *list = asock->ArgusOutputList;
   struct ArgusWireFmtBuffer *awf;
   struct ArgusQueueNode *node;

   if (asock == NULL)
      return;

   while ((node = (struct ArgusQueueNode *)ArgusPopFrontList(list, ARGUS_NOLOCK)) != NULL) {
      awf = node->datum;
      FreeArgusQueueNode(node);
      FreeArgusWireFmtBuffer(awf);
   }
}

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
ArgusEstablishListen (struct ArgusParserStruct *parser,
                      struct ArgusOutputStruct *output,
                      int port, char *baddr, char version)
{
   int s = -1;

   if (version != ARGUS_VERSION_3) /* the only possible value other than 5 */
      version = ARGUS_VERSION;

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
                     if ((retn = listen (s, ARGUS_LISTEN_BACKLOG)) >= 0) {
                        MUTEX_LOCK(&parser->lock);
                        parser->ArgusOutputs[parser->ArgusListens] = output;
                        parser->ArgusLfdVersion[parser->ArgusListens] = version;
                        parser->ArgusLfd[parser->ArgusListens] = s;
                        parser->ArgusListens++;
                        MUTEX_UNLOCK(&parser->lock);

                        output->ArgusLfd[output->ArgusListens] = s;
                        output->ArgusLfdVersion[output->ArgusListens] = version;
                        output->ArgusListens++;
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

#else /* HAVE_GETADDRINFO */

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
               if ((listen (s, ARGUS_LISTEN_BACKLOG)) >= 0) {
                  MUTEX_LOCK(&parser->lock);
                  parser->ArgusOutputs[parser->ArgusListens] = output;
                  parser->ArgusLfdVersion[parser->ArgusListens] = version;
                  parser->ArgusLfd[parser->ArgusListens] = s;
                  parser->ArgusListens++;
                  MUTEX_UNLOCK(&parser->lock);

                  output->ArgusLfd[output->ArgusListens] = s;
                  output->ArgusLfdVersion[output->ArgusListens] = version;
                  output->ArgusListens++;
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

#if defined(ARGUS_THREADS)
   if (parser->listenthread == 0) {
      if ((pthread_create(&parser->listenthread, NULL,
                          ArgusListenProcess, parser)) != 0)
         ArgusLog (LOG_ERR, "%s() pthread_create error %s\n", __func__, strerror(errno));
   }
#endif
     
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

static void
ArgusDeleteClient(struct ArgusClientData *client)
{
#ifdef ARGUSDEBUG
   ArgusDebug(1, "%s(%p)\n", __func__, client);
#endif
   if (client->clientid) {
      ArgusFree(client->clientid);
      client->clientid = NULL;
   }
   RingFree(&client->ring);
}

struct ArgusOutputStruct *
ArgusNewOutput (struct ArgusParserStruct *parser, int sasl_min_ssf,
                int sasl_max_ssf, int auth_localhost)
{
   struct ArgusOutputStruct *retn = NULL;

   if ((retn = (struct ArgusOutputStruct *) ArgusCalloc (1, sizeof (struct ArgusOutputStruct))) == NULL)
     ArgusLog (LOG_ERR, "ArgusNewOutput() ArgusCalloc error %s\n", strerror(errno));


   if ((retn->ArgusClients = ArgusNewQueue()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewOutput: clients queue %s", strerror(errno));

   retn->ArgusParser    = parser;

   retn->ArgusPortNum   = parser->ArgusPortNum;
   retn->ArgusBindAddr  = parser->ArgusBindAddr;
   retn->ArgusWfileList = parser->ArgusWfileList;

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
   retn->sasl_min_ssf = sasl_min_ssf;
   retn->sasl_max_ssf = sasl_max_ssf;
   retn->auth_localhost = auth_localhost;
#if defined(ARGUS_THREADS)
   retn->ListenNotify[0] = retn->ListenNotify[1] = -1;
#endif

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

   if (output->ArgusClients &&
       MUTEX_LOCK(&output->ArgusClients->lock) == 0) {
      struct ArgusClientData *oc;

      oc = (struct ArgusClientData *)output->ArgusClients->start;
      while (oc) {
         ArgusDeleteClient(oc);
         oc = (struct ArgusClientData *)oc->qhdr.nxt;
      }
      MUTEX_UNLOCK(&output->ArgusClients->lock);
   }

   ArgusDeleteList(output->ArgusInputList, ARGUS_OUTPUT_LIST);
   ArgusDeleteList(output->ArgusOutputList, ARGUS_OUTPUT_LIST);
   ArgusDeleteQueue(output->ArgusClients);

   if (output->ArgusInitMar != NULL)
      ArgusFree(output->ArgusInitMar);

   parser->ArgusOutputList = NULL;
#if defined(ARGUS_THREADS)
   if (output->ListenNotify[0] >= 0)
      close(output->ListenNotify[0]);
   if (output->ListenNotify[1] >= 0)
      close(output->ListenNotify[1]);
#endif
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

   if ((retn = (struct ArgusOutputStruct *) ArgusCalloc (1, sizeof (struct ArgusOutputStruct))) == NULL)
     ArgusLog (LOG_ERR, "ArgusNewControlChannel() ArgusCalloc error %s\n", strerror(errno));

   if ((retn->ArgusClients = ArgusNewQueue()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewControlChannel: clients queue %s", strerror(errno));

   retn->ArgusParser      = parser;
   retn->ArgusControlPort = parser->ArgusControlPort;
   retn->ArgusBindAddr    = parser->ArgusBindAddr;
   retn->ArgusWfileList   = parser->ArgusWfileList;

   retn->ArgusInputList   = parser->ArgusOutputList;
   parser->ArgusWfileList = NULL;

   memset(&retn->ArgusMarReportInterval, 0,
          sizeof(retn->ArgusMarReportInterval));

   gettimeofday (&retn->ArgusStartTime, 0L);
   retn->ArgusLastMarUpdateTime = retn->ArgusStartTime;

   retn->ArgusReportTime.tv_sec   = retn->ArgusStartTime.tv_sec + parser->ArgusMarReportInterval.tv_sec;
   retn->ArgusReportTime.tv_usec  = retn->ArgusStartTime.tv_usec + parser->ArgusMarReportInterval.tv_usec;

   if (retn->ArgusReportTime.tv_usec > 1000000) {
      retn->ArgusReportTime.tv_sec++;
      retn->ArgusReportTime.tv_usec -= 1000000;
   }

#if defined(ARGUS_THREADS)
   retn->ListenNotify[0] = retn->ListenNotify[1] = -1;
#endif

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
#if defined(ARGUS_THREADS)
   if (output->ListenNotify[0] >= 0)
      close(output->ListenNotify[0]);
   if (output->ListenNotify[1] >= 0)
      close(output->ListenNotify[1]);
#endif
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

      if (output->ArgusWfileList != NULL) {
         int i, retn, count = output->ArgusWfileList->count;

         if (setuid(getuid()) < 0)
            ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusCalloc %s", strerror(errno));

         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) ArgusPopFrontList(output->ArgusWfileList, ARGUS_LOCK)) != NULL) {
               struct ArgusClientData *client = (void *) ArgusCalloc (1, sizeof(struct ArgusClientData));

               if (client == NULL)
                  ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusCalloc %s", strerror(errno));

               if (output->ArgusInitMar != NULL)
                  ArgusFree (output->ArgusInitMar);

               if ((output->ArgusInitMar = ArgusGenerateInitialMar(output, ARGUS_VERSION)) == NULL)
                  ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusGenerateInitialMar error %s", strerror(errno));

               len = ntohs(output->ArgusInitMar->hdr.len) * 4;

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
                     client->version = ARGUS_VERSION;

                  } else {
                     if ((client->fd = open (wfile->filename, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0x1a4)) < 0)
                        ArgusLog (LOG_ERR, "ArgusInitOutput: open %s: %s", wfile->filename, strerror(errno));

                     wfile->format = ARGUS_DATA;
                     client->format = wfile->format;
                     client->version = ARGUS_VERSION;
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

#if defined(ARGUS_SASL)
      int retn = 0;
#endif /* ARGUS_SASL */

#if defined(ARGUS_THREADS)
      pthread_attr_t attrbuf, *attr = &attrbuf;

      pthread_mutex_init(&output->lock, NULL);
#endif

      if ((output->ArgusOutputList = ArgusNewList()) == NULL)
         ArgusLog (LOG_ERR, "ArgusInitControlChannel: ArgusList %s", strerror(errno));

      if (output->ArgusWfileList != NULL) {
         int i, count = output->ArgusWfileList->count;

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
ArgusCloseListen(struct ArgusParserStruct *parser)
{
#ifdef ARGUSDEBUG
   ArgusDebug(1, "%s\n", __func__);
#endif
#if defined(ARGUS_THREADS)
   if (parser->listenthread)
      pthread_join(parser->listenthread, NULL);
#endif
}


void ArgusGenerateCorrelateStruct(struct ArgusRecordStruct *);
void ArgusGenerateV3CorrelateStruct(struct ArgusRecordStruct *);

struct ArgusRecord *
ArgusGenerateRecord (struct ArgusRecordStruct *rec, unsigned char state, char *buf, int vers)
{
   struct ArgusRecord *retn = NULL;

   switch (vers) {
      case 3:  retn = (struct ArgusRecord *)ArgusGenerateV3Record (rec, state, buf); break;

      default:
      case 5:  retn = ArgusGenerateV5Record (rec, state, buf); break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusGenerateRecord (%p, %d, %p, %d) returns %p", rec, state, buf, vers, retn);
#endif 
   return (retn);
}

struct ArgusV3Record *
ArgusGenerateV3Record (struct ArgusRecordStruct *rec, unsigned char state, char *buf)
{
   struct ArgusV3Record *retn = (struct ArgusV3Record *) buf;
   unsigned int ind, dsrlen = 1, dsrindex = 0;
   unsigned int *dsrptr = (unsigned int *)retn + 1;
   int x, y, len = 0, type = 0;
   struct ArgusDSRHeader *dsr;
   struct cnamemem *cp;

   if (rec) {
      extern struct cnamemem  converttable[HASHNAMESIZE];
      char srcidbuf[256], *srcid = NULL;
      bzero(srcidbuf, 256);

      ArgusPrintSourceID(ArgusParser, srcidbuf, rec, 256);
      srcid = ArgusTrimString(srcidbuf);

      cp = check_cmem(converttable, (const u_char *) srcid);

      if (rec->correlates != NULL)
         ArgusGenerateV3CorrelateStruct(rec);
      
      switch (rec->hdr.type & 0xF0) {

// Here we will need to check if the MAR is a v3 or v5 record, and if v5, move the srcid around.

         case ARGUS_MAR: {
            if (rec->dsrs[0] != NULL) {
               struct ArgusMarStruct *man = (struct ArgusMarStruct *) &((struct ArgusRecord *) rec->dsrs[0])->ar_un.mar;

               if (man->major_version > ARGUS_VERSION_3) {
                  switch (retn->hdr.cause & 0xF0) {
                     case ARGUS_START:
                        man->argusid = ARGUS_V3_COOKIE;
                        break;

                     default:
                        if (((man->status & ARGUS_IDIS_UUID) == ARGUS_IDIS_UUID)  || ((man->status & ARGUS_IDIS_IPV6) == ARGUS_IDIS_IPV6)) {
                           if (cp != NULL) {
                              man->status &= ~(ARGUS_ID_INC_INF | ARGUS_IDIS_UUID | ARGUS_IDIS_IPV6 | ARGUS_IDIS_STRING | ARGUS_IDIS_INT | ARGUS_IDIS_IPV4);
                              man->status |= cp->type;
                              man->argusid = cp->addr.a_un.value;
                           } else {
                              man->argusid = man->value;
                           }
                        } else {
                           man->status &= ~ARGUS_ID_INC_INF;
                        }
                        break;
                  }
                  bzero(&man->pad, sizeof(man->pad));
                  man->thisid = 0;
                  man->major_version = ARGUS_VERSION_3;
               }

               retn->hdr.type   = ARGUS_MAR | ARGUS_VERSION_3;
               retn->hdr.cause &= ~ARGUS_SRC_RADIUM;

               bcopy ((char *)rec->dsrs[0], (char *) retn, rec->hdr.len * 4);
               retn->hdr = rec->hdr;

               if (state) {
                  retn->hdr.cause &= 0x0F;
                  retn->hdr.cause |= (state & 0xF0) | (retn->hdr.cause & 0x0F);
               }
            }
            break;
         }

// Events have a different structure, so we'll need to adjust the length for the legacy ArgusAddrStruct.
// We can copy all the rest around.


// Argus fars need their transport hdrs, Cor metric, and Correlate structs to be adjusted.

         case ARGUS_EVENT:
         case ARGUS_NETFLOW:
         case ARGUS_AFLOW:
         case ARGUS_FAR: {
            retn->hdr  = rec->hdr;
            retn->hdr.type  &= ~ARGUS_VERSION_5;
            retn->hdr.type  |= ARGUS_VERSION_3;

            dsrindex = rec->dsrindex;
            for (y = 0, ind = 1; (dsrindex && (y < ARGUSMAXDSRTYPE)); y++, ind <<= 1) {
               if ((dsr = rec->dsrs[y]) != NULL) {
                  len = ((dsr->type & ARGUS_IMMEDIATE_DATA) ? 1 :
                        ((dsr->subtype & ARGUS_LEN_16BITS)  ? dsr->argus_dsrvl16.len :
                                                              dsr->argus_dsrvl8.len));
                  switch (y) {
                     case ARGUS_TRANSPORT_INDEX: {
                        struct ArgusTransportStruct *trans = (struct ArgusTransportStruct *) dsr;
                        struct ArgusV3TransportStruct *dtrans = (struct ArgusV3TransportStruct *) dsrptr;
                        x = 0;

                        if (cp != NULL) {
                           bcopy(&cp->addr, &trans->srcid, sizeof(cp->addr));
                           trans->hdr.argus_dsrvl8.qual = cp->type;
                        } else {
                           trans->hdr.argus_dsrvl8.qual &= ~ARGUS_TYPE_INTERFACE;

                           switch (trans->hdr.argus_dsrvl8.qual) {

// Argus V3 doesn't support IPv6 of UUID srcid types, so these need to be converted to IPV4 or INTs.
// Assume that if it was an address, we should keep it is an address.  The values should be
// translated using some form of translation lookup, if the records existing srcid are these
// types.
                              case ARGUS_TYPE_IPV6: {
                                 trans->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                                 break;
                              }

                              case ARGUS_TYPE_UUID: {
                                 trans->hdr.argus_dsrvl8.qual = ARGUS_TYPE_INT;
                                 break;
                              }
                        }
                        }

                        *dsrptr++ = ((unsigned int *)dsr)[x++];
                        
                        if (trans->hdr.subtype & ARGUS_SRCID) {
                           switch (trans->hdr.argus_dsrvl8.qual) {
                              case ARGUS_TYPE_INT:
                              case ARGUS_TYPE_IPV4:
                              case ARGUS_TYPE_STRING:
                                 *dsrptr++ = ((unsigned int *)dsr)[x++];
                                 break;
                                 
                              case ARGUS_TYPE_IPV6:
                              case ARGUS_TYPE_UUID: {
                                 *dsrptr++ = ((unsigned int *)dsr)[x++];
                                 int z;
                                 for (z = 0; z < 4; z++) {
                                    *dsrptr++ = ((unsigned int *)dsr)[x++];
                                 }  
                                 break;
                              }  
                           }  
                        }  
                        if (trans->hdr.subtype & ARGUS_SEQ) {
                           *dsrptr++ = (unsigned int)trans->seqnum;
                           x++;
                        }  
                        dtrans->hdr.argus_dsrvl8.len = x;
                        len = x;
                        break;
                     }

                     case ARGUS_NETWORK_INDEX: {
                        struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) dsr;
                        switch (net->hdr.subtype) {
                           case ARGUS_TCP_INIT: {
                              struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *)dsr;
                              struct ArgusTCPObject *tcp = &net->net_union.tcp;
                              struct ArgusTCPInitStatus tcpinit;
                              tcpinit.status  = tcp->status;
                              tcpinit.seqbase = tcp->src.seqbase;
                              tcpinit.options = tcp->options;
                              tcpinit.win = tcp->src.win;
                              tcpinit.flags = tcp->src.flags;
                              tcpinit.winshift = tcp->src.winshift;

                              net->hdr.argus_dsrvl8.len = 5;

                              *dsrptr++ = *(unsigned int *)&net->hdr;
                              *dsrptr++ = ((unsigned int *)&tcpinit)[0];
                              *dsrptr++ = ((unsigned int *)&tcpinit)[1];
                              *dsrptr++ = ((unsigned int *)&tcpinit)[2];
                              *dsrptr++ = ((unsigned int *)&tcpinit)[3];
                              len = 5;
                              break;
                           }
                           case ARGUS_TCP_STATUS: {
                              struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *)dsr;
                              struct ArgusTCPObject *tcp = &net->net_union.tcp;
                              struct ArgusTCPStatus tcpstatus;
                              tcpstatus.status = tcp->status;
                              tcpstatus.src = tcp->src.flags;
                              tcpstatus.dst = tcp->dst.flags;
                              tcpstatus.pad[0] = 0;
                              tcpstatus.pad[1] = 0;
                              net->hdr.argus_dsrvl8.len = 3;
                              *dsrptr++ = *(unsigned int *)&net->hdr;
                              *dsrptr++ = ((unsigned int *)&tcpstatus)[0];
                              *dsrptr++ = ((unsigned int *)&tcpstatus)[1];
                              len = 3;
                              break;
                           }

                           case ARGUS_TCP_PERF:
                           default: {
                              for (x = 0; x < len; x++)
                                 *dsrptr++ = ((unsigned int *)dsr)[x];
                              break;
                           }
                        }
                        break;
                     }

                     case ARGUS_AGR_INDEX: {
                        struct ArgusAgrStruct *agr = (struct ArgusAgrStruct *) dsr;
                        if ((ArgusParser->ArgusAggregator) != NULL)  {
                           if (ArgusParser->ArgusAggregator->RaMetricFetchAlgorithm == ArgusFetchDuration) {
                              if (agr->count == 1) {
                                 len = 0;
                                 break;
                              }
                           }
                        }
// Deliberately fall through
                     }

                     default:
                        for (x = 0; x < len; x++)
                           *dsrptr++ = ((unsigned int *)rec->dsrs[y])[x];
                        break;

                     case ARGUS_TIME_INDEX: {
                        struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *) rec->dsrs[ARGUS_METRIC_INDEX];
                        struct ArgusTimeObject *dtime = (struct ArgusTimeObject *) dsr;
                        struct ArgusTimeObject *dsrtime = (struct ArgusTimeObject *) dsrptr;
                        unsigned char subtype = 0;
                        long long dur = RaGetuSecDuration(rec);
                        unsigned char tlen = 1;
                        int cnt = 0;

                        if (dtime->src.start.tv_sec > 0)
                           subtype |= ARGUS_TIME_SRC_START;
                        if (dtime->src.end.tv_sec > 0) 
                           subtype |= ARGUS_TIME_SRC_END;

                        if ((subtype & ARGUS_TIME_SRC_START) && (subtype & ARGUS_TIME_SRC_END)) {
                           if ((dtime->src.start.tv_sec  == dtime->src.end.tv_sec) &&
                               (dtime->src.start.tv_usec == dtime->src.end.tv_usec))
                              subtype &= ~ARGUS_TIME_SRC_END;
                        }

                        if (dtime->dst.start.tv_sec > 0) 
                           subtype |= ARGUS_TIME_DST_START;
                        if (dtime->dst.end.tv_sec > 0) 
                           subtype |= ARGUS_TIME_DST_END;

                        if ((subtype & ARGUS_TIME_DST_START) && (subtype & ARGUS_TIME_DST_END)) {
                           if ((dtime->dst.start.tv_sec  == dtime->dst.end.tv_sec) &&
                               (dtime->dst.start.tv_usec == dtime->dst.end.tv_usec))
                              subtype &= ~ARGUS_TIME_DST_END;
                        }

                        if (metric && (metric->src.pkts == 0))
                           subtype &= ~(ARGUS_TIME_SRC_START | ARGUS_TIME_SRC_END);

                        if (metric && (metric->dst.pkts == 0))
                           subtype &= ~(ARGUS_TIME_DST_START | ARGUS_TIME_DST_END);

                        for (x = 0; x < 4; x++)
                           if (subtype & (ARGUS_TIME_SRC_START << x)) 
                              cnt++;

                        if (cnt && (dtime->hdr.argus_dsrvl8.qual != ARGUS_TYPE_UTC_NANOSECONDS)) {
                           if (cnt == 1) 
                              subtype |= ARGUS_TIME_ABSOLUTE_TIMESTAMP;
                           else if (dur > 1000000000)
                              subtype |= ARGUS_TIME_ABSOLUTE_RANGE;
                           else
                              subtype |= ARGUS_TIME_RELATIVE_RANGE;
                        } else {
                           subtype &= ~ARGUS_TIME_RELATIVE_TIMESTAMP;
                           subtype |= ARGUS_TIME_ABSOLUTE_TIMESTAMP;
                        }

                        dtime->hdr.subtype = subtype;

//  We'd like to use relative uSec or nSec timestamps if there are more
//  than one timestamp in the record. ARGUS_TIME_RELATIVE_TIMESTAMP
//  So lets test uSec deltas, and report for time.

//#define ARGUS_TIME_ABSOLUTE_TIMESTAMP           0x01    // All time indicators are 64-bit sec, usec values, implies more than 2
//#define ARGUS_TIME_ABSOLUTE_RANGE               0x02    // All timestamp are absolute, and the second timestamp is the flow range
//#define ARGUS_TIME_ABSOLUTE_RELATIVE_RANGE      0x03    // First timestamp is absolute, the second indicator is a range offset
//#define ARGUS_TIME_RELATIVE_TIMESTAMP           0x04    // First timestamp is absolute, all others are relative, uSec or nSec
//#define ARGUS_TIME_RELATIVE_RANGE               0x05    // First timestamp is absolute, only one other value is flow range, uSec or nSec

                      
                        if (subtype & ARGUS_TIME_RELATIVE_RANGE) {
                           *dsrptr++ = *(unsigned int *)dsr;

                           if (subtype & ARGUS_TIME_SRC_START) {         // assume at this point that all indicators are reasonable
                              long long stime  = (dtime->src.start.tv_sec * 1000000L) + dtime->src.start.tv_usec;

                              *dsrptr++ = dtime->src.start.tv_sec;    // if there is not a src start, then there is not a src end
                              *dsrptr++ = dtime->src.start.tv_usec;
                              tlen += 2;

                              for (x = 1; x < 4; x++) {
                                 int mask = (ARGUS_TIME_SRC_START << x);
                                 if (subtype & mask) {
                                    switch (mask) {
                                       case ARGUS_TIME_SRC_END: {
                                          long long send = (dtime->src.end.tv_sec * 1000000L) + dtime->src.end.tv_usec;
                                          int value = send - stime;
                                          *dsrptr++ = value;
                                          tlen += 1;
                                          break;
                                       }
                                       case ARGUS_TIME_DST_START: {
                                          long long dstart = (dtime->dst.start.tv_sec * 1000000L) + dtime->dst.start.tv_usec;
                                          int value = dstart - stime;
                                          *dsrptr++ = value;
                                          tlen += 1;
                                          break;
                                       }
                                       case ARGUS_TIME_DST_END: {
                                          long long dend = (dtime->dst.end.tv_sec * 1000000L) + dtime->dst.end.tv_usec;
                                          int value = dend - stime;
                                          *dsrptr++ = value;
                                          tlen += 1;
                                          break;
                                       }
                                    }
                                 }
                              }

                           } else {
                              if (subtype & ARGUS_TIME_DST_START) {         // assume its just dst start and possibly end.
                                 *dsrptr++ = dtime->dst.start.tv_sec;
                                 *dsrptr++ = dtime->dst.start.tv_usec;
                                 tlen += 2;

                                 if (subtype & ARGUS_TIME_DST_END) {
                                    *dsrptr++ = dur;  // the dur at this point is the difference
                                    tlen += 1;
                                 }
                              }
                           }

                        } else {
                           *dsrptr++ = *(unsigned int *)&dtime->hdr;
                           
                           for (x = 0; x < 4; x++) {
                              if (subtype & (ARGUS_TIME_SRC_START << x)) {
                                 switch (ARGUS_TIME_SRC_START << x) {
                                    case ARGUS_TIME_SRC_START:
                                       *dsrptr++ = dtime->src.start.tv_sec;
                                       *dsrptr++ = dtime->src.start.tv_usec;
                                       tlen += 2;
                                       break;
                                    case ARGUS_TIME_SRC_END:
                                       *dsrptr++ = dtime->src.end.tv_sec;
                                       *dsrptr++ = dtime->src.end.tv_usec;
                                       tlen += 2;
                                       break;
                                    case ARGUS_TIME_DST_START:
                                       *dsrptr++ = dtime->dst.start.tv_sec;
                                       *dsrptr++ = dtime->dst.start.tv_usec;
                                       tlen += 2;
                                       break;
                                    case ARGUS_TIME_DST_END:
                                       *dsrptr++ = dtime->dst.end.tv_sec;
                                       *dsrptr++ = dtime->dst.end.tv_usec;
                                       tlen += 2;
                                       break;
                                 }
                              }
                           }
                        }

                        dsrtime->hdr.argus_dsrvl8.len = tlen;
                        len = tlen;
                        break;
                     }

                     case ARGUS_METRIC_INDEX: {
                        struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *) dsr;

                        if (((metric->src.pkts + metric->dst.pkts) > 0) ||
                            ((metric->src.bytes + metric->dst.bytes) > 0)) {
                           if (((metric->src.pkts) && (metric->dst.pkts)) ||
                               ((metric->src.bytes) && (metric->dst.bytes))) {
                              if ((0xFF >= metric->src.pkts)  && (0xFF >= metric->dst.pkts) &&
                                  (0xFF >= metric->src.bytes) && (0xFF >= metric->dst.bytes))
                                 type = ARGUS_SRCDST_BYTE;
                              else
                              if ((0xFFFF >= metric->src.bytes) && (0xFFFF >= metric->dst.bytes))
                                 type = ARGUS_SRCDST_SHORT;
                              else
                              if ((0xFFFFFFFF >= metric->src.bytes) && (0xFFFFFFFF >= metric->dst.bytes))
                                 type = ARGUS_SRCDST_INT;
                              else
                                 type = ARGUS_SRCDST_LONGLONG;

                           } else {
                              if ((metric->src.pkts) || (metric->src.bytes)) {
                                 if (0xFFFF >= metric->src.bytes)
                                    type = ARGUS_SRC_SHORT;
                                 else
                                 if (0xFFFFFFFF >= metric->src.bytes)
                                    type = ARGUS_SRC_INT;
                                 else
                                    type = ARGUS_SRC_LONGLONG;
                              } else {
                                 if (0xFFFF >= metric->dst.bytes)
                                    type = ARGUS_DST_SHORT;
                                 else
                                 if (0xFFFFFFFF >= metric->dst.bytes)
                                    type = ARGUS_DST_INT;
                                 else
                                    type = ARGUS_DST_LONGLONG;
                              }
                           }
                        } else {
                           type = ARGUS_SRCDST_BYTE;
                        }

                        dsr = (struct ArgusDSRHeader *)dsrptr;
                        dsr->type    = ARGUS_METER_DSR;

                        if (metric->src.appbytes || metric->dst.appbytes) {
                           dsr->subtype = ARGUS_METER_PKTS_BYTES_APP;
                           switch (type) {
                              case ARGUS_SRCDST_BYTE:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned char *)(dsr + 1))[0] = (unsigned char) metric->src.pkts;
                                 ((unsigned char *)(dsr + 1))[1] = (unsigned char) metric->src.bytes;
                                 ((unsigned char *)(dsr + 1))[2] = (unsigned char) metric->src.appbytes;
                                 ((unsigned char *)(dsr + 1))[3] = (unsigned char) metric->dst.pkts;
                                 ((unsigned char *)(dsr + 1))[4] = (unsigned char) metric->dst.bytes;
                                 ((unsigned char *)(dsr + 1))[5] = (unsigned char) metric->dst.appbytes;
                                 ((unsigned char *)(dsr + 1))[6] = 0;
                                 ((unsigned char *)(dsr + 1))[7] = 0;
                                 break;
                              case ARGUS_SRCDST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 4;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->src.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->src.bytes);
                                 ((unsigned short *)(dsr + 1))[2] = ((unsigned short) metric->src.appbytes);
                                 ((unsigned short *)(dsr + 1))[3] = ((unsigned short) metric->dst.pkts);
                                 ((unsigned short *)(dsr + 1))[4] = ((unsigned short) metric->dst.bytes);
                                 ((unsigned short *)(dsr + 1))[5] = ((unsigned short) metric->dst.appbytes);
                                 break;
                              case ARGUS_SRCDST_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 7;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->src.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->src.bytes);
                                 ((unsigned int *)(dsr + 1))[2] = ((unsigned int) metric->src.appbytes);
                                 ((unsigned int *)(dsr + 1))[3] = ((unsigned int) metric->dst.pkts);
                                 ((unsigned int *)(dsr + 1))[4] = ((unsigned int) metric->dst.bytes);
                                 ((unsigned int *)(dsr + 1))[5] = ((unsigned int) metric->dst.appbytes);
                                 break;
                              case ARGUS_SRCDST_LONGLONG: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 13;
                                 long long *ptr = (long long *)(dsr + 1);

                                 bcopy(&metric->src.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->src.bytes,    ptr++, sizeof(long long));
                                 bcopy(&metric->src.appbytes, ptr++, sizeof(long long));
                                 bcopy(&metric->dst.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->dst.bytes,    ptr++, sizeof(long long));
                                 bcopy(&metric->dst.appbytes, ptr++, sizeof(long long));
                                 break;
                              }

                              case ARGUS_SRC_BYTE:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned char *)(dsr + 1))[0] = ((unsigned char) metric->src.pkts);
                                 ((unsigned char *)(dsr + 1))[1] = ((unsigned char) metric->src.bytes);
                                 ((unsigned char *)(dsr + 1))[2] = ((unsigned char) metric->src.appbytes);
                                 ((unsigned char *)(dsr + 1))[3] = 0;
                                 break;
                              case ARGUS_SRC_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->src.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->src.bytes);
                                 ((unsigned short *)(dsr + 1))[2] = ((unsigned short) metric->src.appbytes);
                                 ((unsigned short *)(dsr + 1))[3] = 0;
                                 break;
                              case ARGUS_SRC_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 4;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->src.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->src.bytes);
                                 ((unsigned int *)(dsr + 1))[2] = ((unsigned int) metric->src.appbytes);
                                 break;
                              case ARGUS_SRC_LONGLONG: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 7;
                                 long long *ptr = (long long *)(dsr + 1);

                                 bcopy(&metric->src.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->src.bytes,    ptr++, sizeof(long long));
                                 bcopy(&metric->src.appbytes, ptr++, sizeof(long long));
                                 break;
                              }

                              case ARGUS_DST_BYTE:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned char *)(dsr + 1))[0] = ((unsigned char) metric->dst.pkts);
                                 ((unsigned char *)(dsr + 1))[1] = ((unsigned char) metric->dst.bytes);
                                 ((unsigned char *)(dsr + 1))[2] = ((unsigned char) metric->dst.appbytes);
                                 ((unsigned char *)(dsr + 1))[3] = 0;
                                 break;
                              case ARGUS_DST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->dst.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->dst.bytes);
                                 ((unsigned short *)(dsr + 1))[2] = ((unsigned short) metric->dst.appbytes);
                                 ((unsigned short *)(dsr + 1))[3] = 0;
                                 break;
                              case ARGUS_DST_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 4;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->dst.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->dst.bytes);
                                 ((unsigned int *)(dsr + 1))[2] = ((unsigned int) metric->dst.appbytes);
                                 break;
                              case ARGUS_DST_LONGLONG: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 7;
                                 long long *ptr = (long long *)(dsr + 1);

                                 bcopy(&metric->dst.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->dst.bytes,    ptr++, sizeof(long long));
                                 bcopy(&metric->dst.appbytes, ptr++, sizeof(long long));
                                 break;
                              }
                           }
                        } else {
                           dsr->subtype = ARGUS_METER_PKTS_BYTES;
                           switch (type) {
                              case ARGUS_SRCDST_BYTE:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned char *)(dsr + 1))[0] = (unsigned char) metric->src.pkts;
                                 ((unsigned char *)(dsr + 1))[1] = (unsigned char) metric->src.bytes;
                                 ((unsigned char *)(dsr + 1))[2] = (unsigned char) metric->dst.pkts;
                                 ((unsigned char *)(dsr + 1))[3] = (unsigned char) metric->dst.bytes;
                                 break;
                              case ARGUS_SRCDST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->src.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->src.bytes);
                                 ((unsigned short *)(dsr + 1))[2] = ((unsigned short) metric->dst.pkts);
                                 ((unsigned short *)(dsr + 1))[3] = ((unsigned short) metric->dst.bytes);
                                 break;
                              case ARGUS_SRCDST_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 5;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->src.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->src.bytes);
                                 ((unsigned int *)(dsr + 1))[2] = ((unsigned int) metric->dst.pkts);
                                 ((unsigned int *)(dsr + 1))[3] = ((unsigned int) metric->dst.bytes);
                                 break;
                              case ARGUS_SRCDST_LONGLONG: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 9;
                                 long long *ptr = (long long *)(dsr + 1);

                                 bcopy(&metric->src.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->src.bytes,    ptr++, sizeof(long long));
                                 bcopy(&metric->dst.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->dst.bytes,    ptr++, sizeof(long long));
                                 break;
                              }

                              case ARGUS_SRC_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->src.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->src.bytes);
                                 break;
                              case ARGUS_SRC_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->src.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->src.bytes);
                                 break;
                              case ARGUS_SRC_LONGLONG: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 5;
                                 long long *ptr = (long long *)(dsr + 1);

                                 bcopy(&metric->src.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->src.bytes,    ptr++, sizeof(long long));
                                 break;
                              }

                              case ARGUS_DST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->dst.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->dst.bytes);
                                 break;
                              case ARGUS_DST_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->dst.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->dst.bytes);
                                 break;
                              case ARGUS_DST_LONGLONG: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 5;
                                 long long *ptr = (long long *)(dsr + 1);

                                 bcopy(&metric->dst.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->dst.bytes,    ptr++, sizeof(long long));
                                 break;
                              }
                           }
                        }
                        len     = dsr->argus_dsrvl8.len;
                        dsrptr += len;
                        break;
                     }

                     case ARGUS_PSIZE_INDEX: {
                        struct ArgusPacketSizeStruct *psize  = (struct ArgusPacketSizeStruct *) dsr;

                        if ((psize->src.psizemax > 0) && (psize->dst.psizemax > 0))
                           type = ARGUS_SRCDST_SHORT;
                        else
                        if (psize->src.psizemax > 0)
                           type = ARGUS_SRC_SHORT;
                        else
                        if (psize->dst.psizemax > 0)
                           type = ARGUS_DST_SHORT;
                        else
                           type = 0;

                        if (type) {
                           unsigned char value = 0, tmp = 0, *ptr;
                           int max, i;
//                         int cnt;

                           dsr = (struct ArgusDSRHeader *)dsrptr;
                           dsr->type    = ARGUS_PSIZE_DSR;

                           switch (type) {
                              case ARGUS_SRCDST_SHORT:
                                 dsr->subtype = ARGUS_PSIZE_SRC_MAX_MIN | ARGUS_PSIZE_DST_MAX_MIN;
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned short *)(dsr + 1))[0] = psize->src.psizemin;
                                 ((unsigned short *)(dsr + 1))[1] = psize->src.psizemax;
                                 ((unsigned short *)(dsr + 1))[2] = psize->dst.psizemin;
                                 ((unsigned short *)(dsr + 1))[3] = psize->dst.psizemax;
                                 break;

                              case ARGUS_SRC_SHORT:
                                 dsr->subtype = ARGUS_PSIZE_SRC_MAX_MIN;
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned short *)(dsr + 1))[0] = psize->src.psizemin;
                                 ((unsigned short *)(dsr + 1))[1] = psize->src.psizemax;
                                 break;

                              case ARGUS_DST_SHORT:
                                 dsr->subtype = ARGUS_PSIZE_DST_MAX_MIN;
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned short *)(dsr + 1))[0] = psize->dst.psizemin;
                                 ((unsigned short *)(dsr + 1))[1] = psize->dst.psizemax;
                                 break;

                              default:
                                 break;
                           }

                           if (dsr->subtype & ARGUS_PSIZE_SRC_MAX_MIN) {
                              ptr = (unsigned char *)(dsr + dsr->argus_dsrvl8.len);

//                            for (cnt = 0, i = 0; i < 8; i++)
//                               cnt += psize->src.psize[i];

                              dsr->subtype |= ARGUS_PSIZE_HISTO;

                              dsr->argus_dsrvl8.len++;
                              *((unsigned int *)(dsr + dsr->argus_dsrvl8.len)) = 0;

                              for (i = 0, max = 0; i < 8; i++)
                                 if (max < psize->src.psize[i])
                                    max = psize->src.psize[i];

                              for (i = 0; i < 8; i++) {
                                 if ((tmp = psize->src.psize[i])) {
                                    if (i & 0x01) {
                                       if (max > 15)
                                         tmp = ((tmp * 15)/max);
                                       if (!tmp) tmp++;
                                       value |= tmp;
                                       *ptr++ = value;
                                    } else {
                                       if (max > 15)
                                         tmp = ((tmp * 15)/max);
                                       if (!tmp) tmp++;
                                       value = (tmp << 4);
                                    }
                                 } else {
                                    if (i & 0x01) {
                                       value &= 0xF0;
                                       *ptr++ = value;
                                    } else {
                                       value = 0;
                                    }
                                 }
                              }
                           }

                           if (dsr->subtype & ARGUS_PSIZE_DST_MAX_MIN) {
                              ptr = (unsigned char *)(dsr + dsr->argus_dsrvl8.len);

//                            for (cnt = 0, i = 0; i < 8; i++)
//                               cnt += psize->dst.psize[i];

                              dsr->subtype |= ARGUS_PSIZE_HISTO;

                              dsr->argus_dsrvl8.len++;
                              *((unsigned int *)(dsr + dsr->argus_dsrvl8.len)) = 0;

                              for (i = 0, max = 0; i < 8; i++)
                                 if (max < psize->dst.psize[i])
                                    max = psize->dst.psize[i];

                              for (i = 0; i < 8; i++) {
                                 if ((tmp = psize->dst.psize[i])) {
                                    if (i & 0x01) {
                                       if (max > 15)
                                         tmp = ((tmp * 15)/max);
                                       if (!tmp) tmp++;
                                       value |= tmp;
                                       *ptr++ = value;
                                    } else {
                                       if (max > 15)
                                         tmp = ((tmp * 15)/max);
                                       if (!tmp) tmp++;
                                       value = (tmp << 4);
                                    }
                                 } else {
                                    if (i & 0x01) {
                                       value &= 0xF0;
                                       *ptr++ = value;
                                    } else {
                                       value = 0;
                                    }
                                 }
                              }
                           }

                           dsr->argus_dsrvl8.qual = type;
                           len = dsr->argus_dsrvl8.len;
                           dsrptr += len;
                        } else
                           len = 0;

                        break;
                     }

                     case ARGUS_MPLS_INDEX: {
                        struct ArgusMplsStruct *mpls  = (struct ArgusMplsStruct *) dsr;
                        struct ArgusMplsStruct *tmpls = (struct ArgusMplsStruct *) dsrptr;
                        unsigned char subtype = tmpls->hdr.subtype & ~(ARGUS_MPLS_SRC_LABEL | ARGUS_MPLS_DST_LABEL);

                        *dsrptr++ = *(unsigned int *)dsr;
                        len = 1;

                        if (((mpls->hdr.argus_dsrvl8.qual & 0xF0) >> 4) > 0) {
                           subtype |= ARGUS_MPLS_SRC_LABEL;
                           *dsrptr++ = mpls->slabel;
                           len++;
                        }
                        if (((mpls->hdr.argus_dsrvl8.qual & 0x0F)) > 0) {
                           subtype |= ARGUS_MPLS_DST_LABEL;
                           *dsrptr++ = mpls->dlabel;
                           len++;
                        }
                        tmpls->hdr.subtype = subtype;
                        tmpls->hdr.argus_dsrvl8.len = len;
                        break;
                     }

                     case ARGUS_JITTER_INDEX: {
#if defined(HAVE_XDR)
                        struct ArgusJitterStruct *jitter = (struct ArgusJitterStruct *) dsr;
                        struct ArgusJitterStruct *tjit   = (struct ArgusJitterStruct *) dsrptr;

                        int size = (sizeof(struct ArgusStatObject) + 3) / 4;
                        XDR xdrbuf, *xdrs = &xdrbuf;

                        unsigned char value = 0, tmp = 0, *ptr;
                        unsigned int fdist = 0;
                        int max, i;
//                      int cnt;

                        *dsrptr++ = *(unsigned int *)dsr;
                        tjit->hdr.argus_dsrvl8.len = 1;
                        
                        if (jitter->hdr.argus_dsrvl8.qual & ARGUS_SRC_ACTIVE_JITTER) {
                           xdrmem_create(xdrs, (char *)dsrptr, sizeof(struct ArgusStatObject), XDR_ENCODE);
                           xdr_int(xdrs,   &jitter->src.act.n);
                           xdr_float(xdrs, &jitter->src.act.minval);
                           xdr_float(xdrs, &jitter->src.act.meanval);
                           xdr_float(xdrs, &jitter->src.act.stdev);
                           xdr_float(xdrs, &jitter->src.act.maxval);

                           switch (jitter->hdr.subtype & (ARGUS_HISTO_EXP | ARGUS_HISTO_LINEAR)) {
                              case ARGUS_HISTO_EXP: {
                                 value = 0;
                                 ptr = (unsigned char *)&fdist;
//                               for (cnt = 0, i = 0; i < 8; i++)
//                                  cnt += jitter->src.act.fdist[i];

                                 for (i = 0, max = 0; i < 8; i++)
                                    if (max < jitter->src.act.fdist[i])
                                       max = jitter->src.act.fdist[i];

                                 for (i = 0; i < 8; i++) {
                                    if ((tmp = jitter->src.act.fdist[i])) {
                                       if (i & 0x01) {
                                          if (max > 15)
                                            tmp = ((tmp * 15)/max);
                                          if (!tmp) tmp++;
                                          value |= tmp;
                                          *ptr++ = value;
                                       } else {
                                          if (max > 15)
                                            tmp = ((tmp * 15)/max);
                                          if (!tmp) tmp++;
                                          value = (tmp << 4);
                                       }
                                    } else {
                                       if (i & 0x01) {
                                          value &= 0xF0;
                                          *ptr++ = value;
                                       } else {
                                          value = 0;
                                       }
                                    }
                                 }
                                 xdr_u_int(xdrs, &fdist);
                                 dsrptr += size;
                                 tjit->hdr.argus_dsrvl8.len += size;
                                 break;
                              }

                              default: 
                              case ARGUS_HISTO_LINEAR: 
                                 dsrptr += 5;
                                 tjit->hdr.argus_dsrvl8.len += 5;
                                 break;
                           }
                        }

                        if (jitter->hdr.argus_dsrvl8.qual & ARGUS_SRC_IDLE_JITTER) {
                           xdrmem_create(xdrs, (char *)dsrptr, sizeof(struct ArgusStatObject), XDR_ENCODE);
                           xdr_int(xdrs, &jitter->src.idle.n);
                           xdr_float(xdrs, &jitter->src.idle.minval);
                           xdr_float(xdrs, &jitter->src.idle.meanval);
                           xdr_float(xdrs, &jitter->src.idle.stdev);
                           xdr_float(xdrs, &jitter->src.idle.maxval);

                           switch (jitter->hdr.subtype & (ARGUS_HISTO_EXP | ARGUS_HISTO_LINEAR)) {
                              case ARGUS_HISTO_EXP: {
                                 value = 0;
                                 ptr = (unsigned char *)&fdist;
//                               for (cnt = 0, i = 0; i < 8; i++)
//                                  cnt += jitter->src.idle.fdist[i];

                                 for (i = 0, max = 0; i < 8; i++)
                                    if (max < jitter->src.idle.fdist[i])
                                       max = jitter->src.idle.fdist[i];

                                 for (i = 0; i < 8; i++) {
                                    if ((tmp = jitter->src.idle.fdist[i])) {
                                       if (i & 0x01) {
                                          if (max > 15)
                                            tmp = ((tmp * 15)/max);
                                          if (!tmp) tmp++;
                                          value |= tmp;
                                          *ptr++ = value;
                                       } else {
                                          if (max > 15)
                                            tmp = ((tmp * 15)/max);
                                          if (!tmp) tmp++;
                                          value = (tmp << 4);
                                       }
                                    } else {
                                       if (i & 0x01) {
                                          value &= 0xF0;
                                          *ptr++ = value;
                                       } else {
                                          value = 0;
                                       }
                                    }
                                 }

                                 xdr_u_int(xdrs, &fdist);
                                 dsrptr += size;
                                 tjit->hdr.argus_dsrvl8.len += size;
                                 break;
                              }

                              default: 
                              case ARGUS_HISTO_LINEAR: {
                                 dsrptr += 5;
                                 tjit->hdr.argus_dsrvl8.len += 5;
                                 break;
                              }
                           }
                        }
                        if (jitter->hdr.argus_dsrvl8.qual & ARGUS_DST_ACTIVE_JITTER) {
                           xdrmem_create(xdrs, (char *)dsrptr, sizeof(struct ArgusStatObject), XDR_ENCODE);
                           xdr_int(xdrs, &jitter->dst.act.n);
                           xdr_float(xdrs, &jitter->dst.act.minval);
                           xdr_float(xdrs, &jitter->dst.act.meanval);
                           xdr_float(xdrs, &jitter->dst.act.stdev);
                           xdr_float(xdrs, &jitter->dst.act.maxval);
                           switch (jitter->hdr.subtype & (ARGUS_HISTO_EXP | ARGUS_HISTO_LINEAR)) {
                              case ARGUS_HISTO_EXP: {
                                 value = 0;
                                 ptr = (unsigned char *)&fdist;
//                               for (cnt = 0, i = 0; i < 8; i++)
//                                  cnt += jitter->dst.act.fdist[i];

                                 for (i = 0, max = 0; i < 8; i++)
                                    if (max < jitter->dst.act.fdist[i])
                                       max = jitter->dst.act.fdist[i];

                                 for (i = 0; i < 8; i++) {
                                    if ((tmp = jitter->dst.act.fdist[i])) {
                                       if (i & 0x01) {
                                          if (max > 15)
                                            tmp = ((tmp * 15)/max);
                                          if (!tmp) tmp++;
                                          value |= tmp;
                                          *ptr++ = value;
                                       } else {
                                          if (max > 15)
                                            tmp = ((tmp * 15)/max);
                                          if (!tmp) tmp++;
                                          value = (tmp << 4);
                                       }
                                    } else {
                                       if (i & 0x01) {
                                          value &= 0xF0;
                                          *ptr++ = value;
                                       } else {
                                          value = 0;
                                       }
                                    }
                                 }

                                 xdr_u_int(xdrs, &fdist);
                                 dsrptr += size;
                                 tjit->hdr.argus_dsrvl8.len += size;
                                 break;
                              }

                              default:
                              case ARGUS_HISTO_LINEAR: {
                                 dsrptr += 5;
                                 tjit->hdr.argus_dsrvl8.len += 5;
                                 break;
                              }
                           }
                        }
                        if (jitter->hdr.argus_dsrvl8.qual & ARGUS_DST_IDLE_JITTER) {
                           xdrmem_create(xdrs, (char *)dsrptr, sizeof(struct ArgusStatObject), XDR_ENCODE);
                           xdr_int(xdrs, &jitter->dst.idle.n);
                           xdr_float(xdrs, &jitter->dst.idle.minval);
                           xdr_float(xdrs, &jitter->dst.idle.meanval);
                           xdr_float(xdrs, &jitter->dst.idle.stdev);
                           xdr_float(xdrs, &jitter->dst.idle.maxval);
                           switch (jitter->hdr.subtype & (ARGUS_HISTO_EXP | ARGUS_HISTO_LINEAR)) {
                              case ARGUS_HISTO_EXP: {
                                 value = 0;
                                 ptr = (unsigned char *)&fdist;
//                               for (cnt = 0, i = 0; i < 8; i++)
//                                  cnt += jitter->dst.idle.fdist[i];

                                 for (i = 0, max = 0; i < 8; i++)
                                    if (max < jitter->dst.idle.fdist[i])
                                       max = jitter->dst.idle.fdist[i];

                                 for (i = 0; i < 8; i++) {
                                    if ((tmp = jitter->dst.idle.fdist[i])) {
                                       if (i & 0x01) {
                                          if (max > 15)
                                            tmp = ((tmp * 15)/max);
                                          if (!tmp) tmp++;
                                          value |= tmp;
                                          *ptr++ = value;
                                       } else {
                                          if (max > 15)
                                            tmp = ((tmp * 15)/max);
                                          if (!tmp) tmp++;
                                          value = (tmp << 4);
                                       }
                                    } else {
                                       if (i & 0x01) {
                                          value &= 0xF0;
                                          *ptr++ = value;
                                       } else {
                                          value = 0;
                                       }
                                    }
                                 }

                                 xdr_u_int(xdrs, &fdist);
                                 dsrptr += size;
                                 tjit->hdr.argus_dsrvl8.len += size;
                                 break;
                              }

                              default:
                              case ARGUS_HISTO_LINEAR: {
                                 dsrptr += 5;
                                 tjit->hdr.argus_dsrvl8.len += 5;
                                 break;
                              }
                           }
                        }

                        len = tjit->hdr.argus_dsrvl8.len;
#endif
                        break;
                     }

                     case ARGUS_IPATTR_INDEX: {
                        struct ArgusIPAttrStruct *attr  = (struct ArgusIPAttrStruct *) dsr;
                        struct ArgusIPAttrStruct *tattr = (struct ArgusIPAttrStruct *) dsrptr;

                        *dsrptr++ = *(unsigned int *)dsr;
                        len = 1;

                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC) {
                           *dsrptr++ = *(unsigned int *)&attr->src;
                           len++;
                        }
                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC_OPTIONS) {
                           *dsrptr++ = attr->src.options;
                           len++;
                        }
                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST) {
                           *dsrptr++ = *(unsigned int *)&attr->dst;
                           len++;
                        }
                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST_OPTIONS) {
                           *dsrptr++ = attr->dst.options;
                           len++;
                        }
                        tattr->hdr.argus_dsrvl8.len = len;
                        break;
                     }

                     case ARGUS_LABEL_INDEX: {
                        struct ArgusLabelStruct *label  = (struct ArgusLabelStruct *) dsr;
                        int labelen = 0, slen = 0;

                        if (label->l_un.label != NULL)
                           slen = strlen(label->l_un.label);
                        
                        if (slen > 0) {
                           labelen = (label->hdr.argus_dsrvl8.len - 1) * 4;
                           *dsrptr++ = *(unsigned int *)dsr;
                           bcopy ((char *)label->l_un.label, (char *)dsrptr, slen);
                           if (labelen > slen)
                              bzero(&((char *)dsrptr)[slen], labelen - slen);
                           dsrptr += (labelen + 3)/4;
                           len = 1 + ((labelen + 3)/4);
                        } else
                           len = 0;
                        break;
                     }
                  }

                  dsrlen += len;
                  dsrindex &= ~ind;
               }
            }

            if (retn->hdr.len != 0) {
               if (!(rec->status & ARGUS_RECORD_MODIFIED) && (retn->hdr.len != dsrlen)) {
                  if (retn->hdr.len > dsrlen) {
                     int i, cnt = retn->hdr.len - dsrlen;
#ifdef ARGUSDEBUG
                     ArgusDebug (6, "ArgusGenerateRecord (%p, %d) old len %d new len %d\n", 
                        rec, state, retn->hdr.len * 4, dsrlen * 4);
#endif 
                     for (i = 0; i < cnt; i++) {
                       dsr = (void *) dsrptr++;
                       dsr->type = 0; dsr->subtype = 0;
                       dsr->argus_dsrvl8.qual = 0;
                       dsr->argus_dsrvl8.len = 1;
                       dsrlen++;
                     }
                  }
               }
            }

            retn->hdr.len = dsrlen;

            if (((char *)dsrptr - (char *)retn) != (dsrlen * 4))
               ArgusLog (LOG_ERR, "ArgusGenerateRecord: parse length error %d:%d", ((char *)dsrptr - (char *)retn), dsrlen);

            break;
         }

         default:
            retn = NULL;
            break;
      }
         
   } else {
      retn->hdr.type = ARGUS_MAR;
      retn->hdr.type  |= ARGUS_VERSION_3;
      retn->hdr.cause = state & 0xF0;
      retn->hdr.len = dsrlen;
   }
 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusGenerateV3Record (%p, %d) len %d\n", rec, state, dsrlen * 4);
#endif 
   return (retn);
}

unsigned int /* dwords */
ArgusGenerateV5SrcId(struct ArgusTransportStruct *trans, unsigned int *buf)
{
   struct ArgusTransportStruct *dtrans = (struct ArgusTransportStruct *)buf;
   unsigned int *dsrptr = buf;
   unsigned int x = 0;

   *dsrptr++ = ((unsigned int *)trans)[x++];

   if (trans->hdr.subtype & ARGUS_SRCID) {
      switch (trans->hdr.argus_dsrvl8.qual & ~ARGUS_TYPE_INTERFACE) {
         case ARGUS_TYPE_INT:
         case ARGUS_TYPE_IPV4:
         case ARGUS_TYPE_STRING:
            *dsrptr++ = ((unsigned int *)trans)[x++];
            break;

         case ARGUS_TYPE_IPV6:
         case ARGUS_TYPE_UUID: {
            int z;
            for (z = 0; z < 4; z++) {
               *dsrptr++ = ((unsigned int *)trans)[x++];
            }
            break;
         }
      }
      if (trans->hdr.argus_dsrvl8.qual & ARGUS_TYPE_INTERFACE) {
         bcopy(&trans->srcid.inf,  dsrptr++, sizeof(trans->srcid.inf));
         x++;
      }
   }
   if (trans->hdr.subtype & ARGUS_SEQ) {
      *dsrptr++ = (unsigned int)trans->seqnum;
      x++;
   }
   dtrans->hdr.argus_dsrvl8.len = x;
   return x;
}

struct ArgusRecord *
ArgusGenerateV5Record (struct ArgusRecordStruct *rec, unsigned char state, char *buf)
{
   struct ArgusRecord *retn = (struct ArgusRecord *) buf;
   unsigned int ind, dsrlen = 1, dsrindex = 0;
   unsigned int *dsrptr = (unsigned int *)retn + 1;
   int x, y, len = 0, type = 0;
   struct ArgusDSRHeader *dsr;

   if (rec) {
      if (rec->correlates != NULL)
         ArgusGenerateCorrelateStruct(rec);
      
      switch (rec->hdr.type & 0xF0) {
         case ARGUS_MAR: {
            if (rec->dsrs[0] != NULL) {
               bcopy ((char *)rec->dsrs[0], (char *) retn, rec->hdr.len * 4);
               retn->hdr = rec->hdr;
               if (state) {
                  retn->hdr.cause &= 0x0F;
                  retn->hdr.cause |= (state & 0xF0) | (retn->hdr.cause & 0x0F);
               }
            }
            break;
         }

         case ARGUS_EVENT:
         case ARGUS_NETFLOW:
         case ARGUS_AFLOW:
         case ARGUS_FAR: {
            retn->hdr  = rec->hdr;
            retn->hdr.type  |= ARGUS_VERSION;

            dsrindex = rec->dsrindex;
            for (y = 0, ind = 1; (dsrindex && (y < ARGUSMAXDSRTYPE)); y++, ind <<= 1) {
               if ((dsr = rec->dsrs[y]) != NULL) {
                  len = ((dsr->type & ARGUS_IMMEDIATE_DATA) ? 1 :
                        ((dsr->subtype & ARGUS_LEN_16BITS)  ? dsr->argus_dsrvl16.len :
                                                              dsr->argus_dsrvl8.len));
                  switch (y) {
                     case ARGUS_TRANSPORT_INDEX:
                        len = ArgusGenerateV5SrcId((struct ArgusTransportStruct *)dsr, dsrptr);
                        dsrptr += len;
                        break;

                     case ARGUS_NETWORK_INDEX: {
                        struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) dsr;
                        switch (net->hdr.subtype) {
                           case ARGUS_TCP_INIT: {
                              struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *)dsr;
                              struct ArgusTCPObject *tcp = &net->net_union.tcp;
                              struct ArgusTCPInitStatus tcpinit;
                              tcpinit.status  = tcp->status;
                              tcpinit.seqbase = tcp->src.seqbase;
                              tcpinit.options = tcp->options;
                              tcpinit.win = tcp->src.win;
                              tcpinit.flags = tcp->src.flags;
                              tcpinit.winshift = tcp->src.winshift;
                              tcpinit.maxseg = tcp->src.maxseg;

                              net->hdr.argus_dsrvl8.len = 6;

                              *dsrptr++ = *(unsigned int *)&net->hdr;
                              *dsrptr++ = ((unsigned int *)&tcpinit)[0];
                              *dsrptr++ = ((unsigned int *)&tcpinit)[1];
                              *dsrptr++ = ((unsigned int *)&tcpinit)[2];
                              *dsrptr++ = ((unsigned int *)&tcpinit)[3];
                              *dsrptr++ = ((unsigned int *)&tcpinit)[4];
                              len = 6;
                              break;
                           }
                           case ARGUS_TCP_STATUS: {
                              struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *)dsr;
                              struct ArgusTCPObject *tcp = &net->net_union.tcp;
                              struct ArgusTCPStatus tcpstatus;
                              tcpstatus.status = tcp->status;
                              tcpstatus.src = tcp->src.flags;
                              tcpstatus.dst = tcp->dst.flags;
                              tcpstatus.pad[0] = 0;
                              tcpstatus.pad[1] = 0;
                              net->hdr.argus_dsrvl8.len = 3;
                              *dsrptr++ = *(unsigned int *)&net->hdr;
                              *dsrptr++ = ((unsigned int *)&tcpstatus)[0];
                              *dsrptr++ = ((unsigned int *)&tcpstatus)[1];
                              len = 3;
                              break;
                           }

                           case ARGUS_TCP_PERF:
                           default: {
                              for (x = 0; x < len; x++)
                                 *dsrptr++ = ((unsigned int *)dsr)[x];
                              break;
                           }
                        }
                        break;
                     }

                     case ARGUS_AGR_INDEX: {
                        struct ArgusAgrStruct *agr = (struct ArgusAgrStruct *) dsr;
                        if ((ArgusParser->ArgusAggregator) != NULL)  {
                           if (ArgusParser->ArgusAggregator->RaMetricFetchAlgorithm == ArgusFetchDuration) {
                              if (agr->count == 1) {
                                 len = 0;
                                 break;
                              }
                           }
                        }
// Deliberately fall through
                     }

                     default:
                        for (x = 0; x < len; x++)
                           *dsrptr++ = ((unsigned int *)rec->dsrs[y])[x];
                        break;

                     case ARGUS_TIME_INDEX: {
                        struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *) rec->dsrs[ARGUS_METRIC_INDEX];
                        struct ArgusTimeObject *dtime = (struct ArgusTimeObject *) dsr;
                        struct ArgusTimeObject *dsrtime = (struct ArgusTimeObject *) dsrptr;
                        long long dur = RaGetuSecDuration(rec);
                        unsigned char subtype = 0;
                        unsigned char tlen = 1;
                        int cnt = 0;

                        if (dtime->src.start.tv_sec > 0)
                           subtype |= ARGUS_TIME_SRC_START;
                        if (dtime->src.end.tv_sec > 0) 
                           subtype |= ARGUS_TIME_SRC_END;

                        if ((subtype & ARGUS_TIME_SRC_START) && (subtype & ARGUS_TIME_SRC_END)) {
                           if ((dtime->src.start.tv_sec  == dtime->src.end.tv_sec) &&
                               (dtime->src.start.tv_usec == dtime->src.end.tv_usec))
                              subtype &= ~ARGUS_TIME_SRC_END;
                        }

                        if (dtime->dst.start.tv_sec > 0) 
                           subtype |= ARGUS_TIME_DST_START;
                        if (dtime->dst.end.tv_sec > 0) 
                           subtype |= ARGUS_TIME_DST_END;

                        if ((subtype & ARGUS_TIME_DST_START) && (subtype & ARGUS_TIME_DST_END)) {
                           if ((dtime->dst.start.tv_sec  == dtime->dst.end.tv_sec) &&
                               (dtime->dst.start.tv_usec == dtime->dst.end.tv_usec))
                              subtype &= ~ARGUS_TIME_DST_END;
                        }

                        if (metric && (metric->src.pkts == 0))
                           subtype &= ~(ARGUS_TIME_SRC_START | ARGUS_TIME_SRC_END);

                        if (metric && (metric->dst.pkts == 0))
                           subtype &= ~(ARGUS_TIME_DST_START | ARGUS_TIME_DST_END);

                        for (x = 0; x < 4; x++)
                           if (subtype & (ARGUS_TIME_SRC_START << x)) 
                              cnt++;

                        if (cnt && (dtime->hdr.argus_dsrvl8.qual != ARGUS_TYPE_UTC_NANOSECONDS)) {
                           if (cnt == 1) 
                              subtype |= ARGUS_TIME_ABSOLUTE_TIMESTAMP;
                           else if (dur > 1000000000)
                              subtype |= ARGUS_TIME_ABSOLUTE_RANGE;
                           else
                              subtype |= ARGUS_TIME_RELATIVE_RANGE;
                        } else {
                           subtype &= ~ARGUS_TIME_RELATIVE_TIMESTAMP;
                           subtype |= ARGUS_TIME_ABSOLUTE_TIMESTAMP;
                        }

                        dtime->hdr.subtype = subtype;

//  We'd like to use relative uSec or nSec timestamps if there are more
//  than one timestamp in the record. ARGUS_TIME_RELATIVE_TIMESTAMP
//  So lets test uSec deltas, and report for time.

//#define ARGUS_TIME_ABSOLUTE_TIMESTAMP           0x01    // All time indicators are 64-bit sec, usec values, implies more than 2
//#define ARGUS_TIME_ABSOLUTE_RANGE               0x02    // All timestamp are absolute, and the second timestamp is the flow range
//#define ARGUS_TIME_ABSOLUTE_RELATIVE_RANGE      0x03    // First timestamp is absolute, the second indicator is a range offset
//#define ARGUS_TIME_RELATIVE_TIMESTAMP           0x04    // First timestamp is absolute, all others are relative, uSec or nSec
//#define ARGUS_TIME_RELATIVE_RANGE               0x05    // First timestamp is absolute, only one other value is flow range, uSec or nSec

                      
                        *dsrptr++ = *(unsigned int *)&dtime->hdr;

                        if (subtype & ARGUS_TIME_RELATIVE_RANGE) {
                           if (subtype & ARGUS_TIME_SRC_START) {      // assume at this point that all indicators are reasonable
                              long long stime  = (dtime->src.start.tv_sec * 1000000L) + dtime->src.start.tv_usec;

                              *dsrptr++ = dtime->src.start.tv_sec;    // if there is not a src start, then there is not a src end
                              *dsrptr++ = dtime->src.start.tv_usec;
                              tlen += 2;

                              for (x = 1; x < 4; x++) {
                                 int mask = (ARGUS_TIME_SRC_START << x);
                                 if (subtype & mask) {
                                    switch (mask) {
                                       case ARGUS_TIME_SRC_END: {
                                          long long send = (dtime->src.end.tv_sec * 1000000L) + dtime->src.end.tv_usec;
                                          int value = send - stime;
                                          *dsrptr++ = value;
                                          tlen += 1;
                                          break;
                                       }
                                       case ARGUS_TIME_DST_START: {
                                          long long dstart = (dtime->dst.start.tv_sec * 1000000L) + dtime->dst.start.tv_usec;
                                          int value = dstart - stime;
                                          *dsrptr++ = value;
                                          tlen += 1;
                                          break;
                                       }
                                       case ARGUS_TIME_DST_END: {
                                          long long dend = (dtime->dst.end.tv_sec * 1000000L) + dtime->dst.end.tv_usec;
                                          int value = dend - stime;
                                          *dsrptr++ = value;
                                          tlen += 1;
                                          break;
                                       }
                                    }
                                 }
                              }

                           } else {
                              if (subtype & ARGUS_TIME_DST_START) {         // assume its just dst start and possibly end.
                                 *dsrptr++ = dtime->dst.start.tv_sec;
                                 *dsrptr++ = dtime->dst.start.tv_usec;
                                 tlen += 2;

                                 if (subtype & ARGUS_TIME_DST_END) {
                                    *dsrptr++ = dur;  // the dur at this point is the difference
                                    tlen += 1;
                                 }
                              }
                           }

                        } else {
                           
                           for (x = 0; x < 4; x++) {
                              int mask = (ARGUS_TIME_SRC_START << x);
                              if (subtype & mask) {
                                 switch (mask) {
                                    case ARGUS_TIME_SRC_START:
                                       *dsrptr++ = dtime->src.start.tv_sec;
                                       *dsrptr++ = dtime->src.start.tv_usec;
                                       tlen += 2;
                                       break;
                                    case ARGUS_TIME_SRC_END:
                                       *dsrptr++ = dtime->src.end.tv_sec;
                                       *dsrptr++ = dtime->src.end.tv_usec;
                                       tlen += 2;
                                       break;
                                    case ARGUS_TIME_DST_START:
                                       *dsrptr++ = dtime->dst.start.tv_sec;
                                       *dsrptr++ = dtime->dst.start.tv_usec;
                                       tlen += 2;
                                       break;
                                    case ARGUS_TIME_DST_END:
                                       *dsrptr++ = dtime->dst.end.tv_sec;
                                       *dsrptr++ = dtime->dst.end.tv_usec;
                                       tlen += 2;
                                       break;
                                 }
                              }
                           }
                        }

                        dsrtime->hdr.argus_dsrvl8.len = tlen;
                        len = tlen;
                        break;
                     }

                     case ARGUS_METRIC_INDEX: {
                        struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *) dsr;

                        if (((metric->src.pkts + metric->dst.pkts) > 0) ||
                            ((metric->src.bytes + metric->dst.bytes) > 0)) {
                           if (((metric->src.pkts) && (metric->dst.pkts)) ||
                               ((metric->src.bytes) && (metric->dst.bytes))) {
                              if ((0xFF >= metric->src.pkts)  && (0xFF >= metric->dst.pkts) &&
                                  (0xFF >= metric->src.bytes) && (0xFF >= metric->dst.bytes))
                                 type = ARGUS_SRCDST_BYTE;
                              else
                              if ((0xFFFF >= metric->src.bytes) && (0xFFFF >= metric->dst.bytes))
                                 type = ARGUS_SRCDST_SHORT;
                              else
                              if ((0xFFFFFFFF >= metric->src.bytes) && (0xFFFFFFFF >= metric->dst.bytes))
                                 type = ARGUS_SRCDST_INT;
                              else
                                 type = ARGUS_SRCDST_LONGLONG;

                           } else {
                              if ((metric->src.pkts) || (metric->src.bytes)) {
                                 if (0xFFFF >= metric->src.bytes)
                                    type = ARGUS_SRC_SHORT;
                                 else
                                 if (0xFFFFFFFF >= metric->src.bytes)
                                    type = ARGUS_SRC_INT;
                                 else
                                    type = ARGUS_SRC_LONGLONG;
                              } else {
                                 if (0xFFFF >= metric->dst.bytes)
                                    type = ARGUS_DST_SHORT;
                                 else
                                 if (0xFFFFFFFF >= metric->dst.bytes)
                                    type = ARGUS_DST_INT;
                                 else
                                    type = ARGUS_DST_LONGLONG;
                              }
                           }
                        } else {
                           type = ARGUS_SRCDST_BYTE;
                        }

                        dsr = (struct ArgusDSRHeader *)dsrptr;
                        dsr->type    = ARGUS_METER_DSR;

                        if (metric->src.appbytes || metric->dst.appbytes) {
                           dsr->subtype = ARGUS_METER_PKTS_BYTES_APP;
                           switch (type) {
                              case ARGUS_SRCDST_BYTE:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned char *)(dsr + 1))[0] = (unsigned char) metric->src.pkts;
                                 ((unsigned char *)(dsr + 1))[1] = (unsigned char) metric->src.bytes;
                                 ((unsigned char *)(dsr + 1))[2] = (unsigned char) metric->src.appbytes;
                                 ((unsigned char *)(dsr + 1))[3] = (unsigned char) metric->dst.pkts;
                                 ((unsigned char *)(dsr + 1))[4] = (unsigned char) metric->dst.bytes;
                                 ((unsigned char *)(dsr + 1))[5] = (unsigned char) metric->dst.appbytes;
                                 ((unsigned char *)(dsr + 1))[6] = 0;
                                 ((unsigned char *)(dsr + 1))[7] = 0;
                                 break;
                              case ARGUS_SRCDST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 4;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->src.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->src.bytes);
                                 ((unsigned short *)(dsr + 1))[2] = ((unsigned short) metric->src.appbytes);
                                 ((unsigned short *)(dsr + 1))[3] = ((unsigned short) metric->dst.pkts);
                                 ((unsigned short *)(dsr + 1))[4] = ((unsigned short) metric->dst.bytes);
                                 ((unsigned short *)(dsr + 1))[5] = ((unsigned short) metric->dst.appbytes);
                                 break;
                              case ARGUS_SRCDST_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 7;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->src.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->src.bytes);
                                 ((unsigned int *)(dsr + 1))[2] = ((unsigned int) metric->src.appbytes);
                                 ((unsigned int *)(dsr + 1))[3] = ((unsigned int) metric->dst.pkts);
                                 ((unsigned int *)(dsr + 1))[4] = ((unsigned int) metric->dst.bytes);
                                 ((unsigned int *)(dsr + 1))[5] = ((unsigned int) metric->dst.appbytes);
                                 break;
                              case ARGUS_SRCDST_LONGLONG: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 13;
                                 long long *ptr = (long long *)(dsr + 1);

                                 bcopy(&metric->src.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->src.bytes,    ptr++, sizeof(long long));
                                 bcopy(&metric->src.appbytes, ptr++, sizeof(long long));
                                 bcopy(&metric->dst.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->dst.bytes,    ptr++, sizeof(long long));
                                 bcopy(&metric->dst.appbytes, ptr++, sizeof(long long));
                                 break;
                              }

                              case ARGUS_SRC_BYTE:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned char *)(dsr + 1))[0] = ((unsigned char) metric->src.pkts);
                                 ((unsigned char *)(dsr + 1))[1] = ((unsigned char) metric->src.bytes);
                                 ((unsigned char *)(dsr + 1))[2] = ((unsigned char) metric->src.appbytes);
                                 ((unsigned char *)(dsr + 1))[3] = 0;
                                 break;
                              case ARGUS_SRC_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->src.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->src.bytes);
                                 ((unsigned short *)(dsr + 1))[2] = ((unsigned short) metric->src.appbytes);
                                 ((unsigned short *)(dsr + 1))[3] = 0;
                                 break;
                              case ARGUS_SRC_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 4;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->src.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->src.bytes);
                                 ((unsigned int *)(dsr + 1))[2] = ((unsigned int) metric->src.appbytes);
                                 break;
                              case ARGUS_SRC_LONGLONG: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 7;
                                 long long *ptr = (long long *)(dsr + 1);

                                 bcopy(&metric->src.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->src.bytes,    ptr++, sizeof(long long));
                                 bcopy(&metric->src.appbytes, ptr++, sizeof(long long));

                                 break;
                              }

                              case ARGUS_DST_BYTE:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned char *)(dsr + 1))[0] = ((unsigned char) metric->dst.pkts);
                                 ((unsigned char *)(dsr + 1))[1] = ((unsigned char) metric->dst.bytes);
                                 ((unsigned char *)(dsr + 1))[2] = ((unsigned char) metric->dst.appbytes);
                                 ((unsigned char *)(dsr + 1))[3] = 0;
                                 break;
                              case ARGUS_DST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->dst.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->dst.bytes);
                                 ((unsigned short *)(dsr + 1))[2] = ((unsigned short) metric->dst.appbytes);
                                 ((unsigned short *)(dsr + 1))[3] = 0;
                                 break;
                              case ARGUS_DST_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 4;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->dst.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->dst.bytes);
                                 ((unsigned int *)(dsr + 1))[2] = ((unsigned int) metric->dst.appbytes);
                                 break;
                              case ARGUS_DST_LONGLONG: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 7;
                                 long long *ptr = (long long *)(dsr + 1);

                                 bcopy(&metric->dst.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->dst.bytes,    ptr++, sizeof(long long));
                                 bcopy(&metric->dst.appbytes, ptr++, sizeof(long long));
                                 break;
                              }
                           }
                        } else {
                           dsr->subtype = ARGUS_METER_PKTS_BYTES;
                           switch (type) {
                              case ARGUS_SRCDST_BYTE:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned char *)(dsr + 1))[0] = (unsigned char) metric->src.pkts;
                                 ((unsigned char *)(dsr + 1))[1] = (unsigned char) metric->src.bytes;
                                 ((unsigned char *)(dsr + 1))[2] = (unsigned char) metric->dst.pkts;
                                 ((unsigned char *)(dsr + 1))[3] = (unsigned char) metric->dst.bytes;
                                 break;
                              case ARGUS_SRCDST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->src.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->src.bytes);
                                 ((unsigned short *)(dsr + 1))[2] = ((unsigned short) metric->dst.pkts);
                                 ((unsigned short *)(dsr + 1))[3] = ((unsigned short) metric->dst.bytes);
                                 break;
                              case ARGUS_SRCDST_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 5;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->src.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->src.bytes);
                                 ((unsigned int *)(dsr + 1))[2] = ((unsigned int) metric->dst.pkts);
                                 ((unsigned int *)(dsr + 1))[3] = ((unsigned int) metric->dst.bytes);
                                 break;
                              case ARGUS_SRCDST_LONGLONG: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 9;
                                 long long *ptr = (long long *)(dsr + 1);

                                 bcopy(&metric->src.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->src.bytes,    ptr++, sizeof(long long));
                                 bcopy(&metric->dst.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->dst.bytes,    ptr++, sizeof(long long));

                                 break;
                              }

                              case ARGUS_SRC_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->src.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->src.bytes);
                                 break;
                              case ARGUS_SRC_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->src.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->src.bytes);
                                 break;
                              case ARGUS_SRC_LONGLONG: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 5;
                                 long long *ptr = (long long *)(dsr + 1);

                                 bcopy(&metric->src.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->src.bytes,    ptr++, sizeof(long long));
                                 break;
                              }

                              case ARGUS_DST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->dst.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->dst.bytes);
                                 break;
                              case ARGUS_DST_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->dst.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->dst.bytes);
                                 break;
                              case ARGUS_DST_LONGLONG: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 5;
                                 long long *ptr = (long long *)(dsr + 1);

                                 bcopy(&metric->dst.pkts,     ptr++, sizeof(long long));
                                 bcopy(&metric->dst.bytes,    ptr++, sizeof(long long));
                                 break;
                              }
                           }
                        }
                        len     = dsr->argus_dsrvl8.len;
                        dsrptr += len;
                        break;
                     }

                     case ARGUS_PSIZE_INDEX: {
                        struct ArgusPacketSizeStruct *psize  = (struct ArgusPacketSizeStruct *) dsr;

                        if ((psize->src.psizemax > 0) && (psize->dst.psizemax > 0))
                           type = ARGUS_SRCDST_SHORT;
                        else
                        if (psize->src.psizemax > 0)
                           type = ARGUS_SRC_SHORT;
                        else
                        if (psize->dst.psizemax > 0)
                           type = ARGUS_DST_SHORT;
                        else
                           type = 0;

                        if (type) {
                           unsigned char value = 0, tmp = 0, *ptr;
                           int max, i;
//                         int cnt;

                           dsr = (struct ArgusDSRHeader *)dsrptr;
                           dsr->type    = ARGUS_PSIZE_DSR;

                           switch (type) {
                              case ARGUS_SRCDST_SHORT:
                                 dsr->subtype = ARGUS_PSIZE_SRC_MAX_MIN | ARGUS_PSIZE_DST_MAX_MIN;
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned short *)(dsr + 1))[0] = psize->src.psizemin;
                                 ((unsigned short *)(dsr + 1))[1] = psize->src.psizemax;
                                 ((unsigned short *)(dsr + 1))[2] = psize->dst.psizemin;
                                 ((unsigned short *)(dsr + 1))[3] = psize->dst.psizemax;
                                 break;

                              case ARGUS_SRC_SHORT:
                                 dsr->subtype = ARGUS_PSIZE_SRC_MAX_MIN;
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned short *)(dsr + 1))[0] = psize->src.psizemin;
                                 ((unsigned short *)(dsr + 1))[1] = psize->src.psizemax;
                                 break;

                              case ARGUS_DST_SHORT:
                                 dsr->subtype = ARGUS_PSIZE_DST_MAX_MIN;
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned short *)(dsr + 1))[0] = psize->dst.psizemin;
                                 ((unsigned short *)(dsr + 1))[1] = psize->dst.psizemax;
                                 break;

                              default:
                                 break;
                           }

                           if (dsr->subtype & ARGUS_PSIZE_SRC_MAX_MIN) {
                              ptr = (unsigned char *)(dsr + dsr->argus_dsrvl8.len);

//                            for (cnt = 0, i = 0; i < 8; i++)
//                               cnt += psize->src.psize[i];

                              dsr->subtype |= ARGUS_PSIZE_HISTO;

                              dsr->argus_dsrvl8.len++;
                              *((unsigned int *)(dsr + dsr->argus_dsrvl8.len)) = 0;

                              for (i = 0, max = 0; i < 8; i++)
                                 if (max < psize->src.psize[i])
                                    max = psize->src.psize[i];

                              for (i = 0; i < 8; i++) {
                                 if ((tmp = psize->src.psize[i])) {
                                    if (i & 0x01) {
                                       if (max > 15)
                                         tmp = ((tmp * 15)/max);
                                       if (!tmp) tmp++;
                                       value |= tmp;
                                       *ptr++ = value;
                                    } else {
                                       if (max > 15)
                                         tmp = ((tmp * 15)/max);
                                       if (!tmp) tmp++;
                                       value = (tmp << 4);
                                    }
                                 } else {
                                    if (i & 0x01) {
                                       value &= 0xF0;
                                       *ptr++ = value;
                                    } else {
                                       value = 0;
                                    }
                                 }
                              }
                           }

                           if (dsr->subtype & ARGUS_PSIZE_DST_MAX_MIN) {
                              ptr = (unsigned char *)(dsr + dsr->argus_dsrvl8.len);

//                            for (cnt = 0, i = 0; i < 8; i++)
//                               cnt += psize->dst.psize[i];

                              dsr->subtype |= ARGUS_PSIZE_HISTO;

                              dsr->argus_dsrvl8.len++;
                              *((unsigned int *)(dsr + dsr->argus_dsrvl8.len)) = 0;

                              for (i = 0, max = 0; i < 8; i++)
                                 if (max < psize->dst.psize[i])
                                    max = psize->dst.psize[i];

                              for (i = 0; i < 8; i++) {
                                 if ((tmp = psize->dst.psize[i])) {
                                    if (i & 0x01) {
                                       if (max > 15)
                                         tmp = ((tmp * 15)/max);
                                       if (!tmp) tmp++;
                                       value |= tmp;
                                       *ptr++ = value;
                                    } else {
                                       if (max > 15)
                                         tmp = ((tmp * 15)/max);
                                       if (!tmp) tmp++;
                                       value = (tmp << 4);
                                    }
                                 } else {
                                    if (i & 0x01) {
                                       value &= 0xF0;
                                       *ptr++ = value;
                                    } else {
                                       value = 0;
                                    }
                                 }
                              }
                           }

                           dsr->argus_dsrvl8.qual = type;
                           len = dsr->argus_dsrvl8.len;
                           dsrptr += len;
                        } else
                           len = 0;

                        break;
                     }

                     case ARGUS_MPLS_INDEX: {
                        struct ArgusMplsStruct *mpls  = (struct ArgusMplsStruct *) dsr;
                        struct ArgusMplsStruct *tmpls = (struct ArgusMplsStruct *) dsrptr;
                        unsigned char subtype = tmpls->hdr.subtype & ~(ARGUS_MPLS_SRC_LABEL | ARGUS_MPLS_DST_LABEL);

                        *dsrptr++ = *(unsigned int *)dsr;
                        len = 1;

                        if (((mpls->hdr.argus_dsrvl8.qual & 0xF0) >> 4) > 0) {
                           subtype |= ARGUS_MPLS_SRC_LABEL;
                           *dsrptr++ = mpls->slabel;
                           len++;
                        }
                        if (((mpls->hdr.argus_dsrvl8.qual & 0x0F)) > 0) {
                           subtype |= ARGUS_MPLS_DST_LABEL;
                           *dsrptr++ = mpls->dlabel;
                           len++;
                        }
                        tmpls->hdr.subtype = subtype;
                        tmpls->hdr.argus_dsrvl8.len = len;
                        break;
                     }

                     case ARGUS_JITTER_INDEX: {
#if defined(HAVE_XDR)
                        struct ArgusJitterStruct *jitter = (struct ArgusJitterStruct *) dsr;
                        struct ArgusJitterStruct *tjit   = (struct ArgusJitterStruct *) dsrptr;
                        int size = sizeof(struct ArgusStatsObject) / 4;

                        XDR xdrbuf, *xdrs = &xdrbuf;

                        *dsrptr++ = *(unsigned int *)dsr;
                        len = 1;

                        if (jitter->hdr.argus_dsrvl8.qual & ARGUS_SRC_ACTIVE_JITTER) {
                           bzero((char *)dsrptr, sizeof(struct ArgusStatsObject));
                           xdrmem_create(xdrs, (char *)dsrptr, sizeof(struct ArgusStatsObject), XDR_ENCODE);
                           xdr_int(xdrs, &jitter->src.act.n);
                           xdr_float(xdrs, &jitter->src.act.minval);
                           xdr_float(xdrs, &jitter->src.act.meanval);
                           xdr_float(xdrs, &jitter->src.act.stdev);
                           xdr_float(xdrs, &jitter->src.act.maxval);
                           dsrptr += size;
                           len += size;
			}
                        if (jitter->hdr.argus_dsrvl8.qual & ARGUS_SRC_IDLE_JITTER) {
                           bzero((char *)dsrptr, sizeof(struct ArgusStatsObject));
                           xdrmem_create(xdrs, (char *)dsrptr, sizeof(struct ArgusStatsObject), XDR_ENCODE);
                           xdr_int(xdrs, &jitter->src.idle.n);
                           xdr_float(xdrs, &jitter->src.idle.minval);
                           xdr_float(xdrs, &jitter->src.idle.meanval);
                           xdr_float(xdrs, &jitter->src.idle.stdev);
                           xdr_float(xdrs, &jitter->src.idle.maxval);
                           dsrptr += size;
                           len += size;
			}
                        if (jitter->hdr.argus_dsrvl8.qual & ARGUS_DST_ACTIVE_JITTER) {
                           bzero((char *)dsrptr, sizeof(struct ArgusStatsObject));
                           xdrmem_create(xdrs, (char *)dsrptr, sizeof(struct ArgusStatsObject), XDR_ENCODE);
                           xdr_int(xdrs, &jitter->dst.act.n);
                           xdr_float(xdrs, &jitter->dst.act.minval);
                           xdr_float(xdrs, &jitter->dst.act.meanval);
                           xdr_float(xdrs, &jitter->dst.act.stdev);
                           xdr_float(xdrs, &jitter->dst.act.maxval);
                           dsrptr += size;
                           len += size;
                        }
                        if (jitter->hdr.argus_dsrvl8.qual & ARGUS_DST_IDLE_JITTER) {
                           bzero((char *)dsrptr, sizeof(struct ArgusStatsObject));
                           xdrmem_create(xdrs, (char *)dsrptr, sizeof(struct ArgusStatsObject), XDR_ENCODE);
                           xdr_int(xdrs, &jitter->dst.idle.n);
                           xdr_float(xdrs, &jitter->dst.idle.minval);
                           xdr_float(xdrs, &jitter->dst.idle.meanval);
                           xdr_float(xdrs, &jitter->dst.idle.stdev);
                           xdr_float(xdrs, &jitter->dst.idle.maxval);
                           dsrptr += size;
                           len += size;
                        }

                        tjit->hdr.argus_dsrvl8.len = len;
                        break;
#endif
                     }

                     case ARGUS_IPATTR_INDEX: {
                        struct ArgusIPAttrStruct *attr  = (struct ArgusIPAttrStruct *) dsr;
                        struct ArgusIPAttrStruct *tattr = (struct ArgusIPAttrStruct *) dsrptr;

                        *dsrptr++ = *(unsigned int *)dsr;
                        len = 1;

                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC) {
                           *dsrptr++ = *(unsigned int *)&attr->src;
                           len++;
                        }
                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC_OPTIONS) {
                           *dsrptr++ = attr->src.options;
                           len++;
                        }
                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST) {
                           *dsrptr++ = *(unsigned int *)&attr->dst;
                           len++;
                        }
                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST_OPTIONS) {
                           *dsrptr++ = attr->dst.options;
                           len++;
                        }
                        tattr->hdr.argus_dsrvl8.len = len;
                        break;
                     }

                     case ARGUS_LABEL_INDEX: {
                        struct ArgusLabelStruct *label  = (struct ArgusLabelStruct *) dsr;
                        int labelen = 0, slen = 0;

                        if (label->l_un.label != NULL)
                           slen = strlen(label->l_un.label);
                        
                        if (slen > 0) {
                           labelen = (label->hdr.argus_dsrvl8.len - 1) * 4;
                           *dsrptr++ = *(unsigned int *)dsr;
                           bcopy ((char *)label->l_un.label, (char *)dsrptr, slen);
                           if (labelen > slen)
                              bzero(&((char *)dsrptr)[slen], labelen - slen);
                           dsrptr += (labelen + 3)/4;
                           len = 1 + ((labelen + 3)/4);
                        } else
                           len = 0;
                        break;
                     }


                     case ARGUS_GEO_INDEX: {
#if defined(HAVE_XDR)
                        struct ArgusGeoLocationStruct *geo  = (struct ArgusGeoLocationStruct *) dsr;
                        struct ArgusV3GeoLocationStruct *tgeo = (struct ArgusV3GeoLocationStruct *) dsrptr;

                        int size = (sizeof(struct ArgusCoordinates) + 3) / 4;
                        XDR xdrbuf, *xdrs = &xdrbuf;

                        *dsrptr++ = *(unsigned int *)dsr;
                        tgeo->hdr.argus_dsrvl8.len = 1;
                        
                        if (geo->hdr.argus_dsrvl8.qual & ARGUS_SRC_GEO) {
                           xdrmem_create(xdrs, (char *)dsrptr, sizeof(struct ArgusCoordinates), XDR_ENCODE);
                           xdr_float(xdrs, &geo->src.lat);
                           xdr_float(xdrs, &geo->src.lon);
                           dsrptr += size;
                           tgeo->hdr.argus_dsrvl8.len += size;
                        }

                        if (geo->hdr.argus_dsrvl8.qual & ARGUS_DST_GEO) {
                           xdrmem_create(xdrs, (char *)dsrptr, sizeof(struct ArgusCoordinates), XDR_ENCODE);
                           xdr_float(xdrs, &geo->dst.lat);
                           xdr_float(xdrs, &geo->dst.lon);
                           dsrptr += size;
                           tgeo->hdr.argus_dsrvl8.len += size;
                        }

                        if (geo->hdr.argus_dsrvl8.qual & ARGUS_INODE_GEO) {
                           xdrmem_create(xdrs, (char *)dsrptr, sizeof(struct ArgusCoordinates), XDR_ENCODE);
                           xdr_float(xdrs, &geo->inode.lat);
                           xdr_float(xdrs, &geo->inode.lon);
                           dsrptr += size; 
                           tgeo->hdr.argus_dsrvl8.len += size;
                        }
                        len = tgeo->hdr.argus_dsrvl8.len;
#endif
                        break;
                     }
                  }

                  dsrlen += len;
                  dsrindex &= ~ind;
               }
            }

            if (retn->hdr.len != 0) {
               if (!(rec->status & ARGUS_RECORD_MODIFIED) && (retn->hdr.len != dsrlen)) {
                  if (retn->hdr.len > dsrlen) {
                     int i, cnt = retn->hdr.len - dsrlen;
#ifdef ARGUSDEBUG
                     ArgusDebug (6, "ArgusGenerateV5Record (%p, %d) old len %d new len %d\n", 
                        rec, state, retn->hdr.len * 4, dsrlen * 4);
#endif 
                     for (i = 0; i < cnt; i++) {
                       dsr = (void *) dsrptr++;
                       dsr->type = 0; dsr->subtype = 0;
                       dsr->argus_dsrvl8.qual = 0;
                       dsr->argus_dsrvl8.len = 1;
                       dsrlen++;
                     }
                  }
               }
            }

            retn->hdr.len = dsrlen;

            if (((char *)dsrptr - (char *)retn) != (dsrlen * 4))
               ArgusLog (LOG_ERR, "ArgusGenerateV5Record: parse length error %d:%d", ((char *)dsrptr - (char *)retn), dsrlen);

            break;
         }

         default:
            retn = NULL;
            break;
      }
         
   } else {
      retn->hdr.type = ARGUS_MAR | ARGUS_VERSION;
      retn->hdr.cause &= 0x0F;
      retn->hdr.cause |= state & 0xF0;
      retn->hdr.len = dsrlen;
   }
 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusGenerateV5Record (%p, %d) len %d\n", rec, state, dsrlen * 4);
#endif 
   return (retn);
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


static void ArgusCheckClientStatus (struct ArgusOutputStruct *, int, char);
int ArgusCheckClientMessage (struct ArgusOutputStruct *, struct ArgusClientData *);
int ArgusCheckControlMessage (struct ArgusOutputStruct *, struct ArgusClientData *);
int ArgusCongested = 0;

struct timeval *getArgusMarReportInterval(struct ArgusParserStruct *);
int ArgusOutputStatusTime(struct ArgusOutputStruct *);

int
ArgusOutputStatusTime(struct ArgusOutputStruct *output)
{
   int retn = 0;

   /* MAR output disabled if reporting interval set to zero */
   if (output->ArgusMarReportInterval.tv_sec == 0 &&
       output->ArgusMarReportInterval.tv_usec == 0)
      return 0;

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

static int
__output_is_active(const struct ArgusOutputStruct * const output)
{
   if (output == NULL)
      return 0;

   if (output->status & ARGUS_STOP)
      return 0;

   return 1;
}

static int
__build_output_array(struct ArgusParserStruct *parser,
                     struct ArgusOutputStruct *outputs[],
                     int lfd[],
                     int notifyfd[], /* pipes for completion notification */
                     char lfdver[])
{
   int i;
   int count;

   MUTEX_LOCK(&parser->lock);
   for (i = 0, count = 0; i < parser->ArgusListens; i++) {
      if (__output_is_active(parser->ArgusOutputs[i])) {
         outputs[count] = parser->ArgusOutputs[i];
         lfd[count] = parser->ArgusLfd[i];
         lfdver[count] = parser->ArgusLfdVersion[i];
#if defined(ARGUS_THREADS)
         notifyfd[count] = parser->ArgusOutputs[i]->ListenNotify[0];
#endif
         count++;
      }
   }
   MUTEX_UNLOCK(&parser->lock);

   return count;
}

#ifdef ARGUS_THREADS
# define LISTEN_WAIT_INITIALIZER {1, 0}
#else
# define LISTEN_WAIT_INITIALIZER {0, 0}
#endif

void *ArgusListenProcess(void *arg)
{
   struct ArgusParserStruct *parser = arg;
   struct ArgusOutputStruct *output;
   struct ArgusOutputStruct *outputs[ARGUS_MAXLISTEN];
   int lfd[ARGUS_MAXLISTEN];
   int notifyfd[ARGUS_MAXLISTEN];
   char lfdver[ARGUS_MAXLISTEN];
   int nbout;

#if defined(ARGUS_THREADS)
   sigset_t blocked_signals;
#endif /* ARGUS_THREADS */

#ifdef ARGUSDEBUG
   ArgusDebug (2, "%s(0x%x) starting\n", __func__, arg);
#endif

   if (arg == NULL)
      goto out;

   nbout = __build_output_array(parser, outputs, lfd, notifyfd, lfdver);

#if defined(ARGUS_THREADS)
   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

   while (nbout > 0 && !parser->RaShutDown)
#else
   if (nbout > 0 && !parser->RaShutDown)
#endif
   {
      int cur;
      int count;
      int val;

         struct timeval wait = LISTEN_WAIT_INITIALIZER;
         fd_set readmask;
         int width = 0;

         /* Build new fd_set of listening sockets */

         FD_ZERO(&readmask);

         for (cur = 0; cur < nbout; cur++) {
            /* Build new fd_set of client sockets */

            if (lfd[cur] != -1) {
               FD_SET(lfd[cur], &readmask);
               width = (lfd[cur] > width) ? lfd[cur] : width;
            }
            if (notifyfd[cur] != -1) {
               FD_SET(notifyfd[cur], &readmask);
               width = (notifyfd[cur] > width) ? notifyfd[cur] : width;
            }

            output = outputs[cur];

            MUTEX_LOCK(&output->ArgusClients->lock);
            if ((count = output->ArgusClients->count) > 0) {
               struct ArgusClientData *client = (void *)output->ArgusClients->start;
               int i;

               for (i = 0; i < count && client; i++) {
                  if (client->sock &&
                      client->sock->filename == NULL &&
                      client->readable == 0 &&
                      client->fd != -1) {
                     FD_SET(client->fd, &readmask);
                     width = (client->fd > width) ? client->fd : width;
                  }
                  client = (void *) client->qhdr.nxt;
               }
            }
            MUTEX_UNLOCK(&output->ArgusClients->lock);
         }

         if ((val = select (width + 1, &readmask, NULL, NULL, &wait)) >= 0) {
            if (val > 0) {
               struct ArgusClientData *client;
               char pchar;

#ifdef ARGUSDEBUG
               ArgusDebug(3, "%s() select returned with tasks\n", __func__);
#endif

               for (cur = 0; cur < nbout; cur++) {

                  if (FD_ISSET(lfd[cur], &readmask))
                     ArgusCheckClientStatus(outputs[cur], lfd[cur], lfdver[cur]);

                  /* If the pipe(2) failed then the notifyfd could be -1. */
                  if (notifyfd[cur] >= 0 && FD_ISSET(notifyfd[cur], &readmask)) {
                     if (read(notifyfd[cur], &pchar, 1) < 0) {
                     }

                     /* Make sure we don't try to read from the
                      * notifyfd a second time since the notifyfd array
                      * can have duplicate entries when there is more
                      * than one listening fd per output thread.
                      */
                     FD_CLR(notifyfd[cur], &readmask);
                  }

                  output = outputs[cur];

                  /* This is not great since checkmessage() can take a
                   * while for RADIUM_FILE.
                   */
                  MUTEX_LOCK(&output->ArgusClients->lock);
                  client = (void *)output->ArgusClients->start;
                  if (client != NULL)  {
                     do {
                        if (client->fd != -1) {
                           if (FD_ISSET(client->fd, &readmask)) {
                              client->readable = 1;
                           }
                        }
                        client = (void *) client->qhdr.nxt;
                     } while (client != (void *)output->ArgusClients->start);
                  }
                  MUTEX_UNLOCK(&output->ArgusClients->lock);

               }
            }
         }

#if defined(ARGUS_THREADS)
      nbout = __build_output_array(parser, outputs, lfd, notifyfd, lfdver);
#endif
   }

   /* The list of clients must be cleaned up somewhere else.  Currently,
    * __ArgusOutputProcess() does this.
    */

out:
#ifdef ARGUSDEBUG
   ArgusDebug (2, "%s(0x%x) exiting\n", __func__, arg);
#endif
   return NULL;
}

typedef int (*ArgusCheckMessageFunc)(struct ArgusOutputStruct *output,
                                     struct ArgusClientData *client);

static void *
__ArgusOutputProcess(struct ArgusOutputStruct *output,
                     unsigned short *portnum,
                     ArgusCheckMessageFunc checkmessage,
                     const char * const caller)
{
   struct timeval ArgusUpDate = {0, 50000}, ArgusNextUpdate = {0,0};
   int count;
   void *retn = NULL;

#if defined(ARGUS_THREADS)
   sigset_t blocked_signals;
#endif /* ARGUS_THREADS */

#ifdef ARGUSDEBUG
   ArgusDebug (2, "%s/%s(0x%x) starting\n", caller, __func__, output);
#endif

#if defined(ARGUS_THREADS)
   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);
   if (pipe(output->ListenNotify) < 0) {
      /* If the fd is -1, write() will fail with EBADF which we will
       * ignore.  The result will be slower responses to client commands.
       */
      ArgusLog(LOG_WARNING, "%s/%s: unable to open pipe fd pair\n", caller,
               __func__);
      output->ListenNotify[0] = output->ListenNotify[1] = -1;
   }

   while (!(output->status & ARGUS_STOP)) {
#else
   {
#endif
      struct ArgusListStruct *list = NULL;
      struct ArgusRecordStruct *rec = NULL;

      if (output && ((list = output->ArgusOutputList) != NULL)) {
         gettimeofday (&output->ArgusGlobalTime, 0L);

         if ((*portnum != 0) &&
            ((output->ArgusGlobalTime.tv_sec >  ArgusNextUpdate.tv_sec) ||
            ((output->ArgusGlobalTime.tv_sec == ArgusNextUpdate.tv_sec) &&
             (output->ArgusGlobalTime.tv_usec > ArgusNextUpdate.tv_usec)))) {
/*
            have_argus_client = 0;
            have_argusv3_client = 0;
            have_ciscov5_client = 0;

            MUTEX_LOCK(&output->ArgusClients->lock);
            if ((count = output->ArgusClients->count) > 0) {
               struct ArgusClientData *client = (void *)output->ArgusClients->start;
               int i;

               for (i = 0; i < count && client; i++) {
                  if (client->sock && (client->fd != -1)) {
                     if (client->format == ARGUS_DATA) {
                        if (client->version == ARGUS_VERSION_3)
                           have_argusv3_client = 1;
                        else
                           have_argus_client = 1;
                     }
                     else if (client->format == ARGUS_CISCO_V5_DATA) {
                        have_ciscov5_client = 1;
                     }
                  }
                  client = (void *) client->qhdr.nxt;
               }
            }
            MUTEX_UNLOCK(&output->ArgusClients->lock);
*/
            ArgusNextUpdate.tv_sec  += ArgusUpDate.tv_sec;
            ArgusNextUpdate.tv_usec += ArgusUpDate.tv_usec;
            if (ArgusNextUpdate.tv_usec > 1000000) {
               ArgusNextUpdate.tv_sec++;
               ArgusNextUpdate.tv_usec -= 1000000;
            }
         }

         /* FIXME: Need to generate a Status MAR if live interface */
         /* FIXME: Need to also generate a V3 MAR if there are any v3 clients */

         if ((*portnum != 0) && ArgusOutputStatusTime(output)) {
            if ((rec = ArgusGenerateStatusMarRecord(output, ARGUS_STATUS, ARGUS_VERSION)) != NULL) 
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
                  ArgusDebug(3, "%s/%s() received mar 0x%x totals %lld count %d remaining %d\n",
                             caller, __func__, rec, output->ArgusTotalRecords,
                             output->ArgusInputList->count,
                             output->ArgusOutputList->count);
#endif
               count = 0;

               if (output->ArgusClients) {
                  struct ArgusWireFmtBuffer *arg;
                  struct ArgusWireFmtBuffer *argv3;
                  struct ArgusWireFmtBuffer *v5;

#if defined(ARGUS_THREADS)
                  pthread_mutex_lock(&output->ArgusClients->lock);
#endif
                  if (output->ArgusClients->count) {
                     struct ArgusClientData *client = (void *)output->ArgusClients->start;
                     int i, ArgusWriteRecord = 0;
                     int have_argus_client = 0;
                     int have_argusv3_client = 0;
                     int have_ciscov5_client = 0;

#ifdef ARGUSDEBUG
                     ArgusDebug(5, "%s/%s() %d client(s) for record 0x%x\n", caller, __func__, output->ArgusClients->count, rec);
#endif
                     for (i = 0; i < output->ArgusClients->count; i++) {
                        have_argus_client = 0;
                        have_argusv3_client = 0;
                        have_ciscov5_client = 0;

                        if (client->sock && (client->fd != -1)) {
                           if (client->format == ARGUS_DATA) {
                              if (client->version == ARGUS_VERSION_3)
                                 have_argusv3_client = 1;
                              else
                                 have_argus_client = 1;
                           }
                           else if (client->format == ARGUS_CISCO_V5_DATA) {
                              have_ciscov5_client = 1;
                           }
                        }

                        if (have_argus_client)
                           arg = NewArgusWireFmtBuffer(rec, ARGUS_DATA, ARGUS_VERSION);
                        else
                           arg = NULL;

                        if (have_argusv3_client)
                           argv3 = NewArgusWireFmtBuffer(rec, ARGUS_DATA, ARGUS_VERSION_3);
                        else
                           argv3 = NULL;

                        if (have_ciscov5_client)
                           v5 = NewArgusWireFmtBuffer(rec, ARGUS_CISCO_V5_DATA, 0);
                        else
                           v5 = NULL;

                        if ((client->fd != -1) && (client->sock != NULL) && client->ArgusClientStart) {
#ifdef ARGUSDEBUG
                           ArgusDebug(5, "%s/%s() client 0x%x ready fd %d sock 0x%x start %d",
                                      caller, __func__, client, client->fd,
                                      client->sock, client->ArgusClientStart);
#endif
                           ArgusWriteRecord = 1;
                           if (client->ArgusFilterInitialized)
                              if (!(ArgusFilterRecord ((struct nff_insn *)client->ArgusNFFcode.bf_insns, rec)))
                                 ArgusWriteRecord = 0;

                           if (ArgusWriteRecord) {
                              /* post record for transmit */
                              if (client->format == ARGUS_DATA) {
                                 if (client->version == ARGUS_VERSION && have_argus_client)
                                    ArgusWriteSocket (output, client, arg);
                                 else if (client->version == ARGUS_VERSION_3 && have_argusv3_client)
                                    ArgusWriteSocket (output, client, argv3);
                              }
                              else if ((client->format == ARGUS_CISCO_V5_DATA) && have_ciscov5_client) {
                                 ArgusWriteSocket (output, client, v5);
                              }

                              /* write available records */
                              if (ArgusWriteOutSocket (output, client) < 0) {
                                 ArgusDeleteSocket(output, client);
                              }

                           } else {
#ifdef ARGUSDEBUG
                              ArgusDebug(5, "%s/%s() client 0x%x filter blocks fd %d sock 0x%x start %d",
                                         caller, __func__, client, client->fd,
                                         client->sock,
                                         client->ArgusClientStart);
#endif
                           }

                        } else {
                           struct timeval tvbuf, *tvp = &tvbuf;
#ifdef ARGUSDEBUG
                           ArgusDebug(5, "%s/%s() %d client(s) not ready fd %d sock 0x%x start %d",
                                      caller, __func__, output->ArgusClients->count,
                                      client->fd, client->sock,
                                      client->ArgusClientStart);
#endif
                           RaDiffTime (&output->ArgusGlobalTime, &client->startime, tvp);
                           if (tvp->tv_sec >= ARGUS_CLIENT_STARTUP_TIMEOUT) {
                              if (client->sock != NULL) {
                                 ArgusDeleteSocket(output, client);
                                 ArgusLog(LOG_WARNING,
                                          "%s: client %s never started: timed out",
                                          __func__, client->hostname);
                              }
                              client->ArgusClientStart = 1;
                           }
                        }
                        client = (void *) client->qhdr.nxt;

                        if (have_argus_client)
                           FreeArgusWireFmtBuffer(arg);
                        if (have_argusv3_client)
                           FreeArgusWireFmtBuffer(argv3);
                        if (have_ciscov5_client)
                           FreeArgusWireFmtBuffer(v5);
                     }
                  }
#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&output->ArgusClients->lock);
#endif
               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug(5, "%s/%s() no client for record 0x%x\n",
                             caller, __func__, rec);
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
         if ((*portnum != 0) && output->ArgusClients->count) {
            struct ArgusClientData *client = (void *)output->ArgusClients->start;
            int i, status;

            for (i = 0; i < output->ArgusClients->count; i++) {
               if ((client->fd != -1) && (client->sock != NULL)) {
                  if ((output->status & ARGUS_STOP) || (output->status & ARGUS_SHUTDOWN)) {
#ifdef ARGUSDEBUG
                     ArgusDebug(1, "%s/%s() draining queue\n", caller, __func__);
#endif
                     ArgusWriteOutSocket (output, client);
                     ArgusDeleteSocket(output, client);
                  } else {
                     int delete = 0;

                     if (client->readable || RingNullTerm(&client->ring)) {
                        if (checkmessage(output, client) < 0)
                           delete = 1;
                        client->readable = 0;

#if defined(ARGUS_THREADS)
                        /* tell ArgusListenProcess() we're done */
                        if (write(output->ListenNotify[1], "0", 1) < 0) {
                           delete = 1;
                        }
#endif
                     }

                     if (ArgusWriteOutSocket (output, client) < 0) {
                        delete = 1;
                     } else {
                        if (client->pid > 0) {
                           if (waitpid(client->pid, &status, WNOHANG) == client->pid) {
                              client->ArgusClientStart++;
                              delete = 1;
                           }
                        }
                     }
                     if (delete)
                        ArgusDeleteSocket(output, client);
                  }
               }
               client = (void *) client->qhdr.nxt;
            }

            for (i = 0, count = output->ArgusClients->count; (i < count) && output->ArgusClients->count; i++) {
               if (client->delete) {
                  ArgusRemoveFromQueue(output->ArgusClients, &client->qhdr, ARGUS_NOLOCK);
#ifdef ARGUSDEBUG
                  ArgusDebug(1, "%s/%s: client %p %s %s removed", caller, __func__,
                             client,
                             client->hostname ? client->hostname : "(unknown)",
                             client->clientid ? client->clientid : "(unknown)");
#endif
                  ArgusDeleteClient(client);
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
         ArgusDebug(1, "%s/%s() waiting for ArgusOutputList 0x%x\n",
                    caller, __func__, output);
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
      ArgusDebug (1, "%s/%s() shuting down\n", caller, __func__);
#endif
      while ((client = (void *) output->ArgusClients->start) != NULL) {
         if ((client->fd != -1) && (client->sock != NULL)) {
             ArgusWriteOutSocket (output, client);
             ArgusDeleteSocket(output, client);
          }
          ArgusRemoveFromQueue(output->ArgusClients, &client->qhdr, ARGUS_LOCK);
          ArgusDeleteClient(client);
          ArgusFree(client);
       }
    }

#if defined(ARGUS_THREADS)
#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s/%s() exiting\n", caller, __func__);
#endif
   pthread_exit(retn);
#endif /* ARGUS_THREADS */

   return (retn);
}

void *
ArgusOutputProcess(void *arg)
{
   void *rv;
   struct ArgusOutputStruct *output = (struct ArgusOutputStruct *)arg;
   unsigned short *portnum = &output->ArgusPortNum;
   ArgusCheckMessageFunc checkmessage = ArgusCheckClientMessage;

   rv = __ArgusOutputProcess(arg, portnum, checkmessage, __func__);
#if defined(ARGUS_THREADS)
   RaParseComplete(1);
#endif
   return rv;
}

static void *
ArgusControlChannelProcess(void *arg)
{
   struct ArgusOutputStruct *output = (struct ArgusOutputStruct *)arg;
   unsigned short *portnum = &output->ArgusControlPort;
   ArgusCheckMessageFunc checkmessage = ArgusCheckControlMessage;
   return __ArgusOutputProcess(arg, portnum, checkmessage, __func__);
}

static char clienthost[NI_MAXHOST*2+1] = "[local]";

#ifdef ARGUS_SASL
static sasl_security_properties_t *mysasl_secprops(int, int);
#endif

#ifdef ARGUS_SASL
/* This function is only called when SASL is available */
static int
ArgusLocalConnection(struct sockaddr *local, struct sockaddr *remote)
{
   int localaddr_lo = 0;
   int remoteaddr_lo = 0;
   struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)remote;
   struct sockaddr_in *in = (struct sockaddr_in *)remote;
   uint32_t *u6_addr32;

   if (remote->sa_family == AF_INET &&
      (in->sin_addr.s_addr == htonl(INADDR_LOOPBACK))) {
      remoteaddr_lo = 1;
   } else if (remote->sa_family == AF_INET6) {
      u6_addr32 = (uint32_t *)&(in6->sin6_addr.s6_addr[0]);

      if (IN6_IS_ADDR_LOOPBACK(&(in6->sin6_addr)) ||
         (IN6_IS_ADDR_V4MAPPED(&(in6->sin6_addr))
              && u6_addr32[3] == htonl(INADDR_LOOPBACK)))
      remoteaddr_lo = 1;
   }

   if (remoteaddr_lo == 0)
      return 0;

   in6 = (struct sockaddr_in6 *)local;
   in = (struct sockaddr_in *)local;

   if (local->sa_family == AF_INET &&
      (in->sin_addr.s_addr == htonl(INADDR_LOOPBACK))) {
      localaddr_lo = 1;
   } else if (remote->sa_family == AF_INET6) {
      u6_addr32 = (uint32_t *)&(in6->sin6_addr.s6_addr[0]);

      if (IN6_IS_ADDR_LOOPBACK(&(in6->sin6_addr)) ||
         (IN6_IS_ADDR_V4MAPPED(&(in6->sin6_addr))
              && u6_addr32[3] == htonl(INADDR_LOOPBACK)))
      localaddr_lo = 1;
   }

   return localaddr_lo;
}
#endif

static void
ArgusCheckClientStatus (struct ArgusOutputStruct *output, int s,
                        char version)
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
   int auth_localhost = 1;
#endif

   if ((fd = accept (s, (struct sockaddr *)&from, (socklen_t *)&len)) > 0) {
      int flags = fcntl (fd, F_GETFL, 0L);
      if ((fcntl (fd, F_SETFL, flags | O_NONBLOCK)) >= 0) {
         bzero(clienthost, sizeof(clienthost));
         if (ArgusTcpWrapper (output, fd, &from, clienthost) >= 0) {
            if (output->ArgusClients->count <= ARGUS_MAXCLIENTS) {
               struct ArgusClientData *client = (void *) ArgusCalloc (1, sizeof(struct ArgusClientData));

               if (client == NULL)
                  ArgusLog (LOG_ERR, "ArgusCheckClientStatus: ArgusCalloc %s", strerror(errno));

               if (RingAlloc(&client->ring) < 0)
                  ArgusLog (LOG_ERR, "%s: unable to allocate command buffer\n", __func__);

               gettimeofday (&client->startime, 0L);
               client->fd = fd;
               client->format = ARGUS_DATA;
               client->version = version;

               if (strlen(clienthost) > 0)
                  client->hostname = strdup(clienthost);
#ifdef ARGUSDEBUG
               ArgusDebug (6, "ArgusCheckClientStatus() new client %s\n", client->hostname);
#endif
               if ((client->sock = ArgusNewSocket(fd)) == NULL)
                  ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusNewSocket error %s", strerror(errno));

               if (output->ArgusInitMar != NULL)
                  ArgusFree(output->ArgusInitMar);

               if ((output->ArgusInitMar = ArgusGenerateInitialMar(output, version)) == NULL)
                  ArgusLog (LOG_ERR, "ArgusCheckClientStatus: ArgusGenerateInitialMar error %s", strerror(errno));

#ifdef ARGUS_SASL
               if (output->sasl_max_ssf == 0)
                  goto no_auth;
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

                      /* If the configuration allows, skip authentication for
                       * localhost.
                       */
                      if (output->auth_localhost == 0 &&
                          ArgusLocalConnection((struct sockaddr *)&localaddr,
                                               (struct sockaddr *)&remoteaddr)) {
                         auth_localhost = 0;
                         goto no_auth;
                      }
                  }
               }

#ifdef ARGUSDEBUG
               ArgusDebug (2, "ArgusCheckClientStatus: SASL enabled\n");
#endif

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

               secprops = mysasl_secprops(output->sasl_min_ssf, output->sasl_max_ssf);
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
               /* send initial MAR if this is NOT a control channel */
               if (output->ArgusControlPort == 0) {
                  len = ntohs(output->ArgusInitMar->hdr.len) * 4;

                  if (write (client->fd, (char *) output->ArgusInitMar, len) != len) {
                     close (client->fd);
                     /* FIXME: this is not a reason for the process to exit */
                     ArgusLog (LOG_ERR, "ArgusInitOutput: write(): %s", strerror(errno));
                  }
               }

#ifdef ARGUS_SASL
               if (auth_localhost && output->sasl_max_ssf > 0) {
                  int flags = fcntl (fd, F_GETFL, 0);

                  fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
                  if (ArgusAuthenticateClient (client, output->sasl_max_ssf)) {
                     ArgusDeleteSocket(output, client);
                     ArgusLog (LOG_ALERT, "ArgusCheckClientStatus: ArgusAuthenticateClient failed\n");
                  } else {
                     ArgusAddToQueue(output->ArgusClients, &client->qhdr, ARGUS_LOCK);
                     fcntl (fd, F_SETFL, flags);
                  }

               } else {
                     ArgusAddToQueue(output->ArgusClients, &client->qhdr, ARGUS_LOCK);
               }
#else
               ArgusAddToQueue(output->ArgusClients, &client->qhdr, ARGUS_LOCK);
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
   int retn = 0, cnt = 0, found = 0;
   char *buf = NULL, *ptr = NULL;
   int i,  fd = client->fd;
   unsigned int value = 0;

#ifdef ARGUS_SASL
   const char *outputbuf = NULL;
   unsigned int outputlen = 0;
#endif /* ARGUS_SASL */

   if ((buf = ArgusCalloc (1, MAXSTRLEN)) != NULL) {
      ptr = buf;
      value = MAXSTRLEN;

      if ((cnt = recv (fd, buf, value, 0)) > 0) {
#ifdef ARGUSDEBUG
         ArgusDebug (3, "ArgusCheckClientMessage (0x%x, %d) recv() returned %d bytes\n", client, fd, cnt);
#endif

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
                  retn = -1;

               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (3, "ArgusCheckClientMessage (0x%x, %d) sasl_decode() returned %d bytes\n", client, fd, outputlen);
#endif
                  if (outputlen > 0) {
                     if (outputlen < MAXSTRLEN) {
                        bzero (buf, MAXSTRLEN);
                        bcopy (outputbuf, buf, outputlen);
                        cnt = outputlen;
                     } else {
                        ArgusLog (LOG_ERR, "ArgusCheckClientMessage(0x%x, %d) sasl_decode returned %d bytes\n", client, fd, outputlen);
                        retn = -1;
                     }
                  }
               }
            }
         }
#endif /* ARGUS_SASL */

         if (retn == 0) {
            int isprintable = 1;
            for (i = 0; i < cnt; i++) {
               int c = ptr[i];
               if (isprint(c) == 0) {
                  isprintable = 0;
                  break;
               }
            }

            if (isprintable) {
#ifdef ARGUSDEBUG
               ArgusDebug (3, "ArgusCheckClientMessage (0x%x, %d) read '%s' from remote\n", client, fd, ptr);
#endif
               if (ArgusParser->ArgusParseClientMessage != NULL) {
                  if (ArgusParser->ArgusParseClientMessage(ArgusParser, output, client, ptr))
                     found++;
               } else {
                  for (i = 0, found = 0; (i < ARGUSMAXCLIENTCOMMANDS) && !found; i++) {
                     if (ArgusClientCommands[i] != NULL) {
                        if (!(strncmp (ptr, ArgusClientCommands[i], strlen(ArgusClientCommands[i])))) {
                           found++;
                           switch (i) {
                              case RADIUM_START: {
                                 int slen = strlen(ArgusClientCommands[i]);
                                 char *sptr;

                                 if (strlen(ptr) > slen) {
                                    if ((sptr = strstr(ptr, "user=")) != NULL) {
                                       if (client->clientid != NULL)
                                          free(client->clientid);
                                       client->clientid = strdup(sptr);

                                    }
                                 }
                                 client->ArgusClientStart++;
                                 retn = 0; break;
                              }
                              case RADIUM_DONE:  {
                                 if (client->hostname != NULL)
                                    ArgusLog (LOG_INFO, "ArgusCheckClientMessage: client %s sent DONE", client->hostname);
                                 else
                                    ArgusLog (LOG_INFO, "ArgusCheckClientMessage: received DONE");
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
                           }
                           break;
                        }
                     }
                  }

                  if (!found) {
                     if (client->hostname)
                        ArgusLog (LOG_INFO, "ArgusCheckClientMessage: client %s sent %s\n",  client->hostname, ptr);
                     else
                        ArgusLog (LOG_INFO, "ArgusCheckClientMessage: received %s\n",  ptr);
                  }
               }
            } else {
               ArgusLog (LOG_INFO, "ArgusCheckClientMessage: client %s sent unprintable chars\n",  client->hostname);
               retn = -1;
            }
         }

      } else {
         if (cnt == 0) {
#ifdef ARGUSDEBUG
            ArgusDebug (3, "%s (0x%x, %d) recv() found no connection\n", __func__, client, fd);
#endif
         } else {
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
         }
         retn = -1;
      }

      ArgusFree(buf);

   } else
     ArgusLog (LOG_ERR, "ArgusCheckClientMessage(%p, %p) ArgusCalloc error %s\n", output, client, strerror(errno));

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusCheckClientMessage: returning %d\n", retn);
#endif

   return (retn);
}

struct ArgusControlHandlerStruct ArgusControlCommands[] = {
   { "START: ", NULL},
   { "DONE: ", NULL},
   { "DISPLAY: ", NULL},
   { "HIGHLIGHT: ", NULL},
   { "SEARCH: ", NULL},
   { "FILTER: ", NULL},
   { "TREE: ", NULL},
   { "MAR: ", ArgusHandleMARCommand},
   { NULL, NULL},
};

int
ArgusCheckControlMessage (struct ArgusOutputStruct *output, struct ArgusClientData *client)
{
   int retn = 0, cnt = 0, i, found, fd = client->fd;
   char buf[ARGUS_RINGBUFFER_MAX+1];
   char **result = NULL;
   char *ptr;
   struct RingBuffer *ring = &client->ring;
   unsigned avail = RingAvail(ring);
   unsigned used;

   if (avail == 0) {
#ifdef ARGUSDEBUG
      ArgusDebug(8, "%s: no room left in ring buffer\n", __func__);
#endif
      /* If the buffer is full skip ahead and try to execute the next command */
      goto process;
   }

   cnt = recv (fd, buf, avail, 0);
   if (cnt == 0) {
#ifdef ARGUSDEBUG
      ArgusDebug (3, "%s (0x%x, %d) recv() found no connection\n", __func__,
                  client, fd);
#endif
      return -1;
   } else if (cnt < 0) {
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
            return -1;
            break;

         case EINTR:
         case ENOTSOCK:
         case EWOULDBLOCK:
            break;
      }
      cnt = 0;

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (3, "ArgusCheckControlMessage (0x%x, %d) recv() returned %d bytes\n", client, fd, cnt);
#endif
   }

   if (cnt == 0)
      goto process;

#ifdef ARGUSDEBUG
   buf[cnt] = '\0';
#endif

   /* Null terminate the string(s) by replacing \r and/or \n with \0.
    * There may be more than one command in the input buffer.  Keep
    * in mind that the end of the buffer may not be the end of a
    * command and that there may be more than one command in the
    * buffer.
    */
   i = cnt - 1;
   while (i >= 0) {
      if (buf[i] == '\r' || buf[i] == '\n')
         buf[i] = '\0';
      i--;
   }

   RingEnqueue(ring, buf, (unsigned)cnt);

process:
   /* Skip over any NULL characters to find the start of the next command */
   while (RingOccupancy(ring) > 0 && *RingHeadPtr(ring) == '\0')
      RingAdvance(&ring->CrbHead, 1);

   avail = RingAvail(ring);

   if (!RingNullTerm(ring))
      goto out;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCheckControlMessage (0x%x, %d) read %s", client, fd,
               buf);
#endif

   used = RingOccupancy(ring);
   ptr = RingDequeue(ring);

#ifdef ARGUSDEBUG
   if (ptr)
      ArgusDebug (1, "ArgusCheckControlMessage: dequeued %s\n", ptr);
#endif

   for (i = 0, found = 0; ArgusControlCommands[i].command; i++) {
      size_t cmdlen = strlen(ArgusControlCommands[i].command);
      int cmp;

      if (cmdlen > used)
	 /* ring buffer holds less than the command string length.
	  * cannot possibly match.
          */
         continue;

      cmp = strncmp(ptr, ArgusControlCommands[i].command, cmdlen);

      if (cmp == 0) {
         if (ArgusControlCommands[i].handler != NULL) {
               result = ArgusControlCommands[i].handler(output, ptr);

            if (result != NULL) {
               int sindex = 0;
               char *rstr = NULL;

               while ((rstr = result[sindex++]) != NULL) {
                  int slen = strlen(rstr);
                  int rv = -1;

                  while (slen > 0 && retn == 0) {
                     rv = send (fd, rstr, slen, 0);
                     if (rv > 0) {
                         slen -= rv;
                         rstr += rv;
                     } else if (rv == 0) {
                         retn = -3;
                     } else if (rv < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                         retn = -3;
                     }
                  }
#ifdef ARGUSDEBUG
                  if (rv < 0)
                     ArgusDebug (3, "ArgusCheckControlMessage: send error %s\n", strerror(errno));
#endif
               }
               if (retn != -3) {
                  if (send (fd, "OK\n", 3, 0) != 3) {
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
                  if (cnt > 0) {
                     if (client->hostname)
                        ArgusDebug (2, "ArgusCheckControlMessage: client %s sent %s",  client->hostname, buf);
                     else
                        ArgusDebug (2, "ArgusCheckControlMessage: received %s",  buf);
                  }
#endif
                  break;
            }
         }
         break;
      }
   }
   if (ptr)
      ArgusFree(ptr);

   if (!found) {
#ifdef ARGUSDEBUG
      if (client->hostname)
         ArgusDebug (2, "ArgusCheckControlMessage: client %s sent %s",  client->hostname, buf);
      else
         ArgusDebug (2, "ArgusCheckControlMessage: received %s",  buf);
#endif
   }

out:
#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusCheckControlMessage: returning %d\n", retn);
#endif

   return (retn);
}


//  The primary difference between V3 and V5 Management records is the ArgusAddrStruct definition
//  which is composed of an sid plus an optional 4 bytes inf struct, which is not in the management
//  record..  The sid adds v6 and uuid types ... so it is very different, although it fits in
//  the original 128 byte record.  All the changes are in the the V3 pad[3] field, and the
//  actual value, is at the end of the 16 byte region rather than the beginning of the V5 struct.
//  
//  Argus V3 and V5 management records have different ARGUS_COOKIEs, and the mar->hdr.cause code
//  is used to identify the source in Argus V5 records.
//  
//  Need to make these changes to accomodate V3 compatibility.

static
struct ArgusRecord *
ArgusGenerateInitialMar (struct ArgusOutputStruct *output, char version)
{
   struct ArgusAddrStruct asbuf, *asptr = &asbuf;
   struct timeval tbuf, *tptr = &tbuf;
   struct ArgusRecord *retn;

   if ((retn = (struct ArgusRecord *) ArgusCalloc (1, sizeof(struct ArgusRecord))) == NULL)
     ArgusLog (LOG_ERR, "ArgusGenerateInitialMar(0x%x) ArgusCalloc error %s\n", output, strerror(errno));

   switch (version) {
      case ARGUS_VERSION_3:
         retn->hdr.type  = ARGUS_MAR | ARGUS_VERSION_3;
         retn->hdr.cause = ARGUS_START;
         retn->argus_mar.argusid = htonl(ARGUS_V3_COOKIE);
         break;

      case ARGUS_VERSION_5:
         retn->hdr.type  = ARGUS_MAR | ARGUS_VERSION_5;
         retn->hdr.cause = ARGUS_START | ARGUS_SRC_RADIUM;
         retn->argus_mar.argusid = htonl(ARGUS_COOKIE);
         break;
   }
   
   retn->hdr.len   = htons((unsigned short) sizeof(struct ArgusRecord)/4);

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

   retn->argus_mar.major_version = version;
   retn->argus_mar.minor_version = VERSION_MINOR;
   retn->argus_mar.reportInterval = 0;

   if (getParserArgusID(ArgusParser, asptr)) {
   switch (version) {
      case ARGUS_VERSION_3: {
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
         break;
      }

      case ARGUS_VERSION_5: {
         switch (getArgusIDType(ArgusParser) & ~ARGUS_TYPE_INTERFACE) {
            case ARGUS_TYPE_STRING: {
               retn->argus_mar.status |= ARGUS_IDIS_STRING;
               bcopy (&asptr->a_un.str, &retn->argus_mar.str, 4);
               break;
            }
            case ARGUS_TYPE_INT: {
               retn->argus_mar.status |= ARGUS_IDIS_INT;
               retn->argus_mar.value = htonl(asptr->a_un.value);
               break;
            }
            case ARGUS_TYPE_IPV4: {
               retn->argus_mar.status |= ARGUS_IDIS_IPV4;
               retn->argus_mar.ipv4 = htonl(asptr->a_un.ipv4);
               break;
            }
            case ARGUS_TYPE_IPV6: {
               retn->argus_mar.status |= ARGUS_IDIS_IPV6;
               bcopy (&asptr->a_un.ipv6, &retn->argus_mar.ipv6, sizeof(retn->argus_mar.ipv6));
               break;
            }
            case ARGUS_TYPE_UUID: {
               retn->argus_mar.status |= ARGUS_IDIS_UUID;
               bcopy (&asptr->a_un.uuid, &retn->argus_mar.uuid, sizeof(retn->argus_mar.uuid));
               break;
            }
         }

         if (getArgusManInf(ArgusParser) != NULL)
            retn->argus_mar.status |=  ARGUS_ID_INC_INF;
         }
         break;
      }

      retn->argus_mar.status = htonl(retn->argus_mar.status);
   }

   retn->argus_mar.record_len = htonl(-1);

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusGenerateInitialMar() returning\n");
#endif

   return (retn);
}

struct ArgusRecordStruct *
ArgusGenerateStatusMarRecord(struct ArgusOutputStruct *output,
                             unsigned char status, char version)
{
   extern unsigned int ArgusAllocTotal, ArgusFreeTotal, ArgusAllocBytes;
   struct ArgusAddrStruct asbuf, *asptr = &asbuf;
   struct ArgusRecordStruct *retn;
   struct ArgusRecord *rec;
   struct timeval now;

   if ((retn = (struct ArgusRecordStruct *) ArgusCalloc (1, sizeof(*retn))) == NULL)
     ArgusLog (LOG_ERR, "ArgusGenerateStatusMarRecord(0x%x) ArgusCalloc error %s\n", output, strerror(errno));

   retn->hdr.type  = ARGUS_MAR | ARGUS_VERSION_5;
   retn->hdr.cause = ARGUS_STATUS | ARGUS_SRC_RADIUM;
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
                  rec->argus_mar.status |= ARGUS_IDIS_IPV6;
                  bcopy (&asptr->a_un.ipv6, &rec->argus_mar.ipv6, sizeof(rec->argus_mar.ipv6));
                  break;
               }
               case ARGUS_TYPE_UUID: {
                  rec->argus_mar.status |= ARGUS_IDIS_UUID;
                  bcopy (&asptr->a_un.uuid, &rec->argus_mar.uuid, sizeof(rec->argus_mar.uuid));
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

      rec->argus_mar.major_version = version;
      rec->argus_mar.minor_version = VERSION_MINOR;
      rec->argus_mar.reportInterval = 0;


      rec->argus_mar.argusMrInterval = output->ArgusMarReportInterval.tv_sec;

      rec->argus_mar.localnet = output->ArgusLocalNet;
      rec->argus_mar.netmask = output->ArgusNetMask;

      rec->argus_mar.nextMrSequenceNum = output->ArgusOutputSequence;
      rec->argus_mar.record_len = -1;
   }

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
setArgusZeroConf (struct ArgusParserStruct *parser, unsigned int type)
{
   parser->ArgusZeroConf = type;
}

unsigned int
getArgusZeroConf (struct ArgusParserStruct *parser)
{
   return (parser->ArgusZeroConf);
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
      unsigned int niflags;
      socklen_t salen;

      salen = sizeof(remoteaddr);
      bzero(hbuf, NI_MAXHOST);

      if ((getpeername(fd, (struct sockaddr *)&remoteaddr, &salen) == 0) &&
                         (remoteaddr.ss_family == AF_INET || remoteaddr.ss_family == AF_INET6)) {
         if (getnameinfo((struct sockaddr *)&remoteaddr, salen, hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) == 0) {
            strncpy(clienthost, hbuf, NI_MAXHOST);
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
      DrainArgusSocketQueue(client);
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
      client->delete = 1;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusDeleteSocket (0x%x) returning\n", asock);
#endif
}  


#include <sys/stat.h>
#include <fcntl.h>

#define ARGUS_MAXERROR		500000
#define ARGUS_MAXWRITENUM	64

static const int ArgusMaxListLength = 500000;
int ArgusCloseFile = 0;


static
void
ArgusWriteSocket(struct ArgusOutputStruct *output,
                 struct ArgusClientData *client,
                 struct ArgusWireFmtBuffer *awf)
{
   struct ArgusSocketStruct *asock = client->sock;
   struct ArgusListStruct *list = asock->ArgusOutputList;
   struct ArgusQueueNode *node;

   if (list->count > ArgusMaxListLength) {
      struct ArgusWireFmtBuffer *tawf;
      int i = 0;

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&list->lock);
#endif

      /* Get the queue length down to the max.  The addition below
       * will push it back over the max length and ArgusWriteOutSocket()
       * can later determine if it needs to hang up the connection.
       */
      while (list->count > ArgusMaxListLength) {
         node = (struct ArgusQueueNode *)ArgusPopFrontList(list, ARGUS_NOLOCK);
         if (node == NULL)
            break;

         tawf = node->datum;
         FreeArgusQueueNode(node);
         FreeArgusWireFmtBuffer(tawf);
         i++;
      }

      ArgusLog(LOG_WARNING, "%s: tossed %d record(s) for slow client %s\n",
               __func__, i, client->hostname);


#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&list->lock);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWriteSocket (0x%x, 0x%x, 0x%x) schedule buffer\n", output, asock, awf);
#endif

   node = NewArgusQueueNode(awf);
   if (node == NULL) {
#ifdef ARGUSDEBUG
      ArgusDebug(2, "%s: failed to allocate node for ArgusWireFmtBuffer\n",
                 __func__);
      return;
#endif
   }

   if (ArgusPushBackList(list, (struct ArgusListRecord *)node, ARGUS_LOCK))
      awf->refcount++;
   else
      FreeArgusQueueNode(node);
}


static
int
ArgusWriteOutSocket(struct ArgusOutputStruct *output,
                    struct ArgusClientData *client)
{
   struct ArgusSocketStruct *asock = client->sock;
   struct ArgusListStruct *list = NULL;
   int retn = 0, count = 0, len, ocnt;
   struct stat statbuf;
   unsigned char *ptr;
   struct ArgusWireFmtBuffer *awf;
   struct ArgusQueueNode *node;
   const char *outputbuf = NULL;
   unsigned outputlen = 0;

   if ((list = asock->ArgusOutputList) != NULL) {
      if (asock->rec != NULL)
         count = 1;

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&list->lock);
#endif
      if ((count += ArgusGetListCount(list)) > 0) {
         if (count > ARGUS_MAXWRITENUM)
            count = ARGUS_MAXWRITENUM;

         while ((asock->fd != -1 ) && count--) {
            if ((awf = asock->rec) == NULL) {
               asock->writen = 0;
               asock->length = 0;

               if ((node = (struct ArgusQueueNode *)ArgusPopFrontList(list, ARGUS_NOLOCK)) != NULL) {
                     awf = node->datum;
                     FreeArgusQueueNode(node);
                     switch (client->format) {
                        case ARGUS_DATA: {
#ifdef ARGUS_SASL
                              if (!client->sasl_conn) {
#endif
                                 outputlen = awf->len;
                                 outputbuf = (const char *)&awf->data.buf[0];
#ifdef ARGUS_SASL
                              } else {
                                 struct ArgusWireFmtBuffer *awfsasl;
                                 outputlen = 0;
                                 outputbuf = NULL;

                                 awfsasl = NewArgusWireFmtBuffer(NULL, -1, -1);
                                 if (awfsasl == NULL)
                                    /* no memory, try to keep going */
                                    continue;
#ifdef ARGUSDEBUG
                                 ArgusDebug (7, "ArgusHandleClientData: sasl_encode(0x%x, %d, 0x%x, 0x%x)\n",
                                                            client->sasl_conn, awf->len, &outputbuf, &outputlen);
#endif
                                 if ((retn = sasl_encode(client->sasl_conn, (const char *)&awf->data.buf[0],
                                                         awf->len, &outputbuf, &outputlen)) == SASL_OK) {
#ifdef ARGUSDEBUG
                                    ArgusDebug (7, "ArgusHandleClientData: sasl_encode returned %d bytes\n", outputlen);
#endif
                                    if (outputlen > ARGUS_MAXRECORD)
                                       ArgusLog (LOG_ERR, "sasl_encode: returned too many bytes %d\n", outputlen);

                                    /* replace the original buffer with
                                     * our sasl buffer.  It's only kept
                                     * around if the socket can't accept
                                     * the entire buffer this time.
                                     */
                                    memcpy(&awfsasl->data.buf[0], outputbuf, outputlen);
                                    FreeArgusWireFmtBuffer(awf);
                                    awf = awfsasl;
                                    awf->len = outputlen;

                                 } else
                                    ArgusLog (LOG_ERR, "sasl_encode: failed returned %d\n", retn);
                              }
#endif
                              asock->length = outputlen;
                              asock->rec = awf;

                           break;
                        }
                     }
               }
            }

            if (asock->rec != NULL) {
               awf = asock->rec;
               ptr = (unsigned char *)&awf->data.buf[0];
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
                                 output->ArgusInitMar = ArgusGenerateInitialMar(output, client->version);
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
                     if ((retn = sendto (asock->fd, (unsigned char *)&ptr[asock->writen], len, 0,
                                         client->host->ai_addr, client->host->ai_addrlen)) < 0)
                        ArgusLog (LOG_ERR, "ArgusInitOutput: sendto(): retn %d %s", retn, strerror(errno));
#ifdef ARGUSDEBUG
                     ArgusDebug (3, "ArgusWriteSocket: sendto (%d, %x, %d, ...) %d\n",
                                 asock->fd, outputbuf, outputlen, retn);
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
                           FreeArgusWireFmtBuffer(asock->rec);
                           asock->rec = NULL;
                        }
                        DrainArgusSocketQueue(client);

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
                              FreeArgusWireFmtBuffer(awf);
                              DrainArgusSocketQueue(client);

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
                  FreeArgusWireFmtBuffer(awf);
                  asock->rec = NULL;

               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (6, "ArgusWriteOutSocket: still work to be done for 0x%x, len %d writen %d turns %d", awf, asock->length, asock->writen, count);
#endif
               }

            } else {
               count = 0;
#ifdef ARGUSDEBUG
               ArgusDebug (6, "ArgusWriteOutSocket: nothing to be done for 0x%x, len %d writen %d", awf, asock->length, asock->writen);
#endif
            }
         }

         if (asock->errornum >= ARGUS_MAXERROR) {
            ArgusLog (LOG_WARNING, "ArgusWriteOutSocket(0x%x) client not processing (%d errors): disconnecting\n", asock, asock->errornum);
            close(asock->fd);
            asock->fd = -1;
            if (asock->rec != NULL) {
               FreeArgusWireFmtBuffer(asock->rec);
               asock->rec = NULL;
               asock->writen = 0;
               asock->length = 0;
            }
            DrainArgusSocketQueue(client);
            asock->errornum = 0;
            retn = -1;
         }

         if ((ArgusGetListCount(list)) > ArgusMaxListLength) {
            if (client->clientid == NULL) {
               ArgusLog(LOG_WARNING,
                        "ArgusWriteOutSocket(0x%x) max queue exceeded %d on client hostname %s\n",
                        asock, ArgusMaxListLength, client->hostname);
            } else {
               ArgusLog(LOG_WARNING,
                        "ArgusWriteOutSocket(0x%x) max queue exceeded %d on client hostname %s %s\n",
                        asock, ArgusMaxListLength, client->hostname, client->clientid);
            }
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
static
sasl_security_properties_t *
mysasl_secprops(int min_ssf, int max_ssf)
{
    static sasl_security_properties_t ret;

    bzero((char *)&ret, sizeof(ret));

    ret.maxbufsize = PROT_BUFSIZE;
    ret.min_ssf = min_ssf; /* minimum allowable security strength */
    ret.max_ssf = max_ssf; /* maximum allowable security strength */

    ret.security_flags = 0;
    
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
 

#ifdef ARGUS_SASL

int ArgusGetSaslString(FILE *, char *, int);
int ArgusSendSaslString(FILE *, const char *, int, int);

static int
ArgusAuthenticateClient (struct ArgusClientData *client, int use_sasl)
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

   if (use_sasl == 0)
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

#define MAR_RESPONSE_BUFLEN 1024
static char *mar_response_array[3];
static char *mar_response_buf = NULL;
static char **
ArgusHandleMARCommand(struct ArgusOutputStruct *output, char *command)
{
   struct ArgusRecordStruct *argus;

   mar_response_array[0] = "FAIL\n";
   mar_response_array[1] = NULL;

   if (mar_response_buf == NULL)
      mar_response_buf = ArgusMalloc(MAR_RESPONSE_BUFLEN);

   if (mar_response_buf == NULL)
      goto out;

   mar_response_buf[0] = 0;
   argus = ArgusGenerateStatusMarRecord(output, ARGUS_STATUS, ARGUS_VERSION);
   if (argus == NULL)
      goto out;

   ArgusPrintRecord(output->ArgusParser, mar_response_buf, argus,
                    MAR_RESPONSE_BUFLEN);
   mar_response_array[0] = mar_response_buf;
   mar_response_array[1] = "\n";
   mar_response_array[2] = NULL;

out:
      return mar_response_array;
}
