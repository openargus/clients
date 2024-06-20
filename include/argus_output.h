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
 * $Id: //depot/gargoyle/clients/include/argus_output.h#13 $ 
 * $DateTime: 2016/09/13 16:02:42 $ 
 * $Change: 3182 $ 
 */


#ifndef ArgusRadium_h
#define ArgusRadium_h

#ifdef __cplusplus
extern "C" {
#endif

#define ARGUS_MONITORPORT	561

#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <sys/wait.h>

#if defined(__NetBSD__)
#include <sys/sched.h>
#else
#include <sched.h>
#endif

#include <fcntl.h>
#include <signal.h>
#include <ctype.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>

#include <argus_filter.h>
#include "ring.h"

#ifdef ARGUS_SASL
#include <sasl/sasl.h>
#endif

// Type transport type
#define ARGUS_NAMED_PIPE_OUTPUT		0x200

#define ARGUS_READINGPREHDR     	1
#define ARGUS_READINGHDR        	2
#define ARGUS_READINGBLOCK      	4

#define ARGUS_WAS_FUNCTIONAL            0x10
#define ARGUS_SOCKET_COMPLETE           0x20
#define ARGUS_MAXRECORD                 0x40000

#define ARGUS_CLIENT_STARTUP_TIMEOUT	5

struct ArgusSocketStruct {
   struct ArgusListStruct *ArgusOutputList;
   int fd, status, cnt, expectedSize, errornum;
   int ArgusLastRecord, ArgusReadState;
   struct timeval lastwrite;
   unsigned char *ptr;
   void *rec;
   int length, writen;
   struct sockaddr sock;
   struct stat statbuf;
   char *filename;
   void *obj;
};


struct ArgusClientData {
   struct ArgusQueueHeader qhdr;
   int fd, pid, ArgusClientStart;
   int ArgusFilterInitialized;
   int ArgusGeneratorInitialized;
   struct timeval startime, lasttime;
   struct ArgusSocketStruct *sock;
   struct nff_program ArgusNFFcode;
   char *filename, *hostname, *filter;
   char *clientid;
   int format;
   struct RingBuffer ring;
   char readable;
   char version;
   char delete; /* marked for deletion if > 0 */

#if defined(HAVE_GETADDRINFO)
   struct addrinfo *host;
#endif

#ifdef ARGUS_SASL
   sasl_conn_t *sasl_conn;
   struct {
      char *ipremoteport;
      char *iplocalport;
      sasl_ssf_t ssf;
      char *authid;
   } saslprops;
#endif
};

struct ArgusOutputStruct {
   int status, format;

#if defined(ARGUS_THREADS)
   pthread_t thread;
   pthread_mutex_t lock;
   int ListenNotify[2]; /* used by output thread to signal the listen thread
                         * that it is finished reading the client's command
                         */
#endif

   struct ArgusSourceStruct *ArgusSrc;
   struct ArgusParserStruct *ArgusParser;
   struct ArgusListStruct *ArgusWfileList;
   struct ArgusListStruct *ArgusInputList;
   struct ArgusListStruct *ArgusOutputList;
   struct ArgusQueueStruct *ArgusClients;
   struct ArgusRecord *ArgusInitMar;

   long long ArgusTotalRecords, ArgusLastRecords;
   int ArgusWriteStdOut, ArgusOutputSequence;
   unsigned short ArgusPortNum, ArgusControlPort;
   int ArgusUseWrapper, nflag;
   int ArgusLfd[ARGUS_MAXLISTEN];
   char ArgusLfdVersion[ARGUS_MAXLISTEN];
   int ArgusListens;
   int sasl_min_ssf;
   int sasl_max_ssf;
   int auth_localhost;
 
   char *ArgusBindAddr;

   struct timeval ArgusGlobalTime;
   struct timeval ArgusStartTime;
   struct timeval ArgusReportTime;
   struct timeval ArgusNextUpdate;
   struct timeval ArgusLastMarUpdateTime;
   struct timeval ArgusMarReportInterval;
   unsigned int ArgusLocalNet, ArgusNetMask;
};

typedef char** (*ArgusControlHandler)
               (struct ArgusOutputStruct *, char *);

struct ArgusControlHandlerStruct {
  char *command;
  ArgusControlHandler handler;
};

#define CONTROL_START                   0
#define CONTROL_DONE                    1
#define CONTROL_DISPLAY                 2
#define CONTROL_HIGHLIGHT               3
#define CONTROL_SEARCH                  4
#define CONTROL_FILTER                  5
#define CONTROL_TREE                    6


#if defined(ArgusOutput)

struct ArgusOutputStruct *ArgusOutputTask = NULL;

void *ArgusListenProcess(void *arg);
void *ArgusOutputProcess(void *);

void ArgusUsr1Sig (int);
void ArgusUsr2Sig (int);
void ArgusChildExit (int);


void ArgusClientError(void);
void ArgusInitClientProcess(struct ArgusClientData *, struct ArgusWfileStruct *);

void setArgusOutputVersion (struct ArgusOutputStruct *, char *);
int getArgusOutputVersion (struct ArgusOutputStruct *);
void ArgusCloseListen(struct ArgusParserStruct *);

void ArgusSendFile (struct ArgusOutputStruct *, struct ArgusClientData *, char *, int);


#else

#define ARGUS_MAXPROCESS		0x10000

extern void clearArgusWfile(struct ArgusParserStruct *);

int  ArgusTcpWrapper (struct ArgusOutputStruct *, int, struct sockaddr *, char *);

int RadiumParseResourceFile (struct ArgusParserStruct *, char *);
int ArgusEstablishListen(struct ArgusParserStruct *,
                         struct ArgusOutputStruct *,
                         int, char *, char);

struct ArgusRecordStruct *
ArgusGenerateStatusMarRecord (struct ArgusOutputStruct *, unsigned char, char);

extern void setArgusOutputVersion (struct ArgusOutputStruct *, char *);
extern int getArgusOutputVersion (struct ArgusOutputStruct *);
extern void ArgusCloseListen(struct ArgusParserStruct *);
void setArgusMarReportInterval (struct ArgusParserStruct *, char *);
struct timeval *getArgusMarReportInterval(struct ArgusParserStruct *);
void setArgusPortNum (struct ArgusParserStruct *, int, char *);
int getArgusPortNum(struct ArgusParserStruct *);
void setArgusOflag(struct ArgusParserStruct *, unsigned int);
void setArgusBindAddr (struct ArgusParserStruct *, char *);

void setParserArgusID(struct ArgusParserStruct *, void *, int, unsigned int);
void ArgusParseSourceID (struct ArgusParserStruct *, char *);

extern void ArgusSendFile (struct ArgusOutputStruct *, struct ArgusClientData *, char *, int);

void setArgusZeroConf(struct ArgusParserStruct *, unsigned int);
unsigned int getArgusZeroConf(struct ArgusParserStruct *);

void clearRadiumConfiguration (void);

struct ArgusRecordStruct *ArgusCopyRecordStruct (struct ArgusRecordStruct *);

void *ArgusListenProcess(void *arg);
void *ArgusOutputProcess(void *);
void ArgusInitOutput (struct ArgusOutputStruct *);
struct ArgusOutputStruct *ArgusNewOutput (struct ArgusParserStruct *, int, int, int);
void ArgusDeleteOutput (struct ArgusParserStruct *, struct ArgusOutputStruct *);
void ArgusCloseOutput(struct ArgusOutputStruct *);

void ArgusInitControlChannel (struct ArgusOutputStruct *);
struct ArgusOutputStruct *ArgusNewControlChannel (struct ArgusParserStruct *);
void ArgusDeleteControlChannel (struct ArgusParserStruct *, struct ArgusOutputStruct *);
void ArgusCloseControlChannel (struct ArgusOutputStruct *);

struct ArgusSocketStruct *ArgusNewSocket (int);
void ArgusDeleteSocket (struct ArgusOutputStruct *, struct ArgusClientData *);

extern void ArgusLoadList(struct ArgusListStruct *, struct ArgusListStruct *);
extern void ArgusCloseInput(struct ArgusParserStruct *parser, struct ArgusInput *);
extern void ArgusDeleteInput(struct ArgusParserStruct *parser, struct ArgusInput *);

extern struct ArgusOutputStruct *ArgusOutputTask;

extern void ArgusCloseSocket (int);
extern void ArgusCloseClients (void);

extern void ArgusUsr1Sig (int);
extern void ArgusUsr2Sig (int);

extern void ArgusClientError(void);
extern void ArgusInitClientProcess(struct ArgusClientData *, struct ArgusWfileStruct *);

extern struct ArgusControlHandlerStruct ArgusControlCommands[];
#endif
#ifdef __cplusplus
}
#endif
#endif /* #ifndef ArgusRadium_h */

