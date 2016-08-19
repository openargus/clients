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
 * $Id: //depot/argus/clients/include/argus_output.h#6 $ 
 * $DateTime: 2016/06/01 15:17:28 $ 
 * $Change: 3148 $ 
 */


#ifndef ArgusRadium_h
#define ArgusRadium_h

#ifdef __cplusplus
extern "C" {
#endif

#define ARGUS_MONITORPORT	561
#define ARGUS_MAXLISTEN		32

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

#ifdef ARGUS_SASL
#include <sasl/sasl.h>
#endif

#define ARGUS_READINGPREHDR     1
#define ARGUS_READINGHDR        2
#define ARGUS_READINGBLOCK      4

#define ARGUS_WAS_FUNCTIONAL            0x10
#define ARGUS_SOCKET_COMPLETE           0x20
#define ARGUS_MAXRECORD                 0x10000

#define ARGUS_CLIENT_STARTUP_TIMEOUT	5

struct ArgusSocketStruct {
   struct ArgusListStruct *ArgusOutputList;
   int fd, status, cnt, expectedSize, errornum;
   int ArgusLastRecord, ArgusReadState;
   struct timeval lastwrite;
   unsigned char buf[ARGUS_MAXRECORD], *ptr;
   struct ArgusRecordStruct *rec;
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
   struct timeval startime, lasttime;
   struct ArgusSocketStruct *sock;
   struct nff_program ArgusNFFcode;
   char *filename, *hostname, *filter;
   int format;

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
   int ArgusPortNum, nflag;
   int ArgusLfd[ARGUS_MAXLISTEN];
   int ArgusListens;
 
   char *ArgusBindAddr;

   struct timeval ArgusGlobalTime;
   struct timeval ArgusStartTime;
   struct timeval ArgusReportTime;
   struct timeval ArgusNextUpdate;
   struct timeval ArgusLastMarUpdateTime;
   struct timeval ArgusMarReportInterval;
   unsigned int ArgusLocalNet, ArgusNetMask;
};



#if defined(ArgusOutput)

struct ArgusOutputStruct *ArgusOutputTask = NULL;

void *ArgusOutputProcess(void *);

void ArgusUsr1Sig (int);
void ArgusUsr2Sig (int);
void ArgusChildExit (int);

void ArgusClientError(void);
void ArgusInitClientProcess(struct ArgusClientData *, struct ArgusWfileStruct *);

#else



#define ARGUS_MAXPROCESS		0x10000

extern void clearArgusWfile(struct ArgusParserStruct *);

int  ArgusTcpWrapper (int, struct sockaddr *, char *);

int RadiumParseResourceFile (struct ArgusParserStruct *, char *);
int ArgusEstablishListen (struct ArgusParserStruct *, int, char *);

struct ArgusRecord *ArgusGenerateInitialMar (struct ArgusOutputStruct *);
struct ArgusRecordStruct *ArgusGenerateInitialMarRecord (struct ArgusOutputStruct *);
struct ArgusRecordStruct *ArgusGenerateStatusMarRecord (struct ArgusOutputStruct *, unsigned char);

void setArgusMarReportInterval (struct ArgusParserStruct *, char *);
struct timeval *getArgusMarReportInterval(struct ArgusParserStruct *);
void setArgusPortNum (struct ArgusParserStruct *, int, char *);
int getArgusPortNum(struct ArgusParserStruct *);
void setArgusOflag(struct ArgusParserStruct *, unsigned int);
unsigned int getArgusIDType(struct ArgusParserStruct *);
void setArgusBindAddr (struct ArgusParserStruct *, char *);
void setArgusID(struct ArgusParserStruct *, void *, unsigned int);
unsigned int getArgusID(struct ArgusParserStruct *);
void clearRadiumConfiguration (void);

struct ArgusRecordStruct *ArgusCopyRecordStruct (struct ArgusRecordStruct *);

void *ArgusOutputProcess(void *);
void ArgusInitOutput (struct ArgusOutputStruct *);
struct ArgusOutputStruct *ArgusNewOutput (struct ArgusParserStruct *);
void ArgusDeleteOutput (struct ArgusParserStruct *, struct ArgusOutputStruct *);
struct ArgusSocketStruct *ArgusNewSocket (int);
void ArgusDeleteSocket (struct ArgusOutputStruct *, struct ArgusClientData *);
void ArgusCloseOutput(struct ArgusOutputStruct *);

int ArgusWriteSocket (struct ArgusOutputStruct *, struct ArgusClientData *, struct ArgusRecordStruct *);
int ArgusWriteOutSocket (struct ArgusOutputStruct *, struct ArgusClientData *);

extern void ArgusLoadList(struct ArgusListStruct *, struct ArgusListStruct *);
extern void ArgusCloseInput(struct ArgusParserStruct *parser, struct ArgusInput *);

extern struct ArgusOutputStruct *ArgusOutputTask;

extern void ArgusCloseSocket (int);
extern void ArgusCloseClients (void);

extern void ArgusUsr1Sig (int);
extern void ArgusUsr2Sig (int);

extern void ArgusClientError(void);
extern void ArgusInitClientProcess(struct ArgusClientData *, struct ArgusWfileStruct *);

#endif
#ifdef __cplusplus
}
#endif
#endif /* #ifndef ArgusRadium_h */

