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
 * $Id: //depot/gargoyle/clients/include/argus_main.h#9 $
 * $DateTime: 2016/10/24 12:28:54 $
 * $Change: 3227 $
 */

#ifndef ArgusMain_h
#define ArgusMain_h

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include <netdb.h>

#include <argus_def.h>
#include <argus_out.h>

#include <net/nff.h>

#define MINOR_VERSION_0    0
#define MINOR_VERSION_1    1
#define MINOR_VERSION_2    2
#define MINOR_VERSION_3    3
#define MINOR_VERSION_4    4
#define MINOR_VERSION_5    5
#define MINOR_VERSION_6    6
#define MINOR_VERSION_7    7
#define MINOR_VERSION_8    8
#define MINOR_VERSION_9    9
#define MAJOR_VERSION_1    1
#define MAJOR_VERSION_2    2
#define MAJOR_VERSION_3    3
#define MAJOR_VERSION_4    4
#define MAJOR_VERSION_5    5
#define MAJOR_VERSION_6    6
#define VERSION_MAJOR      MAJOR_VERSION_5
#define VERSION_MINOR      MINOR_VERSION_0

#ifndef MAXPATHNAMELEN
#define MAXPATHNAMELEN          BUFSIZ
#endif

#define ARGUS_DEFAULTPORT	561

#define ARGUS_ENCODE_ASCII	0
#define ARGUS_ENCODE_64		1
#define ARGUS_ENCODE_32		2
#define ARGUS_HEXDUMP		3
#define ARGUS_ENCODE_OBFUSCATE	4
 
#define ARGUS_FILE		1
#define ARGUS_SOCKET		2

 
struct naddrmem {
   struct naddrmem *nxt;
   unsigned int addr;
   unsigned short port;
};

struct ArgusModeStruct {
   struct ArgusModeStruct *nxt;
   char *mode;
};

struct ArgusRfileStruct {
   struct ArgusListObjectStruct *nxt;
   char *name;
};

struct ArgusLfileStruct {
   struct ArgusListObjectStruct *nxt;
   char *filename;
   FILE *fd;

   struct stat statbuf;
};

#define ARGUS_DATA		0x01
#define ARGUS_CISCO_V5_DATA	0x02
#define ARGUS_CISCO_V9_DATA	0x04
#define ARGUS_IPFIX_DATA	0x08

struct ArgusWfileStruct {
   struct ArgusListObjectStruct *nxt, *prv;
   struct ArgusHashTableHdr *htblhdr;
   struct ArgusAggregatorStruct *agg;

   char *filename, *filetarget, *command;
   char *filterstr;

   FILE *fd;
   int format;
   struct stat statbuf;
   struct nff_program filter;
   int firstWrite, startSecs, endSecs;
   struct timeval laststat;
   struct timeval stime, etime;
#ifdef HAVE_FCNTL_H
   struct flock lock;
#endif
};


#define MAXTIME			100000
#define READ_REMOTE_CON		0x40000000
#define READ_LOCAL_CON		0x20000000

#define ARGUS_MAX_REMOTE_CONN		5

#define RA_REQ_STATE	0
#define RA_ACC_STATE	1
#define RA_CON_STATE	2
#define RA_CLO_STATE	3
#define RA_TIM_STATE	4
#define RA_RST_STATE	5
#define RA_FIN_STATE	6
#define RA_STA_STATE	7


extern int ArgusAuthenticate (struct ArgusInput *);
int RaOnePassComplete(void);


#ifdef ArgusMain

#define MAXPROCSTATE		8

struct timeval RaClientTimeout = {1,0};

char *process_state_strings [MAXPROCSTATE] = {
   "REQ", "ACC", "CON", "CLO", "TIM", "RST", "FIN", "STA",
};

extern struct ArgusParserStruct *ArgusParser;

#if defined(CYGWIN)
#include <getopt.h>
#endif

extern void RaClearConfiguration (struct ArgusParserStruct *);
 
void ArgusMainInit (struct ArgusParserStruct *, int, char **);
void setArgusArchive(struct ArgusParserStruct *, char *);
void setArgusLfile(struct ArgusParserStruct *, char *);
void setArgusWfile(struct ArgusParserStruct *, char *, char *);
void ArgusInitStructs (struct ArgusParserStruct *);
void setArguspidflag (struct ArgusParserStruct *, int);
int getArguspidflag (struct ArgusParserStruct *);

extern char *ArgusCreatePIDFile (struct ArgusParserStruct *, char *);
extern int ArgusDeletePIDFile (struct ArgusParserStruct *);

extern void clearArgusWfile(struct ArgusParserStruct *);

extern void usage (void);

extern void RaArgusInputComplete (struct ArgusInput *);

void ArgusShutDown (int);
extern void RaParseComplete (int);

void ArgusParseInit (struct ArgusParserStruct *parser, struct ArgusInput *);

void ArgusProcessSOptions (struct ArgusParserStruct *);
void ArgusProcessStripOptions (struct ArgusParserStruct *, char *);

void read_udp_services (char *);

int RaProcessArchiveFiles (char *, int);
int RaProcessRecursiveFiles (char *, int);

int RaScheduleRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int ArgusHandleDatum (struct ArgusParserStruct *, struct ArgusInput *, struct ArgusRecord *, struct nff_program *);
int ArgusHandleRecord (struct ArgusParserStruct *, struct ArgusInput *, struct ArgusRecord *, unsigned long, struct nff_program *);
int ArgusHandleRecordStruct (struct ArgusParserStruct *, struct ArgusInput *, struct ArgusRecordStruct *, struct nff_program *);
void ArgusReformatRecord (struct ArgusRecord *, struct ArgusRecord *);

extern int ArgusReadConnection (struct ArgusParserStruct *parser, struct ArgusInput *, int);
void ArgusReadStreams (struct ArgusParserStruct *parser, struct ArgusQueueStruct *);
void ArgusReadStream (struct ArgusParserStruct *parser, struct ArgusQueueStruct *);
void ArgusReadFileStream (struct ArgusParserStruct *parser, struct ArgusInput *);

int ArgusProcessRecord (struct ArgusRecordStruct *);

void ArgusGenerateCanonicalRecord (struct ArgusRecord *, struct ArgusCanonRecord *);

int ArgusGetServerSocket (struct ArgusInput *, int);

int ArgusAddBaselineList (struct ArgusParserStruct *, char *, int, long long, long long);
int ArgusPushBaselineList (struct ArgusParserStruct *, char *, int, long long, long long);
struct ArgusFileInput *ArgusPopBaselineList (struct ArgusParserStruct *);
void ArgusDeleteBaselineList (struct ArgusParserStruct *);

int ArgusAddFileList (struct ArgusParserStruct *, char *, int, long long, long long);
int ArgusPushFileList (struct ArgusParserStruct *, char *, int, long long, long long);
void ArgusDeleteFileList (struct ArgusParserStruct *);
int ArgusAddServerList (struct ArgusParserStruct *, char *, int, int);
void ArgusDeleteServerList (struct ArgusParserStruct *);
int ArgusAddModeList (struct ArgusParserStruct *, char *);
void ArgusDeleteModeList (struct ArgusParserStruct *);
int ArgusAddMaskList (struct ArgusParserStruct *, const char * const);
void ArgusDeleteMaskList (struct ArgusParserStruct *);

extern int ArgusParseAliasFile (char *);

int ArgusWriteNewLogfile (struct ArgusParserStruct *parser, struct ArgusInput *, struct ArgusWfileStruct *, struct ArgusRecord *);

int parseUserDataArg (char **, char **, int);
int ArgusCheckTimeFormat (struct tm *tm, char *str);
int ArgusParseTime (char *, struct tm *, struct tm *, char *, char, int *, int);

char *ArgusCopyArgv(char **);


#else /* ArgusMain */
 
extern char *ArgusProgramArgs;
extern char *process_state_strings [];

extern char *RaDatabase;
extern char **RaTables;
extern int ArgusGrepSource;
extern int ArgusGrepDestination;

extern struct ArgusParserStruct *ArgusParser;
extern struct timeval ArgusRealTime;
extern struct timeval ArgusGlobalTime;

extern char *RaInputFilter[];
extern char *RaTimeFormat;
extern char  RaFieldDelimiter;

extern int RaCloseInputFd;

extern u_int ArgusThisFarStatus;
extern struct ArgusDSRHeader *ArgusThisDsrs[];

extern char *exceptfile, *wfile;

extern struct ArgusInput *ArgusInput;
extern struct ArgusInput *ArgusInputFileList;
extern struct ArgusInput *ArgusRemoteServerList;
extern struct ArgusModeStruct *ArgusModeList;
extern struct ArgusModeStruct *ArgusMaskList;

extern char *tag_string;
extern int major_version;
extern int minor_version;
extern int read_size;
extern int read_mode;

extern struct ArgusRecord *initCon;

extern unsigned int ArgusLocalNet, ArgusNetMask;

extern struct ArgusRecord *ArgusOriginal;

extern int totalrecords;
extern int farrecords;
extern int marrecords;
extern int explicit_date;
 
extern long thiszone;

extern int total_nets;
extern int total_hosts;

extern char *ArgusCopyArgv(char **);
extern void ArgusShutDown (int);
extern void ArgusParseInit (struct ArgusParserStruct *parser, struct ArgusInput *);
extern char *argus_lookupdev(char *);

extern void ArgusProcessSOptions (struct ArgusParserStruct *);
extern void ArgusProcessStripOptions (struct ArgusParserStruct *, char *);

extern void read_udp_services (char *);

extern void setArgusRank(struct ArgusParserStruct *, int);
extern int getArgusRank(struct ArgusParserStruct *);

extern void setArgusArchive(struct ArgusParserStruct *, char *);
extern void setArgusLfile(struct ArgusParserStruct *, char *);
extern void setArgusWfile(struct ArgusParserStruct *, char *, char *);

extern int RaProcessArchiveFiles (char *, int);
extern int RaProcessRecursiveFiles (char *, int);

extern int RaScheduleRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern int ArgusHandleDatum (struct ArgusParserStruct *, struct ArgusInput *, struct ArgusRecord *, struct nff_program *);
extern int ArgusHandleRecord (struct ArgusParserStruct *, struct ArgusInput *, struct ArgusRecord *, unsigned long, struct nff_program *);
extern int ArgusHandleRecordStruct (struct ArgusParserStruct *, struct ArgusInput *, struct ArgusRecordStruct *, struct nff_program *);
extern void ArgusReformatRecord (struct ArgusRecord *, struct ArgusRecord *);
extern int ArgusReadRemoteConnection (int, struct nff_program *);
extern int ArgusReadConnection (struct ArgusParserStruct *parser, struct ArgusInput *, int);
extern void ArgusReadStreams (struct ArgusParserStruct *parser, struct ArgusQueueStruct *);
extern void ArgusReadStream (struct ArgusParserStruct *parser, struct ArgusQueueStruct *);
extern void ArgusReadFileStream (struct ArgusParserStruct *parser, struct ArgusInput *);

extern int ArgusProcessRecord (struct ArgusRecordStruct *);

extern void ArgusGenerateCanonicalRecord (struct ArgusRecord *, struct ArgusCanonRecord *);
extern void ArgusReadRemote (int, struct nff_program *);
extern int read_file (int fd, struct nff_program *);

extern int ArgusParseAliasFile (char *);

extern int ArgusGetServerSocket (struct ArgusInput *, int);

extern int ArgusAddFileList (struct ArgusParserStruct *, char *, int, long long, long long);
extern int ArgusPushFileList (struct ArgusParserStruct *, char *, int, long long, long long);
extern void ArgusDeleteFileList (struct ArgusParserStruct *);

extern int ArgusAddBaselineList (struct ArgusParserStruct *, char *, int, long long, long long);
extern int ArgusPushBaselineList (struct ArgusParserStruct *, char *, int, long long, long long);
extern struct ArgusFileInput *ArgusPopBaselineList (struct ArgusParserStruct *);
extern void ArgusDeleteBaselineList (struct ArgusParserStruct *);

extern int ArgusAddServerList (struct ArgusParserStruct *, char *, int, int);
extern void ArgusDeleteServerList (struct ArgusParserStruct *);
extern int ArgusAddModeList (struct ArgusParserStruct *, char *);
extern void ArgusDeleteModeList (struct ArgusParserStruct *);
extern int ArgusAddMaskList (struct ArgusParserStruct *, const char * const);
extern void ArgusDeleteMaskList (struct ArgusParserStruct *);

extern int ArgusWriteNewLogfile (struct ArgusParserStruct *parser, struct ArgusInput *, struct ArgusWfileStruct *, struct ArgusRecord *);

extern int parseUserDataArg (char **, char **, int);
extern int ArgusCheckTimeFormat (struct tm *tm, char *str);
extern int ArgusParseTime (char *, struct tm *, struct tm *, char *, char, int *, int);

#endif

struct ArgusModeStruct *
RaParseSplitMode(struct ArgusParserStruct *,
                 struct RaBinProcessStruct **,
                 struct ArgusModeStruct *,
                 int *);

#ifdef __cplusplus
}
#endif
#endif /* ArgusMain */

