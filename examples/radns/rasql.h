/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software, released under the GNU General
 * Public License; you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software
 * Foundation; either version 3, or any later version.
 *
 * Other licenses are available through QoSient, LLC.
 * Inquire at info@qosient.com.
 *
 * This program is distributed WITHOUT ANY WARRANTY; without even the
 * implied warranty of * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * rasqlinsert  - Read Argus data and insert records into a
 *                database schema.
 *
 */

/*
 * $Id: //depot/gargoyle/clients/examples/radns/rasql.h#2 $
 * $DateTime: 2016/04/18 10:48:08 $
 * $Change: 3137 $
 */


#if !defined(RaDns_h)
#define RaDns_h

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>
  
#include <argus_compat.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
 
#include <argus_namedb.h>
#include <argus_filter.h>

#include <rasplit.h>
#include <argus_sort.h>
#include <argus_cluster.h>
 
#include <glob.h>
 
#include <syslog.h>
#include <signal.h>
#include <string.h>
  
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <math.h>
#include <ctype.h>
#include <errno.h>

#if defined(HAVE_IFADDRS_H) && HAVE_IFADDRS_H
#define HAVE_GETIFADDRS
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#endif

void RaProcessRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

struct RaOutputProcessStruct {
   int status, timeout;
   int value, size;
   struct ArgusRecordStruct *ns;
   struct ArgusQueueStruct *queue, *delqueue;
   struct ArgusHashTable *htable;
   struct nff_program filter;
};

#define ARGUS_FORWARD           1
#define ARGUS_BACKWARD          2
 
#define RA_DIRTYBINS            0x20

char RaOutputBuffer[MAXSTRLEN];
struct RaOutputProcessStruct *RaDnsNewProcess(struct ArgusParserStruct *parser);
void RaClientSortQueue (struct ArgusSorterStruct *, struct ArgusQueueStruct *, int);
void ArgusUpdateScreen(void);
void ArgusTouchScreen(void);

#if defined(ARGUS_THREADS)
pthread_attr_t RaDnsAttr;
pthread_t RaDnsThread      = 0;
pthread_t RaDataThread        = 0;
pthread_t RaDnsInputThread = 0;
#endif

#define RATOPSTARTINGINDEX	2
#define ARGUS_MAX_PROCESSORS	16

struct RaOutputProcessStruct *RaProcesses[ARGUS_MAX_PROCESSORS];

#define ARGUS_DISPLAY_PROCESS	0
#define ARGUS_EVENTS_PROCESS	1
#define ARGUS_HISTORY_PROCESS	2

char * ArgusTrimString (char *);

struct RaOutputProcessStruct *RaOutputProcess = NULL;

int ArgusCloseDown = 0;
int RaSortItems = 0;

float RaUpdateRate = 1.0;
int RaDnsRealTime = 0;
int RaCursorOffset = 0;
int RaCursorX = 0;
int RaCursorY = 0;

struct ArgusQueueStruct *ArgusModelerQueue = NULL;
struct ArgusQueueStruct *ArgusFileQueue = NULL;
struct ArgusQueueStruct *ArgusProbeQueue = NULL;
struct ArgusListStruct *ArgusSQLQueryList = NULL;
struct ArgusListStruct *ArgusSQLInsertQueryList = NULL;
struct ArgusListStruct *ArgusSQLSelectQueryList = NULL;
struct ArgusListStruct *ArgusSQLUpdateQueryList = NULL;

void RaResizeHandler (int);
void * ArgusDnsOutputProcess (void *);
void * ArgusProcessData (void *);
void * ArgusProcessCursesInput (void *);



int ArgusProcessCommand (struct ArgusParserStruct *, int, int);

char RaLastSearchBuf[MAXSTRLEN], *RaLastSearch = RaLastSearchBuf;
char RaLastCommandBuf[MAXSTRLEN], *RaLastCommand = RaLastCommandBuf;
int RaIter = 1, RaDigitPtr = 0;
char RaDigitBuffer[16];

#if defined(ARGUS_HISTORY)
#include <readline/history.h>

void argus_enable_history(void);
void argus_disable_history(void);
void argus_recall_history(void);
void argus_save_history(void);

int argus_history_is_enabled(void);
#endif

struct RaBinProcessStruct *ArgusNewRateBins (struct ArgusParserStruct *, struct ArgusRecordStruct *);

int ArgusTerminalColors = 0;
int ArgusDisplayStatus = 0;
int ArgusCursesEnabled = 0;

int ArgusSearchDirection = ARGUS_FORWARD;
int ArgusAlwaysUpdate    = 0;

struct timeval RaStartTime = {0x7FFFFFFF, 0x7FFFFFFF};
struct timeval RaEndTime   = {0, 0};

extern void ArgusInitAggregatorStructs(struct ArgusAggregatorStruct *);

void RaMySQLInit (void);

void RaDnsLoop (struct ArgusParserStruct *);
void RaOutputModifyScreen (void);
void RaOutputHelpScreen (void);
int RaSearchDisplay (struct ArgusParserStruct *, struct ArgusQueueStruct *, int, int *, int *, char *, int);

struct RaBinProcessStruct *RaBinProcess = NULL;

struct RaTopProcessStruct *RaTopNewProcess(struct ArgusParserStruct *parser);

char *ArgusGenerateProgramArgs(struct ArgusParserStruct *);
char RaProgramArgs[MAXSTRLEN];


int RaOutputStatus    = 1;
int RaOutputModified  = 1;
int RaOutputImmediate = 1;

struct timeval RaDnsStartTime      = {0, 0};
struct timeval RaDnsStopTime       = {0, 0};
struct timeval RaDnsUpdateTime     = {1, 0};
struct timeval RaDnsUpdateInterval = {0, 20000};
struct timeval RaProbeUptime       = {0, 0};

void clearArgusWfile(struct ArgusParserStruct *);

int RaDnsInit         = 0;
int RaServerMode      = 0;

extern void RaClientSortQueue (struct ArgusSorterStruct *, struct ArgusQueueStruct *, int);
extern char * ArgusTrimString (char *);

#if defined(ARGUS_THREADS)
extern pthread_attr_t RaDnsAttr;
extern pthread_t RaDnsThread;
extern pthread_t RaDataThread;
extern pthread_t RaDnsInputThread;
#endif

#define RATOPSTARTINGINDEX       2

extern struct RaOutputProcessStruct *RaOutputProcess;

extern struct ArgusListStruct *ArgusSQLQueryList;
extern struct ArgusListStruct *ArgusSQLInsertQueryList;
extern struct ArgusListStruct *ArgusSQLSelectQueryList;
extern struct ArgusListStruct *ArgusSQLUpdateQueryList;

extern int RaOutputStatus;
extern int RaOutputModified;
extern int RaOutputImmediate;
extern int RaSortItems;

extern float RaUpdateRate;
extern int RaDnsRealTime;

extern struct timeval ArgusLastRealTime;
extern struct timeval ArgusLastTime;
extern struct timeval ArgusThisTime;
extern struct timeval ArgusCurrentTime;

extern struct timeval dLastTime;
extern struct timeval dRealTime;
extern struct timeval dThisTime;
extern struct timeval dTime;

extern long long thisUsec;
extern long long lastUsec;

extern struct ArgusQueueStruct *ArgusModelerQueue;
extern struct ArgusQueueStruct *ArgusFileQueue;
extern struct ArgusQueueStruct *ArgusProbeQueue;
extern struct ArgusListStruct *ArgusSQLQueryList;

extern void * ArgusProcessData (void *);

extern int RaIter, RaDigitPtr;
extern char RaDigitBuffer[16];

extern struct RaBinProcessStruct *ArgusNewRateBins (struct ArgusParserStruct *, struct ArgusRecordStruct *);

extern int ArgusSearchDirection;
extern int ArgusAlwaysUpdate;

extern int ArgusCursesEnabled;

extern struct timeval RaStartTime;
extern struct timeval RaEndTime;

extern void ArgusInitAggregatorStructs(struct ArgusAggregatorStruct *);

extern char *ArgusGenerateProgramArgs(struct ArgusParserStruct *);
extern char RaProgramArgs[MAXSTRLEN];

extern struct timeval RaDnsStartTime;
extern struct timeval RaDnsStopTime;
extern struct timeval RaDnsUpdateTime;
extern struct timeval RaDnsUpdateInterval;
extern struct timeval RaProbeUptime;

extern void clearArgusWfile(struct ArgusParserStruct *);

extern int RaFilterIndex;
extern int ArgusPrintTotals;

#endif  // RaDns_h
