/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
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
 * rasqlinsert  - Read Argus data and insert records into a
 *                database schema.
 *
 */

/*
 * $Id: //depot/gargoyle/clients/examples/ramysql/rasqlinsert.h#10 $
 * $DateTime: 2016/12/05 10:32:59 $
 * $Change: 3255 $
 */


#ifndef __RAMYSQL_RASQLINSERT_H
#define __RAMYSQL_RASQLINSERT_H

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

#define ARGUS_COLOR_SUPPORT
 
#if defined(ARGUS_CURSES)
#if defined(HAVE_NCURSES_H)
#include <ncurses.h>
#endif
#if defined(HAVE_CURSES_H)
#include <curses.h>
#endif
  
#if defined(__NetBSD__) || defined(CYGWIN)
#include <termios.h>
#else
#include <term.h>
#endif // NetBSD || CYGWIN 
#endif /* ARGUS_CURSES */
 
struct ArgusSQLQueryStruct {
   struct ArgusListObjectStruct *nxt;
   char *tbl, *sptr, *dptr;
};


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
 
#define ARGUS_REMOTE_FILTER     1
#define ARGUS_LOCAL_FILTER      2
#define ARGUS_DISPLAY_FILTER    3
 
#define RAMON_NETS_CLASSA       0
#define RAMON_NETS_CLASSB       1
#define RAMON_NETS_CLASSC       2
#define RAMON_NETS_CLASS        3
 
#define RA_DIRTYBINS            0x20


struct ArgusWindowStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusQueueStruct *queue;
 
   WINDOW *window;

#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
#endif
   char *desc;
   int (*data)(struct ArgusWindowStruct *);
   void *values[2048];
};


struct ArgusDomainStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusQueueStruct *queue;
  
   struct ArgusAddrStruct srcid;
   struct ArgusWindowStruct *ws;
};

extern struct timeval RaCursesUpdateInterval;

#if defined(RA_CURSES_MAIN)

#if defined(HAVE_ZLIB_H)
#include <zlib.h>
#endif

void ArgusThreadsInit(pthread_attr_t *);
int RaCursesClose(struct ArgusParserStruct *parser, pthread_attr_t *);
int RaHighlightDisplay (struct ArgusParserStruct *, struct ArgusQueueStruct *, char *);
int RaCursesSetWindowFocus(struct ArgusParserStruct *, WINDOW *);
WINDOW *RaCursesGetWindowFocus(struct ArgusParserStruct *);
extern void ArgusSetDebugString (char *, int, int);
extern void ArgusCopyDebugString (char *, int);
extern void ArgusZeroDebugString (void);

struct RaAddressStruct *RaFindAddress (struct ArgusParserStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);

int ArgusCloseDown = 0;

void ArgusResetSearch (void);
struct ArgusRecordStruct *ArgusSearchHitRecord = NULL;
int ArgusSearchHitRank = 0;

struct ArgusQueueStruct *ArgusWindowQueue = NULL;
int ArgusProcessQueue (struct ArgusQueueStruct *);
void ArgusGetInterfaceAddresses(struct ArgusParserStruct *);

int ArgusProcessQueue (struct ArgusQueueStruct *);
int ArgusCorrelateRecord (struct ArgusRecordStruct *);
int ArgusCorrelateQueue (struct ArgusQueueStruct *);

struct ArgusWindowStruct *RaCurrentWindow = NULL;
struct ArgusQueueStruct *ArgusDomainQueue = NULL;

struct ArgusWindowStruct *RaHeaderWindowStruct = NULL;
struct ArgusWindowStruct *RaDebugWindowStruct  = NULL;
struct ArgusWindowStruct *RaStatusWindowStruct = NULL;
struct ArgusWindowStruct *RaDataWindowStruct   = NULL;

#define ARGUS_LIGHT     230
#define ARGUS_DARK      234

int ArgusBackGround = ARGUS_DARK;
#if defined(ARGUS_THREADS)
pthread_mutex_t RaCursesLock;
#endif

struct ArgusAttributeStruct {
   attr_t attr;
   short pair;
};

struct ArgusAttributeStruct *RaColorArray = NULL;

#if defined(ARGUS_COLOR_SUPPORT)

#define ARGUS_MAX_COLOR_ALG	128

#define ARGUS_BLACK     0
#define ARGUS_RED       1
#define ARGUS_GREEN     2
#define ARGUS_YELLOW    3
#define ARGUS_BLUE      4
#define ARGUS_MAGENTA   5
#define ARGUS_CYAN      6
#define ARGUS_WHITE     7
#define ARGUS_ORANGE    8
#define ARGUS_VIOLET    9

#define ARGUS_BASE03	10
#define ARGUS_BASE02	11
#define ARGUS_BASE01	12
#define ARGUS_BASE00	13
#define ARGUS_BASE0	14
#define ARGUS_BASE1	15
#define ARGUS_BASE2	16
#define ARGUS_BASE3	17

int ArgusGetDisplayLineColor(struct ArgusParserStruct *, WINDOW *, struct ArgusRecordStruct *, struct ArgusAttributeStruct *);
int (*RaColorAlgorithms[ARGUS_MAX_COLOR_ALG]) (struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusAttributeStruct *, short, attr_t);


#endif

char RaOutputBuffer[MAXSTRLEN];
struct RaOutputProcessStruct *RaCursesNewProcess(struct ArgusParserStruct *parser);
void ArgusUpdateScreen(void);
void ArgusTouchScreen(void);

#if defined(ARGUS_THREADS)
pthread_attr_t RaCursesAttr;
pthread_t RaOutputThread      = 0;
pthread_t RaDataThread        = 0;
pthread_t RaCursesInputThread = 0;
#endif

#define RATOPSTARTINGINDEX	2
#define ARGUS_MAX_PROCESSORS	16

struct RaOutputProcessStruct *RaProcesses[ARGUS_MAX_PROCESSORS];

#define ARGUS_DISPLAY_PROCESS	0
#define ARGUS_EVENTS_PROCESS	1
#define ARGUS_HISTORY_PROCESS	2

char * ArgusTrimString (char *);

struct RaOutputProcessStruct *RaOutputProcess = NULL;
struct RaOutputProcessStruct *RaEventProcess = NULL;
struct RaOutputProcessStruct *RaHistoryProcess = NULL;

struct ArgusAggregatorStruct *ArgusEventAggregator = NULL;

int ArgusWindowClosing = 0;
int RaSortItems = 0;

float RaUpdateRate = 1.0;
int RaCursesRealTime = 0;
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
struct ArgusListStruct *ArgusSQLDeleteQueryList = NULL;

void RaResizeHandler (int);
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

void RaCursesLoop (struct ArgusParserStruct *);
void RaOutputModifyScreen (void);
void RaOutputHelpScreen (void);
int RaSearchDisplay (struct ArgusParserStruct *, struct ArgusQueueStruct *, int, int *, int *, char *, int);

struct RaBinProcessStruct *RaBinProcess = NULL;

struct RaTopProcessStruct *RaTopNewProcess(struct ArgusParserStruct *parser);

char *ArgusGenerateProgramArgs(struct ArgusParserStruct *);
char RaProgramArgs[MAXSTRLEN];


int RaWindowStatus    = 1;
int RaWindowModified  = 1;
int RaWindowImmediate = 1;

struct timeval RaCursesStartTime      = {0, 0};
struct timeval RaCursesStopTime       = {0, 0};
struct timeval RaCursesUpdateTime     = {1, 0};
struct timeval RaProbeUptime       = {0, 0};

void clearArgusWfile(struct ArgusParserStruct *);

#define RAIDLESTATUS    0
#define RANEWCOMMAND    1
#define RAGETTINGa      2
#define RAGETTINGA      3
#define RAGETTINGb      4
#define RAGETTINGB      5
#define RAGETTINGc      6
#define RAGETTINGd      7
#define RAGETTINGD      8
#define RAGETTINGf      9
#define RAGETTINGF      10
#define RAGETTINGh      11
#define RAGETTINGm      12
#define RAGETTINGM      13
#define RAGETTINGn      14
#define RAGETTINGN      15
#define RAGETTINGq      16
#define RAGETTINGr      17
#define RAGETTINGR      18
#define RAGETTINGs      19
#define RAGETTINGS      20
#define RAGETTINGt      21
#define RAGETTINGT      22
#define RAREADINGSTR    23
#define RAGETTINGu      24
#define RAGETTINGU      25
#define RAGETTINGw      26
#define RAGETTINGp      27
#define RAGETTINGslash  28
#define RAGETTINGcolon  29
#define RAGETTINGe      30

#define RAGOTslash      40
#define RAGOTcolon      41

#define RANEWCOMMANDSTR    ""
#define RAGETTINGaSTR      "Add: "
#define RAGETTINGBSTR      "Save to Database Table: "
#define RAGETTINGcSTR      "Connect to Database (user/auth@host:project): "
#define RAGETTINGdSTR      "Drop Connection to: "
#define RAGETTINGDSTR      "Set Debug Level: "
#define RAGETTINGeSTR      "Specify regex: "
#define RAGETTINGfSTR      "Specify filter: "
#define RAGETTINGnSTR      "Print Names: (all, proto, port, none) "
#define RAGETTINGtSTR      "Specify time range: "
#define RAGETTINGTSTR      "Specify record idle timeout (secs): "
#define RAGETTINGFSTR      "Specify fields: "
#define RAGETTINGhSTR      "Help menu (press any key to continue): "
#define RAGETTINGmSTR      "Specify flow model fields: "
#define RAGETTINGMSTR      "Specify modes: "
#define RAGETTINGNSTR      "Connections to display: "
#define RAGETTINGqSTR      "Quit(y/n): "
#define RAGETTINGRSTR      "Recurse directory(s): "
#define RAGETTINGrSTR      "Read file(s): "
#define RAGETTINGSSTR      "Connect to Server: "
#define RAGETTINGsSTR      "Specify Sort fields: "
#define RAGETTINGuSTR      "Specify Update value: "
#define RAGETTINGUSTR      "Specify Playback rate (sec/sec): "
#define RAGETTINGwSTR      "Write display to file: "
#define RAGETTINGpSTR      "Set Precision: "

char RaCommandInputStr[MAXSTRLEN];
char RaCommandError[MAXSTRLEN];

WINDOW *RaCommandWindow      = NULL;
strproc *RaCommandValueArray = NULL;
char **RaCommandArray        = NULL;

int RaInputStatus            = RAGOTslash;
char *RaInputString          = " ";
char *RaSearchString         = " ";
int RaCommandIndex           = 0;
int RaCommandInsert          = 0;
int RaCommandLines           = 0;
int RaMinCommandLines        = 0;
int RaMaxCommandLines        = 0;

int RaFilterIndex            = 0;
int ArgusPrintTotals         = 0;


WINDOW *RaHeaderWindow     = NULL;
WINDOW *RaDisplayWindow    = NULL;
WINDOW *RaStatusWindow     = NULL;
WINDOW *RaDebugWindow      = NULL;
WINDOW *RaCursorWindow     = NULL;
WINDOW *RaAvailableWindow  = NULL;
WINDOW *RaFailedWindow     = NULL;
WINDOW *RaRecordWindow     = NULL;
WINDOW *RaFocusWindow      = NULL;

#define FAILEDWINSIZE    15

int RaRecordWindowNum = 0;
int RaCursesInit      = 0;
int RaServerMode      = 0;
int RaWindowLines     = 0;
int RaWindowStartLine = 0;
int RaWindowCursorX   = 0;
int RaWindowCursorY   = 1;

int RaHeaderWinSize   = 1;
int RaStatusWinSize   = 1;
int RaDebugWinSize    = 1;

int RaDisplayLines    = 0;
int RaDisplayLinesSet = 0;
int RaScreenResize    = 0;
int RaScreenMove      = 0;
int RaScreenLines     = 0;
int RaScreenColumns   = 0;
int RaScreenStartX    = 0;
int RaScreenStartY    = 0;

#define MAXLINES 2048
#if !defined(MAXNAMELEN)
#define MAXNAMELEN 1024
#endif

// this is what procps top does by default, so let's do this, if nothing is
// specified
//
#ifndef DEFAULT_SHOW
//                       0         1         2         3 
//                       0123456789012345678901234567890 
#define DEFAULT_SHOW    "AbcDgHIjklMnoTP|qrsuzyV{EFWX"
#endif


#else  // RA_CURSES_MAIN

extern char RaOutputBuffer[MAXSTRLEN];
extern struct RaOutputProcessStruct *RaCursesNewProcess(struct ArgusParserStruct *parser);
extern void ArgusSetDebugString (char *, int, int);
extern void ArgusUpdateScreen(void);
extern void ArgusResetSearch (void);

extern struct ArgusWindowStruct *RaCurrentWindow;

extern void ArgusProcessSqlData(struct ArgusWindowStruct *);

extern char * ArgusTrimString (char *);

#if defined(ARGUS_THREADS)
extern pthread_attr_t RaCursesAttr;
extern pthread_t RaOutputThread;
extern pthread_t RaDataThread;
extern pthread_t RaCursesInputThread;
#endif

#define RATOPSTARTINGINDEX       2

extern struct RaOutputProcessStruct *RaOutputProcess;
extern struct RaOutputProcessStruct *RaEventProcess;
extern struct RaOutputProcessStruct *RaHistoryProcess;
extern struct ArgusAggregatorStruct *ArgusEventAggregator;

extern struct ArgusListStruct *ArgusSQLQueryList;
extern struct ArgusListStruct *ArgusSQLInsertQueryList;
extern struct ArgusListStruct *ArgusSQLSelectQueryList;
extern struct ArgusListStruct *ArgusSQLUpdateQueryList;
extern struct ArgusListStruct *ArgusSQLDeleteQueryList;

extern int RaWindowStatus;
extern int RaWindowModified;
extern int RaWindowImmediate;
extern int ArgusWindowClosing;
extern int RaSortItems;

extern float RaUpdateRate;
extern int RaCursesRealTime;

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
extern struct RaBinProcessStruct *RaBinProcess;

extern int ArgusSearchDirection;
extern int ArgusAlwaysUpdate;

extern int ArgusCursesEnabled;

extern struct timeval RaStartTime;
extern struct timeval RaEndTime;

extern void ArgusInitAggregatorStructs(struct ArgusAggregatorStruct *);

extern char *ArgusGenerateProgramArgs(struct ArgusParserStruct *);
extern char RaProgramArgs[MAXSTRLEN];

extern struct timeval RaCursesStartTime;
extern struct timeval RaCursesStopTime;
extern struct timeval RaCursesUpdateTime;
extern struct timeval RaProbeUptime;

extern void clearArgusWfile(struct ArgusParserStruct *);

extern int RaInputStatus;
extern char *RaInputString;
extern char *RaSearchString;
extern int RaCommandIndex;
extern int RaCommandInsert;
extern int RaCommandLines;
extern int RaMinCommandLines;
extern int RaMaxCommandLines;

extern int RaFilterIndex;
extern int ArgusPrintTotals;

#endif  // RA_CURSES_MAIN
#endif
