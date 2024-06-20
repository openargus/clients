/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
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
 */

/* 
 * $Id: //depot/gargoyle/clients/examples/raevent/raevent.h#2 $
 * $DateTime: 2014/10/07 15:00:33 $
 * $Change: 2938 $
 */


#if !defined(RaTop_h)
#define RaTop_h

#include <unistd.h>
#include <stdlib.h>
 
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>

#include <argus_namedb.h>
#include <argus_filter.h>

#include <signal.h>
#include <string.h>
 
#include <netinet/in.h>
#include <math.h>
#include <ctype.h>
#include <errno.h>

char *RaGetCiscoServers(void); 
char *RaGetNoOutputStatus(void); 
char *RaGetUserAuth(void); 
char *RaGetUserPass(void); 
char *RaGetOutputFile(void);
char *RaGetExceptionOutputFile(void); 
char *RaGetTimeRange(void); 
char *RaGetRunTime(void); 
char *RaGetFieldDelimiter(void); 
char *RaGetTimeFormat(void); 
char *RaGetPrecision(void); 
char *RaGetTimeSeries(void); 
char *RaGetValidateStatus(void); 
char *RaGetNumber(void); 
char *RaGetDebugLevel(void); 
char *RaGetUserDataEncode(void); 

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
#endif /* NetBSD || CYGWIN */

char *RaModifyCommandArray[] = {
   "RA_CISCONETFLOW_SOURCE=",
   "RA_NO_OUTPUT=",
   "RA_USER_AUTH=",
   "RA_AUTH_PASS=",
   "RA_OUTPUT_FILE=",
   "RA_EXCEPTION_OUTPUT_FILE=",
   "RA_TIMERANGE=",
   "RA_RUN_TIME=",
   "RA_FIELD_DELIMITER=",
   "RA_TIME_FORMAT=",
   "RA_USEC_PRECISION=",
   "RAGATOR_TIME_SERIES=",
   "RAGATOR_VALIDATE=",
   "RAMON_NUMBER=",
   "RA_DEBUG_LEVEL=",
   "RA_USERDATA_ARG=",
   "RA_USERDATA_ENCODE=",
   "RA_HOST_FIELD_LENGTH=",
   "RA_PORT_FIELD_LENGTH=",
};

void clearArgusWfile(struct ArgusParserStruct *);

#define ARGUS_MAX_MODIFY_ELEMENTS 16
strproc RaModifyCommandValueArray[ARGUS_MAX_MODIFY_ELEMENTS] = {
   RaGetCiscoServers,
   RaGetNoOutputStatus,
   RaGetUserAuth,
   RaGetUserPass,
   RaGetOutputFile,
   RaGetExceptionOutputFile,
   RaGetTimeRange,
   RaGetRunTime,
   RaGetFieldDelimiter,
   RaGetTimeFormat,
   RaGetPrecision,
   RaGetTimeSeries,
   RaGetValidateStatus,
   RaGetNumber,
   RaGetDebugLevel,
   RaGetUserDataEncode,
};

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
#define RAGETTINGN      14
#define RAGETTINGq      15
#define RAGETTINGr      16
#define RAGETTINGR      17
#define RAGETTINGs      18
#define RAGETTINGS      19
#define RAGETTINGt      20
#define RAGETTINGT      21
#define RAREADINGSTR    22
#define RAGETTINGu      23
#define RAGETTINGU      24
#define RAGETTINGw      25
#define RAGETTINGp      26
#define RAGETTINGslash  27
#define RAGETTINGcolon  28
#define RAGETTINGe      29

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

WINDOW *RaWindow = NULL;
WINDOW *RaHeaderWindow = NULL;
WINDOW *RaCursorWindow = NULL;
WINDOW *RaAvailableWindow = NULL;
WINDOW *RaFailedWindow = NULL;
WINDOW *RaRecordWindow = NULL;

#define FAILEDWINSIZE    15
 
int RaRecordWindowNum = 0;
int RaCursesInit      = 0;
int RaServerMode      = 0;
int RaWindowLines     = 0;
int RaWindowStartLine = 0;
int RaWindowCursorX   = 0;
int RaWindowCursorY   = 1;

int RaHeaderWinSize   = 1;

int RaDisplayLines    = 0;
int RaDisplayLinesSet = 0;
int RaScreenResize    = 0;
int RaScreenMove      = 0;
int RaScreenLines     = 0;
int RaScreenColumns   = 0;
int RaScreenStartX    = 0;
int RaScreenStartY    = 0;

struct termios RaOrigTty;
int RaInitCurses(struct ArgusParserStruct *);

#else
#define TRUE		1
#define FALSE		0
#endif /* ARGUS_CURSES */

int RaWindowStatus    = 1;
int RaWindowModified  = 1;
int RaWindowImmediate = 1;

struct timeval RaTopStartTime      = {0, 0};
struct timeval RaTopStopTime       = {0, 0};
struct timeval RaTopUpdateTime     = {0, 0};
struct timeval RaTopUpdateInterval = {0, 0};
struct timeval RaProbeUptime       = {0, 0};

#define MAXLINES 2048
#if !defined(MAXNAMELEN)
#define MAXNAMELEN 1024
#endif

/* this is what procps top does by default, so let's do this, if nothing is
 * specified
 */
#ifndef DEFAULT_SHOW
/*                       0         1         2         3 */
/*                       0123456789012345678901234567890 */
#define DEFAULT_SHOW    "AbcDgHIjklMnoTP|qrsuzyV{EFWX"
#endif


#endif
