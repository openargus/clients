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
 *     ratop - curses (color) based argus GUI modeled after the top program.
 *
 *  rasqlinsert.c - this module handles the curses screen input and
 *               output operations
 *
 *  Author: Carter Bullard carter@qosient.com
 */


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <time.h>

#define ARGUS_RECORD_MODIFIED   0x0100
#define ARGUS_RECORD_CLEARED    0x0200

#define ARGUS_SQL_INSERT        0x0100000
#define ARGUS_SQL_UPDATE        0x0200000
#define ARGUS_SQL_DELETE        0x0400000

#define ARGUS_SQL_STATUS        (ARGUS_SQL_INSERT | ARGUS_SQL_UPDATE | ARGUS_SQL_DELETE)

#if defined(CYGWIN)
#define USE_IPV6
#endif

#define RA_CURSES_MAIN
#include <rasqlinsert.h>

#if defined(ARGUS_THREADS)
pthread_attr_t RaTopAttr;
pthread_t RaMySQLThread = 0;
pthread_t RaMySQLSelectThread = 0;
pthread_t RaMySQLUpdateThread = 0;
pthread_t RaMySQLInsertThread = 0;
pthread_mutex_t RaMySQLlock;

void *ArgusMySQLInsertProcess (void *);
void *ArgusMySQLUpdateProcess (void *);
void *ArgusMySQLSelectProcess (void *);
#endif

#if defined(ARGUS_MYSQL)
int ArgusTotalInsertSQLStatements = 0;
int ArgusTotalUpdateSQLStatements = 0;
int ArgusTotalSelectSQLStatements = 0;


#include <netdb.h>
#include <sys/socket.h>

#include <mysql.h>

char *RaDatabase = NULL;
char **RaTables = NULL;

int ArgusTotalSQLSearches = 0;
int ArgusTotalSQLUpdates  = 0;
int ArgusTotalSQLWrites = 0;
 
int ArgusSQLBulkInsertSize = 0;
int ArgusSQLMaxPacketSize = 0;
int ArgusSQLBulkBufferSize = 0;
int ArgusSQLBulkBufferIndex = 0;
int ArgusSQLBulkBufferCount = 0;
char *ArgusSQLBulkLastTable = NULL;
char *ArgusSQLBulkBuffer = NULL;
char *ArgusSQLVersion = NULL;
int MySQLVersionMajor = 0;
int MySQLVersionMinor = 0;
int MySQLVersionSub = 0;

extern int ArgusSOptionRecord;
int ArgusDeleteTable = 0;

int ArgusDropTable = 0;
int ArgusCreateTable = 0;
int ArgusAutoId = 0;

struct timeval ArgusLastRealTime     = {0, 0};
struct timeval ArgusLastTime         = {0, 0};
struct timeval ArgusThisTime         = {0, 0};
struct timeval ArgusCurrentTime      = {0, 0};

char ArgusSQLSaveTableNameBuf[1024];
struct tm ArgusSaveTableTmStruct;
time_t ArgusSaveTableSeconds = 0;

int ArgusCreateSQLSaveTable(char *, char *);
char *ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, int, int);
void RaMySQLDeleteRecords(struct ArgusParserStruct *, struct ArgusRecordStruct *);

void RaSQLQueryTable (char *);
void RaSQLQueryNetworksTable (unsigned int, unsigned int, unsigned int);
void RaSQLQueryProbes (void);
void RaSQLQuerySecondsTable (unsigned int, unsigned int);

char *ArgusCreateSQLSaveTableName (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);
struct RaBinProcessStruct *ArgusNewRateBins (struct ArgusParserStruct *, struct ArgusRecordStruct *);

int RaInitialized = 0;
int RaSQLMcastMode = 0;

char *RaRoleString = NULL;
char *RaProbeString = NULL;
char *RaSQLCurrentTable = NULL;

char RaSQLSaveTable[MAXSTRLEN];

#define RA_MAXTABLES            0x100000

unsigned int RaTableFlags = 0;

char *RaTableValues[256];
char *RaTableExistsNames[RA_MAXTABLES];
char *RaTableCreateNames[RA_MAXTABLES];
char *RaTableCreateString[RA_MAXTABLES];
char *RaTableDeleteString[RA_MAXTABLES];

char *RaSource       = NULL;
char *RaArchive      = NULL;
char *RaLocalArchive = NULL;
char *RaFormat       = NULL;
char *RaTable        = NULL;
int   RaPeriod       = 1;
int   RaStatus       = 1;

int   RaSQLMaxSecs   = 0;
int   RaSQLUpdateDB  = 1;
int   RaSQLCacheDB   = 0;
int   RaSQLDBInserts = 0;
int   RaSQLDBUpdates = 0;
int   RaSQLDBDeletes = 1;
int   RaFirstManRec  = 1;

char ArgusArchiveBuf[MAXPATHNAMELEN];
char RaLocalArchiveBuf[MAXSTRLEN];

extern char *RaRemoteFilter;
extern char *RaLocalFilter;

extern char RaFilterSQLStatement[];

char *RaHost = NULL, *RaUser = NULL, *RaPass = NULL;
int RaPort = 0;

struct ArgusInput *ArgusInput = NULL;
void RaMySQLInit (void);

MYSQL_ROW row;
MYSQL *RaMySQL = NULL;

struct ArgusSQLQueryStruct {
   struct ArgusListObjectStruct *nxt;
   char *tbl, *sptr, *dptr;
};


#define RA_MAXSQLQUERY          3
char *RaTableQueryString[RA_MAXSQLQUERY] = {
   "SELECT id, name from NTAIS.Probes",
   "SELECT * from %s_%s_Seconds WHERE second >= %u and second <= %u",
   "SELECT filename from %s_%s_Filename WHERE id = %d",
};

#define RA_MAXMCASTSQLQUERY     3
char *RaMcastTableQueryString[RA_MAXMCASTSQLQUERY] = {
   "SELECT record from %s_CurrMcastGroups where groupaddr=\"\"",
   "SELECT record from %s_CurrMcastSender",
   "SELECT record from %s_CurrMcastMember",
};


#define RAMYSQL_NETWORKSTABLE_NUMBER	0
#define RAMYSQL_NETWORKSTABLE_START	1
#define RAMYSQL_NETWORKSTABLE_END	2

struct RaMySQLNetworksTable {
   struct ArgusQueueHeader qhdr;
   unsigned int number;
   unsigned int start;
   unsigned int last;
};
 
struct RaMySQLFileStruct {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   unsigned int fileindex;
   char *filename;
   unsigned int ostart, ostop;
};

#define RAMYSQL_SECONDTABLE_PROBE	0
#define RAMYSQL_SECONDTABLE_SECOND	1
#define RAMYSQL_SECONDTABLE_FILEINDEX	2
#define RAMYSQL_SECONDTABLE_OSTART	3
#define RAMYSQL_SECONDTABLE_OSTOP 	4

struct RaMySQLSecondsTable {
   struct ArgusQueueHeader qhdr;
   unsigned int fileindex;
   char *filename;
   unsigned int probe;
   unsigned int second;
   unsigned int ostart, ostop;
};

#define RAMYSQL_PROBETABLE_PROBE	0
#define RAMYSQL_PROBETABLE_NAME		1

struct RaMySQLProbeTable {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   char *name;
};
 

void RaMySQLInit (void);

#endif

#if defined(ARGUS_COLOR_SUPPORT)
int ArgusColorAvailability(struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusAttributeStruct *, short, attr_t);
int ArgusColorAddresses(struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusAttributeStruct *, short, attr_t);
int ArgusColorFlowFields(struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusAttributeStruct *, short, attr_t);
int ArgusColorGeoLocation(struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusAttributeStruct *, short, attr_t);
void ArgusInitializeColorMap(struct ArgusParserStruct *, WINDOW *);
#endif

int
main(int argc, char **argv)
{
   struct ArgusParserStruct *parser = NULL;
   int ArgusExitStatus, i, cc;
   pthread_attr_t attr;

   for (i = 0, cc = 0; i < argc; i++)
      cc += strlen(argv[i]);

   if (strchr (argv[0], '/'))
      argv[0] = strrchr(argv[0], '/') + 1;

   ArgusThreadsInit(&attr);

   if ((parser = ArgusNewParser(argv[0])) != NULL) {
      ArgusParser = parser;
      ArgusMainInit (parser, argc, argv);
      ArgusClientInit (parser);

#ifdef ARGUS_CURSES
#if defined(ARGUS_THREADS)
      sigset_t blocked_signals;

      sigfillset(&blocked_signals);
      sigdelset(&blocked_signals, SIGTERM);
      sigdelset(&blocked_signals, SIGINT);
      sigdelset(&blocked_signals, SIGWINCH);

      pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

      if (parser->writeDbstr != NULL) {
         if (parser->readDbstr != NULL)
            free(parser->readDbstr);
         parser->readDbstr = NULL; //if writing we'll need to read the same db
      }

#if defined(ARGUS_MYSQL)
      RaMySQLInit();
      ArgusParseInit(parser, NULL);

      if (RaDatabase && RaTable)
         parser->RaTasksToDo = 1;

#if defined(ARGUS_THREADS)
      {
         sigset_t blocked_signals;
         sigset_t sigs_to_catch;

         sigfillset(&blocked_signals);
         pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

         if ((pthread_create(&RaMySQLInsertThread, NULL, ArgusMySQLInsertProcess, ArgusParser)) != 0)
            ArgusLog (LOG_ERR, "main() pthread_create error %s\n", strerror(errno));

         if ((pthread_create(&RaMySQLSelectThread, NULL, ArgusMySQLSelectProcess, ArgusParser)) != 0)
            ArgusLog (LOG_ERR, "main() pthread_create error %s\n", strerror(errno));

         if ((pthread_create(&RaMySQLUpdateThread, NULL, ArgusMySQLUpdateProcess, ArgusParser)) != 0)
            ArgusLog (LOG_ERR, "main() pthread_create error %s\n", strerror(errno));

         sigemptyset(&sigs_to_catch);
         sigaddset(&sigs_to_catch, SIGHUP);
         sigaddset(&sigs_to_catch, SIGTERM);
         sigaddset(&sigs_to_catch, SIGQUIT);
         sigaddset(&sigs_to_catch, SIGINT);
         pthread_sigmask(SIG_UNBLOCK, &sigs_to_catch, NULL);
      }
#endif
#endif
      if ((pthread_create(&RaCursesThread, NULL, ArgusOutputProcess, NULL)) != 0)
         ArgusLog (LOG_ERR, "ArgusOutputProcess() pthread_create error %s\n", strerror(errno));
 
      if ((pthread_create(&RaDataThread, NULL, ArgusProcessData, NULL)) != 0)
         ArgusLog (LOG_ERR, "main() pthread_create error %s\n", strerror(errno));

      pthread_join(RaDataThread, NULL);

      ArgusCloseDown = 1;

      pthread_join(RaCursesThread, NULL);
      pthread_join(RaMySQLInsertThread, NULL);
      pthread_join(RaMySQLUpdateThread, NULL);
      pthread_join(RaMySQLSelectThread, NULL);

      mysql_close(RaMySQL);
      ArgusWindowClose();
#endif
#endif
   }

   ArgusExitStatus = RaCursesClose(parser, &attr);
   exit (ArgusExitStatus);
}

int
RaCursesSetWindowFocus(struct ArgusParserStruct *parser, WINDOW *win)
{
   int i, cnt, retn = 0;
   if ((cnt = ArgusWindowQueue->count) > 0) {
      for (i = 0; i < cnt; i++) {
         struct ArgusWindowStruct *ws = (struct ArgusWindowStruct *)ArgusPopQueue(ArgusWindowQueue, ARGUS_LOCK);
         ArgusAddToQueue (ArgusWindowQueue, &ws->qhdr, ARGUS_LOCK);

         if (ws->window == win) {
#ifdef ARGUSDEBUG
            ArgusDebug (1, "setting window focus to %s", ws->desc);
#endif
            RaFocusWindow = win;
            break;
         }
      }
   }
   return (retn);
}

WINDOW *
RaCursesGetWindowFocus(struct ArgusParserStruct *parser)
{
   return(RaFocusWindow);
}


int
RaCursesClose(struct ArgusParserStruct *parser, pthread_attr_t *attr)
{
   struct ArgusInput *addr;
   int retn = 0;


#if defined(ARGUS_THREADS)
   if (parser->Sflag) {
      void *retn = NULL;

      if (parser->ArgusReliableConnection)
         pthread_attr_destroy(attr);

      while ((addr = (void *)ArgusPopQueue(parser->ArgusActiveHosts, ARGUS_LOCK)) != NULL) {
         if (addr->tid != (pthread_t) 0) {
            pthread_join(addr->tid, &retn);
         }
      }
   }

   if (parser->dns != (pthread_t) 0)
      pthread_join(parser->dns, NULL);
#endif

   retn = parser->ArgusExitStatus;

//   ArgusCloseParser(parser);
   return (retn);
}


int RaInitCurses (void);
void RaRefreshDisplay (void);
void RaOutputModifyScreen (void);
void RaOutputHelpScreen (void);
void RaResizeScreen(void);
void RaUpdateHeaderWindow(WINDOW *);
void RaUpdateDebugWindow(WINDOW *);
void RaUpdateStatusWindow(WINDOW *);
void ArgusOutputProcessInit(void);
void ArgusOutputProcessClose(void);
void ArgusDrawWindow(struct ArgusWindowStruct *);

int ArgusFetchWindowData(struct ArgusWindowStruct *);

void *
ArgusOutputProcess (void *arg)
{
   struct timeval ntvbuf, *ntvp = &ntvbuf;
   struct timeval tvbuf, *tvp = &tvbuf;

   struct timespec tsbuf, *tsp = &tsbuf;
   int ArgusDisplayNeedsRefreshing;

   int cnt = 0;

   ArgusOutputProcessInit();

   while (!ArgusCloseDown) {
      ArgusDisplayNeedsRefreshing = 0;
      gettimeofday(tvp, NULL);

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&RaCursesLock);
#endif
      if (RaScreenResize == TRUE)
         RaResizeScreen();

      if ((cnt = ArgusWindowQueue->count) > 0) {
         int i, retn;

         for (i = 0; i < cnt; i++) {
            struct ArgusWindowStruct *ws = (struct ArgusWindowStruct *)ArgusPopQueue(ArgusWindowQueue, ARGUS_LOCK);

            if ((retn = ws->data(ws)) > 0) {
               if (ws == RaDataWindowStruct) {
                  struct ArgusQueueStruct *queue = RaOutputProcess->queue;

                  if (queue->status & RA_MODIFIED)
                     ArgusTouchScreen();

                  if (RaWindowImmediate || ((tvp->tv_sec > ntvp->tv_sec) || ((tvp->tv_sec  == ntvp->tv_sec) &&
                                                                             (tvp->tv_usec >  ntvp->tv_usec)))) {
                     ArgusDrawWindow(ws);
                     ntvp->tv_sec  = tvp->tv_sec  + RaCursesUpdateInterval.tv_sec;
                     ntvp->tv_usec = tvp->tv_usec + RaCursesUpdateInterval.tv_usec;
                     while (ntvp->tv_usec > 1000000) {
                        ntvp->tv_sec  += 1;
                        ntvp->tv_usec -= 1000000;
                     }
                     RaWindowImmediate = FALSE;
                     ArgusDisplayNeedsRefreshing = 1;
                  }

               } else
                  ArgusDrawWindow(ws);
            }
            ArgusAddToQueue (ArgusWindowQueue, &ws->qhdr, ARGUS_LOCK);
         }

         if (ArgusDisplayNeedsRefreshing) {
            RaRefreshDisplay();
         }
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&RaCursesLock);
#endif
      tsp->tv_sec  = 0;
      tsp->tv_nsec = 50000000;
      nanosleep(tsp, NULL);
   }

   ArgusOutputProcessClose();

#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#else
   return (NULL);
#endif
}


int RaWindowPass    = 1;

struct ArgusInputCommand *ArgusInputHitTable [0x200];

struct ArgusInputCommand {
   int ch;
   int (*process)(WINDOW *, int, int);
};



void ArgusProcessCursesInputInit(WINDOW *);
int ArgusProcessTerminator (WINDOW *, int, int);
int ArgusProcessNewPage (WINDOW *, int, int);
int ArgusProcessDeviceControl (WINDOW *, int, int);
int ArgusProcessEscape (WINDOW *, int, int);
int ArgusProcessEndofTransmission (WINDOW *, int, int);
int ArgusProcessKeyUp (WINDOW *, int, int);
int ArgusProcessKeyDown (WINDOW *, int, int);
int ArgusProcessKeyLeft (WINDOW *, int, int);
int ArgusProcessKeyRight (WINDOW *, int, int);
int ArgusProcessBell (WINDOW *, int, int);
int ArgusProcessBackspace (WINDOW *, int, int);
int ArgusProcessDeleteLine (WINDOW *, int, int);

int ArgusProcessCharacter(WINDOW *, int, int);

#define MAX_INPUT_OPERATORS	21
struct ArgusInputCommand ArgusInputCommandTable [MAX_INPUT_OPERATORS] = {
   {0,             ArgusProcessCharacter },
   {'\n',          ArgusProcessTerminator },
   {'\r',          ArgusProcessTerminator },
   {0x07,          ArgusProcessBell },
   {0x0c,          ArgusProcessNewPage },
   {0x11,          ArgusProcessDeviceControl },
   {0x12,          ArgusProcessDeviceControl },
   {0x13,          ArgusProcessDeviceControl },
   {0x14,          ArgusProcessDeviceControl },
   {0x15,          ArgusProcessDeleteLine },
   {0x1B,          ArgusProcessEscape },
   {0x04,          ArgusProcessEndofTransmission },
   {KEY_UP,        ArgusProcessKeyUp },
   {KEY_DOWN,      ArgusProcessKeyDown },
   {KEY_LEFT,      ArgusProcessKeyLeft },
   {KEY_RIGHT,     ArgusProcessKeyRight },
   {'\b',          ArgusProcessBackspace },
   {0x7F,          ArgusProcessBackspace },
   {KEY_DC,        ArgusProcessBackspace },
   {KEY_BACKSPACE, ArgusProcessBackspace },
   {KEY_DL,        ArgusProcessDeleteLine },
};


int ArgusInputInit = 0;
void
ArgusProcessCursesInputInit(WINDOW *win)
{
   int i, ch;

   if (ArgusInputInit++ == 0) {
      bzero(ArgusInputHitTable, sizeof(ArgusInputHitTable));
   
      for (i = 0; i < KEY_MAX; i++)
         ArgusInputHitTable[i] = &ArgusInputCommandTable[0];

      for (i = 1; i < MAX_INPUT_OPERATORS; i++) {
         if ((ch = ArgusInputCommandTable[i].ch) < KEY_MAX)
            ArgusInputHitTable[ch] = &ArgusInputCommandTable[i];
      }
   }

   cbreak();
 
#if defined(ARGUS_READLINE) || defined(ARGUS_EDITLINE)
   keypad(win, FALSE);
#else
   keypad(win, TRUE);
#endif
   meta(win, TRUE);
   noecho();
   nonl();
 
   idlok (win, TRUE);
   notimeout(win, TRUE);
   nodelay(win, TRUE);
   intrflush(win, FALSE);
}

void *
ArgusProcessCursesInput(void *arg)
{
   struct timeval tvbuf, *tvp = &tvbuf;
   fd_set in;
   int ch;

   ArgusProcessCursesInputInit(RaStatusWindow);

   tvp->tv_sec = 0; tvp->tv_usec = 10000;

   while (!ArgusCloseDown) {
      FD_ZERO(&in); FD_SET(0, &in);
      while (!ArgusWindowClosing && (select(1, &in, 0, 0, tvp) > 0)) {
         if ((ch = wgetch(RaStatusWindow)) != ERR) {
            RaInputStatus = ArgusProcessCommand (ArgusParser, RaInputStatus, ch);
         }
      }
      tvp->tv_sec = 0; tvp->tv_usec = 10000;
   }

#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#else
   return (NULL);
#endif
}


int
ArgusProcessCommand (struct ArgusParserStruct *parser, int status, int ch)
{
   int retn = status;
   struct ArgusInputCommand *ic;

   if (status == RAGETTINGh) {
      RaWindowStatus = 1;
      wclear(RaCurrentWindow->window);

      RaInputString = RANEWCOMMANDSTR;
      bzero(RaCommandInputStr, MAXSTRLEN);
      RaCommandIndex = 0;
      RaCursorOffset = 0;
      RaWindowCursorY = 0;
      RaWindowCursorX = 0;

      retn = RAGOTslash;
   } else
      if ((ic = ArgusInputHitTable[ch]) != NULL)
         retn = ic->process(RaCurrentWindow->window, status, ch);

   return (retn);
}


int
ArgusProcessTerminator(WINDOW *win, int status, int ch)
{
   struct ArgusParserStruct *parser = ArgusParser;
   int retn = status;

   if ((ch == '\n') || (ch == '\r')) {
      RaCursorOffset = 0;
      RaCommandInputStr[RaCommandIndex] = '\0';
      switch (retn) {
         case RAGETTINGN: {
            char *ptr = NULL;
            int value = strtol(RaCommandInputStr, (char **)&ptr, 10);

            if (ptr != RaCommandInputStr) {
               int len = (RaScreenLines - (RaHeaderWinSize + RaStatusWinSize + RaDebugWinSize));
               RaDisplayLines = (value < len) ?  value : len;
            }
      
            break;
         }

         case RAGETTINGS: {
            if (!(ArgusAddHostList (ArgusParser, RaCommandInputStr, (ArgusParser->Cflag ? ARGUS_CISCO_DATA_SOURCE : ARGUS_DATA_SOURCE), 0))) {
               ArgusLog (LOG_ALERT, "%s%s host not found", RaInputString, RaCommandInputStr);
            } else {
               ArgusDeleteHostList(ArgusParser);
               ArgusAddHostList (ArgusParser, RaCommandInputStr, (ArgusParser->Cflag ? ARGUS_CISCO_DATA_SOURCE : ARGUS_DATA_SOURCE), 0);
               ArgusParser->Sflag = 1;
               ArgusParser->RaParseDone = 0;
            }
            break;
         }

         case RAGETTINGa: {
            if (!(strncasecmp(RaCommandInputStr, "Totals", 6))) {
               RaScreenResize = TRUE;
               if (ArgusPrintTotals == 0) {
                  ArgusPrintTotals = 1;
                  RaHeaderWinSize++;
                  RaScreenMove = TRUE;
               }
            }
            if (!(strncasecmp(RaCommandInputStr, "-Totals", 6))) {
               RaScreenResize = TRUE;
               if (ArgusPrintTotals > 0) {
                  ArgusPrintTotals = 0;
                  RaHeaderWinSize--;
                  RaScreenMove = FALSE;
                  getbegyx(RaCurrentWindow->window, RaScreenStartY, RaScreenStartX);
                  if (mvwin(RaCurrentWindow->window, RaScreenStartY - 1, RaScreenStartX) == ERR)
                     ArgusLog (LOG_ERR, "RaResizeScreen: mvwin %d, %d returned ERR\n", RaScreenStartY - 1, RaScreenStartX);
               }
            }
         }
         break;

         case RAGETTINGd: {
            struct ArgusInput *input;
            char strbuf[MAXSTRLEN];

            if ((input = (void *)ArgusParser->ArgusActiveHosts->start) != NULL) {
               do {
                  sprintf (strbuf, " %s:%d", input->hostname, input->portnum);
                  if ((strstr (RaCommandInputStr, strbuf))) {
                     ArgusRemoveFromQueue (ArgusParser->ArgusActiveHosts, &input->qhdr, ARGUS_LOCK);
                     ArgusCloseInput(ArgusParser, input);
                     break;
                  }
                  input = (void *)input->qhdr.nxt;
               } while (input != (void *)ArgusParser->ArgusActiveHosts->start);
            }
         }
         break;

         case RAGETTINGD: {
            char *ptr = NULL;
            int value = strtol(RaCommandInputStr, (char **)&ptr, 10);

            if (ptr != RaCommandInputStr)
               ArgusParser->debugflag = value;
            break;
         }

         case RAGETTINGc: {
            break;
         }

         case RAGETTINGe: {
            char *ptr = NULL;

            ptr = RaCommandInputStr;
            while (isspace((int)*ptr)) ptr++;
            if (ArgusParser->estr != NULL)
               free(ArgusParser->estr);
            ArgusParser->estr = strdup(RaCommandInputStr);
            break;
         }

         case RAGETTINGf: {
            struct nff_program lfilter;
            char *ptr = NULL, *str = NULL;
            int ind = ARGUS_REMOTE_FILTER;
            int fretn, i;

            bzero ((char *) &lfilter, sizeof (lfilter));
            ptr = RaCommandInputStr;
            while (isspace((int)*ptr)) ptr++;

            if ((str = strstr (ptr, "local")) != NULL) {
               ptr = strdup(&str[strlen("local ")]);
               ind = ARGUS_LOCAL_FILTER;
            } else 
            if ((str = strstr (ptr, "display")) != NULL) {
               ptr = strdup(&str[strlen("display ")]);
               ind = ARGUS_DISPLAY_FILTER;
            } else 
            if ((str = strstr (ptr, "remote")) != NULL) {
               ptr = strdup(&str[strlen("remote ")]);
               ind = ARGUS_REMOTE_FILTER;
            } else 
            if ((str = strstr (ptr, "none")) != NULL) {
               ptr = NULL;
               ind = RaFilterIndex;
            } else
               ptr = NULL;

            if ((fretn = ArgusFilterCompile (&lfilter, ptr, 1)) < 0) {
               char sbuf[1024];
               sprintf (sbuf, "%s %s syntax error", RAGETTINGfSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
            } else {
               char sbuf[1024];
               sprintf (sbuf, "%s %s filter accepted", RAGETTINGfSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);
               if ((str = ptr) != NULL)
                  while (isspace((int)*str)) str++;
               
               switch (ind) {
                  case ARGUS_LOCAL_FILTER:
                     if (ArgusParser->ArgusFilterCode.bf_insns != NULL)
                        free (ArgusParser->ArgusFilterCode.bf_insns);

                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusFilterCode, sizeof(lfilter));
                     if (ArgusParser->ArgusLocalFilter !=  NULL) {
                        free(ArgusParser->ArgusLocalFilter);
                        ArgusParser->ArgusLocalFilter = NULL;
                     }
                     if (str && (strlen(str) > 0))
                        ArgusParser->ArgusLocalFilter = ptr;
                     else
                        if (ptr != NULL) free(ptr);
                     break;

                  case ARGUS_DISPLAY_FILTER:
                     if (ArgusParser->ArgusDisplayCode.bf_insns != NULL)
                        free (ArgusParser->ArgusDisplayCode.bf_insns);

                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusDisplayCode, sizeof(lfilter));
                     bcopy((char *)&lfilter, (char *)&ArgusSorter->filter, sizeof(lfilter));

                     if (ArgusParser->ArgusDisplayFilter !=  NULL) {
                        free(ArgusParser->ArgusDisplayFilter);
                        ArgusParser->ArgusDisplayFilter = NULL;
                     }
                     if (str && (strlen(str) > 0))
                        ArgusParser->ArgusDisplayFilter = ptr;
                     else
                        if (ptr != NULL) free(ptr);
                     break;

                  case ARGUS_REMOTE_FILTER:
                     if (ArgusParser->ArgusFilterCode.bf_insns != NULL)
                        free (ArgusParser->ArgusFilterCode.bf_insns);
                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusFilterCode, sizeof(lfilter));
                     if (ArgusParser->ArgusRemoteFilter !=  NULL) {
                        free(ArgusParser->ArgusRemoteFilter);
                        ArgusParser->ArgusRemoteFilter = NULL;
                     }
                     if (str && (strlen(str) > 0))
                        ArgusParser->ArgusRemoteFilter = ptr;
                     else
                        if (ptr != NULL) free(ptr);
                     break;
               }
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaOutputProcess->queue->lock);
#endif
            RaClientSortQueue(ArgusSorter, RaOutputProcess->queue, ARGUS_NOLOCK);
            if (ArgusParser->ns) {
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->ns = NULL;
            }
            for (i = 0; i < RaOutputProcess->queue->count; i++) {
               struct ArgusRecordStruct *ns;
               if ((ns = (struct ArgusRecordStruct *)RaOutputProcess->queue->array[i]) == NULL)
                  break;
               if (ArgusParser->ns)
                  ArgusMergeRecords (parser->ArgusAggregator, ArgusParser->ns, ns);
               else
                  ArgusParser->ns = ArgusCopyRecordStruct (ns);
            }
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaOutputProcess->queue->lock);
#endif
            RaWindowStatus = 1;
            break;
         }
                      
         case RAGETTINGm: {
            struct ArgusRecordStruct *ns = NULL;
            char strbuf[MAXSTRLEN], *tok = NULL, *ptr;
            struct ArgusModeStruct *mode = NULL, *modelist = NULL, *list; 
            struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
            int i;                                  

            ArgusParser->RaMonMode = 0;

            if ((agg->modeStr == NULL) || strcmp(agg->modeStr, RaCommandInputStr)) {
               if (agg->modeStr != NULL)
                  free(agg->modeStr);
               agg->modeStr = strdup(RaCommandInputStr);
               strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

               if ((mode = ArgusParser->ArgusMaskList) != NULL)
                  ArgusDeleteMaskList(ArgusParser);

               agg->mask = 0;
               agg->saddrlen = 0;
               agg->daddrlen = 0;

               if ((ptr = strbuf) != NULL) {
                  while ((tok = strtok (ptr, " \t")) != NULL) {
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
               } else {
                  if ((modelist = ArgusParser->ArgusMaskList) == NULL)
                     agg->mask  = ( ARGUS_MASK_SRCID_INDEX | ARGUS_MASK_PROTO_INDEX |
                                    ARGUS_MASK_SADDR_INDEX | ARGUS_MASK_SPORT_INDEX |
                                    ARGUS_MASK_DADDR_INDEX | ARGUS_MASK_DPORT_INDEX );
               }

               ArgusInitAggregatorStructs(agg);

               if ((mode = modelist) != NULL) {
                  while (mode) {
                     char *ptr = NULL, **endptr = NULL;
                     int value = 0;

                     if ((ptr = strchr(mode->mode, '/')) != NULL) {
                        ptr++;
                        if ((value = strtol(ptr, endptr, 10)) == 0)
                           if (*endptr == ptr)
                              usage();
                     }
                     if (!(strncasecmp (mode->mode, "none", 4))) {
                        agg->mask  = 0;
                     } else
                     if (!(strncasecmp (mode->mode, "macmatrix", 9))) {
                        agg->ArgusMatrixMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SMAC);
                        agg->mask |= (0x01LL << ARGUS_MASK_DMAC);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "mac", 3))) {
                        ArgusParser->RaMonMode++;
                        if (agg->correct != NULL) {
                           free(agg->correct);
                           agg->correct = NULL;
                        }
                        agg->mask |= (0x01LL << ARGUS_MASK_SMAC);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "addr", 4))) {
                        ArgusParser->RaMonMode++;
                        if (agg->correct != NULL) {
                           free(agg->correct);
                           agg->correct = NULL;
                        }
                        agg->mask |= (0x01LL << ARGUS_MASK_SADDR);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "matrix", 6))) {
                        agg->ArgusMatrixMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SADDR);
                        agg->mask |= (0x01LL << ARGUS_MASK_DADDR);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else {
                        struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs;

                        for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                           if (!(strncasecmp (mode->mode, ArgusMaskDefs[i].name, ArgusMaskDefs[i].slen))) {
                              agg->mask |= (0x01LL << i);
                              switch (i) {
                                 case ARGUS_MASK_SADDR:
                                    if (value > 0) {
                                       agg->saddrlen = value;
                                       if (value <= 32)
                                          agg->smask.addr_un.ipv4 = (0xFFFFFFFF << (32 - value));
                                    }
                                    break;

                                 case ARGUS_MASK_DADDR:
                                    if (value > 0) {
                                       agg->daddrlen = value;
                                       if (value <= 32)
                                          agg->dmask.addr_un.ipv4 = (0xFFFFFFFF << (32 - value));
                                    }
                                    break;

                                case ARGUS_MASK_SMPLS:
                                case ARGUS_MASK_DMPLS: {
                                   int x, RaNewIndex = 0;
                                   char *ptr;

                                   if ((ptr = strchr(mode->mode, '[')) != NULL) {
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
                             }
                             break;
                          }
                       }
                    }
                    mode = mode->nxt;
                 }
              }

               ArgusParser->ArgusMaskList = modelist;

               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaOutputProcess->queue, ARGUS_LOCK)) != NULL) {
                  if (ArgusSearchHitRecord == ns)
                     ArgusResetSearch();
                  ArgusDeleteRecordStruct (ArgusParser, ns);
               }

               ArgusEmptyHashTable(RaOutputProcess->htable);

               if (ArgusParser->ns) {
                  ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                  ArgusParser->ns = NULL;
               }

               ArgusParser->RaClientUpdate.tv_sec = 0;
               werase(RaCurrentWindow->window);
               ArgusTouchScreen();
            }

            break;
         }

         case RAGETTINGM: {
            char strbuf[MAXSTRLEN], *str = strbuf, *tok = NULL, sbuf[1024];
            struct ArgusModeStruct *mode = NULL;
            int mretn = 0;
            char *tzptr;

            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if ((tzptr = strstr(strbuf, "TZ=")) != NULL) {
               if (ArgusParser->RaTimeZone)
                  free (ArgusParser->RaTimeZone);
               ArgusParser->RaTimeZone = strdup(tzptr);
               tzptr = getenv("TZ");
#if defined(HAVE_SETENV) && HAVE_SETENV
               if ((mretn = setenv("TZ", (ArgusParser->RaTimeZone + 3), 1)) < 0) {
                  sprintf (sbuf, "setenv(TZ, %s, 1) error %s", ArgusParser->RaTimeZone + 3, strerror(errno));
                  ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
               }
#else
               if ((mretn = putenv(ArgusParser->RaTimeZone)) < 0) {
                  sprintf (sbuf, "setenv(TZ, %s, 1) error %s", ArgusParser->RaTimeZone + 3, strerror(errno));
                  ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
               }
#endif
               if (mretn == 0) {
                  tzset();
                  sprintf (sbuf, "Timezone changed from %s to %s", tzptr, getenv("TZ"));
                  ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);
               }

               ArgusTouchScreen();
               break;
            }

            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               ArgusDeleteModeList(ArgusParser);
               ArgusParser->RaCumulativeMerge = 1;
            }

            if (strlen(strbuf) > 0) {
               while ((tok = strtok(str, " \t\n")) != NULL) {
                  if (!(strncasecmp (tok, "none", 4)))
                     ArgusDeleteModeList(ArgusParser);
                  else if (!(strncasecmp (tok, "default", 7))) {
                     ArgusDeleteModeList(ArgusParser);
                  } else
                     ArgusAddModeList (ArgusParser, tok);
                  str = NULL;
               }
            }

            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               struct ArgusAdjustStruct *nadp = NULL;
               struct RaBinProcessStruct *RaBinProcess = parser->RaBinProcess;
               int i, ind;

               while (mode) {
                  for (i = 0, ind = -1; i < ARGUSSPLITMODENUM; i++) {
                     if (!(strncasecmp (mode->mode, RaSplitModes[i], strlen(RaSplitModes[i])))) {
                        ind = i;
                        break;
                     }
                  }

                  if (ind >= 0) {
                     char *mptr = NULL;
                     int size = -1;
                     nadp = &RaBinProcess->nadp;

                     nadp = &RaBinProcess->nadp;

                     switch (ind) {
                        case ARGUSSPLITRATE:  {   /* "%d:%d[yMwdhms]" */
                           struct ArgusModeStruct *tmode = NULL; 
                           nadp->mode = ind;
                           if ((tmode = mode->nxt) != NULL) {
                              mptr = tmode->mode;
                              if (isdigit((int)*tmode->mode)) {
                                 char *ptr = NULL;
                                 nadp->len = strtol(tmode->mode, (char **)&ptr, 10);
                                 if (*ptr++ != ':') 
                                    usage();
                                 tmode->mode = ptr;
                              }
                           }
                        }

                        case ARGUSSPLITTIME: /* "%d[yMwdhms] */
                           nadp->mode = ind;
                           if ((mode = mode->nxt) != NULL) {
                              if (isdigit((int)*mode->mode)) {
                                 char *ptr = NULL;
                                 nadp->value = strtol(mode->mode, (char **)&ptr, 10);
                                 if (ptr == mode->mode)
                                    usage();
                                 else {
                                    switch (*ptr) {
                                       case 'y':
                                          nadp->qual = ARGUSSPLITYEAR;  
                                          size = nadp->value * 31556926;
                                          break;
                                       case 'M':
                                          nadp->qual = ARGUSSPLITMONTH; 
                                          size = nadp->value * 2629744;
                                          break;
                                       case 'w':
                                          nadp->qual = ARGUSSPLITWEEK;  
                                          size = nadp->value * 604800;
                                          break;
                                       case 'd':
                                          nadp->qual = ARGUSSPLITDAY;   
                                          size = nadp->value * 86400;
                                          break;
                                       case 'h':
                                          nadp->qual = ARGUSSPLITHOUR;  
                                          size = nadp->value * 3600;
                                          break;
                                       case 'm':
                                          nadp->qual = ARGUSSPLITMINUTE;
                                          size = nadp->value * 60;
                                          break;
                                        default:
                                          nadp->qual = ARGUSSPLITSECOND;
                                          size = nadp->value;
                                          break;
                                    }
                                 }
                              }
                              if (mptr != NULL)
                                  mode->mode = mptr;
                           }

                           nadp->modify = 1;

                           if (ind == ARGUSSPLITRATE) {
                              /* need to set the flow idle timeout value to be equal to or
                                 just a bit bigger than (nadp->len * size) */

                              ArgusParser->timeout.tv_sec  = (nadp->len * size);
                              ArgusParser->timeout.tv_usec = 0;
                           }

                           ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;
                           ArgusSorter->ArgusSortAlgorithms[1] = NULL;
                           break;

                        case ARGUSSPLITSIZE:
                        case ARGUSSPLITCOUNT:
                           nadp->mode = ind;
                           nadp->count = 1;

                           if ((mode = mode->nxt) != NULL) {
                              if (isdigit((int)*mode->mode)) {
                                 char *ptr = NULL;
                                 nadp->value = strtol(mode->mode, (char **)&ptr, 10);
                                 if (ptr == mode->mode)
                                    usage();
                                 else {
                                    switch (*ptr) {
                                       case 'B':   
                                       case 'b':  nadp->value *= 1000000000; break;
                                        
                                       case 'M':   
                                       case 'm':  nadp->value *= 1000000; break;
                                        
                                       case 'K':   
                                       case 'k':  nadp->value *= 1000; break;
                                    }
                                 }
                              }
                           }
                           ArgusSorter->ArgusSortAlgorithms[0] = NULL;
                           break;

                        case ARGUSSPLITNOMODIFY:
                           nadp->modify = 0;
                           break;

                        case ARGUSSPLITHARD:
                           nadp->hard++;
                           break;

                        case ARGUSSPLITZERO:
                           nadp->zero++;
                           break;
                     }

                  } else {
                     if (!(strncasecmp (mode->mode, "nomerge", 7))) {
                        ArgusParser->RaCumulativeMerge = 0;
                     } else
                     if (!(strncasecmp (mode->mode, "merge", 5))) {
                        ArgusParser->RaCumulativeMerge = 1;
                     }
                  }

                  mode = mode->nxt;
               }
            }

            break;
         }

         case RAGETTINGn: {
            char sbuf[1024], *name = NULL;;
            if (strstr(RaCommandInputStr, "all")) ArgusParser->nflag = 0; else
            if (strstr(RaCommandInputStr, "port")) ArgusParser->nflag = 1; else
            if (strstr(RaCommandInputStr, "proto")) ArgusParser->nflag = 2; else
            if (strstr(RaCommandInputStr, "none")) ArgusParser->nflag = 3;

             switch (ArgusParser->nflag) {
                case 0: name = "all"; break;
                case 1: name = "port"; break;
                case 2: name = "proto"; break;
                case 3: name = "none"; break;
                default: name = "port"; ArgusParser->nflag = 1; break;
             }

            sprintf (sbuf, "%s changed to %s ", RAGETTINGnSTR, name);
            ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);
            ArgusProcessNewPage(RaCurrentWindow->window, 0, 0);
            break;
         }

         case RAGETTINGp: {
            int value = 0;
            char *endptr = NULL;

            value = strtod(RaCommandInputStr, &endptr);

            if (RaCommandInputStr != endptr) {
               ArgusParser->pflag = value;
            } else {
               char sbuf[1024];
               sprintf (sbuf, "%s %s syntax error", RAGETTINGuSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
            }
            break;
         }

         case RAGETTINGR: {
            char strbuf[MAXSTRLEN], *str = strbuf, *ptr = NULL;
            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if (strlen(strbuf) > 0) {
               ArgusDeleteFileList(ArgusParser);
               while ((ptr = strtok(str, " ")) != NULL) {
                  RaProcessRecursiveFiles (ptr);
                  str = NULL;
               }
            }
            break;
         }

         case RAGETTINGr: {
            char strbuf[MAXSTRLEN], *str = strbuf, *ptr = NULL;
            glob_t globbuf;

            bzero (strbuf, MAXSTRLEN);
            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if (strlen(strbuf) > 0) {
               struct ArgusRecordStruct *ns = NULL;

               ArgusDeleteFileList(ArgusParser);
               while ((ptr = strtok(str, " ")) != NULL) {
                  glob (ptr, 0, NULL, &globbuf);
                  if (globbuf.gl_pathc > 0) {
                     int i;
                     for (i = 0; i < globbuf.gl_pathc; i++)
                        ArgusAddFileList (ArgusParser, globbuf.gl_pathv[i], ARGUS_DATA_SOURCE, -1, -1);
                  } else {
                     char sbuf[1024];
                     sprintf (sbuf, "%s no files found for %s", RAGETTINGrSTR, ptr);
                     ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
                  }
                  str = NULL;
               }
               ArgusParser->RaTasksToDo = 1;
               ArgusParser->Sflag = 0;
               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaOutputProcess->queue, ARGUS_LOCK)) != NULL)  {
                  if (ArgusSearchHitRecord == ns) {
                     ArgusResetSearch();
                  }
                  ArgusDeleteRecordStruct (ArgusParser, ns);
               }
               ArgusEmptyHashTable(RaOutputProcess->htable);
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->RaClientUpdate.tv_sec = 0;
               ArgusParser->status &= ~ARGUS_FILE_LIST_PROCESSED;
               ArgusParser->ns = NULL;
               ArgusParser->ArgusLastTime.tv_sec  = 0;
               ArgusParser->ArgusLastTime.tv_usec = 0;
            }
            break;
         }

         case RAGETTINGs: {
            char strbuf[MAXSTRLEN], *ptr = strbuf, *tok;
            int (*srtalg[ARGUS_MAX_SORT_ALG])(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
            int i, x, ind = 0;
            strncpy (strbuf, RaCommandInputStr, MAXSTRLEN);
            bzero(srtalg, sizeof(srtalg));
            while ((tok = strtok(ptr, " ")) != NULL) {
               for (x = 0; x < ARGUS_MAX_SORT_ALG; x++) {
                  if (!strncmp (ArgusSortKeyWords[x], tok, strlen(ArgusSortKeyWords[x]))) {
                     srtalg[ind++] = ArgusSortAlgorithmTable[x];
                     break;
                  }
               }
               if (x == ARGUS_MAX_SORT_ALG) {
                  bzero(srtalg, sizeof(srtalg));
                  ArgusLog (LOG_ALERT, "sort keyword %s not valid", tok);
                  break;
               }
               ptr = NULL;
            }

            if (srtalg[0] != NULL) {
               for (x = 0; x < ARGUS_MAX_SORT_ALG; x++)
                  ArgusSorter->ArgusSortAlgorithms[x] = srtalg[x];
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaOutputProcess->queue->lock);
#endif
            RaClientSortQueue(ArgusSorter, RaOutputProcess->queue, ARGUS_NOLOCK);
            if (ArgusParser->ns) {
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->ns = NULL;
            }
            for (i = 0; i < RaOutputProcess->queue->count; i++) {
               struct ArgusRecordStruct *ns;
               if ((ns = (struct ArgusRecordStruct *)RaOutputProcess->queue->array[i]) == NULL)
                  break;
               if (ArgusParser->ns)
                  ArgusMergeRecords (parser->ArgusAggregator, ArgusParser->ns, ns);
               else
                  ArgusParser->ns = ArgusCopyRecordStruct (ns);
            }
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaOutputProcess->queue->lock);
#endif
            ArgusTouchScreen();
            break;
         }

         case RAGETTINGT: {
            double sec, usec, value;
            char *ptr = NULL;

            value = strtod(RaCommandInputStr, (char **)&ptr);
            if (ptr != RaCommandInputStr) {
               usec = modf(value, &sec);
               ArgusParser->timeout.tv_sec  = sec;
               ArgusParser->timeout.tv_usec = usec;
            }
            break;
         }

         case RAGETTINGt: {
            if (ArgusParser->timearg) {
               free (ArgusParser->timearg);
               ArgusParser->timearg = NULL;
            }

            if (strlen(RaCommandInputStr))
               ArgusParser->timearg = strdup(RaCommandInputStr);

            ArgusCheckTimeFormat (&ArgusParser->RaTmStruct, ArgusParser->timearg);
            break;
         }

         case RAGETTINGu: {
            double value = 0.0, ivalue, fvalue;
            char *endptr = NULL;
            char sbuf[1024];
#if defined(ARGUS_READLINE)
            int keytimeout;
#endif
 
            value = strtod(RaCommandInputStr, &endptr);
 
            if (RaCommandInputStr != endptr) {
               fvalue = modf(value, &ivalue);
 
               RaCursesUpdateInterval.tv_sec  = (int) ivalue;
               RaCursesUpdateInterval.tv_usec = (int) (fvalue * 1000000.0);

#if defined(ARGUS_READLINE)
               keytimeout = (RaCursesUpdateInterval.tv_sec * 1000000) + RaCursesUpdateInterval.tv_usec;
               keytimeout = (keytimeout == 1000000) ? keytimeout - 1 : keytimeout;
#if defined(HAVE_DECL_RL_SET_KEYBOARD_INPUT_TIMEOUT) && HAVE_DECL_RL_SET_KEYBOARD_INPUT_TIMEOUT
               rl_set_keyboard_input_timeout (keytimeout);
#endif
#endif
               sprintf (sbuf, "%s %s interval accepted", RAGETTINGuSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);
               RaCursesUpdateTime = ArgusParser->ArgusRealTime;
 
            } else {
               sprintf (sbuf, "%s %s syntax error", RAGETTINGuSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
            }

            break;
         }

         case RAGETTINGU: {
            double value = 0.0;
            char *endptr = NULL;
            char sbuf[1024];
 
            value = strtod(RaCommandInputStr, &endptr);
 
            if (RaCommandInputStr != endptr) {
               RaUpdateRate = value;
               sprintf (sbuf, "%s %s accepted", RAGETTINGUSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);
 
            } else {
               sprintf (sbuf, "%s %s syntax error", RAGETTINGUSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
            }

            break;
         }

         
         case RAGETTINGw: {
            struct ArgusListStruct *wlist = ArgusParser->ArgusWfileList;
            struct ArgusWfileStruct *wfile = NULL;
            struct ArgusRecord *argusrec = NULL;
            struct ArgusRecordStruct *ns;
            static char sbuf[0x10000];
            int i;

            if (strlen(RaCommandInputStr)) {
               if (RaOutputProcess->queue->count > 0) {
                  ArgusParser->ArgusWfileList = NULL;
                  setArgusWfile (ArgusParser, RaCommandInputStr, NULL);
                  wfile = (struct ArgusWfileStruct *) ArgusParser->ArgusWfileList->start;

                  for (i = 0; i < RaOutputProcess->queue->count; i++) {
                     int pass = 1;

                     if ((ns = (struct ArgusRecordStruct *) RaOutputProcess->queue->array[i]) == NULL)
                        break;

                     if (wfile->filterstr) {
                        struct nff_insn *wfcode = wfile->filter.bf_insns;
                        pass = ArgusFilterRecord (wfcode, ns);
                     }

                     if (pass != 0) {
                        if ((argusrec = ArgusGenerateRecord (ns, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                           ArgusHtoN(argusrec);
#endif
                           ArgusWriteNewLogfile (ArgusParser, ns->input, wfile, argusrec);

                        }
                     }
                  }
            
                  fflush(wfile->fd);
                  fclose(wfile->fd);
                  clearArgusWfile(ArgusParser);
                  ArgusParser->ArgusWfileList = wlist;
               }
            }

            break;   
         }

         case RAGETTINGF: {
            struct ArgusQueueStruct *queue = RaOutputProcess->queue;
            char strbuf[MAXSTRLEN], *ptr = strbuf, *tok;
            int x;

            strncpy (strbuf, RaCommandInputStr, MAXSTRLEN);
            bzero ((char *)ArgusParser->RaPrintOptionStrings, sizeof(ArgusParser->RaPrintOptionStrings));
            ArgusParser->RaPrintOptionIndex = 0;
            while ((tok = strtok(ptr, " ")) != NULL) {
               if (ArgusParser->RaPrintOptionIndex <  ARGUS_MAX_S_OPTIONS)
                  ArgusParser->RaPrintOptionStrings[ArgusParser->RaPrintOptionIndex++] = tok;
               ptr = NULL;
            }

            if (ArgusParser->RaPrintOptionIndex > 0) {
               ArgusProcessSOptions(ArgusParser);
               for (x = 0; x < ArgusParser->RaPrintOptionIndex; x++) 
                  if (ArgusParser->RaPrintOptionStrings[x] != NULL) 
                     ArgusParser->RaPrintOptionStrings[x] = NULL;
               ArgusParser->RaPrintOptionIndex = 0;
            }

            for (x = 0, ArgusAlwaysUpdate = 0; x < MAX_PRINT_ALG_TYPES; x++)
               if (parser->RaPrintAlgorithmList[x] != NULL)
                  if (parser->RaPrintAlgorithmList[x]->print == ArgusPrintIdleTime)
                     ArgusAlwaysUpdate++;

            if (queue == RaOutputProcess->queue) {
               int i;
               if (ArgusParser->ns) {
                  ArgusParser->ns->status |= ARGUS_RECORD_MODIFIED;
               }
               for (i = 0; i < queue->count; i++) {
                  struct ArgusRecordStruct *ns;
                  if ((ns = (struct ArgusRecordStruct *)queue->array[i]) == NULL)
                     break;
                  ns->status |= ARGUS_RECORD_MODIFIED;
               }
            }
            ArgusTouchScreen();
            break;
         }

         case RAGETTINGcolon: {
            char *endptr = NULL;
            int linenum, startline;

            linenum = (int)strtol(RaCommandInputStr, &endptr, 10);
            if (RaCommandInputStr == endptr) {
               switch (*RaCommandInputStr) {
                  case 'q': {
                     bzero (RaCommandInputStr, MAXSTRLEN);
                     ArgusTouchScreen();
                     RaParseComplete(SIGINT);
                     break;
                  }
               }
            } else {
               if ((linenum >= RaWindowStartLine) && (linenum <= (RaWindowStartLine + RaDisplayLines)))
                  RaWindowCursorY = linenum - RaWindowStartLine;
               else {
                  startline = ((linenum - 1)/ RaDisplayLines) * RaDisplayLines;
                  startline = (RaOutputProcess->queue->count > startline) ? startline : RaOutputProcess->queue->count - RaDisplayLines;
                  startline = (startline > 0) ? startline : 0;
                  RaWindowStartLine = startline;
                  if ((RaWindowCursorY = linenum % RaDisplayLines) == 0)
                     RaWindowCursorY = RaDisplayLines;
               }
               retn = RAGOTcolon;
               RaCursesSetWindowFocus(ArgusParser, RaCurrentWindow->window);
               ArgusTouchScreen();
            }
            break;
         }

         case RAGETTINGslash: {
            int linenum = RaWindowCursorY;
            int cursx = RaWindowCursorX, cursy = RaWindowCursorY + RaWindowStartLine;
            char sbuf[1024];

            if ((linenum = RaSearchDisplay(ArgusParser, RaOutputProcess->queue, ArgusSearchDirection, &cursx, &cursy, RaCommandInputStr, ARGUS_LOCK)) < 0) {
               if (ArgusSearchDirection == ARGUS_FORWARD) {
                  sprintf (sbuf, "search hit BOTTOM, continuing at TOP");
                  ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
                  cursx = 0; cursy = 0;
               } else {
                  sprintf (sbuf, "search hit TOP, continuing at BOTTOM");
                  ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
                  cursx = RaScreenColumns; cursy = RaOutputProcess->queue->count;
               }
               linenum = RaSearchDisplay(ArgusParser, RaOutputProcess->queue, ArgusSearchDirection, &cursx, &cursy, RaCommandInputStr, ARGUS_LOCK);
            }

            if (linenum >= 0) {
               int startline = ((cursy - 1)/ RaDisplayLines) * RaDisplayLines;

               startline = (RaOutputProcess->queue->count > startline) ? startline : RaOutputProcess->queue->count - RaDisplayLines;
               startline = (startline > 0) ? startline : 0;
               retn = RAGOTslash;
               RaWindowStartLine = startline;
               if ((RaWindowCursorY = cursy % RaDisplayLines) == 0)
                  RaWindowCursorY = RaDisplayLines;
               RaWindowCursorX = cursx;
               
            
            } else {
               sprintf (sbuf, "Pattern not found: %s", RaCommandInputStr);
               ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
               retn = RAGOTslash;
               RaInputString = RANEWCOMMANDSTR;
               bzero(RaCommandInputStr, MAXSTRLEN);
               RaCommandIndex = 0;
               RaCursorOffset = 0;
               RaWindowCursorY = 0;
               RaWindowCursorX = 0;
            }

            RaCursesSetWindowFocus(ArgusParser, RaCurrentWindow->window);
            retn = RAGOTslash;
            RaInputString = "/";
            ArgusTouchScreen();
            break;
         }
      }

      if ((retn != RAGOTslash) && (retn != RAGOTcolon)) {
         retn = RAGOTslash;
         RaInputString = RANEWCOMMANDSTR;
         RaCommandInputStr[0] = '\0';
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessTerminator(%p, 0x%x, 0x%x) returned 0x%x\n", win, status, ch, retn);
#endif
   return (retn);
}

int
ArgusProcessNewPage(WINDOW *win, int status, int ch)
{
   int retn = status;

   bzero(&RaCursesUpdateTime, sizeof(RaCursesUpdateTime));
   wclear(RaCurrentWindow->window);
   RaWindowStatus = 1;
   ArgusUpdateScreen();
   RaRefreshDisplay();

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessNewPage(%p, 0x%x, 0x%x) returned 0x%x\n", win, status, ch);
#endif
   return (retn);
}

int
ArgusProcessDeviceControl(WINDOW *win, int status, int ch)
{
   int retn = status;

   switch (ch) {
         case 0x11:  
         case 0x13:  
         case 0x14: {
            break;
         }
         case 0x12: {
            int startline = RaWindowCursorY + RaWindowStartLine;
            struct ArgusRecordStruct *ns;

            if ((ns = (struct ArgusRecordStruct *) RaOutputProcess->queue->array[startline - 1]) != NULL) {

               ArgusRemoveFromQueue(RaOutputProcess->queue, &ns->qhdr, ARGUS_LOCK);
               ArgusReverseRecord(ns);

               if (ns->htblhdr != NULL)
                  ArgusRemoveHashEntry(&ns->htblhdr);

               RaProcessThisRecord (ArgusParser, ns);

               RaWindowCursorY++;
               if ((RaOutputProcess->queue->count - RaWindowStartLine) < RaDisplayLines) {
                  int maxwincount = RaOutputProcess->queue->count - RaWindowStartLine;
                  if (RaWindowCursorY > maxwincount) {
                     RaWindowCursorY = maxwincount;
                     beep();
                  }

               } else {
                  if (RaWindowCursorY > RaDisplayLines) {
                     if ((RaOutputProcess->queue->count - RaWindowStartLine) > RaDisplayLines) {
                        RaWindowStartLine++;
                        wscrl(RaCurrentWindow->window, 1);
                        ArgusTouchScreen();
                     } else
                        beep();

                     RaWindowCursorY = RaDisplayLines;
                  }
               }
               ArgusTouchScreen();
            }
            break;
         }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessDeviceControl(%p, 0x%x, 0x%x) returned 0x%x\n", win, status, ch);
#endif
   return (retn);
}

int
ArgusProcessEscape(WINDOW *win, int status, int ch)
{
   int retn = status;

#if defined(ARGUS_READLINE)
   struct timeval tvbuf, *tvp = &tvbuf;
   int eindex = 0;
   int escbuf[16];
   fd_set in;

   bzero(escbuf, sizeof(escbuf));
   tvp->tv_sec = 0; tvp->tv_usec = 10000;
   FD_ZERO(&in); FD_SET(0, &in);
   while ((select(1, &in, 0, 0, tvp) > 0) && (eindex < 2)) {
      if ((ch = wgetch(RaStatusWindow)) != ERR) {
         escbuf[eindex++] = ch;
      }
      FD_ZERO(&in); FD_SET(0, &in);
   }

   if (eindex == 2) {
      int offset;
      switch (escbuf[0]) {
         case '[': // process ESC 
            switch (escbuf[1]) {
               case 'A': // cursor up 
                  RaWindowCursorY--;
                  if (RaWindowCursorY < 1) {
                     RaWindowCursorY = 1;
                     if (RaWindowStartLine > 0) {
                        RaWindowStartLine--;
                        wscrl(RaCurrentWindow->window, -1);
                        ArgusTouchScreen();
                     } else
                        beep();
                  }
                  break;
               case 'B': // cursor down 
                  RaWindowCursorY++;
                  if ((RaOutputProcess->queue->count - RaWindowStartLine) < RaDisplayLines) {
                     int maxwincount = RaOutputProcess->queue->count - RaWindowStartLine;
                     if (RaWindowCursorY > maxwincount) {
                        RaWindowCursorY = maxwincount;
                        beep();
                     }

                  } else {
                     if (RaWindowCursorY > RaDisplayLines) {
                        if ((RaOutputProcess->queue->count - RaWindowStartLine) > RaDisplayLines) {
                           RaWindowStartLine++;
                           wscrl(RaCurrentWindow->window, 1);
                           ArgusTouchScreen();
                        } else
                           beep();

                        RaWindowCursorY = RaDisplayLines;
                     }
                  }
                  break;
               case 'C': { // cursor forward 
                  int startline = RaWindowCursorY + RaWindowStartLine;
                  struct ArgusRecordStruct *ns;
                  int len;

                  if ((ns = (struct ArgusRecordStruct *) RaOutputProcess->queue->array[startline - 1]) != NULL) {
                     char buf[MAXSTRLEN];

                     if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != startline)) {
                        if (ns->disp.str != NULL)
                           free(ns->disp.str);

                        buf[0] = '\0';
                        ns->rank = startline;
                        ArgusPrintRecord(ArgusParser, buf, ns, MAXSTRLEN);
                        ns->disp.str = strdup(buf);
                        ns->status &= ~ARGUS_RECORD_MODIFIED;
                     }

                     len = strlen(ns->disp.str);

                     bcopy(ns->disp.str, buf, len + 1);
                     RaWindowCursorX++;
                     if (RaWindowCursorX >= len) {
                        RaWindowCursorX = len - 1;
                        beep();
                     }
                  }
                  ArgusTouchScreen();
                  break;
               }

               case 'D': // cursor backward 
                  RaWindowCursorX--;
                  if (RaWindowCursorX < 0) {
                     RaWindowCursorX = 0;
                     beep();
                  }
                  ArgusTouchScreen();
                  break;
            }
            break;
         default:
            break;
      }
      offset = (RaWindowCursorY % (RaDisplayLines + 1));
      if (offset > (RaSortItems - RaWindowStartLine)) {
         RaWindowCursorY = (RaSortItems - RaWindowStartLine);
         offset = (RaSortItems - RaWindowStartLine);
      }
      offset += RaHeaderWinSize;
      wmove (RaCurrentWindow->window, offset, RaWindowCursorX);
   }
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessEscape(%p, 0x%x, 0x%x) returned 0x%x\n", win, status, ch);
#endif

   return (retn);
}

int
ArgusProcessEndofTransmission (WINDOW *win, int status, int ch)
{
   int retn = status;

   bzero (RaCommandInputStr, MAXSTRLEN);
   RaCommandIndex = 0;
   RaCursorOffset = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessEndOfTransmission(%p, 0x%x, 0x%x) returned 0x%x\n", win, status, ch);
#endif

   return (retn);
}

int
ArgusProcessKeyUp (WINDOW *win, int status, int ch)
{
   int retn = status;
   int done = 0, start = RaFilterIndex;

   switch (retn) {
      case RAGETTINGf: {
         do {
            RaFilterIndex = ((RaFilterIndex + 1) > ARGUS_DISPLAY_FILTER) ? ARGUS_REMOTE_FILTER : RaFilterIndex + 1;
            switch (RaFilterIndex) {
               case ARGUS_REMOTE_FILTER:
                  if (ArgusParser->ArgusRemoteFilter) {
                     sprintf (RaCommandInputStr, "remote %s ", ArgusParser->ArgusRemoteFilter);
                     RaCommandIndex = strlen(RaCommandInputStr);
                     RaFilterIndex = ARGUS_REMOTE_FILTER;
                     RaWindowImmediate = TRUE;
                     done++;
                     break;
                  }

               case ARGUS_LOCAL_FILTER:
                  if (ArgusParser->ArgusLocalFilter) {
                     sprintf (RaCommandInputStr, "local %s ", ArgusParser->ArgusLocalFilter);
                     RaCommandIndex = strlen(RaCommandInputStr);
                     RaFilterIndex = ARGUS_LOCAL_FILTER;
                     RaWindowImmediate = TRUE;
                     done++;
                     break;
                  }
               case ARGUS_DISPLAY_FILTER:
                  if (ArgusParser->ArgusDisplayFilter) {
                     sprintf (RaCommandInputStr, "display %s ", ArgusParser->ArgusDisplayFilter);
                     RaCommandIndex = strlen(RaCommandInputStr);
                     RaFilterIndex = ARGUS_DISPLAY_FILTER;
                     RaWindowImmediate = TRUE;
                     done++;
                     break;
                  }
            }
         } while ((start != RaFilterIndex) && !done);
         break;
      }

      default: {
         RaWindowCursorY--;
         if (RaWindowCursorY < 1) {
            RaWindowCursorY = 1;
            if (RaWindowStartLine > 0) {
               RaWindowStartLine--;
               wscrl(RaCurrentWindow->window, -1);
               ArgusTouchScreen();
            } else
               beep();
         }
         break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessKeyUp(%p, 0x%x, 0x%x) returned 0x%x\n", win, status, ch);
#endif

   return (retn);
}

int
ArgusProcessKeyDown (WINDOW *win, int status, int ch)
{
   int retn = status;
   int trips = 0, done = 0, start = RaFilterIndex;

   switch (retn) {
      case RAGETTINGf: {
         do {
            RaFilterIndex = ((RaFilterIndex - 1) < ARGUS_REMOTE_FILTER) ? ARGUS_DISPLAY_FILTER : RaFilterIndex - 1;
            switch (RaFilterIndex) {
               case ARGUS_DISPLAY_FILTER:
                  if (ArgusParser->ArgusDisplayFilter) {
                     sprintf (RaCommandInputStr, " display %s", ArgusParser->ArgusDisplayFilter);
                     RaCommandIndex = strlen(RaCommandInputStr);
                     RaFilterIndex = ARGUS_DISPLAY_FILTER;
                     RaWindowImmediate = TRUE;
                     done++;
                     break;
                  }

               case ARGUS_LOCAL_FILTER:
                  if (ArgusParser->ArgusLocalFilter) {
                     sprintf (RaCommandInputStr, " local %s", ArgusParser->ArgusLocalFilter);
                     RaCommandIndex = strlen(RaCommandInputStr);
                     RaFilterIndex = ARGUS_LOCAL_FILTER;
                     RaWindowImmediate = TRUE;
                     done++;
                     break;
                  }

               case ARGUS_REMOTE_FILTER:
                  if (ArgusParser->ArgusRemoteFilter) {
                     sprintf (RaCommandInputStr, " remote %s", ArgusParser->ArgusRemoteFilter);
                     RaCommandIndex = strlen(RaCommandInputStr);
                     RaFilterIndex = ARGUS_REMOTE_FILTER;
                     RaWindowImmediate = TRUE;
                     done++;
                     break;
                  }
            }
            trips++;
         } while ((start != RaFilterIndex) && !done && (trips < 3));
         break;
      }
      default: {
         RaWindowCursorY++;
         if ((RaOutputProcess->queue->count - RaWindowStartLine) < RaDisplayLines) {
            int maxwincount = RaOutputProcess->queue->count - RaWindowStartLine;
            if (RaWindowCursorY > maxwincount) {
               RaWindowCursorY = maxwincount;
               beep();
            }

         } else {
            if (RaWindowCursorY > RaDisplayLines) {
               if ((RaOutputProcess->queue->count - RaWindowStartLine) > RaDisplayLines) {
                  RaWindowStartLine++;
                  wscrl(RaCurrentWindow->window, 1);
                  ArgusTouchScreen();
               } else
                  beep();

               RaWindowCursorY = RaDisplayLines;
            }
         }
         break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessKeyDown(%p, 0x%x, 0x%x) returned 0x%x\n", win, status, ch);
#endif
   return (retn);
}

int
ArgusProcessKeyLeft (WINDOW *win, int status, int ch)
{
   int retn = status;

   if (++RaCursorOffset > RaCommandIndex)
      RaCursorOffset = RaCommandIndex;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessKeyLeft(%p, 0x%x, 0x%x) returned 0x%x\n", win, status, ch);
#endif
   return (retn);
}

int
ArgusProcessKeyRight (WINDOW *win, int status, int ch)
{
   int retn = status;

   if (--RaCursorOffset < 0)
      RaCursorOffset = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessKeyRight(%p, 0x%x, 0x%x) returned 0x%x\n", win, status, ch);
#endif
   return (retn);
}

int
ArgusProcessBell (WINDOW *win, int status, int ch)
{
   int retn = status;

   ArgusDisplayStatus = (ArgusDisplayStatus ? 0 : 1);
   ArgusZeroDebugString();
   if (ArgusParser->Pauseflag)
      ArgusSetDebugString ("Paused", LOG_ERR, ARGUS_LOCK);
   ArgusTouchScreen();

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessBell(%p, 0x%x, 0x%x) returned 0x%x\n", win, status, ch);
#endif
   return (retn);
}

int
ArgusProcessBackspace (WINDOW *win, int status, int ch)
{
   int retn = status;

   if (RaCursorOffset == 0) {
      RaCommandInputStr[RaCommandIndex--] = '\0';
      RaCommandInputStr[RaCommandIndex] = '\0';
   } else {
      if (RaCursorOffset < RaCommandIndex) {
         int z, start;
         start = RaCommandIndex - (RaCursorOffset + 1);
         if (start < 0)
            start = 0;
         for (z = start; z < (RaCommandIndex - 1); z++)
            RaCommandInputStr[z] = RaCommandInputStr[z + 1];
         RaCommandInputStr[RaCommandIndex--] = '\0';
         RaCommandInputStr[RaCommandIndex] = '\0';
         if (RaCursorOffset > RaCommandIndex)
            RaCursorOffset = RaCommandIndex;
      }
   }

   if (RaCommandIndex < 0)
      RaCommandIndex = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessBackspace(%p, 0x%x, 0x%x) returned 0x%x\n", win, status, ch);
#endif
   return (retn);
}


int
ArgusProcessDeleteLine (WINDOW *win, int status, int ch)
{
   int retn = status;

   bzero (RaCommandInputStr, MAXSTRLEN);
   RaCommandIndex = 0;
   RaCursorOffset = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessDeleteLine(%p, 0x%x, 0x%x) returned 0x%x\n", win, status, ch);
#endif
   return (retn);
}


int
ArgusProcessCharacter(WINDOW *win, int status, int ch)
{
   struct ArgusParserStruct *parser = ArgusParser;
   int retn = status, x;

   int iter;
   if (retn == RAGOTslash) {
      if (isdigit(ch) && (ch != '0')) {
         if (RaDigitPtr < 16)
            RaDigitBuffer[RaDigitPtr++] = ch;
      } else {
         if (RaDigitPtr) {
            char *ptr;
            RaIter= strtol(RaDigitBuffer, (char **)&ptr, 10);
            if (ptr == RaDigitBuffer)
               RaIter = 1;
            bzero(RaDigitBuffer, sizeof(RaDigitBuffer));
            RaDigitPtr = 0;
         } else
            RaIter = 1;

#if defined(ARGUSDEBUG)
         ArgusDebug (6, "ArgusProcessCommand: calling with %d iterations", RaIter);
#endif
      }
   } else
      RaIter = 1;

   for (iter = 0; iter < RaIter; iter++) {
      int olddir = -1;

      switch (retn) {
         case RAGOTcolon:
         case RAGOTslash: {
            ArgusZeroDebugString();
            switch (ch) {
               case 0x07: {
                  ArgusDisplayStatus = (ArgusDisplayStatus ? 0 : 1);
                  ArgusTouchScreen();
                  break;
               }
               case '%': {
                  ArgusParser->Pctflag = (ArgusParser->Pctflag == 1) ? 0 : 1;
                  if (ArgusParser->Pctflag)
                     RaInputString = "Toggle percent on";
                  else
                     RaInputString = "Toggle percent off";
                  break;
               }
               case 'A':
                  ArgusParser->Aflag = ArgusParser->Aflag ? 0 : 1;
                  break;
               case 'H':
                  ArgusParser->Hflag = ArgusParser->Hflag ? 0 : 1;
                  break;
               case 'P': {
                  ArgusParser->Pauseflag = (ArgusParser->Pauseflag > 0.0) ? 0.0 : 1.0;
                  if (ArgusParser->Pauseflag)
                     ArgusSetDebugString ("Paused", LOG_ERR, ARGUS_LOCK);
                  break;
               }
               case 'v':
                  if (ArgusParser->vflag) {
                     ArgusParser->vflag = 0;
                     ArgusReverseSortDir = 0;
                  } else {
                     ArgusParser->vflag = 1;
                     ArgusReverseSortDir++;
                  }

                  RaClientSortQueue(ArgusSorter, RaOutputProcess->queue, ARGUS_LOCK);
                  break;

               case 'N': 
                  olddir = ArgusSearchDirection;
                  ArgusSearchDirection = (ArgusSearchDirection == ARGUS_FORWARD) ?  ARGUS_BACKWARD : ARGUS_FORWARD;
               case 'n': {
                  char *ArgusSearchString = ArgusParser->ArgusSearchString, sbuf[1024];

                  if ((retn == RAGOTslash) && ((ArgusSearchString != NULL) && strlen(ArgusSearchString))) {
                     int cursx = RaWindowCursorX, cursy = RaWindowCursorY + RaWindowStartLine;
                     int linenum;
#if defined(ARGUS_THREADS)
                     pthread_mutex_lock(&RaCursesLock);
#endif
                     if ((linenum = RaSearchDisplay(ArgusParser, RaOutputProcess->queue, ArgusSearchDirection, &cursx, &cursy, ArgusSearchString, ARGUS_LOCK)) < 0) {
                        if (ArgusSearchDirection == ARGUS_FORWARD) {
                           sprintf (sbuf, "search hit BOTTOM, continuing at TOP");
                           ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
                           cursx = 0; cursy = 0;
                        } else {
                           sprintf (sbuf, "search hit TOP, continuing at BOTTOM");
                           ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
                           cursx = RaScreenColumns; cursy = RaOutputProcess->queue->count;
                        }
                        linenum = RaSearchDisplay(ArgusParser, RaOutputProcess->queue, ArgusSearchDirection, &cursx, &cursy, ArgusSearchString, ARGUS_LOCK);
                     }
                     if (linenum >= 0) {
                        if ((linenum < RaWindowStartLine) || ((linenum > RaWindowStartLine + RaDisplayLines))) {
                           int startline = ((cursy - 1)/ RaDisplayLines) * RaDisplayLines;
                           startline = (RaOutputProcess->queue->count > startline) ? startline : RaOutputProcess->queue->count - RaDisplayLines;
                           startline = (startline > 0) ? startline : 0;
                           RaWindowStartLine = startline;

                           if ((RaWindowCursorY = cursy % RaDisplayLines) == 0)
                              RaWindowCursorY = RaDisplayLines;

                        } else
                           RaWindowCursorY = cursy - RaWindowStartLine;

                        RaWindowCursorX = cursx;
                        ArgusTouchScreen();
                        RaRefreshDisplay();
                     } 
#if defined(ARGUS_THREADS)
                     pthread_mutex_unlock(&RaCursesLock);
#endif
                  }
                  if (olddir != -1)
                     ArgusSearchDirection = olddir;
                  break;
               }

               case KEY_LEFT:
               case 'h': {
                  RaWindowCursorX--;
                  if (RaWindowCursorX < 0) {
                     RaWindowCursorX = 0;
                     beep();
                  }
                  break;
               }
               case 'j': 
               case 0x05:
               case 0x0E:
               case KEY_DOWN: {
                  RaWindowCursorY++;
                  if ((RaOutputProcess->queue->count - RaWindowStartLine) < RaDisplayLines) {
                     int maxwincount = RaOutputProcess->queue->count - RaWindowStartLine;
                     if (RaWindowCursorY > maxwincount) {
                        RaWindowCursorY = maxwincount;
                        beep();
                     }

                  } else {
                     if (RaWindowCursorY > RaDisplayLines) {
                        if ((RaOutputProcess->queue->count - RaWindowStartLine) > RaDisplayLines) {
                           RaWindowStartLine++;
                           wscrl(RaCurrentWindow->window, 1);
                           ArgusTouchScreen();
                        } else
                           beep();

                        RaWindowCursorY = RaDisplayLines;
                     }
                  }
                  ArgusSearchHitRank   = 0;
                  break;
               }

               case 0x19:
               case KEY_UP:
               case 'k': {
                  RaWindowCursorY--;
                  if (RaWindowCursorY < 1) {
                     RaWindowCursorY = 1;
                     if (RaWindowStartLine > 0) {
                        RaWindowStartLine--;
                        wscrl(RaCurrentWindow->window, -1);
                        ArgusTouchScreen();
                     } else
                        beep();
                  }
                  ArgusSearchHitRank   = 0;
                  break;
               }

               case KEY_RIGHT:
               case 'l': {
                  RaWindowCursorX++;
                  if (RaWindowCursorX >= RaScreenColumns) {
                     RaWindowCursorX = RaScreenColumns - 1;
                     beep();
                  }
                  ArgusSearchHitRank   = 0;
                  break;
               }

               case 'g':
               case KEY_HOME:
                  if ((RaWindowStartLine != 0) || ((RaWindowCursorX != 0) || (RaWindowCursorY != 0))) {
                     RaWindowStartLine = 0;
                     RaWindowCursorX = 0;
                     RaWindowCursorY = 1;
                     RaWindowModified = RA_MODIFIED;
                     ArgusSearchHitRank   = 0;
                  } else
                     beep();
                  break;

               case 'G':
               case KEY_END:
                  if (RaWindowStartLine != (RaOutputProcess->queue->count - RaDisplayLines)) {
                     RaWindowStartLine = RaOutputProcess->queue->count - RaDisplayLines;
                     if (RaWindowStartLine < 0)
                        RaWindowStartLine = 0;
                     RaWindowCursorX = 0;
                     RaWindowCursorY = RaOutputProcess->queue->count - RaWindowStartLine;
                     if (RaWindowCursorY >= RaDisplayLines)
                        RaWindowCursorY = RaDisplayLines - 1;
                     RaWindowModified = RA_MODIFIED;
                     ArgusSearchHitRank   = 0;
                  } else
                     beep();
                  break;
               case 0x06:
               case 0x04:
               case ' ':
               case KEY_NPAGE: {
                  int count = (RaSortItems - RaWindowStartLine) - 1;
                  if (count > RaDisplayLines) {
                     RaWindowStartLine += RaDisplayLines - 1;
                     wscrl(RaCurrentWindow->window, RaDisplayLines - 1);
                     RaWindowModified = RA_MODIFIED;

                     if ((count = (RaSortItems - RaWindowStartLine) - 1) < RaDisplayLines) {
                        wmove(win, count + 2, 0);
                        wclrtobot(win);
                     }

                  } else {
                     if (count) {
                        RaWindowStartLine += count;
                        wscrl(RaCurrentWindow->window, count);
                        RaWindowModified = RA_MODIFIED;
                        wmove(win, count + 2, 0);
                        wclrtobot(win);
                     } else
                        beep();
                  }
                  break;
               }

               case 0x02:
               case 0x15:
               case KEY_PPAGE:
                  if (RaWindowStartLine > 0) { 
                     wscrl(RaCurrentWindow->window, (RaDisplayLines > RaWindowStartLine) ? -RaWindowStartLine : -(RaDisplayLines - 1));
                     RaWindowStartLine -= (RaDisplayLines - 1);
                     if (RaWindowStartLine < 0)
                        RaWindowStartLine = 0;
                     RaWindowModified = RA_MODIFIED;
                  } else
                     beep();
                  break;

               case 'b': {
                  int startline = RaWindowCursorY + RaWindowStartLine;
                  struct ArgusRecordStruct *ns;

                  if (RaWindowCursorX == 0) {
                     if (RaWindowCursorY > 1) {
                           RaWindowCursorY--;
                     } else {
                        if (RaWindowStartLine > 0) {
                           RaWindowStartLine--;
                           ArgusTouchScreen();
                        } else {
                           beep();
                           break;
                        }
                     }

                     startline = RaWindowCursorY + RaWindowStartLine;
                     if (startline == 0) {
                        startline = 1;
                     }
                  }

                  if (RaSortItems >= startline) {
                     if ((ns = (struct ArgusRecordStruct *) RaOutputProcess->queue->array[startline - 1]) != NULL) {
                        char buf[MAXSTRLEN], *ptr;

                        if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != startline)) {
                           if (ns->disp.str != NULL)
                              free(ns->disp.str);

                           buf[0] = '\0';
                           ns->rank = startline;
                           ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                           ns->disp.str = strdup(buf);
                           ns->status &= ~ARGUS_RECORD_MODIFIED;
                        }

                        bcopy(ns->disp.str, buf, strlen(ns->disp.str) + 1);

                        if (RaWindowCursorX == 0)
                           RaWindowCursorX = strlen(buf) - 1;

                        if ((ptr = &buf[RaWindowCursorX]) != NULL) {
                           while ((ptr > buf) && isspace((int)*(ptr - 1)))
                              ptr--;

                           if (ispunct((int)*(--ptr))) {
                              while ((ptr > buf) && ispunct((int)*(ptr - 1)))
                                 ptr--;
                           } else {
                              while ((ptr > buf) && !(isspace((int)*(ptr - 1)) || ispunct((int)*(ptr - 1))))
                                 ptr--;
                           }
                           RaWindowCursorX = ptr - buf;
                        }
                     }
                  }
                  ArgusSearchHitRank   = 0;
                  break;
               }

               case 'w': {
                  int startline = RaWindowCursorY + RaWindowStartLine;
                  struct ArgusRecordStruct *ns;

                  if (startline == 0)
                     startline = 1;

                  if (RaSortItems >= startline) {
                     int done = 0;
                     int shifted = 0;

                     while (!done) {
                        if ((ns = (struct ArgusRecordStruct *) RaOutputProcess->queue->array[startline - 1]) != NULL) {
                           char buf[MAXSTRLEN], *ptr;
                           int cursor, passpunct = 0;

                           if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != startline)) {
                              char buf[MAXSTRLEN];

                              if (ns->disp.str != NULL)
                                 free(ns->disp.str);

                              buf[0] = '\0';
                              ns->rank = startline;
                              ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                              ns->disp.str = strdup(buf);
                              ns->status &= ~ARGUS_RECORD_MODIFIED;
                           }

                           bcopy(ns->disp.str, buf, strlen(ns->disp.str) + 1);

                           if (!shifted) {
                              cursor = RaWindowCursorX + 1;
                              if (ispunct((int)buf[RaWindowCursorX]))
                                 passpunct = 1;
                           } else
                              cursor = RaWindowCursorX;

                           if ((ptr = &buf[cursor]) != NULL) {
                              if (!shifted)
                                 while ((*ptr != '\0') && !(isspace((int)*ptr)) && (passpunct ? ispunct((int)*ptr) : !(ispunct((int)*ptr))))
                                    ptr++;
                              while (isspace((int)*ptr) && (*ptr != '\0'))
                                 ptr++;
                              if (*ptr != '\0') {
                                 RaWindowCursorX = ptr - buf;
                                 done++;
                              } else {
                                 if (RaWindowCursorY == RaDisplayLines) {
                                    if (RaOutputProcess->queue->array[startline] != NULL) {
                                       shifted++;
                                       startline++;
                                       RaWindowStartLine++;
                                       ArgusTouchScreen();
                                       RaWindowCursorX = 0;
                                    }
                                 } else {
                                    shifted++;
                                    startline++;
                                    RaWindowCursorY++;
                                    RaWindowCursorX = 0;
                                 }
                              }
                           }
                        }
                     }
                     ArgusSearchHitRank   = 0;
                  }
                  break;
               }

               case '0':
               case '^': {
                  RaWindowCursorX = 0;
                  ArgusSearchHitRank   = 0;
                  break;
               }
               case '$': {
                  int startline = RaWindowCursorY + RaWindowStartLine;
                  struct ArgusRecordStruct *ns;

                  if (startline == 0)
                     startline = 1;

                  if (RaSortItems >= startline) {
                     if ((ns = (struct ArgusRecordStruct *) RaOutputProcess->queue->array[startline - 1]) != NULL) {
                        char buf[MAXSTRLEN];
                        int len = strlen(ns->disp.str);

                        if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != startline)) {
                           char buf[MAXSTRLEN];

                           if (ns->disp.str != NULL)
                              free(ns->disp.str);

                           buf[0] = '\0';
                           ns->rank = startline;
                           ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                           ns->disp.str = strdup(buf);
                           ns->status &= ~ARGUS_RECORD_MODIFIED;
                        }

                        len = strlen(ns->disp.str);
                        bcopy(ns->disp.str, buf, len + 1);
                        if ((RaWindowCursorX = len - 1) < 0)
                           RaWindowCursorX = 0;
                     }
                  }
                  ArgusSearchHitRank   = 0;
                  break;
               }

               case '?':
                  RaCursesSetWindowFocus(ArgusParser, RaStatusWindow);
#if defined(ARGUS_READLINE)
                  argus_getsearch_string(ARGUS_BACKWARD);
#else
                  retn = RAGETTINGslash;
                  RaInputString = "?";
                  ArgusSearchDirection = ARGUS_BACKWARD;
                  bzero(RaCommandInputStr, MAXSTRLEN);
                  RaCommandIndex = 0;
                  RaWindowCursorX = 0;
#endif
                  break;

               case '/':
                  RaCursesSetWindowFocus(ArgusParser, RaStatusWindow);
#if defined(ARGUS_READLINE)
                  argus_getsearch_string(ARGUS_FORWARD);
#else
                  retn = RAGETTINGslash;
                  RaInputString = "/";
                  ArgusSearchDirection = ARGUS_FORWARD;
                  bzero(RaCommandInputStr, MAXSTRLEN);
                  RaCommandIndex = 0;
                  RaWindowCursorX = 0;
#endif
                  break;

               case ':': {
                  RaCursesSetWindowFocus(ArgusParser, RaStatusWindow);
#if defined(ARGUS_READLINE)
                  argus_command_string();
#else
                  retn = RAGETTINGcolon;
                  RaInputString = ":";
                  bzero(RaCommandInputStr, MAXSTRLEN);
                  RaCommandIndex = 0;
                  RaWindowCursorX = 0;
#endif
                  break;
               }
            }
            break;
         }

         case RAGETTINGq:
            if (*RaCommandInputStr == 'y') {
               RaParseComplete(SIGINT);
            } else {
               retn = RAGOTslash;
               RaInputString = RANEWCOMMANDSTR;
               RaCommandInputStr[0] = '\0';
               RaCommandIndex = 0;
            }
            break;


         case RAGETTINGcolon: {
            if (RaCommandIndex == 0) {
               switch (ch) {
                  case '%': {
                     ArgusParser->Pctflag = (ArgusParser->Pctflag == 1) ? 0 : 1;
                     if (ArgusParser->Pctflag)
                        RaInputString = "Toggle percent on";
                     else
                        RaInputString = "Toggle percent off";
                     break;
                  }

                  case 'a': {
                     retn = RAGETTINGa;
                     RaInputString = RAGETTINGaSTR;
                     break;
                  }

                  case 'A':
                     ArgusParser->Aflag = ArgusParser->Aflag ? 0 : 1;
                     break;

                  case 'c': {
                     break;
                  }

                  case 'd': {
                     retn = RAGETTINGd;
                     RaInputString = RAGETTINGdSTR;

                     if (ArgusParser->ArgusRemoteHostList) {
                        struct ArgusInput *input = (void *)ArgusParser->ArgusActiveHosts->start;
                        do {
                           sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s:%d", input->hostname, input->portnum);
                           RaCommandIndex = strlen(RaCommandInputStr); 
                           input = (void *)input->qhdr.nxt;
                        } while (input != (void *)ArgusParser->ArgusActiveHosts->start);
                     }

                     break;
                  }
    
                  case 'D': {
                     retn = RAGETTINGD;
                     RaInputString = RAGETTINGDSTR;
                     sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d", ArgusParser->debugflag);
                     RaCommandIndex = strlen(RaCommandInputStr); 
                     break;
                  }

                  case 'e': {
                     retn = RAGETTINGe;
                     RaInputString = RAGETTINGeSTR;
                     if (ArgusParser->estr) {
                        sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", ArgusParser->estr);
                     } 
                     RaCommandIndex = strlen(RaCommandInputStr); 
                     break;
                  }

                  case 'f': {
                     retn = RAGETTINGf;
                     RaInputString = RAGETTINGfSTR;
                     RaFilterIndex = 3;
                     if (ArgusParser->ArgusRemoteFilter) {
                        sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " remote %s", ArgusParser->ArgusRemoteFilter);
                        RaFilterIndex = ARGUS_REMOTE_FILTER;
                     } else
                     if (ArgusParser->ArgusLocalFilter) {
                        sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " local %s", ArgusParser->ArgusLocalFilter);
                        RaFilterIndex = ARGUS_LOCAL_FILTER;
                     } else
                     if (ArgusParser->ArgusDisplayFilter) {
                        sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " display %s", ArgusParser->ArgusDisplayFilter);
                        RaFilterIndex = ARGUS_DISPLAY_FILTER;
                     }
                     RaCommandIndex = strlen(RaCommandInputStr); 
                     break;
                  }

                  case 'm': {
                     struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
                     struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
                     int i;

                     retn = RAGETTINGm;
                     RaInputString = RAGETTINGmSTR;

                     if (agg->modeStr != NULL) {
                        sprintf (RaCommandInputStr, "%s", agg->modeStr);
                     } else {
                        for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                           if (agg->mask & (0x01LL << i)) {
                              sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", ArgusMaskDefs[i].name);

                              switch (i) {
                                 case ARGUS_MASK_SADDR:
                                    if (agg->saddrlen > 0)
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "/%d", agg->saddrlen);
                                    break;
                                 case ARGUS_MASK_DADDR:
                                    if (agg->daddrlen > 0)
                                       sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "/%d", agg->daddrlen);
                                    break;
                              }
                           }
                        }

                        agg->modeStr = strdup(RaCommandInputStr);
                     }

                     RaCommandIndex = strlen(RaCommandInputStr);
                     break;
                  }

                  case 'M': {
                     struct ArgusModeStruct *mode;
                     retn = RAGETTINGM;
                     RaInputString = RAGETTINGMSTR;
            
                     if ((mode = ArgusParser->ArgusModeList) != NULL) {
                        while (mode) {
                           sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", mode->mode);
                           mode = mode->nxt;
                        }
                     }
                     RaCommandIndex = strlen(RaCommandInputStr);
                     break;
                  }

                  case 'n':
                     retn = RAGETTINGn;
                     RaInputString = RAGETTINGnSTR;
                     break;

                  case 'N':
                     retn = RAGETTINGN;
                     RaInputString = RAGETTINGNSTR;
                     break;

                  case 'p': {
                     retn = RAGETTINGp;
                     RaInputString = RAGETTINGpSTR;
                     sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d", ArgusParser->pflag);
                     RaCommandIndex = strlen(RaCommandInputStr); 
                     break;
                  }

                  case 'P': {
                     ArgusParser->Pauseflag = (ArgusParser->Pauseflag > 0.0) ? 0.0 : 1.0;
                     if (ArgusParser->Pauseflag)
                        ArgusSetDebugString ("Paused", LOG_ERR, ARGUS_LOCK);
                     break;
                  }

                  case 't':
                     retn = RAGETTINGt;
                     RaInputString = RAGETTINGtSTR;
                     if (ArgusParser->timearg) {
                        sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", ArgusParser->timearg);
                     }
                     RaCommandIndex = strlen(RaCommandInputStr); 
                     break;

                  case 'T':
                     retn = RAGETTINGT;
                     RaInputString = RAGETTINGTSTR;
                     sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d.%06d",
                        (int)ArgusParser->timeout.tv_sec, (int)ArgusParser->timeout.tv_usec);
                     RaCommandIndex = strlen(RaCommandInputStr); 
                     break;

                  case 'R': {
                     struct ArgusInput *input = ArgusParser->ArgusInputFileList;
                     retn = RAGETTINGR;
                     RaInputString = RAGETTINGRSTR;
                     while (input) {
                        sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", input->filename);
                        RaCommandIndex = strlen(RaCommandInputStr); 
                        input = (void *)input->qhdr.nxt;
                     }
                     break;
                  }

                  case 'r': {
                     struct ArgusInput *input = ArgusParser->ArgusInputFileList;
                     retn = RAGETTINGr;
                     RaInputString = RAGETTINGrSTR;
                     while (input) {
                        sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s", input->filename);
                        RaCommandIndex = strlen(RaCommandInputStr); 
                        input = (void *)input->qhdr.nxt;
                     }
                     break;
                  }

                  case 'S': {
                     struct ArgusInput *input = ArgusParser->ArgusRemoteHostList;
                     retn = RAGETTINGS;
                     RaInputString = RAGETTINGSSTR;
                     while (input) {
                        sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " %s:%d", input->hostname, input->portnum);
                        RaCommandIndex = strlen(RaCommandInputStr); 
                        input = (void *)input->qhdr.nxt;
                     }
                     break;
                  }

                  case 's': {
                     int x, y;
                     retn = RAGETTINGs;
                     RaInputString = RAGETTINGsSTR;
                     for (x = 0; x < ARGUS_MAX_SORT_ALG; x++) {
                        if (ArgusSorter->ArgusSortAlgorithms[x]) {
                           for (y = 0; y < ARGUS_MAX_SORT_ALG; y++) {
                              if (ArgusSorter->ArgusSortAlgorithms[x] == ArgusSortAlgorithmTable[y]) {
                                 sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", 
                                       ArgusSortKeyWords[y]);
                                 break;
                              }
                           }
                        }
                     }
                     RaCommandIndex = strlen(RaCommandInputStr); 
                     break;
                  }

                  case 'u':
                     retn = RAGETTINGu;
                     RaInputString = RAGETTINGuSTR;
                     sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d.", (int) RaCursesUpdateInterval.tv_sec);
                     sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%06d",(int) RaCursesUpdateInterval.tv_usec);
                     RaCommandIndex = strlen(RaCommandInputStr); 
                     break;

                  case 'U':
                     retn = RAGETTINGU;
                     RaInputString = RAGETTINGUSTR;
                     sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%2.2f", RaUpdateRate);
                     RaCommandIndex = strlen(RaCommandInputStr); 
                     break;

                  case 'w':
                     retn = RAGETTINGw;
                     RaInputString = RAGETTINGwSTR;
                     break;

                  case 'F': {
                     retn = RAGETTINGF;
                     RaInputString = RAGETTINGFSTR;

                     for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                        int y;
                        if (parser->RaPrintAlgorithmList[x] != NULL) {
                           for (y = 0; y < MAX_PRINT_ALG_TYPES; y++) {
                              if ((void *) parser->RaPrintAlgorithmList[x]->print == (void *) RaPrintAlgorithmTable[y].print) {
                                 sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s:%d ",
                                    RaPrintAlgorithmTable[y].field, RaPrintAlgorithmTable[y].length);
                                 break;
                              }
                           }
                        } else
                           break;
                     }
                     RaCommandIndex = strlen(RaCommandInputStr);
                     break;
                  }

                  case 'Q':
                     retn = RAGETTINGq;
                     RaInputString = RAGETTINGqSTR;
                     break;

                  case 'H':
                     ArgusParser->Hflag = ArgusParser->Hflag ? 0 : 1;
                     break;

                  case 'h':
                     retn = RAGETTINGh;
                     RaInputString = RAGETTINGhSTR;
                     RaWindowStatus = 0;
                     RaOutputHelpScreen();
                     break;

                  case 'v': 
                     if (ArgusParser->vflag) {
                        ArgusParser->vflag = 0;
                        ArgusReverseSortDir = 0;
                     } else {
                        ArgusParser->vflag = 1;
                        ArgusReverseSortDir++;
                     }

                     RaClientSortQueue(ArgusSorter, RaOutputProcess->queue, ARGUS_LOCK);
                     break;

                  case '=':  {
                     struct ArgusRecordStruct *ns = NULL;

                     werase(RaCurrentWindow->window);
                     ArgusTouchScreen();
#if defined(ARGUS_THREADS)
                     pthread_mutex_lock(&RaOutputProcess->queue->lock);
#endif
                     while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaOutputProcess->queue, ARGUS_NOLOCK)) != NULL) {
                        if (ArgusSearchHitRecord == ns) {
                           ArgusResetSearch();
                        }
                        ArgusDeleteRecordStruct (ArgusParser, ns);
                     }

                     ArgusEmptyHashTable(RaOutputProcess->htable);
                     ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                     ArgusParser->RaClientUpdate.tv_sec = 0;
                     ArgusParser->ArgusTotalRecords = 0;
                     RaCursesStartTime.tv_sec = 0;
                        RaCursesStartTime.tv_usec = 0;
                        RaCursesStopTime.tv_sec = 0;
                        RaCursesStopTime.tv_usec = 0;
                        if ((ns = ArgusParser->ns) != NULL) {
                           ArgusDeleteRecordStruct (ArgusParser, ns);
                           ArgusParser->ns = NULL;
                        }

#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&RaOutputProcess->queue->lock);
#endif
                        break;
                     }

                     case 'z':  
                        if (++ArgusParser->zflag > 1) {
                           ArgusParser->zflag = 0;
                        }
                        break;

                     case 'Z':  
                        switch (ArgusParser->Zflag) {
                           case '\0': ArgusParser->Zflag = 'b'; break;
                           case  'b': ArgusParser->Zflag = 's'; break;
                           case  's': ArgusParser->Zflag = 'd'; break;
                           case  'd': ArgusParser->Zflag = '\0'; break;
                        }
                        break;

                     default:
                        RaCommandInputStr[RaCommandIndex++] = ch;
                        break;

                  }
                  break;
               }
            }

            default: {
               switch (ch) {
                  case KEY_RIGHT:
                     if (--RaCursorOffset < 0)
                        RaCursorOffset = 0;
                     break;
                  case KEY_LEFT:
                     if (++RaCursorOffset > RaCommandIndex)
                        RaCursorOffset = RaCommandIndex;
                     break;
     
                  default:
                     if (isascii(ch)) {
                        if (RaCursorOffset == 0) 
                           RaCommandInputStr[RaCommandIndex++] = ch;
                        else {
                           int z, start; 
                           start = RaCommandIndex - RaCursorOffset;
                           for (z = RaCommandIndex; z > start; z--)
                              RaCommandInputStr[z] = RaCommandInputStr[z-1];

                           RaCommandInputStr[start] = ch;
                           RaCommandIndex++;
                        }
                     }
               }
               break;
            }
         }

         if (ArgusParser->Pauseflag)
            ArgusSetDebugString ("Paused", LOG_ERR, ARGUS_LOCK);
      }

#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusProcessCharacter(%p, 0x%x, 0x%x) returned 0x%x\n", win, status, ch, retn);
#endif
      return (retn);
}


void
ArgusDrawWindow(struct ArgusWindowStruct *ws)
{
      WINDOW *win = ws->window;

      if (win == RaCurrentWindow->window) {
         struct ArgusParserStruct *parser = ArgusParser;
         struct ArgusRecordStruct *ns = NULL;
         struct ArgusQueueStruct *queue = RaOutputProcess->queue;

         if ((RaWindowModified == RA_MODIFIED) || ArgusAlwaysUpdate) {
            int x = 0, cnt = 0;

            parser->RaLabel = NULL;
            if (RaWindowStatus) {
#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&queue->lock);
#endif
               if (ArgusParser->RaCursesMode) 
                  RaClientSortQueue(ArgusSorter, queue, ARGUS_NOLOCK);
               else
                  RaClientSortQueue(ArgusSorter, queue, ARGUS_NOLOCK | ARGUS_NOSORT);

               if (ArgusParser->RaCursesMode) {
               if (queue->count) {
                  if (RaSortItems) {
                     if (queue == RaOutputProcess->queue) {
                        int i;

                        if (ArgusParser->ns) {
                           ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                           ArgusParser->ns = NULL;
                        }
                        for (i = 0; i < queue->count; i++) {
                           struct ArgusRecordStruct *ns;
                           if ((ns = (struct ArgusRecordStruct *)queue->array[i]) == NULL)
                              break;
                           if (ArgusParser->ns)
                              ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
                           else
                              ArgusParser->ns = ArgusCopyRecordStruct (ns);
                        }
                     }
                  }

                  if (queue->array != NULL) {
                     int i;
                     if (parser->ns != NULL) {
#if defined(ARGUS_COLOR_SUPPORT)
                        int attrs = 0;
                        if (ArgusTerminalColors) {
                           attrs = COLOR_PAIR(ARGUS_WHITE);
                           wattron(win, attrs);
                        }
#endif
                        if (parser->RaLabel == NULL)
                           parser->RaLabel = ArgusGenerateLabel(parser, parser->ns);
                        mvwaddnstr (win, 0, 0, parser->RaLabel, RaScreenColumns);
                        wclrtoeol(win);
#if defined(ARGUS_COLOR_SUPPORT)
                        if (ArgusTerminalColors) {
                           wattroff(win, attrs);
                        }
#endif
                     }

                     if (queue->count < RaWindowStartLine) {
                        RaWindowStartLine = queue->count - RaDisplayLines;
                        RaWindowStartLine = (RaWindowStartLine > 0) ? RaWindowStartLine : 0;
                     }

                     cnt = ((RaDisplayLines > 0) ? RaDisplayLines : RaWindowLines) - 1;
                     cnt = (cnt > (queue->count - RaWindowStartLine)) ? (queue->count - RaWindowStartLine) : cnt;

                     for (x = 0, i = RaWindowStartLine; x < cnt; x++, i++) {
                        if ((ns = (struct ArgusRecordStruct *) queue->array[i]) != NULL) {
#if defined(ARGUS_COLOR_SUPPORT)
                           int z, sz = -1, ez = 0;
                           attr_t attr, tattr;
                           short pair, tpair;
#endif
                           if (ArgusAlwaysUpdate || (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != (i + 1)))) {
                              char buf[MAXSTRLEN];

                              bzero(buf, RaScreenColumns + 1);

                              if (ns->disp.str != NULL)
                                 free(ns->disp.str);

                              ns->rank =  i + 1;
                              ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                              ns->disp.str = strdup(buf);
                           }

                           mvwprintw (win, x + 1, 0, "%s", ns->disp.str);
                           wclrtoeol(win);

#if defined(ARGUS_COLOR_SUPPORT)
                           if (ArgusTerminalColors) {
                              if (wattr_get(win, &attr, &pair, NULL) == ERR)
                                 ArgusLog (LOG_ERR, "wattr_get failed");
                              tattr = attr; tpair = pair;

                              ArgusGetDisplayLineColor(ArgusParser, win, ns, RaColorArray);

                              for (z = 0; z < RaScreenColumns; z++) {
                                 if (sz == -1) sz = z;
                                 if ((tattr != RaColorArray[z].attr) || (tpair != RaColorArray[z].pair)) {
                                    if (ez == 0) {
                                       tattr = RaColorArray[z].attr;
                                       tpair = RaColorArray[z].pair;
                                    } else {
                                       if ((tattr != attr) || (tpair != pair))
                                          mvwchgat(win, x + 1, sz, (ez - sz) + 1, tattr, PAIR_NUMBER(tpair), NULL);
                                       sz = z;
                                       ez = 0;
                                    }
                                 } else
                                    ez = z;
                              }

                              if ((tattr != attr) || (tpair != pair))
                                 mvwchgat(win, x + 1, sz, (ez - sz) + 1, attr, PAIR_NUMBER(tpair), NULL);
                           }
#endif
                           wmove(win, x + 2, 0);

                        } else
                           break;
                     }
                  }

                  if (x < (RaDisplayLines - 1)) {
                     wmove(win, x + 1, 0);
                     wclrtobot(win);
                  }

                  if (parser->ArgusSearchString != NULL) {
                     if (ArgusSearchHitRecord != NULL) {
                        int rank = ArgusSearchHitRecord->rank;
                        if (ArgusSearchHitRank && (ArgusSearchHitRank != rank)) {
#ifdef ARGUSDEBUG
                           ArgusDebug (2, "RaSearchResults: %d was %d\n", rank, ArgusSearchHitRank);
#endif
                           if ((rank < RaWindowStartLine) || ((rank > (RaWindowStartLine + RaDisplayLines)))) {
                              int startline = ((rank - 1)/ RaDisplayLines) * RaDisplayLines;
                              startline = (RaOutputProcess->queue->count > startline) ? startline : RaOutputProcess->queue->count - RaDisplayLines;
                              startline = (startline > 0) ? startline : 0;
                              RaWindowStartLine = startline;

                              if ((RaWindowCursorY = rank % RaDisplayLines) == 0)
                                 RaWindowCursorY = RaDisplayLines;

                           } else
                              RaWindowCursorY = rank - RaWindowStartLine;
                           ArgusSearchHitRank = rank;
                        }

                     } else {
                        int linenum, cursx, cursy;
                        char sbuf[1024];

                        cursx = RaWindowCursorX, cursy = RaWindowCursorY + RaWindowStartLine;
                        if ((linenum = RaSearchDisplay(ArgusParser, RaOutputProcess->queue, ArgusSearchDirection, &cursx, &cursy, parser->ArgusSearchString, ARGUS_NOLOCK)) < 0) {

                           if (ArgusSearchDirection == ARGUS_FORWARD) {
                              sprintf (sbuf, "search hit BOTTOM, continuing at TOP");
                              ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
                              cursx = 0; cursy = 0;
                           } else {
                              sprintf (sbuf, "search hit TOP, continuing at BOTTOM");
                              ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
                              cursx = RaScreenColumns; cursy = RaOutputProcess->queue->count;
                           }
                           linenum = RaSearchDisplay(ArgusParser, RaOutputProcess->queue, ArgusSearchDirection, &cursx, &cursy, parser->ArgusSearchString, ARGUS_NOLOCK);
                        }
                        if (linenum >= 0) {
                           if ((linenum < RaWindowStartLine) || ((linenum > RaWindowStartLine + RaDisplayLines))) {
                              int startline = ((cursy - 1)/ RaDisplayLines) * RaDisplayLines;
                              startline = (RaOutputProcess->queue->count > startline) ? startline : RaOutputProcess->queue->count - RaDisplayLines;
                              startline = (startline > 0) ? startline : 0;
                              RaWindowStartLine = startline;

                              if ((RaWindowCursorY = cursy % RaDisplayLines) == 0)
                                 RaWindowCursorY = RaDisplayLines;

                           } else
                              RaWindowCursorY = cursy - RaWindowStartLine;

                           RaWindowCursorX = cursx;
                        }
                     }

                     RaHighlightDisplay(ArgusParser, RaOutputProcess->queue, parser->ArgusSearchString);
                  }
               }
            }

#if defined(ARGUS_MYSQL)
            if (RaSQLUpdateDB && RaSQLCurrentTable) {
               char *sbuf = calloc(1, MAXBUFFERLEN);
               int i;
 
               if (RaOutputProcess->queue->array != NULL) {
                  for (i = 0; i < RaOutputProcess->queue->count; i++) {
                     struct ArgusRecordStruct *ns = (struct ArgusRecordStruct *)RaOutputProcess->queue->array[i];
 
                     if (ns && (ns->status & ARGUS_RECORD_MODIFIED)) {
                        ArgusScheduleSQLQuery (ArgusParser, ArgusParser->ArgusAggregator, ns, sbuf, MAXBUFFERLEN, ARGUS_STATUS);
                        ns->status &= ~ARGUS_RECORD_MODIFIED;
                     }
                  }
               }

               free(sbuf);
            }
#endif

#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&queue->lock);
#endif
         }
         wmove(RaCurrentWindow->window, RaWindowCursorY, RaWindowCursorX);
         RaWindowModified = 0;
         RaWindowImmediate = FALSE;
      }
   }

   if (win == RaHeaderWindow)
      RaUpdateHeaderWindow (win);

   if (win == RaDebugWindow)
      RaUpdateDebugWindow (win);

   if (win == RaStatusWindow)
      RaUpdateStatusWindow (win);
}


// Manage curses screen.

#if defined(ARGUS_CURSES)

void
RaResizeHandler (int sig)
{
   RaScreenResize = TRUE;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaResizeHandler(%d)\n", sig);
#endif
}

void
ArgusOutputProcessInit()
{
   struct ArgusDomainStruct *dom = NULL;
   struct ArgusWindowStruct *ws  = NULL;

#if defined(ARGUS_THREADS)
/*
   sigset_t blocked_signals;

   sigemptyset (&blocked_signals);
   sigaddset (&blocked_signals, SIGWINCH);
   pthread_sigmask(SIG_UNBLOCK, &blocked_signals, NULL);
*/

   (void) signal (SIGWINCH,(void (*)(int)) RaResizeHandler);
#endif

   if (ArgusParser->RaCursesMode) {
      RaInitCurses();
   }

   if ((ArgusDomainQueue = ArgusNewQueue()) == NULL)
      ArgusLog(LOG_ERR, "ArgusOutputProcessInit: RaNewQueue error %s", strerror(errno));

   if ((ArgusWindowQueue = ArgusNewQueue()) == NULL)
      ArgusLog(LOG_ERR, "ArgusOutputProcessInit: RaNewQueue error %s", strerror(errno));

   if ((ws = (struct ArgusWindowStruct *)ArgusCalloc(1, sizeof(*ws))) == NULL)
      ArgusLog(LOG_ERR, "ArgusOutputProcessInit: ArgusCalloc error %s", strerror(errno));

   RaHeaderWindowStruct = ws;
   ws->window = RaHeaderWindow;
   ws->desc = strdup("RaHeaderWindow");
   ws->data = ArgusFetchWindowData;
#if defined(ARGUS_THREADS)
   pthread_mutex_init(&ws->lock, NULL);
#endif
   ArgusAddToQueue (ArgusWindowQueue, &ws->qhdr, ARGUS_LOCK);

   if ((ws = (struct ArgusWindowStruct *)ArgusCalloc(1, sizeof(*ws))) == NULL)
      ArgusLog(LOG_ERR, "ArgusOutputProcessInit: ArgusCalloc error %s", strerror(errno));

   RaStatusWindowStruct = ws;
   ws->window = RaStatusWindow;
   ws->desc = strdup("RaStatusWindow");
   ws->data = ArgusFetchWindowData;
#if defined(ARGUS_THREADS)
   pthread_mutex_init(&ws->lock, NULL);
#endif
   ArgusAddToQueue (ArgusWindowQueue, &ws->qhdr, ARGUS_LOCK);

   if ((ws = (struct ArgusWindowStruct *)ArgusCalloc(1, sizeof(*ws))) == NULL)
      ArgusLog(LOG_ERR, "ArgusOutputProcessInit: ArgusCalloc error %s", strerror(errno));

   RaDebugWindowStruct  = ws;
   ws->window = RaDebugWindow;
   ws->desc = strdup("RaDebugWindow");
   ws->data = ArgusFetchWindowData;
#if defined(ARGUS_THREADS)
   pthread_mutex_init(&ws->lock, NULL);
#endif
   ArgusAddToQueue (ArgusWindowQueue, &ws->qhdr, ARGUS_LOCK);

   if ((ws = (struct ArgusWindowStruct *)ArgusCalloc(1, sizeof(*ws))) == NULL)
      ArgusLog(LOG_ERR, "ArgusOutputProcessInit: ArgusCalloc error %s", strerror(errno));
 
   RaDataWindowStruct   = ws;
   ws->window = RaDisplayWindow;
   ws->desc = strdup("RaDisplayWindow");
   ws->data = ArgusFetchWindowData;
#if defined(ARGUS_THREADS)
   pthread_mutex_init(&ws->lock, NULL);
#endif
   ArgusAddToQueue (ArgusWindowQueue, &ws->qhdr, ARGUS_LOCK);

   if ((dom = (struct ArgusDomainStruct *) ArgusCalloc(1, sizeof(*dom))) == NULL)
      ArgusLog (LOG_ERR, "ArgusOutputProcess() ArgusCalloc error %s\n", strerror(errno));

   dom->ws = RaDataWindowStruct;
   ArgusAddToQueue (ArgusDomainQueue, &dom->qhdr, ARGUS_LOCK);

   RaCurrentWindow = RaDataWindowStruct;

   if (ArgusParser->RaCursesMode) {
      if ((RaColorArray = (struct ArgusAttributeStruct *)ArgusCalloc(MAXSTRLEN, sizeof(*RaColorArray))) == NULL)
         ArgusLog(LOG_ERR, "ArgusOutputProcessInit: ArgusCalloc error %s", strerror(errno));

#if defined(ARGUS_THREADS)
      if ((pthread_create(&RaCursesInputThread, NULL, ArgusProcessCursesInput, NULL)) != 0)
         ArgusLog (LOG_ERR, "ArgusOutputProcess() pthread_create error %s\n", strerror(errno));
#endif
   }
}


int
ArgusFetchWindowData(struct ArgusWindowStruct *ws)
{
   int retn = 1;
   return(retn);
}



void
ArgusOutputProcessClose()
{

#if defined(ARGUS_MYSQL)
   if (RaSQLUpdateDB && RaSQLCurrentTable) {
      char *sbuf = calloc(1, MAXBUFFERLEN);
      int i;

      RaClientSortQueue(ArgusSorter, RaOutputProcess->queue, ARGUS_NOLOCK);

      if (RaOutputProcess->queue->array != NULL) {
         for (i = 0; i < RaOutputProcess->queue->count; i++) {
            struct ArgusRecordStruct *ns = (struct ArgusRecordStruct *)RaOutputProcess->queue->array[i];

            if (ns && (ns->status & ARGUS_RECORD_MODIFIED)) {
               ArgusScheduleSQLQuery (ArgusParser, ArgusParser->ArgusAggregator, ns, sbuf, MAXBUFFERLEN, ARGUS_STATUS);
               ns->status &= ~ARGUS_RECORD_MODIFIED;
            }
         }
      }
      free(sbuf);
   }
#endif

#if defined(ARGUS_THREADS)
   if (ArgusParser->RaCursesMode)
      pthread_join(RaCursesInputThread, NULL);
#endif
}

int 
RaInitCurses ()
{
   char sbuf[1024];
#if defined(ARGUS_CURSES) && (defined(ARGUS_READLINE) || defined(ARGUS_EDITLINE))
#if defined(ARGUS_READLINE)
   int keytimeout;
#endif

   rl_initialize();
#if defined(ARGUS_HISTORY)
   using_history();
#endif
   rl_redisplay_function = argus_redisplay_function;
   rl_getc_function = argus_getch_function;

#if defined(HAVE_DECL_RL_EVENT_HOOK) && HAVE_DECL_RL_EVENT_HOOK
   rl_event_hook = argus_readline_timeout;
#endif

#if defined(ARGUS_READLINE)
   keytimeout = RaCursesUpdateInterval.tv_sec * 1000000 + RaCursesUpdateInterval.tv_usec;
   keytimeout = (keytimeout == 1000000) ? keytimeout - 1 : keytimeout;
#if defined(HAVE_DECL_RL_SET_KEYBOARD_INPUT_TIMEOUT) && HAVE_DECL_RL_SET_KEYBOARD_INPUT_TIMEOUT
   rl_set_keyboard_input_timeout (keytimeout);
#endif
#endif

   rl_outstream = NULL;

#if defined(HAVE_DECL_RL_CATCH_SIGNALS) && HAVE_DECL_RL_CATCH_SIGNALS
   rl_catch_signals = 0;
   rl_catch_sigwinch = 0;
#endif
#endif

   RaCursesInit++;

#if HAVE_SETENV
   if (setenv("ESCDELAY", "0", 1) < 0) {
      sprintf (sbuf, "setenv(ESCDELAY, 0, 1) error %s", strerror(errno));
      ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
   }
#else
   {
      char buf[16];
      sprintf (buf, "ESCDELAY=0");
      if (putenv(buf) < 0) {
         sprintf (sbuf, "putenv(%s) error %s", buf, strerror(errno));
         ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
      }
   }
#endif

   initscr();

#if defined(ARGUS_COLOR_SUPPORT)
   if (has_colors() == TRUE) {
      int colors;

      if (ArgusParser->ArgusColorSupport) {
         ArgusTerminalColors++;
         start_color();

         colors = COLORS;

         if (colors > 16) {
/* Accent Colors */
            init_pair( ARGUS_RED,     160, ArgusBackGround); // red on kinda black
            init_pair( ARGUS_GREEN,    64, ArgusBackGround); // light green on kinda black
            init_pair( ARGUS_YELLOW,  136, ArgusBackGround); // light green on kinda black
            init_pair( ARGUS_BLUE,     33, ArgusBackGround); // light blue on kinda black
            init_pair( ARGUS_MAGENTA, 125, ArgusBackGround); // light blue on kinda black
            init_pair( ARGUS_CYAN,     37, ArgusBackGround); // light cyan on kinda black
            init_pair( ARGUS_ORANGE,  166, ArgusBackGround); // orange on kinda black
            init_pair( ARGUS_VIOLET,   61, ArgusBackGround); // light green on kinda black

            if (ArgusBackGround == ARGUS_DARK) {
               init_pair(ARGUS_WHITE,  15, ArgusBackGround); // white on kinda black

/* Monotone Colors */
               init_pair( ARGUS_BASE3,   230, ArgusBackGround); // 
               init_pair( ARGUS_BASE2,   254, ArgusBackGround); // 
               init_pair( ARGUS_BASE1,   245, ArgusBackGround); // 
               init_pair( ARGUS_BASE0,   244, ArgusBackGround); // 
               init_pair( ARGUS_BASE00,  241, ArgusBackGround); // 
               init_pair( ARGUS_BASE01,  240, ArgusBackGround); // 
               init_pair( ARGUS_BASE02,  235, ArgusBackGround); // 
               init_pair( ARGUS_BASE03,  234, ArgusBackGround); // 

            } else {
               init_pair(ARGUS_WHITE, 235, ArgusBackGround); // white on kinda black

               init_pair( ARGUS_BASE3,   234, ArgusBackGround); // light gray on kinda black
               init_pair( ARGUS_BASE2,   235, ArgusBackGround); // light gray on kinda black
               init_pair( ARGUS_BASE1,   240, ArgusBackGround); // light gray on kinda black
               init_pair( ARGUS_BASE0,   241, ArgusBackGround); // light gray on kinda black
               init_pair( ARGUS_BASE00,  244, ArgusBackGround); // light gray on kinda black
               init_pair( ARGUS_BASE01,  245, ArgusBackGround); // light gray on kinda black
               init_pair( ARGUS_BASE02,  254, ArgusBackGround); // light gray on kinda black
               init_pair( ARGUS_BASE03,  230, ArgusBackGround); // light gray on kinda black
            }

         } else {
            if (colors > 8) {
               init_pair( ARGUS_RED,      88, ArgusBackGround); // red on kinda white
               init_pair( ARGUS_WHITE,    15, ArgusBackGround); // white on kinda white
               init_pair( ARGUS_BASE0,   248, ArgusBackGround); // gray on kinda white
               init_pair( ARGUS_ORANGE,  131, ArgusBackGround); // organe on kinda white
               init_pair( ARGUS_BLUE,     27, ArgusBackGround); // light blue on kinda white

            } else {
               init_pair( ARGUS_RED,       COLOR_RED, COLOR_BLACK); // red on kinda white
               init_pair( ARGUS_WHITE,   COLOR_WHITE, COLOR_BLACK); // white on kinda white
               init_pair( ARGUS_BASE0,   COLOR_WHITE, COLOR_BLACK); // gray on kinda white
               init_pair( ARGUS_ORANGE,    COLOR_RED, COLOR_BLACK); // organe on kinda white
               init_pair( ARGUS_BLUE,     COLOR_BLUE, COLOR_BLACK); // light blue on kinda white
               init_pair( ARGUS_GREEN,   COLOR_GREEN, COLOR_BLACK); // light blue on kinda white
               init_pair( ARGUS_CYAN,     COLOR_CYAN, COLOR_BLACK); // light blue on kinda white
            }
         }

         if (ArgusParser->ArgusColorConfig) {
            if ((ArgusParser->ArgusColorLabeler = ArgusNewLabeler(ArgusParser, 0L)) != NULL)
               if (RaReadFlowLabels (ArgusParser, ArgusParser->ArgusColorLabeler, ArgusParser->ArgusColorConfig) != 0)
                  ArgusLog (LOG_ERR, "ArgusNewLabeler: RaReadFlowLabels error");
         }
      }
   }

#endif

   getmaxyx(stdscr, RaScreenLines, RaScreenColumns);
 
   RaWindowLines   = RaScreenLines - (RaHeaderWinSize + RaStatusWinSize + RaDebugWinSize);
   RaDisplayLines  = RaWindowLines;

   RaHeaderWindow  = newwin (RaHeaderWinSize, RaScreenColumns, 0, 0);
   RaDebugWindow   = newwin (RaDebugWinSize,  RaScreenColumns, RaScreenLines - 2, 0);
   RaStatusWindow  = newwin (RaStatusWinSize, RaScreenColumns, RaScreenLines - 1, 0);
   RaDisplayWindow = newwin (RaDisplayLines, RaScreenColumns, RaHeaderWinSize, 0);

#if defined(ARGUS_COLOR_SUPPORT)
   if (ArgusTerminalColors) {
      wbkgd(RaHeaderWindow,  COLOR_PAIR(ARGUS_WHITE));
      wbkgd(RaDebugWindow,   COLOR_PAIR(ARGUS_WHITE));
      wbkgd(RaStatusWindow,  COLOR_PAIR(ARGUS_WHITE));
      wbkgd(RaDisplayWindow, COLOR_PAIR(ARGUS_BASE0));

      wattrset(RaHeaderWindow,  COLOR_PAIR(ARGUS_WHITE));
      wattrset(RaStatusWindow,  COLOR_PAIR(ARGUS_WHITE));
      wattrset(RaDebugWindow,   COLOR_PAIR(ARGUS_WHITE));
      wattrset(RaDisplayWindow, COLOR_PAIR(ARGUS_BASE0));

      wcolor_set(RaHeaderWindow,  ARGUS_WHITE, NULL);
      wcolor_set(RaDebugWindow,   ARGUS_WHITE, NULL);
      wcolor_set(RaStatusWindow,  ARGUS_WHITE, NULL);
      wcolor_set(RaDisplayWindow, ARGUS_BASE0, NULL);
      refresh();

      RaColorAlgorithms[0] = ArgusColorAvailability;
      RaColorAlgorithms[1] = ArgusColorFlowFields;
      RaColorAlgorithms[2] = ArgusColorAddresses;
      RaColorAlgorithms[3] = ArgusColorGeoLocation;
   }

#endif

   intrflush(RaDisplayWindow, FALSE);
   curs_set(1);

#if defined(ARGUS_READLINE)
#if defined(HAVE_DECL_RL_RESIZE_TERMINAL) && HAVE_DECL_RL_RESIZE_TERMINAL
   rl_resize_terminal();
#endif
#endif

   clearok(stdscr, TRUE);
   werase(stdscr);
   refresh();
   return (1);
}


#endif


void
ArgusTouchScreen(void)
{
   RaWindowModified  = RA_MODIFIED;
   RaWindowImmediate = TRUE;
}

void
ArgusUpdateScreen(void)
{
   struct ArgusQueueStruct *queue;

   RaWindowModified  = RA_MODIFIED;
   RaWindowImmediate = TRUE;

   if ((queue = RaOutputProcess->queue) != NULL) {
      int i;

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&queue->lock);
#endif
      if (ArgusParser->ns)
         ArgusParser->ns->status |= ARGUS_RECORD_MODIFIED;

      if (queue->array) {
         for (i = 0; i < queue->count; i++) {
            struct ArgusRecordStruct *ns;
            if ((ns = (struct ArgusRecordStruct *)queue->array[i]) == NULL)
               break;
            ns->status |= ARGUS_RECORD_MODIFIED;
         }
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock);
#endif
   }
}


void ArgusWindowClose(void);

void
ArgusWindowClose(void)
{
   if (!(ArgusWindowClosing++)) {
#if defined(ARGUS_CURSES)
      struct timeval tvbuf, *tvp = &tvbuf;
      fd_set in;
      int ch;

      if (RaCursesInit && (!(isendwin()))) {
         tvp->tv_sec = 0; tvp->tv_usec = 0;
         FD_ZERO(&in); FD_SET(0, &in);

         while (select(1, &in, 0, 0, tvp) > 0)
            if ((ch = wgetch(RaStatusWindow)) == ERR)
               break;

         endwin();
         printf("\n");
      }
#endif
   }

   ArgusParser->RaCursesMode = 0;
#if defined(ARGUSDEBUG)
   ArgusDebug (1, "ArgusWindowClose () returning\n");
#endif
}


int
RaProcessSplitOptions(struct ArgusParserStruct *parser, char *str, int len, struct ArgusRecordStruct *ns)
{
   char resultbuf[MAXSTRLEN], tmpbuf[MAXSTRLEN];
   char *ptr = NULL, *tptr = str;
   int retn = 0, i, x;

   bzero (resultbuf, len);

   while ((ptr = strchr (tptr, '$')) != NULL) {
      *ptr++ = '\0';
      sprintf (&resultbuf[strlen(resultbuf)], "%s", tptr);

      for (i = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (!strncmp (RaPrintAlgorithmTable[x].field, ptr, strlen(RaPrintAlgorithmTable[x].field))) {
            bzero (tmpbuf, MAXSTRLEN);
            RaPrintAlgorithmTable[x].print(parser, tmpbuf, ns, RaPrintAlgorithmTable[x].length);

            while (isspace((int)tmpbuf[strlen(tmpbuf) - 1]))
               tmpbuf[strlen(tmpbuf) - 1] = '\0';

            while (isspace((int)tmpbuf[i])) i++;
            sprintf (&resultbuf[strlen(resultbuf)], "%s", &tmpbuf[i]);

            ptr += strlen(RaPrintAlgorithmTable[x].field);
            while (*ptr && (*ptr != '$'))
               bcopy (ptr++, &resultbuf[strlen(resultbuf)], 1);
            break;
         }
      }

      tptr = ptr;
      retn++;
   }

   if (retn) {
      bzero (str, len);
      bcopy (resultbuf, str, strlen(resultbuf));
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaProcessSplitOptions(%s, %d, 0x%x): returns %d", str, len, ns, retn);
#endif

   return (retn);
}

#if defined(ARGUS_CURSES) && (defined(ARGUS_READLINE) || defined(ARGUS_EDITLINE))
int
argus_getch_function(FILE *file)
{
   int retn = wgetch(RaStatusWindow);
   if (retn  != ERR) {
      return retn;
   } else
      return -1;
}


int
argus_readline_timeout(void)
{
   int retn = 0;

   if (RaWindowModified == RA_MODIFIED) {
      switch (RaInputStatus) {
         case RAGETTINGh:
            break;
         default:
            argus_redisplay_function();
            break;
      }

      RaWindowModified  = 0;
      RaWindowImmediate = FALSE;
   }
   return (retn);
}


int ArgusReadlinePoint = 0;
void
argus_redisplay_function()
{
   int offset = 0, plen, sw = RaScreenColumns - 1;

   switch (RaInputStatus) {
      case RAGETTINGh: {
         RaWindowStatus = 1;

         RaInputStatus = RAGOTslash;
         RaInputString = RANEWCOMMANDSTR;
         RaCommandInputStr[0] = '\0';
         RaWindowModified = RA_MODIFIED;
#if defined(HAVE_DECL_RL_DONE) && HAVE_DECL_RL_DONE
         rl_done = 1;
#endif
         break;
      }

      case RAGETTINGcolon: 
         RaInputStatus = argus_process_command (ArgusParser, RaInputStatus);
         break;
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&RaCursesLock);
#endif

   sprintf (RaOutputBuffer, "%s", RaInputString);
   plen = strlen(RaOutputBuffer);

   if ((rl_point + 1) > (sw - plen)) {
      offset = (rl_point + 1) - (sw - plen);
      RaOutputBuffer[plen - 1] = '<';
      sprintf (&RaOutputBuffer[plen], "%s", &rl_line_buffer[offset]);
   } else {
      sprintf (&RaOutputBuffer[plen], "%s", rl_line_buffer);
   }

   if (strlen(RaOutputBuffer) > sw)
      RaOutputBuffer[sw] = '>';

#ifdef ARGUSDEBUG
   ArgusDebug (4, "argus_redisplay_function: sw %d plen %d rl_point %d offset %d", sw, plen, rl_point, offset);
#endif

   mvwaddnstr (RaStatusWindow, 0, 0, RaOutputBuffer, sw + 1);
   wclrtoeol(RaStatusWindow);

   if (offset > 0)
      wmove(RaStatusWindow, 0, plen + (rl_point - offset));
   else
      wmove(RaStatusWindow, 0, plen + rl_point);

   touchwin(RaStatusWindow);
   wrefresh(RaStatusWindow);

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&RaCursesLock);
#endif
}


void
argus_getsearch_string(int dir)
{
   char *line;

#if defined(ARGUS_HISTORY)
   if (!(argus_history_is_enabled()))
      argus_enable_history();
#endif

   ArgusSearchDirection = dir;

   RaInputStatus = RAGETTINGslash;
   RaInputString = (dir == ARGUS_FORWARD) ? "/" : "?";
   ArgusSearchDirection = dir;
   bzero(RaCommandInputStr, MAXSTRLEN);
   RaCommandIndex = 0;

   ArgusReadlinePoint = 0;

   if ((line = readline("")) != NULL) {
      int linenum = RaWindowCursorY;
      int cursx = RaWindowCursorX, cursy = RaWindowCursorY + RaWindowStartLine;

      if (strlen(line) > 0) {
         strcpy (RaCommandInputStr, line);
#if defined(ARGUS_HISTORY)
         if (*line && argus_history_is_enabled()) {
            add_history (line);
         }
#endif
         free(line);
         sprintf(RaLastSearch, "%s", RaCommandInputStr);
      } else {
         if (strlen(RaLastSearch) > 0) 
            sprintf(RaCommandInputStr, "%s", RaLastSearch);
         else {
            if (ArgusParser->ArgusSearchString != NULL) {
               free(ArgusParser->ArgusSearchString);
               ArgusParser->ArgusSearchString = NULL;
            }
         }
      }

      ArgusParser->ArgusSearchString = strdup(RaCommandInputStr);

      if ((linenum = RaSearchDisplay(ArgusParser, RaOutputProcess->queue, ArgusSearchDirection, &cursx, &cursy, ArgusParser->ArgusSearchString, ARGUS_LOCK)) < 0) {
         if (ArgusSearchDirection == ARGUS_FORWARD) {
            ArgusSetDebugString ("search hit BOTTOM, continuing at TOP", LOG_ERR, ARGUS_LOCK);
            cursx = 0; cursy = 0;
         } else {
            ArgusSetDebugString ("search hit TOP, continuing at BOTTOM", LOG_ERR, ARGUS_LOCK);
            cursx = RaScreenColumns; cursy = RaSortItems;
         }
         linenum = RaSearchDisplay(ArgusParser, RaOutputProcess->queue, ArgusSearchDirection, &cursx, &cursy, ArgusParser->ArgusSearchString, ARGUS_LOCK);
      }

      if (linenum >= 0) {
         if ((linenum < RaWindowStartLine) || ((linenum > RaWindowStartLine + RaDisplayLines))) {
            int startline = ((cursy - 1)/ RaDisplayLines) * RaDisplayLines;
            startline = (RaSortItems > startline) ? startline : RaSortItems - RaDisplayLines;
            startline = (startline > 0) ? startline : 0;
            RaWindowStartLine = startline;

            if ((RaWindowCursorY = cursy % RaDisplayLines) == 0)
               RaWindowCursorY = RaDisplayLines;

         } else
            RaWindowCursorY = cursy - RaWindowStartLine;

         RaWindowCursorX = cursx;

      } else {
         char sbuf[1024];
         sprintf (sbuf, "Pattern not found: %s", ArgusParser->ArgusSearchString);
         ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
         RaInputString = RANEWCOMMANDSTR;
         bzero(RaCommandInputStr, MAXSTRLEN);
         RaCommandIndex = 0;
      }

      RaInputStatus = RAGOTslash;
      RaInputString = (dir == ARGUS_FORWARD) ? "/" : "?";

   } else {
      if (ArgusParser->ArgusSearchString != NULL) {
         free(ArgusParser->ArgusSearchString);
         ArgusParser->ArgusSearchString = NULL;
      }
   }

   cbreak();
   RaCursesSetWindowFocus(ArgusParser, RaCurrentWindow->window);
   ArgusTouchScreen();
}


void
argus_command_string(void)
{
   char *line;

#if defined(ARGUS_HISTORY)
   argus_disable_history();
#endif

   RaInputStatus = RAGETTINGcolon;
   RaInputString = ":";
   bzero(RaCommandInputStr, MAXSTRLEN);
   RaCommandIndex = 0;

   ArgusReadlinePoint = 0;

   if ((line = readline("")) != NULL) {
      if (strlen(line) > 0) {
         strcpy (RaCommandInputStr, line);
         free(line);
         sprintf(RaLastCommand, "%s", RaCommandInputStr);
      } else {
         if (strlen(RaLastCommand) > 0) 
            sprintf(RaCommandInputStr, "%s", RaLastCommand);
      }
   }

   if (*RaCommandInputStr == 'q') {
      bzero (RaCommandInputStr, MAXSTRLEN);
      ArgusTouchScreen();
      RaParseComplete(SIGINT);
   }

   if (strlen(RaCommandInputStr)) {
      switch(RaInputStatus) {
         case RAGETTINGh: {
            RaWindowStatus = 1;
            RaInputStatus = RAGOTcolon;
            wclear(RaCurrentWindow->window);
            ArgusTouchScreen();
            RaRefreshDisplay();
            break;
         }

         case RAGETTINGN: {
            char *ptr = NULL;
            int value = strtol(RaCommandInputStr, (char **)&ptr, 10);

            RaDisplayLinesSet = 1;

            if (ptr != RaCommandInputStr) {
               int len = (RaScreenLines - (RaHeaderWinSize + 1));
               RaDisplayLines = (value < len) ?  value : len;
               ArgusTouchScreen();

            } else
               RaDisplayLinesSet = 0;

            break;
         }

         case RAGETTINGS: {
            if (!(ArgusAddHostList (ArgusParser, RaCommandInputStr, (ArgusParser->Cflag ? ARGUS_CISCO_DATA_SOURCE : ARGUS_DATA_SOURCE), 0))) {
               ArgusLog (LOG_ALERT, "%s%s host not found", RaInputString, RaCommandInputStr);
            } else {
               ArgusParser->Sflag = 1;
               ArgusParser->RaParseDone = 0;
            }
            break;
         }

         case RAGETTINGa: {
            if (!(strncasecmp(RaCommandInputStr, "Totals", 6))) {
               RaScreenResize = TRUE;
               if (ArgusPrintTotals == 0) {
                  ArgusPrintTotals = 1;
                  RaHeaderWinSize++;
                  RaScreenMove = TRUE;
               }
               ArgusTouchScreen();
            }
            if (!(strncasecmp(RaCommandInputStr, "-Totals", 6))) {
               RaScreenResize = TRUE;
               if (ArgusPrintTotals > 0) {
                  ArgusPrintTotals = 0;
                  RaHeaderWinSize--;
                  RaScreenMove = FALSE;
                  getbegyx(RaCurrentWindow->window, RaScreenStartY, RaScreenStartX);
                  if (mvwin(RaCurrentWindow->window, RaScreenStartY - 1, RaScreenStartX) == ERR)
                     ArgusLog (LOG_ERR, "RaResizeScreen: mvwin %d, %d returned ERR\n", RaScreenStartY - 1, RaScreenStartX);
               }
               ArgusTouchScreen();
            }
         }
         break;

         case RAGETTINGd: {
            struct ArgusInput *input;
            char strbuf[MAXSTRLEN];

            if ((input = (void *)ArgusParser->ArgusActiveHosts->start) != NULL) {
               do {
                  sprintf (strbuf, " %s:%d", input->hostname, input->portnum);
                  if ((strstr (RaCommandInputStr, strbuf))) {
                     ArgusRemoveFromQueue (ArgusParser->ArgusActiveHosts, &input->qhdr, ARGUS_LOCK);
                     ArgusCloseInput(ArgusParser, input);
                     break;
                  }
                  input = (void *)input->qhdr.nxt;
               } while (input != (void *)ArgusParser->ArgusActiveHosts->start);
            }
         }
         break;

         case RAGETTINGD: {
            char *ptr = NULL;
            int value = strtol(RaCommandInputStr, (char **)&ptr, 10);

            if (ptr != RaCommandInputStr)
               ArgusParser->debugflag = value;
            break;
         }

         case RAGETTINGc: {
            break;
         }

         case RAGETTINGe: {
            char *ptr = NULL;

            ptr = RaCommandInputStr;
            while (isspace((int)*ptr)) ptr++;

            ArgusParser->ArgusGrepSource = 1;
            ArgusParser->ArgusGrepDestination = 1;

            if (ArgusParser->estr != NULL)
               free(ArgusParser->estr);
            ArgusParser->estr = strdup(RaCommandInputStr);

            if ((ArgusParser->estr[0] == 's') && (ArgusParser->estr[1] == ':')) {
                  ArgusParser->ArgusGrepDestination = 0;
                  ArgusParser->estr = &ArgusParser->estr[2];
            }
            if ((ArgusParser->estr[0] == 'd') && (ArgusParser->estr[1] == ':')) {
                  ArgusParser->ArgusGrepSource = 0;
                  ArgusParser->estr = &ArgusParser->estr[2];
            }

            break;
         }

         case RAGETTINGf: {
            struct nff_program lfilter;
            char *ptr = NULL, *str = NULL;
            int ind = ARGUS_REMOTE_FILTER;
            int i, retn;

            bzero ((char *) &lfilter, sizeof (lfilter));
            ptr = RaCommandInputStr;
            while (isspace((int)*ptr)) ptr++;

            if ((str = strstr (ptr, "local")) != NULL) {
               ptr = strdup(&str[strlen("local ")]);
               ind = ARGUS_LOCAL_FILTER;
            } else 
            if ((str = strstr (ptr, "display")) != NULL) {
               ptr = strdup(&str[strlen("display ")]);
               ind = ARGUS_DISPLAY_FILTER;
            } else 
            if ((str = strstr (ptr, "remote")) != NULL) {
               ptr = strdup(&str[strlen("remote ")]);
               ind = ARGUS_REMOTE_FILTER;
            } else 
            if ((str = strstr (ptr, "none")) != NULL) {
               ind = RaFilterIndex;
            }

            if ((retn = ArgusFilterCompile (&lfilter, ptr, 1)) < 0) {
               char sbuf[1024];
               sprintf (sbuf, "%s%s syntax error", RAGETTINGfSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);

           } else {
               char sbuf[1024];
               sprintf (sbuf, "%s%s filter accepted", RAGETTINGfSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);
               if ((str = ptr) != NULL)
                  while (isspace((int)*str)) str++;
               
               switch (ind) {
                  case ARGUS_LOCAL_FILTER:
                     if (ArgusParser->ArgusFilterCode.bf_insns != NULL)
                        free (ArgusParser->ArgusFilterCode.bf_insns);

                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusFilterCode, sizeof(lfilter));
                     if (ArgusParser->ArgusLocalFilter !=  NULL) {
                        free(ArgusParser->ArgusLocalFilter);
                        ArgusParser->ArgusLocalFilter = NULL;
                     }
                     if (strlen(str) > 0)
                        ArgusParser->ArgusLocalFilter = ptr;
                     else
                        if (ptr != NULL) free(ptr);
                     break;

                  case ARGUS_DISPLAY_FILTER:
                     if (ArgusParser->ArgusDisplayCode.bf_insns != NULL)
                        free (ArgusParser->ArgusDisplayCode.bf_insns);

                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusDisplayCode, sizeof(lfilter));
                     bcopy((char *)&lfilter, (char *)&ArgusSorter->filter, sizeof(lfilter));

                     if (ArgusParser->ArgusDisplayFilter !=  NULL) {
                        free(ArgusParser->ArgusDisplayFilter);
                        ArgusParser->ArgusDisplayFilter = NULL;
                     }
                     if (strlen(str) > 0)
                        ArgusParser->ArgusDisplayFilter = ptr;
                     else
                        if (ptr != NULL) free(ptr);
                     break;

                  case ARGUS_REMOTE_FILTER:
                     if (ArgusParser->ArgusFilterCode.bf_insns != NULL)
                        free (ArgusParser->ArgusFilterCode.bf_insns);
                     bcopy((char *)&lfilter, (char *)&ArgusParser->ArgusFilterCode, sizeof(lfilter));
                     if (ArgusParser->ArgusRemoteFilter !=  NULL) {
                        free(ArgusParser->ArgusRemoteFilter);
                        ArgusParser->ArgusRemoteFilter = NULL;
                     }
                     if (strlen(str) > 0)
                        ArgusParser->ArgusRemoteFilter = ptr;
                     else
                        if (ptr != NULL) free(ptr);
                     break;
               }

#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&RaOutputProcess->queue->lock);
#endif
               RaClientSortQueue(ArgusSorter, RaOutputProcess->queue, ARGUS_NOLOCK);

               if (RaSortItems) {
                  if (ArgusParser->ns) {
                     ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
                     ArgusParser->ns = NULL;
                  }
                  for (i = 0; i < RaSortItems; i++) {
                     struct ArgusRecordStruct *ns;
                     if ((ns = (struct ArgusRecordStruct *)RaOutputProcess->queue->array[i]) == NULL)
                        break;
                     if (ArgusParser->ns)
                        ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
                     else
                        ArgusParser->ns = ArgusCopyRecordStruct (ns);
                  }
               }
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&RaOutputProcess->queue->lock);
#endif
               RaWindowStatus = 1;
               ArgusTouchScreen();
               RaRefreshDisplay();
            }
            break;
         }
                      
         case RAGETTINGm: {
            struct ArgusRecordStruct *ns = NULL;
            char strbuf[MAXSTRLEN], *tok = NULL, *ptr;
            struct ArgusModeStruct *mode = NULL, *modelist = NULL, *list; 
            struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;
            int i;                                  

            if ((agg->modeStr == NULL) || strcmp(agg->modeStr, RaCommandInputStr)) {
               if (agg->modeStr != NULL)
                  free(agg->modeStr);
               agg->modeStr = strdup(RaCommandInputStr);
               ArgusParser->RaMonMode = 0;
               strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

               if ((mode = ArgusParser->ArgusMaskList) != NULL)
                  ArgusDeleteMaskList(ArgusParser);

               agg->mask = 0;
               agg->saddrlen = 0;
               agg->daddrlen = 0;

               if ((ptr = strbuf) != NULL) {
                  while ((tok = strtok (ptr, " \t")) != NULL) {
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
               } else {
                  if ((modelist = ArgusParser->ArgusMaskList) == NULL)
                     agg->mask  = ( ARGUS_MASK_SRCID_INDEX | ARGUS_MASK_PROTO_INDEX |
                                    ARGUS_MASK_SADDR_INDEX | ARGUS_MASK_SPORT_INDEX |
                                    ARGUS_MASK_DADDR_INDEX | ARGUS_MASK_DPORT_INDEX );
               }

               ArgusInitAggregatorStructs(agg);

               if ((mode = modelist) != NULL) {
                  while (mode) {
                     char *ptr = NULL, **endptr = NULL;
                     int value = 0;

                     if ((ptr = strchr(mode->mode, '/')) != NULL) {
                        ptr++;
                        if ((value = strtol(ptr, endptr, 10)) == 0)
                           if (*endptr == ptr)
                              usage();
                     }
                     if (!(strncasecmp (mode->mode, "none", 4))) {
                        agg->mask  = 0;
                     } else
                     if (!(strncasecmp (mode->mode, "mac", 3))) {
                        ArgusParser->RaMonMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SMAC);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "addr", 4))) {
                        ArgusParser->RaMonMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SADDR);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else
                     if (!(strncasecmp (mode->mode, "matrix", 6))) {
                        agg->ArgusMatrixMode++;
                        agg->mask |= (0x01LL << ARGUS_MASK_SADDR);
                        agg->mask |= (0x01LL << ARGUS_MASK_DADDR);
                        if (value > 0) {
                           agg->saddrlen = value;
                           agg->daddrlen = value;
                        }
                     } else {
                        struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs;

                        for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                           if (!(strncasecmp (mode->mode, ArgusMaskDefs[i].name, ArgusMaskDefs[i].slen))) {
                              agg->mask |= (0x01LL << i);
                              switch (i) {
                                 case ARGUS_MASK_SADDR:
                                    if (value > 0) {
                                       agg->saddrlen = value;
                                       if (value <= 32)
                                          agg->smask.addr_un.ipv4 = (0xFFFFFFFF << (32 - value));
                                    }
                                    break;
                                 case ARGUS_MASK_DADDR:
                                    if (value > 0) {
                                       agg->daddrlen = value;
                                       if (value <= 32)
                                          agg->dmask.addr_un.ipv4 = (0xFFFFFFFF << (32 - value));
                                    }
                                    break;

                                 case ARGUS_MASK_SMPLS:
                                 case ARGUS_MASK_DMPLS: {
                                    int x, RaNewIndex = 0;
                                    char *ptr;

                                    if ((ptr = strchr(mode->mode, '[')) != NULL) {
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
                              }
                              break;
                           }
                        }
                     }
                     mode = mode->nxt;
                  }
               }

               ArgusParser->ArgusMaskList = modelist;

#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&RaOutputProcess->queue->lock);
#endif
               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaOutputProcess->queue, ARGUS_NOLOCK)) != NULL) {
                  if (ArgusSearchHitRecord == ns) {
                     ArgusResetSearch();
                  }
                  ArgusDeleteRecordStruct (ArgusParser, ns);
               }

               ArgusEmptyHashTable(RaOutputProcess->htable);
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->RaClientUpdate.tv_sec = 0;
               ArgusParser->ns = NULL;
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&RaOutputProcess->queue->lock);
#endif
               werase(RaCurrentWindow->window);
               ArgusTouchScreen();
            }

            break;
         }

         case RAGETTINGM: {
            char strbuf[MAXSTRLEN], *str = strbuf, *tok = NULL, sbuf[1024];
            struct ArgusModeStruct *mode = NULL;
            char *tzptr;
            int retn = 0;

            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if ((tzptr = strstr(strbuf, "TZ=")) != NULL) {
               if (ArgusParser->RaTimeZone)
                  free (ArgusParser->RaTimeZone);
               ArgusParser->RaTimeZone = strdup(tzptr);
               tzptr = getenv("TZ");
#if defined(HAVE_SETENV) && HAVE_SETENV
               if ((retn = setenv("TZ", (ArgusParser->RaTimeZone + 3), 1)) < 0) {
                  sprintf (sbuf, "setenv(TZ, %s, 1) error %s", ArgusParser->RaTimeZone + 3, strerror(errno));
                  ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
               }
#else
               if ((retn = putenv(ArgusParser->RaTimeZone)) < 0) {
                  sprintf (sbuf, "setenv(TZ, %s, 1) error %s", ArgusParser->RaTimeZone + 3, strerror(errno));
                  ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
               }
#endif
               if (retn == 0) {
                  tzset();
                  sprintf (sbuf, "Timezone changed from %s to %s", tzptr, getenv("TZ"));
                  ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);
               }

               ArgusTouchScreen();
               break;
            }

            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               ArgusDeleteModeList(ArgusParser);
               ArgusParser->RaCumulativeMerge = 1;
            }

            if (strlen(strbuf) > 0) {
               while ((tok = strtok(str, " \t\n")) != NULL) {
                  if (!(strncasecmp (tok, "none", 4)))
                     ArgusDeleteModeList(ArgusParser);
                  else if (!(strncasecmp (tok, "default", 7))) {
                     ArgusDeleteModeList(ArgusParser);
                  } else
                     ArgusAddModeList (ArgusParser, tok);
                  str = NULL;
               }
            }

            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               struct RaBinProcessStruct *RaBinProcess = ArgusParser->RaBinProcess;
               struct ArgusAdjustStruct *nadp = NULL;
               int i, ind;

               while (mode) {
                  for (i = 0, ind = -1; i < ARGUSSPLITMODENUM; i++) {
                     if (!(strncasecmp (mode->mode, RaSplitModes[i], strlen(RaSplitModes[i])))) {
                        ind = i;
                        break;
                     }
                  }

                  if (ind >= 0) {
                     char *mptr = NULL;
                     int size = -1;
                     nadp = &RaBinProcess->nadp;

                     nadp = &RaBinProcess->nadp;

                     switch (ind) {
                        case ARGUSSPLITRATE:  {   /* "%d:%d[yMwdhms]" */
                           struct ArgusModeStruct *tmode = NULL; 
                           nadp->mode = ind;
                           if ((tmode = mode->nxt) != NULL) {
                              mptr = tmode->mode;
                              if (isdigit((int)*tmode->mode)) {
                                 char *ptr = NULL;
                                 nadp->len = strtol(tmode->mode, (char **)&ptr, 10);
                                 if (*ptr++ != ':') 
                                    usage();
                                 tmode->mode = ptr;
                              }
                           }
                        }

                        case ARGUSSPLITTIME: /* "%d[yMwdhms] */
                           nadp->mode = ind;
                           if ((mode = mode->nxt) != NULL) {
                              if (isdigit((int)*mode->mode)) {
                                 char *ptr = NULL;
                                 nadp->value = strtol(mode->mode, (char **)&ptr, 10);
                                 if (ptr == mode->mode)
                                    usage();
                                 else {
                                    switch (*ptr) {
                                       case 'y':
                                          nadp->qual = ARGUSSPLITYEAR;  
                                          size = nadp->value * 31556926;
                                          break;
                                       case 'M':
                                          nadp->qual = ARGUSSPLITMONTH; 
                                          size = nadp->value * 2629744;
                                          break;
                                       case 'w':
                                          nadp->qual = ARGUSSPLITWEEK;  
                                          size = nadp->value * 604800;
                                          break;
                                       case 'd':
                                          nadp->qual = ARGUSSPLITDAY;   
                                          size = nadp->value * 86400;
                                          break;
                                       case 'h':
                                          nadp->qual = ARGUSSPLITHOUR;  
                                          size = nadp->value * 3600;
                                          break;
                                       case 'm':
                                          nadp->qual = ARGUSSPLITMINUTE;
                                          size = nadp->value * 60;
                                          break;
                                        default:
                                          nadp->qual = ARGUSSPLITSECOND;
                                          size = nadp->value;
                                          break;
                                    }
                                 }
                              }
                              if (mptr != NULL)
                                  mode->mode = mptr;
                           }

                           nadp->modify = 1;

                           if (ind == ARGUSSPLITRATE) {
                              /* need to set the flow idle timeout value to be equal to or
                                 just a bit bigger than (nadp->len * size) */

                              ArgusParser->timeout.tv_sec  = (nadp->len * size);
                              ArgusParser->timeout.tv_usec = 0;
                           }

                           ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;
                           ArgusSorter->ArgusSortAlgorithms[1] = NULL;
                           break;

                        case ARGUSSPLITSIZE:
                        case ARGUSSPLITCOUNT:
                           nadp->mode = ind;
                           nadp->count = 1;

                           if ((mode = mode->nxt) != NULL) {
                              if (isdigit((int)*mode->mode)) {
                                 char *ptr = NULL;
                                 nadp->value = strtol(mode->mode, (char **)&ptr, 10);
                                 if (ptr == mode->mode)
                                    usage();
                                 else {
                                    switch (*ptr) {
                                       case 'B':   
                                       case 'b':  nadp->value *= 1000000000; break;
                                        
                                       case 'M':   
                                       case 'm':  nadp->value *= 1000000; break;
                                        
                                       case 'K':   
                                       case 'k':  nadp->value *= 1000; break;
                                    }
                                 }
                              }
                           }
                           ArgusSorter->ArgusSortAlgorithms[0] = NULL;
                           break;

                        case ARGUSSPLITNOMODIFY:
                           nadp->modify = 0;
                           break;

                        case ARGUSSPLITHARD:
                           nadp->hard++;
                           break;

                        case ARGUSSPLITZERO:
                           nadp->zero++;
                           break;
                     }

                  } else {
                     if (!(strncasecmp (mode->mode, "nomerge", 7))) {
                        ArgusParser->RaCumulativeMerge = 0;
                     } else
                     if (!(strncasecmp (mode->mode, "merge", 5))) {
                        ArgusParser->RaCumulativeMerge = 1;
                     }
                  }

                  mode = mode->nxt;
               }
            }

            break;
         }

         case RAGETTINGn: {
            char sbuf[1024], *name = NULL;;

            if (strstr(RaCommandInputStr, "all")) ArgusParser->nflag = 0; else
            if (strstr(RaCommandInputStr, "port")) ArgusParser->nflag = 1; else
            if (strstr(RaCommandInputStr, "proto")) ArgusParser->nflag = 2; else
            if (strstr(RaCommandInputStr, "none")) ArgusParser->nflag = 3;

             switch (ArgusParser->nflag) {
                case 0: name = "all"; break;
                case 1: name = "port"; break;
                case 2: name = "proto"; break;
                case 3: name = "none"; break;
                default: name = "port"; ArgusParser->nflag = 2; break;
             }

            sprintf (sbuf, "%s changed to %s ", RAGETTINGnSTR, name);
            ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);
            ArgusProcessNewPage(RaCurrentWindow->window, 0, 0);
            break;
         }

         case RAGETTINGp: {
            char *endptr = NULL, sbuf[1024];
            int value = 0;

            value = strtod(RaCommandInputStr, &endptr);

            if (RaCommandInputStr != endptr) {
               ArgusParser->pflag = value;
               sprintf (sbuf, "%s %s precision accepted", RAGETTINGpSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);
            } else {
               sprintf (sbuf, "%s %s syntax error", RAGETTINGuSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
            }

            ArgusUpdateScreen();
            break;
         }

         case RAGETTINGR: {
            char strbuf[MAXSTRLEN], *str = strbuf, *ptr = NULL;
            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if (strlen(strbuf) > 0) {
               ArgusDeleteFileList(ArgusParser);
               while ((ptr = strtok(str, " ")) != NULL) {
                  RaProcessRecursiveFiles (ptr);
                  str = NULL;
               }
            }
            break;
         }

         case RAGETTINGr: {
            char strbuf[MAXSTRLEN], *str = strbuf, *ptr = NULL, sbuf[1024];
            glob_t globbuf;

            bzero (strbuf, MAXSTRLEN);
            strncpy(strbuf, RaCommandInputStr, MAXSTRLEN);

            if (strlen(strbuf) > 0) {
               struct ArgusRecordStruct *ns = NULL;

               ArgusDeleteFileList(ArgusParser);
               while ((ptr = strtok(str, " ")) != NULL) {
                  glob (ptr, 0, NULL, &globbuf);
                  if (globbuf.gl_pathc > 0) {
                     int i;
                     for (i = 0; i < globbuf.gl_pathc; i++)
                        ArgusAddFileList (ArgusParser, globbuf.gl_pathv[i], ARGUS_DATA_SOURCE, -1, -1);
                  } else {
                     sprintf (sbuf, "%s no files found for %s", RAGETTINGrSTR, ptr);
                     ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
                  }
                  str = NULL;
               }
               ArgusParser->RaTasksToDo = 1;
               ArgusParser->Sflag = 0;

#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&RaOutputProcess->queue->lock);
#endif
               while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaOutputProcess->queue, ARGUS_NOLOCK)) != NULL)  {
                  if (ArgusSearchHitRecord == ns) {
                     ArgusResetSearch();
                  }
                  ArgusDeleteRecordStruct (ArgusParser, ns);
               }

               ArgusEmptyHashTable(RaOutputProcess->htable);
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->RaClientUpdate.tv_sec = 0;
               ArgusParser->status &= ~ARGUS_FILE_LIST_PROCESSED;
               ArgusParser->ns = NULL;
               ArgusParser->ArgusLastTime.tv_sec  = 0;
               ArgusParser->ArgusLastTime.tv_usec = 0;
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&RaOutputProcess->queue->lock);
#endif
            }
            break;
         }

         case RAGETTINGs: {
            char strbuf[MAXSTRLEN], *ptr = strbuf, *tok;
            int (*srtalg[ARGUS_MAX_SORT_ALG])(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
            int i, x, ind = 0;
            strncpy (strbuf, RaCommandInputStr, MAXSTRLEN);
            bzero(srtalg, sizeof(srtalg));
            while ((tok = strtok(ptr, " ")) != NULL) {
               for (x = 0; x < ARGUS_MAX_SORT_ALG; x++) {
                  if (!strncmp (ArgusSortKeyWords[x], tok, strlen(ArgusSortKeyWords[x]))) {
                     srtalg[ind++] = ArgusSortAlgorithmTable[x];
                     break;
                  }
               }
               if (x == ARGUS_MAX_SORT_ALG) {
                  bzero(srtalg, sizeof(srtalg));
                  ArgusLog (LOG_ALERT, "sort keyword %s not valid", tok);
                  break;
               }
               ptr = NULL;
            }

            if (srtalg[0] != NULL) {
               for (x = 0; x < ARGUS_MAX_SORT_ALG; x++)
                  ArgusSorter->ArgusSortAlgorithms[x] = srtalg[x];
            }

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&RaOutputProcess->queue->lock);
#endif
            RaClientSortQueue(ArgusSorter, RaOutputProcess->queue, ARGUS_NOLOCK);
            if (ArgusParser->ns) {
               ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
               ArgusParser->ns = NULL;
            }
            for (i = 0; i < RaOutputProcess->queue->count; i++) {
               struct ArgusRecordStruct *ns;
               if ((ns = (struct ArgusRecordStruct *)RaOutputProcess->queue->array[i]) == NULL)
                  break;
               if (ArgusParser->ns)
                  ArgusMergeRecords (ArgusParser->ArgusAggregator, ArgusParser->ns, ns);
               else
                  ArgusParser->ns = ArgusCopyRecordStruct (ns);
            }
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&RaOutputProcess->queue->lock);
#endif
            ArgusTouchScreen();
            break;
         }

         case RAGETTINGT: {
            double sec, usec, value;
            char *ptr = NULL;

            value = strtod(RaCommandInputStr, (char **)&ptr);
            if (ptr != RaCommandInputStr) {
               usec = modf(value, &sec);
               ArgusParser->timeout.tv_sec  = sec;
               ArgusParser->timeout.tv_usec = usec;
            }
            break;
         }

         case RAGETTINGt: {
            if (ArgusParser->timearg) {
               free (ArgusParser->timearg);
               ArgusParser->timearg = NULL;
            }

            if (strlen(RaCommandInputStr))
               ArgusParser->timearg = strdup(RaCommandInputStr);

            ArgusCheckTimeFormat (&ArgusParser->RaTmStruct, ArgusParser->timearg);
            break;
         }

         case RAGETTINGu: {
            double value = 0.0, ivalue, fvalue;
            char *endptr = NULL, sbuf[1024];
       
            value = strtod(RaCommandInputStr, &endptr);
       
            if (RaCommandInputStr != endptr) {
               fvalue = modf(value, &ivalue);
       
               RaCursesUpdateInterval.tv_sec  = (int) ivalue;
               RaCursesUpdateInterval.tv_usec = (int) (fvalue * 1000000.0);
       
               sprintf (sbuf, "%s %s interval accepted", RAGETTINGuSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);
               RaCursesUpdateTime = ArgusParser->ArgusRealTime;
       
            } else {
               sprintf (sbuf, "%s %s syntax error", RAGETTINGuSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
            }

            break;
         }


         case RAGETTINGU: {
            char *endptr = NULL, sbuf[1024];
            double value = 0.0;
       
            value = strtod(RaCommandInputStr, &endptr);
       
            if (RaCommandInputStr != endptr) {
               RaUpdateRate = value;
               sprintf (sbuf, "%s %s accepted", RAGETTINGUSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, 0, ARGUS_LOCK);
       
            } else {
               sprintf (sbuf, "%s %s syntax error", RAGETTINGUSTR, RaCommandInputStr);
               ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
            }

            break;
         }

         
         case RAGETTINGw: {
            struct ArgusListStruct *wlist = ArgusParser->ArgusWfileList;
            struct ArgusWfileStruct *wfile = NULL;
            struct ArgusRecord *argusrec = NULL;
            struct ArgusRecordStruct *ns;
            static char sbuf[0x10000];
            int i;

            if (strlen(RaCommandInputStr)) {
               if (RaSortItems > 0) {
                  ArgusParser->ArgusWfileList = NULL;
                  setArgusWfile (ArgusParser, RaCommandInputStr, NULL);
                  wfile = (struct ArgusWfileStruct *) ArgusParser->ArgusWfileList->start;

#if defined(ARGUS_THREADS)
                  pthread_mutex_lock(&RaOutputProcess->queue->lock);
#endif
                  for (i = 0; i < RaSortItems; i++) {
                     int pass = 1;

                     if ((ns = (struct ArgusRecordStruct *) RaOutputProcess->queue->array[i]) == NULL)
                        break;

                     if (wfile->filterstr) {
                        struct nff_insn *wfcode = wfile->filter.bf_insns;
                        pass = ArgusFilterRecord (wfcode, ns);
                     }

                     if (pass != 0) {
                        if ((argusrec = ArgusGenerateRecord (ns, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                           ArgusHtoN(argusrec);
#endif
                           ArgusWriteNewLogfile (ArgusParser, ns->input, wfile, argusrec);

                        }
                     }
                  }
#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&RaOutputProcess->queue->lock);
#endif
                  fflush(wfile->fd);
                  fclose(wfile->fd);
                  clearArgusWfile(ArgusParser);
                  ArgusParser->ArgusWfileList = wlist;
               }
            }

            break;   
         }

         case RAGETTINGF: {
            struct ArgusQueueStruct *queue = RaOutputProcess->queue;
            char strbuf[MAXSTRLEN], *ptr = strbuf, *tok;
            int x;

            strncpy (strbuf, RaCommandInputStr, MAXSTRLEN);
            bzero ((char *)ArgusParser->RaPrintOptionStrings, sizeof(ArgusParser->RaPrintOptionStrings));
            ArgusParser->RaPrintOptionIndex = 0;
            while ((tok = strtok(ptr, " ")) != NULL) {
               if (ArgusParser->RaPrintOptionIndex <  ARGUS_MAX_S_OPTIONS)
                  ArgusParser->RaPrintOptionStrings[ArgusParser->RaPrintOptionIndex++] = tok;
               ptr = NULL;
            }

            if (ArgusParser->RaPrintOptionIndex > 0) {
               ArgusProcessSOptions(ArgusParser);
               for (x = 0; x < ArgusParser->RaPrintOptionIndex; x++) 
                  if (ArgusParser->RaPrintOptionStrings[x] != NULL) 
                     ArgusParser->RaPrintOptionStrings[x] = NULL;
               ArgusParser->RaPrintOptionIndex = 0;
            }

            for (x = 0, ArgusAlwaysUpdate = 0; x < MAX_PRINT_ALG_TYPES; x++)
               if (ArgusParser->RaPrintAlgorithmList[x] != NULL)
                  if (ArgusParser->RaPrintAlgorithmList[x]->print == ArgusPrintIdleTime)
                     ArgusAlwaysUpdate++;

            if (queue == RaOutputProcess->queue) {
               int i;
               if (ArgusParser->ns) {
                  ArgusParser->ns->status |= ARGUS_RECORD_MODIFIED;
               }
               for (i = 0; i < queue->count; i++) {
                  struct ArgusRecordStruct *ns;
                  if ((ns = (struct ArgusRecordStruct *)queue->array[i]) == NULL)
                     break;
                  ns->status |= ARGUS_RECORD_MODIFIED;
               }
            }
            ArgusInitializeColorMap(ArgusParser, RaDisplayWindow);
            ArgusTouchScreen();
            break;
         }

         case RAGETTINGcolon: {
            char *endptr = NULL;
            int linenum, startline;

            linenum = (int)strtol(RaCommandInputStr, &endptr, 10);
            if (RaCommandInputStr == endptr) {
               switch (*RaCommandInputStr) {
                  case 'q': {
                     bzero (RaCommandInputStr, MAXSTRLEN);
                     ArgusTouchScreen();
                     RaParseComplete(SIGINT);
                     break;
                  }
               }
            } else {
               if ((linenum >= RaWindowStartLine) && (linenum <= (RaWindowStartLine + RaDisplayLines)))
                  RaWindowCursorY = linenum - RaWindowStartLine;
               else {
                  startline = ((linenum - 1)/ RaDisplayLines) * RaDisplayLines;
                  startline = (RaSortItems > startline) ? startline : RaSortItems - RaDisplayLines;
                  startline = (startline > 0) ? startline : 0;
                  RaWindowStartLine = startline;
                  if ((RaWindowCursorY = linenum % RaDisplayLines) == 0)
                     RaWindowCursorY = RaDisplayLines;
               }
               RaCursorOffset = 0;
               RaWindowCursorX = 0;
               ArgusTouchScreen();
            }
            break;
         }
      }
   }

   RaInputStatus = RAGOTcolon;
   RaInputString = RANEWCOMMANDSTR;
   bzero(RaCommandInputStr, MAXSTRLEN);
   RaCommandIndex = 0;

   cbreak();
   RaCursesSetWindowFocus(ArgusParser, RaCurrentWindow->window);

#if defined(ARGUS_HISTORY)
   argus_enable_history();
#endif
}


int
argus_process_command (struct ArgusParserStruct *parser, int status)
{
   char promptbuf[256], *prompt = promptbuf;
   int retn = status;

   if (strlen(rl_line_buffer) == 1) {
      switch (*rl_line_buffer) {
          case 'a': {
             retn = RAGETTINGa;
             RaInputString = RAGETTINGaSTR;
             break;
          }

          case 'c': {
             break;
          }

          case 'd': {
             struct ArgusInput *input;
             retn = RAGETTINGd;

             RaInputString = RAGETTINGdSTR;

            if ((input = (void *)ArgusParser->ArgusActiveHosts->start) != NULL) {
               do {
                  sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s:%d ", input->hostname, input->portnum);
                  input = (void *)input->qhdr.nxt;
               } while (input != (void *)ArgusParser->ArgusActiveHosts->start);
            }
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }
                   
          case 'D': {
             retn = RAGETTINGD;
             RaInputString = RAGETTINGDSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d", ArgusParser->debugflag);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }

          case 'e': {
             retn = RAGETTINGe;
             RaInputString = RAGETTINGeSTR;
             if (ArgusParser->estr)
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", ArgusParser->estr);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }

          case 'f': 
             retn = RAGETTINGf;
             RaInputString = RAGETTINGfSTR;
             RaFilterIndex = 3;
             if (ArgusParser->ArgusRemoteFilter) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "remote %s ", ArgusParser->ArgusRemoteFilter);
                RaCommandIndex = strlen(RaCommandInputStr); 
                RaFilterIndex = ARGUS_REMOTE_FILTER;
             } else
             if (ArgusParser->ArgusLocalFilter) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "local %s ", ArgusParser->ArgusLocalFilter);
                RaCommandIndex = strlen(RaCommandInputStr); 
                RaFilterIndex = ARGUS_LOCAL_FILTER;
             } else
             if (ArgusParser->ArgusDisplayFilter) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "display %s ", ArgusParser->ArgusDisplayFilter);
                RaCommandIndex = strlen(RaCommandInputStr); 
                RaFilterIndex = ARGUS_DISPLAY_FILTER;
             }
             break;

         case 'm': {
            struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;
            struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
            int i;

            retn = RAGETTINGm;
            RaInputString = RAGETTINGmSTR;
            if (agg->modeStr != NULL) {
               sprintf (RaCommandInputStr, "%s", agg->modeStr);
            } else {
               for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                  if (agg->mask & (0x01LL << i)) {
                     sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", ArgusMaskDefs[i].name);

                     switch (i) {
                        case ARGUS_MASK_SADDR:
                           if (agg->saddrlen > 0)
                              sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "/%d", agg->saddrlen);
                           break;
                        case ARGUS_MASK_DADDR:
                           if (agg->daddrlen > 0)
                              sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "/%d", agg->daddrlen);
                           break;
                     }

                     sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], " ");
                  }
               }

               agg->modeStr = strdup(RaCommandInputStr);
            }
            RaCommandIndex = strlen(RaCommandInputStr);
            break;
         }

         case 'M': {
            struct ArgusModeStruct *mode;
            retn = RAGETTINGM;
            RaInputString = RAGETTINGMSTR;
    
            if ((mode = ArgusParser->ArgusModeList) != NULL) {
               while (mode) {
                  sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", mode->mode);
                  mode = mode->nxt;
               }
            }
            RaCommandIndex = strlen(RaCommandInputStr);
            break;
         }

          case 'N':
             retn = RAGETTINGN;
             RaInputString = RAGETTINGNSTR;
             break;

          case 'n': {
             char *name = NULL;
             retn = RAGETTINGn;
             RaInputString = RAGETTINGnSTR;
             switch (ArgusParser->nflag) {
                case 0: name = "all"; break;
                case 1: name = "port"; break;
                case 2: name = "proto"; break;
                case 3: name = "none"; break;
                default: name = "port"; ArgusParser->nflag = 1; break;
             }
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", name);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }

          case 'p': {
             retn = RAGETTINGp;
             RaInputString = RAGETTINGpSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d", ArgusParser->pflag);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }

          case 'P': {
             ArgusParser->Pauseflag = (ArgusParser->Pauseflag > 0.0) ? 0.0 : 1.0;
             if (ArgusParser->Pauseflag)
                  ArgusSetDebugString ("Paused", LOG_ERR, ARGUS_LOCK);
#if defined(HAVE_DECL_RL_DONE) && HAVE_DECL_RL_DONE
             rl_done = 1;
#endif
             break;
          }

          case 't':
             retn = RAGETTINGt;
             RaInputString = RAGETTINGtSTR;
             if (ArgusParser->timearg) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s", ArgusParser->timearg);
                RaCommandIndex = strlen(RaCommandInputStr); 
             } else {
             }
             break;

          case 'T':
             retn = RAGETTINGT;
             RaInputString = RAGETTINGTSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d.%06d", 
                       (int)ArgusParser->timeout.tv_sec, (int)ArgusParser->timeout.tv_usec);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;

          case 'R': {
             struct ArgusInput *input = ArgusParser->ArgusInputFileList;
             retn = RAGETTINGR;
             RaInputString = RAGETTINGRSTR;
             while (input) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", input->filename);
                RaCommandIndex = strlen(RaCommandInputStr); 
                input = (void *) input->qhdr.nxt;
             }
             break;
          }

          case 'r': {
             struct ArgusInput *input = ArgusParser->ArgusInputFileList;
             retn = RAGETTINGr;
             RaInputString = RAGETTINGrSTR;
             while (input) {
                sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", input->filename);
                RaCommandIndex = strlen(RaCommandInputStr); 
                input = (void *) input->qhdr.nxt;
             }
             break;
          }

          case 'S': {
             struct ArgusInput *input;
             retn = RAGETTINGS;
             RaInputString = RAGETTINGSSTR;

            if ((input = (void *)ArgusParser->ArgusActiveHosts->start) != NULL) {
               do {
                  sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s:%d ", input->hostname, input->portnum);
                  input = (void *)input->qhdr.nxt;
               } while (input != (void *)ArgusParser->ArgusActiveHosts->start);

               RaCommandIndex = strlen(RaCommandInputStr); 
            }
            break;
         }

          case 's': {
             int x, y;
             retn = RAGETTINGs;
             RaInputString = RAGETTINGsSTR;
             for (x = 0; x < ARGUS_MAX_SORT_ALG; x++) {
                if (ArgusSorter->ArgusSortAlgorithms[x]) {
                   for (y = 0; y < ARGUS_MAX_SORT_ALG; y++) {
                      if (ArgusSorter->ArgusSortAlgorithms[x] == ArgusSortAlgorithmTable[y]) {
                         sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s ", 
                               ArgusSortKeyWords[y]);
                         break;
                      }
                   }
                }
             }
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;
          }

          case 'u':
             retn = RAGETTINGu;
             RaInputString = RAGETTINGuSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%d.", (int) RaCursesUpdateInterval.tv_sec);
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%06d",(int) RaCursesUpdateInterval.tv_usec);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;

          case 'U':
             retn = RAGETTINGU;
             RaInputString = RAGETTINGUSTR;
             sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%2.2f", RaUpdateRate);
             RaCommandIndex = strlen(RaCommandInputStr); 
             break;

          case 'w':
             retn = RAGETTINGw;
             RaInputString = RAGETTINGwSTR;
             break;

          case 'F': {
             int x, y;

             RaInputString = RAGETTINGFSTR;
             retn = RAGETTINGF;

             for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                if (parser->RaPrintAlgorithmList[x] != NULL) {
                   for (y = 0; y < MAX_PRINT_ALG_TYPES; y++) {
                      if ((void *) parser->RaPrintAlgorithmList[x]->print == (void *) RaPrintAlgorithmTable[y].print) {
                         sprintf (&RaCommandInputStr[strlen(RaCommandInputStr)], "%s:%d ",
                            RaPrintAlgorithmTable[y].field, RaPrintAlgorithmTable[y].length);
                         break;
                      }
                   }
                } else
                   break;
             }
             RaCommandIndex = strlen(RaCommandInputStr);
             break;
          }

          case 'Q':
             retn = RAGETTINGq;
             RaInputString = RAGETTINGqSTR;
             break;

          case 'h':
             retn = RAGETTINGh;
             RaInputString = RAGETTINGhSTR;
             RaWindowStatus = 0;
             RaOutputHelpScreen();
             break;

          case 'v': 
             if (ArgusParser->vflag) {
                ArgusParser->vflag = 0;
                ArgusReverseSortDir = 0;
             } else {
                ArgusParser->vflag = 1;
                ArgusReverseSortDir++;
             }

             RaClientSortQueue(ArgusSorter, RaOutputProcess->queue, ARGUS_LOCK);

#if defined(HAVE_DECL_RL_DONE) && HAVE_DECL_RL_DONE
             rl_done = 1;
#endif
             break;

          case '=':  {
             struct ArgusRecordStruct *ns = NULL;

             werase(RaCurrentWindow->window);
             ArgusTouchScreen();

#if defined(ARGUS_THREADS)
             pthread_mutex_lock(&RaOutputProcess->queue->lock);
#endif
             while ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(RaOutputProcess->queue, ARGUS_NOLOCK)) != NULL) {
                if (ArgusSearchHitRecord == ns) {
                   ArgusResetSearch();
                }
                ArgusDeleteRecordStruct (ArgusParser, ns);
             }

             ArgusEmptyHashTable(RaOutputProcess->htable);
             ArgusDeleteRecordStruct (ArgusParser, ArgusParser->ns);
             ArgusParser->RaClientUpdate.tv_sec = 0;
             ArgusParser->ArgusTotalRecords = 0;
             RaCursesStartTime.tv_sec = 0;
             RaCursesStartTime.tv_usec = 0;
             RaCursesStopTime.tv_sec = 0;
             RaCursesStopTime.tv_usec = 0;
             ArgusParser->ns = NULL;
#if defined(ARGUS_THREADS)
             pthread_mutex_unlock(&RaOutputProcess->queue->lock);
#endif
#if defined(HAVE_DECL_RL_DONE) && HAVE_DECL_RL_DONE
             rl_done = 1;
#endif
             break;
          }

          case 'z':  
             if (++ArgusParser->zflag > 1) {
                ArgusParser->zflag = 0;
             }
#if defined(HAVE_DECL_RL_DONE) && HAVE_DECL_RL_DONE
             rl_done = 1;
#endif
             break;

          case 'Z':  
             switch (ArgusParser->Zflag) {
                case '\0': ArgusParser->Zflag = 'b'; break;
                case  'b': ArgusParser->Zflag = 's'; break;
                case  's': ArgusParser->Zflag = 'd'; break;
                case  'd': ArgusParser->Zflag = '\0'; break;
             }
#if defined(HAVE_DECL_RL_DONE) && HAVE_DECL_RL_DONE
             rl_done = 1;
#endif
             break;

          default:
             break;
      }

      if (retn != status) {
         sprintf (prompt, ":%s ", RaInputString);

         rl_set_prompt(prompt);

#if defined(HAVE_DECL_RL_SAVE_PROMPT) && HAVE_DECL_RL_SAVE_PROMPT
         rl_save_prompt();
#endif

#if defined(ARGUS_READLINE)
#if defined(HAVE_DECL_RL_REPLACE_LINE) && HAVE_DECL_RL_REPLACE_LINE
         rl_replace_line(RaCommandInputStr, 1);
#else
#if defined(HAVE_DECL_RL_DELETE_TEXT) && HAVE_DECL_RL_DELETE_TEXT
         rl_delete_text(0, rl_point);
#endif
         sprintf(rl_line_buffer, "%s", RaCommandInputStr);
#endif
         rl_point = strlen(rl_line_buffer);
         rl_end = rl_point;
#else
#endif
      }
   }

   return (retn);
}


#endif

#if defined(ARGUS_HISTORY)

char ratop_historybuf[MAXSTRLEN];
char *ratop_history = NULL;

int argus_history_enabled = 1;

void
argus_recall_history(void)
{
   if (ratop_history != NULL)
      read_history(ratop_history);
}

void
argus_save_history(void)
{
   if (ratop_history == NULL) {
      char *home;

      if ((home = getenv("HOME")) != NULL) {
         sprintf (ratop_historybuf, "%s/.ratop_history", home);
         ratop_history = ratop_historybuf;
      }
   }

   if (ratop_history != NULL)
      write_history(ratop_history);
}

void
argus_enable_history(void)
{
   argus_recall_history();
   argus_history_enabled = 1;
}


void
argus_disable_history(void)
{
   argus_save_history();
   clear_history();
   argus_history_enabled = 0;
}

int
argus_history_is_enabled(void)
{
   return (argus_history_enabled);
}

#endif  // ARGUS_HISTORY


void
RaRefreshDisplay (void)
{
#if defined(ARGUS_CURSES)
   struct timeval tvpbuf, *tvp = &tvpbuf;
#endif

   gettimeofday (tvp, NULL);

   if (RaCursesUpdateTime.tv_sec == 0)
      RaCursesUpdateTime = *tvp;

   if (RaWindowImmediate || ((RaCursesUpdateTime.tv_sec   < tvp->tv_sec) ||
                            ((RaCursesUpdateTime.tv_sec  == tvp->tv_sec) &&
                             (RaCursesUpdateTime.tv_usec <= tvp->tv_usec)))) {
      int cnt, i;

      RaWindowImmediate = FALSE;
      RaCursesUpdateTime = *tvp;

      RaCursesUpdateTime.tv_sec  += RaCursesUpdateInterval.tv_sec;
      RaCursesUpdateTime.tv_usec += RaCursesUpdateInterval.tv_usec;

      if (RaCursesUpdateTime.tv_usec >= 1000000) {
         RaCursesUpdateTime.tv_sec  += 1;
         RaCursesUpdateTime.tv_usec -= 1000000;
      }

      if ((cnt = ArgusWindowQueue->count) > 0) {
         for (i = 0; i < cnt; i++) {
            struct ArgusWindowStruct *ws = (struct ArgusWindowStruct *)ArgusPopQueue(ArgusWindowQueue, ARGUS_LOCK);
            wrefresh(ws->window);
            ArgusAddToQueue (ArgusWindowQueue, &ws->qhdr, ARGUS_LOCK);
         }
      }
   }
}

void
RaUpdateHeaderWindow(WINDOW *win)
{   
#if defined(ARGUS_CURSES)
   struct tm *tm, tmbuf;
   char stimebuf[128];
#endif

   struct timeval tvpbuf, *tvp = &tvpbuf;

   gettimeofday (tvp, NULL);

   if (tvp->tv_sec > 0) {
      time_t tsec =  tvp->tv_sec;
      tm = localtime_r(&tsec, &tmbuf);
      strftime ((char *) stimebuf, 32, "%Y/%m/%d.%T", tm);
      sprintf ((char *)&stimebuf[strlen(stimebuf)], " ");
      strftime(&stimebuf[strlen(stimebuf)], 32, "%Z ", tm);

   } else
      sprintf (stimebuf, " ");

   mvwaddnstr (win, 0, 0, ArgusGenerateProgramArgs(ArgusParser), RaScreenColumns - 5);
   wclrtoeol(win);
   mvwaddnstr (win, 0, RaScreenColumns - strlen(stimebuf) , stimebuf, strlen(stimebuf));
   touchwin(win);
}

void
RaUpdateDebugWindow(WINDOW *win)
{
   char strbuf[MAXSTRLEN];
   int len = 0;
#if defined(ARGUS_COLOR_SUPPORT)
   int attrs = 0;
#endif

   if (ArgusDisplayStatus && (ArgusParser->debugflag == 0)) {
      char tbuf[MAXSTRLEN];
      struct timeval dtime;
      float secs, rate;
  
      dtime.tv_sec   = RaCursesStopTime.tv_sec  - RaCursesStartTime.tv_sec;
      dtime.tv_usec  = RaCursesStopTime.tv_usec - RaCursesStartTime.tv_usec;
  
      if (dtime.tv_usec < 0) {
         dtime.tv_sec--;
         dtime.tv_usec += 1000000;
      }
  
      secs = (dtime.tv_sec * 1.0) + ((dtime.tv_usec * 1.0)/1000000.0);
      rate = (ArgusParser->ArgusTotalRecords * 1.0);

      sprintf (tbuf, "ProcessQueue %6d DisplayQueue %6d TotalRecords %8lld  Rate %11.4f rps SQL inq %d selq %d upq %d tin %d tsel %d tup %d",
                          RaOutputProcess->queue->count, RaSortItems,
                          ArgusParser->ArgusTotalRecords, rate/secs,
                          ArgusSQLInsertQueryList->count, ArgusSQLSelectQueryList->count, ArgusSQLUpdateQueryList->count,
                          ArgusTotalInsertSQLStatements, ArgusTotalSelectSQLStatements, ArgusTotalUpdateSQLStatements);

      ArgusSetDebugString (tbuf, 0, ARGUS_LOCK);
   }

#if defined(ARGUS_COLOR_SUPPORT)
   if (ArgusTerminalColors) {
      if (ArgusParser->RaDebugStatus == LOG_ERR)
         attrs = COLOR_PAIR(ARGUS_RED);
      else
         attrs = COLOR_PAIR(ARGUS_BASE2);

      wattron(win, attrs);
   }
#endif
   ArgusCopyDebugString (strbuf, MAXSTRLEN);
   len = strlen(strbuf);
   len = (len >= RaScreenColumns) ? RaScreenColumns - 1 : len;
   strbuf[len] = '\0';
   mvwprintw (win, 0, 0, "%s", strbuf);
   wclrtoeol(win);

#if defined(ARGUS_COLOR_SUPPORT)
   if (ArgusTerminalColors) {
      wattroff(RaCurrentWindow->window, attrs);
   }
#endif
}

void
RaUpdateStatusWindow(WINDOW *win)
{
   if (strlen(RaInputString) == 0) {
      mvwaddnstr (win, 0, 0, " ", 1);
      wclrtoeol(win);
   }
}

int
RaHighlightDisplay (struct ArgusParserStruct *parser, struct ArgusQueueStruct *queue, char *pattern)
{
   int retn = -1, x = 0, cursy = 0, refresh = 0, options, rege;
   struct ArgusRecordStruct *ns = NULL;
   regex_t pregbuf, *preg = &pregbuf;
   regmatch_t pmbuf[32], *pm = &pmbuf[0];
   char sbuf[1024];

#if defined(ARGUS_PCRE)
   options = 0;
#else
   options = REG_EXTENDED | REG_NEWLINE;
#if defined(REG_ENHANCED)
   options |= REG_ENHANCED;
#endif
#endif

   bzero (preg, sizeof(*preg));

   if ((rege = regcomp(preg, pattern, options)) != 0) {
      char errbuf[MAXSTRLEN];
      if (regerror(rege, preg, errbuf, MAXSTRLEN))
         sprintf (sbuf, "RaHighlightDisplay %s", errbuf);
      ArgusSetDebugString (sbuf, LOG_ERR, ARGUS_LOCK);
      return retn;
   }

   if (queue->array != NULL) {
      char *sptr;
      int cnt  = queue->count;
      int dlen = RaWindowStartLine + RaDisplayLines;

      cnt = (dlen > cnt) ? cnt : dlen;

      for (x = RaWindowStartLine; x < cnt; x++) {
         cursy++;
         if ((ns = (struct ArgusRecordStruct *) queue->array[x]) != NULL) {
            if ((sptr = ns->disp.str) !=  NULL) {
               int cursx = 0;

               bzero(pm, sizeof(*pm));
               while ((retn = regexec(preg, sptr, 1, pm, 0)) == 0) {
                  int span = pm->rm_eo - pm->rm_so;
                  cursx += pm->rm_so;
#if defined(ARGUS_COLOR_SUPPORT)
                  if (ArgusTerminalColors) {
                     mvwchgat(RaCurrentWindow->window, cursy, cursx, span, 0, ARGUS_GREEN, NULL);
                  }
#endif
                  sptr += pm->rm_eo;
                  cursx += span;
                  refresh = 1;
               }
            }
         }
      }
   }
   if (refresh)
      touchwin(RaCurrentWindow->window);

   regfree(preg);
   return (retn);
}

int
RaSearchDisplay (struct ArgusParserStruct *parser, struct ArgusQueueStruct *queue, 
                                 int dir, int *cursx, int *cursy, char *pattern, int type)
{
   int retn = -1, x = 0, startline = *cursy, options, rege;
   struct ArgusRecordStruct *ns = NULL;
   regex_t pregbuf, *preg = &pregbuf;
   char buf[MAXSTRLEN], *ptr;

#if defined(ARGUS_PCRE)
   options = 0;
#else
   options = REG_EXTENDED | REG_NEWLINE;
#if defined(REG_ENHANCED)
   options |= REG_ENHANCED;
#endif
#endif

   bzero (preg, sizeof(*preg));

   if ((rege = regcomp(preg, pattern, options)) != 0) {
      char errbuf[MAXSTRLEN];
      if (regerror(rege, preg, errbuf, MAXSTRLEN))
         sprintf (buf, "RaSearchDisplay %s", errbuf);
      ArgusSetDebugString (buf, LOG_ERR, ARGUS_LOCK);
      return retn;
   }

#if defined(ARGUS_THREADS)
   if (type == ARGUS_LOCK)
      pthread_mutex_lock(&queue->lock);
#endif

   if (queue->array != NULL) {
      if (startline == 0) {
         *cursy = 1; startline = 1;
      }
  
      if (queue->count >= startline) {
         if ((ns = (struct ArgusRecordStruct *) queue->array[startline - 1]) != NULL) {
            int offset = *cursx, found = 0;

            if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != startline)) {
               char buf[MAXSTRLEN];

               if (ns->disp.str != NULL)
                  free(ns->disp.str);

               buf[0] = '\0';
               ns->rank = startline;
               ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
               ns->disp.str = strdup(buf);
               ns->status &= ~ARGUS_RECORD_MODIFIED;
            }

            bcopy(ns->disp.str, buf, strlen(ns->disp.str) + 1);

            switch (dir) {
               case ARGUS_FORWARD: {
                  regmatch_t pmbuf[32], *pm = &pmbuf[0];
                  int rege, nmatch = 1;
                  char *p = &buf[offset];

                  if ((rege = regexec(preg, p, nmatch, pm, 0)) == 0) {
                     if (pm->rm_so == 0) {
                        if (regexec(preg, p + 1, nmatch, pm, 0) == 0) {
                           offset += pm->rm_so + 1;
                           found++;
                        }
                     } else {
                        offset += pm->rm_so;
                        found++;
                     }
                     if (found) {
                        retn = *cursy;
                        *cursx = offset;
#if defined(ARGUS_THREADS)
                        if (type == ARGUS_LOCK)
                           pthread_mutex_unlock(&queue->lock);
#endif
                        ArgusSearchHitRecord = ns;
                        ArgusSearchHitRank = ns->rank;
                        return (retn);
                     }
                  }
                  break;
               }

               case ARGUS_BACKWARD: {
                  char *lastmatch = NULL;
                  buf[offset] = '\0';
                  ptr = buf;
                  while ((ptr = strstr(ptr, pattern)) != NULL)
                     lastmatch = ptr++;

                  if (lastmatch) {
                     retn = *cursy;
                     *cursx = (lastmatch - buf);
#if defined(ARGUS_THREADS)
                     if (type == ARGUS_LOCK)
                        pthread_mutex_unlock(&queue->lock);
#endif
                     ArgusSearchHitRecord = ns;
                     ArgusSearchHitRank = ns->rank;
                     return (retn);
                  }
                  break;
               }
            }
         }

         switch (dir) {
            case ARGUS_FORWARD:
               for (x = startline; x < queue->count; x++) {
                  if ((ns = (struct ArgusRecordStruct *) queue->array[x]) != NULL) {
                     regmatch_t pmbuf[32], *pm = &pmbuf[0];

                     if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != (x + 1))) {
                        char buf[MAXSTRLEN];

                        if (ns->disp.str != NULL)
                           free(ns->disp.str);

                        buf[0] = '\0';
                        ns->rank = (x + 1);
                        ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                        ns->disp.str = strdup(buf);
                        ns->status &= ~ARGUS_RECORD_MODIFIED;
                     }

                     bcopy(ns->disp.str, buf, strlen(ns->disp.str) + 1);
      
                     if ((retn = regexec(preg, buf, 1, pm, 0)) == 0) {
                        retn = x + 1;
                        *cursx = pm->rm_so;
                        *cursy = retn;
#if defined(ARGUS_THREADS)
                        if (type == ARGUS_LOCK)
                           pthread_mutex_unlock(&queue->lock);
#endif
                        ArgusSearchHitRecord = ns;
                        ArgusSearchHitRank = ns->rank;
                        return (retn);
                        break;
                     }
                  }
               }
               break;

            case ARGUS_BACKWARD: {
               for (x = (startline - 2); x >= 0; x--) {
                  if ((ns = (struct ArgusRecordStruct *) queue->array[x]) != NULL) {
                     char *lastmatch = NULL;

                     if (((ns->disp.str == NULL) || (ns->status & ARGUS_RECORD_MODIFIED)) || (ns->rank != (x + 1))) {
                        char buf[MAXSTRLEN];

                        if (ns->disp.str != NULL)
                           free(ns->disp.str);

                        buf[0] = '\0';
                        ns->rank = x + 1;
                        ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
                        ns->disp.str = strdup(buf);
                        ns->status &= ~ARGUS_RECORD_MODIFIED;
                     }

                     bcopy(ns->disp.str, buf, strlen(ns->disp.str) + 1);

                     ptr = buf;
                     while ((ptr = strstr(ptr, pattern)) != NULL)
                        lastmatch = ptr++;

                     if (lastmatch) {
                        retn = x + 1;
                        *cursx = (lastmatch - buf);
                        *cursy = retn;
#if defined(ARGUS_THREADS)
                        if (type == ARGUS_LOCK)
                           pthread_mutex_unlock(&queue->lock);
#endif
                        ArgusSearchHitRecord = ns;
                        ArgusSearchHitRank = ns->rank;
                        return (retn);
                     }
                  }
               }
               break;
            }
         }
      }
   }
#if defined(ARGUS_THREADS)
   if (type == ARGUS_LOCK)
      pthread_mutex_unlock(&queue->lock);
#endif

   ArgusSearchHitRecord = NULL;
   ArgusSearchHitRank = 0;
   regfree(preg);
   return (-1);
}

void
ArgusResetSearch (void)
{
   ArgusSearchHitRecord = NULL;
   ArgusSearchHitRank   = 0;
   RaWindowCursorY      = 1;
   RaWindowCursorX      = 0;
   RaWindowStartLine = 0;
}


void
RaResizeScreen(void)
{
   if (ArgusParser->RaCursesMode) {
      struct winsize size;
      int i, count;

      if (ioctl(fileno(stdout), TIOCGWINSZ, &size) == 0) {
#if defined(__FreeBSD__) || (__NetBSD__) || (__OpenBSD__)
         resizeterm(size.ws_row, size.ws_col);
#else
#if defined(ARGUS_SOLARIS)
#else
         resize_term(size.ws_row, size.ws_col);
#endif
#endif
      }

      getmaxyx(stdscr, RaScreenLines, RaScreenColumns);
#if defined(ARGUS_READLINE)
      rl_set_screen_size(RaScreenLines - 1, RaScreenColumns);
#endif

      RaWindowLines  = RaScreenLines - (RaHeaderWinSize + RaStatusWinSize + RaDebugWinSize);
      RaDisplayLines = RaWindowLines;

#if !defined(ARGUS_SOLARIS)
      wresize(RaHeaderWindow, RaHeaderWinSize, RaScreenColumns);
      wresize(RaDebugWindow,  RaDebugWinSize,  RaScreenColumns);
      wresize(RaStatusWindow, RaStatusWinSize, RaScreenColumns);

      if (mvwin(RaDebugWindow, RaScreenLines - 2, RaScreenStartX) == ERR)
         ArgusLog (LOG_ERR, "RaResizeScreen: mvwin %d, %d returned ERR\n", RaScreenStartY + 5, RaScreenStartX);

      if (mvwin(RaStatusWindow, RaScreenLines - 1, RaScreenStartX) == ERR)
         ArgusLog (LOG_ERR, "RaResizeScreen: mvwin %d, %d returned ERR\n", RaScreenStartY + 5, RaScreenStartX);

      if ((count = ArgusDomainQueue->count) > 0) {
         for (i = 0; i < count; i++) {
            struct ArgusDomainStruct *dom = (struct ArgusDomainStruct *)ArgusPopQueue(ArgusDomainQueue, ARGUS_LOCK);
            ArgusAddToQueue (ArgusDomainQueue, &dom->qhdr, ARGUS_LOCK);
            wresize(dom->ws->window, RaDisplayLines, RaScreenColumns);
         }
      }

#ifdef ARGUSDEBUG
      ArgusDebug (1, "RaResizeScreen() y %d x %d\n", RaScreenLines, RaScreenColumns);
#endif

#else
      delwin(RaHeaderWindow);
      RaHeaderWindow = newwin (RaHeaderWinSize, RaScreenColumns, 0, 0);
      idlok (RaHeaderWindow, TRUE);
      notimeout(RaHeaderWindow, TRUE);

      if ((count = ArgusDomainQueue->count) > 0) {
         for (i = 0; i < count; i++) {
            struct ArgusDomainStruct *dom = (struct ArgusDomainStruct *)ArgusPopQueue(ArgusDomainQueue, ARGUS_LOCK);
            ArgusAddToQueue (ArgusDomainQueue, &dom->qhdr, ARGUS_LOCK);
            delwin(dom->ws->window);
            dom->ws->window = newwin (RaWindowLines, RaScreenColumns, RaHeaderWinSize, 0);
            idlok (dom->ws->window, TRUE);
            notimeout(dom->ws->window, TRUE);
         }
      }

#endif    // ARGUS_SOLARIS 

      ArgusTouchScreen();
      RaRefreshDisplay();
      RaScreenResize = FALSE;
   }
}


void
RaOutputModifyScreen ()
{
   int i = 0;
   werase(RaCurrentWindow->window);
   for (i = RaMinCommandLines; i < (RaMaxCommandLines + 1); i++) {
      mvwprintw (RaCurrentWindow->window, i, 1, RaCommandArray[i - RaMinCommandLines]);
      if (i == RaMinCommandLines)
         wstandout(RaCurrentWindow->window);
      wprintw (RaCurrentWindow->window, "%s", RaCommandValueArray[i - RaMinCommandLines]());
      if (i == RaMinCommandLines)
         wstandend(RaCurrentWindow->window);
   }
}

void
RaOutputHelpScreen ()
{
   extern char version[];
   wclear(RaCurrentWindow->window);

   mvwprintw (RaCurrentWindow->window, 0, 1, "RaCurses Version %s\n", version);
   mvwprintw (RaCurrentWindow->window, 1, 1, "Key Commands: c,d,D,f,F,h,m,n,N,p,P,q,r,R,s,S,t,T,u,U,v,w,z,Z,=");
   mvwprintw (RaCurrentWindow->window, 3, 1, "  ^D - Clear command line. Reset input (also ESC).");
   mvwprintw (RaCurrentWindow->window, 4, 1, "   c - Connect to remote Argus Source");
   mvwprintw (RaCurrentWindow->window, 5, 1, "   d - Drop connection from remote argus source");
   mvwprintw (RaCurrentWindow->window, 6, 1, "   D - Set debug printing level");
   mvwprintw (RaCurrentWindow->window, 7, 1, "   f - Specify filter expression");
   mvwprintw (RaCurrentWindow->window, 8, 1, "   F - Specify fields to print (use arrow keys to navigate).");
   mvwprintw (RaCurrentWindow->window, 9, 1, "         +[#]field - add field to optional column # or end of line");
   mvwprintw (RaCurrentWindow->window,10, 1, "         -field    - remove field from display");
   mvwprintw (RaCurrentWindow->window,11, 1, "          field    - reset fields and add to display");
   mvwprintw (RaCurrentWindow->window,12, 1, "             available fields are:");
   mvwprintw (RaCurrentWindow->window,13, 1, "               srcid, stime, ltime, dur, avgdur, trans, flgs, dir, state, seq, bins, binnum");
   mvwprintw (RaCurrentWindow->window,14, 1, "               mac, smac, dmac, mpls, smpls, dmpls, vlan, svlan, dvlan, svid, dvid, svpri, dvpri");
   mvwprintw (RaCurrentWindow->window,15, 1, "               saddr, daddr, snet, dnet, proto, sport, dport, stos, dtos, sttl, dttl, sipid, dipid");
   mvwprintw (RaCurrentWindow->window,16, 1, "               tcpext, tcprtt, stcpb, dtcpb, swin, dwin, srng, drng, spksz, dpksz, smaxsz, sminsz, dmaxsz, dminsz");
   mvwprintw (RaCurrentWindow->window,17, 1, "               suser, duser, svc, pkts, spkts, dpkts, load,sload, dload, bytes, sbytes, dbytes, rate, srate, drate");
   mvwprintw (RaCurrentWindow->window,18, 1, "               sloss, dloss, sintpkt, dintpkt, sjit, djit, sintpktact, dintpktact, sintpktidl, dintpktidl");
   mvwprintw (RaCurrentWindow->window,19, 1, "               sjitidl, djitidl, ddur, dstime, dltime, dspkts, ddpkts, dsbytes, ddbytes");
   mvwprintw (RaCurrentWindow->window,20, 1, "               djitact, jitidl, sjitidl, djitidl, state, ddur, dstime, dltime, dspkts, ddpkts");
   mvwprintw (RaCurrentWindow->window,21, 1, "   H - Toggle number abbreviations.");
   mvwprintw (RaCurrentWindow->window,21, 1, "   m - Specify the flow model objects.");
   mvwprintw (RaCurrentWindow->window,22, 1, "   n - Toggle name to number conversion(cycle through).");
   mvwprintw (RaCurrentWindow->window,23, 1, "   N - Specify the number of items to print.");
   mvwprintw (RaCurrentWindow->window,24, 1, "   %% - Show percent values.");
   mvwprintw (RaCurrentWindow->window,25, 1, "   p - Specify precision.");
   mvwprintw (RaCurrentWindow->window,26, 1, "   P - Pause the program");
   mvwprintw (RaCurrentWindow->window,27, 1, "   q - Quit the program.");
   mvwprintw (RaCurrentWindow->window,28, 1, "   r - Read argus data file(s)");
   mvwprintw (RaCurrentWindow->window,29, 1, "   R - Recursively open argus data files(s)");
   mvwprintw (RaCurrentWindow->window,30, 1, "   s - Specify sort fields.");
   mvwprintw (RaCurrentWindow->window,31, 1, "   t - Specify time range. same as -t command line option. ");
   mvwprintw (RaCurrentWindow->window,32, 1, "   T - Specify idle timeout (float) value [60.0s].");
   mvwprintw (RaCurrentWindow->window,33, 1, "   u - Specify the window update timer, in seconds [0.1s]");
   mvwprintw (RaCurrentWindow->window,34, 1, "   U - Specify the playback rate, in seconds per second [1.0]");
   mvwprintw (RaCurrentWindow->window,35, 1, "   v - reverse the sort order");
   mvwprintw (RaCurrentWindow->window,36, 1, "   w - Write display to file");
   mvwprintw (RaCurrentWindow->window,37, 1, "   z - Toggle State field output formats");
   mvwprintw (RaCurrentWindow->window,38, 1, "   Z - Toggle TCP State field output");
   mvwprintw (RaCurrentWindow->window,39, 1, "   = - Clear Flow List");
   mvwprintw (RaCurrentWindow->window,40, 1, "   h - Print help screen.");
   mvwprintw (RaCurrentWindow->window,42, 1, "Navigation Keys (vi): g,G,h,j,k,l,i,w,$,^,^F,^D,^B,^U");

   wrefresh(RaCurrentWindow->window);
}


char *
ArgusGenerateProgramArgs(struct ArgusParserStruct *parser)
{
   char *retn = RaProgramArgs;
   struct ArgusModeStruct *mode = NULL;
   struct ArgusInput *input = NULL;
   
   sprintf (retn, "%s ", parser->ArgusProgramName);

   if (parser->ArgusActiveHosts) {
      if (parser->Sflag) {
         sprintf (&retn[strlen(retn)], "-S ");
         if ((input = (void *)parser->ArgusActiveHosts->start) != NULL) {
            do {
                  sprintf (&retn[strlen(retn)], "%s:%d ", input->hostname, input->portnum);
               input = (void *)input->qhdr.nxt;
            } while (input != (void *)parser->ArgusActiveHosts->start);
         }
      } else {
         sprintf (&retn[strlen(retn)], "-r ");
         if ((input = (void *)parser->ArgusInputFileList) != NULL) {
            while (input != NULL) {
               sprintf (&retn[strlen(retn)], "%s ", input->filename);
               input = (void *)input->qhdr.nxt;
            }
         }
      }

   }

   if (RaDatabase && RaTable) {
      if (ArgusParser->readDbstr != NULL) {
         sprintf (&retn[strlen(retn)], "-r %s/%s ", ArgusParser->readDbstr, ArgusSQLSaveTableNameBuf);
      }
      if (ArgusParser->writeDbstr != NULL)
         sprintf (&retn[strlen(retn)], "-w %s/%s ", ArgusParser->writeDbstr, RaSQLCurrentTable);
   }

   if ((mode = parser->ArgusModeList) != NULL) { 
      sprintf (&retn[strlen(retn)], "-M ");
      while (mode) { 
         sprintf (&retn[strlen(retn)], "%s ", mode->mode);
         mode = mode->nxt;
      }
   }

   if (((mode = parser->ArgusMaskList) != NULL) || ((parser->ArgusAggregator != NULL) && (parser->ArgusAggregator->mask == 0))) {
      sprintf (&retn[strlen(retn)], "-m ");
      while (mode) {
         sprintf (&retn[strlen(retn)], "%s ", mode->mode);
         mode = mode->nxt;
      }
   }

   if (parser->Hstr)
      sprintf (&retn[strlen(retn)], "-H %s ", parser->Hstr);

   if ((parser->ArgusDisplayFilter) || parser->ArgusLocalFilter || parser->ArgusRemoteFilter) {
      sprintf (&retn[strlen(retn)], "- ");
      if (parser->ArgusDisplayFilter)
         sprintf (&retn[strlen(retn)], "display '%s' ", parser->ArgusDisplayFilter);
      if (parser->ArgusLocalFilter)
         sprintf (&retn[strlen(retn)], "local '%s' ", parser->ArgusLocalFilter);
      if (parser->ArgusRemoteFilter) 
         sprintf (&retn[strlen(retn)], "remote '%s' ", parser->ArgusRemoteFilter);
   }
   return (retn);
}


#if defined(ARGUS_COLOR_SUPPORT)

int
ArgusColorAvailability(struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, struct ArgusAttributeStruct *cols, short pair, attr_t attr)
{
   short tpair = pair;
   attr_t tattr = attr;
   int retn = 0, i;

   if (ArgusTerminalColors) {
      ArgusProcessServiceAvailability(parser, ns);

      if (parser->Aflag & (ns->status & RA_SVCFAILED)) {
         tpair = COLOR_PAIR(ARGUS_ORANGE);

         for (i = 0; i < RaScreenColumns; i++) {
            cols[i].pair = tpair;
            cols[i].attr = tattr;
         }
      }
   }
   return(retn);
}

int
ArgusColorAddresses(struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, struct ArgusAttributeStruct *cols, short pair, attr_t attr)
{
   struct ArgusLabelerStruct *labeler = NULL;
   int ArgusSrcAddrPair, ArgusDstAddrPair;
   int retn = 0;

   if (ArgusTerminalColors) {
      extern int ArgusTestMulticast( struct ArgusInput *input, unsigned int);
      struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];

      ArgusSrcAddrPair = pair;
      ArgusDstAddrPair = pair;

      switch (ns->hdr.type & 0xF0) {
         case ARGUS_MAR:
         case ARGUS_EVENT: {
            break;
         }

         case ARGUS_NETFLOW:
         case ARGUS_FAR: {
            if (flow) {
               int i, done;
               switch (flow->hdr.subtype & 0x3F) {
                  case ARGUS_FLOW_CLASSIC5TUPLE:
                  case ARGUS_FLOW_LAYER_3_MATRIX: {
                     switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                        case ARGUS_TYPE_IPV4: {
                           if (ArgusTestMulticast(ns->input, flow->ip_flow.ip_src))
                              ArgusSrcAddrPair = COLOR_PAIR(ARGUS_BASE00);

                           if (ArgusTestMulticast(ns->input, flow->ip_flow.ip_dst))
                              ArgusDstAddrPair = COLOR_PAIR(ARGUS_BASE00);

                           if ((labeler = parser->ArgusLocalLabeler) != NULL) {
                              int status;

                              status = RaProcessAddress (parser, labeler, &flow->ip_flow.ip_src, flow->ip_flow.smask, ARGUS_TYPE_IPV4);
                              switch (status) {
                                 case ARGUS_MY_ADDRESS: ArgusSrcAddrPair = COLOR_PAIR(ARGUS_BLUE); break;
                                 case ARGUS_MY_NETWORK: ArgusSrcAddrPair = COLOR_PAIR(ARGUS_CYAN); break;
                              }

                              status = RaProcessAddress (parser, labeler, &flow->ip_flow.ip_dst, flow->ip_flow.dmask, ARGUS_TYPE_IPV4);
                              switch (status) {
                                 case ARGUS_MY_ADDRESS: ArgusDstAddrPair = COLOR_PAIR(ARGUS_BLUE); break;
                                 case ARGUS_MY_NETWORK: ArgusDstAddrPair = COLOR_PAIR(ARGUS_CYAN); break;
                              }
                           }
                           break;
                        }

                        case ARGUS_TYPE_IPV6: {
#ifndef IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(a) (((__const uint8_t *) (a))[0] == 0xff)
#endif
                           if (IN6_IS_ADDR_MULTICAST((struct in6_addr *)&flow->ipv6_flow.ip_src))
                              ArgusSrcAddrPair = COLOR_PAIR(ARGUS_BASE00);

                           if (IN6_IS_ADDR_MULTICAST((struct in6_addr *)&flow->ipv6_flow.ip_dst))
                              ArgusDstAddrPair = COLOR_PAIR(ARGUS_BASE00);

                           break;
                        }
                     }
                     break;
                  }

                  case ARGUS_FLOW_ARP: {
                     switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                        case ARGUS_TYPE_ARP: {
                           if ((labeler = parser->ArgusLocalLabeler) != NULL) {
                              int status;

                              status = RaProcessAddress (parser, labeler, &flow->arp_flow.arp_spa, 32, ARGUS_TYPE_IPV4);
                              switch (status) {
                                 case ARGUS_MY_ADDRESS: ArgusSrcAddrPair = COLOR_PAIR(ARGUS_BLUE); break;
                                 case ARGUS_MY_NETWORK: ArgusSrcAddrPair = COLOR_PAIR(ARGUS_CYAN); break;
                              }

                              status = RaProcessAddress (parser, labeler, &flow->arp_flow.arp_tpa, 32, ARGUS_TYPE_IPV4);
                              switch (status) {
                                 case ARGUS_MY_ADDRESS: ArgusDstAddrPair = COLOR_PAIR(ARGUS_BLUE); break;
                                 case ARGUS_MY_NETWORK: ArgusDstAddrPair = COLOR_PAIR(ARGUS_CYAN); break;
                              }
                           }
                        }
                     }
                     break;
                  }
               }

               for (i = 0, done = 0; i < MAX_PRINT_ALG_TYPES && !done; i++) {
                  struct ArgusPrintFieldStruct *f;
                  if ((f = parser->RaPrintAlgorithmList[i]) != NULL) {
                     int slen   = f->length;
                     int offset = f->offset;
                     int x;

                     switch (f->value) {
                        case ARGUSPRINTSRCADDR: {
                           f->pair = ArgusSrcAddrPair;
                           f->attr = attr;
                           for (x = 0; x < slen; x++) {
                              cols[offset + x].pair = f->pair;
                              cols[offset + x].attr = f->attr;
                           }
                           break;
                        }
                        case ARGUSPRINTDSTADDR: {
                           f->pair = ArgusDstAddrPair;
                           f->attr = attr;
                           for (x = 0; x < slen; x++) {
                              cols[offset + x].pair = f->pair;
                              cols[offset + x].attr = f->attr;
                           }
                           break;
                        }
                     }
                  } else
                     done = 1;
               }
            }
         }
      }
   }
   return (retn);
}


int
ArgusColorFlowFields(struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, struct ArgusAttributeStruct *cols, short pair, attr_t attr)
{
   struct ArgusLabelerStruct *labeler = parser->ArgusColorLabeler;
   int retn = 0;

   if (labeler != NULL) {
      char *color = RaFlowColor(parser, ns);
      if (color != NULL) {
         char ptrbuf[1024], *ptr = ptrbuf;
         char *tok = NULL;
         int i, done;

         strncpy(ptr, color, sizeof(ptrbuf));

         while ((tok = strsep (&ptr, ";")) != NULL) {
            char *cptr, *aptr, *fields = tok;

            if ((cptr = strchr(tok, ':')) != NULL) {
               char *tfield = fields, *tcolor = NULL, *tattr = NULL;

               *cptr++ = '\0';
               tcolor = cptr;
               if ((aptr = strchr(tcolor, '+')) != NULL) {
                  *aptr = '\0';
                  tattr = aptr + 1;
               }

               if (tcolor) {
                  switch (*tcolor) {
                     case 'W': pair = COLOR_PAIR(ARGUS_WHITE); break;
                     case 'G': pair = COLOR_PAIR(ARGUS_GREEN); break;
                     case 'B': pair = COLOR_PAIR(ARGUS_BLUE); break;
                     case 'V': pair = COLOR_PAIR(ARGUS_VIOLET); break;
                     case 'C': pair = COLOR_PAIR(ARGUS_CYAN); break;
                     case 'R': pair = COLOR_PAIR(ARGUS_RED); break;
                     case 'M': pair = COLOR_PAIR(ARGUS_MAGENTA); break;
                     case 'O': pair = COLOR_PAIR(ARGUS_ORANGE); break;
                     case 'Y': pair = COLOR_PAIR(ARGUS_YELLOW); break;
                      default: pair = COLOR_PAIR(ARGUS_BASE0); break;
                  }
               }
               if (tattr) {
                  switch (*tattr) {
                     case 'N': attr = A_NORMAL; break;     //  Normal display (no highlight)
                     case 'S': attr = A_STANDOUT; break;   //  Best highlighting mode of the terminal.
                     case 'U': attr = A_UNDERLINE; break;  //  Underlining
                     case 'R': attr = A_REVERSE; break;    //  Reverse video
                     case 'B': attr = A_BLINK; break;      //  Blinking
                     case 'D': attr = A_DIM; break;        //  Half bright
//                   case 'B': attr = A_BOLD; break;       //  Extra bright or bold
                     case 'P': attr = A_PROTECT; break;    //  Protected mode
                     case 'I': attr = A_INVIS; break;      //  Invisible or blank mode
                     case 'A': attr = A_ALTCHARSET; break; //  Alternate character set
                     case 'C': attr = A_CHARTEXT; break;   //  Bit-mask to extract a character
                  }
               }

               if (!(strcmp("all", tfield))) {
                  for (i = 0; i < RaScreenColumns; i++) {
                     cols[i].pair = pair;
                     cols[i].attr = attr;
                  }
               } else {
                  for (i = 0, done = 0; i < MAX_PRINT_ALG_TYPES && !done; i++) {
                     struct ArgusPrintFieldStruct *f;
                     char *fptr;

                     if ((f = parser->RaPrintAlgorithmList[i]) != NULL) {
                        if ((fptr = strstr(tfield, f->field)) != NULL) {
                           int slen   = f->length;
                           int offset = f->offset;
                           int x;

                           for (x = 0; x < slen; x++) {
                              cols[offset + x].pair = pair;
                              cols[offset + x].attr = attr;
                           }
                        }
                     } else
                        done = 1;
                  }
               }
            }
         }
      }
   }

   return (retn);
}

int
ArgusColorGeoLocation(struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, struct ArgusAttributeStruct *cols, short pair, attr_t attr)
{
   struct ArgusLabelerStruct *labeler = NULL;
   int retn = 0;

   if (labeler != NULL) {
   }

   return (retn);
}

int ArgusDisplayColorsInitialized = 0;

void
ArgusInitializeColorMap(struct ArgusParserStruct *parser, WINDOW *win)
{
   int i, done;
   attr_t attr;
   short pair;

   wattr_get(win, &attr, &pair, NULL);
   
   for (i = 0, done = 0; i < MAX_PRINT_ALG_TYPES && !done; i++) {
      struct ArgusPrintFieldStruct *f;
      if ((f = parser->RaPrintAlgorithmList[i]) != NULL) {
         switch (f->value) {
            case ARGUSPRINTRANK: 
               f->pair = COLOR_PAIR(ARGUS_BASE02);
               f->attr = attr;
               break;
            default:
               f->pair = pair;
               f->attr = attr;
               break;
         }
      } else
         done = 1;
   }
}

int
ArgusGetDisplayLineColor(struct ArgusParserStruct *parser, WINDOW *win, struct ArgusRecordStruct *ns, struct ArgusAttributeStruct *cols)
{
   int retn = 0, i, done;
   attr_t attr;
   short pair;
   
   if (!(ArgusDisplayColorsInitialized)) {
      ArgusInitializeColorMap(parser, win);
      ArgusDisplayColorsInitialized = 1;
   }

   bzero(cols, sizeof(*cols) * RaScreenColumns);
   wattr_get(win, &attr, &pair, NULL);

   for (i = 0, done = 0; i < MAX_PRINT_ALG_TYPES && !done; i++) {
      struct ArgusPrintFieldStruct *f;
      if ((f = parser->RaPrintAlgorithmList[i]) != NULL) {
         int slen   = f->length;
         int offset = f->offset;
         int x;

         for (x = 0; x < slen; x++) {
            cols[offset + x].pair = f->pair;
            cols[offset + x].attr = f->attr;
         }
      } else
         done = 1;
   }

   for (i = 0; i < ARGUS_MAX_COLOR_ALG; i++)
      if (RaColorAlgorithms[i] != NULL)
         RaColorAlgorithms[i](parser, ns, cols, pair, attr);

   return (retn);
}
#endif



#if defined(ARGUS_MYSQL)

void
RaSQLQueryTable (char *table)
{
   char buf[0x10000], sbuf[0x10000];
   MYSQL_RES *mysqlRes;
   struct timeval now;
   int retn, x;

   if ((ArgusInput = (struct ArgusInput *) ArgusCalloc (1, sizeof(struct ArgusInput))) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

   ArgusInput->ArgusInitCon.hdr.type  = ARGUS_MAR | ARGUS_VERSION;
   ArgusInput->ArgusInitCon.hdr.cause = ARGUS_START;
   ArgusInput->ArgusInitCon.hdr.len   = htons((unsigned short) sizeof(struct ArgusRecord)/4);

   ArgusInput->ArgusInitCon.argus_mar.argusid = htonl(ARGUS_COOKIE);

   gettimeofday (&now, 0L);

   ArgusInput->ArgusInitCon.argus_mar.now.tv_sec  = now.tv_sec;
   ArgusInput->ArgusInitCon.argus_mar.now.tv_usec = now.tv_usec;

   ArgusInput->ArgusInitCon.argus_mar.major_version = VERSION_MAJOR;
   ArgusInput->ArgusInitCon.argus_mar.minor_version = VERSION_MINOR;

   bcopy((char *)&ArgusInput->ArgusInitCon, (char *)&ArgusParser->ArgusInitCon, sizeof (ArgusParser->ArgusInitCon));

   sprintf (buf, "SELECT record from %s", table);

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaSQLQueryProbes: SQL Query %s\n", buf);
#endif

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&RaMySQLlock);
#endif

   if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
      ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));
   else {

      ArgusTotalSQLSearches++;

      if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               unsigned long *lengths;

               lengths = mysql_fetch_lengths(mysqlRes);
               bzero(sbuf, sizeof(sbuf));
 
               for (x = 0; x < retn; x++) {
                  bcopy (row[x], sbuf, (int) lengths[x]);

                  if (((struct ArgusRecord *)sbuf)->hdr.type & ARGUS_MAR) {
                     bcopy ((char *) &sbuf, (char *)&ArgusInput->ArgusInitCon, sizeof (struct ArgusRecord));
                  } else 
                     ArgusHandleRecord (ArgusParser, ArgusInput, (struct ArgusRecord *)&sbuf, &ArgusParser->ArgusFilterCode);
               }
            }
         }

         mysql_free_result(mysqlRes);
      }
   }
#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&RaMySQLlock);
#endif
}


void
RaSQLQueryProbes ()
{
   struct RaMySQLProbeTable *sqry = NULL;
   char buf[2048], sbuf[2048];
   MYSQL_RES *mysqlRes;
   char *endptr;
   int retn, x;

   sprintf (buf, "%s", RaTableQueryString[0]);
#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaSQLQueryProbes: SQL Query %s\n", buf);
#endif

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&RaMySQLlock);
#endif
   if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
      ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));

   else {
      if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               unsigned long *lengths;
    
               lengths = mysql_fetch_lengths(mysqlRes);
               bzero(sbuf, sizeof(sbuf));

               if ((sqry = (void *) ArgusCalloc (1, sizeof(*sqry))) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

               for (x = 0; x < retn; x++) {
                  snprintf(sbuf, 2048, "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");
                  switch (x) {
                     case RAMYSQL_PROBETABLE_PROBE:
                        sqry->probe = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_PROBETABLE_NAME:
                        sqry->name = strdup(sbuf);
                        break;
                  }
               }
               ArgusAddToQueue (ArgusProbeQueue, &sqry->qhdr, ARGUS_LOCK);
            }
         }
         mysql_free_result(mysqlRes);
      }
   }
#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&RaMySQLlock);
#endif
}

void
RaSQLQuerySecondsTable (unsigned int start, unsigned int stop)
{
   struct RaMySQLSecondsTable *sqry = NULL;
   char buf[2048], sbuf[2048];
   MYSQL_RES *mysqlRes;
   char *endptr, *str;
   int retn, x;


   if (RaRoleString) {
      str = "SELECT * from %s_Seconds WHERE second >= %u and second <= %u",
      sprintf (buf, str, RaRoleString, start, stop);
   } else {
      str = "SELECT * from Seconds WHERE second >= %u and second <= %u",
      sprintf (buf, str, start, stop);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaSQLQuerySecondsTable: SQL Query %s\n", buf);
#endif

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&RaMySQLlock);
#endif

   if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
      ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));

   else {
      if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               unsigned long *lengths;
    
               lengths = mysql_fetch_lengths(mysqlRes);
               bzero(sbuf, sizeof(sbuf));

               if ((sqry = (void *) ArgusCalloc (1, sizeof(*sqry))) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

               for (x = 0; x < retn; x++) {
                  int y = x;
                  snprintf(sbuf, 2048, "%.*s ", (int) lengths[x], row[x] ? row[x] : "NULL");
                  if (!(RaRoleString)) 
                     y++;
                  
                  switch (y) {
                     case RAMYSQL_SECONDTABLE_PROBE:
                        sqry->probe = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_SECONDTABLE_SECOND:
                        sqry->second = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_SECONDTABLE_FILEINDEX:
                        sqry->fileindex = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_SECONDTABLE_OSTART:
                        sqry->ostart = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_SECONDTABLE_OSTOP:
                        sqry->ostop = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;
                  }
               }

               ArgusAddToQueue (ArgusModelerQueue, &sqry->qhdr, ARGUS_LOCK);
            }
         }

         mysql_free_result(mysqlRes);
      }
   }
#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&RaMySQLlock);
#endif
}


/*
   Mysql URL that we will respond to is:
      mysql://[username[:password]@]hostname[:port]/database/tablename
*/

/*
   ArgusProcessSQLQueryList
      As long as we don't have any errors, process the list.
      If there are errors, return with the error code, such as
      CR_SERVER_GONE_ERROR, or CR_SERVER_LOST.  The calling routine
      will decide what to do.
*/


#if defined(ARGUS_THREADS)

int ArgusProcessSQLUpdateQueryList(struct ArgusParserStruct *);
int ArgusProcessSQLSelectQueryList(struct ArgusParserStruct *);
int ArgusProcessSQLInsertQueryList(struct ArgusParserStruct *);

int ArgusProcessSQLQueryList(struct ArgusParserStruct *, struct ArgusListStruct *);


int
ArgusProcessSQLQueryList(struct ArgusParserStruct *parser, struct ArgusListStruct *ArgusSQLQueryList)
{
   int retn = 0;

   if ((ArgusSQLQueryList != NULL) && (ArgusSQLQueryList->count > 0)) {
      struct ArgusSQLQueryStruct *sqry = NULL;
      char *sptr = NULL;
      int slen = 0;

      while (!retn && !(ArgusListEmpty(ArgusSQLQueryList))) {
         if ((sqry = (void *) ArgusPopFrontList(ArgusSQLQueryList, ARGUS_LOCK)) != NULL) {   // pop off sql queries 
            if ((sptr = sqry->sptr) != NULL) {
               slen = strlen(sptr);
#if defined(ARGUSDEBUG)
               if (sqry->dptr != NULL)
                  ArgusDebug (3, "ArgusSQLQuery (%s)\n", sqry->dptr);
               else
                  ArgusDebug (3, "ArgusSQLQuery (%s)\n", sqry->sptr);
#endif
               switch (*sptr) {
                  case 'S':  {
#ifdef ARGUSDEBUG
                     ArgusDebug (3, "ArgusProcessSQLQueryList: Select query\n");
#endif
#if defined(ARGUS_THREADS)
                     pthread_mutex_lock(&RaMySQLlock);
#endif
                     ArgusTotalSelectSQLStatements++;
#if defined(ARGUS_THREADS)
                     pthread_mutex_unlock(&RaMySQLlock);
#endif
                     break;
                  }

                  case 'U':  {
                     int slen = strlen(sptr);
#if defined(ARGUS_THREADS)
                     pthread_mutex_lock(&RaMySQLlock);
#endif
                     if ((retn = mysql_real_query(RaMySQL, sptr, slen)) != 0) {
                        ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));
                     } else {
                        ArgusTotalSQLWrites += slen;
                        ArgusTotalSQLUpdates++;
                     }
                     ArgusTotalUpdateSQLStatements++;

#if defined(ARGUS_THREADS)
                     pthread_mutex_unlock(&RaMySQLlock);
#endif
                     break;
                  }

                  case 'I': {
                     if (0 == ArgusTotalInsertSQLStatements++)
                        ArgusSQLBulkLastTable = strdup(sqry->tbl);

                     if (ArgusSQLBulkBuffer != NULL) {  // the idea here is to bulk up inserts to the max size
                                                        // so if there is a bulking buffer, use it if you can,
                                                        // if not, writeout the query.
                        char *tptr = sptr;

                        if (ArgusSQLBulkLastTable) {
                           if ((strncmp(ArgusSQLBulkLastTable, sqry->tbl, strlen(sqry->tbl))) ||
                              ((ArgusSQLBulkBufferIndex + slen) > ArgusSQLBulkInsertSize)) {
#ifdef ARGUSDEBUG
                              ArgusDebug (3, "ArgusProcessSQLQueryList: ArgusSQLBulkLastTable Query count %d len %d\n", retn, ArgusSQLBulkBufferIndex);
#endif
#if defined(ARGUS_THREADS)
                              pthread_mutex_lock(&RaMySQLlock);
#endif
                              if ((retn = mysql_real_query(RaMySQL, ArgusSQLBulkBuffer, ArgusSQLBulkBufferIndex)) != 0)
                                 ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));
                              else {
                                 ArgusTotalSQLWrites += ArgusSQLBulkBufferIndex;
                                 ArgusTotalSQLUpdates++;
                              }
                              ArgusSQLBulkBufferIndex = 0;
                              ArgusSQLBulkBufferCount = 0;
                              bzero(ArgusSQLBulkBuffer, 32);

                              if (ArgusSQLBulkLastTable) {
                                 free(ArgusSQLBulkLastTable);
                                 ArgusSQLBulkLastTable   = NULL;
                              }
#if defined(ARGUS_THREADS)
                              pthread_mutex_unlock(&RaMySQLlock);
#endif
                           }

                           if (ArgusSQLBulkBufferIndex > 0) {
                              char *vptr = strstr(tptr, "VALUES (");
                              if (vptr != NULL) {
                                 if ((vptr = strchr(vptr, '(')) != NULL)  {
                                    tptr = vptr;
                                    slen = strlen(tptr);
                                    sprintf(&ArgusSQLBulkBuffer[ArgusSQLBulkBufferIndex++], ",");
                                 }
                              } else {
                                 ArgusLog(LOG_INFO, "bulk buffer error query has no values %s", tptr);
                                 tptr = NULL;
                              }
                           }

                           if (tptr != NULL) {
                              bcopy(tptr, &ArgusSQLBulkBuffer[ArgusSQLBulkBufferIndex], slen);
                              ArgusSQLBulkBufferCount++;
                              ArgusSQLBulkBufferIndex += slen;
                              if (ArgusSQLBulkLastTable == NULL)
                                 ArgusSQLBulkLastTable = strdup(sqry->tbl);
                           }

                        } else {
#ifdef ARGUSDEBUG
                           ArgusDebug (3, "ArgusProcessSQLQueryList: single SQL Query len %d\n", slen);
#endif
#if defined(ARGUS_THREADS)
                           pthread_mutex_lock(&RaMySQLlock);
#endif
                           if ((retn = mysql_real_query(RaMySQL, sptr, slen)) != 0) {
                              ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));
                           } else {
                              ArgusTotalSQLWrites += ArgusSQLBulkBufferIndex;
                              ArgusSQLBulkBufferIndex = 0;
                              ArgusSQLBulkBufferCount = 0;
                           }
#if defined(ARGUS_THREADS)
                           pthread_mutex_unlock(&RaMySQLlock);
#endif
                        }
                     }
                     break;
                  }
               }

               if (sqry->sptr != NULL)
                  free(sqry->sptr);
               if (sqry->dptr != NULL)
                  free(sqry->dptr);
               if (sqry->tbl != NULL)
                  free(sqry->tbl);
               ArgusFree(sqry);
            }
         }
      }
   }

   return (retn);
}


void *
ArgusMySQLInsertProcess (void *arg)
{
   struct ArgusParserStruct *parser = (struct ArgusParserStruct *) arg;
   sigset_t blocked_signals;
   int i;

   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusMySQLInsertProcess() starting");
#endif

   for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
      if (parser->RaPrintAlgorithmList[i] != NULL) {
         parser->RaPrintAlgorithm = parser->RaPrintAlgorithmList[i];
         if (!strncmp(parser->RaPrintAlgorithm->field, "autoid", 6)) {
            ArgusAutoId = 1;
            break;
         }
      }
   }

   while (!(ArgusCloseDown)) {
      if ((ArgusSQLInsertQueryList != NULL) && (ArgusSQLInsertQueryList->count > 0))
         ArgusProcessSQLQueryList(parser, ArgusSQLInsertQueryList);

      else {
         struct timespec tsbuf, *ts = &tsbuf;

         if (ArgusSQLInsertQueryList) {
            struct timeval tvp;

            gettimeofday (&tvp, 0L);
            ts->tv_sec   = parser->RaClientTimeout.tv_sec  + tvp.tv_sec;
            ts->tv_nsec  = (parser->RaClientTimeout.tv_usec + tvp.tv_usec) * 1000;
            if (ts->tv_nsec > 1000000000) {
               ts->tv_sec++;
               ts->tv_nsec -= 1000000000;
            }
            pthread_mutex_lock(&ArgusSQLInsertQueryList->lock);
            pthread_cond_timedwait(&ArgusSQLInsertQueryList->cond, &ArgusSQLInsertQueryList->lock, ts);
            pthread_mutex_unlock(&ArgusSQLInsertQueryList->lock);

         } else {
            ts->tv_sec  = parser->RaClientTimeout.tv_sec;
            ts->tv_nsec = parser->RaClientTimeout.tv_usec * 1000;
            nanosleep(ts, NULL);
         }
      }

      if (ArgusSQLBulkBufferIndex > 0) {
         int retn;

#ifdef ARGUSDEBUG
         ArgusDebug (3, "ArgusMySQLInsertProcess: residual buffer Count %d SQL Query len %d\n", ArgusSQLBulkBufferCount, ArgusSQLBulkBufferIndex);
#endif
#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&RaMySQLlock);
#endif
         if ((retn = mysql_real_query(RaMySQL, ArgusSQLBulkBuffer, ArgusSQLBulkBufferIndex)) != 0) {
            ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));
         } else {
            ArgusTotalSQLWrites += ArgusSQLBulkBufferIndex;
         }

         ArgusSQLBulkBufferIndex = 0;
         ArgusSQLBulkBufferCount = 0;
#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&RaMySQLlock);
#endif
      }
   }

   pthread_join(RaCursesThread, NULL);

   if ((ArgusSQLInsertQueryList != NULL) && (ArgusSQLInsertQueryList->count > 0))
      ArgusProcessSQLQueryList(parser, ArgusSQLInsertQueryList);

   if (RaSQLUpdateDB) {
      if (ArgusSQLBulkBufferIndex > 0) {
         int retn;

#ifdef ARGUSDEBUG
         ArgusDebug (3, "ArgusMySQLInsertProcess: residual buffer Count %d SQL Query len %d\n", ArgusSQLBulkBufferCount, ArgusSQLBulkBufferIndex);
#endif
#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&RaMySQLlock);
#endif
         if ((retn = mysql_real_query(RaMySQL, ArgusSQLBulkBuffer, ArgusSQLBulkBufferIndex)) != 0) {
            ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));
         } else {
            ArgusTotalSQLWrites += ArgusSQLBulkBufferIndex;
         }

         ArgusSQLBulkBufferIndex = 0;
         ArgusSQLBulkBufferCount = 0;
#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&RaMySQLlock);
#endif
      }
   }

   if (RaSQLUpdateDB) {
         int i, retn;
         char *str = NULL;

      if (ArgusDeleteTable) {
         for (i = 0; i < RA_MAXTABLES; i++) {
            if ((str = RaTableDeleteString[i]) != NULL) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "deleting table %s\n", str);
#endif
#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&RaMySQLlock);
#endif
               if ((retn = mysql_real_query(RaMySQL, str, strlen(str))) != 0)
                  ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&RaMySQLlock);
#endif
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusMySQLInsertProcess() done!");
#endif

#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#else
   return (NULL);
#endif
}



void *
ArgusMySQLSelectProcess (void *arg)
{
   struct ArgusParserStruct *parser = (struct ArgusParserStruct *) arg;
   struct timespec tsbuf, *ts = &tsbuf;
   sigset_t blocked_signals;
   int i;

   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

   ts->tv_sec  = parser->RaClientTimeout.tv_sec;
   ts->tv_nsec = parser->RaClientTimeout.tv_usec * 1000;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusMySQLSelectProcess() starting");
#endif

   for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
      if (parser->RaPrintAlgorithmList[i] != NULL) {
         parser->RaPrintAlgorithm = parser->RaPrintAlgorithmList[i];
         if (!strncmp(parser->RaPrintAlgorithm->field, "autoid", 6)) {
            ArgusAutoId = 1;
            break;
         }
      }
   }

   while (!(ArgusCloseDown)) {
      if ((ArgusSQLSelectQueryList != NULL) && (ArgusSQLSelectQueryList->count > 0))
         ArgusProcessSQLQueryList(parser, ArgusSQLSelectQueryList);
      else {
         struct timespec tsbuf, *ts = &tsbuf;

         if (ArgusSQLSelectQueryList) {
            struct timeval tvp;

            gettimeofday (&tvp, 0L);
            ts->tv_sec   = parser->RaClientTimeout.tv_sec  + tvp.tv_sec;
            ts->tv_nsec  = (parser->RaClientTimeout.tv_usec + tvp.tv_usec) * 1000;
            if (ts->tv_nsec > 1000000000) {
               ts->tv_sec++;
               ts->tv_nsec -= 1000000000;
            }
            pthread_mutex_lock(&ArgusSQLSelectQueryList->lock);
            pthread_cond_timedwait(&ArgusSQLSelectQueryList->cond, &ArgusSQLSelectQueryList->lock, ts);
            pthread_mutex_unlock(&ArgusSQLSelectQueryList->lock);

         } else {
            ts->tv_sec  = parser->RaClientTimeout.tv_sec;
            ts->tv_nsec = parser->RaClientTimeout.tv_usec * 1000;
            nanosleep(ts, NULL);
         }
      }
   }

   pthread_join(RaCursesThread, NULL);

   if ((ArgusSQLSelectQueryList != NULL) && (ArgusSQLSelectQueryList->count > 0))
      ArgusProcessSQLQueryList(parser, ArgusSQLSelectQueryList);

   if (RaSQLUpdateDB) {
         int i, retn;
         char *str = NULL;

      if (ArgusDeleteTable) {
         for (i = 0; i < RA_MAXTABLES; i++) {
            if ((str = RaTableDeleteString[i]) != NULL) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "deleting table %s\n", str);
#endif
#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&RaMySQLlock);
#endif
               if ((retn = mysql_real_query(RaMySQL, str, strlen(str))) != 0)
                  ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&RaMySQLlock);
#endif
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusMySQLSelectProcess() done!");
#endif

#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#else
   return (NULL);
#endif
}



void *
ArgusMySQLUpdateProcess (void *arg)
{
   struct ArgusParserStruct *parser = (struct ArgusParserStruct *) arg;
   struct timespec tsbuf, *ts = &tsbuf;
   sigset_t blocked_signals;
   int i;

   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

   ts->tv_sec  = parser->RaClientTimeout.tv_sec;
   ts->tv_nsec = parser->RaClientTimeout.tv_usec * 1000;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusMySQLUpdateProcess() starting");
#endif

   for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
      if (parser->RaPrintAlgorithmList[i] != NULL) {
         parser->RaPrintAlgorithm = parser->RaPrintAlgorithmList[i];
         if (!strncmp(parser->RaPrintAlgorithm->field, "autoid", 6)) {
            ArgusAutoId = 1;
            break;
         }
      }
   }

            
   while (!(ArgusCloseDown)) {
      if ((ArgusSQLUpdateQueryList != NULL) && (ArgusSQLUpdateQueryList->count > 0))
         ArgusProcessSQLQueryList(parser, ArgusSQLUpdateQueryList);
      else {
         struct timespec tsbuf, *ts = &tsbuf;

         if (ArgusSQLUpdateQueryList) {
            struct timeval tvp;

            gettimeofday (&tvp, 0L);
            ts->tv_sec   = parser->RaClientTimeout.tv_sec  + tvp.tv_sec;
            ts->tv_nsec  = (parser->RaClientTimeout.tv_usec + tvp.tv_usec) * 1000;
            if (ts->tv_nsec > 1000000000) {
               ts->tv_sec++;
               ts->tv_nsec -= 1000000000;
            }
            pthread_mutex_lock(&ArgusSQLUpdateQueryList->lock);
            pthread_cond_timedwait(&ArgusSQLUpdateQueryList->cond, &ArgusSQLUpdateQueryList->lock, ts);
            pthread_mutex_unlock(&ArgusSQLUpdateQueryList->lock);

         } else {
            ts->tv_sec  = parser->RaClientTimeout.tv_sec;
            ts->tv_nsec = parser->RaClientTimeout.tv_usec * 1000;
            nanosleep(ts, NULL);
         }
      }
   }

   pthread_join(RaCursesThread, NULL);

   if ((ArgusSQLUpdateQueryList != NULL) && (ArgusSQLUpdateQueryList->count > 0))
      ArgusProcessSQLQueryList(parser, ArgusSQLUpdateQueryList);

   if (RaSQLUpdateDB) {
         int i, retn;
         char *str = NULL;

      if (ArgusDeleteTable) {
         for (i = 0; i < RA_MAXTABLES; i++) {
            if ((str = RaTableDeleteString[i]) != NULL) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "deleting table %s\n", str);
#endif
#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&RaMySQLlock);
#endif
               if ((retn = mysql_real_query(RaMySQL, str, strlen(str))) != 0)
                  ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&RaMySQLlock);
#endif
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusMySQLUpdateProcess() done!");
#endif

#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#else
   return (NULL);
#endif
}

#endif


void
RaMySQLInit ()
{
   my_bool reconnectbuf = 1, *reconnect = &reconnectbuf;
   char *sptr = NULL, *ptr;
   char userbuf[1024], sbuf[1024], db[1024], *dbptr = NULL;
   MYSQL_RES *mysqlRes;
   int retn = 0, x;

   bzero((char *)RaTableExistsNames,  sizeof(RaTableExistsNames));
   bzero((char *)RaTableCreateNames,  sizeof(RaTableCreateNames));
   bzero((char *)RaTableCreateString, sizeof(RaTableCreateString));
   bzero((char *)RaTableDeleteString, sizeof(RaTableDeleteString));

   if (ArgusParser->MySQLDBEngine == NULL)
      ArgusParser->MySQLDBEngine = strdup("MyISAM");

   if ((RaUser == NULL) && (ArgusParser->dbuserstr != NULL)) {
      bzero(userbuf, sizeof(userbuf));
      strncpy (userbuf, ArgusParser->dbuserstr, sizeof(userbuf));
      if ((sptr = strchr (userbuf, ':')) != NULL) {
         *sptr++ = '\0';
         RaPass = strdup(sptr);
      }
      RaUser = strdup(userbuf);
   }

   if ((RaPass == NULL) && (ArgusParser->dbpassstr != NULL))
      RaPass = ArgusParser->dbpassstr;

   if (RaDatabase == NULL) {
      if (ArgusParser->writeDbstr != NULL)
         RaDatabase = strdup(ArgusParser->writeDbstr);

      else if (ArgusParser->readDbstr != NULL)
         RaDatabase = strdup(ArgusParser->readDbstr);

      if (RaDatabase != NULL)
         if (!(strncmp("mysql:", RaDatabase, 6))) {
            char *tmp = RaDatabase;
            RaDatabase = strdup(&RaDatabase[6]);
            free(tmp);
         }
   }

   if (RaDatabase == NULL) {
      ArgusLog(LOG_ERR, "must specify database"); 

   } else {
      sprintf(db, "%s", RaDatabase);
      dbptr = db;
/*
      //[[username[:password]@]hostname[:port]]/database/tablename
*/

      if (!(strncmp ("//", dbptr, 2))) {
         char *rhost = NULL, *ruser = NULL, *rpass = NULL;
         if ((strncmp ("///", dbptr, 3))) {
            dbptr = &dbptr[2];
            rhost = dbptr;
            if ((ptr = strchr (dbptr, '/')) != NULL) {
               *ptr++ = '\0';
               dbptr = ptr;

               if ((ptr = strchr (rhost, '@')) != NULL) {
                  ruser = rhost;
                  *ptr++ = '\0';
                  rhost = ptr;
                  if ((ptr = strchr (ruser, ':')) != NULL) {
                     *ptr++ = '\0';
                     rpass = ptr;
                  } else {
                     rpass = NULL;
                  }
               }

               if ((ptr = strchr (rhost, ':')) != NULL) {
                  *ptr++ = '\0';
                  RaPort = atoi(ptr);
               }
            } else
               dbptr = NULL;

         } else {
            dbptr = &dbptr[3];
         }

         if (ruser != NULL) {
            if (RaUser != NULL) free(RaUser);
            RaUser = strdup(ruser);
         }
         if (rpass != NULL) {
            if (RaPass != NULL) free(RaPass);
            RaPass = strdup(rpass);
         }
         if (rhost != NULL) {
            if (RaHost != NULL) free(RaHost);
            RaHost = strdup(rhost);
         }
         free(RaDatabase);
         RaDatabase = strdup(dbptr);
      }
   }
 
   if ((ptr = strchr (RaDatabase, '/')) != NULL) {
      *ptr++ = '\0';
      RaTable = ptr;

      if (ArgusParser->writeDbstr != NULL)
         snprintf (RaSQLSaveTable, MAXSTRLEN, "%s", RaTable);
   }

   if (!(ArgusParser->status & ARGUS_REAL_TIME_PROCESS))
      ArgusLastTime = ArgusParser->ArgusRealTime;

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&RaMySQLlock, NULL);
   pthread_mutex_lock(&RaMySQLlock);
#endif

   if (RaMySQL == NULL)
      if ((RaMySQL = (void *) ArgusCalloc(1, sizeof(*RaMySQL))) == NULL)
         ArgusLog(LOG_ERR, "RaMySQLInit: ArgusCalloc error %s", strerror(errno));
 
   if ((mysql_init(RaMySQL)) == NULL)
      ArgusLog(LOG_ERR, "mysql_init error %s");

   if (!mysql_thread_safe())
      ArgusLog(LOG_INFO, "mysql not thread-safe");

   mysql_options(RaMySQL, MYSQL_READ_DEFAULT_GROUP, ArgusParser->ArgusProgramName);
   mysql_options(RaMySQL, MYSQL_OPT_RECONNECT, reconnect);

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaMySQLInit: connect %s %s %d\n", RaHost, RaUser, RaPort);
#endif

   if ((mysql_real_connect(RaMySQL, RaHost, RaUser, RaPass, NULL, RaPort, NULL, 0)) == NULL)
      ArgusLog(LOG_ERR, "mysql_connect error %s", mysql_error(RaMySQL));

   bzero(sbuf, sizeof(sbuf));
   sprintf (sbuf, "SHOW VARIABLES LIKE 'version'");

   if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         while ((row = mysql_fetch_row(mysqlRes))) {
            int matches = 0;
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");

           ArgusSQLVersion = strdup(sbuf);
           if ((matches = sscanf(ArgusSQLVersion,"%d.%d.%d", &MySQLVersionMajor, &MySQLVersionMinor, &MySQLVersionSub)) > 0) {
            }
         }
      }
      mysql_free_result(mysqlRes);
   }

   bzero(sbuf, sizeof(sbuf));
   sprintf (sbuf, "SHOW VARIABLES LIKE 'bulk_insert_buffer_size'");

   if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         while ((row = mysql_fetch_row(mysqlRes))) {
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");

           ArgusSQLBulkBufferSize = (int)strtol(sbuf, (char **)NULL, 10);
         }
      }
      mysql_free_result(mysqlRes);
   }

   bzero(sbuf, sizeof(sbuf));
   sprintf (sbuf, "SHOW VARIABLES LIKE 'max_allowed_packet'");

   if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         while ((row = mysql_fetch_row(mysqlRes))) {
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");
            
           ArgusSQLMaxPacketSize = (int)strtol(sbuf, (char **)NULL, 10);
         }
      }
      mysql_free_result(mysqlRes);
   }

   ArgusSQLBulkInsertSize = (ArgusSQLMaxPacketSize < ArgusSQLBulkBufferSize) ? ArgusSQLMaxPacketSize : ArgusSQLBulkBufferSize;

   if ((ArgusSQLBulkBuffer = calloc(1, ArgusSQLBulkInsertSize)) == NULL)
      ArgusLog(LOG_WARNING, "ArgusMySQLInit: cannot alloc bulk buffer size %d\n", ArgusSQLBulkInsertSize);

   bzero(sbuf, sizeof(sbuf));
   sprintf (sbuf, "CREATE DATABASE IF NOT EXISTS %s", RaDatabase);

   if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)  
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   sprintf (sbuf, "USE %s", RaDatabase);

   if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   if ((mysqlRes = mysql_list_tables(RaMySQL, NULL)) != NULL) {
      char sbuf[MAXSTRLEN];

      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         int thisIndex = 0;

         while ((row = mysql_fetch_row(mysqlRes))) {
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            bzero(sbuf, sizeof(sbuf));
               for (x = 0; x < retn; x++)
               sprintf(&sbuf[strlen(sbuf)], "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

            RaTableExistsNames[thisIndex++] = strdup (sbuf);
         }

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "mysql_num_fields() returned zero.\n");
#endif
      }
      mysql_free_result(mysqlRes);
   }

   if (ArgusParser->writeDbstr != NULL) {
      char *ptr;
      sprintf (ArgusParser->RaDBString, "-w %s", ArgusParser->writeDbstr);
      if ((ptr = strrchr(ArgusParser->writeDbstr, '/')) != NULL)
         *ptr = '\0';

   } else 
   if (ArgusParser->readDbstr != NULL) {
      char *ptr;
      sprintf (ArgusParser->RaDBString, "-r %s", ArgusParser->readDbstr);
      if ((ptr = strrchr(ArgusParser->readDbstr, '/')) != NULL)
         *ptr = '\0';
   } else  {
      sprintf (ArgusParser->RaDBString, "db %s", RaDatabase);

      if (RaHost)
         sprintf (&ArgusParser->RaDBString[strlen(ArgusParser->RaDBString)], "@%s", RaHost);

      sprintf (&ArgusParser->RaDBString[strlen(ArgusParser->RaDBString)], " user %s", RaUser);
   }
#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&RaMySQLlock);
#endif

   if ((ArgusParser->ArgusInputFileList != NULL)  ||
        (ArgusParser->ArgusRemoteHosts && (ArgusParser->ArgusRemoteHosts->count > 0))) {

      if (strlen(RaSQLSaveTable) > 0) {
         if (!((strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$'))))
            if (ArgusCreateSQLSaveTable(RaDatabase, RaSQLSaveTable))
               ArgusLog(LOG_ERR, "mysql create %s.%s returned error", RaDatabase, RaSQLSaveTable);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaMySQLInit () RaSource %s RaArchive %s RaFormat %s", RaSource, RaArchive, RaFormat);
#endif
}

/*
    So first look to see if the table already exists.
    If so and we're suppose to delete, then delete it.
    Then look to see if the name is in our list of default
    RaTableCreateNames[] to see if we need to remove it
    from that list, if we didn't catch the table in the
    other list.  At the end of this routine cindex is pointing 
    at the right place.
*/

extern int RaDaysInAMonth[12];

time_t ArgusTableStartSecs = 0;
time_t ArgusTableEndSecs = 0;

char *
ArgusCreateSQLSaveTableName (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, char *table)
{
   struct RaBinProcessStruct *RaBinProcess = parser->RaBinProcess;
   struct ArgusAdjustStruct *nadp = &RaBinProcess->nadp;
   char *retn = NULL;

   if (strchr(table, '%') || strchr(table, '$')) {
      int size = nadp->size / 1000000;
      long long start;
      time_t tableSecs;
      struct tm tmval;

      if (ns != NULL) 
         start = ArgusFetchStartuSecTime(ns);
      else 
         start = parser->ArgusRealTime.tv_sec * 1000000LL + parser->ArgusRealTime.tv_usec;
      
      tableSecs = start / 1000000;

      if (!(ArgusTableStartSecs) || !((tableSecs >= ArgusTableStartSecs) && (tableSecs < ArgusTableEndSecs))) {
         switch (nadp->qual) {
            case ARGUSSPLITYEAR:
            case ARGUSSPLITMONTH:
            case ARGUSSPLITWEEK: 
               gmtime_r(&tableSecs, &tmval);
               break;
         }

         switch (nadp->qual) {
            case ARGUSSPLITYEAR:
               tmval.tm_mon = 0;
            case ARGUSSPLITMONTH:
               tmval.tm_mday = 1;

            case ARGUSSPLITWEEK: 
               if (nadp->qual == ARGUSSPLITWEEK) {
                  if ((tmval.tm_mday - tmval.tm_wday) < 0) {
                     if (tmval.tm_mon == 0) {
                        if (tmval.tm_year != 0)
                           tmval.tm_year--;
                        tmval.tm_mon = 11;
                     } else {
                        tmval.tm_mon--;
                     }
                     tmval.tm_mday = RaDaysInAMonth[tmval.tm_mon];
                  }
                  tmval.tm_mday -= tmval.tm_wday;
               }

               tmval.tm_hour = 0;
               tmval.tm_min  = 0;
               tmval.tm_sec  = 0;
               tableSecs = timegm(&tmval);
               localtime_r(&tableSecs, &tmval);

#if defined(HAVE_TM_GMTOFF)
               tableSecs -= tmval.tm_gmtoff;
#endif
               break;

            case ARGUSSPLITDAY:
            case ARGUSSPLITHOUR:
            case ARGUSSPLITMINUTE:
            case ARGUSSPLITSECOND: {
               localtime_r(&tableSecs, &tmval);
#if defined(HAVE_TM_GMTOFF)
               tableSecs += tmval.tm_gmtoff;
#endif
               tableSecs = tableSecs / size;
               tableSecs = tableSecs * size;
#if defined(HAVE_TM_GMTOFF)
               tableSecs -= tmval.tm_gmtoff;
#endif
               break;
            }
         }

         localtime_r(&tableSecs, &tmval);

         if (strftime(ArgusSQLSaveTableNameBuf, MAXSTRLEN, table, &tmval) <= 0)
            ArgusLog (LOG_ERR, "ArgusCreateSQLSaveTableName () strftime %s\n", strerror(errno));

         RaProcessSplitOptions(ArgusParser, ArgusSQLSaveTableNameBuf, MAXSTRLEN, ns);
/* 
         if (strcmp(wfile->filename, ArgusSQLSaveTableNameBuf))
            ArgusInitNewFilename(ArgusParser, wfile, ArgusSQLSaveTableNameBuf);
*/
         ArgusTableStartSecs = tableSecs;

         switch (nadp->qual) {
            case ARGUSSPLITYEAR:  
               tmval.tm_year++;
               ArgusTableEndSecs = mktime(&tmval);
               break;
            case ARGUSSPLITMONTH:
               tmval.tm_mon++;
               ArgusTableEndSecs = mktime(&tmval);
               break;
            case ARGUSSPLITWEEK: 
            case ARGUSSPLITDAY: 
            case ARGUSSPLITHOUR: 
            case ARGUSSPLITMINUTE: 
            case ARGUSSPLITSECOND: 
               ArgusTableEndSecs = tableSecs + size;
               break;
         }
      }
/*
      if (tableSecs > ArgusSaveTableSeconds) {
         if (strftime(tmpbuf, 1024, table, localtime_r(&tSecs, &tmval)) <= 0)
            ArgusLog (LOG_ERR, "ArgusCreateSQLSaveTableName () strftime %s\n", strerror(errno));

         if (ArgusSaveTableSeconds < tableSecs)
            ArgusSaveTableSeconds = tableSecs;

         RaProcessSplitOptions(parser, tmpbuf, 1024, ns);
      }
*/
      retn = ArgusSQLSaveTableNameBuf;

   } else {
      bcopy(ArgusSQLSaveTableNameBuf, table, strlen(table));
      retn = ArgusSQLSaveTableNameBuf;
   }

   return (retn);
}


int
ArgusCreateSQLSaveTable(char *db, char *table)
{
   int retn = 0, cindex = 0, ind = 0, i, x, exists = 0;
   struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
   char stable[1024], sbuf[MAXSTRLEN], kbuf[MAXSTRLEN];
   MYSQL_RES *mysqlRes;

   sprintf (stable, "%s.%s", db, table);

   for (i = 0; i < RA_MAXTABLES; i++) {
      if (RaTableExistsNames[i] != NULL) {
         free (RaTableExistsNames[i]);
         RaTableExistsNames[i] = NULL;
      } else
         break;
   }

   bzero(sbuf, sizeof(sbuf));
   bzero(kbuf, sizeof(kbuf));

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&RaMySQLlock);
#endif

   if ((mysqlRes = mysql_list_tables(RaMySQL, NULL)) != NULL) {
      char sbuf[MAXSTRLEN];

      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         int thisIndex = 0;

         while ((row = mysql_fetch_row(mysqlRes))) {
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            bzero(sbuf, sizeof(sbuf));
            for (x = 0; x < retn; x++)
               sprintf(&sbuf[strlen(sbuf)], "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

            RaTableExistsNames[thisIndex++] = strdup (sbuf);
         }

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "mysql_num_fields() returned zero.\n");
#endif
      }
      mysql_free_result(mysqlRes);
   }

   for (i = 0; i < RA_MAXTABLES && !exists; i++) {
      if (RaTableExistsNames[i] != NULL) {
         if (!strcmp(RaTableExistsNames[i], table)) {
            if (ArgusDropTable) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "ArgusCreateSQLSaveTable: drop table %s\n", table);
#endif
               sprintf (sbuf, "DROP TABLE %s", table);
               if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
                  ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
            } else
               exists++;
            break;
         }
      } else
         break;
   }

   if (!exists) {
      RaTableCreateNames[cindex] = strdup(stable);

      sprintf (sbuf, "CREATE table %s (", RaTableCreateNames[cindex]);
      ind = 0;

      for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
         if (ArgusParser->RaPrintAlgorithmList[i] != NULL) {
            ArgusParser->RaPrintAlgorithm = ArgusParser->RaPrintAlgorithmList[i];

            if ((ArgusAutoId == 0) && !strncmp(ArgusParser->RaPrintAlgorithm->field, "autoid", 6))
               ArgusAutoId = 1;

            for (x = 0; x < ARGUS_MAX_PRINT_ALG; x++) {
               if (!strcmp(ArgusParser->RaPrintAlgorithm->field, RaPrintAlgorithmTable[x].field)) {
                  if (ind++ > 0)
                     sprintf (&sbuf[strlen(sbuf)], ",");

                  sprintf (&sbuf[strlen(sbuf)], "%s %s", RaPrintAlgorithmTable[x].field, RaPrintAlgorithmTable[x].dbformat);
                  break;
               }
            }
         }
      }

      if ((ArgusParser->ArgusAggregator != NULL) || ArgusAutoId) {
         struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;

         long long mask = 0;
         int status = 0;

         while (agg != NULL) {
            mask |= agg->mask;
            status |= agg->status;
            agg = agg->nxt;
         }

         if (mask || ArgusAutoId) {
            ind = 0;
            sprintf (kbuf, "primary key (");

            if (ArgusAutoId) {
               sprintf (&kbuf[strlen(kbuf)], "autoid");
               ind++;
            }

            if (mask) {
               for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
                  int found; 
                  if (mask & (0x01LL << i)) {
                     for (found = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                        if (ArgusParser->RaPrintAlgorithmList[x] != NULL) {
                           ArgusParser->RaPrintAlgorithm = ArgusParser->RaPrintAlgorithmList[x];
                           if (!strcmp(ArgusParser->RaPrintAlgorithm->field, ArgusMaskDefs[i].name)) {
                              found = 1;
                              break;
                           }
                        }
                     }

                     if (!found)
                        ArgusLog(LOG_ERR, "key field '%s' not in schema (-s option)",  ArgusMaskDefs[i].name);

                     for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                        if (!(strcasecmp (ArgusMaskDefs[i].name, RaPrintAlgorithmTable[x].field))) {
                           if (ind++ > 0)
                              sprintf (&kbuf[strlen(kbuf)], ",");

                           sprintf (&kbuf[strlen(kbuf)], "%s", RaPrintAlgorithmTable[x].field);
                           break;
                        }
                     }
                  }
               }
            }
            sprintf (&kbuf[strlen(kbuf)], ")");
         }
      }

      if (strlen(kbuf))
         sprintf (&sbuf[strlen(sbuf)], ", %s", kbuf);

      if (ArgusSOptionRecord)
         sprintf (&sbuf[strlen(sbuf)], ", record blob");

      if ((MySQLVersionMajor > 4) || ((MySQLVersionMajor == 4) &&
                                      (MySQLVersionMinor >= 1)))
         sprintf (&sbuf[strlen(sbuf)], ") ENGINE=%s", ArgusParser->MySQLDBEngine);
      else
         sprintf (&sbuf[strlen(sbuf)], ") TYPE=%s", ArgusParser->MySQLDBEngine);
      RaTableCreateString[cindex] = strdup(sbuf);

      cindex++;

      for (i = 0; i < cindex; i++) {
         char *str = NULL;
         if (RaTableCreateNames[i] != NULL) {
            if ((str = RaTableCreateString[i]) != NULL) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "ArgusCreateSQLSaveTable: %s\n", str);
#endif
               if ((retn = mysql_real_query(RaMySQL, str, strlen(str))) != 0)
                  ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));

               ArgusCreateTable = 1;
               RaSQLCurrentTable = strdup(stable);
            }
         }
      }

   } else {
      if (RaSQLCurrentTable == NULL)
         RaSQLCurrentTable = strdup(stable);
      retn = 0;
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&RaMySQLlock);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCreateSQLSaveTable (%s) returning", table, retn);
#endif
   return (retn);
}


void
RaMySQLDeleteRecords(struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{

#if defined(ARGUS_MYSQL)
   if (RaSQLUpdateDB && strlen(RaSQLSaveTable)) {
      char *sbuf = calloc(1, MAXBUFFERLEN);

      if (ns->htblhdr != NULL) {
         ArgusRemoveHashEntry(&ns->htblhdr);
         ns->htblhdr = NULL;
      }

      if (ns->hinthdr != NULL) {
         ArgusRemoveHashEntry(&ns->hinthdr);
         ns->hinthdr = NULL;
      }

      if (RaSQLDBDeletes)
         if (ArgusScheduleSQLQuery (ArgusParser, ArgusParser->ArgusAggregator, ns, sbuf, MAXBUFFERLEN, ARGUS_STOP) == NULL)
            ArgusLog(LOG_ERR, "RaMySQLDeleteRecords: ArgusScheduleSQLQuery error %s", strerror(errno));

      free(sbuf);
   }
#endif

   ArgusDeleteRecordStruct (parser, ns);

#ifdef ARGUSDEBUG
      ArgusDebug (4, "RaMySQLDeleteRecords (0x%x, 0x%x) done", parser, ns);
#endif
}


// We construct the mysql query here.
// Query can get big, so we have a real query, and a debug string representing the query.
// The structure of the query is 

// If we are inserting the record, ArgusSOptionRecord == 1, we need to generate a mysql escaped record.


char *
ArgusScheduleSQLQuery (struct ArgusParserStruct *parser, struct ArgusAggregatorStruct *agg, struct ArgusRecordStruct *ns, char *sbuf, int slen, int state)
{
   char *retn = sbuf, *rbuf = NULL;
   char tbuf[1024], fbuf[1024], ubuf[1024], *ptr, *tptr;
   char vbuf[1024], ibuf[1024];

   char   *mbuf = calloc(1, (ARGUS_MAXRECORDSIZE * 2) + 1);
   char *tmpbuf = calloc(1, MAXBUFFERLEN);

#ifdef ARGUSDEBUG
   char dbuf[MAXSTRLEN];
#endif
   struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs;
   struct ArgusSQLQueryStruct *sqry = NULL;
   struct ArgusRecord *argus = NULL;

   int y, len, ind = 0, mind = 0, iind = 0;
   int  nflag, found, uflag;

   nflag = parser->nflag;
   parser->nflag = 2;

   bzero(tbuf, sizeof(vbuf));
   bzero(fbuf, sizeof(fbuf));
   bzero(ubuf, sizeof(ubuf));
   bzero(vbuf, sizeof(vbuf));
   bzero(ibuf, sizeof(ibuf));

   if (ArgusSOptionRecord)
     rbuf = calloc(1, ARGUS_MAXRECORDSIZE);

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&parser->lock);
#endif

   for (parser->RaPrintIndex = 0; parser->RaPrintIndex < MAX_PRINT_ALG_TYPES; parser->RaPrintIndex++) {
      if (parser->RaPrintAlgorithmList[parser->RaPrintIndex] != NULL) {
         parser->RaPrintAlgorithm = parser->RaPrintAlgorithmList[parser->RaPrintIndex];

         if (strncmp(parser->RaPrintAlgorithm->field, "autoid", 6)) {
            int len = parser->RaPrintAlgorithm->length;
            len = (len > 256) ? len : 256;

            found = 0;
            bzero (tmpbuf, len + 1);

            if (agg && agg->mask) {
               for (y = 0; y < ARGUS_MAX_MASK_LIST; y++) {
                  if (agg->mask & (0x01LL << y)) {
                     if (!strcmp(parser->RaPrintAlgorithm->field, ArgusMaskDefs[y].name)) {
                        found++;
                     }
                  }
               }
            }

            if (ind++ > 0) {
               sprintf (&fbuf[strlen(fbuf)], ",");
               sprintf (&vbuf[strlen(vbuf)], ",");
            }

            if (found) {
               if (mind++ > 0)
                  sprintf (&ubuf[strlen(ubuf)], " and ");
            } else {
               if (iind++ > 0)
                  sprintf (&ibuf[strlen(ibuf)], ",");
            }

            uflag = ArgusParser->uflag;
            ArgusParser->uflag++;

            parser->RaPrintAlgorithm->print(parser, tmpbuf, ns, len);

            ArgusParser->uflag = uflag;

            if ((ptr = ArgusTrimString(tmpbuf)) != NULL) {
               snprintf (tbuf, 1024, "\"%s\"", ptr);
               tptr = &fbuf[strlen(fbuf)];
               sprintf (tptr, "%s", tbuf);

               snprintf (&vbuf[strlen(vbuf)], 1024, "%s", parser->RaPrintAlgorithm->field);
               snprintf (tbuf, 1024, "%s=\"%s\"", parser->RaPrintAlgorithm->field, ptr);

               if (found) {
                  tptr = &ubuf[strlen(ubuf)];
                  sprintf (tptr, "%s", tbuf);
               } else {
                  tptr = &ibuf[strlen(ibuf)];
                  sprintf (tptr, "%s", tbuf);
               }
            }
         }
      }
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&parser->lock);
#endif

   parser->nflag   = nflag;

   if (state != ARGUS_STOP) {
      len = 0;
      if (ArgusSOptionRecord) {
         int tlen;

         if ((argus = ArgusGenerateRecord (ns, 0L, rbuf)) == NULL)
            ArgusLog(LOG_ERR, "ArgusScheduleSQLQuery: ArgusGenerateRecord error %s", strerror(errno));
#ifdef _LITTLE_ENDIAN
         ArgusHtoN(argus);
#endif

         if ((tlen = ntohs(argus->hdr.len) * 4) < ARGUS_MAXRECORDSIZE) {
            if ((len = mysql_real_escape_string(RaMySQL, mbuf, (char *)argus, tlen)) <= 0)
               ArgusLog(LOG_ERR, "mysql_real_escape_string error %s", mysql_error(RaMySQL));
         }
      }

      if (len < (MAXBUFFERLEN - (strlen(ibuf) + strlen(ubuf)))) {
         if (!(ns->status & ARGUS_SQL_INSERT)) {
            if (ArgusSOptionRecord) {
               if (strlen(ibuf)) {
                  snprintf (sbuf, slen, "UPDATE %s SET %s,record=\"%s\" WHERE %s", RaSQLCurrentTable, ibuf, mbuf, ubuf);
#ifdef ARGUSDEBUG
                  snprintf (dbuf, MAXSTRLEN, "UPDATE %s SET %s,record=\"...\" WHERE %s", RaSQLCurrentTable, ibuf, ubuf);
#endif
               } else {
                  snprintf (sbuf, slen, "UPDATE %s SET record=\"%s\" WHERE %s", RaSQLCurrentTable, mbuf, ubuf);
#ifdef ARGUSDEBUG
                  snprintf (dbuf, MAXSTRLEN, "UPDATE %s SET record=\"...\" WHERE %s", RaSQLCurrentTable, ubuf);
#endif
               }
            } else {
               snprintf (sbuf, slen, "UPDATE %s SET %s WHERE %s", RaSQLCurrentTable, ibuf, ubuf);
#ifdef ARGUSDEBUG
               snprintf (dbuf, MAXSTRLEN, "%s", sbuf);
#endif
            }
            ns->status |= ARGUS_SQL_UPDATE;

         } else {
            if (ArgusSOptionRecord) {
               int tlen;
               snprintf (sbuf, slen, "INSERT INTO %s (%s,record) VALUES (%s,\"", RaSQLCurrentTable, vbuf, fbuf);
               tlen = strlen(sbuf);
               bcopy(mbuf, &sbuf[tlen], len + 1);
               tlen = strlen(sbuf);
               snprintf (&sbuf[tlen], slen - tlen, "\")");
#ifdef ARGUSDEBUG
               snprintf (dbuf, MAXSTRLEN, "INSERT INTO %s (%s,record) VALUES (%s,...)", RaSQLCurrentTable, vbuf, fbuf);
#endif

            } else {
               snprintf (sbuf, slen, "INSERT INTO %s (%s) VALUES (%s)", RaSQLCurrentTable, vbuf, fbuf);
#ifdef ARGUSDEBUG
               snprintf (dbuf, MAXSTRLEN, "%s", sbuf);
#endif
            }

#ifdef ARGUSDEBUG
            ArgusDebug (2, "ArgusScheduleSQLQuery (0x%x, 0x%x, 0x%x, %s, %d) done\n", parser, agg, ns, dbuf, state);
#endif
         }
      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusScheduleSQLQuery: query too large for allocated buffer\n", len);
#endif
      }

   } else {
      ns->status &= ~(ARGUS_SQL_STATUS);
      ns->status |= ARGUS_SQL_DELETE;

      snprintf (sbuf, slen, "DELETE FROM %s WHERE %s", RaSQLCurrentTable, ubuf);
#ifdef ARGUSDEBUG
      snprintf (dbuf, MAXSTRLEN, "%s", sbuf);
      ArgusDebug (2, "ArgusScheduleSQLQuery (0x%x, 0x%x, 0x%x, %s, %d) done\n", parser, agg, ns, dbuf, state);
#endif
   }

   ns->qhdr.logtime = ArgusParser->ArgusRealTime;

   if ((sqry = (void *) ArgusCalloc(1, sizeof(*sqry))) == NULL)
      ArgusLog(LOG_ERR, "ArgusScheduleSQLQuery: ArgusCalloc error %s", strerror(errno));

   sqry->tbl  = strdup(RaSQLCurrentTable);
   sqry->sptr = strdup(retn);
#ifdef ARGUSDEBUG
   sqry->dptr = strdup(dbuf);
#endif

   switch (ns->status & ARGUS_SQL_STATUS) {
      case ARGUS_SQL_INSERT:  
         ArgusPushBackList (ArgusSQLInsertQueryList, (struct ArgusListRecord *)&sqry->nxt, ARGUS_LOCK);
         pthread_cond_signal(&ArgusSQLInsertQueryList->cond);
         break;

      case ARGUS_SQL_UPDATE:  
         ArgusPushBackList (ArgusSQLUpdateQueryList, (struct ArgusListRecord *)&sqry->nxt, ARGUS_LOCK);
         pthread_cond_signal(&ArgusSQLUpdateQueryList->cond);
         break;
      case ARGUS_SQL_DELETE:  
         ArgusPushBackList (ArgusSQLSelectQueryList, (struct ArgusListRecord *)&sqry->nxt, ARGUS_LOCK);
         pthread_cond_signal(&ArgusSQLSelectQueryList->cond);
         break;
   }
   ns->status &= ~(ARGUS_SQL_STATUS);

   free(tmpbuf);
   free(mbuf);

   if (rbuf != NULL) free(rbuf);

   return (retn);
}


#endif
