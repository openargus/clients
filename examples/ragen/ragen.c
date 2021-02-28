/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2016 QoSient, LLC
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
 * $Id: //depot/gargoyle/clients/clients/ragen.c#20 $
 * $DateTime: 2016/11/30 00:54:11 $
 * $Change: 3245 $
 */

/*
 * ragen.c  - this is the argus record distribtion node.
 *    Acting just like a ra* program, supporting all the options
 *    and functions of ra(), and providing access to data, like
 *    argus, supporting remote filtering, and MAR record generation.
 *    This is an important workhorse for the argus architecture.
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <grp.h>
#include <pwd.h>

#if defined(HAVE_SYS_VFS_H)
#include <sys/vfs.h>
#else
#include <sys/param.h>
#include <sys/mount.h>
#endif

#include <argus_compat.h>
#include <argus_util.h>
#include <argus_sort.h>
#include <argus_output.h>
#include <argus_clientconfig.h>

#include <rabins.h>
#include <rasplit.h>
#include <ragen.h>

#if defined(HAVE_ZLIB_H)
#include <zlib.h>
#endif

#if defined(ARGUS_MYSQL)
#include <rasplit.h>

#include "rasql_common.h"
#include "argus_mysql.h"
#include <mysqld_error.h>

int argus_version = ARGUS_VERSION;

char *RaDatabase = NULL;
char *RaTable = NULL;

struct RaBinProcessStruct *RaBinProcess = NULL;
char **RaTables = NULL;
char ArgusSQLStatement[MAXSTRLEN];

int ArgusReadSQLTables (struct ArgusParserStruct *);
int ArgusCreateSQLSaveTable(char *);
char *ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, int);
void RaMySQLDeleteRecords(struct ArgusParserStruct *, struct ArgusRecordStruct *);

void RaSQLProcessQueue (struct ArgusQueueStruct *);

void RaSQLQueryNetworksTable (unsigned int, unsigned int, unsigned int);
void RaSQLQueryProbes (void);
void RaSQLQuerySecondsTable (unsigned int, unsigned int);
void RaSQLQueryDatabaseTable (char *, unsigned int, unsigned int);

int RaInitialized = 0;
int ArgusAutoId = 0;
int ArgusDropTable = 0;
int ArgusCreateTable = 0;

char *RaProgramPath = RABINPATH;
char *RaRoleString = NULL;
char *RaProbeString = NULL;
char *RaSQLSaveTable = NULL;
char *RaSQLCurrentTable = NULL;

struct timeval ArgusLastRealTime     = {0, 0};
struct timeval ArgusLastTime         = {0, 0};
struct timeval ArgusThisTime         = {0, 0};
struct timeval ArgusCurrentTime      = {0, 0};
 
char ArgusSQLSaveTableNameBuf[MAXSTRLEN];
struct tm ArgusSaveTableTmStruct;
time_t ArgusSaveTableSeconds = 0;
 
struct timeval dLastTime = {0, 0};
struct timeval dRealTime = {0, 0};
struct timeval dThisTime = {0, 0};
struct timeval dTime     = {0, 0};
 
long long thisUsec = 0;
long long lastUsec = 0;
 
struct ArgusQueueStruct *ArgusModelerQueue;
struct ArgusQueueStruct *ArgusFileQueue;
struct ArgusQueueStruct *ArgusProbeQueue;
 
char ArgusArchiveBuf[4098];
 
#define RAMON_NETS_CLASSA	0
#define RAMON_NETS_CLASSB	1
#define RAMON_NETS_CLASSC	2
#define RAMON_NETS_CLASS	3

#define RA_MINTABLES            128
#define RA_MAXTABLES            0x10000
unsigned int RaTableFlags = 0;
 
char       *RaTableValues[256];
char  *RaTableExistsNames[RA_MAXTABLES];
char  *RaTableCreateNames[RA_MINTABLES];
char *RaTableCreateString[RA_MINTABLES];
char *RaTableDeleteString[RA_MINTABLES];

#define ARGUSSQLMAXQUERYTIMESPAN	300
#define ARGUSSQLMAXCOLUMNS		256
#define ARGUSSQLMAXROWNUMBER		0x80000

char *ArgusTableColumnName[ARGUSSQLMAXCOLUMNS];

char ArgusSQLTableNameBuf[MAXSTRLEN];

char *RaSource         = NULL;
char *RaArchive        = NULL;
char *RaLocalArchive   = NULL;
char *RaFormat         = NULL;

extern char *RaTable;

int   RaStatus         = 1;
int   RaPeriod         = 1;
int   RaSQLMaxSeconds  = 0;

int ArgusSQLSecondsTable = 0;
int ArgusSQLBulkInsertSize = 0;
int ArgusSQLMaxPacketSize = 0;
int ArgusSQLBulkBufferSize = 0;
int ArgusSQLBulkBufferIndex = 0;
char *ArgusSQLBulkLastTable = NULL;
char *ArgusSQLBulkBuffer = NULL;
char *ArgusSQLVersion = NULL;
int MySQLVersionMajor = 0;
int MySQLVersionMinor = 0;
int MySQLVersionSub = 0;

time_t ArgusTableStartSecs = 0;
time_t ArgusTableEndSecs = 0;

extern int ArgusSOptionRecord;
int ArgusDeleteTable = 0;

char RaLocalArchBuf[MAXSTRLEN];

extern char *RaRemoteFilter;
extern char RaFilterSQLStatement[];
  
char *RaHost = NULL, *RaUser = NULL, *RaPass = NULL;
int RaPort = 0;
struct ArgusInput *ArgusInput = NULL;
void RaMySQLInit (void);

/* Do not try to create a database.  Allows read-only operations
 * with fewer database permissions.
 */
static int RaSQLNoCreate = 0;

MYSQL_ROW row;
MYSQL mysql, *RaMySQL = NULL;

struct RaMySQLFileStruct {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   unsigned int fileindex;
   unsigned int second;
   char *filename;
   int ostart, ostop;
};

#define RAMYSQL_SECONDTABLE_PROBE       0
#define RAMYSQL_SECONDTABLE_SECOND      1
#define RAMYSQL_SECONDTABLE_FILEINDEX   2
#define RAMYSQL_SECONDTABLE_OSTART      3
#define RAMYSQL_SECONDTABLE_OSTOP       4

struct RaMySQLSecondsTable {
   struct ArgusQueueHeader qhdr;
   unsigned int fileindex;
   char *filename;
   unsigned int probe;
   unsigned int second;
   int ostart, ostop;
};

#define RAMYSQL_PROBETABLE_PROBE        0
#define RAMYSQL_PROBETABLE_NAME         1

struct RaMySQLProbeTable {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   char *name;
};

#endif

#if defined(HAVE_UUID_UUID_H)
#include <uuid/uuid.h>
#else
#if defined(HAVE_UUID_H)
#include <uuid.h>
#endif
#endif

#define ARGUSMAXCLIENTCOMMANDS         7
#define RAGEN_START                    0
#define RAGEN_DONE                     1
#define RAGEN_FILTER                   2
#define RAGEN_MODEL                    3
#define RAGEN_PROJECT                  4
#define RAGEN_FILE                     5
#define RAGEN_GEN                      6

char *RaGenClientCommands[ARGUSMAXCLIENTCOMMANDS] =
{
   "START:",
   "DONE:",
   "FILTER:",
   "MODEL:",
   "PROJECT:",
   "FILE:",
   "GEN:",
};


#define RAGEN_MAX_ANALYTICS    128
struct ArgusRecordStruct *(*RaGenAnalyticAlgorithmTable[RAGEN_MAX_ANALYTICS])(struct ArgusParserStruct *, struct ArgusRecordStruct *) = {
   NULL, NULL, NULL
};
                                                                                                                           
void RaGenSendFile (struct ArgusOutputStruct *, struct ArgusClientData *, char *, int);
int RaGenParseSourceID (struct ArgusAddrStruct *, char *);
int RaGenParseSrcidConversionFile (char *);

static int RaGenMinSsf = 0;
static int RaGenMaxSsf = 0;
static int RaGenAuthLocalhost = 1;

static struct timeval RabinsTimeoutAbs; 
static int RabinsOldestIndex = 0;

static double RaCurrentBinStartTime = 0;
static double RaCurrentBinLastTime = 0;

void clearRaGenConfiguration (void);
//const static unsigned int ArgusClientMaxQueueDepth = 500000;

extern char *chroot_dir;
extern uid_t new_uid;
extern gid_t new_gid;

void ArgusSetChroot(char *);

#define RAGEN_RCITEMS                          28

#define RAGEN_MONITOR_ID                       0
#define RAGEN_MONITOR_ID_INCLUDE_INF		1
#define RAGEN_ARGUS_SERVER                     2
#define RAGEN_ARGUS_CLIENT			3
#define RAGEN_DAEMON                           4
#define RAGEN_CISCONETFLOW_PORT                5
#define RAGEN_ACCESS_PORT                      6
#define RAGEN_INPUT_FILE                       7
#define RAGEN_USER_AUTH                        8
#define RAGEN_AUTH_PASS                        9
#define RAGEN_OUTPUT_FILE                      10
#define RAGEN_OUTPUT_STREAM                    11
#define RAGEN_MAR_STATUS_INTERVAL              12
#define RAGEN_DEBUG_LEVEL                      13
#define RAGEN_FILTER_OPTIMIZER                 14
#define RAGEN_FILTER_TAG                       15
#define RAGEN_BIND_IP                          16
#define RAGEN_MIN_SSF                          17
#define RAGEN_MAX_SSF                          18
#define RAGEN_ADJUST_TIME                      19
#define RAGEN_CHROOT_DIR                       20
#define RAGEN_SETUSER_ID                       21
#define RAGEN_SETGROUP_ID                      22
#define RAGEN_CLASSIFIER_FILE                  23
#define RAGEN_ZEROCONF_REGISTER                24
#define RAGEN_V3_ACCESS_PORT                   25
#define RAGEN_SRCID_CONVERSION_FILE            26
#define RAGEN_AUTH_LOCALHOST                   27

char *RaGenResourceFileStr [] = {
   "RAGEN_MONITOR_ID=",
   "RAGEN_MONITOR_ID_INCLUDE_INF=",
   "RAGEN_ARGUS_SERVER=",
   "RAGEN_ARGUS_CLIENT=",
   "RAGEN_DAEMON=",
   "RAGEN_CISCONETFLOW_PORT=",
   "RAGEN_ACCESS_PORT=",
   "RAGEN_INPUT_FILE=",
   "RAGEN_USER_AUTH=",
   "RAGEN_AUTH_PASS=",
   "RAGEN_OUTPUT_FILE=",
   "RAGEN_OUTPUT_STREAM=",
   "RAGEN_MAR_STATUS_INTERVAL=",
   "RAGEN_DEBUG_LEVEL=",
   "RAGEN_FILTER_OPTIMIZER=",
   "RAGEN_FILTER=",
   "RAGEN_BIND_IP=",
   "RAGEN_MIN_SSF=",
   "RAGEN_MAX_SSF=",
   "RAGEN_ADJUST_TIME=",
   "RAGEN_CHROOT_DIR=",
   "RAGEN_SETUSER_ID=",
   "RAGEN_SETGROUP_ID=",
   "RAGEN_CLASSIFIER_FILE=",
   "RAGEN_ZEROCONF_REGISTER=",
   "RAGEN_V3_ACCESS_PORT=",
   "RAGEN_SRCID_CONVERSION_FILE=",
   "RAGEN_AUTH_LOCALHOST=",
};


void ArgusGenerateStatusRecords(struct ArgusGenerator *);
void *ArgusProcessStatusRecords(void *);
void ArgusStartGenerator(struct ArgusGenerator *);
void ArgusStopGenerator(struct ArgusGenerator *);

static int RaGenParseResourceLine (struct ArgusParserStruct *, int, char *, int, int);
struct ArgusListStruct *ArgusGeneratorList = NULL;
struct ArgusGenerator *ArgusNewGenerator (struct ArgusParserStruct *, struct ArgusClientData *, struct ArgusOutputStruct *, char *);


// ArgusNewGenerator - this routine creates the complete environment for an argus generator.
//      An argus generator is a baseline set of flow that output as bins (ala rabins.1 logic).
//      A generator configuration provides the baseline as a file or sql table, a starting time,
//      an interval (rabins -M time interval value) and a duration.
//      
//      The concept is that the generator is a complete environment, containing parser, inputs,
//      outputs, and in this case a RaBinsProcess ...
//      
//      rabins.1 is not really structured for this task, as it takes in flows and carves them
//      up completely for processing bins that then are processed as a whole.
//      
//      ragen.1 would like to process a large number of baseline flows, but process and output
//      flow 1 bin at a time, so that we generate a realtime output stream.
//

struct ArgusGenerator *
ArgusNewGenerator (struct ArgusParserStruct *parser, struct ArgusClientData *client, struct ArgusOutputStruct *output, char *ptr)
{
   time_t tsec = ArgusParser->ArgusRealTime.tv_sec;
   struct ArgusGenerator *gen = NULL, *tgen = NULL;
   struct ArgusAdjustStruct nadpbuf, *nadp = &nadpbuf;
   struct ArgusQueueStruct *queue;
   struct ArgusGenConfig *config;
   struct tm tmbuf, *tm = &tmbuf;
   char *file = NULL, *sptr, *str = strdup(ptr);
   int i, cnt;

   if ((config = ArgusCalloc (1, sizeof(*config))) == NULL) 
      ArgusLog (LOG_ERR, "%s: ArgusCalloc failed\n", __func__);
   
   sptr = str;
   while (isspace((int)*sptr)) sptr++;
   bzero(&tmbuf, sizeof(tmbuf));

   while ((optarg = strtok(sptr, ";")) != NULL) {
      char *key, *value, *dptr;
      if ((dptr = strchr(optarg, '=')) != NULL) {
         key = optarg;
         *dptr++ = '\0';
         value = dptr;
      }
      if (strcasecmp(key, "baseline") == 0) {
         config->baseline = strdup(value);
      } else if ((strcasecmp(key, "startime") == 0) || (strcasecmp(key, "stime") == 0)) {
         if (!(strcasecmp(value, "now"))) 
            bcopy (&parser->RaTmStruct, tm, sizeof(*tm));
	 
      } else if (strcasecmp(key, "interval") == 0) {
         config->interval = strdup(value);
      } else if (strcasecmp(key, "dur") == 0) {
         config->duration = atof(value);
      }
      sptr = NULL;
   }

   if (parser->startime_t.tv_sec > 0) {
      if (config->duration > 0) {
         parser->lasttime_t.tv_sec = parser->startime_t.tv_sec + config->duration;
      }
   }

   bzero(nadp, sizeof(*nadp));

   if (strlen(config->interval) > 0) {
      if (ArgusParser->tflag)
         tsec = parser->startime_t.tv_sec;

      nadp->mode = ARGUSSPLITTIME;
      nadp->modify = 1;

      if (isdigit((int)*config->interval)) {
         char *ptr = NULL;
         nadp->value = strtod(config->interval, (char **)&ptr);

         switch (*ptr) {
            case 'y':
               nadp->qual = ARGUSSPLITYEAR;  
               localtime_r(&tsec, &nadp->RaStartTmStruct);
               nadp->RaStartTmStruct.tm_sec = 0;
               nadp->RaStartTmStruct.tm_min = 0;
               nadp->RaStartTmStruct.tm_hour = 0;
               nadp->RaStartTmStruct.tm_mday = 1;
               nadp->RaStartTmStruct.tm_mon = 0;
               tsec= mktime(&nadp->RaStartTmStruct);
               nadp->size = nadp->value*3600.0*24.0*7.0*52.0*1000000LL;
               break;

            case 'M':
               nadp->qual = ARGUSSPLITMONTH; 
               localtime_r(&tsec, &nadp->RaStartTmStruct);
               nadp->RaStartTmStruct.tm_sec = 0;
               nadp->RaStartTmStruct.tm_min = 0;
               nadp->RaStartTmStruct.tm_hour = 0;
               nadp->RaStartTmStruct.tm_mday = 1;
               nadp->RaStartTmStruct.tm_mon = 0;
               tsec = mktime(&nadp->RaStartTmStruct);
               nadp->size = nadp->value*3600.0*24.0*7.0*4.0*1000000LL;
               break;

            case 'w':
               nadp->qual = ARGUSSPLITWEEK;  
               localtime_r(&tsec, &nadp->RaStartTmStruct);
               nadp->RaStartTmStruct.tm_sec = 0;
               nadp->RaStartTmStruct.tm_min = 0;
               nadp->RaStartTmStruct.tm_hour = 0;
               nadp->RaStartTmStruct.tm_mday = 1;
               nadp->RaStartTmStruct.tm_mon = 0;
               tsec = mktime(&nadp->RaStartTmStruct);
               nadp->size = nadp->value*3600.0*24.0*7.0*1000000LL;
               break;

            case 'd':
               nadp->qual = ARGUSSPLITDAY;   
               localtime_r(&tsec, &nadp->RaStartTmStruct);
               nadp->RaStartTmStruct.tm_sec = 0;
               nadp->RaStartTmStruct.tm_min = 0;
               nadp->RaStartTmStruct.tm_hour = 0;
               tsec = mktime(&nadp->RaStartTmStruct);
               nadp->size = nadp->value*3600.0*24.0*1000000LL;
               break;

            case 'h':
               nadp->qual = ARGUSSPLITHOUR;  
               localtime_r(&tsec, &nadp->RaStartTmStruct);
               nadp->RaStartTmStruct.tm_sec = 0;
               nadp->RaStartTmStruct.tm_min = 0;
               tsec = mktime(&nadp->RaStartTmStruct);
               nadp->size = nadp->value*3600.0*1000000LL;
               break;

            case 'm': {
               nadp->qual = ARGUSSPLITMINUTE;
               localtime_r(&tsec, &nadp->RaStartTmStruct);
               nadp->RaStartTmStruct.tm_sec = 0;
               tsec = nadp->value*60.0*1000000LL;
               nadp->size = tsec;
               break;
            }

            default: 
            case 's': {
               long long val = tsec / nadp->value;
               nadp->qual = ARGUSSPLITSECOND;
               tsec = val * nadp->value;
               localtime_r(&tsec, &nadp->RaStartTmStruct);
               nadp->start.tv_sec = tsec;
               nadp->size = nadp->value * 1000000LL;
               break;
            }
         }
      }
   }

   if (config->duration > 0) {
      parser->startime_t = nadp->start;
      parser->lasttime_t.tv_sec = parser->startime_t.tv_sec + config->duration;
      nadp->end = parser->lasttime_t;
      localtime_r(&parser->lasttime_t.tv_sec, &nadp->RaEndTmStruct);
   }

   if ((file = config->baseline) != NULL) {
      if ((file = realpath (file, NULL)) != NULL) {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusNewGenerator(%p, %p) sending file %s\n", parser, client, file);
#endif
         config->baseline = strdup(file);
      }
   }

   if ((cnt = ArgusGeneratorList->count) > 0) {
#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&ArgusGeneratorList->lock);
#endif

      for (i = 0; i < cnt; i++) {
         if ((tgen = (struct ArgusGenerator *)ArgusPopFrontList(ArgusGeneratorList, ARGUS_NOLOCK)) != NULL) {
            if (tgen->client == client)
               gen = tgen;
            ArgusPushBackList(ArgusGeneratorList, (struct ArgusListRecord *) tgen, ARGUS_NOLOCK);
         }
      }
#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&ArgusGeneratorList->lock);
#endif
   }

   if (gen == NULL) {
      if ((gen = ArgusCalloc (1, sizeof(*gen))) == NULL)
         ArgusLog (LOG_ERR, "%s: ArgusCalloc failed\n", __func__);

      gen->queue = ArgusNewQueue();
      gen->configs = ArgusNewQueue();
      gen->parser = ArgusNewParser(parser->ArgusProgramName);
      bcopy(ArgusParser, gen->parser, sizeof(*ArgusParser));

      if ((gen->bins = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*gen->bins))) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

      if ((gen->bins->array = (void *)ArgusCalloc(4, sizeof(void *))) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

      bcopy(nadp, &gen->bins->nadp, sizeof(*nadp));
      gen->bins->size  = nadp->size;

      gen->bins->start = (nadp->start.tv_sec * 1000000LL) + nadp->start.tv_usec;
      gen->bins->end   = (nadp->end.tv_sec * 1000000LL) + nadp->end.tv_usec;

#if defined(ARGUS_THREADS)
      pthread_mutex_init(&gen->bins->lock, NULL);
#endif
      gen->bins->scalesecs = 0;

      if ((gen->parser->ArgusAggregator = ArgusNewAggregator(gen->parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      gen->parser->ProcessRealTime = 0;
      gen->client = client;
      gen->output = output;
      gen->parser->ArgusOutput =  gen->output;

      if (!(ArgusPushBackList (ArgusGeneratorList, (struct ArgusListRecord *) gen, ARGUS_LOCK)))
         ArgusLog(LOG_ERR, "ArgusNewGenerator: error: file arg %s", file);
   }

   config->gen = gen;
   if ((queue = gen->configs) != NULL)
      ArgusAddToQueue(queue, &config->qhdr, ARGUS_LOCK);
   free(str);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusNewGenerator(%p, %p, %p, '%s') returns %d\n", parser, client, output, ptr, gen);
#endif

   return (gen);
}

int ArgusDeleteGenerator(struct ArgusGenerator *);

int
ArgusDeleteGenerator(struct ArgusGenerator *gen)
{
   struct ArgusQueueStruct *queue = gen->configs;
   struct ArgusParserStruct *parser = gen->parser;
   int retn = 0;

   if (queue && queue->count) {
      struct ArgusGenConfig *config;
      int i, cnt = queue->count;

      for (i = 0; i < cnt; i++) {
         if ((config = (struct ArgusGenConfig *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
            if (config->status & ARGUS_START) {
               if (config->tid && (config->status & ARGUS_STOP))
                  pthread_join(config->tid, NULL);
#ifdef ARGUSDEBUG
               ArgusDebug (1, "ArgusDeleteGenerator(%p) baseline %s\n", gen, config->baseline); 
#endif
               if (config->baseline != NULL)
                  free (config->baseline);

               if (gen->status & ARGUS_START) {
/*
                  if (config->finput->file != NULL) {
                     fclose(config->finput->file);
                     config->finput->file = NULL;
                  }
*/
               }
               if (config->finput->fd)
                  close(config->finput->fd);

               if (config->finput->tempfile != NULL) {
                  unlink(config->finput->tempfile);
                  free(config->finput->tempfile);
               }
            }
         }
      }
   }

   ArgusFree(parser);
   ArgusFree(gen);
   return (retn);
}


static int
RaGenParseClientMessage (struct ArgusParserStruct *parser, void *o, void *c, char *ptr)
{
   struct ArgusOutputStruct *output = (struct ArgusOutputStruct *)o;
   struct ArgusClientData *client = (struct ArgusClientData *) c;
   struct ArgusGenerator *gen;

   int fd = client->fd, slen = 0;
   int i, cnt, retn = 1, found;
   char *reply;

   for (i = 0, found = 0; (i < ARGUSMAXCLIENTCOMMANDS) && !found; i++) {
         if (RaGenClientCommands[i] != NULL) {
            if (!(strncmp (ptr, RaGenClientCommands[i], strlen(RaGenClientCommands[i])))) {
               found++;
               switch (i) {
                  case RAGEN_START: {
                     int slen = strlen(RaGenClientCommands[i]);
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

                  case RAGEN_DONE:  {
                     if (client->hostname != NULL)
                        ArgusLog (LOG_INFO, "RaGenParseClientMessage: client %s sent DONE", client->hostname);
                     else
                        ArgusLog (LOG_INFO, "RaGenParseClientMessage: received DONE");

                     if ((cnt = ArgusGeneratorList->count) > 0) {
#if defined(ARGUS_THREADS)
                        pthread_mutex_lock(&ArgusGeneratorList->lock);
#endif

                        /* Get the queue length down to the max.  The addition below
                         * will push it back over the max length and ArgusWriteOutSocket()
                         * can later determine if it needs to hang up the connection.
                         */
                        for (i = 0; i < cnt; i++) {
                           struct ArgusGenerator *gen;

                           if ((gen = (struct ArgusGenerator *)ArgusPopFrontList(ArgusGeneratorList, ARGUS_NOLOCK)) != NULL) {
                              if (gen->client == client) {
                                 ArgusStopGenerator(gen);
                              }
                              ArgusPushBackList(ArgusGeneratorList, (struct ArgusListRecord *) gen, ARGUS_NOLOCK);
                           }
                        }

#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&ArgusGeneratorList->lock);
#endif
                     }
                     retn = -4;
                     break; 
                  }

                  case RAGEN_FILTER: {
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

                  case RAGEN_PROJECT: 
                  case RAGEN_MODEL: 
                     break;

                  case RAGEN_FILE: {
                     char *file = &ptr[6];
#ifdef ARGUSDEBUG
                     ArgusDebug (3, "ArgusCheckClientMessage: ArgusFile %s requested.\n", file);
#endif
                     ArgusSendFile (output, client, file, 0);
                     retn = 5;
                     break;
                  }

/*
		This is the key to ragen.1 ... get a request to send generated traffic from this client.
		A generator is a thread that has its own parser and input(s) and writes out to the
                specific output that the request came from.

                Currently, ragen.1 will take the configuration, generate a source file that contains
                the requested records, read the file, and then write the data for realtime output. 
                This compels the approach to have a dedicated ArgusParserStruct and ArgusInput structures.

                When the client exits, we need to delete the generator correctl ...
*/

                  case RAGEN_GEN: {
                     if ((gen = ArgusNewGenerator(parser, client, output, &ptr[4])) != NULL) {
                        client->ArgusGeneratorInitialized++;
                        reply = "OK";
                        retn = 1;
                     } else {
                        reply = "FAIL";
                        retn = 0;
                     }

                     slen = strlen(reply);
                     if ((cnt = send (fd, reply, slen, 0)) != slen) {
                        retn = -3;
#ifdef ARGUSDEBUG
                        ArgusDebug (3, "RaGenParseClientMessage: send error %s\n", strerror(errno));
#endif
                     } else {
#ifdef ARGUSDEBUG
                        ArgusDebug (3, "RaGenParseClientMessage: ArgusGeneratorConfiguration processed.\n");
#endif
                     }
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


#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaGenParseClientMessage(%p, %p, %p, '%s') returns %d\n", parser, o, c, ptr, retn);
#endif

   return (retn);
}

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode;
   FILE *tmpfile = NULL;
   struct timeval *tvp;
   int pid, dflag;
#if defined(ARGUS_THREADS)
   sigset_t blocked_signals;
#endif /* ARGUS_THREADS */

   parser->RaWriteOut = 1;
   parser->ArgusReverse = 1;
   parser->ArgusTimeoutThread = 1;

   parser->ArgusParseClientMessage = RaGenParseClientMessage;

   if (!(parser->RaInitialized)) {
      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "zeroconf", 8)))
               parser->ArgusZeroConf = 1;
            mode = mode->nxt;
         }
      }

      dflag = parser->dflag;
      parser->dflag = 0;

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if ((ArgusGeneratorList = ArgusNewList()) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewList error");

      if ((ArgusSorter = ArgusNewSorter(parser)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewSorter error %s", strerror(errno));

      bzero (ArgusSorter->ArgusSortAlgorithms, sizeof (ArgusSorter->ArgusSortAlgorithms));
      ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortStartTime;

      if (parser->ArgusFlowModelFile != NULL) {
         RaParseResourceFile (parser, parser->ArgusFlowModelFile,
                              ARGUS_SOPTIONS_IGNORE, RaGenResourceFileStr,
                              RAGEN_RCITEMS, RaGenParseResourceLine);
      } else {
         if (!(parser->Xflag)) {
            RaParseResourceFile (parser, "/etc/ragen.conf",
                                 ARGUS_SOPTIONS_IGNORE, RaGenResourceFileStr,
                                 RAGEN_RCITEMS, RaGenParseResourceLine);
         }
      }

      parser->dflag = (parser->dflag) ? (dflag ? 0 : 1) : dflag;

      if (parser->dflag) {
         pid_t parent = getppid();

         if (parent != 1) {
            if ((pid = fork ()) < 0) {
               ArgusLog (LOG_ERR, "Can't fork daemon %s", strerror(errno));
            } else {
               if (pid) {
                  struct timespec ts = {0, 500000000};
                  int status;

                  nanosleep(&ts, NULL);
                  waitpid(pid, &status, WNOHANG);
                  if (kill(pid, 0) < 0) {
                     exit (1);
                  } else
                     exit (0);

               } else {
                  if (chdir ("/") < 0)
                     ArgusLog (LOG_ERR, "Can't chdir to / %s", strerror(errno));

                  if ((parser->ArgusSessionId = setsid()) < 0)
                     ArgusLog (LOG_ERR, "setsid error %s", strerror(errno));

                  umask(0);
    
                  ArgusLog(LOG_INFO, "started");

                  if ((tmpfile = freopen ("/dev/null", "r", stdin)) == NULL)
                     ArgusLog (LOG_ERR, "Cannot map stdout to /dev/null");

                  if ((tmpfile = freopen ("/dev/null", "a+", stdout)) == NULL)
                     ArgusLog (LOG_ERR, "Cannot map stdout to /dev/null");
    
                  if ((tmpfile = freopen ("/dev/null", "a+", stderr)) == NULL)
                     ArgusLog (LOG_ERR, "Cannot map stderr to /dev/null");
               }
            }
         }
      }

      if (chroot_dir != NULL)
         ArgusSetChroot(chroot_dir);
 
      if (new_gid > 0) {
         if (setgid(new_gid) < 0)
            ArgusLog (LOG_ERR, "ArgusClientInit: setgid error %s", strerror(errno));
      }

      if (new_uid > 0) {
         if (setuid(new_uid) < 0)
            ArgusLog (LOG_ERR, "ArgusClientInit: setuid error %s", strerror(errno));
      }

/*
   This is the basic new argus() strategy for processing output
   records.  The thread will do two basic things: 
      1) it will grab stuff off the queue, and then do the basic
         processing that this ragen will do, such as time
         adjustment, aggregation, correction, and anonymization, etc...

      2) it will establish the permanent and non-argus outputs
         from the configuration file.

      3) it will manage the listen, to deal without remote argus
         requests.  ragen() can write its records to a file, and
         any number of remote clients, so ......

   The ArgusClientTimeout() routine will drive all the maintenance
   and so it should be run, probably 4x a second, just for good
   measure.

*/
      parser->ArgusReliableConnection++;

      parser->RaClientTimeout.tv_sec  = 0;
      parser->RaClientTimeout.tv_usec = 250000;

      tvp = getArgusMarReportInterval(ArgusParser);
      if ((tvp->tv_sec == 0) && (tvp->tv_usec == 0)) {
         setArgusMarReportInterval (ArgusParser, "5s");
      }

      if ((parser->ArgusOutput = ArgusNewOutput(parser, RaGenMinSsf, RaGenMaxSsf, RaGenAuthLocalhost)) == NULL)
         ArgusLog (LOG_ERR, "could not create output: %s\n", strerror(errno));

      /* Need valid parser->ArgusOutput before starting listener */
      if (parser->ArgusPortNum != 0) {
         if (ArgusEstablishListen (parser, parser->ArgusOutput,
                                   parser->ArgusPortNum, parser->ArgusBindAddr,
                                   ARGUS_VERSION) < 0)
            ArgusLog (LOG_ERR, "setArgusPortNum: ArgusEstablishListen returned %s", strerror(errno));
      }
      if (parser->ArgusV3Port != 0) {
         if (ArgusEstablishListen (parser, parser->ArgusOutput,
                                   parser->ArgusV3Port, parser->ArgusBindAddr,
                                   ARGUS_VERSION_3) < 0)
            ArgusLog (LOG_ERR, "%s: ArgusEstablishListen returned %s",
                      __func__, strerror(errno));
      }

#if defined(ARGUS_THREADS)
      sigemptyset(&blocked_signals);
      pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);
#endif
      (void) signal (SIGHUP,  (void (*)(int)) ArgusShutDown);
      (void) signal (SIGTERM, (void (*)(int)) ArgusShutDown);
      (void) signal (SIGQUIT, (void (*)(int)) ArgusShutDown);
      (void) signal (SIGINT,  (void (*)(int)) ArgusShutDown);

      (void) signal (SIGPIPE, SIG_IGN);
      (void) signal (SIGTSTP, SIG_IGN);
      (void) signal (SIGTTOU, SIG_IGN);
      (void) signal (SIGTTIN, SIG_IGN);

      parser->Sflag++;
      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input)
{

};

void
RaParseComplete (int sig)
{
   struct ArgusRecordStruct *rec = NULL;
   int i, cnt = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaParseComplete(%d) Starting\n", sig);
#endif

   if (!ArgusParser->RaParseCompleting) {
      ArgusParser->RaParseCompleting++;
      ArgusParser->RaParseDone++;

      if (ArgusParser->ArgusActiveHosts != NULL) {
         struct ArgusQueueStruct *queue =  ArgusParser->ArgusActiveHosts;
         struct ArgusInput *input = NULL;

         while (queue->count > 0) {
            if ((input = (struct ArgusInput *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
//             ArgusCloseInput(ArgusParser, input);
               if (input->hostname != NULL)
                  free (input->hostname);
               if (input->filename != NULL)
                  free (input->filename);
#if defined(HAVE_GETADDRINFO)
               if (input->host != NULL)
                  freeaddrinfo (input->host);
#endif
               ArgusFree(input);
            }
         }
         ArgusDeleteQueue(queue);
         ArgusParser->ArgusActiveHosts = NULL;
      }

      if ((cnt = ArgusGeneratorList->count) > 0) {
#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&ArgusGeneratorList->lock);
#endif
         for (i = 0; i < cnt; i++) {
            struct ArgusGenerator *gen;

            if ((gen = (struct ArgusGenerator *)ArgusPopFrontList(ArgusGeneratorList, ARGUS_NOLOCK)) != NULL) {
               ArgusDeleteGenerator(gen);
            }
         }

#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&ArgusGeneratorList->lock);
#endif
      }

      if (ArgusParser->ArgusOutput) {
         if ((rec = ArgusGenerateStatusMarRecord(ArgusParser->ArgusOutput, ARGUS_SHUTDOWN, ARGUS_VERSION)) != NULL)
            ArgusPushBackList(ArgusParser->ArgusOutput->ArgusOutputList, (struct ArgusListRecord *)rec, ARGUS_LOCK);
      
         ArgusCloseListen(ArgusParser);
         ArgusCloseOutput(ArgusParser->ArgusOutput);
         ArgusDeleteOutput(ArgusParser, ArgusParser->ArgusOutput);
         ArgusParser->ArgusOutput = NULL;
      }

      if (ArgusSorter != NULL)
         ArgusDeleteSorter(ArgusSorter);

      if (sig >= 0) {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(caught signal $d)\n", sig);
#endif

         switch (sig) {
            case SIGHUP:
            case SIGINT:
            case SIGTERM:
            case SIGQUIT: {
               struct ArgusWfileStruct *wfile = NULL;

               ArgusShutDown(sig);

               if (ArgusParser->ArgusWfileList != NULL) {
                  struct ArgusListObjectStruct *lobj = NULL;
                  int i, count = ArgusParser->ArgusWfileList->count;

                  if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
                     for (i = 0; i < count; i++) {
                        if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                           if (wfile->fd != NULL) {
#ifdef ARGUSDEBUG
                              ArgusDebug (2, "RaParseComplete: closing %s\n", wfile->filename);
#endif
                              fflush (wfile->fd);
                              fclose (wfile->fd);
                              wfile->fd = NULL;
                           }
                        }
                        lobj = lobj->nxt;
                     }
                  }
               }
#if defined(ARGUS_THREADS)
               pthread_exit(0);
#else
               exit(0);
#endif /* ARGUS_THREADS */
               break;
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaParseComplete(%d) returning\n", sig);
#endif
}

void
ArgusStartGenerator(struct ArgusGenerator *gen)
{
   struct ArgusQueueStruct *queue = gen->configs;

   if (queue && queue->count) {
      struct ArgusGenConfig *config;
      int i, cnt = queue->count;

      for (i = 0; i < cnt; i++) {
         if ((config = (struct ArgusGenConfig *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
            if (!(config->status & ARGUS_STATUS)) {
               pthread_attr_t attrbuf, *attr = &attrbuf;

               pthread_attr_init(attr);
               pthread_attr_setdetachstate(attr, PTHREAD_CREATE_JOINABLE);

               if (getuid() == 0)
                  pthread_attr_setschedpolicy(attr, SCHED_RR);
               else
                  attr = NULL;

               if ((pthread_create(&config->tid, attr, ArgusProcessStatusRecords, (void *)config)) != 0)
                  ArgusLog (LOG_ERR, "ArgusGetName() pthread_create error %s\n", strerror(errno));
               config->status |= ARGUS_STATUS;
            }
            ArgusAddToQueue(queue, &config->qhdr, ARGUS_LOCK);
         }
      }
   }
}


void
ArgusStopGenerator(struct ArgusGenerator *gen)
{
   struct ArgusQueueStruct *queue = gen->configs;

   gen->parser->RaParseDone = 1;

   if (queue && queue->count) {
      struct ArgusGenConfig *config;
      int i, cnt = queue->count;

      for (i = 0; i < cnt; i++) {
         if ((config = (struct ArgusGenConfig *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
            if (config->status & ARGUS_STATUS) {
               config->status |= ARGUS_STOP;
               if (config->tid)
                  pthread_join(config->tid, NULL);
            }
            ArgusAddToQueue(queue, &config->qhdr, ARGUS_LOCK);
         }
      }
   }
   gen->status |= ARGUS_STOP;
}

void
ArgusAdjustRecordTime(struct ArgusParserStruct *parser, struct ArgusQueueStruct *queue)
{
   double deltaStartTime = -1;
   int i, cnt = queue->count;

   for (i = 0; i < cnt; i++) {
      struct ArgusRecordStruct *ns;

      if ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
         struct ArgusTimeObject *time = (void *)ns->dsrs[ARGUS_TIME_INDEX];
         if (time != NULL) {
            if (deltaStartTime == -1) {
               double stime = ArgusFetchStartTime(ns);
               deltaStartTime = parser->startime_t.tv_sec - (int)stime;
	    }
	    if (time->hdr.subtype & ARGUS_TIME_SRC_START) {
               time->src.start.tv_sec += deltaStartTime;
	    }
	    if (time->hdr.subtype & ARGUS_TIME_DST_START) {
               time->dst.start.tv_sec += deltaStartTime;
	    }
	    if (time->hdr.subtype & ARGUS_TIME_SRC_END)   {
               time->src.end.tv_sec += deltaStartTime;
	    }
	    if (time->hdr.subtype & ARGUS_TIME_DST_END)   {
               time->dst.end.tv_sec += deltaStartTime;
	    }
	 }
         ArgusAddToQueue(queue, &ns->qhdr, ARGUS_LOCK);
      }
   }
#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusAdjustRecordTime(%p, %p)\n", parser, queue);
#endif
}

void
ArgusGenerateStatusRecords(struct ArgusGenerator *gen)
{
   struct ArgusQueueStruct *queue = gen->configs;
   struct ArgusParserStruct *parser = gen->parser;

   if (queue && queue->count) {
      struct ArgusGenConfig *config;
      int i, cnt = queue->count;

      for (i = 0; i < cnt; i++) {
         if ((config = (struct ArgusGenConfig *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
            if (!(config->status & ARGUS_START)) {
               if ((config->finput = ArgusCalloc (1, sizeof(*config->finput))) != NULL) {
                  config->finput->filename = strdup(config->baseline);
                  config->finput->type = ARGUS_DATA_SOURCE;
                  config->finput->ostart = -1;
                  config->finput->ostop = -1;
                  config->finput->fd = open(config->finput->filename, O_RDONLY);
                  config->finput->file = fdopen(config->finput->fd, "r");

/*
   this code segment uses rabins.1 to generate a complete
   list of records for the run, but this can be huge and VMs were
   running out of memory ... so instead, we'll read in the baselines
   into a generator parser and then create our own rabins.1 output stream.

                  config->finput->fd = mkstemp(config->finput->tempfile);
                  config->finput->file = fdopen(config->finput->fd, "r");

                  snprintf (cmd, 1024, "/usr/bin/rabins -P stime -r %s -M time %s -w %s", 
                               config->baseline, config->interval, config->finput->tempfile);

#ifdef ARGUSDEBUG
                  ArgusDebug (2, "ArgusGenerateStatusRecord(%p) calling '%s'\n", gen, cmd);
#endif
                  if ((retn = system(cmd))  < 0) {
                     ArgusLog (LOG_ERR, "%s: system() failed\n", __func__);
                  }
                  snprintf (cmd, 1024, "/usr/bin/rasort -m stime -r %s -M replace", config->finput->tempfile);
                  if ((retn = system(cmd))  < 0) {
                     ArgusLog (LOG_ERR, "%s: system() failed\n", __func__);
                  }
*/
               }

               if (config->input == NULL) {
                  config->input = ArgusMalloc(sizeof(*config->input));
                  if (config->input == NULL)
                     ArgusLog(LOG_ERR, "unable to allocate input structure\n");

                  if (strcmp (config->finput->filename, "-")) {
                     if (strlen(config->finput->filename)) {
                        if (config->finput->file != NULL)
                           fseek(config->finput->file, 0, SEEK_SET);

                        ArgusInputFromFile(config->input, config->finput);
                        config->finput->fd = config->finput->fd;
                        config->input->file = config->finput->file;
                        config->finput->file = NULL;

                        /*
                           input->file now "owns" this pointer.  Setting it
                           to NULL prevents ArgusFileFree() from closing the
                           file a second time.
                        */

                        parser->ArgusCurrentInput = config->input;

                        if ((config->input->file != NULL) && ((ArgusReadConnection (parser, config->input, ARGUS_FILE)) >= 0)) {
#if defined(ARGUS_THREADS)
                           pthread_mutex_lock(&parser->lock);
#endif
                           parser->ArgusTotalMarRecords++;
                           parser->ArgusTotalRecords++;
#if defined(ARGUS_THREADS)
                           pthread_mutex_unlock(&parser->lock);
#endif
                           if (parser->RaPollMode) {
                              ArgusHandleRecord (parser, config->input, &config->input->ArgusInitCon, 0, &parser->ArgusFilterCode);
                           } else {
                              if (config->finput->ostart != -1) {
                                 config->input->offset = config->finput->ostart;
                                 if (fseek(config->input->file, config->input->offset, SEEK_SET) >= 0)
                                    ArgusReadFileStream(parser, config->input);
                              } else {
                                 ArgusHandleRecord (parser, config->input, &config->input->ArgusInitCon, 0, &parser->ArgusFilterCode);
                                 ArgusReadFileStream(parser, config->input);
                              }
                           }

                        } else
                           config->finput->fd = -1;
                     }
                  }

#ifdef ARGUSDEBUG
                  ArgusDebug (1, "main: ArgusProcessStatusRecord (%s) done", config->finput->filename);
#endif
                  RaArgusInputComplete(config->input);
                  parser->ArgusCurrentInput = NULL;
                  ArgusCloseInput(parser, config->input);
                  ArgusFree(config->input);
                  config->input = NULL;
               }

               if (parser->ArgusAggregator && (parser->ArgusAggregator->queue->count > 0)) {
                  struct ArgusQueueStruct *que = parser->ArgusAggregator->queue;
                  int i, cnt = que->count;

		  ArgusSortQueue(ArgusSorter, que, ARGUS_LOCK);
		  ArgusAdjustRecordTime(parser, que);

                  for (i = 0; i < cnt; i++) {
                     struct ArgusRecordStruct *ns;

                     if ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(que, ARGUS_LOCK)) != NULL) {
                        if (ns->bins == NULL) {
                           if ((ns->bins = ArgusCalloc(1, sizeof(*ns->bins))) != NULL) {

                              if ((ns->bins->array = (void *)ArgusCalloc(4, sizeof(void *))) == NULL)
                                 ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

                              bcopy(&gen->bins->nadp, &ns->bins->nadp, sizeof(gen->bins->nadp));
                              ArgusAlignInit(parser, ns, &ns->bins->nadp);

			   } else
                              ArgusLog(LOG_ERR, "ArgusGenerateStatusRecord: ArgusCalloc error %s\n", strerror(errno));
			}
                        ArgusAddToQueue(gen->queue, &ns->qhdr, ARGUS_LOCK);
	             }
	          }
	       }
            }

#ifdef ARGUSDEBUG
            ArgusDebug (2, "ArgusGenerateStatusRecord(%p) output %p client %p flow data stored in '%s'\n", 
                    gen, gen->output, gen->client, config->finput->tempfile);
#endif
            ArgusAddToQueue(queue, &config->qhdr, ARGUS_LOCK);
         }
      }
   }
}

void *
ArgusProcessStatusRecords(void *param)
{
   struct ArgusGenConfig *config = (struct ArgusGenConfig *) param;
   struct ArgusGenerator *gen = config->gen;
   struct ArgusParserStruct *parser = gen->parser;
   struct RaBinProcessStruct *rbps = gen->bins;
   struct RaBinStruct *bin = NULL;
   int ind = 0;

   while (!(parser->RaParseDone)) {
      struct timespec tsbuf = {0, 100000000}, *ts = &tsbuf;
      struct ArgusQueueStruct *queue;

   /*
    * OK, the concept here is to figure out if we have a new bin, 
    * and if so, we want to load up the bin with all the records
    * from the generator list that fit this bin, sort them by
    * stime, and then print them out.
    *
    * So, first step is to establish the bin and its start and
    * end timestamps.  Then with the generator list, move the ns
    * into the bin if the time ranges fit.
    * 
    * when its stime , transmit the bin.
    *

      if (gen->bins->array == NULL) 
         if ((gen->bins->array = (void *)ArgusCalloc(4, sizeof(void *))) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));
    */

      if ((bin = rbps->array[ind]) == NULL) {
         if (ind > rbps->max)
            rbps->max = ind;

         if ((rbps->array[ind] = RaNewBin(parser, rbps, NULL,
                                             /* knock rbps->index off of ind so that the record
                                              * falls within the bin boundaries. */
                                             (rbps->start + ((ind - rbps->index) * rbps->size)),
                                             0)) == NULL)
            ArgusLog (LOG_ERR, "ArgusInsertRecord: RaNewBin error %s", strerror(errno));

         rbps->count++; /* the number of used array entries */
         bin = rbps->array[ind];
      }

      if ((queue = gen->queue) != NULL) {
#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&queue->lock);
#endif
         if (queue->count > 0) {
            int i, cnt = queue->count;

            for (i = 0; i < cnt; i++) {
               struct ArgusRecordStruct *ns, *tns = NULL;

//  This loop loads up the next ns for this baseline descriptor
//  Its up to us to figure out when to send it ...
//  The concept is we should transmit all records whose stime fits in
//  the current output bin (which is defined by a master nadp) ...
//  So check the current output bin's time bounds, and if the stime
//  of any record is in the range, send it on its way ...

               if ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
                  if (ns->bins->array[0] == NULL) 
		     ns->bins->array[0] = (void *)ArgusAlignRecord(parser, ns, &ns->bins->nadp);

                  if ((tns = (struct ArgusRecordStruct *) ns->bins->array[0]) != NULL) {
	             double t1 = ArgusFetchStartTime(tns);
	             double st = rbps->array[0]->stime.tv_sec;
	             double et = rbps->array[0]->etime.tv_sec;

	             if ((t1 >= st) && (t1 < et)) {
                        ArgusPushBackList(parser->ArgusOutput->ArgusOutputList, (struct ArgusListRecord *) tns, ARGUS_LOCK);
                        ns->bins->array[0] = NULL;
		     }

		  }
                  ArgusAddToQueue(gen->queue, &ns->qhdr, ARGUS_NOLOCK);
               }
            }
         }
#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&queue->lock);
#endif
      }

      nanosleep (ts, NULL);

      gettimeofday(&parser->ArgusRealTime, 0);
      parser->ArgusGlobalTime = parser->ArgusRealTime;

      if (bin && (bin->etime.tv_sec <= parser->ArgusRealTime.tv_sec)) {
	 RaDeleteBin(parser, rbps, 0);
	 rbps->start = (bin->etime.tv_sec * 1000000LL);
	 rbps->array[0] = NULL;
	 bin = NULL;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusProcessStatusRecord(%p)\n", config);
#endif
#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#endif
   return (NULL);
}


void
ArgusClientTimeout ()
{
   int i, cnt = 0;
   gettimeofday(&ArgusParser->ArgusRealTime, 0);
   ArgusParser->ArgusGlobalTime = ArgusParser->ArgusRealTime;

   if ((cnt = ArgusGeneratorList->count) > 0) {
#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&ArgusGeneratorList->lock);
#endif

      /* Get the queue length down to the max.  The addition below
       * will push it back over the max length and ArgusWriteOutSocket()
       * can later determine if it needs to hang up the connection.
       */

      for (i = 0; i < cnt; i++) {
         struct ArgusGenerator *gen;

         if ((gen = (struct ArgusGenerator *)ArgusPopFrontList(ArgusGeneratorList, ARGUS_NOLOCK)) != NULL) {
            if (!(gen->status & ARGUS_START)) {
               ArgusGenerateStatusRecords(gen);
               gen->status |= ARGUS_START;
            } else 
            if (!(gen->status & ARGUS_STATUS)) {
               ArgusStartGenerator(gen);
            } else
            if (gen->status & ARGUS_STOP) {
               ArgusDeleteGenerator(gen);
               gen = NULL;
            }
            if (gen != NULL)
               ArgusPushBackList(ArgusGeneratorList, (struct ArgusListRecord *) gen, ARGUS_NOLOCK);
         }
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&ArgusGeneratorList->lock);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusClientTimeout()\n");
#endif
}

void
parse_arg (int argc, char**argv)
{}

void
usage ()
{
   extern char version[];

   fprintf (stdout, "RaGen Version %s\n", version);
   fprintf (stdout, "usage: %s [ragenoptions] [raoptions]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -c <dir>       daemon chroot directory.\n");
   fprintf (stdout, "         -d             run as a daemon.\n");
   fprintf (stdout, "         -f conf.file   read %s configure file.\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "         -u <userid>    specify user id for daemon.\n");
   fprintf (stdout, "         -g <groupid>   specify group id for daemon.\n");
#if defined (ARGUSDEBUG)
   fprintf (stdout, "         -D <level>     specify debug level\n");
#endif
#ifdef ARGUS_SASL
   fprintf (stdout, "         -U <user/auth> specify <user/auth> authentication information.\n");
#endif
   fflush (stdout);
   exit(1);
}


void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusRecordStruct *ns;

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR: {
         struct ArgusRecord *rec = (struct ArgusRecord *)argus->dsrs[0];
         if (rec && parser->ArgusAdjustTime) {
            struct timeval drift;

            drift.tv_sec  = parser->ArgusRealTime.tv_sec  - ntohl(rec->argus_mar.now.tv_sec);
            drift.tv_usec = parser->ArgusRealTime.tv_usec - ntohl(rec->argus_mar.now.tv_usec);
            argus->input->ArgusTimeDrift  = drift.tv_sec * 1000000;
            argus->input->ArgusTimeDrift += drift.tv_usec;
            rec->argus_mar.drift = argus->input->ArgusTimeDrift;
#ifdef ARGUSDEBUG
#if defined(__APPLE_CC__) || defined(__APPLE__)
            ArgusDebug (3, "RaProcessRecord: ArgusInput 0x%x drift %lld\n", 
                             argus->input, argus->input->ArgusTimeDrift);
#else
            ArgusDebug (3, "RaProcessRecord: ArgusInput 0x%x drift %Ld\n",
                             argus->input, argus->input->ArgusTimeDrift);
#endif
#endif
         }
         break;
      }

      case ARGUS_EVENT:
      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         struct ArgusTimeObject *time = (void *)argus->dsrs[ARGUS_TIME_INDEX];

         if (time != NULL) {
            if (parser->ArgusAdjustTime) {
               int secs = 0, usecs = 0;

               if (parser->ProcessRealTime) {
                  struct timeval tvpbuf, *now = &tvpbuf;
                  double lastTime = ArgusFetchLastTime(argus);

                  gettimeofday(now, NULL);
                  secs  = now->tv_sec - (int)lastTime;
                  usecs = now->tv_usec - ((lastTime - (int)lastTime) * 1000000);
                  if (usecs < 0) { usecs += 1000000; secs--; }

               } else {
                  long long ArgusDriftLevel = parser->ArgusAdjustTime * 1000000;
                  if (time && ((argus->input->ArgusTimeDrift >  ArgusDriftLevel) || 
                               (argus->input->ArgusTimeDrift < -ArgusDriftLevel))) {
                        secs  = argus->input->ArgusTimeDrift / 1000000;
                        usecs = argus->input->ArgusTimeDrift % 1000000;
                     }
               }

               if ((secs > 0) || (usecs > 0)) {
                  if (time->hdr.subtype & (ARGUS_TIME_SRC_START | ARGUS_TIME_DST_START)) {
                     time->hdr.argus_dsrvl8.qual |= ARGUS_TIMEADJUST;
                     if (time->hdr.subtype & ARGUS_TIME_SRC_START) {
                        if (time->src.start.tv_sec > 0) {
                           time->src.start.tv_sec  += secs;
                           time->src.start.tv_usec += usecs;
                           if (time->src.start.tv_usec > 1000000) {
                              time->src.start.tv_sec++;
                              time->src.start.tv_usec -= 1000000;
                           }
                        }
                        if (time->src.end.tv_sec > 0) {
                           time->src.end.tv_sec  += secs;
                           time->src.end.tv_usec += usecs;
                           if (time->src.end.tv_usec > 1000000) {
                              time->src.end.tv_sec++;
                              time->src.end.tv_usec -= 1000000;
                           }
                        }
                     }

                     if (time->hdr.subtype & ARGUS_TIME_DST_START) {
                        if (time->dst.start.tv_sec > 0) {
                           time->dst.start.tv_sec  += secs;
                           time->dst.start.tv_usec += usecs;
                           if (time->dst.start.tv_usec > 1000000) {
                              time->dst.start.tv_sec++;
                              time->dst.start.tv_usec -= 1000000;
                           }
                        }
                        if (time->dst.end.tv_sec > 0) {
                           time->dst.end.tv_sec  += secs;
                           time->dst.end.tv_usec += usecs;
                           if (time->dst.end.tv_usec > 1000000) {
                              time->dst.end.tv_sec++;
                              time->dst.end.tv_usec -= 1000000;
                           }
                        }
                     }
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "RaProcessRecord() ArgusInput 0x%x adjusting timestamps by %d secs and %d usecs\n", argus->input, secs, usecs);
#endif
                  }
               }
            }
         }
         break;
      }
   }

   if ((ns = ArgusCopyRecordStruct(argus)) != NULL) {
      int i;
      for (i = 0; i < RAGEN_MAX_ANALYTICS; i++) {
         if (RaGenAnalyticAlgorithmTable[i] != NULL) {
            if ((ns = RaGenAnalyticAlgorithmTable[i](parser, ns)) == NULL)
               break;

         } else
            break;
      }

      if (ns != NULL)
         ArgusAddToQueue(parser->ArgusAggregator->queue, &ns->qhdr, ARGUS_LOCK);
//       ArgusPushBackList(parser->ArgusOutput->ArgusOutputList, (struct ArgusListRecord *) ns, ARGUS_LOCK);
   }

#if defined(ARGUS_THREADS)
/*
   if (parser->ArgusOutput && parser->ArgusOutput->ArgusOutputList) {
      unsigned int cnt;

      pthread_mutex_lock(&parser->ArgusOutput->ArgusOutputList->lock);
      pthread_cond_signal(&parser->ArgusOutput->ArgusOutputList->cond);
      cnt = parser->ArgusOutput->ArgusOutputList->count;
      pthread_mutex_unlock(&parser->ArgusOutput->ArgusOutputList->lock);

      if (cnt > ArgusClientMaxQueueDepth) {
         struct timespec tsbuf = {0, 10000000}, *ts = &tsbuf;
         nanosleep (ts, NULL);
      }
   }
*/

#else
   ArgusListenProcess(parser);
   ArgusOutputProcess(parser->ArgusOutput);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (4, "RaProcessRecord (0x%x, 0x%x) returning", parser, argus); 
#endif
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}

/* used by RaGenParseResourceLine */
static int roption = 0;

static int
RaGenParseResourceLine (struct ArgusParserStruct *parser, int linenum,
                         char *optarg, int quoted, int idx)
{
   int retn = 0;
   char *ptr;

   switch (idx) {
      case RAGEN_MONITOR_ID: {
         if (optarg && quoted) {   // Argus ID is a string.  Limit to date is 4 characters.
            int slen = strlen(optarg);
            if (slen > 4) optarg[4] = '\0';
            if (optarg[3] == '\"') optarg[3] = '\0';
            setParserArgusID (parser, optarg, 4, ARGUS_TYPE_STRING);

         } else {
            if (optarg && (*optarg == '`')) {
               if (strrchr(optarg, (int) '`') != optarg) {
                  char *val = ArgusExpandBackticks(optarg);

#ifdef ARGUSDEBUG
                  ArgusDebug(1, "expanded %s to %s\n", optarg, val);
#endif
                  ArgusParseSourceID(parser, val);
                  free(val);
               } else {
                  ArgusLog (LOG_ERR, "%s: syntax error line %d\n", __func__, linenum);
               }
            } else {
               ArgusParseSourceID(parser, optarg);
            }
         }
         break;
      }

      case RAGEN_MONITOR_ID_INCLUDE_INF:
         setArgusManInf(parser, optarg);
         break;

      case RAGEN_ARGUS_CLIENT:
         break;

      case RAGEN_ARGUS_SERVER:
         if (!parser->Sflag++ && (parser->ArgusRemoteServerList != NULL))
            ArgusDeleteServerList(parser);

         if (!(ArgusAddServerList (parser, optarg, ARGUS_DATA_SOURCE, IPPROTO_TCP)))
            ArgusLog (LOG_ERR, "%s: host %s unknown\n", optarg);
         break;

      case RAGEN_CISCONETFLOW_PORT: {
         ++parser->Cflag;
         if (!parser->Sflag++ && (parser->ArgusRemoteServerList != NULL))
            ArgusDeleteServerList(parser);

         if (!(ArgusAddServerList (parser, optarg, ARGUS_CISCO_DATA_SOURCE, IPPROTO_UDP)))
            ArgusLog (LOG_ERR, "%s: host %s unknown\n", optarg);

         break;
      }

      case RAGEN_DAEMON: {
         if (!(strncasecmp(optarg, "yes", 3)))
            parser->dflag = 1;
         else
         if (!(strncasecmp(optarg, "no", 2)))
            parser->dflag = 0;
         break;
      }

      case RAGEN_INPUT_FILE:
         if ((!roption++) && (parser->ArgusInputFileList != NULL))
            ArgusDeleteFileList(parser);

         if (!(ArgusAddFileList (parser, optarg, ARGUS_DATA_SOURCE, -1, -1))) {
            ArgusLog (LOG_ERR, "%s: error: file arg %s\n", optarg);
         }
         break;

      case RAGEN_ACCESS_PORT:
         parser->ArgusPortNum = atoi(optarg);
         break;
/*
      case RAGEN_USER_AUTH:
         ustr = strdup(optarg);
         break;

      case RAGEN_AUTH_PASS:
         pstr = strdup(optarg);
         break;
*/
      case RAGEN_OUTPUT_FILE:
      case RAGEN_OUTPUT_STREAM: {
         char *filter = NULL, *fptr;

         if ((filter = strchr (optarg, ' ')) != NULL) {
            *filter++ = '\0';

            if ((fptr = strchr (filter, '"')) != NULL) {
               *fptr++ = '\0';
               filter = fptr;
            }
         }

         setArgusWfile (parser, optarg, filter);
         break;
      }

      case RAGEN_V3_ACCESS_PORT:
         parser->ArgusV3Port = atoi(optarg);
         break;

      case RAGEN_SRCID_CONVERSION_FILE:
         parser->RadiumSrcidConvertFile = strdup(optarg);
         RaGenParseSrcidConversionFile (parser->RadiumSrcidConvertFile);
         break;

      case RAGEN_MAR_STATUS_INTERVAL:
         setArgusMarReportInterval (parser, optarg);
         break;

      case RAGEN_DEBUG_LEVEL:
         parser->debugflag = atoi(optarg);
         break;

      case RAGEN_FILTER_OPTIMIZER:
         if ((strncasecmp(optarg, "yes", 3)))
            setArgusOflag  (parser, 1);
         else
            setArgusOflag  (parser, 0);
         break;

      case RAGEN_FILTER_TAG:
         if ((parser->ArgusRemoteFilter = ArgusCalloc (1, MAXSTRLEN)) != NULL) {
            char *str = optarg;
            ptr = parser->ArgusRemoteFilter;
            while (*str) {
               if ((*str != '\n') && (*str != '"'))
                  *ptr++ = *str++;
               else
                  str++;
            }
#ifdef ARGUSDEBUG
            ArgusDebug (1, "%s: ArgusFilter \"%s\" \n", __func__, parser->ArgusRemoteFilter);
#endif
         }
         break;

      case RAGEN_BIND_IP:
         if (*optarg != '\0')
            setArgusBindAddr (parser, optarg);
#ifdef ARGUSDEBUG
         ArgusDebug (1, "%s: ArgusBindAddr \"%s\" \n", __func__, parser->ArgusBindAddr);
#endif
         break;

      case RAGEN_MIN_SSF:
         if (*optarg != '\0') {
#ifdef ARGUS_SASL
            RaGenMinSsf = atoi(optarg);
#ifdef ARGUSDEBUG
         ArgusDebug (1, "%s: RaGenMinSsf \"%d\" \n", __func__, RaGenMinSsf);
#endif
#endif
         }
         break;

      case RAGEN_MAX_SSF:
         if (*optarg != '\0') {
#ifdef ARGUS_SASL
            RaGenMaxSsf = atoi(optarg);
#ifdef ARGUSDEBUG
            ArgusDebug (1, "%s: RaGenMaxSsf \"%d\" \n", __func__, RaGenMaxSsf);
#endif
#endif
         }
         break;

      case RAGEN_ADJUST_TIME: {
         char *ptr;
         parser->ArgusAdjustTime = strtol(optarg, (char **)&ptr, 10);
         if (ptr == optarg)
            ArgusLog (LOG_ERR, "%s: syntax error: line %d", __func__, linenum);

         if (isalpha((int) *ptr)) {
            switch (*ptr) {
               case 's': break;
               case 'm': parser->ArgusAdjustTime *= 60; break;
               case 'h': parser->ArgusAdjustTime *= 3600; break;
            }
         }
#ifdef ARGUSDEBUG
         ArgusDebug (1, "%s: ArgusAdjustTime is %d secs\n", __func__, parser->ArgusAdjustTime);
#endif
         break;
      }

      case RAGEN_CHROOT_DIR: {
         if (chroot_dir != NULL)
            free(chroot_dir);
         chroot_dir = strdup(optarg);
         break;
      }
      case RAGEN_SETUSER_ID: {
         struct passwd *pw;
         if ((pw = getpwnam(optarg)) == NULL)
            ArgusLog (LOG_ERR, "unknown user \"%s\"\n", optarg);
         new_uid = pw->pw_uid;
         endpwent();
         break;
      }
      case RAGEN_SETGROUP_ID: {
         struct group *gr;
         if ((gr = getgrnam(optarg)) == NULL)
             ArgusLog (LOG_ERR, "unknown group \"%s\"\n", optarg);
         new_gid = gr->gr_gid;
         endgrent();
         break;
      }

      case RAGEN_CLASSIFIER_FILE: {
         if (parser->ArgusLabeler == NULL) {
            if ((parser->ArgusLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
               ArgusLog (LOG_ERR, "%s: ArgusNewLabeler error", __func__);
         }

         if (RaLabelParseResourceFile (parser, parser->ArgusLabeler, optarg) != 0)
            ArgusLog (LOG_ERR, "%s: label conf file error %s", __func__, strerror(errno));

         RaGenAnalyticAlgorithmTable[0] = ArgusLabelRecord;
         break;
      }

      case RAGEN_ZEROCONF_REGISTER: {
         if ((strncasecmp(optarg, "yes", 3)))
            setArgusZeroConf (parser, 0);
         else
            setArgusZeroConf (parser, 1);
         break;

         break;
      }

      case RAGEN_AUTH_LOCALHOST:
         if (strncasecmp(optarg, "no", 2) == 0)
            RaGenAuthLocalhost = 0;
         break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s(%d,%s%s,%d) returning %d\n", __func__, linenum,
               RaGenResourceFileStr[idx], optarg, idx, retn);
#endif

   return (retn);
}


void
clearRaGenConfiguration (void)
{
   ArgusParser->dflag = 0;
   setParserArgusID (ArgusParser, 0, 0, 0);

   ArgusParser->ArgusPortNum = 0;

   clearArgusWfile (ArgusParser);
   setArgusBindAddr (ArgusParser, NULL);
   setArgusOflag (ArgusParser, 1);

   ArgusParser->dflag = 0;

   if (ArgusParser->ArgusRemoteServerList != NULL)
      ArgusDeleteServerList(ArgusParser);

   if (ArgusParser->ArgusInputFileList) {
      ArgusDeleteFileList(ArgusParser);
   }
 
   if (ArgusParser->ArgusRemoteFilter) {
      ArgusFree(ArgusParser->ArgusRemoteFilter);
      ArgusParser->ArgusRemoteFilter = NULL;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "clearRaGenConfiguration () returning\n");
#endif 
}

int
RaGenParseSourceID (struct ArgusAddrStruct *srcid, char *optarg)
{
   return ArgusCommonParseSourceID(srcid, NULL, optarg);
}


/*
   RaGenParseSrcidConversionFile (char *file)
      srcid 	conversionValue
*/

extern struct cnamemem converttable[HASHNAMESIZE];

int 
RaGenParseSrcidConversionFile (char *file)
{
   struct stat statbuf;
   FILE *fd = NULL;
   int retn = 0;

   if (file != NULL) {
      if (stat(file, &statbuf) >= 0) {
         if ((fd = fopen(file, "r")) != NULL) {
            char strbuf[MAXSTRLEN], *str = strbuf, *optarg = NULL;
            char *srcid = NULL, *convert = NULL;
            int lines = 0;

            retn = 1;

            while ((fgets(strbuf, MAXSTRLEN, fd)) != NULL)  {
               lines++;
               str = strbuf;
               while (*str && isspace((int)*str))
                   str++;

#define RA_READING_SRCID                0
#define RA_READING_ALIAS                1

               if (*str && (*str != '#') && (*str != '\n') && (*str != '!')) {
                  int state = RA_READING_SRCID;
                  struct cnamemem  *ap;
                  int done = 0;
                  u_int hash;

                  while ((optarg = strtok(str, " \t\n")) != NULL) {
                     switch (state) {
                        case RA_READING_SRCID: {
                           int i, len = strlen(optarg);
                           for (i = 0; i < len; i++)
                              optarg[i] = tolower(optarg[i]);
                           srcid = optarg;
                           state = RA_READING_ALIAS;
                           break;
                        }

                        case RA_READING_ALIAS: {
                           convert = optarg;
                           done = 1;
                           break;
                        }
                     }
                     str = NULL;
                    
                     if (done)
                        break;
                  }

                  hash = getnamehash((const u_char *)srcid);
                  ap = &converttable[hash % (HASHNAMESIZE-1)];
                  while (ap->n_nxt)
                     ap = ap->n_nxt;
     
                  ap->hashval = hash;
                  ap->name = strdup((char *) srcid);

                  ap->type = RaGenParseSourceID(&ap->addr, convert);
                  ap->n_nxt = (struct cnamemem *)calloc(1, sizeof(*ap));
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaGenParseSrcidConversionFile (%s) returning %d\n", file, retn);
#endif

   return (retn);
}


#if defined(ARGUS_MYSQL)
/*
   Mysql URL that we will respond to is:
      mysql://[username[:password]@]hostname[:port]/database/tablename
*/

void
RaMySQLInit ()
{
   my_bool reconnectbuf = 1, *reconnect = &reconnectbuf;
   char userbuf[1024], sbuf[1024], db[1024], *dbptr = NULL;
   char *sptr = NULL, *ptr;
   MYSQL_RES *mysqlRes;
   int retn = 0, x;

   bzero((char *)RaTableExistsNames,  sizeof(RaTableExistsNames));
   bzero((char *)RaTableCreateNames,  sizeof(RaTableCreateNames));
   bzero((char *)RaTableCreateString, sizeof(RaTableCreateString));
   bzero((char *)RaTableDeleteString, sizeof(RaTableDeleteString));

   if (RaTables != NULL) {
      int i = 0;
      while (RaTables[i] != NULL) {
         free(RaTables[i]);
         i++;
      }
      ArgusFree(RaTables);
      RaTables = NULL;
   }

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

      if (RaDatabase) 
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
         RaSQLSaveTable = strdup(RaTable);
   }

   if (!(ArgusParser->status & ARGUS_REAL_TIME_PROCESS))
      ArgusLastTime = ArgusParser->ArgusRealTime;

   if (RaMySQL == NULL) {
      if ((RaMySQL = (void *) ArgusCalloc(1, sizeof(*RaMySQL))) == NULL)
         ArgusLog(LOG_ERR, "RaMySQLInit: ArgusCalloc error %s", strerror(errno));

      if ((mysql_init(RaMySQL)) != NULL) {
         if (!mysql_thread_safe())
            ArgusLog(LOG_INFO, "mysql not thread-safe");

         mysql_options(RaMySQL, MYSQL_READ_DEFAULT_GROUP, ArgusParser->ArgusProgramName);
         mysql_options(RaMySQL, MYSQL_OPT_RECONNECT, reconnect);

         if ((mysql_real_connect(RaMySQL, RaHost, RaUser, RaPass, NULL, RaPort, NULL, 0)) != NULL) {
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

            sprintf (sbuf, "USE argus");

/* If we don't an argus database, then we don't have -t support in the database */

            if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) == 0) {
               if ((mysqlRes = mysql_list_tables(RaMySQL, NULL)) != NULL) {
                  char sbuf[MAXSTRLEN];

                  if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                     while ((row = mysql_fetch_row(mysqlRes))) {
                        unsigned long *lengths;
                        lengths = mysql_fetch_lengths(mysqlRes);
                        bzero(sbuf, sizeof(sbuf));
                           for (x = 0; x < retn; x++)
                           sprintf(&sbuf[strlen(sbuf)], "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

                        if (!(strncmp(sbuf, "Seconds", 8))) {
                           ArgusSQLSecondsTable = 1;
                        }
                     }

                  }
                  mysql_free_result(mysqlRes);
               }

            } else {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "argus database is missing or has no tables.\n");
#endif
            }

            if (ArgusSQLSecondsTable == 0) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "argus database returned no tables.\n");
#endif
            }

            if (!RaSQLNoCreate) {
               bzero(sbuf, sizeof(sbuf));
               sprintf (sbuf, "CREATE DATABASE IF NOT EXISTS %s", RaDatabase);

               if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
                  ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
            }
         } else {
            ArgusFree(RaMySQL);
            RaMySQL = NULL;
         }
      } else {
         ArgusFree(RaMySQL);
         RaMySQL = NULL;
      }
   }

   if (RaMySQL != NULL) {
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

      if (RaTable != NULL) {
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

      if ((ArgusParser->ArgusInputFileList != NULL)  ||
           (ArgusParser->ArgusRemoteHosts && (ArgusParser->ArgusRemoteHosts->count > 0))) {

         if (RaSQLSaveTable != NULL) {
            if (!((strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$'))))
               if (ArgusCreateSQLSaveTable(RaSQLSaveTable))
                  ArgusLog(LOG_ERR, "mysql create %s returned error", RaSQLSaveTable);
         }
      }

      if (ArgusParser->MySQLDBEngine == NULL)
         ArgusParser->MySQLDBEngine = strdup("InnoDB");
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaMySQLInit () RaSource %s RaArchive %s RaFormat %s", RaSource, RaArchive, RaFormat);
#endif
}


void
RaSQLQuerySecondsTable (unsigned int start, unsigned int stop)
{
   struct RaMySQLSecondsTable *sqry = NULL;
   MYSQL_RES *mysqlRes;
   char *endptr, *str;
   char *buf, *sbuf;

   unsigned int t1, t2;
   int retn, x;

   if ((buf = (char *)ArgusCalloc (1, MAXSTRLEN)) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

   if ((sbuf = (char *)ArgusCalloc (1, MAXSTRLEN)) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

   for (t1 = start; t1 <= stop; t1 += ARGUSSQLMAXQUERYTIMESPAN) {
      t2 = ((t1 + ARGUSSQLMAXQUERYTIMESPAN) > stop) ? stop : (t1 + ARGUSSQLMAXQUERYTIMESPAN);

      str = "SELECT * from %s.Seconds WHERE second >= %u and second <= %u";
      sprintf (buf, str, RaDatabase, t1, t2);

#ifdef ARGUSDEBUG
      ArgusDebug (2, "SQL Query %s\n", buf);
#endif

      if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
         ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

      else {
         if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
            if ((retn = mysql_num_fields(mysqlRes)) > 0) {
               while ((row = mysql_fetch_row(mysqlRes))) {
                  unsigned long *lengths;
       
                  lengths = mysql_fetch_lengths(mysqlRes);
                  bzero(sbuf, MAXSTRLEN);

                  if ((sqry = (void *) ArgusCalloc (1, sizeof(*sqry))) == NULL)
                     ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

                  for (x = 0; x < retn; x++) {
                     int y = x;
                     snprintf(sbuf, MAXSTRLEN, "%.*s ", (int) lengths[x], row[x] ? row[x] : "NULL");
                     
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
   }
   ArgusFree(sbuf);
   ArgusFree(buf);
}

void
RaSQLQueryDatabaseTable (char *table, unsigned int start, unsigned int stop)
{
   MYSQL_RES *mysqlRes;
   char *timeField = NULL;
   char *buf, *sbuf;
   int i, slen = 0;
   int retn, x, count = 0;

   if ((buf = (char *)ArgusCalloc (1, MAXSTRLEN)) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

   if ((sbuf = (char *)ArgusCalloc (1, MAXARGUSRECORD)) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

   for (i = 0; (ArgusTableColumnName[i] != NULL) && (i < ARGUSSQLMAXCOLUMNS); i++) {
      if (!(strcmp("ltime", ArgusTableColumnName[i]))) {
         timeField = "ltime";
      }
      if (!(strcmp("stime", ArgusTableColumnName[i]))) {
         timeField = "stime";
         break;
      }
   }

   if (timeField == NULL)
      timeField = "second";

   {
      char *ArgusSQLStatement;
      unsigned int t1, t2;

      if ((ArgusSQLStatement = ArgusCalloc(1, MAXSTRLEN)) == NULL)
         ArgusLog(LOG_ERR, "unable to allocate ArgusSQLStatement: %s", strerror(errno));

      sprintf (buf, "SELECT count(*) from %s", table);
      if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) == 0) {
         if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
            if ((retn = mysql_num_fields(mysqlRes)) > 0) {
               while ((row = mysql_fetch_row(mysqlRes))) {
                  count = atoi(row[0]);
               }
            }
         }
      }

      if (count > ARGUSSQLMAXROWNUMBER) {
         if (timeField && (ArgusParser->tflag == 0)) {
            sprintf (buf, "SELECT min(%s) start, max(%s) stop from %s", timeField, timeField, table);
            if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) == 0) {
               if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
                  if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                     while ((row = mysql_fetch_row(mysqlRes))) {
                        start = atoi(row[0]);
                        stop  = atoi(row[1]) + 1;
                     }
                  }
               }
            }
         }

         for (t1 = start; t1 <= stop; t1 += ARGUSSQLMAXQUERYTIMESPAN) {
            t2 = ((t1 + ARGUSSQLMAXQUERYTIMESPAN) > stop) ? stop : (t1 + ARGUSSQLMAXQUERYTIMESPAN);

            *ArgusSQLStatement = '\0';
         
            if (ArgusParser->ArgusSQLStatement != NULL)
               strcpy(ArgusSQLStatement, ArgusParser->ArgusSQLStatement);

            if (ArgusAutoId)
               sprintf (buf, "SELECT autoid,record from %s", table);
            else
               sprintf (buf, "SELECT record from %s", table);

            if ((slen = strlen(ArgusSQLStatement)) > 0) {
               snprintf (&ArgusSQLStatement[strlen(ArgusSQLStatement)], MAXSTRLEN - slen, " and ");
               slen = strlen(ArgusSQLStatement);
            }

            snprintf (&ArgusSQLStatement[slen], MAXSTRLEN - slen, "%s >= %d and %s < %d", timeField, t1, timeField, t2);

            if (strlen(ArgusSQLStatement) > 0)
               sprintf (&buf[strlen(buf)], " WHERE %s", ArgusSQLStatement);

#ifdef ARGUSDEBUG
            ArgusDebug (1, "SQL Query %s\n", buf);
#endif
            if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) == 0) {
               if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
                  if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                     while ((row = mysql_fetch_row(mysqlRes))) {
                        unsigned long *lengths = mysql_fetch_lengths(mysqlRes);
                        int autoid = 0;

                        if (ArgusAutoId && (retn > 1)) {
                           char *endptr;
                           autoid = strtol(row[0], &endptr, 10);
                           if (row[0] == endptr)
                              ArgusLog(LOG_ERR, "mysql database error: autoid returned %s", row[0]);
                           x = 1;
                        } else
                           x = 0;

                        ArgusParser->ArgusAutoId = autoid;
                        bcopy (row[x], sbuf, (int) lengths[x]);

                        ArgusHandleRecord (ArgusParser, ArgusInput, (struct ArgusRecord *)sbuf, lengths[x], &ArgusParser->ArgusFilterCode);
                     }
                  }

                  mysql_free_result(mysqlRes);
               }

            } else {
               if (mysql_errno(RaMySQL) != ER_NO_SUCH_TABLE) {
                  ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
#ifdef ARGUSDEBUG
               } else {
                  ArgusDebug (4, "%s: skip missing table %s", __func__, table);
#endif
               }
            }
         }

      } else {
         *ArgusSQLStatement = '\0';
         
         if (ArgusParser->ArgusSQLStatement != NULL)
            strcpy(ArgusSQLStatement, ArgusParser->ArgusSQLStatement);

         if (ArgusAutoId)
            sprintf (buf, "SELECT autoid,record from %s", table);
         else
            sprintf (buf, "SELECT record from %s", table);

         if (strlen(ArgusSQLStatement) > 0)
            sprintf (&buf[strlen(buf)], " WHERE %s", ArgusSQLStatement);

#ifdef ARGUSDEBUG
         ArgusDebug (1, "SQL Query %s\n", buf);
#endif
         if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) == 0) {
            if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
               if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                  while ((row = mysql_fetch_row(mysqlRes))) {
                     unsigned long *lengths = mysql_fetch_lengths(mysqlRes);
                     int autoid = 0;

                     if (ArgusAutoId && (retn > 1)) {
                        char *endptr;
                        autoid = strtol(row[0], &endptr, 10);
                        if (row[0] == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: autoid returned %s", row[0]);
                        x = 1;
                     } else
                        x = 0;

                     ArgusParser->ArgusAutoId = autoid;
                     bcopy (row[x], sbuf, (int) lengths[x]);

                     ArgusHandleRecord (ArgusParser, ArgusInput, (struct ArgusRecord *)sbuf, lengths[x], &ArgusParser->ArgusFilterCode);
                  }
               }

               mysql_free_result(mysqlRes);
            }

         } else {
            if (mysql_errno(RaMySQL) != ER_NO_SUCH_TABLE) {
               ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
#ifdef ARGUSDEBUG
            } else {
               ArgusDebug (4, "%s: skip missing table %s", __func__, table);
#endif
            }
         }
      }
   }

   ArgusFree(sbuf);
   ArgusFree(buf);
}

void 
RaSQLProcessQueue (struct ArgusQueueStruct *queue)
{
   struct RaMySQLFileStruct *fstruct = NULL;
   struct RaMySQLSecondsTable *sqry = NULL, *tsqry = NULL;

   while (queue->count) {
      if ((sqry = (struct RaMySQLSecondsTable *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
         int i, cnt = queue->count;

         if ((fstruct = (void *) ArgusCalloc (1, sizeof(*fstruct))) == NULL)
            ArgusLog(LOG_ERR, "RaSQLProcessQueue: ArgusCalloc error %s", strerror(errno));

         fstruct->fileindex = sqry->fileindex;
         fstruct->probe  = sqry->probe;
         fstruct->second = sqry->second;
         fstruct->ostart = sqry->ostart;
         fstruct->ostop  = sqry->ostop;
         ArgusAddToQueue (ArgusFileQueue, &fstruct->qhdr, ARGUS_LOCK);

         if (cnt > 0) {
            for (i = 0; i < cnt; i++) {
               if ((tsqry = (void *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
                  if (sqry->fileindex == tsqry->fileindex) {
                     if (fstruct->second > tsqry->second)
                        fstruct->second = tsqry->second;
                     if (fstruct->ostart > tsqry->ostart)
                        fstruct->ostart = tsqry->ostart;
                     if (fstruct->ostop < tsqry->ostop)
                        fstruct->ostop = tsqry->ostop;

                     ArgusFree(tsqry);

                  } else {
                     ArgusAddToQueue(queue, &tsqry->qhdr, ARGUS_LOCK);
                  }
               }
            }
         }

         ArgusFree(sqry);
      }
   }

   if (ArgusFileQueue->count) {
      int i, cnt = ArgusFileQueue->count;
      char *buf, *sbuf;
      MYSQL_RES *mysqlRes;
      struct stat statbuf;
      int retn, x;

      if ((buf = ArgusMalloc(1024)) == NULL)
         ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

      if ((sbuf = ArgusMalloc(1024)) == NULL)
         ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

      for (i = 0; i < cnt; i++) {
         if ((fstruct = (struct RaMySQLFileStruct *) ArgusPopQueue(ArgusFileQueue, ARGUS_LOCK)) !=  NULL) {
            char *str = NULL;

            str = "SELECT filename from %s.Filename WHERE id = %d",
            sprintf (buf, str, RaDatabase, fstruct->fileindex);

            if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
               ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

            else {
               if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
                  if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                     while ((row = mysql_fetch_row(mysqlRes))) {
                        char *file, *filenamebuf, *directorypath;
                        char *ptr = NULL;
                        unsigned long *lengths;

                        if ((file = ArgusMalloc(MAXSTRLEN)) == NULL)
                           ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

                        if ((filenamebuf = ArgusMalloc(MAXSTRLEN)) == NULL)
                           ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

                        if ((directorypath = ArgusMalloc(MAXSTRLEN)) == NULL)
                           ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));
          
                        lengths = mysql_fetch_lengths(mysqlRes);
                        if (RaFormat) {
                           char fbuf[1024];
                           time_t secs;
                           bzero (fbuf, sizeof(fbuf));
                           if ((ptr = strstr(RaFormat, "$srcid")) != NULL) {
                              struct RaMySQLProbeTable *psqry = (void *)ArgusProbeQueue->start;
                              RaProbeString = NULL;
                              bcopy (RaFormat, fbuf, (ptr - RaFormat));
                              if (psqry) {
                                 for (x = 0; x < ArgusProbeQueue->count; x++) {
                                    if ((psqry->probe == fstruct->probe) || (fstruct->probe == 0)) {
                                       RaProbeString = psqry->name;
                                       break;
                                    }
                                    psqry = (void *)psqry->qhdr.nxt;
                                 }
                                 if (RaProbeString)
                                    sprintf (&fbuf[strlen(fbuf)], "%s", RaProbeString);
                              }
                              
                              bcopy (&ptr[6], &fbuf[strlen(fbuf)], strlen(&ptr[6]));

                           } else {
                              bcopy (RaFormat, fbuf, strlen(RaFormat));
                           }

                           secs = (fstruct->second/RaPeriod) * RaPeriod;
                           strftime (directorypath, MAXSTRLEN, fbuf, localtime(&secs));
                        }

                        for (x = 0; x < retn; x++)
                           snprintf(sbuf, MAXSTRLEN, "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

                        if ((ptr = strchr(sbuf, '.')) == NULL)
                           ArgusLog(LOG_ERR, "RaSQLProcessQueue: Filename format error %s", sbuf);

                        if (RaFormat) 
                           sprintf (file, "%s/%s", directorypath, sbuf);
                        else
                           sprintf (file, "%s", sbuf);

                        while (file[strlen(file) - 1] == ' ')
                           file[strlen(file) - 1] = '\0';

                        if (!(strncmp(&file[strlen(file) - 3], ".gz", 3))) 
                           file[strlen(file) - 3] = '\0';

                        if (RaRoleString) {
                           sprintf (filenamebuf, "%s/%s/%s", ArgusArchiveBuf, RaRoleString, file);
                        } else {
                           sprintf (filenamebuf, "%s/%s", ArgusArchiveBuf, file);
                        }

                        if ((stat (filenamebuf, &statbuf)) != 0) {   // does file exist
                           char *compressbuf = NULL;
                           char *filepath =  NULL;

                           if ((filepath = ArgusMalloc(MAXSTRLEN)) == NULL)
                              ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

                           if (ArgusParser->RaTempFilePath != NULL)
                              sprintf(filepath, "%s/%s", ArgusParser->RaTempFilePath, filenamebuf);

                           if ((stat (filepath, &statbuf)) != 0) {  // is file in temporary cache 

                              if ((compressbuf = ArgusMalloc(MAXSTRLEN)) == NULL)
                                 ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

                              sprintf (compressbuf, "%s.gz", filenamebuf);

                              if ((stat (compressbuf, &statbuf)) == 0) {
                                 if ((fstruct->ostart >= 0) || (fstruct->ostop > 0)) {
                                    char *command =  NULL;

                                    if ((command = ArgusMalloc(MAXSTRLEN)) == NULL)
                                       ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

                                    ArgusMkdirPath(filepath);

                                    sprintf (command, "gunzip -c \"%s\" > \"%s\"", compressbuf, filepath);
#ifdef ARGUSDEBUG
                                    ArgusDebug (2, "RaSQLProcessQueue: local decomression command %s\n", command);
#endif
                                    if (system(command) < 0)
                                       ArgusLog(LOG_ERR, "RaSQLProcessQueue: system error", strerror(errno));

                                    sprintf (filenamebuf, "%s", filepath);
                                    ArgusFree(command);

                                 } else {
                                    sprintf (filenamebuf, "%s", compressbuf);
                                 }

                              } else {
                                 if (RaHost) {
                                    int RaPort = ArgusParser->ArgusPortNum ?  ArgusParser->ArgusPortNum : ARGUS_DEFAULTPORT;
                                    char *command =  NULL;

                                    if ((command = ArgusMalloc(MAXSTRLEN)) == NULL)
                                       ArgusLog(LOG_ERR, "RaSQLProcessQueue: alloc error", strerror(errno));

                                    if (RaRoleString != NULL)
                                       sprintf (command, "\"%s/ra\" -S %s:%d%s/%s/%s -w %s", RaProgramPath, RaHost, RaPort, RaArchive, RaRoleString, file, filenamebuf);
                                    else
                                       sprintf (command, "\"%s/ra\" -S %s:%d%s/%s -w %s", RaProgramPath, RaHost, RaPort, RaArchive, file, filenamebuf);
#ifdef ARGUSDEBUG
                                    ArgusDebug (2, "RaSQLProcessQueue: remote file caching command  %s\n", command);
#endif
                                    if (system(command) < 0)
                                       ArgusLog(LOG_ERR, "RaSQLProcessQueue: system error", strerror(errno));

                                    ArgusFree(command);
                                 }
                              }

                           } else {
                              sprintf (filenamebuf, "%s", filepath);
                           }
                           ArgusFree(filepath);
                        }

                        fstruct->filename = strdup (filenamebuf);
                        ArgusFree(file);
                        ArgusFree(filenamebuf);
                        ArgusFree(directorypath);
                     }
                  }

                  mysql_free_result(mysqlRes);
               }
            }
            ArgusAddToQueue(ArgusFileQueue, &fstruct->qhdr, ARGUS_LOCK);
         }
      }

      ArgusFree(buf);
      ArgusFree(sbuf);
   }

   if (ArgusFileQueue->count) {
      struct RaMySQLFileStruct *fptr = NULL;
      int x;

      while ((fstruct = (struct RaMySQLFileStruct *) ArgusPopQueue(ArgusFileQueue, ARGUS_LOCK)) != NULL) {
         fptr = (struct RaMySQLFileStruct *) ArgusFileQueue->start;

         for (x = 0; x < ArgusFileQueue->count; x++) {
            if (fstruct->fileindex == fptr->fileindex) {
               if (fstruct->ostart < fptr->ostart)
                  fptr->ostart = fstruct->ostart;
               if (fstruct->ostop > fptr->ostop)
                  fptr->ostop = fstruct->ostop;

               ArgusFree(fstruct);
               fstruct = NULL;
               break;
            }

            fptr = (struct RaMySQLFileStruct *) fptr->qhdr.nxt;
         }

         if (fstruct != NULL) {
            ArgusAddFileList(ArgusParser, fstruct->filename, ARGUS_DATA_SOURCE,
                       fstruct->ostart, fstruct->ostop);
#ifdef ARGUSDEBUG
            ArgusDebug (2, "RaSQLProcessQueue: filename %s ostart %d  ostop %d\n",
                              fstruct->filename, fstruct->ostart, fstruct->ostop);
#endif
         }
      }

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (2, "RaSQLProcessQueue: query return NULL");
#endif
      RaParseComplete(SIGINT);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaSQLProcessQueue(0x%x)", queue);
#endif
}

extern int RaDaysInAMonth[12];


/*
    So first look to see if the table already exists.
    If so and we're suppose to delete, then delete it.
    Then look to see if the name is in our list of default
    RaTableCreateNames[] to see if we need to remove it
    from that list, if we didn't catch the table in the
    other list.  At the end of this routine cindex is pointing 
    at the right place.
*/

int
ArgusCreateSQLSaveTable(char *table)
{
   int retn = 0, cindex = 0, ind = 0, i, x, exists = 0;
   struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
   char stable[256], sbuf[MAXSTRLEN], kbuf[MAXSTRLEN];

   sprintf (stable, "%s", table);

   bzero(sbuf, sizeof(sbuf));
   bzero(kbuf, sizeof(kbuf));

   for (i = 0; i < RA_MAXTABLES && !exists; i++) {
      if (RaTableExistsNames[i] != NULL) {
         if (!strcmp(RaTableExistsNames[i], stable))
            exists++;
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
               ArgusDebug (2, "generating table %s\n", str);
#endif
               if ((retn = mysql_real_query(RaMySQL, str, strlen(str))) != 0)
                  ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));

               ArgusCreateTable = 1;
               RaSQLCurrentTable = strdup(table);
            }
         }
      }

   } else {
      if (RaSQLCurrentTable == NULL)
         RaSQLCurrentTable = strdup(table);
      retn = 0;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCreateSQLSaveTable (%s) returning", table, retn);
#endif
   return (retn);
}

int
ArgusReadSQLTables (struct ArgusParserStruct *parser)
{
   int retn = 0, found = 0, tableIndex;
   char *table = NULL;
   MYSQL_RES *mysqlRes;

   if (parser->tflag) {
// so we've been given a time filter, so we have a start and end time
// stored in parser->startime_t && parser->lasttime_t, and we support
// wildcard options, so ..., the idea is that we need at some point to
// calculate the set of tables that we'll search for records.  We
// should do that here.
//
// So the actual table, datatbase, etc..., were set in the RaMySQLInit()
// call so we can test some values here.
// 
      RaTables = ArgusCreateSQLTimeTableNames(parser, &ArgusTableStartSecs,
                                              &ArgusTableEndSecs,
                                              ArgusSQLSecondsTable,
                                              &RaBinProcess->nadp, RaTable);
   }

   if ((RaTables == NULL) && (RaTable != NULL)) {
      sprintf (ArgusSQLTableNameBuf, "%s", RaTable);

      if ((RaTables = ArgusCalloc(sizeof(void *), 2)) == NULL)
         ArgusLog(LOG_ERR, "mysql_init error %s", strerror(errno));

      RaTables[0] = strdup(ArgusSQLTableNameBuf);
   }

   if (RaTables != NULL) {
      bzero(&ArgusTableColumnName, sizeof (ArgusTableColumnName));

      tableIndex = 0;
      retn = -1;
      while ((table = RaTables[tableIndex]) != NULL) {
         if (strcmp("Seconds", table)) {
            sprintf (ArgusSQLStatement, "desc %s", table);
            if ((retn = mysql_real_query(RaMySQL, ArgusSQLStatement , strlen(ArgusSQLStatement))) != 0) {
               if (mysql_errno(RaMySQL) != ER_NO_SUCH_TABLE) {
                  ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
#ifdef ARGUSDEBUG
               } else {
                  ArgusDebug (4, "%s: skip missing table %s", __func__, table);
#endif
               }
            } else {
               found++;
               break;
            }
         } else
            retn = 0;
         tableIndex++;
      }
   }

   if (retn == 0) {
      if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            int ind = 0;
            while ((row = mysql_fetch_row(mysqlRes)))
               ArgusTableColumnName[ind++] = strdup(row[0]);

            mysql_free_result(mysqlRes);
         }
      }

      if (retn > 0) {
         int x, i = 0;

         while (parser->RaPrintAlgorithmList[i] != NULL) {
           ArgusFree(parser->RaPrintAlgorithmList[i]);
           parser->RaPrintAlgorithmList[i] = NULL;
           i++;
         }

         for (x = 0; (ArgusTableColumnName[x] != NULL) && (x < ARGUSSQLMAXCOLUMNS); x++) {
            for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
               if (!strcmp(RaPrintAlgorithmTable[i].field, ArgusTableColumnName[x])) {
                  if ((parser->RaPrintAlgorithmList[x] = ArgusCalloc(1, sizeof(*parser->RaPrintAlgorithm))) == NULL)
                     ArgusLog (LOG_ERR, "ArgusCalloc error %s", strerror(errno));

                  bcopy(&RaPrintAlgorithmTable[i], parser->RaPrintAlgorithmList[x], sizeof(*parser->RaPrintAlgorithm));
               }
            }
         }

         ArgusProcessSOptions(parser);
      }

      if (RaTables) {
         RaSQLQueryTable (RaMySQL, (const char **)RaTables, ArgusAutoId,
                          argus_version,
                          (const char **)&ArgusTableColumnName[0]);

         parser->RaTasksToDo = RA_ACTIVE;
      }
   }

   return (retn);
}
#endif 


/* timeout functions:
 *
 * ragen.1 is about providing a realtime stream of synthetic data
 * based on a flexible set of baselines.  As a result, we want to
 * process everything based on realtime processing.
 *
 */
static void
RabinsSetTimeout(struct RaBinProcessStruct *rbps, struct timeval *timer,
                 const struct timeval * const interval)
{
   int ind = RabinsOldestIndex ? RabinsOldestIndex : rbps->index;

   if (rbps->array && rbps->array[ind])
      timeradd(&rbps->array[ind]->etime, interval, timer);
   else {
      timer->tv_sec = 0;
      timer->tv_usec = 0;
   }
}

static int
RabinsCheckTimeout(const struct ArgusParserStruct * const parser,
                   const struct timeval * const timer)
{
   if (timer->tv_sec == 0)
      return 0;

   return !!timercmp(&parser->ArgusRealTime, timer, >);
}

