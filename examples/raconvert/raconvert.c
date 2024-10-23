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
 *
 */

/*
 * raconvert - this converts ra() ascii output back into argus binary records.
 *
 *    The primary file format that this program will support is the simple
 *    title, data, .... data default ascii output that ra() generates.
 *    So read in the title line, and then parse the columns found.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

/*
 * $Id: //depot/gargoyle/clients/examples/raconvert/raconvert.c#11 $
 * $DateTime: 2016/11/07 12:39:19 $
 * $Change: 3240 $
 */
#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#include <argus_compat.h>

#if defined(ARGUS_SOLARIS) || (__FreeBSD__) || (__NetBSD__) || (__OpenBSD__)
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include <unistd.h>
#include <string.h>

#include <sys/time.h>
#include <netinet/in.h>
#include <net/if.h>

#include <netinet/tcp.h>


#include <unistd.h>

#include <netinet/tcp.h>

#if defined(ARGUS_THREADS) 
#include <pthread.h>
#endif

#define ArgusMain

#include <argus_compat.h>

#include <argus_def.h>
#include <argus_out.h>

#include <signal.h>

#include <argus_util.h>
#include <argus_output.h>

#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <argus_grep.h>
#include <argus_dscodepoints.h>

#include <argus_json.h>
#include <raconvert.h>

#include <ctype.h>
#include <strings.h>

#if defined(ARGUS_SOLARIS)
#include <string.h>
#endif

#include <sys/wait.h>

#if defined(__NetBSD__)
#include <sys/sched.h>
#else
#include <sched.h>
#endif

#define RACONVERT_RCITEMS		9

#define RACONVERT_SOURCE		0
#define ARGUS_MONITOR_ID		1
#define RACONVERT_TIME_FORMAT		2
#define RACONVERT_FIELD_SPECIFIER	3
#define RACONVERT_FIELD_DELIMITER	4
#define RACONVERT_FIELD_EMPTY		5
#define RACONVERT_FIELD_UNDEFINED	6
#define RACONVERT_FIELD_QUOTED		7
#define RACONVERT_CONVERSION_MAP	8	

#define ARGUS_MAX_CONVERSION		1024

int ArgusInputType = 0;

extern char *ArgusTCPFlags[];

struct RaConversionMapStruct {
   char *field;
   char *value;
   void (*func)(struct ArgusParserStruct *, char *);
};

struct RaConversionMapStruct RaConversionMapTable[ARGUS_MAX_CONVERSION];
char *RaConvertOptionStrings[ARGUS_MAX_CONVERSION];

int RaConversionMapIndex = 0;
int RaConvertOptionIndex = 0;

char *ArgusConvertResourceFileStr[] = {
    "RACONVERT_SOURCE=",
    "ARGUS_MONITOR_ID=",
    "RACONVERT_TIME_FORMAT=",
    "RACONVERT_FIELD_SPECIFIER=",
    "RACONVERT_FIELD_DELIMITER=",
    "RACONVERT_FIELD_EMPTY=",
    "RACONVERT_FIELD_UNDEFINED=",
    "RACONVERT_FIELD_QUOTED=",
    "RACONVERT_CONVERSION_MAP=",
};

#define ARGUS_MAX_PRINT_FIELDS		512

struct ArgusParseFieldStruct (*RaParseAlgorithms[ARGUS_MAX_PRINT_FIELDS]);
int RaParseAlgorithmIndex = 0;
char RaConvertFieldDelimiter[32] = {'\0', '\0'};

#define ARGUSMAXSTR	0x10000

char ArgusConvertTitleString[ARGUSMAXSTR];
char ArgusProcessTitleString = 0;


struct ArgusLogPriorityStruct {
   int priority;
   char *label;
};

extern struct ArgusParserStruct *ArgusParser;

#define RASCII_MAXMODES		1
#define RASCIIDEBUG		0

char *RaConvertDaemonModes[RASCII_MAXMODES] = {
   "debug",
};

int ArgusDebugMode = 0;


#define RASCII_MAXDEBUG		2

#define RASCII_DEBUGDUMMY	0
#define RASCII_DEBUGTASKS	1

#define RASCII_DEBUGTASKMASK	1

char *ArgusDebugModes[RASCII_MAXDEBUG] = {
   " ",
   "tasks",
};

static int argus_version = ARGUS_VERSION;

char *ArgusExpandBackticks(const char * const);
int RaParseEtherAddr (struct ArgusParserStruct *, char *);

int ArgusParseConversionFile(struct ArgusParserStruct *, char *);
void RaConvertReadFile (struct ArgusParserStruct *, struct ArgusInput *);
void RaConvertParseTitleString (char *);
int RaFlagsIndicationStatus[64];
int RaConvertParseDirLabel = 0;
int RaConvertParseStateLabel = 0;


unsigned int ArgusSourceId = 0;
unsigned int ArgusIdType = 0;


int
main (int argc, char **argv) {
#if !defined(CYGWIN)
   extern char *optarg;
#endif
   int ArgusExitStatus;
   int i, cc;

#if defined(ARGUS_THREADS)
   pthread_attr_t attr;
#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN)
   int thread_policy;
   struct sched_param thread_param;
#if defined(HAVE_SCHED_GET_PRIORITY_MIN)
   int rr_min_priority, rr_max_priority;
#endif
#endif
   int status;
   size_t stacksize;
#endif

   for (i = 0, cc = 0; i < argc; i++)
      cc += strlen(argv[i]);

   if (strchr (argv[0], '/'))
      argv[0] = strrchr(argv[0], '/') + 1;

   if ((ArgusParser = ArgusNewParser(argv[0])) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewParser failed %s", strerror(errno));

#if defined(ARGUS_THREADS)
   if ((status = pthread_attr_init(&attr)) != 0)
      ArgusLog (LOG_ERR, "pthreads init error");
 
#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN)
   if ((status = pthread_attr_getschedpolicy(&attr, &thread_policy)) != 0)
      ArgusLog (LOG_ERR, "pthreads get policy error");
   if ((status = pthread_attr_getschedparam(&attr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads get sched params error");
   if ((status = pthread_attr_setschedpolicy(&attr, SCHED_RR)) != 0)
      ArgusLog (LOG_ERR, "pthreads set SCHED_RR error");

#if defined(HAVE_SCHED_GET_PRIORITY_MIN)
   if ((rr_min_priority = sched_get_priority_min(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority min error");
   if ((rr_max_priority = sched_get_priority_max(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority max error");

   thread_param.sched_priority = (rr_max_priority + rr_min_priority)/2 + 1;

   if (thread_param.sched_priority > rr_max_priority)
      thread_param.sched_priority = rr_max_priority;
   if (thread_param.sched_priority < (rr_max_priority - 8))
      thread_param.sched_priority = rr_max_priority - 8;

   if ((status = pthread_attr_setschedparam(&attr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads set sched param error");
#endif
#else
   pthread_attr_setschedpolicy(&attr, SCHED_RR);
#endif

#if defined(_POSIX_THREAD_ATTR_STACKSIZE)
#define ARGUS_MIN_STACKSIZE	524288

   if (pthread_attr_getstacksize(&attr, &stacksize))
      ArgusLog (LOG_ERR, "pthreads get stacksize error");

   if (stacksize < ARGUS_MIN_STACKSIZE) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "setting stacksize from %d to %d", stacksize, ARGUS_MIN_STACKSIZE);
#endif
      if (pthread_attr_setstacksize(&attr, ARGUS_MIN_STACKSIZE))
         ArgusLog (LOG_ERR, "pthreads set stacksize error");
   }
#endif
 
   pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
#endif

   ArgusMainInit (ArgusParser, argc, argv);
   ArgusClientInit (ArgusParser);
 
   if (ArgusParser->ArgusInputFileList == NULL)
      if (!(ArgusAddFileList (ArgusParser, "-", ARGUS_DATA_SOURCE, -1, -1)))
         ArgusLog(LOG_ERR, "%s: error: file arg %s", *argv, optarg);

/*
   OK now we're ready.  Read in all the files, for as many passes as
   needed, and then attach to any remote sources as a group until
   they close, then we're done.
*/

   if (ArgusParser->ArgusInputFileList != NULL) {
      struct ArgusInput *input;
      struct ArgusFileInput *file;

      while (ArgusParser->ArgusPassNum) {
         if ((input = ArgusMalloc(sizeof(*input))) == NULL)
            ArgusLog(LOG_ERR, "unable to allocate input structure\n");

         file = ArgusParser->ArgusInputFileList;
         while (file && ArgusParser->eNflag) {

            ArgusInputFromFile(input, file);
            ArgusParser->ArgusCurrentInput = input;

            if (strcmp (file->filename, "-")) {
               RaConvertReadFile(ArgusParser, input);
            } else {
               if (ArgusParser->ArgusPassNum == 1)
                  RaConvertReadFile(ArgusParser, input);
            }

#ifdef ARGUSDEBUG
            ArgusDebug (1, "main: RaConvertReadFile(%s) done", file->filename);
#endif
            RaArgusInputComplete(input);
            ArgusParser->ArgusCurrentInput = NULL;
            file = (struct ArgusFileInput *)file->qhdr.nxt;
         }

         ArgusParser->ArgusPassNum--;
      }

      ArgusDeleteInput(ArgusParser, input);
      input = NULL;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "main: reading files completed");
#endif

   ArgusParser->RaParseDone++;
   ArgusExitStatus = ArgusParser->ArgusExitStatus;
   ArgusCloseParser(ArgusParser);
   exit (ArgusExitStatus);
}

extern char version[];

void
usage () {
   fprintf (stdout, "RaConvert Version %s\n", version);
   fprintf (stdout, "usage: %s options\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -r <input>  specify input ascii file name.\n");
   fprintf (stdout, "         -w <output> specify output argus data file.\n");
   fflush (stdout);
   exit(1);
}


void
ArgusClientInit(struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   int i, x, ind;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaConvertInit()");
#endif

   gettimeofday(&ArgusParser->ArgusRealTime, 0);

   if ((mode = ArgusParser->ArgusModeList) != NULL) {
      while (mode) {
// Scan the modes	      
         for (i = 0, ind = -1; i < RASCII_MAXMODES; i++) {
            if (!(strncasecmp (mode->mode, RaConvertDaemonModes[i], 3))) {
               ind = i;
               switch (ind) {
                  case RASCIIDEBUG:
                     if ((mode = mode->nxt) == NULL)
                        usage();
                     break;
               }
            }
         }
         if (ind < 0)
            usage();

         switch (ind) {
            case RASCIIDEBUG: {
// Scan the debug modes	      
               for (x = 0, ind = -1; x < RASCII_MAXDEBUG; x++) {
                  if (!(strncasecmp (mode->mode, ArgusDebugModes[x], 3))) {
                     ArgusDebugMode |= 0x01 << x;
                     switch (ind) {
                        case RASCII_DEBUGTASKS:
                           break;
                     }
                  }
               }
               break;
            }

            default:
               usage();
               break;
         }

         mode = mode->nxt;
      }
   }

/*
struct ArgusRecord {
   struct ArgusRecordHeader hdr;
   union {
      struct ArgusMarStruct mar;
      struct ArgusFarStruct far;
   } ar_un;
};
  
struct ArgusMarStruct {
   unsigned int status, argusid;
   unsigned int localnet, netmask, nextMrSequenceNum;
   struct ArgusTime startime, now;
   unsigned char  major_version, minor_version;
   unsigned char interfaceType, interfaceStatus;
   unsigned short reportInterval, argusMrInterval;
   unsigned long long pktsRcvd, bytesRcvd;
   long long drift;
 
   unsigned int records, flows, dropped;
   unsigned int queue, output, clients;
   unsigned int bufs, bytes;
   unsigned int pad[4];
   unsigned int thisid, record_len;
};
*/

   if (ArgusParser->ArgusFlowModelFile != NULL)
      ArgusParseConversionFile(ArgusParser, ArgusParser->ArgusFlowModelFile);

   ArgusParser->ArgusInitCon.hdr.type                    = (ARGUS_MAR | ARGUS_VERSION);
   ArgusParser->ArgusInitCon.hdr.cause                   = ARGUS_START;
   ArgusParser->ArgusInitCon.hdr.len                     = (unsigned short) (sizeof(struct ArgusMarStruct) + 4)/4;
   ArgusParser->ArgusInitCon.argus_mar.thisid            = ArgusSourceId;
   ArgusParser->ArgusInitCon.argus_mar.argusid           = ARGUS_COOKIE;
 
   ArgusParser->ArgusInitCon.argus_mar.startime.tv_sec   = ArgusParser->ArgusRealTime.tv_sec;
   ArgusParser->ArgusInitCon.argus_mar.startime.tv_usec  = ArgusParser->ArgusRealTime.tv_usec;
   ArgusParser->ArgusInitCon.argus_mar.now.tv_sec        = ArgusParser->ArgusRealTime.tv_sec;
   ArgusParser->ArgusInitCon.argus_mar.now.tv_usec       = ArgusParser->ArgusRealTime.tv_usec;

   ArgusParser->ArgusInitCon.argus_mar.major_version     = VERSION_MAJOR;
   ArgusParser->ArgusInitCon.argus_mar.minor_version     = VERSION_MINOR;
   ArgusParser->ArgusInitCon.argus_mar.reportInterval    = 0;
   ArgusParser->ArgusInitCon.argus_mar.argusMrInterval   = 0;

   ArgusParser->ArgusInitCon.argus_mar.record_len        = -1;

   ArgusHtoN(&ArgusParser->ArgusInitCon);
}


void
RaConvertParseTitleString (char *str)
{
   char *buf, *ptr, *obj;
   int i, len = 0, items = 0;

   if ((buf = ArgusCalloc (1, ARGUSMAXSTR)) != NULL) {
      bzero ((char *)RaParseAlgorithms, sizeof(RaParseAlgorithms));

      if ((ptr = strchr(str, '\n')) != NULL)
         *ptr = '\0';

      ptr = buf;
      bcopy (str, buf, strlen(str));
      while (isspace((int)*ptr)) ptr++;

// Lets determine the delimiter, if we need to.  This will make this go a bit faster

      for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
         len = strlen(RaParseAlgorithmTable[i].title);
         if (!(strncmp(RaParseAlgorithmTable[i].title, ptr, len))) {
            ptr += len;
            if (RaConvertFieldDelimiter[0] == '\0')
               RaConvertFieldDelimiter[0] = *ptr++;
            else {
               if (*ptr && (RaConvertFieldDelimiter[0] != *ptr++))
                  ArgusLog (LOG_ERR, "RaConvertFrontList: title format error: inconsistent delimiter: %s", str);
            }
            break;
         }
      }

      ptr = buf;

      while ((obj = strtok(ptr, RaConvertFieldDelimiter)) != NULL) {
         int found = 0;
         len = strlen(obj);
         if (len > 0) {
            for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
               if (!(strncmp(RaParseAlgorithmTable[i].title, obj, len))) {
                  RaParseAlgorithmIndex++;
                  RaParseAlgorithms[items] = &RaParseAlgorithmTable[i];
                  if (strcmp("Dir",obj) == 0)   RaConvertParseDirLabel++;
                  if (strcmp("State",obj) == 0)   RaConvertParseStateLabel++;
                  found++;
                  break;
               }
            }
            if (!found) 
               ArgusLog (LOG_ERR, "RaConvertList: unsupported field conversion: '%s'", obj);
         }

         items++;
         ptr = NULL;
      }
      ArgusProcessTitleString = 1;
      ArgusFree(buf);

   } else
      ArgusLog (LOG_ERR, "RaConvertParseTitleString: ArgusCalloc error %s", strerror(errno));

#ifdef ARGUSDEBUG
   ArgusDebug (9, "RaConvertParseTitleString('%s') done", str);
#endif
}


int RaConvertParseRecordString (struct ArgusParserStruct *, char *, int);
int RaConvertJsonValue (struct ArgusParserStruct *, ArgusJsonValue *);

unsigned int ArgusRecordSequence = 1;
int ArgusParseDirStatus = 0;
int ArgusConvertParseState = 0;
extern int ArgusThisProto;


#define ARGUS_PARSING_KEY	0
#define ARGUS_PARSING_VALUE	1

int ArgusProcessJsonItem(struct ArgusParserStruct *, char *, ArgusJsonValue *);

int
ArgusProcessJsonItem(struct ArgusParserStruct *parser, char *key, ArgusJsonValue *item) 
{
   char valbuf[32], *val = valbuf;
   char *value = NULL, *buf = NULL;
   int retn = 1, i;

   switch (item->type) {
      case ARGUS_JSON_BOOL:
         sprintf(val, "%c", (item->value.boolean) ? 'T': 'F');
         break;
      case ARGUS_JSON_INTEGER: {
         sprintf(val, "%d", (int) item->value.number);
         break;
      }
      case ARGUS_JSON_DOUBLE: {
         sprintf(val, "%f", item->value.number);
         break;
      }
      case ARGUS_JSON_STRING: {
         val = item->value.string;
         break;
      }
      case ARGUS_JSON_ARRAY: {
         if ((buf = ArgusCalloc (1, MAXSTRLEN)) != NULL) {
            val = buf;
            ArgusJsonPrint(item, val, MAXSTRLEN);
	    if (strchr(val, ']') == NULL) {
	       int slen = strlen(val);
	       while ((val[slen] != ',') && (slen > 0)) slen--;
	       val[slen] = ']';
	       val[slen + 1] = '\0';
	    }
         }
         break;
      }
   }

   for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
      int len = strlen(RaParseAlgorithmTable[i].field);
      if (!(strncmp(RaParseAlgorithmTable[i].field, key, len))) {
         if (RaParseAlgorithmTable[i].parse == ArgusParseLabel) {
            if ((value = ArgusCalloc (1, MAXSTRLEN)) != NULL) {
               snprintf (value, ARGUSMAXSTR, "%s=%s", key, val);
               val = value;
            }
         }
         RaParseAlgorithmTable[i].parse(parser, val);
         if (i == ARGUSPARSEDIR)
            RaConvertParseDirLabel = 1;
         if (i == ARGUSPARSESTATE)
            RaConvertParseStateLabel = 1;
      } 
   }

   if (buf != NULL)
      ArgusFree (buf);
   if (value != NULL)
      ArgusFree(value);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessJsonItem(%p, '%s', '%s') returning %d", parser, key, val, retn);
#endif
   return retn;
}

int
RaConvertJsonValue (struct ArgusParserStruct *parser, ArgusJsonValue *parent) {
   int retn = 1, i;

   if (parent->type == ARGUS_JSON_OBJECT) {
      vector *vec = (vector *) &parent->value.array;
      ArgusJsonValue *item = (ArgusJsonValue *)vec->data;
      int state = ARGUS_PARSING_KEY;
      char *key = NULL;

      for (i = 0; i < vec->size; i++) {
         switch (item->type) {
            case ARGUS_JSON_KEY: {
               key = item->value.string;
               state = ARGUS_PARSING_VALUE;
               break;
            }

            case ARGUS_JSON_BOOL:
            case ARGUS_JSON_INTEGER:
            case ARGUS_JSON_DOUBLE:
            case ARGUS_JSON_STRING: {
               if (state == ARGUS_PARSING_VALUE) {
                  retn = ArgusProcessJsonItem(parser, key, item);
                  state = ARGUS_PARSING_KEY;
	       }
               break;
            }
            case ARGUS_JSON_OBJECT: {
               break;
            }
            case ARGUS_JSON_ARRAY: {
               if (state == ARGUS_PARSING_VALUE) {
                  retn = ArgusProcessJsonItem(parser, key, item);
                  state = ARGUS_PARSING_KEY;
	       }
               break;
            }
         }
         item = (ArgusJsonValue *)((char *)item + vec->data_size);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (9, "RaConvertJsonValue(%p, %p) returning %d", parser, parent, retn);
#endif
   return retn;
}

int
RaConvertParseRecordString (struct ArgusParserStruct *parser, char *str, int slen)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   int retn = 1, numfields = 1, i;
   char *argv[ARGUS_MAX_PRINT_FIELDS], **ap = argv;
   char delim[16], *ptr, *tptr, *tok;

   if (str != NULL) {
      if ((ptr = strchr(str, '\n')) != NULL)
         *ptr = '\0';

      ptr = str;
      bzero (argv, sizeof(argv));
      bzero ((char *)argus, sizeof(*argus));

      bzero (delim, sizeof(delim));

      bzero ((char *)&parser->argus, sizeof(parser->argus));
      bzero ((char *)&parser->canon, sizeof(parser->canon));

      ArgusThisProto = 0;

      while (isspace((int)*ptr)) ptr++;
      sprintf (delim, "%c", RaConvertFieldDelimiter[0]);
      tptr = ptr;

      if (strchr (ptr, '{')) {
         ArgusJsonValue l1root, *res1 = NULL;
         bzero(&l1root, sizeof(l1root));

         if ((res1 = ArgusJsonParse(ptr, &l1root)) != NULL) {
            retn = RaConvertJsonValue(parser, res1);
            numfields = ARGUS_MAX_PRINT_FIELDS;
         }

      } else {
         while ((tok = strchr(tptr, RaConvertFieldDelimiter[0])) != NULL) {
            *tok++ = '\0';
            if (strlen(tptr))
               *ap = tptr;
            else
               *ap = NULL;
      
            numfields++;
            if (++ap >= &argv[ARGUS_MAX_PRINT_FIELDS])
               break;
            tptr = tok;
         }
         if (strlen(tptr)) {
            *ap = tptr;
            numfields++;
         }
      }

      for (i = 0; i < numfields; i++) {
            if (RaParseAlgorithms[i] != NULL) {
               if ((argv[i] != NULL) && strlen(argv[i]) && strcmp(argv[i], "-")) {
                  char *value = NULL;
                  if ((value = (char *)ArgusCalloc(1, ARGUSMAXSTR)) != NULL) {
                     if (RaParseAlgorithms[i]->parse == ArgusParseLabel) {
                        snprintf (value, ARGUSMAXSTR, "%s=%s", RaConvertOptionStrings[i], argv[i]);
	             } else {
                        snprintf(value, ARGUSMAXSTR, "%s", argv[i]);
	             }

                     RaParseAlgorithms[i]->parse(ArgusParser, value);
                     ArgusFree(value);
                     switch (parser->argus.hdr.type) {
                        case ARGUS_MAR:
                        case ARGUS_EVENT:
                           return(retn);
                           break;
                     }

	          } else
                     ArgusLog (LOG_ERR, "RaConvertParseRecordString: ArgusCalloc error %s", strerror(errno));
               }
            }
      }

      if (argus->dsrs[ARGUS_TRANSPORT_INDEX] == NULL) {
            argus->dsrs[ARGUS_TRANSPORT_INDEX] = &parser->canon.trans.hdr;
            argus->dsrindex |= 0x1 << ARGUS_TRANSPORT_INDEX;

            bcopy(&parser->trans, &parser->canon.trans, sizeof(parser->trans));
            parser->canon.trans.seqnum = ArgusRecordSequence++;
            if (ArgusRecordSequence == 0) ArgusRecordSequence++;
      }

      if (RaConvertParseDirLabel) {
            struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) &parser->canon.net;
            if (net) {
               switch (net->hdr.subtype) {
                  case ARGUS_TCP_INIT:
                  case ARGUS_TCP_STATUS:
                  case ARGUS_TCP_PERF: {
                     struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                     tcp->status |= ArgusParseDirStatus;
                  }
               }
            }
      }
      if (RaConvertParseStateLabel) {
            struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) &parser->canon.net;
            if (net) {
               switch (net->hdr.subtype) {
                  case ARGUS_TCP_INIT:
                  case ARGUS_TCP_STATUS:
                  case ARGUS_TCP_PERF: {
                     struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                     tcp->status |= ArgusConvertParseState;
                  }
               }
            }
      }

      if (RaFlagsIndicationStatus[3] != 0) {
            switch (parser->canon.flow.hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4: {
                  switch (parser->canon.flow.ip_flow.ip_p) {
                     case IPPROTO_TCP: {
                        struct ArgusNetworkStruct *net;
                        struct ArgusTCPObject *tcp;
                        if ((net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX]) == NULL) {
                           argus->dsrs[ARGUS_NETWORK_INDEX] = &parser->canon.net.hdr;
                           argus->dsrindex |= 0x1 << ARGUS_NETWORK_INDEX;
                           net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX];
                           net->hdr.type    = ARGUS_NETWORK_DSR;
                           net->hdr.subtype = ARGUS_TCP_INIT;
                           net->hdr.argus_dsrvl8.len = ((sizeof(*tcp) + 3)/4) + 1;
                        }
                        tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                        tcp->status |= RaFlagsIndicationStatus[3];
                     }
                  }
                  break;
               }
            }
      }

      if (argus->dsrs[ARGUS_METRIC_INDEX] != NULL) {
         if ((parser->canon.metric.src.pkts == 0) && (parser->canon.metric.dst.pkts == 0))
            retn = 0;
      } else
         retn = 0;

   } else
      retn = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (9, "RaConvertParseRecordString('%s') returning %d", str, retn);
#endif

   return (retn);
}


int RaPrintCounter = 1;
char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];

void
RaConvertReadFile (struct ArgusParserStruct *parser, struct ArgusInput *input)
{
   FILE *fd = NULL;
   char *file = input->filename;
   int retn = 0, sNflag = 0, eNflag = 0;

   if ((ArgusParser->sNoflag > 0) || (ArgusParser->eNoflag > 0)) {
      sNflag = ArgusParser->sNoflag;
      eNflag = ArgusParser->eNoflag;
   }

   if ((ArgusParser->sNflag > 0) || (ArgusParser->eNflag > 0)) {
      sNflag = ArgusParser->sNflag;
      eNflag = ArgusParser->eNflag;
   }

   if (strcmp (file, "-")) {
      if ((!(strncmp(".gz", &file[strlen(file) - 3], 3))) ||
          (!(strncmp("-gz", &file[strlen(file) - 3], 3))) ||
          (!(strncmp(".z",  &file[strlen(file) - 2], 2))) ||
          (!(strncmp("-z",  &file[strlen(file) - 2], 2))) ||
          (!(strncmp("_z",  &file[strlen(file) - 2], 2))) ||
          (!(strncmp(".Z",  &file[strlen(file) - 2], 2)))) {
         char cmd[256];
         bzero(cmd, 256); 
         strncpy(cmd, "gzip -dc ", 10);

         strncat(cmd, input->filename, (256 - strlen(cmd)));
         strncat(cmd, " 2>/dev/null", (256 - strlen(cmd)));

         if ((input->pipe = popen(cmd, "r")) == NULL)
            ArgusLog (LOG_ERR, "ArgusReadConnection: popen(%s) failed. %s", cmd, strerror(errno));

         fd = input->pipe;
#ifdef ARGUSDEBUG
         ArgusDebug (7, "uncompressing '%s'", file);
#endif
      } else       
      if ((!(strncmp(".bz2", &file[strlen(file) - 4], 4))) ||
          (!(strncmp(".bz",  &file[strlen(file) - 3], 3)))) {
         char cmd[256];
         bzero(cmd, 256);
         strncpy(cmd, "bzip2 -dc ", 11);

         strncat(cmd, input->filename, (256 - strlen(cmd)));
         strncat(cmd, " 2>/dev/null", (256 - strlen(cmd)));

         if ((input->pipe = popen(cmd, "r")) == NULL)
            ArgusLog (LOG_ERR, "ArgusReadConnection: popen(%s) failed. %s", cmd, strerror(errno));

         fd = input->pipe;
#ifdef ARGUSDEBUG
         ArgusDebug (7, "uncompressing '%s'", file);
#endif

      } else {
         if ((fd = fopen(file, "r")) == NULL) {
#ifdef ARGUSDEBUG
            ArgusDebug (0, "open '%s': %s", file, strerror(errno));
#endif
         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (7, "RaConvertReadFile: opened %s", file);
#endif
         }
      }

   } else 
      fd = stdin;

   if (fd != NULL) {
      char *strbuf = NULL, *str;
      size_t len = ARGUSMAXSTR, slen;
      int line = 0, done = 0;

      if ((strbuf = ArgusCalloc (1, ARGUSMAXSTR)) == NULL)
         ArgusLog (LOG_ERR, "%s: ArgusCalloc error\n", __func__, strerror(errno));

      while (!done && ((slen = getline(&strbuf, &len, fd)) != -1)) {
         int i;
         str = strbuf;
         line++;

         if (line == 1) {
            for (i = 0; i < slen; i++) {
               if (!(isascii((int) str[i]))) {
                  ArgusLog (LOG_INFO, "RaConvertReadFile: file '%s' not ascii", file);
                  done++;
                  break;
               }
            }
            ArgusProcessTitleString = 0;
            if (*str == '{')
               ArgusProcessTitleString = 1;
         }

         if ((*str != '#') && (slen > 1)) {
            if (ArgusProcessTitleString) {
               struct ArgusRecordStruct *argus = &parser->argus;

               if (RaConvertParseRecordString(parser, str, slen)) {
                  if (parser->ArgusWfileList != NULL) {
                     struct ArgusWfileStruct *wfile = NULL;
                     struct ArgusListObjectStruct *lobj = NULL;
                     int i, count = parser->ArgusWfileList->count;
 
                     if ((lobj = parser->ArgusWfileList->start) != NULL) {
                        for (i = 0; i < count; i++) {
                           if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                              retn = 1;
                              if (wfile->filterstr) {
                                 struct nff_insn *wfcode = wfile->filter.bf_insns;
                                 retn = ArgusFilterRecord (wfcode, argus);
                              }
 
                              if (retn != 0) {
                                 if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                                    struct ArgusRecord *argusrec = NULL;
                                    int rv;

                                       if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
                                          ArgusHtoN(argusrec);
#endif
                                          rv = ArgusWriteNewLogfile (parser, input, wfile, argusrec);
                                          if (rv < 0)
                                             ArgusLog (LOG_ERR, "%s: unable to open file\n", __func__);
                                       }
                                    }
                                 }
                              }
                           }
 
                           lobj = lobj->nxt;
                        }
                     } else {

                     if (!parser->qflag) {
                        char *buf = NULL;
                        int retn = 0;

                        if ((buf = ArgusCalloc (1, ARGUSMAXSTR)) != NULL) {
                           argus->rank = RaPrintCounter++;

			      if (parser->Lflag && (!(ArgusParser->ArgusPrintJson))) {
                              if (parser->RaLabel == NULL)
                                 parser->RaLabel = ArgusGenerateLabel(parser, argus);

                              if (!(parser->RaLabelCounter++ % parser->Lflag))
                                 if ((retn = printf ("%s\n", parser->RaLabel)) < 0)
                                    RaParseComplete (SIGQUIT);

                              if (parser->Lflag < 0)
                                 parser->Lflag = 0;
                           }

                           if ((eNflag == 0 ) || ((eNflag >= argus->rank) && (sNflag <= argus->rank))) {
                              ArgusPrintRecord(parser, buf, argus, ARGUSMAXSTR);
                  
                              if ((retn = fprintf (stdout, "%s", buf)) < 0)
                                 RaParseComplete (SIGQUIT);
                  
                              if (parser->eflag == ARGUS_HEXDUMP) {
                                 char *sbuf;
                                 int i;

                                 if ((sbuf = ArgusCalloc(1, 65536)) == NULL)
                                    ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusCalloc error");

                                 for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
                                    if (ArgusParser->RaPrintAlgorithmList[i] != NULL) {
                                       struct ArgusDataStruct *user = NULL;
                                       if (ArgusParser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcUserData) {
                                          int slen = 0, len = ArgusParser->RaPrintAlgorithmList[i]->length;
                                          if (len > 0) {
                                             if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) != NULL) {
                                                if (user->hdr.type == ARGUS_DATA_DSR) {
                                                   slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                                                } else
                                                   slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

                                                slen = (user->count < slen) ? user->count : slen;
                                                slen = (slen > len) ? len : slen;
                                                ArgusDump ((const u_char *) &user->array, slen, "      ", sbuf);
                                                printf ("%s\n", sbuf);
                                             }
                                          }
                                       }
                                       if (ArgusParser->RaPrintAlgorithmList[i]->print == ArgusPrintDstUserData) {
                                          int slen = 0, len = ArgusParser->RaPrintAlgorithmList[i]->length;
                                          if (len > 0) {
                                             if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) != NULL) {
                                                if (user->hdr.type == ARGUS_DATA_DSR) {
                                                   slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                                                } else
                                                   slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

                                                slen = (user->count < slen) ? user->count : slen;
                                                slen = (slen > len) ? len : slen;
                                                ArgusDump ((const u_char *) &user->array, slen, "      ", sbuf);
                                                printf ("%s\n", sbuf);
                                             }
                                          }
                                       }
                                    } else
                                       break;
                                 }
                                 ArgusFree(sbuf);
                              }
                     
                              fprintf (stdout, "\n");
                              fflush (stdout);

                           } else {
                              if ((eNflag != 0 ) && (eNflag < argus->rank))
                                 RaParseComplete (SIGQUIT);
                           }
                           ArgusFree(buf);
                        } else 
                           ArgusLog (LOG_ERR, "RaConvertReadFile: ArgusCalloc: error %s", strerror(errno));
                     }
                  }
               }
            } else {
               RaConvertParseTitleString(str);
               ArgusProcessTitleString = 1;
            }
         }
      }

      ArgusFree(strbuf);

      if (!(feof(fd)) && ferror(fd))
         ArgusLog (LOG_ERR, "getline: error %s", strerror(errno));
   }

   if (fd)
      fclose(fd);

   if (input->pipe)
      pclose(input->pipe);

#ifdef ARGUSDEBUG
   ArgusDebug (9, "RaConvertReadFile('%s') done", file);
#endif
}


char *RaDateFormat = "%m/%d.%H:%M:%S";

#define RACONVERTTIME	6

char *RaConvertTimeFormats[RACONVERTTIME] = {
   NULL,
   "%Y/%m/%d %T",
   "%Y/%m/%d.%T",
   "%Y/%m/%d.%H:%M:%S",
   "%H:%M:%S",
   "%T",
};

struct tm timebuf, *RaConvertTmPtr = NULL;
extern char *strptime(const char *s, const char *format, struct tm *tm);

void
ArgusParseRank (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   unsigned int value = strtol(buf, &endptr, 10);
   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseRank(0x%xs, %s) format error\n", parser, buf);

   argus->rank = value;
}

void
ArgusParseAutoId (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   unsigned int value = strtol(buf, &endptr, 10);
   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseAutoId(0x%xs, %s) format error\n", parser, buf);

   argus->autoid = value;
}

void
ArgusParseStartDate (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *ptr, date[128], *frac;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   int i, len, unixtime = 1;
   char *endptr;
   int done = 0;

   bzero (date, sizeof(date));
   bzero (tvp, sizeof(*tvp));

   bcopy (buf, date, strlen(buf));

   if (RaConvertTmPtr == NULL) {
      gettimeofday(tvp, 0);
      if ((RaConvertTmPtr = localtime(&tvp->tv_sec)) == NULL)
         ArgusLog (LOG_ERR, "ArgusParseStartDate(0x%xs, %s) localtime error\n", parser, buf, strerror(errno));
      bcopy ((char *)RaConvertTmPtr, (char *)&timebuf, sizeof (timebuf));
      RaConvertTmPtr = &timebuf;
   }

   if ((frac = strrchr(date, '.')) != NULL) {
      int useconds = 0, precision;
      int flen;
      char tdate[128];

      flen = (frac - date);

      bcopy(date, tdate, flen);

      *frac++ = '\0';
      useconds = strtol(frac, &endptr, 10);
      if (endptr == frac)
         ArgusLog (LOG_ERR, "ArgusParseStartDate(0x%xs, %s) fractonal format error\n", parser, buf);

      if (*endptr != '\0') {
         while (*endptr != '\0')  
            date[flen++] = *endptr++;
         date[flen] = '\0';
      }
         
      if ((precision = strlen(frac)) > 0) {
         int n, power = 6 - precision;

         for (n = 0; n < power; n++)
            useconds *= 10;
      }

      tvp->tv_usec = useconds;
   }

   if (RaDateFormat != NULL) {
      if ((ptr = strptime(date, RaDateFormat, RaConvertTmPtr)) != NULL) {
         if (*ptr == '\0') {
            done++;
            tvp->tv_sec = mktime(RaConvertTmPtr);
         }
      }

   } else {
      ptr = date;
      len = strlen(ptr);

      for (i = 0; i < len; i++) {
         if (!(isdigit((int)ptr[i]))) {
            unixtime = 0;
            break;
         }
      }

      if (unixtime) {
         tvp->tv_sec = strtol(date, &endptr, 10);
         if (endptr == date)
            ArgusLog (LOG_ERR, "ArgusParseStartDate(0x%xs, %s) fractonal format error\n", parser, buf);
      } else {
         if (RaConvertTimeFormats[0] == NULL) {
            char *sptr;
            RaConvertTimeFormats[0] = strdup(RaDateFormat);
            if ((sptr = strstr(RaConvertTimeFormats[0], ".%f")) != NULL) {
               
            }
         }

         for (i = 0; (i < RACONVERTTIME) && (!done); i++) {
            char *format = NULL;
            if ((format = RaConvertTimeFormats[i]) != NULL) {
               if ((ptr = strptime(date, format, RaConvertTmPtr)) != NULL) {
                  if (*ptr == '\0') {
                     done++;
                     RaDateFormat = format;
                  }
               }
            }
         }

         if (done) {
            tvp->tv_sec = mktime(RaConvertTmPtr);
         } else {
            ArgusLog (LOG_ERR, "ArgusParseStartTime(0x%xs, %s) time format not defined\n", parser, buf);
         }
      }
   }


   if (parser->canon.time.hdr.type == 0) {
      parser->canon.time.hdr.type    = ARGUS_TIME_DSR;	
      parser->canon.time.hdr.subtype = ARGUS_TIME_ABSOLUTE_TIMESTAMP;	
      parser->canon.time.hdr.subtype |= ARGUS_TIME_SRC_START;
      parser->canon.time.hdr.argus_dsrvl8.qual = ARGUS_TYPE_UTC_MICROSECONDS;
      parser->canon.time.hdr.argus_dsrvl8.len  = 3;
   }

   if (argus->dsrs[ARGUS_TIME_INDEX] == NULL) {
      argus->dsrs[ARGUS_TIME_INDEX] = &parser->canon.time.hdr;
      argus->dsrindex |= 0x1 << ARGUS_TIME_INDEX;
   }

   parser->canon.time.src.start.tv_sec  = tvp->tv_sec;
   parser->canon.time.src.start.tv_usec = tvp->tv_usec;

   parser->canon.time.dst.start.tv_sec  = tvp->tv_sec;
   parser->canon.time.dst.start.tv_usec = tvp->tv_usec;
}


void
ArgusParseLastDate (struct ArgusParserStruct *parser, char *buf)
{
}

void
ArgusParseType (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   int found = 0;

   if (strcmp("man", buf) == 0)  { argus->hdr.type |= ARGUS_MAR; found++; }
   if (strcmp("flow", buf) == 0) { argus->hdr.type |= ARGUS_FAR; found++; }
   if (strcmp("aflow", buf) == 0) { argus->hdr.type |= ARGUS_AFLOW; found++; }
   if (strcmp("nflow", buf) == 0) { argus->hdr.type |= ARGUS_NETFLOW; found++; }
   if (strcmp("index", buf) == 0) { argus->hdr.type |= ARGUS_INDEX; found++; }
   if (strcmp("supp", buf) == 0) { argus->hdr.type |= ARGUS_DATASUP; found++; }
   if (strcmp("archive", buf) == 0) { argus->hdr.type |= ARGUS_ARCHIVAL; found++; }
   if (strcmp("arch", buf) == 0) { argus->hdr.type |= ARGUS_ARCHIVAL; found++; }
   if (strcmp("event", buf) == 0) { argus->hdr.type |= ARGUS_EVENT; found++; }
   if (strcmp("evnt", buf) == 0) { argus->hdr.type |= ARGUS_EVENT; found++; }
   if (strcmp("unknown", buf) == 0) { found++; }

   if (!found)
      ArgusLog (LOG_ERR, "ArgusParseType(0x%xs, %s) type not found\n", parser, buf);
}

/*
   ArgusParseSourceID is provided in common/argus_util.c

void
ArgusParseSourceID (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   struct ArgusCIDRAddr *taddr = NULL;

   if ((taddr = RaParseCIDRAddr (parser, buf)) != NULL) {
      if (argus->dsrs[ARGUS_TRANSPORT_INDEX] == NULL) {
         argus->dsrs[ARGUS_TRANSPORT_INDEX] = &parser->canon.trans.hdr;
         argus->dsrindex |= 0x1 << ARGUS_TRANSPORT_INDEX;

         parser->canon.trans.hdr.type     = ARGUS_TRANSPORT_DSR;
         parser->canon.trans.hdr.subtype |= ARGUS_SRCID;
      }

      switch (taddr->type) {
         case AF_INET: {
            parser->canon.trans.hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
            parser->canon.trans.hdr.argus_dsrvl8.len  = 3;
            parser->canon.trans.srcid.a_un.value = *taddr->addr;
            break;
         }
         case AF_INET6: {
            parser->canon.trans.hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV6;
            parser->canon.trans.hdr.argus_dsrvl8.len  = 6;
            break;
         }
      }

   } else {

   }
}
*/


#include <argus_encapsulations.h>


void
ArgusParseFlags (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char str[16];
   int len;

   bzero(RaFlagsIndicationStatus, sizeof(RaFlagsIndicationStatus));

   if ((len = strlen(buf)) > 16)
      len = 16;

   bcopy (buf, str, len);

   if (str[0] == 'N') ArgusInputType = ARGUS_NETFLOW;
   if (str[0] == 'A') ArgusInputType = ARGUS_AFLOW;
   if (str[0] == 'T') parser->canon.time.hdr.argus_dsrvl8.qual |= ARGUS_TIMEADJUST;

   if (str[1] != ' ') {
      if (argus->dsrs[ARGUS_ENCAPS_INDEX] == NULL) {
         argus->dsrs[ARGUS_ENCAPS_INDEX] = &parser->canon.encaps.hdr;
         argus->dsrindex |= 0x1 << ARGUS_ENCAPS_INDEX;
         parser->canon.encaps.hdr.type = ARGUS_ENCAPS_DSR;
         parser->canon.encaps.hdr.argus_dsrvl8.len   = (sizeof(parser->canon.encaps) + 3)/4;
      }
      switch (str[1]) {
         case '*':
         case 'e': 
            parser->canon.encaps.src |= ARGUS_ENCAPS_ETHER; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_ETHER; 
            break;
         case 'M': {
            if (argus->dsrs[ARGUS_MAC_INDEX] == NULL) {
               struct ArgusMacStruct *mac = (struct ArgusMacStruct *) argus->dsrs[ARGUS_MAC_INDEX];
               if (mac == NULL) {
                  argus->dsrs[ARGUS_MAC_INDEX] = &parser->canon.mac.hdr;
                  argus->dsrindex |= 0x1 << ARGUS_MAC_INDEX;
                  mac = (struct ArgusMacStruct *) argus->dsrs[ARGUS_MAC_INDEX];
                  mac->hdr.type = ARGUS_MAC_DSR;
                  mac->hdr.argus_dsrvl8.len = 0;
               }
               mac->hdr.argus_dsrvl8.qual |= ARGUS_MULTIPATH;
            }
            break;
         }
         case 'm':
            parser->canon.encaps.src |= ARGUS_ENCAPS_MPLS; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_MPLS; 
            break;
         case 'l':
            parser->canon.encaps.src |= ARGUS_ENCAPS_LLC; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_LLC; 
            break;
         case 'v':
            parser->canon.encaps.src |= ARGUS_ENCAPS_8021Q; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_8021Q; 
            break;
         case 'w':
            parser->canon.encaps.src |= ARGUS_ENCAPS_802_11; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_802_11; 
            break;
         case 'p':
            parser->canon.encaps.src |= ARGUS_ENCAPS_PPP; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_PPP; 
            break;
         case 'i':
            parser->canon.encaps.src |= ARGUS_ENCAPS_ISL; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_ISL; 
            break;
         case 'G':
            parser->canon.encaps.src |= ARGUS_ENCAPS_GRE; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_GRE; 
            break;
         case 'a':
            parser->canon.encaps.src |= ARGUS_ENCAPS_AVS; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_AVS; 
            break;
         case 'P':
            parser->canon.encaps.src |= ARGUS_ENCAPS_IP; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_IP; 
            break;
         case '6':
            parser->canon.encaps.src |= ARGUS_ENCAPS_IPV6; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_IPV6; 
            break;
         case 'H':
            parser->canon.encaps.src |= ARGUS_ENCAPS_HDLC; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_HDLC; 
            break;
         case 'C':
            parser->canon.encaps.src |= ARGUS_ENCAPS_CHDLC; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_CHDLC; 
            break;
         case 'A':
            parser->canon.encaps.src |= ARGUS_ENCAPS_ATM; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_ATM; 
            break;
         case 'S':
            parser->canon.encaps.src |= ARGUS_ENCAPS_SLL; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_SLL; 
            break;
         case 'F':
            parser->canon.encaps.src |= ARGUS_ENCAPS_FDDI; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_FDDI; 
            break;
         case 's':
            parser->canon.encaps.src |= ARGUS_ENCAPS_SLIP; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_SLIP; 
            break;
         case 'R':
            parser->canon.encaps.src |= ARGUS_ENCAPS_ARCNET; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_ARCNET; 
            break;
      }
   }

   if (str[2] != ' ') {
      if (argus->dsrs[ARGUS_ICMP_INDEX] == NULL) {
         argus->dsrs[ARGUS_ICMP_INDEX] = &parser->canon.icmp.hdr;
         argus->dsrindex |= 0x1 << ARGUS_ICMP_INDEX;
         parser->canon.icmp.hdr.type = ARGUS_ICMP_DSR;
         parser->canon.icmp.hdr.argus_dsrvl8.qual |= ARGUS_ICMP_MAPPED;
         parser->canon.icmp.hdr.argus_dsrvl8.len   = (sizeof(parser->canon.icmp) + 3)/4;
      }
      switch (str[1]) {
         case 'I':
         case 'U': 
         case 'R':
         case 'T':
            break;
      }
   }

   if (str[3] != ' ') {
      switch (str[3]) {
         case '*': RaFlagsIndicationStatus[3] = ARGUS_SRC_PKTS_RETRANS | ARGUS_DST_PKTS_RETRANS; break;
         case 's': RaFlagsIndicationStatus[3] = ARGUS_SRC_PKTS_RETRANS; break;
         case 'd': RaFlagsIndicationStatus[3] = ARGUS_DST_PKTS_RETRANS; break;
         case '&': RaFlagsIndicationStatus[3] = ARGUS_SRC_OUTOFORDER | ARGUS_DST_OUTOFORDER; break;
         case 'i': RaFlagsIndicationStatus[3] = ARGUS_SRC_OUTOFORDER; break;
         case 'r': RaFlagsIndicationStatus[3] = ARGUS_DST_OUTOFORDER; break;
      }
   }

   if (str[4] != ' ') {
      switch (str[4]) {
         case '@': RaFlagsIndicationStatus[4] = ARGUS_SRC_WINDOW_SHUT | ARGUS_DST_WINDOW_SHUT; break;
         case 'S': RaFlagsIndicationStatus[4] = ARGUS_SRC_WINDOW_SHUT; break;
         case 'D': RaFlagsIndicationStatus[4] = ARGUS_DST_WINDOW_SHUT; break;
         case '*': RaFlagsIndicationStatus[4] = ARGUS_RTP_SRCSILENCE | ARGUS_RTP_DSTSILENCE; break;
         case 's': RaFlagsIndicationStatus[4] = ARGUS_RTP_SRCSILENCE; break;
         case 'd': RaFlagsIndicationStatus[4] = ARGUS_RTP_DSTSILENCE; break;
      }
   }

   if (str[5] != ' ') {
      switch (str[5]) {
         case 'E': RaFlagsIndicationStatus[5] = ARGUS_SRC_CONGESTED | ARGUS_DST_CONGESTED; break;
         case 'x': RaFlagsIndicationStatus[5] = ARGUS_SRC_CONGESTED; break;
         case 't': RaFlagsIndicationStatus[5] = ARGUS_DST_CONGESTED; break;
      }
   }

   if (str[6] != ' ') {
      switch (str[6]) {
         case 'V': RaFlagsIndicationStatus[6] = ARGUS_FRAGOVERLAP; break;
         case 'f': RaFlagsIndicationStatus[6] = ARGUS_FRAGMENTS; break;
         case 'F': RaFlagsIndicationStatus[6] = ARGUS_IPATTR_SRC_FRAGMENTS | ARGUS_IPATTR_DST_FRAGMENTS; break;
      }
   }

   if (str[7] != ' ') {
      struct ArgusIPAttrStruct *attr;

      if (argus->dsrs[ARGUS_IPATTR_INDEX] == NULL) {
         argus->dsrs[ARGUS_IPATTR_INDEX] = &parser->canon.attr.hdr;
         argus->dsrindex |= 0x1 << ARGUS_IPATTR_INDEX;
         parser->canon.attr.hdr.type = ARGUS_IPATTR_DSR;
         parser->canon.attr.hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_SRC_OPTIONS;
         parser->canon.attr.hdr.argus_dsrvl8.len   = (sizeof(parser->canon.attr) + 3)/4;
      }

      attr = (struct ArgusIPAttrStruct *)argus->dsrs[ARGUS_IPATTR_INDEX];

      switch (str[7]) {
         case 'A': attr->src.options = ARGUS_RTRALERT; break;
         case 'T': attr->src.options = ARGUS_TIMESTAMP; break;
         case 'R': attr->src.options = ARGUS_RECORDROUTE; break;
         case '+': attr->src.options = ARGUS_SECURITY; break;
         case 'L': attr->src.options = ARGUS_LSRCROUTE; break;
         case 'S': attr->src.options = ARGUS_SSRCROUTE; break;
         case 'D': attr->src.options = ARGUS_SATID; break;
         case 'O': attr->src.options = -1; break;
         case 'U': attr->src.options = 99; break;
      }
   }
}

void
ArgusParseSrcMacAddress (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   struct ArgusMacStruct *mac = (struct ArgusMacStruct *)argus->dsrs[ARGUS_MAC_INDEX];

   if (RaParseEtherAddr (parser,buf)) {
      unsigned char *eaddr = argus_ether_aton(buf);
      if (mac == NULL) {
         mac = (struct ArgusMacStruct *)&parser->canon.mac.hdr;
         argus->dsrs[ARGUS_MAC_INDEX] = &mac->hdr;
         argus->dsrindex |= 0x1 << ARGUS_MAC_INDEX;

         memset(mac, 0, sizeof(*mac));
         mac->hdr.type = ARGUS_MAC_DSR;
         mac->hdr.subtype = 0;
         mac->hdr.argus_dsrvl8.qual = 0;
         mac->hdr.argus_dsrvl8.len = 5;
      }

      bcopy (eaddr, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost, 6);
   }
}

void
ArgusParseDstMacAddress (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   struct ArgusMacStruct *mac = (struct ArgusMacStruct *)argus->dsrs[ARGUS_MAC_INDEX];

   if (RaParseEtherAddr (parser,buf)) {
      unsigned char *eaddr = argus_ether_aton(buf);
      if (mac == NULL) {
         mac = (struct ArgusMacStruct *)&parser->canon.mac.hdr;
         argus->dsrs[ARGUS_MAC_INDEX] = &mac->hdr;
         argus->dsrindex |= 0x1 << ARGUS_MAC_INDEX;

         memset(mac, 0, sizeof(*mac)); 
         mac->hdr.type = ARGUS_MAC_DSR;
         mac->hdr.subtype = 0;
         mac->hdr.argus_dsrvl8.qual = 0;
         mac->hdr.argus_dsrvl8.len = 5;
      }

      bcopy (eaddr, (char *)&mac->mac.mac_union.ether.ehdr.ether_dhost, 6);
   }
}

void
ArgusParseMacAddress (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcMacAddress (parser, buf);
   ArgusParseDstMacAddress (parser, buf);
*/
}

void
ArgusParseProto (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;

   if (isdigit((int)*buf)) {
      ArgusThisProto = atoi(buf);

   } else {
      if (*buf == '*') {
         ArgusThisProto = 0xFF;
      } else {
         struct protoent *proto;

         if (!(strncmp(buf, "man", 3))) {
            argus->hdr.type = ARGUS_MAR;
            return;
         } else
         if (!(strncmp(buf, "evt", 3))) {
            argus->hdr.type = ARGUS_EVENT;
            return;
         } else
            argus->hdr.type = ARGUS_FAR | ArgusInputType;

         if ((proto = getprotobyname(buf)) != NULL) {
            ArgusThisProto = proto->p_proto;

         } else {
            int retn = argus_nametoeproto(buf);
            if (retn == PROTO_UNDEF)
               ArgusLog (LOG_ERR, "ArgusParseProto(0x%xs, %s) proto not found\n", parser, buf);
	    else
               ArgusThisProto = retn;
         }
      }
   }

   if (argus->dsrs[ARGUS_FLOW_INDEX] == NULL) {
      argus->dsrs[ARGUS_FLOW_INDEX] = &parser->canon.flow.hdr;
      argus->dsrindex |= 0x1 << ARGUS_FLOW_INDEX;
      argus->hdr.type = ARGUS_FAR | ArgusInputType;

      parser->canon.flow.hdr.type = ARGUS_FLOW_DSR;
   }

   switch (ArgusThisProto) {
         case IPPROTO_IGMP:
         case IPPROTO_ICMP:
         case IPPROTO_ICMPV6:
         case IPPROTO_ESP:
         case IPPROTO_UDP:
         case IPPROTO_TCP: {
            parser->canon.flow.hdr.subtype  = ARGUS_FLOW_CLASSIC5TUPLE;
            if (parser->canon.flow.hdr.argus_dsrvl8.qual & ARGUS_TYPE_IPV4)
               parser->canon.flow.flow_un.ip.ip_p = ArgusThisProto;
            else 
            if (parser->canon.flow.hdr.argus_dsrvl8.qual & ARGUS_TYPE_IPV6)
               parser->canon.flow.flow_un.ipv6.ip_p = ArgusThisProto;
            else {
               parser->canon.flow.hdr.argus_dsrvl8.qual |= ARGUS_TYPE_IPV4;
               parser->canon.flow.flow_un.ip.ip_p = ArgusThisProto;
            }
            break;
         }

         case 2054: {
            struct ArgusArpFlow *arp = &parser->canon.flow.arp_flow;

            parser->canon.flow.hdr.subtype           = ARGUS_FLOW_ARP;
            parser->canon.flow.hdr.argus_dsrvl8.qual = ARGUS_TYPE_ARP;
            parser->canon.flow.hdr.argus_dsrvl8.len  = 1 + sizeof(*arp)/4;
            arp->hrd     = 1;
            arp->pro     = 2048;
            arp->hln     = 6;
            arp->pln     = 4;
            arp->op      = 1;
            break;
         }
 
         default:
            parser->canon.flow.hdr.argus_dsrvl8.qual = ARGUS_TYPE_ETHER;
            parser->canon.flow.flow_un.mac.mac_union.ether.ehdr.ether_type = ArgusThisProto;
            break;
   }

   switch (ArgusThisProto) {
      case IPPROTO_TCP: {
         struct ArgusNetworkStruct *net;
         struct ArgusTCPObject *tcp;

         if ((net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX]) == NULL) {
            argus->dsrs[ARGUS_NETWORK_INDEX] = &parser->canon.net.hdr;
            argus->dsrindex |= 0x1 << ARGUS_NETWORK_INDEX;
            net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX];
            net->hdr.type    = ARGUS_NETWORK_DSR;
            net->hdr.subtype = ARGUS_TCP_INIT;
            net->hdr.argus_dsrvl8.len = ((sizeof(*tcp) + 3)/4) + 1;
         }
         break;
      }
   }
}


void
ArgusParseSrcNet (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCADDR].length;
   if (parser->RaMonMode) {
      sprintf (&buf[strlen(buf)], "%*sNet%*s ", (len - 3)/2, " ", (len - 3)/2, " ");
   } else {
      sprintf (&buf[strlen(buf)], "%*sSrcNet%*s ", (len - 6)/2, " ", (len - 6)/2, " ");
   }

   if ((len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}

/*
   Check to see if the format is correct xx:xx:xx:xx:xx
*/

int
RaParseEtherAddr (struct ArgusParserStruct *parser, char *buf)
{
   unsigned int c1, c2, c3, c4, c5, c6;
   int retn = 0;

   if ((sscanf (buf, "%02x:%02x:%02x:%02x:%02x:%02x", &c1, &c2, &c3, &c4, &c5, &c6)) == 6)
      retn = 1;

   return (retn);
}

void
ArgusParseSrcAddr (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   struct ArgusCIDRAddr *taddr = NULL;

   if (RaParseEtherAddr (parser,buf)) {
      unsigned char *eaddr = argus_ether_aton(buf);

      parser->canon.flow.hdr.type               = ARGUS_FLOW_DSR;
      parser->canon.flow.hdr.subtype            = ARGUS_FLOW_CLASSIC5TUPLE;
      parser->canon.flow.hdr.argus_dsrvl8.qual  = ARGUS_TYPE_ETHER;
      parser->canon.flow.hdr.argus_dsrvl8.len   = 5;
      bcopy (eaddr, (char *)&parser->canon.flow.flow_un.mac.mac_union.ether.ehdr.ether_shost, 6);
      free (eaddr);

   } else

   if ((taddr = RaParseCIDRAddr (parser, buf)) != NULL) {
      if (argus->dsrs[ARGUS_FLOW_INDEX] == NULL) {
         argus->dsrs[ARGUS_FLOW_INDEX] = &parser->canon.flow.hdr;
         argus->dsrindex |= 0x1 << ARGUS_FLOW_INDEX;
         parser->canon.flow.hdr.type              = ARGUS_FLOW_DSR;
         parser->canon.flow.hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
      }

      switch (taddr->type) {
         case AF_INET: {
            switch(parser->canon.flow.hdr.subtype) {
               case ARGUS_FLOW_ARP: {
                  struct ArgusArpFlow *arp = &parser->canon.flow.arp_flow;
                  arp->arp_spa = *taddr->addr;
                  break;
               }

               default: {
                  parser->canon.flow.hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4 | ARGUS_MASKLEN;
                  parser->canon.flow.hdr.argus_dsrvl8.len   = 5;

                  parser->canon.flow.flow_un.ip.ip_src = *taddr->addr;
                  parser->canon.flow.flow_un.ip.smask  = taddr->masklen;
                  if (ArgusThisProto)
                     parser->canon.flow.flow_un.ip.ip_p  = ArgusThisProto;
                  break;
               }
            }
            break;
         }

         case AF_INET6: {
            unsigned int *sp  = (unsigned int *)&parser->canon.flow.flow_un.ipv6.ip_src;
            unsigned int *rsp = (unsigned int *)taddr->addr;
            int i;

            parser->canon.flow.hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV6;
            parser->canon.flow.hdr.argus_dsrvl8.len   = 11;

            for (i = 0; i < 4; i++)
               *sp++ = *rsp++;

            if (ArgusThisProto)
               parser->canon.flow.flow_un.ipv6.ip_p = ArgusThisProto;

            break;
         }
      }
   }
}

void
ArgusParseDstNet (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTADDR].length;
   sprintf (&buf[strlen(buf)], " %*sDstNet%*s ", (len - 6)/2, " ", (len - 6)/2, " ");
   if ((len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}

void
ArgusParseDstAddr (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   struct ArgusCIDRAddr *taddr = NULL;

   if (RaParseEtherAddr (parser,buf)) {
      unsigned char *eaddr = argus_ether_aton(buf);

      parser->canon.flow.hdr.type               = ARGUS_FLOW_DSR;
      parser->canon.flow.hdr.subtype            = ARGUS_FLOW_CLASSIC5TUPLE;
      parser->canon.flow.hdr.argus_dsrvl8.qual  = ARGUS_TYPE_ETHER;
      parser->canon.flow.hdr.argus_dsrvl8.len   = 5;
      bcopy (eaddr, (char *)&parser->canon.flow.flow_un.mac.mac_union.ether.ehdr.ether_dhost, 6);
      free (eaddr);

   } else

   if ((taddr = RaParseCIDRAddr (parser, buf)) != NULL) {
      if (argus->dsrs[ARGUS_FLOW_INDEX] == NULL) {
         argus->dsrs[ARGUS_FLOW_INDEX] = &parser->canon.flow.hdr;
         argus->dsrindex |= 0x1 << ARGUS_FLOW_INDEX;

         parser->canon.flow.hdr.type              = ARGUS_FLOW_DSR;
         parser->canon.flow.hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
         switch (taddr->type) {
            case AF_INET: {
               parser->canon.flow.hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4 | ARGUS_MASKLEN;
               parser->canon.flow.hdr.argus_dsrvl8.len   = 5;
               break;
            }
            case AF_INET6: {
               parser->canon.flow.hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV6;
               parser->canon.flow.hdr.argus_dsrvl8.len   = 11;
               break;
            }
         }
      }

      switch (taddr->type) {
         case AF_INET: {
            switch(parser->canon.flow.hdr.subtype) {
               case ARGUS_FLOW_ARP: {
                  struct ArgusArpFlow *arp = &parser->canon.flow.arp_flow;
                  arp->arp_tpa = *taddr->addr;
                  break;
               }

               default:
                  parser->canon.flow.flow_un.ip.ip_dst    = *taddr->addr;
                  parser->canon.flow.flow_un.ip.dmask     =  taddr->masklen;
                  break;
            }
            break;
         }

         case AF_INET6: {
            unsigned int *sp  = (unsigned int *)&parser->canon.flow.flow_un.ipv6.ip_dst;
            unsigned int *rsp = (unsigned int *)taddr->addr;
            int i;

            for (i = 0; i < 4; i++)
               *sp++ = *rsp++;

            break;
         }
      }
   }
}

void
ArgusParseSrcPort (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   int value = -1;
   char *endptr;

   if (argus->dsrs[ARGUS_FLOW_INDEX] == NULL) {
      argus->dsrs[ARGUS_FLOW_INDEX] = &parser->canon.flow.hdr;
      argus->dsrindex |= 0x1 << ARGUS_FLOW_INDEX;
   }

   if (isdigit((int)*buf)) {
      value = strtol(buf, &endptr, 0);
      if (endptr == buf)
         ArgusLog (LOG_ERR, "ArgusParseSrcPortLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
   } else {
      if (*buf == '*')
         value = 0x00;
   }

   switch (parser->canon.flow.hdr.argus_dsrvl8.qual & 0x1F) {
      case ARGUS_TYPE_ETHER:
         if (value < 0) {
            if (parser->canon.flow.flow_un.mac.mac_union.ether.ehdr.ether_type == 0) { /* llc */
               int i = 0;
               while (llcsap_db[i].s != NULL) {
                  if (!(strncmp(buf, llcsap_db[i].s, strlen(llcsap_db[i].s)))) {
                     value = llcsap_db[i].v;
                     break;
                  }
                  i++;
               }
            }
         }
         if (!(value < 0))
            parser->canon.flow.flow_un.mac.mac_union.ether.ssap = value;
         break;

      case ARGUS_TYPE_IPV4: {
         switch (ArgusThisProto) {
            default:
            case IPPROTO_ICMP:
            case IPPROTO_TCP:
            case IPPROTO_UDP:
               if (value < 0) {
                  int proto, port;
                  proto = ArgusThisProto;
                  if (argus_nametoport(buf, &port, &proto))
                     value = port;
               }
               parser->canon.flow.flow_un.ip.sport = value;
               break;

            case IPPROTO_ESP:
               break;
         }
         break;
      }

      case ARGUS_TYPE_IPV6: {
         switch (ArgusThisProto) {
            default:
            case IPPROTO_TCP:
            case IPPROTO_UDP:
               if (value < 0) {
                  int proto, port;
                  proto = ArgusThisProto;
                  if (argus_nametoport(buf, &port, &proto))
                     value = port;
               }
               parser->canon.flow.flow_un.ipv6.sport = value;
               break;

            case IPPROTO_ICMP:
            case IPPROTO_ESP:
               break;
         }
         break;
      }
   }
}

void
ArgusParseDstPort (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   int value = -1;
   char *endptr;

   if (argus->dsrs[ARGUS_FLOW_INDEX] == NULL) {
      argus->dsrs[ARGUS_FLOW_INDEX] = &parser->canon.flow.hdr;
      argus->dsrindex |= 0x1 << ARGUS_FLOW_INDEX;
   }

   if (isdigit((int)*buf)) {
      value = strtol(buf, &endptr, 0);
      if (endptr == buf)
         ArgusLog (LOG_ERR, "ArgusParseSrcPortLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
   } else {
      if (*buf == '*')
         value = 0x00;
   }

   switch (parser->canon.flow.hdr.argus_dsrvl8.qual & 0x1F) {
      case ARGUS_TYPE_ETHER:
         if (value < 0) {
            if (parser->canon.flow.flow_un.mac.mac_union.ether.ehdr.ether_type == 0) { /* llc */
               int i = 0;
               while (llcsap_db[i].s != NULL) {
                  if (!(strncmp(buf, llcsap_db[i].s, strlen(llcsap_db[i].s)))) {
                     value = llcsap_db[i].v;
                     break;
                  }
                  i++;
               }
            }
         }
         if (!(value < 0))
            parser->canon.flow.flow_un.mac.mac_union.ether.dsap = value;
         break;

      case ARGUS_TYPE_IPV4: {
         switch (ArgusThisProto) {
            default:
            case IPPROTO_ICMP:
            case IPPROTO_TCP:
            case IPPROTO_UDP:
               if (value < 0) {
                  int proto, port;
                  if (ArgusThisProto == 0)
                     proto = IPPROTO_TCP;
		  else
                     proto = ArgusThisProto;
                  if (argus_nametoport(buf, &port, &proto))
                     value = port;
               }
               parser->canon.flow.flow_un.ip.dport = value;
               break;

            case IPPROTO_ESP:
               parser->canon.flow.flow_un.esp.spi = value;
               break;

         }
         break;
      }
      case ARGUS_TYPE_IPV6: {
         switch (ArgusThisProto) {
            default:
            case IPPROTO_TCP:
            case IPPROTO_UDP:
               if (value < 0) {
                  int proto, port;
                  proto = ArgusThisProto;
                  if (argus_nametoport(buf, &port, &proto))
                     value = port;
               } 
               parser->canon.flow.flow_un.ipv6.dport = value;
               parser->canon.flow.flow_un.ipv6.ip_p = ArgusThisProto;
               break;

            case IPPROTO_ESP:
               parser->canon.flow.flow_un.espv6.spi = value;
               break;

            case IPPROTO_ICMP:
               break;
         }
         break;
      }
   }
}

void
ArgusParseSrcIpId (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCIPID].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SIpId");
*/
}

void
ArgusParseDstIpId (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTIPID].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DIpId");
*/
}

void
ArgusParseIpId (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcIpId (parser, buf);
   ArgusParseDstIpId (parser, buf);
*/
}

void
ArgusParseSrcDSByte (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCTOS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "sDSb");
*/
}

void
ArgusParseDstDSByte (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTTOS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dDSb");
*/
}

void
ArgusParseSrcTos (struct ArgusParserStruct *parser, char *buf)
{  
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCTOS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "sTos");
*/
}

void
ArgusParseDstTos (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTTOS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dTos");
*/
}
   
void
ArgusParseSrcTtl (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr; 
   
   int value = strtol(buf, &endptr, 10);
   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcTtl(0x%xs, %s) fractonal format error\n", parser, buf);

   if (argus->dsrs[ARGUS_IPATTR_INDEX] == NULL) {
      argus->dsrs[ARGUS_IPATTR_INDEX] = &parser->canon.attr.hdr;
      argus->dsrindex |= 0x1 << ARGUS_IPATTR_INDEX;
      parser->canon.attr.hdr.argus_dsrvl8.len = (sizeof(struct ArgusIPAttrStruct) + 3)/4;
   }

   parser->canon.attr.hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_SRC;
   parser->canon.attr.src.ttl = value;
}

void
ArgusParseDstTtl (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;
  
   int value = strtol(buf, &endptr, 10);
   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcTtl(0x%xs, %s) fractonal format error\n", parser, buf);

   if (argus->dsrs[ARGUS_IPATTR_INDEX] == NULL) {
      argus->dsrs[ARGUS_IPATTR_INDEX] = &parser->canon.attr.hdr;
      argus->dsrindex |= 0x1 << ARGUS_IPATTR_INDEX;
      parser->canon.attr.hdr.argus_dsrvl8.len = (sizeof(struct ArgusIPAttrStruct) + 3)/4;
   }

   parser->canon.attr.hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_DST;
   parser->canon.attr.dst.ttl = value;
}

void
ArgusParseTtl (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcTtl (parser, buf);
   ArgusParseDstTtl (parser, buf);
*/
}


void
ArgusParseDirection (struct ArgusParserStruct *parser, char *buf)
{
   ArgusParseDirStatus = 0;
   if (!(strcmp (buf, " ->"))) {
      ArgusParseDirStatus |= (ARGUS_SAW_SYN | ARGUS_SAW_SYN_SENT);
   }
   if (!(strcmp (buf, "<- "))) {
      ArgusParseDirStatus |= ARGUS_SAW_SYN_SENT;
   }
}


void
ArgusParsePackets (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   if (strlen(buf)) {
      parser->canon.metric.src.pkts = strtoll(buf, &endptr, 10);
      if (endptr == buf)
         ArgusLog (LOG_ERR, "ArgusParsePackets(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
   } else
      parser->canon.metric.src.pkts = 0;

}

void
ArgusParseSrcPackets (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.src.pkts = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}

void
ArgusParseDstPackets (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.dst.pkts = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}


void
ArgusParseBytes (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.src.bytes = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}

void
ArgusParseSrcBytes (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.src.bytes = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcBytesLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}

void
ArgusParseDstBytes (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.dst.bytes = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}


void
ArgusParseAppBytes (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.src.appbytes = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}

void
ArgusParseSrcAppBytes (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.src.appbytes = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcBytesLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}

void
ArgusParseDstAppBytes (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.dst.appbytes = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}

void
ArgusParseSrcIntPkt (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   struct ArgusJitterStruct *jitter = NULL;
   float meanval;
   char *endptr;

   if (argus->dsrs[ARGUS_JITTER_INDEX] == NULL) {
      jitter = (struct ArgusJitterStruct *) &parser->canon.jitter;
      memset(jitter, 0, sizeof(*jitter));
      argus->dsrs[ARGUS_JITTER_INDEX]    = (struct ArgusDSRHeader *) jitter;
      jitter->hdr.type                  = ARGUS_JITTER_DSR;
      jitter->hdr.subtype               = 0;
      jitter->hdr.argus_dsrvl8.len      = 1;

      argus->dsrindex |= 1 << ARGUS_JITTER_INDEX;
   }

   meanval = strtof(buf, &endptr);
   parser->canon.jitter.src.act.meanval = meanval;
   parser->canon.jitter.src.act.minval = meanval;
   parser->canon.jitter.src.act.maxval = meanval;
   parser->canon.jitter.src.act.n = 1;
   parser->canon.jitter.hdr.argus_dsrvl8.qual |= ARGUS_SRC_ACTIVE_JITTER;

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));

/*
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SrcIntPkt");
*/
}

void
ArgusParseSrcIntPktMax (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SrcIntPkt");
*/
}

void
ArgusParseSrcIntPktMin (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SrcIntPkt");
*/
}
 
void
ArgusParseDstIntPkt (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   struct ArgusJitterStruct *jitter = NULL;
   float meanval;
   char *endptr;

   if (argus->dsrs[ARGUS_JITTER_INDEX] == NULL) {
      jitter = (struct ArgusJitterStruct *) &parser->canon.jitter;
      memset(jitter, 0, sizeof(*jitter));
      argus->dsrs[ARGUS_JITTER_INDEX]    = (struct ArgusDSRHeader *) jitter;
      jitter->hdr.type                  = ARGUS_JITTER_DSR;
      jitter->hdr.subtype               = 0;
      jitter->hdr.argus_dsrvl8.len      = 1;

      argus->dsrindex |= 1 << ARGUS_JITTER_INDEX;
   }

   meanval = strtof(buf, &endptr);
   parser->canon.jitter.dst.act.meanval = meanval;
   parser->canon.jitter.dst.act.minval = meanval;
   parser->canon.jitter.dst.act.maxval = meanval;
   parser->canon.jitter.dst.act.n = 1;

   parser->canon.jitter.hdr.argus_dsrvl8.qual |= ARGUS_DST_ACTIVE_JITTER;

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));


/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DstIntPkt");
*/
}

void
ArgusParseDstIntPktMax (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DstIntPkt");
*/
}

void
ArgusParseDstIntPktMin (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DstIntPkt");
*/
}
 

void
ArgusParseActiveSrcIntPkt (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVESRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActSrcIntPkt");
*/
}

void
ArgusParseActiveSrcIntPktMax (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVESRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActSrcIntPkt");
*/
}

void
ArgusParseActiveSrcIntPktMin (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVESRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActSrcIntPkt");
*/
}

 
void
ArgusParseActiveDstIntPkt (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVEDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActDstIntPkt");
*/
}

void
ArgusParseActiveDstIntPktMax (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVEDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActDstIntPkt");
*/
}

void
ArgusParseActiveDstIntPktMin (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVEDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActDstIntPkt");
*/
}

 

void
ArgusParseIdleSrcIntPkt (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLESRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlSrcIntPkt");
*/
}

void
ArgusParseIdleSrcIntPktMax (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLESRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlSrcIntPkt");
*/
}

void
ArgusParseIdleSrcIntPktMin (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLESRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlSrcIntPkt");
*/
}

 
void
ArgusParseIdleDstIntPkt (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLEDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlDstIntPkt");
*/
}

void
ArgusParseIdleDstIntPktMax (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLEDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlDstIntPkt");
*/
}

void
ArgusParseIdleDstIntPktMin (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLEDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlDstIntPkt");
*/
}

 
void
ArgusParseSrcJitter (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCJITTER].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SrcJitter");
*/
}

void
ArgusParseDstJitter (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTJITTER].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DstJitter");
*/
}


void
ArgusParseActiveSrcJitter (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVESRCJITTER].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActSrcJitter");
*/
}

void
ArgusParseActiveDstJitter (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVEDSTJITTER].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActDstJitter");
*/
}

void
ArgusParseIdleSrcJitter (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLESRCJITTER].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlSrcJitter");
*/
}

void
ArgusParseIdleDstJitter (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLEDSTJITTER].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlDstJitter");
*/
}



void
ArgusParseState (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   int match = 0;

   ArgusConvertParseState = 0;
   if (ArgusInputType == ARGUS_AFLOW) {
      RaConvertParseDirLabel = 1;
      RaConvertParseStateLabel = 1;
      unsigned int tcpstatus = 0; 
      short srcflags = 0; 
      short dstflags = 0; 

      if (!(strcmp (buf, "S0")))     {  ArgusConvertParseState |= (ARGUS_SAW_SYN); match++; } else
      if (!(strcmp (buf, "S1")))     {  ArgusConvertParseState |= (ARGUS_SAW_SYN | ARGUS_SAW_SYN_SENT | ARGUS_CON_ESTABLISHED); match++; } else
      if (!(strcmp (buf, "SF")))     {  ArgusConvertParseState |= (ARGUS_SAW_SYN | ARGUS_SAW_SYN_SENT | ARGUS_CON_ESTABLISHED | ARGUS_NORMAL_CLOSE); match++; } else
      if (!(strcmp (buf, "REJ")))    {  ArgusConvertParseState |= (ARGUS_SAW_SYN | ARGUS_RESET); match++; } else
      if (!(strcmp (buf, "S2")))     {  ArgusConvertParseState |= (ARGUS_SAW_SYN); match++; } else
      if (!(strcmp (buf, "S3")))     {  ArgusConvertParseState |= (ARGUS_SAW_SYN); match++; } else
      if (!(strcmp (buf, "RSTO")))   {  ArgusConvertParseState |= (ARGUS_SAW_SYN | ARGUS_SAW_SYN_SENT | ARGUS_CON_ESTABLISHED | ARGUS_RESET); match++; } else
      if (!(strcmp (buf, "RSTR")))   {  ArgusConvertParseState |= (ARGUS_SAW_SYN | ARGUS_CON_ESTABLISHED | ARGUS_RESET); match++; } else
      if (!(strcmp (buf, "RSTOS0"))) {  ArgusConvertParseState |= (ARGUS_SAW_SYN | ARGUS_RESET); match++; } else
      if (!(strcmp (buf, "RSTRH")))  {  ArgusConvertParseState |= (ARGUS_SAW_SYN_SENT | ARGUS_RESET); match++; } else
      if (!(strcmp (buf, "SH")))     {  ArgusConvertParseState |= (ARGUS_SAW_SYN | ARGUS_FIN); match++; } else
      if (!(strcmp (buf, "SHR")))    {  ArgusConvertParseState |= (ARGUS_SAW_SYN_SENT | ARGUS_FIN); match++; } else
      if (!(strcmp (buf, "OTH")))    {  ArgusConvertParseState |= (ARGUS_CON_ESTABLISHED); match++; }

      if (match) {
	 ArgusParseDirStatus = ArgusConvertParseState;
      } else {
/*
	 if (strchr (buf, 's')) ArgusParseDirStatus |= ARGUS_SAW_SYN;
         if (strchr (buf, 'S')) ArgusParseDirStatus |= ARGUS_SAW_SYN_SENT;
         if (strchr (buf, 'E')) ArgusParseDirStatus |= ARGUS_CON_ESTABLISHED;
         if (strchr (buf, 'f')) ArgusParseDirStatus |= ARGUS_FIN;
         if (strchr (buf, 'F')) ArgusParseDirStatus |= ARGUS_FIN_ACK;
         if (strchr (buf, 'C')) ArgusParseDirStatus |= ARGUS_NORMAL_CLOSE;
         if (strchr (buf, 'R')) ArgusParseDirStatus |= ARGUS_RESET;
*/
         if (strchr (buf, 'S')) srcflags |= TH_SYN;
         if (strchr (buf, 's')) dstflags |= TH_SYN;
         if (strchr (buf, 'H')) srcflags |= TH_SYN | TH_ACK;
         if (strchr (buf, 'h')) dstflags |= TH_SYN | TH_ACK;
         if (strchr (buf, 'A')) srcflags |= TH_ACK;
         if (strchr (buf, 'a')) dstflags |= TH_ACK;
         if (strchr (buf, 'F')) srcflags |= TH_FIN;
         if (strchr (buf, 'f')) dstflags |= TH_FIN;
         if (strchr (buf, 'R')) srcflags |= TH_RST;
         if (strchr (buf, 'r')) dstflags |= TH_RST;
         if (strchr (buf, 'G')) tcpstatus |= ARGUS_SRC_GAP;
         if (strchr (buf, 'g')) tcpstatus |= ARGUS_DST_GAP;
         if (strchr (buf, 'T')) tcpstatus |= ARGUS_SRC_PKTS_RETRANS;
         if (strchr (buf, 't')) tcpstatus |= ARGUS_DST_PKTS_RETRANS;
         if (strchr (buf, 'W')) tcpstatus |= ARGUS_SRC_WINDOW_SHUT;
         if (strchr (buf, 'w')) tcpstatus |= ARGUS_DST_WINDOW_SHUT;
//       if (strchr (buf, 'I')) ;
//       if (strchr (buf, 'i')) ;
//       if (strchr (buf, 'Q')) ;
//       if (strchr (buf, 'q')) ;
//       if (strchr (buf, '^')) ; 
      }

      if (tcpstatus || srcflags || dstflags) {
         struct ArgusRecordStruct *argus = &parser->argus;
         struct ArgusNetworkStruct *net;

         if ((net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX]) != NULL) {
            struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;

            if (tcpstatus) tcp->status |= tcpstatus;
            if (srcflags)  tcp->src.flags |= srcflags;
            if (dstflags)  tcp->dst.flags |= dstflags;
         }
      }
      /*
         S0: Connection attempt seen, no reply.
         S1: Connection established, not terminated.
         SF: Normal establishment and termination. Note that this is the same symbol as for state S1.
	     You can tell the two apart because for S1 there will not be any byte counts in the summary, while for SF there will be.
         REJ: Connection attempt rejected.
         S2: Connection established and close attempt by originator seen (but no reply from responder).
         S3: Connection established and close attempt by responder seen (but no reply from originator).
         RSTO: Connection established, originator aborted (sent a RST).
         RSTR: Responder sent a RST.
         RSTOS0: Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder.
         RSTRH: Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator.
         SH: Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was “half” open).
         SHR: Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator.
         OTH: No SYN seen, just midstream traffic (one example of this is a “partial connection” that was not later closed).

       */

   } else {
      if (!(strcmp (buf, "INT"))) {  ArgusConvertParseState |= ARGUS_START; match++; }
      if (!(strcmp (buf, "REQ"))) {  ArgusConvertParseState |= ARGUS_SAW_SYN; match++; }
      if (!(strcmp (buf, "ACC"))) {  ArgusConvertParseState |= ARGUS_SAW_SYN_SENT; match++; }
      if (!(strcmp (buf, "CON"))) {  ArgusConvertParseState |= ARGUS_CON_ESTABLISHED; match++; }
      if (!(strcmp (buf, "TIM"))) {  ArgusConvertParseState |= ARGUS_TIMEOUT; match++; }
      if (!(strcmp (buf, "CLO"))) {  ArgusConvertParseState |= ARGUS_NORMAL_CLOSE; match++; }
      if (!(strcmp (buf, "FIN"))) {  ArgusConvertParseState |= ARGUS_FIN; match++; }
      if (!(strcmp (buf, "RST"))) {  ArgusConvertParseState |= ARGUS_RESET; match++; }

      if (!match) {
         int i;
         for (i = 0; i < ICMP_MAXTYPE; i++) {
            if (icmptypestr[i] != NULL) 
               if (!(strcmp (buf, icmptypestr[i]))) {
               }
         }
      }

      if (!match) {
         if (strchr (buf, 's')) ArgusParseDirStatus |= ARGUS_SAW_SYN;
         if (strchr (buf, 'S')) ArgusParseDirStatus |= ARGUS_SAW_SYN_SENT;
         if (strchr (buf, 'E')) ArgusParseDirStatus |= ARGUS_CON_ESTABLISHED;
         if (strchr (buf, 'f')) ArgusParseDirStatus |= ARGUS_FIN;
         if (strchr (buf, 'F')) ArgusParseDirStatus |= ARGUS_FIN_ACK;
         if (strchr (buf, 'C')) ArgusParseDirStatus |= ARGUS_NORMAL_CLOSE;
         if (strchr (buf, 'R')) ArgusParseDirStatus |= ARGUS_RESET;
      }
   }
   if (ArgusConvertParseState & ARGUS_START)
      argus->hdr.cause = ARGUS_START;
}

void
ArgusParseTCPSrcBase (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTTCPSRCBASE].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SrcTCPBase");
*/
}

void
ArgusParseTCPDstBase (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTTCPDSTBASE].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DstTCPBase");
*/
}

void
ArgusParseTCPRTT (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) &parser->canon.net;
   struct ArgusTCPObject *tcpExt = NULL;
   unsigned int tcprtt = 0;
   char *endptr;

   tcprtt = strtol(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseTCPRTTLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));

   if (argus->dsrs[ARGUS_NETWORK_INDEX] == NULL) {
      argus->dsrs[ARGUS_NETWORK_INDEX] = &parser->canon.net.hdr;
      argus->dsrindex |= 0x1 << ARGUS_NETWORK_INDEX;

      net->hdr.type              = ARGUS_NETWORK_DSR;
      net->hdr.subtype           = ARGUS_TCP_PERF;
      net->hdr.argus_dsrvl8.qual = 0;
      net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusTCPObject)+3))/4 + 1;

      tcpExt                     = &net->net_union.tcp;
      bzero ((char *)tcpExt, sizeof(*tcpExt));
      tcpExt->synAckuSecs        = 0;
      tcpExt->ackDatauSecs       = tcprtt;
   }
}


void
ArgusParseDeltaDuration (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTADURATION].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dDur");
*/
}

void
ArgusParseDeltaStartTime (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTASTARTTIME].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dsTime");
*/
}

void
ArgusParseDeltaLastTime (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTALASTTIME].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dlTime");
*/
}

void
ArgusParseDeltaSrcPkts (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTASRCPKTS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dsPkts");
*/
}

void
ArgusParseDeltaDstPkts (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTADSTPKTS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ddPkts");
*/
}

void
ArgusParseDeltaSrcBytes (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTASRCBYTES].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dsBytes");
*/
}

void
ArgusParseDeltaDstBytes (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTADSTBYTES].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ddBytes");
*/
}

void
ArgusParsePercentDeltaSrcPkts (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTPERCENTDELTASRCPKTS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "pdsPkt");
*/
}

void
ArgusParsePercentDeltaDstPkts (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTPERCENTDELTADSTPKTS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "pddPkt");
*/
}

void
ArgusParsePercentDeltaSrcBytes (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTPERCENTDELTASRCBYTES].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "pdsByte");
*/
}

void
ArgusParsePercentDeltaDstBytes (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTPERCENTDELTADSTBYTES].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "pddByte");
*/
}

void
ArgusParseSrcUserData (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCUSERDATA].length;
   int slen = 0;
 
   if (len > 0) {
      switch (parser->eflag) {
         case ARGUS_ENCODE_ASCII:
            slen = len;
            break;
 
         case ARGUS_ENCODE_32:
         case ARGUS_ENCODE_64:
            slen = len * 2;
            break;
      }
 
      if (len > 10) slen++;
      sprintf (&buf[strlen(buf)], "%*ssrcUdata%*s ", (slen)/2, " ", (slen)/2, " ");
      if (slen & 0x01)
         sprintf(&buf[strlen(buf)], " ");
   }
*/
}

void
ArgusParseDstUserData (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTUSERDATA].length;
   int slen = 0;

   if (len > 0) {
      switch (parser->eflag) {
         case ARGUS_ENCODE_ASCII:
            slen = len;
            break;

         case ARGUS_ENCODE_32:
         case ARGUS_ENCODE_64:
            slen = len * 2;
            break;
      }

      if (len > 10) slen++;
      sprintf (&buf[strlen(buf)], "%*sdstUdata%*s ", (slen)/2, " ", (slen)/2, " ");
      if (slen & 0x01)
         sprintf(&buf[strlen(buf)], " ");
   }
*/
}

void
ArgusParseUserData (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcUserData (parser, buf);
   ArgusParseDstUserData (parser, buf);
*/
}

void
ArgusParseTCPExtensions (struct ArgusParserStruct *parser, char *buf)
{
}

void
ArgusParseSrcLoad (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCLOAD].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "Src_pps");
*/
}

void
ArgusParseDstLoad (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTLOAD].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "Dst_pps");
*/
}

void
ArgusParseLoad (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTLOAD].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "Tot_pps");
*/
}


void
ArgusParseSrcLoss (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCLOSS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "Src_Loss");
*/
}

void
ArgusParseDstLoss (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTLOSS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "Dst_Loss");
*/
}

void
ArgusParseLoss (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcLoss (parser, buf);
   ArgusParseDstLoss (parser, buf);

*/
}

void
ArgusParsePercentSrcLoss (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCPERCENTLOSS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "pSrc_Loss");
*/
}

void
ArgusParsePercentDstLoss (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTPERCENTLOSS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "pDst_Loss");
*/
}


void
ArgusParsePercentLoss (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcPercentLoss (parser, buf);
   ArgusParseDstPercentLoss (parser, buf);
*/
}

void
ArgusParseSrcPktSize (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCPKTSIZE].length;
   if (len > 8)
      sprintf (&buf[strlen(buf)], "%*sSrcPktSz%*s ", (len - 8)/2, " ", (len - 8)/2, " ");
   else
      sprintf (buf, "%*.*s ", len, len, "SrcPktSz");
*/
}

void
ArgusParseDstPktSize (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTPKTSIZE].length;
   if (len > 8)
      sprintf (&buf[strlen(buf)], "%*sDstPktSz%*s ", (len - 8)/2, " ", (len - 8)/2, " ");
   else
      sprintf (buf, "%*.*s ", len, len, "DstPktSz");
*/
}


void
ArgusParseSrcMaxPktSize (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCPKTSIZEMAX].length;
   sprintf (buf, "%*.*s ", len, len, "SMaxSz");
*/
}

void
ArgusParseSrcMinPktSize (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCPKTSIZEMIN].length;
   sprintf (buf, "%*.*s ", len, len, "SMinSz");
*/
}


void
ArgusParseDstMaxPktSize (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTPKTSIZEMAX].length;
   sprintf (buf, "%*.*s ", len, len, "DMaxSz");
*/
}

void
ArgusParseDstMinPktSize (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTPKTSIZEMIN].length;
   sprintf (buf, "%*.*s ", len, len, "DMinSz");
*/
}


void
ArgusParseSrcRate (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCRATE].length;
   char *ptr;
   if (parser->Aflag)
      ptr = "SrcApp_bps";
   else
      ptr = "Src_bps";

   sprintf (buf, "%*.*s ", len, len, ptr);
*/
}

void
ArgusParseDstRate (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTRATE].length;
   char *ptr;
   if (parser->Aflag)
      ptr = "DstApp_bps";
   else
      ptr = "Dst_bps";

   sprintf (buf, "%*.*s ", len, len, ptr);
*/
}

void
ArgusParseRate (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTRATE].length;
   char *ptr;
   if (parser->Aflag)
      ptr = "TotApp_bps";
   else 
      ptr = "Tot_bps";
   sprintf (buf, "%*.*s ", len, len, ptr);
*/
}

void
ArgusParseSrcMpls (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCMPLS].length;
   int index = RaPrintAlgorithmTable[ARGUSPRINTSRCMPLS].index;
   int i = 0;

   while (index) {
      if (index & 0x01) {
         char strbuf[32];
         sprintf (strbuf, "sMpls[%d]", i);
         sprintf (&buf[strlen(buf)], "%*.*s ", len, len, strbuf);
      }
      i++;
      index = index >> 1;
   }
*/
}

void
ArgusParseDstMpls (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTMPLS].length;
   int index = RaPrintAlgorithmTable[ARGUSPRINTDSTMPLS].index;
   int i = 0;

   while (index) {
      if (index & 0x01) {
         char strbuf[32];
         sprintf (strbuf, "dMpls[%d]", i);
         sprintf (&buf[strlen(buf)], "%*.*s ", len, len, strbuf);
      }  
      i++;
      index = index >> 1; 
   }  
*/
}

void
ArgusParseMpls (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcMpls (parser, buf);
   ArgusParseDstMpls (parser, buf);
*/
}

void
ArgusParseSrcVLAN (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCVLAN].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "sVlan");
*/
}

void
ArgusParseDstVLAN (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTVLAN].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dVlan");
*/
}

void
ArgusParseVLAN (struct ArgusParserStruct *parser, char *buf)
{
   ArgusParseSrcVLAN (parser, buf);
   ArgusParseDstVLAN (parser, buf);
}


void
ArgusParseSrcVID (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCVID].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "sVid");
*/
}

void
ArgusParseDstVID (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTVID].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dVid");
*/
}

void
ArgusParseVID (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcVID (parser, buf);
   ArgusParseDstVID (parser, buf);
*/
}

void
ArgusParseSrcVPRI (struct ArgusParserStruct *parser, char *buf)
{
/*
   sprintf (&buf[strlen(buf)], " sVpri ");
*/
}

void
ArgusParseDstVPRI (struct ArgusParserStruct *parser, char *buf)
{
/*
   sprintf (&buf[strlen(buf)], " dVpri ");
*/
}


void
ArgusParseVPRI (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcVPRI (parser, buf);
   ArgusParseDstVPRI (parser, buf);
*/
}

void
ArgusParseJoinDelay (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTJOINDELAY].length;
   sprintf (&buf[strlen(buf)], "%*sJDelay%*s ", (len - 6)/2, " ", (len - 6)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}

void
ArgusParseLeaveDelay (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTJOINDELAY].length;
   sprintf (&buf[strlen(buf)], "%*sLDelay%*s ", (len - 6)/2, " ", (len - 6)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}


void
ArgusParseWindow (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcWindow (parser, buf);
   ArgusParseDstWindow (parser, buf);
*/
}

void
ArgusParseSrcWindow (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCWINDOW].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SrcWin");
*/
}

void
ArgusParseDstWindow (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTWINDOW].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DstWin");
*/
}

void
ArgusParseDuration (struct ArgusParserStruct *parser, char *buf)
{
   struct timeval tvpbuf, *tvp = &tvpbuf;
   char date[128], *frac;
   char *endptr;

   bzero (date, sizeof(date));
   bcopy (buf, date, strlen(buf));

   if ((frac = strchr(date, '.')) != NULL) {
      int precision;
      *frac++ = '\0';
      tvp->tv_usec = strtol(frac, &endptr, 10);
      if (endptr == frac)
         ArgusLog (LOG_ERR, "ArgusParseDuration(0x%xs, %s) fractonal format error\n", parser, buf);

      if ((precision = strlen(frac)) > 0) {
         int n, power = 6 - precision;

         for (n = 0; n < power; n++)
            tvp->tv_usec *= 10;
      }
   } else
      tvp->tv_usec = 0;

   tvp->tv_sec = strtol(buf, &endptr, 10);
   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseDuration(0x%xs, %s) fractonal format error\n", parser, buf);

   if (parser->canon.time.src.start.tv_sec != 0) {
      parser->canon.time.src.end = parser->canon.time.src.start;
      parser->canon.time.src.end.tv_sec  += tvp->tv_sec;
      parser->canon.time.src.end.tv_usec += tvp->tv_usec;
      if (parser->canon.time.src.end.tv_usec > 1000000) {
         parser->canon.time.src.end.tv_sec++;
         parser->canon.time.src.end.tv_usec -= 1000000;
      }

      parser->canon.time.hdr.subtype |= ARGUS_TIME_ABSOLUTE_TIMESTAMP;	
      parser->canon.time.hdr.subtype |= ARGUS_TIME_SRC_END;

      parser->canon.time.hdr.argus_dsrvl8.qual = ARGUS_TYPE_UTC_MICROSECONDS;
      parser->canon.time.hdr.argus_dsrvl8.len  = 5;
   }
}

void
ArgusParseMean (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTAVGDURATION].length;
   sprintf (&buf[strlen(buf)], "%*sAvgDur%*s", (len - 6)/2, " ", (len - 6)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}

void
ArgusParseMax (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTAVGDURATION].length;
   sprintf (&buf[strlen(buf)], "%*sAvgDur%*s", (len - 6)/2, " ", (len - 6)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}

void
ArgusParseMin (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTAVGDURATION].length;
   sprintf (&buf[strlen(buf)], "%*sAvgDur%*s", (len - 6)/2, " ", (len - 6)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}


void
ArgusParseStartRange (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSTARTRANGE].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SRange");
*/
}

void
ArgusParseEndRange (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTENDRANGE].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ERange");
*/
}

void
ArgusParseTransactions (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTTRANSACTIONS].length;
   char *ptr;
   if (parser->Pctflag)
      ptr = "PctTrans";
   else
      ptr = "Trans";
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, ptr);
*/
}

void
ArgusParseSequenceNumber (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   int value = strtol(buf, &endptr, 10);
   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseDuration(0x%xs, %s) fractonal format error\n", parser, buf);

   if (argus->dsrs[ARGUS_TRANSPORT_INDEX] == NULL) {
      argus->dsrs[ARGUS_TRANSPORT_INDEX] = &parser->canon.trans.hdr;
      argus->dsrindex |= 0x1 << ARGUS_TRANSPORT_INDEX;

      parser->canon.trans.hdr.type             = ARGUS_TRANSPORT_DSR;
      parser->canon.trans.hdr.subtype         |= ARGUS_SEQ;
      parser->canon.trans.hdr.argus_dsrvl8.len = 3;
   }

   parser->canon.trans.seqnum = value;
}

void
ArgusParseBinNumber (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTBINNUMBER].length;
   sprintf (&buf[strlen(buf)], "%*sBin%*s ", (len - 3)/2, " ", (len - 3)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}

void
ArgusParseBins (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTBINNUMBER].length;
   sprintf (&buf[strlen(buf)], "%*sBins%*s ", (len - 4)/2, " ", (len - 4)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}

void
ArgusParseLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;

   ArgusAddToRecordLabel(parser, argus, buf);
}


void ArgusParseSrcTcpFlags (struct ArgusParserStruct *, char *);
void ArgusParseDstTcpFlags (struct ArgusParserStruct *, char *);

void
ArgusParseSrcTcpFlags (struct ArgusParserStruct *parser, char *buf)
{
   if (buf != NULL) {
      unsigned short flags = 0;
      int i, slen;

      if ((slen = strlen(buf)) > 0) {
         for (i = 0; i < 8; i++) {
            if (strchr(buf, *ArgusTCPFlags[i]))
               flags |= 1 << i;
         }
      }
      
      if (flags != 0) {
         struct ArgusRecordStruct *argus = &parser->argus;
         struct ArgusNetworkStruct *net;

         if ((net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX]) != NULL) {
            struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
            tcp->src.flags = flags;
         }
      }
   }
}

void
ArgusParseDstTcpFlags (struct ArgusParserStruct *parser, char *buf)
{
   if (buf != NULL) {
      unsigned short flags = 0;
      int i, slen;

      if ((slen = strlen(buf)) > 0) {
         for (i = 0; i < 8; i++) {
            if (strchr(buf, *ArgusTCPFlags[i]))
               flags |= 1 << i;
         }
      }
      
      if (flags != 0) {
         struct ArgusRecordStruct *argus = &parser->argus;
         struct ArgusNetworkStruct *net;

         if ((net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX]) != NULL) {
            struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
            tcp->dst.flags = flags;
         }
      }
   }
}

void
ArgusParseSrcCountryCode (struct ArgusParserStruct *parser, char *buf)
{
   if (buf != NULL) {
      struct ArgusRecordStruct *argus = &parser->argus;
      struct ArgusCountryCodeStruct *cocode = (struct ArgusCountryCodeStruct *)argus->dsrs[ARGUS_COCODE_INDEX];

      if (cocode == NULL) {
         cocode = (struct ArgusCountryCodeStruct *) &parser->canon.cocode.hdr;
         cocode->hdr.type             = ARGUS_COCODE_DSR;
         cocode->hdr.argus_dsrvl8.len = (sizeof(*cocode) + 3) / 4;
         cocode->hdr.subtype = 0;

         argus->dsrindex |= (0x01 << ARGUS_COCODE_INDEX);
         argus->dsrs[ARGUS_COCODE_INDEX] = (struct ArgusDSRHeader*) cocode;
      }

      bcopy(buf, &cocode->src[0], 2);
   }
}

void
ArgusParseDstCountryCode (struct ArgusParserStruct *parser, char *buf)
{
   if (buf != NULL) {
      struct ArgusRecordStruct *argus = &parser->argus;
      struct ArgusCountryCodeStruct *cocode = (struct ArgusCountryCodeStruct *)argus->dsrs[ARGUS_COCODE_INDEX];
      
      if (cocode == NULL) {
         cocode = (struct ArgusCountryCodeStruct *) &parser->canon.cocode.hdr;
         cocode->hdr.type             = ARGUS_COCODE_DSR;
         cocode->hdr.argus_dsrvl8.len = (sizeof(*cocode) + 3) / 4;
         cocode->hdr.subtype = 0;
         
         argus->dsrindex |= (0x01 << ARGUS_COCODE_INDEX);
         argus->dsrs[ARGUS_COCODE_INDEX] = (struct ArgusDSRHeader*) cocode;
      }
         
      bcopy(buf, &cocode->dst[0], 2);
   }
}


void
ArgusParseActiveDstIntPktDist (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseActiveSrcIntPktDist (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseAppByteRatio (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseBssid (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseByteOffset (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseCause (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseCor (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstAsn (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstDuration (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstEncaps (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstFirst (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstGap (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstGroup (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstHopCount (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstIntPktDist (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstLastDate (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstLatitude (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstLocal (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstLongitude (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstMaxSeg (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstMeanPktSize (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstNacks (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstName (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstOui (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstRetrans (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstSolo (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstStartDate (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstTransEfficiency (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstVirtualNID (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseDstVlan (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseEtherType (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseFirst (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseHashIndex (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseHashRef (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseIcmpId (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseIdleDstIntPktDist (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseIdleMax (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseIdleMean (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseIdleMin (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseIdleSrcIntPktDist (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseIdleStdDeviation (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseIdleTime (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseInf (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseInode (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseInodeAsn (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseInodeCountryCode (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseInodeLatitude (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseInodeLongitude (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseIntFlow (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseIntFlowMax (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseIntFlowMin (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseIntFlowStdDev (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseKeyStrokeDstNStroke (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseKeyStrokeNStroke (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseKeyStrokeSrcNStroke (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseLocal (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseLocalAddr (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseLocalNet (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseNacks (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseNode (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParsePercentDstFirst (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParsePercentDstNacks (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParsePercentDstRetrans (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParsePercentDstSolo (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParsePercentFirst (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParsePercentNacks (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParsePercentRetrans (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParsePercentSolo (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParsePercentSrcFirst (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParsePercentSrcNacks (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParsePercentSrcRetrans (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParsePercentSrcSolo (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseProducerConsumerRatio (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseRelativeDate (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseRemoteAddr (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseRemoteNet (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseResponse (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseRetrans (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseRunTime (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSID (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseScore (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSolo (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcAsn (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcDuration (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcEncaps (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcFirst (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcGap (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcGroup (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcHopCount (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcIntPktDist (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcLastDate (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcLatitude (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcLocal (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcLongitude (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcMaxSeg (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcMeanPktSize (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcNacks (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcName (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcOui (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcRetrans (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcSolo (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcStartDate (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcTransEfficiency (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcVirtualNID (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSrcVlan (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSsid (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseStatus (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseStdDeviation (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseSum (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseTCPAckDat (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseTCPDstMax (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseTCPOptions (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseTCPSrcMax (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseTCPSynAck (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}


void
ArgusParseTransEfficiency (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaParseAlgorithmTable[].length;
*/
}



void ArgusClientTimeout () { return; }
void RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus) { return; }
void RaArgusInputComplete (struct ArgusInput *input) { return; }
void ArgusWindowClose(void) { return; }
int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if ((sig == SIGINT) || (sig == SIGQUIT))
         exit(0);
   }
}

int
ArgusParseConversionFile(struct ArgusParserStruct *parser, char *file) {
   int retn = 0, i, len, found = 0, lines = 0;
   int linenum = 0, RaParsingConversionMap = 0;
   char *optarg = NULL, *ptr = NULL;
   char *strbuf = NULL;
   FILE *fd;

   if ((strbuf = (char *)ArgusCalloc(1, ARGUSMAXSTR)) != NULL) {
      char *str = strbuf;

      if (file) {
         if ((fd = fopen(file, "r")) != NULL) {
            retn = 1;

            while ((fgets(strbuf, ARGUSMAXSTR, fd)) != NULL) {
               lines++;
               str = strbuf;
               while (*str && isspace((int)*str))
                  str++;

               if (*str && (*str != '#') && (*str != '\n') && (*str != '!')) {
                  found = 0;
                  len = 0;
	       if (RaParsingConversionMap) {
                     if ((strchr(str, '=')) != NULL) {
                        char *tok = NULL;
                        int ind = 0;

                        optarg = &str[len];
                        while ((tok = strtok(optarg, "= ,")) != NULL) {
                           switch (ind) {
                              case 0: RaConversionMapTable[RaConversionMapIndex].field = strdup(tok); break;
                              case 1: RaConversionMapTable[RaConversionMapIndex].value = strdup(tok); break;
                           }
                           ind++;
                           optarg = NULL;
                           found = 1;
                        }
                        RaConversionMapIndex++;
		  }

	          if (!found)
                        RaParsingConversionMap = 0;
	       }

                  if (!(RaParsingConversionMap))
                  for (i = 0; i < RACONVERT_RCITEMS; i++) {
                     len = strlen(ArgusConvertResourceFileStr[i]);
                     if (!(strncmp(str, ArgusConvertResourceFileStr[i], len))) {
                        int quoted = 0;
                        optarg = &str[len];

                        while (optarg[strlen(optarg) - 1] == '\n')
                           optarg[strlen(optarg) - 1] = '\0';

                        if (*optarg == '\"') {
                           while (*optarg == '\"') 
                              optarg++;

                           while (optarg[strlen(optarg) - 1] == '\"')
                              optarg[strlen(optarg) - 1] = '\0';
                           quoted = 1;
		     }

                        if (*optarg == '\0')
                           optarg = NULL;

                        if (optarg) {
                           switch (i) {
                              case RACONVERT_SOURCE: {
	                      if (strcasecmp(optarg, "argus") == 0) {
			      } else if (strcasecmp(optarg, "netflow") == 0) {
			         ArgusInputType = ARGUS_NETFLOW;
			      } else if (strcasecmp(optarg, "zeek") == 0) {
			         ArgusInputType = ARGUS_AFLOW;
			      }
                                 break;
                              }

                              case ARGUS_MONITOR_ID: {
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

                              case RACONVERT_FIELD_DELIMITER: {
                                 ptr = optarg;
                                 if ((ptr = strchr(optarg, '\'')) != NULL) {
                                    ptr++;
                                    if (ptr[0] == '\'')
                                       break;
                                 }

                                 if (ptr[0] == '\\') {
                                    switch (ptr[1]) {
                                    case 'a':
                                       RaConvertFieldDelimiter[0] = '\a';
                                       break;
                                    case 'b':
                                       RaConvertFieldDelimiter[0] = '\b';
                                       break;
                                    case 't':
                                       RaConvertFieldDelimiter[0] = '\t';
                                       break;
                                    case 'n':
                                       RaConvertFieldDelimiter[0] = '\n';
                                       break;
                                    case 'v':
                                       RaConvertFieldDelimiter[0] = '\v';
                                       break;
                                    case 'f':
                                       RaConvertFieldDelimiter[0] = '\f';
                                       break;
                                    case 'r':
                                       RaConvertFieldDelimiter[0] = '\r';
                                       break;
                                    case '\\':
                                       RaConvertFieldDelimiter[0] = '\\';
                                       break;
                                    }
                                    if (RaConvertFieldDelimiter[0] != '\0')
                                       break;
                                 } else
                                    RaConvertFieldDelimiter[0] = *ptr;

                                 parser->RaFieldWidth = RA_VARIABLE_WIDTH;
                                 break;
                              }

                              case RACONVERT_FIELD_QUOTED:
                                 if (!(strncasecmp(optarg, "double", 6)))
                                    parser->RaFieldQuoted = RA_DOUBLE_QUOTED;
                                 if (!(strncasecmp(optarg, "single", 6)))
                                    parser->RaFieldQuoted = RA_SINGLE_QUOTED;
                                 break;

                              case RACONVERT_TIME_FORMAT: {
                                 struct timeval tv, *tvp = &tv;
                                 char tbuf[256], *ptr;

                                 RaDateFormat = strdup(optarg);

                                 if ((ptr = strstr(RaDateFormat, ".\%f")) != NULL) {
                                    parser->ArgusFractionalDate = 1;
                                    *ptr++ = '\0'; *ptr++ = '\0'; *ptr++ = '\0';
                                    if (*ptr != '\0') {
                                       strcat(RaDateFormat, ptr);
			         }
			      }

                                 gettimeofday(tvp, 0);
                                 bzero(tbuf, sizeof(tbuf));
                                 ArgusPrintTime(parser, tbuf, sizeof(tbuf), tvp);

                                 if ((len = strlen(tbuf)) > 0)
                                    if (len > 128)
                                       ArgusLog(LOG_ERR, "ArgusParseResourceFile: date string %s too long", optarg);

                                 RaPrintAlgorithmTable[ARGUSPRINTSTARTDATE].length = len - parser->pflag;
                                 RaPrintAlgorithmTable[ARGUSPRINTLASTDATE].length = len - parser->pflag;
                                 break;
                              }

                              case RACONVERT_FIELD_SPECIFIER: {
                                 char *tok = NULL;

                                 while ((tok = strtok(optarg, " ,")) != NULL) {
                                    RaConvertOptionStrings[RaConvertOptionIndex++] = strdup(tok);
                                    if (RaConvertOptionIndex > ARGUS_MAX_CONVERSION)
                                       ArgusLog(LOG_ERR, "usage: number of -s options exceeds %d", ARGUS_MAX_CONVERSION);
                                    optarg = NULL;
                                 }

                                 break;
                              }

                              case RACONVERT_CONVERSION_MAP: {
	                      RaParsingConversionMap = 1;
                                 break;
                              }
                           }
                           found++;
                           break;
                        }
                     }
                  }
                  if (!found)
                     ArgusLog(LOG_ERR, "%s: syntax error line %d", file, lines);
               }
            }

            if (RaConvertOptionIndex > 0) {
               for (i = 0; i < RaConvertOptionIndex; i++) {
                  if (RaConvertOptionStrings[i] != NULL) {
	          int x, y, found = 0;
	          for (x = 0; (x < RaConversionMapIndex) && !found; x++) {
	             if (strcmp(RaConvertOptionStrings[i], RaConversionMapTable[x].field) == 0) {
                           for (y = 0; y < MAX_PRINT_ALG_TYPES; y++) {
                              if (!(strcmp(RaParseAlgorithmTable[y].field, RaConversionMapTable[x].value))) {
                                 RaConversionMapTable[x].func = RaParseAlgorithmTable[y].parse;
                                 break;
                              }
                           }

	                parser->RaPrintOptionStrings[i] = RaConversionMapTable[x].value;
	                sprintf(&ArgusConvertTitleString[strlen(ArgusConvertTitleString)], "%s%c", RaConversionMapTable[x].value, RaConvertFieldDelimiter[0]);
	                found = 1;
	                break;
                        }
                     }
	          if (!found) 
                        ArgusLog (LOG_ERR, "ArgusParseConversionFile item %s not found", RaConvertOptionStrings[i]);
                  }
               }

//          ArgusProcessSOptions(parser);
	    RaConvertParseTitleString (ArgusConvertTitleString);
            }

            fclose(fd);

         } else {
#ifdef ARGUSDEBUG
            ArgusDebug(2, "%s: %s\n", file, strerror(errno));
#endif
         }
      }
      ArgusFree(strbuf);

   } else
      ArgusLog (LOG_ERR, "ArgusCalloc failed %s", strerror(errno));

#ifdef ARGUSDEBUG
   ArgusDebug(2, "ArgusParseConversionFile (%s) returning %d\n", file, retn);
#endif

   return (retn);
}


#if defined(HAVE_STDINT_H)
# include <stdint.h>
#endif
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "argus_compat.h"
#include "argus_util.h"
#include "argus_output.h"
#include "argus_config.h"

#if defined(HAVE_UUID_UUID_H)
#include <uuid/uuid.h>
#else
#if defined(HAVE_LINUX_UUID_H)
#include <linux/uuid.h>
#else
#if defined(HAVE_UUID_H)
#include <uuid.h>
#endif
#endif
#endif


#ifdef CYGWIN
static int
__wmic_get_uuid(char *uuidstr, size_t len)
{
   FILE *fp;
   char str[64];
   int res = -1;

   if (len < 37)
      /* need 37 bytes, including terminating null, to hold uuid string */
      return -1;

   fp = popen("/cygdrive/c/Windows/System32/Wbem/wmic"
              " path win32_computersystemproduct get uuid", "r");
   if (fp == NULL)
      return -1;

   if (fgets(str, sizeof(str), fp) == NULL)
      goto close_out;

   if (strncmp(str, "UUID", 4) == 0) {
      if (fgets(str, sizeof(str), fp) == NULL)
         goto close_out;

      if (strlen(str) >= 37) {
         strncpy(uuidstr, str, 36);
         uuidstr[36] = '\0';
         res = 0;
      }
   }

close_out:
   fclose(fp);
   return res;
}
#endif

