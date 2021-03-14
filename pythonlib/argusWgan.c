/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2018 QoSient, LLC
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

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include <argus_compat.h>
#include <argus_util.h>
#include <argus_main.h>
#include "argus_threads.h"

#include "argusWgan.h"

extern void ArgusLog (int, char *, ...);
void RaConvertParseTitleString (char *);

int RaFlagsIndicationStatus[64];
int RaConvertParseDirLabel = 0;
int RaConvertParseStateLabel = 0;


unsigned int ArgusSourceId = 0;
unsigned int ArgusIdType = 0;

#define ARGUS_CONTINUE          0x100
#define ARGUS_REQUEST           0x200
#define ARGUS_RESPONSE          0x400
#define ARGUS_INIT              0x800

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

void
ArgusClientInit(struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   int i, x, ind;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaConvertInit()");
#endif

   if (parser->ver3flag)
      argus_version = ARGUS_VERSION_3;

   if ((mode = ArgusParser->ArgusModeList) != NULL) {
      while (mode) {
         for (i = 0, ind = -1; i < RASCII_MAXMODES; i++) {
            if (!(strncasecmp (mode->mode, RaConvertDaemonModes[i], 3))) {
               ind = i;
               switch (ind) {
                  case RASCIIDEBUG:
                     if ((mode = mode->nxt) == NULL)
                     break;
               }
            }
         }

         switch (ind) {
            case RASCIIDEBUG: {
               for (x = 0, ind = -1; x < RASCII_MAXMODES; x++) {
                  if (!(strncasecmp (mode->mode, RaConvertDaemonModes[x], 3))) {
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
               break;
         }

         mode = mode->nxt;
      }
   }

   ArgusParser->ArgusInitCon.hdr.type                    = (ARGUS_MAR | argus_version);
   ArgusParser->ArgusInitCon.hdr.cause                   = ARGUS_START;
   ArgusParser->ArgusInitCon.hdr.len                     = (unsigned short) (sizeof(struct ArgusRecord) + 3)/4;
   ArgusParser->ArgusInitCon.argus_mar.thisid            = ArgusSourceId;
   ArgusParser->ArgusInitCon.argus_mar.argusid           = (argus_version == ARGUS_VERSION_3)
                                                           ? ARGUS_V3_COOKIE : ARGUS_COOKIE;
 
   ArgusParser->ArgusInitCon.argus_mar.startime.tv_sec   = ArgusParser->ArgusRealTime.tv_sec;
   ArgusParser->ArgusInitCon.argus_mar.startime.tv_usec  = ArgusParser->ArgusRealTime.tv_usec;
   ArgusParser->ArgusInitCon.argus_mar.now.tv_sec        = ArgusParser->ArgusRealTime.tv_sec;
   ArgusParser->ArgusInitCon.argus_mar.now.tv_sec        = ArgusParser->ArgusRealTime.tv_usec;

   ArgusParser->ArgusInitCon.argus_mar.major_version     = VERSION_MAJOR;
   ArgusParser->ArgusInitCon.argus_mar.minor_version     = VERSION_MINOR;
   ArgusParser->ArgusInitCon.argus_mar.reportInterval    = 0;
   ArgusParser->ArgusInitCon.argus_mar.argusMrInterval    = 0;

   ArgusParser->ArgusInitCon.argus_mar.record_len                = -1;

   ArgusHtoN(&ArgusParser->ArgusInitCon);
}

#define ARGUS_MAX_PRINT_FIELDS		512

void (*RaParseLabelAlgorithms[ARGUS_MAX_PRINT_FIELDS])(struct ArgusParserStruct *, char *);
int RaParseLabelAlgorithmIndex = 0;
char RaConvertDelimiter[2] = {'\0', '\0'};


void
RaConvertParseTitleString (char *str)
{
   char buf[MAXSTRLEN], *ptr, *obj;
   int i, len = 0, items = 0;


   bzero ((char *)RaParseLabelAlgorithms, sizeof(RaParseLabelAlgorithms));
   bzero ((char *)buf, sizeof(buf));

   if ((ptr = strchr(str, '\n')) != NULL)
      *ptr = '\0';

   ptr = buf;
   bcopy (str, buf, strlen(str));
   while (isspace((int)*ptr)) ptr++;

// Lets determine the delimiter, if we need to.  This will make this go a bit faster

   for (i = 0; i < MAX_PARSE_ALG_TYPES; i++) {
      len = strlen(RaParseLabelStringTable[i]);
      if (!(strncmp(RaParseLabelStringTable[i], ptr, len))) {
         ptr += len;
         if (*RaConvertDelimiter == '\0')
            *RaConvertDelimiter = *ptr++;
         else {
            if (*ptr && (*RaConvertDelimiter != *ptr++))
               ArgusLog (LOG_ERR, "RaConvertFrontList: title format error: inconsistent delimiter: %s", str);
         }
         break;
      }
   }

   ptr = buf;

   while ((obj = strtok(ptr, RaConvertDelimiter)) != NULL) {
      len = strlen(obj);
      if (len > 0) {
         for (i = 0; i < MAX_PARSE_ALG_TYPES; i++) {
            if (!(strncmp(RaParseLabelStringTable[i], obj, len))) {
               RaParseLabelAlgorithmIndex++;
               RaParseLabelAlgorithms[items] = RaParseLabelAlgorithmTable[i];
               if (i == ARGUSPARSEDIRLABEL)
                  RaConvertParseDirLabel++;
               if (i == ARGUSPARSESTATELABEL)
                  RaConvertParseStateLabel++;
               break;
            }
         }
      }

      items++;
      ptr = NULL;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (9, "RaConvertParseTitleString('%s') done", str);
#endif
}

int
setSchema (char *str)
{
   struct ArgusParserStruct *parser = NULL;
   int retn = 0;

   if ((parser = ArgusParser) == NULL) {
      if ((ArgusParser = ArgusNewParser("argusWgan")) == NULL)
         ArgusLog (LOG_ERR, "ArgusNewParser failed %s", strerror(errno));
      parser = ArgusParser;
      ArgusClientInit (ArgusParser);
   }

   if (str != NULL) {
      RaConvertParseTitleString(str);
   }

   return (retn);
}


int
argustime (char *time_string, int *start, int *end)
{
   int retn = 1;
   char *string;
   struct tm starttime = {0, };
   struct tm endtime = {0, };
   int frac;
   time_t tsec;
   struct timeval now;

   /* Also remember where in the string the separator was. */
   char *plusminusloc = NULL;
   int off = 0;
   char wildcarddate = 0;

   /* If the date string has two parts, remember which character
    * separates them.
    */
   char plusminus;

   *start = -1;
   *end = -1;
   string = strdup(time_string);

   if (string[0] == '-')
      /* skip leading minus, if present */
      off++;

   /* look through the time string for a plus or minus to indicate
    * a compound time.
    */
   while (!plusminusloc && !isspace(string[off]) && string[off] != '\0') {
      if (string[off] == '-' || string[off] == '+') {
         plusminusloc = &string[off];
         plusminus = string[off];
         string[off] = '\0'; /* split the string in two */
      }
      off++;
   }

   gettimeofday(&now, NULL);
   tsec = now.tv_sec;
   localtime_r(&tsec, &endtime);

   if (ArgusParseTime(&wildcarddate, &starttime, &endtime, string, ' ', &frac, 0) <= 0) {
      retn = 0;
      goto out;
   }

   if (plusminusloc) {
      if (ArgusParseTime(&wildcarddate, &endtime, &starttime, plusminusloc+1, plusminus, &frac, 1) <= 0) {
         retn = 0;
         goto out;
      }
   } else if (string[0] != '-') {
      /* Not a time relative to "now" AND not a time range */
      /* endtime = starttime; */
   }

out:
   if (retn == 1) {
      *start = (int)mktime(&starttime);
      *end = (int)mktime(&endtime);
   }

   if (string)
      free(string);
   return retn;
}



void ArgusClientInit (struct ArgusParserStruct *parser) { }
void RaArgusInputComplete (struct ArgusInput *input) { return; }
void RaParseComplete (int sig) { }
void ArgusClientTimeout () { }
void parse_arg (int argc, char**argv) {}
void usage () { }
void RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus) { }
int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}
void ArgusWindowClose(void) {}
