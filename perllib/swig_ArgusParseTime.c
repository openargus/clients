/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2018-2024 QoSient, LLC
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

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <argus_compat.h>
#include <argus_util.h>
#include <argus_main.h>
#include <argus_parser.h>
#include "argus_threads.h"
#include <ctype.h>

#include "swig_ArgusParseTime.h"

#define ARGUS_YEAR      	1
#define ARGUS_MONTH     	2
#define ARGUS_DAY       	3
#define ARGUS_HOUR      	4
#define ARGUS_MIN       	5
#define ARGUS_SEC       	6
#define RA_HASHTABLESIZE	2048

static int RaDaysInAMonth[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
extern struct ArgusParserStruct *ArgusParser;

void usage (void) { return; }
void RaParseComplete (int sig) { return; }
void RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *rec) { return; }
int RaSendArgusRecord(struct ArgusRecordStruct *rec) { return 0 ; }
void ArgusClientTimeout (void) { return; }
void ArgusWindowClose(void) { return; }

int
swig_ArgusParseTime (char *time_string, int *start, int *end)
{
   int retn = 1;
   char *buf = NULL, *ptr = NULL;
   struct tm starttime = {0, };
   struct tm endtime = {0, };
   struct tm tm = {0, };
   struct timeval now;
   time_t tsec;
   int frac;

   /* Also remember where in the string the separator was. */
   char wildcarddate = 0;

   ArgusDebug (1, "swig_ArgusParseTime(%s, %d, %d) starting\n", time_string, start, end);

   *start = -1;
   *end = -1;
   buf = strdup(time_string);

   if (*buf == '-')
      *buf = '_';

   gettimeofday(&now, NULL);
   tsec = now.tv_sec;
   localtime_r(&tsec, &endtime);
   bcopy (&endtime, &starttime, sizeof(tm));

   /* look through the time string for a plus or minus to indicate
    * a compound time.
    */

   if (((ptr = strchr(buf, '-')) != NULL) || ((ptr = strchr(buf, '+')) != NULL)) {
      char mode  = *ptr;
      if (*buf == '_') *buf = '-';

      *ptr++ = '\0';

      while (isspace((int) buf[strlen(buf) - 1]))
         buf[strlen(buf) - 1] = 0;
      while (isspace((int) *ptr))
         ptr++;

      ArgusDebug (1, "ArgusParseTime(%s) parsing %s and %s\n", time_string, buf, ptr);

      if ((retn = ArgusParseTime(&wildcarddate, &starttime, &tm, buf, mode, &frac, 0)) > 0) {
         *start = (int)mktime(&starttime);
         *end = (int)mktime(&tm);
         ArgusDebug (1, "First ArgusParseTime(%s) returns %d, starttime:%d endtime:%d\n", buf, retn, *start, *end);

         if (mode == '-') {
            localtime_r(&tsec, &endtime);
            bcopy (&endtime, &tm, sizeof(tm));

            if ((retn = ArgusParseTime(&wildcarddate, &tm, &endtime, ptr, ' ', &frac, 0)) > 0) {
               *start = (int)mktime(&tm);
               *end = (int)mktime(&endtime);
               ArgusDebug (1, "Second ArgusParseTime(%s) returns %d, starttime:%d endtime:%d\n", ptr, retn, *start, *end);
            }
            retn = 0;
         } else {
            bcopy(&starttime, &tm, sizeof(tm));
            *start = (int)mktime(&starttime);
            *end = (int)mktime(&endtime);
            ArgusDebug (1, "Second ArgusParseTime(%s) called with starttime:%d endtime:%d\n", ptr, *start, *end);
            ArgusDebug (1, "Second ArgusParseTime(%p, %p, %p, %s, '+', %d, 1)\n", &wildcarddate, &starttime, &endtime, ptr, frac);
            ArgusParseTime (&wildcarddate, &endtime, &tm, ptr, '+', &frac, 1);
            *start = (int)mktime(&starttime);
            *end = (int)mktime(&endtime);
            ArgusDebug (1, "Second ArgusParseTime(%s) returns %d, starttime:%d endtime:%d\n", ptr, retn, *start, *end);
            retn = 0;
         }
      }
   } else {
      int len = strlen(buf);

      if (*buf == '_') *buf = '-';

      if ((retn = ArgusParseTime(&wildcarddate, &starttime, &endtime, buf, ' ', &frac, 0)) > 0) {
         *start = (int)mktime(&starttime);
         *end = (int)mktime(&endtime);
         ArgusDebug (1, "ArgusParseTime(%s) returns %d, starttime:%d endtime:%d\n", buf, retn, *start, *end);
         if (*buf != '-') {
            bcopy (&starttime, &endtime, sizeof(struct tm));
            if (buf[len - 1] != '.') {
               switch (retn) {
                  case ARGUS_YEAR:  endtime.tm_year++; break;
                  case ARGUS_MONTH: endtime.tm_mon++; break;
                  case ARGUS_DAY:   endtime.tm_mday++; break;
                  case ARGUS_HOUR:  endtime.tm_hour++; break;
                  case ARGUS_MIN:   endtime.tm_min++; break;
                  case ARGUS_SEC:   endtime.tm_sec++; break;
                  default: break;
               }

               while (endtime.tm_sec  > 59) {endtime.tm_min++;  endtime.tm_sec -= 60;}
               while (endtime.tm_min  > 59) {endtime.tm_hour++; endtime.tm_min  -= 60;}
               while (endtime.tm_hour > 23) {endtime.tm_mday++; endtime.tm_hour -= 24;}
               while (endtime.tm_mday > RaDaysInAMonth[endtime.tm_mon]) {endtime.tm_mday -= RaDaysInAMonth[endtime.tm_mon]; endtime.tm_mon++;}
               while (endtime.tm_mon  > 11) {endtime.tm_year++; endtime.tm_mon  -= 12;}
            }
         } else
            ArgusParseTime (&wildcarddate, &endtime, &starttime, &buf[1], '+', &frac, 1);

	 retn = 0;
      }
      /* Not a time relative to "now" AND not a time range */
      /* endtime = starttime; */
   }

   if (retn == 0) {
      *start = (int)mktime(&starttime);
      *end = (int)mktime(&endtime);
   }

   if (buf)
      free(buf);
   return retn;
}

/*
void
ArgusLog (int d, char *fmt, ...)
{
   return;
}

extern char ArgusDebugBuf[MAXSTRLEN];

void
ArgusDebug (int d, char *fmt, ...)
{
   va_list ap;
   char *buf = ArgusDebugBuf;
   struct timeval tvp;
   size_t len = 0;
   size_t remain = sizeof(ArgusDebugBuf);
   int c;

   if (ArgusParser == NULL) ArgusParser = ArgusNewParser("perlScript");
   ArgusParser->debugflag = -1;

   if ((ArgusParser != NULL) && (d <= ArgusParser->debugflag)) {
      gettimeofday (&tvp, 0L);
      buf[0] = '\0';

      (void) snprintf_append(buf, &len, &remain, "%s[%d]: ", ArgusParser->ArgusProgramName, (int)getpid());
      c = ArgusPrintTime(ArgusParser, &buf[len], remain, &tvp);
      len += c;
      remain -= c;
      snprintf_append(buf, &len, &remain, " ");

#if defined(__STDC__)
      va_start(ap, fmt);
#else
      va_start(ap);
#endif

      c = vsnprintf (&buf[len], remain, fmt, ap);
      if (c > 0) {
         if (c < remain) {
            len += c;
            remain -= c;
         } else {
            len += remain;
            remain = 0;
            buf[MAXSTRLEN-1] = 0;
         }
      }
      va_end (ap);

      while (buf[len - 1] == '\n') {
         buf[len - 1] = '\0';
         len--;
         remain++;
      }
      fprintf (stderr, "%s\n", buf);
   }
}

#include <stdarg.h>

int
ArgusPrintTime(struct ArgusParserStruct *parser, char *buf, size_t buflen, struct timeval *tvp)
{
   char timeFormatBuf[128], *tstr = timeFormatBuf;
   char *timeFormat = parser->RaTimeFormat;
   char *ptr;
   struct tm tmbuf, *tm = &tmbuf;
   time_t tsec = tvp->tv_sec;
   size_t remain = buflen;
   size_t len = 0;
   int c;
 
   timeFormatBuf[0] = '\0';

   if (timeFormat == NULL)
      timeFormat = "%m/%d.%T.%f";

   if ((tm = localtime_r (&tsec, &tmbuf)) == NULL)
      return 0;

   if (parser->uflag || timeFormat == NULL) {
      size_t tlen = 0;
      c = snprintf (tstr, sizeof(timeFormatBuf), "%u", (int) tvp->tv_sec);
      if (c > 0)
         tlen += c;
      if (parser->pflag) {
         ptr = &tstr[tlen];
         sprintf (ptr, ".%06u", (int) tvp->tv_usec);
         ptr[parser->pflag + 1] = '\0';
      }
      snprintf_append(buf, &len, &remain, "%s", tstr);
      return (int)len;
   }

   strncpy(timeFormatBuf, timeFormat, sizeof(timeFormatBuf) - 1);

   for (ptr=tstr; *ptr; ptr++) {
      if (*ptr != '%') {
         if (remain) {
            buf[len] = *ptr;
            len++;
            remain--;
         }
      } else {
         switch (*++ptr) {
            case 'f': {
               if (parser->pflag) {
                  char *p;
                  int i;

                  while (isspace((int)buf[len - 1])) {
                     buf[len - 1] = '\0';
                     len--;
                     remain++;
                  }
                  p = &buf[len];
                  snprintf_append(buf, &len, &remain, "%06u", (int) tvp->tv_usec);
                  for (i = parser->pflag; i < 6; i++) {
                     p[i] = '\0';
                     len--;
                     remain++;
                  }
               } else {
                  if (buf[len - 1] == '.') {
                     buf[len - 1] = '\0';
                     len--;
                     remain++;
                  }
               }
               break;
            }

            case '%': {
               if (remain == 0)
                  break;

               buf[len] = '%';
               len++;
               remain--;
               break;
            }

            case 'E':
            case 'O': {
               char sbuf[8];
               sprintf (sbuf, "%%%.2s", ptr++);
               c = strftime (&buf[len], remain, sbuf, tm);
               if (c > 0) {
                  if (c > remain)
                     c = remain;
                  len += c;
                  remain -= c;
               }
               break;
            }

            case 'z': {
               if (parser->ArgusPrintXml) {
                  char sbuf[16];
                  int slen, i;
                  bzero (sbuf, 16);
                  if ((strftime ((char *) sbuf, 16, "%z", tm)) == 0)
                     ArgusLog (LOG_ERR, "ArgusPrintTime: strftime() error\n");
                  if (strstr(sbuf, "0000")) {
                     sprintf (sbuf, "Z");
                  } else {
                     if ((slen = strlen(sbuf)) > 0) {
                        for (i = 0; i < 2; i++)
                           sbuf[slen - i] = sbuf[slen - (i + 1)];
                        sbuf[slen - 2] = ':';
                     }
                  }
                  snprintf_append(buf, &len, &remain, "%s", sbuf);
                  break;
               }
               // Fall through to default if %z and not parser->ArgusPrintXml
            }
            default: {
               char sbuf[8];
               sprintf (sbuf, "%%%c", *ptr);
               c = strftime (&buf[len], remain, sbuf, tm);
               if (c > 0) {
                  if (c > remain)
                     c = remain;
                  len += c;
                  remain -= c;
               }
               break;
            }
         }
      }
   }
   return (int)len;
}


struct ArgusParserStruct *
ArgusNewParser(char *progname)
{
   struct ArgusParserStruct *retn = NULL;
   char progbuf[1024], *ptr;

   if (progname != NULL) {
      strncpy (progbuf, progname, 1024 - 1);
      if ((ptr = strrchr (progbuf, '/')) != NULL) {
         *ptr++ = '\0';
         progname = ptr;
      }
   } else 
      ArgusLog (LOG_ERR, "ArgusNewParser(%s) no program name");

   if ((retn  = (struct ArgusParserStruct *) calloc(1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewParser(%s) calloc error %s", progname, strerror(errno));

   retn->ArgusProgramName = strdup(progname);
   retn->ArgusCIDRPtr = &retn->ArgusCIDRBuffer;
   retn->RaTimeFormat = strdup("%T.%f");
   retn->ArgusFractionalDate = 1;

   retn->ArgusHashTableSize = RA_HASHTABLESIZE;
   retn->RaFilterTimeout = 1.5;

   retn->RaClientTimeout.tv_sec = 1;
   retn->RaCloseInputFd = 1;
   retn->Oflag  = 1;
   retn->nflag  = 1;
   retn->sNflag = -1;
   retn->eNflag = -1;
   retn->Lflag = -1;
   retn->pflag  = 6;
   retn->ArgusReverse = 1;
   retn->ArgusPrintWarnings = 1;
   retn->ArgusPerformCorrection = 0;
   retn->RaSeparateAddrPortWithPeriod = 1;
   retn->RaPruneMode = 1;

   retn->timeout.tv_sec  = -1;
   retn->timeout.tv_usec =  0;

   retn->ArgusPassNum = 1;

   ArgusInitializeParser(retn);
   return (retn);
}


static void
ArgusInitializeParser(struct ArgusParserStruct *parser)
{
   int i;

   parser->RaStartTime.tv_sec  = 0x7FFFFFFF;
   parser->RaStartTime.tv_usec = 0;
   parser->RaEndTime.tv_sec    = 0;
   parser->RaEndTime.tv_usec   = 0;

   parser->startime_t.tv_sec   = 0x7FFFFFFF;
   parser->lasttime_t.tv_sec   = 0;

   parser->ArgusTotalRecords    = 0;
   parser->ArgusTotalMarRecords = 0;
   parser->ArgusTotalFarRecords = 0;
   parser->ArgusTotalPkts       = 0;
   parser->ArgusTotalSrcPkts    = 0;
   parser->ArgusTotalDstPkts    = 0;
   parser->ArgusTotalBytes      = 0;
   parser->ArgusTotalSrcBytes   = 0;
   parser->ArgusTotalDstBytes   = 0;

   parser->RaLabelCounter      = 0;

   parser->RaFieldWidth = RA_FIXED_WIDTH;

   parser->ArgusGenerateManRecords = 0;

   for (i = 0; i < ARGUS_MAXLISTEN; i++) {
      parser->ArgusLfd[i] = -1;
      parser->ArgusOutputs[i] = NULL;
   }

   parser->ArgusListens = 0;

// parser->ArgusInputList = ArgusNewList();
// parser->ArgusOutputList = ArgusNewList();
// parser->ArgusRemoteHosts = ArgusNewQueue();
// parser->ArgusActiveHosts = ArgusNewQueue();

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&parser->lock, NULL);
   pthread_mutex_init(&parser->sync, NULL);
   pthread_cond_init(&parser->cond, NULL);
#endif

   gettimeofday(&parser->ArgusStartRealTime, 0L);
   gettimeofday(&parser->ArgusRealTime, 0L);
}
*/
