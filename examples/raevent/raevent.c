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
 * raevent.c  - event for ra* client programs.
 *    add application specific code, stir and enjoy.
 */

/* 
 * $Id: //depot/gargoyle/clients/examples/raevent/raevent.c#18 $
 * $DateTime: 2016/09/14 23:15:04 $
 * $Change: 3185 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>

#include <argus_compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <signal.h>
#include <ctype.h>

static int argus_version = ARGUS_VERSION;

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "poll", 4)))
               parser->RaPollMode++;
            mode = mode->nxt;
         }
      }

      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input) { return; }


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if ((sig == SIGINT) || (sig == SIGQUIT)) {
         ArgusShutDown(sig);
         exit(0);
      }
   }
}


void
ArgusClientTimeout ()
{
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

   fprintf (stdout, "Raevent Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] -S remoteServer  [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -A                 print record summaries on termination.\n");
   fprintf (stdout, "         -b                 dump packet-matching code.\n");
   fprintf (stdout, "         -c <char>          specify a delimiter <char> for output columns.\n");
#if defined (ARGUSDEBUG)
   fprintf (stdout, "         -D <level>         specify debug level\n");
#endif
   fprintf (stdout, "         -e <regex>         match regex in the event header.\n");
   fprintf (stdout, "         -F <conffile>      read configuration from <conffile>.\n");
   fprintf (stdout, "         -h                 print help.\n");
   fprintf (stdout, "         -n                 don't convert numbers to names.\n");
   fprintf (stdout, "         -p <digits>        print fractional time with <digits> precision.\n");
   fprintf (stdout, "         -q                 quiet mode. don't print record outputs.\n");
   fprintf (stdout, "         -r <file>          read argus data <file>. '-' denotes stdin.\n");
   fprintf (stdout, "         -R <dir>           recursively process files in directory\n");
   fprintf (stdout, "         -S <host[:port]>   specify remote argus <host> and optional port\n");
   fprintf (stdout, "                            number.\n");
   fprintf (stdout, "         -t <timerange>     specify <timerange> for reading records.\n");
   fprintf (stdout, "                   format:  timeSpecification[-timeSpecification]\n");
   fprintf (stdout, "                            timeSpecification: [[[yyyy/]mm/]dd.]hh[:mm[:ss]]\n");
   fprintf (stdout, "                                                 [yyyy/]mm/dd\n");
   fprintf (stdout, "                                                 -%%d{yMdhms}\n");
   fprintf (stdout, "         -T <secs>          attach to remote server for T seconds.\n");
   fprintf (stdout, "         -u                 print time in Unix time format.\n");
#ifdef ARGUS_SASL
   fprintf (stdout, "         -U <user/auth>     specify <user/auth> authentication information.\n");
#endif
   fprintf (stdout, "         -w <file>          write output to <file>. '-' denotes stdout.\n");
   fflush (stdout);
   exit(1);
}

#if defined(HAVE_ZLIB_H)
#include <zlib.h>
#endif


char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   switch (argus->hdr.type & 0xF0) {
      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: 
         break;

      case ARGUS_MAR:
         RaProcessManRecord (parser, argus);
         break;

      case ARGUS_EVENT: {
         if (parser->ArgusWfileList != NULL) {
            struct ArgusWfileStruct *wfile = NULL;
            struct ArgusListObjectStruct *lobj = NULL;
            int i, count = parser->ArgusWfileList->count;

            if ((lobj = parser->ArgusWfileList->start) != NULL) {
               for (i = 0; i < count; i++) {
                  if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                     int retn = 1;
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
                              rv = ArgusWriteNewLogfile (parser, argus->input,
                                                         wfile, argusrec);
                              if (rv < 0)
                                 ArgusLog(LOG_ERR, "%s unable to open file\n",
                                          __func__);
                           }
                        }
                     }
                  }

                  lobj = lobj->nxt;
               }
            }

         } else {
               struct ArgusTimeObject *time = (void *)argus->dsrs[ARGUS_TIME_INDEX];
               struct ArgusDataStruct *data = NULL;

               if ((data = (void *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) == NULL)
                  if ((data = (void *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) == NULL)
                     return;

               if (!parser->qflag) {
                  struct timeval tvpbuf, *tvp = &tvpbuf;
                  char tbuf[129], sbuf[129], *sptr = sbuf;
                  char *dptr = data->array;
                  char *ptr = ArgusRecordBuffer;
                  unsigned long len = sizeof(ArgusRecordBuffer);
                  int cnt = 0;

                  if (parser->Lflag && !(parser->ArgusPrintXml)) {
                  }

#if defined(HAVE_ZLIB_H)
                  if (data->hdr.subtype & ARGUS_DATA_COMPRESS) {
                     bzero (ptr, sizeof(ArgusRecordBuffer));
                     uncompress((Bytef *)ptr, (uLongf *)&len, (Bytef *)&data->array, data->count);
                     dptr = ptr;
                     cnt = data->size;
                  } else {
#endif
                     cnt = data->count;
#if defined(HAVE_ZLIB_H)
                  }
#endif

                  tbuf[0] = '\0';
                  bzero (sptr, sizeof(sbuf));
                  tvp->tv_sec  = time->src.start.tv_sec;
                  tvp->tv_usec = time->src.start.tv_usec;

                  ArgusPrintTime(parser, tbuf, sizeof(tbuf), tvp);
                  ArgusPrintSourceID(parser, sptr, argus, 128);

                  while (isspace((int)sbuf[strlen(sbuf) - 1]))
                     sbuf[strlen(sbuf) - 1] = '\0';

                  while (isspace((int)*sptr)) sptr++;

                  if (!(parser->ArgusPrintXml)) {
                     if (fprintf (stdout, "event[%d]=\n%s:srcid=%s:%s\n", cnt, tbuf, sptr, dptr) < 0)
                        RaParseComplete(SIGQUIT);
                  } else {
                     if (fprintf (stdout, "%s\n", dptr) < 0)
                        RaParseComplete(SIGQUIT);
                  }
                  fflush (stdout);
               }
         }
         break;
      }
   }
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}

void
RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   if (parser->ArgusWfileList != NULL) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = parser->ArgusWfileList->count;

      if ((lobj = parser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               int retn = 1;
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
                        rv = ArgusWriteNewLogfile (parser, argus->input,
                                                   wfile, argusrec);
                        if (rv < 0)
                           ArgusLog(LOG_ERR, "%s unable to open file\n", __func__);
                     }
                  }
               }
            }

            lobj = lobj->nxt;
         }
      }

   } else {
      static char buf[MAXSTRLEN];

      if ((parser->ArgusPrintMan) && (!parser->qflag)) {
         if (parser->Lflag && !(parser->ArgusPrintXml)) {
            if (parser->RaLabel == NULL)
               parser->RaLabel = ArgusGenerateLabel(parser, argus);
 
            if (!(parser->RaLabelCounter++ % parser->Lflag))
               printf ("%s\n", parser->RaLabel);
 
            if (parser->Lflag < 0)
               parser->Lflag = 0;
         }

         bzero (buf, sizeof(buf));
         ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);

         if (fprintf (stdout, "%s\n", buf) < 0)
            RaParseComplete(SIGQUIT);
         fflush (stdout);
      }
   }

#ifdef ARGUSDEBUG
   {
      struct ArgusRecord *rec = (struct ArgusRecord *) argus->dsrs[0];
      if (rec != NULL) {
         struct ArgusMarStruct *mar = &rec->ar_un.mar;
         ArgusDebug (6, "RaProcessManRecord (0x%x, 0x%x) mar parsed 0x%x", parser, argus, mar); 
      } else 
         ArgusDebug (6, "RaProcessManRecord (0x%x, 0x%x) mar parsed", parser, argus); 
   }
#endif
}
