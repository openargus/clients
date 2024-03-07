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
 * ratimerange.c  - print out the time range for the data seen.
 *
 * Carter Bullard
 * QoSient, LLC
 *
 */

/*
 * $Id: //depot/gargoyle/clients/examples/ratimerange/ratimerange.c#5 $
 * $DateTime: 2016/10/13 07:13:10 $
 * $Change: 3222 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <signal.h>
#include <ctype.h>

struct timeval RaStartTime = {0x7FFFFFFF, 0x7FFFFFFF};
struct timeval RaEndTime   = {0x00000000, 0x00000000};

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   parser->RaWriteOut = 1;

   if (!(parser->RaInitialized)) {

/*
   the library sets signal handling routines for 
   SIGHUP, SIGTERM, SIGQUIT, SIGINT, SIGUSR1, and SIGUSR2.
   SIGHUP doesn't do anything, SIGTERM, SIGQUIT, and SIGINT
   call the user supplied RaParseComplete().  SIGUSR1 and
   SIGUSR2 modify the debug level so if compiled with
   ARGUS_DEBUG support, programs can start generating 
   debug information.  USR1 increments by 1, USR2 sets
   it back to zero.

*/
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input) { return; }


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
         char sbuf[128], ebuf[128];

         sbuf[0] = '\0';
         ebuf[0] = '\0';

         if (ArgusParser->ArgusTotalRecords > 0) {
            ArgusPrintTime(ArgusParser, sbuf, sizeof(sbuf), &RaStartTime);
            ArgusPrintTime(ArgusParser, ebuf, sizeof(ebuf), &RaEndTime);

            printf ("%s - %s\n", sbuf, ebuf);
            fflush (stdout);
         }

#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(caught signal %d)\n", sig);
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
               exit(0);
               break;
            }
         }
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

   fprintf (stdout, "Ratemplate Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [ra-options] -S remoteServer [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [ra-options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -C <[host]:port>   specify remote Cisco Netflow source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stdout, "         -D <level>         specify debug level\n");
#endif
   fprintf (stdout, "         -F <conffile>      read configuration from <conffile>.\n");
   fprintf (stdout, "         -h                 print help.\n");
   fprintf (stdout, "         -p <digits>        print fractional time with <digits> precision.\n");
   fprintf (stdout, "         -r <file>          read argus data <file>. '-' denotes stdin.\n");
   fprintf (stdout, "         -R <dir>           recursively decend to read argus data files.\n");
   fprintf (stdout, "         -S <host[:port]>   specify remote argus <host> and optional port number.\n");
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
   fflush (stdout);

   exit(1);
}


void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR: {
         struct ArgusRecord *rec = (struct ArgusRecord *)argus->dsrs[0];
         if ((rec->hdr.cause & 0xF0) == ARGUS_START) {
            if (rec->ar_un.mar.now.tv_sec)
               if ((RaStartTime.tv_sec  > rec->ar_un.mar.now.tv_sec) ||
                  ((RaStartTime.tv_sec == rec->ar_un.mar.now.tv_sec) &&
                  (RaStartTime.tv_usec > rec->ar_un.mar.now.tv_usec))) {
                  RaStartTime.tv_sec  = rec->ar_un.mar.now.tv_sec;
                  RaStartTime.tv_usec = rec->ar_un.mar.now.tv_usec;
               }

         } else 
            if (rec->ar_un.mar.now.tv_sec)
               if ((RaEndTime.tv_sec  < rec->ar_un.mar.now.tv_sec) ||
                  ((RaEndTime.tv_sec == rec->ar_un.mar.now.tv_sec) &&
                  (RaEndTime.tv_usec < rec->ar_un.mar.now.tv_usec))) {
                  RaEndTime.tv_sec  = rec->ar_un.mar.now.tv_sec;
                  RaEndTime.tv_usec = rec->ar_un.mar.now.tv_usec;
               }
         break;
      }

      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusTimeObject *time = (void *)argus->dsrs[ARGUS_TIME_INDEX];

         if (time != NULL) {
            if (time->src.start.tv_sec) 
            if ((RaStartTime.tv_sec  > time->src.start.tv_sec) ||
               ((RaStartTime.tv_sec == time->src.start.tv_sec) &&
                (RaStartTime.tv_usec > time->src.start.tv_usec))) {
               RaStartTime.tv_sec  = time->src.start.tv_sec;
               RaStartTime.tv_usec = time->src.start.tv_usec;
            }

            if (time->dst.start.tv_sec) 
            if ((RaStartTime.tv_sec  > time->dst.start.tv_sec) ||
               ((RaStartTime.tv_sec == time->dst.start.tv_sec) &&
                (RaStartTime.tv_usec > time->dst.start.tv_usec))) {
               RaStartTime.tv_sec  = time->dst.start.tv_sec;
               RaStartTime.tv_usec = time->dst.start.tv_usec;
            }

            if (time->src.start.tv_sec) 
            if ((RaEndTime.tv_sec  < time->src.start.tv_sec) ||
               ((RaEndTime.tv_sec == time->src.start.tv_sec) &&
                (RaEndTime.tv_usec < time->src.start.tv_usec))) {
               RaEndTime.tv_sec  = time->src.start.tv_sec;
               RaEndTime.tv_usec = time->src.start.tv_usec;
            }

            if (time->src.end.tv_sec) 
            if ((RaEndTime.tv_sec  < time->src.end.tv_sec) ||
               ((RaEndTime.tv_sec == time->src.end.tv_sec) &&
                (RaEndTime.tv_usec < time->src.end.tv_usec))) {
               RaEndTime.tv_sec  = time->src.end.tv_sec;
               RaEndTime.tv_usec = time->src.end.tv_usec;
            }

            if (time->dst.start.tv_sec) 
            if ((RaEndTime.tv_sec  < time->dst.start.tv_sec) ||
               ((RaEndTime.tv_sec == time->dst.start.tv_sec) &&
                (RaEndTime.tv_usec < time->dst.start.tv_usec))) {
               RaEndTime.tv_sec  = time->dst.start.tv_sec;
               RaEndTime.tv_usec = time->dst.start.tv_usec;
            }

            if (time->dst.end.tv_sec) 
            if ((RaEndTime.tv_sec  < time->dst.end.tv_sec) ||
               ((RaEndTime.tv_sec == time->dst.end.tv_sec) &&
                (RaEndTime.tv_usec < time->dst.end.tv_usec))) {
               RaEndTime.tv_sec  = time->dst.end.tv_sec;
               RaEndTime.tv_usec = time->dst.end.tv_usec;
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
