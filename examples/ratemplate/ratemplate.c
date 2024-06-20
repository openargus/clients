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
 * ratemplate.c  - template for ra* client programs.  add application
 *                 specific code, stir and enjoy.
 *
 */

/*
 * $Id: //depot/gargoyle/clients/examples/ratemplate/ratemplate.c#6 $
 * $DateTime: 2014/10/07 15:35:03 $
 * $Change: 2940 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>

#include <argus_compat.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>

/*
   For client specific definitions, name the include file by
   the same name as the app.  rabins.c is a perfect example.

#include <rabins.h>

*/

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   if (parser != NULL) {
      parser->RaWriteOut = 1;

      if (!(parser->RaInitialized)) {
         struct ArgusModeStruct *mode = NULL;

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

   /*
      many clients will do conventional work on argus records, like
      filtering, aggregation, etc...  Some of these library supported
      functions require initialization, which should be done here.

      For example, if you plan to merge records together, you could
      instantiate an aggregation object here.

         if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");
    */

   /*
      The clients library parses -M mode options, and you the client
      program should parse them out here.  The modes are stored
      in the ArgusModeList in the parser.  Here is a sample
      processing loop for handling a list of the common modes
      that argus clients support.
    */

         if ((mode = parser->ArgusModeList) != NULL) {
            while (mode) {
               if (!(strncasecmp (mode->mode, "poll", 4)))
                  parser->RaPollMode++;

               if (!(strncasecmp (mode->mode, "rmon", 4)))
                  parser->RaMonMode++;

               if (!(strncasecmp (mode->mode, "uni", 3)))
                  parser->RaUniMode++;

               if (!(strncasecmp (mode->mode, "oui", 3)))
                  parser->ArgusPrintEthernetVendors++;

               if (!(strncasecmp (mode->mode, "man", 3)))
                  parser->ArgusPrintMan = 1;

               if (!(strncasecmp (mode->mode, "noman", 5)))
                  parser->ArgusPrintMan = 0;

               mode = mode->nxt;
            }
         }

         parser->RaInitialized++;
      }

      if (parser->dflag) {
         int pid;

         if (parser->Sflag)
            parser->ArgusReliableConnection++;

         ArgusLog(LOG_INFO, "started");
         if (chdir ("/") < 0)
            ArgusLog (LOG_ERR, "Can't chdir to / %s", strerror(errno));

         if ((pid = fork ()) < 0) {
            ArgusLog (LOG_ERR, "Can't fork daemon %s", strerror(errno));
         } else {
            if (pid) {
               struct timespec ts = {0, 20000000};
               int status;
               nanosleep(&ts, NULL);   
               waitpid(pid, &status, WNOHANG);
               if (kill(pid, 0) < 0) {
                  exit (1);
               } else
                  exit (0);
            } else {
               FILE *tmpfile;

               parser->ArgusSessionId = setsid();
               if ((tmpfile = freopen ("/dev/null", "r", stdin)) == NULL)
                  ArgusLog (LOG_ERR, "Cannot map stdout to /dev/null");

               if ((tmpfile = freopen ("/dev/null", "a+", stdout)) == NULL)
                  ArgusLog (LOG_ERR, "Cannot map stdout to /dev/null");

               if ((tmpfile = freopen ("/dev/null", "a+", stderr)) == NULL)
                  ArgusLog (LOG_ERR, "Cannot map stderr to /dev/null");
            }
         }

      } else 
         fprintf (stdout, "ratemplate initialized\n");
   }
}

void RaArgusInputComplete (struct ArgusInput *input) { return; }


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (ArgusParser && !ArgusParser->RaParseCompleting++) {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(caught signal %d)\n", sig);
#endif
         fprintf (stdout, "ratemplate shutdown\n");
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
                           lobj = lobj->nxt;
                        }
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
   fprintf (stdout, "ratemplate calling timer routine\n");
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
   fprintf (stdout, "usage: %s [options] -S remoteServer  [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -A                 print record summaries on termination.\n");
   fprintf (stdout, "         -b                 dump packet-matching code.\n");
   fprintf (stdout, "         -c <char>          specify a delimiter <char> for output columns.\n");
   fprintf (stdout, "         -C <[host]:port>   specify remote Cisco Netflow source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stdout, "         -D <level>         specify debug level\n");
#endif
   fprintf (stdout, "         -e <encode>        convert user data using <encode> method.\n");
   fprintf (stdout, "                            Supported types are <Ascii> and <Encode64>.\n");
   fprintf (stdout, "         -E <file>          write records that are rejected by the filter\n");
   fprintf (stdout, "                            into <file>\n");
   fprintf (stdout, "         -F <conffile>      read configuration from <conffile>.\n");
   fprintf (stdout, "         -h                 print help.\n");
   fprintf (stdout, "         -n                 don't convert numbers to names.\n");
   fprintf (stdout, "         -p <digits>        print fractional time with <digits> precision.\n");
   fprintf (stdout, "         -q                 quiet mode. don't print record outputs.\n");
   fprintf (stdout, "         -r <file>          read argus data <file>. '-' denotes stdin.\n");
   fprintf (stdout, "         -R <dir>           recursively process files in directory\n");
   fprintf (stdout, "         -s [-][+[#]]field  specify fields to print.\n");
   fprintf (stdout, "                   fields:  srcid, stime, ltime, trans, seq, flgs, dur, avgdur,\n");
   fprintf (stdout, "                            stddev, mindur, maxdur, saddr, daddr, proto, sport,\n");
   fprintf (stdout, "                            dport, stos, dtos, sdsb, ddsb, sttl, dttl, sipid,\n");
   fprintf (stdout, "                            dipid, smpls, dmpls, [s|d]pkts, [s|d]bytes,\n");
   fprintf (stdout, "                            [s||d]appbytes, [s|d]load, [s|d]loss, [s|d]ploss,\n");
   fprintf (stdout, "                            [s|d]rate, smac, dmac, dir, [s|d]intpkt, [s|d]jit,\n");
   fprintf (stdout, "                            status, suser, duser, swin, dwin, svlan, dvlan,\n");
   fprintf (stdout, "                            svid, dvid, svpri, dvpri, srng, drng, stcpb, dtcpb,\n");
   fprintf (stdout, "                            tcprtt, inode\n");
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
   fprintf (stdout, "         -z                 print Argus TCP state changes.\n");
   fprintf (stdout, "         -Z <s|d|b>         print actual TCP flag values.\n");
   fprintf (stdout, "                            <'s'rc | 'd'st | 'b'oth>\n");
   fflush (stdout);

   exit(1);
}


void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
         fprintf (stdout, "ratemplate processing management record\n");
         break;
      case ARGUS_EVENT:
         fprintf (stdout, "ratemplate processing event record\n");
         break;
      case ARGUS_AFLOW:
         fprintf (stdout, "ratemplate processing aflow record\n");
         break;
      case ARGUS_NETFLOW:
         fprintf (stdout, "ratemplate processing netflow record\n");
         break;
      case ARGUS_FAR:
         fprintf (stdout, "ratemplate processing flow record\n");
         break;
   }
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}
