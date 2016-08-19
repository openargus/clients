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
 */

/* 
 * $Id: //depot/argus/clients/clients/ra.c#80 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

/*
 *
 * ra  - Read Argus 
 *       This program reads argus output streams, either through a socket,
 *       a piped stream, or in a file, filters and optionally writes the
 *       output to 1) a file, 2) its stdout or 3) prints the binary records
 *       to stdout in ASCII.
 *
 * written by Carter Bullard
 * QoSient, LLC
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

extern int ArgusTotalMarRecords;
extern int ArgusTotalFarRecords;

extern struct ArgusParserStruct *ArgusParser;

int RaPrintCounter = 1;


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

      if (parser->Pctflag) {
         parser->ArgusPassNum = 2;
         if ((parser->ArgusAggregator = ArgusNewAggregator(parser, "srcid", ARGUS_RECORD_AGGREGATOR)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");
      }


      if (parser->dflag) {
         int pid;

         if (parser->Sflag)
            parser->ArgusReliableConnection++;

         ArgusLog(LOG_WARNING, "started");
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
      }

      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input) { return; }

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {

         if (ArgusParser->Aflag) {
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__APPLE_CC__) || defined(__APPLE__) || defined(ARGUS_SOLARIS)
            printf (" Totalrecords %-8lld  TotalMarRecords %-8lld  TotalFarRecords %-8lld TotalPkts %-8lld TotalBytes %-8lld\n",
                          ArgusParser->ArgusTotalRecords + 1, ArgusParser->ArgusTotalMarRecords, ArgusParser->ArgusTotalFarRecords,
                          ArgusParser->ArgusTotalPkts, ArgusParser->ArgusTotalBytes);
#else
            printf (" Totalrecords %-8Ld  TotalManRecords %-8Ld  TotalFarRecords %-8Ld TotalPkts %-8Ld TotalBytes %-8Ld\n",
                          ArgusParser->ArgusTotalRecords + 1, ArgusParser->ArgusTotalMarRecords, ArgusParser->ArgusTotalFarRecords,
                          ArgusParser->ArgusTotalPkts, ArgusParser->ArgusTotalBytes);
#endif
         }

         fflush(stdout);
         ArgusShutDown(sig);
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


void
ArgusClientTimeout ()
{
   if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = ArgusParser->ArgusWfileList->count;

      if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               if (wfile->fd != NULL)
                  fflush(wfile->fd);
            }
            lobj = lobj->nxt;
         }
      }
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

   fprintf (stdout, "Ra Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] [- filter-expression]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -A                     print record summaries on termination.\n");
   fprintf (stdout, "         -b                     dump packet-matching code.\n");
   fprintf (stdout, "         -c <char>              specify a delimiter <char> for output columns.\n");
   fprintf (stdout, "         -C <[host]:port>       specify Cisco Netflow source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stdout, "         -D <level>             specify debug level\n");
#endif
   fprintf (stdout, "         -e <regex>             match regular expression in flow user data fields.\n");
   fprintf (stdout, "                                Prepend the regex with either \"s:\" or \"d:\" to limit the match\n");
   fprintf (stdout, "                                to either the source or destination user data fields.\n");
   fprintf (stdout, "         -E <file>              write records that are rejected by the filter into <file>\n");
   fprintf (stdout, "         -F <conffile>          read configuration from <conffile>.\n");
   fprintf (stdout, "         -h                     print help.\n");
   fprintf (stdout, "         -H                     abbreviate numeric values. Use -p option to control precision.\n");
   fprintf (stdout, "         -M <option>            specify a Mode of operation.\n");
   fprintf (stdout, "            rmon                convert bi-directional flow data to RMON in/out stats\n");
   fprintf (stdout, "            poll                attach to remote server to get MAR and then disconnect\n");
   fprintf (stdout, "            xml                 print output in xml format\n");
   fprintf (stdout, "            TZ='timezone'       set TZ environment variable with timezone string\n");
   fprintf (stdout, "            saslmech='mech'     specify the sasl mechanism to use for this connection\n");
   fprintf (stdout, "            label='str'         specify label matching expression\n");
   fprintf (stdout, "            printer='printer'   specify user data printing format\n");
   fprintf (stdout, "               ascii            print user data using ascii encoding\n");
   fprintf (stdout, "               obfuscate        print user data using ascii` encoding, obfuscate passwords\n");
   fprintf (stdout, "               encode32         print user data using encode32 encoding\n");
   fprintf (stdout, "               encode64         print user data using encode64 encoding\n");
   fprintf (stdout, "               hex              print user data using hex encoding\n");
   fprintf (stdout, "            dsrs='strip str'    specify input dsrs (see rastrip.1)\n");
   fprintf (stdout, "            sql='str'           use str as \"WHERE\" clause in sql call.\n");
   fprintf (stdout, "            disa                Use US DISA diff-serve encodings\n");
   fprintf (stdout, "         -n                     don't convert numbers to names.\n");
   fprintf (stdout, "         -N [io]<num>           process the first <num> records in the stream. Optional initial char\n");
   fprintf (stdout, "                                specifies the input or output stream.  The default is 'i'nput.\n");
   fprintf (stdout, "            [io]<start-end>     process this inclusive range of matching records.\n");
   fprintf (stdout, "            [io]<start+num>     process this number of matching records, starting at start.\n");
   fprintf (stdout, "         -p <digits>            print fractional time with <digits> precision.\n");
   fprintf (stdout, "         -q                     quiet mode. don't print record outputs.\n");
   fprintf (stdout, "         -r <[type:]file[::ostart[:ostop]] ...>\n");
   fprintf (stdout, "                                read <type> data from <file>. '-' denotes stdin.\n");
   fprintf (stdout, "                                types supported are argus (default), 'cisco' and 'ft' (flow-tools)\n");
   fprintf (stdout, "                                optionally provide starting and ending byte offsets\n");
   fprintf (stdout, "                                for seeking into file. Must be legitimate record boundaries.\n");
   fprintf (stdout, "         -R <dir>               recursively process files in directory\n");
   fprintf (stdout, "         -s [-][+[#]]field[:w]  specify fields to print.\n");
   fprintf (stdout, "                   fields:      srcid, stime, ltime, sstime, dstime, sltime, dltime,\n");
   fprintf (stdout, "                                trans, seq, flgs, dur, avgdur, stddev, mindur, maxdur,\n");
   fprintf (stdout, "                                saddr, daddr, proto, sport, dport, stos, dtos, sdsb, ddsb\n");
   fprintf (stdout, "                                sco, dco, sttl, dttl, sipid, dipid, smpls, dmpls, svlan, dvlan\n");
   fprintf (stdout, "                                svid, dvid, svpri, dvpri, [s|d]pkts, [s|d]bytes,\n");
   fprintf (stdout, "                                [s||d]appbytes, [s|d]load, [s|d]loss, [s|d]ploss, [s|d]rate,\n");
   fprintf (stdout, "                                smac, dmac, dir, [s|d]intpkt, [s|d]jit, state, suser, duser,\n");
   fprintf (stdout, "                                swin, dwin, trans, srng, erng, stcpb, dtcpb, tcprtt, inode,\n");
   fprintf (stdout, "                                offset, smaxsz, dmaxsz, sminsz, dminsz\n");
   fprintf (stdout, "         -S <[user[:pass]@]host[:port]>       specify remote argus and optional port number\n");
   fprintf (stdout, "         -S <URI://[user[:pass]@]host[:port]> \n");
   fprintf (stdout, "             URI : argus-udp    \n");
   fprintf (stdout, "                   argus-tcp    \n");
   fprintf (stdout, "                   argus        \n");
   fprintf (stdout, "                                \n");
   fprintf (stdout, "         -t <timerange>         specify <timerange> for reading records.\n");
   fprintf (stdout, "                   format:      timeSpecification[-timeSpecification]\n");
   fprintf (stdout, "                                timeSpecification: [[[yyyy/]mm/]dd.]hh[:mm[:ss]]\n");
   fprintf (stdout, "                                                     [yyyy/]mm/dd\n");
   fprintf (stdout, "                                                     -%%d{yMdhms}\n");
   fprintf (stdout, "         -T <secs>              attach to remote server for T seconds.\n");
   fprintf (stdout, "         -u                     print time in Unix time format.\n");
#ifdef ARGUS_SASL
   fprintf (stdout, "         -U <user/auth>         specify <user/auth> authentication information.\n");
#endif
   fprintf (stdout, "         -w <file>              write output to <file>. '-' denotes stdout.\n");
   fprintf (stdout, "         -X                     don't read default rarc file.\n");
   fprintf (stdout, "         -z                     print Argus TCP state changes.\n");
   fprintf (stdout, "         -Z <s|d|b>             print actual TCP flag values.\n");
   fprintf (stdout, "                                <'s'rc | 'd'st | 'b'oth>\n");
   fflush (stdout);
   exit(1);
}

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
         RaProcessManRecord (parser, argus);
         break;

      case ARGUS_EVENT:
         RaProcessEventRecord (parser, argus);
         break;

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (ArgusParser->Aflag) {
            struct ArgusMetricStruct *metric = (void *)argus->dsrs[ARGUS_METRIC_INDEX];

            if (metric != NULL) {
               parser->ArgusTotalPkts  += metric->src.pkts;
               parser->ArgusTotalPkts  += metric->dst.pkts;
               parser->ArgusTotalBytes += metric->src.bytes;
               parser->ArgusTotalBytes += metric->dst.bytes;
            }
         }

         if ((parser->RaMonMode) || (parser->RaUniMode)) {
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(argus);
            struct ArgusFlow *flow;

            if ((flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, argus);
            ArgusReverseRecord(tns);

            if ((flow = (void *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);

         } else {
            RaProcessThisRecord(parser, argus);
         }
      }
   }
}


extern void ArgusUniDirectionalRecord (struct ArgusRecordStruct *argus);

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   static char buf[MAXSTRLEN];
            
   if (parser->RaUniMode) {
      struct ArgusMetricStruct *metric = (void *)argus->dsrs[ARGUS_METRIC_INDEX];

      ArgusUniDirectionalRecord (argus);
      if (metric->src.pkts == 0)
         return;
   }

   switch (parser->ArgusPassNum)  {
      case 2: {
         if (parser->Pctflag) {
            if (parser->ns == NULL) {
               parser->ns = ArgusCopyRecordStruct(argus);
            } else {
               ArgusMergeRecords (parser->ArgusAggregator, parser->ns, argus);
            }
         }
         break;
      }

      case 1: {
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
                        argus->rank = RaPrintCounter++;

                        if ((ArgusParser->eNoflag == 0 ) || ((ArgusParser->eNoflag >= argus->rank) && (ArgusParser->sNoflag <= argus->rank))) {
                           if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                              struct ArgusRecord *argusrec = NULL;
                              static char sbuf[0x10000];

                              if ((argusrec = ArgusGenerateRecord (argus, 0L, sbuf)) != NULL) {
      #ifdef _LITTLE_ENDIAN
                                 ArgusHtoN(argusrec);
      #endif
                                 ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                              }
                           }

                        } else {
                           if (ArgusParser->eNoflag < argus->rank) 
                              break;
                        }
                     }
                  }
      
                  lobj = lobj->nxt;
               }
            }
      
         } else {
            if (!parser->qflag) {
               int retn = 0;
               if (parser->Lflag && !(parser->ArgusPrintXml)) {
                  if (parser->RaLabel == NULL)
                     parser->RaLabel = ArgusGenerateLabel(parser, argus);
       
                  if (!(parser->RaLabelCounter++ % parser->Lflag))
                     if ((retn = printf ("%s\n", parser->RaLabel)) < 0) 
                        RaParseComplete (SIGQUIT);
       
                  if (parser->Lflag < 0)
                     parser->Lflag = 0;
               }
      
               bzero (buf, sizeof(buf));
               argus->rank = RaPrintCounter++;

               if ((ArgusParser->eNoflag == 0 ) || ((ArgusParser->eNoflag >= argus->rank) && (ArgusParser->sNoflag <= argus->rank))) {
                  ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);
      
                  if ((retn = fprintf (stdout, "%s", buf)) < 0)
                     RaParseComplete (SIGQUIT);
      
                  if (parser->eflag == ARGUS_HEXDUMP) {
                     int i;
                     for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
                        if (parser->RaPrintAlgorithmList[i] != NULL) {
                           struct ArgusDataStruct *user = NULL;
                           if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcUserData) {
                              int slen = 0, len = parser->RaPrintAlgorithmList[i]->length;
                              if (len > 0) {
                                 if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) != NULL) {
                                    if (user->hdr.type == ARGUS_DATA_DSR) {
                                       slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                                    } else
                                       slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;
                                       
                                    slen = (user->count < slen) ? user->count : slen;
                                    slen = (slen > len) ? len : slen;
                                    ArgusDump ((const u_char *) &user->array, slen, "      ");
                                 }
                              }
                           }
                           if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintDstUserData) {
                              int slen = 0, len = parser->RaPrintAlgorithmList[i]->length;
                              if (len > 0) {
                                 if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) != NULL) {
                                    if (user->hdr.type == ARGUS_DATA_DSR) {
                                       slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                                    } else
                                       slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;
         
                                    slen = (user->count < slen) ? user->count : slen;
                                    slen = (slen > len) ? len : slen;
                                    ArgusDump ((const u_char *) &user->array, slen, "      ");
                                 }
                              }
                           }
                        } else
                           break;
                     }
                  }
         
                  fprintf (stdout, "\n");
                  fflush (stdout);

               } else {
                  if ((ArgusParser->eNoflag != 0 ) && (ArgusParser->eNoflag < argus->rank))
                     RaParseComplete (SIGQUIT);
               }
            }
         }
      }
   }
}

void
RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   static char buf[MAXSTRLEN];

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
                  struct ArgusRecord *argusrec = NULL;
                  if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                     if (argus->status & ARGUS_INIT_MAR) {
                        argusrec = &argus->input->ArgusInitCon;
                     } else {
                        static char sbuf[0x10000];
                        if ((argusrec = ArgusGenerateRecord (argus, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                           ArgusHtoN(argusrec);
#endif
                        }
                     }
                     if (argusrec != NULL)
                        ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                  }
               }
            }

            lobj = lobj->nxt;
         }
      }

   } else {

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
         if (argus->dsrs[0] != NULL) {
            ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);
            if (fprintf (stdout, "%s\n", buf) < 0)
               RaParseComplete (SIGQUIT);
         }
         fflush (stdout);
      }
   }

#ifdef ARGUSDEBUG
   {
      struct ArgusRecord *rec = (struct ArgusRecord *)argus->dsrs[0];
      if (rec != NULL) {
         struct ArgusMarStruct *mar = &rec->ar_un.mar;
         ArgusDebug (6, "RaProcessManRecord (0x%x, 0x%x) mar parsed 0x%x", parser, argus, mar); 
      }
   }
#endif
}


void
RaProcessEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   static char buf[MAXSTRLEN];

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
                     static char sbuf[0x10000];
                     if ((argusrec = ArgusGenerateRecord (argus, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                     }
                  }
               }
            }

            lobj = lobj->nxt;
         }
      }

   } else {

      if ((parser->ArgusPrintEvent) && (!parser->qflag)) {
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
            RaParseComplete (SIGQUIT);
         fflush (stdout);
      }
   }

#ifdef ARGUSDEBUG
   {
      struct ArgusRecord *rec = (struct ArgusRecord *)argus->dsrs[0];

      if (rec != NULL) {
         struct ArgusEventStruct *event = &rec->ar_un.event;
         ArgusDebug (6, "RaProcessEventRecord (0x%x, 0x%x) event parsed 0x%x", parser, argus, event); 
      }
   }
#endif
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}
