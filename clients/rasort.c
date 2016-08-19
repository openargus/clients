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
 * 
 * $Id: //depot/argus/clients/clients/rasort.c#53 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

/*
 * rasort.c  - sort argus records based on various fields.
 *       
 * written by Carter Bullard
 * QoSient, LLC
 *
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
#include <argus_sort.h>
#include <argus_filter.h>

#include <signal.h>
#include <ctype.h>


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode;
   int i = 0, x = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      parser->RaWriteOut = 0;

      if (parser->vflag)
         ArgusReverseSortDir++;

      if ((ArgusSorter = ArgusNewSorter(parser)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit ArgusNewSorter error %s", strerror(errno));

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strcmp ("replace", mode->mode))) {
               ArgusProcessFileIndependantly = 1;
               parser->ArgusReplaceMode |= ARGUS_REPLACE_MODE_TRUE;

               if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList)))) {
                  ArgusLog (LOG_ERR, "replace mode and -w option are incompatible\n");
               }
            } else
            if (!(strncasecmp (mode->mode, "poll", 4)))
               parser->RaPollMode++;
            else
            if (!(strncasecmp (mode->mode, "rmon", 4)))
               parser->RaMonMode++;
            else
            if (!(strncasecmp (mode->mode, "uni", 3)))
               parser->RaUniMode++;
            else
            if (!(strncasecmp (mode->mode, "oui", 3)))
               parser->ArgusPrintEthernetVendors++;
            else
            if (!(strncasecmp (mode->mode, "man", 3)))
               parser->ArgusPrintMan = 1;
            else
            if (!(strncasecmp (mode->mode, "noman", 5)))
               parser->ArgusPrintMan = 0;

            mode = mode->nxt;
         }
      }

      if ((mode = parser->ArgusMaskList) != NULL) {
         char *ptr;
         while (mode) {
            for (x = 0; x < MAX_SORT_ALG_TYPES; x++) {
               if (!strncmp (ArgusSortKeyWords[x], mode->mode, strlen(ArgusSortKeyWords[x]))) {
                  ArgusSorter->ArgusSortAlgorithms[i++] = ArgusSortAlgorithmTable[x];
                  if (ArgusSortAlgorithmTable[x] == ArgusSortSrcAddr) {
                     if ((ptr = strchr(mode->mode, '/')) != NULL) {
                        int cidr = 0;
                        ptr++;
                        cidr = atoi(ptr);
                        ArgusSorter->ArgusSrcAddrCIDR = cidr;
                     }
                  }
                  if (ArgusSortAlgorithmTable[x] == ArgusSortDstAddr) {
                     if ((ptr = strchr(mode->mode, '/')) != NULL) {
                        int cidr = 0;
                        ptr++;
                        cidr = atoi(ptr);
                        ArgusSorter->ArgusSrcAddrCIDR = cidr;
                     }
                  }
                  break;
               }
            }

            if (x == MAX_SORT_ALG_TYPES)
               ArgusLog (LOG_ERR, "sort syntax error. \'%s\' not supported", mode->mode);

            mode = mode->nxt;
         }
      }

      parser->RaParseCompleting = 0;
      parser->RaInitialized++;
   }
}

void
RaArgusInputComplete (struct ArgusInput *input)
{
   if (ArgusProcessFileIndependantly) {
      ArgusParser->ArgusCurrentInput = input;
      RaParseComplete (0);

      ArgusParser->RaInitialized = 0;
      ArgusParser->ArgusCurrentInput = NULL;
      ArgusClientInit(ArgusParser);
   }
}


void
RaParseComplete (int sig)
{
   struct ArgusInput *file = ArgusParser->ArgusCurrentInput;
   int i = 0, count = 0;
   char buf[MAXSTRLEN];
   int label;

   if (sig >= 0) {
      if (!(ArgusParser->RaParseCompleting++)) {
         int rank = 1;

         ArgusParser->RaParseCompleting += sig;

         if (ArgusParser->ArgusReplaceMode && file) {
            if (ArgusParser->ArgusReplaceMode & ARGUS_REPLACE_COMPRESSED_GZ) {
               char *ptr;
               if ((ptr = strstr(file->filename, ".gz")) != NULL) {
                  ArgusParser->ArgusReplaceMode |= ARGUS_REPLACE_FILENAME_MODIFIED;
                  *ptr = '\0';
               }
            }
            if (ArgusParser->ArgusReplaceMode & ARGUS_REPLACE_COMPRESSED_BZ) {
               char *ptr;
               if ((ptr = strstr(file->filename, ".bz2")) != NULL) {
                  ArgusParser->ArgusReplaceMode |= ARGUS_REPLACE_FILENAME_MODIFIED;
                  *ptr = '\0';
               }
            }

            if (!(ArgusParser->ArgusRandomSeed))
               srandom(ArgusParser->ArgusRandomSeed);

            srandom (ArgusParser->ArgusRealTime.tv_usec);
            label = random() % 100000;

            bzero(buf, sizeof(buf));
            snprintf (buf, MAXSTRLEN, "%s.tmp%d", file->filename, label);

            setArgusWfile(ArgusParser, buf, NULL);
         }

         count = ArgusSorter->ArgusRecordQueue->count;

         if (count > 0) {
            ArgusSortQueue (ArgusSorter, ArgusSorter->ArgusRecordQueue);
            count = ArgusSorter->ArgusRecordQueue->arraylen;
 
            for (i = 0; i < count; i++) {
               struct ArgusRecordStruct *ns = (struct ArgusRecordStruct *) ArgusSorter->ArgusRecordQueue->array[i];
               ns->rank = rank++;

               if ((ArgusParser->eNoflag == 0 ) || ((ArgusParser->eNoflag >= ns->rank) && (ArgusParser->sNoflag <= ns->rank)))
                  RaSendArgusRecord (ns);
               else
                  if (ArgusParser->eNoflag < ns->rank) 
                     break;
            }
         }
      }

      if (ArgusParser->ArgusReplaceMode && file) {
         if (ArgusParser->ArgusWfileList != NULL) {
            struct ArgusWfileStruct *wfile = NULL;

            if ((wfile = (void *)ArgusParser->ArgusWfileList->start) != NULL) {
               fflush (wfile->fd);
               rename (wfile->filename, file->filename);
               fclose (wfile->fd);
               wfile->fd = NULL;
            }

            ArgusDeleteList(ArgusParser->ArgusWfileList, ARGUS_WFILE_LIST);
            ArgusParser->ArgusWfileList = NULL;

            if (ArgusParser->Vflag)
               ArgusLog(LOG_INFO, "file %s aggregated", file->filename);
         }

         if (ArgusParser->ArgusReplaceMode & ARGUS_REPLACE_COMPRESSED_GZ) {
            char cmdbuf[MAXSTRLEN], *cmd = cmdbuf;

            sprintf(cmd, "gzip -q %s\n", file->filename);
            if (system(cmd) < 0)
               ArgusLog (LOG_ERR, "compressing file %s failed");
         } else
         if (ArgusParser->ArgusReplaceMode & ARGUS_REPLACE_COMPRESSED_BZ) {
            char cmdbuf[MAXSTRLEN], *cmd = cmdbuf;

            sprintf(cmd, "bzip2 -f -q %s\n", file->filename);
            if (system(cmd) < 0)
               ArgusLog (LOG_ERR, "compressing file %s failed");
         }
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
             
   fprintf (stdout, "Rasort Version %s\n", version);
   fprintf (stdout, "usage: %s [[-M mode] [-m sortfield] ...] [ra-options] [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "options:    -M replace         replace the original file with the sorted output.\n");
   fprintf (stdout, "            -m <sortfield>     specify the <sortfield>(s) in order.\n");
   fprintf (stdout, "                               valid sorfields are:\n");
   fprintf (stdout, "                                  stime, ltime, trans, dur, avgdur, mindur,\n");
   fprintf (stdout, "                                  maxdur, smac, dmac, saddr[/cidr], daddr[/cidr], \n");
   fprintf (stdout, "                                  proto, sport, dport, stos, dtos, sttl, dttl,\n");
   fprintf (stdout, "                                  bytes, sbytes, dbytes, pkts, spkts, dpkts, load,\n"); 
   fprintf (stdout, "                                  sload, sload, dload, loss, sloss, dloss,\n"); 
   fprintf (stdout, "                                  ploss, psloss, pdloss, rate, srate, drate,\n"); 
   fprintf (stdout, "                                  seq, smpls, dmpls, svlan, dvlan, srcid,\n");
   fprintf (stdout, "                                  stcpb, dtcpb, tcprtt, smeansz, dmeansz\n"); 
   fprintf (stdout, "\n"); 
   fprintf (stdout, "ra-options: -b                 dump packet-matching code.\n");
   fprintf (stdout, "            -C <[host]:<port>  specify remote Cisco Netflow source.\n");
   fprintf (stdout, "                               source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stdout, "            -D <level>         specify debug level\n");
#endif
   fprintf (stdout, "            -F <conffile>      read configuration from <conffile>.\n");
   fprintf (stdout, "            -h                 print help.\n");
   fprintf (stdout, "            -r <file>          read argus data <file>. '-' denotes stdin.\n");
   fprintf (stdout, "            -s [-][+[#]]field  specify fields to print.\n");
   fprintf (stdout, "            -S <host[:port]>   specify remote argus <host> and optional port\n");
   fprintf (stdout, "                               number.\n");
   fprintf (stdout, "            -t <timerange>     specify <timerange> for reading records.\n");
   fprintf (stdout, "                      format:  timeSpecification[-timeSpecification]\n");
   fprintf (stdout, "                               timeSpecification: [mm/dd[/yy].]hh[:mm[:ss]]\n");
   fprintf (stdout, "                                                   mm/dd[/yy]\n");
   fprintf (stdout, "                                                   -%%d{yMhdms}\n");
   fprintf (stdout, "            -T <secs>          attach to remote server for T seconds.\n");
#ifdef ARGUS_SASL
   fprintf (stdout, "            -U <user/auth>     specify <user/auth> authentication information.\n");
#endif
   fprintf (stdout, "            -w <file>          write output to <file>. '-' denotes stdout.\n");
   fflush (stdout);
   exit(1);
}

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusRecordStruct *tns = NULL;

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_MAR:
         break;

      case ARGUS_EVENT:
      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if ((tns = ArgusCopyRecordStruct(ns)) == NULL)
            ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCopyRecordStruct(0x%x) error\n", ns);

         ArgusAddToQueue (ArgusSorter->ArgusRecordQueue, &tns->qhdr, ARGUS_NOLOCK);
         break;
      }
   }
}

int
RaSendArgusRecord(struct ArgusRecordStruct *ns)
{
   int retn = 1;
   char buf[0x10000];

   if (ns->status & ARGUS_RECORD_WRITTEN)
      return (retn);
 
   if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = ArgusParser->ArgusWfileList->count;

      if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               int pass = 1;
               if (wfile->filterstr) {
                  struct nff_insn *wfcode = wfile->filter.bf_insns;
                  pass = ArgusFilterRecord (wfcode, ns);
               }

               if (pass != 0) {
                  if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
                     struct ArgusRecord *argusrec = NULL;
                     if ((argusrec = ArgusGenerateRecord (ns, 0L, buf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        ArgusWriteNewLogfile (ArgusParser, ns->input, wfile, argusrec);
                     }
                  }
               }
            }
            lobj = lobj->nxt;
         }
      }

   } else {
      if (!ArgusParser->qflag) {
         if (ArgusParser->Lflag) {
            if (ArgusParser->RaLabel == NULL)
               ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, ns);
 
            if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag))
               printf ("%s\n", ArgusParser->RaLabel);
 
            if (ArgusParser->Lflag < 0)
               ArgusParser->Lflag = 0;
         }

         *(int *)&buf = 0;
         ArgusPrintRecord(ArgusParser, buf, ns, MAXSTRLEN);
         if (fprintf (stdout, "%s\n", buf) < 0)
           RaParseComplete(SIGQUIT);

         if (ArgusParser->eflag == ARGUS_HEXDUMP) {
            int i;
            for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
               if (ArgusParser->RaPrintAlgorithmList[i] != NULL) {
                  struct ArgusDataStruct *user = NULL;
                  if (ArgusParser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcUserData) {
                     int slen = 0, len = ArgusParser->RaPrintAlgorithmList[i]->length;
                     if (len > 0) {
                        if ((user = (struct ArgusDataStruct *)ns->dsrs[ARGUS_SRCUSERDATA_INDEX]) != NULL) {
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
                  if (ArgusParser->RaPrintAlgorithmList[i]->print == ArgusPrintDstUserData) {
                     int slen = 0, len = ArgusParser->RaPrintAlgorithmList[i]->length;
                     if (len > 0) {
                        if ((user = (struct ArgusDataStruct *)ns->dsrs[ARGUS_DSTUSERDATA_INDEX]) != NULL) {
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
         fflush(stdout);
      }
   }

   ns->status |= ARGUS_RECORD_WRITTEN;
   return (retn);
}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}



