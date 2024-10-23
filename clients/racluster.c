/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
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

/*
 * racluster.c  - command line aggregation.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/clients/racluster.c#27 $
 * $DateTime: 2016/11/30 00:54:11 $
 * $Change: 3245 $
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

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_sort.h>

#include <argus_filter.h>
#include <argus_cluster.h>
#include <netinet/ip_icmp.h>

static int argus_version = ARGUS_VERSION;

void ArgusIdleClientTimeout (void);

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   int correct = -1, preserve = 1;
   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      parser->ArgusReverse = 1;

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "correct", 7)))
               correct = 1;
            else
            if (!(strncasecmp (mode->mode, "nocorrect", 9)))
               correct = 0;
            else
            if (!(strncasecmp (mode->mode, "preserve", 8)))
               preserve = 1;
            else
            if (!(strncasecmp (mode->mode, "nopreserve", 10)))
               preserve = 0;
            else
            if (!(strncasecmp (mode->mode, "rmon", 4))) {
               parser->RaMonMode++;
               correct = 0;
            } else
            if (!(strncasecmp (mode->mode, "norep", 5)))
               parser->RaAgMode++;
            else
            if (!(strncasecmp (mode->mode, "ind", 3)))
               ArgusProcessFileIndependantly = 1;
            else
            if (!(strncasecmp (mode->mode, "oui", 3))) 
               parser->ArgusPrintEthernetVendors++;
            else
            if (!(strncasecmp (mode->mode, "poll", 4)))
               parser->RaPollMode++;
            else
            if (!(strncasecmp (mode->mode, "normal", 6))) {
               parser->ArgusNormalize++;
            } else
            if (!(strncasecmp (mode->mode, "uni", 3)))
               parser->RaUniMode++;
            else
            if (!(strncasecmp (mode->mode, "man", 3)))
               parser->ArgusPrintMan = 1;
            else
            if (!(strncasecmp (mode->mode, "noman", 5)))
               parser->ArgusPrintMan = 0;
            else
            if (!(strncasecmp (mode->mode, "replace", 7))) {
               ArgusProcessFileIndependantly = 1;
               parser->ArgusReplaceMode |= ARGUS_REPLACE_MODE_TRUE;

               if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList)))) {
                  ArgusLog (LOG_ERR, "replace mode and -w option are incompatible\n");
               }
            }
            mode = mode->nxt;
         }
      }

      if (parser->ArgusFlowModelFile) {
         if ((parser->ArgusAggregator = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseAggregator error");
        
      } else {
         if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");
      }

      if (parser->ArgusAggregator != NULL) {
         if (correct >= 0) {
            if (correct == 0) {
               if (parser->ArgusAggregator->correct != NULL)
                  free(parser->ArgusAggregator->correct);
               parser->ArgusAggregator->correct = NULL;
            } else {
               if (parser->ArgusAggregator->correct != NULL)
                  free(parser->ArgusAggregator->correct);
               parser->ArgusAggregator->correct = strdup("yes");
               parser->ArgusPerformCorrection = 1;
            }
         }

         if (preserve == 0) {
            if (parser->ArgusAggregator->pres != NULL)
               free(parser->ArgusAggregator->pres);
            parser->ArgusAggregator->pres = NULL;
         } else {
            if (parser->ArgusAggregator->pres != NULL)
               free(parser->ArgusAggregator->pres);
            parser->ArgusAggregator->pres = strdup("yes");
         }
      }
      
      if (parser->vflag)
         ArgusReverseSortDir++;

      if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList))))
         parser->nflag = 2;

      parser->RaInitialized++;
      parser->RaParseCompleting = 0;
      parser->ArgusLastRecordTime = 0;
      parser->RaSortedInput = 1;


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
      }
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

#ifdef ARGUSDEBUG
   ArgusDebug (7, "RaArgusInputComplete(0x%x) done", input);
#endif
}

void
RaParseComplete (int sig)
{
   struct ArgusModeStruct *mode = NULL;
   int i = 0, x = 0, nflag = ArgusParser->eNflag;
   struct ArgusInput *file = ArgusParser->ArgusCurrentInput;
   char buf[MAXSTRLEN];
   int label;

   if (sig >= 0) {
      switch (sig) {
         case SIGINT:
            exit(0);
            break;
      }

      if (!(ArgusParser->RaParseCompleting++)) {
         struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;

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

         while (agg != NULL) {
            struct ArgusRecordStruct *ns;
            int cnt;

            if ((cnt = agg->queue->count) > 0) {
               struct ArgusRecordStruct *argus;

               if (!(ArgusSorter))
                  if ((ArgusSorter = ArgusNewSorter(ArgusParser)) == NULL)
                     ArgusLog (LOG_ERR, "RaParseComplete: ArgusNewSorter error %s", strerror(errno));

               if (agg->queue->count > 1) {
                  if ((mode = ArgusParser->ArgusMaskList) != NULL) {
                     while (mode) {
                        for (x = 0; x < MAX_SORT_ALG_TYPES; x++) {
                           if (ArgusSortKeyWords[x] != NULL) {
                              if (!strncmp (ArgusSortKeyWords[x], mode->mode, strlen(ArgusSortKeyWords[x]))) {
                                 ArgusSorter->ArgusSortAlgorithms[i++] = ArgusSortAlgorithmTable[x];
                                 break;
                              }
                           }
                        }
                        mode = mode->nxt;
                     }
                  }
               }

               ArgusSortQueue (ArgusSorter, agg->queue, ARGUS_LOCK);

               for (i = 0; i < cnt; i++) {
                  if ((ns = (struct ArgusRecordStruct *)ArgusPopQueue(agg->queue, ARGUS_LOCK)) != NULL) {
                     if (i == 0) {
                        argus = ArgusCopyRecordStruct(ns);
                     } else {
                        ArgusMergeRecords (agg, argus, ns);
                     }
                     ArgusAddToQueue (agg->queue, &ns->qhdr, ARGUS_LOCK);
                  }
               }

               ArgusParser->ns = argus;

               if (nflag <= 0)
                  ArgusParser->eNflag = cnt;
               else
                  ArgusParser->eNflag = nflag > cnt ? cnt : nflag;

               if (nflag != 0)
                  cnt = nflag > agg->queue->count ? agg->queue->count : nflag;

               for (i = 0; i < ArgusParser->eNflag; i++) {
                  if ((ns = (struct ArgusRecordStruct *)ArgusPopQueue(agg->queue, ARGUS_LOCK)) != NULL) {
                     ns->rank = i;
		     if ((ArgusParser->eNoflag == 0 ) || ((ArgusParser->eNoflag >= (argus->rank + 1)) && (ArgusParser->sNoflag <= (argus->rank + 1))))
                        RaSendArgusRecord ((struct ArgusRecordStruct *) ns);
                  }
                  ArgusDeleteRecordStruct(ArgusParser, ns);
               }

               ArgusDeleteRecordStruct(ArgusParser, ArgusParser->ns);
            }
            agg = agg->nxt;
         }

         if (ArgusSorter != NULL) {
            ArgusDeleteSorter(ArgusSorter);
            ArgusSorter = NULL;
         }

         if (ArgusParser->ArgusAggregator != NULL)
            ArgusDeleteAggregator(ArgusParser, ArgusParser->ArgusAggregator);

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

   ArgusParser->eNflag = nflag;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaParseComplete(%d) done", sig);
#endif
}


void
ArgusIdleClientTimeout ()
{
   struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;

   while (agg) {
      struct ArgusRecordStruct *ns = NULL;

      if (agg->idleint > 0) {
         while ((ns = (struct ArgusRecordStruct *) agg->queue->start) != NULL) {
            double nslt = ArgusFetchLastTime(ns);
            double glt  = (double)(ArgusParser->ArgusGlobalTime.tv_sec * 1.0) + (double)(ArgusParser->ArgusGlobalTime.tv_usec/1000000.0);

            if ((glt - nslt) >= agg->idleint) {
               ns = (void *) ArgusPopQueue(agg->queue, ARGUS_LOCK);
               RaSendArgusRecord(ns);
               ArgusDeleteRecordStruct (ArgusParser, ns);

            } else
               break;
         }
      }

      agg = agg->nxt;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusIdleClientTimeout()\n");
#endif
}

void
ArgusClientTimeout ()
{
   struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;

   if ((agg != NULL) && (agg->statusint > 0)) {
      int count, i;

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&agg->queue->lock);
#endif

      if ((count = agg->queue->count) > 0) {
         struct ArgusRecordStruct *ns = (struct ArgusRecordStruct *) agg->queue->start;

         for (i = 0; i < count; i++) {
            double nsst = ArgusFetchStartTime(ns);
            double glt  = (double)(ArgusParser->ArgusGlobalTime.tv_sec * 1.0) + (double)(ArgusParser->ArgusGlobalTime.tv_usec/1000000.0);

            if (agg->statusint && ((glt - nsst) >= agg->statusint))
               RaSendArgusRecord(ns);

            ns = (struct ArgusRecordStruct *) ns->qhdr.nxt;
         }
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&agg->queue->lock);
#endif
   }


#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusClientTimeout()\n");
#endif
}

void
parse_arg (int argc, char**argv)
{}

void
usage ()
{
   extern char version[];  
          
   fprintf (stdout, "Racluster Version %s\n", version);
   fprintf (stdout, "usage:  %s [-f racluster.conf]\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage:  %s [-f racluster.conf] [ra-options] [- filter-expression]\n\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "options:  -f <racluster.conf>      read aggregation rules from <racluster.conf>.\n");
   fprintf (stdout, "          -m flow key fields       specify fields to be used as flow keys.\n");
   fprintf (stdout, "          -M modes                 modify mode of operation.\n");
   fprintf (stdout, "             Available modes:      \n");
   fprintf (stdout, "                correct            turn on direction correction (default)\n");
   fprintf (stdout, "                nocorrect          turn off direction correction\n");
   fprintf (stdout, "                ind                aggregate multiple files independently\n");
   fprintf (stdout, "                norep              do not report aggregation statistics\n");
   fprintf (stdout, "                rmon               convert bi-directional data into rmon in/out data\n");
   fprintf (stdout, "                replace            replace input files with aggregation output\n");
   fprintf (stdout, "          -V                       verbose mode.\n");
   fflush (stdout);

   exit(1); 
}


void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   {
      double nowTime = ArgusFetchStartTime(ns);
      if (parser->ArgusLastRecordTime == 0) {
         parser->ArgusLastRecordTime = nowTime;
      } else {
         if (parser->ArgusLastRecordTime > nowTime)
            parser->RaSortedInput = 0;
         parser->ArgusLastRecordTime = nowTime;
      }
   }

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_EVENT:
      case ARGUS_MAR:
         break;

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];

         ArgusIdleClientTimeout();

         if (parser->Vflag || parser->Aflag) {
            ArgusProcessServiceAvailability(parser, ns);
            if (parser->xflag) {
               if ((parser->vflag && (ns->status & RA_SVCPASSED)) ||
                  (!parser->vflag && (ns->status & RA_SVCFAILED))) {
#ifdef ARGUSDEBUG
                  ArgusDebug (3, "RaProcessRecord (0x%x, 0x%x) service test failed", parser, ns); 
#endif
                  return;
               }
            }
         }

         if (parser->ArgusNormalize) {
            RaMatrixNormalizeEtherAddrs(ns);
         }

         if (parser->RaMonMode && (flow != NULL)) {
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(ns);
            struct ArgusFlow *flow;

            if ((flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, ns);

            ArgusReverseRecord(tns);

            if ((flow = (void *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);
            
         } else {
            struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
         
            if (flow && agg && agg->ArgusMatrixMode) {
               if (agg->mask & ((0x01LL << ARGUS_MASK_SADDR) | (0x01LL << ARGUS_MASK_DADDR))) {
                  switch (flow->hdr.subtype & 0x3F) {
                     case ARGUS_FLOW_LAYER_3_MATRIX:
                     case ARGUS_FLOW_CLASSIC5TUPLE: {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: {
                              if (flow->ip_flow.ip_src > flow->ip_flow.ip_dst) 
                                 ArgusReverseRecord(ns);
                           }
                           break; 

                           case ARGUS_TYPE_IPV6: {
                              int i;
                              for (i = 0; i < 4; i++) {
                                 if (flow->ipv6_flow.ip_src[i] < flow->ipv6_flow.ip_dst[i])
                                    break;

                                 if (flow->ipv6_flow.ip_src[i] > flow->ipv6_flow.ip_dst[i]) {
                                    ArgusReverseRecord(ns);
                                    break;
                                 }
                              }
                           }
                           break; 
                        }
                        break; 
                     }

                     default:
                        break; 
                  }

               } else 
               if (agg->mask & ((0x01LL << ARGUS_MASK_SMAC) | (0x01LL << ARGUS_MASK_DMAC))) {

                  struct ArgusMacStruct *m1 = NULL;
                  if ((m1 = (struct ArgusMacStruct *) ns->dsrs[ARGUS_MAC_INDEX]) != NULL) {
                     switch (m1->hdr.subtype) {
                        default:
                        case ARGUS_TYPE_ETHER: {
                           struct ether_header *e1 = &m1->mac.mac_union.ether.ehdr;
                           int i;

                           for (i = 0; i < 6; i++) {
#if defined(ARGUS_SOLARIS)
                              if (e1->ether_shost.ether_addr_octet[i] < e1->ether_dhost.ether_addr_octet[i])
                                 break;
                              if (e1->ether_shost.ether_addr_octet[i] > e1->ether_dhost.ether_addr_octet[i]) {
                                 ArgusReverseRecord(ns);
                                 break;
                              }
#else
                              if (e1->ether_shost[i] < e1->ether_dhost[i])
                                 break;
                              if (e1->ether_shost[i] > e1->ether_dhost[i]) {
                                 ArgusReverseRecord(ns);
                                 break;
                              }
#endif
                           }
                           break;
                        }
                     }
                  }
               }

               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, ns);
         }
         break;
      }
   }
}


void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
   struct ArgusHashStruct *hstruct = NULL;
   int found = 0;

   if (agg != NULL) {
      while (agg && !found) {
         int retn = 0, fretn = -1, lretn = -1;

         if (agg->filterstr) {
            struct nff_insn *fcode = agg->filter.bf_insns;
            fretn = ArgusFilterRecord (fcode, argus);
         }

         if (agg->grepstr) {
            struct ArgusLabelStruct *label;
            if (((label = (void *)argus->dsrs[ARGUS_LABEL_INDEX]) != NULL)) {
               if (regexec(&agg->lpreg, label->l_un.label, 0, NULL, 0))
                  lretn = 0;
               else
                  lretn = 1;
            } else
               lretn = 0;
         }

         retn = (lretn < 0) ? ((fretn < 0) ? 1 : fretn) : ((fretn < 0) ? lretn : (lretn && fretn));

         if (retn != 0) {
            struct ArgusRecordStruct *tns, *ns;
            struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];

            ns = ArgusCopyRecordStruct(argus);

            if (agg->labelstr)
               ArgusAddToRecordLabel(parser, ns, agg->labelstr);

            if (agg->mask) {
               if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
                  agg->rap = agg->drap;

               ArgusGenerateNewFlow(agg, ns);
               agg->ArgusMaskDefs = NULL;

               if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL) {
                  if ((tns = ArgusFindRecord(agg->htable, hstruct)) == NULL) {
                     if (!parser->RaMonMode && parser->ArgusReverse) {
                        int tryreverse = 0;

                        if (flow != NULL) {
                           if (agg->correct != NULL)
                              tryreverse = 1;

                           switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                              case ARGUS_TYPE_IPV4: {
                                 switch (flow->ip_flow.ip_p) {
                                   case IPPROTO_ESP:
                                       tryreverse = 0;
                                       break;
                                 }
                                 break;
                              }
                              case ARGUS_TYPE_IPV6: {
                                 switch (flow->ipv6_flow.ip_p) {
                                    case IPPROTO_ESP:
                                       tryreverse = 0;
                                       break;
                                 }
                                 break;
                              }
                           }
                        } else
                           tryreverse = 0;

                        if (tryreverse) {
                           if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL) {

                           if ((tns = ArgusFindRecord(agg->htable, hstruct)) == NULL) {
                              switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                 case ARGUS_TYPE_IPV4: {
                                    switch (flow->ip_flow.ip_p) {
                                       case IPPROTO_ICMP: {
                                          struct ArgusICMPFlow *icmpFlow = &flow->flow_un.icmp;

                                          if (ICMP_INFOTYPE(icmpFlow->type)) {
                                             switch (icmpFlow->type) {
                                                case ICMP_ECHO:
                                                case ICMP_ECHOREPLY:
                                                   icmpFlow->type = (icmpFlow->type == ICMP_ECHO) ? ICMP_ECHOREPLY : ICMP_ECHO;
                                                   if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                      tns = ArgusFindRecord(agg->htable, hstruct);
                                                   icmpFlow->type = (icmpFlow->type == ICMP_ECHO) ? ICMP_ECHOREPLY : ICMP_ECHO;
                                                   if (tns)
                                                      ArgusReverseRecord (ns);
                                                   break;

                                                case ICMP_ROUTERADVERT:
                                                case ICMP_ROUTERSOLICIT:
                                                   icmpFlow->type = (icmpFlow->type == ICMP_ROUTERADVERT) ? ICMP_ROUTERSOLICIT : ICMP_ROUTERADVERT;
                                                   if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                      tns = ArgusFindRecord(agg->htable, hstruct);
                                                   icmpFlow->type = (icmpFlow->type == ICMP_ROUTERADVERT) ? ICMP_ROUTERSOLICIT : ICMP_ROUTERADVERT;
                                                   if (tns)
                                                      ArgusReverseRecord (ns);
                                                   break;

                                                case ICMP_TSTAMP:
                                                case ICMP_TSTAMPREPLY:
                                                   icmpFlow->type = (icmpFlow->type == ICMP_TSTAMP) ? ICMP_TSTAMPREPLY : ICMP_TSTAMP;
                                                   if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                      tns = ArgusFindRecord(agg->htable, hstruct);
                                                   icmpFlow->type = (icmpFlow->type == ICMP_TSTAMP) ? ICMP_TSTAMPREPLY : ICMP_TSTAMP;
                                                   if (tns)
                                                      ArgusReverseRecord (ns);
                                                   break;

                                                case ICMP_IREQ:
                                                case ICMP_IREQREPLY:
                                                   icmpFlow->type = (icmpFlow->type == ICMP_IREQ) ? ICMP_IREQREPLY : ICMP_IREQ;
                                                   if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                      tns = ArgusFindRecord(agg->htable, hstruct);
                                                   icmpFlow->type = (icmpFlow->type == ICMP_IREQ) ? ICMP_IREQREPLY : ICMP_IREQ;
                                                   if (tns)
                                                      ArgusReverseRecord (ns);
                                                   break;

                                                case ICMP_MASKREQ:
                                                case ICMP_MASKREPLY:
                                                   icmpFlow->type = (icmpFlow->type == ICMP_MASKREQ) ? ICMP_MASKREPLY : ICMP_MASKREQ;
                                                   if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                      tns = ArgusFindRecord(agg->htable, hstruct);
                                                   icmpFlow->type = (icmpFlow->type == ICMP_MASKREQ) ? ICMP_MASKREPLY : ICMP_MASKREQ;
                                                   if (tns)
                                                      ArgusReverseRecord (ns);
                                                   break;
                                             }
                                          }
                                          break;
                                       }
                                    }
                                 }
                              }

                              hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct);

                           } else {    // OK, so we have a match (tns) that is the reverse of the current flow (ns)
                                       // Need to decide which direction wins.

                              struct ArgusNetworkStruct *nnet = (struct ArgusNetworkStruct *)ns->dsrs[ARGUS_NETWORK_INDEX];
                              struct ArgusNetworkStruct *tnet = (struct ArgusNetworkStruct *)tns->dsrs[ARGUS_NETWORK_INDEX];

                              switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                 case ARGUS_TYPE_IPV4: {
                                    switch (flow->ip_flow.ip_p) {
                                       case IPPROTO_TCP: {
                                          if ((nnet != NULL) && (tnet != NULL)) {
                                             struct ArgusTCPObject *ntcp = &nnet->net_union.tcp;
                                             struct ArgusTCPObject *ttcp = &tnet->net_union.tcp;

// first if both flows have syn, then don't merge;
                                             if ((ntcp->status & ARGUS_SAW_SYN) && (ttcp->status & ARGUS_SAW_SYN)) {
                                                tns = NULL;
                                             } else {
                                                if ((ntcp->status & ARGUS_SAW_SYN) || 
                                                   ((ntcp->status & ARGUS_SAW_SYN_SENT) && (ntcp->status & ARGUS_CON_ESTABLISHED))) {
                                                   struct ArgusFlow *tflow = (struct ArgusFlow *) tns->dsrs[ARGUS_FLOW_INDEX];
                                                   ArgusRemoveHashEntry(&tns->htblhdr);
                                                   ArgusReverseRecord (tns);
                                                   hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                                   tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                                   tflow->hdr.subtype &= ~ARGUS_REVERSE;
                                                   tflow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
                                                } else
                                                   ArgusReverseRecord (ns);
                                             }
                                          }
                                          break;
                                       }

                                       default: {
                                          double  nstime = ArgusFetchStartTime(ns);
                                          double tnstime = ArgusFetchStartTime(tns);
                                          if (tnstime > nstime) {
                                             struct ArgusFlow *tflow = (struct ArgusFlow *) tns->dsrs[ARGUS_FLOW_INDEX];
                                             ArgusRemoveHashEntry(&tns->htblhdr);
                                             ArgusReverseRecord (tns);
                                             hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                             tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                             tflow->hdr.subtype &= ~ARGUS_REVERSE;
                                             tflow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
                                          } else
                                             ArgusReverseRecord (ns);
                                          break;
                                       }
                                    }
                                    break;
                                 }

                                 case ARGUS_TYPE_IPV6: {
                                    switch (flow->ipv6_flow.ip_p) {
                                       case IPPROTO_TCP: {
                                          if ((nnet != NULL) && (tnet != NULL)) {
                                             struct ArgusTCPObject *ntcp = &nnet->net_union.tcp;
                                             struct ArgusTCPObject *ttcp = &tnet->net_union.tcp;

// first if both flows have syn, then don't merge;
                                             if ((ntcp->status & ARGUS_SAW_SYN) && (ttcp->status & ARGUS_SAW_SYN)) {
                                                tns = NULL;
                                             } else {
                                                if (ntcp->status & ARGUS_SAW_SYN) {
                                                   ArgusRemoveHashEntry(&tns->htblhdr);
                                                   ArgusReverseRecord (tns);
                                                   hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                                   tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                                } else
                                                if ((ntcp->status & ARGUS_SAW_SYN_SENT) && (ntcp->status & ARGUS_CON_ESTABLISHED)) {
                                                   ArgusRemoveHashEntry(&tns->htblhdr);
                                                   ArgusReverseRecord (tns);
                                                   hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                                   tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                                } else
                                                   ArgusReverseRecord (ns);
                                             }
                                          }
                                          break;
                                       }

                                       default: {
                                          double  nstime = ArgusFetchStartTime(ns);
                                          double tnstime = ArgusFetchStartTime(tns);
                                          if (tnstime > nstime) {
                                             struct ArgusFlow *tflow = (struct ArgusFlow *) tns->dsrs[ARGUS_FLOW_INDEX];
                                             ArgusRemoveHashEntry(&tns->htblhdr);
                                             ArgusReverseRecord (tns);
                                             hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                             tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                             tflow->hdr.subtype &= ~ARGUS_REVERSE;
                                             tflow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
                                          } else
                                             ArgusReverseRecord (ns);
                                          break;
                                       }
                                    }
                                    break;
                                 }

                                 default: {
                                    double  nstime = ArgusFetchStartTime(ns);
                                    double tnstime = ArgusFetchStartTime(tns);
                                    if (tnstime > nstime) {
                                       struct ArgusFlow *tflow = (struct ArgusFlow *) tns->dsrs[ARGUS_FLOW_INDEX];
                                       ArgusRemoveHashEntry(&tns->htblhdr);
                                       ArgusReverseRecord (tns);
                                       hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                       tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                       tflow->hdr.subtype &= ~ARGUS_REVERSE;
                                       tflow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
                                    } else
                                       ArgusReverseRecord (ns);
                                    break;
                                 }
                              }
                           }
                           }
                        }
                     }
                  }

                  if (tns != NULL) {                            // found record in queue
                     if (parser->Aflag) {
                        if ((tns->status & RA_SVCTEST) != (ns->status & RA_SVCTEST)) {
                           RaSendArgusRecord(tns);
                           tns->status &= ~(RA_SVCTEST);
                           tns->status |= (ns->status & RA_SVCTEST);
                        }
                     }

                     {
// Test for TCP port reuse
                        struct ArgusNetworkStruct *nnet = (struct ArgusNetworkStruct *)ns->dsrs[ARGUS_NETWORK_INDEX];
                        struct ArgusNetworkStruct *tnet = (struct ArgusNetworkStruct *)tns->dsrs[ARGUS_NETWORK_INDEX];
                        struct ArgusTCPObject *ntcp = NULL;
                        struct ArgusTCPObject *ttcp = NULL;

                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: {
                              switch (flow->ip_flow.ip_p) {
                                 case IPPROTO_TCP: {
                                    if ((nnet != NULL) && (tnet != NULL)) {
                                       ntcp = &nnet->net_union.tcp;
                                       ttcp = &tnet->net_union.tcp;
                                    }
                                 }
                              }
                              break;
                           }

                           case ARGUS_TYPE_IPV6: {
                              switch (flow->ipv6_flow.ip_p) {
                                 case IPPROTO_TCP: {
                                    if ((nnet != NULL) && (tnet != NULL)) {
                                       ntcp = &nnet->net_union.tcp;
                                       ttcp = &tnet->net_union.tcp;
                                    }
                                 }
                              }
                              break;
                           }
                        }
                        if (ntcp && ttcp) {
                           if (((ttcp->status & 0x0F) == 0x0F) && (ntcp->status & ARGUS_SAW_SYN)) {
                              if (ntcp->status & ARGUS_PORT_REUSE) {
//                               RaSendArgusRecord(tns);
                              }
                           }
                        }
                     }

                     if (tns->status & ARGUS_RECORD_WRITTEN) {
                        ArgusZeroRecord (tns);
                     } else {
                        if ((agg->statusint > 0) || (agg->idleint > 0)) {   // if any timers, need to flush if needed
                           double dur, nsst, tnsst, nslt, tnslt;

                           nsst  = ArgusFetchStartTime(ns);
                           tnsst = ArgusFetchStartTime(tns);
                           nslt  = ArgusFetchLastTime(ns);
                           tnslt = ArgusFetchLastTime(tns);

                           dur = ((tnslt > nslt) ? tnslt : nslt) - ((nsst < tnsst) ? nsst : tnsst); 
                        
                           if ((agg->statusint > 0) && (dur >= agg->statusint)) {
                              RaSendArgusRecord(tns);
                              ArgusZeroRecord(tns);
                           } else {
                              dur = ((nslt < tnsst) ? (tnsst - nslt) : ((tnslt < nsst) ? (nsst - tnslt) : 0.0));
                              if (agg->idleint && (dur >= agg->idleint)) {
                                 RaSendArgusRecord(tns);
                                 ArgusZeroRecord(tns);
                              }
                           }

                        }
                     }

                     ArgusMergeRecords (agg, tns, ns);

                     ArgusRemoveFromQueue (agg->queue, &tns->qhdr, ARGUS_LOCK);
                     ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_LOCK);         // use the agg queue as an idle timeout queue

                     ArgusDeleteRecordStruct(parser, ns);
                     agg->status |= ARGUS_AGGREGATOR_DIRTY;

                  } else {
                     tns = ns;
                     if ((hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct)) != NULL) {
                        tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                        ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_LOCK);
                        agg->status |= ARGUS_AGGREGATOR_DIRTY;
                     }
                  }
               }

            } else {
               ArgusAddToQueue (agg->queue, &ns->qhdr, ARGUS_LOCK);
               agg->status |= ARGUS_AGGREGATOR_DIRTY;
            }

            if (agg->cont)
               agg = agg->nxt;
            else
               found++;

         } else
            agg = agg->nxt;
      }

   } else {
// no key, no aggregation, so printing the record out 
      RaSendArgusRecord(argus);
   }
}

char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];

int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{
   struct ArgusRecord *argusrec = NULL;
   int retn = 1;

   if (ArgusParser->RaAgMode)
      argus->dsrs[ARGUS_AGR_INDEX] = NULL;

   if (argus->status & ARGUS_RECORD_WRITTEN)
      return (retn);

   if (ArgusParser->ArgusWfileList != NULL) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = ArgusParser->ArgusWfileList->count;

      if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
         ArgusHtoN(argusrec);
#endif
 
         if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
            for (i = 0; i < count; i++) {
               if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                  int pass = 1;
                  if (wfile->filterstr) {
                     struct nff_insn *wfcode = wfile->filter.bf_insns;
                     pass = ArgusFilterRecord (wfcode, argus);
                  }

                  if (pass != 0) {
                     if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
                        int rv;

                        rv = ArgusWriteNewLogfile (ArgusParser, argus->input,
                                                   wfile, argusrec);
                        if (rv < 0)
                           ArgusLog(LOG_ERR, "%s unable to open file\n", __func__);
                     }
                  }

                  lobj = lobj->nxt;
               }
            }
         }
      }

   } else {
      if (!ArgusParser->qflag) {
         char buf[MAXSTRLEN];

         if (!(ArgusParser->ArgusPrintJson) && (ArgusParser->Lflag)) {
            if (ArgusParser->RaLabel == NULL)
               ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, argus);
 
            if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag))
               printf ("%s\n", ArgusParser->RaLabel);
 
            if (ArgusParser->Lflag < 0)
               ArgusParser->Lflag = 0;
         }

         buf[0] = 0;
         ArgusPrintRecord(ArgusParser, buf, argus, MAXSTRLEN);

         if (fprintf (stdout, "%s\n", buf) < 0)
            RaParseComplete (SIGQUIT);

         if (ArgusParser->eflag == ARGUS_HEXDUMP) {
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
         fflush(stdout);
      }
   }

   argus->status |= ARGUS_RECORD_WRITTEN;
   return (retn);
}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}
