/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
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
 * rap.c  - track associations with access points using eapol and arp.
 *
 * written by Carter Bullard
 * QoSient, LLC 2003
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/examples/rap/rap.c#13 $
 * $DateTime: 2016/11/07 12:39:19 $
 * $Change: 3240 $
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

struct ArgusAggregatorStruct *ArgusProbeAggregator = NULL;
struct ArgusAggregatorStruct *ArgusMpcAggregator = NULL;

char *ArgusAggregatorConfig[6] = {
   "RACLUSTER_PRESERVE_FIELDS=no",
   "filter=\"ether proto eapol\" model=\"srcid smac dmac proto\"  status=0 idle=0\n",
   "filter=\"arp\" model=\"srcid\"  status=0 idle=0\n",
   "filter=\"ip\" model=\"srcid\"  status=0 idle=0\n",
   "filter=\"\" model=\"srcid\"  status=0 idle=0\n",
   NULL,
};


#define RA_MAXSESSIONS  0x1000

struct ArgusRecordStruct *RaCurrentControl = NULL;
int RapSessionIndex = 0;
struct ArgusAggregatorStruct *sessions[RA_MAXSESSIONS];

static int argus_version = ARGUS_VERSION;

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

      if ((parser->ArgusMaskList) == NULL)
         parser->ArgusReverse = 1;
      else
         parser->ArgusReverse = 0;

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "correct", 7))) {
               correct = 1;
               parser->ArgusReverse = 1;
            }
            if (!(strncasecmp (mode->mode, "nocorrect", 9)))
               correct = 0;
            if (!(strncasecmp (mode->mode, "preserve", 8)))
               preserve = 1;
            if (!(strncasecmp (mode->mode, "nopreserve", 10)))
               preserve = 0;
            if (!(strncasecmp (mode->mode, "rmon", 4))) {
               parser->RaMonMode++;
               correct = 0;
            }
            if (!(strncasecmp (mode->mode, "norep", 5)))
               parser->RaAgMode++;
            if (!(strncasecmp (mode->mode, "ind", 3)))
               ArgusProcessFileIndependantly = 1;
            if (!(strncasecmp (mode->mode, "oui", 3))) 
               parser->ArgusPrintEthernetVendors++;
            if (!(strncasecmp (mode->mode, "poll", 4)))
               parser->RaPollMode++;
            if (!(strncasecmp (mode->mode, "uni", 3)))
               parser->RaUniMode++;
            if (!(strncasecmp (mode->mode, "oui", 3)))
               parser->ArgusPrintEthernetVendors++;
            if (!(strncasecmp (mode->mode, "man", 3)))
               parser->ArgusPrintMan = 1;
            if (!(strncasecmp (mode->mode, "noman", 5)))
               parser->ArgusPrintMan = 0;

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
        
      } else 
         if ((parser->ArgusAggregator = ArgusParseAggregator(parser, NULL, ArgusAggregatorConfig)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseAggregator error");

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

      bzero(sessions, sizeof(sessions));
      
      if (parser->vflag)
         ArgusReverseSortDir++;

      if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList))))
         parser->nflag = 2;

      parser->RaInitialized++;
      parser->RaParseCompleting = 0;
      parser->ArgusLastRecordTime = 0;
      parser->RaSortedInput = 1;
   }
}

void
RaArgusInputComplete (struct ArgusInput *input)
{
   if (ArgusProcessFileIndependantly) {
      ArgusParser->ArgusCurrentFile = input;
      RaParseComplete (0);

      ArgusParser->RaInitialized = 0;
      ArgusParser->ArgusCurrentFile = NULL;
      ArgusClientInit(ArgusParser);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (7, "RaArgusInputComplete(0x%x) done", input);
#endif
}

void
RaParseComplete (int sig)
{
   struct ArgusInput *file = ArgusParser->ArgusCurrentFile;
   int x = 0, nflag = ArgusParser->eNflag;
   struct ArgusModeStruct *mode = NULL;
   char buf[MAXSTRLEN];
   int label;

   if (sig >= 0) {
      switch (sig) {
         case SIGINT:
            exit(0);
            break;
      }

      if (!(ArgusParser->RaParseCompleting++)) {
         struct ArgusAggregatorStruct *agg;
         int i;


         if (!(ArgusParser->ArgusPrintJson))
            fprintf (stdout, "\n");

         for (i = 0; i < RA_MAXSESSIONS; i++) {
            if ((agg = sessions[i]) != NULL) {
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
                  if (agg->queue->count) {
                     struct ArgusRecordStruct *argus;
                     int rank = 0;

                     if (!(ArgusSorter))
                        if ((ArgusSorter = ArgusNewSorter(ArgusParser)) == NULL)
                           ArgusLog (LOG_ERR, "RaParseComplete: ArgusNewSorter error %s", strerror(errno));

                     if ((mode = ArgusParser->ArgusMaskList) != NULL) {
                        while (mode) {
                           for (x = 0; x < MAX_SORT_ALG_TYPES; x++) {
                              if (!strncmp (ArgusSortKeyWords[x], mode->mode, strlen(ArgusSortKeyWords[x]))) {
                                 ArgusSorter->ArgusSortAlgorithms[i++] = ArgusSortAlgorithmTable[x];
                                 break;
                              }
                           }

                           mode = mode->nxt;
                        }
                     }

                     ArgusSortQueue (ArgusSorter, agg->queue, ARGUS_LOCK);
             
                     argus = ArgusCopyRecordStruct((struct ArgusRecordStruct *) agg->queue->array[0]);

                     if (nflag == 0)
                        ArgusParser->eNflag = agg->queue->count;
                     else
                        ArgusParser->eNflag = nflag > agg->queue->count ? agg->queue->count : nflag;

                     for (i = 1; i < ArgusParser->eNflag; i++)
                        ArgusMergeRecords (agg, argus, (struct ArgusRecordStruct *)agg->queue->array[i]);

                     ArgusParser->ns = argus;

                     for (i = 0; i < ArgusParser->eNflag; i++) {
                        argus = (struct ArgusRecordStruct *) agg->queue->array[i];
                        argus->rank = rank++;

                        if ((ArgusParser->eNoflag == 0 ) || ((ArgusParser->eNoflag >= (argus->rank + 1)) && (ArgusParser->sNoflag <= (argus->rank + 1))))
                           RaSendArgusRecord (argus);

                        agg->queue->array[i] = NULL;
                        ArgusDeleteRecordStruct(ArgusParser, argus);
                     }

                     ArgusDeleteRecordStruct(ArgusParser, ArgusParser->ns);
                  }

                  agg = agg->nxt;
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
            } else
               break;

            if ((agg = sessions[i]) != NULL) {
               ArgusDeleteAggregator(ArgusParser, agg);
               sessions[i] = NULL;
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
ArgusClientTimeout ()
{
   struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;

   while (agg) {
      int i, count;

      if (agg->statusint > 0) {
      if ((count = agg->queue->count) > 0) {
         for (i = 0; i < count; i++) {
            struct ArgusRecordStruct *ns = (void *) ArgusPopQueue(agg->queue, ARGUS_LOCK);
            double nsst = ArgusFetchStartTime(ns);
            double nslt = ArgusFetchLastTime(ns);
            double glt  = (double)(ArgusParser->ArgusGlobalTime.tv_sec * 1.0) + (double)(ArgusParser->ArgusGlobalTime.tv_usec/1000000.0);

            if (agg->statusint && ((glt - nsst) >= agg->statusint)) {
               RaSendArgusRecord(ns);

            } else {
               if (agg->idleint && ((glt - nslt) >= agg->idleint)) {
                  ArgusRemoveHashEntry(&ns->htblhdr);
                  RaSendArgusRecord(ns);
                  ArgusDeleteRecordStruct (ArgusParser, ns);
                  ns = NULL;
               }
            }

            if (ns != NULL)
               ArgusAddToQueue(agg->queue, &ns->qhdr, ARGUS_LOCK);
         }
      }
      } else {
         if (agg->idleint) {
            int done = 0;
            while ((!done) && (agg->queue->count > 0)) {
               struct ArgusRecordStruct *ns = (void *) agg->queue->start;
               double nslt = ArgusFetchLastTime(ns);
               double glt  = (double)(ArgusParser->ArgusGlobalTime.tv_sec * 1.0) + (double)(ArgusParser->ArgusGlobalTime.tv_usec/1000000.0);

               if ((glt - nslt) >= agg->idleint) {
                  ArgusRemoveHashEntry(&ns->htblhdr);
                  RaSendArgusRecord(ns);
                  ArgusDeleteRecordStruct (ArgusParser, ns);
               } else
                  done = 1;
            }
         }
      }

      agg = agg->nxt;
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
          
   fprintf (stdout, "Rap Version %s\n", version);
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
      case ARGUS_MAR:
      case ARGUS_EVENT:
         break;

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];

         ArgusClientTimeout();

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

         ns = ArgusCopyRecordStruct(argus);

         if (agg->labelstr)
            ArgusAddToRecordLabel(parser, ns, agg->labelstr);

         if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
            agg->rap = agg->drap;

         ArgusGenerateNewFlow(agg, ns);
         agg->ArgusMaskDefs = NULL;

         if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
            ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

         if ((tns = ArgusFindRecord(agg->htable, hstruct)) == NULL) {
            struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
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
                  if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                     ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

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

                     if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                        ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

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
                                       if (ntcp->status & ARGUS_SAW_SYN) {
                                          ArgusRemoveHashEntry(&tns->htblhdr);
                                          ArgusReverseRecord (tns);
                                          if ((hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                                             ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));
                                          tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                       } else
                                       if ((ntcp->status & ARGUS_SAW_SYN_SENT) && (ntcp->status & ARGUS_CON_ESTABLISHED)) {
                                          ArgusRemoveHashEntry(&tns->htblhdr);
                                          ArgusReverseRecord (tns);
                                          if ((hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                                             ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));
                                          tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                       } else
                                          ArgusReverseRecord (ns);
                                    }
                                 }
                                 break;
                              }

                              default:
                                 ArgusReverseRecord (ns);
                                 break;
                           }
                        }
                        break;

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
                                          if ((hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                                             ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));
                                          tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                       } else
                                       if ((ntcp->status & ARGUS_SAW_SYN_SENT) && (ntcp->status & ARGUS_CON_ESTABLISHED)) {
                                          ArgusRemoveHashEntry(&tns->htblhdr);
                                          ArgusReverseRecord (tns);
                                          if ((hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                                             ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));
                                          tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                       } else
                                          ArgusReverseRecord (ns);
                                    }
                                 }
                                 break;
                              }

                              default:
                                 ArgusReverseRecord (ns);
                                 break;
                           }
                        }
                        break;

                        default:
                           ArgusReverseRecord (ns);
                     }
                  }
               }
            }
         }

         if (tns != NULL) {
            if (parser->Aflag) {
               if ((tns->status & RA_SVCTEST) != (ns->status & RA_SVCTEST)) {
                  RaSendArgusRecord(tns);
                  tns->status &= ~(RA_SVCTEST);
                  tns->status |= (ns->status & RA_SVCTEST);
               }
            }

            if (tns->status & ARGUS_RECORD_WRITTEN) {
               ArgusZeroRecord (tns);

            } else {
               if (agg->statusint || agg->idleint) {
                  double dur, nsst, tnsst, nslt, tnslt;

                  nsst  = ArgusFetchStartTime(ns);
                  tnsst = ArgusFetchStartTime(tns);
                  nslt  = ArgusFetchLastTime(ns);
                  tnslt = ArgusFetchLastTime(tns);

                  dur = ((tnslt > nslt) ? tnslt : nslt) - ((nsst < tnsst) ? nsst : tnsst); 
               
                  if (agg->statusint && (dur >= agg->statusint)) {
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
            ArgusRemoveFromQueue (agg->queue, &tns->qhdr, ARGUS_NOLOCK);
            ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_NOLOCK);
            ArgusDeleteRecordStruct(parser, ns);
            agg->status |= ARGUS_AGGREGATOR_DIRTY;

         } else {
            tns = ns;
            if ((hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
               ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));
            tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
            ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_NOLOCK);
            agg->status |= ARGUS_AGGREGATOR_DIRTY;
         }

         if (RaCurrentControl) {
            if (agg == parser->ArgusAggregator) {
               if (RaCurrentControl != tns) {
                  ArgusRemoveFromQueue (agg->queue, &tns->qhdr, ARGUS_NOLOCK);

                  if (RapSessionIndex < RA_MAXSESSIONS) {
                     sessions[RapSessionIndex++] = agg;
                     if ((parser->ArgusAggregator = ArgusCopyAggregator(agg)) == NULL)
                        ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusCopyAggregator failed\n");
                  }
                  
                  RaCurrentControl = tns;
               }
            }

         } else
            RaCurrentControl = tns;

         if (agg->cont)
            agg = agg->nxt;
         else
            found++;

      } else
         agg = agg->nxt;
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

   if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
      ArgusHtoN(argusrec);
#endif
      if (ArgusParser->ArgusWfileList != NULL) {
         struct ArgusWfileStruct *wfile = NULL;
         struct ArgusListObjectStruct *lobj = NULL;
         int i, count = ArgusParser->ArgusWfileList->count;
 
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
                           ArgusLog(LOG_ERR, "%s unable to open file\n",
                                    __func__);
                     }
                  }

                  lobj = lobj->nxt;
               }
            }
         }

      } else {
         char buf[MAXSTRLEN];
         if (!ArgusParser->qflag) {
            if (ArgusParser->Lflag && (!(ArgusParser->ArgusPrintXml) && !(ArgusParser->ArgusPrintJson))) {
               if (ArgusParser->RaLabel == NULL)
                  ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, argus);
 
               if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag))
                  printf ("%s\n", ArgusParser->RaLabel);
 
               if (ArgusParser->Lflag < 0)
                  ArgusParser->Lflag = 0;
            }

            buf[0] = 0;
            ArgusPrintRecord(ArgusParser, buf, argus, MAXSTRLEN);

            if (fprintf (stdout, "%s", buf) < 0)
               RaParseComplete(SIGQUIT);

            if (ArgusParser->eflag == ARGUS_HEXDUMP) {
               int i;
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
                              ArgusDump ((const u_char *) &user->array, slen, "      ");
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
                              ArgusDump ((const u_char *) &user->array, slen, "      ");
                           }
                        }
                     }
                  } else
                     break;
               }
            }

            if (!(ArgusParser->ArgusPrintJson)) 
               fprintf (stdout, "\n");
            fflush(stdout);
         }
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
