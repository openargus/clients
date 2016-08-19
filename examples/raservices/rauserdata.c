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
 * rauserdata - formulate the service signature file.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * 
 * $Id: //depot/argus/clients/examples/raservices/rauserdata.c#12 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_label.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_sort.h>

#include <argus_cluster.h>
#include <argus_filter.h>

int RaSignatureLength = 16;
int RaSrcSig = 1;
int RaDstSig = 1;

int RaTestUserData(struct RaBinStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *, int);
void ArgusMergeUserData(struct RaBinStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);

void RaProcessSrvRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
struct RaBinProcessStruct *RaNewBinProcess (struct ArgusParserStruct *, int);
void RaPrintOutQueue (struct RaBinStruct *, struct ArgusQueueStruct *, int);


char *ArgusAggregationConfig[2] = {
   "filter=\"ip\" model=\"proto dport\"  status=120 idle=3600\n",
   NULL,
};


int RaSrcTestThreshold  = 10;
int RaDstTestThreshold  = 10;
int RaMinStartThreshold = 4;

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   int i;

   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      if ((parser->ArgusLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      if (parser->ArgusFlowModelFile) {
         RaReadSrvSignature (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile);
         parser->ArgusFlowModelFile = NULL;
      }

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "Src", 3))) {
               RaSrcSig = 1;
               RaDstSig = 0;
            }
             
            if (!(strncasecmp (mode->mode, "Dst", 3))) {
               RaSrcSig = 0;
               RaDstSig = 1;
            }
             
            mode = mode->nxt;
         }
      }

      if ((parser->ArgusAggregator = ArgusParseAggregator(parser, NULL, ArgusAggregationConfig)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseAggregator error");

      for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
         if (parser->RaPrintAlgorithmList[i] != NULL) {
            if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcUserData) {
               if (RaSignatureLength < parser->RaPrintAlgorithmList[i]->length) 
                  RaSignatureLength = parser->RaPrintAlgorithmList[i]->length;
            }

            if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintDstUserData) {
               if (RaSignatureLength < parser->RaPrintAlgorithmList[i]->length) 
                  RaSignatureLength = parser->RaPrintAlgorithmList[i]->length;
            }

         } else
            break;
      }
      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input) {};

#define ARGUS_MAXFLOWDEFS	3
#define ARGUS_SERVICE		0
#define ARGUS_SERVER		1
#define ARGUS_CLIENT		2

int RaTotals[ARGUS_MAXFLOWDEFS] = {0, 0, 0};

void
RaParseComplete (int sig)
{
   struct ArgusModeStruct *mode = NULL;

   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {

         if (!(ArgusSorter))
            if ((ArgusSorter = ArgusNewSorter(ArgusParser)) == NULL) 
               ArgusLog (LOG_ERR, "RaParseComplete: ArgusNewSorter error %s", strerror(errno));
     
         if ((mode = ArgusParser->ArgusMaskList) != NULL) {
            int x = 0, i = 0;
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

         if (ArgusParser->ArgusAggregator->queue && (ArgusParser->ArgusAggregator->queue->count)) {
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__APPLE_CC__) || defined(__APPLE__) || defined(ARGUS_SOLARIS)
            printf ("Total Records %lld SrcThreshold %d Dst Threshold %d ", ArgusParser->ArgusTotalRecords, RaSrcTestThreshold, RaDstTestThreshold);
#else
            printf ("Total Records %Ld SrcThreshold %d Dst Threshold %d ", ArgusParser->ArgusTotalRecords, RaSrcTestThreshold, RaDstTestThreshold);
#endif
            if (ArgusParser->Lflag > 0) printf ("Total Services %d  ", RaTotals[ARGUS_SERVICE]);
            if (ArgusParser->Lflag > 1) printf ("Total Servers  %d  ", RaTotals[ARGUS_SERVER]);
            if (ArgusParser->Lflag > 2) printf ("Total Clients  %d  ", RaTotals[ARGUS_CLIENT]);
            printf ("\n");

            ArgusSortQueue (ArgusSorter, ArgusParser->ArgusAggregator->queue);
            RaPrintOutQueue (NULL, ArgusParser->ArgusAggregator->queue, 0);
         }

         ArgusShutDown(sig);

         if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
            struct ArgusWfileStruct *wfile = NULL, *start = NULL;
    
            if ((wfile = (struct ArgusWfileStruct *) ArgusFrontList(ArgusParser->ArgusWfileList)) != NULL) {
               start = wfile;
               fflush(wfile->fd);
               ArgusPopFrontList(ArgusParser->ArgusWfileList, ARGUS_NOLOCK);
               ArgusPushBackList(ArgusParser->ArgusWfileList, (struct ArgusListRecord *) wfile, ARGUS_NOLOCK);
               wfile = (struct ArgusWfileStruct *) ArgusFrontList(ArgusParser->ArgusWfileList);
            } while (wfile != start);

         } else { 
         }
      }

      fflush(stdout);
      exit(0);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaParseComplete (%d) returning\n", sig);
#endif
}


void
ArgusClientTimeout ()
{

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusClientTimeout: returning\n");
#endif
}

void
parse_arg (int argc, char**argv)
{ 

#ifdef ARGUSDEBUG
   ArgusDebug (6, "parse_arg (%d, 0x%x) returning\n", argc, argv);
#endif
}


void
usage ()
{
   extern char version[];
   fprintf (stdout, "Ratemplate Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] -S remoteServer  [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -f <conffile>     read service signatures from <conffile>.\n");
   fflush (stdout);

   exit(1);
}

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusDataStruct *d1 = (struct ArgusDataStruct *) argus->dsrs[ARGUS_SRCUSERDATA_INDEX];
   struct ArgusDataStruct *d2 = (struct ArgusDataStruct *) argus->dsrs[ARGUS_DSTUSERDATA_INDEX];

   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   struct RaSrvSignature *sig;
   int process= 0;

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }
      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (flow) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4:
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_TCP: {
                              process++;
                              break;
                           }
                           case IPPROTO_UDP: {
                              process++;
                              break;
                           }
                        }
                        break; 

                     case ARGUS_TYPE_IPV6: {
                        switch (flow->ipv6_flow.ip_p) {
                           case IPPROTO_TCP: {
                              process++;
                              break;
                           }
                           case IPPROTO_UDP: {
                              process++;
                              break;
                           }
                        }
                        break; 
                     }
                  }
                  break; 
               }
            }

            if (process) {
#ifdef ARGUSDEBUG
               ArgusDebug (5, "RaProcessRecord (0x%x) validating service", argus);
#endif
               if (!(sig = RaValidateService (parser, argus))) {
                  ArgusReverseRecord(argus);
                  if (!(sig = RaValidateService (parser, argus)))
                     ArgusReverseRecord(argus);
               }

               if (sig == NULL) {
                  if (((d1 != NULL) && (d1->count > RaSignatureLength)) ||
                      ((d2 != NULL) && (d2->count > RaSignatureLength)))
                  RaProcessSrvRecord (parser, argus);
               } else
                  sig->count++;
            }

         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (5, "RaProcessRecord (0x%x) record not validated\n", argus);
#endif
         }
         break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessRecord (0x%x) returning\n", argus);
#endif
}


void ArgusPruneSignatures (struct ArgusParserStruct *, struct ArgusRecordStruct *, struct RaBinStruct *);

void
ArgusPruneSignatures (struct ArgusParserStruct *parser, struct ArgusRecordStruct *tns, struct RaBinStruct *bin)
{
   struct ArgusQueueStruct *queue;
   struct ArgusRecordStruct *ans, *pns;
   int deleted = 0;


   if (bin == NULL)
      return;

   if ((ans = (struct ArgusRecordStruct *)bin->agg->queue->start) == NULL)
      return;

   if (tns->bins) {
      int i = 0;

      for (i = 0; i < tns->bins->arraylen; i++) {
         struct RaBinStruct *tbin;

         if ((tbin = tns->bins->array[i]) != NULL) {
            if (tbin != bin) {
               queue = tbin->agg->queue;

               if ((pns = (struct ArgusRecordStruct *)queue->start) != NULL) {
                  if (RaTestUserData(tbin, ans, pns, ARGUS_LONGEST_MATCH)) {
                     ArgusMergeUserData (bin, pns, ans);
                     ArgusMergeRecords (parser->ArgusAggregator, pns, ans);
                     deleted++;
                  }
               }
            }
         }
      }

      if (deleted) {
         for (i = 0; i < tns->bins->arraylen; i++) {
            if (tns->bins->array[i] == bin) {
               tns->bins->array[i] = NULL;
               tns->bins->count--;
               RaDeleteBin(parser, bin);
               break;
            }
         }

         for (i = 0; i < tns->bins->arraylen; i++) {
            int x;
            if (i < (tns->bins->count - 1)) {
               while (tns->bins->array[i] == NULL) {
                  for (x = i; x < tns->bins->arraylen; x++) {
                     if (x == tns->bins->arraylen - 1) {
                        tns->bins->array[x] = NULL;
                     } else {
                        tns->bins->array[x] = tns->bins->array[x + 1];
                     }
                  }
               }
            }
         }
      }
   }
}


void
RaProcessSrvRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
   struct ArgusHashStruct *hstruct = NULL;
   struct ArgusRecordStruct *tns;
   int retn, found = 0;

   while (agg && !found) {
      struct nff_insn *fcode = agg->filter.bf_insns;

      if ((retn = ArgusFilterRecord (fcode, ns)) != 0) {
         struct ArgusRecordStruct *ans = NULL;

         if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
            agg->rap = agg->drap;

         ArgusGenerateNewFlow(agg, ns);

         if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
            ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

         if ((tns = ArgusFindRecord(agg->htable, hstruct)) != NULL) {
            if (parser->Aflag) {
               if ((tns->status & RA_SVCTEST) != (ns->status & RA_SVCTEST)) {
                  RaSendArgusRecord(tns);
                  ArgusZeroRecord(tns);
                  tns->status &= ~(RA_SVCTEST);
                  tns->status |= (ns->status & RA_SVCTEST);
               }
            }

         } else {
            struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];

            if (!parser->RaMonMode) {
               int tryreverse = 1;

               if (flow != NULL) {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_ESP:
                              tryreverse = 0;
                              break;
                        }
                     }
                  }
               }

               if (tryreverse) {
                  if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                     ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                  if ((tns = ArgusFindRecord(agg->htable, hstruct)) == NULL) {
                     if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                        ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

                  } else {
                     ArgusReverseRecord (ns);
                  }
               }
            }

            if (tns != NULL) {
               if (parser->Aflag) {
                  if ((tns->status & RA_SVCTEST) != (ns->status & RA_SVCTEST)) {
                     RaSendArgusRecord(tns);
                     ArgusZeroRecord(tns);
                  }
                  tns->status &= ~(RA_SVCTEST);
                  tns->status |= (ns->status & RA_SVCTEST);
               }

            } else {
               tns = ArgusCopyRecordStruct(ns);
               ArgusAddHashEntry (agg->htable, tns, hstruct);
               ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_LOCK);
            }
         }

         if (tns->bins) {
            struct RaBinStruct *bin;
            int i, merged = 0;

            for (i = 0; i < tns->bins->arraylen; i++) {
               if ((bin = tns->bins->array[i]) != NULL) {
                  if ((ans = (struct ArgusRecordStruct *)bin->agg->queue->start) != NULL) {
                     if (RaTestUserData(bin, ans, ns, ARGUS_LONGEST_MATCH)) {
                        ArgusMergeUserData (bin, ans, ns);
                        ArgusMergeRecords (parser->ArgusAggregator, tns, ns);
                        merged++;
                        break;
                     }
                  }

               } else {
                  tns->bins->array[i] = RaNewBin (parser, tns->bins, ns, 0, i);
                  tns->bins->count++;

                  if ((ans =  ArgusCopyRecordStruct(ns)) != NULL) {
                     if (agg != NULL) {
                        struct ArgusHashStruct *hstruct = NULL;
         
                        if ((hstruct = ArgusGenerateHashStruct(agg, ans, NULL)) == NULL)
                           ArgusLog (LOG_ERR, "RaNewBin: ArgusGenerateHashStruct error %s", strerror(errno));
         
                        ArgusAddHashEntry (tns->bins->array[i]->agg->htable, ans, hstruct);
                        ArgusAddToQueue (tns->bins->array[i]->agg->queue, &ans->qhdr, ARGUS_LOCK);
                     }
                  }

                  break;
               }
            }

            if (merged)
               ArgusPruneSignatures (parser, tns, bin);

         } else {
            if ((tns->bins = RaNewBinProcess(parser, 32)) == NULL)
               ArgusLog (LOG_ERR, "RaProcessSrvRecord: RaNewBinProcess error: %s", strerror(errno));

            tns->bins->array[0] = RaNewBin (parser, tns->bins, ns, 0, 0);
            tns->bins->count = 1;

            if ((ans =  ArgusCopyRecordStruct(ns)) != NULL) {
               if ((agg = tns->bins->array[0]->agg) != NULL) {
                  struct ArgusHashStruct *hstruct = NULL;

                  if ((hstruct = ArgusGenerateHashStruct(agg, ans, NULL)) == NULL)
                     ArgusLog (LOG_ERR, "RaNewBin: ArgusGenerateHashStruct error %s", strerror(errno));

                  ArgusAddHashEntry (agg->htable, ans, hstruct);
                  ArgusAddToQueue (agg->queue, &ans->qhdr, ARGUS_LOCK);
               }
            }
         }

         found++;

      } else
         agg = agg->nxt;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessSrvRecord (0x%x, 0x%x) returning\n", parser, ns);
#endif
}

int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaSendArgusRecord (0x%x) returning\n", argus);
#endif
   return 1;
}


void ArgusWindowClose(void) { } 

int
RaTestUserData(struct RaBinStruct *bin, struct ArgusRecordStruct *ns1, struct ArgusRecordStruct *ns2, int type)
{
   struct ArgusAgrStruct *agr = (struct ArgusAgrStruct *) ns1->dsrs[ARGUS_AGR_INDEX];
   int retn = 0, len, len1 = 0, len2 = 0, x, count, weight;
   unsigned char thisdatamask[16];

   if (RaSrcSig) {
      struct ArgusDataStruct *d1 = (struct ArgusDataStruct *) ns1->dsrs[ARGUS_SRCUSERDATA_INDEX];
      struct ArgusDataStruct *d2 = (struct ArgusDataStruct *) ns2->dsrs[ARGUS_SRCUSERDATA_INDEX];

      if (d1 && d2) {
         retn = 0;
         count = 0;
         if (!(RaSrcTestThreshold)) {
            retn++;

         } else {
            len1 = d1->count;
            len2 = d2->count;

            len = (len1 > len2) ? len2 : len1;
            len = (len > RaSignatureLength) ? RaSignatureLength : len;

            bcopy (&bin->ArgusSrcDataMask, thisdatamask, sizeof(thisdatamask));

            for (x = 0, weight = 5; x < len; x++) {
               if (!(thisdatamask[x/8] & (0x80 >> (x % 8)))) {
                  if (d2->array[x] == d1->array[x])
                     count += (weight >= 1) ? weight : 1;
                  else {
                     if (type == ARGUS_EXACT_MATCH) {
                        return(0);
                     } else {
                        if (agr->count > 1) {
                           if (x < ((RaSrcTestThreshold > RaMinStartThreshold) ? RaMinStartThreshold : RaSrcTestThreshold) - 1) {
                              retn = 0;
                           }
                        }
                        count -= (weight >= 1) ? weight : 1;
                     }
                  }
               }
               weight--;
            }
               
            if (count >= RaSrcTestThreshold)
               retn++;
         }

      } else
         retn++;
   }

   if (RaDstSig && (!RaSrcSig || (RaSrcSig && retn))) {
      struct ArgusDataStruct *d1 = (struct ArgusDataStruct *) ns1->dsrs[ARGUS_DSTUSERDATA_INDEX];
      struct ArgusDataStruct *d2 = (struct ArgusDataStruct *) ns2->dsrs[ARGUS_DSTUSERDATA_INDEX];

      if (d1 && d2) {
         retn = 0;
         count = 0;
         if (!(RaDstTestThreshold)) {
            retn++;

         } else {
            len1 = d1->count;
            len2 = d2->count;

            len = (len1 > len2) ? len2 : len1;
            len = (len > RaSignatureLength) ? RaSignatureLength : len;

            bcopy (&bin->ArgusDstDataMask, thisdatamask, sizeof(thisdatamask));

            for (x = 0, weight = 5; x < len; x++) {
               if (!(thisdatamask[x/8] & (0x80 >> (x % 8)))) {
                  if (d2->array[x] == d1->array[x])
                     count += (weight >= 1) ? weight : 1;
                  else {
                     if (agr->count > 1) {
                        if (x < ((RaDstTestThreshold > RaMinStartThreshold) ? RaMinStartThreshold : RaDstTestThreshold) - 1) {
                           retn = 0;
                        }
                     }
                     count -= (weight >= 1) ? weight : 1;
                  }
               }
               weight--;
            }
               
            if (count >= RaDstTestThreshold)
               retn++;
         }

      } else
         retn++;
   }

   return(retn);
}


void
ArgusMergeUserData(struct RaBinStruct *bin, struct ArgusRecordStruct *ns1, struct ArgusRecordStruct *ns2)
{
   struct ArgusAgrStruct *agr = (struct ArgusAgrStruct *) ns1->dsrs[ARGUS_AGR_INDEX];
   unsigned char thisdatamask[16];

   if (RaSrcSig) {
      struct ArgusDataStruct *d1 = (struct ArgusDataStruct *) ns1->dsrs[ARGUS_SRCUSERDATA_INDEX];
      struct ArgusDataStruct *d2 = (struct ArgusDataStruct *) ns2->dsrs[ARGUS_SRCUSERDATA_INDEX];
      int x, count;

      if (d1 && d2) {
         int len, len1 = d1->count, len2 = d2->count;

         len = (len1 > len2) ? len2 : len1;
         len = (len > RaSignatureLength) ? RaSignatureLength : len;

         bcopy (&bin->ArgusSrcDataMask, thisdatamask, sizeof(thisdatamask));

         for (x = 0; x < len; x++)
            if (d2->array[x] != d1->array[x]) 
               thisdatamask[x/8] |= (0x80 >> (x % 8));
 
         for (; x < 128; x++) {
            thisdatamask[x/8] |= (0x80 >> (x % 8));
         }
 
         for (x = 0, count = 0; x < 128; x++) {
            if (thisdatamask[x/8] & (0x80 >> (x % 8)))
               count++;
         }
 
         if ((128 - count) < RaSrcTestThreshold) {
#ifdef ARGUSDEBUG
            ArgusDebug (2, "RaMergeUserData Src Threshold failed\n");
#endif
         }

         bcopy (thisdatamask, &bin->ArgusSrcDataMask, sizeof(thisdatamask));
      }
   }

   if (RaDstSig) {
      struct ArgusDataStruct *d1 = (struct ArgusDataStruct *) ns1->dsrs[ARGUS_DSTUSERDATA_INDEX];
      struct ArgusDataStruct *d2 = (struct ArgusDataStruct *) ns2->dsrs[ARGUS_DSTUSERDATA_INDEX];
      int x, count;

      if (d1 && d2) {
         int len, len1 = d1->count, len2 = d2->count;

         len = (len1 > len2) ? len2 : len1;
         len = (len > RaSignatureLength) ? RaSignatureLength : len;

         bcopy (&bin->ArgusDstDataMask, thisdatamask, sizeof(thisdatamask));

         for (x = 0; x < len; x++)
            if (d2->array[x] != d1->array[x]) 
               thisdatamask[x/8] |= (0x80 >> (x % 8));
 
         for (; x < 128; x++) {
            thisdatamask[x/8] |= (0x80 >> (x % 8));
         }
 
         for (x = 0, count = 0; x < 128; x++) {
            if (thisdatamask[x/8] & (0x80 >> (x % 8)))
               count++;
         }
 
         if ((128 - count) < RaDstTestThreshold) {
#ifdef ARGUSDEBUG
            ArgusDebug (2, "RaMergeUserData Dst Threshold failed\n");
#endif
         }

         bcopy (thisdatamask, &bin->ArgusDstDataMask, sizeof(thisdatamask));
      }
   }

   if (agr != NULL)
      agr->count++;

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusMergeUserData (0x%x, 0x%x) returning\n", ns1, ns2);
#endif
}


struct RaBinProcessStruct * 
RaNewBinProcess (struct ArgusParserStruct *parser, int size)
{ 
   struct RaBinProcessStruct *retn = NULL;
   struct ArgusAdjustStruct *tnadp;
  
   parser->ArgusReverse = 0;
 
   if ((retn = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewBinProcess: ArgusCalloc error %s", strerror(errno));

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&retn->lock, NULL);
#endif
  
   tnadp = &retn->nadp;
   tnadp->mode    = -1;
   tnadp->modify  =  1;
   tnadp->slen    =  2;
   tnadp->count   = 1;
   tnadp->value   = 1;

   if ((retn->array = (struct RaBinStruct **)ArgusCalloc(size, sizeof(struct RaBinStruct *))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewBinProcess: ArgusCalloc error %s", strerror(errno));

   retn->arraylen = size;
   return (retn);
}


int RaSortUserDataBins (const void *, const void *);

int
RaSortUserDataBins (const void *item1, const void *item2)
{
   int retn = 0;
   struct RaBinStruct *b1 = *(struct RaBinStruct **) item1;
   struct RaBinStruct *b2 = *(struct RaBinStruct **) item2;

   if (b1 && b2) {
      struct ArgusAgrStruct *a1 = NULL, *a2 = NULL;
 
      if (b1->agg && b1->agg->queue && b1->agg->queue->start)
         a1 = (void *)((struct ArgusRecordStruct *)b1->agg->queue->start)->dsrs[ARGUS_AGR_INDEX];

      if (b2->agg && b2->agg->queue && b2->agg->queue->start)
         a2 = (void *)((struct ArgusRecordStruct *)b2->agg->queue->start)->dsrs[ARGUS_AGR_INDEX];
   
      if ((a1 != NULL) && (a2 != NULL)) {
         retn = (a2->count - a1->count);
      } else {
         retn = a1 ? -1 : +1;
      }

   } else {
      retn = b1 ? -1 : +1;
   }

   return (retn);
}


void
RaPrintOutQueue (struct RaBinStruct *bin, struct ArgusQueueStruct *queue, int level)
{
   struct ArgusRecordStruct *obj = NULL;
   int print, n, num = ArgusParser->eNflag;
   char buf[MAXSTRLEN];

   if (ArgusParser->eNflag <= 0)
      num = queue->count;

   for (n = 0; n < num; n++) {
      if ((obj = (struct ArgusRecordStruct *) queue->array[n]) != NULL) {
         bzero(buf, sizeof(buf));
         print = 0;

         if (obj->bins) {
            int i = 0;

            qsort (obj->bins->array, obj->bins->count, sizeof(struct RaBinStruct *), RaSortUserDataBins);

            for (i = 0; i < obj->bins->arraylen; i++) {
               if ((bin = obj->bins->array[i]) != NULL) {
                  struct ArgusQueueStruct *q = bin->agg->queue;

                  if (q->count > 0) {
                     ArgusSortQueue (ArgusSorter, bin->agg->queue);
                     RaPrintOutQueue (bin, bin->agg->queue, level);
                     print = 1;
                  }
               } else
                  break;
            }

            if (print)
               sprintf (buf, "\n");

         } else {
            struct ArgusFlow *flow = (struct ArgusFlow *) obj->dsrs[ARGUS_FLOW_INDEX];
            struct ArgusAgrStruct *agr = (struct ArgusAgrStruct *) obj->dsrs[ARGUS_AGR_INDEX];

            int i, slen = 16, dlen = 16;
            char pbuf[64];

            for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
               if (ArgusParser->RaPrintAlgorithmList[i] != NULL) {
                  if (ArgusParser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcUserData)
                     slen = ArgusParser->RaPrintAlgorithmList[i]->length;
                  if (ArgusParser->RaPrintAlgorithmList[i]->print == ArgusPrintDstUserData)
                     dlen = ArgusParser->RaPrintAlgorithmList[i]->length;
               } else
                  break;
            }

            bzero (pbuf, 64);
            ArgusPrintDstPort (ArgusParser, pbuf, obj, 16);
            if (flow != NULL) {
               switch (flow->flow_un.ip.ip_p) {
                  case IPPROTO_TCP: sprintf(buf, "Service: %s tcp port %-5d", pbuf, flow->flow_un.ip.dport); break;
                  case IPPROTO_UDP: sprintf(buf, "Service: %s udp port %-5d", pbuf, flow->flow_un.ip.dport); break;
               }
            }

            if (agr != NULL)
               sprintf (&buf[strlen(buf)], " n = %5d ", agr->count);

            if (RaSrcSig && (slen > 0)) {
               struct ArgusDataStruct *d1 = (struct ArgusDataStruct *) obj->dsrs[ARGUS_SRCUSERDATA_INDEX];
               int exlen = slen;

               switch (ArgusParser->eflag) {
                  case ARGUS_ENCODE_ASCII:
                     break;
 
                  case ARGUS_ENCODE_32:
                  case ARGUS_ENCODE_64:
                     exlen *= 2;
                     break;
               }
 
               if (d1 != NULL) {
                  int len = d1->count > slen ? slen : d1->count;
                  char strbuf[128], *str = strbuf;
 
                  bzero (strbuf, sizeof(strbuf));
                  if ((len = ArgusEncode (ArgusParser, d1->array, (char *)bin->ArgusSrcDataMask, len, str, 128)) != 0)
                     sprintf(&buf[strlen(buf)], "src = \"%*.*s\"  ", len, len, str);
 
               } else {
                  sprintf(&buf[strlen(buf)], "src = \"%-*s\"  ", exlen," ");
               }
            }

            if (RaDstSig && (dlen > 0)) {
               struct ArgusDataStruct *d1 = (struct ArgusDataStruct *) obj->dsrs[ARGUS_DSTUSERDATA_INDEX];
               int exlen = dlen;
 
               switch (ArgusParser->eflag) {
                  case ARGUS_ENCODE_ASCII:
                     break;
 
                  case ARGUS_ENCODE_32:
                  case ARGUS_ENCODE_64:
                     exlen *= 2;
                     break;
               }
 
               if (d1 != NULL) {
                  int len = d1->count > dlen ? dlen : d1->count;
                  char strbuf[128], *str = strbuf;
                  bzero (strbuf, sizeof(strbuf));
                  if ((len = ArgusEncode (ArgusParser, d1->array, (char *)bin->ArgusDstDataMask, len, str, 128)) != 0)
                     sprintf(&buf[strlen(buf)], "dst = \"%*.*s\"  ", len, len, str);
 
               } else {
                  sprintf(&buf[strlen(buf)], "dst = \"%-*s\"  ", exlen," ");
               }
            }
/*
            sprintf(&buf[strlen(buf)], "sintdist = ");
            ArgusPrintSrcIntPktDist (ArgusParser, &buf[strlen(buf)], obj, 8);

            sprintf(&buf[strlen(buf)], "dintdist = ");
            ArgusPrintDstIntPktDist (ArgusParser, &buf[strlen(buf)], obj, 8);
*/
            sprintf(&buf[strlen(buf)], "\n");
         }
         printf("%s", buf);
      }

      fflush(stdout);
   }
}
