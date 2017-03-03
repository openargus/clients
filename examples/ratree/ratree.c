/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2014 QoSient, LLC
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
 * ratree  - build patricia tree of addresses in file.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * $Id: //depot/gargoyle/clients/examples/ratree/ratree.c#14 $
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

#include <math.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_label.h>
#include <argus_client.h>
#include <argus_filter.h>
#include <argus_main.h>
#include <argus_cluster.h>

int ArgusDebugTree = 0;

/*
   IANA style address label configuration file syntax is:
      addr "label"

      where addr is:
         %d[[[.%d].%d].%d]/%d   CIDR address
         CIDR - CIDR            Address range

   The Regional Internet Registries (RIR) database support allows for
   country codes to be associated with address prefixes.  We'll treat
   them as simple labels.   The file syntax is:

      rir|co|[asn|ipv4|ipv6]|#allocatable|[allocated | assigned]

   So if we find '|', we know the format.

   This is a sample line out of delegated-ipv4.conf which is supplied in this distribution
      delegated-arin-latest:arin|US|ipv4|208.0.0.0|2359296|19960313|allocated
*/


#define ARGUS_VISITED		0x10


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   extern int RaPrintLabelStartTreeLevel, RaPrintLabelTreeLevel;
   struct RaAddressStruct **ArgusAddrTree;
   struct ArgusModeStruct *mode = NULL;
   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      if ((ArgusLabeler = ArgusNewLabeler(parser, ARGUS_LABELER_ADDRESS)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      if (ArgusLabeler->ArgusAddrTree == NULL)
         if ((ArgusLabeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog (LOG_ERR, "RaReadAddressConfig: ArgusCalloc error %s\n", strerror(errno));

      ArgusAddrTree = ArgusLabeler->ArgusAddrTree;
      parser->ArgusLabeler = ArgusLabeler;

      if ((parser->ArgusLocalLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE_VISITED;

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "addr", 4))) {
               if (parser->ArgusFlowModelFile) {
                  if (!(RaReadAddressConfig (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile) > 0))
                     ArgusLog (LOG_ERR, "ArgusNewLabeler: RaReadAddressConfig error");
               }
            } else
            if ((!(strncasecmp (mode->mode, "debug.tree", 10))) ||
                (!(strncasecmp (mode->mode, "debug", 5)))) {
               ArgusDebugTree = 1;
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE;
               RaPrintLabelTree (ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0);
            } else
            if (!(strncasecmp (mode->mode, "debug.local", 10))) {
               if (parser->ArgusLocalLabeler != NULL) {
                  parser->ArgusLocalLabeler->RaPrintLabelTreeMode = ARGUS_TREE;
                  if (!(strncasecmp (mode->mode, "debug.localnode", 14))) {
                     parser->ArgusLocalLabeler->status |= ARGUS_LABELER_DEBUG_NODE;
                  } else
                     parser->ArgusLocalLabeler->status |= ARGUS_LABELER_DEBUG_LOCAL;
               }
            } else
            if (!(strncasecmp (mode->mode, "graph", 5))) {
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_GRAPH;
            } else
            if (!(strncasecmp (mode->mode, "json", 4))) {
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_JSON;
            } else
            if (!(strncasecmp (mode->mode, "rmon", 4))) {
               parser->RaMonMode++;
            } else
            if (!(strncasecmp (mode->mode, "noprune", 7))) {
               parser->RaPruneMode = 0;
            } else
            if (!(strncasecmp (mode->mode, "prune", 5))) {
               parser->RaPruneMode = 1;
            }

            mode = mode->nxt;
         }
      }

      if (parser->ArgusPrintJson)
         if (parser->ArgusLabeler)
            parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_JSON;

      if (parser->ArgusPrintNewick)
         if (parser->ArgusLabeler)
            parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_NEWICK;

/*
      if (parser->ArgusFlowModelFile) {
         RaLabelParseResourceFile (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile);
         parser->ArgusFlowModelFile = NULL;
      }
*/

      if (parser->ArgusLabeler &&  parser->ArgusLabeler->status & ARGUS_LABELER_DEBUG) {
         if (parser->ArgusLabeler && parser->ArgusLabeler->ArgusAddrTree) {
            if (parser->Lflag > 0) {
               RaPrintLabelTreeLevel = parser->Lflag;
            }
            RaPrintLabelTree (parser->ArgusLabeler, parser->ArgusLabeler->ArgusAddrTree[AF_INET], 0, 0);
         }
         exit(0);
      }

      if (parser->ArgusLocalLabeler && ((parser->ArgusLocalLabeler->status & ARGUS_LABELER_DEBUG_LOCAL) ||
                                        (parser->ArgusLocalLabeler->status & ARGUS_LABELER_DEBUG_NODE))) {
         if (parser->ArgusLocalLabeler &&  parser->ArgusLocalLabeler->ArgusAddrTree) {
            if (parser->Lflag > 0) {
               RaPrintLabelTreeLevel = parser->Lflag;
            }
            RaPrintLabelTree (parser->ArgusLocalLabeler, parser->ArgusLocalLabeler->ArgusAddrTree[AF_INET], 0, 0);
         }
         exit(0);
      }
      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input) { return; }


void
RaParseComplete (int sig)
{
   extern int RaPrintLabelStartTreeLevel, RaPrintLabelTreeLevel;

   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
         struct RaAddressStruct **ArgusAddrTree;

         if (ArgusParser->ArgusPrintJson)
            fprintf (stdout, "\n");

         if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
            struct ArgusWfileStruct *wfile = NULL, *start = NULL;
    
            if ((wfile = (struct ArgusWfileStruct *) ArgusFrontList(ArgusParser->ArgusWfileList)) != NULL) {
               start = wfile;
               fflush(wfile->fd);
               ArgusPopFrontList(ArgusParser->ArgusWfileList, ARGUS_NOLOCK);
               ArgusPushBackList(ArgusParser->ArgusWfileList, (struct ArgusListRecord *) wfile, ARGUS_NOLOCK);
               wfile = (struct ArgusWfileStruct *) ArgusFrontList(ArgusParser->ArgusWfileList);
            } while (wfile != start);
         } 

         if (ArgusLabeler) {
            ArgusAddrTree = ArgusLabeler->ArgusAddrTree;

            if (ArgusParser->iLflag > 0) {
               RaPrintLabelStartTreeLevel = ArgusParser->iLflag;
            }

            if (ArgusParser->Lflag > 0) {
               RaPrintLabelTreeLevel = ArgusParser->Lflag;
            }

            if (ArgusAddrTree && (ArgusAddrTree[AF_INET] != NULL)) {
               RaPruneAddressTree(ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0);
               RaPrintLabelTree (ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0);
            }
         }
      }

      if (ArgusParser->ArgusPrintJson)
         fprintf (stdout, "\n");

      ArgusShutDown(sig);

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
   fprintf (stderr, "Ratree Version %s\n", version);
   fprintf (stderr, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [options] [- filter-expression]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stderr, "options: -f <conffile>     read service signatures from <conffile>.\n");
   exit(1);
}

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct RaAddressStruct **ArgusAddrTree = ArgusLabeler->ArgusAddrTree;

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT:
         break;

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {

         if (parser->RaMonMode) {
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(ns);
            struct ArgusFlow *flow;

            if ((flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, ns);

            ArgusReverseRecord(tns);

            if ((flow = (struct ArgusFlow *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }
    
            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);

         } else {
            struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;

            if (agg && agg->ArgusMatrixMode) {
               if (agg->mask & ((0x01 << ARGUS_MASK_SADDR) | (0x01 << ARGUS_MASK_DADDR))) {
                  struct ArgusFlow *flow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];

                  if (flow != NULL) {
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
                  }

               } else
               if (agg->mask & ((0x01 << ARGUS_MASK_SMAC) | (0x01 << ARGUS_MASK_DMAC))) {

                  struct ArgusMacStruct *m1 = NULL;
                  if ((m1 = (struct ArgusMacStruct *) ns->dsrs[ARGUS_MAC_INDEX]) != NULL) {
                     switch (m1->hdr.subtype) {
                        case ARGUS_TYPE_ETHER: {
                           struct ether_header *e1 = &m1->mac.mac_union.ether.ehdr;
                           int i;

                           for (i = 0; i < 6; i++) {
#if defined(HAVE_SOLARIS) | defined(ARGUS_PLURIBUS)
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
      }
   }

   if (ArgusDebugTree)
      if (ArgusLabeler && (ArgusAddrTree && (ArgusAddrTree[AF_INET] != NULL))) {
         if (fprintf (stdout, "----------------------\n") < 0)
            RaParseComplete(SIGQUIT);
         RaPrintLabelTree (ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0);
         if (fprintf (stdout, "----------------------\n") < 0)
            RaParseComplete(SIGQUIT);
      }
}


char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusLabelerStruct *labeler = ArgusLabeler;

   if ((agg->rap = RaFlowModelOverRides(agg, argus)) == NULL)
      agg->rap = agg->drap;

   ArgusGenerateNewFlow(agg, argus);
   agg->ArgusMaskDefs = NULL;

   if (parser->ArgusWfileList != NULL) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = parser->ArgusWfileList->count;

      if ((lobj = parser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                  struct ArgusRecord *argusrec = NULL;
                  if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, ARGUS_VERSION)) != NULL) {
#ifdef _LITTLE_ENDIAN
                     ArgusHtoN(argusrec);
#endif
                     ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                  }
               }
            }

            lobj = lobj->nxt;
         }
      }

   } else {
      if (!parser->qflag) {
         char buf[MAXSTRLEN];

         *(int *)&buf = 0;
         ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);
         if (fprintf (stdout, "%s ", buf) < 0)
            RaParseComplete(SIGQUIT);
      }
   }

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }
      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (flow) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  struct RaAddressStruct *src = NULL, *dst = NULL;
                  int smask = flow->ip_flow.smask;
                  int dmask = flow->ip_flow.dmask;

                  if (flow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT) {
                     flow->hdr.argus_dsrvl8.qual &= ~ARGUS_FRAGMENT;
                     smask  = 32;
                     dmask  = 32;
                     flow->ip_flow.smask = 32;
                     flow->ip_flow.dmask = 32;
                  } else {
                     smask = flow->ip_flow.smask;
                     dmask = flow->ip_flow.dmask;
                  }

                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        if (agg->mask & ARGUS_MASK_SADDR_INDEX) {
                           src = RaProcessAddress(parser, labeler, &flow->ip_flow.ip_src, smask, ARGUS_TYPE_IPV4, ARGUS_EXACT_MATCH);

                           while (src) {
                              if (src->ns == NULL) 
                                 src->ns = ArgusCopyRecordStruct(argus);
                              else
                                 ArgusMergeRecords (parser->ArgusAggregator, src->ns, argus);
                              src = src->p;
                           }
                        }
                        if (agg->mask & ARGUS_MASK_DADDR_INDEX) {
                           dst = RaProcessAddress(parser, labeler, &flow->ip_flow.ip_dst, dmask, ARGUS_TYPE_IPV4, ARGUS_EXACT_MATCH);
                           while (dst) {
                              if (dst->ns == NULL) 
                                 dst->ns = ArgusCopyRecordStruct(argus);
                              else
                                 ArgusMergeRecords (parser->ArgusAggregator, dst->ns, argus);
                              dst = dst->p;
                           }
                        }
                        break;
                     }
                     case ARGUS_TYPE_IPV6: {
                        if (agg->mask & ARGUS_MASK_SADDR_INDEX)
                           src = RaProcessAddress(parser, labeler, (unsigned int *) &flow->ipv6_flow.ip_src, smask, ARGUS_TYPE_IPV6, ARGUS_EXACT_MATCH);
                        if (agg->mask & ARGUS_MASK_DADDR_INDEX)
                           dst = RaProcessAddress(parser, labeler, (unsigned int *) &flow->ipv6_flow.ip_dst, dmask, ARGUS_TYPE_IPV6, ARGUS_EXACT_MATCH);
                        break;
                     }
                  }
                  break; 
               }
            }
         }
         break;
      }
   }

   if ((parser->ArgusWfileList == NULL) && !parser->qflag)
      if (!(parser->ArgusPrintJson))
         fprintf (stdout, "\n");

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessRecord (0x%x) returning\n", argus);
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
