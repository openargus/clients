/*
 * Gargoyle Client Software.  Tools to read, analyze and manage Argus data.
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
 */

/*
 * ratrace  - repeatedly provide an active trace capability for 
 *            IP addresses as they are learned from a stream.
 *            
 *            We'll provide an opportunity to configure the tool with
 *            an IANA country code file (delegated-ipv4-latest) to
 *            seed the country patricia tree, and then, as addresses
 *            are learned, we insert into the tree.  This gives us a
 *            good data structure to track and schedule traces.
 *            The tree lets us limit traces based on CIDR prefix length
 *            so we're not hitting the same subnet with multiple traces.
 *            
 *            Using the tree, we can schedule traces based on country
 *            as well as CIDR division.
 *            
 *            There is no reason for us to track the actual path generation
 *            as we're just the active part, but we can to manage the
 *            whole process.
 *
 *            Everything will driven by ArgusClientTimeout() to scan the
 *            tree and to schedule new traces.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * $Id: //depot/gargoyle/clients/examples/ratrace/ratrace.c#17 $
 * $DateTime: 2016/10/28 18:37:18 $
 * $Change: 3235 $
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
#include <arpa/inet.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_label.h>
#include <argus_client.h>
#include <argus_filter.h>
#include <argus_main.h>
#include <argus_cluster.h>

int ArgusDebugTree = 0;
int RaPrintTraceTreeLevel = 1000000;
char RaAddrTreeArray[MAXSTRLEN];


void RaPrintTraceTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

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

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE_VISITED;

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if ((!(strncasecmp (mode->mode, "debug.label", 11))) ||
                (!(strncasecmp (mode->mode, "debug.cco", 9))) ||
                (!(strncasecmp (mode->mode, "debug", 5)))) {
               ArgusDebugTree = 1;
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE;

               if (!(strncasecmp (mode->mode, "debug.label", 11)))
                  RaPruneAddressTree(ArgusLabeler, ArgusAddrTree[AF_INET], ARGUS_TREE_PRUNE_LABEL | ARGUS_TREE_PRUNE_ADJ, 0);
               if (!(strncasecmp (mode->mode, "debug.cco", 9)))
                  RaPruneAddressTree(ArgusLabeler, ArgusAddrTree[AF_INET], ARGUS_TREE_PRUNE_CCO | ARGUS_TREE_PRUNE_ADJ, 0);

               RaPrintTraceTree (ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0);
               ArgusAddrTree[AF_INET] = NULL;
               RaParseComplete(0);

            } else
            if (!(strncasecmp (mode->mode, "rmon", 4)))
               parser->RaMonMode++;

            mode = mode->nxt;
         }
      }

      RaPruneAddressTree(ArgusLabeler, ArgusAddrTree[AF_INET], ARGUS_TREE_PRUNE_CCO | ARGUS_TREE_PRUNE_ADJ, 0);

      if (parser->Lflag > 0)
         RaPrintTraceTreeLevel = parser->Lflag - 1;

#if defined(ARGUS_THREADS)
      {
         extern void *ArgusTraceProcess (void *);
         if (ArgusParser->ArgusProcessList == NULL) {
            pthread_attr_t attrbuf, *attr = &attrbuf;

            pthread_attr_init(attr);
            pthread_attr_setdetachstate(attr, PTHREAD_CREATE_JOINABLE);

            if (getuid() == 0)
               pthread_attr_setschedpolicy(attr, SCHED_RR);
            else
               attr = NULL;

            ArgusParser->ArgusProcessList = ArgusNewList();
            if ((pthread_create(&ArgusParser->thread, attr, ArgusTraceProcess, NULL)) != 0)
               ArgusLog (LOG_ERR, "ArgusTraceProcess() pthread_create error %s\n", strerror(errno));
         }
      }
#endif

      parser->ArgusPrintJson = 0;
      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input) { return; }



void
RaParseComplete (int sig)
{
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
            if (ArgusAddrTree && (ArgusAddrTree[AF_INET] != NULL)) {
               RaPruneAddressTree(ArgusLabeler, ArgusAddrTree[AF_INET], ARGUS_TREE_PRUNE_RECORD | ARGUS_TREE_PRUNE_ADJ, 0);
               RaPrintTraceTree (ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0);
            }
         }
      }

      ArgusShutDown(sig);

      fflush(stdout);
      exit(0);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaParseComplete (%d) returning\n", sig);
#endif
}

int ArgusScanTreeForWork (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

int
ArgusScanTreeForWork (struct ArgusLabelerStruct *labeler, struct RaAddressStruct *node, int level, int dir)
{
   int retn = 0, value;

   if (level > RaPrintTraceTreeLevel)
      return (0);

   if (node != NULL) {
      if (node->addr.masklen > 31) {
         if (node->ns != NULL) {
            retn = 1;
         }
      } else {
         retn += ( value = ArgusScanTreeForWork(labeler, node->r, level + 1, RA_SRV_RIGHT)) ? ((node->addr.masklen == 24) ? 1 : value) : 0;
         retn += ( value = ArgusScanTreeForWork(labeler, node->l, level + 1, RA_SRV_RIGHT)) ? ((node->addr.masklen == 24) ? 1 : value) : 0;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusScanTreeForWork(%p, %p, %d, %d) returning %d\n", labeler, node, level, dir, retn);
#endif

   return (retn);
}

void
ArgusClientTimeout ()
{
#ifdef ARGUSDEBUG
   struct RaAddressStruct **ArgusAddrTree = ArgusLabeler->ArgusAddrTree;
   int traces = ArgusScanTreeForWork(ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0);

   ArgusDebug (3, "ArgusClientTimeout: %d nets/24 available for trace\n", traces);
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
   fprintf (stderr, "Ratrace Version %s\n", version);
   fprintf (stderr, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "usage: %s [options] [- filter-expression]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stderr, "options: -f <conffile>     read service signatures from <conffile>.\n");
   exit(1);
}


int RaProcessThisAddress (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct ArgusRecordStruct *, unsigned int *, int, int);

int
RaProcessThisAddress (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, struct ArgusRecordStruct *argus, unsigned int *addr, int masklen, int type)
{
   struct RaAddressStruct **ArgusAddrTree = labeler->ArgusAddrTree;
   struct RaAddressStruct *raddr;
   int retn = 0;

   if (ArgusAddrTree != NULL) {
      if (addr && *addr) {
         switch (type) {
            case ARGUS_TYPE_IPV4: {
               struct RaAddressStruct *node = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*node));

               if (masklen == 0)
                  masklen = 32;

               if (node != NULL) {
                  node->addr.type = AF_INET;
                  node->addr.len = 4;
                  node->addr.masklen = masklen;
                  node->addr.addr[0] = *addr;
                  node->addr.mask[0] = 0xFFFFFFFF << (32 - masklen);

                  if ((raddr = RaFindAddress (parser, ArgusAddrTree[node->addr.type], node, ARGUS_EXACT_MATCH)) == NULL) {
                     struct ArgusListObjectStruct *list;
                     node = RaInsertAddress (parser, ArgusLabeler, NULL, node, ARGUS_VISITED);

                     if (!(ArgusParser->ArgusLoadingData)) {
                        if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                           ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

                        list->list_val = *addr;
                        ArgusPushBackList(ArgusParser->ArgusProcessList, (struct ArgusListRecord *)list, ARGUS_LOCK);
                     }

                  } else {
                     ArgusFree(node);
                     node = raddr;
                  }

                  while (node != NULL) {
                     if (node->ns != NULL)
                        ArgusMergeRecords (parser->ArgusAggregator, node->ns, argus);
                     else
                        node->ns = ArgusCopyRecordStruct(argus);
                     node = node->p;
                  }
               }
               break;
            }

            case ARGUS_TYPE_IPV6:
               break;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessThisAddress (0x%x, 0x%x, 0x%x, %d, %d) returning\n", parser, argus, addr, type, masklen);
#endif

   return (retn);
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
#if defined(HAVE_SOLARIS) || defined(ARGUS_PLURIBUS)
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
         RaPrintTraceTree (ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0);
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

   int retn = 0;

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

         buf[0] = 0;
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
                  int smask = flow->ip_flow.smask;
                  int dmask = flow->ip_flow.dmask;

                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4:
                        if (!retn && (agg->mask & ARGUS_MASK_SADDR_INDEX))
                           retn = RaProcessThisAddress(parser, labeler, argus, &flow->ip_flow.ip_src, smask, ARGUS_TYPE_IPV4);
                        if (!retn && (agg->mask & ARGUS_MASK_DADDR_INDEX))
                           retn = RaProcessThisAddress(parser, labeler, argus, &flow->ip_flow.ip_dst, dmask, ARGUS_TYPE_IPV4);
                        break;
                     case ARGUS_TYPE_IPV6:
                        if (!retn && (agg->mask & ARGUS_MASK_SADDR_INDEX))
                           retn = RaProcessThisAddress(parser, labeler, argus, (unsigned int *) &flow->ipv6_flow.ip_src, smask, ARGUS_TYPE_IPV6);
                        if (!retn && (agg->mask & ARGUS_MASK_DADDR_INDEX))
                           retn = RaProcessThisAddress(parser, labeler, argus, (unsigned int *) &flow->ipv6_flow.ip_dst, dmask, ARGUS_TYPE_IPV6);
                        break;
                  }

                  break; 
               }
            }
         }
         break;
      }
   }

   if ((parser->ArgusWfileList == NULL) && !parser->qflag)
      fprintf (stdout, "\n");

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessThisRecord (0x%x) returning\n", argus);
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



void
RaPrintTraceTree (struct ArgusLabelerStruct *labeler, struct RaAddressStruct *node, int level, int dir)
{
   int i = 0, length, len;
   int olen = strlen(RaAddrTreeArray);
   char str[MAXSTRLEN], chr = ' ';

   if (level > RaPrintTraceTreeLevel)
      return;

   bzero(str, MAXSTRLEN);

   if (node != NULL) {
      switch (labeler->RaPrintLabelTreeMode) {
         case ARGUS_TREE:
         case ARGUS_TREE_VISITED:
         case ARGUS_TREE_POPULATED: {
            if (node->status & ARGUS_VISITED) {
               if (dir == RA_SRV_LEFT) {
                  strcat (str, "   |");
                  strcat (RaAddrTreeArray, str);
                  printf ("%s\n", RaAddrTreeArray);
               }

               length = strlen(RaAddrTreeArray);
               if ((len = length) > 0) {
                  chr = RaAddrTreeArray[len - 1];
                  if (node->r != NULL) {
                     if (dir == RA_SRV_RIGHT)
                        RaAddrTreeArray[len - 1] = ' ';
                  }
               }

               strcat (RaAddrTreeArray, "   |");

               RaPrintTraceTree(labeler, node->r, level + 1, RA_SRV_RIGHT);

               for (i = length, len = strlen(RaAddrTreeArray); i < len; i++)
                  RaAddrTreeArray[i] = '\0';

               if ((len = length) > 0)
                  RaAddrTreeArray[len - 1] = chr;
         
               printf ("%s+", RaAddrTreeArray);

               if (node->addr.str)
                  printf ("%s ", node->addr.str);

               else  {
                  if (node->addr.masklen > 0) {
                     printf ("%s/%d ", intoa(node->addr.addr[0] & (0xFFFFFFFF << (32 - node->addr.masklen))), node->addr.masklen);
                  } else
                     printf ("0.0.0.0/0 ");
               }

               if (strlen(node->cco))
                  printf ("%s ", node->cco);

               if (node->label)
                  printf ("%s ", node->label);

               if (node->ns) {
                  char buf[MAXSTRLEN];
                  bzero (buf, sizeof(buf));
                  ArgusPrintRecord(ArgusParser, buf, node->ns, MAXSTRLEN);
                  printf ("%s ", buf);
               }

               printf ("\n");

               len = strlen(RaAddrTreeArray);
               if (len > 0) {
                  chr = RaAddrTreeArray[len - 1];
                  if (node->l != NULL) {
                     if (dir == RA_SRV_LEFT)
                        RaAddrTreeArray[len - 1] = ' ';
                  }
               }

               RaPrintTraceTree(labeler, node->l, level + 1, RA_SRV_LEFT);

               if (dir == RA_SRV_RIGHT) {
                  printf ("%s", RaAddrTreeArray);
                  putchar ('\n');
               }

               for (i = olen, len = strlen(RaAddrTreeArray); i < len; i++)
                  RaAddrTreeArray[i] = '\0';
            }
            break;
         }

         case ARGUS_GRAPH: {
            if (node->status & ARGUS_VISITED) {
               if (node->r || node->l) {
                  if (node->r) {
                     if (node->addr.str)
                        printf ("\"%s\" ", node->addr.str);
                     else  {
                        if (node->addr.addr[0]) {
                           if (node->addr.masklen > 0) {
                              printf ("\"%s/%d\" ", intoa(node->addr.addr[0] & (0xFFFFFFFF << (32 - node->addr.masklen))),
                                        node->addr.masklen);
                           } else
                              printf ("\"0.0.0.0/0\" ");
                        }
                     }
                     printf (" -> ");
                     if (node->r->addr.str)
                        printf ("\"%s\"\n", node->r->addr.str);
                     else  {
                        if (node->r->addr.addr[0]) {
                           if (node->r->addr.masklen > 0) {
                              printf ("\"%s/%d\"\n", intoa(node->r->addr.addr[0] & (0xFFFFFFFF << (32 - node->r->addr.masklen))),
                                        node->r->addr.masklen);
                           } else
                              printf ("\"0.0.0.0/0\"\n");
                        }
                     }
                     RaPrintTraceTree(labeler, node->r, level + 1, RA_SRV_RIGHT);
                  }

                  if (node->l) {
                     if (node->addr.str)
                        printf ("\"%s\" ", node->addr.str);
                     else  {
                        if (node->addr.addr[0]) {
                           if (node->addr.masklen > 0) {
                              printf ("\"%s/%d\" ", intoa(node->addr.addr[0] & (0xFFFFFFFF << (32 - node->addr.masklen))),
                                        node->addr.masklen);
                           } else
                              printf ("\"0.0.0.0/0\" ");
                        }
                     }
                     printf (" -> ");
                     if (node->l->addr.str)
                        printf ("\"%s\"\n", node->l->addr.str);
                     else  {
                        if (node->l->addr.addr[0]) {
                           if (node->l->addr.masklen > 0) {
                              printf ("\"%s/%d\"\n", intoa(node->l->addr.addr[0] & (0xFFFFFFFF << (32 - node->l->addr.masklen))),
                                        node->l->addr.masklen);
                           } else
                              printf ("\"0.0.0.0/0\"\n");
                        }
                     }
                     RaPrintTraceTree(labeler, node->l, level + 1, RA_SRV_RIGHT);
                  }
               }
            }
            break;
         }
      }
   }
}


#define ARGUS_PENDING	1

#if defined(ARGUS_THREADS)
void * ArgusTraceProcess (void *);

void *
ArgusTraceProcess (void *arg)
{
   extern struct hnamemem  hnametable[HASHNAMESIZE];
   struct timespec tsbuf = {1, 0}, *ts = &tsbuf;
   sigset_t blocked_signals;

   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusTraceProcess() starting");
#endif

   while (!(ArgusParser->RaParseDone)) {
      if (ArgusParser->ArgusProcessList == NULL) {
         nanosleep(ts, NULL);

      } else {
         struct timespec sts = {1, 250000000};
         struct timeval nowbuf, *now = &nowbuf;
         
         while (!ArgusListEmpty(ArgusParser->ArgusProcessList)) {
            struct ArgusListObjectStruct *list = ArgusParser->ArgusProcessList->start;

            gettimeofday(now, NULL);

            if (list != NULL) {
               u_int addr = list->list_val;
               static struct hnamemem *p;      /* static for longjmp() */
               int found = 0;
   
               ArgusPopFrontList(ArgusParser->ArgusProcessList, ARGUS_LOCK);
               ArgusFree(list);
   
               p = &hnametable[addr % (HASHNAMESIZE-1)];
               for (; p->nxt; p = p->nxt) {
                  if (p->addr == addr) {
                     found++;
                     break;
                  }
               }

               if (!found) {
                  p->addr = addr;
                  addr = htonl(addr);
                  p->nname = strdup(inet_ntoa(*(struct in_addr *)&addr));
                  addr = ntohl(addr);
                  p->nxt = (struct hnamemem *)calloc(1, sizeof (*p));
                  p->sec  = now->tv_sec;
               }

#ifdef ARGUSDEBUG
               ArgusDebug (1, "ArgusTraceProcess() query %s pending requests %d", p->nname, ArgusParser->ArgusProcessList->count);
#endif
            }
         }
         nanosleep(&sts, NULL);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusTraceProcess() done!");
#endif

#if defined(ARGUS_THREADS)
   pthread_exit (NULL);
#endif
   return (NULL);
}
#endif
