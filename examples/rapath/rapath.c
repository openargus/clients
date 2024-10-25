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
 * rasqltimeindex  - Read Argus data and build a time index suitable for
 *                   inserting into a database schema.
 *
 */

/*
 * rapath - print derivable path information from argus data.
 *
 *  The strategy is to take in 'icmpmap' data, and to formulate path information
 *  for the collection of records received. By classifying all the flow data by
 *  the tuple {src, dst}, we can track any number of simulataneous traceroutes
 *  and report on the results in a manner that preserves the granularity of the
 *  data seen, but provide means to modify that granularity to get interesting
 *  results.
 *
 *  The intermediate nodes
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * $Id: //depot/gargoyle/clients/examples/rapath/rapath.c#15 $
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

#include <math.h>

int RaInitialized = 0;
int RaPrintThinkMapOutput = 0;
int RaPrintSVGOutput = 0;
int RaPrintASNum = 0;
int RaPrintNode = 0;
int RaPrintAddr = 0;
int RaPrintTreeNode = 0;
int RaPrintDistance = 0;

struct ArgusQueueStruct *ArgusModelerQueue;

int RaCompareArgusStore (const void *, const void *);
void RaPackQueue (struct ArgusQueueStruct *);
void RaSortQueue (struct ArgusQueueStruct *);
void RaProcessQueue(struct ArgusQueueStruct *, unsigned char);

#define RAMAP_ETHER_MAC_ADDR            0x1
#define RAMAP_IP_ADDR                   0x10

#define MAX_OBJ_SIZE            1024
unsigned int RaMapHash = 0;
unsigned int RaHashSize  = 0;

struct RaMapHashTableStruct {
   int size;
   struct RaMapHashTableHeader **array;
};
 
struct RaMapHashTableHeader {
   struct ArgusQueueHeader qhdr;
   struct RaMapHashTableHeader *nxt, *prv;
   unsigned int hash;
   int type, len, value, mask, visited;
   void *obj, *sub;
};
 
struct ArgusHashTable *ArgusHashTable;
struct RaMapHashTableStruct RaMapAddrTable;
struct RaMapHashTableHeader *RaMapFindHashObject (struct RaMapHashTableStruct *, void *, int, int);
struct RaMapHashTableHeader *RaMapAddHashEntry (struct RaMapHashTableStruct *, void *, int, int);
void RaMapRemoveHashEntry (struct RaMapHashTableStruct *, struct RaMapHashTableHeader *);


unsigned int RaMapCalcHash (void *, int, int);

struct ArgusAggregatorStruct *ArgusMatrixAggregator = NULL;
struct ArgusAggregatorStruct *ArgusFlowAggregator = NULL;
        
char *RaLabelConfiguration[] = {
   "RALABEL_GEOIP_ASN=yes",
   "RALABEL_GEOIP_ASN_FILE=\"/usr/local/share/GeoIP/GeoIPASNum.dat\"",
   "RALABEL_GEOIP_V6_ASN_FILE=\"/usr/local/share/GeoIP/GeoIPASNumv6.dat\"",
   NULL,
};

char *RaMatrixAggregationConfig[] = {
   "RACLUSTER_PRESERVE_FIELDS=yes",
   "                   model=\"srcid saddr daddr\"        status=0   idle=3600\n",
   NULL,
};

char *RaPathAggregationConfig[] = {
   "RACLUSTER_PRESERVE_FIELDS=yes",
   "filter=\"icmpmap\" model=\"srcid saddr daddr proto sttl inode\"  status=120 idle=3600\n",
   "                   model=\"srcid saddr daddr proto sttl\"        status=0   idle=3600\n",
   NULL,
};

#define ARGUS_RCITEMS    4

#define ARGUS_RC_FILTER  0
#define ARGUS_RC_MODEL   1
#define ARGUS_RC_STATUS  2
#define ARGUS_RC_IDLE    3

static int argus_version = ARGUS_VERSION;

extern char *ArgusAggregatorFields[];

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;

   parser->RaWriteOut = 0;
 
   if (!(parser->RaInitialized)) {
      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strcasecmp (mode->mode, "think")))
               RaPrintThinkMapOutput++;
            if (!(strcasecmp (mode->mode, "svg")))
               RaPrintSVGOutput++;
            if (!(strcasecmp (mode->mode, "addr"))) {
               RaPrintAddr = 1;
               RaPrintNode = 0;
            }
            if (!(strcasecmp (mode->mode, "tree")))
               RaPrintTreeNode = 1;

            if (!(strcasecmp (mode->mode, "node"))) {
               RaPrintAddr = 0;
               RaPrintNode = 1;
            }
            if (!(strcasecmp (mode->mode, "aspath"))) {
               RaPrintASNum++;
            }
            if (!(strcasecmp (mode->mode, "asnode"))) {
               RaPrintASNum++;
               RaPrintNode++;
            }
            if (!(strcasecmp (mode->mode, "asaddr"))) {
               RaPrintASNum++;
               RaPrintAddr++;
            }
            if (!(strcasecmp (mode->mode, "dist")))
               RaPrintDistance = 1;
            mode = mode->nxt;
         }
      }

      if (!(RaPrintAddr) && !(RaPrintNode) && !(RaPrintASNum))
         RaPrintNode = 1;

      if (ArgusParser->RaPrintOptionStrings[0] == NULL) {
         parser->RaPrintOptionIndex = 0;
         parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("srcid");
         parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("saddr");
         parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("dir");
         parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("daddr");
         parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("inode");

         if (RaPrintASNum)
            parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("ias:8");

         parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("sttl");
         parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("mean");
         parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("stddev");
         parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("max");
         parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("min");
         parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("trans");
         ArgusProcessSOptions(parser);
      } 

      if (parser->ArgusFlowModelFile) {
         if ((parser->ArgusLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

         RaLabelParseResourceFile (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile);
         free(parser->ArgusFlowModelFile);
         parser->ArgusFlowModelFile = NULL;
      }

      if ((ArgusFlowAggregator = ArgusParseAggregator(parser, NULL, RaPathAggregationConfig)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseAggregator error");

      if (parser->ArgusMaskList != NULL) {
         if ((parser->ArgusPathAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

// have to see if we need to modify the model definition in our RaPathAggregation Config

         if (ArgusFlowAggregator->saddrlen != parser->ArgusPathAggregator->saddrlen) {
            ArgusFlowAggregator->saddrlen = parser->ArgusPathAggregator->saddrlen;
            bcopy(&parser->ArgusPathAggregator->smask, &ArgusFlowAggregator->smask, sizeof(parser->ArgusPathAggregator->smask));
         }

         if (ArgusFlowAggregator->daddrlen != parser->ArgusPathAggregator->daddrlen) {
            ArgusFlowAggregator->daddrlen = parser->ArgusPathAggregator->daddrlen;
            bcopy(&parser->ArgusPathAggregator->dmask, &ArgusFlowAggregator->dmask, sizeof(parser->ArgusPathAggregator->dmask));
         }

      } else {
         if ((parser->ArgusPathAggregator = ArgusParseAggregator(parser, NULL, RaMatrixAggregationConfig)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseAggregator error");
      }

      if ((ArgusSorter = ArgusNewSorter(parser)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewSorter error %s", strerror(errno));

      if (parser->vflag)
         ArgusReverseSortDir++;

      bzero ((char *) ArgusSorter->ArgusSortAlgorithms, sizeof(ArgusSorter->ArgusSortAlgorithms));
      ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortAlgorithmTable[ARGUSSORTSRCADDR];
      ArgusSorter->ArgusSortAlgorithms[1] = ArgusSortAlgorithmTable[ARGUSSORTDSTADDR];
      ArgusSorter->ArgusSortAlgorithms[2] = ArgusSortAlgorithmTable[ARGUSSORTPROTOCOL];
      ArgusSorter->ArgusSortAlgorithms[3] = ArgusSortAlgorithmTable[ARGUSSORTSRCTTL];
      ArgusSorter->ArgusSortAlgorithms[4] = ArgusSortAlgorithmTable[ARGUSSORTTRANSACTIONS];
      ArgusSorter->ArgusSortAlgorithms[4] = ArgusSortAlgorithmTable[ARGUSSORTMINDURATION];
 
      if ((ArgusModelerQueue = ArgusNewQueue()) == NULL)
         exit(0);

      if ((ArgusHashTable = ArgusNewHashTable(RABINS_HASHTABLESIZE)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s\n", strerror(errno));

      if ((RaMapAddrTable.array = (struct RaMapHashTableHeader **) ArgusCalloc (parser->ArgusHashTableSize,
                                    sizeof (struct RaMapHashTableHeader *))) != NULL) {
         RaMapAddrTable.size = parser->ArgusHashTableSize;
      }

      parser->RaCumulativeMerge = 1;
      parser->RaInitialized++;
      parser->ArgusPrintJson = 0;
   }
}


void
ArgusClientTimeout ()
{
/*
   RaProcessQueue (ArgusModelerQueue, ARGUS_STATUS);
*/
#ifdef ARGUSDEBUG
      ArgusDebug (9, "ArgusClientTimeout() done\n");
#endif  
}


struct RaPathNode {
   struct RaPathNode *nxt;
   struct ArgusQueueStruct *nodes;
   int as, ttl;
};

struct RaPathTree {
};


struct RaPathNode *RaPathBuildPath (struct ArgusQueueStruct *);
void RaPathDeletePath (struct RaPathNode *);
void RaPrintPath (struct RaPathNode *, char *, int);

/*
   The idea is to build the path tree for a given queue.  The queue
   should have ArgusRecordStruct's that have unique icmp->osrcaddr
   elements, sorted by sttl.  These queue elements represent the
   unique elements to deal with in this path and a path is constructed.

   Nodes in the path can be single elements,

*/

 
void RaPathInsertTree (struct RaPathTree *, struct RaPathNode *);
void RaPrintPathNodes (struct RaPathNode *, int, char *buf, int);

struct RaPathNode *
RaPathBuildPath (struct ArgusQueueStruct *queue)
{
   struct RaPathNode *path = NULL, *node = NULL;
   struct ArgusRecordStruct *ns, *argus;
   int count = 0;

   if (queue == NULL)
      return (path);

   if ((count = queue->count) > 0) {
      unsigned int pttl, tttl, as;
      int i = 0;

      for (i = 0; i < count; i++) {
         if  ((ns = (struct ArgusRecordStruct *) ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
            if ((argus = ArgusCopyRecordStruct(ns)) != NULL) {
               struct ArgusIPAttrStruct *attr = (void *)argus->dsrs[ARGUS_IPATTR_INDEX];
               struct ArgusAsnStruct *asn = (void *)argus->dsrs[ARGUS_ASN_INDEX];

               tttl = attr->src.ttl;

               if (path == NULL) {
                  if ((path = (struct RaPathNode *) ArgusCalloc (1, sizeof (*node))) == NULL)
                     ArgusLog (LOG_ERR, "ArgusCalloc error %s", strerror(errno));

                  node = path;
                  node->ttl = tttl;

                  if ((asn !=  NULL) && (asn->hdr.argus_dsrvl8.len > 2)) 
                     if ((as = asn->inode_as) != 0) {
                        node->as = as;
                     }

                  if ((node->nodes = ArgusNewQueue()) == NULL)
                     ArgusLog (LOG_ERR, "ArgusNewQueue error %s", strerror(errno));

                  ArgusAddToQueue (node->nodes, &argus->qhdr, ARGUS_NOLOCK);

               } else {
                  struct ArgusIPAttrStruct *pattr = (void *)((struct ArgusRecordStruct *)node->nodes->start)->dsrs[ARGUS_IPATTR_INDEX];

                  if ((pattr != NULL) && (attr != NULL)) {
                     pttl = pattr->src.ttl;

                     if (pttl == tttl) {
                        ArgusAddToQueue (node->nodes, &argus->qhdr, ARGUS_NOLOCK);

                        if ((asn !=  NULL) && (asn->hdr.argus_dsrvl8.len > 2))
                           if (node->as != asn->inode_as)
                              node->as = -1;
                     } else {
                        struct RaPathNode *prv = node;

                        if ((node = (struct RaPathNode *) ArgusCalloc (1, sizeof (*node))) == NULL)
                           ArgusLog (LOG_ERR, "ArgusCalloc error %s", strerror(errno));

                        node->ttl = tttl;

                        if ((asn !=  NULL) && (asn->hdr.argus_dsrvl8.len > 2)) 
                           if ((as = asn->inode_as) != 0)
                              node->as = as;

                        prv->nxt = node;

                        if ((node->nodes = ArgusNewQueue()) == NULL)
                           ArgusLog (LOG_ERR, "ArgusNewQueue error %s", strerror(errno));

                        ArgusAddToQueue (node->nodes, &argus->qhdr, ARGUS_NOLOCK);
                     }
                  }
               }
               ArgusAddToQueue (queue, &ns->qhdr, ARGUS_NOLOCK);
            }
         }
      }
   }
 
   return (path);
}

void
RaPathDeletePath (struct RaPathNode *path)
{
   if (path->nxt != NULL)
      RaPathDeletePath(path->nxt);

   if (path->nodes != NULL) {
      ArgusDeleteQueue(path->nodes);
   }
   ArgusFree(path);

   return;
}


void
RaPathInsertTree (struct RaPathTree *tree, struct RaPathNode *path)
{
}

// "as"       AS1 -> AS2 -> AS3
// "node"     A -> B -> {C, D} -> F
// "node"     [A -> B] -> [{C, D} -> F] -> [G -> H]
// "asnode"   AS30496:[A -> B] -> AS6079:[C -> {D,E}] -> AS1257:[F] -> AS11164:[G -> H] -> AS5050:[I] -> AS9:[J -> {K,L}]
// "asaddr"   AS30496:[A -> B] -> AS6079:[C -> {D,E}] -> AS1257:[F] -> AS11164:[G -> H] -> AS5050:[I] -> AS9:[J -> {K,L}]

void
RaPrintPathNodes (struct RaPathNode *tree, int level, char *buf, int len)
{
   struct RaPathNode *path = tree;
   unsigned short as = 0;
   int status = 0, shop = 0;

   while (path != NULL) {
      struct ArgusQueueStruct *queue = path->nodes;
      struct ArgusRecordStruct *argus = NULL;
      int hopcount, multias = 0;

      if (status == 0) {
         if (path->as != 0) {
            if (path->as == -1) {
               multias = 1;
            } else {
               as = path->as;

               if (RaPrintASNum) {
                  sprintf (&buf[strlen(buf)], "AS%d", as);

                  if (RaPrintNode || RaPrintAddr)
                     sprintf (&buf[strlen(buf)], ":[");

               } else 
                  sprintf (&buf[strlen(buf)], "[");

               status++;
            }
         }
         shop = path->ttl;
         hopcount = 0;
      }

      if (queue->count > 1) {
         if (RaPrintNode || RaPrintAddr) {
            sprintf (&buf[strlen(buf)], "{");
            while ((argus = (struct ArgusRecordStruct *) ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
               if (multias) {
                  struct ArgusAsnStruct *asn = (void *)argus->dsrs[ARGUS_ASN_INDEX];
                  if ((asn != NULL) && (asn->hdr.argus_dsrvl8.len > 2)) {
                     if (RaPrintASNum) {
                        if (asn->inode_as > 0) {
                          sprintf (&buf[strlen(buf)], "AS%d", asn->inode_as);
                        } else {
                           sprintf (&buf[strlen(buf)], "%c", argus->autoid);
                        }
                     } else
                        sprintf (&buf[strlen(buf)], ":[");
                  }
               }

               if (RaPrintAddr) {
                  char inodeStr[256], *inodePtr = inodeStr;
                  ArgusPrintInode (ArgusParser, inodeStr, argus, 256);
                  while (*inodePtr == ' ') inodePtr++;
                  while (inodePtr[strlen(inodePtr) - 1] == ' ') inodePtr[strlen(inodePtr) - 1] = '\0';
                  sprintf (&buf[strlen(buf)], "%s", inodePtr);
               } else
                  sprintf (&buf[strlen(buf)], "%c", argus->autoid);

               if (multias) {
                  sprintf (&buf[strlen(buf)], "]");
               }

               if (queue->count > 0)
                  sprintf (&buf[strlen(buf)], ", ");

               ArgusAddToQueue(ArgusModelerQueue, &argus->qhdr, ARGUS_LOCK);
            }

            sprintf (&buf[strlen(buf)], "}");
            if (RaPrintDistance) {
               sprintf (&buf[strlen(buf)], ":%d", path->ttl);
               shop = path->ttl;
            }

            while ((argus = (struct ArgusRecordStruct *) ArgusPopQueue(ArgusModelerQueue, ARGUS_LOCK)) != NULL)
               ArgusAddToQueue(queue, &argus->qhdr, ARGUS_NOLOCK);
         }

      } else {
         argus = (struct ArgusRecordStruct *) queue->start;
         
         if (RaPrintAddr) {
            char inodeStr[256], *inodePtr = inodeStr;
            ArgusPrintInode (ArgusParser, inodeStr, argus, 256);
            while (*inodePtr == ' ') inodePtr++;
            while (inodePtr[strlen(inodePtr) - 1] == ' ') inodePtr[strlen(inodePtr) - 1] = '\0';
            sprintf (&buf[strlen(buf)], "%s", inodePtr);

         } else 
         if (RaPrintNode) {
            sprintf (&buf[strlen(buf)], "%c", argus->autoid);
         }

         if (RaPrintDistance) {
            sprintf (&buf[strlen(buf)], ":%d", path->ttl);
            shop = path->ttl;
         }
      }

      if ((path = path->nxt) != NULL) {
         if (status) {
            if (path->as != as) {
               if (RaPrintNode || RaPrintAddr)
                  sprintf (&buf[strlen(buf)], "]");

               if (RaPrintDistance) {
                  if ((hopcount - shop) > 0) {
                     sprintf (&buf[strlen(buf)], ":%d-%d", shop, hopcount);
                     hopcount = 0;
                  }
               }

               sprintf (&buf[strlen(buf)], " -> ");
               status--;
               as = 0;

            } else {
               if (RaPrintNode || RaPrintAddr)
                  sprintf (&buf[strlen(buf)], " -> ");
               hopcount = path->ttl;
            }

         } else
            if (RaPrintNode || RaPrintAddr)
               sprintf (&buf[strlen(buf)], " -> ");

      } else {
         if (status) {
            if (RaPrintDistance) {
               if ((hopcount - shop) > 0)
                  sprintf (&buf[strlen(buf)], ":%d-%d", shop, hopcount);
            }

            if (RaPrintNode || RaPrintAddr)
               sprintf (&buf[strlen(buf)], "]");
         }
      }
   }
}


void
RaPrintPath (struct RaPathNode *tree, char *buf, int len)
{
   bzero (buf, len);
   RaPrintPathNodes(tree, 0, buf, len);
}


void RaArgusInputComplete (struct ArgusInput *input) { return; }


int RaParseCompleting = 0;
struct RaPathTree *RaTreeNode = NULL;

void
RaParseComplete (int sig)
{
   struct ArgusModeStruct *mode = NULL;
   int i = 0, x = 0, nflag = ArgusParser->eNflag;

   if (sig >= 0) {
      if (!(ArgusParser->RaParseCompleting++)) {
         struct ArgusAggregatorStruct *agg = ArgusParser->ArgusPathAggregator;

         ArgusParser->RaParseCompleting += sig;
 
         if (agg != NULL) {
            if (agg->queue->count) {
               struct ArgusRecordStruct *tns = NULL, *cns = NULL;

               if (!(ArgusSorter)) {
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
               }

               ArgusSortQueue (ArgusSorter, agg->queue, ARGUS_LOCK);
               if (nflag == 0)
                  ArgusParser->eNflag = agg->queue->count;
               else
                  ArgusParser->eNflag = nflag > agg->queue->count ? agg->queue->count : nflag;

               for (i = 0; i < ArgusParser->eNflag; i++) {
                  tns = (struct ArgusRecordStruct *) agg->queue->array[i];

                  if (tns->agg != NULL) {
                     int cnt = tns->agg->queue->count;
                     char nodeChar = 'A';

                     ArgusSortQueue (ArgusSorter, tns->agg->queue, ARGUS_LOCK);

                     for (x = 0; x < cnt; x++) {
                        cns = (struct ArgusRecordStruct *) tns->agg->queue->array[x];
                        cns->autoid = nodeChar;
                        nodeChar = ((nodeChar == 'Z') ? 'a' : nodeChar + 1);
                     }

                     if (ArgusParser->Aflag) {
                        struct RaPathNode *path = RaPathBuildPath (tns->agg->queue);
                        char *sbuf = NULL, *RaTreeBuffer = NULL;

                        if (path) {
                           char srcId[64], srcAddr[32], dstAddr[32];

                           if ((sbuf = calloc(1, MAXSTRLEN)) == NULL)
                              ArgusLog (LOG_ERR, "RaParseComplete: calloc error %s", strerror(errno));

                           if ((RaTreeBuffer = calloc(1, MAXSTRLEN)) == NULL)
                              ArgusLog (LOG_ERR, "RaParseComplete: calloc error %s", strerror(errno));

                           if (RaPrintTreeNode)
                              RaPathInsertTree(RaTreeNode, path);

                           cns = (struct ArgusRecordStruct *) tns->agg->queue->array[0];

                           bzero(srcId,   sizeof(srcId));
                           bzero(srcAddr, sizeof(srcAddr));
                           bzero(dstAddr, sizeof(dstAddr));

                           ArgusPrintSourceID (ArgusParser,  srcId, cns, 0);
                           ArgusPrintSrcAddr (ArgusParser, srcAddr, cns, 0);
                           ArgusPrintDstAddr (ArgusParser, dstAddr, cns, 0);

                           RaPrintPath (path, RaTreeBuffer, sizeof(RaTreeBuffer));
                           srcId[strlen(srcId) - 1] = '\0';
                           srcAddr[strlen(srcAddr) - 1] = '\0';
                           dstAddr[strlen(dstAddr) - 1] = '\0';

                           sprintf(sbuf, "%s(%s::%s) %s\n", srcId, srcAddr, dstAddr, RaTreeBuffer);
                           printf("%s\n", sbuf);
                           RaPathDeletePath(path);
                        }

                        if (RaTreeBuffer) free (RaTreeBuffer);
                        if (sbuf) free (sbuf);
                     }

                     for (x = 0; x < cnt; x++) {
                        cns = (struct ArgusRecordStruct *) tns->agg->queue->array[x];
                        RaSendArgusRecord (cns);
                     }
                     if (!(ArgusParser->qflag))
                        printf ("\n");
                  }
               }

               if (ArgusParser->ns != NULL)
                  ArgusFree(ArgusParser->ns);
               ArgusParser->ns = NULL;
            }
         }

         ArgusDeleteAggregator(ArgusParser, ArgusFlowAggregator);
         ArgusDeleteHashTable(ArgusHashTable);
         ArgusDeleteSorter(ArgusSorter);
         ArgusDeleteQueue(ArgusModelerQueue);

         if (RaMapAddrTable.array != NULL) {
            ArgusFree (RaMapAddrTable.array);
            RaMapAddrTable.array =  NULL;
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

   ArgusParser->eNflag = nflag;
}

void
usage ()
{
   extern char version[];

   fprintf (stdout, "Rapath Version %s\n", version);
   fprintf (stdout, "usage:  %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage:  %s [-f ralabel.conf] [ra-options] [- filter-expression]\n\n", ArgusParser->ArgusProgramName);


   fprintf (stdout, "options:  -f <racluster.conf>  read label rules from <ralabel.conf>.\n");
   fprintf (stdout, "          -A                   print path graph\n");
#ifdef ARGUSDEBUG
   fprintf (stdout, "          -D <level>           specify debug level\n");
#endif
   fprintf (stdout, "          -q                   quiet mode.  Supress printing records.\n");
   fprintf (stdout, "          -m flow key fields   modify the flow model for path data.\n");
   fprintf (stdout, "          -M <option>          specify a Mode of operation.\n");
   fprintf (stdout, "             Available modes:      \n");
   fprintf (stdout, "               as              print path with AS information\n");
   fprintf (stdout, "               addr            print path as list of addresses\n");
   fprintf (stdout, "               node            print path as list of nodes\n");
   fprintf (stdout, "               dist            print path with hop counts\n");
   fprintf (stdout, "               tree            print path tree\n");

   fflush (stdout);

   exit(1);
}

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaPrintArgusPath (struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusIcmpStruct *icmp = NULL;

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_LAYER_3_MATRIX:
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        if (flow->ip_flow.ip_src > flow->ip_flow.ip_dst) {
                        }
                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        int i;
                        for (i = 0; i < 4; i++) {
                           if (flow->ipv6_flow.ip_src[i] < flow->ipv6_flow.ip_dst[i])
                              break;

                           if (flow->ipv6_flow.ip_src[i] > flow->ipv6_flow.ip_dst[i]) {
                              break;
                           }
                        }
                        break;
                     }
                  }
                  break;
               }
               default:
                  return;
                  break;
            }

            if ((icmp = (struct ArgusIcmpStruct *) ns->dsrs[ARGUS_ICMP_INDEX]) != NULL) {
               if ((icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMPUNREACH_MAPPED) ||
                   (icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMPTIMXCED_MAPPED)) {

               }

               switch (flow->ip_flow.ip_p) {
                  case IPPROTO_UDP:
                  case IPPROTO_TCP:
                     break;

                  case IPPROTO_ICMP:
                     break;

                  default:
                     break;
               }

               RaProcessThisRecord (parser, ns);
            }
         }
         break;
      }
   }
}


void RaUpdateArgusStorePath(struct ArgusRecord *, struct ArgusRecordStruct *);
struct ArgusRecordStruct *RaProcessAggregation(struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *);

struct ArgusRecordStruct *
RaProcessAggregation(struct ArgusParserStruct *parser, struct ArgusAggregatorStruct *agg, struct ArgusRecordStruct *ns)
{
   struct ArgusHashStruct *hstruct = NULL;
   struct ArgusRecordStruct *retn = NULL;

   if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
      agg->rap = agg->drap;

   ArgusGenerateNewFlow(agg, ns);
   agg->ArgusMaskDefs = NULL;

   if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
      ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

   if ((retn = ArgusFindRecord(agg->htable, hstruct)) != NULL) {
/*
      if (parser->Aflag) {
         if ((retn->status & RA_SVCTEST) != (ns->status & RA_SVCTEST)) {
            RaSendArgusRecord(retn);
            ArgusZeroRecord(retn);
            retn->status &= ~(RA_SVCTEST);
            retn->status |= (ns->status & RA_SVCTEST);
         }
      }
*/
      ArgusMergeRecords (agg, retn, ns);

   } else {
      if (!parser->RaMonMode) {
         struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
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

            if ((retn = ArgusFindRecord(agg->htable, hstruct)) == NULL) {
               if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
                  ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));

            } else {
               ArgusReverseRecord (ns);
            }
         }
      }

      if (retn != NULL) {
         if (parser->Aflag) {
            if ((retn->status & RA_SVCTEST) != (ns->status & RA_SVCTEST)) {
               RaSendArgusRecord(retn);
               ArgusZeroRecord(retn);
            }
            retn->status &= ~(RA_SVCTEST);
            retn->status |= (ns->status & RA_SVCTEST);
         } else
            ArgusMergeRecords (agg, retn, ns);

      } else {
         retn = ArgusCopyRecordStruct(ns);
         ArgusAddHashEntry (agg->htable, retn, hstruct);
         ArgusAddToQueue (agg->queue, &retn->qhdr, ARGUS_NOLOCK);
      }
   }

   return retn;
}

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusAggregatorStruct *agg  = parser->ArgusPathAggregator;
   struct ArgusRecordStruct *tns, *cns;
   int retn = 0;

   struct nff_insn *fcode = agg->filter.bf_insns;

   if ((retn = ArgusFilterRecord (fcode, ns)) != 0) {
      if ((cns = ArgusCopyRecordStruct(ns)) == NULL)
         ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusCopyRecordStruct error %s", strerror(errno));

      ArgusLabelRecord(parser, cns);

      if ((tns = RaProcessAggregation(parser, agg, cns)) != NULL) {
         if (tns->agg == NULL) 
            if ((tns->agg = ArgusCopyAggregator(ArgusFlowAggregator)) == NULL)
               ArgusLog (LOG_ERR, "RaProcessThisRecod: ArgusCopyAggregator error");

         if (tns != NULL)
            RaProcessAggregation(parser, tns->agg, cns);
      }

      ArgusDeleteRecordStruct(parser, cns);
   }
}


char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];

int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{
   struct ArgusRecord *argusrec = NULL;
   int retn = 1;

   if (argus->status & ARGUS_RECORD_WRITTEN)
      return (retn);
 
   if (ArgusParser->RaAgMode)
      argus->dsrs[ARGUS_AGR_INDEX] = NULL;

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
               }
               lobj = lobj->nxt;
            }
         }

      } else {
         char buf[MAXSTRLEN];
         if (!ArgusParser->qflag) {
            if (ArgusParser->Lflag && (!(ArgusParser->ArgusPrintXml) && !(ArgusParser->ArgusPrintJson))) {
               if (ArgusParser->RaLabel == NULL)
                  ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, argus);
 
               if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag)) {
                  if (ArgusParser->Aflag && (!(RaPrintAddr)))
                     printf (" Node %s\n", ArgusParser->RaLabel);
                  else
                     printf ("%s\n", ArgusParser->RaLabel);
               }
 
               if (ArgusParser->Lflag < 0)
                  ArgusParser->Lflag = 0;
            }

            buf[0] = 0;
            ArgusPrintRecord(ArgusParser, buf, argus, MAXSTRLEN);
            
            if (ArgusParser->Aflag && (!(RaPrintAddr))) {
               int ret = fprintf (stdout, "  %c   %s\n", argus->autoid, buf);
               if (ret < 0)
                  RaParseComplete(SIGQUIT);
            } else
               if (fprintf (stdout, "%s\n", buf) < 0)
                  RaParseComplete(SIGQUIT);
            fflush(stdout);
         }
      }
   }

   argus->status |= ARGUS_RECORD_WRITTEN;
   return (retn);
}

void ArgusWindowClose(void) { } 
