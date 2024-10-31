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
 */

/*
 * ralabel - add descriptor labels to flows.
 *           this particular labeler adds descriptors based
 *           on addresses.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * $Id: //depot/gargoyle/clients/examples/ralabel/ralabel.c#17 $
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#if defined(ARGUS_SOLARIS)
#include <strings.h>
#include <string.h>
#endif

#include <math.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_label.h>
#include <argus_client.h>
#include <argus_filter.h>
#include <argus_main.h>
#include <argus_cluster.h>

struct ArgusQueueStruct *ArgusModelerQueue = NULL;
struct ArgusQueueStruct *ArgusFileQueue = NULL;
struct ArgusQueueStruct *ArgusProbeQueue = NULL;

struct ArgusAggregatorStruct *ArgusMatrixAggregator = NULL;
struct ArgusAggregatorStruct *ArgusFlowAggregator = NULL;

char *RaLabelConfiguration[] = {
    "RALABEL_GEOIP_ASN=*:asn,asorg",
    "RALABEL_GEOIP_ASN_FILE=GeoLite2-ASN.mmdb",
    "RALABEL_GEOIP_CITY=*:lat,lon",
    "RALABEL_GEOIP_CITY_FILE=GeoLite2-City.mmdb",
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

unsigned int RaMapHash = 0;
unsigned int RaHashSize  = 0;

int ArgusDebugTree = 0;
int RaPrintTraceTreeLevel = 1000000;

static int argus_version = ARGUS_VERSION;
extern char RaAddrTreeArray[];

char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];
 
void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int RaProcessThisAddress (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct ArgusRecordStruct *, unsigned int *, int, int);
void RaProcessICMPPathRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
struct ArgusRecordStruct *RaProcessAggregation(struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *);
int ArgusScanTreeForWork (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   extern int RaPrintLabelTreeLevel;
   struct RaAddressStruct **ArgusAddrTree;
   struct ArgusModeStruct *mode = NULL;
   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      if ((ArgusLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      if (ArgusLabeler->ArgusAddrTree == NULL)
         if ((ArgusLabeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog (LOG_ERR, "RaReadAddressConfig: ArgusCalloc error %s\n", strerror(errno));

      ArgusAddrTree = ArgusLabeler->ArgusAddrTree;
      parser->ArgusLabeler = ArgusLabeler;

      if (parser->ArgusLocalLabeler == NULL)
         if ((parser->ArgusLocalLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strcmp ("replace", mode->mode))) {
               ArgusProcessFileIndependantly = 1;
               parser->ArgusReplaceMode |= ARGUS_REPLACE_MODE_TRUE;

               if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList)))) {
                  ArgusLog (LOG_ERR, "replace mode and -w option are incompatible\n");
               }
            } else
            if (!(strncasecmp (mode->mode, "noprune", 7))) {
               if (parser->ArgusLabeler) parser->ArgusLabeler->prune = 0;
               if (parser->ArgusLocalLabeler) parser->ArgusLocalLabeler->prune = 0;
            } else
            if (!(strncasecmp (mode->mode, "addr", 4))) {
               if (parser->ArgusFlowModelFile) {
                  if (!(RaReadAddressConfig (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile) > 0))
                     ArgusLog (LOG_ERR, "ArgusNewLabeler: RaReadAddressConfig error");
                  parser->ArgusFlowModelFile = NULL;
		  parser->ArgusLabeler->RaLabelIanaAddress = 1;
               }
            } else
            if ((!(strncasecmp (mode->mode, "debug.label", 11))) ||
                (!(strncasecmp (mode->mode, "debug.cco", 9))) ||
                (!(strncasecmp (mode->mode, "debug", 5)))) {
               ArgusDebugTree = 1;
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE;

               if (!(strncasecmp (mode->mode, "debug.label", 11)))
                  RaPruneAddressTree(ArgusLabeler, ArgusAddrTree[AF_INET], ARGUS_TREE_PRUNE_LABEL | ARGUS_TREE_PRUNE_ADJ, 0);
               if (!(strncasecmp (mode->mode, "debug.cco", 9)))
                  RaPruneAddressTree(ArgusLabeler, ArgusAddrTree[AF_INET], ARGUS_TREE_PRUNE_CCO | ARGUS_TREE_PRUNE_ADJ, 0);

               RaPrintLabelTree (ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0);
               ArgusAddrTree[AF_INET] = NULL;
               RaParseComplete(0);

            } else
            if (!(strncasecmp (mode->mode, "rmon", 4)))
               parser->RaMonMode++;

            mode = mode->nxt;
         }
      }

      if (parser->ArgusFlowModelFile) {
         RaLabelParseResourceFile (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile);
         parser->ArgusFlowModelFile = NULL;
      }

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
      parser->RaInitialized++;
   }
}

void
RaArgusInputComplete (struct ArgusInput *input) 
{
   if (ArgusProcessFileIndependantly) {
      ArgusParser->ArgusCurrentInput = input;

      RaParseComplete (0);

      if (ArgusParser->ArgusReplaceMode && input) {
         if (ArgusParser->ArgusWfileList != NULL) {
            struct ArgusWfileStruct *wfile = NULL;

            if ((wfile = (void *)ArgusParser->ArgusWfileList->start) != NULL) {
               fflush (wfile->fd);
               rename (wfile->filename, input->filename);
               fclose (wfile->fd);
               wfile->fd = NULL;
            }

            ArgusDeleteList(ArgusParser->ArgusWfileList, ARGUS_WFILE_LIST);
            ArgusParser->ArgusWfileList = NULL;

            if (ArgusParser->Vflag)
               ArgusLog(LOG_INFO, "file %s labeled", input->filename);
         }
      }
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
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
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

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaParseComplete (%d) returning\n", sig);
#endif
}

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
   struct timeval tvbuf, *tvp = &tvbuf;

   if (!(ArgusParser->Pauseflag)) {
      gettimeofday(&ArgusParser->ArgusRealTime, 0);
      ArgusAdjustGlobalTime (ArgusParser, NULL);
   }

   *tvp = ArgusParser->ArgusGlobalTime;
   ArgusGetInterfaceAddresses(ArgusParser);

#ifdef ARGUSDEBUG
   struct RaAddressStruct **ArgusAddrTree = ArgusLabeler->ArgusAddrTree;
   int traces = ArgusScanTreeForWork(ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0);
 
   ArgusDebug (1, "ArgusClientTimeout: %d nets/24 available for trace\n", traces);
#endif

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
   fprintf (stdout, "RaLabeler Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [ra-options] -S remoteServer  [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [ra-options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "options: -f <conffile>     read ralabel spec from <conffile>.\n");
   fflush (stdout);
   exit(1);
}


void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusInput *input = argus->input;
   struct ArgusRecordStruct *ns = NULL;
   char *buf = NULL;
   int label;

   ArgusProcessServiceAvailability(parser, argus);
   ArgusLabelRecord(parser, argus);
   RaProcessThisRecord(parser, argus);

   if ((buf = ArgusCalloc(1, MAXSTRLEN)) == NULL)
      ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s\n", strerror(errno));

   if (ArgusParser->ArgusReplaceMode && input) {
      if (parser->ArgusWfileList == NULL) {
         if (!(ArgusParser->ArgusRandomSeed))
            srandom(ArgusParser->ArgusRandomSeed);

         srandom (ArgusParser->ArgusRealTime.tv_usec);
         label = random() % 100000;

         snprintf (buf, MAXSTRLEN, "%s.tmp%d", input->filename, label);
         setArgusWfile(ArgusParser, buf, NULL);
      }
   }

   if ((ns = ArgusCopyRecordStruct(argus)) != NULL) {
      ArgusLabelRecord(parser, ns);

      if (parser->ArgusWfileList != NULL) {
         struct ArgusWfileStruct *wfile = NULL;
         struct ArgusListObjectStruct *lobj = NULL;
         int i, count = parser->ArgusWfileList->count;

         if ((lobj = parser->ArgusWfileList->start) != NULL) {
            for (i = 0; i < count; i++) {
               if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                  if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                     struct ArgusRecord *argusrec = NULL;
                     int rv;

                     if ((argusrec = ArgusGenerateRecord (ns, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        rv = ArgusWriteNewLogfile (parser, ns->input, wfile, argusrec);
                        if (rv < 0)
                           ArgusLog(LOG_ERR, "%s unable to open file\n", __func__);
                     }
                  }
               }

               lobj = lobj->nxt;
            }
         }

      } else {
         if (!parser->qflag) {
            if (parser->Lflag && (!(parser->ArgusPrintXml) && !(ArgusParser->ArgusPrintJson))) {
               if (parser->RaLabel == NULL)
                  parser->RaLabel = ArgusGenerateLabel(parser, ns);
    
               if (!(parser->RaLabelCounter++ % parser->Lflag))
                  printf ("%s\n", parser->RaLabel);
    
               if (parser->Lflag < 0)
                  parser->Lflag = 0;
            }

            memset(buf, 0, MAXSTRLEN);
            ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
            if (parser->ArgusPrintJson) {
               if (fprintf (stdout, "%s", buf) < 0)
                  RaParseComplete (SIGQUIT);
            } else {
               if (fprintf (stdout, "%s\n", buf) < 0)
                  RaParseComplete (SIGQUIT);
            }
         }
      }
                    
      fflush (stdout);
      ArgusDeleteRecordStruct(parser, ns);
   }

   ArgusFree(buf);

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessRecord (0x%x) returning\n", argus);
#endif
}



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

struct ArgusRecordStruct *
RaProcessAggregation(struct ArgusParserStruct *parser, struct ArgusAggregatorStruct *agg, struct ArgusRecordStruct *ns)
{
    struct ArgusHashStruct *hstruct = NULL;
    struct ArgusRecordStruct *retn = NULL;
    
    if ((agg != NULL) && (ns != NULL)) {
        if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
            agg->rap = agg->drap;
        
        ArgusGenerateNewFlow(agg, ns);
        
        if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) == NULL)
            ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusGenerateHashStruct error %s", strerror(errno));
        
        if ((retn = ArgusFindRecord(agg->htable, hstruct)) != NULL) {
            if (parser->Aflag) {
                if ((retn->status & RA_SVCTEST) != (ns->status & RA_SVCTEST)) {
                    RaSendArgusRecord(retn);
                    ArgusZeroRecord(retn);
                    retn->status &= ~(RA_SVCTEST);
                    retn->status |= (ns->status & RA_SVCTEST);
                }
            }
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
                ArgusMergeRecords (agg, retn, ns);
            } else {
                retn = ArgusCopyRecordStruct(ns);
                ArgusAddHashEntry (agg->htable, retn, hstruct);
                ArgusAddToQueue (agg->queue, &retn->qhdr, ARGUS_NOLOCK);
            }
        }
    }
    
    return retn;
}

void
RaProcessICMPPathRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
    struct ArgusAggregatorStruct *agg  = parser->ArgusPathAggregator;
    struct ArgusRecordStruct *tns, *cns;
    
    struct nff_insn *fcode = agg->filter.bf_insns;
    
    if (ArgusFilterRecord (fcode, ns) != 0) {
        if ((cns = ArgusCopyRecordStruct(ns)) == NULL)
            ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusCopyRecordStruct error %s", strerror(errno));
                
        if ((tns = RaProcessAggregation(parser, agg, cns)) != NULL) {
            if (tns->agg == NULL)
                if ((tns->agg = ArgusCopyAggregator(ArgusFlowAggregator)) == NULL)
                    ArgusLog (LOG_ERR, "RaProcessThisRecod: ArgusCopyAggregator error");
            
            if (tns != NULL)
                RaProcessAggregation(parser, tns->agg, cns);
        }
        
        ArgusDeleteRecordStruct(parser, cns);
    }
    
#if defined(ARGUSDEBUG)
    ArgusDebug (6, "ArgusProcessICMPPathRecord () returning\n");
#endif
}



char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
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
                  int rv;

                  if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
                     ArgusHtoN(argusrec);
#endif
                     rv = ArgusWriteNewLogfile (parser, argus->input, wfile,
                                                argusrec);
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
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
         struct ArgusNetspatialStruct *local = (struct ArgusNetspatialStruct *) argus->dsrs[ARGUS_LOCAL_INDEX];

         if (flow) {
            int sloc = 5, dloc = 5;
            if (local != NULL) {
               sloc = local->sloc;
               dloc = local->dloc;
            }
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        if (!retn && (agg->mask & ARGUS_MASK_SADDR_INDEX)) {
                           if (sloc < 4) {
                              int smask = flow->ip_flow.smask;
                              int atype = RaIPv4AddressType(parser, flow->ip_flow.ip_src);
                              if (atype == ARGUS_IPV4_UNICAST) {
                                 retn = RaProcessThisAddress(parser, labeler, argus, &flow->ip_flow.ip_src, smask, ARGUS_TYPE_IPV4);
                              }
                           }
                        }
                        if (!retn && (agg->mask & ARGUS_MASK_DADDR_INDEX)) {
                           if (dloc < 4) {
                              int dmask = flow->ip_flow.dmask;
                              int atype = RaIPv4AddressType(parser, flow->ip_flow.ip_dst);
                              if (atype == ARGUS_IPV4_UNICAST) {
                                 retn = RaProcessThisAddress(parser, labeler, argus, &flow->ip_flow.ip_dst, dmask, ARGUS_TYPE_IPV4);
                              }
                           }
                        }
                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        if (!retn && (agg->mask & ARGUS_MASK_SADDR_INDEX)) {
                           if (sloc < 4) {
                              int atype = RaIPv6AddressType(parser, (struct in6_addr *)&flow->ipv6_flow.ip_src);
                              if (atype == ARGUS_IPV6_UNICAST) {
                                 retn = RaProcessThisAddress(parser, labeler, argus, (unsigned int *) &flow->ipv6_flow.ip_src, 0, ARGUS_TYPE_IPV6);
                              }
                           }
                        }
                        if (!retn && (agg->mask & ARGUS_MASK_DADDR_INDEX)) {
                           if (dloc < 4) {
                              int atype = RaIPv6AddressType(parser, (struct in6_addr *)&flow->ipv6_flow.ip_dst);
                              if (atype == ARGUS_IPV6_UNICAST) {
                                 retn = RaProcessThisAddress(parser, labeler, argus, (unsigned int *) &flow->ipv6_flow.ip_dst, 0, ARGUS_TYPE_IPV6);
                              }
                           }
                        }
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


#define ARGUS_PENDING	1

#if defined(ARGUS_THREADS)
void * ArgusTraceProcess (void *);

void *
ArgusTraceProcess (void *arg)
{
   extern struct hnamemem  hnametable[HASHNAMESIZE];
   struct timespec tsbuf = {1, 0}, *ts = &tsbuf;
   sigset_t blocked_signals;
   char command[256];

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

               sprintf (command, "/usr/sbin/traceroute -w 1 -z 200 -m 32 %s", p->nname);
#ifdef ARGUSDEBUG
               ArgusDebug (1, "ArgusTraceProcess() query '%s' pending requests %d", command, ArgusParser->ArgusProcessList->count);
#endif
               if (system(command) < 0) 
                  ArgusLog(LOG_INFO, "RaTraceProcess: system error", strerror(errno));
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
