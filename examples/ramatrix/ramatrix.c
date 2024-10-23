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
 * ramatrix.c  - command line chord diagram matrix and data processor.
 *               This program will spit out a table and a matrix that
 *               are suitable as javascript data variables.
 *
 *               objects  = [{name:"value",color:"value"},
 *                           {name:"value",color:"value"},
 *                           . . .
 *                           {name:"value",color:"value"}];
 *
 *               The matrix is an NxN matrix (array of arrays) containing scalers.
 *
 *               matrix   = [[1,2,...,N],[1,2,...,N],...];
 *
 *               category = [[1,2,...,N],[1,2,...,N],...];
 *
 *
 *               So, we need to aggregate the data appropriately for the study,
 *               we'll use a -M option to specify which type of study this, ether, ip,
 *               net, as, service, apps, etc...  We aggregate the data to the objects
 *               and the value N, and then we'll use a printing directive to generate
 *               the ascii matrix output.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/clients/ramatrix.c#13 $
 * $DateTime: 2015/10/14 12:27:46 $
 * $Change: 3075 $
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


void ArgusIdleClientTimeout (void);

#define ARGUS_ETHER_STUDY	0
int ArgusStudy     = 0;
int ArgusNormalize = 0;
int ArgusSelfIndex = -1;
int ArgusRouterIndex = -1;

struct ArgusAggregatorStruct *ArgusMatrixAggregator = NULL;
struct ArgusAggregatorStruct *ArgusEntityAggregator = NULL;

char *RaEtherMatrixAggregationConfig[] = {
   "RACLUSTER_PRESERVE_FIELDS=yes",
   "model=\"smac dmac\"   status=0 idle=0\n",
   NULL,
};

char *RaIPMatrixAggregationConfig[] = {
   "RACLUSTER_PRESERVE_FIELDS=yes",
   "model=\"saddr daddr\" status=0 idle=0\n",
   NULL,
};

char *RaEtherEntityAggregationConfig[] = {
   "RACLUSTER_PRESERVE_FIELDS=yes",
   "model=\"smac\"         status=0 idle=0\n",
   NULL,
};

char *RaIPEntityAggregationConfig[] = {
   "RACLUSTER_PRESERVE_FIELDS=yes",
   "model=\"saddr\"         status=0 idle=0\n",
   NULL,
};

static int argus_version = ARGUS_VERSION;

extern struct enamemem elabeltable[HASHNAMESIZE];
extern char *ArgusTrimString (char *str);

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   int correct = -1, preserve = 1;
   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      char **RaEntityAggregationConfig =  NULL;
      char **RaMatrixAggregationConfig =  NULL;

      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "ether", 5)))
               ArgusStudy = ARGUS_ETHER_STUDY;
            if (!(strncasecmp (mode->mode, "normal", 6)))
               parser->ArgusNormalize++;
            if (!(strncasecmp (mode->mode, "oui", 3)))
               parser->ArgusPrintEthernetVendors = 1;

            mode = mode->nxt;
         }
      }

      ArgusGetInterfaceAddresses(parser);

      if ((parser->ArgusMaskList) == NULL)
         parser->ArgusReverse = 1;
      else
         parser->ArgusReverse = 0;

      switch (ArgusStudy) {
         default:
         case ARGUS_ETHER_STUDY:
            RaMatrixAggregationConfig = RaEtherMatrixAggregationConfig;
            RaEntityAggregationConfig = RaEtherEntityAggregationConfig;
            break;
      }

      if (parser->ArgusFlowModelFile) {
         if ((parser->ArgusLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

         RaLabelParseResourceFile (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile);
         free(parser->ArgusFlowModelFile);
         parser->ArgusFlowModelFile = NULL;
      }

      if ((parser->ArgusAggregator = ArgusParseAggregator(parser, NULL, RaMatrixAggregationConfig)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseAggregator error");

      if ((parser->ArgusPathAggregator = ArgusParseAggregator(parser, NULL, RaEntityAggregationConfig)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseAggregator error");

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

void ArgusProcessMatrix(struct ArgusParserStruct *);

/* 
 *               objects = [{name:"value", addr:"value", oui:"value",rank:"value", color:"value"},
 *                          {name:"value", addr:"value", oui:"value",rank:"value", color:"value"},
 *                          . . .
 *                          {name:"value", addr:"value", oui:"value",rank:"value", color:"value"}];
 */

#define ARGUS_MAX_OUI_COLORS	16
#define ARGUS_MAX_CATEGORIES	16

struct ArgusCategoryData {
   char *id;
   double order, score, weight;
   char *color, *label;
};

struct ArgusCategoryData categorySchemes[ARGUS_MAX_CATEGORIES] = {
   {"FAF",10.3,0,0.5,"#5E4EA1","Familiar Friendly"},
   {"FNO",10.1,0,0.5,"#4776B4","Familiar Nodes"},
   {"FBT",9,0,1,"#4D9DB4","Broadcast/Multicast Traffic"},
   {"FRC",8.3,0,0.5,"#4CC4C4","Familiar Router/Control"},
 
   {"FN",8.1,0,0.5,"#9CD6A4","UF Friendly Network"},
   {"FAP",7.3,0,0.5,"#C7F89E","UF Friendly Apps"},
   {"FP",7.1,0,0.5,"#EAF195","UF Friendly Protocols"},
   {"FA",6,0,1,"#F0F38C","UF Friendly Actions"},

   {"NIP",5,0,0.7,"#FFC704","UU Non-IP Traffic"},
   {"DT",4,0,0.6,"#FFB504","UU Discovery Traffic"},
   {"BRB",3.2,0,0.6,"#FF9E04","UU Bad Reputation Blocked"},
   {"ATS",3.1,0,0.6,"#FFA004","UU Attack Traffic Seen"},
 
   {"BAS",2.0,0,1,"#E1514B","FU Bad Actor Seen"},
   {"BAB",1.3,0,0.5,"#E32F4B","FU Bad Actor Behavior"},
   {"BRR",1.1,0,0.5,"#9E0041","FU Bad Repuation Requested"},
   {"BRA",1.1,0,0.5,"#9E0041","FU Bad Repuation Accessed"}
};


#define ARGUS_SELF_WEIGHT	2.5f
#define ARGUS_ROUTER_WEIGHT	1.5f
#define ARGUS_BROADCAST_WEIGHT	0.2f
#define ARGUS_DEFAULT_WEIGHT	1.0f
#define ARGUS_MIN_WEIGHT	0.1f

void
ArgusProcessMatrix(struct ArgusParserStruct *parser)
{
   struct ArgusAggregatorStruct *agg;
   struct ArgusRecordStruct *argus;
   struct enamemem entitytable[HASHNAMESIZE];
   int i = 0, x = 0, n = 0, nflag = ArgusParser->eNflag;

   agg = ArgusParser->ArgusPathAggregator;

   if ((n = agg->queue->count) > 1) {
      for (i = 0; i < n; i++) {
         if ((argus = (void *) ArgusPopQueue(agg->queue, ARGUS_NOLOCK)) != NULL) {
            struct ArgusMacStruct *mac = (struct ArgusMacStruct *) argus->dsrs[ARGUS_MAC_INDEX];
            if (mac != NULL) {
               ArgusAddToQueue (agg->queue, &argus->qhdr, ARGUS_NOLOCK);         // use the agg queue as an idle timeout queue
            } else {
               ArgusDeleteRecordStruct (parser, argus);
            }
         }
      }
   }

   if ((n = agg->queue->count) > 1) {
      double (*matrix)[n] = (double(*)[n])calloc(sizeof(double), n * n);
      double (*category)[n] = (double(*)[n])calloc(sizeof(double), n * n);
      int rank = 0;

      ArgusSortQueue (ArgusSorter, agg->queue, ARGUS_LOCK);
      bzero(entitytable, sizeof(entitytable));

      printf ("objects = [ ");

      for (i = 0; i < n; i++) {
         if ((argus = (struct ArgusRecordStruct *) agg->queue->array[i]) != NULL) {
            struct ArgusMacStruct *mac = (struct ArgusMacStruct *) argus->dsrs[ARGUS_MAC_INDEX];
            if (mac != NULL) {
               char addr[64], ouiaddr[64], oui[64], class[5], pcr[64];
               char *color = NULL, *category;
               struct enamemem *tp = NULL;
               argus->rank = rank++;

               bzero(addr, sizeof(addr));
               bzero(oui, sizeof(oui));
               bzero(pcr, sizeof(pcr));

	       parser->ArgusPrintEthernetVendors = 0;
               ArgusPrintSrcMacAddress(parser, addr, argus, 20);
	       parser->ArgusPrintEthernetVendors = 1;
               ArgusPrintSrcMacAddress(parser, ouiaddr, argus, 20);
               ArgusPrintSrcOui(parser, oui, argus, 20);
               ArgusPrintSrcMacClass(parser, class, argus, 5);
               ArgusPrintProducerConsumerRatio(parser, pcr, argus, 20);

               if (strstr(oui, "IPv6-Neighbor-Di") != NULL) {
                  if (parser->ArgusNormalize) {
                     char *optr = NULL;
                     strcpy(oui, "IPv6mcast");
                     if ((optr = strstr(addr, "IPv6-Nei")) != NULL) {
                        bcopy("IPv6mcas", optr, 8);
                     }
                  }
               }

               if (strstr(oui, "mcas") != NULL) {
                  category = categorySchemes[2].id;
                  x = 2;
               } else 
               if (strstr(oui, "dcas") != NULL) {
                  category = categorySchemes[2].id;
                  x = 2;
               } else {
                  x = (random() % 6);
                  category =  categorySchemes[x].id;
                  color = categorySchemes[x].color;
               }

               if (color == NULL) color = "#AAAAAA";
               if (argus->rank > 0) printf (",");

               printf ("{name:\"%s\", addr:\"%s\", oui:\"%s\", class:\"%s\", pcr:\"%s\", category:\"%s\", color:\"%s\"}", 
                         ArgusTrimString(ouiaddr), 
                         ArgusTrimString(addr), 
                         ArgusTrimString(oui),
                         ArgusTrimString(class),
                         ArgusTrimString(pcr),
                         category, color);

               if ((tp = lookup_emem (entitytable, (unsigned char *)&mac->mac.mac_union.ether.ehdr.ether_shost)) != NULL) {
                  tp->rank = argus->rank;
                  tp->category = (x > 0) ? x : 1;
               }

               if ((tp = check_emem(elabeltable, (unsigned char *)&mac->mac.mac_union.ether.ehdr.ether_shost)) != NULL) {
                  ArgusSelfIndex = argus->rank;
               }
            }
         }
      }

      printf("];\n");

      printf ("matrix = [");

      agg = ArgusParser->ArgusAggregator;
      if (agg->queue->count) {
         struct ArgusRecordStruct *argus;
         int rank = 0;

         ArgusSortQueue (ArgusSorter, agg->queue, ARGUS_LOCK);

         if (nflag == 0)
            ArgusParser->eNflag = agg->queue->arraylen;
         else
            ArgusParser->eNflag = nflag > agg->queue->arraylen ? agg->queue->arraylen : nflag;

         for (i = 0; i < agg->queue->arraylen; i++) {
            argus = (struct ArgusRecordStruct *) agg->queue->array[i];
            argus->rank = rank++;

            if (!((ArgusParser->eNoflag == 0 ) || ((ArgusParser->eNoflag >= (argus->rank + 1)) && (ArgusParser->sNoflag <= (argus->rank + 1))))) {
               agg->queue->array[i] = NULL;
               ArgusDeleteRecordStruct(ArgusParser, argus);
            }
         }

         argus = ArgusCopyRecordStruct((struct ArgusRecordStruct *) agg->queue->array[0]);
         for (i = 1; i < ArgusParser->eNflag; i++)
            if (agg->queue->array[i] != NULL)
               ArgusMergeRecords (agg, argus, (struct ArgusRecordStruct *)agg->queue->array[i]);

         ArgusParser->ns = argus;

         for (i = 0; i < parser->eNflag; i++) {
            if ((argus = (struct ArgusRecordStruct *) agg->queue->array[i]) != NULL) {
               struct ArgusMacStruct *mac = (struct ArgusMacStruct *) argus->dsrs[ARGUS_MAC_INDEX];

               if (mac != NULL) {
                  struct enamemem *stp = NULL, *dtp = NULL;
                  int x = -1, y = -1;

                  switch (mac->hdr.subtype & 0x3F) {
                     default:
                     case ARGUS_TYPE_ETHER:
                        if ((stp = check_emem(entitytable, (unsigned char *)&mac->mac.mac_union.ether.ehdr.ether_shost)) != NULL) 
                           x = stp->rank;
                        if ((dtp = check_emem(entitytable, (unsigned char *)&mac->mac.mac_union.ether.ehdr.ether_dhost)) != NULL) 
                           y = dtp->rank;
                        break;
                  }

                  if ((x >= 0) && (y >= 0)) {
                     struct ArgusMetricStruct *metric =  (void *)argus->dsrs[ARGUS_METRIC_INDEX];
                     double weight = ARGUS_DEFAULT_WEIGHT;
                     double cvalue = 0;

                     if ((stp->category == 2) || (dtp->category == 2)) {
                        weight = 3.0 / n;
                        weight = (weight < ARGUS_MIN_WEIGHT) ? ARGUS_MIN_WEIGHT : weight;
                        cvalue = 2;
                     } else {
                        if ((x == ArgusSelfIndex) || (y == ArgusSelfIndex))
                           weight = ARGUS_SELF_WEIGHT;
                        else
                           if ((x == ArgusRouterIndex) || (y == ArgusRouterIndex))
                              weight = ARGUS_ROUTER_WEIGHT;

                        cvalue = dtp->category;
                     }
                     if (metric != NULL) {
                        if (metric->src.pkts > 0) {
                           matrix[x][y] = weight;
			} else {
                           matrix[x][y] = ARGUS_MIN_WEIGHT;
			}
                        category[x][y] = cvalue;

                        if (metric->dst.pkts > 0) {
                           matrix[y][x] = weight;
                        } else {
                           matrix[y][x] = ARGUS_MIN_WEIGHT;
                        }
                        category[y][x] = cvalue;
                     }
                  }
               }
            }
         }

         for (i = 0; i < n; i++) {
            printf ("\[");
            for (x = 0; x < n; x++) {
               if (x > 0) printf (",%0.2f", matrix[i][x]);
               else       printf ("%0.2f",  matrix[i][x]);
            }
            if (i < (n -1)) printf ("],");
            else            printf ("]");
         }
      }
      printf ("];\n");

      printf ("category = [");
      for (i = 0; i < n; i++) {
         printf ("\[");
         for (x = 0; x < n; x++) {
            if (category[i][x] == 0)
               category[i][x] = 3;
            if (x > 0) printf (",%0.2f", category[i][x]);
            else       printf ("%0.2f",  category[i][x]);
         }
         if (i < (n -1)) printf ("],");
         else            printf ("]");
      }
      printf ("];\n");

      free(matrix);
      free(category);
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

   if (sig >= 0) {
      switch (sig) {
         case SIGINT:
            exit(0);
            break;
      }

      if (!(ArgusParser->RaParseCompleting++)) {
         ArgusParser->RaParseCompleting += sig;

         if (!(ArgusParser->ArgusPrintJson))
            fprintf (stdout, "\n");

         if (!(ArgusSorter))
            if ((ArgusSorter = ArgusNewSorter(ArgusParser)) == NULL)
               ArgusLog (LOG_ERR, "RaParseComplete: ArgusNewSorter error %s", strerror(errno));

         if (ArgusSorter->ArgusSortAlgorithms[0] == NULL) {
            ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortAlgorithmTable[ARGUSSORTSRCMACCLASS];
            ArgusSorter->ArgusSortAlgorithms[1] = ArgusSortAlgorithmTable[ARGUSSORTSRCMAC];
            ArgusSorter->ArgusSortAlgorithms[2] = ArgusSortAlgorithmTable[ARGUSSORTSRCPKTSCOUNT];
	 }

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

         ArgusProcessMatrix(ArgusParser);

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
   fprintf (stdout, "usage:  %s [-f ramatrix.conf]\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage:  %s [-f ramatrix.conf] [ra-options] [- filter-expression]\n\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "options:  -f <ramatrix.conf>      read aggregation rules from <ramatrix.conf>.\n");
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

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *);

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

         ArgusIdleClientTimeout();

         if (parser->ArgusNormalize) {
            parser->noflag = 1;
            RaMatrixNormalizeEtherAddrs(ns);
         }

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

         if (flow != NULL) {
            struct ArgusAggregatorStruct *agg = parser->ArgusPathAggregator;
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(ns);
            struct ArgusFlow *flow;
            int rev = parser->ArgusReverse;

            parser->ArgusReverse = 0;

            if ((flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, parser->ArgusPathAggregator, ns);

            ArgusReverseRecord(tns);

            if ((flow = (void *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, agg, tns);
            ArgusDeleteRecordStruct(parser, tns);
            parser->ArgusReverse = rev;
         }

         if (flow != NULL) {
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

            RaProcessThisRecord(parser, parser->ArgusAggregator, ns);
         }
         break;
      }
   }
}


void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusAggregatorStruct *agg, struct ArgusRecordStruct *argus)
{
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

            if (tns != NULL) {                            // found record in queue
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
                  if (agg->statusint || agg->idleint) {   // if any timers, need to flush if needed
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

               ArgusRemoveFromQueue (agg->queue, &tns->qhdr, ARGUS_LOCK);
               ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_LOCK);         // use the agg queue as an idle timeout queue

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
            if (ArgusParser->Lflag) {
               if (ArgusParser->RaLabel == NULL)
                  ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, argus);
 
               if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag))
                  printf ("%s\n", ArgusParser->RaLabel);
 
               if (ArgusParser->Lflag < 0)
                  ArgusParser->Lflag = 0;
            }

            buf[0] = 0;
            ArgusPrintRecord(ArgusParser, buf, argus, MAXSTRLEN);
            if (ArgusParser->ArgusPrintJson) {
               if (fprintf (stdout, "%s", buf) < 0)
                  RaParseComplete (SIGQUIT);
            } else {
               if (fprintf (stdout, "%s\n", buf) < 0)
                  RaParseComplete (SIGQUIT);
            }

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
