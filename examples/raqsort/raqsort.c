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
 */

/*
 * $Id: //depot/gargoyle/clients/examples/raqsort/raqsort.c#6 $
 * $DateTime: 2016/11/07 12:39:19 $
 * $Change: 3240 $
 */

/*
 * raqsort.c  - sort argus records based on various fields.
 * This is an experimental effort around flow data processing - sorting.
 * 
 * Generally, we want to work with very large files, and so reading
 * in the complete set of data, and sorting the records in memory, and
 * then writing those records out, (the algorithm used by rasort.1) doesn't
 * scale with file size and nodal resources.
 * 
 * In this example we investigate "external sorting" as defined by Knuth,
 * where the data records are not in internal memory, but are left extant
 * to the algorithmic context.
 * 
 * So, here we are first going to do a system that generates an offset list
 * that represents the sorted file.  We don't have to write out the sorted
 * file, we can write the list of offsets, and squirrel that away if that
 * is a good thing.
 * 
 * Using basically rasort.1 and rahisto.1 types of processing, we'll support
 * a "-m field(s)" like option to support multi-key sorting strategies, based
 * on ArgusFetchAlgorithmTable[x] lookup mechanisms.  This can support everything
 * except strings, array values, and IPv6 addresses.
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
#include <argus_metric.h>

#include <signal.h>
#include <ctype.h>

struct ArgusQsortStruct {
   struct ArgusQueueHeader qhdr;
   unsigned long long offset, len;
   double value[];
};

int ArgusQsortRoutine (const void *, const void *);
void ArgusQsortQueue (struct ArgusSorterStruct *, struct ArgusQueueStruct *);

double *RaLastInputValue = NULL;
int RaRunNumber = 0;
int ArgusSecondPass = 0;

int RaPrintCounter = 0;

static int argus_version = ARGUS_VERSION;

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

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      parser->RaWriteOut = 0;

      if (parser->vflag)
         ArgusReverseSortDir++;

      if ((ArgusSorter = ArgusNewSorter(parser)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit ArgusNewSorter error %s", strerror(errno));

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strcmp ("replace", mode->mode))) {
               ArgusProcessFileIndependantly = 1;
               ArgusSorter->ArgusReplaceMode++;
            } else
            if (!(strncasecmp (mode->mode, "oui", 3))) {
               parser->ArgusPrintEthernetVendors++;
            }
 
            mode = mode->nxt;
         }
      }

      ArgusSorter->ArgusFetchAlgorithms[0] = ArgusFetchStartTime;
      ArgusSorter->ArgusFetchAlgNumber = 1;

      if (parser->RaSortOptionIndex > 0) {
         for (i = 0; i < parser->RaSortOptionIndex; i++) {
            char *str = parser->RaSortOptionStrings[0];
            for (x = 0; x < MAX_METRIC_ALG_TYPES; x++) {
               if (!strncmp (RaFetchAlgorithmTable[x].field, str, strlen(str))) {
                  ArgusSorter->ArgusFetchAlgorithms[i] = RaFetchAlgorithmTable[x].fetch;
                  ArgusSorter->ArgusFetchAlgNumber = i + 1;
               }
            }
         }
      }

      if ((mode = parser->ArgusMaskList) != NULL) {
         bzero(ArgusSorter->ArgusFetchAlgorithms, sizeof(ArgusSorter->ArgusFetchAlgorithms));
         ArgusSorter->ArgusFetchAlgNumber = 0;
         i = 0;
         while (mode) {
            for (x = 0; x < MAX_METRIC_ALG_TYPES; x++) {
               if (!strncmp (RaFetchAlgorithmTable[x].field, mode->mode, strlen(mode->mode))) {
                  ArgusSorter->ArgusFetchAlgorithms[i++] = RaFetchAlgorithmTable[x].fetch;
                  ArgusSorter->ArgusFetchAlgNumber = i;
/*
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
*/
                  break;
               }
            }

            if (x == MAX_METRIC_ALG_TYPES)
               ArgusLog (LOG_ERR, "sort syntax error. \'%s\' not supported", mode->mode);

            mode = mode->nxt;
         }
      }

      parser->ArgusPassNum = 2;
      parser->RaParseCompleting = 0;
      parser->RaInitialized++;
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
}



int
ArgusQsortRoutine (const void *void1, const void *void2)
{
   int retn = 0, i = 0;
   struct ArgusQsortStruct *ns1 = *(struct ArgusQsortStruct **)void1;
   struct ArgusQsortStruct *ns2 = *(struct ArgusQsortStruct **)void2;
   double t1 = 0.0, t2 = 0.0;

   for (i = 0; i < ArgusSorter->ArgusFetchAlgNumber; i++) {
      if (ns1) t1 = ns1->value[i];
      if (ns2) t2 = ns2->value[i];
      retn = (t1 > t2) ? 1 : ((t1 == t2) ? 0 : -1);
      if (retn != 0)
         break;
   }

   return (ArgusReverseSortDir ? ((retn > 0) ? -1 : ((retn == 0) ? 0 : 1)) : retn);
}

void
ArgusQsortQueue (struct ArgusSorterStruct *sorter, struct ArgusQueueStruct *queue)
{
   int cnt, i;

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&queue->lock);
#endif

   if (queue->array != NULL) {
      ArgusFree(queue->array);
      queue->array = NULL;
   }

   if ((cnt = queue->count) > 1) {
      if ((queue->array = (struct ArgusQueueHeader **) ArgusMalloc(sizeof(struct ArgusQueueHeader *) * (cnt + 1))) != NULL) {
         struct ArgusQsortStruct *tqs = NULL;

         for (i = 0; i < cnt; i++)
            queue->array[i] = ArgusPopQueue(queue, ARGUS_NOLOCK);
         queue->array[i] = NULL;

         qsort ((char *) queue->array, cnt, sizeof (struct ArgusQueueHeader *), ArgusQsortRoutine);

         for (i = 0; i < cnt; i++) {
            struct ArgusQsortStruct *qs = (struct ArgusQsortStruct *) ArgusSorter->ArgusRecordQueue->array[i];

            if (tqs == NULL) {
               if ((tqs = ArgusCalloc(1, sizeof(struct ArgusQsortStruct) + ArgusSorter->ArgusFetchAlgNumber*sizeof(double))) != NULL) {
                  tqs->value[0] = qs->value[0];
                  tqs->offset   = qs->offset;
                  tqs->len      = qs->len;
               } else
                  ArgusLog (LOG_ERR, "ArgusQsortQueue: ArgusCalloc %s\n", strerror(errno));

            } else {
               if (qs->offset == tqs->offset + tqs->len) {
                  tqs->len += qs->len;
               } else {
                  ArgusAddToQueue (queue, &tqs->qhdr, ARGUS_NOLOCK);

                  if ((tqs = ArgusCalloc(1, sizeof(struct ArgusQsortStruct) + ArgusSorter->ArgusFetchAlgNumber*sizeof(double))) != NULL) {
                     tqs->value[0] = qs->value[0];
                     tqs->offset   = qs->offset;
                     tqs->len      = qs->len;

                  } else
                     ArgusLog (LOG_ERR, "ArgusQsortQueue: ArgusCalloc %s\n", strerror(errno));
               }
            }

            ArgusFree(qs);
            ArgusSorter->ArgusRecordQueue->array[i] = NULL;
         }

         ArgusAddToQueue (queue, &tqs->qhdr, ARGUS_NOLOCK);
         ArgusFree(queue->array);
         queue->array = NULL;

#ifdef ARGUSDEBUG
         if ((cnt = queue->count) > 1) {
            char outputbuf[256];
            ArgusDebug (1, "RaQsort processing %d runs and %d blocks", RaRunNumber, cnt);
            for (i = 0; i < cnt; i++) {
               tqs = (struct ArgusQsortStruct *)ArgusPopQueue(queue, ARGUS_NOLOCK);
               snprintf (outputbuf, 256, "value %f offset %llu - %llu\n", tqs->value[0], tqs->offset, tqs->offset + tqs->len);
               ArgusDebug (2, "%s", outputbuf);
               ArgusAddToQueue (queue, &tqs->qhdr, ARGUS_NOLOCK);
            }
         } else
            ArgusDebug (1, "file sorted, no modifications");
#endif
      } else
         ArgusLog (LOG_ERR, "ArgusQsortQueue: ArgusMalloc %s\n", strerror(errno));
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&queue->lock);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusQsortQueue(%p) returned\n", queue);
#endif
}


void
RaParseComplete (int sig)
{
   struct ArgusInput *input = NULL;
   struct ArgusFileInput *file = NULL;
   int label, have_input = 0, alloc_input = 0;
   char *buf = ArgusCalloc(1, MAXSTRLEN);

   if ((input = ArgusParser->ArgusCurrentFile) == NULL) {
      file = ArgusParser->ArgusInputFileList;

      if (file) {
         input = ArgusMalloc(sizeof(*input));
         if (input == NULL)
            ArgusLog(LOG_ERR, "unable to allocate input structure\n");

         ArgusInputFromFile(input, file);
         alloc_input = 1;
      }
   }

   if (input || file)
      have_input = 1;

   ArgusParser->ArgusCurrentInput = input;

   if (sig >= 0) {
      if (!(ArgusParser->RaParseCompleting++)) {
         ArgusParser->RaParseCompleting += sig;

         if (ArgusParser->ArgusPrintJson)
            fprintf (stdout, "\n");

         if (ArgusSorter->ArgusReplaceMode && have_input) {
            if (!(ArgusParser->ArgusRandomSeed))
               srandom(ArgusParser->ArgusRandomSeed);

            srandom (ArgusParser->ArgusRealTime.tv_usec);
            label = random() % 100000;

            snprintf (buf, MAXSTRLEN, "%s.tmp%d", input->filename, label);

            setArgusWfile(ArgusParser, buf, NULL);
         }

         if (ArgusSorter->ArgusRecordQueue->count > 0) {
            ArgusQsortQueue(ArgusSorter, ArgusSorter->ArgusRecordQueue);
            ArgusSecondPass = 1;

            if (have_input) {
               if (input->file == NULL) {
                  struct ArgusQsortStruct *qs;

                  ArgusParseInit(ArgusParser, input);

                  if ((input->file = fopen (input->filename, "r")) == NULL)
                     ArgusLog (LOG_ERR, "ArgusQsortQueue: fopen %s\n", strerror(errno));

                  while ((qs = (struct ArgusQsortStruct *)ArgusPopQueue(ArgusSorter->ArgusRecordQueue, ARGUS_NOLOCK)) != NULL) {
                     input->offset = qs->offset;
                     input->ostart = qs->offset;
                     input->ostop  = qs->offset + qs->len;
                     if (fseek(input->file, input->offset, SEEK_SET) >= 0) {
                        int done = 0;
      	             while (!done) {
                        done = ArgusReadStreamSocket (ArgusParser, input);
                        }
                     }
                     input->ArgusReadSocketCnt = 0;
                     input->ArgusReadSocketSize = 0;
                  }
               }
            }
         }
      }

      if (ArgusSorter->ArgusReplaceMode && have_input) {
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
               ArgusLog(LOG_INFO, "file %s aggregated", input->filename);
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

   ArgusFree(buf);
   if (alloc_input)
      ArgusFree(input);
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
             
   fprintf (stderr, "Rasort Version %s\n", version);
   fprintf (stderr, "usage: %s [[-M mode] [-m sortfield] ...] [ra-options] [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stderr, "options:    -M replace         replace the original file with the sorted output.\n");
   fprintf (stderr, "            -m <sortfield>     specify the <sortfield>(s) in order.\n");
   fprintf (stderr, "                               valid sorfields are:\n");
   fprintf (stderr, "                                  stime, ltime, trans, dur, avgdur, mindur,\n");
   fprintf (stderr, "                                  maxdur, smac, dmac, saddr[/cidr], daddr[/cidr], \n");
   fprintf (stderr, "                                  proto, sport, dport, stos, dtos, sttl, dttl,\n");
   fprintf (stderr, "                                  bytes, sbytes, dbytes, pkts, spkts, dpkts, load,\n"); 
   fprintf (stderr, "                                  sload, sload, dload, loss, sloss, dloss,\n"); 
   fprintf (stderr, "                                  ploss, psloss, pdloss, rate, srate, drate,\n"); 
   fprintf (stderr, "                                  seq, smpls, dmpls, svlan, dvlan, srcid,\n");
   fprintf (stderr, "                                  stcpb, dtcpb, tcprtt, smeansz, dmeansz\n"); 
   fprintf (stderr, "\n"); 
   fprintf (stderr, "ra-options: -b                 dump packet-matching code.\n");
   fprintf (stderr, "            -C <[host]:<port>  specify remote Cisco Netflow source.\n");
   fprintf (stderr, "                               source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stderr, "            -D <level>         specify debug level\n");
#endif
   fprintf (stderr, "            -F <conffile>      read configuration from <conffile>.\n");
   fprintf (stderr, "            -h                 print help.\n");
   fprintf (stderr, "            -r <file>          read argus data <file>. '-' denotes stdin.\n");
   fprintf (stderr, "            -s [-][+[#]]field  specify fields to print.\n");
   fprintf (stderr, "            -S <host[:port]>   specify remote argus <host> and optional port\n");
   fprintf (stderr, "                               number.\n");
   fprintf (stderr, "            -t <timerange>     specify <timerange> for reading records.\n");
   fprintf (stderr, "                      format:  timeSpecification[-timeSpecification]\n");
   fprintf (stderr, "                               timeSpecification: [mm/dd[/yy].]hh[:mm[:ss]]\n");
   fprintf (stderr, "                                                   mm/dd[/yy]\n");
   fprintf (stderr, "                                                   -%%d{yMhdms}\n");
   fprintf (stderr, "            -T <secs>          attach to remote server for T seconds.\n");
#ifdef ARGUS_SASL
   fprintf (stderr, "            -U <user/auth>     specify <user/auth> authentication information.\n");
#endif
   fprintf (stderr, "            -w <file>          write output to <file>. '-' denotes stdout.\n");
   exit(1);
}


char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];


void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   static char buf[MAXSTRLEN];

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_MAR: {
         break;
      }

      case ARGUS_EVENT:
      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         if (!(ArgusSecondPass)) {
            struct ArgusQsortStruct *obj = NULL;

            if ((obj = ArgusCalloc(1, sizeof(struct ArgusQsortStruct) + ArgusSorter->ArgusFetchAlgNumber*sizeof(double))) != NULL) {
               int i;
               for (i = 0; i < ArgusSorter->ArgusFetchAlgNumber; i++)
                  obj->value[i] = ArgusSorter->ArgusFetchAlgorithms[i](ns);

               obj->offset = ns->offset;
               obj->len = ns->hdr.len * 4;
               ArgusAddToQueue (ArgusSorter->ArgusRecordQueue, &obj->qhdr, ARGUS_NOLOCK);

               if (RaLastInputValue != NULL) {
                  for (i = 0; i < ArgusSorter->ArgusFetchAlgNumber; i++) {
                     double lvalue, rvalue;
                     if (!(ArgusReverseSortDir)) {
                        lvalue = RaLastInputValue[i];
                        rvalue = obj->value[i];
                     } else {
                        rvalue = RaLastInputValue[i];
                        lvalue = obj->value[i];
                     }

                     if (lvalue < rvalue)
                        break;
                     if (lvalue == rvalue) 
                        continue;
                     if (lvalue > rvalue) 
                        RaRunNumber++;
                  }
               } else {
                  if ((RaLastInputValue = (double *) ArgusCalloc(ArgusSorter->ArgusFetchAlgNumber, sizeof(double))) == NULL)
                     ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc %s\n", strerror(errno));

                  for (i = 0; i < ArgusSorter->ArgusFetchAlgNumber; i++)
                     RaLastInputValue[i] = obj->value[i];
               }
            }

         } else {
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
                        retn = ArgusFilterRecord (wfcode, ns);
                     }
      
                     if (retn != 0) {
                        if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                           struct ArgusRecord *argusrec = NULL;
                           int rv;

                           if ((argusrec = ArgusGenerateRecord (ns, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
      #ifdef _LITTLE_ENDIAN
                              ArgusHtoN(argusrec);
      #endif
                              rv = ArgusWriteNewLogfile (parser, ns->input,
                                                         wfile, argusrec);
                              if (rv < 0)
                                 ArgusLog(LOG_ERR, "%s unable to open file\n",
                                          __func__);
                           }
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
                     parser->RaLabel = ArgusGenerateLabel(parser, ns);
       
                  if (!(parser->RaLabelCounter++ % parser->Lflag))
                     if ((retn = printf ("%s\n", parser->RaLabel)) < 0) 
                        RaParseComplete (SIGQUIT);
       
                  if (parser->Lflag < 0)
                     parser->Lflag = 0;
               }
      
               bzero (buf, sizeof(buf));
               ns->rank = RaPrintCounter++;

               if ((ArgusParser->eNoflag == 0 ) || ((ArgusParser->eNoflag >= (ns->rank + 1)) && (ArgusParser->sNoflag <= (ns->rank + 1)))) {
                  ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
      
                  if ((retn = fprintf (stdout, "%s", buf)) < 0)
                     RaParseComplete (SIGQUIT);
      
                  if (parser->eflag == ARGUS_HEXDUMP) {
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
                                 if ((user = (struct ArgusDataStruct *)ns->dsrs[ARGUS_SRCUSERDATA_INDEX]) != NULL) {
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
                                 if ((user = (struct ArgusDataStruct *)ns->dsrs[ARGUS_DSTUSERDATA_INDEX]) != NULL) {
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

                  if (!(ArgusParser->ArgusPrintJson))
                     fprintf (stdout, "\n");
                  fflush (stdout);

               } else {
                  if ((ArgusParser->eNoflag != 0 ) && (ArgusParser->eNoflag < (ns->rank + 1)))
                     RaParseComplete (SIGQUIT);
               }
            }
         }
         }
         break;
      }
   }
}

int
RaSendArgusRecord(struct ArgusRecordStruct *ns)
{
   int retn = 1;

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
                     int rv;

                     if ((argusrec = ArgusGenerateRecord (ns, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        rv = ArgusWriteNewLogfile (ArgusParser, ns->input,
                                                   wfile, argusrec);
                        if (rv < 0)
                           ArgusLog(LOG_ERR, "%s unable to open file\n",
                                    __func__);
                     }
                  }
               }
            }
            lobj = lobj->nxt;
         }
      }

   } else {
      char buf[MAXSTRLEN];
      if (!ArgusParser->qflag) {
         if (ArgusParser->Lflag) {
            if (ArgusParser->RaLabel == NULL)
               ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, ns);
 
            if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag))
               printf ("%s\n", ArgusParser->RaLabel);
 
            if (ArgusParser->Lflag < 0)
               ArgusParser->Lflag = 0;
         }

         buf[0] = 0;
         ArgusPrintRecord(ArgusParser, buf, ns, MAXSTRLEN);
         if (fprintf (stdout, "%s\n", buf) < 0)
           RaParseComplete(SIGQUIT);
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

/*
 * raqsort.1 is a 2-pass program that collects the field values that are used
 * for sorting in pass 1, calculates the offset and lengths of records that need
 * to be moved, and then in pass 2, it seeks and reads the input files, to
 * create a sorted output stream.
 *
 * The core library supports multi-pass processing, through the use of the
 * counter ArgusParser->ArgusPassNum, which is 1 by default.  When the core is
 * done with the last pass of the input sources, as indicated by ArgusPassNum,
 * the core library closes all the inputs, and de-allocates all the structs.
 *
 * raqsort.1, wants to process its input files in the routine, RaParseComplete(),
 * which normally comes after processing all the input files, and any streaming
 * data input.  Because the core library currently deallocates all the input
 * file information before this routine, raqsort.1 needs to bypass this
 * core library cleanup.
 *
 * To do this, rasqsort.1 needs to provide a RaOnePassComplete() routine, which
 * is called at the end of the first pass, and set the ArgusPassNum to 0.
 * This will cause the core library to jump past the file input cleanup routines 
 * and call RaParseComplete(), leaving ArgusParser->ArgusInputFileList intact.
 *
 */

int
RaOnePassComplete(void) {
   ArgusParser->ArgusPassNum = 0;
   return 1;
}

