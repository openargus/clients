/*
 * Argus Software
 * Copyright (c) 2000-2022 QoSient, LLC
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
 * rahisto.c  - histogram tracking.
 *       
 * written by Carter Bullard
 * QoSient, LLC
 * 
 * $Id: //depot/gargoyle/clients/examples/rahisto/rahisto.c#9 $
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

#include <argus_compat.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
 
#include <rabins.h>
#include <rasplit.h>
#include <argus_sort.h>
#include <argus_cluster.h>
#include <argus_metric.h>
 
#include <signal.h>
#include <ctype.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "rahisto.h"

/* The man page claims 112 metrics are supported.  Hopefully sixteen
 * per run are enough.  Season to taste.
 */
#define RAHISTO_MAX_CONFIGS 16
 
static struct ArgusRecordStruct **RaHistoRecordsPtrs[RAHISTO_MAX_CONFIGS];
static struct ArgusAggregatorStruct *RaHistoAggregators[RAHISTO_MAX_CONFIGS];
static struct RaHistoConfigStruct *RaHistoConfigMem[RAHISTO_MAX_CONFIGS];
static int RaHistoConfigCount;
static int ArgusProcessOutLayers;
static int ArgusProcessNoZero = 0;
static int ArgusPrintInterval = 0;
static int RaValuesAreIntegers[RAHISTO_MAX_CONFIGS];
static int ArgusPerAddressHistograms;

long long RaNumberOfValues[RAHISTO_MAX_CONFIGS];
long long RaValueBufferSize[RAHISTO_MAX_CONFIGS];
double *RaValueBufferMem[RAHISTO_MAX_CONFIGS];
static int argus_version = ARGUS_VERSION;

static int RaFindModes(double *, long long, double *, int);
static int RaSortValueBuffer (const void *, const void *);

// Format is "[abs] metric bins[L][:range]" or "[abs] metric bins[:size]"
// range is value-value and size if just a single number.  Value is 
// %f[umsMHD] or %f[umKMG] depending on the type of metric used.
//
// If the format simply provides the number of bins, the range/size
// part is determined from the data.  When this occurs the routine returns
//
//    ARGUS_HISTO_RANGE_UNSPECIFIED
//
// and the program needs to determine its own range.
//
// Appropriate metrics are any metrics support for sorting.
static int
ArgusHistoMetricParse (const char * const Hstr,
                       int RaHistoConfigIndex)
{
   char *ptr, *vptr, tmpbuf[128], *tmp = tmpbuf;
   char *endptr = NULL;
   char *metric = NULL;
   int retn = 0, keyword = -1;

   struct RaHistoConfigStruct *RaHistoConfig;
   struct ArgusAggregatorStruct *agr;

   RaHistoConfig = RaHistoConfigMem[RaHistoConfigIndex];
   agr = RaHistoAggregators[RaHistoConfigIndex];

   bzero (tmpbuf, 128);
   snprintf (tmpbuf, 128, "%s", Hstr);

   if ((ptr = strstr (tmp, "abs ")) != NULL) {
      agr->AbsoluteValue++;
      tmp = ptr + 4;
   }

   if ((ptr = strchr (tmp, ' ')) != NULL) {
      int x, found = 0;
      metric = tmp;
      *ptr++ = '\0';
      tmp = ptr;

         for (x = 0; x < MAX_METRIC_ALG_TYPES; x++) {
            if (!strncmp(RaFetchAlgorithmTable[x].field, metric, strlen(metric))) {
               agr->RaMetricFetchAlgorithm = RaFetchAlgorithmTable[x].fetch;
               agr->ArgusMetricIndex = x;
               keyword = x;
               found++;
               break;
            }
         }
         if (!found)
            usage();

         if ((ptr = strchr (tmp, ':')) != NULL) {
            *ptr++ = '\0';
            vptr = ptr;

            if (strchr (tmp, 'L'))
               RaHistoConfig->RaHistoMetricLog++;

            if (isdigit((int)*tmp))
               if ((RaHistoConfig->RaHistoBins = atoi(tmp)) < 0)
                  return (retn);

// Need to add code to deal with ranges that include negative numbers
// So parse a number, then check for the -, then parse another number
// if needed.

            RaHistoConfig->RaHistoStart = strtod(vptr, &endptr);
            if (endptr == vptr)
               return (retn);

            vptr = endptr;
            if ((ptr = strchr (vptr, '-')) != NULL) {
               *ptr++ = '\0';
               RaHistoConfig->RaHistoEnd = strtod(ptr, &endptr);
               if (endptr == ptr)
                  return (retn);
            } else {
               RaHistoConfig->RaHistoBinSize = RaHistoConfig->RaHistoStart;
               RaHistoConfig->RaHistoStart = 0.0;
               RaHistoConfig->RaHistoEnd = RaHistoConfig->RaHistoBinSize * (RaHistoConfig->RaHistoBins * 1.0);
            }

            switch (*endptr) {
               case 'u': RaHistoConfig->RaHistoStart *= 0.000001;
                         RaHistoConfig->RaHistoEnd   *= 0.000001; break;
               case 'm': RaHistoConfig->RaHistoStart *= 0.001;
                         RaHistoConfig->RaHistoEnd   *= 0.001;    break;
               case 's': RaHistoConfig->RaHistoStart *= 1.0;
                         RaHistoConfig->RaHistoEnd   *= 1.0;      break;
               case 'M': {
                  switch (keyword) {
                     case ARGUSMETRICSTARTTIME:
                     case ARGUSMETRICLASTTIME:
                     case ARGUSMETRICDURATION:
                     case ARGUSMETRICMEAN:
                     case ARGUSMETRICMIN:
                     case ARGUSMETRICMAX:
                        RaHistoConfig->RaHistoStart *= 60.0;
                        RaHistoConfig->RaHistoEnd   *= 60.0;
                        break;

                     default:
                        RaHistoConfig->RaHistoStart *= 1000000.0;
                        RaHistoConfig->RaHistoEnd   *= 1000000.0;
                        break;
                  }
                  break;
               }
               case 'H': RaHistoConfig->RaHistoStart *= 3600.0;
                         RaHistoConfig->RaHistoEnd   *= 3600.0;   break;
               case 'D': RaHistoConfig->RaHistoStart *= 86400.0;
                         RaHistoConfig->RaHistoEnd   *= 86400.0;  break;
               case 'K': RaHistoConfig->RaHistoStart *= 1000.0;
                         RaHistoConfig->RaHistoEnd   *= 1000.0;  break;
               case 'G': RaHistoConfig->RaHistoStart *= 1000000000.0;
                         RaHistoConfig->RaHistoEnd   *= 1000000000.0;  break;
               case  ' ':
               case '\0': break;

               default:
                  return (retn);
            }

            retn = 1;

         } else {
            if (isdigit((int)*tmp))
               if ((RaHistoConfig->RaHistoBins = atoi(tmp)) < 0)
                  return (retn);

            retn = ARGUS_HISTO_RANGE_UNSPECIFIED;
         }

         if ((RaHistoRecordsPtrs[RaHistoConfigIndex] = (struct ArgusRecordStruct **)
              ArgusCalloc (RaHistoConfig->RaHistoBins + 2,
              sizeof(struct ArgusRecordStruct *))) != NULL) {
            RaHistoConfig->RaHistoRangeState = retn;

            if (RaHistoConfig->RaHistoMetricLog) {
               RaHistoConfig->RaHistoEndLog      = log10(RaHistoConfig->RaHistoEnd);

               if (RaHistoConfig->RaHistoStart > 0) {
                  RaHistoConfig->RaHistoStartLog = log10(RaHistoConfig->RaHistoStart);
               } else {
                  RaHistoConfig->RaHistoLogInterval = (RaHistoConfig->RaHistoEndLog/(RaHistoConfig->RaHistoBins * 1.0));
               }

               RaHistoConfig->RaHistoBinSize = (RaHistoConfig->RaHistoEndLog - RaHistoConfig->RaHistoStartLog) / RaHistoConfig->RaHistoBins * 1.0;

            } else
               RaHistoConfig->RaHistoBinSize = ((RaHistoConfig->RaHistoEnd - RaHistoConfig->RaHistoStart) * 1.0) / RaHistoConfig->RaHistoBins * 1.0;

         } else
            ArgusLog (LOG_ERR, "%s: ArgusCalloc %s\n", __func__, strerror(errno));
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "%s(RaHistoConfig=%p): returning %d \n", __func__, RaHistoConfig, retn);
#endif
   return (retn);
}

static int
ArgusHistoTallyMetric (int RaHistoConfigIndex, struct ArgusRecordStruct *ns,
                       double value)
{
   int retn = 0, i = 0;
   double start, end, bsize;
   double iptr;
   struct RaHistoConfigStruct *RaHistoConfig;
   struct ArgusAggregatorStruct *agg;
   struct ArgusRecordStruct **RaHistoRecords;

   if (ns == NULL)
       goto out;

   RaHistoConfig = RaHistoConfigMem[RaHistoConfigIndex];
   agg = RaHistoAggregators[RaHistoConfigIndex];
   RaHistoRecords = RaHistoRecordsPtrs[RaHistoConfigIndex];

   if (RaHistoConfig->RaHistoMetricLog) {
      value = log10(value);
      start = RaHistoConfig->RaHistoStartLog;
        end = RaHistoConfig->RaHistoEndLog;
   } else {
      start = RaHistoConfig->RaHistoStart;
        end = RaHistoConfig->RaHistoEnd;
   }

   if (value >= start) {
      bsize = RaHistoConfig->RaHistoBinSize;
      modf((value - start)/bsize, &iptr);

      if ((i = iptr) > RaHistoConfig->RaHistoBins)
         i = RaHistoConfig->RaHistoBins + 1;

      if (value < (end + bsize))
         i++;
   }

   if (RaHistoRecords[i] != NULL) {
      ArgusMergeRecords (agg, RaHistoRecords[i], ns);
   } else
      RaHistoRecords[i] = ArgusCopyRecordStruct(ns);

out:
#ifdef ARGUSDEBUG
   ArgusDebug (3, "%s(RaHistoConfigIndex=%d, %p): returning %d\n", __func__,
               RaHistoConfigIndex, ns, retn);
#endif
   return (retn);
}

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   parser->RaWriteOut = 0;
 
   if (!(parser->RaInitialized)) {
      int i;

      if (RaHistoConfigCount == 0)
      /* if (parser->Hstr == NULL) */
         usage();

      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;
 
      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "interval", 8)))
               ArgusPrintInterval = 1;
            if (!(strncasecmp (mode->mode, "nozero", 6)))
               ArgusProcessNoZero = 1;
            if (!(strncasecmp (mode->mode, "outlayer", 8)))
               ArgusProcessOutLayers = 1;

            mode = mode->nxt;
         }
      }

      if (ArgusParser->RaPrintOptionStrings[0] == NULL) {
         int i = 0;
         while (parser->RaPrintAlgorithmList[i] != NULL) {
           ArgusFree(parser->RaPrintAlgorithmList[i]);
           parser->RaPrintAlgorithmList[i] = NULL;
           i++;
         }
      }

      parser->nflag += 2;

      if (parser->vflag)
         ArgusReverseSortDir++;
 
      for (i = 0; i < RaHistoConfigCount; i++) {
          RaValuesAreIntegers[i] = 1;
          RaValueBufferSize[i] = 100000;
      }

      parser->RaInitialized++;
   }
}


void RaArgusInputComplete (struct ArgusInput *input) { return; }
char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];

static int
writing_records_to_stdout(struct ArgusListStruct *files)
{
   struct ArgusWfileStruct *wfile;
   struct ArgusListObjectStruct *lobj;
   int have_devstdout = 1;
   struct stat stat_devstdout;
   struct stat stat_thisfile;

   if (files == NULL)
      return 0;

   lobj = files->start;
   if (stat("/dev/stdout", &stat_devstdout) < 0)
      have_devstdout = 0;

   while (lobj) {
      wfile = (struct ArgusWfileStruct *)lobj;
      if (wfile) {
         if (wfile->filename &&
             wfile->filename[0] == '-' &&
             wfile->filename[1] == 0)
            return 1;

         if (wfile->fd &&
             (wfile->fd == stdout ||
              fileno(wfile->fd) == fileno(stdout)))
            return 1;

         if (have_devstdout &&
             wfile->filename &&
             stat(wfile->filename, &stat_thisfile) == 0 &&
             stat_devstdout.st_ino == stat_thisfile.st_ino)
            return 1;
      }
      lobj = lobj->nxt;
   }
   return 0;
}

void
RaParseComplete (int sig)
{
   struct ArgusParserStruct *parser = ArgusParser;
   struct ArgusRecordStruct *ns = NULL;
   struct ArgusAgrStruct *tagr = NULL;
   int i, freq, class = 1, start = 999999999, end = 0;
   double bs = 0.0, be = 0.0, bf = 0.0;
   float rel, relcum = 0.0;
   int i, printed;
   int _writing_records_to_stdout;
   int cid;  /* rahisto config index */

   if (sig >= 0) {
      if (!parser->RaParseCompleting++) {

         _writing_records_to_stdout =
          writing_records_to_stdout(parser->ArgusWfileList);

         if (RaHistoConfigCount > 1
             && !ArgusParser->qflag
             && ArgusParser->ArgusPrintJson)
            printf("[\n");

         for (cid = 0; cid < RaHistoConfigCount; cid++) {
            struct RaHistoConfigStruct *RaHistoConfig = RaHistoConfigMem[cid];
            struct ArgusRecordStruct **RaHistoRecords = RaHistoRecordsPtrs[cid];
            double *RaValueBuffer = RaValueBufferMem[cid];

            if (RaHistoRecords == NULL)
               continue;

            class = 1;
            printed = 0;
            ns = NULL;

            for (i = 0; i < RaHistoConfig->RaHistoBins + 2; i++) {
               struct ArgusRecordStruct *argus = RaHistoRecords[i];
               if ((!ArgusProcessOutLayers && ((i > 0) && (i <= RaHistoConfig->RaHistoBins))) || ArgusProcessOutLayers) {
                  if (argus) {
                     if (i < start) start = i;
                     if (i > end)   end   = i;
                     if (ns == NULL)
                        ns = ArgusCopyRecordStruct (argus);
                     else
                        ArgusMergeRecords (parser->ArgusAggregator, ns, argus);
                  }
               }
            }

            if (ns != NULL) {
               double start, bsize;
               char buf[MAXSTRLEN];
               if ((tagr = (void *)ns->dsrs[ARGUS_AGR_INDEX]) != NULL) {
                  if (!_writing_records_to_stdout) {
                     int len, tlen, numModes = 0, pflag = parser->pflag;
                     double modeValues[1024];
                     double median = 0.0, percentile = 0.0;
                     char *meanStr = NULL, *medianStr = NULL, *percentStr = NULL;
                     char *stdStr = NULL, *maxValStr = NULL, *minValStr = NULL;
                     char *modeStr = NULL;
                     long long ind;
                     char c;

                     sprintf (buf, "%-.*f", pflag, tagr->act.stdev);
                     stdStr = strdup(buf);

                     sprintf (buf, "%-.*f", pflag, tagr->act.meanval);
                     meanStr = strdup(buf);

                     if (RaValueBuffer != NULL) {
                        qsort (RaValueBuffer, RaNumberOfValues[cid], sizeof(double), RaSortValueBuffer);

                        if (RaNumberOfValues[cid] % 2) {
                           median = RaValueBuffer[(RaNumberOfValues[cid] + 1)/2];

                           if (RaValuesAreIntegers[cid])
                              pflag = 0;

                        } else {
                           ind = (RaNumberOfValues[cid] / 2) - 1;
                           median = (RaValueBuffer[ind] + RaValueBuffer[ind + 1]) / 2.0;
                        }

                        sprintf (buf, "%-.*f", pflag, median);
                        medianStr = strdup(buf);

                        if (RaValuesAreIntegers[cid])
                           pflag = 0;

                        ind = RaNumberOfValues[cid] * 0.95;
                        percentile = RaValueBuffer[ind];

                        sprintf (buf, "%-.*f", pflag, percentile);
                        percentStr = strdup(buf);

                        numModes = RaFindModes(RaValueBuffer, RaNumberOfValues[cid], modeValues, 1024);

                        if (numModes > 0) {
                           bzero(buf, sizeof(buf));
                           for (i = 0; i < numModes; i++) {
                              if (i > 0)
                                 sprintf(&buf[strlen(buf)], ",");
 
                              if (RaValuesAreIntegers[cid])
                                 sprintf(&buf[strlen(buf)], "%-.0f", modeValues[i]);
                              else
                                 sprintf(&buf[strlen(buf)], "%-.*f", pflag, modeValues[i]);
                           }
                           modeStr = strdup(buf);
                        }
                     }

                     sprintf (buf, "%-.*f", pflag, tagr->act.maxval);
                     maxValStr = strdup(buf);
                     sprintf (buf, "%-.*f", pflag, tagr->act.minval);
                     minValStr = strdup(buf);

                     len = strlen(meanStr);
                     if (medianStr && (len < (tlen = strlen(medianStr))))   len = tlen;
                     if (percentStr && (len < (tlen = strlen(percentStr)))) len = tlen;
                     if (stdStr && (len < (tlen = strlen(stdStr))))         len = tlen;

                     if (!ArgusParser->qflag) {
                        if (ArgusParser->ArgusPrintJson) {
                           printf ("{\n");
                           printf (" \"N\":\"%d\", \"bins\":\"%d\", \"size\": \"%.*f\", \n \"mean\": \"%s\", \"stddev\": \"%s\", \"max\": \"%s\", \"min\": \"%s\",",
                                        tagr->act.n, RaHistoConfig->RaHistoBins, pflag, RaHistoConfig->RaHistoBinSize, meanStr, stdStr, maxValStr, minValStr);
                           printf ("\n \"median\": \"%s\", \"95%%\": \"%s\", ", medianStr, percentStr);
                           if (RaHistoConfigCount > 1)
                              printf ("\"metric\": \"%s\",\n",
                                      RaFetchAlgorithmTable[RaHistoAggregators[cid]->ArgusMetricIndex].field);
                        } else {
                           if ((c = ArgusParser->RaFieldDelimiter) != '\0') {
                              printf ("N=%d%cmean=%s%cstddev=%s%cmax=%s%cmin=%s%c",
                                           tagr->act.n, c, meanStr, c, stdStr, c, maxValStr, c, minValStr, c);
                              printf ("median=%s%c95%%=%s", medianStr, c, percentStr);
                           } else {
                              printf (" N = %-6d  mean = %*s  stddev = %*s  max = %s  min = %s\n",
                                           tagr->act.n, len, meanStr, len, stdStr, maxValStr, minValStr);
                              printf ("           median = %*s     95%% = %s\n", len, medianStr, percentStr);
                              if (RaHistoConfigCount > 1)
                                 printf ("           metric = %s\n",
                                         RaFetchAlgorithmTable[RaHistoAggregators[cid]->ArgusMetricIndex].field);
                           }
                        }

                        if (numModes > 0) {
                           int tlen = strlen(modeStr);
                           if (tlen > len)
                              len = tlen;

                           if (ArgusParser->ArgusPrintJson) {
                              printf(" \"mode\": [ \"%s\" ],\n", modeStr);
                           } else {
                              if ((c = ArgusParser->RaFieldDelimiter) != '\0') {
                                 printf ("%cmode=%s", c, modeStr);
                              } else
                                 printf ("             mode = %*s\n", len, modeStr);

                              if ((c = ArgusParser->RaFieldDelimiter) != '\0')
                                 printf ("\n");
                           }
                        }
                     }

                     if (stdStr)     free(stdStr);
                     if (meanStr)    free(meanStr);
                     if (medianStr)  free(medianStr);
                     if (percentStr) free(percentStr);
                     if (maxValStr)  free(maxValStr);
                     if (minValStr)  free(minValStr);
                     if (modeStr)    free(modeStr);
                  }
               }

               if (!ArgusParser->ArgusPrintJson && !_writing_records_to_stdout) {
                  if (ArgusParser->RaLabel == NULL) {
                     char rangeval[32], rangebuf[128], c;
                     int size = 0, rblen = 0;

                     size = parser->pflag > 16 ? 16 : parser->pflag;
                     snprintf (rangeval, 32, "%*.*e", size, size, be);

                     if (ArgusPrintInterval) 
                        snprintf (rangebuf, 128, "%s-%s ", rangeval, rangeval);
                     else
                        snprintf (rangebuf, 128, "%s ", rangeval);

                        rblen = ((strlen(rangebuf) - strlen("Interval"))/4) * 2;

                        ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, ns);

                        if ((c = ArgusParser->RaFieldDelimiter) != '\0') {
                           printf ("Class%cInterval%cFreq%cRel.Freq%cCum.Freq", c, c, c, c);
                           if (ArgusParser->RaLabel && strlen(ArgusParser->RaLabel)) {
                              printf ("%c%s\n", c, ArgusParser->RaLabel);
                           } else
                              printf ("\n");
                        } else {
                           if (ArgusPrintInterval)
                              printf (" Class     %*.*s%s%*.*s       Freq    Rel.Freq     Cum.Freq    %s\n",
                                   rblen, rblen, " ", "Interval", rblen, rblen, " ", ArgusParser->RaLabel);
                           else
                              printf (" Class    %*.*s%s%*.*s       Freq    Rel.Freq     Cum.Freq    %s\n",
                                   rblen, rblen, " ", "Interval", rblen, rblen, " ", ArgusParser->RaLabel);
                        }
                     }

                     if (ArgusParser->ArgusPrintJson)
                        printf (" \"values\": [\n");
                  }
               }

               if (RaHistoConfig->RaHistoMetricLog) {
                  start = RaHistoConfig->RaHistoStartLog;
               } else {
                  start = RaHistoConfig->RaHistoStart;
               }
               bsize = RaHistoConfig->RaHistoBinSize;

               for (i = 0; i < RaHistoConfig->RaHistoBins + 2; i++) {
                  struct ArgusRecordStruct *argus = RaHistoRecords[i];

                  if (i == 0) {
                     bs = -HUGE_VAL;
                     be = start;
                     if (RaHistoConfig->RaHistoMetricLog)
                        be = (be > 0 ) ? pow(10.0, be) : 0;

                  } else {
                     bs = (start + ((i - 1) * bsize));
                     if (i > RaHistoConfig->RaHistoBins) {
                        be = bs;
                     } else {
                        be = (start +  (i * bsize));
                     }
                     if (RaHistoConfig->RaHistoMetricLog) {
                        bs = (bs > 0 ) ? pow(10.0, bs) : 0;
                        be = pow(10.0, be);
                     }
                  }

                  if ((!ArgusProcessOutLayers && ((i > 0) && (i <= RaHistoConfig->RaHistoBins))) || ArgusProcessOutLayers) {
                     if (!ArgusProcessNoZero || (ArgusProcessNoZero && ((i >= start) && (i <= end)))) {
                        if (parser->ArgusWfileList != NULL) {
                           if (argus) {
                              struct ArgusTimeObject *time = NULL;
                              struct ArgusWfileStruct *wfile = NULL;
                              struct ArgusListObjectStruct *lobj = NULL;
                              int i, count = parser->ArgusWfileList->count;
                              double value, frac;

                              if ((time = (void *)argus->dsrs[ARGUS_TIME_INDEX]) != NULL) {
                                 frac = modf(bs, &value);
                                 time->src.start.tv_sec  = value;
                                 time->src.start.tv_usec = frac * 1000000;

                                 frac = modf(be, &value);
                                 time->src.end.tv_sec    = value;
                                 time->src.end.tv_usec   = frac * 1000000;
                                 time->hdr.subtype       = ARGUS_TIME_RELATIVE_TIMESTAMP;
                              }

                              if ((lobj = parser->ArgusWfileList->start) != NULL) {
                                 for (i = 0; i < count; i++) {
                                    if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                                       int pass = 1;
                                       if (wfile->filterstr) {
                                          struct nff_insn *wfcode = wfile->filter.bf_insns;
                                          pass = ArgusFilterRecord (wfcode, argus);
                                       }

                                       if (pass != 0) {
                                          if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                                             struct ArgusRecord *argusrec = NULL;
                                             if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
                                                ArgusHtoN(argusrec);
#endif
                                                ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                                             }
                                          }
                                       }
                                    }

                                    lobj = lobj->nxt;
                                 }
                              }
                           }

                        }

                        if (!_writing_records_to_stdout &&
                            !parser->qflag) {
                           int printThis = 0, size = parser->pflag;

                           bzero(buf, MAXSTRLEN);
                           freq = 0; rel = 0.0;

                           if (argus != NULL) {
                              struct ArgusAgrStruct *agr = (void *)argus->dsrs[ARGUS_AGR_INDEX];
                              char *sptr;
                              int slen;

                              if (agr != NULL) {
                                 freq =  agr->count;
                                 rel  = (agr->count * 1.0)/(tagr->act.n * 1.0);
                              } else {
                                 freq = 1;
                                 rel  = 1.0/(tagr->act.n * 1.0);
                              }

                              ArgusPrintRecord (parser, buf, argus, MAXSTRLEN);
                              slen = strlen(buf);

                              relcum += rel;

                                 memmove(buf, sptr, slen);
                              }

                              cum    += freq;
                              relcum += rel;

                              if (i > RaHistoConfig->RaHistoBins) {
                                 if (argus && (agr && (agr->count > 0))) {
                                    bf = be;
                                    do {
                                       if (RaHistoConfig->RaHistoMetricLog)
                                          bf += pow(10.0, RaHistoConfig->RaHistoBinSize);
                                       else
                                          bf += RaHistoConfig->RaHistoBinSize;
                                    } while (!(bf >= agr->act.maxval));

                                    printThis++;
                                 }

                              } else {
                                 if (!ArgusProcessNoZero || (ArgusProcessNoZero && (freq > 0.0))) {
                                    if (i == 0) {
                                       if (be != bs)
                                          printThis++;
                                    } else
                                       printThis++;
                                 }
                              }
                           } else {
                              if (!ArgusProcessNoZero) {
                                 printThis++;
                              }
                           }

                           if (printThis) {
                              if (ArgusParser->ArgusPrintJson) {
                                 if (printed++ > 0)
                                    printf (",\n");
                                 if (strlen(buf))
                                    printf ("   {\"Class\": \"%d\", \"Interval\": \"%*.*e\", \"Freq\": \"%d\", \"Rel.Freq\": \"%8.4f\", \"Cum.Freq\": \"%8.4f\", %s }",
                                                   class++, size, size, bs, freq, rel * 100.0, relcum * 100.0, buf);
                                 else
                                    printf ("   {\"Class\": \"%d\", \"Interval\": \"%*.*e\", \"Freq\": \"%d\", \"Rel.Freq\": \"%8.4f\", \"Cum.Freq\": \"%8.4f\" }",
                                                   class++, size, size, bs, freq, rel * 100.0, relcum * 100.0);
                              } else {
                                 char c;
                                 if ((c = ArgusParser->RaFieldDelimiter) != '\0') {
                                    if (ArgusPrintInterval) {
                                       printf ("%d%c%e-%e%c%d%c%f%%%c%f%%",
                                             class++, c, bs, be, c, freq, c, rel * 100.0, c, relcum * 100.0);
                                    } else {
                                       printf ("%d%c%e%c%d%c%f%%%c%f%%",
                                             class++, c, bs, c, freq, c, rel * 100.0, c, relcum * 100.0);
                                    }
                                    if (strlen(buf)) {
                                       printf ("%c%s\n", c, buf);
                                    } else
                                       printf ("\n");
                                 } else {
                                    if (ArgusPrintInterval) {
                                       printf ("%6d   % *.*e-%*.*e %10d   %8.4f%%    %8.4f%%    %s\n",
                                             class++, size, size, bs, size, size, be, freq, rel * 100.0, relcum * 100.0, buf);
                                    } else {
                                       printf ("%6d   % *.*e %10d   %8.4f%%    %8.4f%%    %s\n",
                                             class++, size, size, bs, freq, rel * 100.0, relcum * 100.0, buf);
                                    }
                                 }
                              }
                           }
                        }
                     }
                  }
               }

               if (!ArgusParser->qflag) {
                  if (ArgusParser->ArgusPrintJson) {
                     printf("\n  ]\n}");
                     if (RaHistoConfigCount > 1)
                         printf("%s", cid < (RaHistoConfigCount-1) ? "," : "");
                  }
                  printf("\n");
               }

               ArgusDeleteRecordStruct(ArgusParser, ns);
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

         if (RaHistoConfigCount > 1
             && !ArgusParser->qflag
             && ArgusParser->ArgusPrintJson)
            printf("]\n");
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

   fprintf (stdout, "Rahisto Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [raoptions] -H metric bins[L]:[range | size]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -H metric bins[L][:(range | size)] \n");
   fprintf (stdout, "            metric - any metric in argus data record\n");
   fprintf (stdout, "              bins - number of bins to use in histogram\n");
   fprintf (stdout, "               [L] - optionally specify logorithmic bin sizes\n");
   fprintf (stdout, "             range - minimum and maxium values for histogram bins\n");
   fprintf (stdout, "                syntax:  value-value\n");
   fprintf (stdout, "                         value = %%f[umsMHD] | %%f[umKMG] depending on metric type\n");
   fprintf (stdout, "              size - single numeric for size of each bin\n");
   fprintf (stdout, "\n");
   fprintf (stdout, "         -M [nozero | outlayer]\n");
   fprintf (stdout, "             nozero - don't print bins that have zero frequency\n");
   fprintf (stdout, "           outlayer - accumlate bins that are outside bin range\n");

#if defined (ARGUSDEBUG)
   fprintf (stdout, "         -D <level>         specify debug level\n");
#endif
   fflush (stdout);

   exit(1);
}




static int
RaSortValueBuffer (const void *item1, const void *item2)
{
   double b1 = *(double *) item1;
   double b2 = *(double *) item2;
   int retn = (b1 > b2) ? 1 : ((b1 == b2) ? 0 : -1);
   return (retn);
}


void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         int i;

         for (i = 0; i < RaHistoConfigCount; i++) {

         struct ArgusAggregatorStruct *agg;
         struct RaHistoConfigStruct *RaHistoConfig;
         double *RaValueBuffer;

         agg = RaHistoAggregators[i];
         RaHistoConfig = RaHistoConfigMem[i];
         RaValueBuffer = RaValueBufferMem[i];

         switch (RaHistoConfig->ArgusPassNum)  {
            case 2: {
               if (RaHistoConfig->RaHistoRangeState & ARGUS_HISTO_RANGE_UNSPECIFIED) {
                  if (agg && (agg->RaMetricFetchAlgorithm != NULL)) {
                     double frac, value, inte;
                     value = agg->RaMetricFetchAlgorithm(argus);
                     if (agg->AbsoluteValue) value = fabs(value);

                     if ((frac = modf(value, &inte)) != 0.0)
                         RaValuesAreIntegers[i] = 0;

                     if (RaValueBufferMem[i] == NULL) {
                        if ((RaValueBufferMem[i] = malloc(sizeof(double) * RaValueBufferSize[i])) == NULL)
                           ArgusLog (LOG_ERR, "RaProcessRecord: malloc error %s", strerror(errno));
                     } else {
                        if (RaNumberOfValues[i] >= RaValueBufferSize[i]) {
                           RaValueBufferSize[i] += 100000;
                           if ((RaValueBufferMem[i] = realloc(RaValueBuffer, sizeof(double) * RaValueBufferSize[i])) == NULL)
                              ArgusLog (LOG_ERR, "RaProcessRecord: realloc error %s", strerror(errno));
                        }
                     }

                     RaValueBuffer = RaValueBufferMem[i];
                     RaValueBuffer[RaNumberOfValues[i]++] = value;

                     if (RaHistoConfig->RaHistoStart > value)
                        RaHistoConfig->RaHistoStart = value;

                     if (RaHistoConfig->RaHistoEnd < value)
                        RaHistoConfig->RaHistoEnd = value;
                  }
               }
               break;
            }

            case 1: {
               double range, value, frac, inte;

               if (RaHistoConfig->RaHistoRangeState & ARGUS_HISTO_RANGE_UNSPECIFIED) {
                  int cycle = 0;

                  RaHistoConfig->RaHistoRangeState &= ~ARGUS_HISTO_RANGE_UNSPECIFIED;

                  if (RaHistoConfig->RaHistoStart > 0)
                     RaHistoConfig->RaHistoStart = 0.0;

                  if ((value = (RaHistoConfig->RaHistoEnd - RaHistoConfig->RaHistoStart) / (RaHistoConfig->RaHistoBins * 1.0)) > 0) {
                     while (value < 10.0) {
                        value *= 10.0;
                        cycle++;
                     }
                  }

                  if ((frac = modf(value, &range)) != 0.0) 
                     range += 1.0;

                  RaHistoConfig->RaHistoEnd = range * RaHistoConfig->RaHistoBins;
                  while (cycle > 0) {
                     RaHistoConfig->RaHistoEnd /= 10.0;
                     cycle--;
                  }

                  RaHistoConfig->RaHistoBinSize = ((RaHistoConfig->RaHistoEnd - RaHistoConfig->RaHistoStart) * 1.0) / RaHistoConfig->RaHistoBins * 1.0;
               }

               value = agg->RaMetricFetchAlgorithm(argus);
               if (agg->AbsoluteValue) value = fabs(value);

               if (RaHistoConfig->RaHistoRangeState & ARGUS_HISTO_CAPTURE_VALUES) {
                     if ((value >= RaHistoConfig->RaHistoStart) && (value <= RaHistoConfig->RaHistoEnd)) {
                        if ((frac = modf(value, &inte)) != 0.0)
                            RaValuesAreIntegers[i] = 0;

                        if (RaValueBufferMem[i] == NULL) {
                           if ((RaValueBufferMem[i] = malloc(sizeof(double) * RaValueBufferSize[i])) == NULL)
                              ArgusLog (LOG_ERR, "RaProcessRecord: malloc error %s", strerror(errno));
                        } else {
                           if (RaNumberOfValues[i] >= RaValueBufferSize[i]) {
                              RaValueBufferSize[i] += 100000;
                              if ((RaValueBufferMem[i] = realloc(RaValueBuffer, sizeof(double) * RaValueBufferSize[i])) == NULL)
                                 ArgusLog (LOG_ERR, "RaProcessRecord: realloc error %s", strerror(errno));
                           }
                        }

                     RaValueBuffer = RaValueBufferMem[i];
                     RaValueBuffer[RaNumberOfValues[i]++] = value;
                  }
               }

               if (agg) {
                  struct ArgusAgrStruct *agr = (void *)argus->dsrs[ARGUS_AGR_INDEX];

                  if (agr) {
                     agr->hdr.subtype  = 0x01;
                     agr->count        = 1;
                     agr->act.maxval   = value;
                     agr->act.minval   = value;
                     agr->act.meanval  = value;
                     agr->act.n        = 1;
                     agr->act.stdev    = 0;

                     agr->idle.maxval  = 0;
                     agr->idle.minval  = 0;
                     agr->idle.meanval = 0;
                     agr->idle.n       = 0;
                     agr->idle.stdev   = 0;
                  }
               }

               if (agg && (agg->RaMetricFetchAlgorithm != NULL))
                  ArgusHistoTallyMetric (i, argus, value);
               break;
            }
         }
      }
      }
   }
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}


static int
RaFindModes(double *buf, long long num, double *modeValues, int len)
{
   int retn = 0;
   double value = -1;
   int i, x, winner = 2;
   int count = 0;

   for (i = 0; i < num; i++) {
      if (buf[i] == value) 
         count++;
      else {
         if (count > winner) {
            for (x = 0; x < retn; x++)
               modeValues[x] = 0;
            winner = count;
            retn = 0;
            modeValues[retn++] = value;
         } else
         if (count && (count == winner)) {
            modeValues[retn++] = value;
         }

         value = buf[i];
         count = 1;
      }
   }

   return (retn);
}



int
RaParseOptHStr(const char *const Hstr) {
   int retn;
   struct RaHistoConfigStruct *RaHistoConfig;

   if (!Hstr)
      return 0;

   RaHistoAggregators[RaHistoConfigCount] =
    ArgusNewAggregator(ArgusParser, NULL, ARGUS_RECORD_AGGREGATOR);
   if (RaHistoAggregators[RaHistoConfigCount] == NULL)
      ArgusLog (LOG_ERR, "%s: ArgusNewAggregator error", __func__);

   RaHistoConfigMem[RaHistoConfigCount] = ArgusCalloc(1, sizeof(*RaHistoConfigMem[0]));
   if (RaHistoConfigMem[RaHistoConfigCount] == NULL)
      ArgusLog (LOG_ERR, "%s: unable to allocate config structure", __func__);
   RaHistoConfig = RaHistoConfigMem[RaHistoConfigCount];

   if (!(retn = ArgusHistoMetricParse (Hstr, RaHistoConfigCount)))
      usage ();

   RaHistoConfig->ArgusPassNum = 1;
   RaHistoConfigCount++;

   switch (retn) {
      case ARGUS_HISTO_RANGE_UNSPECIFIED: {
         RaHistoConfig->ArgusPassNum = ArgusParser->ArgusPassNum = 2;
         RaHistoConfig->RaHistoStart =  HUGE_VAL;
         RaHistoConfig->RaHistoEnd   = -HUGE_VAL;
         break;
      }

      default:
         RaHistoConfig->RaHistoRangeState |= ARGUS_HISTO_CAPTURE_VALUES;
         break;
   }
   return 1;
}

int
RaOnePassComplete(void) {
   int i;

   for (i = 0; i < RaHistoConfigCount; i++) {
       struct RaHistoConfigStruct *RaHistoConfig;

       RaHistoConfig = RaHistoConfigMem[i];
       RaHistoConfig->ArgusPassNum--;
   }
   return 1;
}

/**** What to do with binary output file when multiple metrics? *****/
