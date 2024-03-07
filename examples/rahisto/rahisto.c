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

 
struct RaBinProcessStruct *RaBinProcess = NULL;
int ArgusProcessOutLayers = 0;
int ArgusProcessNoZero = 0;
int ArgusPrintInterval = 0;
int RaValuesAreIntegers = 1;

long long RaNumberOfValues  = 0;
long long RaValueBufferSize = 100000;
double *RaValueBuffer = NULL;
static int argus_version = ARGUS_VERSION;

int RaFindModes(double *, long long, double *, int);
int RaSortValueBuffer (const void *, const void *);

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
ArgusHistoMetricParse (struct ArgusParserStruct *parser,
                       struct ArgusAggregatorStruct *agr)
{
   char *ptr, *vptr, tmpbuf[128], *tmp = tmpbuf;
   char *str = parser->Hstr, *endptr = NULL;
   char *metric = NULL;
   int retn = 0, keyword = -1;

   bzero (tmpbuf, 128);
   snprintf (tmpbuf, 128, "%s", str);

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
               parser->RaHistoMetricLog++;

            if (isdigit((int)*tmp))
               if ((parser->RaHistoBins = atoi(tmp)) < 0)
                  return (retn);

// Need to add code to deal with ranges that include negative numbers
// So parse a number, then check for the -, then parse another number
// if needed.

            parser->RaHistoStart = strtod(vptr, &endptr);
            if (endptr == vptr)
               return (retn);

            vptr = endptr;
            if ((ptr = strchr (vptr, '-')) != NULL) {
               *ptr++ = '\0';
               parser->RaHistoEnd = strtod(ptr, &endptr);
               if (endptr == ptr)
                  return (retn);
            } else {
               parser->RaHistoBinSize = parser->RaHistoStart;
               parser->RaHistoStart = 0.0;
               parser->RaHistoEnd = parser->RaHistoBinSize * (parser->RaHistoBins * 1.0);
            }

            switch (*endptr) {
               case 'u': parser->RaHistoStart *= 0.000001;
                         parser->RaHistoEnd   *= 0.000001; break;
               case 'm': parser->RaHistoStart *= 0.001;
                         parser->RaHistoEnd   *= 0.001;    break;
               case 's': parser->RaHistoStart *= 1.0;
                         parser->RaHistoEnd   *= 1.0;      break;
               case 'M': {
                  switch (keyword) {
                     case ARGUSMETRICSTARTTIME:
                     case ARGUSMETRICLASTTIME:
                     case ARGUSMETRICDURATION:
                     case ARGUSMETRICMEAN:
                     case ARGUSMETRICMIN:
                     case ARGUSMETRICMAX:
                        parser->RaHistoStart *= 60.0;
                        parser->RaHistoEnd   *= 60.0;
                        break;

                     default:
                        parser->RaHistoStart *= 1000000.0;
                        parser->RaHistoEnd   *= 1000000.0;
                        break;
                  }
                  break;
               }
               case 'H': parser->RaHistoStart *= 3600.0;
                         parser->RaHistoEnd   *= 3600.0;   break;
               case 'D': parser->RaHistoStart *= 86400.0;
                         parser->RaHistoEnd   *= 86400.0;  break;
               case 'K': parser->RaHistoStart *= 1000.0;
                         parser->RaHistoEnd   *= 1000.0;  break;
               case 'G': parser->RaHistoStart *= 1000000000.0;
                         parser->RaHistoEnd   *= 1000000000.0;  break;
               case  ' ':
               case '\0': break;

               default:
                  return (retn);
            }

            retn = 1;

         } else {
            if (isdigit((int)*tmp))
               if ((parser->RaHistoBins = atoi(tmp)) < 0)
                  return (retn);

            retn = ARGUS_HISTO_RANGE_UNSPECIFIED;
         }

         if ((parser->RaHistoRecords = (struct ArgusRecordStruct **) ArgusCalloc (parser->RaHistoBins + 2, sizeof(struct ArgusRecordStruct *))) != NULL) {
            parser->RaHistoRangeState = retn;

            if (parser->RaHistoMetricLog) {
               parser->RaHistoEndLog      = log10(parser->RaHistoEnd);

               if (parser->RaHistoStart > 0) {
                  parser->RaHistoStartLog = log10(parser->RaHistoStart);
               } else {
                  parser->RaHistoLogInterval = (parser->RaHistoEndLog/(parser->RaHistoBins * 1.0));
                  parser->RaHistoStartLog = parser->RaHistoEndLog - (parser->RaHistoLogInterval * parser->RaHistoBins);
               }

               parser->RaHistoBinSize = (parser->RaHistoEndLog - parser->RaHistoStartLog) / parser->RaHistoBins * 1.0;

            } else
               parser->RaHistoBinSize = ((parser->RaHistoEnd - parser->RaHistoStart) * 1.0) / parser->RaHistoBins * 1.0;

         } else
            ArgusLog (LOG_ERR, "%s: ArgusCalloc %s\n", __func__, strerror(errno));
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "%s(%p): returning %d \n", __func__, parser, retn);
#endif
   return (retn);
}

static int
ArgusHistoTallyMetric (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, double value)
{
   int retn = 0, i = 0;
   double start, end, bsize;
   double iptr;

   if (parser && (ns != NULL)) {
      bsize = parser->RaHistoBinSize;

      if (parser->RaHistoMetricLog) {
         value = log10(value);
         start = parser->RaHistoStartLog;
           end = parser->RaHistoEndLog;
      } else {
         start = parser->RaHistoStart;
           end = parser->RaHistoEnd;
      }

      if (value >= start) {
         modf((value - start)/bsize, &iptr);

         if ((i = iptr) > parser->RaHistoBins)
            i = parser->RaHistoBins + 1;

         if (value < (end + bsize))
            i++;
      } else {
         i = 0;
      }
   }

   if (parser->RaHistoRecords[i] != NULL) {
      ArgusMergeRecords (parser->ArgusAggregator, parser->RaHistoRecords[i], ns);
   } else
      parser->RaHistoRecords[i] = ArgusCopyRecordStruct(ns);

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusHistoTallyMetric(%p, %p): returning %d\n", parser, ns, retn);
#endif
   return (retn);
}

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   parser->RaWriteOut = 0;
 
   if (!(parser->RaInitialized)) {

      if (parser->Hstr == NULL)
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
 
      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");
 
      if (parser->Hstr) {
         int retn;
         if (!(retn = ArgusHistoMetricParse (parser, parser->ArgusAggregator)))
            usage ();

         switch (retn) {
            case ARGUS_HISTO_RANGE_UNSPECIFIED: {
               parser->ArgusPassNum = 2;
               parser->RaHistoStart =  HUGE_VAL;
               parser->RaHistoEnd   = -HUGE_VAL;
               break;
            }

            default: 
               parser->RaHistoRangeState |= ARGUS_HISTO_CAPTURE_VALUES;
               break;
         }
      }
 
      parser->nflag += 2;

      if (parser->vflag)
         ArgusReverseSortDir++;
 
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
   int i, printed = 0;
   int _writing_records_to_stdout;

   if (sig >= 0) {
      if (!parser->RaParseCompleting++) {

         _writing_records_to_stdout =
          writing_records_to_stdout(parser->ArgusWfileList);

         if (parser->RaHistoRecords) {
            for (i = 0; i < parser->RaHistoBins + 2; i++) {
               struct ArgusRecordStruct *argus = parser->RaHistoRecords[i];
               if ((!ArgusProcessOutLayers && ((i > 0) && (i <= parser->RaHistoBins))) || ArgusProcessOutLayers) {
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
                        qsort (RaValueBuffer, RaNumberOfValues, sizeof(double), RaSortValueBuffer);

                        if (RaNumberOfValues % 2) {
                           median = RaValueBuffer[(RaNumberOfValues + 1)/2];

                           if (RaValuesAreIntegers)
                              pflag = 0;

                        } else {
                           ind = (RaNumberOfValues / 2) - 1;
                           median = (RaValueBuffer[ind] + RaValueBuffer[ind + 1]) / 2.0;
                        }

                        sprintf (buf, "%-.*f", pflag, median);
                        medianStr = strdup(buf);

                        if (RaValuesAreIntegers)
                           pflag = 0;

                        ind = RaNumberOfValues * 0.95;
                        percentile = RaValueBuffer[ind];

                        sprintf (buf, "%-.*f", pflag, percentile);
                        percentStr = strdup(buf);

                        numModes = RaFindModes(RaValueBuffer, RaNumberOfValues, modeValues, 1024);

                        if (numModes > 0) {
                           bzero(buf, sizeof(buf));
                           for (i = 0; i < numModes; i++) {
                              if (i > 0)
                                 sprintf(&buf[strlen(buf)], ",");
 
                              if (RaValuesAreIntegers)
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
                                        tagr->act.n, parser->RaHistoBins, pflag, parser->RaHistoBinSize, meanStr, stdStr, maxValStr, minValStr);
                           printf ("\n \"median\": \"%s\", \"95%%\": \"%s\",\n", medianStr, percentStr);
                        } else {
                           if ((c = ArgusParser->RaFieldDelimiter) != '\0') {
                              printf ("N=%d%cmean=%s%cstddev=%s%cmax=%s%cmin=%s%c",
                                           tagr->act.n, c, meanStr, c, stdStr, c, maxValStr, c, minValStr, c);
                              printf ("median=%s%c95%%=%s", medianStr, c, percentStr);
                           } else {
                              printf (" N = %-6d  mean = %*s  stddev = %*s  max = %s  min = %s\n",
                                           tagr->act.n, len, meanStr, len, stdStr, maxValStr, minValStr);
                              printf ("           median = %*s     95%% = %s\n", len, medianStr, percentStr);
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

               if (parser->RaHistoMetricLog) {
                  start = parser->RaHistoStartLog;
               } else {
                  start = parser->RaHistoStart;
               }
               bsize = parser->RaHistoBinSize;

               for (i = 0; i < parser->RaHistoBins + 2; i++) {
                  struct ArgusRecordStruct *argus = parser->RaHistoRecords[i];

                  if (i == 0) {
                     bs = 0;
                     be = start;
                     if (parser->RaHistoMetricLog)
                        be = pow(10.0, be);

                  } else {
                     bs = (start + ((i - 1) * bsize));
                     if (i > parser->RaHistoBins) {
                        be = bs;
                     } else {
                        be = (start +  (i * bsize));
                     }
                     if (parser->RaHistoMetricLog) {
                        bs = pow(10.0, bs);
                        be = pow(10.0, be);
                     }
                  }

                  if ((!ArgusProcessOutLayers && ((i > 0) && (i <= parser->RaHistoBins))) || ArgusProcessOutLayers) {
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

                              if (i > parser->RaHistoBins) {
                                 if (argus && (agr && (agr->count > 0))) {
                                    bf = be;
                                    do {
                                       if (parser->RaHistoMetricLog)
                                          bf += pow(10.0, parser->RaHistoBinSize);
                                       else
                                          bf += parser->RaHistoBinSize;
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
                                 if (i == 0) {
                                    if (be != bs)
                                       printThis++;
                                 } else
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
                  if (ArgusParser->ArgusPrintJson) 
                     printf ("\n  ]\n}\n");
               }
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




int
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
         struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;

         switch (parser->ArgusPassNum)  {
            case 2: {
               if (parser->RaHistoRangeState & ARGUS_HISTO_RANGE_UNSPECIFIED) {
                  if (agg && (agg->RaMetricFetchAlgorithm != NULL)) {
                     double frac, value, inte;
                     value = agg->RaMetricFetchAlgorithm(argus);
                     if (agg->AbsoluteValue) value = fabs(value);

                     if ((frac = modf(value, &inte)) != 0.0)
                         RaValuesAreIntegers = 0;

                     if (RaValueBuffer == NULL) {
                        if ((RaValueBuffer = malloc(sizeof(double) * RaValueBufferSize)) == NULL)
                           ArgusLog (LOG_ERR, "RaProcessRecord: malloc error %s", strerror(errno));
                     } else {
                        if (RaNumberOfValues >= RaValueBufferSize) {
                           RaValueBufferSize += 100000;
                           if ((RaValueBuffer = realloc(RaValueBuffer, sizeof(double) * RaValueBufferSize)) == NULL)
                              ArgusLog (LOG_ERR, "RaProcessRecord: realloc error %s", strerror(errno));
                        }
                     }

                     RaValueBuffer[RaNumberOfValues++] = value;

                     if (parser->RaHistoStart > value)
                        parser->RaHistoStart = value;

                     if (parser->RaHistoEnd < value)
                        parser->RaHistoEnd = value;
                  }
               }
               break;
            }

            case 1: {
               double range, value, frac, inte;

               if (parser->RaHistoRangeState & ARGUS_HISTO_RANGE_UNSPECIFIED) {
                  int cycle = 0;

                  parser->RaHistoRangeState &= ~ARGUS_HISTO_RANGE_UNSPECIFIED;

                  if (parser->RaHistoStart > 0) 
                     parser->RaHistoStart = 0.0;

                  if ((value = (parser->RaHistoEnd - parser->RaHistoStart) / (parser->RaHistoBins * 1.0)) > 0) {
                     while (value < 10.0) {
                        value *= 10.0;
                        cycle++;
                     }
                  }

                  if ((frac = modf(value, &range)) != 0.0) 
                     range += 1.0;

                  parser->RaHistoEnd = range * parser->RaHistoBins;
                  while (cycle > 0) {
                     parser->RaHistoEnd /= 10.0;
                     cycle--;
                  }

                  parser->RaHistoBinSize = ((parser->RaHistoEnd - parser->RaHistoStart) * 1.0) / parser->RaHistoBins * 1.0;
               }

               value = agg->RaMetricFetchAlgorithm(argus);
               if (agg->AbsoluteValue) value = fabs(value);

               if (parser->RaHistoRangeState & ARGUS_HISTO_CAPTURE_VALUES) {
                     if ((value >= parser->RaHistoStart) && (value <= parser->RaHistoEnd)) {
                        if ((frac = modf(value, &inte)) != 0.0)
                            RaValuesAreIntegers = 0;

                        if (RaValueBuffer == NULL) {
                           if ((RaValueBuffer = malloc(sizeof(double) * RaValueBufferSize)) == NULL)
                              ArgusLog (LOG_ERR, "RaProcessRecord: malloc error %s", strerror(errno));
                        } else {
                           if (RaNumberOfValues >= RaValueBufferSize) {
                              RaValueBufferSize += 100000;
                              if ((RaValueBuffer = realloc(RaValueBuffer, sizeof(double) * RaValueBufferSize)) == NULL)
                                 ArgusLog (LOG_ERR, "RaProcessRecord: realloc error %s", strerror(errno));
                           }
                        }

                     RaValueBuffer[RaNumberOfValues++] = value;
                  }
               }

               if (ArgusParser && ArgusParser->ArgusAggregator) {
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
                  ArgusHistoTallyMetric (parser, argus, value);
               break;
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


int
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
