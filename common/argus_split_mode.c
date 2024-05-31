/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */ 

/*
 * Argus-5.0 Client Library
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

#include <time.h>
#include "rasplit.h"
#include "argus_client.h"
#include "argus_sort.h"

const char *RaSplitModes[ARGUSSPLITMODENUM] = {
  "time",
  "count",
  "size",
  "flow",
  "pattern",
  "nomodify",
  "hard",
  "soft",
  "zero",
  "rate",
};

/* Since the mode pointer may be advanced here, return the resulting
 * value.  If the split mode is either ARGUSSPLITSIZE or ARGUSSPLITCOUNT,
 * it is up to the caller to truncate the ArgusSorter array.
 */

struct ArgusModeStruct *
RaParseSplitMode(struct ArgusParserStruct * parser,
                 struct RaBinProcessStruct **RaBinProcess,
                 struct ArgusModeStruct *mode,
                 int *splitmode)
{
   int i;
   int ind;
   int size = 1;
   struct ArgusAdjustStruct *nadp = NULL;
   time_t tsec = ArgusParser->ArgusRealTime.tv_sec;

   for (i = 0, ind = -1; i < ARGUSSPLITMODENUM; i++) {
      if (!(strncasecmp (mode->mode, RaSplitModes[i], strlen(RaSplitModes[i])))) {
         if (*RaBinProcess == NULL) {
            if ((*RaBinProcess = RaNewBinProcess(parser, 256)) == NULL)
               ArgusLog(LOG_ERR, "%s: RaNewBinProcess error %s", __func__,
                        strerror(errno));
         }
         nadp = &((*RaBinProcess)->nadp);

         nadp->mode   = -1;
         nadp->modify =  0;
         nadp->slen   =  2;

         if (parser->aflag)
            nadp->slen = parser->aflag;

         ind = i;
         break;
      }
   }

   if (ind >= 0) {
      char *mptr = NULL;
      switch (ind) {
         case ARGUSSPLITRATE:  {   /* "%d:%d[yMwdhms]" */
            struct ArgusModeStruct *tmode = NULL;
            nadp->mode = ind;
            if ((tmode = mode->nxt) != NULL) {
               mptr = tmode->mode;
               if (isdigit((int)*tmode->mode)) {
                  char *ptr = NULL;
                  nadp->count = strtol(tmode->mode, (char **)&ptr, 10);
                  if (*ptr++ != ':')
                     usage();
                  tmode->mode = ptr;
               }
            }
            /* purposefully drop through */
         }

         case ARGUSSPLITTIME: /* "%d[yMwdhms] */
            if (ArgusParser->tflag)
               tsec = ArgusParser->startime_t.tv_sec;

            nadp->mode = ind;
            if ((mode = mode->nxt) != NULL) {
               if (isdigit((int)*mode->mode)) {
                  char *ptr = NULL;
                  nadp->value = strtol(mode->mode, (char **)&ptr, 10);
                  if (ptr == mode->mode)
                     usage();
                  else {
                     switch (*ptr) {
                        case 'y':
                        case 'Y':
                           nadp->qual = ARGUSSPLITYEAR;
                           localtime_r(&tsec, &nadp->RaStartTmStruct);
                           nadp->RaStartTmStruct.tm_sec = 0;
                           nadp->RaStartTmStruct.tm_min = 0;
                           nadp->RaStartTmStruct.tm_hour = 0;
                           nadp->RaStartTmStruct.tm_mday = 1;
                           nadp->RaStartTmStruct.tm_mon = 0;
                           nadp->size = nadp->value*3600.0*24.0*7.0*52.0*1000000LL;
                           break;

                        case 'M':
                           nadp->qual = ARGUSSPLITMONTH;
                           localtime_r(&tsec, &nadp->RaStartTmStruct);
                           nadp->RaStartTmStruct.tm_sec = 0;
                           nadp->RaStartTmStruct.tm_min = 0;
                           nadp->RaStartTmStruct.tm_hour = 0;
                           nadp->RaStartTmStruct.tm_mday = 1;
                           nadp->RaStartTmStruct.tm_mon = 0;
                           nadp->size = nadp->value*3600.0*24.0*7.0*4.0*1000000LL;
                           break;

                        case 'w':
                           nadp->qual = ARGUSSPLITWEEK;
                           localtime_r(&tsec, &nadp->RaStartTmStruct);
                           nadp->RaStartTmStruct.tm_sec = 0;
                           nadp->RaStartTmStruct.tm_min = 0;
                           nadp->RaStartTmStruct.tm_hour = 0;
                           nadp->RaStartTmStruct.tm_mday = 1;
                           nadp->RaStartTmStruct.tm_mon = 0;
                           nadp->size = nadp->value*3600.0*24.0*7.0*1000000LL;
                           break;

                        case 'd':
                           nadp->qual = ARGUSSPLITDAY;
                           localtime_r(&tsec, &nadp->RaStartTmStruct);
                           nadp->RaStartTmStruct.tm_sec = 0;
                           nadp->RaStartTmStruct.tm_min = 0;
                           nadp->RaStartTmStruct.tm_hour = 0;
                           nadp->size = nadp->value*3600.0*24.0*1000000LL;
                           break;

                        case 'h':
                           nadp->qual = ARGUSSPLITHOUR;
                           localtime_r(&tsec, &nadp->RaStartTmStruct);
                           nadp->RaStartTmStruct.tm_sec = 0;
                           nadp->RaStartTmStruct.tm_min = 0;
                           nadp->size = nadp->value*3600.0*1000000LL;
                           break;

                        case 'm': {
                           nadp->qual = ARGUSSPLITMINUTE;
                           localtime_r(&tsec, &nadp->RaStartTmStruct);
                           nadp->RaStartTmStruct.tm_sec = 0;
                           nadp->size = nadp->value*60.0*1000000LL;
                           break;
                        }

                         default:
                        case 's': {
                           long long val = tsec / nadp->value;
                           nadp->qual = ARGUSSPLITSECOND;
                           tsec = val * nadp->value;
                           localtime_r(&tsec, &nadp->RaStartTmStruct);
                           nadp->size = nadp->value * 1000000LL;
                           break;
                        }
                     }
                  }
               }
               if (mptr != NULL)
                   mode->mode = mptr;
            }

            nadp->modify = 1;

            if (ind == ARGUSSPLITRATE) {
               /* need to set the flow idle timeout value to be equal to or
                  just a bit bigger than (nadp->count * size) */

               ArgusParser->timeout.tv_sec  = (nadp->count * size);
               ArgusParser->timeout.tv_usec = 0;
            }

            (*RaBinProcess)->rtime.tv_sec = tsec;

         case ARGUSSPLITSIZE:
         case ARGUSSPLITCOUNT:
            nadp->mode = ind;
            nadp->count = 1;

            if ((mode = mode->nxt) != NULL) {
               if (isdigit((int)*mode->mode)) {
                  char *ptr = NULL;
                  nadp->value = strtol(mode->mode, (char **)&ptr, 10);
                  if (ptr == mode->mode)
                     usage();
                  else {
                     switch (*ptr) {
                        case 'B':
                        case 'b':  nadp->value *= 1000000000; break;

                        case 'M':
                        case 'm':  nadp->value *= 1000000; break;

                        case 'K':
                        case 'k':  nadp->value *= 1000; break;
                     }
                  }
               }
            }
            break;

         case ARGUSSPLITNOMODIFY:
            nadp->modify = 0;
            break;

         case ARGUSSPLITHARD:
            nadp->hard++;
            break;

         case ARGUSSPLITZERO:
            nadp->zero++;
            break;
      }

      (*RaBinProcess)->size = nadp->size;

      if (nadp->mode < 0) {
         nadp->mode = ARGUSSPLITCOUNT;
         nadp->value = 10000;
         nadp->count = 1;
      }

   }

   *splitmode = ind;
   return mode;
}
