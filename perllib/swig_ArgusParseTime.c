/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2018 QoSient, LLC
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

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <argus_compat.h>
#include <argus_util.h>
#include <argus_main.h>
#include "argus_threads.h"
#include <ctype.h>

int
swig_ArgusParseTime (char *time_string, int *start, int *end)
{
   int retn = 1;
   char *string;
   struct tm starttime = {0, };
   struct tm endtime = {0, };
   int frac;
   time_t tsec;
   struct timeval now;

   /* Also remember where in the string the separator was. */
   char *plusminusloc = NULL;
   int off = 0;
   char wildcarddate = 0;

   /* If the date string has two parts, remember which character
    * separates them.
    */
   char plusminus;

   *start = -1;
   *end = -1;
   string = strdup(time_string);

   if (string[0] == '-')
      /* skip leading minus, if present */
      off++;

   /* look through the time string for a plus or minus to indicate
    * a compound time.
    */
   while (!plusminusloc && !isspace(string[off]) && string[off] != '\0') {
      if (string[off] == '-' || string[off] == '+') {
         plusminusloc = &string[off];
         plusminus = string[off];
         string[off] = '\0'; /* split the string in two */
      }
      off++;
   }

   gettimeofday(&now, NULL);
   tsec = now.tv_sec;
   localtime_r(&tsec, &endtime);

   if (ArgusParseTime(&wildcarddate, &starttime, &endtime,
                      string, ' ', &frac, 0) <= 0) {
      retn = 0;
      goto out;
   }

   if (plusminusloc) {
      if (ArgusParseTime(&wildcarddate, &endtime, &starttime,
                         plusminusloc+1, plusminus, &frac, 1) <= 0) {
         retn = 0;
         goto out;
      }
   } else if (string[0] != '-') {
      /* Not a time relative to "now" AND not a time range */
      endtime = starttime;
   }

out:
   if (retn == 1) {
      *start = (int)mktime(&starttime);
      *end = (int)mktime(&endtime);
   }

   if (string)
      free(string);
   return retn;
}
