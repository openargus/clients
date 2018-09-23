/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2018 QoSient, LLC
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

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

#if defined(__NetBSD__)
#include <machine/limits.h>
#endif

#include <syslog.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include <argus_compat.h>

#include <string.h>
#include <time.h>

#ifndef HAVE_POSIX_MEMALIGN
# ifdef HAVE_MEMALIGN
#  include <malloc.h>
# endif
#endif

#include <argus_util.h>
#include <argus_parser.h>
#include <argus_filter.h>
#include <argus_output.h>
#include <argus_client.h>
#include <argus_main.h>

#define ARGUS_YEAR      1
#define ARGUS_MONTH     2
#define ARGUS_DAY       3
#define ARGUS_HOUR      4
#define ARGUS_MIN       5
#define ARGUS_SEC       6

/* The "continued" parameter should be != 0 when parsing the second
 * part (that after a +/-).  Or can we determine that just from the
 * mode parameter???
 */
int
ArgusParseTime (char *wildcarddate, struct tm *tm, struct tm *ctm, char *buf,
                char mode, int *frac, int continued)
{
   char *hptr = NULL, *dptr = NULL, *mptr = NULL, *yptr = NULL, *pptr = NULL;
   char *minptr = NULL, *secptr = NULL, *ptr;
   char strbuf[128], *str = strbuf;
   int retn = 0, year = 0, month = 0, day = 0, hour = 0, mins = 0, sec = 0, sign = 1;
   time_t thistime = 0;
   double i = 0;

   /*[[[yyyy/]mm/]dd].]hh[:mm[:ss]]*/
   /* yyyy/mm */
   /* yyyy */
   /* %d[yMdhms] */
   /* %d[yMdhms][[+]%d[yMdhms]] explict time range */
   /* -%d[yMdhms] explicit time range ending with now time in the range */

   bzero(str, sizeof(strbuf));
   strncpy(str, buf, sizeof(strbuf));

   if (!(isdigit((int)*str)) && !(*str == '-') && !(*str == '*')) {
      retn = -1;
   } else {
      if ((ptr = strpbrk (str, "yMdhms")) != NULL) {
         int status = 0;

         if (mode == ' ') {
            if (!continued)
               bcopy ((u_char *) ctm, (u_char *) tm, sizeof (struct tm));
         } else
            bcopy ((u_char *) ctm, (u_char *) tm, sizeof (struct tm));

         thistime = mktime (tm);

         do {
            int wildcard = 0;
            char *endptr;

            if (*str == '*') {
               wildcard++;
               switch (*ptr) {
                  case 'y': i = 1970; status |= (1 << RAWILDCARDYEAR); break;
                  case 'M': i =    0; status |= (1 << RAWILDCARDMONTH); break;
                  case 'd': i =    1; status |= (1 << RAWILDCARDDAY); break;
                  case 'h': i =    0; status |= (1 << RAWILDCARDHOUR); break;
                  case 'm': i =    0; status |= (1 << RAWILDCARDMIN); break;
                  case 's': i =    0; status |= (1 << RAWILDCARDSEC); break;
               }
               *wildcarddate = status;
               
            } else  {
               i = strtod(str, &endptr);
               if (endptr == str) {
                  ArgusLog (LOG_INFO, "time syntax error %s", buf);
                  retn = -1;
                  goto out;
               }
            }

            if ((i >= 0) && (mode == ' ')) {
               switch (*ptr) {
                  case 'y': tm->tm_year = (i - 1900); retn = ARGUS_YEAR; break;
                  case 'M': tm->tm_mon = (i - 1); retn = ARGUS_MONTH; break;
                  case 'd': tm->tm_mday = i; retn = ARGUS_DAY; break;
                  case 'h': tm->tm_hour = i; retn = ARGUS_HOUR; break;
                  case 'm': tm->tm_min = i; retn = ARGUS_MIN; break;
                  case 's': tm->tm_sec = i; retn = ARGUS_SEC; break;
               }

            } else {
               if (!continued)
                  i++;

               if (wildcard) {
                  ArgusLog (LOG_INFO, "time syntax error %s", buf);
                  retn = -1;
                  goto out;
               }

               switch (mode) {
                  case '-': sign = -1; break;
                  case '+': break;
               }

               switch (*ptr) {
                  case 'y': tm->tm_year += (i * sign); retn = ARGUS_YEAR; break;

                  case 'M': {
                     while (i > tm->tm_mon) {
                        tm->tm_year += 1 * sign;
                        i -= 12;
                     }
                     tm->tm_mon += i * sign;
                     thistime = mktime (tm);
                     retn = ARGUS_MONTH;
                     break;
                  }

                  case 'd':
                     thistime += (i * ((60 * 60) * 24)) * sign;
                     localtime_r (&thistime, tm);
                     retn = ARGUS_DAY;
                     break;

                  case 'h':
                     thistime += (i * (60 * 60)) * sign;
                     localtime_r (&thistime, tm);
                     retn = ARGUS_HOUR;
                     break;

                  case 'm':
                     thistime += (i * 60) * sign;
                     localtime_r (&thistime, tm);
                     retn = ARGUS_MIN;
                     break;

                  case 's':
                     thistime += i * sign;
                     localtime_r (&thistime, tm);
                     retn = ARGUS_SEC;
                     break;

                  default:
                     retn = -1;
                     break;
               }
            }

            if (retn >= 0) {
               str = ptr + 1;
               if ((!(isdigit((int)*str))) && !(*str == '*'))
                  break;
            } else
               break;

         } while ((ptr = strpbrk (str, "yMdhms")) != NULL);

         switch (retn) {
            case ARGUS_YEAR:   tm->tm_mon  = 0;
            case ARGUS_MONTH:  tm->tm_mday = 1;
            case ARGUS_DAY:    tm->tm_hour = 0;
            case ARGUS_HOUR:   tm->tm_min  = 0;
            case ARGUS_MIN:    tm->tm_sec  = 0;
            case ARGUS_SEC:    break;
         }

         if ((retn >= 0) && (sign < 0)) {
            struct tm tmbuf;
            bcopy ((u_char *) ctm, (u_char *)&tmbuf, sizeof (struct tm));
            bcopy ((u_char *) tm, (u_char *) ctm, sizeof (struct tm));
            bcopy ((u_char *)&tmbuf, (u_char *) tm, sizeof (struct tm));
         }
         
      } else {
         int status = *wildcarddate;

         bcopy ((u_char *) ctm, (u_char *) tm, sizeof (struct tm));
         year  = tm->tm_year;
         month = tm->tm_mon;
         day   = tm->tm_mday;
         hour  = tm->tm_hour;
         mins  = tm->tm_min;
         sec   = tm->tm_sec;

#if HAVE_STRUCT_TM_TM_ZONE
         tm->tm_zone = NULL;
         tm->tm_gmtoff = 0;
#endif
         thistime = mktime (tm);

         if ((hptr = strchr (str, '.')) != NULL) {
            if ((hptr - str) != (strlen(str) - 1)) {
               *hptr++ = '\0';
               if (!(isdigit((int)*hptr)) && !(*hptr == '*'))
                  return -1;
            } else {
               *hptr = '\0';
               pptr = hptr;
               hptr = NULL;
            }
         }
      
         if ((dptr = strrchr (str, '/')) != NULL) {  /* mm/dd  || yyyy/mm  || yyyy/mm/dd */
                                                     /*   ^   */
            *dptr++ = '\0';
            if ((mptr = strrchr (str, '/')) != NULL) {  /* yyyy/mm/dd */
               *mptr++ = '\0';
               yptr = str;

            } else {
               if (strlen(str) == 4) {
                  yptr = str;
                  mptr = dptr;
                  dptr =  NULL;
                  tm->tm_mday = 1;
               } else
                  mptr = str;
            }

         } else {
            if (hptr != NULL)
               dptr = str;
            else {
               int value = atoi(str);
               if ((value > 1900) && (value <= (tm->tm_year + 1900))) {
                  yptr = str;
                  hour = 0;
               } else
                  hptr = str;
            }
         }
      
         if (yptr) {
            if (strlen(yptr) != 4)
               return -1;

            for (ptr = yptr, i = 0; i < strlen(yptr); i++) {
               if (*ptr == '*') {
                  status |= 1 << RAWILDCARDYEAR;
                  break;
               }
               if (!(isdigit((int)*ptr++)))
                  return -1;
            }

            if (!(status & (1 << RAWILDCARDYEAR))) {
               tm->tm_year = atoi(yptr) - 1900;
            } else
               tm->tm_year = 70;
            retn = ARGUS_YEAR;
            year = tm->tm_year;
         }

         if (mptr) {
            if (strlen(mptr) != 2)
               return -1;
            for (ptr = mptr, i = 0; i < strlen(mptr); i++) {
               if (*ptr == '*') {
                  status |= 1 << RAWILDCARDMONTH;
                  break;
               }
               if (!(isdigit((int)*ptr++)))
                  return -1;
            }
            if (!(status & (1 << RAWILDCARDMONTH))) {
               tm->tm_mon  = atoi(mptr) - 1;
            } else 
               tm->tm_mon  = 0;
            retn = ARGUS_MONTH;
            month = tm->tm_mon;
         }
      
         if (dptr) {
            if (strlen(dptr) != 2)
               return -1;
            for (ptr = dptr, i = 0; i < strlen(dptr); i++) {
               if (*ptr == '*') {
                  status |= 1 << RAWILDCARDDAY;
                  break;
               }
               if (!(isdigit((int)*ptr++)))
                  return -1;
            }
            if (!(status & (1 << RAWILDCARDDAY))) {
               tm->tm_mday = atoi(dptr);
            } else
               tm->tm_mday = 1;
            retn = ARGUS_DAY;
            day = tm->tm_mday;
         }
      
         if (hptr) {
            if ((pptr = strchr (hptr, '.')) != NULL) {
               char *tptr = pptr + 1;
               float scale = 1000000.0;
               *pptr = '\0';

                while(isdigit((int)*tptr++)) scale /= 10.0;
               *frac = atoi(&pptr[1]) * scale;
            }
            if ((minptr = strchr (hptr, ':')) != NULL) {
               *minptr++ = '\0';
               if ((secptr = strchr (minptr, ':')) != NULL) {
                  *secptr++ = '\0';
               }
            }

            for (ptr = hptr, i = 0; i < strlen(hptr); i++) {
               if (*ptr == '*') {
                  status |= 1 << RAWILDCARDHOUR;
                  break;
               }
               if (!(isdigit((int)*ptr++)))
                  return -1;
            }
      
            if (!(status & (1 << RAWILDCARDHOUR))) {
               hour = atoi(hptr);
               if (hour < 24) {
                  retn = ARGUS_HOUR;
               }
            } else
               hour = 0;

            if (minptr != NULL) {
               for (ptr = minptr, i = 0; i < strlen(minptr); i++) {
                  if (*ptr == '*') {
                     status |= 1 << RAWILDCARDMIN;
                     break;
                  }
                  if (!(isdigit((int)*ptr++)))
                     return -1;
               }
      
               if (!(status & (1 << RAWILDCARDMIN))) {
                  mins = atoi(minptr);
                  retn = ARGUS_MIN;
               } else
                  mins = 0;
            }
      
            if (secptr != NULL) {
               for (ptr = secptr, i = 0; i < strlen(secptr); i++) {
                  if (*ptr == '*') {
                     status |= 1 << RAWILDCARDSEC;
                     break;
                  }
                  if (!(isdigit((int)*ptr++)))
                     return -1;
               }

               if (!(status & (1 << RAWILDCARDSEC))) {
                  sec = atoi(secptr);
                  retn = ARGUS_SEC;
               } else
                  sec = 0;
            }
         }

         switch (retn) {
            case ARGUS_YEAR:   tm->tm_mon  = month = 0;
            case ARGUS_MONTH:  tm->tm_mday = day = 1;
            case ARGUS_DAY:    tm->tm_hour = hour = 0;
            case ARGUS_HOUR:   tm->tm_min  = mins = 0;
            case ARGUS_MIN:    tm->tm_sec  = sec = 0;
            case ARGUS_SEC:    break;
         }

         if (hour > 24) {
            time_t value = hour;
            bzero(tm, sizeof(*tm));
            localtime_r (&value, tm);
            year  = tm->tm_year;
            month = tm->tm_mon;
            day   = tm->tm_mday;
            hour  = tm->tm_hour;
            mins  = tm->tm_min;
            sec   = tm->tm_sec;
            retn  = 1;
            status = 0;

         } else {
            tm->tm_hour = hour;
            tm->tm_min  = mins;
            tm->tm_sec  = sec;
      
            if (tm->tm_year < 0)
               retn = -1;
            if ((tm->tm_mon > 11) || (tm->tm_mon < 0))
               retn = -1;
            if ((tm->tm_mday > 31) || (tm->tm_mday < 1))
               retn = -1;
            if ((tm->tm_hour > 23) || (tm->tm_hour < 0))
               retn = -1;
            if ((tm->tm_min > 60) || (tm->tm_min < 0))
               retn = -1;
            if ((tm->tm_sec > 60) || (tm->tm_sec < 0))
               retn = -1;
         }

         *wildcarddate = status;

         if (retn >= 0) {
#if HAVE_STRUCT_TM_TM_ZONE
            tm->tm_isdst  = 0;
            tm->tm_gmtoff = 0;
            tm->tm_zone   = 0;
#endif
            thistime = mktime (tm);

#if HAVE_STRUCT_TM_TM_ZONE
            if (tm->tm_zone != NULL) {
               char *tmzone = strdup(tm->tm_zone);
               localtime_r (&thistime, tm);
               if (strncpy(tmzone, tm->tm_zone, strlen(tmzone))) {
                  tm->tm_year = year;
                  tm->tm_mon  = month;
                  tm->tm_mday = day;
                  tm->tm_hour = hour;
                  thistime    = mktime (tm);
               }
               free(tmzone);
            }
#endif
         }

         if (pptr != NULL)
            *pptr = '.';
      }
   }

out:
#ifdef ARGUSDEBUG
   {
      char *rstr = "";
      switch (retn) {
         case ARGUS_YEAR:  rstr = "year"; break;
         case ARGUS_MONTH: rstr = "mon"; break;
         case ARGUS_DAY:   rstr = "day"; break;
         case ARGUS_HOUR:  rstr = "hour"; break;
         case ARGUS_MIN:   rstr = "min"; break;
         case ARGUS_SEC:   rstr = "sec"; break;
      }

      ArgusDebug (3, "ArgusParseTime (%p, %p, %p, \"%s\", '%c', 0.%06d, %d) retn %s(%d)\n",
                  wildcarddate, tm, ctm, buf, mode, *frac, continued, rstr,
                  thistime);
   }
#endif
   return (retn);
}
