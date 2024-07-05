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

static int RaDaysInAMonth[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

/* 
 * ArgusParseTime takes the buf, and decodes the time format and fills 
 * in the start and end 'struct tm' to represent the start and end times
 * for the range specified in the date buffer.
 * 
 * The format for the time string is pretty complex, wanting to provide as
 * much support as possible.
 *    [[[yyyy/]mm/]dd].]hh[:mm[:ss]]
 *    yyyy                       returns the range from yyyy+1y
 *    yyyy/mm                    returns the range from yyyy/mm+1m
 *    yyyy/mm/dd                 returns the range from yyyy/mm/dd+1d
 *    yyyy/mm/dd.hh              returns the range from yyyy/mm/dd.hh+1h
 *    yyyy/mm/dd.hh.mm           returns the range from yyyy/mm/dd.hh+1M
 *    yyyy/mm/dd.hh.mm.ss        returns the range from yyyy/mm/dd.hh:mm:ss+1S
 *
 *    %d[.%d]                    unixtime (d > 10000000)
 *    %d[yMdhms]                 
 *    %d[yMdhms][[+]%d[yMdhms]]  explict time range 
 *    -%d[yMdhms] explicit time  range ending with now time in the range 
 * 
 * The "continued" parameter should be != 0 when parsing the second
 * part (that after a +/-).  Or can we determine that just from the
 * mode parameter???
 */

int
ArgusParseTime (char *wildcarddate, struct tm *startm, struct tm *endtm, char *buf,
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
   /* if %d is > 1000000, then assume its a unix timestamp */

   bzero(str, sizeof(strbuf));
   strncpy(str, buf, sizeof(strbuf) - 1);

   if (!(isdigit((int)*str)) && !(*str == '-') && !(*str == '*')) {
      retn = -1;
   } else {
      if ((ptr = strpbrk (str, "YyMdhms")) != NULL) {
         int status = 0;

         if (mode == ' ') {
            if (!continued)
               bcopy ((u_char *) endtm, (u_char *) startm, sizeof (struct tm));
         } else
            bcopy ((u_char *) endtm, (u_char *) startm, sizeof (struct tm));

         thistime = mktime (startm);

         do {
            int wildcard = 0;
            char *endptr;

            if (*str == '*') {
               wildcard++;
               switch (*ptr) {
                  case 'Y': i = 1970; status |= (1 << RAWILDCARDYEAR); break;
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
                  case 'y': startm->tm_year = (i - 1900); retn = ARGUS_YEAR; break;
                  case 'M': startm->tm_mon = (i - 1); retn = ARGUS_MONTH; break;
                  case 'd': startm->tm_mday = i; retn = ARGUS_DAY; break;
                  case 'h': startm->tm_hour = i; retn = ARGUS_HOUR; break;
                  case 'm': startm->tm_min = i; retn = ARGUS_MIN; break;
                  case 's': startm->tm_sec = i; retn = ARGUS_SEC; break;
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
                  case 'y': {
                     startm->tm_year += (i * sign); 
		     retn = ARGUS_YEAR; break;
                  }
                  case 'M': {
                     while (i > startm->tm_mon) {
                        startm->tm_year += 1 * sign;
                        i -= 12;
                     }
                     startm->tm_mon += i * sign;
                     startm->tm_hour = 12;
                     thistime = mktime (startm);
                     startm->tm_hour = 0;
                     retn = ARGUS_MONTH;
                     break;
                  }

                  case 'd':
                     thistime += (i * ((60 * 60) * 24)) * sign;
                     localtime_r (&thistime, startm);
                     retn = ARGUS_DAY;
                     break;

                  case 'h':
                     thistime += (i * (60 * 60)) * sign;
                     localtime_r (&thistime, startm);
                     retn = ARGUS_HOUR;
                     break;

                  case 'm':
                     thistime += (i * 60) * sign;
                     localtime_r (&thistime, startm);
                     retn = ARGUS_MIN;
                     break;

                  case 's':
                     thistime += i * sign;
                     localtime_r (&thistime, startm);
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

         } while ((ptr = strpbrk (str, "yYMdhms")) != NULL);

         switch (retn) {
            case ARGUS_YEAR:   startm->tm_mon  = 0;
            case ARGUS_MONTH:  startm->tm_mday = 1;
            case ARGUS_DAY:    startm->tm_hour = 0;
            case ARGUS_HOUR:   startm->tm_min  = 0;
            case ARGUS_MIN:    startm->tm_sec  = 0;
            case ARGUS_SEC:    break;
         }

         switch (retn) {
            case ARGUS_YEAR:   endtm->tm_mon  = 0;
            case ARGUS_MONTH:  endtm->tm_mday = 1;
            case ARGUS_DAY:    endtm->tm_hour = 0;
            case ARGUS_HOUR:   endtm->tm_min  = 0;
            case ARGUS_MIN:    endtm->tm_sec  = 0;
            case ARGUS_SEC:    break;
         }

         if ((retn >= 0) && (sign < 0)) {
            struct tm tmbuf;
            bcopy ((u_char *) endtm, (u_char *)&tmbuf, sizeof (struct tm));
            bcopy ((u_char *) startm, (u_char *) endtm, sizeof (struct tm));
            bcopy ((u_char *)&tmbuf, (u_char *) startm, sizeof (struct tm));
         }
         
      } else {
         int status = *wildcarddate;
         int unixt = 0;

         bcopy ((u_char *) endtm, (u_char *) startm, sizeof (struct tm));

         if (!(strpbrk(str, "/:"))) {
            int value = atoi(str);
            if (value > 10000000) {
               unixt = 1;
               thistime = value;
               retn = 1;
            } else {
               unixt = 0;
               retn = -1;
            }
         }
         if (unixt) {
            localtime_r (&thistime, startm);
         } else {
            year  = startm->tm_year;
            month = startm->tm_mon;
            day   = startm->tm_mday;
            hour  = startm->tm_hour;
            mins  = startm->tm_min;
            sec   = startm->tm_sec;

#if HAVE_STRUCT_TM_TM_ZONE
            startm->tm_zone = NULL;
            startm->tm_gmtoff = 0;
#endif
            thistime = mktime (startm);

            if ((hptr = strchr (str, '.')) != NULL) {
               if ((unsigned long) (hptr - str) != (strlen(str) - 1)) {
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
                     startm->tm_mday = 1;
                  } else
                     mptr = str;
               }

            } else {
               if (hptr != NULL)
                  dptr = str;
               else {
                  int value = atoi(str);
                  if ((value > 1900) && (value <= (startm->tm_year + 1900))) {
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
                  startm->tm_year = atoi(yptr) - 1900;
               } else
                  startm->tm_year = 70;
               retn = ARGUS_YEAR;
               year = startm->tm_year;
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
                  startm->tm_mon  = atoi(mptr) - 1;
               } else 
                  startm->tm_mon  = 0;
               retn = ARGUS_MONTH;
               month = startm->tm_mon;
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
                  startm->tm_mday = atoi(dptr);
               } else
                  startm->tm_mday = 1;
               retn = ARGUS_DAY;
               day = startm->tm_mday;
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
                  if (mode == '+')
                     hour += startm->tm_hour;
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
               case ARGUS_YEAR:   startm->tm_mon  = month = 0;
               case ARGUS_MONTH:  startm->tm_mday = day = 1;
               case ARGUS_DAY:    startm->tm_hour = hour = 0;
               case ARGUS_HOUR:   startm->tm_min  = mins = 0;
               case ARGUS_MIN:    startm->tm_sec  = sec = 0;
               case ARGUS_SEC:    break;
            }

            if (unixt) {
               time_t value = hour;
               bzero(startm, sizeof(*startm));
               localtime_r (&value, startm);
               year  = startm->tm_year;
               month = startm->tm_mon;
               day   = startm->tm_mday;
               hour  = startm->tm_hour;
               mins  = startm->tm_min;
               sec   = startm->tm_sec;
               retn  = 1;
               status = 0;

            } else {
               startm->tm_hour = hour;
               startm->tm_min  = mins;
               startm->tm_sec  = sec;
         
               if (startm->tm_year < 0)
                  retn = -1;
               if ((startm->tm_mon > 11) || (startm->tm_mon < 0))
                  retn = -1;
               if ((startm->tm_mday > 31) || (startm->tm_mday < 1))
                  retn = -1;
               if ((startm->tm_hour > 23) || (startm->tm_hour < 0))
                  retn = -1;
               if ((startm->tm_min > 60) || (startm->tm_min < 0))
                  retn = -1;
               if ((startm->tm_sec > 60) || (startm->tm_sec < 0))
                  retn = -1;
            }

            *wildcarddate = status;

            if (retn >= 0) {
#if HAVE_STRUCT_TM_TM_ZONE
               startm->tm_isdst  = 0;
               startm->tm_gmtoff = 0;
               startm->tm_zone   = 0;
#endif
               thistime = mktime (startm);

#if HAVE_STRUCT_TM_TM_ZONE
               if (startm->tm_zone != NULL) {
                  char *tmzone = strdup(startm->tm_zone);
                  localtime_r (&thistime, startm);
                  if (strncpy(tmzone, startm->tm_zone, strlen(tmzone))) {
                     startm->tm_year = year;
                     startm->tm_mon  = month;
                     startm->tm_mday = day;
                     startm->tm_hour = hour;
                     thistime    = mktime (startm);
                  }
                  free(tmzone);
               }
#endif

            bcopy ((char *)startm, (char *)endtm, sizeof(struct tm));
               switch (retn) {
                  case ARGUS_YEAR:  endtm->tm_year++; year++; break;
                  case ARGUS_MONTH: endtm->tm_mon++; month++; break;
                  case ARGUS_DAY:   endtm->tm_mday++; day++; break;
                  case ARGUS_HOUR:  endtm->tm_hour++; hour++; break;
                  case ARGUS_MIN:   endtm->tm_min++; mins++; break;
                  case ARGUS_SEC:   endtm->tm_sec++; sec++; break;
                  default: break;
               }

               while (endtm->tm_sec  > 59) {endtm->tm_min++;  endtm->tm_sec -= 60;}
               while (endtm->tm_min  > 59) {endtm->tm_hour++; endtm->tm_min  -= 60;}
               while (endtm->tm_hour > 23) {endtm->tm_mday++; endtm->tm_hour -= 24;}
               while (endtm->tm_mday > RaDaysInAMonth[endtm->tm_mon]) {endtm->tm_mday -= RaDaysInAMonth[endtm->tm_mon]; endtm->tm_mon++;}
               while (endtm->tm_mon  > 11) {endtm->tm_year++; endtm->tm_mon  -= 12;}

#if HAVE_STRUCT_TM_TM_ZONE
               endtm->tm_isdst  = 0;
               endtm->tm_gmtoff = 0;
               endtm->tm_zone   = 0;
#endif
               thistime = mktime (endtm);
               localtime_r (&thistime, endtm);
               if (endtm->tm_zone != NULL) {
                  char *tmzone = strdup(endtm->tm_zone);
                  localtime_r (&thistime, endtm);
                  if (strncpy(tmzone, endtm->tm_zone, strlen(tmzone))) {
                     endtm->tm_year = year;
                     endtm->tm_mon  = month;
                     endtm->tm_mday = day;
                     endtm->tm_hour = hour;
                     thistime    = mktime (endtm);
                  }
                  free(tmzone);
               }
            }

            if (pptr != NULL)
               *pptr = '.';
         }
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
                  wildcarddate, startm, endtm, buf, mode, *frac, continued, rstr,
                  thistime);
   }
#endif
   return (retn);
}
