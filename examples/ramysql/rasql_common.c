#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/syslog.h>
#include "argus_util.h"
#include "argus_parser.h"
#include "argus_client.h"
#include "rasplit.h"

#define ARGUS_MAX_TABLE_LIST_SIZE	0x10000

extern int RaDaysInAMonth[12];

char **
ArgusCreateSQLTimeTableNames (struct ArgusParserStruct *parser,
                              time_t *ArgusTableStartSecs,
                              time_t *ArgusTableEndSecs,
                              int ArgusSQLSecondsTable,
                              const struct ArgusAdjustStruct * const nadp,
                              const char * const table)
{
   char **retn = NULL, *fileStr = NULL;
   char *ArgusSQLTableNameBuf;
   int retnIndex = 0;

   if ((retn = ArgusCalloc(sizeof(void *), ARGUS_MAX_TABLE_LIST_SIZE)) == NULL)
      ArgusLog(LOG_ERR, "%s ArgusCalloc %s", __func__, strerror(errno));

   ArgusSQLTableNameBuf = ArgusMalloc(MAXSTRLEN);
   if (ArgusSQLTableNameBuf == NULL)
      ArgusLog(LOG_ERR, "%s failed to allocate memory for table name %s",
               __func__, strerror(errno));

   retnIndex = 0;

   if (table && (strchr(table, '%') || strchr(table, '$'))) {
      if (nadp->size > 0) {
         int size = nadp->size / 1000000;
         long long start;
         time_t tableSecs;
         struct tm tmval;

         if (parser->startime_t.tv_sec > 0) {
            start = parser->startime_t.tv_sec * 1000000LL;
         } else
            start = parser->ArgusRealTime.tv_sec * 1000000LL + parser->ArgusRealTime.tv_usec;

         if (parser->lasttime_t.tv_sec > parser->ArgusRealTime.tv_sec)
            parser->lasttime_t = parser->ArgusRealTime;

         *ArgusTableEndSecs = start / 1000000;

         while (*ArgusTableEndSecs < parser->lasttime_t.tv_sec) {
               fileStr = NULL;
               tableSecs = *ArgusTableEndSecs;

               switch (nadp->qual) {
                  case ARGUSSPLITYEAR:
                  case ARGUSSPLITMONTH:
                  case ARGUSSPLITWEEK: 
                     gmtime_r(&tableSecs, &tmval);
                     break;
               }

               switch (nadp->qual) {
                  case ARGUSSPLITYEAR:
                     tmval.tm_mon = 0;
                  case ARGUSSPLITMONTH:
                     tmval.tm_mday = 1;

                  case ARGUSSPLITWEEK: 
                     if (nadp->qual == ARGUSSPLITWEEK) {
                        if ((tmval.tm_mday - tmval.tm_wday) < 0) {
                           if (tmval.tm_mon == 0) {
                              if (tmval.tm_year != 0)
                                 tmval.tm_year--;
                              tmval.tm_mon = 11;
                           } else {
                              tmval.tm_mon--;
                           }
                           tmval.tm_mday = RaDaysInAMonth[tmval.tm_mon];
                        }
                        tmval.tm_mday -= tmval.tm_wday;
                     }

                     tmval.tm_hour = 0;
                     tmval.tm_min  = 0;
                     tmval.tm_sec  = 0;
                     tableSecs = timegm(&tmval);
                     localtime_r(&tableSecs, &tmval);
#if defined(HAVE_TM_GMTOFF)
                     tableSecs -= tmval.tm_gmtoff;
#endif
                     break;

                  case ARGUSSPLITDAY:
                  case ARGUSSPLITHOUR:
                  case ARGUSSPLITMINUTE:
                  case ARGUSSPLITSECOND: {
                     localtime_r(&tableSecs, &tmval);
#if defined(HAVE_TM_GMTOFF)
                     tableSecs += tmval.tm_gmtoff;
#endif
                     tableSecs = tableSecs / size;
                     tableSecs = tableSecs * size;
#if defined(HAVE_TM_GMTOFF)
                     tableSecs -= tmval.tm_gmtoff;
#endif
                     break;
                  }
               }

               localtime_r(&tableSecs, &tmval);

               if (strftime(ArgusSQLTableNameBuf, MAXSTRLEN, table, &tmval) <= 0)
                  ArgusLog (LOG_ERR, "RaSendArgusRecord () ArgusCalloc %s\n", strerror(errno));

               *ArgusTableStartSecs = tableSecs;

               switch (nadp->qual) {
                  case ARGUSSPLITYEAR:  
                     tmval.tm_year++;
                     *ArgusTableEndSecs = mktime(&tmval);
                     break;
                  case ARGUSSPLITMONTH:
                     tmval.tm_mon++;
                     *ArgusTableEndSecs = mktime(&tmval);
                     break;
                  case ARGUSSPLITWEEK: 
                  case ARGUSSPLITDAY: 
                  case ARGUSSPLITHOUR: 
                  case ARGUSSPLITMINUTE: 
                  case ARGUSSPLITSECOND: 
                     *ArgusTableEndSecs = tableSecs + size;
                     break;
               }

               fileStr = ArgusSQLTableNameBuf;

               if (fileStr != NULL) {
                  retn[retnIndex++] = strdup(fileStr);
               }
            }

            /* when looking at explicit table expansion, we shouldn't
             * go to the Seconds table
             */

         } else
            ArgusLog(LOG_ERR, "ArgusCreateSQLTimeTableNames no time mode (-M time xx) specified");

      } else {
         if (table) {
            bcopy(table, ArgusSQLTableNameBuf, strlen(table));
            fileStr = ArgusSQLTableNameBuf;

            if (retn == NULL) {
               if ((retn = ArgusCalloc(sizeof(void *), 16)) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCreateSQLTimeTableNames ArgusCalloc %s", strerror(errno));
               retnIndex = 0;
            }

            retn[retnIndex++] = strdup(fileStr);

         } else
            if (ArgusSQLSecondsTable)
               retn[retnIndex++] = strdup("Seconds");
      }

   ArgusFree(ArgusSQLTableNameBuf);
   return (retn);
}
