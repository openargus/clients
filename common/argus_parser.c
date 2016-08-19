/*
 * Argus Software
 * Copyright (c) 2000-2016 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/*
 * Argus Parser
 w
 * Routines needed to connect, read and parse Argus Records.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/argus/clients/common/argus_parser.c#53 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#ifndef ArgusParse
#define ArgusParse
#endif

#include <unistd.h>
#include <stdlib.h>
#include <argus_compat.h>

#include <syslog.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>

struct ArgusParserStruct *ArgusParser = NULL; 

/*

   struct ArgusParserStruct *
   ArgusNewParser (char *progname)

      This allocates a new parser struct, initializes the basic
      structures and returns with a pointer to the new struct.
      This struct contains all the globals that were previously
      used by ra* programs.

*/

extern void ArgusLog (int, char *, ...);

struct ArgusParserStruct *
ArgusNewParser(char *progname)
{
   struct ArgusParserStruct *retn = NULL;

   if ((retn  = (struct ArgusParserStruct *) ArgusCalloc(1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewParser(%s) ArgusCalloc error %s", progname, strerror(errno));

   retn->ArgusProgramName = strdup(progname);
   retn->ArgusCIDRPtr = &retn->ArgusCIDRBuffer;
   retn->RaTimeFormat = strdup("%T.%f");
   retn->ArgusFractionalDate = 1;

   retn->RaClientTimeout.tv_sec = 1;
   retn->RaCloseInputFd = 1;
   retn->Oflag  = 1;
   retn->nflag  = 1;
   retn->sNflag = -1;
   retn->eNflag = -1;
   retn->Lflag = -1;
   retn->pflag  = 6;
   retn->ArgusReverse = 1;
   retn->ArgusPerformCorrection = 1;
   retn->ArgusTimeMultiplier = 1.0;
   retn->RaSeparateAddrPortWithPeriod = 1;

   retn->timeout.tv_sec  = -1;
   retn->timeout.tv_usec =  0;

   retn->ArgusPassNum = 1;

   ArgusInitializeParser(retn);
   ArgusParser = retn;
   return (retn);
}

void
ArgusInitializeParser(struct ArgusParserStruct *parser)
{
   int i;

   parser->RaStartTime.tv_sec  = 0x7FFFFFFF;
   parser->RaStartTime.tv_usec = 0;
   parser->RaEndTime.tv_sec    = 0;
   parser->RaEndTime.tv_usec   = 0;

   parser->startime_t.tv_sec   = 0x7FFFFFFF;
   parser->lasttime_t.tv_sec   = 0;

   parser->ArgusTotalRecords    = 0;
   parser->ArgusTotalMarRecords = 0;
   parser->ArgusTotalFarRecords = 0;
   parser->ArgusTotalPkts       = 0;
   parser->ArgusTotalSrcPkts    = 0;
   parser->ArgusTotalDstPkts    = 0;
   parser->ArgusTotalBytes      = 0;
   parser->ArgusTotalSrcBytes   = 0;
   parser->ArgusTotalDstBytes   = 0;

   parser->RaLabelCounter       = 0;
   parser->RaFilterTimeout      = 1.5;

   if (parser->ArgusListens) {
      for (i = 0; i < parser->ArgusListens; i++)
         close(parser->ArgusLfd[i]);
   }

   parser->RaFieldWidth = RA_FIXED_WIDTH;
   parser->ArgusListens = 0;

   parser->ArgusGenerateManRecords = 1;

   for (i = 0; i < ARGUS_MAXLISTEN; i++)
      parser->ArgusLfd[i] = -1;

   if (parser->ArgusInputList == NULL)
      parser->ArgusInputList = ArgusNewList();

   if (parser->ArgusOutputList == NULL)
      parser->ArgusOutputList = ArgusNewList();

   if (parser->ArgusRemoteHosts == NULL)
      parser->ArgusRemoteHosts = ArgusNewQueue();

   if (parser->ArgusActiveHosts == NULL)
      parser->ArgusActiveHosts = ArgusNewQueue();

   if (parser->MySQLDBEngine != NULL) {
      free(parser->MySQLDBEngine);
      parser->MySQLDBEngine = NULL;
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&parser->lock, NULL);
#endif

   gettimeofday(&parser->ArgusStartRealTime, 0L);
   gettimeofday(&parser->ArgusRealTime, 0L);
}

void
ArgusCloseParser(struct ArgusParserStruct *parser)
{
   int z = 0;
/*
#define ARGUSPERFMETRICS		1
*/
#if defined(ARGUSPERFMETRICS)
   extern int ArgusAllocMax, ArgusAllocBytes;
   extern int ArgusAllocTotal, ArgusFreeTotal;

   struct timeval timediff;
   int x = 0 , len;
   double totaltime;
   char buf[256];

   long long ArgusTotalNewFlows;
   long long ArgusTotalClosedFlows;
   long long ArgusTotalSends;
   long long ArgusTotalBadSends;
   long long ArgusTotalUpdates;
   long long ArgusTotalCacheHits;

   char *ArgusIntStr[ARGUS_MAX_REMOTE];

   bzero(ArgusIntStr, sizeof(ArgusIntStr));

   if (parser && parser->ArgusInputFileList) {
      struct ArgusInput *addr = parser->ArgusInputFileList;

      while (addr) {
        if (addr->filename) {
           ArgusIntStr[x++] = strdup(addr->filename);
        }
        addr = (struct ArgusInput *)addr->qhdr.nxt;
      }
   }
/*
   for (i = 0; i < parser->tcount; i++) {
      if (parser->remote[i].input->hostname != NULL) {
         ArgusIntStr[x++] = strdup(parser->remote[i].input->hostname);
      }
   }
*/
#endif

#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&parser->lock);
#endif

   ArgusFreeEtherarray();
   ArgusFreeServarray(parser);
   ArgusFreeProtoidarray();
   ArgusFreeLlcsaparray();

   if (parser->ArgusModeList)
      ArgusDeleteModeList(parser);

   if (parser->ArgusInputFileList)
      ArgusDeleteFileList(parser);

   if (parser->ArgusInputList)
      ArgusDeleteList(parser->ArgusInputList, ARGUS_OUTPUT_LIST);

   if (parser->ArgusOutputList)
      ArgusDeleteList(parser->ArgusOutputList, ARGUS_OUTPUT_LIST);

   if (parser->ArgusRemoteHosts)
      ArgusDeleteQueue(parser->ArgusRemoteHosts);

   if (parser->ArgusActiveHosts)
      ArgusDeleteQueue(parser->ArgusActiveHosts);

   if (parser->ArgusWfileList != NULL)
      ArgusDeleteList(parser->ArgusWfileList, ARGUS_WFILE_LIST);

   if (parser->ArgusLabeler != NULL)
      ArgusDeleteLabeler (parser, parser->ArgusLabeler);

   if (parser->ArgusLocalLabeler != NULL)
      ArgusDeleteLabeler (parser, parser->ArgusLocalLabeler);

   if (parser->ArgusColorLabeler != NULL)
      ArgusDeleteLabeler (parser, parser->ArgusColorLabeler);

   if (parser->ArgusColorConfig != NULL)
      free (parser->ArgusColorConfig);

   if (parser->ArgusAggregator != NULL) {
#if defined(ARGUSPERFMETRICS)
      struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
      do {
         ArgusTotalNewFlows    = agg->ArgusTotalNewFlows;
         ArgusTotalClosedFlows = agg->ArgusTotalClosedFlows;
         ArgusTotalSends       = agg->ArgusTotalSends;
         ArgusTotalBadSends    = agg->ArgusTotalBadSends;
         ArgusTotalUpdates     = agg->ArgusTotalUpdates;
         ArgusTotalCacheHits   = agg->ArgusTotalCacheHits;
         agg = agg->nxt;
      } while (agg != NULL);
#endif
      ArgusDeleteAggregator(parser, parser->ArgusAggregator);
   }

/*
   if ((tcount = parser->tcount) > 0) {
      struct ArgusInput *input = NULL;
      for (i = 0; i < tcount; i++) {
         if ((input = parser->remote[i].input) != NULL) {
            ArgusCloseInput(parser, input);
            parser->remote[i].input = NULL;
         }
      }
   }
*/

   if (parser->RaSortOptionIndex > 0) {
      int i;
      for (i = 0; i < parser->RaSortOptionIndex; i++) 
         free(parser->RaSortOptionStrings[i]);
   }

   if (parser->ArgusEthernetVendorFile != NULL)
      free (parser->ArgusEthernetVendorFile);

   if (parser->RaTimeFormat != NULL)
      free (parser->RaTimeFormat);

   if (parser->RaTimeZone != NULL)
      free (parser->RaTimeZone);

   if (parser->pstr != NULL)
      free(parser->pstr);

   if (parser->ustr != NULL)
      free(parser->ustr);

   if (parser->ArgusPidPath != NULL)
      free( parser->ArgusPidPath);

   if (parser->ArgusProgramOptions != NULL)
      free(parser->ArgusProgramOptions);

   if (parser->MySQLDBEngine != NULL)
      free(ArgusParser->MySQLDBEngine);

   parser->debugflag = -1;

   if (parser->ArgusProgramArgs != NULL)
      ArgusFree(parser->ArgusProgramArgs);

#if defined(ARGUSPERFMETRICS)
   if (parser->ArgusEndRealTime.tv_sec == 0)
      gettimeofday (&parser->ArgusEndRealTime, 0L);

   bzero(buf, sizeof(buf));

   timediff.tv_sec  = parser->ArgusEndRealTime.tv_sec  - parser->ArgusStartRealTime.tv_sec;
   timediff.tv_usec = parser->ArgusEndRealTime.tv_usec - parser->ArgusStartRealTime.tv_usec;
 
   if (timediff.tv_usec < 0) {
      timediff.tv_usec += 1000000;
      timediff.tv_sec--;
   }
 
   totaltime = (double) timediff.tv_sec + (((double) timediff.tv_usec)/1000000.0);

   if (parser->estr != NULL) {
      int i;
      free(parser->estr);
      for (i = 0; i < parser->ArgusRegExItems; i++)
         regfree(&parser->upreg[i]);
   }

   if (parser->ArgusMatchLabel != NULL) {
      free(parser->ArgusMatchLabel);
      parser->ArgusMatchLabel = NULL;
      regfree(&parser->lpreg);
   }

/*
   {
      char sbuf[MAXSTRLEN];
      if (ArgusSourceTask->ArgusInterface[i].ArgusDevice != NULL) {
         sprintf (sbuf, "%s\n    Total Pkts %8lld  Rate %f\n",
                     ArgusSourceTask->ArgusInterface[i].ArgusDevice->name, ArgusSourceTask->ArgusInterface[i].ArgusTotalPkts,
                     ArgusSourceTask->ArgusInterface[i].ArgusTotalPkts/totaltime);
         ArgusIntStr[i] = strdup(sbuf);
      }
   }
*/

   len = strlen(parser->ArgusProgramName);
   for (i = 0; i < len; i++)
      buf[i] = ' ';
/*
   if (ArgusTotalNewFlows > 0) {
      extern int ArgusAllocTotal, ArgusFreeTotal, ArgusAllocMax;

      fprintf (stderr, "%s: Time %d.%06d Flows %-8lld  Closed %-8lld  Sends %-8lld  BSends %-8lld\n",
                         parser->ArgusProgramName, (int)timediff.tv_sec, (int)timediff.tv_usec,
                         ArgusTotalNewFlows,  ArgusTotalClosedFlows,
                         ArgusTotalSends, ArgusTotalBadSends);
      fprintf (stderr, "%*s  Updates %-8lld Cache %-8lld\n", (int)strlen(parser->ArgusProgramName), " ",
                         ArgusTotalUpdates, ArgusTotalCacheHits);
      fprintf (stderr, "%*s  Total Memory %-8d Free %-8d MaxBytes %d\n", (int)strlen(parser->ArgusProgramName), " ",
                         ArgusAllocTotal, ArgusFreeTotal, ArgusAllocMax);
   }
*/
/*
   for (i = 0; i < ARGUS_MAX_REMOTE; i++) {
      if (ArgusIntStr[i] != NULL) {
*/
   {
         float rate = parser->ArgusTotalRecords / totaltime;
         fprintf (stderr, "%s: Source: %s\n", parser->ArgusProgramName, ArgusIntStr[0]);
         fprintf (stderr, "Time %d.%06d    Records %-8lld Rate %-5.4f rps\n",
                            (int)timediff.tv_sec, (int)timediff.tv_usec,
                            parser->ArgusTotalRecords, rate);
         fprintf (stderr, "%*s  Total Memory %-8d Free %-8d MaxBytes %d\n", (int)strlen(parser->ArgusProgramName), " ",
                            ArgusAllocTotal, ArgusFreeTotal, ArgusAllocMax);
         free(ArgusIntStr[i]);
   }
/*
      }
   }
*/
#endif

#if defined(ARGUS_THREADS)
   pthread_mutex_destroy(&parser->lock);
#endif

   if (parser->ArgusProgramName != NULL)
      free(parser->ArgusProgramName);

   if (parser->ArgusDelegatedIPFile != NULL)
      free (parser->ArgusDelegatedIPFile);
   if (parser->readDbstr != NULL)
      free (parser->readDbstr);
   if (parser->dbuserstr != NULL)
      free (parser->dbuserstr);
   if (parser->dbpassstr != NULL)
      free (parser->dbpassstr);
   if (parser->dbportstr != NULL)
      free (parser->dbportstr);
   if (parser->dbhoststr != NULL)
      free (parser->dbhoststr);
   if (parser->dbportstr != NULL)
      free (parser->dbportstr);
   if (parser->ais != NULL)
      free (parser->ais);

   if (parser->ArgusAggregatorFile != NULL)
      free (parser->ArgusAggregatorFile);

   if (parser->ArgusFlowModelFile != NULL)
      free (parser->ArgusFlowModelFile);

   if (parser->RaFlowModelFile != NULL)
      free (parser->RaFlowModelFile);

   if (parser->ArgusRemoteFilter != NULL)
      free (parser->ArgusRemoteFilter);

   ArgusDeleteMaskList(parser);

   while (parser->RaPrintAlgorithmList[z] != NULL) {
      ArgusFree (parser->RaPrintAlgorithmList[z]);
      z++;
   }
   ArgusFree(parser);
   return;
}
