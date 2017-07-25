/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2016 QoSient, LLC
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
 * $Id: //depot/gargoyle/clients/examples/radhcp/radhcp.c#7 $
 * $DateTime: 2016/11/30 00:54:11 $
 * $Change: 3245 $
 */

/*
 *     radhcp.c  - process DHCP requests from argus data
 *                 extract DHCP query and response into a DHCP structure
 *                 that allows for fast processing of DHCP relevant data.
 */


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>

#if defined(HAVE_ARPA_INET_H)
#include <arpa/inet.h>
#endif

#include <argus_compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <argus_label.h>
#include <argus_output.h>
#include "argus_threads.h"
#include "rabootp_timer.h"
#include "rabootp_proto_timers.h"
#include "rabootp_interval_tree.h" /* for ArgusHandleSearchCommand.  maybe move this function */
#include "rabootp_memory.h" /* for ArgusHandleSearchCommand.  maybe move this function */
#include "rabootp_print.h"
#include "rabootp_patricia_tree.h"
#include "rabootp_lease_pullup.h"
#include "argus_format_json.h"
#include "rabootp_l2addr_list.h"
#include "rabootp_sql.h"
#include "rasql.h"

#if defined(ARGUS_MYSQL)
#include <mysql.h>

extern pthread_mutex_t RaMySQLlock;
extern MYSQL *RaMySQL;
extern struct RaBinProcessStruct *RaBinProcess;
#endif

struct RaBinProcessStruct *RaBinProcess;

#if defined(HAVE_ZLIB_H)
#include <zlib.h>
#endif

#include <interface.h>
#include <rabootp.h>

#define RaDomain   1

#include <signal.h>
#include <ctype.h>

char ArgusBuf[MAXSTRLEN];

int ArgusThisEflag = 0;
int ArgusDebugTree = 0;

struct ArgusAggregatorStruct *ArgusEventAggregator = NULL;

void RaArgusInputComplete (struct ArgusInput *input) {};
int RaTreePrinted = 0;
int RaPruneLevel = 0;

/* max number of interval-tree nodes to allocate in an array for searching */
static const size_t INVECMAX = 16*1024;

struct RaProcessStruct {
   int status, timeout;
   int value, size;
   struct ArgusRecordStruct *ns;
   struct ArgusQueueStruct *queue, *delqueue;
   struct ArgusHashTable *htable;
   struct nff_program filter;
};

struct RaProcessStruct *RaEventProcess = NULL;
struct RaProcessStruct *RaNewProcess(struct ArgusParserStruct *);

extern char *ArgusTrimString (char *);

char *ArgusHandleResponseArray[1024];

char **ArgusHandleTreeCommand (char *);
char **ArgusHandleSearchCommand (char *);

static struct RabootpTimerStruct *timer = NULL;
static pthread_t timer_thread;

int ArgusParseTime (char *, struct tm *, struct tm *, char *, char, int *, int);
static char temporary[32];
static char *invecstr;
static char *global_query_str;
static const unsigned long INVECSTRLEN = 1024*1024; /* 1 MB */
static const struct ArgusFormatterTable *fmtable = &ArgusJsonFormatterTable;

static const size_t INTVL_NODE_ARRAY_MAX = 64;

struct invecTimeRangeStruct {
   struct invecStruct *x;
   const struct timeval * starttime;
   const struct timeval * endtime;
};

static int
__is_oneshot_query(void)
{
   if (global_query_str != NULL)
      return 1;
   return 0;
}

static int
__search_ipaddr_cb(struct rabootp_l2addr_entry *e, void *arg)
{
   struct invecTimeRangeStruct *itr = arg;
   struct invecStruct *x = itr->x;
   ssize_t count;

   count = IntvlTreeOverlapsRange(e->datum,
                                  itr->starttime,
                                  itr->endtime,
                                  &x->invec[x->used],
                                  x->nitems - x->used);

   if (count > 0)
      x->used += count;

   return 0;
}

static int
__search_ipaddr(const struct in_addr * const addr,
                const struct timeval * const starttime,
                const struct timeval * const endtime,
                struct ArgusDhcpIntvlNode *invec,
                size_t invec_nitems)
{
   struct RaAddressStruct *ras;
   struct invecTimeRangeStruct itr;
   struct invecStruct x;
   size_t i;
   int rv = 0;

   MUTEX_LOCK(&ArgusParser->lock);

   ras = RabootpPatriciaTreeFind(&addr->s_addr, ArgusParser);
   if (ras == NULL)
     goto out;

   x.nitems = invec_nitems;
   x.used = 0;
   x.invec = invec;

   if (x.invec == NULL)
      goto out;

   itr.x = &x;
   itr.starttime = starttime;
   itr.endtime = endtime;

   rabootp_l2addr_list_foreach(ras->obj, __search_ipaddr_cb, &itr);

   rv = (int)x.used;

out:
   MUTEX_UNLOCK(&ArgusParser->lock);
   return rv;
}

/* SEARCH: <argus-time-string> */
char **
ArgusHandleSearchCommand (char *command)
{
   int res = 0; /* ok */
   char *string = &command[8];
   char **retn = ArgusHandleResponseArray;
   struct ArgusDhcpIntvlNode *invec, *tmp_invec;
   size_t invec_nitems = 0;
   ssize_t invec_used, tmp_invec_used;
   int pullup = 0; /* combine consecutive leases for same mac/ip pair */

   struct tm starttime = {0, };
   struct tm endtime = {0, };
   int frac;
   time_t tsec = ArgusParser->ArgusGlobalTime.tv_sec;
   struct timeval starttime_tv;
   struct timeval endtime_tv;
   struct in_addr addr = {0, };


   /* Also remember where in the string the separator was. */
   char *plusminusloc = NULL;
   int off = 0;
   char wildcarddate = 0;

   /* If the date string has two parts, remember which character
    * separates them.
    */
   char plusminus;

   bzero(retn, sizeof(ArgusHandleResponseArray));

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

   /* Look for the end of the time string.  If not compound, string[off] is
    * the end.  Otherwise, keep looking.
    */
   while (!isspace(string[off]) && string[off] != '\0') {
      off++;
   }

   /* Replace the whitespace in between the time and IP address (if any) with
    * NULL characters.
    */
   while (isspace(string[off]) && string[off] != '\0') {
      string[off] = '\0';
      off++;
   }

   if (string[off] != '\0') {
      if (string[off] == 'i' && string[off+1] == 'p' && string[off+2] == '=') {
         DEBUGLOG(1, "%s: Checking for IP address in command (str=%s)\n",
                  __func__, &string[off+3]);
         /* unsafe - no check for null term */
         if (inet_aton(&string[off+3], &addr) != 1) {
            retn[0] = "Invalid IP address\n";
            retn[1] = "FAIL\n";
            res = -1;
            goto out;
         }
         addr.s_addr = ntohl(addr.s_addr);
         DEBUGLOG(1, "%s: Searching for IP address 0x%08x\n", __func__, addr.s_addr);
         /* skip over the ip=... */
         while (!isspace(string[off]) && string[off] != '\0')
            off++;

         /* and any spaces after */
         while (isspace(string[off]) && string[off] != '\0')
            off++;
      }
   }

   if (!strcasecmp(&string[off], "pullup"))
      pullup = 1;

   localtime_r(&tsec, &endtime);

   if (ArgusParseTime(&wildcarddate, &starttime, &endtime,
                      string, ' ', &frac, 0) <= 0) {
      retn[0] = "FAIL\n";
      res = -1;
      goto out;
   }

   if (plusminusloc) {
      if (ArgusParseTime(&wildcarddate, &endtime, &starttime,
                         plusminusloc+1, plusminus, &frac, 1) <= 0) {
         retn[0] = "FAIL\n";
         res = -1;
         goto out;
      }
   } else if (string[0] != '-') {
      /* Not a time relative to "now" AND not a time range */
      endtime = starttime;
   }

   invec_nitems = RabootpIntvlTreeCount();
   if (invec_nitems == 0)
      invec_nitems = 1;
   else if (invec_nitems > INVECMAX)
      invec_nitems = INVECMAX;

   invec = ArgusMalloc(invec_nitems * sizeof(struct ArgusDhcpIntvlNode));
   if (invec == NULL)
      goto out;

   starttime_tv.tv_sec = mktime(&starttime);
   starttime_tv.tv_usec = 0;
   endtime_tv.tv_sec = mktime(&endtime);
   endtime_tv.tv_usec = 0;

   tmp_invec = ArgusMalloc(sizeof(*tmp_invec)*invec_nitems);
   if (tmp_invec == NULL) {
      retn[0] = "Not enough memory\n";
      retn[1] = "FAIL\n";
      retn[2] = NULL;
      res = -1;
      goto out;
   }

   if (addr.s_addr == 0) {
      tmp_invec_used = RabootpIntvlTreeOverlapsRange(&starttime_tv, &endtime_tv,
                                                     tmp_invec, invec_nitems);

      if (tmp_invec_used < 0) {
         retn[0] = "FAIL\n";
         retn[1] = NULL;
         res = -1;
         ArgusFree(tmp_invec);
         goto out;
      }

      /* If we're going to combine consecutive leases, need to first sort
       * the array.
       */
      if (tmp_invec_used > 0 && pullup)
         RabootpLeasePullupSort(tmp_invec, tmp_invec_used);
   } else {
      tmp_invec_used = __search_ipaddr(&addr, &starttime_tv, &endtime_tv,
                                       tmp_invec, invec_nitems);
      if (tmp_invec_used < 0) {
         retn[0] = "FAIL\n";
         retn[1] = NULL;
         res = -1;
         ArgusFree(tmp_invec);
         goto out;
      }
   }

   if (pullup) {
      invec_used = RabootpLeasePullup(tmp_invec, tmp_invec_used,
                                      invec, invec_nitems);
      while (tmp_invec_used > 0) {
        tmp_invec_used--;
        ArgusDhcpStructFree(tmp_invec[tmp_invec_used].data);
      }
   } else {
      invec_used = tmp_invec_used;
      while (tmp_invec_used > 0) {
        tmp_invec_used--;
        invec[tmp_invec_used] = tmp_invec[tmp_invec_used];
      }
   }
   ArgusFree(tmp_invec);

   if (invec_used < 0) {
         retn[0] = "FAIL\n";
         res = -1;
         goto out;
   }

   /* format string here */
   /* TEMP: output number of transactions found */
   snprintf(temporary, sizeof(temporary), "%zd\n", invec_used);
   retn[0] = &temporary[0];

   /* only dump search results to database if the query was supplied
    * on the commandline.
    */
   if (global_query_str && ArgusParser->writeDbstr) {
      ssize_t i;

      for (i = 0; i < invec_used; i++) {
         struct ArgusDhcpStruct *ads = invec[i].data;
         ArgusCreateSQLSaveTable(RaDatabase, ads->sql_table_name);
         RabootpSQLInsertOne(ArgusParser, &invec[i], ads->sql_table_name);
      }
   } else {
      invecstr[0] = '\0';
      memset(invecstr, 0, INVECSTRLEN); /* FIXME: this shouldn't be necessary */

      /* leave a little room at the end of the buffer because
       * ArgusPrintTime() doesn't take a length parameter so we can't
       * tell it when to stop!
       */
      RabootpPrintDhcp(ArgusParser, invec, invec_used, invecstr, INVECSTRLEN-64, fmtable);
      retn[1] = invecstr;
   }

   while (invec_used > 0) {
     invec_used--;
     ArgusDhcpStructFree(invec[invec_used].data);
   }
   ArgusFree(invec);

out:

#ifdef ARGUSDEBUG
   {
      char t1[32], t2[32];
      int i;

      asctime_r(&starttime, t1);
      asctime_r(&endtime, t2);

      for (i = 0; i < sizeof(t1) && t1[i] != '\0'; i++) {
         if (t1[i] == '\n')
            t1[i] = '\0';
      }
      for (i = 0; i < sizeof(t2) && t2[i] != '\0'; i++) {
         if (t2[i] == '\n')
            t2[i] = '\0';
      }
      ArgusDebug (1, "ArgusHandleSearchCommand(%s) search %s 'til %s %s",
                  string, t1, t2, res ? "FAIL" : "OK");
   }
#endif
   return retn;
}

char **
ArgusHandleTreeCommand (char *command)
{
   static char buf[4096];

   char *string = &command[6], *sptr;
   char **retn = ArgusHandleResponseArray;
   char *result;
   int verbose = 0;
 
   if (*string == 'v')
      verbose = 1;

   buf[0] = '\0';
   result = RabootpDumpTreeStr(verbose);
   if (result) {
      strncpy(&buf[0], result, sizeof(buf));
      free(result);
   }
 
   if (result) {
      retn[0] = "OK\n";
      retn[1] = &buf[0];
      retn[2] = "\n";
      retn[3] = NULL;
   } else {
      retn[0] = "FAIL\n";
      retn[1] = NULL;
   }

   RabootpIntvlTreeDump();

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s(%s) result %s", __func__, string, retn[0]);
#endif
   return retn;
}


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct RaAddressStruct **ArgusAddrTree;
   struct ArgusModeStruct *mode = NULL;
   parser->RaWriteOut = 1;

   if (!(parser->RaInitialized)) {

/*
   the library sets signal handling routines for 
   SIGHUP, SIGTERM, SIGQUIT, SIGINT, SIGUSR1, and SIGUSR2.
   SIGHUP doesn't do anything, SIGTERM, SIGQUIT, and SIGINT
   call the user supplied RaParseComplete().  SIGUSR1 and
   SIGUSR2 modify the debug level so if compiled with
   ARGUS_DEBUG support, programs can start generating 
   debug information.  USR1 increments by 1, USR2 sets
   it back to zero.

*/
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      ArgusThisEflag = parser->eflag;
      parser->eflag = ARGUS_HEXDUMP;

      if ((ArgusLabeler = ArgusNewLabeler(parser, ARGUS_LABELER_ADDRESS)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      if (ArgusLabeler->ArgusAddrTree == NULL)
         if ((ArgusLabeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog (LOG_ERR, "RaReadAddressConfig: ArgusCalloc error %s\n", strerror(errno));

      ArgusAddrTree = ArgusLabeler->ArgusAddrTree;
      parser->ArgusLabeler = ArgusLabeler;

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if (ArgusAddrTree[AF_INET] != NULL)
         RaLabelMaskAddressStatus(ArgusAddrTree[AF_INET], ~ARGUS_VISITED);

      if ((ArgusEventAggregator = ArgusNewAggregator(parser, "srcid saddr daddr proto sport dport", ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE_VISITED;

      if ((mode = parser->ArgusModeList) != NULL) {
         struct ArgusModeStruct *nxtmode;
         int splitmode = -1;

         while (mode) {

            nxtmode = RaParseSplitMode(parser, &RaBinProcess, mode, &splitmode);
            if (nxtmode != mode) {
               mode = nxtmode;
               continue;
            }

            if ((!(strncasecmp (mode->mode, "debug.tree", 10))) ||
                (!(strncasecmp (mode->mode, "debug", 5)))) {
               ArgusDebugTree = 1;
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE;
               RaPrintLabelTree (ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0);
            } else
            if (!(strncasecmp (mode->mode, "nocontrol", 9))) {
               parser->ArgusControlPort = 0;
            } else
            if (!(strncasecmp (mode->mode, "control:", 8))) {
               char *ptr = &mode->mode[8];
               double value = 0.0;
               char *endptr = NULL;
               value = strtod(ptr, &endptr);
               if (ptr != endptr) {
                  parser->ArgusControlPort = value;
               }
            } else
            if (!(strncasecmp (mode->mode, "graph", 5))) {
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_GRAPH;
            } else
            if (!(strncasecmp (mode->mode, "rmon", 4))) {
               parser->RaMonMode++;
            } else
            if (!(strncasecmp (mode->mode, "prune", 5))) {
               char *ptr, *str;
               parser->RaPruneMode++;
               if ((str = strchr(mode->mode, '/')) != NULL) {
                  RaPruneLevel = strtod(++str, (char **)&ptr);
                  if (ptr == str)
                     ArgusLog (LOG_ERR, "ArgusClientInit: prune syntax error");
               }
            } else
            if (!strncasecmp(mode->mode, "json-obj-only", 13)) {
               fmtable = &ArgusJsonObjOnlyFormatterTable;
            } else
            if (!strncasecmp(mode->mode, "query:", 6)) {
               global_query_str = strdup(mode->mode+6);
            }
            mode = mode->nxt;
         }
      }

      if ((RaEventProcess = RaNewProcess(parser)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: RaNewProcess error");

      parser->RaInitialized++;

      if (parser->ArgusControlPort != 0) {
         struct timeval *tvp = getArgusMarReportInterval(ArgusParser);

         if ((parser->ArgusControlChannel = ArgusNewControlChannel (parser)) == NULL)
            ArgusLog (LOG_ERR, "could not create control channel: %s\n", strerror(errno));

         if (ArgusEstablishListen (parser, parser->ArgusControlChannel,
                                   parser->ArgusControlPort, "127.0.0.1",
                                   ARGUS_VERSION) < 0)
            ArgusLog (LOG_ERR, "setArgusPortNum: ArgusEstablishListen returned %s", strerror(errno));

         if ((tvp->tv_sec == 0) && (tvp->tv_usec == 0)) {
            setArgusMarReportInterval (ArgusParser, "60s");
         }

         ArgusControlCommands[CONTROL_TREE].handler   = ArgusHandleTreeCommand;
         ArgusControlCommands[CONTROL_SEARCH].handler = ArgusHandleSearchCommand;
      }

#if defined(ARGUS_MYSQL)
      RaMySQLInit();
#endif
      RabootpCallbacksInit(parser);
      timer = RabootpTimerInit(NULL, NULL); /* for now */
      if (!__is_oneshot_query()) {
         if (pthread_create(&timer_thread, NULL, RabootpTimer, timer) < 0)
            ArgusLog(LOG_ERR, "%s: unable to create timer thread\n", __func__);
         RabootpProtoTimersInit(timer);
      }
   }

   invecstr = ArgusMalloc(INVECSTRLEN);
   if (invecstr == NULL)
      ArgusLog(LOG_ERR, "could not allocate memory for query results\n");
}


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!(ArgusParser->RaParseCompleting++)) {
         int ArgusExitStatus = 0;

         if (global_query_str) {
            int i = 0;

            ArgusHandleSearchCommand(global_query_str);
            while (ArgusHandleResponseArray[i]) {
               printf("%s", ArgusHandleResponseArray[i]);
               i++;
            }
            free(global_query_str);
         }

         if (ArgusDebugTree)
            RabootpDumpTree();
         ArgusShutDown(sig);
         ArgusExitStatus = ArgusParser->ArgusExitStatus;

#if defined(ARGUS_MYSQL)
         mysql_close(RaMySQL);
#endif
         if (!__is_oneshot_query()) {
            pthread_join(timer_thread, NULL);
            RabootpProtoTimersCleanup(timer);
            RabootpTimerCleanup(timer);
         }
         RabootpCallbacksCleanup();
         RabootpCleanup();
         ArgusFree(invecstr);

         ArgusCloseParser(ArgusParser);
         exit (ArgusExitStatus);
      }
   }
}

void
ArgusClientTimeout ()
{
#ifdef ARGUSDEBUG
   ArgusDebug (6, "%s()\n", __func__);
#endif
}

void
parse_arg (int argc, char**argv)
{}

void
usage ()
{
   extern char version[];

   fprintf (stdout, "Radns Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] [ra-options]  [- filter-expression]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -v          print verbose protocol information.\n");
   fprintf (stdout, "         -s +suser   dump the source user data buffer.\n");
   fprintf (stdout, "            +duser   dump the destination user buffer.\n");
   fflush (stdout);
   exit(1);
}

#define ISPORT(p) (dport == (p) || sport == (p))

void RaProcessEventRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessThisEventRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessManRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   char buf[MAXSTRLEN], tbuf[64];

   bzero (buf, MAXSTRLEN);
   bzero (tbuf, 64);
   ArgusPrintStartDate(parser, tbuf, argus, 32);
   ArgusTrimString(tbuf);

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_EVENT:
         RaProcessEventRecord(parser, argus);
         break;

      case ARGUS_MAR:
         RaProcessManRecord(parser, argus);
         break;

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];

         unsigned short proto = 0, sport = 0, dport = 0;
         int type, process = 0, dhcpTransaction = 0;

         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch ((type = flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_IPV4: {
                        proto = flow->ip_flow.ip_p;
                        process++;

                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_UDP: {
                              sport = flow->ip_flow.sport;
                              dport = flow->ip_flow.dport;
                              break;
                           }
                        }

                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        switch (flow->ipv6_flow.ip_p) {
                           case IPPROTO_UDP: {
                              proto = flow->ipv6_flow.ip_p;
                              sport = flow->ipv6_flow.sport;
                              dport = flow->ipv6_flow.dport;
                              break;
                           }
                        }
                        break;
                     }
                  }
                  break;
               }
            }
         }

         if (process) {
            switch (proto) {
               case IPPROTO_UDP: 
                  if (ISPORT(IPPORT_BOOTPS) || ISPORT(IPPORT_BOOTPC))
                     dhcpTransaction++;
                  break;
            }

            if (dhcpTransaction) {
               if (ArgusParseDhcpRecord(parser, argus, timer) != NULL) {
                  DEBUGLOG(2, "%s: %s", __func__, ArgusBuf);
                  ArgusBuf[0] = '\0';
               }

            } else {
            }
         }
         break;
      }
   }
}


void
RaProcessEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   if (parser->ArgusCorrelateEvents) {
      struct ArgusTimeObject *time = (void *)argus->dsrs[ARGUS_TIME_INDEX];
      struct ArgusDataStruct *data = NULL;
      struct timeval tvpbuf, *tvp = &tvpbuf;
      char buf[0x10000], *ptr = buf;
      char tbuf[129], sbuf[129], *sptr = sbuf;
      char *dptr, *str;
      unsigned long len = 0x10000;
      int title = 0;

      if ((data = (void *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) == NULL)
         return;

      if (data->hdr.subtype & ARGUS_DATA_COMPRESS) {
#if defined(HAVE_ZLIB_H)
         bzero (ptr, sizeof(buf));
         uncompress((Bytef *)ptr, (uLongf *)&len, (Bytef *)&data->array, data->count);
         dptr = ptr;
#else
#if defined(ARGUSDEBUG)
         ArgusDebug (3, "RaProcessEventRecord: unable to decompress payload\n");
#endif
         return;
#endif
      } else {
         dptr = data->array;
      }

      if (strstr(dptr, "argus-lsof")) {
         tbuf[0] = '\0';
         bzero (sptr, sizeof(sbuf));
         tvp->tv_sec  = time->src.start.tv_sec;
         tvp->tv_usec = time->src.start.tv_usec;

         ArgusPrintTime(parser, tbuf, sizeof(tbuf), tvp);
         ArgusPrintSourceID(parser, sptr, argus, 24);

         while (isspace((int)sbuf[strlen(sbuf) - 1]))
            sbuf[strlen(sbuf) - 1] = '\0';

         while (isspace((int)*sptr)) sptr++;

// COMMAND     PID           USER   FD   TYPE     DEVICE SIZE/OFF   NODE NAME

         while ((str = strsep(&dptr, "\n")) != NULL) {
            if (title) {
               char *tok, *app = NULL, *pid = NULL, *user = NULL;
               char *node = NULL, *name = NULL, *state = NULL;
               int field = 0;
               while ((tok = strsep(&str, " ")) != NULL) {
                  if (*tok != '\0') {
                     switch (field++) {
                        case 0: app  = tok; break;
                        case 1: pid  = tok; break;
                        case 2: user = tok; break;
                        case 7: node = tok; break;
                        case 8: name = tok; break;
                        case 9: state = tok; break;
                     }
                  }
               }
               if (name != NULL) {
                  short proto = 0;

                  if (!(strcmp("TCP", node))) proto = IPPROTO_TCP;
                  else if (!(strcmp("UDP", node))) proto = IPPROTO_UDP;

                  if ((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {
                     struct ArgusFlow flowbuf, *flow = &flowbuf;
                     char *saddr = NULL, *daddr = NULL;
                     char *sport = NULL, *dport = NULL;
                     field = 0;

                     if (strstr(name, "->") != NULL) {
                        struct ArgusCIDRAddr *cidr = NULL, scidr, dcidr;
                        int sPort = 0, dPort = 0;

                        if (strchr(name, '[')) {
                           while ((tok = strsep(&name, "[]->")) != NULL) {
                              if (*tok != '\0') {
                                 switch (field++) {
                                    case 0: saddr  = tok; break;
                                    case 1: sport  = tok+1; break;
                                    case 2: daddr = tok; break;
                                    case 3: dport = tok+1; break;
                                 }
                              }
                           }
                        } else {
                           while ((tok = strsep(&name, ":->")) != NULL) {
                              if (*tok != '\0') {
                                 switch (field++) {
                                    case 0: saddr  = tok; break;
                                    case 1: sport  = tok; break;
                                    case 2: daddr = tok; break;
                                    case 3: dport = tok; break;
                                 }
                              }
                           }
                        }

                        if (daddr && ((cidr = RaParseCIDRAddr (parser, saddr)) != NULL))
                           bcopy ((char *)cidr, (char *)&scidr, sizeof (*cidr));

                        if (daddr && ((cidr = RaParseCIDRAddr (parser, daddr)) != NULL))
                           bcopy ((char *)cidr, (char *)&dcidr, sizeof (*cidr));
    
                        if (sport) sPort = strtol(sport, NULL, 10);
                        if (dport) dPort = strtol(dport, NULL, 10);

                        if ((sPort != 0) && (dPort != 0)) {
                           switch (scidr.type) {
                              case AF_INET: {
                                 bzero((char *)flow, sizeof(*flow));
                                 flow->hdr.type              = ARGUS_FLOW_DSR;
                                 flow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                                 flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                                 flow->hdr.argus_dsrvl8.len    = 5;

                                 bcopy(&scidr.addr, &flow->ip_flow.ip_src, scidr.len);
                                 bcopy(&dcidr.addr, &flow->ip_flow.ip_dst, dcidr.len);
                                 flow->ip_flow.ip_p  = proto;
                                 flow->ip_flow.sport = sPort;
                                 flow->ip_flow.dport = dPort;
                                 flow->ip_flow.smask = 32;
                                 flow->ip_flow.dmask = 32;
                                 break;
                              }

                              case AF_INET6: {
                                 bzero((char *)flow, sizeof(*flow));
                                 flow->hdr.type              = ARGUS_FLOW_DSR;
                                 flow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                                 flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV6;
                                 flow->hdr.argus_dsrvl8.len    = 12;

                                 bcopy(&scidr.addr, &flow->ipv6_flow.ip_src, scidr.len);
                                 bcopy(&dcidr.addr, &flow->ipv6_flow.ip_dst, dcidr.len);
                                 flow->ipv6_flow.ip_p  = proto;
                                 flow->ipv6_flow.sport = sPort;
                                 flow->ipv6_flow.dport = dPort;
                                 flow->ipv6_flow.smask = 128;
                                 flow->ipv6_flow.dmask = 128;
                                 break;
                              }
                           }

                           {
                              struct ArgusRecordStruct *ns = NULL;
                              struct ArgusTransportStruct *atrans, *btrans;
                              struct ArgusLabelStruct *label;
                              struct ArgusTimeObject *btime;
                              struct ArgusFlow *bflow;
                              extern char ArgusCanonLabelBuffer[];
                              char *lptr = ArgusCanonLabelBuffer;

#if defined(ARGUSDEBUG)
                           ArgusDebug (3, "RaProcessEventRecord: %s:srcid=%s:%s: %s %s.%s -> %s.%s %s\n", tbuf, sptr, app, node, 
                                               saddr, sport, daddr, dport, state);
#endif
                              if ((ns = ArgusGenerateRecordStruct(NULL, NULL, NULL)) != NULL) {
                                 extern struct ArgusCanonRecord ArgusGenerateCanonBuffer;
                                 struct ArgusCanonRecord  *canon = &ArgusGenerateCanonBuffer;

                                 ns->status = argus->status;

                                 if ((atrans = (struct ArgusTransportStruct *)argus->dsrs[ARGUS_TRANSPORT_INDEX]) != NULL)
                                    if ((btrans = (struct ArgusTransportStruct *)ns->dsrs[ARGUS_TRANSPORT_INDEX]) != NULL)
                                       bcopy ((char *)atrans, (char *)btrans, sizeof(*atrans));
                                 ns->dsrindex |= (0x1 << ARGUS_TRANSPORT_INDEX);

                                 if ((btime = (struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX]) != NULL)
                                    bcopy ((char *)time, (char *)btime, sizeof(*btime));
                                 ns->dsrindex |= (0x1 << ARGUS_TIME_INDEX);

                                 if ((bflow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX]) == NULL) {
                                    ns->dsrs[ARGUS_FLOW_INDEX] = (struct ArgusDSRHeader*) &canon->flow;
                                    bflow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];
                                 }
                                 bcopy ((char *)flow, (char *)bflow, sizeof(*flow));
                                 ns->dsrindex |= (0x1 << ARGUS_FLOW_INDEX);

                                 if (state && (proto == IPPROTO_TCP)) {
                                    struct ArgusNetworkStruct *bnet;
                                    struct ArgusTCPObject *tcp;

                                    if ((bnet = (struct ArgusNetworkStruct *)ns->dsrs[ARGUS_NETWORK_INDEX]) == NULL) {
                                       ns->dsrs[ARGUS_NETWORK_INDEX] = (struct ArgusDSRHeader*) &canon->net;
                                       bnet = (struct ArgusNetworkStruct *)ns->dsrs[ARGUS_NETWORK_INDEX];
                                    }

                                    bnet->hdr.type    = ARGUS_NETWORK_DSR;
                                    bnet->hdr.subtype = ARGUS_TCP_STATUS;
                                    bnet->hdr.argus_dsrvl8.len  = 3;
                                    tcp = (struct ArgusTCPObject *)&bnet->net_union.tcp;

                                    if (!(strcmp(state, "(ESTABLISHED)")))     tcp->status = ARGUS_CON_ESTABLISHED;
                                    else if (!(strcmp(state, "(CLOSED)")))     tcp->status = ARGUS_NORMAL_CLOSE;
                                    else if (!(strcmp(state, "(CLOSE_WAIT)"))) tcp->status = ARGUS_CLOSE_WAITING;
                                    else if (!(strcmp(state, "(TIME_WAIT)")))  tcp->status = ARGUS_CLOSE_WAITING;

                                    ns->dsrindex |= (0x01 << ARGUS_NETWORK_INDEX);
                                 }

                                 if ((label = (struct ArgusLabelStruct *)ns->dsrs[ARGUS_LABEL_INDEX]) == NULL) {
                                    ns->dsrs[ARGUS_LABEL_INDEX] = (struct ArgusDSRHeader*) &canon->label;
                                    label = (struct ArgusLabelStruct *)ns->dsrs[ARGUS_LABEL_INDEX];
                                 }

                                 bzero(lptr, MAXBUFFERLEN);
                                 sprintf (lptr, "pid=%s:usr=%s:app=%s", pid, user, app);

                                 label->hdr.type    = ARGUS_LABEL_DSR;
                                 label->hdr.subtype = ARGUS_PROC_LABEL;
                                 label->hdr.argus_dsrvl8.len  = 1 + ((strlen(lptr) + 3)/4);
                                 label->l_un.label = lptr;
                                 ns->dsrindex |= (0x01 << ARGUS_LABEL_INDEX);

                                 RaProcessThisEventRecord (parser, ns);
                              }
                           }
                        }
                     }
                  }
               }

            } else
            if (strstr (str, "COMMAND"))
               title++;
         }
      }

//    ArgusCorrelateQueue (RaProcess->queue);
   }
}

void
RaProcessThisEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (flow != NULL) {
            unsigned int addr, *daddr = NULL;

            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_IPV4: {
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_TCP: {
                              daddr = &flow->ip_flow.ip_dst;
                              break;
                           }
                        }
                        break;
                     }
                  }
                  break;
               }
            }

            if ((daddr != NULL) && (addr = *(unsigned int *)daddr)) {
               extern unsigned int RaIPv4AddressType(struct ArgusParserStruct *, unsigned int);

               if (RaIPv4AddressType(parser, addr) == ARGUS_IPV4_UNICAST) {
                  struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;
                  struct RaAddressStruct *raddr = NULL, node;

                  bzero ((char *)&node, sizeof(node));
                  node.addr.type = AF_INET;
                  node.addr.addr[0] = addr;
                  node.addr.mask[0] = 0xFFFFFFFF;
                  node.addr.masklen = 32;
                  node.addr.len = 4;

                  if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_EXACT_MATCH)) == NULL) {
                     if ((raddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*raddr))) != NULL) {
                        bcopy(&node, raddr, sizeof(node));
                        RaInsertAddress (parser, labeler, NULL, raddr, ARGUS_VISITED);
                     }
                  }
               }
            }
         }
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessThisEventRecord () returning\n"); 
#endif
}

void
RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
}


struct RaProcessStruct *
RaNewProcess(struct ArgusParserStruct *parser)
{
   struct RaProcessStruct *retn = NULL;

   if ((retn = (struct RaProcessStruct *) ArgusCalloc (1, sizeof(*retn))) != NULL) {
      if ((retn->queue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "RaNewProcess: ArgusNewQueue error %s\n", strerror(errno));

      if ((retn->delqueue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "RaNewProcess: ArgusNewQueue error %s\n", strerror(errno));

      if ((retn->htable = ArgusNewHashTable(0x100000)) == NULL)
         ArgusLog (LOG_ERR, "RaNewProcess: ArgusCalloc error %s\n", strerror(errno));

   } else
      ArgusLog (LOG_ERR, "RaNewProcess: ArgusCalloc error %s\n", strerror(errno));

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaNewProcess(0x%x) returns 0x%x\n", parser, retn);
#endif
   return (retn);
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}

/*
 * Print out a null-terminated filename (or other ascii string).
 * If ep is NULL, assume no truncation check is needed.
 * Return true if truncated.
 */
int
fn_print(register const u_char *s, register const u_char *ep, char *buf)
{
   register int ret;
   register u_char c;

   ret = 1;                        /* assume truncated */
   while (ep == NULL || s < ep) {
      c = *s++;
      if (c == '\0') {
         ret = 0;
         break;
      }
      if (!isascii(c)) {
         c = toascii(c);
         sprintf(&buf[strlen(buf)], "%c", 'M');
         sprintf(&buf[strlen(buf)], "%c", '-');
      }
      if (!isprint(c)) {
         c ^= 0x40;      /* DEL to ?, others to alpha */
         sprintf(&buf[strlen(buf)], "%c", '^');
      }
      sprintf(&buf[strlen(buf)], "%c", c);
   }
   return(ret);
}

/*                      
 * Print out a counted filename (or other ascii string).
 * If ep is NULL, assume no truncation check is needed.
 * Return true if truncated.
 */                     

char *
fn_printn(register const u_char *s, register u_int n,
          register const u_char *ep, char *buf)
{
   register u_char c;
   int len = strlen(buf);
   char *ebuf = &buf[len];

   while ((n > 0) && (ep == NULL || s < ep)) {
      n--;
      c = *s++;
      if (!isascii(c)) {
         c = toascii(c);
         *ebuf++ = 'M';
         *ebuf++ = '-';
      }
      if (!isprint(c)) {
         c ^= 0x40;      /* DEL to ?, others to alpha */
         *ebuf++ = '^';
      }
      *ebuf++ = c;
   }
   return (n == 0) ? ebuf : NULL;
}

/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *   The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */


#include <argus/extract.h>

#include <stdio.h>
#include <string.h>


/*
 * Convert a token value to a string; use "fmt" if not found.
const char *
tok2str(const struct tok *lp, const char *fmt, int v)
{
   static char buf[128];

   while (lp->s != NULL) {
      if (lp->v == v)
         return (lp->s);
      ++lp;
   }
   if (fmt == NULL)
      fmt = "#%d";
   (void)snprintf(buf, sizeof(buf), fmt, v);
   return (buf);
}   
 */

/*
 * Convert a token value to a string; use "fmt" if not found.
 */

const char *
tok2strbuf(register const struct tok *lp, register const char *fmt,
           register int v, char *buf, size_t bufsize)
{
   if (lp != NULL) {
      while (lp->s != NULL) {
         if (lp->v == v)
            return (lp->s);
         ++lp;
      }
   }
   if (fmt == NULL)                
      fmt = "#%d"; 
                
   (void)snprintf(buf, bufsize, fmt, v);
   return (const char *)buf;
}  

/*
 * Convert a 32-bit netmask to prefixlen if possible
 * the function returns the prefix-len; if plen == -1
 * then conversion was not possible;
 */
int mask2plen (u_int32_t);

int
mask2plen (u_int32_t mask)
{
   u_int32_t bitmasks[33] = {
                0x00000000,
                0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
                0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
                0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
                0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
                0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
                0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
                0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
                0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff
   };
   int prefix_len = 32;

   /* let's see if we can transform the mask into a prefixlen */
   while (prefix_len >= 0) {
      if (bitmasks[prefix_len] == mask)
         break;
      prefix_len--;
   }
   return (prefix_len);
}

