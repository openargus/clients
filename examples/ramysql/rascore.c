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
 *
 * rascore  - Score streaming argus data based on using rollup databases
 *            as a source of baseline data.
 *
 */

/* 
 * $Id: //depot/gargoyle/clients/examples/ramysql/rasql.c#17 $
 * $DateTime: 2016/12/05 11:55:57 $
 * $Change: 3256 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <argus_grep.h>
#include <rasqlinsert.h>

#include <signal.h>
#include <ctype.h>
#include <time.h>
  
#include <netdb.h>
#include <sys/socket.h>

#include <rabins.h>
#include <rasplit.h>

#if defined(ARGUS_MYSQL)
 
#include "argus_mysql.h"
#include <mysqld_error.h>

char *RaDatabase = NULL;
char **RaBaselines = NULL;
char **RaTables = NULL;

extern int ArgusTimeRangeStrategy;
int ArgusScoreHandleRecord (struct ArgusParserStruct *, struct ArgusInput *, struct RaOutputProcessStruct *, struct ArgusRecord *, struct nff_program *);

struct RaOutputProcessStruct *RaScoreNewProcess(struct ArgusParserStruct *);

struct RaOutputProcessStruct *RaAnnualProcess = NULL;
struct RaOutputProcessStruct *RaMonthlyProcess = NULL;

char **ArgusCreateSQLTimeTableNames (struct ArgusParserStruct *, char *);
void RaSQLQueryTable (char *, struct RaOutputProcessStruct *);

int ArgusCreateSQLSaveTable(char *);
char *ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, int);
void RaMySQLDeleteRecords(struct ArgusParserStruct *, struct ArgusRecordStruct *);

void RaSQLQueryNetworksTable (unsigned int, unsigned int, unsigned int);
void RaSQLQueryProbes (void);
void RaSQLQuerySecondsTable (unsigned int, unsigned int);

char *ArgusCreateSQLSaveTableName (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);

int RaInitialized = 0;
int ArgusAutoId = 0;
int ArgusDropTable = 0;
int ArgusCreateTable = 0;

char *RaRoleString = NULL;
char *RaProbeString = NULL;
char *RaSQLSaveTable = NULL;
char *RaSQLCurrentTable = NULL;

struct timeval RaStartTime = {0x7FFFFFFF, 0x7FFFFFFF};
struct timeval RaEndTime = {0, 0};
 
struct timeval ArgusLastRealTime     = {0, 0};
struct timeval ArgusLastTime         = {0, 0};
struct timeval ArgusThisTime         = {0, 0};
struct timeval ArgusCurrentTime      = {0, 0};
 
char ArgusSQLSaveTableNameBuf[MAXSTRLEN];
struct tm ArgusSaveTableTmStruct;
time_t ArgusSaveTableSeconds = 0;
 
struct timeval dLastTime = {0, 0};
struct timeval dRealTime = {0, 0};
struct timeval dThisTime = {0, 0};
struct timeval dTime     = {0, 0};
 
long long thisUsec = 0;
long long lastUsec = 0;
 
struct ArgusQueueStruct *ArgusModelerQueue;
struct ArgusQueueStruct *ArgusFileQueue;
struct ArgusQueueStruct *ArgusProbeQueue;
 
char ArgusArchiveBuf[4098];
 
#define RAMON_NETS_CLASSA	0
#define RAMON_NETS_CLASSB	1
#define RAMON_NETS_CLASSC	2
#define RAMON_NETS_CLASS	3

#define RA_MINTABLES            128
#define RA_MAXTABLES            0x10000
unsigned int RaTableFlags = 0;
 
char       *RaTableValues[256];
char  *RaTableExistsNames[RA_MAXTABLES];
char  *RaTableCreateNames[RA_MINTABLES];
char *RaTableCreateString[RA_MINTABLES];
char *RaTableDeleteString[RA_MINTABLES];

#define ARGUSSQLMAXCOLUMNS	256
char *ArgusTableColumnName[ARGUSSQLMAXCOLUMNS];

char ArgusSQLTableNameBuf[MAXSTRLEN];

char *RaSource         = NULL;
char *RaArchive        = NULL;
char *RaLocalArchive   = NULL;
char *RaFormat         = NULL;
char *RaTable          = NULL;

int   RaStatus         = 1;
int   RaPeriod         = 1;
int   RaSQLMaxSeconds  = 0;

int ArgusSQLSecondsTable = 0;
int ArgusSQLBulkInsertSize = 0;
int ArgusSQLMaxPacketSize = 0;
int ArgusSQLBulkBufferSize = 0;
int ArgusSQLBulkBufferIndex = 0;
char *ArgusSQLBulkLastTable = NULL;
char *ArgusSQLBulkBuffer = NULL;
char *ArgusSQLVersion = NULL;
int MySQLVersionMajor = 0;
int MySQLVersionMinor = 0;
int MySQLVersionSub = 0;

extern int ArgusSOptionRecord;
int ArgusDeleteTable = 0;

char RaLocalArchBuf[MAXSTRLEN];

extern char *RaRemoteFilter;
extern char RaFilterSQLStatement[];
  
char *RaHost = NULL, *RaUser = NULL, *RaPass = NULL;
int RaPort = 0;
struct ArgusInput *ArgusInput = NULL;
void RaMySQLInit (void);

/* Do not try to create a database.  Allows read-only operations
 * with fewer database permissions.
 */
static int RaSQLNoCreate = 0;

MYSQL_ROW row;
MYSQL mysql, *RaMySQL = NULL;

struct RaMySQLFileStruct {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   unsigned int fileindex;
   unsigned int second;
   char *filename;
   int ostart, ostop;
};

#define RAMYSQL_SECONDTABLE_PROBE       0
#define RAMYSQL_SECONDTABLE_SECOND      1
#define RAMYSQL_SECONDTABLE_FILEINDEX   2
#define RAMYSQL_SECONDTABLE_OSTART      3
#define RAMYSQL_SECONDTABLE_OSTOP       4

struct RaMySQLSecondsTable {
   struct ArgusQueueHeader qhdr;
   unsigned int fileindex;
   char *filename;
   unsigned int probe;
   unsigned int second;
   int ostart, ostop;
};

#define RAMYSQL_PROBETABLE_PROBE        0
#define RAMYSQL_PROBETABLE_NAME         1

struct RaMySQLProbeTable {
   struct ArgusQueueHeader qhdr;
   unsigned int probe;
   char *name;
};

enum RaScoreLimitsEnum {
   RASCORE_LIMIT_NOSCORE = 0,
   RASCORE_LIMIT_MIN = 1,
   RASCORE_LIMIT_MAX = 15,
};



extern int ArgusTotalMarRecords;
extern int ArgusTotalFarRecords;

extern struct ArgusParserStruct *ArgusParser;
struct RaBinProcessStruct *RaBinProcess = NULL;

void RaArgusInputComplete (struct ArgusInput *input) {};

void
RaParseComplete (int sig)
{
   if (!ArgusParser->RaParseCompleting++) {
      mysql_close(RaMySQL);
   }
#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaParseComplete done\n");
#endif
   exit(0);
}

void
ArgusClientTimeout ()
{
#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusClientTimeout()\n");
#endif
}

void
parse_arg (int argc, char**argv)
{}

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessBaselineData (struct ArgusParserStruct *, struct ArgusRecordStruct *, struct RaOutputProcessStruct *);

void
RaProcessBaselineData (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, struct RaOutputProcessStruct *process)
{
   switch (argus->hdr.type & 0xF0) {
      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
         struct ArgusHashStruct *hstruct = NULL;
         int found = 0;

         if (agg != NULL) {
            while (agg && !found) {
               int retn = 0, fretn = -1, lretn = -1;
               if (agg->grepstr) {
                  struct ArgusLabelStruct *label;
                  if (((label = (void *)argus->dsrs[ARGUS_LABEL_INDEX]) != NULL)) {
                     if (regexec(&agg->lpreg, label->l_un.label, 0, NULL, 0))
                        lretn = 0;
                     else
                        lretn = 1;
                  } else
                     lretn = 0;
               }

               retn = (lretn < 0) ? ((fretn < 0) ? 1 : fretn) : ((fretn < 0) ? lretn : (lretn && fretn));

               if (retn != 0) {
                  struct ArgusRecordStruct *ns, *tns;

                  ns = ArgusCopyRecordStruct(argus);

                  if (agg->labelstr)
                     ArgusAddToRecordLabel(parser, ns, agg->labelstr);

                  if (agg->mask) {
                     if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
                        agg->rap = agg->drap;

                     ArgusGenerateNewFlow(agg, ns);
                     agg->ArgusMaskDefs = NULL;

                     if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL) {
                        if ((tns = ArgusFindRecord(process->htable, hstruct)) == NULL) {
                           ns->htblhdr = ArgusAddHashEntry (process->htable, ns, hstruct);
                           ArgusAddToQueue (process->queue, &ns->qhdr, ARGUS_LOCK);
                           process->status |= ARGUS_AGGREGATOR_DIRTY;

                        } else {
                           ArgusMergeRecords (agg, tns, ns);

                           ArgusRemoveFromQueue (process->queue, &tns->qhdr, ARGUS_LOCK);
                           ArgusAddToQueue (process->queue, &tns->qhdr, ARGUS_LOCK);         // use the agg queue as an idle timeout queue

                           ArgusDeleteRecordStruct(parser, ns);
                           process->status |= ARGUS_AGGREGATOR_DIRTY;
                        }
                     }

                  } else {
                     ArgusAddToQueue (process->queue, &ns->qhdr, ARGUS_LOCK);
                     process->status |= ARGUS_AGGREGATOR_DIRTY;
                  }

                  if (agg->cont)
                     agg = agg->nxt;
                  else
                     found++;

               } else
                  agg = agg->nxt;
            }

         }
#if defined(ARGUSDEBUG)
         ArgusDebug (3, "RaProcessBaselineData () returning\n"); 
#endif
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "RaProcessBaselineData (%p, %p, %p)\n", parser, argus, process);
#endif
}

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;
   struct ArgusLabelerStruct *local = parser->ArgusLocalLabeler;
   struct ArgusFlow *flow;
   int retn = 0;

   struct ArgusRecordStruct *argus = ArgusCopyRecordStruct(ns);
   flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
         RaProcessThisRecord (parser, argus);
         break;

      case ARGUS_EVENT:
         RaProcessThisRecord (parser, argus);
         break;

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusMetricStruct *metric = (void *)argus->dsrs[ARGUS_METRIC_INDEX];

         if (metric != NULL) {
            parser->ArgusTotalPkts  += metric->src.pkts;
            parser->ArgusTotalPkts  += metric->dst.pkts;
            parser->ArgusTotalBytes += metric->src.bytes;
            parser->ArgusTotalBytes += metric->dst.bytes;
         }

         if (flow) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4:
                        if ((!retn && parser->ArgusAggregator->mask & ARGUS_MASK_SADDR_INDEX)) {
                           if (flow->ip_flow.smask == 32) {
                              if ((retn = RaProcessAddressLocality(parser, local, argus, &flow->ip_flow.ip_src, 32, ARGUS_TYPE_IPV4, ARGUS_MASK_SADDR_INDEX | ARGUS_SUPER_MATCH)) == 0) {
                                 if ((retn = RaProcessAddressLocality(parser, local, argus, &flow->ip_flow.ip_src, 24, ARGUS_TYPE_IPV4, ARGUS_MASK_SADDR_INDEX | ARGUS_MASK_MATCH)) == 0) {
                                 }
                              }
                              if ((retn = RaProcessAddressLabel(parser, labeler, argus, &flow->ip_flow.ip_src, 32, ARGUS_TYPE_IPV4, ARGUS_MASK_SADDR_INDEX | ARGUS_SUPER_MATCH)) == 0) {
                                 if ((retn = RaProcessAddressLabel(parser, labeler, argus, &flow->ip_flow.ip_src, 24, ARGUS_TYPE_IPV4, ARGUS_MASK_SADDR_INDEX | ARGUS_MASK_MATCH)) == 0) {
                                 } else {
                                    struct ArgusLabelStruct *label;
                                    if (((label = (void *)argus->dsrs[ARGUS_LABEL_INDEX]) != NULL)) {
                                       char *slabel = label->l_un.label;
                                       if (strlen(slabel)) {
                                          if (strstr(slabel, "esoc")) argus->score = 8;
                                       }
                                    }
                                 }
                              } else {
                                 struct ArgusLabelStruct *label;
                                 if (((label = (void *)argus->dsrs[ARGUS_LABEL_INDEX]) != NULL)) {
                                    char *slabel = label->l_un.label;
                                    if (strlen(slabel)) {
                                       if (strstr(slabel, "firehol") && strstr(slabel, "level4")) argus->score = 9;
                                       if (strstr(slabel, "firehol") && strstr(slabel, "level3")) argus->score = 10;
                                       if (strstr(slabel, "firehol") && strstr(slabel, "level2")) argus->score = 11;
                                       if (strstr(slabel, "firehol") && strstr(slabel, "level1")) argus->score = 12;
                                       if (strstr(slabel, "esoc")) argus->score = 12;
                                    }
                                 } else {
                                    argus->score = 12;
                                 }
                              }
                           }
                        }
                        if ((parser->ArgusAggregator->mask & ARGUS_MASK_DADDR_INDEX)) {
                           if (flow->ip_flow.dmask == 32) {
                              if ((retn = RaProcessAddressLocality(parser, local, argus, &flow->ip_flow.ip_dst, 32, ARGUS_TYPE_IPV4, ARGUS_MASK_DADDR_INDEX | ARGUS_SUPER_MATCH)) == 0) {
                                 if ((retn = RaProcessAddressLocality(parser, local, argus, &flow->ip_flow.ip_dst, 24, ARGUS_TYPE_IPV4, ARGUS_MASK_DADDR_INDEX | ARGUS_MASK_MATCH)) == 0) {
                                 }
                              }
                              if ((retn = RaProcessAddressLabel(parser, labeler, argus, &flow->ip_flow.ip_dst, 32, ARGUS_TYPE_IPV4, ARGUS_MASK_DADDR_INDEX | ARGUS_SUPER_MATCH)) == 0) {
                                 if ((retn = RaProcessAddressLabel(parser, labeler, argus, &flow->ip_flow.ip_dst, 24, ARGUS_TYPE_IPV4, ARGUS_MASK_DADDR_INDEX | ARGUS_MASK_MATCH)) == 0) {
                                 } else {
                                    argus->score = 9;
                                 } 
                              } else {
                                 argus->score = 12;
                              } 
                           }
                        }
                        break;
                     case ARGUS_TYPE_IPV6:
                        if (!retn && (parser->ArgusAggregator->mask & ARGUS_MASK_SADDR_INDEX)) {
                           retn = RaProcessAddressLocality(parser, local, argus, (unsigned int *) &flow->ipv6_flow.ip_src, 128, ARGUS_TYPE_IPV6, ARGUS_SUPER_MATCH);
                        }
                        if (!retn && (parser->ArgusAggregator->mask & ARGUS_MASK_DADDR_INDEX)) {
                           retn = RaProcessAddressLocality(parser, local, argus, (unsigned int *) &flow->ipv6_flow.ip_dst, 128, ARGUS_TYPE_IPV6, ARGUS_SUPER_MATCH);
                        }
                        break;
                  }
                  break;
               }
            }
         }

         if (parser->RaMonMode) {
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(argus);
            struct ArgusFlow *flow;

            if ((flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, argus);
            ArgusReverseRecord(tns);

            if ((flow = (void *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);

         } else {
            RaProcessThisRecord(parser, argus);
         }
      }
   }
   ArgusDeleteRecordStruct(parser, argus);
}

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
   struct ArgusHashStruct *hstruct = NULL;
   struct RaOutputProcessStruct *process;
   int found = 0;

   if (agg != NULL) {
      while (agg && !found) {
         int retn = 0, fretn = -1, lretn = -1;
         if (agg->filterstr) {
            struct nff_insn *fcode = agg->filter.bf_insns;
            fretn = ArgusFilterRecord (fcode, argus);
         }
         if (agg->grepstr) {
            struct ArgusLabelStruct *label;
            if (((label = (void *)argus->dsrs[ARGUS_LABEL_INDEX]) != NULL)) {
               if (regexec(&agg->lpreg, label->l_un.label, 0, NULL, 0))
                  lretn = 0;
               else
                  lretn = 1;
            } else
               lretn = 0;
         }

         retn = (lretn < 0) ? ((fretn < 0) ? 1 : fretn) : ((fretn < 0) ? lretn : (lretn && fretn));

         if (retn != 0) {
            if (agg->labelstr)
               ArgusAddToRecordLabel(parser, argus, agg->labelstr);

            if (agg->mask) {
               if ((agg->rap = RaFlowModelOverRides(agg, argus)) == NULL)
                  agg->rap = agg->drap;

               ArgusGenerateNewFlow(agg, argus);
               agg->ArgusMaskDefs = NULL;

#define FIRST_PASS	0
#define SECOND_PASS	1

               if ((hstruct = ArgusGenerateHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) != NULL) {
                  int pass;

		  /* don't output a score if there isn't already
		   * one present and we have no baseline data
                   */
                  if ((RaAnnualProcess == NULL) && (RaMonthlyProcess == NULL) && (argus->dsrs[ARGUS_SCORE_INDEX] == NULL)) {
                  } else {
//                   argus->score = 0;
                  }

                  for (pass = 0; pass < 2; pass++) {
                     struct ArgusRecordStruct *tns;
                     switch (pass) {
                         case FIRST_PASS: process = RaAnnualProcess; break;
                        case SECOND_PASS: process = RaMonthlyProcess; break;
                     }

                     if (process == NULL)
                        /* skip this pass if it has no data */
                        continue;

                     if ((tns = ArgusFindRecord(process->htable, hstruct)) == NULL) {
                        struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
                        if (!parser->RaMonMode && parser->ArgusReverse) {
                           int tryreverse = 0;

                           if (flow != NULL) {
                              if (agg->correct != NULL)
                                 tryreverse = 1;

                              switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                 case ARGUS_TYPE_IPV4: {
                                    switch (flow->ip_flow.ip_p) {
                                       case IPPROTO_ESP:
                                          tryreverse = 0;
                                          break;
                                    }
                                    break;
                                 }
                                 case ARGUS_TYPE_IPV6: {
                                    switch (flow->ipv6_flow.ip_p) {
                                       case IPPROTO_ESP:
                                          tryreverse = 0;
                                          break;
                                    }
                                    break;
                                 }
                              }
                           } else
                              tryreverse = 0;

                           if (tryreverse) {
                              if ((hstruct = ArgusGenerateReverseHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) != NULL) {

                              if ((tns = ArgusFindRecord(process->htable, hstruct)) == NULL) {
                                 switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                    case ARGUS_TYPE_IPV4: {
                                       switch (flow->ip_flow.ip_p) {
                                          case IPPROTO_ICMP: {
                                             struct ArgusICMPFlow *icmpFlow = &flow->flow_un.icmp;

                                             if (ICMP_INFOTYPE(icmpFlow->type)) {
                                                switch (icmpFlow->type) {
                                                   case ICMP_ECHO:
                                                   case ICMP_ECHOREPLY:
                                                      icmpFlow->type = (icmpFlow->type == ICMP_ECHO) ? ICMP_ECHOREPLY : ICMP_ECHO;
                                                      if ((hstruct = ArgusGenerateReverseHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                         tns = ArgusFindRecord(process->htable, hstruct);
                                                      icmpFlow->type = (icmpFlow->type == ICMP_ECHO) ? ICMP_ECHOREPLY : ICMP_ECHO;
                                                      if (tns)
                                                         ArgusReverseRecord (argus);
                                                      break;

                                                   case ICMP_ROUTERADVERT:
                                                   case ICMP_ROUTERSOLICIT:
                                                      icmpFlow->type = (icmpFlow->type == ICMP_ROUTERADVERT) ? ICMP_ROUTERSOLICIT : ICMP_ROUTERADVERT;
                                                      if ((hstruct = ArgusGenerateReverseHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                         tns = ArgusFindRecord(process->htable, hstruct);
                                                      icmpFlow->type = (icmpFlow->type == ICMP_ROUTERADVERT) ? ICMP_ROUTERSOLICIT : ICMP_ROUTERADVERT;
                                                      if (tns)
                                                         ArgusReverseRecord (argus);
                                                      break;

                                                   case ICMP_TSTAMP:
                                                   case ICMP_TSTAMPREPLY:
                                                      icmpFlow->type = (icmpFlow->type == ICMP_TSTAMP) ? ICMP_TSTAMPREPLY : ICMP_TSTAMP;
                                                      if ((hstruct = ArgusGenerateReverseHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                         tns = ArgusFindRecord(process->htable, hstruct);
                                                      icmpFlow->type = (icmpFlow->type == ICMP_TSTAMP) ? ICMP_TSTAMPREPLY : ICMP_TSTAMP;
                                                      if (tns)
                                                         ArgusReverseRecord (argus);
                                                      break;

                                                   case ICMP_IREQ:
                                                   case ICMP_IREQREPLY:
                                                      icmpFlow->type = (icmpFlow->type == ICMP_IREQ) ? ICMP_IREQREPLY : ICMP_IREQ;
                                                      if ((hstruct = ArgusGenerateReverseHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                         tns = ArgusFindRecord(process->htable, hstruct);
                                                      icmpFlow->type = (icmpFlow->type == ICMP_IREQ) ? ICMP_IREQREPLY : ICMP_IREQ;
                                                      if (tns)
                                                         ArgusReverseRecord (argus);
                                                      break;

                                                   case ICMP_MASKREQ:
                                                   case ICMP_MASKREPLY:
                                                      icmpFlow->type = (icmpFlow->type == ICMP_MASKREQ) ? ICMP_MASKREPLY : ICMP_MASKREQ;
                                                      if ((hstruct = ArgusGenerateReverseHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                         tns = ArgusFindRecord(process->htable, hstruct);
                                                      icmpFlow->type = (icmpFlow->type == ICMP_MASKREQ) ? ICMP_MASKREPLY : ICMP_MASKREQ;
                                                      if (tns)
                                                         ArgusReverseRecord (argus);
                                                      break;
                                                }
                                             }
                                             break;
                                          }
                                       }
                                    }
                                 }

                                 hstruct = ArgusGenerateHashStruct(agg, argus, (struct ArgusFlow *)&agg->fstruct);

                              } else {    // OK, so we have a match (tns) that is the reverse of the current flow (ns)
                                          // Need to decide which direction wins.

                                 struct ArgusNetworkStruct *nnet = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX];
                                 struct ArgusNetworkStruct *tnet = (struct ArgusNetworkStruct *)tns->dsrs[ARGUS_NETWORK_INDEX];

                                 switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                    case ARGUS_TYPE_IPV4: {
                                       switch (flow->ip_flow.ip_p) {
                                          case IPPROTO_TCP: {
                                             if ((nnet != NULL) && (tnet != NULL)) {
                                                struct ArgusTCPObject *ntcp = &nnet->net_union.tcp;
                                                struct ArgusTCPObject *ttcp = &tnet->net_union.tcp;

// first if both flows have syn, then don't merge;
                                                if ((ntcp->status & ARGUS_SAW_SYN) && (ttcp->status & ARGUS_SAW_SYN)) {
                                                   tns = NULL;
                                                } else {
                                                   if (ntcp->status & ARGUS_SAW_SYN) {
                                                      ArgusRemoveHashEntry(&tns->htblhdr);
                                                      ArgusReverseRecord (tns);
                                                      hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                                      tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                                   } else
                                                   if ((ntcp->status & ARGUS_SAW_SYN_SENT) && (ntcp->status & ARGUS_CON_ESTABLISHED)) {
                                                      ArgusRemoveHashEntry(&tns->htblhdr);
                                                      ArgusReverseRecord (tns);
                                                      hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                                      tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                                   } else
                                                      ArgusReverseRecord (argus);
                                                }
                                             }
                                             break;
                                          }

                                          default:
                                             ArgusReverseRecord (argus);
                                             break;
                                       }
                                    }
                                    break;

                                    case ARGUS_TYPE_IPV6: {
                                       switch (flow->ipv6_flow.ip_p) {
                                          case IPPROTO_TCP: {
                                             if ((nnet != NULL) && (tnet != NULL)) {
                                                struct ArgusTCPObject *ntcp = &nnet->net_union.tcp;
                                                struct ArgusTCPObject *ttcp = &tnet->net_union.tcp;

// first if both flows have syn, then don't merge;
                                                if ((ntcp->status & ARGUS_SAW_SYN) && (ttcp->status & ARGUS_SAW_SYN)) {
                                                   tns = NULL;
                                                } else {
                                                   if (ntcp->status & ARGUS_SAW_SYN) {
                                                      ArgusRemoveHashEntry(&tns->htblhdr);
                                                      ArgusReverseRecord (tns);
                                                      hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                                      tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                                   } else
                                                   if ((ntcp->status & ARGUS_SAW_SYN_SENT) && (ntcp->status & ARGUS_CON_ESTABLISHED)) {
                                                      ArgusRemoveHashEntry(&tns->htblhdr);
                                                      ArgusReverseRecord (tns);
                                                      hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                                      tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                                   } else
                                                      ArgusReverseRecord (argus);
                                                }
                                             }
                                             break;
                                          }

                                          default:
                                             ArgusReverseRecord (argus);
                                             break;
                                       }
                                    }
                                    break;

                                    default:
                                       ArgusReverseRecord (argus);
                                 }
                              }
                              }
                           }
                        }
                     }
                     if (tns != NULL) {                            // found record in the baseline (process) queue
                        struct timeval nstvbuf, tstvbuf, *nstvp = &nstvbuf, *tstvp = &tstvbuf;
                        float tdur = RaGetFloatDuration (tns);

                        process->ns = tns;

                        RaGetStartTime(argus,  nstvp);
                        RaGetStartTime(tns, tstvp);

#define	SECONDS_IN_DAY		86400
#define	SECONDS_IN_WEEK		86400*7
#define	SECONDS_IN_MONTH	86400*7*4
#define	SECONDS_IN_QUARTER	86400*7*4*4
#define	SECONDS_IN_YEAR		86400*365.25

// First test if we've seen this before, so if the times are the same, then we're in baseline.

                        if (nstvp->tv_sec > tstvp->tv_sec) {
                           int score = (pass == FIRST_PASS) ? ((tdur > SECONDS_IN_QUARTER) ? 4 : ((tdur > SECONDS_IN_MONTH) ? 4 : (tdur > SECONDS_IN_WEEK) ? 3 : 1)) : 0;
                           argus->score = argus->score > score ? argus->score : score;
                        } else {
                           if ((nstvp->tv_sec == tstvp->tv_sec) && (nstvp->tv_usec == tstvp->tv_usec)) {
                              if (argus->score == 0) {
                                 argus->score = 1;
                              }
                           }
                        }
                     }
                  }

                  if (((RaAnnualProcess != NULL) && (RaAnnualProcess->ns != NULL)) && 
                      ((RaMonthlyProcess != NULL) && (RaMonthlyProcess->ns != NULL))) {
                     float ydur = RaGetFloatDuration (RaAnnualProcess->ns);
                     float mdur = RaGetFloatDuration (RaMonthlyProcess->ns);
                     if (ydur == mdur) {
                        argus->score = argus->score > 1 ? argus->score : 1;
		     }
		  }
                  
                  RaSendArgusRecord(argus);

                  if (RaAnnualProcess != NULL)  RaAnnualProcess->ns = NULL; 
                  if (RaMonthlyProcess != NULL) RaMonthlyProcess->ns = NULL; 
               }
            }

            if (agg->cont)
               agg = agg->nxt;
            else
               found++;

         } else
            agg = agg->nxt;
      }
   }
}

char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];

int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{
   struct ArgusScoreStruct  *score  = (void *)argus->dsrs[ARGUS_SCORE_INDEX];
   struct ArgusRecord *argusrec = NULL;
   int retn = 1;

   if (ArgusParser->RaAgMode)
      argus->dsrs[ARGUS_AGR_INDEX] = NULL;

   if (argus->status & ARGUS_RECORD_WRITTEN)
      return (retn);

   if (argus->score) {
      if (score == NULL) {
         struct ArgusScoreStruct *score = (struct ArgusScoreStruct *) ArgusCalloc(1, sizeof(*score));
         if (score == NULL) 
            ArgusLog(LOG_ERR, "RaSendArgusRecord: ArgusCalloc failed");

         score->hdr.type = ARGUS_SCORE_DSR;
         score->hdr.subtype = ARGUS_BEHAVIOR_SCORE;
         score->hdr.argus_dsrvl8.len = (sizeof(*score) + 3)/4;
         argus->dsrs[ARGUS_SCORE_INDEX] = (struct ArgusDSRHeader*) &score->hdr;
         argus->dsrindex |= (0x01 << ARGUS_SCORE_INDEX);

         score->behvScore.values[0] = argus->score;

      } else {
         score->behvScore.values[0] = argus->score;
      }
   }

   if (ArgusParser->ArgusWfileList != NULL) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = ArgusParser->ArgusWfileList->count;

      if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, ARGUS_VERSION)) != NULL) {
#ifdef _LITTLE_ENDIAN
         ArgusHtoN(argusrec);
#endif
         if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
            for (i = 0; i < count; i++) {
               if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                  int pass = 1;
                  if (wfile->filterstr) {
                     struct nff_insn *wfcode = wfile->filter.bf_insns;
                     pass = ArgusFilterRecord (wfcode, argus);
                  }

                  if (pass != 0) {
                     if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
                        int rv;

                        rv = ArgusWriteNewLogfile (ArgusParser, argus->input,
                                                   wfile, argusrec);
                        if (rv < 0)
                           ArgusLog(LOG_ERR, "%s unable to open file\n",
                                    __func__);
                     }
                  }

                  lobj = lobj->nxt;
               }
            }
         }
      }

   } else {
      if (!ArgusParser->qflag) {
         char buf[MAXSTRLEN];

         if (!(ArgusParser->ArgusPrintJson) && (ArgusParser->Lflag)) {
            if (ArgusParser->RaLabel == NULL)
               ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, argus);
 
            if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag))
               printf ("%s\n", ArgusParser->RaLabel);
 
            if (ArgusParser->Lflag < 0)
               ArgusParser->Lflag = 0;
         }

         buf[0] = 0;
         ArgusPrintRecord(ArgusParser, buf, argus, MAXSTRLEN);

         if (fprintf (stdout, "%s\n", buf) < 0)
            RaParseComplete (SIGQUIT);

         if (ArgusParser->eflag == ARGUS_HEXDUMP) {
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
                        if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) != NULL) {
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
                        if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) != NULL) {
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
         fflush(stdout);
      }
   }

   argus->status |= ARGUS_RECORD_WRITTEN;
   return (retn);
}


void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}

/*
   Mysql URL that we will respond to is:
      mysql://[username[:password]@]hostname[:port]/database/tablename
*/

void
RaMySQLInit ()
{
   char userbuf[1024], sbuf[1024], db[1024], *dbptr = NULL;
   char *sptr = NULL, *ptr;
   MYSQL_RES *mysqlRes;
   int retn = 0, x;

   bzero((char *)RaTableExistsNames,  sizeof(RaTableExistsNames));
   bzero((char *)RaTableCreateNames,  sizeof(RaTableCreateNames));
   bzero((char *)RaTableCreateString, sizeof(RaTableCreateString));
   bzero((char *)RaTableDeleteString, sizeof(RaTableDeleteString));

   if ((RaUser == NULL) && (ArgusParser->dbuserstr != NULL)) {
      bzero(userbuf, sizeof(userbuf));
      strncpy (userbuf, ArgusParser->dbuserstr, sizeof(userbuf));
      if ((sptr = strchr (userbuf, ':')) != NULL) {
         *sptr++ = '\0';
         RaPass = strdup(sptr);
      }
      RaUser = strdup(userbuf);
   }

   if ((RaPass == NULL) && (ArgusParser->dbpassstr != NULL))
      RaPass = ArgusParser->dbpassstr;

   if (RaDatabase == NULL) {
      if (ArgusParser->writeDbstr != NULL)
         RaDatabase = strdup(ArgusParser->writeDbstr);

      else if (ArgusParser->readDbstr != NULL)
         RaDatabase = strdup(ArgusParser->readDbstr);

      if (RaDatabase) 
         if (!(strncmp("mysql:", RaDatabase, 6))) {
            char *tmp = RaDatabase;
            RaDatabase = strdup(&RaDatabase[6]);
            free(tmp);
         }
   }
      
   if (RaDatabase == NULL) {
      ArgusLog(LOG_ERR, "must specify database");

   } else {
      sprintf(db, "%s", RaDatabase);
      dbptr = db;
/*
      //[[username[:password]@]hostname[:port]]/database/tablename
*/

      if (!(strncmp ("//", dbptr, 2))) {
         char *rhost = NULL, *ruser = NULL, *rpass = NULL;
         if ((strncmp ("///", dbptr, 3))) {
            dbptr = &dbptr[2];
            rhost = dbptr;
            if ((ptr = strchr (dbptr, '/')) != NULL) {
               *ptr++ = '\0';
               dbptr = ptr;

               if ((ptr = strchr (rhost, '@')) != NULL) {
                  ruser = rhost;
                  *ptr++ = '\0';
                  rhost = ptr;
                  if ((ptr = strchr (ruser, ':')) != NULL) {
                     *ptr++ = '\0';
                     rpass = ptr;
                  } else {
                     rpass = NULL;
                  }
               }

               if ((ptr = strchr (rhost, ':')) != NULL) {
                  *ptr++ = '\0';
                  RaPort = atoi(ptr);
               }
            } else
               dbptr = NULL;

         } else {
            dbptr = &dbptr[3];
         }

         if (ruser != NULL) {
            if (RaUser != NULL) free(RaUser);
            RaUser = strdup(ruser);
         }
         if (rpass != NULL) {
            if (RaPass != NULL) free(RaPass);
            RaPass = strdup(rpass);
         }
         if (rhost != NULL) {
            if (RaHost != NULL) free(RaHost);
            RaHost = strdup(rhost);
         }
         free(RaDatabase);
         RaDatabase = strdup(dbptr);
      }
   }

   if ((ptr = strchr (RaDatabase, '/')) != NULL) {
      *ptr++ = '\0';
      RaTable = ptr;

      if (ArgusParser->writeDbstr != NULL)
         RaSQLSaveTable = strdup(RaTable);
   }

   if (!(ArgusParser->status & ARGUS_REAL_TIME_PROCESS))
      ArgusLastTime = ArgusParser->ArgusRealTime;

   if (RaMySQL == NULL)
      if ((RaMySQL = (void *) ArgusCalloc(1, sizeof(*RaMySQL))) == NULL)
         ArgusLog(LOG_ERR, "RaMySQLInit: ArgusCalloc error %s", strerror(errno));

   if ((mysql_init(RaMySQL)) == NULL)
      ArgusLog(LOG_ERR, "mysql_init error %s");

   if (!mysql_thread_safe())
      ArgusLog(LOG_INFO, "mysql not thread-safe");

   mysql_options(RaMySQL, MYSQL_READ_DEFAULT_GROUP, ArgusParser->ArgusProgramName);

   if ((mysql_real_connect(RaMySQL, RaHost, RaUser, RaPass, NULL, RaPort, NULL, 0)) == NULL)
      ArgusLog(LOG_ERR, "mysql_connect error %s", mysql_error(RaMySQL));

   bzero(sbuf, sizeof(sbuf));
   sprintf (sbuf, "SHOW VARIABLES LIKE 'version'");

   if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         while ((row = mysql_fetch_row(mysqlRes))) {
            int matches = 0;
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");

           ArgusSQLVersion = strdup(sbuf);
           if ((matches = sscanf(ArgusSQLVersion,"%d.%d.%d", &MySQLVersionMajor, &MySQLVersionMinor, &MySQLVersionSub)) > 0) {
            }
         }
      }
      mysql_free_result(mysqlRes);
   }

   bzero(sbuf, sizeof(sbuf));
   sprintf (sbuf, "SHOW VARIABLES LIKE 'bulk_insert_buffer_size'");

   if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         while ((row = mysql_fetch_row(mysqlRes))) {
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");

           ArgusSQLBulkBufferSize = (int)strtol(sbuf, (char **)NULL, 10);
         }
      }
      mysql_free_result(mysqlRes);
   }

   bzero(sbuf, sizeof(sbuf));
   sprintf (sbuf, "SHOW VARIABLES LIKE 'max_allowed_packet'");

   if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         while ((row = mysql_fetch_row(mysqlRes))) {
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            sprintf(sbuf, "%.*s", (int) lengths[1], row[1] ? row[1] : "NULL");
            
           ArgusSQLMaxPacketSize = (int)strtol(sbuf, (char **)NULL, 10);
         }
      }
      mysql_free_result(mysqlRes);
   }

   ArgusSQLBulkInsertSize = (ArgusSQLMaxPacketSize < ArgusSQLBulkBufferSize) ? ArgusSQLMaxPacketSize : ArgusSQLBulkBufferSize;

   if ((ArgusSQLBulkBuffer = calloc(1, ArgusSQLBulkInsertSize)) == NULL)
      ArgusLog(LOG_WARNING, "ArgusMySQLInit: cannot alloc bulk buffer size %d\n", ArgusSQLBulkInsertSize);

   if (!RaSQLNoCreate) {
      bzero(sbuf, sizeof(sbuf));
      sprintf (sbuf, "CREATE DATABASE IF NOT EXISTS %s", RaDatabase);

      if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
         ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
   }

   sprintf (sbuf, "USE %s", RaDatabase);

   if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   if ((mysqlRes = mysql_list_tables(RaMySQL, NULL)) != NULL) {
      char sbuf[MAXSTRLEN];

      if ((retn = mysql_num_fields(mysqlRes)) > 0) {
         int thisIndex = 0;

         while ((row = mysql_fetch_row(mysqlRes))) {
            unsigned long *lengths;
            lengths = mysql_fetch_lengths(mysqlRes);
            bzero(sbuf, sizeof(sbuf));
               for (x = 0; x < retn; x++)
               sprintf(&sbuf[strlen(sbuf)], "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

            RaTableExistsNames[thisIndex++] = strdup (sbuf);
            if (!(strncmp(sbuf, "Seconds", 8))) {
               ArgusSQLSecondsTable = 1;
            }
         }

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "mysql_num_fields() returned zero.\n");
#endif
      }
      mysql_free_result(mysqlRes);
   }

   if (RaTable != NULL) {
   }

   if (ArgusParser->writeDbstr != NULL) {
      char *ptr;
      sprintf (ArgusParser->RaDBString, "-w %s", ArgusParser->writeDbstr);
      if ((ptr = strrchr(ArgusParser->writeDbstr, '/')) != NULL)
         *ptr = '\0';

   } else 
   if (ArgusParser->readDbstr != NULL) {
      char *ptr;
      sprintf (ArgusParser->RaDBString, "-r %s", ArgusParser->readDbstr);
      if ((ptr = strrchr(ArgusParser->readDbstr, '/')) != NULL)
         *ptr = '\0';
   } else  {
      sprintf (ArgusParser->RaDBString, "db %s", RaDatabase);

      if (RaHost)
         sprintf (&ArgusParser->RaDBString[strlen(ArgusParser->RaDBString)], "@%s", RaHost);

      sprintf (&ArgusParser->RaDBString[strlen(ArgusParser->RaDBString)], " user %s", RaUser);
   }

   if ((ArgusParser->ArgusInputFileList != NULL)  ||
        (ArgusParser->ArgusRemoteHosts && (ArgusParser->ArgusRemoteHosts->count > 0))) {

      if (RaSQLSaveTable != NULL) {
         if (!((strchr(RaSQLSaveTable, '%') || strchr(RaSQLSaveTable, '$'))))
            if (ArgusCreateSQLSaveTable(RaSQLSaveTable))
               ArgusLog(LOG_ERR, "mysql create %s returned error", RaSQLSaveTable);
      }
   }

   if (ArgusParser->MySQLDBEngine == NULL)
      ArgusParser->MySQLDBEngine = strdup("InnoDB");

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaMySQLInit () RaSource %s RaArchive %s RaFormat %s", RaSource, RaArchive, RaFormat);
#endif
}


void
RaSQLQueryTable (char *table, struct RaOutputProcessStruct *process)
{
   char ArgusSQLStatement[MAXSTRLEN];
   char buf[MAXARGUSRECORD], sbuf[MAXARGUSRECORD];
   MYSQL_RES *mysqlRes;
   struct timeval now;
   int retn, x;

   if ((ArgusInput = (struct ArgusInput *) ArgusCalloc (1, sizeof(struct ArgusInput))) == NULL)
      ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

   ArgusInput->fd            = -1;
   ArgusInput->ArgusOriginal = (struct ArgusRecord *)&ArgusInput->ArgusOriginalBuffer;
   ArgusInput->mode          = ARGUS_DATA_SOURCE;
   ArgusInput->status       |= ARGUS_DATA_SOURCE;
   ArgusInput->index         = -1;
   ArgusInput->ostart        = -1;
   ArgusInput->ostop         = -1;

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&ArgusInput->lock, NULL);
#endif

   ArgusInput->ArgusInitCon.hdr.type  = ARGUS_MAR | ARGUS_VERSION;
   ArgusInput->ArgusInitCon.hdr.cause = ARGUS_START;
   ArgusInput->ArgusInitCon.hdr.len   = htons((unsigned short) sizeof(struct ArgusRecord)/4);

   ArgusInput->ArgusInitCon.argus_mar.argusid = htonl(ARGUS_COOKIE);

   gettimeofday (&now, 0L);

   ArgusInput->ArgusInitCon.argus_mar.now.tv_sec  = now.tv_sec;
   ArgusInput->ArgusInitCon.argus_mar.now.tv_usec = now.tv_usec;

   ArgusInput->ArgusInitCon.argus_mar.major_version = VERSION_MAJOR;
   ArgusInput->ArgusInitCon.argus_mar.minor_version = VERSION_MINOR;

   bcopy((char *)&ArgusInput->ArgusInitCon, (char *)&ArgusParser->ArgusInitCon, sizeof (ArgusParser->ArgusInitCon));

   if (ArgusParser->ArgusSQLStatement != NULL)
      strcpy(ArgusSQLStatement, ArgusParser->ArgusSQLStatement);
   else
      ArgusSQLStatement[0] = '\0';


   if (ArgusParser->tflag && (process == NULL)) {  // apply time filter to table  being scored not the rollup tables
      char *timeField = NULL;
      int i, slen = 0;

      for (i = 0; (ArgusTableColumnName[i] != NULL) && (i < ARGUSSQLMAXCOLUMNS); i++) {
//       if (!(strcmp("ltime", ArgusTableColumnName[i]))) {
//          timeField = "ltime";
//          break;
//       }
//       if (!(strcmp("stime", ArgusTableColumnName[i])))
//          timeField = "stime";
      }

      if (timeField == NULL) 
//       timeField = "second";
         timeField = "stime";

      if ((slen = strlen(ArgusSQLStatement)) > 0) {
         snprintf (&ArgusSQLStatement[strlen(ArgusSQLStatement)], MAXSTRLEN - slen, " and ");
         slen = strlen(ArgusSQLStatement);
      }

      snprintf (&ArgusSQLStatement[slen], MAXSTRLEN - slen, "%s >= %d and %s <= %d", timeField, (int)ArgusParser->startime_t.tv_sec, timeField, (int)ArgusParser->lasttime_t.tv_sec);
   }

   if (table != NULL) {
   if (!(strcmp ("Seconds", table))) {
      RaSQLQuerySecondsTable (ArgusParser->startime_t.tv_sec, ArgusParser->lasttime_t.tv_sec);

   } else {
      if (ArgusAutoId)
         sprintf (buf, "SELECT autoid,record from %s", table);
      else
         sprintf (buf, "SELECT record from %s", table);

      if (strlen(ArgusSQLStatement) > 0)
         sprintf (&buf[strlen(buf)], " WHERE %s", ArgusSQLStatement);

#ifdef ARGUSDEBUG
      ArgusDebug (1, "SQL Query %s\n", buf);
#endif
      if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) == 0) {
         if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
            if ((retn = mysql_num_fields(mysqlRes)) > 0) {
               while ((row = mysql_fetch_row(mysqlRes))) {
                  unsigned long *lengths = mysql_fetch_lengths(mysqlRes);
                  int autoid = 0;

                  bzero(sbuf, sizeof(sbuf));
                  if (ArgusAutoId && (retn > 1)) {
                     char *endptr;
                     autoid = strtol(row[0], &endptr, 10);
                     if (row[0] == endptr)
                        ArgusLog(LOG_ERR, "mysql database error: autoid returned %s", row[0]);
                     x = 1;
                  } else
                     x = 0;

                  ArgusParser->ArgusAutoId = autoid;
                  bcopy (row[x], sbuf, (int) lengths[x]);
                  ArgusScoreHandleRecord (ArgusParser, ArgusInput, process, (struct ArgusRecord *)&sbuf, &ArgusParser->ArgusFilterCode);
               }
            }

            mysql_free_result(mysqlRes);
         }

      } else {
         if (mysql_errno(RaMySQL) != ER_NO_SUCH_TABLE) {
            ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
#ifdef ARGUSDEBUG
         } else {
            ArgusDebug (4, "%s: skip missing table %s", __func__, table);
#endif
         }
      }
   }
   }
}

void
RaSQLQuerySecondsTable (unsigned int start, unsigned int stop)
{
   struct RaMySQLSecondsTable *sqry = NULL;
   char buf[2048], sbuf[2048];
   MYSQL_RES *mysqlRes;
   char *endptr, *str;
   int retn, x;

   str = "SELECT * from Seconds WHERE second >= %u and second <= %u",
   sprintf (buf, str, start, stop);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "SQL Query %s\n", buf);
#endif

   if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
      ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

   else {
      if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
         if ((retn = mysql_num_fields(mysqlRes)) > 0) {
            while ((row = mysql_fetch_row(mysqlRes))) {
               unsigned long *lengths;
    
               lengths = mysql_fetch_lengths(mysqlRes);
               bzero(sbuf, sizeof(sbuf));

               if ((sqry = (void *) ArgusCalloc (1, sizeof(*sqry))) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCalloc error %s", strerror(errno));

               for (x = 0; x < retn; x++) {
                  int y = x;
                  snprintf(sbuf, 2048, "%.*s ", (int) lengths[x], row[x] ? row[x] : "NULL");
                  
                  switch (y) {
                     case RAMYSQL_SECONDTABLE_PROBE:
                        sqry->probe = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_SECONDTABLE_SECOND:
                        sqry->second = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_SECONDTABLE_FILEINDEX:
                        sqry->fileindex = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_SECONDTABLE_OSTART:
                        sqry->ostart = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;

                     case RAMYSQL_SECONDTABLE_OSTOP:
                        sqry->ostop = strtol(sbuf, &endptr, 10);
                        if (sbuf == endptr)
                           ArgusLog(LOG_ERR, "mysql database error: second returned %s", sbuf);
                        break;
                  }
               }

               ArgusAddToQueue (ArgusModelerQueue, &sqry->qhdr, ARGUS_LOCK);
            }
         }

         mysql_free_result(mysqlRes);
      }
   }
}

void RaSQLProcessQueue (struct ArgusQueueStruct *);

void 
RaSQLProcessQueue (struct ArgusQueueStruct *queue)
{
   struct RaMySQLFileStruct *fstruct = NULL;
   struct RaMySQLSecondsTable *sqry = NULL, *tsqry = NULL;

   if (queue == NULL)
      return;

   while (queue->count) {
      if ((sqry = (struct RaMySQLSecondsTable *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
         int i, cnt = queue->count;

         if ((fstruct = (void *) ArgusCalloc (1, sizeof(*fstruct))) == NULL)
            ArgusLog(LOG_ERR, "RaSQLProcessQueue: ArgusCalloc error %s", strerror(errno));

         fstruct->fileindex = sqry->fileindex;
         fstruct->probe  = sqry->probe;
         fstruct->second = sqry->second;
         fstruct->ostart = sqry->ostart;
         fstruct->ostop  = sqry->ostop;
         ArgusAddToQueue (ArgusFileQueue, &fstruct->qhdr, ARGUS_LOCK);

         if (cnt > 0) {
            for (i = 0; i < cnt; i++) {
               if ((tsqry = (void *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
                  if (sqry->fileindex == tsqry->fileindex) {
                     if (fstruct->second > tsqry->second)
                        fstruct->second = tsqry->second;
                     if (fstruct->ostart > tsqry->ostart)
                        fstruct->ostart = tsqry->ostart;
                     if (fstruct->ostop < tsqry->ostop)
                        fstruct->ostop = tsqry->ostop;

                     ArgusFree(tsqry);

                  } else {
                     ArgusAddToQueue(queue, &tsqry->qhdr, ARGUS_LOCK);
                  }
               }
            }
         }

         ArgusFree(sqry);
      }
   }

   if (ArgusFileQueue->count) {
      int i, cnt = ArgusFileQueue->count;
      char buf[2048], sbuf[2048];
      MYSQL_RES *mysqlRes;
      struct stat statbuf;
      int retn, x;

      for (i = 0; i < cnt; i++) {
         if ((fstruct = (struct RaMySQLFileStruct *) ArgusPopQueue(ArgusFileQueue, ARGUS_LOCK)) !=  NULL) {
            char *str = NULL;
            bzero (buf, sizeof(buf));

            str = "SELECT filename from Filename WHERE id = %d",
            sprintf (buf, str, fstruct->fileindex);

            if ((retn = mysql_real_query(RaMySQL, buf, strlen(buf))) != 0)
               ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));

            else {
               if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
                  if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                     while ((row = mysql_fetch_row(mysqlRes))) {
                        char file[MAXSTRLEN];
                        char filenamebuf[MAXSTRLEN];
                        char directorypath[MAXSTRLEN];
                        char *ptr = NULL;
                        unsigned long *lengths;
          
                        lengths = mysql_fetch_lengths(mysqlRes);
                        if (RaFormat) {
                           char fbuf[1024];
                           time_t secs;
                           bzero (fbuf, sizeof(fbuf));
                           if ((ptr = strstr(RaFormat, "$srcid")) != NULL) {
                              struct RaMySQLProbeTable *psqry = (void *)ArgusProbeQueue->start;
                              RaProbeString = NULL;
                              bcopy (RaFormat, fbuf, (ptr - RaFormat));
                              if (psqry) {
                                 for (x = 0; x < ArgusProbeQueue->count; x++) {
                                    if ((psqry->probe == fstruct->probe) || (fstruct->probe == 0)) {
                                       RaProbeString = psqry->name;
                                       break;
                                    }
                                    psqry = (void *)psqry->qhdr.nxt;
                                 }
                                 if (RaProbeString)
                                    sprintf (&fbuf[strlen(fbuf)], "%s", RaProbeString);
                              }
                              
                              bcopy (&ptr[6], &fbuf[strlen(fbuf)], strlen(&ptr[6]));

                           } else {
                              bcopy (RaFormat, fbuf, strlen(RaFormat));
                           }

                           secs = (fstruct->second/RaPeriod) * RaPeriod;
                           strftime (directorypath, MAXSTRLEN, fbuf, localtime(&secs));
                        }

                        for (x = 0; x < retn; x++)
                           snprintf(sbuf, 2048, "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

                        if ((ptr = strchr(sbuf, '.')) == NULL)
                           ArgusLog(LOG_ERR, "RaSQLProcessQueue: Filename format error %s", sbuf);

                        if (RaFormat) 
                           sprintf (file, "%s/%s", directorypath, sbuf);
                        else
                           sprintf (file, "%s", sbuf);

                        while (file[strlen(file) - 1] == ' ')
                           file[strlen(file) - 1] = '\0';

                        if (!(strncmp(&file[strlen(file) - 3], ".gz", 3))) 
                           file[strlen(file) - 3] = '\0';

                        if (RaRoleString) {
                           sprintf (filenamebuf, "%s/%s/%s", ArgusArchiveBuf, RaRoleString, file);
                        } else {
                           sprintf (filenamebuf, "%s/%s", ArgusArchiveBuf, file);
                        }

                        if ((stat (filenamebuf, &statbuf)) != 0) {
                           char compressbuf[MAXSTRLEN];
                           sprintf (compressbuf, "%s.gz", filenamebuf);
                           if ((stat (compressbuf, &statbuf)) == 0) {
                              if ((fstruct->ostart >= 0) || (fstruct->ostop > 0)) {
                                 char command[MAXSTRLEN];
                                 sprintf (command, "gunzip %s", compressbuf);
#ifdef ARGUSDEBUG
                                 ArgusDebug (2, "RaSQLProcessQueue: local decomression command %s\n", command);
#endif
                                 if (system(command) < 0)
                                    ArgusLog(LOG_ERR, "RaSQLProcessQueue: system error", strerror(errno));
                              } else {
                                 sprintf (filenamebuf, "%s", compressbuf);
                              }

                           } else {
                              if (RaHost) {
                                 char command[MAXSTRLEN];
                                 int RaPort = ArgusParser->ArgusPortNum ?  ArgusParser->ArgusPortNum : ARGUS_DEFAULTPORT;

                                 if (RaRoleString != NULL)
                                    sprintf (command, "/usr/local/bin/ra -nnS %s:%d%s/%s/%s -w %s", RaHost, RaPort, RaArchive, RaRoleString, file, filenamebuf);
                                 else
                                    sprintf (command, "/usr/local/bin/ra -nnS %s:%d%s/%s -w %s", RaHost, RaPort, RaArchive, file, filenamebuf);
#ifdef ARGUSDEBUG
                                 ArgusDebug (2, "RaSQLProcessQueue: remote file caching command  %s\n", command);
#endif
                                 if (system(command) < 0)
                                    ArgusLog(LOG_ERR, "RaSQLProcessQueue: system error", strerror(errno));
                              }
                           }
                        }

                        fstruct->filename = strdup (filenamebuf);
                     }
                  }

                  mysql_free_result(mysqlRes);
               }
            }

            ArgusAddToQueue(ArgusFileQueue, &fstruct->qhdr, ARGUS_LOCK);
         }
      }
   }

   if (ArgusFileQueue->count) {
      struct RaMySQLFileStruct *fptr = NULL;
      int x;

      while ((fstruct = (struct RaMySQLFileStruct *) ArgusPopQueue(ArgusFileQueue, ARGUS_LOCK)) != NULL) {
         fptr = (struct RaMySQLFileStruct *) ArgusFileQueue->start;

         for (x = 0; x < ArgusFileQueue->count; x++) {
            if (fstruct->fileindex == fptr->fileindex) {
               if (fstruct->ostart < fptr->ostart)
                  fptr->ostart = fstruct->ostart;
               if (fstruct->ostop > fptr->ostop)
                  fptr->ostop = fstruct->ostop;

               ArgusFree(fstruct);
               fstruct = NULL;
               break;
            }

            fptr = (struct RaMySQLFileStruct *) fptr->qhdr.nxt;
         }

         if (fstruct != NULL) {
            ArgusAddFileList(ArgusParser, fstruct->filename, ARGUS_DATA_SOURCE,
                       fstruct->ostart, fstruct->ostop);
#ifdef ARGUSDEBUG
            ArgusDebug (2, "RaSQLProcessQueue: filename %s ostart %d  ostop %d\n",
                              fstruct->filename, fstruct->ostart, fstruct->ostop);
#endif
         }
      }

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (2, "RaSQLProcessQueue: query return NULL");
#endif
      RaParseComplete(SIGINT);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaSQLProcessQueue(0x%x)", queue);
#endif
}

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusAdjustStruct *nadp = NULL;
   int x, retn, found = 0, tableIndex;
   struct ArgusModeStruct *mode;
   char *table = NULL;

   if (!(parser->RaInitialized)) {
      char ArgusSQLStatement[MAXSTRLEN];
      MYSQL_RES *mysqlRes;

      parser->RaInitialized++;
      parser->RaWriteOut = 0;

      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      ArgusParseInit(ArgusParser, NULL);

      if (parser->ver3flag)
         ArgusLog(LOG_ERR, "rascore does not support version 3 output\n");

      if (ArgusParser->Sflag)
         usage();

      for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (parser->RaPrintAlgorithmList[x] != NULL) {
            if (!(strncmp(parser->RaPrintAlgorithmList[x]->field, "autoid", 6))) {
               ArgusAutoId = 1;
               break;
            }
         } else
            break;
      }

      if ((parser->ArgusMaskList) == NULL)
         parser->ArgusReverse = 1;
      else
         parser->ArgusReverse = 0;

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");


      if (parser->ArgusLabelerFileList) {
         struct ArgusLfileStruct *lfile = NULL, *start = NULL;

         if (parser->ArgusLabeler == NULL)
            if ((parser->ArgusLabeler = ArgusNewLabeler(parser, ARGUS_LABELER_ADDRESS)) == NULL)
               ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

         if ((lfile = (struct ArgusLfileStruct *)ArgusFrontList(parser->ArgusLabelerFileList)) != NULL) {
            start = lfile;
            do {
               if (!(RaReadAddressConfig (parser, parser->ArgusLabeler, lfile->filename) > 0))
                  ArgusLog (LOG_ERR, "ArgusNewLabeler: RaReadAddressConfig %s error", lfile->filename);

               ArgusPopFrontList(parser->ArgusLabelerFileList, ARGUS_LOCK);
               ArgusPushBackList(parser->ArgusLabelerFileList, (struct ArgusListRecord *)lfile, ARGUS_LOCK);
               lfile = (struct ArgusLfileStruct *)ArgusFrontList(parser->ArgusLabelerFileList);

            } while (lfile != start);
         }
      }

      if (parser->ArgusFlowModelFile) {
         if (parser->ArgusLabeler == NULL) {
            if ((parser->ArgusLabeler = ArgusNewLabeler(parser, ARGUS_LABELER_ADDRESS)) == NULL)
               ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");
         } else {
            if (!(RaReadAddressConfig (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile) > 0))
               ArgusLog (LOG_ERR, "ArgusNewLabeler: RaReadAddressConfig error");
         }
      }

      if (parser->ArgusAggregator->correct != NULL) { free(parser->ArgusAggregator->correct); parser->ArgusAggregator->correct = NULL; }

      if ((ArgusModelerQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

      if ((ArgusProbeQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

      if ((ArgusFileQueue = ArgusNewQueue()) == NULL)
         ArgusLog(LOG_ERR, "ArgusClientInit: RaNewQueue error %s", strerror(errno));

      if ((RaBinProcess = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*RaBinProcess))) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

#if defined(ARGUS_THREADS)
      pthread_mutex_init(&RaBinProcess->lock, NULL);
#endif

      nadp = &RaBinProcess->nadp;

      nadp->mode   = -1;
      nadp->modify =  0;
      nadp->slen   =  2;
 
      if (parser->aflag)
         nadp->slen = parser->aflag;

      if ((mode = parser->ArgusModeList) != NULL) {
         int i, ind;
         while (mode) {
            for (i = 0, ind = -1; i < ARGUSSPLITMODENUM; i++) {
               if (!(strncasecmp (mode->mode, RaSplitModes[i], strlen(RaSplitModes[i])))) {
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
                  }

                  case ARGUSSPLITTIME: /* "%d[yMwdhms] */
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
                                    nadp->qual = ARGUSSPLITYEAR;  
                                    nadp->size = nadp->value * 31556926 * 1000000LL;
                                    break;
                                 case 'M':
                                    nadp->qual = ARGUSSPLITMONTH; 
                                    nadp->size = nadp->value * 2629744 * 1000000LL;
                                    break;
                                 case 'w':
                                    nadp->qual = ARGUSSPLITWEEK;  
                                    nadp->size = nadp->value * 604800 * 1000000LL;
                                    break;
                                 case 'd':
                                    nadp->qual = ARGUSSPLITDAY;   
                                    nadp->size = nadp->value * 86400 * 1000000LL;
                                    break;
                                 case 'h':
                                    nadp->qual = ARGUSSPLITHOUR;  
                                    nadp->size = nadp->value * 3600 * 1000000LL;
                                    break;
                                 case 'm':
                                    nadp->qual = ARGUSSPLITMINUTE;
                                    nadp->size = nadp->value * 60 * 1000000LL;
                                    break;
                                  default:
                                    nadp->qual = ARGUSSPLITSECOND;
                                    nadp->size = nadp->value * 1000000LL;
                                    break;
                              }
                           }
                        }
                        if (mptr != NULL)
                            mode->mode = mptr;
                     }

                     nadp->modify = 1;

                     if (ind == ARGUSSPLITRATE) {
                        /* need to set the flow idle timeout value to be equal to or
                           just a bit bigger than (nadp->count * nadp->size) */

                        ArgusParser->timeout.tv_sec  = (nadp->count * (nadp->size / 1000000));
                        ArgusParser->timeout.tv_usec = 0;
                     }
                     break;

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

            } else {
               if (!(strncasecmp (mode->mode, "nocorrect", 9))) {
                  if (parser->ArgusAggregator->correct != NULL) {
                     free(parser->ArgusAggregator->correct);
                     parser->ArgusAggregator->correct = NULL;
                  }
                  parser->ArgusPerformCorrection = 0;
               } else
               if (!(strncasecmp (mode->mode, "rtime", 5)) ||
                  (!(strncasecmp (mode->mode, "realtime", 8)))) {
                  ArgusParser->status |= ARGUS_REAL_TIME_PROCESS;
               } else
               if (!(strncasecmp (mode->mode, "oui", 3))) {
                  parser->ArgusPrintEthernetVendors++;
               } else
               if (!strncasecmp (mode->mode, "nocreate", 8)) {
                  RaSQLNoCreate = 1;
               } else
               if (!(strncasecmp (mode->mode, "dump.tree", 9))) {
                  parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_LABEL;
                  parser->ArgusLabeler->status |= ARGUS_LABELER_DUMP;
               } else
               if ((!(strncasecmp (mode->mode, "debug.tree", 10))) ||
                   (!(strncasecmp (mode->mode, "debug", 5)))) {
                  parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE;
                  parser->ArgusLabeler->status |= ARGUS_LABELER_DEBUG;
               }
            }

            mode = mode->nxt;
         }
      }

      if (parser->ArgusLabeler && ((parser->ArgusLabeler->status & ARGUS_LABELER_DEBUG) ||
                                   (parser->ArgusLabeler->status & ARGUS_LABELER_DUMP))) {
         RaPrintLabelTree (parser->ArgusLabeler, parser->ArgusLabeler->ArgusAddrTree[AF_INET], 0, 0);
         exit(0);
      }

      RaBinProcess->size = nadp->size;

      if (nadp->mode < 0) {
         nadp->mode = ARGUSSPLITCOUNT;
         nadp->value = 10000;
         nadp->count = 1;
      }

//
// We need to loadup the baseline files if configured
//
      struct ArgusFileInput *baseline = NULL;

      if ((baseline = parser->ArgusBaselineList) != NULL) {
         char *optarg = baseline->filename;

         if (!(strncmp ("mysql:", optarg, 6))) {
            if (parser->readDbstr == NULL) {
                  free(parser->readDbstr);
               parser->readDbstr = strdup(optarg);
            }
         }
      }

      RaMySQLInit();

// so we've been given a time filter, so we have a start and end time
// stored in parser->startime_t && parser->lasttime_t, and we support
// wildcard options, so ..., the idea is that we need at some point to
// calculate the set of tables that we'll search for records.  We
// should do that here.  If startime_t is maxed out, then it has not
// been initialized, so set both start and last time to now ...
//
      if (parser->startime_t.tv_sec == 0x7FFFFFFF) {
         gettimeofday (&parser->startime_t, 0L);
         parser->lasttime_t = parser->startime_t;
      }

//
// So the actual baseline tables, datatbase, etc..., were set in the
// RaMySQLInit() based on the baseline definition.
//
// The idea is that we want a yearly, and monthly baseline in order
// to understand of the classification of FF / FU / UF / UU for a
// given input flow.  The (F)amiliar score is based on how often
// have we seen this flow identifier, and we compare it against
// a baseline for presence.
// 
// So, read in the annual and monthly baselines given a starting date,
// and compare against those for first seen and frequency.
// These will be stored in RaBaselines[0] and RaBaselines[1];
//

      RaTables = ArgusCreateSQLTimeTableNames(parser, RaTable);

      if (baseline && (RaBaselines == NULL)) {
         char *sptr, *str = NULL, *base = NULL;
         char *year = NULL, *month = NULL;

         char RaAnnualBaseLineTable[256];
         char RaMonthlyBaseLineTable[256];
         int n = 0;

            if (RaDatabase == NULL) {
               RaDatabase = strdup("inventory");
            }

            if (strcmp(RaDatabase, "inventory") == 0) {
               struct tm tmval;
               localtime_r(&parser->startime_t.tv_sec, &tmval);
               strftime (ArgusSQLTableNameBuf, 256, "ipAddrs_%Y_%m_%d", &tmval);
               str = strdup(ArgusSQLTableNameBuf);

            } else
            if (strcmp(RaDatabase, "ipMatrix") == 0) {
               struct tm tmval;
               localtime_r(&parser->startime_t.tv_sec, &tmval);
               strftime (ArgusSQLTableNameBuf, 256, "ip_%Y_%m_%d", &tmval);
               str = strdup(ArgusSQLTableNameBuf);

            } else
            if (strcmp(RaDatabase, "dnsMatrix") == 0) {
               struct tm tmval;
               localtime_r(&parser->startime_t.tv_sec, &tmval);
               strftime (ArgusSQLTableNameBuf, 256, "dns_%Y_%m_%d", &tmval);
               str = strdup(ArgusSQLTableNameBuf);
            } else
            if (strcmp(RaDatabase, "arpMatrix") == 0) {
               struct tm tmval;
               struct timeval durbuf, *dur = &durbuf;
               RaDiffTime (&parser->lasttime_t, &parser->startime_t, dur);

               localtime_r(&parser->startime_t.tv_sec, &tmval);
               if (dur->tv_sec > (86400 * 182))  {
                  strftime (ArgusSQLTableNameBuf, 256, "arp_%Y", &tmval);
               } else
               if (dur->tv_sec > (86400 * 14))  {
                  strftime (ArgusSQLTableNameBuf, 256, "arp_%Y_%m", &tmval);
               } else
                  strftime (ArgusSQLTableNameBuf, 256, "arp_%Y_%m_%d", &tmval);

               str = strdup(ArgusSQLTableNameBuf);
            } else
            if ((strcmp(RaDatabase, "ether") == 0) || (strcmp(RaDatabase, "etherMatrix") == 0)) {
               struct tm tmval;
               struct timeval durbuf, *dur = &durbuf;
               RaDiffTime (&parser->lasttime_t, &parser->startime_t, dur);

               localtime_r(&parser->startime_t.tv_sec, &tmval);
               if (dur->tv_sec > (86400 * 182))  {
                  strftime (ArgusSQLTableNameBuf, 256, "ether_%Y", &tmval);
               } else
               if (dur->tv_sec > (86400 * 14))  {
                  strftime (ArgusSQLTableNameBuf, 256, "ether_%Y_%m", &tmval);
               } else
                  strftime (ArgusSQLTableNameBuf, 256, "ether_%Y_%m_%d", &tmval);

               str = strdup(ArgusSQLTableNameBuf);
            }

            if (str != NULL) {
               char *tstr = strdup(str);
               if ((RaBaselines = ArgusCalloc(sizeof(void *), 5)) == NULL)
                  ArgusLog(LOG_ERR, "mysql_init error %s", strerror(errno));

               while ((sptr = strsep(&str, "_")) != NULL) {
                  switch (n++) {
                     case 0:  base = strdup(sptr); break;
                     case 1:  year = strdup(sptr); break;
                     case 2:  month = strdup(sptr); break;
                  }
               }

               snprintf (RaAnnualBaseLineTable, 256, "%s_%s", base, year);
               snprintf (RaMonthlyBaseLineTable, 256, "%s_%s_%s", base, year, month);

               if (strcmp(tstr, RaAnnualBaseLineTable))
                  RaBaselines[0] = strdup(RaAnnualBaseLineTable);

               if (strcmp(tstr, RaMonthlyBaseLineTable))
                  RaBaselines[1] = strdup(RaMonthlyBaseLineTable);

               if (str != NULL) free(str);
               if (tstr != NULL) free(tstr);
               if (base != NULL) free(base);
               if (year != NULL) free(year);
               if (month != NULL) free(month);
#ifdef ARGUSDEBUG
               ArgusDebug (2, "%s: opening baseline tables %s, %s", __func__, RaBaselines[0], RaBaselines[1]);
#endif
            }
            if (baseline->filename)
               free(baseline->filename);
            ArgusFree(baseline);
         }

         bzero(&ArgusTableColumnName, sizeof (ArgusTableColumnName));

         if (RaBaselines != NULL) {
            int eNflag = parser->eNflag;
            int sNflag = parser->sNflag;

	    parser->eNflag = -1;
	    sNflag = 0;

            tableIndex = 0;
            retn = -1;
            while ((table = RaBaselines[tableIndex]) != NULL) {
               tableIndex++;
            }
            for (x = 0; x < tableIndex; x++) {
               table = RaBaselines[x];
               if (strcmp("Seconds", table)) {
                  sprintf (ArgusSQLStatement, "desc %s", table);
                  if ((retn = mysql_real_query(RaMySQL, ArgusSQLStatement , strlen(ArgusSQLStatement))) != 0) {
                     if (mysql_errno(RaMySQL) != ER_NO_SUCH_TABLE) {
                        ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(RaMySQL));
#ifdef ARGUSDEBUG
                     } else {
                        ArgusDebug (4, "%s: skip missing table %s", __func__, table);
#endif
                     }
                  } else {
                     break;
                  }
               }
            }

            if (retn == 0) {
               if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
                  if ((retn = mysql_num_fields(mysqlRes)) > 0) {
                     int ind = 0;
                     while ((row = mysql_fetch_row(mysqlRes)))
                        ArgusTableColumnName[ind++] = strdup(row[0]);

                     mysql_free_result(mysqlRes);
                  }
               }

               if (retn > 0) {
                  int x, i = 0;

                  while (parser->RaPrintAlgorithmList[i] != NULL) {
                    ArgusFree(parser->RaPrintAlgorithmList[i]);
                    parser->RaPrintAlgorithmList[i] = NULL;
                    i++;
                  }

                  for (x = 0; (ArgusTableColumnName[x] != NULL) && (x < ARGUSSQLMAXCOLUMNS); x++) {
                     for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
                        if (!strcmp(RaPrintAlgorithmTable[i].field, ArgusTableColumnName[x])) {
                           if ((parser->RaPrintAlgorithmList[x] = ArgusCalloc(1, sizeof(*parser->RaPrintAlgorithm))) == NULL)
                              ArgusLog (LOG_ERR, "ArgusCalloc error %s", strerror(errno));

                           bcopy(&RaPrintAlgorithmTable[i], parser->RaPrintAlgorithmList[x], sizeof(*parser->RaPrintAlgorithm));
                        }
                     }
                  }

                  ArgusProcessSOptions(parser);
               }

               if (RaBaselines) {
                  if (RaBaselines[0] != NULL) {
                     if ((RaAnnualProcess = RaScoreNewProcess(parser)) == NULL)
                        ArgusLog (LOG_ERR, "ArgusClientInit: RaScoreNewProcess error");
                     RaSQLQueryTable (RaBaselines[0], RaAnnualProcess);
                  }

                  if (RaBaselines[1] != NULL) {
                     if ((RaMonthlyProcess = RaScoreNewProcess(parser)) == NULL)
                        ArgusLog (LOG_ERR, "ArgusClientInit: RaScoreNewProcess error");
                     RaSQLQueryTable (RaBaselines[1], RaMonthlyProcess);
                  }
                  found++;
               }
            }
            if (!found) {
#ifdef ARGUSDEBUG
               ArgusDebug (1, "No SQL Baseline tables found\n");
#endif
            }
            parser->eNflag = eNflag;
            parser->sNflag = sNflag;
         }
      }

   if (RaTables != NULL) {
      tableIndex = 0;
      while ((table = RaTables[tableIndex]) != NULL) {
         tableIndex++;
      }

      for (x = 0; x < tableIndex; x++) {
         RaSQLQueryTable (RaTables[x], NULL);
 
         if (ArgusModelerQueue->count > 0)
            RaSQLProcessQueue (ArgusModelerQueue);
         else
            RaParseComplete (SIGINT);
      }
   }
}

void
usage ()
{
   extern char version[];

   fprintf (stdout, "RaSql Version %s\n", version);
   fprintf (stdout, "usage: %s -r mysql://[user[:pass]@]host[:port]/db/table\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s -t timerange -r mysql://[user[:pass]@]host[:port]/db\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [ra-options] [rasql-options] [- filter-expression]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -M sql='where clause'  pass where clause to database engine.\n");
   fprintf (stdout, "         -r <dbUrl>             read argus data from mysql database.\n");
   fprintf (stdout, "             Format:            mysql://[user[:pass]@]host[:port]/db/table\n");
   fflush (stdout);

   exit(1);
}


/*
 *  Convert host name to internet address.
 *  Return 0 upon failure.
 */

unsigned int **
argus_nametoaddr(char *name)
{
#ifndef h_addr
   static unsigned int *hlist[2];
#endif
   struct hostent *hp;

   if ((hp = gethostbyname(name)) != NULL) {
#ifndef h_addr
      hlist[0] = (unsigned int *)hp->h_addr;
#if defined(_LITTLE_ENDIAN)
      *hp->h_addr = ntohl(*hp->h_addr);
#endif
      return hlist;
#else
#if defined(_LITTLE_ENDIAN)
      {
         unsigned int **p;
          for (p = (unsigned int **)hp->h_addr_list; *p; ++p)
             **p = ntohl(**p);
      }
#endif
      return (unsigned int **)hp->h_addr_list;
#endif
   }
   else
      return 0;
}



int
RaProcessSplitOptions(struct ArgusParserStruct *parser, char *str, int len, struct ArgusRecordStruct *ns)
{
   char resultbuf[MAXSTRLEN], tmpbuf[MAXSTRLEN];
   char *ptr = NULL, *tptr = str;
   int retn = 0, i, x;

   len = len > MAXSTRLEN ? MAXSTRLEN : len;
   bzero (resultbuf, len);

   if (ns == NULL)
      return (1);

   while ((ptr = strchr (tptr, '$')) != NULL) {
      *ptr++ = '\0';
      sprintf (&resultbuf[strlen(resultbuf)], "%s", tptr);

      for (i = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
         if (!strncmp (RaPrintAlgorithmTable[x].field, ptr, strlen(RaPrintAlgorithmTable[x].field))) {
            bzero (tmpbuf, sizeof(tmpbuf));
            RaPrintAlgorithmTable[x].print(parser, tmpbuf, ns, RaPrintAlgorithmTable[x].length);

            while (isspace((int)tmpbuf[strlen(tmpbuf) - 1]))
               tmpbuf[strlen(tmpbuf) - 1] = '\0';

            while (isspace((int)tmpbuf[i])) i++;
            sprintf (&resultbuf[strlen(resultbuf)], "%s", &tmpbuf[i]);

            ptr += strlen(RaPrintAlgorithmTable[x].field);
            while (*ptr && (*ptr != '$'))
               bcopy (ptr++, &resultbuf[strlen(resultbuf)], 1);
            break;
         }
      }

      tptr = ptr;
      retn++;
   }

   if (retn) {
      bzero (str, len);
      bcopy (resultbuf, str, strlen(resultbuf));
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaProcessSplitOptions(%s, %d, 0x%x): returns %d", str, len, ns, retn);
#endif

   return (retn);
}


extern int RaDaysInAMonth[12];

time_t ArgusTableStartSecs = 0;
time_t ArgusTableEndSecs = 0;

#define ARGUS_MAX_TABLE_LIST_SIZE	0x10000

char **
ArgusCreateSQLTimeTableNames (struct ArgusParserStruct *parser, char *table)
{
   char **retn = NULL, *fileStr = NULL;
   struct ArgusAdjustStruct *nadp = &RaBinProcess->nadp;
   int retnIndex = 0;

   if (table && (strchr(table, '%') || strchr(table, '$'))) {
      if ((retn = ArgusCalloc(sizeof(void *), ARGUS_MAX_TABLE_LIST_SIZE)) == NULL)
         ArgusLog(LOG_ERR, "ArgusCreateSQLTimeTableNames ArgusCalloc %s", strerror(errno));

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

         ArgusTableEndSecs = start / 1000000;

         while (ArgusTableEndSecs < parser->lasttime_t.tv_sec) {
            fileStr = NULL;
            tableSecs = ArgusTableEndSecs;

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

            ArgusTableStartSecs = tableSecs;

            switch (nadp->qual) {
               case ARGUSSPLITYEAR:  
                  tmval.tm_year++;
                  ArgusTableEndSecs = mktime(&tmval);
                  break;
               case ARGUSSPLITMONTH:
                  tmval.tm_mon++;
                  ArgusTableEndSecs = mktime(&tmval);
                  break;
               case ARGUSSPLITWEEK: 
               case ARGUSSPLITDAY: 
               case ARGUSSPLITHOUR: 
               case ARGUSSPLITMINUTE: 
               case ARGUSSPLITSECOND: 
                  ArgusTableEndSecs = tableSecs + size;
                  break;
            }

            fileStr = ArgusSQLTableNameBuf;

            if (fileStr != NULL) {
               retn[retnIndex++] = strdup(fileStr);
            }
         }

      } else {
         ArgusLog(LOG_ERR, "ArgusCreateSQLTimeTableNames no time mode (-M time xx) specified");
      }

   } else {
      if (table) {
         bcopy(table, ArgusSQLTableNameBuf, strlen(table));
         fileStr = ArgusSQLTableNameBuf;

         if (retn == NULL) {
            if ((retn = ArgusCalloc(sizeof(void *), 16)) == NULL)
               ArgusLog(LOG_ERR, "ArgusCreateSQLTimeTableNames ArgusCalloc %s", strerror(errno));
            retnIndex = 0;
         }

         retn[retnIndex] = strdup(fileStr);
      }
   }

   return (retn);
}


/*
    So first look to see if the table already exists.
    If so and we're suppose to delete, then delete it.
    Then look to see if the name is in our list of default
    RaTableCreateNames[] to see if we need to remove it
    from that list, if we didn't catch the table in the
    other list.  At the end of this routine cindex is pointing 
    at the right place.
*/


char *
ArgusCreateSQLSaveTableName (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns, char *table)
{
   char *retn = NULL;
   struct ArgusAdjustStruct *nadp = &RaBinProcess->nadp;

   if (strchr(table, '%') || strchr(table, '$')) {
      int size = nadp->size / 1000000;
      long long start;
      time_t tableSecs;
      struct tm tmval;

      if (ns != NULL) 
         start = ArgusFetchStartuSecTime(ns);
      else 
         start = parser->ArgusRealTime.tv_sec * 1000000LL + parser->ArgusRealTime.tv_usec;
      
      tableSecs = start / 1000000;

      if (!(ArgusTableStartSecs) || !((tableSecs >= ArgusTableStartSecs) && (tableSecs < ArgusTableEndSecs))) {
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

         if (strftime(ArgusSQLSaveTableNameBuf, MAXSTRLEN, table, &tmval) <= 0)
            ArgusLog (LOG_ERR, "RaSendArgusRecord () ArgusCalloc %s\n", strerror(errno));

         RaProcessSplitOptions(ArgusParser, ArgusSQLSaveTableNameBuf, MAXSTRLEN, ns);

         ArgusTableStartSecs = tableSecs;

         switch (nadp->qual) {
            case ARGUSSPLITYEAR:  
               tmval.tm_year++;
               ArgusTableEndSecs = mktime(&tmval);
               break;
            case ARGUSSPLITMONTH:
               tmval.tm_mon++;
               ArgusTableEndSecs = mktime(&tmval);
               break;
            case ARGUSSPLITWEEK: 
            case ARGUSSPLITDAY: 
            case ARGUSSPLITHOUR: 
            case ARGUSSPLITMINUTE: 
            case ARGUSSPLITSECOND: 
               ArgusTableEndSecs = tableSecs + size;
               break;
         }
      }

      retn = ArgusSQLSaveTableNameBuf;

   } else {
      bcopy(ArgusSQLSaveTableNameBuf, table, strlen(table));
      retn = ArgusSQLSaveTableNameBuf;
   }

   return (retn);
}


int
ArgusCreateSQLSaveTable(char *table)
{
   int retn = 0, cindex = 0, ind = 0, i, x, exists = 0;
   struct ArgusMaskStruct *ArgusMaskDefs = ArgusIpV4MaskDefs; 
   char stable[256], sbuf[MAXSTRLEN], kbuf[MAXSTRLEN];

   sprintf (stable, "%s", table);

   bzero(sbuf, sizeof(sbuf));
   bzero(kbuf, sizeof(kbuf));

   for (i = 0; i < RA_MAXTABLES && !exists; i++) {
      if (RaTableExistsNames[i] != NULL) {
         if (!strcmp(RaTableExistsNames[i], stable))
            exists++;
      } else
         break;
   }

   if (!exists) {
      RaTableCreateNames[cindex] = strdup(stable);

      sprintf (sbuf, "CREATE table %s (", RaTableCreateNames[cindex]);
      ind = 0;

      for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
         if (ArgusParser->RaPrintAlgorithmList[i] != NULL) {
            ArgusParser->RaPrintAlgorithm = ArgusParser->RaPrintAlgorithmList[i];

            for (x = 0; x < ARGUS_MAX_PRINT_ALG; x++) {
               if (!strcmp(ArgusParser->RaPrintAlgorithm->field, RaPrintAlgorithmTable[x].field)) {
                  if (ind++ > 0)
                     sprintf (&sbuf[strlen(sbuf)], ",");

                  sprintf (&sbuf[strlen(sbuf)], "%s %s", RaPrintAlgorithmTable[x].field, RaPrintAlgorithmTable[x].dbformat);
                  break;
               }
            }
         }
      }

      if ((ArgusParser->ArgusAggregator != NULL) || ArgusAutoId) {
         struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;

         long long mask = 0;

         while (agg != NULL) {
            mask |= agg->mask;
            agg = agg->nxt;
         }

         if (mask || ArgusAutoId) {
            ind = 0;
            sprintf (kbuf, "primary key (");

            if (ArgusAutoId) {
               sprintf (&kbuf[strlen(kbuf)], "autoid");
               ind++;
            }

            for (i = 0; i < ARGUS_MAX_MASK_LIST; i++) {
               int found; 
               if (mask & (0x01LL << i)) {
                  for (found = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                     if (ArgusParser->RaPrintAlgorithmList[x] != NULL) {
                        ArgusParser->RaPrintAlgorithm = ArgusParser->RaPrintAlgorithmList[x];
                        if (!strcmp(ArgusParser->RaPrintAlgorithm->field, ArgusMaskDefs[i].name)) {
                           found = 1;
                           break;
                        }
                     }
                  }

                  if (!found)
                     ArgusLog(LOG_ERR, "key field '%s' not in schema (-s option)",  ArgusMaskDefs[i].name);

                  for (x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
                     if (!(strcasecmp (ArgusMaskDefs[i].name, RaPrintAlgorithmTable[x].field))) {
                        if (ind++ > 0)
                           sprintf (&kbuf[strlen(kbuf)], ",");

                        sprintf (&kbuf[strlen(kbuf)], "%s", RaPrintAlgorithmTable[x].field);
                        break;
                     }
                  }
               }
            }
            sprintf (&kbuf[strlen(kbuf)], ")");
         }
      }

      if (strlen(kbuf))
         sprintf (&sbuf[strlen(sbuf)], ", %s", kbuf);

      if (ArgusSOptionRecord)
         sprintf (&sbuf[strlen(sbuf)], ", record blob");

      if ((MySQLVersionMajor > 4) || ((MySQLVersionMajor == 4) &&
                                      (MySQLVersionMinor >= 1)))
         sprintf (&sbuf[strlen(sbuf)], ") ENGINE=%s", ArgusParser->MySQLDBEngine);
      else
         sprintf (&sbuf[strlen(sbuf)], ") TYPE=%s", ArgusParser->MySQLDBEngine);
      RaTableCreateString[cindex] = strdup(sbuf);

      cindex++;

      for (i = 0; i < cindex; i++) {
         char *str = NULL;
         if (RaTableCreateNames[i] != NULL) {
            if ((str = RaTableCreateString[i]) != NULL) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "generating table %s\n", str);
#endif
               if ((retn = mysql_real_query(RaMySQL, str, strlen(str))) != 0)
                  ArgusLog(LOG_INFO, "mysql_real_query error %s", mysql_error(RaMySQL));

               ArgusCreateTable = 1;
               RaSQLCurrentTable = strdup(table);
            }
         }
      }

   } else {
      if (RaSQLCurrentTable == NULL)
         RaSQLCurrentTable = strdup(table);
      retn = 0;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCreateSQLSaveTable (%s) returning", table, retn);
#endif
   return (retn);
}


struct RaOutputProcessStruct *
RaScoreNewProcess(struct ArgusParserStruct *parser)
{
   struct RaOutputProcessStruct *retn = NULL;

   if ((retn = (struct RaOutputProcessStruct *) ArgusCalloc (1, sizeof(*retn))) != NULL) {
      if ((retn->queue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "RaScoreNewProcess: ArgusNewQueue error %s\n", strerror(errno));

      if ((retn->delqueue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "RaScoreNewProcess: ArgusNewQueue error %s\n", strerror(errno));

      if ((retn->htable = ArgusNewHashTable(0x100000)) == NULL)
         ArgusLog (LOG_ERR, "RaScoreNewProcess: ArgusCalloc error %s\n", strerror(errno));

   } else
      ArgusLog (LOG_ERR, "RaScoreNewProcess: ArgusCalloc error %s\n", strerror(errno));

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaScoreNewProcess(0x%x) returns 0x%x\n", parser, retn);
#endif
   return (retn);
}


char ArgusScoreHandleRecordBuffer[ARGUS_MAXRECORDSIZE];

int
ArgusScoreHandleRecord (struct ArgusParserStruct *parser, 
                        struct ArgusInput *input, 
                        struct RaOutputProcessStruct *process, 
                        struct ArgusRecord *ptr, 
                        struct nff_program *filter)
{
   struct ArgusRecordStruct *argus = NULL;
   int retn = 0;

   if (ptr != NULL) {
      int len = ntohs(ptr->hdr.len) * 4;
      struct nff_insn *fcode = filter->bf_insns;

      if (len < sizeof(input->ArgusOriginalBuffer)) {
         bcopy ((char *)ptr, (char *)input->ArgusOriginal, len);
#ifdef _LITTLE_ENDIAN
         ArgusNtoH(ptr);
#endif
         switch (ptr->hdr.type & 0xF0) {
            case ARGUS_MAR:
               parser->ArgusTotalMarRecords++;
               break;

            case ARGUS_EVENT:
               parser->ArgusTotalEventRecords++;
               break;
      
            case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
            case ARGUS_FAR:
               parser->ArgusTotalFarRecords++;
               break;
         }

         if ((argus = ArgusGenerateRecordStruct (parser, input, (struct ArgusRecord *) ptr)) != NULL) {
            if ((retn = ArgusFilterRecord (fcode, argus)) != 0) {
               if (parser->ArgusGrepSource || parser->ArgusGrepDestination)
                  if (ArgusGrepUserData(parser, argus) == 0)
                     return (argus->hdr.len * 4);

               if (parser->ArgusMatchLabel) {
                  struct ArgusLabelStruct *label;
                  if (((label = (void *)argus->dsrs[ARGUS_LABEL_INDEX]) != NULL)) {
                     if (regexec(&parser->lpreg, label->l_un.label, 0, NULL, 0))
                        return (argus->hdr.len * 4);
                  } else
                     return (argus->hdr.len * 4);
               }

               if (!(((ptr->hdr.type & 0xF0) == ARGUS_MAR) && (argus->status & ARGUS_INIT_MAR)))
                  parser->ArgusTotalRecords++;
               else {
#ifdef _LITTLE_ENDIAN
                  ArgusHtoN(ptr);
#endif
               }

               if (parser->sNflag && (parser->sNflag >= parser->ArgusTotalRecords))
                  return (argus->hdr.len * 4);

               if (process != NULL) 
                  RaProcessBaselineData (parser, argus, process);
               else {
                  if ((retn = ArgusCheckTime (parser, argus, ArgusTimeRangeStrategy)) != 0)
                     RaProcessRecord (parser, argus);
               }      
            }
      
            retn = 0;
      
            if (ptr->hdr.type & ARGUS_MAR) {
               switch (ptr->hdr.cause & 0xF0) {
                  case ARGUS_STOP:
                  case ARGUS_SHUTDOWN:
                  case ARGUS_ERROR: {
                     if (ptr->argus_mar.value == input->srcid.a_un.value) {
#ifdef ARGUSDEBUG
                        ArgusDebug (3, "ArgusScoreHandleRecord (%p, %p) received closing Mar\n", ptr, filter);
#endif
                        if (parser->Sflag)
                           retn = 1;
                     }
                     break;
                  }
               }
            }

         } else
            retn = -1;

         if ((parser->eNflag >= 0) && (parser->ArgusTotalRecords > parser->eNflag)) {
               parser->eNflag = 0;
               retn = -2;
         }

         if (parser->RaPollMode)
            retn = -1;

         if (retn >= 0)
            retn = argus->hdr.len * 4;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusScoreHandleRecord (%p, %p) returning %d\n", ptr, filter, retn);
#endif

   return (retn);
}
#endif
