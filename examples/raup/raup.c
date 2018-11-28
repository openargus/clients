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
 */

/*
 * raup - acceptable use policy processing node.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * $Id: //depot/gargoyle/clients/examples/raup/raup.c#13 $
 * $DateTime: 2018/06/12 10:32:48 $
 * $Change: 1 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>

#include <sys/types.h>
#include <dirent.h>

#if defined(ARGUS_SOLARIS)
#include <strings.h>
#include <string.h>
#endif

#include <math.h>

#if defined(HAVE_UUID_UUID_H)
#include <uuid/uuid.h>
#else
#if defined(HAVE_UUID_H)
#include <uuid.h>
#endif
#endif

#include <rabins.h>
#include <argus_util.h>
#include <argus_label.h>
#include <argus_client.h>
#include <argus_filter.h>
#include <argus_main.h>
#include <argus_cluster.h>
#include "rasplit.h"

#ifdef ARGUS_MYSQL
# include <mysql.h>
# include "rasql_common.h"
#endif

#include <argus_threads.h>
#include <time.h>


#define RAUP_POLICY_DIRTY	0x0100

#define ARGUS_RECORD_MODIFIED   0x0100
#define ARGUS_RECORD_CLEARED    0x0200

#define ARGUS_SQL_INSERT        0x0100000
#define ARGUS_SQL_SELECT        0x0200000
#define ARGUS_SQL_UPDATE        0x0400000
#define ARGUS_SQL_DELETE        0x0800000
#define ARGUS_SQL_REWRITE       0x1000000

#define ARGUS_SQL_STATUS        (ARGUS_SQL_INSERT | ARGUS_SQL_SELECT | ARGUS_SQL_UPDATE | ARGUS_SQL_DELETE)

extern void ArgusSetChroot(char *);

int RaRealTime = 0;
time_t RaLastDatabaseTimeStamp = 0;
time_t RaLastDatabaseTimeInterval = 0;

#if defined(ARGUS_THREADS)
pthread_attr_t RaTopAttr;
pthread_t RaMySQLThread = 0;
pthread_t RaMySQLSelectThread = 0;
pthread_t RaMySQLUpdateThread = 0;
pthread_t RaMySQLInsertThread = 0;
pthread_t RaMySQLDeleteThread = 0;
pthread_mutex_t RaMySQLlock;

void *ArgusMySQLInsertProcess (void *);
void *ArgusMySQLSelectProcess (void *);
void *ArgusMySQLUpdateProcess (void *);
void *ArgusMySQLDeleteProcess (void *);
#endif


static int RaDescend(struct ArgusQueueStruct *, char *, size_t, size_t);
struct ArgusFileInput *ArgusAddConfigList (struct ArgusQueueStruct *, char *, int, long long, long long);
int RaProcessRecursiveConfigs (struct ArgusQueueStruct *, char *);

char *RaHost = NULL, *RaUser = NULL, *RaPass = NULL;
int RaPort = 0;

struct ArgusInput *ArgusInput = NULL;

#ifdef ARGUS_MYSQL
void RaMySQLInit (int);
MYSQL_ROW row;
MYSQL *RaMySQL = NULL;

char *RaDatabase = NULL;
char **RaTables = NULL;

long long ArgusTotalSQLSearches = 0;
long long ArgusTotalSQLUpdates  = 0;
long long ArgusTotalSQLWrites = 0;

int ArgusSQLBulkInsertSize = 0;
int ArgusSQLMaxPacketSize = 0;
int ArgusSQLBulkBufferSize = 0;
int ArgusSQLBulkBufferIndex = 0;
int ArgusSQLBulkBufferCount = 0;
char *ArgusSQLBulkLastTable = NULL;
char *ArgusSQLBulkBuffer = NULL;
char *ArgusSQLVersion = NULL;
char *ArgusTableColumnName[ARGUSSQLMAXCOLUMNS];
size_t ArgusTableColumnKeys;
int MySQLVersionMajor = 0;
int MySQLVersionMinor = 0;
int MySQLVersionSub = 0;

#endif /* ARGUS_MYSQL */

extern int ArgusSOptionRecord;
int ArgusDeleteTable = 0;

int ArgusDropTable = 0;
int ArgusCreateTable = 0;
int ArgusAutoId = 0;
int ArgusSQLSecondsTable = 0;
time_t ArgusTableStartSecs = 0;
time_t ArgusTableEndSecs = 0;

struct timeval ArgusLastRealTime     = {0, 0};
struct timeval ArgusLastTime         = {0, 0};
struct timeval ArgusThisTime         = {0, 0};
struct timeval ArgusCurrentTime      = {0, 0};

char ArgusSQLSaveTableNameBuf[MAXSTRLEN];
struct tm ArgusSaveTableTmStruct;
time_t ArgusSaveTableSeconds = 0;

int ArgusCreateSQLSaveTable(char *, char *);
int ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, int);
struct ArgusRecordStruct *ArgusCheckSQLCache(struct ArgusParserStruct *, struct RaBinStruct *, struct ArgusRecordStruct *);

struct ArgusSQLQueryStruct *ArgusGenerateSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, int);
void ArgusDeleteSQLQuery (struct ArgusSQLQueryStruct *);

void RaMySQLDeleteRecords(struct ArgusParserStruct *, struct ArgusRecordStruct *);

void RaSQLQueryNetworksTable (unsigned int, unsigned int, unsigned int);
void RaSQLQueryProbes (void);
void RaSQLQuerySecondsTable (unsigned int, unsigned int);

char *ArgusCreateSQLSaveTableName (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);
struct RaBinProcessStruct *ArgusNewRateBins (struct ArgusParserStruct *, struct ArgusRecordStruct *);

int RaInitialized = 0;
int RaSQLMcastMode = 0;

char *RaRoleString = NULL;
char *RaProbeString = NULL;
char *RaSQLSaveTable = NULL;
char *RaSQLCurrentTable = NULL;

#define RA_MINTABLES            128
#define RA_MAXTABLES            0x10000
unsigned int RaTableFlags = 0;

char       *RaTableValues[256];
char  *RaTableExistsNames[RA_MAXTABLES];
char  *RaTableCreateNames[RA_MINTABLES];
char *RaTableCreateString[RA_MINTABLES];
char *RaTableDeleteString[RA_MINTABLES];

#define ARGUSSQLMAXCOLUMNS      256
char *ArgusTableColumnName[ARGUSSQLMAXCOLUMNS];

char ArgusSQLTableNameBuf[MAXSTRLEN];

char *RaSource       = NULL;
char *RaArchive      = NULL;
char *RaLocalArchive = NULL;
char *RaFormat       = NULL;
char *RaTable        = NULL;
int   RaPeriod       = 1;
int   RaStatus       = 1;

int   RaSQLMaxSecs   = 0;
int   RaSQLUpdateDB  = 1;
int   RaSQLCacheDB   = 0;
int   RaSQLRewrite   = 0;
int   RaSQLDBInserts = 0;
int   RaSQLDBUpdates = 0;
int   RaSQLDBDeletes = 1;
int   RaFirstManRec  = 1;


#define RAUP_POLICY_STRATEGY_INDEX	0x0100
#define RAUP_PERMISSIVE_POLICY		0x0000
#define RAUP_RESTRICTIVE_POLICY		0x0100

#define RAUP_SERVICE_VERIFICATION	0x0200

#define RAUP_PARSING_SINGLELINE		0x1000
#define RAUP_PARSING_MULTILINE		0x2000


#define RAUP_ITEMS          		4
#define RAUP_SERVICE_MATCHED		0x01
#define RAUP_SRC_GROUP_VALIDATED	0x02
#define RAUP_DST_GROUP_VALIDATED	0x04
#define RAUP_SERVICE_VALIDATED		0x08

#define RAUP_VERIFICATION_MASK		0x07


#define RAUP_RCITEMS			11

#define RAUP_POLICYUUID			0
#define RAUP_POLICYNAME			1
#define RAUP_POLICYVERSION		2
#define RAUP_POLICYSTATUS		3
#define RAUP_POLICYSETSTRATEGY		4
#define RAUP_SERVICE            	5
#define RAUP_VERIFICATION       	6
#define RA_SERVICES_SIGNATURES		7
#define RA_GROUP              		8
#define RAUP_GROUP              	9
#define RAUP_POLICYSET              	10

char *RaupResourceFileStr [] = {
   "RAUP_POLICYUUID=",
   "RAUP_POLICYNAME=",
   "RAUP_POLICYVERSION=",
   "RAUP_POLICYSTATUS=",
   "RAUP_POLICYSETSTRATEGY=",
   "RAUP_SERVICE=",
   "RAUP_VERIFICATION=",
   "RA_SERVICES_SIGNATURES=",
   "RA_GROUP=",
   "RAUP_GROUP=",
   "RAUP_POLICYSET=",
};

struct RaAupGroupStruct {
   int status;
   char *name;
   char *locality;

   struct ArgusQueueStruct *queue;
   struct ArgusLabelerStruct *labeler;
};

struct RaAupTargetStruct {
   char *targetString;
};

struct RaAupEffectStruct {
   char *effectString;
};

struct RaAupConditionStruct {
   char *conditionString;
};

struct RaAupObligationStruct {
   char *obligationString;
};

struct RaAupAdvice {
   char *adviceString;
};

struct RaAupServiceStruct {
   struct RaAupServiceStruct *n_nxt;
   unsigned int status, hashval, ref;
   struct timeval stime, ltime;

   char *name;
   char *rule;
   struct nff_program filter;
};

struct RaAupCombiningAlgStruct {
   char *combiningString;
};

struct RaAupPolicyStruct {
   struct ArgusListObjectStruct *nxt, *prv;
   unsigned int status, value;
   struct timeval stime, ltime;

   char *name;

   struct RaAupTargetStruct *target;
   struct RaAupCombiningAlgStruct *ruleCombiningAlgorithm;
   struct RaAupEffectStruct *effect;
   struct RaAupConditionStruct *condition;
   struct RaAupObligationStruct *obligation;
   struct RaAupAdviceStruct *advice;

   char *rule;
   int ruleIndex;
   struct RaAupServiceStruct *service;
   struct RaAupGroupStruct *clients;
   struct RaAupGroupStruct *servers;

   unsigned int conform, nonconform, match, client, server, verify, replies;
};

struct RaAupRuleSetStruct {
   struct ArgusListObjectStruct *nxt, *prv;
   unsigned int status, value;
   struct timeval stime, ltime;

   char *name;

   struct RaAupTargetStruct *target;
   struct RaAupCombiningAlgStruct *policyCombiningAlgorithm;
   struct RaAupObligationStruct *obligation;
   struct RaAupAdviceStruct *advice;

   struct RaAupServiceStruct *service;
   struct ArgusListStruct *policies;

   unsigned int conform, nonconform, match, client, server, verify, replies;
};

struct RaAupPolicySetStruct {
   u_int status;
   char *name;

   struct RaAupTargetStruct *target;
   struct RaAupCombiningAlgStruct *policyCombiningAlgorithm;
   struct RaAupObligationStruct *obligation;
   struct RaAupAdviceStruct *advice;

   struct ArgusListStruct *ruleSet;
   struct ArgusListStruct *policies;
};

struct RaAupStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusQueueStruct *queue;
   u_int status, retn;
   uuid_t uuid;
   char *name;
   int version;

   struct snamemem servicetable[HASHNAMESIZE];
   struct gnamemem grouptable[HASHNAMESIZE];

   struct ArgusLabelerStruct *ArgusLocalLabeler;
   struct ArgusLabelerStruct *ArgusServicesLabeler;
   struct RaAupPolicySetStruct *ArgusPolicySet;
};


int RaProcessAup (struct ArgusParserStruct *, struct ArgusRecordStruct *, struct RaAupStruct *);
int RaFlushAup (struct ArgusParserStruct *, struct RaAupStruct *);
int RaPrintAup (struct ArgusParserStruct *, struct RaAupStruct *);
struct RaAupRuleSetStruct *ArgusNewRuleSet(struct RaAupServiceStruct *);
struct RaAupRuleSetStruct *RaFindRuleSet (struct RaAupPolicySetStruct *, struct RaAupServiceStruct *);


#include <ctype.h>

static int argus_version = ARGUS_VERSION;
struct RaBinProcessStruct *RaBinProcess = NULL;

struct ArgusQueueStruct *ArgusAupQueue = NULL;
struct RaAupStruct *ArgusAupStruct = NULL;

int RaupParseResourceFile(struct ArgusParserStruct *, char *);
int RaProcessAddressGroup (struct ArgusParserStruct *, struct ArgusLabelerStruct *, unsigned int *, int, int, int);
struct RaAupGroupStruct *RaParseGroupEntry (struct ArgusParserStruct *, char *);

struct RaAupPolicyStruct *RaParsePolicyRule(struct ArgusParserStruct *, struct RaAupStruct *, struct RaAupPolicyStruct *);
struct RaAupServiceStruct *RaParseServiceEntry(char *);
struct RaAupPolicySetStruct *ArgusNewPolicySet(void);

extern int RaDaysInAMonth[12];

struct RaAupPolicySetStruct *
ArgusNewPolicySet(void)
{
   struct RaAupPolicySetStruct *retn;

   if ((retn = (struct RaAupPolicySetStruct *) ArgusCalloc(1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewPolicySet(%s) ArgusCalloc error %s\n", optarg, strerror(errno));

   if ((retn->ruleSet = ArgusNewList()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewPolicySet() ArgusNewList error %s\n", strerror(errno));

   if ((retn->policies = ArgusNewList()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewPolicySet() ArgusNewList error %s\n", strerror(errno));

   return (retn);
}

struct RaAupRuleSetStruct *
ArgusNewRuleSet(struct RaAupServiceStruct *service)
{
   struct RaAupRuleSetStruct *retn;

   if ((retn = (struct RaAupRuleSetStruct *) ArgusCalloc(1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewRuleSet(%s) ArgusCalloc error %s\n", optarg, strerror(errno));

   if ((retn->policies = ArgusNewList()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewPolicySet() ArgusNewList error %s\n", strerror(errno));

   retn->service = service;
   retn->name = strdup(service->name);
   return (retn);
}


//
// Policy Rule syntax is
//   Examples
//      Policy name:localdns  service:dns clients:LocalDnsClientsGroup servers:LocalDnsServerGroup effect:Permit
//      Policy name:remotedns service:dns clients:LocalDnsServerGroup servers:RemoteDnsServerGroup effect:Permit
//      Policy name:localntp  service:ntp clients:local:any servers:10.2.34.2,10.2.243.18 effect:Permit
//      Policy name:remotentp service:ntp clients:10.2.34.2,10.2.243.18 servers:remote:any effect:Permit
//

struct RaAupPolicyStruct *
RaParsePolicyRule(struct ArgusParserStruct *parser, struct RaAupStruct *aup, struct RaAupPolicyStruct *pol)
{
   struct RaAupPolicySetStruct *policySet = aup->ArgusPolicySet;
   struct RaAupRuleSetStruct *ruleSet;
   struct RaAupPolicyStruct *retn = pol;
   char *sptr, *cptr, *dptr, *tptr = NULL;
   char *rule = pol->rule;

   struct snamemem *sp;
   struct gnamemem *gp;

   if ((rule != NULL) && (strlen(rule) > 0)) {
      if ((sptr = strstr(rule, "name:")) != NULL) {
         sptr += strlen("name:");
         while(isspace(*sptr)) sptr++;
         if ((tptr = strchr(sptr, ' ')) != NULL)
            *tptr = '\0';

         if (strlen(sptr))
            retn->name = strdup(sptr);

         if (tptr != NULL)
            *tptr++ = ' ';
      }

      if ((sptr = strstr(rule, "service:")) != NULL) {
         sptr += strlen("service:");
         while(isspace(*sptr)) sptr++;
         if ((tptr = strchr(sptr, ' ')) != NULL)
            *tptr = '\0';

         if ((sp = check_service(aup->servicetable, (const u_char *)sptr)) != NULL) {
            retn->service = sp->service;
         }

         if (tptr != NULL)
            *tptr++ = ' ';
      }

      if ((cptr = strstr(rule, "clients:")) != NULL) {
         cptr += strlen("clients:");
         while(isspace(*cptr)) cptr++;
         if ((tptr = strchr(cptr, ' ')) != NULL)
            *tptr = '\0';

         if ((gp = check_group(aup->grouptable, (const u_char *)cptr)) != NULL) {
            retn->clients = gp->group;
         } else {
            retn->clients = RaParseGroupEntry(parser, cptr);
         }
         if (tptr != NULL)
            *tptr++ = ' ';
      }

      if (tptr == NULL) tptr = rule;
      if ((dptr = strstr(rule, "servers:")) != NULL) {
         dptr += strlen("servers:");
         while(isspace(*dptr)) dptr++;
         if ((tptr = strchr(dptr, ' ')) != NULL)
            *tptr++ = '\0';

         if ((gp = check_group(aup->grouptable, (const u_char *)dptr)) != NULL) {
            retn->servers = gp->group;
         } else {
            retn->servers = RaParseGroupEntry(parser, dptr);
         }
         if (tptr != NULL)
            *tptr++ = ' ';
      }

      if ((sptr = strstr(rule, "effect:")) != NULL) {
         sptr += strlen("effect:");
         while(isspace(*sptr)) sptr++;
         if ((tptr = strchr(sptr, ' ')) != NULL)
            *tptr = '\0';

         if (strlen(sptr)) {
            if ((retn->effect = (struct RaAupEffectStruct *) ArgusCalloc(1, sizeof(*retn->effect))) == NULL)
               ArgusLog (LOG_ERR, "RaupParseServiceEntry(%s) ArgusCalloc error %s\n", optarg, strerror(errno));
            retn->effect->effectString = strdup(sptr);
         }

         if (tptr != NULL)
            *tptr++ = ' ';
      }

      if ((ruleSet = RaFindRuleSet(policySet, retn->service)) == NULL) {
         if ((ruleSet = ArgusNewRuleSet(retn->service)) == NULL) 
            ArgusLog (LOG_ERR, "RaParsePolicyRule() ArgusNewRuleSet error %s\n", strerror(errno));

         ruleSet->status |= RAUP_POLICY_DIRTY;
         ArgusPushBackList((struct ArgusListStruct *)policySet->ruleSet, (struct ArgusListRecord *) ruleSet, ARGUS_LOCK);
      }

      ArgusPushBackList(ruleSet->policies, (struct ArgusListRecord *) retn, ARGUS_LOCK);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaParsePolicyRule(%p, %p, %s): returning %p\n", parser, policySet, rule, retn);
#endif

   return (retn);
}


struct RaAupRuleSetStruct *
RaFindRuleSet (struct RaAupPolicySetStruct *policySet, struct RaAupServiceStruct *service)
{
   struct RaAupRuleSetStruct *retn = NULL;
   
   if (policySet && (policySet->ruleSet != NULL)) {
      struct ArgusListStruct *ruleSet = policySet->ruleSet;
      struct ArgusListObjectStruct *lobj = NULL;
      struct RaAupRuleSetStruct *rule = NULL;
      int i, count = ArgusGetListCount(ruleSet);

      if ((lobj = ruleSet->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((rule = (struct RaAupRuleSetStruct *) lobj) != NULL) {
               if (rule->service == service) {
                  retn = rule;
                  break;
               }
               lobj = lobj->nxt;
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaFindRuleSet(%p, %p): returning %p\n", policySet, service, retn);
#endif
   return (retn);
}

//
// Service Entry syntax is
//   Service name and an argus filter list (see ra.1 for specification)
//   which should represent a port based service filter appropriate
//   for ra.1.
//
//   Examples
//      RAUP_SERVICE="dns:'port (53 or 5353)'"
//      RAUP_SERVICE="ntp:'udp and dst port 123'"
//      RAUP_SERVICE="http:'tcp and dst port (80 or 8080 or 8088)'"
//      RAUP_SERVICE="imaps:'tcp and dst port 993'"
//

struct RaAupServiceStruct *
RaParseServiceEntry(char *optarg)
{
   struct RaAupServiceStruct *retn = NULL;

   if (optarg != NULL) {
      char *srv, *rule, *tptr, *qptr;

      if ((retn = (struct RaAupServiceStruct *) ArgusCalloc(1, sizeof(*retn))) == NULL)
         ArgusLog (LOG_ERR, "RaupParseServiceEntry(%s) ArgusCalloc error %s\n", optarg, strerror(errno));

      if ((qptr = strdup(ArgusTrimString(optarg))) != NULL) {
         srv = qptr;
         if (*srv == '\"') {
            srv++;
            if ((tptr = strchr(srv, '"')) != NULL)
               *tptr++ = '\0';
            else
               ArgusLog (LOG_ERR, "%s(%s) string unterminated\n", __func__, optarg);
         }
         if ((rule = strchr(srv, ':')) != NULL) {
            *rule++ = '\0';
            retn->name = strdup(srv);
            retn->rule = strdup(rule);
            if (ArgusFilterCompile (&retn->filter, rule, ArgusParser->Oflag) < 0)
               ArgusLog (LOG_ERR, "RaParseServiceEntry(%s): ArgusFilterCompile returned error", optarg);
         }

         free(qptr);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaParseServiceEntry(%s): returning %p\n", optarg, retn);
#endif

   return (retn);
}

//
//  struct RaAupGroupStruct *RaParseGroupEntry(char *optarg)
//     Syntax for group definition is:
//        RAUP_GROUP="LocalDnsClientsGroup = local:any"
//        RAUP_GROUP="RemoteDnsServerGroup = remote:10.5.10.0/24,10.8.11.0/24"
//        RAUP_GROUP="LocalDnsServerGroup  = local:10.2.10.2,10.2.11.2"
//
//

struct RaAupGroupStruct *
RaParseGroupEntry (struct ArgusParserStruct *parser, char *optarg)
{
   struct RaAupGroupStruct *retn = NULL;

   if (optarg != NULL) {
      char *sptr = NULL, *qptr = NULL, *cptr = NULL;
      char *lptr = NULL, *aptr = NULL, *tptr;
      struct ArgusCIDRAddr *cidr;

      if ((retn = (struct RaAupGroupStruct *) ArgusCalloc(1, sizeof(*retn))) == NULL)
         ArgusLog (LOG_ERR, "RaupParseGroupEntry(%s) ArgusCalloc error %s\n", optarg, strerror(errno));

      if ((retn->labeler = ArgusNewLabeler(parser, 0L)) == NULL)
         ArgusLog (LOG_ERR, "RaParseGroupEntry: ArgusNewLabeler error");

      if ((retn->labeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
         ArgusLog (LOG_ERR, "RaParseGroupEntry: ArgusCalloc error %s\n", strerror(errno));

      sptr = strdup(optarg);
      qptr = sptr;

      if (*qptr == '\"') {
         qptr++;
         if ((tptr = strchr(qptr, '"')) != NULL)
            *tptr++ = '\0';
         else
            ArgusLog (LOG_ERR, "%s(%s) string unterminated\n", __func__, optarg);
      }

      if (qptr != NULL) {
         if ((cptr = strchr(qptr, '=')) != NULL) {
            *cptr++ = '\0';
            retn->name = strdup(ArgusTrimString(qptr));
         } else {
            cptr = qptr;
         }

         cptr = ArgusTrimString(cptr);

         if ((lptr = strstr(cptr, "local:")) != NULL) {
            retn->locality = strdup("local");
            cptr += strlen("local:");
         } else
            if ((lptr = strstr(cptr, "remote:")) != NULL) {
               retn->locality = strdup("remote");
               cptr += strlen("remote:");
         }

         while ((aptr = strsep(&cptr, ",")) != NULL) {
               struct RaAddressStruct *saddr = NULL;

               if (strcmp(aptr, "any")) {
                  if ((tptr = strchr(aptr, '-')) != NULL) {
                     *tptr = '\0';
                     if (((cidr = RaParseCIDRAddr (parser, (tptr + 1))) != NULL) &&
                         ((cidr = RaParseCIDRAddr (parser, aptr)) != NULL)) {
                        *tptr = '-';
                        if ((saddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*saddr))) != NULL) {
                           bcopy ((char *)cidr, (char *)&saddr->addr, sizeof (*cidr));
                           saddr->str = strdup(aptr);

                           if (retn->queue == NULL)
                              if ((retn->queue = (struct ArgusQueueStruct *) ArgusNewQueue()) == NULL)
                                 ArgusLog (LOG_ERR, "RaupParseGroupEntry(%s) ArgusNewQueue error %s\n", optarg, strerror(errno));

                           ArgusAddToQueue(retn->queue, &saddr->qhdr, ARGUS_LOCK);
                           RaInsertLocalityTree (parser, retn->labeler, aptr);

                        } else
                           ArgusLog (LOG_ERR, "RaupParseGroupEntry(%s) parse error, no address found\n", optarg);
                     } else
                        ArgusLog (LOG_ERR, "RaupParseGroupEntry(%s) parse error, not valid range\n", optarg);


                  } else {
                     if ((cidr = RaParseCIDRAddr (parser, aptr)) != NULL) {
                        if ((saddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*saddr))) != NULL) {
                           bcopy ((char *)cidr, (char *)&saddr->addr, sizeof (*cidr));
                           saddr->str = strdup(aptr);

                           if (retn->queue == NULL)
                              if ((retn->queue = (struct ArgusQueueStruct *) ArgusNewQueue()) == NULL)
                                 ArgusLog (LOG_ERR, "RaupParseGroupEntry(%s) ArgusNewQueue error %s\n", optarg, strerror(errno));

                           ArgusAddToQueue(retn->queue, &saddr->qhdr, ARGUS_LOCK);
                           RaInsertLocalityTree (parser, retn->labeler, aptr);
                        }
                     } else
                        ArgusLog (LOG_ERR, "RaupParseGroupEntry(%s) parse error, no address found\n", optarg);
                  }
               }
#ifdef ARGUSDEBUG
               ArgusDebug (3, "RaParseGroupEntry(): processing group:%s locality:%s addr:%s\n", retn->name, retn->locality, aptr);
#endif
         }
         free(sptr);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaParseGroupEntry(%s): returning %p\n", optarg, retn);
#endif

   return (retn);
}

int
RaupParseResourceFile(struct ArgusParserStruct *parser, char *file)
{
   struct ArgusQueueStruct *ArgusConfigFiles = NULL;
   struct ArgusFileInput *ifile;
   char strbuf[MAXSTRLEN], *str = strbuf, *optarg = NULL, *tptr;
   int retn = 1, i, len, found = 0, lines = 0;
   unsigned int state = 0;
   FILE *fd;

   if ((ArgusAupQueue = ArgusNewQueue()) == NULL)
      ArgusLog (LOG_ERR, "RaupParseResourceFile() ArgusNewQueue error %s\n", strerror(errno));

   if ((ArgusConfigFiles = ArgusNewQueue()) == NULL)
      ArgusLog (LOG_ERR, "RaupParseResourceFile() ArgusNewQueue error %s\n", strerror(errno));


   RaProcessRecursiveConfigs (ArgusConfigFiles, file);
   
   while ((ifile = (struct ArgusFileInput *) ArgusPopQueue(ArgusConfigFiles, ARGUS_LOCK)) != NULL) {

      if ((ArgusAupStruct = (struct RaAupStruct *) ArgusCalloc(1, sizeof(*ArgusAupStruct))) == NULL)
            ArgusLog (LOG_ERR, "RaupParseResourceFile() ArgusCalloc error %s\n", strerror(errno));

      if ((fd = fopen (ifile->filename, "r")) != NULL) {
         retn = 0;
         while ((fgets(str, MAXSTRLEN, fd)) != NULL)  {
            lines++;
            while (*str && isspace((int)*str))
                str++;

            if (*str && (*str != '#') && (*str != '\n') && (*str != '!')) {
               int unterm = 0;
               found = 0;

               if (state & RAUP_PARSING_MULTILINE) {
                  if (state & (0x1 << RAUP_POLICYSET)) {
                     char *ptr;
                     if ((ptr = strstr(str, "Policy ")) != NULL) {
                        struct RaAupPolicyStruct *pol = NULL;

                        ptr += strlen("Policy ");

                        if ((pol = (struct RaAupPolicyStruct *) ArgusCalloc(1, sizeof(*pol))) == NULL)
                           ArgusLog (LOG_ERR, "RaupParseServiceEntry(%s) ArgusCalloc error %s\n", optarg, strerror(errno));

                        pol->rule = strdup(ptr);
                        ArgusPushBackList(ArgusAupStruct->ArgusPolicySet->policies, (struct ArgusListRecord *)pol, ARGUS_LOCK);
                     }
                     if (strchr(str, '\"')) {
                        state &= ~RAUP_PARSING_MULTILINE;
                     }
                  }
                  found++;

               } else
               for (i = 0; i < RAUP_RCITEMS; i++) {
                  len = strlen(RaupResourceFileStr[i]);
                  if (!(strncmp (str, RaupResourceFileStr[i], len))) {
                     optarg = &str[len];

                     if (optarg[strlen(optarg) - 1] == '\n')
                        optarg[strlen(optarg) - 1] = '\0';

                     if (*optarg == '"') {
                        optarg++;
                        if ((tptr = strchr(optarg, '"')) != NULL)
                           *tptr++ = '\0';
                        else
                           unterm++;
                     }

                     if (unterm == 0 && *optarg == '\0')
                        optarg = NULL;

                     if (optarg) {
                        switch (i) {
                           case RAUP_POLICYUUID: {
                              if (uuid_parse(optarg, ArgusAupStruct->uuid) < 0) {
                                 ArgusLog (LOG_ERR, "RaupParseResourceFile: uuid format error %s", optarg);
                              }
#ifdef ARGUSDEBUG
                              ArgusDebug (3, "RaupParseResourceFile(%s): Policy uuid %s\n", ifile->filename, optarg);
#endif
                              break;
                           }
                           case RAUP_POLICYNAME: {
                              ArgusAupStruct->name = strdup(optarg);
#ifdef ARGUSDEBUG
                              ArgusDebug (3, "RaupParseResourceFile(%s): Policy Name %s\n", ifile->filename, optarg);
#endif
                              break;
                           }
                           case RAUP_POLICYVERSION: {
                              ArgusAupStruct->version = atoi(optarg);
#ifdef ARGUSDEBUG
                              ArgusDebug (3, "RaupParseResourceFile(%s): Policy Version %s\n", ifile->filename, optarg);
#endif
                              break;
                           }
                           case RAUP_POLICYSTATUS: {
                              if (strcasecmp(optarg, "inactive") == 0)
                                 ArgusAupStruct->status = 0;
                              if (strcasecmp(optarg, "active") == 0)
                                 ArgusAupStruct->status = 1;
#ifdef ARGUSDEBUG
                              ArgusDebug (3, "RaupParseResourceFile(%s): Policy Status %s\n", ifile->filename, optarg);
#endif
                              break;
                           }
                           case RAUP_POLICYSETSTRATEGY: {
                              if (!(strncmp(optarg, "Restrictive", strlen("Restrictive"))))
                                 ArgusAupStruct->status |= RAUP_RESTRICTIVE_POLICY;
#ifdef ARGUSDEBUG
                              ArgusDebug (3, "RaupParseResourceFile(%s): Policy Strategy %s\n", ifile->filename, optarg);
#endif
                              break;
                           }

                           case RAUP_SERVICE: {
                              struct RaAupServiceStruct *srv = RaParseServiceEntry(optarg);
                              if (srv != NULL) {
                                 struct snamemem *sp;

                                 if ((sp = lookup_service(ArgusAupStruct->servicetable, (u_char *)srv->name)) != NULL) {
                                    if (sp->service != NULL) {
                                    } else {
                                       sp->service = srv;
                                    }
                                 }
                              }
                              break;
                           }

                           case RAUP_VERIFICATION: {
                              if (!(strncasecmp(optarg, "yes", 3)))
                                 ArgusAupStruct->status |= RAUP_SERVICE_VERIFICATION;
                              else
                                 ArgusAupStruct->status &= ~RAUP_SERVICE_VERIFICATION;
#ifdef ARGUSDEBUG
                              ArgusDebug (3, "RaupParseResourceFile(%s): Service verification %s\n", ifile->filename, optarg);
#endif
                              break;
                           }

                           case RA_SERVICES_SIGNATURES: {
                              if (ArgusAupStruct->ArgusServicesLabeler == NULL)
                                 if ((ArgusAupStruct->ArgusServicesLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
                                    ArgusLog (LOG_ERR, "RaupParseResourceFile: ArgusNewLabeler error");

                              RaReadSrvSignature (parser, ArgusAupStruct->ArgusServicesLabeler, optarg);
                              break;
                           }

                           case RA_GROUP: {
                              if (ArgusAupStruct->ArgusLocalLabeler == NULL)
                                 if ((ArgusAupStruct->ArgusLocalLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
                                    ArgusLog (LOG_ERR, "RaupParseResourceFile: ArgusNewLabeler error");

                              RaReadLocalityConfig (parser, ArgusAupStruct->ArgusLocalLabeler, optarg);
#ifdef ARGUSDEBUG
                              ArgusDebug (3, "RaupParseResourceFile(%s): Group Definition file: %s\n", ifile->filename, optarg);
#endif
                              break;
                           }

                           case RAUP_GROUP: {
                              struct RaAupGroupStruct *grp = RaParseGroupEntry(parser, optarg);
                              struct gnamemem *gp;

                              if ((gp = lookup_group(ArgusAupStruct->grouptable, (u_char *)grp->name)) != NULL) {
                                 if (gp->group != NULL) {
                                 } else {
                                    gp->group = grp;
                                 }
                              }

                              break;
                           }

                           case RAUP_POLICYSET: {
                              if ((ArgusAupStruct->ArgusPolicySet = ArgusNewPolicySet()) == NULL)
                                 ArgusLog (LOG_ERR, "RaupParseResourceFile() ArgusNewPolicySet error %s\n", strerror(errno));

                              if (unterm) {
                                 state = RAUP_PARSING_MULTILINE;
                              }
                              break;
                           }
                        }
                     }
                     state |= 0x01 << i;
                     found++;
                     break;
                  }
               }

               if (!found) {
                  ArgusLog (LOG_ERR, "%s: syntax error line %d\n", ifile->filename, lines);
               }
            }
         }
         fclose(fd);

         {
            struct ArgusListStruct *policies = ArgusAupStruct->ArgusPolicySet->policies;
            if (policies != NULL) {
               struct RaAupPolicyStruct *policy;
               struct ArgusListObjectStruct *lobj = NULL;

               while ((lobj = (struct ArgusListObjectStruct *)ArgusPopFrontList(policies, ARGUS_LOCK)) != NULL) {
                  if ((policy = (struct RaAupPolicyStruct *) lobj) != NULL) {
                     if (policy->rule) 
                        RaParsePolicyRule(parser, ArgusAupStruct, policy);
                  }
               }
            }
         }

         ArgusAddToQueue(ArgusAupQueue, &ArgusAupStruct->qhdr, ARGUS_LOCK);

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaupParseResourceFile: %s: %s\n", ifile->filename, strerror(errno));
#endif
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaupParseResourceFile (%s) returning %d\n", file, retn);
#endif

   return (retn);
}

extern char *chroot_dir;
extern uid_t new_uid;
extern gid_t new_gid;

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct timeval now;
   struct ArgusAdjustStruct *nadp;
   struct ArgusModeStruct *mode = NULL;
   struct ArgusLabelerStruct *labeler = NULL;
   int ArgusLabelerStatus = ARGUS_LABELER_ADDRESS;
   int i = 0, ind = 0;
   time_t tsec;

   gettimeofday (&now, 0L);
   tsec = now.tv_sec;
   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      if ((RaBinProcess = (struct RaBinProcessStruct *)ArgusCalloc(1, sizeof(*RaBinProcess))) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusCalloc error %s", strerror(errno));

#if defined(ARGUS_THREADS)
      pthread_mutex_init(&RaBinProcess->lock, NULL);
#endif

      RaBinProcess->scalesecs = 0;

      nadp = &RaBinProcess->nadp;
      bzero((char *)nadp, sizeof(*nadp));

      nadp->mode      = -1;
      nadp->modify    =  1;
      nadp->slen      =  2;

      if (parser->aflag)
         nadp->slen = parser->aflag;

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (isdigit((int) *mode->mode)) {
               ind = 0;
            } else {
               int done = 0;
               for (i = 0, ind = -1; !(done) && (i < ARGUSSPLITMODENUM); i++) {
                  if (!(strncasecmp (mode->mode, RaSplitModes[i], 3))) {
                     ind = i;
                     switch (ind) {
                        case ARGUSSPLITTIME:
                        case ARGUSSPLITSIZE:
                        case ARGUSSPLITCOUNT: {
                           if ((mode = mode->nxt) == NULL)
                              usage();
                           done++;
                        }
                     }
                  }
               }
            }

            if (ind < 0)
               usage();

            switch (ind) {
               case ARGUSSPLITTIME:
                  if (ArgusParser->tflag)
                     tsec = ArgusParser->startime_t.tv_sec;

                  nadp->mode = ind;
                  if (isdigit((int)*mode->mode)) {
                     char *ptr = NULL;
                     nadp->value = strtod(mode->mode, (char **)&ptr);
                     if (ptr == mode->mode)
                        usage();
                     else {

                        switch (*ptr) {
                           case 'y':
                              nadp->qual = ARGUSSPLITYEAR;  
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->RaStartTmStruct.tm_min = 0;
                              nadp->RaStartTmStruct.tm_hour = 0;
                              nadp->RaStartTmStruct.tm_mday = 1;
                              nadp->RaStartTmStruct.tm_mon = 0;
                              tsec= mktime(&nadp->RaStartTmStruct);
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
                              tsec = mktime(&nadp->RaStartTmStruct);
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
                              tsec = mktime(&nadp->RaStartTmStruct);
                              nadp->size = nadp->value*3600.0*24.0*7.0*1000000LL;
                              break;

                           case 'd':
                              nadp->qual = ARGUSSPLITDAY;   
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->RaStartTmStruct.tm_min = 0;
                              nadp->RaStartTmStruct.tm_hour = 0;
                              tsec = mktime(&nadp->RaStartTmStruct);
                              nadp->size = nadp->value*3600.0*24.0*1000000LL;
                              break;

                           case 'h':
                              nadp->qual = ARGUSSPLITHOUR;  
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              nadp->RaStartTmStruct.tm_min = 0;
                              tsec = mktime(&nadp->RaStartTmStruct);
                              nadp->size = nadp->value*3600.0*1000000LL;
                              break;

                           case 'm': {
                              nadp->qual = ARGUSSPLITMINUTE;
                              localtime_r(&tsec, &nadp->RaStartTmStruct);
                              nadp->RaStartTmStruct.tm_sec = 0;
                              tsec = mktime(&nadp->RaStartTmStruct);
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

                  RaBinProcess->rtime.tv_sec = tsec;

                  if (RaRealTime) 
                     nadp->start.tv_sec = 0;

                  break;

               case ARGUSSPLITSIZE:
               case ARGUSSPLITCOUNT:
               case ARGUSSPLITNOMODIFY:
               case ARGUSSPLITSOFT:
               case ARGUSSPLITZERO:
                  break;

               case ARGUSSPLITHARD:
                  nadp->hard++;
                  break;
            }

            mode = mode->nxt;
         }
      }

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "debug", 5))) {
               if (!(strncasecmp (mode->mode, "debug.local", 11)))
                  ArgusLabelerStatus |= ARGUS_TREE_DEBUG_LOCAL;

               if (!(strncasecmp (mode->mode, "debug.node", 10)))
                  ArgusLabelerStatus |= ARGUS_TREE_DEBUG_NODE;

               if (!(strncasecmp (mode->mode, "debug.group", 11)))
                  ArgusLabelerStatus |= ARGUS_TREE_DEBUG_GROUP;

               if (!(strncasecmp (mode->mode, "debug.tree", 10)))
                  ArgusLabelerStatus |= ARGUS_TREE_DEBUG;
            }
            if (!(strncasecmp (mode->mode, "level=", 6))) {
               extern int RaPrintLabelTreeLevel;
               int value = 0;
               char *endptr = NULL;
               value = strtod(&mode->mode[6], &endptr);
               if (&mode->mode[6] != endptr) {
                  RaPrintLabelTreeLevel = value;
               }
            }

            mode = mode->nxt;
         }
      }

      if (parser->ArgusFlowModelFile != NULL) {
         if (RaupParseResourceFile(parser, parser->ArgusFlowModelFile))
            ArgusLog (LOG_ERR, "ArgusClientInit: RaupParseResourceFile() error");

      } else
         ArgusLog (LOG_ERR, "ArgusClientInit: no address list, use -f");

      if ((parser->ArgusLabeler = ArgusNewLabeler(parser, ArgusLabelerStatus)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      if (ArgusLabelerStatus & ARGUS_TREE_DEBUG) {
         if ((labeler = parser->ArgusLabeler) != NULL) {
            RaPrintLabelTree (labeler, labeler->ArgusAddrTree[AF_INET], 0, 0);
            exit(0);
         }
      }

      if (ArgusLabelerStatus & ARGUS_TREE_DEBUG_LOCAL) {
         if ((labeler = parser->ArgusLocalLabeler) != NULL) {
            RaPrintLabelTree (labeler, labeler->ArgusAddrTree[AF_INET], 0, 0);
            exit(0);
         }
      }

      if (ArgusLabelerStatus & ARGUS_TREE_DEBUG_GROUP) {
         extern struct gnamemem grouptable[];
         struct RaAupGroupStruct *grp;
         struct gnamemem *gp;
         int i;

         for (i = 0; i < HASHNAMESIZE; i++) {
            if ((gp = &grouptable[i]) != NULL) {
               do {
                  if ((grp = gp->group) != NULL) {
                     printf ("Group: %s\n", grp->name);
                     if ((labeler = grp->labeler) != NULL) {
                        RaPrintLabelTree (labeler, labeler->ArgusAddrTree[AF_INET], 0, 0);
                        printf ("\n");
                     }
                  }
               } while ((gp = gp->g_nxt) != NULL);
            }
         }
         exit(0);
      }


      ArgusAlignTime(parser, &RaBinProcess->nadp, &tsec);

      if (RaLastDatabaseTimeStamp == 0)
         RaLastDatabaseTimeStamp = tsec;

      if (RaLastDatabaseTimeInterval == 0)
         RaLastDatabaseTimeInterval = RaBinProcess->nadp.start.tv_sec;
#ifdef ARGUS_MYSQL
      if (ArgusParser->writeDbstr != NULL)
         RaMySQLInit(1);
#endif /* ARGUS_MYSQL */

      parser->RaInitialized++;

      if (parser->dflag) {
         pid_t parent = getppid();
         FILE *tmpfile = NULL;
         int pid;

         if (parent != 1) {
            if ((pid = fork ()) < 0) {
               ArgusLog (LOG_ERR, "Can't fork daemon %s", strerror(errno));
            } else {
               if (pid) {
                  struct timespec ts = {0, 500000000};
                  int status;

                  nanosleep(&ts, NULL);
                  waitpid(pid, &status, WNOHANG);
                  if (kill(pid, 0) < 0) {
                     exit (1);
                  } else
                     exit (0);

               } else {
                  if (chdir ("/") < 0)
                     ArgusLog (LOG_ERR, "Can't chdir to / %s", strerror(errno));

                  if ((parser->ArgusSessionId = setsid()) < 0)
                     ArgusLog (LOG_ERR, "setsid error %s", strerror(errno));

                  umask(0);
    
                  ArgusLog(LOG_INFO, "started");

                  if ((tmpfile = freopen ("/dev/null", "r", stdin)) == NULL)
                     ArgusLog (LOG_ERR, "Cannot map stdout to /dev/null");

                  if ((tmpfile = freopen ("/dev/null", "a+", stdout)) == NULL)
                     ArgusLog (LOG_ERR, "Cannot map stdout to /dev/null");
    
                  if ((tmpfile = freopen ("/dev/null", "a+", stderr)) == NULL)
                     ArgusLog (LOG_ERR, "Cannot map stderr to /dev/null");
               }
            }
         }
      }

      if (chroot_dir != NULL)
         ArgusSetChroot(chroot_dir);
 
      if (new_gid > 0) {
         if (setgid(new_gid) < 0)
            ArgusLog (LOG_ERR, "ArgusInitOutput: setgid error %s", strerror(errno));
      }

      if (new_uid > 0) {
         if (setuid(new_uid) < 0)
            ArgusLog (LOG_ERR, "ArgusInitOutput: setuid error %s", strerror(errno));
      }
   }
}


void RaArgusInputComplete (struct ArgusInput *input) { return; }


int RaParseCompleting = 0;

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
         if (ArgusParser->ArgusPrintJson)
            fprintf (stdout, "\n");

         if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
            struct ArgusWfileStruct *wfile = NULL, *start = NULL;

            if ((wfile = (struct ArgusWfileStruct *) ArgusFrontList(ArgusParser->ArgusWfileList)) != NULL) {
               start = wfile;
               fflush(wfile->fd);
               ArgusPopFrontList(ArgusParser->ArgusWfileList, ARGUS_NOLOCK);
               ArgusPushBackList(ArgusParser->ArgusWfileList, (struct ArgusListRecord *) wfile, ARGUS_NOLOCK);
               wfile = (struct ArgusWfileStruct *) ArgusFrontList(ArgusParser->ArgusWfileList);
            } while (wfile != start);
         }

         while ((ArgusAupStruct = (struct RaAupStruct *) ArgusPopQueue(ArgusAupQueue, ARGUS_LOCK)) != NULL)
            RaPrintAup (ArgusParser, ArgusAupStruct);

         fflush(stdout);
         ArgusShutDown(sig);
         exit(0);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaParseComplete (%d) returning\n", sig);
#endif
}

void
ArgusClientTimeout ()
{
   if (MUTEX_LOCK(&ArgusAupQueue->lock) == 0) {
      int i, cnt = ArgusAupQueue->count;
      for (i = 0 ; i < cnt; i++) {
         ArgusAupStruct = (struct RaAupStruct *) ArgusPopQueue(ArgusAupQueue, ARGUS_NOLOCK);
         if (ArgusAupStruct != NULL)
            RaPrintAup (ArgusParser, ArgusAupStruct);
         ArgusAddToQueue(ArgusAupQueue, &ArgusAupStruct->qhdr, ARGUS_NOLOCK);
      }
      MUTEX_UNLOCK(&ArgusAupQueue->lock);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusClientTimeout: returning\n");
#endif
}

void
parse_arg (int argc, char**argv)
{

#ifdef ARGUSDEBUG
   ArgusDebug (6, "parse_arg (%d, 0x%x) returning\n", argc, argv);
#endif
}


void
usage ()
{
   extern char version[];
   fprintf (stdout, "rafilteraddr Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [-v] -f address.file [raoptions] \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "options: -f          specify file containing address(es).\n");
   fprintf (stdout, "         -v          invert the logic and print flows that don't match.\n");
   fprintf (stdout, "         -M level=x  set the level when printing out the address tree.\n");
   fflush (stdout);
   exit(1);
}

char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];

//
// RaProcessAup - given a RaAupStruct and an argus record, return an aup score.
//                Positive values are conformant, negative non-conformant.


int
RaProcessAup (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, struct RaAupStruct *aup)
{
   int retn = 0;
   struct ArgusMetricStruct *metric =  (void *)argus->dsrs[ARGUS_METRIC_INDEX];

   if (aup != NULL) {
      struct RaAupPolicySetStruct *policySet = aup->ArgusPolicySet;
      struct RaAupRuleSetStruct *ruleSet;
      struct RaAupPolicyStruct *policy;

      if (policySet != NULL) {
         struct ArgusListStruct *ruleList = policySet->ruleSet;
         if (ruleList != NULL) {
            struct ArgusListObjectStruct *robj = NULL, *lobj = NULL;
            int i, count = ruleList->count;

            if ((robj = ruleList->start) != NULL) {
               for (i = 0; i < count; i++) {
                  if ((ruleSet = (struct RaAupRuleSetStruct *) robj) != NULL) {
                     struct RaAupServiceStruct *srv = ruleSet->service;
                     struct ArgusListStruct *policies = ruleSet->policies;

                     int x, cnt = policies->count;
                     ruleSet->value = 0;

                     if ((lobj = policies->start) != NULL) {
                        for (x = 0; x < cnt; x++) {
                           if ((policy = (struct RaAupPolicyStruct *) lobj) != NULL) {
                              struct RaAupGroupStruct *clnt  = policy->clients;
                              struct RaAupGroupStruct *srvs  = policy->servers;

                              policy->value = 0;

                              if (srv != NULL) {
                                 struct nff_insn *fcode = srv->filter.bf_insns;

                                 if (ArgusFilterRecord (fcode, argus) != 0) {
                                    struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];

                                    policy->status |= RAUP_POLICY_DIRTY;
                                    policy->value |= RAUP_SERVICE_MATCHED;

                                    switch (flow->hdr.subtype & 0x3F) {
                                       case ARGUS_FLOW_CLASSIC5TUPLE:
                                       case ARGUS_FLOW_LAYER_3_MATRIX: {
                                          switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                             case ARGUS_TYPE_IPV4: {
                                                if (clnt && (clnt->queue != NULL)) {
                                                   if (RaProcessAddressGroup (parser, clnt->labeler, &flow->ip_flow.ip_src, flow->ip_flow.smask, ARGUS_TYPE_IPV4, ARGUS_SUPER_MATCH)) {
                                                      policy->value |= RAUP_SRC_GROUP_VALIDATED;
                                                      policy->client++;
                                                   }
                                                } else {
                                                   policy->value |= RAUP_SRC_GROUP_VALIDATED;
                                                   policy->client++;
                                                }

                                                if (srvs && (srvs->queue != NULL)) {
                                                   if (RaProcessAddressGroup (parser, srvs->labeler, &flow->ip_flow.ip_dst, flow->ip_flow.dmask, ARGUS_TYPE_IPV4, ARGUS_SUPER_MATCH)) {
                                                      policy->value |= RAUP_DST_GROUP_VALIDATED;
                                                      policy->server++;
                                                   }
                                                } else {
                                                   policy->value |= RAUP_DST_GROUP_VALIDATED;
                                                   policy->server++;
                                                }
                                                break;
                                             }
                                          }
                                       }
                                    }

                                    if (policy->value != 0) {
                                       if (ArgusAupStruct->status & RAUP_SERVICE_VERIFICATION) {
                                          if (ArgusAupStruct->ArgusServicesLabeler != NULL) {
                                             struct RaSrvSignature *sig;

                                             if (!(sig = RaValidateService (parser, argus))) {
                                                struct ArgusMetricStruct *metric =  (void *)argus->dsrs[ARGUS_METRIC_INDEX];
                                                if ((metric != NULL) && (metric->dst.pkts)) {
                                                   ArgusReverseRecord(argus);
                                                   sig = RaValidateService (parser, argus);
                                                   ArgusReverseRecord(argus);
                                                }
                                             }
                                             if (sig != NULL) {
                                                if (!(strcmp(sig->name, srv->name)))
                                                   policy->value |= RAUP_SERVICE_VALIDATED;
                                                policy->verify++;
                                             }
                                          }
                                       } else {
                                       }
                                    }
                                 }
                              }

                              if (ruleSet->value < policy->value)
                                 ruleSet->value = policy->value;

                              lobj = lobj->nxt;
                           }
                        }
                     }
                     if (ruleSet->value > 0) {
                        ruleSet->status |= RAUP_POLICY_DIRTY;

                        if (ruleSet->stime.tv_sec == 0)
                           ruleSet->stime = ArgusParser->ArgusRealTime;

                        ruleSet->ltime = ArgusParser->ArgusRealTime;

                        ruleSet->match++;

                        if (ruleSet->value & RAUP_SRC_GROUP_VALIDATED)
                           ruleSet->client++;

                        if (ruleSet->value & RAUP_DST_GROUP_VALIDATED)
                           ruleSet->server++;

                        if (ruleSet->value & RAUP_SERVICE_VALIDATED)
                           ruleSet->verify++;

                        if ((ruleSet->value & RAUP_VERIFICATION_MASK) == RAUP_VERIFICATION_MASK) {
                           ruleSet->conform++;
                        } else {
                           ruleSet->nonconform++;
                        }

                        if ((metric != NULL) && (metric->src.pkts && metric->dst.pkts))
                           ruleSet->replies++;

                        if (retn < ruleSet->value)
                           retn = ruleSet->value;
                     }
                     robj = robj->nxt;
                  }
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaProcessAup (%p, %p, %p) returning %d\n", parser, argus, aup, retn);
#endif
   return (retn);
}


int
RaFlushAup (struct ArgusParserStruct *parser, struct RaAupStruct *aup)
{
   int retn = 0;

   RaPrintAup (parser, aup);

   if (aup != NULL) {
      struct RaAupPolicySetStruct *policySet = aup->ArgusPolicySet;
      struct RaAupRuleSetStruct *ruleSet;

      if (policySet != NULL) {
         struct ArgusListStruct *ruleList = policySet->ruleSet;
         if (ruleList != NULL) {
            struct ArgusListObjectStruct *robj = NULL;
            int i, count = ruleList->count;

            if ((robj = ruleList->start) != NULL) {
               for (i = 0; i < count; i++) {
                  if ((ruleSet = (struct RaAupRuleSetStruct *) robj) != NULL) {
                     ruleSet->match       = 0;
                     ruleSet->conform     = 0;
                     ruleSet->nonconform  = 0;
                     ruleSet->client      = 0;
                     ruleSet->server      = 0;
                     ruleSet->verify      = 0;
                     ruleSet->replies     = 0;
                     robj = robj->nxt;
                  }
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaFlushAup (%p, %p) returning %d\n", parser, aup, retn);
#endif
   return (retn);
}


int
RaPrintAup (struct ArgusParserStruct *parser, struct RaAupStruct *aup)
{
   int retn = 0;

   if (aup != NULL) {
      struct RaAupPolicySetStruct *policySet = aup->ArgusPolicySet;
      struct RaAupRuleSetStruct *ruleSet;
      char sbuf[512];

      if (policySet != NULL) {
         struct ArgusListStruct *ruleList = policySet->ruleSet;
         if (ruleList != NULL) {
            struct ArgusListObjectStruct *robj = NULL;
            int i, count = ruleList->count;

            if ((robj = ruleList->start) != NULL) {
               for (i = 0; i < count; i++) {
                  if ((ruleSet = (struct RaAupRuleSetStruct *) robj) != NULL) {
                     if (ruleSet->status & RAUP_POLICY_DIRTY) {
                        if (ArgusParser->writeDbstr != NULL) {
#ifdef ARGUS_MYSQL
                           int slen = 0;

                           sprintf (sbuf, "INSERT INTO %s (`stime`,`ltime`,`status`, `policy`, `name`, `version`, `match`,`conform`,`nonconform`,`client`,`server`,`verify`,`replies`)", RaTable);
                           slen = strlen(sbuf);
                           sprintf (&sbuf[slen], " VALUES (%ld, %ld, %d, \"%s\", \"%s\", %d, %d, %d, %d, %d, %d, %d, %d) ", 
                                    RaLastDatabaseTimeStamp, ruleSet->ltime.tv_sec, aup->status & 0x0F, aup->name, ruleSet->name, aup->version, ruleSet->match,
                                    ruleSet->conform, ruleSet->nonconform, ruleSet->client, ruleSet->server, ruleSet->verify, ruleSet->replies);
                           slen = strlen(sbuf);
                           sprintf (&sbuf[slen], " ON DUPLICATE KEY UPDATE ");
                           slen = strlen(sbuf);
                           sprintf (&sbuf[slen], "`ltime`=%ld,`status`=%d, `match`=%d,`conform`=%d,`nonconform`=%d,`client`=%d,`server`=%d,`verify`=%d,`replies`=%d;\n", 
                                    ruleSet->ltime.tv_sec, aup->status & 0x0F, ruleSet->match, ruleSet->conform, ruleSet->nonconform, ruleSet->client, 
                                    ruleSet->server, ruleSet->verify, ruleSet->replies);

#ifdef ARGUSDEBUG
                           ArgusDebug (3, "RaPrintAup (%p, %p) sql: %s\n", parser, aup, sbuf);
#endif
                           if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
                              ArgusLog(LOG_ERR, "%s: %s, mysql_real_query error %s",
                                       __func__, sbuf, mysql_error(RaMySQL));
#endif /* ARGUS_MYSQL */
                        } else {
                           if (ArgusParser->ArgusPrintJson) {
                              sprintf (sbuf, "{\"policy\": \"%s_%s\", \"stime\" : %ld, \"ltime\" : %ld, \"match\" : %d, \"conform\" : %d, \"nonconform\" : %d, \"client\" : %d, \"server\" : %d, \"verify\" : %d, \"replies\" : %d}\n", 
                                    aup->name, ruleSet->service->name, RaLastDatabaseTimeStamp, ruleSet->ltime.tv_sec, ruleSet->match, ruleSet->conform, ruleSet->nonconform, ruleSet->client, 
                                    ruleSet->server, ruleSet->verify, ruleSet->replies);
                           } else {

                              sprintf (sbuf, "`policy`=\"%s_%s\",`stime`=%ld,`ltime`=%ld,`match`=%d,`conform`=%d,`nonconform`=%d,`client`=%d,`server`=%d,`verify`=%d,`replies`=%d;\n", 
                                    aup->name, ruleSet->service->name, RaLastDatabaseTimeStamp, ruleSet->ltime.tv_sec, ruleSet->match, ruleSet->conform, ruleSet->nonconform, ruleSet->client, 
                                    ruleSet->server, ruleSet->verify, ruleSet->replies);
                           }

                           fprintf(stdout, "%s\n", sbuf);
                        }
                        
                        ruleSet->status &= ~RAUP_POLICY_DIRTY;
                     }
                     robj = robj->nxt;
                  }
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaPrintAup (%p, %p) returning %d\n", parser, aup, retn);
#endif
   return (retn);
}

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   int i, cnt = ArgusAupQueue->count;
   int retn = 0;

   if (parser->ArgusTotalRecords == 1)
      ArgusAlignInit(parser, argus, &RaBinProcess->nadp);

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (flow) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        time_t tsec = (ArgusParser->ArgusRealTime.tv_sec * 1000000LL + ArgusParser->ArgusRealTime.tv_usec) / 1000000;

                        ArgusAlignTime(parser, &RaBinProcess->nadp, &tsec);

                        if (RaLastDatabaseTimeStamp == 0)
                           RaLastDatabaseTimeStamp = tsec;

                        if (RaLastDatabaseTimeInterval == 0)
                           RaLastDatabaseTimeInterval = RaBinProcess->nadp.start.tv_sec;

                        if (RaLastDatabaseTimeInterval != RaBinProcess->nadp.start.tv_sec) {
                           for (i = 0 ; i < cnt; i++) {
                              ArgusAupStruct = (struct RaAupStruct *) ArgusPopQueue(ArgusAupQueue, ARGUS_LOCK);
                              ArgusAupStruct->retn = RaFlushAup(parser, ArgusAupStruct);
                              ArgusAddToQueue(ArgusAupQueue, &ArgusAupStruct->qhdr, ARGUS_LOCK);
                           }
                           RaLastDatabaseTimeInterval = RaBinProcess->nadp.start.tv_sec;
                           RaLastDatabaseTimeStamp = tsec;
                        }
                        for (i = 0 ; i < cnt; i++) {
                           ArgusAupStruct = (struct RaAupStruct *) ArgusPopQueue(ArgusAupQueue, ARGUS_LOCK);
                           ArgusAupStruct->retn = RaProcessAup(parser, argus, ArgusAupStruct);
                           ArgusAddToQueue(ArgusAupQueue, &ArgusAupStruct->qhdr, ARGUS_LOCK);
                        }
                        break;
                     }
                     case ARGUS_TYPE_IPV6:
                        break;
                  }
                  break;
               }
            }
         }

         if (parser->ArgusWfileList != NULL) {
            struct ArgusWfileStruct *wfile = NULL;
            struct ArgusListObjectStruct *lobj = NULL;
            int i, count = parser->ArgusWfileList->count;

            if ((lobj = parser->ArgusWfileList->start) != NULL) {
               for (i = 0; i < count; i++) {
                  if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                     struct ArgusRecord *argusrec = NULL;
                     if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        if (parser->exceptfile != NULL) {
                           if (retn && strcmp(wfile->filename, parser->exceptfile))
                              ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                           else
                              if (!retn && !strcmp(wfile->filename, parser->exceptfile))
                                 ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);

                        } else {
                           if (retn)
                              ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                        }
                     }
                  }

                  lobj = lobj->nxt;
               }
            }

         } else {
            for (i = 0 ; i < cnt; i++) {
               ArgusAupStruct = (struct RaAupStruct *) ArgusPopQueue(ArgusAupQueue, ARGUS_LOCK);

               if (ArgusAupStruct->retn) {
                  struct ArgusMetricStruct *metric =  (void *)argus->dsrs[ARGUS_METRIC_INDEX];
                  char buf[MAXSTRLEN];

                  if (!parser->qflag) {
                     char policy[8];
                     int i;

                     if (parser->Lflag && !(ArgusParser->ArgusPrintJson)) {
                        if (parser->RaLabel == NULL)
                           parser->RaLabel = ArgusGenerateLabel(parser, argus);

                        if (!(parser->RaLabelCounter++ % parser->Lflag))
                           printf ("%s\n", parser->RaLabel);

                        if (parser->Lflag < 0)
                           parser->Lflag = 0;
                     }

                     buf[0] = 0;
                     ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);
                     if (fprintf (stdout, "%s", buf) < 0)
                        RaParseComplete(SIGQUIT);

                     sprintf(policy, "     ");

                        for (i = 0; i < RAUP_ITEMS; i++) {
                           if (ArgusAupStruct->retn & (0x01 << i)) {
                              switch (0x01 << i) {
                                 case RAUP_SERVICE_MATCHED: policy[i] = 'M'; break;
                                 case RAUP_SRC_GROUP_VALIDATED: policy[i] = 'S'; break;
                                 case RAUP_DST_GROUP_VALIDATED: policy[i] = 'D'; break;
                                 case RAUP_SERVICE_VALIDATED: policy[i] = 'V'; break;
                              }
                           }
                        }
                     if ((metric != NULL) && (metric->src.pkts && metric->dst.pkts)) {
                        policy[RAUP_ITEMS] = 'C';
                     }
                     if (fprintf (stdout, " %s", policy) < 0)
                        RaParseComplete(SIGQUIT);

                     if (parser->ArgusWfileList == NULL)
                        if (!(parser->ArgusPrintJson))
                           if (fprintf (stdout, "\n") < 0)
                              RaParseComplete(SIGQUIT);
                  }
               }
               ArgusAddToQueue(ArgusAupQueue, &ArgusAupStruct->qhdr, ARGUS_LOCK);
            }
         }
         break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessRecord (0x%x) returning\n", argus);
#endif
}


int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaSendArgusRecord (0x%x) returning\n", argus);
#endif
   return 1;
}

void ArgusWindowClose(void) { }


int
RaProcessAddressGroup (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, unsigned int *addr, int mask, int type, int mode)
{
   struct RaAddressStruct *raddr;
   int retn = 0;

   if ((labeler != NULL) && (labeler->ArgusAddrTree != NULL)) {
      switch (type) {
         case ARGUS_TYPE_IPV4: {
            struct RaAddressStruct node;
            bzero ((char *)&node, sizeof(node));

            node.addr.type = AF_INET;
            node.addr.len = 4;
            node.addr.addr[0] = *addr;
            node.addr.mask[0] = 0xFFFFFFFF << (32 - mask);
            node.addr.masklen = mask;

            /* always try exact match first? */
            if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_EXACT_MATCH)) != NULL)
               retn = 1;
            else if (mode != ARGUS_EXACT_MATCH)
                  if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, mode)) != NULL)
                     retn = 1;
            break;
         }

         case ARGUS_TYPE_IPV6:
            break;
      }

#ifdef ARGUSDEBUG
      ArgusDebug (5, "RaProcessAddressGroup (0x%x, 0x%x, 0x%x, %d, %d) returning %d\n", parser, addr, type, mode, retn);
#endif
   }

   return (retn);
}


#if defined(ARGUS_MYSQL)

/*
   Mysql URL that we will respond to is:
      mysql://[username[:password]@]hostname[:port]/database/tablename
*/



#ifdef ARGUS_MYSQL
void
RaMySQLInit (int ncons)
{
   my_bool reconnectbuf = 1, *reconnect = &reconnectbuf;
   char *sptr = NULL, *ptr;
   char userbuf[1024], sbuf[1024], db[1024], *dbptr = NULL;
   MYSQL_RES *mysqlRes;
   int retn = 0;

   bzero((char *)RaTableCreateNames,  sizeof(RaTableCreateNames));
   bzero((char *)RaTableCreateString, sizeof(RaTableCreateString));
   bzero((char *)RaTableDeleteString, sizeof(RaTableDeleteString));

   if (ArgusParser->MySQLDBEngine == NULL)
      ArgusParser->MySQLDBEngine = strdup("MyISAM");

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

      if (RaDatabase != NULL)
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

   MUTEX_INIT(&RaMySQLlock, NULL);
   if (MUTEX_LOCK(&RaMySQLlock) == 0) {
      int con;

      if (RaMySQL == NULL)
         if ((RaMySQL = (void *) ArgusCalloc(ncons, sizeof(*RaMySQL))) == NULL)
            ArgusLog(LOG_ERR, "RaMySQLInit: ArgusCalloc error %s", strerror(errno));
    
      for (con = 0; con < ncons; con++)
         if ((mysql_init(RaMySQL+con)) == NULL)
            ArgusLog(LOG_ERR, "mysql_init error %s");

      if (!mysql_thread_safe())
         ArgusLog(LOG_INFO, "mysql not thread-safe");

      mysql_options(RaMySQL, MYSQL_READ_DEFAULT_GROUP, ArgusParser->ArgusProgramName);
      mysql_options(RaMySQL, MYSQL_OPT_RECONNECT, reconnect);

#ifdef ARGUSDEBUG
      ArgusDebug (2, "RaMySQLInit: connect %s %s %d\n", RaHost, RaUser, RaPort);
#endif

      for (con = 0; con < ncons; con++)
         if ((mysql_real_connect(RaMySQL+con, RaHost, RaUser, RaPass, NULL, RaPort, NULL, 0)) == NULL)
            ArgusLog(LOG_ERR, "mysql_connect error %s", mysql_error(RaMySQL));

      bzero(sbuf, sizeof(sbuf));
      sprintf (sbuf, "SHOW VARIABLES LIKE 'version'");

      if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
         ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

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
         ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

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
         ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

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

      bzero(sbuf, sizeof(sbuf));
      sprintf (sbuf, "CREATE DATABASE IF NOT EXISTS %s", RaDatabase);

#ifdef ARGUSDEBUG
      ArgusDebug (6, "RaMySQLInit () mysql_real_query: %s\n", sbuf);
#endif

      if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)  
         ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

      sprintf (sbuf, "USE %s", RaDatabase);

      for (con = 0; con < ncons; con++)
         if ((retn = mysql_real_query(RaMySQL+con, sbuf, strlen(sbuf))) != 0)
            ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

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
      MUTEX_UNLOCK(&RaMySQLlock);
   }

   if ((ArgusParser->ArgusInputFileList != NULL)  ||
        (ArgusParser->ArgusRemoteHosts && (ArgusParser->ArgusRemoteHosts->count > 0))) {

      if (RaSQLSaveTable && (strlen(RaSQLSaveTable) > 0)) {
         if (strchr(RaSQLSaveTable, '%')) {
            int err = 1;
            if (RaBinProcess != NULL) {
               struct ArgusAdjustStruct *nadp = &RaBinProcess->nadp;
               if (nadp->mode == ARGUSSPLITTIME) 
                  err = 0;
            }
            if (err)
               ArgusLog (LOG_ERR, "RaMySQLInit: mysql save table time subsitution, but time mode not set\n", strerror(errno));

         } else
            if (ArgusCreateSQLSaveTable(RaDatabase, RaSQLSaveTable))
               ArgusLog(LOG_ERR, "mysql create %s.%s returned error", RaDatabase, RaSQLSaveTable);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaMySQLInit () RaSource %s RaArchive %s RaFormat %s", RaSource, RaArchive, RaFormat);
#endif
}
#endif /* ARGUS_MYSQL */


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


extern struct dbtblmem dbtables[];

#ifdef ARGUS_MYSQL
int
ArgusCreateSQLSaveTable(char *db, char *table)
{
   int retn = 0, cindex = 0, i, exists = 0;
   char stable[1024], sbuf[MAXSTRLEN], kbuf[MAXSTRLEN];
   MYSQL_RES *mysqlRes;

   MUTEX_LOCK(&RaMySQLlock);

   if ((db != NULL) && (table != NULL)) {
      sprintf (stable, "%s.%s", db, table);
 
      if (check_dbtbl(dbtables, (u_char *)stable) == NULL) {
         bzero(sbuf, sizeof(sbuf));
         bzero(kbuf, sizeof(kbuf));

         sprintf (sbuf, "SHOW TABLES LIKE '%s'", table);
         if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
            ArgusLog(LOG_INFO, "ArgusCreateSQLSaveTable: mysql_real_query %s error %s", sbuf, mysql_error(RaMySQL));

         if ((mysqlRes = mysql_store_result(RaMySQL)) != NULL) {
            exists = mysql_num_rows(mysqlRes);
            mysql_free_result(mysqlRes);
         }

         if (ArgusDropTable) {
            if (exists) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "ArgusCreateSQLSaveTable: drop table %s\n", table);
#endif
               sprintf (sbuf, "DROP TABLE %s", table);
               if ((retn = mysql_real_query(RaMySQL, sbuf, strlen(sbuf))) != 0)
                  ArgusLog(LOG_ERR, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));
               exists = 0;
            }
         }

         if (!exists) {
            if (RaTableCreateNames[cindex])
               free(RaTableCreateNames[cindex]);

            RaTableCreateNames[cindex] = strdup(stable);

            sprintf (sbuf, "CREATE table %s (`policy` VARCHAR(64), `name` VARCHAR(64), `version` int(1), `stime` double(18,6) unsigned not null, `ltime` double(18,6) unsigned not null, `status` int(1), `match` bigint(1), `conform` bigint(1), `nonconform` bigint(1), `client` bigint(1), `server` bigint(1), `verify` bigint(1), `replies` bigint(1), primary key (stime,policy,name,version)", RaTableCreateNames[cindex]);

            if ((MySQLVersionMajor > 4) || ((MySQLVersionMajor == 4) &&
                                            (MySQLVersionMinor >= 1)))
               sprintf (&sbuf[strlen(sbuf)], ") ENGINE=%s", ArgusParser->MySQLDBEngine);
            else
               sprintf (&sbuf[strlen(sbuf)], ") TYPE=%s", ArgusParser->MySQLDBEngine);

            if (RaTableCreateString[cindex])
               free(RaTableCreateString[cindex]);
            RaTableCreateString[cindex] = strdup(sbuf);

            cindex++;

            for (i = 0; i < cindex; i++) {
               char *str = NULL;
               if (RaTableCreateNames[i] != NULL) {
                  if ((str = RaTableCreateString[i]) != NULL) {
#ifdef ARGUSDEBUG
                     ArgusDebug (2, "ArgusCreateSQLSaveTable: %s\n", str);
#endif
                     if ((retn = mysql_real_query(RaMySQL, str, strlen(str))) != 0)
                        ArgusLog(LOG_INFO, "MySQLInit: %s, mysql_real_query error %s", sbuf, mysql_error(RaMySQL));

                     ArgusCreateTable = 1;
                  }
               }
            }

            lookup_dbtbl(dbtables, (u_char *)stable);
         }
      }

   } else {
      char *tbl = RaSQLCurrentTable;
      RaSQLCurrentTable = NULL;
      free(tbl);

      for (i = 0; i < RA_MINTABLES; i++) {
         if (RaTableCreateNames[i] != NULL){free (RaTableCreateNames[i]); RaTableCreateNames[i] = NULL;}
         if (RaTableCreateString[i] != NULL){free (RaTableCreateString[i]); RaTableCreateString[i] = NULL;}
      }
   }

   MUTEX_UNLOCK(&RaMySQLlock);

#ifdef ARGUSDEBUG
   if (retn)
      ArgusDebug (1, "ArgusCreateSQLSaveTable (%s, %s) created", db, table);
#endif
   return (retn);
}
#endif /* ARGUS_MYSQL */

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

#endif // ARGUS_MYSQL

int
RaProcessRecursiveConfigs (struct ArgusQueueStruct *queue, char *path)
{
   struct ArgusFileInput *file;
   struct stat statbuf;
   size_t pathlen;
   int retn = 1;
   char *name;

   if (stat(path, &statbuf) < 0)
      return(0);

   pathlen = strlen(path);
   if (pathlen > MAXSTRLEN) {
      ArgusLog(LOG_WARNING, "%s: path name > %u\n", __func__, MAXSTRLEN);
      return 0;
   }

   if ((pathlen > 1) && ((path[0] == '.') && (path[1] != '/')))
      return (0);

   name = ArgusMalloc(MAXSTRLEN);
   if (name == NULL)
      ArgusLog(LOG_ERR, "%s: Unable to allocate filename buffer\n", __func__);

   strcpy(name, path);

   if ((statbuf.st_mode & S_IFMT) == S_IFDIR) {
      retn = RaDescend (queue, name, MAXSTRLEN, pathlen);
   } else {
      if ((statbuf.st_mode & S_IFMT) == S_IFREG) {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaProcessRecursiveConfigs: adding %s\n", path);
#endif
         if (!(file = ArgusAddConfigList (queue, path, ARGUS_DATA_SOURCE, -1, -1)))
            ArgusLog (LOG_ERR, "error: -R file arg %s\n", path);

         /* Copy the stat() results since we already have them. */
         file->statbuf = statbuf;
      }
   }

   ArgusFree(name);
   return (retn);
}


static int
RaDescend(struct ArgusQueueStruct *queue, char *name, size_t len, size_t end)
{
   int retn = 0;
   DIR *dir;
   struct ArgusFileInput *file;
   struct dirent *direntry;
   struct stat statbuf;
   int slen;
 
   if (stat(name, &statbuf) < 0)
      return(0);
 
   if ((dir = opendir(name)) != NULL) {
      while ((direntry = readdir(dir)) != NULL) {
         if (*direntry->d_name != '.') {
            /* append another directory component */
            slen = snprintf (&name[end], len-end, "/%s", direntry->d_name);

            /* snprintf returns the number of bytes that would be used
             * even if that exceeds the length parameter
             */
            if (slen > (len - end))
               slen = len - end;

            if (stat(name, &statbuf) == 0) {
               if ((statbuf.st_mode & S_IFMT) == S_IFDIR) {
                  retn += RaDescend(queue, name, len, end + slen);
 
               } else {
                  if ((statbuf.st_mode & S_IFMT) == S_IFREG) {
#ifdef ARGUSDEBUG
                     ArgusDebug (2, "RaDescend: adding %s\n", name);
#endif
                     if (!(file = ArgusAddConfigList (queue, name, ARGUS_DATA_SOURCE, -1, -1)))
                        ArgusLog (LOG_ERR, "error: -R file arg %s\n", name);
                     file->statbuf = statbuf;
                     retn++;
                  }
               }
            }
            /* remove a directory component */
            name[end] = '0';
         }
      }
      closedir(dir);

   }
 
   return(retn);
}


struct ArgusFileInput *
ArgusAddConfigList (struct ArgusQueueStruct *queue, char *ptr, int type, long long ostart, long long ostop)
{
   struct ArgusFileInput *retn = NULL;

   if (ptr) {
      if ((retn = ArgusCalloc (1, sizeof(*retn))) != NULL) {

         retn->type = type;
         retn->ostart = ostart;
         retn->ostop = ostop;
         retn->filename = strdup(ptr);
         retn->fd = -1;
         ArgusAddToQueue(queue, &retn->qhdr, ARGUS_LOCK);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusAddConfigList (0x%x, %s, %d, %d, %d) returning %d\n", queue, ptr, type, ostart, ostop, retn);
#endif

   return (retn);
}
