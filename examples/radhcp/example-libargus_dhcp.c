/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2019 QoSient, LLC
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

#include <limits.h>
#include <arpa/inet.h>
#include <sys/syslog.h>
#include "argus_util.h"
#include "argus_client.h"
#include "argus_main.h"
#include "rabootp.h"
#include "rabootp_print.h"
#include "rabootp_memory.h"
#include "argus_format_json.h"
#include "argus_dhcp.h"

#if defined(CYGWIN)
# include <sys/cygwin.h>
# define USE_IPV6
#endif

#ifdef ARGUSDEBUG
# define DEBUGLOG(lvl, fmt...) ArgusDebug(lvl, fmt)
#else
# define DEBUGLOG(lvl, fmt...)
#endif

#include "argus_mysql.h"
#include <mysqld_error.h>

#define RA_MAXTABLES	0x10000
#define INVECSTRLEN	(8*1024*1024)

/* these must be global/extern */
char *RaDatabase = NULL;
struct ArgusInput *ArgusInput = NULL;
MYSQL *RaMySQL = NULL;

static char *RaSource;
static char *RaArchive;
static char *RaFormat;
static char *RaTable;
static char *RaSQLSaveTable;
static char *RaTableExistsNames[RA_MAXTABLES];
static int ArgusSQLSecondsTable;
static int ArgusSQLBulkInsertSize;
static int ArgusSQLMaxPacketSize;
static int ArgusSQLBulkBufferSize;
static char *ArgusSQLBulkBuffer;
static char *ArgusSQLVersion;
static int MySQLVersionMajor;
static int MySQLVersionMinor;
static int MySQLVersionSub;
static struct timeval ArgusLastTime;
static char *RaHost;
static char *RaUser;
static char *RaPass;
static int RaPort;
static struct RaBinProcessStruct *RaBinProcess;
static MYSQL_ROW row;
static bool pullup;
static bool have_clientmac;
static unsigned char clientmac[16];

/* Do not try to create a database.  Allows read-only operations
 * with fewer database permissions.
 */
static int RaSQLNoCreate;

extern int ArgusSOptionRecord;
extern char *RaRemoteFilter;
extern char RaFilterSQLStatement[];

void RaArgusInputComplete (struct ArgusInput *input) { return; }
void ArgusClientTimeout (void) { return; }
void usage (void) { return; }
int RaSendArgusRecord(struct ArgusRecordStruct *argus) { return 0; }
void ArgusWindowClose(void) { return; }


void RaSQLQuerySecondsTable (unsigned int, unsigned int);
void RaSQLQuerySecondsTable (unsigned int start, unsigned int stop) { return; }

static void
libArgusDhcpExampleParseClientMac(const char * const str)
{
   if (__ether_aton(str+strlen("clientmac="), clientmac) == 0)
      have_clientmac = 1;
   else
      ArgusLog(LOG_ERR, "unable to parse mac address\n");
}

static void
RaMySQLInit()
{
   my_bool reconnectbuf = 1, *reconnect = &reconnectbuf;
   char userbuf[1024], sbuf[1024], db[1024], *dbptr = NULL;
   char *sptr = NULL, *ptr;
   MYSQL_RES *mysqlRes;
   int retn = 0, x;

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
   mysql_options(RaMySQL, MYSQL_OPT_RECONNECT, reconnect);

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

   }

   if (ArgusParser->MySQLDBEngine == NULL)
      ArgusParser->MySQLDBEngine = strdup("MyISAM");

   DEBUGLOG(1, "%s() RaSource %s RaArchive %s RaFormat %s", __func__,
            RaSource, RaArchive, RaFormat);
}

void
ArgusClientInit(struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   int splitmode = -1;

  if ((mode = parser->ArgusModeList) == NULL)
     return;

  while (mode) {
     if (strcmp(mode->mode, "pullup") == 0) {
        pullup = true;
        mode = mode->nxt;
     } else if (strncmp(mode->mode, "clientmac=", 10) == 0) {
        libArgusDhcpExampleParseClientMac(mode->mode);
        mode = mode->nxt;
     } else
        mode = RaParseSplitMode(parser, &RaBinProcess, mode, &splitmode);
  }

  RaMySQLInit();
  ArgusDeleteFileList(parser);
  parser->RaParseDone = 1;
  parser->RaShutDown = 1;
}

void RaProcessRecord(struct ArgusParserStruct *parser,
                     struct ArgusRecordStruct *argus)
{
   DEBUGLOG(6, "%s?\n", __func__);
}

void RaParseComplete(int sig)
{
   static const ssize_t nleases = 1024*1024;
   struct ArgusDhcpIntvlNode *nodes;
   ssize_t i;
   int num;
   char *invecstr;

   if (sig < 0)
      return;

   if (ArgusParser->RaParseCompleting++)
      return;

   nodes = ArgusMalloc(sizeof(*nodes) * nleases);
   if (nodes == NULL) {
      ArgusLog(LOG_ERR, "unable to allocate lease array\n");
      return;
   }

   num = ArgusDhcpSqlQuery(ArgusParser, &RaBinProcess->nadp,
                           have_clientmac ? &clientmac[0] : NULL,
                           "dhcp_detail_%Y_%m_%d", pullup, nodes, nleases);
   if (num < 0) {
      ArgusLog(LOG_WARNING, "SQL query failed\n");
      goto out;
   }

   invecstr = ArgusMalloc(INVECSTRLEN);
   RabootpPrintDhcp(ArgusParser, nodes, num, invecstr, INVECSTRLEN,
                    &ArgusJsonFormatterTable);
   printf("%s\n", invecstr);
   ArgusFree(invecstr);

out:
   for (i = 0; i < num; i++)
      ArgusDhcpStructFree(nodes[i].data);

   ArgusFree(nodes);
   DEBUGLOG(1, "%s: found %d leases\n", __func__, num);
   mysql_close(RaMySQL);
   RaMySQL = NULL;
}
