/*
 * The RaMySQLInit() function really needs to go in a library, but the
 * use of globals will need to be cleaned up first.
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <stdlib.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/syslog.h>
#include "argus_util.h"
#include "argus_client.h"
#include "argus_mysql.h"
#include "ramysqlinit.h"

#define RA_MAXTABLES    0x10000

/* these must be global/extern */
char *RaDatabase = NULL;
extern struct ArgusInput *ArgusInput;
extern MYSQL *RaMySQL;

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
static int RaSQLNoCreate;

int
RaMySQLGetMaxPacketSize(void)
{
   return ArgusSQLMaxPacketSize;
}

void
RaMySQLInit(struct ArgusParserStruct *parser)
{
// my_bool reconnectbuf = 1, *reconnect = &reconnectbuf;
   char userbuf[1024], sbuf[1024], db[1024], *dbptr = NULL;
   char *sptr = NULL, *ptr;
   MYSQL_RES *mysqlRes;
   MYSQL_ROW row;
   int retn = 0, x;

   if ((RaUser == NULL) && (parser->dbuserstr != NULL)) {
      bzero(userbuf, sizeof(userbuf));
      strncpy (userbuf, parser->dbuserstr, sizeof(userbuf));
      if ((sptr = strchr (userbuf, ':')) != NULL) {
         *sptr++ = '\0';
         RaPass = strdup(sptr);
      }
      RaUser = strdup(userbuf);
   }

   if ((RaPass == NULL) && (parser->dbpassstr != NULL))
      RaPass = parser->dbpassstr;

   if (RaDatabase == NULL) {
      if (parser->writeDbstr != NULL)
         RaDatabase = strdup(parser->writeDbstr);

      else if (parser->readDbstr != NULL)
         RaDatabase = strdup(parser->readDbstr);

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

      if (parser->writeDbstr != NULL)
         RaSQLSaveTable = strdup(RaTable);
   }

   if (!(parser->status & ARGUS_REAL_TIME_PROCESS))
      ArgusLastTime = parser->ArgusRealTime;

   if (RaMySQL == NULL)
      if ((RaMySQL = (void *) ArgusCalloc(1, sizeof(*RaMySQL))) == NULL)
         ArgusLog(LOG_ERR, "RaMySQLInit: ArgusCalloc error %s", strerror(errno));

   if ((mysql_init(RaMySQL)) == NULL)
      ArgusLog(LOG_ERR, "mysql_init error %s");

   if (!mysql_thread_safe())
      ArgusLog(LOG_INFO, "mysql not thread-safe");

   mysql_options(RaMySQL, MYSQL_READ_DEFAULT_GROUP, parser->ArgusProgramName);
// mysql_options(RaMySQL, MYSQL_OPT_RECONNECT, reconnect);

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

   if (parser->writeDbstr != NULL) {
      char *ptr;
      sprintf (parser->RaDBString, "-w %s", parser->writeDbstr);
      if ((ptr = strrchr(parser->writeDbstr, '/')) != NULL)
         *ptr = '\0';

   } else
   if (parser->readDbstr != NULL) {
      char *ptr;
      sprintf (parser->RaDBString, "-r %s", parser->readDbstr);
      if ((ptr = strrchr(parser->readDbstr, '/')) != NULL)
         *ptr = '\0';
   } else  {
      sprintf (parser->RaDBString, "db %s", RaDatabase);

      if (RaHost)
         sprintf (&parser->RaDBString[strlen(parser->RaDBString)], "@%s", RaHost);

      sprintf (&parser->RaDBString[strlen(parser->RaDBString)], " user %s", RaUser);
   }

   if ((parser->ArgusInputFileList != NULL)  ||
        (parser->ArgusRemoteHosts && (parser->ArgusRemoteHosts->count > 0))) {

   }

   if (parser->MySQLDBEngine == NULL)
      parser->MySQLDBEngine = strdup("MyISAM");

#ifdef ARGUSDEBUG
   ArgusDebug(1, "%s() RaSource %s RaArchive %s RaFormat %s", __func__,
            RaSource, RaArchive, RaFormat);
#endif
}
