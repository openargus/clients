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
 * argus_event.c - library for event generation
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */
 
/*
 * $Id: //depot/argus/clients/common/argus_event.c#22 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */
 

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#define ARGUS_EVENT_PROC		1
#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>

#include <syslog.h>
#include <errno.h>
#include <math.h>
#include <ctype.h>

#include <string.h>

#include <sys/types.h>
#include <pwd.h>

#if defined(ARGUSMYSQL)
#include <mysql.h>
#endif

#include <argus_util.h>
#include <argus_parser.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_event.h>

#include <argus_cluster.h>

#define RATOTALSQLOBJECTS	40

char *RaSQLFieldObject [RATOTALSQLOBJECTS] = {
   "srcid", "startime", "lasttime", "dur", "avgdur",
   "saddr", "daddr", "proto", "sport", "dport",
   "ipid", "stos", "dtos", "sttl", "dttl",
   "sbytes", "dbytes", "spkts", "dpkts", "sload",

   "dload", "sloss", "dloss", "srate", "drate",
   "ind", "smac", "dmac", "dir", "jitter", "status", "user",
   "win", "trans", "seq", "vlan", "vid", "vpri", 
   "mpls", "svc"
};

#if defined(ARGUSMYSQL)

char *RaSQLFieldType [RATOTALSQLOBJECTS] = {
   "varchar(32) not null",
   "varchar(32) not null",
   "varchar(32) not null",
   "float not null",
   "float not null",
   "varchar(64) not null",
   "varchar(64) not null",
   "varchar(16) not null",
   "smallint unsigned not null",
   "smallint unsigned not null",

   "smallint unsigned not null",
   "tinyint unsigned not null",
   "tinyint unsigned not null",
   "tinyint unsigned not null",
   "tinyint unsigned not null",
   "int unsigned not null",
   "int unsigned not null",
   "int unsigned not null",
   "int unsigned not null",
   "float unsigned not null",

   "float unsigned not null",
   "int unsigned not null",
   "int unsigned not null",
   "float unsigned not null",
   "float unsigned not null",

   "int unsigned not null",
   "varchar(64) not null",
   "varchar(64) not null",
   "varchar(4) not null",
   "int unsigned not null",
   "varchar(8) not null",
   "varchar(64) not null",

   "int unsigned not null",
   "int unsigned not null",
   "int unsigned not null",
   "int unsigned not null",
   "int unsigned not null",
   "int unsigned not null",

   "int unsigned not null",
   "varchar(16) not null",
};

struct ArgusEventObject *
ArgusNewEvent(struct ArgusParserStruct *parser, int target, int type, int cause,
                     int facility, int severity, char *accounts, char *message, char *metadata)
{
   struct ArgusEventObject *retn = NULL;

   if ((retn = (struct ArgusEventObject *) calloc(1, sizeof (*retn))) != NULL) {
      retn->target   = target;
      retn->type     = type;
      retn->cause    = cause;
      retn->facility = facility;
      retn->severity = severity;
      if (accounts)
         retn->accounts = strdup(accounts);
      if (message)
         retn->message  = strdup(message);
      if (metadata)
         retn->metadata  = strdup(metadata);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusNewEvent(0x%x) returns 0x%x\n", parser, retn);
#endif
   return (retn);
}

void
ArgusDeleteEvent(struct ArgusEventObject *event)
{
   if (event->accounts)
      free (event->accounts);
   if (event->message)
      free (event->message);
   if (event->metadata)
      free (event->metadata);

   free(event);
 
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusDeleteEvent(0x%x)\n", event);
#endif
}


int ArgusProcessSQLEvent (struct ArgusParserStruct *, struct ArgusEventObject *, struct ArgusRecordStruct *);
int ArgusProcessSyslogEvent (struct ArgusParserStruct *, struct ArgusEventObject *, struct ArgusRecordStruct *);
int ArgusProcessFileEvent (struct ArgusParserStruct *, struct ArgusEventObject *, struct ArgusRecordStruct *);
int ArgusProcessTermEvent (struct ArgusParserStruct *, struct ArgusEventObject *, struct ArgusRecordStruct *);

int
ArgusProcessEvent (struct ArgusParserStruct *parser, struct ArgusEventObject *event, struct ArgusRecordStruct *ns)
{
   int retn = 0, i, x;

   if (!(event->target)) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "RaProcessEvent: No event disposition targets selected");
#endif
   } else {
      char resultbuf[MAXSTRLEN], tmpbuf[MAXSTRLEN];
      char *tptr = event->metadata, *ptr, *cptr;

      if (tptr && strchr (tptr, '$')) {
         bzero (resultbuf, sizeof(resultbuf));

         while ((ptr = strchr (tptr, '$')) != NULL) {
            *ptr++ = '\0';
            sprintf (&resultbuf[strlen(resultbuf)], "%s", tptr);
 
            for (i = 0, x = 0; x < MAX_PRINT_ALG_TYPES; x++) {
               if (!strncmp (RaPrintAlgorithmTable[x].field, ptr, strlen(RaPrintAlgorithmTable[x].field))) {
                  if (ns != NULL)
                     RaPrintAlgorithmTable[x].print(parser, tmpbuf, ns, RaPrintAlgorithmTable[x].length);
 
                  while (isspace((int)tmpbuf[strlen(tmpbuf) - 1]))
                     tmpbuf[strlen(tmpbuf) - 1] = '\0';
 
                  while (isspace((int)tmpbuf[i])) i++;
                  sprintf (&resultbuf[strlen(resultbuf)], "%s", &tmpbuf[i]);
 
                  ptr += strlen(RaPrintAlgorithmTable[x].field);
                  cptr = &resultbuf[strlen(resultbuf)];
 
                  while (*ptr && (*ptr != '$')) {
                     *cptr++ = *ptr++;
                  }
                  *cptr = '\0';
                  break;
               }
            }
 
            tptr = ptr;
            retn++;
         }

         free (event->metadata);
         event->metadata = strdup(resultbuf);
      }
       
      for (i = 1; i < (AIS_ETARGETS + 1); i++) {
         if (event->target & (0x01 << (i - 1))) {
            switch ((0x01 << (i - 1))) {
               case AIS_DATABASE: retn = ArgusProcessSQLEvent(parser, event, ns); break;
               case AIS_SYSLOG :  retn = ArgusProcessSyslogEvent(parser, event, ns); break;
               case AIS_FILE:     retn = ArgusProcessFileEvent(parser, event, ns); break;
               case AIS_TERM:     retn = ArgusProcessTermEvent(parser, event, ns); break;
               default:  break;
            }

            if (retn) return(retn);
         }
      }
   }

#ifdef ARGUSDEBUG
      ArgusDebug (1, "RaProcessEvent(0x%x, 0x%x, 0x%x) return %d", parser, event, ns, retn);
#endif

   return (retn);
}


int
ArgusProcessSQLEvent (struct ArgusParserStruct *parser, struct ArgusEventObject *event, struct ArgusRecordStruct *ns)
{
   char *RaDatabase = NULL, *RaHost = NULL, *RaUser = NULL;
   char *RaPass = NULL, *RaTable = NULL;
   char *ArgusEventTableName = NULL;
   char sbuf[MAXBUFFERLEN], mbuf[MAXBUFFERLEN];
   char username[256], userbuf[256]; 
   char rbuf[ARGUS_MAXRECORDSIZE];
   char *ptr, *aname, *accounts = NULL;
   char *sptr, *hptr; 
   struct ArgusRecord *argus = NULL;
   char stim[128], etim[128];
   struct timeval stvp, etvp;
   extern char version[];
   int retn = 0, i, x, len;
   MYSQL_RES *mysqlRes;
   MYSQL_ROW row;
   MYSQL mysql;

   if ((RaUser == NULL) && (ArgusParser->dbustr != NULL)) {
      bzero(userbuf, sizeof(userbuf));
      strncpy (userbuf, ArgusParser->dbustr, sizeof(userbuf));
      if ((sptr = strchr (userbuf, '/')) != NULL)
         *sptr = '\0';
      RaUser = strdup(userbuf);
   }
 
   if ((RaPass == NULL) && (ArgusParser->dbpstr != NULL))
      RaPass = ArgusParser->dbpstr;
 
   if ((RaDatabase == NULL) && (ArgusParser->writeDbstr != NULL))
      RaDatabase = ArgusParser->writeDbstr;
 
   if (RaDatabase == NULL)
      ArgusLog(LOG_ERR, "must specify database");
 
   if ((hptr = strchr (RaDatabase, '@')) != NULL) {
      *hptr++ = '\0';
      RaHost = hptr;
   }
 
   if ((ptr = strchr (RaDatabase, ':')) != NULL) {
      *ptr++ = '\0';
      RaTable = ptr;
   }

   sprintf (sbuf, "%s_Events", RaDatabase);
   ArgusEventTableName = strdup(sbuf);

   bzero((char *)RaExistTableNames, sizeof(RaExistTableNames));
 
   if ((mysql_init(&mysql)) != NULL) {
      mysql_options(&mysql, MYSQL_READ_DEFAULT_GROUP, parser->ArgusProgramName);
      if ((mysql_real_connect(&mysql, RaHost, RaUser, RaPass, NULL, 0, NULL, 0)) != NULL) {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "RaProcessSQLEvent: mysql_real_connect() connected as %s.\n", RaUser);
#endif
         bzero(sbuf, sizeof(sbuf));

         sprintf (sbuf, "CREATE DATABASE IF NOT EXISTS %s", RaDataBase);
#ifdef ARGUSDEBUG
         ArgusDebug (1, "RaProcessSQLEvent: mysql_real_query() %s\n", sbuf);
#endif
         if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) == 0) {
            sprintf (sbuf, "USE %s", RaDataBase);
            if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) != 0)
               ArgusLog(LOG_ERR, "RaProcessSQLEvent: mysql: %s error %s", sbuf, mysql_error(&mysql));
         } else
            ArgusLog(LOG_ERR, "RaProcessSQLEvent: mysql: %s error %s", sbuf, mysql_error(&mysql));

         if ((mysqlRes = mysql_list_tables(&mysql, NULL)) != NULL) {
            if ((retn = mysql_num_fields(mysqlRes)) > 0) {
               int ind = 0;

               while ((row = mysql_fetch_row(mysqlRes))) {
                  if (ind > RA_MAX_TABLE_ARRAY) {
                     unsigned long *lengths;
                
                     lengths = mysql_fetch_lengths(mysqlRes);
                     bzero(sbuf, sizeof(sbuf));
                     for (x = 0; x < retn; x++)
                        sprintf(&sbuf[strlen(sbuf)], "%.*s", (int) lengths[x], row[x] ? row[x] : "NULL");

                     RaExistTableNames[ind++] = strdup (sbuf);

                  } else
                     break;
               }

            } else {
#ifdef ARGUSDEBUG
               ArgusDebug (1, "RaProcessSQLEvent: mysql_num_fields() returned zero.\n");
#endif
            }

            mysql_free_result(mysqlRes);

            for (x = 0; x < RA_MAX_TABLE_ARRAY; x++) {
               if (RaExistTableNames[x]) {
#ifdef ARGUSDEBUG
                  ArgusDebug (7, "RaProcessSQLEvent: existing table name '%s'\n", RaExistTableNames[x]);
#endif
                  for (i = 0; i < RA_MAXTABLES; i++) {
                     if (RaExistTableNames[x] && ArgusEventTableName) {
                        if (!(strcmp(RaExistTableNames[x], ArgusEventTableName))) {
                           RaTableFlags |= (0x01 << i);
                           break;
                        }
                     }
                  }
               } else
                  break;
            }
         }

         if (RaTableFlags != RA_MAXTABLES_MASK) {
            char qstr[MAXSTRLEN];

            for (i = 0; i < RA_MAXTABLES; i++) {
#ifdef ARGUSDEBUG
               ArgusDebug (2, "RaProcessSQLEvent: generating table %s\n", ArgusEventTableName);
#endif
               sprintf (qstr, ArgusEventTableCreationString[i], ArgusEventTableName);
               if ((retn = mysql_real_query(&mysql, qstr, strlen(qstr))) != 0)
                  ArgusLog(LOG_ERR, "mysql_real_query error %s", mysql_error(&mysql));
            }

         } else {
         }

      } else
         ArgusLog(LOG_ERR, "RaProcessSQLEvent: mysql_connect error %s", mysql_error(&mysql));

#ifdef ARGUSDEBUG
      ArgusDebug (2, "RaProcessSQLEvent: all %s tables ok\n", RaDataBase);
#endif
   } else
      ArgusLog(LOG_ERR, "mysql_init error %s", mysql_error(&mysql));

   if (event->type & (AIS_EVENT | AIS_CONDITION)) {
      if (ns != NULL) {
         struct ArgusTimeObject *time = (void *) ns->dsrs[ARGUS_TIME_INDEX];
         if (time != NULL) {
            if ((time->src.start.tv_sec  == time->src.start.tv_sec) &&
                (time->src.start.tv_usec == time->src.start.tv_usec)) {
               event->type |= AIS_EVENT;
            } else {
               event->type |= AIS_CONDITION;
            }
         }
      }
   }

   if (accounts == NULL)
      accounts = getpwuid(geteuid())->pw_name;

   while ((aname = strtok (accounts, " ")) != NULL) {
      char *uid = NULL, *name = NULL, *pass = NULL, *stat = NULL;
      char *fullname = NULL, *address = NULL, *telephone = NULL;
      char *mobile = NULL, *fax = NULL, *email = NULL, *url = NULL, *filter = NULL;

      sprintf (username, "%s", aname);
      bzero(sbuf, sizeof(sbuf));
      sprintf (sbuf, "SELECT * FROM Accounts WHERE name=\"%s\" and status=\"active\"", username);

#ifdef ARGUSDEBUG
      ArgusDebug (1, "RaProcessSQLEvent: mysql_real_query() %s\n", sbuf);
#endif
      if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) != 0)
         ArgusLog(LOG_ERR, "RaProcessSQLEvent: mysql_real_query error %s", mysql_error(&mysql));
      else {
         if ((mysqlRes = mysql_store_result(&mysql)) != NULL) {
            if ((retn = mysql_num_fields(mysqlRes)) == 12) {
               if ((row = mysql_fetch_row(mysqlRes)) != NULL) {
                  if (row[0]) uid       = strdup((const char *)row [0]);
                  if (row[1]) name      = strdup((const char *)row [1]);
                  if (row[2]) fullname  = strdup((const char *)row [2]);
                  if (row[3]) address   = strdup((const char *)row [3]);
                  if (row[4]) telephone = strdup((const char *)row [4]);
                  if (row[5]) mobile    = strdup((const char *)row [5]);
                  if (row[6]) fax       = strdup((const char *)row [6]);
                  if (row[7]) email     = strdup((const char *)row [7]);
                  if (row[8]) url       = strdup((const char *)row [8]);
                  if (row[9]) pass      = strdup((const char *)row [9]);
                  if (row[10]) filter   = strdup((const char *)row [10]);
                  if (row[11]) stat     = strdup((const char *)row [11]);
               }
            } else
               ArgusLog(LOG_ERR, "RaProcessSQLEvent: mysql query %s returned %d items", sbuf, retn);

            mysql_free_result(mysqlRes);
         }
      }

      if (uid) free(uid);
      if (name) free(name);
      if (fullname) free(fullname);
      if (address) free(address);
      if (telephone) free(telephone);
      if (mobile) free(mobile);
      if (fax) free(fax);
      if (email) free(email);
      if (url) free(url);
      if (pass) free(pass);
      if (filter) free(filter);
      if (stat) free(stat);
    
      accounts = NULL;
   }

#ifdef ARGUSDEBUG
   {
      char debugmsg[MAXSTRLEN];
      char types[MAXSTRLEN];
      int i, seen;

      bzero(types, MAXSTRLEN);
      for (i = 0, seen = 0; i < AIS_NTYPES; i++) {
         if (event->type & (0x01 << i)) {
            if (seen) sprintf (&types[strlen(types)], "|");
            sprintf (&types[strlen(types)], "%s", RaSQLEventTypes[i].s);
            seen++;
         }
      }

      sprintf (debugmsg, "%s -T %s -c %s -f %s -s %s -t %s", parser->ArgusProgramName,
         types, RaSQLEventCause[event->cause].s, RaSQLEventFacilities[event->facility].s,
         RaSQLEventSeverities[event->severity].s, parser->timearg);

      if (event->message != NULL)
         sprintf (&debugmsg[strlen(debugmsg)], " -m '%s'", event->message);

      if (event->metadata != NULL)
         sprintf (&debugmsg[strlen(debugmsg)], " -M '%s'", event->metadata);

      ArgusDebug (1, "%s", debugmsg);
   }
#endif

   if (parser->RaTimeFormat != NULL)
      free (parser->RaTimeFormat);

   parser->RaTimeFormat = strdup("%Y-%m-%d %H:%M:%S"); /* so can be freed */
   
   bzero(sbuf, sizeof(sbuf));
   bzero(stim, sizeof(stim));
   bzero(etim, sizeof(etim));

   if (ns == NULL) {
      if ((stvp.tv_sec = parser->startime_t.tv_sec) == 0x7FFFFFFF)
         gettimeofday(&stvp, 0L);

      if ((etvp.tv_sec  = parser->lasttime_t.tv_sec) == 0)
         gettimeofday(&etvp, 0L);

   } else {
      struct ArgusTimeObject *time = (void *) ns->dsrs[ARGUS_TIME_INDEX];
      if (time != NULL) {
         stvp.tv_sec = time->src.start.tv_sec;
         etvp.tv_sec = time->src.end.tv_sec;
      }
   }

   ArgusPrintTime (parser, stim, &stvp);
   ArgusPrintTime (parser, etim, &etvp);

   if (ns != NULL) {
      if ((argus = ArgusGenerateRecord (ns, 0L, rbuf)) == NULL)
         ArgusLog(LOG_ERR, "RaProcessSQLEvent: ArgusGenerateRecord error %s", strerror(errno));

#ifdef _LITTLE_ENDIAN
      ArgusHtoN(argus);
#endif
      if ((len = mysql_real_escape_string(&mysql, mbuf, (char *)argus, ntohs(argus->hdr.len) * 4)) <= 0)
         ArgusLog(LOG_ERR, "RaProcessSQLEvent: mysql_real_escape_string error %s", mysql_error(&mysql));
   }
   
   if (argus != NULL) {
      sprintf (sbuf, "INSERT %s (project, start, end, type, cause, facility, severity, version, message, metadata, status, record) VALUES ", ArgusEventTableName);
      sprintf (&sbuf[strlen(sbuf)], "(\"%s\", \"%s\", \"%s\", %d, %d, %d, %d, \"%s\", \"%s\", \"%s\", %d, \"%s\")",
               RaDatabase, stim, etim, event->type, event->cause, event->facility, 
               event->severity, version, event->message, event->metadata, 0, mbuf);
   } else {
      sprintf (sbuf, "INSERT %s (project, start, end, type, cause, facility, severity, version, message, metadata, status) VALUES ", ArgusEventTableName);
      sprintf (&sbuf[strlen(sbuf)], "(\"%s\", \"%s\", \"%s\", %d, %d, %d, %d, \"%s\", \"%s\", \"%s\", %d)",
               RaDatabase, stim, etim, event->type, event->cause, event->facility, 
               event->severity, version, event->message, event->metadata, 0);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaProcessSQLEvent: mysql_real_query() %s\n", sbuf);
#endif

   if ((retn = mysql_real_query(&mysql, sbuf, strlen(sbuf))) != 0)
      ArgusLog(LOG_ERR, "RaProcessSQLEvent: mysql_real_query error %s", mysql_error(&mysql));

   mysql_close(&mysql);

   if (ArgusEventTableName != NULL)
      free (ArgusEventTableName);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessSQLEvent(0x%x, 0x%x, 0x%x) returns %d\n", parser, event, ns, retn);
#endif
   return (retn);
}


int
ArgusProcessSyslogEvent (struct ArgusParserStruct *parser, struct ArgusEventObject *event, struct ArgusRecordStruct *ns)
{
   int retn = 0, logopt = LOG_PID, i;
   char sbuf[MAXSTRLEN];
   char *facility;

   for (i = 0; i < AIS_NFACILITY; i++)
      if (RaSQLEventFacilities[i].v == event->facility)
         facility = RaSQLEventFacilities[i].s;

   sprintf (sbuf, "[ais] %s:%s:'%s' ", facility, event->metadata, event->message);

   if (ns != NULL)
      ArgusPrintRecord (parser, &sbuf[strlen(sbuf)], ns, MAXSTRLEN - strlen(sbuf));

   openlog (parser->ArgusProgramName, logopt, LOG_DAEMON);
   syslog (event->severity, sbuf);
   closelog();
 
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessSyslogEvent(0x%x, 0x%x, 0x%x) returns %d\n", parser, event, ns, retn);
#endif
   return (retn);
}

int
ArgusProcessFileEvent (struct ArgusParserStruct *parser, struct ArgusEventObject *event, struct ArgusRecordStruct *ns)
{
   int retn = 0, i;
   char sbuf[MAXSTRLEN];
   char stimebuf[128];
   struct timeval now;
   char *facility;
 
   gettimeofday (&now, 0L);
   memset(sbuf, 0, MAXSTRLEN);
   memset(stimebuf, 0, 128);
   ArgusPrintTime(ArgusParser, stimebuf, &now);
 
   (void) sprintf (sbuf, "%s %s[%d]: ", stimebuf, ArgusParser->ArgusProgramName, (int)getpid());
 
   for (i = 0; i < AIS_NFACILITY; i++)
      if (RaSQLEventFacilities[i].v == event->facility)
         facility = RaSQLEventFacilities[i].s;
 
   sprintf (&sbuf[strlen(sbuf)], "[ais] %s:%s:'%s' ", facility, event->metadata, event->message);
 
   if (ns != NULL)
      ArgusPrintRecord (parser, &sbuf[strlen(sbuf)], ns, MAXSTRLEN - strlen(sbuf));

   if (parser->ArgusWfileList != NULL) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL; 
      int i, count = parser->ArgusWfileList->count;

      if ((lobj = parser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {  
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                  FILE *fd = NULL;

                  if ((fd = fopen (wfile->filename, "a+")) != NULL) {
                     fprintf (fd, "%s\n", sbuf);
                     fclose(fd);
                  }
               }
            }
            lobj = lobj->nxt; 
         }
      }

   } else
      ArgusLog (LOG_ERR, "ArgusProcessFileEvent: not file specified");
 
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessFileEvent(0x%x, 0x%x, 0x%x) returns %d\n", parser, event, ns, retn);
#endif
   return (retn);
}

int
ArgusProcessTermEvent (struct ArgusParserStruct *parser, struct ArgusEventObject *event, struct ArgusRecordStruct *ns)
{
   int retn = 0, i;
   char sbuf[MAXSTRLEN];
   char stimebuf[128];
   struct timeval now;
   char *facility;

   gettimeofday (&now, 0L);
   memset(sbuf, 0, MAXSTRLEN);
   memset(stimebuf, 0, 128);
   ArgusPrintTime(ArgusParser, stimebuf, &now);

   (void) sprintf (sbuf, "%s %s[%d]: ", stimebuf, ArgusParser->ArgusProgramName, (int)getpid());
 
   for (i = 0; i < AIS_NFACILITY; i++)
      if (RaSQLEventFacilities[i].v == event->facility)
         facility = RaSQLEventFacilities[i].s;

   sprintf (&sbuf[strlen(sbuf)], "[ais] %s:%s:'%s' ", facility, event->metadata, event->message);

   if (ns != NULL)
      ArgusPrintRecord (parser, &sbuf[strlen(sbuf)], ns, MAXSTRLEN - strlen(sbuf));

   printf ("%s\n", sbuf);
 
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusProcessTermEvent(0x%x, 0x%x, 0x%x) returns %d\n", parser, event, ns, retn);
#endif
   return (retn);
}


#endif
