/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
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
 */

/*
 * $Id: //depot/gargoyle/clients/include/argus_sql.h#4 $
 * $DateTime: 2013/11/11 19:24:45 $
 * $Change: 2713 $
 */
 
 
#ifndef Argus_sql_h
#define Argus_sql_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <argus_int.h>
#include <argus_event.h>

char ArgusSQLSaveTableNameBuf[1024];
struct tm ArgusSaveTableTmStruct;
time_t ArgusSaveTableSeconds = 0;

int ArgusCreateSQLSaveTable(char *, char *);
void ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusRecordStruct *, int);
struct ArgusSQLQueryStruct *ArgusConstructSQLQuery (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaMySQLDeleteRecords(struct ArgusParserStruct *, struct ArgusRecordStruct *);

struct ArgusRecordStruct *ArgusRemoveFromSQLList (struct ArgusListStruct *, int);

void RaSQLQueryTable (char *);
void RaSQLQueryNetworksTable (unsigned int, unsigned int, unsigned int);
void RaSQLQueryProbes (void);
void RaSQLQuerySecondsTable (unsigned int, unsigned int);

char *ArgusCreateSQLSaveTableName (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);

int RaSQLMcastMode = 0;

char RaSQLSaveTable[MAXSTRLEN];


char *ArgusEventTableCreationString[RA_MAXTABLES * 2] = {
   "CREATE TABLE %s (id int not null auto_increment, aisid varchar(255) not null, uid int(11) not null, project int(11) not null, start datetime, end datetime, type int(8), cause int(8), facility int(11), severity int(8), access timestamp(14), timestamp datetime not null, hostname varchar(255), sender varchar(255), instance varchar(255), version int(2) not null, message text, metadata text, status int (4), record blob, primary key (id))",

   "CREATE TABLE %s (id int not null auto_increment, %s , aisid varchar(255) not null, uid int(11) not null, project int(11) not null, start datetime, end datetime, type int(8), cause int(8), facility int(11), severity int(8), access timestamp(14), timestamp datetime not null, hostname varchar(255), sender varchar(255), instance varchar(255), version int(2) not null, message text, metadata text, status int (4), record blob, primary key (id))",
};

#if defined(ARGUS_EVENT_PROC)

struct ArgusTokenStruct RaSQLEventTypes[AIS_NTYPES] = {
   { AIS_EVENT,       "event" } ,
   { AIS_CONDITION,   "condition" } ,
   { AIS_INTERNAL,    "internal" } ,
   { AIS_MONITOR,     "monitor" } ,
   { AIS_REPORTED,    "reported" } ,
   { AIS_DERIVED,     "derived" } ,
   { AIS_OPERATIONS,  "ops" } ,
   { AIS_PERFORMANCE, "perf" } ,
   { AIS_SECURITY,    "sec" } ,
};

struct ArgusTokenStruct RaSQLEventCause[AIS_NCAUSE] = {
   { AIS_START,     "start" } ,
   { AIS_STATUS,    "status" } ,
   { AIS_STOP,      "stop" } ,
   { AIS_TIMEOUT,   "timeout" } ,
   { AIS_SHUTDOWN,  "shutdown" } ,
   { AIS_ERROR,     "error" } ,
   { AIS_OUTOFSPEC, "outofspec" } ,
   { AIS_INSPEC,    "inspec" } ,
};

struct ArgusTokenStruct RaSQLEventFacilities[AIS_NFACILITY] = {
   { AIS_AIS,       "ais" } ,
   { AIS_AISD,      "aisd" } ,
   { AIS_RADIUM,    "radium" } ,
   { AIS_RSVP,      "rsvp" } ,
   { AIS_ISIS,      "isis" } ,
   { AIS_USER,      "user" } ,
};

struct ArgusTokenStruct RaSQLEventSeverities[AIS_NSEVERITY] = {
   { 0,              "no" } ,
   { AIS_EMERG,    "emerg" } ,
   { AIS_ALERT,    "alert" } ,
   { AIS_CRIT,     "crit" } ,
   { AIS_ERR,      "err" } ,
   { AIS_WARNING,  "warn" } ,
   { AIS_NOTICE,   "notice" } ,
   { AIS_INFO,     "info" } ,
   { AIS_DEBUG,    "debug" } ,
};

#else

extern struct ArgusTokenStruct RaSQLEventTypes[AIS_NTYPES];
extern struct ArgusTokenStruct RaSQLEventCause[AIS_NCAUSE];
extern struct ArgusTokenStruct RaSQLEventFacilities[AIS_NFACILITY];
extern struct ArgusTokenStruct RaSQLEventSeverities[AIS_NSEVERITY];

#endif

#ifdef __cplusplus
}
#endif
#endif

