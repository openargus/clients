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
 * $Id: //depot/argus/clients/examples/ramysql/rasqltimeindex.h#8 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

/*  rasqltimeindex.h */

#ifndef RaSQLTimeIndex_h
#define RaSQLTimeIndex_h

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <ctype.h>
#include <stdarg.h>

#include <argus_util.h>
#include <argus_parser.h>

#define MAX_OBJ_SIZE            1024

#ifndef MAXSTRLEN
#define MAXSTRLEN		1024
#endif

#ifndef MAXPATHNAMELEN
#define MAXPATHNAMELEN		BUFSIZ
#endif

#define RATIME_PROBE		1
#define RATIME_TIMEVAL		2
#define RATIME_TIMEVAL_SEC	3
#define RATIME_TIMEVAL_USEC	4

MYSQL mysql;
MYSQL_ROW row;
MYSQL_RES *mysqlRes;

char *MDFile(char *);

int RaInitialized = 0;
struct ArgusListStruct *RaTimeIndexList = NULL;
unsigned int RaStartTime = 0xFFFFFFFF, RaEndTime = 0;

struct RaQueueStruct *RaProbeQueue = NULL;
char *RaProbe = NULL;

struct RaTimeHashTableStruct {
   int size, count;
   struct RaTimeHashTableHeader **array;
};

struct RaTimeHashTableHeader {
   struct RaTimeHashTableHeader *nxt, *prv;
   unsigned int hash;
   int type, len, value;
   void *obj;
   struct timeval time;
   int minoffset, maxoffset;
};

struct RaTimeProbesStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusHashTable *htable;
   struct RaTimeHashTableStruct *rtable;
   struct ArgusQueueStruct *queue;
   struct ArgusRecordStruct *tn;
   unsigned int probeid;
};

struct RaTimeProbesStruct *ArgusProbes = NULL;
struct RaTimeHashTableStruct *RaTimeHashTable = NULL;
struct ArgusQueueStruct *ArgusTimeQueue = NULL;


unsigned int RaTimeCalcHash (struct RaTimeHashTableStruct *, void *, int, int *);
struct RaTimeHashTableHeader *RaTimeFindHashObject (struct RaTimeHashTableStruct *, void *, int, int *);
struct RaTimeHashTableHeader *RaTimeAddHashEntry (struct RaTimeHashTableStruct *, void *, int, int *);
void RaTimeRemoveHashEntry (struct RaTimeHashTableStruct *, struct RaTimeHashTableHeader *);

FILE *ArgusArchiveFileIndex = NULL;
char ArgusArchiveBuf[MAXPATHNAMELEN], *ArgusArchivePath = NULL;

int RaCheckArchiveIndexes(char *);
int RaGetFileIndex(char *, char *);


#define RA_NUMTABLES            3
#define RA_NUMTABLES_MASK       0x0007
#define RA_MAXTABLES            0x100

 
char *RaTableValues[256];
char *RaExistsTableNames[RA_MAXTABLES];
char *RaRoleString = NULL;
 
int RaProjectExists = 0;
 
char *RaCreateTableNames[RA_NUMTABLES] = {
   "Filename",
   "Seconds",
   "Probes",
};
 
char *RaTableCreationString[RA_NUMTABLES] = {
   "CREATE TABLE Filename (id int not null auto_increment, filename varchar(255) not null, size int unsigned, creation int unsigned , hmac varchar(64), start int unsigned, stop int unsigned, indexed int unsigned, primary key (id))",
   "CREATE TABLE Seconds (probe int unsigned not null, second int unsigned not null, fileindex int not null, ostart int unsigned not null, ostop int unsigned not null, KEY secondprobeKey(second, probe))",
   "CREATE TABLE Probes (id int not null auto_increment, name varchar(32) not null, url varchar(255) not null, type varchar(255), filter varchar(255), authname varchar(255), authpass varchar(255), description varchar(255), access timestamp(14), created timestamp(14), start timestamp(14), stop timestamp(14), status int unsigned, primary key (id))",
};

#define RA_MAXSQLQUERY		8
char *RaTableQueryString[RA_MAXSQLQUERY] = {
   "SELECT id, indexed from Filename WHERE filename = \"%s\"",
   "INSERT Filename (filename, size, creation, hmac, start, stop, indexed) VALUES (\"%s\", %d, %d, \"%s\", %d, %d, 1)",
   "SELECT id, indexed from Filename WHERE filename = \"%s\"",
   "INSERT INTO Seconds VALUES ",
   "UPDATE Filename set indexed=1 where id=%d",
   "UPDATE Filename set indexed=2 where id=%d",
   "SELECT id from Probes where name=\"%s\"",
   "INSERT Probes (name) VALUES (\"%s\")",
};


#if defined(RaTime)


#else /* defined(RaTime) */


#endif /* defined(RaTime) */
#endif /* RaTime_h */

