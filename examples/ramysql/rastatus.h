/*
 * Argus-5.0 Software. Argus files - Events include files
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
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/gargoyle/argus/argus/ArgusEvents.h#4 $
 * $DateTime: 2015/04/13 00:39:28 $
 * $Change: 2980 $
 */


#ifndef ArgusEvents_h
#define ArgusEvents_h

#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#if defined(__NetBSD__)
#include <sys/sched.h>
#else
#include <sched.h>
#endif

#include <fcntl.h>
#include <signal.h>

#if defined(ARGUS_TILERA)
#include <argus_tilera.h>
#endif

#include <argus_def.h>
#include <argus_filter.h>

#ifdef ARGUS_SASL
#include <sasl/sasl.h>
#endif

#define ARGUS_EVENT_OS_STATUS	0x00000001
#define ARGUS_ZLIB_COMPRESS	0x00000001
#define ARGUS_ZLIB_COMPRESS2	0x00000002


#if defined(ArgusEvents)
struct ArgusEventsStruct *ArgusEventsTask = NULL;
void ArgusInitEvents (struct ArgusEventsStruct *);
void ArgusCloseEvents (struct ArgusEventsStruct *);
int ArgusSortEventList (const void *, const void *);
struct ArgusEventsStruct *ArgusNewEvents (void);

#define RA_NUMTABLES            5
#define RA_NUMTABLES_MASK       0x001F
#define RA_MAXTABLES            0x100

char *RaTableValues[256];
char *RaExistsTableNames[RA_MAXTABLES];
char *RaRoleString = NULL;

int RaProjectExists = 0;

char *RaCreateTableNames[RA_NUMTABLES] = {
   "site_cpu_status",
   "site_disk_status",
   "site_loadavg_status",
   "site_mem_status",
   "site_logs_status",
};

char *RaTableCreationString[RA_NUMTABLES] = {
   "CREATE TABLE `site_cpu_status` ( `stime` double(18,6) DEFAULT NULL, `name` varchar(8) DEFAULT NULL, `system` bigint(1) unsigned DEFAULT NULL, `idle` bigint(1) unsigned DEFAULT NULL, `irq` bigint(1) unsigned DEFAULT NULL, `iowait` bigint(1) unsigned DEFAULT NULL, `nice` bigint(1) unsigned DEFAULT NULL, `user` bigint(1) unsigned DEFAULT NULL, `softirq` bigint(1) unsigned DEFAULT NULL) ENGINE=InnoDB DEFAULT CHARSET=latin1;",

   "CREATE TABLE `site_disk_status` ( `stime` double(18,6) DEFAULT NULL, `name` varchar(32) DEFAULT NULL, `reads` bigint(1) unsigned DEFAULT NULL, `writes` bigint(1) unsigned DEFAULT NULL, `secread` bigint(1) unsigned DEFAULT NULL, `secwrite` bigint(1) unsigned DEFAULT NULL) ENGINE=InnoDB DEFAULT CHARSET=latin1;",

   "CREATE TABLE `site_loadavg_status` ( `stime` double(18,6) DEFAULT NULL, `1minAvg` float DEFAULT NULL, `5minAvg` float DEFAULT NULL, `15minAvg` float DEFAULT NULL, `procs` varchar(16) DEFAULT NULL) ENGINE=InnoDB DEFAULT CHARSET=latin1;",

   "CREATE TABLE `site_mem_status` ( `stime` double(18,6) DEFAULT NULL, `MemTotal` bigint(1) unsigned DEFAULT NULL, `MemAvailable` bigint(1) unsigned DEFAULT NULL, `MemFree` bigint(1) unsigned DEFAULT NULL, `Cached` bigint(1) unsigned DEFAULT NULL, `Buffers` bigint(1) unsigned DEFAULT NULL, `SwapTotal` bigint(1) unsigned DEFAULT NULL, `SwapFree` bigint(1) unsigned DEFAULT NULL, `SwapCached` bigint(1) unsigned DEFAULT NULL) ENGINE=InnoDB DEFAULT CHARSET=latin1;",

   "CREATE TABLE `site_logs_status` ( `stime` double(18,6) unsigned NOT NULL, `emerg` bigint(1) unsigned DEFAULT NULL, `alert` bigint(1) unsigned DEFAULT NULL, `crit` bigint(1) unsigned DEFAULT NULL, `error` bigint(1) unsigned DEFAULT NULL, `warn` bigint(1) unsigned DEFAULT NULL, `notice` bigint(1) unsigned DEFAULT NULL, `info` bigint(1) unsigned DEFAULT NULL, `debug` bigint(1) unsigned DEFAULT NULL, PRIMARY KEY (`stime`)) ENGINE=InnoDB DEFAULT CHARSET=utf8;",
};

#define RA_MAXSQLQUERY          8
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


#else
extern struct ArgusEventsStruct *ArgusEventsTask;
extern void ArgusInitEvents (struct ArgusEventsStruct *);
extern void ArgusCloseEvents (struct ArgusEventsStruct *);
extern int ArgusSortEventList (const void *, const void *);
extern struct ArgusEventsStruct *ArgusNewEvents (void);

extern char *RaCreateTableNames[];
extern char *RaTableCreationString[];
extern char *RaTableQueryString[];

#endif
#endif /* #ifndef ArgusEvents_h */

