/*
** $Id: perf-base.h,v 1.2 2003/10/20 15:03:37 chrisgreen Exp $
**
** perf-base.h
**
** Copyright (C) 2002 Sourcefire,Inc
** Dan Roelker (droelker@sourcefire.com)
** Marc Norton (mnorton@sourcefire.com)
** Chris Green (stream4 instrumentation)
**
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/
#ifndef _PERFBASE_H
#define _PERFBASE_H

#include "sfprocpidstats.h"
#include "sfutil/mpse.h"

#include <time.h>

#define MAX_PERF_STATS 1

typedef struct _PKTSTATS {

    UINT64 pkts_recv;
    UINT64 pkts_drop;

}  PKTSTATS;

typedef struct _SFBASE {

    UINT64   total_packets;
    UINT64   total_wire_bytes;
    UINT64   total_rebuilt_bytes;

    PKTSTATS pkt_stats;

    double   usertime_sec;
    double   systemtime_sec;
    double   realtime_sec;

    time_t time;

    UINT64   iAlerts;
    UINT64   iSyns;      /* SYNS != Connections */
    UINT64   iSynAcks;   /* better estimator  */
    UINT64   iTotalSessions;
    UINT64   iNewSessions;
    UINT64   iDeletedSessions;
    UINT64   iMaxSessions;

    UINT64   iStreamFlushes;  /* # of fake packet is flushed */
    UINT64   iStreamFaults;  /* # of times we run out of memory */
    UINT64   iStreamTimeouts; /* # of timeouts we get in this quanta */
    
    UINT64   iFragCompletes;  /* # of times we call FragIsComplete() */
    UINT64   iFragInserts;    /* # of fraginserts */
    UINT64   iFragDeletes;    /* # of fraginserts */
    UINT64   iFragFlushes;    
    UINT64   iFragTimeouts;   /* # of times we've reached timeout */
    UINT64   iFragFaults;     /* # of times we've run out of memory */    

    int      iFlags;

#ifdef LINUX_SMP
    SFPROCPIDSTATS sfProcPidStats;
#endif

}  SFBASE;

typedef struct _SYSTIMES {

    double usertime;
    double systemtime;
    double totaltime;
    double realtime;

}  SYSTIMES;

typedef struct _SFBASE_STATS {

    UINT64   total_packets;
    UINT64   total_sessions;
    UINT64   max_sessions;
    SYSTIMES kpackets_per_sec;
    SYSTIMES usecs_per_packet;
    SYSTIMES wire_mbits_per_sec;
    SYSTIMES rebuilt_mbits_per_sec;
    SYSTIMES mbits_per_sec;
    int      avg_bytes_per_packet;
    double   idle_cpu_time;
    double   user_cpu_time;
    double   system_cpu_time;
    PKTSTATS pkt_stats;
    double   pkt_drop_percent; 
    double   alerts_per_second;
    double   syns_per_second;
    double   synacks_per_second;
    double   deleted_sessions_per_second;
    double   new_sessions_per_second;

    double stream_flushes_per_second;
    UINT64 stream_faults;
    UINT64 stream_timeouts;

    double frag_completes_per_second;
    double frag_inserts_per_second;
    double frag_deletes_per_second;
    double frag_flushes_per_second;
    UINT64 frag_timeouts;
    UINT64 frag_faults;
    
    double   patmatch_percent;
    time_t   time;

#ifdef LINUX_SMP
    SFPROCPIDSTATS *sfProcPidStats;
#endif

}  SFBASE_STATS;

int InitBaseStats(SFBASE *sfBase);
int UpdateBaseStats(SFBASE *sfBase, int len, int iRebuiltPkt);
int ProcessBaseStats(SFBASE *sfBase,int console, int file, FILE * fh);
int AddStreamSession(SFBASE *sfBase);
int RemoveStreamSession(SFBASE *sfBase);
     
#endif


