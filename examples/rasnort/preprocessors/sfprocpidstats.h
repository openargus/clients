/*
** $Id: sfprocpidstats.h,v 1.3 2003/10/20 15:03:37 chrisgreen Exp $
**
** sfprocpidstats.h
**
** Copyright (C) 2002 Sourcefire,Inc
** Dan Roelker <droelker@sourcefire.com>
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
**
**  DESCRIPTION
**    This file gets the correct CPU usage for SMP linux machines.
**
*/
#ifndef __SFPROCPIDSTATS__
#define __SFPROCPIDSTATS__

#ifdef LINUX_SMP

typedef struct _CPUSTAT {
    
    double user;
    double sys;
    double total;
    double idle;

} CPUSTAT;

typedef struct _SFPROCPIDSTATS {
    
    CPUSTAT *SysCPUs;

    int iCPUs;
    
} SFPROCPIDSTATS;

int sfInitProcPidStats(SFPROCPIDSTATS *sfProcPidStats);
int sfProcessProcPidStats(SFPROCPIDSTATS *sfProcPidStats);

#endif

#endif
