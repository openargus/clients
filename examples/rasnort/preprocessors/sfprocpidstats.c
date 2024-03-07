/*
** $Id: sfprocpidstats.c,v 1.3 2003/10/20 15:03:37 chrisgreen Exp $
**
**  sfprocpidstats.c
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
#include "sfprocpidstats.h"

#ifdef LINUX_SMP

#include <stdlib.h>
#include <stdio.h>
#include <linux/param.h>
#include <sys/types.h>
#include <string.h>
#include <math.h>

#include "util.h"

#define PROC_STAT       "/proc/stat"
#define PROC_SELF_CPU   "/proc/self/cpu"
#define PROC_SELF_STAT  "/proc/self/stat"

typedef struct _USERSYS {
    u_long user;
    u_long sys;
    u_long idle;
} USERSYS;

static int giCPUs = 1;

static USERSYS *gpStatCPUs;
static USERSYS *gpStatCPUs_2;

static FILE *proc_stat;

static int GetProcStatCpu(USERSYS *pStatCPUs, int iCPUs)
{
    int iRet;
    int iCtr;
    u_long ulUser;
    u_long ulNice;
    u_long ulSys;
    u_long ulIdle;

    rewind(proc_stat);

    /*
    **  Read the total CPU usage, don't use right now.
    */
    iRet = fscanf(proc_stat, "%*s %*u %*u %*u %*u");
    if(iRet == EOF)
        return -1;

    /*
    **  Read the individual CPU usages.  This tells us where
    **  sniffing and snorting is occurring.
    */
    for(iCtr = 0; iCtr < iCPUs; iCtr++)
    {
        iRet = fscanf(proc_stat, "%*s %lu %lu %lu %lu",
                      &ulUser, &ulNice, &ulSys, &ulIdle);

        if(iRet == EOF || iRet < 4)
            return -1;

        pStatCPUs[iCtr].user = ulUser + ulNice;
        pStatCPUs[iCtr].sys  = ulSys;
        pStatCPUs[iCtr].idle = ulIdle;
    }

    return 0;
}

static int GetCpuNum()
{
    int iRet;
    int iCPUs = 0;
    char acCpuName[10+1];

    rewind(proc_stat);

    while(1)
    {
        iRet = fscanf(proc_stat, "%10s %*u %*u %*u %*u", acCpuName);
        if(iRet < 1 || iRet == EOF)
        {
            return 0;
        }

        acCpuName[sizeof(acCpuName)-1] = 0x00;
            
        if(strncmp(acCpuName, "cpu", 3))
        {
            break;
        }

        iCPUs++;
    }

    /*
    **  We subtract one here for the "total" combined CPU
    **  counter.
    */
    iCPUs--;

    return iCPUs;
}

int sfInitProcPidStats(SFPROCPIDSTATS *sfProcPidStats)
{
    proc_stat = fopen(PROC_STAT, "r");
    if(!proc_stat)
    {
        FatalError("PERFMONITOR ERROR: Can't open %s.", PROC_STAT);
    }

    giCPUs = GetCpuNum();
    if(giCPUs == 0)
    {
        FatalError("PERFMONITOR ERROR: Error reading CPUs from %s.",
                   PROC_STAT);
    }

    gpStatCPUs   = (USERSYS *)calloc(giCPUs, sizeof(USERSYS));
    if(!gpStatCPUs)
        FatalError("PERFMONITOR ERROR: Error allocating CPU mem.");

    gpStatCPUs_2 = (USERSYS *)calloc(giCPUs, sizeof(USERSYS));
    if(!gpStatCPUs_2)
        FatalError("PERFMONITOR ERROR: Error allocating CPU mem.");

    /*
    **  Allocate for sfProcPidStats CPUs
    */
    sfProcPidStats->SysCPUs = (CPUSTAT *)calloc(giCPUs, sizeof(CPUSTAT));
    if(!sfProcPidStats->SysCPUs)
        FatalError("PERFMONITOR ERROR: Error allocating SysCPU mem.");

    sfProcPidStats->iCPUs = giCPUs;

    if(GetProcStatCpu(gpStatCPUs, giCPUs))
        FatalError("PERFMONITOR ERROR: Error while reading '%s'.",
                PROC_STAT);

    fclose(proc_stat);

    return 0;
}

int sfProcessProcPidStats(SFPROCPIDSTATS *sfProcPidStats)
{
    static int iError = 0;
    int iCtr;
    u_long ulCPUjiffies;

    proc_stat = fopen(PROC_STAT, "r");
    if(!proc_stat)
    {
        if(!iError)
        {
            ErrorMessage("PERFMONITOR ERROR: Cannot open %s.", PROC_STAT);
            iError = 1;
        }

        return -1;
    }

    if(GetProcStatCpu(gpStatCPUs_2, giCPUs))
    {
        if(!iError)
        {
            ErrorMessage("PERFMONITOR ERROR: Error while reading '%s'.",
                    PROC_STAT);
            iError = 1;
        }

        return -1;
    }

    fclose(proc_stat);

    /*
    **  SysCPUs (The system's CPU usage, like top gives you)
    */
    for(iCtr = 0; iCtr < giCPUs; iCtr++)
    {
        ulCPUjiffies = (gpStatCPUs_2[iCtr].user - gpStatCPUs[iCtr].user) +
                       (gpStatCPUs_2[iCtr].sys - gpStatCPUs[iCtr].sys) +
                       (gpStatCPUs_2[iCtr].idle - gpStatCPUs[iCtr].idle);

        if(gpStatCPUs_2[iCtr].user > gpStatCPUs[iCtr].user)
        {
            sfProcPidStats->SysCPUs[iCtr].user = (((double)(gpStatCPUs_2[iCtr].user - 
                                                 gpStatCPUs[iCtr].user)) /
                                                 ulCPUjiffies) * 100.0;
            if(sfProcPidStats->SysCPUs[iCtr].user < .01)
            {
                sfProcPidStats->SysCPUs[iCtr].user = 0;
            }
        }
        else
        {
            sfProcPidStats->SysCPUs[iCtr].user = 0;
        }

        if(gpStatCPUs_2[iCtr].sys > gpStatCPUs[iCtr].sys)
        {
            sfProcPidStats->SysCPUs[iCtr].sys = (((double)(gpStatCPUs_2[iCtr].sys - 
                                                gpStatCPUs[iCtr].sys)) /
                                                ulCPUjiffies) * 100.0;
            if(sfProcPidStats->SysCPUs[iCtr].sys < .01)
            {
                sfProcPidStats->SysCPUs[iCtr].sys = 0;
            }
        }
        else
        {
            sfProcPidStats->SysCPUs[iCtr].sys = 0;
        }

        if(gpStatCPUs_2[iCtr].idle > gpStatCPUs[iCtr].idle)
        {
            sfProcPidStats->SysCPUs[iCtr].idle = (((double)(gpStatCPUs_2[iCtr].idle - 
                                                 gpStatCPUs[iCtr].idle)) /
                                                 ulCPUjiffies) * 100.0;
            if(sfProcPidStats->SysCPUs[iCtr].idle < .01)
            {
                sfProcPidStats->SysCPUs[iCtr].idle = 0;
            }
        }
        else
        {
            sfProcPidStats->SysCPUs[iCtr].idle = 0;
        }

        /*
        **  Set statistics for next processing.
        */
        gpStatCPUs[iCtr].user  = gpStatCPUs_2[iCtr].user;
        gpStatCPUs[iCtr].sys   = gpStatCPUs_2[iCtr].sys;
        gpStatCPUs[iCtr].idle  = gpStatCPUs_2[iCtr].idle;
    }

    return 0;
}

#endif

