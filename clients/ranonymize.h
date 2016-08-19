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
*
 * $Id: //depot/argus/clients/clients/ranonymize.h#12 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

/*  ranonymize.h */

#ifndef RaMap_h
#define RaMap_h

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <argus_ethertype.h>

#include <signal.h>
#include <ctype.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <stdarg.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <net/if.h>

#include <netinet/if_ether.h>


#ifndef MAXSTRLEN
#define MAXSTRLEN		1024
#endif


#ifndef MAXPATHNAMELEN
#define MAXPATHNAMELEN		BUFSIZ
#endif


#if defined(RaMap)

void RaMapInit (void);
void RaMapShutDown (void);

int RaMapParseConversionFile (char *);
void RaMapInventory(void *, int, int);

#else /* defined(RaMap) */

extern void RaMapInit (void);
extern void RaMapShutDown (void);

int RaMapParseConversionFile (char *);
extern void RaMapInventory(void *, int, int);

#endif /* defined(RaMap) */
#endif /* RaMap_h */

