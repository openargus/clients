/*
 * Argus-5.0 Software. Argus files - Events include files
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */

/*
 * $Id: //depot/gargoyle/clients/include/argus_events.h#4 $
 * $DateTime: 2015/04/13 00:39:28 $
 * $Change: 2980 $
 */


#define RA_STATUS_RETURN	0x01
#define RA_STATUS_DELTA		0x02

struct ArgusEventsStruct {
   int status;

#if defined(ARGUS_THREADS)
   pthread_t thread;
   pthread_mutex_t lock;
#endif

   struct ArgusListStruct *ArgusEventsList;
};

typedef int (*parseEventMethod)(void *, char *);

struct ArgusEventRecordStruct {
   struct ArgusListObjectStruct *nxt;
   struct timespec poptime, remaining;
   int status, interval;
   long long runs;

   char *entry;
   char *method;
   char *filename;
   char *db, *table;
   parseEventMethod parser;
   void *buf;
};
