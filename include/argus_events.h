/*
 * Gargoyle Software. Argus files - Events include files
 * Copyright (c) 2000-2015 QoSient, LLC
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
