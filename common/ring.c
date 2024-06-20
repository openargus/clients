/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2017-2024 QoSient, LLC
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
 */

#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif
#include <sys/syslog.h>
#include "argus_util.h"
#include "argus_client.h"
#include "ring.h"

int
RingAlloc(struct RingBuffer *r)
{
   /* allocate one extra byte so there is always a terminating null for
    * safety
    */

   r->Buffer = ArgusCalloc(1, ARGUS_RINGBUFFER_MAX + 1);
   if (r->Buffer == NULL)
      return -1;

   r->CrbHead = r->CrbTail = 0;
   return 0;
}

void
RingFree(struct RingBuffer *r)
{
   if (r->Buffer)
      ArgusFree(r->Buffer);
}

/* results of RingDequeue() are undefined if !RingNullTerm(r) */
char *
RingDequeue(struct RingBuffer * const r)
{
   char *tmp;
   unsigned next_null;
   unsigned slen;

   if (r->CrbTail == r->CrbHead)
      return NULL;

   slen = 0;
   next_null = r->CrbHead;
   while (next_null != r->CrbTail && *(r->Buffer + next_null) != '\0') {
      RingAdvance(&next_null, 1);
      slen++;
   }

   slen++; /* make room for the terminating null */
   tmp = ArgusMalloc(slen);
   if (tmp == NULL)
      ArgusLog(LOG_ERR, "%s: Unable to allocate temporary buffer\n",
               __func__);

   if (next_null > r->CrbHead) {
      bcopy(RingHeadPtr(r), tmp, slen);
   } else {
      unsigned bytes_until_wrap = RingBytesUntilWrap(r);

      bcopy(RingHeadPtr(r), tmp, bytes_until_wrap);
      bcopy(r->Buffer, tmp + bytes_until_wrap, next_null+1);
   }

   /* Skip over extra nulls at the end of the string, if any */
   while (next_null != r->CrbTail && *(r->Buffer + next_null) == '\0')
      RingAdvance(&next_null, 1);
   r->CrbHead = next_null;

   return tmp;
}
