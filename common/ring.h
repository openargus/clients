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

#ifndef __ARGUS_RING_H
# define __ARGUS_RING_H
# ifdef HAVE_CONFIG_H
# include "argus_config.h"
# endif
# include <string.h>
# include <strings.h>

# define ARGUS_RINGBUFFER_MAX 0x200
# define ARGUS_RINGBUFFER_MASK 0x1ff

struct RingBuffer {
   char *Buffer;        /* must be power of 2 in size */
   unsigned CrbHead;    /* offset into Buffer */
   unsigned CrbTail;    /* offset into Buffer */
};

int RingAlloc(struct RingBuffer *);
void RingFree(struct RingBuffer *);
char *RingDequeue(struct RingBuffer * const);

static inline __attribute__((always_inline))
unsigned
RingAvail(const struct RingBuffer * const ring)
{
   unsigned avail;

   if (ring->CrbTail > ring->CrbHead)
      avail = ARGUS_RINGBUFFER_MAX - (ring->CrbTail - ring->CrbHead);
   else if (ring->CrbTail < ring->CrbHead)
      avail = (ring->CrbHead - ring->CrbTail);
   else
      avail = ARGUS_RINGBUFFER_MAX;

   return avail;
}

/* return 1 if null terminated string found */
static inline __attribute__((always_inline))
int
RingNullTerm(const struct RingBuffer * const ring)
{
   unsigned loc = ring->CrbTail;

   while (loc != ring->CrbHead) {
      if (ring->Buffer[loc] == 0)
         return 1;
      loc = (loc - 1) % ARGUS_RINGBUFFER_MAX;
   }

   return 0;
}

static inline __attribute__((always_inline))
void
RingAdvance(unsigned * const headtail, unsigned count)
{
   *headtail = (*headtail + count) % ARGUS_RINGBUFFER_MAX;
}

static inline __attribute__((always_inline))
int
RingEnqueue(struct RingBuffer *ring, char *buf,
            unsigned buflen)
{
   if (buflen > RingAvail(ring))
      return -1;

   if ((ring->CrbTail + buflen) <= ARGUS_RINGBUFFER_MAX) {
      /* This is the most likely case.  Handle it first. */
      bcopy(buf, &ring->Buffer[ring->CrbTail], buflen);
   } else {
      /* write to buffer will wrap around */
      unsigned first = ARGUS_RINGBUFFER_MAX - ring->CrbTail;

      bcopy(buf, &ring->Buffer[ring->CrbTail], first);
      bcopy(buf + first, ring->Buffer, (unsigned)buflen - first);
   }
   RingAdvance(&ring->CrbTail, buflen);
   return 0;
}

static inline __attribute__((always_inline))
unsigned
RingBytesUntilWrap(const struct RingBuffer * const ring)
{
   return ARGUS_RINGBUFFER_MAX - ring->CrbHead;
}

static inline __attribute__((always_inline))
unsigned
RingOccupancy(const struct RingBuffer * const ring)
{
   return ARGUS_RINGBUFFER_MAX - RingAvail(ring);
}

static inline __attribute__((always_inline))
const char * const
RingHeadPtr(const struct RingBuffer * const ring)
{
   return ring->Buffer + ring->CrbHead;
}
#endif
