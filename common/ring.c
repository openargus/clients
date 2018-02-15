/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2017 QoSient, LLC
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
