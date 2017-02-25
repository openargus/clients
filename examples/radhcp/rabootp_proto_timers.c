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
 */

/*
 * This file contains routines, executed as callbacks from the parser,
 * that manage the DHCP lease timer and also a radhcp-specific timer
 * to indicate when a transaction structure for an expired/relinquished
 * lease should be dropped from the tree.  These are kept around for a
 * while after expiration for use by streaming analytics.
 */

#include "rabootp.h"

/* This function should only be called from the timer thread */
static ArgusTimerResult
__lease_exp_cb(struct argus_timer *tim, struct timespec *ts)
{
   /* TODO: add transaction to expired queue for main thread to find */
   return FINISHED;
}

/* This function changes the contents of the cached transaction and shoud
 * only be called from the main/parse thread
 */
static int
RabootpProtoTimersLeaseSet(const void * const v_parsed,
                           void *v_cached,
                           void *v_arg)
{
   const struct ArgusDhcpStruct * const parsed = v_parsed;
   struct ArgusDhcpStruct *cached = v_cached;

   /* did we just transition to the BOUND state? */
   if (parsed->state == BOUND && cached->state != BOUND) {
      struct RabootpTimerStruct *rts = v_arg;
      struct timespec exp = {
         .tv_sec = parsed->rep.leasetime,
      };

      cached->timers.lease = RabootpTimerStart(rts, &exp, __lease_exp_cb,
                                               cached);
   }

   return 0;
}

void RabootpProtoTimersInit(struct RabootpTimerStruct *rts)
{
   RabootpCallbackRegister(CALLBACK_STATECHANGE,
                           RabootpProtoTimersLeaseSet, rts);
}

void RabootpProtoTimersCleanup(void)
{
   RabootpCallbackUnregister(CALLBACK_STATECHANGE, RabootpProtoTimersLeaseSet);
}
