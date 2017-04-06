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

#include <stdlib.h>
#include "argus_threads.h"
#include "rabootp.h"
#include "rabootp_memory.h"
#include "rabootp_client_tree.h"

static const time_t RABOOTP_PROTO_TIMER_NONLEASE=10;
static const time_t RABOOTP_PROTO_TIMER_HOLDDOWN=30;

/* This function should only be called from the timer thread */
static ArgusTimerResult
__lease_exp_cb(struct argus_timer *tim, struct timespec *ts)
{
   int holddown_expired = 0;
   int result = FINISHED;
   struct timespec exp = {
      .tv_sec = RABOOTP_PROTO_TIMER_HOLDDOWN,
   };

   /* TODO: Don't call mutex functions here.  Add work item to queue
    * for a "bottom half" thread to handle so we don't block the timer
    * thread.
    */

   struct ArgusDhcpStruct *ads = tim->data;
   MUTEX_LOCK(ads->lock);
   if (ads->flags & ARGUS_DHCP_LEASEEXP) {
      holddown_expired = 1;
   } else {
      free(ads->timers.lease);
      ads->flags |= ARGUS_DHCP_LEASEEXP;
      ads->timers.lease = NULL;
      *ts = exp;
      result = RESCHEDULE_REL;
   }
   MUTEX_UNLOCK(ads->lock);

   if (holddown_expired)
      ArgusDhcpStructFree(ads);

   return result;
}

/* This function changes the contents of the cached transaction and should
 * only be called from the main/parse thread
 *
 * PREREQ: calling function must hold reference to v_cached
 *         (must have incremented refcount) so that the reference
 *         count can safely be incremented here without holding the
 *         client tree lock!!!  Caller must hold v_cached->lock.
 *
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

      ArgusDhcpStructUpRef(cached);
      cached->flags &= ~ARGUS_DHCP_LEASEEXP;
      if (cached->timers.lease)
          RabootpTimerStop(rts, cached->timers.lease);
      cached->timers.lease = RabootpTimerStart(rts, &exp, __lease_exp_cb,
                                               cached);
   }

   return 0;
}

/* This function should only be called from the timer thread */
static ArgusTimerResult
__discover_exp_cb(struct argus_timer *tim, struct timespec *ts)
{
   /*
    * TODO: Don't call mutex functions here.  Add work item to queue
    * for a "bottom half" thread to handle so we don't block the timer
    * thread.
    */

   struct ArgusDhcpStruct *ads = tim->data;
   int bound = 0;
   int have_timer = 0; /* avoid race with RabootpProtoTimersNonleaseSet() */

   MUTEX_LOCK(ads->lock);
   if (ads->timers.non_lease) {
      have_timer = 1;
      ads->timers.non_lease = NULL;
      if (ads->state == BOUND)
         bound = 1;
   }
   MUTEX_UNLOCK(ads->lock);

   if (!have_timer)
      goto out;

   /* decrement refcount -- timer tree is done with this. */
   ArgusDhcpStructFree(ads);

   if (!bound) {
      /* remove from client tree here */
      RabootpClientRemove(ads);
      /* decrement refcount -- client tree is done with this. */
      ArgusDhcpStructFree(ads);
   }

out:
   return FINISHED;
}

/* This function changes the contents of the cached transaction and should
 * only be called from the main/parse thread
 *
 * PREREQ: calling function must hold reference to v_cached
 *         (must have incremented refcount) so that the reference
 *         count can safely be incremented here without holding the
 *         client tree lock!!!  Caller must hold v_cached->lock.
 *
 * RabootpProtoTimersNonleaseSet starts a timer when a message that
 * does not bind or "un-bind" a lease is sent by the client.  A
 * response to that message from a server should stop the timer.
 *
 */
static int RabootpProtoTimersNonleaseSet(const void * const v_parsed,
			      void *v_cached, void *v_arg)
{
   const struct ArgusDhcpStruct * const parsed = v_parsed;
   struct ArgusDhcpStruct *cached = v_cached;
   struct RabootpTimerStruct *rts = v_arg;

   if (cached->state == BOUND) {
      if (cached->timers.non_lease) {
         RabootpTimerStop(rts, cached->timers.non_lease);
         free(cached->timers.non_lease);
         cached->timers.non_lease = NULL;

         /* decrement refcount -- timer tree is done with this. */
         ArgusDhcpStructFree(cached);

      }
   } else {
      struct timespec exp = {
         .tv_sec = RABOOTP_PROTO_TIMER_NONLEASE,
      };

      /* Otherwise, if we send or receive any kind of message and
       * are still not BOUND, set/reset the timer
       */

      if (cached->timers.non_lease) {
         RabootpTimerStop(rts, cached->timers.non_lease);
         free(cached->timers.non_lease);
      } else {
         ArgusDhcpStructUpRef(cached);
      }
      cached->timers.non_lease = RabootpTimerStart(rts, &exp, __discover_exp_cb,
                                                   cached);
   }

   return 0;
}

void RabootpProtoTimersInit(struct RabootpTimerStruct *rts)
{
   RabootpCallbackRegister(CALLBACK_STATECHANGE,
                           RabootpProtoTimersLeaseSet, rts);
   RabootpCallbackRegister(CALLBACK_XIDUPDATE,
                           RabootpProtoTimersNonleaseSet, rts);
   RabootpCallbackRegister(CALLBACK_XIDNEW,
                           RabootpProtoTimersNonleaseSet, rts);
}

void RabootpProtoTimersCleanup(void)
{
   RabootpCallbackUnregister(CALLBACK_STATECHANGE, RabootpProtoTimersLeaseSet);
   RabootpCallbackUnregister(CALLBACK_XIDUPDATE, RabootpProtoTimersNonleaseSet);
   RabootpCallbackUnregister(CALLBACK_XIDNEW, RabootpProtoTimersNonleaseSet);
}
