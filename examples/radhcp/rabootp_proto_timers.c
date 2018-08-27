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

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <stdlib.h>
#include <syslog.h>
#include "argus_threads.h"
#include "argus_util.h"    /* needed by argus_client.h */
#include "argus_client.h"  /* ArgusLog() */
#include "argus_threads.h"
#include "argus_main.h"
#include "rabootp.h"
#include "rabootp_memory.h"
#include "rabootp_client_tree.h"
#include "rabootp_interval_tree.h"
#include "rabootp_patricia_tree.h"
#include "rabootp_proto_timers.h"

static const time_t RABOOTP_PROTO_TIMER_NONLEASE=10;
static const time_t RABOOTP_PROTO_TIMER_HOLDDOWN=30;
static const time_t RABOOTP_PROTO_TIMER_INTVLTREE=86400;
static const time_t RABOOTP_PROTO_TIMER_GC=10;

static const unsigned RABOOTP_PROTO_TIMER_GC_MAX = 128;
static struct argus_timer **gcarray;
static unsigned gcarraylen = 0;
static struct argus_timer *gctimer;


static ArgusTimerResult
__gctimer_cb(struct argus_timer *tim, struct timespec *ts)
{
   /* A "garbage collector" to free expired timers.  It's not safe
    * to free a timer from it's own expiration-callback because the
    * structure is referenced again by the timer library.
    */

   unsigned count = 0;
   struct timespec exp = {
      .tv_sec = RABOOTP_PROTO_TIMER_GC,
   };

   if (gcarraylen)
      DEBUGLOG(2, "%s removing %u\n", __func__, gcarraylen);

   while (count < gcarraylen) {
      free(*(gcarray+count));
      count++;
   }
   gcarraylen = 0;
   tim->expiry = exp;
   return RESCHEDULE_REL;
}

static void
__gc_schedule(struct argus_timer *tim)
{
   if (gcarraylen < RABOOTP_PROTO_TIMER_GC_MAX) {
      *(gcarray+gcarraylen) = tim;
      gcarraylen++;
   } else {
      /* free one to make room */
      free(*gcarray);
      *gcarray = tim;
   }
}

/* This function should only be called from the timer thread */
static ArgusTimerResult
__lease_exp_cb(struct argus_timer *tim, struct timespec *ts)
{
   int holddown_expired = 0;
   int remove_err;
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
   if (ads->timers.lease == tim) {
      if (ads->flags & ARGUS_DHCP_LEASEEXP) {
         holddown_expired = 1;
         ads->timers.lease = NULL;
         __gc_schedule(tim);

         /* remove from client tree here */
         remove_err = RabootpClientRemove(ads);

      } else {
         ads->flags |= ARGUS_DHCP_LEASEEXP;
         tim->expiry = exp;
         result = RESCHEDULE_REL;
      }
   }
   MUTEX_UNLOCK(ads->lock);

   if (holddown_expired) {
      /* decrement refcount -- client tree is done with this */
      if (remove_err == 0)
         ArgusDhcpStructFree(ads);

      /* decrement refcount -- lease timer does with this */
      ArgusDhcpStructFree(ads);
   }

   return result;
}

/* This function should only be called from the timer thread */
static ArgusTimerResult
__intvl_exp_cb(struct argus_timer *tim, struct timespec *ts)
{
   /* TODO: Don't call mutex functions here.  Add work item to queue
    * for a "bottom half" thread to handle so we don't block the timer
    * thread.
    */
   struct ArgusDhcpIntvlNode *intvlnode = tim->data;
   struct ArgusDhcpStruct *ads;
   int timer_removed = 0;
   int premove_err = 0;

   if (intvlnode == NULL)
      return FINISHED;

   ads = intvlnode->data;
   if (ads == NULL)
      goto cleanup;

   MUTEX_LOCK(ads->lock);
   if (ads->timers.intvl) {
      if (tim == ads->timers.intvl) {
         ads->timers.intvl = NULL;
         timer_removed = 1;
      }
   }

   if (!timer_removed)
      goto cleanup;

   MUTEX_LOCK(&ArgusParser->lock);
   premove_err = RabootpPatriciaTreeRemoveLease(&ads->rep.yiaddr.s_addr,
                                                ads->chaddr, ads->hlen,
                                                &intvlnode->intlo, ads, NULL);
   MUTEX_UNLOCK(&ArgusParser->lock);
   MUTEX_UNLOCK(ads->lock);

   if (premove_err == 0)
      /* decrement refcount -- patricia tree is done with this. */
      ArgusDhcpStructFree(ads);

   if (RabootpIntvlRemove(&intvlnode->intlo, ads) == 0)
      /* decrement refcount -- interval tree is done with this. */
      ArgusDhcpStructFree(ads);

   /* decrement refcount -- interval timer done with this */
   ArgusDhcpStructFree(ads);

cleanup:
   ArgusFree(intvlnode);
   __gc_schedule(tim);

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
 */
static int
RabootpProtoTimersLeaseSet(const void * const v_parsed,
                           void *v_cached,
                           void *v_arg)
{
   const struct ArgusDhcpStruct * const parsed = v_parsed;
   struct ArgusDhcpStruct *cached = v_cached;
   struct ArgusDhcpIntvlNode *intvlnode;

   /* did we just transition to the BOUND state? */
   if (parsed->state == BOUND && cached->state != BOUND) {
      struct RabootpTimerStruct *rts = v_arg;
      struct timespec exp_lease = {
         .tv_sec = parsed->rep.leasetime,
      };
      struct timespec exp_intvl = {
         .tv_sec = parsed->rep.leasetime + RABOOTP_PROTO_TIMER_INTVLTREE,
      };

      cached->flags &= ~ARGUS_DHCP_LEASEEXP;
      if (cached->timers.lease) {
          RabootpTimerStop(rts, cached->timers.lease);
          free(cached->timers.lease);
      } else {
         ArgusDhcpStructUpRef(cached); /* up once for the lease timer */
      }
      cached->timers.lease = RabootpTimerStart(rts, &exp_lease, __lease_exp_cb,
                                               cached);

      intvlnode = ArgusCalloc(1, sizeof(*intvlnode));
      if (intvlnode) {
         if (cached->timers.intvl) {
            RabootpTimerStop(rts, cached->timers.intvl);
            free(cached->timers.intvl);
          } else {
            /* up again for the interval timer */
            ArgusDhcpStructUpRef(cached);
         }
         intvlnode->data = cached;
         intvlnode->intlo = cached->first_bind;
         cached->timers.intvl = RabootpTimerStart(rts, &exp_intvl, __intvl_exp_cb,
                                                  intvlnode);
      }
   }

   return 0;
}


/* This function changes the contents of the cached transaction and should
 * only be called from the main/parse thread
 *
 * Add this function to the XIDDELETE callback list.
 *
 * PREREQ: calling function must hold reference to v_cached
 *         (must have incremented refcount) so that the reference
 *         count can safely be incremented here without holding the
 *         client tree lock!!!  Caller must hold v_cached->lock.
 *
 */
static int
RabootpProtoTimersHolddownSet(const void * const v_parsed,
                              void *v_cached,
                              void *v_arg)
{
   const struct ArgusDhcpStruct * const parsed = v_parsed;
   struct ArgusDhcpStruct *cached = v_cached;
   struct RabootpTimerStruct *rts = v_arg;
   struct ArgusDhcpIntvlNode *intvlnode;
   struct timespec exp_lease = {
      .tv_sec = RABOOTP_PROTO_TIMER_HOLDDOWN,
   };
   struct timespec exp_intvl = {
      .tv_sec = RABOOTP_PROTO_TIMER_INTVLTREE,
   };

   if (__mask2type(parsed->msgtypemask) != DHCPRELEASE)
      return 0;

   if (cached->flags & ARGUS_DHCP_LEASEREL)
      return 0;

   if (cached->timers.lease) {
      RabootpTimerStop(rts, cached->timers.lease);
      free(cached->timers.lease);
   } else {
      ArgusDhcpStructUpRef(cached); /* up once for the lease timer */
   }

   cached->flags |= ARGUS_DHCP_LEASEREL;
   cached->timers.lease = RabootpTimerStart(rts, &exp_lease, __lease_exp_cb,
                                            cached);

   intvlnode = ArgusCalloc(1, sizeof(*intvlnode));
   if (intvlnode) {
      if (cached->timers.intvl) {
         RabootpTimerStop(rts, cached->timers.intvl);
         free(cached->timers.intvl);
       } else {
         /* up again for the interval timer */
         ArgusDhcpStructUpRef(cached);
      }
      intvlnode->data = cached;
      intvlnode->intlo = cached->first_bind;
      cached->timers.intvl = RabootpTimerStart(rts, &exp_intvl,
                                               __intvl_exp_cb, intvlnode);
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
   if (ads->timers.non_lease == tim) {
      have_timer = 1;
      ads->timers.non_lease = NULL;
      if (ads->state == BOUND || ads->state == REBINDING ||
          ads->state == RENEWING)
         bound = 1;
   }
   MUTEX_UNLOCK(ads->lock);

   if (!have_timer)
      goto out;

   /* decrement refcount -- timer tree is done with this. */
   ArgusDhcpStructFree(ads);

   if (!bound) {
      /* remove from client tree here */
      if (RabootpClientRemove(ads) == 0)
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
   struct ArgusDhcpStruct *cached = v_cached;
   struct RabootpTimerStruct *rts = v_arg;

   /* If this lease has ever been in the bound state, make sure
    * the discovery timer has been stopped.
    */
   if (cached->last_bind.tv_sec || cached->last_bind.tv_usec) {
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
   unsigned const gclen = sizeof(*gcarray) * RABOOTP_PROTO_TIMER_GC_MAX;
   struct timespec exp = {
      .tv_sec = RABOOTP_PROTO_TIMER_GC,
   };

   RabootpCallbackRegister(CALLBACK_STATECHANGE,
                           RabootpProtoTimersLeaseSet, rts);
   RabootpCallbackRegister(CALLBACK_XIDUPDATE,
                           RabootpProtoTimersNonleaseSet, rts);
   RabootpCallbackRegister(CALLBACK_XIDNEW,
                           RabootpProtoTimersNonleaseSet, rts);
   RabootpCallbackRegister(CALLBACK_XIDDELETE,
                           RabootpProtoTimersHolddownSet, rts);

   gcarray = ArgusMallocAligned(gclen, 64);
   if (gcarray == NULL)
      ArgusLog(LOG_ERR, "%s: Unable to allocate garbage collection array\n",
               __func__);

   if (RabootpTimerLock(rts) == 0) {
      gctimer = RabootpTimerStart(rts, &exp, __gctimer_cb, NULL);
      RabootpTimerUnlock(rts);
   }
}

void RabootpProtoTimersCleanup(struct RabootpTimerStruct *rts)
{
   RabootpCallbackUnregister(CALLBACK_STATECHANGE, RabootpProtoTimersLeaseSet);
   RabootpCallbackUnregister(CALLBACK_XIDUPDATE, RabootpProtoTimersNonleaseSet);
   RabootpCallbackUnregister(CALLBACK_XIDNEW, RabootpProtoTimersNonleaseSet);
   RabootpCallbackUnregister(CALLBACK_XIDDELETE, RabootpProtoTimersHolddownSet);
   RabootpTimerStop(rts, gctimer);
   ArgusFree(gcarray);
   gcarray = NULL;
   free(gctimer);
   gctimer = NULL;
}
