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

/*
 * Argus-5.0 timer library
 * Eric Kinzie <eric@qosient.com>
 *
 */

#pragma GCC diagnostic ignored "-Wunused-function"

#include <stdlib.h>
#include <errno.h>
#include "argus_config.h"
#include "argus_timer.h"
#include "argus_util.h"

unsigned missed = 0;
unsigned replayed = 0;
unsigned recovered = 0;

static int
__argus_timer_compare(struct argus_timer *a, struct argus_timer *b)
{
   struct timespec result;

   result.tv_sec = a->expiry.tv_sec - b->expiry.tv_sec;
   result.tv_nsec = a->expiry.tv_nsec - b->expiry.tv_nsec;
   if (result.tv_nsec < 0) {
      --result.tv_sec;
      result.tv_nsec += 1000000000;
   }
   if (result.tv_sec < 0)
      return -1;
   if (result.tv_sec > 0)
      return 1;

   /* times are the same.  compare distinguishers */
   if (a->td < b->td)
      return -1;
   if (a->td > b->td)
      return 1;
   return 0;
}

RB_GENERATE_STATIC(argus_timer_tree, argus_timer, tree, __argus_timer_compare);

#define TS_MSEC(ts) ((ts)->tv_sec*1000+(ts)->tv_nsec/1000000)
static unsigned
__slot(struct argus_timer_wheel *w, struct timespec *when)
{
   return (unsigned)((TS_MSEC(when)/TS_MSEC(&w->period)) % w->nslots);
}

static inline void
__advance(struct argus_timer_wheel *w)
{
   struct timespec sum;

   __timespec_add(&w->now, &w->period, &sum);
   w->now = sum;
   w->current = (w->current + 1) % w->nslots;
}

static int
__gettime_default(struct timespec *ts)
{
#if HAVE_CLOCK_GETTIME
   return clock_gettime(CLOCK_MONOTONIC, ts);
#else
   struct timeval tv;
   int rv;

   rv = gettimeofday(&tv, NULL);
   ts->tv_sec = tv.tv_sec;
   ts->tv_nsec = tv.tv_usec * 1000;
   return rv;
#endif
}

int
ArgusTimerSleep(struct argus_timer_wheel *w)
{
   int rv;
   struct timespec req;

#if HAVE_CLOCK_NANOSLEEP
   __timespec_add(&w->now, &w->period, &req);
   while ((rv = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &req, NULL)) == EINTR);
#else
   struct timespec rem;

   req = w->period;
   while ((rv = nanosleep(&req, &rem)) == EINTR)
      req = rem;
#endif

   return rv;
}

struct argus_timer_wheel *
ArgusTimerWheel(unsigned nslots, const struct timespec * const period,
                gettimefunc gettime)
{
   struct argus_timer_wheel *tmp;
   unsigned u;
   size_t slotmem;

   tmp = malloc(sizeof(*tmp));
   if (tmp == NULL)
      goto out;

   memset(tmp, 0, sizeof(*tmp));
   tmp->period = *period;

   if (gettime)
      tmp->gettime = gettime;
   else
      tmp->gettime = __gettime_default;

   tmp->nslots = nslots;
   slotmem = sizeof(*(tmp->slots)) * nslots;
   tmp->slots = malloc(slotmem);
   if (tmp->slots == NULL) {
      free(tmp);
      tmp = NULL;
      goto out;
   }

   memset(tmp->slots, 0, slotmem);
   for (u = 0; u < nslots; u++) {
      tmp->slots[u] = malloc(sizeof(*(tmp->slots[0])));
      RB_INIT(tmp->slots[u]);
   }

out:
   return tmp;
}

int
ArgusTimerFreeWheel(struct argus_timer_wheel *w)
{
   int rv = 0;
   unsigned u;

   if (w == NULL)
      return -1;

   if (w->slots == NULL) {
      rv = -1;
      goto free_wheel;
   }

   /* don't free the timer trees since each of those structres may be
    * referenced outside of this library.  That is the responsibility of
    * the caller.
    */

   for (u = 0; u < w->nslots; u++) {
      struct argus_timer_tree *tree = w->slots[u];
      while (!RB_EMPTY(tree))
         RB_REMOVE(argus_timer_tree, tree, RB_MIN(argus_timer_tree, tree));
      free(tree);
   }
   free(w->slots);

free_wheel:
   free(w);

   return rv;
}

static struct argus_timer *
__argus_timer_start(struct argus_timer_wheel *w, struct argus_timer *tim_in,
                    struct timespec *exp, callback_t callback,
                    cleanup_t cleanup, void *callbackdata, int relative)
{
   struct argus_timer *tim;
   unsigned slot;

   /* If we're just starting the first timer, make sure we have the current
    * time and are referencing the correct slot in the wheel.
    */
   if (w->ntimers == 0) {
       struct timespec currenttime;

       w->gettime(&currenttime);
       w->now = currenttime;
       w->current = __slot(w, &currenttime);
   }

   if (tim_in)
      tim = tim_in;
   else
      tim = malloc(sizeof(*tim));
   memset(&tim->tree, 0, sizeof(tim->tree));

   if (relative) {
      struct timespec expabs;

      __timespec_add(&w->now, exp, &expabs);
      tim->expiry = expabs;
   } else {
      tim->expiry = *exp;
   }

   tim->callback = callback;
   tim->cleanup = cleanup;
   tim->data = callbackdata;
   tim->td = w->distinguisher++;
   w->ntimers++;

   slot = __slot(w, &tim->expiry);
   RB_INSERT(argus_timer_tree, w->slots[slot], tim);

   return tim;
}

struct argus_timer *
ArgusTimerStartRelative(struct argus_timer_wheel *w, struct timespec *exp,
                        callback_t callback, cleanup_t cleanup,
                        void *callbackdata)
{
   return __argus_timer_start(w, NULL, exp, callback, cleanup, callbackdata, 1);
}

struct argus_timer *
ArgusTimerStartAbsolute(struct argus_timer_wheel *w, struct timespec *exp,
                        callback_t callback, cleanup_t cleanup,
                        void *callbackdata)
{
   return __argus_timer_start(w, NULL, exp, callback, cleanup, callbackdata, 0);
}

void
ArgusTimerStop(struct argus_timer_wheel *w, struct argus_timer *tim)
{
   unsigned slot = __slot(w, &tim->expiry);
   RB_REMOVE(argus_timer_tree, w->slots[slot], tim);
}

static unsigned
__fire_timers(struct argus_timer_wheel *w,
              struct argus_timer_tree *tree,
              const struct timespec * const currenttime)
{
   struct argus_timer *tim;
   unsigned count = 0;
   int done = 0;

   if (RB_EMPTY(tree))
      done = 1;

   while (!done) {
      tim = RB_MIN(argus_timer_tree, tree);
      if (TS_MSEC(&tim->expiry) <= TS_MSEC(currenttime)) {
         ArgusTimerResult res;

         count++;
         RB_REMOVE(argus_timer_tree, tree, tim);
         w->ntimers--;
         if ((res = tim->callback(tim, &w->now)) < FINISHED) {
            /* reschedule - callback updated expiry */
            __argus_timer_start(w, tim, &tim->expiry, tim->callback,
                                tim->cleanup, tim->data, (int)res);
         } else {
            if (tim->cleanup)
               tim->cleanup(tim->data);
         }
      } else {
         done = 1;
      }
      if (RB_EMPTY(tree))
         done = 1;
   }
   return count;
}

int
ArgusTimerAdvanceWheel(struct argus_timer_wheel *w)
{
   /* see if anything in our current slot has expired.  If so, remove
    * the timer from the wheel, run the callback, reschedule if
    * necessary.  Then advance the wheel.
    */

   struct argus_timer_tree *tree = w->slots[w->current];

   /* Look for the timers in the tree that expire soonest and see if
    * that's now.
    */

   __fire_timers(w, tree, &w->now);

   if (w->current) {
      __advance(w);
   } else {
      /* once every revolution check for procession (or the system
       * clock being set).  This will be minimized by using absolute
       * timeouts in __nanosleep().
       */
       struct timespec currenttime;
       struct timespec diff;

       w->gettime(&currenttime);
       __timespec_sub(&w->now, &currenttime, &diff);
       /* this needs to take into account the update period */
       if (diff.tv_sec < 0) {
          /* if our time is behind, advance the wheel until we're
           * caught up.
           */
           unsigned target_slot = __slot(w, &currenttime);
           while (w->current != target_slot) {
              recovered += __fire_timers(w, w->slots[w->current], &currenttime);
              __advance(w);
           }
           missed++;
       } else /* if some threshold such as diff.tv_sec > 0 */ {
           /* unlikely */
       }

       w->now = currenttime;
       w->current = __slot(w, &currenttime);
   }

   return 0;
}

/* consistency check - check the wheel timer count against the sum of
 * the slot counts
*/

int ArgusTimerWheelCheck(struct argus_timer_wheel *);

int
ArgusTimerWheelCheck(struct argus_timer_wheel *w)
{
   uint64_t total = 0;
   uint64_t u;
   struct argus_timer *t;

   for (u = 0; u < w->nslots; u++) {
      RB_FOREACH(t, argus_timer_tree, w->slots[u]) {
         total++;
      }
   }
   return (total == w->ntimers);
}
