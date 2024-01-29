/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2018-2024 QoSient, LLC
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

/*
 * Argus-5.0 timer library
 * Eric Kinzie <eric@qosient.com>
 *
 */

#ifndef __ARGUS_TIMER_H
# define __ARGUS_TIMER_H

# include "argus_config.h"

# include <time.h>
# include <sys/types.h>
# if HAVE_STDINT_H
#  include <stdint.h>
# endif

# include "bsd/sys/tree.h"

typedef enum __argus_timer_result {
   RESCHEDULE_ABS = 0,
   RESCHEDULE_REL = 1,
   FINISHED,
} ArgusTimerResult;

struct argus_timer;
typedef ArgusTimerResult (*callback_t)(struct argus_timer *, struct timespec *);
typedef void (*cleanup_t)(void *); /* can be free() */
typedef int (*gettimefunc)(struct timespec *);

RB_HEAD(argus_timer_tree, argus_timer);

/* The "td" field is used to differentiate timers with the same
 * expiration time.  Timer trees are ordered by time and the RB tree
 * implementation will not insert duplicates.
 */
struct argus_timer {
   struct timespec expiry;
   uint64_t td; /* timer distinguisher */
   callback_t callback;
   cleanup_t cleanup;
   void *data;
   RB_ENTRY(argus_timer) tree;
};

struct argus_timer_wheel {
   /* circular array of timer trees */
   struct argus_timer_tree **slots;
   unsigned nslots;
   unsigned current;	/* 0 <= current < nslots */
   struct timespec period; /* update period - only good down to milliseconds */
   struct timespec now;	/* incremented once each update period */
   uint64_t ntimers;	/* number of timers on the wheel */
   uint64_t distinguisher;
   gettimefunc gettime;
};

struct argus_timer_wheel *
ArgusTimerWheel(unsigned, const struct timespec * const, gettimefunc);

struct argus_timer *
ArgusTimerStartRelative(struct argus_timer_wheel *, struct timespec *,
                        callback_t, cleanup_t, void *);

struct argus_timer *
ArgusTimerStartAbsolute(struct argus_timer_wheel *, struct timespec *,
                        callback_t, cleanup_t, void *);

void
ArgusTimerStop(struct argus_timer_wheel *, struct argus_timer *);

struct argus_timer_wheel *
ArgusTimerAllocateWheel(unsigned, struct timespec *, gettimefunc);

int
ArgusTimerFreeWheel(struct argus_timer_wheel *);

int
ArgusTimerSleep(struct argus_timer_wheel *);

/* ArgusTimerAdvanceWheel can be buried inside of a client's
 * ArgusClientTimeout() function so that it is called once per second,
 * assuming that's the desired period.
 */
int
ArgusTimerAdvanceWheel(struct argus_timer_wheel *);

static inline void
__timespec_sub(const struct timespec * const a,
               const struct timespec * const b,
               struct timespec *result)
{
    result->tv_sec = a->tv_sec - b->tv_sec;
    result->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (result->tv_nsec < 0) {
      --result->tv_sec;
      result->tv_nsec += 1000000000;
    }
}

static inline void
__timespec_add(const struct timespec * const a,
               const struct timespec * const b,
               struct timespec *result)
{
    result->tv_sec = a->tv_sec + b->tv_sec;
    result->tv_nsec = a->tv_nsec + b->tv_nsec;
    if (result->tv_nsec >= 1000000000)
      {
        ++result->tv_sec;
        result->tv_nsec -= 1000000000;
      }
}

#endif
