#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(ARGUS_THREADS)
# define _GNU_SOURCE
# include <pthread.h>
#endif

#include "rabootp_timer.h"
#include "argus_util.h"
#include "argus_parser.h"
#include "argus_threads.h"

/* These could be tunables */
static const unsigned __timer_wheel_slots = 60;
static const struct timespec __period = {1, 0}; /* 1s resolution */

extern struct ArgusParserStruct *ArgusParser;

struct RabootpTimerStruct {
   struct argus_timer_wheel *w;
   sleepfunc sleepfunc;
   pthread_mutex_t lock;
};

/* pthread */
void *
RabootpTimer(void *arg)
{
   struct RabootpTimerStruct *rts = arg;
   struct argus_timer_wheel dummy;

#ifdef __linux
   pthread_setname_np(pthread_self(), "radhcp/timer");
#endif

   /* set once; period doesn't change */
   dummy.period = rts->w->period;

   while (!ArgusParser->RaDonePending && !ArgusParser->RaParseDone) {
      MUTEX_LOCK(&rts->lock);
      ArgusTimerAdvanceWheel(rts->w);
      dummy.now = rts->w->now;
      MUTEX_UNLOCK(&rts->lock);

      rts->sleepfunc(&dummy);
   }

   return NULL;
}

/* RabootpTimerInit:
 *   gettime: If wall-clock time is not desired, pass in a function here
 *            to retrieve the current time.
 *   sleepfunc: If wall-clock time is not desired, pass in a function
 *              here to "sleep" for a specified time.
 *
 *   If gettime is non-NULL, sleepfunc must also be non-NULL and vice
 *   versa.
 */
struct RabootpTimerStruct *
RabootpTimerInit(gettimefunc gettime, sleepfunc sleepfunc)
{
   struct RabootpTimerStruct *rts = ArgusMalloc(sizeof(*rts));

   if (rts == NULL)
      return NULL;

   MUTEX_INIT(&rts->lock, NULL);

   if (sleepfunc)
      rts->sleepfunc = sleepfunc;
   else
      rts->sleepfunc = ArgusTimerSleep;

   rts->w = ArgusTimerWheel(__timer_wheel_slots, &__period, gettime);
   if (rts->w == NULL) {
      ArgusFree(rts);
      rts = NULL;
   }

   return rts;
}

void
RabootpTimerCleanup(struct RabootpTimerStruct *rts)
{
   ArgusTimerFreeWheel(rts->w);
   pthread_mutex_destroy(&rts->lock);
   ArgusFree(rts);
}

int RabootpTimerLock(struct RabootpTimerStruct *rts)
{
   return MUTEX_LOCK(&rts->lock);
}

int RabootpTimerUnlock(struct RabootpTimerStruct *rts)
{
   return MUTEX_UNLOCK(&rts->lock);
}

struct argus_timer *
RabootpTimerStart(struct RabootpTimerStruct *rts, struct timespec *exp,
                  callback_t callback, void *arg)
{
   struct argus_timer *tim;

   tim = ArgusTimerStartRelative(rts->w, exp, callback, NULL, arg);
   return tim;
}

/* Start a timer with the expiry described as an absolute time of day
 * in seconds after the unix epoch (wall-clock time).
 */
struct argus_timer *
RabootpTimerStartRealclock(struct RabootpTimerStruct *rts,
                           struct timespec *exp_realabs,
                           callback_t callback, void *arg)
{
   struct argus_timer *tim;
   struct timeval nowtv;
   struct timespec now;
   struct timespec diff;

   gettimeofday(&nowtv, NULL);
   now.tv_sec = nowtv.tv_sec;
   now.tv_nsec = nowtv.tv_usec * 1000;
   __timespec_sub(exp_realabs, &now, &diff);

   /* If the time has already passed, just wait a second and process the
    * timer when the wheel is next advanced.
    */
   if (diff.tv_sec < 0 || diff.tv_nsec < 0) {
      diff.tv_sec = 1;
      diff.tv_nsec = 0;
   }
   tim = ArgusTimerStartRelative(rts->w, &diff, callback, NULL, arg);
   return tim;
}

void
RabootpTimerStop(struct RabootpTimerStruct *rts, struct argus_timer *tim)
{
   ArgusTimerStop(rts->w, tim);
}
