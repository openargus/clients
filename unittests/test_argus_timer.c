#include "argus_config.h"
#include "argus_timer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unittest.h"

#define TS_MSEC(ts) ((ts)->tv_sec*1000+(ts)->tv_nsec/1000000)

typedef int (*sleepfunc)(struct argus_timer_wheel *);

/* from argus_timer.c.  This is a "private" function that does not appear
 * in the header file.
 */
int ArgusTimerWheelCheck(struct argus_timer_wheel *w);


static unsigned callback_count = 0;
static struct timespec callback_lasttime = {0, };
static struct timespec callback_lastexp = {0, };
static ArgusTimerResult __callback(struct argus_timer *tim, struct timespec *now)
{
   callback_count++;
   callback_lasttime = *now;
   callback_lastexp = tim->expiry;
   return FINISHED;
}

static void __callback_stats(void)
{
   printf("\n   callback executed %u times\n", callback_count);
   printf("   last callback time %d.%09d for expiry %d.%09d\n",
          callback_lasttime.tv_sec,
          callback_lasttime.tv_nsec,
          callback_lastexp.tv_sec,
          callback_lastexp.tv_nsec);
}

static void __callback_reset(void)
{
   callback_count = 0;
   memset(&callback_lasttime, 0, sizeof(callback_lasttime));
   memset(&callback_lastexp, 0, sizeof(callback_lastexp));
}

/* time of final expiration returned in duration.  Use this to calculate the
 * number of times the wheel must be advanced to expire all timers.
 */
int
test_add_many_timers(struct argus_timer_wheel *w,
                     unsigned count,
                     const struct timespec * const duration,
                     struct argus_timer ***tims)
{
   struct timespec d = *duration;
   struct timespec tmp;
   unsigned u;
   int fail = 0;

   *tims = malloc(sizeof(struct argus_timer *)*count);
   if (*tims == NULL)
      return -1;

   for (u = 0; u < count && !fail; u++) {
      (*tims)[u] = ArgusTimerStartRelative(w, &d, __callback, NULL, NULL);
      if ((*tims)[u] == NULL)
          fail = 1;
      __timespec_add(&d, duration, &tmp);
      d = tmp;
   }

   if (fail) {
      for (; u > 0; u--)
         free((*tims)[u]);
      free((*tims)[0]);
      free(*tims);
      return -1;
   }

   return 0;
}

/* period is the timer wheel period.  duration is the running time of
 * each timer inserted into the wheel.
 */
int runtests(unsigned slots, struct timespec *period,
             struct timespec *duration,
             gettimefunc gettime,
             sleepfunc sleepfunc)
{
   struct argus_timer_wheel *timerwheel;
   struct argus_timer *tim;
   struct argus_timer **tims;
   unsigned i;
   unsigned iter = slots+1; /* one revolution + 1 cycle */

   if (sleepfunc == NULL)
      sleepfunc = ArgusTimerSleep;

   printf("Timer wheel settings: slots=%u period=%d.%09d\n\n",
          slots, period->tv_sec, period->tv_nsec);

   TestReset();

   TestSectionHeading("Test operation of empty timer wheel");

   TestHeading("Allocate new timer wheel");
   timerwheel = ArgusTimerWheel(slots, period, gettime);
   TestResult(timerwheel != NULL);
   if (timerwheel == NULL)
      return 1;

   TestHeading("Advance timer wheel");
   for (i = 0; i < iter; i++) {
      ArgusTimerAdvanceWheel(timerwheel);
      sleepfunc(timerwheel);
   }
   TestResult(1); /* no crash */




   TestSectionHeading("Test operation of timer wheel with single entry");

   TestHeading("Add timer");
   tim = ArgusTimerStartRelative(timerwheel, period, __callback, NULL, NULL);
   TestResult(tim != NULL);

   TestHeading("Wheel has one timer");
   TestResult(timerwheel->ntimers == 1);

   TestHeading("Wheel consistency check");
   TestResult(ArgusTimerWheelCheck(timerwheel));

   TestHeading("Advance timer wheel (with timer)");
   for (i = 0; i < iter; i++) {
      ArgusTimerAdvanceWheel(timerwheel);
      sleepfunc(timerwheel);
   }
   TestResult(1); /* no crash */
   free(tim);

   TestHeading("Wheel has no timers");
   TestResult(timerwheel->ntimers == 0);

   TestHeading("Wheel consistency check");
   TestResult(ArgusTimerWheelCheck(timerwheel));

   TestHeading("Callback executed 1 time");
   TestResult(callback_count == 1);

   __callback_reset();



   TestSectionHeading("Test operation of timer wheel with more entries than slots");

   TestHeading("Add many (10000) timers");
   TestResult(test_add_many_timers(timerwheel, 10000, duration, &tims) == 0);
   iter = ((TS_MSEC(duration) * 10000) / TS_MSEC(period)) + slots + 1;

   TestHeading("Wheel has 10000 timers");
   TestResult(timerwheel->ntimers == 10000);

   TestHeading("Wheel consistency check");
   TestResult(ArgusTimerWheelCheck(timerwheel));

   TestHeading("Advance timer wheel (with many timers)");
   for (i = 0; i < iter; i++) {
      ArgusTimerAdvanceWheel(timerwheel);
      sleepfunc(timerwheel);
   }
   TestResult(1); /* no crash */
   for (i = 0; i < 10000; i++)
      free(tims[i]);
   free(tims);

   TestHeading("Wheel has no timers");
   TestResult(timerwheel->ntimers == 0);

   TestHeading("Wheel consistency check");
   TestResult(ArgusTimerWheelCheck(timerwheel));

   TestHeading("Callback executed 10000 times");
   TestResult(callback_count == 10000);

   __callback_reset();




   TestSectionHeading("Delete timers from wheel with ArgusTimerFreeWheel");

   TestHeading("Add many (10000) timers");
   TestResult(test_add_many_timers(timerwheel, 10000, duration, &tims) == 0);

   TestHeading("Wheel has 10000 timers");
   TestResult(timerwheel->ntimers == 10000);

   TestHeading("Wheel consistency check");
   TestResult(ArgusTimerWheelCheck(timerwheel));

   TestHeading("Free the timer wheel");
   TestResult(ArgusTimerFreeWheel(timerwheel) == 0);
   for (i = 0; i < 10000; i++)
      free(tims[i]);
   free(tims);




   TestSectionHeading("Test operation of timer wheel with only one slot");

   TestHeading("Allocate new timer wheel with one slot");
   timerwheel = ArgusTimerWheel(1, period, gettime);
   TestResult(timerwheel != NULL);
   if (timerwheel == NULL)
      return 1;

   TestHeading("Add many (10000) timers");
   TestResult(test_add_many_timers(timerwheel, 10000, duration, &tims) == 0);

   TestHeading("Wheel has 10000 timers");
   TestResult(timerwheel->ntimers == 10000);

   TestHeading("Wheel consistency check");
   TestResult(ArgusTimerWheelCheck(timerwheel));

   TestHeading("Advance timer wheel");
   for (i = 0; i < iter; i++) {
      ArgusTimerAdvanceWheel(timerwheel);
      sleepfunc(timerwheel);
   }
   TestResult(1); /* no crash */
   for (i = 0; i < 10000; i++)
      free(tims[i]);
   free(tims);

   TestHeading("Wheel has no timers");
   TestResult(timerwheel->ntimers == 0);

   TestHeading("Wheel consistency check");
   TestResult(ArgusTimerWheelCheck(timerwheel));

   TestHeading("Free the timer wheel");
   TestResult(ArgusTimerFreeWheel(timerwheel) == 0);

   TestHeading("Callback executed 10000 times");
   TestResult(callback_count == 10000);
   __callback_reset();

   return !!TestSummary();


   return 0;
}
