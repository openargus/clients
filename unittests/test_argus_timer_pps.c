#include "argus_config.h"
#include "argus_timer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unittest.h"

#define TS_MSEC(ts) ((ts)->tv_sec*1000+(ts)->tv_nsec/1000000)

typedef int (*sleepfunc)(struct argus_timer_wheel *);


static unsigned callback_count = 0;
static struct timespec callback_lasttime = {0, };
static struct timespec callback_lastexp = {0, };
static ArgusTimerResult __callback(struct argus_timer *tim, struct timespec *now)
{
   printf(" %s", callback_count % 2 ? "TOCK" : "TICK");
   fflush(stdout);

   callback_count++;
   callback_lasttime = *now;
   callback_lastexp = tim->expiry;
   tim->expiry.tv_sec++;

   if (callback_count < 10)
      return RESCHEDULE_ABS;
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

   TestSectionHeading("Test operation of automatic re-arm");

   TestHeading("Allocate new timer wheel");
   timerwheel = ArgusTimerWheel(slots, period, gettime);
   TestResult(timerwheel != NULL);
   if (timerwheel == NULL)
      return 1;

   TestHeading("Add timer");
   tim = ArgusTimerStartRelative(timerwheel, period, __callback, NULL, NULL);
   TestResult(tim != NULL);

   TestHeading("Wheel has one timer");
   TestResult(timerwheel->ntimers == 1);

   TestHeading("Advance timer wheel (with timer)");
   for (i = 0; i < iter; i++) {
      ArgusTimerAdvanceWheel(timerwheel);
      sleepfunc(timerwheel);
   }
   TestResult(1); /* no crash */
   free(tim);

   TestHeading("Wheel has no timers");
   TestResult(timerwheel->ntimers == 0);

   TestHeading("Callback executed 10 times");
   TestResult(callback_count == 10);

   return !!TestSummary();
}

int main(int argc, char **argv, char **env)
{

   unsigned slots = 40;
   struct timespec duration = {0, 1000000}; /* 1 ms */
   struct timespec period = {0, 250000000}; /* 1/4 second */

   return runtests(slots, &period, &duration, NULL, NULL);
}

