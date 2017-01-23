#include "argus_config.h"
#include "argus_timer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unittest.h"
#include "test_argus_timer.h"

static struct timespec now = {0, };
static int
__mygettime(struct timespec *ts)
{
  *ts = now;
  return 0;
}

static int
__sleep(struct argus_timer_wheel *w)

{
   struct timespec tmp;
   __timespec_add(&now, &w->period, &tmp);
   now = tmp;
}

int main(int argc, char **argv, char **env)
{

   unsigned slots = 600;
   struct timespec duration = {10, 0}; /* 10s */
   struct timespec period = {1, 0}; /* 1s */

   return runtests(slots, &period, &duration, __mygettime, __sleep);
}
