#ifndef __TEST_ARGUS_TIMER_H
# define __TEST_ARGUS_TIMER_H
# include "argus_timer.h"

typedef int (*sleepfunc)(struct argus_timer_wheel *);
int runtests(unsigned, struct timespec *, struct timespec *,
             gettimefunc, sleepfunc);

#endif
