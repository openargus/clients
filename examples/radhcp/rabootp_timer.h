#ifndef __RABOOTP_TIMER_H
# define __RABOOTP_TIMER_H

#include "argus_timer.h"

typedef int (*sleepfunc)(struct argus_timer_wheel *);
struct RabootpTimerStruct;

void *RabootpTimer(void *);
struct argus_timer *RabootpTimerStart(struct RabootpTimerStruct *rts,
                                      struct timespec *exp,
                                      callback_t callback, void *arg);
void RabootpTimerStop(struct RabootpTimerStruct *rts, struct argus_timer *tim);
struct RabootpTimerStruct *RabootpTimerInit(gettimefunc, sleepfunc);
void RabootpTimerCleanup(struct RabootpTimerStruct *);

#endif