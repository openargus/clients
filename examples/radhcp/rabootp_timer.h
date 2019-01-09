#ifndef __RABOOTP_TIMER_H
# define __RABOOTP_TIMER_H

#include "argus_timer.h"

typedef int (*sleepfunc)(struct argus_timer_wheel *);
struct RabootpTimerStruct;

void *RabootpTimer(void *);
struct argus_timer *RabootpTimerStart(struct RabootpTimerStruct *rts,
                                      struct timespec *exp,
                                      callback_t callback, void *arg);
struct argus_timer *RabootpTimerStartRealclock(struct RabootpTimerStruct *,
                                      struct timespec *, callback_t , void *);
void RabootpTimerStop(struct RabootpTimerStruct *rts, struct argus_timer *tim);
struct RabootpTimerStruct *RabootpTimerInit(gettimefunc, sleepfunc);
void RabootpTimerCleanup(struct RabootpTimerStruct *);
int RabootpTimerLock(struct RabootpTimerStruct *);
int RabootpTimerUnlock(struct RabootpTimerStruct *);

#endif
