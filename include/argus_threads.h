#ifndef __ARGUS_THREADS_H
#  define __ARGUS_THREADS_H

#  if defined(ARGUS_THREADS)
#    include <pthread.h>
#    define MUTEX_LOCK(l) pthread_mutex_lock(l)
#    define MUTEX_UNLOCK(l) pthread_mutex_unlock(l)
#    define MUTEX_INIT(l, a) pthread_mutex_init((l), (a))
#    define COND_SIGNAL(cond) pthread_cond_signal(cond)

#  else /* ARGUS_THREADS */
#    define MUTEX_LOCK(l) (0)
#    define MUTEX_UNLOCK(l) (0)
#    define MUTEX_INIT(l, a) (0)
#    define COND_SIGNAL(cond) (0)

#  endif /* ARGUS_THREADS */

#endif