/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
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

#ifndef __ARGUS_THREADS_H
#  define __ARGUS_THREADS_H

#  ifdef HAVE_CONFIG_H
#   include "argus_config.h"
#  endif

#  if defined(ARGUS_THREADS)
#    include <pthread.h>
#    define MUTEX_LOCK(l) pthread_mutex_lock(l)
#    define MUTEX_UNLOCK(l) pthread_mutex_unlock(l)
#    define MUTEX_INIT(l, a) pthread_mutex_init((l), (a))
#    define MUTEX_DESTROY(l) pthread_mutex_destroy(l);
#    define COND_SIGNAL(cond) pthread_cond_signal(cond)

#  else /* ARGUS_THREADS */
#    define MUTEX_LOCK(l) (0)
#    define MUTEX_UNLOCK(l) (0)
#    define MUTEX_INIT(l, a) (0)
#    define MUTEX_DESTROY(l) (0)
#    define COND_SIGNAL(cond) (0)

#  endif /* ARGUS_THREADS */

#endif
