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

#ifndef __ARGUS_LOCKFILE_H
# define __ARGUS_LOCKFILE_H
# include "argus_config.h"

struct _argus_lock_context;
typedef struct _argus_lock_context *ArgusLockContext;

# if defined(CYGWIN)
char *
ArgusCygwinConvPath2Win(const char * const);
# endif


int
ArgusCreateLockFile(const char * const filename, int nonblock,
                   ArgusLockContext *ctx);

int
ArgusReleaseLockFile(ArgusLockContext *ctx);

#endif
