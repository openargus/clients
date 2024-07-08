/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2018-2024 QoSient, LLC
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

#ifndef __SWIG_ARGUSPARSETIME_H
# define __SWIG_ARGUSPARSETIME_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif

void ArgusLog (int d, char *fmt, ...);
void ArgusDebug (int d, char *fmt, ...);
int swig_ArgusParseTime (char *time_string, int *start, int *end);

void usage (void);
void RaParseComplete (int);
void RaProcessRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int RaSendArgusRecord(struct ArgusRecordStruct *);
void ArgusClientTimeout (void);
void ArgusWindowClose(void);

#endif
