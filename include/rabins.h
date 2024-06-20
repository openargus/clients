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

/* 
 * $Id: //depot/gargoyle/clients/include/rabins.h#7 $
 * $DateTime: 2014/05/14 00:30:13 $
 * $Change: 2825 $
 */

#ifndef RaBins_h
#define RaBins_h

#ifdef __cplusplus
extern "C" {
#endif

struct timeval *RaMaxTime  (struct timeval *, struct timeval *);
struct timeval *RaMinTime  (struct timeval *, struct timeval *);
int RaDiffTime (struct timeval *, struct timeval *, struct timeval *);

#ifdef __cplusplus
}
#endif
#endif
