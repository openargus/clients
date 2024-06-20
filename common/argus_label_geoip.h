/*
 * Argus Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2022 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <sys/types.h>
#include <argus_compat.h>
#include <argus_util.h>
#include <argus_client.h>
#include "argus_parser.h"

#if defined(ARGUS_GEOIP)
#define ARGUS_GEOIP_TOTAL_OBJECTS       14
extern struct ArgusGeoIPCityObject ArgusGeoIPCityObjects[];

int ArgusLabelRecordGeoIP(struct ArgusParserStruct *,
                          struct ArgusRecordStruct *, char *, size_t, int *);

#endif

#if defined(ARGUS_GEOIP2)
int ArgusLabelRecordGeoIP2(struct ArgusParserStruct *,
                           struct ArgusRecordStruct *, char *, size_t, int *);
int ArgusGeoIP2FindObject(const char * const);

int geoip2_path_compare(const void *, const void *);
int ArgusLabelRecordGeoIP2(struct ArgusParserStruct *, struct ArgusRecordStruct *, char *, size_t, int *);
int ArgusGeoIP2FindObject(const char * const);
#endif
