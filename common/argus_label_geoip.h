/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2018 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
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
#endif
