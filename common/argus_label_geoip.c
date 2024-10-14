/*
 * Argus Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
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

#if defined(ARGUS_GEOIP) || defined(ARGUS_GEOIP2)

#ifndef ArgusLabel
#define ArgusLabel
#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>

#include <argus_compat.h>
#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_sort.h>
#include <argus_metric.h>
#include <argus_label.h>

#if defined(__OpenBSD__)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/tcp.h>

#include "argus_label_geoip.h"

#define ARGUS_GEOIP_COUNTRY_CODE        1
#define ARGUS_GEOIP_COUNTRY_CODE_3      2
#define ARGUS_GEOIP_COUNTRY_NAME        3
#define ARGUS_GEOIP_REGION              4
#define ARGUS_GEOIP_CITY_NAME           5
#define ARGUS_GEOIP_POSTAL_CODE         6
#define ARGUS_GEOIP_LATITUDE            7
#define ARGUS_GEOIP_LONGITUDE           8
#define ARGUS_GEOIP_METRO_CODE          9
#define ARGUS_GEOIP_AREA_CODE           10
#define ARGUS_GEOIP_CHARACTER_SET       11
#define ARGUS_GEOIP_CONTINENT_CODE      12
#define ARGUS_GEOIP_NETMASK             13
#define ARGUS_GEOIP_ASN			14
#define ARGUS_GEOIP_ASNORG		15

#if defined(ARGUS_GEOIP)
#include <GeoIPCity.h>

struct ArgusGeoIPCityObject ArgusGeoIPCityObjects[] = {
   { "", "%s", 0, 0, 0, 0},
   { "cco", "%s", 3, 2, 0, ARGUS_GEOIP_COUNTRY_CODE},
   { "cco3", "%s", 4, 3, 0, ARGUS_GEOIP_COUNTRY_CODE_3},
   { "cname", "%s", 5, 128, 0, ARGUS_GEOIP_COUNTRY_NAME},
   { "region", "%s", 6, 128, 0, ARGUS_GEOIP_REGION},
   { "city", "%s", 4, 128, 0, ARGUS_GEOIP_CITY_NAME},
   { "pcode", "%s", 5, 16, 0, ARGUS_GEOIP_POSTAL_CODE},
   { "lat", "%f", 3, 16, 0, ARGUS_GEOIP_LATITUDE},
   { "lon", "%f", 3, 16, 0, ARGUS_GEOIP_LONGITUDE},
   { "metro", "%d", 5, 16, 0, ARGUS_GEOIP_METRO_CODE},
   { "area", "%d", 4, 16, 0, ARGUS_GEOIP_AREA_CODE},
   { "charset", "%d", 7, 16, 0, ARGUS_GEOIP_CHARACTER_SET},
   { "cont", "%s", 4, 16, 0, ARGUS_GEOIP_CONTINENT_CODE},
   { "netmask", "%d", 7, 4, 0, ARGUS_GEOIP_NETMASK},
};

static int
ArgusPrintGeoIPRecord(struct ArgusParserStruct *parser, GeoIPRecord *gir,
                      char *label, int len, int found, char *prefix)
{
   int slen = strlen(label), x, tf = 0;

   if (found) {
      snprintf (&label[slen], len - slen, ":");
      slen++;
   }

   snprintf (&label[slen], len - slen, "%s", prefix);
   slen = strlen(label);

   for (x = 0; x < ARGUS_GEOIP_TOTAL_OBJECTS; x++) {
      struct ArgusGeoIPCityObject *obj;
      int ind;
      if ((ind = parser->ArgusLabeler->RaLabelGeoIPCityLabels[x]) > 0) {
         if (tf) {
            snprintf (&label[slen], len - slen, "%c", ',');
            slen++;
         }
         obj = &ArgusGeoIPCityObjects[ind];
         switch (obj->value) {
            case ARGUS_GEOIP_COUNTRY_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->country_code);
               break;
            case ARGUS_GEOIP_COUNTRY_CODE_3:
               snprintf (&label[slen], len - slen, obj->format, gir->country_code3);
               break;
            case ARGUS_GEOIP_COUNTRY_NAME:
               snprintf (&label[slen], len - slen, obj->format, gir->country_name);
               break;
            case ARGUS_GEOIP_REGION:
               snprintf (&label[slen], len - slen, obj->format, gir->region);
               break;
            case ARGUS_GEOIP_CITY_NAME:
               snprintf (&label[slen], len - slen, obj->format, gir->city);
               break;
            case ARGUS_GEOIP_POSTAL_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->postal_code);
               break;
            case ARGUS_GEOIP_LATITUDE:
               snprintf (&label[slen], len - slen, obj->format, gir->latitude);
               break;
            case ARGUS_GEOIP_LONGITUDE:
               snprintf (&label[slen], len - slen, obj->format, gir->longitude);
               break;
            case ARGUS_GEOIP_METRO_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->metro_code);
               break;
            case ARGUS_GEOIP_AREA_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->area_code);
               break;
            case ARGUS_GEOIP_CHARACTER_SET:
               snprintf (&label[slen], len - slen, obj->format, gir->charset);
               break;
            case ARGUS_GEOIP_CONTINENT_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->continent_code);
               break;
//          case ARGUS_GEOIP_NETMASK:
//             snprintf (&label[slen], len - slen, obj->format, gir->netmask);
//             break;
         }
         slen = strlen(label);
         tf++;

      } else
         break;
   }

   return found;
}

int
ArgusLabelRecordGeoIP(struct ArgusParserStruct *parser,
                      struct ArgusRecordStruct *argus,
                      char *label, size_t len,
                      int *found)
{
   int _found = *found;
   struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;

   if (labeler->RaLabelGeoIPAsn) {
      if (labeler->RaGeoIPv4AsnObject != NULL) {
         struct ArgusAsnStruct *asn = (struct ArgusAsnStruct *) argus->dsrs[ARGUS_ASN_INDEX];
         struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
         struct ArgusIcmpStruct *icmp = (void *)argus->dsrs[ARGUS_ICMP_INDEX];
         char *rstr;

         if (flow != NULL) {
            if (asn == NULL) {
               if ((asn = ArgusCalloc(1, sizeof(*asn))) == NULL)
                  ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s", strerror(errno));

               asn->hdr.type              = ARGUS_ASN_DSR;
               asn->hdr.subtype           = ARGUS_ASN_ORIGIN;
               asn->hdr.argus_dsrvl8.qual = 0;
               asn->hdr.argus_dsrvl8.len  = 3;

               argus->dsrs[ARGUS_ASN_INDEX] = (struct ArgusDSRHeader *) asn;
               argus->dsrindex |= (0x01 << ARGUS_ASN_INDEX);
            }

            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        if (asn->src_as == 0) {
                           if ((rstr = GeoIP_org_by_ipnum (labeler->RaGeoIPv4AsnObject, flow->ip_flow.ip_src)) != NULL) {
                              if (strlen(rstr)) {
                                 int result = 0;
                                 if (sscanf(rstr, "AS%d", &result) == 1)
                                    asn->src_as = result;
                              }
                              free(rstr);
                           }
                        }

                        if (asn->dst_as == 0) {
                           if ((rstr = GeoIP_org_by_ipnum (labeler->RaGeoIPv4AsnObject, flow->ip_flow.ip_dst)) != NULL) {
                              if (strlen(rstr)) {
                                 int result = 0;
                                 if (sscanf(rstr, "AS%d", &result) == 1)
                                    asn->dst_as = result;
                              }
                              free(rstr);
                           }
                        }

                        if (asn->inode_as == 0) {
                           if (icmp != NULL) {
                              if (icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED) {
                                 if ((rstr = GeoIP_org_by_ipnum (labeler->RaGeoIPv4AsnObject, icmp->osrcaddr)) != NULL) {
                                    if (strlen(rstr)) {
                                       int result = 0;
                                       if (sscanf(rstr, "AS%d", &result) == 1)
                                          asn->inode_as = result;

                                       asn->hdr.argus_dsrvl8.len  = 4;
                                    }
                                    free(rstr);
                                 }
                              }
                           }
                        }
                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        if (labeler->RaGeoIPv6AsnObject) {
                           if (asn->src_as == 0) {
                              struct in6_addr saddr;

                              bcopy(flow->ipv6_flow.ip_src, saddr.s6_addr, sizeof(saddr));

                              if ((rstr = GeoIP_org_by_ipnum_v6 (labeler->RaGeoIPv6AsnObject, saddr)) != NULL) {
                                 if (strlen(rstr)) {
                                    int result = 0;
                                    if (sscanf(rstr, "AS%d", &result) == 1)
                                       asn->src_as = result;
                                 }
                                 free(rstr);
                              }
                           }

                           if (asn->dst_as == 0) {
                              struct in6_addr daddr;

                              bcopy(flow->ipv6_flow.ip_dst, daddr.s6_addr, sizeof(daddr));

                              if ((rstr = GeoIP_org_by_ipnum_v6 (labeler->RaGeoIPv6AsnObject, daddr)) != NULL) {
                                 if (strlen(rstr)) {
                                    int result = 0;
                                    if (sscanf(rstr, "AS%d", &result) == 1)
                                       asn->dst_as = result;
                                 }
                                 free(rstr);
                              }
                           }
                        }
                        break;
                     }
                  }
                  break;
               }
            }
         }
      }
   }

   if (labeler->RaLabelGeoIPCity) {
      if (labeler->RaGeoIPv4CityObject != NULL) {
         struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
         GeoIPRecord *gir;

         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        struct ArgusGeoLocationStruct *geo = NULL;

                        if (labeler->RaLabelGeoIPCity & ARGUS_SRC_ADDR)
                           if ((gir = GeoIP_record_by_ipnum (labeler->RaGeoIPv4CityObject, flow->ip_flow.ip_src)) != NULL) {
                              if ((geo = (struct ArgusGeoLocationStruct *)argus->dsrs[ARGUS_GEO_INDEX]) == NULL) {
                                 geo = (struct ArgusGeoLocationStruct *) ArgusCalloc(1, sizeof(*geo));
                                 geo->hdr.type = ARGUS_GEO_DSR;
                                 geo->hdr.argus_dsrvl8.len = (sizeof(*geo) + 3) / 4;

                                 argus->dsrs[ARGUS_GEO_INDEX] = &geo->hdr;
                                 argus->dsrindex |= (0x1 << ARGUS_GEO_INDEX);
                              }
                              geo->hdr.argus_dsrvl8.qual |= ARGUS_SRC_GEO;
                              geo->src.lat = gir->latitude;
                              geo->src.lon = gir->longitude;

                              ArgusPrintGeoIPRecord(parser, gir, label, len, _found, "scity=");
                              GeoIPRecord_delete(gir);
                              _found++;
                           }

                        if (labeler->RaLabelGeoIPCity & ARGUS_DST_ADDR)
                           if ((gir = GeoIP_record_by_ipnum (labeler->RaGeoIPv4CityObject, flow->ip_flow.ip_dst)) != NULL) {
                              if ((geo = (struct ArgusGeoLocationStruct *)argus->dsrs[ARGUS_GEO_INDEX]) == NULL) {
                                 geo = (struct ArgusGeoLocationStruct *) ArgusCalloc(1, sizeof(*geo));
                                 geo->hdr.type = ARGUS_GEO_DSR;
                                 geo->hdr.argus_dsrvl8.len = (sizeof(*geo) + 3) / 4;
                                 argus->dsrs[ARGUS_GEO_INDEX] = &geo->hdr;
                                 argus->dsrindex |= (0x1 << ARGUS_GEO_INDEX);
                              }
                              geo->hdr.argus_dsrvl8.qual |= ARGUS_DST_GEO;
                              geo->dst.lat = gir->latitude;
                              geo->dst.lon = gir->longitude;
                              ArgusPrintGeoIPRecord(parser, gir, label, len, _found, "dcity=");
                              GeoIPRecord_delete(gir);
                              _found++;

                           }

                        if (labeler->RaLabelGeoIPCity & ARGUS_INODE_ADDR) {
                           struct ArgusIcmpStruct *icmp = (void *)argus->dsrs[ARGUS_ICMP_INDEX];

                           if (icmp != NULL) {
                              if (icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED) {
                                 struct ArgusFlow *flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX];

                                 if (flow != NULL) {
                                    switch (flow->hdr.subtype & 0x3F) {
                                       case ARGUS_FLOW_CLASSIC5TUPLE:
                                       case ARGUS_FLOW_LAYER_3_MATRIX: {
                                          switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                             case ARGUS_TYPE_IPV4:
                                                if ((gir = GeoIP_record_by_ipnum (labeler->RaGeoIPv4CityObject, icmp->osrcaddr)) != NULL) {
                                                   if ((geo = (struct ArgusGeoLocationStruct *)argus->dsrs[ARGUS_GEO_INDEX]) == NULL) {
                                                      geo = (struct ArgusGeoLocationStruct *) ArgusCalloc(1, sizeof(*geo));
                                                      geo->hdr.type = ARGUS_GEO_DSR;
                                                      geo->hdr.argus_dsrvl8.len = (sizeof(*geo) + 3) / 4;
                                                      argus->dsrs[ARGUS_GEO_INDEX] = &geo->hdr;
                                                      argus->dsrindex |= (0x1 << ARGUS_GEO_INDEX);
                                                   }
                                                   geo->hdr.argus_dsrvl8.qual |= ARGUS_INODE_GEO;
                                                   geo->inode.lat = gir->latitude;
                                                   geo->inode.lon = gir->longitude;
                                                   ArgusPrintGeoIPRecord(parser, gir, label, len, _found, "icity=");
                                                   GeoIPRecord_delete(gir);
                                                   _found++;
                                                }
                                                break;

                                             case ARGUS_TYPE_IPV6:
                                                break;
                                          }
                                          break;
                                       }

                                       default:
                                          break;
                                    }
                                 }
                              }
                           }
                        }
                        break;
                     }
                     case ARGUS_TYPE_IPV6: {
                        if (labeler->RaGeoIPv6CityObject != NULL) {
                           if (labeler->RaLabelGeoIPCity & ARGUS_SRC_ADDR) {
                              struct in6_addr saddr;
                              bcopy(flow->ipv6_flow.ip_src, saddr.s6_addr, sizeof(saddr));

                              if ((gir = GeoIP_record_by_ipnum_v6 (labeler->RaGeoIPv6CityObject, saddr)) != NULL) {
                                 ArgusPrintGeoIPRecord(parser, gir, label, len, _found, "scity=");
                                 GeoIPRecord_delete(gir);
                                 _found++;
                              }
                           }

                           if (labeler->RaLabelGeoIPCity & ARGUS_DST_ADDR) {
                              struct in6_addr daddr;
                              bcopy(flow->ipv6_flow.ip_dst, daddr.s6_addr, sizeof(daddr));

                              if ((gir = GeoIP_record_by_ipnum_v6 (labeler->RaGeoIPv6CityObject, daddr)) != NULL) {
                                 ArgusPrintGeoIPRecord(parser, gir, label, len, _found, "dcity=");
                                 GeoIPRecord_delete(gir);
                                 _found++;
                              }
                           }
                        }
                        break;
                     }
                  }
               }
            }
         }
      }
   }

   *found = _found;
   return 1;
}

#elif defined(ARGUS_GEOIP2)
#include <maxminddb.h>
#include "maxminddb-compat-util.h"

typedef int (*geoip2_fmt_dsr_func)(struct ArgusParserStruct *,
                                   struct ArgusRecordStruct *,
                                   MMDB_entry_data_list_s *const, void *, int);

/* arg: pointer to integer with direction information.  Can be
 * ARGUS_INODE_ADDR, ARGUS_DST_ADDR or ARGUS_SRC_ADDR.
 */
static int
ArgusFormatDSR_GEO(struct ArgusParserStruct *parser,
                   struct ArgusRecordStruct *argus,
                   MMDB_entry_data_list_s *const value,
                   void *user,
                   int dir)
{
   struct ArgusGeoLocationStruct *geo = NULL;

   geo = (struct ArgusGeoLocationStruct *)argus->dsrs[ARGUS_GEO_INDEX];
   if (geo == NULL) {
      geo = (struct ArgusGeoLocationStruct *) ArgusCalloc(1, sizeof(*geo));
      geo->hdr.type = ARGUS_GEO_DSR;
      geo->hdr.argus_dsrvl8.len = (sizeof(*geo) + 3) / 4;
      argus->dsrs[ARGUS_GEO_INDEX] = &geo->hdr;
      argus->dsrindex |= (0x1 << ARGUS_GEO_INDEX);
   }

   geo->hdr.argus_dsrvl8.qual |= ARGUS_DST_GEO;
   if (!strcmp(user, "latitude")) {
      if (dir & ARGUS_DST_ADDR)
         geo->dst.lat = (float)value->entry_data.double_value;
      else if (dir & ARGUS_SRC_ADDR)
         geo->src.lat = (float)value->entry_data.double_value;
      else if (dir == ARGUS_INODE_ADDR)
         geo->inode.lat = (float)value->entry_data.double_value;
   } else if (!strcmp(user, "longitude")) {
      if (dir & ARGUS_DST_ADDR)
         geo->dst.lon = (float)value->entry_data.double_value;
      else if (dir & ARGUS_SRC_ADDR)
         geo->src.lon = (float)value->entry_data.double_value;
      else if (dir == ARGUS_INODE_ADDR)
         geo->inode.lon = (float)value->entry_data.double_value;
   }

   return 1;
}

/* arg: pointer to integer with direction information.  Can be
 * ARGUS_INODE_ADDR, ARGUS_DST_ADDR or ARGUS_SRC_ADDR.
 */
static int
ArgusFormatDSR_ASN(struct ArgusParserStruct *parser,
                   struct ArgusRecordStruct *argus,
                   MMDB_entry_data_list_s *const value,
                   void *user,
                   int dir)
{
   uint32_t vasn = value->entry_data.uint32;
   struct ArgusAsnStruct *asn = (struct ArgusAsnStruct *) argus->dsrs[ARGUS_ASN_INDEX];
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusIcmpStruct *icmp = (void *)argus->dsrs[ARGUS_ICMP_INDEX];
   struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;

   if (value->entry_data.type != MMDB_DATA_TYPE_UINT32) {
      ArgusLog(LOG_WARNING, "%s: unexpected libmaxminddb type %d\n",
               __func__, value->entry_data.type);
      return -1;
   }

   if (!labeler->RaLabelGeoIPAsn)
      return 0;

   if (flow == NULL)
      return 0;

   if (asn == NULL) {
      if ((asn = ArgusCalloc(1, sizeof(*asn))) == NULL)
         ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s", strerror(errno));

      asn->hdr.type              = ARGUS_ASN_DSR;
      asn->hdr.subtype           = ARGUS_ASN_ORIGIN;
      asn->hdr.argus_dsrvl8.qual = 0;
      asn->hdr.argus_dsrvl8.len  = 3;

      argus->dsrs[ARGUS_ASN_INDEX] = (struct ArgusDSRHeader *) asn;
      argus->dsrindex |= (0x01 << ARGUS_ASN_INDEX);
   }

   switch (flow->hdr.subtype & 0x3F) {
      case ARGUS_FLOW_CLASSIC5TUPLE:
      case ARGUS_FLOW_LAYER_3_MATRIX:
         switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
            case ARGUS_TYPE_IPV4:
            case ARGUS_TYPE_IPV6:

               if (dir & ARGUS_SRC_ADDR)
                  asn->src_as = asn->src_as ? asn->src_as : vasn;
               else if (dir & ARGUS_DST_ADDR)
                  asn->dst_as = asn->dst_as ? asn->dst_as : vasn;
               else if (dir == ARGUS_INODE_ADDR && icmp) {
                  if (icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED) {
                     asn->inode_as = vasn;
                     asn->hdr.argus_dsrvl8.len  = 4;
                  }
               }
               break;
            }
         break;
   }
   return 1;
}

static int
ArgusFormatDSR_ASNORG(struct ArgusParserStruct *parser,
                   struct ArgusRecordStruct *argus,
                   MMDB_entry_data_list_s *const value,
                   void *user,
                   int dir)
{
   struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;

   if (value->entry_data.type != MMDB_DATA_TYPE_UTF8_STRING) {
      ArgusLog(LOG_WARNING, "%s: unexpected libmaxminddb type %d\n", __func__, value->entry_data.type);
      return -1;
   }

   if (!labeler->RaLabelGeoIPAsn)
      return 0;
   return 1;
}


static int _geoip2_to_argus_names_sorted = 0;
typedef struct _geoip2_to_argus_names {
   char *geoip2_path;
   char *argus_name;
   int item;
   geoip2_fmt_dsr_func fmt_dsr_func;
} geoip2_to_argus_names_t;

static geoip2_to_argus_names_t geoip2_to_argus_names[] = {
   { "country iso_code", "cco", ARGUS_GEOIP_COUNTRY_CODE, NULL },
   { "country names en", "cname", ARGUS_GEOIP_COUNTRY_NAME, NULL },
   { "subdivisions iso_code", "region", ARGUS_GEOIP_REGION, NULL },
   { "city names en", "city", ARGUS_GEOIP_CITY_NAME, NULL },
   { "postal code", "pcode", ARGUS_GEOIP_POSTAL_CODE, NULL },
   { "location latitude", "lat", ARGUS_GEOIP_LATITUDE, ArgusFormatDSR_GEO },
   { "location longitude", "lon", ARGUS_GEOIP_LONGITUDE, ArgusFormatDSR_GEO },
   { "location metro_code", "metro", ARGUS_GEOIP_METRO_CODE, NULL },
   { "continent code", "cont", ARGUS_GEOIP_CONTINENT_CODE, NULL },
   { "autonomous_system_number", "asn", ARGUS_GEOIP_ASN, ArgusFormatDSR_ASN },
   { "autonomous_system_organization", "asorg", ARGUS_GEOIP_ASNORG, ArgusFormatDSR_ASNORG },
};
static const size_t geoip2_to_argus_names_len =
   sizeof(geoip2_to_argus_names)/sizeof(geoip2_to_argus_names[0]);

/* used to sort and search the translation table by geoip2 path string */
int geoip2_path_compare(const void *a, const void *b) {
   const geoip2_to_argus_names_t *aa = a;
   const geoip2_to_argus_names_t *bb = b;

   return strcmp(aa->geoip2_path, bb->geoip2_path);
}

static const size_t ARGUS_GEOIP2_MAX_PATH = 128;

/* look through the configured label types [city,asn] for @item and return 1
 * if found
 */
static int
is_item_enabled(struct ArgusParserStruct *parser, int item)
{
    int ena = 0;
    int ind;

    if (ena == 0) {
       static const int maxlabels =
          sizeof(parser->ArgusLabeler->RaLabelGeoIPCityLabels)/
          sizeof(parser->ArgusLabeler->RaLabelGeoIPCityLabels[0]);

       for (ind = 0; ind < maxlabels && !ena; ind++) {
          int i = parser->ArgusLabeler->RaLabelGeoIPCityLabels[ind];

          if (geoip2_to_argus_names[i].item == item)
             ena = 1;
       }
    }
    if (ena == 0) {
       static const int maxlabels =
          sizeof(parser->ArgusLabeler->RaLabelGeoIPAsnLabels)/
          sizeof(parser->ArgusLabeler->RaLabelGeoIPAsnLabels[0]);

       for (ind = 0; ind < maxlabels && !ena; ind++) {
          int i = parser->ArgusLabeler->RaLabelGeoIPAsnLabels[ind];

          if (geoip2_to_argus_names[i].item == item)
             ena = 1;
       }
    }

    return ena;
}

static MMDB_entry_data_list_s *
dump_entry_data_list(
    struct ArgusParserStruct *parser,
    struct ArgusRecordStruct *argus,
    MMDB_entry_data_list_s *entry_data_list,
    const char * const path, /* where we are in the data structure, e.g.
                              * "country names"
                              */
    char *str,               /* output string */
    size_t *str_offset,      /* string end pointer (IN/OUT) */
    size_t *str_remain,      /* remaining bytes allocated for string (IN/OUT) */
    int dir,
    int *status)
{
   geoip2_to_argus_names_t gkey = {NULL, };
   geoip2_to_argus_names_t *xlate;
   char dirprefix = ' ';
   int skip = 1;

   switch (entry_data_list->entry_data.type) {
      case MMDB_DATA_TYPE_MAP: {
         uint32_t size = entry_data_list->entry_data.data_size;
         char *key = NULL, *nextpath = NULL;

         for (entry_data_list = entry_data_list->next; size && entry_data_list; size--) {
            if (MMDB_DATA_TYPE_UTF8_STRING != entry_data_list->entry_data.type) {
               *status = MMDB_INVALID_DATA_ERROR;
               return NULL;
            }

            key = mmdb_strndup( (char *)entry_data_list->entry_data.utf8_string,
                                              entry_data_list->entry_data.data_size);
            if (NULL == key) {
               *status = MMDB_OUT_OF_MEMORY_ERROR;
               return NULL;
            }

            nextpath = ArgusMalloc(ARGUS_GEOIP2_MAX_PATH);
            if (nextpath == NULL)
               ArgusLog(LOG_ERR, "%s: unable to allocate path buffer", __func__);

            snprintf(nextpath, ARGUS_GEOIP2_MAX_PATH, "%s%s%s", path, *path == 0 ? "" : " ", key);
            free(key);

            entry_data_list = entry_data_list->next;
            entry_data_list = dump_entry_data_list(parser, argus, entry_data_list, nextpath, str,
                                         str_offset, str_remain, dir, status);

            ArgusFree(nextpath);

            if (MMDB_SUCCESS != *status) {
               return NULL;
            }
         }
         goto out;
         break;
      }
      case MMDB_DATA_TYPE_ARRAY: {
         uint32_t size = entry_data_list->entry_data.data_size;

         for (entry_data_list = entry_data_list->next; size && entry_data_list; size--) {
            entry_data_list = dump_entry_data_list(parser, argus, entry_data_list, path, str,
                                         str_offset, str_remain, dir, status);
            if (MMDB_SUCCESS != *status) {
               return NULL;
            }
         }
         goto out;
         break;
      }
   }

   /* Check if Argus knows anything about the current datum */
   gkey.geoip2_path = strdup(path);
   if (gkey.geoip2_path == NULL)
      ArgusLog(LOG_ERR, "%s: unable to duplicate path string");

#ifdef ARGUSDEBUG
   ArgusDebug(4, "looking for \"%s\"\n", path);
#endif

   xlate = bsearch(&gkey, geoip2_to_argus_names, geoip2_to_argus_names_len,
                    sizeof(geoip2_to_argus_names[0]), geoip2_path_compare);

   if (xlate == NULL) {
      free(gkey.geoip2_path);
      gkey.geoip2_path = NULL;

      /* skip to the next key/map/list */
      if (entry_data_list)
         entry_data_list = entry_data_list->next;
      goto out;
   }

   if (dir == ARGUS_SRC_ADDR)
      dirprefix = 's';
   else if (dir == ARGUS_DST_ADDR)
      dirprefix = 'd';
   else if (dir == ARGUS_INODE_ADDR)
      dirprefix = 'i';

   if (xlate->fmt_dsr_func) {
      char *key = strrchr(gkey.geoip2_path, ' ');
      int res;

      if (key == NULL)
         key = gkey.geoip2_path;
      else
         key++;

      res = xlate->fmt_dsr_func(parser, argus, entry_data_list, key, dir);
      if (res < 0)
         ArgusLog(LOG_WARNING, "%s: path=\"%s\": DSR formatting function failed\n", __func__, path);
   }
   free(gkey.geoip2_path);
   gkey.geoip2_path = NULL;

   if (is_item_enabled(parser, xlate->item))
      skip = 0;

   /* if no label key or field not requested, continue on to the next
    * list item
    */
   if (skip || xlate->argus_name == NULL) {
      if (entry_data_list)
         entry_data_list = entry_data_list->next;
      goto out;
   }

   switch (entry_data_list->entry_data.type) {
      case MMDB_DATA_TYPE_UTF8_STRING: {
         char *string = mmdb_strndup((char *)entry_data_list->entry_data.utf8_string,
                                             entry_data_list->entry_data.data_size);
         if (NULL == string) {
            *status = MMDB_OUT_OF_MEMORY_ERROR;
            return NULL;
         }
         (void)snprintf_append(str, str_offset, str_remain, "%c%s=%s",
                                 dirprefix, xlate->argus_name, string);
         free(string);
         entry_data_list = entry_data_list->next;
         break;
      }
      case MMDB_DATA_TYPE_BYTES: {
#if 0
         char *hex_string = bytes_to_hex((uint8_t *)entry_data_list->entry_data.bytes,
                                                    entry_data_list->entry_data.data_size);
         if (NULL == hex_string) {
            *status = MMDB_OUT_OF_MEMORY_ERROR;
            return NULL;
         }
         (void)snprintf_append(str, str_offset, str_remain, "%c%s=%s", dirprefix, key.argus_name, hex_string);
         free(hex_string);
#endif
         entry_data_list = entry_data_list->next;
         break;
      }
      case MMDB_DATA_TYPE_DOUBLE: {
         (void)snprintf_append(str, str_offset, str_remain, "%c%s=%f",
                             dirprefix, xlate->argus_name,
                             entry_data_list->entry_data.double_value);
         entry_data_list = entry_data_list->next;
         break;
      }
      case MMDB_DATA_TYPE_FLOAT: {
         (void)snprintf_append(str, str_offset, str_remain, "%c%s=%f",
                             dirprefix, xlate->argus_name,
                             entry_data_list->entry_data.float_value);
         entry_data_list = entry_data_list->next;
         break;
      }
      case MMDB_DATA_TYPE_UINT16: {
         (void)snprintf_append(str, str_offset, str_remain, "%c%s=%u",
                             dirprefix, xlate->argus_name,
                             entry_data_list->entry_data.uint16);
         entry_data_list = entry_data_list->next;
         break;
      }
      case MMDB_DATA_TYPE_UINT32: {
         (void)snprintf_append(str, str_offset, str_remain, "%c%s=%u",
                             dirprefix, xlate->argus_name,
                             entry_data_list->entry_data.uint32);
         entry_data_list = entry_data_list->next;
         break;
      }
      case MMDB_DATA_TYPE_BOOLEAN: {
       (void)snprintf_append(str, str_offset, str_remain, "%c%s=%s",
                             dirprefix, xlate->argus_name,
                             entry_data_list->entry_data.boolean ? "true" : "false");
       entry_data_list = entry_data_list->next;
       break;
      }
      case MMDB_DATA_TYPE_UINT64: {
       (void)snprintf_append(str, str_offset, str_remain, "%c%s=%" PRIu64,
                             dirprefix, xlate->argus_name,
                             entry_data_list->entry_data.uint64);
       entry_data_list = entry_data_list->next;
       break;
      }
      case MMDB_DATA_TYPE_UINT128: {
#if MMDB_UINT128_IS_BYTE_ARRAY
# if 0
         char *hex_string =
             bytes_to_hex((uint8_t *)entry_data_list->entry_data.uint128, 16);
         if (NULL == hex_string) {
             *status = MMDB_OUT_OF_MEMORY_ERROR;
             return NULL;
         }
         (void)snprintf_append(str, str_offset, str_remain, "%c%s=%s",
                             dirprefix, xlate->argus_name, hex_string);
         free(hex_string);
# endif
#else
         uint64_t high = entry_data_list->entry_data.uint128 >> 64;
         uint64_t low = (uint64_t)entry_data_list->entry_data.uint128;
         (void)snprintf_append(str, str_offset, str_remain,
                             "%c%s=0x%016" PRIX64 "%016" PRIX64,
                             dirprefix, xlate->argus_name, high, low);
#endif
         entry_data_list = entry_data_list->next;
         break;
      }
      case MMDB_DATA_TYPE_INT32: {
         (void)snprintf_append(str, str_offset, str_remain, "%c%s=%d",
                             dirprefix, xlate->argus_name,
                             entry_data_list->entry_data.int32);
         entry_data_list = entry_data_list->next;
         break;
      }

      default:
         *status = MMDB_INVALID_DATA_ERROR;
         return NULL;
   }
   (void)snprintf_append(str, str_offset, str_remain, ",");

out:
   *status = MMDB_SUCCESS;
   return entry_data_list;
}

static MMDB_entry_data_list_s *
dump_result_entry_data_list(
    struct ArgusParserStruct *parser,
    struct ArgusRecordStruct *argus,
    MMDB_lookup_result_s *result,
    const char * const path, /* where we are in the data structure, e.g.
                              * "country names"
                              */
    char *str,               /* output string */
    size_t *str_offset,      /* string end pointer (IN/OUT) */
    size_t *str_remain,      /* remaining bytes allocated for string (IN/OUT) */
    int dir,
    int *status)
{
    MMDB_entry_data_list_s *entry_data_list = NULL;
    MMDB_entry_data_list_s *rv = NULL;

   *status = MMDB_get_entry_data_list(&result->entry,
                                     &entry_data_list);
   if (*status != MMDB_SUCCESS) {
       ArgusLog(LOG_WARNING, "%s: MMDB_get_entry_data_list(): %s\n",
                __func__, MMDB_strerror(*status));
       if (entry_data_list)
          MMDB_free_entry_data_list(entry_data_list);
       return NULL;
   }

   if (!entry_data_list) {
       ArgusLog(LOG_WARNING, "%s: entry_data_list is NULL\n",
                __func__);
       return NULL;
   }

   rv = dump_entry_data_list(parser, argus, entry_data_list, path,
                        str, str_offset, str_remain,
                        dir, status);

#ifdef ARGUSDEBUG
   if (*status != MMDB_SUCCESS)
      ArgusDebug(1, "dump_entry_data_list failed, status %d\n", *status);
#endif

   MMDB_free_entry_data_list(entry_data_list);
   return rv;
}

static int
lookup_city(
    struct ArgusParserStruct *parser,
    struct ArgusRecordStruct *argus,
    const char * const path, /* where we are in the data structure, e.g.
                              * "country names"
                              */
    struct sockaddr *sa,
    char *str,               /* output string */
    size_t *str_offset,      /* string end pointer (IN/OUT) */
    size_t *str_remain,      /* remaining bytes allocated for string (IN/OUT) */
    int dir)
{
   int status;
   int mmdb_error;
   MMDB_lookup_result_s result;
   struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;

   result = MMDB_lookup_sockaddr(&labeler->RaGeoIPCityObject, sa, &mmdb_error);
   if (result.found_entry) {
      dump_result_entry_data_list(parser, argus, &result, path, str,
                                  str_offset, str_remain, dir, &status);
      return 1;
   }
   return 0;
}

static int
lookup_asn(
    struct ArgusParserStruct *parser,
    struct ArgusRecordStruct *argus,
    const char * const path, /* where we are in the data structure, e.g.
                              * "country names"
                              */
    struct sockaddr *sa,
    char *str,               /* output string */
    size_t *str_offset,      /* string end pointer (IN/OUT) */
    size_t *str_remain,      /* remaining bytes allocated for string (IN/OUT) */
    int dir)
{
   int status;
   int mmdb_error;
   MMDB_lookup_result_s result;
   struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;

   result = MMDB_lookup_sockaddr(&labeler->RaGeoIPAsnObject, sa, &mmdb_error);
   if (result.found_entry) {
      dump_result_entry_data_list(parser, argus, &result, path, str,
                                  str_offset, str_remain, dir, &status);
      return 1;
   }
   return 0;
}

int
ArgusLabelRecordGeoIP2(struct ArgusParserStruct *parser,
                       struct ArgusRecordStruct *argus,
                       char *label, size_t len,
                       int *found)
{
   size_t str_offset = 0;
   size_t str_remain = len;
   struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];

   if (flow == NULL)
      return 0;

   switch (flow->hdr.subtype & 0x3F) {
      case ARGUS_FLOW_CLASSIC5TUPLE:
      case ARGUS_FLOW_LAYER_3_MATRIX:
         break;
      default:
         return 0;
   }

   /* This array must be sorted so we can use bsearch() */
   if (!_geoip2_to_argus_names_sorted) {
      qsort(geoip2_to_argus_names, geoip2_to_argus_names_len,
            sizeof(geoip2_to_argus_names[0]), geoip2_path_compare);
      _geoip2_to_argus_names_sorted = 1;
   }

   /* iterate through the structure returned by libmaxminddb and add the
    * values we find to the label string.  This is based on the function
    * dump_entry_data_list() in the libmaxminddb source.
    */

   *label = 0;

   switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
      case ARGUS_TYPE_IPV4: {
         struct sockaddr_in addr;

         addr.sin_family = AF_INET;
         addr.sin_port = 0;

         if (labeler->RaLabelGeoIPCity & ARGUS_SRC_ADDR) {
            addr.sin_addr.s_addr = htonl(flow->ip_flow.ip_src);
            lookup_city(parser, argus, "", (struct sockaddr *)&addr,
                        label, &str_offset, &str_remain, ARGUS_SRC_ADDR);

         }
         if (labeler->RaLabelGeoIPAsn & ARGUS_DST_ADDR) {
            addr.sin_addr.s_addr = htonl(flow->ip_flow.ip_src);
            lookup_asn(parser, argus, "", (struct sockaddr *)&addr,
                       label, &str_offset, &str_remain, ARGUS_SRC_ADDR);
         }

         if (labeler->RaLabelGeoIPCity & ARGUS_DST_ADDR) {
            addr.sin_addr.s_addr = htonl(flow->ip_flow.ip_dst);
            lookup_city(parser, argus, "", (struct sockaddr *)&addr,
                        label, &str_offset, &str_remain, ARGUS_DST_ADDR);

         }
         if (labeler->RaLabelGeoIPAsn & ARGUS_DST_ADDR) {
            addr.sin_addr.s_addr = htonl(flow->ip_flow.ip_dst);
            lookup_asn(parser, argus, "", (struct sockaddr *)&addr,
                       label, &str_offset, &str_remain, ARGUS_DST_ADDR);
         }
         if (labeler->RaLabelGeoIPCity & ARGUS_INODE_ADDR) {
            struct ArgusIcmpStruct *icmp;

            icmp = (void *)argus->dsrs[ARGUS_ICMP_INDEX];
            if (icmp != NULL &&
                icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED) {
               addr.sin_addr.s_addr = htonl(icmp->osrcaddr);
               lookup_city(parser, argus, "", (struct sockaddr *)&addr,
                           label, &str_offset, &str_remain, ARGUS_INODE_ADDR);
            }
         }
         if (labeler->RaLabelGeoIPAsn & ARGUS_INODE_ADDR) {
            struct ArgusIcmpStruct *icmp;

            icmp = (void *)argus->dsrs[ARGUS_ICMP_INDEX];
            if (icmp != NULL &&
                icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED) {
               addr.sin_addr.s_addr = htonl(icmp->osrcaddr);
               lookup_asn(parser, argus, "", (struct sockaddr *)&addr,
                          label, &str_offset, &str_remain, ARGUS_INODE_ADDR);
            }
         }
         break;
      }

      case ARGUS_TYPE_IPV6: {
         struct sockaddr_in6 addr;

         addr.sin6_family = AF_INET6;
         addr.sin6_port = 0;

         if (labeler->RaLabelGeoIPCity & ARGUS_SRC_ADDR) {
            memcpy(addr.sin6_addr.s6_addr, flow->ipv6_flow.ip_src,
                   sizeof(addr.sin6_addr.s6_addr));
            lookup_city(parser, argus, "", (struct sockaddr *)&addr,
                        label, &str_offset, &str_remain, ARGUS_SRC_ADDR);
         }
         if (labeler->RaLabelGeoIPAsn) {
            memcpy(addr.sin6_addr.s6_addr, flow->ipv6_flow.ip_src,
                   sizeof(addr.sin6_addr.s6_addr));
            lookup_asn(parser, argus, "", (struct sockaddr *)&addr,
                       label, &str_offset, &str_remain, ARGUS_SRC_ADDR);
         }
         if (labeler->RaLabelGeoIPCity & ARGUS_DST_ADDR) {
            memcpy(addr.sin6_addr.s6_addr, flow->ipv6_flow.ip_dst,
                   sizeof(addr.sin6_addr.s6_addr));
            lookup_city(parser, argus, "", (struct sockaddr *)&addr,
                        label, &str_offset, &str_remain, ARGUS_DST_ADDR);
         }
         if (labeler->RaLabelGeoIPAsn) {
            memcpy(addr.sin6_addr.s6_addr, flow->ipv6_flow.ip_dst,
                   sizeof(addr.sin6_addr.s6_addr));
            lookup_asn(parser, argus, "", (struct sockaddr *)&addr,
                       label, &str_offset, &str_remain, ARGUS_DST_ADDR);
         }
         break;
      }
   }

   if (*label != 0) {
      /* knock off the trailing comma */
      if (str_offset > 0) {
         if (label[str_offset-1] == ',')
            label[str_offset-1] = 0;
      }

      *found = 1;
   }
   return 1;
}

/* return an index into geoip2_to_argus_names[] that holds the entry
 * with name (const char * const)name
 */
int
ArgusGeoIP2FindObject(const char * const name)
{
   size_t i;

   if (!_geoip2_to_argus_names_sorted) {
      qsort(geoip2_to_argus_names, geoip2_to_argus_names_len,
            sizeof(geoip2_to_argus_names[0]), geoip2_path_compare);
      _geoip2_to_argus_names_sorted = 1;
   }

   for (i = 0; i < geoip2_to_argus_names_len; i++) {
      if (!geoip2_to_argus_names[i].argus_name)
         continue;
      if (!strcmp(name, geoip2_to_argus_names[i].argus_name))
         return i;
   }
   return -1;
}

# endif

#endif
