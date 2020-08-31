#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#if defined(ARGUS_MYSQL)
# include "argus_mysql.h"
# include <sys/time.h>
# include <arpa/inet.h>
# include <math.h>
# include <uuid/uuid.h>
# include "argus_print.h"
# include "../radhcp/rabootp_print.h"
# include "../radhcp/rabootp_sql_scan.h"
# include "racontext.h"
# include "racontext_sql_scan.h"

#if 0
int
RacontextSQLScanString(const MYSQL_BIND * const b,
                      const struct ArgusParserStruct * const parser,
                      const struct ArgusPrinterTable * const table_entry,
                      const void * const datum,
                      void *arg)
{
   return RabootpSQLScanString(b, parser, table_entry, datum, arg);
}

int
RacontextSQLScanL2Addr(const MYSQL_BIND * const b,
                       const struct ArgusParserStruct * const parser,
                       const struct ArgusPrinterTable * const table_entry,
                       const void * const datum,
                       void *arg)
{
   struct racontext_attribute *attr = arg;

   if (b->buffer_type != MYSQL_TYPE_STRING ||
       b->buffer_type != MYSQL_TYPE_VAR_STRING)
      return -1;

   if (*b->length < ETH_ALEN || *b->length > sizeof(attr->value_un.l2addr))
      return -1;

   memcpy(attr->value_un.l2addr, b->buffer, *b->length);
   return 0;
}

int
RacontextSQLScanL3Addr(const MYSQL_BIND * const b,
                       const struct ArgusParserStruct * const parser,
                       const struct ArgusPrinterTable * const table_entry,
                       const void * const datum,
                       void *arg)
{
   struct racontext_attribute *attr = arg;
   struct sockaddr_in6 *sin6 = &attr->value_un.l3addr;
   struct sockaddr_in *sin = (struct sockaddr_in *)&attr->value_un.l3addr;

   if (b->buffer_type != MYSQL_TYPE_STRING ||
       b->buffer_type != MYSQL_TYPE_VAR_STRING)
      return -1;

   if (*b->length == sizeof(sin->sin_addr.s_addr)) {
      sin->sin_family = AF_INET;
      memcpy(&sin->sin_addr.s_addr, b->buffer, sizeof(sin->sin_addr.s_addr));
   } else if ( *b->length != sizeof(sin6->sin6_addr.s6_addr)) {
      sin6->sin6_family = AF_INET6;
      memcpy(&sin6->sin6_addr.s6_addr, b->buffer,
             sizeof(sin6->sin6_addr.s6_addr));
   } else {
      return -1;
   }
   return 0;
}

int
RacontextSQLScanUint8(const MYSQL_BIND * const b,
                      const struct ArgusParserStruct * const parser,
                      const struct ArgusPrinterTable * const table_entry,
                      const void * const datum,
                      void *arg)
{
   return RabootpSQLScanUint8(b, parser, table_entry, datum, arg);
}

/* RacontextSQLScanVal() depends on attr->attrib_num having a valid
 * value matching the current row's value type.
 */
int
RacontextSQLScanVal(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg)
{
   struct racontext_attribute *attr = arg;

   switch (attr->attrib_num) {
      case CTX_ATTRIB_BSSID:
      case CTX_ATTRIB_DHCP_SERVER_MAC:
      case CTX_ATTRIB_NEXT_HOP_MAC:
      case CTX_ATTRIB_IGMP_QUERIER_MAC:
      case CTX_ATTRIB_MCAST_SOURCE_MAC:
      case CTX_ATTRIB_BCAST_SOURCE_MAC:
      case CTX_ATTRIB_MCAST_DEST_MAC:
         return RacontextSQLScanL2Addr(b, parser, table_entry, datum, arg);

      case CTX_ATTRIB_SLAAC_PREFIX:
      case CTX_ATTRIB_DHCP_DNS_SERVER:
      case CTX_ATTRIB_DHCP_NEXTHOP:
      case CTX_ATTRIB_IGMP_QUERIER_ADDRESS:
         return RacontextSQLScanL3Addr(b, parser, table_entry, datum, arg);

      case CTX_ATTRIB_DHCP_DNS_DOMAIN:
      case CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME:
         return RacontextSQLScanString(b, parser, table_entry, datum,
                                       &attr->value_un.name);
   }
   return -1;
}
#endif

int
RacontextSQLScanInt32(const MYSQL_BIND * const b,
                      const struct ArgusParserStruct * const parser,
                      const struct ArgusPrinterTable * const table_entry,
                      const void * const datum,
                      void *arg)
{
   int32_t val;

   if (!IS_NUM(b->buffer_type)) {
      DEBUGLOG(2, "%s: value provided for %s is not a number\n", __func__,
               table_entry->label);
      return -1;
   }

   if (b->is_unsigned) {
      DEBUGLOG(2, "%s: value provided for %s is unsigned\n", __func__,
               table_entry->label);
      return -1;
   }

   switch (*b->length) {
      case 1:
         val = *(int8_t *)b->buffer & 0xff;
         break;
      case 2:
         val = *(int16_t *)b->buffer & 0xffff;
         break;
      case 4:
         val = *(int32_t *)b->buffer & 0xffffffff;
         break;
      case 8:
         val = *(int64_t *)b->buffer & 0xffffffff;
         break;
      default:
         DEBUGLOG(2, "%s: unknown integer size %lu for %s\n", __func__,
                  *b->length, table_entry->label);
   }

   *(int32_t *)arg = val;
   return 0;
}

int
RacontextSQLScanInt64(const MYSQL_BIND * const b,
                      const struct ArgusParserStruct * const parser,
                      const struct ArgusPrinterTable * const table_entry,
                      const void * const datum,
                      void *arg)
{
   int64_t val;

   if (!IS_NUM(b->buffer_type)) {
      DEBUGLOG(2, "%s: value provided for %s is not a number\n", __func__,
               table_entry->label);
      return -1;
   }

   if (b->is_unsigned) {
      DEBUGLOG(2, "%s: value provided for %s is unsigned\n", __func__,
               table_entry->label);
      return -1;
   }

   switch (*b->length) {
      case 1:
         val = *(int8_t *)b->buffer & 0xff;
         break;
      case 2:
         val = *(int16_t *)b->buffer & 0xffff;
         break;
      case 4:
         val = *(int32_t *)b->buffer & 0xffffffff;
         break;
      case 8:
         val = *(int64_t *)b->buffer;
         break;
      default:
         DEBUGLOG(2, "%s: unknown integer size %lu for %s\n", __func__,
                  *b->length, table_entry->label);
   }

   *(int64_t *)arg = val;
   return 0;
}

int
RacontextSQLScanUuid(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg)
{
   uuid_t *uuid = arg;

   if (b->buffer_type != MYSQL_TYPE_STRING)
      return -1;

   if (*b->length != sizeof(*uuid))
      return -1;

   memcpy(uuid, b->buffer, sizeof(*uuid));
   return 0;
}

#endif
