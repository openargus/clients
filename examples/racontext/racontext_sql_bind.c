#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#if defined(ARGUS_MYSQL)
# include "argus_mysql.h"
# include <sys/time.h>
# include <arpa/inet.h>
# include <net/ethernet.h>
# include <math.h>
# include <uuid/uuid.h>
# include "argus_print.h"
# include "../radhcp/rabootp_print.h"
# include "racontext.h"
# include "racontext_sql_bind.h"

int
RacontextSQLBindString(MYSQL_BIND *b,
                      const struct ArgusParserStruct * const parser,
                      const struct ArgusPrinterTable * const table_entry,
                      const void * const datum,
                      const struct ArgusFormatterTable * const fmtable)
{
   char *buffer = ArgusMalloc(RACONTEXT_VALUE_NAMELEN);
   unsigned long *length = ArgusMalloc(sizeof(*length));
   ssize_t slength;
   const char * const str = *(const char ** const)datum;

   if (buffer == NULL)
      goto err;

   if (length == NULL)
      goto err;

   slength = snprintf(buffer, RACONTEXT_VALUE_NAMELEN, "%s", str);

   if (slength < 0)
      goto err;

   if (slength >= RACONTEXT_VALUE_NAMELEN)
      goto err;

   *length = (unsigned long)slength;

   b->buffer_type = MYSQL_TYPE_VAR_STRING;
   b->buffer_length = RACONTEXT_VALUE_NAMELEN;
   b->buffer = buffer;
   b->is_null = 0;
   b->length = length;

   return 0;

err:
   if (buffer)
      ArgusFree(buffer);
   if (length)
      ArgusFree(length);

   return -1;
}

static int
RacontextSQLBindL2Addr(MYSQL_BIND * b,
                       const struct ArgusParserStruct * const parser,
                       const struct ArgusPrinterTable * const table_entry,
                       const struct racontext_attribute * const attr,
                       const struct ArgusFormatterTable * const fmtable)
{
   char *buffer = ArgusMalloc(sizeof(attr->value_un.l2addr));
   unsigned long *length = ArgusMalloc(sizeof(*length));

   if (buffer == NULL)
      goto err;

   if (length == NULL)
      goto err;

   *length = ETH_ALEN;
   memcpy(buffer, attr->value_un.l2addr, ETH_ALEN);

   b->buffer_type = MYSQL_TYPE_VAR_STRING;
   b->buffer_length = sizeof(attr->value_un.l2addr);
   b->buffer = buffer;
   b->is_null = 0;
   b->length = length;

   return 0;

err:
   if (buffer)
      ArgusFree(buffer);
   if (length)
      ArgusFree(length);

   return -1;
}

static int
RacontextSQLBindL3Addr(MYSQL_BIND * b,
                       const struct ArgusParserStruct * const parser,
                       const struct ArgusPrinterTable * const table_entry,
                       const struct racontext_attribute * const attr,
                       const struct ArgusFormatterTable * const fmtable)
{
   char *buffer = ArgusMalloc(sizeof(attr->value_un.l3addr.sin6_addr.s6_addr));
   unsigned long *length = ArgusMalloc(sizeof(*length));
   struct sockaddr_in *sin = (struct sockaddr_in *)&attr->value_un.l3addr;

   if (buffer == NULL)
      goto err;

   if (length == NULL)
      goto err;

   if (attr->value_un.l3addr.sin6_family == AF_INET6) {
      *length = sizeof(attr->value_un.l3addr.sin6_addr.s6_addr);
      memcpy(buffer, &attr->value_un.l3addr.sin6_addr.s6_addr, *length);
   } else if (attr->value_un.l3addr.sin6_family == AF_INET) {
      *length = sizeof(sin->sin_addr.s_addr);
      memcpy(buffer, &sin->sin_addr.s_addr, *length);
   } else
      goto err;

   b->buffer_type = MYSQL_TYPE_VAR_STRING;
   b->buffer_length = *length;
   b->buffer = buffer;
   b->is_null = 0;
   b->length = length;

   return 0;

err:
   if (buffer)
      ArgusFree(buffer);
   if (length)
      ArgusFree(length);

   return -1;
}

int
RacontextSQLBindIdx(MYSQL_BIND * b,
                    const struct ArgusParserStruct * const parser,
                    const struct ArgusPrinterTable * const table_entry,
                    const void * const datum,
                    const struct ArgusFormatterTable * const fmtable)
{
   const struct racontext_attribute * const attr =
    *(const struct racontext_attribute ** const)datum;
   int32_t *i = ArgusMalloc(sizeof(*i));

   if (i == NULL)
      return -1;

   *i = attr->attrib_num;
   b->buffer_type = MYSQL_TYPE_LONG;
   b->buffer = i;
   b->is_unsigned = 0;

   return 0;
}

int
RacontextSQLBindPrefixlen(MYSQL_BIND * b,
                          const struct ArgusParserStruct * const parser,
                          const struct ArgusPrinterTable * const table_entry,
                          const void * const datum,
                          const struct ArgusFormatterTable * const fmtable)
{
   const struct racontext_attribute * const attr =
    *(const struct racontext_attribute ** const)datum;
   uint8_t *i = ArgusMalloc(sizeof(*i));

   if (i == NULL)
      return -1;

   *i = attr->prefixlen;
   b->buffer_type = MYSQL_TYPE_TINY;
   b->buffer = i;
   b->is_unsigned = 1;

   return 0;
}


int
RacontextSQLBindValue(MYSQL_BIND * b,
                      const struct ArgusParserStruct * const parser,
                      const struct ArgusPrinterTable * const table_entry,
                      const void * const datum,
                      const struct ArgusFormatterTable * const fmtable)
{
   const struct racontext_attribute * const attr =
    *(const struct racontext_attribute ** const)datum;
   int rv = -1;

   switch (attr->attrib_num) {
      case CTX_ATTRIB_BSSID:
      case CTX_ATTRIB_DHCP_SERVER_MAC:
      case CTX_ATTRIB_NEXT_HOP_MAC:
      case CTX_ATTRIB_IGMP_QUERIER_MAC:
      case CTX_ATTRIB_MCAST_SOURCE_MAC:
      case CTX_ATTRIB_BCAST_SOURCE_MAC:
      case CTX_ATTRIB_MCAST_DEST_MAC:
         rv = RacontextSQLBindL2Addr(b, parser, table_entry, attr, fmtable);
         break;

      case CTX_ATTRIB_SLAAC_PREFIX:
      case CTX_ATTRIB_DHCP_DNS_SERVER:
      case CTX_ATTRIB_DHCP_NEXTHOP:
      case CTX_ATTRIB_IGMP_QUERIER_ADDRESS:
         rv = RacontextSQLBindL3Addr(b, parser, table_entry, attr, fmtable);
         break;

      case CTX_ATTRIB_DHCP_DNS_DOMAIN:
      case CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME:
         rv = RacontextSQLBindString(b, parser, table_entry,
                                     &attr->value_un.name, fmtable);
         break;
   }
   return rv;
}

int
RacontextSQLBindUuid(MYSQL_BIND * b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     const struct ArgusFormatterTable * const fmtable)
{
   char *buffer = ArgusMalloc(sizeof(uuid_t));
   unsigned long *length = ArgusMalloc(sizeof(*length));

   if (buffer == NULL)
      goto err;

   if (length == NULL)
      goto err;

   memcpy(buffer, datum, sizeof(uuid_t));

   *length = sizeof(uuid_t);

   b->buffer_type = MYSQL_TYPE_STRING;
   b->buffer_length = *length;
   b->buffer = buffer;
   b->is_null = 0;
   b->length = length;

   return 0;

err:
   if (buffer)
      ArgusFree(buffer);
   if (length)
      ArgusFree(length);

   return -1;
}
#endif
