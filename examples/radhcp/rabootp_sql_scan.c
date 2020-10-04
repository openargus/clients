/*
 * Functions to take data from MySQL and put them back into
 * 'ArgusDhcpStruct's.
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#if defined(ARGUS_MYSQL)
# include "argus_mysql.h"
# include <sys/time.h>
# include <arpa/inet.h>
# include <math.h>
# include "argus_print.h"
# include "rabootp_print.h"
# include "rabootp_sql_scan.h"


int
RabootpSQLScanString(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg)
{
   char **str = arg;
   ssize_t slength;

   if (b->length == NULL)
      goto err;

   *str = ArgusMalloc((*b->length)+1);
   if (*str == NULL)
      goto err;

   slength = snprintf(*str, (*b->length)+1, "%s", (char *)b->buffer);
   if (slength < 0)
      goto err;

   return 0;

err:
   if (*str) {
      ArgusFree(*str);
      *str = NULL;
   }
   return -1;
}

/* void *arg points to an array of 16 unsigned chars, rather than a
 * malloc'd pointer
 */
int
RabootpSQLScanL2Addr(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg)
{
   if (b->buffer_type != MYSQL_TYPE_STRING && b->buffer_type != MYSQL_TYPE_VAR_STRING)
      return -1;

   return __ether_aton((const char * const)b->buffer, (unsigned char *)arg);
}

int
RabootpSQLScanL3Addr(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg)
{
   int rv;

   if (b->buffer_type != MYSQL_TYPE_STRING && b->buffer_type != MYSQL_TYPE_VAR_STRING)
      return -1;

   rv = inet_pton(AF_INET, (const char *)b->buffer, arg);
   if (rv == 1)
      *(uint32_t *)arg = htonl(*(uint32_t *)arg);

   return (rv == 1) ? 0 : -1;
}

int
RabootpSQLScanUint8(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg)
{
   uint8_t val;

   if (!IS_NUM(b->buffer_type)) {
      DEBUGLOG(2, "%s: value provided for %s is not a number\n", __func__,
               table_entry->label);
      return -1;
   }

   if (!b->is_unsigned) {
      DEBUGLOG(2, "%s: value provided for %s is signed\n", __func__,
               table_entry->label);
      return -1;
   }

   switch (*b->length) {
      case 1:
         val = *(uint8_t *)b->buffer & 0xff;
         break;
      case 2:
         val = *(uint16_t *)b->buffer & 0xff;
         break;
      case 4:
         val = *(uint32_t *)b->buffer & 0xff;
         break;
      case 8:
         val = *(uint64_t *)b->buffer & 0xff;
         break;
      default:
         DEBUGLOG(2, "%s: unknown integer size %lu for %s\n", __func__,
                  *b->length, table_entry->label);
         return -1;
         break;
   }

   *(uint8_t *)arg = val;
   return 0;
}

int
RabootpSQLScanUint32(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg)
{
   uint32_t val;

   if (!IS_NUM(b->buffer_type)) {
      DEBUGLOG(2, "%s: value provided for %s is not a number\n", __func__,
               table_entry->label);
      return -1;
   }

   if (!b->is_unsigned) {
      DEBUGLOG(2, "%s: value provided for %s is signed\n", __func__,
               table_entry->label);
      return -1;
   }

   switch (*b->length) {
      case 1:
         val = *(uint8_t *)b->buffer & 0xff;
         break;
      case 2:
         val = *(uint16_t *)b->buffer & 0xffff;
         break;
      case 4:
         val = *(uint32_t *)b->buffer & 0xffffffff;
         break;
      case 8:
         val = *(uint64_t *)b->buffer & 0xffffffff;
         break;
      default:
         DEBUGLOG(2, "%s: unknown integer size %lu for %s\n", __func__,
                  *b->length, table_entry->label);
         return -1;
         break;
   }

   *(uint32_t *)arg = val;
   return 0;
}

int
RabootpSQLScanTimeval(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg)
{
   double val;
   double ipart; /* integer */
   double fpart; /* fraction */
   struct timeval tv;

   /* Right now, let's just support getting this from a floating point
    * value of some sort.  Can add integer and mysql time types later.
    */

   if (b->buffer_type != MYSQL_TYPE_FLOAT && b->buffer_type != MYSQL_TYPE_DOUBLE)
      return -1;

   if (*b->length == sizeof(double))
      val = *(double *)b->buffer;
   else if (*b->length == sizeof(float))
      val = *(float *)b->buffer;
   else
      return -1;

   fpart = modf(val, &ipart);
   tv.tv_sec = (time_t)ipart;
   tv.tv_usec = fpart * 1000;
   *(struct timeval *)arg = tv;

   return 0;
}

#endif /* ARGUS_MYSQL */
