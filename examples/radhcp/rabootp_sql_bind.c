#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#if defined(ARGUS_MYSQL)
# include "argus_mysql.h"
# include <sys/time.h>
# include "argus_print.h"
# include "rabootp_print.h"
# include "rabootp_sql_bind.h"

void
RabootpSQLBindFree(MYSQL_BIND *b)
{
   if (b->buffer)
      ArgusFree(b->buffer);

   b->buffer = NULL;

   if (b->length)
      ArgusFree(b->length);

   b->length = NULL;
}

int
RabootpSQLBindString(MYSQL_BIND *b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     const struct ArgusFormatterTable * const fmtable)
{
   char *buffer = ArgusMalloc(RASQL_MAX_VARCHAR);
   unsigned long *length = ArgusMalloc(sizeof(*length)); 
   ssize_t slength;

   if (buffer == NULL)
      goto err;

   if (length == NULL)
      goto err;

   /* ArgusPrintField() will add the offset to datum, so we have to
    * undo it here first.  Need to find a better way.
    */
   slength = RabootpPrintField(parser, table_entry,
                               ((char *)datum)-(table_entry->offset),
                               buffer, RASQL_MAX_VARCHAR,
                               &ArgusSQLFormatterTable);

   if (slength < 0)
      goto err;

   *length = (unsigned long)slength;

   b->buffer_type = MYSQL_TYPE_STRING;
   b->buffer_length = RASQL_MAX_VARCHAR;
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
RabootpSQLBindUnsigned(MYSQL_BIND *b,
                       const struct ArgusParserStruct * const parser,
                       const struct ArgusPrinterTable * const table_entry,
                       const void * const datum,
                       const struct ArgusFormatterTable * const fmtable)
{
   uint32_t *u = ArgusMalloc(sizeof(*u));

   if (u == NULL)
      return -1;

   *u = *(uint32_t *)datum;
   b->buffer_type = MYSQL_TYPE_LONG;
   b->buffer = u;
   b->is_unsigned = 1;

   return 0;
}

int
RabootpSQLBindTiny(MYSQL_BIND *b,
                   const struct ArgusParserStruct * const parser,
                   const struct ArgusPrinterTable * const table_entry,
                   const void * const datum,
                   const struct ArgusFormatterTable * const fmtable)
{
   uint8_t *u = ArgusMalloc(sizeof(*u));

   if (u == NULL)
      return -1;

   *u = *(uint8_t *)datum;
   b->buffer_type = MYSQL_TYPE_TINY;
   b->buffer = u;
   b->is_unsigned = 1;

   return 0;
}

int
RabootpSQLBindTimeval(MYSQL_BIND *b,
                      const struct ArgusParserStruct * const parser,
                      const struct ArgusPrinterTable * const table_entry,
                      const void * const datum,
                      const struct ArgusFormatterTable * const fmtable)
{
   double *d = ArgusMalloc(sizeof(*d));
   const struct timeval * const tv = datum;

   if (d == NULL)
      return -1;

   *d = 1.*tv->tv_sec + (1.*tv->tv_usec)/1000000.;

   b->buffer_type = MYSQL_TYPE_DOUBLE;
   b->buffer = d;
   b->is_unsigned = 1;

   return 0;
}

#endif /* ARGUS_MYSQL */
