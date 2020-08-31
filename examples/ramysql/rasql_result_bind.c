#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#if defined(ARGUS_MYSQL)
# include <stdio.h>
# include <sys/time.h>
# include <sys/syslog.h>
# include "argus_util.h"
# include "argus_client.h"
# include "argus_mysql.h"
# include "rasql_result_bind.h"

void
RaSQLResultBindFreeOne(MYSQL_BIND *b)
{
   if (b->buffer)
      ArgusFree(b->buffer);

   b->buffer = NULL;

   if (b->length)
      ArgusFree(b->length);

   b->length = NULL;
}

void
RaSQLResultBindFree(MYSQL_BIND *b, int nfields)
{
   int i;

   for (i = 0; i < nfields; i++)
      RaSQLResultBindFreeOne(&b[i]);
}

/* RaSQLResultBindOne:
 *
 * Given a field description from mysql_fetch_fields(), create a bind
 * structure for receiving binary data from the server.  An array of
 * these MYSQL_BIND structures can be passed to mysql_stmt_bind_result()
 * when "SELECT" is in a prepared statement.
 */
int
RaSQLResultBindOne(MYSQL_BIND *b, const MYSQL_FIELD * const field)
{
   char *buffer;
   unsigned long *length;
   unsigned long bytes;

   switch(field->type) {
      case MYSQL_TYPE_TINY:
         bytes = sizeof(signed char);
         break;
      case MYSQL_TYPE_SHORT:
         bytes = sizeof(short int);
         break;
      case MYSQL_TYPE_BIT:
      case MYSQL_TYPE_LONG:
      case MYSQL_TYPE_INT24:
         bytes = sizeof(int);
         break;
      case MYSQL_TYPE_LONGLONG:
         bytes = sizeof(long long int);
         break;
      case MYSQL_TYPE_FLOAT:
         bytes = sizeof(float);
         break;
      case MYSQL_TYPE_DOUBLE:
         bytes = sizeof(double);
         break;
      case MYSQL_TYPE_TIME:
      case MYSQL_TYPE_DATE:
      case MYSQL_TYPE_DATETIME:
      case MYSQL_TYPE_TIMESTAMP:
         bytes = sizeof(MYSQL_TIME);
         break;
      case MYSQL_TYPE_TINY_BLOB:
         bytes = 1 << 8;
         break;
      case MYSQL_TYPE_BLOB:
         bytes = 1 << 16;
         break;
      case MYSQL_TYPE_MEDIUM_BLOB:
         bytes = 1 << 24;
         break;
      case MYSQL_TYPE_STRING:
      case MYSQL_TYPE_VAR_STRING:
         bytes = RASQL_MAX_VARCHAR;
         break;
      case MYSQL_TYPE_LONG_BLOB:
         /* fall through - we don't do anything that would put 4 GB in a
          * SQL record.
          */
      default:
         ArgusLog(LOG_INFO, "unable to handle mysql type %d\n", field->type);
         return -1;
   }

   buffer = ArgusMalloc(bytes);
   length = ArgusMalloc(sizeof(*length));

   if (buffer == NULL)
      goto err;

   if (length == NULL)
      goto err;

   b->buffer_type = field->type;
   b->buffer_length = bytes;
   b->buffer = buffer;
   b->is_null = 0;
   b->is_unsigned = (field->flags & UNSIGNED_FLAG) ? 1 : 0;
   b->length = length;

   return 0;

err:
   if (buffer)
      ArgusFree(buffer);
   if (length)
      ArgusFree(length);

   return -1;
}

/* RaSQLResultBind:
 *
 * Given an array of field descriptions from mysql_fetch_fields(), create
 * an array of bind structures for receiving binary data from the server.
 * This array can be passed to mysql_stmt_bind_result() when "SELECT"
 * is in a prepared statement.
 */
int
RaSQLResultBind(MYSQL_BIND *b, const MYSQL_FIELD * const field, int nfields)
{
   int i;
   int rv = 0;

   for (i = 0; rv == 0 && i < nfields; i++)
      rv = RaSQLResultBindOne(&b[i], &field[i]);

   return rv;
}
#endif
