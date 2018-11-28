#ifndef __RABOOTP_SQL_BIND_H
# define __RABOOTP_SQL_BIND_H

# if defined(ARGUS_MYSQL)
#  include <sys/time.h>
#  include "argus_mysql.h"
#  include "argus_print.h"
#  include "rabootp_print.h"

#  define RASQL_MAX_COLUMNS     64
#  define RASQL_MAX_VARCHAR     128

void RabootpSQLBindFree(MYSQL_BIND *b);

int RabootpSQLBindString(MYSQL_BIND *b,
                         const struct ArgusParserStruct * const parser,
                         const struct ArgusPrinterTable * const table_entry,
                         const void * const datum,
                         const struct ArgusFormatterTable * const fmtable);

int RabootpSQLBindUnsigned(MYSQL_BIND *b,
                           const struct ArgusParserStruct * const parser,
                           const struct ArgusPrinterTable * const table_entry,
                           const void * const datum,
                           const struct ArgusFormatterTable * const fmtable);

int RabootpSQLBindTiny(MYSQL_BIND *b,
                       const struct ArgusParserStruct * const parser,
                       const struct ArgusPrinterTable * const table_entry,
                       const void * const datum,
                       const struct ArgusFormatterTable * const fmtable);

int RabootpSQLBindTimeval(MYSQL_BIND *b,
                          const struct ArgusParserStruct * const parser,
                          const struct ArgusPrinterTable * const table_entry,
                          const void * const datum,
                          const struct ArgusFormatterTable * const fmtable);

#endif /* ARGUS_MYSQL */
#endif /* __RABOOTP_SQL_BIND_H */
