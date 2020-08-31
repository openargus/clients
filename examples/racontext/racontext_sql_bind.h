#ifndef __RACONTEXT_SQL_BIND_H
# define __RACONTEXT_SQL_BIND_H

# ifdef HAVE_CONFIG_H
# include "argus_config.h"
# endif
# if defined(ARGUS_MYSQL)
#  include "argus_mysql.h"
#  include <sys/time.h>
#  include <arpa/inet.h>
#  include "argus_print.h"
#  include "rabootp_print.h"

int
RacontextSQLBindString(MYSQL_BIND *b,
                      const struct ArgusParserStruct * const parser,
                      const struct ArgusPrinterTable * const table_entry,
                      const void * const datum,
                      const struct ArgusFormatterTable * const fmtable);

int
RacontextSQLBindIdx(MYSQL_BIND * b,
                    const struct ArgusParserStruct * const parser,
                    const struct ArgusPrinterTable * const table_entry,
                    const void * const datum,
                    const struct ArgusFormatterTable * const fmtable);

int
RacontextSQLBindPrefixlen(MYSQL_BIND * b,
                          const struct ArgusParserStruct * const parser,
                          const struct ArgusPrinterTable * const table_entry,
                          const void * const datum,
                          const struct ArgusFormatterTable * const fmtable);

int
RacontextSQLBindValue(MYSQL_BIND * b,
                      const struct ArgusParserStruct * const parser,
                      const struct ArgusPrinterTable * const table_entry,
                      const void * const datum,
                      const struct ArgusFormatterTable * const fmtable);

int
RacontextSQLBindUuid(MYSQL_BIND * b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     const struct ArgusFormatterTable * const fmtable);

# endif
#endif
