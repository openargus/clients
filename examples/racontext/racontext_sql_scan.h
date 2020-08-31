#ifndef __RACONTEXT_SQL_SCAN_H
# define __RACONTEXT_SQL_SCAN_H

# ifdef HAVE_CONFIG_H
# include "argus_config.h"
# endif
# if defined(ARGUS_MYSQL)
#  include "argus_mysql.h"
#  include <sys/time.h>
#  include <arpa/inet.h>
#  include "argus_print.h"
#  include "rabootp_print.h"

#  if 0
int RacontextSQLScanString(const MYSQL_BIND * const b,
                           const struct ArgusParserStruct * const parser,
                           const struct ArgusPrinterTable * const table_entry,
                           const void * const datum,
                           void *arg);

int RacontextSQLScanL2Addr(const MYSQL_BIND * const b,
                           const struct ArgusParserStruct * const parser,
                           const struct ArgusPrinterTable * const table_entry,
                           const void * const datum,
                           void *arg);

int RacontextSQLScanL3Addr(const MYSQL_BIND * const b,
                           const struct ArgusParserStruct * const parser,
                           const struct ArgusPrinterTable * const table_entry,
                           const void * const datum,
                           void *arg);

int RacontextSQLScanUint8(const MYSQL_BIND * const b,
                          const struct ArgusParserStruct * const parser,
                          const struct ArgusPrinterTable * const table_entry,
                          const void * const datum,
                          void *arg);

int RacontextSQLScanVal(const MYSQL_BIND * const b,
                        const struct ArgusParserStruct * const parser,
                        const struct ArgusPrinterTable * const table_entry,
                        const void * const datum,
                        void *arg);
#  endif /* 0 */

int RacontextSQLScanInt32(const MYSQL_BIND * const b,
                          const struct ArgusParserStruct * const parser,
                          const struct ArgusPrinterTable * const table_entry,
                          const void * const datum,
                          void *arg);

int RacontextSQLScanInt64(const MYSQL_BIND * const b,
                          const struct ArgusParserStruct * const parser,
                          const struct ArgusPrinterTable * const table_entry,
                          const void * const datum,
                          void *arg);

int RacontextSQLScanUuid(const MYSQL_BIND * const b,
                         const struct ArgusParserStruct * const parser,
                         const struct ArgusPrinterTable * const table_entry,
                         const void * const datum,
                         void *arg);

# endif
#endif
