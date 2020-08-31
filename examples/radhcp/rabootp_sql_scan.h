#ifndef __RABOOTP_SQL_SCAN_H
# define __RABOOTP_SQL_SCAN_H

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
RabootpSQLScanString(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg);

int
RabootpSQLScanL2Addr(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg);

int
RabootpSQLScanL3Addr(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg);

int
RabootpSQLScanUint8(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg);

int
RabootpSQLScanUint32(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg);

int
RabootpSQLScanTimeval(const MYSQL_BIND * const b,
                     const struct ArgusParserStruct * const parser,
                     const struct ArgusPrinterTable * const table_entry,
                     const void * const datum,
                     void *arg);

# endif /* ARGUS_MYSQL */
#endif
