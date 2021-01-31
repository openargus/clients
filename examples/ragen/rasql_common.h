#ifndef __RASQL_COMMON_H
# define __RASQL_COMMON_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif

#include <mysql.h>
#include <mysqld_error.h>

# include "argus_util.h"
# include "argus_parser.h"
# include "argus_client.h"
# include "rasplit.h"

#define ARGUSSQLMAXCOLUMNS	256

char **
ArgusCreateSQLTimeTableNames (struct ArgusParserStruct *parser,
                              time_t *ArgusTableStartSecs,
                              time_t *ArgusTableEndSecs,
                              int ArgusSQLSecondsTable,
                              const struct ArgusAdjustStruct * const nadp,
                              const char * const table);

void
RaSQLQueryTable (MYSQL *, const char **, int, int, const char **); 

int
RaSQLManageGetColumns(MYSQL *, const char * const, char **, size_t , size_t *);

void
RaSQLOptimizeTables (MYSQL *, const char **);
#endif
