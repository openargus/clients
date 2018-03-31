#ifndef __RASQL_COMMON_H
# define __RASQL_COMMON_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif

# include "argus_util.h"
# include "argus_parser.h"
# include "argus_client.h"
# include "rasplit.h"

char **
ArgusCreateSQLTimeTableNames (struct ArgusParserStruct *parser,
                              time_t *ArgusTableStartSecs,
                              time_t *ArgusTableEndSecs,
                              int ArgusSQLSecondsTable,
                              const struct ArgusAdjustStruct * const nadp,
                              const char * const table);

#endif
