#ifndef __RADHCP_RASQL_H
# define __RADHCP_RASQL_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include <argus_compat.h>
# include <argus_util.h>
# include <argus_client.h>

void RaMySQLInit (void);

char *
ArgusCreateSQLSaveTableName(struct ArgusParserStruct *parser,
                            struct ArgusRecordStruct *ns, char *table);

int
ArgusCreateSQLSaveTable(char *db, char *table);

#endif
