#ifndef __RABOOTP_SQL_H
# define __RABOOTP_SQL_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include "argus_util.h"
# include "argus_parser.h"
# include "argus_print.h"
# include "rabootp_interval_tree.h"

# if defined(ARGUS_MYSQL)
int
RabootpSQLCreateTable(const struct ArgusParserStruct * const parser,
                      const char * const table);
int
RabootpSQLInsertOne(const struct ArgusParserStruct * const parser,
                    const struct ArgusDhcpIntvlNode *node,
                    const char * const table);
int
RabootpSQLInsert(const struct ArgusParserStruct * const parser,
                 const struct ArgusDhcpIntvlNode *invec, size_t invec_nitems);
# endif
#endif
