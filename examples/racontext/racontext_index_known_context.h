#ifndef __HAVE_RACONTEXT_INDEX_KNOWN_CONTEXT_H
# define __HAVE_RACONTEXT_INDEX_KNOWN_CONTEXT_H
# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif

# include <uuid/uuid.h>
# include "argus_util.h"
# include "argus_client.h"
# include "racontext.h"
# include "argus_mysql.h"

int
RacontextIndexKnownContext(const struct ArgusParserStruct * const parser,
                           const uuid_t nid,
                           const char * const tablename,
                           unsigned total_weight,
                           const char * const indextable,
                           MYSQL *mysql);

int
RacontextIndexSQLCreateTable(const struct ArgusParserStruct * const parser,
                             MYSQL *mysql, const char * const table);

#endif
