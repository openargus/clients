#ifndef __HAVE_RACONTEXT_INSERT_KNOWN_CONTEXT_H
# define __HAVE_RACONTEXT_INSERT_KNOWN_CONTEXT_H
# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif

# include <uuid/uuid.h>
# include "argus_util.h"
# include "argus_client.h"
# include "racontext.h"
# include "argus_mysql.h"

int
RacontextInsertKnownContext(const struct ArgusParserStruct * const parser,
                            const struct racontext * const ctx,
                            const uuid_t nid, MYSQL *mysql,
                            const char * const table);

int
KnownContextSQLCreateTable(const struct ArgusParserStruct * const parser,
                           MYSQL *mysql, const char * const table);

#endif
