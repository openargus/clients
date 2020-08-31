#ifndef __RACONTEXT_QUERY_KNOWN_CONTEXT_H
# define __RACONTEXT_QUERY_KNOWN_CONTEXT_H
# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include "argus_mysql.h"
# include "racontext.h"

int RacontextQueryKnownContext(MYSQL *mysql, struct racontext *ctx);

#endif
