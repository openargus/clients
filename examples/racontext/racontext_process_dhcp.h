#ifndef __RACONTEXT_PROCESS_DHCP_H
# define __RACONTEXT_PROCESS_DHCP_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include "argus_util.h"
# include "argus_parser.h"
# include "argus_mysql.h"
# include "racontext.h"

int
RacontextProcessDhcp(const struct ArgusParserStruct * const parser,
                      const configuration_t * const config,
                      struct RaBinProcessStruct *rbps,
                      struct sid_tree *RacontextSidtree, MYSQL *RaMySQL);


#endif
