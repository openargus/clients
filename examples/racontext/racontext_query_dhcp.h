#ifndef __RACONTEXT_QUERY_DHCP_H
# define __RACONTEXT_QUERY_DHCP_H
# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include "argus_util.h"
# include "argus_client.h"
# include "rabootp.h"
# include "argus_dhcp.h"
# include "argus_mysql.h"

void
RacontextQueryDhcpFree(struct ArgusDhcpIntvlNode *nodes, size_t num);

int
RacontextQueryDhcp(const struct ArgusParserStruct * const parser,
                   const struct RaBinProcessStruct * const rpbs,
                   const unsigned char * const clientmac,
                   struct ArgusDhcpIntvlNode **nodes,
                   size_t nleases);
#endif
