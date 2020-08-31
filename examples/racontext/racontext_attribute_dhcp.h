#ifndef __RACONTEXT_ATTRIBUTE_DHCP_H
# define __RACONTEXT_ATTRIBUTE_DHCP_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include "rabootp.h"
# include "argus_dhcp.h"
# include "racontext.h"

int
RacontextAttributeDhcpUpdate(struct racontext *ctx,
                             const struct ArgusDhcpIntvlNode * const node);


#endif
