#ifndef __RACONTEXT_ATTRIBUTE_FLOW_H
# define __RACONTEXT_ATTRIBUTE_FLOW_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include "argus_client.h"
# include "argus_parser.h"
# include "rabootp.h"
# include "racontext.h"

int
RacontextAttributeFlowUpdate(struct racontext *ctx,
                             const struct ArgusRecordStruct * const argus);

#endif
