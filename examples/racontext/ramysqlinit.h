#ifndef __RACONTEXT_RAMYSQLINIT_H
# define __RACONTEXT_RAMYSQLINIT_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include "argus_util.h"
# include "argus_parser.h"

int RaMySQLGetMaxPacketSize(void);
void RaMySQLInit(struct ArgusParserStruct *);

#endif
