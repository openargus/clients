#ifndef __RABOOTP_PRINT_H
# define __RABOOTP_PRINT_H

# include "argus_parser.h"
# include "argus_print.h"
# include "rabootp_interval_tree.h"

int RabootpPrintDhcp(const struct ArgusParserStruct * const,
                     const struct ArgusDhcpIntvlNode *,
                     size_t, char *, size_t,
                     const struct ArgusFormatterTable * const);

#endif
