#ifndef __RABOOTP_PRINT_H
# define __RABOOTP_PRINT_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include "argus_parser.h"
# include "argus_print.h"
# include "rabootp_interval_tree.h"

ssize_t
RabootpPrintField(const struct ArgusParserStruct * const,
                  const struct ArgusPrinterTable * const,
                  const void * const,
                  char *, size_t,
                  const struct ArgusFormatterTable * const);

int RabootpPrintDhcp(const struct ArgusParserStruct * const,
                     const struct ArgusDhcpIntvlNode *,
                     size_t, char *, size_t,
                     const struct ArgusFormatterTable * const);

unsigned RabootpPrintMaxFields(void);

# if defined(ARGUS_MYSQL)
int RabootpPrintLabelSQL(const struct ArgusParserStruct * const,
                    const char **, size_t);
int RabootpPrintSQL(const struct ArgusParserStruct * const,
                    const struct ArgusDhcpIntvlNode *,
                    MYSQL_BIND *, size_t);
int RabootpPrintTypeSQL(const struct ArgusParserStruct * const parser,
                        const char **typevec, size_t nitems);

# endif
#endif
