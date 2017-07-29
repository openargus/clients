#ifndef __RABOOTP_QUERYSTR_H
# define __RABOOTP_QUERYSTR_H

# include <sys/types.h>

struct QueryOptsStruct {
   const char *lhs;
   unsigned has_argument;
};

# define RABOOTP_QS_UNKNOWN 1
# define RABOOTP_QS_NEEDARG 2

int
RabootpParseQueryString(const struct QueryOptsStruct * const qopts,
                        size_t nqopts, char *in, char *parsed[]);

#endif
