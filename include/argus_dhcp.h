#ifndef __RADHCP_ARGUS_DHCP_H
# define __RADHCP_ARGUS_DHCP_H
# include <stdbool.h>
# include "argus_mysql.h"
# include "argus_util.h"
# include "argus_parser.h"
# include "rabootp_interval_tree.h"

int
ArgusDhcpSqlQueryOneTable(MYSQL_STMT *stmt, MYSQL_BIND *resbind,
                          const char * const query, int querylen,
                          bool *have_resbind, size_t ncols);

int
ArgusDhcpSqlQuery(const struct ArgusParserStruct * const parser,
                  const struct ArgusAdjustStruct * const nadp,
                  const unsigned char * const clientmac,
                  const char * const table, bool pullup,
                  struct ArgusDhcpIntvlNode *nodes, ssize_t nleases);
#endif
