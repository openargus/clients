#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <limits.h>
#include <arpa/inet.h>
#include <sys/syslog.h>
#include "argus_util.h"
#include "argus_client.h"
#include "argus_main.h"
#include "rabootp.h"
#include "rabootp_memory.h"
#include "argus_dhcp.h"
#include "racontext_query_dhcp.h"

#if defined(CYGWIN)
# include <sys/cygwin.h>
# define USE_IPV6
#endif

#ifdef ARGUSDEBUG
# define DEBUGLOG(lvl, fmt...) ArgusDebug(lvl, fmt)
#else
# define DEBUGLOG(lvl, fmt...)
#endif

#include "argus_mysql.h"
#include <mysqld_error.h>

void
RacontextQueryDhcpFree(struct ArgusDhcpIntvlNode *nodes, size_t num)
{
   size_t i;

   for (i = 0; i < num; i++)
      ArgusDhcpStructFree(nodes[i].data);
   ArgusFree(nodes);
}

int
RacontextQueryDhcp(const struct ArgusParserStruct * const parser,
                   const struct RaBinProcessStruct * const rbps,
                   const unsigned char * const clientmac,
                   struct ArgusDhcpIntvlNode **nodes,
                   size_t nleases)
{
   static const bool pullup = true;
   int num;

   *nodes = ArgusMalloc(sizeof(**nodes) * nleases);
   if (nodes == NULL) {
      ArgusLog(LOG_ERR, "unable to allocate lease array\n");
      return -1;
   }

   num = ArgusDhcpSqlQuery(ArgusParser, &rbps->nadp, clientmac,
                           "dhcp_summary_%Y_%m_%d", pullup, *nodes, nleases);
   if (num < 0) {
      ArgusLog(LOG_WARNING, "SQL query failed\n");
      RacontextQueryDhcpFree(*nodes, num);
   }

   return num;
}
