#ifndef __RABOOTP_SQL_RESULT_BIND_H
# define __RABOOTP_SQL_RESULT_BIND_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# if defined(ARGUS_MYSQL)
#  include "argus_mysql.h"

void RaSQLResultBindFreeOne(MYSQL_BIND *);
void RaSQLResultBindFree(MYSQL_BIND *, int);
int RaSQLResultBindOne(MYSQL_BIND *, const MYSQL_FIELD * const);
int RaSQLResultBind(MYSQL_BIND *, const MYSQL_FIELD * const, int);

# endif /* ARGUS_MYSQL */
#endif
