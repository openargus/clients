#ifndef ARGUS_MYSQL_H
# define ARGUS_MYSQL_H
# ifdef ARGUS_MYSQL
#  ifdef HAVE_STDBOOL_H
#   include <stdbool.h>
#  endif
#  include <mysql.h>
#  ifndef HAVE_MYSQL_MY_BOOL
#   define my_bool bool
#  endif
#  define RASQL_MAX_VARCHAR     128
# endif /* ARGUS_MYSQL*/
#endif /* ARGUS_MYSQL_H */
