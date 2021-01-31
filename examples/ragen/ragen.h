#ifndef __CLIENTS_RAGEN_H
# define __CLIENTS_RAGEN_H
# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif

typedef struct RaGenConfig {
   char *baseline;
   struct timeval startime;
   double interval;
   double duration;
} ragen_config_t;


#endif
