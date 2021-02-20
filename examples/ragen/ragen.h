#ifndef __CLIENTS_RAGEN_H
# define __CLIENTS_RAGEN_H
# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif

#include <rabins.h>

#define RA_IDLE                 0
#define RA_ACTIVE               1
#define RA_SORTING              2

typedef struct ArgusGenConfig {
   struct ArgusQueueHeader qhdr;
   struct ArgusQueueStruct *queue;

#if defined(ARGUS_THREADS)
   pthread_t tid;
   pthread_mutex_t lock;
#endif

   int status, type, mode, index;
   char *baseline;
   struct timeval startime;
   char *interval;
   double duration;

   struct ArgusInput *input;
   struct ArgusFileInput *finput;
/*
   FILE *file;
   long long ostart;
   long long ostop;
   int type;
   int fd;
   struct stat statbuf;
*/
} ragen_config_t;


struct ArgusGenerator {
   struct ArgusListObjectStruct *nxt, *prv;
   int status, type, mode, index;

#if defined(ARGUS_THREADS)
   pthread_t tid;
   pthread_mutex_t lock;
#endif

   struct ArgusParserStruct *parser;
   struct ArgusClientData *client;
   struct ArgusOutputStruct *output;

   struct ArgusQueueStruct *configs;
};


#endif
