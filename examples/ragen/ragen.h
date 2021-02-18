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

   struct RaBinProcessStruct *bins;
   struct ArgusClientData *client;
   struct ArgusOutputStruct *output;

   char *baseline;
   char *tempfile;
   struct timeval startime;
   double interval;
   double duration;

   FILE *file;
   long long ostart;
   long long ostop;
   int type;
   int fd;
   struct stat statbuf;
} ragen_config_t;


struct ArgusGenerator {
   struct ArgusListObjectStruct *nxt, *prv;
   int status, type, mode, index;

#if defined(ARGUS_THREADS)
   pthread_t tid;
   pthread_mutex_t lock;
#endif

   struct ArgusGenConfig config;

   struct timeval ArgusStartTime, ArgusLastTime;
   long long ArgusTimeDrift;
   int ArgusMarInterval;
   struct stat statbuf;
   int ArgusBufferLen;
   unsigned char *ArgusReadBuffer, *ArgusConvBuffer;
   unsigned char *ArgusReadPtr, *ArgusConvPtr, *ArgusReadBlockPtr;
   int ArgusReadSocketCnt, ArgusReadSocketSize;
   int ArgusReadSocketState, ArgusReadCiscoVersion;
   int ArgusReadSocketNum, ArgusReadSize;
   ArgusNetFlowHandler ArgusCiscoNetFlowParse;

   struct ArgusRecord ArgusInitCon, ArgusManStart;
   struct ArgusRecord *ArgusOriginal;

   struct ArgusCanonRecord  ArgusGenerateRecordCanonBuf;
   struct ArgusRecordStruct ArgusGenerateRecordStructBuf;

   char ArgusGenerateRecordLabelBuf[MAXBUFFERLEN];

   char ArgusOriginalBuffer[MAXARGUSRECORD];

   char ArgusSrcUserData[0x10000];
   char ArgusDstUserData[0x10000];

   unsigned char ArgusSrcActDist[256];
   unsigned char ArgusSrcIdleDist[256];
   unsigned char ArgusDstActDist[256];
   unsigned char ArgusDstIdleDist[256];
};


#endif
