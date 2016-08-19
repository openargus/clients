/*
 * Argus Software
 * Copyright (c) 2000-2016 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/*
 * raconvert - this converts ra() ascii output back into argus binary records.
 *
 *    The primary file format that this program will support is the simple
 *    title, data, .... data default ascii output that ra() generates.
 *    So read in the title line, and then parse the columns found.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

/*
 * $Id: //depot/argus/clients/examples/raconvert/raconvert.c#16 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <sys/types.h>
#include <unistd.h>

#if defined(ARGUS_THREADS) 
#include <pthread.h>
#endif

#define ArgusMain

#include <argus_compat.h>

#include <argus_def.h>
#include <argus_out.h>

#include <signal.h>

#include <argus_util.h>

#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <argus_grep.h>
#include <argus_dscodepoints.h>

#include <raconvert.h>

#include <ctype.h>
#include <strings.h>

#if defined(ARGUS_SOLARIS)
#include <string.h>
#endif

#include <sys/wait.h>

#if defined(__NetBSD__)
#include <sys/sched.h>
#else
#include <sched.h>
#endif


void RaConvertReadFile (struct ArgusParserStruct *, struct ArgusInput *);

void RaConvertParseTitleString (char *);

int RaFlagsIndicationStatus[64];
int RaConvertParseDirLabel = 0;
int RaConvertParseStateLabel = 0;


unsigned int ArgusSourceId = 0;
unsigned int ArgusIdType = 0;


#define ARGUS_CONTINUE		0x100
#define ARGUS_REQUEST		0x200
#define ARGUS_RESPONSE		0x400
#define ARGUS_INIT		0x800

int
main (int argc, char **argv)
{
   extern char *optarg;
   int ArgusExitStatus;
   int i, cc;

#if defined(ARGUS_THREADS)
   pthread_attr_t attr;
#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN)
   int thread_policy;
   struct sched_param thread_param;
#if defined(HAVE_SCHED_GET_PRIORITY_MIN)
   int rr_min_priority, rr_max_priority;
#endif
#endif
   int status;
   size_t stacksize;
#endif

   for (i = 0, cc = 0; i < argc; i++)
      cc += strlen(argv[i]);

   if (strchr (argv[0], '/'))
      argv[0] = strrchr(argv[0], '/') + 1;

   if ((ArgusParser = ArgusNewParser(argv[0])) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewParser failed %s", strerror(errno));

#if defined(ARGUS_THREADS)
   if ((status = pthread_attr_init(&attr)) != 0)
      ArgusLog (LOG_ERR, "pthreads init error");
 
#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN)
   if ((status = pthread_attr_getschedpolicy(&attr, &thread_policy)) != 0)
      ArgusLog (LOG_ERR, "pthreads get policy error");
   if ((status = pthread_attr_getschedparam(&attr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads get sched params error");
   if ((status = pthread_attr_setschedpolicy(&attr, SCHED_RR)) != 0)
      ArgusLog (LOG_ERR, "pthreads set SCHED_RR error");

#if defined(HAVE_SCHED_GET_PRIORITY_MIN)
   if ((rr_min_priority = sched_get_priority_min(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority min error");
   if ((rr_max_priority = sched_get_priority_max(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority max error");

   thread_param.sched_priority = (rr_max_priority + rr_min_priority)/2 + 1;

   if (thread_param.sched_priority > rr_max_priority)
      thread_param.sched_priority = rr_max_priority;
   if (thread_param.sched_priority < (rr_max_priority - 8))
      thread_param.sched_priority = rr_max_priority - 8;

   if ((status = pthread_attr_setschedparam(&attr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads set sched param error");
#endif
#else
   pthread_attr_setschedpolicy(&attr, SCHED_RR);
#endif

#if defined(_POSIX_THREAD_ATTR_STACKSIZE)
#define ARGUS_MIN_STACKSIZE	524288

   if (pthread_attr_getstacksize(&attr, &stacksize))
      ArgusLog (LOG_ERR, "pthreads get stacksize error");

   if (stacksize < ARGUS_MIN_STACKSIZE) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "setting stacksize from %d to %d", stacksize, ARGUS_MIN_STACKSIZE);
#endif
      if (pthread_attr_setstacksize(&attr, ARGUS_MIN_STACKSIZE))
         ArgusLog (LOG_ERR, "pthreads set stacksize error");
   }
#endif
 
   pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
#endif

   ArgusMainInit (ArgusParser, argc, argv);
   ArgusClientInit (ArgusParser);
 
   if (ArgusParser->ArgusInputFileList == NULL)
      if (!(ArgusAddFileList (ArgusParser, "-", ARGUS_DATA_SOURCE, -1, -1)))
         ArgusLog(LOG_ERR, "%s: error: file arg %s", *argv, optarg);

/*
   OK now we're ready.  Read in all the files, for as many passes as
   needed, and then attach to any remote sources as a group until
   they close, then we're done.
*/

   if (ArgusParser->ArgusInputFileList != NULL) {
      struct ArgusInput *file; 

      while (ArgusParser->ArgusPassNum) {
         file = ArgusParser->ArgusInputFileList;
         while (file && ArgusParser->eNflag) {

            if (strcmp (file->filename, "-")) {
               RaConvertReadFile(ArgusParser, file);
            } else {
               if (ArgusParser->ArgusPassNum == 1)
                  RaConvertReadFile(ArgusParser, file);
            }

#ifdef ARGUSDEBUG
            ArgusDebug (1, "main: RaConvertReadFile(%s) done", file->filename);
#endif
            RaArgusInputComplete(file);
            file = (struct ArgusInput *)file->qhdr.nxt;
         }

         ArgusParser->ArgusPassNum--;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "main: reading files completed");
#endif

   ArgusParser->RaParseDone++;
   ArgusExitStatus = ArgusParser->ArgusExitStatus;
   ArgusCloseParser(ArgusParser);
   exit (ArgusExitStatus);
}

extern char version[];

void
usage ()
{
   fprintf (stdout, "RaConvert Version %s\n", version);
   fprintf (stdout, "usage: %s options\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -r <input>  specify input ascii file name.\n");
   fprintf (stdout, "         -w <output> specify output argus data file.\n");
   fflush (stdout);
   exit(1);
}

struct ArgusLogPriorityStruct {
   int priority;
   char *label;
};



extern struct ArgusParserStruct *ArgusParser;

#define RASCII_MAXMODES		1
#define RASCIIDEBUG		0

char *RaConvertDaemonModes[RASCII_MAXMODES] = {
   "debug",
};

int ArgusDebugMode = 0;


#define RASCII_MAXDEBUG		2

#define RASCII_DEBUGDUMMY	0
#define RASCII_DEBUGTASKS	1

#define RASCII_DEBUGTASKMASK	1

char *ArgusDebugModes[RASCII_MAXDEBUG] = {
   " ",
   "tasks",
};

void
ArgusClientInit(struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   int i, x, ind;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaConvertInit()");
#endif

   if ((mode = ArgusParser->ArgusModeList) != NULL) {
      while (mode) {
         for (i = 0, ind = -1; i < RASCII_MAXMODES; i++) {
            if (!(strncasecmp (mode->mode, RaConvertDaemonModes[i], 3))) {
               ind = i;
               switch (ind) {
                  case RASCIIDEBUG:
                     if ((mode = mode->nxt) == NULL)
                        usage();
                     break;
               }
            }
         }
         if (ind < 0)
            usage();

         switch (ind) {
            case RASCIIDEBUG: {
               for (x = 0, ind = -1; x < RASCII_MAXDEBUG; x++) {
                  if (!(strncasecmp (mode->mode, RaConvertDaemonModes[x], 3))) {
                     ArgusDebugMode |= 0x01 << x;
                     switch (ind) {
                        case RASCII_DEBUGTASKS:
                           break;
                     }
                  }
               }
               break;
            }

            default:
               usage();
               break;
         }

         mode = mode->nxt;
      }
   }

/*
struct ArgusRecord {
   struct ArgusRecordHeader hdr;
   union {
      struct ArgusMarStruct mar;
      struct ArgusFarStruct far;
   } ar_un;
};
  
struct ArgusMarStruct {
   unsigned int status, argusid;
   unsigned int localnet, netmask, nextMrSequenceNum;
   struct ArgusTime startime, now;
   unsigned char  major_version, minor_version;
   unsigned char interfaceType, interfaceStatus;
   unsigned short reportInterval, argusMrInterval;
   unsigned long long pktsRcvd, bytesRcvd;
   long long drift;
 
   unsigned int records, flows, dropped;
   unsigned int queue, output, clients;
   unsigned int bufs, bytes;
   unsigned int pad[4];
   unsigned int thisid, record_len;
};
*/

   ArgusParser->ArgusInitCon.hdr.type                    = (ARGUS_MAR | ARGUS_VERSION);
   ArgusParser->ArgusInitCon.hdr.cause                   = ARGUS_START;
   ArgusParser->ArgusInitCon.hdr.len                     = (unsigned short) (sizeof(struct ArgusRecord) + 3)/4;
   ArgusParser->ArgusInitCon.argus_mar.thisid            = ArgusSourceId;
   ArgusParser->ArgusInitCon.argus_mar.argusid           = ARGUS_COOKIE;
 
   ArgusParser->ArgusInitCon.argus_mar.startime.tv_sec   = ArgusParser->ArgusRealTime.tv_sec;
   ArgusParser->ArgusInitCon.argus_mar.startime.tv_usec  = ArgusParser->ArgusRealTime.tv_usec;
   ArgusParser->ArgusInitCon.argus_mar.now.tv_sec        = ArgusParser->ArgusRealTime.tv_sec;
   ArgusParser->ArgusInitCon.argus_mar.now.tv_sec        = ArgusParser->ArgusRealTime.tv_usec;

   ArgusParser->ArgusInitCon.argus_mar.major_version     = VERSION_MAJOR;
   ArgusParser->ArgusInitCon.argus_mar.minor_version     = VERSION_MINOR;
   ArgusParser->ArgusInitCon.argus_mar.reportInterval    = 0;
   ArgusParser->ArgusInitCon.argus_mar.argusMrInterval    = 0;

   ArgusParser->ArgusInitCon.argus_mar.record_len                = -1;

   ArgusHtoN(&ArgusParser->ArgusInitCon);
}

#define ARGUS_MAX_PRINT_FIELDS		512

void (*RaParseLabelAlgorithms[ARGUS_MAX_PRINT_FIELDS])(struct ArgusParserStruct *, char *);
int RaParseLabelAlgorithmIndex = 0;
char RaConvertDelimiter[2] = {'\0', '\0'};


void
RaConvertParseTitleString (char *str)
{
   char buf[MAXSTRLEN], *ptr, *obj;
   int i, len = 0, items = 0;


   bzero ((char *)RaParseLabelAlgorithms, sizeof(RaParseLabelAlgorithms));
   bzero ((char *)buf, sizeof(buf));

   if ((ptr = strchr(str, '\n')) != NULL)
      *ptr = '\0';

   ptr = buf;
   bcopy (str, buf, strlen(str));
   while (isspace((int)*ptr)) ptr++;

// Lets determine the delimiter, if we need to.  This will make this go a bit faster

   for (i = 0; i < MAX_PARSE_ALG_TYPES; i++) {
      len = strlen(RaParseLabelStringTable[i]);
      if (!(strncmp(RaParseLabelStringTable[i], ptr, len))) {
         ptr += len;
         if (*RaConvertDelimiter == '\0')
            *RaConvertDelimiter = *ptr++;
         else {
            if (*ptr && (*RaConvertDelimiter != *ptr++))
               ArgusLog (LOG_ERR, "RaConvertFrontList: title format error: inconsistent delimiter: %s", str);
         }
         break;
      }
   }

   ptr = buf;

   while ((obj = strtok(ptr, RaConvertDelimiter)) != NULL) {
      len = strlen(obj);
      if (len > 0) {
         for (i = 0; i < MAX_PARSE_ALG_TYPES; i++) {
            if (!(strncmp(RaParseLabelStringTable[i], obj, len))) {
               RaParseLabelAlgorithmIndex++;
               RaParseLabelAlgorithms[items] = RaParseLabelAlgorithmTable[i];
               if (i == ARGUSPARSEDIRLABEL)
                  RaConvertParseDirLabel++;
               if (i == ARGUSPARSESTATELABEL)
                  RaConvertParseStateLabel++;
               break;
            }
         }
      }

      items++;
      ptr = NULL;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (9, "RaConvertParseTitleString('%s') done", str);
#endif
}


int RaConvertParseRecordString (struct ArgusParserStruct *, char *);
int ArgusParseDirStatus = -1;
int ArgusParseTCPState = -1;
int ArgusParseState = -1;
int ArgusThisProto = -1;


int
RaConvertParseRecordString (struct ArgusParserStruct *parser, char *str)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char buf[MAXSTRLEN], delim[16], *ptr, *tptr;
   char **ap, *argv[ARGUS_MAX_PRINT_FIELDS];
   int retn = 1, numfields, i;

   if ((ptr = strchr(str, '\n')) != NULL)
      *ptr = '\0';

   ptr = buf;

   bzero (argv, sizeof(argv));
   bzero ((char *)argus, sizeof(*argus));
   bcopy (str, buf, strlen(str) + 1);
   bzero (delim, sizeof(delim));

   bzero ((char *)&parser->argus, sizeof(parser->argus));
   bzero ((char *)&parser->canon, sizeof(parser->canon));

   ArgusThisProto = 0;

   while (isspace((int)*ptr)) ptr++;
   sprintf (delim, "%c", RaConvertDelimiter[0]);
   tptr = ptr;

   for (ap = argv; (*ap = strsep(&tptr, delim)) != NULL;)
      if (++ap >= &argv[ARGUS_MAX_PRINT_FIELDS])
         break;

   numfields = ((char *)ap - (char *)argv)/sizeof(ap);

   for (i = 0; i < numfields; i++) {
      if (RaParseLabelAlgorithms[i] != NULL) {
         if (argv[i] != NULL) {
            RaParseLabelAlgorithms[i](ArgusParser, argv[i]);
            switch (parser->argus.hdr.type) {
               case ARGUS_MAR:
               case ARGUS_EVENT:
                  return(0);
                  break;
            }
         }
      }
   }

   if (RaConvertParseDirLabel) {
      struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) &parser->canon.net;
      switch (net->hdr.subtype) {
         case ARGUS_TCP_INIT:
         case ARGUS_TCP_STATUS:
         case ARGUS_TCP_PERF: {
            struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
            tcp->status |= ArgusParseDirStatus;
         }
      }
   }
   if (RaConvertParseStateLabel) {
      switch (parser->canon.flow.hdr.argus_dsrvl8.qual & 0x1F) {
         case ARGUS_TYPE_IPV4: {
            switch (parser->canon.flow.ip_flow.ip_p) {
               case IPPROTO_TCP: {
                  struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) &parser->canon.net;
                  switch (net->hdr.subtype) {
                     case ARGUS_TCP_INIT:
                     case ARGUS_TCP_STATUS:
                     case ARGUS_TCP_PERF: {
                        struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                        tcp->status |= ArgusParseTCPState;
                     }
                  }
                  break;
               }
               case IPPROTO_UDP: {
                  switch (ArgusParseState) {
                     case ARGUS_REQUEST:
                     case ARGUS_CONTINUE:
                     case ARGUS_RESPONSE:
                        break;

                     case ARGUS_INIT:
                        parser->argus.hdr.cause |= ARGUS_START;
                        break;
                  }
                  break;
               }
            }
            break;
         }
         case ARGUS_TYPE_IPV6: {
            switch (parser->canon.flow.ipv6_flow.ip_p) {
               case IPPROTO_TCP: {
                  struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) &parser->canon.net;
                  switch (net->hdr.subtype) {
                     case ARGUS_TCP_INIT:
                     case ARGUS_TCP_STATUS:
                     case ARGUS_TCP_PERF: {
                        struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                        tcp->status |= ArgusParseTCPState;
                     }
                  }
                  break;
               }
               case IPPROTO_UDP: {
                  switch (ArgusParseState) {
                     case ARGUS_REQUEST:
                     case ARGUS_CONTINUE:
                     case ARGUS_RESPONSE:
                        break;

                     case ARGUS_INIT:
                        parser->argus.hdr.cause |= ARGUS_START;
                        break;
                  }
                  break;
               }
            }
            break;
         }

         case ARGUS_TYPE_RARP:
         case ARGUS_TYPE_ARP: {
            switch (ArgusParseState) {
               case ARGUS_REQUEST:
               case ARGUS_CONTINUE:
               case ARGUS_RESPONSE:
                  break;

               case ARGUS_INIT:
                  parser->argus.hdr.cause |= ARGUS_START;
                  break;
            }
         }
      }
   }

   if (RaFlagsIndicationStatus[3] != 0) {
      switch (parser->canon.flow.hdr.argus_dsrvl8.qual & 0x1F) {
         case ARGUS_TYPE_IPV4: {
            switch (parser->canon.flow.ip_flow.ip_p) {
               case IPPROTO_TCP: {
                  struct ArgusNetworkStruct *net;
                  struct ArgusTCPObject *tcp;
                  if ((net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX]) == NULL) {
                     argus->dsrs[ARGUS_NETWORK_INDEX] = &parser->canon.net.hdr;
                     argus->dsrindex |= 0x1 << ARGUS_NETWORK_INDEX;
                     net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX];
                     net->hdr.type    = ARGUS_NETWORK_DSR;
                     net->hdr.subtype = ARGUS_TCP_INIT;
                     net->hdr.argus_dsrvl8.len = ((sizeof(*tcp) + 3)/4) + 1;
                  }
                  tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                  tcp->status |= RaFlagsIndicationStatus[3];
               }
            }
            break;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (9, "RaConvertParseRecordString('%s') returning %d", str, retn);
#endif

   return (retn);
}


void
RaConvertReadFile (struct ArgusParserStruct *parser, struct ArgusInput *input)
{
   FILE *fd = NULL;
   char *file = input->filename;

   if (strcmp (file, "-")) {
      if ((!(strncmp(".gz", &file[strlen(file) - 3], 3))) ||
          (!(strncmp("-gz", &file[strlen(file) - 3], 3))) ||
          (!(strncmp(".z",  &file[strlen(file) - 2], 2))) ||
          (!(strncmp("-z",  &file[strlen(file) - 2], 2))) ||
          (!(strncmp("_z",  &file[strlen(file) - 2], 2))) ||
          (!(strncmp(".Z",  &file[strlen(file) - 2], 2)))) {
         char cmd[256];
         bzero(cmd, 256); 
         strncpy(cmd, "gzip -dc ", 10);

         strncat(cmd, input->filename, (256 - strlen(cmd)));
         strncat(cmd, " 2>/dev/null", (256 - strlen(cmd)));

         if ((input->pipe = popen(cmd, "r")) == NULL)
            ArgusLog (LOG_ERR, "ArgusReadConnection: popen(%s) failed. %s", cmd, strerror(errno));

         fd = input->pipe;
#ifdef ARGUSDEBUG
         ArgusDebug (7, "uncompressing '%s'", file);
#endif
      } else       
      if ((!(strncmp(".bz2", &file[strlen(file) - 4], 4))) ||
          (!(strncmp(".bz",  &file[strlen(file) - 3], 3)))) {
         char cmd[256];
         bzero(cmd, 256);
         strncpy(cmd, "bzip2 -dc ", 11);

         strncat(cmd, input->filename, (256 - strlen(cmd)));
         strncat(cmd, " 2>/dev/null", (256 - strlen(cmd)));

         if ((input->pipe = popen(cmd, "r")) == NULL)
            ArgusLog (LOG_ERR, "ArgusReadConnection: popen(%s) failed. %s", cmd, strerror(errno));

         fd = input->pipe;
#ifdef ARGUSDEBUG
         ArgusDebug (7, "uncompressing '%s'", file);
#endif

      } else {
         if ((fd = fopen(file, "r")) == NULL) {
#ifdef ARGUSDEBUG
            ArgusDebug (0, "open '%s': %s", file, strerror(errno));
#endif
         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (7, "RaConvertReadFile: opened %s", file);
#endif
         }
      }

   } else 
      fd = stdin;

   if (fd != NULL) {
      char strbuf[MAXSTRLEN], *str;
      int done = 0, start = 0, line = 0;

      while (!done && ((str = fgets(strbuf, MAXSTRLEN, fd)) != NULL)) {
         int len = strlen(str), i;

         line++;

         for (i = 0; i < len; i++) {
            if (!(isascii((int) str[i]))) {
               ArgusLog (LOG_INFO, "RaConvertReadFile: file '%s' not ascii", file);
               done++;
               break;
            }
         }

         if ((*str != '#') && (strlen(str) > 1)) {
            if (start == 0) {
               RaConvertParseTitleString(str);
               start++;
            } else {
               if (RaConvertParseRecordString(parser, str)) {
                  struct ArgusRecordStruct *argus = &parser->argus;

                  if (parser->ArgusWfileList != NULL) {
                     struct ArgusWfileStruct *wfile = NULL;
                     struct ArgusListObjectStruct *lobj = NULL;
                     int i, count = parser->ArgusWfileList->count;
 
                     if ((lobj = parser->ArgusWfileList->start) != NULL) {
                        for (i = 0; i < count; i++) {
                           if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                              int retn = 1;
                              if (wfile->filterstr) {
                                 struct nff_insn *wfcode = wfile->filter.bf_insns;
                                 retn = ArgusFilterRecord (wfcode, argus);
                              }
 
                              if (retn != 0) {
                                 if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                                    struct ArgusRecord *argusrec = NULL;
                                    static char sbuf[0x10000];
                                    if ((argusrec = ArgusGenerateRecord (argus, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                                       ArgusHtoN(argusrec);
#endif
                                       ArgusWriteNewLogfile (parser, input, wfile, argusrec);
                                    }
                                 }
                              }
                           }
 
                           lobj = lobj->nxt;
                        }
                     }

                  } else {
                     if (!parser->qflag) {
                        static char buf[MAXSTRLEN];
                        int retn = 0, RaPrintCounter = 1;

                        if (parser->Lflag && !(parser->ArgusPrintXml)) {
                           if (parser->RaLabel == NULL)
                              parser->RaLabel = ArgusGenerateLabel(parser, argus);
                
                           if (!(parser->RaLabelCounter++ % parser->Lflag))
                              if ((retn = printf ("%s\n", parser->RaLabel)) < 0) 
                                 RaParseComplete (SIGQUIT);
                
                           if (parser->Lflag < 0)
                              parser->Lflag = 0;
                        }
               
                        bzero (buf, sizeof(buf));
                        argus->rank = RaPrintCounter++;

                        if ((ArgusParser->eNoflag == 0 ) || ((ArgusParser->eNoflag >= argus->rank) && (ArgusParser->sNoflag <= argus->rank))) {
                           ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);
               
                           if ((retn = fprintf (stdout, "%s", buf)) < 0)
                              RaParseComplete (SIGQUIT);
               
                           if (parser->eflag == ARGUS_HEXDUMP) {
                              int i;
                              for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
                                 if (parser->RaPrintAlgorithmList[i] != NULL) {
                                    struct ArgusDataStruct *user = NULL;
                                    if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcUserData) {
                                       int slen = 0, len = parser->RaPrintAlgorithmList[i]->length;
                                       if (len > 0) {
                                          if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) != NULL) {
                                             if (user->hdr.type == ARGUS_DATA_DSR) {
                                                slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                                             } else
                                                slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;
                                                
                                             slen = (user->count < slen) ? user->count : slen;
                                             slen = (slen > len) ? len : slen;
                                             ArgusDump ((const u_char *) &user->array, slen, "      ");
                                          }
                                       }
                                    }
                                    if (parser->RaPrintAlgorithmList[i]->print == ArgusPrintDstUserData) {
                                       int slen = 0, len = parser->RaPrintAlgorithmList[i]->length;
                                       if (len > 0) {
                                          if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) != NULL) {
                                             if (user->hdr.type == ARGUS_DATA_DSR) {
                                                slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                                             } else
                                                slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;
                  
                                             slen = (user->count < slen) ? user->count : slen;
                                             slen = (slen > len) ? len : slen;
                                             ArgusDump ((const u_char *) &user->array, slen, "      ");
                                          }
                                       }
                                    }
                                 } else
                                    break;
                              }
                           }
                  
                           fprintf (stdout, "\n");
                           fflush (stdout);

                        } else {
                           if ((ArgusParser->eNoflag != 0 ) && (ArgusParser->eNoflag < argus->rank))
                              RaParseComplete (SIGQUIT);
                        }
                     }
                  }
               }
            }
         }
      }

      if (!(feof(fd)) && ferror(fd))
         ArgusLog (LOG_ERR, "fgets: error %s", strerror(errno));
   }

   if (fd)
      fclose(fd);

   if (input->pipe)
      pclose(input->pipe);

#ifdef ARGUSDEBUG
   ArgusDebug (9, "RaConvertReadFile('%s') done", file);
#endif
}


char *RaDateFormat = NULL;

#define RACONVERTTIME	6

char *RaConvertTimeFormats[RACONVERTTIME] = {
   NULL,
   "%Y/%m/%d %T",
   "%Y/%m/%d.%T",
   "%Y/%m/%d.%H:%M:%S",
   "%H:%M:%S",
   "%T",
};

struct tm timebuf, *RaConvertTmPtr = NULL;
extern char *strptime(const char *s, const char *format, struct tm *tm);


void
ArgusParseStartDateLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *ptr, date[128], *frac;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   int i, len, unixtime = 1;
   char *endptr;
   int done = 0;

   bzero (date, sizeof(date));
   bzero (tvp, sizeof(*tvp));

   bcopy (buf, date, strlen(buf));

   if (RaConvertTmPtr == NULL) {
      gettimeofday(tvp, 0L);
      if ((RaConvertTmPtr = localtime(&tvp->tv_sec)) == NULL)
         ArgusLog (LOG_ERR, "ArgusParseStartDate(0x%xs, %s) localtime error\n", parser, buf, strerror(errno));
      bcopy ((char *)RaConvertTmPtr, (char *)&timebuf, sizeof (timebuf));
      RaConvertTmPtr = &timebuf;
   }

   if ((frac = strrchr(date, '.')) != NULL) {
      int useconds = 0, precision;

      *frac++ = '\0';
      useconds = strtol(frac, &endptr, 10);
      if (endptr == frac)
         ArgusLog (LOG_ERR, "ArgusParseStartDate(0x%xs, %s) fractonal format error\n", parser, buf);
         
      if ((precision = strlen(frac)) > 0) {
         int n, power = 6 - precision;

         for (n = 0; n < power; n++)
            useconds *= 10;
      }

      tvp->tv_usec = useconds;
   }


   if (RaDateFormat != NULL) {
      if ((ptr = strptime(date, RaDateFormat, RaConvertTmPtr)) != NULL) {
         if (*ptr == '\0') {
            done++;
            tvp->tv_sec = mktime(RaConvertTmPtr);
         }
      }

   } else {
      ptr = date;
      len = strlen(ptr);

      for (i = 0; i < len; i++) {
         if (!(isdigit((int)ptr[i]))) {
            unixtime = 0;
            break;
         }
      }

      if (unixtime) {
         tvp->tv_sec = strtol(date, &endptr, 10);
         if (endptr == date)
            ArgusLog (LOG_ERR, "ArgusParseStartDate(0x%xs, %s) fractonal format error\n", parser, buf);
      } else {
         if (RaConvertTimeFormats[0] == NULL) {
            char *sptr;
            RaConvertTimeFormats[0] = strdup(parser->RaTimeFormat);
            if ((sptr = strstr(RaConvertTimeFormats[0], ".%f")) != NULL)
               *sptr = '\0';
         }

         for (i = 0; (i < RACONVERTTIME) && (!done); i++) {
            char *format = NULL;
            if ((format = RaConvertTimeFormats[i]) != NULL) {
               if ((ptr = strptime(date, format, RaConvertTmPtr)) != NULL) {
                  if (*ptr == '\0') {
                     done++;
                     RaDateFormat = format;
                  }
               }
            }
         }

         if (done) {
            tvp->tv_sec = mktime(RaConvertTmPtr);
         } else {
            ArgusLog (LOG_ERR, "ArgusParseStartTime(0x%xs, %s) time format not defined\n", parser, buf);
         }
      }
   }


   if (parser->canon.time.hdr.type == 0) {
      parser->canon.time.hdr.type    = ARGUS_TIME_DSR;	
      parser->canon.time.hdr.subtype = ARGUS_TIME_ABSOLUTE_TIMESTAMP;	
      parser->canon.time.hdr.subtype |= ARGUS_TIME_SRC_START;
      parser->canon.time.hdr.argus_dsrvl8.qual = ARGUS_TYPE_UTC_MICROSECONDS;
      parser->canon.time.hdr.argus_dsrvl8.len  = 3;
   }

   if (argus->dsrs[ARGUS_TIME_INDEX] == NULL) {
      argus->dsrs[ARGUS_TIME_INDEX] = &parser->canon.time.hdr;
      argus->dsrindex |= 0x1 << ARGUS_TIME_INDEX;
   }

   parser->canon.time.src.start.tv_sec  = tvp->tv_sec;
   parser->canon.time.src.start.tv_usec = tvp->tv_usec;

   parser->canon.time.dst.start.tv_sec  = tvp->tv_sec;
   parser->canon.time.dst.start.tv_usec = tvp->tv_usec;
}


void
ArgusParseLastDateLabel (struct ArgusParserStruct *parser, char *buf)
{
}

void
ArgusParseSourceIDLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   struct ArgusCIDRAddr *taddr = NULL;

   if ((taddr = RaParseCIDRAddr (parser, buf)) != NULL) {
      if (argus->dsrs[ARGUS_TRANSPORT_INDEX] == NULL) {
         argus->dsrs[ARGUS_TRANSPORT_INDEX] = &parser->canon.trans.hdr;
         argus->dsrindex |= 0x1 << ARGUS_TRANSPORT_INDEX;

         parser->canon.trans.hdr.type     = ARGUS_TRANSPORT_DSR;
         parser->canon.trans.hdr.subtype |= ARGUS_SRCID;
      }

      switch (taddr->type) {
         case AF_INET: {
            parser->canon.trans.hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
            parser->canon.trans.hdr.argus_dsrvl8.len  = 3;
            parser->canon.trans.srcid.a_un.value = *taddr->addr;
            break;
         }
         case AF_INET6: {
            parser->canon.trans.hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV6;
            parser->canon.trans.hdr.argus_dsrvl8.len  = 6;
            break;
         }
      }

   } else {

   }
}


#include <argus_encapsulations.h>


void
ArgusParseFlagsLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char str[16];
   int len;

   bzero(RaFlagsIndicationStatus, sizeof(RaFlagsIndicationStatus));

   if ((len = strlen(buf)) > 16)
      len = 16;

   bcopy (buf, str, len);

   if (str[0] == 'T') parser->canon.time.hdr.argus_dsrvl8.qual |= ARGUS_TIMEADJUST;

   if (str[1] != ' ') {
      if (argus->dsrs[ARGUS_ENCAPS_INDEX] == NULL) {
         argus->dsrs[ARGUS_ENCAPS_INDEX] = &parser->canon.encaps.hdr;
         argus->dsrindex |= 0x1 << ARGUS_ENCAPS_INDEX;
         parser->canon.encaps.hdr.type = ARGUS_ENCAPS_DSR;
         parser->canon.encaps.hdr.argus_dsrvl8.len   = (sizeof(parser->canon.encaps) + 3)/4;
      }
      switch (str[1]) {
         case '*':
         case 'e': 
            parser->canon.encaps.src |= ARGUS_ENCAPS_ETHER; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_ETHER; 
            break;
         case 'M': {
            if (argus->dsrs[ARGUS_MAC_INDEX] == NULL) {
               struct ArgusMacStruct *mac = (struct ArgusMacStruct *) argus->dsrs[ARGUS_MAC_INDEX];
               if (mac == NULL) {
                  argus->dsrs[ARGUS_MAC_INDEX] = &parser->canon.mac.hdr;
                  argus->dsrindex |= 0x1 << ARGUS_MAC_INDEX;
                  mac = (struct ArgusMacStruct *) argus->dsrs[ARGUS_MAC_INDEX];
                  mac->hdr.type = ARGUS_MAC_DSR;
                  mac->hdr.argus_dsrvl8.len = 0;
               }
               mac->hdr.argus_dsrvl8.qual |= ARGUS_MULTIPATH;
            }
            break;
         }
         case 'm':
            parser->canon.encaps.src |= ARGUS_ENCAPS_MPLS; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_MPLS; 
            break;
         case 'l':
            parser->canon.encaps.src |= ARGUS_ENCAPS_LLC; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_LLC; 
            break;
         case 'v':
            parser->canon.encaps.src |= ARGUS_ENCAPS_8021Q; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_8021Q; 
            break;
         case 'w':
            parser->canon.encaps.src |= ARGUS_ENCAPS_802_11; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_802_11; 
            break;
         case 'p':
            parser->canon.encaps.src |= ARGUS_ENCAPS_PPP; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_PPP; 
            break;
         case 'i':
            parser->canon.encaps.src |= ARGUS_ENCAPS_ISL; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_ISL; 
            break;
         case 'G':
            parser->canon.encaps.src |= ARGUS_ENCAPS_GRE; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_GRE; 
            break;
         case 'a':
            parser->canon.encaps.src |= ARGUS_ENCAPS_AVS; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_AVS; 
            break;
         case 'P':
            parser->canon.encaps.src |= ARGUS_ENCAPS_IP; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_IP; 
            break;
         case '6':
            parser->canon.encaps.src |= ARGUS_ENCAPS_IPV6; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_IPV6; 
            break;
         case 'H':
            parser->canon.encaps.src |= ARGUS_ENCAPS_HDLC; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_HDLC; 
            break;
         case 'C':
            parser->canon.encaps.src |= ARGUS_ENCAPS_CHDLC; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_CHDLC; 
            break;
         case 'A':
            parser->canon.encaps.src |= ARGUS_ENCAPS_ATM; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_ATM; 
            break;
         case 'S':
            parser->canon.encaps.src |= ARGUS_ENCAPS_SLL; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_SLL; 
            break;
         case 'F':
            parser->canon.encaps.src |= ARGUS_ENCAPS_FDDI; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_FDDI; 
            break;
         case 's':
            parser->canon.encaps.src |= ARGUS_ENCAPS_SLIP; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_SLIP; 
            break;
         case 'R':
            parser->canon.encaps.src |= ARGUS_ENCAPS_ARCNET; 
            parser->canon.encaps.dst |= ARGUS_ENCAPS_ARCNET; 
            break;
      }
   }

   if (str[2] != ' ') {
      if (argus->dsrs[ARGUS_ICMP_INDEX] == NULL) {
         argus->dsrs[ARGUS_ICMP_INDEX] = &parser->canon.icmp.hdr;
         argus->dsrindex |= 0x1 << ARGUS_ICMP_INDEX;
         parser->canon.icmp.hdr.type = ARGUS_ICMP_DSR;
         parser->canon.icmp.hdr.argus_dsrvl8.qual |= ARGUS_ICMP_MAPPED;
         parser->canon.icmp.hdr.argus_dsrvl8.len   = (sizeof(parser->canon.icmp) + 3)/4;
      }
      switch (str[1]) {
         case 'I':
         case 'U': 
         case 'R':
         case 'T':
            break;
      }
   }

   if (str[3] != ' ') {
      switch (str[3]) {
         case '*': RaFlagsIndicationStatus[3] = ARGUS_SRC_PKTS_RETRANS | ARGUS_DST_PKTS_RETRANS; break;
         case 's': RaFlagsIndicationStatus[3] = ARGUS_SRC_PKTS_RETRANS; break;
         case 'd': RaFlagsIndicationStatus[3] = ARGUS_DST_PKTS_RETRANS; break;
         case '&': RaFlagsIndicationStatus[3] = ARGUS_SRC_OUTOFORDER | ARGUS_DST_OUTOFORDER; break;
         case 'i': RaFlagsIndicationStatus[3] = ARGUS_SRC_OUTOFORDER; break;
         case 'r': RaFlagsIndicationStatus[3] = ARGUS_DST_OUTOFORDER; break;
      }
   }

   if (str[4] != ' ') {
      switch (str[4]) {
         case '@': RaFlagsIndicationStatus[4] = ARGUS_SRC_WINDOW_SHUT | ARGUS_DST_WINDOW_SHUT; break;
         case 'S': RaFlagsIndicationStatus[4] = ARGUS_SRC_WINDOW_SHUT; break;
         case 'D': RaFlagsIndicationStatus[4] = ARGUS_DST_WINDOW_SHUT; break;
         case '*': RaFlagsIndicationStatus[4] = ARGUS_RTP_SRCSILENCE | ARGUS_RTP_DSTSILENCE; break;
         case 's': RaFlagsIndicationStatus[4] = ARGUS_RTP_SRCSILENCE; break;
         case 'd': RaFlagsIndicationStatus[4] = ARGUS_RTP_DSTSILENCE; break;
      }
   }

   if (str[5] != ' ') {
      switch (str[5]) {
         case 'E': RaFlagsIndicationStatus[5] = ARGUS_SRC_CONGESTED | ARGUS_DST_CONGESTED; break;
         case 'x': RaFlagsIndicationStatus[5] = ARGUS_SRC_CONGESTED; break;
         case 't': RaFlagsIndicationStatus[5] = ARGUS_DST_CONGESTED; break;
      }
   }


   if (str[6] != ' ') {
      switch (str[6]) {
         case 'V': RaFlagsIndicationStatus[6] = ARGUS_FRAGOVERLAP; break;
         case 'f': RaFlagsIndicationStatus[6] = ARGUS_FRAGMENTS; break;
         case 'F': RaFlagsIndicationStatus[6] = ARGUS_IPATTR_SRC_FRAGMENTS | ARGUS_IPATTR_DST_FRAGMENTS; break;
      }
   }

   if (str[7] != ' ') {
      struct ArgusIPAttrStruct *attr;

      if (argus->dsrs[ARGUS_IPATTR_INDEX] == NULL) {
         argus->dsrs[ARGUS_IPATTR_INDEX] = &parser->canon.attr.hdr;
         argus->dsrindex |= 0x1 << ARGUS_IPATTR_INDEX;
         parser->canon.attr.hdr.type = ARGUS_IPATTR_DSR;
         parser->canon.attr.hdr.argus_dsrvl8.len   = (sizeof(parser->canon.attr) + 3)/4;
      }

      attr = (struct ArgusIPAttrStruct *)argus->dsrs[ARGUS_IPATTR_INDEX];

      switch (str[7]) {
         case 'A': attr->src.options = ARGUS_RTRALERT; break;
         case 'T': attr->src.options = ARGUS_TIMESTAMP; break;
         case 'R': attr->src.options = ARGUS_RECORDROUTE; break;
         case '+': attr->src.options = ARGUS_SECURITY; break;
         case 'L': attr->src.options = ARGUS_LSRCROUTE; break;
         case 'S': attr->src.options = ARGUS_SSRCROUTE; break;
         case 'D': attr->src.options = ARGUS_SATID; break;
         case 'O': attr->src.options = -1; break;
         case 'U': attr->src.options = 99; break;
      }
   }
}

void
ArgusParseSrcMacAddressLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCMACADDRESS].length;
   if (parser->RaMonMode) {
      sprintf (&buf[strlen(buf)], " %*sMac%*s ", (len - 3)/2, " ", (len - 3)/2, " ");
   } else {
      sprintf (&buf[strlen(buf)], "%*sSrcMac%*s ", (len - 6)/2, " ", (len - 6)/2, " ");
   }
*/
}

void
ArgusParseDstMacAddressLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTMACADDRESS].length;
   sprintf (&buf[strlen(buf)], "%*sDstMac%*s ", (len - 6)/2, " ", (len - 6)/2, " ");
*/
}

void
ArgusParseMacAddressLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcMacAddressLabel (parser, buf);
   ArgusParseDstMacAddressLabel (parser, buf);
*/
}

void
ArgusParseProtoLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   if (isdigit((int)*buf)) {
      ArgusThisProto = atoi(buf);
      parser->canon.flow.hdr.type     = ARGUS_FLOW_DSR;
      parser->canon.flow.hdr.subtype  = ARGUS_FLOW_CLASSIC5TUPLE;
      argus->hdr.type = ARGUS_FAR;

   } else {
      if (*buf == '*') {
         ArgusThisProto = 0xFF;
      } else {
         struct protoent *proto;

         if (!(strncmp(buf, "man", 3))) {
            argus->hdr.type = ARGUS_MAR;
            return;
         } else
         if (!(strncmp(buf, "evt", 3))) {
            argus->hdr.type = ARGUS_EVENT;
            return;
         } else
            argus->hdr.type = ARGUS_FAR;

         if ((proto = getprotobyname(buf)) != NULL) {
            ArgusThisProto = proto->p_proto;

         } else {
            int retn;
            if ((retn = argus_nametoeproto(buf)) == PROTO_UNDEF)
               ArgusLog (LOG_ERR, "ArgusParseProto(0x%xs, %s) proto not found\n", parser, buf);

            if (argus->dsrs[ARGUS_FLOW_INDEX] == NULL) {
               argus->dsrs[ARGUS_FLOW_INDEX] = &parser->canon.flow.hdr;
               argus->dsrindex |= 0x1 << ARGUS_FLOW_INDEX;
            }
 
            switch (retn) {
               case 2054: {
                  struct ArgusArpFlow *arp = &parser->canon.flow.arp_flow;

                  bzero(&parser->canon.flow, sizeof(parser->canon.flow));
                  parser->canon.flow.hdr.type              = ARGUS_FLOW_DSR;
                  parser->canon.flow.hdr.subtype           = ARGUS_FLOW_ARP;
                  parser->canon.flow.hdr.argus_dsrvl8.qual = ARGUS_TYPE_ARP;
                  parser->canon.flow.hdr.argus_dsrvl8.len  = 1 + sizeof(*arp)/4;
                  arp->hrd     = 1;
                  arp->pro     = 2048;
                  arp->hln     = 6;
                  arp->pln     = 4;
                  arp->op      = 1;
                  break;
               }
 
               default:
                  parser->canon.flow.hdr.argus_dsrvl8.qual = ARGUS_TYPE_ETHER;
                  parser->canon.flow.flow_un.mac.mac_union.ether.ehdr.ether_type = retn;
                  break;
            }
            ArgusThisProto = retn;
            return;
         }
      }
   }

   switch (ArgusThisProto) {
      case IPPROTO_TCP: {
         struct ArgusNetworkStruct *net;
         struct ArgusTCPObject *tcp;
         if ((net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX]) == NULL) {
            argus->dsrs[ARGUS_NETWORK_INDEX] = &parser->canon.net.hdr;
            argus->dsrindex |= 0x1 << ARGUS_NETWORK_INDEX;
            net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX];
            net->hdr.type    = ARGUS_NETWORK_DSR;
            net->hdr.subtype = ARGUS_TCP_INIT;
            net->hdr.argus_dsrvl8.len = ((sizeof(*tcp) + 3)/4) + 1;
         }
         break;
      }
   }
}


void
ArgusParseSrcNetLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCADDR].length;
   if (parser->RaMonMode) {
      sprintf (&buf[strlen(buf)], "%*sNet%*s ", (len - 3)/2, " ", (len - 3)/2, " ");
   } else {
      sprintf (&buf[strlen(buf)], "%*sSrcNet%*s ", (len - 6)/2, " ", (len - 6)/2, " ");
   }

   if ((len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}

/*
   Check to see if the format is correct xx:xx:xx:xx:xx
*/
int RaParseEtherAddr (struct ArgusParserStruct *, char *);

int
RaParseEtherAddr (struct ArgusParserStruct *parser, char *buf)
{
   unsigned int c1, c2, c3, c4, c5, c6;
   int retn = 0;

   if ((sscanf (buf, "%x:%x:%x:%x:%x:%x", &c1, &c2, &c3, &c4, &c5, &c6)) == 6)
      retn = 1;

   return (retn);
}

void
ArgusParseSrcAddrLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   struct ArgusCIDRAddr *taddr = NULL;

   if (RaParseEtherAddr (parser,buf)) {
      unsigned char *eaddr = argus_ether_aton(buf);

      parser->canon.flow.hdr.type               = ARGUS_FLOW_DSR;
      parser->canon.flow.hdr.subtype            = ARGUS_FLOW_CLASSIC5TUPLE;
      parser->canon.flow.hdr.argus_dsrvl8.qual  = ARGUS_TYPE_ETHER;
      parser->canon.flow.hdr.argus_dsrvl8.len   = 5;
      bcopy (eaddr, (char *)&parser->canon.flow.flow_un.mac.mac_union.ether.ehdr.ether_shost, 6);
      free (eaddr);

   } else

   if ((taddr = RaParseCIDRAddr (parser, buf)) != NULL) {
      if (argus->dsrs[ARGUS_FLOW_INDEX] == NULL) {
         argus->dsrs[ARGUS_FLOW_INDEX] = &parser->canon.flow.hdr;
         argus->dsrindex |= 0x1 << ARGUS_FLOW_INDEX;

         parser->canon.flow.hdr.type              = ARGUS_FLOW_DSR;
         parser->canon.flow.hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
         switch (taddr->type) {
            case AF_INET: {
               parser->canon.flow.hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4 | ARGUS_MASKLEN;
               parser->canon.flow.hdr.argus_dsrvl8.len   = 5;
               break;
            }
            case AF_INET6: {
               parser->canon.flow.hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV6;
               parser->canon.flow.hdr.argus_dsrvl8.len   = 11;
               break;
            }
         }
      }

      switch (taddr->type) {
         case AF_INET: {
            switch(parser->canon.flow.hdr.subtype) {
               case ARGUS_FLOW_ARP: {
                  struct ArgusArpFlow *arp = &parser->canon.flow.arp_flow;
                  arp->arp_spa = *taddr->addr;
                  break;
               }

               default:
                  parser->canon.flow.flow_un.ip.ip_src = *taddr->addr;
                  parser->canon.flow.flow_un.ip.smask  = taddr->masklen;
                  break;
            }
            break;
         }

         case AF_INET6: {
            unsigned int *sp  = (unsigned int *)&parser->canon.flow.flow_un.ipv6.ip_src;
            unsigned int *rsp = (unsigned int *)taddr->addr;
            int i;

            for (i = 0; i < 4; i++)
               *sp++ = *rsp++;

            break;
         }
      }
   }
}

void
ArgusParseDstNetLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTADDR].length;
   sprintf (&buf[strlen(buf)], " %*sDstNet%*s ", (len - 6)/2, " ", (len - 6)/2, " ");
   if ((len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}

void
ArgusParseDstAddrLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   struct ArgusCIDRAddr *taddr = NULL;

   if (RaParseEtherAddr (parser,buf)) {
      unsigned char *eaddr = argus_ether_aton(buf);

      parser->canon.flow.hdr.type               = ARGUS_FLOW_DSR;
      parser->canon.flow.hdr.subtype            = ARGUS_FLOW_CLASSIC5TUPLE;
      parser->canon.flow.hdr.argus_dsrvl8.qual  = ARGUS_TYPE_ETHER;
      parser->canon.flow.hdr.argus_dsrvl8.len   = 5;
      bcopy (eaddr, (char *)&parser->canon.flow.flow_un.mac.mac_union.ether.ehdr.ether_dhost, 6);
      free (eaddr);

   } else

   if ((taddr = RaParseCIDRAddr (parser, buf)) != NULL) {
      if (argus->dsrs[ARGUS_FLOW_INDEX] == NULL) {
         argus->dsrs[ARGUS_FLOW_INDEX] = &parser->canon.flow.hdr;
         argus->dsrindex |= 0x1 << ARGUS_FLOW_INDEX;

         parser->canon.flow.hdr.type              = ARGUS_FLOW_DSR;
         parser->canon.flow.hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
         switch (taddr->type) {
            case AF_INET: {
               parser->canon.flow.hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4 | ARGUS_MASKLEN;
               parser->canon.flow.hdr.argus_dsrvl8.len   = 5;
               break;
            }
            case AF_INET6: {
               parser->canon.flow.hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV6;
               parser->canon.flow.hdr.argus_dsrvl8.len   = 11;
               break;
            }
         }
      }

      switch (taddr->type) {
         case AF_INET: {
            switch(parser->canon.flow.hdr.subtype) {
               case ARGUS_FLOW_ARP: {
                  struct ArgusArpFlow *arp = &parser->canon.flow.arp_flow;
                  arp->arp_tpa = *taddr->addr;
                  break;
               }

               default:
                  parser->canon.flow.flow_un.ip.ip_dst    = *taddr->addr;
                  parser->canon.flow.flow_un.ip.dmask     =  taddr->masklen;
                  break;
            }
            break;
         }

         case AF_INET6: {
            unsigned int *sp  = (unsigned int *)&parser->canon.flow.flow_un.ipv6.ip_dst;
            unsigned int *rsp = (unsigned int *)taddr->addr;
            int i;

            for (i = 0; i < 4; i++)
               *sp++ = *rsp++;

            break;
         }
      }
   }
}

void
ArgusParseSrcPortLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   int value = -1;
   char *endptr;

   if (argus->dsrs[ARGUS_FLOW_INDEX] == NULL) {
      argus->dsrs[ARGUS_FLOW_INDEX] = &parser->canon.flow.hdr;
      argus->dsrindex |= 0x1 << ARGUS_FLOW_INDEX;
   }

   if (isdigit((int)*buf)) {
      value = strtol(buf, &endptr, 0);
      if (endptr == buf)
         ArgusLog (LOG_ERR, "ArgusParseSrcPortLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
   } else {
      if (*buf == '*')
         value = 0x00;
   }

   switch (parser->canon.flow.hdr.argus_dsrvl8.qual & 0x1F) {
      case ARGUS_TYPE_ETHER:
         if (value < 0) {
            if (parser->canon.flow.flow_un.mac.mac_union.ether.ehdr.ether_type == 0) { /* llc */
               int i = 0;
               while (llcsap_db[i].s != NULL) {
                  if (!(strncmp(buf, llcsap_db[i].s, strlen(llcsap_db[i].s)))) {
                     value = llcsap_db[i].v;
                     break;
                  }
                  i++;
               }
            }
         }
         if (!(value < 0))
            parser->canon.flow.flow_un.mac.mac_union.ether.ssap = value;
         break;

      case ARGUS_TYPE_IPV4: {
         switch (ArgusThisProto) {
            case IPPROTO_ICMP:
            case IPPROTO_TCP:
            case IPPROTO_UDP:
               if (value < 0) {
                  int proto, port;
                  proto = ArgusThisProto;
                  if (argus_nametoport(buf, &port, &proto))
                     value = port;
               }
               parser->canon.flow.flow_un.ip.sport = value;
               parser->canon.flow.flow_un.ip.ip_p = ArgusThisProto;
               break;

            case IPPROTO_ESP:
               break;
         }
         break;
      }

      case ARGUS_TYPE_IPV6: {
         switch (ArgusThisProto) {
            case IPPROTO_TCP:
            case IPPROTO_UDP:
               if (value < 0) {
                  int proto, port;
                  proto = ArgusThisProto;
                  if (argus_nametoport(buf, &port, &proto))
                     value = port;
               }
               parser->canon.flow.flow_un.ipv6.sport = value;
               parser->canon.flow.flow_un.ipv6.ip_p = ArgusThisProto;
               break;

            case IPPROTO_ICMP:
            case IPPROTO_ESP:
               break;
         }
         break;
      }
   }
}

void
ArgusParseDstPortLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   int value = -1;
   char *endptr;

   if (argus->dsrs[ARGUS_FLOW_INDEX] == NULL) {
      argus->dsrs[ARGUS_FLOW_INDEX] = &parser->canon.flow.hdr;
      argus->dsrindex |= 0x1 << ARGUS_FLOW_INDEX;
   }

   if (isdigit((int)*buf)) {
      value = strtol(buf, &endptr, 0);
      if (endptr == buf)
         ArgusLog (LOG_ERR, "ArgusParseSrcPortLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
   } else {
      if (*buf == '*')
         value = 0x00;
   }

   switch (parser->canon.flow.hdr.argus_dsrvl8.qual & 0x1F) {
      case ARGUS_TYPE_ETHER:
         if (value < 0) {
            if (parser->canon.flow.flow_un.mac.mac_union.ether.ehdr.ether_type == 0) { /* llc */
               int i = 0;
               while (llcsap_db[i].s != NULL) {
                  if (!(strncmp(buf, llcsap_db[i].s, strlen(llcsap_db[i].s)))) {
                     value = llcsap_db[i].v;
                     break;
                  }
                  i++;
               }
            }
         }
         if (!(value < 0))
            parser->canon.flow.flow_un.mac.mac_union.ether.dsap = value;
         break;

      case ARGUS_TYPE_IPV4: {
         switch (ArgusThisProto) {
            case IPPROTO_ICMP:
            case IPPROTO_TCP:
            case IPPROTO_UDP:
               if (value < 0) {
                  int proto, port;
                  proto = ArgusThisProto;
                  if (argus_nametoport(buf, &port, &proto))
                     value = port;
               }
               parser->canon.flow.flow_un.ip.dport = value;
               parser->canon.flow.flow_un.ip.ip_p = ArgusThisProto;
               break;

            case IPPROTO_ESP:
               parser->canon.flow.flow_un.esp.spi = value;
               break;

         }
         break;
      }
      case ARGUS_TYPE_IPV6: {
         switch (ArgusThisProto) {
            case IPPROTO_TCP:
            case IPPROTO_UDP:
               if (value < 0) {
                  int proto, port;
                  proto = ArgusThisProto;
                  if (argus_nametoport(buf, &port, &proto))
                     value = port;
               } 
               parser->canon.flow.flow_un.ipv6.dport = value;
               parser->canon.flow.flow_un.ip.ip_p = ArgusThisProto;
               break;

            case IPPROTO_ESP:
               parser->canon.flow.flow_un.espv6.spi = value;
               break;

            case IPPROTO_ICMP:
               break;
         }
         break;
      }
   }
}

void
ArgusParseSrcIpIdLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCIPID].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SIpId");
*/
}

void
ArgusParseDstIpIdLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTIPID].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DIpId");
*/
}

void
ArgusParseIpIdLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcIpIdLabel (parser, buf);
   ArgusParseDstIpIdLabel (parser, buf);
*/
}

void
ArgusParseSrcDSByteLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCTOS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "sDSb");
*/
}

void
ArgusParseDstDSByteLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTTOS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dDSb");
*/
}

void
ArgusParseDSByteLabel (struct ArgusParserStruct *parser, char *buf)
{
   ArgusParseSrcDSByteLabel (parser, buf);
   ArgusParseDstDSByteLabel (parser, buf);
}


void
ArgusParseSrcTosLabel (struct ArgusParserStruct *parser, char *buf)
{  
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCTOS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "sTos");
*/
}

void
ArgusParseDstTosLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTTOS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dTos");
*/
}
   
void  
ArgusParseTosLabel (struct ArgusParserStruct *parser, char *buf)
{     
/*
   ArgusParseSrcTosLabel (parser, buf);
   ArgusParseDstTosLabel (parser, buf);
*/
}

void
ArgusParseSrcTtlLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCTTL].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "sTtl");
*/
}

void
ArgusParseDstTtlLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCTTL].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dTtl");
*/
}

void
ArgusParseTtlLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcTtlLabel (parser, buf);
   ArgusParseDstTtlLabel (parser, buf);
*/
}


void
ArgusParseDirLabel (struct ArgusParserStruct *parser, char *buf)
{
   ArgusParseDirStatus = 0;
   if (!(strcmp (buf, " ->"))) {
      ArgusParseDirStatus |= (ARGUS_SAW_SYN | ARGUS_SAW_SYN_SENT);
   }
   if (!(strcmp (buf, "<- "))) {
      ArgusParseDirStatus |= ARGUS_SAW_SYN_SENT;
   }
}


void
ArgusParsePacketsLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.src.pkts = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}

void
ArgusParseSrcPacketsLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.src.pkts = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}

void
ArgusParseDstPacketsLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.dst.pkts = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}


void
ArgusParseBytesLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.src.bytes = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}

void
ArgusParseSrcBytesLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.src.bytes = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcBytesLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}

void
ArgusParseDstBytesLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.dst.bytes = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}


void
ArgusParseAppBytesLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.src.appbytes = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}

void
ArgusParseSrcAppBytesLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.src.appbytes = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcBytesLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}

void
ArgusParseDstAppBytesLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   if (argus->dsrs[ARGUS_METRIC_INDEX] == NULL) {
      argus->dsrs[ARGUS_METRIC_INDEX] = &parser->canon.metric.hdr;
      argus->dsrindex |= 0x1 << ARGUS_METRIC_INDEX;
      parser->canon.metric.hdr.type            = ARGUS_METER_DSR;
      parser->canon.metric.hdr.subtype         = ARGUS_METER_PKTS_BYTES;
      parser->canon.metric.hdr.argus_dsrvl8.len  = 2;
   }

   parser->canon.metric.dst.appbytes = strtoll(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));
}

void
ArgusParseSrcIntPktLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SrcIntPkt");
*/
}

void
ArgusParseSrcIntPktMaxLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SrcIntPkt");
*/
}

void
ArgusParseSrcIntPktMinLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SrcIntPkt");
*/
}
 
void
ArgusParseDstIntPktLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DstIntPkt");
*/
}

void
ArgusParseDstIntPktMaxLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DstIntPkt");
*/
}

void
ArgusParseDstIntPktMinLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DstIntPkt");
*/
}
 

void
ArgusParseSrcIntPktActiveLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVESRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActSrcIntPkt");
*/
}

void
ArgusParseSrcIntPktActiveMaxLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVESRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActSrcIntPkt");
*/
}

void
ArgusParseSrcIntPktActiveMinLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVESRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActSrcIntPkt");
*/
}

 
void
ArgusParseDstIntPktActiveLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVEDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActDstIntPkt");
*/
}

void
ArgusParseDstIntPktActiveMaxLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVEDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActDstIntPkt");
*/
}

void
ArgusParseDstIntPktActiveMinLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVEDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActDstIntPkt");
*/
}

 

void
ArgusParseSrcIntPktIdleLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLESRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlSrcIntPkt");
*/
}

void
ArgusParseSrcIntPktIdleMaxLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLESRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlSrcIntPkt");
*/
}

void
ArgusParseSrcIntPktIdleMinLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLESRCINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlSrcIntPkt");
*/
}

 
void
ArgusParseDstIntPktIdleLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLEDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlDstIntPkt");
*/
}

void
ArgusParseDstIntPktIdleMaxLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLEDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlDstIntPkt");
*/
}

void
ArgusParseDstIntPktIdleMinLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLEDSTINTPKT].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlDstIntPkt");
*/
}

 
void
ArgusParseSrcJitterLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCJITTER].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SrcJitter");
*/
}

void
ArgusParseDstJitterLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTJITTER].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DstJitter");
*/
}

void
ArgusParseJitterLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcJitterLabel(parser,buf);
   ArgusParseDstJitterLabel(parser,buf);
*/
}

void
ArgusParseActiveSrcJitterLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVESRCJITTER].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActSrcJitter");
*/
}

void
ArgusParseActiveDstJitterLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTACTIVEDSTJITTER].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ActDstJitter");
*/
}

void
ArgusParseActiveJitterLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseActiveSrcJitterLabel(parser,buf);
   ArgusParseActiveDstJitterLabel(parser,buf);
*/
}

void
ArgusParseIdleSrcJitterLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLESRCJITTER].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlSrcJitter");
*/
}

void
ArgusParseIdleDstJitterLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTIDLEDSTJITTER].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "IdlDstJitter");
*/
}

void
ArgusParseIdleJitterLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseIdleSrcJitterLabel(parser,buf);
   ArgusParseIdleDstJitterLabel(parser,buf);
*/
}


void
ArgusParseStateLabel (struct ArgusParserStruct *parser, char *buf)
{
   int match = 0;

   ArgusParseTCPState = 0;
   ArgusParseState = 0;

   if (!(strcmp (buf, "REQ"))) {  ArgusParseTCPState |= ARGUS_SAW_SYN;
                                     ArgusParseState |= ARGUS_REQUEST; match++; }
   if (!(strcmp (buf, "ACC"))) {  ArgusParseTCPState |= ARGUS_SAW_SYN_SENT; match++; }
   if (!(strcmp (buf, "CON"))) {  ArgusParseTCPState |= ARGUS_CON_ESTABLISHED; match++; }
   if (!(strcmp (buf, "TIM"))) {  ArgusParseTCPState |= ARGUS_TIMEOUT; match++; }
   if (!(strcmp (buf, "CLO"))) {  ArgusParseTCPState |= ARGUS_NORMAL_CLOSE; match++; }
   if (!(strcmp (buf, "FIN"))) {  ArgusParseTCPState |= ARGUS_FIN; match++; }
   if (!(strcmp (buf, "RST"))) {  ArgusParseTCPState |= ARGUS_RESET; match++; }

   if (!(strcmp (buf, "CON"))) {  ArgusParseState |= ARGUS_CONTINUE; match++; }
   if (!(strcmp (buf, "RSP"))) {  ArgusParseState |= ARGUS_RESPONSE; match++; }
   if (!(strcmp (buf, "INT"))) {  ArgusParseState |= ARGUS_INIT; match++; }

   if (!match) {
      int i;
      for (i = 0; i < ICMP_MAXTYPE; i++) {
         if (icmptypestr[i] != NULL) {
            int len = strlen(icmptypestr[i]);
            if ((len > 0) && !(strncmp (buf, icmptypestr[i], len))) {
               switch (i) {
                  default:
                  case ICMP_MASKREPLY: 
                  case ICMP_ECHOREPLY:  {
                     parser->canon.flow.flow_un.icmp.type = i;
                     parser->canon.flow.flow_un.icmp.code = 0;
                     break;
                  }
                  case ICMP_UNREACH: 
                     parser->canon.flow.flow_un.icmp.type = i;
                     switch (buf[2]) {
                        case 'O': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_PROTOCOL; break;
                        case 'S': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_SRCFAIL; break;
                        case 'I': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_ISOLATED; break;
                        case 'C': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_PRECEDENCE_CUTOFF; break;
                        case 'P': {
                           switch(buf[3]) {
                              case '\0': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_PORT; break;
                              case  'R': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_HOST_PRECEDENCE; break;
                           }
                           break;
                        }
                        case 'F': {
                           switch(buf[3]) { 
                              case '\0': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_NEEDFRAG; break;
                              case  'I': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_FILTER_PROHIB; break;
                           }
                           break;
                        }
                        case 'H': {
                           switch(buf[3]) { 
                              case '\0': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_HOST; break;
                              case  'U': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_HOST_UNKNOWN; break;
                              case  'P': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_HOST_PROHIB; break;
                           }
                           break;
                        }
                        case 'N': {
                           switch(buf[3]) { 
                              case '\0': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_NET; break;
                              case  'U': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_NET_UNKNOWN; break;
                              case  'P': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_NET_PROHIB; break;
                              case  'T': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_TOSHOST; break;
                           }
                           break;
                        }
                     }
                     break;

                  case ICMP_REDIRECT:
                     parser->canon.flow.flow_un.icmp.type = i;
                     switch (buf[2]) {
                        case 'O': parser->canon.flow.flow_un.icmp.code = ICMP_UNREACH_PROTOCOL; break;

                     }
                     break;
               }
            }
         }
      }
   }

   if (!match) {
      if (strchr (buf, 's')) ArgusParseDirStatus |= ARGUS_SAW_SYN;
      if (strchr (buf, 'S')) ArgusParseDirStatus |= ARGUS_SAW_SYN_SENT;
      if (strchr (buf, 'E')) ArgusParseDirStatus |= ARGUS_CON_ESTABLISHED;
      if (strchr (buf, 'f')) ArgusParseDirStatus |= ARGUS_FIN;
      if (strchr (buf, 'F')) ArgusParseDirStatus |= ARGUS_FIN_ACK;
      if (strchr (buf, 'C')) ArgusParseDirStatus |= ARGUS_NORMAL_CLOSE;
      if (strchr (buf, 'R')) ArgusParseDirStatus |= ARGUS_RESET;
   }
}

void
ArgusParseTCPBaseLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseTCPSrcBaseLabel (parser, buf);
   ArgusParseTCPDstBaseLabel (parser, buf);
*/
}

void
ArgusParseTCPSrcBaseLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTTCPSRCBASE].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SrcTCPBase");
*/
}

void
ArgusParseTCPDstBaseLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTTCPDSTBASE].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DstTCPBase");
*/
}

void
ArgusParseTCPRTTLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) &parser->canon.net;
   struct ArgusTCPObject *tcpExt = NULL;
   unsigned int tcprtt = 0;
   char *endptr;

   tcprtt = strtol(buf, &endptr, 10);

   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseSrcPacketsLabel(0x%xs, %s) strtol error %s\n", parser, buf, strerror(errno));

   if (argus->dsrs[ARGUS_NETWORK_INDEX] == NULL) {
      argus->dsrs[ARGUS_NETWORK_INDEX] = &parser->canon.net.hdr;
      argus->dsrindex |= 0x1 << ARGUS_NETWORK_INDEX;

      net->hdr.type              = ARGUS_NETWORK_DSR;
      net->hdr.subtype           = ARGUS_TCP_PERF;
      net->hdr.argus_dsrvl8.qual = 0;
      net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusTCPObject)+3))/4 + 1;

      tcpExt                     = &net->net_union.tcp;
      bzero ((char *)tcpExt, sizeof(*tcpExt));
      tcpExt->synAckuSecs        = 0;
      tcpExt->ackDatauSecs       = tcprtt;
   }
}

void
ArgusParseServiceLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSERVICE].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "Service");
*/
}

void
ArgusParseDeltaDurationLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTADURATION].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dDur");
*/
}

void
ArgusParseDeltaStartTimeLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTASTARTTIME].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dsTime");
*/
}

void
ArgusParseDeltaLastTimeLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTALASTTIME].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dlTime");
*/
}

void
ArgusParseDeltaSrcPktsLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTASRCPKTS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dsPkts");
*/
}

void
ArgusParseDeltaDstPktsLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTADSTPKTS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ddPkts");
*/
}

void
ArgusParseDeltaSrcBytesLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTASRCBYTES].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dsBytes");
*/
}

void
ArgusParseDeltaDstBytesLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDELTADSTBYTES].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ddBytes");
*/
}

void
ArgusParsePercentDeltaSrcPktsLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTPERCENTDELTASRCPKTS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "pdsPkt");
*/
}

void
ArgusParsePercentDeltaDstPktsLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTPERCENTDELTADSTPKTS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "pddPkt");
*/
}

void
ArgusParsePercentDeltaSrcBytesLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTPERCENTDELTASRCBYTES].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "pdsByte");
*/
}

void
ArgusParsePercentDeltaDstBytesLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTPERCENTDELTADSTBYTES].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "pddByte");
*/
}

void
ArgusParseSrcUserDataLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCUSERDATA].length;
   int slen = 0;
 
   if (len > 0) {
      switch (parser->eflag) {
         case ARGUS_ENCODE_ASCII:
            slen = len;
            break;
 
         case ARGUS_ENCODE_32:
         case ARGUS_ENCODE_64:
            slen = len * 2;
            break;
      }
 
      if (len > 10) slen++;
      sprintf (&buf[strlen(buf)], "%*ssrcUdata%*s ", (slen)/2, " ", (slen)/2, " ");
      if (slen & 0x01)
         sprintf(&buf[strlen(buf)], " ");
   }
*/
}

void
ArgusParseDstUserDataLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTUSERDATA].length;
   int slen = 0;

   if (len > 0) {
      switch (parser->eflag) {
         case ARGUS_ENCODE_ASCII:
            slen = len;
            break;

         case ARGUS_ENCODE_32:
         case ARGUS_ENCODE_64:
            slen = len * 2;
            break;
      }

      if (len > 10) slen++;
      sprintf (&buf[strlen(buf)], "%*sdstUdata%*s ", (slen)/2, " ", (slen)/2, " ");
      if (slen & 0x01)
         sprintf(&buf[strlen(buf)], " ");
   }
*/
}

void
ArgusParseUserDataLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcUserDataLabel (parser, buf);
   ArgusParseDstUserDataLabel (parser, buf);
*/
}

void
ArgusParseTCPExtensionsLabel (struct ArgusParserStruct *parser, char *buf)
{
}

void
ArgusParseSrcLoadLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCLOAD].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "Src_pps");
*/
}

void
ArgusParseDstLoadLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTLOAD].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "Dst_pps");
*/
}

void
ArgusParseLoadLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTLOAD].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "Tot_pps");
*/
}


void
ArgusParseSrcLossLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCLOSS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "Src_Loss");
*/
}

void
ArgusParseDstLossLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTLOSS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "Dst_Loss");
*/
}

void
ArgusParseLossLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcLossLabel (parser, buf);
   ArgusParseDstLossLabel (parser, buf);

*/
}

void
ArgusParseSrcPercentLossLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCPERCENTLOSS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "pSrc_Loss");
*/
}

void
ArgusParseDstPercentLossLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTPERCENTLOSS].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "pDst_Loss");
*/
}


void
ArgusParsePercentLossLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcPercentLossLabel (parser, buf);
   ArgusParseDstPercentLossLabel (parser, buf);
*/
}

void
ArgusParseSrcPktSizeLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCPKTSIZE].length;
   if (len > 8)
      sprintf (&buf[strlen(buf)], "%*sSrcPktSz%*s ", (len - 8)/2, " ", (len - 8)/2, " ");
   else
      sprintf (buf, "%*.*s ", len, len, "SrcPktSz");
*/
}

void
ArgusParseDstPktSizeLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTPKTSIZE].length;
   if (len > 8)
      sprintf (&buf[strlen(buf)], "%*sDstPktSz%*s ", (len - 8)/2, " ", (len - 8)/2, " ");
   else
      sprintf (buf, "%*.*s ", len, len, "DstPktSz");
*/
}


void
ArgusParseSrcPktSizeMaxLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCPKTSIZEMAX].length;
   sprintf (buf, "%*.*s ", len, len, "SMaxSz");
*/
}

void
ArgusParseSrcPktSizeMinLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCPKTSIZEMIN].length;
   sprintf (buf, "%*.*s ", len, len, "SMinSz");
*/
}


void
ArgusParseDstPktSizeMaxLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTPKTSIZEMAX].length;
   sprintf (buf, "%*.*s ", len, len, "DMaxSz");
*/
}

void
ArgusParseDstPktSizeMinLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTPKTSIZEMIN].length;
   sprintf (buf, "%*.*s ", len, len, "DMinSz");
*/
}


void
ArgusParseSrcRateLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCRATE].length;
   char *ptr;
   if (parser->Aflag)
      ptr = "SrcApp_bps";
   else
      ptr = "Src_bps";

   sprintf (buf, "%*.*s ", len, len, ptr);
*/
}

void
ArgusParseDstRateLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTRATE].length;
   char *ptr;
   if (parser->Aflag)
      ptr = "DstApp_bps";
   else
      ptr = "Dst_bps";

   sprintf (buf, "%*.*s ", len, len, ptr);
*/
}

void
ArgusParseRateLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTRATE].length;
   char *ptr;
   if (parser->Aflag)
      ptr = "TotApp_bps";
   else 
      ptr = "Tot_bps";
   sprintf (buf, "%*.*s ", len, len, ptr);
*/
}

void
ArgusParseSrcMplsLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCMPLS].length;
   int index = RaPrintAlgorithmTable[ARGUSPRINTSRCMPLS].index;
   int i = 0;

   while (index) {
      if (index & 0x01) {
         char strbuf[32];
         sprintf (strbuf, "sMpls[%d]", i);
         sprintf (&buf[strlen(buf)], "%*.*s ", len, len, strbuf);
      }
      i++;
      index = index >> 1;
   }
*/
}

void
ArgusParseDstMplsLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTMPLS].length;
   int index = RaPrintAlgorithmTable[ARGUSPRINTDSTMPLS].index;
   int i = 0;

   while (index) {
      if (index & 0x01) {
         char strbuf[32];
         sprintf (strbuf, "dMpls[%d]", i);
         sprintf (&buf[strlen(buf)], "%*.*s ", len, len, strbuf);
      }  
      i++;
      index = index >> 1; 
   }  
*/
}

void
ArgusParseMplsLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcMplsLabel (parser, buf);
   ArgusParseDstMplsLabel (parser, buf);
*/
}

void
ArgusParseSrcVLANLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCVLAN].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "sVlan");
*/
}

void
ArgusParseDstVLANLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTVLAN].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dVlan");
*/
}

void
ArgusParseVLANLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcVLANLabel (parser, buf);
   ArgusParseDstVLANLabel (parser, buf);
*/
}

void
ArgusParseSrcVIDLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCVID].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "sVid");
*/
}

void
ArgusParseDstVIDLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTVID].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "dVid");
*/
}

void
ArgusParseVIDLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcVIDLabel (parser, buf);
   ArgusParseDstVIDLabel (parser, buf);
*/
}

void
ArgusParseSrcVPRILabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   sprintf (&buf[strlen(buf)], " sVpri ");
*/
}

void
ArgusParseDstVPRILabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   sprintf (&buf[strlen(buf)], " dVpri ");
*/
}

void
ArgusParseVPRILabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcVPRILabel (parser, buf);
   ArgusParseDstVPRILabel (parser, buf);
*/
}

void
ArgusParseJoinDelayLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTJOINDELAY].length;
   sprintf (&buf[strlen(buf)], "%*sJDelay%*s ", (len - 6)/2, " ", (len - 6)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}

void
ArgusParseLeaveDelayLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTJOINDELAY].length;
   sprintf (&buf[strlen(buf)], "%*sLDelay%*s ", (len - 6)/2, " ", (len - 6)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}


void
ArgusParseWindowLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   ArgusParseSrcWindowLabel (parser, buf);
   ArgusParseDstWindowLabel (parser, buf);
*/
}

void
ArgusParseSrcWindowLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSRCWINDOW].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SrcWin");
*/
}

void
ArgusParseDstWindowLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTDSTWINDOW].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "DstWin");
*/
}

void
ArgusParseDurationLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct timeval tvpbuf, *tvp = &tvpbuf;
   char date[128], *frac;
   char *endptr;

   bzero (date, sizeof(date));
   bcopy (buf, date, strlen(buf));

   if ((frac = strchr(date, '.')) != NULL) {
      int precision;
      *frac++ = '\0';
      tvp->tv_usec = strtol(frac, &endptr, 10);
      if (endptr == frac)
         ArgusLog (LOG_ERR, "ArgusParseDuration(0x%xs, %s) fractonal format error\n", parser, buf);

      if ((precision = strlen(frac)) > 0) {
         int n, power = 6 - precision;

         for (n = 0; n < power; n++)
            tvp->tv_usec *= 10;
      }
   } else
      tvp->tv_usec = 0;

   tvp->tv_sec = strtol(buf, &endptr, 10);
   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseDuration(0x%xs, %s) fractonal format error\n", parser, buf);

   if (parser->canon.time.src.start.tv_sec != 0) {
      parser->canon.time.src.end = parser->canon.time.src.start;
      parser->canon.time.src.end.tv_sec  += tvp->tv_sec;
      parser->canon.time.src.end.tv_usec += tvp->tv_usec;
      if (parser->canon.time.src.end.tv_usec > 1000000) {
         parser->canon.time.src.end.tv_sec++;
         parser->canon.time.src.end.tv_usec -= 1000000;
      }

      parser->canon.time.hdr.subtype |= ARGUS_TIME_ABSOLUTE_TIMESTAMP;	
      parser->canon.time.hdr.subtype |= ARGUS_TIME_SRC_END;

      parser->canon.time.hdr.argus_dsrvl8.qual = ARGUS_TYPE_UTC_MICROSECONDS;
      parser->canon.time.hdr.argus_dsrvl8.len  = 5;
   }
}

void
ArgusParseMeanLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTAVGDURATION].length;
   sprintf (&buf[strlen(buf)], "%*sAvgDur%*s", (len - 6)/2, " ", (len - 6)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}

void
ArgusParseMaxLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTAVGDURATION].length;
   sprintf (&buf[strlen(buf)], "%*sAvgDur%*s", (len - 6)/2, " ", (len - 6)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}

void
ArgusParseMinLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTAVGDURATION].length;
   sprintf (&buf[strlen(buf)], "%*sAvgDur%*s", (len - 6)/2, " ", (len - 6)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}


void
ArgusParseStartRangeLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTSTARTRANGE].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "SRange");
*/
}

void
ArgusParseEndRangeLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTENDRANGE].length;
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, "ERange");
*/
}

void
ArgusParseTransactionsLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTTRANSACTIONS].length;
   char *ptr;
   if (parser->Pctflag)
      ptr = "PctTrans";
   else
      ptr = "Trans";
   sprintf (&buf[strlen(buf)], "%*.*s ", len, len, ptr);
*/
}

void
ArgusParseSequenceNumberLabel (struct ArgusParserStruct *parser, char *buf)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *endptr;

   int value = strtol(buf, &endptr, 10);
   if (endptr == buf)
      ArgusLog (LOG_ERR, "ArgusParseDuration(0x%xs, %s) fractonal format error\n", parser, buf);

   if (argus->dsrs[ARGUS_TRANSPORT_INDEX] == NULL) {
      argus->dsrs[ARGUS_TRANSPORT_INDEX] = &parser->canon.trans.hdr;
      argus->dsrindex |= 0x1 << ARGUS_TRANSPORT_INDEX;

      parser->canon.trans.hdr.type             = ARGUS_TRANSPORT_DSR;
      parser->canon.trans.hdr.subtype         |= ARGUS_SEQ;
      parser->canon.trans.hdr.argus_dsrvl8.len = 3;
   }

   parser->canon.trans.seqnum = value;
}

void
ArgusParseBinNumberLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTBINNUMBER].length;
   sprintf (&buf[strlen(buf)], "%*sBin%*s ", (len - 3)/2, " ", (len - 3)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}

void
ArgusParseBinsLabel (struct ArgusParserStruct *parser, char *buf)
{
/*
   int len = RaPrintAlgorithmTable[ARGUSPRINTBINNUMBER].length;
   sprintf (&buf[strlen(buf)], "%*sBins%*s ", (len - 4)/2, " ", (len - 4)/2, " ");
   if (!(len & 0x01)) sprintf (&buf[strlen(buf)], " ");
*/
}


void ArgusClientTimeout () { return; }
void RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus) { return; }
void RaArgusInputComplete (struct ArgusInput *input) { return; }
void ArgusWindowClose(void) { return; }
int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if ((sig == SIGINT) || (sig == SIGQUIT))
         exit(0);
   }
}
