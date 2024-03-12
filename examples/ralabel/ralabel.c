/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 */

/*
 * ralabel - add descriptor labels to flows.
 *           this particular labeler adds descriptors based
 *           on addresses.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * $Id: //depot/gargoyle/clients/examples/ralabel/ralabel.c#17 $
 * $DateTime: 2016/11/30 00:54:11 $
 * $Change: 3245 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>

#if defined(ARGUS_SOLARIS)
#include <strings.h>
#include <string.h>
#endif

#include <math.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_label.h>
#include <argus_client.h>
#include <argus_filter.h>
#include <argus_main.h>
#include <argus_cluster.h>

static int argus_version = ARGUS_VERSION;


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   extern int RaPrintLabelTreeLevel;
   struct ArgusModeStruct *mode = NULL;
   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      if ((parser->ArgusLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      if (parser->ArgusLocalLabeler == NULL)
         if ((parser->ArgusLocalLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strcmp ("replace", mode->mode))) {
               ArgusProcessFileIndependantly = 1;
               parser->ArgusReplaceMode |= ARGUS_REPLACE_MODE_TRUE;

               if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList)))) {
                  ArgusLog (LOG_ERR, "replace mode and -w option are incompatible\n");
               }
            } else
            if (!(strncasecmp (mode->mode, "noprune", 7))) {
               if (parser->ArgusLabeler) parser->ArgusLabeler->prune = 0;
               if (parser->ArgusLocalLabeler) parser->ArgusLocalLabeler->prune = 0;
            } else
            if (!(strncasecmp (mode->mode, "addr", 4))) {
               if (parser->ArgusFlowModelFile) {
                  if (!(RaReadAddressConfig (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile) > 0))
                     ArgusLog (LOG_ERR, "ArgusNewLabeler: RaReadAddressConfig error");
                  parser->ArgusFlowModelFile = NULL;
		  parser->ArgusLabeler->RaLabelIanaAddress = 1;
               }
            } else
            if (!(strncasecmp (mode->mode, "debug.local", 10))) {
               if (parser->ArgusLocalLabeler != NULL) {
                  parser->ArgusLocalLabeler->RaPrintLabelTreeMode = ARGUS_TREE;
                  if (!(strncasecmp (mode->mode, "debug.localnode", 14))) {
                     parser->ArgusLocalLabeler->status |= ARGUS_LABELER_DEBUG_NODE;
                  } else
                     parser->ArgusLocalLabeler->status |= ARGUS_LABELER_DEBUG_LOCAL;
               }
            } else
            if ((!(strncasecmp (mode->mode, "debug.tree", 10))) ||
                (!(strncasecmp (mode->mode, "debug", 5)))) {
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE;
               parser->ArgusLabeler->status |= ARGUS_LABELER_DEBUG;
            }

            mode = mode->nxt;
         }
      }

      if (parser->ArgusFlowModelFile) {
         RaLabelParseResourceFile (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile);
         parser->ArgusFlowModelFile = NULL;
      }

      if (parser->ArgusLabeler &&  parser->ArgusLabeler->status & ARGUS_LABELER_DEBUG) {
         if (parser->ArgusLabeler && parser->ArgusLabeler->ArgusAddrTree) {
            if (parser->Lflag > 0) {
               RaPrintLabelTreeLevel = parser->Lflag;
            }
            RaPrintLabelTree (parser->ArgusLabeler, parser->ArgusLabeler->ArgusAddrTree[AF_INET], 0, 0);
         }
         exit(0);
      }

      if (parser->ArgusLocalLabeler && ((parser->ArgusLocalLabeler->status & ARGUS_LABELER_DEBUG_LOCAL) ||
                                        (parser->ArgusLocalLabeler->status & ARGUS_LABELER_DEBUG_NODE))) {
         if (parser->ArgusLocalLabeler &&  parser->ArgusLocalLabeler->ArgusAddrTree) {
            if (parser->Lflag > 0) {
               RaPrintLabelTreeLevel = parser->Lflag;
            }
            RaPrintLabelTree (parser->ArgusLocalLabeler, parser->ArgusLocalLabeler->ArgusAddrTree[AF_INET], 0, 0);
         }
         exit(0);
      }

      parser->RaInitialized++;
   }
}

void
RaArgusInputComplete (struct ArgusInput *input) 
{
   if (ArgusProcessFileIndependantly) {
      ArgusParser->ArgusCurrentInput = input;

      RaParseComplete (0);

      if (ArgusParser->ArgusReplaceMode && input) {
         if (ArgusParser->ArgusWfileList != NULL) {
            struct ArgusWfileStruct *wfile = NULL;

            if ((wfile = (void *)ArgusParser->ArgusWfileList->start) != NULL) {
               fflush (wfile->fd);
               rename (wfile->filename, input->filename);
               fclose (wfile->fd);
               wfile->fd = NULL;
            }

            ArgusDeleteList(ArgusParser->ArgusWfileList, ARGUS_WFILE_LIST);
            ArgusParser->ArgusWfileList = NULL;

            if (ArgusParser->Vflag)
               ArgusLog(LOG_INFO, "file %s labeled", input->filename);
         }
      }
      ArgusParser->RaInitialized = 0;
      ArgusParser->ArgusCurrentInput = NULL;
      ArgusClientInit(ArgusParser);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (7, "RaArgusInputComplete(0x%x) done", input);
#endif
}


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
         switch (sig) {
            case SIGHUP:
            case SIGINT:
            case SIGTERM:
            case SIGQUIT: {
               struct ArgusWfileStruct *wfile = NULL;
               ArgusShutDown(sig);

               if (ArgusParser->ArgusWfileList != NULL) {
                  struct ArgusListObjectStruct *lobj = NULL;
                  int i, count = ArgusParser->ArgusWfileList->count;

                  if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
                     for (i = 0; i < count; i++) {
                        if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                           if (wfile->fd != NULL) {
#ifdef ARGUSDEBUG
                              ArgusDebug (2, "RaParseComplete: closing %s\n", wfile->filename);
#endif
                              fflush (wfile->fd);
                              fclose (wfile->fd);
                              wfile->fd = NULL;
                           }
                        }
                        lobj = lobj->nxt;
                     }
                  }
               }
               exit(0);
               break;
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaParseComplete (%d) returning\n", sig);
#endif
}

void
ArgusClientTimeout ()
{
   struct timeval tvbuf, *tvp = &tvbuf;

   if (!(ArgusParser->Pauseflag)) {
      gettimeofday(&ArgusParser->ArgusRealTime, 0);
      ArgusAdjustGlobalTime (ArgusParser, NULL);
   }

   *tvp = ArgusParser->ArgusGlobalTime;
   ArgusGetInterfaceAddresses(ArgusParser);

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusClientTimeout: returning\n");
#endif
}

void
parse_arg (int argc, char**argv)
{ 

#ifdef ARGUSDEBUG
   ArgusDebug (6, "parse_arg (%d, 0x%x) returning\n", argc, argv);
#endif
}


void
usage ()
{
   extern char version[];
   fprintf (stdout, "RaLabeler Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [ra-options] -S remoteServer  [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [ra-options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "options: -f <conffile>     read ralabel spec from <conffile>.\n");
   fflush (stdout);
   exit(1);
}

/*
char *RaLabelProcessAddress (struct ArgusParserStruct *, struct ArgusRecordStruct *, unsigned int *, int);

char *
RaLabelProcessAddress (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, unsigned int *addr, int type)
{
   struct ArgusLabelerStruct *labeler = NULL;
   struct RaAddressStruct *raddr;
   char *retn = NULL;

   if ((labeler = parser->ArgusLabeler) == NULL)
      ArgusLog (LOG_ERR, "RaLabelProcessAddress: No labeler\n");

   if (labeler->ArgusAddrTree != NULL) {
      switch (type) {
         case ARGUS_TYPE_IPV4: {
            struct RaAddressStruct node;
            bzero ((char *)&node, sizeof(node));

            node.addr.type = AF_INET;
            node.addr.len = 4;
            node.addr.addr[0] = *addr;
            node.addr.masklen = 32;

            if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_LONGEST_MATCH)) != NULL)
               retn = raddr->label;
            else {
               char *ptr, *sptr;
               if ((ptr = ArgusGetName(ArgusParser, (u_char *)addr)) != NULL) {
                  if ((sptr = strrchr(ptr, '.')) != NULL) {
                     if (strlen(++sptr) == 2) {
                        if (!isdigit((int)*sptr)) {
                           char *tptr = sptr;
                           int i, ch;
                           for (i = 0; i < 2; i++, tptr++) {
                              ch = *tptr;
                              if (islower(ch)) {
                                 ch = toupper(ch);
                                 *tptr = ch;
                              }
                           }
                           retn = sptr;
                        }
                     }
                  }
               }
            }

            break;
         }

         case ARGUS_TYPE_IPV6:
            break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaLabelProcessAddress (0x%x, 0x%x, 0x%x, %d) returning %s\n", parser, argus, addr, type, retn);
#endif

   return (retn);
}
*/


char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusInput *input = argus->input;
   struct ArgusRecordStruct *ns = NULL;
   static char buf[MAXSTRLEN];
   int label;

   if (ArgusParser->ArgusReplaceMode && input) {
      if (parser->ArgusWfileList == NULL) {
         if (!(ArgusParser->ArgusRandomSeed))
            srandom(ArgusParser->ArgusRandomSeed);

         srandom (ArgusParser->ArgusRealTime.tv_usec);
         label = random() % 100000;

         bzero(buf, sizeof(buf));
         snprintf (buf, MAXSTRLEN, "%s.tmp%d", input->filename, label);

         setArgusWfile(ArgusParser, buf, NULL);
      }
   }

   if ((ns = ArgusCopyRecordStruct(argus)) != NULL) {
      ArgusLabelRecord(parser, ns);

      if (parser->ArgusWfileList != NULL) {
         struct ArgusWfileStruct *wfile = NULL;
         struct ArgusListObjectStruct *lobj = NULL;
         int i, count = parser->ArgusWfileList->count;

         if ((lobj = parser->ArgusWfileList->start) != NULL) {
            for (i = 0; i < count; i++) {
               if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                  if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                     struct ArgusRecord *argusrec = NULL;
                     int rv;

                     if ((argusrec = ArgusGenerateRecord (ns, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        rv = ArgusWriteNewLogfile (parser, ns->input, wfile, argusrec);
                        if (rv < 0)
                           ArgusLog(LOG_ERR, "%s unable to open file\n", __func__);
                     }
                  }
               }

               lobj = lobj->nxt;
            }
         }

      } else {
         if (!parser->qflag) {
            if (parser->Lflag && (!(parser->ArgusPrintXml) && !(ArgusParser->ArgusPrintJson))) {
               if (parser->RaLabel == NULL)
                  parser->RaLabel = ArgusGenerateLabel(parser, ns);
    
               if (!(parser->RaLabelCounter++ % parser->Lflag))
                  printf ("%s\n", parser->RaLabel);
    
               if (parser->Lflag < 0)
                  parser->Lflag = 0;
            }

            buf[0] = 0;
            ArgusPrintRecord(parser, buf, ns, MAXSTRLEN);
            if (parser->ArgusPrintJson) {
               if (fprintf (stdout, "%s", buf) < 0)
                  RaParseComplete (SIGQUIT);
            } else {
               if (fprintf (stdout, "%s\n", buf) < 0)
                  RaParseComplete (SIGQUIT);
            }
         }
      }
                    
      fflush (stdout);
      ArgusDeleteRecordStruct(parser, ns);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessRecord (0x%x) returning\n", argus);
#endif
}


int
RaSendArgusRecord(struct ArgusRecordStruct *argus)
{

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaSendArgusRecord (0x%x) returning\n", argus);
#endif
   return 1;
}

void ArgusWindowClose(void) { } 

