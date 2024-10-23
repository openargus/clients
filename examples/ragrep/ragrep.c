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
 * 
 * $Id: //depot/gargoyle/clients/examples/ragrep/ragrep.c#7 $
 * $DateTime: 2016/10/28 18:37:18 $
 * $Change: 3235 $
 */

/*
 *
 * ragrep.c  - grep () implementation for argus user data searching.
 *
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(CYGWIN)
#define USE_IPV6
#endif

#include <unistd.h>
#include <stdlib.h>

#include <argus_compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <argus_grep.h>

#include <signal.h>
#include <ctype.h>

static int argus_version = ARGUS_VERSION;

extern int ArgusTotalMarRecords;
extern int ArgusTotalFarRecords;

extern struct ArgusParserStruct *ArgusParser;

int ArgusParseGrepExpressionFile(struct ArgusParserStruct *, char *);

#define ARGUS_GREP_BUFFER	1048576	
#define ARGUS_GREP_STRLEN	65536

char *ArgusGrepBuffer = NULL;
int ArgusRecordMatches = 0;
int ArgusTotalMatches = 0;

int
ArgusParseGrepExpressionFile(struct ArgusParserStruct *parser, char *file) {
   char buffer [ARGUS_GREP_STRLEN];
   int eop = 0, retn = 0;
   char *sptr = NULL, *eptr = NULL;
   FILE *fd;

   if (file) {
      if ((fd = fopen (file, "r")) != NULL) {
         while (fgets (buffer, ARGUS_GREP_STRLEN, fd)) {
            if ((*buffer != '#') && (*buffer != '\n') && (*buffer != '!') && strlen(buffer)) {
               int slen = strlen(buffer);

               while (buffer[slen - 1] == '\n') {
                  buffer[slen - 1] = '\0';
                  slen--;
               }

               if (buffer[slen - 1] == '\\') {
                  buffer[slen - 1] = '\0';
                  slen--;
               } else {
                  eop++;
               }

               if (ArgusGrepBuffer == NULL) {
                  if ((ArgusGrepBuffer = calloc(1, ARGUS_GREP_BUFFER)) == NULL)
                     ArgusLog (LOG_ERR, "ArgusCalloc error %s\n", strerror(errno));

                  sptr = ArgusGrepBuffer;
                  eptr = ArgusGrepBuffer + ARGUS_GREP_BUFFER;
                  parser->estr = ArgusGrepBuffer;
               }

               if ((sptr + slen) < eptr) {
                  bcopy(buffer, sptr, slen);
                  sptr += slen;
               }

               if (eop) {
                  if (*ArgusGrepBuffer != '\0') {
                     ArgusInitializeGrep(parser);
                     bzero(ArgusGrepBuffer, ARGUS_GREP_BUFFER);
                     sptr = ArgusGrepBuffer;
                  }
               }
            }

            eop = 0;
         }

         if (*ArgusGrepBuffer != '\0')
            ArgusInitializeGrep(parser);

         fclose (fd);


      } else {
         retn = 1;
         ArgusLog (LOG_ERR, "%s %s\n", file,  strerror(errno));
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusParseGrepExpressionFile(0x%x, %s) done\n", parser, file);
#endif
   return (retn);
}

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   parser->RaWriteOut = 0;
   parser->ArgusPrintMan = 0;

   if (!(parser->RaInitialized)) {

      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      if (parser->ArgusFlowModelFile) {
         parser->ArgusGrepSource++;
         parser->ArgusGrepDestination++;
 
         if (ArgusParseGrepExpressionFile (parser, parser->ArgusFlowModelFile) != 0)
            ArgusLog (LOG_ERR, "ArgusClientInit: ArgusParseGrepExpression error");
      }


      if (parser->Lflag < 0)
         parser->Lflag = 0;

      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input) { 
   if (input->major_version > 0) {

      if (ArgusParser->Lflag) {
         if (ArgusRecordMatches == 0) {
            printf ("%s\n", input->filename);
         }
      } else
      if (ArgusParser->lflag) {
         if (ArgusRecordMatches > 0) {
            printf ("%s\n", input->filename);
         }
      } else
      if (ArgusParser->cflag)
         printf ("%s:%d\n", input->filename, ArgusRecordMatches);
   }

   ArgusTotalMatches += ArgusRecordMatches;
   ArgusRecordMatches = 0;

   return; 
}


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
         if (ArgusParser->ArgusPrintJson)
            fprintf (stdout, "\n");

#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(caught signal %d)\n", sig);
#endif
         switch (sig) {
            case SIGHUP:
            case SIGINT:
            case SIGTERM:
            case SIGQUIT: {
               struct ArgusWfileStruct *wfile = NULL;

               ArgusShutDown(0);

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

               if (ArgusTotalMatches > 0)
                  exit(0);
               else
                  exit(1);
               break;
            }
         }
      }
   }
}


void
ArgusClientTimeout ()
{
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusClientTimeout()\n");
#endif
}

void
parse_arg (int argc, char**argv)
{}

void
usage ()
{
   extern char version[];

   fprintf (stdout, "Ragrep Version %s\n", version);
   fprintf (stdout, "usage: %s -bcHhiLnqv [-e regex] [-f regex.file] [raoptions]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -b                 print the byte offset within the input file before each record of output.\n");
   fprintf (stdout, "         -c <char>          Suppress normal output, print a count of matching records for each input file.\n");
#if defined (ARGUSDEBUG)
   fprintf (stdout, "         -D <level>         specify debug level\n");
#endif
   fprintf (stdout, "         -e <regex>         match regular expression in flow user data fields.\n");
   fprintf (stdout, "                            Prepend the regex with either \"s:\" or \"d:\" to limit the match\n");
   fprintf (stdout, "                            to either the source or destination user data fields.\n");
   fprintf (stdout, "         -f <regex.file>    Obtain patterns from regex.file, one per line.\n");
   fprintf (stdout, "         -H                 print the filename for each record match.\n");
   fprintf (stdout, "         -h                 suppress the prefixing of filenames on output when multiple files are searched.\n");
   fprintf (stdout, "         -i                 ignore case distinctions in both the pattern and the input files.\n");
   fprintf (stdout, "         -L                 Suppress normal output, print the name of each input file from which no output would normally have been printed.\n");
   fprintf (stdout, "         -l                 Suppress normal output, print the name of each input file from which output would normally have been printed.\n");
   fprintf (stdout, "         -q                 quiet mode. don't print record outputs.\n");
   fprintf (stdout, "         -v                 invert the sense of matching, to select non-matching records.\n");
   fflush (stdout);
   exit(1);
}


void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
         RaProcessManRecord (parser, argus);
         break;

      case ARGUS_EVENT:
         RaProcessEventRecord (parser, argus);
         break;

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         if (parser->qflag) {
            exit(0);
         } else {
            struct ArgusMetricStruct *metric = (void *)argus->dsrs[ARGUS_METRIC_INDEX];
            ArgusRecordMatches++;

            if (metric != NULL) {
               parser->ArgusTotalPkts  += metric->src.pkts;
               parser->ArgusTotalPkts  += metric->dst.pkts;
               parser->ArgusTotalBytes += metric->src.bytes;
               parser->ArgusTotalBytes += metric->dst.bytes;
            }

            if (parser->RaMonMode) {
               struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(argus);
               struct ArgusFlow *flow;

               if ((flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
                  flow->hdr.subtype &= ~ARGUS_REVERSE;
                  flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
               }

               RaProcessThisRecord(parser, argus);
               ArgusReverseRecord(tns);

               if ((flow = (void *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
                  flow->hdr.subtype &= ~ARGUS_REVERSE;
                  flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
               }

               RaProcessThisRecord(parser, tns);
               ArgusDeleteRecordStruct(parser, tns);

            } else {
               RaProcessThisRecord(parser, argus);
            }
         }
      }

      if (parser->mflag && (parser->mflag <= ArgusRecordMatches)) {
         parser->RaParseDone++;
      }
   }
}


char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];

void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   static char buf[MAXSTRLEN];

   switch (parser->ArgusPassNum)  {
      case 2: {
         if (parser->Pctflag) {
            if (parser->ns == NULL) {
               parser->ns = ArgusCopyRecordStruct(argus);
            } else {
               ArgusMergeRecords (parser->ArgusAggregator, parser->ns, argus);
            }
         }
         break;
      }

      case 1: {
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
                           int rv;

                           if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
      #ifdef _LITTLE_ENDIAN
                              ArgusHtoN(argusrec);
      #endif
                              rv = ArgusWriteNewLogfile (parser, argus->input,
                                                         wfile, argusrec);
                              if (rv < 0)
                                 ArgusLog(LOG_ERR, "%s unable to open file\n",
                                          __func__);
                           }
                        }
                     }
                  }
      
                  lobj = lobj->nxt;
               }
            }
      
         } else {
            if (!(parser->qflag || parser->Lflag || parser->lflag || parser->cflag)) {
               if (!(parser->ArgusPrintXml) && !(ArgusParser->ArgusPrintJson)) {
                  if (parser->RaLabel == NULL)
                     parser->RaLabel = ArgusGenerateLabel(parser, argus);
               }
      
               bzero (buf, sizeof(buf));
               ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);

               if (argus->input->filename != NULL)
                  if (((parser->ArgusInputFileCount > 1) || parser->Hflag) && !(parser->hflag))
                     fprintf (stdout, "%s:", argus->input->filename);

               if (parser->bflag)
                  fprintf (stdout, "%lld:", argus->offset);

               if (fprintf (stdout, "%s", buf) < 0)
                  RaParseComplete(SIGQUIT);
      
               if (parser->eflag == ARGUS_HEXDUMP) {
                  char *sbuf;
                  int i;

                  if ((sbuf = ArgusCalloc(1, 65536)) == NULL)
                     ArgusLog (LOG_ERR, "RaProcessThisRecord: ArgusCalloc error");

                  for (i = 0; i < MAX_PRINT_ALG_TYPES; i++) {
                     if (ArgusParser->RaPrintAlgorithmList[i] != NULL) {
                        struct ArgusDataStruct *user = NULL;
                        if (ArgusParser->RaPrintAlgorithmList[i]->print == ArgusPrintSrcUserData) {
                           int slen = 0, len = ArgusParser->RaPrintAlgorithmList[i]->length;
                           if (len > 0) {
                              if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) != NULL) {
                                 if (user->hdr.type == ARGUS_DATA_DSR) {
                                    slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                                 } else
                                    slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

                                 slen = (user->count < slen) ? user->count : slen;
                                 slen = (slen > len) ? len : slen;
                                 ArgusDump ((const u_char *) &user->array, slen, "      ", sbuf);
                                 printf ("%s\n", sbuf);
                              }
                           }
                        }
                        if (ArgusParser->RaPrintAlgorithmList[i]->print == ArgusPrintDstUserData) {
                           int slen = 0, len = ArgusParser->RaPrintAlgorithmList[i]->length;
                           if (len > 0) {
                              if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) != NULL) {
                                 if (user->hdr.type == ARGUS_DATA_DSR) {
                                    slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
                                 } else
                                    slen = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

                                 slen = (user->count < slen) ? user->count : slen;
                                 slen = (slen > len) ? len : slen;
                                 ArgusDump ((const u_char *) &user->array, slen, "      ", sbuf);
                                 printf ("%s\n", sbuf);
                              }
                           }
                        }
                     } else
                        break;
                  }
                  ArgusFree(sbuf);
               }
      
               if (!(ArgusParser->ArgusPrintJson))
                  fprintf (stdout, "\n");
               fflush (stdout);
            }
         }
      }
   }
}

void
RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   static char buf[MAXSTRLEN];

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
                     int rv;

                     if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        rv = ArgusWriteNewLogfile (parser, argus->input,
                                                   wfile, argusrec);
                        if (rv < 0)
                           ArgusLog(LOG_ERR, "%s unable to open file\n",
                                    __func__);
                     }
                  }
               }
            }

            lobj = lobj->nxt;
         }
      }

   } else {

      if ((parser->ArgusPrintMan) && (!parser->qflag)) {
         if (parser->Lflag && (!(parser->ArgusPrintXml) && !(ArgusParser->ArgusPrintJson))) {
            if (parser->RaLabel == NULL)
               parser->RaLabel = ArgusGenerateLabel(parser, argus);
 
            if (!(parser->RaLabelCounter++ % parser->Lflag))
               printf ("%s\n", parser->RaLabel);
 
            if (parser->Lflag < 0)
               parser->Lflag = 0;
         }

         bzero (buf, sizeof(buf));
         if (argus->dsrs[0] != NULL) {
            ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);

            if (parser->ArgusPrintJson) {
               if (fprintf (stdout, "%s", buf) < 0)
                  RaParseComplete (SIGQUIT);
            } else {
               if (fprintf (stdout, "%s\n", buf) < 0)
                  RaParseComplete (SIGQUIT);
            }
         }
         fflush (stdout);
      }
   }

#ifdef ARGUSDEBUG
   {
      struct ArgusRecord *rec = (struct ArgusRecord *)argus->dsrs[0];
      if (rec != NULL) {
         struct ArgusMarStruct *mar = &rec->ar_un.mar;
         ArgusDebug (6, "RaProcessManRecord (0x%x, 0x%x) mar parsed 0x%x", parser, argus, mar); 
      }
   }
#endif
}


void
RaProcessEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   static char buf[MAXSTRLEN];

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
                     int rv;

                     if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        rv = ArgusWriteNewLogfile (parser, argus->input,
                                                   wfile, argusrec);
                        if (rv < 0)
                           ArgusLog(LOG_ERR, "%s unable to open file\n",
                                    __func__);
                     }
                  }
               }
            }

            lobj = lobj->nxt;
         }
      }

   } else {

      if ((parser->ArgusPrintEvent) && (!parser->qflag)) {
         if (parser->Lflag && (!(parser->ArgusPrintXml) && !(ArgusParser->ArgusPrintJson))) {
            if (parser->RaLabel == NULL)
               parser->RaLabel = ArgusGenerateLabel(parser, argus);
 
            if (!(parser->RaLabelCounter++ % parser->Lflag))
               printf ("%s\n", parser->RaLabel);
 
            if (parser->Lflag < 0)
               parser->Lflag = 0;
         }

         bzero (buf, sizeof(buf));
         ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);

         if (parser->ArgusPrintJson) {
            if (fprintf (stdout, "%s", buf) < 0)
               RaParseComplete (SIGQUIT);
         } else {
            if (fprintf (stdout, "%s\n", buf) < 0)
               RaParseComplete (SIGQUIT);
         }
         fflush (stdout);
      }
   }

#ifdef ARGUSDEBUG
   {
      struct ArgusRecord *rec = (struct ArgusRecord *)argus->dsrs[0];

      if (rec != NULL) {
         struct ArgusEventStruct *event = &rec->ar_un.event;
         ArgusDebug (6, "RaProcessEventRecord (0x%x, 0x%x) event parsed 0x%x", parser, argus, event); 
      }
   }
#endif
}


int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}
