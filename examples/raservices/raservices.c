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
 * raservices - discover and validate network services.
 *              add ArgusLabelStruct to the argus record
 *              if writing the record out.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * 
 * $Id: //depot/argus/clients/examples/raservices/raservices.c#12 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_label.h>
#include <argus_client.h>
#include <argus_filter.h>
#include <argus_main.h>


int ArgusReplace   = 0;
int ArgusExtend    = 0;
int ArgusDiff      = 0;


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      if ((ArgusLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      parser->ArgusLabeler = ArgusLabeler;

      if (parser->ArgusFlowModelFile) {
         RaReadSrvSignature (parser, parser->ArgusLabeler, parser->ArgusFlowModelFile);
         parser->ArgusFlowModelFile = NULL;
      }

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "replace", 7)))
               ArgusReplace = 1;
            if (!(strncasecmp (mode->mode, "extend", 6)))
               ArgusExtend = 1;
            if (!(strncasecmp (mode->mode, "diff", 4)))
               ArgusDiff = 1;

            mode = mode->nxt;
         }
      }
      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input) {};

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
         if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
            struct ArgusWfileStruct *wfile = NULL, *start = NULL;
 
            if ((wfile = (struct ArgusWfileStruct *) ArgusFrontList(ArgusParser->ArgusWfileList)) != NULL) {
               start = wfile;
               fflush(wfile->fd);
               ArgusPopFrontList(ArgusParser->ArgusWfileList, ARGUS_NOLOCK);
               ArgusPushBackList(ArgusParser->ArgusWfileList, (struct ArgusListRecord *) wfile, ARGUS_NOLOCK);
               wfile = (struct ArgusWfileStruct *) ArgusFrontList(ArgusParser->ArgusWfileList);
            } while (wfile != start);
         } 

         ArgusShutDown(sig);
      }

      fflush(stdout);
      exit(0);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaParseComplete (%d) returning\n", sig);
#endif
}

void
ArgusClientTimeout ()
{

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
   fprintf (stdout, "%s Version %s\n", ArgusParser->ArgusProgramName, version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] -S remoteServer  [- filter-expression]\n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] -r argusDataFile [- filter-expression]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -f <conffile>     read service signatures from <conffile>.\n");
   fflush (stdout);

   exit(1);
}




void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
// unsigned short sport = 0, dport = 0;
// int type, proto, process = 0, found = 0;
   int type, process = 0, found = 0;
   struct RaSrvSignature *sig;
   char buf[MAXSTRLEN], name[128];

   bzero (name, sizeof(name));

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (flow) {
            if (argus->dsrs[ARGUS_SRCUSERDATA_INDEX] || argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) {
               switch (flow->hdr.subtype & 0x3F) {
                  case ARGUS_FLOW_CLASSIC5TUPLE: {
                     struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) argus->dsrs[ARGUS_NETWORK_INDEX];
          
                     switch (type = (flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                        case ARGUS_TYPE_IPV4:
                           switch (flow->ip_flow.ip_p) {
                              case IPPROTO_TCP:
                              case IPPROTO_UDP: {
//                               proto = flow->ip_flow.ip_p;
//                               sport = flow->ip_flow.sport;
//                               dport = flow->ip_flow.dport;
                                 process++;
                                 break;
                              }
                           }
                           break; 

                        case ARGUS_TYPE_IPV6: {
                           switch (flow->ipv6_flow.ip_p) {
                              case IPPROTO_TCP:
                              case IPPROTO_UDP: {
//                               proto = flow->ipv6_flow.ip_p;
//                               sport = flow->ipv6_flow.sport;
//                               dport = flow->ipv6_flow.dport;
                                 process++;
                                 break;
                              }
                           }
                           break; 
                        }
                     }
                     if (net && (net->hdr.subtype == ARGUS_RTP_FLOW)) {
                        snprintf (name, 128, "%s", "rtp");
                        found++;
                     } else
                     if (net && (net->hdr.subtype == ARGUS_RTCP_FLOW)) {
                        snprintf (name, 128, "%s", "rtcp");
                        found++;
                     }
                     break; 
                  }
               }

               if (process) {
                  int length = 0;

                  if ((length = strlen(name)) == 0) {
#ifdef ARGUSDEBUG
                     ArgusDebug (5, "RaProcessRecord (0x%x) validating service", argus);
#endif
                     if (!(sig = RaValidateService (parser, argus))) {
                        struct ArgusMetricStruct *metric =  (void *)argus->dsrs[ARGUS_METRIC_INDEX];
                        if ((metric != NULL) && (metric->dst.pkts)) {
                           ArgusReverseRecord(argus);
                           sig = RaValidateService (parser, argus);
                           ArgusReverseRecord(argus);
                        }
                     }

                     if (sig != NULL) {
                        length = strlen(sig->name) + 1;
                        length = ((length > 16) ? 16 : length);
                        snprintf ((char *)name, length, "%s", sig->name);
                        found++;

                     } else {
/*
                        if ((dport > 0) && (dport < 1024)) {
                           int len = RaPrintAlgorithmTable[ARGUSPRINTDSTPORT].length;
                           len = ((len > 16) ? 16 : len);
                           ArgusPrintPort (parser, (char *) name, argus, type, proto, dport, len);
                        } else
                        if ((sport > 0) && (sport < 1024)) {
                           int len = RaPrintAlgorithmTable[ARGUSPRINTDSTPORT].length;
                           len = ((len > 16) ? 16 : len);
                           ArgusPrintPort (parser, (char *) name, argus, type, proto, sport, len);

                        } else 
                           found = 0;
*/
                     }
                  }

                  if (found) {
                     struct ArgusLabelStruct labelbuf, *label = &labelbuf;
                     int len = strlen(name) + 4;

                     bzero((char *)label, sizeof(label));

                     label->hdr.type             = ARGUS_LABEL_DSR;
                     label->hdr.subtype          = ARGUS_SVC_LABEL;
                     label->hdr.argus_dsrvl8.len = 1 + ((len + 3)/4);

                     if (argus->dsrs[ARGUS_LABEL_INDEX] == NULL) {  // working with the canonical record here
                        struct ArgusCanonRecord *canon = &parser->canon;

                        if (argus->input != NULL) {
                           label->l_un.svc = argus->input->ArgusGenerateRecordLabelBuf;
                        } else {
                           extern char ArgusCanonLabelBuffer[MAXBUFFERLEN];
                           label->l_un.svc = ArgusCanonLabelBuffer;
                        }

                        sprintf(label->l_un.svc, "srv=%s", name);
                        bcopy((char *)label, (char *)&canon->label, sizeof(*label));

                        argus->dsrs[ARGUS_LABEL_INDEX] = (struct ArgusDSRHeader*) &canon->label;
                        argus->dsrindex |= (0x01 << ARGUS_LABEL_INDEX);

                     } else {
                        struct ArgusLabelStruct *l1 = (void *) argus->dsrs[ARGUS_LABEL_INDEX];
                        char RaServicesCanonLabelBuffer[MAXSTRLEN];
                        char buf[MAXSTRLEN];
                        int blen;

                        RaServicesCanonLabelBuffer[0] = '\0';
                        label->l_un.svc = RaServicesCanonLabelBuffer;
                        sprintf(label->l_un.svc, "srv=%s", name);

                        bzero(buf, 4);

                        ArgusMergeLabel(l1, label, buf, MAXSTRLEN, ARGUS_UNION);

                        if ((blen = strlen(buf)) > 0) {
                           int len = (blen >= (MAXSTRLEN - 1)) ? MAXSTRLEN - 1 : blen;
                           bcopy(buf, l1->l_un.label, len);
                           l1->l_un.label[len] = '\0';
                        } else
                           *l1->l_un.label = '\0';
                     }
                  }
               }
            }

         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (5, "RaProcessRecord (0x%x) record not validated\n", argus);
#endif
         }
         break;
      }
   }


   if (parser->ArgusWfileList != NULL) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = parser->ArgusWfileList->count;

      if ((lobj = parser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               struct ArgusRecord *argusrec = NULL;
               static char sbuf[0x10000];

               if ((argusrec = ArgusGenerateRecord (argus, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                  ArgusHtoN(argusrec);
#endif
                  if (parser->exceptfile != NULL) {
                     if (strlen (name) && strcmp(wfile->filename, parser->exceptfile))
                        ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                     else
                        if (!strlen (name) && !strcmp(wfile->filename, parser->exceptfile))
                           ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);

                  } else
                     ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
               }
            }
            lobj = lobj->nxt;
         }
      }

   } else {
      if (!parser->qflag) {
         if (parser->Lflag) {
            if (parser->RaLabel == NULL)
               parser->RaLabel = ArgusGenerateLabel(parser, argus);
 
            if (!(parser->RaLabelCounter++ % parser->Lflag))
               printf ("%s\n", parser->RaLabel);
 
            if (parser->Lflag < 0)
               parser->Lflag = 0;
         }

         *(int *)&buf = 0;
         ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);
         if (fprintf (stdout, "%s\n", buf) < 0)
            RaParseComplete(SIGQUIT);
      }
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
