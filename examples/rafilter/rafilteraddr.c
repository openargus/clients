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
 * rafilteraddr - filter records based on an address list.  bypasses
 *                standard filter compiler.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * $Id: //depot/gargoyle/clients/examples/rafilter/rafilteraddr.c#13 $
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

/*
   IANA style address label configuration file syntax is:
      addr "label"

      where addr is:
         %d[[[.%d].%d].%d]/%d   CIDR address
         CIDR - CIDR            Address range

   The Regional Internet Registries (RIR) database support allows for
   country codes to be associated with address prefixes.  We'll treat
   them as simple labels.   The file syntax is:

      rir|co|[asn|ipv4|ipv6]|#allocatable|[allocated | assigned]

   so if we find '|', we know the format.
   
*/


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusLabelerStruct *labeler = NULL;
   struct ArgusModeStruct *mode = NULL;
   parser->RaWriteOut = 0;

   if (!(parser->RaInitialized)) {
      int ArgusLabelerStatus = ARGUS_LABELER_ADDRESS;

      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "debug", 5))) {
               ArgusLabelerStatus |= ARGUS_TREE_DEBUG;

               if (!(strncasecmp (mode->mode, "debug.node", 10)))
                  ArgusLabelerStatus |= ARGUS_TREE_DEBUG_NODE;
            }
            if (!(strncasecmp (mode->mode, "level=", 6))) {
               extern int RaPrintLabelTreeLevel;
               int value = 0;
               char *endptr = NULL;
               value = strtod(&mode->mode[6], &endptr);
               if (&mode->mode[6] != endptr) {
                  RaPrintLabelTreeLevel = value;
               }
            }

            mode = mode->nxt;
         }
      }

      if (!(parser->ArgusFlowModelFile))
         ArgusLog (LOG_ERR, "ArgusClientInit: no address list, use -f");

      if ((parser->ArgusLabeler = ArgusNewLabeler(parser, ArgusLabelerStatus)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      labeler = parser->ArgusLabeler;

      if (ArgusLabelerStatus & (ARGUS_TREE_DEBUG | ARGUS_TREE_DEBUG_NODE)) {
         if (!(ArgusLabelerStatus & ARGUS_TREE_DEBUG_NODE))
            RaPrintLabelTree (labeler, labeler->ArgusAddrTree[AF_INET], 0, 0);
         exit(0);
      }

      parser->RaInitialized++;
   }
}

void RaArgusInputComplete (struct ArgusInput *input) { return; }


int RaParseCompleting = 0;

void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
         if (ArgusParser->ArgusPrintJson)
            fprintf (stdout, "\n");

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

         fflush(stdout);
         ArgusShutDown(sig);
         exit(0);
      }
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
   fprintf (stdout, "rafilteraddr Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [-v] -f address.file [raoptions] \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "options: -f          specify file containing address(es).\n");
   fprintf (stdout, "         -v          invert the logic and print flows that don't match.\n");
   fprintf (stdout, "         -M level=x  set the level when printing out the address tree.\n");
   fflush (stdout);
   exit(1);
}

char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;

   int retn = 0;
   int mode = ARGUS_SUPER_MATCH;

   if (parser->ArgusLabelRecord > 0) {
      mode |= ARGUS_LABEL_RECORD;
   }

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         if (flow) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        if ((!retn && parser->ArgusAggregator->mask & ARGUS_MASK_SADDR_INDEX))
                           retn = RaProcessAddressLocality(parser, labeler, argus, &flow->ip_flow.ip_src, 32, ARGUS_TYPE_IPV4, mode | ARGUS_MASK_SADDR_INDEX);
                        if (!retn && (parser->ArgusAggregator->mask & ARGUS_MASK_DADDR_INDEX))
                           retn = RaProcessAddressLocality(parser, labeler, argus, &flow->ip_flow.ip_dst, 32, ARGUS_TYPE_IPV4, mode | ARGUS_MASK_DADDR_INDEX);
                        break;
                     }
                     case ARGUS_TYPE_IPV6: {
                        if (!retn && (parser->ArgusAggregator->mask & ARGUS_MASK_SADDR_INDEX))
                           retn = RaProcessAddressLocality(parser, labeler, argus, (unsigned int *) &flow->ipv6_flow.ip_src, 128, ARGUS_TYPE_IPV6, mode | ARGUS_MASK_SADDR_INDEX);
                        if (!retn && (parser->ArgusAggregator->mask & ARGUS_MASK_DADDR_INDEX))
                           retn = RaProcessAddressLocality(parser, labeler, argus, (unsigned int *) &flow->ipv6_flow.ip_dst, 128, ARGUS_TYPE_IPV6, mode | ARGUS_MASK_DADDR_INDEX);
                        break;
                     }
                     case ARGUS_FLOW_ARP: {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_ARP: {
                              if ((!retn && parser->ArgusAggregator->mask & ARGUS_MASK_SADDR_INDEX)) {
                                 unsigned int *saddr = (unsigned int *)&flow->arp_flow.arp_spa;
                                 retn = RaProcessAddressLocality(parser, labeler, argus, saddr, 32, ARGUS_TYPE_IPV4, mode | ARGUS_MASK_SADDR_INDEX);
                              }
                              if (!retn && (parser->ArgusAggregator->mask & ARGUS_MASK_DADDR_INDEX)) {
                                 unsigned int *daddr = (unsigned int *)&flow->arp_flow.arp_tpa;
                                 retn = RaProcessAddressLocality(parser, labeler, argus, daddr, 32, ARGUS_TYPE_IPV4, mode | ARGUS_MASK_DADDR_INDEX);
                              }
                              break;
                           }
                           case ARGUS_TYPE_RARP: {
                              break;
                           }
                        }
                        break;
                     }
                  }
                  break; 
               }
               case ARGUS_FLOW_ARP: {
                  if ((!retn && parser->ArgusAggregator->mask & ARGUS_MASK_SADDR_INDEX)) {
                     unsigned int *saddr = (unsigned int *)&flow->arp_flow.arp_spa;
                     retn = RaProcessAddressLocality(parser, labeler, argus, saddr, 32, ARGUS_TYPE_IPV4, mode | ARGUS_MASK_SADDR_INDEX);
                  }
                  if (!retn && (parser->ArgusAggregator->mask & ARGUS_MASK_DADDR_INDEX)) {
                     unsigned int *daddr = (unsigned int *)&flow->arp_flow.arp_tpa;
                     retn = RaProcessAddressLocality(parser, labeler, argus, daddr, 32, ARGUS_TYPE_IPV4, mode | ARGUS_MASK_DADDR_INDEX);
                  }
                  break;
               }
            }
         }

         if (parser->vflag)
            retn = (retn) ? 0 : 1;

         if (parser->ArgusWfileList != NULL) {
            struct ArgusWfileStruct *wfile = NULL;
            struct ArgusListObjectStruct *lobj = NULL;
            int i, count = parser->ArgusWfileList->count;

            if ((lobj = parser->ArgusWfileList->start) != NULL) {
               for (i = 0; i < count; i++) {
                  if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                     struct ArgusRecord *argusrec = NULL;
                     if ((argusrec = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
                        int rv = 0;

#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        if (parser->exceptfile != NULL) {

                           if (retn && strcmp(wfile->filename, parser->exceptfile))
                              rv = ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                           else
                              if (!retn && !strcmp(wfile->filename, parser->exceptfile))
                                 rv = ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);

                        } else {
                           if (retn)
                              rv = ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                        }

                        if (rv < 0)
                           ArgusLog(LOG_ERR, "%s unable to open file\n", __func__);
                     }
                  }

                  lobj = lobj->nxt;
               }
            }

         } else {
            if (retn) {
               char buf[MAXSTRLEN];
               if (!parser->qflag) {
                  if (parser->Lflag && !(ArgusParser->ArgusPrintJson)) {
                     if (parser->RaLabel == NULL)
                        parser->RaLabel = ArgusGenerateLabel(parser, argus);
          
                     if (!(parser->RaLabelCounter++ % parser->Lflag))
                        printf ("%s\n", parser->RaLabel);
          
                     if (parser->Lflag < 0)
                        parser->Lflag = 0;
                  }

                  buf[0] = 0;
                  ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);
                  if (fprintf (stdout, "%s", buf) < 0)
                     RaParseComplete(SIGQUIT);
               }
               if (parser->ArgusWfileList == NULL)
                  if (!(parser->ArgusPrintJson)) 
                     if (fprintf (stdout, "\n") < 0)
                        RaParseComplete(SIGQUIT);
            }
         }

         break;
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

