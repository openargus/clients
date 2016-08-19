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
 * rafilteraddr - filter records based on an address list.  bypasses
 *                standard filter compiler.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 * $Id: //depot/argus/clients/examples/rafilter/rafilteraddr.c#12 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
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

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if (!(strncasecmp (mode->mode, "debug.mol", 9))) {
               ArgusLabelerStatus |= ARGUS_MOL;

               exit(0);
            }
            if (!(strncasecmp (mode->mode, "debug", 5))) {
               ArgusLabelerStatus |= ARGUS_TREE_DEBUG;

               if (!(strncasecmp (mode->mode, "debug.node", 10)))
                  ArgusLabelerStatus |= ARGUS_TREE_DEBUG_NODE;
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
   fflush (stdout);
   exit(1);
}

/*
extern struct RaAddressStruct *RaFindAddress (struct ArgusParserStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);
int RaProcessAddress (struct ArgusParserStruct *, struct ArgusRecordStruct *, unsigned int *, int);

int
RaProcessAddress (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, unsigned int *addr, int type)
{
   struct ArgusLabelerStruct *labeler = NULL;
   struct RaAddressStruct *raddr;
   int retn = 0;

   if ((labeler = parser->ArgusLabeler) == NULL)
      ArgusLog (LOG_ERR, "RaProcessAddress: No labeler\n");

   switch (type) {
      case ARGUS_TYPE_IPV4: {
         struct RaAddressStruct node;
         bzero ((char *)&node, sizeof(node));

         node.addr.type = AF_INET;
         node.addr.len = 4;
         node.addr.addr[0] = *addr;
         node.addr.masklen = 32;

         if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_NODE_MATCH)) != NULL) {
            retn++;
         }
         break;
      }

      case ARGUS_TYPE_IPV6:
         break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "RaProcessAddress (0x%x, 0x%x, 0x%x, %d) returning %d\n", parser, argus, addr, type, retn);
#endif

   return (retn);
}
*/

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;

   int retn = 0;

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (flow) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4:
                        if ((!retn && parser->ArgusAggregator->mask & ARGUS_MASK_SADDR_INDEX))
                           retn = RaProcessAddress(parser, labeler, &flow->ip_flow.ip_src, 32, ARGUS_TYPE_IPV4);
                        if (!retn && (parser->ArgusAggregator->mask & ARGUS_MASK_DADDR_INDEX))
                           retn = RaProcessAddress(parser, labeler, &flow->ip_flow.ip_dst, 32, ARGUS_TYPE_IPV4);
                        break;
                     case ARGUS_TYPE_IPV6:
                        if (!retn && (parser->ArgusAggregator->mask & ARGUS_MASK_SADDR_INDEX))
                           retn = RaProcessAddress(parser, labeler, (unsigned int *) &flow->ipv6_flow.ip_src, 128, ARGUS_TYPE_IPV6);
                        if (!retn && (parser->ArgusAggregator->mask & ARGUS_MASK_DADDR_INDEX))
                           retn = RaProcessAddress(parser, labeler, (unsigned int *) &flow->ipv6_flow.ip_dst, 128, ARGUS_TYPE_IPV6);
                        break;
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
                     static char sbuf[0x10000];

                     if ((argusrec = ArgusGenerateRecord (argus, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        if (parser->exceptfile != NULL) {
                           if (retn && strcmp(wfile->filename, parser->exceptfile))
                              ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                           else
                              if (!retn && !strcmp(wfile->filename, parser->exceptfile))
                                 ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);

                        } else {
                           if (retn)
                              ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                        }
                     }
                  }

                  lobj = lobj->nxt;
               }
            }

         } else {
            if (retn) {
               char buf[MAXSTRLEN];
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
                  if (fprintf (stdout, "%s ", buf) < 0)
                     RaParseComplete(SIGQUIT);
               }
               if (parser->ArgusWfileList == NULL)
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

