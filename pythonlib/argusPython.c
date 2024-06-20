/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2018-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define argusPython
#define NPY_NO_DEPRECATED_API NPY_1_7_API_VERSION

#include <Python.h>
#include <numpy/arrayobject.h>

#include <dlfcn.h>

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include <argus_compat.h>
#include <argus_util.h>
#include <argus_main.h>
#include <argus_client.h>
#include <argus_metric.h>
#include <argus_filter.h>
#include <argus_threads.h>

#include "argusPython.h"

void RaArgusInputComplete (struct ArgusInput *input) { return; }
void RaParseComplete (int sig) { }
void ArgusClientTimeout () { }
void parse_arg (int argc, char**argv) {}
void usage () { }
int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}
void ArgusWindowClose(void) {}

struct ArgusRecordStruct *ArgusFindRecordInBaseline (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int ArgusLoadDataFiles (struct ArgusParserStruct *, int);

struct ArgusAggregatorStruct *ArgusBaselineAggregator = NULL;
struct ArgusAggregatorStruct *ArgusSampleAggregator = NULL;

struct RaCursesProcessStruct *RaBaselineProcess = NULL;
struct RaCursesProcessStruct *RaSampleProcess = NULL;

extern struct ArgusTokenStruct llcsap_db[];
extern void ArgusLog (int, char *, ...);
void RaConvertParseTitleString (char *);
int RaConvertParseRecordString (struct ArgusParserStruct *, char *);

int ArgusParseDirStatus = -1;
int ArgusParseTCPState = -1;
int ArgusParseState = -1;
extern u_short ArgusThisProto;

int RaFlagsIndicationStatus[64];
int RaConvertParseDirLabel = 0;
int RaConvertParseStateLabel = 0;

int ArgusProcessingBaseline   = 0;
int ArgusProcessingSample     = 0;
int ArgusProcessingComplete   = 0;

unsigned int ArgusSourceId = 0;
unsigned int ArgusIdType = 0;

#define ARGUS_CONTINUE          0x100
#define ARGUS_REQUEST           0x200
#define ARGUS_RESPONSE          0x400
#define ARGUS_INIT              0x800

#define RASCII_MAXMODES		1
#define RASCIIDEBUG		0

extern struct ArgusParserStruct *ArgusParser;

static struct PyModuleDef argusPythonmodule = {
    PyModuleDef_HEAD_INIT,
    "argusPython",   /* name of module */
};

typedef char *(*func_ptr_t)(void);

PyMODINIT_FUNC
PyInit_argusPython(void) {
   PyObject *m = PyModule_Create(&argusPythonmodule);
   struct ArgusParserStruct *parser = NULL;
   
   if ((parser = ArgusParser) == NULL) {
      if ((ArgusParser = ArgusNewParser("argusPython")) == NULL)
         ArgusLog (LOG_ERR, "ArgusNewParser failed %s", strerror(errno));
      parser = ArgusParser; 
      ArgusClientInit (parser);
   }

   if (PyArray_API == NULL) {
      import_array(); 
   }
   return m;
}

char *RaConvertDaemonModes[RASCII_MAXMODES] = {
   "debug",
};

int 
argusInit(void) {
   struct ArgusParserStruct *parser = NULL;
   int retn = 0;

   if ((parser = ArgusParser) == NULL) {
      if ((ArgusParser = ArgusNewParser("argusPython")) == NULL)
         ArgusLog (LOG_ERR, "ArgusNewParser failed %s", strerror(errno));
      parser = ArgusParser;
      ArgusClientInit (parser);
   }

   return retn;
}

int ArgusDebugMode = 0;

#define RASCII_MAXDEBUG		2
#define RASCII_DEBUGDUMMY	0
#define RASCII_DEBUGTASKS	1
#define RASCII_DEBUGTASKMASK	1

#define RA_DIRTYBINS            0x20

char *ArgusDebugModes[RASCII_MAXDEBUG] = {
   " ",
   "tasks",
};

static int argus_version = ARGUS_VERSION;

void
ArgusIdleClientTimeout ()
{
   struct ArgusAggregatorStruct *agg = ArgusParser->ArgusAggregator;

   while (agg) {
      struct ArgusRecordStruct *ns = NULL;

      if (agg->idleint > 0) {
         while ((ns = (struct ArgusRecordStruct *) agg->queue->start) != NULL) {
            double nslt = ArgusFetchLastTime(ns);
            double glt  = (double)(ArgusParser->ArgusGlobalTime.tv_sec * 1.0) + (double)(ArgusParser->ArgusGlobalTime.tv_usec/1000000.0);

            if ((glt - nslt) >= agg->idleint) {
               ns = (void *) ArgusPopQueue(agg->queue, ARGUS_LOCK);
               RaSendArgusRecord(ns);
               ArgusDeleteRecordStruct (ArgusParser, ns);

            } else
               break;
         }
      }

      agg = agg->nxt;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusIdleClientTimeout()\n");
#endif
}

void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   {
      double nowTime = ArgusFetchStartTime(ns);
      if (parser->ArgusLastRecordTime == 0) {
         parser->ArgusLastRecordTime = nowTime;
      } else {
         if (parser->ArgusLastRecordTime > nowTime)
            parser->RaSortedInput = 0;
         parser->ArgusLastRecordTime = nowTime;
      }
   }

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_EVENT:
         break;

      case ARGUS_MAR:
      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];

         ArgusIdleClientTimeout();

         if (parser->Vflag || parser->Aflag) {
            ArgusProcessServiceAvailability(parser, ns);
            if (parser->xflag) {
               if ((parser->vflag && (ns->status & RA_SVCPASSED)) ||
                  (!parser->vflag && (ns->status & RA_SVCFAILED))) {
#ifdef ARGUSDEBUG
                  ArgusDebug (3, "RaProcessRecord (0x%x, 0x%x) service test failed", parser, ns); 
#endif
                  return;
               }
            }
         }

         if (parser->RaMonMode && (flow != NULL)) {
            struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(ns);
            struct ArgusFlow *flow;

            if ((flow = (void *)ns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, ns);

            ArgusReverseRecord(tns);

            if ((flow = (void *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);
            
         } else {
            struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
         
            if (flow && agg && agg->ArgusMatrixMode) {
               if (agg->mask & ((0x01LL << ARGUS_MASK_SADDR) | (0x01LL << ARGUS_MASK_DADDR))) {
                  switch (flow->hdr.subtype & 0x3F) {
                     case ARGUS_FLOW_LAYER_3_MATRIX:
                     case ARGUS_FLOW_CLASSIC5TUPLE: {
                        switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                           case ARGUS_TYPE_IPV4: {
                              if (flow->ip_flow.ip_src > flow->ip_flow.ip_dst) 
                                 ArgusReverseRecord(ns);
                           }
                           break; 

                           case ARGUS_TYPE_IPV6: {
                              int i;
                              for (i = 0; i < 4; i++) {
                                 if (flow->ipv6_flow.ip_src[i] < flow->ipv6_flow.ip_dst[i])
                                    break;

                                 if (flow->ipv6_flow.ip_src[i] > flow->ipv6_flow.ip_dst[i]) {
                                    ArgusReverseRecord(ns);
                                    break;
                                 }
                              }
                           }
                           break; 
                        }
                        break; 
                     }

                     default:
                        break; 
                  }

               } else 
               if (agg->mask & ((0x01LL << ARGUS_MASK_SMAC) | (0x01LL << ARGUS_MASK_DMAC))) {

                  struct ArgusMacStruct *m1 = NULL;
                  if ((m1 = (struct ArgusMacStruct *) ns->dsrs[ARGUS_MAC_INDEX]) != NULL) {
                     switch (m1->hdr.subtype) {
                        default:
                        case ARGUS_TYPE_ETHER: {
                           struct ether_header *e1 = &m1->mac.mac_union.ether.ehdr;
                           int i;

                           for (i = 0; i < 6; i++) {
#if defined(ARGUS_SOLARIS)
                              if (e1->ether_shost.ether_addr_octet[i] < e1->ether_dhost.ether_addr_octet[i])
                                 break;
                              if (e1->ether_shost.ether_addr_octet[i] > e1->ether_dhost.ether_addr_octet[i]) {
                                 ArgusReverseRecord(ns);
                                 break;
                              }
#else
                              if (e1->ether_shost[i] < e1->ether_dhost[i])
                                 break;
                              if (e1->ether_shost[i] > e1->ether_dhost[i]) {
                                 ArgusReverseRecord(ns);
                                 break;
                              }
#endif
                           }
                           break;
                        }
                     }
                  }
               }

               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, ns);
         }
         break;
      }
   }
}


void
RaProcessThisRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusAggregatorStruct *agg = parser->ArgusAggregator;
   struct ArgusHashStruct *hstruct = NULL;
   int found = 0;

   if (agg != NULL) {
      while (agg && !found) {
         int retn = 0, fretn = -1, lretn = -1;

         if (agg->filterstr) {
            struct nff_insn *fcode = agg->filter.bf_insns;
            fretn = ArgusFilterRecord (fcode, argus);
         }

         if (agg->grepstr) {
            struct ArgusLabelStruct *label;
            if (((label = (void *)argus->dsrs[ARGUS_LABEL_INDEX]) != NULL)) {
               if (regexec(&agg->lpreg, label->l_un.label, 0, NULL, 0))
                  lretn = 0;
               else
                  lretn = 1;
            } else
               lretn = 0;
         }

         retn = (lretn < 0) ? ((fretn < 0) ? 1 : fretn) : ((fretn < 0) ? lretn : (lretn && fretn));

         if (retn != 0) {
            struct ArgusRecordStruct *tns, *ns;

            ns = ArgusCopyRecordStruct(argus);

            if (agg->labelstr)
               ArgusAddToRecordLabel(parser, ns, agg->labelstr);

            if (agg->mask) {
               if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
                  agg->rap = agg->drap;

               ArgusGenerateNewFlow(agg, ns);
               agg->ArgusMaskDefs = NULL;

               if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL) {
                  if ((tns = ArgusFindRecord(agg->htable, hstruct)) == NULL) {
                     struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];
                     if (!parser->RaMonMode && parser->ArgusReverse) {
                        int tryreverse = 0;

                        if (flow != NULL) {
                           if (agg->correct != NULL)
                              tryreverse = 1;

                           switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                              case ARGUS_TYPE_IPV4: {
                                 switch (flow->ip_flow.ip_p) {
                                   case IPPROTO_ESP:
                                       tryreverse = 0;
                                       break;
                                 }
                                 break;
                              }
                              case ARGUS_TYPE_IPV6: {
                                 switch (flow->ipv6_flow.ip_p) {
                                    case IPPROTO_ESP:
                                       tryreverse = 0;
                                       break;
                                 }
                                 break;
                              }
                           }
                        } else
                           tryreverse = 0;

                        if (tryreverse) {
                           if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL) {

                           if ((tns = ArgusFindRecord(agg->htable, hstruct)) == NULL) {
                              switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                 case ARGUS_TYPE_IPV4: {
                                    switch (flow->ip_flow.ip_p) {
                                       case IPPROTO_ICMP: {
                                          struct ArgusICMPFlow *icmpFlow = &flow->flow_un.icmp;

                                          if (ICMP_INFOTYPE(icmpFlow->type)) {
                                             switch (icmpFlow->type) {
                                                case ICMP_ECHO:
                                                case ICMP_ECHOREPLY:
                                                   icmpFlow->type = (icmpFlow->type == ICMP_ECHO) ? ICMP_ECHOREPLY : ICMP_ECHO;
                                                   if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                      tns = ArgusFindRecord(agg->htable, hstruct);
                                                   icmpFlow->type = (icmpFlow->type == ICMP_ECHO) ? ICMP_ECHOREPLY : ICMP_ECHO;
                                                   if (tns)
                                                      ArgusReverseRecord (ns);
                                                   break;

                                                case ICMP_ROUTERADVERT:
                                                case ICMP_ROUTERSOLICIT:
                                                   icmpFlow->type = (icmpFlow->type == ICMP_ROUTERADVERT) ? ICMP_ROUTERSOLICIT : ICMP_ROUTERADVERT;
                                                   if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                      tns = ArgusFindRecord(agg->htable, hstruct);
                                                   icmpFlow->type = (icmpFlow->type == ICMP_ROUTERADVERT) ? ICMP_ROUTERSOLICIT : ICMP_ROUTERADVERT;
                                                   if (tns)
                                                      ArgusReverseRecord (ns);
                                                   break;

                                                case ICMP_TSTAMP:
                                                case ICMP_TSTAMPREPLY:
                                                   icmpFlow->type = (icmpFlow->type == ICMP_TSTAMP) ? ICMP_TSTAMPREPLY : ICMP_TSTAMP;
                                                   if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                      tns = ArgusFindRecord(agg->htable, hstruct);
                                                   icmpFlow->type = (icmpFlow->type == ICMP_TSTAMP) ? ICMP_TSTAMPREPLY : ICMP_TSTAMP;
                                                   if (tns)
                                                      ArgusReverseRecord (ns);
                                                   break;

                                                case ICMP_IREQ:
                                                case ICMP_IREQREPLY:
                                                   icmpFlow->type = (icmpFlow->type == ICMP_IREQ) ? ICMP_IREQREPLY : ICMP_IREQ;
                                                   if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                      tns = ArgusFindRecord(agg->htable, hstruct);
                                                   icmpFlow->type = (icmpFlow->type == ICMP_IREQ) ? ICMP_IREQREPLY : ICMP_IREQ;
                                                   if (tns)
                                                      ArgusReverseRecord (ns);
                                                   break;

                                                case ICMP_MASKREQ:
                                                case ICMP_MASKREPLY:
                                                   icmpFlow->type = (icmpFlow->type == ICMP_MASKREQ) ? ICMP_MASKREPLY : ICMP_MASKREQ;
                                                   if ((hstruct = ArgusGenerateReverseHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL)
                                                      tns = ArgusFindRecord(agg->htable, hstruct);
                                                   icmpFlow->type = (icmpFlow->type == ICMP_MASKREQ) ? ICMP_MASKREPLY : ICMP_MASKREQ;
                                                   if (tns)
                                                      ArgusReverseRecord (ns);
                                                   break;
                                             }
                                          }
                                          break;
                                       }
                                    }
                                 }
                              }

                              hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct);

                           } else {    // OK, so we have a match (tns) that is the reverse of the current flow (ns)
                                       // Need to decide which direction wins.

                              struct ArgusNetworkStruct *nnet = (struct ArgusNetworkStruct *)ns->dsrs[ARGUS_NETWORK_INDEX];
                              struct ArgusNetworkStruct *tnet = (struct ArgusNetworkStruct *)tns->dsrs[ARGUS_NETWORK_INDEX];

                              switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                 case ARGUS_TYPE_IPV4: {
                                    switch (flow->ip_flow.ip_p) {
                                       case IPPROTO_TCP: {
                                          if ((nnet != NULL) && (tnet != NULL)) {
                                             struct ArgusTCPObject *ntcp = &nnet->net_union.tcp;
                                             struct ArgusTCPObject *ttcp = &tnet->net_union.tcp;

// first if both flows have syn, then don't merge;
                                             if ((ntcp->status & ARGUS_SAW_SYN) && (ttcp->status & ARGUS_SAW_SYN)) {
                                                tns = NULL;
                                             } else {
                                                if ((ntcp->status & ARGUS_SAW_SYN) || 
                                                   ((ntcp->status & ARGUS_SAW_SYN_SENT) && (ntcp->status & ARGUS_CON_ESTABLISHED))) {
                                                   struct ArgusFlow *tflow = (struct ArgusFlow *) tns->dsrs[ARGUS_FLOW_INDEX];
                                                   ArgusRemoveHashEntry(&tns->htblhdr);
                                                   ArgusReverseRecord (tns);
                                                   hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                                   tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                                   tflow->hdr.subtype &= ~ARGUS_REVERSE;
                                                   tflow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
                                                } else
                                                   ArgusReverseRecord (ns);
                                             }
                                          }
                                          break;
                                       }

                                       default: {
                                          double  nstime = ArgusFetchStartTime(ns);
                                          double tnstime = ArgusFetchStartTime(tns);
                                          if (tnstime > nstime) {
                                             struct ArgusFlow *tflow = (struct ArgusFlow *) tns->dsrs[ARGUS_FLOW_INDEX];
                                             ArgusRemoveHashEntry(&tns->htblhdr);
                                             ArgusReverseRecord (tns);
                                             hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                             tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                             tflow->hdr.subtype &= ~ARGUS_REVERSE;
                                             tflow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
                                          } else
                                             ArgusReverseRecord (ns);
                                          break;
                                       }
                                    }
                                    break;
                                 }

                                 case ARGUS_TYPE_IPV6: {
                                    switch (flow->ipv6_flow.ip_p) {
                                       case IPPROTO_TCP: {
                                          if ((nnet != NULL) && (tnet != NULL)) {
                                             struct ArgusTCPObject *ntcp = &nnet->net_union.tcp;
                                             struct ArgusTCPObject *ttcp = &tnet->net_union.tcp;

// first if both flows have syn, then don't merge;
                                             if ((ntcp->status & ARGUS_SAW_SYN) && (ttcp->status & ARGUS_SAW_SYN)) {
                                                tns = NULL;
                                             } else {
                                                if (ntcp->status & ARGUS_SAW_SYN) {
                                                   ArgusRemoveHashEntry(&tns->htblhdr);
                                                   ArgusReverseRecord (tns);
                                                   hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                                   tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                                } else
                                                if ((ntcp->status & ARGUS_SAW_SYN_SENT) && (ntcp->status & ARGUS_CON_ESTABLISHED)) {
                                                   ArgusRemoveHashEntry(&tns->htblhdr);
                                                   ArgusReverseRecord (tns);
                                                   hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                                   tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                                } else
                                                   ArgusReverseRecord (ns);
                                             }
                                          }
                                          break;
                                       }

                                       default: {
                                          double  nstime = ArgusFetchStartTime(ns);
                                          double tnstime = ArgusFetchStartTime(tns);
                                          if (tnstime > nstime) {
                                             struct ArgusFlow *tflow = (struct ArgusFlow *) tns->dsrs[ARGUS_FLOW_INDEX];
                                             ArgusRemoveHashEntry(&tns->htblhdr);
                                             ArgusReverseRecord (tns);
                                             hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                             tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                             tflow->hdr.subtype &= ~ARGUS_REVERSE;
                                             tflow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
                                          } else
                                             ArgusReverseRecord (ns);
                                          break;
                                       }
                                    }
                                    break;
                                 }

                                 default: {
                                    double  nstime = ArgusFetchStartTime(ns);
                                    double tnstime = ArgusFetchStartTime(tns);
                                    if (tnstime > nstime) {
                                       struct ArgusFlow *tflow = (struct ArgusFlow *) tns->dsrs[ARGUS_FLOW_INDEX];
                                       ArgusRemoveHashEntry(&tns->htblhdr);
                                       ArgusReverseRecord (tns);
                                       hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct);
                                       tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                                       tflow->hdr.subtype &= ~ARGUS_REVERSE;
                                       tflow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
                                    } else
                                       ArgusReverseRecord (ns);
                                    break;
                                 }
                              }
                           }
                           }
                        }
                     }
                  }

                  if (tns != NULL) {                            // found record in queue
                     if (parser->Aflag) {
                        if ((tns->status & RA_SVCTEST) != (ns->status & RA_SVCTEST)) {
                           RaSendArgusRecord(tns);
                           tns->status &= ~(RA_SVCTEST);
                           tns->status |= (ns->status & RA_SVCTEST);
                        }
                     }

                     if (tns->status & ARGUS_RECORD_WRITTEN) {
                        ArgusZeroRecord (tns);

                     } else {
                        if ((agg->statusint > 0) || (agg->idleint > 0)) {   // if any timers, need to flush if needed
                           double dur, nsst, tnsst, nslt, tnslt;

                           nsst  = ArgusFetchStartTime(ns);
                           tnsst = ArgusFetchStartTime(tns);
                           nslt  = ArgusFetchLastTime(ns);
                           tnslt = ArgusFetchLastTime(tns);

                           dur = ((tnslt > nslt) ? tnslt : nslt) - ((nsst < tnsst) ? nsst : tnsst); 
                        
                           if ((agg->statusint > 0) && (dur >= agg->statusint)) {
                              RaSendArgusRecord(tns);
                              ArgusZeroRecord(tns);
                           } else {
                              dur = ((nslt < tnsst) ? (tnsst - nslt) : ((tnslt < nsst) ? (nsst - tnslt) : 0.0));
                              if (agg->idleint && (dur >= agg->idleint)) {
                                 RaSendArgusRecord(tns);
                                 ArgusZeroRecord(tns);
                              }
                           }
                        }
                     }

                     ArgusMergeRecords (agg, tns, ns);

                     ArgusRemoveFromQueue (agg->queue, &tns->qhdr, ARGUS_LOCK);
                     ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_LOCK);         // use the agg queue as an idle timeout queue

                     ArgusDeleteRecordStruct(parser, ns);
                     agg->status |= ARGUS_AGGREGATOR_DIRTY;

                  } else {
                     tns = ns;
                     if ((hstruct = ArgusGenerateHashStruct(agg, tns, (struct ArgusFlow *)&agg->fstruct)) != NULL) {
                        tns->htblhdr = ArgusAddHashEntry (agg->htable, tns, hstruct);
                        ArgusAddToQueue (agg->queue, &tns->qhdr, ARGUS_LOCK);
                        agg->status |= ARGUS_AGGREGATOR_DIRTY;
                     }
                  }
               }

            } else {
               ArgusAddToQueue (agg->queue, &ns->qhdr, ARGUS_LOCK);
               agg->status |= ARGUS_AGGREGATOR_DIRTY;
            }

            if (agg->cont)
               agg = agg->nxt;
            else
               found++;

         } else
            agg = agg->nxt;
      }

   } else {
// no key, no aggregation, so printing the record out 
      RaSendArgusRecord(argus);
   }
}

void
ArgusClientInit(struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL;
   int i, x, ind;

   parser->debugflag = 3;

#ifdef ARGUSDEBUG
   ArgusDebug (0, "ArgusPythonClientInit()");
#endif

   if (parser->ver3flag)
      argus_version = ARGUS_VERSION_3;

   if (parser->RaTimeFormat == NULL)
      parser->RaTimeFormat = strdup("%Y-%m-%dT%H:%M:%S.%f");

   if ((mode = ArgusParser->ArgusModeList) != NULL) {
      while (mode) {
         for (i = 0, ind = -1; i < RASCII_MAXMODES; i++) {
            if (!(strncasecmp (mode->mode, RaConvertDaemonModes[i], 3))) {
               ind = i;
               switch (ind) {
                  case RASCIIDEBUG:
                     if ((mode = mode->nxt) == NULL)
                     break;
               }
            }
         }

         switch (ind) {
            case RASCIIDEBUG: {
               for (x = 0, ind = -1; x < RASCII_MAXMODES; x++) {
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
               break;
         }

         mode = mode->nxt;
      }
   }

   parser->nflag = 3;

   while (parser->RaPrintOptionIndex > 0) {
      if (parser->RaPrintOptionStrings[parser->RaPrintOptionIndex-1]) {
         parser->RaPrintOptionIndex--;
         free(parser->RaPrintOptionStrings[parser->RaPrintOptionIndex]);
         parser->RaPrintOptionStrings[parser->RaPrintOptionIndex] = NULL;
      }
   }

   parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("stime");
   parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("dur");
   parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("proto:5");
   parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("saddr");
   parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("sport");
   parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("dir");
   parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("daddr");
   parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("dport");
   parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("pkts");
   parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("bytes");
   parser->RaPrintOptionStrings[parser->RaPrintOptionIndex++] = strdup("state");

   ArgusProcessSOptions(parser);

   ArgusParser->ArgusInitCon.hdr.type                    = (ARGUS_MAR | argus_version);
   ArgusParser->ArgusInitCon.hdr.cause                   = ARGUS_START;
   ArgusParser->ArgusInitCon.hdr.len                     = (unsigned short) (sizeof(struct ArgusRecord) + 3)/4;
   ArgusParser->ArgusInitCon.argus_mar.thisid            = ArgusSourceId;
   ArgusParser->ArgusInitCon.argus_mar.argusid           = (argus_version == ARGUS_VERSION_3)
                                                           ? ARGUS_V3_COOKIE : ARGUS_COOKIE;
 
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

   if (parser->ArgusFlowModelFile) {
      parser->ArgusAggregator = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL);
      ArgusBaselineAggregator = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL);
      ArgusSampleAggregator   = ArgusParseAggregator(parser, parser->ArgusFlowModelFile, NULL);

   } else {
      char *mask = NULL;
      if (parser->ArgusMaskList == NULL) mask = "sid saddr daddr proto sport dport";
      parser->ArgusAggregator = ArgusNewAggregator(parser, mask, ARGUS_RECORD_AGGREGATOR);

      if ((mask = parser->ArgusBaseLineMask) == NULL) mask = "saddr daddr proto dport";
      ArgusBaselineAggregator = ArgusNewAggregator(parser, mask, ARGUS_RECORD_AGGREGATOR);

      if ((mask = parser->ArgusSampleMask) == NULL) mask = "sid saddr daddr proto sport dport";
      ArgusSampleAggregator   = ArgusNewAggregator(parser, mask, ARGUS_RECORD_AGGREGATOR);
   }

}

#define ARGUS_MAX_PRINT_FIELDS		512

void (*RaParseLabelAlgorithms[ARGUS_MAX_PRINT_FIELDS])(struct ArgusParserStruct *, char *);
double (*RaComparisonAlgorithms[ARGUS_MAX_PRINT_FIELDS])(struct ArgusRecordStruct *, struct ArgusRecordStruct *);

int RaParseLabelAlgorithmIndex = 0;
int RaComparisonAlgorithmIndex = 0;

char RaConvertDelimiter[2] = {'\0', '\0'};


void
RaConvertParseTitleString (char *str)
{
   char *buf, *ptr, *obj;
   int i, len = 0, items = 0;

   if ((buf = ArgusCalloc(1, MAXSTRLEN)) == NULL)
      ArgusLog(LOG_ERR, "RaConvertParseTitleString ArgusCalloc error %s", strerror(errno));

   bzero ((char *)RaParseLabelAlgorithms, sizeof(RaParseLabelAlgorithms));
   bzero ((char *)RaComparisonAlgorithms, sizeof(RaComparisonAlgorithms));

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
      int found = 0;
      len = strlen(obj);
      if (len > 0) {
         for (i = 0; (i < MAX_PARSE_ALG_TYPES) && !found; i++) {
            if (!(strncmp(RaParseLabelStringTable[i], obj, len))) {
               RaParseLabelAlgorithmIndex++;
               RaComparisonAlgorithmIndex++;

               RaParseLabelAlgorithms[items] = RaParseLabelAlgorithmTable[i];
               RaComparisonAlgorithms[items] = RaComparisonAlgorithmTable[i];

               if (i == ARGUSPARSEDIRLABEL)
                  RaConvertParseDirLabel++;
               if (i == ARGUSPARSESTATELABEL)
                  RaConvertParseStateLabel++;
               found++;
               break;
            }
         }
         if (!found) {
#ifdef ARGUSDEBUG
            ArgusDebug (0, "RaConvertParseTitleString() column %s not found", obj);
#endif
         }
      }

      items++;
      ptr = NULL;
   }

   ArgusFree (buf);

#ifdef ARGUSDEBUG
   ArgusDebug (9, "RaConvertParseTitleString('%s') done", str);
#endif
}


int
RaConvertParseRecordString (struct ArgusParserStruct *parser, char *str)
{
   struct ArgusRecordStruct *argus = &parser->argus;
   char *buf, delim[16], *ptr, *tptr;
   char **ap, **argv;
   int retn = 1, numfields, i;

   if ((buf = ArgusCalloc(1, MAXSTRLEN)) == NULL)
      ArgusLog(LOG_ERR, "RaConvertParseTitleString ArgusCalloc error %s", strerror(errno));

   if ((argv = ArgusCalloc(sizeof(char *), ARGUS_MAX_PRINT_FIELDS)) == NULL)
      ArgusLog(LOG_ERR, "RaConvertParseTitleString ArgusCalloc error %s", strerror(errno));

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaConvertParseRecordString('%s')", str);
#endif

   if ((ptr = strchr(str, '\n')) != NULL)
      *ptr = '\0';

   ptr = buf;

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
      if ((strcasecmp(argv[i], "-nan") == 0) || (strcasecmp(argv[i], "nan") == 0)) {
         return(0);
      } else
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

   ArgusFree (argv);
   ArgusFree (buf);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaConvertParseRecordString('%s') returning %d", str, retn);
#endif

   return (retn);
}

int
setArgusSchema (char *str)
{
   int retn = -1;

   if (str != NULL) {
      RaConvertParseTitleString(str);
      retn = 1;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (0, "ArgusPython: setArgusSchema('%s') done", str);
#endif

   return (retn);
}


int
readArgusData (char *optarg)
{
   struct ArgusParserStruct *parser = NULL;
   int type = ARGUS_DATA_SOURCE;
   long long ostart = -1, ostop = -1;
   int retn = 1;
   char *ptr, *eptr;

   if ((parser = ArgusParser) != NULL) {
#if defined(ARGUS_MYSQL)
      if (!(strncmp ("mysql:", optarg, 6))) {
         if (parser->readDbstr != NULL)
            free(parser->readDbstr);
         parser->readDbstr = strdup(optarg);
         type &= ~ARGUS_DATA_SOURCE;
         type |= ARGUS_DBASE_SOURCE;
         optarg += 6;
      }
#endif
      if (!(strncmp ("cisco:", optarg, 6))) {
         parser->Cflag++;
         type |= ARGUS_CISCO_DATA_SOURCE;
         optarg += 6;
      } else
      if (!(strncmp ("jflow:", optarg, 6))) {
         parser->Cflag++;
         type |= ARGUS_JFLOW_DATA_SOURCE;
         optarg += 6;
      } else
      if (!(strncmp ("ft:", optarg, 3))) {
         type |= ARGUS_FLOW_TOOLS_SOURCE;
         optarg += 3;
      } else
      if (!(strncmp ("sflow:", optarg, 6))) {
         type |= ARGUS_SFLOW_DATA_SOURCE;
         optarg += 6;
      }


      if ((ptr = strstr(optarg, "::")) != NULL) {
         char *endptr = NULL;

         *ptr++ = '\0';
         ptr++;

         ostart = strtol(ptr, (char **)&endptr, 10);
         if (endptr == optarg)
            usage ();

         if ((eptr = strstr(ptr, ":")) != NULL) {
            ostop = strtol((eptr + 1), (char **)&endptr, 10);
            if (endptr == optarg)
               usage ();
         }
      }

      if (!(ArgusAddFileList (parser, optarg, type, ostart, ostop)))
         ArgusLog(LOG_ERR, "%s: error: file arg %s", "ArgusPython: setArgusBaseline", optarg);
      stat(optarg, &((struct ArgusFileInput *) ArgusParser->ArgusBaselineListTail)->statbuf);

      ArgusLoadDataFiles(parser, ARGUS_DATA_SOURCE);

#ifdef ARGUSDEBUG 
      ArgusDebug (0, "ArgusPython: readArgusData('%s') done ... read %d records", optarg, parser->ArgusTotalRecords);
#endif
   } else {
#ifdef ARGUSDEBUG 
      ArgusDebug (0, "ArgusPython: readArgusData ('%s') no Parser", optarg);
#endif
   }

   return (retn);
}

int
setArgusBaseline (char *optarg)
{
   struct ArgusParserStruct *parser = NULL;
   int type = ARGUS_DATA_SOURCE | ARGUS_BASELINE_SOURCE;
   long long ostart = -1, ostop = -1;
   int retn = 1;
   char *ptr, *eptr;

   if ((parser = ArgusParser) != NULL) {
#if defined(ARGUS_MYSQL)
      if (!(strncmp ("mysql:", optarg, 6))) {
         if (parser->readDbstr != NULL)
            free(parser->readDbstr);
         parser->readDbstr = strdup(optarg);
         type &= ~ARGUS_DATA_SOURCE;
         type |= ARGUS_DBASE_SOURCE;
         optarg += 6;
      }
#endif
      if (!(strncmp ("cisco:", optarg, 6))) {
         parser->Cflag++;
         type |= ARGUS_CISCO_DATA_SOURCE;
         optarg += 6;
      } else
      if (!(strncmp ("jflow:", optarg, 6))) {
         parser->Cflag++;
         type |= ARGUS_JFLOW_DATA_SOURCE;
         optarg += 6;
      } else
      if (!(strncmp ("ft:", optarg, 3))) {
         type |= ARGUS_FLOW_TOOLS_SOURCE;
         optarg += 3;
      } else
      if (!(strncmp ("sflow:", optarg, 6))) {
         type |= ARGUS_SFLOW_DATA_SOURCE;
         optarg += 6;
      }


      if ((ptr = strstr(optarg, "::")) != NULL) {
         char *endptr = NULL;

         *ptr++ = '\0';
         ptr++;

         ostart = strtol(ptr, (char **)&endptr, 10);
         if (endptr == optarg)
            usage ();

         if ((eptr = strstr(ptr, ":")) != NULL) {
            ostop = strtol((eptr + 1), (char **)&endptr, 10);
            if (endptr == optarg)
               usage ();
         }
      }

      if (type & ARGUS_BASELINE_SOURCE) {
         if (!(ArgusAddBaselineList (parser, optarg, type, ostart, ostop)))
            ArgusLog(LOG_ERR, "%s: error: file arg %s", "ArgusPython: setArgusBaseline", optarg);
         stat(optarg, &((struct ArgusFileInput *) ArgusParser->ArgusBaselineListTail)->statbuf);
      }

      ArgusLoadDataFiles(parser, ARGUS_BASELINE_SOURCE);

#ifdef ARGUSDEBUG 
      ArgusDebug (0, "ArgusPython: setArgusBaseline('%s') done ... read %d records", optarg, parser->ArgusTotalRecords);
#endif

   } else {
#ifdef ARGUSDEBUG 
      ArgusDebug (0, "ArgusPython: setArgusBaseline('%s') no Parser", optarg);
#endif
   }

   return (retn);
}


int
ArgusLoadDataFiles (struct ArgusParserStruct *parser, int type)
{
   struct ArgusInput *input = NULL, *current;
   struct ArgusFileInput *file = NULL;
   char sbuf[1024];
   int retn = 1;

   current = parser->ArgusCurrentInput;

   switch (type) {
      case ARGUS_BASELINE_SOURCE:
         file = parser->ArgusBaselineList;
         break;

      default:
         file = parser->ArgusInputFileList;
         break;
   }

   if (file != NULL) {
      ArgusProcessingSample = 0;

#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusLoadDataFiles (%p, %d) allocating input struct", parser, type);
#endif
      input = ArgusMalloc(sizeof(*input));
      if (input == NULL)
         ArgusLog(LOG_ERR, "unable to allocate input structure\n");

      while (file && parser->eNflag) {
         if (type == ARGUS_BASELINE_SOURCE)
            ArgusProcessingBaseline = 1;

         switch (file->type & 0x17FF) {
#if defined(ARGUS_MYSQL)
/*
            case ARGUS_DBASE_SOURCE: {
               if (RaTables == NULL)
                  if ((RaTables = ArgusCalloc(sizeof(void *), 2)) == NULL)
                     ArgusLog(LOG_ERR, "mysql_init error %s", strerror(errno));

               RaTables[0] = strdup(file->filename);
               ArgusReadSQLTables (parser);
               ArgusFree(RaTables);
               RaTables = NULL;
               break;
            }
*/
#endif
            case ARGUS_DATA_SOURCE:
            case ARGUS_V2_DATA_SOURCE:
            case ARGUS_NAMED_PIPE_SOURCE:
            case ARGUS_DOMAIN_SOURCE:
            case ARGUS_BASELINE_SOURCE:
            case ARGUS_DATAGRAM_SOURCE:
            case ARGUS_SFLOW_DATA_SOURCE:
            case ARGUS_JFLOW_DATA_SOURCE:
            case ARGUS_CISCO_DATA_SOURCE:
            case ARGUS_IPFIX_DATA_SOURCE:
            case ARGUS_FLOW_TOOLS_SOURCE: {
               ArgusInputFromFile(input, file);
               parser->ArgusCurrentInput = input;

               if (strcmp (input->filename, "-")) {
                  if (input->fd < 0) {
                     if ((input->file = fopen(input->filename, "r")) != NULL) {
                     }
                  } else {
                     fseek(input->file, 0, SEEK_SET);
                  }

                  if ((input->file != NULL) && ((ArgusReadConnection (parser, input, ARGUS_FILE)) >= 0)) {
#ifdef ARGUSDEBUG
                     ArgusDebug (1, "ArgusLoadDataFiles (%p, %d) processing input filename: %s", parser, type, input->filename);
#endif
                     parser->ArgusTotalMarRecords++;
                     parser->ArgusTotalRecords++;
                     if (parser->RaPollMode) {
                         ArgusHandleRecord (parser, input, &input->ArgusInitCon, 0, &parser->ArgusFilterCode);
                     } else {
                        if (input->ostart != -1) {
                           input->offset = input->ostart;
                           if (fseek(input->file, input->offset, SEEK_SET) >= 0)
                              ArgusReadFileStream(parser, input);
                        } else
                           ArgusReadFileStream(parser, input);
                     }
#ifdef ARGUSDEBUG
                  ArgusDebug (1, "ArgusLoadDataFiles (%p, %d) ArgusReadFileStream complete", parser, type);
#endif

                  } else {
                     input->fd = -1;
                     sprintf (sbuf, "ArgusReadConnection '%s': %s", input->filename, strerror(errno));
                  }

               } else {
                  input->file = stdin;
                  input->ostart = -1;
                  input->ostop = -1;

                  if (((ArgusReadConnection (parser, input, ARGUS_FILE)) >= 0)) {
                     parser->ArgusTotalMarRecords++;
                     parser->ArgusTotalRecords++;
                     fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);
                     ArgusReadFileStream(parser, input);
                  }
               }
               break;
            }
         }
         RaArgusInputComplete(input);
         ArgusParser->ArgusCurrentInput = NULL;
         ArgusCloseInput(ArgusParser, input);

         if (type == ARGUS_BASELINE_SOURCE)
            ArgusProcessingBaseline = 0;

         file = (struct ArgusFileInput *)file->qhdr.nxt;
      }

      parser->ArgusCurrentInput = NULL;

      if (type == ARGUS_BASELINE_SOURCE)
         parser->status |= ARGUS_BASELINE_LIST_PROCESSED;

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusLoadDataFiles (%p, %d) no list to process", parser, type);
#endif
      parser->status |= ARGUS_BASELINE_LIST_PROCESSED;
   }

   parser->ArgusCurrentInput = current;
   return (retn);
}

struct ArgusRecordStruct *
ArgusFindRecordInBaseline (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   int tretn = 0, fretn = -1, lretn = -1;

   struct ArgusRecordStruct *retn = NULL;
   struct ArgusAggregatorStruct *agg = NULL;
   struct ArgusHashStruct *hstruct = NULL;

   if ((agg = ArgusBaselineAggregator) != NULL) {
      if (agg->filterstr) {
         struct nff_insn *fcode = agg->filter.bf_insns;
         fretn = ArgusFilterRecord (fcode, ns);
      }

      if (agg->grepstr) {
         struct ArgusLabelStruct *label;
         if (((label = (void *)ns->dsrs[ARGUS_LABEL_INDEX]) != NULL)) {
            if (regexec(&agg->lpreg, label->l_un.label, 0, NULL, 0))
               lretn = 0;
            else
               lretn = 1;
         } else
            lretn = 0;
      }

      tretn = (lretn < 0) ? ((fretn < 0) ? 1 : fretn) : ((fretn < 0) ? lretn : (lretn && fretn));

      if (tretn != 0) {
         if (agg->mask) {
            if ((agg->rap = RaFlowModelOverRides(agg, ns)) == NULL)
               agg->rap = agg->drap;

            ArgusGenerateNewFlow(agg, ns);
            agg->ArgusMaskDefs = NULL;

            if ((hstruct = ArgusGenerateHashStruct(agg, ns, (struct ArgusFlow *)&agg->fstruct)) != NULL) {
               retn = ArgusFindRecord(RaBaselineProcess->htable, hstruct);
            }
         }
      }
   }
   return (retn);
}

char ArgusConBuf[2][MAXARGUSRECORD];
char ArgusOutBuf[2][MAXSTRLEN];


PyObject *
argus_critic (PyObject *y_true, PyObject *y_pred)
{
   struct ArgusParserStruct *parser = NULL;
   PyObject *retn = NULL;
   int yt_dims, yt_size, yp_size;
   int py_equal;

   PyArrayObject *arrays[3];  /* holds input and output array */
   PyArrayObject *results;    /* holds results array */
   npy_uint32 op_flags[3];
   npy_uint32 iterator_flags;
   PyArray_Descr *op_dtypes[3];

   NpyIter_IterNextFunc *iternext;
   NpyIter *iter;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "argus_critic(%p, %p) called\n", y_true, y_pred);
#endif

   arrays[0] = (PyArrayObject *) y_true;
   arrays[1] = (PyArrayObject *) y_pred;

   if (PyArray_API == NULL) {
      import_array();
   }

   if (!(PyArray_Check(arrays[0]) && PyArray_Check(arrays[1]))) {
      PyObject_Print(y_true, stdout, 0);
      printf("\n");
      fflush(stdout);
      Py_RETURN_NONE;
   }

   if ((yt_dims = PyArray_NDIM(arrays[1])) == 0)
      return NULL;
   if ((yt_size = PyArray_Size(y_true)) == 0)
      return NULL;
   if ((yp_size = PyArray_Size(y_pred)) == 0)
      return NULL;

   if ((py_equal = PyArray_EquivArrTypes(arrays[0], arrays[1])) == 0)
      return NULL;

   arrays[2] = NULL;

   iterator_flags = (NPY_ITER_ZEROSIZE_OK |
                     NPY_ITER_BUFFERED |
                     NPY_ITER_EXTERNAL_LOOP |
                     NPY_ITER_GROWINNER);

   op_flags[0] = (NPY_ITER_READONLY |
                  NPY_ITER_NBO |
                  NPY_ITER_ALIGNED);
   op_flags[1] = op_flags[0];

    /* Ask the iterator to allocate an array to write the output to */
    op_flags[2] = NPY_ITER_WRITEONLY | NPY_ITER_ALLOCATE;

    /*
     * Ensure the iteration has the correct type, could be checked
     * specifically here.
     */
    op_dtypes[0] = PyArray_DescrFromType(NPY_FLOAT64);
    op_dtypes[1] = op_dtypes[0];
    op_dtypes[2] = op_dtypes[0];

    iter = NpyIter_MultiNew(3, arrays, iterator_flags,
                            /* Use input order for output and iteration */
                            NPY_KEEPORDER,
                            /* Allow only byte-swapping of input */
                            NPY_EQUIV_CASTING, op_flags, op_dtypes);

    Py_DECREF(op_dtypes[0]);

    if (iter == NULL)
        return NULL;

    iternext = NpyIter_GetIterNext(iter, NULL);
    if (iternext == NULL) {
        NpyIter_Deallocate(iter);
        return NULL;
    }

/* Fetch the output array which was allocated by the iterator: */
    results = NpyIter_GetOperandArray(iter)[2];
    Py_INCREF(results);

    if (NpyIter_GetIterSize(iter) == 0) {
        /*
         * If there are no elements, the loop cannot be iterated.
         * This check is necessary with NPY_ITER_ZEROSIZE_OK.
         */
        NpyIter_Deallocate(iter);
        retn = (PyObject *)results;
        return retn;
    }

    /* The location of the data pointer which the iterator may update */
    char **dataptr = NpyIter_GetDataPtrArray(iter);

    /* The location of the stride which the iterator may update */
    npy_intp *strideptr = NpyIter_GetInnerStrideArray(iter);

    /* The location of the inner loop size which the iterator may update */
    npy_intp *innersizeptr = NpyIter_GetInnerLoopSizePtr(iter);

    npy_intp *shape = PyArray_SHAPE(arrays[0]);


    /* iterate over the arrays */
    do {
        npy_intp stride = strideptr[0];
        npy_intp count = *innersizeptr;

#ifdef ARGUSDEBUG
        ArgusDebug (1, "ArgusPython: numpyParse: stride:%d count:%d\n", stride, count);
#endif

        /* out is always contiguous, so use double */
        double *out = (double *)dataptr[2];
        char *in0 = dataptr[0];
        char *in1 = dataptr[1];
        int i = 0, slen0 = 0, slen1 = 0;

        /* The output is allocated and guaranteed contiguous (out++ works): */
        assert(strideptr[2] == sizeof(double));

        /*
         * For optimization it can make sense to add a check for
         * stride == sizeof(double) to allow the compiler to optimize for that.
         */

        bzero (ArgusConBuf[0], sizeof(ArgusConBuf[0]));

        while (count--) {
           if ((i++ % shape[1]) == 0) {
              if (slen0 > 0) {
                 if ((parser = ArgusParser) != NULL) {
                    if (RaConvertParseRecordString (parser, ArgusConBuf[0])) {
                       struct ArgusRecordStruct *argus = &parser->argus;
                       ArgusPrintRecord(parser, ArgusOutBuf[0], argus, MAXSTRLEN);
#ifdef ARGUSDEBUG
                       ArgusDebug (1, "ArgusPython: record:'%s'\n", ArgusOutBuf[0]);
#endif
                    }
                    if (RaConvertParseRecordString (parser, ArgusConBuf[1])) {
                       struct ArgusRecordStruct *argus = &parser->argus;
                       ArgusPrintRecord(parser, ArgusOutBuf[1], argus, MAXSTRLEN);
#ifdef ARGUSDEBUG
                       ArgusDebug (1, "ArgusPython: record:'%s'\n", ArgusOutBuf[1]);
#endif
                    }
                 }

                 bzero (ArgusConBuf[0], sizeof(ArgusConBuf[0]));
                 bzero (ArgusConBuf[1], sizeof(ArgusConBuf[1]));
                 slen0 = 0;
                 slen1 = 0;
                 i = 1;
              }
           }
           if (i > 1) {
              slen0 += snprintf (&ArgusConBuf[0][slen0], sizeof(ArgusConBuf[0]) - slen0, ",");
              slen1 += snprintf (&ArgusConBuf[1][slen1], sizeof(ArgusConBuf[1]) - slen1, ",");
           }
           slen0 += snprintf (&ArgusConBuf[0][slen0], sizeof(ArgusConBuf[0]) - slen0, "%f", *(double *)in0);
           slen1 += snprintf (&ArgusConBuf[1][slen1], sizeof(ArgusConBuf[1]) - slen1, "%f", *(double *)in1);
           *out = cos(*(double *)in0 + *(double *)in1);
           out++;
           in0 += stride;
           in1 += stride;
        }
    } while (iternext(iter));

    /* Clean up and return the result */
    NpyIter_Deallocate(iter);

   if (results == NULL)
      Py_RETURN_NONE;
   else {
      retn = (PyObject *)results;
      return (retn);
   }
}

// This matching function is passed an N x M array and
// returns an N x 1 array with binary scores ...

PyObject *
argus_match (PyObject *y_true)
{
   struct ArgusParserStruct *parser = NULL;
   PyObject *retn = NULL;

   PyArrayObject *arrays[2];  // holds input and results array 
   PyObject *output = NULL;          // holds output array 
   double *out = NULL;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "argus_match(%p): called\n", y_true);
#endif

   arrays[0] = (PyArrayObject *) y_true;

   if (PyArray_API == NULL) {
      import_array();
   }

   if (!(PyArray_Check(arrays[0]))) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "argus_match(%p): array doesn't checkout\n", y_true);
#endif
      PyObject_Print(y_true, stdout, 0);
      printf("\n");
      fflush(stdout);
      Py_RETURN_NONE;
   }

   npy_intp *shape = PyArray_SHAPE(arrays[0]);
   output = PyArray_SimpleNew(1, shape, NPY_FLOAT64);
   out = (double *) PyArray_DATA((PyArrayObject *) output);

   int i, x;
#ifdef ARGUSDEBUG
   int cnt = 0;
#endif

   for (i = 0; i < shape[0]; i++) {
      int slen = 0;
      void *value;

      bzero (ArgusConBuf[0], sizeof(ArgusConBuf[0]));
      bzero (ArgusOutBuf[0], sizeof(ArgusOutBuf[0]));

      for (x = 0; x < shape[1]; x++) {
         if ((value = PyArray_GETPTR2(arrays[0], i, x)) != NULL) {
            if (x > 0) {
               slen += snprintf (&ArgusConBuf[0][slen], sizeof(ArgusConBuf[0]) - slen, ",");
            }
            slen += snprintf (&ArgusConBuf[0][slen], sizeof(ArgusConBuf[0]) - slen, "%f", *(double *)value);
         }
      }

      if (slen > 0) {
         struct ArgusRecordStruct *ns = NULL;

         if ((parser = ArgusParser) != NULL) {
#ifdef ARGUSDEBUG
            cnt++;
#endif
            if (RaConvertParseRecordString (parser, ArgusConBuf[0])) {
               struct ArgusRecordStruct *argus = &parser->argus;

               argus = &parser->argus;
               ns = ArgusFindRecordInBaseline(parser, argus);
               ArgusPrintRecord(parser, ArgusOutBuf[0], argus, MAXSTRLEN);
#ifdef ARGUSDEBUG
               ArgusDebug (1, "argus_match(%2.2d): retn: %d :: '%s'\n", cnt, retn, ArgusOutBuf[0]);
#endif
            }
         }
         *out++ = (ns != NULL) ? 2 : -2;
         bzero (ArgusConBuf[0], sizeof(ArgusConBuf[0]));
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "argus_match(%p): done\n", y_true);
#endif

   if (output != NULL) {
      retn = (PyObject *)output;
      return (retn);
   }
   Py_RETURN_NONE;
}

/*

This matching function scores individual cells in the N x M matrix passed...

PyObject *
argus_match (PyObject *y_true)
{
   struct ArgusParserStruct *parser = NULL;
   PyObject *retn = NULL;
   int yt_dims, yt_size;

   PyArrayObject *arrays[2];  // holds input and results array 
   PyArrayObject *results;    // holds results array 
   npy_uint32 op_flags[2];
   npy_uint32 iterator_flags;
   PyArray_Descr *op_dtypes[2];

   NpyIter_IterNextFunc *iternext;
   NpyIter *iter;

   arrays[0] = (PyArrayObject *) y_true;

   if (PyArray_API == NULL) {
      import_array();
   }

   if (!(PyArray_Check(arrays[0]))) {
      PyObject_Print(y_true, stdout, 0);
      printf("\n");
      fflush(stdout);
      Py_RETURN_NONE;
   }

   if ((yt_dims = PyArray_NDIM(arrays[0])) == 0)
      return NULL;
   if ((yt_size = PyArray_Size(y_true)) == 0)
      return NULL;

   arrays[1] = NULL;

   iterator_flags = (NPY_ITER_ZEROSIZE_OK |
                     NPY_ITER_BUFFERED |
                     NPY_ITER_GROWINNER);

   op_flags[0] = (NPY_ITER_READONLY |
                  NPY_ITER_NBO |
                  NPY_ITER_ALIGNED);
   op_flags[1] = op_flags[0];

   op_flags[1] = NPY_ITER_WRITEONLY | NPY_ITER_ALLOCATE;

   op_dtypes[0] = PyArray_DescrFromType(NPY_FLOAT64);
   op_dtypes[1] = op_dtypes[0];

   iter = NpyIter_MultiNew(2, arrays, iterator_flags,
                            NPY_KEEPORDER,
                            NPY_EQUIV_CASTING, op_flags, op_dtypes);
    Py_DECREF(op_dtypes[0]);

    if (iter == NULL)
        return NULL;

    iternext = NpyIter_GetIterNext(iter, NULL);
    if (iternext == NULL) {
        NpyIter_Deallocate(iter);
        return NULL;
    }

    results = NpyIter_GetOperandArray(iter)[1];
    Py_INCREF(results);

    if (NpyIter_GetIterSize(iter) == 0) {
        NpyIter_Deallocate(iter);
        retn = (PyObject *)results;
        return retn;
    }

    // The location of the data pointer which the iterator may update 
    char **dataptr = NpyIter_GetDataPtrArray(iter);

    // The location of the stride which the iterator may update 
    npy_intp *strideptr = NpyIter_GetInnerStrideArray(iter);

    // The location of the inner loop size which the iterator may update 
    npy_intp *innersizeptr = NpyIter_GetInnerLoopSizePtr(iter);

    npy_intp *shape = PyArray_SHAPE(arrays[0]);

    // output = PyArray_SimpleNew(1, shape, NPY_FLOAT64);

    // iterate over the arrays
    do {
        npy_intp stride = strideptr[0];
        npy_intp count = *innersizeptr;
        // out is always contiguous, so use double 

        double *out = (double *)dataptr[1];
        char *in0 = dataptr[0];
        int i = 0, slen0 = 0, cnt = 0;

        // The output is allocated and guaranteed contiguous (out++ works):
        assert(strideptr[1] == sizeof(double));

        //
        // For optimization it can make sense to add a check for
        // stride == sizeof(double) to allow the compiler to optimize for that.
        //

        bzero (ArgusConBuf[0], sizeof(ArgusConBuf[0]));
        bzero (ArgusOutBuf[0], sizeof(ArgusOutBuf[0]));

        while (count-- >= 0) {
           if ((i++ % shape[1]) == 0) {
              if (slen0 > 0) {
                 if ((parser = ArgusParser) != NULL) {
                    cnt++;
                    if (RaConvertParseRecordString (parser, ArgusConBuf[0])) {
                       struct ArgusRecordStruct *argus = &parser->argus, *retn;
                       int x;
                       retn = ArgusFindRecordInBaseline(parser, argus);

                       for (x = 0; x < shape[1]; x++) {
                          if (retn != NULL) {
                             if (RaComparisonAlgorithms[x] != NULL)
                                *out = RaComparisonAlgorithms[x](argus, retn);
                          } else
                             *out = 0.0;
                          out++;
                       }

                       ArgusPrintRecord(parser, ArgusOutBuf[0], argus, MAXSTRLEN);
#ifdef ARGUSDEBUG
                       ArgusDebug (1, "argus_match(%2.2d): retn: %d :: '%s'\n", cnt, (retn != NULL) ? 1 : 0, ArgusOutBuf[0]);
#endif
                    }
                 }
                 bzero (ArgusConBuf[0], sizeof(ArgusConBuf[0]));
                 slen0 = 0;
                 i = 1;
              }
           }
           if (i > 1) {
              slen0 += snprintf (&ArgusConBuf[0][slen0], sizeof(ArgusConBuf[0]) - slen0, ",");
           }
           slen0 += snprintf (&ArgusConBuf[0][slen0], sizeof(ArgusConBuf[0]) - slen0, "%f", *(double *)in0);
           in0 += stride;
        }
    } while (iternext(iter));

    // Clean up and generate the output 
    NpyIter_Deallocate(iter);

   if (results == NULL)
      Py_RETURN_NONE;
   else {
      retn = (PyObject *)results;
      return (retn);
   }
}
*/


int
argustime (char *time_string, int *start, int *end)
{
   int retn = 1;
   char *string;
   struct tm starttime = {0, };
   struct tm endtime = {0, };
   int frac;
   time_t tsec;
   struct timeval now;

   /* Also remember where in the string the separator was. */
   char *plusminusloc = NULL;
   int off = 0;
   char wildcarddate = 0;

   /* If the date string has two parts, remember which character
    * separates them.
    */
   char plusminus;

   *start = -1;
   *end = -1;
   string = strdup(time_string);

   if (string[0] == '-')
      /* skip leading minus, if present */
      off++;

   /* look through the time string for a plus or minus to indicate
    * a compound time.
    */
   while (!plusminusloc && !isspace(string[off]) && string[off] != '\0') {
      if (string[off] == '-' || string[off] == '+') {
         plusminusloc = &string[off];
         plusminus = string[off];
         string[off] = '\0'; /* split the string in two */
      }
      off++;
   }

   gettimeofday(&now, NULL);
   tsec = now.tv_sec;
   localtime_r(&tsec, &endtime);

   if (ArgusParseTime(&wildcarddate, &starttime, &endtime, string, ' ', &frac, 0) <= 0) {
      retn = 0;
      goto out;
   }

   if (plusminusloc) {
      if (ArgusParseTime(&wildcarddate, &endtime, &starttime, plusminusloc+1, plusminus, &frac, 1) <= 0) {
         retn = 0;
         goto out;
      }
   } else if (string[0] != '-') {
      /* Not a time relative to "now" AND not a time range */
      /* endtime = starttime; */
   }

out:
   if (retn == 1) {
      *start = (int)mktime(&starttime);
      *end = (int)mktime(&endtime);
   }

   if (string)
      free(string);
   return retn;
}



char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];
extern struct ArgusCIDRAddr *RaParseCIDRAddr (struct ArgusParserStruct *, char *);


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
            if (parser->RaTimeFormat) {
               RaConvertTimeFormats[0] = strdup(parser->RaTimeFormat);
               if ((sptr = strstr(RaConvertTimeFormats[0], ".%f")) != NULL)
                  *sptr = '\0';
            }
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
            tvp->tv_sec  = 0;
            tvp->tv_usec = 0;
            done++;
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

#ifdef ARGUSDEBUG
   ArgusDebug (9, "ArgusParseStartDateLabel (%p, '%s')\n", parser, buf); 
#endif
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

   if (isdigit((int)*buf) || (*buf == '-')) {
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
#ifdef ARGUSDEBUG
   ArgusDebug (9, "ArgusParseSrcAddrLabel (%p, '%s')\n", parser, buf); 
#endif
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


double
ArgusCompareStartDate (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;
  if (argus && match) 
     retn = ArgusFetchStartTime(argus) - ArgusFetchStartTime(match);
   
#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareLastDate (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;
  if (argus && match) 
     retn = ArgusFetchLastTime(argus) - ArgusFetchLastTime(match);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSourceID (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareFlags (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcMacAddress (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstMacAddress (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareMacAddress (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareProto (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareAddr (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcNet (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcAddr (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstNet (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstAddr (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcPort (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstPort (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcIpId (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstIpId (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareIpId (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcTtl (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstTtl (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareTtl (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDir (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusComparePackets (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcPackets (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;
   if (argus && match) {
      double adur = ArgusFetchDuration(argus);
      double acnt = ArgusFetchSrcRate(argus);
      double mcnt = ArgusFetchSrcRate(match);
      retn = (acnt - mcnt) * adur;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstPackets (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;
  if (argus && match) {
     double adur = ArgusFetchDuration(argus);
     double acnt = ArgusFetchDstRate(argus);
     double mcnt = ArgusFetchDstRate(match);
     retn = (acnt - mcnt) * adur;
  }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareBytes (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcBytes (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;
  if (argus && match) {
     double adur = ArgusFetchDuration(argus);
     double asld = ArgusFetchSrcLoad(argus);
     double msld = ArgusFetchSrcLoad(match);
     retn = (asld - msld) * adur;
  }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstBytes (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

  if (argus && match) {
     double adur = ArgusFetchDuration(argus);
     double asld = ArgusFetchDstLoad(argus);
     double msld = ArgusFetchDstLoad(match);
     retn = (asld - msld) * adur;
  }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareAppBytes (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcAppBytes (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;
  if (argus && match) {
     double adur = ArgusFetchDuration(argus);
     double mdur = ArgusFetchDuration(match);
     double asab = ArgusFetchSrcAppByteCount(argus);
     double msab = ArgusFetchSrcAppByteCount(match);
     if ((mdur > 0) && (adur > 0))
        retn = asab - (msab * adur) / mdur;
     else {
        retn = adur ? asab : -msab;
     }
  }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstAppBytes (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

  if (argus && match) {
     double adur = ArgusFetchDuration(argus);
     double mdur = ArgusFetchDuration(match);
     double asab = ArgusFetchSrcAppByteCount(argus);
     double msab = ArgusFetchSrcAppByteCount(match);
     if ((mdur > 0) && (adur > 0))
        retn = asab - (msab * adur) / mdur;
     else {
        retn = adur ? asab : -msab;
     }
  }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcPktSize (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstPktSize (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcPktSizeMax (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcPktSizeMin (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstPktSizeMax (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstPktSizeMin (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcIntPkt (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

   if (argus && match) {
      double asip = ArgusFetchSrcIntPkt(argus);
      double msip = ArgusFetchSrcIntPkt(match);
      retn = asip - msip;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstIntPkt (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

   if (argus && match) {
      double asip = ArgusFetchDstIntPkt(argus);
      double msip = ArgusFetchDstIntPkt(match);
      retn = asip - msip;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcIntPktMax (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

   if (argus && match) {
      double asip = ArgusFetchSrcIntPkt(argus);
      double msip = ArgusFetchSrcIntPkt(match);
      retn = asip - msip;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcIntPktMin (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstIntPktMax (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstIntPktMin (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcIntPktActive (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcIntPktActiveMax (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcIntPktActiveMin (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstIntPktActive (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstIntPktActiveMax (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstIntPktActiveMin (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcIntPktIdle (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcIntPktIdleMax (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcIntPktIdleMin (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstIntPktIdle (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstIntPktIdleMax (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstIntPktIdleMin (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareJitter (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcJitter (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstJitter (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareActiveJitter (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareActiveSrcJitter (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareActiveDstJitter (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareIdleJitter (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareIdleSrcJitter (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareIdleDstJitter (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareState (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDeltaDuration (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDeltaStartTime (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDeltaLastTime (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDeltaSrcPkts (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDeltaDstPkts (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDeltaSrcBytes (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDeltaDstBytes (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusComparePercentDeltaSrcPkts (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusComparePercentDeltaDstPkts (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusComparePercentDeltaSrcBytes (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusComparePercentDeltaDstBytes (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcUserData (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstUserData (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareUserData (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareTCPExtensions (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcLoad (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstLoad (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareLoad (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcLoss (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstLoss (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareLoss (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcPercentLoss (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstPercentLoss (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusComparePercentLoss (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcRate (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstRate (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareRate (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareTos (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcTos (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstTos (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDSByte (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcDSByte (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstDSByte (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcVLAN (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstVLAN (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareVLAN (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcVID (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstVID (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareVID (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcVPRI (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstVPRI (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareVPRI (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcMpls (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstMpls (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareMpls (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareWindow (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSrcWindow (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDstWindow (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareJoinDelay (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareLeaveDelay (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareMean (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareMax (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareMin (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareStartRange (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareEndRange (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareDuration (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;
   if (argus && match) {
      double adur = ArgusFetchDuration(argus) / ArgusFetchTransactions(argus);
      double mdur = ArgusFetchDuration(match) / ArgusFetchTransactions(match);
      retn = (adur - mdur);
   }
   
#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareTransactions (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareSequenceNumber (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareBinNumber (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareBins (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareService (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareTCPBase (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareTCPSrcBase (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareTCPDstBase (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}


double
ArgusCompareTCPRTT (struct ArgusRecordStruct *argus, struct ArgusRecordStruct *match)
{
   double retn = 1.0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "%s (%p, %p)", __func__, argus, match);
#endif
   return retn;
}

