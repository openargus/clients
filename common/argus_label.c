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
 * $Id: //depot/argus/clients/common/argus_label.c#76 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

/*
 * argus labeler/classifier library
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#ifndef ArgusLabel
#define ArgusLabel
#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <stdlib.h>
#include <syslog.h>
#include <errno.h>

#include <math.h>
#include <ctype.h>

#include <sys/types.h>
#include <argus_compat.h>

#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_sort.h>
#include <argus_metric.h>
#include <argus_histo.h>
#include <argus_label.h>

#include <rasplit.h>


#include <rasplit.h>

#if defined(__OpenBSD__)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif
 
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/tcp.h>

#include <ctype.h>

#if defined(ARGUS_GEOIP)
#include <GeoIPCity.h>
#endif

int RaReadAddressConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
int RaReadIeeeAddressConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

void RaAddSrvTreeNode(struct RaSrvTreeNode *, struct RaSrvSignature *, int, int);
int ArgusSortSrvSignatures (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
void RaAddToSrvTree (struct RaSrvSignature *, int);
int RaGenerateBinaryTrees(struct ArgusParserStruct *, struct ArgusLabelerStruct *);
int RaReadSrvSignature(struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
struct RaSrvSignature *RaFindSrv (struct RaSrvTreeNode *, u_char *ptr, int, int);

int ArgusAddToRecordLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);

int RaFindService(struct ArgusRecordStruct *);
struct RaSrvSignature *RaValidateService(struct ArgusParserStruct *, struct ArgusRecordStruct *);

int ArgusNodesAreEqual (struct RaAddressStruct *, struct RaAddressStruct *);
void ArgusUpdateNode (struct RaAddressStruct *, struct RaAddressStruct *);

struct RaSrvSignature *RaBestGuess = NULL;
int RaBestGuessScore = 0;


int RaPrintLabelTreeLevel = 1000000;
int RaPrintLabelTreeDebug = 0;

#define RALABEL_RCITEMS                         24

#define RALABEL_IANA_ADDRESS                    0
#define RALABEL_IANA_ADDRESS_FILE               1
#define RALABEL_IEEE_ADDRESS                    2
#define RALABEL_IEEE_ADDRESS_FILE               3
#define RALABEL_ARIN_COUNTRY_CODES              4
#define RA_DELEGATED_IP                         5
#define RALABEL_BIND_NAME                       6
#define RA_PRINT_DOMAINONLY                     7
#define RALABEL_IANA_PORT                       8
#define RALABEL_IANA_PORT_FILE                  9
#define RALABEL_ARGUS_FLOW                      10
#define RALABEL_ARGUS_FLOW_FILE                 11
#define RALABEL_GEOIP_ASN                       12
#define RALABEL_GEOIP_ASN_FILE                  13
#define RALABEL_GEOIP_V4_ASN_FILE               14
#define RALABEL_GEOIP_V6_ASN_FILE               15
#define RALABEL_GEOIP_CITY                      16
#define RALABEL_GEOIP_CITY_FILE                 17
#define RALABEL_GEOIP_V4_CITY_FILE              18
#define RALABEL_GEOIP_V6_CITY_FILE              19
#define RALABEL_PRINT_DOMAINONLY		20
#define RALABEL_PRINT_LOCALONLY			21
#define RALABEL_BIND_NON_BLOCKING		22
#define RALABEL_DNS_NAME_CACHE_TIMEOUT		23

char *RaLabelResourceFileStr [] = {
   "RALABEL_IANA_ADDRESS=",
   "RALABEL_IANA_ADDRESS_FILE=",
   "RALABEL_IEEE_ADDRESS=",
   "RALABEL_IEEE_ADDRESS_FILE=",
   "RALABEL_ARIN_COUNTRY_CODES=",
   "RA_DELEGATED_IP=",
   "RALABEL_BIND_NAME=",
   "RA_PRINT_DOMAINONLY=",
   "RALABEL_IANA_PORT=",
   "RALABEL_IANA_PORT_FILE=",
   "RALABEL_ARGUS_FLOW=",
   "RALABEL_ARGUS_FLOW_FILE=",
   "RALABEL_GEOIP_ASN=",
   "RALABEL_GEOIP_ASN_FILE=",
   "RALABEL_GEOIP_V4_ASN_FILE=",
   "RALABEL_GEOIP_V6_ASN_FILE=",
   "RALABEL_GEOIP_CITY=",
   "RALABEL_GEOIP_CITY_FILE=",
   "RALABEL_GEOIP_V4_CITY_FILE=",
   "RALABEL_GEOIP_V6_CITY_FILE=",
   "RALABEL_PRINT_DOMAINONLY=",
   "RALABEL_PRINT_LOCALONLY=",
   "RALABEL_BIND_NON_BLOCKING=",
   "RALABEL_DNS_NAME_CACHE_TIMEOUT=",
};



int
RaLabelParseResourceFile (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *file)
{
   int retn = 1, i, len, found = 0, lines = 0;
   char strbuf[MAXSTRLEN], *str = strbuf, *optarg = NULL;
   FILE *fd = NULL;

   if (file) {
      if ((fd = fopen (file, "r")) != NULL) {
         retn = 0;
         while ((fgets(str, MAXSTRLEN, fd)) != NULL)  {
            lines++;
            while (*str && isspace((int)*str))
                str++;

            if (*str && (*str != '#') && (*str != '\n') && (*str != '!')) {
               found = 0;
               for (i = 0; i < RALABEL_RCITEMS; i++) {
                  len = strlen(RaLabelResourceFileStr[i]);
                  if (!(strncmp (str, RaLabelResourceFileStr[i], len))) {

                     optarg = &str[len];

                     if (optarg[strlen(optarg) - 1] == '\n')
                        optarg[strlen(optarg) - 1] = '\0';

                     if (*optarg == '\"')
                        optarg++;

                     if (optarg[strlen(optarg) - 1] == '\"')
                        optarg[strlen(optarg) - 1] = '\0';
                        
                     if (*optarg == '\0')
                        optarg = NULL;

                     if (optarg) {
                        switch (i) {
                           case RALABEL_IANA_ADDRESS:
                              if (!(strncasecmp(optarg, "yes", 3)))
                                 labeler->RaLabelIanaAddress = 1;
                              else
                                 labeler->RaLabelIanaAddress = 0;
                              break;

                           case RALABEL_IANA_ADDRESS_FILE:
                              if (!(RaReadAddressConfig (parser, parser->ArgusLabeler, optarg) > 0))
                                 ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadAddressConfig error");
                              break;

                           case RALABEL_IEEE_ADDRESS:
                              if (!(strncasecmp(optarg, "yes", 3)))
                                 labeler->RaLabelIeeeAddress = 1;
                              else
                                 labeler->RaLabelIeeeAddress = 0;
                              break;

                           case RALABEL_IEEE_ADDRESS_FILE:
                              if (!(RaReadIeeeAddressConfig (parser, parser->ArgusLabeler, optarg) > 0))
                                 ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadIeeeAddressConfig error");
                              break;

                           case RALABEL_ARIN_COUNTRY_CODES:
                              if (!(strncasecmp(optarg, "yes", 3)))
                                 labeler->RaLabelCountryCode = 1;
                              else
                                 labeler->RaLabelCountryCode = 0;
                              break;

                           case RA_DELEGATED_IP:
                              if (!(RaReadAddressConfig (parser, parser->ArgusLabeler, optarg) > 0))
                                 ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadAddressConfig error");
                              break;


                           case RALABEL_BIND_NAME:
                              if (!(strncasecmp(optarg, "yes", 3))) labeler->RaLabelBindName = ARGUS_ADDR_MASK; else
                              if (!(strncasecmp(optarg, "all", 3))) labeler->RaLabelBindName = ARGUS_ADDR_MASK; else
                              if (!(strncasecmp(optarg, "saddr", 5))) labeler->RaLabelBindName = ARGUS_SRC_ADDR; else
                              if (!(strncasecmp(optarg, "daddr", 5))) labeler->RaLabelBindName = ARGUS_DST_ADDR; else
                              if (!(strncasecmp(optarg, "inode", 5))) labeler->RaLabelBindName = ARGUS_INODE_ADDR;

                              if (labeler->RaLabelBindName) {
                                 parser->nflag = 0;
#if defined(ARGUS_THREADS)
                                 if (ArgusParser->NonBlockingDNS) {
                                    extern void *ArgusDNSProcess (void *);
                                    if (ArgusParser->ArgusNameList == NULL) {
                                       pthread_attr_t attrbuf, *attr = &attrbuf;
   
                                       pthread_attr_init(attr);
                                       pthread_attr_setdetachstate(attr, PTHREAD_CREATE_JOINABLE);
   
                                       if (getuid() == 0)
                                          pthread_attr_setschedpolicy(attr, SCHED_RR);
                                       else
                                          attr = NULL;
   
                                       ArgusParser->ArgusNameList = ArgusNewList();
                                       if ((pthread_create(&ArgusParser->dns, attr, ArgusDNSProcess, NULL)) != 0)
                                          ArgusLog (LOG_ERR, "ArgusGetName() pthread_create error %s\n", strerror(errno));
                                    }
                                 }
#endif
                              } else
                                 labeler->RaLabelBindName = 0;
                              break;

                           case RALABEL_PRINT_DOMAINONLY:
                              if (!(strncasecmp(optarg, "yes", 3)))
                                 parser->domainonly = 1;
                              else
                                 parser->domainonly = 0;
                              break;

                           case RALABEL_PRINT_LOCALONLY:
                              if (!(strncasecmp(optarg, "yes", 3)))
                                 ++parser->fflag;
                              else
                                 parser->fflag = 0;
                              break;

                           case RALABEL_BIND_NON_BLOCKING:
                              break;

                           case RALABEL_DNS_NAME_CACHE_TIMEOUT:
                              if (isdigit((int)*optarg))
                                 parser->RaDNSNameCacheTimeout = (int)strtol(optarg, NULL, 10);
                              break;

                           case RALABEL_IANA_PORT:
                              if (!(strncasecmp(optarg, "yes", 3))) {
                                 labeler->RaLabelIanaPort = 1;
                              } else {
                                 labeler->RaLabelIanaPort = 0;
                              }
                              break;

                           case RALABEL_IANA_PORT_FILE:
                              if (RaReadPortConfig (parser, parser->ArgusLabeler, optarg) != 0)
                                 ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadPortConfig error");
                              break;

                           case RALABEL_ARGUS_FLOW:
                              if (!(strncasecmp(optarg, "yes", 3))) {
                                 labeler->RaLabelArgusFlow = 1;
                              } else {
                                 labeler->RaLabelArgusFlow = 0;
                              }
                              break;

                           case RALABEL_ARGUS_FLOW_FILE:
                              if (RaReadFlowLabels (parser, parser->ArgusLabeler, optarg) != 0)
                                 ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadFlowLabels error");
                              break;
#if defined(ARGUS_GEOIP)
                           case RALABEL_GEOIP_ASN:
                              if (!(strncasecmp(optarg, "yes", 3))) {
                                 labeler->RaLabelGeoIPAsn = 1;
                              } else {
                                 labeler->RaLabelGeoIPAsn = 0;
                              }
                              break;

                           case RALABEL_GEOIP_ASN_FILE:
                           case RALABEL_GEOIP_V4_ASN_FILE:
                              if ((parser->ArgusLabeler->RaGeoIPv4AsnObject = GeoIP_open (optarg, GEOIP_INDEX_CACHE)) == NULL)
                                 ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadGeoIPAsn database error");
                              break;

                           case RALABEL_GEOIP_V6_ASN_FILE:
                              if ((parser->ArgusLabeler->RaGeoIPv6AsnObject = GeoIP_open (optarg, GEOIP_INDEX_CACHE)) == NULL)
                                 ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadGeoIPAsn database error");
                              break;

                           case RALABEL_GEOIP_CITY: {
                              if (!(strncasecmp(optarg, "no", 2))) {
                                 labeler->RaLabelGeoIPCity = 0;
                              } else {
                                 char *sptr, *fptr, *tptr;
                                 int ind = 0, x;

                                 bzero(parser->ArgusLabeler->RaLabelGeoIPCityLabels, sizeof(parser->ArgusLabeler->RaLabelGeoIPCityLabels));

                                 if ((tptr = strchr(optarg, ':')) != NULL) {
                                    *tptr++ = '\0';
 
                                    while ((fptr = strtok(optarg, ",")) != NULL) {
                                       if (!strncmp(fptr, "*", 1))     parser->ArgusLabeler->RaLabelGeoIPCity |= ARGUS_ADDR_MASK; else
                                       if (!strncmp(fptr, "saddr", 5)) parser->ArgusLabeler->RaLabelGeoIPCity |= ARGUS_SRC_ADDR; else
                                       if (!strncmp(fptr, "daddr", 5)) parser->ArgusLabeler->RaLabelGeoIPCity |= ARGUS_DST_ADDR; else
                                       if (!strncmp(fptr, "inode", 5)) parser->ArgusLabeler->RaLabelGeoIPCity |= ARGUS_INODE_ADDR;
                                       optarg = NULL;
                                    }
                                 } else
                                    parser->ArgusLabeler->RaLabelGeoIPCity |= ARGUS_ADDR_MASK;

                                 while ((sptr = strtok(tptr, ",")) != NULL) {
                                    for (x = 1; x < ARGUS_GEOIP_TOTAL_OBJECTS; x++) {
                                       if (!(strncmp(sptr, ArgusGeoIPCityObjects[x].field, ArgusGeoIPCityObjects[x].length))) {
                                          parser->ArgusLabeler->RaLabelGeoIPCityLabels[ind] = ArgusGeoIPCityObjects[x].value;
                                          ind++;
                                          break;
                                       }
                                    }
                                    tptr = NULL;
                                 }
                              }
                              break;
                           }

                           case RALABEL_GEOIP_CITY_FILE:
                           case RALABEL_GEOIP_V4_CITY_FILE:
                              if ((parser->ArgusLabeler->RaGeoIPv4CityObject = GeoIP_open( optarg, GEOIP_INDEX_CACHE)) == NULL)
                                 ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadGeoIPAsn database error");
                              break;

                           case RALABEL_GEOIP_V6_CITY_FILE:
                              if ((parser->ArgusLabeler->RaGeoIPv6CityObject = GeoIP_open( optarg, GEOIP_INDEX_CACHE)) == NULL)
                                 ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadGeoIPAsn database error");
                              break;
#endif
                           default:
                              break;
                        }
                     }
                     found++;
                     break;
                  }
               }
               if (!found) {
                  ArgusLog (LOG_ERR, "%s: syntax error line %d\n", file, lines);
               }
            }
         }

         fclose(fd);

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "%s: %s\n", file, strerror(errno));
#endif
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaLabelParseResourceFile (%s) returning %d\n", file, retn);
#endif

   return (retn);
}

#if defined(ARGUS_GEOIP)
int ArgusPrintGeoIPRecord (struct ArgusParserStruct *, GeoIPRecord *, char *, int, int, char*);

int
ArgusPrintGeoIPRecord (struct ArgusParserStruct *parser, GeoIPRecord *gir, char *label, int len, int found, char *prefix)
{
   int slen = strlen(label), x, tf = 0;

   if (found) {
      snprintf (&label[slen], len - slen, ":");
      slen++;
   }

   snprintf (&label[slen], len - slen, "%s", prefix);
   slen = strlen(label);

   for (x = 0; x < ARGUS_GEOIP_TOTAL_OBJECTS; x++) {
      struct ArgusGeoIPCityObject *obj;
      int ind;
      if ((ind = parser->ArgusLabeler->RaLabelGeoIPCityLabels[x]) > 0) {
         if (tf) {
            snprintf (&label[slen], len - slen, "%c", ',');
            slen++;
         }
         obj = &ArgusGeoIPCityObjects[ind];
         switch (obj->value) {
            case ARGUS_GEOIP_COUNTRY_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->country_code);
               break;
            case ARGUS_GEOIP_COUNTRY_CODE_3:
               snprintf (&label[slen], len - slen, obj->format, gir->country_code3);
               break;
            case ARGUS_GEOIP_COUNTRY_NAME:
               snprintf (&label[slen], len - slen, obj->format, gir->country_name);
               break;
            case ARGUS_GEOIP_REGION:
               snprintf (&label[slen], len - slen, obj->format, gir->region);
               break;
            case ARGUS_GEOIP_CITY_NAME:
               snprintf (&label[slen], len - slen, obj->format, gir->city);
               break;
            case ARGUS_GEOIP_POSTAL_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->postal_code);
               break;
            case ARGUS_GEOIP_LATITUDE:
               snprintf (&label[slen], len - slen, obj->format, gir->latitude);
               break;
            case ARGUS_GEOIP_LONGITUDE:
               snprintf (&label[slen], len - slen, obj->format, gir->longitude);
               break;
            case ARGUS_GEOIP_METRO_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->metro_code);
               break;
            case ARGUS_GEOIP_AREA_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->area_code);
               break;
            case ARGUS_GEOIP_CHARACTER_SET:
               snprintf (&label[slen], len - slen, obj->format, gir->charset);
               break;
            case ARGUS_GEOIP_CONTINENT_CODE:
               snprintf (&label[slen], len - slen, obj->format, gir->continent_code);
               break;
//          case ARGUS_GEOIP_NETMASK:
//             snprintf (&label[slen], len - slen, obj->format, gir->netmask);
//             break;
         }
         slen = strlen(label);
         tf++;

      } else
         break;
   }

   return found;
}
#endif


int
ArgusAddToRecordLabel (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, char *tlabel)
{
   struct ArgusLabelStruct *l1 = (void *) argus->dsrs[ARGUS_LABEL_INDEX], *l2;
   char buf[MAXBUFFERLEN], *label = NULL;
   int len = 0, retn = 0, tlen = strlen(tlabel);

   len = 4 * ((tlen + 3)/4);
   if ((l2 = ArgusCalloc(1, sizeof(*l2))) == NULL)
      ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s", strerror(errno));

   if ((l2->l_un.label = calloc(1, len + 4)) == NULL)
      ArgusLog (LOG_ERR, "RaProcessRecord: calloc error %s", strerror(errno));

   l2->hdr.type             = ARGUS_LABEL_DSR;
   l2->hdr.argus_dsrvl8.len = 1 + ((len + 3)/4);
   bcopy (tlabel, l2->l_un.label, tlen);

   bzero (buf, sizeof(buf));

   if ((label = ArgusMergeLabel(l1, l2, buf, MAXBUFFERLEN, ARGUS_UNION)) != NULL) {
      if (l1 != NULL) {
         int slen = strlen(label);
         int len = 4 * ((slen + 3)/4);

         if (l1->l_un.label != NULL) 
            free(l1->l_un.label);

         if ((l1->l_un.label = calloc(1, len)) == NULL)
            ArgusLog (LOG_ERR, "RaProcessRecord: calloc error %s", strerror(errno));

         l1->hdr.argus_dsrvl8.len = 1 + ((len + 3)/4);
         bcopy (label, l1->l_un.label, slen);

         free(l2->l_un.label);
         ArgusFree(l2);

      } else {
         argus->dsrs[ARGUS_LABEL_INDEX] = (struct ArgusDSRHeader*) l2;
         argus->dsrindex |= (0x1 << ARGUS_LABEL_INDEX);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAddToRecordLabel (%p, %p, %s) returning %d\n", parser, argus, tlabel, retn);
#endif

   return retn;
}


struct ArgusRecordStruct *
ArgusLabelRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;
   struct ArgusRecordStruct *retn = argus;
   char label[MAXBUFFERLEN];
   int found = 0, slen = 0;
   char *rstr = NULL;

   if (labeler == NULL)
      return (retn);

   bzero(label, sizeof(MAXBUFFERLEN));

   if (labeler->RaLabelIanaAddress) {
      if ((rstr = RaAddressLabel (parser, argus)) != NULL) {
         if (found) {
            snprintf (&label[slen], MAXBUFFERLEN - slen, ":");
            slen++;
         }
         snprintf (&label[slen], MAXBUFFERLEN - slen, "%s", rstr);
         found++;
      }
   }

   if (labeler->RaLabelCountryCode)
      RaCountryCodeLabel (parser, argus);

   if (labeler->RaLabelBindName) {
      struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];

      if (flow != NULL) {
         char *addrstr;

         switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
            case ARGUS_TYPE_IPV4: {
               if (labeler->RaLabelBindName & ARGUS_SRC_ADDR) {
                  slen = strlen(label);
                  if ((addrstr = ArgusGetName (parser, (unsigned char *)&flow->ip_flow.ip_src)) != NULL) {
                     if (strcmp(addrstr, "not resolved")) {
                        if (found) {
                           snprintf (&label[slen], MAXBUFFERLEN - slen, ":");
                           slen++;
                        }
                        snprintf (&label[slen], MAXBUFFERLEN - slen, "sname=%s", addrstr);
                        found++;
                     }
                  }
               }
               if (labeler->RaLabelBindName & ARGUS_DST_ADDR) {
                  slen = strlen(label);
                  if ((addrstr = ArgusGetName (parser, (unsigned char *)&flow->ip_flow.ip_dst)) != NULL) {
                     if (strcmp(addrstr, "not resolved")) {
                        if (found) {
                           snprintf (&label[slen], MAXBUFFERLEN - slen, ":");
                           slen++;
                        }
                        snprintf (&label[slen], MAXBUFFERLEN - slen, "dname=%s", addrstr);
                        found++;
                     }
                  }
               }
               if (labeler->RaLabelBindName & ARGUS_INODE_ADDR) {
                  struct ArgusIcmpStruct *icmp = (void *)argus->dsrs[ARGUS_ICMP_INDEX];
                  slen = strlen(label);
                  if (icmp != NULL) {
                     if (icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED) {
                        if ((addrstr = ArgusGetName (parser, (unsigned char *)&icmp->osrcaddr)) != NULL) {
                           if (strcmp(addrstr, "not resolved")) {
                              if (found) {
                                 snprintf (&label[slen], MAXBUFFERLEN - slen, ":");
                                 slen++;
                              }
                              snprintf (&label[slen], MAXBUFFERLEN - slen, "iname=%s", addrstr);
                              found++;
                           }
                        }
                     }
                  }
               }
               break;
            }
            case ARGUS_TYPE_IPV6: {
                break;
            }
         }
      }
   }

   if (labeler->RaLabelIanaPort) {
      char buf[MAXSTRLEN];
      if ((rstr = RaPortLabel (parser, argus, buf, MAXSTRLEN)) != NULL) {
         if (strlen(rstr)) {
            slen = strlen(label);
            if (found) {
               snprintf (&label[slen], MAXBUFFERLEN - slen, ":");
               slen++;
            }
            snprintf (&label[slen], MAXBUFFERLEN - slen, "%s", rstr);
            found++;
         }
      }
   }

   if (labeler->RaLabelArgusFlow) {
      char buf[MAXSTRLEN];
      if ((rstr = RaFlowLabel (parser, argus, buf, MAXSTRLEN)) != NULL) {
         if (strlen(rstr)) {
            slen = strlen(label);
            if (found) {
               snprintf (&label[slen], MAXBUFFERLEN - slen, ":");
               slen++;
            }
            snprintf (&label[slen], MAXBUFFERLEN - slen, "%s", rstr);
            found++;
         }
      }
   }

#if defined(ARGUS_GEOIP)
   if (labeler->RaLabelGeoIPAsn) {
      if (labeler->RaGeoIPv4AsnObject != NULL) {
         struct ArgusAsnStruct *asn = (struct ArgusAsnStruct *) argus->dsrs[ARGUS_ASN_INDEX];
         struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
         struct ArgusIcmpStruct *icmp = (void *)argus->dsrs[ARGUS_ICMP_INDEX];

         if (asn == NULL) {
            if ((asn = ArgusCalloc(1, sizeof(*asn))) == NULL)
               ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s", strerror(errno));

            asn->hdr.type              = ARGUS_ASN_DSR;
            asn->hdr.subtype           = ARGUS_ASN_ORIGIN;
            asn->hdr.argus_dsrvl8.qual = 0;
            asn->hdr.argus_dsrvl8.len  = 3;

            argus->dsrs[ARGUS_ASN_INDEX] = (struct ArgusDSRHeader*) asn;
            argus->dsrindex |= (0x01 << ARGUS_ASN_INDEX);
         }

         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        if (asn->src_as == 0) {
                           if ((rstr = GeoIP_org_by_ipnum (labeler->RaGeoIPv4AsnObject, flow->ip_flow.ip_src)) != NULL) {
                              if (strlen(rstr)) {
                                 int result = 0;
                                 if (sscanf(rstr, "AS%d", &result) == 1)
                                    asn->src_as = result;
                              }
                              free(rstr);
                           }
                        }

                        if (asn->dst_as == 0) {
                           if ((rstr = GeoIP_org_by_ipnum (labeler->RaGeoIPv4AsnObject, flow->ip_flow.ip_dst)) != NULL) {
                              if (strlen(rstr)) {
                                 int result = 0;
                                 if (sscanf(rstr, "AS%d", &result) == 1)
                                    asn->dst_as = result;
                              }
                              free(rstr);
                           }
                        }

                        if (asn->inode_as == 0) {
                           if (icmp != NULL) {
                              if (icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED) {
                                 if ((rstr = GeoIP_org_by_ipnum (labeler->RaGeoIPv4AsnObject, icmp->osrcaddr)) != NULL) {
                                    if (strlen(rstr)) {
                                       int result = 0;
                                       if (sscanf(rstr, "AS%d", &result) == 1)
                                          asn->inode_as = result;

                                       asn->hdr.argus_dsrvl8.len  = 4;
                                    }
                                    free(rstr);
                                 }
                              }
                           }
                        }
                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        if (labeler->RaGeoIPv6AsnObject) {
                           if (asn->src_as == 0) {
                              struct in6_addr saddr;

                              bcopy(flow->ipv6_flow.ip_src, saddr.s6_addr, sizeof(saddr));

                              if ((rstr = GeoIP_org_by_ipnum_v6 (labeler->RaGeoIPv6AsnObject, saddr)) != NULL) {
                                 if (strlen(rstr)) {
                                    int result = 0;
                                    if (sscanf(rstr, "AS%d", &result) == 1)
                                       asn->src_as = result;
                                 }
                                 free(rstr);
                              }
                           }

                           if (asn->dst_as == 0) {
                              struct in6_addr daddr;

                              bcopy(flow->ipv6_flow.ip_dst, daddr.s6_addr, sizeof(daddr));

                              if ((rstr = GeoIP_org_by_ipnum_v6 (labeler->RaGeoIPv6AsnObject, daddr)) != NULL) {
                                 if (strlen(rstr)) {
                                    int result = 0;
                                    if (sscanf(rstr, "AS%d", &result) == 1)
                                       asn->dst_as = result;
                                 }
                                 free(rstr);
                              }
                           }
                        }
                        break;
                     }
                  }
                  break;
               }
            }
         }
      }
   }

   if (labeler->RaLabelGeoIPCity) {
      if (labeler->RaGeoIPv4CityObject != NULL) {
         struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
         GeoIPRecord *gir;

         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE:
               case ARGUS_FLOW_LAYER_3_MATRIX: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        if (labeler->RaLabelGeoIPCity & ARGUS_SRC_ADDR)
                           if ((gir = GeoIP_record_by_ipnum (labeler->RaGeoIPv4CityObject, flow->ip_flow.ip_src)) != NULL) {
                              ArgusPrintGeoIPRecord(parser, gir, label, sizeof(label), found, "scity=");
                              GeoIPRecord_delete(gir);
                              found++;
                           }

                        if (labeler->RaLabelGeoIPCity & ARGUS_DST_ADDR)
                           if ((gir = GeoIP_record_by_ipnum (labeler->RaGeoIPv4CityObject, flow->ip_flow.ip_dst)) != NULL) {
                              ArgusPrintGeoIPRecord(parser, gir, label, sizeof(label), found, "dcity=");
                              GeoIPRecord_delete(gir);
                              found++;
                           }

                        if (labeler->RaLabelGeoIPCity & ARGUS_INODE_ADDR) {
                           struct ArgusIcmpStruct *icmp = (void *)argus->dsrs[ARGUS_ICMP_INDEX];

                           if (icmp != NULL) {
                              if (icmp->hdr.argus_dsrvl8.qual & ARGUS_ICMP_MAPPED) {
                                 struct ArgusFlow *flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX];

                                 if (flow != NULL) {
                                    switch (flow->hdr.subtype & 0x3F) {
                                       case ARGUS_FLOW_CLASSIC5TUPLE:
                                       case ARGUS_FLOW_LAYER_3_MATRIX: {
                                          switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                                             case ARGUS_TYPE_IPV4:
                                                if ((gir = GeoIP_record_by_ipnum (labeler->RaGeoIPv4CityObject, icmp->osrcaddr)) != NULL) {
                                                   ArgusPrintGeoIPRecord(parser, gir, label, sizeof(label), found, "icity=");
                                                   GeoIPRecord_delete(gir);
                                                   found++;
                                                }
                                                break;

                                             case ARGUS_TYPE_IPV6:
                                                break;
                                          }
                                          break;
                                       }

                                       default:
                                          break;
                                    }
                                 }
                              }
                           }
                        }
                        break;
                     }
                     case ARGUS_TYPE_IPV6: {
                        if (labeler->RaGeoIPv6CityObject != NULL) {
                           if (labeler->RaLabelGeoIPCity & ARGUS_SRC_ADDR) {
                              struct in6_addr saddr;
                              bcopy(flow->ipv6_flow.ip_src, saddr.s6_addr, sizeof(saddr));

                              if ((gir = GeoIP_record_by_ipnum_v6 (labeler->RaGeoIPv6CityObject, saddr)) != NULL) {
                                 ArgusPrintGeoIPRecord(parser, gir, label, sizeof(label), found, "scity=");
                                 GeoIPRecord_delete(gir);
                                 found++;
                              }
                           }

                           if (labeler->RaLabelGeoIPCity & ARGUS_DST_ADDR) {
                              struct in6_addr daddr;
                              bcopy(flow->ipv6_flow.ip_dst, daddr.s6_addr, sizeof(daddr));

                              if ((gir = GeoIP_record_by_ipnum_v6 (labeler->RaGeoIPv6CityObject, daddr)) != NULL) {
                                 ArgusPrintGeoIPRecord(parser, gir, label, sizeof(label), found, "dcity=");
                                 GeoIPRecord_delete(gir);
                                 found++;
                              }
                           }
                        }
                        break;
                     }
                  }
               }
            }
         }
      }
   }
#endif

   if (found)
      ArgusAddToRecordLabel (parser, argus, label);

   return (retn);
}


#define ARGUS_RCITEMS    4

#define ARGUS_RC_FILTER  0
#define ARGUS_RC_LABEL   1
#define ARGUS_RC_COLOR   2
#define ARGUS_RC_CONT    3

char *ArgusFlowLabelFields[ARGUS_RCITEMS] = {
   "filter", "label", "color", "cont",
};

int
RaReadFlowLabels (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *file)
{
   char strbuf[MAXSTRLEN], *str = strbuf;
   char *ptr, *end, *value, *filter;
   char *label = NULL, *color = NULL;
   int retn = 1, linenum = 0;
   FILE *fd =  NULL;

   if (labeler != NULL) {
      if (labeler->ArgusFlowQueue == NULL)
         if ((labeler->ArgusFlowQueue = ArgusNewQueue()) == NULL)
            ArgusLog (LOG_ERR, "RaReadAddressConfig: ArgusNewList error %s\n", strerror(errno));

      if ((fd = fopen (file, "r")) != NULL) {
         while ((ptr = fgets (str, MAXSTRLEN, fd)) != NULL) {
            linenum++;
            while (isspace((int)*ptr)) ptr++;

            if (*str && (*str != '\n') && (*str != '!')) {
               switch (*ptr) {
                  case '#': {
                     if (!strncmp((char *)&ptr[1], "include ", 8)) {
                        char *sptr;
                        if ((sptr = strtok(&ptr[9], " \t\n")) != NULL)
                           RaReadFlowLabels (parser, labeler, sptr);
                     }
                     break;
                  }

                  default: {
                     int i, done = 0, tlines = 0, cont = 0, defined = 0;

                     while (!done) {
                        for (i = 0; i < ARGUS_RCITEMS; i++) {
                           if (!(strncmp(str, ArgusFlowLabelFields[i], strlen(ArgusFlowLabelFields[i])))) {
                              ptr = str + strlen(ArgusFlowLabelFields[i]); 
                              while (*ptr && isspace((int)*ptr)) ptr++;

                              if (!(*ptr == '=') && (i != ARGUS_RC_CONT))
                                 ArgusLog (LOG_ERR, "ArgusParseFlowLabeler: syntax error line %d %s", tlines, str);

                              ptr++;
                              while (*ptr && isspace((int)*ptr)) ptr++;

                              switch (i) {
                                 case ARGUS_RC_FILTER: 
                                 case ARGUS_RC_LABEL:
                                 case ARGUS_RC_COLOR: {
                                    if ((*ptr == '\"') || (*ptr =='\'')) {
                                       char delim = *ptr;
                                       ptr++;
                                       end = ptr;
                                       while (*end != delim) end++;
                                       *end++ = '\0';
                                       value = strdup(ptr);
                                       ptr = end;
                                    }
                                    break;
                                 }
                              }

                              switch (i) {
                                 case ARGUS_RC_FILTER: filter = value; break;
                                 case ARGUS_RC_LABEL:  label  = value; break;
                                 case ARGUS_RC_COLOR:  color  = value; break;
                                 case ARGUS_RC_CONT: {
                                   cont++;
                                   done++;
                                   break;
                                 }
                              }

                              while (*ptr && isspace((int)*ptr)) ptr++;
                              str = ptr;
                              defined++;
                           }
                        }

                        if (!(done || defined))
                           ArgusLog (LOG_ERR, "ArgusParseAggregator: syntax error line %d: %s", tlines, str);

                        if (ptr && ((*ptr == '\n') || (*ptr == '\0')))
                           done++;
                     }

                     if (defined) {
                        struct RaFlowLabelStruct *raflow = NULL;
                        if ((raflow = (void *)ArgusCalloc(1, sizeof(*raflow))) != NULL) {
                           if (filter != NULL) {
                              raflow->filterstr = strdup(filter);
                              if (ArgusFilterCompile (&raflow->filter, raflow->filterstr, ArgusParser->Oflag) < 0)
                                 ArgusLog (LOG_ERR, "RaReadFlowLabels ArgusFilterCompile returned error");
                           }

                           if (label != NULL)
                              raflow->labelstr = strdup(label);

                           if (color != NULL)
                              raflow->colorstr = strdup(color);

                           if (cont != 0)
                              raflow->cont = 1;
                        }
                        ArgusAddToQueue(labeler->ArgusFlowQueue, &raflow->qhdr, ARGUS_LOCK);
                     }
                     retn = 0;
                     break;
                  }
               }
            }
            str = strbuf;
         }
 
         fclose(fd);
 
      } else
         ArgusLog (LOG_ERR, "%s: %s", file, strerror(errno));
   }
 
#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaReadFlowLabels (0x%x, 0x%x, %s) returning %d\n", parser, labeler, file, retn);
#endif
 
   return (retn);
}


struct RaAddressStruct *RaFindAddress (struct ArgusParserStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);
struct RaAddressStruct *RaInsertAddress (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);

void RaInsertRIRTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *);
void RaInsertAddressTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *);

struct RaAddressStruct *
RaFindAddress (struct ArgusParserStruct *parser, struct RaAddressStruct *tree, struct RaAddressStruct *node, int mode)
{
   struct RaAddressStruct *retn = NULL;
   int done = 0;

   while (tree && !done) {
     unsigned int mask, taddr, naddr;

      switch (tree->addr.type) {
         case AF_INET: {
            if (tree->addr.masklen > 0)
               mask = 0xFFFFFFFF << (32 - tree->addr.masklen);
            else
               mask = 0;

            taddr = tree->addr.addr[0] & mask;
            naddr = node->addr.addr[0] & mask;

            if (taddr == naddr) {
               switch (mode) {
                  case ARGUS_NODE_MATCH: 
                     if ((tree->l == NULL) && (tree->r == NULL)) {
                        retn = tree;
                        done++;
                        break;
                     } else
                     if (tree->status & ARGUS_NODE) {
                        retn = tree;
                        done++;
                        break;
                     }

                  case ARGUS_EXACT_MATCH: 
                     if (node->addr.masklen == tree->addr.masklen)
                        retn = tree;
                     else
                     if ((tree->l == NULL) && (tree->r == NULL)) {
                        retn = NULL;

                     } else {
                        if ((node->addr.addr[0] >> (32 - (tree->addr.masklen + 1))) & 0x01)
                          retn = RaFindAddress (parser, tree->l, node, mode);
                        else 
                          retn = RaFindAddress (parser, tree->r, node, mode);
                     }
                     done++;
                     break;

                  case ARGUS_LONGEST_MATCH: 
                     if ((node->addr.addr[0] >> (32 - (tree->addr.masklen + 1))) & 0x01) {
                        if ((retn = RaFindAddress (parser, tree->l, node, mode)) == NULL)
                           retn = tree;
                     } else {
                        if ((retn = RaFindAddress (parser, tree->r, node, mode)) == NULL)
                           retn = tree;
                     }
                     done++;
                     break;
                  
                  case ARGUS_ANY_MATCH:
                     retn = tree;
                     done++;
                     break;
               }

            } else 
               done++;
            break;
         }

         case AF_INET6: {
            done++;
            break;
         }
      }
   }

   return (retn);
}


int
ArgusNodesAreEqual (struct RaAddressStruct *tree, struct RaAddressStruct *node)
{
   int retn = 0;
   if (tree && node)
      retn = bcmp(&tree->addr, &node->addr, sizeof(tree->addr));

   return ((retn == 0) ? 1 : 0);
}

void
ArgusUpdateNode (struct RaAddressStruct *tree, struct RaAddressStruct *node)
{
   if (strlen(node->cco)) strncpy(tree->cco, node->cco, sizeof(tree->cco));
   if ((tree->label != NULL) && (node->label == NULL))
      node->label = strdup(tree->label);
}


struct RaAddressStruct *
RaInsertAddress (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, struct RaAddressStruct *tree, struct RaAddressStruct *node, int status)
{
   struct RaAddressStruct **ArgusAddrTree = labeler->ArgusAddrTree;
   struct RaAddressStruct *retn  = NULL;

   if ((labeler == NULL) || (node == NULL)) 
      return (retn);

   if ((tree == NULL) && (ArgusAddrTree[node->addr.type] == NULL)) {
      ArgusAddrTree[node->addr.type] = node;
      node->status |= ARGUS_NODE | status;
      return (node);
   }

   if (tree == NULL) tree = ArgusAddrTree[node->addr.type];

// OK, so we need to decend into the tree, and insert this record,
// and any additional interior nodes, needed.
// As long as the the new node, and the current nodes masked addrs
// are equal, then we just needed to decend either left of right.

   if (ArgusNodesAreEqual(tree, node)) {
      ArgusUpdateNode(tree, node);
      tree->status |= status;
      return (NULL);

   } else {
      unsigned int taddr, naddr;
      unsigned int tmask, nmask;

      node->status |= status;

      switch (tree->addr.type) {
         case AF_INET: {
            tmask = tree->addr.mask[0];
            taddr = tree->addr.addr[0] & tmask;
            naddr = node->addr.addr[0] & tmask;

            if (naddr == taddr) {     // node and tree address are same, but may not be at right part in tree
               if (node->addr.masklen > tree->addr.masklen) {  // if node mask is longer, then we'll insert below, which side?
                  unsigned int naddr = 0;
                  int nmasklen = (32 - (tree->addr.masklen + 1));

                  if (nmasklen != 0)
                     naddr = node->addr.addr[0] >> nmasklen;

                  if (naddr & 0x01) {
                     if (tree->l == NULL) {
                        if (node->addr.masklen > 0) {
                           nmask = (0xFFFFFFFF << (32 - node->addr.masklen));
                           nmask &= (0xFFFFFFFF >> tree->addr.masklen);
                        } else
                           nmask = 0;

                        node->offset = tree->addr.masklen;
                        tree->l = node;
                        node->p = tree;
                        retn = node;

                     } else {
                        struct RaAddressStruct *lt = tree->l;

                        if (node->addr.masklen < lt->addr.masklen) {
                           int maskn = node->addr.masklen;
                           int i = tree->addr.masklen + 1;

                           for (; i < node->addr.masklen; i++) {
                              tmask = (0xFFFFFFFF << (32 - i));
                              taddr = lt->addr.addr[0] & tmask;
                              naddr = node->addr.addr[0] & tmask;
                              if (naddr != taddr)
                                 break;
                              maskn = i;
                           }
                           if (maskn == node->addr.masklen) {
                              tree->l = node;
                              node->p = tree;
                              return (RaInsertAddress (parser, labeler, tree->l, lt, status));

                           } else {
                              struct RaAddressStruct *addr = NULL;

                              if ((addr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*addr))) == NULL)
                                 ArgusLog (LOG_ERR, "RaInsertAddress: ArgusCalloc error %s\n", strerror(errno));

                              bcopy ((char *)&node->addr, (char *)&addr->addr, sizeof(addr->addr));
                              addr->addr.masklen = maskn;
                              addr->offset = lt->offset;
                              addr->status = status;

                              if (addr->addr.masklen) {
                                 addr->addr.mask[0]  = (0xFFFFFFFF << (32 - addr->addr.masklen));
                                 addr->addr.addr[0] &= addr->addr.mask[0];
                              } else
                                 addr->addr.mask[0] = 0;

                              addr->addr.mask[0] &= addr->addr.mask[0] & (0xFFFFFFFF >> addr->offset);
                              tree->l = addr;
                              addr->p = tree;

                              RaInsertAddress (parser, labeler, tree->l, lt, status);
                              return (RaInsertAddress (parser, labeler, tree->l, node, status));
                           }

                        } else
                           return (RaInsertAddress (parser, labeler, tree->l, node, status));
                     }

                  } else {
                     if (tree->r == NULL) {
                        if (node->addr.masklen > 0) {
                           nmask  = (0xFFFFFFFF << (32 - node->addr.masklen));
                           nmask &= (0xFFFFFFFF >> tree->addr.masklen);
                        } else
                           nmask = 0;
   
                        node->offset = tree->addr.masklen;
//                      node->addr.mask[0] = nmask;
                        tree->r = node;
                        node->p = tree;
                        retn = node;
   
                     } else {
                        struct RaAddressStruct *rt = tree->r;

                        if (node->addr.masklen < rt->addr.masklen) {
                           int maskn = node->addr.masklen;
                           int i = tree->addr.masklen + 1;

                           for (; i < node->addr.masklen; i++) {
                              tmask = (0xFFFFFFFF << (32 - i));
                              taddr = rt->addr.addr[0] & tmask;
                              naddr = node->addr.addr[0] & tmask;
                              if (naddr != taddr) 
                                 break;
                              maskn = i;
                           }
                           if (maskn == node->addr.masklen) {
                              tree->r = node;
                              node->p = tree;
                              return (RaInsertAddress (parser, labeler, tree->r, rt, status));

                           } else {
                              struct RaAddressStruct *addr = NULL;

                              if ((addr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*addr))) == NULL)
                                 ArgusLog (LOG_ERR, "RaInsertAddress: ArgusCalloc error %s\n", strerror(errno));

                              bcopy ((char *)&node->addr, (char *)&addr->addr, sizeof(addr->addr));
                              addr->addr.masklen = maskn;
                              addr->offset = rt->offset;
                              addr->status = status;

                              if (addr->addr.masklen) {
                                 addr->addr.mask[0]  = (0xFFFFFFFF << (32 - addr->addr.masklen));
                                 addr->addr.addr[0] &= addr->addr.mask[0];
                              } else
                                 addr->addr.mask[0] = 0;

                              addr->addr.mask[0] &= addr->addr.mask[0] & (0xFFFFFFFF >> addr->offset);
                              tree->r = addr;
                              addr->p = tree;

                              RaInsertAddress (parser, labeler, tree->r, rt, status);
                              return (RaInsertAddress (parser, labeler, tree->r, node, status));
                           }

                        } else
                           return (RaInsertAddress (parser, labeler, tree->r, node, status));
                     }
                  }
   
               } else {
                  struct RaAddressStruct *ptree = tree->p;

                  if ((32 - (node->addr.masklen + 1)) > 0)
                     naddr = tree->addr.addr[0] >> (32 - (node->addr.masklen + 1));
                  if (node->addr.masklen > 0)
                     nmask = (0xFFFFFFFF << (32 - node->addr.masklen));
                  else
                     nmask = 0;

                  if (naddr & 0x01) {
                     node->l = tree;
                     tree->p = node;
                  } else {
                     node->r = tree;
                     tree->p = node;
                  }
                  
                  if (ptree != NULL) {
                     if (ptree->l == tree)
                        ptree->l = node;
                     else
                        ptree->r = node;

                     node->p = ptree;

                     if (ptree->addr.masklen < 32)
                        nmask &= nmask & (0xFFFFFFFF >> ptree->addr.masklen);
                     else
                        nmask = 0;
                     node->offset = ptree->addr.masklen;

                  } else {
                     ArgusAddrTree[node->addr.type] = node;
                     node->offset = 0;
                  }

                  node->addr.mask[0] = nmask;
                  tree->offset = node->addr.masklen;

                  if (32 - tree->addr.masklen)
                     tmask = (0xFFFFFFFF << (32 - tree->addr.masklen));
                  else
                     tmask = 0;
                  tmask &= tmask & (0xFFFFFFFF >> node->addr.masklen);
                  tree->addr.mask[0] = tmask;
               }
               retn = node;

            } else {
               struct RaAddressStruct *addr = NULL, *ptree = tree->p;
               unsigned int value;
               int i, len = (node->addr.masklen - tree->offset);
               int masklen = 0;

               if (tree->addr.masklen > 0)
                  tmask = (0xFFFFFFFF << (32 - tree->addr.masklen));
               else
                  tmask = 0;
    
               value = ~(taddr ^ naddr) & tmask;
               value = value << tree->offset;

               for (i = 0; i < len; i++) {
                  if (value & 0x80000000) {
                     masklen++;
                     value = value << 1;
                  } else
                     break;
               }

               if ((addr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*addr))) == NULL)
                  ArgusLog (LOG_ERR, "RaInsertAddress: ArgusCalloc error %s\n", strerror(errno));

               bcopy ((char *)&node->addr, (char *)&addr->addr, sizeof(addr->addr));
               addr->offset = tree->offset;
               addr->status = status;

               if (ptree != NULL) {
                  addr->addr.masklen = ptree->addr.masklen + masklen;
               } else {
                  addr->addr.masklen = masklen;
               }

               if (addr->addr.masklen) {
                  addr->addr.mask[0]  = (0xFFFFFFFF << (32 - addr->addr.masklen));
                  addr->addr.addr[0] &= addr->addr.mask[0];
               } else
                  addr->addr.mask[0] = 0;

               addr->addr.mask[0] &= addr->addr.mask[0] & (0xFFFFFFFF >> addr->offset);

               tree->offset += masklen;

               if (tree->addr.masklen)
                  tree->addr.mask[0] = (0xFFFFFFFF << (32 - tree->addr.masklen));
               else
                  tree->addr.mask[0] = 0;

               tree->addr.mask[0] &= tree->addr.mask[0] & (0xFFFFFFFF >> tree->offset);

               node->offset  = tree->offset;
               value = tree->addr.addr[0] >> (32 - (tree->offset + 1));

               if ((node->addr.addr[0] == addr->addr.addr[0]) &&
                   (node->addr.masklen == addr->addr.masklen)) {
                  ArgusFree(addr);
                  if (ptree) {
                     if (ptree->l == tree) {
                        ptree->l = node;
                        node->p = ptree;
                     } else {
                        ptree->r = node;
                        node->p = ptree;
                     }  
                  } else {
                     ArgusAddrTree[tree->addr.type] = node;
                     node->offset = 0;
                  }

                  if (value & 0x01) {
                     node->l = tree;
                     tree->p = node;
                  } else {
                     node->r = tree;
                     tree->p = node;
                  }
               } else {
                  if (ptree) {
                     if (ptree->l == tree) {
                        ptree->l = addr;
                        addr->p = ptree;
                     } else {
                        ptree->r = addr;
                        addr->p = ptree;
                     }
                  } else {
                     ArgusAddrTree[tree->addr.type] = addr;
                     addr->offset = 0;
                  }

                  if (value & 0x01) {
                     addr->p = tree->p;
                     addr->l = tree;
                     addr->r = node;
                     tree->p = addr;
                     node->p = addr;
                  } else {
                     addr->p = tree->p;
                     addr->l = node;
                     addr->r = tree;
                     tree->p = addr;
                     node->p = addr;
                  }
                  if (tree->ns)
                     addr->ns = ArgusCopyRecordStruct(tree->ns);
               }

               if (node->addr.masklen > 0)
                  node->addr.mask[0] = (0xFFFFFFFF << (32 - node->addr.masklen));

               node->addr.mask[0] &= node->addr.mask[0] & (0xFFFFFFFF >> node->offset);
               retn = node;
            }
            break;
         }

         case AF_INET6: {
            retn = node;
            break;
         }
      }

      if (retn != NULL)
         retn->status |= status;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "RaInsertAddress (0x%x, 0x%x, 0x%x, 0x%x) returning 0x%x\n", parser, ArgusAddrTree, node, status, retn);
#endif

   return (retn);
}

void RaDeleteAddressTree(struct RaAddressStruct *);
char *RaPruneAddressTree (struct ArgusLabelerStruct *, struct RaAddressStruct *);

void
RaDeleteAddressTree(struct RaAddressStruct *node)
{
   if (node->l) RaDeleteAddressTree(node->l);
   if (node->r) RaDeleteAddressTree(node->r);

   if (node->addr.str) { free(node->addr.str); node->addr.str = NULL;}
   if (node->str)   {free(node->str); node->str = NULL;}
   if (node->label) {free(node->label); node->label = NULL;}
   if (node->dns)   {free(node->dns); node->dns = NULL;}
   if (node->ns) {ArgusDeleteRecordStruct(ArgusParser, node->ns); node->ns = NULL;}

   ArgusFree(node);
}

char *
RaPruneAddressTree (struct ArgusLabelerStruct *labeler, struct RaAddressStruct *node)
{
   char *retn = NULL, *lstr = NULL, *rstr = NULL;

   if (node == NULL)
      return(NULL);

   if (node->l || node->r) {   // if we have sub-trees, grab the labels below.
      if ((lstr = RaPruneAddressTree(labeler, node->l)) != NULL) {
         if (node->addr.masklen != (node->l->addr.masklen - 1))
            lstr = NULL;
      }

      if ((rstr = RaPruneAddressTree(labeler, node->r)) != NULL) {
         if (node->addr.masklen != (node->r->addr.masklen - 1))
            rstr = NULL;
      }

      if (node->l && node->r) {
         if (lstr && rstr) {    // the idea here is to propagate up the label
                                // so that if they are equal, then we can trim
                                // the tree, by removing everything below.
            if (strlen(lstr) && strlen(rstr)) {
               if (!(strcmp(lstr, rstr))) {
                  retn = lstr;  // children are equal, so propagate up for comparison
               } 
            }
         }

      } else {
         if (node->l && lstr) 
            retn = lstr;
         
         if (node->r && rstr) 
            retn = rstr;
      }

      if (retn && strlen(retn)) {              // there is a child label, so compare to current
         if (node->label) {
            if ((strcmp(node->label, retn)))   // if sub-tree labels aren't equal to current
                                               // then nothing to propagate up .... return NULL
               retn = NULL;
         } else {
            node->label = strdup(retn);        // so children are equal and node is not labeled, label it
            retn = node->label;
         }
      }

   } else                                      // if there are no children, then give back current label
      retn = node->label;

   if (retn != NULL) {                         // at this point, we can prune the tree.
      if (node->l) {
         RaDeleteAddressTree(node->l);
         node->l = NULL;
      }
      if (node->r) {
         RaDeleteAddressTree(node->r);
         node->r = NULL;
      }
   }
   return (retn);
}


struct ArgusCIDRAddr *ArgusGetCIDRList (struct ArgusCIDRAddr *, int *, int);

struct ArgusCIDRAddr *
ArgusGetCIDRList (struct ArgusCIDRAddr *addr, int *elem, int type)
{
   struct ArgusCIDRAddr *retn = NULL;

   if (*elem > 0) {
      double bvalue, value, lbval, l2;
      bvalue = *elem * 1.0;
      lbval = log(bvalue);
      l2 = log(2.0);
      l2 = lbval/l2;
 
      if ((value = floor(l2)) > 0) {  // compare this as a mask.
         long long eval = pow (2.0, value);
         int len, i;

         for (i = value; i > 0; i--) {
            uint32_t mask = (0xFFFFFFFF << i);
            if ((addr->addr[0] & mask) == addr->addr[0])
               break;
         }

         {
            struct ArgusCIDRAddr *cidr = NULL;
 
            if (i == value) {
               if ((cidr = ArgusCalloc(1, sizeof(*cidr))) == NULL)
                  ArgusLog (LOG_ERR, "ArgusGetCIDRList: ArgusCalloc error %s\n", strerror(errno));
 
               bcopy(addr, cidr, sizeof(*cidr));
 
               cidr->masklen = (32 - i);
               cidr->mask[0] = 0xFFFFFFFF << i;
             
               addr->addr[0] += eval;
               *elem -= eval;
               retn = cidr;

            } else {
               eval = pow (2.0, i);
               len = eval;
               retn = ArgusGetCIDRList (addr, &len, type);
               *elem -= (eval - len);
            }
         }
      }
   }

   return(retn);
}

void
RaInsertRIRTree (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *str)
{
   struct RaAddressStruct *saddr = NULL, *node;
   char tstrbuf[MAXSTRLEN], *sptr = tstrbuf, *tptr;
   char *co = NULL, *type = NULL;
// char *rir = NULL;
   char *addr, *endptr = NULL;
   int tok = 0, elem = -1, ttype = 0;

   if (labeler != NULL) {
      struct RaAddressStruct **ArgusAddrTree = labeler->ArgusAddrTree;

      snprintf (tstrbuf, MAXSTRLEN, "%s", str);

      while ((tptr = strtok(sptr, "|\n")) != NULL) {
         switch (tok++) {
            case 0:               break;
//          case 0:  rir  = tptr; break;
            case 1:  co   = tptr; break;
            case 2:  type = tptr; break;
            case 3:  addr = tptr; break;
            case 4:
               if (isdigit((int)*tptr)) {
                  if ((elem = strtol(tptr, &endptr, 10)) == 0)
                     if (endptr == tptr)
                        usage();
               }

            case 5:  break;
            case 6:  break;
         }

         sptr = NULL;
      }

      if (!(strcmp("ipv4", type)))
         ttype = ARGUS_TYPE_IPV4;
      if (!(strcmp("ipv6", type)))
         ttype = ARGUS_TYPE_IPV6;

      if (ttype && (strcmp ("*", co))) {
         if ((co != NULL) && (addr != NULL)) {
            struct ArgusCIDRAddr *cidr = NULL, *ncidr;

            switch (ttype) {
               case ARGUS_TYPE_IPV4: 
               case ARGUS_TYPE_IPV6: {
                  if ((cidr = RaParseCIDRAddr (parser, addr)) != NULL) 
                     while ((ncidr = ArgusGetCIDRList (cidr, &elem, ttype)) != NULL) {
                        if ((saddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*saddr))) != NULL) {
                           bcopy ((char *)ncidr, (char *)&saddr->addr, sizeof (*ncidr));
                           if ((node = RaFindAddress (parser, ArgusAddrTree[saddr->addr.type], saddr, ARGUS_EXACT_MATCH)) == NULL) {
                              strncpy(saddr->cco, co, 4);
                              RaInsertAddress (parser, labeler, NULL, saddr, ARGUS_VISITED);

                           } else {
                              ArgusFree(saddr);
                              saddr = NULL;
                              strncpy(node->cco, co, 4);
                           }
                        }
                        ArgusFree(ncidr);
                     }
               }
            }
         }
      }
   }
}


#define ARGUS_PARSING_START_ADDRESS	0
#define ARGUS_PARSING_END_ADDRESS	1
#define ARGUS_PARSING_LABEL		2
#define ARGUS_PARSING_DONE		3

void
RaInsertAddressTree (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *str)
{
   struct RaAddressStruct *saddr = NULL, *node;
   struct ArgusCIDRAddr *cidr, scidr, dcidr;
   char *sptr = NULL, *eptr = NULL, *ptr = NULL;
   char tstrbuf[MAXSTRLEN], *tptr = NULL, *label = NULL;
   long long i, step = 0, arange;
   unsigned int masklen = 32;
   double mstep = 0;

   if (labeler != NULL) {
      struct RaAddressStruct **ArgusAddrTree = labeler->ArgusAddrTree;
      int state = ARGUS_PARSING_START_ADDRESS;

      snprintf (tstrbuf, MAXSTRLEN, "%s", str);
      ptr = tstrbuf;

      while ((sptr = strtok(ptr, " \t\n\"")) != NULL) {
         switch (state) {
            case ARGUS_PARSING_START_ADDRESS: {
               if ((eptr = strchr(sptr, '-')) != NULL)
                  *eptr++ = '\0';

               if (sptr && ((cidr = RaParseCIDRAddr (parser, sptr)) != NULL))
                  bcopy ((char *)cidr, (char *)&scidr, sizeof (*cidr));

               if (eptr && ((cidr = RaParseCIDRAddr (parser, eptr)) != NULL))
                  bcopy ((char *)cidr, (char *)&dcidr, sizeof (*cidr));
               else
                  bcopy ((char *)&scidr, (char *)&dcidr, sizeof (scidr));

               state = ARGUS_PARSING_LABEL;
               break;
            }

            case ARGUS_PARSING_END_ADDRESS: {
               if (sptr && ((cidr = RaParseCIDRAddr (parser, sptr)) != NULL))
                  bcopy ((char *)cidr, (char *)&dcidr, sizeof (*cidr));
               state = ARGUS_PARSING_LABEL;
               break;
            }

            case ARGUS_PARSING_LABEL: {
               if (*sptr == '-')
                  state = ARGUS_PARSING_END_ADDRESS;
               else {
                  label = sptr;
                  state = ARGUS_PARSING_DONE;
               }
               break;
            }

            case ARGUS_PARSING_DONE:
               break;
         }
         ptr = NULL;
      }

//  OK, so we've got the range of addresses to load up into the tree.      
//  Lets figure out a good starting point for the netmask.

      {
         int slen = 0, len = dcidr.addr[0] - scidr.addr[0];

         if (len > 0) {
            while ((len / 2) >= 2) {
               slen++;
               len = len >> 1;
            }

            while (slen && ((scidr.addr[0] & (0xFFFFFFFF << slen)) != scidr.addr[0]))
               slen--;

            masklen = 32 - slen;
         }
      }

      if (masklen < scidr.masklen) {
         scidr.masklen = masklen;
         scidr.mask[0] = 0xFFFFFFFF << (32 - masklen);
         
      }

      for (i = scidr.addr[0]; i <= dcidr.addr[0]; i += step) {
         struct RaAddressStruct *paddr = saddr;

         if ((saddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*saddr))) != NULL) {
            unsigned int taddr;

            if (paddr != NULL) {
               bcopy ((char *)&paddr->addr, (char *)&saddr->addr, sizeof (*cidr));
               saddr->addr.addr[0] = i;

               do {
                  arange  = dcidr.addr[0] - saddr->addr.addr[0];
                  arange -= (0xFFFFFFFF >> saddr->addr.masklen);

                  if (arange < 0) {
                     if (saddr->addr.masklen < dcidr.masklen)
                        saddr->addr.masklen++;
                     else {
                        arange = (dcidr.addr[0] - saddr->addr.addr[0]);
                        break;
                     }
                  }
               } while (arange < 0);

               taddr = saddr->addr.addr[0] + ((0xFFFFFFFF >> saddr->addr.masklen) + 1);
 
               if (taddr != (taddr & (0xFFFFFFFF << (32 - (saddr->addr.masklen - 1))))) {
                  int carry = dcidr.addr[0] - (saddr->addr.addr[0] + (0xFFFFFFFF >> (saddr->addr.masklen - 1)));
                  if ((carry > 0) && (arange >= carry)) {
                     saddr->addr.masklen--;
                     saddr->addr.mask[0] = 0xFFFFFFFF << (32 - saddr->addr.masklen);
                     saddr->addr.addr[0] &= saddr->addr.mask[0];
                  } else {
                     if (arange == 1) {
                     }
                  }
               }

            } else {
               bcopy ((char *)&scidr, (char *)&saddr->addr, sizeof (*cidr));
               saddr->addr.addr[0] = i;
            }

            if ((node = RaFindAddress (parser, ArgusAddrTree[saddr->addr.type], saddr, ARGUS_EXACT_MATCH)) == NULL) {
               if (tptr)
                  saddr->addr.str = strdup(tptr);

               RaInsertAddress (parser, labeler, NULL, saddr, ARGUS_VISITED);
               
               if (label) {
                  if (saddr->label != NULL) {
                     char sbuf[1024];
                     snprintf(sbuf, 1024, "%s,", saddr->label);
#if HAVE_STRLCAT
                     strlcat(sbuf, label, 1024 - strlen(sbuf));
#else
                     strncat(sbuf, label, 1024 - strlen(sbuf));
#endif
                     free(saddr->label);
                     saddr->label = strdup(sbuf);
                  } else
                     saddr->label = strdup (label);
               }

               if (labeler->status & ARGUS_TREE_DEBUG_NODE) {
                  RaPrintLabelTree (labeler, labeler->ArgusAddrTree[AF_INET], 0, 0);
                  printf("\n");
               }


            } else {
               ArgusFree(saddr);
               saddr = node;

               if (label) {
                  if (node->label != NULL) {
                     char sbuf[1024];
                     snprintf(sbuf, 1024, "%s,", node->label);
#if HAVE_STRLCAT
                     strlcat(sbuf, label, 1024 - strlen(sbuf));
#else
                     strncat(sbuf, label, 1024 - strlen(sbuf));
#endif
                     free(node->label);
                     node->label = strdup(sbuf);
                  } else
                     node->label = strdup (label);
               }
            }
         }

         mstep = pow (2.0, (32 - saddr->addr.masklen));
         step = mstep;
      }
   }
}


int RaReadAddressConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

int
RaReadAddressConfig (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *file)
{
   char strbuf[MAXSTRLEN], *str = strbuf, *ptr;
   int retn = 1, linenum = 0;
   FILE *fd =  NULL;

   if (labeler != NULL) {
      if (labeler->ArgusAddrTree == NULL)
         if ((labeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog (LOG_ERR, "RaReadAddressConfig: ArgusCalloc error %s\n", strerror(errno));

      if ((fd = fopen (file, "r")) != NULL) {
         while ((ptr = fgets (str, MAXSTRLEN, fd)) != NULL) {
            linenum++;
            while (isspace((int)*ptr)) ptr++;
            switch (*ptr) {
               case '#': {
                  if (!strncmp((char *)&ptr[1], "include ", 8)) {
                     char *sptr;
                     if ((sptr = strtok(&ptr[9], " \t\n")) != NULL)
                        RaReadAddressConfig (parser, labeler, sptr);
                  }
                  break;
               }

               default:
                  if (isdigit((int)*ptr)) {
                     RaInsertAddressTree (parser, labeler, ptr);
                  } else {
                     if (strchr(ptr, '|')) {
                        RaInsertRIRTree (parser, labeler, ptr);
                     }
                  }
                  break;
            }
         }

         fclose(fd);

      } else
         ArgusLog (LOG_ERR, "%s: %s", file, strerror(errno));

      if (labeler->prune) 
         RaPruneAddressTree(labeler, labeler->ArgusAddrTree[AF_INET]);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaReadAddressConfig (0x%x, 0x%x, %s) returning %d\n", parser, labeler, file, retn);
#endif

   return (retn);
}

struct enamemem elabeltable[HASHNAMESIZE];
extern struct enamemem *lookup_emem(struct enamemem *, const unsigned char *);

int
RaReadIeeeAddressConfig (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *file)
{
   int retn = 1;
   struct enamemem *tp;
   struct argus_etherent *ep;
   FILE *fp;

   /* Suck in entire ethers file */
   fp = fopen(PCAP_ETHERS_FILE, "r");
   if (fp != NULL) {
      while ((ep = argus_next_etherent(fp)) != NULL) {
         tp = lookup_emem(elabeltable, ep->addr);
         tp->e_name = savestr(ep->name);
      }
      (void)fclose(fp);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaReadIeeeAddressConfig (0x%x, 0x%x, %s) returning %d\n", parser, labeler, file, retn);
#endif

   return (retn);
}



struct RaPortStruct *RaParsePortEntry (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
int RaReadPortConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);


struct RaPortStruct ArgusPortBuf;

/*
dbbrowse        47557/tcp  Databeam Corporation
*/

struct RaPortStruct *
RaParsePortEntry (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *str)
{
   struct RaPortStruct *retn = NULL;
   char *strend, *label = NULL, *port = NULL;
   char *proto = NULL, *desc = NULL, *ptr, *tmp;
   int error = 0, len = 0;

   len = strlen(str);
   strend = str + len;

   ptr = str;
   while  (!isspace(*ptr)) ptr++;
   *ptr++ = '\0';
   label = str;
   while  (isspace(*ptr)) ptr++;
   port = ptr;
   if ((proto = strchr (port, '/')) != NULL) {
      *proto++ = '\0';
      ptr = proto;
      while  (!isspace(*ptr)) ptr++;
      *ptr++ = '\0';
   }

   if (ptr < strend) {
      while (isspace(*ptr)) ptr++;
      desc = ptr;
      tmp = NULL;
      while (*ptr != '\n') {
         if (isspace(*ptr)) {
            if (tmp == NULL)
               tmp = ptr;
         } else
            tmp = NULL;
         ptr++;
      }
      if (tmp != NULL)
         *tmp = '\0';
      else
         *ptr = '\0';
   }

   if ((port == NULL) || (proto == NULL)) {
   } else {
      char *endptr;

      retn = &ArgusPortBuf;
      retn->proto = (strcmp (proto, "tcp")) ? 17 : 6;

      if (label != NULL)
         retn->label = label;
      if (desc != NULL)
         retn->desc = desc;

      retn->start = strtol(port, &endptr, 10);
      if ((endptr != NULL) && (endptr == port)) {
         error++;
      } else {
         if ((ptr = strchr(port, '-')) != NULL) {
            retn->end   = strtol(ptr + 1, &endptr, 10);
            if ((endptr != NULL) && (endptr == port))
               error++;
         } else {
            retn->end   = retn->start;
         }
      }
   }

   return(retn);
}

int
RaReadPortConfig (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *file)
{
   struct RaPortStruct *tp, *port, **array;
   int retn = 0, lines = 0;
   char buf[MAXSTRLEN], *str = buf;
   FILE *fd;

   if (file) {
      if ((fd = fopen (file, "r")) != NULL) {
         while ((fgets(str, MAXSTRLEN, fd)) != NULL)  {
            lines++;
            if (*str && (*str != '#') && (*str != '\n') && (*str != '!')) {
               if (strstr (str, "/udp") || strstr (str, "/tcp") || strstr (str, "/ddp")) {
                  if ((tp = RaParsePortEntry (parser, labeler, str)) != NULL) {
                     if ((port = ArgusCalloc(1, sizeof(*port))) == NULL)
                        ArgusLog (LOG_ERR, "RaReadPortConfig: ArgusCalloc error %s", strerror(errno));

                     bcopy ((char *)tp, (char *)port, sizeof(*tp));
                     if (tp->label != NULL)
                        port->label = strdup(tp->label);
                     if (tp->desc != NULL)
                        port->desc = strdup(tp->desc);

                     switch (port->proto) {
                        case IPPROTO_TCP: {
                           if ((array = labeler->ArgusTCPPortLabels) == NULL) {
                              if ((array = (void *) ArgusCalloc(1, 0x10000 * sizeof(port))) == NULL)
                                 ArgusLog (LOG_ERR, "RaReadPortConfig: ArgusCalloc error %s", strerror(errno));
                              labeler->ArgusTCPPortLabels = array;
                           }
                           break;
                        }

                        case IPPROTO_UDP: {
                           if ((array = labeler->ArgusUDPPortLabels) == NULL) {
                              if ((array = (void *) ArgusCalloc(1, 0x10000 * sizeof(port))) == NULL)
                                 ArgusLog (LOG_ERR, "RaReadPortConfig: ArgusCalloc error %s", strerror(errno));
                              labeler->ArgusUDPPortLabels = array;
                           }
                           break;
                        }
                     }

                     if (array != NULL) {
                        int i;
                        for (i = port->start; i <= port->end; i++) {
/* so if there is already a port descriptor here, we'll add this label
   to any existing label, but replace the existing tp with the newly
   allocated port */
                           if ((tp = array[i]) != NULL) {
                              int found = 0;
                              char *plabel = port->label;

                              if (plabel && strlen(plabel)) {
                                 char *tlabel = tp->label;
                                 if (strlen(tlabel)) {
                                    char tbuf[MAXSTRLEN], *tok, *tptr = tbuf;
                                    snprintf (tbuf, MAXSTRLEN, "%s", tlabel);
                                    while (!found && ((tok = strtok (tptr, ":")) != NULL)) {
                                       if (!strcmp(tok, plabel))
                                          found++;
                                       tptr = NULL;
                                    }

                                    free(port->label);

                                    if (!found) {
                                       snprintf (tbuf, MAXSTRLEN, "%s", tlabel);
                                       sprintf(&tbuf[strlen(tbuf)], ":%s", plabel);
                                       port->label = strdup(tbuf);
                                    } else
                                       port->label = strdup(tlabel);
                                 }
                              }
                              if (tp->label != NULL)
                                 free (tp->label);
                              if (tp->desc != NULL)
                                 free (tp->desc);
                              ArgusFree (tp);
                           }
                           array[i] = port;
                        }
                     }

                  } else  {
                     ArgusLog (LOG_ERR, "RaReadPortConfig: syntax error line %d", lines);
                  }
               }
            }
         }

         fclose(fd);

      } else 
         ArgusLog (LOG_ERR, "RaReadPortConfig: fopen error %s", strerror(errno));
   }
   return (retn);
}


struct ArgusLabelerStruct *
ArgusNewLabeler (struct ArgusParserStruct *parser, int status)
{
   struct ArgusLabelerStruct *retn = NULL;

   if ((retn = (struct ArgusLabelerStruct *) ArgusCalloc (1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewLabeler: ArgusCalloc error %s", strerror(errno));

   if ((retn->drap = (struct RaPolicyStruct *) ArgusCalloc(1, sizeof(*retn->drap))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewLabeler: ArgusCalloc error %s", strerror(errno));

   if ((retn->queue = ArgusNewQueue()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewLabeler: ArgusNewQueue error %s", strerror(errno));

   if ((retn->htable.array = (struct ArgusHashTableHdr **) ArgusCalloc (RA_HASHTABLESIZE, sizeof(void *))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewLabeler: ArgusCalloc error %s", strerror(errno));

   retn->htable.size = RA_HASHTABLESIZE;

   retn->status = status;

   retn->RaPrintLabelTreeMode = ARGUS_TREE;

   if (status & ARGUS_LABELER_COCODE) {
      if (parser->ArgusDelegatedIPFile) {
         if (!(RaReadAddressConfig (parser, retn, parser->ArgusDelegatedIPFile) > 0))
            ArgusLog (LOG_ERR, "ArgusNewLabeler: RaReadAddressConfig error");
      }
   }

   if (status & ARGUS_LABELER_ADDRESS) {
      if (parser->ArgusFlowModelFile) {
         if (!(RaReadAddressConfig (parser, retn, parser->ArgusFlowModelFile) > 0))
            ArgusLog (LOG_ERR, "ArgusNewLabeler: RaReadAddressConfig error");
      }
   }

   retn->prune = 1;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusNewLabeler (%p, %d) returning %p\n", parser, status, retn);
#endif
   return (retn);
}

void
ArgusDeleteLabeler (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler)
{
   if (labeler != NULL) {
      struct RaAddressStruct **ArgusAddrTree;

      if (labeler->drap !=  NULL)
         ArgusFree (labeler->drap);

      if (labeler->queue !=  NULL)
         ArgusDeleteQueue (labeler->queue);

      ArgusEmptyHashTable (&labeler->htable);

      if (labeler->htable.array != NULL)
         ArgusFree(labeler->htable.array);

      if ((ArgusAddrTree = labeler->ArgusAddrTree) != NULL) {
         if (labeler->ArgusAddrTree[AF_INET] != NULL)
            RaDeleteAddressTree (labeler->ArgusAddrTree[AF_INET]);

         ArgusFree(ArgusAddrTree);
      }

      ArgusFree(labeler);
   }
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusDeleteLabeler (%p, %p) returning\n", parser, labeler);
#endif
}


struct RaSrvSignature *RaCreateSrvEntry(struct ArgusLabelerStruct *, int, char *);

struct RaSrvSignature *
RaCreateSrvEntry(struct ArgusLabelerStruct *labeler, int linenum, char *str)
{
   struct RaSrvSignature *srv = NULL;
   char *ptr = NULL, *tmp, *dup;

   dup = strdup(str);

   if ((ptr = strstr (dup, "Service: ")) != NULL) {
      if ((srv = (void *) ArgusCalloc(1, sizeof(*srv))) != NULL) {
         ptr += strlen("Service: ");
         tmp = ptr;
         while (!isspace((int)*ptr)) ptr++;
         *ptr++ = '\0';
         srv->name = strdup(tmp);
         tmp = ptr;

         if ((tmp = strstr(ptr, "tcp port ")) != NULL) {
            tmp += strlen("tcp port ");
            srv->proto = IPPROTO_TCP;
            srv->port  = atoi(tmp);
         } else {
            if ((tmp = strstr(ptr, "udp port ")) != NULL) {
               tmp += strlen("udp port ");
               srv->proto = IPPROTO_UDP;
               srv->port  = atoi(tmp);
            }
         }

         if ((tmp = strstr(ptr, "n =")) != NULL) {
            tmp += strlen("n =") + 1;
            srv->count = atoi(tmp);
         }

         if (((tmp = strstr(ptr, "src = ")) == NULL) &&
             ((tmp = strstr(ptr, "dst = ")) == NULL)) {
            if ((tmp = strchr(ptr, '\"')) != NULL) {
               char nbuf[4], *nptr = nbuf, *ptmp, *endptr;
               int value, i, length;

               tmp++;
               if ((ptmp = strchr(tmp, '\"')) == NULL)
                  ArgusLog (LOG_ERR, "RaCreateSrvEntry: format error %s\n", ptr);

               *ptmp++ = '\0';

               length = ((strlen(tmp) > (RASIGLENGTH * 2)) ? RASIGLENGTH : strlen(tmp))/2;
               for (i = 0; i < length; i++) {
                  endptr = NULL;
                  bzero (nbuf, 4);
                  nbuf[0] = *tmp++;
                  nbuf[1] = *tmp++;
                  if (nbuf[0] == ' ') {
                     ((u_char *)&srv->srcmask)[i/8] |= (0x80 >> (i % 8));
                     value = 0;
                  } else {
                     value = strtol(nptr, &endptr, 16);
                     if ((endptr != NULL) && (endptr != (nptr + 2)))
                        ArgusLog (LOG_ERR, "RaCreateSrvEntry: format error %s\n", ptr);
                  }
                  srv->src[i] = (u_char) value;
               }

               for ( ; i < RASIGLENGTH; i++) {
                  ((u_char *)&srv->srcmask)[i/8] |= (0x80 >> (i % 8));
               }
               tmp++;
            }

            if ((tmp = strchr(tmp, '\"')) != NULL) {
               char nbuf[4], *nptr = nbuf, *ptmp, *endptr;
               int value, i, length;

               tmp++;
               if ((ptmp = strchr(tmp, '\"')) == NULL)
                  ArgusLog (LOG_ERR, "RaCreateSrvEntry: format error %s\n", ptr);
               else
                  *ptmp = '\0';
               
               length = ((strlen(tmp) > (RASIGLENGTH * 2)) ? RASIGLENGTH : strlen(tmp))/2;
               for (i = 0; i < length; i++) {
                  endptr = NULL;
                  bzero (nbuf, 4);
                  nbuf[0] = *tmp++;
                  nbuf[1] = *tmp++;
                  if (nbuf[0] == ' ') {
                     ((u_char *)&srv->dstmask)[i/8] |= (0x80 >> (i % 8));
                     value = 0;
                  } else {
                     value = strtol(nptr, &endptr, 16);
                     if ((endptr != NULL) && (endptr != (nptr + 2)))
                        ArgusLog (LOG_ERR, "RaCreateSrvEntry: format error %s\n", ptr);
                  }
                  srv->dst[i] = (u_char) value;
               }

               for ( ; i < RASIGLENGTH; i++) {
                  ((u_char *)&srv->dstmask)[i/8] |= (0x80 >> (i % 8));
               }
            } else {
               srv->srcmask = 0xFFFFFFFF;
               srv->dstmask = 0xFFFFFFFF;
            }

         } else {
            if ((tmp = strstr(ptr, "src = ")) != NULL) {
               tmp += strlen("src = ");

               if ((tmp = strchr(tmp, '\"')) != NULL) {
                  char nbuf[4], *nptr = nbuf, *ptmp, *endptr;
                  int value, i, length;

                  tmp++;
                  if ((ptmp = strchr(tmp, '\"')) == NULL)
                     ArgusLog (LOG_ERR, "RaCreateSrvEntry: format error %s\n", ptr);

                  *ptmp++ = '\0';
                  ptr = ptmp;

                  length = ((strlen(tmp) > (RASIGLENGTH * 2)) ? RASIGLENGTH : strlen(tmp))/2;
                  for (i = 0; i < length; i++) {
                     endptr = NULL;
                     bzero (nbuf, 4);
                     nbuf[0] = *tmp++;
                     nbuf[1] = *tmp++;
                     if (nbuf[0] == ' ') {
                        ((u_char *)&srv->srcmask)[i/8] |= (0x80 >> (i % 8));
                        value = 0;
                     } else {
                        value = strtol(nptr, &endptr, 16);
                        if ((endptr != NULL) && (endptr != (nptr + 2)))
                           ArgusLog (LOG_ERR, "RaCreateSrvEntry: format error %s\n", dup);
                     }
                     srv->src[i] = (u_char) value;
                  }

                  for ( ; i < RASIGLENGTH; i++) {
                     ((u_char *)&srv->srcmask)[i/8] |= (0x80 >> (i % 8));
                  }
                  tmp++;
               }
            } else
               srv->srcmask = 0xFFFFFFFF;

            if ((tmp = strstr(ptr, "dst = ")) != NULL) {
               tmp += strlen("dst = ");
 
               if ((tmp = strchr(ptr, '\"')) != NULL) {
                  char nbuf[4], *nptr = nbuf, *ptmp, *endptr;
                  int value, i, length;
                
                  tmp++;
                  if ((ptmp = strchr(tmp, '\"')) == NULL)
                     ArgusLog (LOG_ERR, "RaCreateSrvEntry: format error %s\n", ptr);
    
                  *ptmp++ = '\0';
                  ptr = ptmp;
    
                  length = ((strlen(tmp) > (RASIGLENGTH * 2)) ? RASIGLENGTH : strlen(tmp))/2;
                  for (i = 0; i < length; i++) {
                     endptr = NULL;
                     bzero (nbuf, 4);
                     nbuf[0] = *tmp++;
                     nbuf[1] = *tmp++;
                     if (nbuf[0] == ' ') {
                        ((u_char *)&srv->dstmask)[i/8] |= (0x80 >> (i % 8));
                        value = 0;
                     } else {
                        value = strtol(nptr, &endptr, 16);
                        if ((endptr != NULL) && (endptr != (nptr + 2)))
                           ArgusLog (LOG_ERR, "RaCreateSrvEntry: format error %s\n", ptr);
                     }
                     srv->dst[i] = (u_char) value;
                  }
 
                  for ( ; i < RASIGLENGTH; i++) {
                     ((u_char *)&srv->dstmask)[i/8] |= (0x80 >> (i % 8));
                  }
                  tmp++;
               }
            } else
               srv->dstmask = 0xFFFFFFFF;
         }

         if ((tmp = strstr(ptr, "encrypted")) != NULL) {
            tmp += strlen("encrypted") + 1;
            srv->status = RA_SVC_WILDCARD;
         }
         
         ArgusAddToQueue (labeler->queue, &srv->qhdr, ARGUS_LOCK);
      }
   }

   free(dup);
   return(srv);
}



int RaTallySrvTree (struct RaSrvTreeNode *);
void RaPrintSrvTree (struct ArgusLabelerStruct *, struct RaSrvTreeNode *, int, int);


int
RaTallySrvTree (struct RaSrvTreeNode *node)
{
   int retn = 0;

   if (node != NULL) {
      retn += RaTallySrvTree(node->r);
      retn += RaTallySrvTree(node->l);
      retn += node->srv->count;
   }

   return (retn);
}


void
RaPrintSrvTree (struct ArgusLabelerStruct *labeler, struct RaSrvTreeNode *node, int level, int dir)
{
   int i = 0, length, len, olen = strlen(RaSrvTreeArray);
   char str[MAXSTRLEN], chr = ' ';

   bzero(str, MAXSTRLEN);

   if (node != NULL) {
      if (dir == RA_SRV_LEFT) {
         strncat (str, "   |", (MAXSTRLEN - strlen(str)));
         strncat (RaSrvTreeArray, str, (MAXSTRLEN - olen));
         printf ("%s\n", RaSrvTreeArray);
      }

      length = strlen(RaSrvTreeArray);
      if ((len = length) > 0) {
         chr = RaSrvTreeArray[len - 1];
         if (node->r != NULL) {
            if (dir == RA_SRV_RIGHT)
               RaSrvTreeArray[len - 1] = ' ';
         }
      }

      strncat (RaSrvTreeArray, "   |", (MAXSTRLEN - strlen(RaSrvTreeArray)));

      RaPrintSrvTree(labeler, node->r, level + 1, RA_SRV_RIGHT);

      for (i = length, len = strlen(RaSrvTreeArray); i < len; i++)
         RaSrvTreeArray[i] = '\0';

      if ((len = length) > 0)
         RaSrvTreeArray[len - 1] = chr;
      
      printf ("%s+", RaSrvTreeArray);
      printf ("%s %s port %d  n = %d\n", node->srv->name,
                       (node->srv->proto == IPPROTO_TCP) ? "tcp" : "udp",
                        node->srv->port, node->srv->count);

      len = strlen(RaSrvTreeArray);
      if (len > 0) {
         chr = RaSrvTreeArray[len - 1];
         if (node->l != NULL) {
            if (dir == RA_SRV_LEFT)
               RaSrvTreeArray[len - 1] = ' ';
         }
      }

      RaPrintSrvTree(labeler, node->l, level + 1, RA_SRV_LEFT);

      if (dir == RA_SRV_RIGHT) {
         printf ("%s", RaSrvTreeArray);
         putchar ('\n');
      }

      for (i = olen, len = strlen(RaSrvTreeArray); i < len; i++)
         RaSrvTreeArray[i] = '\0';
   }
}


int
RaGenerateBinaryTrees(struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler)
{
   struct ArgusQueueStruct *queue = labeler->queue;
   struct RaSrvSignature *srv;
   int retn = 1;

   if (ArgusSorter) {
      ArgusSorter->ArgusSortAlgorithms[0] = ArgusSortSrvSignatures;
      ArgusSorter->ArgusSortAlgorithms[1] = NULL;
      ArgusSortQueue (ArgusSorter, queue);
   }

   while ((srv = (struct RaSrvSignature *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
      if (srv->srcmask != 0xFFFFFFFF)
         RaAddToSrvTree (srv, RA_SRC_SERVICES);

      if (srv->dstmask != 0xFFFFFFFF)
         RaAddToSrvTree (srv, RA_DST_SERVICES);
   }

#ifdef ARGUSDEBUG
   if (ARGUS_DEBUG_SERVICES & parser->dflag) {
      int i;

      printf ("\nTCP Src Services Tree:\n");
      for (i = 0; i < RASIGLENGTH; i++) {
         if (RaSrcTCPServicesTree[i] != NULL) {
            printf ("  signature length %d\n", i);
            bzero (RaSrvTreeArray, MAXSTRLEN);
            RaPrintSrvTree (labeler, RaSrcTCPServicesTree[i], 0, RA_SRV_ROOT);
            fflush (stdout);
         }
      }

      printf ("\nTCP Dst Services Tree:\n");
      for (i = 0; i < RASIGLENGTH; i++) {
         if (RaDstTCPServicesTree[i] != NULL) {
            printf ("  signature length %d\n", i);
            bzero (RaSrvTreeArray, MAXSTRLEN);
            RaPrintSrvTree (labeler, RaDstTCPServicesTree[i], 0, RA_SRV_ROOT);
            fflush (stdout);
         }
      }

      printf ("\nUDP Src Services Tree:\n");
      for (i = 0; i < RASIGLENGTH; i++) {
         if (RaSrcUDPServicesTree[i] != NULL) {
            printf ("  signature length %d\n", i);
            bzero (RaSrvTreeArray, MAXSTRLEN);
            RaPrintSrvTree (labeler, RaSrcUDPServicesTree[i], 0, RA_SRV_ROOT);
            fflush (stdout);
         }
      }
 
      printf ("\nUDP Dst Services Tree:\n");
      for (i = 0; i < RASIGLENGTH; i++) {
         if (RaDstUDPServicesTree[i] != NULL) {
            printf ("  signature length %d\n", i);
            bzero (RaSrvTreeArray, MAXSTRLEN);
            RaPrintSrvTree (labeler, RaDstUDPServicesTree[i], 0, RA_SRV_ROOT);
            fflush (stdout);
         }
      }

      ArgusShutDown(0);
      exit(0);
   }
#endif

   return (retn);
}

struct RaSrvTreeNode *RaTCPSrcArray[0x10000], *RaTCPDstArray[0x10000];
struct RaSrvTreeNode *RaUDPSrcArray[0x10000], *RaUDPDstArray[0x10000];
int RaAddToArray(struct RaSrvTreeNode **, struct RaSrvSignature *, int);

int
RaAddToArray(struct RaSrvTreeNode *array[], struct RaSrvSignature *srv, int mode)
{
   int retn = 1;
   struct RaSrvTreeNode *tree;

   if ((tree = array[srv->port]) == NULL) {
      if ((tree = (struct RaSrvTreeNode *) ArgusCalloc (1, sizeof(*tree))) != NULL) {
         tree->srv = srv;
         array[srv->port] = tree;
      } else
         ArgusLog (LOG_ERR, "ArgusCalloc error %s\n", strerror(errno));

   } else {
      if ((srv->srcmask == 0xFFFFFFFF) && (srv->dstmask == 0xFFFFFFFF)) {
         tree->srv = srv;
      } else {
         RaAddSrvTreeNode(tree, srv, 0, mode);
      }
   }

   return (retn);
}



int
RaReadSrvSignature(struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *file)
{
   int retn = 0;
   struct RaSrvSignature *srv = NULL;
   char strbuf[MAXSTRLEN], *str = strbuf, **model = NULL;
   int i = 0, RaSigLineNumber = 0;
   FILE *fd;

   bzero ((char *) RaTCPSrcArray, sizeof(RaTCPSrcArray));
   bzero ((char *) RaTCPDstArray, sizeof(RaTCPDstArray));
   bzero ((char *) RaUDPSrcArray, sizeof(RaUDPSrcArray));
   bzero ((char *) RaUDPDstArray, sizeof(RaUDPDstArray));

   if (model == NULL) {
      bzero ((char *) sigbuf, sizeof(sigbuf));
      if ((fd = fopen (file, "r")) != NULL) {
         while ((str = fgets (str, MAXSTRLEN, fd)) != NULL)
            sigbuf[i++] = strdup(str);

         model = sigbuf;
         fclose(fd);

      } else
         ArgusLog (LOG_ERR, "%s: %s", file, strerror(errno));
   }

   while ((str = *model++) != NULL) {
      RaSigLineNumber++;

      while (isspace((int)*str))
         str++;
      if (strlen(str)) {
         switch (*str) {
            case '#':
            case '\n':
            case '!':
               break;

            default: {
               if ((srv = RaCreateSrvEntry(labeler, RaSigLineNumber, str)) != NULL) {
                  RaSigLineNumber++;
                  switch (srv->proto) {
                     case IPPROTO_TCP:
                        if (srv->srcmask != 0xFFFFFFFF)
                           RaAddToArray(RaTCPSrcArray, srv, RA_SRC_SERVICES);
                        if (srv->dstmask != 0xFFFFFFFF)
                           RaAddToArray(RaTCPDstArray, srv, RA_DST_SERVICES);
                        break;

                     case IPPROTO_UDP:
                        if (srv->srcmask != 0xFFFFFFFF)
                           RaAddToArray(RaUDPSrcArray, srv, RA_SRC_SERVICES);
                        if (srv->dstmask != 0xFFFFFFFF)
                           RaAddToArray(RaUDPDstArray, srv, RA_DST_SERVICES);
                        break;
                  }
               }

               break;
            }
         }
      }
   }

   if (RaSigLineNumber > 0)
      retn = RaGenerateBinaryTrees(parser, labeler);

   return (retn);
}


void
RaAddSrvTreeNode(struct RaSrvTreeNode *node, struct RaSrvSignature *srv, int ind, int mode)
{
   struct RaSrvTreeNode *tree = NULL;
   u_char *sbuf = NULL, *tbuf = NULL;
   unsigned int mask;
   int i = 0;

   switch (mode) {
      case RA_SRC_SERVICES:
         mask = node->srv->srcmask;
         sbuf  = node->srv->src;
         tbuf  = srv->src;
         break;

      case RA_DST_SERVICES:
         mask = node->srv->dstmask;
         sbuf  = node->srv->dst;
         tbuf  = srv->dst;
         break;
 
      default:
         return;
   }

   if (mask != 0xFFFFFFFF) {
      for (i = ind; i < RASIGLENGTH; i++)
         if ((!(((u_char *)&mask)[i/8] & (0x80 >> (i % 8)))) && (sbuf[i] != tbuf[i]))
            break;
       
      if (i != RASIGLENGTH) {
         if (tbuf[i] > sbuf[i]) {
            if (node->r != NULL) {
               RaAddSrvTreeNode(node->r, srv, ind, mode);
            } else {
               if ((tree = (struct RaSrvTreeNode *) ArgusCalloc (1, sizeof(*tree))) != NULL) {
                  tree->srv = srv;
                  node->r = tree;
               }
            }
 
         } else {
            if (node->l != NULL) {
               RaAddSrvTreeNode(node->l, srv, ind, mode);
            } else {
               if ((tree = (struct RaSrvTreeNode *) ArgusCalloc (1, sizeof(*tree))) != NULL) {
                  tree->srv = srv;
                  node->l = tree;
               }
            }
         }
      }
   }
}


void
RaAddToSrvTree (struct RaSrvSignature *srv, int mode)
{
   struct RaSrvTreeNode *tree = NULL;
   struct RaSrvTreeNode **RaServicesTree = NULL;
   unsigned int mask;
   int i = 0;

   switch (mode) {
      case RA_SRC_SERVICES:
         mask = srv->srcmask;
         switch (srv->proto) {
            case IPPROTO_TCP: RaServicesTree = RaSrcTCPServicesTree; break;
            case IPPROTO_UDP: RaServicesTree = RaSrcUDPServicesTree; break;
         }
         break;
 
      case RA_DST_SERVICES:
         mask = srv->dstmask;
         switch (srv->proto) {
            case IPPROTO_TCP: RaServicesTree = RaDstTCPServicesTree; break;
            case IPPROTO_UDP: RaServicesTree = RaDstUDPServicesTree; break;
         }
         break;
   }


   for (i = 0; i < RASIGLENGTH; i++)
      if (!(((u_char *)&mask)[i/8] & (0x80 >> (i % 8))))
         break;
 
   if (i < RASIGLENGTH) {
      if (RaServicesTree[i] != NULL)
         RaAddSrvTreeNode(RaServicesTree[i], srv, i, mode);
      else {
         if ((tree = (struct RaSrvTreeNode *) ArgusCalloc (1, sizeof(*tree))) != NULL) {
            tree->srv = srv;
            RaServicesTree[i] = tree;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (ARGUS_DEBUG_POLICY, "RaAddToSrvTree (0x%x) returning\n", srv);
#endif
}


struct RaSrvSignature *
RaFindSrv (struct RaSrvTreeNode *node, u_char *ptr, int len, int mode)
{
   int i, nomatch = 0, guess = 0, wildcard = 0;
   struct RaSrvSignature *retn = NULL;
   unsigned int mask;
   u_char *buf = NULL;

   if ((node != NULL)  && (ptr != NULL)) {
      if (node->srv->status & RA_SVC_WILDCARD)
         wildcard++;

      switch (mode) {
         case RA_SRC_SERVICES:
            mask = node->srv->srcmask;
            buf  = node->srv->src;
            break;
         case RA_DST_SERVICES:
            mask = node->srv->dstmask;
            buf  = node->srv->dst;
            break;

         default:
            return (retn);
      }

      if (buf && (mask != 0xFFFFFFFF)) {
         retn = node->srv;

         for (i = 0; i < RASIGLENGTH; i++) {
            if (!(((u_char *)&mask)[i/8] & (0x80 >> (i % 8)))) {
               if (buf[i] != ptr[i]) {
                  if (!(isalpha(buf[i]) && 
                      ((isupper(buf[i]) ? (tolower(buf[i]) == ptr[i]) :
                                          (toupper(buf[i]) == ptr[i]))))) {
                     nomatch++;
                     if (buf[i] > ptr[i]) 
                        retn = RaFindSrv (node->l, ptr, len, mode);
                     else
                        retn = RaFindSrv (node->r, ptr, len, mode);
                     break;

                  } else {
                     guess++;
                  }
               } else {
                  guess++;
               }
            } else
               guess++;
         }

         for (; i < RASIGLENGTH; i++) {
            if (!(((u_char *)&mask)[i/8] & (0x80 >> (i % 8)))) {
               if (buf[i] == ptr[i])
                  guess++;
            } else
               guess++;
         }

         if (nomatch) {
            if (guess > RaBestGuessScore) {
               RaBestGuessScore = guess;
               RaBestGuess = node->srv;
            }
         }
      }

      if (wildcard)
         retn = node->srv;
   }

   return (retn);
}

int
RaFindService(struct ArgusRecordStruct *argus)
{
   int retn = 0;
   struct RaSrvTreeNode **array = NULL;
   struct RaSrvTreeNode *tree = NULL;
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   
   if (flow) {
      switch (flow->ip_flow.ip_p) {
         case IPPROTO_TCP: array = RaTCPSrcArray; break;
         case IPPROTO_UDP: array = RaUDPSrcArray; break;

         default:
            return (0);
      }

      if ((tree = array[flow->ip_flow.dport]) != NULL)
         retn = 1;
      else
         if ((tree = array[flow->ip_flow.sport]) != NULL)
            retn = 1;
   }

   return(retn);
}


struct RaSrvSignature *
RaValidateService(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct RaSrvSignature *retn = NULL;
   struct RaSrvSignature *srvSrc = NULL, *srcGuess = NULL;
   struct RaSrvSignature *srvDst = NULL, *dstGuess = NULL;
   struct ArgusDataStruct *suser, *duser;
   int srcPort = 0, dstPort = 0;
   struct ArgusFlow *flow = NULL;
#ifdef ARGUSDEBUG
   int srcScore = 0, dstScore = 0;
   char buf[MAXSTRLEN];
#endif
   int found = 0;

   if ((flow = (struct ArgusFlow *)argus->dsrs[ARGUS_FLOW_INDEX]) == NULL)
      return(retn);

   suser = (void *) argus->dsrs[ARGUS_SRCUSERDATA_INDEX];
   duser = (void *) argus->dsrs[ARGUS_DSTUSERDATA_INDEX];

   if (!(suser || duser)) {
      struct RaSrvTreeNode **array = NULL;
      struct RaSrvTreeNode *node = NULL;

      switch (flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case IPPROTO_TCP: array = RaTCPSrcArray; break;
                     case IPPROTO_UDP: array = RaUDPSrcArray; break;
                        break;
                  }
                  if (array != NULL)
                     if ((node = array[flow->ip_flow.dport]) == NULL)
                           node = array[flow->ip_flow.sport];
                  if (node != NULL)
                     RaBestGuess = node->srv;
                  break;

               case ARGUS_TYPE_IPV6: {
                  switch (flow->ipv6_flow.ip_p) {
                     case IPPROTO_TCP: array = RaTCPSrcArray; break;
                     case IPPROTO_UDP: array = RaUDPSrcArray; break;
                  }
                  if (array != NULL)
                     if ((node = array[flow->ipv6_flow.dport]) == NULL)
                        node = array[flow->ipv6_flow.sport];
                  if (node != NULL)
                     RaBestGuess = node->srv;
                  break;
               }
            }
         }
      }
      return (RaBestGuess);
   }

   if (suser != NULL) {
      struct RaSrvTreeNode *tree = NULL;
      u_char *ptr = (u_char *) &suser->array;
      struct RaSrvTreeNode **array = NULL;
      int i, len = suser->count;

      RaBestGuess = NULL;
      RaBestGuessScore = 0;

      switch (flow->ip_flow.ip_p) {
         case IPPROTO_TCP: array = RaTCPSrcArray; break;
         case IPPROTO_UDP: array = RaUDPSrcArray; break;
         default:
            return (retn);
      }

      if ((tree = array[flow->ip_flow.dport]) != NULL) {
         if ((srvSrc = RaFindSrv (tree, ptr, len, RA_SRC_SERVICES)) == NULL) {
            if (RaBestGuess && (RaBestGuessScore > 5)) {
               srvSrc = RaBestGuess;
               srcPort++;
            }
         }
      }

      if ((tree = array[flow->ip_flow.sport]) == NULL) {
         if (srvSrc == NULL)
            for (i = 0; i < RASIGLENGTH && !found; i++) {
               switch (flow->ip_flow.ip_p) {
                  case IPPROTO_TCP: tree = RaSrcTCPServicesTree[i]; break;
                  case IPPROTO_UDP: tree = RaSrcUDPServicesTree[i]; break;
               }
               if (tree != NULL)
                  if ((srvSrc = RaFindSrv(tree, ptr, len, RA_SRC_SERVICES)) != NULL)
                         break;
            }
      }
      srcGuess = RaBestGuess;
#ifdef ARGUSDEBUG
      srcScore = RaBestGuessScore;
#endif
   }

   if (duser != NULL) {
      struct RaSrvTreeNode *tree = NULL;
      u_char *ptr = (u_char *) &duser->array;
      struct RaSrvTreeNode **array = NULL;
      int i, len = duser->count;

      RaBestGuess = NULL;
      RaBestGuessScore = 0;
    
      switch (flow->ip_flow.ip_p) {
         case IPPROTO_TCP: array = RaTCPDstArray; break;
         case IPPROTO_UDP: array = RaUDPDstArray; break;
         default:
            return (retn);
      }

      if ((tree = array[flow->ip_flow.dport]) != NULL) {
         if ((srvDst = RaFindSrv (tree, ptr, len, RA_DST_SERVICES)) == NULL) {
            if (RaBestGuess && (RaBestGuessScore > 4)) {
               srvDst = RaBestGuess;
               dstPort++;
            }
         }
      }

      if ((srvSrc == NULL) && (srvDst == NULL)) {
         for (i = 0; i < RASIGLENGTH && !found; i++) {
            switch (flow->ip_flow.ip_p) {
               case IPPROTO_TCP: tree = RaDstTCPServicesTree[i]; break;
               case IPPROTO_UDP: tree = RaDstUDPServicesTree[i]; break;
            }

            if (tree != NULL)
               if ((srvDst = RaFindSrv(tree, ptr, len, RA_DST_SERVICES)) != NULL)
                   break;
         }
      }

#ifdef ARGUSDEBUG
      dstGuess = RaBestGuess;
      dstScore = RaBestGuessScore;
#endif
   }

#ifdef ARGUSDEBUG
   ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);
#endif

   if (srvSrc && srvDst) {
      if (!(strcmp(srvSrc->name, srvDst->name))) {
#ifdef ARGUSDEBUG
         ArgusDebug (ARGUS_DEBUG_POLICY, "%s both match %s\n", buf, srvSrc->name);
#endif
         retn = srvSrc;

      } else {
         if (srcPort && dstPort) {
#ifdef ARGUSDEBUG
            ArgusDebug (ARGUS_DEBUG_POLICY, "%s src %s dst %s mismatch\n", buf, srvSrc->name, srvDst->name);
#endif
            retn = srvSrc;

         } else {
            if (srcPort && !dstPort) {
#ifdef ARGUSDEBUG
               ArgusDebug (ARGUS_DEBUG_POLICY, "%s match %s with dst null\n", buf, srvSrc->name);
#endif
               retn = srvSrc;

            } else {
#ifdef ARGUSDEBUG
               ArgusDebug (ARGUS_DEBUG_POLICY, "%s match %s with src null\n", buf, srvDst->name);
#endif
               retn = srvDst;
            }
         }
      }

   } else {
      if (srvDst && (argus->dsrs[ARGUS_SRCUSERDATA_INDEX] == NULL)) {
         if (srvDst && (srvDst->srcmask == 0xFFFFFFFF)) {
#ifdef ARGUSDEBUG
            ArgusDebug (ARGUS_DEBUG_POLICY, "%s dst buffer matches %s\n", buf, srvDst->name);
#endif
            retn = srvDst;

         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (ARGUS_DEBUG_POLICY, "%s dst buffer matches %s\n", buf, srvDst->name);
#endif
            retn = srvDst;
         }

      } else
      if (srvSrc && (argus->dsrs[ARGUS_DSTUSERDATA_INDEX] == NULL)) {
         if (srvSrc && (srvSrc->dstmask == 0xFFFFFFFF)) {
#ifdef ARGUSDEBUG
            ArgusDebug (ARGUS_DEBUG_POLICY, "%s src buffer matches %s\n", buf, srvSrc->name);
#endif
            retn = srvSrc;
         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (ARGUS_DEBUG_POLICY, "%s src buffer matches %s\n", buf, srvSrc->name);
#endif
            retn = srvSrc;
         }

      } else {
         if (srvSrc && (srvDst == NULL)) {
            if ((dstGuess) && (srvSrc == dstGuess)) {
#ifdef ARGUSDEBUG
               ArgusDebug (ARGUS_DEBUG_POLICY, "%s match with dst search %s score %d\n", buf, srvSrc->name, dstScore);
#endif
               retn = srvSrc;

            } else {
               if (dstPort == 0) {
#ifdef ARGUSDEBUG
                  ArgusDebug (ARGUS_DEBUG_POLICY, "%s match with dst null\n", buf, srvSrc->name);
#endif
                  retn = srvSrc;

               } else {
                  retn = NULL;
               }
            }

         } else
         if (srvDst && (srvSrc == NULL)) {
            if ((srcGuess) && (srvDst == srcGuess)) {
#ifdef ARGUSDEBUG
               ArgusDebug (ARGUS_DEBUG_POLICY, "%s match with src search %s score %d\n", buf, srvDst->name, srcScore);
#endif
               retn = srvDst;

            } else {
               if (srcPort == 0) {
#ifdef ARGUSDEBUG
                  ArgusDebug (ARGUS_DEBUG_POLICY, "%s match %s with src null\n", buf, srvDst->name);
#endif
               } else
                  retn = NULL;
            }

         } else {
            retn = NULL;
         }
      }
   }

   return (retn);
}


int RaMatchService(struct ArgusRecord *);

int
RaMatchService(struct ArgusRecord *argus)
{
   int retn = 0;
   return (retn);
}


extern void ArgusPrintSrcCountryCode (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);
extern void ArgusPrintDstCountryCode (struct ArgusParserStruct *, char *, struct ArgusRecordStruct *, int);


int
RaCountryCodeLabel (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   int retn = 0;

   if (argus != NULL) {
      struct ArgusCountryCodeStruct *cocode = (struct ArgusCountryCodeStruct *)argus->dsrs[ARGUS_COCODE_INDEX];
      char sbuf[16], dbuf[16];

      bzero (sbuf, sizeof(sbuf));
      bzero (dbuf, sizeof(dbuf));

      if (cocode == NULL) {
         if ((cocode = ArgusCalloc(1, sizeof(*cocode))) == NULL)
            ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s", strerror(errno));

         cocode->hdr.type             = ARGUS_COCODE_DSR;
         cocode->hdr.argus_dsrvl8.len = (sizeof(*cocode) + 3) / 4;
         cocode->hdr.subtype = 0;

         ArgusPrintSrcCountryCode (parser, sbuf, argus, 2);
         ArgusPrintDstCountryCode (parser, dbuf, argus, 2);

         bcopy(sbuf, &cocode->src[0], 2);
         bcopy(dbuf, &cocode->dst[0], 2);

         argus->dsrindex |= (0x01 << ARGUS_COCODE_INDEX);
         argus->dsrs[ARGUS_COCODE_INDEX] = (struct ArgusDSRHeader*) cocode;
      }
   }

   return (retn);
}


char RaAddressLabelBuffer[1024];

char *
RaAddressLabel (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   char *retn = NULL, *saddr = NULL, *daddr = NULL;
   int found = 0;

   bzero (RaAddressLabelBuffer, sizeof(RaAddressLabelBuffer));
   if (flow != NULL) {
      switch(flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_LAYER_3_MATRIX:
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4: {
                  if ((saddr = RaFetchIPv4AddressLabel(parser, &flow->ip_flow.ip_src)) != NULL) {
                     int slen = strlen(RaAddressLabelBuffer);
                     snprintf (&RaAddressLabelBuffer[slen], 1024 - slen, "saddr=%s", saddr);
                     free(saddr);
                     found++;
                  }
                  if ((daddr = RaFetchIPv4AddressLabel(parser, &flow->ip_flow.ip_dst)) != NULL) {
                     int slen = strlen(RaAddressLabelBuffer);
                     if (found) {
                        snprintf (&RaAddressLabelBuffer[slen], 1024 - slen, ":");
                        slen++;
                     }
                     snprintf (&RaAddressLabelBuffer[slen], 1024 - slen, "daddr=%s", daddr);
                     free(daddr);
                     found++;
                  }
               }
            }
         }
      }
   }

   if (found)
      retn = RaAddressLabelBuffer;

   return(retn);
}

char RaIANAAddressLabel[128];

char *RaLabelIPv4Address(struct ArgusParserStruct *, unsigned int *);
char *RaLabelIPv6Address(struct ArgusParserStruct *, struct in6_addr *);

char *
RaLabelIANAAddressType (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   char *retn = NULL, *saddr = NULL, *daddr = NULL;

   if (flow != NULL) {
      switch(flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_LAYER_3_MATRIX:
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            int found = 0;

            bzero (RaIANAAddressLabel, sizeof(RaIANAAddressLabel));

            switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4: {
                  if ((saddr = RaLabelIPv4Address(parser, &flow->ip_flow.ip_src)) != NULL) {
                     int slen = strlen(RaIANAAddressLabel);
                     snprintf (&RaIANAAddressLabel[slen], 128 - slen, "saddr=%s", saddr);
                     found++;
                  }
                  if ((daddr = RaLabelIPv4Address(parser, &flow->ip_flow.ip_dst)) != NULL) {
                     int slen = strlen(RaIANAAddressLabel);
                     if (found) {
                        snprintf (&RaIANAAddressLabel[slen], 128 - slen, ":");
                        slen++;
                     }
                     snprintf (&RaIANAAddressLabel[slen], 128 - slen, "daddr=%s", daddr);
                     found++;
                  }
                  break;
               }

               case ARGUS_TYPE_IPV6: {
                  if ((saddr = RaLabelIPv6Address(parser, (struct in6_addr *)&flow->ipv6_flow.ip_src)) != NULL) {
                     int slen = strlen(RaIANAAddressLabel);
                     snprintf (&RaIANAAddressLabel[slen], 128 - slen, "saddr=%s", saddr);
                     found++;
                  }
                  if ((daddr = RaLabelIPv6Address(parser, (struct in6_addr *)&flow->ipv6_flow.ip_dst)) != NULL) {
                     int slen = strlen(RaIANAAddressLabel);
                     if (found) {
                        snprintf (&RaIANAAddressLabel[slen], 128 - slen, ":");
                        slen++;
                     }
                     snprintf (&RaIANAAddressLabel[slen], 128 - slen, "daddr=%s", daddr);
                     found++;
                  }
                  break;
               }
            }

            if (found)
               retn = RaIANAAddressLabel;
         }
      }
   }

   return (retn);
}

char *
RaLabelIPv4Address(struct ArgusParserStruct *parser, unsigned int *aptr)
{
   unsigned int addr = *aptr;
   char *retn = NULL;

   if (IN_MULTICAST(addr)) {
      if ((addr & 0xFF000000) == 0xE0000000) {
         if ((addr & 0x00FFFFFF) <  0x00000100) retn="IPv4AddrMulticastLocal"; else
         if ((addr & 0x00FFFFFF) <  0x00000200) retn="IPv4AddrMulticastInternet"; else
         if ((addr & 0x00FFFFFF) <  0x0000FF00) retn="IPv4AddrMulticastAdHoc"; else
         if ((addr & 0x00FFFFFF) <  0x00020000) retn="IPv4AddrMulticastReserved"; else
         if ((addr & 0x00FFFFFF) <  0x00030000) retn="IPv4AddrMulticastSdpSap"; else
         if ((addr & 0x00FFFFFF) <  0x00030040) retn="IPv4AddrMulticastNasdaq"; else
         if ((addr & 0x00FFFFFF) <  0x00FD0000) retn="IPv4AddrMulticastReserved"; else
         if ((addr & 0x00FFFFFF) <= 0x00FD0000) retn="IPv4AddrMulticastDisTrans";
      }
      if (((addr & 0xFF000000) > 0xE0000000) && ((addr & 0xFF000000) < 0xE8000000)) {
         retn="IPv4AddrMulticastReserved";
      }
      if ((addr & 0xFF000000) == 0xE8000000) {
         retn="IPv4AddrMulticastSrcSpec";
      }
      if ((addr & 0xFF000000) == 0xE9000000) {
         retn="IPv4AddrMulticastGlop";
      }
      if (((addr & 0xFF000000) >= 0xE9000000) && ((addr & 0xFF000000) <= 0xEE000000)) {
         retn="IPv4AddrMulticastReserved";
      }
      if ((addr & 0xFF000000) == 0xEF000000) {
         retn="IPv4AddrMulticastAdmin";
         if (((addr & 0x00FF0000) > 0x00000000) && ((addr & 0x00FF0000) <  0x00C00000)) {
            retn="IPv4AddrMulticastReserved";
         }
         if (((addr & 0x00FF0000) >= 0x00C00000) && ((addr & 0x00FF0000) <  0x00FC0000)) {
            retn="IPv4AddrMulticastOrgLocal";
         }
         if (((addr & 0x00FF0000) >= 0x00FC0000) && ((addr & 0x00FF0000) <= 0x00FF0000)) {
            retn="IPv4AddrMulticastSiteLocal";
         }
      }

   } else {
      if (((addr & 0xFF000000) == 0x00000000)) {
         retn="IPv4AddrUnicastThisNet";
      } else 
      if (((addr & 0xFF000000) > 0x00000000) && ((addr & 0xFF000000) <  0x03000000)) {
         retn="IPv4AddrUnicastReserved";
      } else 
      if ((addr & 0xFF000000) == 0x05000000) {
         retn="IPv4AddrUnicastReserved";
      } else
      if ((addr & 0xFF000000) == 0x17000000) {
         retn="IPv4AddrUnicastReserved";
      } else
      if ((addr & 0xFF000000) == 0x1B000000) {
         retn="IPv4AddrUnicastReserved";
      } else
      if (((addr & 0xFF000000) == 0x24000000) || ((addr & 0xFF000000) == 0x25000000)) {
         retn="IPv4AddrUnicastReserved";
      } else
      if (((addr & 0xFF000000) == 0x29000000) || ((addr & 0xFF000000) == 0x30000000)) {
         retn="IPv4AddrUnicastReserved";
      } else
      if (((addr & 0xFF000000) >= 0x49000000) && ((addr & 0xFF000000) <  0x50000000)) {
         retn="IPv4AddrUnicastReserved";
      } else
      if (((addr & 0xFF000000) >= 0x59000000) && ((addr & 0xFF000000) <  0x7F000000)) {
         retn="IPv4AddrUnicastReserved";
      } else
      if ((addr & 0xFF000000) == 0x7F000000) {
         retn="IPv4AddrUnicastLoopBack";
      } else
      if ((addr & 0xFFFF0000) == 0xAC100000) {
         retn="IPv4AddrUnicastPrivate";
      } else
      if (((addr & 0xFF000000) >= 0xAD000000) && ((addr & 0xFF000000) <  0xBC000000)) {
         if ((addr & 0xFFFF0000) == 0xA9FE0000)
            retn="IPv4AddrUnicastLinkLocal";
         else
            retn="IPv4AddrUnicastReserved";
      } else
      if (((addr & 0xFF000000) >= 0xBE000000) && ((addr & 0xFF000000) <  0xC0000000)) {
         retn="IPv4AddrUnicastReserved";
      } else
      if ((addr & 0xFF000000) == 0xC0000000) {
         if ((addr & 0xFFFFFF00) == 0xC0000200)
            retn="IPv4AddrUnicastTestNet";
         else
         if ((addr & 0xFFFF0000) == 0xC0A80000)
            retn="IPv4AddrUnicastPrivate";
         else
            retn="IPv4AddrUnicast";
      } else
      if ((addr & 0xFF000000) == 0xC5000000) {
         retn="IPv4AddrUnicastReserved";
      } else
      if ((addr & 0xFF000000) == 0xDF000000) {
         retn="IPv4AddrUnicastReserved";
      } else
      if (((addr & 0xFF000000) >= 0xBE000000) && ((addr & 0xFF000000) <  0xC0000000)) {
         retn="IPv4AddrUnicastReserved";
      } else
      if (((addr & 0xFF000000) >= 0xF0000000) && ((addr & 0xFF000000) <= 0xFF000000)) {
         retn="IPv4AddrUnicastReserved";
      } else
      if ((addr & 0xFF000000) == 0x0A000000) {
         retn="IPv4AddrUnicastPrivate";
      } else
         retn="IPv4AddrUnicast";
   }

   return (retn);
}

char *
RaLabelIPv6Address(struct ArgusParserStruct *parser, struct in6_addr *addr)
{
   char *retn = NULL;

   if (IN6_IS_ADDR_UNSPECIFIED(addr))  retn = "IPv6AddrUnspecified"; else
   if (IN6_IS_ADDR_LOOPBACK(addr))     retn = "IPv6AddrLoopback"; else
   if (IN6_IS_ADDR_V4COMPAT(addr))     retn = "IPv6AddrV4Compat"; else
   if (IN6_IS_ADDR_V4MAPPED(addr))     retn = "IPv6AddrV4Mapped"; else
 
   if (IN6_IS_ADDR_LINKLOCAL(addr))    retn = "IPv6AddrLinkLocal"; else
   if (IN6_IS_ADDR_SITELOCAL(addr))    retn = "IPv6AddrSiteLocal"; else
 
   if (IN6_IS_ADDR_MC_NODELOCAL(addr)) retn = "IPv6AddrMulticastNodeLocal"; else
   if (IN6_IS_ADDR_MC_LINKLOCAL(addr)) retn = "IPv6AddrMulticastLinkLocal"; else
   if (IN6_IS_ADDR_MC_SITELOCAL(addr)) retn = "IPv6AddrMulticastSiteLocal"; else
   if (IN6_IS_ADDR_MC_ORGLOCAL(addr))  retn = "IPv6AddrMulticastOrgLocal"; else
   if (IN6_IS_ADDR_MC_GLOBAL(addr))    retn = "IPv6AddrMulticastGlobal";

   return (retn);
}


char ArgusIPv4AddressLabelBuffer[1024];
char *ArgusReturnLabel (struct RaAddressStruct *);

char *
RaFetchIPv4AddressLabel(struct ArgusParserStruct *parser, unsigned int *aptr)
{
   struct ArgusLabelerStruct *labeler;
   struct RaAddressStruct *raddr;
   unsigned int addr = *aptr;
   char *retn = NULL;

   bzero(ArgusIPv4AddressLabelBuffer, sizeof(ArgusIPv4AddressLabelBuffer));

   if ((labeler = parser->ArgusLabeler) != NULL) {
      if (labeler->ArgusAddrTree) {
         struct RaAddressStruct node;
         bzero ((char *)&node, sizeof(node));

         node.addr.type = AF_INET;
         node.addr.len = 4;
         node.addr.addr[0] = addr;
         node.addr.masklen = 32;

         if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_LONGEST_MATCH)) != NULL)
            retn = ArgusReturnLabel(raddr);
      }
   }

   return(retn);
}


char *
RaPortLabel (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, char *buf, int len)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   char *retn = NULL, *sport = NULL, *dport = NULL;
   int found = 0;

   bzero (buf, len);
   if (flow != NULL) {
      switch(flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_LAYER_3_MATRIX:
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4: {
                  if ((sport = RaFetchIPPortLabel(parser, flow->ip_flow.ip_p, flow->ip_flow.sport)) != NULL) {
                     if (strlen(sport)) {
                        int slen = strlen(buf);
                        snprintf (&buf[slen], len - slen, "sport=%s", sport);
                        found++;
                     }
                  }
                  if ((dport = RaFetchIPPortLabel(parser, flow->ip_flow.ip_p, flow->ip_flow.dport)) != NULL) {
                     if (strlen(dport)) {
                        int slen = strlen(buf);
                        if (found) {
                           snprintf (&buf[slen], len - slen, ":");
                           slen++;
                        }
                        snprintf (&buf[slen], len - slen, "dport=%s", dport);
                        found++;
                     }
                  }
               }
            }
         }
      }
   }

   if (found)
      retn = buf;

   return(retn);
}


char ArgusIPPortLabelBuffer[1024];

char *
RaFetchIPPortLabel(struct ArgusParserStruct *parser, unsigned short proto, unsigned short port)
{
   struct RaPortStruct **array = NULL, *ps = NULL;
   struct ArgusLabelerStruct *labeler;
   char *retn = NULL;

   bzero(ArgusIPPortLabelBuffer, sizeof(ArgusIPPortLabelBuffer));

   if ((labeler = parser->ArgusLabeler) != NULL) {
      switch (proto) {
         case IPPROTO_TCP:
            array = labeler->ArgusTCPPortLabels;
            break;

         case IPPROTO_UDP:
            array = labeler->ArgusUDPPortLabels;
            break;
      }

      if (array != NULL)
         if ((ps = array[port]) != NULL)
            retn = ps->label;
   }

   return(retn);
}


char *
RaFlowLabel (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, char *buf, int len)
{
   struct ArgusLabelerStruct *labeler = NULL;
   struct RaFlowLabelStruct *raflow = NULL;
   int found = 0, count = 0, done = 0, x, z;
   struct ArgusQueueStruct *queue = NULL;
   char *retn = NULL;

   if ((labeler = parser->ArgusLabeler) == NULL)
      ArgusLog (LOG_ERR, "RaProcessAddress: No labeler\n");

   bzero (buf, len);

   if ((queue = labeler->ArgusFlowQueue) && ((count = labeler->ArgusFlowQueue->count) > 0)) {
      for (x = 0, z = count; x < z; x++) {
         if ((raflow = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
            if (!done) {
               int pass = 1;
               if (raflow->filterstr != NULL) {
                  struct nff_insn *wfcode = raflow->filter.bf_insns;
                  pass = ArgusFilterRecord (wfcode, argus);
               }

               if (pass != 0) {
                  int slen = strlen(buf);
                  if (found) {
                     snprintf (&buf[slen], MAXSTRLEN - slen, ":");
                     slen++;
                  }
                  snprintf (&buf[slen], MAXSTRLEN - slen, "flow=%s", raflow->labelstr);
                  found++;
                  if (raflow->cont == 0)
                     done = 1;
               }
            }
            ArgusAddToQueue (queue, &raflow->qhdr, ARGUS_NOLOCK);
         }
      }
   }

   if (found)
      retn = buf;

   return(retn);
}


char *
ArgusReturnLabel (struct RaAddressStruct *raddr)
{
   char *retn = NULL, *ptr = NULL;

   if (raddr->p)
      ptr = ArgusReturnLabel(raddr->p);

   if (raddr->label) {
      if (ptr != NULL) {
         int slen = strlen(ptr) + strlen(raddr->label) + 2;
         if ((retn = malloc(slen)) != NULL)  {
            snprintf(retn, slen, "%s,%s", ptr, raddr->label);
            free(ptr);
         }
      } else
         retn = strdup(raddr->label);
   } else 
      retn = ptr;

   return (retn);
}


char RaFlowColorBuffer[1024];

char *
RaFlowColor (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusLabelerStruct *labeler = NULL;
   struct RaFlowLabelStruct *raflow = NULL;
   struct ArgusQueueStruct *queue = NULL;
   int count = 0, done = 0, x, z;
   char *retn = NULL;

   if ((labeler = parser->ArgusColorLabeler) == NULL)
      return(retn);

   bzero (RaFlowColorBuffer, sizeof(RaFlowColorBuffer));

   if ((queue = labeler->ArgusFlowQueue) && ((count = labeler->ArgusFlowQueue->count) > 0)) {
      for (x = 0, z = count; x < z; x++) {
         if ((raflow = (void *)ArgusPopQueue(queue, ARGUS_NOLOCK)) != NULL) {
            if (!done) {
               int pass = 1;
               if (raflow->filterstr != NULL) {
                  struct nff_insn *wfcode = raflow->filter.bf_insns;
                  pass = ArgusFilterRecord (wfcode, argus);
               }

               if (pass != 0) {
                  int slen = strlen(RaFlowColorBuffer);
                  if (slen) {
                     snprintf (&RaFlowColorBuffer[slen], 1024 - slen, ";");
                     slen++;
                  }
                  snprintf (&RaFlowColorBuffer[slen], 1024 - slen, "%s", raflow->colorstr);
                  if (raflow->cont == 0)
                     done = 1;
               }
            }
            ArgusAddToQueue (queue, &raflow->qhdr, ARGUS_NOLOCK);
         }
      }
   }

   if (strlen(RaFlowColorBuffer))
      retn = RaFlowColorBuffer;

   return(retn);
}


int RaLabelItemNum = 0;

float xBaseValue = 30.0;
float yBaseValue = 100.0;

float yDelta = -2.0;
float xDelta = -12.0;

void
RaMapLabelMol (struct ArgusLabelerStruct *labeler, struct RaAddressStruct *node, int level, int x, int y, int dir)
{
   if (node != NULL) {
      x += (xDelta * 16.0/node->addr.masklen);
      if (node->r) RaMapLabelMol(labeler, node->r, level + 1, x, y, dir);
      node->x = x;
      node->y = yBaseValue + (RaLabelItemNum++ * yDelta);
      if (node->l) RaMapLabelMol(labeler, node->l, level + 1, x, y, dir);
   }
}

void
RaPrintLabelMol (struct ArgusLabelerStruct *labeler, struct RaAddressStruct *node, int level, int x, int y, int dir)
{
   char strbuf[256];
   float xl, yl, zl;
   int slen = 0;

   if (node != NULL) {
      float size = 0.2;

      if (node->addr.masklen)
         size = 32.0/node->addr.masklen;

      if (node->r) {
         printf ("draw arrow {%f %f %f} {%f %f %f}\n", node->x, node->y, 0.0, node->r->x, node->r->y, 0.0); 
         RaPrintLabelMol(labeler, node->r, level + 1, x, y, RA_SRV_RIGHT);
      }

      if (!(node->r || node->l))
         printf ("draw color green\n");

      printf ("draw sphere {%f %f %f} radius %f resolution 32\n", node->x, node->y, 0.0, size); 

      snprintf (strbuf, sizeof(strbuf), "%s/%d ", intoa(node->addr.addr[0] & (0xFFFFFFFF << (32 - node->addr.masklen))), node->addr.masklen);
      printf ("draw color white\n"); 
      slen = strlen(strbuf);

      if (node->label) {
         char *ptr;
         if ((ptr = strchr (node->label, '\n')) != NULL) *ptr = '\0';
         snprintf (&strbuf[slen], sizeof(strbuf) - slen,  "%s", node->label);
         xl = node->x; yl = node->y; zl = (size*2 + 0.25);

      } else {
         snprintf (&strbuf[slen], sizeof(strbuf) - slen,  "\"");
         xl = node->x; yl = node->y; zl = (size*2 + 0.25);
      }

      printf ("draw text {%f %f %f} \"%s size %f\n", xl, yl, zl, strbuf, size/4); 
      printf ("draw color blue\n"); 

      if (node->l) {
         printf ("draw arrow {%f %f %f} {%f %f %f}\n", node->x, node->y, 0.0, node->l->x, node->l->y, 0.0); 
         RaPrintLabelMol(labeler, node->l, level + 1, x, y, RA_SRV_LEFT);
      }
   }
}



char RaAddrTreeArray[MAXSTRLEN];

void
RaPrintLabelTree (struct ArgusLabelerStruct *labeler, struct RaAddressStruct *node, int level, int dir)
{
   int i = 0, length, len;
   int olen = strlen(RaAddrTreeArray);
   char str[MAXSTRLEN], chr = ' ';

   if (level > RaPrintLabelTreeLevel)
      return;

   bzero(str, MAXSTRLEN);

   if (node != NULL) {
      switch (labeler->RaPrintLabelTreeMode) {

         case ARGUS_TREE:
         case ARGUS_TREE_VISITED: {
            if (node->status & ARGUS_VISITED) {
               if (dir == RA_SRV_LEFT) {
                  strcat (str, "   |");
                  strcat (RaAddrTreeArray, str);
                  printf ("%s\n", RaAddrTreeArray);
               }

               length = strlen(RaAddrTreeArray);
               if ((len = length) > 0) {
                  chr = RaAddrTreeArray[len - 1];
                  if (node->r != NULL) {
                     if (dir == RA_SRV_RIGHT)
                        RaAddrTreeArray[len - 1] = ' ';
                  }
               }

               strcat (RaAddrTreeArray, "   |");

               RaPrintLabelTree(labeler, node->r, level + 1, RA_SRV_RIGHT);

               for (i = length, len = strlen(RaAddrTreeArray); i < len; i++)
                  RaAddrTreeArray[i] = '\0';

               if ((len = length) > 0)
                  RaAddrTreeArray[len - 1] = chr;
         
               printf ("%s+", RaAddrTreeArray);

               if (node->addr.str)
                  printf ("%s ", node->addr.str);

               else  {
                  if (node->addr.masklen > 0) {
                     printf ("%s/%d ", intoa(node->addr.addr[0] & (0xFFFFFFFF << (32 - node->addr.masklen))),
                                  node->addr.masklen);
//                   printf ("%s ", intoa((0xFFFFFFFF << (32 - node->addr.masklen))));
                  } else
                     printf ("0.0.0.0/0 ");
               }

               if (strlen(node->cco))
                  printf ("%s ", node->cco);

               if (node->label)
                  printf ("%s ", node->label);

               if (node->ns) {
                  char buf[MAXSTRLEN];
                  bzero (buf, sizeof(buf));
                  ArgusPrintRecord(ArgusParser, buf, node->ns, MAXSTRLEN);
                  printf ("%s ", buf);
               }

               printf ("\n");

               len = strlen(RaAddrTreeArray);
               if (len > 0) {
                  chr = RaAddrTreeArray[len - 1];
                  if (node->l != NULL) {
                     if (dir == RA_SRV_LEFT)
                        RaAddrTreeArray[len - 1] = ' ';
                  }
               }

               RaPrintLabelTree(labeler, node->l, level + 1, RA_SRV_LEFT);

               if (dir == RA_SRV_RIGHT) {
                  printf ("%s", RaAddrTreeArray);
                  putchar ('\n');
               }

               for (i = olen, len = strlen(RaAddrTreeArray); i < len; i++)
                  RaAddrTreeArray[i] = '\0';
            }
            break;
         }

         case ARGUS_GRAPH: {
            if (node->status & ARGUS_VISITED) {
               if (node->r || node->l) {
                  if (node->r) {
                     if (node->addr.str)
                        printf ("\"%s\" ", node->addr.str);
                     else  {
                        if (node->addr.addr[0]) {
                           if (node->addr.masklen > 0) {
                              printf ("\"%s/%d\" ", intoa(node->addr.addr[0] & (0xFFFFFFFF << (32 - node->addr.masklen))),
                                        node->addr.masklen);
                           } else
                              printf ("\"0.0.0.0/0\" ");
                        }
                     }
                     printf (" -> ");
                     if (node->r->addr.str)
                        printf ("\"%s\"\n", node->r->addr.str);
                     else  {
                        if (node->r->addr.addr[0]) {
                           if (node->r->addr.masklen > 0) {
                              printf ("\"%s/%d\"\n", intoa(node->r->addr.addr[0] & (0xFFFFFFFF << (32 - node->r->addr.masklen))),
                                        node->r->addr.masklen);
                           } else
                              printf ("\"0.0.0.0/0\"\n");
                        }
                     }
                     RaPrintLabelTree(labeler, node->r, level + 1, RA_SRV_RIGHT);
                  }

                  if (node->l) {
                     if (node->addr.str)
                        printf ("\"%s\" ", node->addr.str);
                     else  {
                        if (node->addr.addr[0]) {
                           if (node->addr.masklen > 0) {
                              printf ("\"%s/%d\" ", intoa(node->addr.addr[0] & (0xFFFFFFFF << (32 - node->addr.masklen))),
                                        node->addr.masklen);
                           } else
                              printf ("\"0.0.0.0/0\" ");
                        }
                     }
                     printf (" -> ");
                     if (node->l->addr.str)
                        printf ("\"%s\"\n", node->l->addr.str);
                     else  {
                        if (node->l->addr.addr[0]) {
                           if (node->l->addr.masklen > 0) {
                              printf ("\"%s/%d\"\n", intoa(node->l->addr.addr[0] & (0xFFFFFFFF << (32 - node->l->addr.masklen))),
                                        node->l->addr.masklen);
                           } else
                              printf ("\"0.0.0.0/0\"\n");
                        }
                     }
                     RaPrintLabelTree(labeler, node->l, level + 1, RA_SRV_RIGHT);
                  }
               }
            }
            break;
         }
      }
   }
}

