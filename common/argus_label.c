/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
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

/*
 * $Id: //depot/gargoyle/clients/common/argus_label.c#51 $
 * $DateTime: 2016/11/30 00:54:11 $
 * $Change: 3245 $
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include <argus_compat.h>

#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_sort.h>
#include <argus_metric.h>
#include <argus_histo.h>
#include <argus_label.h>
#include <argus_json.h>

#include <rasplit.h>


#if defined(__OpenBSD__)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif
 
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/tcp.h>

#include "argus_label_geoip.h"

#if defined(ARGUS_GEOIP) || defined(ARGUS_GEOIP2)
#include "argus_label_geoip.h"
#endif


extern struct cnamemem *lookup_cmem(struct cnamemem *, const u_char *);
extern struct cnamemem ipv6cidrtable[];

struct enamemem elabeltable[HASHNAMESIZE];

struct ArgusLabelerStruct *ArgusLabeler;

int RaReadAddressConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
int RaReadIeeeAddressConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

void ArgusGetInterfaceAddresses(struct ArgusParserStruct *);

char *ArgusUpgradeLabel(char *, char *, int);
void RaAddSrvTreeNode(struct RaSrvTreeNode *, struct RaSrvSignature *, int, int);
int ArgusSortSrvSignatures (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
void RaAddToSrvTree (struct RaSrvSignature *, int);
int RaGenerateBinaryTrees(struct ArgusParserStruct *, struct ArgusLabelerStruct *);
int RaReadSrvSignature(struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
struct RaSrvSignature *RaFindSrv (struct RaSrvTreeNode *, u_char *ptr, int, int, int);

int ArgusAddToRecordLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);

int RaFindService(struct ArgusRecordStruct *);
struct RaSrvSignature *RaValidateService(struct ArgusParserStruct *, struct ArgusRecordStruct *);

int ArgusNodesAreEqual (struct RaAddressStruct *, struct RaAddressStruct *);
void ArgusUpdateNode (struct RaAddressStruct *, struct RaAddressStruct *);

struct RaSrvSignature *RaBestGuess = NULL;
int RaBestGuessScore = 0;


int RaPrintLabelStartTreeLevel = 0;
int RaPrintLabelTreeLevel = 1000000;

int RaPrintLabelTreeDebug = 0;

#define RALABEL_RCITEMS                         29

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
#define RALABEL_LOCALITY			12
#define RALABEL_LOCALITY_FILE			13
#define RALABEL_GEOIP_ASN                       14
#define RALABEL_GEOIP_ASN_FILE                  15
#define RALABEL_GEOIP_V4_ASN_FILE               16
#define RALABEL_GEOIP_V6_ASN_FILE               17
#define RALABEL_GEOIP_CITY                      18
#define RALABEL_GEOIP_CITY_FILE                 19
#define RALABEL_GEOIP_V4_CITY_FILE              20
#define RALABEL_GEOIP_V6_CITY_FILE              21
#define RALABEL_PRINT_DOMAINONLY		22
#define RALABEL_PRINT_LOCALONLY			23
#define RALABEL_BIND_NON_BLOCKING		24
#define RALABEL_DNS_NAME_CACHE_TIMEOUT		25
#define RALABEL_ARGUS_FLOW_SERVICE              26
#define RALABEL_SERVICE_SIGNATURES              27
#define RALABEL_FIREHOL_FILES			28

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
   "RALABEL_LOCALITY=",
   "RALABEL_LOCALITY_FILE=",
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
   "RALABEL_ARGUS_FLOW_SERVICE=",
   "RALABEL_SERVICE_SIGNATURES=",
   "RALABEL_FIREHOL_FILES=",
};


int RaLabelParseResourceBuffer (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char **);
int RaLabelParseResourceStr (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

int
RaLabelParseResourceBuffer (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char **bufarray)
{
   int retn = 1, i = 0;
   char *str = NULL;

   while ((str = bufarray[i]) != NULL) {
      char *tstr = strdup(str);
      char *cstr = tstr;

      while (*cstr && isspace((int)*cstr))
         cstr++;
      i++;

      if (RaLabelParseResourceStr (parser, labeler, cstr) == 0)
         ArgusLog (LOG_ERR, "RaLabelParseResourceBuffer: syntax error line %d\n", i);

      free(tstr);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaLabelParseResourceBuffer: %d lines processed\n", i);
#endif
   return (retn);
}

int
RaLabelParseResourceFile (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *file)
{
   extern int ArgusEtherArrayInited;
   char *strbuf, *str;
   int retn = 1, lines = 0;
   FILE *fd = NULL;

   if (ArgusEtherArrayInited == 0)
      ArgusInitEtherarray();

   if (file) {
      if ((strbuf = (void *)ArgusCalloc(MAXSTRLEN, sizeof(char))) == NULL) 
         ArgusLog (LOG_ERR, "RaRealFlowLabels: ArgusCalloc error %s\n", strerror(errno));

      str = strbuf;

      if ((fd = fopen (file, "r")) != NULL) {
         retn = 0;
         while ((fgets(str, MAXSTRLEN, fd)) != NULL)  {
            lines++;
            while (*str && isspace((int)*str))
                str++;
 
            if (RaLabelParseResourceStr (parser, labeler, str) == 0)
               ArgusLog (LOG_ERR, "RaLabelParseResourceFile: %s: syntax error line %d\n", file, lines);
         }

         fclose(fd);
      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaLabelParseResourceFile:  %s: %s\n", file, strerror(errno));
#endif
      }

      ArgusFree(strbuf);
   }
#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaLabelParseResourceFile: %s done\n", file);
#endif

   return (retn);
}


int
RaLabelParseResourceStr (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *str)
{
   int retn = 1, i, len, found = 0;
   char *optarg = NULL;

   if (str) {
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
                        if (!(RaReadAddressConfig (parser, labeler, optarg) > 0))
                           ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadAddressConfig error");
                        break;

                     case RALABEL_IEEE_ADDRESS:
                        if (!(strncasecmp(optarg, "yes", 3)))
                           labeler->RaLabelIeeeAddress = 1;
                        else
                           labeler->RaLabelIeeeAddress = 0;
                        break;

                     case RALABEL_IEEE_ADDRESS_FILE:
                        if (!(RaReadIeeeAddressConfig (parser, labeler, optarg) > 0))
                           ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadIeeeAddressConfig error");
                        break;

                     case RALABEL_ARIN_COUNTRY_CODES:
                        if (!(strncasecmp(optarg, "yes", 3)))
                           labeler->RaLabelCountryCode = 1;
                        else
                           labeler->RaLabelCountryCode = 0;
                        break;

                     case RA_DELEGATED_IP:
                        if (!(RaReadAddressConfig (parser, labeler, optarg) > 0))
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
                        if (RaReadPortConfig (parser, labeler, optarg) != 0)
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
                        if (RaReadFlowLabels (parser, labeler, optarg) != 0)
                           ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadFlowLabels error");
                        break;

                     case RALABEL_LOCALITY:
                        if (!(strncasecmp(optarg, "yes", 3))) {
                           labeler->RaLabelLocality = 1;
                        } else {
                           labeler->RaLabelLocality = 0;
                        }
                        break;

                     case RALABEL_LOCALITY_FILE:
                        if (parser->ArgusLocalLabeler == NULL) 
                           if ((parser->ArgusLocalLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
                              ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

                        if (!(RaReadLocalityConfig (parser, parser->ArgusLocalLabeler, optarg) > 0))
                           ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadLocalityConfig error");
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
                        if ((labeler->RaGeoIPv4AsnObject = GeoIP_open (optarg, GEOIP_INDEX_CACHE)) == NULL)
                           ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadGeoIPAsn database error");
                        break;

                     case RALABEL_GEOIP_V6_ASN_FILE:
                        if ((labeler->RaGeoIPv6AsnObject = GeoIP_open (optarg, GEOIP_INDEX_CACHE)) == NULL)
                           ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadGeoIPAsn database error");
                        break;

                     case RALABEL_GEOIP_CITY: {
                        if (!(strncasecmp(optarg, "no", 2))) {
                           labeler->RaLabelGeoIPCity = 0;
                        } else {
                           char *sptr, *fptr, *tptr;
                           int ind = 0, x;

                           bzero(labeler->RaLabelGeoIPCityLabels, sizeof(labeler->RaLabelGeoIPCityLabels));

                           if ((tptr = strchr(optarg, ':')) != NULL) {
                              *tptr++ = '\0';
 
                              while ((fptr = strtok(optarg, ",")) != NULL) {
                                 if (!strncmp(fptr, "*", 1)) labeler->RaLabelGeoIPCity |= ARGUS_ADDR_MASK; else
                                 if (!strncmp(fptr, "saddr", 5)) labeler->RaLabelGeoIPCity |= ARGUS_SRC_ADDR; else
                                 if (!strncmp(fptr, "daddr", 5)) labeler->RaLabelGeoIPCity |= ARGUS_DST_ADDR; else
                                 if (!strncmp(fptr, "inode", 5)) labeler->RaLabelGeoIPCity |= ARGUS_INODE_ADDR;
                                 optarg = NULL;
                              }
                           } else
                              labeler->RaLabelGeoIPCity |= ARGUS_ADDR_MASK;

                           while ((sptr = strtok(tptr, ",")) != NULL) {
                              for (x = 1; x < ARGUS_GEOIP_TOTAL_OBJECTS; x++) {
                                 if (!(strncmp(sptr, ArgusGeoIPCityObjects[x].field, ArgusGeoIPCityObjects[x].length))) {
                                    labeler->RaLabelGeoIPCityLabels[ind] = ArgusGeoIPCityObjects[x].value;
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
                        if ((labeler->RaGeoIPv4CityObject = GeoIP_open( optarg, GEOIP_INDEX_CACHE)) == NULL)
                           ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadGeoIPAsn database error");
                        break;

                     case RALABEL_GEOIP_V6_CITY_FILE:
                        if ((labeler->RaGeoIPv6CityObject = GeoIP_open( optarg, GEOIP_INDEX_CACHE)) == NULL)
                           ArgusLog (LOG_ERR, "RaLabelParseResourceFile: RaReadGeoIPAsn database error");
                        break;
#endif

#if defined(ARGUS_GEOIP2)
                     case RALABEL_GEOIP_ASN:
                        if (!(strncasecmp(optarg, "no", 3))) {
                           labeler->RaLabelGeoIPAsn = 0;
                        } else {
                           char *sptr, *fptr, *tptr;
                           int ind = 0;
                           int maxlabels = sizeof(labeler->RaLabelGeoIPAsnLabels)/
                                           sizeof(labeler->RaLabelGeoIPAsnLabels[0]);

                           bzero(labeler->RaLabelGeoIPAsnLabels, sizeof(labeler->RaLabelGeoIPAsnLabels));

                           if ((tptr = strchr(optarg, ':')) != NULL) {
                              *tptr++ = '\0';

                              while ((fptr = strtok(optarg, ",")) != NULL) {
                                 if (!strncmp(fptr, "*", 1))     labeler->RaLabelGeoIPAsn |= ARGUS_ADDR_MASK; else
                                 if (!strncmp(fptr, "saddr", 5)) labeler->RaLabelGeoIPAsn |= ARGUS_SRC_ADDR; else
                                 if (!strncmp(fptr, "daddr", 5)) labeler->RaLabelGeoIPAsn |= ARGUS_DST_ADDR; else
                                 if (!strncmp(fptr, "inode", 5)) labeler->RaLabelGeoIPAsn |= ARGUS_INODE_ADDR;
                                 optarg = NULL;
                              }
                           } else
                              labeler->RaLabelGeoIPAsn |= ARGUS_ADDR_MASK;

                           while ((sptr = strtok(tptr, ",")) != NULL && ind < maxlabels) {
                              int obidx = ArgusGeoIP2FindObject(sptr);

                              tptr = NULL;
                              if (obidx >= 0) {
                                 labeler->RaLabelGeoIPAsnLabels[ind] = obidx;
                                 ind++;
                              }
                           }
                        }
                        break;

                     case RALABEL_GEOIP_ASN_FILE:
                     case RALABEL_GEOIP_V4_ASN_FILE: 
                     case RALABEL_GEOIP_V6_ASN_FILE: {
                        int status = MMDB_open(optarg, MMDB_MODE_MMAP, &labeler->RaGeoIPAsnObject);

                        if (status != MMDB_SUCCESS) {
                           ArgusLog(LOG_ERR, "%s: failed to open GeoIP2 ASN database: %s\n", __func__, MMDB_strerror(status));
                        }
                        break;
                     }

                     case RALABEL_GEOIP_CITY: {
                        if (!(strncasecmp(optarg, "no", 2))) {
                           labeler->RaLabelGeoIPCity = 0;
                        } else {
                           char *sptr, *fptr, *tptr;
                           int ind = 0;
                           int maxlabels = sizeof(labeler->RaLabelGeoIPCityLabels)/
                                           sizeof(labeler->RaLabelGeoIPCityLabels[0]);

                           bzero(labeler->RaLabelGeoIPCityLabels, sizeof(labeler->RaLabelGeoIPCityLabels));

                           if ((tptr = strchr(optarg, ':')) != NULL) {
                              *tptr++ = '\0';
 
                              while ((fptr = strtok(optarg, ",")) != NULL) {
                                 if (!strncmp(fptr, "*", 1))     labeler->RaLabelGeoIPCity |= ARGUS_ADDR_MASK; else
                                 if (!strncmp(fptr, "saddr", 5)) labeler->RaLabelGeoIPCity |= ARGUS_SRC_ADDR; else
                                 if (!strncmp(fptr, "daddr", 5)) labeler->RaLabelGeoIPCity |= ARGUS_DST_ADDR; else
                                 if (!strncmp(fptr, "inode", 5)) labeler->RaLabelGeoIPCity |= ARGUS_INODE_ADDR;
                                 optarg = NULL;
                              }
                           } else {
                              labeler->RaLabelGeoIPCity |= ARGUS_ADDR_MASK;
                              tptr = optarg;
                           }

                           while ((sptr = strtok(tptr, ",")) != NULL && ind < maxlabels) {
                              int obidx = ArgusGeoIP2FindObject(sptr);

                              tptr = NULL;
                              if (obidx >= 0) {
                                 labeler->RaLabelGeoIPCityLabels[ind] = obidx;
                                 ind++;
                              }
                           }
                        }
                        break;
                     }

                     case RALABEL_GEOIP_CITY_FILE:
                     case RALABEL_GEOIP_V4_CITY_FILE:
                     case RALABEL_GEOIP_V6_CITY_FILE: {
                        int status = MMDB_open(optarg, MMDB_MODE_MMAP, &labeler->RaGeoIPCityObject);

                        if (status != MMDB_SUCCESS) {
                           ArgusLog(LOG_ERR,
                                    "%s: failed to open GeoIP2 city database: %s\n",
                                    __func__, MMDB_strerror(status));
                        }
                        break;
                     }
#endif
                     case RALABEL_ARGUS_FLOW_SERVICE: {
                        if (!(strncasecmp(optarg, "yes", 3))) {
                           labeler->RaLabelArgusFlowService = 1;
                        } else {
                           labeler->RaLabelArgusFlowService = 0;
                        }
                        break;
                     }

                     case RALABEL_SERVICE_SIGNATURES: {
                        if (parser->ArgusLabeler == NULL)
                           if ((parser->ArgusLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
                              ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

                        RaReadSrvSignature (parser, parser->ArgusLabeler, optarg);
                        break;
                     }

                     default:
                        break;
                  }
               }
               found++;
               break;
            }
         }

         if (!found)
            retn = 0;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaLabelParseResourceStr (%s) returning %d\n", str, retn);
#endif

   return (retn);
}


int
ArgusAddToRecordLabel (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, char *tlabel)
{
   struct ArgusLabelStruct *l1 = (void *) argus->dsrs[ARGUS_LABEL_INDEX], *l2 = NULL;
   char *buf, *label = NULL;
   int len = 0, retn = 0, tlen = strlen(tlabel);

   if ((buf = (char *) ArgusCalloc(1, MAXSTRLEN)) == NULL)
      ArgusLog (LOG_ERR, "ArgusAddToRecordLabel: ArgusCalloc error %s", strerror(errno));

   len = 4 * ((tlen + 3)/4);
   if ((l2 = ArgusCalloc(1, sizeof(*l2))) == NULL)
      ArgusLog (LOG_ERR, "ArgusAddToRecordLabel: ArgusCalloc error %s", strerror(errno));

   if ((l2->l_un.label = calloc(1, len + 4)) == NULL)
      ArgusLog (LOG_ERR, "ArgusAddToRecordLabel: calloc error %s", strerror(errno));

   l2->hdr.type             = ARGUS_LABEL_DSR;
   l2->hdr.argus_dsrvl8.len = 1 + ((len + 3)/4);
   bcopy (tlabel, l2->l_un.label, tlen);

   if (l1 != NULL) {
      if ((label = ArgusMergeLabel(l1->l_un.label, l2->l_un.label, buf, MAXSTRLEN, ARGUS_UNION)) != NULL) {
         int slen = strlen(label);
         int len = 4 * ((slen + 3)/4);

         if (l1->l_un.label != NULL) 
            free(l1->l_un.label);

         if ((l1->l_un.label = calloc(1, len + 1)) == NULL)
            ArgusLog (LOG_ERR, "RaProcessRecord: calloc error %s", strerror(errno));

         l1->hdr.argus_dsrvl8.len = 1 + len;
         bcopy (label, l1->l_un.label, slen);
      }

      free(l2->l_un.label);
      ArgusFree(l2);

   } else {
      argus->dsrs[ARGUS_LABEL_INDEX] = (struct ArgusDSRHeader*) l2;
      argus->dsrindex |= (0x1 << ARGUS_LABEL_INDEX);
   }

   ArgusFree(buf);
#ifdef ARGUSDEBUG
   ArgusDebug (7, "ArgusAddToRecordLabel (%p, %p, %s) returning %d\n", parser, argus, tlabel, retn);
#endif

   return retn;
}

struct ArgusRecordStruct *
ArgusLabelRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;
   struct ArgusRecordStruct *retn = argus;
   char label[MAXSTRLEN];
   int found = 0, slen = 0;
   char *rstr = NULL;

   if (labeler == NULL)
      return (retn);

   bzero(label, MAXSTRLEN);

   if (labeler->RaLabelIanaAddress) {
      if ((rstr = RaAddressLabel (parser, argus)) != NULL) {
         if (found) {
            snprintf (&label[slen], MAXSTRLEN - slen, ":");
            slen++;
         }
         snprintf (&label[slen], MAXSTRLEN - slen, "%s", rstr);
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
                           snprintf (&label[slen], MAXSTRLEN - slen, ":");
                           slen++;
                        }
                        snprintf (&label[slen], MAXSTRLEN - slen, "sname=%s", addrstr);
                        found++;
                     }
                  }
               }
               if (labeler->RaLabelBindName & ARGUS_DST_ADDR) {
                  slen = strlen(label);
                  if ((addrstr = ArgusGetName (parser, (unsigned char *)&flow->ip_flow.ip_dst)) != NULL) {
                     if (strcmp(addrstr, "not resolved")) {
                        if (found) {
                           snprintf (&label[slen], MAXSTRLEN - slen, ":");
                           slen++;
                        }
                        snprintf (&label[slen], MAXSTRLEN - slen, "dname=%s", addrstr);
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
                                 snprintf (&label[slen], MAXSTRLEN - slen, ":");
                                 slen++;
                              }
                              snprintf (&label[slen], MAXSTRLEN - slen, "iname=%s", addrstr);
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
               snprintf (&label[slen], MAXSTRLEN - slen, ":");
               slen++;
            }
            snprintf (&label[slen], MAXSTRLEN - slen, "%s", rstr);
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
               snprintf (&label[slen], MAXSTRLEN - slen, ":");
               slen++;
            }
            snprintf (&label[slen], MAXSTRLEN - slen, "%s", rstr);
            found++;
         }
      }
   }

   if (labeler->RaLabelLocality) {
      if ((rstr = RaLocalityLabel (parser, argus)) != NULL) {
         if (strlen(rstr)) {
            slen = strlen(label);
            if (found) {
               snprintf (&label[slen], MAXSTRLEN - slen, ":");
               slen++;
            }
            snprintf (&label[slen], MAXSTRLEN - slen, "%s", rstr);
            found++;
         }
      }
   }

   if (labeler->RaLabelArgusFlowService) {
      if ((rstr = RaServiceLabel (parser, argus)) != NULL) {
         if (strlen(rstr)) {
            slen = strlen(label);
            if (found) {
               snprintf (&label[slen], MAXSTRLEN - slen, ":");
               slen++;
            }
            snprintf (&label[slen], MAXSTRLEN - slen, "%s", rstr);
            found++;
         }
      }
   }


#if defined(ARGUS_GEOIP)
   ArgusLabelRecordGeoIP(parser, argus, label, MAXSTRLEN, &found);
#elif defined(ARGUS_GEOIP2)
   ArgusLabelRecordGeoIP2(parser, argus, label, MAXSTRLEN, &found);
#endif

   if (found)
      ArgusAddToRecordLabel (parser, argus, label);

   retn->status |=  ARGUS_RECORD_MODIFIED;
   return (retn);
}


// 
// Labels are metadata, and use metadata conventions for format, syntax, etc... 
// 
// Historically, label metadata was a string of colon separated fields.  This proved
// to be somewhat limiting, and so JSON style formats were adopted in late 2019.
// To distinquish one from the other, is the occurence of a '{', a JSON object delimimter,
// as the first char, if not there, then it is consider a legacy format and parsed.
// 
// Merging the label object is either an intersection of the label objects in
// the two records,  or a union of the two labels.
//
// OK, the label syntax is:
//    label[:label]
//    label :: [object=]word[,word[;[object=]word[,word]]]
//    word  :: value,array
//    value :: value,array
//    array :: [value, ...]
//
// So when we merge these together, we'd like to preserve the labels and the object
// specification, and by default we'll do the union, to see that that goes.


#define ARGUS_MAX_LABEL_VALUES		32
struct ArgusLabelObject {
   char *object;
   int count;
   char *values[ARGUS_MAX_LABEL_VALUES]; 
};


char *ArgusMergeLabel(char *, char *, char *, int, int);
char *ArgusConvertLabelToJson(char *, char *, int);

// char *ArgusMergeLabel(struct ArgusLabelStruct *l1, struct ArgusLabelStruct *l2, char *buf, int len, int type)
//
// This routine merges argus label meta-data.  The types of merging possible are:
//    ARGUS_UNION    Union - Where all the attributes and values are simple added to the label
//    ARGUS_INTER    Intersection - Where only the attributes that are in common are retained
//    ARGUS_REPLACE  Replace - When the attributes are in common, the values are replaced.

char *
ArgusConvertLabelToJson(char *label, char *buf, int len)
{
   char *retn = NULL, *ptr, *sptr, *obj;
   int slen, format = 0;
   int i, x; 
   
// first parse all the attributes and values. This system limits the 
// number of attributes to 256 and ARGUS_MAX_LABEL_VALUES per attribute.

#define ARGUS_LEGACY_LABEL	1
#define ARGUS_JSON_LABEL	2

   if (label != NULL) {
      sptr = ptr = strdup(label);

      while (*sptr && isspace((int)*sptr)) sptr++;
      if ((strchr(sptr, '{')) || (strchr(sptr, '"'))) {
         format = ARGUS_JSON_LABEL;
      } else {
         format = ARGUS_LEGACY_LABEL;
      }

      switch (format) {
         case ARGUS_LEGACY_LABEL: {
            struct ArgusLabelObject *llabs = NULL;
            int llabsindex = 0;

            if ((llabs = ArgusCalloc(256, sizeof(struct ArgusLabelObject))) == NULL)
               ArgusLog (LOG_ERR, "ArgusConvertLabelToJson: ArgusCalloc error %s", strerror(errno));

            while ((obj = strtok(sptr, ":")) != NULL) {
               if (llabsindex < 256) {
                  llabs[llabsindex].object = strdup(obj);
                  llabsindex++;
               }     
               sptr = NULL; 
            }

            for (i = 0; i < llabsindex; i++) {
               if ((obj = llabs[i].object) != NULL) {
                  if ((sptr = strchr(obj, '=')) != NULL) {
                     int vind = 0;
                     char *val;

                     *sptr++ = '\0';
                     while ((val = strtok(sptr, ",")) != NULL) {
                        llabs[i].values[vind++] = strdup(val);
                        sptr = NULL;
                     }
                     llabs[i].count = vind;
                  }
               }
            }

            sprintf(buf, "{ ");
            for (i = 0; i < llabsindex; i++) {
               int slen = strlen(buf);
               if (i > 0) {
                  snprintf(&buf[slen], 1024, ",");
                  slen++;
               }

               if ((obj =  llabs[i].object) != NULL) {
                  snprintf(&buf[slen], 1024, "\"%s\":",llabs[i].object);

                  if (llabs[i].count > 1) {
                     slen = strlen(buf);
                     snprintf(&buf[slen], 1024, "[");
                  }
                  for (x = 0; x < llabs[i].count; x++) {
                     slen = strlen(buf);
                     if (x > 0) {
                        snprintf(&buf[slen], 1024, ",");
                        slen++;
                     }
                     if (llabs[i].values[x]) {
                        int n;
                        float f;
                        if ((sscanf(llabs[i].values[x],"%d",&n) == 1) || (sscanf(llabs[i].values[x],"%f",&f) == 1))
                           snprintf(&buf[slen], 1024, "%s",llabs[i].values[x]);
			else
                           snprintf(&buf[slen], 1024, "\"%s\"",llabs[i].values[x]);
                        free(llabs[i].values[x]);
                     }
                  }
                  if (llabs[i].count > 1) {
                     slen = strlen(buf);
                     snprintf(&buf[slen], 1024, "]");
                  }
                  free(obj);
               }
            }
            slen = strlen(buf);
            snprintf(&buf[slen], 1024, " }");
            retn = buf;

            if (llabs != NULL) ArgusFree(llabs);
            break;
         }

         case ARGUS_JSON_LABEL: {
            if (*sptr != '{') {
               snprintf(buf, 1024, "{ %s }", label);
            } else {
               snprintf(buf, 1024, "%s", label);
            }
            retn = buf;
            break;
         }
      }
      if (ptr != NULL) free(ptr);
   }
   return (retn);
}


char *
ArgusMergeLabel(char *l1, char *l2, char *buf, int len, int type)
{
   ArgusJsonValue l1root, l2root, *res1 = NULL, *res2 = NULL;
   char *l1str = NULL, *l2str = NULL, *retn = NULL;
   char *l1buf = NULL, *l2buf = NULL;

   bzero(&l1root, sizeof(l1root));
   bzero(&l2root, sizeof(l2root));

   if ((l1 != NULL) && (l2 != NULL)) {
      if (strcmp(l1, l2) == 0) 
         return retn;
   }

   if (l1 != NULL) {
      if ((l1buf = (void *)ArgusCalloc(1, MAXSTRLEN)) == NULL)
         ArgusLog (LOG_ERR, "ArgusMergeLabel: ArgusCalloc error %s\n", strerror(errno));

      if ((l1str = ArgusConvertLabelToJson(l1, l1buf, MAXSTRLEN)) != NULL) {
         res1 = ArgusJsonParse(l1str, &l1root);
      }
   }

   if (l2 != NULL) {
      if ((l2buf = (void *)ArgusCalloc(1, MAXSTRLEN)) == NULL)
         ArgusLog (LOG_ERR, "ArgusMergeLabel: ArgusCalloc error %s\n", strerror(errno));

      if ((l2str = ArgusConvertLabelToJson(l2, l2buf, MAXSTRLEN)) != NULL) {
         res2 = ArgusJsonParse(l2str, &l2root);
      }
   }

// OK, at this point were ready to go, just go through all the attributes
// first in l1 and then in l2, and create the actual label string.

   if (res1 && res2) {
      ArgusJsonValue *result;
      if ((result = ArgusJsonMergeValues(res1, res2)) != NULL) {
         retn = ArgusJsonPrint(result, buf, len);
         json_free_value(result);
      }
   }

   if (l1buf != NULL) ArgusFree(l1buf);
   if (l2buf != NULL) ArgusFree(l2buf);

   if (res1 != NULL) json_free_value(res1);
   if (res2 != NULL) json_free_value(res2);

   return (retn);
}

char *
ArgusUpgradeLabel(char *label, char *buf, int len)
{
   char *retn = NULL;
   int slen;

// First is to correct key '=' value to key ':' value.
// If we find '=', we'll assume legacy label format and
// convert ':' object delimiters as well.

   if (!(strchr(label, '{'))) {
      if (strchr(label, '=')) {
         char *tlabel = strdup(label);
         char *tvalue;

         if ((tvalue = (void *)ArgusCalloc(1, MAXSTRLEN)) == NULL)
            ArgusLog (LOG_ERR, "ArgusUpgradeLabel: ArgusCalloc error %s\n", strerror(errno));

         char *tptr, *sptr = tlabel;
         char *key = NULL, *value = NULL;
//       int cnt = 0;

         snprintf(buf, len, "{");
         slen = 1;

         while ((tptr = strtok(sptr, ":")) != NULL) {
            char *nptr;
            if ((nptr = strchr(tptr, '=')) != NULL) {
               *nptr++ = '\0';
               key = tptr;
               value = nptr;

               if (strchr(value, ',')) {
                  if (!(strchr(value, '['))) {
                     snprintf(tvalue, 1024, "[%s]", value);
                     value = tvalue;
                  }
               }

               slen = strlen(buf);
               if (*key != '\"') {
                  snprintf (&buf[slen], MAXSTRLEN - slen, "\"%s\":%s", key, value);
               } else {
                  snprintf (&buf[slen], MAXSTRLEN - slen, "%s:%s", key, value);
               }
            }
            sptr = NULL;
//          cnt++;
         }

         slen = strlen(buf);
         snprintf(buf, (len - slen), "}");
         free(tlabel);
         ArgusFree(tvalue);
      }

      if (strchr(buf, '{')) {
      } else {
         char *tlabel = strdup(label);
         char *tvalue;

         if ((tvalue = (void *)ArgusCalloc(1, MAXSTRLEN)) == NULL)
            ArgusLog (LOG_ERR, "ArgusUpgradeLabel: ArgusCalloc error %s\n", strerror(errno));

         char *sptr = tlabel;
         char *key = NULL, *value = NULL;

         if ((sptr = strchr(tlabel, ':')) != NULL) {
            *sptr++ = '\0';
            key = tlabel;
            value = sptr;

            if (strchr(value, ',')) {
               if (!(strchr(value, '['))) {
                  snprintf(tvalue, 1024, "[%s]", value);
                  value = tvalue;
               }
            }

            slen = strlen(buf);
            if (*key != '\"') {
               snprintf (&buf[slen], 1024 - slen, "{ \"%s\":%s }", key, value);
            } else {
               snprintf (&buf[slen], 1024 - slen, "{ %s:%s }", key, value);
            }
         }
         free(tlabel);
         ArgusFree(tvalue);
      }

      if (strlen(buf) > 0) {
         retn = buf;
      }
   }
   return retn;
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
   char *strbuf;
   char *filter = NULL, *label = NULL, *color = NULL;
   char *ptr, *end;

   int retn = 1;
   int linenum = 0;
   FILE *fd =  NULL;

   if (labeler != NULL) {
      if ((strbuf = ArgusCalloc(1, MAXSTRLEN)) == NULL)
         ArgusLog (LOG_ERR, "RaInsertRIRTree: ArgusCalloc error %s\n", strerror(errno));

      if (labeler->ArgusFlowQueue == NULL)
         if ((labeler->ArgusFlowQueue = ArgusNewQueue()) == NULL)
            ArgusLog (LOG_ERR, "RaReadAddressConfig: ArgusNewList error %s\n", strerror(errno));

      if ((fd = fopen (file, "r")) != NULL) {
         while ((ptr = fgets (strbuf, MAXSTRLEN, fd)) != NULL) {
            linenum++;
            if (*ptr) while (isspace((int)*ptr)) ptr++;

            if (*ptr && (*ptr != '\n') && (*ptr != '!')) {
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
                     int i, done = 0, cont = 0, defined = 0;

                     while (!done) {
                        for (i = 0; i < ARGUS_RCITEMS; i++) {
                           if (!(strncmp(ptr, ArgusFlowLabelFields[i], strlen(ArgusFlowLabelFields[i])))) {
                              char *value = NULL;

                              ptr = ptr + strlen(ArgusFlowLabelFields[i]); 
                              while (*ptr && isspace((int)*ptr)) ptr++;

                              if (!(*ptr == '=') && (i != ARGUS_RC_CONT))
                                 ArgusLog (LOG_ERR, "ArgusParseFlowLabeler: syntax error line %d %s", linenum, strbuf);

                              ptr++;
                              if (*ptr) while (*ptr && isspace((int)*ptr)) ptr++;

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

                              if (*ptr) while (*ptr && isspace((int)*ptr)) ptr++;
                              defined++;
                           }
                        }

                        if (!(done || defined))
                           ArgusLog (LOG_ERR, "ArgusParseAggregator: syntax error line %d: %s", linenum, strbuf);

                        if (ptr && ((*ptr == '\n') || (*ptr == '\0')))
                           done++;
                     }

                     if (defined) {
                        struct RaFlowLabelStruct *raflow = NULL;
                        if ((raflow = (void *)ArgusCalloc(1, sizeof(*raflow))) != NULL) {
                           if (filter != NULL) {
                              raflow->filterstr = filter; filter = NULL;
                              if (ArgusFilterCompile (&raflow->filter, raflow->filterstr, ArgusParser->Oflag) < 0)
                                 ArgusLog (LOG_ERR, "RaReadFlowLabels ArgusFilterCompile returned error");
                           }

                           if (label != NULL) {
                              raflow->labelstr = label;
                              label = NULL;
                           }

                           if (color != NULL) {
                              raflow->colorstr = color;
                              color = NULL;
                           }

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
            bzero(strbuf, MAXSTRLEN);
         }
         fclose(fd);

      } else
         ArgusLog (LOG_ERR, "%s: %s", file, strerror(errno));

      if (filter != NULL) free(filter);
      if (label != NULL) free(label);
      if (color != NULL) free(color);

      ArgusFree(strbuf);
   }
 
#ifdef ARGUSDEBUG
   ArgusDebug (7, "RaReadFlowLabels (0x%x, 0x%x, %s) returning %d\n", parser, labeler, file, retn);
#endif
 
   return (retn);
}


struct RaAddressStruct *RaFindAddress (struct ArgusParserStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);
struct RaAddressStruct *RaInsertAddress (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);

void RaInsertRIRTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *);
int RaInsertAddressTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *, char *);
int RaInsertLocalityTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *);

struct RaAddressStruct *
RaFindAddress (struct ArgusParserStruct *parser, struct RaAddressStruct *tree, struct RaAddressStruct *node, int mode)
{
   struct RaAddressStruct *retn = NULL;
   int done = 0;

   while (!done) {
     unsigned int mask, taddr, naddr;

      switch (node->addr.type) {
         case AF_INET: {
            if (tree != NULL) {
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
                        }

                     case ARGUS_MASK_MATCH: 
                        if (tree->addr.masklen >= node->addr.masklen) {
                           retn = tree;
                           done++;
                           break;
                        }

                     case ARGUS_EXACT_MATCH: 
                        if ((node->addr.masklen == tree->addr.masklen) &&
                            (node->addr.addr[0] == tree->addr.addr[0]))
                           retn = tree;
                        else
                        if (tree->l || tree->r) {
                           if ((node->addr.addr[0] >> (32 - (tree->addr.masklen + 1))) & 0x01)
                             retn = RaFindAddress (parser, tree->l, node, mode);
                           else
                             retn = RaFindAddress (parser, tree->r, node, mode);
                        }
                        done++;
                        break;

                     case ARGUS_SUPER_MATCH: 
                        if ((node->addr.masklen == tree->addr.masklen) &&
                            (node->addr.addr[0] == tree->addr.addr[0]))
                           retn = tree;
                        else
                        if ((tree->l == NULL) && (tree->r == NULL)) {
                           retn = tree;
                        } else
                        if (tree->l || tree->r) {
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
                  
                  if ((mode == ARGUS_NODE_MATCH) && (retn == NULL)) {

// In one case we went down the tree and no matches ... this node matches however, and has a label,
// we should return this node as a match ...

                     if ((tree->addr.masklen > 16) || ((tree->addr.masklen + 4) > node->addr.masklen) || (tree->label != NULL))
                        retn = tree;
                     done++;
                  }

               } else  {
                  if (mode == ARGUS_MASK_MATCH) {
                     if (tree->addr.masklen > node->addr.masklen) {
                        if (node->addr.masklen > 0)
                           mask = 0xFFFFFFFF << (32 - node->addr.masklen);
                        else
                           mask = 0;
                        taddr = tree->addr.addr[0] & mask;
                        naddr = node->addr.addr[0] & mask;
                        if (taddr == naddr)
                           retn = tree;
                     }
                  }
                  done++;
               }
            } else
               done++;
            break;
         }

         case AF_INET6: {
            struct in6_addr naddr = *(struct in6_addr *)node->addr.addr;
            char ntop_buf[INET6_ADDRSTRLEN];
            const char *cp;
 
            if ((cp = inet_ntop(AF_INET6, (const void *) &naddr, ntop_buf, sizeof(ntop_buf))) != NULL) {
               struct cnamemem *cptr;
               extern struct cnamemem ipv6cidrtable[HASHNAMESIZE];
  
               cptr = check_cmem(ipv6cidrtable, (const u_char *) cp);
  
               if (cptr != NULL) {
                  retn = cptr->node;
               }
            }
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
   int retn = 1;
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
      switch (node->addr.type) {
         case AF_INET: {
            ArgusAddrTree[node->addr.type] = node;
            node->status |= ARGUS_NODE | status;
            labeler->count = 1;
            return (node);
            break;
         }
         case AF_INET6: {
            break;
         }
      }
   }

// OK, IPv4 and IPv6 address trees are handled differently ...
// For the moment, we'll use patricia trees for IPv4 and a hashed array for IPv6
//
// So we need to decend into the tree, and insert this record,
// and any additional interior nodes, needed.
// As long as the new node, and the current nodes masked addrs
// are equal, then we just needed to decend either left of right.

   if (ArgusNodesAreEqual(tree, node)) {
      ArgusUpdateNode(tree, node);
      tree->status |= status;
      return (NULL);

   } else {
      unsigned int taddr, naddr;
      unsigned int tmask, nmask;

      switch (node->addr.type) {
         case AF_INET: {
            if (tree == NULL) tree = ArgusAddrTree[node->addr.type];

            tree->status |= status;
            node->status |= status;

            tmask = tree->addr.mask[0];
            taddr = tree->addr.addr[0] & tmask;
            naddr = node->addr.addr[0] & tmask;

            if (naddr == taddr) {     // node and tree address are same, but may not be at right part in tree
               if (node->addr.masklen == tree->addr.masklen) {  // node is in the tree ... done.
                  retn = node;
               } else
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

                           for (; i <= node->addr.masklen; i++) {
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
                              RaInsertAddress (parser, labeler, tree->l, lt, status);
                              return (node);

                           } else {
                              struct RaAddressStruct *addr = NULL;

                              if ((addr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*addr))) == NULL)
                                 ArgusLog (LOG_ERR, "RaInsertAddress: ArgusCalloc error %s\n", strerror(errno));

                              bcopy ((char *)&node->addr, (char *)&addr->addr, sizeof(addr->addr));
                              if (node->addr.str != NULL)
                                 addr->addr.str = strdup(node->addr.str);

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
                        tree->r = node;
                        node->p = tree;
                        retn = node;
   
                     } else {
                        struct RaAddressStruct *rt = tree->r;

                        if (node->addr.masklen < rt->addr.masklen) {
                           int maskn = node->addr.masklen;
                           int i = tree->addr.masklen + 1;

                           for (; i <= node->addr.masklen; i++) {
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
                              RaInsertAddress (parser, labeler, tree->r, rt, status);
                              return (node);

                           } else {
                              struct RaAddressStruct *addr = NULL;

                              if ((addr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*addr))) == NULL)
                                 ArgusLog (LOG_ERR, "RaInsertAddress: ArgusCalloc error %s\n", strerror(errno));

                              bcopy ((char *)&node->addr, (char *)&addr->addr, sizeof(addr->addr));
                              if (node->addr.str != NULL)
                                 addr->addr.str = strdup(node->addr.str);

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
    
               value = taddr ^ naddr;
               value = ~value;
               value &= tmask;
               value = value << tree->offset;

               for (i = 0; i < len; i++) {
                  if (value & 0x80000000) {
                     masklen++;
                     value = value << 1;
                  } else
                     break;
               }

// Need to add a node, create it here.

               if ((addr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*addr))) == NULL)
                  ArgusLog (LOG_ERR, "RaInsertAddress: ArgusCalloc error %s\n", strerror(errno));

               bcopy ((char *)&tree->addr, (char *)&addr->addr, sizeof(addr->addr));

//             if (tree->addr.str != NULL)
//                addr->addr.str = strdup(tree->addr.str);

               addr->addr.str = NULL;
               addr->offset = tree->offset;
               addr->status = status;

               if (ptree != NULL) {
                  if ((ptree->addr.masklen + masklen) <= node->addr.masklen)
                     addr->addr.masklen = ptree->addr.masklen + masklen;
                  else 
                     addr->addr.masklen = masklen;
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
            labeler->count++;
            break;
         }

         case AF_INET6: {
// So we'll do a hash table for the time being and figure out the best 
// patricia way a little later
// get the address string and then hash it as a generic string.

            struct in6_addr naddr = *(struct in6_addr *)node->addr.addr;
            char ntop_buf[INET6_ADDRSTRLEN];
            const char *cp;
 
            if ((cp = inet_ntop(AF_INET6, (const void *) &naddr, ntop_buf, sizeof(ntop_buf))) != NULL) {
               struct cnamemem *cptr;
               extern struct cnamemem ipv6cidrtable[HASHNAMESIZE];
  
               cptr = check_cmem(ipv6cidrtable, (const u_char *) cp);
  
               if (cptr != NULL) {
                  retn = cptr->node;
               } else {
                  cptr = lookup_cmem(ipv6cidrtable, (const u_char *) cp);
                  cptr->node = node;
                  retn = node;
               }
            }

            break;
         }
      }

      if (retn != NULL)
         retn->status |= status | ARGUS_NODE;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "RaInsertAddress (0x%x, 0x%x, 0x%x, 0x%x) returning 0x%x\n", parser, ArgusAddrTree, node, status, retn);
#endif

   return (retn);
}

void RaDeleteAddressTree(struct ArgusLabelerStruct *, struct RaAddressStruct *);
char *RaPruneAddressTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);
int RaTimeoutAddressTree(struct ArgusLabelerStruct *,struct RaAddressStruct *node, struct timeval *, struct timeval *);
unsigned int RaStatusAddressTree(struct RaAddressStruct *node, unsigned int mask);

void
RaDeleteAddressTree(struct ArgusLabelerStruct *labeler, struct RaAddressStruct *node)
{
   if (node->p != NULL) {
      if (node->p->l == node)
         node->p->l = NULL;
      if (node->p->r == node)
         node->p->r = NULL;
   } else {
      if (labeler != NULL) {
         struct RaAddressStruct **ArgusAddrTree = labeler->ArgusAddrTree;
         if (node == ArgusAddrTree[node->addr.type])
            ArgusAddrTree[node->addr.type] = NULL;

         if (node->status & ARGUS_NODE)
            labeler->count--;
      }
   }

   if (node->l) RaDeleteAddressTree(labeler, node->l);
   if (node->r) RaDeleteAddressTree(labeler, node->r);

   if (node->addr.str) { free(node->addr.str); node->addr.str = NULL;}
   if (node->str)      { free(node->str); node->str = NULL;}
   if (node->group)    { free(node->group); node->group = NULL;}
   if (node->label)    { free(node->label); node->label = NULL;}

   if (node->dns)      { ArgusFree(node->dns); node->dns = NULL;}
   if (node->obj)      { ArgusFree(node->obj); node->obj = NULL;}

   if (node->asnlabel) { free(node->asnlabel); node->asnlabel = NULL;}
   if (node->ns) {ArgusDeleteRecordStruct(ArgusParser, node->ns); node->ns = NULL;}

   ArgusFree(node);
}

unsigned int
RaStatusAddressTree(struct RaAddressStruct *node, unsigned int mask)
{
   unsigned int retn = 0;
   if (node->l) retn |= RaStatusAddressTree(node->l, mask);
   if (node->r) retn |= RaStatusAddressTree(node->r, mask);
   if ((node->l == NULL) && (node->r == NULL))
      retn = node->status & mask;

   return (retn);
}

int
RaTimeoutAddressTree(struct ArgusLabelerStruct *labeler, struct RaAddressStruct *node, struct timeval *timeout, struct timeval *currentTime)
{
   int retn = 0;
   if (node != NULL) {
      if (node->rtime.tv_sec == 0) 
         node->rtime = *currentTime;

      if (((node->rtime.tv_sec  + timeout->tv_sec)  < currentTime->tv_sec) ||
         (((node->rtime.tv_sec  + timeout->tv_sec)  == currentTime->tv_sec) &&
          ((node->rtime.tv_usec + timeout->tv_usec) <  currentTime->tv_usec))) {
         RaDeleteAddressTree(labeler, node);
         retn = 1;

      } else {
         if (node->l || node->r) {
            if (node->l) retn |= RaTimeoutAddressTree(labeler, node->l, timeout, currentTime);
            if (node->r) retn |= RaTimeoutAddressTree(labeler, node->r, timeout, currentTime);
         }
      }
   }
   return (retn);
}


char *
RaPruneAddressTree (struct ArgusLabelerStruct *labeler, struct RaAddressStruct *node, int mode, int level)
{
   char *retn = NULL, *lstr = NULL, *rstr = NULL;

   if (node != NULL) {
      switch (mode & 0xFF) {
         case ARGUS_TREE_PRUNE_CCO:
         case ARGUS_TREE_PRUNE_GROUP:
         case ARGUS_TREE_PRUNE_LABEL: {
            if (node->l || node->r) {   // if we have sub-trees, grab the labels below.
               if ((lstr = RaPruneAddressTree(labeler, node->l, mode, level)) != NULL) {
                  if (mode & ARGUS_TREE_PRUNE_ADJ)
                     if (node->addr.masklen != (node->l->addr.masklen - 1))
                        lstr = NULL;
                  if (level > 0)
                     if (node->addr.masklen < level)
                        lstr = NULL;
               }

               if ((rstr = RaPruneAddressTree(labeler, node->r, mode, level)) != NULL) {
                  if (mode & ARGUS_TREE_PRUNE_ADJ)
                     if (node->addr.masklen != (node->r->addr.masklen - 1))
                        rstr = NULL;
                  if (level > 0)
                     if (node->addr.masklen < level)
                        rstr = NULL;
               }

               if (node->l && node->r) {
                  if (lstr && rstr) {    // the idea here is to propagate up the label, group, or country 
                                         // code so that if they are equal, then we can trim
                                         // the tree, by removing everything below.
                     int llen = strlen(lstr);
                     int rlen = strlen(rstr);
                     if (llen && rlen) {
                        if (mode & ARGUS_TREE_DNS_TLD) {
                           char *ltld = NULL, *rtld = NULL;
                           int ind = llen - 1;
                           while (lstr[ind] == '.') ind--;
                           while (ind && (lstr[ind] != '.')) ind--;
                           if (lstr[ind] != '.') ltld = &lstr[ind];
                           else                  ltld = &lstr[ind + 1];

                           ind = rlen - 1;
                           while (rstr[ind] == '.') ind--;
                           while (ind && (rstr[ind] != '.')) ind--;
                           if (rstr[ind] != '.') rtld = &rstr[ind];
                           else                  rtld = &rstr[ind + 1];

                           if (!(strcmp(ltld, rtld))) {
                              retn = lstr;  // children are equal, so propagate up for comparison
                           } 

                        } else 
                        if (mode & ARGUS_TREE_DNS_SLD) {
                           char *lsld = NULL, *rsld = NULL;
                           int ind = llen - 1, sld = 0; 

                           while (lstr[ind] == '.') ind--;
                           while (ind   && (lstr[ind] != '.')) ind--;
                           if (ind) {ind--; sld = 1;}
                           while (ind && (lstr[ind] != '.')) ind--;

                           if (sld) {
                              if (lstr[ind] != '.') lsld = &lstr[ind];
                              else                  lsld = &lstr[ind + 1];
                           }

                           ind = rlen - 1, sld = 0;

                           while (rstr[ind] == '.') ind--;
                           while (ind && (rstr[ind] != '.')) ind--;
                           if (ind) {ind--; sld = 1;}
                           while (ind && (rstr[ind] != '.')) ind--;

                           if (rstr[ind] != '.') rsld = &rstr[ind];
                           else                  rsld = &rstr[ind + 1];

                           if (lsld && rsld) {
                              if (!(strcmp(lsld, rsld))) {
                                 retn = lsld;  // children are equal, so propagate up for comparison
                              }
                           }

                        } else
                        if (!(strcmp(lstr, rstr))) {
                           node->locality = min(node->l->locality, node->r->locality);
                           retn = lstr;  // children are equal, so propagate up for comparison
                        } 
                     }
                  }

               } else {
                  if (node->l)
                     retn = lstr;
                  
                  if (node->r)
                     retn = rstr;
               }

               if (retn && strlen(retn)) {              // there is a child label, so compare to current
                  char *str = NULL;

                  switch (mode & 0xFF) {
                     case ARGUS_TREE_PRUNE_CCO: {
                        str = node->cco;
                        break;
                     }
                     case ARGUS_TREE_PRUNE_GROUP: {
                        str = node->group;
                        break;
                     }
                     case ARGUS_TREE_PRUNE_LABEL: {
                        str = node->label;
                        break;
                     }
                  }

                  if (str && strlen(str)) {             // cco can be a null string
                     if ((strcmp(str, retn)))           // if sub-tree labels aren't equal to current
                                                        // then nothing to propagate up .... return NULL
                        retn = NULL;
                  } else {
                     switch (mode & 0x0F) {
                        case ARGUS_TREE_PRUNE_CCO: {
                           strncpy(node->cco, retn, sizeof(node->cco));
                           retn = node->cco;
                           break;
                        }
                        case ARGUS_TREE_PRUNE_GROUP: {
                           node->group = strdup(retn);
                           retn = node->group;
                           break;
                        }
                        case ARGUS_TREE_PRUNE_LABEL: {
                           node->label = strdup(retn);
                           retn = node->label;
                           break;
                        }
                     }
                  }
               }

            } else {                                     // if there are no children, then give back current label
               switch (mode & 0xFF) {
                  case ARGUS_TREE_PRUNE_CCO: {     
                     retn = node->cco;
                     break;
                  }
                  case ARGUS_TREE_PRUNE_GROUP: {
                     retn = node->group;
                     break;
                  }
                  case ARGUS_TREE_PRUNE_LABEL: {
                     retn = node->label;
                     break;
                  }
               }
            }

            if (retn != NULL) {                         // at this point, we can prune the tree.
               if (node->l) {
                  RaDeleteAddressTree(labeler, node->l);
                  node->l = NULL;
               }
               if (node->r) {
                  RaDeleteAddressTree(labeler, node->r);
                  node->r = NULL;
               }
            }
            break;
         }

         case ARGUS_TREE_PRUNE_ASN: {
            char *lstr = NULL, *rstr = NULL;

            if (node->l != NULL) lstr = RaPruneAddressTree(labeler, node->l, mode, 0);
            if (node->r != NULL) rstr = RaPruneAddressTree(labeler, node->r, mode, 0);

            if (lstr || rstr) {    // if we have prunable sub-trees, check this level
               if (lstr && rstr) {
                  if ((node->l->asn || node->r->asn) &&
                     ((node->l->asn  == node->r->asn) &&
                      (node->l->addr.mask[0] == node->r->addr.mask[0]))) {
                     node->asn = node->l->asn;
                     RaDeleteAddressTree(labeler, node->l);
                     RaDeleteAddressTree(labeler, node->r);
                     node->l = NULL;
                     node->r = NULL;
                     retn = lstr;
                  }

               } else {
                  if (node->l && node->r)
                     retn = NULL;
                  else
                     retn = "TRUE";

                  if (lstr) {
                     if (node->l->asn && (node->l->asn == node->asn)) {
                        RaDeleteAddressTree(labeler, node->l);
                        node->l = NULL;
                     } else
                        retn = NULL;
                  }

                  if (rstr) {
                     if (node->r->asn && (node->r->asn == node->asn)) {
                        RaDeleteAddressTree(labeler, node->r);
                        node->r = NULL;
                     } else
                        retn = NULL;
                  }
               }

            } else
               if (!(node->l || node->r))
                  retn = "TRUE";

            break;
         }
         case ARGUS_TREE_PRUNE_LOCALITY: {
            char *lstr = NULL, *rstr = NULL;

            if (node->l != NULL) lstr = RaPruneAddressTree(labeler, node->l, mode, 0);
            if (node->r != NULL) rstr = RaPruneAddressTree(labeler, node->r, mode, 0);

            if (lstr || rstr) {    // if we have prunable sub-trees, check this level
               if (lstr && rstr) {
                  if ((node->l->locality || node->r->locality) &&
                     ((node->l->locality  == node->r->locality) &&
                      (node->l->addr.mask[0] == node->r->addr.mask[0]))) {
                     node->locality = node->l->locality;
                     RaDeleteAddressTree(labeler, node->l);
                     RaDeleteAddressTree(labeler, node->r);
                     node->l = NULL;
                     node->r = NULL;
                     retn = lstr;
                  }

               } else {
                  if (node->l && node->r)
                     retn = NULL;
                  else
                     retn = "TRUE";

                  if (lstr) {
                     if (node->l->locality && (node->l->locality == node->locality)) {
                        RaDeleteAddressTree(labeler, node->l);
                        node->l = NULL;
                     } else
                        retn = NULL;
                  }

                  if (rstr) {
                     if (node->r->locality && (node->r->locality == node->locality)) {
                        RaDeleteAddressTree(labeler, node->r);
                        node->r = NULL;
                     } else
                        retn = NULL;
                  }
               }

            } else
               if (!(node->l || node->r))
                  retn = "TRUE";

            break;
         }

         case ARGUS_TREE_PRUNE_RECORD: {
            if (node->ns)
               retn = "TRUE";

            if (node->l != NULL) {
               if ((lstr = RaPruneAddressTree(labeler, node->l, mode, 0)) == NULL) {
                  RaDeleteAddressTree(labeler, node->l);
                  node->l = NULL;
               }
            }

            if (node->r != NULL) {
               if ((rstr = RaPruneAddressTree(labeler, node->r, mode, 0)) == NULL) {
                  RaDeleteAddressTree(labeler, node->r);
                  node->r = NULL;
               }
            }

            break;
         }
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
               if (addr->str != NULL)
                  cidr->str = strdup(addr->str);
 
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
   char *co = NULL, *type = NULL;
   char *addr = NULL;
   char *endptr = NULL;
   int tok = 0, elem = -1, ttype = 0;

   if (labeler != NULL) {
      struct RaAddressStruct **ArgusAddrTree = labeler->ArgusAddrTree;
      char *tstrbuf, *tptr, *sptr = NULL;

      if ((tstrbuf = ArgusMalloc(MAXSTRLEN)) == NULL)
         ArgusLog (LOG_ERR, "RaInsertRIRTree: ArgusCalloc error %s\n", strerror(errno));

      snprintf (tstrbuf, MAXSTRLEN - 1, "%s", str);
      sptr = tstrbuf;

      while ((tptr = strtok(sptr, "|\n")) != NULL) {
         switch (tok++) {
            case 0:                     ; break;
            case 1:  co   = strdup(tptr); break;
            case 2:  type = strdup(tptr); break;
            case 3:  addr = strdup(tptr); break;
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

      if (type && !(strcmp("ipv4", type)))
         ttype = ARGUS_TYPE_IPV4;
      if (type && !(strcmp("ipv6", type)))
         ttype = ARGUS_TYPE_IPV6;

      if (ttype && co && (strcmp ("*", co))) {
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
      if (co      != NULL) free(co);
      if (type    != NULL) free(type);
      if (addr    != NULL) free(addr);
      if (tstrbuf != NULL) ArgusFree(tstrbuf);
   }
}


#define ARGUS_PARSING_START_ADDRESS	0
#define ARGUS_PARSING_END_ADDRESS	1
#define ARGUS_PARSING_LABEL		2
#define ARGUS_PARSING_LOCALITY		3
#define ARGUS_PARSING_ASN		4
#define ARGUS_PARSING_GROUP		5
#define ARGUS_PARSING_DONE		6


int
RaInsertAddressTree (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *str, char *object)
{
   struct RaAddressStruct *saddr = NULL, *node;
   struct ArgusQueueStruct *ArgusAddressQueue = NULL;
   struct ArgusCIDRAddr *cidr, scidr, dcidr;
   char *sptr = NULL, *eptr = NULL, *cptr = NULL;
   char *ptr = NULL, *label = NULL;
   char *tstrbuf, *tptr = NULL;
   long long i, step = 0, arange;
   unsigned int masklen = 32;
   double mstep = 0;
   int retn = 0;

   if (labeler != NULL) {
      struct RaAddressStruct **ArgusAddrTree = labeler->ArgusAddrTree;
      int state = ARGUS_PARSING_START_ADDRESS;
      int slen = (strlen(str) > MAXSTRLEN) ? strlen(str) : MAXSTRLEN;

      if ((tstrbuf = malloc(slen + 1)) == NULL) 
         ArgusLog (LOG_ERR, "RaInsertAddressTree: malloc error %s", strerror(errno));

      snprintf (tstrbuf, slen, "%s", str);
      ptr = tstrbuf;

      while ((sptr = strtok(ptr, "\t\n\r")) != NULL) {
         switch (state) {
            case ARGUS_PARSING_START_ADDRESS: {
               if (strchr(sptr, ',') != NULL) {
                  if (ArgusAddressQueue == NULL)
                     if ((ArgusAddressQueue = ArgusNewQueue()) == NULL)
                        ArgusLog (LOG_ERR, "ArgusReadCiscoDatagramSocket: ArgusNewQueue error %s", strerror(errno));

                  while ((cptr = strsep(&sptr, ",")) != NULL) {
                     if (cptr && ((cidr = RaParseCIDRAddr (parser, cptr)) != NULL)) {
                        if ((saddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*saddr))) != NULL) {
                           bcopy ((char *)cidr, (char *)&saddr->addr, sizeof (*cidr));
                           if (cidr->str != NULL) 
                              saddr->str = strdup(cidr->str);

                           ArgusAddToQueue(ArgusAddressQueue, &saddr->qhdr, ARGUS_LOCK);
                        }
                     }
                  }

               } else {
                  if ((eptr = strchr(sptr, '-')) != NULL)
                     *eptr++ = '\0';

                  if (sptr && ((cidr = RaParseCIDRAddr (parser, sptr)) != NULL))
                     bcopy ((char *)cidr, (char *)&scidr, sizeof (*cidr));

                  if (eptr && ((cidr = RaParseCIDRAddr (parser, eptr)) != NULL))
                     bcopy ((char *)cidr, (char *)&dcidr, sizeof (*cidr));
                  else
                     bcopy ((char *)&scidr, (char *)&dcidr, sizeof (scidr));
               }
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

      if (ArgusAddressQueue != NULL) {
         while ((saddr = (struct RaAddressStruct *) ArgusPopQueue(ArgusAddressQueue, ARGUS_LOCK)) != NULL) {
            if ((node = RaFindAddress (parser, ArgusAddrTree[saddr->addr.type], saddr, ARGUS_EXACT_MATCH)) == NULL) {
               if (tptr) {
                  if (saddr->addr.str) free(saddr->addr.str);
                  saddr->addr.str = strdup(tptr);
               }

               node = RaInsertAddress (parser, labeler, NULL, saddr, ARGUS_VISITED);
                  
               if (label || object) {
                  char lbuf[128];
                  if ((object != NULL) && (label != NULL)) {
                     if (*label == '"') {
                        snprintf(lbuf, 128, "{ \"%s\":{ %s }}", object, label);
                     } else {
                        snprintf(lbuf, 128, "%s.%s", object, label);
                     }
                  } else 
                  if (object != NULL) {
                     snprintf(lbuf, 128, "%s", object);
                  } else 
                  if (label != NULL) {
                     snprintf(lbuf, 128, "%s", label);
                  }

                  if (saddr->label != NULL) {
                     char sbuf[1024], *sptr = NULL;
                     sbuf[0] = '\0';
                     if ((sptr = ArgusMergeLabel(lbuf, saddr->label, sbuf, 1024, ARGUS_UNION)) != NULL) {
                        free(saddr->label);
                        saddr->label = strdup(sbuf);
                     }

                  } else {
                     saddr->label = strdup (lbuf);
                  }
               }

               if (labeler->status & ARGUS_LABELER_DEBUG_NODE) {
                  RaPrintLabelTree (labeler, labeler->ArgusAddrTree[AF_INET], 0, 0);
                  printf("\n");
               }

            } else {
               ArgusFree(saddr);
               saddr = node;

               if (label || object) {
                  char lbuf[128];
                  if ((object != NULL) && (label != NULL)) {
                     if ((*label == '"') || (*label == '{')) {
                        snprintf(lbuf, 128, "{ \"%s\":{ %s }}", object, label);
                     } else {
                        snprintf(lbuf, 128, "%s.%s", object, label);
                     }
                  } else
                  if (object != NULL) {
                     snprintf(lbuf, 128, "%s", object);
                  } else
                  if (label != NULL) {
                     snprintf(lbuf, 128, "%s", label);
                  }

                  if (node->label != NULL) {
                     char sbuf[1024], *sptr = NULL;
                     sbuf[0] = '\0';
                     if ((sptr = ArgusMergeLabel(lbuf, node->label, sbuf, 1024, ARGUS_UNION)) != NULL) {
                        free(node->label);
                        node->label = strdup(sbuf);
                     }

                  } else {
                     node->label = strdup (lbuf);
                  }
               }
            }
         }


      } else {
         {
            long long slen = 0, len = dcidr.addr[0] - scidr.addr[0];

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
                  if (tptr) {
                     if (saddr->addr.str) free(saddr->addr.str);
                     saddr->addr.str = strdup(tptr);
                  }

                  node = RaInsertAddress (parser, labeler, NULL, saddr, ARGUS_VISITED);

                  if (label || object) {
                     char lbuf[128];
                     if ((object != NULL) && (label != NULL)) {
                        if ((*label == '"') || (*label == '{')) {
                           snprintf(lbuf, 128, "{\"%s\":%s}", object, label);
                        } else {
                           snprintf(lbuf, 128, "%s.%s", object, label);
                        }
                     } else
                     if (object != NULL) {
                        if (*object == '{') {
                           snprintf(lbuf, 128, "%s", object);
                        } else {
                           snprintf(lbuf, 128, "{ %s }", object);
                        }
                     } else
                     if (label != NULL) {
                        snprintf(lbuf, 128, "%s", label);
                     }
   
                     if (saddr->label != NULL) {
                        char sbuf[1024], *sptr = NULL;
                        sbuf[0] = '\0';
                        if ((sptr = ArgusMergeLabel(lbuf, saddr->label, sbuf, 1024, ARGUS_UNION)) != NULL) {
                           free(saddr->label);
                           saddr->label = strdup(sbuf);
                        }
                     } else {
                        saddr->label = strdup (lbuf);
                     }
                  }
                  
                  if (labeler->status & ARGUS_LABELER_DEBUG_NODE) {
                     RaPrintLabelTree (labeler, labeler->ArgusAddrTree[AF_INET], 0, 0);
                     printf("\n");
                  }


               } else {
                  ArgusFree(saddr);
                  saddr = node;

                  if (label || object) {
                     char lbuf[128];
                     if ((object != NULL) && (label != NULL)) {
                        if ((*label == '"') || (*label == '{')) {
                           snprintf(lbuf, 128, "{ \"%s\":{ %s }}", object, label);
                        } else {
                           snprintf(lbuf, 128, "%s.%s", object, label);
                        }
                     } else
                     if (object != NULL) {
                        snprintf(lbuf, 128, "%s", object);
                     } else
                     if (label != NULL) {
                        snprintf(lbuf, 128, "%s", label);
                     }

                     if (saddr->label != NULL) {
                        char sbuf[1024], *sptr = NULL;
                        sbuf[0] = '\0';
                        if ((sptr = ArgusMergeLabel(lbuf, saddr->label, sbuf, 1024, ARGUS_UNION)) != NULL) {
                           free(saddr->label);
                           saddr->label = strdup(sbuf);
                        }

                     } else {
                        saddr->label = strdup (lbuf);
                     }
                  }
               }
            }

            mstep = pow (2.0, (32 - saddr->addr.masklen));
            step = mstep;
         }
      }
      free(tstrbuf);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "RaInsertAddressTree (%p, %p, %s, %s) returning %d\n", parser, labeler, str, label, retn);
#endif

   return (retn);
}

void RaLabelMaskAddressStatus(struct RaAddressStruct *, unsigned int);

void
RaLabelMaskAddressStatus(struct RaAddressStruct *addr, unsigned int mask) {
   if (addr->l != NULL) RaLabelMaskAddressStatus(addr->l, mask);
   if (addr->r != NULL) RaLabelMaskAddressStatus(addr->r, mask);
   addr->status &= mask;
}

void RaLabelAddressLocality(struct RaAddressStruct *, int);
void RaLabelAddressAsn(struct RaAddressStruct *, int);
void RaLabelAddressGroup(struct RaAddressStruct *, char *);
void RaLabelSuperAddresses(struct RaAddressStruct *);
void RaLabelSubAddresses(struct RaAddressStruct *);


void
RaLabelAddressLocality(struct RaAddressStruct *addr, int locality)
{
   char buf[16];

   if (ArgusParser->ArgusLocalLabeler && (ArgusParser->ArgusLocalLabeler->RaLabelLocalityOverwrite)) {
      snprintf (buf, 16, "%d", locality);
      addr->locality = locality;
      if (addr->label != NULL) free (addr->label);
      addr->label = strdup(buf);
   } else {
      if (addr->locality < locality) {
         addr->locality = locality;
         snprintf (buf, 16, "%d", locality);
         if (addr->label != NULL) free (addr->label);
         addr->label = strdup(buf);
      }
   }

   if (addr->l != NULL) RaLabelAddressLocality(addr->l, locality);
   if (addr->r != NULL) RaLabelAddressLocality(addr->r, locality);
}

void
RaLabelAddressAsn(struct RaAddressStruct *addr, int asn) {
   if (ArgusParser->ArgusLocalLabeler && (ArgusParser->ArgusLocalLabeler->RaLabelLocalityOverwrite))
      addr->asn = asn;
   else
      if (addr->asn == 0) 
         addr->asn = asn;

   if (addr->l != NULL) RaLabelAddressAsn(addr->l, asn);
   if (addr->r != NULL) RaLabelAddressAsn(addr->r, asn);
}

void
RaLabelAddressGroup(struct RaAddressStruct *addr, char *group) {
   if (ArgusParser->ArgusLocalLabeler && (ArgusParser->ArgusLocalLabeler->RaLabelLocalityOverwrite)) {
      if (addr->group != NULL) free(addr->group);
      addr->group = strdup(group);
   } else
      if (addr->group == NULL)
         addr->group = strdup(group);

   if (addr->l != NULL) RaLabelAddressGroup(addr->l, group);
   if (addr->r != NULL) RaLabelAddressGroup(addr->r, group);
}



int
RaInsertLocalityTree (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *str)
{
   extern struct enamemem elabeltable[HASHNAMESIZE];
   struct RaAddressStruct *saddr = NULL, *node;
   struct ArgusCIDRAddr *cidr, scidr, dcidr;
   char *sptr = NULL, *eptr = NULL, *ptr = NULL;
   char *tstrbuf, *tptr = NULL, *label = NULL, *group = NULL;
   int retn = 0, locality = -1, asn = -1;
   long long i, step = 0, arange;
   unsigned int masklen = 32;
   double mstep = 0;

   if (labeler != NULL) {
      int state = ARGUS_PARSING_START_ADDRESS;
      struct enamemem *tp = NULL;
      int slen = (strlen(str) > MAXSTRLEN) ? strlen(str) : MAXSTRLEN;

      if ((tstrbuf = malloc(slen + 1)) == NULL) 
         ArgusLog (LOG_ERR, "RaInsertAddressTree: malloc error %s", strerror(errno));

      snprintf (tstrbuf, slen, "%s", str);
      ptr = tstrbuf;

      while ((sptr = strtok(ptr, " \t\r\n\"")) != NULL) {
         switch (state) {
            case ARGUS_PARSING_START_ADDRESS: {
               if ((eptr = strchr(sptr, '-')) != NULL)
                  *eptr++ = '\0';

               if (RaIsEtherAddr (parser, sptr)) {
                  tp = lookup_emem(elabeltable, (const u_char *) sptr);
                  if (tp->e_name == NULL) {
                     tp->e_name = savestr(sptr);
                  }
               } else {
                  if (sptr && ((cidr = RaParseCIDRAddr (parser, sptr)) != NULL))
                     bcopy ((char *)cidr, (char *)&scidr, sizeof (*cidr));

                  if (eptr && ((cidr = RaParseCIDRAddr (parser, eptr)) != NULL))
                     bcopy ((char *)cidr, (char *)&dcidr, sizeof (*cidr));
                  else
                     bcopy ((char *)&scidr, (char *)&dcidr, sizeof (scidr));
               }
               state = ARGUS_PARSING_LOCALITY;
               break;
            }

            case ARGUS_PARSING_END_ADDRESS: {
               if (sptr && ((cidr = RaParseCIDRAddr (parser, sptr)) != NULL))
                  bcopy ((char *)cidr, (char *)&dcidr, sizeof (*cidr));
               state = ARGUS_PARSING_LOCALITY;
               break;
            }

            case ARGUS_PARSING_LOCALITY: {
               if (*sptr == '-')
                  state = ARGUS_PARSING_END_ADDRESS;
               else {
               if (sptr != NULL) {
                  char *endptr = NULL;
                  locality = strtod(sptr, &endptr);
                  if (endptr == sptr) {
                     state = ARGUS_PARSING_DONE;
                  } else 
                     state = ARGUS_PARSING_ASN;
               } else
                  state = ARGUS_PARSING_DONE;
               }
               break;
            }

            case ARGUS_PARSING_ASN: {
               if (sptr != NULL) {
                  char *endptr = NULL;
                  asn = strtod(sptr, &endptr);
                  if (endptr == sptr) {
                     state = ARGUS_PARSING_DONE;
                  } else
                     state = ARGUS_PARSING_GROUP;
               } else
                  state = ARGUS_PARSING_DONE;
               break;
            }

            case ARGUS_PARSING_GROUP: {
               if (sptr != NULL) {
                  if (strstr(sptr, "//")) {
                     state = ARGUS_PARSING_DONE;
                  } else {
                     group = sptr;
                  }
               } else
                  state = ARGUS_PARSING_DONE;
               break;
            }

            case ARGUS_PARSING_DONE:
               break;
         }
         ptr = NULL;
      }

//  OK, so we've got the range of addresses to load up into the tree.      
//  Lets figure out a good starting point for the netmask.

      if (tp != NULL) {
         tp->loc = locality;
      } else {
         {
            long long slen = 0, len = dcidr.addr[0] - scidr.addr[0];

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
                     } else {
                        if (arange == 1) {
                        }
                     }
                  }
                  saddr->addr.mask[0] = 0xFFFFFFFF << (32 - saddr->addr.masklen);
                  saddr->addr.addr[0] &= saddr->addr.mask[0];

               } else {
                  bcopy ((char *)&scidr, (char *)&saddr->addr, sizeof (*cidr));
                  saddr->addr.addr[0] = i;
               }

               if ((node = RaFindAddress (parser, labeler->ArgusAddrTree[saddr->addr.type], saddr, ARGUS_EXACT_MATCH)) == NULL) {
                  if ((node = RaInsertAddress (parser, labeler, NULL, saddr, ARGUS_VISITED)) != saddr) {
                     ArgusFree(saddr);
                     saddr = node;
                  }
               }

               if (saddr != NULL) {
                  if (tptr) {
                     if (saddr->addr.str != NULL) free(saddr->addr.str);
                     saddr->addr.str = strdup(tptr);
                  }

                  RaLabelSuperAddresses(saddr);

                  if (label != NULL) {
                     labeler->prune |= ARGUS_TREE_PRUNE_LABEL;
                     if (saddr->label) free(saddr->label);
                     saddr->label = strdup(label);
                  }

                  if (locality >= 0) {
                     labeler->prune |= ARGUS_TREE_PRUNE_LOCALITY;
                     RaLabelAddressLocality(saddr, locality);
                  }
                  if (asn >= 0) {
                     labeler->prune |= ARGUS_TREE_PRUNE_ASN;
                     RaLabelAddressAsn(saddr, asn);
                  }
                  if (group != NULL) {
                     labeler->prune |= ARGUS_TREE_PRUNE_GROUP;
                     RaLabelAddressGroup(saddr, group);
                  }

                  if (labeler->status & ARGUS_LABELER_DEBUG_NODE) {
                     RaPrintLabelTree (labeler, labeler->ArgusAddrTree[AF_INET], 0, 0);
                     printf("\n");
                  }
               }
            }

            if (saddr != NULL) {
               mstep = pow (2.0, (32 - saddr->addr.masklen));
               step = mstep;
            } else {
               break;
            }
         }
      }
      free (tstrbuf);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "RaInsertLocalityTree (%p, %p, %s, %s) returning %d\n", parser, labeler, str, retn);
#endif

   return (retn);
}


int RaReadAddressConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
 
int
RaReadAddressConfig (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *file)
{
   char *str, *ptr;
   char labelbuf[256], *label = NULL;
   int retn = 1, fhl = 0;
   char *banner = NULL;
   FILE *fd =  NULL;

#ifdef ARGUSDEBUG
   int linenum = 0;
#endif

   if (labeler != NULL) {
      if (labeler->ArgusAddrTree == NULL)
         if ((labeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog (LOG_ERR, "RaReadAddressConfig: ArgusCalloc error %s\n", strerror(errno));

//  In address configurations, the first or second comment line will include the name of the
//  configuration.  We'll try to find it and use it for labeling.  The label will become the
//  key for the complete configuration labels.
//  

      if ((fd = fopen (file, "r")) != NULL) {
         struct stat statbuf;
         int bufsize;

         stat(file, &statbuf);
	 bufsize = (statbuf.st_size > MAXSTRLEN) ? statbuf.st_size + 1 : MAXSTRLEN;

         if ((str = ArgusMalloc(bufsize)) == NULL)
            ArgusLog (LOG_ERR, "RaReadAddressConfig: ArgusMalloc error %s\n", strerror(errno));

         while ((ptr = fgets (str, bufsize, fd)) != NULL) {
#ifdef ARGUSDEBUG
            linenum++;
#endif
            while (isspace((int)*ptr)) ptr++;
            switch (*ptr) {
               case '#': {
                  if (!strncmp((char *)&ptr[1], "include ", 8)) {
                     char *sptr;
                     if ((sptr = strtok(&ptr[9], " \t\n")) != NULL)
                        RaReadAddressConfig (parser, labeler, sptr);
                  } else {
                     if (strlen(ptr) > 2) {
                        char *cptr = ptr + 1;
                        int slen;
                        while (isspace((int)*cptr)) cptr++;
                        if ((slen = strlen(cptr)) > 0) {
                           if (cptr[slen - 1] == '\n') cptr[slen - 1] = '\0';
                           if (strncmp(cptr, "firehol_", 8) == 0) {
                              snprintf(labelbuf, 256, "{\"firehol\":\"%s\" }", &cptr[8]);
                              if (strstr(cptr, "firehol_level1")) {
                                 fhl = 1;
                              } else 
                              if (strstr(cptr, "firehol_level2")) {
                                 fhl = 2;
                              } else 
                              if (strstr(cptr, "firehol_level3")) {
                                 fhl = 3;
                              } else 
                              if (strstr(cptr, "firehol_level4")) {
                                 fhl = 4;
                              }
                              if (label != NULL) free(label);
                              label = strdup(labelbuf);
                           }
                        }
                     }
                  }
                  break;
               }

               default: {
                  if (strlen(ptr) > 0) {
                     if (strchr(ptr, '|')) {
                        RaInsertRIRTree (parser, labeler, ptr);
                     } else {
                        if ((!strcmp(ptr, "0.0.0.0/8\n") && (fhl >= 1)) ||
                            (!strcmp(ptr, "10.0.0.0/8\n") && (fhl >= 1)) ||
                            (!strcmp(ptr, "127.0.0.0/8\n") && (fhl >= 1)) ||
                            (!strcmp(ptr, "169.254.0.0/16\n") && (fhl >= 1)) ||
                            (!strcmp(ptr, "192.168.0.0/16\n") && (fhl >= 1)) ||
                            (!strcmp(ptr, "224.0.0.0/3\n") && (fhl >= 1))) {
		        } else
                           RaInsertAddressTree (parser, labeler, ptr, label);
                     }
                  }
                  break;
               }
            }
         }

         ArgusFree(str);
         fclose(fd);

      } else
         ArgusLog (LOG_WARNING, "%s: %s", file, strerror(errno));

      if (labeler->prune) 
         RaPruneAddressTree(labeler, labeler->ArgusAddrTree[AF_INET], ARGUS_TREE_PRUNE_ADJ, 0);

      if (banner != NULL) free(banner);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "RaReadAddressConfig (0x%x, 0x%x, %s) lines %d, returning %d\n", parser, labeler, file, linenum, retn);
#endif

   return (retn);
}


int RaReadLocalityConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

#define RALOCAL_RCITEMS                         2

#define RALABEL_LOCAL_INTERFACE_IS_ME           0
#define RALABEL_LOCALITY_OVERWRITE              1

char *RaLocalResourceFileStr [] = {
   "RALABEL_LOCAL_INTERFACE_IS_ME=",
   "RALABEL_LOCALITY_OVERWRITE=",
};
 
int
RaReadLocalityConfig (struct ArgusParserStruct *parser, struct ArgusLabelerStruct *labeler, char *file)
{
   char strbuf[MAXSTRLEN], *str = strbuf, *ptr;
   int retn = 1, found = 0;
   int linenum = 0;
   FILE *fd =  NULL;

   if (labeler != NULL) {
      if (labeler->ArgusAddrTree == NULL) {
         if ((labeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog (LOG_ERR, "RaReadLocalityConfig: ArgusCalloc error %s\n", strerror(errno));
      }

      if ((fd = fopen (file, "r")) != NULL) {
         while ((ptr = fgets (str, MAXSTRLEN, fd)) != NULL) {
            linenum++;
            while (isspace((int)*ptr)) ptr++;
            if (*ptr && (*ptr != '#') && (*ptr != '\n') && (*ptr != '!')) {
               int i, len;
               found = 0;
               for (i = 0; i < RALOCAL_RCITEMS; i++) {
                  len = strlen(RaLocalResourceFileStr[i]);
                  if (!(strncmp (ptr, RaLocalResourceFileStr[i], len))) {
                     optarg = &ptr[len];

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
                           case RALABEL_LOCAL_INTERFACE_IS_ME: {
                              if (!(strncasecmp(optarg, "yes", 3))) {
                                 labeler->RaLabelLocalityInterfaceIsMe = 1;

                                 if (parser->ArgusLocalLabeler == NULL)
                                    if ((parser->ArgusLocalLabeler = ArgusNewLabeler(parser, 0L)) == NULL)
                                       ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

                              } else
                                 labeler->RaLabelLocalityInterfaceIsMe = 0;

                              found++;
                              break;
                           }

                           case RALABEL_LOCALITY_OVERWRITE: {
                              if (!(strncasecmp(optarg, "yes", 3))) {
                                 parser->ArgusLocalLabeler->RaLabelLocalityOverwrite = 1;
                              } else {
                                 parser->ArgusLocalLabeler->RaLabelLocalityOverwrite = 0;
                              }
                              found++;
                              break;
                           }
                        }
                     }
                  }
               }
            }

            if (!found) {
               switch (*ptr) {
                  case '#': {
                     if (!strncmp((char *)&ptr[1], "include ", 8)) {
                        char *sptr;
                        if ((sptr = strtok(&ptr[9], " \t\n")) != NULL)
                           RaReadLocalityConfig (parser, labeler, sptr);
                     }
                     break;
                  }

                  default:
                     if (strlen(ptr))
                        if (RaInsertLocalityTree (parser, labeler, ptr))
                           ArgusLog (LOG_ERR, "RaReadLocalityConfig: Syntax error: file %s line number %d\n", file, linenum);
                     break;
               }
            }
         }

         fclose(fd);

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "RaReadAddressConfig (0x%x, 0x%x, %s) error %s\n", parser, labeler, file, strerror(errno));
#endif
      }
      ArgusGetInterfaceAddresses(parser);

      if (labeler->prune & ARGUS_PRUNE_TREE)  {
         if (labeler->prune & ARGUS_TREE_PRUNE_GROUP) {
            RaPruneAddressTree(labeler, labeler->ArgusAddrTree[AF_INET], ARGUS_TREE_PRUNE_GROUP, 0);
         } else
         if (labeler->prune & ARGUS_TREE_PRUNE_CCO) {
            RaPruneAddressTree(labeler, labeler->ArgusAddrTree[AF_INET], ARGUS_TREE_PRUNE_CCO, 0);
         } else
         if (labeler->prune & ARGUS_TREE_PRUNE_LOCALITY) {
            RaPruneAddressTree(labeler, labeler->ArgusAddrTree[AF_INET], ARGUS_TREE_PRUNE_LOCALITY, 0);
         } else
         if (labeler->prune & ARGUS_TREE_PRUNE_ASN) {
            RaPruneAddressTree(labeler, labeler->ArgusAddrTree[AF_INET], ARGUS_TREE_PRUNE_ASN, 0);
         } else
         if (labeler->prune & ARGUS_TREE_PRUNE_LABEL) {
            RaPruneAddressTree(labeler, labeler->ArgusAddrTree[AF_INET], ARGUS_TREE_PRUNE_LABEL, 0);
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "RaReadAddressConfig (0x%x, 0x%x, %s) returning %d\n", parser, labeler, file, retn);
#endif

   return (retn);
}

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
   ArgusDebug (10, "RaReadIeeeAddressConfig (0x%x, 0x%x, %s) returning %d\n", parser, labeler, file, retn);
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
   int len = 0;

   len = strlen(str);
   strend = str + len;

   ptr = str;
   while  (!isspace((int)*ptr)) ptr++;
   *ptr++ = '\0';
   label = str;
   while  (isspace((int)*ptr)) ptr++;
   port = ptr;
   if ((proto = strchr (port, '/')) != NULL) {
      *proto++ = '\0';
      ptr = proto;
      while  (!isspace((int)*ptr)) ptr++;
      *ptr++ = '\0';
   }

   if (ptr < strend) {
      while (isspace((int)*ptr)) ptr++;
      desc = ptr;
      tmp = NULL;
      while (*ptr != '\n') {
         if (isspace((int)*ptr)) {
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
//       error++;
      } else {
         if ((ptr = strchr(port, '-')) != NULL) {
            retn->end   = strtol(ptr + 1, &endptr, 10);
            if ((endptr != NULL) && (endptr == port)) {
//             error++;
            }
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
   struct RaPortStruct *tp, *port, **array = NULL;
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

   if ((retn->htable = ArgusNewHashTable(parser->ArgusHashTableSize)) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewLabeler: ArgusCalloc error %s", strerror(errno));

   retn->status = status;

   retn->RaPrintLabelTreeMode = ARGUS_TREE;

   if (parser->ArgusLabelerFileList != NULL) {
/*
      struct ArgusWfileStruct *wfile = NULL, *start = NULL;

      if ((wfile = (struct ArgusWfileStruct *)ArgusFrontList(parser->ArgusWfileList)) != NULL) {
         start = wfile;
         do {
            if (!((argus->hdr.type & ARGUS_MAR) && ((argus->hdr.cause & 0xF0) == ARGUS_START)))
               if (ArgusWriteNewLogfile (parser, input, wfile, input->ArgusOriginal))
                  ArgusLog (LOG_ERR, "ArgusWriteNewLogfile failed. %s", strerror(errno));

            ArgusPopFrontList(parser->ArgusWfileList, ARGUS_LOCK);
            ArgusPushBackList(parser->ArgusWfileList, (struct ArgusListRecord *)wfile, ARGUS_LOCK);
            wfile = (struct ArgusWfileStruct *)ArgusFrontList(parser->ArgusWfileList);
         } while (wfile != start);
      }
*/
   }

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
         parser->ArgusFlowModelFile = NULL;
      }
   }

   if (status & ARGUS_LABELER_NAMES) {
   }

   retn->prune = ARGUS_PRUNE_TREE;

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

      if (labeler->htable !=  NULL)
         ArgusDeleteHashTable (labeler->htable);

      if ((ArgusAddrTree = labeler->ArgusAddrTree) != NULL) {
         if (labeler->ArgusAddrTree[AF_INET] != NULL)
            RaDeleteAddressTree (labeler, labeler->ArgusAddrTree[AF_INET]);

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

      strncat (RaSrvTreeArray, "   |", (MAXSTRLEN - (strlen(RaSrvTreeArray) + 1)));

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
      ArgusSortQueue (ArgusSorter, queue, ARGUS_LOCK);
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
RaFindSrv (struct RaSrvTreeNode *node, u_char *ptr, int len, int mode, int wildcard)
{
   int i, nomatch = 0, guess = 0;
   struct RaSrvSignature *retn = NULL;
   unsigned int mask;
   u_char *buf = NULL;

   if ((node != NULL)  && (ptr != NULL)) {
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
                        retn = RaFindSrv (node->l, ptr, len, mode, wildcard);
                     else
                        retn = RaFindSrv (node->r, ptr, len, mode, wildcard);
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

static struct RaSrvSignature *
RaTestEncryption(struct RaSrvTreeNode *tree, u_char *ptr, int len)
{
   struct RaSrvSignature *retn = NULL;
   int val[16];
   int i, cmax = -1, N = len * 2;
   double cbnd = 0, pmax, H, entropy;

   bzero(val, sizeof(val));

   for (i = 0; i < len; i++) {
      int v1 = ptr[i] & 0x0F;
      int v2 = (ptr[i] & 0xF0) >> 4;

      val[v1]++;
      val[v2]++;
   }

   for (i = 0; i < 16; i++) {
      if (val[i] > cmax) cmax = val[i];
   }

   pmax = cmax * (1.0) / (N * 1.0);
   cbnd = cmax * (1.0) + 2.3 * sqrt(N * pmax * (1 - pmax));
   H    =  (-1.0) * log2(cbnd / (N * 1.0));
   entropy = (H * 100.0/ 4.0);

   if (entropy > 80.0)
      retn = (struct RaSrvSignature *) tree;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaTestEncryption: entropy is %.3f\n", entropy);
#endif

   return (retn);
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
   struct RaSrvTreeNode *tree = NULL;
   int status = 0 ,found = 0;

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

   if ((tree = RaTCPSrcArray[flow->ip_flow.dport]) != NULL) 
      status |= tree->srv->status;
   
   if ((tree = RaTCPDstArray[flow->ip_flow.dport]) != NULL) 
      status |= tree->srv->status;

   if (suser != NULL) {
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
         if ((srvSrc = RaFindSrv (tree, ptr, len, RA_SRC_SERVICES, (status & RA_SVC_WILDCARD))) == NULL) {
            if (RaBestGuess && (RaBestGuessScore > 5)) {
               srvSrc = RaBestGuess;
               srcPort++;
            }
         }
      }

      if ((tree = array[flow->ip_flow.sport]) == NULL) {
         if (srvSrc == NULL) {
            if (status & RA_SVC_WILDCARD) {
            } else {
               for (i = 0; i < RASIGLENGTH && !found; i++) {
                  switch (flow->ip_flow.ip_p) {
                     case IPPROTO_TCP: tree = RaSrcTCPServicesTree[i]; break;
                     case IPPROTO_UDP: tree = RaSrcUDPServicesTree[i]; break;
                  }
                  if (tree != NULL)
                     if ((srvSrc = RaFindSrv(tree, ptr, len, RA_SRC_SERVICES, (status & RA_SVC_WILDCARD))) != NULL)
                            break;
               }
            }
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
         if ((srvDst = RaFindSrv (tree, ptr, len, RA_DST_SERVICES, (status & RA_SVC_WILDCARD))) == NULL) {
            if (RaBestGuess && (RaBestGuessScore > 4)) {
               srvDst = RaBestGuess;
               dstPort++;
            }
         }
      }

      if ((srvSrc == NULL) && (srvDst == NULL)) {
         if (status & RA_SVC_WILDCARD) {
            if (suser != NULL) {
               u_char *ptr = (u_char *) &suser->array;
               srvSrc = RaTestEncryption(tree, ptr, len);
            }
            if (duser != NULL) {
               u_char *ptr = (u_char *) &duser->array;
               srvDst = RaTestEncryption(tree, ptr, len);
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
               if ((srvDst = RaFindSrv(tree, ptr, len, RA_DST_SERVICES, (status & RA_SVC_WILDCARD))) != NULL)
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
   int mask = 0, found = 0;

   if (parser->ArgusAggregator != NULL) {
      mask |= parser->ArgusAggregator->mask & (ARGUS_MASK_SADDR_INDEX | ARGUS_MASK_DADDR_INDEX);
   } else {
      mask |= ARGUS_MASK_SADDR_INDEX | ARGUS_MASK_DADDR_INDEX;
   }

   bzero (RaAddressLabelBuffer, sizeof(RaAddressLabelBuffer));
   if (flow != NULL) {
      switch(flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_LAYER_3_MATRIX:
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
               case ARGUS_TYPE_IPV4: {
                  if (mask & ARGUS_MASK_SADDR_INDEX) 
                     if ((saddr = RaFetchIPv4AddressLabel(parser, &flow->ip_flow.ip_src)) != NULL) {
                        int slen = strlen(RaAddressLabelBuffer);
                        snprintf (&RaAddressLabelBuffer[slen], 1024 - slen, "saddr=%s", saddr);
                        free(saddr);
                        found++;
                     }
                  if (mask & ARGUS_MASK_DADDR_INDEX) 
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


static char RaLocalityLabelBuffer[256];

char *
RaLocalityLabel (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusLabelerStruct *labeler;
   struct RaAddressStruct *saddr = NULL, *daddr = NULL;
   char *retn = NULL;
   int found = 0;

   if ((labeler = parser->ArgusLocalLabeler) != NULL) {
      if (labeler->ArgusAddrTree) {
         struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
         int slen = 0;

         if (flow != NULL) {
            switch(flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_LAYER_3_MATRIX:
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4: {
                        struct RaAddressStruct node;

                        bzero ((char *)&node, sizeof(node));
 
                        node.addr.type = AF_INET;
                        node.addr.len = 4;
                        node.addr.addr[0] = flow->ip_flow.ip_src;
                        node.addr.masklen = 32;
                        if (labeler->RaLabelLocalityInterfaceIsMe) {
                           if ((labeler = parser->ArgusLocalLabeler) != NULL)
                              if ((saddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_SUPER_MATCH)) == NULL)
                                 saddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_NODE_MATCH);
                        }

                        if (saddr == NULL)
                           saddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_LONGEST_MATCH);

                        if (saddr != NULL) {
                           if (saddr->locality > 0) {
                              struct ArgusNetspatialStruct *nss = NULL;
                              if ((nss = (struct ArgusNetspatialStruct *)argus->dsrs[ARGUS_LOCAL_INDEX]) == NULL) {
                                 nss = (struct ArgusNetspatialStruct *) ArgusCalloc(1, sizeof(*nss));
                                 nss->hdr.type = ARGUS_LOCAL_DSR;
                                 nss->hdr.argus_dsrvl8.len = (sizeof(*nss) + 3) / 4;

                                 argus->dsrs[ARGUS_LOCAL_INDEX] = &nss->hdr;
                                 argus->dsrindex |= (0x1 << ARGUS_LOCAL_INDEX);

                                 nss->hdr.argus_dsrvl8.qual |= ARGUS_SRC_LOCAL;
                                 nss->sloc = saddr->locality;

                              } else {
                                 if (labeler->RaLabelLocalityOverwrite) {
                                    nss->hdr.argus_dsrvl8.qual |= ARGUS_SRC_LOCAL;
                                    nss->sloc = saddr->locality;
                                 } else {
                                    if (!(nss->hdr.argus_dsrvl8.qual & ARGUS_SRC_LOCAL)) {
                                       nss->hdr.argus_dsrvl8.qual |= ARGUS_SRC_LOCAL;
                                       nss->sloc = saddr->locality;
                                    }
                                 }
                              }
                           
                              if (saddr->asn > 0) {
                                 struct ArgusAsnStruct *asn = (struct ArgusAsnStruct *) argus->dsrs[ARGUS_ASN_INDEX];

                                 if (asn == NULL) {
                                    if ((asn = ArgusCalloc(1, sizeof(*asn))) == NULL)
                                       ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s", strerror(errno));

                                    asn->hdr.type              = ARGUS_ASN_DSR;
                                    asn->hdr.subtype           = ARGUS_ASN_LOCAL;
                                    asn->hdr.argus_dsrvl8.qual = 0;
                                    asn->hdr.argus_dsrvl8.len  = 3;

                                    argus->dsrs[ARGUS_ASN_INDEX] = (struct ArgusDSRHeader *) asn;
                                    argus->dsrindex |= (0x01 << ARGUS_ASN_INDEX);

                                    asn->src_as = saddr->asn;

                                 } else {
                                    asn->hdr.subtype   = ARGUS_ASN_LOCAL;
                                    asn->src_as        = saddr->asn;
                                 }
                              }
                           }
                        }

                        node.addr.addr[0] = flow->ip_flow.ip_dst;

                        if (labeler->RaLabelLocalityInterfaceIsMe) {
                           if ((labeler = parser->ArgusLocalLabeler) != NULL)
                              if ((daddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_SUPER_MATCH)) == NULL)
                                 daddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_NODE_MATCH);
                        }

                        if (daddr == NULL)
                           daddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_LONGEST_MATCH);

                        if (daddr != NULL) {
                           if (daddr->locality > 0) {
                              struct ArgusNetspatialStruct *nss = NULL;
                              if ((nss = (struct ArgusNetspatialStruct *)argus->dsrs[ARGUS_LOCAL_INDEX]) == NULL) {
                                 nss = (struct ArgusNetspatialStruct *) ArgusCalloc(1, sizeof(*nss));
                                 nss->hdr.type = ARGUS_LOCAL_DSR;
                                 nss->hdr.argus_dsrvl8.len = (sizeof(*nss) + 3) / 4;

                                 argus->dsrs[ARGUS_LOCAL_INDEX] = &nss->hdr;
                                 argus->dsrindex |= (0x1 << ARGUS_LOCAL_INDEX);

                                 nss->hdr.argus_dsrvl8.qual |= ARGUS_DST_LOCAL;
                                 nss->dloc = daddr->locality;
                              } else {
                                 if (labeler->RaLabelLocalityOverwrite) {
                                    nss->hdr.argus_dsrvl8.qual |= ARGUS_DST_LOCAL;
                                    nss->dloc = daddr->locality;
                                 } else {
                                    if (!(nss->hdr.argus_dsrvl8.qual & ARGUS_DST_LOCAL)) {
                                       nss->hdr.argus_dsrvl8.qual |= ARGUS_DST_LOCAL;
                                       nss->dloc = daddr->locality;
                                    }
                                 }
                              }

                              if (daddr->asn > 0) {
                                 struct ArgusAsnStruct *asn = (struct ArgusAsnStruct *) argus->dsrs[ARGUS_ASN_INDEX];

                                 if (asn == NULL) {
                                    if ((asn = ArgusCalloc(1, sizeof(*asn))) == NULL)
                                       ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s", strerror(errno));

                                    asn->hdr.type              = ARGUS_ASN_DSR;
                                    asn->hdr.subtype           = ARGUS_ASN_LOCAL;
                                    asn->hdr.argus_dsrvl8.qual = 0;
                                    asn->hdr.argus_dsrvl8.len  = 3;

                                    argus->dsrs[ARGUS_ASN_INDEX] = (struct ArgusDSRHeader *) asn;
                                    argus->dsrindex |= (0x01 << ARGUS_ASN_INDEX);

                                    asn->dst_as = daddr->asn;

                                 } else {
                                    asn->hdr.subtype   = ARGUS_ASN_LOCAL;
                                    asn->dst_as        = daddr->asn;
                                 }
                              }
                           }
                        }
                        break;
                     }
                     case ARGUS_TYPE_IPV6: {
                        struct ArgusNetspatialStruct *nss = NULL;
                        if ((nss = (struct ArgusNetspatialStruct *)argus->dsrs[ARGUS_LOCAL_INDEX]) == NULL) {
                           nss = (struct ArgusNetspatialStruct *) ArgusCalloc(1, sizeof(*nss));
                           nss->hdr.type = ARGUS_LOCAL_DSR;
                           nss->hdr.argus_dsrvl8.len = (sizeof(*nss) + 3) / 4;

                           argus->dsrs[ARGUS_LOCAL_INDEX] = &nss->hdr;
                           argus->dsrindex |= (0x1 << ARGUS_LOCAL_INDEX);

                           nss->hdr.argus_dsrvl8.qual |= ARGUS_SRC_LOCAL;
                           nss->sloc = RaFetchAddressLocality (parser, labeler, (unsigned int *) &flow->ipv6_flow.ip_src, 0, ARGUS_TYPE_IPV6, ARGUS_NODE_MATCH);
                           nss->hdr.argus_dsrvl8.qual |= ARGUS_DST_LOCAL;
                           nss->dloc = RaFetchAddressLocality (parser, labeler, (unsigned int *) &flow->ipv6_flow.ip_dst, 0, ARGUS_TYPE_IPV6, ARGUS_NODE_MATCH);

                        } else {
                           if (labeler->RaLabelLocalityOverwrite) {
                              nss->hdr.argus_dsrvl8.qual |= ARGUS_SRC_LOCAL;
                              nss->sloc = RaFetchAddressLocality (parser, labeler, (unsigned int *) &flow->ipv6_flow.ip_src, 0, ARGUS_TYPE_IPV6, ARGUS_NODE_MATCH);
                              nss->hdr.argus_dsrvl8.qual |= ARGUS_DST_LOCAL;
                              nss->dloc = RaFetchAddressLocality (parser, labeler, (unsigned int *) &flow->ipv6_flow.ip_dst, 0, ARGUS_TYPE_IPV6, ARGUS_NODE_MATCH);
                           } else {
                              if (!(nss->hdr.argus_dsrvl8.qual & ARGUS_SRC_LOCAL)) {
                                 nss->hdr.argus_dsrvl8.qual |= ARGUS_SRC_LOCAL;
                                 nss->sloc = RaFetchAddressLocality (parser, labeler, (unsigned int *) &flow->ipv6_flow.ip_src, 0, ARGUS_TYPE_IPV6, ARGUS_NODE_MATCH);
                              }
                              if (!(nss->hdr.argus_dsrvl8.qual & ARGUS_DST_LOCAL)) {
                                 nss->hdr.argus_dsrvl8.qual |= ARGUS_DST_LOCAL;
                                 nss->dloc = RaFetchAddressLocality (parser, labeler, (unsigned int *) &flow->ipv6_flow.ip_dst, 0, ARGUS_TYPE_IPV6, ARGUS_NODE_MATCH);
                              }
                           }
                        }
                        break;
                     }
                     case ARGUS_TYPE_RARP: {
                        break;
                     }
                     case ARGUS_TYPE_ARP: {
                        break;
                     }
                     case ARGUS_TYPE_ISIS: {
                        break;
                     }
                     case ARGUS_TYPE_ETHER: {
                        break;
                     }
                  }
                  break;
               }

               case ARGUS_FLOW_ARP: {
                  void *arpsaddr = NULL;
                  void *arpdaddr = NULL;

                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_RARP:
                        break;

                     case ARGUS_TYPE_ARP:
                        arpsaddr = &flow->arp_flow.arp_spa;
                        arpdaddr = &flow->arp_flow.arp_spa;

                        struct RaAddressStruct node;

                        bzero ((char *)&node, sizeof(node));
 
                        node.addr.type = AF_INET;
                        node.addr.len = 4;
                        node.addr.addr[0] = *(unsigned int *)arpsaddr;
                        node.addr.masklen = 32;
                        if (labeler->RaLabelLocalityInterfaceIsMe) {
                           if ((labeler = parser->ArgusLocalLabeler) != NULL)
                              if ((saddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_SUPER_MATCH)) == NULL)
                                 saddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_NODE_MATCH);
                        }

                        if (saddr == NULL)
                           saddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_LONGEST_MATCH);

                        if (saddr != NULL) {
                           if (saddr->locality > 0) {
                              struct ArgusNetspatialStruct *nss = NULL;
                              if ((nss = (struct ArgusNetspatialStruct *)argus->dsrs[ARGUS_LOCAL_INDEX]) == NULL) {
                                 nss = (struct ArgusNetspatialStruct *) ArgusCalloc(1, sizeof(*nss));
                                 nss->hdr.type = ARGUS_LOCAL_DSR;
                                 nss->hdr.argus_dsrvl8.len = (sizeof(*nss) + 3) / 4;

                                 argus->dsrs[ARGUS_LOCAL_INDEX] = &nss->hdr;
                                 argus->dsrindex |= (0x1 << ARGUS_LOCAL_INDEX);

                                 nss->hdr.argus_dsrvl8.qual |= ARGUS_SRC_LOCAL;
                                 nss->sloc = saddr->locality;

                              } else {
                                 if (labeler->RaLabelLocalityOverwrite) {
                                    nss->hdr.argus_dsrvl8.qual |= ARGUS_SRC_LOCAL;
                                    nss->sloc = saddr->locality;
                                 } else {
                                    if (!(nss->hdr.argus_dsrvl8.qual & ARGUS_SRC_LOCAL)) {
                                       nss->hdr.argus_dsrvl8.qual |= ARGUS_SRC_LOCAL;
                                       nss->sloc = saddr->locality;
                                    }
                                 }
                              }
                           
                              if (saddr->asn > 0) {
                                 struct ArgusAsnStruct *asn = (struct ArgusAsnStruct *) argus->dsrs[ARGUS_ASN_INDEX];

                                 if (asn == NULL) {
                                    if ((asn = ArgusCalloc(1, sizeof(*asn))) == NULL)
                                       ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s", strerror(errno));

                                    asn->hdr.type              = ARGUS_ASN_DSR;
                                    asn->hdr.subtype           = ARGUS_ASN_LOCAL;
                                    asn->hdr.argus_dsrvl8.qual = 0;
                                    asn->hdr.argus_dsrvl8.len  = 3;

                                    argus->dsrs[ARGUS_ASN_INDEX] = (struct ArgusDSRHeader *) asn;
                                    argus->dsrindex |= (0x01 << ARGUS_ASN_INDEX);

                                    asn->src_as = saddr->asn;

                                 } else {
                                    asn->hdr.subtype   = ARGUS_ASN_LOCAL;
                                    asn->src_as        = saddr->asn;
                                 }
                              }
                           }
                        }

                        node.addr.addr[0] = *(unsigned int *)arpdaddr;

                        if (labeler->RaLabelLocalityInterfaceIsMe) {
                           if ((labeler = parser->ArgusLocalLabeler) != NULL)
                              if ((daddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_SUPER_MATCH)) == NULL)
                                 daddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_NODE_MATCH);
                        }

                        if (daddr == NULL)
                           daddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_LONGEST_MATCH);

                        if (daddr != NULL) {
                           if (daddr->locality > 0) {
                              struct ArgusNetspatialStruct *nss = NULL;
                              if ((nss = (struct ArgusNetspatialStruct *)argus->dsrs[ARGUS_LOCAL_INDEX]) == NULL) {
                                 nss = (struct ArgusNetspatialStruct *) ArgusCalloc(1, sizeof(*nss));
                                 nss->hdr.type = ARGUS_LOCAL_DSR;
                                 nss->hdr.argus_dsrvl8.len = (sizeof(*nss) + 3) / 4;

                                 argus->dsrs[ARGUS_LOCAL_INDEX] = &nss->hdr;
                                 argus->dsrindex |= (0x1 << ARGUS_LOCAL_INDEX);

                                 nss->hdr.argus_dsrvl8.qual |= ARGUS_DST_LOCAL;
                                 nss->dloc = daddr->locality;
                              } else {
                                 if (labeler->RaLabelLocalityOverwrite) {
                                    nss->hdr.argus_dsrvl8.qual |= ARGUS_DST_LOCAL;
                                    nss->dloc = daddr->locality;
                                 } else {
                                    if (!(nss->hdr.argus_dsrvl8.qual & ARGUS_DST_LOCAL)) {
                                       nss->hdr.argus_dsrvl8.qual |= ARGUS_DST_LOCAL;
                                       nss->dloc = daddr->locality;
                                    }
                                 }
                              }

                              if (daddr->asn > 0) {
                                 struct ArgusAsnStruct *asn = (struct ArgusAsnStruct *) argus->dsrs[ARGUS_ASN_INDEX];

                                 if (asn == NULL) {
                                    if ((asn = ArgusCalloc(1, sizeof(*asn))) == NULL)
                                       ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s", strerror(errno));

                                    asn->hdr.type              = ARGUS_ASN_DSR;
                                    asn->hdr.subtype           = ARGUS_ASN_LOCAL;
                                    asn->hdr.argus_dsrvl8.qual = 0;
                                    asn->hdr.argus_dsrvl8.len  = 3;

                                    argus->dsrs[ARGUS_ASN_INDEX] = (struct ArgusDSRHeader *) asn;
                                    argus->dsrindex |= (0x01 << ARGUS_ASN_INDEX);

                                    asn->dst_as = daddr->asn;

                                 } else {
                                    asn->hdr.subtype   = ARGUS_ASN_LOCAL;
                                    asn->dst_as        = daddr->asn;
                                 }
                              }
                           }
                        }
                        break;
                  }
               }
            }
         }

         if (saddr && saddr->label) {
            slen = snprintf(RaLocalityLabelBuffer, sizeof(RaLocalityLabelBuffer),
                            "sloc=%s", saddr->label);
            found++;
         }
         if (daddr && daddr->label) {
            snprintf(&RaLocalityLabelBuffer[slen],
                     sizeof(RaLocalityLabelBuffer) - slen,
                     "%sdloc=%s", found ? ":" : "", daddr->label);
            found++;
         }
      }
   }

   if (found)
      retn = RaLocalityLabelBuffer;

   return (retn);
}


static char RaServiceLabelBuffer[256];

char *
RaServiceLabel (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusLabelerStruct *labeler;
   struct RaSrvSignature *sig = NULL;
   int type, process = 0, found = 0;
   char *retn = NULL;

   if ((labeler = parser->ArgusLocalLabeler) != NULL) {
      bzero(RaServiceLabelBuffer, sizeof(RaServiceLabelBuffer));

      if (labeler->ArgusAddrTree) {
         struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];

         if (flow != NULL) {
            if (argus->dsrs[ARGUS_SRCUSERDATA_INDEX] || argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) {
               switch(flow->hdr.subtype & 0x3F) {
                  case ARGUS_FLOW_CLASSIC5TUPLE: {
                     struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) argus->dsrs[ARGUS_NETWORK_INDEX];
          
                     switch (type = (flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                        case ARGUS_TYPE_IPV4:
                           switch (flow->ip_flow.ip_p) {
                              case IPPROTO_TCP:
                              case IPPROTO_UDP: {
                                 process++;
                                 break;
                              }
                           }
                           break; 

                        case ARGUS_TYPE_IPV6: {
                           switch (flow->ipv6_flow.ip_p) {
                              case IPPROTO_TCP:
                              case IPPROTO_UDP: {
                                 process++;
                                 break;
                              }
                           }
                           break; 
                        }
                     }
                     if (net && (net->hdr.subtype == ARGUS_RTP_FLOW)) {
                        snprintf (RaServiceLabelBuffer, 128, "%s", "rtp");
                        found++;
                     } else
                     if (net && (net->hdr.subtype == ARGUS_RTCP_FLOW)) {
                        snprintf (RaServiceLabelBuffer, 128, "%s", "rtcp");
                        found++;
                     }
                     break; 
                  }
                  break;
               }

               if (process) {
                  int length = 0;
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
                     length = strlen(sig->name) + 5;
                     length = ((length > 32) ? 32 : length);
                     snprintf ((char *)RaServiceLabelBuffer, length, "srv=%s", sig->name);
                     found++;
                  }
               }
            }
         }
      }
   }

   if (found)
      retn = RaServiceLabelBuffer;

   return (retn);
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
      ArgusLog (LOG_ERR, "RaFlowLabel: No labeler\n");

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
int RaPrintLabelTreeEntries (struct RaAddressStruct *);

int
RaPrintLabelTreeEntries (struct RaAddressStruct *node)
{
   int retn = 0, level = 0;
   if (node != NULL) {
      level = node->addr.masklen;
      if (level > RaPrintLabelTreeLevel)
         return(retn);

      if (level >= RaPrintLabelStartTreeLevel)
         retn++;

      if (node->r) retn += RaPrintLabelTreeEntries(node->r);
      if (node->l) retn += RaPrintLabelTreeEntries(node->l);
   }
   return(retn);
}

void
RaPrintLabelTree (struct ArgusLabelerStruct *labeler, struct RaAddressStruct *node, int level, int dir)
{
   int i = 0, length, len;
   int olen = strlen(RaAddrTreeArray);
   char str[MAXSTRLEN], chr = ' ';

   bzero(str, MAXSTRLEN);

   if (node != NULL) {

      if (node->addr.masklen > RaPrintLabelTreeLevel)
         return;

      switch (labeler->RaPrintLabelTreeMode) {
         case ARGUS_TREE:
         case ARGUS_TREE_VISITED: {
            level = node->addr.masklen;
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
                     printf ("%s/%d ", intoa(node->addr.addr[0] & (0xFFFFFFFF << (32 - node->addr.masklen))), node->addr.masklen);
                  } else
                     printf ("0.0.0.0/0 ");
               }

               if (strlen(node->cco))
                  printf ("%s ", node->cco);

               if (node->group && strlen(node->group))
                  printf ("'%s' ", node->group);

               if (node->label && strlen(node->label))
                  printf ("'%s' ", node->label);

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

         case ARGUS_LABEL: {
            level = node->addr.masklen;
            if (node->r || node->l) {
               RaPrintLabelTree(labeler, node->r, level + 1, RA_SRV_RIGHT);
               RaPrintLabelTree(labeler, node->l, level + 1, RA_SRV_LEFT);
            }

           if (node->label) {
              char nbuf[1024];
              int slen;
              if (node->addr.str) {
                 snprintf (nbuf, 1024, "%s", node->addr.str);
              } else  {
                 if (node->addr.masklen == 32) {
                    snprintf (nbuf, 1024, "%s", intoa(node->addr.addr[0] & (0xFFFFFFFF << (32 - node->addr.masklen))));
                 } else
                 if (node->addr.masklen > 0) {
                    snprintf (nbuf, 1024, "%s/%d", intoa(node->addr.addr[0] & (0xFFFFFFFF << (32 - node->addr.masklen))), node->addr.masklen);
                 } else
                    snprintf (nbuf, 1024, "0.0.0.0");
              }
              slen = strlen(nbuf);
              snprintf (&nbuf[slen], 1024 - slen, "\t%s", node->label);
              printf ("%s\n", nbuf);
            }
            break;
         }

         case ARGUS_GRAPH: {
            level = node->addr.masklen;
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

         case ARGUS_JSON: {
               char nbuf[1024];
               int rcnt = 0, lcnt = 0;

               level = node->addr.masklen;
               if (level >= RaPrintLabelStartTreeLevel)
                  strcat (RaAddrTreeArray, " ");

               if (node->addr.str)
                  snprintf (nbuf, 1024, "%s", node->addr.str);
               else  {
                  if (node->addr.masklen > 0) {
                     snprintf (nbuf, 1024, "%s/%d", intoa(node->addr.addr[0] & (0xFFFFFFFF << (32 - node->addr.masklen))), node->addr.masklen);
                  } else
                     snprintf (nbuf, 1024, "0.0.0.0/0");
               }

               if (level == 0) 
                  printf ("{\n");

               if (level >= RaPrintLabelStartTreeLevel)
                  printf ("%s{", RaAddrTreeArray);

               if (node->r || node->l) {
                  rcnt = RaPrintLabelTreeEntries(node->r); 
                  lcnt = RaPrintLabelTreeEntries(node->l);

                  if (rcnt || lcnt) {
                     if ((level >= RaPrintLabelStartTreeLevel)) {
                        strcat (RaAddrTreeArray, " ");
                        printf ("\n%s\"name\": \"%s\"", RaAddrTreeArray, nbuf);
                        if (node->ns) {
                           char sbuf[256], *sptr = sbuf;
                           bzero(sbuf, 256);
                           ArgusPrintRecord(ArgusParser, sbuf, node->ns, 256);
                           if ((sptr = strchr(sbuf, '{')) != NULL) {
                              char *tptr = strchr(sbuf, '}');
                              if (tptr != NULL) *tptr = '\0';
                              sptr++;
                              printf (", %s", sptr);
                           }
                        }
                        printf (",\n%s\"children\": [\n", RaAddrTreeArray);
                     }

                     if (rcnt) RaPrintLabelTree(labeler, node->r, level + 1, RA_SRV_RIGHT);
                     if (rcnt && lcnt) printf (",\n");
                     if (lcnt) RaPrintLabelTree(labeler, node->l, level + 1, RA_SRV_LEFT);

                     if ((level >= RaPrintLabelStartTreeLevel)) {
                        printf ("\n%s]\n", RaAddrTreeArray);
                        RaAddrTreeArray[strlen(RaAddrTreeArray) - 1] = '\0';
                        printf ("%s}", RaAddrTreeArray);
                     }

                  } else {
                     printf ("\"name\": \"%s\"", nbuf);
                     if (node->ns) {
                        char sbuf[256], *sptr = sbuf;
                        bzero(sbuf, 256);
                        ArgusPrintRecord(ArgusParser, sbuf, node->ns, 256);
                        if ((sptr = strchr(sbuf, '{')) != NULL) {
                           char *tptr = strchr(sbuf, '}');
                           if (tptr != NULL) *tptr = '\0';
                           sptr++;
                           printf (", %s", sptr);
                        }
                     }
                     printf ("}");
                  }
               } else {
                  if ((level >= RaPrintLabelStartTreeLevel)) {
                     printf ("\"name\": \"%s\"", nbuf);
                     if (node->ns) {
                        char sbuf[256], *sptr = sbuf;
                        bzero(sbuf, 256);
                        ArgusPrintRecord(ArgusParser, sbuf, node->ns, 256);
                        if ((sptr = strchr(sbuf, '{')) != NULL) {
                           char *tptr = strchr(sbuf, '}');
                           if (tptr != NULL) *tptr = '\0';
                           sptr++;
                           printf (", %s", sptr);
                        }
                     }
                     printf ("}");
                  }
               }

           for (i = olen, len = strlen(RaAddrTreeArray); i < len; i++)
              RaAddrTreeArray[i] = '\0';

           if (level == 0)
              printf ("\n}\n");
           break;
        }

        case ARGUS_NEWICK: {
           char nbuf[1024];
           int rcnt, lcnt;

           if (node->r || node->l) {
              rcnt = RaPrintLabelTreeEntries(node->r);
              lcnt = RaPrintLabelTreeEntries(node->l);

              if (rcnt || lcnt) {
                 printf ("(");
                 if (rcnt) RaPrintLabelTree(labeler, node->r, level + 1, RA_SRV_RIGHT);
                 if (rcnt && lcnt) printf (",");
                 if (lcnt) RaPrintLabelTree(labeler, node->l, level + 1, RA_SRV_LEFT);
                 printf (")");
              }

           } else {
              if ((level >= RaPrintLabelStartTreeLevel)) {
              }
           }
           if (node->addr.str)
              snprintf (nbuf, 1024, "%s", node->addr.str);
           else  {
              if (node->addr.masklen > 0) {
                 snprintf (nbuf, 1024, "%s", intoa(node->addr.addr[0] & (0xFFFFFFFF << (32 - node->addr.masklen))));
              } else
                 snprintf (nbuf, 1024, "0.0.0.0");
           }
           printf ("%s:%d", nbuf, node->addr.masklen);
           if (level == 0) printf (";\n");
           break;
        }
      }
   }
   fflush(stdout);
}


void
RaLabelSuperAddresses(struct RaAddressStruct *raddr)
{
   if (raddr != NULL) {
      int superlocality = 0, superasn = 0;
      struct RaAddressStruct *paddr = raddr;

      do {
         if (paddr->locality > 0) {
            superlocality = paddr->locality;
            break;
         }
      } while ((paddr = paddr->p) != NULL);
    
      if (superlocality > 0) {
         paddr = raddr;
         do {
            if (paddr->locality != superlocality)
               paddr->locality = superlocality;
            else
               break;
         } while ((paddr = paddr->p) != NULL);
      }
    
      paddr = raddr;
      do {
         if (paddr->asn > 0) {
            superasn = paddr->asn;
            break;
         }
      } while ((paddr = paddr->p) != NULL);
    
      if (superasn > 0) {
         paddr = raddr;
         do {
            if (paddr->asn != superasn)
               paddr->asn = superasn;
            else
               break;
         } while ((paddr = paddr->p) != NULL);
      }
   }
}


void
RaLabelSubAddresses(struct RaAddressStruct *raddr)
{
   if (raddr != NULL) {
      if (raddr->l) {
         if (raddr->l->locality < raddr->locality) {
            raddr->l->locality = raddr->locality;
            if (raddr->asn != 0)
               raddr->l->asn = raddr->asn;
            RaLabelSubAddresses(raddr->l);
         }
      }
      if (raddr->r) {
         if (raddr->r->locality < raddr->locality) {
            raddr->r->locality = raddr->locality;
            if (raddr->asn != 0)
               raddr->r->asn = raddr->asn;
            RaLabelSubAddresses(raddr->r);
         }
      }
   }
}

#if defined(HAVE_NET_IF_DL_H) && HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif

void
ArgusGetInterfaceAddresses(struct ArgusParserStruct *parser)
{
#if defined(HAVE_IFADDRS_H) && HAVE_IFADDRS_H
   struct ArgusLabelerStruct *labeler = NULL;
   struct ifaddrs *ifa = NULL, *p;
   
   if ((labeler = parser->ArgusLocalLabeler) != NULL) {
      if (labeler->ArgusAddrTree == NULL)
         if ((labeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog (LOG_ERR, "ArgusGetInterfaceAddresses: ArgusCalloc error %s\n", strerror(errno));

      if (getifaddrs(&ifa) != 0) 
         ArgusLog (LOG_ERR, "ArgusGetInterfaceAddrs: getifaddrs error %s", strerror(errno));

      for (p = ifa; p != NULL; p = p->ifa_next) {
         if (p->ifa_addr != NULL) {

#if defined(ARGUS_SOLARIS)
            int s, family = p->ifa_addr->ss_family;
#else
            int s, family = p->ifa_addr->sa_family;
#endif

            switch (family) {
               case AF_INET: {
                  struct ArgusCIDRAddr *cidr = NULL;
                  char ip_addr[NI_MAXHOST];
                  uint32_t tmask, mask = ((struct sockaddr_in *)(p->ifa_netmask))->sin_addr.s_addr;
                  int i, cidrlen = 0;

                  if ((s = getnameinfo((void *)p->ifa_addr, sizeof(struct sockaddr_in), ip_addr, sizeof(ip_addr), NULL, 0, NI_NUMERICHOST)) != 0)
                     ArgusLog (LOG_ERR, "ArgusGetInerfaceAddresses: error %s\n", strerror(errno));

                  mask = ntohl(mask);
                  for (i = 0, tmask = 0xffffffff; i < 32; i++) {
                     if ((tmask << i) == mask) {
                        cidrlen = 32 - i;
                     }
                  }

                  RaInsertAddressTree (parser, labeler, ip_addr, NULL);

                  if ((cidr = RaParseCIDRAddr (parser, ip_addr)) != NULL) {
                     struct RaAddressStruct *raddr = NULL;
                     struct RaAddressStruct node;

                     bzero ((char *)&node, sizeof(node));
                     bcopy (cidr, &node.addr, sizeof(*cidr));
                     node.addr.str = NULL;

                     if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_SUPER_MATCH)) != NULL) {
                        RaLabelSuperAddresses(raddr);
                        if (raddr->locality != 5) {
                           raddr->locality = 5;
                           if (raddr->label != NULL) free(raddr->label);
                           raddr->label = strdup("5");
                        }
                     }
                     cidrlen = cidr->masklen;
                  }

                  if (cidrlen < 32) {
                     sprintf(&ip_addr[strlen(ip_addr)], "/%d", cidrlen);
                     RaInsertAddressTree (parser, labeler, ip_addr, NULL);

                     if ((cidr = RaParseCIDRAddr (parser, ip_addr)) != NULL) {
                        struct RaAddressStruct *raddr = NULL;
                        struct RaAddressStruct node;

                        bzero ((char *)&node, sizeof(node));
                        bcopy (cidr, &node.addr, sizeof(*cidr));
                        if (cidr->str != NULL)
                           node.addr.str = strdup(cidr->str);

                        if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_SUPER_MATCH)) != NULL) {
                           if (raddr->locality != 4) {
                              raddr->locality = 4;
                              if (raddr->label != NULL) free(raddr->label);
                              raddr->label = strdup("4");
                           }
                        }
                     }
                  }

#if defined(ARGUSDEBUG)
                  ArgusDebug (5, "ArgusGetInterfaceAddresses: %-7s: %s", p->ifa_name, ip_addr);
#endif
                  break;
               }


               case AF_INET6: {
#if defined(ARGUSDEBUG)
                  ArgusDebug (5, "ArgusGetInterfaceAddresses: %-7s: family AF_INET6", p->ifa_name);
#endif
                  break;
               }

#if defined(AF_LINK)
               case AF_LINK: {
                  extern struct enamemem elabeltable[HASHNAMESIZE];
                  struct sockaddr_dl *sdp = (struct sockaddr_dl *) p->ifa_addr; 
                  static struct argus_etherent e;
                  struct enamemem *tp;
                  char *macstr = NULL;

                  bzero((char *)&e, sizeof(e));
                  bcopy((unsigned char *)(sdp->sdl_data + sdp->sdl_nlen), e.addr, 6);

                  tp = lookup_emem(elabeltable, e.addr);
                  if (tp->e_name == NULL) {
                     macstr = etheraddr_string (parser, e.addr);
                     tp->e_name = savestr(macstr);
                  }
#if defined(ARGUSDEBUG)
                  ArgusDebug (5, "ArgusGetInterfaceAddresses: %-7s: family AF_LINK: %s", p->ifa_name, macstr);
#endif
                  break;
               }
#endif

               default: {
#if defined(ARGUSDEBUG)
#if defined(ARGUS_SOLARIS)
                  ArgusDebug (5, "ArgusGetInterfaceAddresses: %-7s: family %d", p->ifa_name, p->ifa_addr->ss_family);
#else
                  ArgusDebug (5, "ArgusGetInterfaceAddresses: %-7s: family %d", p->ifa_name, p->ifa_addr->sa_family);
#endif
#endif
                  break;
               }
            }
         }
      }
      freeifaddrs(ifa);
   }
#endif

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "ArgusGetInterfaceAddresses () done"); 
#endif
}
