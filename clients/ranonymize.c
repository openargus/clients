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
 * 
 * $Id: //depot/argus/clients/clients/ranonymize.c#37 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

/*
 * ranonymize.c  - anonymize fields in argus records.
 *       
 * written by Carter Bullard
 * QoSient, LLC
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

#include <ranonymize.h>

#define MAX_OBJ_SIZE            1024

unsigned int RaMapHash = 0;
unsigned int RaHashSize  = 1024;

unsigned short RaMapIpIdValue = 0;
unsigned int RaMapOffsetValue  = 0;
unsigned int RaMapTransOffsetValue  = 0;
unsigned int RaMapASNumOffsetValue  = 0;
unsigned int RaMapSequenceOffsetValue = 0;
unsigned int RaMapTimeSecOffsetValue  = 0;
unsigned int RaMapTimeuSecOffsetValue = 0;
unsigned int RaPortMappingOffsetValue = 0;
unsigned char RaTosMappingOffsetValue = 0;

int RaMapMacCounter = 0;
int RaMapMacMultiCastCounter = 0;
int RaMapClassACounter = 0;
int RaMapClassBCounter = 0;
int RaMapClassCCounter = 0;
int RaMapClassANetCounter = 0;
int RaMapClassBNetCounter = 0;
int RaMapClassCNetCounter = 0;
int RaMapMultiCastCounter = 0;

int RaMapASNumberCounter = 0;

struct ArgusListStruct *RaMapEtherAddrList = NULL;
struct ArgusListStruct *RaMapIPAddrList = NULL;

void ArgusAnonymizeTransport(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeTime(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeTimeAdjust(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeFlow(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeMetric(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeAgr(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeFrag(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeNetwork(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeASNumber(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeVlan(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeMpls(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeMac(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeJitter(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeIPattribute(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeSrcUserData(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeDstUserData(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeIcmp(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeCorrelate(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizePacketSize(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeEncaps(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeBehavior(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeLabel(struct ArgusParserStruct *, struct ArgusRecordStruct *);
void ArgusAnonymizeCountryCode(struct ArgusParserStruct *, struct ArgusRecordStruct *);

unsigned char RaMapInventoryToTTL (void *, int, int);

struct RaMapHashTableStruct {
   int size;
   struct RaMapHashTableHeader **array;
};

struct RaMapHashTableHeader {
   struct RaMapHashTableHeader *nxt, *prv;
   unsigned int hash;
   int type, len, value, mask;
   struct RaClassNets *net;
   void *obj, *sub;
};

struct RaMapHashTableStruct RaMapHashTable;
struct RaMapHashTableStruct RaMapNetTable;

struct RaClassNets {
   struct RaClassNets *supernet;
   unsigned int net;
   unsigned int index;
};

struct RaClassNets *RaClassANets[256];


#define RA_MAX_PROTO            255
#define RA_MAX_PORT             65535


unsigned short RaProtoMapping [256];
unsigned short RaPortMapping [65536];
unsigned short RaPortRandom [65536];
unsigned short RaPortTemp [65536];
int RaMapConvert = 0;

int RaNonParseResourceFile (char *);

int RaPreserveBroadcastAddress = 1;
int RaPreserveWellKnownPorts = 1;
int RaPreserveRegisteredPorts = 0;
int RaPreservePrivatePorts = 0;
int RaPreserveIpId = 0;

char *RaNonSeed = "time";
char *RaNonTransRefNumOffset = "random";
char *RaNonSeqNumOffset = "random";
char *RaNonTimeSecOffset = "random";
char *RaNonTimeuSecOffset = "random";
char *RaPortMappingOffset = "offset:random";
char *RaNonASNumOffset = "random";

#define RANON_NONE              0
#define RANON_SUBNET            1
#define RANON_CLASS             2
#define RANON_CIDR              3

#define RANON_RANDOM            1
#define RANON_SHIFT             2


char *RaNonPreserveNetAddrHierarchy = "class";
unsigned int RaMapNetAddrHierarchy = RANON_CLASS;


#define ARGUS_ADD_OPTION		1
#define ARGUS_SUB_OPTION		2

int ArgusDSRFields[ARGUSMAXDSRTYPE];
extern char *ArgusDSRKeyWords[ARGUSMAXDSRTYPE];

int ArgusFirstMOptionField = 1;

void ArgusProcessOptions(struct ArgusModeStruct *);

struct RaMapHashTableHeader *RaMapAllocateEtherAddr (struct ether_header *, int, int);
struct RaMapHashTableHeader *RaMapAllocateASNumber (unsigned int *, int, int);
struct RaMapHashTableHeader *RaMapAllocateIPAddr (unsigned int *, int, int);
struct RaMapHashTableHeader *RaMapAllocateNet (unsigned int, unsigned int);

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct ArgusModeStruct *mode = NULL, *pmode = NULL;;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   int retn, cnt, ind = 0, x, y, count = 0, shiftcount = 0, start;
   unsigned short i, value, startport = 0;
   char *ptr = NULL;

   parser->RaWriteOut = 0;
   parser->RaCumulativeMerge = 1;
   RaMapConvert = 1;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      (void) signal (SIGTERM, (void (*)(int)) RaParseComplete);
      (void) signal (SIGQUIT, (void (*)(int)) RaParseComplete);
      (void) signal (SIGINT,  (void (*)(int)) RaParseComplete);

      parser->RaInitialized++;

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            struct ArgusModeStruct *tmode;

            if (!(strncasecmp (mode->mode, "poll", 4)))
               parser->RaPollMode++;
            else
            if (!(strncasecmp (mode->mode, "rmon", 4)))
               parser->RaMonMode++;
            else
            if (!(strncasecmp (mode->mode, "uni", 3)))
               parser->RaUniMode++;
            else
            if (!(strncasecmp (mode->mode, "oui", 3)))
               parser->ArgusPrintEthernetVendors++;
            else
            if (!(strncasecmp (mode->mode, "man", 3)))
               parser->ArgusPrintMan = 1;
            else
            if (!(strncasecmp (mode->mode, "noman", 5)))
               parser->ArgusPrintMan = 0;
            else
            if (!(strncasecmp ("replace", mode->mode, strlen("replace")))) {
               ArgusProcessFileIndependantly = 1;
               parser->ArgusReplaceMode++;
               if ((parser->ArgusWfileList != NULL) && (!(ArgusListEmpty(parser->ArgusWfileList)))) {
                  ArgusLog (LOG_ERR, "replace mode and -w option are incompatible\n");
               }
               if (pmode) {
                  pmode->nxt = mode->nxt;
               }
               tmode = mode;
               mode = mode->nxt;
               free(tmode->mode);
               ArgusFree(tmode);
               if ((pmode == NULL) && (mode == NULL))
                  parser->ArgusModeList = NULL;

            } else {
               pmode = mode;
               mode  = mode->nxt;
            }
         }
      }

      if ((mode = parser->ArgusModeList) != NULL)
         ArgusProcessOptions(mode);
      else {
         bzero ((char *)ArgusDSRFields, sizeof(ArgusDSRFields));
         ArgusDSRFields[ARGUS_FLOW_INDEX] = 1;
         ArgusDSRFields[ARGUS_NETWORK_INDEX] = 1;
         ArgusDSRFields[ARGUS_ICMP_INDEX] = 1;
         ArgusDSRFields[ARGUS_ASN_INDEX] = 1;
      }


      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if ((RaMapHashTable.array = (struct RaMapHashTableHeader **)
                  ArgusCalloc (RaHashSize, sizeof (struct RaMapHashTableHeader))) == NULL)
         ArgusLog (LOG_ERR, "RaMapInit: ArgusCalloc error %s\n", strerror(errno));

      RaMapHashTable.size = RaHashSize;

      if ((RaMapNetTable.array = (struct RaMapHashTableHeader **)
                  ArgusCalloc (RaHashSize, sizeof (struct RaMapHashTableHeader))) == NULL)
         ArgusLog (LOG_ERR, "RaMapInit: ArgusCalloc error %s\n", strerror(errno));

      RaMapNetTable.size = RaHashSize;

      if (parser->ArgusFlowModelFile)
         if ((RaNonParseResourceFile (parser->ArgusFlowModelFile)) < 0)
            exit(0);

      bzero ((char *)RaClassANets, sizeof(RaClassANets));

      if (isdigit((int) *RaNonSeed)) {
         unsigned long seed = 0;
         char *ptr;

         seed = strtol(RaNonSeed, (char **)&ptr, 10);
         srandom(seed);

      } else
      if (!(strncmp(RaNonSeed, "crypto", 6))) {
#if defined(HAVE_SRANDOMDEV)
         srandomdev();
#else
         gettimeofday(tvp, 0L);
         srandom(tvp->tv_usec);
#endif
      } else
      if (!(strncmp(RaNonSeed, "time", 4))) {
         gettimeofday(tvp, 0L);
         srandom(tvp->tv_usec);
      }

      if (!(strncmp(RaNonTransRefNumOffset, "random", 6)))
         RaMapTransOffsetValue    = random() % 100000;
      else {
         if (!(strncmp(RaNonTransRefNumOffset, "fixed", 5))) {
            if ((ptr = strchr(RaNonTransRefNumOffset, ':')) != NULL)
               RaMapTransOffsetValue = atoi(++ptr);
            else
               ArgusLog(LOG_ERR, "RANON_TIME_SEC_OFFSET syntax error\n");
         } else
            if (!(strncmp(RaNonTransRefNumOffset, "no", 2)))
               RaMapTransOffsetValue = 0;
            else
               ArgusLog(LOG_ERR, "RANON_TRANSREFNUM_OFFSET syntax error\n");
      }

      if (!(strncmp(RaNonASNumOffset, "random", 6)))
         RaMapASNumOffsetValue = random() % 1000000;
      else {
         if (!(strncmp(RaNonASNumOffset, "fixed", 5))) {
            if ((ptr = strchr(RaNonASNumOffset, ':')) != NULL)
               RaMapASNumOffsetValue = atoi(++ptr);
            else
               ArgusLog(LOG_ERR, "RANON_TIME_SEC_OFFSET syntax error\n");
         } else
            if (!(strncmp(RaNonASNumOffset, "no", 2)))
               RaMapASNumOffsetValue = 0;
            else
               ArgusLog(LOG_ERR, "RANON_SEQASNUM_OFFSET syntax error\n");
      }

      if (!(strncmp(RaNonSeqNumOffset, "random", 6)))
         RaMapSequenceOffsetValue = random() % 1000000;
      else {
         if (!(strncmp(RaNonSeqNumOffset, "fixed", 5))) {
            if ((ptr = strchr(RaNonSeqNumOffset, ':')) != NULL)
               RaMapSequenceOffsetValue = atoi(++ptr);
            else
               ArgusLog(LOG_ERR, "RANON_TIME_SEC_OFFSET syntax error\n");
         } else
            if (!(strncmp(RaNonSeqNumOffset, "no", 2)))
               RaMapSequenceOffsetValue = 0;
            else
               ArgusLog(LOG_ERR, "RANON_SEQNUM_OFFSET syntax error\n");
      }

      if (!(strncmp(RaNonTimeSecOffset, "random", 6)))
         RaMapTimeSecOffsetValue  = random();
      else {
         if (!(strncmp(RaNonTimeSecOffset, "fixed", 5))) {
            if ((ptr = strchr(RaNonTimeSecOffset, ':')) != NULL)
               RaMapTimeSecOffsetValue = atoi(++ptr);
            else
               ArgusLog(LOG_ERR, "RANON_TIME_SEC_OFFSET syntax error\n");
         } else
            if (!(strncmp(RaNonTimeSecOffset, "no", 2)))
               RaMapTimeSecOffsetValue  = 0;
            else
               ArgusLog(LOG_ERR, "RANON_TIME_SEC_OFFSET syntax error\n");
      }

      if (!(strncmp(RaNonTimeuSecOffset, "random", 6)))
         RaMapTimeuSecOffsetValue = random() % 500000;
      else {
         if (!(strncmp(RaNonTimeuSecOffset, "fixed", 5))) {
            if ((ptr = strchr(RaNonTimeuSecOffset, ':')) != NULL)
               RaMapTimeuSecOffsetValue = atoi(++ptr);
            else
               ArgusLog(LOG_ERR, "RANON_TIME_USEC_OFFSET syntax error\n");
         } else
            if (!(strncmp(RaNonTimeuSecOffset, "no", 2)))
               RaMapTimeuSecOffsetValue = 0;
            else
               ArgusLog(LOG_ERR, "RANON_TIME_USEC_OFFSET syntax error\n");
      }

      if (!(strncmp(RaNonPreserveNetAddrHierarchy, "cidr", 4))) {
         RaMapNetAddrHierarchy = RANON_CIDR;
      } else {
         if (!(strncmp(RaNonPreserveNetAddrHierarchy, "class", 5))) {
               RaMapNetAddrHierarchy = RANON_CLASS;
         } else {
            if (!(strncmp(RaNonPreserveNetAddrHierarchy, "subnet", 6)))
               RaMapNetAddrHierarchy = RANON_SUBNET;
            else {
               if (!(strncmp(RaNonPreserveNetAddrHierarchy, "no", 2)))
                  RaMapNetAddrHierarchy = RANON_NONE;
               else
                  ArgusLog(LOG_ERR, "RANON_PRESERVE_NET_ADDRESS_HIERARCHY syntax error\n");
            }
         }
      }

      if (!(RaPreserveIpId))
         RaMapIpIdValue = (unsigned short) (random() % 0x10000);

      bzero ((char *) RaProtoMapping, sizeof(RaProtoMapping));
      bzero ((char *) RaPortMapping, sizeof(RaPortMapping));
      bzero ((char *) RaPortRandom, sizeof(RaPortRandom));

      for (i = 0; i < RA_MAX_PROTO; i++)
         RaProtoMapping[i] = i;

      for (i = 0; i < RA_MAX_PORT; i++) {
         RaPortMapping[i] = i;
         RaPortRandom[i] = i;
      }

      RaPortMapping[RA_MAX_PORT] = RA_MAX_PORT;
      RaPortMapping[RA_MAX_PORT] = RA_MAX_PORT;

      if (RaPreserveWellKnownPorts) {
         if (RaPreserveRegisteredPorts) {
            if (RaPreservePrivatePorts) {
                  startport = RA_MAX_PORT - 1;
            } else
               startport = 49152;
         } else
            startport = 1024;
      } else
         startport = 1;

      if (!(strncmp(RaPortMappingOffset, "random", 6))) {
         for (i = startport, start = startport; i < RA_MAX_PORT; i++) {
               if (shiftcount > 5) {
                  cnt = 0;
                  shiftcount = 0;
                  y = start;
                  bzero ((char *) RaPortTemp, sizeof(RaPortTemp));
                  for (x = i; x < RA_MAX_PORT; x++) {
                     while ((RaPortRandom[y] == 0) && (y < RA_MAX_PORT)) y++;
                     if (RaPortRandom[y]) {
                        RaPortTemp[x] = RaPortRandom[y];
                        RaPortRandom[y] = 0;
                        cnt++;
                     } else
                        break;
                  }
                  bcopy ((char *)RaPortTemp, (char *) RaPortRandom, sizeof(RaPortRandom));
                  start = i;
               }

               retn = i + (random() % (RA_MAX_PORT - i));
               ind = retn;
               while (RaPortRandom[ind] == 0) {
                  if (retn & 0x01) {
                     if (ind >= start) {
                        ind--;
                     } else {
                        ind = retn++;
                        shiftcount++;
                     }
                  } else {
                     if (ind <= RA_MAX_PORT) {
                        ind++;
                     } else {
                        ind = retn--;
                        shiftcount++;
                     }
                  }
               }

               if ((value = RaPortRandom[ind])) {
                  RaPortMapping[i] = value;
                  RaPortRandom[ind] = 0;
                  count++;
               }
         }
      } else {
         if (!(strncmp(RaPortMappingOffset, "offset:random", 13))) {
            RaPortMappingOffsetValue = (random() % RA_MAX_PORT);
         } else 
         if (!(strncmp(RaPortMappingOffset, "offset:fixed", 12))) {
            if ((ptr = strchr(RaPortMappingOffset, ':')) != NULL)
               RaPortMappingOffsetValue = atoi(++ptr);
            else
               ArgusLog(LOG_ERR, "RANON_PORT_METHOD syntax error\n");
         } else 
         if (!(strncmp(RaPortMappingOffset, "no", 2)))
            RaPortMappingOffsetValue = 0;
         else
            ArgusLog(LOG_ERR, "RANON_PORT_METHOD syntax error\n");

         if (RaPortMappingOffsetValue > 0) {
            for (i = startport, start = startport; i < RA_MAX_PORT; i++) {
               RaPortMapping[i] += RaPortMappingOffsetValue;
               if (RaPortMapping[i] < startport)
                  RaPortMapping[i] += startport;
            }
         }
      }
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
               ArgusLog(LOG_INFO, "file %s anonymized", input->filename);
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
      if (!(ArgusParser->RaParseCompleting++)) {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(caught signal %d)\n", sig);
#endif
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

   fprintf (stdout, "Ranonymize Version %s\n", version);
   fprintf (stdout, "usage: %s [-M [modes] [+|-]dsr [dsr ...]] [ra-options]\n\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -M replace      nonymize dsrs and overwrite current file.\n");
   fprintf (stdout, "            [+|-] dsrs   [add|subtract] dsrs from records.\n");
   fprintf (stdout, "               dsrs:     stime, ltime, count, dur, avgdur,\n");
   fprintf (stdout, "                         srcid, ind, mac, dir, jitter, status, user,\n");
   fprintf (stdout, "                         win, trans, seq, vlan, vid, vpri, mpls.\n");
   fflush (stdout);

   exit(1);
}

#define RAMAP_ETHER_MAC_ADDR            0x1
#define RAMAP_IP_ADDR                   0x10
#define RAMAP_AS_NUMBER                 0x20

int RaFirstRecord = 1;

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusInput *input = argus->input;
   static char buf[MAXSTRLEN];
   int label, x;

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

   if (RaFirstRecord) {
#ifdef _LITTLE_ENDIAN
      ArgusNtoH(&input->ArgusInitCon);
#endif
      RaMapInventory(&input->ArgusInitCon.argus_mar.localnet, RAMAP_IP_ADDR, 4);
      RaMapInventory(&input->ArgusInitCon.argus_mar.argusid, RAMAP_IP_ADDR, 4);

      input->ArgusInitCon.argus_mar.startime.tv_sec  -= RaMapTimeSecOffsetValue;
      input->ArgusInitCon.argus_mar.startime.tv_usec -= RaMapTimeuSecOffsetValue;
      if (input->ArgusInitCon.argus_mar.startime.tv_usec < 0) {
         input->ArgusInitCon.argus_mar.startime.tv_sec--;
         input->ArgusInitCon.argus_mar.startime.tv_usec += 1000000;
      }

      input->ArgusInitCon.argus_mar.now.tv_sec  -= RaMapTimeSecOffsetValue;
      input->ArgusInitCon.argus_mar.now.tv_usec -= RaMapTimeuSecOffsetValue;
      if (input->ArgusInitCon.argus_mar.now.tv_usec < 0) {
         input->ArgusInitCon.argus_mar.now.tv_sec--;
         input->ArgusInitCon.argus_mar.now.tv_usec += 1000000;
      }

#ifdef _LITTLE_ENDIAN
      ArgusHtoN(&input->ArgusInitCon);
#endif
      RaFirstRecord = 0;
   }


   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         for (x = 0; x < ARGUSMAXDSRTYPE; x++) {
            if (ArgusDSRFields[x]) {
               switch (x) {
/*
#define ARGUS_TRANSPORT_INDEX		0
#define ARGUS_FLOW_INDEX		1
#define ARGUS_TIME_INDEX		2
#define ARGUS_METRIC_INDEX		3
#define ARGUS_AGR_INDEX			4
#define ARGUS_FRAG_INDEX		5
#define ARGUS_NETWORK_INDEX		5 
#define ARGUS_VLAN_INDEX                6 
#define ARGUS_MPLS_INDEX                7
#define ARGUS_JITTER_INDEX              8
#define ARGUS_IPATTR_INDEX              9
#define ARGUS_PSIZE_INDEX               10
#define ARGUS_SRCUSERDATA_INDEX		11
#define ARGUS_DSTUSERDATA_INDEX		12
#define ARGUS_MAC_INDEX                 13 
#define ARGUS_ICMP_INDEX		14
#define ARGUS_ENCAPS_INDEX              15
#define ARGUS_TIME_ADJ_INDEX		16
#define ARGUS_BEHAVIOR_INDEX            17
#define ARGUS_HISTO_INDEX               18
#define ARGUS_COR_INDEX			18
#define ARGUS_COCODE_INDEX		19
#define ARGUS_LABEL_INDEX               20
#define ARGUS_ASN_INDEX                 21
*/

                  case ARGUS_TRANSPORT_INDEX:   ArgusAnonymizeTransport(parser, argus); break;
                  case ARGUS_FLOW_INDEX:        ArgusAnonymizeFlow(parser, argus); break;
                  case ARGUS_TIME_INDEX:        ArgusAnonymizeTime(parser, argus); break;
                  case ARGUS_METRIC_INDEX:      ArgusAnonymizeMetric(parser, argus); break;
                  case ARGUS_AGR_INDEX:         ArgusAnonymizeAgr(parser, argus); break;
                  case ARGUS_NETWORK_INDEX:     ArgusAnonymizeNetwork(parser, argus); break;
                  case ARGUS_VLAN_INDEX:        ArgusAnonymizeVlan(parser, argus); break;
                  case ARGUS_MPLS_INDEX:        ArgusAnonymizeMpls(parser, argus); break;
                  case ARGUS_JITTER_INDEX:      ArgusAnonymizeJitter(parser, argus); break;
                  case ARGUS_IPATTR_INDEX:      ArgusAnonymizeIPattribute(parser, argus); break;
                  case ARGUS_PSIZE_INDEX:       ArgusAnonymizePacketSize(parser, argus); break;
                  case ARGUS_SRCUSERDATA_INDEX: ArgusAnonymizeSrcUserData(parser, argus); break;
                  case ARGUS_DSTUSERDATA_INDEX: ArgusAnonymizeDstUserData(parser, argus); break;
                  case ARGUS_MAC_INDEX:         ArgusAnonymizeMac(parser, argus); break;
                  case ARGUS_ICMP_INDEX:        ArgusAnonymizeIcmp(parser, argus); break;
                  case ARGUS_ENCAPS_INDEX:      ArgusAnonymizeEncaps(parser, argus); break;
                  case ARGUS_TIME_ADJ_INDEX:    ArgusAnonymizeTimeAdjust(parser, argus); break;
                  case ARGUS_BEHAVIOR_INDEX:    ArgusAnonymizeBehavior(parser, argus); break;
                  case ARGUS_COR_INDEX:         ArgusAnonymizeCorrelate(parser, argus); break;
                  case ARGUS_COCODE_INDEX:      ArgusAnonymizeCountryCode(parser, argus); break;
                  case ARGUS_LABEL_INDEX:       ArgusAnonymizeLabel(parser, argus); break;
                  case ARGUS_ASN_INDEX:         ArgusAnonymizeASNumber(parser, argus); break;
               }
            } else {
            }
         }
         
         if (parser->ArgusWfileList != NULL) {
            struct ArgusWfileStruct *wfile = NULL;
            struct ArgusListObjectStruct *lobj = NULL;
            int i, count = parser->ArgusWfileList->count;

            if ((lobj = parser->ArgusWfileList->start) != NULL) {
               for (i = 0; i < count; i++) {
                  if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                     int pass = 1;
                     if (wfile->filterstr) {
                        struct nff_insn *wfcode = wfile->filter.bf_insns;
                        pass = ArgusFilterRecord (wfcode, argus);
                     }

                     if (pass != 0) {
                        if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                           struct ArgusRecord *argusrec = NULL;
                           static char sbuf[0x10000];
                           if ((argusrec = ArgusGenerateRecord (argus, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                              ArgusHtoN(argusrec);
#endif
                              ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                           }
                        }
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
         break;
      }
   }
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}

void
ArgusProcessOptions(struct ArgusModeStruct *mode)
{
   int x, RaOptionOperation, setValue = 0;
   char *ptr = NULL;

   if (mode != NULL) {
      while (mode) {
         if ((strcmp ("replace", mode->mode))) {
            if (isdigit((int)*mode->mode)) {

            } else {
               if (*mode->mode == '-') {
                  if (ArgusFirstMOptionField) {
                     for (x = 0; x < ARGUSMAXDSRTYPE; x++)
                        ArgusDSRFields[x] = 1;
                     ArgusFirstMOptionField = 0;
                  }
                  ptr = mode->mode + 1;
                  RaOptionOperation = ARGUS_SUB_OPTION;
               } else 
               if (*mode->mode == '+') {
                  if (ArgusFirstMOptionField) {
                     bzero ((char *)ArgusDSRFields, sizeof(ArgusDSRFields));
                     ArgusDSRFields[ARGUS_FLOW_INDEX] = 1;
                     ArgusDSRFields[ARGUS_NETWORK_INDEX] = 1;
                  }
                  ptr = mode->mode + 1;
                  RaOptionOperation = ARGUS_ADD_OPTION;
               } else {
                  if (ArgusFirstMOptionField) {
                     bzero ((char *) ArgusDSRFields, sizeof(ArgusDSRFields));
                     ArgusFirstMOptionField = 0;
                  }
                  ptr = mode->mode;
                  RaOptionOperation = ARGUS_ADD_OPTION;
               }

               setValue = (RaOptionOperation == ARGUS_ADD_OPTION) ? 1 : 0;

               for (x = 0; x < ARGUSMAXDSRTYPE; x++) {
                  if (ArgusDSRKeyWords[x] != NULL) {
                     if (!strncmp (ArgusDSRKeyWords[x], ptr, strlen(ArgusDSRKeyWords[x]))) {
                        ArgusDSRFields[x] = setValue;
                        break;
                     }
                  }
               }
            }
         }

         mode = mode->nxt;
      }
   }
}


#ifndef RaMap
#define RaMap
#endif

#ifndef RaMapUtil
#define RaMapUtil
#endif

#include <unistd.h>
#include <stdlib.h>

#include <arpa/inet.h>


#define MAXSTRSIZE 1024
#define MAX_OBJ_SIZE		1024

 
struct RaMapHashTableStruct RaMapHashTable;

#ifndef IN_CLASSD
#define IN_CLASSD(i) (((int32_t)(i) & 0xf0000000) == 0xe0000000)
#endif

int RaPreserveEtherVendor = 0;
int RaPreserveIPHierarchy = 1;
int RaPreserveNoHierarchy = 0;

unsigned int RaMapEtherAddrs = 2;
unsigned int RaMapIPAddrs = 2;


#define ETHER_INTERNET_BROADCAST	0x01005E00
#define RA_ETHER_VENDOR			0x00000001

struct RaMapHashTableHeader *RaMapFindHashObject (struct RaMapHashTableStruct *, void *, int, int);
struct RaMapHashTableHeader *RaMapAddHashEntry (struct RaMapHashTableStruct *, void *, int, int);
void RaMapRemoveHashEntry (struct RaMapHashTableStruct *, struct RaMapHashTableHeader *);
unsigned int RaMapCalcHash (void *, int, int);

extern char *etheraddr_string(struct ArgusParserStruct *, u_char *);


struct RaMapHashTableHeader *
RaMapAllocateEtherAddr (struct ether_header *src, int type, int len)
{
   struct RaMapHashTableHeader *retn = NULL;
   struct ether_header dstbuf, *dst = &dstbuf;
   unsigned int RaMapEtherVendors = htonl(RA_ETHER_VENDOR);
   unsigned int tmp = htonl(ETHER_INTERNET_BROADCAST);
   unsigned char *ptr = (unsigned char *) src;
   int i = 0, broadcast = 1;
   
   if (src) {
      for (i = 0; i < 6; i++)
         if (ptr[i] != (unsigned char) 0xff)
            broadcast = 0;

      if (broadcast) {
         bcopy ((char *) src, (char *) dst, 6);

      } else {
         if (RaPreserveEtherVendor || (!(bcmp (((char *)src), (char *)&tmp, 3)))) {
            bcopy ((char *) src, (char *) dst, 3);
         } else {
            for (i = 0; i < (sizeof (int) - 1); i++)
               ((char *)dst)[i] = ((char *)&RaMapEtherVendors)[i + 1];
         }

         ptr = &((unsigned char *) dst)[3];

         RaMapEtherAddrs = ntohl(RaMapEtherAddrs);

         for (i = 0; i < (sizeof (int) - 1); i++)
            ptr[i] = ((char *)&RaMapEtherAddrs)[i + 1];

         ptr = (unsigned char *) src;

         if (ptr[5] & 0x01)
            ((unsigned char *) dst)[5] |= 0x01;

         RaMapEtherAddrs = htonl(RaMapEtherAddrs);

         RaMapEtherAddrs += 2;
      }

      if (!(retn = RaMapAddHashEntry (&RaMapHashTable, src, type, len))) {
         ArgusLog (LOG_ERR, "RaMapInventory: RaMapAddHashEntry error %s\n", strerror(errno));
      } else {
         if (((char *)src)[0] & 0x01) {
            RaMapMacMultiCastCounter++;
#ifdef ARGUSDEBUG
            ArgusDebug (2, "RaMapInventory () adding multicast addr %s\n", etheraddr_string (ArgusParser, (u_char *)src));
#endif
         } else {
            RaMapMacCounter++;
#ifdef ARGUSDEBUG
            ArgusDebug (2, "RaMapInventory () adding %s\n", etheraddr_string (ArgusParser, (u_char *)src));
#endif
         }

         if ((retn->sub = (void *) ArgusCalloc (1, len)) != NULL)
            bcopy ((char *) dst, (char *) retn->sub, len);
      }

#ifdef ARGUSDEBUG
   {
      char sbuf1[32], sbuf2[32];
      sprintf (sbuf1, "%s", etheraddr_string (ArgusParser, (u_char *) dst));
      sprintf (sbuf2, "%s", etheraddr_string (ArgusParser, (u_char *) src));
      ArgusDebug (2, "RaMapAllocateEtherAddr allocating %s for %s", sbuf1, sbuf2);
   }
#endif
   }

   return (retn);
}

/*
   So available class A addresses for our algorithm are
   [0 1 2 5 10 23 27 31 36 37 39 41 42 58-60 69-79 82-127 197 220-223 240-254]
   we will start with 1.0.0 and move up to 254.0.0
*/

#define RA_MAX_CLASS_VALUE	65535
#define RA_MAX_CLASS		109
int RaClassIndex = 0;

int RaClassAddress[RA_MAX_CLASS] =
{  1,2,5,10,23,27,31,36,37,39,
   41,42,58,59,60,69,70,71,72,73,
   74,75,76,77,78,79,82,83,84,85,
   86,87,88,89,90,91,92,93,94,95,
   96,97,98,99,
   100,101,102,103,104,105,106,107,108,109,
   110,111,112,113,114,115,116,117,118,119,
   120,121,122,123,124,125,126,127, 197,
   220,221,222,223,224,225,226,227,228,229,
   230,231,232,233,234,235,236,237,238,239,
   240,241,242,243,244,245,246,247,248,249,
   250,251,252,253,254,255,
};

#define RA_MAX_CLASS_A		44
int RaClassAIndex = 0;

int RaClassAAddress[RA_MAX_CLASS_A] =
{  1,2,5,10,23,27,31,36,37,39,
   41,42,58,59,60,69,70,71,72,73,
   74,75,76,77,78,79,82,83,84,85,
   86,87,88,89,90,91,92,93,94,95,
   96,97,98,99,
};

#define RA_MAX_CLASS_B		28
int RaClassBIndex = 0;

int RaClassBAddress[RA_MAX_CLASS_B] = 
{  100,101,102,103,104,105,106,107,108,109,
   110,111,112,113,114,115,116,117,118,119,
   120,121,122,123,124,125,126,127,
};

#define RA_MAX_CLASS_C		21
int RaClassCIndex = 0;

int RaClassCAddress[RA_MAX_CLASS_C] = 
{  197,220,221,222,223,240,241,242,243,244,
   245,246,247,248,249,250,251,252,253,254,
   255,
};

#define RA_MAX_CLASS_M		16
int RaClassMIndex = 0;

int RaClassMAddress[RA_MAX_CLASS_M] = 
{  
   224,225,226,227,228,229,230,231,232,233,
   234,235,236,237,238,239,
};


/* in comes a request for a network alias */

#ifndef IN_CLASSD_NET
#define IN_CLASSD_NET	0xffffffff
#endif

struct RaMapHashTableHeader *RaMapNewNetwork (unsigned int, unsigned int);

unsigned int RaMapLocalNetwork = 0;

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define RAMAP_CLASSA	1
#define RAMAP_CLASSB	2
#define RAMAP_CLASSC	3
#define RAMAP_CLASSM	4

struct RaMapHashTableHeader *
RaMapNewNetwork (unsigned int host, unsigned int mask)
{
   struct RaMapHashTableHeader *retn = NULL;
   struct RaClassNets *thisNet = NULL;
   char buf[MAXSTRLEN];
   struct in_addr addrbuf, *addr = &addrbuf;
   struct hostent *hp;
   unsigned int **p;
   int hostclass;

   if (IN_CLASSA(host)) hostclass = RAMAP_CLASSA; else
   if (IN_CLASSB(host)) hostclass = RAMAP_CLASSB; else
   if (IN_CLASSC(host)) hostclass = RAMAP_CLASSC; else
   if (IN_CLASSD(host)) hostclass = RAMAP_CLASSM; else
   hostclass = RAMAP_CLASSC;

   bzero (buf, MAXSTRLEN);
   do {
      if (RaMapNetAddrHierarchy > RANON_SUBNET) {
         switch (hostclass) {
            case RAMAP_CLASSA:
               sprintf (buf, "%d.0.0.0", RaClassAAddress[RaClassAIndex]);
               break;
            case RAMAP_CLASSB:
               sprintf (buf, "%d.0.0.0", RaClassBAddress[RaClassBIndex]);
               break;
            default:
            case RAMAP_CLASSC:
               sprintf (buf, "%d.0.0.0", RaClassCAddress[RaClassCIndex]);
               break;
            case RAMAP_CLASSM:
               sprintf (buf, "%d.0.0.0", RaClassMAddress[RaClassMIndex]);
               break;
         }
      } else
         sprintf (buf, "%d.0.0.0", RaClassAddress[RaClassIndex]);
   
      if ((hp = gethostbyname(buf)) != NULL) {
         for (p = (unsigned int **)hp->h_addr_list; *p; ++p)
            **p = ntohl(**p);
      } else
         ArgusLog (LOG_ERR, "RaMapNewNetwork: gethostbyname(%s) error %s", optarg, strerror(errno));
   
      addr->s_addr = **(unsigned int **)hp->h_addr_list;
      if ((retn = RaMapFindHashObject (&RaMapNetTable, &addr->s_addr, RAMAP_IP_ADDR, 4))) {
         if (retn->net->index >= RA_MAX_CLASS_VALUE) {
            if (RaMapNetAddrHierarchy > RANON_SUBNET) {
               switch (hostclass) {
                  case RAMAP_CLASSA:
                     if (RaClassAIndex < RA_MAX_CLASS_A) {
                        RaClassAIndex++;
                        break;
                     } else
                        hostclass = RAMAP_CLASSB;
                  case RAMAP_CLASSB:
                     if (RaClassBIndex < RA_MAX_CLASS_B) {
                        RaClassBIndex++;
                        break;
                     } else
                        hostclass = RAMAP_CLASSC;
                  case RAMAP_CLASSC:
                     if (RaClassCIndex < RA_MAX_CLASS_C) {
                        RaClassCIndex++;
                        break;
                     } else
                        ArgusLog (LOG_ERR, "RaMapNewNetwork: no addresses");

                  case RAMAP_CLASSM:
                     if (RaClassMIndex < RA_MAX_CLASS_M) {
                        RaClassMIndex++;
                     } else
                        ArgusLog (LOG_ERR, "RaMapNewNetwork: no multicast addresses");
               }
            }
         }
      }

   } while (retn && (retn->net->index >= RA_MAX_CLASS_VALUE));

   if (!(retn)) {
      if ((retn = RaMapAddHashEntry (&RaMapNetTable, &addr->s_addr, RAMAP_IP_ADDR, 4))) {
         if ((thisNet = (void *) ArgusCalloc (1, sizeof(struct RaClassNets))) != NULL) {
            thisNet->net = addr->s_addr;
            thisNet->index = 1;
            retn->net = thisNet;

            if ((retn->sub = (void *) ArgusCalloc (1, sizeof(addr->s_addr))) != NULL)
               bcopy ((char *)&addr->s_addr, (char *) retn->sub, sizeof(addr->s_addr));
            else
               ArgusLog (LOG_ERR, "RaMapNewNetwork: ArgusCalloc() error %s", strerror(errno));

         } else
            ArgusLog (LOG_ERR, "RaMapNewNetwork: ArgusCalloc() error %s", strerror(errno));
      } else
         ArgusLog (LOG_ERR, "RaMapNewNetwork: RaMapAddHashEntry() error %s", strerror(errno));
   }

#ifdef ARGUSDEBUG
   {
      char sbuf1[32], sbuf2[32];
      sprintf (sbuf1, "%s", ipaddr_string(&host));
      sprintf (sbuf2, "%s", ipaddr_string(&mask));
      ArgusDebug (2, "RaMapNewNetwork (%s, %s) returns 0x%x\n", sbuf1, sbuf2, retn);
   }
#endif
   return (retn);
}


struct RaMapHashTableHeader *
RaMapAllocateNet (unsigned int addr, unsigned int mask)
{
   struct RaMapHashTableHeader *retn = NULL;
   struct RaMapHashTableHeader *net = NULL;
   unsigned int newaddr = 0;
   char buf[MAXSTRLEN];

   bzero (buf, MAXSTRLEN);
   if (!(retn = RaMapFindHashObject (&RaMapNetTable, &addr, RAMAP_IP_ADDR, 4))) {
      switch (mask) {
         case IN_CLASSA_NET:
            break;

         case IN_CLASSB_NET:
            if (RaMapNetAddrHierarchy == RANON_CIDR) {
               return (RaMapAllocateNet (addr & IN_CLASSA_NET, IN_CLASSA_NET));
               break;
            }
            break;

         case IN_CLASSC_NET:
            if (RaMapNetAddrHierarchy == RANON_CIDR) {
               return (RaMapAllocateNet (addr & IN_CLASSB_NET, IN_CLASSB_NET));
               break;
            }
            break;

         case IN_CLASSD_NET:
            return (RaMapAllocateNet (addr & IN_CLASSC_NET, IN_CLASSC_NET));
            break;
      }

      if (!(RaMapNetAddrHierarchy)) {
         
      } 

      if (!(net) || (net->net->index >= RA_MAX_CLASS_VALUE))
         net = RaMapNewNetwork(addr, mask);

      if ((retn = RaMapAddHashEntry (&RaMapNetTable, (void *)&addr, RAMAP_IP_ADDR, 4))) {
         if ((retn->net = (void *) ArgusCalloc (1, sizeof(struct RaClassNets))) != NULL) {
            retn->net->supernet = net->net;
            newaddr = net->net->net | (net->net->index++ << 8);
            retn->net->net = newaddr;
            retn->net->index = 1;
         }


         if (!(retn->sub)) {
            if ((retn->sub = (void *) ArgusCalloc (1, 4)) != NULL) {
               bcopy ((char *)&newaddr, (char *) retn->sub, 4);
            } else {
               ArgusLog (LOG_ERR, "RaMapAllocateNet: ArgusCalloc error %s", strerror(errno));
            }
#ifdef ARGUSDEBUG
            {
               char sbuf1[32], sbuf2[32], sbuf3[32];
               sprintf (sbuf1, "%s", ipaddr_string(&addr));
               sprintf (sbuf2, "%s", ipaddr_string(&mask));
               sprintf (sbuf3, "%s", ipaddr_string(&newaddr));
               ArgusDebug (2, "RaMapAllocateNet (%s, %s) maps to %s\n", sbuf1, sbuf2, sbuf3);
            }
#endif
         }
         
      } else
         ArgusLog (LOG_ERR, "RaMapAllocateNet () RaMapAddHashEntry error %s\n", strerror(errno));
   }

#ifdef ARGUSDEBUG
   {
      char sbuf1[32], sbuf2[32];
      sprintf (sbuf1, "%s", ipaddr_string(&addr));
      sprintf (sbuf2, "%s", ipaddr_string(&mask));
      ArgusDebug (2, "RaMapAllocateNet (%s, %s) return 0x%x\n", sbuf1, sbuf2, retn);
   }
#endif

   return (retn);
}


struct RaMapHashTableHeader *
RaMapAllocateIPAddr (unsigned int *addr, int type, int len)
{
   struct RaMapHashTableHeader *retn = NULL, *net = NULL;
   unsigned int newaddr = 0;

   if (!(retn = RaMapFindHashObject (&RaMapHashTable, addr, type, len))) {
      if ((net = RaMapAllocateNet (*addr, IN_CLASSD_NET))) {
         if (((*addr & 0xff) == 0xff) && RaPreserveBroadcastAddress)
            newaddr = *((unsigned int *)net->sub) | 0xFF;
         else
         if (((*addr & 0xff) == 0x00) && RaPreserveBroadcastAddress)
            newaddr = *((unsigned int *)net->sub);
         else
            newaddr = *((unsigned int *)net->sub) + ((struct RaClassNets *)net->net)->index++;

         if ((retn = RaMapAddHashEntry (&RaMapHashTable, (void *)addr, type, len))) {
            retn->net = net->net;
            if ((retn->sub = (void *) ArgusCalloc (1, 4)) != NULL) {
               bcopy ((char *)&newaddr, (char *) retn->sub, 4);
            } else {
               ArgusLog (LOG_ERR, "RaMapAllocateNet: ArgusCalloc error %s", strerror(errno));
            }
         } else
            ArgusLog (LOG_ERR, "RaAllocateIPAddr () RaMapAddHashEntry error %s\n", strerror(errno));

      } else
         ArgusLog (LOG_ERR, "RaAllocateIPAddr () RaMapAllocateNet failed.");
   } else
      newaddr = *(unsigned int *)retn->sub;

#ifdef ARGUSDEBUG
   {
      char sbuf1[32], sbuf2[32];
      sprintf (sbuf1, "%s", ipaddr_string(addr));
      sprintf (sbuf2, "%s", ipaddr_string(&newaddr));
      ArgusDebug (2, "RaAllocateIPAddr (%s, %d, %d) converts to %s\n", sbuf1, type, len, sbuf2);
   }
#endif

   return (retn);
}

struct RaMapHashTableHeader *
RaMapAllocateASNumber (unsigned int *num, int type, int len)
{
   struct RaMapHashTableHeader *retn = NULL;
   
   if (num != NULL) {
      if (!(retn = RaMapAddHashEntry (&RaMapHashTable, num, type, len))) {
         ArgusLog (LOG_ERR, "RaMapInventory: RaMapAddHashEntry error %s\n", strerror(errno));
      }
      RaMapASNumberCounter++;
#ifdef ARGUSDEBUG
      ArgusDebug (2, "RaMapInventory () adding AS %u\n", *num);
#endif
   }
   return (retn);
}

void
RaMapInventory (void *oid, int type, int len)
{
   struct RaMapHashTableHeader *retn = NULL;
   struct ArgusListObjectStruct *lobj = NULL;

   switch (type) {
      case RAMAP_ETHER_MAC_ADDR: {
         if (!(retn = RaMapFindHashObject (&RaMapHashTable, oid, type, len))) {

            if (!(retn = RaMapAllocateEtherAddr (oid, type, len))) 
               ArgusLog (LOG_ERR, "RaMapInventory: RaMapAllocateEtherAddr error %s\n", strerror(errno));

            if (!(RaMapEtherAddrList))
               RaMapEtherAddrList = ArgusNewList();

            if ((lobj = ArgusCalloc(1, sizeof(*lobj))) == NULL)
               ArgusLog (LOG_ERR, "RaMapInventory: ArgusCalloc error %s\n", strerror(errno));

            lobj->list_obj = retn;
            ArgusPushBackList(RaMapEtherAddrList, (struct ArgusListRecord *)lobj, ARGUS_LOCK);
         }

         if (RaMapConvert)
            if (retn->sub)
               bcopy ((char *)retn->sub, (char *) oid, len);
      
         break;     
      }

      case RAMAP_IP_ADDR: {
         if (!(retn = RaMapFindHashObject (&RaMapHashTable, oid, type, len))) {
            if (!(retn = RaMapAllocateIPAddr (oid, type, len)))
               ArgusLog (LOG_ERR, "RaMapInventory: RaMapAllocateIPAddr error %s\n", strerror(errno));
            
            if (!(RaMapIPAddrList))
               RaMapIPAddrList = ArgusNewList();

            if ((lobj = ArgusCalloc(1, sizeof(*lobj))) == NULL)
               ArgusLog (LOG_ERR, "RaMapInventory: ArgusCalloc error %s\n", strerror(errno));

            lobj->list_obj = retn;
            ArgusPushBackList(RaMapIPAddrList, (struct ArgusListRecord *)lobj, ARGUS_LOCK);
         }

         if (RaMapConvert)
            if (retn->sub)
               bcopy ((char *)retn->sub, (char *) oid, len);

         break;     
      }

      case RAMAP_AS_NUMBER: {
         if (!(retn = RaMapFindHashObject (&RaMapHashTable, oid, type, len))) {

            if (!(retn = RaMapAllocateASNumber (oid, type, len)))
               ArgusLog (LOG_ERR, "RaMapInventory: RaMapAllocateASNumber error %s\n", strerror(errno));
         }

         if (RaMapConvert)
            if (retn->sub)
               bcopy ((char *)retn->sub, (char *) oid, len);

         break;     
      }
   }
 
#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaMapInventory (0x%x, %d, %d) returning\n", oid, type, len);
#endif
}

unsigned char
RaMapInventoryToTTL (void *oid, int type, int len)
{
   unsigned char retn = 0;
   
   return (retn);
}


unsigned int
RaMapCalcHash (void *obj, int type, int len)
{
   u_char buf[MAX_OBJ_SIZE];
   unsigned int retn = 0;

   switch (type) {
      case RAMAP_ETHER_MAC_ADDR:
          len = 6;
          break;

      case RAMAP_IP_ADDR:
      case RAMAP_AS_NUMBER:
          len = 4;
          break;

      default:
          break;
   }

   bzero (buf, sizeof buf);

   if (RaHashSize <= 0x100) {
      unsigned char hash = 0, *ptr = (unsigned char *) buf;
      int i, nitems = len;

      bcopy ((char *) obj, (char *) &buf, len);

      for (i = 0; i < nitems; i++)
         hash += *ptr++;

      retn = hash;

   } else
   if (RaHashSize <= 0x10000) {
      unsigned short hash = 0, *ptr = (unsigned short *) buf;
      int i, nitems = (len / sizeof(unsigned short)) + 2;

      bcopy ((char *) obj, &buf[1], len);

      for (i = 0; i < nitems; i++)
         hash += *ptr++;

      retn = hash;

   } else {
      unsigned int hash = 0, *ptr = (unsigned int *) buf;
      int i, nitems = (len /sizeof(unsigned int)) + 2;

      bcopy ((char *) obj, &buf[3], len);

      for (i = 0; i < nitems; i++)
         hash += *ptr++;

      retn = hash;
   }

   return (retn);
}



struct RaMapHashTableHeader *
RaMapFindHashObject (struct RaMapHashTableStruct *table, void *obj, int type, int len)
{
   struct RaMapHashTableHeader *retn = NULL, *head = NULL, *target;
   int RaMapHash = 0;

   RaMapHash = RaMapCalcHash (obj, type, len);

   if ((target = table->array[RaMapHash % table->size]) != NULL) {
      head = target;
      do {
         if ((type == target->type) && (len == target->len)) {
            if (!(bcmp ((char *) obj, (char *) target->obj, len))) {
               retn = target;
               break;
            }
         }

         target = target->nxt;
      } while (target != head);
   }

#ifdef TCPCLEANDEBUG
   RaMapDebug (6, "RaMapFindHashEntry () returning 0x%x RaMapHash %d\n", retn, RaMapHash);
#endif
 
   return (retn);
}


struct RaMapHashTableHeader *
RaMapAddHashEntry (struct RaMapHashTableStruct *table, void *oid, int type, int len)
{
   struct RaMapHashTableHeader *retn = NULL, *start = NULL;

   if ((retn = (struct RaMapHashTableHeader *) ArgusCalloc (1, sizeof (struct RaMapHashTableHeader))) != NULL) {
      RaMapHash = RaMapCalcHash (oid, type, len);

      retn->hash = RaMapHash;
      retn->type = type;
      retn->len  = len;

      if ((retn->obj = (void *) ArgusCalloc (1, len)) == NULL)
         ArgusLog (LOG_ERR, "RaMapAddHashEntry: ArgusCalloc error %s\n", strerror(errno));
      else
         bcopy ((char *) oid, (char *)retn->obj, len);
      
      if ((start = table->array[RaMapHash % table->size]) != NULL) {
         retn->nxt = start;
         retn->prv = start->prv;
         retn->prv->nxt = retn;
         retn->nxt->prv = retn;
      } else
         retn->prv = retn->nxt = retn;

      table->array[RaMapHash % table->size] = retn;
   }

#ifdef TCPCLEANDEBUG
   RaMapDebug (3, "RaMapAddHashEntry (0x%x, %d, %d) returning 0x%x\n", oid, type, len, retn);
#endif

   return (retn);
}

 
void
RaMapRemoveHashEntry (struct RaMapHashTableStruct *table, struct RaMapHashTableHeader *htblhdr)
{
   unsigned short hash = htblhdr->hash;

   htblhdr->prv->nxt = htblhdr->nxt;
   htblhdr->nxt->prv = htblhdr->prv;

   if (htblhdr == table->array[hash % table->size]) {
      if (htblhdr == htblhdr->nxt)
         table->array[hash % table->size] = NULL;
      else
         table->array[hash % table->size] = htblhdr->nxt;
   }

   ArgusFree (htblhdr);

#ifdef TCPCLEANDEBUG
   RaMapDebug (6, "RaMapRemoveHashEntry (0x%x) returning\n", htblhdr);
#endif
}


#define RANON_RCITEMS				35

#define RANON_SEED				0
#define RANON_TRANSREFNUM_OFFSET 		1
#define RANON_SEQNUM_OFFSET 			2
#define RANON_TIME_SEC_OFFSET 			3
#define RANON_TIME_USEC_OFFSET 			4
#define RANON_ETHERNET_ANONYMIZATION		5
#define RANON_PRESERVE_ETHERNET_VENDOR		6
#define RANON_PRESERVE_ETHERNET_BROADCAST	7
#define RANON_PRESERVE_ETHERNET_MULTICAST	8
#define RANON_NET_ANONYMIZATION			9
#define RANON_HOST_ANONYMIZATION		10
#define RANON_NETWORK_ADDRESS_LENGTH		11
#define RANON_PRESERVE_NET_ADDRESS_HIERARCHY	12
#define RANON_PRESERVE_BROADCAST_ADDRESS	13
#define RANON_PRESERVE_MULTICAST_ADDRESS	14
#define RANON_PRESERVE_IP_ID			15
#define RANON_SPECIFY_NET_TRANSLATION		16
#define RANON_SPECIFY_HOST_TRANSLATION		17
#define RANON_PRESERVE_WELLKNOWN_PORT_NUMS	18
#define RANON_PRESERVE_REGISTERED_PORT_NUMS	19
#define RANON_PRESERVE_PRIVATE_PORT_NUMS	20
#define RANON_PRESERVE_PORT_NUMS		21
#define RANON_PRESERVE_PORT_NUM			22
#define RANON_CLASSA_NET_ADDRESS_LIST		23
#define RANON_CLASSB_NET_ADDRESS_LIST		24
#define RANON_CLASSC_NET_ADDRESS_LIST		25
#define RANON_CLASSM_NET_ADDRESS_LIST		26
#define RANON_MAP_DUMPFILE			27
#define RANON_PORT_METHOD			28
#define RANON_PRESERVE_ICMPMAPPED_TTL		29
#define RANON_PRESERVE_IP_TTL			30
#define RANON_PRESERVE_IP_TOS			31
#define RANON_PRESERVE_IP_OPTIONS		32
#define RANON_AS_ANONYMIZATION			33
#define RANON_SPECIFY_ASN_TRANSLATION		34


char *RaNonResourceFileStr [] = {
   "RANON_SEED=",
   "RANON_TRANSREFNUM_OFFSET=",
   "RANON_SEQNUM_OFFSET=",
   "RANON_TIME_SEC_OFFSET=",
   "RANON_TIME_USEC_OFFSET=",
   "RANON_ETHERNET_ANONYMIZATION=",
   "RANON_PRESERVE_ETHERNET_VENDOR=",
   "RANON_PRESERVE_ETHERNET_BROADCAST=",
   "RANON_PRESERVE_ETHERNET_MULTICAST=",
   "RANON_NET_ANONYMIZATION=",
   "RANON_HOST_ANONYMIZATION=",
   "RANON_NETWORK_ADDRESS_LENGTH=",
// "RANON_PRESERVE_ADDRESS=",
// "RANON_SPECIFY_ADDRESS=",
   "RANON_PRESERVE_NET_ADDRESS_HIERARCHY=",
   "RANON_PRESERVE_BROADCAST_ADDRESS=",
   "RANON_PRESERVE_MULTICAST_ADDRESS=",
   "RANON_PRESERVE_IP_ID=",
   "RANON_SPECIFY_NET_TRANSLATION=",
   "RANON_SPECIFY_HOST_TRANSLATION=",
   "RANON_PRESERVE_WELLKNOWN_PORT_NUMS=",
   "RANON_PRESERVE_REGISTERED_PORT_NUMS=",
   "RANON_PRESERVE_PRIVATE_PORT_NUMS=",
   "RANON_PRESERVE_PORT_NUMS=",
   "RANON_PRESERVE_PORT_NUM=",
   "RANON_CLASSA_NET_ADDRESS_LIST=",
   "RANON_CLASSB_NET_ADDRESS_LIST=",
   "RANON_CLASSC_NET_ADDRESS_LIST=",
   "RANON_CLASSM_NET_ADDRESS_LIST=",
   "RANON_MAP_DUMPFILE=",
   "RANON_PORT_METHOD=",
   "RANON_PRESERVE_ICMPMAPPED_TTL=",
   "RANON_PRESERVE_IP_TTL=",
   "RANON_PRESERVE_IP_TOS=",
   "RANON_PRESERVE_IP_OPTIONS=",
   "RANON_AS_ANONYMIZATION=",
   "RANON_SPECIFY_ASN_TRANSLATION=",
};

#include <ctype.h>

int
RaNonParseResourceFile (char *file)
{
   int retn = 0, i, len, found = 0, lines = 0;
   char strbuf[MAXSTRLEN], *str = strbuf, *optarg = NULL;
   FILE *fd;

   if (file) {
      if ((fd = fopen (file, "r")) != NULL) {
         retn = 1;
         while ((fgets(str, MAXSTRLEN, fd)) != NULL)  {
            lines++;
            while (*str && isspace((int)*str))
                str++;

            if (*str && (*str != '#') && (*str != '\n') && (*str != '!')) {
               found = 0;
               for (i = 0; i < RANON_RCITEMS; i++) {
                  len = strlen(RaNonResourceFileStr[i]);
                  if (!(strncmp (str, RaNonResourceFileStr[i], len))) {

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
                           case RANON_SEED:
                              RaNonSeed = strdup(optarg);
                              break;

                           case RANON_TRANSREFNUM_OFFSET:
                              RaNonTransRefNumOffset = strdup(optarg);
                              break;

                           case RANON_SEQNUM_OFFSET:
                              RaNonSeqNumOffset = strdup(optarg);
                              break;

                           case RANON_TIME_SEC_OFFSET:
                              RaNonTimeSecOffset = strdup(optarg);
                              break;

                           case RANON_TIME_USEC_OFFSET:
                              RaNonTimeuSecOffset = strdup(optarg);
                              break;

                           case RANON_ETHERNET_ANONYMIZATION:
                              break;

                           case RANON_NET_ANONYMIZATION:
                              break;

                           case RANON_HOST_ANONYMIZATION:
                              break;

                           case RANON_AS_ANONYMIZATION:
                              break;

                           case RANON_SPECIFY_ASN_TRANSLATION: {
                              char *ptr;

                              if ((ptr = strstr(optarg, "::")) == NULL)
                                 ArgusLog (LOG_ERR, "%s: syntax error line %d RANON_SPECIFY_ASN_TRANSLATION needs '::'\n",
                                                 file, lines);
                              *ptr = '\0';
                              ptr += 2;
                              break;
                           }

                           case RANON_PRESERVE_NET_ADDRESS_HIERARCHY:
                              RaNonPreserveNetAddrHierarchy = strdup(optarg); 
                              break;

                           case RANON_PRESERVE_BROADCAST_ADDRESS:
                              if (!(strncasecmp(optarg, "yes", 3)))
                                 RaPreserveBroadcastAddress++;
                              else
                                 RaPreserveBroadcastAddress = 0;
                              break;

                           case RANON_SPECIFY_NET_TRANSLATION: {
                              struct RaClassNets *thisNet = NULL;
                              struct RaMapHashTableHeader *mhdr = NULL;
                              struct in_addr oaddrbuf, *oaddr = &oaddrbuf;
                              struct in_addr naddrbuf, *naddr = &naddrbuf;
                              struct hostent *hp;
                              unsigned int **p;
                              char *ptr;

                              if ((ptr = strstr(optarg, "::")) == NULL)
                                 ArgusLog (LOG_ERR, "%s: syntax error line %d RANON_SPECIFY_NET_TRANSLATION needs '::'\n",
                                                 file, lines);
                              *ptr = '\0';
                              ptr += 2;

                              if ((hp = gethostbyname(optarg)) != NULL) {
                                 for (p = (unsigned int **)hp->h_addr_list; *p; ++p)
                                    **p = ntohl(**p);
                                 oaddr->s_addr = **(unsigned int **)hp->h_addr_list;
                              } else
                                 ArgusLog (LOG_ERR, "RaNonParseResourceFile: gethostbyname(%s) error %s",
                                                optarg, strerror(errno));

                              if ((hp = gethostbyname(ptr)) != NULL) {
                                 for (p = (unsigned int **)hp->h_addr_list; *p; ++p)
                                    **p = ntohl(**p);
                              } else
                                 ArgusLog (LOG_ERR, "RaNonParseResourceFile: gethostbyname(%s) error %s",
                                                ptr, strerror(errno));

                              naddr->s_addr = **(unsigned int **)hp->h_addr_list;

                              if ((mhdr = RaMapAddHashEntry (&RaMapNetTable, &oaddr->s_addr, RAMAP_IP_ADDR, 4))) {
                                 if ((thisNet = (void *) ArgusCalloc (1, sizeof(struct RaClassNets))) != NULL) {
                                    thisNet->net = oaddr->s_addr;
                                    thisNet->index = 1;
                                    mhdr->net = thisNet;

                                    if ((mhdr->sub = (void *) ArgusCalloc (1, sizeof(naddr->s_addr))) != NULL)
                                       bcopy ((char *)&naddr->s_addr, (char *) mhdr->sub, sizeof(naddr->s_addr));
                                    else
                                       ArgusLog (LOG_ERR, "RaMapNewNetwork: ArgusCalloc() error %s", strerror(errno));

                                 } else
                                    ArgusLog (LOG_ERR, "RaMapNewNetwork: ArgusCalloc() error %s", strerror(errno));
                              } else
                                 ArgusLog (LOG_ERR, "RaMapNewNetwork: RaMapAddHashEntry() error %s", strerror(errno));

                              break;
                           }

                           case RANON_SPECIFY_HOST_TRANSLATION: {
                              struct RaMapHashTableHeader *mhdr = NULL;
                              struct in_addr oaddrbuf, *oaddr = &oaddrbuf;
                              struct in_addr naddrbuf, *naddr = &naddrbuf;
                              struct hostent *hp;
                              unsigned int **p;
                              char *ptr;

                              if ((ptr = strstr(optarg, "::")) == NULL)
                                 ArgusLog (LOG_ERR, "%s: syntax error line %d RANON_SPECIFY_HOST_TRANSLATION needs '::'\n",
                                                 file, lines);

                              *ptr = '\0';
                              ptr += 2;

                              if ((hp = gethostbyname(optarg)) != NULL) {
                                 for (p = (unsigned int **)hp->h_addr_list; *p; ++p)
                                    **p = ntohl(**p);
                                 oaddr->s_addr = **(unsigned int **)hp->h_addr_list;
                              } else
                                 ArgusLog (LOG_ERR, "RaNonParseResourceFile: gethostbyname(%s) error %s",
                                                optarg, strerror(errno));

                              if ((hp = gethostbyname(ptr)) != NULL) {
                                 for (p = (unsigned int **)hp->h_addr_list; *p; ++p)
                                    **p = ntohl(**p);
                                 naddr->s_addr = **(unsigned int **)hp->h_addr_list;
                              } else
                                 ArgusLog (LOG_ERR, "RaNonParseResourceFile: gethostbyname(%s) error %s",
                                                ptr, strerror(errno));
#ifdef ARGUSDEBUG
                              ArgusDebug (1, "RaNonParseResourceFile: RANON_SPECIFY_HOST_TRANSLATION=%s::%s\n",
                                                optarg, ptr);
#endif
                              if (!(mhdr = RaMapFindHashObject (&RaMapHashTable, &oaddr->s_addr, RAMAP_IP_ADDR, 4))) {
                                 if ((mhdr = RaMapAddHashEntry (&RaMapHashTable, (void *)&oaddr->s_addr, RAMAP_IP_ADDR, 4))) {
                                    struct ArgusListObjectStruct *lobj = NULL;

                                    if ((mhdr->sub = (void *) ArgusCalloc (1, 4)) != NULL) {
                                       bcopy ((char *)&naddr->s_addr, (char *) mhdr->sub, 4);
                                    } else {
                                       ArgusLog (LOG_ERR, "RaNonParseResourceFile: ArgusCalloc error %s",
                                                      strerror(errno));
                                    }

                                    if (!(RaMapIPAddrList))
                                       RaMapIPAddrList = ArgusNewList();

                                    if ((lobj = ArgusCalloc(1, sizeof(*lobj))) == NULL)
                                       ArgusLog (LOG_ERR, "RaMapInventory: ArgusCalloc error %s\n", strerror(errno));
                        
                                    lobj->list_obj = mhdr;
                                    ArgusPushBackList(RaMapIPAddrList, (struct ArgusListRecord *)mhdr, ARGUS_LOCK);

                                 } else
                                    ArgusLog (LOG_ERR, "RaAllocateIPAddr () RaMapAddHashEntry error %s\n", strerror(errno));

                              } else
                                 ArgusLog (LOG_ERR, "RaNonParseResourceFile: line %d address %s already allocated\n",
                                                lines, optarg);
                              break;
                           }

                           case RANON_PRESERVE_WELLKNOWN_PORT_NUMS:
                              if (!(strncasecmp(optarg, "yes", 3)))
                                 RaPreserveWellKnownPorts++;
                              else
                                 RaPreserveWellKnownPorts = 0;
                              break;

                           case RANON_PRESERVE_REGISTERED_PORT_NUMS:
                              if (!(strncasecmp(optarg, "yes", 3)))
                                 RaPreserveRegisteredPorts++;
                              else
                                 RaPreserveRegisteredPorts = 0;
                              break;

                           case RANON_PRESERVE_PRIVATE_PORT_NUMS:
                              if (!(strncasecmp(optarg, "yes", 3)))
                                 RaPreservePrivatePorts++;
                              else
                                 RaPreservePrivatePorts = 0;
                              break;

                           case RANON_PORT_METHOD:
                              RaPortMappingOffset = strdup(optarg);
                              break;

                           case RANON_PRESERVE_PORT_NUMS:
                              break;

                           case RANON_PRESERVE_PORT_NUM:
                              break;

                           case RANON_PRESERVE_IP_ID:
                              if (!(strncasecmp(optarg, "yes", 3)))
                                 RaPreserveIpId++;
                              else
                                 RaPreserveIpId = 0;
                              break;

                           case RANON_CLASSA_NET_ADDRESS_LIST:
                              break;

                           case RANON_CLASSB_NET_ADDRESS_LIST:
                              break;

                           case RANON_CLASSC_NET_ADDRESS_LIST:
                              break;

                           case RANON_MAP_DUMPFILE:
                              break;

                           case RANON_PRESERVE_ETHERNET_VENDOR:
                              if (!(strncasecmp(optarg, "yes", 3)))
                                 RaPreserveEtherVendor++;
                              else
                                 RaPreserveEtherVendor = 0;
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
   ArgusDebug (1, "ArgusParseResourceFile (%s) returning %d\n", file, retn);
#endif

   return (retn);
}

void
ArgusAnonymizeTransport(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusTransportStruct *trans = (struct ArgusTransportStruct *) argus->dsrs[ARGUS_TRANSPORT_INDEX];

   if (trans != NULL) {
      RaMapInventory (&trans->srcid, RAMAP_IP_ADDR, 4);
      trans->seqnum += RaMapSequenceOffsetValue;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeTransport (0x%x, 0x%x)\n", parser, argus);
#endif
}

void
ArgusAnonymizeTime(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusTimeObject *time = (struct ArgusTimeObject *) argus->dsrs[ARGUS_TIME_INDEX];

   if (time != NULL) {
      if (time->src.start.tv_sec) {
         time->src.start.tv_sec  -=  RaMapTimeSecOffsetValue;
         time->src.start.tv_usec -= RaMapTimeuSecOffsetValue;

         if (time->src.start.tv_usec < 0) {
            time->src.start.tv_sec--;
            time->src.start.tv_usec += 1000000;
         }
      }
      if (time->dst.start.tv_sec) {
         time->dst.start.tv_sec  -=  RaMapTimeSecOffsetValue;
         time->dst.start.tv_usec -= RaMapTimeuSecOffsetValue;

         if (time->dst.start.tv_usec < 0) {
            time->dst.start.tv_sec--;
            time->dst.start.tv_usec += 1000000;
         }
      }
      if (time->src.end.tv_sec) {
         time->src.end.tv_sec  -=  RaMapTimeSecOffsetValue;
         time->src.end.tv_usec -= RaMapTimeuSecOffsetValue;

         if (time->src.end.tv_usec < 0) {
            time->src.end.tv_sec--;
            time->src.end.tv_usec += 1000000;
         }
      }
      if (time->dst.end.tv_sec) {
         time->dst.end.tv_sec  -=  RaMapTimeSecOffsetValue;
         time->dst.end.tv_usec -= RaMapTimeuSecOffsetValue;

         if (time->dst.end.tv_usec < 0) {
            time->dst.end.tv_sec--;
            time->dst.end.tv_usec += 1000000;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeTransport (0x%x, 0x%x)\n", parser, argus);
#endif
}

void
ArgusAnonymizeTimeAdjust(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeTimeAdjust (0x%x, 0x%x)\n", parser, argus);
#endif
}


void
ArgusAnonymizeFlow(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];

   if (flow == NULL)
      return;

   switch (flow->hdr.subtype & 0x3F) {
      case ARGUS_FLOW_LAYER_3_MATRIX:
      case ARGUS_FLOW_CLASSIC5TUPLE: {
         switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
            case ARGUS_TYPE_IPV4: {
               RaMapInventory (&flow->ip_flow.ip_src, RAMAP_IP_ADDR, 4);
               RaMapInventory (&flow->ip_flow.ip_dst, RAMAP_IP_ADDR, 4);
               switch (flow->ip_flow.ip_p) {
                  case IPPROTO_UDP:
                  case IPPROTO_TCP: {
                     flow->ip_flow.sport = RaPortMapping[flow->ip_flow.sport];
                     flow->ip_flow.dport = RaPortMapping[flow->ip_flow.dport];
                     break;
                  }
                  case IPPROTO_ESP: {
                     break;
                  }

                  default:
                     flow->ip_flow.ip_p = RaProtoMapping[flow->ip_flow.ip_p];
               }
               break;
            }

            case ARGUS_TYPE_IPV6: {
               switch (flow->ipv6_flow.ip_p) {
                  case IPPROTO_UDP:
                  case IPPROTO_TCP: {
                     flow->ipv6_flow.sport = RaPortMapping[flow->ipv6_flow.sport];
                     flow->ipv6_flow.dport = RaPortMapping[flow->ipv6_flow.dport];
                     break;
                  }
                  case IPPROTO_ESP: {
                     break;
                  }

                  default:
                     flow->ipv6_flow.ip_p = RaProtoMapping[flow->ipv6_flow.ip_p];
               }
               break;
            }

            case ARGUS_TYPE_ETHER: {
               RaMapInventory (&flow->mac_flow.mac_union.ether.ehdr.ether_shost, RAMAP_ETHER_MAC_ADDR, 6);
               RaMapInventory (&flow->mac_flow.mac_union.ether.ehdr.ether_dhost, RAMAP_ETHER_MAC_ADDR, 6);
               break;
            }
         }
         break;
      }

      case ARGUS_FLOW_ARP: {
         switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
            case ARGUS_TYPE_RARP: {
               struct ArgusRarpFlow *rarp = &flow->rarp_flow;

               if (flow->arp_flow.pln == 4)
                  RaMapInventory (&rarp->arp_tpa, RAMAP_IP_ADDR, 4);

               RaMapInventory (&rarp->shaddr, RAMAP_ETHER_MAC_ADDR, 6);
               RaMapInventory (&rarp->dhaddr, RAMAP_ETHER_MAC_ADDR, 6);
               break;
            }

            case ARGUS_TYPE_ARP: {
               struct ArgusArpFlow *arp = &flow->arp_flow;
               RaMapInventory (&arp->haddr, RAMAP_ETHER_MAC_ADDR, 6);

               if (flow->arp_flow.pln == 4) {
                  RaMapInventory (&arp->arp_spa, RAMAP_IP_ADDR, 4);
                  RaMapInventory (&arp->arp_tpa, RAMAP_IP_ADDR, 4);
               }
               break;
            }
         }
         break;
      }

      case ARGUS_FLOW_MPLS: {
         break;
      }

      case ARGUS_FLOW_VLAN: {
         break;
      }

      default:
         break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeFlow (0x%x, 0x%x)\n", parser, argus);
#endif
}

void
ArgusAnonymizeMetric(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeMetric (0x%x, 0x%x)\n", parser, argus);
#endif
}

void
ArgusAnonymizeAgr(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeAgr (0x%x, 0x%x)\n", parser, argus);
#endif
}

void
ArgusAnonymizeNetwork(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeNetwork (0x%x, 0x%x)\n", parser, argus);
#endif
}


void
ArgusAnonymizeASNumber(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusAsnStruct *asn = (void *)argus->dsrs[ARGUS_ASN_INDEX];

   if (asn != NULL) {
      RaMapInventory (&asn->src_as,   RAMAP_AS_NUMBER, 4);
      RaMapInventory (&asn->dst_as,   RAMAP_AS_NUMBER, 4);
      RaMapInventory (&asn->inode_as, RAMAP_AS_NUMBER, 4);

#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusAnonymizeASNumber (0x%x, 0x%x)\n", parser, argus);
#endif
   }
}

void
ArgusAnonymizeVlan(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeVlan (0x%x, 0x%x)\n", parser, argus);
#endif
}

void
ArgusAnonymizeMpls(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeMpls (0x%x, 0x%x)\n", parser, argus);
#endif
}

void
ArgusAnonymizeMac(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusMacStruct *mac = (struct ArgusMacStruct *) argus->dsrs[ARGUS_MAC_INDEX];

   RaMapInventory (&mac->mac.mac_union.ether.ehdr.ether_shost, RAMAP_ETHER_MAC_ADDR, 6);
   RaMapInventory (&mac->mac.mac_union.ether.ehdr.ether_dhost, RAMAP_ETHER_MAC_ADDR, 6);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeMac (0x%x, 0x%x)\n", parser, argus);
#endif
}

void
ArgusAnonymizeJitter(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeJitter (0x%x, 0x%x)\n", parser, argus);
#endif
}

void
ArgusAnonymizeIPattribute(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusIPAttrStruct *attr = (void *)argus->dsrs[ARGUS_IPATTR_INDEX];
   struct ArgusFlow *flow = (struct ArgusFlow *)argus->dsrs[ARGUS_FLOW_INDEX];

   if ((attr == NULL) || (flow == NULL))
      return;

   switch (attr->src.ttl) {
      case 0:
      case 255:
      case 254:
         break;
      default: {
         attr->src.ttl += RaMapInventoryToTTL (&flow->ip_flow.ip_src, RAMAP_IP_ADDR, 4);
         attr->src.ttl += RaMapInventoryToTTL (&flow->ip_flow.ip_src, RAMAP_IP_ADDR, 4);
         break;
      }
   }

   switch (attr->dst.ttl) {
      case 0:
      case 255:
      case 254: 
         break;
      default:
         attr->dst.ttl += RaMapInventoryToTTL (&flow->ip_flow.ip_src, RAMAP_IP_ADDR, 4);
         break;
   }

   attr->src.tos += RaTosMappingOffsetValue;
   attr->dst.tos += RaTosMappingOffsetValue;

   attr->src.options = 0;
   attr->dst.options = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeIPattribute (0x%x, 0x%x)\n", parser, argus);
#endif
}

void
ArgusAnonymizeSrcUserData(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeSrcUserData (0x%x, 0x%x)\n", parser, argus);
#endif
}

void
ArgusAnonymizeDstUserData(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeDstUserData (0x%x, 0x%x)\n", parser, argus);
#endif
}

/*
struct ArgusIcmpStruct {
   struct ArgusDSRHeader hdr;
   unsigned char icmp_type, icmp_code;
   unsigned short iseq;
   unsigned int osrcaddr, odstaddr;
   unsigned int isrcaddr, idstaddr;
   unsigned int igwaddr;
};
*/

void
ArgusAnonymizeIcmp(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusIcmpStruct *icmp = (void *) argus->dsrs[ARGUS_ICMP_INDEX];

   if (icmp != NULL) {
      RaMapInventory (&icmp->osrcaddr, RAMAP_IP_ADDR, 4);
      RaMapInventory (&icmp->odstaddr, RAMAP_IP_ADDR, 4);
      RaMapInventory (&icmp->isrcaddr, RAMAP_IP_ADDR, 4);
      RaMapInventory (&icmp->idstaddr, RAMAP_IP_ADDR, 4);
      RaMapInventory (&icmp->igwaddr,  RAMAP_IP_ADDR, 4);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeIcmp (0x%x, 0x%x)\n", parser, argus);
#endif
}

void
ArgusAnonymizeCorrelate(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeCorrelate (0x%x, 0x%x)\n", parser, argus);
#endif
}

void
ArgusAnonymizePacketSize(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizePacketSize (0x%x, 0x%x)\n", parser, argus);
#endif
}


void
ArgusAnonymizeEncaps(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeEncaps (0x%x, 0x%x)\n", parser, argus);
#endif
}


void
ArgusAnonymizeBehavior(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeBehavior (0x%x, 0x%x)\n", parser, argus);
#endif
}


void
ArgusAnonymizeLabel(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeLabel (0x%x, 0x%x)\n", parser, argus);
#endif
}


void
ArgusAnonymizeCountryCode(struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAnonymizeCountryCode (0x%x, 0x%x)\n", parser, argus);
#endif
}

