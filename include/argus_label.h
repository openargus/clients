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
 * $Id: //depot/gargoyle/clients/include/argus_label.h#32 $
 * $DateTime: 2016/06/01 10:28:03 $
 * $Change: 3143 $
 */

#ifndef ArgusLabeler_h
#define ArgusLabeler_h

#ifdef __cplusplus
extern "C" {
#endif

#if defined(ARGUS_GEOIP)
#include <GeoIP.h>
#endif

#if defined(ARGUS_GEOIP2)
#include <maxminddb.h>
#endif

#define ARGUS_LABELER_DEBUG	    0x0100
#define ARGUS_LABELER_DEBUG_LOCAL   0x0200
#define ARGUS_LABELER_DEBUG_NODE    0x0400
#define ARGUS_LABELER_DEBUG_GROUP   0x0800
#define ARGUS_LABELER_DUMP          0x1000

#define ARGUS_TREE_DEBUG	    0x0100
#define ARGUS_TREE_DEBUG_LOCAL      0x0200
#define ARGUS_TREE_DEBUG_NODE       0x0400
#define ARGUS_TREE_DEBUG_GROUP      0x0800

#define ARGUS_LABELER_COCODE	    0x01
#define ARGUS_LABELER_ADDRESS	    0x02
#define ARGUS_LABELER_NAMES	    0x04

#define ARGUS_TREE                  0x01
#define ARGUS_TREE_VISITED          0x02
#define ARGUS_TREE_POPULATED        0x04
#define ARGUS_NODE                  0x08
#define ARGUS_VISITED               0x10

#define ARGUS_NEWICK                0x20
#define ARGUS_GRAPH                 0x30
#define ARGUS_JSON                  0x40
#define ARGUS_LABEL                 0x50

#define ARGUS_UNION		    0x01
#define ARGUS_INTERSECT		    0x02
#define ARGUS_REPLACE		    0x03

#define ARGUS_TREE_PRUNE_LABEL      0x00
#define ARGUS_TREE_PRUNE_CCO        0x01
#define ARGUS_TREE_PRUNE_LOCALITY   0x02
#define ARGUS_TREE_PRUNE_RECORD     0x04
#define ARGUS_TREE_PRUNE_NAMES      0x08
#define ARGUS_TREE_PRUNE_ASN        0x10
#define ARGUS_TREE_PRUNE_GROUP      0x20

#define ARGUS_TREE_PRUNE_ADJ        0x100
#define ARGUS_TREE_PRUNE_ANY        0x200

#define ARGUS_TREE_DNS_TLD          0x400
#define ARGUS_TREE_DNS_SLD          0x800

#define ARGUS_PRUNE_TREE            0x1000

struct ArgusGeoIPCityObject {
   char *field, *format;
   int length, index, offset, value;
};
 
struct ArgusLabelerStruct {
   int status;

   struct ArgusQueueStruct *queue;
   struct ArgusHashTable *htable;
 
   struct RaAddressStruct **ArgusAddrTree;
   struct RaAddressStruct **ArgusRIRTree;
   struct RaNameStruct **ArgusNameTree;

   struct RaPolicyStruct *drap, *rap;
   struct RaFlowModelStruct *fmodel;

   int mask, inserts, prune, count;
   int RaPrintLabelTreeMode;

   char RaLabelIanaAddress;
   char RaLabelIeeeAddress;
   char RaLabelCountryCode;
   char RaLabelBindName;
   char RaLabelIanaPort;
   char RaLabelArgusFlow;
   char RaLabelArgusFlowService;
   char RaLabelLocality;
   char RaLabelLocalityOverwrite;
   char RaLabelLocalityInterfaceIsMe;

#if defined(ARGUS_GEOIP2)
   int RaLabelGeoIPAsn;
   MMDB_s RaGeoIPAsnObject;
   int RaLabelGeoIPAsnLabels[16];
   int RaLabelGeoIPCity;
   MMDB_s RaGeoIPCityObject;
   int RaLabelGeoIPCityLabels[16];
#elif defined(ARGUS_GEOIP)
   int RaLabelGeoIPAsn;
   GeoIP *RaGeoIPv4AsnObject;
   GeoIP *RaGeoIPv6AsnObject;
   int RaLabelGeoIPAsnLabels[16];

   int RaLabelGeoIPCity;
   GeoIP *RaGeoIPv4CityObject;
   GeoIP *RaGeoIPv6CityObject;
   int RaLabelGeoIPCityLabels[16];
#endif

   struct RaPortStruct **ArgusTCPPortLabels;
   struct RaPortStruct **ArgusUDPPortLabels;
   struct ArgusQueueStruct *ArgusFlowQueue;
};

#define ARGUS_EXACT_MATCH       0x00
#define ARGUS_LONGEST_MATCH     0x01
#define ARGUS_ANY_MATCH         0x02
#define ARGUS_NODE_MATCH        0x04
#define ARGUS_MASK_MATCH        0x08
#define ARGUS_SUPER_MATCH       0x10

#define ARGUS_LABEL_RECORD      0x20

struct RaNameStruct {
   struct ArgusQueueHeader qhdr;
   struct RaNameStruct *l, *r, *p, *tld;
   struct ArgusRecordStruct *ns;

   struct ArgusCIDRAddr addr;

   int type, status, offset, count;
   struct timeval atime, rtime;
   char *str, *label, *asnlabel;

   void *obj;
};

struct RaAddressStruct {
   struct ArgusQueueHeader qhdr;
   struct RaAddressStruct *l, *r, *p;
   struct ArgusRecordStruct *ns;
   struct ArgusLabelerStruct *labeler;

   struct ArgusCIDRAddr addr;

   int type, status, offset, count, ttl;
   struct timeval atime, rtime;
   char *str, *label, *asnlabel, *group;

   struct ArgusListStruct *dns;
   void *obj;

   float lat, lon, x, y, z;
   int locality;
   uint32_t asn;
   char cco[4];
};


struct RaPortStruct {
   struct ArgusQueueHeader qhdr;
   unsigned short proto, start, end;
   int offset, count, status;
   char *label, *desc;
};


struct RaFlowLabelStruct {
   struct ArgusQueueHeader qhdr;
   int status, cont;
   char *filterstr, *labelstr, *grepstr, *colorstr;
   struct nff_program filter;
};


#if defined(ArgusLabel)

/*
struct ArgusGeoIPCityObject {
   char *field, *format;
   int length, index, offset, value;
}
*/

int RaLabelParseResourceFile (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
int RaLabelParseResourceBuffer (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char **);
int RaLabelParseResourceStr (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

struct ArgusLabelerStruct *ArgusNewLabeler (struct ArgusParserStruct *, int);
void ArgusDeleteLabeler (struct ArgusParserStruct *, struct ArgusLabelerStruct *);

extern struct ArgusLabelerStruct *ArgusLabeler;
int ArgusAddToRecordLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);

struct ArgusRecordStruct *ArgusLabelRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void ArgusGetInterfaceAddresses(struct ArgusParserStruct *);
void RaPrintLabelTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

struct RaAddressStruct *RaFindAddress (struct ArgusParserStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);
struct RaAddressStruct *RaInsertAddress (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);

int RaInsertAddressTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *, char *);
int RaInsertLocalityTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *);

char *RaPruneAddressTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

void RaLabelMaskAddressStatus(struct RaAddressStruct *, unsigned int);

int RaReadAddressConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
int RaReadLocalityConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
int RaReadPortConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
int RaReadFlowLabels (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

void RaMapLabelMol (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int, int, int);
void RaPrintLabelMol (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int, int, int);
void RaPrintLabelTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

int RaCountryCodeLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaAddressLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaLocalityLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaServiceLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaLabelIANAAddressType (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaFetchIPv4AddressLabel(struct ArgusParserStruct *, unsigned int *);
char *RaPortLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *, int);
char *RaFlowLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *, int);
char *RaFlowColor (struct ArgusParserStruct *, struct ArgusRecordStruct *);
char *RaFetchIPPortLabel(struct ArgusParserStruct *, unsigned short, unsigned short);

char *ArgusUpgradeLabel(char *, char *, int);

#else

#define ARGUS_GEOIP_COUNTRY_CODE        1
#define ARGUS_GEOIP_COUNTRY_CODE_3      2
#define ARGUS_GEOIP_COUNTRY_NAME        3
#define ARGUS_GEOIP_REGION              4
#define ARGUS_GEOIP_CITY_NAME           5
#define ARGUS_GEOIP_POSTAL_CODE         6
#define ARGUS_GEOIP_LATITUDE            7
#define ARGUS_GEOIP_LONGITUDE           8
#define ARGUS_GEOIP_METRO_CODE          9
#define ARGUS_GEOIP_AREA_CODE           10
#define ARGUS_GEOIP_CHARACTER_SET       11
#define ARGUS_GEOIP_CONTINENT_CODE      12
#define ARGUS_GEOIP_NETMASK             13

extern int RaLabelParseResourceFile (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
extern int RaLabelParseResourceBuffer (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char **);
extern int RaLabelParseResourceStr (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

extern struct ArgusLabelerStruct *ArgusNewLabeler (struct ArgusParserStruct *, int);
extern void ArgusDeleteLabeler (struct ArgusParserStruct *, struct ArgusLabelerStruct *);
extern struct ArgusLabelerStruct *ArgusLabeler;
extern void RaPrintLabelTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

extern void ArgusGetInterfaceAddresses(struct ArgusParserStruct *);

extern struct ArgusRecordStruct *ArgusLabelRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern int ArgusAddToRecordLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *);

extern struct RaAddressStruct *RaFindAddress (struct ArgusParserStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);
extern struct RaAddressStruct *RaInsertAddress (struct ArgusParserStruct *, struct ArgusLabelerStruct *, struct RaAddressStruct *, struct RaAddressStruct *, int);

extern int RaInsertAddressTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *, char *);
extern int RaInsertLocalityTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *labeler, char *);

extern char *RaPruneAddressTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

extern void RaLabelMaskAddressStatus(struct RaAddressStruct *, unsigned int);

extern int RaReadAddressConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
extern int RaReadLocalityConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
extern int RaReadPortConfig (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);
extern int RaReadFlowLabels (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);

extern void RaMapLabelMol (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int, int, int);
extern void RaPrintLabelMol (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int, int, int);
extern void RaPrintLabelTree (struct ArgusLabelerStruct *, struct RaAddressStruct *, int, int);

extern int RaCountryCodeLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaAddressLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaLocalityLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaServiceLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaLabelIANAAddressType (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaFetchIPv4AddressLabel(struct ArgusParserStruct *, unsigned int *);
extern char *RaPortLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *, int);
extern char *RaFlowLabel (struct ArgusParserStruct *, struct ArgusRecordStruct *, char *, int);
extern char *RaFlowColor (struct ArgusParserStruct *, struct ArgusRecordStruct *);
extern char *RaFetchIPPortLabel(struct ArgusParserStruct *, unsigned short, unsigned short);
extern char *ArgusUpgradeLabel(char *, char *, int);

#endif
#ifdef __cplusplus
}
#endif
#endif

