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
 * $Id: //depot/gargoyle/clients/include/argus_parser.h#41 $
 * $DateTime: 2016/11/30 12:38:04 $
 * $Change: 3249 $
 */


#ifndef ArgusParser_h
#define ArgusParser_h

#ifdef __cplusplus
extern "C" {
#endif

#if defined(ARGUS_PCRE)
#include "pcreposix.h"
#else
#include <regex.h>
#endif

#if defined(HAVE_DNS_SD_H)
#include <dns_sd.h>
#endif

#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>
#include <argus_events.h>

#include <net/nff.h>

#if defined(ARGUS_THREADS)
#include <pthread.h>
#endif

#define ARGUS_RECORD_WRITTEN	0x0001

#define ARGUS_READING_FILES 	0x1000
#define ARGUS_READING_STDIN 	0x2000
#define ARGUS_READING_REMOTE	0x4000

#define ARGUS_PRINTGMT		0x0020
#define ARGUS_PRINTNET		0x0040

#define RA_ENABLE_CIDR_ADDRESS_FORMAT	1
#define RA_STRICT_CIDR_ADDRESS_FORMAT	2
 
#define ARGUS_ENCODE_ASCII	0
#define ARGUS_ENCODE_64		1
#define ARGUS_ENCODE_32		2
#define ARGUS_HEXDUMP		3
#define ARGUS_ENCODE_OBFUSCATE	4       

#define ARGUS_MAX_S_OPTIONS      256

#define RA_PRINTPROTO		1
#define RA_PRINTSRCID		2
 
#define RAMON_TOPN		1
#define RAMON_MATRIX		2
#define RAMON_SVCS		3
#define RAMON_SINGLE		4

#define RA_FIXED_WIDTH		1
#define RA_VARIABLE_WIDTH	2

#define RA_SINGLE_QUOTED	'\''
#define RA_DOUBLE_QUOTED	'\"'

#define ARGUS_ITEM_QUOTED	0x40

#define ARGUS_MAX_REMOTE	256
#define ARGUS_MAX_REGEX		16384

#define RABINS_HASHTABLESIZE	0x100

#define RAMAXWILDCARDFIELDS     6

#define RAWILDCARDYEAR          0
#define RAWILDCARDMONTH         1
#define RAWILDCARDDAY           2
#define RAWILDCARDHOUR          3
#define RAWILDCARDMIN           4
#define RAWILDCARDSEC           5

#define ARGUS_ASN_ASPLAIN	0
#define ARGUS_ASN_ASDOTPLUS	1
#define ARGUS_ASN_ASDOT    	2

/* the ArgusRecordStruct (ns) is a single point data structure
   for clients to use to process and report on ARGUS flow data.  
   To support this rather nebulous function, the ns  provides
   a canonical record buffer which supports a completely
   parsed and formatted record (exploded view), and indexes
   to the various sections of the ns structure.

   A queue header struct is supported so that the strucutre
   can be placed in a queue, and there is an hstruct pointer
   provided so that if the record is hashed, the hash entry
   can be found quickly, ie for removal.

   Because ns data is time series data, there is a desire to
   support an array style data structure to provide the
   ability to  maintain some aspects fo the time-series
   qualities.  This struct was enabled in earlier versions
   using the 'H' (histogram) option.  In order to support the
   concept of the Stream Block Processor, however, this data
   structure needs to be embeeded in the ns itself.

   The concept is that the ns itself holds the aggregate
   stats for the time series array.  Each  member is an
   ns, which can further subdivided into additional time series
   structures.  For most applications, this structure will
   be NULL, indicating that subdivision is not being done.

*/

struct ArgusParserStruct;
typedef void (*ArgusEmptyHashCallback)(void *);
typedef void (*ArgusHashForEachCallback)(void *, void*);

 
struct ArgusHashStruct {
   unsigned int len, hash;
   unsigned int *buf; 
}; 
 
struct ArgusHashTableHdr {
   struct ArgusHashTableHdr *nxt, *prv;
   struct ArgusHashTable *htbl;
   struct ArgusHashStruct hstruct;
   void *object;
};

struct ArgusHashTable {
   unsigned int size, count;
#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
#endif /* ARGUS_THREADS */
   struct ArgusHashTableHdr **array;
};

struct ArgusAdjustStruct {
   int mode, turns, modify, hard, zero;
   int count, qual, slen, len;

   double stperiod, dtperiod, trperiod;
   double stduration, dtduration, trduration;

   double sploss, dploss;

   double spkts, sbytes, sappbytes;
   double scpkts, scbytes, scappbytes;
   double dpkts, dbytes, dappbytes;
   double dcpkts, dcbytes, dcappbytes;

   struct timeval start, end;
   struct tm RaStartTmStruct, RaEndTmStruct;

   double value;
   long long startuSecs, enduSecs, size;

   char *filename, *filterstr;
   struct nff_program filter;
};

struct RaBinStruct {
   int status;
#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
#endif
   long long value, size;
   struct timeval stime, etime, timeout;
   struct ArgusAggregatorStruct *agg;
   char *table, *file;

   unsigned char ArgusSrcDataMask[16],ArgusDstDataMask[16];
};

struct RaBinProcessStruct {
   int status;
#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
#endif
   long long start, end, size;
   struct timeval startpt, endpt, rtime;
   int arraylen, len, max, count, index;
   int scalesecs;
   struct RaBinStruct **array;
   struct ArgusAdjustStruct nadp;
};

struct ArgusCorStruct {
   int count, size;
   struct ArgusRecordStruct **array;
};

struct ArgusDisplayStruct {
   int type, status;
   char *str;
};

#define ARGUS_NSR_STICKY		0x01000000

#define ARGUS_RECORD_MODIFIED		0x0100
#define ARGUS_RECORD_NEW		0x0200
#define ARGUS_RECORD_PROCESSED		0x0400
#define ARGUS_RECORD_DISCARD		0x0800

#define ARGUS_RECORD_BASELINE		0x0010000 
#define ARGUS_RECORD_MATCH   		0x0020000 

struct ArgusRecordStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusDisplayStruct disp;
   struct ArgusAggregatorStruct *agg;
   unsigned int status, dsrindex, rank, autoid;
   unsigned short timeout, idle;
   struct timeval lastSrcStartTime, lastDstStartTime;
   struct RaBinProcessStruct *bins;
   struct ArgusHashTableHdr *htblhdr;
   struct ArgusHashTableHdr *hinthdr;
   struct ArgusQueueStruct *nsq;
   struct ArgusInput *input;
   struct RaBinStruct *bin;
   struct ArgusRecordHeader hdr;
   struct ArgusDSRHeader *dsrs[ARGUSMAXDSRTYPE];
   struct ArgusCorStruct *correlates;
   int sloss, dloss, score;
   float srate, drate, sload, dload, dur, mean;
   float pcr, sploss, dploss;
   long long offset;
};

struct ArgusRemoteStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusInput *input;

#if defined(ARGUS_THREADS)
   pthread_t tid;
   pthread_mutex_t lock;
#endif
};

struct ArgusCIDRAddr {
   u_char type, len, masklen, pad; 
   u_int addr[4], mask[4];
   char *str;
};

#define ARGUS_MAXTHREADS	128
#define ARGUS_MAXLISTEN		8
#define ARGUS_LISTEN_BACKLOG    32
#define ARGUS_MAXCLIENTS        32

#define ARGUS_REAL_TIME_PROCESS   	0x0100
#define ARGUS_FILE_LIST_PROCESSED	0x1000
#define ARGUS_BASELINE_LIST_PROCESSED	0x2000

#define ARGUS_LOCAL_TIME		0x01
#define ARGUS_FORCE_LOCAL_SRC		0x02
#define ARGUS_FORCE_LOCAL_DST		0x04
#define ARGUS_SUGGEST_LOCAL_SRC		0x08
#define ARGUS_SUGGEST_LOCAL_DST		0x10

#define ARGUS_PORT_SERVICES		0x100
#define ARGUS_PORT_WELLKNOWN		0x200
#define ARGUS_PORT_REGISTERED		0x400

#define ARGUS_ADDR_DIR_MASK (ARGUS_SUGGEST_LOCAL_SRC | ARGUS_SUGGEST_LOCAL_DST | ARGUS_FORCE_LOCAL_SRC | ARGUS_FORCE_LOCAL_DST)
#define ARGUS_PORT_DIR_MASK (ARGUS_PORT_SERVICES | ARGUS_PORT_WELLKNOWN | ARGUS_PORT_REGISTERED)

#define ARGUS_REPLACE_MODE_TRUE		0x01
#define ARGUS_REPLACE_COMPRESSED_GZ	0x02
#define ARGUS_REPLACE_COMPRESSED_BZ	0x04
#define ARGUS_REPLACE_FILENAME_MODIFIED	0x08

struct ArgusProgramStruct {
   int status;

   char *ArgusProgramName, *RaTimeFormat, *RaTimeZone;
   char *ArgusProgramArgs, *ArgusProgramOptions;
   char *ArgusSQLStatement, *MySQLDBEngine;
   char *ArgusSearchString;

   struct timeval ArgusRealTime, ArgusGlobalTime;
};

enum ArgusLockFilesEnum {
   ARGUS_FILE_NOLCK = 0,
   ARGUS_FILE_LCK,
   ARGUS_FILE_LCK_NONBLOCKING,
};

#define ARGUS_PRINT_NULL                0x01
#define ARGUS_PRINT_EMPTY_STRING        0x02
#define ARGUS_OMIT_EMPTY_STRING         0x04

struct ArgusParserStruct {
   int status;
   uid_t uid;
   pid_t pid;

   char RaParseCompleting, RaParseDone;
   char RaDonePending, RaShutDown, RaSortedInput;
   char RaTasksToDo, ArgusReliableConnection, ArgusPrintWarnings;
   char ArgusCorrelateEvents, ArgusPerformCorrection;
   char ArgusExitStatus, ArgusPassNum, ArgusLabelRecord;
   char ArgusLoadingData, ArgusFractionalDate;

   char *ArgusProgramName, *RaTimeFormat, *RaTimeZone;
   char *ArgusProgramArgs, *ArgusProgramOptions;
   char *ArgusSQLStatement, *MySQLDBEngine;
   char *ArgusAliasFile, *RadiumSrcidConvertFile;
   char *ArgusSourceIDString, *RaMarInfName;
   char *RaTempFilePath, *ArgusBaseLineFile;
   char *ArgusSearchString;

   struct timeval ArgusRealTime, ArgusGlobalTime;
   struct timeval ArgusStartRealTime, ArgusEndRealTime;
   struct timeval RaClientTimeout;		/* timeout interval */
   struct timeval RaClientTimeoutAbs;		/* when current timeout interval ends */
   struct timeval RaClientUpdate;
   struct timeval RaStartTime, RaEndTime;
   struct timeval ArgusStartTimeVal;
   struct timeval ArgusTimeDelta;
   struct timeval ArgusTimeOffset;

   int (*ArgusParseClientMessage)(struct ArgusParserStruct *, void *, void *, char *);
   int (*ArgusWriteClientMessage)(struct ArgusParserStruct *, void *, void *, char *);

   int ArgusDirectionFunction, ArgusZeroConf;

   double ArgusLastRecordTime;

   struct tm RaStartFilter, RaLastFilter;
   struct tm RaTmStruct;

   float RaFilterTimeout;

   struct ArgusAggregatorStruct *ArgusAggregator;
   struct ArgusAggregatorStruct *ArgusProbeAggregator;
   struct ArgusAggregatorStruct *ArgusPathAggregator;

   struct ArgusLabelerStruct *ArgusLocalLabeler;
   struct ArgusLabelerStruct *ArgusColorLabeler;
   struct ArgusLabelerStruct *ArgusLabeler;
   struct RaBinProcessStruct *RaBinProcess;
   struct ArgusEventsStruct *ArgusEventsTask;

#if defined(ARGUS_THREADS)
   pthread_t thread, remote, output, timer, dns, script;
   pthread_t listenthread;
   pthread_mutex_t lock, sync;
   pthread_cond_t cond;
#endif /* ARGUS_THREADS */

   pid_t ArgusSessionId;

   char ArgusTimeoutThread, NonBlockingDNS;
   char RaDNSNameCacheTimeout, ArgusDSCodePoints;
   char ArgusColorSupport, RaSeparateAddrPortWithPeriod;

   char *ArgusPidFile, *ArgusPidPath;
   char *ArgusColorConfig;

   struct ArgusRecordStruct *ns;

   struct ArgusOutputStruct *ArgusOutput;
   struct ArgusOutputStruct *ArgusControlChannel;

   /* ArgusOutputs[] is a parallel array with ArgusLfd*.  It maps
    * listening file descriptors to a particular output process.  Since
    * a single output thread can have multiple listening file
    * descriptors there may be valid duplicate entries in this array.
    */
   struct ArgusOutputStruct *ArgusOutputs[ARGUS_MAXLISTEN];

   struct ArgusListStruct *ArgusOutputList, *ArgusInputList;
   struct ArgusListStruct *ArgusNameList, *ArgusProcessList;

   struct ArgusQueueStruct *ArgusRemoteHosts, *ArgusActiveHosts;
   struct ArgusQueueStruct *ArgusRemoteList;

   regex_t upreg[ARGUS_MAX_REGEX];
   regex_t lpreg;
   regex_t sgpreg, dgpreg;

   int ArgusHashTableSize;
   int ArgusRegExItems;
   int ArgusListens;

   char ArgusRemotes;
   char ArgusReplaceMode;
   char ArgusHostsActive;
   int ArgusLfd[ARGUS_MAXLISTEN];        /* listen file descriptors */
   char ArgusLfdVersion[ARGUS_MAXLISTEN]; /* argus protocol version for this fd */
   char ArgusAdjustTime;
   char ArgusConnectTime;
   char ArgusReverse;
   char ArgusGenerateManRecords;
   char ArgusPrintMan, ArgusPrintEvent;
   char ArgusPrintXml, ArgusAsnFormat;
   char ArgusPrintJson, ArgusPrintNewick;
   char ArgusPrintJsonEmptyString;
   char ArgusPrintD3;
   char ArgusSrvInit;
   char RaOutputStarted; 
   char ArgusGrepSource;
   char ArgusGrepDestination;
   char ArgusAutoId;
   char ArgusPrintPortZero;
   char ArgusPrintHashZero;
   char ArgusEtherFrameCnt;

   char ArgusStripFields;
   char ArgusDSRFields[ARGUSMAXDSRTYPE];

   char *RadiumArchive;
   char *ArgusMatchLabel;
   char *ArgusMatchGroup;

   unsigned int ArgusIDType;
   struct ArgusTransportStruct trans;

   struct timeval ArgusReportTime;
   struct timeval ArgusUpdateInterval;
   struct timeval ArgusMarReportInterval;
   struct timeval timeout;

   struct timeval ArgusThisTime;
   struct timeval ArgusLastTime;
   struct timeval ArgusCurrentTime;
   struct timeval ArgusLastRealTime;

   long long ArgusTotalRecords;
   long long ArgusTotalMarRecords;
   long long ArgusTotalEventRecords;
   long long ArgusTotalFarRecords;
   long long ArgusTotalPkts, ArgusTotalSrcPkts, ArgusTotalDstPkts;
   long long ArgusTotalBytes, ArgusTotalSrcBytes, ArgusTotalDstBytes;

   char debugflag, RaInitialized;
   char RaFieldDelimiter, RaFieldQuoted; 

   char aflag, Aflag, bflag, cidrflag;
   char cflag, Cflag, dflag, Dflag, eflag, Eflag;
   char fflag, Fflag, gflag, Gflag, Hflag;
   signed char idflag, jflag, Jflag, lflag, iLflag, Lflag, mflag, hflag;
   char notNetflag, Oflag, Pflag, qflag, Qflag;
   char Netflag, nflag, nlflag, Normflag, Pctflag, pidflag;

   char tflag, uflag, Wflag, vflag, Vflag, iflag;
   char Iflag, rflag, Rflag, Sflag, sflag, Tflag, xflag;
   char Xflag, yflag, zflag, Zflag, domainonly;
   char Uflag, noflag, labelflag;
   char ver3flag;

   char *estr, *Mflag;
   double Bflag;

   signed int RaFieldWidth, RaWriteOut;
   signed int pflag, sNflag, eNflag, sNoflag, eNoflag;

   struct timeval startime_t, lasttime_t;

   float Pauseflag;
   float ProcessRealTime;

   char RaLabelStr[0x10000], *RaLabel;
   char RaDBString[0x10000], *RaDBStr;
   int ArgusRandomSeed;
   int RaLabelCounter;

   int RaPrintOptionIndex;
   char *RaPrintOptionStrings[ARGUS_MAX_S_OPTIONS];

   int RaSortOptionIndex;
   char *RaSortOptionStrings[ARGUS_MAX_S_OPTIONS];

   int ArgusFilterFiledes[2];
   int ArgusControlFiledes[2];

   char RaCumulativeMerge;
   char RaAllocHashTableHeaders;
   char RaAllocArgusRecord;
   char RaThisActiveIndex;
   char RaThisFlowNum;
   char RaThisModelNum;
   char RaParseError;
   char ArgusMinuteUpdate;
   char ArgusHourlyUpdate;

   char RaMpcProbeMode;
   char RaMpcNetMode;
   char RaCorrelate;
   char RaPollMode;
   char RaAgMode;
   char RaMonMode;
   char RaUniMode;
   char RaPruneMode;
   char RaPrintMode;
   char RaCursesMode;
   char RaWildCardDate;
   char RaDebugStatus;

   char ArgusNormalize;
   char ArgusPrintEthernetVendors;

   int RaPolicyStatus;

   unsigned short ArgusSourcePort, ArgusPortNum;
   unsigned short ArgusControlPort, ArgusV3Port;

   int RaCloseInputFd;
   int RaPrintIndex;

   char *RaFlowModelFile, *exceptfile;
   char *writeDbstr, *readDbstr;
   char *dbuserstr, *dbpassstr, *dbportstr, *dbhoststr;
   char *ais, *aistrategy, *ustr, *pstr; 
   char *timearg, *wfile;

   char *ArgusFlowModelFile;
   char *ArgusAggregatorFile;
   char *ArgusDelegatedIPFile;
   char *ArgusLocalFilter;
   char *ArgusRemoteFilter;
   char *ArgusDisplayFilter;

   char *ArgusGeneratorConfig;

   char *ArgusBindAddr;
   char *ArgusEthernetVendorFile;

   struct nff_program ArgusFilterCode;
   struct nff_program ArgusDisplayCode;

   struct RaFlowModelStruct *RaFlowModel;

   struct ArgusCIDRAddr ArgusCIDRBuffer, *ArgusCIDRPtr;

   struct ArgusModeStruct *ArgusModeList;
   struct ArgusModeStruct *ArgusMaskList;

   char *ArgusBaseLineMask;
   char *ArgusSampleMask;

   size_t ArgusInputFileCount;
   struct ArgusFileInput *ArgusInputFileList;	        /* first element in file list */
   struct ArgusFileInput *ArgusInputFileListTail;	/* last element in file list */

   size_t ArgusBaselineCount;
   struct ArgusFileInput *ArgusBaselineList;	/* first element in file list */
   struct ArgusFileInput *ArgusBaselineListTail;	/* last element in file list */

   struct ArgusInput *ArgusRemoteServerList;
   struct ArgusInput *ArgusCurrentFile;

   struct ArgusOutput *ArgusRemoteClientList;

   struct ArgusListStruct *ArgusLabelerFileList;
   struct ArgusListStruct *ArgusWfileList;

   struct ArgusInput *ArgusCurrentInput;

   struct ArgusPrintFieldStruct *RaPrintAlgorithm;
   struct ArgusPrintFieldStruct *RaPrintAlgorithmList[ARGUS_MAX_PRINT_ALG];

#if defined(HAVE_DNS_SD_H)
   DNSServiceRef dnsSrvRef;
#endif

   char ArgusLockWriteFiles;	/* enforce exclusive access to output files */
   char RaDebugString[MAXSTRLEN];

   struct ArgusRecordStruct argus;
   struct ArgusCanonRecord canon;
   struct ArgusRecord ArgusInitCon;

   char ArgusSrcUserData[0x10000];
   char ArgusDstUserData[0x10000];

   char ArgusSrcActDist[256];
   char ArgusSrcIdleDist[256];
   char ArgusDstActDist[256];
   char ArgusDstIdleDist[256];
};


#ifdef ArgusParse
struct ArgusParserStruct *ArgusNewParser(char *);
struct ArgusParserStruct *ArgusCopyParser(struct ArgusParserStruct *);
void ArgusCloseParser(struct ArgusParserStruct *);

#else
extern struct ArgusParserStruct *ArgusNewParser(char *);
extern struct ArgusParserStruct *ArgusCopyParser(struct ArgusParserStruct *);
extern void ArgusCloseParser(struct ArgusParserStruct *);
#endif

#ifdef __cplusplus
}
#endif
#endif
