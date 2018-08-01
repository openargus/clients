/*
 * Argus Software
 * Copyright (c) 2000-2022 QoSient, LLC
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

#define ARGUS_LABEL_LEGACY	0
#define ARGUS_LABEL_JSON	1


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

struct ArgusRecordStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusDisplayStruct disp;
   struct ArgusAggregatorStruct *agg;
   unsigned int status, dsrindex, rank, autoid;
   unsigned short timeout, idle;
   struct RaBinProcessStruct *bins;
   struct ArgusHashTableHdr *htblhdr;
   struct ArgusHashTableHdr *hinthdr;
   struct ArgusQueueStruct *nsq;
   struct ArgusInput *input;
   struct RaBinStruct *bin;
   struct ArgusRecordHeader hdr;
   struct ArgusDSRHeader *dsrs[ARGUSMAXDSRTYPE];
   struct ArgusCorStruct *correlates;
   int score;
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
   char ArgusExitStatus, ArgusPassNum;
   char ArgusLoadingData, ArgusFractionalDate;

   char *ArgusProgramName, *RaTimeFormat, *RaTimeZone;
   char *ArgusProgramArgs, *ArgusProgramOptions;
   char *ArgusSQLStatement, *MySQLDBEngine;
   char *ArgusSourceIDString, *RaMarInfName;
   char *RaTempFilePath, *ArgusBaseLineFile;
   char *ArgusSearchString;

   struct timeval ArgusRealTime, ArgusGlobalTime;
   struct timeval ArgusStartRealTime, ArgusEndRealTime;
   struct timeval RaClientTimeout, RaClientUpdate;
   struct timeval RaStartTime, RaEndTime;
   struct timeval ArgusStartTimeVal;
   struct timeval ArgusTimeDelta;
   struct timeval ArgusTimeOffset;

   int ArgusDirectionFunction, ArgusZeroConf;

   double ArgusLastRecordTime;

   struct tm RaStartFilter, RaLastFilter;
   struct tm RaTmStruct;

   float RaFilterTimeout;

   struct ArgusAggregatorStruct *ArgusAggregator;
   struct ArgusAggregatorStruct *ArgusPathAggregator;
   struct ArgusLabelerStruct *ArgusLocalLabeler;
   struct ArgusLabelerStruct *ArgusColorLabeler;
   struct ArgusLabelerStruct *ArgusLabeler;
   struct RaBinProcessStruct *RaBinProcess;

#if defined(ARGUS_THREADS)
   pthread_t thread, remote, output, timer, dns;
   pthread_t listenthread;
   pthread_mutex_t lock;
   pthread_cond_t cond;
#endif /* ARGUS_THREADS */

   void *ArgusClientContext;

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
   regex_t dpreg;

   int ArgusRegExItems;
   int ArgusListens;
   int ArgusAdjustTime;
   int ArgusConnectTime;
   int ArgusReverse;
   int ArgusGenerateManRecords;
   int ArgusPrintMan, ArgusPrintEvent;
   int ArgusPrintXml, ArgusAsnFormat;
   int ArgusPrintJson, ArgusPrintD3;
   int ArgusPrintJsonEmptyString;
   int ArgusLabelFormat;
   int RaXMLStarted; 
   int ArgusSrvInit;
   int ArgusGrepSource;
   int ArgusGrepDestination;
   int ArgusAutoId;

   int ArgusStripFields;
   int ArgusDSRFields[ARGUSMAXDSRTYPE];

   char *RadiumArchive;
   char *ArgusMatchLabel;

   unsigned int ArgusID, ArgusIDType;
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

   signed char RaOutputStarted;
   signed char aflag, Aflag, bflag, cidrflag;
   signed char cflag, Cflag, dflag, Dflag, eflag, Eflag;
   signed char fflag, Fflag, gflag, Gflag, Hflag;
   signed char idflag, jflag, Jflag, lflag, Lflag, mflag, hflag;
   signed char notNetflag, Oflag, pflag, Pflag, qflag, Qflag;
   signed char Netflag, nflag, Normflag, Pctflag, pidflag;

   char tflag, uflag, Wflag, vflag, Vflag, iflag;
   char Iflag, rflag, Rflag, Sflag, sflag, Tflag, xflag;
   char Xflag, yflag, zflag, Zflag, domainonly;
   char Uflag, noflag;
   char ver3flag;

   char *estr, *Hstr, *Mflag;
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
   char RaFlowMajorModified;
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
   char RaZeroMode;
   char RaPruneMode;
   char RaPrintMode;
   char RaCursesMode;
   char RaWildCardDate;
   char RaDebugStatus;

   char ArgusPrintEthernetVendors;

   int RaPolicyStatus;

   int RaHistoMetricSeries;
   int RaHistoMetricLog;
   int RaHistoRangeState;

   double RaHistoLogInterval;
   double RaHistoBinSize;
   double RaHistoStart, RaHistoStartLog;
   double RaHistoEnd, RaHistoEndLog;
   struct ArgusRecordStruct **RaHistoRecords;

   unsigned short ArgusSourcePort, ArgusPortNum;
   unsigned short ArgusControlPort, ArgusV3Port;

   int RaHistoBins, RaCloseInputFd;
   int RaPrintIndex;

   char *RaFlowModelFile, *exceptfile;
   char *writeDbstr, *readDbstr;
   char *dbuserstr, *dbpassstr, *dbportstr, *dbhoststr;
   char *ais, *ustr, *pstr; 
   char *timearg, *wfile;

   char *ArgusFlowModelFile;
   char *ArgusAggregatorFile;
   char *ArgusDelegatedIPFile;
   char *ArgusLocalFilter;
   char *ArgusRemoteFilter;
   char *ArgusDisplayFilter;

   char *ArgusBindAddr;
   char *ArgusEthernetVendorFile;

   struct nff_program ArgusFilterCode;
   struct nff_program ArgusDisplayCode;

   struct RaFlowModelStruct *RaFlowModel;

   struct ArgusCIDRAddr ArgusCIDRBuffer, *ArgusCIDRPtr;

   struct ArgusModeStruct *ArgusModeList;
   struct ArgusModeStruct *ArgusMaskList;

   size_t ArgusInputFileCount;
   struct ArgusFileInput *ArgusInputFileList;	/* first element in file list */
   struct ArgusFileInput *ArgusInputFileListTail;	/* last element in file list */
   struct ArgusInput *ArgusRemoteHostList;

   struct ArgusListStruct *ArgusLabelerFileList;
   struct ArgusListStruct *ArgusWfileList;

   struct ArgusInput *ArgusCurrentInput;

   struct ArgusPrintFieldStruct *RaPrintAlgorithm;
   struct ArgusPrintFieldStruct *RaPrintAlgorithmList[ARGUS_MAX_PRINT_ALG];

#if defined(HAVE_DNS_SD_H)
   DNSServiceRef dnsSrvRef;
#endif

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
