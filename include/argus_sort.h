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
 * $Id: //depot/gargoyle/clients/include/argus_sort.h#9 $
 * $DateTime: 2016/10/10 23:14:45 $
 * $Change: 3219 $
 */

#ifndef ArgusSort_h
#define ArgusSort_h

#ifdef __cplusplus
extern "C" {
#endif

#define ARGUS_MAX_SORT_ALG		79
#define MAX_SORT_ALG_TYPES		79

struct ArgusSortRecord {
   struct ArgusQueueHeader qhdr;
   struct ArgusRecordStruct *record;
};

struct ArgusSorterStruct {
   int ArgusSortOptionIndex, ArgusReplaceMode;
   struct ArgusQueueStruct *ArgusRecordQueue;
   int (*ArgusSortAlgorithms[ARGUS_MAX_SORT_ALG])(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
   int (*ArgusSortAlgorithm)(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
   double (*ArgusFetchAlgorithms[ARGUS_MAX_SORT_ALG])(struct ArgusRecordStruct *);
   int  ArgusFetchAlgNumber;
   char *ArgusSOptionStrings[ARGUS_MAX_S_OPTIONS];
   struct nff_program filter;
   char ArgusSrcAddrCIDR, ArgusDstAddrCIDR;
};

#define ARGUSSORTSTARTTIME		1
#define ARGUSSORTLASTTIME		2
#define ARGUSSORTTRANSACTIONS		3
#define ARGUSSORTDURATION		4
#define ARGUSSORTAVGDURATION		5
#define ARGUSSORTMINDURATION		6
#define ARGUSSORTMAXDURATION		7
#define ARGUSSORTSRCMAC			8
#define ARGUSSORTDSTMAC			9
#define ARGUSSORTSRCADDR		10

#define ARGUSSORTDSTADDR		11
#define ARGUSSORTPROTOCOL		12
#define ARGUSSORTSRCIPID		13
#define ARGUSSORTDSTIPID		14
#define ARGUSSORTSRCPORT		15
#define ARGUSSORTDSTPORT		16
#define ARGUSSORTSRCTOS			17
#define ARGUSSORTDSTTOS			18
#define ARGUSSORTSRCTTL			19
#define ARGUSSORTDSTTTL			20

#define ARGUSSORTBYTECOUNT		21
#define ARGUSSORTSRCBYTECOUNT		22
#define ARGUSSORTDSTBYTECOUNT		23
#define ARGUSSORTPKTSCOUNT		24
#define ARGUSSORTSRCPKTSCOUNT		25
#define ARGUSSORTDSTPKTSCOUNT		26
#define ARGUSSORTAPPBYTECOUNT		27
#define ARGUSSORTSRCAPPBYTECOUNT	28
#define ARGUSSORTDSTAPPBYTECOUNT	29
#define ARGUSSORTLOAD			30

#define ARGUSSORTSRCLOAD		31
#define ARGUSSORTDSTLOAD		32
#define ARGUSSORTLOSS			33
#define ARGUSSORTPERCETLOSS		34
#define ARGUSSORTRATE			35
#define ARGUSSORTSRCRATE		36
#define ARGUSSORTDSTRATE		37
#define ARGUSSORTTRANREF		38
#define ARGUSSORTSEQ			39
#define ARGUSSORTSRCMPLS		40

#define ARGUSSORTDSTMPLS		41
#define ARGUSSORTSRCVLAN		42
#define ARGUSSORTDSTVLAN		43
#define ARGUSSORTSRCID			44
#define ARGUSSORTSRCTCPBASE		45
#define ARGUSSORTDSTTCPBASE		46
#define ARGUSSORTTCPRTT			47
#define ARGUSSORTSRCLOSS		48
#define ARGUSSORTDSTLOSS		49
#define ARGUSSORTPERCENTSRCLOSS		50

#define ARGUSSORTPERCENTDSTLOSS		51
#define ARGUSSORTSRCMAXPKTSIZE		52
#define ARGUSSORTSRCMINPKTSIZE		53
#define ARGUSSORTDSTMAXPKTSIZE		54
#define ARGUSSORTDSTMINPKTSIZE		55
#define ARGUSSORTSRCDSBYTE    		56
#define ARGUSSORTDSTDSBYTE    		57
#define ARGUSSORTSRCCOCODE 		58
#define ARGUSSORTDSTCOCODE    		59
#define ARGUSSORTSRCAS	 		60

#define ARGUSSORTDSTAS    		61
#define ARGUSSORTSUM    		62
#define ARGUSSORTRUNTIME    		63
#define ARGUSSORTIDLETIME   		64
#define ARGUSSORTSRCOUI        		65
#define ARGUSSORTDSTOUI        		66
#define ARGUSSORTAPPBYTERATIO        	67
#define ARGUSSORTPRODCONSUMERRATIO    	68

#define ARGUSSORTINODE	        	69
#define ARGUSSORTLOCALITY	       	70
#define ARGUSSORTSRCLOCALITY	       	71
#define ARGUSSORTDSTLOCALITY	       	72
#define ARGUSSORTSRCHOPS	       	72
#define ARGUSSORTDSTHOPS	       	73

#define ARGUSSORTSRCMASKLEN	       	74
#define ARGUSSORTDSTMASKLEN	       	75

#define ARGUSSORTSID			76
#define ARGUSSORTINF			77

#if defined(ArgusSort)

struct ArgusSorterStruct *ArgusSorter = NULL;
int ArgusReverseSortDir = 0;

struct ArgusSorterStruct *ArgusNewSorter (struct ArgusParserStruct *parser);

void ArgusDeleteSorter (struct ArgusSorterStruct *);
void ArgusProcessSortOptions(void);
void ArgusSortQueue (struct ArgusSorterStruct *, struct ArgusQueueStruct *, int); 
int ArgusSortRoutine (const void *, const void *);

int ArgusSortSrcId (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSID (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortInf (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortIdleTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortStartTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortLastTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortTransactions (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDuration (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortMean (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortMin (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortMax (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcMac (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstMac (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcAddr (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstAddr (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortInode (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

int ArgusSortLocality (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcLocality (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstLocality (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

int ArgusSortProtocol (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcMpls (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstMpls (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcVlan (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstVlan (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcIpId (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstIpId (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcPort (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstPort (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcTos (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstTos (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcDSByte (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstDSByte (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcTtl (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstTtl (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortLoad (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcLoad (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstLoad (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortPercentLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortRate (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcRate (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstRate (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcMeanPktSize (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstMeanPktSize (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortTranRef (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSeq (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

int ArgusSortAppByteRatio (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

int ArgusSortAppByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortAppSrcByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortAppDstByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

int ArgusSortPktsCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcPktsCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstPktsCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortAppByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcAppByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstAppByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcTcpBase (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstTcpBase (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortTcpRtt (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortPercentSrcLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortPercentDstLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcMaxPktSize (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcMinPktSize (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstMaxPktSize (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstMinPktSize (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcCountryCode (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstCountryCode (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcASNum (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstASNum (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSum (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcOui (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstOui (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

int ArgusSortLocality (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortSrcLocality (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstLocality (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

int ArgusSortSrcHops (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstHops (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

int ArgusSortSrcMasklen (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstMasklen (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

/*
int ArgusSortSrcDup (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
int ArgusSortDstDup (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
*/

int (*ArgusSortAlgorithmTable[MAX_SORT_ALG_TYPES])(struct ArgusRecordStruct *, struct ArgusRecordStruct *) = {
   ArgusSortStartTime,
   ArgusSortStartTime,
   ArgusSortLastTime,
   ArgusSortTransactions,
   ArgusSortDuration,
   ArgusSortMean,
   ArgusSortMin,
   ArgusSortMax,
   ArgusSortSrcMac,
   ArgusSortDstMac,
   ArgusSortSrcAddr,
   ArgusSortDstAddr,
   ArgusSortProtocol,
   ArgusSortSrcIpId,
   ArgusSortDstIpId,
   ArgusSortSrcPort,
   ArgusSortDstPort,
   ArgusSortSrcTos,
   ArgusSortDstTos,
   ArgusSortSrcTtl,
   ArgusSortDstTtl,

   ArgusSortByteCount,
   ArgusSortSrcByteCount,
   ArgusSortDstByteCount,
   ArgusSortPktsCount,
   ArgusSortSrcPktsCount,
   ArgusSortDstPktsCount,

   ArgusSortAppByteCount,
   ArgusSortSrcAppByteCount,
   ArgusSortDstAppByteCount,

   ArgusSortLoad,
   ArgusSortSrcLoad,
   ArgusSortDstLoad,

   ArgusSortLoss,
   ArgusSortPercentLoss,
   ArgusSortRate,
   ArgusSortSrcRate,
   ArgusSortDstRate,
   ArgusSortTranRef,
   ArgusSortSeq,
   ArgusSortSrcMpls,
   ArgusSortDstMpls,
   ArgusSortSrcVlan,
   ArgusSortDstVlan,
   ArgusSortSrcId,
   ArgusSortSrcTcpBase,
   ArgusSortDstTcpBase,
   ArgusSortTcpRtt,
   ArgusSortSrcLoss,
   ArgusSortDstLoss,
   ArgusSortPercentSrcLoss,
   ArgusSortPercentDstLoss,
   ArgusSortSrcMaxPktSize,
   ArgusSortSrcMinPktSize,
   ArgusSortDstMaxPktSize,
   ArgusSortDstMinPktSize,
   ArgusSortSrcDSByte,
   ArgusSortDstDSByte,
   ArgusSortSrcCountryCode,
   ArgusSortDstCountryCode,
   ArgusSortSrcASNum,
   ArgusSortDstASNum,
   ArgusSortSum,
   ArgusSortSum,
   ArgusSortIdleTime,
   ArgusSortSrcOui,
   ArgusSortDstOui,
   ArgusSortAppByteRatio,
   ArgusSortAppByteRatio,
   ArgusSortInode,
   ArgusSortLocality,
   ArgusSortSrcLocality,
   ArgusSortDstLocality,
   ArgusSortSrcHops,
   ArgusSortDstHops,
   ArgusSortSrcMasklen,
   ArgusSortDstMasklen,
   ArgusSortSID,
   ArgusSortInf,
};

char *ArgusSortKeyWords[MAX_SORT_ALG_TYPES] = {
   "stime",
   "stime",
   "ltime",
   "trans",
   "dur",
   "mean",
   "min",
   "max",
   "smac",
   "dmac",
   "saddr",

   "daddr",
   "proto",
   "sipid",
   "dipid",
   "sport",
   "dport",
   "stos",
   "dtos",
   "sttl",
   "dttl",

   "bytes",
   "sbytes",
   "dbytes",
   "pkts",
   "spkts",
   "dpkts",
   "appbytes",
   "sappbytes",
   "dappbytes",
   "load",

   "sload",
   "dload",
   "loss",
   "ploss",
   "rate",
   "srate",
   "drate",
   "tranref",
   "seq",
   "smpls",

   "dmpls",
   "svlan",
   "dvlan",
   "srcid",
   "stcpb",
   "dtcpb",
   "tcprtt",
   "sloss",
   "dloss",
   "sploss",

   "dploss",
   "smaxsz",
   "sminsz",
   "dmaxsz",
   "dminsz",
   "sdsb",
   "ddsb",
   "sco",
   "dco",
   "sas",

   "das",
   "sum",
   "runtime",
   "idle",
   "soui",
   "doui",
   "abr",
   "pcr",
   "inode",
   "loc",

   "sloc",
   "dloc",
   "shops",
   "dhops",
   "smask",
   "dmask",

   "sid",
   "inf",
};

#else


extern struct ArgusSorterStruct *ArgusSorter;
extern int ArgusReverseSortDir;

extern struct ArgusSorterStruct *ArgusNewSorter (struct ArgusParserStruct *parser);
extern void ArgusDeleteSorter (struct ArgusSorterStruct *);
extern void ArgusProcessSortOptions(void);
extern void ArgusSortQueue (struct ArgusSorterStruct *, struct ArgusQueueStruct *, int); 
extern int ArgusSortRoutine (const void *, const void *);
 
extern int ArgusSortSrcId (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSID (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortInf (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortIdleTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortStartTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortLastTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortTransactions (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDuration (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortMean (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortMin (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortMax (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcAddr (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstAddr (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortInode (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

extern int ArgusSortLocality (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcLocality (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstLocality (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

extern int ArgusSortProtocol (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortIpId (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcPort (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstPort (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcTos (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstTos (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcDSByte (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstDSByte (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcTtl (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstTtl (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortLoad (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortPercentLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortRate (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortTranRef (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSeq (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortPktsCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcPktsCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstPktsCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortAppByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcAppByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstAppByteCount (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcTcpBase (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstTcpBase (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortTcpRtt (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcOui (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstOui (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

extern int ArgusSortSrcGap (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstGap (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortSrcDup (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern int ArgusSortDstDup (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

extern int (*ArgusSortAlgorithmTable[MAX_SORT_ALG_TYPES])(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
extern char *ArgusSortKeyWords[MAX_SORT_ALG_TYPES];
#endif

#ifdef __cplusplus
}
#endif
#endif

