/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
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
 * $Id: //depot/gargoyle/clients/examples/raconvert/raconvert.h#6 $
 * $DateTime: 2018/10/10 16:07:21 $
 * $Change: 3077 $
 */


#ifndef Raconvert_h
#define Raconvert_h

#include <argus_json.h>

struct ArgusParseFieldStruct {
   char *field, *format;
   int length, index, type, value;
   void (*parse)(struct ArgusParserStruct *, char *);
   char *dbformat;
   int offset;
   char *title;
};

void ArgusParseType (struct ArgusParserStruct *, char *);

void ArgusParseBssid (struct ArgusParserStruct *, char *);
void ArgusParseSsid (struct ArgusParserStruct *, char *);
void ArgusParseCause (struct ArgusParserStruct *, char *);
void ArgusParseStartDate (struct ArgusParserStruct *, char *);
void ArgusParseLastDate (struct ArgusParserStruct *, char *);
void ArgusParseSrcStartDate (struct ArgusParserStruct *, char *);
void ArgusParseSrcLastDate (struct ArgusParserStruct *, char *);
void ArgusParseDstStartDate (struct ArgusParserStruct *, char *);
void ArgusParseDstLastDate (struct ArgusParserStruct *, char *);
void ArgusParseRelativeDate (struct ArgusParserStruct *, char *);
void ArgusParseSourceID (struct ArgusParserStruct *, char *);
void ArgusParseSID (struct ArgusParserStruct *, char *);
void ArgusParseNode (struct ArgusParserStruct *, char *);
void ArgusParseInf (struct ArgusParserStruct *, char *);
void ArgusParseStatus (struct ArgusParserStruct *, char *);
void ArgusParseScore (struct ArgusParserStruct *, char *);
void ArgusParseFlags (struct ArgusParserStruct *, char *);
void ArgusParseSrcMacAddress (struct ArgusParserStruct *, char *);
void ArgusParseDstMacAddress (struct ArgusParserStruct *, char *);
void ArgusParseMacAddress (struct ArgusParserStruct *, char *);
void ArgusParseEtherType (struct ArgusParserStruct *, char *);
void ArgusParseProto (struct ArgusParserStruct *, char *);
void ArgusParseAddr (struct ArgusParserStruct *, char *);
void ArgusParseSrcNet (struct ArgusParserStruct *, char *);
void ArgusParseSrcAddr (struct ArgusParserStruct *, char *);
void ArgusParseSrcName (struct ArgusParserStruct *, char *);
void ArgusParseSrcGroup (struct ArgusParserStruct *, char *);
void ArgusParseDstNet (struct ArgusParserStruct *, char *);
void ArgusParseDstAddr (struct ArgusParserStruct *, char *);
void ArgusParseDstName (struct ArgusParserStruct *, char *);
void ArgusParseDstGroup (struct ArgusParserStruct *, char *);
void ArgusParseLocalNet (struct ArgusParserStruct *, char *);
void ArgusParseLocalAddr (struct ArgusParserStruct *, char *);
void ArgusParseRemoteNet (struct ArgusParserStruct *, char *);
void ArgusParseRemoteAddr (struct ArgusParserStruct *, char *);
void ArgusParseSrcPort (struct ArgusParserStruct *, char *);
void ArgusParseDstPort (struct ArgusParserStruct *, char *);
void ArgusParseSrcIpId (struct ArgusParserStruct *, char *);
void ArgusParseDstIpId (struct ArgusParserStruct *, char *);
void ArgusParseIpId (struct ArgusParserStruct *, char *);
void ArgusParseSrcTtl (struct ArgusParserStruct *, char *);
void ArgusParseDstTtl (struct ArgusParserStruct *, char *);
void ArgusParseTtl (struct ArgusParserStruct *, char *);
void ArgusParseDirection (struct ArgusParserStruct *, char *);
void ArgusParsePackets (struct ArgusParserStruct *, char *);
void ArgusParseSrcPackets (struct ArgusParserStruct *, char *);
void ArgusParseDstPackets (struct ArgusParserStruct *, char *);
void ArgusParseBytes (struct ArgusParserStruct *, char *);
void ArgusParseSrcBytes (struct ArgusParserStruct *, char *);
void ArgusParseDstBytes (struct ArgusParserStruct *, char *);
void ArgusParseAppBytes (struct ArgusParserStruct *, char *);
void ArgusParseSrcAppBytes (struct ArgusParserStruct *, char *);
void ArgusParseDstAppBytes (struct ArgusParserStruct *, char *);
void ArgusParseProducerConsumerRatio (struct ArgusParserStruct *, char *);
void ArgusParseAppByteRatio (struct ArgusParserStruct *, char *);
void ArgusParseTransEfficiency (struct ArgusParserStruct *, char *);
void ArgusParseSrcTransEfficiency (struct ArgusParserStruct *, char *);
void ArgusParseDstTransEfficiency (struct ArgusParserStruct *, char *);
void ArgusParseSrcIntPkt (struct ArgusParserStruct *, char *);
void ArgusParseSrcIntPktDist (struct ArgusParserStruct *, char *);
void ArgusParseDstIntPkt (struct ArgusParserStruct *, char *);
void ArgusParseDstIntPktDist (struct ArgusParserStruct *, char *);
void ArgusParseActiveIntPkt (struct ArgusParserStruct *, char *);
void ArgusParseActiveIntPkt (struct ArgusParserStruct *, char *);
void ArgusParseActiveIntPktDist (struct ArgusParserStruct *, char *);
void ArgusParseActiveSrcIntPkt (struct ArgusParserStruct *, char *);
void ArgusParseActiveSrcIntPktDist (struct ArgusParserStruct *, char *);
void ArgusParseActiveDstIntPkt (struct ArgusParserStruct *, char *);
void ArgusParseActiveDstIntPktDist (struct ArgusParserStruct *, char *);
void ArgusParseIdleIntPkt (struct ArgusParserStruct *, char *);
void ArgusParseIdleIntPktDist (struct ArgusParserStruct *, char *);
void ArgusParseIdleSrcIntPkt (struct ArgusParserStruct *, char *);
void ArgusParseIdleSrcIntPktDist (struct ArgusParserStruct *, char *);
void ArgusParseIdleDstIntPkt (struct ArgusParserStruct *, char *);
void ArgusParseIdleDstIntPktDist (struct ArgusParserStruct *, char *);
void ArgusParseSrcIntPktMax (struct ArgusParserStruct *, char *);
void ArgusParseSrcIntPktMin (struct ArgusParserStruct *, char *);
void ArgusParseDstIntPktMax (struct ArgusParserStruct *, char *);
void ArgusParseDstIntPktMin (struct ArgusParserStruct *, char *);
void ArgusParseActiveSrcIntPktMax (struct ArgusParserStruct *, char *);
void ArgusParseActiveSrcIntPktMin (struct ArgusParserStruct *, char *);
void ArgusParseActiveDstIntPktMax (struct ArgusParserStruct *, char *);
void ArgusParseActiveDstIntPktMin (struct ArgusParserStruct *, char *);
void ArgusParseIdleSrcIntPktMax (struct ArgusParserStruct *, char *);
void ArgusParseIdleSrcIntPktMin (struct ArgusParserStruct *, char *);
void ArgusParseIdleDstIntPktMax (struct ArgusParserStruct *, char *);
void ArgusParseIdleDstIntPktMin (struct ArgusParserStruct *, char *);
void ArgusParseIntFlow (struct ArgusParserStruct *, char *);
void ArgusParseIntFlowDist (struct ArgusParserStruct *, char *);
void ArgusParseIntFlowStdDev (struct ArgusParserStruct *, char *);
void ArgusParseIntFlowMax (struct ArgusParserStruct *, char *);
void ArgusParseIntFlowMin (struct ArgusParserStruct *, char *);
void ArgusParseSrcJitter (struct ArgusParserStruct *, char *);
void ArgusParseDstJitter (struct ArgusParserStruct *, char *);
void ArgusParseActiveSrcJitter (struct ArgusParserStruct *, char *);
void ArgusParseActiveDstJitter (struct ArgusParserStruct *, char *);
void ArgusParseIdleSrcJitter (struct ArgusParserStruct *, char *);
void ArgusParseIdleDstJitter (struct ArgusParserStruct *, char *);
void ArgusParseState (struct ArgusParserStruct *, char *);
void ArgusParseDeltaDuration (struct ArgusParserStruct *, char *);
void ArgusParseDeltaStartTime (struct ArgusParserStruct *, char *);
void ArgusParseDeltaLastTime (struct ArgusParserStruct *, char *);
void ArgusParseDeltaSrcPkts (struct ArgusParserStruct *, char *);
void ArgusParseDeltaDstPkts (struct ArgusParserStruct *, char *);
void ArgusParseDeltaSrcBytes (struct ArgusParserStruct *, char *);
void ArgusParseDeltaDstBytes (struct ArgusParserStruct *, char *);
void ArgusParsePercentDeltaSrcPkts (struct ArgusParserStruct *, char *);
void ArgusParsePercentDeltaDstPkts (struct ArgusParserStruct *, char *);
void ArgusParsePercentDeltaSrcBytes (struct ArgusParserStruct *, char *);
void ArgusParsePercentDeltaDstBytes (struct ArgusParserStruct *, char *);
void ArgusParseSrcUserData (struct ArgusParserStruct *, char *);
void ArgusParseDstUserData (struct ArgusParserStruct *, char *);
void ArgusParseUserData (struct ArgusParserStruct *, char *);
void ArgusParseTCPOptions (struct ArgusParserStruct *, char *);
void ArgusParseTCPExtensions (struct ArgusParserStruct *, char *);
void ArgusParseSrcLoad (struct ArgusParserStruct *, char *);
void ArgusParseDstLoad (struct ArgusParserStruct *, char *);
void ArgusParseLoad (struct ArgusParserStruct *, char *);
void ArgusParseSrcLoss (struct ArgusParserStruct *, char *);
void ArgusParseDstLoss (struct ArgusParserStruct *, char *);
void ArgusParseLoss (struct ArgusParserStruct *, char *);
void ArgusParseSrcRetrans (struct ArgusParserStruct *, char *);
void ArgusParseDstRetrans (struct ArgusParserStruct *, char *);
void ArgusParseRetrans (struct ArgusParserStruct *, char *);
void ArgusParsePercentSrcRetrans (struct ArgusParserStruct *, char *);
void ArgusParsePercentDstRetrans (struct ArgusParserStruct *, char *);
void ArgusParsePercentRetrans (struct ArgusParserStruct *, char *);
void ArgusParseSrcNacks (struct ArgusParserStruct *, char *);
void ArgusParseDstNacks (struct ArgusParserStruct *, char *);
void ArgusParseNacks (struct ArgusParserStruct *, char *);
void ArgusParsePercentSrcNacks (struct ArgusParserStruct *, char *);
void ArgusParsePercentDstNacks (struct ArgusParserStruct *, char *);
void ArgusParsePercentNacks (struct ArgusParserStruct *, char *);
void ArgusParseSrcSolo (struct ArgusParserStruct *, char *);
void ArgusParseDstSolo (struct ArgusParserStruct *, char *);
void ArgusParseSolo (struct ArgusParserStruct *, char *);
void ArgusParsePercentSrcSolo (struct ArgusParserStruct *, char *);
void ArgusParsePercentDstSolo (struct ArgusParserStruct *, char *);
void ArgusParsePercentSolo (struct ArgusParserStruct *, char *);
void ArgusParseSrcFirst (struct ArgusParserStruct *, char *);
void ArgusParseDstFirst (struct ArgusParserStruct *, char *);
void ArgusParseFirst (struct ArgusParserStruct *, char *);
void ArgusParsePercentSrcFirst (struct ArgusParserStruct *, char *);
void ArgusParsePercentDstFirst (struct ArgusParserStruct *, char *);
void ArgusParsePercentFirst (struct ArgusParserStruct *, char *);
void ArgusParsePercentSrcLoss (struct ArgusParserStruct *, char *);
void ArgusParsePercentDstLoss (struct ArgusParserStruct *, char *);
void ArgusParsePercentLoss (struct ArgusParserStruct *, char *);
void ArgusParseSrcRate (struct ArgusParserStruct *, char *);
void ArgusParseDstRate (struct ArgusParserStruct *, char *);
void ArgusParseRate (struct ArgusParserStruct *, char *);
void ArgusParseSrcTos (struct ArgusParserStruct *, char *);
void ArgusParseDstTos (struct ArgusParserStruct *, char *);
void ArgusParseSrcDSByte (struct ArgusParserStruct *, char *);
void ArgusParseDstDSByte (struct ArgusParserStruct *, char *);
void ArgusParseSrcVlan (struct ArgusParserStruct *, char *);
void ArgusParseDstVlan (struct ArgusParserStruct *, char *);
void ArgusParseSrcVID (struct ArgusParserStruct *, char *);
void ArgusParseDstVID (struct ArgusParserStruct *, char *);
void ArgusParseSrcVPRI (struct ArgusParserStruct *, char *);
void ArgusParseDstVPRI (struct ArgusParserStruct *, char *);
void ArgusParseSrcMpls (struct ArgusParserStruct *, char *);
void ArgusParseDstMpls (struct ArgusParserStruct *, char *);
void ArgusParseWindow (struct ArgusParserStruct *, char *);
void ArgusParseSrcWindow (struct ArgusParserStruct *, char *);
void ArgusParseDstWindow (struct ArgusParserStruct *, char *);
void ArgusParseSrcMaxSeg (struct ArgusParserStruct *, char *);
void ArgusParseDstMaxSeg (struct ArgusParserStruct *, char *);
void ArgusParseJoinDelay (struct ArgusParserStruct *, char *);
void ArgusParseLeaveDelay (struct ArgusParserStruct *, char *);
void ArgusParseMean (struct ArgusParserStruct *, char *);
void ArgusParseMin (struct ArgusParserStruct *, char *);
void ArgusParseMax (struct ArgusParserStruct *, char *);
void ArgusParseStdDeviation (struct ArgusParserStruct *, char *);
void ArgusParseIdleMean (struct ArgusParserStruct *, char *);
void ArgusParseIdleMin (struct ArgusParserStruct *, char *);
void ArgusParseIdleMax (struct ArgusParserStruct *, char *);
void ArgusParseIdleSum (struct ArgusParserStruct *, char *);
void ArgusParseIdleStdDeviation (struct ArgusParserStruct *, char *);
void ArgusParseStartRange (struct ArgusParserStruct *, char *);
void ArgusParseEndRange (struct ArgusParserStruct *, char *);
void ArgusParseSrcDuration (struct ArgusParserStruct *, char *);
void ArgusParseDstDuration (struct ArgusParserStruct *, char *);
void ArgusParseDuration (struct ArgusParserStruct *, char *);
void ArgusParseTransactions (struct ArgusParserStruct *, char *);
void ArgusParseSequenceNumber (struct ArgusParserStruct *, char *);
void ArgusParseHashRef (struct ArgusParserStruct *, char *);
void ArgusParseHashIndex (struct ArgusParserStruct *, char *);
void ArgusParseRank (struct ArgusParserStruct *, char *);
void ArgusParseBinNumber (struct ArgusParserStruct *, char *);
void ArgusParseBins (struct ArgusParserStruct *, char *);
void ArgusParseTCPSrcBase (struct ArgusParserStruct *, char *);
void ArgusParseTCPDstBase (struct ArgusParserStruct *, char *);
void ArgusParseTCPRTT (struct ArgusParserStruct *, char *);
void ArgusParseTCPSynAck (struct ArgusParserStruct *, char *);
void ArgusParseTCPAckDat (struct ArgusParserStruct *, char *);
void ArgusParseTCPSrcMax (struct ArgusParserStruct *, char *);
void ArgusParseTCPDstMax (struct ArgusParserStruct *, char *);
void ArgusParseSrcGap (struct ArgusParserStruct *, char *);
void ArgusParseDstGap (struct ArgusParserStruct *, char *);
void ArgusParseInode (struct ArgusParserStruct *, char *);
void ArgusParseByteOffset (struct ArgusParserStruct *, char *);
void ArgusParseSrcEncaps (struct ArgusParserStruct *, char *);
void ArgusParseDstEncaps (struct ArgusParserStruct *, char *);
void ArgusParseMaxPktSize (struct ArgusParserStruct *, char *);
void ArgusParseSrcPktSize (struct ArgusParserStruct *, char *);
void ArgusParseSrcMaxPktSize (struct ArgusParserStruct *, char *);
void ArgusParseSrcMinPktSize (struct ArgusParserStruct *, char *);
void ArgusParseSrcMeanPktSize (struct ArgusParserStruct *, char *);
void ArgusParseDstPktSize (struct ArgusParserStruct *, char *);
void ArgusParseDstMaxPktSize (struct ArgusParserStruct *, char *);
void ArgusParseDstMinPktSize (struct ArgusParserStruct *, char *);
void ArgusParseDstMeanPktSize (struct ArgusParserStruct *, char *);
void ArgusParseSrcCountryCode (struct ArgusParserStruct *, char *);
void ArgusParseDstCountryCode (struct ArgusParserStruct *, char *);
void ArgusParseInodeCountryCode (struct ArgusParserStruct *, char *);
void ArgusParseSrcLatitude (struct ArgusParserStruct *, char *);
void ArgusParseDstLatitude (struct ArgusParserStruct *, char *);
void ArgusParseInodeLatitude (struct ArgusParserStruct *, char *);
void ArgusParseSrcLongitude (struct ArgusParserStruct *, char *);
void ArgusParseDstLongitude (struct ArgusParserStruct *, char *);
void ArgusParseInodeLongitude (struct ArgusParserStruct *, char *);
void ArgusParseLocal (struct ArgusParserStruct *, char *);
void ArgusParseSrcLocal (struct ArgusParserStruct *, char *);
void ArgusParseDstLocal (struct ArgusParserStruct *, char *);
void ArgusParseSrcHopCount (struct ArgusParserStruct *, char *);
void ArgusParseDstHopCount (struct ArgusParserStruct *, char *);
void ArgusParseIcmpId (struct ArgusParserStruct *, char *);
void ArgusParseAutoId (struct ArgusParserStruct *, char *);
void ArgusParseLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcAsn (struct ArgusParserStruct *, char *);
void ArgusParseDstAsn (struct ArgusParserStruct *, char *);
void ArgusParseInodeAsn (struct ArgusParserStruct *, char *);
void ArgusParseKeyStrokeSrcNStroke (struct ArgusParserStruct *, char *);
void ArgusParseKeyStrokeDstNStroke (struct ArgusParserStruct *, char *);
void ArgusParseKeyStrokeNStroke (struct ArgusParserStruct *, char *);
void ArgusParseSum (struct ArgusParserStruct *, char *);
void ArgusParseRunTime (struct ArgusParserStruct *, char *);
void ArgusParseIdleTime (struct ArgusParserStruct *, char *);
void ArgusParseResponse (struct ArgusParserStruct *, char *);
void ArgusParseSrcOui (struct ArgusParserStruct *, char *);
void ArgusParseDstOui (struct ArgusParserStruct *, char *);
void ArgusParseCor (struct ArgusParserStruct *, char *);
void ArgusParseSrcVirtualNID (struct ArgusParserStruct *, char *);
void ArgusParseDstVirtualNID (struct ArgusParserStruct *, char *);

void ArgusParseMpls (struct ArgusParserStruct *, char *);
void ArgusParseSrcMpls (struct ArgusParserStruct *, char *);
void ArgusParseDstMpls (struct ArgusParserStruct *, char *);
void ArgusParseVLAN (struct ArgusParserStruct *, char *);
void ArgusParseSrcVLAN (struct ArgusParserStruct *, char *);
void ArgusParseDstVLAN (struct ArgusParserStruct *, char *);
void ArgusParseVID (struct ArgusParserStruct *, char *);
void ArgusParseSrcVID (struct ArgusParserStruct *, char *);
void ArgusParseDstVID (struct ArgusParserStruct *, char *);
void ArgusParseVPRI (struct ArgusParserStruct *, char *);
void ArgusParseSrcVPRI (struct ArgusParserStruct *, char *);
void ArgusParseDstVPRI (struct ArgusParserStruct *, char *);

#define ARGUS_PTYPE_INT         0
#define ARGUS_PTYPE_UINT        1
#define ARGUS_PTYPE_DOUBLE      2
#define ARGUS_PTYPE_STRING      4

struct ArgusParseFieldStruct 
RaParseAlgorithmTable[MAX_PRINT_ALG_TYPES] = {
#define ARGUSPARSESTARTDATE		0
   { "stime", "%T.%f", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESTARTDATE, ArgusParseStartDate, "double(18,6) unsigned not null", 0, "StartTime"},
#define ARGUSPARSELASTDATE		1
   { "ltime", "%T.%f", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSELASTDATE, ArgusParseLastDate, "double(18,6) unsigned not null", 0, "LastTime"},
#define ARGUSPARSETRANSACTIONS		2
   { "trans", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSETRANSACTIONS, ArgusParseTransactions, "int unsigned", 0, "Trans"},
#define ARGUSPARSEDURATION		3
   { "dur", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDURATION, ArgusParseDuration, "double(18,6) not null", 0, "Dur"},
#define ARGUSPARSEMEAN		        4
   { "mean", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEMEAN, ArgusParseMean, "double", 0, "Mean"},
#define ARGUSPARSEMIN			5
   { "min", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEMIN, ArgusParseMin, "double", 0, "Min"},
#define ARGUSPARSEMAX			6
   { "max", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEMAX, ArgusParseMax, "double", 0, "Max"},
#define ARGUSPARSESRCADDR		7
   { "saddr", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCADDR, ArgusParseSrcAddr, "varchar(64) not null", 0, "SrcAddr"},
#define ARGUSPARSEDSTADDR		8
   { "daddr", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTADDR, ArgusParseDstAddr, "varchar(64) not null", 0, "DstAddr"},
#define ARGUSPARSEPROTO			9
   { "proto", "", 6 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEPROTO, ArgusParseProto, "varchar(16) not null", 0, "Proto"},
#define ARGUSPARSESRCPORT		10
   { "sport", "", 6 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCPORT, ArgusParseSrcPort, "varchar(10) not null", 0, "Sport"},
#define ARGUSPARSEDSTPORT		11
   { "dport", "", 6 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTPORT, ArgusParseDstPort, "varchar(10) not null", 0, "Dport"},
#define ARGUSPARSESRCTOS		12
   { "stos", "", 5 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCTOS, ArgusParseSrcTos, "tinyint unsigned", 0, "sTos"},
#define ARGUSPARSEDSTTOS		13
   { "dtos", "", 5 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTTOS, ArgusParseDstTos, "tinyint unsigned", 0, "dTos"},
#define ARGUSPARSESRCDSBYTE		14
   { "sdsb", "", 5 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCDSBYTE, ArgusParseSrcDSByte, "varchar(4) not null", 0, "sDSb"},
#define ARGUSPARSEDSTDSBYTE		15
   { "ddsb", "", 5 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTDSBYTE, ArgusParseDstDSByte, "varchar(4) not null", 0, "dDSb"},
#define ARGUSPARSESRCTTL		16
   { "sttl", "", 4 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCTTL, ArgusParseSrcTtl, "tinyint unsigned", 0, "sTtl"},
#define ARGUSPARSEDSTTTL		17
   { "dttl", "", 4 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTTTL, ArgusParseDstTtl, "tinyint unsigned", 0, "dTtl"},
#define ARGUSPARSEBYTES			18
   { "bytes", "", 10 , 1, ARGUS_PTYPE_INT, ARGUSPARSEBYTES, ArgusParseBytes, "bigint", 0, "TotBytes"},
#define ARGUSPARSESRCBYTES		19
   { "sbytes", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCBYTES, ArgusParseSrcBytes, "bigint", 0, "SrcBytes"},
#define ARGUSPARSEDSTBYTES		20
   { "dbytes", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTBYTES, ArgusParseDstBytes, "bigint", 0, "DstBytes"},
#define ARGUSPARSEAPPBYTES              21
   { "appbytes", "", 10 , 1, ARGUS_PTYPE_INT, ARGUSPARSEAPPBYTES, ArgusParseAppBytes, "bigint", 0, "AppBytes"},
#define ARGUSPARSESRCAPPBYTES           22
   { "sappbytes", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCAPPBYTES, ArgusParseSrcAppBytes, "bigint", 0, "SAppBytes"},
#define ARGUSPARSEDSTAPPBYTES           23
   { "dappbytes", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTAPPBYTES, ArgusParseDstAppBytes, "bigint", 0, "DAppBytes"},
#define ARGUSPARSEPACKETS		24
   { "pkts", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPARSEPACKETS, ArgusParsePackets, "bigint", 0, "TotPkts"},
#define ARGUSPARSESRCPACKETS		25
   { "spkts", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCPACKETS, ArgusParseSrcPackets, "bigint", 0, "SrcPkts"},
#define ARGUSPARSEDSTPACKETS		26
   { "dpkts", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTPACKETS, ArgusParseDstPackets, "bigint", 0, "DstPkts"},
#define ARGUSPARSELOAD			27
   { "load", "", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSELOAD, ArgusParseLoad, "double", 0, "Load"},
#define ARGUSPARSESRCLOAD		28
   { "sload", "", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESRCLOAD, ArgusParseSrcLoad, "double", 0, "SrcLoad"},
#define ARGUSPARSEDSTLOAD		29
   { "dload", "", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDSTLOAD, ArgusParseDstLoad, "double", 0, "DstLoad"},
#define ARGUSPARSELOSS			30
   { "loss", "", 10 , 1, ARGUS_PTYPE_INT, ARGUSPARSELOSS, ArgusParseLoss, "int", 0, "Loss"},
#define ARGUSPARSESRCLOSS		31
   { "sloss", "", 10 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCLOSS, ArgusParseSrcLoss, "int", 0, "SrcLoss"},
#define ARGUSPARSEDSTLOSS		32
   { "dloss", "", 10 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTLOSS, ArgusParseDstLoss, "int", 0, "DstLoss"},
#define ARGUSPARSEPERCENTLOSS		33
   { "ploss", "", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTLOSS, ArgusParsePercentLoss, "double", 0, "pLoss"},
#define ARGUSPARSESRCPERCENTLOSS	34
   { "sploss", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESRCPERCENTLOSS, ArgusParsePercentSrcLoss, "double", 0, "pSrcLoss"},
#define ARGUSPARSEDSTPERCENTLOSS	35
   { "dploss", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDSTPERCENTLOSS, ArgusParsePercentDstLoss, "double", 0, "pDstLoss"},
#define ARGUSPARSERATE			36
   { "rate", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSERATE, ArgusParseRate, "double", 0, "Rate"},
#define ARGUSPARSESRCRATE		37
   { "srate", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESRCRATE, ArgusParseSrcRate, "double", 0, "SrcRate"},
#define ARGUSPARSEDSTRATE		38
   { "drate", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDSTRATE, ArgusParseDstRate, "double", 0, "DstRate"},
#define ARGUSPARSESOURCEID		39
   { "srcid", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESOURCEID, ArgusParseSourceID, "varchar(64)", 0, "SrcId"},
#define ARGUSPARSEFLAGS			40
   { "flgs", "", 9 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEFLAGS, ArgusParseFlags, "varchar(32)", 0, "Flgs"},
#define ARGUSPARSESRCMACADDRESS		41
   { "smac", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCMACADDRESS, ArgusParseSrcMacAddress, "varchar(24)", 0, "SrcMac"},
#define ARGUSPARSEDSTMACADDRESS		42
   { "dmac", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTMACADDRESS, ArgusParseDstMacAddress, "varchar(24)", 0, "DstMac"},
#define ARGUSPARSEDIR			43
   { "dir", "", 5 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDIR, ArgusParseDirection, "varchar(3)", 0, "Dir"},
#define ARGUSPARSESRCINTPKT		44
   { "sintpkt", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESRCINTPKT, ArgusParseSrcIntPkt, "double", 0, "SIntPkt"},
#define ARGUSPARSEDSTINTPKT		45
   { "dintpkt", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDSTINTPKT, ArgusParseDstIntPkt, "double", 0, "DIntPkt"},
#define ARGUSPARSEACTSRCINTPKT		46
   { "sintpktact", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEACTSRCINTPKT, ArgusParseActiveSrcIntPkt, "double", 0, "SIntPktAct"},
#define ARGUSPARSEACTDSTINTPKT		47
   { "dintpktact", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEACTDSTINTPKT, ArgusParseActiveDstIntPkt, "double", 0, "DIntPktAct"},
#define ARGUSPARSEIDLESRCINTPKT		48
   { "sintpktidl", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEIDLESRCINTPKT, ArgusParseIdleSrcIntPkt, "double", 0, "SIntPktIdl"},
#define ARGUSPARSEIDLEDSTINTPKT		49
   { "dintpktidl", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEIDLEDSTINTPKT, ArgusParseIdleDstIntPkt, "double", 0, "DIntPktIdl"},
#define ARGUSPARSESRCINTPKTMAX		50
   { "sintpktmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESRCINTPKTMAX, ArgusParseSrcIntPktMax, "double", 0, "SIntPktMax"},
#define ARGUSPARSESRCINTPKTMIN		51
   { "sintpktmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESRCINTPKTMIN, ArgusParseSrcIntPktMin, "double", 0, "SIntPktMin"},
#define ARGUSPARSEDSTINTPKTMAX		52
   { "dintpktmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDSTINTPKTMAX, ArgusParseDstIntPktMax, "double", 0, "DIntPktMax"},
#define ARGUSPARSEDSTINTPKTMIN		53
   { "dintpktmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDSTINTPKTMIN, ArgusParseDstIntPktMin, "double", 0, "DIntPktMin"},
#define ARGUSPARSEACTSRCINTPKTMAX	54
   { "sintpktactmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEACTSRCINTPKTMAX, ArgusParseActiveSrcIntPktMax, "double", 0, "SIntPktActMax"},
#define ARGUSPARSEACTSRCINTPKTMIN	55
   { "sintpktactmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEACTSRCINTPKTMIN, ArgusParseActiveSrcIntPktMin, "double", 0, "SIntPktActMin"},
#define ARGUSPARSEACTDSTINTPKTMAX	56
   { "dintpktactmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEACTDSTINTPKTMAX, ArgusParseActiveDstIntPktMax, "double", 0, "DIntPktActMax"},
#define ARGUSPARSEACTDSTINTPKTMIN	57
   { "dintpktactmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEACTDSTINTPKTMIN, ArgusParseActiveDstIntPktMin, "double", 0, "DIntPktActMin"},
#define ARGUSPARSEIDLESRCINTPKTMAX	58
   { "sintpktidlmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEIDLESRCINTPKTMAX, ArgusParseIdleSrcIntPktMax, "double", 0, "SIntPktIdlMax"},
#define ARGUSPARSEIDLESRCINTPKTMIN	59
   { "sintpktidlmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEIDLESRCINTPKTMIN, ArgusParseIdleSrcIntPktMin, "double", 0, "SIntPktIdlMin"},
#define ARGUSPARSEIDLEDSTINTPKTMAX	60
   { "dintpktidlmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEIDLEDSTINTPKTMAX, ArgusParseIdleDstIntPktMax, "double", 0, "DIntPktIdlMax"},
#define ARGUSPARSEIDLEDSTINTPKTMIN	61
   { "dintpktidlmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEIDLEDSTINTPKTMIN, ArgusParseIdleDstIntPktMin, "double", 0, "DIntPktIdlMin"},
#define ARGUSPARSESPACER		62
   { "xxx", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESPACER, NULL, "varchar(3)", 0, "xxx"},
#define ARGUSPARSESRCJITTER		63
   { "sjit", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESRCJITTER, ArgusParseSrcJitter, "double", 0, "SrcJitter"},
#define ARGUSPARSEDSTJITTER		64
   { "djit", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDSTJITTER, ArgusParseDstJitter, "double", 0, "DstJitter"},
#define ARGUSPARSEACTSRCJITTER		65
   { "sjitact", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEACTSRCJITTER, ArgusParseActiveSrcJitter, "double", 0, "ActSrcJitter"},
#define ARGUSPARSEACTDSTJITTER		66
   { "djitact", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEACTDSTJITTER, ArgusParseActiveDstJitter, "double", 0, "ActDstJitter"},
#define ARGUSPARSEIDLESRCJITTER		67
   { "sjitidl", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEIDLESRCJITTER, ArgusParseIdleSrcJitter, "double", 0, "IdlSrcJitter"},
#define ARGUSPARSEIDLEDSTJITTER		68
   { "djitidl", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEIDLEDSTJITTER, ArgusParseIdleDstJitter, "double", 0, "IdlDstJitter"},
#define ARGUSPARSESTATE			69
   { "state", "", 5 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESTATE, ArgusParseState, "varchar(32)", 0, "State"},
#define ARGUSPARSEDELTADURATION		70
   { "dldur", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDELTADURATION, ArgusParseDeltaDuration, "double", 0, "dDur"},
#define ARGUSPARSEDELTASTARTTIME	71
   { "dlstime", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDELTASTARTTIME, ArgusParseDeltaStartTime, "double(18,6)", 0, "dsTime"},
#define ARGUSPARSEDELTALASTTIME		72
   { "dlltime", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDELTALASTTIME, ArgusParseDeltaLastTime, "double(18,6)", 0, "dlTime"},
#define ARGUSPARSEDELTASPKTS		73
   { "dlspkt", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDELTASPKTS, ArgusParseDeltaSrcPkts, "int", 0, "dsPkts"},
#define ARGUSPARSEDELTADPKTS		74
   { "dldpkt", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDELTADPKTS, ArgusParseDeltaDstPkts, "int", 0, "ddPkts"},
#define ARGUSPARSEDELTASRCPKTS		75
   { "dspkts", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDELTASRCPKTS, ArgusParseDeltaSrcPkts, "int", 0, "dsPkts"},
#define ARGUSPARSEDELTADSTPKTS		76
   { "ddpkts", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDELTADSTPKTS, ArgusParseDeltaDstPkts, "int", 0, "ddPkts"},
#define ARGUSPARSEDELTASRCBYTES		77
   { "dsbytes", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDELTASRCBYTES, ArgusParseDeltaSrcBytes, "int", 0, "dsBytes"},
#define ARGUSPARSEDELTADSTBYTES		78
   { "ddbytes", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDELTADSTBYTES, ArgusParseDeltaDstBytes, "int", 0, "ddBytes"},
#define ARGUSPARSEPERCENTDELTASRCPKTS	79
   { "pdspkts", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTDELTASRCPKTS, ArgusParsePercentDeltaSrcPkts, "double", 0, "pdsPkt"},
#define ARGUSPARSEPERCENTDELTADSTPKTS	80
   { "pddpkts", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTDELTADSTPKTS, ArgusParsePercentDeltaDstPkts, "double", 0, "pddPkt"},
#define ARGUSPARSEPERCENTDELTASRCBYTES	81
   { "pdsbytes", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTDELTASRCBYTES, ArgusParsePercentDeltaSrcBytes, "double", 0, "pdsByte"},
#define ARGUSPARSEPERCENTDELTADSTBYTES	82
   { "pddbytes", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTDELTADSTBYTES, ArgusParsePercentDeltaDstBytes, "double", 0, "pddByte"},
#define ARGUSPARSESRCUSERDATA		83
   { "suser", "", 16 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCUSERDATA, ArgusParseSrcUserData, "varbinary(2048)", 0, "srcUdata"},
#define ARGUSPARSEDSTUSERDATA		84
   { "duser", "", 16 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTUSERDATA, ArgusParseDstUserData, "varbinary(2048)", 0, "dstUdata"},
#define ARGUSPARSETCPEXTENSIONS		85
   { "tcpext", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSETCPEXTENSIONS, ArgusParseTCPExtensions, "varchar(64)", 0, ""},
#define ARGUSPARSESRCWINDOW		86
   { "swin", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCWINDOW, ArgusParseSrcWindow, "tinyint unsigned", 0, ""},
#define ARGUSPARSEDSTWINDOW		87
   { "dwin", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTWINDOW, ArgusParseDstWindow, "tinyint unsigned", 0, ""},
#define ARGUSPARSEJOINDELAY		88
   { "jdelay", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEJOINDELAY, ArgusParseJoinDelay, "double", 0, ""},
#define ARGUSPARSELEAVEDELAY		89
   { "ldelay", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSELEAVEDELAY, ArgusParseLeaveDelay, "double", 0, ""},
#define ARGUSPARSESEQUENCENUMBER	90
   { "seq", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSESEQUENCENUMBER, ArgusParseSequenceNumber, "int unsigned", 0, ""},
#define ARGUSPARSEBINS			91
   { "bins", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSEBINS, ArgusParseBins, "int unsigned", 0, ""},
#define ARGUSPARSEBINNUMBER		92
   { "binnum", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSEBINNUMBER, ArgusParseBinNumber, "int unsigned", 0, ""},
#define ARGUSPARSESRCMPLS		93
   { "smpls", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCMPLS, ArgusParseSrcMpls, "int unsigned", 0, ""},
#define ARGUSPARSEDSTMPLS		94
   { "dmpls", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTMPLS, ArgusParseDstMpls, "int unsigned", 0, ""},
#define ARGUSPARSESRCVLAN		95
   { "svlan", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCVLAN, ArgusParseSrcVlan, "smallint unsigned", 0, ""},
#define ARGUSPARSEDSTVLAN		96
   { "dvlan", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTVLAN, ArgusParseDstVlan, "smallint unsigned", 0, ""},
#define ARGUSPARSESRCVID		97
   { "svid", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCVID, ArgusParseSrcVID, "smallint unsigned", 0, ""},
#define ARGUSPARSEDSTVID		98
   { "dvid", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTVID, ArgusParseDstVID, "smallint unsigned", 0, ""},
#define ARGUSPARSESRCVPRI		99
   { "svpri", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCVPRI, ArgusParseSrcVPRI, "smallint unsigned", 0, ""},
#define ARGUSPARSEDSTVPRI		100
   { "dvpri", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTVPRI, ArgusParseDstVPRI, "smallint unsigned", 0, ""},
#define ARGUSPARSESRCIPID		101
   { "sipid", "", 7 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCIPID, ArgusParseSrcIpId, "smallint unsigned", 0, ""},
#define ARGUSPARSEDSTIPID		102
   { "dipid", "", 7 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTIPID, ArgusParseDstIpId, "smallint unsigned", 0, ""},
#define ARGUSPARSESTARTRANGE		103
   { "srng", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSESTARTRANGE, ArgusParseStartRange, "int unsigned", 0, ""},
#define ARGUSPARSEENDRANGE		104
   { "erng", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSEENDRANGE, ArgusParseEndRange, "int unsigned", 0, ""},
#define ARGUSPARSETCPSRCBASE		105
   { "stcpb", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSETCPSRCBASE, ArgusParseTCPSrcBase, "int unsigned", 0, ""},
#define ARGUSPARSETCPDSTBASE		106
   { "dtcpb", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSETCPDSTBASE, ArgusParseTCPDstBase, "int unsigned", 0, ""},
#define ARGUSPARSETCPRTT		107
   { "tcprtt", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSETCPRTT, ArgusParseTCPRTT, "double", 0, ""},
#define ARGUSPARSEINODE   		108
   { "inode", "", 18, 1, ARGUS_PTYPE_STRING, ARGUSPARSEINODE, ArgusParseInode, "varchar(64)", 0, ""},
#define ARGUSPARSESTDDEV  		109
   { "stddev", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESTDDEV, ArgusParseStdDeviation, "double unsigned", 0, ""},
#define ARGUSPARSERELDATE		110
   { "rtime", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSERELDATE, ArgusParseRelativeDate, "double(18,6)", 0, ""},
#define ARGUSPARSEBYTEOFFSET		111
   { "offset", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSEBYTEOFFSET, ArgusParseByteOffset, "bigint", 0, ""},
#define ARGUSPARSESRCNET		112
   { "snet", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCNET, ArgusParseSrcNet, "varchar(64)", 0, ""},
#define ARGUSPARSEDSTNET		113
   { "dnet", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTNET, ArgusParseDstNet, "varchar(64)", 0, ""},
#define ARGUSPARSESRCDURATION		114
   { "sdur", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESRCDURATION, ArgusParseSrcDuration, "double", 0, ""},
#define ARGUSPARSEDSTDURATION		115
   { "ddur", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDSTDURATION, ArgusParseDstDuration, "double", 0, ""},
#define ARGUSPARSETCPSRCMAX		116
   { "stcpmax", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSETCPSRCMAX, ArgusParseTCPSrcMax, "double", 0, ""},
#define ARGUSPARSETCPDSTMAX		117
   { "dtcpmax", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSETCPDSTMAX, ArgusParseTCPDstMax, "double", 0, ""},
#define ARGUSPARSETCPSYNACK		118
   { "synack", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSETCPSYNACK, ArgusParseTCPSynAck, "double", 0, ""},
#define ARGUSPARSETCPACKDAT		119
   { "ackdat", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSETCPACKDAT, ArgusParseTCPAckDat, "double", 0, ""},
#define ARGUSPARSESRCSTARTDATE		120
   { "sstime", "%T.%f", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCSTARTDATE, ArgusParseSrcStartDate, "double(18,6) unsigned not null", 0, ""},
#define ARGUSPARSESRCLASTDATE		121
   { "sltime", "%T.%f", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCLASTDATE, ArgusParseSrcLastDate, "double(18,6) unsigned not null", 0, ""},
#define ARGUSPARSEDSTSTARTDATE		122
   { "dstime", "%T.%f", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTSTARTDATE, ArgusParseDstStartDate, "double(18,6) unsigned not null", 0, ""},
#define ARGUSPARSEDSTLASTDATE		123
   { "dltime", "%T.%f", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTLASTDATE, ArgusParseDstLastDate, "double(18,6) unsigned not null", 0, ""},
#define ARGUSPARSESRCENCAPS		124
   { "senc", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCENCAPS, ArgusParseSrcEncaps, "varchar(32)", 0, ""},
#define ARGUSPARSEDSTENCAPS		125
   { "denc", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTENCAPS, ArgusParseDstEncaps, "varchar(32)", 0, ""},
#define ARGUSPARSESRCPKTSIZE		126
   { "spktsz", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCPKTSIZE, ArgusParseSrcPktSize, "varchar(32)", 0, ""},
#define ARGUSPARSESRCMAXPKTSIZE		127
   { "smaxsz", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCMAXPKTSIZE, ArgusParseSrcMaxPktSize, "smallint unsigned", 0, ""},
#define ARGUSPARSESRCMINPKTSIZE		128
   { "sminsz", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCMINPKTSIZE, ArgusParseSrcMinPktSize, "smallint unsigned", 0, ""},
#define ARGUSPARSEDSTPKTSIZE		129
   { "dpktsz", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTPKTSIZE, ArgusParseDstPktSize, "varchar(32)", 0, ""},
#define ARGUSPARSEDSTMAXPKTSIZE		130
   { "dmaxsz", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTMAXPKTSIZE, ArgusParseDstMaxPktSize, "smallint unsigned", 0, ""},
#define ARGUSPARSEDSTMINPKTSIZE		131
   { "dminsz", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTMINPKTSIZE, ArgusParseDstMinPktSize, "smallint unsigned", 0, ""},
#define ARGUSPARSESRCCOUNTRYCODE	132
   { "sco", "", 3 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCCOUNTRYCODE, ArgusParseSrcCountryCode, "varchar(2)", 0, ""},
#define ARGUSPARSEDSTCOUNTRYCODE	133
   { "dco", "", 3 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTCOUNTRYCODE, ArgusParseDstCountryCode, "varchar(2)", 0, ""},
#define ARGUSPARSESRCHOPCOUNT		134
   { "shops", "", 5 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCHOPCOUNT, ArgusParseSrcHopCount, "smallint", 0, ""},
#define ARGUSPARSEDSTHOPCOUNT		135
   { "dhops", "", 5 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTHOPCOUNT, ArgusParseDstHopCount, "smallint", 0, ""},
#define ARGUSPARSEICMPID		136
   { "icmpid", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSEICMPID, ArgusParseIcmpId, "smallint unsigned", 0, ""},
#define ARGUSPARSELABEL			137
   { "label", "", 5 , 1, ARGUS_PTYPE_STRING, ARGUSPARSELABEL, ArgusParseLabel, "varchar(4098)", 0, ""},
#define ARGUSPARSESRCINTPKTDIST		138
   { "sintdist", "", 8, 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCINTPKTDIST, ArgusParseSrcIntPktDist, "varchar(8)", 0, ""},
#define ARGUSPARSEDSTINTPKTDIST		139
   { "dintdist", "", 8, 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTINTPKTDIST, ArgusParseDstIntPktDist, "varchar(8)", 0, ""},
#define ARGUSPARSEACTSRCINTPKTDIST	140
   { "sintdistact", "", 11, 1, ARGUS_PTYPE_STRING, ARGUSPARSEACTSRCINTPKTDIST, ArgusParseActiveSrcIntPktDist, "varchar(8)", 0, ""},
#define ARGUSPARSEACTDSTINTPKTDIST	141
   { "dintdistact", "", 11, 1, ARGUS_PTYPE_STRING, ARGUSPARSEACTDSTINTPKTDIST, ArgusParseActiveDstIntPktDist, "varchar(8)", 0, ""},
#define ARGUSPARSEIDLESRCINTPKTDIST	142
   { "sintdistidl", "", 11, 1, ARGUS_PTYPE_STRING, ARGUSPARSEIDLESRCINTPKTDIST, ArgusParseIdleSrcIntPktDist, "varchar(8)", 0, ""},
#define ARGUSPARSEIDLEDSTINTPKTDIST	143
   { "dintdistidl", "", 11, 1, ARGUS_PTYPE_STRING, ARGUSPARSEIDLEDSTINTPKTDIST, ArgusParseIdleDstIntPktDist, "varchar(8)", 0, ""},
#define ARGUSPARSERETRANS          	144
   { "retrans", "", 7, 1, ARGUS_PTYPE_INT, ARGUSPARSERETRANS, ArgusParseRetrans, "int", 0, ""},
#define ARGUSPARSESRCRETRANS          	145
   { "sretrans", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPARSESRCRETRANS, ArgusParseSrcRetrans, "int", 0, ""},
#define ARGUSPARSEDSTRETRANS          	146
   { "dretrans", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTRETRANS, ArgusParseDstRetrans, "int", 0, ""},
#define ARGUSPARSEPERCENTRETRANS        147
   { "pretrans", "", 7, 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTRETRANS, ArgusParsePercentRetrans, "double", 0, ""},
#define ARGUSPARSEPERCENTSRCRETRANS     148
   { "spretrans", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTSRCRETRANS, ArgusParsePercentSrcRetrans, "double", 0, ""},
#define ARGUSPARSEPERCENTDSTRETRANS     149
   { "dpretrans", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTDSTRETRANS, ArgusParsePercentDstRetrans, "double", 0, ""},
#define ARGUSPARSENACKS          	150
   { "nacks", "", 7, 1, ARGUS_PTYPE_INT, ARGUSPARSENACKS, ArgusParseNacks, "int", 0, ""},
#define ARGUSPARSESRCNACKS          	151
   { "snacks", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPARSESRCNACKS, ArgusParseSrcNacks, "int", 0, ""},
#define ARGUSPARSEDSTNACKS          	152
   { "dnacks", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTNACKS, ArgusParseDstNacks, "int", 0, ""},
#define ARGUSPARSEPERCENTNACKS		153
   { "pnacks", "", 7, 1, ARGUS_PTYPE_INT, ARGUSPARSEPERCENTNACKS, ArgusParsePercentNacks, "double", 0, ""},
#define ARGUSPARSEPERCENTSRCNACKS	154
   { "spnacks", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTSRCNACKS, ArgusParsePercentSrcNacks, "double", 0, ""},
#define ARGUSPARSEPERCENTDSTNACKS	155
   { "dpnacks", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTDSTNACKS, ArgusParsePercentDstNacks, "double", 0, ""},
#define ARGUSPARSESOLO          	156
   { "solo", "", 7, 1, ARGUS_PTYPE_INT, ARGUSPARSESOLO, ArgusParseSolo, "int", 0, ""},
#define ARGUSPARSESRCSOLO          	157
   { "ssolo", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPARSESRCSOLO, ArgusParseSrcSolo, "int", 0, ""},
#define ARGUSPARSEDSTSOLO          	158
   { "dsolo", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTSOLO, ArgusParseDstSolo, "int", 0, ""},
#define ARGUSPARSEPERCENTSOLO		159
   { "psolo", "", 7, 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTSOLO, ArgusParsePercentSolo, "double", 0, ""},
#define ARGUSPARSEPERCENTSRCSOLO	160
   { "spsolo", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTSRCSOLO, ArgusParsePercentSrcSolo, "double", 0, ""},
#define ARGUSPARSEPERCENTDSTSOLO	161
   { "dpsolo", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTDSTSOLO, ArgusParsePercentDstSolo, "double", 0, ""},
#define ARGUSPARSEFIRST          	162
   { "first", "", 7, 1, ARGUS_PTYPE_INT, ARGUSPARSEFIRST, ArgusParseFirst, "int", 0, ""},
#define ARGUSPARSESRCFIRST          	163
   { "sfirst", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPARSESRCFIRST, ArgusParseSrcFirst, "int", 0, ""},
#define ARGUSPARSEDSTFIRST          	164
   { "dfirst", "", 8, 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTFIRST, ArgusParseDstFirst, "int", 0, ""},
#define ARGUSPARSEPERCENTFIRST		165
   { "pfirst", "", 7, 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTFIRST, ArgusParsePercentFirst, "double", 0, ""},
#define ARGUSPARSEPERCENTSRCFIRST	166
   { "spfirst", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTSRCFIRST, ArgusParsePercentSrcFirst, "double", 0, ""},
#define ARGUSPARSEPERCENTDSTFIRST	167
   { "dpfirst", "", 8, 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPERCENTDSTFIRST, ArgusParsePercentDstFirst, "double", 0, ""},
#define ARGUSPARSEAUTOID		168
   { "autoid", "", 6, 1, ARGUS_PTYPE_INT, ARGUSPARSEAUTOID, ArgusParseAutoId, "int not null auto_increment", 0, ""},
#define ARGUSPARSESRCASN		169
   { "sas", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCASN, ArgusParseSrcAsn, "int unsigned", 0, ""},
#define ARGUSPARSEDSTASN		170
   { "das", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTASN, ArgusParseDstAsn, "int unsigned", 0, ""},
#define ARGUSPARSEINODEASN		171
   { "ias", "", 5 , 1, ARGUS_PTYPE_INT, ARGUSPARSEINODEASN, ArgusParseInodeAsn, "int unsigned", 0, ""},
#define ARGUSPARSECAUSE			172
   { "cause", "", 7 , 1, ARGUS_PTYPE_STRING, ARGUSPARSECAUSE, ArgusParseCause, "varchar(8)", 0, ""},
#define ARGUSPARSEBSSID			173
   { "bssid", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEBSSID, ArgusParseBssid, "varchar(24)", 0, ""},
#define ARGUSPARSESSID			174
   { "ssid", "", 9 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESSID, ArgusParseSsid, "varchar(32)", 0, ""},
#define ARGUSPARSEKEYSTROKENSTROKE      175
   { "nstroke", "", 9 , 1, ARGUS_PTYPE_INT, ARGUSPARSEKEYSTROKENSTROKE, ArgusParseKeyStrokeNStroke, "int unsigned", 0, ""},
#define ARGUSPARSEKEYSTROKESRCNSTROKE   176
   { "snstroke", "", 9 , 1, ARGUS_PTYPE_INT, ARGUSPARSEKEYSTROKESRCNSTROKE, ArgusParseKeyStrokeSrcNStroke, "int unsigned", 0, ""},
#define ARGUSPARSEKEYSTROKEDSTNSTROKE   177
   { "dnstroke", "", 9 , 1, ARGUS_PTYPE_INT, ARGUSPARSEKEYSTROKEDSTNSTROKE, ArgusParseKeyStrokeDstNStroke, "int unsigned", 0, ""},
#define ARGUSPARSESRCMEANPKTSIZE        178
   { "smeansz", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCMEANPKTSIZE, ArgusParseSrcMeanPktSize, "smallint unsigned", 0, ""},
#define ARGUSPARSEDSTMEANPKTSIZE        179
   { "dmeansz", "", 12 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTMEANPKTSIZE, ArgusParseDstMeanPktSize, "smallint unsigned", 0, ""},
#define ARGUSPARSERANK			180
   { "rank", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSERANK, ArgusParseRank, "int unsigned", 0, ""},
#define ARGUSPARSESUM                   181
   { "sum", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESUM, ArgusParseSum, "double", 0, ""},
#define ARGUSPARSERUN                   182
   { "runtime", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSERUN, ArgusParseRunTime, "double", 0, ""},
#define ARGUSPARSEIDLETIME              183
   { "idle", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEIDLETIME, ArgusParseIdleTime, "double", 0, ""},
#define ARGUSPARSETCPOPTIONS            184
   { "tcpopt", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSETCPOPTIONS, ArgusParseTCPOptions, "varchar(12)", 0, ""},
#define ARGUSPARSERESPONSE              185
   { "resp", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSERESPONSE, ArgusParseResponse, "varchar(12)", 0, ""},
#define ARGUSPARSETCPSRCGAP		186
   { "sgap", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPARSETCPSRCGAP, ArgusParseSrcGap, "int unsigned", 0, ""},
#define ARGUSPARSETCPDSTGAP		187
   { "dgap", "", 8 , 1, ARGUS_PTYPE_INT, ARGUSPARSETCPDSTGAP, ArgusParseDstGap, "int unsigned", 0, ""},
#define ARGUSPARSESRCOUI   		188
   { "soui", "", 9 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCOUI, ArgusParseSrcOui, "varchar(9)", 0, ""},
#define ARGUSPARSEDSTOUI   		189
   { "doui", "", 9 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTOUI, ArgusParseDstOui, "varchar(9)", 0, ""},
#define ARGUSPARSECOR   		190
   { "cor", "", 12 , 1, ARGUS_PTYPE_STRING, ARGUSPARSECOR, ArgusParseCor, "varchar(12)", 0, ""},
#define ARGUSPARSELOCALADDR             191
   { "laddr", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPARSELOCALADDR, ArgusParseLocalAddr, "varchar(64) not null", 0, ""},
#define ARGUSPARSEREMOTEADDR            192
   { "raddr", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEREMOTEADDR, ArgusParseRemoteAddr, "varchar(64) not null", 0, ""},
#define ARGUSPARSELOCALNET              193
   { "lnet", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPARSELOCALADDR, ArgusParseLocalNet, "varchar(64) not null", 0, ""},
#define ARGUSPARSEREMOTENET             194
   { "rnet", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEREMOTEADDR, ArgusParseRemoteNet, "varchar(64) not null", 0, ""},
#define ARGUSPARSEAPPBYTERATIO          195
   { "abr", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEAPPBYTERATIO, ArgusParseAppByteRatio, "double", 0, ""},
#define ARGUSPARSEPRODUCERCONSUMERRATIO 196
   { "pcr", "", 10 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEPRODUCERCONSUMERRATIO, ArgusParseProducerConsumerRatio, "double", 0, ""},
#define ARGUSPARSETRANSEFFICIENCY       197
   { "tf", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSETRANSEFFICIENCY, ArgusParseTransEfficiency, "double", 0, ""},
#define ARGUSPARSESRCTRANSEFFICIENCY    198
   { "stf", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESRCTRANSEFFICIENCY, ArgusParseSrcTransEfficiency, "double", 0, ""},
#define ARGUSPARSEDSTTRANSEFFICIENCY    199
   { "dtf", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDSTTRANSEFFICIENCY, ArgusParseDstTransEfficiency, "double", 0, ""},
#define ARGUSPARSEINODECOUNTRYCODE	200
   { "ico", "", 3 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEINODECOUNTRYCODE, ArgusParseInodeCountryCode, "varchar(2)", 0, ""},
#define ARGUSPARSESRCLATITUDE		201
   { "slat", "", 3 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESRCLATITUDE, ArgusParseSrcLatitude, "double", 0, ""},
#define ARGUSPARSESRCLONGITUDE		202
   { "slon", "", 3 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESRCLONGITUDE, ArgusParseSrcLongitude, "double", 0, ""},
#define ARGUSPARSEDSTLATITUDE		203
   { "dlat", "", 3 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDSTLATITUDE, ArgusParseDstLatitude, "double", 0, ""},
#define ARGUSPARSEDSTLONGITUDE		204
   { "dlon", "", 3 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEDSTLONGITUDE, ArgusParseDstLongitude, "double", 0, ""},
#define ARGUSPARSEINODELATITUDE		205
   { "ilat", "", 3 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEINODELATITUDE, ArgusParseInodeLatitude, "double", 0, ""},
#define ARGUSPARSEINODELONGITUDE	206
   { "ilon", "", 3 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEINODELONGITUDE, ArgusParseInodeLongitude, "double", 0, ""},
#define ARGUSPARSESRCLOCAL		207
   { "sloc", "", 3 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCLOCAL, ArgusParseSrcLocal, "tinyint unsigned", 0, ""},
#define ARGUSPARSEDSTLOCAL		208
   { "dloc", "", 3 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTLOCAL, ArgusParseDstLocal, "tinyint unsigned", 0, ""},
#define ARGUSPARSELOCAL			209
   { "loc", "", 3 , 1, ARGUS_PTYPE_INT, ARGUSPARSELOCAL, ArgusParseLocal, "tinyint unsigned", 0, ""},
#define ARGUSPARSESID			210
   { "sid", "", 18 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESID, ArgusParseSID, "varchar(64)", 0, ""},
#define ARGUSPARSENODE			211
   { "node", "", 8 , 1, ARGUS_PTYPE_STRING, ARGUSPARSENODE, ArgusParseNode, "varchar(64)", 0, ""},
#define ARGUSPARSEINF			212
   { "inf", "", 4 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEINF, ArgusParseInf, "varchar(4)", 0, ""},
#define ARGUSPARSESTATUS		213
   { "status", "", 4 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESTATUS, ArgusParseStatus, "varchar(8)", 0, ""},
#define ARGUSPARSESRCGROUP		214
   { "sgrp", "", 4 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCGROUP, ArgusParseSrcGroup, "varchar(64)", 0, ""},
#define ARGUSPARSEDSTGROUP		215
   { "dgrp", "", 4 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTGROUP, ArgusParseDstGroup, "varchar(64)", 0, ""},
#define ARGUSPARSEHASHREF		216
   { "hash", "", 4 , 1, ARGUS_PTYPE_UINT, ARGUSPARSEHASHREF, ArgusParseHashRef, "int unsigned", 0, ""},
#define ARGUSPARSEHASHINDEX		217
   { "ind", "", 4 , 1, ARGUS_PTYPE_UINT, ARGUSPARSEHASHINDEX, ArgusParseHashIndex, "int unsigned", 0, ""},
#define ARGUSPARSESCORE			218
   { "score", "%d", 5 , 1, ARGUS_PTYPE_INT, ARGUSPARSESCORE, ArgusParseScore, "tinyint", 0, ""},
#define ARGUSPARSESRCNAME		219
   { "sname", "%s", 16 , 1, ARGUS_PTYPE_STRING, ARGUSPARSESRCNAME, ArgusParseSrcName, "varchar(64)", 0, ""},
#define ARGUSPARSEDSTNAME		220
   { "dname", "%s", 16 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEDSTNAME, ArgusParseDstName, "varchar(64)", 0, ""},
#define ARGUSPARSEETHERTYPE		221
   { "etype", "%u", 8 , 1, ARGUS_PTYPE_STRING, ARGUSPARSEETHERTYPE, ArgusParseEtherType, "varchar(32)", 0, ""},
#define ARGUSPARSEMEANIDLE		222
   { "idlemean", "%u", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEMEANIDLE, ArgusParseIdleMean, "double unsigned", 0, ""},
#define ARGUSPARSEMINIDLE		223
   { "idlemin", "%u", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEMINIDLE, ArgusParseIdleMin, "double unsigned", 0, ""},
#define ARGUSPARSEMAXIDLE		224
   { "idlemax", "%u", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEMAXIDLE, ArgusParseIdleMax, "double unsigned", 0, ""},
#define ARGUSPARSESTDDEVIDLE  		225
   { "idlestddev", "%u", 8 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSESTDDEVIDLE, ArgusParseIdleStdDeviation, "double unsigned", 0, ""},
#define ARGUSPARSESRCMAXSEG  		226
   { "smss", "%d", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCMAXSEG, ArgusParseSrcMaxSeg, "tinyint unsigned", 0, ""},
#define ARGUSPARSEDSTMAXSEG  		227
   { "dmss", "%d", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTMAXSEG, ArgusParseDstMaxSeg, "tinyint unsigned", 0, ""},
#define ARGUSPARSEINTFLOW		228
   { "intflow", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEINTFLOW, ArgusParseIntFlow, "double", 0, ""},
#define ARGUSPARSEACTINTFLOW            229
   { "actintflow", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEACTINTFLOW, NULL, "double", 0, ""},
#define ARGUSPARSEIDLEINTFLOW           230
   { "idleintflow", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEIDLEINTFLOW, NULL, "double", 0, ""},
#define ARGUSPARSEINTFLOWMAX		231
   { "intflowmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEINTFLOWMAX, ArgusParseIntFlowMax, "double", 0, ""},
#define ARGUSPARSEINTFLOWMIN		232
   { "intflowmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEINTFLOWMIN, ArgusParseIntFlowMin, "double", 0, ""},
#define ARGUSPARSEINTFLOWSDEV		233
   { "intflowsdev", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEINTFLOWSDEV, ArgusParseIntFlowStdDev, "double", 0, ""},
#define ARGUSPARSEACTINTFLOWMAX         234
   { "actintflowmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEACTINTFLOWMAX, NULL, "double", 0, ""},
#define ARGUSPARSEACTINTFLOWMIN         235
   { "actintflowmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEACTINTFLOWMIN, NULL, "double", 0, ""},
#define ARGUSPARSEACTINTFLOWSDEV        236
   { "actintflowsdev", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEACTINTFLOWSDEV, NULL, "double", 0, ""},
#define ARGUSPARSEIDLEINTFLOWMAX        237
   { "idleintflowmax", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEIDLEINTFLOWMAX, NULL, "double", 0, ""},
#define ARGUSPARSEIDLEINTFLOWMIN        238
   { "idleintflowmin", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEIDLEINTFLOWMIN, NULL, "double", 0, ""},
#define ARGUSPARSEIDLEINTFLOWSDEV       239
   { "idleintflowsdev", "", 12 , 1, ARGUS_PTYPE_DOUBLE, ARGUSPARSEIDLEINTFLOWSDEV, NULL, "double", 0, ""},
#define ARGUSPARSESRCVNID		240
   { "svnid", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSESRCVNID, ArgusParseSrcVirtualNID, "int", 0, ""},
#define ARGUSPARSEDSTVNID		241
   { "dvnid", "", 6 , 1, ARGUS_PTYPE_INT, ARGUSPARSEDSTVNID, ArgusParseDstVirtualNID, "int", 0, ""},
#define ARGUSPARSETYPE			242
   { "type", "", 6 , 1, ARGUS_PTYPE_STRING, ARGUSPARSETYPE, ArgusParseType, "varchar(4)", 0, "Type"},
};

extern struct ArgusTokenStruct llcsap_db[];
#endif
