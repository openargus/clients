/*
 * Argus Software
 * Copyright (c) 2000-2022 QoSient, LLC
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
 * $Id: //depot/argus/clients/examples/raconvert/raconvert.h#5 $
 * $DateTime: 2014/05/12 10:49:40 $
 * $Change: 2818 $
 */

#ifndef Rascii_h
#define Rascii_h

#include <argus_json.h>

void ArgusParseRankLabel (struct ArgusParserStruct *, char *);
void ArgusParseAutoIdLabel (struct ArgusParserStruct *, char *);
void ArgusParseStartDateLabel (struct ArgusParserStruct *, char *);
void ArgusParseLastDateLabel (struct ArgusParserStruct *, char *);
void ArgusParseSourceIDLabel (struct ArgusParserStruct *, char *);
void ArgusParseFlagsLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcMacAddressLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstMacAddressLabel (struct ArgusParserStruct *, char *);
void ArgusParseMacAddressLabel (struct ArgusParserStruct *, char *);
void ArgusParseProtoLabel (struct ArgusParserStruct *, char *);
void ArgusParseAddrLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcNetLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcAddrLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstNetLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstAddrLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcPortLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstPortLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcIpIdLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstIpIdLabel (struct ArgusParserStruct *, char *);
void ArgusParseIpIdLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcTtlLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstTtlLabel (struct ArgusParserStruct *, char *);
void ArgusParseTtlLabel (struct ArgusParserStruct *, char *);
void ArgusParseDirLabel (struct ArgusParserStruct *, char *);
void ArgusParsePacketsLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcPacketsLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstPacketsLabel (struct ArgusParserStruct *, char *);

void ArgusParseBytesLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcBytesLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstBytesLabel (struct ArgusParserStruct *, char *);

void ArgusParseAppBytesLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcAppBytesLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstAppBytesLabel (struct ArgusParserStruct *, char *);

void ArgusParseSrcPktSizeLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstPktSizeLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcPktSizeMaxLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcPktSizeMinLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstPktSizeMaxLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstPktSizeMinLabel (struct ArgusParserStruct *, char *);

void ArgusParseSrcIntPktLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstIntPktLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcIntPktMaxLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcIntPktMinLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstIntPktMaxLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstIntPktMinLabel (struct ArgusParserStruct *, char *);

void ArgusParseSrcIntPktActiveLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcIntPktActiveMaxLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcIntPktActiveMinLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstIntPktActiveLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstIntPktActiveMaxLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstIntPktActiveMinLabel (struct ArgusParserStruct *, char *);

void ArgusParseSrcIntPktIdleLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcIntPktIdleMaxLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcIntPktIdleMinLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstIntPktIdleLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstIntPktIdleMaxLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstIntPktIdleMinLabel (struct ArgusParserStruct *, char *);

void ArgusParseJitterLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcJitterLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstJitterLabel (struct ArgusParserStruct *, char *);
void ArgusParseActiveJitterLabel (struct ArgusParserStruct *, char *);
void ArgusParseActiveSrcJitterLabel (struct ArgusParserStruct *, char *);
void ArgusParseActiveDstJitterLabel (struct ArgusParserStruct *, char *);
void ArgusParseIdleJitterLabel (struct ArgusParserStruct *, char *);
void ArgusParseIdleSrcJitterLabel (struct ArgusParserStruct *, char *);
void ArgusParseIdleDstJitterLabel (struct ArgusParserStruct *, char *);
void ArgusParseStateLabel (struct ArgusParserStruct *, char *);
void ArgusParseDeltaDurationLabel (struct ArgusParserStruct *, char *);
void ArgusParseDeltaStartTimeLabel (struct ArgusParserStruct *, char *);
void ArgusParseDeltaLastTimeLabel (struct ArgusParserStruct *, char *);
void ArgusParseDeltaSrcPktsLabel (struct ArgusParserStruct *, char *);
void ArgusParseDeltaDstPktsLabel (struct ArgusParserStruct *, char *);
void ArgusParseDeltaSrcBytesLabel (struct ArgusParserStruct *, char *);
void ArgusParseDeltaDstBytesLabel (struct ArgusParserStruct *, char *);
void ArgusParsePercentDeltaSrcPktsLabel (struct ArgusParserStruct *, char *);
void ArgusParsePercentDeltaDstPktsLabel (struct ArgusParserStruct *, char *);
void ArgusParsePercentDeltaSrcBytesLabel (struct ArgusParserStruct *, char *);
void ArgusParsePercentDeltaDstBytesLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcUserDataLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstUserDataLabel (struct ArgusParserStruct *, char *);
void ArgusParseUserDataLabel (struct ArgusParserStruct *, char *);
void ArgusParseTCPExtensionsLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcLoadLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstLoadLabel (struct ArgusParserStruct *, char *);
void ArgusParseLoadLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcLossLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstLossLabel (struct ArgusParserStruct *, char *);
void ArgusParseLossLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcPercentLossLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstPercentLossLabel (struct ArgusParserStruct *, char *);
void ArgusParsePercentLossLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcRateLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstRateLabel (struct ArgusParserStruct *, char *);
void ArgusParseRateLabel (struct ArgusParserStruct *, char *);
void ArgusParseTosLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcTosLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstTosLabel (struct ArgusParserStruct *, char *);
void ArgusParseDSByteLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcDSByteLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstDSByteLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcVLANLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstVLANLabel (struct ArgusParserStruct *, char *);
void ArgusParseVLANLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcVIDLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstVIDLabel (struct ArgusParserStruct *, char *);
void ArgusParseVIDLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcVPRILabel (struct ArgusParserStruct *, char *);
void ArgusParseDstVPRILabel (struct ArgusParserStruct *, char *);
void ArgusParseVPRILabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcMplsLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstMplsLabel (struct ArgusParserStruct *, char *);
void ArgusParseMplsLabel (struct ArgusParserStruct *, char *);
void ArgusParseWindowLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcWindowLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstWindowLabel (struct ArgusParserStruct *, char *);
void ArgusParseJoinDelayLabel (struct ArgusParserStruct *, char *);
void ArgusParseLeaveDelayLabel (struct ArgusParserStruct *, char *);
void ArgusParseMeanLabel (struct ArgusParserStruct *, char *);
void ArgusParseMaxLabel (struct ArgusParserStruct *, char *);
void ArgusParseMinLabel (struct ArgusParserStruct *, char *);
void ArgusParseStartRangeLabel (struct ArgusParserStruct *, char *);
void ArgusParseEndRangeLabel (struct ArgusParserStruct *, char *);
void ArgusParseDurationLabel (struct ArgusParserStruct *, char *);
void ArgusParseTransactionsLabel (struct ArgusParserStruct *, char *);
void ArgusParseSequenceNumberLabel (struct ArgusParserStruct *, char *);
void ArgusParseBinNumberLabel (struct ArgusParserStruct *, char *);
void ArgusParseBinsLabel (struct ArgusParserStruct *, char *);
void ArgusParseServiceLabel (struct ArgusParserStruct *, char *);
void ArgusParseTCPBaseLabel (struct ArgusParserStruct *, char *);
void ArgusParseTCPSrcBaseLabel (struct ArgusParserStruct *, char *);
void ArgusParseTCPDstBaseLabel (struct ArgusParserStruct *, char *);
void ArgusParseTCPRTTLabel (struct ArgusParserStruct *, char *);
void ArgusParseLabelLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcTcpFlagsLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstTcpFlagsLabel (struct ArgusParserStruct *, char *);
void ArgusParseSrcCountryCodeLabel (struct ArgusParserStruct *, char *);
void ArgusParseDstCountryCodeLabel (struct ArgusParserStruct *, char *);


#define MAX_PARSE_ALG_TYPES	122

void (*RaParseLabelAlgorithmTable[MAX_PARSE_ALG_TYPES])(struct ArgusParserStruct *, char *) = {
   ArgusParseRankLabel,
   ArgusParseAutoIdLabel,
   ArgusParseStartDateLabel,
   ArgusParseLastDateLabel,
   ArgusParseTransactionsLabel,
   ArgusParseDurationLabel,
   ArgusParseMeanLabel,
   ArgusParseMinLabel,
   ArgusParseMaxLabel,
   ArgusParseSrcAddrLabel,
   ArgusParseSrcAddrLabel,
   ArgusParseDstAddrLabel,
   ArgusParseProtoLabel,
   ArgusParseSrcPortLabel,
   ArgusParseDstPortLabel,
   ArgusParseSrcTosLabel,
   ArgusParseDstTosLabel,
   ArgusParseSrcDSByteLabel,
   ArgusParseDstDSByteLabel,
   ArgusParseSrcTtlLabel,
   ArgusParseDstTtlLabel,
   ArgusParseBytesLabel,
   ArgusParseSrcBytesLabel,
   ArgusParseDstBytesLabel,
   ArgusParseAppBytesLabel,
   ArgusParseSrcAppBytesLabel,
   ArgusParseDstAppBytesLabel,
   ArgusParsePacketsLabel,
   ArgusParseSrcPacketsLabel,
   ArgusParseSrcPacketsLabel,
   ArgusParseDstPacketsLabel,
   ArgusParseDstPacketsLabel,
   ArgusParseLoadLabel,
   ArgusParseSrcLoadLabel,
   ArgusParseDstLoadLabel,
   ArgusParseLossLabel,
   ArgusParseSrcLossLabel,
   ArgusParseDstLossLabel,
   ArgusParsePercentLossLabel,
   ArgusParseSrcPercentLossLabel,
   ArgusParseDstPercentLossLabel,
   ArgusParseRateLabel,
   ArgusParseSrcRateLabel,
   ArgusParseDstRateLabel,
   ArgusParseSourceIDLabel,
   ArgusParseFlagsLabel,
   ArgusParseSrcMacAddressLabel,
   ArgusParseSrcMacAddressLabel,
   ArgusParseDstMacAddressLabel,
   ArgusParseDirLabel,
   ArgusParseSrcIntPktLabel,
   ArgusParseDstIntPktLabel,
   ArgusParseSrcIntPktActiveLabel,
   ArgusParseDstIntPktActiveLabel,
   ArgusParseSrcIntPktIdleLabel,
   ArgusParseDstIntPktIdleLabel,
   ArgusParseSrcIntPktMaxLabel,
   ArgusParseSrcIntPktMinLabel,
   ArgusParseDstIntPktMaxLabel,
   ArgusParseDstIntPktMinLabel,
   ArgusParseSrcIntPktActiveMaxLabel,
   ArgusParseSrcIntPktActiveMinLabel,
   ArgusParseDstIntPktActiveMaxLabel,
   ArgusParseDstIntPktActiveMinLabel,
   ArgusParseSrcIntPktIdleMaxLabel,
   ArgusParseSrcIntPktIdleMinLabel,
   ArgusParseDstIntPktIdleMaxLabel,
   ArgusParseDstIntPktIdleMinLabel,
   NULL,

   ArgusParseSrcJitterLabel,
   ArgusParseDstJitterLabel,
   ArgusParseActiveSrcJitterLabel,
   ArgusParseActiveDstJitterLabel,
   ArgusParseIdleSrcJitterLabel,
   ArgusParseIdleDstJitterLabel,

   ArgusParseStateLabel,
   ArgusParseDeltaDurationLabel,
   ArgusParseDeltaStartTimeLabel,
   ArgusParseDeltaLastTimeLabel,
   ArgusParseDeltaSrcPktsLabel,
   ArgusParseDeltaDstPktsLabel,
   ArgusParseDeltaSrcBytesLabel,
   ArgusParseDeltaDstBytesLabel,
   ArgusParsePercentDeltaSrcPktsLabel,
   ArgusParsePercentDeltaDstPktsLabel,
   ArgusParsePercentDeltaSrcBytesLabel,
   ArgusParsePercentDeltaDstBytesLabel,
   ArgusParseSrcUserDataLabel,
   ArgusParseDstUserDataLabel,
   ArgusParseTCPExtensionsLabel,
   ArgusParseSrcWindowLabel,
   ArgusParseDstWindowLabel,
   ArgusParseJoinDelayLabel,
   ArgusParseLeaveDelayLabel,
   ArgusParseSequenceNumberLabel,
   ArgusParseBinsLabel,
   ArgusParseBinNumberLabel,
   ArgusParseSrcMplsLabel,
   ArgusParseDstMplsLabel,
   ArgusParseSrcVLANLabel,
   ArgusParseDstVLANLabel,
   ArgusParseSrcVIDLabel,
   ArgusParseDstVIDLabel,
   ArgusParseSrcVPRILabel,
   ArgusParseDstVPRILabel,
   ArgusParseSrcIpIdLabel,
   ArgusParseDstIpIdLabel,
   ArgusParseStartRangeLabel,
   ArgusParseEndRangeLabel,
   ArgusParseServiceLabel,
   ArgusParseTCPSrcBaseLabel,
   ArgusParseTCPDstBaseLabel,
   ArgusParseTCPRTTLabel,
   ArgusParseSrcPktSizeMaxLabel,
   ArgusParseSrcPktSizeMinLabel,
   ArgusParseDstPktSizeMaxLabel,
   ArgusParseDstPktSizeMinLabel,
   ArgusParseLabelLabel,
   ArgusParseSrcTcpFlagsLabel,
   ArgusParseDstTcpFlagsLabel,
   ArgusParseSrcCountryCodeLabel,
   ArgusParseDstCountryCodeLabel,
};


char *RaParseLabelStringTable[MAX_PARSE_ALG_TYPES] = {
   "Rank",
   "AutoId",
   "StartTime",
   "LastTime",
   "Trans",
   "Dur",
   "Mean",
   "Min",
   "Max",
   "Host",
   "SrcAddr",
   "DstAddr",
   "Proto",
   "Sport",
   "Dport",
   "sTos",
   "dTos",
   "sDSb",
   "dDSb",
   "sTtl",
   "dTtl",
   "TotBytes",
   "SrcBytes",
   "DstBytes",
   "AppBytes",
   "SrcAppBytes",
   "DstAppBytes",
   "TotPkts",
   "SrcPkts",
   "OutPkts",
   "DstPkts",
   "InPkts",
   "Load",
   "SrcLoad",
   "DstLoad",
   "Loss",
   "SrcLoss",
   "DstLoss",
   "pLoss",
   "pSrcLoss",
   "pDstLoss",
   "Rate",
   "SrcRate",
   "DstRate",
   "SrcId",
   "Flgs",
   "Mac",
   "SrcMac",
   "DstMac",
   "Dir",
   "SrcIntPkt",
   "DstIntPkt",
   "SrcIntPktAct",
   "DstIntPktAct",
   "SrcIntPktIdl",
   "DstIntPktIdl",
   "SrcIntPktMax",
   "SrcIntPktMin",
   "DstIntPktMax",
   "DstIntPktMin",
   "SrcIntPktActMax",
   "SrcIntPktActMin",
   "DstIntPktActMax",
   "DstIntPktActMin",
   "SrcIntPktIdlMax",
   "SrcIntPktIdlMin",
   "DstIntPktIdlMax",
   "DstIntPktIdlMin",
   "xxx",
   "SrcJitter",
   "DstJitter",
   "ActSrcJitter",
   "ActDstJitter",
   "IdlSrcJitter",
   "IdlDstJitter",

   "State",
   "dDur",
   "dsTime",
   "dlTime",
   "dsPkts",
   "ddPkts",
   "dsBytes",
   "ddBytes",
   "pdsPkt",

   "pddPkt",
   "pdsByte",
   "pddByte",
   "srcUdata",
   "dstUdata",
   "tcpExt",
   "SrcWin",
   "DstWin",
   "JDelay",
   "LDelay",
   "Seq",
   "Bins",
   "Bin",
   "sMpls",
   "dMpls",
   "sVlan",
   "dVlan",
   "sVid",
   "dVid",
   "sVpri",
   "dVpri",
   "sIpId",
   "dIpId",
   "sRange",
   "eRange",
   "Service",
   "SrcTCPBase",
   "DstTCPBase",
   "TcpRtt",
   "sMaxSz",
   "sMinSz",
   "dMaxSz",
   "dMinSz",
   "Label",
   "sTcpF",
   "dTcpF",
   "sCo",
   "dCo",
};

extern struct ArgusTokenStruct llcsap_db[];
#endif
