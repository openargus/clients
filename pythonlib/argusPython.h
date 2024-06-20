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

#ifndef __SWIG_ARGUSPARSETIME_H
# define __SWIG_ARGUSPARSETIME_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif

#include "argus_int.h"
#include "argus_util.h"

void ArgusDebug (int d, char *fmt, ...);
int argustime (char *time_string, int *start, int *end);
PyObject *argus_critic(PyObject *y_true, PyObject *y_pred);
PyObject *argus_match(PyObject *y_true);

struct RaCursesProcessStruct {
   int status, timeout;
   int value, size;
   struct ArgusRecordStruct *ns;
   struct ArgusQueueStruct *queue, *delqueue;
   struct ArgusHashTable *htable;
   struct nff_program filter;
};

#if defined(argusPython)

#ifndef Raconvert_h
#define Raconvert_h

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

double ArgusCompareStartDate (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareLastDate (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSourceID (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareFlags (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcMacAddress (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstMacAddress (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareMacAddress (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareProto (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareAddr (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcNet (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcAddr (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstNet (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstAddr (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcPort (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstPort (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcIpId (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstIpId (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareIpId (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcTtl (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstTtl (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareTtl (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDir (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusComparePackets (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcPackets (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstPackets (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

double ArgusCompareBytes (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcBytes (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstBytes (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

double ArgusCompareAppBytes (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcAppBytes (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstAppBytes (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

double ArgusCompareSrcPktSize (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstPktSize (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcPktSizeMax (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcPktSizeMin (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstPktSizeMax (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstPktSizeMin (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

double ArgusCompareSrcIntPkt (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstIntPkt (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcIntPktMax (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcIntPktMin (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstIntPktMax (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstIntPktMin (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

double ArgusCompareSrcIntPktActive (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcIntPktActiveMax (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcIntPktActiveMin (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstIntPktActive (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstIntPktActiveMax (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstIntPktActiveMin (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

double ArgusCompareSrcIntPktIdle (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcIntPktIdleMax (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcIntPktIdleMin (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstIntPktIdle (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstIntPktIdleMax (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstIntPktIdleMin (struct ArgusRecordStruct *, struct ArgusRecordStruct *);

double ArgusCompareJitter (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcJitter (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstJitter (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareActiveJitter (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareActiveSrcJitter (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareActiveDstJitter (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareIdleJitter (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareIdleSrcJitter (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareIdleDstJitter (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareState (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDeltaDuration (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDeltaStartTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDeltaLastTime (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDeltaSrcPkts (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDeltaDstPkts (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDeltaSrcBytes (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDeltaDstBytes (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusComparePercentDeltaSrcPkts (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusComparePercentDeltaDstPkts (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusComparePercentDeltaSrcBytes (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusComparePercentDeltaDstBytes (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcUserData (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstUserData (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareUserData (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareTCPExtensions (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcLoad (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstLoad (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareLoad (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcPercentLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstPercentLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusComparePercentLoss (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcRate (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstRate (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareRate (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareTos (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcTos (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstTos (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDSByte (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcDSByte (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstDSByte (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcVLAN (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstVLAN (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareVLAN (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcVID (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstVID (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareVID (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcVPRI (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstVPRI (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareVPRI (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcMpls (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstMpls (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareMpls (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareWindow (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSrcWindow (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDstWindow (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareJoinDelay (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareLeaveDelay (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareMean (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareMax (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareMin (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareStartRange (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareEndRange (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareDuration (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareTransactions (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareSequenceNumber (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareBinNumber (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareBins (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareService (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareTCPBase (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareTCPSrcBase (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareTCPDstBase (struct ArgusRecordStruct *, struct ArgusRecordStruct *);
double ArgusCompareTCPRTT (struct ArgusRecordStruct *, struct ArgusRecordStruct *);


#define MAX_PARSE_ALG_TYPES	115

#define ARGUSPARSESTARTDATELABEL		0
#define ARGUSPARSELASTDATELABEL			1
#define ARGUSPARSETRANSACTIONSLABEL		2
#define ARGUSPARSEDURATIONLABEL			3
#define ARGUSPARSEMEANLABEL			4
#define ARGUSPARSEMINLABEL			5
#define ARGUSPARSEMAXLABEL			6
#define ARGUSPARSEADDRLABEL			7
#define ARGUSPARSESRCADDRLABEL			8
#define ARGUSPARSEDSTADDRLABEL			9
#define ARGUSPARSEPROTOLABEL			10
#define ARGUSPARSESRCPORTLABEL			11
#define ARGUSPARSEDSTPORTLABEL			12
#define ARGUSPARSESRCTOSLABEL			13
#define ARGUSPARSEDSTTOSLABEL			14
#define ARGUSPARSESRCDSBYTELABEL		15
#define ARGUSPARSEDSTDSBYTELABEL		16
#define ARGUSPARSESRCTTLLABEL			17
#define ARGUSPARSEDSTTTLLABEL			18
#define ARGUSPARSEBYTESLABEL			19
#define ARGUSPARSESRCBYTESLABEL			20
#define ARGUSPARSEDSTBYTESLABEL			21
#define ARGUSPARSEAPPBYTESLABEL			22
#define ARGUSPARSESRCAPPBYTESLABEL		23
#define ARGUSPARSEDSTAPPBYTESLABEL		24
#define ARGUSPARSETOTALPACKETSLABEL		25
#define ARGUSPARSESRCPACKETSLABEL		26
#define ARGUSPARSEOUTPACKETSLABEL		27
#define ARGUSPARSEDSTPACKETSLABEL		28
#define ARGUSPARSEINPACKETSLABEL		29
#define ARGUSPARSELOADLABEL			30
#define ARGUSPARSESRCLOADLABEL			31
#define ARGUSPARSEDSTLOADLABEL			32
#define ARGUSPARSELOSSLABEL			33
#define ARGUSPARSESRCLOSSLABEL			34
#define ARGUSPARSEDSTLOSSLABEL			35
#define ARGUSPARSEPERCENTLOSSLABEL		36
#define ARGUSPARSESRCPERCENTLOSSLABEL		37
#define ARGUSPARSEDSTPERCENTLOSSLABEL		38
#define ARGUSPARSERATELABEL			39
#define ARGUSPARSESRCRATELABEL			40
#define ARGUSPARSEDSTRATELABEL			41
#define ARGUSPARSESOURCEIDLABEL			42
#define ARGUSPARSEFLAGSLABEL			43
#define ARGUSPARSEMACADDRESSLABEL		44
#define ARGUSPARSESRCMACADDRESSLABEL		45
#define ARGUSPARSEDSTMACADDRESSLABEL		46
#define ARGUSPARSEDIRLABEL			47
#define ARGUSPARSESRCINTPKTLABEL		48
#define ARGUSPARSEDSTINTPKTLABEL		49
#define ARGUSPARSESRCINTPKTACTIVELABEL		50
#define ARGUSPARSEDSTINTPKTACTIVELABEL		51
#define ARGUSPARSESRCINTPKTIDLELABEL		52
#define ARGUSPARSEDSTINTPKTIDLELABEL		53
#define ARGUSPARSESRCINTPKTMAXLABEL		54
#define ARGUSPARSESRCINTPKTMINLABEL		55
#define ARGUSPARSEDSTINTPKTMAXLABEL		56
#define ARGUSPARSEDSTINTPKTMINLABEL		57
#define ARGUSPARSESRCINTPKTACTIVEMAXLABEL	58
#define ARGUSPARSESRCINTPKTACTIVEMINLABEL	59
#define ARGUSPARSEDSTINTPKTACTIVEMAXLABEL	60
#define ARGUSPARSEDSTINTPKTACTIVEMINLABEL	61
#define ARGUSPARSESRCINTPKTIDLEMAXLABEL		62
#define ARGUSPARSESRCINTPKTIDLEMINLABEL		63
#define ARGUSPARSEDSTINTPKTIDLEMAXLABEL		64
#define ARGUSPARSEDSTINTPKTIDLEMINLABEL		65

#define ARGUSPARSESRCJITTERLABEL		67
#define ARGUSPARSEDSTJITTERLABEL		68
#define ARGUSPARSEACTIVESRCJITTERLABEL		69
#define ARGUSPARSEACTIVEDSTJITTERLABEL		70
#define ARGUSPARSEIDLESRCJITTERLABEL		71
#define ARGUSPARSEIDLEDSTJITTERLABEL		72
#define ARGUSPARSESTATELABEL			73
#define ARGUSPARSEDELTADURATIONLABEL		74
#define ARGUSPARSEDELTASTARTTIMELABEL		75
#define ARGUSPARSEDELTALASTTIMELABEL		76
#define ARGUSPARSEDELTASRCPKTSLABEL		77
#define ARGUSPARSEDELTADSTPKTSLABEL		78
#define ARGUSPARSEDELTASRCBYTESLABEL		79
#define ARGUSPARSEDELTADSTBYTESLABEL		80
#define ARGUSPARSEPERCENTDELTASRCPKTSLABEL	81
#define ARGUSPARSEPERCENTDELTADSTPKTSLABEL	82
#define ARGUSPARSEPERCENTDELTASRCBYTESLABEL	83
#define ARGUSPARSEPERCENTDELTADSTBYTESLABEL	84
#define ARGUSPARSESRCUSERDATALABEL		85
#define ARGUSPARSEDSTUSERDATALABEL		86
#define ARGUSPARSETCPEXTENSIONSLABEL		87
#define ARGUSPARSESRCWINDOWLABEL		88
#define ARGUSPARSEDSTWINDOWLABEL		89
#define ARGUSPARSEJOINDELAYLABEL		90
#define ARGUSPARSELEAVEDELAYLABEL		91
#define ARGUSPARSESEQUENCENUMBERLABEL		92
#define ARGUSPARSEBINSLABEL			93
#define ARGUSPARSEBINNUMBERLABEL		94
#define ARGUSPARSESRCMPLSLABEL			95
#define ARGUSPARSEDSTMPLSLABEL			96
#define ARGUSPARSESRCVLANLABEL			97
#define ARGUSPARSEDSTVLANLABEL			98
#define ARGUSPARSESRCVIDLABEL			99
#define ARGUSPARSEDSTVIDLABEL			100
#define ARGUSPARSESRCVPRILABEL			101
#define ARGUSPARSEDSTVPRILABEL			102
#define ARGUSPARSESRCIPIDLABEL			103
#define ARGUSPARSEDSTIPIDLABEL			104
#define ARGUSPARSESTARTRANGELABEL		105
#define ARGUSPARSEENDRANGELABEL			106
#define ARGUSPARSESERVICELABEL			107
#define ARGUSPARSETCPSRCBASELABEL		108
#define ARGUSPARSETCPDSTBASELABEL		109
#define ARGUSPARSETCPRTTLABEL			110
#define ARGUSPARSESRCPKTSIZEMAXLABEL		111
#define ARGUSPARSESRCPKTSIZEMINLABEL		112
#define ARGUSPARSEDSTPKTSIZEMAXLABEL		113
#define ARGUSPARSEDSTPKTSIZEMINLABEL		114

void (*RaParseLabelAlgorithmTable[MAX_PARSE_ALG_TYPES])(struct ArgusParserStruct *, char *) = {
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
};


double (*RaComparisonAlgorithmTable[MAX_PARSE_ALG_TYPES])(struct ArgusRecordStruct *, struct ArgusRecordStruct *) = {
   ArgusCompareStartDate,
   ArgusCompareLastDate,
   ArgusCompareTransactions,
   ArgusCompareDuration,
   ArgusCompareMean,
   ArgusCompareMin,
   ArgusCompareMax,
   ArgusCompareSrcAddr,
   ArgusCompareSrcAddr,
   ArgusCompareDstAddr,
   ArgusCompareProto,
   ArgusCompareSrcPort,
   ArgusCompareDstPort,
   ArgusCompareSrcTos,
   ArgusCompareDstTos,
   ArgusCompareSrcDSByte,
   ArgusCompareDstDSByte,
   ArgusCompareSrcTtl,
   ArgusCompareDstTtl,
   ArgusCompareBytes,
   ArgusCompareSrcBytes,
   ArgusCompareDstBytes,
   ArgusCompareAppBytes,
   ArgusCompareSrcAppBytes,
   ArgusCompareDstAppBytes,
   ArgusComparePackets,
   ArgusCompareSrcPackets,
   ArgusCompareSrcPackets,
   ArgusCompareDstPackets,
   ArgusCompareDstPackets,
   ArgusCompareLoad,
   ArgusCompareSrcLoad,
   ArgusCompareDstLoad,
   ArgusCompareLoss,
   ArgusCompareSrcLoss,
   ArgusCompareDstLoss,
   ArgusComparePercentLoss,
   ArgusCompareSrcPercentLoss,
   ArgusCompareDstPercentLoss,
   ArgusCompareRate,
   ArgusCompareSrcRate,
   ArgusCompareDstRate,
   ArgusCompareSourceID,
   ArgusCompareFlags,
   ArgusCompareSrcMacAddress,
   ArgusCompareSrcMacAddress,
   ArgusCompareDstMacAddress,
   ArgusCompareDir,
   ArgusCompareSrcIntPkt,
   ArgusCompareDstIntPkt,
   ArgusCompareSrcIntPktActive,
   ArgusCompareDstIntPktActive,
   ArgusCompareSrcIntPktIdle,
   ArgusCompareDstIntPktIdle,
   ArgusCompareSrcIntPktMax,
   ArgusCompareSrcIntPktMin,
   ArgusCompareDstIntPktMax,
   ArgusCompareDstIntPktMin,
   ArgusCompareSrcIntPktActiveMax,
   ArgusCompareSrcIntPktActiveMin,
   ArgusCompareDstIntPktActiveMax,
   ArgusCompareDstIntPktActiveMin,
   ArgusCompareSrcIntPktIdleMax,
   ArgusCompareSrcIntPktIdleMin,
   ArgusCompareDstIntPktIdleMax,
   ArgusCompareDstIntPktIdleMin,
   NULL,
   ArgusCompareSrcJitter,
   ArgusCompareDstJitter,
   ArgusCompareActiveSrcJitter,
   ArgusCompareActiveDstJitter,
   ArgusCompareIdleSrcJitter,
   ArgusCompareIdleDstJitter,
   ArgusCompareState,
   ArgusCompareDeltaDuration,
   ArgusCompareDeltaStartTime,
   ArgusCompareDeltaLastTime,
   ArgusCompareDeltaSrcPkts,
   ArgusCompareDeltaDstPkts,
   ArgusCompareDeltaSrcBytes,
   ArgusCompareDeltaDstBytes,
   ArgusComparePercentDeltaSrcPkts,
   ArgusComparePercentDeltaDstPkts,
   ArgusComparePercentDeltaSrcBytes,
   ArgusComparePercentDeltaDstBytes,
   ArgusCompareSrcUserData,
   ArgusCompareDstUserData,
   ArgusCompareTCPExtensions,
   ArgusCompareSrcWindow,
   ArgusCompareDstWindow,
   ArgusCompareJoinDelay,
   ArgusCompareLeaveDelay,
   ArgusCompareSequenceNumber,
   ArgusCompareBins,
   ArgusCompareBinNumber,
   ArgusCompareSrcMpls,
   ArgusCompareDstMpls,
   ArgusCompareSrcVLAN,
   ArgusCompareDstVLAN,
   ArgusCompareSrcVID,
   ArgusCompareDstVID,
   ArgusCompareSrcVPRI,
   ArgusCompareDstVPRI,
   ArgusCompareSrcIpId,
   ArgusCompareDstIpId,
   ArgusCompareStartRange,
   ArgusCompareEndRange,
   ArgusCompareService,
   ArgusCompareTCPSrcBase,
   ArgusCompareTCPDstBase,
   ArgusCompareTCPRTT,
   ArgusCompareSrcPktSizeMax,
   ArgusCompareSrcPktSizeMin,
   ArgusCompareDstPktSizeMax,
   ArgusCompareDstPktSizeMin,
};


char *RaParseLabelStringTable[MAX_PARSE_ALG_TYPES] = {
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
   "SAppBytes",
   "DAppBytes",
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
   "SIntPkt",
   "DIntPkt",
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
};
#endif
#endif
#endif

