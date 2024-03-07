/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
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
 * $Id: //depot/gargoyle/clients/include/argus_histo.h#4 $
 * $DateTime: 2014/05/14 00:30:13 $
 * $Change: 2825 $
 */

#ifndef Argus_Histo_h
#define Argus_Histo_h

#ifdef __cplusplus
extern "C" {
#endif


#define ARGUS_HISTO_RANGE_UNSPECIFIED	0x02
#define ARGUS_HISTO_CAPTURE_VALUES	0x10

extern double ArgusFetchSrcId (struct ArgusRecordStruct *);
extern double ArgusFetchTime (struct ArgusRecordStruct *);
extern double ArgusFetchStartTime (struct ArgusRecordStruct *);
extern double ArgusFetchLastTime (struct ArgusRecordStruct *);
extern double ArgusFetchTransactions (struct ArgusRecordStruct *);
extern double ArgusFetchuSecDuration (struct ArgusRecordStruct *);
extern double ArgusFetchDuration (struct ArgusRecordStruct *);
extern double ArgusFetchMean (struct ArgusRecordStruct *);
extern double ArgusFetchMin (struct ArgusRecordStruct *);
extern double ArgusFetchMax (struct ArgusRecordStruct *);
extern double ArgusFetchIdleMean (struct ArgusRecordStruct *);
extern double ArgusFetchIdleMin (struct ArgusRecordStruct *);
extern double ArgusFetchIdleMax (struct ArgusRecordStruct *);
extern double ArgusFetchSrcMac (struct ArgusRecordStruct *);
extern double ArgusFetchDstMac (struct ArgusRecordStruct *);
extern double ArgusFetchSrcAddr (struct ArgusRecordStruct *);
extern double ArgusFetchDstAddr (struct ArgusRecordStruct *);
extern double ArgusFetchEtherType (struct ArgusRecordStruct *);
extern double ArgusFetchProtocol (struct ArgusRecordStruct *);
extern double ArgusFetchSrcMpls (struct ArgusRecordStruct *);
extern double ArgusFetchDstMpls (struct ArgusRecordStruct *);
extern double ArgusFetchSrcVlan (struct ArgusRecordStruct *);
extern double ArgusFetchDstVlan (struct ArgusRecordStruct *);
extern double ArgusFetchSrcIpId (struct ArgusRecordStruct *);
extern double ArgusFetchDstIpId (struct ArgusRecordStruct *);
extern double ArgusFetchSrcPort (struct ArgusRecordStruct *);
extern double ArgusFetchDstPort (struct ArgusRecordStruct *);
extern double ArgusFetchSrcTos (struct ArgusRecordStruct *);
extern double ArgusFetchDstTos (struct ArgusRecordStruct *);
extern double ArgusFetchSrcTtl (struct ArgusRecordStruct *);
extern double ArgusFetchDstTtl (struct ArgusRecordStruct *);
extern double ArgusFetchByteCount (struct ArgusRecordStruct *);
extern double ArgusFetchLoad (struct ArgusRecordStruct *);
extern double ArgusFetchSrcLoad (struct ArgusRecordStruct *);
extern double ArgusFetchDstLoad (struct ArgusRecordStruct *);
extern double ArgusFetchLoss (struct ArgusRecordStruct *);
extern double ArgusFetchRate (struct ArgusRecordStruct *);
extern double ArgusFetchSrcRate (struct ArgusRecordStruct *);
extern double ArgusFetchDstRate (struct ArgusRecordStruct *);
extern double ArgusFetchSrcMeanPktSize (struct ArgusRecordStruct *);
extern double ArgusFetchDstMeanPktSize (struct ArgusRecordStruct *);
extern double ArgusFetchTranRef (struct ArgusRecordStruct *);
extern double ArgusFetchSeq (struct ArgusRecordStruct *);
extern double ArgusFetchSrcByteCount (struct ArgusRecordStruct *);
extern double ArgusFetchDstByteCount (struct ArgusRecordStruct *);
extern double ArgusFetchPktsCount (struct ArgusRecordStruct *);
extern double ArgusFetchSrcPktsCount (struct ArgusRecordStruct *);
extern double ArgusFetchDstPktsCount (struct ArgusRecordStruct *);
extern double ArgusFetchSrcTcpBase (struct ArgusRecordStruct *);
extern double ArgusFetchDstTcpBase (struct ArgusRecordStruct *);
extern double ArgusFetchTcpRtt (struct ArgusRecordStruct *);
extern double ArgusFetchTcpSynAck (struct ArgusRecordStruct *);
extern double ArgusFetchTcpAckDat (struct ArgusRecordStruct *);
extern double ArgusFetchSrcTcpMax (struct ArgusRecordStruct *);
extern double ArgusFetchDstTcpMax (struct ArgusRecordStruct *);
extern double ArgusFetchSrcGap (struct ArgusRecordStruct *);
extern double ArgusFetchDstGap (struct ArgusRecordStruct *);
extern double ArgusFetchSrcDup (struct ArgusRecordStruct *);
extern double ArgusFetchDstDup (struct ArgusRecordStruct *);
extern double ArgusFetchSrcLoss (struct ArgusRecordStruct *);
extern double ArgusFetchDstLoss (struct ArgusRecordStruct *);

#ifdef __cplusplus
}
#endif
#endif

