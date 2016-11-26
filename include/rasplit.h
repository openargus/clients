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
 * $Id: //depot/argus/clients/include/rasplit.h#22 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

#ifndef RaSplit_h
#define RaSplit_h

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <stdlib.h>

#include <signal.h>
#include <string.h>

#include <netinet/in.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_namedb.h>
#include <argus_filter.h>
#include <argus_main.h>
#include <argus_metric.h>

#include <ctype.h>
 
#define ARGUSSECONDS		-1 
#define ARGUSMINUTE		0
#define ARGUSHOURLY		1 
#define ARGUSDAILY		2
#define ARGUSWEEKLY		3
#define ARGUSMONTHLY		4 
#define ARGUSNNUALY		5 
             
#define ARGUSSPLITMODENUM	10
#define ARGUSSPLITTIME		0
#define ARGUSSPLITCOUNT		1
#define ARGUSSPLITSIZE		2
#define ARGUSSPLITFLOW		3
#define ARGUSSPLITPATTERN	4

#define ARGUSSPLITNOMODIFY	5
#define ARGUSSPLITHARD		6
#define ARGUSSPLITSOFT		7
#define ARGUSSPLITZERO		8
#define ARGUSSPLITRATE		9

#define ARGUSSPLITYEAR		1
#define ARGUSSPLITMONTH		2
#define ARGUSSPLITWEEK		3
#define ARGUSSPLITDAY		4
#define ARGUSSPLITHOUR		5
#define ARGUSSPLITMINUTE	6
#define ARGUSSPLITSECOND	7

#if defined(ArgusClient)

char *RaSplitModes[ARGUSSPLITMODENUM] = {
  "time",
  "count",  
  "size",    
  "flow",    
  "pattern",    
  "nomodify",    
  "hard",    
  "soft",    
  "zero",    
  "rate",    
};

#else

extern char *RaSplitModes[ARGUSSPLITMODENUM];

#endif
 
char *RaSplitFilename (struct ArgusAdjustStruct *);
 
extern void ArgusAlignConfig(struct ArgusParserStruct *, struct ArgusAdjustStruct *);
extern void ArgusAlignInit(struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusAdjustStruct *);
extern struct ArgusRecordStruct *ArgusAlignRecord(struct ArgusParserStruct *, struct ArgusRecordStruct *, struct ArgusAdjustStruct *);

int RaProcessSplitOptions(struct ArgusParserStruct *, char *, int, struct ArgusRecordStruct*); 

#ifdef __cplusplus
}
#endif
#endif
