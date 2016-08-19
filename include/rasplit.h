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
 */

/* 
 * $Id: //depot/argus/clients/include/rasplit.h#16 $
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
