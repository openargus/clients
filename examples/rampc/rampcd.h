/*
 * Gargoyle Client Software.  Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2010 QoSient, LLC
 * All Rights Reserved
 *
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


#ifndef RaMpcD_h
#define RaMpcD_h

#include <stdlib.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>

#include <netdb.h>
#include <ctype.h>

#include <argus_filter.h>

#define RAMPC_CIRCLEX		260
#define RAMPC_CIRCLEY		225


struct ArgusHashTable *RaMpcMonitorTable = NULL;


#define RAMPC_TIMEOUT          300

struct ArgusProbeStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusHashTableHdr *htblhdr;
   struct ArgusTransportStruct trans;
   struct ArgusAggregatorStruct *agg;
   unsigned int status;
   struct timeval start;
};

struct ArgusAdjustStruct RaStreamDefaultNadp, *RaStreamNadp;

struct RaBinProcessStruct *ArgusBinProcess = NULL;
struct RaBinProcessStruct *RaNewBinProcess (struct ArgusParserStruct *, int);
void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

struct ArgusRecordStruct *RaFindMpcStream(struct ArgusParserStruct *, struct ArgusProbeStruct *, struct ArgusRecordStruct *);


struct ArgusHashTable ArgusProbeTable;
struct ArgusQueueStruct *ArgusProbeQueue = NULL;



#define RAMPC_HASHSIZE		128

#define RA_MPC_TYPE		0x3F0000

#define RA_MPC_PROBE		0x010000
#define RA_MPC_NETWORK		0x020000
#define RA_MPC_ROUTER		0x040000
#define RA_MPC_SNDRGROUP	0x080000
#define RA_MPC_RCVRGROUP	0x100000
#define RA_MPC_SENDER		0x120000
#define RA_MPC_RECVER		0x140000
#define RA_MPC_MEMBER		0x180000
#define RA_MPC_PROBEMATRIX	0x200000

char *RaMcastTypes[] = {
"   ", "PRB", "NET", "NPB", "RTR", "   ", "   ", "   ",
"SGP", "   ", "   ", "   ", "   ", "   ", "   ", "   ",
"RGP", "   ", "SND", "   ", "RCV", "   ", "   ", "   ",
"MBR", "   ", "   ", "   ", "   ", "   ", "   ", "   ",
};

 
struct ArgusListStruct *RaMpcProbeList = NULL;
struct ArgusListStruct *RaMpcNetList = NULL;

struct ArgusQueueStruct *RaProbeQueue = NULL;
struct ArgusQueueStruct *RaMcastQueue = NULL;

struct ArgusHashTable RaMpcHashTable;
struct ArgusHashTable RaMpcProbeTable;
struct ArgusHashTable RaMcastTable;


extern struct ArgusFlow *RaThisFlow;
 
struct ArgusRecordStruct *RaMpcCorrelate (struct ArgusProbeStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *);

int RaMpcUpdateRemoteProbes (struct ArgusRecordStruct *, struct ArgusRecordStruct *, struct ArgusRecordStruct *, int);
int RaMpcProbeMonitorsThisAddr (struct ArgusRecordStruct *, unsigned int); 
 
struct ArgusRecordStruct *RaMpcEstablishMpcStream(struct ArgusProbeStruct *, struct ArgusRecordStruct *);
void RaFreeMpcStream (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void *RaFindMpcObject (struct ArgusHashTable *, struct ArgusHashStruct *);
struct ArgusHashTable *RaMpcAddHashObject (struct ArgusHashTable *, void *, struct ArgusHashStruct *);
struct ArgusHashTableHdr *RaMpcFindHash (struct ArgusHashTable *, struct ArgusHashStruct *);
void RaRemoveHashObject (struct ArgusHashTableHdr *);
void RaMpcCleanHashTable (struct ArgusHashTable *);
void RaMpcDeleteHashTable (struct ArgusHashTable *);

struct ArgusRecordStruct *RaNewMcast (struct ArgusRecordStruct *, unsigned int *id);
void RaFreeMcast (struct ArgusRecordStruct *);

int RaMpcAdvertiseHints(struct ArgusProbeStruct *, struct ArgusRecordStruct *);
struct ArgusProbeStruct *ArgusProcessProbe (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessThisRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
int ArgusProcessQueue (struct ArgusQueueStruct *);

#define RA_CAST_MAX_SORT_ALG	5
int (*RaMpcSortAlgorithms[RA_CAST_MAX_SORT_ALG])(const void *, const void *);
void RaMpcSortQueue (struct RaQueueStruct *);

int RaMpcSortMcastId (const void *, const void *);
int RaMpcSortMcastType (const void *, const void *);
int RaMpcSortArgusSrc (const void *, const void *);
int RaMpcSortMcastSrcId (const void *, const void *);

int RaMpcProbeMode       = 1;
int RaMpcNetMode         = 0;
int RaMpcSvgMode         = 0;
int RaMpcGroupMode       = 0;
int RaMpcSingleProbeMode = 0;
int RaMpcHtmlMode        = 0;

struct ArgusAggregatorStruct *ArgusProbeAggregator = NULL;
struct ArgusAggregatorStruct *ArgusMpcAggregator = NULL;

char *ArgusProbeAggregatorConfig[2] = {
   "filter=\"\" model=\"srcid\"  status=0 idle=0\n",
   NULL,
};

char *ArgusMpcAggregatorConfig[2] = {
   "filter=\"\" model=\"saddr daddr proto sport dport\"  status=3600 idle=0\n",
   NULL,
};

struct RaFlowModelStruct *RaFlowModel = NULL;
struct ArgusRecordStruct RaGlobalStoreBuf, *RaGlobalStore = &RaGlobalStoreBuf;

int RaCheckTimeout(struct ArgusRecordStruct *, struct ArgusRecordStruct *);
void RaProcessQueue(struct RaQueueStruct *, unsigned char state);

void error_end(int rno);
void end(int signo);
void stop(int signo);
void window_size(int signo);
void do_key(char c);

/* configurable field display support */

int pflags[30];
int sflags[10];
int Numfields;
int RaPFlag = 0;

#define MAXLINES 2048

#if !defined(MAXNAMELEN)
#define MAXNAMELEN 1024
#endif

/* this is what procps top does by default, so let's do this, if nothing is
 * specified
 */
#ifndef DEFAULT_SHOW
/*                       0         1         2         3 */
/*                       0123456789012345678901234567890 */
#define DEFAULT_SHOW    "AbcDgHIjklMnoTP|qrsuzyV{EFWX"
#endif
char Fields[256] = "";

extern struct timeval RaClientTimeout;

int totaloutrecords;
 
int RaThisFlowModelIndex = 0;
char **RaFlowModelFiles [256];

struct RaSpaceStruct {
   struct ArgusQueueHeader qhdr;
   char *name;
   int count, index;
   void **array;
};

struct RaSubSpaceStruct {
   struct ArgusQueueHeader qhdr;
   int number, thisN, thatN;
   char *name;
   struct RaQueueStruct *groups;
};

struct RaPointStruct {
   unsigned int x, y;
};

struct RaGroupStruct {
   struct ArgusQueueHeader qhdr;
   int addr;
   struct RaPointStruct start, stop;
};

struct RaQueueStruct *RaSpaceQueue = NULL;
struct RaSpaceStruct *RaThisSpace = NULL;
struct RaSubSpaceStruct *RaThisSubSpace = NULL;
struct RaGroupStruct *RaThisGroup = NULL;

#define ARGUS_RCITEMS			6

#define RA_START_COORD			0
#define RA_END_COORD			1
#define RA_SPACE			2
#define RA_PARTITIONS			3
#define RA_SUBSPACE			4
#define RA_GROUP_TO_REGION		5


char *RaSpaceResourceFileStr [] = {
   "Starting Coordinates: ",
   "Ending Coordinates: ",
   "SPACE: ",
   "Total number of partitions:",
   "Subspace:",
   "Mpc Group to Region List:",
};


#include <math.h>

#define RA_QUERY_FLOAT		0
#define RA_QUERY_HEX		1
#define RA_QUERY_STRING		2

#endif


