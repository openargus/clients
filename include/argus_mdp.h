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
 * $Id: //depot/argus/clients/include/argus_mdp.h#10 $
 * $DateTime: 2016/06/01 15:17:28 $
 * $Change: 3148 $
 */

 
#ifndef ArgusMdp_h
#define ArgusMdp_h

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/time.h>

#define MDP_PROTOCOL_VERSION	9
#define MDP_MSG_SIZE_MAX	8192
#define MDP_SESSION_NAME_MAX	64 
#define MDP_NODE_NAME_MAX	64

#define MDP_SEGMENT_SIZE_MIN	64
#define MDP_SEGMENT_SIZE_MAX	8128

enum MdpMessageType {
   MDP_MSG_INVALID, 
   MDP_REPORT, 
   MDP_INFO, 
   MDP_DATA, 
   MDP_PARITY,
   MDP_CMD,
   MDP_NACK,
   MDP_ACK
};
    
enum MdpStatusFlag {
   MDP_CLIENT = 0x01,
   MDP_SERVER = 0x02,
   MDP_ACKING = 0x04,
};
    
enum MdpReportType {
   MDP_REPORT_INVALID,   
   MDP_REPORT_HELLO
};
    

struct MdpBlockStats {
   unsigned long  count;
   unsigned long  lost_00;
   unsigned long  lost_05;
   unsigned long  lost_10;
   unsigned long  lost_20;
   unsigned long  lost_40;
   unsigned long  lost_50;
};

struct MdpBufferStats {
   unsigned long  buf_total;
   unsigned long  peak;
   unsigned long  overflow;
};

struct MdpClientStats {
   unsigned long          duration;
   unsigned long          success;
   unsigned long          active;
   unsigned long          fail;
   unsigned long          resync;
   struct MdpBlockStats   blk_stat;
   unsigned long          tx_rate;
   unsigned long          nack_cnt;
   unsigned long          supp_cnt;
   struct MdpBufferStats  buf_stat;
   unsigned long          goodput;
   unsigned long          rx_rate;
};

struct MdpReportMsg {
   unsigned char          status;
   unsigned char          flavor;
   struct MdpClientStats  client_stats;
};
    

#define MDP_DATA_FLAG_REPAIR		0x01
#define MDP_DATA_FLAG_BLOCK_END		0x02
#define MDP_DATA_FLAG_RUNT		0x04
#define MDP_DATA_FLAG_INFO		0x10
#define MDP_DATA_FLAG_UNRELIABLE	0x20
#define MDP_DATA_FLAG_FILE		0x80

struct MdpInfoMsg {
   unsigned short segment_size;
};

struct MdpDataMsg {
   unsigned long  offset;
   unsigned short segment_size;
};

struct MdpParityMsg {
   unsigned long  offset;
   unsigned char  parity_id;
};

struct MdpObjectMsg {
   unsigned short sequence;
   unsigned long  object_id;
   unsigned long  object_size;
   unsigned char  ndata;
   unsigned char  nparity;
   unsigned char  flags;
   unsigned char  grtt;

   union {
      struct MdpInfoMsg   info;
      struct MdpDataMsg   data;
      struct MdpParityMsg parity;   
   };
};


enum MdpCmdMsgType {
   MDP_CMD_NULL,
   MDP_CMD_FLUSH,
   MDP_CMD_SQUELCH,
   MDP_CMD_ACK_REQ,
   MDP_CMD_GRTT_REQ,
   MDP_CMD_NACK_ADV,
};

enum {
   MDP_CMD_FLAG_EOT = 0x01
};

struct MdpFlushCmd {
   char flags;
   unsigned long object_id;
};

struct MdpSquelchCmd {
   unsigned long   sync_id;
   unsigned short  len;
};

struct MdpAckReqCmd {
   unsigned long   object_id;
   unsigned short  len;
};


enum {
   MDP_CMD_GRTT_FLAG_WILDCARD = 0x01
};
    
struct MdpGrttReqCmd {
   char           flags;
   unsigned char  sequence;
   struct timeval send_time;
   struct timeval hold_time;
   unsigned short segment_size;
   unsigned long  rate;
   unsigned char  rtt;
   unsigned short loss;
   unsigned short len;
};

struct MdpNackAdvCmd {
   unsigned short len; 
};
    
struct MdpCmdMsg {
   unsigned short  sequence;
   unsigned char   grtt;
   unsigned char   flavor;
   union {
      struct MdpFlushCmd     flush;
      struct MdpSquelchCmd   squelch;
      struct MdpAckReqCmd    ack_req;
      struct MdpGrttReqCmd   grtt_req;
      struct MdpNackAdvCmd   nack_adv;
   };
};

    
struct MdpNackMsg {
   unsigned long   server_id;
   struct timeval  grtt_response;
   unsigned short  loss_estimate;
   unsigned char   grtt_req_sequence;
};

enum MdpRepairType {
    MDP_REPAIR_INVALID = 0,
    MDP_REPAIR_SEGMENTS,
    MDP_REPAIR_BLOCKS,
    MDP_REPAIR_INFO,
    MDP_REPAIR_OBJECT
};
    
struct MdpRepairNack {
   unsigned char   type;
   unsigned char   nerasure;
   unsigned long   offset;
   unsigned short  mask_len;
   char*           mask;
};    

struct MdpObjectNack {
   unsigned long   object_id;
   unsigned short  nack_len;
   unsigned short  max_len;
};
        
enum MdpAckType {
    MDP_ACK_INVALID = 0,  
    MDP_ACK_OBJECT,
    MDP_ACK_GRTT
};
    
struct MdpAckMsg {
   unsigned long   server_id;
   struct timeval  grtt_response;
   unsigned short  loss_estimate;
   unsigned char   grtt_req_sequence;
   char            type;
   unsigned long   object_id;
};

struct mdphdr {
   unsigned char           type;
   unsigned char           version;
   unsigned long           node_id;
   union {
      struct MdpReportMsg  report;
      struct MdpObjectMsg  object;
      struct MdpCmdMsg     cmd;
      struct MdpNackMsg    nack;
      struct MdpAckMsg     ack;
   };
};

const double MDP_GRTT_MIN = 0.001;
const double MDP_GRTT_MAX = 15.0;

const double RTT_MIN = 1.0e-06;
const double RTT_MAX = 1000.0;        

#ifdef __cplusplus
}
#endif
#endif /* ArgusMdp_h */

