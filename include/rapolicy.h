/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
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

/* 
 * $Id: //depot/gargoyle/clients/include/rapolicy.h#7 $
 * $DateTime: 2014/05/14 00:30:13 $
 * $Change: 2825 $
 */


#ifndef RaPolicy_h
#define RaPolicy_h

#ifdef __cplusplus
extern "C" {
#endif

#define ARGUS_POLICY_SHOW_DENY		0x01
#define ARGUS_POLICY_LABEL_ALL		0x02
#define ARGUS_POLICY_LABEL_LOG		0x04
#define ARGUS_POLICY_PERMIT_OTHERS	0x08
#define ARGUS_POLICY_DUMP_POLICY	0x10
#define ARGUS_POLICY_LABEL_IMPLICIT	0x20
#define ARGUS_POLICY_JUST_LABEL		0x40


#define DEFAULT_POLICY   "rapolicy.conf"
#define POLICY_STRING    "access-list"
#define PREFIX_STRING    "prefix-list"

#define POLICYFIELDNUM     9

#define POLICYSTRING       0
#define POLICYID           1
#define POLICYACTION       2
#define POLICYPROTO        3
#define POLICYSRC          4
#define POLICYSRCPORT      5
#define POLICYDST          6
#define POLICYDSTPORT      7
#define POLICYNOTIFICATION 8
#define POLICYCOMPLETE     9
#define POLICYREMARK       10
#define POLICYSEQUENCE     11

#define POLICYERRORNUM     14
#define POLICYERR_NOACL    0
#define POLICYERR_NOID     1
#define POLICYERR_NOACTION 2
#define POLICYERR_NOPROTO  3
#define POLICYERR_NOSRCADR 4
#define POLICYERR_NOSRCMSK 5
#define POLICYERR_SP_ACT   6
#define POLICYERR_SPORT    7
#define POLICYERR_NODSTADR 8
#define POLICYERR_NODSTMSK 9
#define POLICYERR_DP_ACT   10
#define POLICYERR_DPORT    11
#define POLICYERR_NONOTE   12
#define POLICYERR_NOSEQ    13

#define POLICYTESTCRITERIA 5

#define POLICYTESTPROTO    0
#define POLICYTESTSRC      1
#define POLICYTESTSRCPORT  2
#define POLICYTESTDST      3
#define POLICYTESTDSTPORT  4

#define RA_PERMIT    0x10000
#define RA_DENY      0x20000
#define RA_COMMENT   0x40000

#define RA_PROTO_SET	0x0001
#define RA_SRC_SET	0x0002
#define RA_DST_SET	0x0004
#define RA_SRCPORT_SET	0x0008
#define RA_DSTPORT_SET	0x0010
#define RA_TCPFLG_SET   0x0020
#define RA_PREC_SET     0x0040
#define RA_TOS_SET      0x0080
#define RA_LOG_SET      0x0100
#define RA_DSCP_SET     0x0200
#define RA_EST_SET      0x0400
#define RA_ICMP_SET	0x0800
#define RA_IGMP_SET	0x1000


#define RA_EQ        0x01
#define RA_LT        0x02
#define RA_GT        0x04
#define RA_NEQ       0x08
#define RA_RANGE     0x10

#define RA_FIN	0x0001
#define RA_SYN	0x0002
#define RA_RST	0x0004
#define RA_PSH	0x0008
#define RA_ACK	0x0010
#define RA_URG	0x0020
#define RA_ECE	0x0040
#define RA_CWR	0x0080
#define RA_NS	0x0100

#define ICMPCodeAny   99

#define RA_SRCROUTED      0x01
#define RA_IPACCESSLIST     0x02
#define RA_PREFIXLIST     0x04
#define RA_ETHERTYPEACCESSLIST     0x08
#define RA_ETHERADDRACCESSLIST     0x10

struct ArgusNetStruct {
   arg_int32 operator;
   arg_uint32 addr;
   arg_uint32 mask;
};

struct RaPolicyPolicyStruct {
   struct RaPolicyPolicyStruct *prv, *nxt;
   char *policyID;
   arg_uint8 TCPflags, tos, precedence, dscp;
   arg_uint8 ICMPtype, ICMPcode, IGMPtype;
   arg_int32 type, flags, seq, tags;
   long long  hitCount, hitPkts, hitBytes;
   arg_uint32 line;
   arg_uint16 IPoptions;
   arg_uint16 proto, src_port_low, src_port_hi;
   arg_uint16 dst_port_low, dst_port_hi, src_action, dst_action;
   arg_int32 notification;
   struct ArgusNetStruct src, dst;
   char *str;
   char *labelStr;
};


#if defined(RA_POLICY_C)


/****************************************************************************************
 * Some basic definitions for the finite state machine that controls the parsing of the
 * Access Control List entries
 * *************************************************************************************/

/****************************************************************************************
 * The states which are effectively the row index of a two-dimensional array of entry_t
 * structures containing the next state and a pointer to a function called at the current state
 * Using enum avoids the need to have a static value for the highest valid state number
 * S_FINAL the entry that sets the number of rows in the state event table array.
 * Values beyond S_FINAL are flags and are defined to avoid compiler warnings 
 * ************************************************************************************/

enum states {
S_START,
S_NUMACL,
S_STDACL,
S_STDADDR,
S_GETADDR,
S_GETWC,
S_EXTACL,
S_EXTSADDR,
S_EXTGETSWC,
S_EXTGETSADDR,
S_EXTSPORT,
S_EXTGETSPORT,
S_EXTGETSPORT1,
S_EXTGETSPORT2,
S_EXTDADDR,
S_EXTGETDWC,
S_EXTGETDADDR,
S_EXTDPORT,
S_EXTGETDPORT,
S_EXTGETDPORT1,
S_EXTGETDPORT2,
S_TAGS,
S_NAMACL,
S_DONE,
S_FINAL,                // defines the number of rows in the state event table 
                        // anything beyond this comment is a valid value (no compiler warning) but is really an inband indicator
S_LOCAL = 1000,		// no chage in the current state
S_NONE			// the state cannot be determined always an indication of failure
};

typedef enum states states_t;

/* Sometimes it's nice to be able to print the names of the states */

char *stateNames[] = {
"S_START", "S_NUMACL", "S_STDACL", "S_STDADDR", "S_GETADDR", "S_GETWC", "S_EXTACL", "S_EXTSADDR", "S_EXTGETSWC", "S_EXTGETSADDR", "S_EXTSPORT", "S_EXTGETSPORT",
"S_EXTGETSPORT1", "S_EXTGETSPORT2", "S_EXTDADDR", "S_EXTGETDWC", "S_EXTGETDADDR", "S_EXTDPORT", "S_EXTGETDPORT", "S_EXTGETDPORT1", "S_EXTGETDPORT2", "S_TAGS",
"S_NAMACL", "S_DONE", "S_FINAL", "S_LOCAL", "S_NONE" };

/****************************************************************************************
 * The events which are effectively the column index of a two-dimensional array of entry_t
 * structures containing the next state and a pointer to a function called at the current state
 * Using enum avoids the need to have a static value for the highest valid event number
 * E_FINAL is the entry that sets the number of columns in the state event table array.
 * Values beyond E_FINAL are flags and are defined to avoid compiler warnings 
 * ************************************************************************************/
enum events {
E_ACL,		// "access-list"
E_ACTION,	// "permit" "deny"
E_ANY,		//"any"
E_HOST,		// "host"
E_QUAD,		// a.b.c.d
E_INTEGER,	// nnnn
E_EOL,		// \n
E_STD,		// "standard" or ACL number 1-99 or ?-?
E_EXT,		// "extended" or ACL number 100-199 or x-x
E_REMARK,	// "remark"
E_IP,		// "ip"
E_ICMP,		// "icmp"
E_IGMP,		// "igmp"
E_UDP,		// "udp"
E_TCP,		// "tcp"
E_PROTO,	// any of the other protocols: ah eigrp esp gre igrp ipinip nos ospf
E_PORTUDP,	// any service name that is valid as a Cisco UDP port
E_PORTTCP,	// any service name that is valid as a Cisco TCP port
E_PORTIP,	// any service name that is valis as either TCP or UDP
E_UNARY,	// any of the unary relational operators lt eq gt ne
E_BINARY,	// the binary relational operator range
E_TOS,		// "tos"
E_LOG,		// "log"
E_IGMPTYPE,	// any of the valid IGMP type names
E_ICMPCODE,	// any of the valid ICMP code names
E_ICMPMSG,	// any of the valid ICMP message names
E_EST,		// "est[ablished]"
E_FLAGS,	// named TCP flags ack syn urg push rst fin
E_PRECEDENCE,	// Precedence Value
E_PRFLG,	// "precedence" 
E_TOSVAL,	// TOS value name
E_DSCPFLG,	// "dscp"
E_DSCPVAL,	// any of the DiffServ values
E_IPOPT,	// any of the IP Header options values
E_IGNORE,	// Anything that we recognize but do not process
E_RAWTEXT,	// any unclassified ascii string
E_FINAL,	 // defines the number of columns in the state event table 
E_NULL = 1000		// a function must either return E_NULL or an event token less than E_FINAL which is treated as an injected event
};

typedef enum events events_t;

/* And their printable names */

char *eventNames[] = {
"E_ACL", "E_ACTION", "E_ANY", "E_HOST", "E_QUAD", "E_INTEGER", "E_EOL", "E_STD", "E_EXT", "E_REMARK", "E_IP",	"E_ICMP", "E_IGMP","E_UDP",		
"E_TCP", "E_PROTO","E_PORTUDP","E_PORTTCP","E_PORTIP","E_UNARY","E_BINARY","E_TOS","E_LOG", "E_IGMPTYPE","E_ICMPCODE",	"E_ICMPMSG",	
"E_EST", "E_FLAGS","E_PRECEDENCE","E_PRFLG","E_TOSVAL",	"E_DSCPFLG","E_DSCPVAL","E_IPOPT","E_IGNORE","E_RAWTEXT","E_FINAL","E_NULL"};



/* Function prototypes for the the parser actions */

events_t terror(struct RaPolicyPolicyStruct *policy, char *token);
events_t initACL(struct RaPolicyPolicyStruct *policy, char *token);
events_t initEXT(struct RaPolicyPolicyStruct *policy, char *token);
events_t procACLnum(struct RaPolicyPolicyStruct *policy, char *token);
events_t saveName(struct RaPolicyPolicyStruct *policy, char *token);
events_t notYet(struct RaPolicyPolicyStruct *policy, char *token);
events_t setAction(struct RaPolicyPolicyStruct *policy, char *token);
events_t setsAddr(struct RaPolicyPolicyStruct *policy, char *token);
events_t setswc(struct RaPolicyPolicyStruct *policy, char *token);
events_t setsany(struct RaPolicyPolicyStruct *policy, char *token);
events_t setdAddr(struct RaPolicyPolicyStruct *policy, char *token);
events_t setdwc(struct RaPolicyPolicyStruct *policy, char *token);
events_t setdany(struct RaPolicyPolicyStruct *policy, char *token);
events_t finished(struct RaPolicyPolicyStruct *policy, char *token);
events_t getSeq(struct RaPolicyPolicyStruct *policy, char *token);
events_t setsrel(struct RaPolicyPolicyStruct *policy, char *token);
events_t setdrel(struct RaPolicyPolicyStruct *policy, char *token);
events_t setProto(struct RaPolicyPolicyStruct *policy, char *token);
events_t setsport(struct RaPolicyPolicyStruct *policy, char *token);
events_t setdport(struct RaPolicyPolicyStruct *policy, char *token);
events_t setsport2(struct RaPolicyPolicyStruct *policy, char *token);
events_t setdport2(struct RaPolicyPolicyStruct *policy, char *token);
events_t setsportname(struct RaPolicyPolicyStruct *policy, char *token);
events_t setdportname(struct RaPolicyPolicyStruct *policy, char *token);
events_t flagLog(struct RaPolicyPolicyStruct *policy, char *token);
events_t setIGMP(struct RaPolicyPolicyStruct *policy, char *token);
events_t setICMPcode(struct RaPolicyPolicyStruct *policy, char *token);
events_t setICMPmsg(struct RaPolicyPolicyStruct *policy, char *token);
events_t setEst(struct RaPolicyPolicyStruct *policy, char *token);
events_t setTCPflag(struct RaPolicyPolicyStruct *policy, char *token);
events_t getRemark(struct RaPolicyPolicyStruct *policy, char *token);
events_t flagTOS(struct RaPolicyPolicyStruct *policy, char *token);
events_t flagPrecedence(struct RaPolicyPolicyStruct *policy, char *token);
events_t setPrecValue(struct RaPolicyPolicyStruct *policy, char *token);
events_t setTOSvalue(struct RaPolicyPolicyStruct *policy, char *token);
events_t flagDSCP(struct RaPolicyPolicyStruct *policy, char *token);
events_t setDSCPvalue(struct RaPolicyPolicyStruct *policy, char *token);
events_t idle(struct RaPolicyPolicyStruct *policy, char *token);
events_t setProtoParameter(struct RaPolicyPolicyStruct *policy, char *token);

events_t tokenize( char *token);

/*******************************************************************************************************
 * The actual state event table for Cisco IOS Access Control List Entries
 * It will handle standard and extended IP access lists in either the
 * numbered or named variations. The FSM populates a single instance of
 * a RaPolicyPolicyStruct structure which is joined to  a linked list of
 * these structure which is traversed for each flow until a match is found
 * 
 * Standard Named:
 * ip access-list standard standard-named-list-sample
 * permit 10.1.1.0 0.0.0.255
 * deny any
 *
 * Extended Named:
 * ip access-list extended extended-named-list-sample
 * permit udp any gt 5000 host 10.1.1.2 eq 53 log
 * permit tcp 10.1.1.0 0.0.0.255 range 5000 5002 host 10.1.1.7 tos max-reliability log
 *
 * Standard Numbered:
 * access-list 10 permit 10.1.1.0 0.0.0.255
 * access-list 10 deny any
 *
 * Extended Numbered:
 * access-list 110 permit udp any gt host 5000 host 10.1.1.2 eq 53 log
 * access-list 110 permit tcp 10.1.1.0 0.0.0.255 range 500 5002 host 10.1.1.7 tos max-reliability log
 *
 * NB: This set of values was selected to provide accurate parsing of a well formed access list
 * it is not a syntax checker and it is very apt to accept access lists that are not syntactically
 * valid. The ideal input to rapolicy() is an access list taken from the output of "show running" which,
 * by definition, is in good form. 
 *
 * ****************************************************************************************************/

typedef struct {
states_t nextState;
events_t (* fn) (struct RaPolicyPolicyStruct *policy, char *token);
} entry_t;

entry_t stateTable[(int) S_FINAL][(int) E_FINAL] = {
	{ //S_START
		{S_NUMACL, initACL}, //E_ACL
		{S_EXTACL, setAction}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_NONE, terror}, //E_QUAD
		{S_START, getSeq}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NAMACL, initEXT},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_NUMACL
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_NONE, terror}, //E_QUAD
		{S_NUMACL, procACLnum}, //E_INTEGER
		{S_NUMACL, terror}, //E_EOL
		{S_STDACL, saveName}, //E_STD
		{S_EXTACL, saveName}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_STDACL
		{S_NONE, terror}, //E_ACL
		{S_STDADDR, setAction}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_NONE, terror}, //E_QUAD
		{S_NONE, terror}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_STDADDR
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_DONE, setsany}, //E_ANY
		{S_GETADDR, setswc}, //E_HOST
		{S_GETWC, setsAddr}, //E_QUAD
		{S_NONE, terror}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_GETADDR
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_DONE, setsAddr}, //E_QUAD
		{S_NONE, terror}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_GETWC
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_DONE, setswc}, //E_QUAD
		{S_NONE, terror}, //E_INTEGER
		{S_NONE, finished}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_EXTACL
		{S_NONE, terror}, //E_ACL
		{S_EXTACL, setAction}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_NONE, terror}, //E_QUAD
		{S_EXTSADDR, setProto}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_EXTSADDR, setProto},  //E_IP,
		{S_EXTSADDR, setProto},  //E_ICMP,
		{S_EXTSADDR, setProto},  //E_IGMP,
		{S_EXTSADDR, setProto},  //E_UDP,
		{S_EXTSADDR, setProto},  //E_TCP,
		{S_EXTSADDR, setProto},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_EXTSADDR, setProto},  //E_RAWTEXT,
	},

	{ //S_EXTSADDR
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_EXTSPORT, setsany}, //E_ANY
		{S_EXTGETSADDR, setswc}, //E_HOST
		{S_EXTGETSWC, setsAddr}, //E_QUAD
		{S_NONE, terror}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_EXTGETSWC
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_EXTSPORT, setswc}, //E_QUAD
		{S_NONE, terror}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_EXTGETSADDR
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_EXTSPORT, setsAddr}, //E_QUAD
		{S_NONE, terror}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_EXTSPORT
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_EXTDPORT, setdany}, //E_ANY
		{S_EXTGETDADDR, setdwc}, //E_HOST
		{S_EXTGETDWC, setdAddr}, //E_QUAD
		{S_NONE, terror}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_EXTGETSPORT, setsrel},  //E_UNARY,
		{S_EXTGETSPORT1, setsrel},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_EXTGETSPORT
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_NONE, terror}, //E_QUAD
		{S_EXTDADDR, setsport}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_EXTDADDR, setsportname},  //E_PORTUDP,
		{S_EXTDADDR, setsportname},  //E_PORTTCP,
		{S_EXTDADDR, setsportname},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_EXTDADDR, setsportname},  //E_RAWTEXT,
	},

	{ //S_EXTGETSPORT1
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_NONE, terror}, //E_QUAD
		{S_EXTGETSPORT2, setsport}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_EXTGETSPORT2
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_NONE, terror}, //E_QUAD
		{S_EXTDADDR, setsport2}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_EXTDADDR
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_EXTDPORT, setdany}, //E_ANY
		{S_EXTGETDADDR, setdwc}, //E_HOST
		{S_EXTGETDWC, setdAddr}, //E_QUAD
		{S_NONE, terror}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_EXTGETDWC
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_EXTDPORT, setdwc}, //E_QUAD
		{S_NONE, terror}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, idle},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_EXTGETDADDR
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_EXTDPORT, setdAddr}, //E_QUAD
		{S_NONE, terror}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_EXTDPORT
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_NONE, terror}, //E_QUAD
		{S_LOCAL, setProtoParameter}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_TAGS, setIGMP},  //E_PROTO  This might be PIMv1 in an IGMP packet
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_EXTGETDPORT, setdrel},  //E_UNARY,
		{S_EXTGETDPORT1, setdrel},  //E_BINARY,
		{S_TAGS, flagTOS},  //E_TOS,
		{S_TAGS, flagLog},  //E_LOG,
		{S_TAGS, setIGMP},  //E_IGMPTYPE,
		{S_TAGS, setICMPcode},  //E_ICMPCODE,
		{S_TAGS, setICMPmsg},  //E_ICMPMSG,
		{S_TAGS, setEst},  //E_EST,
		{S_TAGS, setTCPflag},  //E_FLAGS,
		{S_TAGS, setPrecValue},  //E_PRECEDENCE,
		{S_TAGS, flagPrecedence},  //E_PRFLG,
		{S_TAGS, setTOSvalue},	//E_TOSVAL
		{S_TAGS, flagDSCP}, //E_DSCPFLG
		{S_TAGS, setDSCPvalue}, //E_DSCPVAL
		{S_LOCAL, idle},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_EXTGETDPORT
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_NONE, terror}, //E_QUAD
		{S_TAGS, setdport}, //E_INTEGER
		{S_DONE, finished}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_TAGS, setdportname},  //E_PORTUDP,
		{S_TAGS, setdportname},  //E_PORTTCP,
		{S_TAGS, setdportname},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, idle},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_TAGS, setdportname},  //E_RAWTEXT,
	},

	{ //S_EXTGETDPORT1
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_NONE, terror}, //E_QUAD
		{S_EXTGETDPORT2, setdport}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_EXTGETDPORT2
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_NONE, terror}, //E_QUAD
		{S_TAGS, setdport2}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_TAGS
		{S_NONE, terror}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_NONE, terror}, //E_QUAD
		{S_NONE, terror}, //E_INTEGER
		{S_DONE, finished}, //E_EOL
		{S_NONE, terror}, //E_STD
		{S_NONE, terror}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_TAGS, setIGMP},  //E_PROTO this could be PIMv1 in an IGMP packet
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_TAGS, flagTOS},  //E_TOS,
		{S_TAGS, flagLog},  //E_LOG,
		{S_TAGS, setIGMP},  //E_IGMPTYPE,
		{S_TAGS, setICMPcode},  //E_ICMPCODE,
		{S_TAGS, setICMPmsg},  //E_ICMPMSG,
		{S_TAGS, setEst},  //E_EST,
		{S_TAGS, setTCPflag},  //E_FLAGS,
		{S_TAGS, setPrecValue},  //E_PRECEDENCE,
		{S_TAGS, flagPrecedence},  //E_PRFLG,
		{S_TAGS, setTOSvalue},	//E_TOSVAL
		{S_TAGS, flagDSCP}, //E_DSCPFLG
		{S_TAGS, setDSCPvalue}, //E_DSCPVAL
		{S_LOCAL, idle},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_NONE, terror},  //E_RAWTEXT,
	},

	{ //S_NAMACL
		{S_NAMACL, initACL}, //E_ACL
		{S_NONE, terror}, //E_ACTION
		{S_NONE, terror}, //E_ANY
		{S_NONE, terror}, //E_HOST
		{S_NONE, terror}, //E_QUAD
		{S_NONE, terror}, //E_INTEGER
		{S_NONE, terror}, //E_EOL
		{S_NAMACL, idle}, //E_STD
		{S_NAMACL, idle}, //E_EXT
		{S_DONE, getRemark},  //E_REMARK,
		{S_NONE, terror},  //E_IP,
		{S_NONE, terror},  //E_ICMP,
		{S_NONE, terror},  //E_IGMP,
		{S_NONE, terror},  //E_UDP,
		{S_NONE, terror},  //E_TCP,
		{S_NONE, terror},  //E_PROTO
		{S_NONE, terror},  //E_PORTUDP,
		{S_NONE, terror},  //E_PORTTCP,
		{S_NONE, terror},  //E_PORTIP,
		{S_NONE, terror},  //E_UNARY,
		{S_NONE, terror},  //E_BINARY,
		{S_NONE, terror},  //E_TOS,
		{S_NONE, terror},  //E_LOG,
		{S_NONE, terror},  //E_IGMPTYPE,
		{S_NONE, terror},  //E_ICMPCODE,
		{S_NONE, terror},  //E_ICMPMSG,
		{S_NONE, terror},  //E_EST,
		{S_NONE, terror},  //E_FLAGS,
		{S_NONE, terror},  //E_PRECEDENCE,
		{S_NONE, terror},	//E_PRFLG,
		{S_NONE, terror},	//E_TOSVAL
		{S_NONE, terror}, //E_DSCPFLG
		{S_NONE, terror}, //E_DSCPVAL
		{S_NONE, terror},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_DONE, saveName},  //E_RAWTEXT,
	},

	{ //S_DONE
		{S_LOCAL, idle}, //E_ACL
		{S_LOCAL, idle}, //E_ACTION
		{S_LOCAL, idle}, //E_ANY
		{S_LOCAL, idle}, //E_HOST
		{S_LOCAL, idle}, //E_QUAD
		{S_LOCAL, idle}, //E_INTEGER
		{S_DONE, finished}, //E_EOL
		{S_LOCAL, idle}, //E_STD
		{S_LOCAL, idle}, //E_EXT
		{S_DONE, idle},  //E_REMARK,
		{S_LOCAL, idle},  //E_IP,
		{S_LOCAL, idle},  //E_ICMP,
		{S_LOCAL, idle},  //E_IGMP,
		{S_LOCAL, idle},  //E_UDP,
		{S_LOCAL, idle},  //E_TCP,
		{S_LOCAL, idle},  //E_PROTO
		{S_LOCAL, idle},  //E_PORTUDP,
		{S_LOCAL, idle},  //E_PORTTCP,
		{S_LOCAL, idle},  //E_PORTIP,
		{S_LOCAL, idle},  //E_UNARY,
		{S_LOCAL, idle},  //E_BINARY,
		{S_LOCAL, idle},  //E_TOS,
		{S_LOCAL, idle},  //E_LOG,
		{S_LOCAL, idle},  //E_IGMPTYPE,
		{S_LOCAL, idle},  //E_ICMPCODE,
		{S_LOCAL, idle},  //E_ICMPMSG,
		{S_LOCAL, idle},  //E_EST,
		{S_LOCAL, idle},  //E_FLAGS,
		{S_LOCAL, idle},  //E_PRECEDENCE,
		{S_LOCAL, idle},	//E_PRFLG,
		{S_LOCAL, idle},	//E_TOSVAL
		{S_LOCAL, idle}, //E_DSCPFLG
		{S_LOCAL, idle}, //E_DSCPVAL
		{S_LOCAL, idle},	//E_IPOPT,
		{S_LOCAL, idle},	//E_IGNORE,
		{S_LOCAL, idle},  //E_RAWTEXT,
	},
};



/*********************************************************************************************
* There are many things that can appear in an ACL entry
* At the end of the day they fall into only a few general categories
* Integer	port and protocol numbers are the most common
* Quad 		IP addresses and wildcards 
* Text		port names, protocol names, ICMP codes and options, 
* Metavalues 	any, host, IP, access-list, log, etc.
* Relational Operators
*  Unary	lt, eq, ne, gt
*  binary	range
* 
* Any input symbol that isn't an integer or a quad is tokenized according to this structure
* which may be a candidate for a representation that is more efficient than O(n) 
* 
* Three elements to the structure: the string, its length for strnlen, the output token
***********************************************************************************************/

typedef struct {
	char 	*symbol;
	int	len;
	events_t token;
} str_t;

str_t strings[] = {
	{"access-list", 11, E_ACL},
	{"permit", 6, E_ACTION},
	{"deny", 4, E_ACTION},
	{"any", 3, E_ANY},
	{"host", 4, E_HOST},
	{"extended", 8, E_EXT},
	{"standard", 8, E_STD},
	{"log", 3, E_LOG},
	{"log-input", 9, E_LOG},
	{"est", 3, E_EST},
	{"established", 11, E_EST},
	{"remark", 6, E_REMARK},

	// Protocols these can also be entered as decimal values
	
	{"ip", 2, E_IP},	//       Any Internet Protocol	(0)
	{"tcp", 3, E_TCP},	//      Transmission Control Protocol (6)
	{"udp", 3, E_UDP},	//      User Datagram Protocol	(17)
	{"ahp", 3, E_PROTO},	//      Authentication Header Protocol (51) Normally called "ah"
	{"eigrp", 5, E_PROTO},	//    Cisco's EIGRP routing protocol (88)	
	{"esp", 3, E_PROTO},	//      Encapsulation Security Payload (50)
	{"gre", 3, E_PROTO},	//      Cisco's GRE tunneling  (47)
	{"icmp", 4, E_ICMP},	//     Internet Control Message Protocol (1)
	{"igmp", 4, E_IGMP},	//     Internet Group Management Protocol (2)
	{"ipinip", 6, E_PROTO},	//   IP in IP tunneling (94) (possibly 131)
	{"nos", 3, E_PROTO},	//      KA9Q NOS compatible IP over IP tunneling
	{"ospf", 4, E_PROTO},	//     OSPF routing protocol (89)
	{"pcp", 3, E_PROTO},	//      Payload Compression Protocol
	{"pim", 3, E_PROTO},	//      Protocol Independent Multicast (103)

	// Relational Operators
	
	{"range", 5, E_BINARY},
	{"lt", 2, E_UNARY},
	{"gt", 2, E_UNARY},
	{"neq", 3, E_UNARY},
	{"eq", 2, E_UNARY},

	// TCP Flags
	
	{"syn", 3, E_FLAGS},
	{"fin", 3, E_FLAGS},
	{"rst", 3, E_FLAGS},
	{"ack", 3, E_FLAGS},
	{"psh", 3, E_FLAGS},
	{"urg", 3, E_FLAGS},

	// DSCP code points  (note: the bit values represent the six high order bits in the octet, the two low order bits 
	//		MUST be ignored.)
	
	{"dscp", 4, E_DSCPFLG},
	{"af11", 4, E_DSCPVAL},	//     Match packets with AF11 dscp (001010)
	{"af12", 4, E_DSCPVAL},	//     Match packets with AF12 dscp (001100)
	{"af13", 4, E_DSCPVAL},	//     Match packets with AF13 dscp (001110)
	{"af21", 4, E_DSCPVAL},	//     Match packets with AF21 dscp (010010)
	{"af22", 4, E_DSCPVAL},	//     Match packets with AF22 dscp (010100)
	{"af23", 4, E_DSCPVAL},	//     Match packets with AF23 dscp (010110)
	{"af31", 4, E_DSCPVAL},	//     Match packets with AF31 dscp (011010)
	{"af32", 4, E_DSCPVAL},	//     Match packets with AF32 dscp (011100)
	{"af33", 4, E_DSCPVAL},	//     Match packets with AF33 dscp (011110)
	{"af41", 4, E_DSCPVAL},	//     Match packets with AF41 dscp (100010)
	{"af42", 4, E_DSCPVAL},	//     Match packets with AF42 dscp (100100)
	{"af43", 4, E_DSCPVAL},	//     Match packets with AF43 dscp (100110)
	{"cs1", 3, E_DSCPVAL},	//      Match packets with CS1(precedence 1) dscp (001000)
	{"cs2", 3, E_DSCPVAL},	//      Match packets with CS2(precedence 2) dscp (010000)
	{"cs3", 3, E_DSCPVAL},	//      Match packets with CS3(precedence 3) dscp (011000)
	{"cs4", 3, E_DSCPVAL},	//      Match packets with CS4(precedence 4) dscp (100000)
	{"cs5", 3, E_DSCPVAL},	//      Match packets with CS5(precedence 5) dscp (101000)
	{"cs6", 3, E_DSCPVAL},	//      Match packets with CS6(precedence 6) dscp (110000)
	{"cs7", 3, E_DSCPVAL},	//      Match packets with CS7(precedence 7) dscp (111000)
	{"default", 7, E_DSCPVAL},	//  Match packets with default dscp (000000)
	{"ef", 2, E_DSCPVAL},	//       Match packets with EF dscp (101110)

	// ICMP Messages and Codes these can also be entered as decimal values
	
	{"administratively-prohibited", 27, E_ICMPMSG },   // Administratively prohibited  3 13
	{"alternate-address", 17, E_ICMPMSG },             // Alternate address  6 0
	{"conversion-error", 16, E_ICMPMSG },              // Datagram conversion  31 0
	{"dod-host-prohibited",19, E_ICMPMSG },           // Host prohibited  3 10
	{"dod-net-prohibited", 18, E_ICMPMSG },            // Net prohibited  3  9
	{"echo", 4, E_ICMPMSG },                     	   // Echo (ping) 8 0
	{"echo-reply", 10, E_ICMPMSG },                    // Echo reply   0 0
	{"general-parameter-problem", 25, E_ICMPMSG },     // Parameter problem  12 0
	{"host-isolated", 13, E_ICMPMSG },                 // Host isolated 3 8
	{"host-precedence-unreachable", 27, E_ICMPMSG },   // Host unreachable for precedence    3 14
	{"host-redirect", 13, E_ICMPMSG },                 // Host redirect  5 1
	{"host-tos-redirect", 17, E_ICMPMSG },             // Host redirect for TOS   5   3
	{"host-tos-unreachable", 20, E_ICMPMSG },          // Host unreachable for TOS   3  12
	{"host-unknown", 12, E_ICMPMSG },                  // Host unknown    3  7
	{"host-unreachable", 16, E_ICMPMSG },              // Host unreachable  3  1
	{"information-reply", 17, E_ICMPMSG },             // Information replies  16  0
	{"information-request", 19, E_ICMPMSG },           // Information requests  15  0
	{"mask-reply", 10, E_ICMPMSG },                    // Mask replies  18  0
	{"mask-request", 12, E_ICMPMSG },                  // Mask requests  17  0
	{"mobile-redirect", 15, E_ICMPMSG },               // Mobile host redirect 32 0
	{"net-redirect", 12, E_ICMPMSG },                  // Network redirect  5 0
	{"net-tos-redirect", 16, E_ICMPMSG },              // Net redirect for TOS  5  2
	{"net-tos-unreachable", 19, E_ICMPMSG },           // Network unreachable for TOS  3  11
	{"net-unreachable", 15, E_ICMPMSG },               // Net unreachable  3  0
	{"network-unknown", 15, E_ICMPMSG },               // Network unknown  3  6
	{"no-room-for-option", 18, E_ICMPMSG },            // Parameter required but no room 12  2
	{"option-missing", 14, E_ICMPMSG },                // Parameter required but not present  12  1
	{"packet-too-big", 14, E_ICMPMSG },                // Fragmentation needed and DF set   3  4
	{"parameter-problem", 17, E_ICMPMSG },             // All parameter problems  12
	{"port-unreachable", 16, E_ICMPMSG },              // Port unreachable  3  3
	{"precedence-unreachable", 22, E_ICMPMSG },        // Precedence cutoff  3  15
	{"protocol-unreachable", 20, E_ICMPMSG },          // Protocol unreachable  3  2
	{"reassembly-timeout", 18, E_ICMPMSG },            // Reassembly timeout  11  1
	{"redirect", 8, E_ICMPMSG },                       // All redirects  5
	{"router-advertisement", 20, E_ICMPMSG },          // Router discovery advertisements  9 0
	{"router-solicitation", 19, E_ICMPMSG },           // Router discovery solicitations  10 0
	{"source-quench", 13, E_ICMPMSG },                 // Source quenches  4 0
	{"source-route-failed", 19, E_ICMPMSG },           // Source route failed    3  5
	{"time-exceeded", 13, E_ICMPMSG },                 // All time exceededs   11
	{"timestamp-reply", 15, E_ICMPMSG },               // Timestamp replies  14 0
	{"timestamp-request", 17, E_ICMPMSG },             // Timestamp requests 13 0
	{"traceroute", 10, E_ICMPMSG },                    // Traceroute 30 0
	{"ttl-exceeded", 12, E_ICMPMSG },                  // TTL exceeded    11  1
	{"unreachable", 11, E_ICMPMSG },                   // All unreachables 3 

	// IGMP Types these can also be entered as decimal values
	
	{"dvmrp", 5, E_IGMPTYPE},		//          Distance Vector Multicast Routing Protocol(19)
	{"host-query", 10, E_IGMPTYPE},	//     IGMP Membership Query(17)
	{"mtrace-resp", 11, E_IGMPTYPE},	//    Multicast Traceroute Response(30)
	{"mtrace-route", 12, E_IGMPTYPE},	//   Multicast Traceroute(31)
	{"trace", 5, E_IGMPTYPE},		//          Multicast trace(21)
	{"v1host-report", 13, E_IGMPTYPE},	//  IGMPv1 Membership Report(18)
	{"v2host-report", 13, E_IGMPTYPE},	//  IGMPv2 Membership Report(22)
	{"v3host-report", 13, E_IGMPTYPE},	//  IGMPv3 Membership Report(34)
	{"v2leave-group", 13, E_IGMPTYPE},	//  IGMPv2 Leave Group(23)

	//  PIM Version 1 was transported over IGMP this is a conflict that is handled in the state machine 
	//	because the match with the protocol name will be made much earlier and the event will be E_PROTO
	//	the value handler routine will prevent any other protocol name from being accepted as an IGMP type
	
	{"pim", 3, E_IGMPTYPE},			//  PIMv1(20)

	// TOS these can also be entered as decimal values
	
	{"tos", 3, E_TOS},
	{"max-reliability", 15, E_TOSVAL},	//    Match packets with max reliable TOS (2)
	{"max-throughput", 14, E_TOSVAL},	//     Match packets with max throughput TOS (4)
	{"min-delay", 9, E_TOSVAL},	//          Match packets with min delay TOS (8)
	{"min-monetary-cost", 17, E_TOSVAL},	//  Match packets with min monetary cost TOS (1)
	{"normal", 6, E_TOSVAL},	//             Match packets with normal TOS (0)
	// Precedence these can also be entered as decimal values
	{"precedence", 10, E_PRFLG},
	{"critical", 8, E_PRECEDENCE},	//        Match packets with critical precedence (5)
	{"flash", 5, E_PRECEDENCE},	//           Match packets with flash precedence (3)
	{"flash-override", 14, E_PRECEDENCE},	//  Match packets with flash override precedence (4)
	{"immediate", 9, E_PRECEDENCE},	//       Match packets with immediate precedence (2)
	{"internet", 8, E_PRECEDENCE},	//        Match packets with internetwork control precedence (6)
	{"network", 7, E_PRECEDENCE},	//         Match packets with network control precedence (7)
	{"priority", 8, E_PRECEDENCE},	//        Match packets with priority precedence (1)
	{"routine", 7, E_PRECEDENCE},	//         Match packets with routine precedence (0)

	// IP Header Options these can also be entered as decimal values
	// more than a single value may be associated with a flow, we may need to encode these as
	// a bit vector and set the bit at the appropriate offset for each optikon seen in a flow
	// obviously this depends on Argus and its internal representation of the material
	// for now, we are parsing the values but not using them to make a permit or deny choice
	
	{"add-ext", 7, E_IPOPT},	//       Match packets with Address Extension Option (147)
	{"any-options", 11, E_IPOPT},	//   Match packets with ANY Option
	{"com-security", 12, E_IPOPT},	//  Match packets with Commercial Security Option (134)
	{"dps", 3, E_IPOPT},	//           Match packets with Dynamic Packet State Option (151)
	{"encode", 6, E_IPOPT},	//        Match packets with Encode Option (15)
	{"eool", 4, E_IPOPT},	//          Match packets with End of Options (0)
	{"ext-ip", 6, E_IPOPT},	//        Match packets with Extended IP Option (145)
	{"ext-security", 13, E_IPOPT},	//  Match packets with Extended Security Option (133)
	{"finn", 4, E_IPOPT},	//          Match packets with Experimental Flow Control Option (205)
	{"imitd", 5, E_IPOPT},	//         Match packets with IMI Traffic Desriptor Option (144)
	{"lsr", 3, E_IPOPT},	//           Match packets with Loose Source Route Option (131)
	{"mtup", 4, E_IPOPT},	//          Match packets with MTU Probe Option (11)
	{"mtur", 4, E_IPOPT},	//          Match packets with MTU Reply Option (12)
	{"no-op", 5, E_IPOPT},	//         Match packets with No Operation Option (1)
	{"nsapa", 5, E_IPOPT},	//         Match packets with NSAP Addresses Option (150)
	{"record-route", 12, E_IPOPT},	//  Match packets with Record Route Option (7)
	{"router-alert", 12, E_IPOPT},	//  Match packets with Router Alert Option (148)
	{"sdb", 3, E_IPOPT},	//           Match packets with Selective Directed Broadcast Option (149)
	{"security", 8, E_IPOPT},	//      Match packets with Basic Security Option (130)
	{"ssr", 3, E_IPOPT},	//           Match packets with Strict Source Routing Option (137)
	{"stream-id", 9, E_IPOPT},	//     Match packets with Stream ID Option (136)
	{"timestamp", 9, E_IPOPT},	//     Match packets with Time Stamp Option (68)
	{"traceroute", 10, E_IPOPT},	//    Match packets with Trace Route Option (82)
	{"ump", 3, E_IPOPT},	//           Match packets with Upstream Multicast Packet Option (152)
	{"visa", 4, E_IPOPT},	//          Match packets with Experimental Access Control Option (142)
	{"zsu", 3, E_IPOPT},	//           Match packets with Experimental Measurement Option (10)

	// Things that we need to ignore for now
	
	{"drip", 4, E_IGNORE},
	{"fragments", 9, E_IGNORE},
	{"time-range", 10, E_IGNORE},
	{"non500-isakmp", 13, E_IGNORE},
	{"reflex", 6, E_IGNORE},
	{"", 0, E_NULL},
};


/***********************************************************************************************************************
 * Values used in mapping  specific components of an access list entry from a name to an internal representation
 * ********************************************************************************************************************/
struct tlv {
 char *name;
 int len;
 int value;
 } ;

typedef struct tlv tlv_t;


 tlv_t igmpmap [] =   
{
	{"dvmrp", 5, 19},               //          Distance Vector Multicast Routing Protocol
        {"host-query", 10, 17}, 	//  	   IGMP Membership Query
        {"mtrace-resp", 11, 30},        //    Multicast Traceroute Response
        {"mtrace-route", 12, 31},       //   	Multicast Traceroute
        {"trace", 5, 21},               //      Multicast trace
        {"v1host-report", 13, 18},      //  IGMPv1 Membership Report
        {"v2host-report", 13, 22},      //  IGMPv2 Membership Report
        {"v3host-report", 13, 34},      //  IGMPv3 Membership Report
        {"v2leave-group", 13, 23},      //  IGMPv2 Leave Group
        {"pim", 3, 20},      		// PIMv1 
	{"", 0, 0}
};

/******************************************************************************************************
 * The six most significant bits of one of the IP header bytes have been defined and redefined
 * as experience with the realities of the Internet came to be understood.
 * The two least significant bits of this same byte were taken for use as ECN (explicit
 * congestion notification) indicators
 *
 * If we are using the RFC 4274 definitions of this byte
 * The six most significant bits taken as a set became the DiffServ Code Points
 * The three most significant bits still retained there original IP precedence meanings
 * Whenever the three least significant bits are all set to 0 the DSCP code point name
 * is designated as CS (Class Selector) and a value between 0 and 7.
 * If any of the three least significant bits are set, then the code point is designated
 * AF (Assured Forwarding) or EF (Expedited Forwarding) 
 *
 * If we are using the RFC 791 / RFC 1349 definitions of this byte
 * The least significant bit is always 0
 * The three most significant bits are the IP precedence
 * The four bits in between are the TOS value
 * 
 * Effectively we inspect the same set of bits three different ways to match
 * TOS, DSCP, and Precedence.
 * TOS = ( (byteValue > 1) & 0x0f)
 * Precedence = ( byteValue >> 5)
 * DSCP = ( byteValue >> 2)
 *
 * The shifts are zero extended (unsigned) 
 *******************************************************************************************************/
tlv_t precmap [] =   
{
	{"critical", 8, 5},  //        Match packets with critical precedence (5)
        {"flash", 5, 3},     //           Match packets with flash precedence (3)
        {"flash-override", 14, 4},   //  Match packets with flash override precedence (4)
        {"immediate", 9, 2}, //       Match packets with immediate precedence (2)
        {"internet", 8, 6},  //        Match packets with internetwork control precedence (6)
        {"network", 7, 7},   //         Match packets with network control precedence (7)
        {"priority", 8, 1},  //        Match packets with priority precedence (1)
        {"routine", 7, 0},   //         Match packets with routine precedence (0)
	{"",0,0}
};


 tlv_t tosmap [] =  
{
       	 {"max-reliability", 14, 2},      //    Match packets with max reliable TOS (2)
       	 {"max-throughput", 13, 4},       //     Match packets with max throughput TOS (4)
       	 {"min-delay", 9, 8},     //          Match packets with min delay TOS (8)
       	 {"min-monetary-cost", 16, 1},    //  Match packets with min monetary cost TOS (1)
       	 {"normal", 6, 0},        //             Match packets with normal TOS (0)
	 {"", 0, 0}
};


 tlv_t DSCPmap [] =  
{
        {"af11", 4, 10}, //     Match packets with AF11 dscp (001010)
        {"af12", 4, 12}, //     Match packets with AF12 dscp (001100)
        {"af13", 4, 14}, //     Match packets with AF13 dscp (001110)
        {"af21", 4, 18}, //     Match packets with AF21 dscp (010010)
        {"af22", 4, 20}, //     Match packets with AF22 dscp (010100)
        {"af23", 4, 22}, //     Match packets with AF23 dscp (010110)
        {"af31", 4, 26}, //     Match packets with AF31 dscp (011010)
        {"af32", 4, 28}, //     Match packets with AF32 dscp (011100)
        {"af33", 4, 30}, //     Match packets with AF33 dscp (011110)
        {"af41", 4, 34}, //     Match packets with AF41 dscp (100010)
        {"af42", 4, 36}, //     Match packets with AF42 dscp (100100)
        {"af43", 4, 38}, //     Match packets with AF43 dscp (100110)
        {"cs1", 3, 8},  //      Match packets with CS1(precedence 1) dscp (001000)
        {"cs2", 3, 16},  //     Match packets with CS2(precedence 2) dscp (010000)
        {"cs3", 3, 24},  //     Match packets with CS3(precedence 3) dscp (011000)
        {"cs4", 3, 32},  //     Match packets with CS4(precedence 4) dscp (100000)
        {"cs5", 3, 40},  //     Match packets with CS5(precedence 5) dscp (101000)
        {"cs6", 3, 48},  //     Match packets with CS6(precedence 6) dscp (110000)
        {"cs7", 3, 56},  //     Match packets with CS7(precedence 7) dscp (111000)
        {"default", 7, 0},  //  Match packets with default dscp (000000)
        {"ef", 2, 46},   //     Match packets with EF dscp (101110)
	{"", 0, 0}
};

struct tlv2 {
 char *name;
 int len;
 int value1;
 int value2;
 };

typedef struct tlv2 tlv2_t;

tlv2_t icmpmap [] =
{
        {"administratively-prohibited", 26, 3,13 },   // Administratively prohibited  3 13
        {"alternate-address", 17, 6, 0 },             // Alternate address  6 0
        {"conversion-error", 16, 31, 0 },              // Datagram conversion  31 0
        {"dod-host-prohibited", 20, 3, 10 },           // Host prohibited  3 10
        {"dod-net-prohibited", 19, 3, 9 },            // Net prohibited  3  9
        {"echo", 4, 8, 0 },                           // Echo (ping) 8 0
        {"echo-reply", 10, 0, 0 },                    // Echo reply   0 0
        {"general-parameter-problem", 25, 12, 0 },     // Parameter problem  12 0
        {"host-isolated", 12, 3, 8 },                 // Host isolated 3 8
        {"host-precedence-unreachable", 28, 3, 14 },   // Host unreachable for precedence    3 14
        {"host-redirect", 12, 5, 1 },                 // Host redirect  5 1
        {"host-tos-redirect", 10, 5, 3 },             // Host redirect for TOS   5   3
        {"host-tos-unreachable", 20, 3,12 },          // Host unreachable for TOS   3  12
        {"host-unknown", 12, 3, 7 },                  // Host unknown    3  7
        {"host-unreachable", 16, 3, 1 },              // Host unreachable  3  1
        {"information-reply", 17, 16, 0 },             // Information replies  16  0
        {"information-request", 19, 15, 0 },           // Information requests  15  0
        {"mask-reply", 10, 18, 0 },                    // Mask replies  18  0
        {"mask-request", 12, 17, 0 },                  // Mask requests  17  0
        {"mobile-redirect", 16, 32, 0 },               // Mobile host redirect 32 0
        {"net-redirect", 12, 5, 0 },                  // Network redirect  5 0
        {"net-tos-redirect", 17, 5, 2 },              // Net redirect for TOS  5  2
        {"net-tos-unreachable", 20, 3, 11 },           // Network unreachable for TOS  3  11
        {"net-unreachable", 17,  3, 0 },               // Net unreachable  3  0
        {"network-unknown", 17, 3, 6 },               // Network unknown  3  6
        {"no-room-for-option", 20, 12, 2 },            // Parameter required but no room 12  2
        {"option-missing", 17, 12, 1 },                // Parameter required but not present  12  1
        {"packet-too-big", 17, 3, 4 },                // Fragmentation needed and DF set   3  4
        {"parameter-problem", 20, 12, ICMPCodeAny },             // All parameter problems  12
        {"port-unreachable", 19, 3, 3 },              // Port unreachable  3  3
        {"precedence-unreachable", 25, 3, 15 },        // Precedence cutoff  3  15
        {"protocol-unreachable", 23,  3, 2 },          // Protocol unreachable  3  2
        {"reassembly-timeout", 18, 11, 1 },            // Reassembly timeout  11  1
        {"redirect", 8,  5, ICMPCodeAny },                       // All redirects  5
        {"router-advertisement", 20, 9, 0 },          // Router discovery advertisements  9 0
        {"router-solicitation", 19, 10, 0 },           // Router discovery solicitations  10 0
        {"source-quench", 13, 4, 0 },                 // Source quenches  4 0
        {"source-route-failed", 19, 3, 5 },           // Source route failed    3  5
        {"time-exceeded", 13, 11, ICMPCodeAny },                 // All time exceededs   11
        {"timestamp-reply", 15, 14, 0 },               // Timestamp replies  14 0
        {"timestamp-request", 17, 13, 0 },             // Timestamp requests 13 0
        {"traceroute", 10, 30, 0 },                    // Traceroute 30 0
        {"ttl-exceeded", 12, 11, 0 },                  // TTL exceeded    11  1
        {"unreachable", 11, 3, ICMPCodeAny },                   // All unreachables 3
        {"", 0, 0, 0 },                   
};

#endif //  RA_POLICY_C

#ifdef __cplusplus
}
#endif
#endif
