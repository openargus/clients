/* $Id: parser.c,v 1.3 2004/05/14 15:44:35 qosient Exp $ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>
#include <ctype.h>
#ifndef WIN32
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <grp.h>
#include <pwd.h>
#endif /* !WIN32 */
#include <unistd.h>

#include "preprocessors/flow/flow_print.h"
#include "rules.h"
#include "parser.h"
#include "plugbase.h"
#include "debug.h"
#include "util.h"
#include "mstring.h"
#include "detect.h"
#include "fpcreate.h"
#include "log.h"
#include "generators.h"
#include "tag.h"
#include "signature.h"
#include "sfthreshold.h"
#include "sfutil/sfthd.h"
#include "snort.h"

PV pv;              /* program vars */
PacketCount pc;     /* packet count info */

char *groupname = NULL;
char *username  = NULL;

unsigned long groupid = 0;
unsigned long userid  = 0;

struct passwd *pw;
struct group *gr;

#include <argus_client.h>


void LogMessage(const char *str, ...){};


ListHead Alert;       /* Alert Block Header */
ListHead Log;         /* Log Block Header */
ListHead Pass;        /* Pass Block Header */
ListHead Activation;   /* Activation Block Header */
ListHead Dynamic;      /* Dynamic Block Header */

RuleTreeNode *rtn_tmp;     /* temp data holder */
OptTreeNode *otn_tmp;      /* OptTreeNode temp ptr */
ListHead *head_tmp = NULL;  /* ListHead temp ptr */

RuleListNode *RuleLists;

struct VarEntry *VarHead = NULL;

char *file_name;      /* current rules file being processed */
int file_line;        /* current line being processed in the rules
               * file */
int list_file_line;    /* current line being processed in the list
               * file */
int rule_count;       /* number of rules generated */
int head_count;       /* number of header blocks (chain heads?) */
int opt_count;        /* number of chains */

int dynamic_rules_present;
int active_dynamic_nodes;

extern unsigned int giFlowbitSize; /** size of flowbits tracking */

KeywordXlateList *KeywordList = NULL;   /* detection/response plugin keywords */
PreprocessKeywordList *PreprocessKeywords = NULL;   /* preprocessor plugin * keywords */
OutputFuncNode *AlertList = NULL;   /* Alert function list */
OutputFuncNode *LogList = NULL; /* log function list */

/* Local Function Declarations */
void ProcessHeadNode(RuleTreeNode *, ListHead *, int);
void ParseSID(char *, OptTreeNode *);
void ParseRev(char *, OptTreeNode *);
void XferHeader(RuleTreeNode *, RuleTreeNode *);
void DumpChain(RuleTreeNode *, char *, char *);
void IntegrityCheck(RuleTreeNode *, char *, char *);
void SetLinks(RuleTreeNode *, RuleTreeNode *);
int ProcessIP(char *, RuleTreeNode *, int );
IpAddrSet *AllocAddrNode(RuleTreeNode *, int );
int TestHeader(RuleTreeNode *, RuleTreeNode *);
RuleTreeNode *GetDynamicRTN(int, RuleTreeNode *);
OptTreeNode *GetDynamicOTN(int, RuleTreeNode *);
void AddrToFunc(RuleTreeNode *, int);
void PortToFunc(RuleTreeNode *, int, int, int);
void SetupRTNFuncList(RuleTreeNode *);

void RaSnortInit (char *);
     
void
RaSnortInit (char *confile)
{
   bzero (&pv, sizeof(pv));
   /* initialize the packet counter to loop forever */
   pv.pkt_cnt = -1; 
     
   /* set the default alert mode */
   pv.alert_mode = ALERT_FULL; 
     
   /* set the default assurance mode (used with stream 4) */
   pv.assurance_mode = ASSURE_ALL; 
     
   /* turn on checksum verification by default */
   pv.checksums_mode = DO_IP_CHECKSUMS | DO_TCP_CHECKSUMS |
                       DO_UDP_CHECKSUMS | DO_ICMP_CHECKSUMS;

   if (!pv.log_dir) {
      if ((pv.log_dir = strdup(DEFAULT_LOG_DIR)) == NULL) {
         ArgusLog(LOG_ERR,"RaSnortInit default log dir is NULL"); 
      }
   }

   if ((pv.config_file = strdup(confile)) != NULL) {
      /* is there a directory seperator in the filename */
      if(strrchr(pv.config_file,'/')) {
         char *tmp; 
         /* lazy way, we waste a few bytes of memory here */
         if(!(pv.config_dir = strdup(pv.config_file)))
            ArgusLog(LOG_ERR, "Out of memory extracting config dir\n");
             
         tmp = strrchr(pv.config_dir,'/'); 
         *(++tmp) = '\0';
      } else {
#ifdef WIN32
        /* is there a directory seperator in the filename */
         if(strrchr(pv.config_file,'\\')) {
            char *tmp;  
            /* lazy way, we waste a few bytes of memory here */
            if(!(pv.config_dir = strdup(pv.config_file)))
                ArgusLog(LOG_ERR, "Out of memory extracting config dir\n"); 
             
            tmp = strrchr(pv.config_dir,'\\'); 
            *(++tmp) = '\0';
         } else     
#endif       
            if (!(pv.config_dir = strdup("./")))
                ArgusLog(LOG_ERR, "Out of memory extracting config dir\n");
        }
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "Config file = %s, config dir = "
                    "%s\n", pv.config_file, pv.config_dir););
   }

   InitPlugIns();
   CreateDefaultRules();
}



/****************************************************************************
 *
 * Function: ParseRulesFile(char *, int)
 *
 * Purpose:  Read the rules file a line at a time and send each rule to
 *         the rule parser
 *
 * Arguments: file => rules file filename
 *         inclevel => nr of stacked "include"s
 *
 * Returns: void function
 *
 ***************************************************************************/
void
ParseRulesFile(char *file, int inclevel)
{
   FILE *thefp;      /* file pointer for the rules file */
   char buf[STD_BUF];     /* file read buffer */
   char *index;      /* buffer indexing pointer */
   char *stored_file_name = file_name;
   int stored_file_line = file_line;
   char *saved_line = NULL;
   int continuation = 0;
   char *new_line = NULL;
   struct stat file_stat; /* for include path testing */

   if(inclevel == 0) {
      if(!pv.quiet_flag) {
         LogMessage("\n+++++++++++++++++++++++++++++++++++++++++++++++++++\n");
         LogMessage("Initializing rule chains...\n");
      }
   }

   stored_file_line = file_line;
   stored_file_name = file_name;
   file_line = 0;
   
   /* Changed to
   *  stat the file relative to the  current directory
   *  if that fails - stat it relative to the directory
   *  that the configuration file was in
   */ 

   file_name = strdup(file);
   if(file_name == NULL) {
      ArgusLog(LOG_ERR,"ParseRulesFile strdup failed: %s\n", strerror(errno));
   }

   /* Well the file isn't the one that we thought it was - lets
     try the file relative to the current directory
   */
   
   if(stat(file_name, &file_stat) < 0) {
      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"ParseRulesFile: stat "
                     "on %s failed - going to config_dir\n", file_name););
   
      free(file_name);

      file_name = calloc(strlen(file) + strlen(pv.config_dir) + 1, sizeof(char));
      if(file_name == NULL) 
         ArgusLog(LOG_ERR,"ParseRulesFile calloc failed: %s\n", strerror(errno));

      strncpy(file_name, pv.config_dir, strlen(file) + strlen(pv.config_dir) + 1);
      strncat(file_name, file, strlen(file) + strlen(pv.config_dir) + 1);

      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"ParseRulesFile: Opening "
               "and parsing %s\n", file_name););
   }

   /* open the rules file */
   if((thefp = fopen(file_name, "r")) == NULL)
      ArgusLog(LOG_ERR,"Unable to open rules file: %s or %s\n", file, file_name);

   /* clear the line buffer */
   bzero((char *) buf, STD_BUF);

   /* loop thru each file line and send it to the rule parser */
   while((fgets(buf, STD_BUF, thefp)) != NULL) {
      /*
      * inc the line counter so the error messages know which line to
      * bitch about
      */
      file_line++;

      index = buf;

#ifdef DEBUG2
      LogMessage("Got line %s (%d): %s", file_name, file_line, buf);
#endif
   /* advance through any whitespace at the beginning of the line */
      while(*index == ' ' || *index == '\t')
         index++;

   /* if it's not a comment or a <CR>, send it to the parser */
      if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL)) {
         if(continuation == 1) {
            new_line = (char *) calloc((strlen(saved_line) + strlen(index) +1), sizeof(char)); 
            strncat(new_line, saved_line, strlen(saved_line));
            strncat(new_line, index, strlen(index));
            free(saved_line);
            saved_line = NULL;
            index = new_line;

            if(strlen(index) > PARSERULE_SIZE) {
               ArgusLog(LOG_ERR,"Please don't try to overflow the parser, "
                     "that's not very nice of you... (%d-byte "
                     "limit on rule size)\n", PARSERULE_SIZE);
            }

            DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"concat rule: %s\n", new_line););
         }

      /* check for a '\' continuation character at the end of the line
      * if it's there we need to get the next line in the file
      */
         if(ContinuationCheck(index) == 0) {
            DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES, "[*] Processing rule: %s\n", index););

            ParseRule(thefp, index, inclevel);

            if(new_line != NULL) {
               free(new_line);
               new_line = NULL;
               continuation = 0;
            }

         } else {
            /* save the current line */
            saved_line = strdup(index);

            /* set the flag to let us know the next line is 
            * a continuation line
            */ 
            continuation = 1;
         }   
      }
      bzero((char *) buf, STD_BUF);
   }

   if(file_name)
      free(file_name);

   file_name = stored_file_name;
   file_line = stored_file_line;

   if(inclevel == 0 && !pv.quiet_flag) {
      LogMessage("%d Snort rules read...\n", rule_count);
      LogMessage("%d Option Chains linked into %d Chain Headers\n", opt_count, head_count);
      LogMessage("%d Dynamic rules\n", dynamic_rules_present);
      LogMessage("+++++++++++++++++++++++++++++++++++++++++++++++++++\n\n");
   }

   fclose(thefp);

   /* plug all the dynamic rules together */
   if(dynamic_rules_present)
      LinkDynamicRules();

   if(inclevel == 0) {
#ifdef DEBUG
      DumpRuleChains();
#endif
      IntegrityCheckRules();
      /*FindMaxSegSize();*/
   }
   return;
}



int
ContinuationCheck(char *rule)
{
   char *idx;  /* indexing var for moving around on the string */

   idx = rule + strlen(rule) - 1;

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"initial idx set to \'%c\'\n", *idx););

   while(isspace((int)*idx))
   idx--;

   if(*idx == '\\') {
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Got continuation char, "
            "clearing char and returning 1\n"););
   /* clear the '\' so there isn't a problem on the appended string */
   *idx = '\x0';
   return 1;
   }
   return 0;
}


int
CheckRule(char *str) {
   int len;
   int got_paren = 0;
   int got_semi = 0;
   char *index;

   len = strlen(str);
   index = str + len - 1; /* go to the end of the string */

   while((isspace((int)*index))) {
   if(index > str)
      index--;
   else
      return 0;
   }

   /* the last non-whitspace character should be a ')' */
   if(*index == ')') {
   got_paren = 1;
   index--;
   }

   while((isspace((int)*index))) {
   if(index > str)
      index--;
   else
      return 0;
   }

   /* the next to last char should be a semicolon */
   if(*index == ';') {
   got_semi = 1;
   }

   if(got_semi && got_paren) {
   return 1;
   } else {
   /* check for a '(' to make sure that rule options are being used... */
   for(index = str; index < str+len; index++) {
      if(*index == '(') {
         return 0;
      }
   }
   return 1;
   }
}

void
DumpRuleChains() {
   RuleListNode *rule;

   rule = RuleLists;

   while(rule != NULL) {
   DumpChain(rule->RuleList->IpList, rule->name, "IP Chains");
   DumpChain(rule->RuleList->TcpList, rule->name, "TCP Chains");
   DumpChain(rule->RuleList->UdpList, rule->name, "UDP Chains");
   DumpChain(rule->RuleList->IcmpList, rule->name, "ICMP Chains");
   rule = rule->next;
   }
}

void
IntegrityCheckRules() {
   RuleListNode *rule;

   rule = RuleLists;

   if(!pv.quiet_flag) {
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Performing Rule "
            "List Integrity Tests...\n"););
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"----------------"
            "-----------------------\n"););
   }

   while(rule != NULL) {
   IntegrityCheck(rule->RuleList->IpList, rule->name, "IP Chains");
   IntegrityCheck(rule->RuleList->TcpList, rule->name, "TCP Chains");
   IntegrityCheck(rule->RuleList->UdpList, rule->name, "UDP Chains");
   IntegrityCheck(rule->RuleList->IcmpList, rule->name, "ICMP Chains");
   rule = rule->next;
   }

   if(!pv.quiet_flag) {
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,
            "---------------------------------------\n\n"););
   }
}

/****************************************************************************
 *
 * Function: ParseRule(FILE*, char *, int)
 *
 * Purpose:  Process an individual rule and add it to the rule list
 *
 * Arguments: rule => rule string
 *         inclevel => nr of stacked "include"s
 *
 * Returns: void function
 *
 ***************************************************************************/
void
ParseRule(FILE *rule_file, char *prule, int inclevel) {
   char **toks;      /* dbl ptr for mSplit call, holds rule tokens */
   int num_toks;      /* holds number of tokens found by mSplit */
   int rule_type;     /* rule type enumeration variable */
   char rule[PARSERULE_SIZE];
   int protocol = 0;
   char *tmp;
   RuleTreeNode proto_node;
   RuleListNode *node = RuleLists;

   /* chop off the <CR/LF> from the string */
   tmp = &prule[strlen(prule) - 1];
   while (isspace(*tmp)) {*tmp-- = '\0';}

   /* expand all variables */
   bzero((void *)rule, sizeof(rule));

   strncpy(rule, ExpandVars(prule), PARSERULE_SIZE-1);

   /* break out the tokens from the rule string */
   toks = mSplit(rule, " ", 10, &num_toks, 0);

   /* clean house */
   bzero((char *) &proto_node, sizeof(RuleTreeNode));

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"[*] Rule start\n"););

   /* figure out what we're looking at */
   rule_type = RuleType(toks[0]);

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Rule type: "););

   /* handle non-rule entries */
   switch(rule_type) {
      case RULE_PASS:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Pass\n"););
         break;

      case RULE_LOG:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Log\n"););
         break;

      case RULE_ALERT:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Alert\n"););
         break;

      case RULE_INCLUDE:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Include\n"););
         if(*toks[1] == '$') {
            if((tmp = VarGet(toks[1]+1)) == NULL) {
               ArgusLog(LOG_ERR,"%s(%d) => Undefined variable %s\n", 
                       file_name, file_line, toks[1]);
            }
         } else {
            tmp = toks[1];
         }

         ParseRulesFile(tmp, inclevel + 1);
         mSplitFree(&toks, num_toks);
         return;

      case RULE_VAR:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Variable\n"););
         VarDefine(toks[1], toks[2]);
         mSplitFree(&toks, num_toks);
         return;

      case RULE_PREPROCESS:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Preprocessor\n"););
         mSplitFree(&toks, num_toks);
         return;

      case RULE_OUTPUT:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Output Plugin\n"););
         ParseOutputPlugin(rule);
         mSplitFree(&toks, num_toks);
         return;

      case RULE_ACTIVATE:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Activation rule\n"););
         break;

      case RULE_DYNAMIC:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Dynamic rule\n"););
         break;
 
      case RULE_CONFIG: 
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Rule file config\n"););
         ParseConfig(rule); 
         mSplitFree(&toks, num_toks);
         return; 

      case RULE_DECLARE:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Rule type declaration\n"););
         ParseRuleTypeDeclaration(rule_file, rule);
         mSplitFree(&toks, num_toks);
         return;
    
      case RULE_THRESHOLD:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Threshold\n"););
         ParseSFThreshold(rule_file, rule);
         mSplitFree(&toks, num_toks);
         return;
      
      case RULE_SUPPRESS:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Suppress\n"););
         ParseSFSuppress(rule_file, rule);
         mSplitFree(&toks, num_toks);
         return;
    
      case RULE_UNKNOWN:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Unknown rule type, might be declared\n"););

         /* find out if this ruletype has been declared */
         while(node != NULL) {
            if(!strcasecmp(node->name, toks[0]))
               break;
            node = node->next;
         }

         if(node == NULL)
            ArgusLog(LOG_ERR,"%s(%d) => Unknown rule type: %s\n", file_name, file_line, toks[0]);
         break; 

      default:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Invalid input: %s\n", prule););
         mSplitFree(&toks, num_toks);
         return;
   }

   if (num_toks < 7) 
      ArgusLog(LOG_ERR,"%s(%d): Bad rule in rules file\n", file_name, file_line);

   if(!CheckRule(prule)) {
      ArgusLog(LOG_ERR,"Unterminated rule in file %s, line %d\n" 
              "   (Snort rules must be contained on a single line or\n"
              "   on multiple lines with a '\\' continuation character\n"
              "   at the end of the line,  make sure there are no\n"
              "   carriage returns before the end of this line)\n",
              file_name, file_line);
      return;
   }

   if (rule_type == RULE_UNKNOWN)
      proto_node.type = node->mode;
   else
      proto_node.type = rule_type;

   /* set the rule protocol */
   protocol = WhichProto(toks[1]);

   /* Process the IP address and CIDR netmask */
   /* changed version 1.2.1 */
   /*
   * "any" IP's are now set to addr 0, netmask 0, and the normal rules are
   * applied instead of checking the flag
   */
   /*
   * if we see a "!<ip number>" we need to set a flag so that we can
   * properly deal with it when we are processing packets
   */
   /* we found a negated address */
   /* if( *toks[2] == '!' )   
     {
     proto_node.flags |= EXCEPT_SRC_IP;
     ProcessIP(&toks[2][1], &proto_node, SRC);
     }
     else
     {*/
   ProcessIP(toks[2], &proto_node, SRC);
   /*}*/

   /* check to make sure that the user entered port numbers */
   /* sometimes they forget/don't know that ICMP rules need them */
   if(!strcasecmp(toks[3], "->") || !strcasecmp(toks[3], "<>")) {
      ArgusLog(LOG_ERR,"%s:%d => Port value missing in rule!\n", file_name, file_line);
   }

   /* do the same for the port */
   if(ParsePort(toks[3], (u_short *) & proto_node.hsp, (u_short *) & proto_node.lsp, toks[1], (int *) &proto_node.not_sp_flag)) {
      proto_node.flags |= ANY_SRC_PORT;
   }

   if(proto_node.not_sp_flag)
      proto_node.flags |= EXCEPT_SRC_PORT;

   /* New in version 1.3: support for bidirectional rules */
   /*
   * this checks the rule "direction" token and sets the bidirectional flag
   * if the token = '<>'
   */
   if(!strncmp("<>", toks[4], 2)) {
      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Bidirectional rule!\n"););
      proto_node.flags |= BIDIRECTIONAL;
   }

   /* changed version 1.8.4
   * Die when someone has tried to define a rule character other than
     -> or <>
   */
   if(strcmp("->", toks[4]) && strcmp("<>", toks[4])) {
      ArgusLog(LOG_ERR,"%s(%d): Illegal direction specifier: %s\n", file_name, file_line, toks[4]);
   }


   /* changed version 1.2.1 */
   /*
   * "any" IP's are now set to addr 0, netmask 0, and the normal rules are
   * applied instead of checking the flag
   */
   /*
   * if we see a "!<ip number>" we need to set a flag so that we can
   * properly deal with it when we are processing packets
   */
   /* we found a negated address */

   ProcessIP(toks[5], &proto_node, DST);

   if(ParsePort(toks[6], (u_short *) & proto_node.hdp, (u_short *) & proto_node.ldp, toks[1], (int *) &proto_node.not_dp_flag)) {
      proto_node.flags |= ANY_DST_PORT;
   }

   if(proto_node.not_dp_flag)
      proto_node.flags |= EXCEPT_DST_PORT;

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"proto_node.flags = 0x%X\n", proto_node.flags););
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Processing Head Node....\n"););

   switch(rule_type) {
      case RULE_ALERT:
         ProcessHeadNode(&proto_node, &Alert, protocol);
         break;

      case RULE_LOG:
         ProcessHeadNode(&proto_node, &Log, protocol);
         break;

      case RULE_PASS:
         ProcessHeadNode(&proto_node, &Pass, protocol);
         break;

      case RULE_ACTIVATE:
         ProcessHeadNode(&proto_node, &Activation, protocol);
         break;

      case RULE_DYNAMIC:
         ProcessHeadNode(&proto_node, &Dynamic, protocol);
         break;

      case RULE_UNKNOWN:
         ProcessHeadNode(&proto_node, node->RuleList, protocol);
         break;

      default:
         ArgusLog(LOG_ERR,"Unable to determine rule type (%s) for processing, exiting!\n", toks[0]);
   }

   rule_count++;

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Parsing Rule Options...\n"););

   if (rule_type == RULE_UNKNOWN)
      ParseRuleOptions(rule, node->mode, protocol);
   else
      ParseRuleOptions(rule, rule_type, protocol);

   mSplitFree(&toks, num_toks);

   return;
}

/****************************************************************************
 *
 * Function: ProcessHeadNode(RuleTreeNode *, ListHead *, int)
 *
 * Purpose:  Process the header block info and add to the block list if
 *         necessary
 *
 * Arguments: test_node => data generated by the rules parsers
 *         list => List Block Header refernece
 *         protocol => ip protocol
 *
 * Returns: void function
 *
 ***************************************************************************/
void
ProcessHeadNode(RuleTreeNode * test_node, ListHead * list, int protocol) {
   int match = 0;
   RuleTreeNode *rtn_idx;
   RuleTreeNode *rtn_prev;
   RuleTreeNode *rtn_head_ptr;
   int count = 0;
   int insert_complete = 0;
#ifdef DEBUG
   int i;
#endif

   /* select the proper protocol list to attach the current rule to */
   switch(protocol) {
   case IPPROTO_TCP:
      rtn_idx = list->TcpList;
      break;

   case IPPROTO_UDP:
      rtn_idx = list->UdpList;
      break;

   case IPPROTO_ICMP:
      rtn_idx = list->IcmpList;
      break;

   case ETHERNET_TYPE_IP:
      rtn_idx = list->IpList;
      break;

   default:
      rtn_idx = NULL;
      break;
   }

   /* 
   * save which list we're on in case we need to do an insertion
   * sort on a new node
   */
   rtn_head_ptr = rtn_idx;

   /*
   * if the list head is NULL (empty), make a new one and attach the
   * ListHead to it
   */
   if(rtn_idx == NULL) {
   head_count++;
   switch(protocol) {
      case IPPROTO_TCP:
         list->TcpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), 
               sizeof(char));
         rtn_tmp = list->TcpList;
         break;

      case IPPROTO_UDP:
         list->UdpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), 
               sizeof(char));
         rtn_tmp = list->UdpList;
         break;

      case IPPROTO_ICMP:
         list->IcmpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), 
               sizeof(char));
         rtn_tmp = list->IcmpList;
         break;

      case ETHERNET_TYPE_IP:
         list->IpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), 
               sizeof(char));
         rtn_tmp = list->IpList;
         break;

   }

   /* copy the prototype header data into the new node */
   XferHeader(test_node, rtn_tmp);
   rtn_tmp->head_node_number = head_count;

   /* null out the down (options) pointer */
   rtn_tmp->down = NULL;

   /* add the function list to the new rule */
   SetupRTNFuncList(rtn_tmp);

   /* add link to parent listhead */
   rtn_tmp->listhead = list;

   return;
   }

   /* see if this prototype node matches any of the existing header nodes */
   match = TestHeader(rtn_idx, test_node);

   while((rtn_idx->right != NULL) && !match) {
   count++;
   match = TestHeader(rtn_idx, test_node);

   if(!match)
      rtn_idx = rtn_idx->right;
   else
      break;
   }

   /*
   * have to check this twice since my loop above exits early, which sucks
   * but it's not performance critical
   */
   match = TestHeader(rtn_idx, test_node);

   /*
   * if it doesn't match any of the existing nodes, make a new node and
   * stick it at the end of the list
   */
   if(!match) {
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Building New Chain head node\n"););

   head_count++;

   /* build a new node */
   //rtn_idx->right = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), 
   rtn_tmp = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), 
         sizeof(char));

   /* set the global ptr so we can play with this from anywhere */
   //rtn_tmp = rtn_idx->right;

   /* uh oh */
   if(rtn_tmp == NULL)
      ArgusLog(LOG_ERR,"Unable to allocate Rule Head Node!!\n");

   /* copy the prototype header info into the new header block */
   XferHeader(test_node, rtn_tmp);

   rtn_tmp->head_node_number = head_count;
   rtn_tmp->down = NULL;

   /* initialize the function list for the new RTN */
   SetupRTNFuncList(rtn_tmp);

   /* add link to parent listhead */
   rtn_tmp->listhead = list;
   
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,
         "New Chain head flags = 0x%X\n", rtn_tmp->flags););

   /* we do an insertion sort of new RTNs for TCP/UDP traffic */
   if(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
      /* 
      * insert the new node into the RTN chain, order by destination
      * port
      */
      rtn_idx = rtn_head_ptr;
      rtn_prev = NULL;
      insert_complete = 0;

      /* 
      * Loop thru the RTN list and check to see of the low dest port
      * of the new node is greater than the low dest port of the 
      * new node.  If it is, insert the new node ahead of (to the 
      * left) of the existing node.
      */
      if(rtn_tmp->flags & EXCEPT_DST_PORT) {
         switch(protocol) {
            case IPPROTO_TCP:
               rtn_tmp->right = list->TcpList;
               list->TcpList = rtn_tmp;
               break;

            case IPPROTO_UDP:
               rtn_tmp->right = list->UdpList;
               list->UdpList = rtn_tmp;
               break;
         }

         rtn_head_ptr = rtn_tmp;
         insert_complete = 1;
      } else {
         while(rtn_idx != NULL) {
            if(rtn_idx->flags & EXCEPT_DST_PORT || rtn_idx->ldp < rtn_tmp->ldp) {
               rtn_prev = rtn_idx;
               rtn_idx = rtn_idx->right;
            } else if(rtn_idx->ldp == rtn_tmp->ldp) {
               rtn_tmp->right = rtn_idx->right;
               rtn_idx->right = rtn_tmp;
               insert_complete = 1;
               break;
            } else {
               rtn_tmp->right = rtn_idx;

               if(rtn_prev != NULL) {
                  rtn_prev->right = rtn_tmp;
               } else {
                  switch(protocol) {
                     case IPPROTO_TCP:
                        list->TcpList = rtn_tmp;
                        break;

                     case IPPROTO_UDP:
                        list->UdpList = rtn_tmp;
                        break;
                  }

                  rtn_head_ptr = rtn_tmp;
               }

               insert_complete = 1;
               break;
            }
         } 
      }

      if(!insert_complete) {
         rtn_prev->right = rtn_tmp;   
      }
      
      rtn_idx = rtn_head_ptr;

      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES, 
            "New %s node inserted, new order:\n", 
            protocol == IPPROTO_TCP?"TCP":"UDP"););
      
#ifdef DEBUG
      i = 0;

      while(rtn_idx != NULL) {
         if(rtn_idx->flags & EXCEPT_DST_PORT) {
            LogMessage("!");
         }

         ArgusDebug(DEBUG_CONFIGRULES, "%d ", rtn_idx->ldp);
         rtn_idx = rtn_idx->right;
         if(i++ == 10) {
            ArgusDebug(DEBUG_CONFIGRULES, "\n");
            i = 0;
         }
      }
      ArgusDebug(DEBUG_CONFIGRULES, "\n");
#endif
   } else {
      rtn_idx->right = rtn_tmp;
   }

   } else {
   rtn_tmp = rtn_idx;
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,
         "Chain head %d  flags = 0x%X\n", count, rtn_tmp->flags););

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,
            "Adding options to chain head %d\n", count););
   }
}


/****************************************************************************
 * 
 * Function: AddOptFuncToList(int (*func)(), OptTreeNode *)
 *
 * Purpose: Links the option detection module to the OTN
 *
 * Arguments: (*func)() => function pointer to the detection module
 *            otn =>  pointer to the current OptTreeNode
 *
 * Returns: void function
 *
 ***************************************************************************/
OptFpList *
AddOptFuncToList(int (*func)(struct ArgusRecord *, struct _OptTreeNode *, struct _OptFpList *), OptTreeNode * otn)
{
   OptFpList *idx;     /* index pointer */

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Adding new rule to list\n"););
    /* set the index pointer to the start of this OTN's function list */
   idx = otn->opt_func;
    /* if there are no nodes on the function list... */
   if (idx == NULL) {
      /* calloc the list head */
      otn->opt_func = (OptFpList *) calloc(sizeof(OptFpList), sizeof(char));

      if(otn->opt_func == NULL)
         ArgusLog(LOG_ERR, "new node calloc failed: %s\n", strerror(errno));

      /* set the head function */
      otn->opt_func->OptTestFunc = func;
      idx = otn->opt_func;

   } else {
      /* walk to the end of the list */
      while(idx->next != NULL)
            idx = idx->next;
      /* allocate a new node on the end of the list */
      idx->next = (OptFpList *) calloc(sizeof(OptFpList), sizeof(char));

      if(idx->next == NULL)
         ArgusLog(LOG_ERR, "AddOptFuncToList new node calloc failed: %s\n", strerror(errno));

      /* move up to the new node */
      idx = idx->next;
      /* link the function to the new node */
      idx->OptTestFunc = func;

      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Set OptTestFunc to %p\n", func););
   }

   return idx;
}


/****************************************************************************
 *
 * Function: AddRuleFuncToList(int (*func)(), RuleTreeNode *)
 *
 * Purpose:  Adds RuleTreeNode associated detection functions to the
 *        current rule's function list
 *
 * Arguments: *func => function pointer to the detection function
 *         rtn   => pointer to the current rule
 *
 * Returns: void function
 *
 ***************************************************************************/
void
AddRuleFuncToList(int (*func) (struct ArgusRecord *, struct _RuleTreeNode *, struct _RuleFpList *), RuleTreeNode * rtn) {
   RuleFpList *idx;

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Adding new rule to list\n"););

   idx = rtn->rule_func;

   if(idx == NULL) {
   rtn->rule_func = (RuleFpList *) calloc(sizeof(RuleFpList), sizeof(char));
   rtn->rule_func->RuleHeadFunc = func;

   } else {
   while(idx->next != NULL)
      idx = idx->next;

   idx->next = (RuleFpList *) calloc(sizeof(RuleFpList), sizeof(char));

   idx = idx->next;
   idx->RuleHeadFunc = func;
   }
}


/****************************************************************************
 *
 * Function: SetupRTNFuncList(RuleTreeNode *)
 *
 * Purpose: Configures the function list for the rule header detection
 *        functions (addrs and ports)
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *
 * Returns: void function
 *
 ***************************************************************************/

void
SetupRTNFuncList(RuleTreeNode * rtn) {
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Initializing RTN function list!\n"););
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Functions: "););

   if(rtn->flags & BIDIRECTIONAL) {
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"CheckBidirectional->\n"););
   AddRuleFuncToList(CheckBidirectional, rtn);
   } else {
   /* Attach the proper port checking function to the function list */
   /*
   * the in-line "if's" check to see if the "any" or "not" flags have
   * been set so the PortToFunc call can determine which port testing
   * function to attach to the list
   */
   PortToFunc(rtn, (rtn->flags & ANY_DST_PORT ? 1 : 0),
           (rtn->flags & EXCEPT_DST_PORT ? 1 : 0), DST);

   /* as above */
   PortToFunc(rtn, (rtn->flags & ANY_SRC_PORT ? 1 : 0),
           (rtn->flags & EXCEPT_SRC_PORT ? 1 : 0), SRC);

   /* link in the proper IP address detection function */
   AddrToFunc(rtn, SRC);

   /* last verse, same as the first (but for dest IP) ;) */
   AddrToFunc(rtn, DST);
   }

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"RuleListEnd\n"););

   /* tack the end (success) function to the list */
   AddRuleFuncToList(RuleListEnd, rtn);
}



/****************************************************************************
 *
 * Function: AddrToFunc(RuleTreeNode *, u_long, u_long, int, int)
 *
 * Purpose: Links the proper IP address testing function to the current RTN
 *        based on the address, netmask, and addr flags
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *         ip =>  IP address of the current rule
 *         mask => netmask of the current rule
 *         exception_flag => indicates that a "!" has been set for this
 *                       address
 *         mode => indicates whether this is a rule for the source
 *               or destination IP for the rule
 *
 * Returns: void function
 *
 ***************************************************************************/
void
AddrToFunc(RuleTreeNode * rtn, int mode) {
   /*
   * if IP and mask are both 0, this is a "any" IP and we don't need to
   * check it
   */
   switch(mode) {
   case SRC:
      if((rtn->flags & ANY_SRC_IP) == 0) {
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"CheckSrcIP -> "););
         AddRuleFuncToList(CheckSrcIP, rtn);
      }
      break;

   case DST:
      if((rtn->flags & ANY_DST_IP) == 0) {
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"CheckDstIP -> "););
         AddRuleFuncToList(CheckDstIP, rtn);
      }
      break;
   }
}



/****************************************************************************
 *
 * Function: PortToFunc(RuleTreeNode *, int, int, int)
 *
 * Purpose: Links in the port analysis function for the current rule
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *         any_flag =>  accept any port if set
 *         except_flag => indicates negation (logical NOT) of the test
 *         mode => indicates whether this is a rule for the source
 *               or destination port for the rule
 *
 * Returns: void function
 *
 ***************************************************************************/
void
PortToFunc(RuleTreeNode * rtn, int any_flag, int except_flag, int mode) {
   /*
   * if the any flag is set we don't need to perform any test to match on
   * this port
   */
   if(any_flag)
   return;

   /* if the except_flag is up, test with the "NotEq" funcs */
   if(except_flag) {
   switch(mode) {
      case SRC:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"CheckSrcPortNotEq -> "););
         AddRuleFuncToList(CheckSrcPortNotEq, rtn);
         break;

      case DST:
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"CheckDstPortNotEq -> "););
         AddRuleFuncToList(CheckDstPortNotEq, rtn);
         break;
   }

   return;
   }
   /* default to setting the straight test function */
   switch(mode) {
   case SRC:
      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"CheckSrcPortEqual -> "););
      AddRuleFuncToList(CheckSrcPortEqual, rtn);
      break;

   case DST:
      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"CheckDstPortEqual -> "););
      AddRuleFuncToList(CheckDstPortEqual, rtn);
      break;
   }
   return;
}





/****************************************************************************
 *
 * Function: ParsePreprocessor(char *)
 *
 * Purpose: Walks the preprocessor function list looking for the user provided
 *        keyword.  Once found, call the preprocessor's initialization
 *        function.
 *
 * Arguments: rule => the preprocessor initialization string from the rules file
 *
 * Returns: void function
 *
 ***************************************************************************/
void
ParsePreprocessor(char *rule)
{
   char **toks;      /* pointer to the tokenized array parsed from
               * the rules list */
   char **pp_head;    /* parsed keyword list, with preprocessor
               * keyword being the 2nd element */
   char *funcname;    /* the ptr to the actual preprocessor keyword */
   char *pp_args = NULL;   /* parsed list of arguments to the
                  * preprocessor */
   int num_arg_toks;   /* number of argument tokens returned by the mSplit function */
   int num_head_toks;  /* number of head tokens returned by the mSplit function */
   int found = 0;     /* flag var */
   PreprocessKeywordList *pl_idx;  /* index into the preprocessor
                        * keyword/func list */

   /* break out the arguments from the keywords */
   toks = mSplit(rule, ":", 2, &num_arg_toks, '\\');

   if(num_arg_toks > 1) {
   /*
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"toks[1] = %s\n", toks[1]););
   */
   /* the args are everything after the ":" */
    pp_args = toks[1];
   }

   /* split the head section for the preprocessor keyword */
   pp_head = mSplit(toks[0], " ", 2, &num_head_toks, '\\');

   /* set a pointer to the actual keyword */
   funcname = pp_head[1];

   /* set the index to the head of the keyword list */
   pl_idx = PreprocessKeywords;

   /* walk the keyword list */
   while(pl_idx != NULL) {
      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES, "comparing: \"%s\" => \"%s\"\n",
                 funcname, pl_idx->entry.keyword););

     /* compare the keyword against the current list element's keyword */
      if(!strcasecmp(funcname, pl_idx->entry.keyword)) {
         pl_idx->entry.func(pp_args);
         found = 1;
      }

      if(!found) {
         pl_idx = pl_idx->next;
      } else
         break;
   }

   mSplitFree(&toks, num_arg_toks);
   mSplitFree(&pp_head, num_head_toks);

   if(!found) {
      ArgusLog(LOG_ERR," unknown preprocessor \"%s\"\n", funcname);
   }
}


OutputKeywordNode *GetOutputPlugin(char *plugin_name) {return (NULL);}

void
ParseOutputPlugin(char *rule) {
   char **toks;
   char **pp_head;
   char *plugin_name;
   char *pp_args = NULL;
   int num_arg_toks;
   int num_head_toks;
   OutputKeywordNode *plugin;

   toks = mSplit(rule, ":", 2, &num_arg_toks, '\\');

   if(num_arg_toks > 1)
      pp_args = toks[1];
   
   pp_head = mSplit(toks[0], " ", 2, &num_head_toks, '\\');

   plugin_name = pp_head[1];
   plugin = GetOutputPlugin(plugin_name);

   if( plugin != NULL ) {
      switch(plugin->node_type) {
      case NT_OUTPUT_SPECIAL:
         if(pv.alert_cmd_override)
            ArgusLog(LOG_ALERT, "command line overrides rules file alert plugin!\n");
         if(pv.log_cmd_override)
            ArgusLog(LOG_ALERT, "command line overrides rules file login plugin!\n");
         plugin->func(pp_args);
         break;
      case NT_OUTPUT_ALERT:
         if(!pv.alert_cmd_override) {
         /* call the configuration function for the plugin */
            plugin->func(pp_args);
         } else {
            ArgusLog(LOG_ALERT, "command line overrides rules file alert plugin!\n");
         }

         break;

      case NT_OUTPUT_LOG:
         if(!pv.log_cmd_override) {
         /* call the configuration function for the plugin */
            plugin->func(pp_args);
         } else {
            ArgusLog(LOG_ALERT,"command line overrides rules file logging plugin!\n");
         }

         break;
      }
   }
   mSplitFree(&toks, num_arg_toks);
   mSplitFree(&pp_head, num_head_toks);
}



/****************************************************************************
 *
 * Function: ParseRuleOptions(char *, int)
 *
 * Purpose:  Process an individual rule's options and add it to the
 *         appropriate rule chain
 *
 * Arguments: rule => rule string
 *         rule_type => enumerated rule type (alert, pass, log)
 *
 * Returns: void function
 *
 ***************************************************************************/

void ParseTag(char *args, OptTreeNode *otn) {}  

void
ParseRuleOptions(char *rule, int rule_type, int protocol) {
   char **toks = NULL;
   char **opts = NULL;
   char *idx;
   char *aux;
   int num_toks, original_num_toks=0;
   int i;
   int num_opts;
   int found = 0;
   OptTreeNode *otn_idx;
   KeywordXlateList *kw_idx;
   THDX_STRUCT thdx;
   int one_threshold = 0;
   
   /* set the OTN to the beginning of the list */
   otn_idx = rtn_tmp->down;

   /*
   * make a new one and stick it either at the end of the list or hang it
   * off the RTN pointer
   */
   if(otn_idx != NULL) {
      /* loop to the end of the list */
      while(otn_idx->next != NULL) {
         otn_idx = otn_idx->next;
      }

      /* setup the new node */
      otn_idx->next = (OptTreeNode *) calloc(sizeof(OptTreeNode), 
                                   sizeof(char));

      /* set the global temp ptr */
      otn_tmp = otn_idx->next;

      if(otn_tmp == NULL) {
         ArgusLog(LOG_ERR,"Unable to alloc OTN: %s", strerror(errno));
      }

      otn_tmp->next = NULL;
      opt_count++;

   } else {
      /* first entry on the chain, make a new node and attach it */
      otn_idx = (OptTreeNode *) calloc(sizeof(OptTreeNode), sizeof(char));

      bzero((char *) otn_idx, sizeof(OptTreeNode));

      otn_tmp = otn_idx;

      if(otn_tmp == NULL) {
         ArgusLog(LOG_ERR,"Unable to alloc OTN!\n");
      }
      otn_tmp->next = NULL;
      rtn_tmp->down = otn_tmp;
      opt_count++;
   }

   otn_tmp->chain_node_number = opt_count;
   otn_tmp->type = rule_type;
   otn_tmp->proto_node = rtn_tmp;
   otn_tmp->event_data.sig_generator = GENERATOR_SNORT_ENGINE;

   /* add link to parent RuleTreeNode */
   otn_tmp->rtn = rtn_tmp;

   /* find the start of the options block */
   idx = index(rule, '(');
   i = 0;

   if(idx != NULL) {
   int one_msg = 0;
   int one_logto = 0;
   int one_activates = 0;
   int one_activated_by = 0;
   int one_count = 0;
   int one_tag = 0;
   int one_sid = 0;
   int one_rev = 0;
   int one_priority = 0;
   int one_classtype = 0;
   int one_stateless = 0;
   
   idx++;

      /* find the end of the options block */
      aux = strrchr(idx, ')');

      /* get rid of the trailing ")" */
      if(aux == NULL) {
         ArgusLog(LOG_ERR,"%s(%d): Missing trailing ')' in rule: %s.\n",
                 file_name, file_line, rule);
      }

      *aux = 0;

      /* seperate all the options out, the seperation token is a semicolon */
      /*
      * NOTE: if you want to include a semicolon in the content of your
      * rule, it must be preceeded with a '\'
      */
      toks = mSplit(idx, ";", 64, &num_toks, '\\');
      original_num_toks = num_toks;  /* so we can properly deallocate toks later */

      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"   Got %d tokens\n", num_toks););
      /* decrement the number of toks */
      num_toks--;

      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Parsing options list: "););

      while(num_toks) {
         char* option_name = NULL;
         char* option_args = NULL;

         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"   option: %s\n", toks[i]););

         /* break out the option name from its data */
         opts = mSplit(toks[i], ":", 4, &num_opts, '\\');

         /* can't free opts[0] later if it has been incremented, so
         * must use another variable here */
         option_name = opts[0];
         option_args = opts[1];

         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"   option name: %s\n", option_name););
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"   option args: %s\n", option_args););

         /* advance to the beginning of the data (past the whitespace) */
         while(isspace((int) *option_name))
            option_name++;
      
         /* figure out which option tag we're looking at */
         if(!strcasecmp(option_name, "msg")) {
            ONE_CHECK (one_msg, option_name);
            if(num_opts == 2) {
               ParseMessage(option_args);
            } else {
               ArgusLog(LOG_ERR,"\n%s(%d) => No argument passed to "
                     "keyword \"%s\"\nMake sure you didn't forget a ':' "
                     "or the argument to this keyword!\n", file_name, 
                     file_line, option_name);
            }
         } else if(!strcasecmp(option_name, "logto")) {
            ONE_CHECK (one_logto, option_name);
            if(num_opts == 2) {
               ParseLogto(option_args);
            } else {
               ArgusLog(LOG_ERR,"\n%s(%d) => No argument passed to "
                     "keyword \"%s\"\nMake sure you didn't forget a ':' "
                     "or the argument to this keyword!\n", file_name, 
                     file_line, option_name);
            }
         } else if(!strcasecmp(option_name, "activates")) {
            ONE_CHECK (one_activates, option_name);
            if(num_opts == 2) {
               ParseActivates(option_args);
               dynamic_rules_present++;
            } else {
               ArgusLog(LOG_ERR,"\n%s(%d) => No argument passed to "
                     "keyword \"%s\"\nMake sure you didn't forget a ':' "
                     "or the argument to this keyword!\n", file_name, 
                     file_line, option_name);
            }
         } else if(!strcasecmp(option_name, "activated_by")) {
            ONE_CHECK (one_activated_by, option_name);
            if(num_opts == 2) {
               ParseActivatedBy(option_args);
               dynamic_rules_present++;
            } else {
               ArgusLog(LOG_ERR,"\n%s(%d) => No argument passed to "
                     "keyword \"%s\"\nMake sure you didn't forget a ':' "
                     "or the argument to this keyword!\n", file_name, 
                     file_line, opts[0]);
            }
         } else if(!strcasecmp(option_name, "count")) {
            ONE_CHECK (one_count, option_name);
            if(num_opts == 2) {
               if(otn_tmp->type != RULE_DYNAMIC)
                  ArgusLog(LOG_ERR,"The \"count\" option may only be used with "
                        "the dynamic rule type!\n");
               ParseCount(opts[1]);
            } else {
               ArgusLog(LOG_ERR,"\n%s(%d) => No argument passed to "
                     "keyword \"%s\"\nMake sure you didn't forget a ':' "
                     "or the argument to this keyword!\n", file_name, 
                     file_line, opts[0]);
            }
         } else if(!strcasecmp(option_name, "tag")) {
            ONE_CHECK (one_tag, opts[0]);
            if(num_opts == 2) {
               ParseTag(opts[1], otn_tmp);
            } else {
               ArgusLog(LOG_ERR,"\n%s(%d) => No argument passed to "
                     "keyword \"%s\"\nMake sure you didn't forget a ':' "
                     "or the argument to this keyword!\n", file_name, 
                     file_line, opts[0]);
            }
         } else if(!strcasecmp(option_name, "threshold")) {
            ONE_CHECK (one_threshold, opts[0]);
            if(num_opts == 2) {
               ParseThreshold2(&thdx, opts[1]);
            } else {
               ArgusLog(LOG_ERR,"\n%s(%d) => No argument passed to "
                     "keyword \"%s\"\nMake sure you didn't forget a ':' "
                     "or the argument to this keyword!\n", file_name, 
                     file_line, opts[0]);
            }
         } else if(!strcasecmp(option_name, "sid")) {
            ONE_CHECK (one_sid, opts[0]);
            if(num_opts == 2) {
               ParseSID(opts[1], otn_tmp);
            } else {
               ArgusLog(LOG_ERR,"\n%s(%d) => No argument passed to "
                     "keyword \"%s\"\nMake sure you didn't forget a ':' "
                     "or the argument to this keyword!\n", file_name, 
                     file_line, opts[0]);
            }
         } else if(!strcasecmp(option_name, "rev")) {
            ONE_CHECK (one_rev, opts[0]);
            if(num_opts == 2) {
               ParseRev(opts[1], otn_tmp);
            } else {
               ArgusLog(LOG_ERR,"\n%s(%d) => No argument passed to "
                     "keyword \"%s\"\nMake sure you didn't forget a ':' "
                     "or the argument to this keyword!\n", file_name, 
                     file_line, opts[0]);
            }
         } else if(!strcasecmp(option_name, "reference")) {
            if(num_opts == 2) {
               ParseReference(opts[1], otn_tmp);
            } else {
               ArgusLog(LOG_ERR,"\n%s(%d) => No argument passed to "
                     "keyword \"%s\"\nMake sure you didn't forget a ':' "
                     "or the argument to this keyword!\n", file_name, 
                     file_line, opts[0]);
            }
         } else if(!strcasecmp(option_name, "priority")) {
            ONE_CHECK (one_priority, opts[0]);
            if(num_opts == 2) {
               ParsePriority(opts[1], otn_tmp);
            } else {
               ArgusLog(LOG_ERR,"\n%s(%d) => No argument passed to "
                     "keyword \"%s\"\nMake sure you didn't forget a ':' "
                     "or the argument to this keyword!\n", file_name, 
                     file_line, opts[0]);
            }
         } else if(!strcasecmp(option_name, "classtype")) {
            ONE_CHECK (one_classtype, opts[0]);
            if(num_opts == 2) {
               ParseClassType(opts[1], otn_tmp);
            } else {
               ArgusLog(LOG_ERR,"\n%s(%d) => No argument passed to "
                     "keyword \"%s\"\nMake sure you didn't forget a ':' "
                     "or the argument to this keyword!\n", file_name, 
                     file_line, option_name);
            }
         } else if(!strcasecmp(option_name, "stateless")) {
            ONE_CHECK (one_stateless, opts[0]);
            otn_tmp->stateless = 1;
         } else {
            kw_idx = KeywordList;
            found = 0;

            while(kw_idx != NULL) {
               DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "comparing: \"%s\" => \"%s\"\n", 
                  option_name, kw_idx->entry.keyword););

               if(!strcasecmp(option_name, kw_idx->entry.keyword)) {
                  if(num_opts == 2) {
                     kw_idx->entry.func(option_args, otn_tmp, protocol);
                  } else {
                     kw_idx->entry.func(NULL, otn_tmp, protocol);
                  }
                  DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "%s->", kw_idx->entry.keyword););
                  found = 1;
                  break;
               }
               kw_idx = kw_idx->next;
            }

            if(!found) {
               /* Unrecognized rule option, complain */
               ArgusLog(LOG_ERR,"Warning: %s(%d) => Unknown keyword '%s' in "
                       "rule!\n", file_name, file_line, opts[0]);
            }
         }

         mSplitFree(&opts,num_opts);

         --num_toks;
         i++;
      }

      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"OptListEnd\n"););
      AddOptFuncToList(OptListEnd, otn_tmp);

   } else {
      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"OptListEnd\n"););
      AddOptFuncToList(OptListEnd, otn_tmp);
   }

   if (one_threshold) {
      int rstat;
      thdx.sig_id = otn_tmp->sigInfo.id;
      thdx.gen_id = GENERATOR_SNORT_ENGINE;
      if( (rstat=sfthreshold_create( &thdx )) ) {
         if( rstat == THD_TOO_MANY_THDOBJ ) {
            ArgusLog(LOG_ERR,"Rule-Threshold-Parse: could not create a threshold object -- only one per sid, sid = %u\n",thdx.sig_id);
         } else {
            ArgusLog(LOG_ERR,"Unable to add Threshold object for Rule-sid =  %u\n",thdx.sig_id);
         }
      }
   }
   
   if(idx != NULL)
   mSplitFree(&toks,original_num_toks);
}


/****************************************************************************
 *
 * Function: RuleType(char *)
 *
 * Purpose:  Determine what type of rule is being processed and return its
 *         equivalent value
 *
 * Arguments: func => string containing the rule type
 *
 * Returns: The rule type designation
 *
 ***************************************************************************/
int
RuleType(char *func) {
   if(func == NULL) 
   ArgusLog(LOG_ERR,"%s(%d) => NULL rule type\n", file_name, file_line);
   
   if(!strcasecmp(func, "log"))
   return RULE_LOG;

   if(!strcasecmp(func, "alert"))
   return RULE_ALERT;

   if(!strcasecmp(func, "pass"))
   return RULE_PASS;

   if(!strcasecmp(func, "var"))
   return RULE_VAR;

   if(!strcasecmp(func, "include"))
   return RULE_INCLUDE;

   if(!strcasecmp(func, "preprocessor"))
   return RULE_PREPROCESS;

   if(!strcasecmp(func, "output"))
   return RULE_OUTPUT;

   if(!strcasecmp(func, "activate"))
   return RULE_ACTIVATE;

   if(!strcasecmp(func, "dynamic"))
   return RULE_DYNAMIC;

   if(!strcasecmp(func, "config"))
   return RULE_CONFIG;

   if(!strcasecmp(func, "ruletype"))
   return RULE_DECLARE;
   
   if(!strcasecmp(func, "threshold"))
   return RULE_THRESHOLD;
   
   if(!strcasecmp(func, "suppress"))
   return RULE_SUPPRESS;

   return RULE_UNKNOWN;
}


/****************************************************************************
 *
 * Function: WhichProto(char *)
 *
 * Purpose: Figure out which protocol the current rule is talking about
 *
 * Arguments: proto_str => the protocol string
 *
 * Returns: The integer value of the protocol
 *
 ***************************************************************************/
int
WhichProto(char *proto_str) {
   if(!strcasecmp(proto_str, "tcp"))
   return IPPROTO_TCP;

   if(!strcasecmp(proto_str, "udp"))
   return IPPROTO_UDP;

   if(!strcasecmp(proto_str, "icmp"))
   return IPPROTO_ICMP;

   if(!strcasecmp(proto_str, "ip"))
   return ETHERNET_TYPE_IP;

   if(!strcasecmp(proto_str, "arp"))
   return ETHERNET_TYPE_ARP;

   /*
   * if we've gotten here, we have a protocol string we din't recognize and
   * should exit
   */
   ArgusLog(LOG_ERR,"%s(%d) => Bad protocol: %s\n", file_name, file_line, proto_str);

   return 0;
}


int
ProcessIP(char *addr, RuleTreeNode *rtn, int mode) {
   char **toks = NULL;
   int num_toks;
   int i;
   IpAddrSet *tmp_addr;
   char *tmp;
   char *enbracket;

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Got address string: %s\n", addr););

   if(*addr == '!') {
      switch(mode) {
         case SRC: rtn->flags |= EXCEPT_SRC_IP; break;
         case DST: rtn->flags |= EXCEPT_DST_IP; break;
      }
      addr++;
   }

   if(*addr == '$') {
      if((tmp = VarGet(addr + 1)) == NULL) 
         ArgusLog(LOG_ERR,"%s(%d) => Undefined variable %s\n", file_name, file_line, addr);
   } else
      tmp = addr;

   /* check to see if the first char is a 
   * bracket, which signifies a list 
   */
   if(*tmp == '[') {
      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Found IP list!\n"););

      /* *(tmp+strlen(tmp)) = ' ';*/
      enbracket = strrchr(tmp, (int)']'); /* null out the en-bracket */
      if(enbracket) *enbracket = '\x0';

      toks = mSplit(tmp+1, ",", 128, &num_toks, 0);

      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"mSplit got %d tokens...\n", num_toks););

      for(i=0; i< num_toks; i++) {
         DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"adding %s to IP "
               "address list\n", toks[i]););
         tmp = toks[i];
         while (isspace((int)*tmp)||*tmp=='[') tmp++;
         enbracket = strrchr(tmp, (int)']'); /* null out the en-bracket */
         if(enbracket) *enbracket = '\x0';

         if (strlen(tmp) == 0)
            continue;
         
         tmp_addr = AllocAddrNode(rtn, mode); 
         ParseIP(tmp, tmp_addr);
         if(tmp_addr->ip_addr == 0 && tmp_addr->netmask == 0) {
            switch(mode) {
               case SRC: rtn->flags |= ANY_SRC_IP; break;
               case DST: rtn->flags |= ANY_DST_IP; break;
            }
         }
      }

      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES, "Freeing %d tokens...\n", num_toks););

      mSplitFree(&toks, num_toks);

   } else {
      DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES, "regular IP address, processing...\n"););
      tmp_addr = AllocAddrNode(rtn, mode);
      ParseIP(tmp, tmp_addr);
      if(tmp_addr->ip_addr == 0 && tmp_addr->netmask == 0) {
         switch(mode) {
            case SRC: rtn->flags |= ANY_SRC_IP; break;
            case DST: rtn->flags |= ANY_DST_IP; break;
         }
      }
   }
   return 0;
}



IpAddrSet *
AllocAddrNode(RuleTreeNode *rtn, int mode) {
   IpAddrSet *idx; /* indexing pointer */

   switch(mode) {
   case SRC:
      if(rtn->sip == NULL) {
         rtn->sip = (IpAddrSet *)calloc(sizeof(IpAddrSet), sizeof(char));
         if(rtn->sip == NULL)
         {
            ArgusLog(LOG_ERR," Unable to allocate node for IP list\n");
         }
         return rtn->sip;
      } else {
         idx = rtn->sip;

         while(idx->next != NULL) {
            idx = idx->next;
         }

         idx->next = (IpAddrSet *)calloc(sizeof(IpAddrSet), sizeof(char));
         if(idx->next == NULL) {
            ArgusLog(LOG_ERR," Unable to allocate node for IP list\n");
         }
         return idx->next;
      }


   case DST:
      if(rtn->dip == NULL) {
         rtn->dip = (IpAddrSet *)calloc(sizeof(IpAddrSet), sizeof(char));
         if(rtn->dip == NULL) {
            ArgusLog(LOG_ERR," Unable to allocate node for IP list\n");
         }
         return rtn->dip;
      } else {
         idx = rtn->dip;

         while(idx->next) {
            idx = idx->next;
         }

         idx->next = (IpAddrSet *)calloc(sizeof(IpAddrSet), sizeof(char));
         if(idx->next == NULL) {
            ArgusLog(LOG_ERR," Unable to allocate node for IP list\n");
         }
         return idx->next;
      }
   }

   return NULL;
}

u_long netmasks[33] =  {
    0x00000000, 0x80000000, 0xC0000000, 0xE0000000, 0xF0000000, 0xF8000000, 0xFC000000,
    0xFE000000, 0xFF000000, 0xFF800000, 0xFFC00000, 0xFFE00000, 0xFFF00000, 0xFFF80000,
    0xFFFC0000, 0xFFFE0000, 0xFFFF0000, 0xFFFF8000, 0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
    0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00, 0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0,
    0xFFFFFFF0, 0xFFFFFFF8, 0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF,
};

/*
 * Function: ParseIP(char *, u_long *, u_long *)
 *
 * Purpose: Convert a supplied IP address to it's network order 32-bit long
 *        value.  Also convert the CIDR block notation into a real
 *        netmask.
 *
 * Arguments: addr => address string to convert
 *         ip_addr => storage point for the converted ip address
 *         netmask => storage point for the converted netmask
 *
 * Returns: 0 for normal addresses, 1 for an "any" address
 */
int
ParseIP(char *paddr, IpAddrSet *address_data) {
   char **toks;      /* token dbl buffer */
   int num_toks;      /* number of tokens found by mSplit() */
   int cidr = 1;      /* is network expressed in CIDR format */
   int nmask;        /* netmask temporary storage */
   char *addr;       /* string to parse, eventually a variable-contents */
   struct hostent *host_info;  /* various struct pointers for stuff */
   struct sockaddr_in sin; /* addr struct */

   addr = paddr;

   if(*addr == '!') {
      address_data->addr_flags |= EXCEPT_IP;
      addr++;  /* inc past the '!' */
   }

   /* check for wildcards */
   if(!strcasecmp(addr, "any")) {
      address_data->ip_addr = 0;
      address_data->netmask = 0;
      return 1;
   }

   /* break out the CIDR notation from the IP address */
   toks = mSplit(addr, "/", 2, &num_toks, 0);

   /* "/" was not used as a delimeter, try ":" */
   if(num_toks == 1) {
      mSplitFree(&toks, num_toks);
      toks = NULL;
      toks = mSplit(addr, ":", 2, &num_toks, 0);
   }

   /*
   * if we have a mask spec and it is more than two characters long, assume
   * it is netmask format
   */
   if((num_toks > 1) && strlen(toks[1]) > 2)
      cidr = 0;

   switch(num_toks) {
   case 1:
      address_data->netmask = netmasks[32];
      break;

   case 2:
      if(cidr) {
         /* convert the CIDR notation into a real live netmask */
         nmask = atoi(toks[1]);

         /* it's pain to differ whether toks[1] is correct if netmask */
         /* is /0, so we deploy some sort of evil hack with isdigit */

         if(!isdigit((int) toks[1][0]))
            nmask = -1;

         if((nmask > -1) && (nmask < 33)) {
            address_data->netmask = netmasks[nmask];
         } else {
            ArgusLog(LOG_ERR,"%s(%d) => Invalid CIDR block for IP addr %s\n", file_name, file_line, addr);
         }
      } else {
         /* convert the netmask into its 32-bit value */

         /* broadcast address fix from 
         * Steve Beaty <beaty@emess.mscd.edu> 
         */

         /*
         * * if the address is the (v4) broadcast address, inet_addr *
         * returns -1 which usually signifies an error, but in the *
         * broadcast address case, is correct.  we'd use inet_aton() *
         * here, but it's less portable.
         */
         if(!strncmp(toks[1], "255.255.255.255", 15))
         {
            address_data->netmask = INADDR_BROADCAST;
         }
         else if((address_data->netmask = inet_addr(toks[1])) == -1)
         {
            ArgusLog(LOG_ERR,"%s(%d) => Unable to parse rule netmask (%s)\n", file_name, file_line, toks[1]);
         }
      }
      break;

   default:
      ArgusLog(LOG_ERR,"%s(%d) => Unrecognized IP address/netmask %s\n", file_name, file_line, addr);
      break;
   }

#ifndef WORDS_BIGENDIAN
   /*
   * since PC's store things the "wrong" way, shuffle the bytes into the
   * right order.  Non-CIDR netmasks are already correct.
   */
   if(cidr) {
      address_data->netmask = htonl(address_data->netmask);
   }
#endif

   /* convert names to IP addrs */
   if(isalpha((int) toks[0][0])) {
   /* get the hostname and fill in the host_info struct */
      if((host_info = gethostbyname(toks[0]))) {
         bcopy(host_info->h_addr, (char *) &sin.sin_addr, host_info->h_length);
      } else if((sin.sin_addr.s_addr = inet_addr(toks[0])) == INADDR_NONE) {
         ArgusLog(LOG_ERR,"%s(%d) => Couldn't resolve hostname %s\n", file_name, file_line, toks[0]);
      }

      address_data->ip_addr = ((u_long) (sin.sin_addr.s_addr) & 
                     (address_data->netmask));
      mSplitFree(&toks, num_toks);
      toks = NULL;
      return 1;
   }

   /* convert the IP addr into its 32-bit value */

   /* broadcast address fix from Steve Beaty <beaty@emess.mscd.edu> */

   /*
   * * if the address is the (v4) broadcast address, inet_addr returns -1 *
   * which usually signifies an error, but in the broadcast address case, *
   * is correct.  we'd use inet_aton() here, but it's less portable.
   */
   if(!strncmp(toks[0], "255.255.255.255", 15)) {
      address_data->ip_addr = INADDR_BROADCAST;
   } else if((address_data->ip_addr = inet_addr(toks[0])) == -1) {
      ArgusLog(LOG_ERR,"%s(%d) => Rule IP addr (%s) didn't translate!\n", file_name, file_line, toks[0]);
   } else {
      /* set the final homenet address up */
      address_data->ip_addr = ((u_long) (address_data->ip_addr) & (address_data->netmask));
   }

   mSplitFree(&toks, num_toks);
   toks = NULL;

   return 0;
}



/****************************************************************************
 *
 * Function: ParsePort(char *, u_short *)
 *
 * Purpose:  Convert the port string over to an integer value
 *
 * Arguments: prule_port => port rule string
 *         port => converted integer value of the port
 *
 * Returns: 0 for a normal port number, 1 for an "any" port
 *
 ***************************************************************************/
int
ParsePort(char *prule_port, u_short * hi_port, u_short * lo_port, char *proto, int *not_flag) {
   char **toks;      /* token dbl buffer */
   int num_toks;      /* number of tokens found by mSplit() */
   char *rule_port;   /* port string */

   *not_flag = 0;

   /* check for variable */
   if(!strncmp(prule_port, "$", 1)) {
      if((rule_port = VarGet(prule_port + 1)) == NULL) {
         ArgusLog(LOG_ERR,"%s(%d) => Undefined variable %s\n", file_name, file_line, prule_port);
      }
   } else
      rule_port = prule_port;

   if(rule_port[0] == '(')
      /* user forgot to put a port number in for this rule */
      ArgusLog(LOG_ERR,"%s(%d) => Bad port number: \"%s\"\n", file_name, file_line, rule_port);

   /* check for wildcards */
   if(!strcasecmp(rule_port, "any")) {
      *hi_port = 0;
      *lo_port = 0;
      return 1;
   }

   if(rule_port[0] == '!') {
      *not_flag = 1;
      rule_port++;
   }

   if(rule_port[0] == ':')
      *lo_port = 0;

   toks = mSplit(rule_port, ":", 2, &num_toks, 0);

   switch(num_toks) {
      case 1:
         *hi_port = ConvPort(toks[0], proto);

         if(rule_port[0] == ':')
            *lo_port = 0;
         else {
            *lo_port = *hi_port;

            if(index(rule_port, ':') != NULL) {
               *hi_port = 65535;
            }
         }

         break;

      case 2:
         *lo_port = ConvPort(toks[0], proto);
         if(toks[1][0] == 0)
            *hi_port = 65535;
         else
            *hi_port = ConvPort(toks[1], proto);
         break;

      default:
         ArgusLog(LOG_ERR,"%s(%d) => port conversion failed on \"%s\"\n", file_name, file_line, rule_port);
   }

   mSplitFree(&toks, num_toks);
   return 0;
}


/****************************************************************************
 *
 * Function: ConvPort(char *, char *)
 *
 * Purpose:  Convert the port string over to an integer value
 *
 * Arguments: port => port string
 *         proto => converted integer value of the port
 *
 * Returns:  the port number
 *
 ***************************************************************************/
int
ConvPort(char *port, char *proto) {
   int conv;         /* storage for the converted number */
   char *digit;     /* used to check for a number */
   struct servent *service_info;

   /*
   * convert a "word port" (http, ftp, imap, whatever) to its corresponding
   * numeric port value
   */
   if(isalpha((int) port[0]) != 0) {
   service_info = getservbyname(port, proto);

   if(service_info != NULL) {
      conv = ntohs(service_info->s_port);
      return conv;
   } else {
      ArgusLog(LOG_ERR,"%s(%d) => getservbyname() failed on \"%s\"\n",
              file_name, file_line, port);
   }
   }
   digit = port;
   while (*digit) {
   if(!isdigit((int) *digit))
      ArgusLog(LOG_ERR,"%s(%d) => Invalid port: %s\n", file_name, file_line, port);
   digit++;
   }
   /* convert the value */
   conv = atoi(port);

   /* make sure it's in bounds */
   if((conv >= 0) && (conv < 65536)) {
   return conv;
   } else 
   ArgusLog(LOG_ERR,"%s(%d) => bad port number: %s\n", file_name, file_line, port);

   return 0;
}



/****************************************************************************
 *
 * Function: ParseMessage(char *)
 *
 * Purpose: Stuff the alert message onto the rule
 *
 * Arguments: msg => the msg string
 *
 * Returns: void function
 *
 ***************************************************************************/
void
ParseMessage(char *msg) {
   char *ptr;
   char *end;
   int size;
   int count = 0;
   char *read;
   char *write;

   /* figure out where the message starts */
   ptr = index(msg, '"');

   if(ptr == NULL) {
   ptr = msg;
   } else
   ptr++;

   end = index(ptr, '"');

   if(end != NULL)
   *end = 0;

   while(isspace((int) *ptr))
   ptr++;


   read = write = ptr;

   while(read < end) {
   if(*read == '\\') {
      read++;
      count++;

      if(read >= end)
         break;
   }
   *write++ = *read++;
   }

   if(end) 
   *(end - count) = '\x0';

   /* find the end of the alert string */
   size = strlen(msg) + 1;
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES, "Message: %s\n", msg););

   /* alloc space for the string and put it in the rule */
   if(size > 0) {
   otn_tmp->sigInfo.message = strdup(ptr);

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES, "Rule message set to: %s\n", 
         otn_tmp->sigInfo.message););

   } else {
   ArgusLog(LOG_ALERT,"%s(%d): bad alert message size %d\n", file_name, file_line, size);
   }

   return;
}



/****************************************************************************
 *
 * Function: ParseLogto(char *)
 *
 * Purpose: stuff the special log filename onto the proper rule option
 *
 * Arguments: filename => the file name
 *
 * Returns: void function
 *
 ***************************************************************************/
void
ParseLogto(char *filename) {
   char *sptr;
   char *eptr;

   /* grab everything between the starting " and the end one */
   sptr = index(filename, '"');
   eptr = strrchr(filename, '"');

   if(sptr != NULL && eptr != NULL) {
   /* increment past the first quote */
   sptr++;

   /* zero out the second one */
   *eptr = 0;
   } else {
   sptr = filename;
   }

   /* malloc up a nice shiny clean buffer */
   otn_tmp->logto = (char *) calloc(strlen(sptr) + 1, sizeof(char));

   bzero((char *) otn_tmp->logto, strlen(sptr) + 1);

   strncpy(otn_tmp->logto, sptr, strlen(sptr)+1);

   return;
}




/****************************************************************************
 *
 * Function: ParseActivates(char *)
 *
 * Purpose: Set an activation link record
 *
 * Arguments: act_num => rule number to be activated
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseActivates(char *act_num)
{
   /*
   * allocate a new node on the RTN get rid of whitespace at the front of
   * the list
   */
   while(!isdigit((int) *act_num))
   act_num++;

   otn_tmp->activates = atoi(act_num);

   return;
}




/****************************************************************************
 *
 * Function: ParseActivatedBy(char *)
 *
 * Purpose: Set an activation link record
 *
 * Arguments: act_by => rule number to be activated
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseActivatedBy(char *act_by)
{
   ActivateList *al_ptr;

   al_ptr = rtn_tmp->activate_list;

   if(al_ptr == NULL)
   {
   rtn_tmp->activate_list = (ActivateList *) calloc(sizeof(ActivateList), sizeof(char));

   if(rtn_tmp->activate_list == NULL)
   {
      ArgusLog(LOG_ERR,"ParseActivatedBy() calloc failed: %s\n", strerror(errno));
   }

   al_ptr = rtn_tmp->activate_list;
   }
   else
   {
   while(al_ptr->next != NULL)
   {
      al_ptr = al_ptr->next;
   }

   al_ptr->next = (ActivateList *) calloc(sizeof(ActivateList), sizeof(char));

   al_ptr = al_ptr->next;

   if(al_ptr == NULL)
   {
      ArgusLog(LOG_ERR,"ParseActivatedBy() calloc failed: %s\n", strerror(errno));
   }
   }

   /* get rid of whitespace at the front of the list */
   while(!isdigit((int) *act_by))
   act_by++;

   /* set the RTN list node number */
   al_ptr->activated_by = atoi(act_by);

   /* set the OTN list node number */
   otn_tmp->activated_by = atoi(act_by);

   return;
}



void ParseCount(char *num)
{
   while(!isdigit((int) *num))
   num++;

   otn_tmp->activation_counter = atoi(num);

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Set activation counter to %d\n", otn_tmp->activation_counter););

   return;
}




/****************************************************************************
 *
 * Function: XferHeader(RuleTreeNode *, RuleTreeNode *)
 *
 * Purpose: Transfer the rule block header data from point A to point B
 *
 * Arguments: rule => the place to xfer from
 *         rtn => the place to xfer to
 *
 * Returns: void function
 *
 ***************************************************************************/
void XferHeader(RuleTreeNode * rule, RuleTreeNode * rtn)
{
   rtn->type = rule->type;
   rtn->sip = rule->sip;
   rtn->dip = rule->dip;
   rtn->hsp = rule->hsp;
   rtn->lsp = rule->lsp;
   rtn->hdp = rule->hdp;
   rtn->ldp = rule->ldp;
   rtn->flags = rule->flags;
   rtn->not_sp_flag = rule->not_sp_flag;
   rtn->not_dp_flag = rule->not_dp_flag;
}



/****************************************************************************
 *
 * Function: TestHeader(RuleTreeNode *, RuleTreeNode *)
 *
 * Purpose: Check to see if the two header blocks are identical
 *
 * Arguments: rule => uh
 *         rtn  => uuuuhhhhh....
 *
 * Returns: 1 if they match, 0 if they don't
 *
 ***************************************************************************/
int TestHeader(RuleTreeNode * rule, RuleTreeNode * rtn)
{
   IpAddrSet *rule_idx;  /* ip struct indexer */
   IpAddrSet *rtn_idx;   /* ip struct indexer */

   rtn_idx = rtn->sip;
   for(rule_idx = rule->sip; rule_idx != NULL; rule_idx = rule_idx->next)
   {
   if(rtn_idx && (rtn_idx->ip_addr == rule_idx->ip_addr) &&
         (rtn_idx->netmask == rule_idx->netmask) &&
         (rtn_idx->addr_flags == rule_idx->addr_flags))
   {
      rtn_idx = rtn_idx->next;
   }
   else
   {
      return 0;
   }
   }

   rtn_idx = rtn->dip;
   for(rule_idx = rule->dip ; rule_idx != NULL; rule_idx = rule_idx->next)
   {
   if(rtn_idx && (rtn_idx->ip_addr == rule_idx->ip_addr) &&
         (rtn_idx->netmask == rule_idx->netmask) &&
         (rtn_idx->addr_flags == rule_idx->addr_flags))
   {
      rtn_idx = rtn_idx->next;
   }
   else
   {
      return 0;
   }
   }

   if(rtn->hsp == rule->hsp)
   {
   if(rtn->lsp == rule->lsp)
   {
      if(rtn->hdp == rule->hdp)
      {
         if(rtn->ldp == rule->ldp)
         {
            if(rtn->flags == rule->flags)
            {
               return 1;
            }
         }
      }
   }
   }
   return 0;
}


/****************************************************************************
 *
 * Function: VarAlloc()
 *
 * Purpose: allocates memory for a variable
 *
 * Arguments: none
 *
 * Returns: pointer to new VarEntry
 *
 ***************************************************************************/
struct VarEntry *VarAlloc()
{
   struct VarEntry *new;

   if((new = (struct VarEntry *) calloc(sizeof(struct VarEntry), sizeof(char))) == NULL)
   {
   ArgusLog(LOG_ERR,"cannot allocate memory for VarEntry.");
   }

   return(new);
}

/****************************************************************************
 *
 * Function: VarDefine(char *, char *)
 *
 * Purpose: define the contents of a variable
 *
 * Arguments: name => the name of the variable
 *         value => the contents of the variable
 *
 * Returns: void function
 *
 ***************************************************************************/
struct VarEntry *VarDefine(char *name, char *value)
{
   struct VarEntry *p;

   if(value == NULL)
   {
   ArgusLog(LOG_ERR,"%s(%d):  Bad value in variable definition!\n"
           "Make sure you don't have a \"$\" in the var name\n",
           file_name, file_line);
   }

   if(!VarHead)
   {
   p = VarAlloc();
   p->name = strdup(name);
   p->value = strdup(value);
   p->prev = p;
   p->next = p;

   VarHead = p;

   return p;
   }
   p = VarHead;

   do
   {
   if(strcasecmp(p->name, name) == 0)
   {
   if (!(p->flags & VAR_STATIC))
      {
         if( p->value )
            free(p->value);
         
         p->value = strdup(value);
      }
   return (p);
   }
   p = p->next;

   } while(p != VarHead);

   p = VarAlloc();
   p->name = strdup(name);
   p->value = strdup(value);
   p->prev = VarHead;
   p->next = VarHead->next;
   p->next->prev = p;
   VarHead->next = p;
   
   return p;
}


/****************************************************************************
 *
 * Function: VarDelete(char *)
 *
 * Purpose: deletes a defined variable
 *
 * Arguments: name => the name of the variable
 *
 * Returns: void function
 *
 ***************************************************************************/
void VarDelete(char *name)
{
   struct VarEntry *p;


   if(!VarHead)
   return;

   p = VarHead;

   do
   {
   if(strcasecmp(p->name, name) == 0)
   {
      p->prev->next = p->next;
      p->next->prev = p->prev;

      if(VarHead == p)
         if((VarHead = p->next) == p)
            VarHead = NULL;

      if(p->name)
         free(p->name);

      if(p->value)
         free(p->value);

      free(p);

      return;
   }
   p = p->next;

   } while(p != VarHead);
}


/****************************************************************************
 *
 * Function: VarGet(char *)
 *
 * Purpose: get the contents of a variable
 *
 * Arguments: name => the name of the variable
 *
 * Returns: char * to contents of variable or ArgusLog on an
 *        undefined variable name
 *
 ***************************************************************************/
char *
VarGet(char *name) {
   struct VarEntry *p;

   if ((p = VarHead) != NULL) {
      do {
         if (!(strcasecmp(p->name, name)))
            return(p->value);
         p = p->next;
      } while(p != VarHead);
   }

   ArgusLog(LOG_ERR,"Undefined variable name: (%s:%d): %s\n", file_name, file_line, name);
   return NULL;
}

/****************************************************************************
 *
 * Function: ExpandVars(char *)
 *
 * Purpose: expand all variables in a string
 *
 * Arguments: string => the name of the variable
 *
 * Returns: char * to the expanded string
 *
 ***************************************************************************/
char *ExpandVars(char *string)
{
   static char estring[PARSERULE_SIZE];
   char rawvarname[128], varname[128], varaux[128], varbuffer[128], varmodifier, *varcontents;
   int varname_completed, c, i, j, iv, jv, l_string, name_only;
   int quote_toggle = 0;

   if(!string || !*string || !strchr(string, '$'))
   return(string);

   bzero((char *) estring, sizeof(estring));

   i = j = 0;
   l_string = strlen(string);
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES, "ExpandVars, Before: %s\n", string););

   while(i < l_string && j < sizeof(estring) - 1)
   {
   c = string[i++];
   
   if(c == '"')
   {
      /* added checks to make sure that we are inside a quoted string
      */
      quote_toggle ^= 1;
   }

   if(c == '$' && !quote_toggle)
   {
      bzero((char *) rawvarname, sizeof(rawvarname));
      varname_completed = 0;
      name_only = 1;
      iv = i;
      jv = 0;

      if(string[i] == '(')
      {
         name_only = 0;
         iv = i + 1;
      }

      while(!varname_completed
          && iv < l_string
          && jv < sizeof(rawvarname) - 1)
      {
         c = string[iv++];

         if((name_only && !(isalnum(c) || c == '_'))
           || (!name_only && c == ')'))
         {
            varname_completed = 1;

            if(name_only)
               iv--;
         }
         else
         {
            rawvarname[jv++] = c;
         }
      }

      if(varname_completed || iv == l_string)
      {
         char *p;

         i = iv;

         varcontents = NULL;

         bzero((char *) varname, sizeof(varname));
         bzero((char *) varaux, sizeof(varaux));
         varmodifier = ' ';

         if((p = strchr(rawvarname, ':')))
         {
            strncpy(varname, rawvarname, p - rawvarname);

            if(strlen(p) >= 2)
            {
               varmodifier = *(p + 1);
               strcpy(varaux, p + 2);
            }
         }
         else
            strcpy(varname, rawvarname);

         bzero((char *) varbuffer, sizeof(varbuffer));

         varcontents = VarGet(varname);

         switch(varmodifier)
         {
            case '-':
               if(!varcontents || !strlen(varcontents))
                  varcontents = varaux;
               break;

            case '?':
               if(!varcontents || !strlen(varcontents))
               {
                  ArgusLog(LOG_ALERT,"%s(%d): ", file_name, file_line);

                  if(strlen(varaux))
                     ArgusLog(LOG_ERR,"%s\n", varaux);
                  else
                     ArgusLog(LOG_ERR,"Undefined variable \"%s\"\n", varname);
               }
               break;
         }

         if(varcontents)
         {
            int l_varcontents = strlen(varcontents);

            iv = 0;

            while(iv < l_varcontents && j < sizeof(estring) - 1)
               estring[j++] = varcontents[iv++];
         }
      }
      else
      {
         estring[j++] = '$';
      }
   }
   else
   {
      estring[j++] = c;
   }
   }

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES, "ExpandVars, After: %s\n", estring););

   return(estring);
}



/******************************************************************
 *
 * Function: LinkDynamicRules()
 *
 * Purpose: Move through the activation and dynamic lists and link
 *        the activation rules to the rules that they activate.
 *
 * Arguments: None
 *
 * Returns: void function
 *
 ******************************************************************/
void LinkDynamicRules()
{
   SetLinks(Activation.TcpList, Dynamic.TcpList);
   SetLinks(Activation.UdpList, Dynamic.UdpList);
   SetLinks(Activation.IcmpList, Dynamic.IcmpList);
}




/******************************************************************
 *
 * Function: SetLinks()
 *
 * Purpose: Move through the activation and dynamic lists and link
 *        the activation rules to the rules that they activate.
 *
 * Arguments: activator => the activation rules
 *         activatee => the rules being activated
 *
 * Returns: void function
 *
 ******************************************************************/
void SetLinks(RuleTreeNode * activator, RuleTreeNode * activated_by)
{
   RuleTreeNode *act_idx;
   RuleTreeNode *dyn_idx;
   OptTreeNode *act_otn_idx;

   act_idx = activator;
   dyn_idx = activated_by;

   /* walk thru the RTN list */
   while(act_idx != NULL)
   {
   if(act_idx->down != NULL)
   {
      act_otn_idx = act_idx->down;

      while(act_otn_idx != NULL)
      {
         act_otn_idx->RTN_activation_ptr = GetDynamicRTN(act_otn_idx->activates, dyn_idx);

         if(act_otn_idx->RTN_activation_ptr != NULL)
         {
            act_otn_idx->OTN_activation_ptr = GetDynamicOTN(act_otn_idx->activates, act_otn_idx->RTN_activation_ptr);
         }
         act_otn_idx = act_otn_idx->next;
      }
   }
   act_idx = act_idx->right;
   }
}



RuleTreeNode *GetDynamicRTN(int link_number, RuleTreeNode * dynamic_rule_tree)
{
   RuleTreeNode *rtn_idx;
   ActivateList *act_list;

   rtn_idx = dynamic_rule_tree;

   while(rtn_idx != NULL)
   {
   act_list = rtn_idx->activate_list;

   while(act_list != NULL)
   {
      if(act_list->activated_by == link_number)
      {
         return rtn_idx;
      }
      act_list = act_list->next;
   }

   rtn_idx = rtn_idx->right;
   }

   return NULL;
}




OptTreeNode *GetDynamicOTN(int link_number, RuleTreeNode * dynamic_rule_tree)
{
   OptTreeNode *otn_idx;

   otn_idx = dynamic_rule_tree->down;

   while(otn_idx != NULL)
   {
   if(otn_idx->activated_by == link_number)
   {
      return otn_idx;
   }
   otn_idx = otn_idx->next;
   }

   return NULL;
}


/****************************************************************************
 *
 * Function: ProcessAlertFileOption(char *)
 *
 * Purpose: define the alert file
 *
 * Arguments: filespec => the file specification
 *
 * Returns: void function
 *
 ***************************************************************************/
void
ProcessAlertFileOption(char *filespec)
{
   pv.alert_filename = ProcessFileOption(filespec);

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"alertfile set to: %s\n", 
         pv.alert_filename););
   return;
}


char *
ProcessFileOption(char *filespec)
{
   char *filename;
   char buffer[STD_BUF];

   bzero (buffer, STD_BUF);
   if(filespec == NULL) {
   ArgusLog(LOG_ERR,"no arguement in this file option, remove extra ':' at the end of the alert option\n");
   }

   /* look for ".." in the string and complain and exit if it is found */
   if(strstr(filespec, "..") != NULL) {
   ArgusLog(LOG_ERR,"file definition contains \"..\".  Do not do that!\n");
   }

   if(filespec[0] == '/') {
   /* absolute filespecs are saved as is */
   filename = strdup(filespec);
   } else {
   /* relative filespec is considered relative to the log directory */
   /* or /var/log if the log directory has not been set */
   
   if(pv.log_dir) {
      strncpy(buffer, pv.log_dir, STD_BUF);
   } else {
      strncpy(buffer, "/var/log/snort", STD_BUF);
   }

   strncat(buffer, "/", STD_BUF - strlen(buffer));
   strncat(buffer, filespec, STD_BUF - strlen(buffer));
   filename = strdup(buffer);
   }

   if(!pv.quiet_flag)
   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"ProcessFileOption: %s\n", filename););

   return filename;
}

unsigned int giFlowbitSize = 0; /** size of flowbits tracking */

void
ProcessFlowbitsSize(char **args, int nargs) {
   int i;
   char *pcEnd;

   if(nargs) {
      i = strtol(args[0], &pcEnd, 10);
      if(*pcEnd || i < 0 || i > 256) {
         ArgusLog(LOG_ERR,"%s(%d) => Invalid argument to 'flowbits_size'.  "  
                 "Must be a positive integer and less than 256.\n",
                 file_name, file_line);
      }
   
      giFlowbitSize = (unsigned int)i;
   }

   return;
}

void
ProcessDetectionOptions( char ** args, int nargs ) {
   int i;
   
   for(i=0;i<nargs;i++) {
      if( !strcasecmp(args[i],"search-method") ) {
         i++;
         if( i < nargs ) {
           if(fpSetDetectSearchMethod(args[i])) {
              ArgusLog(LOG_ERR,"%s (%d)=> Invalid argument to 'search-method'.  Must be either 'mwm' or 'ac'.\n", file_name, file_line);
           }
        } else {
           ArgusLog(LOG_ERR,"%s (%d)=> No argument to 'search-method'. Must be either 'mwm' or 'ac'.\n", file_name, file_line);
        }
      } else if(!strcasecmp(args[i], "debug")) {
        fpSetDebugMode();
      } else if(!strcasecmp(args[i], "no_stream_inserts")) {
        fpSetStreamInsert();
      } else if(!strcasecmp(args[i], "max_queue_events")) {
         i++;
         if(i < nargs) {
            if(fpSetMaxQueueEvents(atoi(args[i]))) {
              ArgusLog(LOG_ERR,"%s (%d)=> Invalid argument to 'max_queue_events'.  Argument must be greater than 0.\n",
                   file_name, file_line);
            }
         }
      } else {
        ArgusLog(LOG_ERR,"%s (%d)=> '%s' is an invalid option to the 'config detection:' configuration.\n", 
             file_name, file_line, args[i]);
      }
   }
}

/* verify that we are not reusing some other keyword */
int
checkKeyword(char *keyword) {
   RuleListNode *node = RuleLists;

   if(RuleType(keyword) != RULE_UNKNOWN)
   return 1;
   /* check the declared ruletypes now */
   while(node != NULL) {
   if(!strcasecmp(node->name, keyword)) {
      return 1;
   }
   node = node->next;
   }
   return 0;
}

void
ParseRuleTypeDeclaration(FILE* rule_file, char *rule) {
   char *input;
   char *keyword;
   char **toks;
   int num_toks;
   int type;
   int rval = 1;
   ListHead *listhead = NULL;

   toks = mSplit(rule, " ", 10, &num_toks, 0);
   keyword = strdup(toks[1]);

   /* Verify keyword is unique */
   if(checkKeyword(keyword)) {
   ArgusLog(LOG_ERR,"%s(%d): Duplicate keyword: %s\n", file_name, file_line, keyword);
   }

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Declaring new rule type: %s\n", keyword););

   if(num_toks > 2) {
   if(strcasecmp("{", toks[2]) != 0) {
      ArgusLog(LOG_ERR,"%s(%d): Syntax error: %s\n",
              file_name, file_line, rule);
   }
   } else {
   input = ReadLine(rule_file);
   free(input);
   }

   input = ReadLine(rule_file);

   mSplitFree(&toks, num_toks);

   toks = mSplit(input, " ", 10, &num_toks, 0);

   /* read the type field */
   if(!strcasecmp("type", toks[0])) {
   type = RuleType(toks[1]);
   /* verify it is a valid ruletype */
   if((type != RULE_LOG) && (type != RULE_PASS) && (type != RULE_ALERT) &&
     (type != RULE_ACTIVATE) && (type != RULE_DYNAMIC))
   {
      ArgusLog(LOG_ERR,"%s(%d): Invalid type for rule type declaration: %s\n", file_name, file_line, toks[1]);
   }

   DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"\ttype(%i): %s\n", type, toks[1]););

   if(type == RULE_PASS)
   {
      rval = 0;
   }

   listhead = CreateRuleType(keyword, type, rval, NULL);

   } else {
   ArgusLog(LOG_ERR,"%s(%d): Type not defined for rule file declaration: %s\n", file_name, file_line, keyword);
   }

   free(input);
   input = ReadLine(rule_file);
   
   mSplitFree(&toks, num_toks);

   toks = mSplit(input, " ", 2, &num_toks, 0);

   while(strcasecmp("}", toks[0]) != 0) {
   if(RuleType(toks[0]) != RULE_OUTPUT)
      ArgusLog(LOG_ERR,"%s(%d): Not an output plugin declaration: %s\n", file_name, file_line, keyword);

   head_tmp = listhead;
   ParseOutputPlugin(input);
   head_tmp = NULL;
   free(input);
   input = ReadLine(rule_file);

   mSplitFree(&toks, num_toks);
   toks = mSplit(input, " ", 2, &num_toks, 0);
   }

   mSplitFree(&toks, num_toks);
   pv.num_rule_types++;

   return;
}

/* adapted from ParseRuleFule in rules.c */
char *
ReadLine(FILE * file) {
   char buf[STD_BUF];
   char *index;

   bzero((char *) buf, STD_BUF);

   /*
   * Read a line from file and return it. Skip over lines beginning with #,
   * ;, or a newline
   */
   while((fgets(buf, STD_BUF, file)) != NULL) {
   file_line++;
   index = buf;
#ifdef DEBUG2
   LogMessage("Got line %s (%d): %s", file_name, file_line, buf);
#endif
   /* if it's not a comment or a <CR>, we return it */
   if((*index != '#') && (*index != 0x0a) && (*index != ';') && (index != NULL)) {
      /* advance through any whitespace at the beginning of ther line */
      while(isspace((int) *index))
         ++index;

      /* return a copy of the line */
      return strdup(index);
   }
   }

   return NULL;
}

/*
 * Same as VarGet - but this does not Fatal out if a var is not found
 */
char *
VarSearch(char *name) {
   struct VarEntry *p;
   if ((p = VarHead) != NULL) {
      do {
         if (!(strcasecmp(p->name, name)))
            return p->value;
         p = p->next;
      } while(p != VarHead);
   }
   return NULL;
}


/****************************************************************
 *
 *  Function: mSplit()
 *
 *  Purpose: Splits a string into tokens non-destructively.
 *
 *  Parameters:
 *     char *str => the string to be split
 *     char *sep => a string of token seperaters
 *     int max_strs => how many tokens should be returned
 *     int *toks => place to store the number of tokens found in str
 *     char meta => the "escape metacharacter", treat the character
 *               after this character as a literal and "escape" a
 *               seperator
 *
 *  Returns:
 *     2D char array with one token per "row" of the returned
 *     array.
 *
 ****************************************************************/
char **
mSplit(char *str, char *sep, int max_strs, int *toks, char meta) {
   char **retstr;     /* 2D array which is returned to caller */
   char *idx;        /* index pointer into str */
   char *end;        /* ptr to end of str */
   char *sep_end;     /* ptr to end of seperator string */
   char *sep_idx;     /* index ptr into seperator string */
   int len = 0;      /* length of current token string */
   int curr_str = 0;      /* current index into the 2D return array */
   char last_char = (char) 0xFF;

   if (!str) return NULL;

   *toks = 0;

   DEBUG_WRAP(ArgusDebug(DEBUG_PATTERN_MATCH, 
         "[*] Splitting string: %s\n", str);
      ArgusDebug(DEBUG_PATTERN_MATCH, "curr_str = %d\n", curr_str););

   /*
   * find the ends of the respective passed strings so our while() loops
   * know where to stop
   */
   sep_end = sep + strlen(sep);
   end = str + strlen(str);

   /* remove trailing whitespace */
   while(isspace((int) *(end - 1)) && ((end - 1) >= str))
   *(--end) = '\0';   /* -1 because of NULL */

   /* set our indexing pointers */
   sep_idx = sep;
   idx = str;

   /*
   * alloc space for the return string, this is where the pointers to the
   * tokens will be stored
   */
   if((retstr = (char **) malloc((sizeof(char **) * max_strs))) == NULL)
     ArgusLog(LOG_ERR, "malloc");

   max_strs--;
   DEBUG_WRAP(ArgusDebug(DEBUG_PATTERN_MATCH, "max_strs = %d  curr_str = %d\n", 
         max_strs, curr_str););

   /* loop thru each letter in the string being tokenized */
   while (idx < end) {
   /* loop thru each seperator string char */
   while(sep_idx < sep_end) {
      /*
      * if the current string-indexed char matches the current
      * seperator char...
      */
      if((*idx == *sep_idx) && (last_char != meta)) {
         /* if there's something to store... */
         if(len > 0) {
            DEBUG_WRAP( ArgusDebug(DEBUG_PATTERN_MATCH, 
                     "Allocating %d bytes for token ", len + 1););
            if(curr_str <= max_strs) {
               /* allocate space for the new token */
               if((retstr[curr_str] = (char *) malloc((sizeof(char) * len) + 1)) == NULL) {
                  ArgusLog(LOG_ERR, "malloc");
               }

               /* copy the token into the return string array */
               memcpy(retstr[curr_str], (idx - len), len);
               retstr[curr_str][len] = 0;
               DEBUG_WRAP(ArgusDebug(DEBUG_PATTERN_MATCH, 
                        "tok[%d]: %s\n", curr_str, 
                        retstr[curr_str]););

               /* twiddle the necessary pointers and vars */
               len = 0;
               curr_str++;
               DEBUG_WRAP(ArgusDebug(DEBUG_PATTERN_MATCH, 
                        "curr_str = %d\n", curr_str);
                     ArgusDebug(DEBUG_PATTERN_MATCH, 
                        "max_strs = %d  curr_str = %d\n", 
                        max_strs, curr_str););

               last_char = *idx;
               idx++;
            }

            DEBUG_WRAP(ArgusDebug(DEBUG_PATTERN_MATCH, 
                     "Checking if curr_str (%d) >= max_strs (%d)\n",
                    curr_str, max_strs););

            /*
            * if we've gotten all the tokens requested, return the
            * list
            */
            if(curr_str >= max_strs) {
              while(isspace((int) *idx))
                idx++;

              len = end - idx;
              DEBUG_WRAP(ArgusDebug(DEBUG_PATTERN_MATCH, 
                        "Finishing up...\n");
                     ArgusDebug(DEBUG_PATTERN_MATCH, 
                        "Allocating %d bytes "
                        "for last token ", len + 1););
              fflush(stdout);

              if((retstr[curr_str] = (char *)
                        malloc((sizeof(char) * len) + 1)) == NULL)
                  ArgusLog(LOG_ERR, "malloc");

              memcpy(retstr[curr_str], idx, len);
              retstr[curr_str][len] = 0;

              DEBUG_WRAP(ArgusDebug(DEBUG_PATTERN_MATCH, 
                        "tok[%d]: %s\n", curr_str, 
                        retstr[curr_str]););

              *toks = curr_str + 1;
              DEBUG_WRAP(ArgusDebug(DEBUG_PATTERN_MATCH, 
                        "max_strs = %d  curr_str = %d\n", 
                        max_strs, curr_str);
                     ArgusDebug(DEBUG_PATTERN_MATCH, 
                        "mSplit got %d tokens!\n", *toks););

              return retstr;
           }

         } else {
            /*
            * otherwise, the previous char was a seperator as well,
            * and we should just continue
            */
            last_char = *idx;
            idx++;
            /* make sure to reset this so we test all the sep. chars */
            sep_idx = sep;
            len = 0;
         }
      } else {
         /* go to the next seperator */
         sep_idx++;
      }
   }

   sep_idx = sep;
   len++;
   last_char = *idx;
   idx++;
   }

   /* put the last string into the list */

   if (len > 0) {
     DEBUG_WRAP(ArgusDebug(DEBUG_PATTERN_MATCH, 
            "Allocating %d bytes for last token ", len + 1););

     if((retstr[curr_str] = (char *) malloc((sizeof(char) * len) + 1)) == NULL)
    ArgusLog(LOG_ERR, "malloc");

     memcpy(retstr[curr_str], (idx - len), len);
     retstr[curr_str][len] = 0;

     DEBUG_WRAP(ArgusDebug(DEBUG_PATTERN_MATCH,"tok[%d]: %s\n", curr_str, 
            retstr[curr_str]););
     *toks = curr_str + 1;
   }

   DEBUG_WRAP(ArgusDebug(DEBUG_PATTERN_MATCH, 
         "mSplit got %d tokens!\n", *toks););

   /* return the token list */
   return retstr;
}

/****************************************************************
 *
 * Free the buffer allocated by mSplit().
 *
 * char** toks = NULL;
 * int num_toks = 0;
 * toks = (str, " ", 2, &num_toks, 0);
 * mSplitFree(&toks, num_toks);
 *
 * At this point, toks is again NULL.
 *
 ****************************************************************/
void
mSplitFree(char ***pbuf, int num_toks) {
   int i;
   char** buf;  /* array of string pointers */

   if( pbuf==NULL || *pbuf==NULL ) {
   return;
   }

   buf = *pbuf;

   for(i = 0; i < num_toks; i++) {
     if( buf[i] != NULL ) {
    free( buf[i] );
    buf[i] = NULL;
     }
   }

   free(buf);
   *pbuf = NULL;
}


/* $Id: parser.c,v 1.3 2004/05/14 15:44:35 qosient Exp $ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2002, Sourcefire, Inc.
**   Dan Roelker <droelker@sourcefire.com>
**   Marc Norton <mnorton@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
** NOTES
**   5.7.02: Added interface for new detection engine. (Norton/Roelker)
**
*/

/* #define ITERATIVE_ENGINE */

extern ListHead Alert;       /* Alert Block Header */
extern ListHead Log;         /* Log Block Header */
extern ListHead Pass;        /* Pass Block Header */
extern ListHead Activation;   /* Activation Block Header */
extern ListHead Dynamic;      /* Dynamic Block Header */

extern RuleTreeNode *rtn_tmp;     /* temp data holder */
extern OptTreeNode *otn_tmp;      /* OptTreeNode temp ptr */
extern ListHead *head_tmp;       /* ListHead temp ptr */

extern RuleListNode *RuleLists;

extern int dynamic_rules_present;
extern int active_dynamic_nodes;

extern PreprocessFuncNode *PreprocessList;  /* Preprocessor function list */
extern OutputFuncNode *AlertList;   /* Alert function list */
extern OutputFuncNode *LogList; /* log function list */

/*
**  The HTTP decode structre
*/
extern HttpUri UriBufs[URI_COUNT];

int do_detect;
u_int32_t event_id;
char check_tags_flag;

void printRuleListOrder(RuleListNode * node);
static RuleListNode *addNodeToOrderedList(RuleListNode *ordered_list, 
   RuleListNode *node, int evalIndex);

void
CallLogFuncs(struct ArgusRecord *argus, char *message, ListHead *head, Event *event)
{
   OutputFuncNode *idx = NULL;
   
   if (argus) {
      event->ref_time.tv_sec  = argus->argus_far.time.start.tv_sec;
      event->ref_time.tv_usec = argus->argus_far.time.start.tv_usec;
   /* *  Perform Thresholding Tests */
      if( !sfthreshold_test( event->sig_generator,
                             event->sig_id,
                             argus->argus_far.flow.ip_flow.ip_src,
                             argus->argus_far.flow.ip_flow.ip_src,
                             event->ref_time.tv_sec ) ) {
         return; /* Don't log it ! */
      }
   }

   /* set the event number */
   event->event_id = event_id;

   if(head == NULL) {
      CallLogPlugins(argus, message, NULL, event);
      return;
   }

   pc.log_pkts++;
    
   idx = head->LogList;
   if(idx == NULL)
   idx = LogList;

   while(idx != NULL) {
/*
      idx->func(argus, message, idx->arg, event);
      idx = idx->next;
*/
   }
   return;
}

void
CallLogPlugins(struct ArgusRecord *argus, char *message, void *args, Event *event)
{
   OutputFuncNode *idx;

   idx = LogList;
   pc.log_pkts++;

   while(idx != NULL) {
/*
      idx->func(argus, message, idx->arg, event);
      idx = idx->next;
*/
   }
   return;
}

/* Call the output functions that are directly attached to the signature */
void
CallSigOutputFuncs(struct ArgusRecord *argus, OptTreeNode *otn, Event *event) {
   OutputFuncNode *idx = otn->outputFuncs;

   while(idx) {
/*
      idx->func(argus, otn->sigInfo.message, idx->arg, event);
      idx = idx->next;
*/
   }
}

void
CallAlertFuncs(struct ArgusRecord *argus, char *message, ListHead * head, Event *event) {
   OutputFuncNode *idx = NULL;

   if (argus) {
      event->ref_time.tv_sec  = argus->argus_far.time.start.tv_sec;
      event->ref_time.tv_usec = argus->argus_far.time.start.tv_usec;
   /* *  Perform Thresholding Tests */
      if (argus) {
         if (!sfthreshold_test( event->sig_generator,
                        event->sig_id,
                        argus->argus_far.flow.ip_flow.ip_src,
                        argus->argus_far.flow.ip_flow.ip_src,
                        event->ref_time.tv_sec)) {
            return; /* Don't log it ! */
         }
      }
   }
   /* set the event number */
   event->event_id = ++event_id;
   /* set the event reference info */
   event->event_reference = event->event_id;
   /* set the event number */
   event->event_id = ++event_id;
   /* set the event reference info */
   event->event_reference = event->event_id;

   if(head == NULL) {
      CallAlertPlugins(argus, message, NULL, event);
      return;
   }

   pc.alert_pkts++;
   idx = head->AlertList;

   if(idx == NULL)
      idx = AlertList;

   while(idx != NULL) {
/*
      idx->func(p, message, idx->arg, event);
      idx = idx->next;
*/
   }
   return;
}


void CallAlertPlugins(struct ArgusRecord *argus, char *message, void *args, Event *event)
{
   OutputFuncNode *idx;

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "Call Alert Plugins\n"););
   idx = AlertList;

   pc.alert_pkts++;
   while(idx != NULL) {
/*
      idx->func(p, message, idx->arg, event);
      idx = idx->next;
*/
   }

   return;
}



/****************************************************************************
 *
 * Function: Detect(struct ArgusRecord *)
 *
 * Purpose: Apply the rules lists to the current packet
 *
 * Arguments: p => ptr to the decoded packet struct
 *
 * Returns: 1 == detection event
 *        0 == no detection
 *
 ***************************************************************************/

int CheckTagList(struct ArgusRecord *p, Event *event) {return (0);}
int AlertFlushStream(struct ArgusRecord *p) {return (0);}

int
Detect(struct ArgusRecord *argus) {
   Event event;
   RuleListNode *rule;

   rule = RuleLists;
   check_tags_flag = 1;

   /*
   **  This is where we short circuit so 
   **  that we can do IP checks.
   */
   fpEvalArgusRecord (argus);

   DEBUG_WRAP(ArgusDebug(DEBUG_FLOW, "Checking tags list (if "
         "check_tags_flag = 1)\n"););

   /* if we didn't match on any rules, check the tag list */
   if(check_tags_flag == 1) {
      DEBUG_WRAP(ArgusDebug(DEBUG_FLOW, "calling CheckTagList\n"););

      if(CheckTagList(argus, &event)) {
         DEBUG_WRAP(ArgusDebug(DEBUG_FLOW, "Matching tag node found, "
                  "calling log functions\n"););

         /* if we find a match, we want to send the packet to the
          * logging mechanism
          */
         CallLogFuncs(argus, "Tagged struct ArgusRecord", NULL, &event);
         return 1;
      } 
   }

   return 0;
}

void
TriggerResponses(struct ArgusRecord *argus, OptTreeNode *otn) {

   RspFpList *idx;

   idx = otn->rsp_func;

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"Triggering responses %p\n", idx););

/*
   while(idx != NULL) {
      idx->ResponseFunc(argus, idx);
      idx = idx->next;
   }
*/
}

int CheckAddrPort(IpAddrSet *rule_addr, u_int16_t hi_port, u_int16_t lo_port, 
                  struct ArgusRecord *argus, u_int32_t flags, int mode)
{
   u_long pkt_addr;       /* packet IP address */
   u_short pkt_port;      /* packet port */
   int global_except_addr_flag = 0; /* global exception flag is set */
   int any_port_flag = 0;         /* any port flag set */
   int except_addr_flag = 0;      /* any addr flag set */
   int except_port_flag = 0;      /* port exception flag set */
   int ip_match = 0;            /* flag to indicate addr match made */
   IpAddrSet *idx;  /* ip addr struct indexer */

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "CheckAddrPort: "););
   /* set up the packet particulars */
   if(mode & CHECK_SRC) {
      pkt_addr = argus->argus_far.flow.ip_flow.ip_src;
      pkt_port = argus->argus_far.flow.ip_flow.sport;

      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"SRC "););

      if(mode & INVERSE) {
         global_except_addr_flag = flags & EXCEPT_DST_IP;
         any_port_flag = flags & ANY_DST_PORT;
         except_port_flag = flags & EXCEPT_DST_PORT;
      } else {
         global_except_addr_flag = flags & EXCEPT_SRC_IP;
         any_port_flag = flags & ANY_SRC_PORT;
         except_port_flag = flags & EXCEPT_SRC_PORT;
      }
   } else {
      pkt_addr = argus->argus_far.flow.ip_flow.ip_dst;
      pkt_port = argus->argus_far.flow.ip_flow.dport;

      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "DST "););

      if(mode & INVERSE) {
         global_except_addr_flag = flags & EXCEPT_SRC_IP;
         any_port_flag = flags & ANY_SRC_PORT;
         except_port_flag = flags & EXCEPT_SRC_PORT;
      } else {
         global_except_addr_flag = flags & EXCEPT_DST_IP;
         any_port_flag = flags & ANY_DST_PORT;
         except_port_flag = flags & EXCEPT_DST_PORT;
      }
   }

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "addr %lx, port %d ", pkt_addr, pkt_port););

   idx = rule_addr;
   if(!(global_except_addr_flag)) {
       /*modeled after Check{Src,Dst}IP function*/
      while(idx != NULL) {
         except_addr_flag = idx->addr_flags & EXCEPT_IP;

         /* test the rule address vs. the packet address */
         if(!((idx->ip_addr==(pkt_addr & idx->netmask)) ^ except_addr_flag)) {
            idx = idx->next;
         } else {
            ip_match = 1;
            goto bail;
         }
      }
   } else {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, ", global exception flag set"););
      /* global exception flag is up, we can't match on *any* 
       * of the source addresses 
       */
      while(idx != NULL) {
         except_addr_flag = idx->addr_flags & EXCEPT_IP;

         /* test the rule address vs. the packet address */
         if(((idx->ip_addr == (pkt_addr & idx->netmask)) ^ except_addr_flag)) {
            DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, ", address matched, flow rejected\n"));

            /* got address match on globally negated rule, fail */
            return 0;
         }
         idx = idx->next;
      }
      ip_match = 1;
   }

   bail:
   if(!ip_match) {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, ", no address match, flow rejected\n"););
      return 0;
   }

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, ", addresses accepted"););
   
   /* if the any port flag is up, we're all done (success) */
   if(any_port_flag) {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, ", any port match, flow accepted\n"););
      return 1;
   }

   /* check the packet port against the rule port */
   if((pkt_port > hi_port) || (pkt_port < lo_port)) {
   /* if the exception flag isn't up, fail */
      if(!except_port_flag) {
         DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, ", port mismatch, flow rejected\n"););
         return 0;
      }
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, ", port mismatch exception"););
   } else {
      /* if the exception flag is up, fail */
      if(except_port_flag) {
         DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, ", port match exception, flow rejected\n"););
         return 0;
      }
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, ", ports match"););
   }

   /* ports and address match */
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, ", flow accepted!\n"););
   return 1;
}

/****************************************************************************
 *
 * Function: DumpChain(RuleTreeNode *, char *, char *)
 *
 * Purpose: print out the chain lists by header block node group
 *
 * Arguments: rtn_idx => the RTN index pointer
 *                  rulename => the name of the rule the list belongs to
 *         listname => the name of the list being printed out
 *
 * Returns: void function
 *
 ***************************************************************************/
void DumpChain(RuleTreeNode * rtn_head, char *rulename, char *listname)
{
   RuleTreeNode *rtn_idx;
   IpAddrSet *idx;  /* indexing pointer */
   int i;
#ifdef DEBUG
   OptTreeNode *otn_idx;
#endif


   
   DEBUG_WRAP(ArgusDebug(DEBUG_RULES, "%s %s\n", rulename, listname););

   rtn_idx = rtn_head;

   if(rtn_idx == NULL)
   DEBUG_WRAP(ArgusDebug(DEBUG_RULES, "   Empty!\n\n"););

   /* walk thru the RTN list */
   while(rtn_idx != NULL)
   {
   DEBUG_WRAP(
         ArgusDebug(DEBUG_RULES, "Rule type: %d\n", rtn_idx->type);
         ArgusDebug(DEBUG_RULES, "SRC IP List:\n");
         );
   idx = rtn_idx->sip;
   i = 0;
   while(idx != NULL)
   {
      DEBUG_WRAP(ArgusDebug(DEBUG_RULES,
               "[%d]   0x%.8lX / 0x%.8lX",
               i++, (u_long) idx->ip_addr,
               (u_long) idx->netmask););

      if(idx->addr_flags & EXCEPT_IP)
      {
         DEBUG_WRAP(ArgusDebug(DEBUG_RULES, 
                  "   (EXCEPTION_FLAG Active)\n"););
      }
      else
      {
         DEBUG_WRAP(ArgusDebug(DEBUG_RULES, "\n"););
      }
      idx = idx->next;
   }

   DEBUG_WRAP(ArgusDebug(DEBUG_RULES, "DST IP List:\n"););
   idx = rtn_idx->dip;
   i = 0;

   while(idx != NULL)
   {
      DEBUG_WRAP(ArgusDebug(DEBUG_RULES,
               "[%d]   0x%.8lX / 0x%.8lX",
               i++,(u_long)  idx->ip_addr,
               (u_long)  idx->netmask););      
      if(idx->addr_flags & EXCEPT_IP)
      {
         DEBUG_WRAP(ArgusDebug(DEBUG_RULES, 
                  "   (EXCEPTION_FLAG Active)\n"););
      }
      else
      {
         DEBUG_WRAP(ArgusDebug(DEBUG_RULES, "\n"););
      }

      idx = idx->next;
   }
#ifdef DEBUG
   ArgusDebug(DEBUG_RULES, "SRC PORT: %d - %d \n", rtn_idx->lsp, 
         rtn_idx->hsp);
   ArgusDebug(DEBUG_RULES, "DST PORT: %d - %d \n", rtn_idx->ldp, 
         rtn_idx->hdp);
   ArgusDebug(DEBUG_RULES, "Flags: ");

   if(rtn_idx->flags & EXCEPT_SRC_IP)
      ArgusDebug(DEBUG_RULES, "EXCEPT_SRC_IP ");
   if(rtn_idx->flags & EXCEPT_DST_IP)
      ArgusDebug(DEBUG_RULES, "EXCEPT_DST_IP ");
   if(rtn_idx->flags & ANY_SRC_PORT)
      ArgusDebug(DEBUG_RULES, "ANY_SRC_PORT ");
   if(rtn_idx->flags & ANY_DST_PORT)
      ArgusDebug(DEBUG_RULES, "ANY_DST_PORT ");
   if(rtn_idx->flags & EXCEPT_SRC_PORT)
      ArgusDebug(DEBUG_RULES, "EXCEPT_SRC_PORT ");
   if(rtn_idx->flags & EXCEPT_DST_PORT)
      ArgusDebug(DEBUG_RULES, "EXCEPT_DST_PORT ");
   ArgusDebug(DEBUG_RULES, "\n");

   otn_idx = rtn_idx->down;

      DEBUG_WRAP(
            /* print the RTN header number */
            ArgusDebug(DEBUG_RULES,
               "Head: %d (type: %d)\n",
               rtn_idx->head_node_number, otn_idx->type);
            ArgusDebug(DEBUG_RULES, "     |\n");
            ArgusDebug(DEBUG_RULES, "      ->");
            );

      /* walk thru the OTN chain */
      while(otn_idx != NULL)
      {
         DEBUG_WRAP(ArgusDebug(DEBUG_RULES,
                  " %d", otn_idx->chain_node_number););
         otn_idx = otn_idx->next;
      }

   DEBUG_WRAP(ArgusDebug(DEBUG_RULES, "|=-\n"););
#endif
   rtn_idx = rtn_idx->right;
   }
}



void IntegrityCheck(RuleTreeNode * rtn_head, char *rulename, char *listname)
{
   RuleTreeNode *rtn_idx = NULL;
   OptTreeNode *otn_idx;
   OptFpList *ofl_idx;
   int opt_func_count;

#ifdef DEBUG
   char chainname[STD_BUF];

   snprintf(chainname, STD_BUF - 1, "%s %s", rulename, listname);

   if(!pv.quiet_flag)
   ArgusDebug(DEBUG_DETECT, "%-20s: ", chainname);
#endif

   if(rtn_head == NULL)
   {
#ifdef DEBUG
   if(!pv.quiet_flag)
      ArgusDebug(DEBUG_DETECT,"Empty list...\n");
#endif
   return;
   }

   rtn_idx = rtn_head;

   while(rtn_idx != NULL)
   {
   otn_idx = rtn_idx->down;

   while(otn_idx != NULL)
   {
      ofl_idx = otn_idx->opt_func;
      opt_func_count = 0;

      while(ofl_idx != NULL)
      {
         opt_func_count++;
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "%p->",ofl_idx->OptTestFunc););
         ofl_idx = ofl_idx->next;
      }

      if(opt_func_count == 0) {
         ArgusLog(LOG_ERR, "Zero Length OTN List\n");
      }
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"\n"););
      otn_idx = otn_idx->next;
   }

   rtn_idx = rtn_idx->right;
   }

#ifdef DEBUG
   if(!pv.quiet_flag)
   ArgusDebug(DEBUG_DETECT, "OK\n");
#endif

}



int CheckBidirectional(struct ArgusRecord *p, struct _RuleTreeNode *rtn_idx, 
   RuleFpList *fp_list)
{
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "Checking bidirectional rule...\n"););
   
   if(CheckAddrPort(rtn_idx->sip, rtn_idx->hsp, rtn_idx->lsp, p,
             rtn_idx->flags, CHECK_SRC))
   {
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "   Src->Src check passed\n"););
   if(! CheckAddrPort(rtn_idx->dip, rtn_idx->hdp, rtn_idx->ldp, p,
                  rtn_idx->flags, CHECK_DST))
   {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,
            "   Dst->Dst check failed,"
            " checking inverse combination\n"););
      if(CheckAddrPort(rtn_idx->dip, rtn_idx->hdp, rtn_idx->ldp, p,
                   rtn_idx->flags, (CHECK_SRC | INVERSE)))
      {
         DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,
            "   Inverse Dst->Src check passed\n"););
         if(!CheckAddrPort(rtn_idx->sip, rtn_idx->hsp, rtn_idx->lsp, p,
                       rtn_idx->flags, (CHECK_DST | INVERSE)))
         {
            DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,
               "   Inverse Src->Dst check failed\n"););
            return 0;
         }
         else
         {
            DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "Inverse addr/port match\n"););
         }
      }
      else
      {
         DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "   Inverse Dst->Src check failed,"
            " trying next rule\n"););
         return 0;
      }
   }
   else
   {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "dest IP/port match\n"););
   }
   }
   else
   {
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,
         "   Src->Src check failed, trying inverse test\n"););
   if(CheckAddrPort(rtn_idx->dip, rtn_idx->hdp, rtn_idx->ldp, p,
                rtn_idx->flags, CHECK_SRC | INVERSE))
   {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,
               "   Dst->Src check passed\n"););

      if(! CheckAddrPort(rtn_idx->sip, rtn_idx->hsp, rtn_idx->lsp, p, 
               rtn_idx->flags, CHECK_DST | INVERSE))
      {
         DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,
                  "   Src->Dst check failed\n"););
         return 0;
      }
      else
      {
         DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,
                  "Inverse addr/port match\n"););
      }
   }
   else
   { 
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"   Inverse test failed, "
               "testing next rule...\n"););
      return 0;
   }
   }

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"   Bidirectional success!\n"););
   return 1;
}



/****************************************************************************
 *
 * Function: CheckSrcIpEqual(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the source IP and see if it equals the SIP of the packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *         rtn_idx => ptr to the current rule data struct
 *         fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int
CheckSrcIP(struct ArgusRecord *argus, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
   IpAddrSet *idx; /* ip address indexer */

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"CheckSrcIPEqual: "););

   /* check for global exception flag */
   if(!(rtn_idx->flags & EXCEPT_SRC_IP)) {
      /* do the check */
      for(idx=rtn_idx->sip; idx != NULL; idx=idx->next) {
         if( ((idx->ip_addr == (argus->argus_far.flow.ip_flow.ip_src & idx->netmask)) 
                  ^ (idx->addr_flags & EXCEPT_IP)) ) {
#ifdef DEBUG
            if(idx->addr_flags & EXCEPT_IP) {
               ArgusDebug(DEBUG_DETECT, "  SIP exception match\n");
            } else {
               ArgusDebug(DEBUG_DETECT, "  SIP match\n");
            }

            ArgusDebug(DEBUG_DETECT, "Rule: 0x%X    struct ArgusRecord: 0x%X\n", 
                  idx->ip_addr, (argus->argus_far.flow.ip_flow.ip_src & idx->netmask));
#endif /* DEBUG */

            /* the packet matches this test, proceed to the next test */
            return fp_list->next->RuleHeadFunc(argus, rtn_idx, fp_list->next);
         }
      }

   } else {
      /* global exception flag is up, we can't match on *any* 
       * of the source addresses 
       */
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"  global exception flag, \n"););

      /* do the check */
      for(idx=rtn_idx->sip; idx != NULL; idx=idx->next) {
         if( ((idx->ip_addr == (argus->argus_far.flow.ip_flow.ip_dst & idx->netmask)) ^
                                                           (idx->addr_flags & EXCEPT_IP)) ) {
            DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"address matched, failing on SIP\n"););
            /* got address match on globally negated rule, fail */
            return 0;
         }
      }
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"no matches on SIP, passed\n"););

      return fp_list->next->RuleHeadFunc(argus, rtn_idx, fp_list->next);
   }
   
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"  Mismatch on SIP\n"););

   /* return 0 on a failed test */
   return 0;
}



/****************************************************************************
 *
 * Function: CheckSrcIpNotEq(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the source IP and see if it's unequal to the SIP of the
 *        packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *         rtn_idx => ptr to the current rule data struct
 *         fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int
CheckSrcIPNotEq(struct ArgusRecord *argus, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
   IpAddrSet *idx;  /* IP address indexer */
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "CheckSrcIPNotEq: "););

   /* do the check */
   for(idx=rtn_idx->sip; idx != NULL; idx=idx->next) {
      if( idx->ip_addr != (argus->argus_far.flow.ip_flow.ip_src & idx->netmask) ) {
         DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "  SIP exception match\n"););
         /* the packet matches this test, proceed to the next test */
         return fp_list->next->RuleHeadFunc(argus, rtn_idx, fp_list->next);
      }
   }

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "  Mismatch on SIP\n"););
   /* return 0 on a failed test */
   return 0;
}



/****************************************************************************
 *
 * Function: CheckDstIpEqual(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the dest IP and see if it equals the DIP of the packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *         rtn_idx => ptr to the current rule data struct
 *         fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int
CheckDstIP(struct ArgusRecord *argus, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
   IpAddrSet *idx;  /* ip address indexer */

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "CheckDstIPEqual: ");)

   /* check for global exception flag */
   if(!(rtn_idx->flags & EXCEPT_DST_IP)) {
      /* do the check */
      for(idx=rtn_idx->dip; idx != NULL; idx=idx->next) {
         if( ((idx->ip_addr == (argus->argus_far.flow.ip_flow.ip_dst & idx->netmask)) 
                  ^ (idx->addr_flags & EXCEPT_IP)) ) {
#ifdef DEBUG
            if(idx->addr_flags & EXCEPT_IP) {
               ArgusDebug(DEBUG_DETECT, "  DIP exception match\n");
            } else {
               ArgusDebug(DEBUG_DETECT, "  DIP match\n");
            }
         
            ArgusDebug(DEBUG_DETECT, "Rule: 0x%X    struct ArgusRecord: 0x%X\n", 
                  idx->ip_addr, (argus->argus_far.flow.ip_flow.ip_src & idx->netmask));
#endif /* DEBUG */
         /* the packet matches this test, proceed to the next test */
            return fp_list->next->RuleHeadFunc(argus, rtn_idx, fp_list->next);
         }
      }

   } else {
   /* global exception flag is up, we can't match on *any* 
    * of the source addresses 
    */
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "  global exception flag, \n"););
      /* do the check */
      for(idx=rtn_idx->dip; idx != NULL; idx=idx->next) {
         if( ((idx->ip_addr == (argus->argus_far.flow.ip_flow.ip_dst & idx->netmask)) 
                  ^ (idx->addr_flags & EXCEPT_IP)) ) {
            DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,
               "address matched, failing on DIP\n"););
            /* got address match on globally negated rule, fail */
            return 0;
         }
      }
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "no matches on DIP, passed\n"););
      return fp_list->next->RuleHeadFunc(argus, rtn_idx, fp_list->next);
   }

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "  Mismatch on DIP\n"););
   /* return 0 on a failed test */
   return 0;
}


/****************************************************************************
 *
 * Function: CheckDstIpNotEq(struct ArgusRecord *, struct _RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the dest IP and see if it equals the DIP of the packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *         rtn_idx => ptr to the current rule data struct
 *         fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int
CheckDstIPNotEq(struct ArgusRecord *argus, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
   IpAddrSet *idx; /* ip address indexer */

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"CheckDstIPNotEq: "););
   /* same as above */
   for(idx=rtn_idx->dip;idx != NULL; idx=idx->next) {
      if( idx->ip_addr != (argus->argus_far.flow.ip_flow.ip_dst & idx->netmask) ) {
         DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"  DIP exception match\n"););
         return fp_list->next->RuleHeadFunc(argus, rtn_idx, fp_list->next);
      }
   }
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"  Mismatch on DIP\n"););
   return 0;
}

int
CheckSrcPortEqual(struct ArgusRecord *argus, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"CheckSrcPortEqual: "););

   if( (argus->argus_far.flow.ip_flow.sport <= rtn_idx->hsp) && 
       (argus->argus_far.flow.ip_flow.sport >= rtn_idx->lsp) ) {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "  SP match!\n"););
      return fp_list->next->RuleHeadFunc(argus, rtn_idx, fp_list->next);
   } else {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "   SP mismatch!\n"););
   }

   return 0;
}


int
CheckSrcPortNotEq(struct ArgusRecord *argus, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "CheckSrcPortNotEq: "););

   if( (argus->argus_far.flow.ip_flow.sport > rtn_idx->hsp) || 
       (argus->argus_far.flow.ip_flow.sport < rtn_idx->lsp) ) {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "  SP exception match!\n"););
      return fp_list->next->RuleHeadFunc(argus, rtn_idx, fp_list->next);
   } else {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"   SP mismatch!\n"););
   }
   return 0;
}

int
CheckDstPortEqual(struct ArgusRecord *argus, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"CheckDstPortEqual: "););

   if( (argus->argus_far.flow.ip_flow.dport <= rtn_idx->hdp) && 
       (argus->argus_far.flow.ip_flow.dport >= rtn_idx->ldp) ) {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, " DP match!\n"););
      return fp_list->next->RuleHeadFunc(argus, rtn_idx, fp_list->next);
   } else {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT," DP mismatch!\n"););
   }
   return 0;
}

int
CheckDstPortNotEq(struct ArgusRecord *argus, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "CheckDstPortNotEq: "););

   if( (argus->argus_far.flow.ip_flow.dport > rtn_idx->hdp) || 
       (argus->argus_far.flow.ip_flow.dport < rtn_idx->ldp) ) {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT," DP exception match!\n"););
      return fp_list->next->RuleHeadFunc(argus, rtn_idx, fp_list->next);
   } else {
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT," DP mismatch!\n"););
   }
   return 0;
}


int
RuleListEnd(struct ArgusRecord *argus, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
   return 1;
}


int
OptListEnd(struct ArgusRecord *argus, struct _OptTreeNode *otn_idx, OptFpList *fp_list)
{
   return 1;
}


void CreateDefaultRules()
{
   CreateRuleType("activation", RULE_ACTIVATE, 1, &Activation);
   CreateRuleType("dynamic", RULE_DYNAMIC, 1, &Dynamic);
   CreateRuleType("alert", RULE_ALERT, 1, &Alert);
   CreateRuleType("pass", RULE_PASS, 0, &Pass);
   CreateRuleType("log", RULE_LOG, 1, &Log);
}

void printRuleOrder()
{
   LogMessage("Rule application order: ");
   printRuleListOrder(RuleLists);
}

/****************************************************************************
 *
 * Function: CreateRuleType
 *
 * Purpose: Creates a new type of rule and adds it to the end of the rule list
 *
 * Arguments: name = name of this rule type
 *                  mode = the mode for this rule type
 *               rval = return value for this rule type (for detect events)
 *                  head = list head to use (or NULL to create a new one)
 *
 * Returns: the ListHead for the rule type
 *
 ***************************************************************************/
ListHead *CreateRuleType(char *name, int mode, int rval, ListHead *head)
{
   RuleListNode *node;
   int evalIndex = 0;

   /* Using calloc() instead of malloc() because code isn't initializing
    * all of the structure fields before returning.  This is a non-
    * time-critical function, and is only called a half dozen times
    * on startup.
    */

   /*
    * if this is the first rule list node, then we need to create a new
    * list. we do not allow multiple rules with the same name.
    */
   if(!RuleLists)
   {
   RuleLists = (RuleListNode *)calloc(1, sizeof(RuleListNode));
   node = RuleLists;
   }
   else
   {
   node = RuleLists;

   while(1)
   {
      evalIndex++;
      if(!strcmp(node->name, name))
         return NULL;
      if(!node->next)
         break;
      node = node->next;
   }

   node->next = (RuleListNode *) calloc(1, sizeof(RuleListNode));
   node = node->next;
   }

   if(!head)
   {
   node->RuleList = (ListHead *)calloc(1, sizeof(ListHead));
   node->RuleList->IpList = NULL;
   node->RuleList->TcpList = NULL;
   node->RuleList->UdpList = NULL;
   node->RuleList->IcmpList = NULL;
   node->RuleList->LogList = NULL;
   node->RuleList->AlertList = NULL;
   }
   else
   {
   node->RuleList = head;
   }

   node->RuleList->ruleListNode = node;
   node->mode = mode;
   node->rval = rval;
   node->name = strdup(name);
   node->evalIndex = evalIndex;
   node->next = NULL;
   
   pv.num_rule_types++;
   
   return node->RuleList;
}



/****************************************************************************
 *
 * Function: OrderRuleLists
 *
 * Purpose: Orders the rule lists into the specefied order.
 *
 * Returns: void function
 *
 ***************************************************************************/
void
OrderRuleLists(char *order) {
   int i;
   int evalIndex = 0;
   RuleListNode *ordered_list = NULL;
   RuleListNode *prev;
   RuleListNode *node;
   static int called = 0;
   char **toks;
   int num_toks;

   if( called > 0 )
   LogMessage("Warning: multiple rule order directives.\n");

   toks = mSplit(order, " ", 10, &num_toks, 0);

   for( i = 0; i < num_toks; i++ ) {
   prev = NULL;
   node = RuleLists;

   while( 1 ) {
      if (node == NULL) {
         ArgusLog(LOG_ERR, "ruletype %s does not exist or has already been ordered.\n", toks[i]);
         break;
      }
      if (!strcmp(toks[i], node->name)) {
         if( prev == NULL )
            RuleLists = node->next;
         else
            prev->next = node->next;
         /* Add node to ordered list */
         ordered_list = addNodeToOrderedList(ordered_list, node, 
               evalIndex++);
         break;
      }
      else
      {
         prev = node;
         node = node->next;
      }
   }
   }
   mSplitFree(&toks, num_toks);

   /* anything left in the rule lists needs to be moved to the ordered lists */
   while( RuleLists != NULL ) {
   node = RuleLists;
   RuleLists = node->next;
   /* Add node to ordered list */
   ordered_list = addNodeToOrderedList(ordered_list, node, evalIndex++);
   }

   /* set the rulelists to the ordered list */
   RuleLists = ordered_list;
   called = 1;
}

static RuleListNode *
addNodeToOrderedList(RuleListNode *ordered_list, RuleListNode *node, int evalIndex)
{
   RuleListNode *prev;

   prev = ordered_list;
   
   /* set the eval order for this rule set */
   node->evalIndex = evalIndex;
   
   if(!prev)
   {
   ordered_list = node;
   }
   else
   {
   while(prev->next)
      prev = prev->next;
   prev->next = node;
   }

   node->next = NULL;

   return ordered_list;
}


void printRuleListOrder(RuleListNode * node)
{
   while( node != NULL )
   {
   LogMessage("->%s", node->name);
   node = node->next;
   }

   LogMessage("\n");
}

/* Rule Match Action Functions */
int PassAction()
{
   pc.pass_pkts++;

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"   => Pass rule, returning...\n"););
   return 1;
}



int ActivateAction(struct ArgusRecord *argus, OptTreeNode * otn, Event *event)
{
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,
         "      <!!> Activating and generating alert! \"%s\"\n",
         otn->sigInfo.message););
/*
   CallAlertFuncs(argus, otn->sigInfo.message, otn->rtn->listhead, event);

   if (otn->OTN_activation_ptr == NULL) {
      LogMessage("WARNING: an activation rule with no dynamic rules matched!\n");
      return 0;
   }

   otn->OTN_activation_ptr->active_flag = 1;
   otn->OTN_activation_ptr->countdown = 
   otn->OTN_activation_ptr->activation_counter;

   otn->RTN_activation_ptr->active_flag = 1;
   otn->RTN_activation_ptr->countdown += 
   otn->OTN_activation_ptr->activation_counter;

   active_dynamic_nodes++;
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"   => Finishing activation packet!\n"););
   
   CallLogFuncs(argus, otn->sigInfo.message, otn->rtn->listhead, event);
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, 
         "   => Activation packet finished, returning!\n"););
*/

   return 1;
}




int
AlertAction(struct ArgusRecord *argus, OptTreeNode * otn, Event *event) {
   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,
         "      <!!> Generating alert! \"%s\"\n", otn->sigInfo.message););

   /* Call OptTreeNode specific output functions */
   if(otn->outputFuncs)
   CallSigOutputFuncs(argus, otn, event);
   
   CallAlertFuncs(argus, otn->sigInfo.message, otn->rtn->listhead, event);

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "   => Finishing alert packet!\n"););

/*
   if(p->ssnptr != NULL) {
      if(AlertFlushStream(argus) == 0) {
         CallLogFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);
      }
   } else {
      CallLogFuncs(p, otn->sigInfo.message, otn->rtn->listhead, event);
   }
*/

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"   => Alert packet finished, returning!\n"););

   return 1;
}

int
DynamicAction(struct ArgusRecord *argus, OptTreeNode * otn, Event *event) {
   RuleTreeNode *rtn = otn->rtn;

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "   => Logging packet data and"
         " adjusting dynamic counts (%d/%d)...\n",
         rtn->countdown, otn->countdown););

   CallLogFuncs(argus, otn->sigInfo.message, otn->rtn->listhead, event);

   otn->countdown--;

   if( otn->countdown <= 0 ) {
      otn->active_flag = 0;
      active_dynamic_nodes--;
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "   <!!> Shutting down dynamic OTN node\n"););
   }
   
   rtn->countdown--;

   if( rtn->countdown <= 0 ) {
      rtn->active_flag = 0;
      DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "   <!!> Shutting down dynamic RTN node\n"););
   }

   return 1;
}

int LogAction(struct ArgusRecord *argus, OptTreeNode * otn, Event *event)
{

   DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,"   => Logging packet data and returning...\n"););

   CallLogFuncs(argus, otn->sigInfo.message, otn->rtn->listhead, event);

#ifdef BENCHMARK
   printf("      <!!> Check count = %d\n", check_count);
   check_count = 0;
   printf(" **** cmpcount: %d **** \n", cmpcount);
#endif

   return 1;
}

void
ObfuscatePacket(Packet *p) {
   /* only obfuscate once */
   if(p->packet_flags & PKT_OBFUSCATED)
   return;
   
   /* we only obfuscate IP packets */
   if(!p->iph)
   return;
   
   if(pv.obfuscation_net == 0) {
   p->iph->ip_src.s_addr = 0x00000000;
   p->iph->ip_dst.s_addr = 0x00000000;
   } else {
   if(pv.homenet != 0) {
      if((p->iph->ip_src.s_addr & pv.netmask) == pv.homenet) {
         p->iph->ip_src.s_addr = pv.obfuscation_net |
            (p->iph->ip_src.s_addr & pv.obfuscation_mask);
      }
      if((p->iph->ip_dst.s_addr & pv.netmask) == pv.homenet) {
         p->iph->ip_dst.s_addr = pv.obfuscation_net |
            (p->iph->ip_dst.s_addr & pv.obfuscation_mask);
      }

   } else {
      p->iph->ip_src.s_addr = pv.obfuscation_net |
         (p->iph->ip_src.s_addr & pv.obfuscation_mask);
      p->iph->ip_dst.s_addr = pv.obfuscation_net |
         (p->iph->ip_dst.s_addr & pv.obfuscation_mask);
   }
   }
   p->packet_flags |= PKT_OBFUSCATED;
}

/* end of rule action functions */
     

/*
   sfthreshold.c

   This file contains functions that glue the generic thresholding2 code to 
   snort.

   dependent files:  sfthd sfxghash sfghash sflsq 
                  util mstring

   Copyright (C) 2003 Sourcefire,Inc.
   Marc Norton

   2003-05-29:
     cmg: Added s_checked variable  --
    when this is 1, the sfthreshold_test will always return the same 
    answer until
    sfthreshold_reset is called

   2003-11-3:
     man: cleaned up and added more startup printout.
*/

static int          s_memcap  = 1024 * 1024;
static THD_STRUCT * s_thd     = 0;
static int          s_enabled = 1;
static int          s_checked = 0; /**< have we evaluated this yet? */
static int          s_answer  = 0; /**< what was the last return value? */


/*
*   Fatal Integer Parser
*   Ascii to Integer conversion with fatal error support
*/
static unsigned
xatou( char * s , char * etext) {
    unsigned val;
  
    while( *s == ' ' ) s++;

    if( *s == '-' ) 
    ArgusLog(LOG_ERR,"*** %s\n*** Invalid unsigned integer - negative sign found, input: %s\n",etext ,s );
    
    /*
    *  strtoul - errors on win32 : ERANGE (VS 6.0)
    *            errors on linux : ERANGE, EINVAL
    */ 
    val =(unsigned)strtoul(s,0,10);
    
    if( errno == ERANGE || errno == EINVAL )
    ArgusLog(LOG_ERR, "*** %s\n*** Invalid integer input: %s\n",etext,s );

    return val;      
}

/*

     Parse Threshold Rule option parameters for each RULE

     'threshold: type limit|threshold|both, track by_src|by_dst, count #, seconds #;'

*/
void
ParseThreshold2( THDX_STRUCT * thdx, char * s ) {
   int    i = 0;
   char * argv[100], * t;
   int    argc;
   int    count_flag=0;
   int    seconds_flag=0;
   int    type_flag=0;
   int    tracking_flag=0;
   
   if( !s_enabled )
       return ;

   memset( thdx, 0, sizeof(THDX_STRUCT) );

   thdx->priority = -1; /* Make this lower than standalone threshold command defaults ??? */
   
   /* Parse all of the args - they come in pairs */      
   for( argc=0, t = strtok(s," ,\n");  argc < 100 &&  t != 0 ;  argc++, t = strtok(0," ,\n") )
   {
       argv[ argc ] = t;           
   }

   /* Parameter Check - enough args ?*/
   if( argc != 8 )
   {
       /* Fatal incorrect argument count */ 
       ArgusLog(LOG_ERR,"Threshold-RuleOptionParse: incorrect argument count, should be 4 pairs\n");
   }

   for(i=0;i<argc;i++) {
     if( strcmp(argv[i],"count") == 0  ) {
         i++;
         thdx->count = xatou(argv[i],"threshold: count");
         count_flag++;
      } else if( strcmp(argv[i],"seconds") == 0  ) {
         i++;
         thdx->seconds = xatou(argv[i],"threshold: seconds");
         seconds_flag++;
      } else if( strcmp(argv[i],"type") == 0  ) {
         i++;
         if( strcmp(argv[i],"limit") == 0 ) {
            thdx->type = THD_TYPE_LIMIT;
         } else if( strcmp(argv[i],"threshold") == 0 ) {
            thdx->type = THD_TYPE_THRESHOLD;
         } else if( strcmp(argv[i],"both") == 0 ) {
            thdx->type = THD_TYPE_BOTH;
         } else {
             /* Fatal incorrect threshold type */
              ArgusLog(LOG_ERR,"Threshold-RuleOptionParse: incorrect 'type' argument \n");
         }
         type_flag++;
      } else if( strcmp(argv[i],"track") == 0  ) {
         i++;
         if( strcmp(argv[i],"by_src") == 0 ) {
             thdx->tracking = THD_TRK_SRC;
         } else if( strcmp(argv[i],"by_dst") == 0 ) {
             thdx->tracking = THD_TRK_DST;
         } else {
             /* Fatal incorrect threshold type */
              ArgusLog(LOG_ERR,"Threshold-RuleOptionParse: incorrect tracking type\n");
         }
         tracking_flag++;
      } else {
         /* Fatal Out Here - Unknow Option */
         ArgusLog(LOG_ERR,"Threshold-RuleOptionParse: unknown argument \n");
      }
     }

     if( (count_flag + tracking_flag + type_flag + seconds_flag ) != 4 ) {
      /* Fatal - incorrect argument count */
      ArgusLog(LOG_ERR,"Threshold-RuleOptionParse: incorrect argument count\n");
     }
}

/*

   Process the 'config threshold: memcap #bytes, option2-name option2-value, ...'

   config threshold: memcap #bytes
*/
void ProcessThresholdOptions(char *options)
{
   int     i = 0;
   char ** args;
   int     nargs;
   char ** oargs;
   int     noargs;
   
   if( !s_enabled )
       return ;

   args = mSplit(options,",",10,&nargs,0);  /* get rule option pairs */

   for(i=0;i<nargs;i++)
   {
       oargs = mSplit(options," ",2,&noargs,0);  /* get rule option pairs */

       if( strcmp(oargs[0],"memcap") == 0  )
       {
          s_memcap = xatou(oargs[1],"config threshold: memcap");
       }
       else
       {
          ArgusLog(LOG_ERR,"Threshold-RuleOptionParse: unknown argument\n");
       }
     }
     mSplitFree(&args, nargs);
     mSplitFree(&oargs, noargs);
}

/*
   threshold gen_id #, sig_id #, type limit|threshold|both, track by_src|by_dst,  count #, seconds #

   8/25/03 - added support for a global threshold, uses sid = 0, and is applied after all other thresholding so 
   a sid specific threshold or suppress command has precedence...
*/

void
ParseSFThreshold( FILE * fp, char * rule ) {
     char        **args, **oargs;
     int         nargs, noargs;
     THDX_STRUCT thdx;
     int         count_flag=0;
     int         seconds_flag=0;
     int         type_flag=0;
     int         tracking_flag=0;
/*     
     int         priority_flag=0;
*/
     int         genid_flag=0;
     int         sigid_flag=0;
     int         i;

     memset( &thdx, 0, sizeof(THDX_STRUCT) );

     while( (*rule <= ' ') && (*rule > 0) ) rule++; /* skip whitespace */
     while( (*rule  > ' ') ) rule++;  /* skip 'threshold' */

     args = mSplit(rule,",",15,&nargs,0);  /* get rule option pairs */

     for(i = 0; i < nargs; i++ ) {
      oargs = mSplit(args[i]," ",2,&noargs,0);  /* get rule option pairs */
    if( noargs != 2 ) {
          ArgusLog(LOG_ERR,"Threshold Parse: argument pairing error\n");
      }

      if( strcmp(oargs[0],"type")==0 ) {
         if( strcmp(oargs[1],"limit") == 0 ) {
            thdx.type = THD_TYPE_LIMIT;
         } else if( strcmp(oargs[1],"threshold") == 0 ) {
            thdx.type = THD_TYPE_THRESHOLD;
         } else if( strcmp(oargs[1],"both") == 0 ) {
            thdx.type = THD_TYPE_BOTH;
         } else {
             /* Fatal incorrect threshold type */
              ArgusLog(LOG_ERR,"Threshold-Parse: incorrect 'type' argument \n");
         }
         type_flag++;
      } else if( strcmp(oargs[0],"track")==0 ) {
         if( strcmp(oargs[1],"by_src") == 0 ) {
             thdx.tracking = THD_TRK_SRC;
         } else if( strcmp(oargs[1],"by_dst") == 0 ) {
             thdx.tracking = THD_TRK_DST;
         } else {
             /* Fatal incorrect threshold type */
              ArgusLog(LOG_ERR,"Threshold-Parse: incorrect tracking type\n");
         }
         tracking_flag++;
      } else if( strcmp(oargs[0],"count")==0 ) {
         thdx.count = xatou(oargs[1],"threshold: count");
         count_flag++;
      } else if( strcmp(oargs[0],"seconds")==0 ) {
         thdx.seconds = xatou(oargs[1],"threshold: seconds");
         seconds_flag++;
      } else if( strcmp(oargs[0],"gen_id")==0 ) {
         thdx.gen_id =  xatou(oargs[1],"threshold: gen_id");
         genid_flag++;

    if( oargs[1][0]== '-' ) 
             ArgusLog(LOG_ERR,"Threshold-Parse: gen_id < 0 not supported  '%s %s'\n",oargs[0],oargs[1]);
      } else if( strcmp(oargs[0],"sig_id")==0 ) {
         thdx.sig_id = xatou(oargs[1],"threshold: sig_id");
         sigid_flag++;
    if( oargs[1][0]== '-' ) 
             ArgusLog(LOG_ERR,"Threshold-Parse: sig_id < 0 not supported  '%s %s'\n",oargs[0],oargs[1]);
      } else {
          /* Fatal incorrect threshold type */
          ArgusLog(LOG_ERR,"Threshold-Parse: unsupported option : %s %s\n",oargs[0],oargs[1]);
      }
     }

     if( (count_flag + tracking_flag + type_flag + seconds_flag + genid_flag + sigid_flag) != 6 ) {
   /* Fatal - incorrect argument count */
   ArgusLog(LOG_ERR,"Threshold-Parse: incorrect argument count\n");
     }

     if( sfthreshold_create( &thdx  ) ) {
   if( thdx.sig_id == 0 ) {
   ArgusLog(LOG_ERR,"Global Threshold-Parse: could not create a threshold object -- only one per gen_id=%u!\n",thdx.gen_id);
   } else {
   if( thdx.gen_id ==  0 ) {
      ArgusLog(LOG_ERR,"Global Threshold-Parse: could not create a threshold object -- a gen_id < 0 requires a sig_id < 0, sig_id=%u !\n",thdx.sig_id);
   } else {
      ArgusLog(LOG_ERR,"Threshold-Parse: could not create a threshold object -- only one per sig_id=%u!\n",thdx.sig_id);
   }
   }
     }

     mSplitFree(&args, nargs);
     mSplitFree(&oargs, noargs);
}

/*

    Parse basic CIDR block  - [!]a.b.c.d/bits

*/
static void parseCIDR( THDX_STRUCT * thdx, char * s )
{
   char        **args;
   int          nargs;

   if (*s == '!')
   {
    thdx->not_flag = 1;
    s++;
    while( (*s <= ' ') && (*s > 0) ) s++; /* skip whitespace */
   }

   args = mSplit( s , "/", 2, &nargs, 0 );  /* get rule option pairs */

   if( !nargs || nargs > 2  )
   {
    ArgusLog(LOG_ERR,"Suppress-Parse: argument pairing error\n");
   }

   /*
   *   Keep IP in network order
   */
   thdx->ip_address = inet_addr( args[0] );   

   if( nargs == 2 )
   {
    int      i;
    int      nbits;
    unsigned mask;

    nbits = xatou( args[1],"suppress: cidr mask bits" );
    mask  = 1 << 31;

    for( i=0; i<nbits; i++ )
    {
       thdx->ip_mask |= mask;
       mask >>= 1;
    }

    /* 
       Put mask in network order 
    */
    thdx->ip_mask = htonl(thdx->ip_mask);       
   }
   else
   {
    thdx->ip_mask = 0xffffffff; /* requires exact ip match */
   }

   /* just in case the network is not right */
   thdx->ip_address &= thdx->ip_mask;

   mSplitFree(&args, nargs);
}

/*

   suppress gen_id #, sig_id #, track by_src|by_dst, ip cidr'

*/
void
ParseSFSuppress( FILE * fp, char * rule )
{

     char        **args, **oargs;
     int         nargs, noargs;
     THDX_STRUCT thdx;
     int         genid_flag=0;
     int         sigid_flag=0;
     int         i;

     memset( &thdx, 0, sizeof(THDX_STRUCT) );

     while( (*rule <= ' ') && (*rule > 0) ) rule++; /* skip whitespace */
     while( (*rule  > ' ') ) rule++;  /* skip 'suppress' */

     args = mSplit(rule,",",15,&nargs,0);  /* get rule option pairs */

     thdx.type      =  THD_TYPE_SUPPRESS;
     thdx.priority  =  THD_PRIORITY_SUPPRESS;
     thdx.ip_address=  0;  //default is all ip's- ignore this event altogether
     thdx.ip_mask   =  0;
     thdx.tracking  =  THD_TRK_DST;

     for(i = 0; i < nargs; i++) {
      oargs = mSplit(args[i]," ",2,&noargs,0);  /* get rule option pairs */
      if( noargs != 2 )
          ArgusLog(LOG_ERR,"Suppress-Parse: argument pairing error\n");

      if( strcmp(oargs[0],"track")==0 ) {
         if( strcmp(oargs[1],"by_src") == 0 ) {
             thdx.tracking = THD_TRK_SRC;
         } else
            if( strcmp(oargs[1],"by_dst") == 0 ) {
               thdx.tracking = THD_TRK_DST;
            } else {
             /* Fatal incorrect threshold type */
                ArgusLog(LOG_ERR,"Suppress-Parse: incorrect tracking type\n");
            }
      } else
       if( strcmp(oargs[0],"gen_id")==0 ) {
    char * endptr;
         thdx.gen_id = strtoul(oargs[1],&endptr,10);
         genid_flag++;
    if( oargs[1][0]=='-' )
             ArgusLog(LOG_ERR,"Suppress-Parse: gen_id < 0 is not supported, '%s %s' \n",oargs[0],oargs[1]);
      } else
       if( strcmp(oargs[0],"sig_id")==0 ) {
    char * endptr;
         thdx.sig_id = strtoul(oargs[1],&endptr,10);
         sigid_flag++;
    if( oargs[1][0]=='-' )
             ArgusLog(LOG_ERR,"Suppress-Parse: sig_id < 0 is not supported, '%s %s' \n",oargs[0],oargs[1]);
      } else
       if( strcmp(oargs[0],"ip")==0 ) {
         parseCIDR( &thdx, oargs[1] );
      }
     }

     if( ( genid_flag + sigid_flag) != 2 )
      /* Fatal - incorrect argument count */
      ArgusLog(LOG_ERR,"Suppress-Parse: incorrect argument count\n");

     if( sfthreshold_create( &thdx  ) )
      ArgusLog(LOG_ERR,"Suppress-Parse: could not create a threshold object\n");

     mSplitFree(&args, nargs);
     mSplitFree(&oargs, noargs);
}

/*

    Init Thresholding - call when starting to parsing rules - so we can add them 

    if the init function is not called, than all thresholding is turned off because
    the thd_struct pointer is null.

*/
int
sfthreshold_init() {
   if (!s_enabled)
    return 0;

   /* Check if already init'd */
   if (s_thd)
    return 0;

   s_thd = sfthd_new(s_memcap);

   if (!(s_thd))
      return -1;
   else
      return 0;
}

/*
*  DEBUGGING ONLY
*/
void
print_netip(unsigned long ip) {
    struct in_addr addr;
    char *str;

    addr.s_addr= ip;
    str = inet_ntoa(addr);

    if(str)
     printf("%s", str);

    return;
}

/*
*  DEBUGGING ONLY
*/
void print_thdx( THDX_STRUCT * thdx )
{
    if( thdx->type != THD_TYPE_SUPPRESS )
    {
    printf("THRESHOLD: gen_id=%u, sig_id=%u, type=%d, tracking=%d, count=%d, seconds=%d \n",
                    thdx->gen_id,
                    thdx->sig_id,
                    thdx->type,
                    thdx->tracking,
                    thdx->count,
                    thdx->seconds );
    }
    else
    {
    printf("SUPPRESS: gen_id=%u, sig_id=%u, tracking=%d, not_flag=%d ",
                    thdx->gen_id,
                    thdx->sig_id,
                    thdx->tracking,
                    thdx->not_flag);

    printf(" ip=");
    print_netip(thdx->ip_address); 
    printf(", mask=" );
    print_netip(thdx->ip_mask); 
    printf("\n");
    }
}

static 
void ntoa( char * buff, int blen, unsigned ip )
{
   snprintf(buff,blen,"%d.%d.%d.%d", ip&0xff,(ip>>8)&0xff,(ip>>16)&0xff,(ip>>24)&0xff );
}

#define PRINT_GLOBAL   0
#define PRINT_LOCAL    1
#define PRINT_SUPPRESS 2
/*
 *   type = 0 : global
 *          1 : local
 *          2 : suppres      
 */
void print_thd_node( THD_NODE *p , int type )
{
    char buffer[80];
    switch( type )
    {
       case 0: /* global */
       if(p->type == THD_TYPE_SUPPRESS ) return;
       if(p->sig_id != 0 ) return;
            break;
       
       case 1: /* local */
       if(p->type == THD_TYPE_SUPPRESS ) return;
       if(p->sig_id == 0 || p->gen_id == 0 ) return;
       break;
       
       case 2: /*suppress  */
       if(p->type != THD_TYPE_SUPPRESS ) return;
       break;
    }

/*     LogMessage ("| thd-id=%d",p->thd_id ); */

    if( p->gen_id == 0 )
    {
    LogMessage ("| gen-id=global",p->gen_id );
    }
    else
    {
    LogMessage ("| gen-id=%-6d",p->gen_id );
    }
    if( p->sig_id == 0 )
    {
       LogMessage (" sig-id=global" );
    }
    else
    {
       LogMessage (" sig-id=%-10d",p->sig_id );
    }

/*               
    if( p->type == THD_TYPE_SUPPRESS )
    LogMessage(" type=Suppress ");
*/      
    if( p->type != THD_TYPE_SUPPRESS )
    {
    if( p->type == THD_TYPE_LIMIT )
    LogMessage(" type=Limit    ");
    
    if( p->type == THD_TYPE_THRESHOLD )
    LogMessage(" type=Threshold");
    
    if( p->type == THD_TYPE_BOTH )
    LogMessage("type=Both      ");
    }
    
    LogMessage(" tracking=%s",(!p->tracking) ? "src" : "dst" );
     
    if( p->type == THD_TYPE_SUPPRESS )
    {
    ntoa(buffer,80,p->ip_address);
    if (p->not_flag)
        LogMessage("ip=!%-16s", buffer);
    else
        LogMessage("ip=%-17s", buffer);
    ntoa(buffer,80,p->ip_mask);
    LogMessage(" mask=%-15s", buffer );
    }
    else
    {
    LogMessage(" count=%-3d",p->count);
    LogMessage(" seconds=%-3d",p->seconds);
    }

    LogMessage("\n");
}
/*
 * 
 */


NODE_DATA
sflist_first(SF_LIST *s) {
   NODE_DATA retn = NULL;
   return (retn);
} 

NODE_DATA
sflist_next(SF_LIST *s) {
   NODE_DATA retn = NULL;
   return (retn);
} 

SFGHASH_NODE *
sfghash_findfirst(SFGHASH * t) {
   SFGHASH_NODE *retn = NULL;
   return (retn);
}

SFGHASH_NODE *
sfghash_findnext(SFGHASH * t) {
   SFGHASH_NODE *retn = NULL;
   return (retn);
}


int
print_thd_local(THD_STRUCT * thd, int type) {
   SFGHASH_NODE *item_hash_node;
   SFGHASH      *sfthd_hash; 
   THD_ITEM     *sfthd_item;
   THD_NODE     *sfthd_node;

   int gen_id;
   int lcnt = 0;

   for (gen_id = 0; gen_id < THD_MAX_GENID; gen_id++) {
      sfthd_hash = thd->sfthd_array [ gen_id ];
      if( !sfthd_hash ) {
         continue;
      }

      for (item_hash_node = sfghash_findfirst( sfthd_hash ); item_hash_node != 0; item_hash_node = sfghash_findnext(sfthd_hash)) {
         /* Check for any Permanent sig_id objects for this gen_id */
         sfthd_item = (THD_ITEM*)item_hash_node->data;

         /* For each permanent thresholding object, test/add/update the thd object */
         /* We maintain a list of thd objects for each gen_id+sig_id */
         /* each object has it's own unique thd_id */

         for( sfthd_node  = (THD_NODE*)sflist_first(sfthd_item->sfthd_node_list);
              sfthd_node != 0;
              sfthd_node = (THD_NODE*)sflist_next(sfthd_item->sfthd_node_list) ) {
            print_thd_node( sfthd_node,type);
            lcnt++;
         }
       }
    }

    if (!lcnt) LogMessage("| none\n");
    return 0;
}


/*
 *  Startup Display Of Thresholding
 */
void print_thresholding()
{
   int i, gcnt=0;
     THD_NODE * thd;
       
   LogMessage("\n");
   LogMessage("+-----------------------[thresholding-config]----------------------------------\n");
   LogMessage("| memory-cap : %d bytes\n",s_memcap);

   
   LogMessage("+-----------------------[thresholding-global]----------------------------------\n");
   if( !s_thd ) 
   {
     LogMessage("| none\n");
   }
   else
   {
    for(i=0;i<THD_MAX_GENID;i++)
     {
   thd = s_thd->sfthd_garray[i];
   if( !thd ) continue;
          gcnt++;
     }
     
     if( !gcnt ) 
     LogMessage("| none\n");
     
     /* display gen_id=global  and sig_id=global rules */
     if( gcnt )
    for(i=0;i<THD_MAX_GENID;i++)
     {
   thd = s_thd->sfthd_garray[i];
   if( !thd ) continue;
   
   if( thd->gen_id == 0 && thd->sig_id == 0 )
   {
                   print_thd_node( thd, PRINT_GLOBAL );
         break;
   }
     }

     /* display gen_id!=global and sig_id=global rules */
     if( gcnt )
    for(i=0;i<THD_MAX_GENID;i++)
     {
   thd = s_thd->sfthd_garray[i];
   if( !thd ) continue;
   
   if( thd->gen_id !=0 ||  thd->sig_id != 0 )
   {
               print_thd_node( thd, PRINT_GLOBAL );
   }
     }
   }

   LogMessage("+-----------------------[thresholding-local]-----------------------------------\n");
   if( !s_thd )
   {
     LogMessage("| none\n");
   }
   else
   {
       print_thd_local(s_thd, PRINT_LOCAL );
   }
   
   LogMessage("+-----------------------[suppression]------------------------------------------\n");
     if( !s_thd )
   {
   LogMessage("| none\n");
   }
   else
   {
   print_thd_local(s_thd, PRINT_SUPPRESS );
   }
   
   LogMessage("-------------------------------------------------------------------------------\n");
   
}

/*
    Create and Add a Thresholding Event Object
*/


int
sfthd_create_threshold (THD_STRUCT * thd, unsigned gen_id, unsigned sig_id, int tracking,
                          int type, int priority, int count, int seconds, unsigned ip_address,
                          unsigned ip_mask,  unsigned not_flag ) {
   return (0);
}
 
int
sfthd_test_threshold (THD_STRUCT * thd, unsigned gen_id, unsigned sig_id, unsigned sip, unsigned dip, long curtime) {
   return (0);
}

int
sfthreshold_create (THDX_STRUCT * thdx) {
   if( !s_enabled )
      return 0;

   if( !s_thd ) {
      /* Auto init - memcap must be set 1st, which is not really a problem */
      sfthreshold_init();
      if( !s_thd )
         return -1;
   }

   /* print_thdx( thdx ); */
   /* Add the object to the table - */
   return sfthd_create_threshold( s_thd,
                    thdx->gen_id,
                    thdx->sig_id,
                    thdx->tracking,
                    thdx->type,
                    thdx->priority,
                    thdx->count,
                    thdx->seconds,
                    thdx->ip_address, 
                    thdx->ip_mask,
                    thdx->not_flag ); 
}

/*

    Test an event against the threshold object table
    to determine if it should be logged.

    It will always return the same answer until sfthreshold_reset is
    called

   gen_id:
   sig_id: 
   sip:    host ordered sip
   dip:   host ordered dip
   curtime: 

    2003-05-29 cmg:

     This code is in use in fpLogEvent, CallAlertFuncs, CallLogFuncs
     and the reset function is called in Processstruct ArgusRecord


    returns 1 - log
         0 - don't log

    
*/
int
sfthreshold_test( unsigned gen_id, unsigned  sig_id, unsigned sip, unsigned dip, long curtime ) {
   if( !s_enabled )
      return 1;
  
   if( !s_thd ) {
      /* this should not happen, see the create fcn */
    return 1;
   }

   if( !s_checked ) {
      s_checked = 1;
      s_answer  = !sfthd_test_threshold( s_thd, gen_id, sig_id, sip, dip, curtime );
   }
    
   return s_answer;
}

/** 
 * Reset the thresholding system so that subsequent calls to
 * sfthreshold_test will indeed try to alter the thresholding system
 *
 */
void
sfthreshold_reset(void) {
    s_checked = 0;
}



void
ParseConfig(char *rule)
{
    char ** toks;
    char **rule_toks = NULL;
    char **config_decl = NULL;
    char *args = NULL;
    char *config;
    int num_rule_toks = 0, num_config_decl_toks = 0, num_toks=0;

    rule_toks = mSplit(rule, ":", 2, &num_rule_toks, 0);
    if(num_rule_toks > 1) {
        args = rule_toks[1];
    }

    config_decl = mSplit(rule_toks[0], " ", 2, &num_config_decl_toks, '\\');

    if(num_config_decl_toks != 2) {
        ArgusLog(LOG_ERR,"unable to parse config: %s\n", rule);
    }

    config = config_decl[1];

    DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Config: %s\n", config););
    DEBUG_WRAP(ArgusDebug(DEBUG_CONFIGRULES,"Args: %s\n", args););

    if(!strcasecmp(config, "order")) {
        if(!pv.rules_order_flag)
            OrderRuleLists(args);
        else
   LogMessage("Commandline option overiding rule file config\n");
    
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
   
        return;
    } else if(!strcasecmp(config, "alertfile")) {
        toks = mSplit(args, " ", 1, &num_toks, 0);

        ProcessAlertFileOption(toks[0]);
   
        mSplitFree( &toks, num_toks );
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "classification")) {
        ParseClassificationConfig(args);
   
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "detection")) {
        toks = mSplit(args, ", ",20, &num_toks, 0);
        ProcessDetectionOptions(toks,num_toks);
        mSplitFree( &toks, num_toks );
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "flowbits_size")) {
        toks = mSplit(args, ", ",20, &num_toks, 0);
        ProcessFlowbitsSize(toks, num_toks);
        mSplitFree( &toks, num_toks );
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "dump_chars_only")) {
        /* dump the application layer as text only */
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "Character payload dump set\n"););
        pv.char_data_flag = 1;
   
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "dump_payload")) {
        /* dump the application layer */
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "Payload dump set\n"););
        pv.data_flag = 1;
   
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "disable_decode_alerts")) {
        /* dump the application layer */
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "disabling the decoder alerts\n"););
        pv.decoder_flags.decode_alerts = 0;
   
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "disable_tcpopt_experimental_alerts")) {
        /* dump the application layer */
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "disabling the tcpopt experimental alerts\n"););
        pv.decoder_flags.tcpopt_experiment = 0;
   
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "disable_tcpopt_obsolete_alerts")) {
        /* dump the application layer */
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "disabling the tcpopt obsolete alerts\n"););
        pv.decoder_flags.tcpopt_obsolete = 0;
   
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "disable_ttcp_alerts") ||
            !strcasecmp(config, "disable_tcpopt_ttcp_alerts")) {
        /* dump the application layer */
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "disabling the ttcp alerts\n"););
        pv.decoder_flags.tcpopt_ttcp = 0;
   
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "disable_tcpopt_alerts")) {
        /* dump the application layer */
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "disabling the all the other tcpopt alerts\n"););
        pv.decoder_flags.tcpopt_decode = 0;
   
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "disable_ipopt_alerts")) {
        /* dump the application layer */
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "disabling the all the ipopt alerts\n"););
        pv.decoder_flags.ipopt_decode = 0;
   
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "decode_data_link")) {
        /* dump the data link layer as text only */
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "Decode DLL set\n"););
        pv.show2hdr_flag = 1;
   
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "bpf_file")) {
        /* Read BPF filters from a file */
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "BPF file set\n"););
        /* suck 'em in */
        pv.pcap_cmd = read_infile(args);
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "set_gid")) {
#ifdef WIN32
        ArgusLog(LOG_ERR," Setting the group id is not supported in the WIN32 port of snort!\n");
#else
        if((groupname = calloc(strlen(args) + 1, 1)) == NULL)
            ArgusLog(LOG_ERR,"calloc");

        bcopy(args, groupname, strlen(args));

        if((groupid = atoi(groupname)) == 0) {
            gr = getgrnam(groupname);

            if(gr == NULL) 
                ArgusLog(LOG_ALERT,"%s(%d) => Group \"%s\" unknown\n", file_name, file_line, groupname);

            groupid = gr->gr_gid;
        }
#endif
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);

        return;
    } else if(!strcasecmp(config, "daemon")) {
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "Daemon mode flag set\n"););
        pv.daemon_flag = 1;
        pv.quiet_flag = 1;
   
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;

    } else if(!strcasecmp(config, "reference_net")) {
        GenHomenet(args);
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "threshold")) {
        ProcessThresholdOptions(args);
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "interface")) {
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "alert_with_interface_name")) {
        pv.alert_interface_flag = 1;
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "logdir")) {
        LogMessage("Found logdir config directive (%s)\n", args);
        if(!(pv.log_dir = strdup(args)))
            ArgusLog(LOG_ERR,"Out of memory setting log dir from config file\n");
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "Log directory = %s\n", 
                    pv.log_dir););
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "chroot")) {
        LogMessage("Found chroot config directive (%s)\n", args);
        if(!(pv.chroot_dir = strdup(args)))
            ArgusLog(LOG_ERR,"Out of memory setting chroot dir from config file\n");
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "Chroot directory = %s\n",
                    pv.chroot_dir););
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "umask")) {
        char *p;
        long val = 0;
        int umaskchange = 1;
        int defumask = 0;

        umaskchange = 0;

        val = strtol(args, &p, 8);
        if (*p != '\0' || val < 0 || (val & ~FILEACCESSBITS)) {
            ArgusLog(LOG_ERR,"bad umask %s\n", args);
        } else {
            defumask = val;
        }

        /* if the umask arg happened, set umask */
        if (umaskchange) {
            umask(077);           /* set default to be sane */
        } else {
            umask(defumask);
        }
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "pkt_count")) {
        pv.pkt_cnt = atoi(args);
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "Exiting after %d packets\n", pv.pkt_cnt););
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "nolog")) {
        pv.log_mode = LOG_NONE;
        pv.log_cmd_override = 1;    /* XXX this is a funky way to do things */
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "obfuscate")) {
        pv.obfuscation_flag = 1;
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "no_promisc")) {
        pv.promisc_flag = 0;
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "Promiscuous mode disabled!\n"););
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "snaplen")) {
        pv.pkt_snaplen = atoi(args);
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "Snaplength of struct ArgusRecords set to: %d\n", 
                    pv.pkt_snaplen););
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "quiet")) {
        pv.quiet_flag = 1;
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "read_bin_file")) {
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "checksum_mode")) {
        if(args == NULL || !strcasecmp(args, "all")) {
            pv.checksums_mode = DO_IP_CHECKSUMS | DO_TCP_CHECKSUMS |
                DO_UDP_CHECKSUMS | DO_ICMP_CHECKSUMS;
        } else if(!strcasecmp(args, "noip")) {
            pv.checksums_mode ^= DO_IP_CHECKSUMS;
        } else if(!strcasecmp(args, "notcp")) {
            pv.checksums_mode ^= DO_TCP_CHECKSUMS;
        } else if(!strcasecmp(args, "noudp")) {
            pv.checksums_mode ^= DO_UDP_CHECKSUMS;
        } else if(!strcasecmp(args, "noicmp")) {
            pv.checksums_mode ^= DO_ICMP_CHECKSUMS;
        } else if(!strcasecmp(args, "none")) {
            pv.checksums_mode = 0;
        }
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "set_uid")) {
#ifdef WIN32
        ArgusLog(LOG_ERR,"Setting the user id is not supported in the WIN32 port of snort!\n");
#else
        if((username = calloc(strlen(args) + 1, 1)) == NULL)
            ArgusLog(LOG_ERR,"malloc");

        bcopy(args, username, strlen(args));

        if((userid = atoi(username)) == 0) {
            pw = getpwnam(username);
            if(pw == NULL)
                ArgusLog(LOG_ERR,"User \"%s\" unknown\n", username);

            userid = pw->pw_uid;
        } else {
            pw = getpwuid(userid);
            if(pw == NULL)
                ArgusLog(LOG_ERR, "Can not obtain username for uid: %lu\n", (u_long) userid);
        }

        if(groupname == NULL) {
            char name[256];

            snprintf(name, 255, "%lu", (u_long) pw->pw_gid);

            if((groupname = calloc(strlen(name) + 1, 1)) == NULL) {
                ArgusLog(LOG_ERR, "malloc");
            }
            groupid = pw->pw_gid;
        }

        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "UserID: %lu GroupID: %lu\n",
                    (unsigned long) userid, (unsigned long) groupid););
#endif
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "utc")) {
        pv.use_utc = 1;
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "verbose")) {
        pv.verbose_flag = 1;
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "Verbose Flag active\n"););
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "dump_payload_verbose")) {
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, 
                    "Verbose packet bytecode dumps enabled\n"););

        pv.verbose_bytedump_flag = 1;
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "show_year")) {
        pv.include_year = 1;
        DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "Enabled year in timestamp\n"););
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "stateful")) /* this one's for Johnny! */ {
        pv.assurance_mode = ASSURE_EST;
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "min_ttl")) {
        if(args) {
            pv.min_ttl = atoi(args);
        } else {
            ArgusLog(LOG_ERR,"config min_ttl requires an argument\n");
        }
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    } else if(!strcasecmp(config, "reference")) {
        if(args) {
            ParseReferenceSystemConfig(args);
        } else {
            ArgusLog(LOG_ALERT,"%s(%d) => Reference config without "
                         "arguments\n", file_name, file_line);
        }
   mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }

    ArgusLog(LOG_ERR,"Unknown config directive: %s\n", rule);
    return;
}

/*
 * Function: GenHomenet(char *)
 *
 * Purpose: Translate the command line character string into its equivalent
 *          32-bit network byte ordered value (with netmask)
 *
 * Arguments: netdata => The address/CIDR block
 *
 * Returns: void function
 */
void GenHomenet(char *netdata)
{
    struct in_addr net;    /* place to stick the local network data */
    char **toks;           /* dbl ptr to store mSplit return data in */
    int num_toks;          /* number of tokens mSplit returns */
    int nmask;             /* temporary netmask storage */

    /* break out the CIDR notation from the IP address */
    toks = mSplit(netdata, "/", 2, &num_toks, 0);

    if(num_toks > 1) {
        /* convert the CIDR notation into a real live netmask */
        nmask = atoi(toks[1]);

        if((nmask > 0) && (nmask < 33)) {
            pv.netmask = netmasks[nmask];
        } else {
            ArgusLog(LOG_ERR,"Bad CIDR block [%s:%d], 1 to 32 please!\n",
                       toks[1], nmask);
        }
    } else {
        ArgusLog(LOG_ERR,"No netmask specified for home network!\n");
    }

    pv.netmask = htonl(pv.netmask);

    DEBUG_WRAP(ArgusDebug(DEBUG_INIT, "homenet netmask = %#8lX\n", pv.netmask););

    /* convert the IP addr into its 32-bit value */
    if((net.s_addr = inet_addr(toks[0])) == -1) {
        ArgusLog(LOG_ERR,"Homenet (%s) didn't translate\n",
                   toks[0]);
    } else {
#ifdef DEBUG
        struct in_addr sin;

        ArgusDebug(DEBUG_INIT, "Net = %s (%X)\n", inet_ntoa(net), net.s_addr);
#endif
        /* set the final homenet address up */
        pv.homenet = ((u_long) net.s_addr & pv.netmask);

#ifdef DEBUG
        sin.s_addr = pv.homenet;
        ArgusDebug(DEBUG_INIT, "Homenet = %s (%X)\n", inet_ntoa(sin), sin.s_addr);
#endif
    }

    mSplitFree(&toks, num_toks);
}



/****************************************************************************
 *
 * Function: RegisterPlugin(char *, void (*func)())
 *
 * Purpose:  Associates a rule option keyword with an option setup/linking
 *           function.
 *
 * Arguments: keyword => The option keyword to associate with the option
 *                       handler
 *            *func => function pointer to the handler
 *
 * Returns: void function
 *
 ***************************************************************************/
void RegisterPlugin(char *keyword, void (*func) (char *, OptTreeNode *, int))
{
    KeywordXlateList *idx;

    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Registering keyword:func => %s:%p\n", keyword, 
             func););

    idx = KeywordList;

    if(idx == NULL) {
        KeywordList = (KeywordXlateList *) calloc(sizeof(KeywordXlateList), 
                sizeof(char));

        KeywordList->entry.keyword = (char *) calloc(strlen(keyword) + 1, 
                sizeof(char));
        strncpy(KeywordList->entry.keyword, keyword, strlen(keyword)+1);
        KeywordList->entry.func = func;
    } else {
        /* go to the end of the list */
        while(idx->next != NULL) {
            if(!strcasecmp(idx->entry.keyword, keyword)) {
                ArgusLog(LOG_ERR, "RegisterPlugin: Duplicate detection plugin keyword: (%s) (%s)!\n",
                   idx->entry.keyword, keyword);
            }
            idx = idx->next;
        }

        idx->next = (KeywordXlateList *) calloc(sizeof(KeywordXlateList), sizeof(char));

        idx = idx->next;

        idx->entry.keyword = (char *) calloc(strlen(keyword) + 1, sizeof(char));
        strncpy(idx->entry.keyword, keyword, strlen(keyword)+1);
        idx->entry.func = func;
    }
}


void SessionInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function Session added to rule!\n"););
}
void FragBitsInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function FragBits added to rule!\n"););
}
void FragOffsetInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function FragOffset added to rule!\n"););
}
void IpProtoInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function IpProto added to rule!\n"););
}
void IsDataAtInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function IsDataAt added to rule!\n"););
}
void FlowInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function Flow added to rule!\n"););
}
void ByteTestInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function ByteTest added to rule!\n"););
}
void ByteJumpInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function ByteJump added to rule!\n"););
}
void ArgusPcreInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function ArgusPcre added to rule!\n"););
}
void FlowBitsInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function FlowBits added to rule!\n"););
}
void TCPFlagCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function TCPFlagCheck added to rule!\n"););
}
void IcmpTypeCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function IcmpTypeCheck added to rule!\n"););
}
void IcmpCodeCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function IcmpCodeCheck added to rule!\n"););
}
void TtlCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function TtlCheck added to rule!\n"););
}
void IpIdCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function IpIdCheck added to rule!\n"););
}
void TcpAckCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckTcpAck added to rule!\n"););
}
void TcpSeqCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckTcpSeq added to rule!\n"););
}
void IpOptionInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function IpOption added to rule!\n"););
}
void DsizeCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckDsize added to rule!\n"););
}
void RpcCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckRpc added to rule!\n"););
}
void IcmpIdCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckIcmpId added to rule!\n"););
}
void IcmpSeqCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckIcmpSeq added to rule!\n"););
}
void IpTosCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckIpTos added to rule!\n"););
}
void TcpWinCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckTcpWin added to rule!\n"););
}
void IpSameCheckInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckIpsame added to rule!\n"););
}
void PayloadSearchWithin(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckTcpFlags added to rule!\n"););
}
void PayloadSearchDistance(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckTcpFlags added to rule!\n"););
}
void PayloadSearchUri(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckTcpFlags added to rule!\n"););
}
void PayloadSearchRegex(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckTcpFlags added to rule!\n"););
}
void PayloadSearchRawbytes(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckTcpFlags added to rule!\n"););
}
void PayloadSearchNocase(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckTcpFlags added to rule!\n"););
}
void PayloadSearchDepth(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckTcpFlags added to rule!\n"););
}
void PayloadSearchOffset(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckTcpFlags added to rule!\n"););
}
void PayloadSearchListInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckTcpFlags added to rule!\n"););
}
void PayloadSearchInit(char *data, OptTreeNode *otn, int protocol)
{  
    /* link the plugin function in to the current OTN */
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "OTN function CheckTcpFlags added to rule!\n"););
}

void SetupPatternMatch(void)
{    
    RegisterPlugin("content", PayloadSearchInit);
    RegisterPlugin("content-list", PayloadSearchListInit);
    RegisterPlugin("offset", PayloadSearchOffset);
    RegisterPlugin("depth", PayloadSearchDepth);
    RegisterPlugin("nocase", PayloadSearchNocase);
    RegisterPlugin("rawbytes", PayloadSearchRawbytes);
    RegisterPlugin("regex", PayloadSearchRegex);
    RegisterPlugin("uricontent", PayloadSearchUri);
    RegisterPlugin("distance", PayloadSearchDistance);
    RegisterPlugin("within", PayloadSearchWithin);

    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: PatternMatch Initialized!\n"););
}
void SetupTCPFlagCheck(void)
{    
    RegisterPlugin("flags", TCPFlagCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: TCPFlagCheck Initialized!\n"););
}
void SetupIcmpTypeCheck(void)
{    
    RegisterPlugin("itype", IcmpTypeCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: IcmpTypeCheck Initialized\n"););
}
void SetupIcmpCodeCheck(void)
{    
    RegisterPlugin("icode", IcmpCodeCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: IcmpCodeCheck Initialized!\n"););
}
void SetupTtlCheck(void)
{    
    RegisterPlugin("ttl", TtlCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: TtlCheck Initialized\n"););
}
void SetupIpIdCheck(void)
{    
    RegisterPlugin("id", IpIdCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: IpIdCheck Initialized\n"););
}
void SetupTcpAckCheck(void)
{    
    RegisterPlugin("ack", TcpAckCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: TcpAckCheck Initialized\n"););
}
void SetupTcpSeqCheck(void)
{    
    RegisterPlugin("seq", TcpSeqCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: TcpSeqCheck Initialized\n"););
}
void SetupDsizeCheck(void)
{    
    RegisterPlugin("dsize", DsizeCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: DsizeCheck Initialized!\n"););
}
void SetupIpOptionCheck(void)
{    
    RegisterPlugin("ipopts", IpOptionInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: IpOptionCheck Initialized\n"););
}
void SetupRpcCheck(void)
{    
    RegisterPlugin("rpc", RpcCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: RpcCheck Initialized\n"););
}
void SetupIcmpIdCheck(void)
{    
    RegisterPlugin("icmp_id", IcmpIdCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: IcmpIdCheck Setup!\n"););
}
void SetupIcmpSeqCheck(void)
{    
    RegisterPlugin("icmp_seq", IcmpSeqCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: IcmpSeqCheck Setup\n"););
}
void SetupSession(void)
{    
    RegisterPlugin("session", SessionInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: Session Setup\n"););
}
void SetupIpTosCheck(void)
{    
    RegisterPlugin("tos", IpTosCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: IpTosCheck Initialized\n"););
}
void SetupFragBits(void)
{    
    RegisterPlugin("fragbits", FragBitsInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: FragBits Setup\n"););
}
void SetupFragOffset(void)
{    
    RegisterPlugin("flags", FragOffsetInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: FragOffsetCheck Initialized!\n"););
}
void SetupTcpWinCheck(void)
{    
    RegisterPlugin("window", TcpWinCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: TcpWinCheck Initialized\n"););
}
void SetupIpProto(void)
{    
    RegisterPlugin("ip_proto", IpProtoInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: IpProtoInit Initialized\n"););
}
void SetupIpSameCheck(void)
{    
    RegisterPlugin("sameip", IpSameCheckInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: IpSameCheck Initialized\n"););
}
void SetupClientServer(void)
{    
    RegisterPlugin("flow", FlowInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: ClientServerName(Flow) Setup!\n"););
}
void SetupByteTest(void)
{    
    RegisterPlugin("byte_test", ByteTestInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: ByteTest Setup!\n"););
}
void SetupByteJump(void)
{    
    RegisterPlugin("byte_jump", ByteJumpInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: ByteJump Setup!\n"););
}
void SetupIsDataAt(void)
{    
    RegisterPlugin("isdataat", IsDataAtInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: IsDataAt Initialized\n"););
}
void SetupPcre(void)
{    
    RegisterPlugin("pcre", ArgusPcreInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: ArgusPcre Initialized!\n"););
}
void SetupFlowBits(void)
{    
    RegisterPlugin("flowbits", FlowBitsInit); 
    DEBUG_WRAP(ArgusDebug(DEBUG_PLUGIN, "Plugin: FlowBits Initialized!\n"););
}



void InitPlugIns() 
{
    if(!pv.quiet_flag) { 
        LogMessage("Initializing Plug-ins!\n");
    } 
    SetupPatternMatch();
    SetupIcmpTypeCheck(); 
    SetupIcmpCodeCheck();
    SetupTtlCheck(); 
    SetupIpIdCheck();
    SetupTcpAckCheck(); 
    SetupTcpSeqCheck();      
    SetupDsizeCheck();
    SetupIpOptionCheck();
    SetupRpcCheck();
    SetupIcmpIdCheck();
    SetupIcmpSeqCheck();
    SetupSession(); 
    SetupIpTosCheck();  
    SetupFragBits(); 
    SetupFragOffset();
    SetupTcpWinCheck(); 
    SetupIpProto();
    SetupIpSameCheck();
    SetupClientServer();
    SetupByteTest();
    SetupByteJump();
    SetupIsDataAt();
    SetupPcre();
    SetupFlowBits();
/*
#ifdef ENABLE_RESPONSE
    SetupReact();
    SetupRespond();
#endif
*/
}


/*!
  Create a threshold table, initialize the threshold system, 
  and optionally limit it's memory usage.
   
  @param nbytes maximum memory to use for thresholding objects, in bytes.

  @return  THD_STRUCT*
  @retval  0 error
  @retval !0 valid THD_STRUCT
*/
THD_STRUCT *sfthd_new (unsigned nbytes)
{
    THD_STRUCT * thd;
    int          nrows;

    /* Create the THD struct */   
    if (!(thd = (THD_STRUCT*) calloc(1,sizeof(THD_STRUCT)))) 
        return 0;

    /* Calc max ip nodes for this memory */
    nrows = nbytes /( sizeof(THD_IP_NODE)+sizeof(THD_IP_NODE_KEY) );

#ifndef CRIPPLE 
    /* Create global hash table for all of the IP Nodes */
    thd->ip_nodes = sfxhash_new( nrows,  /* try one node per row - for speed */
                                 sizeof(THD_IP_NODE_KEY), /* keys size */
                                 sizeof(THD_IP_NODE),     /* data size */
                                 nbytes,                  /* memcap **/
                                 1,         /* ANR flag - true ?- Automatic Node Recovery=ANR */
                                 0,         /* ANR callback - none */
                                 0,         /* user freemem callback - none */
                                 1 ) ;      /* Recycle nodes ?*/
    if( !thd->ip_nodes ) {
#ifdef THD_DEBUG       
       printf("Could not allocate the sfxhash table\n");
#endif       
       free(thd);
       return 0;
    }
    /* Calc max ip nodes for global thresholding memory */
    nrows = nbytes /( sizeof(THD_IP_GNODE)+sizeof(THD_IP_GNODE_KEY) );

    /* Create global hash table for all of the Global-Thresholding IP Nodes */
    thd->ip_gnodes = sfxhash_new( nrows,  /* try one node per row - for speed */
                                  sizeof(THD_IP_GNODE_KEY), /* keys size */
                                  sizeof(THD_IP_GNODE),     /* data size */
                                  nbytes,                  /* memcap **/
                                  1,         /* ANR flag - true ?- Automatic Node Recovery=ANR */
                                  0,         /* ANR callback - none */
                                  0,         /* user freemem callback - none */
                                  1 ) ;      /* Recycle nodes ?*/
    if( !thd->ip_gnodes ) {
#ifdef THD_DEBUG       
       printf("Could not allocate the sfxhash table\n");
#endif       
       free(thd);
       return 0;
    }
#endif    
    return thd;
}

/*!
 *
 *  \f sfxhash.c
 *
 *  A Customized hash table library for storing and accessing key + data pairs.
 *
 *  This table incorporates a memory manager (memcap.c) to provide a memory cap,  
 *  and an automatic node recovery system for out of memory management. Keys and
 *  Data are copied into the hash table during the add operation. The data may
 *  be allocated and free'd by the user (by setting the datasize to zero ). A 
 *  user callback is provided to allow the user to do cleanup whenever a node
 *  is released, by either the ANR system or the relase() function.
 *
 *  Users can and should delete nodes when they know they are not needed anymore,
 *  but this custom table is designed for the case where nodes are allocated 
 *  permanently, we have to limit memory, and we wish to recycle old nodes.  
 *  Many problems have a natural node ageing paradigm working in our favor, 
 *  so automated node aging makes sense. i.e. thresholding, tcp state.
 *
 *  This hash table maps keys to data.  All keys must be unique.
 *  Uniqueness is enforcedby the code.
 *
 *  Features:
 *
 *    1) Keys must be fixed length (per table) binary byte sequences.
 *         keys are copied during the add function
 *    2) Data must be fixed length (per table) binary byte sequences.
 *         data is copied during the add function - if datasize > 0
 *       Data may be managed by the user as well.
 *    3) Table row sizes can be automatically adjusted to
 *       the nearest prime number size during table initialization/creation.
 *    4) Memory management includes tracking the size of each allocation, 
 *       number of allocations, enforcing a memory cap, and automatic node 
 *       recovery - when  memory is low the oldest untouched node
 *       is unlinked and recycled for use as a new node.
 *
 *  Per Node Memory Usage:
 *  ----------------------
 *     SFXHASH_NODE bytes
 *     KEYSIZE bytes
 *     [DATASIZE bytes] if datasize > 0 during call to sfxhash_new.
 *
 *  The hash node memory (sfxhash_node,key,and data) is allocated with 
 *  one call to s_malloc/memcap_alloc.
 *
 *  Copyright (C) 2001 Marc A Norton.
 *  Copyright (C) 2003 Sourcefire,Inc.
 *
 *  2003-06-03: cmg - added sfxhash_{l,m}ru to return {least,most}
 *              recently used node from the global list
 *
 *              - added _anrcount function
 *              - changed count function to return unsigned to match structure
 *
 *  2003-06-11: cmg added
 *              overhead_bytes + blocks to separate out the
 *              memcap constraints from the hash table itself
 *              find success v fail
 *
 *  2003-06-19: cmg added
 *
 *              ability to set own hash function
 *              ability to set own key cmp function
 *
 *  2003-06-30: rdempster
 *              fixed bug in that would anr from the freelist
 *              
 */

#include "sfutil/sfxhash.h"

/*
 * Private Malloc - abstract the memory system
 */
static 
void * s_malloc( SFXHASH * t, int n )
{
    return sfmemcap_alloc( &t->mc, n );
}
static 
void s_free( SFXHASH * t, void * p )
{
    sfmemcap_free( &t->mc, p );
}

/*
 *   User access to the memory management, do they need it ? WaitAndSee
 */
void * sfxhash_alloc( SFXHASH * t, unsigned nbytes )
{
    return s_malloc( t, nbytes );
}
void   sfxhash_free( SFXHASH * t, void * p )
{
    s_free( t, p );
}

#ifdef XXXX
/*
 *  A classic hash routine using prime numbers 
 *
 *  Constants for the Prime No. based hash routines  
 */
#define PRIME_INIT   9791
#define PRIME_SCALE  31
static unsigned sfxhash_data( unsigned char *d, int n )
{
    int i;
    register unsigned hash = PRIME_INIT;
    for(i=0;i<n;i++)
    {
        hash = hash * PRIME_SCALE + d[i];
    }  
    return hash;
}

#endif /* XXXX */

/*
 *   Primiitive Prime number test, not very fast nor efficient, but should be ok for 
 *   hash table sizes of typical size.  NOT for real-time usage!
 */
static int isPrime(int num )
{
    int i;
    for(i=2;i<num;i++)
    {
        if( (num % i) == 0 ) break;//oops not prime, should have a remainder
    }
    if( i == num ) return 1;
    return 0;
}
/*
 *  Iterate number till we find a prime.
 */
static int calcNextPrime(int num )
{
    while( !isPrime( num ) ) num++;

    return num;
}

/*!
 *
 * Create a new hash table
 *
 * By default, this will "splay" nodes to the top of a free list. 
 *
 * @param nrows    number of rows in hash table
 * @param keysize  key size in bytes, same for all keys
 * @param datasize datasize in bytes, zero indicates user manages data
 * @param maxmem   maximum memory to use in bytes
 * @param anr_flag Automatic Node Recovery boolean flag
 * @param anrfree  users Automatic Node Recovery memory release function
 * @param usrfree  users standard memory release function
 *
 * @return SFXHASH*
 * @retval  0 out of memory
 * @retval !0 Valid SFXHASH pointer  
 *
 */
/*
  Notes:
  if nrows < 0 don't cal the nearest prime.
  datasize must be the same for all entries, unless datasize is zero.
  maxmem of 0 indicates no memory limits.

*/
SFXHASH * sfxhash_new( int nrows, int keysize, int datasize, int maxmem, 
                       int anr_flag, 
                       int (*anrfree)(void * key, void * data),
                       int (*usrfree)(void * key, void * data),
                       int recycle_flag )
{
    int       i;
    SFXHASH * h;

    if( nrows > 0 ) /* make sure we have a prime number */
    {
        nrows = calcNextPrime( nrows );
    }
    else   /* use the magnitude or nrows as is */
    { 
        nrows = -nrows;
    }

    /* Allocate the table structure from general memory */
    h = (SFXHASH*) calloc( 1, sizeof(SFXHASH) );
    if( !h ) 
    {
        return 0;
    }

    /* this has a default hashing function */
    h->sfhashfcn = sfhashfcn_new( nrows );
    
    if( !h->sfhashfcn ) 
    {
        return 0;
    }

    sfmemcap_init( &h->mc, maxmem );

    /* Allocate the array of node ptrs */
    h->table = (SFXHASH_NODE**) s_malloc( h, sizeof(SFXHASH_NODE*) * nrows );
    if( !h->table ) 
    {
        return 0;
    }

    for( i=0; i<nrows; i++ )
    {
        h->table[i] = 0;
    }

    h->anrfree  = anrfree;
    h->usrfree  = usrfree;
    h->keysize  = keysize;
    h->datasize = datasize;
    h->nrows    = nrows;
    h->crow     = 0; 
    h->cnode    = 0; 
    h->count    = 0;
    h->ghead    = 0;
    h->gtail    = 0;
    h->anr_count= 0;    
    h->anr_tries= 0;
    h->anr_flag = anr_flag; 
    h->splay    = 1; 
    h->recycle_nodes = recycle_flag;

    h->find_success = 0;
    h->find_fail    = 0;
    
    /* save off how much we've already allocated from our memcap */    
    h->overhead_bytes = h->mc.memused;
    h->overhead_blocks = h->mc.nblocks;

    return h;
}

/*!
 *  Set Splay mode : Splays nodes to front of list on each access
 * 
 * @param t SFXHASH table pointer
 * @param n boolean flag toggles splaying of hash nodes
 *
 */
void sfxhash_splaymode( SFXHASH * t, int n )
{
    t->splay = n;
}


/*!
 *  Delete the hash Table 
 *
 *  free key's, free node's, and free the users data.
 *
 * @param h SFXHASH table pointer
 *
 */
void sfxhash_delete( SFXHASH * h )
{
    int         i;
    SFXHASH_NODE * node, * onode;

    if( !h ) return;

     if( h->sfhashfcn ) sfhashfcn_free( h->sfhashfcn );
 
    if( h->table )
    {  
        for(i=0;i<h->nrows;i++)
        {
            for( node=h->table[i]; node;  )
            {
                onode = node;
                node  = node->next;
		
		/* Notify user that we are about to free this node function */
		if( h->usrfree )
                    h->usrfree( onode->key, onode->data );
        
		s_free( h,onode );
            }
        }
        s_free( h, h->table );
        h->table = 0;
    }

    free( h ); /* free the table from general memory */
}

/*!
 *  Get the # of Nodes in HASH the table
 *
 * @param t SFXHASH table pointer
 *
 */
unsigned sfxhash_count( SFXHASH * t )
{
    return t->count;
}

/*!
 *  Get the # auto recovery 
 *
 * @param t SFXHASH table pointer
 *
 */
unsigned sfxhash_anr_count( SFXHASH * t )
{
    return t->anr_count;
}

/*!
 *  Get the # finds
 *
 * @param t SFXHASH table pointer
 *
 */
unsigned sfxhash_find_total( SFXHASH * t )
{
    return t->find_success + t->find_fail;
}

/*!
 *  Get the # unsucessful finds
 *
 * @param t SFXHASH table pointer
 *
 */
unsigned sfxhash_find_fail( SFXHASH * t )
{
    return t->find_fail;
}

/*!
 *  Get the # sucessful finds
 *
 * @param t SFXHASH table pointer
 *
 */
unsigned sfxhash_find_success( SFXHASH * t )
{
    return t->find_success;
}




/*!
 *  Get the # of overhead bytes
 *
 * @param t SFXHASH table pointer
 *
 */
unsigned sfxhash_overhead_bytes( SFXHASH * t )
{
    return t->overhead_bytes;
}

/*!
 *  Get the # of overhead blocks
 *
 * @param t SFXHASH table pointer
 *
 */
unsigned sfxhash_overhead_blocks( SFXHASH * t )
{
    return t->overhead_blocks;
}

/*
 *  Free List - uses the NODE gnext/gprev fields
 */
static
void sfxhash_save_free_node( SFXHASH *t, SFXHASH_NODE * hnode )
{
    /* Add A Node to the Free Node List */
    if( t->fhead ) /* add the node to head of the the existing list */
    {
        hnode->gprev    = 0;  
        hnode->gnext    = t->fhead;
        t->fhead->gprev = hnode;
        t->fhead        = hnode;
        /* tail is not affected */
    }
    else /* 1st node in this list */
    {
        hnode->gprev = 0;
        hnode->gnext = 0;
        t->fhead    = hnode;
        t->ftail    = hnode;
    }
}
static
SFXHASH_NODE * sfxhash_get_free_node( SFXHASH *t )
{
    SFXHASH_NODE * node = t->fhead;

    /* Remove A Node from the Free Node List - remove the head node */
    if( t->fhead  ) 
    {
        t->fhead = t->fhead->gnext;
        if( t->fhead ) 
            t->fhead->gprev = 0;

        if( t->ftail  == node ) /* no more nodes - clear the tail */
            t->ftail  =  0;
    }

    return node;
}

static
void sfxhash_glink_node( SFXHASH *t, SFXHASH_NODE * hnode )
{
    /* Add The Node */
    if( t->ghead ) /* add the node to head of the the existing list */
    {
        hnode->gprev    = 0;  
        hnode->gnext    = t->ghead;
        t->ghead->gprev = hnode;
        t->ghead        = hnode;
        /* tail is not affected */
    }
    else /* 1st node in this list */
    {
        hnode->gprev = 0;
        hnode->gnext = 0;
        t->ghead    = hnode;
        t->gtail    = hnode;
    }
}

static
void sfxhash_gunlink_node( SFXHASH *t, SFXHASH_NODE * hnode )
{
    /* Remove the Head Node */
    if( t->ghead == hnode ) /* add the node to head of the the existing list */
    {
        t->ghead = t->ghead->gnext;
        if( t->ghead ) 
            t->ghead->gprev = 0;
    }

    if( hnode->gprev ) hnode->gprev->gnext = hnode->gnext;
    if( hnode->gnext ) hnode->gnext->gprev = hnode->gprev;

    if( t->gtail  == hnode )
        t->gtail  =  hnode->gprev;             
}

static
void sfxhash_gmovetofront( SFXHASH *t, SFXHASH_NODE * hnode )
{
    if( hnode != t->ghead )
    {
        sfxhash_gunlink_node( t, hnode );
        sfxhash_glink_node( t, hnode );
    }
}

/*
 *
 */
static
void sfxhash_link_node( SFXHASH * t, SFXHASH_NODE * hnode )
{
    /* Add The Node to the Hash Table Row List */
    if( t->table[hnode->rindex] ) /* add the node to the existing list */
    {
        hnode->prev = 0;  // insert node as head node
        hnode->next=t->table[hnode->rindex];
        t->table[hnode->rindex]->prev = hnode;
        t->table[hnode->rindex] = hnode;
    }
    else /* 1st node in this list */
    {
        hnode->prev=0;
        hnode->next=0;
        t->table[hnode->rindex] = hnode;
    }
}

static
void sfxhash_unlink_node( SFXHASH * t, SFXHASH_NODE * hnode )
{
    if( hnode->prev )  // definitely not the 1st node in the list
    {
        hnode->prev->next = hnode->next;
        if( hnode->next ) 
            hnode->next->prev = hnode->prev;
    }
    else if( t->table[hnode->rindex] )  // must be the 1st node in the list
    {
        t->table[hnode->rindex] = t->table[hnode->rindex]->next;
        if( t->table[hnode->rindex] )
            t->table[hnode->rindex]->prev = 0;
    }
}

/*
 *  move a node to the front of the row list at row = 'index'
 */
static void movetofront( SFXHASH *t, SFXHASH_NODE * n )
{
    /* Modify Hash Node Row List */
    if( t->table[n->rindex] != n ) // if not at front of list already...
    {
        /* Unlink the node */
        sfxhash_unlink_node( t, n );
     
        /* Link at front of list */
        sfxhash_link_node( t, n );
    }

    /* Move node in the global hash node list to the front */
    sfxhash_gmovetofront( t, n );
}

/*
 * Allocat a new hash node, uses Auto Node Recovery if needed and enabled.
 * 
 * The oldest node is the one with the longest time since it was last touched, 
 * and does not have any direct indication of how long the node has been around.
 * We don't monitor the actual time since last being touched, instead we use a
 * splayed global list of node pointers. As nodes are accessed they are splayed
 * to the front of the list. The oldest node is just the tail node.
 *
 */
static 
SFXHASH_NODE * sfxhash_newnode( SFXHASH * t )
{
    SFXHASH_NODE * hnode;

    /* Recycle Old Nodes - if any */
    hnode = sfxhash_get_free_node( t );

    /* Allocate memory for a node */
    if( ! hnode )
    {
        hnode = (SFXHASH_NODE*)s_malloc( t, sizeof(SFXHASH_NODE) +
                                         t->keysize + t->datasize );
    }
        
    /*  If we still haven't found hnode, we're at our memory limit.
     *
     *  Uses Automatic Node Recovery, to recycle the oldest node-based on access
     *  (Unlink and reuse the tail node)
     */ 
    if( !hnode && t->anr_flag && t->gtail )
    {
        /* Find the oldes node the users willing to let go. */
        for(hnode = t->gtail; hnode; hnode = hnode->gprev )
        {
            if( t->anrfree ) /* User has provided a permission+release callback function */
            {
                t->anr_tries++;/* Count # ANR requests */
                
                /* Ask the user for permission to release this node, but let them say no! */
                if( t->anrfree( hnode->key, hnode->data ) )
                {
                    /* NO, don't recycle this node, user's not ready to let it go. */                            
                    continue;
                }
                
                /* YES, user said we can recycle this node */
            }

            sfxhash_gunlink_node( t, hnode ); /* unlink from the global list */
            sfxhash_unlink_node( t, hnode ); /* unlink from the row list */
            t->count--;
            t->anr_count++; /* count # of ANR operations */
            break;
        }
    }

    /* either we are returning a node or we're all full and the user
     * won't let us allocate anymore and we return NULL */
    return hnode;
}

/*
 *
 *  Find a Node based on the key, return the node and the index.
 *  The index is valid even if the return value is NULL, in which
 *  case the index is the corect row in which the node should be 
 *  created.
 *
 */
static 
SFXHASH_NODE * sfxhash_find_node_row( SFXHASH * t, void * key, int * rindex )
{
    unsigned       hashkey;
    int            index;
    SFXHASH_NODE  *hnode;

    hashkey = t->sfhashfcn->hash_fcn( t->sfhashfcn,
                                      (unsigned char*)key,
                                      t->keysize );
    
/*     printf("hashkey: %u t->keysize: %d\n", hashkey, t->keysize); */
/*     flowkey_fprint(stdout, key);  */
/*     printf("****\n"); */

    index   = hashkey % t->nrows;

    *rindex = index;
   
    for( hnode=t->table[index]; hnode; hnode=hnode->next )
    {
        if( !t->sfhashfcn->keycmp_fcn(hnode->key,key,t->keysize) )
        {
            if( t->splay > 0 )
                movetofront(t,hnode);

            t->find_success++;            
            return hnode;
        }
    }

    t->find_fail++;            
    return NULL;
}



/*!
 * Add a key + data pair to the hash table
 *
 * 2003-06-06:
 *  - unique_tracker.c assumes that this splays
 *    nodes to the top when they are added.
 *
 *    This is done because of the successful find.
 *
 * @param t SFXHASH table pointer
 * @param key  users key pointer
 * @param data  users data pointer
 *
 * @return integer
 * @retval SFXHASH_OK      success
 * @retval SFXHASH_INTABLE already in the table, t->cnode points to the node
 * @retval SFXHASH_NOMEM   not enough memory
 */
int sfxhash_add( SFXHASH * t, void * key, void * data )
{
    int            index;
    SFXHASH_NODE * hnode;

    /* Enforce uniqueness: Check for the key in the table */
    hnode = sfxhash_find_node_row( t, key, &index );
    if( hnode )
    {
        t->cnode = hnode;

        return SFXHASH_INTABLE; /* found it - return it. */
    }

    /* 
     *  Alloc new hash node - allocate key space and data space at the same time.
     */
    hnode = sfxhash_newnode( t );
    if( !hnode )
    {
        return SFXHASH_NOMEM;
    }

    /* Set up the new key pointer */
    hnode->key = (char*)hnode + sizeof(SFXHASH_NODE);

    /* Copy the key */
    memcpy(hnode->key,key,t->keysize);

    /* Save our table row index */
    hnode->rindex = index;

    /* Copy the users data - or if datasize is zero set ptr to users data */
    if( t->datasize )
    {
        /* Set up the new data pointer */
        hnode->data= (char*)hnode + sizeof(SFXHASH_NODE) + t->keysize;

        memcpy(hnode->data,data,t->datasize);
    }
    else 
    {
        hnode->data = data;
    }
    
    /* Link the node into the table row list */
    sfxhash_link_node ( t, hnode );

    /* Link at the front of the global node list */
    sfxhash_glink_node( t, hnode );

    /* Track # active nodes */
    t->count++;

    return SFXHASH_OK;
}


/*!
 * Find a Node based on the key
 *
 * @param t SFXHASH table pointer
 * @param key  users key pointer
 *
 * @return SFXHASH_NODE*   valid pointer to the hash node
 * @retval 0               node not found
 *
 */
SFXHASH_NODE * sfxhash_find_node( SFXHASH * t, void * key)
{
    int            rindex;

    return sfxhash_find_node_row( t, key, &rindex );
}

/*!
 * Find the users data based associated with the key
 *
 * @param t SFXHASH table pointer
 * @param key  users key pointer
 *
 * @return void*   valid pointer to the users data
 * @retval 0       node not found
 *
 */
void * sfxhash_find( SFXHASH * t, void * key)
{
    SFXHASH_NODE * hnode;
    int            rindex;

    hnode = sfxhash_find_node_row( t, key, &rindex );

    if( hnode ) return hnode->data;

    return NULL;
}


/** 
 * Get the HEAD of the in use list
 * 
 * @param t table pointer 
 * 
 * @return the head of the list or NULL
 */
SFXHASH_NODE *sfxhash_ghead( SFXHASH * t )
{
    if(t)
    {
        return t->ghead;
    }

    return NULL;
}


/** 
 * Walk the global list
 * 
 * @param n current node
 * 
 * @return the next node in the list or NULL when at the end
 */
SFXHASH_NODE *sfxhash_gnext( SFXHASH_NODE *n )
{
    if(n)
    {
        return n->gnext;
    }

    return NULL;
}


/*!
 * Return the most recently used data from the global list
 *
 * @param t SFXHASH table pointer
 *
 * @return void*   valid pointer to the users data
 * @retval 0       node not found
 *
 */
void * sfxhash_mru( SFXHASH * t )
{
    SFXHASH_NODE * hnode;

    hnode = sfxhash_ghead(t);

    if( hnode )
        return hnode->data;
        
    return NULL;
}

/*!
 * Return the least recently used data from the global list
 *
 * @param t SFXHASH table pointer
 *
 * @return void*   valid pointer to the users data
 * @retval 0       node not found
 *
 */
void * sfxhash_lru( SFXHASH * t )
{
    SFXHASH_NODE * hnode;

    hnode = t->gtail;

    if( hnode ) return hnode->data;

    return NULL;
}

/*!
 * Get some hash table statistics. NOT FOR REAL TIME USE.
 *
 * 
 * @param t SFXHASH table pointer
 * @param filled how many 
 *
 * @return max depth of the table
 *
 */
unsigned sfxhash_maxdepth( SFXHASH * t )
{
    unsigned i;
    unsigned max_depth = 0;

    SFXHASH_NODE * hnode;

    for( i=0; i<t->nrows; i++ )
    {
        unsigned cur_depth = 0;

        for(hnode = t->table[i]; hnode != NULL; hnode = hnode->next)
        {
            cur_depth++;
        }

        if(cur_depth > max_depth)
            max_depth = cur_depth;
    }

    return max_depth;
}

/*
 *  Unlink and free the node
 */
static int sfxhash_free_node( SFXHASH * t, SFXHASH_NODE * hnode)
{
    sfxhash_unlink_node( t, hnode ); /* unlink from the hash table row list */

    sfxhash_gunlink_node( t, hnode ); /* unlink from global-hash-node list */

    t->count--;

    if( t->usrfree )
        t->usrfree( hnode->key, hnode->data );

    if( t->recycle_nodes )
    {
        sfxhash_save_free_node( t, hnode );
    }
    else
    {
        s_free( t, hnode );
    }

    return SFXHASH_OK;
}

/*!
 * Remove a Key + Data Pair from the table.
 *
 * @param t SFXHASH table pointer
 * @param key  users key pointer
 *
 * @return 0   success
 * @retval !0  failed
 *
 */
int sfxhash_remove( SFXHASH * t, void * key)
{
    SFXHASH_NODE * hnode;
    unsigned hashkey, index;

    hashkey = t->sfhashfcn->hash_fcn( t->sfhashfcn,
                                      (unsigned char*)key,
                                      t->keysize );
    
    index = hashkey % t->nrows;

    for( hnode=t->table[index]; hnode; hnode=hnode->next )
    {
        if( !t->sfhashfcn->keycmp_fcn(hnode->key,key,t->keysize) )
        {
            return sfxhash_free_node( t, hnode );
        }
    }

    return SFXHASH_ERR;  
}

/* 
   Internal use only 
*/
static 
void sfxhash_next( SFXHASH * t )
{
    if( !t->cnode )
        return ;
 
    /* Next node in current node list */
    t->cnode = t->cnode->next;
    if( t->cnode )
    {
        return;
    }

    /* Next row */ 
    /* Get 1st node in next non-emtoy row/node list */
    for( t->crow++; t->crow < t->nrows; t->crow++ )
    {    
        t->cnode = t->table[ t->crow ];
        if( t->cnode ) 
        {
            return;
        }
    }
}
/*!
 * Find and return the first hash table node
 *
 * @param t SFXHASH table pointer
 *
 * @return 0   failed
 * @retval !0  valid SFXHASH_NODE *
 *
 */
SFXHASH_NODE * sfxhash_findfirst( SFXHASH * t )
{
    SFXHASH_NODE * n;

    /* Start with 1st row */
    for( t->crow=0; t->crow < t->nrows; t->crow++ )
    {    
        /* Get 1st Non-Null node in row list */
        t->cnode = t->table[ t->crow ];
        if( t->cnode )
        {
            n = t->cnode;
            sfxhash_next( t ); // load t->cnode with the next entry
            return n;
        }
    }
    
    return NULL;
}

/*!
 * Find and return the next hash table node
 *
 * @param t SFXHASH table pointer
 *
 * @return 0   failed
 * @retval !0  valid SFXHASH_NODE *
 *
 */
SFXHASH_NODE * sfxhash_findnext( SFXHASH * t )
{
    SFXHASH_NODE * n;

    n = t->cnode;
    if( !n ) /* Done, no more entries */
    {
        return NULL;
    }

    /*
      Preload next node into current node 
    */
    sfxhash_next( t ); 

    return  n;
}


/** 
 * Make sfhashfcn use a separate set of operators for the backend.
 *
 * @param h sfhashfcn ptr
 * @param hash_fcn user specified hash function
 * @param keycmp_fcn user specified key comparisoin function
 */

int sfxhash_set_keyops( SFXHASH *h ,
                        unsigned (*hash_fcn)( SFHASHFCN * p,
                                              unsigned char *d,
                                              int n),
                        int (*keycmp_fcn)( const void *s1,
                                           const void *s2,
                                           size_t n))
{
    if(h && hash_fcn && keycmp_fcn)
    {
        return sfhashfcn_set_keyops(h->sfhashfcn, hash_fcn, keycmp_fcn);
    }

    return -1;
}


/*
 * -----------------------------------------------------------------------------------------
 *   Test Driver for Hashing
 * -----------------------------------------------------------------------------------------
 */
#ifdef SFXHASH_MAIN 


/* 
   This is called when the user releases a node or kills the table 
*/
int usrfree( void * key, void * data )
{

    /* Release any data you need to */
    return 0;  
}

/* 
   Auto Node Recovery Callback - optional 

   This is called to ask the user to kill a node, if it reutrns !0 than the hash
   library does not kill this node.  If the user os willing to let the node die,
   the user must do any free'ing or clean up on the node during this call.
*/
int anrfree( void * key, void * data )
{
    static int bx = 0;

    /* Decide if we can free this node. */

    //bx++; if(bx == 4 )bx=0;       /* for testing */

    /* if we are allowing the node to die, kill it */
    if( !bx ) usrfree( key, data );

    return bx;  /* Allow the caller to  kill this nodes data + key */
}

/*
 *       Hash test program : use 'sfxhash 1000 50000' to stress the Auto_NodeRecover feature
 */
int main ( int argc, char ** argv )
{
    int             i;
    SFXHASH      * t;
    SFXHASH_NODE * n;
    char            strkey[256], strdata[256], * p;
    int             num = 100;
    int             mem = 0;

    memset(strkey,0,20);
    memset(strdata,0,20);

    if( argc > 1 )
    {
        num = atoi(argv[1]);
    }

    if( argc > 2 )
    {
        mem = atoi(argv[2]);
    }

    /* Create a Hash Table */
    t = sfxhash_new( 100,        /* one row per element in table, when possible */
                     20,        /* key size :  padded with zeros */ 
                     20,        /* data size:  padded with zeros */ 
                     mem,       /* max bytes,  0=no max */  
                     1,         /* enable AutoNodeRecovery */
                     anrfree,   /* provide a function to let user know we want to kill a node */
                     usrfree, /* provide a function to release user memory */
                     1);      /* Recycle nodes */
    if(!t)
    {
        printf("Low Memory!\n");
        exit(0);
    }
    /* Add Nodes to the Hash Table */
    for(i=0;i<num;i++) 
    {
        sprintf(strkey, "KeyWord%5.5d",i+1);
        sprintf(strdata,"KeyWord%5.5d",i+1);
        //strupr(strdata);
        sfxhash_add( t, strkey  /* user key */ ,  strdata /* user data */ );
    }  

    /* Find and Display Nodes in the Hash Table */
    printf("\n** FIND KEY TEST\n");
    for(i=0;i<num;i++) 
    {
        sprintf(strkey,"KeyWord%5.5d",i+1);

        p = (char*) sfxhash_find( t, strkey );

        if(p)printf("Hash-key=%*s, data=%*s\n", strlen(strkey),strkey, strlen(strkey), p );
    }  

    /* Show memcap memory */
    printf("\n...******\n");
    sfmemcap_showmem(&t->mc);
    printf("...******\n");

    /* Display All Nodes in the Hash Table findfirst/findnext */
    printf("\n...FINDFIRST / FINDNEXT TEST\n");
    for( n  = sfxhash_findfirst(t); 
         n != 0; 
         n  = sfxhash_findnext(t) )
    {
        printf("hash-findfirst/next: n=%x, key=%s, data=%s\n", n, n->key, n->data );

        /*
          remove node we are looking at, this is first/next safe.
        */
        if( sfxhash_remove(t,n->key) ) 
        {
            printf("...ERROR: Could not remove the key node!\n");
        }
        else  
        {
            printf("...key node removed\n");
        }
    }

    printf("...Auto-Node-Recovery: %d recycle attempts, %d completions.\n",t->anr_tries,t->anr_count);

    /* Free the table and it's user data */
    printf("...sfxhash_delete\n");

    sfxhash_delete( t );
   
    printf("\nnormal pgm finish\n\n");

    return 0;
}
#endif


/*
  sfmemcap.c

  These functions wrap the malloc & free functions. They enforce a memory cap using
  the MEMCAP structure.  The MEMCAP structure tracks memory usage.  Each allocation
  has 4 bytes added to it so we can store the allocation size.  This allows us to 
  free a block and accurately track how much memory was recovered.
  
  Marc Norton  
*/

#include "sfutil/sfmemcap.h"

/*
*   Set max # bytes & init other variables.
*/
void sfmemcap_init( MEMCAP * mc, unsigned nbytes )
{
	mc->memcap = nbytes;
	mc->memused= 0;
	mc->nblocks= 0;
}

/*
*   Create and Init a MEMCAP -  use free to release it
*/
MEMCAP * sfmemcap_new( unsigned nbytes )
{
	 MEMCAP * mc;

	 mc = (MEMCAP*)calloc(1,sizeof(MEMCAP));

         if( mc ) sfmemcap_init( mc, nbytes );
	 
	 return mc;
}

/*
*  Release the memcap structure
*/
void sfmemcap_delete( MEMCAP * p )
{
     if(p)free( p );
}

/*
*  Allocate some memory
*/
void * sfmemcap_alloc( MEMCAP * mc, unsigned nbytes )
{
   int * data;

   //printf("sfmemcap_alloc: %d bytes requested, memcap=%d, used=%d\n",nbytes,mc->memcap,mc->memused);

   nbytes += 4;

   /* Check if we are limiting memory use */
   if( mc->memcap > 0 )
   {
      /* Check if we've maxed out our memory - if we are tracking memory */
      if( (mc->memused + nbytes) > mc->memcap )
      {
	      return 0;
      }
   }

   data = (int*) calloc( 1, nbytes );
   if( data == NULL )
   {
        return 0;
   }

   *data++ = nbytes;

   mc->memused += nbytes;
   mc->nblocks++;

   return data;
}

/*
*   Free some memory
*/
void sfmemcap_free( MEMCAP * mc, void * p )
{
   int * q;

   q = (int*)p;
   q--;
   mc->memused -= *q;
   mc->nblocks--;

   free(q);
}

/*
*   For debugging.
*/
void sfmemcap_showmem( MEMCAP * mc )
{
     fprintf(stderr, "memcap: memcap = %u bytes,",mc->memcap);
     fprintf(stderr, " memused= %u bytes,",mc->memused);
     fprintf(stderr, " nblocks= %d blocks\n",mc->nblocks);
}

/*
*  String Dup Some memory.
*/
char * sfmemcap_strdup( MEMCAP * mc, const char *str )
{
    char * data = (char *)sfmemcap_alloc( mc, strlen(str) + 1 );
    if(data == NULL)
    {
        return  0 ;
    }
    strcpy(data,str);
    return data;
}

/*
*  Dup Some memory.
*/
void * sfmemcap_dupmem( MEMCAP * mc, void * src, int n )
{
    void * data = (char *)sfmemcap_alloc( mc, n );
    if(data == NULL)
    {
        return  0;
    }

    memcpy( data, src, n );

    return data;
}

/*
     sfhashfcn.c 

     Each hash table must allocate it's own SFGHASH struct, this is because
     sfghash_new uses the number of rows in the hash table to modulo the random
     values.

*/

#include "sfutil/sfhashfcn.h"

SFHASHFCN * sfhashfcn_new( int m )
{
   SFHASHFCN *p;

   p = (SFHASHFCN*) malloc( sizeof(SFHASHFCN) );
   if( !p )
       return 0;

   srand( (unsigned) time(0) );

   p->seed       = calcNextPrime( rand() % m );
   p->scale      = calcNextPrime( rand() % m );
   p->hardener   = ( rand() * rand() ) ^ 0xe0c0b0a0;

   p->hash_fcn   = &sfhashfcn_hash;
   p->keycmp_fcn = &memcmp;
       
   return p;
}

void sfhashfcn_free( SFHASHFCN * p )
{
   if( p )
   {
       free( p);
   }
}

unsigned sfhashfcn_hash( SFHASHFCN * p, unsigned char *d, int n )
{
    unsigned hash = p->seed;
    while( n )
    {
        hash *=  p->scale;
        hash += *d++;
        n--;
    }
    return hash ^ p->hardener;
}


/** 
 * Make sfhashfcn use a separate set of operators for the backend.
 *
 * @param h sfhashfcn ptr
 * @param hash_fcn user specified hash function
 * @param keycmp_fcn user specified key comparisoin function
 */
int sfhashfcn_set_keyops( SFHASHFCN *h,
                          unsigned (*hash_fcn)( SFHASHFCN * p,
                                                unsigned char *d,
                                                int n),
                          int (*keycmp_fcn)( const void *s1,
                                             const void *s2,
                                             size_t n))
{
    if(h && hash_fcn && keycmp_fcn)
    {
        h->hash_fcn   = hash_fcn;
        h->keycmp_fcn = keycmp_fcn;

        return 0;
    }

    return -1;
}



/*
**  $Id: parser.c,v 1.3 2004/05/14 15:44:35 qosient Exp $
** 
**  fpcreate.c
**
**  Copyright (C) 2002 Sourcefire,Inc
**  Dan Roelker <droelker@sourcefire.com>
**  Marc Norton <mnorton@sourcefire.com>
**
**  NOTES
**  5.7.02 - Initial Checkin. Norton/Roelker
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rules.h"
#include "parser.h"
#include "fpcreate.h"
#include "fpdetect.h"
#include "detection-plugins/sp_pattern_match.h"
#include "detection-plugins/sp_icmp_code_check.h"
#include "detection-plugins/sp_icmp_type_check.h"
#include "detection-plugins/sp_ip_proto.h"
#include "plugin_enum.h"
#include "util.h"

#include "sfutil/mpse.h"
#include "sfutil/bitop.h"

/*
#define LOCAL_DEBUG
*/

/*
**  Macro for verifying memory allocation and fail
**  accordingly.
*/
#define MEMASSERT(p,s) if(!p){printf("No memory - file:%s %s !\n",__FILE__,s); exit(1);}
/*
**  Main variables to this file. 
**
**  The port-rule-maps map the src-dst ports to rules for
**  udp and tcp, for Ip we map the dst port as the protocol, 
**  and for Icmp we map the dst port to the Icmp type. This 
**  allows us to use the decode packet information to in O(1) 
**  select a group of rules to apply to the packet.  These 
**  rules may have uricontent, content, or they may be no content 
**  rules, or any combination. We process the uricontent 1st,
**  than the content, and than the no content rules for udp/tcp 
**  and icmp, than we process the ip rules.
*/
static PORT_RULE_MAP *prmTcpRTNX = NULL;
static PORT_RULE_MAP *prmUdpRTNX = NULL;
static PORT_RULE_MAP *prmIpRTNX  = NULL;
static PORT_RULE_MAP *prmIcmpRTNX= NULL;

FPDETECT fpDetectBuf;
FPDETECT *fpDetect = &fpDetectBuf;

/*
**  The following functions are wrappers to the pcrm routines,
**  that utilize the variables that we have intialized by
**  calling fpCreateFastPacketDetection().  These functions
**  are also used in the file fpdetect.c, where we do lookups
**  on the initialized variables.
*/
int prmFindRuleGroupIp(int ip_proto, PORT_GROUP **ip_group, PORT_GROUP ** gen)
{
    PORT_GROUP *src;
    return prmFindRuleGroup( prmIpRTNX, ip_proto, -1, &src, ip_group, gen);
}

int prmFindRuleGroupIcmp(int type, PORT_GROUP **type_group, PORT_GROUP ** gen)
{
    PORT_GROUP *src;
    return prmFindRuleGroup( prmIcmpRTNX, type, -1, &src, type_group, gen);
}

int prmFindRuleGroupTcp(int dport, int sport, PORT_GROUP ** src, 
        PORT_GROUP **dst , PORT_GROUP ** gen)
{
    return prmFindRuleGroup( prmTcpRTNX, dport, sport, src, dst , gen);
}

int prmFindRuleGroupUdp(int dport, int sport, PORT_GROUP ** src, 
        PORT_GROUP **dst , PORT_GROUP ** gen)
{
    return prmFindRuleGroup( prmUdpRTNX, dport, sport, src, dst , gen);
}


/*
**  These Otnhas* functions check the otns for different contents.  This
**  helps us decide later what group (uri, content) the otn will go to.
*/
static int OtnHasContent( OptTreeNode * otn ) 
{
    if( !otn ) return 0;
    
    if( otn->ds_list[PLUGIN_PATTERN_MATCH] || otn->ds_list[PLUGIN_PATTERN_MATCH_OR] )
    {
        return 1; 
    }

    return 0;
}

static int OtnHasUriContent( OptTreeNode * otn ) 
{
    if( !otn ) return 0;

    if( otn->ds_list[PLUGIN_PATTERN_MATCH_URI] )
        return 1; 

    return 0;
}

/*
**  
**  NAME
**    CheckPorts::
**
**  DESCRIPTION
**    This function returns the port to use for a given signature.
**    Currently, only signatures that have a unique port (meaning that
**    the port is singular and not a range) are added as specific 
**    ports to the port list.  If there is a range of ports in the
**    signature, then it is added as a generic rule.
**
**    This can be refined at any time, and limiting the number of
**    generic rules would be a good idea.
**
**  FORMAL INPUTS
**    u_short - the high port of the signature range
**    u_short - the low port of the signature range
**
**  FORMAL OUTPUT
**    int - -1 means generic, otherwise it is the port
**
*/
static int CheckPorts(u_short high_port, u_short low_port)
{
    if( high_port == low_port )
    {
       return high_port;
    }
    else
    {
       return -1;
    }
}

/*
**  The following functions deal with the intialization of the 
**  detection engine.  These are set through parser.c with the
**  option 'config detection:'.  This functionality may be 
**  broken out later into it's own file to separate from this
**  file's functionality.
*/

/*
**  Initialize detection options.
*/
int fpInitDetectionEngine()
{
    memset(fpDetect, 0x00, sizeof(*fpDetect));

    /*
    **  We inspect pkts that are going to be rebuilt and
    **  reinjected through snort.
    */
    fpDetect->inspect_stream_insert = 1;
    fpDetect->search_method = MPSE_MWM;
    fpDetect->debug = 0;
    fpDetect->max_queue_events = 5;

    /*
    **  This functions gives fpdetect.c the detection configuration
    **  set up in fpcreate.
    */
    fpSetDetectionOptions(fpDetect);

    return 0;
}

/*
   Search method is set using "config detect: search-method ac | mwm | auto"
*/
int fpSetDetectSearchMethod( char * method )
{
	if( !strcasecmp(method,"ac") )
	{
	   fpDetect->search_method = MPSE_AC ;
	   return 0;
	}

	if( !strcasecmp(method,"mwm") )
	{
	   fpDetect->search_method = MPSE_MWM ;
	   return 0;
	}

	if( !strcasecmp(method,"lowmem") )
	{
	   fpDetect->search_method = MPSE_LOWMEM ;
	   return 0;
	}
    return 1;	
}

/*
**  Set the debug mode for the detection engine.
*/
int fpSetDebugMode()
{
    fpDetect->debug = 1;
    return 0;
}

/*
**  Revert the detection engine back to not inspecting packets
**  that are going to be rebuilt.
*/
int fpSetStreamInsert()
{
    fpDetect->inspect_stream_insert = 0;
    return 0;
}

/*
**  Sets the maximum number of events to queue up in fpdetect before
**  selecting an event.
*/
int fpSetMaxQueueEvents(int iNum)
{
    if(iNum <= 0)
    {
        return 1;
    }

    fpDetect->max_queue_events = iNum;

    return 0;
}

/*
**  Build a Pattern group for the Uri-Content rules in this group
**
**  The patterns added for each rule must be suffcient so if we find any of them
**  we proceed to fully analyze the OTN and RTN against the packet.
**
*/
void BuildMultiPatGroupsUri( PORT_GROUP * pg )
{
    OptTreeNode      *otn;
    RuleTreeNode     *rtn;
    OTNX             *otnx; /* otnx->otn & otnx->rtn */
    PatternMatchData *pmd;
    RULE_NODE        *rnWalk = NULL;
    PMX              *pmx;
    void             *mpse_obj;
    int               method;

    if(!pg || !pg->pgCount)
        return;
      
    /* test for any Content Rules */
    if( !prmGetFirstRuleUri(pg) )
        return;

    method = fpDetect->search_method;
    
    mpse_obj = mpseNew(method);
    MEMASSERT(mpse_obj,"mpse_obj-uricontent");

    /*  
    **  Save the Multi-Pattern data structure for processing Uri's in this 
    **  group later during packet analysis.  
    */
    pg->pgPatDataUri = mpse_obj;
      
    /*
    **  Initialize the BITOP structure for this
    **  port group.  This is most likely going to be initialized
    **  by the non-uri BuildMultiPattGroup.  If for some reason there
    **  is only uri contents in a port group, then we miss the initialization
    **  in the content port groups and catch it here.
    */
    if( boInitBITOP(&(pg->boRuleNodeID),pg->pgCount) )
    {
        return;
    }

    /*
    *  Add in all of the URI contents, since these are effectively OR rules.
    *  
    */
    for( rnWalk=pg->pgUriHead; rnWalk; rnWalk=rnWalk->rnNext)
    {
        otnx = (OTNX *)rnWalk->rnRuleData;

        otn = otnx->otn;
        rtn = otnx->rtn;

        /* Add all of the URI contents */     
        pmd = otn->ds_list[PLUGIN_PATTERN_MATCH_URI];
        while( pmd )
        {
            if(pmd->pattern_buf) 
            {
               pmx = (PMX*)malloc(sizeof(PMX) );
               MEMASSERT(pmx,"pmx-uricontent");
               pmx->RuleNode    = rnWalk;
               pmx->PatternMatchData= pmd;

                mpseAddPattern(mpse_obj, pmd->pattern_buf, pmd->pattern_size,
                pmd->nocase,  /* NoCase: 1-NoCase, 0-Case */
   	        pmd->offset,
                pmd->depth,
                pmx, //(unsigned)rnWalk,        /* rule ptr */ 
                //(unsigned)pmd,
		rnWalk->iRuleNodeID );
            }
            
            pmd = pmd->next;
        }
    }

    /*
    **  This function call sets up an optimized pattern match for Uri
    **  contents.  This only works if the minimum size of a pattern is
    **  2 chars. If we comment this out we use the standard 1 byte bad
    **  character shifts
    */
    mpseLargeShifts( mpse_obj, 1 );
    
    mpsePrepPatterns( mpse_obj );
}

/*
**
**   NAME
**     IsPureNotRule
**
**   DESCRIPTION
**     Checks to see if a rule is a pure not rule.  A pure not rule
**     is a rule that has all "not" contents or Uri contents.
**
**   FORMAL INPUTS
**     PatternMatchData * - the match data to check for not contents.
**
**   FORMAL OUTPUTS
**     int - 1 is rule is a pure not, 0 is rule is not a pure not.
**
*/
static int IsPureNotRule( PatternMatchData * pmd )
{
    int rcnt=0,ncnt=0;

    for( ;pmd; pmd=pmd->next )
    {
        rcnt++;
        if( pmd->exception_flag ) ncnt++;
    }

    if( !rcnt ) return 0;
    
    return ( rcnt == ncnt ) ;  
}

/*
**
**  NAME
**    FindLongestPattern
**
**  DESCRIPTION
**    This functions selects the longest pattern out of a set of
**    patterns per snort rule.  By picking the longest pattern, we
**    help the pattern matcher speed and the selection criteria during
**    detection.
**
**  FORMAL INPUTS
**    PatternMatchData * - contents to select largest
**
**  FORMAL OUTPUTS 
**    PatternMatchData * - ptr to largest pattern
**
*/
static PatternMatchData * FindLongestPattern( PatternMatchData * pmd )
{
    PatternMatchData *pmdmax;
   
    /* Find the 1st pattern that is not a NOT pattern */	   
	while( pmd && pmd->exception_flag ) pmd=pmd->next;
        
	if( !pmd ) return NULL;  /* All Patterns are NOT patterns */
      
        pmdmax = pmd;
	
        while( pmd )
        {
            if(pmd->pattern_buf) 
            {
                if( (pmd->pattern_size > pmdmax->pattern_size) && 
                        !pmd->exception_flag)
                {
                    pmdmax = pmd;
                }
            }
            pmd = pmd->next;
        }
	
	return pmdmax;
}

/*
*  Build Content-Pattern Information for this group
*/
void BuildMultiPatGroup( PORT_GROUP * pg )
{
    OptTreeNode      *otn;
    RuleTreeNode     *rtn;
    OTNX             *otnx; /* otnx->otn & otnx->rtn */
    PatternMatchData *pmd, *pmdmax;
    RULE_NODE        *rnWalk = NULL;
    PMX              *pmx;
    void             *mpse_obj;
    /*int maxpats; */
    int               method;

    if(!pg || !pg->pgCount)
        return;
     
    /* test for any Content Rules */
    if( !prmGetFirstRule(pg) )
        return;
      
    method = fpDetect->search_method;

    mpse_obj = mpseNew( method );
    MEMASSERT(mpse_obj,"mpse_obj-content");

    /* Save the Multi-Pattern data structure for processing this group later 
       during packet analysis.
    */
    pg->pgPatData = mpse_obj;

    /*
    **  Initialize the BITOP structure for this
    **  port group.
    */
    if( boInitBITOP(&(pg->boRuleNodeID),pg->pgCount) )
    {
        return;
    }
      
    /*
    *  For each content rule, add one of the AND contents,
    *  and all of the OR contents
    */
    for(rnWalk=pg->pgHead; rnWalk; rnWalk=rnWalk->rnNext)
    {
        otnx = (OTNX *)(rnWalk->rnRuleData);

        otn = otnx->otn;
        rtn = otnx->rtn;

	/* Add the longest AND patterns, 'content:' patterns*/
        pmd = otn->ds_list[PLUGIN_PATTERN_MATCH];

        /*
        **  Add all the content's for the Pure Not rules, 
        **  because we will check after processing the packet
        **  to see if these pure not rules were hit using the
        **  bitop functionality.  If they were hit, then there
        **  is no event, otherwise there is an event.
        */
        if( pmd && IsPureNotRule( pmd ) )
        {
            /*
            **  Pure Not Rules are not supported.
            */
            LogMessage("SNORT DETECTION ENGINE: Pure Not Rule "
                       "'%s' not added to detection engine.  "
                       "These rules are not supported at this "
                       "time.\n", otn->sigInfo.message);

            while( pmd ) 
            {
                if( pmd->pattern_buf ) 
                {
                    pmx = (PMX*)malloc(sizeof(PMX) );
                    MEMASSERT(pmx,"pmx-!content");
                    pmx->RuleNode   = rnWalk;
                    pmx->PatternMatchData= pmd;

                    mpseAddPattern( mpse_obj, pmd->pattern_buf, 
                      pmd->pattern_size, 
                      pmd->nocase,  /* NoCase: 1-NoCase, 0-Case */
                      pmd->offset, 
                      pmd->depth,
                      pmx,  
                      rnWalk->iRuleNodeID );
                }

                pmd = pmd->next;
            }

            /* Build the list of pure NOT rules for this group */
            prmAddNotNode( pg, (int)rnWalk->iRuleNodeID );
	}
	else
	{
	   /* Add the longest content for normal or mixed contents */
           pmdmax = FindLongestPattern( pmd );  
           if( pmdmax )
           {
               pmx = (PMX*)malloc(sizeof(PMX) );
               MEMASSERT(pmx,"pmx-content");
               pmx->RuleNode    = rnWalk;
               pmx->PatternMatchData= pmdmax;


               mpseAddPattern( mpse_obj, pmdmax->pattern_buf, pmdmax->pattern_size,
                 pmdmax->nocase,  /* NoCase: 1-NoCase, 0-Case */
                 pmdmax->offset, 
                 pmdmax->depth,
                 pmx,  
		 rnWalk->iRuleNodeID );
           }
	}
	   
        /* Add all of the OR contents 'file-list' content */     
        pmd = otn->ds_list[PLUGIN_PATTERN_MATCH_OR];
        while( pmd )
        {
            if(pmd->pattern_buf) 
            {
                pmx = (PMX*)malloc(sizeof(PMX) );
                MEMASSERT(pmx,"pmx-uricontent");
                pmx->RuleNode    = rnWalk;
                pmx->PatternMatchData= pmd;

                mpseAddPattern( mpse_obj, pmd->pattern_buf, pmd->pattern_size,
                pmd->nocase,  /* NoCase: 1-NoCase, 0-Case */
                pmd->offset,
                pmd->depth,
                pmx, //rnWalk,        /* rule ptr */ 
                //(unsigned)pmd,
                rnWalk->iRuleNodeID );
            }

            pmd = pmd->next;
        }
    }

    /*
    **  We don't have PrepLongPatterns here, because we've found that
    **  the minimum length for the BM shift is not fulfilled by snort's
    **  ruleset.  We may add this in later, after initial performance
    **  has been verified.
    */
    
    mpsePrepPatterns( mpse_obj );
}

/*
**
**  NAME
**    BuildMultiPatternGroups::
**
**  DESCRIPTION
**    This is the main function that sets up all the
**    port groups for a given PORT_RULE_MAP.  We iterate
**    through the dst and src ports building up port groups
**    where possible, and then build the generic set.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - the port rule map to build
**
**  FORMAL OUTPUTS
**    None
**
*/
void BuildMultiPatternGroups( PORT_RULE_MAP * prm )
{
    int i;
    PORT_GROUP * pg;
     
    for(i=0;i<MAX_PORTS;i++)
    {
        pg = prmFindSrcRuleGroup( prm, i );
        if(pg)
        {
            BuildMultiPatGroup( pg );
            BuildMultiPatGroupsUri( pg );
        }

        pg = prmFindDstRuleGroup( prm, i );
        if(pg)
        {
            BuildMultiPatGroup( pg );
            BuildMultiPatGroupsUri( pg );
        }
    }

    pg = prm->prmGeneric;
     
    BuildMultiPatGroup( pg );
    BuildMultiPatGroupsUri( pg );
}


/*
**
**  NAME
**    fpCreateFastPacketDetection::
**
**  DESCRIPTION
**    fpCreateFastPacketDetection initializes and creates the whole
**    Faststruct ArgusRecord detection engine.  It reads the list of RTNs and OTNs
**    that snort creates on startup, and adds the RTN/OTN pair for a
**    rule to the appropriate PORT_GROUP.  The routine builds up
**    PORT_RULE_MAPs for TCP, UDP, ICMP, and IP.  More can easily be
**    added if necessary.
**
**    After initialization and setup, stats are printed out about the
**    different PORT_GROUPS.  
**
**  FORMAL INPUTS
**    None
**
**  FORMAL OUTPUTS
**    int - 0 is successful, other is failure.
**
*/
int fpCreateFastPacketDetection()
{
    RuleListNode *rule;
    RuleTreeNode *rtn;
    int sport;
    int dport;
    OptTreeNode * otn;
    int iBiDirectional = 0;

    OTNX * otnx;

    extern RuleListNode *RuleLists;

    prmTcpRTNX = prmNewMap();
    if(prmTcpRTNX == NULL)
        return 1;

    prmUdpRTNX = prmNewMap();
    if(prmUdpRTNX == NULL)
        return 1;

    prmIpRTNX = prmNewMap();
    if(prmIpRTNX == NULL)
        return 1;

    prmIcmpRTNX = prmNewMap();
    if(prmIcmpRTNX == NULL)
        return 1;

    for (rule=RuleLists; rule; rule=rule->next)
    {
        if(!rule->RuleList)
            continue;

        /*
        **  Process TCP signatures
        */
        if(rule->RuleList->TcpList)
        {
            for(rtn = rule->RuleList->TcpList; rtn != NULL; rtn = rtn->right)
            {
#ifdef LOCAL_DEBUG
                printf("** TCP\n");
                printf("** bidirectional = %s\n",
                        (rtn->flags & BIDIRECTIONAL) ? "YES" : "NO");
                printf("** not sp_flag = %d\n", rtn->not_sp_flag);
                printf("** not dp_flag = %d\n", rtn->not_dp_flag);
                printf("** hsp = %u\n", rtn->hsp);
                printf("** lsp = %u\n", rtn->lsp);
                printf("** hdp = %u\n", rtn->hdp);
                printf("** ldp = %u\n\n", rtn->ldp);
#endif
                /*
                **  Check for bi-directional rules
                */
                if(rtn->flags & BIDIRECTIONAL)
                {
                    iBiDirectional = 1;
                }else{
	 	    iBiDirectional = 0;
                }


                sport = CheckPorts(rtn->hsp, rtn->lsp);

                if( rtn->flags & ANY_SRC_PORT ) sport = -1;

                if( sport > 0 &&  rtn->not_sp_flag > 0 )
                {
                    sport = -1;
                }

                dport = CheckPorts(rtn->hdp, rtn->ldp);

                if( rtn->flags & ANY_DST_PORT ) dport = -1;

                if( dport > 0 && rtn->not_dp_flag > 0 )
                {
                    dport = -1;
                }

                /* Walk OTN list -Add as Content/UriContent, or NoContent */
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    otnx = malloc( sizeof(OTNX) );
                    MEMASSERT(otnx,"otnx-TCP");

                    otnx->otn = otn;
                    otnx->rtn = rtn;

                    if( OtnHasContent( otn ) )
                    {
                        if(fpDetect->debug) {
                            printf("TCP Content-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRule(prmTcpRTNX, dport, sport, otnx);

                        if(iBiDirectional)
                        {
                            /*
                            **  We switch the ports.
                            */
                            prmAddRule(prmTcpRTNX, sport, dport, otnx);
                        }
                    }
                    if( OtnHasUriContent( otn ) )
                    {
                        if(fpDetect->debug)
                        {
                            printf("TCP UriContent-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRuleUri(prmTcpRTNX, dport, sport, otnx);

                        if(iBiDirectional)
                        {
                            /*
                            **  We switch the ports.
                            */
                            prmAddRuleUri(prmTcpRTNX, sport, dport, otnx);
                        }
                    }
                    if( !OtnHasContent( otn ) &&  !OtnHasUriContent( otn ) )
                    {
                        if(fpDetect->debug)
                        {
                            printf("TCP NoContent-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRuleNC(prmTcpRTNX, dport, sport, otnx);

                        if(iBiDirectional)
                        {
                            /*
                            **  We switch the ports.
                            */
                            prmAddRuleNC(prmTcpRTNX, sport, dport, otnx);
                        }
                    }
                }
            }
        }

        /*
        **  Process UDP signatures
        */
        if(rule->RuleList->UdpList)
        {
            for(rtn = rule->RuleList->UdpList; rtn != NULL; rtn = rtn->right)
            {
#ifdef LOCAL_DEBUG
                printf("** UDP\n");
                printf("** bidirectional = %s\n",
                        (rtn->flags & BIDIRECTIONAL) ? "YES" : "NO");
                printf("** not sp_flag = %d\n", rtn->not_sp_flag);
                printf("** not dp_flag = %d\n", rtn->not_dp_flag);
                printf("** hsp = %u\n", rtn->hsp);
                printf("** lsp = %u\n", rtn->lsp);
                printf("** hdp = %u\n", rtn->hdp);
                printf("** ldp = %u\n\n", rtn->ldp);
#endif
                /*
                **  Check for bi-directional rules
                */
		if(rtn->flags & BIDIRECTIONAL)
                {
                    iBiDirectional = 1;
                }else{
	 	    iBiDirectional = 0;
                }

                sport = CheckPorts(rtn->hsp, rtn->lsp);

                if( rtn->flags & ANY_SRC_PORT ) sport = -1;

                if(sport > 0 &&  rtn->not_sp_flag > 0 )
                {
                    sport = -1;
                }

                dport = CheckPorts(rtn->hdp, rtn->ldp);

                if( rtn->flags & ANY_DST_PORT ) dport = -1;


                if(dport > 0 && rtn->not_dp_flag > 0 )
                {
                    dport = -1;
                }

                /* Walk OTN list -Add as Content, or NoContent */
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    otnx = malloc( sizeof(OTNX) );
                    MEMASSERT(otnx,"otnx-UDP");

                    otnx->otn = otn;
                    otnx->rtn = rtn;

                    if( OtnHasContent( otn ) )
                    {
                        if(fpDetect->debug)
                        {
                            printf("UDP Content-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRule(prmUdpRTNX, dport, sport, otnx);

                        /*
                        **  If rule is bi-directional we switch
                        **  the ports.
                        */
                        if(iBiDirectional)
                        {
                            prmAddRule(prmUdpRTNX, sport, dport, otnx);
                        }
                    }
                    else
                    {
                        if(fpDetect->debug)
                        {
			                printf("UDP NoContent-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRuleNC(prmUdpRTNX, dport, sport, otnx);

                        /*
                        **  If rule is bi-directional we switch
                        **  the ports.
                        */
                        if(iBiDirectional)
                        {
                            prmAddRuleNC(prmUdpRTNX, sport, dport, otnx);
                        }
                    }
                }
            }
        }

        /*
        **  Process ICMP signatures
        */
        if(rule->RuleList->IcmpList)
        {
            for(rtn = rule->RuleList->IcmpList; rtn != NULL; rtn = rtn->right)
            {
               /* Walk OTN list -Add as Content, or NoContent */
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    int type;
                    IcmpTypeCheckData * IcmpType;

                    otnx = malloc( sizeof(OTNX) );
                    MEMASSERT(otnx,"otnx-ICMP");

                    otnx->otn = otn;
                    otnx->rtn = rtn;
	            
		    IcmpType = (IcmpTypeCheckData *)otn->ds_list[PLUGIN_ICMP_TYPE];
                    if( IcmpType && (IcmpType->operator == ICMP_TYPE_TEST_EQ) )
                    {
                        type = IcmpType->icmp_type;
                    }
                    else
                    {
                        type = -1;
                    }

                    if( OtnHasContent( otn ) )
                    {
                        if(fpDetect->debug)
                        {
                            printf("ICMP Type=%d Content-Rule  %s\n",
                                    type,otn->sigInfo.message);
                        }
                        prmAddRule(prmIcmpRTNX, type, -1, otnx);
                    }
                    else
                    {
                        if(fpDetect->debug)
                        {
                            printf("ICMP Type=%d NoContent-Rule  %s\n",
                                    type,otn->sigInfo.message);
                        }
                        prmAddRuleNC(prmIcmpRTNX, type, -1, otnx);
                    }
                }
            }
        }

        /*
        **  Process IP signatures
        **
        **  NOTE:
        **  We may want to revisit this and add IP rules for TCP and
        **  UDP into the right port groups using the rule ports, instead
        **  of just using the generic port.
        */
        if(rule->RuleList->IpList)
        {
            for(rtn = rule->RuleList->IpList; rtn != NULL; rtn = rtn->right)
            {
                /* Walk OTN list -Add as Content, or NoContent */
                for( otn=rtn->down; otn; otn=otn->next )
                {
                    IpProtoData * IpProto;
                    int protocol;
		    
                    otnx = malloc( sizeof(OTNX) );
                    MEMASSERT(otnx,"otnx-IP");

                    otnx->otn = otn;
                    otnx->rtn = rtn;

                    IpProto =  
                        (IpProtoData *)otn->ds_list[PLUGIN_IP_PROTO_CHECK] ;

                    if( IpProto )
                    {
                        protocol = IpProto->protocol;
                        if( IpProto->comparison_flag == GREATER_THAN )
                            protocol=-1; 
                        
                        if( IpProto->comparison_flag == LESS_THAN )
                            protocol=-1; 

                        if( IpProto->not_flag )
                            protocol=-1;
                    }
                    else
                    {
                        protocol = -1;
                    }
		    
                    if( OtnHasContent( otn ) )
                    {
                        if(fpDetect->debug)
                        {
                            printf("IP Proto=%d Content-Rule %s\n",
                                    protocol,otn->sigInfo.message);
                        }
                        prmAddRule(prmIpRTNX, protocol, -1, otnx);

                        if(protocol == IPPROTO_TCP || protocol == -1)
                        {
                            prmAddRule(prmTcpRTNX, -1, -1, otnx);
                        }
                        
                        if(protocol == IPPROTO_UDP || protocol == -1)
                        {
                            prmAddRule(prmUdpRTNX, -1, -1, otnx);
                        }

                        if(protocol == IPPROTO_ICMP || protocol == -1)
                        {
                            prmAddRule(prmIcmpRTNX, -1, -1, otnx);
                        }
                    }
                    else
                    {
                        if(fpDetect->debug)
                        {
                            printf("IP Proto=%d NoContent-Rule %s\n",
                                    protocol,otn->sigInfo.message);
                        }
                        prmAddRuleNC(prmIpRTNX, protocol, -1, otnx);

                        if(protocol == IPPROTO_TCP || protocol == -1)
                        {
                            prmAddRuleNC(prmTcpRTNX, -1, -1, otnx);
                        }
                        
                        if(protocol == IPPROTO_UDP || protocol == -1)
                        {
                            prmAddRuleNC(prmUdpRTNX, -1, -1, otnx);
                        }

                        if(protocol == IPPROTO_ICMP || protocol == -1)
                        {
                            prmAddRuleNC(prmIcmpRTNX, -1, -1, otnx);
                        }
                    }
                }
            }
        }
    }

    prmCompileGroups(prmTcpRTNX);
    prmCompileGroups(prmUdpRTNX);
    prmCompileGroups(prmIcmpRTNX);
    prmCompileGroups(prmIpRTNX);

    BuildMultiPatternGroups(prmTcpRTNX);
    BuildMultiPatternGroups(prmUdpRTNX);
    BuildMultiPatternGroups(prmIcmpRTNX);
    BuildMultiPatternGroups(prmIpRTNX);

    if(fpDetect->debug)
    {
        printf("\n** TCP Rule Group Stats -- ");
        prmShowStats(prmTcpRTNX);
    
        printf("\n** UDP Rule Group Stats -- ");
        prmShowStats(prmUdpRTNX);
    
        printf("\n** ICMP Rule Group Stats -- ");
        prmShowStats(prmIcmpRTNX);
    
        printf("\n** IP Rule Group Stats -- ");
        prmShowStats(prmIpRTNX);
    }

    return 0;
}

/*
**  Wrapper for prmShowEventStats
*/
int fpShowEventStats()
{
    /*
    **  If not debug, then we don't print anything.
    */
    if(!fpDetect->debug)
    {
        return 1;
    }

    printf("\n** TCP Event Stats -- ");  prmShowEventStats(prmTcpRTNX);
    printf("\n** UDP Event Stats -- ");  prmShowEventStats(prmUdpRTNX);
    printf("\n** ICMP Event Stats -- "); prmShowEventStats(prmIcmpRTNX);
    printf("\n** IP Event Stats -- ");    prmShowEventStats(prmIpRTNX);
    return 0;
}
   



/*
**  $Id: parser.c,v 1.3 2004/05/14 15:44:35 qosient Exp $
**
**  pcrm.c
**
**  Copyright (C) 2002 Sourcefire,Inc
**  Marc Norton <mnorton@sourcefire.com>
**  Dan Roelker <droelker@sourcefire.com>
**
**  NOTES
**  5.15.02   - Initial version of pcrm.c distributed. - Norton/Roelker
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/*
** 
**  struct ArgusRecord Classificationa and Rule Manager
**
**
**  A Fast struct ArgusRecord Classification method for Rule and Pattern Matching in SNORT
**  --------------------------------------------------------------------------
**
**  A simple method for grouping rules into lists and looking them up quickly 
**  in realtime. 
**
**  There is a natural problem when aggregating rules into pattern groups for 
**  performing multi-pattern matching not seen with single pattern Boyer-Moore 
**  strategies.  The problem is how to group the rules efficiently when 
**  considering that there are multiple parameters which govern what rules to
**  apply to each packet or connection. The paramters, sip, dip, sport, dport,
**  and flags form an enormous address space of possible packets that
**  must be tested in realtime against a subset of rule patterns. Methods to 
**  group patterns precisely based on all of these parameters can quickly 
**  become complicated by both algorithmic implications and implementation 
**  details.  The procedure described herein is quick and simple.
**
**  The methodology presented here to solve this problem is based on the 
**  premise that we can use the source and destination ports to isolate 
**  pattern groups for pattern matching, and rely on an event validation 
**  procedure to authenticate other parameters such as sip, dip and flags after 
**  a pattern match is made. An instrinsic assumption here is that most sip 
**  and dip values will be acceptable and that the big gain in performance 
**  is due to the fact that by isolating traffic based on services (ports) 
**  we gain the most benefit.  Additionally, and just as important, is the
**  requirement that we can perform a multi-pattern recognition-inspection phase
**  on a large set of patterns many times quicker than we can apply a single 
**  pattern test against many single patterns.
**
**  The current implementation assumes that for each rule the src and dst ports
**  each have one of 2 possible values.  Either a specific port number or the 
**  ANYPORT designation. This does allow us to handle port ranges, and NOT port
**  rules as well.
**
**  We make the following assumptions about classifying packets based on ports:
**
**    1) There are Unique ports which represent special sevices.  For example,
**       ports 21,25,80,110,etc.
**
**    2) Patterns can be grouped into Unique Pattern groups, and a Generic 
**       Pattern Group
**       a) Unique pattern groups exist for source ports 21,25,80,110,etc.
**       b) Unique pattern groups exist for destination ports 21,25,80,etc.
**       c) A Generic pattern group exists for rules applied to every 
**          combination of source and destination ports.
**   
**  We make the following assumptions about packet traffic:
**  
**    1) Well behaved traffic has one Unique port and one ephemeral port for 
**       most packets and sometimes legitmately, as in the case of  DNS, has 
**       two unique ports that are the same. But we always determine that 
**       packets with two different but Unique ports is bogus, and should 
**       generate an alert.  For example, if you have traffic going from
**       port 80 to port 20.
**    
**    2) In fact, state could tell us which side of this connection is a 
**       service and which side is a client. Than we could handle this packet 
**       more precisely, but this is a rare situation and is still bogus. We 
**       can choose not to do pattern inspections on these packets, or to do
**       complete inspections.
**
**  Rules are placed into each group as follows:
**    
**    1) Src Port == Unique Service, Dst Port == ANY -> Unique Src Port Table
**       Src Port == Unique Service, Dst Port == 
**       Unique -> Unique Src & Dst Port Tables
**    2) Dst Port == Unqiue Service, Src Port == ANY -> Unique Dst Port Table
**       Dst Port == Unqiue Service, Src Port == 
**       Unique -> Unique Dst & Src Port Tables
**    3) Dst Port == ANY, Src Port == ANY -> Generic Rule Set, 
**       And add to all Unique Src/Dst Rule Sets that have entries 
**    4) !Dst or !Src Port is the same as ANY Dst or ANY Src port respectively
**    5) DstA:DstB is treated as an ANY port group, same for SrcA:SrcB
**  
**  Initialization
**  --------------
**  For each rule check the dst-port, if it's specific, than add it to the 
**  dst table.  If the dst-port is Any port, than do not add it to the dst 
**  port table. Repeat this for the src-port.
**
**  If the rule has Any for both ports than it's added generic rule list.
**
**  Also, fill in the Unique-Conflicts array, this indicates if it's OK to have
**  the same Unique service port for both destination and source. This will 
**  force an alert if it's not ok.  We optionally, pattern match against this
**  anyways.
**
**  Procsessing Rules
**  -----------------
**  When packets arrive:
**
**   Categorize the Port Uniqueness:
**   
**   a)Check the DstPort[DstPort] for possible rules, 
**     if no entry than no rules exist for this packet with this destination.
**
**   b)Check the SrcPort[SrcPort] for possible rules, 
**     if no entry than no rules exist for this packet with this source.
**     
**   Process the Uniqueness:
**     
**   If a AND !b has rules or !a AND b has rules than 
**      match agaionst those rules
**   
**   If a AND b has rules than 
**      if( sourcePort != DstPort ) 
**         Alert on this traffic, and optionally match both rule sets
**      else if( SourcePort == DstPort ) 
**         Check the Unique-Conflicts array for allowable conflicts
**             if( NOT allowed ) 
**	       Alert on this traffic, optionally match the rules
**	    else 
**	       match both sets of tules against this traffic
**  
**   If( !a AND ! b )  than
**      Pattern Match against the Generic Rules ( these apply to all packets)
** 
**
**  example.c
**  ---------
**
**   PORT_RULE_MAP * prm;
**   PORT_GROUP  *src, *dst, *generic;
**
**   RULE * prule; //user defined rule structure for user rules
**
**   prm = prmNewMap();
**
**   for( each rule )
**   {
**      prule = ....get a rule pointer
**
**      prmAddRule( prm, prule->dport, prule->sport, prule );
**   }
**
**   prmCompileGroups( prm );
** 
**   while( sniff-packets )
**   {
**      ....
**
**      stat = prmFindRuleGroup( prm, dport, sport, &src, &dst, &generic );
**      switch( stat )
**      {
**         case 0:  // No rules at all
**          break;
**         case 1:  // Dst Rules
**           // pass 'dst->pgPatData', 'dst->pgPatDataUri' to the pattern engine
**          break;
**         case 2:  // Src Rules
**           // pass 'src->pgPatData', 'src->pgPatDataUri' to the pattern engine
**          break;
**         case 3:  // Src/Dst Rules - Both ports represent Unique service ports
**           // pass 'src->pgPatData' ,'src->pgPatDataUri' to the pattern engine
**           // pass 'dst->pgPatData'  'src->pgPatDataUri' to the pattern engine
**          break;
**         case 4:  // Generic Rules Only
**           // pass 'generic->pgPatData' to the pattern engine
**           // pass 'generic->pgPatDataUri' to the pattern engine
**          break;
**      }
**   }
**
*/

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcrm.h"

/*
** 
**  NAME
**    prmNewMap::
**
**  DESCRIPTION
**    Allocate new PORT_RULE_MAP and return pointer.
**
**  FORMAL INPUTS
**    None
**
**  FORMAL OUTPUT
**    PORT_RULE_MAP * - NULL if failed, ptr otherwise.
**
*/
PORT_RULE_MAP * prmNewMap( )
{
    PORT_RULE_MAP * p;

    p = (PORT_RULE_MAP *)calloc(1, sizeof(PORT_RULE_MAP) );

    return p;
}

/*
** 
**  NAME
**    prmNewByteMap::
**
**  DESCRIPTION
**    Allocate new BYTE_RULE_MAP and return pointer.
**
**  FORMAL INPUTS
**    None
**
**  FORMAL OUTPUT
**    BYTE_RULE_MAP * - NULL if failed, ptr otherwise.
**
*/
BYTE_RULE_MAP * prmNewByteMap( )
{
    BYTE_RULE_MAP * p;

    p = (BYTE_RULE_MAP *)calloc(1, sizeof(BYTE_RULE_MAP) );

    return p;
}


/*
**
**  NAME
**    prmxFreeGroup::
**
**  DESCRIPTION
**    Frees a PORT_GROUP of it's RuleNodes.
**
**  FORMAL INPUTS
**    PORT_GROUP * - port group to free
**
**  FORMAL OUTPUT
**    None
**
*/
static void prmxFreeGroup(PORT_GROUP *pg)
{
     RULE_NODE * rn, *rx;

     rn = pg->pgHead;

     while( rn )
     {
       rx = rn->rnNext;       
       free( rn ); 
       rn = rx;
     }         
}

/*
**
**  NAME
**    prmFreeMap
**
**  DESCRIPTION
**    Frees the memory utilized by a PORT_RULE_MAP.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - PORT_RULE_MAP to free
**
**  FORMAL OUTPUT
**    None
** 
*/
void prmFreeMap( PORT_RULE_MAP * p )
{
     int i;

     if( p )
     {
       for(i=0;i<MAX_PORTS;i++)
       {
           if(p->prmSrcPort[i])
           {
               prmxFreeGroup( p->prmSrcPort[i] );     
               free(p->prmSrcPort[i]);
           }
       }

       for(i=0;i<MAX_PORTS;i++)
       {
           if(p->prmDstPort[i])
           {
               prmxFreeGroup( p->prmDstPort[i] );     
               free(p->prmDstPort[i]);
           }
       }

       if(p->prmGeneric)
       {
           prmxFreeGroup( p->prmGeneric );     
           free(p->prmGeneric);
       }

       free( p ); 
     }
}

/*
**
**  NAME
**    prmFreeByteMap
**
**  DESCRIPTION
**    Frees the memory utilized by a BYTE_RULE_MAP.
**
**  FORMAL INPUTS
**    BYTE_RULE_MAP * - BYTE_RULE_MAP to free
**
**  FORMAL OUTPUT
**    None
** 
*/
void prmFreeByteMap( BYTE_RULE_MAP * p )
{
     int i;

     if( p )
     {
       for(i=0;i<256;i++)
       {
          prmxFreeGroup( &p->prmByteGroup[i] );     
       }

       prmxFreeGroup( &p->prmGeneric );     

       free( p ); 
     }
}

/*
**
**  NAME
**    prmxAddPortRule::
**
**  DESCRIPTION
**    Adds a RULE_NODE to a PORT_GROUP.  This particular
**    function is specific in that it adds "content" rules.
**    A "content" rule is a snort rule that has a content
**    flag.
**
**    Each RULE_NODE in a PORT_GROUP is given a RULE_NODE
**    ID.  This allows us to track particulars as to what
**    rules have been alerted upon, and allows other neat
**    things like correlating events on different streams.
**    The RULE_NODE IDs may not be consecutive, because
**    we can add RULE_NODES into "content", "uri", and
**    "no content" lists.  
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to add the rule to.
**    RULE_PTR - void ptr to the user information
**
**  FORMAL OUTPUT
**    int - 0 is successful, 1 is failure
**
*/
static int prmxAddPortRule( PORT_GROUP *p, RULE_PTR rd )
{
    if( !p->pgHead )
    {
         p->pgHead = (RULE_NODE*) malloc( sizeof(RULE_NODE) );
         if( !p->pgHead )return 1;
	 
         p->pgHead->rnNext      = 0;
         p->pgHead->rnRuleData  = rd;
         p->pgTail              = p->pgHead;
    }
    else
    {
         p->pgTail->rnNext = (RULE_NODE*)malloc( sizeof(RULE_NODE) );
         if(!p->pgTail->rnNext)return 1;
	 
         p->pgTail             = p->pgTail->rnNext;
         p->pgTail->rnNext     = 0;
         p->pgTail->rnRuleData = rd;
    }

    /*
    **  Set RULE_NODE ID to unique identifier
    */
    p->pgTail->iRuleNodeID = p->pgCount;
   
    /*
    **  Update the total Rule Node Count for this PORT_GROUP
    */
    p->pgCount++;  
    
    p->pgContentCount++;

    return 0;
}

/*
**
**  NAME
**    prmxAddPortRuleUri::
**
**  DESCRIPTION
**    Adds a RULE_NODE to a PORT_GROUP.  This particular
**    function is specific in that it adds "uri" rules.
**    A "uri" rule is a snort rule that has a uri
**    flag.
**
**    Each RULE_NODE in a PORT_GROUP is given a RULE_NODE
**    ID.  This allows us to track particulars as to what
**    rules have been alerted upon, and allows other neat
**    things like correlating events on different streams.
**    The RULE_NODE IDs may not be consecutive, because
**    we can add RULE_NODES into "content", "uri", and
**    "no content" lists.  
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to add the rule to.
**    RULE_PTR - void ptr to the user information
**
**  FORMAL OUTPUT
**    int - 0 is successful, 1 is failure
**
*/
static int prmxAddPortRuleUri( PORT_GROUP *p, RULE_PTR rd )
{
    if( !p->pgUriHead )
    {
         p->pgUriHead = (RULE_NODE*) malloc( sizeof(RULE_NODE) );
         if( !p->pgUriHead ) return 1;
	 
         p->pgUriTail              = p->pgUriHead;
         p->pgUriHead->rnNext      = 0;
         p->pgUriHead->rnRuleData  = rd;
    }
    else
    {
         p->pgUriTail->rnNext = (RULE_NODE*)malloc( sizeof(RULE_NODE) );
         if( !p->pgUriTail->rnNext) return 1;
	 
         p->pgUriTail             = p->pgUriTail->rnNext;
         p->pgUriTail->rnNext     = 0;
         p->pgUriTail->rnRuleData = rd;
    }

    /*
    **  Set RULE_NODE ID to unique identifier
    */
    p->pgUriTail->iRuleNodeID = p->pgCount;
   
    /*
    **  Update the total Rule Node Count for this PORT_GROUP
    */
    p->pgCount++; 

    p->pgUriContentCount++;

    return 0;
}

/*
**
**  NAME
**    prmxAddPortRuleNC::
**
**  DESCRIPTION
**    Adds a RULE_NODE to a PORT_GROUP.  This particular
**    function is specific in that it adds "no content" rules.
**    A "no content" rule is a snort rule that has no "content"
**    or "uri" flag, and hence does not need to be pattern
**    matched.
**
**    Each RULE_NODE in a PORT_GROUP is given a RULE_NODE
**    ID.  This allows us to track particulars as to what
**    rules have been alerted upon, and allows other neat
**    things like correlating events on different streams.
**    The RULE_NODE IDs may not be consecutive, because
**    we can add RULE_NODES into "content", "uri", and
**    "no content" lists.  
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to add the rule to.
**    RULE_PTR - void ptr to the user information
**
**  FORMAL OUTPUT
**    int - 0 is successful, 1 is failure
**
*/
static int prmxAddPortRuleNC( PORT_GROUP *p, RULE_PTR rd )
{
    if( !p->pgHeadNC )
    {
         p->pgHeadNC = (RULE_NODE*) malloc( sizeof(RULE_NODE) );
         if( !p->pgHeadNC )return 1;
	 
         p->pgTailNC             = p->pgHeadNC;
         p->pgHeadNC->rnNext     = 0;
         p->pgHeadNC->rnRuleData = rd;
    }
    else
    {
         p->pgTailNC->rnNext = (RULE_NODE*)malloc( sizeof(RULE_NODE) );
         if(!p->pgTailNC->rnNext)return 1;
	 
         p->pgTailNC             = p->pgTailNC->rnNext;
         p->pgTailNC->rnNext     = 0;
         p->pgTailNC->rnRuleData = rd;
    }

    /*
    **  Set RULE_NODE ID to unique identifier
    */
    p->pgTailNC->iRuleNodeID = p->pgCount;
   
    /*
    **  Update the Total Rule Node Count for this PORT_GROUP
    */
    p->pgCount++; 

    p->pgNoContentCount++;

    return 0;
}

/*
**
**  NAME
**    prmAddNotNode::
**
**  DESCRIPTION
**    NOT SUPPORTED YET.  Build a list of pur NOT nodes i.e. content !"this" 
**    content:!"that".
**
*/
void prmAddNotNode( PORT_GROUP * pg, int id )
{
    NOT_RULE_NODE * p = malloc(sizeof( NOT_RULE_NODE));

    if( !p ) return ;
    
    p->iPos = id;
    
    if( !pg->pgNotRuleList )
    {
       pg->pgNotRuleList = p;
       p->next = 0;
    }
    else
    {
       p->next = pg->pgNotRuleList;
       pg->pgNotRuleList = p;
    }
}


/*
**
**  NAME
**    prmGetFirstRule::
**
**  DESCRIPTION
**    This function returns the first rule user data in
**    the "content" list of a PORT_GROUP.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to retrieve data from.
**
**  FORMAL OUTPUT
**    RULE_PTR - the ptr to the user data.
**    
*/
RULE_PTR prmGetFirstRule( PORT_GROUP * pg )
{
    pg->pgCur = pg->pgHead;
    
    if( !pg->pgCur ) 
        return 0;
     
    return pg->pgCur->rnRuleData;
}  

/*
**
**  NAME
**    prmGetNextRule::
**
**  DESCRIPTION
**    Gets the next "content" rule.  This function allows easy
**    walking of the "content" rule list.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to retrieve data from.
**
**  FORMAL OUTPUT
**    RULE_PTR - ptr to the user data
**    
*/
RULE_PTR prmGetNextRule( PORT_GROUP * pg )
{
    if( pg->pgCur ) 
        pg->pgCur = pg->pgCur->rnNext;
     
    if( !pg->pgCur ) 
        return 0;
    
    return pg->pgCur->rnRuleData;
}

/*
**
**  NAME
**    prmGetFirstRuleUri::
**
**  DESCRIPTION
**    This function returns the first rule user data in
**    the "uri" list of a PORT_GROUP.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to retrieve data from.
**
**  FORMAL OUTPUT
**    RULE_PTR - the ptr to the user data.
**    
*/
RULE_PTR prmGetFirstRuleUri( PORT_GROUP * pg )
{
    pg->pgUriCur = pg->pgUriHead;
    
    if( !pg->pgUriCur ) 
        return 0;
     
    return pg->pgUriCur->rnRuleData;
}  

/*
**
**  NAME
**    prmGetNextRuleUri::
**
**  DESCRIPTION
**    Gets the next "uri" rule.  This function allows easy
**    walking of the "uri" rule list.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to retrieve data from.
**
**  FORMAL OUTPUT
**    RULE_PTR - ptr to the user data
**    
*/
RULE_PTR prmGetNextRuleUri( PORT_GROUP * pg )
{
    if( pg->pgUriCur ) 
        pg->pgUriCur = pg->pgUriCur->rnNext;
     
    if( !pg->pgUriCur ) 
        return 0;
    
    return pg->pgUriCur->rnRuleData;
}  

/*
**
**  NAME
**    prmGetFirstRuleNC::
**
**  DESCRIPTION
**    This function returns the first rule user data in
**    the "no content" list of a PORT_GROUP.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to retrieve data from.
**
**  FORMAL OUTPUT
**    RULE_PTR - the ptr to the user data.
**    
*/
RULE_PTR prmGetFirstRuleNC( PORT_GROUP * pg )
{
    pg->pgCurNC = pg->pgHeadNC;
    
    if( !pg->pgCurNC ) 
        return 0;
     
    return pg->pgCurNC->rnRuleData;
}  

/*
**
**  NAME
**    prmGetNextRuleNC::
**
**  DESCRIPTION
**    Gets the next "no content" rule.  This function allows easy
**    walking of the "no content" rule list.
**
**  FORMAL INPUTS
**    PORT_GROUP * - PORT_GROUP to retrieve data from.
**
**  FORMAL OUTPUT
**    RULE_PTR - ptr to the user data
**    
*/
RULE_PTR prmGetNextRuleNC( PORT_GROUP * pg )
{
    if( pg->pgCurNC ) 
        pg->pgCurNC = pg->pgCurNC->rnNext;
     
    if( !pg->pgCurNC ) 
        return 0;
    
    return pg->pgCurNC->rnRuleData;
}  

/*
**
**  NAME
**    prmAddRule::
**
**  DESCRIPTION
**    This function adds a rule to a PORT_RULE_MAP.  Depending on the
**    values of the sport and dport, the rule gets added in different
**    groups (src,dst,generic).  The values for dport and sport
**    can be: 0 -> 64K or -1 for generic (meaning that the rule applies
**    to all values.
**
**    Warning: Consider this carefully.
**    Some rules use 6000:6005 -> any  for a port designation, we could
**    add each rule to it's own group, in this case Src=6000 to 6005.
**    But we opt to add them as ANY rules for now, to reduce groups.
**
**    IMPORTANT:
**    This function adds a rule to the "content" list of rules.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - PORT_RULE_MAP to add rule to.
**    int - the dst port value.
**    int - the src port value.
**    RULE_PTR - the ptr to the user data for the rule.
**
**  FORMAL OUTPUT
**    int - 0 is successful, 1 is failure.
**  
*/
int prmAddRule( PORT_RULE_MAP * p, int dport, int sport, RULE_PTR rd )
{
    if( dport != ANYPORT && dport < MAX_PORTS )  /* dst=21,25,80,110,139 */
    {
       p->prmNumDstRules++;

       /*
       **  Check to see if this PORT_GROUP has been initialized
       */
       if(p->prmDstPort[dport] == NULL)
       {
           p->prmDstPort[dport] = (PORT_GROUP *)calloc(1, sizeof(PORT_GROUP));
           if(p->prmDstPort[dport] == NULL)
           {
               return 1;
           }
       }

       if(p->prmDstPort[dport]->pgCount==0) p->prmNumDstGroups++;

       prmxAddPortRule( p->prmDstPort[ dport ], rd );
    }
    
    if( sport != ANYPORT && sport < MAX_PORTS) /* src=ANY, SRC=80,21,25,etc. */
    {
       p->prmNumSrcRules++;

       /*
       **  Check to see if this PORT_GROUP has been initialized
       */
       if(p->prmSrcPort[sport] == NULL)
       {
           p->prmSrcPort[sport] = (PORT_GROUP *)calloc(1, sizeof(PORT_GROUP));
           if(p->prmSrcPort[sport] == NULL)
           {
               return 1;
           }
       }

       if(p->prmSrcPort[sport]->pgCount==0) p->prmNumSrcGroups++;

       prmxAddPortRule( p->prmSrcPort[ sport ], rd );
    }
    
    if( sport == ANYPORT && dport == ANYPORT) /* dst=ANY, src=ANY */
    {
       p->prmNumGenericRules++;

       /*
       **  Check to see if this PORT_GROUP has been initialized
       */
       if(p->prmGeneric == NULL)
       {
           p->prmGeneric = (PORT_GROUP *)calloc(1, sizeof(PORT_GROUP));
           if(p->prmGeneric == NULL)
           {
               return 1;
           }
       }

       prmxAddPortRule( p->prmGeneric, rd );
    }

  return 0;
}

int prmAddByteRule( BYTE_RULE_MAP * p, int dport, RULE_PTR rd )
{
    if( dport != ANYPORT && dport < 256 )  /* dst=21,25,80,110,139 */
    {
       p->prmNumRules++;
       if( p->prmByteGroup[dport].pgCount==0 ) p->prmNumGroups++;

       prmxAddPortRule( &(p->prmByteGroup[ dport ]), rd );
    }
    
    else if( dport == ANYPORT ) /* dst=ANY, src=ANY */
    {
       p->prmNumGenericRules++;

       prmxAddPortRule( &(p->prmGeneric), rd );
    }

  return 0;
}

/*
**
**  NAME
**    prmAddRuleUri::
**
**  DESCRIPTION
**    This function adds a rule to a PORT_RULE_MAP.  Depending on the
**    values of the sport and dport, the rule gets added in different
**    groups (src,dst,generic).  The values for dport and sport
**    can be: 0 -> 64K or -1 for generic (meaning that the rule applies
**    to all values.
**
**    Warning: Consider this carefully.
**    Some rules use 6000:6005 -> any  for a port designation, we could
**    add each rule to it's own group, in this case Src=6000 to 6005.
**    But we opt to add them as ANY rules for now, to reduce groups.
**
**    IMPORTANT:
**    This function adds a rule to the "uri" list of rules.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - PORT_RULE_MAP to add rule to.
**    int - the dst port value.
**    int - the src port value.
**    RULE_PTR - the ptr to the user data for the rule.
**
**  FORMAL OUTPUT
**    int - 0 is successful, 1 is failure.
**  
*/
int prmAddRuleUri( PORT_RULE_MAP * p, int dport, int sport, RULE_PTR rd )
{
    if( dport != ANYPORT && dport < MAX_PORTS )  /* dst=21,25,80,110,139 */
    {
       p->prmNumDstRules++;

       /*
       **  Check to see if this PORT_GROUP has been initialized
       */
       if(p->prmDstPort[dport] == NULL)
       {
           p->prmDstPort[dport] = (PORT_GROUP *)calloc(1, sizeof(PORT_GROUP));
           if(p->prmDstPort[dport] == NULL)
           {
               return 1;
           }
       }

       if(p->prmDstPort[dport]->pgCount==0) p->prmNumDstGroups++;

       prmxAddPortRuleUri( p->prmDstPort[ dport ], rd );
    }
    
    if( sport != ANYPORT && sport < MAX_PORTS) /* src=ANY, SRC=80,21,25,etc. */
    {
       p->prmNumSrcRules++;

       /*
       **  Check to see if this PORT_GROUP has been initialized
       */
       if(p->prmSrcPort[sport] == NULL)
       {
           p->prmSrcPort[sport] = (PORT_GROUP *)calloc(1, sizeof(PORT_GROUP));
           if(p->prmSrcPort[sport] == NULL)
           {
               return 1;
           }
       }

       if(p->prmSrcPort[sport]->pgCount==0) p->prmNumSrcGroups++;

       prmxAddPortRuleUri( p->prmSrcPort[ sport ], rd );
    }
    
    if( sport == ANYPORT && dport == ANYPORT) /* dst=ANY, src=ANY */
    {
       p->prmNumGenericRules++;

       /*
       **  Check to see if this PORT_GROUP has been initialized
       */
       if(p->prmGeneric == NULL)
       {
           p->prmGeneric = (PORT_GROUP *)calloc(1, sizeof(PORT_GROUP));
           if(p->prmGeneric == NULL)
           {
               return 1;
           }
       }

       prmxAddPortRuleUri( p->prmGeneric, rd );
    }

  return 0;
}

/*
**
**  NAME
**    prmAddRuleNC::
**
**  DESCRIPTION
**    This function adds a rule to a PORT_RULE_MAP.  Depending on the
**    values of the sport and dport, the rule gets added in different
**    groups (src,dst,generic).  The values for dport and sport
**    can be: 0 -> 64K or -1 for generic (meaning that the rule applies
**    to all values.
**
**    Warning: Consider this carefully.
**    Some rules use 6000:6005 -> any  for a port designation, we could
**    add each rule to it's own group, in this case Src=6000 to 6005.
**    But we opt to add them as ANY rules for now, to reduce groups.
**
**    IMPORTANT:
**    This function adds a rule to the "no content" list of rules.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - PORT_RULE_MAP to add rule to.
**    int - the dst port value.
**    int - the src port value.
**    RULE_PTR - the ptr to the user data for the rule.
**
**  FORMAL OUTPUT
**    int - 0 is successful, 1 is failure.
**  
*/
int prmAddRuleNC( PORT_RULE_MAP * p, int dport, int sport, RULE_PTR rd )
{
    if( dport != ANYPORT && dport < MAX_PORTS )  /* dst=21,25,80,110,139 */
    {
       p->prmNumDstRules++;

       /*
       **  Check to see if this PORT_GROUP has been initialized
       */
       if(p->prmDstPort[dport] == NULL)
       {
           p->prmDstPort[dport] = (PORT_GROUP *)calloc(1, sizeof(PORT_GROUP));
           if(p->prmDstPort[dport] == NULL)
           {
               return 1;
           }
       }

       if(p->prmDstPort[dport]->pgCount==0) p->prmNumDstGroups++;

       prmxAddPortRuleNC( p->prmDstPort[ dport ], rd );
    }
    
    if( sport != ANYPORT && sport < MAX_PORTS) /* src=ANY, SRC=80,21,25,etc. */
    {
       p->prmNumSrcRules++;

       /*
       **  Check to see if this PORT_GROUP has been initialized
       */
       if(p->prmSrcPort[sport] == NULL)
       {
           p->prmSrcPort[sport] = (PORT_GROUP *)calloc(1, sizeof(PORT_GROUP));
           if(p->prmSrcPort[sport] == NULL)
           {
               return 1;
           }
       }

       if(p->prmSrcPort[sport]->pgCount==0) p->prmNumSrcGroups++;

       prmxAddPortRuleNC( p->prmSrcPort[ sport ], rd );
    }
    
    if( sport == ANYPORT && dport == ANYPORT) /* dst=ANY, src=ANY */
    {
       p->prmNumGenericRules++;

       /*
       **  Check to see if this PORT_GROUP has been initialized
       */
       if(p->prmGeneric == NULL)
       {
           p->prmGeneric = (PORT_GROUP *)calloc(1, sizeof(PORT_GROUP));
           if(p->prmGeneric == NULL)
           {
               return 1;
           }
       }

       prmxAddPortRuleNC( p->prmGeneric, rd );
    }

  return 0;
}


int prmAddByteRuleNC( BYTE_RULE_MAP * p, int dport, RULE_PTR rd )
{
    if( dport != ANYPORT && dport < 256 )  /* dst=21,25,80,110,139 */
    {
       p->prmNumRules++;
       if(p->prmByteGroup[dport].pgCount==0) p->prmNumGroups++;

       prmxAddPortRuleNC( &(p->prmByteGroup[ dport ]), rd );
    }
    
    else if( dport == ANYPORT) /* dst=ANY, src=ANY */
    {
       p->prmNumGenericRules++;

       prmxAddPortRuleNC( &(p->prmGeneric), rd );
    }

  return 0;
}

/*
**
**  NAME
**    prmFindRuleGroup::
**
**  DESCRIPTION
**    Given a PORT_RULE_MAP, this function selects the PORT_GROUP or
**    PORT_GROUPs necessary to fully match a given dport, sport pair.
**    The selection logic looks at both the dport and sport and
**    determines if one or both are unique.  If one is unique, then 
**    the appropriate PORT_GROUP ptr is set.  If both are unique, then
**    both th src and dst PORT_GROUP ptrs are set.  If neither of the
**    ports are unique, then the gen PORT_GROUP ptr is set.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - the PORT_RULE_MAP to pick PORT_GROUPs from.
**    int             - the dst port value (0->64K or -1 for generic)
**    int             - the src port value (0->64K or -1 for generic)
**    PORT_GROUP **   - the src PORT_GROUP ptr to set.
**    PORT_GROUP **   - the dst PORT_GROUP ptr to set.
**    PORT_GROUP **   - the generic PORT_GROUP ptr to set.
**
**  FORMAL OUTPUT
**    int -  0: No rules
**           1: Use Dst Rules
**           2: Use Src Rules
**           3: Use Both Dst and Src Rules
**           4: Use Generic Rules
**
**  NOTES
**    Currently, if there is a "unique conflict", we return both the src
**    and dst PORT_GROUPs.  This conflict forces us to do two searches, one
**    for the src and one for the dst.  So we are taking twice the time to
**    inspect a packet then usual.  Obviously, this is not good.  There
**    are several options that we have to deal with unique conflicts, but
**    have not implemented any currently.  The optimum solution will be to
**    incorporate streaming and protocol analysis to a session so we know
**    what to match against.
**
*/
int prmFindRuleGroup( PORT_RULE_MAP * p, int dport, int sport, PORT_GROUP ** src, PORT_GROUP **dst , PORT_GROUP ** gen)
{
    int stat= 0;

    if( (dport != ANYPORT && dport < MAX_PORTS) && p->prmDstPort[dport] )
    {
         *dst  = p->prmDstPort[dport];
         stat = 1;

    }else{
      
       *dst=NULL;
    }

    if( (sport != ANYPORT && sport < MAX_PORTS ) && p->prmSrcPort[sport])
    {
       *src   = p->prmSrcPort[sport];
        stat |= 2;
       
    }else{
       *src = NULL;
    }

    /* If no Src/Dst rules - use the generic set, if any exist  */
    if( !stat &&  (p->prmGeneric > 0) ) 
    {
       *gen  = p->prmGeneric;
        stat = 4;

    }else{
     
      *gen = NULL;
    }

    
    return stat;
}

/*
*
*/
int prmFindByteRuleGroup( BYTE_RULE_MAP * p, int dport, PORT_GROUP **dst , PORT_GROUP ** gen)
{
    int stat= 0;

    if( (dport != ANYPORT && dport < 256 ) && p->prmByteGroup[dport].pgCount  )
    {
         *dst  = &p->prmByteGroup[dport];
         stat = 1;

    }else{
      
       *dst=0;
    }

    /* If no Src/Dst rules - use the generic set, if any exist  */
    if( !stat &&  (p->prmGeneric.pgCount > 0) ) 
    {
       *gen  = &p->prmGeneric;
        stat = 4;

    }else{
     
      *gen = 0;
    }

    
    return stat;
}

/*
** Access each Rule group by index (0-MAX_PORTS)
*/
PORT_GROUP * prmFindDstRuleGroup( PORT_RULE_MAP * p, int port )
{
    if( port < 0 || port >= MAX_PORTS ) return 0;
	
    if( p->prmDstPort[port])
        return p->prmDstPort[port];
	
    return 0;
}

/*
** Access each Rule group by index (0-MAX_PORTS)
*/
PORT_GROUP * prmFindSrcRuleGroup( PORT_RULE_MAP * p, int port )
{
    if( port < 0 || port >= MAX_PORTS ) return 0;
	
    if( p->prmSrcPort[port])	
      return p->prmSrcPort[port];
    
    return 0;
}

/*
** Access each Rule group by index (0-MAX_PORTS)
*/
PORT_GROUP * prmFindByteRuleGroupUnique( BYTE_RULE_MAP * p, int port )
{
    if( port < 0 || port >= MAX_PORTS ) return 0;
	
    if( p->prmByteGroup[port].pgCount )	
      return &p->prmByteGroup[port];
    
    return 0;
}


/*
** Assign the pattern matching data to this group
*/
int prmSetGroupPatData( PORT_GROUP * pg, void * data )
{
    pg->pgPatData = data;
    return 0;
}

/*
** Get the patttern matching data for this group
*/
void * prmGetGroupPatData( PORT_GROUP * pg )
{
    return pg->pgPatData;
}  

/*
**
**  NAME
**    prmCompileGroups::
**
**  DESCRIPTION
**    Add Generic rules to each Unique rule group, this could be 
**    optimized a bit, right now we will process generic rules 
**    twice when packets have 2 unique ports, but this will not 
**    occur often.
**
**    The generic rues are added to the Unique rule groups, so that 
**    the setwise methodology can be taking advantage of.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - the PORT_RULE_MAP to compile generice rules.
**
**  FORMAL OUTPUT
**    int - 0 is successful;
**
*/
int prmCompileGroups( PORT_RULE_MAP * p )
{
   PORT_GROUP *pgGen, *pgSrc, *pgDst;
   RULE_PTR   *prule;
   int  i;

   /*
   **  Add Generic to Src and Dst groups 
   */
   pgGen = p->prmGeneric;

   if(!pgGen)
        return 0;
   
   for(i=0;i<MAX_PORTS;i++)  
   {
     /* Add to the Unique Src and Dst Groups as well, 
     ** but don't inc thier prmNUMxxx counts, we want these to be true Uniqe counts
     ** we can add the Generic numbers if we want these, besides
     ** each group has it's own count.
     */

     if(p->prmSrcPort[i])
     {
        pgSrc = p->prmSrcPort[i];  
	 
        prule = prmGetFirstRule( pgGen );
        while( prule )
        {
           prmxAddPortRule( pgSrc, prule );
           prule = prmGetNextRule( pgGen );
        }

        prule = prmGetFirstRuleUri( pgGen );
        while( prule )
        {
           prmxAddPortRuleUri( pgSrc, prule );
           prule = prmGetNextRuleUri( pgGen );
        }

        prule = prmGetFirstRuleNC( pgGen );
        while( prule )
        {
           prmxAddPortRuleNC( pgSrc, prule );
           prule = prmGetNextRuleNC( pgGen );
        }
     }

     if(p->prmDstPort[i]) 
     {
        pgDst = p->prmDstPort[i];   
	
        prule = prmGetFirstRule( pgGen );
        while( prule )
        {
           prmxAddPortRule( pgDst, prule );
           prule = prmGetNextRule( pgGen );
        }

        prule = prmGetFirstRuleUri( pgGen );
        while( prule )
        {
           prmxAddPortRuleUri( pgDst, prule );
           prule = prmGetNextRuleUri( pgGen );
        }

        prule = prmGetFirstRuleNC( pgGen );
        while( prule )
        {
           prmxAddPortRuleNC( pgDst, prule );
           prule = prmGetNextRuleNC( pgGen );
        }
     }
     
   }

   return 0;
}


/*
*
*
*/
int prmCompileByteGroups( BYTE_RULE_MAP * p )
{
   PORT_GROUP *pgGen, *pgByte;
   RULE_PTR   *prule;
   int  i;

   /*
   **  Add Generic to Unique groups 
   */
   pgGen = &p->prmGeneric;

   if( !pgGen->pgCount )
        return 0;
   
   for(i=0;i<256;i++)  
   {
      if(p->prmByteGroup[i].pgCount)
      {
        pgByte = &p->prmByteGroup[i];  
	 
        prule = prmGetFirstRule( pgGen );
        while( prule )
        {
           prmxAddPortRule( pgByte, prule );
           prule = prmGetNextRule( pgGen );
        }

        prule = prmGetFirstRuleNC( pgGen );
        while( prule )
        {
           prmxAddPortRuleNC( pgByte, prule );
           prule = prmGetNextRuleNC( pgGen );
        }
     }
   }
   
   return 0;
}

/*
**
**  NAME
**    prmShowStats::
**
**  DESCRIPTION
**    This function shows some basic stats on the fast packet
**    classification.  It show the the number of PORT_GROUPS 
**    for a PORT_RULE_MAP, and the break down of the different
**    rule types (content, uri, no content).
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - the PORT_RULE_MAP to show stats on.
**
**  FORMAL OUTPUT
**    int - 0 is successful.
**
*/
int prmShowStats( PORT_RULE_MAP * p )
{
   int i;
   PORT_GROUP * pg;

   printf("struct ArgusRecord Classification Rule Manager Stats ----\n");
   printf("NumDstGroups   : %d\n",p->prmNumDstGroups);
   printf("NumSrcGroups   : %d\n",p->prmNumSrcGroups);
   printf("\n");
   printf("NumDstRules    : %d\n",p->prmNumDstRules);
   printf("NumSrcRules    : %d\n",p->prmNumSrcRules);
   printf("NumGenericRules: %d\n",p->prmNumGenericRules);
   printf("\n");

   printf("%d Dst Groups In Use, %d Unique Rules, includes generic\n",p->prmNumDstGroups,p->prmNumDstRules);
   for(i=0;i<MAX_PORTS;i++)
   {
     pg = prmFindDstRuleGroup( p, i );
     if(pg)
     {
       printf("  Dst Port %5d : %d uricontent, %d content, %d nocontent \n",i, 
                 pg->pgUriContentCount,pg->pgContentCount,pg->pgNoContentCount);
       if( pg->avgLen )
       {
         printf("MinLen=%d MaxLen=%d AvgLen=%d",pg->minLen,pg->maxLen,pg->avgLen);
         if(pg->c1)printf(" [1]=%d",pg->c1);   
         if(pg->c2)printf(" [2]=%d",pg->c2);   
         if(pg->c3)printf(" [3]=%d",pg->c3);   
         if(pg->c4)printf(" [4]=%d",pg->c4);   
         printf("\n");
       }
     }
   }

   printf("%d Src Groups In Use, %d Unique Rules, includes generic\n",p->prmNumSrcGroups,p->prmNumSrcRules);
   for(i=0;i<MAX_PORTS;i++)
   {
     pg = prmFindSrcRuleGroup( p, i );
     if(pg){
        printf("  Src Port %5d : %d uricontent, %d content, %d nocontent \n",i, 
                 pg->pgUriContentCount,pg->pgContentCount,pg->pgNoContentCount);
        if( pg->avgLen )
	{  
	   printf("MinLen=%d MaxLen=%d AvgLen=%d",pg->minLen,pg->maxLen,pg->avgLen);
          if(pg->c1)printf(" [1]=%d",pg->c1);   
          if(pg->c2)printf(" [2]=%d",pg->c2);   
          if(pg->c3)printf(" [3]=%d",pg->c3);   
          if(pg->c4)printf(" [4]=%d",pg->c4);   
          printf("\n");
	}
     }
   }

   pg = p->prmGeneric;
     if(pg){
        printf("   Generic Rules : %d uricontent, %d content, %d nocontent \n",
                 pg->pgUriContentCount,pg->pgContentCount,pg->pgNoContentCount);
        if( pg->avgLen )
	{
	  printf("MinLen=%d MaxLen=%d AvgLen=%d",pg->minLen,pg->maxLen,pg->avgLen);
          if(pg->c1)printf(" [1]=%d",pg->c1);   
          if(pg->c2)printf(" [2]=%d",pg->c2);   
          if(pg->c3)printf(" [3]=%d",pg->c3);   
          if(pg->c4)printf(" [4]=%d",pg->c4);   
          printf("\n");
	}
     }

   return 0;
}


int prmShowByteStats( BYTE_RULE_MAP * p )
{
   int i;
   PORT_GROUP * pg;

   printf("struct ArgusRecord Classification Rule Manager Stats ----\n");
   printf("NumGroups   : %d\n",p->prmNumGroups);
   printf("\n");
   printf("NumRules    : %d\n",p->prmNumRules);
   printf("NumGenericRules: %d\n",p->prmNumGenericRules);
   printf("\n");

   printf("%d Byte Groups In Use, %d Unique Rules, includes generic\n",p->prmNumGroups,p->prmNumRules);
   for(i=0;i<256;i++)
   {
     pg = prmFindByteRuleGroupUnique( p, i );
     if(pg)
     {
       printf("  Proto/Type %5d : %d content, %d nocontent \n",i, 
                 pg->pgContentCount,pg->pgNoContentCount);
       if( pg->avgLen )
       {
         printf("MinLen=%d MaxLen=%d AvgLen=%d",pg->minLen,pg->maxLen,pg->avgLen);
         if(pg->c1)printf(" [1]=%d",pg->c1);   
         if(pg->c2)printf(" [2]=%d",pg->c2);   
         if(pg->c3)printf(" [3]=%d",pg->c3);   
         if(pg->c4)printf(" [4]=%d",pg->c4);   
         printf("\n");
       }
     }
   }

 
   pg = &p->prmGeneric;
     if(pg){
        printf("   Generic Rules : %d content, %d nocontent \n",
                pg->pgContentCount,pg->pgNoContentCount);
        if( pg->avgLen )
	{
	  printf("MinLen=%d MaxLen=%d AvgLen=%d",pg->minLen,pg->maxLen,pg->avgLen);
          if(pg->c1)printf(" [1]=%d",pg->c1);   
          if(pg->c2)printf(" [2]=%d",pg->c2);   
          if(pg->c3)printf(" [3]=%d",pg->c3);   
          if(pg->c4)printf(" [4]=%d",pg->c4);   
          printf("\n");
	}
     }

   return 0;
}

/*
**
**  NAME
**    prmShowEventStats::
**
**  DESCRIPTION
**    This function is used at the close of the Fast struct ArgusRecord
**    inspection.  It tells how many non-qualified and qualified
**    hits occurred for each PORT_GROUP.  A non-qualified hit
**    is defined by an initial match against a packet, but upon
**    further inspection a hit was not validated.  Non-qualified
**    hits occur because we can match on the most unique aspect
**    of a packet, this is the content.  Snort has other flags
**    then content though, so once we hit a content match we must
**    verify these additional flags.  Sometimes these flags do
**    not pass the validation.  A qualified hit is an event that
**    has been fully qualified, and has been put in the event
**    cache for event selection.  Qualified hits are not a subset
**    of non-qualified hits.  Ideally, non-qualified hits should
**    be zero.  The reason for these stats is that it allows
**    users to trouble shoot PORT_GROUPs.  A poorly written rule
**    may cause many non-qualified events, and these stats
**    allow the user to track this down.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * -  the PORT_RULE_MAP to show stats on.
**
**  FORMAL OUTPUT
**    int - 0 is successful.
**
*/
int prmShowEventStats( PORT_RULE_MAP * p )
{
   int i;
   PORT_GROUP * pg;

   int NQEvents = 0;
   int QEvents = 0;

   printf("struct ArgusRecord Classification Rule Manager Stats ----\n");
   printf("NumDstGroups   : %d\n",p->prmNumDstGroups);
   printf("NumSrcGroups   : %d\n",p->prmNumSrcGroups);
   printf("\n");
   printf("NumDstRules    : %d\n",p->prmNumDstRules);
   printf("NumSrcRules    : %d\n",p->prmNumSrcRules);
   printf("NumGenericRules: %d\n",p->prmNumGenericRules);
   printf("\n");

   printf("%d Dst Groups In Use, %d Unique Rules, includes generic\n",p->prmNumDstGroups,p->prmNumDstRules);
   for(i=0;i<MAX_PORTS;i++)
   {
     pg = prmFindDstRuleGroup( p, i );
     if(pg)
     {
       NQEvents += pg->pgNQEvents;
       QEvents  += pg->pgQEvents;

       if( pg->pgNQEvents + pg->pgQEvents )
       {
          printf("  Dst Port %5d : %d group entries \n",i, pg->pgCount);
          printf("    NQ Events  : %d\n", pg->pgNQEvents);
          printf("     Q Events  : %d\n", pg->pgQEvents);
       }
     }
   }

   printf("%d Src Groups In Use, %d Unique Rules, includes generic\n",p->prmNumSrcGroups,p->prmNumSrcRules);
   for(i=0;i<MAX_PORTS;i++)
   {
     pg = prmFindSrcRuleGroup( p, i );
     if(pg)
     {

        NQEvents += pg->pgNQEvents;
        QEvents += pg->pgQEvents;
    
        if( pg->pgNQEvents + pg->pgQEvents )
        {
          printf("  Src Port %5d : %d group entries \n",i, pg->pgCount);
          printf("    NQ Events  : %d\n", pg->pgNQEvents);
          printf("     Q Events  : %d\n", pg->pgQEvents);
        }
     }
   }

   pg = p->prmGeneric;
   if(pg)
   {
      NQEvents += pg->pgNQEvents;
      QEvents += pg->pgQEvents;

      if( pg->pgNQEvents + pg->pgQEvents )
      {
        printf("  Generic Rules : %d group entries\n", pg->pgCount);
        printf("    NQ Events   : %d\n", pg->pgNQEvents);
        printf("     Q Events   : %d\n", pg->pgQEvents);
      }
   }

   printf("Total NQ Events : %d\n", NQEvents);
   printf("Total  Q Events  : %d\n", QEvents);

   return 0;
}

int prmShowEventByteStats( BYTE_RULE_MAP * p )
{
   int i;
   PORT_GROUP * pg;

   int NQEvents = 0;
   int QEvents = 0;

   printf("struct ArgusRecord Classification Rule Manager Stats ----\n");
   printf("NumGroups   : %d\n",p->prmNumGroups);
   printf("\n");
   printf("NumRules    : %d\n",p->prmNumRules);
   printf("NumGenericRules: %d\n",p->prmNumGenericRules);
   printf("\n");

   printf("%d Byte Groups In Use, %d Unique Rules, includes generic\n",p->prmNumGroups,p->prmNumRules);
   for(i=0;i<256;i++)
   {
     pg = prmFindByteRuleGroupUnique( p, i );
     if(pg)
     {
       NQEvents += pg->pgNQEvents;
       QEvents  += pg->pgQEvents;

       if( pg->pgNQEvents + pg->pgQEvents )
       {
          printf("  Proto/Type %5d : %d group entries \n",i, pg->pgCount);
          printf("      NQ Events  : %d\n", pg->pgNQEvents);
          printf("       Q Events  : %d\n", pg->pgQEvents);
       }
     }
   }

   pg = &p->prmGeneric;
   if(pg)
   {
      NQEvents += pg->pgNQEvents;
      QEvents += pg->pgQEvents;

      if( pg->pgNQEvents + pg->pgQEvents )
      {
        printf("  Generic Rules : %d group entries\n", pg->pgCount);
        printf("    NQ Events   : %d\n", pg->pgNQEvents);
        printf("     Q Events   : %d\n", pg->pgQEvents);
      }
   }

   printf("Total NQ Events : %d\n", NQEvents);
   printf("Total  Q Events  : %d\n", QEvents);

   return 0;
}


#include "pcrm.h"
#define MAX_EVENT_MATCH 100 

typedef struct {
   OTNX *MatchArray[MAX_EVENT_MATCH]; 
   int  iMatchCount; 
   int  iMatchIndex; 
   int  iMatchMaxLen; 
}MATCH_INFO; 
/* 
**  OTNX_MATCH_DATA 
**  This structure holds information that is
**  referenced during setwise pattern matches. 
**  It also contains information regarding the 
**  number of matches that have occurred and 
**  the event to log based on the event comparison
**  function.
*/ 
typedef struct  { 
   PORT_GROUP * pg;
   struct ArgusRecord *argus; 
   int check_ports;
 
   MATCH_INFO *matchInfo;
   int iMatchInfoArraySize;
} OTNX_MATCH_DATA;

static void InitMatchInfo(OTNX_MATCH_DATA *);
static OTNX_MATCH_DATA omd;
static INLINE int fpEvalHeaderSW(PORT_GROUP *, struct ArgusRecord *, int);
static INLINE void InitMatchInfo(OTNX_MATCH_DATA *);

int
RaSnortProcessTCPRecord (struct ArgusRecord *argus)
{
   PORT_GROUP *src, *dst, *gen;
   unsigned short sport = argus->argus_far.flow.ip_flow.sport;
   unsigned short dport = argus->argus_far.flow.ip_flow.dport;
   int retn = 0;

   switch (prmFindRuleGroupTcp(dport, sport, &src, &dst, &gen)) {
      case 0:
         break;
      case 1:
         InitMatchInfo( &omd );
         if(fpEvalHeaderSW(dst, argus, 1))
            retn = 1;
         break;
      case 2:
         InitMatchInfo( &omd );
         if(fpEvalHeaderSW(src, argus, 1))
            retn = 1;
         break;
      case 3:
         InitMatchInfo( &omd );
         if(fpEvalHeaderSW(src, argus, 1))
            retn = 1;
         if(fpEvalHeaderSW(dst, argus, 1))
            retn = 1;
         break;
      case 4:
         InitMatchInfo( &omd );
         /* destination groups */
         if(fpEvalHeaderSW(gen, argus, 1))
            retn = 1;
         break;
      default:
         break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessTCPRecord (0x%x) returning %d\n", argus, retn);
#endif
   return (retn);
}

void FatalError(const char *str, ...) { }


/*
**  $Id: parser.c,v 1.3 2004/05/14 15:44:35 qosient Exp $
**
**  fpdetect.c
**
**  Copyright (C) 2002 Sourcefire,Inc
**  Author(s):  Dan Roelker <droelker@sourcefire.com>
**              Marc Norton <mnorton@sourcefire.com>
**              Andrew R. Baker <andrewb@snort.org>
**  NOTES
**  5.15.02 - Initial Source Code. Norton/Roelker
**  2002-12-06 - Modify event selection logic to fix broken custom rule types
**               arbitrary rule type ordering (ARB)
**
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

/*
**  This define is for the number of unique events
**  to match before choosing which event to log.
**  (Since we can only log one.) This define is the limit.
*/
#define MAX_EVENT_MATCH 100 

/*
**  This define enables set-wise signature detection for
**  IP and ICMP packets.  During early testing, the old
**  method of detection seemed faster for ICMP and IP 
**  signatures, but with modifications to the set-wise engine
**  performance became much better.  This define could be
**  taken out, but is still in for regression testing.
*/
#define FPSW

/*
**  GLOBALS
**  These variables are local to this file and deal with
**  configuration issues that are set in snort.conf through
**  variables.
*/

/*
**  Assorted global variables from the old detection engine
**  for backwards compatibility.
*/
extern PV          pv;  /* program vars (command line args) */
extern int         active_dynamic_nodes;
extern u_int32_t   event_id;
extern char        check_tags_flag;
extern OptTreeNode *otn_tmp;
extern u_int8_t    DecodeBuffer[DECODE_BLEN];

/*
**  Static function prototypes
*/
static INLINE int fpEvalOTN(OptTreeNode *List, struct ArgusRecord *argus);
static INLINE int fpEvalRTN(RuleTreeNode *rtn, struct ArgusRecord *argus, int check_ports);
static INLINE int fpEvalHeader(PORT_GROUP *port_group, struct ArgusRecord *argus, int check_ports);
static INLINE int fpEvalRTNSW(RuleTreeNode *rtn, OptTreeNode *otn, struct ArgusRecord *argus, int check_ports);
static INLINE int fpEvalHeaderSW(PORT_GROUP *, struct ArgusRecord *, int);
static int otnx_match (void* id, int index, void * data );               
static INLINE int fpAddMatch( OTNX_MATCH_DATA *omd, OTNX *otnx, int pLen );
static INLINE int fpLogEvent(RuleTreeNode *rtn, OptTreeNode *otn, struct ArgusRecord *argus);

u_int8_t *doe_ptr = NULL;

static OTNX_MATCH_DATA omd;

/* initialize the global OTNX_MATCH_DATA variable */
int OtnXMatchDataInitialize()
{
    omd.iMatchInfoArraySize = pv.num_rule_types;
    if(!(omd.matchInfo = calloc(omd.iMatchInfoArraySize, sizeof(MATCH_INFO))))
        ArgusLog(LOG_ERR, "Out of memory initializing detection engine\n");

    return 0;
}
    
/*
**  NAME
**    fpSetDetectionOptions::
**
**  DESCRIPTION
**    This function passes a pointer for us to set.  This pointer
**    contains the detection configuration options.  We use these for 
**    various optimizations.
**
**  FORMAL INPUTS
**    FPDETECT * - the address of the configuration structure to pass
**
**  FORMAL OUTPUTS
**    int - 0 is successful, failure code if otherwise.
**
*/
int fpSetDetectionOptions(FPDETECT *detect_options)
{
    fpDetect = detect_options;
    return 0;
}

/*
**
**  NAME
**    fpLogEvent::
**
**  DESCRIPTION
**    This function takes the corresponding RTN and OTN for a snort rule
**    and logs the event and packet that was alerted upon.  This 
**    function was pulled out of fpEvalSomething, so now we can log an
**    event no matter where we are.
**
**  FORMAL INPUTS
**    RuleTreeNode * - rtn for snort rule
**    OptTreeNode  * - otn for snort rule
**    ArgusRecord  * - argus that iliicited event.
*/
static INLINE int fpLogEvent(RuleTreeNode *rtn, OptTreeNode *otn, struct ArgusRecord *argus)
{
    DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,
                "   => Got rule match, rtn type = %d\n",
                rtn->type););

    /*
    if(p->packet_flags & PKT_STREAM_UNEST_UNI &&
            pv.assurance_mode == ASSURE_EST &&
            (! (p->packet_flags & PKT_REBUILT_STREAM)) &&
            otn->stateless == 0)
    {
        return 1;
    }
        
     *  Perform Thresholding Tests - also done in
     * detect.c/CallLogFuncs & CallAlertFuncs
     */
    if (argus) {
        if( !sfthreshold_test( otn->event_data.sig_generator,
                               otn->event_data.sig_id,
                               argus->argus_far.flow.ip_flow.ip_src,
                               argus->argus_far.flow.ip_flow.ip_src,
                               argus->argus_far.time.last.tv_sec)) {
            return 1; /* Don't log it ! */
        }
    }
    
    /*
    **  Set otn_tmp because log.c uses it to log details
    **  of the event.  Maybe we should look into making this
    **  part of the log routines and not a global variable.
    **  This way we could support multiple events per packet.
    */
    otn_tmp = otn;

    event_id++;

    TriggerResponses(argus, otn);

    switch(rtn->type)
    {
        case RULE_PASS:
            PassAction();
            break;

        case RULE_ACTIVATE:
            ActivateAction(argus, otn, &otn->event_data);
            break;

        case RULE_ALERT:
            AlertAction(argus, otn, &otn->event_data);
            break;

        case RULE_DYNAMIC:
            DynamicAction(argus, otn, &otn->event_data);
            break;

        case RULE_LOG:
            LogAction(argus, otn, &otn->event_data);
            break;
    }

/*
    SetTags(argus, otn, event_id);
*/

    if(rtn->type != RULE_PASS) {
        check_tags_flag = 0;
    }

    return 0;
}

/*
**
**  NAME
**    InitMatchInfo::
**
**  DESCRIPTION
**    Initialize the OTNX_MATCH_DATA structure.  We do this for
**    every packet so calloc is not used as this would zero the
**    whole space and this only sets the necessary counters to
**    zero, and saves us time.
**
**  FORMAL INPUTS
**    OTNX_MATCH_DATA * - pointer to structure to init.
**
**  FORMAL OUTPUT
**    None
**
*/
static INLINE void InitMatchInfo(OTNX_MATCH_DATA *o)
{
    int i = 0;

    for(i = 0; i < o->iMatchInfoArraySize; i++)
    {
        o->matchInfo[i].iMatchCount  = 0;
        o->matchInfo[i].iMatchIndex  = 0;
        o->matchInfo[i].iMatchMaxLen = 0;
    }
}

/*
**
**  NAME
**    fpAddMatch::
**
**  DESCRIPTION
**    Add and Event to the appropriate Match Queue: Alert, Pass, or Log.
**    This allows us to find multiple events per packet and pick the 'best'
**    one.  This function also allows us to change the order of alert,
**    pass, and log signatures by cacheing them for decision later.
**
**    IMPORTANT NOTE:
**    fpAddMatch must be called even when the queue has been maxed
**    out.  This is because there are three different queues (alert,
**    pass, log) and unless all three are filled (or at least the 
**    queue that is in the highest priority), events must be looked
**    at to see if they are members of a queue that is not maxed out.
**
**  FORMAL INPUTS
**    OTNX_MATCH_DATA    * - the omd to add the event to.
**    OTNX               * - the otnx to add.
**    int pLen             - length of pattern that matched, 0 for no content
**
**  FORMAL OUTPUTS
**    int - 1 max_events variable hit, 0 successful.
**
*/
static INLINE int fpAddMatch(OTNX_MATCH_DATA *omd, OTNX *otnx, int pLen )
{
    MATCH_INFO * pmi;
    int evalIndex;

    evalIndex = otnx->otn->rtn->listhead->ruleListNode->evalIndex;
    
    pmi = &omd->matchInfo[evalIndex];

    /*
    **  If we hit the max number of unique events for any rule type alert,
    **  log or pass, then we don't add it to the list.
    */
    if( pmi->iMatchCount == fpDetect->max_queue_events || 
        pmi->iMatchCount == MAX_EVENT_MATCH)
    {
        return 1;
    }

    /*
    **  Add the event to the appropriate list
    */
    pmi->MatchArray[ pmi->iMatchCount ] = otnx;

    /*
    **  This means that we are adding a NC rule
    **  and we only set the index to this rule
    **  if there is no content rules in the
    **  same array.
    */
    if(pLen > 0)
    {
        /*
        **  Event Comparison Function
        **  Here the largest content match is the
        **  priority
        */
        if( pmi->iMatchMaxLen < pLen )
        {
            pmi->iMatchMaxLen = pLen;
            pmi->iMatchIndex  = pmi->iMatchCount;
        }
    }
    
    pmi->iMatchCount++;
  
    return 0;
}

/*
**
**  NAME
**    fpEvalOTN::
**
**  DESCRIPTION
**    Evaluates an OTN against a struct ArgusRecord.
**
**  FORMAL INPUTS
**    OptTreeNode * - the OTN to check
**    struct ArgusRecord *      - struct ArgusRecord to evaluate against OTN
**
**  FORMAL OUTPUT
**    int - 0 if no match, 1 if match.
**
*/
static INLINE int fpEvalOTN(OptTreeNode *List, struct ArgusRecord *argus)
{
    if (List == NULL)
        return 0;

    DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "   => Checking Option Node %d\n",
			    List->chain_node_number););

    if (List->type == RULE_DYNAMIC && !List->active_flag)
        return 0;

    if (List->opt_func == NULL) 
        FatalError("List->opt_func was NULL on option #%d!\n", List->chain_node_number);

    if(!List->opt_func->OptTestFunc(argus, List, List->opt_func))
        return 0;

    return 1;
}

/*
**
**  NAME
**    fpEvalRTN::
**
**  DESCRIPTION
**    Evaluates an RTN against a packet.  We can probably get rid of
**    the check_ports variable, but it's in there for good luck.  :)
**
**  FORMAL INPUTS
**    RuleTreeNode * - RTN to check packet against.
**    ArgusRecord  * - struct ArgusRecord to evaluate
**    int            - whether to do a quick enhancement against ports.
**
**  FORMAL OUTPUT
**    int - 1 if match, 0 if match failed.
**
*/
static INLINE int fpEvalRTN(RuleTreeNode *rtn, struct ArgusRecord *argus, int check_ports)
{
    if (rtn == NULL)
        return 0;

    /*
    **  This used to be a speed improvement.  Might still be.
    */
    if(check_ports)
        if(!(rtn->flags & EXCEPT_DST_PORT) && !(rtn->flags & BIDIRECTIONAL) &&
                (argus->argus_far.flow.ip_flow.dport < rtn->ldp))
            return 0;

    if(rtn->type == RULE_DYNAMIC) {
        if(!active_dynamic_nodes) {
            return 0;
        }
        if(rtn->active_flag == 0) {
            return 0;
        }
    }

    DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "[*] Rule Head %d\n", 
                rtn->head_node_number);)

    if(!rtn->rule_func->RuleHeadFunc(argus, rtn, rtn->rule_func)) {
        DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,
                    "   => Header check failed, checking next node\n"););
        DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, 
                    "   => returned from next node check\n"););
        return 0;
    }

    /*
    **  Return that there is a rule match and log the event outside
    **  of this routine.
    */
    return 1;
}

/*
**  NAME
**    fpEvalRTNSW::
**
**  DESCRIPTION
**    This function checks the RTN for validation first and then checks the
**    OTN for a pattern match.
**  
**  FORMAL INPUTS
**    RuleTreeNode * - rtn to inspect packet against
**    OptTreeNode *  - otn to inspect packet against
**    struct ArgusRecord *       - packet to inspect against
**    int            - whether to check ports for this packet
**
**  FORMAL OUTPUTS
**    int - 1 is successful match
**          0 is no match
**
*/
static INLINE int fpEvalRTNSW(RuleTreeNode *rtn, OptTreeNode *otn, struct ArgusRecord *argus, int check_ports)
{
    /*
    **  This is set to one, because we already have
    **  an OTN hit.
    */
    int rule_match = 0;

    /*
    **  Reset the last match offset for each OTN we touch... 
    */
    doe_ptr = NULL;


    if(rtn == NULL) {
        return 0;
    }

    /*
    **  Used to be a speed optimization.  Might still be.
    */
    if(check_ports) {
        if(!(rtn->flags & EXCEPT_DST_PORT) && !(rtn->flags & BIDIRECTIONAL) &&
                (argus->argus_far.flow.ip_flow.dport < rtn->ldp)) {
            return 0;
        }
    }

    if(rtn->type == RULE_DYNAMIC) {
        if(!active_dynamic_nodes) {
            return 0;
        }

        if(rtn->active_flag == 0) {
            return 0;
        }
    }

    DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "[*] Rule Head %d\n", 
                rtn->head_node_number);)

    if(!rtn->rule_func->RuleHeadFunc(argus, rtn, rtn->rule_func)) {
        DEBUG_WRAP(ArgusDebug(DEBUG_DETECT,
                    "   => Header check failed, checking next node\n"););
        DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, 
                    "   => returned from next node check\n"););
        return 0;
    }

    /*
    **  RTN is validated, now check the OTN.
    */
    rule_match = fpEvalOTN(otn, argus);

    return rule_match;
}

/*
**
**  NAME
**    otnx_match::
**
**  DESCRIPTION
**    When the pattern matcher finds a match, this routine
**    is processed.  The match is checked to see whether the
**    associated otn and rtn have already been validated for
**    this packet, and if so does not do the check again.
**    Otherwise, the otn/rtn validation occurs.
**
**  FORMAL INPUTS
**
**    unsigned  id              : users first handle/ptr-whatever to this pattern
**    unsigned  id2             : users 2nd data 
**    int index                 : index in packet data
**    void *data                : user data passed in when pattern was loaded
**
**  FORMAL OUTPUT
**    int 0 - continue processing
**        1 - stop processing this packet for patterns
**
*/
static int otnx_match( void * id, int index, void * data)
{
    OTNX_MATCH_DATA  *omd    = (OTNX_MATCH_DATA *)data;
    PMX              *pmx    = (PMX*)id;
    RULE_NODE        *rnNode = (RULE_NODE*)(pmx->RuleNode);

    OTNX             *otnx   = (OTNX*)(rnNode->rnRuleData);
    PatternMatchData *pmd    = (PatternMatchData*)pmx->PatternMatchData;

    /*
    **  This is where we check the RULE_NODE ID for
    **  previous hits.
    */
    if(boIsBitSet(&(omd->pg->boRuleNodeID), rnNode->iRuleNodeID))
        return 0;
    
    if( fpEvalRTNSW(otnx->rtn, otnx->otn, omd->argus, omd->check_ports) ) {
        /*
        **  We have a qualified event
        */
        omd->pg->pgQEvents++;
        UpdateQEvents();

        fpAddMatch(omd, otnx, pmd->pattern_size );
    } else {
        /*
        ** This means that the event is non-qualified.
        */
        omd->pg->pgNQEvents++;
        UpdateNQEvents();
    }
     
    /*
    **  Here is where we set the bit array for each RULE_NODE that
    **  we hit.
    */
    if(boSetBit(&(omd->pg->boRuleNodeID), rnNode->iRuleNodeID)) {
        /*
        **  There was an error, don't do anything right now.
        */
    }   

    return 0;
}

/*
**
**  NAME
**    fpSelectEvent::
**
**  DESCRIPTION
**    Select an Event based on the current Rule order set at run time:
**      - Alert->Pass->Log
**      - Pass->Alert->Log
**    This function is called at each level of processing:
**      -Uri content
**      -content
**      -no content
**    This is different than the fpFinalSelectEvent function that gets
**    called after processing on the packet is done.  This is to make
**    sure that we select the right event type (alert, pass, log) when
**    there was no first priority during the search.
**
**  FORMAL INPUTS
**    OTNX_MATCH_DATA * - omd to select event from.
**
**  FORMAL OUTPUT
**    OTNX * - return the OTNX with the select RTN/OTN
**  
*/
static INLINE OTNX *fpSelectEvent(OTNX_MATCH_DATA *o)
{
    if(o->matchInfo[0].iMatchCount)
        return o->matchInfo[0].MatchArray[o->matchInfo[0].iMatchIndex];

    return NULL;
}

/*
**
**  NAME
**    fpFinalSelectEvent::
**
**  DESCRIPTION
**    fpFinalSelectEvent is called at the end of packet processing
**    to decide, if there hasn't already been a selection, to decide
**    what event to select.  This function is different from 
**    fpSelectEvent by the fact that fpSelectEvent only selects an
**    event if it is the first priority setting (pass or alert).
**
**    IMPORTANT NOTE:
**    We call fpFinalSelectEvent() after all processing of the packet
**    has been completed.  The reason this must be called afterwards is
**    because of unique rule group conflicts for a packet.  If there is
**    a unique conflict, then we inspect both rule groups and do the final
**    event select after both rule groups have been inspected.  The
**    problem came up with bi-directional rules with pass rule ordering
**    as the first type of rule.  Before we would detect a alert rule in
**    the first rule group, and since there was no pass rules we would
**    log that alert rule.  However, if we had inspected the second rule
**    group, we would have found a pass rule and that should have taken
**    precedence.  We now inspect both rule groups before doing a final
**    event select.
**
**  FORMAL INPUTS
**    OTNX_MATCH_DATA * - omd to select event from.
**    struct ArgusRecord *          - pointer to packet to log.
**
**  FORMAL OUTPUT
**    int - return 0 if no match, 1 if match.
**   
*/
static INLINE int fpFinalSelectEvent(OTNX_MATCH_DATA *o, struct ArgusRecord *p)
{
    int i = 0;
    OTNX *otnx;

    for(i = 0; i < o->iMatchInfoArraySize; i++)
    {
        if(o->matchInfo[i].iMatchCount)
        {
            otnx = o->matchInfo[i].MatchArray[o->matchInfo[i].iMatchIndex];
            if(otnx)
            {
                fpLogEvent(otnx->rtn, otnx->otn, p);
                return 1;
            }
        }
    }

    return 0;
}

/*
**  fpEvalHeader::
**
**  This function is the old way of walking PORT_GROUPs.  We
**  check the OTNs for matches and then check the RTN for
**  validation if the OTN matches.
**  Kept for backwards-compatibility
*/
static INLINE int fpEvalHeader(PORT_GROUP *port_group, struct ArgusRecord *p, int check_ports)
{
    RULE_NODE *rnWalk;
    OTNX *otnxWalk;

    /*
    **  Walk the content OTNs
    */
    for(rnWalk = port_group->pgHead; rnWalk; rnWalk = rnWalk->rnNext)
    {
        /*
        **  Reset the last match offset for each OTN we touch... 
        */
        doe_ptr = NULL;
        
        otnxWalk = (OTNX *)rnWalk->rnRuleData;
        /*
        **  Do the OTN check, if successful than we check
        **  the RTN for validation purposes.
        */
        if(fpEvalOTN(otnxWalk->otn, p))
        {
            /*
            **  OTN is match, check RTN
            */
            if(fpEvalRTN(otnxWalk->rtn, p, check_ports))
            {
                fpLogEvent(otnxWalk->rtn, otnxWalk->otn, p);
                return 1;
            }
            
            continue;
        }
    }

    /*
    **  Walk the non-content OTNs
    */
    for(rnWalk = port_group->pgHeadNC; rnWalk; rnWalk = rnWalk->rnNext)
    {
        /*
        **  Reset the last match offset for each OTN we touch... 
        */
        doe_ptr = NULL;

        otnxWalk = (OTNX *)rnWalk->rnRuleData;
        /*
        **  Do the OTN check, if successful than we check
        **  the RTN for validation purposes.
        */
        if(fpEvalOTN(otnxWalk->otn, p))
        {
            /*
            **  OTN is match, check RTN
            */
            if(fpEvalRTN(otnxWalk->rtn, p, check_ports))
            {
                fpLogEvent(otnxWalk->rtn, otnxWalk->otn, p);
                return 1;
            }
            
            continue;
        }
    }

    return 0;
}

/*
**  
**  NAME
**    fpEvalHeaderSW::
**
**  DESCRIPTION
**    This function does a set-wise match on content, and walks an otn list
**    for non-content.  The otn list search will eventually be redone for 
**    for performance purposes.
**
**  FORMAL INPUTS
**    PORT_GROUP * - the port group to inspect
**    struct ArgusRecord *     - the packet to inspect
**    int          - whether src/dst ports should be checked (udp/tcp or icmp)
**
**  FORMAL OUTPUTS
**    int - 0 for failed pattern match
**          1 for sucessful pattern match
**
*/
static INLINE int fpEvalHeaderSW(PORT_GROUP *port_group, struct ArgusRecord *argus, int check_ports)
{
    RULE_NODE *rnWalk;
    OTNX *otnx = NULL;
    void * so;
    
    /* XXX it is not a good idea to allocate memory here */
 
    extern HttpUri  UriBufs[URI_COUNT]; /* decode.c */

    /*
    **  Init the info for rule ordering selection
    */
    //InitMatchInfo( &omd );
    
    /*
    **  PKT_STREAM_INSERT packets are being rebuilt and re-injected
    **  through this detection engine.  So in order to avoid pattern
    **  matching bytes twice, we wait until the PKT_STREAM_INSERT 
    **  packets are rebuilt and injected through the detection engine.
    **
    **  PROBLEM:
    **  If a stream gets stomped on before it gets re-injected, an attack
    **  would be missed.  So before a connection gets stomped, we 
    **  re-inject the stream we have.
    */

/*
    if(fpDetect->inspect_stream_insert) {
        *
        **   Uri-Content Match
        **   This check indicates that http_decode found
        **   at least one uri
        *
        if( p->uri_count > 0) {
            int i;
            so = (void *)port_group->pgPatDataUri;
	
            if( so ) {
                mpseSetRuleMask( so, &port_group->boRuleNodeID ); 

                for( i=0; i<p->uri_count; i++) {
                    if(UriBufs[i].uri == NULL)
                        continue;

                    omd.pg = port_group;
                    omd.p  = p;
                    omd.check_ports= check_ports;

                    mpseSearch (so, UriBufs[i].uri, UriBufs[i].length, 
                         otnx_match, &omd);

                    otnx = fpSelectEvent( &omd );

                    if(otnx)
                    {
                        fpLogEvent(otnx->rtn, otnx->otn, p);
                        boResetBITOP(&(port_group->boRuleNodeID));
   
                        return 1;
                    }
                }   
            }
        }

         *
        **  If this is a pipeline request don't do the no-content
        **  rules since we already checked them during the
        **  first URI inspection.
        * 
        if(UriBufs[0].decode_flags & HTTPURI_PIPELINE_REQ)
            return 0;

         *
        **  Decode Content Match
        **  We check to see if the packet has been normalized into
        **  the global (decode.c) DecodeBuffer.  Currently, only
        **  telnet normalization writes to this buffer.  So, if
        **  it is set, we do this the match against the normalized
        **  buffer and we do the check against the original 
        **  payload, in case any of the rules have the 
        **  'rawbytes' option.
        * 
        so = (void *)port_group->pgPatData;

        if((p->packet_flags & PKT_ALT_DECODE) && so && p->alt_dsize) {
            mpseSetRuleMask( so, &port_group->boRuleNodeID ); 

            omd.pg = port_group;
            omd.p = p;
            omd.check_ports= check_ports;

            mpseSearch ( so, DecodeBuffer, p->alt_dsize, 
                    otnx_match, &omd );

            otnx = fpSelectEvent( &omd );

            if(otnx)
            {
                fpLogEvent(otnx->rtn, otnx->otn, p);
                boResetBITOP(&(port_group->boRuleNodeID));

                return 1;
            }

             *
             **  The reason that we reset the bitops is because
             **  an OTN might not be verified using the DecodeBuffer
             **  because of the 'rawbytes' option, while the next pass
             **  will need to validate that same rule in the case
             **  of rawbytes.
             * 
            boResetBITOP(&(port_group->boRuleNodeID));
        }
        
         *
        **  Content-Match - If no Uri-Content matches, than do a Content search
        **
        **  NOTE:
        **    We may want to bail after the Content search if there
        **    has been a successful match.
        * 
        if( so && p->data && p->dsize) 
        {
            mpseSetRuleMask( so, &port_group->boRuleNodeID ); 

            omd.pg = port_group;
            omd.p = p;
            omd.check_ports= check_ports;

            mpseSearch ( so, p->data, p->dsize, otnx_match, &omd );
        
            otnx = fpSelectEvent( &omd );

            if(otnx)
            {
                fpLogEvent(otnx->rtn, otnx->otn, p);
                boResetBITOP(&(port_group->boRuleNodeID));

                return 1;
            }
        }

        boResetBITOP(&(port_group->boRuleNodeID));
    }
*/

    /*
    **  PKT_REBUILT_STREAM packets are re-injected streams.  This means
    **  that the "packet headers" are completely bogus and only the 
    **  content matches are important.  So for PKT_REBUILT_STREAMs, we
    **  don't inspect against no-content OTNs since these deal with 
    **  packet headers, packet sizes, etc.
    **
    **  NOTE:
    **  This has been changed when evaluating no-content rules because
    **  it was interfering with the pass->alert ordering.  We still
    **  need to check no-contents against rebuilt packets, because of
    **  this problem.  Immediate solution is to have the detection plugins
    **  bail if the rule should only be inspected against packets, a.k.a
    **  dsize checks.
    */

    /*
    **  Walk and test the non-content OTNs
    */
    for(rnWalk = port_group->pgHeadNC; rnWalk; rnWalk = rnWalk->rnNext) {
        /*
        **  Reset the last match offset for each OTN we touch... 
        */
        doe_ptr = NULL;

        otnx = (OTNX *)rnWalk->rnRuleData;
        /*
        **  Do the OTN check, if successful than we check
        **  the RTN for validation purposes.
        */
        if(fpEvalOTN(otnx->otn, argus)) {
            /*
            *  OTN is match, check RTN
            */
            if(fpEvalRTN(otnx->rtn, argus, check_ports)) {
                port_group->pgQEvents++;
                UpdateQEvents();

                /*
                **  If the array if filled for this type
                **  of event, then it wasn't added and there
                **  is no reason to select the events again.
                */
                if( fpAddMatch(&omd, otnx, 0) ) {
                    continue;
                }

                /*
                **  We select the events to see if this is an
                **  event that can bail us out of processing
                **  the rest of the No-Contents.
                */
                otnx = fpSelectEvent( &omd );
      
                if(otnx) {
                    fpLogEvent(otnx->rtn, otnx->otn, argus);
                    return 1;
                }

            } else {
                /*
                **  This is a non-qualified event
                */
                port_group->pgNQEvents++;
                UpdateNQEvents();
            }

            continue;
        }
    }
    return 0;
}


/*
**
**  NAME
**    fpEvalArgusRecord::
**
**  DESCRIPTION
**    This function is the interface to the Detect() routine.  Here 
**    the IP protocol is processed.  If it is TCP, UDP, or ICMP, we
**    process the both that particular ruleset and the IP ruleset
**    with in the fpEvalHeader for that protocol.  If the protocol
**    is not TCP, UDP, or ICMP, we just process the packet against
**    the IP rules at the end of the fpEvalstruct ArgusRecord routine.  Since
**    we are using a setwise methodology for snort rules, both the
**    network layer rules and the transport layer rules are done
**    at the same time.  While this is not the best for modularity,
**    it is the best for performance, which is what we are working
**    on currently.
**
**  FORMAL INPUTS
**    struct ArgusRecord * - the packet to inspect
**
**  FORMAL OUTPUT
**    int - 0 means that packet has been processed.
**
*/
int fpEvalArgusRecord(struct ArgusRecord *argus)
{
/*
    int ip_proto = argus->argus_far.flow.ip_flow.ip_p;

    switch(ip_proto) {
        case IPPROTO_TCP:
            DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "Detecting on TcpList\n"););
            fpEvalHeaderTcp(argus);
            return 0;

        case IPPROTO_UDP:
            DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "Detecting on UdpList\n"););
            fpEvalHeaderUdp(argus);
            return 0;

        case IPPROTO_ICMP:
            DEBUG_WRAP(ArgusDebug(DEBUG_DETECT, "Detecting on IcmpList\n"););
            fpEvalHeaderIcmp(argus);
            return 0;

        default:
            break;
    }
*/

    /*
    **  No Match on TCP/UDP, Do IP
    */
/*
    fpEvalHeaderIp(argus, ip_proto);
*/
    return 0;
}

SFEVENT *GetEventPtr() { return &sfPerf.sfEvent; }

int
UpdateNQEvents()
{
    SFEVENT *sfEvent = GetEventPtr();

    if(!(sfPerf.iPerfFlags & SFPERF_EVENT))
        return 0;

    sfEvent->NQEvents++;
    sfEvent->TotalEvents++;
    return 0;
}

int UpdateQEvents()
{
    SFEVENT *sfEvent = GetEventPtr();

    if(!(sfPerf.iPerfFlags & SFPERF_EVENT))
        return 0;

    sfEvent->QEvents++;
    sfEvent->TotalEvents++;
    return 0;
}
