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
 * rapolicy.c  - match input argus records against
 *    a Cisco access control policy.
 *       
 * written by Carter Bullard and Dave Edelman
 * QoSient, LLC
 *       
 */

/*
 * $Id: //depot/gargoyle/clients/examples/rapolicy/rapolicy.c#10 $
 * $DateTime: 2016/10/28 18:37:18 $
 * $Change: 3235 $
 */


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(CYGWIN)
#define USE_IPV6
#endif

#define RA_POLICY_C

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <stdio.h>
#include <arpa/inet.h>

#include <argus_compat.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>


#include <rapolicy.h>

struct RaPolicyPolicyStruct *RaPolicy = NULL;
struct RaPolicyPolicyStruct *RaGlobalPolicy = NULL;

static int argus_version = ARGUS_VERSION;

int RaPolicyParseResourceFile (struct ArgusParserStruct *, char *, struct RaPolicyPolicyStruct **);
int RaReadPolicy (struct ArgusParserStruct *, struct RaPolicyPolicyStruct **, char *);
int RaParsePolicy (struct ArgusParserStruct *, struct RaPolicyPolicyStruct **, char *);
int RaCheckPolicy (struct ArgusParserStruct *, struct ArgusRecordStruct *, struct RaPolicyPolicyStruct *);
int RaMeetsPolicyCriteria (struct ArgusParserStruct *, struct ArgusRecordStruct *, struct RaPolicyPolicyStruct *);
void RaDumpPolicy (struct ArgusParserStruct *, struct RaPolicyPolicyStruct *);
void RaDumpCounters (struct RaPolicyPolicyStruct *);
int RaDoNotification (struct ArgusRecordStruct *, struct RaPolicyPolicyStruct *);


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   parser->RaWriteOut = 1;

   if (!(parser->RaInitialized)) {
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);

      if (parser->ver3flag)
         argus_version = ARGUS_VERSION_3;

      parser->RaInitialized++;
      parser->RaWriteOut = 0;

      if (parser->ArgusFlowModelFile != NULL) {
         RaPolicyParseResourceFile (parser, parser->ArgusFlowModelFile, &RaPolicy);
      } else {
         if (!(parser->Xflag)) {
            RaPolicyParseResourceFile (parser, "/etc/rapolicy.conf", &RaPolicy);
         }
      }
   }
}

void RaArgusInputComplete (struct ArgusInput *input) { return; }


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!ArgusParser->RaParseCompleting++) {
         if (ArgusParser->ArgusPrintJson)
            fprintf (stdout, "\n");

#ifdef ARGUSDEBUG
         ArgusDebug (2, "RaParseComplete(caught signal %d)\n", sig);
#endif
         switch (sig) {
            case SIGHUP: 
            case SIGINT:
            case SIGTERM:
            case SIGQUIT: {
               struct ArgusWfileStruct *wfile = NULL;

               if (ArgusParser->Aflag) {
                      RaDumpCounters(RaPolicy);
                  }
               
               ArgusShutDown(sig);

               if (ArgusParser->ArgusWfileList != NULL) {
                  struct ArgusListObjectStruct *lobj = NULL;
                  int i, count = ArgusParser->ArgusWfileList->count;

                  if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
                     for (i = 0; i < count; i++) {
                        if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                           if (wfile->fd != NULL) {
#ifdef ARGUSDEBUG
                              ArgusDebug (2, "RaParseComplete: closing %s\n", wfile->filename);
#endif
                              fflush (wfile->fd);
                              fclose (wfile->fd);
                              wfile->fd = NULL;
                           }
                        }
                        lobj = lobj->nxt;
                     }
                  }
               }
               exit(0);
               break;
            }
         }
      }
   }
}


void
ArgusClientTimeout ()
{
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusClientTimeout()\n");
#endif
}

void
parse_arg (int argc, char**argv)
{}

void
usage ()
{
   extern char version[];

   fprintf (stdout, "Rapolicy Version %s\n", version);
   fprintf (stdout, "usage: %s -f rapolicy.conf [ra-options]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -f rapolicy.conf file.\n");
   fflush (stdout);

   exit(1);
}

void
RaDumpCounters (struct RaPolicyPolicyStruct *policy) 
{
       printf("\nHit Rates [flows  packets   bytes]\n");
       while (policy) {
	if(policy->hitCount != 0) {
         printf("[%10lld %15lld %20lld]\tACL %s Line %ld: %s\n",
           policy->hitCount, policy->hitPkts, policy->hitBytes,
           policy->policyID, policy->line,  policy->str);
	}
         policy = policy->nxt;
       }
}
 
void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   int process= 0;

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
      case ARGUS_EVENT: {
         break;
      }

      case ARGUS_NETFLOW:
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         if (flow) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                     case ARGUS_TYPE_IPV4:
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_TCP:
                           default:
                           case IPPROTO_UDP: {
                              process++;
                              break;
                           }
                        }
                        break;

                     case ARGUS_TYPE_IPV6: {
                        switch (flow->ipv6_flow.ip_p) {
                           case IPPROTO_TCP:
                           case IPPROTO_UDP: {
// not quite ready for IPv6                              process++;
                              break;
                           }
                        }
                        break;
                     }
                  }
                  break;
               }
            }

            if (process){
               struct ArgusRecordStruct *ns = ArgusCopyRecordStruct(argus);
               if ((RaCheckPolicy (parser, ns, RaPolicy) || (parser->RaPolicyStatus & ARGUS_POLICY_JUST_LABEL)))
                  RaSendArgusRecord (ns);
               
               ArgusDeleteRecordStruct(parser, ns);
            }

            if ( (!process) && (parser->RaPolicyStatus & ARGUS_POLICY_PERMIT_OTHERS))
               RaSendArgusRecord (argus);
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "RaProcessRecord () returning\n");
#endif
}


char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];

int
RaSendArgusRecord(struct ArgusRecordStruct *ns)
{
   int retn = 1;

   if (ns->status & ARGUS_RECORD_WRITTEN)
      return (retn);
 
   if ((ArgusParser->ArgusWfileList != NULL) && (!(ArgusListEmpty(ArgusParser->ArgusWfileList)))) {
      struct ArgusWfileStruct *wfile = NULL;
      struct ArgusListObjectStruct *lobj = NULL;
      int i, count = ArgusParser->ArgusWfileList->count;

      if ((lobj = ArgusParser->ArgusWfileList->start) != NULL) {
         for (i = 0; i < count; i++) {
            if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
               int pass = 1;
               if (wfile->filterstr) {
                     struct nff_insn *wfcode = wfile->filter.bf_insns;
                     pass = ArgusFilterRecord (wfcode, ns);
               }

               if (pass != 0) {
                  if ((ArgusParser->exceptfile == NULL) || strcmp(wfile->filename, ArgusParser->exceptfile)) {
                     struct ArgusRecord *argusrec = NULL;
                     int rv;

                     if ((argusrec = ArgusGenerateRecord (ns, 0L, ArgusRecordBuffer, argus_version)) != NULL) {
#ifdef _LITTLE_ENDIAN
                        ArgusHtoN(argusrec);
#endif
                        rv = ArgusWriteNewLogfile (ArgusParser, ns->input,
                                                   wfile, argusrec);
                        if (rv < 0)
                           ArgusLog(LOG_ERR, "%s unable to open file\n",
                                    __func__);
                     }
                  }
               }
            }
            lobj = lobj->nxt;
         }
      }

   } else {
      char buf[MAXSTRLEN];
      if (!ArgusParser->qflag) {
         if (ArgusParser->Lflag && (!(ArgusParser->ArgusPrintXml) && !(ArgusParser->ArgusPrintJson))) {
            if (ArgusParser->RaLabel == NULL)
               ArgusParser->RaLabel = ArgusGenerateLabel(ArgusParser, ns);
 
            if (!(ArgusParser->RaLabelCounter++ % ArgusParser->Lflag))
               printf ("%s\n", ArgusParser->RaLabel);
 
            if (ArgusParser->Lflag < 0)
               ArgusParser->Lflag = 0;
         }

         buf[0] = 0;
         ArgusPrintRecord(ArgusParser, buf, ns, MAXSTRLEN);

         if (ArgusParser->ArgusPrintJson) {
            if (fprintf (stdout, "%s", buf) < 0)
               RaParseComplete (SIGQUIT);
         } else {
            if (fprintf (stdout, "%s\n", buf) < 0)
               RaParseComplete (SIGQUIT);
         }
         fflush(stdout);
      }
   }

   ns->status |= ARGUS_RECORD_WRITTEN;
   return (retn);
}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}

#define RAPOLICY_RCITEMS			8

#define RA_POLICY_SHOW_WHICH			0
#define RA_POLICY_LABEL_ALL			1
#define RA_POLICY_LABEL_LOG			2
#define RA_POLICY_PERMIT_OTHERS			3
#define RA_POLICY_DUMP_POLICY			4
#define RA_POLICY_LABEL_IMPLICIT		5
#define RA_POLICY_JUST_LABEL			6
#define RA_POLICY_ACL_FILE                      7

char *RaPolicyResourceFileStr [] = {
   "RA_POLICY_SHOW_WHICH=",
   "RA_POLICY_LABEL_ALL=",
   "RA_POLICY_LABEL_LOG=",
   "RA_POLICY_PERMIT_OTHERS=",
   "RA_POLICY_DUMP_POLICY=",
   "RA_POLICY_LABEL_IMPLICIT=",
   "RA_POLICY_JUST_LABEL=",
   "RA_POLICY_ACL_FILE=",
};


int RaInitialState = 0;
int RaParseError = 0;

char *RaParseErrorStr [POLICYERRORNUM] = {
   "access-list identifier not found",
   "policy id number not found",
   "permit/deny indication not found",
   "protocol indentifier not found",
   "no source address defined",
   "no source address mask defined",
   "wrong source port operator",
   "wrong source port specification"
   "no destination address defined",
   "no destination address mask defined",
   "wrong destination port operator",
   "wrong destination port specification",
   "access violation notification not found",
};

int
RaPolicyParseResourceFile (struct ArgusParserStruct *parser, char *file, struct RaPolicyPolicyStruct **policy)
{
   int retn = 0, i, len, done = 0;
   struct RaPolicyPolicyStruct *pol;
   char strbuf[MAXSTRLEN], *str = strbuf, *optarg;
   FILE *fd;

   if (file) {
      if ((fd = fopen (file, "r")) != NULL) {
         while ((fgets(str, MAXSTRLEN, fd)) != NULL)  {
            done = 0;
            while (*str && isspace((int)*str))
                str++;

            if (*str && (*str != '#') && (*str != '\n') && (*str != '!')) {
               for (i = 0; i < RAPOLICY_RCITEMS && !done; i++) {
                  len = strlen(RaPolicyResourceFileStr[i]);
                  if (!(strncmp (str, RaPolicyResourceFileStr[i], len))) {
                     optarg = &str[len];
                     if (*optarg == '\"') { optarg++; }
                     if (optarg[strlen(optarg) - 1] == '\n')
                        optarg[strlen(optarg) - 1] = '\0';
                     if (optarg[strlen(optarg) - 1] == '\"')
                        optarg[strlen(optarg) - 1] = '\0';

                     switch (i) {
                        case RA_POLICY_SHOW_WHICH: {
                           if (!(strncasecmp(optarg, "deny", 4)))
                              parser->RaPolicyStatus |= ARGUS_POLICY_SHOW_DENY;
                           else
                              parser->RaPolicyStatus &= ~ARGUS_POLICY_SHOW_DENY;
                           break;
                        }
                        case RA_POLICY_LABEL_ALL: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              parser->RaPolicyStatus |= ARGUS_POLICY_LABEL_ALL;
                           else
                              parser->RaPolicyStatus &= ~ARGUS_POLICY_LABEL_ALL;
                           break;
                        }
                        case RA_POLICY_LABEL_LOG: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              parser->RaPolicyStatus |= ARGUS_POLICY_LABEL_LOG;
                           else
                              parser->RaPolicyStatus &= ~ARGUS_POLICY_LABEL_LOG;
                           break;
                        }
                        case RA_POLICY_PERMIT_OTHERS: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              parser->RaPolicyStatus |= ARGUS_POLICY_PERMIT_OTHERS;
                           else
                              parser->RaPolicyStatus &= ~ARGUS_POLICY_PERMIT_OTHERS;
                           break;
                        }
                        case RA_POLICY_DUMP_POLICY: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              parser->RaPolicyStatus |= ARGUS_POLICY_DUMP_POLICY;
                           else
                              parser->RaPolicyStatus &= ~ARGUS_POLICY_DUMP_POLICY;
                           break;
                        }
                        case RA_POLICY_LABEL_IMPLICIT: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              parser->RaPolicyStatus |= ARGUS_POLICY_LABEL_IMPLICIT;
                           else
                              parser->RaPolicyStatus &= ~ARGUS_POLICY_LABEL_IMPLICIT;
                           break;
                        }
                        case RA_POLICY_JUST_LABEL: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              parser->RaPolicyStatus |= ARGUS_POLICY_JUST_LABEL;
                           else
                              parser->RaPolicyStatus &= ~ARGUS_POLICY_JUST_LABEL;
                           break;
                        }
                       case RA_POLICY_ACL_FILE: {
                          if (!(RaReadPolicy(parser, policy, optarg) > 0) ){
                             ArgusLog (LOG_ERR, "RaPolicy: RaReadPolicy Error");
                             exit(0);
                          }
                          if (parser->RaPolicyStatus & ARGUS_POLICY_DUMP_POLICY) {
                             pol = *policy; 
                             while (pol) {
                                RaDumpPolicy(parser, pol);
                                pol = pol->nxt;
                             }
                             exit(1);
                          }
                          break;
                       }
                     }
                  }
               }
            }
         }
         fclose(fd);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "RaPolicyParseResourceFile (%p, %s, %p) returning %d\n", parser, file, policy, retn);
#endif

   return (retn);
}

int
RaReadPolicy (struct ArgusParserStruct *parser, struct RaPolicyPolicyStruct **policy, char *file)
{
   int retn = 1, linenum = 0;
   struct RaPolicyPolicyStruct *pol, *policyLast = NULL;
   char buffer [1024];
   FILE *fd;

   if (file) {
      if ((fd = fopen (file, "r")) != NULL) {
         while (fgets (buffer, 1024, fd)) {
            linenum++;
            pol = NULL;
            if ((*buffer != '#') && (*buffer != '\n') && (*buffer != '!')) {
               if ((retn = RaParsePolicy (parser, &pol, buffer)) > 0) {
                  if (policyLast)  {
                     policyLast->nxt = pol;
                     pol->prv = policyLast;
                     pol->line = linenum;
                     pol->policyID = policyLast->policyID;
                     policyLast = pol;
                  } else {
                     *policy = policyLast = pol;
                     pol->line = linenum;
                    }
                  if (retn < 0)
                     ArgusLog (LOG_ERR, "RaReadPolicy: line %d: %s\n", linenum, RaParseErrorStr [RaParseError]);
               }
                     sprintf (buffer, "ACL=%s_%s_Line_%4.4d",
                           pol->flags & RA_PERMIT ? "Permit" : "Deny",
                           pol->policyID,
                           (int) pol->line
                     );
                     pol->labelStr = strdup(buffer);
                     if(pol->str[strlen(pol->str)-1] == '\n') pol->str[strlen(pol->str)-1] = '\0';
            }
         }
         fclose (fd);
         retn = 1;

      } else {
         retn = 0;
         ArgusLog (LOG_ERR, "RaReadPolicy: fopen %s %s\n", file,  strerror(errno));
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (2, "RaReadPolicy (0x%x, %s) returning %d\n", policy, file, retn);
#endif
   return (retn);
}


void
RaDumpPolicy (struct ArgusParserStruct *parser, struct RaPolicyPolicyStruct *policy) 
{
struct protoent *proto;
arg_uint32 host, any, low, high;

host = ntohl(inet_addr("0.0.0.0"));
any = ntohl(inet_addr("255.255.255.255"));

    printf("%s Line %4.4ld %s\n",
           policy->policyID, policy->line, policy->str);


    printf("\tThe pointer to the previous policy is %s, to the next policy is %s\n",
           policy->prv == NULL ? "empty (this is the first entry)" : "defined",
           policy->nxt == NULL ? "empty (this is the final entry)" : "defined" );

    if(!((policy->flags & RA_PERMIT) || (policy->flags & RA_DENY))){
       return ;
   }

    printf("\tIn the case of a match, the flow will be %s%s\n",
           (policy->flags & RA_PERMIT) ? "permitted" : "",
           (policy->flags & RA_DENY) ? "denied" : "");

    if (policy->proto == 0) {
       printf("\tThe policy will be applied to flows matching any IP based protocol\n");
    }  else {
        proto = getprotobynumber((int) policy->proto);
        printf("\tThe policy will be applied to flows matching the %s (%d) protocol\n",
           proto->p_name, policy->proto );
    }
    printf("\tThe policy flag value is %lx, which means that a match has these requirements:\n",
           policy->flags);

    if (policy->flags & RA_SRC_SET) {
        printf("\tThe source address will be evaluated:\n");
        printf("\t\tThe source address is %lx (%s) and the source wildcard is %lx (%s)\n",
           policy->src.addr, ArgusGetName(parser, (u_char *) &policy->src.addr), 
           policy->src.mask, ArgusGetName(parser, (u_char *) &policy->src.mask));
        if((policy->src.addr == host) && (policy->src.mask == any)) {
           printf("\t\tThe source may be any IP address\n");
        } else {
          if (policy->src.mask == any) {
              printf("\t\tThe specific host IP address much match\n");
          } else {
            low = policy->src.addr & ~policy->src.mask;
            high = low + policy->src.mask;
            printf("\t\tThe source may be any IP address in the range %s - %s (with possible gaps)\n", 
               ArgusGetName(parser, (u_char *)  &low),
               ArgusGetName(parser, (u_char *) &high));
            }
       } 
    } else {
        printf("\tThe source address will not be evaluated to determine a match\n");
      }


    if (policy->flags & RA_DST_SET) {
        printf("\tThe destination address will be evaluated:\n");
        printf("\t\tThe destination address is %lx (%s) and the destination wildcard is %lx (%s)\n",
           policy->dst.addr, ArgusGetName(parser, (u_char *) &policy->dst.addr), 
           policy->dst.mask, ArgusGetName(parser, (u_char *) &policy->dst.mask));
        if((policy->dst.addr == host) && (policy->dst.mask == any)) {
           printf("\t\tThe destination may be any IP address\n");
        } else {
          if (policy->dst.mask == any) {
              printf("\t\tThe specific host IP address much match\n");
          } else {
            low = policy->dst.addr & ~policy->dst.mask;
            high = low + policy->dst.mask;
            printf("\t\tThe destination may be any IP address in the range %s - %s (with possible gaps)\n", 
               ArgusGetName(parser, (u_char *) &low),
               ArgusGetName(parser, (u_char *) &high));
            }
       } 
    } else {
        printf("\tThe destination address will not be evaluated to determine a match\n");
      }

     if (policy->flags & RA_SRCPORT_SET) {
       printf("\tThe source port will be evaluated and must ");
       switch (policy->src_action){
          case (RA_EQ):
             printf("be equal to %d\n", policy->src_port_low);
             break;
          case (RA_LT):
             printf("be less than %d\n", policy->src_port_low);
             break;
          case (RA_GT):
             printf("be greater than %d\n", policy->src_port_low);
             break;
          case (RA_NEQ):
             printf("not be equal to %d\n", policy->src_port_low);
             break;
          case (RA_RANGE):
             printf("be between %d and  %d\n", policy->src_port_low, policy->src_port_hi);
             break;
      }
    } else {
       printf("\tThe source port will not be evaluated to determine a match\n");
    }
     if (policy->flags & RA_DSTPORT_SET) {
       printf("\tThe destination port will be evaluated and must ");
       switch (policy->dst_action){
          case (RA_EQ):
             printf("be equal to %d\n", policy->dst_port_low);
             break;
          case (RA_LT):
             printf("be less than %d\n", policy->dst_port_low);
             break;
          case (RA_GT):
             printf("be greater than %d\n", policy->dst_port_low);
             break;
          case (RA_NEQ):
             printf("not be equal to %d\n", policy->dst_port_low);
             break;
          case (RA_RANGE):
             printf("be between %d and  %d\n", policy->dst_port_low, policy->dst_port_hi);
             break;
      }
    } else {
       printf("\tThe destination port will not be evaluated to determine a match\n");
    }
   if (policy->flags & RA_TCPFLG_SET) {
      printf("\tThe set of TCP flags from the source will be evaluated and must include:\n\t");
      if (policy->TCPflags & RA_FIN) printf(" FIN ");
      if (policy->TCPflags & RA_SYN) printf(" SYN ");
      if (policy->TCPflags & RA_RST) printf(" RST ");
      if (policy->TCPflags & RA_PSH) printf(" PSH ");
      if (policy->TCPflags & RA_ACK) printf(" ACK ");
      if (policy->TCPflags & RA_URG) printf(" URG ");
      if (policy->TCPflags & RA_ECE) printf(" ECE ");
      if (policy->TCPflags & RA_CWR) printf(" CWR ");
      if (policy->TCPflags & RA_NS) printf(" NS ");
      if (policy->flags & RA_EST_SET) printf(" the TCP session must be established (have the ACK or RST flag set) ");
      printf("\n");
  }
  if (policy->flags & RA_TOS_SET) {
     printf("\tThe TOS must be equal to %d\n", policy->tos);
  }
  if (policy->flags & RA_ICMP_SET) {
     printf("\tThe ICMP message type must be %d ", policy->ICMPtype);
     if (policy->ICMPcode < ICMPCodeAny) {
        printf("and the ICMP message code must be %d\n", policy->ICMPcode);
     } else {
        printf("with any valid ICMP code value\n");
     }
  }
 return ;
}


#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>


// Terminating Error 

events_t
terror (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "terror word is %s [%d]\n", token, strlen(token));
#endif

   printf ("The ACL parser encountered a problem with \"%s\" set debug to 3 for more information\n", token);
   exit (1);
}

events_t 
initACL (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "initACL the word is %s\n", token);
#endif

   policy->type = RA_IPACCESSLIST;
   return E_NULL;
}

events_t 
initEXT (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "initEXT the word is %s\n", token);
#endif

   policy->type = RA_IPACCESSLIST;
   return E_NULL;
}

events_t 
procACLnum (struct RaPolicyPolicyStruct *policy, char *token)
{
   int acl = atoi(token);

#ifdef ARGUSDEBUG
   ArgusDebug (3, "procACLnum the word is %s\n", token);
#endif

   policy->policyID = strdup(token);

//
// The ACL numbers indicate the type of access control list
//
//    1 -   99   Standard IP access list
//  100 -  199   Extended IP access list
//  200 -  299   Ethernet Type Code access list
//  700 -  799   Ethernet Address access control list   
// 1300 - 1999   Standard IP access list
// 2000 - 2699   Extended IP access list
//
// There were other ranges defined but DECnet, IPX, XNS, Vines AppleTalk seem to have fallen out of favor
//
   if (acl > 0 && acl < 100)
      return E_STD;

   if (acl > 1299 && acl < 2000)
      return E_STD;

   if (acl > 99 && acl < 200)
      return E_EXT;

   if (acl > 1999 && acl < 2700)
      return E_EXT;

   if (acl > 199 && acl < 300)
      return E_IGNORE;

   if (acl > 699 && acl < 800)
      return E_IGNORE;

   return E_NULL;
}

events_t 
saveName (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "saveName the word is %s\n", token);
#endif

   policy->policyID = strdup(token);
   return E_NULL;
}

events_t 
notYet (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug  (3, "this capability is not yet available the word is %s\n", token);
#endif

   return E_NULL;
}

events_t 
setAction (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setAction the word is %s\n", token);
#endif

   if ( !strcasecmp("permit", token))
      policy->flags |= RA_PERMIT;
   if ( !strcasecmp("deny", token))
      policy->flags |= RA_DENY;
   return E_NULL;
}

// Set Source Address
events_t
setsAddr (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setsAddr the word is %s\n", token);
#endif

   policy->src.addr = ntohl(inet_addr(token));
   policy->flags |= RA_SRC_SET;
   return E_NULL;
}

// Set Source wildcard
events_t
setswc (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "3, setswc the word is %s\n", token);
#endif

   policy->src.mask = ntohl(inet_addr(token));
   policy->flags |= RA_SRC_SET;
   return E_NULL;
}

// Set a source ANY address
events_t
setsany (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "3, setsany the word is %s\n", token);
#endif

   policy->src.addr = ntohl(inet_addr("0.0.0.0"));
   policy->src.mask = ntohl(inet_addr("255.255.255.255"));
   policy->flags |= RA_SRC_SET;
   return E_NULL;
}

events_t 
finished (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "finished the word is %s\n", token);
#endif

   return E_NULL;
}

events_t 
getSeq (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "getSeq the word is %s\n", token);
#endif

   policy->seq = atoi(token);
   return E_NULL;
}

events_t 
setdAddr (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setdAddr the word is %s\n", token);
#endif

   policy->dst.addr = ntohl(inet_addr(token));
   policy->flags |= RA_DST_SET;
   return E_NULL;
}

events_t 
setdwc (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setdwc the word is %s\n", token);
#endif

   policy->dst.mask = ntohl(inet_addr(token));
   policy->flags |= RA_DST_SET;
   return E_NULL;
}

events_t 
setdany (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setdany the word is %s\n", token);
#endif

   policy->dst.addr = ntohl(inet_addr("0.0.0.0"));
   policy->dst.mask = ntohl(inet_addr("255.255.255.255"));
   policy->flags |= RA_DST_SET;
   return E_NULL;
}

events_t 
setsrel (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setsrel the word is %s\n", token);
#endif

   if (!strcasecmp("eq", token))
      policy->src_action = RA_EQ;
   if (!strcasecmp("ne", token))
      policy->src_action = RA_NEQ;
   if (!strcasecmp("lt", token))
      policy->src_action = RA_LT;
   if (!strcasecmp("gt", token))
      policy->src_action = RA_GT;
   if (!strcasecmp("range", token))
      policy->src_action = RA_RANGE;
   return E_NULL;
}

events_t 
setdrel (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setdrel the word is %s\n", token);
#endif

   if (!strcasecmp("eq", token))
      policy->dst_action = RA_EQ;
   if (!strcasecmp("ne", token))
      policy->dst_action = RA_NEQ;
   if (!strcasecmp("lt", token))
      policy->dst_action = RA_LT;
   if (!strcasecmp("gt", token))
      policy->dst_action = RA_GT;
   if (!strcasecmp("range", token))
      policy->dst_action = RA_RANGE;
   return E_NULL;
}

events_t 
setProto(struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setProto the word is %s\n", token);
#endif

   if (isdigit((int)token[0])) {
      policy->proto = atoi(token);
   } else {
      struct protoent *proto;
      if ((proto = getprotobyname(token)) != NULL)
         policy->proto = proto->p_proto;
   }
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setProto %s is %d\n", token,  policy->proto);
#endif

   policy->flags |= RA_PROTO_SET;
   return E_NULL;
}

events_t 
setsport(struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setsport the word is %s\n", token);
#endif

   policy->src_port_low = (arg_uint16) atoi(token);
   policy->flags |= RA_SRCPORT_SET;
   return E_NULL;
}

events_t 
setdport(struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "sdport the word is %s\n", token);
#endif

   policy->dst_port_low = (arg_uint16) atoi(token);
   policy->flags |= RA_DSTPORT_SET;
   return E_NULL;
}

events_t 
setsport2(struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setsport2 the word is %s\n", token);
#endif

   policy->src_port_hi = (arg_uint16) atoi(token);
   policy->flags |= RA_SRCPORT_SET;
   return E_NULL;
}

events_t 
setdport2(struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setsport2 the word is %s\n", token);
#endif

   policy->dst_port_hi = (arg_uint16) atoi(token);
   policy->flags |= RA_DSTPORT_SET;
   return E_NULL;
}

events_t
setsportname(struct RaPolicyPolicyStruct *policy, char *token)
{
   int port, proto;


   proto = (policy->proto) ?  policy->proto : 17 ;
   argus_nametoport(token, &port, &proto);
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setsportname the word is %s the proto is %d  the port is %d\n", token, proto, port);
#endif
   policy->src_port_low = port;
   policy->flags |= RA_SRCPORT_SET;
   return E_NULL;
}

events_t
setdportname(struct RaPolicyPolicyStruct *policy, char *token)
{
   int port, proto;


   proto = (policy->proto) ?  policy->proto : 17 ; // Or your favorite manifest constant
   argus_nametoport(token, &port, &proto);
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setsportname the word is %s the proto is %d  the port is %d\n", token, proto, port);
#endif
   policy->dst_port_low = port;
   policy->flags |= RA_DSTPORT_SET;
   return E_NULL;
}

events_t 
flagLog(struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "flagLog the word is %s\n", token);
#endif

   policy->flags |= RA_LOG_SET;
   return E_NULL;
}

events_t 
setIGMP(struct RaPolicyPolicyStruct *policy, char *token)
{
   int i;

   for ( i = 0; igmpmap[i].len > 0; i++) {
      if (!strncasecmp(igmpmap[i].name, token, igmpmap[i].len)) {
         policy->IGMPtype = igmpmap[i].value;
#ifdef ARGUSDEBUG
         ArgusDebug (3, "setIGMP the word is %s\n", token);
#endif

         policy->flags |= RA_IGMP_SET;
         return E_NULL;
      }
   }

   // The IGMP type can be expressed as a number
   if (isdigit((int)token[0])) {
      i = atoi(token);
      if (( i > 0) && (i < 256) ) {
         policy->IGMPtype = i;
#ifdef ARGUSDEBUG
         ArgusDebug( 3, "setIGMP the IGMP type is %d\n", i);
#endif

         policy->flags |= RA_IGMP_SET;
         return E_NULL;
      }
   }
#ifdef ARGUSDEBUG
   ArgusDebug (3, "%s is not a valid IGMP type\n", token);
#endif

   return E_NULL;
}

events_t 
setICMPmsg(struct RaPolicyPolicyStruct *policy, char *token)
{
   int i;
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setICMPmsg the word is %s\n", token);
#endif


   for ( i = 0; icmpmap[i].len > 0; i++) {
      if (!strncasecmp(icmpmap[i].name, token, icmpmap[i].len)) {
         policy->ICMPtype = icmpmap[i].value1;
         policy->ICMPcode = icmpmap[i].value2;
         policy->flags |= RA_ICMP_SET;
         return E_NULL;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "setICMPmsg no text match, checking for an integer\n");
#endif


   // The ICMP type can be expressed as an integer as well

   if ( isdigit((int)token[0])) {
      i = atoi(token);
      if (( i >= 0) && (i < 256) ) {
         policy->ICMPtype = i;
         policy->flags |= RA_ICMP_SET;
#ifdef ARGUSDEBUG
         ArgusDebug (3, "setICMPmsg found an integer %d\n", i);
#endif

         i = -1 * ( (int) E_ICMPCODE);
#ifdef ARGUSDEBUG
         ArgusDebug (3, "setICMPmsg injecting event  %d\n", i);
#endif

         return (events_t) i;
      }
   }
#ifdef ARGUSDEBUG
   ArgusDebug (3, "%s is not a valid value for ICMP\n", token);
#endif

   return E_NULL;
}

events_t 
setICMPcode(struct RaPolicyPolicyStruct *policy, char *token)
{
   int i;
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setICMPcode the word is %s\n", token);
#endif


   // this can only be an integer value for the ICMP code

   if ( isdigit((int)token[0])) {
      i = atoi(token);
      if (( i >= 0) && (i < 256) ) {
         policy->ICMPcode = i;
         return E_NULL;
      }
   }
   
#ifdef ARGUSDEBUG
   ArgusDebug (3, "%s is not a valid value for ICMP\n", token);
#endif

   return E_NULL;
}

events_t 
setEst (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setEst the word is %s\n", token);
#endif

   policy->flags |= RA_EST_SET;
   return E_NULL;
}

events_t 
setTCPflag (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setTCPflag the word is %s\n", token);
#endif

   policy->flags |= RA_TCPFLG_SET;
   if ( !strcasecmp("fin", token)) {
      policy->TCPflags |=  RA_FIN;
      policy->flags |= RA_TCPFLG_SET;
      return E_NULL;
   }
   if ( !strcasecmp("syn", token)) {
      policy->TCPflags |=  RA_SYN;
      policy->flags |= RA_TCPFLG_SET;
      return E_NULL;
   }
   if ( !strcasecmp("rst", token)) {
      policy->TCPflags |=  RA_RST;
      policy->flags |= RA_TCPFLG_SET;
      return E_NULL;
   }
   if ( !strcasecmp("psh", token)) {
      policy->TCPflags |=  RA_PSH  ;
       policy->flags |= RA_TCPFLG_SET;
       return E_NULL;
   }
   if ( !strcasecmp("ack", token)) {
      policy->TCPflags |=  RA_ACK  ;
       policy->flags |= RA_TCPFLG_SET;
       return E_NULL;
   }
   if ( !strcasecmp("urg", token)) {
      policy->TCPflags |=  RA_URG  ;
       policy->flags |= RA_TCPFLG_SET;
       return E_NULL;
   }
   if ( !strcasecmp("ece", token)) {
      policy->TCPflags |=  RA_ECE  ;
       policy->flags |= RA_TCPFLG_SET;
       return E_NULL;
   }
   if ( !strcasecmp("cwr", token)) {
     policy->TCPflags |=  RA_CWR  ;
     policy->flags |= RA_TCPFLG_SET;
     return E_NULL;
   }
   if ( !strcasecmp("ns",  token)) {
      policy->TCPflags |=  RA_NS;
      policy->flags |= RA_TCPFLG_SET;
      return E_NULL;
   }
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setTCPflag %s is not a valid TCP flag name\n", token);
#endif

   return E_NULL;
}

events_t 
idle (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "idle the word is %s\n", token);
#endif

   return E_NULL;
}

events_t 
getRemark (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "getRemark the word is %s\n", token);
#endif

   policy->flags = RA_COMMENT;
   return E_NULL;
}

events_t 
flagTOS(struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "flagTOS the word is %s\n", token);
#endif

   policy->flags |= RA_TOS_SET;

// The next token must contain the value for the TOS comparison
// force the token to advance and inject the E_TOSVAL event

   return (events_t) (-1 * (int) E_TOSVAL);
}

events_t 
flagPrecedence (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "flagPrecedence the word is %s\n", token);
#endif

   policy->flags |= RA_PREC_SET;
// The next token must contain the value for the precedence comparison
// force the token to advance and inject the E_PRECEDENCE event

   return (events_t) (-1 * (int) E_PRECEDENCE);
}

events_t 
setPrecValue(struct RaPolicyPolicyStruct *policy, char *token)
{
   int i;

#ifdef ARGUSDEBUG
   ArgusDebug (3, "setPrecValue the word is %s\n", token);
#endif

   for ( i = 0; precmap[i].len > 0; i++) {
      if (!strncasecmp(precmap[i].name, token, precmap[i].len)) {
         policy->precedence = precmap[i].value;
         return E_NULL;
      }
   }
#ifdef ARGUSDEBUG
   ArgusDebug (3, "%s is not a valid value for precedence\n", token);
#endif

   return E_NULL;
}

events_t 
setTOSvalue(struct RaPolicyPolicyStruct *policy, char *token)
{
   int i;

#ifdef ARGUSDEBUG
   ArgusDebug (3, "setTOSvalue the word is %s\n", token);
#endif

   for ( i = 0; tosmap[i].len > 0; i++) {
      if (!strncasecmp(tosmap[i].name, token, tosmap[i].len)) {
         policy->tos = tosmap[i].value;
         return E_NULL;
      }
   }
#ifdef ARGUSDEBUG
   ArgusDebug (3, "%s is not a valid value for tos\n", token);
#endif

   return E_NULL;
}

events_t 
flagDSCP (struct RaPolicyPolicyStruct *policy, char *token)
{
#ifdef ARGUSDEBUG
   ArgusDebug (3, "flagDSCP the word is %s\n", token);
#endif

   policy->flags |= RA_DSCP_SET;

// The next token must contain the value for the DSCP code point 
// force the token to advance and inject the E_DSCPVAL event

   return (events_t) (-1 * (int) E_DSCPVAL);
}

events_t 
setDSCPvalue(struct RaPolicyPolicyStruct *policy, char *token)
{
   int i;

#ifdef ARGUSDEBUG
   ArgusDebug (3, "setDSCPvalue the word is %s\n", token);
#endif

   for ( i = 0; DSCPmap[i].len > 0; i++) {
      if (!strncasecmp(DSCPmap[i].name, token, DSCPmap[i].len)) {
         policy->dscp = DSCPmap[i].value ;
         return E_NULL;
      }
   }
#ifdef ARGUSDEBUG
   ArgusDebug (3, "%s is not a valid DSCP code point name\n", token);
#endif

   return E_NULL;
}

events_t
setProtoParameter(struct RaPolicyPolicyStruct *policy, char *token)
{
   // There are two instances where naked integers show up at the end of an ACL entry
   // both the ICMP and IGMP protocols can have a type parameter expressed as an integer
   // at this point the token is an integer and we need to determine what it represents
   
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setProtoParameters the word is %s the protocol is %d\n", token, policy->proto);
#endif

   switch (policy->proto) {
      case 1: return E_ICMPMSG;
      case 2: return E_IGMPTYPE;
      default: 
#ifdef ARGUSDEBUG
         ArgusDebug (3, "The raw value %s is not appropriate except for protocols ICMP and IGMP\n", token);
#endif


      return E_NULL;
   }
}

events_t 
tokenize (char * word) 
{
   int i;

   if ( word[0] == '\n')
      return E_EOL;

   if (isdigit((int)word[0])) {
      if (strpbrk ( word, ".") == NULL)
         return E_INTEGER;    

      return E_QUAD;

   } else {
      for (i = 0; strings[i].token != E_NULL; i++) {
         if (!strncasecmp(strings[i].symbol, word, strings[i].len) && (strlen(word) == strings[i].len)) 
            return strings[i].token;
      }
   }

   return E_RAWTEXT;
}

int
RaParsePolicy (struct ArgusParserStruct *parser, struct RaPolicyPolicyStruct **pol, char *buf)
{
   char *str = strdup(buf);
   struct RaPolicyPolicyStruct tpolicy;
   char *word = NULL;
   states_t theState, opState;
   events_t event;

   bzero ((char *)&tpolicy, sizeof(tpolicy));

   char labelStr[1024];
#ifdef ARGUSDEBUG
   ArgusDebug (3, "\n Parsing ACL entry: %s\n", buf);   
#endif

   theState = S_START;
   word = strtok(str, " \t\n\r");
   while (word != NULL) {
      event = tokenize(word);
      while ( event != E_NULL) {
         opState = theState;
         // E_LOCAL indicates that the next state is the same as the current state
         theState = stateTable[opState][event].nextState == S_LOCAL ? opState : stateTable[opState][event].nextState;
         if (theState < S_FINAL) 
#ifdef ARGUSDEBUG
            ArgusDebug (3, "entering state machine state = %d [%s] next = %d [%s] event = %d [%s] word = %s (%d)\n",
               opState, stateNames[opState], theState, stateNames[theState], event, eventNames[event], word, strlen(word));
#endif
         event = (stateTable[opState][event].fn)(&tpolicy, word);      
         if (theState == S_NONE) exit (1);
         // the processing of the event may have resulted in a new event being injected 
         // if so, that event either expects the next token or expects the token to remain
         // at its current value. We will use the convention that an event number less than
         // zero indicates the need to advance the token and pass the absolute value of the
         // injected event into the event loop. An positive event number not equal to 
         // E_NULL will result in the event being injected without advancing the token. And
         // an event of E_NULL will tokenize the next token and put the results on the event loop
         // First we handle the simple case of no special action, just get the next token and
         // inject the next event based on the next token.
         if (event == E_NULL) {
            if((word = strtok(NULL, " \t\n\r")) != NULL)
               event = tokenize(word);
         }
         // Otherwise we need to deal with an injected event so check if we need to advance the token
         // without actually tokenizing the result and make the event a non negative value
         if ( (int) event < 0) {
#ifdef ARGUSDEBUG
            ArgusDebug (3, "Found an injected state requiring a new token %d\n", event);
#endif

            event  = (events_t) (-1 * (int) event);
            word = strtok(NULL, " \t\n\r");
         }
         // Otherwise leave the token where it is and just inject the event as is
#ifdef ARGUSDEBUG
            ArgusDebug (3, "Found an injected state NOT requiring a new token %d\n", event);
#endif

      } // the inner while loop handles functions that inject events aka initiates local actions
   }

   if (str) free (str);

   if ((*pol = (struct RaPolicyPolicyStruct *) ArgusCalloc (1, sizeof (**pol))) != NULL) {
      bcopy ((char *)&tpolicy, (char *)*pol, sizeof(**pol));
      (*pol)->str = strdup(buf);
      if (RaGlobalPolicy != NULL){
         (*pol)->policyID = strdup(RaGlobalPolicy->policyID);
         labelStr[0] = 0;
         sprintf (labelStr, "ACL=%s_%s_Line_%4.4d", RaPolicy->flags & RA_PERMIT ? "Permit" : "Deny",
              RaPolicy->policyID, (int) RaPolicy->line);

         (*pol)->labelStr = strdup(labelStr);   
      }
   }

   return 1;
}

int
RaCheckPolicy (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, struct RaPolicyPolicyStruct *policy)
{
   int retn = 0;
   char buffer[1024];
   struct RaPolicyPolicyStruct *base = policy;

//   scan through a doubly linked list of RaPolicyPolicyStruct 
//   comparing the criteria to the contents of the current flow
//      if this is not a protocol controlled by this policy then send the flow
//      if there is a match on a permit entry, then send the flow
//      if there is a match on a deny entry, then drop the flow
//      if there is no match, advance to the next item in the list
//      if there is no next item, drop the flow because of the implicit deny rule
//      Make the appropriate adjustments based on what you are displaying (deny or permit)

   if (policy) {
      while (policy) {
         if ((retn = RaMeetsPolicyCriteria (parser, argus, policy))) {
            if (retn == 1) { return 1;}  //do the permit stuff
            if (retn == 2) { return 0;}  //do the deny stuff
         }
         policy = policy->nxt;
      }
   }

// There is an implicit deny for all unmatched flows, deal with it as if it were an explicit deny

   if (parser->RaPolicyStatus & ARGUS_POLICY_LABEL_IMPLICIT) {
      policy = base;
      sprintf (buffer, "ACL=ImplicitDeny_%s", policy->policyID);
      ArgusAddToRecordLabel (parser, argus, buffer);
   }

   return((parser->RaPolicyStatus &  ARGUS_POLICY_SHOW_DENY) ? 1 : 0);
}


int
RaMeetsPolicyCriteria (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, struct RaPolicyPolicyStruct *policy)
{

//   There are three possible outcomes:
//      There is a match for a permit ACL entry - send the packet = 1
//      There is a match for a deny ACL entry - drop the packet = 2
//      There is no match for a permit or a deny ACL entry - check the next entry = 0
//

   struct ArgusFlow *flow = (void *)argus->dsrs[ARGUS_FLOW_INDEX];
 
   if (flow != NULL) {
      arg_uint32 saddr = 0, daddr = 0;
      arg_uint16 sport = 0, dport = 0;
      u_char proto = flow->ip_flow.ip_p;
      saddr = flow->ip_flow.ip_src;
      daddr = flow->ip_flow.ip_dst;
      sport = flow->ip_flow.sport;
      dport = flow->ip_flow.dport;

#ifdef ARGUSDEBUG
      ArgusDebug (3, "RaMeetsPolicyCriteria for %s line %d: %s\n", 
         policy->policyID, policy->line, policy->str);
#endif

      if (policy->flags & (RA_COMMENT)) 
         return 0;

      if (policy->flags & (RA_PROTO_SET)) {
         if (policy->proto)
            if (proto != (u_char) policy->proto)
               return 0;
      }

      if (policy->flags & (RA_SRC_SET)) {
         if ((saddr & ~policy->src.mask) != policy->src.addr)
            return 0;
      }

      if (policy->flags & (RA_DST_SET)) {
         if ((daddr & ~policy->dst.mask) != policy->dst.addr)
            return 0;
      }

      if (policy->flags & (RA_SRCPORT_SET)) {
         switch (policy->src_action) {
            case  RA_EQ:
               if (sport != policy->src_port_low)
                  return 0;
               break;

            case  RA_LT:
               if (!(sport < policy->src_port_low))
                  return 0;
               break;

            case  RA_GT:
               if (!(sport > policy->src_port_low))
                  return 0;
               break;

            case RA_NEQ:
               if (sport == policy->src_port_low) 
                  return 0;
               break;

            case RA_RANGE:
               if (((sport < policy->src_port_low) || (sport > policy->src_port_hi)))
                  return 0;
               break;
         }
      } // end of  if testing for source port

      if (policy->flags & (RA_DSTPORT_SET)) {
         switch (policy->dst_action) {
            case  RA_EQ:
               if (dport != policy->dst_port_low)
                  return 0;
               break;
            case  RA_LT:
               if (!(dport < policy->dst_port_low))
                  return 0;
               break;
            case  RA_GT:
               if (!(dport > policy->dst_port_low))
                  return 0;
               break;
            case RA_NEQ:
               if (dport == policy->dst_port_low) 
                  return 0;
               break;

            case RA_RANGE:
               if (((dport < policy->dst_port_low) || (dport > policy->dst_port_hi))) 
                  return 0;
               break;
         }
      } // end of if testing for destination port

      if (policy->flags & (RA_EST_SET)) {
         int status = 0;
         struct ArgusNetworkStruct *net = (void *)argus->dsrs[ARGUS_NETWORK_INDEX];

         if (net != NULL) {
            switch (net->hdr.subtype) {
               case ARGUS_TCP_STATUS: {
                  struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;
                  status = tcp->status;
                  break;
               }
               case ARGUS_TCP_PERF: {
                  struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                  status = tcp->status;
                  break;
               }
            }

            if (!(status & ARGUS_SAW_SYN_SENT))
               return (0);
         }
      }

      if (policy->flags & (RA_TCPFLG_SET)) {
         struct ArgusNetworkStruct *net;
         unsigned char sflags = 0;
 
//  Checking the state of the TCP header flags
//
//   Since we are looking at flow records rather than individual packets we need to make some accommodations
//   The Cicso ACL checks for the specific flag's status regardless of the state of any other flag so there is
//   no need to check the state of any of the other flags.There is a credible arguement that the combination of
//   the SYN and the ACK flags is a special case that requires them both to be set in the same packet
//   Since we have aggregated flow data we need to check that combination against the special status indicator
//   rather than the summary of flags seen in the flow
//
//   We check for ESTABLISHED at this time as well since that is simply a description of a set of
//   TCP header flags that meet a specific requirement
//
         if ((net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX]) != NULL) {
            switch (net->hdr.subtype) {
               case ARGUS_TCP_INIT:
               case ARGUS_TCP_STATUS:
               case ARGUS_TCP_PERF: {
                  struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                  sflags = tcp->src.flags;
                  break;
               }
            }

#ifdef ARGUSDEBUG
            ArgusDebug (3, "Policy wants TCPflags to be %x they are %x\n", policy->TCPflags, sflags);
#endif

//   for the Isolationists looking for only the specified flags,  uncomment the next line               
//          if ((policy->TCPflags ^ sflags) != 0 ) return 0;
            if ((policy->TCPflags & sflags) != (policy->TCPflags))
               return 0;
         }
      }
      
      if (policy->flags & (RA_ICMP_SET)) {
         unsigned char type, code;
         type = flow->icmp_flow.type;
         code = flow->icmp_flow.code;

         if (policy->ICMPtype !=  type)
            return 0;

// Cisco has created meta values that translate to type x  with any code value, we
// indicate that as a code value of ICMPCodeAny which indicates that a match of the type is
// the only match requirement, othewise we compare the code value

         if ((code < ICMPCodeAny) && (policy->ICMPcode != code))
            return 0;
      }
//
//   The tos, precedence,  and DSCP code points are closely coupled so we check them against the same
//   Argus value depending on how the ACL specifies the match
//
    {
         struct ArgusIPAttrStruct *ip1 = (void *)argus->dsrs[ARGUS_IPATTR_INDEX];

         if (ip1) {
            if ((policy->flags & (RA_TOS_SET)) && (policy->tos != ((ip1->src.tos >> 1) & 0x0f)))
                return 0;
             
            if ((policy->flags & (RA_DSCP_SET)) && (policy->dscp != (ip1->src.tos >> 2))) 
               return 0;
                
            
                if ((policy->flags & (RA_PREC_SET)) && (policy->precedence != (ip1->src.tos >> 5))) 
                          return(0);
       }
   }


      if (policy->flags & (RA_IGMP_SET)) {
         unsigned char type;
         type = flow->igmp_flow.type;

         if (policy->IGMPtype != type)
            return 0;
      }
      
      if (policy->flags & (RA_PREC_SET)) {
         // TBD Precedence value comparison
      }
      
      if (policy->flags & (RA_DSCP_SET)) {
         // The DSCP Code Point occupies the 6 MSB of the byte. The value in policy->dscp is already
         // left shifted to accommodate this. 
         // TBD - code being tested now
      }

      // If we make it to here we have a good match. Update the counts for this entry

      {
         struct ArgusMetricStruct *metric = (void *)argus->dsrs[ARGUS_METRIC_INDEX];
         policy->hitCount++;

         if (metric != NULL) {
            policy->hitPkts  += metric->src.pkts;
            policy->hitBytes += metric->src.bytes;
         }

         if ((policy->flags & RA_PERMIT) || (policy->flags & RA_DENY)) {
            if ((((parser->RaPolicyStatus & ARGUS_POLICY_LABEL_LOG)) && (policy->flags & RA_LOG_SET)) || 
                         (parser->RaPolicyStatus & ARGUS_POLICY_LABEL_ALL))
            ArgusAddToRecordLabel ( parser, argus, policy->labelStr);
         }

         if (policy->flags & (RA_PERMIT))
            return((parser->RaPolicyStatus &  ARGUS_POLICY_SHOW_DENY) ? 2 : 1);

         if (policy->flags & (RA_DENY))
            return((parser->RaPolicyStatus &  ARGUS_POLICY_SHOW_DENY) ? 1 : 2);
      }
   }

   return 0;
}
