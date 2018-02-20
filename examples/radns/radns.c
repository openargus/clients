/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2016 QoSient, LLC
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
 */

/* 
 * $Id: //depot/gargoyle/clients/examples/radns/radns.c#24 $
 * $DateTime: 2016/11/30 00:54:11 $
 * $Change: 3245 $
 */

/*
 *     radns.c  - process DNS requests from argus data
 *                extract DNS query and response into a DNS structure
 *                that allows for fast processing of DNS relevant data.
 */


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>

#if defined(HAVE_ARPA_INET_H)
#include <arpa/inet.h>
#endif

#include <argus_compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <argus_label.h>

#include <argus_output.h>

#if defined(ARGUS_MYSQL)
#include <mysql.h>

char *ArgusScheduleSQLQuery (struct ArgusParserStruct *, struct ArgusAggregatorStruct *, struct ArgusRecordStruct *, char *, char *, int, int);
int ArgusGrepBuf (regex_t *, char *, char *);

extern char RaSQLSaveTable[];
extern char *ArgusGetSQLSaveTable();

extern int RaSQLDBDeletes;
extern int ArgusDropTable;
extern int ArgusCreateTable;
extern int RaSQLCacheDB;

extern long long ArgusTotalSQLSearches;
extern long long ArgusTotalSQLUpdates;
extern long long ArgusTotalSQLWrites;

extern int ArgusSOptionRecord;

extern pthread_mutex_t RaMySQLlock;
extern MYSQL *RaMySQL;
#endif

#if defined(HAVE_ZLIB_H)
#include <zlib.h>
#endif

#include <interface.h>
#include <radomain.h>

#define RaDomain   1

#include <signal.h>
#include <ctype.h>

const u_char *snapend = NULL;

char ArgusBuf[MAXSTRLEN];
int ArgusThisEflag = 0;
int ArgusDebugTree = 0;

int ArgusDnsCacheTimeout = 0;
char *ArgusPendingSearchCommand = NULL;

struct ArgusNameSpace {
   struct ArgusQueueStruct *tlds;
   struct ArgusHashTable *table;
};

struct ArgusNameSpace *ArgusDNSNameSpace = NULL;
struct ArgusHashTable *ArgusDNSNameTable = NULL;

struct ArgusAggregatorStruct *ArgusEventAggregator = NULL;

void RaArgusInputComplete (struct ArgusInput *input) {};
int RaTreePrinted = 0;
int RaPruneLevel = 0;

#define ARGUS_MAX_RESPONSE		0x100000
#define ARGUS_DEFAULT_RESULTLEN         0x10000

#define ARGUS_NAME_REQUESTED	0x10
#define ARGUS_DNS_MIN_TTL       30

#define ARGUS_DNS_AUTH   	1
#define ARGUS_DNS_CNAME  	2
#define ARGUS_DNS_ALIAS  	3
#define ARGUS_DNS_REFERER	4
#define ARGUS_DNS_PTR		5

struct RaProcessStruct {
   int status, timeout;
   int value, size;
   struct ArgusRecordStruct *ns;
   struct ArgusQueueStruct *queue, *delqueue;
   struct ArgusHashTable *htable;
   struct nff_program filter;
};

struct RaProcessStruct *RaEventProcess = NULL;
struct RaProcessStruct *RaNewProcess(struct ArgusParserStruct *);

extern char *ArgusTrimString (char *);
extern struct tok ns_type2str[];


char **ArgusHandleResponseArray = NULL;

char **ArgusHandleTreeCommand (struct ArgusOutputStruct *, char *);
char **ArgusHandleSearchCommand (struct ArgusOutputStruct *, char *);

char **
ArgusHandleTreeCommand (struct ArgusOutputStruct *output, char *command)
{
   char *string = &command[10], *sptr;
   int slen = strlen(string);
   char **retn = NULL;

   if (ArgusHandleResponseArray == NULL) {
      if ((ArgusHandleResponseArray = ArgusCalloc(ARGUS_DEFAULT_RESULTLEN, sizeof(char *))) == NULL)
         ArgusLog (LOG_ERR, "ArgusHandleSearchCommand: ArgusCalloc error %s\n", strerror(errno));
   }

   retn = ArgusHandleResponseArray;
 
   sptr = &string[slen - 1];
   while (isspace((int)*sptr)) {*sptr-- = '\0';}
 
   retn[0] = "OK\n";

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusHandleTreeCommand(%s) filter %s", string, retn);
#endif
   return retn;
}


void ArgusPrintAddressResponse(char *, struct RaAddressStruct *, char ***, int *, int *);

void
ArgusPrintAddressResponse(char *string, struct RaAddressStruct *raddr, char ***result, int *rind, int *reslen)
{
   struct ArgusListStruct *dns = raddr->dns;

   if (raddr->r != NULL) ArgusPrintAddressResponse(string, raddr->r, result, rind, reslen);
   if (raddr->l != NULL) ArgusPrintAddressResponse(string, raddr->l, result, rind, reslen);

   if (dns != NULL) {
      struct ArgusListObjectStruct *tdns;
      struct timeval tvbuf, *tvp = &tvbuf;
      char tbuf[128], *resbuf;
      int ind = *rind;

      if ((resbuf = ArgusMalloc(ARGUS_MAX_RESPONSE)) == NULL)
         ArgusLog (LOG_ERR, "ArgusPrintAddressResponse: ArgusMalloc error %s\n", strerror(errno));

      bzero(tbuf, sizeof(tbuf));

      ArgusPrintTime(ArgusParser, tbuf, sizeof(tbuf), &raddr->atime);

      RaDiffTime (&raddr->rtime, &raddr->atime, tvp);

      if (raddr->addr.str == NULL) 
         raddr->addr.str = strdup(ArgusGetName (ArgusParser, (unsigned char *)&raddr->addr.addr[0]));

      if (ArgusParser->ArgusPrintJson) {
         sprintf (resbuf, "{ \"stime\":\"%s\", \"addr\":\"%s\"", tbuf, (raddr->addr.str != NULL) ? raddr->addr.str : string);
      } else {
         sprintf (resbuf, "%s: \"%s\" ", tbuf, (raddr->addr.str != NULL) ? raddr->addr.str : string);
      }

#if defined(ARGUS_THREADS)
      if (pthread_mutex_lock(&raddr->dns->lock) == 0) {
#endif
         int auth = 0, refer = 0, ptr = 0;
         int x, cnt = raddr->dns->count;
         int len = strlen(resbuf);

         tdns = raddr->dns->start;
         for (x = 0; x < cnt; x++) {
            switch (tdns->status) {
               case ARGUS_DNS_AUTH:     auth++; break;
               case ARGUS_DNS_REFERER: refer++; break;
               case ARGUS_DNS_PTR:       ptr++; break;
            }
            tdns = tdns->nxt;
         }

         if (auth > 0) {
            int tref = 0;
            tdns = raddr->dns->start;
            if (ArgusParser->ArgusPrintJson) {
               char *buf = ", \"auth\":";
               sprintf (&resbuf[len], "%s", buf);
               len += strlen(buf);
            } else {
               sprintf (&resbuf[len], "%s", "A: ");
               len += 3;
            }

            if (auth > 1) {
               snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "[");
               len++;
            }
  
            for (x = 0; x < cnt; x++) {
               if (tdns->status == ARGUS_DNS_AUTH) {
                  struct nnamemem *tname = (struct nnamemem *) tdns->list_obj;

                  RaDiffTime (&tname->ltime, &tname->stime, tvp);

                  if (tref++ > 0) {
                     snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, ",");
                     len++;
                  }

                  if (ArgusParser->ArgusPrintJson) {
                     snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "\"%s\"", tname->n_name);
                     len = strlen(resbuf);
                  } else {
                     snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "\"%s\"", tname->n_name);
                     len = strlen(resbuf);
                  }
               }
               tdns = tdns->nxt;
            }

            if (auth > 1)
               sprintf (&resbuf[len++], "]");
         }

         if (refer > 0) {
            int tref = 0;
            tdns = raddr->dns->start;
            if (ArgusParser->ArgusPrintJson) {
               char *buf = ", \"refer\":";
               snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "%s", buf);
               len += strlen(buf);
            } else {
               char *buf;
               if (auth > 0) 
                  buf = " REF: ";
               else
                  buf = "REF: ";
               snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "%s", buf);
               len += strlen(buf);
            }

            if (refer > 1)
               sprintf (&resbuf[len++], "[");

            for (x = 0; x < cnt; x++) {
               if (tdns->status == ARGUS_DNS_REFERER) {
                  struct nnamemem *tname = (struct nnamemem *) tdns->list_obj;

                  RaDiffTime (&tname->ltime, &tname->stime, tvp);

                  if (tref++ > 0)
                     sprintf (&resbuf[len++], ",");

                  if (ArgusParser->ArgusPrintJson) {
                     sprintf (&resbuf[len], "\"%s\"", tname->n_name);
                     len = strlen(resbuf);
                  } else {
                     sprintf (&resbuf[len], "\"%s\"", tname->n_name);
                     len = strlen(resbuf);
                  }
               }
               tdns = tdns->nxt;
            }

            if (refer > 1)
               sprintf (&resbuf[len++], "]");
         }

         if (ptr > 0) {
            int tref = 0;
            tdns = raddr->dns->start;
            if (ArgusParser->ArgusPrintJson) {
               char *buf = ", \"ptr\":";
               int slen = snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "%s", buf);
               len += slen;
            } else {
               char *buf;
               if ((auth > 0) || (refer > 0)) 
                  buf = " PTR: ";
               else
                  buf = "PTR: ";
               int slen = snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "%s", buf);
               len += slen;
            }

            if (ptr > 1) {
               int slen = snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "[");
               len += slen;
            }

            for (x = 0; x < cnt; x++) {
               if (tdns->status == ARGUS_DNS_PTR) {
                  struct nnamemem *tname = (struct nnamemem *) tdns->list_obj;
                  if (tref++ > 0) {
                     int slen = snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, ",");
                     len += slen;
                  }

                  if (ArgusParser->ArgusPrintJson) {
                     snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "\"%s\"", tname->n_name);
                  } else {
                     snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "\"%s\"", tname->n_name);
                  }
                  len = strlen(resbuf);
               }
               tdns = tdns->nxt;
            }

            if (ptr > 1) {
               int slen = snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "]");
               len += slen;
            }
         }

         if (ArgusParser->ArgusPrintJson) {
            int slen = snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "}");
            len += slen;
         }

         if (ind >= *reslen) {
            int blen = *reslen * sizeof(char *);
            int nlen = ARGUS_DEFAULT_RESULTLEN * sizeof(char *);

            if ((*result = ArgusRealloc(*result, blen + nlen)) == NULL)
               ArgusLog (LOG_ERR, "ArgusHandleSearchCommand: ArgusCalloc error %s\n", strerror(errno));

            bzero(&(*result)[blen], nlen);
            *reslen += ARGUS_DEFAULT_RESULTLEN;
         }

         (*result)[ind++] = strdup(resbuf);

#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&raddr->dns->lock);
      }
#endif
      ArgusFree(resbuf);
      *rind = ind;
   }
}


extern int ArgusGrepBuf (regex_t *, char *, char *);


/*
 * ArgusHandleSearchCommand - Generates output searches against IPv4 addresses and names.
 * 
 *   This routine will take a search request and attempt to resolve it.
 *   It searches against a DNS patricia tree in order to provide IP addresses for names,
 *   and names for IP addresses.
 * 
 *   The primary use is to provide names for IP addresses.  A CIDR address is provided,
 *   and a list of IP addresses is provided.  The possibilities include:
 *      1) Authoritative Names
 *      2) Aliases - CNAME record data
 *      3) Reverse lookups - PTR record data for the address of interest.
 *      4) Referers - These are the actual names that were asked for that returned addresses of interest.
 *
 *   DNS can associate a large number of IP addresses of a given name, in A records and C records.
 *   These are very important, but the complete lists have purpose in different settings.
 * 
 *   For this routine, without any configuration, we want to return two basic things for a given IP address: 
 *     1) The actual name for an IP Address (Authoritative)
 *     2) The names that were actually used that resolved to a specific address. (Refers)
 *
 *   The syntax of the response is:
 *      Ascii - IPAddrRequest: A: FQDN... REF: FQDN... PTR: FQDN...
 *        23.50.75.27: A: e8218.dscb1.akamaiedge.net. REF: sr.symcd.com. s2.symcb.com. PTR: a23-50-75-27.deploy.static.akamaitechnologies.com. 

 *      JSON  - {
 *                "query" : "IPAddrRequest", 
 *                 "auth" : ["FQDN", ...], 
 *                "refer" : ["FQDN", ...], 
 *                  "ptr" : ["FQDN", ...],
 *              }
 *
 *   To resolve such a query, the block stored for a given address in the client patricia tree (raddr->dns),
 *   needs to contain all this data, as a result, the dns pointer, points to a list of struct nnamemem *.
 *   which should be the 'struct nnamemem *' for the Authoritative address.
 *
 */



char **
ArgusHandleSearchCommand (struct ArgusOutputStruct *output, char *command)
{
   char *cmd = &command[8], *sptr, *string, *str;
   struct ArgusCIDRAddr *cidr = NULL;
   char *resbuf = NULL;
   int reslen = ARGUS_DEFAULT_RESULTLEN;

   int slen = strlen(cmd), options, rege, rind = 0;
   char **retn = NULL;
   struct RaAddressStruct *raddr = NULL;

   regex_t preg;

   str = string = strdup(cmd);

   sptr = &string[slen - 1];
   while (isspace((int)*sptr)) {*sptr-- = '\0';}

   if (ArgusHandleResponseArray == NULL) {
      if ((ArgusHandleResponseArray = ArgusCalloc(reslen, sizeof(char *))) == NULL)
         ArgusLog (LOG_ERR, "ArgusHandleSearchCommand: ArgusCalloc error %s\n", strerror(errno));
   }

   retn = ArgusHandleResponseArray;

   if (resbuf == NULL) {
      if ((resbuf = ArgusMalloc(0x10000 * sizeof(char *)) + 1) == NULL)
         ArgusLog (LOG_ERR, "ArgusHandleSearchCommand: ArgusCalloc error %s\n", strerror(errno));
   }

   while ((sptr = strtok(string, ",")) != NULL) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusHandleSearchCommand: searching for %s", sptr);
#endif

      if ((cidr = RaParseCIDRAddr (ArgusParser, sptr)) != NULL) {
         struct ArgusLabelerStruct *labeler = ArgusParser->ArgusLabeler;
         struct RaAddressStruct node;
         int matchMode = ARGUS_EXACT_MATCH;

         if (cidr->masklen != 32)
            matchMode = ARGUS_MASK_MATCH;
         
         bzero ((char *)&node, sizeof(node));
         bcopy(cidr, &node.addr, sizeof(*cidr));

         if ((raddr = RaFindAddress (ArgusParser, labeler->ArgusAddrTree[AF_INET], &node, matchMode)) != NULL) {
            ArgusPrintAddressResponse(sptr, raddr, &retn, &rind, &reslen);
         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (1, "ArgusHandleSearchCommand: address search %s returned not found", sptr);
#endif
         }

      } else {
#if defined(ARGUS_PCRE)
         options = 0;
#else
         options = REG_EXTENDED | REG_NOSUB;
#if defined(REG_ENHANCED)
         options |= REG_ENHANCED;
#endif
#endif
         options |= REG_ICASE;

         if ((rege = regcomp(&preg, sptr, options)) != 0) {
            char errbuf[MAXSTRLEN];
            if (regerror(rege, &preg, errbuf, MAXSTRLEN)) {
#ifdef ARGUSDEBUG
               ArgusDebug (1, "ArgusHandleSearchCommand: regex error %s", errbuf);
#endif
            }
         } else {
            struct ArgusHashTable *table = ArgusDNSNameTable;
            int i, mind = 0, mlen = 2048;
            int size = ArgusDNSNameTable->size;
            struct nnamemem **matches;

            if ((matches = ArgusCalloc(2048, sizeof(struct nnamemem *))) == NULL)
               ArgusLog (LOG_ERR, "ArgusHandleSearchCommand: ArgusCalloc error %s\n", strerror(errno));

            for (i = 0; i < size; i++) {
               struct ArgusHashTableHdr *hptr;
               if ((hptr = table->array[i]) != NULL) {
                  do {
                     struct nnamemem *name = (struct nnamemem *)hptr->object;

                     if (name && (name->n_name != NULL))
                        if (ArgusGrepBuf (&preg, name->n_name, &name->n_name[strlen(name->n_name)]))
                           matches[mind++] = name;

                  } while ((mind < mlen) && ((hptr = hptr->nxt) != table->array[i]));
               }
            }

            if (mind > 0) {
               for (i = 0; i < mind; i++) {
                  int x, resultnum = 0, done = 0;
                  char *results[2048];
                  struct nnamemem *cname = NULL;
                  struct nnamemem *name = matches[i];
                  bzero(results, sizeof(results));
                  results[resultnum++] = strdup(name->n_name);
                           
                  if (name->cnames != NULL) {
#if defined(ARGUS_THREADS)
                     do {
                        if (name->cnames == NULL) {
                           done = 1;
                        } else {
                           if (pthread_mutex_lock(&name->cnames->lock) == 0) {
#endif
                              int cnt = name->cnames->count;
                              cnt = (cnt >= (2048 - resultnum)) ? (2048 - resultnum) : cnt;
                              struct ArgusListObjectStruct *list = name->cnames->start;

                              for (x = 0; x < cnt; x++) {
                                 cname = (struct nnamemem *)list->list_obj;
                                 results[resultnum++] = strdup(cname->n_name);
                                 list = list->nxt;
                              }
#if defined(ARGUS_THREADS)
                              pthread_mutex_unlock(&name->cnames->lock);
                           }
                           if ((cname != NULL) && (cname != name))
                              name = cname;
                          else
                              done = 1;
                        }
                     } while (!done && (resultnum < 2048));
#endif
                  }

                  if (name->cidrs != NULL) {
#if defined(ARGUS_THREADS)
                     if (pthread_mutex_lock(&name->cidrs->lock) == 0) {
#endif
                        int x, cnt = name->cidrs->count;
                        struct ArgusListObjectStruct *list = name->cidrs->start;
       
                        for (x = 0; x < cnt; x++) {
                           struct RaAddressStruct *raddr = (struct RaAddressStruct *)list->list_obj;
                           unsigned int addr = htonl(raddr->addr.addr[0]);
                           struct in_addr naddr = *(struct in_addr *)&addr;
                           results[resultnum++] = strdup(inet_ntoa(naddr));
                           list = list->nxt;
                        }
#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&name->cidrs->lock);
                     }
#endif
                  }

                  sprintf (resbuf, "%s: %s [", sptr, results[0]);

                  for (x = 1; x < resultnum; x++) {
                              if (x > 1) sprintf (&resbuf[strlen(resbuf)], ", ");
                              sprintf (&resbuf[strlen(resbuf)], "%s", results[x]);
                              free(results[x]);
                  }
                  sprintf (&resbuf[strlen(resbuf)], "]");
                  retn[rind++] = strdup(resbuf);
                  free(results[0]);
               }
            }
         }
      }
      string = NULL;
   }

   free(str);

   if (retn[0] == NULL)
      retn = NULL;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusHandleSearchCommand(%s) returns %s", cmd, (retn != NULL) ? retn[0] : NULL);
#endif
   return retn;
}


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct RaAddressStruct **ArgusAddrTree;
   struct ArgusModeStruct *mode = NULL;

   parser->RaWriteOut  = 1;
   parser->RaPruneMode = 0;

   if (!(parser->RaInitialized)) {

/*
   the library sets signal handling routines for 
   SIGHUP, SIGTERM, SIGQUIT, SIGINT, SIGUSR1, and SIGUSR2.
   SIGHUP doesn't do anything, SIGTERM, SIGQUIT, and SIGINT
   call the user supplied RaParseComplete().  SIGUSR1 and
   SIGUSR2 modify the debug level so if compiled with
   ARGUS_DEBUG support, programs can start generating 
   debug information.  USR1 increments by 1, USR2 sets
   it back to zero.

*/
      (void) signal (SIGHUP,  (void (*)(int)) RaParseComplete);
      ArgusThisEflag = parser->eflag;
      parser->eflag = ARGUS_HEXDUMP;

      if ((ArgusLabeler = ArgusNewLabeler(parser, ARGUS_LABELER_ADDRESS)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      if (ArgusLabeler->ArgusAddrTree == NULL)
         if ((ArgusLabeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog (LOG_ERR, "RaReadAddressConfig: ArgusCalloc error %s\n", strerror(errno));

      ArgusAddrTree = ArgusLabeler->ArgusAddrTree;
      parser->ArgusLabeler = ArgusLabeler;

      ArgusAddrTree = ArgusLabeler->ArgusAddrTree;
      parser->ArgusLabeler = ArgusLabeler;

      if ((parser->ArgusAggregator = ArgusNewAggregator(parser, NULL, ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      if (ArgusAddrTree[AF_INET] != NULL)
         RaLabelMaskAddressStatus(ArgusAddrTree[AF_INET], ~ARGUS_VISITED);

      if ((ArgusEventAggregator = ArgusNewAggregator(parser, "srcid saddr daddr proto sport dport", ARGUS_RECORD_AGGREGATOR)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewAggregator error");

      parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE_VISITED;

      if ((mode = parser->ArgusModeList) != NULL) {
         while (mode) {
            if ((!(strncasecmp (mode->mode, "debug.tree", 10))) ||
                (!(strncasecmp (mode->mode, "debug", 5)))) {
               ArgusDebugTree = 1;
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE;
               RaPrintLabelTree (ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0);
            } else
            if (!(strncasecmp (mode->mode, "search:", 7))) {
               char *ptr = &mode->mode[7];
               if (*ptr != '\0') {
                  char *buf = malloc(0x1000);
                  if (buf != NULL) {
                     snprintf (buf, 0x1000, "SEARCH: %s", ptr);
                     ArgusPendingSearchCommand = buf;
                  }
               }
            } else
            if (!(strncasecmp (mode->mode, "nocontrol", 9))) {
               parser->ArgusControlPort = 0;
            } else
            if (!(strncasecmp (mode->mode, "control:", 8))) {
               char *ptr = &mode->mode[8];
               double value = 0.0;
               char *endptr = NULL;
               value = strtod(ptr, &endptr);
               if (ptr != endptr) {
                  parser->ArgusControlPort = value;
               }
            } else
            if (!(strncasecmp (mode->mode, "timeout:", 8))) {
               char *ptr = &mode->mode[8];
               double value = 0.0;
               char *endptr = NULL;
               value = strtod(ptr, &endptr);
               if (ptr != endptr) {
                  ArgusDnsCacheTimeout = value;
               }
            } else
            if (!(strncasecmp (mode->mode, "graph", 5))) {
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_GRAPH;
            } else
            if (!(strncasecmp (mode->mode, "rmon", 4))) {
               parser->RaMonMode++;
            } else
            if (!(strncasecmp (mode->mode, "prune", 5))) {
               char *ptr, *str;
               parser->RaPruneMode++;
               if ((str = strchr(mode->mode, '/')) != NULL) {
                  RaPruneLevel = strtod(++str, (char **)&ptr);
                  if (ptr == str)
                     ArgusLog (LOG_ERR, "ArgusClientInit: prune syntax error");
               }
            }
            mode = mode->nxt;
         }
      }

      if ((RaEventProcess = RaNewProcess(parser)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: RaNewProcess error");

      if ((ArgusDNSNameTable = ArgusNewHashTable(0x40000)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewHashTable error");

      if ((ArgusDNSNameSpace = (struct ArgusNameSpace *)ArgusCalloc(1, sizeof(*ArgusDNSNameSpace))) != NULL)
         if ((ArgusDNSNameSpace->tlds = ArgusNewQueue()) != NULL)
            ArgusDNSNameSpace->table = ArgusNewHashTable(0x100000);

      parser->RaInitialized++;

      if (parser->ArgusControlPort != 0) {
         struct timeval *tvp = getArgusMarReportInterval(ArgusParser);

         if ((parser->ArgusControlChannel = ArgusNewControlChannel (parser)) == NULL)
            ArgusLog (LOG_ERR, "could not create control channel: %s\n", strerror(errno));

         if (ArgusEstablishListen (parser, parser->ArgusControlChannel,
                                   parser->ArgusControlPort, "127.0.0.1",
                                   ARGUS_VERSION) < 0)
            ArgusLog (LOG_ERR, "setArgusPortNum: ArgusEstablishListen returned %s", strerror(errno));

         if ((tvp->tv_sec == 0) && (tvp->tv_usec == 0)) {
            setArgusMarReportInterval (ArgusParser, "60s");
         }

         ArgusControlCommands[CONTROL_TREE].handler   = ArgusHandleTreeCommand;
         ArgusControlCommands[CONTROL_SEARCH].handler = ArgusHandleSearchCommand;
      }
   }
}


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!(ArgusParser->RaParseCompleting++)) {
         int ArgusExitStatus = 0;
         char **result = NULL;
         ArgusShutDown(sig);

         if (ArgusPendingSearchCommand != NULL) {
            if ((result = ArgusHandleSearchCommand (NULL, ArgusPendingSearchCommand)) != NULL) {
               while (*result != NULL)
                  printf("%s\n", *result++);
            }
         }
        
         if (ArgusDebugTree) {
            if (RaTreePrinted++ == 0) {
               struct ArgusLabelerStruct *labeler = ArgusParser->ArgusLabeler;
               if (labeler && labeler->ArgusAddrTree) {
                  if (ArgusParser->RaPruneMode)
                     RaPruneAddressTree(labeler, labeler->ArgusAddrTree[AF_INET], ARGUS_TREE_PRUNE_LABEL | ARGUS_TREE_DNS_SLD, RaPruneLevel);
                  RaPrintLabelTree (ArgusParser->ArgusLabeler, ArgusParser->ArgusLabeler->ArgusAddrTree[AF_INET], 0, 0);
                  printf("\n");
               }
            }
         }

#ifdef ARGUSDEBUG
         ArgusDebug (1, "RaParseComplete processed %d DNS names\n", ArgusDNSNameTable->count);
#endif

         ArgusDeleteHashTable(ArgusDNSNameTable);
         ArgusExitStatus = ArgusParser->ArgusExitStatus;

         if (ArgusHandleResponseArray != NULL)
            ArgusFree(ArgusHandleResponseArray);

         ArgusCloseParser(ArgusParser);
         exit (ArgusExitStatus);
      }
   }
}


void
ArgusClientTimeout ()
{
   struct ArgusHashTable *table = ArgusDNSNameTable;

   if (ArgusDnsCacheTimeout > 0) {
      if (table && (table->array != NULL)) {

#if defined(ARGUS_THREADS)
         if (pthread_mutex_lock(&table->lock) == 0) {
#endif
            int i, size = table->size;

            for (i = 0; i < size; i++) {
               struct ArgusHashTableHdr *hptr;
               if ((hptr = table->array[i]) != NULL) {
                  struct nnamemem *name = (struct nnamemem *)hptr->object;

                  if ((name != NULL) && ((name->ltime.tv_sec + ArgusDnsCacheTimeout) < ArgusParser->ArgusCurrentTime.tv_sec)) {
#ifdef ARGUSDEBUG
                     ArgusDebug (2, "ArgusClientTimeout() pruning DNS name hash ... remove %s\n", name->n_name);
#endif
                     if ((hptr->nxt = hptr) != NULL) {
                        hptr->nxt = NULL;
                        hptr->prv = NULL;
                        if (hptr == table->array[i])
                           table->array[i] = NULL;
                     } else {
                        hptr->prv->nxt = hptr->nxt;
                        hptr->nxt->prv = hptr->prv;
                        if (hptr == table->array[i])
                           table->array[i] = hptr->nxt;
                     }
/*
struct nnamemem {
   struct nnamemem *n_nxt;
   unsigned int status, hashval, secs, ref;
   char *n_name, *d_name; 
   struct ArgusListStruct *refers;
   struct ArgusListStruct *cidrs;
   struct ArgusListStruct *cnames;
   struct ArgusListStruct *aliases;
   struct ArgusListStruct *ptrs;
};
*/
                     if (name->n_name) free(name->n_name);
//                   if (name->cidrs  != NULL) ArgusDeleteList(name->cidrs, ARGUS_RR_LIST);
//                   if (name->cnames != NULL) ArgusDeleteList(name->cnames, ARGUS_RR_LIST);

                     ArgusFree(name);
                     ArgusFree(hptr);
                  }
               }
            }
#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&table->lock);
         }
#endif
      }
   }

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

   fprintf (stdout, "Radns Version %s\n", version);
   fprintf (stdout, "usage: %s \n", ArgusParser->ArgusProgramName);
   fprintf (stdout, "usage: %s [options] [ra-options]  [- filter-expression]\n", ArgusParser->ArgusProgramName);

   fprintf (stdout, "options: -v          print verbose protocol information.\n");
   fprintf (stdout, "         -s +suser   dump the source user data buffer.\n");
   fprintf (stdout, "            +duser   dump the destination user buffer.\n");
   fflush (stdout);
   exit(1);
}

int RaProcessARecord (struct ArgusParserStruct *, struct ArgusDomainQueryStruct *, struct timeval *);
int RaProcessCRecord (struct ArgusParserStruct *, struct ArgusDomainQueryStruct *, struct timeval *);
int RaProcessSOARecord (struct ArgusParserStruct *, struct ArgusDomainQueryStruct *, struct timeval *);
int RaProcessNSRecord (struct ArgusParserStruct *, struct ArgusDomainQueryStruct *, struct timeval *);
int RaProcessPTRRecord (struct ArgusParserStruct *, struct ArgusDomainQueryStruct *, struct timeval *);

extern int RaInsertAddressTree (struct ArgusParserStruct *, struct ArgusLabelerStruct *, char *);


// ArgusNameEntry will take a FQDN and insert it into a hash table, as well as insert the
// name into a namespace tree.



struct nnamemem *ArgusNameEntry (struct ArgusHashTable *, char *);


struct nnamemem *
ArgusNameEntry (struct ArgusHashTable *table, char *name)
{
   struct nnamemem *retn = NULL;

   if (name && strlen(name)) {
      struct ArgusHashTableHdr *htbl = NULL;
      struct ArgusHashStruct ArgusHash;
      char *lname = strdup(name), *sptr;
      int i;

      bzero(&ArgusHash, sizeof(ArgusHash));
      ArgusHash.len = strlen(name);
      ArgusHash.hash = getnamehash((const u_char *)lname);
      ArgusHash.buf = (unsigned int *)lname;

      for (i = 0; i < ArgusHash.len; i++)
        lname[i] = tolower((int)lname[i]);

      if ((htbl = ArgusFindHashEntry(table, &ArgusHash)) == NULL) {
         if ((retn = ArgusCalloc(1, sizeof(struct nnamemem))) == NULL)
            ArgusLog (LOG_ERR, "ArgusNameEntry: ArgusCalloc error %s\n", strerror(errno));

         retn->hashval = ArgusHash.hash;
         retn->n_name = lname;
         if ((sptr = strstr(retn->n_name, ".in-addr.arpa")) != NULL)
            retn->d_name = sptr + 1;
         else
            retn->d_name = strchr(retn->n_name, '.') + 1;

         ArgusAddHashEntry(table, (void *)retn, &ArgusHash);

#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusNameEntry() adding DNS name %s[%d] total %d\n", retn->n_name, (retn->hashval % table->size), table->count);
#endif

      } else {
         retn = (struct nnamemem *) htbl->object;
         free(lname);
      }
   }

   return retn;
}


//   
//   
//  RaProcessARecord
//
//  This routine will parse out a complete dns A record, and will associate the name with the address.
//  The name is inserted into a name hash, and the address is inserted into an address patricia tree.
//  These are authoritative addresses for domain names, so there can be many addresses per name, and
//  there can be many names for an address.
//
//  The strategy is to have lists of addresses per name, and lists of names per address.
//  That provides back pointers from one data element (name/address) back to the address/name that
//  is associated.
//  
//   The use of the patricia tree indicates that we can seed the tree with the IANA rir database,
//   delegated-ipv4-*-latest like file, to give us a since of what is allocated and what is not.
//   The concept is that the domain name, or parts of the domain name should cover CIDR addresses.
//   And so we can then start to guess what domain a new address may be in.
//   
//   


int
RaProcessARecord (struct ArgusParserStruct *parser, struct ArgusDomainQueryStruct *res, struct timeval *tvp)
{
   struct ArgusLabelerStruct *labeler;
   int retn = 0;

   if ((labeler = parser->ArgusLabeler) == NULL) {
      parser->ArgusLabeler = ArgusNewLabeler(parser, 0L);
      labeler = parser->ArgusLabeler;
      if (labeler->ArgusAddrTree == NULL)
         if ((labeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog(LOG_ERR, "RaProcessARecord: ArgusCalloc error");
   }

// In this routine, we will insert the dns name in the name table and the
// authoritative IP address into the address tree.  Each name and address
// can have multiple values, and so we need to track all the combos.
// 
// Names are hierarchical, with Top Level Domains (TLD) being the root.
// By parsing the names from right to left, we can build the complete name
// space, with a list of TLDs, and then domain names, and then sub-domains
// and finally to hostnames.  Each node in the tree can have multiple NS and
// DNAME/CNAME records associated.  Only terminal nodes should have A records.
// 
// Given all this, we should build the namespace tree from the A records,
// and then use the NS records to reference how to get to these names.
// The DNS flow records should only go to NS targets, for the names they
// serve.

   if ((res != NULL) && (res->ans != NULL)) {
      struct nnamemem *refer = ArgusNameEntry(ArgusDNSNameTable, res->name);
      struct RaAddressStruct *raddr = NULL;
      int i, ttl = 0, count = res->ans->count;

      for (i = 0; i < count; i++) {
         struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->ans, ARGUS_NOLOCK);
         struct ArgusDomainResourceRecord *rr = list->list_union.obj;

         if (rr != NULL) {
            struct ArgusCIDRAddr *cidr = NULL;
            struct RaAddressStruct node;

            bzero ((char *)&node, sizeof(node));

            if (rr->stime.tv_sec == 0)
               rr->stime = *tvp;
            else
               if ((rr->stime.tv_sec > tvp->tv_sec) || ((rr->stime.tv_sec == tvp->tv_sec) &&
                                                        (rr->stime.tv_usec > tvp->tv_usec)))
                  rr->stime = *tvp;

            if (rr->ltime.tv_sec == 0)
               rr->ltime = *tvp;
            else
               if ((rr->ltime.tv_sec < tvp->tv_sec) || ((rr->ltime.tv_sec == tvp->tv_sec) &&
                                                        (rr->ltime.tv_usec < tvp->tv_usec)))
                  rr->ltime = *tvp;

            if ((cidr = RaParseCIDRAddr (parser, rr->data)) != NULL) {
               int tttl, ncidr = 0, ndns = 0;

               struct nnamemem *name = ArgusNameEntry(ArgusDNSNameTable, rr->name);
       
               if (name != NULL) {
                  name->ref++;

                  bcopy(cidr, &node.addr, sizeof(*cidr));
                  bcopy(cidr, &rr->cidr, sizeof(*cidr));

                  if (name->cidrs == NULL) {
                     name->cidrs = ArgusNewList();
                     ncidr = 1;
                  }

                  if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_EXACT_MATCH)) == NULL) {
                     if ((raddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*raddr))) != NULL) {
                        bcopy(&node, raddr, sizeof(node));
                        RaInsertAddress (parser, labeler, NULL, raddr, ARGUS_VISITED);
                        raddr->label = strdup(rr->name);
                        raddr->addr.str = strdup(rr->data);
                        ncidr = 1;
                     }
                  } else {
#if defined(ARGUS_THREADS)
                     if (pthread_mutex_lock(&name->cidrs->lock) == 0) {
#endif
                        int i, cnt = name->cidrs->count;
                        struct ArgusListObjectStruct *list = name->cidrs->start;
                        ncidr = 1;                          

                        for (i = 0; (ncidr == 1) && (i < cnt); i++) {
                           if (raddr == (struct RaAddressStruct *)list->list_obj)
                              ncidr = 0;                          
                           list = list->nxt;
                        }
#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&name->cidrs->lock);
                     }
#endif
                  }

                  if (raddr && (ncidr != 0)) {
                     struct ArgusListObjectStruct *list;
                     if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                        ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

                     list->status = ARGUS_DNS_AUTH;
                     list->list_obj = raddr;
                     ArgusPushFrontList(name->cidrs, (struct ArgusListRecord *)list, ARGUS_LOCK);
                  }

                  if (raddr->dns == NULL)
                     if ((raddr->dns = ArgusNewList()) == NULL)
                        ArgusLog(LOG_ERR, "ArgusNewList: error %s", strerror(errno));

                  ndns = 1;
#if defined(ARGUS_THREADS)
                  if (pthread_mutex_lock(&raddr->dns->lock) == 0) {
#endif
                     int i, cnt = raddr->dns->count;
                     struct ArgusListObjectStruct *list = raddr->dns->start;

                     for (i = 0; (ndns != 0) && (i < cnt); i++) {
                        struct nnamemem *tname = (struct nnamemem *) list->list_obj;
                        if (tname == name)
                           ndns = 0;
                        list = list->nxt;
                     }
#if defined(ARGUS_THREADS)
                     pthread_mutex_unlock(&raddr->dns->lock);
                  }
#endif
                  if (ndns) {
                     struct ArgusListObjectStruct *list;
                     if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                        ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

                     list->status = ARGUS_DNS_AUTH;
                     list->list_obj = name;
                     ArgusPushFrontList(raddr->dns, (struct ArgusListRecord *)list, ARGUS_LOCK);
                  }

                  if (refer != NULL) {
                     ndns = 1;
#if defined(ARGUS_THREADS)
                     if (pthread_mutex_lock(&raddr->dns->lock) == 0) {
#endif
                        int i, cnt = raddr->dns->count;
                        struct ArgusListObjectStruct *list = raddr->dns->start;

                        for (i = 0; (ndns != 0) && (i < cnt); i++) {
                           struct nnamemem *trefer = (struct nnamemem *) list->list_obj;
                           if (trefer == refer)
                              ndns = 0;
                           list = list->nxt;
                        }
#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&raddr->dns->lock);
                     }
#endif
                     if (ndns) {
                        struct ArgusListObjectStruct *list;
                        if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                           ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

                        list->status = ARGUS_DNS_REFERER;
                        list->list_obj = refer;
                        ArgusPushFrontList(raddr->dns, (struct ArgusListRecord *)list, ARGUS_LOCK);
                     }
                  }

                  tttl = ((rr->ttl < ARGUS_DNS_MIN_TTL) ? ARGUS_DNS_MIN_TTL : rr->ttl);
                  ttl = (ttl > tttl) ? ttl : tttl;

                  if ((raddr->atime.tv_sec == 0) || (raddr->atime.tv_sec > tvp->tv_sec))
                     raddr->atime = *tvp;

                  if (raddr->rtime.tv_sec < (tvp->tv_sec + ttl)) {
                     raddr->rtime.tv_sec  = tvp->tv_sec + ttl;
                     raddr->rtime.tv_usec = tvp->tv_usec;
                  }

                  if ((name->stime.tv_sec == 0) || (name->stime.tv_sec > raddr->atime.tv_sec)) {
                     name->stime.tv_sec = raddr->atime.tv_sec;
                     name->stime.tv_usec = raddr->atime.tv_usec;
                  }

                  if ((name->ltime.tv_sec == 0) || (name->ltime.tv_sec < raddr->rtime.tv_sec)) {
                     name->ltime.tv_sec  = raddr->rtime.tv_sec;
                     name->ltime.tv_usec = raddr->rtime.tv_usec;
                  }
               }
            }
         }

         ArgusPushBackList(res->ans, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
      }

      if (refer) {
         if ((refer->stime.tv_sec == 0) || (refer->stime.tv_sec > tvp->tv_sec))
            refer->stime = *tvp;

         if (refer->ltime.tv_sec < (tvp->tv_sec + ttl)) {
            refer->ltime.tv_sec  = tvp->tv_sec + ttl;
            refer->ltime.tv_usec = tvp->tv_usec;
         }
      }
   }

   return retn;
}

//   
//   
//  RaProcessCRecord
//
//  This routine will parse out a complete dns C record, and will associate the list of
//  aliases with a DNS name.  The DNS name may be authoritative or not, and it doesn't matter ...
//  For all the names in the C Record, they are inserted into the DNS name hash. 
//  For each alias, the alias name record is added to the alias list of the c name record.
//  For each aliases, the C name record is added to the cnames list, for back reference.
//
//   

int
RaProcessCRecord (struct ArgusParserStruct *parser, struct ArgusDomainQueryStruct *res, struct timeval *tvp)
{
   struct ArgusLabelerStruct *labeler;
   struct nnamemem *name = NULL, *cname = NULL;
   int retn = 0, ncname = 0;

   if ((labeler = parser->ArgusLabeler) == NULL) {
      parser->ArgusLabeler = ArgusNewLabeler(parser, 0L);
      labeler = parser->ArgusLabeler;
      if (labeler->ArgusAddrTree == NULL)
         if ((labeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog(LOG_ERR, "RaProcessCRecord: ArgusCalloc error");
   }

   if ((res != NULL) && (res->cname != NULL)) {
      int i, count = res->cname->count;
      for (i = 0; i < count; i++) {
         struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->cname, ARGUS_NOLOCK);
         struct ArgusDomainResourceRecord *rr = list->list_union.obj;

         if ((name = ArgusNameEntry(ArgusDNSNameTable, rr->name)) != NULL) {
            if ((cname = ArgusNameEntry(ArgusDNSNameTable, rr->data)) != NULL) {
               if (name->cnames == NULL)
                  name->cnames = ArgusNewList();

#if defined(ARGUS_THREADS)
               if (pthread_mutex_lock(&name->cnames->lock) == 0) {
#endif
                  int i, cnt = name->cnames->count;
                  struct ArgusListObjectStruct *list = name->cnames->start;
                  ncname = 1;

                  for (i = 0; (ncname == 1) && (i < cnt); i++) {
                     if (cname == (struct nnamemem *)list->list_obj)
                        ncname = 0;   
                     list = list->nxt;
                  }
#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&name->cnames->lock);
               }
#endif

               if (ncname != 0) {
                  struct ArgusListObjectStruct *list;
                  if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                     ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

                  list->status = ARGUS_DNS_CNAME;
                  list->list_obj = cname;
                  ArgusPushFrontList(name->cnames, (struct ArgusListRecord *)list, ARGUS_LOCK);
               }

               if (cname->aliases == NULL)
                  cname->aliases = ArgusNewList();
               
#if defined(ARGUS_THREADS)
               if (pthread_mutex_lock(&cname->aliases->lock) == 0) {
#endif   
                  int i, cnt = cname->aliases->count;
                  struct ArgusListObjectStruct *list = cname->aliases->start;
                  ncname = 1;
                  
                  for (i = 0; (ncname == 1) && (i < cnt); i++) {
                     if (name == (struct nnamemem *)list->list_obj)
                        ncname = 0;   
                     list = list->nxt;
                  }  
#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&cname->aliases->lock);
               }  
#endif  
               if (ncname != 0) {
                  struct ArgusListObjectStruct *list;
                  if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                     ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

                  list->status = ARGUS_DNS_ALIAS;
                  list->list_obj = name;
                  ArgusPushFrontList(cname->aliases, (struct ArgusListRecord *)list, ARGUS_LOCK);
               }
            }

            if ((name->stime.tv_sec == 0) || (name->stime.tv_sec > tvp->tv_sec))
               name->stime = *tvp;

            if ((name->ltime.tv_sec == 0) || (name->ltime.tv_sec < tvp->tv_sec))
               name->ltime = *tvp;
         }

         ArgusPushBackList(res->cname, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
      }
   }

   return retn;
}


//
//
//  RaProcessNSRecord
//
//  This routine will process a dns NS record.  The key is to insert the responses data
//  record, and associate it with the domain name it referenced.
//  
//  NS records can provide scoping for names that we're tracking.  we can, not a hard
//  attribute, but something that can be used to detect inconsistencies of DNS behavior.
//
//

int
RaProcessNSRecord (struct ArgusParserStruct *parser, struct ArgusDomainQueryStruct *res, struct timeval *tvp)
{
   struct nnamemem *ptr = NULL, *name = NULL;
   struct ArgusLabelerStruct *labeler;
   int retn = 0;

   if ((labeler = parser->ArgusLabeler) == NULL) {
      parser->ArgusLabeler = ArgusNewLabeler(parser, 0L);
      labeler = parser->ArgusLabeler;
      if (labeler->ArgusAddrTree == NULL)
         if ((labeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog(LOG_ERR, "RaProcessNSRecord: ArgusCalloc error");
   }

   if ((res != NULL) && (res->ns != NULL)) {
      int x, count = res->ns->count;
      for (x = 0; x < count; x++) {
         struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->ns, ARGUS_NOLOCK);
         struct ArgusDomainResourceRecord *rr = list->list_union.obj;

         if ((ptr = ArgusNameEntry(ArgusDNSNameTable, rr->name)) != NULL) {

            if ((name = ArgusNameEntry(ArgusDNSNameTable, rr->data)) != NULL) {
               char *nptr = strdup(rr->name);
               char *tptr;

               if ((tptr = nptr) != NULL) {
                  free (nptr);
               }
            }
         }

         ArgusPushBackList(res->ns, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
      }
   }

   return retn;
}


//
//
//  RaProcessSOARecord
//
//  This routine will process a dns SOA record.  The key is to insert the responses data
//  record, and associate it with the domain name it referenced.
//  
//  SOA records can provide scoping for names that we're tracking.  we can, not a hard
//  attribute, but something that can be used to detect inconsistencies of DNS behavior.
//
//

int
RaProcessSOARecord (struct ArgusParserStruct *parser, struct ArgusDomainQueryStruct *res, struct timeval *tvp)
{
   struct nnamemem *ptr = NULL;
   struct ArgusLabelerStruct *labeler;
   char *data;
   int retn = 0;

   if ((labeler = parser->ArgusLabeler) == NULL) {
      parser->ArgusLabeler = ArgusNewLabeler(parser, 0L);
      labeler = parser->ArgusLabeler;
      if (labeler->ArgusAddrTree == NULL)
         if ((labeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog(LOG_ERR, "RaProcessCRecord: ArgusCalloc error");
   }

   if ((res != NULL) && (res->soa != NULL)) {
      int x, count = res->soa->count;
      for (x = 0; x < count; x++) {
         struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->soa, ARGUS_NOLOCK);
         struct ArgusDomainResourceRecord *rr = list->list_union.obj;

         if ((ptr = ArgusNameEntry(ArgusDNSNameTable, rr->name)) != NULL) {
            if ((data = rr->data) != NULL) {
            }
         }
         ArgusPushBackList(res->soa, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
      }
   }

   return retn;
}



//
//
//  RaProcessPTRRecord
//
//  This routine will process a dns PTR record.  The key is to insert the responses name
//  record, and associate it with the CIDR address it referenced.  We get the CIDR address
//  from reverse address in the name, look it up or install it in the address table.
//  
//  PTR records can provide the ability to forward-verify a DNS / IP address pair.  we can
//  set this status in the name record, if we can find a match between the name returned in
//  the PTR record with names associated with the address.
//
//

int
RaProcessPTRRecord (struct ArgusParserStruct *parser, struct ArgusDomainQueryStruct *res, struct timeval *tvp)
{
   struct nnamemem *ptr = NULL, *name = NULL;
   struct ArgusLabelerStruct *labeler;
   int retn = 0;

   if ((labeler = parser->ArgusLabeler) == NULL) {
      parser->ArgusLabeler = ArgusNewLabeler(parser, 0L);
      labeler = parser->ArgusLabeler;
      if (labeler->ArgusAddrTree == NULL)
         if ((labeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog(LOG_ERR, "RaProcessCRecord: ArgusCalloc error");
   }

   if ((res != NULL) && (res->ptr != NULL)) {
      int i, x, count = res->ptr->count;
      for (x = 0; x < count; x++) {
         struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->ptr, ARGUS_NOLOCK);
         struct ArgusDomainResourceRecord *rr = list->list_union.obj;

         if ((ptr = ArgusNameEntry(ArgusDNSNameTable, rr->name)) != NULL) {
            if ((name = ArgusNameEntry(ArgusDNSNameTable, rr->data)) != NULL) {
               char *nptr = strdup(rr->name);
               char *sptr, *tptr;

               if ((tptr = nptr) != NULL) {
                  char addrbuf[48], *addr = addrbuf, *a[4];
                  struct RaAddressStruct *raddr = NULL, node;
                  struct ArgusCIDRAddr *cidr = NULL;

                  if ((sptr = strstr(tptr, ".in-addr.arpa")) != NULL) {
                     int ind = 0;

                     bzero(addrbuf, sizeof(addrbuf));

                     *sptr = '\0';
                     while ((sptr = strtok(tptr, ".")) != NULL) {
                        a[ind++] = strdup(sptr);
                        tptr = NULL;
                     }
                     sprintf (addr, "%s.%s.%s.%s", a[3], a[2], a[1], a[0]);
                     for (i = 0; i < 4; i++) free(a[i]);
                  }

                  if ((cidr = RaParseCIDRAddr (ArgusParser, addr)) != NULL) {
                     int ndns, cnt;
                     int ncidr = 0;

                     bzero ((char *)&node, sizeof(node));
                     bcopy(cidr, &node.addr, sizeof(*cidr));

                     if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_EXACT_MATCH)) == NULL) {
                        if ((raddr = (struct RaAddressStruct *) ArgusMalloc (sizeof(*raddr))) != NULL) {
                           int ttl = 0, tttl;

                           bcopy(&node, raddr, sizeof(node));
                           RaInsertAddress (parser, labeler, NULL, raddr, ARGUS_VISITED);
                           raddr->label = strdup(rr->data);
                           tttl = ((rr->ttl < ARGUS_DNS_MIN_TTL) ? ARGUS_DNS_MIN_TTL : rr->ttl);
                           ttl = (ttl > tttl) ? ttl : tttl;

                           if ((raddr->atime.tv_sec == 0) || (raddr->atime.tv_sec > tvp->tv_sec))
                              raddr->atime = *tvp;

                           if (raddr->rtime.tv_sec < (tvp->tv_sec + ttl)) {
                              raddr->rtime.tv_sec  = tvp->tv_sec + ttl;
                              raddr->rtime.tv_usec = tvp->tv_usec;
                           }
                        }
                     }

                     if (raddr->dns == NULL)
                        if ((raddr->dns = ArgusNewList()) == NULL)
                           ArgusLog(LOG_ERR, "ArgusNewList: error %s", strerror(errno));

                     ndns = 1;
#if defined(ARGUS_THREADS)
                     if (pthread_mutex_lock(&raddr->dns->lock) == 0) {
#endif
                        int cnt = raddr->dns->count;
                        struct ArgusListObjectStruct *list = raddr->dns->start;

                        for (i = 0; (ndns != 0) && (i < cnt); i++) {
                           struct nnamemem *tname = (struct nnamemem *) list->list_obj;
                           if ((tname == name) && (list->status == ARGUS_DNS_PTR))
                              ndns = 0;
                           list = list->nxt;
                        }
#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&raddr->dns->lock);
                     }
#endif
                     if (ndns) {
                        struct ArgusListObjectStruct *list;
                        if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                           ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

                        list->status = ARGUS_DNS_PTR;
                        list->list_obj = name;
                        ArgusPushFrontList(raddr->dns, (struct ArgusListRecord *)list, ARGUS_LOCK);
                     }

                     if (name->cidrs == NULL)
                        name->cidrs = ArgusNewList();

#if defined(ARGUS_THREADS)
                     if (pthread_mutex_lock(&name->cidrs->lock) == 0) {
#endif
                        struct ArgusListObjectStruct *list = name->cidrs->start;
                        cnt = name->cidrs->count;

                        for (i = 0, ncidr = 1; (ncidr == 1) && (i < cnt); i++) {
                           if (raddr == (struct RaAddressStruct *)list->list_obj)
                              ncidr = 0;
                           list = list->nxt;
                        }
#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&name->cidrs->lock);
                     }
#endif
                     if (raddr && (ncidr != 0)) {
                        struct ArgusListObjectStruct *list;
                        if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                           ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

                        list->status = ARGUS_DNS_PTR;
                        list->list_obj = raddr;
                        ArgusPushFrontList(name->cidrs, (struct ArgusListRecord *)list, ARGUS_LOCK);
                     }
                  }
                  free (nptr);
               }
            }
         }

         ArgusPushBackList(res->ptr, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
      }
   }

   return retn;
}


#define ISPORT(p) (dport == (p) || sport == (p))

void RaProcessEventRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessThisEventRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessManRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   char buf[MAXSTRLEN], tbuf[64], *tptr;

   bzero (buf, MAXSTRLEN);
   bzero (tbuf, 64);
   ArgusPrintStartDate(parser, tbuf, argus, 32);
   tptr = ArgusTrimString(tbuf);

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_EVENT:
         RaProcessEventRecord(parser, argus);
         break;

      case ARGUS_MAR:
         RaProcessManRecord(parser, argus);
         break;

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
         struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX];

         struct timeval tvpbuf, *tvp = RaGetLastTime(argus, &tvpbuf);

         unsigned short proto = 0, sport = 0, dport = 0;
         int type, process = 0, dnsTransaction = 0;
         unsigned int dnsAddrType = 0;
         struct RaAddressStruct *dnsNode = NULL;
         void *dnsServer = NULL;
         void *daddr = NULL;

         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch ((type = flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_IPV4: {
                        daddr = &flow->ip_flow.ip_dst;
                        proto = flow->ip_flow.ip_p;
                        process++;

                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_TCP: {
                              if (net != NULL) {
                                 struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                                 if (!(argus->hdr.cause & ARGUS_START))
                                    process = 0;
                                 else {
                                    if (!((tcp->status & ARGUS_SAW_SYN) || (tcp->status & ARGUS_SAW_SYN_SENT)))
                                       process = 0;
                                 }
                              }
                           }
                           case IPPROTO_UDP: {
                              sport = flow->ip_flow.sport;
                              dport = flow->ip_flow.dport;
                              break;
                           }
                        }
                        dnsAddrType = RaIPv4AddressType(parser, *(unsigned int *)daddr);
                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        switch (flow->ipv6_flow.ip_p) {
                           case IPPROTO_TCP:
                           case IPPROTO_UDP: {
                              daddr = &flow->ipv6_flow.ip_dst;
                              proto = flow->ipv6_flow.ip_p;
                              sport = flow->ipv6_flow.sport;
                              dport = flow->ipv6_flow.dport;
                              break;
                           }
                        }
                        break;
                     }
                  }
                  break;
               }
            }
         }

         if (process) {
            switch (proto) {
               case IPPROTO_UDP: 
               case IPPROTO_TCP: {
                  if (ISPORT(NAMESERVER_PORT) || ISPORT(MULTICASTDNS_PORT)) {
                     dnsTransaction++;

                     switch (dnsAddrType) {
                        case ARGUS_IPV4_UNICAST: 
                        case ARGUS_IPV4_UNICAST_THIS_NET: 
                        case ARGUS_IPV4_UNICAST_PRIVATE: 
                        case ARGUS_IPV4_UNICAST_LINK_LOCAL: 
                        case ARGUS_IPV4_UNICAST_LOOPBACK: 
                        case ARGUS_IPV4_UNICAST_TESTNET: 
                        case ARGUS_IPV4_UNICAST_RESERVED: 
                           dnsServer = daddr;
                           break;
 
                        case ARGUS_IPV4_MULTICAST:
                        case ARGUS_IPV4_MULTICAST_LOCAL:
                        case ARGUS_IPV4_MULTICAST_INTERNETWORK:
                        case ARGUS_IPV4_MULTICAST_RESERVED:
                        case ARGUS_IPV4_MULTICAST_SDPSAP:
                        case ARGUS_IPV4_MULTICAST_NASDAQ:
                        case ARGUS_IPV4_MULTICAST_DIS:
 
                        case ARGUS_IPV4_MULTICAST_SRCSPEC:
                        case ARGUS_IPV4_MULTICAST_GLOP:
 
                        case ARGUS_IPV4_MULTICAST_ADMIN:
                        case ARGUS_IPV4_MULTICAST_SCOPED:
                        case ARGUS_IPV4_MULTICAST_SCOPED_ORG_LOCAL:
                        case ARGUS_IPV4_MULTICAST_SCOPED_SITE_LOCAL:
                        case ARGUS_IPV4_MULTICAST_SCOPED_REL:
 
                        case ARGUS_IPV4_MULTICAST_ADHOC:
                        case ARGUS_IPV4_MULTICAST_ADHOC_BLK1:
                        case ARGUS_IPV4_MULTICAST_ADHOC_BLK2:
                        case ARGUS_IPV4_MULTICAST_ADHOC_BLK3:
                           break;
                     }
                  }
                  break;
               }
            }

            if (dnsTransaction) {
               struct ArgusDomainStruct dnsbuf, *dns = NULL;
               bzero (&dnsbuf, sizeof(dnsbuf));

               if (dnsServer != NULL) {
                  struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;
                  struct RaAddressStruct *raddr = NULL, node;

                  bzero ((char *)&node, sizeof(node));
                  node.addr.type = AF_INET;
                  node.addr.addr[0] = *(unsigned int *)dnsServer;
                  node.addr.mask[0] = 0xFFFFFFFF;
                  node.addr.masklen = 32;
                  node.addr.len = 4;

                  if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_EXACT_MATCH)) == NULL) {
                     if (!parser->qflag)
                        fprintf (stdout, "%s: RaProcessRecord: new DNS server %s\n", tptr, intoa(node.addr.addr[0]));

                     if ((raddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*raddr))) != NULL) {
                        bcopy(&node, raddr, sizeof(node));
                        RaInsertAddress (parser, labeler, NULL, raddr, ARGUS_VISITED);
                     }

                  }
                  dnsNode = raddr;
               }

               if ((dns = ArgusParseDNSRecord(parser, argus, &dnsbuf)) != NULL) {
                  struct ArgusDomainQueryStruct *req = dns->request;
                  struct ArgusDomainQueryStruct *res = dns->response;

                  dns->server = dnsNode;

                  bzero (buf, MAXSTRLEN);
                  if (req && res) {
                     if ((req->name && strlen(req->name)) && (res->name && strlen(res->name))) {
                        if (req->seqnum == res->seqnum) {
                           if (!(strcasecmp(req->name, res->name))) {
                              if (req->qtype != T_SOA) {
                              if (res->ans)
                                 RaProcessARecord(parser, res, tvp);

                              if (res->soa)
                                 RaProcessSOARecord(parser, res, tvp);

                              if (res->ns)
                                 RaProcessNSRecord(parser, res, tvp);

                              if (res->cname)
                                 RaProcessCRecord(parser, res, tvp);

                              if (res->ptr)
                                 RaProcessPTRRecord(parser, res, tvp);
                              }

                              if (!parser->qflag) {
//  Print the response
                                 char *type = (char *)tok2str(ns_type2str, "Type%d", req->qtype);

                                 fprintf (stdout, "%s: %s? %s : ", tptr, type, res->name);

                                 if (res->ans) {
                                    int i, count = res->ans->count;
                                    type = (char *)tok2str(ns_type2str, "Type%d", res->qtype);

                                    for (i = 0; i < count; i++) {
                                       struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->ans, ARGUS_NOLOCK);
                                       struct ArgusDomainResourceRecord *rr = list->list_union.obj;

                                       type = (char *)tok2str(ns_type2str, "Type%d", rr->type);
                                       if (i == 0) fprintf (stdout, " %s %s %s[%d]", type, rr->name, rr->data, rr->ttl);
                                       else fprintf (stdout, ",%s[%d]", rr->data, rr->ttl);
                                       ArgusPushBackList(res->ans, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                    }
                                 }

                                 if (res->cname) {
                                    int i, count = res->cname->count;
                                    for (i = 0; i < count; i++) {
                                       struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->cname, ARGUS_NOLOCK);
                                       struct ArgusDomainResourceRecord *rr = list->list_union.obj;

                                       type = (char *)tok2str(ns_type2str, "Type%d", rr->type);
                                       fprintf (stdout, " %s %s %s", type, rr->name, rr->data);
                                       ArgusPushBackList(res->cname, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                    }
                                 }

                                 if (res->soa) {
                                    int i, count = res->soa->count;

                                    for (i = 0; i < count; i++) {
                                       struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->soa, ARGUS_NOLOCK);
                                       struct ArgusDomainResourceRecord *rr = list->list_union.obj;

                                       type = (char *)tok2str(ns_type2str, "Type%d", rr->type);

                                       if (i == 0) fprintf (stdout, " %s %s %s %s %d %d %d %d %d", type, rr->name,
                                          rr->mname, rr->rname, rr->serial, rr->refresh, rr->retry, rr->expire, rr->minimum);
                                       else fprintf (stdout, ",%s", rr->mname);
                                       ArgusPushBackList(res->soa, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                    }
                                 }

                                 if (res->ns) {
                                    int i, count = res->ns->count;
                                    
                                    for (i = 0; i < count; i++) {
                                       struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->ns, ARGUS_NOLOCK);
                                       struct ArgusDomainResourceRecord *rr = list->list_union.obj;
                                       
                                       type = (char *)tok2str(ns_type2str, "Type%d", rr->type);
                                       if (i == 0) fprintf (stdout, " %s %s %s[%d]", type, rr->name, rr->data, rr->ttl);
                                       else fprintf (stdout, ",%s[%d]", rr->data, rr->ttl);
                                       ArgusPushBackList(res->ns, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                    }  
                                 }
                                 if (res->ptr) {
                                    int i, count = res->ptr->count;

                                    for (i = 0; i < count; i++) {
                                       struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->ptr, ARGUS_NOLOCK);
                                       struct ArgusDomainResourceRecord *rr = list->list_union.obj;

                                       type = (char *)tok2str(ns_type2str, "Type%d", rr->type);
                                       if (i == 0) fprintf (stdout, " %s %s %s[%d]", type, rr->name, rr->data, rr->ttl);
                                       else fprintf (stdout, ",%s[%d]", rr->data, rr->ttl);
                                       ArgusPushBackList(res->ptr, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                    }
                                 }
                              }

                           } else
                              if (res->ans) {
#if defined(ARGUSDEBUG)
                                 ArgusDebug(1, "%s: radns: request/response name mismatch req:%s res:%s\n", tptr, req->name, res->name);
#endif
                              }
                        } else
                           if (res->ans) {
#if defined(ARGUSDEBUG)
                              ArgusDebug(1, "%s: radns: request/response seq mismatch req:%d res:%d\n", tptr, req->seqnum, res->seqnum);
#endif
                           }
                     }
                     if (!parser->qflag) fprintf (stdout, "\n");
                     fflush(stdout);
                  }

                  if (dns->request != NULL) {
                     struct ArgusDomainQueryStruct *query = dns->request;
                     if (query != NULL) {
                        if (query->name  != NULL) free(query->name);
                        if (query->ans   != NULL) ArgusDeleteList(query->ans,   ARGUS_RR_LIST);
                        if (query->cname != NULL) ArgusDeleteList(query->cname, ARGUS_RR_LIST);
                        if (query->ns    != NULL) ArgusDeleteList(query->ns,    ARGUS_RR_LIST);
                     }
                  }

                  if (dns->response != NULL) {
                     struct ArgusDomainQueryStruct *query = dns->response;
                     if (query != NULL) {
                        if (query->name  != NULL) free(query->name);
                        if (query->ans   != NULL) ArgusDeleteList(query->ans,   ARGUS_RR_LIST);
                        if (query->cname != NULL) ArgusDeleteList(query->cname, ARGUS_RR_LIST);
                        if (query->ns    != NULL) ArgusDeleteList(query->ns,    ARGUS_RR_LIST);
                     }
                  }
               }

            } else {
               struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;
               struct RaAddressStruct *raddr = NULL, node;

               if (labeler != NULL) {
                  extern int ArgusTestMulticast( struct ArgusInput *input, unsigned int);
                  unsigned int addr;

                  if ((daddr != NULL) && (addr = *(unsigned int *)daddr)) {
                     if (!(ArgusTestMulticast(argus->input, addr))) {
                        bzero ((char *)&node, sizeof(node));

                        node.addr.type = AF_INET;
                        node.addr.addr[0] = addr;
                        node.addr.mask[0] = 0xFFFFFFFF;
                        node.addr.masklen = 32;
                        node.addr.len = 4;

                        if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_EXACT_MATCH)) == NULL) {
                           fprintf (stdout, "%s: RaProcessRecord: no DNS cache for remote address %s\n", tptr, intoa(node.addr.addr[0]));

                           if ((raddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*raddr))) != NULL) {
                              bcopy(&node, raddr, sizeof(node));
                              RaInsertAddress (parser, labeler, NULL, raddr, ARGUS_VISITED);
                           }

                        } else {
                           struct ArgusListStruct *list = raddr->dns;

                           if (list != NULL) {
                              
                           }

                           if (raddr->rtime.tv_sec < tvp->tv_sec)
                              raddr->rtime.tv_sec = tvp->tv_sec;
                        }
                     }
                  }
               }
            }
         }
         break;
      }
   }
}


void
RaProcessEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   if (parser->ArgusCorrelateEvents) {
      struct ArgusTimeObject *time = (void *)argus->dsrs[ARGUS_TIME_INDEX];
      struct ArgusDataStruct *data = NULL;
      struct timeval tvpbuf, *tvp = &tvpbuf;
      char buf[0x10000], *ptr = buf;
      char tbuf[129], sbuf[129], *sptr = sbuf;
      char *dptr, *str;
      unsigned long len = 0x10000;
      int title = 0;

      if ((data = (void *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) == NULL)
         return;

      if (data->hdr.subtype & ARGUS_DATA_COMPRESS) {
#if defined(HAVE_ZLIB_H)
         bzero (ptr, sizeof(buf));
         uncompress((Bytef *)ptr, (uLongf *)&len, (Bytef *)&data->array, data->count);
         dptr = ptr;
#else
#if defined(ARGUSDEBUG)
         ArgusDebug (3, "RaProcessEventRecord: unable to decompress payload\n");
#endif
         return;
#endif
      } else {
         dptr = data->array;
      }

      if (strstr(dptr, "argus-lsof")) {
         tbuf[0] = '\0';
         bzero (sptr, sizeof(sbuf));
         tvp->tv_sec  = time->src.start.tv_sec;
         tvp->tv_usec = time->src.start.tv_usec;

         ArgusPrintTime(parser, tbuf, sizeof(tbuf), tvp);
         ArgusPrintSourceID(parser, sptr, argus, 24);

         while (isspace((int)sbuf[strlen(sbuf) - 1]))
            sbuf[strlen(sbuf) - 1] = '\0';

         while (isspace((int)*sptr)) sptr++;

// COMMAND     PID           USER   FD   TYPE     DEVICE SIZE/OFF   NODE NAME

         while ((str = strsep(&dptr, "\n")) != NULL) {
            if (title) {
               char *tok, *app = NULL, *pid = NULL, *user = NULL;
               char *node = NULL, *name = NULL, *state = NULL;
               int field = 0;
               while ((tok = strsep(&str, " ")) != NULL) {
                  if (*tok != '\0') {
                     switch (field++) {
                        case 0: app  = tok; break;
                        case 1: pid  = tok; break;
                        case 2: user = tok; break;
                        case 7: node = tok; break;
                        case 8: name = tok; break;
                        case 9: state = tok; break;
                     }
                  }
               }
               if (name != NULL) {
                  short proto = 0;

                  if (!(strcmp("TCP", node))) proto = IPPROTO_TCP;
                  else if (!(strcmp("UDP", node))) proto = IPPROTO_UDP;

                  if ((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {
                     struct ArgusFlow flowbuf, *flow = &flowbuf;
                     char *saddr = NULL, *daddr = NULL;
                     char *sport = NULL, *dport = NULL;
                     field = 0;

                     if (strstr(name, "->") != NULL) {
                        struct ArgusCIDRAddr *cidr = NULL, scidr, dcidr;
                        int sPort = 0, dPort = 0;

                        if (strchr(name, '[')) {
                           while ((tok = strsep(&name, "[]->")) != NULL) {
                              if (*tok != '\0') {
                                 switch (field++) {
                                    case 0: saddr  = tok; break;
                                    case 1: sport  = tok+1; break;
                                    case 2: daddr = tok; break;
                                    case 3: dport = tok+1; break;
                                 }
                              }
                           }
                        } else {
                           while ((tok = strsep(&name, ":->")) != NULL) {
                              if (*tok != '\0') {
                                 switch (field++) {
                                    case 0: saddr  = tok; break;
                                    case 1: sport  = tok; break;
                                    case 2: daddr = tok; break;
                                    case 3: dport = tok; break;
                                 }
                              }
                           }
                        }

                        if (daddr && ((cidr = RaParseCIDRAddr (parser, saddr)) != NULL))
                           bcopy ((char *)cidr, (char *)&scidr, sizeof (*cidr));

                        if (daddr && ((cidr = RaParseCIDRAddr (parser, daddr)) != NULL))
                           bcopy ((char *)cidr, (char *)&dcidr, sizeof (*cidr));
    
                        if (sport) sPort = strtol(sport, NULL, 10);
                        if (dport) dPort = strtol(dport, NULL, 10);

                        if ((sPort != 0) && (dPort != 0)) {
                           switch (scidr.type) {
                              case AF_INET: {
                                 bzero((char *)flow, sizeof(*flow));
                                 flow->hdr.type              = ARGUS_FLOW_DSR;
                                 flow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                                 flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                                 flow->hdr.argus_dsrvl8.len    = 5;

                                 bcopy(&scidr.addr, &flow->ip_flow.ip_src, scidr.len);
                                 bcopy(&dcidr.addr, &flow->ip_flow.ip_dst, dcidr.len);
                                 flow->ip_flow.ip_p  = proto;
                                 flow->ip_flow.sport = sPort;
                                 flow->ip_flow.dport = dPort;
                                 flow->ip_flow.smask = 32;
                                 flow->ip_flow.dmask = 32;
                                 break;
                              }

                              case AF_INET6: {
                                 bzero((char *)flow, sizeof(*flow));
                                 flow->hdr.type              = ARGUS_FLOW_DSR;
                                 flow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                                 flow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV6;
                                 flow->hdr.argus_dsrvl8.len    = 12;

                                 bcopy(&scidr.addr, &flow->ipv6_flow.ip_src, scidr.len);
                                 bcopy(&dcidr.addr, &flow->ipv6_flow.ip_dst, dcidr.len);
                                 flow->ipv6_flow.ip_p  = proto;
                                 flow->ipv6_flow.sport = sPort;
                                 flow->ipv6_flow.dport = dPort;
                                 flow->ipv6_flow.smask = 128;
                                 flow->ipv6_flow.dmask = 128;
                                 break;
                              }
                           }

                           {
                              struct ArgusRecordStruct *ns = NULL;
                              struct ArgusTransportStruct *atrans, *btrans;
                              struct ArgusLabelStruct *label;
                              struct ArgusTimeObject *btime;
                              struct ArgusFlow *bflow;
                              extern char ArgusCanonLabelBuffer[];
                              char *lptr = ArgusCanonLabelBuffer;

#if defined(ARGUSDEBUG)
                           ArgusDebug (3, "RaProcessEventRecord: %s:srcid=%s:%s: %s %s.%s -> %s.%s %s\n", tbuf, sptr, app, node, 
                                               saddr, sport, daddr, dport, state);
#endif
                              if ((ns = ArgusGenerateRecordStruct(NULL, NULL, NULL)) != NULL) {
                                 extern struct ArgusCanonRecord ArgusGenerateCanonBuffer;
                                 struct ArgusCanonRecord  *canon = &ArgusGenerateCanonBuffer;

                                 ns->status = argus->status;

                                 if ((atrans = (struct ArgusTransportStruct *)argus->dsrs[ARGUS_TRANSPORT_INDEX]) != NULL)
                                    if ((btrans = (struct ArgusTransportStruct *)ns->dsrs[ARGUS_TRANSPORT_INDEX]) != NULL)
                                       bcopy ((char *)atrans, (char *)btrans, sizeof(*atrans));
                                 ns->dsrindex |= (0x1 << ARGUS_TRANSPORT_INDEX);

                                 if ((btime = (struct ArgusTimeObject *)ns->dsrs[ARGUS_TIME_INDEX]) != NULL)
                                    bcopy ((char *)time, (char *)btime, sizeof(*btime));
                                 ns->dsrindex |= (0x1 << ARGUS_TIME_INDEX);

                                 if ((bflow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX]) == NULL) {
                                    ns->dsrs[ARGUS_FLOW_INDEX] = (struct ArgusDSRHeader*) &canon->flow;
                                    bflow = (struct ArgusFlow *)ns->dsrs[ARGUS_FLOW_INDEX];
                                 }
                                 bcopy ((char *)flow, (char *)bflow, sizeof(*flow));
                                 ns->dsrindex |= (0x1 << ARGUS_FLOW_INDEX);

                                 if (state && (proto == IPPROTO_TCP)) {
                                    struct ArgusNetworkStruct *bnet;
                                    struct ArgusTCPObject *tcp;

                                    if ((bnet = (struct ArgusNetworkStruct *)ns->dsrs[ARGUS_NETWORK_INDEX]) == NULL) {
                                       ns->dsrs[ARGUS_NETWORK_INDEX] = (struct ArgusDSRHeader*) &canon->net;
                                       bnet = (struct ArgusNetworkStruct *)ns->dsrs[ARGUS_NETWORK_INDEX];
                                    }

                                    bnet->hdr.type    = ARGUS_NETWORK_DSR;
                                    bnet->hdr.subtype = ARGUS_TCP_STATUS;
                                    bnet->hdr.argus_dsrvl8.len  = 3;
                                    tcp = (struct ArgusTCPObject *)&bnet->net_union.tcp;

                                    if (!(strcmp(state, "(ESTABLISHED)")))     tcp->status = ARGUS_CON_ESTABLISHED;
                                    else if (!(strcmp(state, "(CLOSED)")))     tcp->status = ARGUS_NORMAL_CLOSE;
                                    else if (!(strcmp(state, "(CLOSE_WAIT)"))) tcp->status = ARGUS_CLOSE_WAITING;
                                    else if (!(strcmp(state, "(TIME_WAIT)")))  tcp->status = ARGUS_CLOSE_WAITING;

                                    ns->dsrindex |= (0x01 << ARGUS_NETWORK_INDEX);
                                 }

                                 if ((label = (struct ArgusLabelStruct *)ns->dsrs[ARGUS_LABEL_INDEX]) == NULL) {
                                    ns->dsrs[ARGUS_LABEL_INDEX] = (struct ArgusDSRHeader*) &canon->label;
                                    label = (struct ArgusLabelStruct *)ns->dsrs[ARGUS_LABEL_INDEX];
                                 }

                                 bzero(lptr, MAXBUFFERLEN);
                                 sprintf (lptr, "pid=%s:usr=%s:app=%s", pid, user, app);

                                 label->hdr.type    = ARGUS_LABEL_DSR;
                                 label->hdr.subtype = ARGUS_PROC_LABEL;
                                 label->hdr.argus_dsrvl8.len  = 1 + ((strlen(lptr) + 3)/4);
                                 label->l_un.label = lptr;
                                 ns->dsrindex |= (0x01 << ARGUS_LABEL_INDEX);

                                 RaProcessThisEventRecord (parser, ns);
                              }
                           }
                        }
                     }
                  }
               }

            } else
            if (strstr (str, "COMMAND"))
               title++;
         }
      }

//    ArgusCorrelateQueue (RaProcess->queue);
   }
}

void
RaProcessThisEventRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *ns)
{
   struct ArgusFlow *flow = (struct ArgusFlow *) ns->dsrs[ARGUS_FLOW_INDEX];

   switch (ns->hdr.type & 0xF0) {
      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (flow != NULL) {
            unsigned int addr, *daddr = NULL;

            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_IPV4: {
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_TCP: {
                              daddr = &flow->ip_flow.ip_dst;
                              break;
                           }
                        }
                        break;
                     }
                  }
                  break;
               }
            }

            if ((daddr != NULL) && (addr = *(unsigned int *)daddr)) {
               extern unsigned int RaIPv4AddressType(struct ArgusParserStruct *, unsigned int);

               if (RaIPv4AddressType(parser, addr) == ARGUS_IPV4_UNICAST) {
                  struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;
                  struct RaAddressStruct *raddr = NULL, node;

                  bzero ((char *)&node, sizeof(node));
                  node.addr.type = AF_INET;
                  node.addr.addr[0] = addr;
                  node.addr.mask[0] = 0xFFFFFFFF;
                  node.addr.masklen = 32;
                  node.addr.len = 4;

                  if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_EXACT_MATCH)) == NULL) {
                     if ((raddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*raddr))) != NULL) {
                        bcopy(&node, raddr, sizeof(node));
                        RaInsertAddress (parser, labeler, NULL, raddr, ARGUS_VISITED);
                     }
                  }
               }
            }
         }
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "ArgusProcessThisEventRecord () returning\n"); 
#endif
}

void
RaProcessManRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
}



struct RaProcessStruct *
RaNewProcess(struct ArgusParserStruct *parser)
{
   struct RaProcessStruct *retn = NULL;

   if ((retn = (struct RaProcessStruct *) ArgusCalloc (1, sizeof(*retn))) != NULL) {
      if ((retn->queue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "RaNewProcess: ArgusNewQueue error %s\n", strerror(errno));

      if ((retn->delqueue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "RaNewProcess: ArgusNewQueue error %s\n", strerror(errno));

      if ((retn->htable = ArgusNewHashTable(0x100000)) == NULL)
         ArgusLog (LOG_ERR, "RaNewProcess: ArgusCalloc error %s\n", strerror(errno));

   } else
      ArgusLog (LOG_ERR, "RaNewProcess: ArgusCalloc error %s\n", strerror(errno));

#ifdef ARGUSDEBUG
   ArgusDebug (3, "RaNewProcess(0x%x) returns 0x%x\n", parser, retn);
#endif
   return (retn);
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus) {return 0;}

void ArgusWindowClose(void);

void ArgusWindowClose(void) { 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWindowClose () returning\n"); 
#endif
}

/*
 * Print out a null-terminated filename (or other ascii string).
 * If ep is NULL, assume no truncation check is needed.
 * Return true if truncated.
 */
int
fn_print(register const u_char *s, register const u_char *ep, char *buf)
{
   register int ret;
   register u_char c;

   ret = 1;                        /* assume truncated */
   while (ep == NULL || s < ep) {
      c = *s++;
      if (c == '\0') {
         ret = 0;
         break;
      }
      if (!isascii(c)) {
         c = toascii(c);
         sprintf(&buf[strlen(buf)], "%c", 'M');
         sprintf(&buf[strlen(buf)], "%c", '-');
      }
      if (!isprint(c)) {
         c ^= 0x40;      /* DEL to ?, others to alpha */
         sprintf(&buf[strlen(buf)], "%c", '^');
      }
      sprintf(&buf[strlen(buf)], "%c", c);
   }
   return(ret);
}

/*                      
 * Print out a counted filename (or other ascii string).
 * If ep is NULL, assume no truncation check is needed.
 * Return true if truncated.
 */                     

char *
fn_printn(register const u_char *s, register u_int n,
          register const u_char *ep, char *buf)
{
   register u_char c;
   int len = strlen(buf);
   char *ebuf = &buf[len];

   while ((n > 0) && (ep == NULL || s < ep)) {
      n--;
      c = *s++;
      if (!isascii(c)) {
         c = toascii(c);
         *ebuf++ = 'M';
         *ebuf++ = '-';
      }
      if (!isprint(c)) {
         c ^= 0x40;      /* DEL to ?, others to alpha */
         *ebuf++ = '^';
      }
      *ebuf++ = c;
   }
   return (n == 0) ? ebuf : NULL;
}

/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *   The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */


#include <argus/extract.h>

#include <stdio.h>
#include <string.h>


/*
 * Convert a token value to a string; use "fmt" if not found.
const char *
tok2str(const struct tok *lp, const char *fmt, int v)
{
   static char buf[128];

   while (lp->s != NULL) {
      if (lp->v == v)
         return (lp->s);
      ++lp;
   }
   if (fmt == NULL)
      fmt = "#%d";
   (void)snprintf(buf, sizeof(buf), fmt, v);
   return (buf);
}   
 */

/*
 * Convert a token value to a string; use "fmt" if not found.
 */

const char *
tok2strbuf(register const struct tok *lp, register const char *fmt,
           register int v, char *buf, size_t bufsize)
{
   if (lp != NULL) {
      while (lp->s != NULL) {
         if (lp->v == v)
            return (lp->s);
         ++lp;
      }
   }
   if (fmt == NULL)                
      fmt = "#%d"; 
                
   (void)snprintf(buf, bufsize, fmt, v);
   return (const char *)buf;
}  

/*
 * Convert a 32-bit netmask to prefixlen if possible
 * the function returns the prefix-len; if plen == -1
 * then conversion was not possible;
 */
int mask2plen (u_int32_t);

int
mask2plen (u_int32_t mask)
{
   u_int32_t bitmasks[33] = {
                0x00000000,
                0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
                0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
                0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
                0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
                0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
                0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
                0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
                0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff
   };
   int prefix_len = 32;

   /* let's see if we can transform the mask into a prefixlen */
   while (prefix_len >= 0) {
      if (bitmasks[prefix_len] == mask)
         break;
      prefix_len--;
   }
   return (prefix_len);
}

