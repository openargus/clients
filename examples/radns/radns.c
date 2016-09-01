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
 * $Id: //depot/gargoyle/clients/examples/radns/radns.c#22 $
 * $DateTime: 2016/06/08 00:59:34 $
 * $Change: 3166 $
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

extern void RaMySQLInit (void);

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


char *ArgusHandleResponseArray[1024];

char **ArgusHandleTreeCommand (char *);
char **ArgusHandleSearchCommand (char *);

char **
ArgusHandleTreeCommand (char *command)
{
   char *string = &command[10], *sptr;
   int slen = strlen(string);
   char **retn = ArgusHandleResponseArray;
 
   sptr = &string[slen - 1];
   while (isspace(*sptr)) {*sptr-- = '\0';}
 
   retn[0] = "OK\n";
   retn[1] = NULL;
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusHandleTreeCommand(%s) filter %s", string, retn);
#endif
   return retn;
}


void ArgusPrintAddressResponse(char *, struct RaAddressStruct *, char **, int *);

void
ArgusPrintAddressResponse(char *string, struct RaAddressStruct *raddr, char **result, int *rind)
{
   struct ArgusListStruct *list = raddr->dns;

   if (raddr->r != NULL) ArgusPrintAddressResponse(string, raddr->r, result, rind);
   if (raddr->l != NULL) ArgusPrintAddressResponse(string, raddr->l, result, rind);

   if (list != NULL) {
      int ind = *rind;
      char tbuf[128], resbuf[256];
      bzero(tbuf, sizeof(tbuf));
      bzero(resbuf, sizeof(tbuf));
      ArgusPrintTime(ArgusParser, tbuf, &raddr->atime);

#if defined(ARGUS_THREADS)
      if (pthread_mutex_lock(&raddr->dns->lock) == 0) {
#endif
         int x, cnt = raddr->dns->count;
         struct ArgusListObjectStruct *list = raddr->dns->start;

         for (x = 0; x < cnt; x++) {
            struct ArgusDomainResourceRecord *dns = (struct ArgusDomainResourceRecord *) list->list_obj;
            sprintf (resbuf, "%s: %s [%s, %s, %d]\n", string, dns->data, dns->name, tbuf, dns->ttl);
            result[ind++] = strdup(resbuf);
            list = list->nxt;
         }
#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&raddr->dns->lock);
      }
#endif
      *rind = ind;
   }
}


char **
ArgusHandleSearchCommand (char *command)
{
   char *string = &command[8], *sptr;
   struct ArgusCIDRAddr *cidr = NULL;

   int slen = strlen(string), options, rege, rind = 0;
   char resbuf[0x10000];
   char **retn = NULL;
   struct RaAddressStruct *raddr = NULL;

   regex_t preg;

   sptr = &string[slen - 1];
   while (isspace(*sptr)) {*sptr-- = '\0';}

   bzero(ArgusHandleResponseArray, sizeof(ArgusHandleResponseArray));
   retn = ArgusHandleResponseArray;

   if ((cidr = RaParseCIDRAddr (ArgusParser, string)) != NULL) {
      struct ArgusLabelerStruct *labeler = ArgusParser->ArgusLabeler;
      struct RaAddressStruct node;
      
      bzero ((char *)&node, sizeof(node));
      bcopy(cidr, &node.addr, sizeof(*cidr));

      if ((raddr = RaFindAddress (ArgusParser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_MASK_MATCH)) != NULL) 
         ArgusPrintAddressResponse(string, raddr, retn, &rind);

   } else {
      bzero(resbuf, sizeof(resbuf));

#if defined(ARGUS_PCRE)
      options = 0;
#else
      options = REG_EXTENDED | REG_NOSUB;
#if defined(REG_ENHANCED)
      options |= REG_ENHANCED;
#endif
#endif
      options |= REG_ICASE;

      if ((rege = regcomp(&preg, string, options)) != 0) {
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

#ifdef ARGUSDEBUG
         ArgusDebug (0, "ArgusHandleSearchCommand: searching DNS names for %s", string);
#endif
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
               struct nnamemem *cname, *name = matches[i];
               bzero(results, sizeof(results));
               results[resultnum++] = strdup(name->n_name);
                        
               if (name->cnames != NULL) {
                           do {
#if defined(ARGUS_THREADS)
                              if (name->cnames == NULL) {
                                 done = 1;
                              } else {
                                 if (pthread_mutex_lock(&name->cnames->lock) == 0) {
#endif
                                    int cnt = name->cnames->count;
                                    struct ArgusListObjectStruct *list = name->cnames->start;

                                    for (x = 0; x < cnt; x++) {
                                       cname = (struct nnamemem *)list->list_obj;
                                       results[resultnum++] = strdup(cname->n_name);
                                       list = list->nxt;
                                    }
#if defined(ARGUS_THREADS)
                                    pthread_mutex_unlock(&name->cnames->lock);
                                 }
                                 if (cname != NULL) name = cname; else done = 1;
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

               sprintf (resbuf, "%s: %s [", string, results[0]);

               for (x = 1; x < resultnum; x++) {
                           if (x > 1) sprintf (&resbuf[strlen(resbuf)], ", ");
                           sprintf (&resbuf[strlen(resbuf)], "%s", results[x]);
                           free(results[x]);
               }
               sprintf (&resbuf[strlen(resbuf)], "]\n");
               retn[rind++] = strdup(resbuf);
               free(results[0]);

            }
         }
      }
   }

   if (retn[0] == NULL)
      retn = NULL;
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusHandleSearchCommand(%s) returns %s", string, retn);
#endif
   return retn;
}


void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct RaAddressStruct **ArgusAddrTree;
   struct ArgusModeStruct *mode = NULL;
   parser->RaWriteOut = 1;

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
            if (!(strncasecmp (mode->mode, "debug.mol", 9))) {
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_MOL;

               RaMapLabelMol (ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0, 0, 0);
               RaPrintLabelMol (ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0, 0, 0);
               exit(0);
            } else
            if ((!(strncasecmp (mode->mode, "debug.tree", 10))) ||
                (!(strncasecmp (mode->mode, "debug", 5)))) {
               ArgusDebugTree = 1;
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_TREE;
               RaPrintLabelTree (ArgusLabeler, ArgusAddrTree[AF_INET], 0, 0);
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
            if (!(strncasecmp (mode->mode, "graph", 5))) {
               parser->ArgusLabeler->RaPrintLabelTreeMode = ARGUS_GRAPH;
            } else
            if (!(strncasecmp (mode->mode, "rmon", 4))) {
               parser->RaMonMode++;
            } else
            if (!(strncasecmp (mode->mode, "prune", 5))) {
               char *ptr, *str;
               parser->ArgusPruneTree++;
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

         if (ArgusEstablishListen (parser, parser->ArgusControlPort, "127.0.0.1") < 0)
            ArgusLog (LOG_ERR, "setArgusPortNum: ArgusEstablishListen returned %s", strerror(errno));

         if ((parser->ArgusControlChannel = ArgusNewControlChannel (parser)) == NULL)
            ArgusLog (LOG_ERR, "could not create control channel: %s\n", strerror(errno));

         if ((tvp->tv_sec == 0) && (tvp->tv_usec == 0)) {
            setArgusMarReportInterval (ArgusParser, "60s");
         }

         ArgusControlCommands[CONTROL_TREE].handler   = ArgusHandleTreeCommand;
         ArgusControlCommands[CONTROL_SEARCH].handler = ArgusHandleSearchCommand;
      }

#if defined(ARGUS_MYSQL)
      RaMySQLInit();
#endif
   }
}


void
RaParseComplete (int sig)
{
   if (sig >= 0) {
      if (!(ArgusParser->RaParseCompleting++)) {
         int ArgusExitStatus = 0;
         ArgusShutDown(sig);

         if (ArgusDebugTree) {
            if (RaTreePrinted++ == 0) {
               struct ArgusLabelerStruct *labeler = ArgusParser->ArgusLabeler;
               if (labeler && labeler->ArgusAddrTree) {
                  if (ArgusParser->ArgusPruneTree)
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

#if defined(ARGUS_MYSQL)
         mysql_close(RaMySQL);
#endif
         ArgusCloseParser(ArgusParser);
         exit (ArgusExitStatus);
      }
   }
}


void
ArgusClientTimeout ()
{
   struct ArgusHashTable *table = ArgusDNSNameTable;

   if (table && (table->array != NULL)) {

#if defined(ARGUS_THREADS)
      if (pthread_mutex_lock(&table->lock) == 0) {
#endif
/*
         int i, size = table->size;

         for (i = 0; i < size; i++) {
            struct ArgusHashTableHdr *hptr;
            if ((hptr = table->array[i]) != NULL) {
               struct nnamemem *name = (struct nnamemem *)hptr->object;
               if ((name->secs + 86400) < ArgusParser->ArgusCurrentTime.tv_sec) {
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
                  if (name->n_name) free(name->n_name);
                  if (name->h_name) free(name->h_name);
                  if (name->c_name) free(name->c_name);
                  ArgusFree(name);
                  ArgusFree(hptr);
               }
            }
         }
*/
#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&table->lock);
      }
#endif
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

int RaProcessARecord (struct ArgusParserStruct *, struct ArgusDomainStruct *, struct ArgusDomainResourceRecord *, time_t);
int RaProcessCRecord (struct ArgusParserStruct *, struct ArgusDomainStruct *, struct ArgusDomainResourceRecord *, time_t);
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
      char *lname = strdup(name);
      int i;

      bzero(&ArgusHash, sizeof(ArgusHash));
      ArgusHash.len = strlen(name);
      ArgusHash.hash = getnamehash((const u_char *)lname);
      ArgusHash.buf = (unsigned int *)lname;

      for (i = 0; i < ArgusHash.len; i++)
        lname[i] = tolower(lname[i]);

      if ((htbl = ArgusFindHashEntry(table, &ArgusHash)) == NULL) {
         if ((retn = ArgusCalloc(1, sizeof(struct nnamemem))) == NULL)
            ArgusLog (LOG_ERR, "ArgusNameEntry: ArgusCalloc error %s\n", strerror(errno));

         retn->hashval = ArgusHash.hash;
         retn->n_name = lname;
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
//  This routine will parse out a complete dns a record, and will associate the name with the address.
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
RaProcessARecord (struct ArgusParserStruct *parser, struct ArgusDomainStruct *dns, struct ArgusDomainResourceRecord *rr, time_t sec)
{
   struct ArgusLabelerStruct *labeler;
   struct RaAddressStruct *raddr = NULL;
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


   if (rr != NULL) {
      struct ArgusCIDRAddr *cidr = NULL;
      struct RaAddressStruct node;

      bzero ((char *)&node, sizeof(node));

      if ((cidr = RaParseCIDRAddr (parser, rr->data)) != NULL) {
         struct ArgusDomainResourceRecord *trr = NULL;
         int ttl, ncidr = 0, ndns = 0;

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
               list->list_obj = raddr;
               ArgusPushFrontList(name->cidrs, (struct ArgusListRecord *)list, ARGUS_LOCK);
            }

            if (raddr->dns == NULL) {
               if ((raddr->dns = ArgusNewList()) == NULL)
                  ArgusLog(LOG_ERR, "ArgusNewList: error %s", strerror(errno));
               ndns = 1;

            } else {
#if defined(ARGUS_THREADS)
               if (pthread_mutex_lock(&raddr->dns->lock) == 0) {
#endif
                  int i, cnt = raddr->dns->count;
                  struct ArgusListObjectStruct *list = raddr->dns->start;

                  for (i = 0; (ndns != 0) && (i < cnt); i++) {
                     struct ArgusDomainResourceRecord *trr = (struct ArgusDomainResourceRecord *) list->list_obj;
                     if (!(strcmp(rr->name, trr->name)))
                        ndns = 0;
                     list = list->nxt;
                  }
#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&raddr->dns->lock);
               }
#endif
            }

            if (ndns) {
               struct ArgusListObjectStruct *list;
               if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

               if ((trr = ArgusCalloc(1, sizeof(*trr))) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

               bcopy (rr, trr, sizeof(*trr));
               trr->name = strdup(rr->name);
               trr->data = strdup(rr->data);
               list->list_obj = trr;
               ArgusPushFrontList(raddr->dns, (struct ArgusListRecord *)list, ARGUS_LOCK);
            }

#define ARGUS_DNS_MIN_TTL   15
            ttl = (rr->ttl < ARGUS_DNS_MIN_TTL) ? ARGUS_DNS_MIN_TTL : rr->ttl + 15;

            if (raddr->atime.tv_sec < (sec + ttl))
               raddr->atime.tv_sec = (sec + ttl);

            if (name->secs < raddr->atime.tv_sec)
               name->secs = raddr->atime.tv_sec;
         }
      }
   }

   return retn;
}

int
RaProcessCRecord (struct ArgusParserStruct *parser, struct ArgusDomainStruct *dns, struct ArgusDomainResourceRecord *rr, time_t sec)
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

   if ((name = ArgusNameEntry(ArgusDNSNameTable, rr->name)) != NULL) {
      if ((cname = ArgusNameEntry(ArgusDNSNameTable, rr->data)) != NULL) {
         if (name->cnames == NULL) {
            name->cnames = ArgusNewList();
            ncname = 1;
         } else {
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
         }
         if (cname && (ncname != 0)) {
            struct ArgusListObjectStruct *list;
            if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
               ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));
            list->list_obj = cname;
            ArgusPushFrontList(name->cnames, (struct ArgusListRecord *)list, ARGUS_LOCK);
         }
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

         double val = ArgusFetchLastTime(argus);
         time_t tsec = val;

         unsigned short proto = 0, sport = 0, dport = 0;
         int type, process = 0, dnsTransaction = 0;
         void *saddr = NULL, *daddr = NULL;
         unsigned int dnsAddrType = 0;
         struct RaAddressStruct *dnsNode = NULL;
         void *dnsServer = NULL;

         if (flow != NULL) {
            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch ((type = flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_IPV4: {
                        saddr = &flow->ip_flow.ip_src;
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
                              saddr = &flow->ipv6_flow.ip_src;
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
                              if (res->ans) {
                                 int i, count = res->ans->count;
                                 for (i = 0; i < count; i++) {
                                    struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->ans, ARGUS_NOLOCK);
                                    struct ArgusDomainResourceRecord *rr = list->list_union.obj;
                                    RaProcessARecord(parser, dns, rr, tsec);
                                    ArgusPushBackList(res->ans, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                 }
                              }

                              if (res->cname) {
                                 int i, count = res->cname->count;
                                 for (i = 0; i < count; i++) {
                                    struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->cname, ARGUS_NOLOCK);
                                    struct ArgusDomainResourceRecord *rr = list->list_union.obj;
                                    RaProcessCRecord(parser, dns, rr, tsec);
                                    ArgusPushBackList(res->cname, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                 }
                              }

                              if (!parser->qflag) {
//  Print the response
                                 char *type = (char *)tok2str(ns_type2str, "Type%d", req->qtype);

                                 fprintf (stdout, "%s: %s? %s : ", tptr, type, res->name);

                                 if (res->ans) {
                                    int i, count = res->ans->count;
                                    type = (char *)tok2str(ns_type2str, "Type%d", res->qtype);

                                    fprintf (stdout, "%s ", type);
                                    for (i = 0; i < count; i++) {
                                       struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->ans, ARGUS_NOLOCK);
                                       struct ArgusDomainResourceRecord *rr = list->list_union.obj;

                                       if (i == 0) fprintf (stdout, "%s %s[%d]", rr->name, rr->data, rr->ttl);
                                       else fprintf (stdout, ", %s[%d]", rr->data, rr->ttl);
                                       ArgusPushBackList(res->ans, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                    }

                                    if (res->cname) {
                                       int i, count = res->cname->count;
                                       fprintf (stdout, " CNAME ");
                                       for (i = 0; i < count; i++) {
                                          struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->cname, ARGUS_NOLOCK);
                                          struct ArgusDomainResourceRecord *rr = list->list_union.obj;

                                          if (i > 0) fprintf (stdout, ", ");
                                          fprintf (stdout, "%s %s", rr->name, rr->data);
                                          ArgusPushBackList(res->cname, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                       }
                                    }
                                 }
                              }
                           } else
                              if (res->ans)
                                 fprintf(stdout, "%s: radns: request/response name mismatch req:%s res:%s\n", tptr, req->name, res->name);
                        } else
                           if (res->ans)
                              fprintf(stdout, "%s: radns: request/response seq mismatch req:%d res:%d\n", tptr, req->seqnum, res->seqnum);
                     }
                  }

                  if (!parser->qflag) fprintf (stdout, "\n");
                  fflush(stdout);

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
                              struct ArgusDomainResourceRecord *trr = list->start->list_obj;

                              if ((trr != NULL) && (raddr->atime.tv_sec > 0)) {
                                 if (raddr->atime.tv_sec < tsec) {
                                    if ((raddr->rtime.tv_sec + 3600)  < tsec) {

                                       fprintf (stdout, "%s: RaProcessRecord: address referenced after name cache timed out: %15.15s ttl %d timed out %lds ago\n", 
                                        tptr, intoa(node.addr.addr[0]), trr->ttl, (tsec - raddr->atime.tv_sec));
                                    }
                                 }
                              }
                           }

                           if (raddr->rtime.tv_sec < tsec)
                              raddr->rtime.tv_sec = tsec;
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
         bzero (tbuf, sizeof(tbuf));
         bzero (sptr, sizeof(sbuf));
         tvp->tv_sec  = time->src.start.tv_sec;
         tvp->tv_usec = time->src.start.tv_usec;

         ArgusPrintTime(parser, tbuf, tvp);
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
            unsigned int addr, *saddr = NULL, *daddr = NULL;

            switch (flow->hdr.subtype & 0x3F) {
               case ARGUS_FLOW_CLASSIC5TUPLE: {
                  switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                     case ARGUS_TYPE_IPV4: {
                        switch (flow->ip_flow.ip_p) {
                           case IPPROTO_TCP: {
                              saddr = &flow->ip_flow.ip_src;
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


char *RaDnsUserBuffer (struct ArgusParserStruct *, struct ArgusRecordStruct *, int, int);

char *
RaDnsUserBuffer (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, int ind, int len) 
{
   struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
   unsigned short sport = 0, dport = 0;
   int type, proto, process = 0;
   struct ArgusDataStruct *user = NULL;
   u_char buf[MAXSTRLEN], *bp = NULL;
   int slen = 0;

   if ((user = (struct ArgusDataStruct *)argus->dsrs[ind]) == NULL)
      return (ArgusBuf);

/*
   switch (ind) {
      case ARGUS_SRCUSERDATA_INDEX:
         dchr = 's';
         break;
      case ARGUS_DSTUSERDATA_INDEX:
         dchr = 'd';
         break;
   }
*/

   bp = (u_char *) &user->array;
   slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
   slen = (user->count < slen) ? user->count : slen;
   slen = (slen > len) ? len : slen;
   snapend = bp + slen;

   if (flow != NULL) {
      switch (flow->hdr.subtype & 0x3F) {
         case ARGUS_FLOW_CLASSIC5TUPLE: {
            switch ((type = flow->hdr.argus_dsrvl8.qual & 0x1F)) {
               case ARGUS_TYPE_IPV4:
                  switch (flow->ip_flow.ip_p) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP: {
                        proto = flow->ip_flow.ip_p;
                        sport = flow->ip_flow.sport;
                        dport = flow->ip_flow.dport;
                        process++;
                        break;
                     }
                  }
                  break; 
               case ARGUS_TYPE_IPV6: {
                  switch (flow->ipv6_flow.ip_p) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP: {
                        proto = flow->ipv6_flow.ip_p;
                        sport = flow->ipv6_flow.sport;
                        dport = flow->ipv6_flow.dport;
                        process++;
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

   if (process && bp) {
      *(int *)&buf = 0;

#define ISPORT(p) (dport == (p) || sport == (p))

      switch (proto) {
         case IPPROTO_TCP: {
            if (ISPORT(NAMESERVER_PORT) || ISPORT(MULTICASTDNS_PORT)) 
                ns_print(bp + 2, slen - 2, 0);
            break;
         }

         case IPPROTO_UDP: {
            if (ISPORT(NAMESERVER_PORT))
               ns_print(bp, slen, 0);
            else if (ISPORT(MULTICASTDNS_PORT))
               ns_print(bp, slen, 1);
         }
      }
   }

   return (ArgusBuf);
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

