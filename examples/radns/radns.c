/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2020 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software, released under the GNU General
 * Public License; you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software
 * Foundation; either version 3, or any later version.
 *
 * Other licenses are available through QoSient, LLC.
 * Inquire at info@qosient.com.
 *
 * This program is distributed WITHOUT ANY WARRANTY; without even the
 * implied warranty of * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
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

#include <netinet/tlds.h>

#include <argus_compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <argus_label.h>

#include <argus_output.h>

#if defined(ARGUS_MYSQL)
# include "argus_mysql.h"

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

char ArgusBuf[0x8000];
int ArgusThisEflag = 0;
int ArgusDebugTree = 0;

int ArgusDnsCacheTimeout = 0;
char *ArgusPendingSearchCommand = NULL;

struct ArgusNameSpace {
   struct ArgusQueueStruct *tlds;
   struct ArgusHashTable *table;
};

struct ArgusHashTable *ArgusDNSNameTable = NULL;
struct ArgusHashTable *ArgusDNSServerTable = NULL;
struct ArgusHashTable *ArgusHostNameTable = NULL;

struct ArgusAggregatorStruct *ArgusEventAggregator = NULL;

struct ArgusNameSpace *ArgusDNSNameSpace = NULL;

struct ArgusLabelerStruct *ArgusDnsNames = NULL;
struct ArgusLabelerStruct *ArgusDnsServers = NULL;
struct ArgusLabelerStruct *ArgusDnsClients = NULL;

void RaArgusInputComplete (struct ArgusInput *input) {};
int RaTreePrinted = 0;
int RaPruneLevel = 0;

#define ARGUS_MAX_RESPONSE		0x100000
#define ARGUS_DEFAULT_RESULTLEN         0x100000

#define ARGUS_NAME_REQUESTED	0x10
#define ARGUS_DNS_MIN_TTL       30

#define ARGUS_DNS_AUTH   	0x01
#define ARGUS_DNS_CNAME  	0x02
#define ARGUS_DNS_ALIAS  	0x04
#define ARGUS_DNS_REFERER	0x08
#define ARGUS_DNS_PTR		0x10
#define ARGUS_DNS_TLD		0x20

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


struct nnamemem *ArgusNameEntry (struct ArgusHashTable *, char *, int);
struct nnamemem *ArgusFindNameEntry (struct ArgusHashTable *, char *);

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


void ArgusPrintAddressResponse(char *, struct RaAddressStruct *, char ***, int *, int *, int);

void
ArgusPrintAddressResponse(char *string, struct RaAddressStruct *raddr, char ***result, int *rind, int *reslen, int type)
{
   struct ArgusListStruct *dns = raddr->dns;

   switch (type) {
      case AF_INET: {
         if (raddr->r != NULL) ArgusPrintAddressResponse(string, raddr->r, result, rind, reslen, type);
         if (raddr->l != NULL) ArgusPrintAddressResponse(string, raddr->l, result, rind, reslen, type);

         if (dns != NULL) {
            struct ArgusListObjectStruct *tdns;
            struct timeval tvbuf, *tvp = &tvbuf;
            char tbuf[128], rbuf[128], *resbuf;
            int ind = *rind;

            if ((resbuf = ArgusMalloc(ARGUS_MAX_RESPONSE)) == NULL)
               ArgusLog (LOG_ERR, "ArgusPrintAddressResponse: ArgusMalloc error %s\n", strerror(errno));

            bzero(tbuf, sizeof(tbuf));
            bzero(rbuf, sizeof(rbuf));

            ArgusPrintTime(ArgusParser, tbuf, sizeof(tbuf), &raddr->atime);
            ArgusPrintTime(ArgusParser, rbuf, sizeof(rbuf), &raddr->rtime);

            RaDiffTime (&raddr->rtime, &raddr->atime, tvp);

            if (raddr->addr.str == NULL) 
               raddr->addr.str = strdup(ArgusGetName (ArgusParser, (unsigned char *)&raddr->addr.addr[0]));

            if (ArgusParser->ArgusPrintJson) {
               sprintf (resbuf, "{ \"stime\":\"%s\", \"rtime\":\"%s\", \"addr\":\"%s\"", tbuf, rbuf, (raddr->addr.str != NULL) ? raddr->addr.str : string);
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
                  if (tdns->status & ARGUS_DNS_AUTH)     auth++;
                  if (tdns->status & ARGUS_DNS_REFERER)  refer++;
                  if (tdns->status & ARGUS_DNS_PTR)      ptr++;
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
                     if (tdns->status & ARGUS_DNS_AUTH) {
                        struct nnamemem *tname = (struct nnamemem *) tdns->list_obj;

                        RaDiffTime (&tname->ltime, &tname->stime, tvp);

                        if (strlen(tname->n_name) > 0) {
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
                     if (tdns->status & ARGUS_DNS_REFERER) {
                        struct nnamemem *tname = (struct nnamemem *) tdns->list_obj;

                        RaDiffTime (&tname->ltime, &tname->stime, tvp);

                        if (strlen(tname->n_name) > 0) {
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
                     if (tdns->status & ARGUS_DNS_PTR) {
                        struct nnamemem *tname = (struct nnamemem *) tdns->list_obj;
                        if (strlen(tname->n_name) > 0) {
                           if (tref++ > 0) {
                              int slen = snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, ",");
                              len += slen;
                           }

                           if (ArgusParser->ArgusPrintJson) {
                              snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "\"%s\"", tname->n_name);
                           } else {
                              snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "\"%s\"", tname->n_name);
                           }
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
               } else {
                  int slen = snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "]");
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
         break;
      }

      case AF_INET6: {
         extern struct cnamemem ipv6cidrtable[HASHNAMESIZE];
         int i, match = 0;

         if (strcmp(string, "::/0") == 0) 
            match = 1;

// all match ... dump the complete hash table
         for (i = 0; i < HASHNAMESIZE; i++) {
            struct cnamemem *tp;
            int tmatch = match;

            if ((tp = &ipv6cidrtable[i]) != NULL) {
               while (tp->n_nxt) {
                  if (tmatch == 0)
                     if (!strncmp(string, tp->name, strlen(string)))
                        tmatch = 1;

                  if (tmatch) {
                     if ((raddr = tp->node) != NULL) {
                        struct ArgusListStruct *dns = raddr->dns;

                        if (dns != NULL) {
                           struct ArgusListObjectStruct *tdns;
                           struct timeval tvbuf, *tvp = &tvbuf;
                           char tbuf[128], rbuf[128], *resbuf;
                           int ind = *rind;

                           if ((resbuf = ArgusMalloc(ARGUS_MAX_RESPONSE)) == NULL)
                              ArgusLog (LOG_ERR, "ArgusPrintAddressResponse: ArgusMalloc error %s\n", strerror(errno));

                           bzero(tbuf, sizeof(tbuf));
                           bzero(rbuf, sizeof(rbuf));

                           ArgusPrintTime(ArgusParser, tbuf, sizeof(tbuf), &raddr->atime);
                           ArgusPrintTime(ArgusParser, rbuf, sizeof(rbuf), &raddr->rtime);

                           RaDiffTime (&raddr->rtime, &raddr->atime, tvp);

                           if (raddr->addr.str == NULL) 
                              raddr->addr.str = strdup(ArgusGetName (ArgusParser, (unsigned char *)&raddr->addr.addr[0]));

                           if (ArgusParser->ArgusPrintJson) {
                              sprintf (resbuf, "{ \"stime\":\"%s\", \"rtime\":\"%s\", \"addr\":\"%s\"", tbuf, rbuf, (raddr->addr.str != NULL) ? raddr->addr.str : string);
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
                                 if (tdns->status & ARGUS_DNS_AUTH)     auth++;
                                 if (tdns->status & ARGUS_DNS_REFERER)  refer++;
                                 if (tdns->status & ARGUS_DNS_PTR)      ptr++;
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
                                    if (tdns->status & ARGUS_DNS_AUTH) {
                                       struct nnamemem *tname = (struct nnamemem *) tdns->list_obj;

                                       RaDiffTime (&tname->ltime, &tname->stime, tvp);

                                       if (strlen(tname->n_name) > 0) {
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
                                    if (tdns->status & ARGUS_DNS_REFERER) {
                                       struct nnamemem *tname = (struct nnamemem *) tdns->list_obj;

                                       RaDiffTime (&tname->ltime, &tname->stime, tvp);

                                       if (strlen(tname->n_name) > 0) {
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
                                    if (tdns->status & ARGUS_DNS_PTR) {
                                       struct nnamemem *tname = (struct nnamemem *) tdns->list_obj;
                                       if (strlen(tname->n_name) > 0) {
                                          if (tref++ > 0) {
                                             int slen = snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, ",");
                                             len += slen;
                                          }

                                          if (ArgusParser->ArgusPrintJson) {
                                             snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "\"%s\"", tname->n_name);
                                          } else {
                                             snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "\"%s\"", tname->n_name);
                                          }
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
                              } else {
                                 int slen = snprintf (&resbuf[len], ARGUS_MAX_RESPONSE - len, "]");
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
                  }
                  tp = tp->n_nxt;
               }
            }
         }
         break;
      }
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
      if ((resbuf = ArgusCalloc(0x100000, sizeof(char *))) == NULL)
         ArgusLog (LOG_ERR, "ArgusHandleSearchCommand: ArgusCalloc error %s\n", strerror(errno));
   }

   while ((sptr = strtok(string, ",")) != NULL) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusHandleSearchCommand: searching for %s", sptr);
#endif


// First check to see if the search is a cidr address.

      if ((cidr = RaParseCIDRAddr (ArgusParser, sptr)) != NULL) {
         struct ArgusLabelerStruct *labeler = ArgusParser->ArgusLabeler;
         struct RaAddressStruct node;
         int matchMode = ARGUS_EXACT_MATCH;

         if (!((cidr->masklen == 32) || (cidr->masklen == 128)))
            matchMode = ARGUS_MASK_MATCH;
         
         bzero ((char *)&node, sizeof(node));
         bcopy(cidr, &node.addr, sizeof(*cidr));
         if (node.addr.str != NULL)
            node.addr.str = strdup(cidr->str);

         switch (cidr->type) {
            case AF_INET: {
               if ((raddr = RaFindAddress (ArgusParser, labeler->ArgusAddrTree[cidr->type], &node, matchMode)) != NULL) {
                  ArgusPrintAddressResponse(sptr, raddr, &retn, &rind, &reslen, AF_INET);
               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (1, "ArgusHandleSearchCommand: address search %s returned not found", sptr);
#endif
               }
               break;
            }
            case AF_INET6: {
               ArgusPrintAddressResponse(sptr, &node, &retn, &rind, &reslen, AF_INET6);
               break;
            }
         }

      } else {
#define RADNS_MATCHES_LEN	0x200000
         struct nnamemem **matches;
         int i, mind = 0, mlen = RADNS_MATCHES_LEN;
         struct nnamemem *name;

         if ((matches = ArgusCalloc(mlen, sizeof(struct nnamemem *))) == NULL)
            ArgusLog (LOG_ERR, "ArgusHandleSearchCommand: ArgusCalloc error %s\n", strerror(errno));

// Not cidr, so must be a FQDN or a pattern to match.  If string is in the DNS name table, return that.

         if ((strlen(sptr) > 1) && ((name = ArgusFindNameEntry(ArgusDNSNameTable, sptr)) != NULL)) {
            if (mind < RADNS_MATCHES_LEN)
               matches[mind++] = name;

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
               int size = ArgusDNSNameTable->size;

               for (i = 0; i < size; i++) {
                  struct ArgusHashTableHdr *hptr;
                  if ((hptr = table->array[i]) != NULL) {
                     do {
                        name = (struct nnamemem *)hptr->object;

                        if (name && (name->n_name != NULL))
                           if (ArgusGrepBuf (&preg, name->n_name, &name->n_name[strlen(name->n_name)]))
                              matches[mind++] = name;

                     } while ((mind < mlen) && ((hptr = hptr->nxt) != table->array[i]));
                  }
               }
            }
         }

         if (mind > 0) {
            for (i = 0; i < mind; i++) {
               int x, resultnum = 0, done = 0;
               struct nnamemem *cname = NULL;
               struct nnamemem *name = matches[i];
               char refbuf[16], timebuf[64];
               char **results = NULL;

               struct ArgusListStruct *servers = name->servers;
               struct ArgusListStruct *clients = name->clients;

               if ((results = ArgusCalloc(0x100000, sizeof(char *))) == NULL)
                  ArgusLog (LOG_ERR, "ArgusHandleSearchCommand: ArgusCalloc error %s\n", strerror(errno));

               results[resultnum++] = strdup(name->n_name);

               if (ArgusParser->ArgusPrintJson) {
                  snprintf(refbuf, 16, "\"ref\":\"%d\"", name->ref);
                  results[resultnum++] = strdup(refbuf);
                  if (name->stime.tv_sec > 0) {
                     snprintf(timebuf, 64, "\"stime\":\"%d\",\"ltime\":\"%d\"", (int)name->stime.tv_sec, (int)name->ltime.tv_sec);
                     results[resultnum++] = strdup(timebuf);
                  }
               }
                        
               if (name->cnames != NULL) {
                  char *cnamebuf;
                  int count = 0;

                  if ((cnamebuf = ArgusMalloc(0x4000)) == NULL)
                     ArgusLog (LOG_ERR, "ArgusHandleSearchCommand: ArgusCalloc error %s\n", strerror(errno));

                  if (ArgusParser->ArgusPrintJson) {
                     snprintf(cnamebuf, 0x4000, "\"cname\":[");
                  }
                  
#if defined(ARGUS_THREADS)
                  do {
                     int cnt = 0, slen = 0;
                     if (name->cnames == NULL) {
                        done = 1;
                     } else {
                        if (pthread_mutex_lock(&name->cnames->lock) == 0) {
#endif
                           cnt = name->cnames->count;
                           cnt = (cnt >= (0x10000 - resultnum)) ? (0x10000 - resultnum) : cnt;
                           struct ArgusListObjectStruct *list = name->cnames->start;

                           for (x = 0; x < cnt; x++) {
                              cname = (struct nnamemem *)list->list_obj;
                              if (!(cname->status & ARGUS_VISITED)) {
                                 slen = strlen(cnamebuf);
                                 if (ArgusParser->ArgusPrintJson) {
                                    if (count++ > 0) {
                                       snprintf (&cnamebuf[slen], 0x4000 - slen, ",");
                                       slen++;
                                    }
                                    snprintf (&cnamebuf[slen], 0x4000 - slen, "\"%s\"", cname->n_name);
                                 } else {
                                    results[resultnum++] = strdup(cname->n_name);
                                 }
                                 cname->status |= ARGUS_VISITED;
                              } else {
                                 done = 1;
                              }
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
                  if (ArgusParser->ArgusPrintJson) {
                     slen = strlen(cnamebuf);
                     snprintf (&cnamebuf[slen], 0x4000 - slen, "]");
                     results[resultnum++] = strdup(cnamebuf);
                  }
                  ArgusFree(cnamebuf);

                  if (name->cnames) {
#if defined(ARGUS_THREADS)
                     if (pthread_mutex_lock(&name->cnames->lock) == 0) {
#endif
                        struct ArgusListObjectStruct *list = name->cnames->start;
                        int cnt = name->cnames->count;

                        for (x = 0; x < cnt; x++) {
                           cname = (struct nnamemem *)list->list_obj;
                           cname->status &= ~ARGUS_VISITED;
                           list = list->nxt;
                        }
#if defined(ARGUS_THREADS)
                        pthread_mutex_unlock(&name->cnames->lock);
                     }
#endif
                  }
               }

               if (name->cidrs != NULL) {
#if defined(ARGUS_THREADS)
                  if (pthread_mutex_lock(&name->cidrs->lock) == 0) {
#endif
                     int x, cnt = name->cidrs->count;
                     struct ArgusListObjectStruct *list = name->cidrs->start;

                     for (x = 0; x < cnt; x++) {
                        struct RaAddressStruct *raddr = (struct RaAddressStruct *)list->list_obj;
                        switch (raddr->addr.type) {
                           case AF_INET: {
                              unsigned int addr = htonl(raddr->addr.addr[0]);
                              struct in_addr naddr = *(struct in_addr *)&addr;
                              if (x == 0) {
                                 char sbuf[256];
                                 snprintf (sbuf, 256, "\"addr\":[ \"%s\"", inet_ntoa(naddr));
                                 if (x == (cnt - 1)) 
                                    sprintf (&sbuf[strlen(sbuf)]," ]");
                                 results[resultnum++] = strdup(sbuf);
                              } else {
                                 char sbuf[256];
                                 snprintf (sbuf, 256, "\"%s\"", inet_ntoa(naddr));
                                 if (x == (cnt - 1)) 
                                    sprintf (&sbuf[strlen(sbuf)]," ]");
                                 results[resultnum++] = strdup(sbuf);
                              }
                              break;
                           }
                           case AF_INET6: {
                              struct in6_addr naddr = *(struct in6_addr *)raddr->addr.addr;
                              char ntop_buf[INET6_ADDRSTRLEN];
                              const char *cp;

                              if ((cp = inet_ntop(AF_INET6, (const void *) &naddr, ntop_buf, sizeof(ntop_buf))) != NULL) {
                                 if (x == 0) {
                                    char sbuf[256];
                                    snprintf (sbuf, 256, "\"addr\":[ \"%s\"", cp);
                                    if (x == (cnt - 1)) 
                                       sprintf (&sbuf[strlen(sbuf)]," ]");
                                    results[resultnum++] = strdup(sbuf);
                                 } else {
                                    char sbuf[256];
                                    snprintf (sbuf, 256, "\"%s\"", cp);
                                    if (x == (cnt - 1)) 
                                       sprintf (&sbuf[strlen(sbuf)]," ]");
                                    results[resultnum++] = strdup(sbuf);
                                 }
                              }
                              break;
                           }
                        }

                        list = list->nxt;
                     }
#if defined(ARGUS_THREADS)
                     pthread_mutex_unlock(&name->cidrs->lock);
                  }
#endif
               }

               if (servers != NULL) {
#if defined(ARGUS_THREADS)
                  if (pthread_mutex_lock(&servers->lock) == 0) {
#endif
                     int x, cnt = servers->count;
                     struct ArgusListObjectStruct *list = servers->start;

                     for (x = 0; x < cnt; x++) {
                        struct RaAddressStruct *raddr = (struct RaAddressStruct *)list->list_obj;
                        char *addrStr = NULL;

                        switch (raddr->addr.type) {
                           case AF_INET: {
                              unsigned int addr = htonl(raddr->addr.addr[0]);
                              struct in_addr naddr = *(struct in_addr *)&addr;
                              addrStr = inet_ntoa(naddr);
                              break;
                           }
                           case AF_INET6: {
                              addrStr = raddr->addr.str;
                              break;
                           }
                        }

                        if (x == 0) {
                           char sbuf[256];
                           snprintf (sbuf, 256, "\"server\":[ \"%s\"", addrStr);
                           if (x == (cnt - 1)) 
                              sprintf (&sbuf[strlen(sbuf)]," ]");
                           results[resultnum++] = strdup(sbuf);
                        } else {
                           char sbuf[256];
                           snprintf (sbuf, 256, "\"%s\"", addrStr);
                           if (x == (cnt - 1)) 
                              sprintf (&sbuf[strlen(sbuf)]," ]");
                           results[resultnum++] = strdup(sbuf);
                        }
                        list = list->nxt;
                     }
#if defined(ARGUS_THREADS)
                     pthread_mutex_unlock(&servers->lock);
                  }
#endif
               }

               if (clients != NULL) {
#if defined(ARGUS_THREADS)
                  if (pthread_mutex_lock(&clients->lock) == 0) {
#endif
                     int x, cnt = clients->count;
                     struct ArgusListObjectStruct *list = clients->start;

                     for (x = 0; x < cnt; x++) {
                        struct RaAddressStruct *raddr = (struct RaAddressStruct *)list->list_obj;
                        char *addrStr = NULL;

                        switch (raddr->addr.type) {
                           case AF_INET: {
                              unsigned int addr = htonl(raddr->addr.addr[0]);
                              struct in_addr naddr = *(struct in_addr *)&addr;
                              addrStr = inet_ntoa(naddr);
                              break;
                           }
                           case AF_INET6: {
                              addrStr = raddr->addr.str;
                              break;
                           }
                        }

                        if (x == 0) {
                           char sbuf[256];
                           snprintf (sbuf, 256, "\"client\":[ \"%s\"", addrStr);
                           if (x == (cnt - 1))
                              sprintf (&sbuf[strlen(sbuf)]," ]");
                           results[resultnum++] = strdup(sbuf);
                        } else {
                           char sbuf[256];
                           snprintf (sbuf, 256, "\"%s\"", addrStr);
                           if (x == (cnt - 1))
                              sprintf (&sbuf[strlen(sbuf)]," ]");
                           results[resultnum++] = strdup(sbuf);
                        }
                        list = list->nxt;
                     }
#if defined(ARGUS_THREADS)
                     pthread_mutex_unlock(&clients->lock);
                  }
#endif
               }

               if (ArgusParser->ArgusPrintJson) {
                  sprintf (resbuf, "{ \"name\":\"%s\"", results[0]);
               } else {
                  sprintf (resbuf, "%s: %s [", sptr, results[0]);
               }

               if (resultnum > 1) {
                  if (ArgusParser->ArgusPrintJson) {
                     sprintf (&resbuf[strlen(resbuf)], ", ");
                  }

                  for (x = 1; x < resultnum; x++) {
                     if (x > 1) sprintf (&resbuf[strlen(resbuf)], ", ");
                     sprintf (&resbuf[strlen(resbuf)], "%s", results[x]);
                     free(results[x]);
                  }
               }

               if (ArgusParser->ArgusPrintJson) {
                  if (resultnum > 1) {
                     sprintf (&resbuf[strlen(resbuf)], " }");
                  } else {
                     sprintf (&resbuf[strlen(resbuf)], " }");
                  }
               } else {
                  if (resultnum > 1) {
                     sprintf (&resbuf[strlen(resbuf)], " ]");
                  } else {
                     sprintf (&resbuf[strlen(resbuf)], " ]");
                  }
               }
               retn[rind++] = strdup(resbuf);
               free(results[0]);
               ArgusFree(results);
            }
         }
         ArgusFree(matches);
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

int RaPrintCounter = 1;
static int argus_version = ARGUS_VERSION;

int ArgusParseIanaTlds(struct ArgusLabelerStruct *, char **);

int
ArgusParseIanaTlds(struct ArgusLabelerStruct *labeler, char **tlds)
{
   struct ArgusHashTable *table = labeler->htable;
   int retn = 0, slen;

   while (*tlds != NULL) {
      if (*tlds && (slen = strlen(*tlds))) {
         char *name = strdup(*tlds);
         struct ArgusHashStruct ArgusHash;
         struct nnamemem *nname;
         int i;

         for (i = 0; i < slen; i++)
           name[i] = tolower((int)name[i]);

         bzero(&ArgusHash, sizeof(ArgusHash));
         ArgusHash.len = slen;
         ArgusHash.hash = getnamehash((const u_char *)name);
         ArgusHash.buf = (unsigned int *)name;

         if ((nname = ArgusCalloc(1, sizeof(struct nnamemem))) == NULL)
            ArgusLog (LOG_ERR, "ArgusParseIanaTlds: ArgusCalloc error %s\n", strerror(errno));

         nname->hashval = ArgusHash.hash;
         nname->n_name = name;
         nname->tld_name = name;

         nname->status |= ARGUS_DNS_TLD;
         ArgusAddHashEntry(table, (void *)nname, &ArgusHash);
         retn++;
      }
      tlds++;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusParseIanaTlds(%p, %p) processed %d TLDs\n", table, tlds, table->count);
#endif
   return (retn);
}

#define RA_DNS_RCITEMS		2
#define RADNS_ROOT_DOMAINS      0
#define RADNS_ROOT_DEFAULT	1

struct ArgusListStruct *RaDnsRootDomains = NULL;
char *RaDnsRootDomainDefault = NULL;

char *RaDnsResourceFileStr [] = {
   "RADNS_ROOT_DOMAINS=",
   "RADNS_ROOT_DEFAULT=",
};

static int
RaDnsParseResourceLine(struct ArgusParserStruct *parser, int linenum, char *optarg, int quoted, int idx)
{
   switch (idx) {
      case RADNS_ROOT_DOMAINS: {
         char *domains, *sptr, *dptr;
         struct ArgusListObjectStruct *lobj;

         dptr = domains = strdup(optarg);
         
         if (RaDnsRootDomains == NULL) {
            RaDnsRootDomains = ArgusNewList();
         }

         while ((sptr = strtok(dptr, ",")) != NULL) {
            if ((lobj = ArgusCalloc(1, sizeof(*lobj))) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

            lobj->list_obj = strdup(sptr);
            ArgusPushBackList(RaDnsRootDomains, (struct ArgusListRecord *)lobj, ARGUS_LOCK);
            dptr = NULL;
         }
         free (dptr);
         break;
      }

      case RADNS_ROOT_DEFAULT: {
         if (RaDnsRootDomainDefault != NULL) free(RaDnsRootDomainDefault);
         RaDnsRootDomainDefault = strdup(optarg);
         break;
      }
   }
   return 0;
}

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   struct RaAddressStruct **ArgusAddrTree;
   struct ArgusModeStruct *mode = NULL;
   struct stat statbuf;
   char *path = NULL;

   parser->RaWriteOut  = 0;
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

      if ((path = parser->ArgusFlowModelFile) != NULL) {
         if (stat (path, &statbuf) == 0) {
            RaParseResourceFile (parser, path, ARGUS_SOPTIONS_PROCESS,
                                 RaDnsResourceFileStr, RA_DNS_RCITEMS,
                                 RaDnsParseResourceLine);
         }
      }

// 
// The ArgusLabeler struct holds the addresses returned in DNS queries.
// 

      if ((ArgusLabeler = ArgusNewLabeler(parser, ARGUS_LABELER_ADDRESS)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewLabeler error");

      if (ArgusLabeler->ArgusAddrTree == NULL)
         if ((ArgusLabeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog (LOG_ERR, "RaReadAddressConfig: ArgusCalloc error %s\n", strerror(errno));

      ArgusAddrTree = ArgusLabeler->ArgusAddrTree;
      parser->ArgusLabeler = ArgusLabeler;

      if ((ArgusDnsNames = ArgusNewLabeler(parser, ARGUS_LABELER_NAMES)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusDnsNames ArgusNewLabeler error");

      ArgusParseIanaTlds(ArgusDnsNames, ArgusIanaTopLevelDomains);

      if ((ArgusDnsServers = ArgusNewLabeler(parser, ARGUS_LABELER_ADDRESS)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusDnsServers ArgusNewLabeler error");

      if (ArgusDnsServers->ArgusAddrTree == NULL)
         if ((ArgusDnsServers->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog (LOG_ERR, "RaReadAddressConfig: ArgusCalloc error %s\n", strerror(errno));

      if ((ArgusDnsClients = ArgusNewLabeler(parser, ARGUS_LABELER_ADDRESS)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusDnsClients ArgusNewLabeler error");

      if (ArgusDnsClients->ArgusAddrTree == NULL)
         if ((ArgusDnsClients->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog (LOG_ERR, "RaReadAddressConfig: ArgusCalloc error %s\n", strerror(errno));

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
            if (!(strncasecmp (mode->mode, "debug.names", 11))) {
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
            if (!(strncasecmp (mode->mode, "label", 5))) {
               parser->labelflag = 1;
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

      if ((ArgusDNSServerTable = ArgusNewHashTable(0x1000)) == NULL)
         ArgusLog (LOG_ERR, "ArgusClientInit: ArgusNewHashTable error");

      if ((ArgusDNSNameSpace = (struct ArgusNameSpace *)ArgusCalloc(1, sizeof(*ArgusDNSNameSpace))) != NULL)
         if ((ArgusDNSNameSpace->tlds = ArgusNewQueue()) != NULL)
            ArgusDNSNameSpace->table = ArgusNewHashTable(0x10000);

      if (parser->ArgusWfileList != NULL) {
         parser->qflag = 1;
      }

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

         ArgusDeleteQueue(ArgusDNSNameSpace->tlds);
         ArgusDeleteHashTable(ArgusDNSNameSpace->table);
         ArgusFree(ArgusDNSNameSpace);

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
   unsigned int status, hashval, ref;
   struct timeval stime, ltime;

   char *n_name, *d_name;
   struct ArgusListStruct *refers;
   struct ArgusListStruct *cidrs;
   struct ArgusListStruct *cnames;
   struct ArgusListStruct *aliases;
   struct ArgusListStruct *ptrs;
};
*/
                     if (name->n_name) free(name->n_name);
                     if (name->refers  != NULL) ArgusDeleteList(name->refers, ARGUS_RR_LIST);
                     if (name->cidrs   != NULL) ArgusDeleteList(name->cidrs, ARGUS_RR_LIST);
                     if (name->cnames  != NULL) ArgusDeleteList(name->cnames, ARGUS_RR_LIST);
                     if (name->aliases != NULL) ArgusDeleteList(name->aliases, ARGUS_RR_LIST);
                     if (name->ptrs    != NULL) ArgusDeleteList(name->ptrs, ARGUS_RR_LIST);
                     if (name->servers != NULL) ArgusDeleteList(name->servers, ARGUS_OBJECT_LIST);
                     if (name->clients != NULL) ArgusDeleteList(name->clients, ARGUS_OBJECT_LIST);

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

int RaProcessARecord (struct ArgusParserStruct *, struct ArgusDomainStruct *, struct ArgusDomainQueryStruct *, struct timeval *);
int RaProcessCRecord (struct ArgusParserStruct *, struct ArgusDomainStruct *, struct ArgusDomainQueryStruct *, struct timeval *);
int RaProcessSOARecord (struct ArgusParserStruct *, struct ArgusDomainStruct *, struct ArgusDomainQueryStruct *, struct timeval *);
int RaProcessNSRecord (struct ArgusParserStruct *, struct ArgusDomainStruct *, struct ArgusDomainQueryStruct *, struct timeval *);
int RaProcessPTRRecord (struct ArgusParserStruct *, struct ArgusDomainStruct *, struct ArgusDomainQueryStruct *, struct timeval *);
int RaProcessMXRecord (struct ArgusParserStruct *, struct ArgusDomainStruct *, struct ArgusDomainQueryStruct *, struct timeval *);

// ArgusNameEntry will take a FQDN and insert it into a hash table, as well as insert the
// name into a namespace tree.


struct nnamemem *
ArgusFindNameEntry (struct ArgusHashTable *table, char *name)
{
   struct nnamemem *retn = NULL;

   if (name && strlen(name)) {
      struct ArgusHashTableHdr *htbl = NULL;
      struct ArgusHashStruct ArgusHash;
      char *lname = strdup(name);
      int i;

      bzero(&ArgusHash, sizeof(ArgusHash));
      ArgusHash.buf = (unsigned int *)lname;
      ArgusHash.len = strlen(lname);

      for (i = 0; i < ArgusHash.len; i++)
        lname[i] = tolower((int)lname[i]);

      ArgusHash.hash = getnamehash((const u_char *)lname);

      if ((htbl = ArgusFindHashEntry(table, &ArgusHash)) != NULL) {
         retn = (struct nnamemem *) htbl->object;
      }
      free(lname);
   }
   return(retn);
}


struct nnamemem *
ArgusNameEntry (struct ArgusHashTable *table, char *name, int status)
{
   struct nnamemem *retn = NULL;
   char fqdn[MAXSTRLEN];

   if (name && strlen(name)) {
      struct ArgusHashTableHdr *htbl = NULL;
      struct ArgusHashStruct ArgusHash;
      char *lname = NULL, *sptr, *eptr;
      int slen = strlen(name);
      int i;

      for (i = 0; i < strlen(name); i++)
        name[i] = tolower((int)name[i]);

      if ((RaDnsRootDomainDefault != NULL) && (status == 0)) {
         if (snprintf(fqdn, MAXSTRLEN, "%s", name) > 0) {
            int dotted = 0;

            if ((eptr = strrchr(fqdn, '.')) != NULL) {
               if (eptr == &fqdn[strlen(fqdn) -1]) {
                  *eptr = '\0';
                  dotted = 1;
               }
            }

            if ((sptr = strrchr(fqdn, '.')) == NULL) {
               sptr = fqdn;
            } else {
               sptr++;
            }
            if (dotted) {
               *eptr = '.';
               dotted = 0;
            }

            if (ArgusFindNameEntry(ArgusDnsNames->htable, sptr) == NULL) {
               int splen = 0, len;
               int found = 0;
               if (RaDnsRootDomains != NULL) {
                  struct ArgusListObjectStruct *lobj;
                  char *domain;

                  len = RaDnsRootDomains->count;

                  for (i = 0; (i < len) && !found; i++) {
                     lobj = (struct ArgusListObjectStruct *) ArgusPopFrontList(RaDnsRootDomains, ARGUS_LOCK);
                     domain = (char *)lobj->list_obj;
                     splen = strlen(sptr);

                     ArgusPushBackList(RaDnsRootDomains, (struct ArgusListRecord *)lobj, ARGUS_LOCK);

                     if (strncmp(domain, sptr, splen) == 0) {
                        char *dptr = &domain[splen];
                        snprintf(&fqdn[slen], MAXSTRLEN - slen, "%s.", dptr);
                        found = 1;
                     }
                  }
               }

               if (!found && splen > 0) {
                  if (strncmp(RaDnsRootDomainDefault, sptr, splen) == 0) {
                     char *dptr = &RaDnsRootDomainDefault[splen];
                     snprintf(&fqdn[slen], MAXSTRLEN - slen, "%s.", dptr);
                     found = 1;
                  } else {
                     snprintf(&fqdn[slen], MAXSTRLEN - slen, "%s.", RaDnsRootDomainDefault);
                  }
               }
            }
            lname = strdup(fqdn);
         }

      } else {
         lname = strdup(name);
      }

      bzero(&ArgusHash, sizeof(ArgusHash));
      ArgusHash.len = strlen(lname);
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

         if (retn->d_name && (strlen(retn->d_name) > 0)) {
            if (ArgusNameEntry (ArgusDNSNameSpace->table, retn->d_name, 1) != NULL) {
            }
         }

         ArgusAddHashEntry(table, (void *)retn, &ArgusHash);
#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusNameEntry() adding DNS name %s[%d] tld %s total %d\n", retn->n_name, (retn->hashval % table->size), retn->d_name, table->count);
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
//  The use of the patricia tree indicates that we can seed the tree with the IANA rir database,
//  delegated-ipv4-*-latest like file, to give us a since of what is allocated and what is not.
//  The concept is that the domain name, or parts of the domain name should cover CIDR addresses.
//  And so we can then start to guess what domain a new address may be in.
//   
//   


int
RaProcessARecord (struct ArgusParserStruct *parser, struct ArgusDomainStruct *dns, struct ArgusDomainQueryStruct *res, struct timeval *tvp)
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
      struct nnamemem *refer = ArgusNameEntry(ArgusDNSNameTable, res->name, 0);
      struct RaAddressStruct *raddr = NULL;
      int i, ttl = 0, count = res->ans->count;

      if (dns->server != NULL) {
         if (refer->servers == NULL) 
            refer->servers = ArgusNewList();
         ArgusAddObjectToList(refer->servers, dns->server, ARGUS_LOCK);
      }
 
      if (dns->client != NULL) {
         if (refer->clients == NULL) 
            refer->clients = ArgusNewList();
         ArgusAddObjectToList(refer->clients, dns->client, ARGUS_LOCK);
      }

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

               struct nnamemem *name = ArgusNameEntry(ArgusDNSNameTable, rr->name, 0);
       
               if (name != NULL) {
                  name->ref++;

                  if (dns->server != NULL) {
                     if (name->servers == NULL)
                        name->servers = ArgusNewList();
                     ArgusAddObjectToList(name->servers, dns->server, ARGUS_LOCK);
                  }

                  if (dns->client != NULL) {
                     if (name->clients == NULL)
                        name->clients = ArgusNewList();
                     ArgusAddObjectToList(name->clients, dns->client, ARGUS_LOCK);
                  }

                  bcopy(cidr, &node.addr, sizeof(*cidr));
                  if (cidr->str != NULL)
                     node.addr.str = strdup(cidr->str);

                  bcopy(cidr, &rr->cidr, sizeof(*cidr));
                  if (cidr->str != NULL)
                     rr->cidr.str = strdup(cidr->str);

                  if (name->cidrs == NULL) {
                     name->cidrs = ArgusNewList();
                     ncidr = 1;
                  }

                  if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[cidr->type], &node, ARGUS_EXACT_MATCH)) == NULL) {
                     if ((raddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*raddr))) != NULL) {
                        bcopy(&node, raddr, sizeof(node));
                        if (node.addr.str != NULL)
                           raddr->addr.str = strdup(node.addr.str);

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

                     list->status |= ARGUS_DNS_AUTH;
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

                     list->status |= ARGUS_DNS_AUTH;
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

                        list->status |= ARGUS_DNS_REFERER;
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
RaProcessCRecord (struct ArgusParserStruct *parser, struct ArgusDomainStruct *dns, struct ArgusDomainQueryStruct *res, struct timeval *tvp)
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

         if ((name = ArgusNameEntry(ArgusDNSNameTable, rr->name, 0)) != NULL) {
            if ((cname = ArgusNameEntry(ArgusDNSNameTable, rr->data, 0)) != NULL) {
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
               if (dns->server != NULL) {
                  if (name->servers == NULL)
                     name->servers = ArgusNewList();
                  ArgusAddObjectToList(name->servers, dns->server, ARGUS_LOCK);
               }

               if (dns->client != NULL) {
                  if (name->clients == NULL)
                     name->clients = ArgusNewList();
                  ArgusAddObjectToList(name->clients, dns->client, ARGUS_LOCK);
               }

               if (ncname != 0) {
                  struct ArgusListObjectStruct *list;
                  if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                     ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

                  list->status |= ARGUS_DNS_CNAME;
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

                  list->status |= ARGUS_DNS_ALIAS;
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
RaProcessNSRecord (struct ArgusParserStruct *parser, struct ArgusDomainStruct *dns, struct ArgusDomainQueryStruct *res, struct timeval *tvp)
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

         if ((ptr = ArgusNameEntry(ArgusDNSNameTable, rr->name, 0)) != NULL) {

            if (dns->server != NULL) {
               if (ptr->servers == NULL)
                  ptr->servers = ArgusNewList();
               ArgusAddObjectToList(ptr->servers, dns->server, ARGUS_LOCK);
            }

            if (dns->client != NULL) {
               if (ptr->clients == NULL)
                  ptr->clients = ArgusNewList();
               ArgusAddObjectToList(ptr->clients, dns->client, ARGUS_LOCK);
            }


            if ((name = ArgusNameEntry(ArgusDNSNameTable, rr->data, 0)) != NULL) {
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
RaProcessSOARecord (struct ArgusParserStruct *parser, struct ArgusDomainStruct *dns, struct ArgusDomainQueryStruct *res, struct timeval *tvp)
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
            ArgusLog(LOG_ERR, "RaProcessSOARecord: ArgusCalloc error");
   }

   if ((res != NULL) && (res->soa != NULL)) {
      int x, count = res->soa->count;
      for (x = 0; x < count; x++) {
         struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->soa, ARGUS_NOLOCK);
         struct ArgusDomainResourceRecord *rr = list->list_union.obj;

         if ((ptr = ArgusNameEntry(ArgusDNSNameTable, rr->name, 0)) != NULL) {
            if (dns->server != NULL) {
               if (ptr->servers == NULL)
                  ptr->servers = ArgusNewList();
               ArgusAddObjectToList(ptr->servers, dns->server, ARGUS_LOCK);
            }

            if (dns->client != NULL) {
               if (ptr->clients == NULL)
                  ptr->clients = ArgusNewList();
               ArgusAddObjectToList(ptr->clients, dns->client, ARGUS_LOCK);
            }

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
RaProcessPTRRecord (struct ArgusParserStruct *parser, struct ArgusDomainStruct *dns, struct ArgusDomainQueryStruct *res, struct timeval *tvp)
{
   struct nnamemem *ptr = NULL, *name = NULL;
   struct ArgusLabelerStruct *labeler;
   int retn = 0;

   if ((labeler = parser->ArgusLabeler) == NULL) {
      parser->ArgusLabeler = ArgusNewLabeler(parser, 0L);
      labeler = parser->ArgusLabeler;
      if (labeler->ArgusAddrTree == NULL)
         if ((labeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog(LOG_ERR, "RaProcessPTRRecord: ArgusCalloc error");
   }

   if ((res != NULL) && (res->ptr != NULL)) {
      int i, x, count = res->ptr->count;
      for (x = 0; x < count; x++) {
         struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->ptr, ARGUS_NOLOCK);
         struct ArgusDomainResourceRecord *rr = list->list_union.obj;

         if ((ptr = ArgusNameEntry(ArgusDNSNameTable, rr->name, 0)) != NULL) {
            if ((ptr->stime.tv_sec == 0) || (ptr->stime.tv_sec > dns->stime.tv_sec)) {
               ptr->stime = dns->stime;
            }
            if ((ptr->ltime.tv_sec == 0) || (ptr->ltime.tv_sec < dns->ltime.tv_sec)) {
               ptr->ltime = dns->ltime;
            }

           if (dns->server != NULL) {
              if (ptr->servers == NULL)
                 ptr->servers = ArgusNewList();
              ArgusAddObjectToList(ptr->servers, dns->server, ARGUS_LOCK);
           }

           if (dns->client != NULL) {
              if (ptr->clients == NULL)
                 ptr->clients = ArgusNewList();
              ArgusAddObjectToList(ptr->clients, dns->client, ARGUS_LOCK);
           }

            if ((name = ArgusNameEntry(ArgusDNSNameTable, rr->data, 0)) != NULL) {
               char *nptr = strdup(rr->name);
               char *sptr, *tptr;

               if ((name->stime.tv_sec == 0) || (name->stime.tv_sec > dns->stime.tv_sec)) {
                  name->stime = dns->stime;
               }
               if ((name->ltime.tv_sec == 0) || (name->ltime.tv_sec < dns->ltime.tv_sec)) {
                  name->ltime = dns->ltime;
               }

               if (dns->server != NULL) {
                  if (name->servers == NULL)
                     name->servers = ArgusNewList();
                  ArgusAddObjectToList(name->servers, dns->server, ARGUS_LOCK);
               }

               if (dns->client != NULL) {
                  if (name->clients == NULL)
                     name->clients = ArgusNewList();
                  ArgusAddObjectToList(name->clients, dns->client, ARGUS_LOCK);
               }

               if ((tptr = nptr) != NULL) {
                  struct RaAddressStruct *raddr = NULL, node;
                  struct ArgusCIDRAddr *cidr = NULL;
                  char addrbuf[128], *addr = addrbuf, *a[32];
                  int ind = 0;

                  bzero(addrbuf, sizeof(addrbuf));
                  bzero(a, sizeof(a));

                  if ((sptr = strstr(tptr, ".in-addr.arpa")) != NULL) {
                     *sptr = '\0';
                     while ((sptr = strtok(tptr, ".")) != NULL) {
                        char *dptr = NULL;
                        if ((dptr = strchr(sptr, '-')) != NULL)
                           sptr = dptr + 1;
                        a[ind++] = strdup(sptr);
                        tptr = NULL;
                     }
                     sprintf (addr, "%s.%s.%s.%s", a[3], a[2], a[1], a[0]);
                     for (i = 0; i < ind; i++) if (a[i] != NULL) {free(a[i]); a[i] = NULL;}

                  } else
                  if ((sptr = strstr(tptr, ".ip6.arpa")) != NULL) {
                     int next = 0;
                     *sptr = '\0';
                     while ((sptr = strtok(tptr, ".")) != NULL) {
                        a[ind++] = strdup(sptr);
                        tptr = NULL;
                     }
                     for (i = ind - 1; i >= 0; i--) {
                        if (a[i] != NULL) {
                           if (strcmp(a[i],"0")) {
                              sprintf (&addr[strlen(addr)], "%s", a[i]);
                              next = 1;
                           } else {
                              if (next == 1)
                                 sprintf (&addr[strlen(addr)], "%s", a[i]);
                           }
                           if ((i % 4) == 0) {
                              if (next == 0) sprintf (&addr[strlen(addr)], "0");
                              if (i > 0) sprintf (&addr[strlen(addr)], ":");
                              next = 0;
                           }
                           free(a[i]);
                           a[i] = NULL;
                        }
                     }
                  }

                  if ((cidr = RaParseCIDRAddr (ArgusParser, addr)) != NULL) {
                     int ndns, cnt;
                     int ncidr = 0;

                     bzero ((char *)&node, sizeof(node));
                     bcopy(cidr, &node.addr, sizeof(*cidr));
                     if (node.addr.str != NULL)
                        node.addr.str = strdup(cidr->str);

                     if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[cidr->type], &node, ARGUS_EXACT_MATCH)) == NULL) {
                        if ((raddr = (struct RaAddressStruct *) ArgusMalloc (sizeof(*raddr))) != NULL) {
                           int ttl = 0, tttl;

                           bcopy(&node, raddr, sizeof(node));
                           if (node.addr.str != NULL)
                              raddr->addr.str = strdup(node.addr.str);

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
                           if ((tname == name) && (list->status & ARGUS_DNS_PTR))
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

                        list->status |= ARGUS_DNS_PTR;
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

                        list->status |= ARGUS_DNS_PTR;
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

//
//
//  RaProcessMXRecord
//
//  This routine will process a dns MX record.  The key is to insert the responses data
//  record, and associate it with the domain name it referenced.
//  
//  MX records provide mail server routing.  Amex is interested in generating alarms if
//  these show up.
//
//

int
RaProcessMXRecord (struct ArgusParserStruct *parser, struct ArgusDomainStruct *dns, struct ArgusDomainQueryStruct *res, struct timeval *tvp)
{
   struct nnamemem *ptr = NULL, *name = NULL;
   struct ArgusLabelerStruct *labeler;
   int retn = 0;

   if ((labeler = parser->ArgusLabeler) == NULL) {
      parser->ArgusLabeler = ArgusNewLabeler(parser, 0L);
      labeler = parser->ArgusLabeler;
      if (labeler->ArgusAddrTree == NULL)
         if ((labeler->ArgusAddrTree = ArgusCalloc(128, sizeof(void *))) == NULL)
            ArgusLog(LOG_ERR, "RaProcessMXRecord: ArgusCalloc error");
   }

   if ((res != NULL) && (res->mx != NULL)) {
      int x, count = res->mx->count;
      for (x = 0; x < count; x++) {
         struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(res->mx, ARGUS_NOLOCK);
         struct ArgusDomainResourceRecord *rr = list->list_union.obj;

         if ((ptr = ArgusNameEntry(ArgusDNSNameTable, rr->name, 0)) != NULL) {
            char *dptr = strdup(rr->data), *tptr, *sptr, *mxsptr;
            int ind = 0;

            if ((ptr->stime.tv_sec == 0) || (ptr->stime.tv_sec > dns->stime.tv_sec)) {
               ptr->stime = dns->stime;
            }
            if ((ptr->ltime.tv_sec == 0) || (ptr->ltime.tv_sec < dns->ltime.tv_sec)) {
               ptr->ltime = dns->ltime;
            }
// MX record data string format is "name mx server priority".
// Need to pass the mx server to ArgusNameEntry.
            tptr = dptr;
            while ((sptr = strtok(tptr, " ")) != NULL) {
               if (ind++ == 1) {
                  mxsptr = strdup(sptr);
               }
               tptr = NULL;
            }
            free(dptr);

            if ((name = ArgusNameEntry(ArgusDNSNameTable, mxsptr, 0)) != NULL) {
               if ((name->stime.tv_sec == 0) || (name->stime.tv_sec > dns->stime.tv_sec)) {
                  name->stime = dns->stime;
               }
               if ((name->ltime.tv_sec == 0) || (name->ltime.tv_sec < dns->ltime.tv_sec)) {
                  name->ltime = dns->ltime;
               }

               if (name->mxs == NULL)
                  name->mxs = ArgusNewList();

#if defined(ARGUS_THREADS)
               if (pthread_mutex_lock(&name->mxs->lock) == 0) {
#endif
#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&name->mxs->lock);
               }
#endif
            }
            if (mxsptr != NULL)
               free(mxsptr);
         }
         ArgusPushBackList(res->mx, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
      }
   }
   return retn;
}

#define ISPORT(p) (dport == (p) || sport == (p))

void RaProcessEventRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessThisEventRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);
void RaProcessManRecord (struct ArgusParserStruct *, struct ArgusRecordStruct *);

char ArgusRecordBuffer[ARGUS_MAXRECORDSIZE];
#define ARGUS_MAX_DNS_BUFFER	0x4000

void
RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   char *buf, *label, tbuf[64], *tptr;

   if ((buf = ArgusCalloc(1, ARGUS_MAX_DNS_BUFFER)) == NULL)
      ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s\n", strerror(errno));

   if ((label = ArgusCalloc(1, ARGUS_MAX_DNS_BUFFER)) == NULL)
      ArgusLog (LOG_ERR, "RaProcessRecord: ArgusCalloc error %s\n", strerror(errno));

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
      case ARGUS_AFLOW:
      case ARGUS_FAR: {
         struct ArgusFlow *flow = (struct ArgusFlow *) argus->dsrs[ARGUS_FLOW_INDEX];
         struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX];

         struct timeval tvpbuf, *tvp = RaGetLastTime(argus, &tvpbuf);

         unsigned short proto = 0, sport = 0, dport = 0;
         int type, process = 0, dnsTransaction = 0;

         struct RaAddressStruct *dnsSrvr = NULL;
         struct RaAddressStruct *dnsClnt = NULL;

         unsigned int srcAddrType = 0;
         unsigned int dstAddrType = 0;

         void *dnsClient = NULL, *dnsServer = NULL;
         void *daddr = NULL;
         void *saddr = NULL;

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
                        srcAddrType = RaIPv4AddressType(parser, *(unsigned int *)saddr);
                        dstAddrType = RaIPv4AddressType(parser, *(unsigned int *)daddr);
                        break;
                     }

                     case ARGUS_TYPE_IPV6: {
                        process++;

                        saddr = &flow->ipv6_flow.ip_src;
                        daddr = &flow->ipv6_flow.ip_dst;
                        proto = flow->ipv6_flow.ip_p;

                        switch (flow->ipv6_flow.ip_p) {
                           case IPPROTO_TCP:
                           case IPPROTO_UDP: {
                              sport = flow->ipv6_flow.sport;
                              dport = flow->ipv6_flow.dport;
                              break;
                           }
                        }
                        srcAddrType = RaIPv6AddressType(parser, (struct in6_addr *)saddr);
                        dstAddrType = RaIPv6AddressType(parser, (struct in6_addr *)daddr);
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
                  }
                  break;
               }
            }

            if (dnsTransaction) {
               struct ArgusDomainStruct dnsbuf, *dns = NULL;
               int unicast = 0;

               bzero (&dnsbuf, sizeof(dnsbuf));

               if ((dns = ArgusParseDNSRecord(parser, argus, &dnsbuf, proto)) != NULL) {
                  struct ArgusDomainQueryStruct *req = dns->request;
                  struct ArgusDomainQueryStruct *res = dns->response;
                  unsigned int dnsAddrType = 0;

                  if ((dns->status & ARGUS_ERROR) || (!(req || res))) {
#if defined(ARGUSDEBUG)
                     ArgusDebug (1, "RaProcessRecord: ArgusParseDNSRecord error\n");
#endif
                     return;
                  }
                  if (dns->status & ARGUS_REVERSE) {
                     dnsServer = saddr;
                     dnsClient = daddr;
                  } else {
                     dnsServer = daddr;
                     dnsClient = saddr;
                  }

                  if (req && res) {
                     dnsAddrType = dstAddrType;
                  } else
                  if (req) {
                     dnsAddrType = dstAddrType;
                  } else {
                     dnsAddrType = srcAddrType;
                  }

                  switch (dnsAddrType) {
                        case ARGUS_IPV4_UNICAST: 
                        case ARGUS_IPV4_UNICAST_THIS_NET: 
                        case ARGUS_IPV4_UNICAST_PRIVATE: 
                        case ARGUS_IPV4_UNICAST_LINK_LOCAL: 
                        case ARGUS_IPV4_UNICAST_LOOPBACK: 
                        case ARGUS_IPV4_UNICAST_TESTNET: 
                        case ARGUS_IPV4_UNICAST_RESERVED: 

                        case ARGUS_IPV6_UNICAST:
                        case ARGUS_IPV6_UNICAST_UNSPECIFIED:
                        case ARGUS_IPV6_UNICAST_LOOPBACK:
                        case ARGUS_IPV6_UNICAST_V4COMPAT:
                        case ARGUS_IPV6_UNICAST_V4MAPPED:
                        case ARGUS_IPV6_UNICAST_LINKLOCAL:
                        case ARGUS_IPV6_UNICAST_SITELOCAL:
                           unicast = 1;
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

                        case ARGUS_IPV6_MULTICAST:
                        case ARGUS_IPV6_MULTICAST_NODELOCAL:
                        case ARGUS_IPV6_MULTICAST_LINKLOCAL:
                        case ARGUS_IPV6_MULTICAST_SITELOCAL:
                        case ARGUS_IPV6_MULTICAST_ORGLOCAL:
                        case ARGUS_IPV6_MULTICAST_GLOBAL:
//                         multicast = 1;
                           break;
                  }

// test if there is a regex expression and match against the query/response name.
/*
                  if (parser->estr != NULL) {
                     char *tbuf = (req && req->name) ? req->name : NULL;
                     found = 0;

                     if (tbuf != NULL) {
                        int slen = strlen(tbuf), retn, i;
                        for (i = 0; i < parser->ArgusRegExItems; i++) {
                           if ((retn = ArgusGrepBuf (&parser->upreg[i], tbuf, &tbuf[slen]))) {
                              found++;
                              break;
                           }
                        }
                     }
                     if (!found) {
                        char *tbuf = (res && res->name) ? res->name : NULL;
                        if (tbuf != NULL) {
                           int slen = strlen(tbuf), retn, i;
                           for (i = 0; i < parser->ArgusRegExItems; i++) {
                              if ((retn = ArgusGrepBuf (&parser->upreg[i], tbuf, &tbuf[slen]))) {
                                 found++;
                                 break;
                              }
                           }
                        }
                     }
                  }
*/
                  if (unicast) {
                     struct RaAddressStruct *raddr = NULL, node;
  
                     bzero ((char *)&node, sizeof(node));

                     switch (type) {
                        case ARGUS_TYPE_IPV4: {
                           node.addr.type = AF_INET;
                           node.addr.addr[0] = *(unsigned int *)dnsServer;
                           node.addr.mask[0] = 0xFFFFFFFF;
                           node.addr.masklen = 32;
                           node.addr.len = 4;
 
                           if ((raddr = RaFindAddress (parser, ArgusDnsServers->ArgusAddrTree[AF_INET], &node, ARGUS_EXACT_MATCH)) == NULL) {
#if defined(ARGUSDEBUG)
                              ArgusDebug(1, "%s: RaProcessRecord: new DNS server %s\n", tptr, intoa(node.addr.addr[0]));
#endif
                              if ((raddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*raddr))) != NULL) {
                                 bcopy(&node, raddr, sizeof(node));
                                 if (node.addr.str != NULL)
                                    raddr->addr.str = strdup(node.addr.str);
                                 RaInsertAddress (parser, ArgusDnsServers, NULL, raddr, ARGUS_VISITED);
                              }
                           }
                           dns->server = dnsSrvr = raddr;

                           node.addr.addr[0] = *(unsigned int *)dnsClient;
                           node.addr.str = NULL;

                           if ((raddr = RaFindAddress (parser, ArgusDnsClients->ArgusAddrTree[AF_INET], &node, ARGUS_EXACT_MATCH)) == NULL) {
#if defined(ARGUSDEBUG)
                              ArgusDebug(1, "%s: RaProcessRecord: new DNS client %s\n", tptr, intoa(node.addr.addr[0]));
#endif

                              if ((raddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*raddr))) != NULL) {
                                 bcopy(&node, raddr, sizeof(node));
                                 if (node.addr.str != NULL)
                                    raddr->addr.str = strdup(node.addr.str);
                                 RaInsertAddress (parser, ArgusDnsClients, NULL, raddr, ARGUS_VISITED);
                              }
                           }
                           dns->client = dnsClnt = raddr;
                           break;
                        }
                        case ARGUS_TYPE_IPV6: {
                           char ntop_buf[INET6_ADDRSTRLEN];
                           const char *cp = NULL;

                           if ((cp = inet_ntop(AF_INET6, (const void *) dnsServer, ntop_buf, sizeof(ntop_buf))) != NULL) {
                              struct ArgusCIDRAddr *cidr = NULL;
                              if ((cidr = RaParseCIDRAddr (parser, (char *) cp)) != NULL) {
                                 bcopy(cidr, &node.addr, sizeof(*cidr));
                                 if (node.addr.str == NULL)
                                    node.addr.str = (char *)cp;
                                 if ((raddr = RaFindAddress (parser, ArgusDnsServers->ArgusAddrTree[cidr->type], &node, ARGUS_EXACT_MATCH)) == NULL) {
#if defined(ARGUSDEBUG)
                                    ArgusDebug(1, "%s: RaProcessRecord: new DNS server %s\n", tptr, cp);
#endif
                                    if ((raddr = (struct RaAddressStruct *) ArgusMalloc (sizeof(*raddr))) != NULL) {
                                       bcopy(&node, raddr, sizeof(node));
                                       if (node.addr.str != NULL)
                                          raddr->addr.str = strdup(node.addr.str);

                                       RaInsertAddress (parser, ArgusDnsServers, NULL, raddr, ARGUS_VISITED);
                                    }
                                 }
                                 dns->server = dnsSrvr = raddr;
                              }
                           }

                           if ((cp = inet_ntop(AF_INET6, (const void *) dnsClient, ntop_buf, sizeof(ntop_buf))) != NULL) {
                              struct ArgusCIDRAddr *cidr = NULL;
                              if ((cidr = RaParseCIDRAddr (parser, (char *) cp)) != NULL) {
                                 bcopy(cidr, &node.addr, sizeof(*cidr));
                                 if (node.addr.str == NULL)
                                    node.addr.str = (char *)cp;
                                 if ((raddr = RaFindAddress (parser, ArgusDnsClients->ArgusAddrTree[cidr->type], &node, ARGUS_EXACT_MATCH)) == NULL) {
#if defined(ARGUSDEBUG)
                                    ArgusDebug(1, "%s: RaProcessRecord: new DNS client %s\n", tptr, cp);
#endif
                                    if ((raddr = (struct RaAddressStruct *) ArgusMalloc (sizeof(*raddr))) != NULL) {
                                       bcopy(&node, raddr, sizeof(node));
                                       if (node.addr.str != NULL)
                                          raddr->addr.str = strdup(node.addr.str);

                                       RaInsertAddress (parser, ArgusDnsClients, NULL, raddr, ARGUS_VISITED);
                                    }
                                 }
                                 dns->client = dnsClnt = raddr;
                              }
                           }

                           break;
                        }
                     }
                  }

                  bzero (buf, ARGUS_MAX_DNS_BUFFER);

                  if (req && res) {
                     struct ArgusDomainQueryStruct *treq = req;
                     struct ArgusDomainQueryStruct *tres;
		     
                     while (treq) {
                        tres = res;
                        if (treq->name && strlen(treq->name)) {
                        while (treq->seqnum != tres->seqnum) {
                           if ((tres = tres->nxt) == NULL)
                              break;
			}

                        if (tres && ((tres->name && strlen(tres->name))))  {
                           if (!(strcasecmp(treq->name, tres->name))) {
                              if (treq->qtype != T_SOA) {
                                 if (tres->ans)
                                    RaProcessARecord(parser, dns, tres, tvp);

                                 if (tres->soa)
                                    RaProcessSOARecord(parser, dns, tres, tvp);

                                 if (tres->ns)
                                    RaProcessNSRecord(parser, dns, tres, tvp);

                                 if (tres->cname)
                                    RaProcessCRecord(parser, dns, tres, tvp);

                                 if (tres->ptr)
                                    RaProcessPTRRecord(parser, dns, tres, tvp);
                              }

                              if (!parser->qflag || parser->labelflag) {
                                 char *type = (char *)tok2str(ns_type2str, "Type%d", treq->qtype);

                                 sprintf (&buf[strlen(buf)], "%s: %s? %s : ", tptr, type, tres->name);

                                 if (tres->ans) {
                                    int i, count = tres->ans->count;
                                    type = (char *)tok2str(ns_type2str, "Type%d", tres->qtype);

                                    for (i = 0; i < count; i++) {
                                       struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(tres->ans, ARGUS_NOLOCK);
                                       struct ArgusDomainResourceRecord *rr = list->list_union.obj;

                                       type = (char *)tok2str(ns_type2str, "Type%d", rr->type);
                                       if (i == 0) sprintf (&buf[strlen(buf)], " %s %s %s[%d]", type, rr->name, rr->data, rr->ttl);
                                       else sprintf (&buf[strlen(buf)], ",%s[%d]", rr->data, rr->ttl);
                                       ArgusPushBackList(tres->ans, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                    }
                                 }

                                 if (tres->cname) {
                                    int i, count = tres->cname->count;
                                    for (i = 0; i < count; i++) {
                                       struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(tres->cname, ARGUS_NOLOCK);
                                       struct ArgusDomainResourceRecord *rr = list->list_union.obj;

                                       type = (char *)tok2str(ns_type2str, "Type%d", rr->type);
                                       sprintf (&buf[strlen(buf)], " %s %s %s", type, rr->name, rr->data);
                                       ArgusPushBackList(tres->cname, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                    }
                                 }

                                 if (tres->soa) {
                                    int i, count = tres->soa->count;

                                    for (i = 0; i < count; i++) {
                                       struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(tres->soa, ARGUS_NOLOCK);
                                       struct ArgusDomainResourceRecord *rr = list->list_union.obj;

                                       type = (char *)tok2str(ns_type2str, "Type%d", rr->type);

                                       if (i == 0) sprintf (&buf[strlen(buf)], " %s %s %s %s %d %d %d %d %d", type, rr->name,
                                          rr->mname, rr->rname, rr->serial, rr->refresh, rr->retry, rr->expire, rr->minimum);
                                       else sprintf (&buf[strlen(buf)], ",%s", rr->mname);
                                       ArgusPushBackList(tres->soa, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                    }
                                 }

                                 if (tres->ns) {
                                    int i, count = tres->ns->count;
                                    
                                    for (i = 0; i < count; i++) {
                                       struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(tres->ns, ARGUS_NOLOCK);
                                       struct ArgusDomainResourceRecord *rr = list->list_union.obj;
                                       
                                       type = (char *)tok2str(ns_type2str, "Type%d", rr->type);
                                       if (i == 0) sprintf (&buf[strlen(buf)], " %s %s %s[%d]", type, rr->name, rr->data, rr->ttl);
                                       else sprintf (&buf[strlen(buf)], ",%s[%d]", rr->data, rr->ttl);
                                       ArgusPushBackList(tres->ns, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                    }  
                                 }
                                 if (tres->ptr) {
                                    int i, count = tres->ptr->count;

                                    for (i = 0; i < count; i++) {
                                       struct ArgusListObjectStruct *list =  (struct ArgusListObjectStruct *)ArgusPopFrontList(tres->ptr, ARGUS_NOLOCK);
                                       struct ArgusDomainResourceRecord *rr = list->list_union.obj;

                                       type = (char *)tok2str(ns_type2str, "Type%d", rr->type);
                                       if (i == 0) sprintf (&buf[strlen(buf)], " %s %s %s[%d]", type, rr->name, rr->data, rr->ttl);
                                       else sprintf (&buf[strlen(buf)], ",%s[%d]", rr->data, rr->ttl);
                                       ArgusPushBackList(tres->ptr, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                                    }
                                 }

                                 if (parser->labelflag) {
                                    if (strlen(buf) > 0) {
                                       snprintf (label, ARGUS_MAX_DNS_BUFFER, "dns='%s'", buf);
                                       ArgusAddToRecordLabel (parser, argus, label);
                                       argus->status |= ARGUS_RECORD_MODIFIED;
                                    }
                                 }

                                 if (!parser->qflag) {
                                    fprintf (stdout, "%s\n", buf);
                                    fflush(stdout);
                                    bzero (buf, ARGUS_MAX_DNS_BUFFER);
                                 }
                              }

                           } else
                              if (tres->ans) {
#if defined(ARGUSDEBUG)
                                 ArgusDebug(1, "%s: radns: request/response name mismatch req:%s res:%s\n", tptr, treq->name, tres->name);
#endif
                              }
                        } else
                           if (tres && tres->ans) {
#if defined(ARGUSDEBUG)
                              ArgusDebug(1, "%s: radns: request/response seq mismatch req:%d res:%d\n", tptr, req->seqnum, tres->seqnum);
#endif
                           }
                     }
                     treq = treq->nxt;
                     }
                  } else {
                     if (req != NULL) {
                        if (req->name  != NULL) free(req->name);
                        if (req->ans   != NULL) ArgusDeleteList(req->ans,   ARGUS_RR_LIST);
                        if (req->cname != NULL) ArgusDeleteList(req->cname, ARGUS_RR_LIST);
                        if (req->ns    != NULL) ArgusDeleteList(req->ns,    ARGUS_RR_LIST);
                     }
    
                     if (res != NULL) {
                        if (res->name  != NULL) free(res->name);
                        if (res->ans   != NULL) ArgusDeleteList(res->ans,   ARGUS_RR_LIST);
                        if (res->cname != NULL) ArgusDeleteList(res->cname, ARGUS_RR_LIST);
                        if (res->ns    != NULL) ArgusDeleteList(res->ns,    ARGUS_RR_LIST);
                     }
                  }
               }

            } else {
               struct ArgusLabelerStruct *labeler = parser->ArgusLabeler;
               struct RaAddressStruct *raddr = NULL, node;

               switch (type) {
                  case ARGUS_TYPE_IPV4: {
                     if (labeler != NULL) {
                        extern int ArgusTestMulticast( struct ArgusInput *input, unsigned int);

                        if (daddr != NULL) {
                           if (!(ArgusTestMulticast(argus->input, *(unsigned int *)daddr))) {
                              bzero ((char *)&node, sizeof(node));

                              node.addr.type = AF_INET;
                              node.addr.addr[0] = *(unsigned int *)daddr;
                              node.addr.mask[0] = 0xFFFFFFFF;
                              node.addr.masklen = 32;
                              node.addr.len = 4;

                              if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_EXACT_MATCH)) == NULL) {
#if defined(ARGUSDEBUG)
                                 ArgusDebug (1, "%s: RaProcessRecord: no DNS cache for dest address %s\n", tptr, intoa(node.addr.addr[0]));
#endif
                                 if ((raddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*raddr))) != NULL) {
                                    bcopy(&node, raddr, sizeof(node));
                                    if (node.addr.str != NULL)
                                       raddr->addr.str = strdup(node.addr.str);
                                    RaInsertAddress (parser, labeler, NULL, raddr, ARGUS_VISITED);
                                 }

                              } else {
                                 struct ArgusListStruct *list = raddr->dns;
#if defined(ARGUSDEBUG)
                                 if (raddr->dns != NULL)
                                    ArgusDebug (3, "%s: RaProcessRecord: DNS cache found for dest address %s\n", tptr, intoa(node.addr.addr[0]));
                                 else
                                    ArgusDebug (3, "%s: RaProcessRecord: no DNS cache found for dest address %s\n", tptr, intoa(node.addr.addr[0]));

//                               ArgusPrintAddressResponse(sptr, raddr, &retn, &rind, &reslen, AF_INET);
#endif

                                 if (list != NULL) {
                                    
                                 }

                                 if (raddr->rtime.tv_sec < tvp->tv_sec)
                                    raddr->rtime.tv_sec = tvp->tv_sec;
                              }
                           }
                        }
                     }
                     break;
                  }

                  case ARGUS_TYPE_IPV6: {
                     if (IN6_IS_ADDR_MULTICAST((struct in6_addr *)daddr)) {
                     } else {
                        struct ArgusCIDRAddr *cidr;
                        char ntop_buf[INET6_ADDRSTRLEN];
                        char *cp;

                        if (!((((int *)daddr)[0] == 0) && (((int *)daddr)[1] == 0) && (((int *)daddr)[2] == 0) && (((int *)daddr)[3] == 0))) {
                           if ((cp = (char *) inet_ntop(AF_INET6, (const void *) daddr, ntop_buf, sizeof(ntop_buf))) != NULL) {
                              if ((cidr = RaParseCIDRAddr (parser, cp)) != NULL) {
                                 struct RaAddressStruct node;
                                 bzero ((char *)&node, sizeof(node));
                                 bcopy(cidr, &node.addr, sizeof(node.addr));

                                 if ((raddr = RaFindAddress (parser, labeler->ArgusAddrTree[AF_INET], &node, ARGUS_EXACT_MATCH)) == NULL) {
#if defined(ARGUSDEBUG)
                                    ArgusDebug (1, "%s: RaProcessRecord: no DNS cache for dest address %s\n", tptr, cp);
#endif
                                    if ((raddr = (struct RaAddressStruct *) ArgusCalloc (1, sizeof(*raddr))) != NULL) {
                                       bcopy(&node, raddr, sizeof(node));
                                       if (node.addr.str != NULL)
                                          raddr->addr.str = strdup(cp);
                                       RaInsertAddress (parser, labeler, NULL, raddr, ARGUS_VISITED);
                                    }
                                 } else {
#if defined(ARGUSDEBUG)
                                    if (raddr->dns != NULL) 
                                       ArgusDebug (3, "%s: RaProcessRecord: DNS cache found for dest address %s\n", tptr, cp);
				    else
                                       ArgusDebug (3, "%s: RaProcessRecord: no DNS cache found for dest address %s\n", tptr, cp);

//                                  ArgusPrintAddressResponse(sptr, raddr, &retn, &rind, &reslen, AF_INET);
#endif
                                 }
                              }
                           }
                        }
                     }
                     break;
                  }
               }
            }

            if (parser->ArgusWfileList != NULL) {
               struct ArgusWfileStruct *wfile = NULL;
               struct ArgusListObjectStruct *lobj = NULL;
               int i, count = parser->ArgusWfileList->count;
 
               if ((lobj = parser->ArgusWfileList->start) != NULL) {
                  for (i = 0; i < count; i++) {
                     if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
                        int retn = 1;
                        if (wfile->filterstr) {
                           struct nff_insn *wfcode = wfile->filter.bf_insns;
                           retn = ArgusFilterRecord (wfcode, argus);
                        }
 
                        if (retn != 0) {
                           argus->rank = RaPrintCounter++;
 
                           if ((ArgusParser->eNoflag == 0 ) || ((ArgusParser->eNoflag >= argus->rank) && (ArgusParser->sNoflag <= argus->rank))) {
                              if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
 
                                 if (argus->status & ARGUS_RECORD_MODIFIED) {
                                    struct ArgusRecord *ns = NULL;
 
                                    if ((ns = ArgusGenerateRecord (argus, 0L, ArgusRecordBuffer, argus_version)) == NULL)
                                       ArgusLog(LOG_ERR, "ArgusHandleRecord: ArgusGenerateRecord error %s", strerror(errno));
#ifdef _LITTLE_ENDIAN
                                    ArgusHtoN(ns);
#endif
                                    if (ArgusWriteNewLogfile (parser, argus->input, wfile, ns))
                                       ArgusLog (LOG_ERR, "ArgusWriteNewLogfile failed. %s", strerror(errno));
                                 } else
                                    if (ArgusWriteNewLogfile (parser, argus->input, wfile, argus->input->ArgusOriginal))
                                       ArgusLog (LOG_ERR, "ArgusWriteNewLogfile failed. %s", strerror(errno));
                              }
 
                           } else {
                              if (ArgusParser->eNoflag < argus->rank)
                                 break;
                           }
                        }
                     }
 
                     lobj = lobj->nxt;
                  }
               }
            }
         }
         break;
      }
   }
   ArgusFree(label);
   ArgusFree(buf);
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
      case ARGUS_AFLOW:
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
                        if (node.addr.str != NULL)
                           raddr->addr.str = strdup(node.addr.str);
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

      if ((retn->htable = ArgusNewHashTable(ArgusParser->ArgusHashTableSize)) == NULL)
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

