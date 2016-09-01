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
 * $Id: //depot/gargoyle/clients/examples/radns/radomain.c#10 $
 * $DateTime: 2016/06/08 00:19:40 $
 * $Change: 3165 $
 */

/*
 *     radomain.c  - parse DNS transactions from argus data
 *                   extract DNS query and response information into a DNS structure
 *                   that allows for fast processing of DNS relevant data.
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <stdlib.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <signal.h>
#include <ctype.h>
#include <argus/extract.h>

extern u_char *snapend;

#include "interface.h"
#include "radomain.h"

/* http://www.iana.org/assignments/dns-parameters */
 
struct tok ns_type2str[] = {
   { T_A,        "A" },          /* RFC 1035 */
   { T_NS,       "NS" },         /* RFC 1035 */
   { T_MD,       "MD" },         /* RFC 1035 */
   { T_MF,       "MF" },         /* RFC 1035 */
   { T_CNAME,    "CNAME" },      /* RFC 1035 */
   { T_SOA,      "SOA" },        /* RFC 1035 */
   { T_MB,       "MB" },         /* RFC 1035 */
   { T_MG,       "MG" },         /* RFC 1035 */
   { T_MR,       "MR" },         /* RFC 1035 */
   { T_NULL,     "NULL" },       /* RFC 1035 */
   { T_WKS,      "WKS" },        /* RFC 1035 */
   { T_PTR,      "PTR" },        /* RFC 1035 */
   { T_HINFO,    "HINFO" },      /* RFC 1035 */
   { T_MINFO,    "MINFO" },      /* RFC 1035 */
   { T_MX,       "MX" },         /* RFC 1035 */
   { T_TXT,      "TXT" },        /* RFC 1035 */
   { T_RP,       "RP" },         /* RFC 1183 */
   { T_AFSDB,    "AFSDB" },      /* RFC 1183 */
   { T_X25,      "X25" },        /* RFC 1183 */
   { T_ISDN,     "ISDN" },       /* RFC 1183 */
   { T_RT,       "RT" },         /* RFC 1183 */
   { T_NSAP,     "NSAP" },       /* RFC 1706 */
   { T_NSAP_PTR, "NSAP_PTR" },
   { T_SIG,      "SIG" },        /* RFC 2535 */
   { T_KEY,      "KEY" },        /* RFC 2535 */
   { T_PX,       "PX" },         /* RFC 2163 */
   { T_GPOS,     "GPOS" },       /* RFC 1712 */
   { T_AAAA,     "AAAA" },       /* RFC 1886 */
   { T_LOC,      "LOC" },        /* RFC 1876 */
   { T_NXT,      "NXT" },        /* RFC 2535 */
   { T_EID,      "EID" },        /* Nimrod */
   { T_NIMLOC,    "NIMLOC" },    /* Nimrod */
   { T_SRV,      "SRV" },        /* RFC 2782 */
   { T_ATMA,     "ATMA" },       /* ATM Forum */
   { T_NAPTR,    "NAPTR" },      /* RFC 2168, RFC 2915 */
   { T_A6,       "A6" },         /* RFC 2874 */
   { T_DNAME,    "DNAME" },      /* RFC 2672 */
   { T_OPT,      "OPT" },        /* RFC 2671 */
   { T_APL,      "APL" },        /* RFC 3123 */
   { T_DS,       "DS" },         /* RFC 4034 */
   { T_SSHFP,    "SSHFP" },      /* RFC 4255 */
   { T_IPSECKEY, "IPSECKEY" },   /* RFC 4025 */
   { T_RRSIG,    "RRSIG" },      /* RFC 4034 */
   { T_NSEC,     "NSEC" },       /* RFC 4034 */
   { T_DNSKEY,   "DNSKEY" },     /* RFC 4034 */
   { T_DHCID,    "DHCID" },      /* RFC 4034 */
   { T_NSEC3,    "NSEC3" },      /* RFC 4034 */
   { T_NSEC3PARAM,"NSEC3PARAM"}, /* RFC 4034 */
   { T_TLSA,     "TLSA" },       /* RFC 4034 */
   { T_HIP,      "HIP" },        /* RFC 4034 */
   { T_CDS,      "CDS" },        /* RFC 4034 */
   { T_CDNSKEY,  "CDNSKEY" },    /* RFC 4034 */
   { T_UINFO,    "UINFO" },
   { T_UID,      "UID" },
   { T_GID,      "GID" },
   { T_UNSPEC,   "UNSPEC" },
   { T_UNSPECA,  "UNSPECA" },
   { T_TKEY,     "TKEY" },       /* RFC 2930 */
   { T_TSIG,     "TSIG" },       /* RFC 2845 */
   { T_IXFR,     "IXFR" },       /* RFC 1995 */
   { T_AXFR,     "AXFR" },       /* RFC 1035 */
   { T_MAILB,    "MAILB" },      /* RFC 1035 */
   { T_MAILA,    "MAILA" },      /* RFC 1035 */
   { T_ANY,      "ANY" },
   { 0,           NULL }
};
 
struct tok ns_class2str[] = {
   { C_IN,      "IN" },      /* Not used */
   { C_CSNET,   "CSNET" },
   { C_CHAOS,   "CHAOS" },
   { C_HS,      "HS" },
   { C_NONE,    "NONE" },
   { C_ANY,     "ANY" },
   { 0,          NULL }
};

extern char ArgusBuf[];
static const u_char *ns_nparse(struct ArgusDomainQueryStruct *, register const u_char *, register const u_char *, int);
static const u_char *ns_rparse(struct ArgusDomainQueryStruct *, register u_char *, register const u_char *, int, int);

static const u_char *ns_nprint(register const u_char *, register const u_char *, char *);
static const u_char *ns_cprint(register const u_char *);
static const u_char *ns_nskip(register const u_char *);

static int labellen(const u_char *);
static const u_char *blabel_print(const u_char *);

struct ArgusDomainQueryStruct *ArgusParseDNSBuffer (struct ArgusParserStruct *, struct ArgusDataStruct *);
void relts_print(char *, int);

#define ARGUS_UPDATE   0
#define ARGUS_CHECK     1

struct ArgusDomainQueryStruct *
ArgusParseDNSBuffer (struct ArgusParserStruct *parser, struct ArgusDataStruct *user)
{
   struct ArgusDomainQueryStruct *query = NULL;

   if (user != NULL) {
      register const HEADER *np;
      register const u_char *cp;
      u_char *bp = NULL;
      int slen;

      if ((query = ArgusCalloc(1, sizeof(struct ArgusDomainQueryStruct))) == NULL)
         ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

      bp = (u_char *) &user->array;
      slen = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
      slen = (user->count < slen) ? user->count : slen;
      snapend = bp + slen;

      if (slen >= sizeof(HEADER)) {
         np = (const HEADER *)bp;

         query->seqnum = EXTRACT_16BITS(&np->id);
         query->opcode = DNS_OPCODE(np);

         /* get the byte-order right */
         query->qdcount = EXTRACT_16BITS(&np->qdcount);
         query->ancount = EXTRACT_16BITS(&np->ancount);
         query->nscount = EXTRACT_16BITS(&np->nscount);
         query->arcount = EXTRACT_16BITS(&np->arcount);

         query->flags[0] = np->flags1;
         query->flags[1] = np->flags2;

         bzero(ArgusBuf, 256);
         
         if ((cp = ns_nprint((const u_char *)(np + 1), bp, ArgusBuf)) != NULL) {
            query->name = strdup(ArgusBuf);
            ns_nparse(query, (const u_char *)(np + 1), bp, ARGUS_UPDATE);

            query->qtype = EXTRACT_16BITS(cp);
            cp += 2;
            query->qclass = EXTRACT_16BITS(cp);
            cp += 2;

            if (!(DNS_QR(np))) {
               /* this is a request */
            } else {
               int cnt;
               query->rcode   = DNS_RCODE(np);
               if (cp && ((cnt = query->ancount) > 0)) {
                  do {
                     cp = ns_rparse(query, bp, cp, ARGUS_UPDATE, 0);
                  } while (cp && (--cnt > 0));
               }
               if (cp && ((cnt = query->nscount) > 0)) {
                  do {
                     cp = ns_rparse(query, bp, cp, ARGUS_UPDATE, 0);
                  } while (cp && (--cnt > 0));
               }
            }
         }
      }
   }

   return (query);
}


struct ArgusDomainStruct *
ArgusParseDNSRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus, struct ArgusDomainStruct *dns)
{
   struct ArgusDomainStruct *retn = NULL;

   if (argus != NULL) {
      struct ArgusDataStruct *suser = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX];
      struct ArgusDataStruct *duser = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX];
      struct ArgusDomainQueryStruct *query = NULL;

      if (suser != NULL) {
         if ((query = ArgusParseDNSBuffer (parser, suser)) != NULL)
            dns->request = query;
      }

      if (duser != NULL) {
         if ((query = ArgusParseDNSBuffer (parser, duser)) != NULL)
            dns->response = query;
      }

      retn = dns;
   }

   return (retn);
}

/* parse the domain name */
static const u_char *
ns_nparse(struct ArgusDomainQueryStruct *query, register const u_char *cp, register const u_char *bp, int state)
{
   register u_int i, l;
   register const u_char *rp = NULL;
   register int compress = 0;
   int chars_processed;
   int data_size = snapend - cp;
   int elt;

   char nbuf[1024];
   bzero(nbuf, sizeof(nbuf));

   if ((l = labellen(cp)) == (u_int)-1)
      return(NULL);
   if (!TTEST2(*cp, 1))
      return(NULL);
   chars_processed = 1;
   if (((i = *cp++) & INDIR_MASK) != INDIR_MASK) {
      compress = 0;
      rp = cp + l;
   }

   if (i != 0)
      while (i && cp < snapend) {
         if ((i & INDIR_MASK) == INDIR_MASK) {
            if (!compress) {
               rp = cp + 1;
               compress = 1;
            }
            if (!TTEST2(*cp, 1))
               return(NULL);
            cp = bp + (((i << 8) | *cp) & 0x3fff);
            if ((l = labellen(cp)) == (u_int)-1)
               return(NULL);
            if (!TTEST2(*cp, 1))
               return(NULL);
            i = *cp++;
            chars_processed++;

            /*
             * If we've looked at every character in
             * the message, this pointer will make
             * us look at some character again,
             * which means we're looping.
             */
            if (chars_processed >= data_size) {
               sprintf(&nbuf[strlen(nbuf)],"<LOOP>");
               return (NULL);
            }
            continue;
         }
         if ((i & INDIR_MASK) == EDNS0_MASK) {
            elt = (i & ~INDIR_MASK);
            switch(elt) {
            case EDNS0_ELT_BITLABEL:
               if (blabel_print(cp) == NULL)
                  return (NULL);
               break;
            default:
               /* unknown ELT */
               sprintf(&nbuf[strlen(nbuf)],"<ELT %d>", elt);
               return(NULL);
            }
         } else {
            if (fn_printn(cp, l, snapend, nbuf) == NULL)
               return(NULL);
            else {
               if (query != NULL) {
                  switch (state) {
                     case ARGUS_UPDATE: {
                        struct ArgusListObjectStruct *list;
                        if (query->domains == NULL)
                           query->domains = ArgusNewList();

                        if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                           ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

                        list->list_obj = strdup(nbuf);
                        ArgusPushFrontList(query->domains, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
                        break;
                     }

                     case ARGUS_CHECK: {
                        if (query->domains) {
                           int i, count = query->domains->count;
                           for (i = 0; i < count; i++) {
                           }
                        }
                     }
                  }
               }
            }
         }

         cp += l;
         chars_processed += l;

         bzero(nbuf, sizeof(nbuf));

         if ((l = labellen(cp)) == (u_int)-1)
            return(NULL);
         if (!TTEST2(*cp, 1))
            return(NULL);
         i = *cp++;
         chars_processed++;
         if (!compress)
            rp += l + 1;
   }
   return (rp);
}

static const u_char *
ns_rparse(struct ArgusDomainQueryStruct *query, register u_char *bp, register const u_char *cp, int state, int is_mdns)
{
   register const u_char *rp = NULL;
   register u_short len;

   struct ArgusDomainResourceRecord *rr;

   if ((rr = ArgusCalloc(1, sizeof(*rr))) != NULL) {
      bzero(ArgusBuf, 128);
      if ((cp = ns_nprint(cp, bp, ArgusBuf)) == NULL)
         return NULL;
      
      if (cp == NULL || !TTEST2(*cp, 10))
         return (snapend);

      rr->name = strdup(ArgusBuf);
      rr->type = EXTRACT_16BITS(cp);
      cp += 2;
      rr->class = EXTRACT_16BITS(cp);
      cp += 2;

      if (is_mdns)
         rr->class &= ~C_CACHE_FLUSH;

      if (rr->type == T_OPT) {
         cp += 2;
         rr->opt_flags = EXTRACT_16BITS(cp);
         cp += 2;
      } else {
         rr->ttl = EXTRACT_32BITS(cp);
         cp += 4;
      }

      len = EXTRACT_16BITS(cp);
      cp += 2;

      rp = cp + len;

      if (rp > snapend)
         return(NULL);

      switch (rr->type) {
         case T_A: {
            unsigned int addr = htonl(*(unsigned int *)cp);
            char *str = ipaddr_string(&addr);
            rr->data = strdup(str);
            break;
         }

#ifdef T_DNAME
         case T_DNAME:
#endif
         case T_NS:
         case T_CNAME:
         case T_PTR: {
            bzero(ArgusBuf, 256);
            if (ns_nprint(cp, bp, ArgusBuf) == NULL)
               return(NULL);
            rr->data = strdup(ArgusBuf);
            break;
         }

         case T_SOA:
            if (!ArgusParser->vflag)
               break;
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
            if ((cp = ns_nprint(cp, bp, &ArgusBuf[strlen(ArgusBuf)])) == NULL)
               return(NULL);
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
            if ((cp = ns_nprint(cp, bp, &ArgusBuf[strlen(ArgusBuf)])) == NULL)
               return(NULL);
            if (!TTEST2(*cp, 5 * 4))
               return(NULL);
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u", EXTRACT_32BITS(cp));
            cp += 4;
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u", EXTRACT_32BITS(cp));
            cp += 4;
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u", EXTRACT_32BITS(cp));
            cp += 4;
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u", EXTRACT_32BITS(cp));
            cp += 4;
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u", EXTRACT_32BITS(cp));
            cp += 4;
            break;
         case T_MX:
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
            if (!TTEST2(*cp, 2))
               return(NULL);
            if (ns_nprint(cp + 2, bp, &ArgusBuf[strlen(ArgusBuf)]) == NULL)
               return(NULL);
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %d", EXTRACT_16BITS(cp));
            break;

         case T_TXT:
            while (cp < rp) {
               sprintf(&ArgusBuf[strlen(ArgusBuf)]," \"");
               cp = ns_cprint(cp);
               if (cp == NULL)
                  return(NULL);
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
            }
            break;

         case T_SRV:
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
            if (!TTEST2(*cp, 6))
               return(NULL);
            if (ns_nprint(cp + 6, bp, &ArgusBuf[strlen(ArgusBuf)]) == NULL)
               return(NULL);
            sprintf(&ArgusBuf[strlen(ArgusBuf)],":%d %d %d", EXTRACT_16BITS(cp + 4),
               EXTRACT_16BITS(cp), EXTRACT_16BITS(cp + 2));
            break;

#ifdef INET6
         case T_AAAA:
            if (!TTEST2(*cp, sizeof(struct in6_addr)))
               return(NULL);
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", ip6addr_string(cp));
            break;

         case T_A6: {
            struct in6_addr a;
            int pbit, pbyte;

            if (!TTEST2(*cp, 1))
               return(NULL);
            pbit = *cp;
            pbyte = (pbit & ~7) / 8;
            if (pbit > 128) {
               sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u(bad plen)", pbit);
               break;
            } else if (pbit < 128) {
               if (!TTEST2(*(cp + 1), sizeof(a) - pbyte))
                  return(NULL);
               memset(&a, 0, sizeof(a));
               memcpy(&a.s6_addr[pbyte], cp + 1, sizeof(a) - pbyte);
               sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u %s", pbit, ip6addr_string(&a));
            }
            if (pbit > 0) {
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
               if (ns_nprint(cp + 1 + sizeof(a) - pbyte, bp, &ArgusBuf[strlen(ArgusBuf)]) == NULL)
                  return(NULL);
            }
            break;
         }

#endif // INET6

         case T_OPT:
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," UDPsize=%u", rr->class);
            break;

         case T_UNSPECA:      
            if (!TTEST2(*cp, len))
               return(NULL);
            if (fn_printn(cp, len, snapend, ArgusBuf) == NULL)
               return(NULL);
            break;

         case T_TSIG: {
            if (cp + len > snapend)
               return(NULL);
            if (!ArgusParser->vflag)
               break;
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
            if ((cp = ns_nprint(cp, bp, &ArgusBuf[strlen(ArgusBuf)])) == NULL)
               return(NULL);
            cp += 6;
            if (!TTEST2(*cp, 2))
               return(NULL);
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," fudge=%u", EXTRACT_16BITS(cp));
            cp += 2;
            if (!TTEST2(*cp, 2))
               return(NULL);
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," maclen=%u", EXTRACT_16BITS(cp));
            cp += 2 + EXTRACT_16BITS(cp);
            if (!TTEST2(*cp, 2))
               return(NULL);
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," origid=%u", EXTRACT_16BITS(cp));
            cp += 2;
            if (!TTEST2(*cp, 2))
               return(NULL);
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," error=%u", EXTRACT_16BITS(cp));
            cp += 2;
            if (!TTEST2(*cp, 2))
               return(NULL);
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," otherlen=%u", EXTRACT_16BITS(cp));
            cp += 2;
         }
      }
      {
         struct ArgusListObjectStruct *list;

         switch (rr->type) {
            case T_A: {
               if (query->ans == NULL)
                  query->ans = ArgusNewList();

               if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

               list->list_obj = rr;
               ArgusPushBackList(query->ans, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
               break;
            }

            case T_NS: {
               if (query->ns == NULL)
                  query->ns = ArgusNewList();

               if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

               list->list_obj = rr;
               ArgusPushBackList(query->ns, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
               break;
            }
            case T_CNAME: {
               if (query->cname == NULL)
                  query->cname = ArgusNewList();

               if ((list = ArgusCalloc(1, sizeof(*list))) == NULL)
                  ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));

               list->list_obj = rr;
               ArgusPushBackList(query->cname, (struct ArgusListRecord *)list, ARGUS_NOLOCK);
               break;
            }
         }
      }

   } else
      ArgusLog(LOG_ERR, "ArgusCalloc: error %s", strerror(errno));
   
   return (rp);      /* XXX This isn't always right */
}


static const char *ns_ops[] = {
   "", " inv_q", " stat", " op3", " notify", " update", " op6", " op7",
   " op8", " updataA", " updateD", " updateDA",
   " updateM", " updateMA", " zoneInit", " zoneRef",
};

static const char *ns_resp[] = {
   "", " FormErr", " ServFail", " NXDomain",
   " NotImp", " Refused", " YXDomain", " YXRRSet",
   " NXRRSet", " NotAuth", " NotZone", " Resp11",
   " Resp12", " Resp13", " Resp14", " NoChange",
   " BadVers", " BadKey", " BadTime", " BadMode",
   " BadName", " BadAlg",
};


/* skip over a domain name */
static const u_char *
ns_nskip(register const u_char *cp)
{
   register u_char i;

   if (!TTEST2(*cp, 1))
      return (NULL);
   i = *cp++;
   while (i) {
      if ((i & INDIR_MASK) == INDIR_MASK)
         return (cp + 1);
      if ((i & INDIR_MASK) == EDNS0_MASK) {
         int bitlen, bytelen;

         if ((i & ~INDIR_MASK) != EDNS0_ELT_BITLABEL)
            return(NULL); /* unknown ELT */
         if (!TTEST2(*cp, 1))
            return (NULL);
         if ((bitlen = *cp++) == 0)
            bitlen = 256;
         bytelen = (bitlen + 7) / 8;
         cp += bytelen;
      } else
         cp += i;
      if (!TTEST2(*cp, 1))
         return (NULL);
      i = *cp++;
   }
   return (cp);
}

/* print a <domain-name> */
static const u_char *
blabel_print(const u_char *cp)
{
   int bitlen, slen, b;
   const u_char *bitp, *lim;
   char tc;

   if (!TTEST2(*cp, 1))
      return(NULL);
   if ((bitlen = *cp) == 0)
      bitlen = 256;
   slen = (bitlen + 3) / 4;
   lim = cp + 1 + slen;

   /* print the bit string as a hex string */
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"\\[x");
   for (bitp = cp + 1, b = bitlen; bitp < lim && b > 7; b -= 8, bitp++) {
      TCHECK(*bitp);
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"%02x", *bitp);
   }
   if (b > 4) {
      TCHECK(*bitp);
      tc = *bitp++;
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"%02x", tc & (0xff << (8 - b)));
   } else if (b > 0) {
      TCHECK(*bitp);
      tc = *bitp++;
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"%1x", ((tc >> 4) & 0x0f) & (0x0f << (4 - b)));
   }
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"/%d]", bitlen);
   return lim;
trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)],".../%d]", bitlen);
   return NULL;
}

static int
labellen(const u_char *cp)
{
   register u_int i;

   if (!TTEST2(*cp, 1))
      return(-1);
   i = *cp;
   if ((i & INDIR_MASK) == EDNS0_MASK) {
      int bitlen, elt;
      if ((elt = (i & ~INDIR_MASK)) != EDNS0_ELT_BITLABEL) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"<ELT %d>", elt);
         return(-1);
      }
      if (!TTEST2(*(cp + 1), 1))
         return(-1);
      if ((bitlen = *(cp + 1)) == 0)
         bitlen = 256;
      return(((bitlen + 7) / 8) + 1);
   } else
      return(i);
}

static const u_char *
ns_nprint(register const u_char *cp, register const u_char *bp, char *buf)
{
   register u_int i, l;
   register const u_char *rp = NULL;
   register int compress = 0;
   int chars_processed;
   int elt;
   int data_size = snapend - bp;

   if ((l = labellen(cp)) == (u_int) -1)
      return(NULL);

   if (!TTEST2(*cp, 1))
      return(NULL);

   chars_processed = 1;
   if (((i = *cp++) & INDIR_MASK) != INDIR_MASK) {
      compress = 0;
      rp = cp + l;
   }

   if (i != 0) {
      while (i && cp < snapend) {
         if ((i & INDIR_MASK) == INDIR_MASK) {
            if (!compress) {
               rp = cp + 1;
               compress = 1;
            }
            if (!TTEST2(*cp, 1))
               return(NULL);
            cp = bp + (((i << 8) | *cp) & 0x3fff);
            if ((l = labellen(cp)) == (u_int)-1)
               return(NULL);
            if (!TTEST2(*cp, 1))
               return(NULL);
            i = *cp++;
            chars_processed++;

            /*
             * If we've looked at every character in
             * the message, this pointer will make
             * us look at some character again,
             * which means we're looping.
             */
            if (chars_processed >= data_size) {
               sprintf(buf,"<LOOP>");
               return (NULL);
            }
            continue;
         }
         if ((i & INDIR_MASK) == EDNS0_MASK) {
            elt = (i & ~INDIR_MASK);
            switch(elt) {
            case EDNS0_ELT_BITLABEL:
               if (blabel_print(cp) == NULL)
                  return (NULL);
               break;
            default:
               /* unknown ELT */
               sprintf(buf,"<ELT %d>", elt);
               return(NULL);
            }
         } else {
            if ((buf = fn_printn(cp, l, snapend, buf)) == NULL)
               return(NULL);
         }

         cp += l;
         chars_processed += l;

         *buf++ = '.';
         if ((l = labellen(cp)) == (u_int)-1)
            return(NULL);
         if (!TTEST2(*cp, 1))
            return(NULL);
         i = *cp++;
         chars_processed++;
         if (!compress)
            rp += l + 1;
      }
   } else
      sprintf(buf++, "%c", '.');

   return (rp);
}

/* print a <character-string> */
static const u_char *
ns_cprint(register const u_char *cp)
{
   register u_int i;
   char *buf = &ArgusBuf[strlen(ArgusBuf)];

   if (!TTEST2(*cp, 1))
      return (NULL);
   i = *cp++;
   if (fn_printn(cp, i, snapend, buf) == NULL)
      return (NULL);
   return (cp + i);
}

/* print a query */
static const u_char *
ns_qprint(register const u_char *cp, register const u_char *bp, int is_mdns)
{
   register const u_char *np = cp;
   register u_int i, class;

   cp = ns_nskip(cp);

   if (cp == NULL || !TTEST2(*cp, 4))
      return(NULL);

   /* print the qtype and qclass (if it's not IN) */
   i = EXTRACT_16BITS(cp);
   cp += 2;
   sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", tok2str(ns_type2str, "Type%d", i));
   i = EXTRACT_16BITS(cp);
   cp += 2;

   if (is_mdns)
      class = (i & ~C_QU);
   else
      class = i;

   if (class != C_IN)
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", tok2str(ns_class2str, "(Class %d)", i));

   if (is_mdns) 
      sprintf(&ArgusBuf[strlen(ArgusBuf)], (i & C_QU) ? " (QU)" : " (QM)");

   sprintf(&ArgusBuf[strlen(ArgusBuf)],"? ");
   cp = ns_nprint(np, bp, &ArgusBuf[strlen(ArgusBuf)]);
   return(cp ? cp + 4 : NULL);
}

/* print a reply */
static const u_char *
ns_rprint(register const u_char *cp, register const u_char *bp, int is_mdns)
{
   register u_int class, opt_flags = 0;
   register u_short typ, len;
   register const u_char *rp;

   if (ArgusParser->vflag) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
      if ((cp = ns_nprint(cp, bp, &ArgusBuf[strlen(ArgusBuf)])) == NULL)
         return NULL;
   } else
      cp = ns_nskip(cp);

   if (cp == NULL || !TTEST2(*cp, 10))
      return (snapend);

   /* print the type/qtype and class (if it's not IN) */
   typ = EXTRACT_16BITS(cp);
   cp += 2;
   class = EXTRACT_16BITS(cp);
   cp += 2;

   if (is_mdns)
      class &= ~C_CACHE_FLUSH;

   if ((class != C_IN) && (typ != T_OPT))
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", tok2str(ns_class2str, "(Class %d)", class));

   if (is_mdns && (class & C_CACHE_FLUSH))
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," (Cache flush)");

   if (typ == T_OPT) {
      /* get opt flags */
      cp += 2;
      opt_flags = EXTRACT_16BITS(cp);
      /* ignore rest of ttl field */
      cp += 2;
   } else if (ArgusParser->vflag > 2) {
      /* print ttl */
      sprintf(&ArgusBuf[strlen(ArgusBuf)], " [");
      relts_print(ArgusBuf, EXTRACT_32BITS(cp));
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "]");
      cp += 4;
   } else {
      /* ignore ttl */
      cp += 4;
   }

   len = EXTRACT_16BITS(cp);
   cp += 2;

   rp = cp + len;

   sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", tok2str(ns_type2str, "Type%d", typ));
   if (rp > snapend)
      return(NULL);

   switch (typ) {
   case T_A: {
      unsigned int addr = htonl(*(unsigned int *)cp);
      if (!TTEST2(*cp, sizeof(struct in_addr)))
         return(NULL);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", ipaddr_string(&addr));
      break;
   }

   case T_NS:
   case T_CNAME:
   case T_PTR:
#ifdef T_DNAME
   case T_DNAME:
#endif
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
      if (ns_nprint(cp, bp, &ArgusBuf[strlen(ArgusBuf)]) == NULL)
         return(NULL);
      break;

   case T_SOA:
      if (!ArgusParser->vflag)
         break;
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
      if ((cp = ns_nprint(cp, bp, &ArgusBuf[strlen(ArgusBuf)])) == NULL)
         return(NULL);
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
      if ((cp = ns_nprint(cp, bp, &ArgusBuf[strlen(ArgusBuf)])) == NULL)
         return(NULL);
      if (!TTEST2(*cp, 5 * 4))
         return(NULL);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u", EXTRACT_32BITS(cp));
      cp += 4;
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u", EXTRACT_32BITS(cp));
      cp += 4;
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u", EXTRACT_32BITS(cp));
      cp += 4;
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u", EXTRACT_32BITS(cp));
      cp += 4;
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u", EXTRACT_32BITS(cp));
      cp += 4;
      break;
   case T_MX:
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
      if (!TTEST2(*cp, 2))
         return(NULL);
      if (ns_nprint(cp + 2, bp, &ArgusBuf[strlen(ArgusBuf)]) == NULL)
         return(NULL);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," %d", EXTRACT_16BITS(cp));
      break;

   case T_TXT:
      while (cp < rp) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," \"");
         cp = ns_cprint(cp);
         if (cp == NULL)
            return(NULL);
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", '"');
      }
      break;

   case T_SRV:
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
      if (!TTEST2(*cp, 6))
         return(NULL);
      if (ns_nprint(cp + 6, bp, &ArgusBuf[strlen(ArgusBuf)]) == NULL)
         return(NULL);
      sprintf(&ArgusBuf[strlen(ArgusBuf)],":%d %d %d", EXTRACT_16BITS(cp + 4),
         EXTRACT_16BITS(cp), EXTRACT_16BITS(cp + 2));
      break;

#ifdef INET6
   case T_AAAA:
      if (!TTEST2(*cp, sizeof(struct in6_addr)))
         return(NULL);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", ip6addr_string(cp));
      break;

   case T_A6:
       {
      struct in6_addr a;
      int pbit, pbyte;

      if (!TTEST2(*cp, 1))
         return(NULL);
      pbit = *cp;
      pbyte = (pbit & ~7) / 8;
      if (pbit > 128) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u(bad plen)", pbit);
         break;
      } else if (pbit < 128) {
         if (!TTEST2(*(cp + 1), sizeof(a) - pbyte))
            return(NULL);
         memset(&a, 0, sizeof(a));
         memcpy(&a.s6_addr[pbyte], cp + 1, sizeof(a) - pbyte);
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u %s", pbit, ip6addr_string(&a));
      }
      if (pbit > 0) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
         if (ns_nprint(cp + 1 + sizeof(a) - pbyte, bp, &ArgusBuf[strlen(ArgusBuf)]) == NULL)
            return(NULL);
      }
      break;
       }
#endif /*INET6*/

   case T_OPT:
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," UDPsize=%u", class);
      break;

   case T_UNSPECA:      /* One long string */
      if (!TTEST2(*cp, len))
         return(NULL);
      if (fn_printn(cp, len, snapend, &ArgusBuf[strlen(ArgusBuf)]) == NULL)
         return(NULL);
      break;

   case T_TSIG:
       {
      if (cp + len > snapend)
         return(NULL);
      if (!ArgusParser->vflag)
         break;
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ' ');
      if ((cp = ns_nprint(cp, bp, &ArgusBuf[strlen(ArgusBuf)])) == NULL)
         return(NULL);
      cp += 6;
      if (!TTEST2(*cp, 2))
         return(NULL);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," fudge=%u", EXTRACT_16BITS(cp));
      cp += 2;
      if (!TTEST2(*cp, 2))
         return(NULL);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," maclen=%u", EXTRACT_16BITS(cp));
      cp += 2 + EXTRACT_16BITS(cp);
      if (!TTEST2(*cp, 2))
         return(NULL);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," origid=%u", EXTRACT_16BITS(cp));
      cp += 2;
      if (!TTEST2(*cp, 2))
         return(NULL);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," error=%u", EXTRACT_16BITS(cp));
      cp += 2;
      if (!TTEST2(*cp, 2))
         return(NULL);
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," otherlen=%u", EXTRACT_16BITS(cp));
      cp += 2;
       }
   }
   return (rp);      /* XXX This isn't always right */
}

char *
ns_print(register const u_char *bp, u_int length, int is_mdns)
{
   register const HEADER *np;
   register int qdcount, ancount, nscount, arcount;
   register const u_char *cp;
   u_int16_t b2;

   np = (const HEADER *)bp;
   TCHECK(*np);
   /* get the byte-order right */
   qdcount = EXTRACT_16BITS(&np->qdcount);
   ancount = EXTRACT_16BITS(&np->ancount);
   nscount = EXTRACT_16BITS(&np->nscount);
   arcount = EXTRACT_16BITS(&np->arcount);

   if (DNS_QR(np)) {
      /* this is a response */
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"%d%s%s%s%s%s%s",
         EXTRACT_16BITS(&np->id),
         ns_ops[DNS_OPCODE(np)],
         ns_resp[DNS_RCODE(np)],
         DNS_AA(np)? "*" : "",
         DNS_RA(np)? "" : "-",
         DNS_TC(np)? "|" : "",
         DNS_AD(np)? "$" : "");

      if (qdcount != 1)
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," [%dq]", qdcount);

      /* Print QUESTION section on -vv */
      cp = (const u_char *)(np + 1);
      while (qdcount--) {
         if (qdcount < EXTRACT_16BITS(&np->qdcount) - 1)
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ',');
         if (ArgusParser->vflag > 1) {
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," q:");
            if ((cp = ns_qprint(cp, bp, is_mdns)) == NULL)
               goto trunc;
         } else {
            if ((cp = ns_nskip(cp)) == NULL)
               goto trunc;
            cp += 4;   /* skip QTYPE and QCLASS */
         }
      }
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," %d/%d/%d", ancount, nscount, arcount);
      if (ancount--) {
         if ((cp = ns_rprint(cp, bp, is_mdns)) == NULL)
            goto trunc;
         while (cp < snapend && ancount--) {
            sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ',');
            if ((cp = ns_rprint(cp, bp, is_mdns)) == NULL)
               goto trunc;
         }
      }
      if (ancount > 0)
         goto trunc;
      /* Print NS and AR sections on -vv */
      if (ArgusParser->vflag > 1) {
         if (cp < snapend && nscount--) {
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," ns:");
            if ((cp = ns_rprint(cp, bp, is_mdns)) == NULL)
               goto trunc;
            while (cp < snapend && nscount--) {
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ',');
               if ((cp = ns_rprint(cp, bp, is_mdns)) == NULL)
                  goto trunc;
            }
         }
         if (nscount > 0)
            goto trunc;
         if (cp < snapend && arcount--) {
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," ar:");
            if ((cp = ns_rprint(cp, bp, is_mdns)) == NULL)
               goto trunc;
            while (cp < snapend && arcount--) {
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ',');
               if ((cp = ns_rprint(cp, bp, is_mdns)) == NULL)
                  goto trunc;
            }
         }
         if (arcount > 0)
            goto trunc;
      }

   } else {
      char tbuf[128];
      bzero(tbuf, sizeof(tbuf));

      /* this is a request */
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"%d%s%s%s", EXTRACT_16BITS(&np->id), ns_ops[DNS_OPCODE(np)],
          DNS_RD(np) ? "+" : "",
          DNS_CD(np) ? "%" : "");

      /* any weirdness? */
      b2 = EXTRACT_16BITS(((u_short *)np)+1);
      if (b2 & 0x6cf)
         sprintf(&tbuf[strlen(tbuf)]," [b2&3=0x%x]", b2);

      if (DNS_OPCODE(np) == IQUERY) {
         if (qdcount)
            sprintf(&tbuf[strlen(tbuf)]," [%dq]", qdcount);
         if (ancount != 1)
            sprintf(&tbuf[strlen(tbuf)]," [%da]", ancount);
      }
      else {
         if (ancount)
            sprintf(&tbuf[strlen(tbuf)]," [%da]", ancount);
         if (qdcount != 1)
            sprintf(&tbuf[strlen(tbuf)]," [%dq]", qdcount);
      }
      if (nscount)
         sprintf(&tbuf[strlen(tbuf)]," [%dn]", nscount);
      if (arcount)
         sprintf(&tbuf[strlen(tbuf)]," [%dau]", arcount);

      if (strlen(tbuf) > 0) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", tbuf);
      } else {
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," [_]");
      }

      cp = (const u_char *)(np + 1);
      if (qdcount--) {
         cp = ns_qprint(cp, (const u_char *)np, is_mdns);
         if (!cp)
            goto trunc;
         while (cp < snapend && qdcount--) {
            cp = ns_qprint((const u_char *)cp,
                      (const u_char *)np,
                      is_mdns);
            if (!cp)
               goto trunc;
         }
      }
      if (qdcount > 0)
         goto trunc;

      /* Print remaining sections on -vv */
      if (ArgusParser->vflag > 1) {
         if (ancount--) {
            if ((cp = ns_rprint(cp, bp, is_mdns)) == NULL)
               goto trunc;
            while (cp < snapend && ancount--) {
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ',');
               if ((cp = ns_rprint(cp, bp, is_mdns)) == NULL)
                  goto trunc;
            }
         }
         if (ancount > 0)
            goto trunc;
         if (cp < snapend && nscount--) {
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," ns:");
            if ((cp = ns_rprint(cp, bp, is_mdns)) == NULL)
               goto trunc;
            while (nscount-- && cp < snapend) {
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ',');
               if ((cp = ns_rprint(cp, bp, is_mdns)) == NULL)
                  goto trunc;
            }
         }
         if (nscount > 0)
            goto trunc;
         if (cp < snapend && arcount--) {
            sprintf(&ArgusBuf[strlen(ArgusBuf)]," ar:");
            if ((cp = ns_rprint(cp, bp, is_mdns)) == NULL)
               goto trunc;
            while (cp < snapend && arcount--) {
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "%c", ',');
               if ((cp = ns_rprint(cp, bp, is_mdns)) == NULL)
                  goto trunc;
            }
         }
         if (arcount > 0)
            goto trunc;
      }
   }
   sprintf(&ArgusBuf[strlen(ArgusBuf)]," (%d)", length);
   return ArgusBuf;

  trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|domain]");
   return ArgusBuf;
}
