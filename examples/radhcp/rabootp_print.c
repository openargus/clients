#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif

#include <limits.h>
#include "argus_util.h"
#include "argus_parser.h"
#include "argus_threads.h"
#include "argus_filter.h"
#include "rabootp.h"
#include "rabootp_print.h"
#include "argus_print.h"

#define RABOOTP_PRINT_FIELD_MAX 64

static const struct ArgusFormatterTable ArgusNullFormatterTable = {
   NULL,
};

static ssize_t
RabootpPrintL2(const struct ArgusParserStruct * const parser,
               const void * const datum, char *str, size_t len)
{
   size_t tmplen = 0;
   size_t remain = len;
   ssize_t rv;

   rv = snprintf_append(str, &tmplen, &remain, "%s",
                        etheraddr_string((struct ArgusParserStruct *)parser,
                                         (unsigned char *)datum));
   return tmplen;
}

static ssize_t
RabootpPrintTimeval(const struct ArgusParserStruct * const parser,
                    const void * const datum, char *str, size_t len)
{
   memset(str, 0, len); /* THIS SHOULDN'T BE NECESSARY */
   return ArgusPrintTime((struct ArgusParserStruct *)parser, str, len,
                         (struct timeval *)datum);
}

static ssize_t
RabootpPrintL3(const struct ArgusParserStruct * const parser,
               const void * const datum, char *str, size_t len)
{
   uint32_t addr;

   /* Don't use ArgusPrintAddr for now since it requires a lock on
    * parser and requires parser->RaPrintIndex to be set temporarily
    * to ARGUSPRINTSRCADDR.
    */

   memcpy(&addr, datum, sizeof(addr));
   addr = htonl(addr);
   inet_ntop(AF_INET, &addr, str, len);
   return (ssize_t)strlen(str);
}

static ssize_t
RabootpPrintString(const struct ArgusParserStruct * const parser,
                   const void * const datum, char *str, size_t len)
{
   const char * const *instrp = datum;

   if (*instrp)
      return snprintf(str, len, "%s", *instrp);
   return 0;
}

static ssize_t
RabootpPrintHex32(const struct ArgusParserStruct * const parser,
                  const void * const datum, char *str, size_t len)
{
   uint32_t val;

   memcpy(&val, datum, sizeof(val));
   return snprintf(str, len, "%08x", val);
}

static ssize_t
RabootpPrintUint8(const struct ArgusParserStruct * const parser,
                  const void * const datum, char *str, size_t len)
{
   uint8_t val;

   val = *(uint8_t *)datum;
   return snprintf(str, len, "%hhu", val);
}

static struct ArgusPrinterTable ArgusDhcpReplyPrinterTablep[] = {
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, yiaddr, "clientaddr", \
                           RabootpPrintL3, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, hostname, "hostname", \
                           RabootpPrintString, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, netmask, "netmask", \
                           RabootpPrintL3, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, broadcast, "broadcast", \
                           RabootpPrintL3, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, router, "router", \
                           RabootpPrintL3, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, router_count, "router_count", \
                           RabootpPrintUint8, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, domainname, "domainname", \
                           RabootpPrintString, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, siaddr, "siaddr", \
                           RabootpPrintL3, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, timeserver[0], "timeserver0", \
                           RabootpPrintL3, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, timeserver_count, "timeserver_count", \
                           RabootpPrintUint8, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, nameserver[0], "nameserver0", \
                           RabootpPrintL3, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, nameserver[1], "nameserver1", \
                           RabootpPrintL3, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, nameserver_count, "nameserver_count", \
                           RabootpPrintUint8, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpV4LeaseOptsStruct, shaddr, "servermac", \
                           RabootpPrintL2, 1),
};

static struct ArgusPrinterTable ArgusDhcpStructPrinterTable[] = {
   ARGUS_PRINT_INITIALIZER(ArgusDhcpStruct, chaddr, "clientmac", \
                           RabootpPrintL2, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpStruct, xid, "XID", RabootpPrintHex32, 1),
};

static struct ArgusPrinterTable ArgusDhcpIntvlPrinterTable[] = {
   ARGUS_PRINT_INITIALIZER(ArgusDhcpIntvlNode, intlo, "stime", \
                           RabootpPrintTimeval, 1),
   ARGUS_PRINT_INITIALIZER(ArgusDhcpIntvlNode, inthi, "ltime", \
                           RabootpPrintTimeval, 1),
};

static inline void
__adv(ssize_t val, ssize_t *used, size_t *remain)
{
   if (val <= *remain) {
      if (val <= (SSIZE_MAX-(*used)))
         *used += val;
      else
         *used = SSIZE_MAX;
      *remain -= val;
   } else {
      if (*remain <= (SSIZE_MAX-(*used)))
         *used += *remain;
      else
         *used = SSIZE_MAX;
      *remain = 0;
   }
}

ssize_t
RabootpPrintField(const struct ArgusParserStruct * const parser,
                  const struct ArgusPrinterTable * const table_entry,
                  const void * const ptr,        /* structure */
                  char *out, size_t outlen,
                  const struct ArgusFormatterTable * const fmtable)
{
   ssize_t rv;
   ssize_t used = 0;
   size_t remain = outlen;
   char value[RABOOTP_PRINT_FIELD_MAX];

   if (fmtable->fieldStart) {
      rv = fmtable->fieldStart(out, remain, table_entry->label);
      if (rv > 0)
         __adv(rv, &used, &remain);
   }
   if (fmtable->fieldName) {
      rv = fmtable->fieldName(out+used, remain, table_entry->label);
      if (rv > 0)
         __adv(rv, &used, &remain);
   }
   value[0] = 0;
   rv = ArgusPrintField(parser, table_entry, ptr, 0,
                        value, RABOOTP_PRINT_FIELD_MAX);
   if (fmtable->fieldData) {
      rv = fmtable->fieldData(out+used, remain, DataTypeString, value);
      if (rv > 0)
         __adv(rv, &used, &remain);
   }
   if (fmtable->fieldEnd) {
      rv = fmtable->fieldEnd(out+used, remain, table_entry->label);
      if (rv > 0)
         __adv(rv, &used, &remain);
   }
   return used;
}

/* Format the leased IP address and hostname[.domainname].
 * Return number of chars formatted.  If Not enough space,
 * then retrn number of chars that would have been formatted.
 */
static ssize_t
__print_lease(const struct ArgusParserStruct * const parser,
              const struct ArgusDhcpStruct *ads,
              char *str, size_t strlen,
              const struct ArgusFormatterTable * const fmtable)
{
   ssize_t used = 0;
   ssize_t fmtlen;
   int tmax;
   int t;

   /* First, find the correct response.  For now, use the first
      response in the list.
    */
   if (ads->rep.next) {
      /* TODO: step though these until we find the "right one" */
   }

   tmax = sizeof(ArgusDhcpReplyPrinterTablep)/
          sizeof(ArgusDhcpReplyPrinterTablep[0]);

   for (t = 0; t < tmax; t++) {
      fmtlen = RabootpPrintField(parser, &ArgusDhcpReplyPrinterTablep[t],
                                 &ads->rep, str, strlen, fmtable);
      if (fmtlen > 0) {
         strlen -= ((fmtlen < strlen) ? fmtlen : strlen);
         str += fmtlen;
         used += fmtlen;
      }
      if (fmtable->fieldSeparate && t < (tmax-1) && strlen > 0) {
         fmtlen = fmtable->fieldSeparate(str, strlen,
                                         ArgusDhcpReplyPrinterTablep[t].label);
         if (fmtlen > 0) {
            strlen -= ((fmtlen < strlen) ? fmtlen : strlen);
            str += fmtlen;
            used += fmtlen;
         }
      }
   }
   return used;
}

int
RabootpPrintDhcp(const struct ArgusParserStruct * const parser,
                 const struct ArgusDhcpIntvlNode *invec,
                 size_t nitems, char *str, size_t strlen,
                 const struct ArgusFormatterTable * const fmtable)
{
   size_t n;
   int t;  /* table index */
   int timax; /* size of interval printer table */
   int tcmax; /* size of client printer table */
   ssize_t fmtlen; /* length of string from ArgusPrintField */

   timax = sizeof(ArgusDhcpIntvlPrinterTable)/
           sizeof(ArgusDhcpIntvlPrinterTable[0]);
   tcmax = sizeof(ArgusDhcpStructPrinterTable)/
           sizeof(ArgusDhcpStructPrinterTable[0]);

   if (fmtable->docStart) {
      fmtlen = fmtable->docStart(str, strlen, "Query Results");
      if (fmtlen > 0) {
            strlen -= ((fmtlen < strlen) ? fmtlen : strlen);
            str += fmtlen;
      }
   }

   for (n = 0; n < nitems; n++) {
      char leasestr[16];

      snprintf(leasestr, sizeof(leasestr), "%zu", n);

      if (fmtable->recordStart) {
         fmtlen = fmtable->recordStart(str, strlen, leasestr);
         if (fmtlen > 0) {
               strlen -= ((fmtlen < strlen) ? fmtlen : strlen);
               str += fmtlen;
         }
      }

      for (t = 0; t < timax; t++) {
         fmtlen = RabootpPrintField(parser, &ArgusDhcpIntvlPrinterTable[t],
                                    &invec[n], str, strlen, fmtable);
         if (fmtlen > 0) {
            strlen -= ((fmtlen < strlen) ? fmtlen : strlen);
            str += fmtlen;
         }

         if (fmtable->fieldSeparate == NULL)
            continue;

         fmtlen = fmtable->fieldSeparate(str, strlen,
                                         ArgusDhcpIntvlPrinterTable[t].label);
         if (fmtlen > 0) {
            strlen -= ((fmtlen < strlen) ? fmtlen : strlen);
            str += fmtlen;
         }
      }

      MUTEX_LOCK(invec[n].data->lock);
      for (t = 0; t < tcmax; t++) {
         fmtlen = RabootpPrintField(parser, &ArgusDhcpStructPrinterTable[t],
                                    invec[n].data, str, strlen, fmtable);
         if (fmtlen > 0) {
            strlen -= ((fmtlen < strlen) ? fmtlen : strlen);
            str += fmtlen;
         }

         if (fmtable->fieldSeparate == NULL)
            continue;

         fmtlen = fmtable->fieldSeparate(str, strlen,
                                         ArgusDhcpStructPrinterTable[t].label);
         if (fmtlen > 0) {
            strlen -= ((fmtlen < strlen) ? fmtlen : strlen);
            str += fmtlen;
         }
      }

      fmtlen = __print_lease(parser, invec[n].data, str, strlen, fmtable);
      MUTEX_UNLOCK(invec[n].data->lock);

      if (fmtlen > 0) {
         strlen -= ((fmtlen < strlen) ? fmtlen : strlen);
         str += fmtlen;
      }

      if (fmtable->recordEnd) {
         fmtlen = fmtable->recordEnd(str, strlen, "lease");
         if (fmtlen > 0) {
               strlen -= ((fmtlen < strlen) ? fmtlen : strlen);
               str += fmtlen;
         }
      }

      if (fmtable->recordSeparate && (n < (nitems-1))) {
         fmtlen = fmtable->recordSeparate(str, strlen, "lease");
         if (fmtlen > 0) {
               strlen -= ((fmtlen < strlen) ? fmtlen : strlen);
               str += fmtlen;
         }
      }
   }

   if (fmtable->docEnd) {
      fmtlen = fmtable->docEnd(str, strlen, "Query Results");
      if (fmtlen > 0) {
            strlen -= ((fmtlen < strlen) ? fmtlen : strlen);
            str += fmtlen;
      }
   }

   if (strlen > 0) {
      *str++ = '\n';
      strlen--;
   }

   return 0;
}