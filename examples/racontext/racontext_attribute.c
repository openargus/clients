#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif
#include <stdio.h>
#include <sys/syslog.h>
#include <errno.h>
#include <arpa/inet.h>
#include "argus_compat.h"
#include "argus_util.h"
#include "argus_client.h"
#include "argus_parser.h"
#include "racontext.h"

/* Context Attribute Tree
 *
 * Duplicate values are not allowed in the tree, but are counted.
 */

void
RacontextAttrFree(struct racontext_attribute *a, bool deep)
{
   if (a == NULL)
      return;

   if (deep && (a->attrib_num == CTX_ATTRIB_DHCP_DNS_DOMAIN ||
                a->attrib_num == CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME))
      ArgusFree(a->value_un.name);

   ArgusFree(a);
}

#pragma GCC diagnostic ignored "-Wunused-function"

/* __racontext_attr_compare: if the attribute types are different,
 * just compare the type values.  Otherwise, compare the contents.
 * MAC addresses are compared byte-by-byte.  IP addresses first compare
 * address family; if different, the results are based on a comparison of
 * the numberic AF values (implementation-specific).  If the AFs are the
 * same, the addresses are compared byte-by-byte.  Prefixes also include
 * a comparison of the prefix length if the addresses are identical.
 * Note that this is not longest prefix match computation; this is only
 * used to provide a consistent sorted order and to avoid duplicates.
 * Anything that contains a string value is compared lexigraphically.
 */
static int
__racontext_attr_compare(struct racontext_attribute *a,
                         struct racontext_attribute *b)
{
   long long diff = a->attrib_num - b->attrib_num;

   if (diff)
      return (diff < 0) ? -1 : 1;

   switch (a->attrib_num) {
      case CTX_ATTRIB_BSSID:
      case CTX_ATTRIB_DHCP_SERVER_MAC:
      case CTX_ATTRIB_NEXT_HOP_MAC:
      case CTX_ATTRIB_IGMP_QUERIER_MAC:
      case CTX_ATTRIB_MCAST_SOURCE_MAC:
      case CTX_ATTRIB_BCAST_SOURCE_MAC:
      case CTX_ATTRIB_MCAST_DEST_MAC:
         /* OUI-48 */
         return memcmp(a->value_un.l2addr, b->value_un.l2addr, ETH_ALEN);

      case CTX_ATTRIB_SLAAC_PREFIX:
         /* l3addr + prefix */
      case CTX_ATTRIB_DHCP_DNS_SERVER:
      case CTX_ATTRIB_DHCP_NEXTHOP:
      case CTX_ATTRIB_IGMP_QUERIER_ADDRESS: {
         /* l3addr */
         struct sockaddr_in *a_in;
         struct sockaddr_in *b_in;
         int rv;

         if (a->value_un.l3addr.sin6_family < b->value_un.l3addr.sin6_family)
            return -1;
         if (a->value_un.l3addr.sin6_family > b->value_un.l3addr.sin6_family)
            return 1;

         if (a->value_un.l3addr.sin6_family == AF_INET6) {
            rv = memcmp(&a->value_un.l3addr.sin6_addr,
                        &b->value_un.l3addr.sin6_addr,
                        sizeof(b->value_un.l3addr.sin6_addr));
         } else if (a->value_un.l3addr.sin6_family == AF_INET) {
            a_in = (struct sockaddr_in *)&a->value_un.l3addr;
            b_in = (struct sockaddr_in *)&b->value_un.l3addr;
            rv = memcmp(&a_in->sin_addr, &b_in->sin_addr,
                          sizeof(b_in->sin_addr));
         } else {
            rv = 0;  /* avoid incorrect warnings from clang-800.0.42.1 */
            ArgusLog(LOG_ERR, "%s: unknown address family %d\n", __func__,
                     a->value_un.l3addr.sin6_family);
         }

         if (rv == 0 && a->attrib_num == CTX_ATTRIB_SLAAC_PREFIX) {
            diff = (int)a->prefixlen - (int)b->prefixlen;
            rv = (diff < 0) ? -1 : ((diff == 0) ? 0 : 1);
         }
         return rv;
      }


      case CTX_ATTRIB_DHCP_DNS_DOMAIN:
      case CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME:
         /* string */
         return strcmp(a->value_un.name, b->value_un.name);
   }

   /* blow up */
   ArgusLog(LOG_ERR, "%s: unknown attribute %d\n", __func__, a->attrib_num);

   /* undoubtedly the compiler will complain if this doesn't return a value */
   return 0;
}

RB_GENERATE_STATIC(racontext_attr_tree, racontext_attribute, tree, \
                   __racontext_attr_compare);

struct racontext_attr_tree *
RacontextAttrTreeAlloc(void)
{
   struct racontext_attr_tree *rat;

   rat = ArgusCalloc(1, sizeof(*rat));
   if (rat == NULL)
      return NULL;

   RB_INIT(rat);
   return rat;
}

int
RacontextAttrTreeInsert(struct racontext_attr_tree *rat,
                        const struct racontext_attribute *attr,
                        bool deepcopy)
{
   struct racontext_attribute *newattr;
   struct racontext_attribute *exist;

   newattr = ArgusMalloc(sizeof(*newattr));
   if (newattr == NULL)
      return -ENOMEM;

   *newattr = *attr;
   if (deepcopy &&
       (attr->attrib_num == CTX_ATTRIB_DHCP_DNS_DOMAIN ||
        attr->attrib_num == CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME)) {
      newattr->value_un.name = strdup(attr->value_un.name);
      if (newattr->value_un.name == NULL) {
         ArgusFree(newattr);
         return -ENOMEM;
      }
   }

   exist = RB_INSERT(racontext_attr_tree, rat, newattr);
   if (exist) {
      exist->occurrences++;
      if (deepcopy &&
          (attr->attrib_num == CTX_ATTRIB_DHCP_DNS_DOMAIN ||
           attr->attrib_num == CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME))
         ArgusFree(newattr->value_un.name);
      ArgusFree(newattr);
      return -EEXIST;
   }

   return 0;
}

int
RacontextAttrTreeRemove(struct racontext_attr_tree *rat,
                        struct racontext_attribute *attr)
{
   RB_REMOVE(racontext_attr_tree, rat, attr);
   return 0;
}

struct racontext_attribute *
RacontextAttrTreeFind(struct racontext_attr_tree *rat,
                      struct racontext_attribute *exemplar)
{
   struct racontext_attribute *target;

   target = RB_FIND(racontext_attr_tree, rat, exemplar);
   return target;
}

void
RacontextAttrTreeFree(struct racontext_attr_tree *rat)
{
   if (rat == NULL)
      return;

   while (!RB_EMPTY(rat)) {
      struct racontext_attribute *attr = RB_ROOT(rat);

      RB_REMOVE(racontext_attr_tree, rat, attr);
      RacontextAttrFree(attr, true);
   }

   ArgusFree(rat);
}

bool
RacontextAttrTreeEmpty(struct racontext_attr_tree *rat)
{
   if (rat == NULL)
      return true;

   return (bool)!!RB_EMPTY(rat);
}

char
*RacontextAttrName(const struct racontext_attribute * const attr)
{
   static const size_t buflen = 64;
   char *name = ArgusMalloc(buflen);

   switch (attr->attrib_num) {
      case CTX_ATTRIB_BSSID:
         strncpy(name, "CTX_ATTRIB_BSSID", buflen);
         break;
      case CTX_ATTRIB_DHCP_SERVER_MAC:
         strncpy(name, "CTX_ATTRIB_DHCP_SERVER_MAC", buflen);
         break;
      case CTX_ATTRIB_NEXT_HOP_MAC:
         strncpy(name, "CTX_ATTRIB_NEXT_HOP_MAC", buflen);
         break;
      case CTX_ATTRIB_SLAAC_PREFIX:
         strncpy(name, "CTX_ATTRIB_SLAAC_PREFIX", buflen);
         break;
      case CTX_ATTRIB_DHCP_DNS_SERVER:
         strncpy(name, "CTX_ATTRIB_DHCP_DNS_SERVER", buflen);
         break;
      case CTX_ATTRIB_DHCP_DNS_DOMAIN:
         strncpy(name, "CTX_ATTRIB_DHCP_DNS_DOMAIN", buflen);
         break;
      case CTX_ATTRIB_DHCP_NEXTHOP:
         strncpy(name, "CTX_ATTRIB_DHCP_NEXTHOP", buflen);
         break;
      case CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME:
         strncpy(name, "CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME", buflen);
         break;
      case CTX_ATTRIB_IGMP_QUERIER_MAC:
         strncpy(name, "CTX_ATTRIB_IGMP_QUERIER_MAC", buflen);
         break;
      case CTX_ATTRIB_IGMP_QUERIER_ADDRESS:
         strncpy(name, "CTX_ATTRIB_IGMP_QUERIER_ADDRESS", buflen);
         break;
      case CTX_ATTRIB_MCAST_SOURCE_MAC:
         strncpy(name, "CTX_ATTRIB_MCAST_SOURCE_MAC", buflen);
         break;
      case CTX_ATTRIB_BCAST_SOURCE_MAC:
         strncpy(name, "CTX_ATTRIB_BCAST_SOURCE_MAC", buflen);
         break;
      case CTX_ATTRIB_MCAST_DEST_MAC:
         strncpy(name, "CTX_ATTRIB_MCAST_DEST_MAC", buflen);
         break;
      default:
         strncpy(name, "(UNKNOWN)", buflen);
   }

   return name;
}

char *
RacontextAttrValuePrint(const struct racontext_attribute * const a)
{
   static const size_t buflen = 128;
   size_t remain = buflen;
   size_t used = 0;
   char *buf = ArgusMalloc(buflen);

   if (buf == NULL)
      return NULL;

   switch (a->attrib_num) {
      case CTX_ATTRIB_BSSID:
      case CTX_ATTRIB_DHCP_SERVER_MAC:
      case CTX_ATTRIB_NEXT_HOP_MAC:
      case CTX_ATTRIB_IGMP_QUERIER_MAC:
      case CTX_ATTRIB_MCAST_SOURCE_MAC:
      case CTX_ATTRIB_BCAST_SOURCE_MAC:
      case CTX_ATTRIB_MCAST_DEST_MAC:
         /* OUI-48 */
         snprintf_append(buf, &used, &remain, "%02x:%02x:%02x:%02x:%02x:%02x",
                         a->value_un.l2addr[0], a->value_un.l2addr[1],
                         a->value_un.l2addr[2], a->value_un.l2addr[3],
                         a->value_un.l2addr[4], a->value_un.l2addr[5]);
         break;

      case CTX_ATTRIB_SLAAC_PREFIX:
         /* l3addr + prefix */
      case CTX_ATTRIB_DHCP_DNS_SERVER:
      case CTX_ATTRIB_DHCP_NEXTHOP:
      case CTX_ATTRIB_IGMP_QUERIER_ADDRESS: {
         /* l3addr */
         const char *res;
         const void *addr;
         struct in_addr in;

         if (a->value_un.l3addr.sin6_family == AF_INET) {
            in = ((const struct sockaddr_in *)&a->value_un.l3addr)->sin_addr;
            in.s_addr = ntohl(in.s_addr);
            addr = &in;
         } else
            addr = &a->value_un.l3addr.sin6_addr;

         res = inet_ntop(a->value_un.l3addr.sin6_family, addr, buf, remain);
         if (res == NULL) {
            ArgusFree(buf);
            buf = NULL;
         } else if (a->attrib_num == CTX_ATTRIB_SLAAC_PREFIX) {
            size_t l = strlen(buf);    /* ugh */
            used += l;
            remain -= l;

            snprintf_append(buf, &used, &remain, "/%hhu", a->prefixlen);
         }
         break;
      }

      case CTX_ATTRIB_DHCP_DNS_DOMAIN:
      case CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME:
         /* string */
         snprintf_append(buf, &used, &remain, a->value_un.name);
         break;

      default:
         ArgusFree(buf);
         buf = NULL;
   }

   if (remain == 0) {
      ArgusFree(buf);
      buf = NULL;
   }

   return buf;
}

int
RacontextAttrTreeDump(struct racontext_attr_tree *rat)
{
   struct racontext_attribute *attr;
   int rv = 0;

   RB_FOREACH(attr, racontext_attr_tree, rat) {
      char *name = RacontextAttrName(attr);
      char *value = RacontextAttrValuePrint(attr);

      if (name && value)
         printf("%20s %-20s %10s=%u\n", name, value, "occurrences",
                attr->occurrences);
      else
         rv = -1;

      if (name)
         ArgusFree(name);
      if (value)
         ArgusFree(value);

      if (rv < 0)
         break;
   }
   return rv;
}

struct racontext_attribute *
RacontextAttrTreeFirst(struct racontext_attr_tree *rat)
{
   return RB_MIN(racontext_attr_tree, rat);
}

struct racontext_attribute *
RacontextAttrTreeNext(struct racontext_attribute *attr)
{
   return RB_NEXT(racontext_attr_tree, NULL, attr);
}

static int
RacontextAttrSqlValue(const struct racontext_attribute * const attr,
                      char *buf, size_t *used, size_t *remain)
{
   const char *tmpval;
   struct sockaddr_in sin;
   void *addrp;
   char addrstr[INET6_ADDRSTRLEN+1];
   int af;

   /* format the right hand side of "val = ".  This might be a little
    * inefficient, but it avoids any issues of byte ordering differences
    * between sql client and tables on the sql server.
    */
   switch (attr->attrib_num) {
      case CTX_ATTRIB_BSSID:
      case CTX_ATTRIB_DHCP_SERVER_MAC:
      case CTX_ATTRIB_NEXT_HOP_MAC:
      case CTX_ATTRIB_IGMP_QUERIER_MAC:
      case CTX_ATTRIB_MCAST_SOURCE_MAC:
      case CTX_ATTRIB_BCAST_SOURCE_MAC:
      case CTX_ATTRIB_MCAST_DEST_MAC:
         snprintf_append(buf, used, remain, "UNHEX('%02x%02x%02x%02x%02x%02x')",
                         attr->value_un.l2addr[0], attr->value_un.l2addr[1],
                         attr->value_un.l2addr[2], attr->value_un.l2addr[3],
                         attr->value_un.l2addr[4], attr->value_un.l2addr[5]);
         break;

      case CTX_ATTRIB_SLAAC_PREFIX:
      case CTX_ATTRIB_DHCP_DNS_SERVER:
      case CTX_ATTRIB_DHCP_NEXTHOP:
      case CTX_ATTRIB_IGMP_QUERIER_ADDRESS:
         af = attr->value_un.l3addr.sin6_family;

         if (attr->attrib_num == CTX_ATTRIB_SLAAC_PREFIX) {
            addrp = (void *) &attr->value_un.l3addr.sin6_addr.s6_addr;
         } else {
            sin = *(struct sockaddr_in *)&attr->value_un.l3addr;
            sin.sin_addr.s_addr = ntohl(sin.sin_addr.s_addr);
            addrp = &sin.sin_addr.s_addr;
         }

         tmpval = inet_ntop(af, addrp, addrstr, sizeof(addrstr));
         if (tmpval == NULL)
            return -1;

         snprintf_append(buf, used, remain, "%s('%s')",
                         af == AF_INET6 ? "INET6_ATON" : "INET_ATON", tmpval);
         break;

      case CTX_ATTRIB_DHCP_DNS_DOMAIN:
      case CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME:
         snprintf_append(buf, used, remain, "'%s'", attr->value_un.name);
         break;

      default:
         return -1;
   }

   return 0;
}

/* RacontextAttrSqlWhere: format a set of conditionals suitable for including
 * in a SQL "WHERE" clause.  This function checks the next attribute in the
 * tree to see if it has the same type.  If so, that attribute's value will
 * be included in the "val IN (...)" notation.  This continues until an attr
 * of a different type is found or the last (max) node is reached.
 *
 * The one exception is CTX_ATTRIB_SLAAC_PREFIX which has a second value
 * to check, so don't attempt to group these together.  This really should
 * check for any type than includes a prefix length, but currently there is
 * only one.
 *
 * Returns: a pointer to the first attribute found of a different type
 * than attr.
 */
static const struct racontext_attribute *
RacontextAttrSqlWhere(const struct racontext_attribute * attr,
                      char *buf, size_t *used, size_t *remain)
{
   const struct racontext_attribute *tmp = attr;
   int32_t attrib_num = attr->attrib_num;

   snprintf_append(buf, used, remain, "idx=%d AND val IN (",
                   attr->attrib_num);
   while (tmp && tmp->attrib_num == attrib_num) {
      if (tmp != attr)
         snprintf_append(buf, used, remain, ",");

      RacontextAttrSqlValue(tmp, buf, used, remain);
      tmp = RB_NEXT(racontext_attr_tree, NULL,
                    (struct racontext_attribute *)tmp);
      if (attrib_num == CTX_ATTRIB_SLAAC_PREFIX)
         break;
   }
   snprintf_append(buf, used, remain, ")");
   if (attrib_num == CTX_ATTRIB_SLAAC_PREFIX)
      snprintf_append(buf, used, remain, " AND prefixlen=%hhu",
                      attr->prefixlen);
   return tmp;
}

/* Format for one attribute a SQL "WHERE" clause suitable for including
 * in a SELECT statement.  The resulting clause will test for the presence
 * of any attribute in the tree.  The resulting text is written to the
 * string pointed to by *buf, starting at offset used.  Used and remain
 * are updated to reflect the space consumed.
 */
int
RacontextAttrTreeSqlWhere(struct racontext_attr_tree * rat,
                          char *buf, size_t *used, size_t *remain)
{
   struct racontext_attribute *first = RB_MIN(racontext_attr_tree, rat);
   const struct racontext_attribute *attr = first;

   snprintf_append(buf, used, remain, "WHERE ((");
   while (attr) {
      if (attr != first)
         snprintf_append(buf, used, remain, ") OR (");
      attr = RacontextAttrSqlWhere(attr, buf, used, remain);
      if (*remain == 0)
         return -1;
   }
   snprintf_append(buf, used, remain, "))");
   return 0;
}
