#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif
#include <netinet/in.h>
#include <netinet/igmp.h>
#include <netinet/icmp6.h>
#include "racontext.h"
#include "racontext_attribute_flow.h"

static int
RacontextAttributeFlowInsertMac(struct racontext *ctx,
                                int32_t attrib_num, uint8_t *addr)
{
   struct racontext_attr_tree *attrs = ctx->attrs;
   struct racontext_attribute *attr;
   int res = 0;

   attr = ArgusCalloc(1, sizeof(*attr));
   if (attr == NULL)
      return -ENOMEM;

   attr->attrib_num = attrib_num;
   /* only copy enough for an ethernet mac (oui48) because this is what
    * the Mac flow DSR holds.
    */
   memcpy(attr->value_un.l2addr, addr, ETH_ALEN);
   res = RacontextAttrTreeInsert(attrs, attr, true);
   if (res == -EEXIST)
      res = 0;
   if (res == 0)
      RacontextIncrPerAttrTotal(ctx, attrib_num);
   ArgusFree(attr);
   return res;
}

static int
RacontextAttributeFlowInsertL3(struct racontext *ctx,
                               int32_t attrib_num, struct sockaddr *sa,
                               uint8_t prefixlen)
{
   struct racontext_attr_tree *attrs = ctx->attrs;
   struct racontext_attribute *attr;
   int res = 0;
   size_t len;

   attr = ArgusCalloc(1, sizeof(*attr));
   if (attr == NULL)
      return -ENOMEM;

   if (sa->sa_family == AF_INET)
      len = sizeof(struct sockaddr_in);
   else if (sa->sa_family == AF_INET6)
      len = sizeof(struct sockaddr_in6);
   else
      return -EINVAL;

   attr->attrib_num = attrib_num;
   attr->prefixlen = prefixlen;
   memcpy(&attr->value_un.l3addr, sa, len);
   res = RacontextAttrTreeInsert(attrs, attr, true);
   if (res == -EEXIST)
      res = 0;
   if (res == 0)
      RacontextIncrPerAttrTotal(ctx, attrib_num);
   ArgusFree(attr);
   return res;
}

static int
RacontextAttributeFlowUpdateMac(struct racontext *ctx,
                                const struct ArgusRecordStruct * const argus)
{
   static const uint8_t bcast[ETH_ALEN] = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
   struct ArgusMacStruct *ams;
   uint8_t *dst;
   uint8_t *src;
   int res = 0;

   ams = (struct ArgusMacStruct *)argus->dsrs[ARGUS_MAC_INDEX];
   if (ams == NULL)
      return -EINVAL;

#if 0
   if ((ams->hdr.subtype & 0x3F) != ARGUS_TYPE_ETHER)
      return -EINVAL;
#endif

   /* Check for broadcast traffic */
   dst = &ams->mac.mac_union.ether.ehdr.ether_dhost[0];
   src = &ams->mac.mac_union.ether.ehdr.ether_shost[0];
   if (memcmp(dst, bcast, sizeof(bcast)) == 0) {
      res = RacontextAttributeFlowInsertMac(ctx, CTX_ATTRIB_BCAST_SOURCE_MAC,
                                            src);
      if (res < 0)
         goto out;
   }
   /* Check for multicast traffic */
   else if (dst[0] & 0x1) {
      res = RacontextAttributeFlowInsertMac(ctx, CTX_ATTRIB_MCAST_SOURCE_MAC,
                                            src);
      if (res < 0)
         goto out;
      res = RacontextAttributeFlowInsertMac(ctx, CTX_ATTRIB_MCAST_DEST_MAC,
                                            dst);
      if (res < 0)
         goto out;
   }

out:
   return res;
}

/* struct sockaddr *sa must already point to enough memory to hold the flow
 * source address
 */
static int
__fetch_src_addr(const struct ArgusFlow * const flow, uint8_t type,
                 struct sockaddr *sa, uint8_t *prefixlen)
{
   if (type == ARGUS_TYPE_IPV4) {
      struct sockaddr_in *sin = (struct sockaddr_in *)sa;

      *prefixlen = 32;
      sin->sin_family = AF_INET;
      sin->sin_addr.s_addr = flow->ip_flow.ip_src;
      if (flow->hdr.argus_dsrvl8.qual & ARGUS_MASKLEN)
         *prefixlen = flow->ip_flow.smask;
   } else if (type == ARGUS_TYPE_IPV6) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

      *prefixlen = 128;
      sin6->sin6_family = AF_INET6;
      memcpy(sin6->sin6_addr.s6_addr, &flow->ipv6_flow.ip_src[0],
             sizeof(sin6->sin6_addr.s6_addr));
      if (flow->hdr.argus_dsrvl8.qual & ARGUS_MASKLEN)
         *prefixlen = flow->ipv6_flow.smask;
   } else
      return -1;

   return 0;
}

static int
RacontextAttributeFlowUpdateIgmp(struct racontext *ctx,
                                 const struct ArgusRecordStruct * const argus)
{
   static const uint8_t igmp_membership_query = IGMP_HOST_MEMBERSHIP_QUERY;
   static const uint8_t mld_membership_query = MLD_LISTENER_QUERY;
   struct ArgusFlow *flow = (struct ArgusFlow *)argus->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusDataStruct *data;
   struct ArgusMacStruct *ams;
   struct sockaddr_in6 src;
   uint8_t prefixlen = 0;
   uint8_t type;
   uint8_t *ethsrc;
   int res = 0;

   if (flow == NULL)
      return 0;

   switch (flow->hdr.subtype & 0x3F) {
      case ARGUS_FLOW_CLASSIC5TUPLE:
      case ARGUS_FLOW_LAYER_3_MATRIX:
         break;
      default:
         return 0;
   }

   data = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX];
   ams = (struct ArgusMacStruct *)argus->dsrs[ARGUS_MAC_INDEX];
   type = flow->hdr.argus_dsrvl8.qual & 0x1F;

   if (ams == NULL)
      return 0;

   switch (type) {
      case ARGUS_TYPE_IPV4:
         if (flow->ip_flow.ip_p != IPPROTO_IGMP)
            return 0;
         if (!(data->count > 1 && data->array[0] == igmp_membership_query))
            return 0;
         ethsrc = &ams->mac.mac_union.ether.ehdr.ether_shost[0];
         res = RacontextAttributeFlowInsertMac(ctx,
                                               CTX_ATTRIB_IGMP_QUERIER_MAC,
                                               ethsrc);
         break;
      case ARGUS_TYPE_IPV6:
         if (!(flow->icmpv6_flow.ip_p == IPPROTO_ICMPV6
               && flow->icmpv6_flow.type == mld_membership_query))
            return 0;
         break;
      default:
         return 0;
   }

   __fetch_src_addr(flow, type, (struct sockaddr *)&src, &prefixlen);

   switch (type) {
      case ARGUS_TYPE_IPV4:
         res = RacontextAttributeFlowInsertL3(ctx,
                                              CTX_ATTRIB_IGMP_QUERIER_ADDRESS,
                                              (struct sockaddr *)&src,
                                              prefixlen);
         break;
   }

   /* argus v3 and v5 have no IGMP DSR???? */
   return res;
}

/* IPv6 neighbor discovery */
static int
RacontextAttributeFlowUpdateND(struct racontext *ctx,
                               const struct ArgusRecordStruct * const argus)
{
   static const uint8_t nd_router_advert = ND_ROUTER_ADVERT;
   static const uint8_t nd_router_solicit = ND_ROUTER_SOLICIT;
   static const uint8_t nd_opt_prefix_information = ND_OPT_PREFIX_INFORMATION;
   static const long nd_opt_hdr_length = 4; /* in eight-byte chunks */
   struct ArgusFlow *flow = (struct ArgusFlow *)argus->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusDataStruct *data;
   struct sockaddr_in6 sin6;
   unsigned int prefixlen = 0;
   uint8_t type;
   int res = 0;
   struct nd_router_advert *adv;
   struct nd_opt_hdr *opt;
   long remain; /* remaining user buffer in bytes, signed on purpose */

   if (flow == NULL)
      return 0;

   switch (flow->hdr.subtype & 0x3F) {
      case ARGUS_FLOW_CLASSIC5TUPLE:
      case ARGUS_FLOW_LAYER_3_MATRIX:
         break;
      default:
         return 0;
   }

   data = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX];
   type = flow->hdr.argus_dsrvl8.qual & 0x1F;

   if (data == NULL)
      return 0;

   if (type != ARGUS_TYPE_IPV6)
      return 0;

   /* Argus turns a router advertisement packet into a router
    * solicitation "flow", even if nobody asked.  Since we have
    * the advtertisement header in the user payload, check there
    * for the correct message type.
    */
   if (!(flow->icmpv6_flow.ip_p == IPPROTO_ICMPV6
         && flow->icmpv6_flow.type == nd_router_solicit))
      return 0;

   if (data->count <= sizeof(struct nd_router_advert))
      /* too small to have any options, like prefix */
      return 0;

   adv = (struct nd_router_advert *)&data->array[0];
   if (adv->nd_ra_hdr.icmp6_type != nd_router_advert)
      return 0;

   opt = (struct nd_opt_hdr *)(adv+1);
   remain = data->count - sizeof(*adv);

   while (remain >= nd_opt_hdr_length*8) {
      if (opt->nd_opt_len == 0)
         return -EINVAL;

      if (opt->nd_opt_type == nd_opt_prefix_information) {
         struct nd_opt_prefix_info *pinfo;

         if (opt->nd_opt_len != nd_opt_hdr_length)
            return -EINVAL;

         pinfo = (struct nd_opt_prefix_info *)opt;
         prefixlen = pinfo->nd_opt_pi_prefix_len;
         sin6.sin6_family = AF_INET6;
         sin6.sin6_addr = pinfo->nd_opt_pi_prefix;
         res = RacontextAttributeFlowInsertL3(ctx, CTX_ATTRIB_SLAAC_PREFIX,
                                              (struct sockaddr *)&sin6,
                                              prefixlen);
         break;
      }
      remain -= opt->nd_opt_len*8;
   }

   return res;
}

int
RacontextAttributeFlowUpdate(struct racontext *ctx,
                             const struct ArgusRecordStruct * const argus)
{
   int rv = 0;

   if (argus->dsrs[ARGUS_MAC_INDEX])
      rv = RacontextAttributeFlowUpdateMac(ctx, argus);
   if (rv == 0 && argus->dsrs[ARGUS_FLOW_INDEX])
      rv = RacontextAttributeFlowUpdateIgmp(ctx, argus);
   if (rv == 0 && argus->dsrs[ARGUS_FLOW_INDEX])
      rv = RacontextAttributeFlowUpdateND(ctx, argus);

   return rv;
}
