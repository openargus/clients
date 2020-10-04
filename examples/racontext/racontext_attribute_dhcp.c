#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif
#include "argus_util.h"
#include "argus_client.h"
#include "rabootp.h"
#include "argus_dhcp.h"
#include "racontext.h"
#include "racontext_attribute_dhcp.h"

/*
 * Fill in the CTX_ATTRIB_DHCP_DNS_SERVER, CTX_ATTRIB_DHCP_DNS_DOMAIN,
 * CTX_ATTRIB_DHCP_NEXTHOP and CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME
 * context attributes if available from the dhcp lease.
 */

int
RacontextAttributeDhcpUpdate(struct racontext *ctx,
                             const struct ArgusDhcpIntvlNode * const node)
{
   const struct ArgusDhcpStruct * const data = node->data;
   struct racontext_attribute *attr;
   int res = 0;
   int max;
   int insret;
   int i;

   if (data == NULL)
      return -EINVAL;

   attr = ArgusCalloc(1, sizeof(*attr));
   if (attr == NULL)
      return -ENOMEM;

   max = sizeof(data->rep.nameserver)/sizeof(data->rep.nameserver[0]);
   for (i = 0; i < max; i++) {
      if (data->rep.nameserver_count > i && data->rep.nameserver[i].s_addr != 0) {
         attr->attrib_num = CTX_ATTRIB_DHCP_DNS_SERVER;
         attr->value_un.l3addr.sin6_family = AF_INET;
         ((struct sockaddr_in *)&attr->value_un.l3addr)->sin_addr.s_addr
          = data->rep.nameserver[i].s_addr;

         insret = RacontextAttrTreeInsert(ctx->attrs, attr, true);
         if (insret < 0 && insret != -EEXIST) {
            res = insret;
            goto out;
         }
         RacontextIncrPerAttrTotal(ctx, attr->attrib_num);
      }
   }

   if (data->rep.router.s_addr != 0) {
      attr->attrib_num = CTX_ATTRIB_DHCP_NEXTHOP;
      attr->value_un.l3addr.sin6_family = AF_INET;
      attr->value_un.l3addr.sin6_family = AF_INET;
         ((struct sockaddr_in *)&attr->value_un.l3addr)->sin_addr.s_addr
          = data->rep.router.s_addr;

      insret = RacontextAttrTreeInsert(ctx->attrs, attr, true);
      if (insret < 0 && insret != -EEXIST) {
         res = insret;
         goto out;
      }
      RacontextIncrPerAttrTotal(ctx, attr->attrib_num);
   }

   if (data->rep.domainname && *data->rep.domainname) {
      attr->attrib_num = CTX_ATTRIB_DHCP_DNS_DOMAIN;
      attr->value_un.name = data->rep.domainname;
      insret = RacontextAttrTreeInsert(ctx->attrs, attr, true);

      /* avoid any chance of double-freeing the domainname */
      attr->value_un.name = NULL;

      if (insret < 0 && insret != -EEXIST) {
         res = insret;
         goto out;
      }
      RacontextIncrPerAttrTotal(ctx, attr->attrib_num);
   }

   if (data->req.requested_hostname && *data->req.requested_hostname) {
      attr->attrib_num = CTX_ATTRIB_DHCP_REQUESTED_HOSTNAME;
      attr->value_un.name = data->req.requested_hostname;
      insret = RacontextAttrTreeInsert(ctx->attrs, attr, true);

      /* avoid any chance of double-freeing the domainname */
      attr->value_un.name = NULL;

      if (insret < 0 && insret != -EEXIST) {
         res = insret;
         goto out;
      }
      RacontextIncrPerAttrTotal(ctx, attr->attrib_num);
   }

   attr->attrib_num = CTX_ATTRIB_DHCP_SERVER_MAC;
   memcpy(attr->value_un.l2addr, data->rep.shaddr, sizeof(data->shaddr));
   insret = RacontextAttrTreeInsert(ctx->attrs, attr, true);
   if (insret < 0 && insret != -EEXIST) {
      res = insret;
      goto out;
   }
   RacontextIncrPerAttrTotal(ctx, attr->attrib_num);

out:
   RacontextAttrFree(attr, false);
   return res;
}
