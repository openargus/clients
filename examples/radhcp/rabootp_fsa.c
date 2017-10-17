#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#include <syslog.h>
#include "argus_config.h"
#include "argus_util.h"
#include "argus_client.h"
#include "rabootp.h"
#include "dhcp.h"
#include "rabootp_fsa.h"

int
fsa_choose_initial_state(const struct ArgusDhcpStruct * const parsed)
{
   uint8_t msgtype;
   enum ArgusDhcpState newstate;

   if (parsed->msgtypemask == 0) {
      ArgusLog(LOG_INFO, "%s: parsed message has no type\n", __func__);
      return -1;
   }

   msgtype = __mask2type(parsed->msgtypemask);

   switch (msgtype) {

      case DHCPDISCOVER:
         newstate = SELECTING;
         break;

      case DHCPOFFER:
         newstate = SELECTING;
         break;

      case DHCPREQUEST:
         newstate = REQUESTING;
         break;

      case DHCPACK:
         if (parsed->rep.yiaddr.s_addr > 0)
            newstate = BOUND;
         else
            /* likely a response to a DHCPINFORM request.
             * rfc2131 seciton 3.4
             */
            newstate = INIT;
         break;

      case DHCPFORCERENEW:
         newstate = RENEWING;
         break;

      case DHCPDECLINE:
      case DHCPNAK:
      case DHCPRELEASE:
      case DHCPINFORM:
      case DHCPLEASEQUERY:
      case DHCPLEASEUNASSIGNED:
      case DHCPLEASEUNKNOWN:
      case DHCPLEASEACTIVE:
         newstate = INIT;
         break;

      default:
         ArgusLog(LOG_INFO, "%s: unknown message type %d\n", __func__, msgtype);
         return -1;
   }

   return (int)newstate;
}

static int
fsa_state_init(const struct ArgusDhcpStruct * const parsed,
               const struct ArgusDhcpStruct * const cached)
{
   uint8_t msgtype;
   enum ArgusDhcpState newstate;

   if (parsed->msgtypemask == 0) {
      ArgusLog(LOG_INFO, "%s: parsed message has no type\n", __func__);
      return -1;
   }

   msgtype = __mask2type(parsed->msgtypemask);

   switch (msgtype) {
      case DHCPDISCOVER:
         newstate = SELECTING;
         break;
      default:
         newstate = fsa_choose_initial_state(parsed);
         break;
   }
   return newstate;
}

static int
fsa_state_selecting(const struct ArgusDhcpStruct * const parsed,
                    const struct ArgusDhcpStruct * const cached)
{
   uint8_t msgtype;
   enum ArgusDhcpState newstate;

   if (parsed->msgtypemask == 0) {
      ArgusLog(LOG_INFO, "%s: parsed message has no type\n", __func__);
      return -1;
   }

   msgtype = __mask2type(parsed->msgtypemask);

   switch (msgtype) {
      case DHCPOFFER:
         newstate = SELECTING;
         break;
      case DHCPREQUEST:
         newstate = REQUESTING;
         break;
      default:
         newstate = fsa_choose_initial_state(parsed);
         break;
   }

   return newstate;
}

static int
fsa_state_requesting(const struct ArgusDhcpStruct * const parsed,
                     const struct ArgusDhcpStruct * const cached)
{
   uint8_t msgtype;
   enum ArgusDhcpState newstate;

   if (parsed->msgtypemask == 0) {
      ArgusLog(LOG_INFO, "%s: parsed message has no type\n", __func__);
      return -1;
   }

   msgtype = __mask2type(parsed->msgtypemask);

   switch (msgtype) {
      case DHCPOFFER:
         newstate = REQUESTING;
         break;
      case DHCPACK:
         newstate = BOUND;
         break;
      default:
         newstate = fsa_choose_initial_state(parsed);
         break;
   }

   return newstate;
}

static int
fsa_state_bound(const struct ArgusDhcpStruct * const parsed,
                const struct ArgusDhcpStruct * const cached)
{
   uint8_t msgtype;
   enum ArgusDhcpState newstate;

   if (parsed->msgtypemask == 0) {
      ArgusLog(LOG_INFO, "%s: parsed message has no type\n", __func__);
      return -1;
   }

   msgtype = __mask2type(parsed->msgtypemask);

   switch (msgtype) {
      case DHCPDECLINE:
         /* this should really transition from REQUESTING->INIT,
          * but we will not see the decline message soon enough.
          */
         newstate = INIT;
         break;
      case DHCPOFFER:
      case DHCPACK:
      case DHCPNAK:
         /* no change */
         newstate = BOUND;
         break;
      case DHCPREQUEST:
         newstate = RENEWING;
         break;
      default:
         newstate = fsa_choose_initial_state(parsed);
         break;
   }

   return newstate;
}

static int
fsa_state_renewing(const struct ArgusDhcpStruct * const parsed,
                   const struct ArgusDhcpStruct * const cached)
{
   uint8_t msgtype;
   enum ArgusDhcpState newstate;

   if (parsed->msgtypemask == 0) {
      ArgusLog(LOG_INFO, "%s: parsed message has no type\n", __func__);
      return -1;
   }

   msgtype = __mask2type(parsed->msgtypemask);

   switch (msgtype) {
      case DHCPACK:
         newstate = BOUND;
         break;
      case DHCPREQUEST:
         newstate = REBINDING;
         break;
      case DHCPNAK:
         newstate = INIT;
         break;
      default:
         newstate = fsa_choose_initial_state(parsed);
         break;
   }

   return newstate;
}

static int
fsa_state_rebinding(const struct ArgusDhcpStruct * const parsed,
                    const struct ArgusDhcpStruct * const cached)
{
   uint8_t msgtype;
   enum ArgusDhcpState newstate;

   if (parsed->msgtypemask == 0) {
      ArgusLog(LOG_INFO, "%s: parsed message has no type\n", __func__);
      return -1;
   }

   msgtype = __mask2type(parsed->msgtypemask);

   switch (msgtype) {
      case DHCPACK:
         newstate = BOUND;
         break;
      case DHCPNAK:
         newstate = INIT;
         break;
      default:
         newstate = fsa_choose_initial_state(parsed);
         break;
   }

   return newstate;
}

static statefunc statefuncs[9] = {
   NULL,
   NULL,
   NULL,
   fsa_state_requesting,
   fsa_state_bound,
   fsa_state_renewing,
   fsa_state_rebinding,
   fsa_state_selecting,
   fsa_state_init,
};

int
fsa_advance_state(const struct ArgusDhcpStruct * const parsed,
                  const struct ArgusDhcpStruct * const cached)
{
   int state = (int)cached->state;

   if (state < 1  || state >= sizeof(statefuncs)/sizeof(statefuncs[0]))
      return -1;

   if (statefuncs[state])
      return (statefuncs[state])(parsed, cached);

   /* if there is no state function available, no state change happens. */
   return state;
}
