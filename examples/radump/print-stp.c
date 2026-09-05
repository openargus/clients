/*
 * Copyright (c) 2000 Lennert Buytenhek
 *
 * This software may be distributed either under the terms of the
 * BSD-style license that accompanies tcpdump or the GNU General
 * Public License
 *
 * Format and print IEEE 802.1d spanning tree protocol packets.
 * Contributed by Lennert Buytenhek <buytenh@gnu.org>
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
#include "bootp.h"

extern char ArgusBuf[];

static void
stp_print_bridge_id(const u_char *p)
{
   ARGUSBUF_APPEND("%.2x%.2x.%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
          p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
}

static void
stp_print_config_bpdu(const u_char *p)
{
   ARGUSBUF_APPEND("config ");
   if (p[4] & 1)
      ARGUSBUF_APPEND("TOP_CHANGE ");
   if (p[4] & 0x80)
      ARGUSBUF_APPEND("TOP_CHANGE_ACK ");

   stp_print_bridge_id(p+17);
   ARGUSBUF_APPEND(".%.2x%.2x ", p[25], p[26]);

   ARGUSBUF_APPEND("root ");
   stp_print_bridge_id(p+5);

   ARGUSBUF_APPEND(" pathcost %i ", (p[13] << 24) | (p[14] << 16) | (p[15] << 8) | p[16]);

   ARGUSBUF_APPEND("age %i ", p[27]);
   ARGUSBUF_APPEND("max %i ", p[29]);
   ARGUSBUF_APPEND("hello %i ", p[31]);
   ARGUSBUF_APPEND("fdelay %i", p[33]);
}

static void
stp_print_tcn_bpdu(void)
{
   ARGUSBUF_APPEND("tcn");
}

#define BPDU_TOPOLOGY_CHANGE 	0
#define BPDU_PROPOSAL 		1
#define BPDU_PORT_ROLE 		3
#define BPDU_LEARNING 		4
#define BPDU_FORWARDING 	5
#define BPDU_AGREEMENT 		6
#define BPDU_TOPOLOGY_ACK 	7

static void
stp_print_rapid_bpdu(const u_char *p, u_int length)
{
   int i;
   ARGUSBUF_APPEND("rapid ");

   for (i = 0; i < 8; i++) {
      switch (i) {
         case BPDU_TOPOLOGY_CHANGE:
            if (p[4] & (0x01 << i)) 
               ARGUSBUF_APPEND("top_change ");
            break;
         case BPDU_PROPOSAL:
            if (p[4] & (0x01 << i)) 
               ARGUSBUF_APPEND("prop ");
            break;
         case BPDU_PORT_ROLE:
            if (p[4] & 0x0B) {
               ARGUSBUF_APPEND("role:");
               switch (p[4] & 0x0C) {
                  case 0x04: ARGUSBUF_APPEND("back "); break;
                  case 0x08: ARGUSBUF_APPEND("root "); break;
                  case 0x0C: ARGUSBUF_APPEND("desg "); break;
               }
            }
            break;
         case BPDU_LEARNING:
            if (p[4] & (0x01 << i)) 
               ARGUSBUF_APPEND("learn ");
            break;
         case BPDU_FORWARDING:
            if (p[4] & (0x01 << i)) 
               ARGUSBUF_APPEND("forward ");
            break;
         case BPDU_AGREEMENT:
            if (p[4] & (0x01 << i)) 
               ARGUSBUF_APPEND("agree ");
            break;
         case BPDU_TOPOLOGY_ACK:
            if (p[4] & (0x01 << i)) 
               ARGUSBUF_APPEND("top_change_ack ");
            break;
      }
   }

   ARGUSBUF_APPEND("root ");
   stp_print_bridge_id(p+5);
   ARGUSBUF_APPEND(" cost %i ", (p[13] << 24) | (p[14] << 16) | (p[15] << 8) | p[16]);

   ARGUSBUF_APPEND("bridge ");
   stp_print_bridge_id(p+17);

   ARGUSBUF_APPEND(" port ");
   ARGUSBUF_APPEND("0x%.2x%.2x ", p[25], p[26]);

   ARGUSBUF_APPEND("age %i ", p[27]);
   ARGUSBUF_APPEND("max %i ", p[29]);
   ARGUSBUF_APPEND("hello %i ", p[31]);
   ARGUSBUF_APPEND("fdelay %i", p[33]);
}

/*
 * Print 802.1d packets.
 */


char *
stp_print(const u_char *p, u_int length)
{
   if (length < 4)
      goto trunc;

   ARGUSBUF_APPEND("802.1d ");
   if (p[0] || p[1]) {
      ARGUSBUF_APPEND("unknown protocol");
      return (ArgusBuf);
   }

   switch (p[2]) {
      case 0x00: 
      case 0x02: {
         switch (p[3]) {
            case 0x00:
               if (length < 10)
                  goto trunc;
               stp_print_config_bpdu(p);
               break;

            case 0x02:
               stp_print_rapid_bpdu(p, length);
               break;

            case 0x80:
               stp_print_tcn_bpdu();
               break;

            default:
               ARGUSBUF_APPEND("unknown type %i", p[3]);
               break;
         }
         break;
      }
      default:
         ARGUSBUF_APPEND("unknown version");
         break;
   }
   return (ArgusBuf);
trunc:
   ARGUSBUF_APPEND("[|stp %d]", length);

   return (ArgusBuf);
}
