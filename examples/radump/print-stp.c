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

#include <unistd.h>
#include <stdlib.h>

#include <argus_compat.h>

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
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "%.2x%.2x.%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
          p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
}

static void
stp_print_config_bpdu(const u_char *p)
{
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "config ");
   if (p[4] & 1)
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "TOP_CHANGE ");
   if (p[4] & 0x80)
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "TOP_CHANGE_ACK ");

   stp_print_bridge_id(p+17);
   sprintf(&ArgusBuf[strlen(ArgusBuf)], ".%.2x%.2x ", p[25], p[26]);

   sprintf(&ArgusBuf[strlen(ArgusBuf)], "root ");
   stp_print_bridge_id(p+5);

   sprintf(&ArgusBuf[strlen(ArgusBuf)], " pathcost %i ", (p[13] << 24) | (p[14] << 16) | (p[15] << 8) | p[16]);

   sprintf(&ArgusBuf[strlen(ArgusBuf)], "age %i ", p[27]);
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "max %i ", p[29]);
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "hello %i ", p[31]);
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "fdelay %i", p[33]);
}

static void
stp_print_tcn_bpdu(void)
{
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "tcn");
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
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "rapid ");

   for (i = 0; i < 8; i++) {
      switch (i) {
         case BPDU_TOPOLOGY_CHANGE:
            if (p[4] & (0x01 << i)) 
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "top_change ");
            break;
         case BPDU_PROPOSAL:
            if (p[4] & (0x01 << i)) 
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "prop ");
            break;
         case BPDU_PORT_ROLE:
            if (p[4] & 0x0B) {
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "role:");
               switch (p[4] & 0x0C) {
                  case 0x04: sprintf(&ArgusBuf[strlen(ArgusBuf)], "back "); break;
                  case 0x08: sprintf(&ArgusBuf[strlen(ArgusBuf)], "root "); break;
                  case 0x0C: sprintf(&ArgusBuf[strlen(ArgusBuf)], "desg "); break;
               }
            }
            break;
         case BPDU_LEARNING:
            if (p[4] & (0x01 << i)) 
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "learn ");
            break;
         case BPDU_FORWARDING:
            if (p[4] & (0x01 << i)) 
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "forward ");
            break;
         case BPDU_AGREEMENT:
            if (p[4] & (0x01 << i)) 
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "agree ");
            break;
         case BPDU_TOPOLOGY_ACK:
            if (p[4] & (0x01 << i)) 
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "top_change_ack ");
            break;
      }
   }

   sprintf(&ArgusBuf[strlen(ArgusBuf)], "root ");
   stp_print_bridge_id(p+5);
   sprintf(&ArgusBuf[strlen(ArgusBuf)], " cost %i ", (p[13] << 24) | (p[14] << 16) | (p[15] << 8) | p[16]);

   sprintf(&ArgusBuf[strlen(ArgusBuf)], "bridge ");
   stp_print_bridge_id(p+17);

   sprintf(&ArgusBuf[strlen(ArgusBuf)], " port ");
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "0x%.2x%.2x ", p[25], p[26]);

   sprintf(&ArgusBuf[strlen(ArgusBuf)], "age %i ", p[27]);
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "max %i ", p[29]);
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "hello %i ", p[31]);
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "fdelay %i", p[33]);
}

/*
 * Print 802.1d packets.
 */


char *
stp_print(const u_char *p, u_int length)
{
   if (length < 4)
      goto trunc;

   sprintf(&ArgusBuf[strlen(ArgusBuf)], "802.1d ");
   if (p[0] || p[1]) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)], "unknown protocol");
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
               sprintf(&ArgusBuf[strlen(ArgusBuf)], "unknown type %i", p[3]);
               break;
         }
         break;
      }
      default:
         sprintf(&ArgusBuf[strlen(ArgusBuf)], "unknown version");
         break;
   }
   return (ArgusBuf);
trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)], "[|stp %d]", length);

   return (ArgusBuf);
}
