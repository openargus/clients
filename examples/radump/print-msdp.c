/*
 * Copyright (c) 2001 William C. Fenner.
 *                All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * The name of William C. Fenner may not be used to endorse or
 * promote products derived from this software without specific prior
 * written permission.  THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
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

extern char ArgusBuf[];

#define MSDP_TYPE_MAX   7

char *
msdp_print(const unsigned char *sp, u_int length)
{
   unsigned int type, len;

   TCHECK2(*sp, 3);
   /* See if we think we're at the beginning of a compound packet */
   type = *sp;
   len = EXTRACT_16BITS(sp + 1);
   if (len > 1500 || len < 3 || type == 0 || type > MSDP_TYPE_MAX)
      goto trunc;   /* not really truncated, but still not decodable */
   ARGUSBUF_APPEND(" msdp:");
   while (length > 0) {
      TCHECK2(*sp, 3);
      type = *sp;
      len = EXTRACT_16BITS(sp + 1);
      if (len > 1400 || ArgusParser->vflag)
         ARGUSBUF_APPEND(" [len %u]", len);
      if (len < 3)
         goto trunc;
      sp += 3;
      length -= 3;
      switch (type) {
      case 1:   /* IPv4 Source-Active */
      case 3: /* IPv4 Source-Active Response */
         if (type == 1)
            ARGUSBUF_APPEND(" SA");
         else
            ARGUSBUF_APPEND(" SA-Response");
         TCHECK(*sp);
         ARGUSBUF_APPEND(" %u entries", *sp);
         if ((u_int)((*sp * 12) + 8) < len) {
            ARGUSBUF_APPEND(" [w/data]");
            if (ArgusParser->vflag > 1) {
               ARGUSBUF_APPEND(" ");
/*
               ip_print(gndo, sp + *sp * 12 + 8 - 3,
                        len - (*sp * 12 + 8));
*/
            }
         }
         break;
      case 2:
         ARGUSBUF_APPEND(" SA-Request");
         TCHECK2(*sp, 5);
         ARGUSBUF_APPEND(" for %s", ipaddr_string(sp + 1));
         break;
      case 4:
         ARGUSBUF_APPEND(" Keepalive");
         if (len != 3)
            ARGUSBUF_APPEND("[len=%d] ", len);
         break;
      case 5:
         ARGUSBUF_APPEND(" Notification");
         break;
      default:
         ARGUSBUF_APPEND(" [type=%d len=%d]", type, len);
         break;
      }
      sp += (len - 3);
      length -= (len - 3);
   }
   return ArgusBuf;
trunc:
   ARGUSBUF_APPEND(" [|msdp]");

   return ArgusBuf;
}

/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 8
 * End:
 */
