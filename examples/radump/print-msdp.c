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
   (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," msdp:");
   while (length > 0) {
      TCHECK2(*sp, 3);
      type = *sp;
      len = EXTRACT_16BITS(sp + 1);
      if (len > 1400 || ArgusParser->vflag)
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," [len %u]", len);
      if (len < 3)
         goto trunc;
      sp += 3;
      length -= 3;
      switch (type) {
      case 1:   /* IPv4 Source-Active */
      case 3: /* IPv4 Source-Active Response */
         if (type == 1)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," SA");
         else
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," SA-Response");
         TCHECK(*sp);
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %u entries", *sp);
         if ((u_int)((*sp * 12) + 8) < len) {
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [w/data]");
            if (ArgusParser->vflag > 1) {
               (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," ");
/*
               ip_print(gndo, sp + *sp * 12 + 8 - 3,
                        len - (*sp * 12 + 8));
*/
            }
         }
         break;
      case 2:
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," SA-Request");
         TCHECK2(*sp, 5);
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," for %s", ipaddr_string(sp + 1));
         break;
      case 4:
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Keepalive");
         if (len != 3)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"[len=%d] ", len);
         break;
      case 5:
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," Notification");
         break;
      default:
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [type=%d len=%d]", type, len);
         break;
      }
      sp += (len - 3);
      length -= (len - 3);
   }
   return ArgusBuf;
trunc:
   (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|msdp]");

   return ArgusBuf;
}

/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 8
 * End:
 */
