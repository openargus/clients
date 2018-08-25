/*
 * Copyright (c) 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * L2TP support contributed by Motonori Shindo (mshindo@mshindo.net)
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

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

char *
wol_print(const u_char *dat, u_int length)
{
   const u_char *ptr = dat;
   int i, match = 0;

   sprintf(&ArgusBuf[strlen(ArgusBuf)]," wol:");

   for (i = 0; i < length; i++) {
      if (ptr[i] != 0xff)
         match = 0;
      else
         if (++match == 6) {
            i++;
            break;
         }
   }

   if (match == 6) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," tagged: ");
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," wake-on-lan eaddr %s", etheraddr_string(ArgusParser, (u_char *)&dat[i]));
   }

   return ArgusBuf;
}
