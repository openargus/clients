/*   $NetBSD: print-telnet.c,v 1.2 1999/10/11 12:40:12 sjg Exp $    */

/*-
 * Copyright (c) 1997, 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Simon J. Gerraty.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 *      @(#)Copyright (c) 1994, Simon J. Gerraty.
 *
 *      This is free software.  It comes with NO WARRANTY.
 *      Permission to use, modify and distribute this source code
 *      is granted subject to the following conditions.
 *      1/ that the above copyright notice and this notice
 *      are preserved in all copies.
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

extern u_char *snapend;

#include "interface.h"

extern char ArgusBuf[];

#define TELCMDS
#define TELOPTS
#include "telnet.h"

/* normal */
static const char *cmds[] = {
   "IS", "SEND", "INFO",
};

/* 37: Authentication */
static const char *authcmd[] = {
   "IS", "SEND", "REPLY", "NAME",
};
static const char *authtype[] = {
   "NULL", "KERBEROS_V4", "KERBEROS_V5", "SPX", "MINK",
   "SRP", "RSA", "SSL", NULL, NULL,
   "LOKI", "SSA", "KEA_SJ", "KEA_SJ_INTEG", "DSS",
   "NTLM",
};

/* 38: Encryption */
static const char *enccmd[] = {
   "IS", "SUPPORT", "REPLY", "START", "END",
   "REQUEST-START", "REQUEST-END", "END_KEYID", "DEC_KEYID",
};
static const char *enctype[] = {
   "NULL", "DES_CFB64", "DES_OFB64", "DES3_CFB64", "DES3_OFB64",
   NULL, "CAST5_40_CFB64", "CAST5_40_OFB64", "CAST128_CFB64", "CAST128_OFB64",
};

#define STR_OR_ID(x, tab) \
   (((x) < sizeof(tab)/sizeof(tab[0]) && tab[(x)]) ? tab[(x)] : numstr(x))

static char *
numstr(int x)
{
   static char buf[20];

   snprintf(buf, sizeof(buf), "%#x", x);
   return buf;
}

/* sp points to IAC byte */
static int
telnet_parse(const u_char *sp, u_int length, int print)
{
   int i, x;
   u_int c;
   const u_char *osp, *p;
#define FETCH(c, sp, length) \
   do { \
      if (length < 1) \
         goto pktend; \
      TCHECK(*sp); \
      c = *sp++; \
      length--; \
   } while (0)

   osp = sp;

   FETCH(c, sp, length);
   if (c != IAC)
      goto pktend;
   FETCH(c, sp, length);
   if (c == IAC) {      /* <IAC><IAC>! */
      if (print)
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"IAC IAC");
      goto done;
   }

   i = c - TELCMD_FIRST;
   if (i < 0 || i > IAC - TELCMD_FIRST)
      goto pktend;

   switch (c) {
   case DONT:
   case DO:
   case WONT:
   case WILL:
   case SB:
      /* DONT/DO/WONT/WILL x */
      FETCH(x, sp, length);
      if (x >= 0 && x < NTELOPTS) {
         if (print)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s %s", telcmds[i], telopts[x]);
      } else {
         if (print)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s %#x", telcmds[i], x);
      }
      if (c != SB)
         break;
      /* IAC SB .... IAC SE */
      p = sp;
      while (length > (u_int)(p + 1 - sp)) {
         if (p[0] == IAC && p[1] == SE)
            break;
         p++;
      }
      if (*p != IAC)
         goto pktend;

      switch (x) {
      case TELOPT_AUTHENTICATION:
         if (p <= sp)
            break;
         FETCH(c, sp, length);
         if (print)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", STR_OR_ID(c, authcmd));
         if (p <= sp)
            break;
         FETCH(c, sp, length);
         if (print)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", STR_OR_ID(c, authtype));
         break;
      case TELOPT_ENCRYPT:
         if (p <= sp)
            break;
         FETCH(c, sp, length);
         if (print)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", STR_OR_ID(c, enccmd));
         if (p <= sp)
            break;
         FETCH(c, sp, length);
         if (print)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", STR_OR_ID(c, enctype));
         break;
      default:
         if (p <= sp)
            break;
         FETCH(c, sp, length);
         if (print)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %s", STR_OR_ID(c, cmds));
         break;
      }
      while (p > sp) {
         FETCH(x, sp, length);
         if (print)
            (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," %#x", x);
      }
      /* terminating IAC SE */
      if (print)
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)]," SE");
      sp += 2;
      length -= 2;
      break;
   default:
      if (print)
         (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", telcmds[i]);
      goto done;
   }

done:
   return sp - osp;

trunc:
   (void)sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|telnet]");
pktend:
   return -1;
#undef FETCH
}

char *
telnet_print(const u_char *sp, u_int length)
{
   int first = 1;
   const u_char *osp;
   int l;

   osp = sp;

   while (length > 0 && *sp == IAC) {
      l = telnet_parse(sp, length, 0);
      if (l < 0)
         break;

      /*
       * now print it
       */
      if (ArgusParser->Xflag && 2 < ArgusParser->vflag) {
         if (first)
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"Telnet:");
         hex_print_with_offset(" ", sp, l, sp - osp);
         if (l > 8)
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"\n\t\t\t\t");
         else
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"%*s\t", (8 - l) * 3, "");
      } else
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", (first) ? " [telnet " : ", ");

      (void)telnet_parse(sp, length, 1);
      first = 0;

      sp += l;
      length -= l;
   }
   if (!first) {
      if (ArgusParser->Xflag && 2 < ArgusParser->vflag)
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"\n");
      else
         sprintf(&ArgusBuf[strlen(ArgusBuf)],"]");
   }

   return ArgusBuf;
}
