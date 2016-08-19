/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *   The Regents of the University of California.  All rights reserved.
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
 * Format and print ntp packets.
 *   By Jeffrey Mogul/DECWRL
 *   loosely based on print-bootp.c
 */

#include <unistd.h>
#include <stdlib.h>

#include <argus_compat.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <rabins.h>

#include <signal.h>
#include <ctype.h>
#include <argus/extract.h>

extern u_char *snapend;

#include "interface.h"

#ifdef MODEMASK
#undef MODEMASK               /* Solaris sucks */
#endif
#include "ntp.h"

extern char ArgusBuf[];

static void p_sfix(const struct s_fixedpt *);
static void p_ntp_time(const struct l_fixedpt *);
static void p_ntp_delta(const struct l_fixedpt *, const struct l_fixedpt *);

static struct tok ntp_mode_values[] = {
    { MODE_UNSPEC,    "unspecified" },
    { MODE_SYM_ACT,   "symmetric active" },
    { MODE_SYM_PAS,   "symmetric passive" },
    { MODE_CLIENT,    "Client" },
    { MODE_SERVER,    "Server" },
    { MODE_BROADCAST, "Broadcast" },
    { MODE_RES1,      "Reserved" },
    { MODE_RES2,      "Reserved" },
    { 0, NULL }
};

static struct tok ntp_leapind_values[] = {
    { NO_WARNING,     "" },
    { PLUS_SEC,       "+1s" },
    { MINUS_SEC,      "-1s" },
    { ALARM,          "clock unsynchronized" },
    { 0, NULL }
};

/*
 * Print ntp requests
 */

char *
ntp_print(register const u_char *cp, u_int length)
{
   register const struct ntpdata *bp;
   int mode, version, leapind;

   bp = (struct ntpdata *)cp;

   TCHECK(bp->status);

   version = (int)(bp->status & VERSIONMASK) >> 3;
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"NTPv%d", version);

   mode = bp->status & MODEMASK;
   if (ArgusParser->vflag == 0) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", %s, length %u",
         tok2str(ntp_mode_values, "Unknown mode", mode), length);
      return ArgusBuf;
   }
        
   sprintf(&ArgusBuf[strlen(ArgusBuf)],", length %u %s", length, tok2str(ntp_mode_values, "Unknown mode", mode));

   if ((leapind = bp->status & LEAPMASK) || (ArgusParser->vflag > 1)) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", Leap indicator: %s (%u)",
         tok2str(ntp_leapind_values, "Unknown", leapind), leapind);
   }
   TCHECK(bp->stratum);
   if (bp->stratum || (ArgusParser->vflag > 1)) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", Stratum %u", bp->stratum);
   }
   TCHECK(bp->ppoll);
   if (bp->ppoll || (ArgusParser->vflag > 1)) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", poll %us", bp->ppoll);
   }
   /* Can't TCHECK bp->precision bitfield so bp->distance + 0 instead */
   if (bp->precision || (ArgusParser->vflag > 1)) {
      TCHECK2(bp->root_delay, 0);
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", precision %d", bp->precision);
   }
   TCHECK(bp->root_delay);
   if (bp->root_delay.int_part || (ArgusParser->vflag > 1)) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Root Delay: ");
      p_sfix(&bp->root_delay);
   }
   TCHECK(bp->root_dispersion);
   if (bp->root_dispersion.int_part || (ArgusParser->vflag > 1)) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", Root dispersion: ");
      p_sfix(&bp->root_dispersion);
   }
   TCHECK(bp->refid);
   if (bp->refid || (ArgusParser->vflag > 1)) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)],", Reference-ID: ");

      /* Interpretation depends on stratum */
      switch (bp->stratum) {
         case UNSPECIFIED:
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"(unspec)");
            break;

         case PRIM_REF:
            if (fn_printn((u_char *)&(bp->refid), 4, snapend, ArgusBuf))
               goto trunc;
            break;

         case INFO_QUERY:
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s INFO_QUERY", ipaddr_string(&(bp->refid)));
            /* this doesn't have more content */
            return ArgusBuf;

         case INFO_REPLY:
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s INFO_REPLY", ipaddr_string(&(bp->refid)));
            /* this is too complex to be worth printing */
            return ArgusBuf;

         default:
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"%s", ipaddr_string(&(bp->refid)));
            break;
      }
   }
   TCHECK(bp->ref_timestamp);
   if (bp->ref_timestamp.int_part || (ArgusParser->vflag > 1)) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Reference Timestamp: ");
      p_ntp_time(&(bp->ref_timestamp));
   }

   TCHECK(bp->org_timestamp);
   if (bp->org_timestamp.int_part || (ArgusParser->vflag > 1)) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Originator Timestamp: ");
      p_ntp_time(&(bp->org_timestamp));
   }

   TCHECK(bp->rec_timestamp);
   if (bp->rec_timestamp.int_part || (ArgusParser->vflag > 1)) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Receive Timestamp: ");
      p_ntp_time(&(bp->rec_timestamp));
   }

   TCHECK(bp->xmt_timestamp);
   if (bp->xmt_timestamp.int_part || (ArgusParser->vflag > 1)) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Transmit Timestamp: ");
      p_ntp_time(&(bp->xmt_timestamp));
   }

   if (bp->org_timestamp.int_part || (ArgusParser->vflag > 1)) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Delta Receive Timestamp:  ");
      p_ntp_delta(&(bp->org_timestamp), &(bp->rec_timestamp));

      sprintf(&ArgusBuf[strlen(ArgusBuf)]," Delta Transmit Timestamp: ");
      p_ntp_delta(&(bp->org_timestamp), &(bp->xmt_timestamp));
   }

   return ArgusBuf;

trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|ntp]");
   return ArgusBuf;
}

static void
p_sfix(register const struct s_fixedpt *sfp)
{
   register int i;
   register int f;
   register float ff;

   i = EXTRACT_16BITS(&sfp->int_part);
   f = EXTRACT_16BITS(&sfp->fraction);
   ff = f / 65536.0;   /* shift radix point by 16 bits */
   f = ff * 1000000.0;   /* Treat fraction as parts per million */
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"%d.%06d", i, f);
}

#define   FMAXINT   (4294967296.0)   /* floating point rep. of MAXINT */

static void
p_ntp_time(register const struct l_fixedpt *lfp)
{
   register int32_t i;
   register u_int32_t uf;
   register u_int32_t f;
   register float ff;

   i = EXTRACT_32BITS(&lfp->int_part);
   uf = EXTRACT_32BITS(&lfp->fraction);
   ff = uf;
   if (ff < 0.0)      /* some compilers are buggy */
      ff += FMAXINT;
   ff = ff / FMAXINT;   /* shift radix point by 32 bits */
   f = ff * 1000000000.0;   /* treat fraction as parts per billion */
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"%u.%09d", i, f);

#ifdef HAVE_STRFTIME
   /*
    * print the time in human-readable format.
    */
   if (i) {
       time_t seconds = i - JAN_1970;
       struct tm *tm;
       char time_buf[128];

       tm = localtime(&seconds);
       strftime(time_buf, sizeof (time_buf), "%Y/%m/%d %H:%M:%S", tm);
       sprintf(&ArgusBuf[strlen(ArgusBuf)]," (%s)", time_buf);
   }
#endif
}

/* Prints time difference between *lfp and *olfp */
static void
p_ntp_delta(register const struct l_fixedpt *olfp,
       register const struct l_fixedpt *lfp)
{
   register int32_t i;
   register u_int32_t u, uf;
   register u_int32_t ou, ouf;
   register u_int32_t f;
   register float ff;
   int signbit;

   u = EXTRACT_32BITS(&lfp->int_part);
   ou = EXTRACT_32BITS(&olfp->int_part);
   uf = EXTRACT_32BITS(&lfp->fraction);
   ouf = EXTRACT_32BITS(&olfp->fraction);
   if (ou == 0 && ouf == 0) {
      p_ntp_time(lfp);
      return;
   }

   i = u - ou;

   if (i > 0) {      /* new is definitely greater than old */
      signbit = 0;
      f = uf - ouf;
      if (ouf > uf)   /* must borrow from high-order bits */
         i -= 1;
   } else if (i < 0) {   /* new is definitely less than old */
      signbit = 1;
      f = ouf - uf;
      if (uf > ouf)   /* must carry into the high-order bits */
         i += 1;
      i = -i;
   } else {      /* int_part is zero */
      if (uf > ouf) {
         signbit = 0;
         f = uf - ouf;
      } else {
         signbit = 1;
         f = ouf - uf;
      }
   }

   ff = f;
   if (ff < 0.0)      /* some compilers are buggy */
      ff += FMAXINT;
   ff = ff / FMAXINT;   /* shift radix point by 32 bits */
   f = ff * 1000000000.0;   /* treat fraction as parts per billion */
   if (signbit)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"-");
   else
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"+");
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"%d.%09d", i, f);
}

