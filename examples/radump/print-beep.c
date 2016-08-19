/*
 * Copyright (C) 2000, Richard Sharpe
 *
 * This software may be distributed either under the terms of the
 * BSD-style licence that accompanies tcpdump or under the GNU GPL
 * version 2 or later.
 *
 * print-beep.c
 *
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

/* Check for a string but not go beyond length
 * Return TRUE on match, FALSE otherwise
 *
 * Looks at the first few chars up to tl1 ...
 */

static int l_strnstart(const char *, u_int, const char *, u_int);

static int
l_strnstart(const char *tstr1, u_int tl1, const char *str2, u_int l2)
{

   if (tl1 > l2)
      return 0;

   return (strncmp(tstr1, str2, tl1) == 0 ? 1 : 0);
}

char *
beep_print(const u_char *bp, u_int length)
{

   if (l_strnstart("MSG", 4, (const char *)bp, length)) /* A REQuest */
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," BEEP MSG");
   else if (l_strnstart("RPY ", 4, (const char *)bp, length))
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," BEEP RPY");
   else if (l_strnstart("ERR ", 4, (const char *)bp, length))
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," BEEP ERR");
   else if (l_strnstart("ANS ", 4, (const char *)bp, length))
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," BEEP ANS");
   else if (l_strnstart("NUL ", 4, (const char *)bp, length))
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," BEEP NUL");
   else if (l_strnstart("SEQ ", 4, (const char *)bp, length))
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," BEEP SEQ");
   else if (l_strnstart("END", 4, (const char *)bp, length))
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," BEEP END");
   else
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," BEEP (payload or undecoded)");

   return(ArgusBuf);
}
