/*
 * Copyright (c) 2000 Ben Smithurst <ben@scientia.demon.co.uk>
 * All rights reserved.
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
#include "timed.h"

extern char ArgusBuf[];

static const char *tsptype[TSPTYPENUMBER] =
  { "ANY", "ADJTIME", "ACK", "MASTERREQ", "MASTERACK", "SETTIME", "MASTERUP",
  "SLAVEUP", "ELECTION", "ACCEPT", "REFUSE", "CONFLICT", "RESOLVE", "QUIT",
  "DATE", "DATEREQ", "DATEACK", "TRACEON", "TRACEOFF", "MSITE", "MSITEREQ",
  "TEST", "SETDATE", "SETDATEREQ", "LOOP" };

char *
timed_print(register const u_char *bp, u_int len)
{
#define endof(x) ((u_char *)&(x) + sizeof (x))
   struct tsp *tsp = (struct tsp *)bp;
   long sec, usec;
   const u_char *end;

   if (endof(tsp->tsp_type) > snapend) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|timed]");
      return ArgusBuf;
   }
   if (tsp->tsp_type < TSPTYPENUMBER)
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"TSP_%s", tsptype[tsp->tsp_type]);
   else
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"(tsp_type %#x)", tsp->tsp_type);

   if (endof(tsp->tsp_vers) > snapend) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|timed]");
      return ArgusBuf;
   }
   sprintf(&ArgusBuf[strlen(ArgusBuf)]," vers %d", tsp->tsp_vers);

   if (endof(tsp->tsp_seq) > snapend) {
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|timed]");
      return ArgusBuf;
   }
   sprintf(&ArgusBuf[strlen(ArgusBuf)]," seq %d", tsp->tsp_seq);

   if (tsp->tsp_type == TSP_LOOP) {
      if (endof(tsp->tsp_hopcnt) > snapend) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|timed]");
         return ArgusBuf;
      }
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," hopcnt %d", tsp->tsp_hopcnt);
   } else if (tsp->tsp_type == TSP_SETTIME ||
     tsp->tsp_type == TSP_ADJTIME ||
     tsp->tsp_type == TSP_SETDATE ||
     tsp->tsp_type == TSP_SETDATEREQ) {
      if (endof(tsp->tsp_time) > snapend) {
         sprintf(&ArgusBuf[strlen(ArgusBuf)]," [|timed]");
         return ArgusBuf;
      }
      sec = EXTRACT_32BITS(&tsp->tsp_time.tv_sec);
      usec = EXTRACT_32BITS(&tsp->tsp_time.tv_usec);
      if (usec < 0)
         /* corrupt, skip the rest of the packet */
         return ArgusBuf;
      sprintf(&ArgusBuf[strlen(ArgusBuf)]," time ");
      if (sec < 0 && usec != 0) {
         sec++;
         if (sec == 0)
            sprintf(&ArgusBuf[strlen(ArgusBuf)],"-");
         usec = 1000000 - usec;
      }
      sprintf(&ArgusBuf[strlen(ArgusBuf)],"%ld.%06ld", sec, usec);
   }

   end = memchr(tsp->tsp_name, '\0', snapend - (u_char *)tsp->tsp_name);
   if (end == NULL)
      sprintf(&ArgusBuf[strlen(ArgusBuf)], " [|timed]");
   else {
      sprintf(&ArgusBuf[strlen(ArgusBuf)], " name");
      snprintf(&ArgusBuf[strlen(ArgusBuf)], end - (u_char *)tsp->tsp_name, "%s", tsp->tsp_name);
   }

   return ArgusBuf;
}
