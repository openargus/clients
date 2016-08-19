/*
 * Copyright (c) 1998-2004  Hannes Gredler <hannes@tcpdump.org>
 *      The TCPDUMP project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
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

/* 
 * tokenlists and #defines taken from Ethereal - Network traffic analyzer
 * by Gerald Combs <gerald@ethereal.com>
 */

#define SYSLOG_SEVERITY_MASK 0x0007  /* 0000 0000 0000 0111 */
#define SYSLOG_FACILITY_MASK 0x03f8  /* 0000 0011 1111 1000 */
#define SYSLOG_MAX_DIGITS 3 /* The maximum number if priority digits to read in. */

static const struct tok syslog_severity_values[] = {
  { 0,      "emergency" },
  { 1,      "alert" },
  { 2,      "critical" },
  { 3,      "error" },
  { 4,      "warning" },
  { 5,      "notice" },
  { 6,      "info" },
  { 7,      "debug" },
  { 0, NULL },
};

static const struct tok syslog_facility_values[] = {
  { 0,     "kernel" },
  { 1,     "user" },
  { 2,     "mail" },
  { 3,     "daemon" },
  { 4,     "auth" },
  { 5,     "syslog" },
  { 6,     "lpr" },
  { 7,     "news" },
  { 8,     "uucp" },
  { 9,     "cron" },
  { 10,    "authpriv" },
  { 11,    "ftp" },
  { 12,    "ntp" },
  { 13,    "security" },
  { 14,    "console" },
  { 15,    "cron" },
  { 16,    "local0" },
  { 17,    "local1" },
  { 18,    "local2" },
  { 19,    "local3" },
  { 20,    "local4" },
  { 21,    "local5" },
  { 22,    "local6" },
  { 23,    "local7" },
  { 0, NULL },
};

char *
syslog_print(register const u_char *pptr, register u_int len)
{
    u_int16_t msg_off = 0;
    u_int16_t pri = 0;
    u_int16_t facility,severity;

    /* extract decimal figures that are
     * encapsulated within < > tags
     * based on this decimal figure extract the
     * severity and facility values
     */

    if (!TTEST2(*pptr, 1))
        goto trunc;

    if (*(pptr+msg_off) == '<') {
        msg_off++;

        if (!TTEST2(*(pptr+msg_off), 1))
            goto trunc;

        while ( *(pptr+msg_off) >= '0' &&
                *(pptr+msg_off) <= '9' &&
                msg_off <= SYSLOG_MAX_DIGITS) {

            if (!TTEST2(*(pptr+msg_off), 1))
                goto trunc;

            pri = pri * 10 + (*(pptr+msg_off) - '0');
            msg_off++;

            if (!TTEST2(*(pptr+msg_off), 1))
                goto trunc;

        if (*(pptr+msg_off) == '>')
            msg_off++;
        }
    } else {
        sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|syslog]");
        return ArgusBuf;
    }

    facility = (pri & SYSLOG_FACILITY_MASK) >> 3;
    severity = pri & SYSLOG_SEVERITY_MASK;

    
    if (ArgusParser->vflag < 1 ) {
        sprintf(&ArgusBuf[strlen(ArgusBuf)],"SYSLOG %s.%s, length: %u",
               tok2str(syslog_facility_values, "unknown (%u)", facility),
               tok2str(syslog_severity_values, "unknown (%u)", severity),
               len);
        return ArgusBuf;
    }
       
    sprintf(&ArgusBuf[strlen(ArgusBuf)],"SYSLOG, length: %u\n\tFacility %s (%u), Severity %s (%u)\n\tMsg: ",
           len,
           tok2str(syslog_facility_values, "unknown (%u)", facility),
           facility,
           tok2str(syslog_severity_values, "unknown (%u)", severity),
           severity);

    /* print the syslog text in verbose mode */
    for (; msg_off < len; msg_off++) {
        if (!TTEST2(*(pptr+msg_off), 1))
            goto trunc;
        sprintf(&ArgusBuf[strlen(ArgusBuf)],"%c", *(pptr+msg_off));
    }

   if (ArgusParser->vflag > 1) {
      if(!print_unknown_data(pptr,"\n\t",len))
         return ArgusBuf;
   }
    
   return ArgusBuf;

trunc:
   sprintf(&ArgusBuf[strlen(ArgusBuf)],"[|syslog]");
   return ArgusBuf;
}
