/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 *
 */

/*
 * argus-grep.c  - support to find regular expressions in argus user data buffers.
 *
 * written by Carter Bullard
 * QoSient, LLC
 */

/* 
 * $Id: //depot/gargoyle/clients/common/argus_grep.c#8 $
 * $DateTime: 2016/07/13 18:38:48 $
 * $Change: 3170 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <unistd.h>
#include <sys/types.h>

#include <argus_compat.h>
#include <argus_def.h>
#include <argus_out.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <argus_grep.h>

int ArgusGrepBuf (regex_t *, char *, char *);

void
ArgusInitializeGrep (struct ArgusParserStruct *parser)
{
   if (parser && (parser->estr)) {
      if (parser->ArgusRegExItems < ARGUS_MAX_REGEX) {
         int options;
         int rege;

#if defined(ARGUS_PCRE)
         options = 0;
#else
         options = REG_EXTENDED | REG_NOSUB;
#if defined(REG_ENHANCED)
         options |= REG_ENHANCED;
#endif
#endif
         if (parser->iflag)
            options |= REG_ICASE;

         if ((rege = regcomp(&parser->upreg[parser->ArgusRegExItems], parser->estr, options)) != 0) {
            char errbuf[MAXSTRLEN];
            if (regerror(rege, &parser->upreg[parser->ArgusRegExItems], errbuf, MAXSTRLEN))
               ArgusLog (LOG_ERR, "ArgusProcessLabelOption: user data regex error %s", errbuf);
         }

         parser->ArgusRegExItems++;

      } else
         ArgusLog (LOG_ERR, "Too many regular expressions");
   }
}


/* Scan the specified portion of the buffer, to see if there
   is a match of any kind.  The idea is for every string in the
   buffer, just call regexec() with the strings. */

int
ArgusGrepBuf (regex_t *preg, char *beg, char *lim)
{
   int retn = 0, b;
   char *p = beg;

   while (!(p > lim)) {
      regmatch_t pmbuf, *pm = &pmbuf;
      int nmatch = 0;

      bzero(pm, sizeof(*pm));

      if ((b = regexec(preg, p, nmatch, pm, 0)) != 0) {
         switch (b) {
            case REG_NOMATCH: {
               int slen = strlen(p);
               p += slen + 1;
               break;
            }

            default:
               return retn;
         }

      } else
         return 1;
   }

   return retn;
}



int
ArgusGrepUserData (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus)
{
   struct ArgusDataStruct *user = NULL;
   int i, len, retn = 0, found = 0;

   if (parser->ArgusGrepSource) {
      if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_SRCUSERDATA_INDEX]) !=  NULL) {
         char *buf = (char *)&user->array;
         if ((user->hdr.type == ARGUS_DATA_DSR) && (user->hdr.subtype & ARGUS_LEN_16BITS)) {
            len = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
         } else 
            len = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

         for (i = 0; i < parser->ArgusRegExItems; i++) {
            if ((retn = ArgusGrepBuf (&parser->upreg[i], buf, &buf[len]))) {
               found++;
               break;
            }
         }
      }
   }

   if ((user = (struct ArgusDataStruct *)argus->dsrs[ARGUS_DSTUSERDATA_INDEX]) !=  NULL) {
      char *buf = (char *)&user->array;
      if (parser->ArgusGrepDestination) {
         if ((user->hdr.type == ARGUS_DATA_DSR) && (user->hdr.subtype & ARGUS_LEN_16BITS)) {
            len = (user->hdr.argus_dsrvl16.len - 2 ) * 4;
         } else
            len = (user->hdr.argus_dsrvl8.len - 2 ) * 4;

         for (i = 0; !found && i < parser->ArgusRegExItems; i++) {
            if ((retn = ArgusGrepBuf (&parser->upreg[i], buf, &buf[len])))
               found = 1;
         }
      }
   }

   retn = (parser->vflag) ? (found ? 0 : 1) : found;
   return (retn);
}
