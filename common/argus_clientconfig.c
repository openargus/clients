/*
 * Argus-5.0 Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */ 

/*
 * Argus-5.0 Client Library
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */
#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(HAVE_STDINT_H)
# include <stdint.h>
#endif
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "argus_compat.h"
#include "argus_util.h"
#include "argus_output.h"
#include "argus_config.h"

#if defined(HAVE_UUID_UUID_H)
#include <uuid/uuid.h>
#else
#if defined(HAVE_LINUX_UUID_H)
#include <linux/uuid.h>
#else
#if defined(HAVE_UUID_H)
#include <uuid.h>
#endif
#endif
#endif


#ifdef CYGWIN
static int
__wmic_get_uuid(char *uuidstr, size_t len)
{
   FILE *fp;
   char str[64];
   int res = -1;

   if (len < 37)
      /* need 37 bytes, including terminating null, to hold uuid string */
      return -1;

   fp = popen("/cygdrive/c/Windows/System32/Wbem/wmic"
              " path win32_computersystemproduct get uuid", "r");
   if (fp == NULL)
      return -1;

   if (fgets(str, sizeof(str), fp) == NULL)
      goto close_out;

   if (strncmp(str, "UUID", 4) == 0) {
      if (fgets(str, sizeof(str), fp) == NULL)
         goto close_out;

      if (strlen(str) >= 37) {
         strncpy(uuidstr, str, 36);
         uuidstr[36] = '\0';
         res = 0;
      }
   }

close_out:
   fclose(fp);
   return res;
}
#endif


#ifdef HAVE_MACHINE_ID
static int
__linux_get_machine_id_uuid(char *uuidstr, size_t len)
{
   char str[64], *sptr = str;
   int slen, res = -1;
   FILE *fp;

   if (len < 37)
      /* need 37 bytes, including terminating null, to hold uuid string */
      return -1;

   if ((fp = fopen("/var/lib/dbus/machine-id", "r")) != NULL) {
      if (fgets(str, sizeof(str), fp) == NULL)
         goto linux_close_out;

      if (strncmp(sptr, "UUID", 4) == 0) 
         sptr += 4;

      if (sptr[strlen(sptr) - 1] == '\n') 
         sptr[strlen(sptr) - 1] = '\0';

      if ((slen = strlen(sptr)) >= 32) {
         strncpy(uuidstr, sptr, 32);
         uuidstr[33] = '\0';
         res = 0;
      }

linux_close_out:
      fclose(fp);
   }

   return res;
}
#endif


/* configuration files can contain values with backticks, such as
 * `hostname` and `hostuuid`.  Convert those to the actual values here.
 */

char *ArgusExpandBackticks(const char * const);

char *
ArgusExpandBackticks(const char * const in)
{
   char *res = NULL;
   char *optargstart;
   char *optarg = strdup(in);
   char *ptr;
   FILE *fd;

   optargstart = optarg;
   optarg++;

   if ((ptr = strrchr(optarg, '`')) != NULL) {
       *ptr = '\0';
   }

   if (!(strcmp (optarg, "hostname"))) {
      if ((fd = popen("hostname", "r")) != NULL) {
         char *ptr = NULL;
         char *result = malloc(MAXSTRLEN); /* since we use strdup() elsewhere */

         if (result == NULL)
            ArgusLog (LOG_ERR, "%s: Unable to allocate hostname buffer\n",
                      __func__);

         clearerr(fd);
         while ((ptr == NULL) && !(feof(fd)))
            ptr = fgets(result, MAXSTRLEN, fd);

         if (ptr == NULL)
            ArgusLog (LOG_ERR, "%s: `hostname` failed %s.\n", __func__, strerror(errno));

         ptr[strlen(ptr) - 1] = '\0';
         pclose(fd);

         if ((ptr = strstr(optarg, ".local")) != NULL) {
            if (strlen(ptr) == strlen(".local"))
               *ptr = '\0';
         }

         res = result;
      } else
         ArgusLog (LOG_ERR, "%s: System error: popen() %s\n", __func__, strerror(errno));
   } else
   if (!(strcmp (optarg, "hostuuid"))) {
#ifdef HAVE_GETHOSTUUID
      uuid_t id;
      struct timespec ts = {0,0};
      if (gethostuuid(id, &ts) == 0) {
         char sbuf[64];
         uuid_unparse(id, sbuf);
         res = strdup(sbuf);
      } else
         ArgusLog (LOG_ERR, "%s: System error: gethostuuid() %s\n", __func__, strerror(errno));
#else
# ifdef HAVE_MACHINE_ID
      char uuidstr[64];

      if (__linux_get_machine_id_uuid(uuidstr, 37) == 0)
         res = strdup(uuidstr);
      else
         ArgusLog(LOG_ERR, "%s: unable to read system UUID\n", __func__);
# else
#  ifdef CYGWIN
      char uuidstr[64];

      if (__wmic_get_uuid(uuidstr, 37) == 0)
         res = strdup(uuidstr);
      else
         ArgusLog(LOG_ERR, "%s: unable to read system UUID\n", __func__);
#  endif
# endif
#endif
   } else
      ArgusLog (LOG_ERR, "%s: unsupported command `%s`.\n", __func__, in);

   free(optargstart);
   return res;
}
