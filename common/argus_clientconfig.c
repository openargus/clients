/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2019 QoSient, LLC
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
 * Argus configuration helper routines.
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
#if defined(HAVE_UUID_H)
#include <uuid.h>
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
#ifdef HAVE_GETHOSTUUID
   if (!(strcmp (optarg, "hostuuid"))) {
      uuid_t id;
      struct timespec ts = {0,0};
      if (gethostuuid(id, &ts) == 0) {
         char sbuf[64];
         uuid_unparse(id, sbuf);
         res = strdup(sbuf);
      } else
         ArgusLog (LOG_ERR, "%s: System error: gethostuuid() %s\n", __func__, strerror(errno));
   } else
#else
# ifdef CYGWIN

   if (!(strcmp (optarg, "hostuuid"))) {
      char uuidstr[64];

      if (__wmic_get_uuid(uuidstr, 37) == 0)
         res = strdup(uuidstr);
      else
         ArgusLog(LOG_ERR, "%s: unable to read system UUID\n", __func__);
   } else
# endif
#endif
      ArgusLog (LOG_ERR, "%s: unsupported command `%s`.\n", __func__, in);

   free(optargstart);
   return res;
}
