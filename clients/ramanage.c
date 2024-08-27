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
 *  ramanage.c - Argus archive management toolkit
 *
 *  Author: Eric Kinzie <eric@qosient.com>
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

/* note: realpath() can partially be replaced by GetFullPathName()
 * on Windows systems; they have similar, but not identical
 * functionality.
 */

#include <limits.h> /* PATH_MAX */
#include <errno.h>
#include <sys/types.h>
#include <stdio.h> /* NULL */
#include <stdlib.h> /* strtoul, realpath, rand */
#include <sys/syslog.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <utime.h>
#include <libgen.h>
#include <unistd.h>

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#ifdef HAVE_LIBCARES
# ifdef HAVE_NETDB_H
#  include <netdb.h>
# endif
# ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
# endif
# ifdef HAVE_ARPA_NAMESER_COMPAT_H
#  include <arpa/nameser_compat.h>
# endif
# include <ares.h>
# include <ares_dns.h>
static ares_channel channel;
static struct timeval ares_query_sent;
typedef enum _ares_state_e {
   LIBCARES_WAIT_SRV = 0,	/* first we lookup a service record */
   LIBCARES_DONE,		/* all answers received */
   LIBCARES_FAILED,		/* lack of answer or library error */
} ares_state_e;
ares_state_e ares_state;
static char *ares_srv_hostname;	/* the results of the SRV record lookup */
static unsigned short ares_srv_port;
static const char * const srvname = "_argus_upload._tcp";
static int ares_query_started;
#endif

#include "argus_util.h"
#include "argus_client.h"
#include "argus_lockfile.h"
#include "argus_main.h"
#include "argus_windows_registry.h"
#include "sha1.h"

#if defined(CYGWIN)
# include <sys/cygwin.h>
# define USE_IPV6
#endif

#if defined(__MINGW32__)
# include <process.h>	/* system() */
#endif

#ifdef ARGUSDEBUG
# define DEBUGLOG(lvl, fmt...) ArgusDebug(lvl, fmt)
#else
# define DEBUGLOG(lvl, fmt...)
#endif


enum {
   RAMANAGE_CMDMASK_COMPRESS = 0x1,
   RAMANAGE_CMDMASK_UPLOAD = 0x2,
   RAMANAGE_CMDMASK_REMOVE = 0x4,
} ramanage_cmdmask_e;

typedef struct _configuration_t {
   char *lockfile;
   char *path_archive;
   char *path_staging;
   char *archive_strategy;
   char *time_arg;

   unsigned int  debug_level;
   unsigned int compress_effort;
   unsigned int compress_method;
   unsigned int compress_max_kb;

   unsigned char upload_use_dns;
   char *upload_use_dns_domain; /* look for DNS SRV record in this domain */
   char *upload_user;
   char *upload_pass;
   char *upload_dir;
   struct sockaddr_storage upload_server;
   char *upload_auth;
   unsigned int upload_max_kb;
   unsigned int upload_delay_usec;

   unsigned int rpolicy_delete_after;
   unsigned int rpolicy_compress_after;
   unsigned int rpolicy_max_kb;
   unsigned int process_archive_period; /* minimum time between archive runs (sec) */
   unsigned int rpolicy_min_days;

   unsigned char rpolicy_ignore_archive; /* only process the -r file */
   unsigned char cmd_compress;
   unsigned char cmd_upload;
   unsigned char cmd_remove;

} configuration_t;

typedef struct _ramanage_str_t {
   char *str;
   size_t len;		/* bytes used */
   size_t remain;	/* bytes remaining */
} ramanage_str_t;

typedef enum _RamanageOptTypes {
   RAMANAGE_TYPE_YESNO,
   RAMANAGE_TYPE_UINT,
   RAMANAGE_TYPE_STR,
   RAMANAGE_TYPE_INET,
} RamanageOptTypes;

enum RamanageOpts {
   RAMANAGE_LOCK_FILE = 0,
   RAMANAGE_COMPRESS_EFFORT,
   RAMANAGE_COMPRESS_METHOD,
   RAMANAGE_COMPRESS_MAX_KB,
   RAMANAGE_UPLOAD_USE_DNS,
   RAMANAGE_UPLOAD_USE_DNS_DOMAIN,
   RAMANAGE_UPLOAD_SERVER,
   RAMANAGE_UPLOAD_DIR,
   RAMANAGE_UPLOAD_USER,
   RAMANAGE_UPLOAD_PASS,
   RAMANAGE_UPLOAD_AUTH,
   RAMANAGE_UPLOAD_MAX_KB,
   RAMANAGE_UPLOAD_DELAY_USEC,
   RAMANAGE_PATH_ARCHIVE,
   RAMANAGE_PATH_STAGING,
   RAMANAGE_ARCHIVE_STRATEGY,
   RAMANAGE_TIME_STRING,
   RAMANAGE_RPOLICY_DELETE_AFTER,
   RAMANAGE_RPOLICY_COMPRESS_AFTER,
   RAMANAGE_RPOLICY_MAX_KB,
   RAMANAGE_RPOLICY_MIN_DAYS,
   RAMANAGE_RPOLICY_IGNORE_ARCHIVE,
   RAMANAGE_PROCESS_ARCHIVE_PERIOD,
   RAMANAGE_CMD_COMPRESS,
   RAMANAGE_CMD_DELETE,
   RAMANAGE_CMD_UPLOAD,
   RAMANAGE_DEBUG_LEVEL,
};

static char *RamanageResourceFileStr[] = {
   "RAMANAGE_LOCK_FILE=",
   "RAMANAGE_COMPRESS_EFFORT=",
   "RAMANAGE_COMPRESS_METHOD=",
   "RAMANAGE_COMPRESS_MAX_KB=",
   "RAMANAGE_UPLOAD_USE_DNS=",
   "RAMANAGE_UPLOAD_USE_DNS_DOMAIN=",
   "RAMANAGE_UPLOAD_SERVER=",
   "RAMANAGE_UPLOAD_DIR=",
   "RAMANAGE_UPLOAD_USER=",
   "RAMANAGE_UPLOAD_PASS=",
   "RAMANAGE_UPLOAD_AUTH=",
   "RAMANAGE_UPLOAD_MAX_KB=",
   "RAMANAGE_UPLOAD_DELAY_USEC=",
   "RAMANAGE_PATH_ARCHIVE=",
   "RAMANAGE_PATH_STAGING=",
   "RAMANAGE_ARCHIVE_STRATEGY=",
   "RAMANAGE_TIME_STRING=",
   "RAMANAGE_RPOLICY_DELETE_AFTER=",
   "RAMANAGE_RPOLICY_COMPRESS_AFTER=",
   "RAMANAGE_RPOLICY_MAX_KB=",
   "RAMANAGE_RPOLICY_MIN_DAYS=",
   "RAMANAGE_RPOLICY_IGNORE_ARCHIVE=",
   "RAMANAGE_PROCESS_ARCHIVE_PERIOD=",
   "RAMANAGE_CMD_COMPRESS=",
   "RAMANAGE_CMD_DELETE=",
   "RAMANAGE_CMD_UPLOAD=",
   "RAMANAGE_DEBUG_LEVEL=",
};

static const size_t RAMANAGE_RCITEMS =
   sizeof(RamanageResourceFileStr)/sizeof(RamanageResourceFileStr[0]);

static configuration_t global_config;
static int noconf = 0;
static const int SHA1_INPUT_BUFLEN = 32*1024;
static const char * const state_filename = SHAREDSTATEDIR"/ramanage/timestamp";

#if defined(CYGWIN) || defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
#  include <windows.h>
# define REG_INIT(resstr, v, fieldname)				\
   { .valuename = (resstr),					\
     .valuetype = (v),						\
     .offset = offsetof(struct _configuration_t, fieldname),	\
   }

static int __parse_str(const char * const src, char **dst, size_t max);
static int __parse_uint(const char * const src, unsigned int *dst);
static int __parse_yesno(const char * const src, unsigned char *dst);
static int __parse_network_address(const char * const src,
                                   struct sockaddr_storage *dst);
struct {
   const char * const valuename;
   RamanageOptTypes valuetype;
   size_t offset;
} RamanageWindowsRegistryValues[] = {
   REG_INIT("RAMANAGE_LOCK_FILE", RAMANAGE_TYPE_STR, lockfile),
   REG_INIT("RAMANAGE_COMPRESS_EFFORT", RAMANAGE_TYPE_UINT, compress_effort),
   REG_INIT("RAMANAGE_COMPRESS_METHOD", RAMANAGE_TYPE_UINT, compress_method),
   REG_INIT("RAMANAGE_COMPRESS_MAX_KB", RAMANAGE_TYPE_UINT, compress_max_kb),
   REG_INIT("RAMANAGE_UPLOAD_USE_DNS", RAMANAGE_TYPE_YESNO, upload_use_dns),
   REG_INIT("RAMANAGE_UPLOAD_USE_DNS_DOMAIN", RAMANAGE_TYPE_STR, upload_use_dns_domain),
   REG_INIT("RAMANAGE_UPLOAD_SERVER", RAMANAGE_TYPE_INET, upload_server),
   REG_INIT("RAMANAGE_UPLOAD_DIR", RAMANAGE_TYPE_STR, upload_dir),
   REG_INIT("RAMANAGE_UPLOAD_USER", RAMANAGE_TYPE_STR, upload_user),
   REG_INIT("RAMANAGE_UPLOAD_PASS", RAMANAGE_TYPE_STR, upload_pass),
   REG_INIT("RAMANAGE_UPLOAD_AUTH", RAMANAGE_TYPE_STR, upload_auth),
   REG_INIT("RAMANAGE_UPLOAD_MAX_KB", RAMANAGE_TYPE_UINT, upload_max_kb),
   REG_INIT("RAMANAGE_UPLOAD_DELAY_USEC", RAMANAGE_TYPE_UINT, upload_delay_usec),
   REG_INIT("RAMANAGE_PATH_ARCHIVE", RAMANAGE_TYPE_STR, path_archive),
   REG_INIT("RAMANAGE_PATH_STAGING", RAMANAGE_TYPE_STR, path_staging),
   REG_INIT("RAMANAGE_ARCHIVE_STRATEGY", RAMANAGE_TYPE_STR, archive_strategy),
   REG_INIT("RAMANAGE_TIME_STRING", RAMANAGE_TYPE_STR, time_arg),
   REG_INIT("RAMANAGE_RPOLICY_DELETE_AFTER", RAMANAGE_TYPE_UINT, rpolicy_delete_after),
   REG_INIT("RAMANAGE_RPOLICY_COMPRESS_AFTER", RAMANAGE_TYPE_UINT, rpolicy_compress_after),
   REG_INIT("RAMANAGE_RPOLICY_MAX_KB", RAMANAGE_TYPE_UINT, rpolicy_max_kb),
   REG_INIT("RAMANAGE_RPOLICY_MIN_DAYS", RAMANAGE_TYPE_UINT, rpolicy_min_days),
   REG_INIT("RAMANAGE_RPOLICY_IGNORE_ARCHIVE", RAMANAGE_TYPE_YESNO, rpolicy_ignore_archive),
   REG_INIT("RAMANAGE_PROCESS_ARCHIVE_PERIOD", RAMANAGE_TYPE_UINT, process_archive_period),
   REG_INIT("RAMANAGE_CMD_COMPRESS", RAMANAGE_TYPE_YESNO, cmd_compress),
   REG_INIT("RAMANAGE_CMD_DELETE", RAMANAGE_TYPE_YESNO, cmd_remove),
   REG_INIT("RAMANAGE_CMD_UPLOAD", RAMANAGE_TYPE_YESNO, cmd_upload),
   REG_INIT("RAMANAGE_DEBUG_LEVEL", RAMANAGE_TYPE_UINT, debug_level),
};
static const size_t RAMANAGE_REGITEMS =
   sizeof(RamanageWindowsRegistryValues)/
   sizeof(RamanageWindowsRegistryValues[0]);

/* must have valid hkey */
static int
__fetch_registry_value(HKEY hkey, int index, configuration_t *config)
{
   int rv;
   char *tmp;
   const char * const valuename =
    RamanageWindowsRegistryValues[index].valuename;
   char **strval = (char **)(((char *)config) +
    RamanageWindowsRegistryValues[index].offset);
   unsigned int *intval = (unsigned int *)(((char *)config) +
    RamanageWindowsRegistryValues[index].offset);
   unsigned char *ucval = (unsigned char *)(((char *)config) +
    RamanageWindowsRegistryValues[index].offset);
   struct sockaddr_storage *addrval =
    (struct sockaddr_storage *)(((char *)config) +
    RamanageWindowsRegistryValues[index].offset);

   switch (RamanageWindowsRegistryValues[index].valuetype) {
      case RAMANAGE_TYPE_STR:
         tmp = ArgusMalloc(PATH_MAX);
         rv = ArgusWindowsRegistryGetSZ(hkey, valuename, tmp, PATH_MAX-1);
         if (rv == 0)
            rv = __parse_str(tmp, strval, PATH_MAX);

         ArgusFree(tmp);
         break;

      case RAMANAGE_TYPE_UINT: {
         long long tmpll;

         rv = ArgusWindowsRegistryGetQWORD(hkey, valuename, &tmpll);
         if (rv == 0)
            *intval = (unsigned int)tmpll;
         break;
      }

      case RAMANAGE_TYPE_YESNO:
         tmp = ArgusMalloc(5);
         rv = ArgusWindowsRegistryGetSZ(hkey, valuename, tmp, 4);
         if (rv == 0)
            rv = __parse_yesno(tmp, ucval);

         ArgusFree(tmp);
         break;

      case RAMANAGE_TYPE_INET:
         tmp = ArgusMalloc(PATH_MAX);
         rv = ArgusWindowsRegistryGetSZ(hkey, valuename, tmp, PATH_MAX-1);
         if (rv == 0)
            rv = __parse_network_address(tmp, addrval);

         ArgusFree(tmp);
         break;
   }
   return rv;
}

static void __fetch_registry_values(HKEY hkey, configuration_t *config)
{
   size_t i;

   for (i = 0; i < RAMANAGE_REGITEMS; i++)
      if (__fetch_registry_value(hkey, i, config) == 0)
         DEBUGLOG(2, "updated config from registry item %s\n",
                  RamanageWindowsRegistryValues[i].valuename);
}
#endif

#if !defined(CYGWIN)
# if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
typedef unsigned long useconds_t;
int usleep(useconds_t usec)
{
   HANDLE timer;
   LARGE_INTEGER ft;

   ft.QuadPart = -(10 * (__int64)usec);

   timer = CreateWaitableTimer(NULL, TRUE, NULL);
   SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0);
   WaitForSingleObject(timer, INFINITE);
   CloseHandle(timer);
   return 0;
}
# endif /* _MSC_VER... */
#endif /* CYGWIN */

#ifdef HAVE_LIBCARES
static void
RamanageLibcaresCallback(void *arg, int status, int timeouts,
                         unsigned char *abuf, int alen)
{
   unsigned int ancount;

   (void) timeouts; /* not used here */

   if (ares_state == LIBCARES_FAILED || ares_state == LIBCARES_DONE)
      return;

   /* Display an error message if there was an error, but only stop if
    * we actually didn't get an answer buffer.
    */
   if (status != ARES_SUCCESS) {
      printf("%s\n", ares_strerror(status));
       if (!abuf) {
          ares_state = LIBCARES_FAILED;
          return;
       }
   }

   /* Won't happen, but check anyway, for safety. */
   if (alen < HFIXEDSZ) {
      ares_state = LIBCARES_FAILED;
      return;
   }

   ancount = DNS_HEADER_ANCOUNT(abuf);

   if (ancount < 1) {
      ares_state = LIBCARES_FAILED;
      return;
   }

   if (ares_state == LIBCARES_WAIT_SRV) {
      struct ares_srv_reply *srv_out = NULL;

      status = ares_parse_srv_reply(abuf, alen, &srv_out);
      if (status != ARES_SUCCESS) {
         ares_state = LIBCARES_FAILED;
         return;
      }

      if (srv_out) {
         ares_srv_hostname = strdup(srv_out->host);
         ares_srv_port = srv_out->port;
         /*
         while (tmp) {
            compare priority?  weight?
            tmp = tmp->next;
         }
         */
         ares_free_data(srv_out);
         ares_state = LIBCARES_DONE;
      }
   }
}

static int
RamanageInitLibcares(const configuration_t * const config)
{
   struct ares_options options;
   char *fq_srvname; /* srvname with domain */
   int status;
   int slen;

   if (!config->upload_use_dns || !config->upload_use_dns_domain ||
       !config->cmd_upload)
      return 0;

   slen = snprintf(NULL, 0, "%s.%s", srvname, config->upload_use_dns_domain);
   if (slen < 0)
      return -1;

   fq_srvname = ArgusMalloc(slen+1);
   if (fq_srvname == NULL)
      ArgusLog(LOG_ERR, "unable to allocate memory for service name\n");
   sprintf(fq_srvname, "%s.%s", srvname, config->upload_use_dns_domain);

   options.flags = ARES_FLAG_NOCHECKRESP;
   options.servers = NULL;
   options.nservers = 0;

   status = ares_library_init(ARES_LIB_INIT_ALL);
   if (status != ARES_SUCCESS)
      ArgusLog(LOG_ERR, "ares_library_init: %s\n", ares_strerror(status));

   status = ares_init_options(&channel, &options, ARES_OPT_FLAGS);
   if (status != ARES_SUCCESS)
      ArgusLog(LOG_ERR, "ares_init_options: %s\n", ares_strerror(status));

   gettimeofday(&ares_query_sent, NULL); /* remember when this was sent */
   ares_query(channel, fq_srvname, C_IN, T_SRV, RamanageLibcaresCallback,
              (char *) NULL);
   ares_query_started = 1;

   return 0;
}

static int
RamanageLibcaresProcess(const configuration_t * const config)
{
   struct timeval tv;
   struct timeval *tvp;
   fd_set read_fds;
   fd_set write_fds;
   int rv = 0;
   int nfds;
   int count;

   if (ares_query_started == 0)
      return rv;

   for (;;) {
      FD_ZERO(&read_fds);
      FD_ZERO(&write_fds);
      nfds = ares_fds(channel, &read_fds, &write_fds);
      if (nfds == 0)
        break;

      tvp = ares_timeout(channel, NULL, &tv);
      count = select(nfds, &read_fds, &write_fds, NULL, tvp);
      if (count < 0 && (errno != EINVAL)) {
          rv = -1;
          break;
      }
      ares_process(channel, &read_fds, &write_fds);
    }
    return rv;
}

static void
RamanageCleanupLibcares(void)
{
   if (ares_query_started)
      ares_destroy(channel);
   ares_library_cleanup();
   if (ares_srv_hostname) {
      free(ares_srv_hostname); /* allocated by strdup */
      ares_srv_hostname = NULL;
   }
}
#endif

/* While we don't lock the state file, it should only be written to or
 * read while the lockfile is in our possesion
 */

/* write the current time to a file in ... */
static int
__save_state(void) {
   struct stat statbuf;
   struct timeval now;
   FILE *fp;

   if (stat(state_filename, &statbuf) != 0)
      ArgusMkdirPath(state_filename);

   fp = fopen(state_filename, "w");
   if (fp == NULL) {
      DEBUGLOG(2, "Failed to save state in %s\n", state_filename);
      return -1;
   }

   gettimeofday(&now, NULL);
   fprintf(fp, "%ld\n", now.tv_sec);
   fclose(fp);
   DEBUGLOG(2, "Saved state state in %s\n", state_filename);

   return 0;
}

/* read the time of the previous archive run and compare it to the
 * current time.  Return 1 if ok to process archive again.
 */
static int
__should_process_archive(configuration_t *config) {
   struct timeval then;
   struct timeval now;
   FILE *fp = NULL;
   int res = 0;

   /* no configured period.  just go. */
   if (config->process_archive_period == 0) {
      res = 1;
      goto out;
   }

   fp = fopen(state_filename, "r");
   if (fp == NULL) {
      /* If the file isn't there, assume we have never processed the
       * archive data and that it's ok to do so now
       */
      res = 1;
      goto out;
   }

   if (fscanf(fp, "%ld\n", &then.tv_sec) != 1) {
      /* can't make sense of the time, process the archive and replace
       * the state file.
       */
      res = 1;
      goto out;
   }

   then.tv_usec = 0;
   gettimeofday(&now, NULL);
   if (now.tv_usec >= 5000000) /* round up to nearest second */
      now.tv_sec++;

   if ((now.tv_sec - then.tv_sec) >= config->process_archive_period)
      res = 1;

out:
   DEBUGLOG(2, "Should%s process archive\n", res ? "" : " not");
   if (fp)
      fclose(fp);
   return res;
}

static void
__random_delay_init(void)
{
   struct timeval t;

   gettimeofday(&t, NULL);
   srand(t.tv_usec & (-1U));
}

static int
__random_delay(unsigned int min, unsigned int max /* usec */)
{
   unsigned int u;

   if (max == 0)
      return 0;

   u = (unsigned int)rand();
   u = (u + min) % max;
   DEBUGLOG(1, "%s sleeping %u usec\n", __func__, u);
   return usleep(u);
}

#ifdef ARGUS_CURLEXE
static int
__is_metacharacter(char c)
{
   if (c == '|' || c == '&' || c == ';' || c == '(' || c == ')' ||
       c == '<' || c == '>' || c == ' ' || c == 9 /* tab */ ||
       c == '\\')
      return 1;
   return 0;
}

/* Prepend each bourne shell "metacharacter" with a backslash.
 * Caller is responsible for freeing memory (wth free(), not ArgusFree()).
 */
static char *
__shell_escape(const char * const str)
{
   size_t metacount = 0;  /* number of metacharacters in string */
   size_t orig_strlen = strlen(str);
   size_t i = 0;
   char *newstr;
   char *tmp;

   while (*(str+i) != 0) {
      char c = *(str+i);

      if (__is_metacharacter(c))
         metacount++;
      i++;
   }

   if (metacount == 0) {
      newstr = strdup(str);
      if (newstr == NULL)
         ArgusLog(LOG_ERR, "%s: failed to duplicate string\n", __func__);
      return newstr;
   }

   newstr = malloc(orig_strlen + metacount + 1);
   if (newstr == NULL)
      ArgusLog(LOG_ERR, "%s: failed to allocate new string\n", __func__);

   for (i = 0, tmp = newstr; i < orig_strlen; i++) {
      if (__is_metacharacter(*(str+i)))
         *tmp++ = '\\';
      *tmp++ = *(str+i);
   }
   *tmp = 0;

   return newstr;
}
#endif /* ARGUS_CURLEXE */

static inline int
__file_older_than(const struct ArgusFileInput * const file, time_t when)
{
   return (file->statbuf.st_mtime <= when);
}

static inline time_t
__days_ago(const struct timeval * const now, unsigned int n)
{
   return (now->tv_sec - n*86400);
}

/* remove all occurrances of character "ch" from the end of string "str" */
static void
__chomp(char *str, char ch)
{
   char *tmp = str;

   /* find the end of this string */
   while (*tmp != 0)
      tmp++;

   /* back up one */
   if (tmp > str)
      tmp--;

   while (*tmp == ch && tmp > str) {
      *tmp = 0;
      tmp--;
   }
}

static int
__parse_str(const char * const src, char **dst, size_t max)
{
   int used;

   if (*dst != NULL)
      ArgusFree(*dst);

   *dst = ArgusMalloc(max);
   if (*dst == NULL)
      ArgusLog(LOG_ERR, "%s: unable to allocate memory\n", __func__);

   used = snprintf(*dst, max, "%s", src);
   if (used < 0 || used >= max) {
      ArgusFree(*dst);
      *dst = NULL;
      return 1;
   }

   *dst = ArgusRealloc(*dst, used+1);
   return 0;
}

static int
__parse_uint(const char * const src, unsigned int *dst)
{
   unsigned long tmpdst;
   char *endptr;

   tmpdst = strtoul(src, &endptr, 0);

   if (tmpdst == ULONG_MAX && errno == ERANGE)
      return -1;

   if (src && (src != endptr)) {
      *dst = (unsigned int)tmpdst;
      return 0;
   }

   return -1;
}

static int
__parse_yesno(const char * const src, unsigned char *dst)
{
   if (strcasecmp(src, "yes") == 0)
      *dst = 1;
   else {
      *dst = 0;
      if (strcasecmp(src, "no") != 0)
         return -1;
   }
   return 0;
}

static int
__parse_network_address(const char * const src, struct sockaddr_storage *dst)
{
   size_t slen = strlen(src);
   struct in_addr addr4;
   struct in6_addr addr6;
   int af = AF_INET;

   if (slen > NAME_MAX)
      return -1;

   if (inet_pton(AF_INET, src, &addr4) != 1) {
      if (inet_pton(AF_INET6, src, &addr6) != 1)
         return -1;
      else
         af = AF_INET6;
   }

   dst->ss_family = af;
   if (af == AF_INET)
      ((struct sockaddr_in *)dst)->sin_addr = addr4;
   else
      ((struct sockaddr_in6 *)dst)->sin6_addr = addr6;
   return 0;
}

#ifdef HAVE_ZLIB_H
/* __gzip() returns 0 on success, -1 otherwise. */
static int
__gzip(const char * const filename, const char * const gzfilename,
       off_t filesz, unsigned char *buf, size_t buflen)
{
   gzFile gzfp;
   FILE *fp;
   size_t remain;
   size_t blocks;
   int gzerr;
   unsigned char hdr[3];
   int magicbytes;

   fp = fopen(filename, "rb");
   if (fp == NULL) {
      ArgusLog(LOG_WARNING, "unable to open file %s\n", filename);
      return -1;
   }

   /* don't try to gzip a gzip file */
   magicbytes = fread(&hdr[0], 1, 3, fp);
   if (magicbytes == 3) {
      if (hdr[0] == 31 && hdr[1] == 139 && hdr[2] == 8) {
         DEBUGLOG(2, "skipping gzipped file %s\n", filename);
         fclose(fp);
         return -1;
      }
   }
   rewind(fp);

   gzfp = gzopen(gzfilename,"wb");
   if (gzfp == NULL) {
      ArgusLog(LOG_WARNING, "unable to open file %s\n", gzfilename);
      fclose(fp);
      return -1;
   }

   /* note: use gzsetparams OF((gzFile file, int level, int strategy)) to set
    * compression level
    */

   remain = filesz;
   gzerr = 0;

   while (remain > buflen && !gzerr && !ferror(fp) && !feof(fp)) {
      blocks = fread(buf, buflen, 1, fp);
      if (blocks == 0)
         continue;

      if (gzwrite(gzfp, buf, buflen) != buflen) {
         ArgusLog(LOG_WARNING, "failed writing gzip file\n");
         gzerr = -1;
      }

      remain -= buflen;
   }

   if (remain > 0 && remain < buflen && !gzerr) {
      blocks = fread(buf, remain, 1, fp);
      if (blocks == 0)
         gzerr = -1;
      else if (gzwrite(gzfp, buf, remain) != remain) {
         ArgusLog(LOG_WARNING,
                  "failed writing last bytes of gzip file\n");
         gzerr = -1;
      }
   }

   if (!gzerr && gzclose(gzfp) != Z_OK) {
      ArgusLog(LOG_WARNING, "failed to flush and close gzip file %s\n",
               gzfilename);
      gzerr = -1;
   }

   if (gzerr) {
      ArgusLog(LOG_WARNING, "removing failed gzip file %s\n", gzfilename);
      unlink(gzfilename);
   }

   fclose(fp);
   return gzerr;
}
#endif

#ifdef HAVE_LIBCURL
# include <curl/curl.h>
#else
typedef ramanage_str_t CURL;
#endif

#ifdef HAVE_LIBCURL
static size_t
RamanageLibcurlWriteCallback(char *ptr, size_t size, size_t nmemb, void *user)
{
   return size*nmemb;
}

# ifdef ARGUSDEBUG
static int
__trace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
{
  (void)handle;	/* unused */
  (void)userp;	/* unused */
  (void)size;	/* unused */
  (void)userp;	/* unused */

   switch (type) {
      case CURLINFO_TEXT:
      case CURLINFO_HEADER_IN:
      case CURLINFO_HEADER_OUT:
      case CURLINFO_DATA_IN:
         DEBUGLOG(2, "libcurl: %s", data);
         break;
      default: /* in case a new one is introduced to shock us */
         break;
   }

  return 0;
}
# endif /* ARGUSDEBUG */
#endif /* HAVE_LIBCURL */

/* hash must have 20 bytes allocated */
static int
__sha1(const char * const filename, char *hash)
{
   struct sha1_ctxt ctx;
   FILE *fp = fopen(filename, "r");
   size_t len;
   u_int8_t *buf;

   buf = ArgusMalloc(SHA1_INPUT_BUFLEN);
   if (buf == NULL)
      ArgusLog(LOG_ERR,
               "unable to allocate input buffer for sha1 calculation\n");

   if (fp == NULL)
      return -1;

   SHA1Init(&ctx);
   do {
      len = fread(buf, 1, SHA1_INPUT_BUFLEN, fp);
      SHA1Update(&ctx, buf, len);
   } while (len > 0);
   ArgusFree(buf);

   if (ferror(fp)) {
      fclose(fp);
      return -1;
   }

   fclose(fp);
   SHA1Final(hash, &ctx);
   return 0;
}

static int
__should_upload(const configuration_t * const config)
{
   /* If an authentication type is specified (only SPNEGO supported now),
    * then no username or password is required because it's integral to
    * the authentication method.  Otherwise, those are required.
    */
   if (!config->upload_auth && (!config->upload_user || !config->upload_pass))
      return 0;

#ifdef HAVE_LIBCARES
   /* If configured to look up a service record in DNS, make sure
    * we got one.
    */
   if (config->upload_use_dns && config->upload_use_dns_domain)
      if (ares_state != LIBCARES_DONE || !ares_srv_hostname)
         return 0;
#endif

   return 1;
}

static int
__upload_init(CURL **hnd, const configuration_t * const config)
{
   char *userpwd;
   int slen;

#ifdef HAVE_LIBCURL
   long auth = 0;
#endif

# ifdef ARGUS_CURLEXE
   char *authStr = "";
#endif

#ifdef HAVE_LIBCURL
   /* with libcurl we don't need to re-initialize anything */
   if (*hnd != NULL)
      return 0;
#endif

   userpwd = ArgusMalloc(NAME_MAX);
   if (userpwd == NULL)
      ArgusLog(LOG_ERR,
               "unable to allocate memory for http username:password\n");

   /* Curl on Windows will derive authentication information from the
    * environment if both username and password are empty strings (the
    * resulting userpwd points to ":").  When running as a service,
    * the host kerberos principle is used.
    */

   slen = snprintf(userpwd, NAME_MAX, "%s:%s",
                   config->upload_user ? config->upload_user : "",
                   config->upload_pass ? config->upload_pass : "");
   if (slen >= NAME_MAX) {
      ArgusLog(LOG_WARNING, "username:password combination too long\n");
      ArgusFree(userpwd);
      return -1;
   }

#ifdef HAVE_LIBCURL
   if (config->upload_auth && (strcasecmp(config->upload_auth, "spnego") == 0))
      auth = CURLAUTH_GSSNEGOTIATE;
   else
   if (config->upload_auth && (strcasecmp(config->upload_auth, "digest") == 0))
      auth = CURLAUTH_DIGEST;

   *hnd = curl_easy_init();
   if (*hnd == NULL) {
      ArgusFree(userpwd);
      return -1;
   }

   DEBUGLOG(4, "user pass string '%s'\n", userpwd);

   if (auth)
      curl_easy_setopt(*hnd, CURLOPT_HTTPAUTH, auth);
   curl_easy_setopt(*hnd, CURLOPT_USERPWD, userpwd);

   curl_easy_setopt(*hnd, CURLOPT_SSL_VERIFYPEER, 0L);
   curl_easy_setopt(*hnd, CURLOPT_SSL_VERIFYHOST, 0L);
   curl_easy_setopt(*hnd, CURLOPT_TCP_KEEPALIVE, 1L);
   curl_easy_setopt(*hnd, CURLOPT_WRITEFUNCTION, RamanageLibcurlWriteCallback);
   curl_easy_setopt(*hnd, CURLOPT_UPLOAD, 1L);

# ifdef ARGUSDEBUG
   curl_easy_setopt(*hnd, CURLOPT_DEBUGFUNCTION, __trace);
   curl_easy_setopt(*hnd, CURLOPT_VERBOSE, 1L);
# endif /* ARGUSDEBUG */

#else	/* HAVE_LIBCURL */
   ramanage_str_t *rstr;
   char * const curlexe =
# ifdef ARGUS_CURLEXE
      __shell_escape(ARGUS_CURLEXE)
# else
      strdup("curl")
# endif
   ;

   if (curlexe == NULL)
      ArgusLog(LOG_ERR, "unable to copy curl executable name\n");

   rstr = *hnd;
   if (rstr == NULL) {
      *hnd = rstr = ArgusMalloc(sizeof(*rstr));
      if (rstr == NULL)
         ArgusLog(LOG_ERR,
                  "unable to allocate curl commandline string struct\n");

      rstr->str = ArgusMalloc(PATH_MAX);
      if (rstr == NULL)
         ArgusLog(LOG_ERR, "unable to allocate curl commandline string\n");
   }

   rstr->remain = PATH_MAX;
   rstr->len = 0;

# ifdef ARGUS_CURLEXE
   if (config->upload_auth && (strcasecmp(config->upload_auth, "spnego") == 0)) {
      authStr = "--negotiate";
      auth = 1;
   } else
   if (config->upload_auth && (strcasecmp(config->upload_auth, "digest") == 0)) {
      authStr = "--digest";
      auth = 1;
   }

   slen = snprintf_append(rstr->str, &rstr->len, &rstr->remain,
                          "%s --fail --silent --show-error -k -u %s %s > /dev/null",
                          curlexe, userpwd, auth ? authStr : "");
#endif
   free(curlexe);
   if (slen >= PATH_MAX) {
      ArgusFree(userpwd);
      ArgusLog(LOG_WARNING, "curl commandline (partial) too long\n");
      return -1;
   }
#endif	/* HAVE_LIBCURL */

   ArgusFree(userpwd);
   return 0;
}

/* returns:
 *   0 on success
 *   > 0 if failure reported by libcurl (CURLcode)
 *   < 0 if web server response indicates failure
 */
static int
__upload(CURL *hnd, const char * const filename, off_t filesz,
         const configuration_t * const config)
{
#ifdef HAVE_LIBCURL
   CURLcode ret;
   long response_code;
#else
   int ret;
#endif
   FILE *fp;
   char *upload_dir;
   char *url;
   char *dest;
   int slen;
   int af;
   struct sockaddr_in *addr4;
   struct sockaddr_in6 *addr6;
   void *src;
   char sha1hash[SHA1_RESULTLEN];
   char sha1txt[SHA1_RESULTLEN*2+1];
   int i;

   if (__sha1(filename, sha1hash) < 0) {
      ArgusLog(LOG_WARNING, "Unable to calculate SHA1 for file %s\n",
               filename);
      return -1;
   }
   for (i = 0; i < 20; i++)
      sprintf(&sha1txt[i*2], "%02x", sha1hash[i] & 0xff);

   fp = fopen(filename, "rb");
   if (fp == NULL) {
      ArgusLog(LOG_WARNING, "Unable to open file %s for upload (%s)\n",
               filename, strerror(errno));
      return -1;
   }

   url = ArgusMalloc(PATH_MAX);
   if (url == NULL)
      ArgusLog(LOG_ERR, "unable to allocate memory for url\n");

   if (!config->upload_use_dns || !config->upload_use_dns_domain) {
      dest = ArgusMalloc(INET6_ADDRSTRLEN);
      if (dest == NULL)
         ArgusLog(LOG_ERR, "unable to allocate memory for destination name\n");
      af = config->upload_server.ss_family;
      addr4 = (struct sockaddr_in *)&config->upload_server;
      addr6 = (struct sockaddr_in6 *)&config->upload_server;

      if (af == AF_INET)
         src = &addr4->sin_addr;
      else
         src = &addr6->sin6_addr;

      if (!inet_ntop(config->upload_server.ss_family, src, dest, INET6_ADDRSTRLEN)) {
         ArgusLog(LOG_WARNING, "unable to format string from IP address\n");
         ret = -1;
         goto out;
      }
   } else {
#ifdef HAVE_LIBCARES
      af = 0;
      slen = snprintf(NULL, 0, "%s:%u", ares_srv_hostname, ares_srv_port);
      if (slen <= 0) {
         ArgusLog(LOG_WARNING, "unable for format string from SRV record\n");
         ret = -1;
         goto out;
      }
      dest = ArgusMalloc(slen+1);
      if (dest == NULL)
         ArgusLog(LOG_ERR, "unable to allocate memory for destination name\n");
      sprintf(dest, "%s:%u", ares_srv_hostname, ares_srv_port);
#else
      ret = -1;
      goto out;
#endif
   }

   upload_dir = config->upload_dir;
   while (upload_dir && *upload_dir == '/')
      upload_dir++;

   slen = snprintf(url, PATH_MAX, "https://%s%s%s/%s/%s",
                   af == AF_INET6 ? "[" : "",
                   dest,
                   af == AF_INET6 ? "]" : "",
                   upload_dir ? upload_dir : "",
                   sha1txt);
   ArgusFree(dest);
   if (slen >= PATH_MAX) {
      ArgusLog(LOG_WARNING, "upload URL too long\n");
      ret = -1;
      goto out;
   }
   if (slen < 0) {
      ArgusLog(LOG_WARNING, "error formatting upload URL\n");
      ret = -1;
      goto out;
   }

   DEBUGLOG(4, "uploading to %s\n", url);

#ifdef HAVE_LIBCURL
   /* set where to read from (on Windows you need to use READFUNCTION too) */
   curl_easy_setopt(hnd, CURLOPT_READDATA, fp);
   curl_easy_setopt(hnd, CURLOPT_INFILESIZE_LARGE, (curl_off_t)filesz);
   curl_easy_setopt(hnd, CURLOPT_URL, url);
   ret = curl_easy_perform(hnd);
   if (ret != CURLE_OK)
      goto out;

   curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &response_code);
   if (response_code < 200 || response_code >= 300)
      ret = -1 * response_code;
   DEBUGLOG(4, "http response code %d\n", response_code);
#else
   ramanage_str_t *rstr = hnd;
   size_t rem = rstr->remain;
# ifdef CYGWIN
   char *winpath = ArgusCygwinConvPath2Win(filename);
# else
#ifdef ARGUS_CURLEXE
   char *escaped = __shell_escape(filename);
# else
   char *escaped = NULL;
#endif
# endif /* CYGWIN */

   slen = snprintf_append(rstr->str, &rstr->len, &rstr->remain, " -T \"%s\" %s",
# ifdef CYGWIN
                          winpath,
# else
                          escaped,
#endif
                          url);
   if (slen < 0) {
      ArgusLog(LOG_WARNING,
               "failed to add upload option to curl commandline\n");
      ret = -1;
   } else if ((size_t)slen >= rem) {
      ArgusLog(LOG_WARNING, "curl commandline too long (%d > %u)\n",
               slen, rem);
      ret = -1;
   } else {
      DEBUGLOG(4, "cmd: %s\n", rstr->str);
      ret = system(rstr->str);
      if (WEXITSTATUS(ret) > 0) {
         DEBUGLOG(1, "curl command failed, returned %d.  (%s)\n", ret, rstr->str);
         ret = -ret; /* child process failed */
      }
   }
# ifdef CYGWIN
   ArgusFree(winpath);
# else
   free(escaped);
# endif /* CYGWIN */
#endif /* HAVE_LIBCURL */

out:
   ArgusFree(url);
   fclose(fp);
   return (int)ret;
}

/* move a file from the archive directory to the staging directory.
 * Preserve path elements beyond the configured archive directory.
 */
static int
__upload_move_to_staging(const char * const filename,
                         const configuration_t * const config)
{
   char *bn;
   char *newname;
   char *filename_cpy;
   char *dirname_cpy;
   int slen;
   int ret = 0;
   size_t path_archive_len;

   if (config->path_staging == NULL)
      return -1;

   path_archive_len = strlen(config->path_archive);
   if (*(config->path_archive + path_archive_len) == '/')
      path_archive_len--;

   filename_cpy = strdup(filename);
   if (filename_cpy == NULL)
      ArgusLog(LOG_ERR, "unable to copy filename\n");

   bn = filename_cpy + path_archive_len;
   /* skip over any leading path separators */
   while (*bn == '/')
      bn++;

   newname = ArgusMalloc(PATH_MAX);
   if (newname == NULL)
      ArgusLog(LOG_ERR,
               "unable to allocate memory for filename in staging directory\n");

   slen = snprintf(newname, PATH_MAX, "%s/%s", config->path_staging, bn);
   if (slen >= PATH_MAX) {
      ArgusLog(LOG_WARNING, "filename in staging directory too long\n");
      ret = -1;
      goto out;
   }

   dirname_cpy = strdup(newname);
   if (dirname_cpy == NULL) {
      ArgusLog(LOG_ERR, "unable to copy directory name\n");
   }
   /* ArgusMkdirPath() removes the filename from the path */
   ArgusMkdirPath(dirname_cpy);
   free(dirname_cpy);

   ret = rename(filename, newname);
   if (ret < 0) {
      int ret2;

      ArgusLog(LOG_WARNING,
               "unable to rename %s -> %s (%s)  removing instead\n",
               filename, newname, strerror(errno));
      ret2 = unlink(filename);
      if (ret2 < 0)
         ArgusLog(LOG_WARNING, "unable to remove %s (%s)\n", filename,
                  strerror(errno));
   }

out:
   free(filename_cpy);
   ArgusFree(newname);
   return ret;
}

static void
__upload_done(CURL **hnd)
{
#ifdef HAVE_LIBCURL
   curl_easy_cleanup(*hnd);
#else
   ArgusFree(*hnd);
#endif	/* HAVE_LIBCURL */
   *hnd = NULL;
}

static int
RamanageConfigureParse(struct ArgusParserStruct *parser,
                       int linenum, char *optarg, int quoted,
                       int idx)
{
   int retn = -1;

   switch (idx) {
      case RAMANAGE_LOCK_FILE:
         retn = __parse_str(optarg, &global_config.lockfile, PATH_MAX);
         break;
      case RAMANAGE_COMPRESS_EFFORT:
         retn = __parse_uint(optarg, &global_config.compress_effort);
         if (retn == 0 && global_config.compress_effort > 9) {
            ArgusLog(LOG_WARNING, "RAMANAGE_COMPRESS_EFFORT must be <= 9\n");
            retn = -1;
         }
         break;
      case RAMANAGE_COMPRESS_METHOD:
         retn = __parse_str(optarg, &global_config.upload_dir, NAME_MAX);
         if (retn == 0 && strcasecmp(global_config.upload_dir, "gzip") != 0) {
            ArgusLog(LOG_WARNING, "only gzip compression is supported\n");
            retn = -1;
         }
         break;
      case RAMANAGE_COMPRESS_MAX_KB:
         retn = __parse_uint(optarg, &global_config.compress_max_kb);
         break;
      case RAMANAGE_UPLOAD_USE_DNS:
         retn = __parse_yesno(optarg, &global_config.upload_use_dns);
         break;
      case RAMANAGE_UPLOAD_USE_DNS_DOMAIN:
         retn = __parse_str(optarg, &global_config.upload_use_dns_domain, PATH_MAX);
         break;
      case RAMANAGE_UPLOAD_SERVER:
         retn = __parse_network_address(optarg, &global_config.upload_server);
         break;
      case RAMANAGE_UPLOAD_DIR:
         retn = __parse_str(optarg, &global_config.upload_dir, PATH_MAX);
         break;
      case RAMANAGE_UPLOAD_USER:
         retn = __parse_str(optarg, &global_config.upload_user, NAME_MAX);
         break;
      case RAMANAGE_UPLOAD_PASS:
         retn = __parse_str(optarg, &global_config.upload_pass, NAME_MAX);
         break;
      case RAMANAGE_UPLOAD_AUTH:
         retn = __parse_str(optarg, &global_config.upload_auth, NAME_MAX);
         if ((retn == 0) && ((strcasecmp(global_config.upload_auth, "spnego") != 0) &&
                             (strcasecmp(global_config.upload_auth, "digest") != 0))) {
            ArgusLog(LOG_WARNING, "only spnego,digest authentication are supported\n");
            retn = -1;
         }
         break;
      case RAMANAGE_UPLOAD_MAX_KB:
         retn = __parse_uint(optarg, &global_config.upload_max_kb);
         break;
      case RAMANAGE_UPLOAD_DELAY_USEC:
         retn = __parse_uint(optarg, &global_config.upload_delay_usec);
         break;
      case RAMANAGE_PATH_ARCHIVE:
         retn = __parse_str(optarg, &global_config.path_archive, PATH_MAX);
         if (retn == 0)
            __chomp(global_config.path_archive, '/');
         break;
      case RAMANAGE_PATH_STAGING:
         retn = __parse_str(optarg, &global_config.path_staging, PATH_MAX);
         if (retn == 0)
            __chomp(global_config.path_archive, '/');
         break;
      case RAMANAGE_ARCHIVE_STRATEGY:
         retn = __parse_str(optarg, &global_config.archive_strategy, PATH_MAX);
         if (retn == 0)
            __chomp(global_config.archive_strategy, '/');
         break;
      case RAMANAGE_TIME_STRING:
         retn = __parse_str(optarg, &global_config.time_arg, PATH_MAX);
         if (retn == 0)
            __chomp(global_config.time_arg, '/');
         break;
      case RAMANAGE_RPOLICY_DELETE_AFTER:
         retn = __parse_uint(optarg, &global_config.rpolicy_delete_after);
         break;
      case RAMANAGE_RPOLICY_COMPRESS_AFTER:
         retn = __parse_uint(optarg, &global_config.rpolicy_compress_after);
         break;
      case RAMANAGE_RPOLICY_MAX_KB:
         retn = __parse_uint(optarg, &global_config.rpolicy_max_kb);
         break;
      case RAMANAGE_RPOLICY_MIN_DAYS:
         retn = __parse_uint(optarg, &global_config.rpolicy_min_days);
         break;
      case RAMANAGE_RPOLICY_IGNORE_ARCHIVE:
         retn = __parse_yesno(optarg, &global_config.rpolicy_ignore_archive);
         break;
      case RAMANAGE_PROCESS_ARCHIVE_PERIOD:
         retn = __parse_uint(optarg, &global_config.process_archive_period);
         break;
      case RAMANAGE_CMD_COMPRESS:
         retn = __parse_yesno(optarg, &global_config.cmd_compress);
         break;
      case RAMANAGE_CMD_UPLOAD:
         retn = __parse_yesno(optarg, &global_config.cmd_upload);
         break;
      case RAMANAGE_CMD_DELETE:
         retn = __parse_yesno(optarg, &global_config.cmd_remove);
         break;
      case RAMANAGE_DEBUG_LEVEL:
         retn = __parse_uint(optarg, &global_config.debug_level);
         ArgusParser->debugflag = global_config.debug_level;
         break;
   }

   if (retn)
      ArgusLog(LOG_ERR, "parse error line %d\n", linenum);

   return 0;
}

static int
RamanageConfigure(struct ArgusParserStruct * const parser,
                  configuration_t *config)
{
   struct stat statbuf;
#if defined(CYGWIN) || defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
   HKEY hkey; /* used by Windows systems to read config values */
#endif

   if (noconf == 0 && stat(SYSCONFDIR "/ramanage.conf", &statbuf) == 0) {
      RaParseResourceFile(parser, SYSCONFDIR "/ramanage.conf",
                          ARGUS_SOPTIONS_IGNORE, RamanageResourceFileStr,
                          RAMANAGE_RCITEMS, RamanageConfigureParse);
   }

   if (parser->ArgusFlowModelFile != NULL) {
      RaParseResourceFile(parser, parser->ArgusFlowModelFile,
                          ARGUS_SOPTIONS_IGNORE, RamanageResourceFileStr,
                          RAMANAGE_RCITEMS, RamanageConfigureParse);

   }

#if defined(CYGWIN) || defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
   if (noconf == 0 &&
       ArgusWindowsRegistryOpenKey(ARGUS_CLIENTS_REGISTRY_HKEY,
                                   ARGUS_CLIENTS_REGISTRY_KEYNAME "\\ramanage",
                                   &hkey) == 0) {
      __fetch_registry_values(hkey, config);
      ArgusWindowsRegistryCloseKey(hkey);
   }
#endif

#ifndef HAVE_LIBCARES
   if (config->upload_use_dns)
      ArgusLog(LOG_WARNING,
               "RAMANAGE_UPLOAD_USE_DNS=yes, but no c-ares support.\n");
#endif

   return 0;
}


#ifdef HAVE_ZLIB_H
static int
RamanageCompress(const struct ArgusParserStruct * const parser,
                 struct ArgusFileInput **filvec, size_t filcount,
                 const configuration_t * const config)
{
   static const size_t buflen = 32*1024;
   struct ArgusFileInput *file;
   time_t when; /* files older than this are compressed */
   char *gzfilename;
   char *origfilename;
   unsigned char *buf;
   int gzerr;
   struct utimbuf ut;
   unsigned int compress_kb = 0;
   size_t i;


   gzfilename = ArgusMalloc(PATH_MAX);
   if (gzfilename == NULL)
      ArgusLog(LOG_ERR, "unable to allocate memory for gzip filename\n");

   buf = ArgusMalloc(buflen);
   if (buf == NULL)
      ArgusLog(LOG_ERR, "unable to allocate memory for gzip buffer\n");

   when = __days_ago(&parser->ArgusRealTime, config->rpolicy_compress_after);
   i = 0;
   while (i < filcount && compress_kb <= config->compress_max_kb) {
      file = filvec[i];
      if (__file_older_than(file, when)) {
         int slen;

         slen = snprintf(gzfilename, PATH_MAX, "%s.gz", file->filename);
         if (slen >= PATH_MAX) {
            ArgusLog(LOG_WARNING, "filename too long with .gz extension: %s\n",
                     file->filename);
            i++;
            continue;
         }
         DEBUGLOG(4, "compress file %s -> %s\n", file->filename, gzfilename);

         gzerr = __gzip(file->filename, gzfilename, file->statbuf.st_size,
                        buf, buflen);

         if (gzerr) {
            i++;
            continue;
         }

         compress_kb += file->statbuf.st_size / 1024;

         /* Make the new gzip file's attributes look like those of the
          * original file.  Copy timestamps, ownerhip and permissions
          * to the new file.  Then remove the original, uncompressed,
          * file and update the filename and attributes in the linked
          * list so that subsequent ramanage commands operate on the
          * gzip file.
          */

         ut.actime = file->statbuf.st_atime;
         ut.modtime = file->statbuf.st_mtime;
         if (utime(gzfilename, &ut) < 0)
            ArgusLog(LOG_WARNING, "failed to update timestamp on file %s\n",
                     gzfilename);
         if (chmod(gzfilename, file->statbuf.st_mode) < 0)
            ArgusLog(LOG_WARNING,
                     "failed to update permissions on file %s\n", gzfilename);
         if (chown(gzfilename, file->statbuf.st_uid, file->statbuf.st_gid) < 0)
            ArgusLog(LOG_WARNING, "failed to update ownership of file %s\n",
                     gzfilename);
         origfilename = file->filename;
         file->filename = strdup(gzfilename);
         if (file->filename == NULL)
            ArgusLog(LOG_ERR, "unable to update filename in list\n");
         if (stat(file->filename, &file->statbuf) < 0 )
            ArgusLog(LOG_ERR, "unable to stat new gzip file\n");
         unlink(origfilename);
         free(origfilename);

      }
      i++;
   }

   ArgusFree(gzfilename);
   ArgusFree(buf);
   return 0;
}
#endif

static int
RamanageUpload(const struct ArgusParserStruct * const parser,
               struct ArgusFileInput **filvec, size_t filcount,
               const configuration_t * const config)
{
#ifdef HAVE_LIBCURL
   CURL *hnd;
#else
   ramanage_str_t *hnd;
#endif
   struct ArgusFileInput *file;
   unsigned int upload_kb = 0;
   int res, done = 0;
   size_t i;

   if (!__should_upload(config)) {
      DEBUGLOG(1, "will not upload now.\n");
      return 0;
   }

   i = 0;
   hnd = NULL;
   while (!done && (i < filcount && upload_kb <= config->upload_max_kb)) {
      if (__upload_init(&hnd, config) < 0) {
         ArgusLog(LOG_WARNING, "unable to initialize libcurl\n");
         return -1;
      }

      file = filvec[i];
      DEBUGLOG(4, "upload file %s size %u\n", file->filename, file->statbuf.st_size);
      res = __upload(hnd, file->filename, file->statbuf.st_size, config);
      if (res == 0) {
         DEBUGLOG(4, "move file %s to staging area\n", file->filename);
         __upload_move_to_staging(file->filename, config);
      } else if (res > 0) {
#ifdef HAVE_LIBCURL
         ArgusLog(LOG_WARNING, "libcurl: %s", curl_easy_strerror(res));
#else
         ArgusLog(LOG_WARNING, "error: %s", strerror(errno));
#endif
         done = 1;
      } else {
         ArgusLog(LOG_WARNING, "received non-success code from server (%d)\n", -1 * res);
         done = 1;
      }
      upload_kb += file->statbuf.st_size / 1024;
      i++;
   }

   if (upload_kb > config->upload_max_kb)
      ArgusLog(LOG_WARNING, "upload reached data limit %u KB\n",
               config->upload_max_kb);

   __upload_done(&hnd);
   return 0;
}

static int
__check_path(const char * const path)
{
   size_t len = strlen(path);
   char *rp;

   if (*path != '/' || len < 2)
      return -1;

   rp = realpath(path, NULL);
   if (rp == NULL)
      return -1;

   /* don't count the trailing slash if present */
   if (len > 2 && *(path+len-1) == '/')
      len--;

   /* is canonical?  no relative path elements, symlinks, etc. */
   if (strncmp(path, rp, len)) {
      free(rp);
      return -1;
   }

   free(rp);
   return (int)len;
}

/* prereq: archive and staging paths have already been checked
 * Make sure the filename lives in either the archive or the
 * staging directory.  Expand any relative path elements and
 * follow symlinks before comparing so that we don't accidentally
 * accept something like /path/to/archive/../../somewhere/else.
 */
static int
__check_filename(const char * const filename,
                 int path_archive_len, int path_staging_len,
                 const configuration_t * const config)
{
   char *rp;
   int rplen;
   int rv = -1;

   rp = realpath(filename, NULL);
   if (rp == NULL)
      goto out;
   rplen = strlen(rp);

   if (rplen > (path_archive_len+1) &&
       *(filename+path_archive_len) == '/' &&
       *(filename+path_archive_len+1) != '/' &&
       strncmp(rp, config->path_archive, path_archive_len) == 0)
      rv = 0;
   else if (path_staging_len > 0 &&
            rplen > (path_staging_len+1) &&
            *(filename+path_staging_len) == '/' &&
            *(filename+path_staging_len+1) != '/' &&
            strncmp(rp, config->path_staging, path_staging_len) == 0)
      rv = 0;

   free(rp);
out:
   if (rv == -1) {
      DEBUGLOG(4, "%s: %s: wrong directory\n", __func__,
         filename);
   }
   return rv;
}

static int
RamanageRemove(const struct ArgusParserStruct * const parser,
               struct ArgusFileInput **filvec, size_t filcount,
               const configuration_t * const config)
{
   struct ArgusFileInput *file;
   time_t when; /* files older than this are removed */
   size_t i;

   /* unconfigured removal policy is ignored */
   if (config->rpolicy_delete_after == 0)
      return 0;

   i = 0;
   when = __days_ago(&parser->ArgusRealTime, config->rpolicy_delete_after);
   while (i < filcount) {
      file = filvec[i];
      if (__file_older_than(file, when)) {
         DEBUGLOG(4, "remove file %s\n", file->filename);
         unlink(file->filename);
      }
      i++;
   }
   return 0;
}

static int
RamanageCheckPaths(const struct ArgusParserStruct * const parser,
                   const configuration_t * const config)
{
   struct ArgusFileInput *file;
   int path_archive_len, path_staging_len = 0;
   int rv = 0;

   /* archive directory must be in configuration file.  "", "/" and "." are
    * not acceptable.
    */
   if (config->path_archive == NULL) {
      ArgusLog(LOG_WARNING,
               "refusing to process file without defined archive directory.\n");
      return -1;
   }

   path_archive_len = __check_path(config->path_archive);
   if (path_archive_len < 0) {
      ArgusLog(LOG_WARNING,
               "refusing to process files; archive directory must be canonical.\n");
      return -1;
   }

   if (config->path_staging) {
      path_staging_len = __check_path(config->path_staging);
      if (path_staging_len < 0) {
         ArgusLog(LOG_WARNING,
                  "refusing to process files; staging directory must be canonical.\n");
         return -1;
      }
   }

   file = (struct ArgusFileInput *)parser->ArgusInputFileList;
   while (file && rv == 0) {
      if (file->statbuf.st_mtime == 0) {
         /* If the modification time is zero, we were unable to stat the
          * file.  The most likely cause is that another instance of
          * ramange already compressed/uploaded/deleted this file.
          * Mention this in the debug log and keep going.
          */
         DEBUGLOG(2, "%s skip missing file \"%s\"\n", __func__, file->filename);
      } else {
         rv = __check_filename(file->filename, path_archive_len,
                               path_staging_len, config);
         if (rv < 0)
            ArgusLog(LOG_WARNING,
                     "%s: not processing file %s; wrong directory\n", __func__,
                     file->filename);
      }
      file = (struct ArgusFileInput *)file->qhdr.nxt;
   }

   return rv;
}

static int
__compare_argus_input_file_mtime(const void *a, const void *b)
{
   const struct ArgusFileInput * const *aa = a;
   const struct ArgusFileInput * const *bb = b;

   /* NULL is always > !NULL so that it ends of at the end of the array */
   if (*aa == NULL)
      return 1;
   if (*bb == NULL)
      return -1;

   if ((*aa)->statbuf.st_mtime < (*bb)->statbuf.st_mtime)
      return -1;
   return 1;
}

/* Return an array of pointers into the file list, sorted by
 * modification time.  Do not add files to the array that
 * are missing (stat failed) or that are the file given to
 * the -r parameter.
*/
static size_t
RamanageSortFiles(const struct ArgusParserStruct * const parser,
                  struct ArgusFileInput *exemplar,
                  struct ArgusFileInput **filvec)
{
   struct ArgusFileInput *tmp;
   size_t i;
   size_t off;

   if (parser->ArgusInputFileCount == 0)
      return 0;

   tmp = parser->ArgusInputFileList;
   for (i = 0, off = 0; i < parser->ArgusInputFileCount; i++) {
      if (tmp->statbuf.st_mtime != 0
          && (exemplar == NULL
              || tmp->statbuf.st_ino != exemplar->statbuf.st_ino)) {
         *(filvec+off) = tmp;
         off++;
      } else {
         DEBUGLOG(2, "%s skipping file %s\n", __func__, tmp->filename);
      }
      tmp = (struct ArgusFileInput *)tmp->qhdr.nxt;
   }

   qsort(filvec, off, sizeof(*filvec), __compare_argus_input_file_mtime);

   return off;
}

/* Append whatever files we found in the staging directory to the filvec,
 * but DO NOT sort the resulting array since the only thing done after
 * this is removal of old files.  RamanageRemove() does not assume the
 * array is sorted and will walk the entire contents.
 */
static struct ArgusFileInput **
RamanageAppendStagingFiles(const struct ArgusParserStruct * const parser,
                           struct ArgusFileInput **filvec,
                           size_t *filcount, size_t filindex,
                           const configuration_t * const config)
{
   struct ArgusFileInput *tmp;
   struct ArgusFileInput **newvec = filvec;
   size_t prev_length = *filcount;
   size_t i;

   DEBUGLOG(1, "%s: adding files from staging directory\n", __func__);
   if (RaProcessArchiveFiles(config->path_staging, ARGUS_FILES_NOSORT) == 0) {
      DEBUGLOG(1, "%s: unable to add files from staging directory (%s)\n",
               __func__, config->path_staging);
   }

   newvec = ArgusRealloc(filvec, (parser->ArgusInputFileCount+1) * sizeof(*filvec));
   if (newvec == NULL) {
      ArgusLog(LOG_INFO, "unable to allocate memory for file array\n");
      return NULL;
   }

   tmp = parser->ArgusInputFileList;
   for (i = 0; i < parser->ArgusInputFileCount; i++) {
      if (i >= prev_length)           /* if past the existing file structures . . . */
         *(newvec+i+filindex) = tmp;  /* array data is offset by "filindex" entries */
      tmp = (struct ArgusFileInput *)tmp->qhdr.nxt;
   }

   DEBUGLOG(2, "%s: added %u files\n", __func__,
            (size_t)parser->ArgusInputFileCount - prev_length);

   /* NOTE: filevec/newvec is NOT sorted after appending the staged files */
   *filcount += (parser->ArgusInputFileCount - prev_length);
   return newvec;
}

/* prereq: filvec must be sorted in order of increasing
 * modification time.
 * returns: the number of files trimmed from the array
 */
static size_t
RamanageTrimFiles(size_t filcount,
                  struct ArgusFileInput *exemplar,
                  struct ArgusFileInput **filvec)
{
   size_t i;
   size_t trimmed = 0;

   if (exemplar == NULL || filcount < 1)
      return 0;

   i = filcount - 1;

   /* while filvec[i] is newer than, or the same as, the file
    * specified on the command line
    */
   while (i > 0 && __compare_argus_input_file_mtime(&filvec[i], &exemplar) == 1) {
      DEBUGLOG(6, "trimming %s\n", filvec[i]->filename);
      filvec[i] = NULL;
      trimmed++;
      i--;
   }

   if (i == 0 && __compare_argus_input_file_mtime(&filvec[i], &exemplar) == 1) {
      DEBUGLOG(6, "trimming 0-file %s\n", filvec[0]->filename);
      filvec[0] = NULL;
      trimmed++;
   }

   return trimmed;
}

void ArgusClientInit (struct ArgusParserStruct *parser) { return; }
void RaArgusInputComplete (struct ArgusInput *input) { return; }
void RaParseComplete (int sig) { return; }
void ArgusClientTimeout (void) { return; }
void usage (void) { return; }
void RaProcessRecord (struct ArgusParserStruct *parser, struct ArgusRecordStruct *argus) { return; }
int RaSendArgusRecord(struct ArgusRecordStruct *argus) { return 0; }
void ArgusWindowClose(void) { return; }


int
main(int argc, char **argv)
{
   struct ArgusParserStruct *parser = NULL;
   ArgusLockContext lockctx;
   struct ArgusModeStruct *mode;
   struct ArgusFileInput **filvec = NULL;
   struct ArgusFileInput *exemplar;
   size_t trimmed;
   size_t filcount;

   /* index into filvec[] of first existing file: assume no -r option
    * given and therefor filvec[0] == NULL
    */
   size_t filindex = 1;

   int process_archive = 0;
   int cmdmask = 0;
   int cmdres = 0;
   int i;

   for (i = 1; i < argc; i++) {
      if (argv[i][0] == '-' && argv[i][1] == 'X') {
         noconf++;
      }
   }


   if ((parser = ArgusNewParser(argv[0])) != NULL) {
      ArgusParser = parser;
      ArgusMainInit (parser, argc, argv);
   }

   if (parser->ArgusInputFileCount > 1)
      ArgusLog(LOG_ERR, "Need at most *one* source file (-r)\n");
   exemplar = (struct ArgusFileInput *)parser->ArgusInputFileList;

   if ((mode = parser->ArgusModeList) != NULL) {
      while (mode) {

         if (strcmp(mode->mode, "compress") == 0)
            cmdmask |= RAMANAGE_CMDMASK_COMPRESS;
         else if (strcmp(mode->mode, "upload") == 0)
            cmdmask |= RAMANAGE_CMDMASK_UPLOAD;
         else if (strcmp(mode->mode, "remove") == 0)
            cmdmask |= RAMANAGE_CMDMASK_REMOVE;
         else
            ArgusLog(LOG_ERR, "Unknown command \"%s\"\n", mode->mode);
         mode = mode->nxt;
      }
   }

   cmdres = RamanageConfigure(parser, &global_config);
   if (cmdres)
      goto out;

   if (global_config.cmd_compress)
      cmdmask |= RAMANAGE_CMDMASK_COMPRESS;
   if (global_config.cmd_upload)
      cmdmask |= RAMANAGE_CMDMASK_UPLOAD;
   if (global_config.cmd_remove)
      cmdmask |= RAMANAGE_CMDMASK_REMOVE;

   if (cmdmask == 0)
      ArgusLog(LOG_ERR, "need at least one command\n");

#ifdef HAVE_LIBCURL
   curl_global_init(CURL_GLOBAL_ALL);
#endif
#ifdef HAVE_LIBCARES
   if (RamanageInitLibcares(&global_config) < 0)
      ArgusLog(LOG_ERR, "failed to initialize query for service record\n");
#endif

   __random_delay_init();
   __random_delay(0, global_config.upload_delay_usec);

   if (global_config.lockfile) {
      if (ArgusCreateLockFile(global_config.lockfile, 0, &lockctx) < 0) {
         cmdres = 1;
         ArgusLog(LOG_WARNING, "unable to create lock file\n");
         goto out_nolock;
      }
   }

   if ((global_config.rpolicy_ignore_archive == 0) &&
       (__should_process_archive(&global_config) == 1)) {
      DEBUGLOG(1, "%s: adding files from archive directory\n", __func__);
      if (RaProcessArchiveFiles(global_config.path_archive, ARGUS_FILES_NOSORT) == 0) {
         cmdres = 1;
         goto out;
      }

//    used later to decide if we should also process staged files 
      process_archive = 1;
      __save_state();
   }

   if (RamanageCheckPaths(parser, &global_config) < 0) {
      cmdres = 1;
      goto out;
   }

   /*
    * Allocate one extra entry in the file array so that the zeroeth
    * entry can remain empty until after the files are sorted and
    * the array trimmed.  Then the file specified on the command
    * line can be moved from the end to the beginning of the array
    * without disturbing the sorted order of anything else.
    */
   filvec = ArgusMalloc((parser->ArgusInputFileCount + 1) * sizeof(*filvec));
   if (filvec == NULL)
      ArgusLog(LOG_ERR, "unable to allocate memory for file array\n");

   filcount = RamanageSortFiles(parser, exemplar, filvec+1);

   /* The zeroeth element of the array has been left unused, so
    * let's put the file specified by the -r option there.
    */
   if (exemplar) {
      filvec[0] = exemplar;
      filcount++;
      filindex = 0;

      /* It is possible that another process already dealt with our primary
       * input file.  Update the statbuf for this one file here.
       */
      memset(&exemplar->statbuf, 0, sizeof(exemplar->statbuf));
      if (stat(exemplar->filename, &exemplar->statbuf) < 0)
         /* the file no longer exists - we're done */
         goto out;
   }

   /* remove files newer than the file we were asked to process.
    * Also remove the duplicate of that file in the list, which will be there
    * because of the recursive search of the archive directory.
    * This will avoid monkeying with the files that rastream still
    * has open.
    */
   trimmed = RamanageTrimFiles(exemplar ? filcount-1 : filcount, exemplar,
                               filvec+1);
   DEBUGLOG(1, "Trimmed %zu files from the array\n", trimmed);
   filcount -= trimmed;

#ifdef ARGUSDEBUG
   {
      size_t i;
      for (i = 0; i < filcount; i++)
         DEBUGLOG(6, "FILE[%4zu]: %s\n", i, filvec[i+filindex]->filename);
    }
#endif

#ifdef HAVE_LIBCARES
   if (global_config.cmd_upload && global_config.upload_use_dns) {
      cmdres = RamanageLibcaresProcess(&global_config);
      if (ares_state != LIBCARES_DONE) {
         ArgusLog(LOG_WARNING, "failed to look up service record\n");
         goto out;
      }
   }
#endif

#ifdef HAVE_ZLIB_H
   if (cmdmask & RAMANAGE_CMDMASK_COMPRESS) {
      cmdres = RamanageCompress(parser, &filvec[filindex], filcount,
                                &global_config);
      if (cmdres)
         goto out;
   }
#endif
   if (cmdmask & RAMANAGE_CMDMASK_UPLOAD) {
      cmdres = RamanageUpload(parser, &filvec[filindex], filcount,
                              &global_config);
      if (cmdres)
         goto out;
   }
   if (cmdmask & RAMANAGE_CMDMASK_REMOVE) {
      if (process_archive) {
         struct ArgusFileInput **tmp;

         /* RamanageAppendStagingFiles needs filvec, not &filvec[filindex]
          * because it will re-allocate the file array.
          */
         tmp = RamanageAppendStagingFiles(parser, filvec, &filcount,
                                          filindex, &global_config);
         if (tmp)
            filvec = tmp;
      }
      cmdres = RamanageRemove(parser, &filvec[filindex], filcount, &global_config);
      if (cmdres)
         goto out;
   }

out:
   if (global_config.lockfile) {
      if (ArgusReleaseLockFile(&lockctx) < 0) {
         cmdres = 1;
         goto out_nolock;
      }
   }

out_nolock:
#ifdef HAVE_LIBCARES
   RamanageCleanupLibcares();
#endif
   if (filvec)
      ArgusFree(filvec);
   return cmdres;
}
