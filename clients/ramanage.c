/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2018 QoSient, LLC
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
#include <stdlib.h> /* strtoul, realpath */
#include <sys/syslog.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <zlib.h>
#include <utime.h>
#include <libgen.h>
#include <unistd.h>

#include "argus_util.h"
#include "argus_client.h"
#include "argus_lockfile.h"
#include "argus_main.h"

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

   unsigned int compress_effort;
   unsigned int compress_method;
   unsigned int compress_max_kb;

   unsigned char upload_use_dns;
   char *upload_user;
   char *upload_pass;
   char *upload_dir;
   struct sockaddr_storage upload_server;
   char *upload_auth;
   unsigned int upload_max_kb;

   unsigned int rpolicy_delete_after;
   unsigned int rpolicy_compress_after;
   unsigned int rpolicy_max_kb;
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

enum RamanageOpts {
   RAMANAGE_LOCK_FILE = 0,
   RAMANAGE_COMPRESS_EFFORT,
   RAMANAGE_COMPRESS_METHOD,
   RAMANAGE_COMPRESS_MAX_KB,
   RAMANAGE_UPLOAD_USE_DNS,
   RAMANAGE_UPLOAD_SERVER,
   RAMANAGE_UPLOAD_DIR,
   RAMANAGE_UPLOAD_USER,
   RAMANAGE_UPLOAD_PASS,
   RAMANAGE_UPLOAD_AUTH,
   RAMANAGE_UPLOAD_MAX_KB,
   RAMANAGE_PATH_ARCHIVE,
   RAMANAGE_PATH_STAGING,
   RAMANAGE_RPOLICY_DELETE_AFTER,
   RAMANAGE_RPOLICY_COMPRESS_AFTER,
   RAMANAGE_RPOLICY_MAX_KB,
   RAMANAGE_RPOLICY_MIN_DAYS,
   RAMANAGE_RPOLICY_IGNORE_ARCHIVE,
   RAMANAGE_CMD_COMPRESS,
   RAMANAGE_CMD_DELETE,
   RAMANAGE_CMD_UPLOAD,
};

static char *RamanageResourceFileStr[] = {
   "RAMANAGE_LOCK_FILE=",
   "RAMANAGE_COMPRESS_EFFORT=",
   "RAMANAGE_COMPRESS_METHOD=",
   "RAMANAGE_COMPRESS_MAX_KB=",
   "RAMANAGE_UPLOAD_USE_DNS=",
   "RAMANAGE_UPLOAD_SERVER=",
   "RAMANAGE_UPLOAD_DIR=",
   "RAMANAGE_UPLOAD_USER=",
   "RAMANAGE_UPLOAD_PASS=",
   "RAMANAGE_UPLOAD_AUTH=",
   "RAMANAGE_UPLOAD_MAX_KB=",
   "RAMANAGE_PATH_ARCHIVE=",
   "RAMANAGE_PATH_STAGING=",
   "RAMANAGE_RPOLICY_DELETE_AFTER=",
   "RAMANAGE_RPOLICY_COMPRESS_AFTER=",
   "RAMANAGE_RPOLICY_MAX_KB=",
   "RAMANAGE_RPOLICY_MIN_DAYS=",
   "RAMANAGE_RPOLICY_IGNORE_ARCHIVE=",
   "RAMANAGE_CMD_COMPRESS=",
   "RAMANAGE_CMD_DELETE=",
   "RAMANAGE_CMD_UPLOAD=",
};

static const size_t RAMANAGE_RCITEMS =
   sizeof(RamanageResourceFileStr)/sizeof(RamanageResourceFileStr[0]);

static configuration_t global_config;
struct ArgusParserStruct *ArgusParser;
static int noconf = 0;

static inline int
__file_older_than(const struct ArgusInput * const file, time_t when)
{
   return (file->statbuf.st_mtime <= when);
}

static inline time_t
__days_ago(const struct timeval * const now, unsigned int n)
{
   return (now->tv_sec - n*86400);
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
         ArgusLog(LOG_INFO, "skipping gzipped file %s\n", filename);
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

#ifdef HAVE_LIBCURL
# include <curl/curl.h>
#else
typedef void CURL;
#endif

#ifdef HAVE_LIBCURL
static int
__trace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
{
  (void)handle;	/* unused */
  (void)userp;	/* unused */
  (void)size;	/* unused */
  (void)userp;	/* unused */

   switch (type) {
      case CURLINFO_TEXT:
         ArgusLog(LOG_INFO, "libcurl: %s", data);
         break;
      default: /* in case a new one is introduced to shock us */
         break;
   }

  return 0;
}
#endif

static int
__should_upload(const configuration_t * const config)
{
   /* TODO: apply policy here to determine if this is the right time
    * to push data onto the collector.  Look for SRV record in DNS,
    * examine contents of managed files to look for particular context
    * (broadcast sources, next hop, dhcp requests, etc.)
    */
   return 1;
}

static int
__upload_init(CURL **hnd, const configuration_t * const config)
{
   char *userpwd;
   long auth = 0;
   int slen;

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
   if (config->upload_auth
       && strcasecmp(config->upload_auth, "spnego") == 0)
      auth = CURLAUTH_GSSNEGOTIATE;

   *hnd = curl_easy_init();
   if (*hnd == NULL) {
      ArgusFree(userpwd);
      return -1;
   }

   curl_easy_setopt(*hnd, CURLOPT_BUFFERSIZE, 102400L);
   curl_easy_setopt(*hnd, CURLOPT_NOPROGRESS, 1L);
   curl_easy_setopt(*hnd, CURLOPT_UPLOAD, 1L);
   curl_easy_setopt(*hnd, CURLOPT_USERPWD, userpwd);
   if (auth)
      curl_easy_setopt(*hnd, CURLOPT_HTTPAUTH, auth);
   curl_easy_setopt(*hnd, CURLOPT_USERAGENT, "ramanage");
   curl_easy_setopt(*hnd, CURLOPT_MAXREDIRS, 0L);
   curl_easy_setopt(*hnd, CURLOPT_SSL_VERIFYPEER, 0L);
   curl_easy_setopt(*hnd, CURLOPT_SSL_VERIFYHOST, 0L);
   curl_easy_setopt(*hnd, CURLOPT_TCP_KEEPALIVE, 1L);
   curl_easy_setopt(*hnd, CURLOPT_DEBUGFUNCTION, __trace);
#else	/* HAVE_LIBCURL */
   ramanage_str_t *rstr;

   *hnd = rstr = ArgusMalloc(sizeof(*rstr));
   if (rstr == NULL)
      ArgusLog(LOG_ERR, "unable to allocate curl commandline string struct\n");

   rstr->str = ArgusMalloc(PATH_MAX);
   if (rstr == NULL)
      ArgusLog(LOG_ERR, "unable to allocate curl commandline string\n");

   rstr->remain = PATH_MAX;
   rstr->len = 0;

   if (config->upload_auth
       && strcasecmp(config->upload_auth, "spnego") == 0)
      auth = 1;


   slen = snprintf_append(rstr->str, &rstr->len, &rstr->remain,
                          "curl --silent -k -u %s %s", userpwd,
                          auth ? "--negotiate" : "");
   if (slen >= PATH_MAX) {
      ArgusFree(userpwd);
      ArgusLog(LOG_WARNING, "curl commandline (partial) too long\n");
      return -1;
   }
#endif	/* HAVE_LIBCURL */

   ArgusFree(userpwd);
   return 0;
}

static int
__upload(CURL *hnd, const char * const filename, off_t filesz,
         const configuration_t * const config)
{
#ifdef HAVE_LIBCURL
   CURLcode ret;
#else
   int ret;
#endif
   FILE *fp;
   char *fncopy;
   char *upload_dir;
   char *url;
   char ipstr[INET6_ADDRSTRLEN];
   int slen;
   int af;
   struct sockaddr_in *addr4;
   struct sockaddr_in6 *addr6;
   void *src;

   fp = fopen(filename, "rb");
   if (fp == NULL) {
      ArgusLog(LOG_WARNING, "Unable to open file %s for upload (%s)\n",
               filename, strerror(errno));
      return -1;
   }

   url = ArgusMalloc(PATH_MAX);
   if (url == NULL)
      ArgusLog(LOG_ERR, "unable to allocate memory for url\n");

   /* TODO: fetch name/addr from DNS service record if so configured */

   af = config->upload_server.ss_family;
   addr4 = (struct sockaddr_in *)&config->upload_server;
   addr6 = (struct sockaddr_in6 *)&config->upload_server;

   if (af == AF_INET)
      src = &addr4->sin_addr;
   else
      src = &addr6->sin6_addr;

   if (!inet_ntop(config->upload_server.ss_family, src, ipstr, sizeof(ipstr))) {
      ArgusLog(LOG_WARNING, "unable to format string from IP address\n");
      ret = -1;
      goto out;
   }

   upload_dir = config->upload_dir;
   while (upload_dir && *upload_dir == '/')
      upload_dir++;

   fncopy = strdup(filename);
   if (fncopy == NULL)
      ArgusLog(LOG_ERR, "unable to allocate memory for filename copy\n");
   slen = snprintf(url, PATH_MAX, "https://%s%s%s/%s/%s",
                   af == AF_INET6 ? "[" : "",
                   ipstr,
                   af == AF_INET6 ? "]" : "",
                   upload_dir ? upload_dir : "",
                   basename(fncopy));
   free(fncopy);
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
#else
   ramanage_str_t *rstr = hnd;
   size_t rem = rstr->remain;

   slen = snprintf_append(rstr->str, &rstr->len, &rstr->remain, " -T %s %s",
                          filename, url);
   if (slen >= rstr->remain) {
      ArgusLog(LOG_WARNING, "curl commandline too long\n");
      ret = -1;
   }
   DEBUGLOG(4, "cmd: %s\n", rstr->str);
   ret = system(rstr->str);
   if (ret > 0) {
      ArgusLog(LOG_WARNING, "curl command failed, returned %d\n", ret);
      ret = -ret; /* child process failed */
   }
#endif

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

   ArgusMkdirPath(dirname(newname));

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
         if (retn == 0 &&
             strcasecmp(global_config.upload_auth, "spnego") != 0) {
            ArgusLog(LOG_WARNING, "only spnego authentication is supported\n");
            retn = -1;
         }
         break;
      case RAMANAGE_UPLOAD_MAX_KB:
         retn = __parse_uint(optarg, &global_config.upload_max_kb);
         break;
      case RAMANAGE_PATH_ARCHIVE:
         retn = __parse_str(optarg, &global_config.path_archive, PATH_MAX);
         break;
      case RAMANAGE_PATH_STAGING:
         retn = __parse_str(optarg, &global_config.path_staging, PATH_MAX);
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
      case RAMANAGE_CMD_COMPRESS:
         retn = __parse_yesno(optarg, &global_config.cmd_compress);
         break;
      case RAMANAGE_CMD_UPLOAD:
         retn = __parse_yesno(optarg, &global_config.cmd_upload);
         break;
      case RAMANAGE_CMD_DELETE:
         retn = __parse_yesno(optarg, &global_config.cmd_remove);
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
   return 0;
}

static int
RamanageCompress(const struct ArgusParserStruct * const parser,
                 struct ArgusInput **filvec, size_t filcount,
                 const configuration_t * const config)
{
   static const size_t buflen = 32*1024;
   struct ArgusInput *file;
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

static int
RamanageUpload(const struct ArgusParserStruct * const parser,
               struct ArgusInput **filvec, size_t filcount,
               const configuration_t * const config)
{
#ifdef HAVE_LIBCURL
   CURL *hnd;
#else
   ramanage_str_t *hnd;
#endif
   struct ArgusInput *file;
   unsigned int upload_kb = 0;
   int res;
   size_t i;

   if (!__should_upload(config)) {
      DEBUGLOG(1, "will not upload now.\n");
      return 0;
   }

   if (__upload_init(&hnd, config) < 0) {
      ArgusLog(LOG_WARNING, "unable to initialize libcurl\n");
      return -1;
   }

   i = 0;
   while (i < filcount && upload_kb <= config->upload_max_kb) {
      file = filvec[i];
      DEBUGLOG(4, "upload file %s size %u\n", file->filename,
               file->statbuf.st_size);
      res = __upload(hnd, file->filename, file->statbuf.st_size, config);
      if (res == 0) {
         upload_kb += file->statbuf.st_size / 1024;

         DEBUGLOG(4, "move file %s to staging area\n", file->filename);
         __upload_move_to_staging(file->filename, config);
      } else if (res > 0) {
#ifdef HAVE_LIBCURL
         ArgusLog(LOG_WARNING, "libcurl: %s", curl_easy_strerror(res));
#else
         ArgusLog(LOG_WARNING, "error: %s", strerror(errno));
#endif
      }
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
   return rv;
}

static int
RamanageRemove(const struct ArgusParserStruct * const parser,
               struct ArgusInput **filvec, size_t filcount,
               const configuration_t * const config)
{
   struct ArgusInput *file;
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
   struct ArgusInput *file;
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

   file = (struct ArgusInput *)parser->ArgusInputFileList;
   while (file && rv == 0) {
      rv = __check_filename(file->filename, path_archive_len, path_staging_len,
                            config);
      if (rv < 0)
         ArgusLog(LOG_WARNING, "%s: not processing file %s; wrong directory\n",
                  __func__, file->filename);
      file = (struct ArgusInput *)file->qhdr.nxt;
   }

   return rv;
}

static int
RamanageStat(const struct ArgusParserStruct * const parser)
{
   struct ArgusInput *file;

   file = (struct ArgusInput *)parser->ArgusInputFileList;
   while (file) {
      /* ArgusInput structures are zero-filled at creation.  If the
       * stat buffer holds a modification time of the unix epoch
       * (0), assume that it hasn't already been filled in and we
       * need to call stat().
       */
      if (file->statbuf.st_mtime == 0
          && stat(file->filename, &file->statbuf) < 0) {
         ArgusLog(LOG_WARNING, "unable to stat file %s\n", file->filename);
         return -1;
      }
      file = (struct ArgusInput *)file->qhdr.nxt;
   }
   return 0;
}

static int
__compare_argus_input_file_mtime(const void *a, const void *b)
{
   const struct ArgusInput * const *aa = a;
   const struct ArgusInput * const *bb = b;

   /* NULL is always > !NULL so that it ends of at the end of the array */
   if (*aa == NULL)
      return 1;
   if (*bb == NULL)
      return -1;

   if ((*aa)->statbuf.st_mtime < (*bb)->statbuf.st_mtime)
      return -1;
   return 1;
}

/* return an array of pointers into the file list, sorted by
 * modification time.
*/
static struct ArgusInput **
RamanageSortFiles(const struct ArgusParserStruct * const parser,
                  struct ArgusInput **filvec)
{
   struct ArgusInput *tmp;
   size_t i;

   tmp = parser->ArgusInputFileList;
   for (i = 0; i < parser->ArgusInputFileCount; i++) {
      *(filvec+i) = tmp;
      tmp = (struct ArgusInput *)tmp->qhdr.nxt;
   }

   qsort(filvec, parser->ArgusInputFileCount, sizeof(*filvec),
         __compare_argus_input_file_mtime);

   return filvec;
}

/* prereq: (1) filvec must be sorted in order of increasing
 * modification time (2) exemplar must reside in the archive
 * directory, and therefor may appear in the list twice.
 * returns: the number of files trimmed from the array
 */
static size_t
RamanageTrimFiles(struct ArgusParserStruct *parser, struct ArgusInput *exemplar,
                  struct ArgusInput **filvec)
{
   size_t i = parser->ArgusInputFileCount - 1;
   size_t trimmed = 0;

   /* while filvec[i] is newer than, or the same as, the file
    * specified on the command line
    */
   while (i > 0 && __compare_argus_input_file_mtime(filvec[i], exemplar) == 1) {
      filvec[i] = NULL;
      trimmed++;
      i--;
   }

   if (i == 0 && __compare_argus_input_file_mtime(filvec[i], exemplar) == 1) {
      filvec[0] = NULL;
      trimmed++;
   }

   /* put the exemplar back since it was removed in the loop above */
   if (i > 0)
      filvec[i+1] = exemplar;
   else
      filvec[0] = exemplar;
#ifdef ARGUGDEBUG
   if (trimmed == 0)
      abort();
#endif
   trimmed--;

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
   struct ArgusInput **filvec = NULL;
   struct ArgusInput *exemplar;
   size_t trimmed;
   size_t filcount;

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

   if (parser->ArgusInputFileCount != 1)
      ArgusLog(LOG_ERR, "Need exactly *one* source file (-r)\n");
   exemplar = (struct ArgusInput *)parser->ArgusInputFileList;

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

   if (parser->ArgusInputFileList == NULL)
      goto out;

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


   if (global_config.lockfile) {
      if (ArgusCreateLockFile(global_config.lockfile, 0, &lockctx) < 0) {
         cmdres = 1;
         ArgusLog(LOG_WARNING, "unable to create lock file\n");
         goto out;
      }
   }

   /* NOTE: there should probably be a limit on how many files are
    * added to the list
    */
   if (global_config.rpolicy_ignore_archive == 0) {
      DEBUGLOG(1, "%s: adding files from archive directory\n", __func__);
      if (RaProcessRecursiveFiles(global_config.path_archive) == 0) {
         cmdres = 1;
         goto out;
      }
   }

   if (RamanageStat(parser) < 0) {
      cmdres = 1;
      goto out;
   }

   if (RamanageCheckPaths(parser, &global_config) < 0) {
      cmdres = 1;
      goto out;
   }

   /* RaProcessRecursiveFiles() sorts *all* files in the list, not
    * just the files it added.  So the file specified on the command
    * line with -r will almost certainly not be the first file in
    * the list any more.  Sort the files again based on modification
    * timestamp.  If this program is run from rastream, the target
    * file will end up somewhere near the end of the list.
    *
    * Allocate one extra entry in the file array so that the zeroeth
    * entry can remain empty until after the files are sorted and
    * the array trimmed.  Then the file specified on the command
    * line can be moved from the end to the beginning of the array
    * without disturbing the sorted order of anything else.
    */
   filvec = ArgusMalloc((parser->ArgusInputFileCount + 1) * sizeof(*filvec));
   if (filvec == NULL)
      ArgusLog(LOG_ERR, "unable to allocate memory for file array\n");

   RamanageSortFiles(parser, filvec+1);

   /* remove files newer than the file we were asked to process.
    * Also remove the duplicate of that file in the list, which will be there
    * because of the recursive search of the archive directory.
    * This will avoid monkeying with the files that rastream still
    * has open.
    */
   trimmed = RamanageTrimFiles(parser, exemplar, filvec+1);
   DEBUGLOG(1, "Trimmed %zu files from the array\n", trimmed);
   filcount = parser->ArgusInputFileCount - trimmed;

   /* swap the first and last files in the array so that the compress,
    * upload and delete commands first process the file specified on
    * the command line.
    */
#ifdef ARGUSDEBUG
   if (filvec[filcount] != exemplar)
      abort();
#endif
   filvec[filcount] = NULL;
   filvec[0] = exemplar;

#ifdef ARGUSDEBUG
   {
      size_t i;
      for (i = 0; i < filcount; i++)
         DEBUGLOG(6, "FILE[%4zu]: %s\n", i, filvec[i]->filename);
    }
#endif

   if (cmdmask & RAMANAGE_CMDMASK_COMPRESS) {
      cmdres = RamanageCompress(parser, filvec, filcount, &global_config);
      if (cmdres)
         goto out;
   }
   if (cmdmask & RAMANAGE_CMDMASK_UPLOAD) {
      cmdres = RamanageUpload(parser, filvec, filcount, &global_config);
      if (cmdres)
         goto out;
   }
   if (cmdmask & RAMANAGE_CMDMASK_REMOVE) {
      cmdres = RamanageRemove(parser, filvec, filcount, &global_config);
      if (cmdres)
         goto out;
   }

   if (global_config.lockfile) {
      if (ArgusReleaseLockFile(&lockctx) < 0) {
         cmdres = 1;
         goto out;
      }
   }

out:
   if (filvec)
      ArgusFree(filvec);
   return cmdres;
}