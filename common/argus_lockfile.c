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
 *  argus_lockfile.c - File locking functions for Posix and Windows environments
 *
 *  Author: Eric Kinzie <eric@qosient.com>
 */

#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslog.h>

#include "argus_util.h"
#include "argus_client.h"
#include "argus_lockfile.h"

#if defined(_WIN32) || defined(_WIN64) || defined(CYGWIN)
# if defined(CYGWIN)
#  include <sys/cygwin.h>
# endif
# include <windows.h>
static const DWORD locklen = 1; /* arbitrary value > 0 */

typedef struct _argus_lock_context {
   HANDLE handle;
   char *filename;
} *ArgusLockContext;

# if defined(CYGWIN)
char *
ArgusCygwinConvPath2Win(const char * const posix)
{
   ssize_t size;
   char *win = NULL;

   size = cygwin_conv_path (CCP_POSIX_TO_WIN_A, posix, NULL, 0);
   if (size < 0) {
      ArgusLog(LOG_WARNING, "%s unable to find length of filename\n", __func__);
   } else {
      win = ArgusMalloc(size);
      if (win == NULL)
         ArgusLog(LOG_ERR, "%s unable to allocate memory for filename\n",
                  __func__);

      if (cygwin_conv_path (CCP_POSIX_TO_WIN_A, posix, win, size)) {
         ArgusLog(LOG_WARNING, "%s unable to convert filename\n", __func__);
         ArgusFree(win);
         win = NULL;
      }
   }
   return win;
}
# endif

int
ArgusCreateLockFile(const char * const filename, int nonblock,
                   ArgusLockContext *ctx)
{
   DWORD lasterr;
   OVERLAPPED sOverlapped;
   HANDLE hFile;
   DWORD fail_immediately = 0;
   const char *win32_filename = NULL;
   int rv = 0;

# if defined(CYGWIN)
   win32_filename = ArgusCygwinConvPath2Win(filename);
# endif
   if (win32_filename == NULL)
      win32_filename = filename;

   hFile = CreateFile(TEXT(win32_filename), GENERIC_READ|GENERIC_WRITE,
                      FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, CREATE_NEW, 0,
                      NULL);

   if (hFile == INVALID_HANDLE_VALUE) {
      lasterr = GetLastError();
      if (lasterr != ERROR_FILE_EXISTS) {
         ArgusLog(LOG_WARNING, "Unable to open file reason %d\n", lasterr);
         rv = -1;
         goto err;
      }

      hFile = CreateFile(TEXT(win32_filename), GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, 0, NULL);

      if (hFile == INVALID_HANDLE_VALUE) {
         ArgusLog(LOG_WARNING, "CreateFile failed (%d)\n", GetLastError());
         rv = -1;
         goto err;
      }
   }

   sOverlapped.Offset = 0;
   sOverlapped.OffsetHigh = 0;

   if (nonblock)
      fail_immediately = LOCKFILE_FAIL_IMMEDIATELY;

   if (!LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK | fail_immediately, 0,
                   locklen, 0, &sOverlapped)) {
     ArgusLog(LOG_WARNING, "LockFileEx failed (%d)\n", GetLastError());
     CloseHandle(hFile);
     rv = -1;
     goto err;
   }

   (*ctx) = ArgusCalloc(sizeof(**ctx), 1);
   if ((*ctx) == NULL)
      ArgusLog(LOG_ERR, "Unable to allocate memory for lockfile context\n");

   (*ctx)->handle = hFile;
   (*ctx)->filename = strdup(win32_filename);

err:
   if (win32_filename)
      ArgusFree((void *)win32_filename);
   return rv;
}

int
ArgusReleaseLockFile(ArgusLockContext *ctx)
{
   DWORD lasterr;
   OVERLAPPED sOverlapped;
   int rv = 0;

   /* ctx is pointer to pointer */
   if (*ctx == NULL)
       return -1;

   sOverlapped.Offset = 0;
   sOverlapped.OffsetHigh = 0;

   if (!UnlockFileEx((*ctx)->handle, 0, locklen, 0, &sOverlapped)) {
      ArgusLog(LOG_WARNING, "%s: UnlockFileEx failed (%d)\n", GetLastError(),
              __func__);
      rv = -1;
      goto out;
   }

   if (!CloseHandle((*ctx)->handle)) {
      ArgusLog(LOG_WARNING, "%s: CloseHandle failed (%d)\n", GetLastError(),
              __func__);
      rv = -1;
      goto out;
   }

   if (!DeleteFile(TEXT((*ctx)->filename))) {
      lasterr = GetLastError();

      if (lasterr != ERROR_SHARING_VIOLATION) {
         ArgusLog(LOG_WARNING, "%s: DeleteFile failed (%d)\n", GetLastError(),
                 __func__);
         rv = -1;
         goto out;
      }
   }

   free((*ctx)->filename);  /* allocated by strdup() */
   ArgusFree(*ctx);
   *ctx = NULL;

out:
   return rv;
}

#else /* not windows */
# include <fcntl.h>
# include <unistd.h>
# include <errno.h>

typedef struct _argus_lock_context {
   struct flock lock;
   int fd;
   char *filename;
} *ArgusLockContext;

int
ArgusCreateLockFile(const char * const filename, int nonblock,
                    ArgusLockContext *ctx)
{
   int fd;
   int cmd = F_SETLKW;
   int res;
   struct flock lock;

   fd = open(filename, O_RDWR|O_CREAT|O_TRUNC, 0600);
   if (fd < 0)
      return -1;

   lock.l_type = F_WRLCK;
   lock.l_start = 0;
   lock.l_whence = SEEK_SET;
   lock.l_len = 1;

   if (nonblock)
      cmd = F_SETLK;

   do {
      res = fcntl(fd, cmd, &lock);
   } while (res < 0 && errno == EINTR);

   if (res < 0)
      return -1;

   (*ctx) = ArgusCalloc(sizeof(**ctx), 1);
   if ((*ctx) == NULL)
       ArgusLog(LOG_ERR, "%s: Unable to allocate memory for lockfile context\n",
                __func__);

   (*ctx)->lock = lock;
   (*ctx)->fd = fd;
   (*ctx)->filename = strdup(filename);

   return 0;
}

int
ArgusReleaseLockFile(ArgusLockContext *ctx)
{
   if (*ctx == NULL)
      return -1;

   (*ctx)->lock.l_type = F_UNLCK;
   if (fcntl((*ctx)->fd, F_SETLK, &(*ctx)->lock) < 0)
      ArgusLog(LOG_WARNING, "%s: unable to unlock file\n", __func__);

   close((*ctx)->fd);
   unlink((*ctx)->filename); /* try to clean up, but ok to fail */

   free((*ctx)->filename);
   ArgusFree(*ctx);
   *ctx = NULL;

   return 0;
}

#endif /* windows */

#ifdef NOTDEF
int main(int argc, char **argv)
{
   ArgusLockContext ctx;

   if (ArgusCreateLockFile(argv[1], 0, &ctx) < 0) {
      fprintf(stderr, "pid %8d lock failed\n", getpid());
      return 1;
   } else
      fprintf(stderr, "pid %8d locked\n", getpid());

#if defined(_WIN32) || defined(_WIN64) || defined(CYGWIN)
   Sleep(5*1000);
#else
   sleep(5);
#endif

   if (ArgusReleaseLockFile(&ctx) < 0)
      fprintf(stderr, "pid %8d unlock failed\n", getpid());
   else
      fprintf(stderr, "pid %8d unlocked\n", getpid());

   return 0;
}
#endif
