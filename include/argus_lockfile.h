#ifndef __ARGUS_LOCKFILE_H
# define __ARGUS_LOCKFILE_H

struct _argus_lock_context;
typedef struct _argus_lock_context *ArgusLockContext;

int
ArgusCreateLockFile(const char * const filename, int nonblock,
                   ArgusLockContext *ctx);

int
ArgusReleaseLockFile(ArgusLockContext *ctx);

#endif
