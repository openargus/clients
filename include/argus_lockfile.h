#ifndef __ARGUS_LOCKFILE_H
# define __ARGUS_LOCKFILE_H
# include "argus_config.h"

struct _argus_lock_context;
typedef struct _argus_lock_context *ArgusLockContext;

# if defined(CYGWIN)
char *
ArgusCygwinConvPath2Win(const char * const);
# endif


int
ArgusCreateLockFile(const char * const filename, int nonblock,
                   ArgusLockContext *ctx);

int
ArgusReleaseLockFile(ArgusLockContext *ctx);

#endif
