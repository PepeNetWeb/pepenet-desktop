/* sys/file.h — Windows stand-in: flock over LockFileEx (advisory whole-file
 * lock; keeps main.c's single-writer <coin>.db.lock convention). */
#ifndef DNET_COMPAT_SYS_FILE_H
#define DNET_COMPAT_SYS_FILE_H
#include "../dnet_wincompat.h"

#ifndef DNET_WINCOMPAT_NO_MACROS
#define flock(fd, op) dnet_flock((fd), (op))
#endif

#endif
