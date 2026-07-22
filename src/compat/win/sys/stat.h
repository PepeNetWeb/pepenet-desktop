/* sys/stat.h — Windows shim over the real MinGW header: the only fix is the
 * two-arg POSIX mkdir(path, mode) → _mkdir(path) (mode is ACL-land on
 * Windows; the dirs in question live under the user profile). */
#ifndef DNET_COMPAT_SYS_STAT_H
#define DNET_COMPAT_SYS_STAT_H
#include_next <sys/stat.h>
#include <direct.h>

#ifndef DNET_WINCOMPAT_NO_MACROS
#define mkdir(path, mode) _mkdir(path)
#endif

#endif
