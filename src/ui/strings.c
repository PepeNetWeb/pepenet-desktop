// strings.c — the string table behind TR() (strings.h holds the copy).
#include "strings.h"

#include <stddef.h>

#define X(id, s) [id] = s,
static const char *STR_EN[S__COUNT] = { DNET_STRINGS(X) };
#undef X

const char *ui_str(StrId id) {
    const char *s = (id >= 0 && id < S__COUNT) ? STR_EN[id] : NULL;
    return s ? s : "\xE2\x80\xA6";   // a hole in the table shows as … not a crash
}
