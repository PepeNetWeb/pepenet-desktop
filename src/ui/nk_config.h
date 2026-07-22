// nk_config.h — the ONE nuklear configuration for every translation unit.
// sokol_impl.m adds NK_IMPLEMENTATION before including this; everyone else
// gets declarations only. Keep the flag set identical everywhere or the ABI
// silently diverges.
#ifndef SHIB_NK_CONFIG_H
#define SHIB_NK_CONFIG_H

#define NK_INCLUDE_FIXED_TYPES
#define NK_INCLUDE_STANDARD_IO
#define NK_INCLUDE_DEFAULT_ALLOCATOR
#define NK_INCLUDE_VERTEX_BUFFER_OUTPUT
#define NK_INCLUDE_FONT_BAKING
#define NK_INCLUDE_DEFAULT_FONT
#include "../../vendor/nuklear/nuklear.h"

#endif
