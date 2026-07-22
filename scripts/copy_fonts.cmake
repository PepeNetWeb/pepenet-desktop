# Copies whichever vendored fonts exist into the app bundle's Resources.
# Runs at build time (POST_BUILD) so a checkout that hasn't run
# scripts/fetch_vendors.sh yet still builds — the app then falls back to the
# nuklear default font and prints which files are missing.
if(NOT DEFINED FONT_DIR OR NOT DEFINED DST)
    message(FATAL_ERROR "usage: cmake -DFONT_DIR=<dir> -DDST=<dir> -P copy_fonts.cmake")
endif()
file(MAKE_DIRECTORY "${DST}")
file(GLOB fonts "${FONT_DIR}/*.ttf")
foreach(f ${fonts})
    execute_process(COMMAND ${CMAKE_COMMAND} -E copy_if_different "${f}" "${DST}")
endforeach()
