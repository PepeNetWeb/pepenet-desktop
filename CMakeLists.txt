# pepenet-desktop ("PepeNet") — the decentralized-web GUI client.
#
# GUI over the CANONICAL stack: embeds the headless indexer (indexer/, the
# pinned namespace-indexer submodule — which itself pins the protocol) as its
# sync engine. Never a third fold implementation. The dns/tls embeds
# (dns_embed / tls_embed targets) land in later slices.
#
# First checkout: git submodule update --init --recursive
# (offline/local checkouts: the indexer's nested secp256k1 submodule points at
#  github; override with `git config submodule.vendor/secp256k1.url <local>` in
#  indexer/ before `submodule update` if needed)
#
# Platforms: macOS (Metal, .app bundle) and Windows (D3D11, MinGW-w64/UCRT64 —
# gcc + winpthreads; MSYS2's static OpenSSL/sqlite3; WiX MSI via
# packaging/package-win.ps1). The submodules compile UNCHANGED on Windows:
# src/compat/win/ supplies the POSIX net/fs headers over Winsock.

cmake_minimum_required(VERSION 3.20)

# Distribution floor — MUST precede project(). Without these, CMake stamps the
# binary with the BUILD HOST's OS as its Mach-O minimum (the plist may say
# 11.0, but the loader trusts the binary: "You cannot use this version of
# pepenet with this version of macOS" on anything older than the build
# machine) and builds host-arch only (arm64 — nothing for Intel Macs).
set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING
    "min macOS (Big Sur — the first arm64 release; matches the plist)")
set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64" CACHE STRING
    "universal 2 binary for distribution")

project(pepenet-desktop C)

set(CMAKE_C_STANDARD 11)

if(WIN32)
    # MinGW gates localtime_r/gmtime_r behind this; harmless everywhere else
    add_compile_definitions(_POSIX_THREAD_SAFE_FUNCTIONS=200112L)
endif()

# The overlay discovery mark this deployment flies (indexer.h IDX_DNET_MARK):
# a peer whose P2P subver starts with this prefix is classified as mesh-aware,
# and our own agent advertises it. One mark per NETWORK — every PepeNet node
# must advertise + classify the same prefix or they cannot find each other.
# The generic submodule default is "/pepenet-"; the pep deployment rebrands.
add_compile_definitions("IDX_DNET_MARK=\"/pepenet-\"")

# ── Vendors ───────────────────────────────────────────────────────────────────
set(SOKOL_DIR   ${CMAKE_SOURCE_DIR}/vendor/sokol)
set(NUKLEAR_DIR ${CMAKE_SOURCE_DIR}/vendor/nuklear)
if(NOT EXISTS ${SOKOL_DIR}/sokol_app.h OR NOT EXISTS ${NUKLEAR_DIR}/nuklear.h)
    message(FATAL_ERROR "vendors missing. Run: git submodule update --init --recursive")
endif()

# libsecp256k1 comes via the indexer's own pinned submodule (one pin, one truth).
set(SECP256K1_DIR ${CMAKE_SOURCE_DIR}/indexer/vendor/secp256k1)
if(NOT EXISTS ${SECP256K1_DIR}/CMakeLists.txt)
    message(FATAL_ERROR "libsecp256k1 not found. Run: git submodule update --init --recursive")
endif()
# Static-link into the app; we only need ECDSA + basic EC.
set(BUILD_SHARED_LIBS                  OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK          OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS              OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS   OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CTIME_TESTS        OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES           OFF CACHE BOOL "" FORCE)
set(SECP256K1_INSTALL                  OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ECDH       ON  CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY   OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS  OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG      OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ELLSWIFT   OFF CACHE BOOL "" FORCE)
add_subdirectory(${SECP256K1_DIR} secp256k1 EXCLUDE_FROM_ALL)

# ── Platform seams ────────────────────────────────────────────────────────────
# Windows: the POSIX-over-Winsock compat headers (sys/socket.h, poll.h, …) let
# the submodule sources compile byte-identical; OpenSSL/sqlite3 come static
# from the MSYS2 UCRT64 prefix.
if(WIN32)
    set(COMPAT_WIN_DIR ${CMAKE_SOURCE_DIR}/src/compat/win)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL REQUIRED)
    set(TLS_SSL_LIBS OpenSSL::SSL OpenSSL::Crypto ws2_32 crypt32 bcrypt)
else()
    # OpenSSL 3, statically linked (never system LibreSSL — DANE needs
    # OpenSSL's SSL_dane_* which LibreSSL lacks; static keeps the .app
    # self-contained, no dylib bundling/rpath dance). The universal prefix
    # (scripts/make_universal_openssl.sh — arm64+x86_64 slices, min-OS 11.0)
    # wins when present; Homebrew's arm64-only keg is the dev fallback.
    if(EXISTS ${CMAKE_SOURCE_DIR}/vendor/openssl-universal/lib/libssl.a)
        set(OPENSSL_PREFIX ${CMAKE_SOURCE_DIR}/vendor/openssl-universal)
    else()
        set(OPENSSL_PREFIX /opt/homebrew/opt/openssl@3 CACHE PATH "Homebrew openssl@3")
        if(NOT EXISTS ${OPENSSL_PREFIX}/lib/libssl.a)
            message(FATAL_ERROR "${OPENSSL_PREFIX} missing (brew install openssl@3)")
        endif()
        if("x86_64" IN_LIST CMAKE_OSX_ARCHITECTURES)
            message(FATAL_ERROR "universal build needs universal OpenSSL — run "
                                "scripts/make_universal_openssl.sh first "
                                "(Homebrew's keg is arm64-only)")
        endif()
    endif()
    set(TLS_SSL_LIBS ${OPENSSL_PREFIX}/lib/libssl.a ${OPENSSL_PREFIX}/lib/libcrypto.a)
endif()

# ── The embedded canonical stack ──────────────────────────────────────────────
set(SM_ENGINE_DIR ${CMAKE_SOURCE_DIR}/indexer/protocol/impls/c/src)
set(IDX_DIR       ${CMAKE_SOURCE_DIR}/indexer/src)
set(SHIM_SRC      ${CMAKE_SOURCE_DIR}/indexer/protocol/shim/secp_shim.c)

# Mirror indexer Makefile ENGINE_CORE + ENGINE_CURVE exactly.
set(DESKTOP_ENGINE_SRCS
    ${SM_ENGINE_DIR}/fold.c    ${SM_ENGINE_DIR}/decode.c  ${SM_ENGINE_DIR}/oracle.c
    ${SM_ENGINE_DIR}/digest.c  ${SM_ENGINE_DIR}/state.c   ${SM_ENGINE_DIR}/lease.c
    ${SM_ENGINE_DIR}/market.c  ${SM_ENGINE_DIR}/claim.c   ${SM_ENGINE_DIR}/trade.c
    ${SM_ENGINE_DIR}/bitmap.c  ${SM_ENGINE_DIR}/preblock.c
    ${SM_ENGINE_DIR}/sha256.c  ${SM_ENGINE_DIR}/ripemd160.c
    ${SM_ENGINE_DIR}/gen.c     ${SM_ENGINE_DIR}/harness.c
    ${SM_ENGINE_DIR}/ecmh.c
)
# indexer chain-side sources, minus its CLI main.c / test_chain.c.
set(DESKTOP_IDX_SRCS
    ${IDX_DIR}/attrib.c ${IDX_DIR}/adapter.c ${IDX_DIR}/oracle_feed.c
    ${IDX_DIR}/db.c ${IDX_DIR}/chain.c ${IDX_DIR}/base58.c
    ${IDX_DIR}/sync.c ${IDX_DIR}/pow.c ${IDX_DIR}/serve_store.c
    ${IDX_DIR}/txcheck.c ${IDX_DIR}/mempool.c ${SHIM_SRC}
)

# ── The pepenet-mesh facade (sp_*) ────────────────────────────────────────────
# Compiled from source against the INDEXER'S protocol pin (one pin, one truth) —
# never link mesh's prebuilt .a, which bundles its own hash/secp objects from a
# live namespace-protocol checkout. Quoted "secp256k1.h" here must resolve to
# the protocol-sm header (mesh Makefile's INC_SM), so keep libsecp's include
# dir OFF this target.
set(MESH_DIR ${CMAKE_SOURCE_DIR}/mesh)
add_library(dnet_mesh STATIC
    ${MESH_DIR}/src/crypto.c
    ${MESH_DIR}/src/view.c
    ${MESH_DIR}/src/wire.c
    ${MESH_DIR}/src/state.c
)
target_include_directories(dnet_mesh PUBLIC ${MESH_DIR}/include)
target_include_directories(dnet_mesh PRIVATE ${SM_ENGINE_DIR})

# ── The embedded dns plane (pepenet-dns record store + the dnsnet seam) ──────
# Anchor-ordered per-key LWW zones over dnet_mesh's sp_state — the vpost
# carrier (pepenet-social) is retired. Same include-order dance: this group's
# quoted "secp256k1.h" must resolve to the protocol's secp_* declarations,
# not the vendored libsecp header.
set(DNS_DIR    ${CMAKE_SOURCE_DIR}/dns)
if(NOT EXISTS ${DNS_DIR}/src/dnsd_core.c)
    message(FATAL_ERROR "dns submodule missing. Run: git submodule update --init --recursive")
endif()
add_library(dns_embed STATIC
    ${DNS_DIR}/src/dns_state.c
    ${DNS_DIR}/src/dns_chain.c
    ${DNS_DIR}/src/dns_net.c
    ${DNS_DIR}/src/zone.c
    ${DNS_DIR}/src/dns_wire.c
    ${DNS_DIR}/src/dnsd_core.c
    src/dnsnet.c
    src/dirscan.c
    src/zonekey.c
)
target_include_directories(dns_embed PUBLIC
    ${DNS_DIR}/src
)
target_include_directories(dns_embed PRIVATE
    ${SM_ENGINE_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${IDX_DIR}                 # indexer.h / db.h — dnsnet drives the chain-wire mesh
)
target_link_libraries(dns_embed PUBLIC dnet_mesh)
if(WIN32)
    target_include_directories(dns_embed BEFORE PRIVATE ${COMPAT_WIN_DIR})
endif()

# ── The embedded DANE TLS proxy (pepenet-tls + the webproxy seam) ─────────────
set(TLS_DIR ${CMAKE_SOURCE_DIR}/tls)
if(NOT EXISTS ${TLS_DIR}/src/proxy.c)
    message(FATAL_ERROR "tls submodule missing. Run: git submodule update --init --recursive")
endif()
add_library(tls_embed STATIC
    ${TLS_DIR}/src/ca.c
    ${TLS_DIR}/src/proxy.c
    ${TLS_DIR}/src/dane.c
    ${TLS_DIR}/src/resolve.c
    ${TLS_DIR}/src/origin.c
    ${TLS_DIR}/src/sscert.c
    ${TLS_DIR}/src/fetch.c
    src/webproxy.c
)
# the OS trust-store + system-install halves are per-platform implementations
# of the same headers (trust.h / sysinstall.h)
if(WIN32)
    target_sources(tls_embed PRIVATE src/trust_win.c src/sysinstall_win.c)
    target_include_directories(tls_embed BEFORE PRIVATE ${COMPAT_WIN_DIR})
else()
    target_sources(tls_embed PRIVATE ${TLS_DIR}/src/trust.c src/sysinstall.c)
endif()
target_include_directories(tls_embed PUBLIC
    ${TLS_DIR}/src
)
target_include_directories(tls_embed PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(tls_embed PUBLIC
    dns_embed
    ${TLS_SSL_LIBS}
)
if(NOT WIN32)
    target_include_directories(tls_embed PUBLIC ${OPENSSL_PREFIX}/include)
endif()

# ── The app ───────────────────────────────────────────────────────────────────
set(DESKTOP_COMMON_SRCS
    src/main.c
    src/engine.c
    src/model.c
    src/model_demo.c
    src/wallet.c
    src/bip39.c
    src/bip39_wordlist.c
    src/hdwallet.c
    src/signer.c
    src/ops.c
    src/fee.c
    src/qr.c
    src/favicon.c
    src/ui/theme.c
    src/ui/strings.c
    src/ui/draw.c
    src/ui/ui.c
    src/ui/widgets.c
    src/ui/view_discover.c
    src/ui/view_screens.c
    src/ui/view_dns.c
    src/ui/view_ssl.c
    src/ui/view_peers.c
    src/ui/popups.c
    src/ui/dialogs.c
)

if(WIN32)
    enable_language(RC)
    add_executable(pepenet-desktop
        ${DESKTOP_COMMON_SRCS}
        src/sokol_impl_win.c
        src/tray_win.c
        src/platform_win.c
        src/compat/win_compat.c
        packaging/pepenet.rc
        ${DESKTOP_ENGINE_SRCS}
        ${DESKTOP_IDX_SRCS}
    )
    target_compile_definitions(pepenet-desktop PRIVATE SOKOL_D3D11)
    target_include_directories(pepenet-desktop BEFORE PRIVATE ${COMPAT_WIN_DIR})
    # dev builds keep the console subsystem so the stderr proof hooks stream;
    # release/MSI builds turn it off (a GUI app must not flash a console)
    option(PEPENET_WIN_CONSOLE "console subsystem (dev: stderr hooks visible)" ON)
    if(PEPENET_WIN_CONSOLE)
        target_compile_definitions(pepenet-desktop PRIVATE SOKOL_WIN32_FORCE_MAIN)
    else()
        set_target_properties(pepenet-desktop PROPERTIES WIN32_EXECUTABLE TRUE)
    endif()
    # bake libgcc/winpthread in — the exe ships alone
    target_link_options(pepenet-desktop PRIVATE -static)
    target_link_libraries(pepenet-desktop PRIVATE
        sqlite3 secp256k1 dns_embed tls_embed
        d3d11 dxgi dwmapi comctl32 shell32 ole32 uuid advapi32 gdi32 user32
        ws2_32 crypt32 bcrypt wininet
    )
    # fonts + the privileged install helper ride in resources\ next to the exe
    add_custom_command(TARGET pepenet-desktop POST_BUILD
        COMMAND ${CMAKE_COMMAND}
            -DFONT_DIR=${CMAKE_SOURCE_DIR}/vendor/fonts
            "-DDST=$<TARGET_FILE_DIR:pepenet-desktop>/resources"
            -P ${CMAKE_SOURCE_DIR}/scripts/copy_fonts.cmake
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/packaging/install-helper.ps1
            "$<TARGET_FILE_DIR:pepenet-desktop>/resources/install-helper.ps1"
        COMMENT "Staging resources (fonts + install helper) next to the exe")
else()
    add_executable(pepenet-desktop MACOSX_BUNDLE
        ${DESKTOP_COMMON_SRCS}
        src/sokol_impl.m
        src/tray.m
        src/platform_mac.m
        ${DESKTOP_ENGINE_SRCS}
        ${DESKTOP_IDX_SRCS}
        packaging/pepenet.icns
        packaging/pepenet-tray.png
    )
    # ship the app icon inside the bundle's Resources and name it in Info.plist
    set_source_files_properties(packaging/pepenet.icns PROPERTIES
        MACOSX_PACKAGE_LOCATION "Resources")
    # the menu-bar face (tray.m loads it by APP_TRAY_ICON name)
    set_source_files_properties(packaging/pepenet-tray.png PROPERTIES
        MACOSX_PACKAGE_LOCATION "Resources")
    add_custom_command(TARGET pepenet-desktop POST_BUILD
        COMMAND ${CMAKE_COMMAND}
            -DFONT_DIR=${CMAKE_SOURCE_DIR}/vendor/fonts
            "-DDST=$<TARGET_BUNDLE_CONTENT_DIR:pepenet-desktop>/Resources"
            -P ${CMAKE_SOURCE_DIR}/scripts/copy_fonts.cmake
        COMMENT "Bundling fonts into Resources (scripts/fetch_vendors.sh fetches them)")
    add_custom_command(TARGET pepenet-desktop POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/packaging/install-helper.sh
            "$<TARGET_BUNDLE_CONTENT_DIR:pepenet-desktop>/Resources/install-helper.sh"
        COMMENT "Bundling the privileged install helper into Resources")
    # the SMAppService login agent — bundled so Login Items attributes it to
    # the APP's name, not the signing identity's legal name
    add_custom_command(TARGET pepenet-desktop POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_BUNDLE_CONTENT_DIR:pepenet-desktop>/Library/LaunchAgents"
        COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/packaging/com.pepenet.app.plist
            "$<TARGET_BUNDLE_CONTENT_DIR:pepenet-desktop>/Library/LaunchAgents/com.pepenet.app.plist"
        COMMENT "Bundling the login agent (SMAppService plist)")
    set_source_files_properties(src/sokol_impl.m src/tray.m src/platform_mac.m PROPERTIES
        COMPILE_FLAGS "-x objective-c"
    )
    set_target_properties(pepenet-desktop PROPERTIES
        MACOSX_BUNDLE_INFO_PLIST ${CMAKE_SOURCE_DIR}/packaging/Info.plist.in
        MACOSX_BUNDLE_BUNDLE_NAME "PepeNet"
        MACOSX_BUNDLE_ICON_FILE "pepenet.icns"
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.pepenet.app"
        MACOSX_BUNDLE_BUNDLE_VERSION "0.1.0"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "0.1.0"
    )
    target_link_libraries(pepenet-desktop PRIVATE
        "-framework Cocoa" "-framework QuartzCore" "-framework Metal"
        "-framework MetalKit" "-framework Security" "-framework ServiceManagement"
        sqlite3 secp256k1 dns_embed tls_embed
    )
    target_compile_definitions(pepenet-desktop PRIVATE SOKOL_METAL)
endif()

# dev runs load fonts straight from the tree; the staged copy above serves
# packaged builds (platform_resource_path looks in resources first)
target_compile_definitions(pepenet-desktop PRIVATE
    SHIB_DEV_FONT_DIR="${CMAKE_SOURCE_DIR}/vendor/fonts")
if(APPLE AND NOT WIN32)
    target_compile_definitions(pepenet-desktop PRIVATE
        SHIB_DEV_TRAY_ICON="${CMAKE_SOURCE_DIR}/packaging/pepenet-tray.png")
endif()
set_target_properties(pepenet-desktop PROPERTIES OUTPUT_NAME "pepenet")

# Include order matters: quoted "secp256k1.h" from IDX sources must resolve to
# the vendored libsecp header via the SECPDIR angle path BEFORE the protocol
# repo's self-rolled header dir — mirror the indexer Makefile (-Isrc -ISECP -ISM).
target_include_directories(pepenet-desktop PRIVATE
    ${IDX_DIR}
    ${SECP256K1_DIR}/include
    ${SM_ENGINE_DIR}
    ${SOKOL_DIR}
    ${NUKLEAR_DIR}
)
