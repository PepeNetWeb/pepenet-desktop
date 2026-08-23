// web_svc.c — headless Windows padlock: chain sync + DNS resolver + DANE
// proxy, no GUI. Runs as a Windows Service (boot, Restart=always analogue)
// or in the console for debugging.
//
// Same engines the desktop embeds (engine / dnsnet / webproxy). No wallet,
// no Discover — those need the GUI. Data dir: %PROGRAMDATA%\PepeNet\.pepenet
// when started by the SCM (LocalSystem has no useful USERPROFILE).
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsvc.h>

#include "appconf.h"
#include "platform.h"
#include "engine.h"
#include "dnsnet.h"
#include "webproxy.h"
#include "indexer.h"
#include "ca.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>

#define SVC_NAME "PepeNetWeb"
#define SVC_DISP "PepeNet web (DNS + DANE proxy)"

static SERVICE_STATUS_HANDLE g_svc;
static SERVICE_STATUS        g_st;
static volatile int          g_run = 1;

static void report(DWORD state, DWORD exitcode) {
    g_st.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_st.dwCurrentState = state;
    g_st.dwWin32ExitCode = exitcode;
    g_st.dwControlsAccepted = (state == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP : 0;
    g_st.dwWaitHint = (state == SERVICE_START_PENDING) ? 15000 : 0;
    if (g_svc) SetServiceStatus(g_svc, &g_st);
}

static void dataroot(char *out, size_t cap) {
    const char *pd = getenv("PROGRAMDATA");
    if (!pd || !pd[0]) pd = "C:/ProgramData";
    snprintf(out, cap, "%s/PepeNet", pd);
    _mkdir(out);
}

static void pin_home(void) {
    char root[400];
    dataroot(root, sizeof root);
    SetEnvironmentVariableA("USERPROFILE", root);
    SetEnvironmentVariableA("HOME", root);
}

static int boot_engines(void) {
    pin_home();
    char db[600];
    platform_data_path(APP_COIN ".db", db, sizeof db);
    idx_sync_agent = APP_CHAIN_AGENT;
    dnsnet_boot(APP_COIN, db);
    if (!dnsnet_start()) {
        fprintf(stderr, "pepenet-web: dnsnet_start failed\n");
        return 0;
    }
    if (!webproxy_start(dnsnet_store_path(), dnsnet_chain_path())) {
        fprintf(stderr, "pepenet-web: webproxy_start failed\n");
        return 0;
    }
    if (!engine_start(APP_COIN, db, APP_SEED_PEER)) {
        fprintf(stderr, "pepenet-web: engine_start failed\n");
        return 0;
    }
    fprintf(stderr, "pepenet-web: resolver :%d  proxy :%d  db %s  ca %s\n",
            APP_DNS_PORT, APP_PROXY_PORT, db, ca_root_cert_path());
    return 1;
}

static void stop_engines(void) {
    g_run = 0;
    webproxy_stop();
    dnsnet_stop();
    engine_stop();
}

static DWORD WINAPI ctrl(DWORD code, DWORD ev, LPVOID data, LPVOID ctx) {
    (void)ev; (void)data; (void)ctx;
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
        report(SERVICE_STOP_PENDING, NO_ERROR);
        stop_engines();
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static void WINAPI svc_main(DWORD argc, LPSTR *argv) {
    (void)argc; (void)argv;
    g_svc = RegisterServiceCtrlHandlerExA(SVC_NAME, ctrl, NULL);
    report(SERVICE_START_PENDING, NO_ERROR);
    if (!boot_engines()) {
        report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }
    report(SERVICE_RUNNING, NO_ERROR);
    while (g_run) Sleep(400);
    report(SERVICE_STOPPED, NO_ERROR);
}

static BOOL WINAPI console_ctrl(DWORD t) {
    (void)t;
    stop_engines();
    return TRUE;
}

int main(int argc, char **argv) {
    int i, as_console = 0;
    for (i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--console")) as_console = 1;

    if (!as_console) {
        SERVICE_TABLE_ENTRYA tab[] = {
            { SVC_NAME, svc_main },
            { NULL, NULL }
        };
        if (StartServiceCtrlDispatcherA(tab)) return 0;
        if (GetLastError() != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            return 1;
        // not launched by SCM — fall through to console
    }
    SetConsoleCtrlHandler(console_ctrl, TRUE);
    if (!boot_engines()) return 1;
    fprintf(stderr, "pepenet-web: console (Ctrl+C to stop)\n");
    while (g_run) Sleep(400);
    return 0;
}

#endif /* _WIN32 */
