/* dns-cli — live control client for a running dnsd.
 *
 * Sends one command over the daemon's --ctl unix socket and prints the reply.
 * The daemon holds the owner key and the current log head, so the CLI just
 * forwards a record spec; the daemon signs it and net_submits it to the mesh.
 *
 *   dns-cli --ctl <path> PUT <label> <type> <ttl> <rdata...>
 *   dns-cli --ctl <path> DEL <label> <type>
 *   dns-cli --ctl <path> CLEAR
 *   dns-cli --ctl <path> LIST
 *   dns-cli --ctl <path> USAGE
 *
 * label "@" is the apex. Examples:
 *   dns-cli --ctl /tmp/a.ctl PUT www A 3600 192.0.2.9
 *   dns-cli --ctl /tmp/a.ctl PUT @ TXT 3600 "hello"
 *   dns-cli --ctl /tmp/a.ctl PUT _443._tcp TLSA 3600 3 1 1 <64-hex>
 *   dns-cli --ctl /tmp/a.ctl DEL www A
 *   dns-cli --ctl /tmp/a.ctl LIST
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

int main(int argc, char **argv) {
    const char *ctl = NULL;
    int i = 1;
    if (argc >= 3 && !strcmp(argv[1], "--ctl")) { ctl = argv[2]; i = 3; }
    if (!ctl || i >= argc) {
        fprintf(stderr,
            "usage: dns-cli --ctl <path> <command>\n"
            "  PUT <label> <type> <ttl> <rdata...>   add/replace a record\n"
            "  DEL <label> <type>                    delete a record (tombstone)\n"
            "  CLEAR                                 void the whole zone (new floor)\n"
            "  LIST                                  dump the current zone\n"
            "  USAGE                                 held bytes vs the 8 KB budget\n"
            "  (label \"@\" is the apex)\n");
        return 2;
    }

    /* join the remaining args into one request line */
    char line[2048]; int o = 0;
    for (int j = i; j < argc && o < (int)sizeof line - 2; j++)
        o += snprintf(line + o, sizeof line - (size_t)o, "%s%s", argv[j], j + 1 < argc ? " " : "");
    o += snprintf(line + o, sizeof line - (size_t)o, "\n");

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un un; memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof un.sun_path, "%s", ctl);
    if (connect(fd, (struct sockaddr *)&un, sizeof un) < 0) {
        fprintf(stderr, "dns-cli: cannot connect to %s (is dnsd running with --ctl?)\n", ctl);
        return 1;
    }
    if (write(fd, line, strlen(line)) < 0) { perror("write"); return 1; }

    char buf[8192]; ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) fwrite(buf, 1, (size_t)n, stdout);
    close(fd);
    return 0;
}
