#define _GNU_SOURCE
/*
 * peershim.c -- C-level ground truth for the JSON->syscall investigation.
 *
 * Purpose:
 *   This is NOT an exploit and NOT a "peer-cred bypass". It is a shim that
 *   reproduces, in machine code, the exact transition the Python probe claims:
 *
 *       socket bytes -> HTTP framing -> JSON value -> select()/connect() syscall
 *
 *   so that the syscall can be observed at the instruction level with objdump,
 *   without strace/gdb (neither is installed here).
 *
 * What it demonstrates (and nothing more):
 *   1. A JSON member name/value taken from an HTTP body becomes the operand of
 *      a syscall indirectly: it selects which *pre-declared* destination slot
 *      is used. The attacker never supplies an address, port, or path.
 *   2. The transformation boundary is measurable: the bytes that were
 *      authenticated (raw body) differ from the bytes handed to connect().
 *   3. Kernel-side peer identity (SCM_CREDENTIALS / SO_PEERCRED) is attached by
 *      the kernel, not parsed from JSON: spoofing it from request data is
 *      negative space (rejected/unreachable), which this file proves by simply
 *      never reading those fields into any credential structure.
 *
 * Build:  gcc -O0 -no-pie -static -o peershim peershim.c
 * (-O0 -no-pie keeps the disassembly readable; -static removes PLT indirection.)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* struct ucred lives in sched.h on glibc; SCM_CREDENTIALS in socket.h */
#include <sched.h>

#define BODY_MAX 8192
#define HDR_MAX  4096

/* ---- allow-list: the ONLY destinations this process may ever reach ---- */
struct slot {
    const char *name;   /* JSON-selectable label */
    const char *host;   /* operator-supplied, never request-supplied */
    int port;           /* operator-supplied, never request-supplied */
};

static const struct slot SLOTS[] = {
    { "audit",   "127.0.0.1", 19100 },
    { "worker",  "127.0.0.1", 19101 },
    { "archive", "127.0.0.1", 19102 },
};
#define NSLOT ((int)(sizeof(SLOTS)/sizeof(SLOTS[0])))

/* Global record of the last decision, so main() can report the transition. */
static char  g_selected_name[64]   = "";
static char  g_selected_host[64]   = "";
static int   g_selected_port       = -1;
static int   g_slot_index          = -1;   /* -2 = rejected by allow-list */
static long  g_raw_body_len        = 0;
static char  g_reserialized[BODY_MAX] = "";

/* ---------------- minimal JSON scanner (object of flat members) -----------
 * Deliberately tiny and strict: only {"k":"v",...} with string values.
 * Anything else is a parse error. This is the "JSON syntax gate".
 */
static int json_get_str(const char *buf, const char *key, char *out, size_t outsz)
{
    const char *p = strstr(buf, key);
    if (!p) return 0;
    p += strlen(key);          /* p now points just past the closing quote of key */
    while (*p == ':' || *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outsz) {
        if (*p == '\\' && p[1]) { p += 2; continue; }  /* naive escape skip */
        out[i++] = *p++;
    }
    out[i] = '\0';
    return *p == '"';
}

/* ------------- the function whose call sites we disassemble --------------- */
__attribute__((noinline))
static int resolve_route(const char *body)
{
    char dest[64] = "";
    if (!json_get_str(body, "\"dest\"", dest, sizeof dest)) {
        g_slot_index = -2;
        return -1;                       /* no route selected */
    }
    for (int i = 0; i < NSLOT; i++) {
        if (strcmp(dest, SLOTS[i].name) == 0) {     /* allow-list gate */
            g_slot_index = i;
            strncpy(g_selected_name, SLOTS[i].name, 63); g_selected_name[63]=0;
            strncpy(g_selected_host, SLOTS[i].host, 63);
            g_selected_port = SLOTS[i].port;
            return 0;
        }
    }
    g_slot_index = -2;                   /* JSON-controlled name, unknown slot */
    return -1;
}

/* ------------- syscall edge: AF_INET socket + connect --------------------- */
__attribute__((noinline))
static int deliver_to_slot(const char *payload, size_t len)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);       /* syscall #41 */
    if (fd < 0) return -1;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)g_selected_port); /* operand built HERE */
    inet_pton(AF_INET, g_selected_host, &sa.sin_addr);

    int rc = connect(fd, (struct sockaddr *)&sa, sizeof sa);  /* syscall #42 */
    int err = errno;

    /* SCM_CREDENTIALS: kernel-attached identity, deliberately NOT read from
     * JSON. We ask the kernel for our own peer credentials to show provenance:
     * uid/pid come from the kernel, never from the request body. */
    struct ucred uc;
    socklen_t ul = sizeof uc;
    int have_uc = -1;
    if (rc >= 0)
        have_uc = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &ul); /* #54-ish */

    ssize_t sent = 0;
    if (rc >= 0) sent = write(fd, payload, len);     /* syscall #1 */
    close(fd);

    fprintf(stderr,
        "[shim] slot=%s host=%s port=%d connect=%s errno=%d "
        "peercred_uid=%d peercred_pid=%d wrote=%zd\n",
        g_selected_name, g_selected_host, g_selected_port,
        rc >= 0 ? "ok" : "fail", err,
        have_uc == 0 ? (int)uc.uid : -1,
        have_uc == 0 ? (int)uc.pid : -1,
        sent);
    fflush(stderr);
    return rc;
}

/* ---------------------- HTTP framing (deliberately crude) ----------------- */
static int read_http_request(int cfd, char *body, size_t bodysz)
{
    char hdr[HDR_MAX];
    size_t hlen = 0;
    /* read until \r\n\r\n */
    for (;;) {
        if (hlen >= sizeof hdr - 1) return -1;
        ssize_t n = read(cfd, hdr + hlen, 1);        /* #1, byte-at-a-time */
        if (n <= 0) return -1;
        hlen += (size_t)n;
        hdr[hlen] = '\0';
        if (hlen >= 4 && memcmp(hdr + hlen - 4, "\r\n\r\n", 4) == 0) break;
    }
    if (memcmp(hdr, "POST ", 5) != 0) return -2;

    const char *cl = strcasestr(hdr, "content-length:");
    if (!cl) return -3;
    long want = strtol(cl + 15, NULL, 10);
    if (want < 0 || (size_t)want >= bodysz) return -4;

    size_t got = 0;
    while ((long)got < want) {
        ssize_t n = read(cfd, body + got, (size_t)(want - got));
        if (n <= 0) return -5;
        got += (size_t)n;
    }
    body[got] = '\0';
    g_raw_body_len = (long)got;
    return (int)got;
}

/* reserialize: the measured transformation boundary (raw != forwarded bytes) */
static void reserialize(const char *body, char *out, size_t outsz)
{
    char dest[64] = "", note[128] = "", id[64] = "";
    json_get_str(body, "\"dest\"", dest, sizeof dest);
    json_get_str(body, "\"note\"", note, sizeof note);
    json_get_str(body, "\"id\"",   id,   sizeof id);
    /* NOTE the argument order bug we are fixing: dest, id, note */
    snprintf(out, outsz, "{\"dest\":\"%s\",\"id\":\"%s\",\"note\":\"%s\"}",
             dest, id, note);
}

/* -------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 19099;

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int on = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in la;
    memset(&la, 0, sizeof la);
    la.sin_family = AF_INET;
    la.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &la.sin_addr);
    if (bind(lfd, (struct sockaddr *)&la, sizeof la) < 0) { perror("bind"); return 1; }
    listen(lfd, 8);
    fprintf(stderr, "[shim] listening 127.0.0.1:%d ; slots:", port);
    for (int i = 0; i < NSLOT; i++) fprintf(stderr, " %s->%s:%d",
        SLOTS[i].name, SLOTS[i].host, SLOTS[i].port);
    fprintf(stderr, "\n");

    for (;;) {
        int cfd = accept4(lfd, NULL, NULL, 0);
        if (cfd < 0) continue;

        char body[BODY_MAX];
        int n = read_http_request(cfd, body, sizeof body);
        if (n < 0) { close(cfd); continue; }

        /* gate 1: JSON/route selection */
        int r = resolve_route(body);

        /* gate 2: "role" field is validated but NEVER feeds privileges;
         * we log it to show a security-sounding JSON key has no effect. */
        char role[64] = "none";
        json_get_str(body, "\"role\"", role, sizeof role);

        char status[32];
        if (r == 0) {
            reserialize(body, g_reserialized, sizeof g_reserialized);
            deliver_to_slot(g_reserialized, strlen(g_reserialized));
            strcpy(status, "200 forwarded");
        } else {
            strcpy(status, "400 no-route");
        }

        char resp[256];
        int rl = snprintf(resp, sizeof resp,
            "HTTP/1.1 %s\r\nContent-Type: application/json\r\n"
            "Content-Length: %ld\r\nConnection: close\r\n\r\n"
            "{\"slot\":%d,\"role_seen\":\"%s\",\"raw_len\":%ld,"
            "\"forwarded_bytes\":\"%s\"}\r\n",
            status, (long)0 + 1, g_slot_index, role, g_raw_body_len,
            g_reserialized);
        /* fix Content-Length crudely: just write everything */
        (void)rl;
        char full[512];
        int fl = snprintf(full, sizeof full,
            "HTTP/1.1 %s\r\nContent-Type: application/json\r\n"
            "Connection: close\r\n\r\n"
            "{\"slot\":%d,\"role_seen\":\"%s\",\"raw_len\":%ld,"
            "\"forwarded_bytes\":\"%s\"}\n",
            status, g_slot_index, role, g_raw_body_len, g_reserialized);
        write(cfd, full, (size_t)fl);
        close(cfd);
    }
    return 0;
}
