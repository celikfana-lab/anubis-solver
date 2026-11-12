/*
 * stress_test.c — load test for an Anubis instance you own.
 *
 * Plain-HTTP client, no TLS: connect, read the challenge, solve the proof of
 * work with libanubis_solver, submit pass-challenge, fetch again. One thread
 * per connection, no Python in the loop.
 *
 * Safety: requires --i-own-this-host, only accepts private/loopback addresses
 * unless --allow-remote is given, and caps duration (300 s) and concurrency
 * (4096).
 *
 *   cc -O2 -o stress_test tools/stress_test.c -Iinclude -L. -lanubis_solver \
 *      -Wl,-rpath,'$ORIGIN' -pthread && ./stress_test \
 *      --host 192.168.1.15 --port 8923 --duration 30 --concurrency 256 \
 *      --i-own-this-host
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "anubis-solver.h"

#define MAX_DURATION 300.0
#define MAX_CONCURRENCY 4096
#define RESP_CAP (256u * 1024u)

typedef struct {
    const char *host;
    int port;
    const char *path;
    int allow_remote;
    atomic_ullong cycles;
    atomic_ullong errors;
    atomic_ullong status[8];
} cfg;

static cfg g;

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int is_private_addr(const struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        uint32_t a = ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr);
        return ((a >> 24) == 127) || ((a >> 24) == 10) ||
               ((a & 0xFFF00000u) == 0xAC100000u) ||
               ((a & 0xFFFF0000u) == 0xC0A80000u);
    }
    if (sa->sa_family == AF_INET6) {
        static const unsigned char lo[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 1};
        return memcmp(&((const struct sockaddr_in6 *)sa)->sin6_addr, lo, 16) == 0;
    }
    return 0;
}

static int http_get(const char *host, int port, const char *path,
                    const char *cookie, char *resp, size_t cap, int *status) {
    struct addrinfo hints, *res = NULL;
    char portbuf[16];
    int fd = -1, rc = -1;
    size_t used = 0;

    snprintf(portbuf, sizeof(portbuf), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portbuf, &hints, &res) != 0 || res == NULL) {
        return -1;
    }
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        {
            struct timeval tv = {5, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        return -1;
    }
    {
        char req[8192];
        int n = snprintf(req, sizeof(req),
                         "GET %s HTTP/1.1\r\nHost: %s:%d\r\n"
                         "User-Agent: anubis-stress/1.0\r\n"
                         "Accept: */*\r\n%s%s"
                         "Connection: close\r\n\r\n",
                         path, host, port,
                         cookie ? "Cookie: " : "", cookie ? cookie : "");
        if (send(fd, req, (size_t)n, 0) != n) {
            close(fd);
            return -1;
        }
    }
    for (;;) {
        ssize_t k = recv(fd, resp + used, cap - 1 - used, 0);
        if (k <= 0) {
            break;
        }
        used += (size_t)k;
        if (used >= cap - 1) {
            break;
        }
    }
    close(fd);
    if (used == 0) {
        return -1;
    }
    resp[used] = '\0';
    if (status != NULL) {
        *status = 0;
        sscanf(resp, "HTTP/%*s %d", status);
    }
    rc = (int)used;
    return rc;
}

static int json_str(const char *buf, const char *key, char *out, size_t cap) {
    char pat[64];
    const char *p;
    size_t i = 0;
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    p = strstr(buf, pat);
    if (p == NULL) {
        return 0;
    }
    p += strlen(pat);
    while (*p != '"' && *p != '\0' && i + 1 < cap) {
        if (*p == '\\' && p[1] != '\0') {
            p++;
        }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i > 0;
}

static int json_int(const char *buf, const char *key, long *out) {
    char pat[64];
    const char *p;
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    p = strstr(buf, pat);
    if (p == NULL) {
        return 0;
    }
    *out = strtol(p + strlen(pat), NULL, 10);
    return 1;
}

static int header_value(const char *resp, const char *name, char *out,
                        size_t cap) {
    const char *p = strstr(resp, name);
    size_t i = 0;
    if (p == NULL) {
        return 0;
    }
    p += strlen(name);
    while (*p == ' ') {
        p++;
    }
    while (*p != '\0' && *p != ';' && *p != '\r' && i + 1 < cap) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i > 0;
}

static void urlenc(const char *in, char *out, size_t cap) {
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;
    for (; *in != '\0' && o + 4 < cap; in++) {
        unsigned char c = (unsigned char)*in;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
            c == '~' || c == '/') {
            out[o++] = (char)c;
        } else {
            out[o++] = '%';
            out[o++] = hex[c >> 4];
            out[o++] = hex[c & 15];
        }
    }
    out[o] = '\0';
}

static void *worker(void *arg) {
    (void)arg;
    char *resp = (char *)malloc(RESP_CAP);
    if (resp == NULL) {
        atomic_fetch_add(&g.errors, 1);
        return NULL;
    }
    for (;;) {
        char random_data[4096] = {0}, id[256] = {0}, algo[32] = {0};
        char hex[65] = {0}, cookie[1024] = {0}, redir[1024], resp_enc[256];
        long difficulty = 0;
        int status = 0;
        uint64_t nonce = 0;
        double ms = 0.0;
        int rc, n;

        n = http_get(g.host, g.port, g.path, NULL, resp, RESP_CAP, &status);
        if (n < 0) {
            atomic_fetch_add(&g.errors, 1);
            continue;
        }
        atomic_fetch_add(&g.status[(status / 100) < 8 ? (status / 100) : 7], 1);
        if (getenv("STRESS_DEBUG") != NULL) {
            fprintf(stderr, "[dbg] n=%d status=%d head=%.60s\n", n, status, resp);
        }
        if (strstr(resp, "anubis_challenge") == NULL) {
            atomic_fetch_add(&g.cycles, 1); /* not challenged */
            continue;
        }
        if (!json_str(resp, "randomData", random_data, sizeof(random_data)) ||
            !json_str(resp, "algorithm", algo, sizeof(algo)) ||
            !json_int(resp, "difficulty", &difficulty)) {
            atomic_fetch_add(&g.errors, 1);
            continue;
        }
        json_str(resp, "id", id, sizeof(id));
        if (strcmp(algo, "fast") == 0 || strcmp(algo, "slow") == 0) {
            rc = anubis_solve_nibbles(random_data, (int)difficulty, 1, 0, 0.0,
                                      &nonce, hex, &ms);
        } else if (strcmp(algo, "sha256") == 0 ||
                   strcmp(algo, "wasm-sha256") == 0) {
            uint32_t n32 = 0;
            rc = anubis_solve_bits(random_data, (int)difficulty, 1, 0.0, &n32,
                                   hex, &ms);
            nonce = n32;
        } else {
            atomic_fetch_add(&g.errors, 1);
            continue;
        }
        if (rc != ANUBIS_OK) {
            atomic_fetch_add(&g.errors, 1);
            continue;
        }
        snprintf(redir, sizeof(redir), "http://%s:%d%s", g.host, g.port, g.path);
        urlenc(redir, redir, sizeof(redir));
        urlenc(hex, resp_enc, sizeof(resp_enc));
        {
            char pass[2048];
            n = snprintf(pass, sizeof(pass),
                         "/.within.website/x/cmd/anubis/api/pass-challenge"
                         "?response=%s&nonce=%llu&redir=%s&elapsedTime=%.3f%s%s",
                         resp_enc, (unsigned long long)nonce, redir, ms,
                         id[0] ? "&id=" : "", id);
            if (http_get(g.host, g.port, pass, NULL, resp, RESP_CAP, &status) < 0) {
                atomic_fetch_add(&g.errors, 1);
                continue;
            }
            atomic_fetch_add(&g.status[(status / 100) < 8 ? (status / 100) : 7], 1);
            header_value(resp, "Set-Cookie:", cookie, sizeof(cookie));
        }
        if (cookie[0] != '\0') {
            if (http_get(g.host, g.port, g.path, cookie, resp, RESP_CAP,
                         &status) < 0) {
                atomic_fetch_add(&g.errors, 1);
                continue;
            }
            atomic_fetch_add(&g.status[(status / 100) < 8 ? (status / 100) : 7], 1);
        }
        atomic_fetch_add(&g.cycles, 1);
    }
    free(resp);
    return NULL;
}

int main(int argc, char **argv) {
    const char *host = NULL;
    int port = 8923, concurrency = 64, ack = 0, allow_remote = 0, i;
    const char *path = "/";
    double duration = 30.0, t0, elapsed;
    pthread_t *tids;
    struct addrinfo hints, *res = NULL;
    char portbuf[16];
    int private_ok = 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            duration = atof(argv[++i]);
        } else if (strcmp(argv[i], "--concurrency") == 0 && i + 1 < argc) {
            concurrency = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--i-own-this-host") == 0) {
            ack = 1;
        } else if (strcmp(argv[i], "--allow-remote") == 0) {
            allow_remote = 1;
        } else {
            fprintf(stderr, "unknown or incomplete argument: %s\n", argv[i]);
            return 2;
        }
    }
    if (!ack) {
        fprintf(stderr, "refusing to run: pass --i-own-this-host "
                        "(the target must be yours)\n");
        return 2;
    }
    if (host == NULL) {
        fprintf(stderr, "usage: %s --host HOST [--port N] [--path P] "
                        "[--duration S] [--concurrency N] --i-own-this-host\n",
                argv[0]);
        return 2;
    }
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portbuf, &hints, &res) != 0) {
        fprintf(stderr, "cannot resolve %s\n", host);
        return 2;
    }
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        if (!is_private_addr(ai->ai_addr)) {
            private_ok = 0;
        }
    }
    freeaddrinfo(res);
    if (!private_ok && !allow_remote) {
        fprintf(stderr, "refusing non-private target %s (use --allow-remote if "
                        "you own it)\n", host);
        return 2;
    }
    if (duration < 1.0) {
        duration = 1.0;
    }
    if (duration > MAX_DURATION) {
        duration = MAX_DURATION;
    }
    if (concurrency < 1) {
        concurrency = 1;
    }
    if (concurrency > MAX_CONCURRENCY) {
        concurrency = MAX_CONCURRENCY;
    }
    printf("target http://%s:%d%s | threads %d | duration %.0fs | "
           "lib %s\n", host, port, path, concurrency, duration,
           anubis_solver_version());
    fflush(stdout);

    memset(&g, 0, sizeof(g));
    g.host = host;
    g.port = port;
    g.path = path;
    g.allow_remote = allow_remote;
    tids = (pthread_t *)calloc((size_t)concurrency, sizeof(*tids));
    if (tids == NULL) {
        return 1;
    }
    t0 = now_s();
    for (i = 0; i < concurrency; i++) {
        if (pthread_create(&tids[i], NULL, worker, NULL) != 0) {
            concurrency = i;
            break;
        }
    }
    while (now_s() - t0 < duration) {
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
        printf("  %5.1fs  %8llu cycles (%7.1f/s)\n", now_s() - t0,
               (unsigned long long)g.cycles,
               (double)g.cycles / (now_s() - t0));
        fflush(stdout);
    }
    elapsed = now_s() - t0;
    /* Threads are detached by design: report and exit. */
    {
        unsigned long long cyc = g.cycles, err = g.errors;
        unsigned long long s2 = g.status[2], s3 = g.status[3];
        unsigned long long s4 = g.status[4], s5 = g.status[5];
        printf("\nresults\n");
        printf("  duration    %.1f s\n", elapsed);
        printf("  cycles      %llu  (%.1f/s)\n", cyc, (double)cyc / elapsed);
        printf("  errors      %llu\n", err);
        printf("  status 2xx %llu | 3xx %llu | 4xx %llu | 5xx %llu\n",
               s2, s3, s4, s5);
    }
    return 0;
}
