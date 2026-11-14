/* betterAnusbis — an Anubis-compatible proof-of-work gate, in one C file.
 *
 * It does what Anubis does for a single rule: every request gets a challenge,
 * the client solves it, the server verifies the answer, sets a signed cookie and
 * lets the request through to the backend. Same algorithms, same challenge JSON,
 * same pass-challenge route — so every existing Anubis solver (including ours)
 * works against it unchanged.
 *
 * Deliberately not a policy engine: Anubis's bot rules, weighting, GeoIP and
 * honeypot machinery are the price of being a general gatekeeper. Here there is
 * one rule, set on the command line.
 *
 *   betterAnusbis --listen :8080 --target http://127.0.0.1:3000 --algorithm sha256
 *
 * Verification is done by libanubis_solver.so — the same engine the CLI solves
 * with — so the server and its clients agree bit for bit by construction.
 *
 * Build:  make            (or: cc -O2 -pthread -o betterAnusbis betterAnusbis.c -L.. -lanubis_solver)
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <ctype.h>
#include <regex.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "anubis-solver.h"

/* ----------------------------------------------------------------- config */

#define VERSION "1.15.0"
#define API_PREFIX "/.within.website/x/cmd/anubis/api/"
#define DEFAULT_COOKIE_PREFIX "techaro.lol-anubis"
#define MAX_HEADER 32768
#define MAX_BODY (8u << 20)      /* requests we are willing to buffer */
#define MAX_REPLY (64u << 20)    /* backend responses we are willing to buffer */
#define COOKIE_TTL 604800        /* one week, like Anubis's default */
#define MAX_RULES 64
#define MAX_REDIRECT_PATTERNS 32
#define MAX_GLOB_STARS 4         /* Anubis's own limit in REDIRECT_DOMAINS */

typedef struct {
    const char *listen;
    const char *target;          /* scheme://host[:port] */
    const char *algorithm;
    int difficulty;
    const char *cookie_prefix;
    int verbose;
    /* derived */
    char target_host[256];
    int target_port;
    int target_tls;
    char cookie_name[256];
    uint8_t secret[32];
    int honeypot;                /* 1: render the trap link and run the tarpit */
    const char *honeypot_log;    /* where to append trap hits, or NULL */
    int flag_threshold;          /* trap hits in the window before the network is flagged */
    const char *tls_cert;        /* PEM certificate chain, enables the HTTPS listener */
    const char *tls_key;         /* PEM private key */
    const char *policy_file;     /* optional policy, see policy_load() */
    int stateful;                /* keep issued challenges so they cannot be replayed */
    int target_insecure;         /* skip backend certificate verification */
    const char *web_dir;         /* where the wasm kernels are served from */

    /* Deployment shape. These exist because the flags behind them exist in
     * cmd/anubis, and a gate that cannot be dropped in behind an existing
     * nginx config is a gate nobody deploys. */
    const char *cookie_domain;   /* "" = host-only cookie */
    int cookie_secure;           /* -1: auto, on when we serve TLS; 0/1: forced */
    int cookie_http_only;        /* the page never reads the auth cookie */
    const char *cookie_same_site;/* default, lax, strict, none */
    int cookie_partitioned;      /* CHIPS; dropped when the cookie is not Secure */
    long cookie_ttl;             /* seconds; 0 makes it a session cookie */
    const char *base_prefix;     /* "" or "/prefix", anubis --base-prefix */
    int strip_base_prefix;       /* also strip it before the target */
    const char *real_ip_header;  /* anubis --custom-real-ip-header */
    int use_remote_address;      /* ignore XFF and the custom header entirely */
    int xff_strip_private;       /* anubis --xff-strip-private (default on) */
    const char *redirect_domains;/* extra hosts redir may point at, glob, comma list */
    int challenge_status;        /* status_codes.CHALLENGE, default 200 */
    int deny_status;             /* status_codes.DENY, default 200 like Anubis */
    int serve_robots_txt;        /* anubis --serve-robots-txt */
    const char *target_sni;      /* anubis --target-sni, "auto" = the Host header */
    const char *target_host_hdr; /* anubis --target-host, overrides the Host header */
    int debug_benchmark_js;      /* anubis --debug-benchmark-js: always challenge */
    const char *metrics_bind;    /* "" = no metrics listener at all */
    const char *jwt_restrict_hdr;/* bind the cookie to the client address; "" = off */
    const char *secret_hex;      /* 64 hex chars: the HMAC key, so restarts keep cookies */
    const char *secret_file;     /* read it from here, or create it here with 0600 */
    const char *data_dir;        /* where (data)/... resolves for Anubis policies */
} config;

static config cfg = {
    .listen = ":8080",
    .target = NULL,
    .algorithm = "sha256",
    .difficulty = 4,
    .cookie_prefix = DEFAULT_COOKIE_PREFIX,
    .verbose = 0,
    .honeypot = 1,               /* Anubis enables its honeypot by default too */
    .honeypot_log = NULL,
    .flag_threshold = 25,
    .tls_cert = NULL,
    .tls_key = NULL,
    .policy_file = NULL,
    .stateful = 1,               /* a spent challenge stays spent, like Anubis */
    .target_insecure = 0,
    .web_dir = NULL,
    .cookie_domain = "",
    .cookie_secure = -1,         /* Secure when we serve TLS, not before */
    .cookie_http_only = 1,
    .cookie_same_site = "lax",
    .cookie_partitioned = 1,     /* upstream's default; only emitted with Secure */
    .cookie_ttl = COOKIE_TTL,
    .base_prefix = "",
    .strip_base_prefix = 0,
    .real_ip_header = NULL,
    .use_remote_address = 0,
    .xff_strip_private = 1,
    .redirect_domains = NULL,
    .challenge_status = 200,     /* status_codes.CHALLENGE in Anubis's policy */
    .deny_status = 200,          /* status_codes.DENY, which is also 200 there */
    .serve_robots_txt = 0,
    .target_sni = NULL,
    .target_host_hdr = NULL,
    .debug_benchmark_js = 0,
    .metrics_bind = NULL,        /* upstream defaults to :9090, we default to off */
    .jwt_restrict_hdr = "X-Real-IP",
    .secret_hex = NULL,
    .secret_file = NULL,
    .data_dir = "data",
};

static void logmsg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[betterAnusbis] ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
    va_end(ap);
}

/* --------------------------------------------------------------- helpers */

static void hex_encode(const uint8_t *in, size_t n, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 15];
    }
    out[2 * n] = 0;
}

static int hex_decode(const char *in, uint8_t *out, size_t max) {
    size_t n = strlen(in);
    if (n % 2 || n / 2 > max) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned hi, lo;
        if (sscanf(in + 2 * i, "%1x%1x", &hi, &lo) != 2) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(n / 2);
}

static int random_bytes(uint8_t *out, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, out + got, n - got);
        if (r <= 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

/* base64url without padding, as JWTs use */
static size_t b64url_encode(const uint8_t *in, size_t n, char *out, size_t outcap) {
    static const char *t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        size_t rem = n - i;
        if (o + 4 >= outcap) return 0;
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        if (rem > 1) out[o++] = t[(v >> 6) & 63];
        if (rem > 2) out[o++] = t[v & 63];
    }
    out[o] = 0;
    return o;
}

static int b64url_decode(const char *in, uint8_t *out, size_t outcap) {
    static int8_t map[256];
    static int init = 0;
    if (!init) {
        memset(map, -1, sizeof map);
        const char *t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (int i = 0; i < 64; i++) map[(uint8_t)t[i]] = (int8_t)i;
        map['+'] = 62; map['/'] = 63;   /* tolerate standard base64 */
        init = 1;
    }
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (const char *p = in; *p; p++) {
        if (*p == '=') break;
        int8_t v = map[(uint8_t)*p];
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outcap) return -1;
            out[o++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return (int)o;
}

/* SHA-256 of a byte string, raw digest. Uses our library so the gate and the
 * solver can never disagree about a primitive. */
static int sha256_raw(const uint8_t *data, size_t n, uint8_t out[32]) {
    char hex[65];
    if (anubis_sha256_hex((const char *)data, n, hex) != ANUBIS_OK) return -1;
    return hex_decode(hex, out, 32) == 32 ? 0 : -1;
}

static int hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen,
                       uint8_t out[32]) {
    uint8_t k[64] = {0};
    if (keylen > 64) {
        if (sha256_raw(key, keylen, k) != 0) return -1;
    } else {
        memcpy(k, key, keylen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }

    uint8_t *inner = malloc(64 + msglen);
    if (!inner) return -1;
    memcpy(inner, ipad, 64);
    memcpy(inner + 64, msg, msglen);
    uint8_t ih[32];
    int rc = sha256_raw(inner, 64 + msglen, ih);
    free(inner);
    if (rc != 0) return -1;

    uint8_t outer[64 + 32];
    memcpy(outer, opad, 64);
    memcpy(outer + 64, ih, 32);
    return sha256_raw(outer, 96, out);
}

/* ------------------------------------------------------------ the cookie */

/* A JWT HS256 with the claims Anubis uses, so tools that expect one can read it. */
static int sign_token(char *out, size_t cap, const char *challenge_id,
                      const char *restrict_to, const char *algorithm) {
    char payload[768];
    time_t now = time(NULL);
    /* policyRule is Anubis's rule hash; here it stands for the algorithm+difficulty.
     * Anubis binds the token to the client by default (--jwt-restriction-header,
     * X-Real-IP); so do we, because a cookie that works from any address is a
     * cookie that works from whoever steals it. */
    char restrict_part[128] = "";
    if (restrict_to && *restrict_to && cfg.jwt_restrict_hdr && *cfg.jwt_restrict_hdr)
        snprintf(restrict_part, sizeof restrict_part, ",\"restrict\":\"%s\"", restrict_to);
    snprintf(payload, sizeof payload,
             "{\"challenge\":\"%s\",\"method\":\"%s\",\"policyRule\":\"rule-0\","
             "\"action\":\"CHALLENGE\",\"iat\":%lld,\"exp\":%lld%s}",
             challenge_id ? challenge_id : "issued",
             algorithm && *algorithm ? algorithm : cfg.algorithm,
             (long long)now,
             (long long)(now + (cfg.cookie_ttl > 0 ? cfg.cookie_ttl : COOKIE_TTL)),
             restrict_part);

    const char *header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char h64[256], p64[768];
    if (!b64url_encode((const uint8_t *)header, strlen(header), h64, sizeof h64)) return -1;
    if (!b64url_encode((const uint8_t *)payload, strlen(payload), p64, sizeof p64)) return -1;

    char signing[1024];
    snprintf(signing, sizeof signing, "%s.%s", h64, p64);
    uint8_t mac[32];
    if (hmac_sha256(cfg.secret, sizeof cfg.secret, (const uint8_t *)signing, strlen(signing), mac) != 0)
        return -1;
    char m64[64];
    if (!b64url_encode(mac, 32, m64, sizeof m64)) return -1;
    snprintf(out, cap, "%s.%s", signing, m64);
    return 0;
}

static int verify_token(const char *token, const char *client_ip) {
    const char *dot1 = strchr(token, '.');
    if (!dot1) return 0;
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return 0;

    char signing[1024];
    size_t slen = (size_t)(dot2 - token);
    if (slen >= sizeof signing) return 0;
    memcpy(signing, token, slen);
    signing[slen] = 0;

    uint8_t mac[32];
    if (hmac_sha256(cfg.secret, sizeof cfg.secret, (const uint8_t *)signing, slen, mac) != 0) return 0;
    char want[64];
    if (!b64url_encode(mac, 32, want, sizeof want)) return 0;
    if (strcmp(want, dot2 + 1) != 0) return 0;      /* signature */

    /* expiry, without a JSON parser: find "exp":<number> */
    size_t plen = (size_t)(dot2 - dot1 - 1);
    char payload[768];
    if (plen >= sizeof payload) return 0;
    memcpy(payload, dot1 + 1, plen);
    payload[plen] = 0;
    uint8_t raw[768];
    int n = b64url_decode(payload, raw, sizeof raw - 1);
    if (n < 0) return 0;
    raw[n] = 0;
    char *exp = strstr((char *)raw, "\"exp\":");
    if (exp) {
        long long when = atoll(exp + 6);
        if (when <= (long long)time(NULL)) return 0;
    }
    /* A token minted with a restriction only works for that address. Tokens from
     * before this check existed carry no claim and stay valid, which is what
     * makes the change deployable. */
    char *restrict_claim = strstr((char *)raw, "\"restrict\":\"");
    if (restrict_claim && cfg.jwt_restrict_hdr && *cfg.jwt_restrict_hdr) {
        const char *want = restrict_claim + strlen("\"restrict\":\"");
        const char *end = strchr(want, '"');
        if (!end) return 0;
        size_t n = (size_t)(end - want);
        if (!client_ip || strlen(client_ip) != n || strncmp(want, client_ip, n) != 0) return 0;
    }
    return 1;
}

static const char *find_cookie(const char *headers, const char *name, char *out, size_t cap) {
    const char *p = headers;
    size_t namelen = strlen(name);
    while ((p = strcasestr(p, "cookie:")) != NULL) {
        p += 7;
        while (*p == ' ') p++;
        const char *end = strstr(p, "\r\n");
        if (!end) return NULL;
        const char *q = p;
        while (q < end) {
            while (q < end && (*q == ' ' || *q == ';')) q++;
            if (strncmp(q, name, namelen) == 0 && q[namelen] == '=') {
                const char *v = q + namelen + 1;
                size_t len = 0;
                while (v + len < end && v[len] != ';' && v[len] != ' ' && v[len] != '\r') len++;
                if (len >= cap) len = cap - 1;
                memcpy(out, v, len);
                out[len] = 0;
                return out;
            }
            while (q < end && *q != ';') q++;
        }
        p = end;
    }
    return NULL;
}

/* --------------------------------------------------------- verification */

static int verify_answer(const char *algorithm, const char *random_data, unsigned long long nonce,
                         int difficulty, char *digest_out, size_t digest_cap) {
    char out[65];
    int rc;
    if (!strcasecmp(algorithm, "fast") || !strcasecmp(algorithm, "slow")) {
        rc = anubis_verify_nibbles(random_data, nonce, difficulty, out);
    } else if (!strcasecmp(algorithm, "sha256") || !strcasecmp(algorithm, "wasm-sha256")) {
        rc = anubis_verify_bits(random_data, (uint32_t)nonce, difficulty, out);
    } else if (!strcasecmp(algorithm, "argon2id")) {
        rc = anubis_verify_argon2id(random_data, (uint32_t)nonce, difficulty, out);
    } else if (!strcasecmp(algorithm, "hashx")) {
        rc = anubis_verify_hashx(random_data, (uint32_t)nonce, difficulty, out);
    } else if (!strcasecmp(algorithm, "metarefresh")) {
        char hex[65];
        if (anubis_sha256_hex(random_data, strlen(random_data), hex) != ANUBIS_OK) return -1;
        rc = ANUBIS_OK;                     /* the client's `response` is that digest */
        snprintf(out, sizeof out, "%s", hex);
    } else {
        return -1;
    }
    if (digest_out) snprintf(digest_out, digest_cap, "%s", rc == ANUBIS_OK ? out : "");
    return rc == ANUBIS_OK ? 1 : 0;
}

/* One connection: a socket, and an OpenSSL session when the listener is HTTPS. */
typedef struct {
    int fd;
    void *ssl;                    /* SSL *, or NULL for plain HTTP */
} conn;

static SSL_CTX *server_ctx;       /* the listener's context, once TLS is on */

static ssize_t conn_read(conn *c, void *buf, size_t n);
static ssize_t conn_write(conn *c, const void *buf, size_t n);
static ssize_t send_all(conn *c, const void *buf, size_t n);
static void respond(conn *c, int status, const char *reason, const char *content_type,
                    const char *extra_headers, const char *body, size_t body_len);
static void respond_redirect(conn *c, const char *location, const char *extra_headers);

/* ------------------------------------------- issued challenges (state) */

/* Anubis keeps a spent flag; the stateless id trick (hex(randomData).issued-at)
 * cannot. With state on, an id is looked up, checked, and retired on use, which is
 * what "state verification" means here. The table is fixed: 4096 entries, one per
 * challenge, expiring with the cookie window. */
#define CH_BUCKETS 4096
typedef struct {
    char id[80];
    char rd[65];
    char algorithm[24];
    int difficulty;
    time_t issued;
    int spent;
    int used;
} ch_entry;

static ch_entry ch_table[CH_BUCKETS];
static pthread_mutex_t ch_lock = PTHREAD_MUTEX_INITIALIZER;
static long long ch_issued, ch_accepted, ch_replayed, ch_expired;

static void ch_issue(const char *id, const char *rd, int difficulty, const char *algorithm) {
    if (!cfg.stateful) return;
    time_t now = time(NULL);
    uint32_t h = 2166136261u;
    for (const char *q = id; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
    pthread_mutex_lock(&ch_lock);
    for (int probe = 0; probe < 32; probe++) {
        ch_entry *e = &ch_table[(h + (uint32_t)probe) % CH_BUCKETS];
        if (!e->used || now - e->issued > COOKIE_TTL) {
            snprintf(e->id, sizeof e->id, "%s", id);
            snprintf(e->rd, sizeof e->rd, "%s", rd);
            snprintf(e->algorithm, sizeof e->algorithm, "%s", algorithm);
            e->difficulty = difficulty;
            e->issued = now;
            e->spent = 0;
            e->used = 1;
            ch_issued++;
            pthread_mutex_unlock(&ch_lock);
            return;
        }
        if (!strcmp(e->id, id)) {          /* re-issued: refresh it */
            snprintf(e->rd, sizeof e->rd, "%s", rd);
            snprintf(e->algorithm, sizeof e->algorithm, "%s", algorithm);
            e->difficulty = difficulty;
            e->issued = now;
            e->spent = 0;
            pthread_mutex_unlock(&ch_lock);
            return;
        }
    }
    pthread_mutex_unlock(&ch_lock);        /* table full: the stateless path covers us */
}

/* 1 accepted (and retired), 0 unknown, -1 expired, -2 already spent */
static int ch_take(const char *id, char *rd_out, size_t rd_cap, int *difficulty_out,
                   char *algo_out, size_t algo_cap) {
    time_t now = time(NULL);
    uint32_t h = 2166136261u;
    for (const char *q = id; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
    int rc = 0;
    pthread_mutex_lock(&ch_lock);
    for (int probe = 0; probe < 32; probe++) {
        ch_entry *e = &ch_table[(h + (uint32_t)probe) % CH_BUCKETS];
        if (!e->used) break;
        if (strcmp(e->id, id) != 0) continue;
        if (now - e->issued > COOKIE_TTL) { rc = -1; ch_expired++; break; }
        if (e->spent) { rc = -2; ch_replayed++; break; }
        e->spent = 1;
        snprintf(rd_out, rd_cap, "%s", e->rd);
        if (difficulty_out) *difficulty_out = e->difficulty;
        if (algo_out) snprintf(algo_out, algo_cap, "%s", e->algorithm);
        ch_accepted++;
        rc = 1;
        break;
    }
    pthread_mutex_unlock(&ch_lock);
    return rc;
}

/* Which algorithm was this id issued for, without spending it? The metarefresh
 * path has to know before it decides whether any work is involved. */
static int ch_peek_algorithm(const char *id, char *out, size_t cap) {
    if (!cfg.stateful || !id) return 0;
    uint32_t h = 2166136261u;
    for (const char *q = id; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
    int found = 0;
    pthread_mutex_lock(&ch_lock);
    for (int probe = 0; probe < 32; probe++) {
        ch_entry *e = &ch_table[(h + (uint32_t)probe) % CH_BUCKETS];
        if (!e->used) break;
        if (strcmp(e->id, id) != 0) continue;
        snprintf(out, cap, "%s", e->algorithm);
        found = 1;
        break;
    }
    pthread_mutex_unlock(&ch_lock);
    return found;
}

/* ------------------------------------------------------------ honeypot */

/* Anubis's honeypot, as internal/honeypot/naive does it:
 *
 *   - every challenge page carries a link inside <script type="ignore">, which a
 *     browser never renders and a crawler that parses HTML happily follows
 *   - following it counts as a bot: the network (IPv4 /24, IPv6 /64) gets a hit,
 *     the server sleeps min(count^2, 1000) ms before answering - a tarpit, so the
 *     crawler spends its budget waiting - and the answer is a page of filler with
 *     more links, so it keeps going
 *   - hits are logged, and once a network has crossed the threshold its requests
 *     get a harder challenge (Anubis raises a policy weight by 30; with no policy
 *     engine here the analogue is difficulty +8 bits)
 *
 * The state is a fixed table with a one-hour window. No file, no daemon.
 */
#define HP_BUCKETS 4096
#define HP_WINDOW 3600

typedef struct {
    uint64_t key;
    int count;
    time_t last;
    int used;
} hp_entry;

static hp_entry hp_table[HP_BUCKETS];
static pthread_mutex_t hp_lock = PTHREAD_MUTEX_INITIALIZER;
static long long hp_hits_total;

/* ---------------------------------------------------------------- metrics
 *
 * Upstream serves Prometheus metrics on its own listener (--metrics-bind, :9090
 * by default) plus /healthz. The names follow lib/anubis.go so an existing
 * dashboard keeps working; the labels are fewer, because there is no ASN and no
 * asn_description to fill in.
 *
 * The listener is off unless --metrics-bind is given. Anubis opening :9090 to
 * the world by default is not a habit worth copying: those counters describe
 * your traffic and nothing here authenticates the reader.
 */
enum {
    M_CHALLENGED, M_ALLOWED, M_PROXIED, M_DENIED, M_API, M_STATIC, M_HONEYPOT,
    M_RESULTS
};
static const char *const m_result_names[M_RESULTS] = {
    "challenged", "allowed", "proxied", "denied", "api", "static", "honeypot"
};
static unsigned long long m_requests[M_RESULTS];
static unsigned long long m_issued, m_validated, m_failed, m_proxied;
static int rule_count;          /* defined with the rule table, far below */
static int default_action;      /* ditto, initialised down there too */
/* policy results, by rule index (MAX_RULES is the "default" slot) and action */
static unsigned long long m_policy[MAX_RULES + 1][4];
static const char *const m_policy_actions[4] = {"ALLOW", "DENY", "CHALLENGE", "WEIGH"};
static long long hp_networks_flagged;

/* IPv4 /24, IPv6 /64 as one 64-bit key (the IPv4 case leaves the top bits zero). */
static uint64_t network_key(const char *ip) {
    struct in_addr v4;
    struct in6_addr v6;
    if (strchr(ip, ':') == NULL) {
        if (inet_pton(AF_INET, ip, &v4) != 1) return 0;
        return (uint64_t)(ntohl(v4.s_addr) & 0xFFFFFF00u);
    }
    if (inet_pton(AF_INET6, ip, &v6) != 1) return 0;
    uint64_t hi;
    memcpy(&hi, &v6.s6_addr[0], 8);
    return hi | (1ull << 63);           /* keep v6 keys out of the v4 range */
}

static void hp_record(const char *ip) {
    if (!cfg.honeypot) return;
    uint64_t key = network_key(ip);
    if (!key) return;
    time_t now = time(NULL);
    pthread_mutex_lock(&hp_lock);
    uint64_t slot = key % HP_BUCKETS;
    for (int probe = 0; probe < 32; probe++) {
        hp_entry *e = &hp_table[(slot + probe) % HP_BUCKETS];
        if (e->used && e->key == key) {
            if (now - e->last > HP_WINDOW) e->count = 0;
            e->count++;
            e->last = now;
            hp_hits_total++;
            pthread_mutex_unlock(&hp_lock);
            goto report;
        }
        if (!e->used || now - e->last > HP_WINDOW) {
            e->used = 1;
            e->key = key;
            e->count = 1;
            e->last = now;
            hp_hits_total++;
            pthread_mutex_unlock(&hp_lock);
            goto report;
        }
    }
    pthread_mutex_unlock(&hp_lock);
    return;

report:
    if (cfg.honeypot_log) {
        FILE *f = fopen(cfg.honeypot_log, "a");
        if (f) {
            fprintf(f, "%ld %s %llu\n", (long)now, ip, (unsigned long long)key);
            fclose(f);
        }
    }
    if (cfg.verbose) logmsg("honeypot: hit from %s (network %llu)", ip, (unsigned long long)key);
}

/* Hits for this network inside the window, without counting a new one. */
static int hp_count(const char *ip) {
    if (!cfg.honeypot) return 0;
    uint64_t key = network_key(ip);
    if (!key) return 0;
    time_t now = time(NULL);
    int count = 0;
    pthread_mutex_lock(&hp_lock);
    uint64_t slot = key % HP_BUCKETS;
    for (int probe = 0; probe < 32; probe++) {
        hp_entry *e = &hp_table[(slot + probe) % HP_BUCKETS];
        if (!e->used) break;
        if (e->used && e->key == key) {
            if (now - e->last <= HP_WINDOW) count = e->count;
            break;
        }
    }
    pthread_mutex_unlock(&hp_lock);
    if (count >= cfg.flag_threshold) {
        pthread_mutex_lock(&hp_lock);
        hp_networks_flagged++;
        pthread_mutex_unlock(&hp_lock);
    }
    return count;
}

/* The tarpit: min(hits^2, 1000) ms, exactly Anubis's curve. */
static void hp_tarpit(int count) {
    long long ms = (long long)count * count;
    if (ms > 1000) ms = 1000;
    if (ms > 0) usleep((useconds_t)ms * 1000);
}

/* Filler for a maze page. Anubis fills it from spintax templates; plain
 * generated text is enough to keep a crawler reading and costs nothing. */
static const char *HP_FILLER[] = {
    "The archive continues below. Each entry is cross-referenced with three others.",
    "Index of documents. Links are stable and safe to follow.",
    "This section was migrated in 2019 and kept for reference.",
    "Related material may be found under the previous heading.",
    "The appendix lists every revision with its editor and date.",
    "Additional reading is collected at the end of each chapter.",
    "Figures referenced in this chapter appear after the bibliography.",
    "Corrections are noted inline where the record disagrees with the source.",
};
#define HP_FILLER_N (int)(sizeof HP_FILLER / sizeof HP_FILLER[0])

static void honeypot_maze(conn *c, const char *id, const char *stage, const char *ip, int count) {
    size_t cap = 65536;
    char *body = malloc(cap);
    if (!body) { respond(c, 500, "Internal Server Error", NULL, NULL, "oom", 3); return; }

    size_t off = (size_t)snprintf(body, cap,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"robots\" content=\"noindex,nofollow\">"
        "<title>Document index</title><style>body{font:15px/1.7 Georgia,serif;max-width:52rem;"
        "margin:3rem auto;padding:0 1rem;color:#222}a{color:#0645ad;text-decoration:none}"
        "li{margin:.35rem 0}h2{font-size:1.05rem;margin:2rem 0 .5rem}</style></head><body>"
        "<h1>Document index</h1>");

    /* every page links further in, so a crawler that follows one follows all */
    for (int section = 0; section < 6 && off + 2048 < cap; section++) {
        off += (size_t)snprintf(body + off, cap - off, "<h2>Section %d</h2><ul>", section + 1);
        for (int link = 0; link < 6 && off + 512 < cap; link++) {
            uint8_t r[16];
            char rid[33];
            if (random_bytes(r, sizeof r) != 0) memset(r, 0, sizeof r);
            hex_encode(r, sizeof r, rid);
            off += (size_t)snprintf(body + off, cap - off,
                "<li><a href=\"" API_PREFIX "honeypot/%s/%s\">%s</a></li>",
                rid, stage ? stage : "maze", HP_FILLER[(section * 6 + link) % HP_FILLER_N]);
        }
        off += (size_t)snprintf(body + off, cap - off, "</ul>");
    }
    off += (size_t)snprintf(body + off, cap - off,
        "<p><small>Entries: %d. This index is generated per request; nothing here is cached."
        "</small></p></body></html>", count);

    char extra[256];
    snprintf(extra, sizeof extra, "X-Robots-Tag: noindex, nofollow\r\nX-Honeypot: %s\r\n", id);
    respond(c, 200, "OK", "text/html; charset=utf-8", extra, body, off);
    free(body);
}

/* --------------------------------------------------------------- http io */

typedef struct {
    char method[16];
    char path[4096];
    char query[4096];
    char version[16];
    char *headers;          /* raw, NUL-terminated */
    char *body;
    size_t body_len;
} request;

static ssize_t conn_read(conn *c, void *buf, size_t n) {
    if (!c->ssl) return read(c->fd, buf, n);
    int r = SSL_read((SSL *)c->ssl, buf, (int)n);
    if (r <= 0) {
        int err = SSL_get_error((SSL *)c->ssl, r);
        if (err == SSL_ERROR_ZERO_RETURN) return 0;
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return -1;
        return r;
    }
    return r;
}

static ssize_t conn_write(conn *c, const void *buf, size_t n) {
    if (!c->ssl) return write(c->fd, buf, n);
    int r = SSL_write((SSL *)c->ssl, buf, (int)n);
    return r <= 0 ? -1 : r;
}

static ssize_t send_all(conn *c, const void *buf, size_t n) {
    const char *p = buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = conn_write(c, p + sent, n - sent);
        if (w <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return (ssize_t)sent;
}

static int read_headers(conn *c, char *buf, size_t cap) {
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t r = conn_read(c, buf + used, cap - 1 - used);
        if (r <= 0) return used > 0 ? (int)used : -1;
        used += (size_t)r;
        buf[used] = 0;
        if (strstr(buf, "\r\n\r\n")) return (int)used;
    }
    return -1;
}

static int parse_request(const char *raw, request *req) {
    memset(req, 0, sizeof *req);
    const char *eol = strstr(raw, "\r\n");
    if (!eol) return -1;
    char line[4096];
    size_t len = (size_t)(eol - raw);
    if (len >= sizeof line) return -1;
    memcpy(line, raw, len);
    line[len] = 0;
    char target[4096];
    if (sscanf(line, "%15s %4095s %15s", req->method, target, req->version) != 3) return -1;

    char *q = strchr(target, '?');
    if (q) {
        *q++ = 0;
        snprintf(req->query, sizeof req->query, "%s", q);
    }
    snprintf(req->path, sizeof req->path, "%s", target);
    req->headers = strdup(eol + 2);
    return req->headers ? 0 : -1;
}

static const char *header_value(const request *req, const char *name) {
    static __thread char value[1024];
    size_t namelen = strlen(name);
    const char *p = req->headers;
    while (p && *p) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        if (!strncasecmp(p, name, namelen) && p[namelen] == ':') {
            const char *v = p + namelen + 1;
            while (*v == ' ') v++;
            size_t n = (size_t)(eol - v);
            if (n >= sizeof value) n = sizeof value - 1;
            memcpy(value, v, n);
            value[n] = 0;
            return value;
        }
        p = eol + 2;
    }
    return NULL;
}

/* ------------------------------------------------------- response helpers */

static void sb_app(char *buf, size_t cap, size_t *len, const char *fmt, ...) {
    if (*len + 1 >= cap) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *len, cap - *len, fmt, ap);
    va_end(ap);
    if (n > 0) {
        *len += (size_t)n;
        if (*len > cap - 1) *len = cap - 1;
    }
}

static const char *reason_for(int status) {
    switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 418: return "I'm a teapot";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    default: return status >= 400 ? "Error" : "OK";
    }
}

/* --------------------------------------------------------------- cookies */

/* One place decides the cookie attributes, because every response that sets the
 * auth cookie has to agree on them.
 *
 * Two deliberate differences from Anubis's defaults: no Secure unless we are
 * actually serving TLS (a Secure cookie handed out over plain HTTP is silently
 * dropped by the browser, and this gate is often run on loopback behind a TLS
 * terminator), and HttpOnly on by default (nothing in the page reads the auth
 * cookie; the -cookie-verification marker that the page does look at never gets
 * HttpOnly, so that is not affected).
 */
static int cookie_use_secure(void) {
    if (cfg.cookie_secure >= 0) return cfg.cookie_secure;
    return cfg.tls_cert != NULL;
}

/* max_age > 0 sets Max-Age, 0 makes it an immediate delete, < 0 a session cookie. */
static void cookie_attrs(char *out, size_t cap, long max_age) {
    int secure = cookie_use_secure();
    const char *ss = cfg.cookie_same_site && *cfg.cookie_same_site ? cfg.cookie_same_site : "lax";
    const char *same = "";
    if (!strcasecmp(ss, "none")) same = secure ? "None" : "Lax";   /* None needs Secure */
    else if (!strcasecmp(ss, "lax")) same = "Lax";
    else if (!strcasecmp(ss, "strict")) same = "Strict";
    else if (!strcasecmp(ss, "default")) same = "";

    size_t len = 0;
    out[0] = 0;
    sb_app(out, cap, &len, "; Path=/");
    if (cfg.cookie_domain && *cfg.cookie_domain)
        sb_app(out, cap, &len, "; Domain=%s", cfg.cookie_domain);
    if (max_age >= 0) sb_app(out, cap, &len, "; Max-Age=%ld", max_age);
    if (*same) sb_app(out, cap, &len, "; SameSite=%s", same);
    if (secure) sb_app(out, cap, &len, "; Secure");
    if (cfg.cookie_http_only) sb_app(out, cap, &len, "; HttpOnly");
    /* CHIPS: Partitioned is only honoured on a Secure cookie */
    if (cfg.cookie_partitioned && secure) sb_app(out, cap, &len, "; Partitioned");
}

/* ---------------------------------------------------------------- the client IP
 *
 * Anubis reads X-Forwarded-For and flattens it: from right to left, the first
 * address that is not one of its own hops is the client. CGNAT and link-local
 * hops are always skipped, RFC1918 ones are skipped unless --xff-strip-private
 * is off.
 *
 * One deliberate difference: we only believe the header when the peer is itself
 * loopback or private, which is what a proxy on the same host or LAN looks like.
 * Anubis believes it from anyone, which turns a directly exposed gate into a
 * client-IP forgery machine. A proxy on a public address needs
 * --custom-real-ip-header, exactly as the upstream docs advise.
 */
#define ADDR_PRIVATE 1
#define ADDR_CGNAT 2
#define ADDR_LOOPBACK 4
#define ADDR_LINKLOCAL 8

static int addr_class(const char *ip) {
    struct in_addr v4;
    struct in6_addr v6;
    if (!strchr(ip, ':')) {
        if (inet_pton(AF_INET, ip, &v4) != 1) return 0;
        uint32_t a = ntohl(v4.s_addr);
        if ((a >> 24) == 127) return ADDR_LOOPBACK | ADDR_PRIVATE;
        if ((a >> 24) == 10) return ADDR_PRIVATE;        /* 10.0.0.0/8 */
        if ((a >> 20) == 0xAC1) return ADDR_PRIVATE;     /* 172.16.0.0/12 */
        if ((a >> 16) == 0xC0A8) return ADDR_PRIVATE;    /* 192.168.0.0/16 */
        if ((a >> 22) == 0x191) return ADDR_CGNAT;       /* 100.64.0.0/10 */
        if ((a >> 16) == 0xA9FE) return ADDR_LINKLOCAL;  /* 169.254.0.0/16 */
        return 0;
    }
    if (inet_pton(AF_INET6, ip, &v6) != 1) return 0;
    static const uint8_t loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    static const uint8_t mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    if (!memcmp(&v6, loop, 16)) return ADDR_LOOPBACK | ADDR_PRIVATE;
    if ((v6.s6_addr[0] & 0xfe) == 0xfc) return ADDR_PRIVATE;              /* fc00::/7 */
    if (v6.s6_addr[0] == 0xfe && (v6.s6_addr[1] & 0xc0) == 0x80) return ADDR_LINKLOCAL;
    if (!memcmp(v6.s6_addr, mapped, 12)) {
        char v4s[32];
        snprintf(v4s, sizeof v4s, "%u.%u.%u.%u", v6.s6_addr[12], v6.s6_addr[13],
                 v6.s6_addr[14], v6.s6_addr[15]);
        return addr_class(v4s);
    }
    return 0;
}

/* One list element to a bare address: trims spaces, drops "[..]" and an IPv4 port. */
static void addr_token(char *out, size_t cap, const char *s, size_t n) {
    while (n && (*s == ' ' || *s == '\t')) { s++; n--; }
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) n--;
    if (n && s[0] == '[') {
        const char *close = memchr(s, ']', n);
        if (close) { n = (size_t)(close - s) - 1; s++; }
    } else {
        const char *colon = memchr(s, ':', n);
        if (colon && !memchr(colon + 1, ':', n - (size_t)(colon - s) - 1))
            n = (size_t)(colon - s);       /* exactly one colon: it is a port */
    }
    if (n >= cap) n = cap - 1;
    memcpy(out, s, n);
    out[n] = 0;
}

/* A dual-stack listener reports an IPv4 client as ::ffff:a.b.c.d. Left alone it
 * breaks every CIDR rule and the honeypot's /24 bucketing, so it is folded back
 * to the dotted form before anyone looks at it. */
static void normalize_ip(char *ip, size_t cap) {
    struct in6_addr v6;
    static const uint8_t mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    if (!strchr(ip, ':')) return;
    if (inet_pton(AF_INET6, ip, &v6) != 1) return;
    if (memcmp(v6.s6_addr, mapped, 12) != 0) return;
    char v4[32];
    snprintf(v4, sizeof v4, "%u.%u.%u.%u", v6.s6_addr[12], v6.s6_addr[13],
             v6.s6_addr[14], v6.s6_addr[15]);
    snprintf(ip, cap, "%s", v4);
}

static const char *client_address(const request *req, const char *peer, char *out, size_t cap) {
    out[0] = 0;
    if (!cfg.use_remote_address) {
        if (cfg.real_ip_header && *cfg.real_ip_header) {
            const char *v = header_value(req, cfg.real_ip_header);
            if (v && *v) {
                char tok[64];
                addr_token(tok, sizeof tok, v, strlen(v));
                if (tok[0]) { snprintf(out, cap, "%s", tok); normalize_ip(out, cap); return out; }
            }
        }
        const char *xff = header_value(req, "X-Forwarded-For");
        if (xff && *xff && (addr_class(peer) & ADDR_PRIVATE)) {
            char copy[512];
            snprintf(copy, sizeof copy, "%s", xff);
            char *tokens[16];
            int ntok = 0;
            for (char *p = copy; p && *p && ntok < 16; ) {
                tokens[ntok++] = p;
                char *comma = strchr(p, ',');
                if (!comma) break;
                *comma = 0;
                p = comma + 1;
            }
            for (int i = ntok - 1; i >= 0; i--) {
                char tok[64];
                addr_token(tok, sizeof tok, tokens[i], strlen(tokens[i]));
                if (!tok[0]) continue;
                snprintf(out, cap, "%s", tok);
                normalize_ip(out, cap);
                int cls = addr_class(tok);
                if (cls == 0) return out;                        /* public: this is the client */
                if (cls & ADDR_CGNAT) continue;
                if (cls & ADDR_LINKLOCAL) continue;
                if ((cls & ADDR_PRIVATE) && cfg.xff_strip_private) continue;
                return out;
            }
            if (out[0]) return out;      /* every hop was ours: keep the leftmost */
        }
    }
    snprintf(out, cap, "%s", peer);
    normalize_ip(out, cap);
    return out;
}

/* ------------------------------------------------------------- the redirect
 *
 * Anubis allows its post-challenge redirect to point anywhere unless
 * REDIRECT_DOMAINS is set, which makes the challenge endpoint a redirector for
 * anyone who can hand you a pre-solved link. Here the default is the strict
 * one: a path on this host, or a host the operator named with
 * --redirect-domains (comma list, glob, at most four stars each, same limit as
 * Anubis).
 */
static int glob_match(const char *pat, const char *text, int stars) {
    while (*pat) {
        if (*pat == '*') {
            if (stars <= 0) return 0;
            while (*pat == '*') pat++;
            if (!*pat) return 1;
            for (const char *t = text;; t++) {
                if (glob_match(pat, t, stars - 1)) return 1;
                if (!*t) return 0;
            }
        }
        if (!*text) return 0;
        if (tolower((unsigned char)*pat) != tolower((unsigned char)*text)) return 0;
        pat++;
        text++;
    }
    return *text == 0;
}

static int host_in_redirect_list(const char *authority) {
    if (!cfg.redirect_domains || !*cfg.redirect_domains || !*authority) return 0;
    char copy[1024];
    snprintf(copy, sizeof copy, "%s", cfg.redirect_domains);
    int hits = 0;
    for (char *p = copy; p && *p && hits < MAX_REDIRECT_PATTERNS;) {
        char *comma = strchr(p, ',');
        if (comma) *comma = 0;
        char *pat = p;
        while (*pat == ' ' || *pat == '\t') pat++;
        size_t n = strlen(pat);
        while (n && (pat[n - 1] == ' ' || pat[n - 1] == '\t')) pat[--n] = 0;
        if (*pat) {
            int stars = 0;
            for (const char *q = pat; *q; q++) if (*q == '*') stars++;
            hits++;
            if (stars <= MAX_GLOB_STARS && glob_match(pat, authority, stars)) return 1;
        }
        p = comma ? comma + 1 : NULL;
    }
    return 0;
}

static const char *safe_redirect(const request *req, const char *redir, char *out, size_t cap) {
    if (!redir || !*redir) return "/";
    /* anything that could split the response header is not a redirect */
    for (const char *p = redir; *p; p++)
        if ((unsigned char)*p < 0x20 || *p == 0x7f || *p == ' ') return "/";
    if (redir[0] == '/') {
        if (redir[1] != '/' && redir[1] != '\\') {
            snprintf(out, cap, "%s", redir);
            return out;
        }
        /* scheme-relative: "//host/path", the authority is in the path */
        char authority[256];
        size_t i = 0;
        for (const char *p = redir + 2; *p && *p != '/' && *p != '?' && i < sizeof authority - 1; p++)
            authority[i++] = *p;
        authority[i] = 0;
        if (host_in_redirect_list(authority)) { snprintf(out, cap, "%s", redir); return out; }
        return "/";
    }
    const char *sep = strstr(redir, "://");
    if (!sep) return "/";
    const char *auth = sep + 3;
    const char *end = strpbrk(auth, "/?#");
    size_t alen = end ? (size_t)(end - auth) : strlen(auth);
    char authority[512];
    if (alen >= sizeof authority) return "/";
    memcpy(authority, auth, alen);
    authority[alen] = 0;
    char *at = strrchr(authority, '@');
    if (at) memmove(authority, at + 1, strlen(at + 1) + 1);   /* drop userinfo */
    if (!*authority) return "/";
    const char *host = header_value(req, "Host");
    if (host && *host && !strcasecmp(authority, host)) { snprintf(out, cap, "%s", redir); return out; }
    if (host_in_redirect_list(authority)) { snprintf(out, cap, "%s", redir); return out; }
    return "/";
}

static const char *query_param(const char *query, const char *name, char *out, size_t cap) {
    size_t namelen = strlen(name);
    const char *p = query;
    while (p && *p) {
        if (!strncmp(p, name, namelen) && p[namelen] == '=') {
            const char *v = p + namelen + 1;
            size_t n = 0;
            while (v[n] && v[n] != '&' && n < cap - 1) {
                out[n] = v[n] == '+' ? ' ' : v[n];
                n++;
            }
            out[n] = 0;
            /* percent-decode in place */
            char *r = out, *w = out;
            while (*r) {
                if (*r == '%' && r[1] && r[2]) {
                    unsigned hi, lo;
                    if (sscanf(r + 1, "%1x%1x", &hi, &lo) == 2) {
                        *w++ = (char)((hi << 4) | lo);
                        r += 3;
                        continue;
                    }
                }
                *w++ = *r++;
            }
            *w = 0;
            return out;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
    return NULL;
}

static void respond(conn *c, int status, const char *reason, const char *content_type,
                    const char *extra_headers, const char *body, size_t body_len) {
    char head[2048];
    int n = snprintf(head, sizeof head,
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "Cache-Control: no-store\r\n"
                     "X-Powered-By: betterAnusbis/" VERSION "\r\n"
                     "%s"
                     "\r\n",
                     status, reason, content_type ? content_type : "text/plain; charset=utf-8",
                     body_len, extra_headers ? extra_headers : "");
    if (n > 0) send_all(c, head, (size_t)n);
    if (body && body_len) send_all(c, body, body_len);
}

static void respond_redirect(conn *c, const char *location, const char *extra_headers) {
    char head[4096];
    int n = snprintf(head, sizeof head,
                     "HTTP/1.1 302 Found\r\n"
                     "Location: %s\r\n"
                     "Content-Length: 0\r\n"
                     "Connection: close\r\n"
                     "%s"
                     "\r\n",
                     location, extra_headers ? extra_headers : "");
    if (n > 0) send_all(c, head, (size_t)n);
}

/* ---------------------------------------------------------------- metrics */

static size_t render_metrics(char *buf, size_t cap) {
    size_t o = 0;
    sb_app(buf, cap, &o,
           "# HELP anubis_challenges_issued The total number of challenges issued\n"
           "# TYPE anubis_challenges_issued counter\n"
           "anubis_challenges_issued{method=\"%s\"} %llu\n"
           "# HELP anubis_challenges_validated The total number of challenges validated\n"
           "# TYPE anubis_challenges_validated counter\n"
           "anubis_challenges_validated{method=\"%s\"} %llu\n"
           "# HELP anubis_failed_validations The total number of failed validations\n"
           "# TYPE anubis_failed_validations counter\n"
           "anubis_failed_validations{method=\"%s\"} %llu\n"
           "# HELP anubis_proxied_requests_total Number of requests proxied to the upstream\n"
           "# TYPE anubis_proxied_requests_total counter\n"
           "anubis_proxied_requests_total{host=\"%s\"} %llu\n",
           cfg.algorithm, m_issued, cfg.algorithm, m_validated, cfg.algorithm, m_failed,
           cfg.target_host, m_proxied);

    /* One line per rule index, which is the closest thing the flat policy file
     * has to Anubis's rule names. */
    sb_app(buf, cap, &o,
           "# HELP anubis_policy_results The results of each policy rule\n"
           "# TYPE anubis_policy_results counter\n");
    for (int r = 0; r <= rule_count; r++) {
        const char *label = r == rule_count ? "default" : "rule";
        for (int a = 0; a < 4; a++) {
            if (!m_policy[r][a]) continue;
            if (r == rule_count)
                sb_app(buf, cap, &o, "anubis_policy_results{rule=\"%s\",action=\"%s\"} %llu\n",
                       label, m_policy_actions[a], m_policy[r][a]);
            else
                sb_app(buf, cap, &o,
                       "anubis_policy_results{rule=\"%s %d\",action=\"%s\"} %llu\n",
                       label, r, m_policy_actions[a], m_policy[r][a]);
        }
    }
    /* give the family one sample even before the first request, so a scrape
     * right after start is not an empty series */
    if (m_policy[rule_count][(int)default_action] == 0)
        sb_app(buf, cap, &o, "anubis_policy_results{rule=\"default\",action=\"%s\"} 0\n",
               m_policy_actions[(int)default_action]);

    sb_app(buf, cap, &o, "# HELP anubis_requests_total Requests by outcome\n"
                         "# TYPE anubis_requests_total counter\n");
    for (int i = 0; i < M_RESULTS; i++)
        sb_app(buf, cap, &o, "anubis_requests_total{result=\"%s\"} %llu\n",
               m_result_names[i], m_requests[i]);

    sb_app(buf, cap, &o,
           "# HELP anubis_honeypot_hits_total Trap links followed\n"
           "# TYPE anubis_honeypot_hits_total counter\n"
           "anubis_honeypot_hits_total %lld\n"
           "# HELP anubis_honeypot_networks_flagged Networks that crossed the threshold\n"
           "# TYPE anubis_honeypot_networks_flagged gauge\n"
           "anubis_honeypot_networks_flagged %lld\n"
           "# HELP anubis_challenges_replayed_total Challenges submitted twice\n"
           "# TYPE anubis_challenges_replayed_total counter\n"
           "anubis_challenges_replayed_total %lld\n"
           "# HELP anubis_challenges_expired_total Challenges older than the window\n"
           "# TYPE anubis_challenges_expired_total counter\n"
           "anubis_challenges_expired_total %lld\n"
           "# HELP betteranusbis_build_info The build serving these metrics\n"
           "# TYPE betteranusbis_build_info gauge\n"
           "betteranusbis_build_info{version=\"%s\",algorithm=\"%s\"} 1\n",
           hp_hits_total, hp_networks_flagged, ch_replayed, ch_expired,
           VERSION, cfg.algorithm);
    return o;
}

static void *metrics_thread(void *arg) {
    int fd = *(int *)arg;
    free(arg);
    for (;;) {
        int client = accept(fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            break;
        }
        conn k = {.fd = client, .ssl = NULL};
        char *raw = malloc(MAX_HEADER + 1);
        if (raw) {
            int n = read_headers(&k, raw, MAX_HEADER + 1);
            if (n > 0) {
                raw[n] = 0;
                request rq;
                if (parse_request(raw, &rq) == 0 && !strcmp(rq.method, "GET")) {
                    if (!strcmp(rq.path, "/metrics")) {
                        char *body = malloc(65536);
                        if (body) {
                            size_t len = render_metrics(body, 65536);
                            respond(&k, 200, "OK", "text/plain; version=0.0.4; charset=utf-8",
                                    NULL, body, len);
                            free(body);
                        } else {
                            respond(&k, 500, "Internal Server Error", NULL, NULL, "oom\n", 4);
                        }
                    } else if (!strcmp(rq.path, "/healthz")) {
                        respond(&k, 200, "OK", NULL, NULL, "OK\n", 3);
                    } else {
                        respond(&k, 404, "Not Found", NULL, NULL,
                                "GET /metrics or /healthz\n", 25);
                    }
                } else {
                    respond(&k, 400, "Bad Request", NULL, NULL, "bad request\n", 12);
                }
            }
            free(raw);
        }
        close(client);
    }
    return NULL;
}

/* ------------------------------------------------------------ the proxy */

static int connect_target(void) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port[16];
    snprintf(port, sizeof port, "%d", cfg.target_port);
    if (getaddrinfo(cfg.target_host, port, &hints, &res) != 0 || !res) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* TLS to the backend, for --target https://. Verification is on by default;
 * --target-insecure exists for self-signed internal backends and says so in the
 * log, so nobody turns it on by accident. */
static int target_connect(conn *up) {
    int fd = connect_target();
    if (fd < 0) return -1;
    up->fd = fd;
    up->ssl = NULL;
    if (!cfg.target_tls) return fd;

    static SSL_CTX *client_ctx;
    if (!client_ctx) {
        client_ctx = SSL_CTX_new(TLS_client_method());
        if (!client_ctx) { close(fd); return -1; }
        SSL_CTX_set_min_proto_version(client_ctx, TLS1_2_VERSION);
        if (cfg.target_insecure) {
            SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, NULL);
        } else {
            SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);
            SSL_CTX_set_default_verify_paths(client_ctx);
        }
    }
    SSL *ssl = SSL_new(client_ctx);
    if (!ssl) { close(fd); return -1; }
    SSL_set_fd(ssl, fd);
    /* --target-sni NAME, or "auto" to reuse the Host header, exactly as Anubis
     * spells it; otherwise the SNI is the host we dialled. */
    const char *sni = cfg.target_sni && *cfg.target_sni ? cfg.target_sni : cfg.target_host;
    if (!strcasecmp(sni, "auto")) sni = cfg.target_host;
    if (strcmp(sni, "0.0.0.0") != 0) SSL_set_tlsext_host_name(ssl, sni);
    if (SSL_connect(ssl) != 1) {
        logmsg("TLS to the target %s failed", cfg.target_host);
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    if (!cfg.target_insecure && SSL_get_verify_result(ssl) != X509_V_OK) {
        logmsg("target certificate did not verify: %s",
               X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    up->ssl = ssl;
    return fd;
}

static void proxy_request(conn *c, const request *req, const char *client_ip, const char *path) {
    conn up_c = {.fd = -1, .ssl = NULL};
    int up = target_connect(&up_c);
    if (up < 0) {
        const char *msg = "betterAnusbis: cannot reach the target\n";
        respond(c, 502, "Bad Gateway", NULL, NULL, msg, strlen(msg));
        return;
    }

    char head[8192];
    const char *host_hdr = cfg.target_host_hdr && *cfg.target_host_hdr
                               ? cfg.target_host_hdr : cfg.target_host;
    size_t off = (size_t)snprintf(head, sizeof head, "%s %s HTTP/1.1\r\nHost: %s\r\n",
                                 req->method, path, host_hdr);
    /* forward the client's headers except the ones that must not cross */
    const char *p = req->headers;
    while (p && *p) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        size_t n = (size_t)(eol - p);
        if (n > 0 && n < 512 &&
            strncasecmp(p, "Host:", 5) && strncasecmp(p, "Connection:", 11) &&
            strncasecmp(p, "Keep-Alive:", 11) && strncasecmp(p, "Proxy-", 6) &&
            strncasecmp(p, "Cookie:", 7) && strncasecmp(p, "X-Real-IP:", 10) &&
            strncasecmp(p, "X-Forwarded-For:", 16) && strncasecmp(p, "Upgrade:", 8) &&
            strncasecmp(p, "TE:", 3) && strncasecmp(p, "Trailer:", 8)) {
            if (off + n + 2 < sizeof head) {
                memcpy(head + off, p, n);
                off += n;
                head[off++] = '\r';
                head[off++] = '\n';
            }
        }
        p = eol + 2;
    }
    off += (size_t)snprintf(head + off, sizeof head - off,
                            "X-Real-IP: %s\r\nX-Forwarded-For: %s\r\nConnection: close\r\n\r\n",
                            client_ip, client_ip);
    if (send_all(&up_c, head, off) < 0) { close(up); return; }
    if (req->body_len && send_all(&up_c, req->body, req->body_len) < 0) { close(up); return; }

    /* read the whole reply, then hand it back (simple, and bounded) */
    size_t cap = 65536, used = 0;
    char *reply = malloc(cap);
    if (!reply) { close(up); return; }
    for (;;) {
        if (used == cap - 1) {
            if (cap >= MAX_REPLY) break;
            cap *= 2;
            char *bigger = realloc(reply, cap);
            if (!bigger) break;
            reply = bigger;
        }
        ssize_t r = conn_read(&up_c, reply + used, cap - 1 - used);
        if (r <= 0) break;
        used += (size_t)r;
    }
    if (up_c.ssl) { SSL_shutdown((SSL *)up_c.ssl); SSL_free((SSL *)up_c.ssl); }
    close(up);
    if (used) send_all(c, reply, used);
    free(reply);
}

/* --------------------------------------------------- the challenge page */

static const char *CHALLENGE_JS = R"JS(
(function(){
  const el=document.getElementById("anubis_challenge"); if(!el) return;
  const payload=JSON.parse(el.textContent);
  const rules=payload.rules, ch=payload.challenge;
  const status=document.getElementById("status");
  const say=(m)=>{ if(status) status.textContent=m; };
  const hex2bytes=(h)=>{const a=new Uint8Array(h.length/2);for(let i=0;i<a.length;i++)a[i]=parseInt(h.substr(2*i,2),16);return a;};
  const tohex=(b)=>{let s="";for(const x of b)s+=x.toString(16).padStart(2,"0");return s;};

  // compact SHA-256, enough for the fast/slow/sha256 algorithms
  const K=new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  const rotr=(x,n)=>(x>>>n)|(x<<(32-n));
  function sha256bytes(data){
    const H=new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    const len=data.length, bits=len*8;
    const padded=new Uint8Array(((len+9+63)/64|0)*64); padded.set(data); padded[len]=0x80;
    for(let i=0;i<8;i++) padded[padded.length-1-i]=(bits>>>(8*i))&0xff;
    const w=new Uint32Array(64);
    for(let off=0;off<padded.length;off+=64){
      for(let i=0;i<16;i++) w[i]=(padded[off+4*i]<<24)|(padded[off+4*i+1]<<16)|(padded[off+4*i+2]<<8)|padded[off+4*i+3];
      for(let i=16;i<64;i++){const s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>>3);const s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>>10);w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;}
      let a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for(let i=0;i<64;i++){
        const S1=rotr(e,6)^rotr(e,11)^rotr(e,25),ch=(e&f)^(~e&g);
        const t1=(h+S1+ch+K[i]+w[i])>>>0;
        const S0=rotr(a,2)^rotr(a,13)^rotr(a,22),maj=(a&b)^(a&c)^(b&c);
        const t2=(S0+maj)>>>0;
        h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
      }
      H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;
      H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0;
    }
    const out=new Uint8Array(32);
    for(let i=0;i<8;i++){out[4*i]=H[i]>>>24;out[4*i+1]=(H[i]>>>16)&255;out[4*i+2]=(H[i]>>>8)&255;out[4*i+3]=H[i]&255;}
    return out;
  }
  const lz=(b)=>{let n=0;for(const x of b){if(x===0){n+=8;continue;}n+=Math.clz32(x)-24;break;}return n;};
  /* HASHX-JIT-BEGIN */
  // Build the HashX wasm module for this challenge in the page. This is the same
  // derivation and emission as wasm/hashx_jit.mjs; wasm/verify-jit.mjs parses
  // this block and checks both emitters produce identical bytes for a challenge.
  const HASHX_JIT=(function(){
// hashx_jit.mjs - compile a HashX challenge into a specialized wasm module, in JS.
//
// A HashX program is fixed for a whole challenge: 512 instructions derived from
// the challenge bytes by a deterministic PRF. The interpreter in hashx_pow.wasm
// pays a dispatch per instruction for every nonce; a module that has the program
// baked in does not. tools/gen_hashx_wat.py proves the speedup, but its output is
// assembled by wat2wasm, which a browser does not have. So this file emits the
// wasm binary directly: same derivation as src/hashx/hashx.c (BLAKE2b-512 below
// is SipState::pair_from_seed, the program generator is hashx_program_generate),
// same straight-line body as the Python generator, no toolchain.
//
// The emitted module carries two interfaces on purpose:
//
//   hash(nonce) -> leading zero bits, digest at memory 0     (the demo's bench)
//   digest(nonce) -> same function, aliased for reading
//   solve(base, difficulty, count) -> hit or -1
//   ninstr() -> the program size
//   data_ptr / set_data_length / anubis_work(diff,nonce,step) / result_hash_* /
//   memory                                                   (Anubis's ABI)
//
// so the same bytes drop into the demo and into a challenge page. There are no
// imports, matching hashx_pow.wasm: the program is already in the code.
//
// Numbers are BigInt only where a 64-bit value crosses the JS boundary (keys,
// BLAKE2b, SipHash, wasm i64 constants). The generator itself is 32-bit.

const M32 = 0xFFFFFFFFn;
const M64 = (1n << 64n) - 1n;

const u64 = (x) => x & M64;

function rotl(x, n) {
  const k = BigInt(n);
  return u64((x << k) | (x >> (64n - k)));
}

function load64(bytes, off) {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(bytes[off + i]);
  return v;
}

function store64(out, off, v) {
  for (let i = 0; i < 8; i++) {
    out[off + i] = Number(v & 0xFFn);
    v >>= 8n;
  }
}

/* ------------------------------------------------------------- BLAKE2b-512 */

// HashX derives both SipHash states from BLAKE2b-512(seed, salt="HashX v1").
// The parameters must match hashx_blake2_params in src/hashx/hashx.c.
const BLAKE2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

// The C generator unrolls twelve rounds and names each sigma row explicitly;
// rows 10 and 11 are rows 0 and 1 again, which BLAKE2b's round % 10 also gives.
const BLAKE2B_SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

function blake2bParamBlock() {
  const p = new Uint8Array(64);
  p[0] = 64; // digest_length
  p[1] = 0;  // key_length
  p[2] = 1;  // fanout
  p[3] = 1;  // depth
  // leaf_length, node_offset, node_depth, inner_length, reserved stay zero
  const salt = [0x48, 0x61, 0x73, 0x68, 0x58, 0x20, 0x76, 0x31]; // "HashX v1"
  p.set(salt, 32);
  return p;
}

function blake2bG(v, m, r, i, j, a, b, c, d) {
  const s = BLAKE2B_SIGMA[r];
  v[a] = u64(v[a] + v[b] + m[s[i]]);
  v[d] = rotl(v[d] ^ v[a], 32);   // rotr 32
  v[c] = u64(v[c] + v[d]);
  v[b] = rotl(v[b] ^ v[c], 40);   // rotr 24
  v[a] = u64(v[a] + v[b] + m[s[j]]);
  v[d] = rotl(v[d] ^ v[a], 48);   // rotr 16
  v[c] = u64(v[c] + v[d]);
  v[b] = rotl(v[b] ^ v[c], 1);    // rotr 63
}

function blake2bCompress(st, block) {
  const m = new Array(16);
  for (let i = 0; i < 16; i++) m[i] = load64(block, i * 8);
  const v = new Array(16);
  for (let i = 0; i < 8; i++) v[i] = st.h[i];
  v[8] = BLAKE2B_IV[0];
  v[9] = BLAKE2B_IV[1];
  v[10] = BLAKE2B_IV[2];
  v[11] = BLAKE2B_IV[3];
  v[12] = BLAKE2B_IV[4] ^ st.t0;
  v[13] = BLAKE2B_IV[5] ^ st.t1;
  v[14] = BLAKE2B_IV[6] ^ st.f0;
  v[15] = BLAKE2B_IV[7] ^ st.f1;
  for (let r = 0; r < 12; r++) {
    blake2bG(v, m, r, 0, 1, 0, 4, 8, 12);
    blake2bG(v, m, r, 2, 3, 1, 5, 9, 13);
    blake2bG(v, m, r, 4, 5, 2, 6, 10, 14);
    blake2bG(v, m, r, 6, 7, 3, 7, 11, 15);
    blake2bG(v, m, r, 8, 9, 0, 5, 10, 15);
    blake2bG(v, m, r, 10, 11, 1, 6, 11, 12);
    blake2bG(v, m, r, 12, 13, 2, 7, 8, 13);
    blake2bG(v, m, r, 14, 15, 3, 4, 9, 14);
  }
  for (let i = 0; i < 8; i++) st.h[i] = st.h[i] ^ v[i] ^ v[i + 8];
}

function blake2bIncrement(st, inc) {
  st.t0 = u64(st.t0 + inc);
  st.t1 = u64(st.t1 + (st.t0 < inc ? 1n : 0n));
}

function blake2bUpdate(st, data) {
  let pin = 0;
  let inlen = data.length;
  if (inlen === 0) return;
  if (st.buflen + inlen > 128) {
    const fill = 128 - st.buflen;
    st.buf.set(data.subarray(0, fill), st.buflen);
    blake2bIncrement(st, 128n);
    blake2bCompress(st, st.buf);
    st.buflen = 0;
    pin = fill;
    inlen -= fill;
    while (inlen > 128) {
      blake2bIncrement(st, 128n);
      blake2bCompress(st, data.subarray(pin, pin + 128));
      pin += 128;
      inlen -= 128;
    }
  }
  st.buf.set(data.subarray(pin, pin + inlen), st.buflen);
  st.buflen += inlen;
}

function blake2b512(seed) {
  const h = BLAKE2B_IV.slice();
  const param = blake2bParamBlock();
  for (let i = 0; i < 8; i++) h[i] ^= load64(param, i * 8);
  const st = { h, buf: new Uint8Array(128), buflen: 0, t0: 0n, t1: 0n, f0: 0n, f1: 0n };
  blake2bUpdate(st, seed);
  const inc = BigInt(st.buflen);
  const t0 = u64(st.t0 + inc);
  st.t1 = u64(st.t1 + (t0 < inc ? 1n : 0n));
  st.t0 = t0;
  st.f0 = M64;
  st.buf.fill(0, st.buflen);
  blake2bCompress(st, st.buf);
  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i++) store64(out, i * 8, st.h[i]);
  return out;
}

/** The two SipHash states HashX builds from a seed, exactly as hashx_build() does.
 *  keys[0] seeds the program generator; keys[1] is the register key hashes use. */
function keyPairFromSeed(seed) {
  const out = blake2b512(seed);
  const programKey = [];
  const registerKey = [];
  for (let i = 0; i < 4; i++) {
    programKey.push(load64(out, 8 * i));
    registerKey.push(load64(out, 32 + 8 * i));
  }
  return { programKey, registerKey };
}

/* --------------------------------------------------------------- SipHash */

function sipround(v) {
  v[0] = u64(v[0] + v[1]);
  v[2] = u64(v[2] + v[3]);
  v[1] = rotl(v[1], 13);
  v[3] = rotl(v[3], 16);
  v[1] ^= v[0];
  v[3] ^= v[2];
  v[0] = rotl(v[0], 32);
  v[2] = u64(v[2] + v[1]);
  v[0] = u64(v[0] + v[3]);
  v[1] = rotl(v[1], 17);
  v[3] = rotl(v[3], 21);
  v[1] ^= v[2];
  v[3] ^= v[0];
  v[2] = rotl(v[2], 32);
}

/** SipHash-1-3 in counter mode: one 64-bit output per (counter, key). */
function siphash13(input, key) {
  const v = [key[0], key[1], key[2], key[3]];
  v[3] ^= input;
  sipround(v);
  v[0] ^= input;
  v[2] ^= 0xffn;
  sipround(v);
  sipround(v);
  sipround(v);
  return (v[0] ^ v[1]) ^ (v[2] ^ v[3]);
}

/** The generator's byte/word source. Buffers are refilled big-endian per word. */
class SipRng {
  constructor(key) {
    this.key = key;
    this.counter = 0n;
    this.buffer8 = 0n;
    this.buffer32 = 0n;
    this.count8 = 0;
    this.count32 = 0;
  }

  u8() {
    if (this.count8 === 0) {
      this.buffer8 = siphash13(this.counter, this.key);
      this.counter = u64(this.counter + 1n);
      this.count8 = 8;
    }
    this.count8--;
    return Number((this.buffer8 >> BigInt(this.count8 * 8)) & 0xFFn);
  }

  u32() {
    if (this.count32 === 0) {
      this.buffer32 = siphash13(this.counter, this.key);
      this.counter = u64(this.counter + 1n);
      this.count32 = 2;
    }
    this.count32--;
    return Number((this.buffer32 >> BigInt(this.count32 * 32)) & 0xFFFFFFFFn);
  }
}

/* ------------------------------------------------- HashX program generator */

// Instruction types, in the enum order of src/hashx/hashx.c.
const OP_UMULH_R = 0;
const OP_SMULH_R = 1;
const OP_MUL_R = 2;
const OP_SUB_R = 3;
const OP_XOR_R = 4;
const OP_ADD_RS = 5;
const OP_ROR_C = 6;
const OP_ADD_C = 7;
const OP_XOR_C = 8;
const OP_TARGET = 9;
const OP_BRANCH = 10;

const TARGET_CYCLE = 192;
const REQUIREMENT_SIZE = 512;
const REQUIREMENT_MUL_COUNT = 192;
const REQUIREMENT_LATENCY = 195;
const REGISTER_NEEDS_DISPLACEMENT = 5;
const PORT_MAP_SIZE = TARGET_CYCLE + 4;
const MAX_RETRIES = 1;
const LOG2_BRANCH_PROB = 4;
const BRANCH_MASK = 0x80000000;

const PORT_NONE = 0;
const PORT_P0 = 1;
const PORT_P1 = 2;
const PORT_P5 = 4;
const PORT_P01 = PORT_P0 | PORT_P1;
const PORT_P05 = PORT_P0 | PORT_P5;
const PORT_P015 = PORT_P0 | PORT_P1 | PORT_P5;

// One template per instruction shape; the field names follow instr_template.
const TPL = {
  umulh: { type: OP_UMULH_R, latency: 4, uop1: PORT_P1, uop2: PORT_P5, immMask: 0,
           group: OP_UMULH_R, imm0: false, distinct: false, parSrc: false, hasSrc: true, hasDst: true },
  smulh: { type: OP_SMULH_R, latency: 4, uop1: PORT_P1, uop2: PORT_P5, immMask: 0,
           group: OP_SMULH_R, imm0: false, distinct: false, parSrc: false, hasSrc: true, hasDst: true },
  mul:   { type: OP_MUL_R, latency: 3, uop1: PORT_P1, uop2: PORT_NONE, immMask: 0,
           group: OP_MUL_R, imm0: false, distinct: true, parSrc: true, hasSrc: true, hasDst: true },
  sub:   { type: OP_SUB_R, latency: 1, uop1: PORT_P015, uop2: PORT_NONE, immMask: 0,
           group: OP_ADD_RS, imm0: false, distinct: true, parSrc: true, hasSrc: true, hasDst: true },
  xor:   { type: OP_XOR_R, latency: 1, uop1: PORT_P015, uop2: PORT_NONE, immMask: 0,
           group: OP_XOR_R, imm0: false, distinct: true, parSrc: true, hasSrc: true, hasDst: true },
  addrs: { type: OP_ADD_RS, latency: 1, uop1: PORT_P01, uop2: PORT_NONE, immMask: 3,
           group: OP_ADD_RS, imm0: true, distinct: true, parSrc: true, hasSrc: true, hasDst: true },
  ror:   { type: OP_ROR_C, latency: 1, uop1: PORT_P05, uop2: PORT_NONE, immMask: 63,
           group: OP_ROR_C, imm0: false, distinct: true, parSrc: false, hasSrc: false, hasDst: true },
  addc:  { type: OP_ADD_C, latency: 1, uop1: PORT_P015, uop2: PORT_NONE, immMask: 0xFFFFFFFF,
           group: OP_ADD_C, imm0: false, distinct: true, parSrc: false, hasSrc: false, hasDst: true },
  xorc:  { type: OP_XOR_C, latency: 1, uop1: PORT_P015, uop2: PORT_NONE, immMask: 0xFFFFFFFF,
           group: OP_XOR_C, imm0: false, distinct: true, parSrc: false, hasSrc: false, hasDst: true },
  target:{ type: OP_TARGET, latency: 1, uop1: PORT_P015, uop2: PORT_P015, immMask: 0,
           group: OP_TARGET, imm0: false, distinct: true, parSrc: false, hasSrc: false, hasDst: false },
  branch:{ type: OP_BRANCH, latency: 1, uop1: PORT_P015, uop2: PORT_P015, immMask: BRANCH_MASK,
           group: OP_BRANCH, imm0: false, distinct: true, parSrc: false, hasSrc: false, hasDst: false },
};

const INSTR_LOOKUP = [TPL.ror, TPL.xorc, TPL.addc, TPL.addc, TPL.sub, TPL.xor, TPL.xorc, TPL.addrs];
const WIDE_MUL_LOOKUP = [TPL.smulh, TPL.umulh];

const ITEM_MUL = { templates: [TPL.mul], mask0: 0, mask1: 0, duplicates: true };
const ITEM_TARGET = { templates: [TPL.target], mask0: 0, mask1: 0, duplicates: true };
const ITEM_BRANCH = { templates: [TPL.branch], mask0: 0, mask1: 0, duplicates: true };
const ITEM_WIDE_MUL = { templates: WIDE_MUL_LOOKUP, mask0: 1, mask1: 1, duplicates: true };
const ITEM_ANY = { templates: INSTR_LOOKUP, mask0: 7, mask1: 3, duplicates: false };

// The 36-slot schedule of instruction families. Every 36 instructions is one
// "sub_cycle"; the blend of families is what makes the program deterministic
// across implementations.
const PROGRAM_LAYOUT = [
  ITEM_MUL, ITEM_TARGET, ITEM_ANY, ITEM_MUL, ITEM_ANY, ITEM_ANY, ITEM_MUL, ITEM_ANY,
  ITEM_ANY, ITEM_MUL, ITEM_ANY, ITEM_ANY, ITEM_WIDE_MUL, ITEM_ANY, ITEM_ANY, ITEM_MUL,
  ITEM_ANY, ITEM_ANY, ITEM_MUL, ITEM_BRANCH, ITEM_ANY, ITEM_MUL, ITEM_ANY, ITEM_ANY,
  ITEM_WIDE_MUL, ITEM_ANY, ITEM_ANY, ITEM_MUL, ITEM_ANY, ITEM_ANY, ITEM_MUL, ITEM_ANY,
  ITEM_ANY, ITEM_MUL, ITEM_ANY, ITEM_ANY,
];

const isMul = (type) => type <= OP_MUL_R;

function selectTemplate(ctx, lastInstr, attempt) {
  const item = PROGRAM_LAYOUT[ctx.subCycle % 36];
  let tpl;
  do {
    const index = item.mask0
      ? ctx.rng.u8() & (attempt > 0 ? item.mask1 : item.mask0)
      : 0;
    tpl = item.templates[index];
  } while (!item.duplicates && tpl.group === lastInstr);
  return tpl;
}

function branchMask(rng) {
  let mask = 0;
  let popcnt = 0;
  while (popcnt < LOG2_BRANCH_PROB) {
    const bit = rng.u8() % 32;
    const bitmask = (1 << bit) >>> 0;
    if (!(mask & bitmask)) {
      mask = (mask | bitmask) >>> 0;
      popcnt++;
    }
  }
  return mask;
}

function instrFromTemplate(tpl, rng, instr) {
  instr.op = tpl.type;
  if (tpl.immMask) {
    if (tpl.immMask === BRANCH_MASK) {
      instr.imm = branchMask(rng);
    } else {
      do {
        instr.imm = (rng.u32() & tpl.immMask) >>> 0;
      } while (instr.imm === 0 && !tpl.imm0);
    }
  }
  if (!tpl.parSrc) {
    instr.opPar = tpl.distinct ? 0xFFFFFFFF : rng.u32();
  }
  if (!tpl.hasSrc) instr.src = -1;
  if (!tpl.hasDst) instr.dst = -1;
}

function selectRegister(available, gen, out) {
  if (out.count === 0) return false;
  const index = out.count > 1 ? gen.u32() % out.count : 0;
  out.value = available[index];
  return true;
}

function selectDestination(tpl, instr, ctx, cycle) {
  const available = [];
  for (let i = 0; i < 8; i++) {
    const r = ctx.registers[i];
    let ok = r.latency <= cycle;
    ok = ok && (!tpl.distinct || i !== instr.src);
    ok = ok && (ctx.chainMul || tpl.group !== OP_MUL_R || r.lastOp !== OP_MUL_R);
    ok = ok && (r.lastOp !== tpl.group || (r.lastOpPar >>> 0) !== (instr.opPar >>> 0));
    ok = ok && (instr.op !== OP_ADD_RS || i !== REGISTER_NEEDS_DISPLACEMENT);
    if (ok) available.push(i);
  }
  const out = { value: -1, count: available.length };
  if (!selectRegister(available, ctx.rng, out)) return false;
  instr.dst = out.value;
  return true;
}

function selectSource(tpl, instr, ctx, cycle) {
  const available = [];
  for (let i = 0; i < 8; i++) {
    if (ctx.registers[i].latency <= cycle) available.push(i);
  }
  if (available.length === 2 && instr.op === OP_ADD_RS &&
      (available[0] === REGISTER_NEEDS_DISPLACEMENT || available[1] === REGISTER_NEEDS_DISPLACEMENT)) {
    instr.opPar = instr.src = REGISTER_NEEDS_DISPLACEMENT;
    return true;
  }
  const out = { value: -1, count: available.length };
  if (selectRegister(available, ctx.rng, out)) {
    instr.src = out.value;
    if (tpl.parSrc) instr.opPar = instr.src;
    return true;
  }
  return false;
}

function scheduleUop(uop, ctx, cycle, commit) {
  for (; cycle < PORT_MAP_SIZE; cycle++) {
    if ((uop & PORT_P5) && !ctx.ports[cycle][2]) {
      if (commit) ctx.ports[cycle][2] = uop;
      return cycle;
    }
    if ((uop & PORT_P0) && !ctx.ports[cycle][0]) {
      if (commit) ctx.ports[cycle][0] = uop;
      return cycle;
    }
    if ((uop & PORT_P1) && !ctx.ports[cycle][1]) {
      if (commit) ctx.ports[cycle][1] = uop;
      return cycle;
    }
  }
  return -1;
}

function scheduleInstr(tpl, ctx, commit) {
  if (tpl.uop2 === PORT_NONE) return scheduleUop(tpl.uop1, ctx, ctx.cycle, commit);
  for (let cycle = ctx.cycle; cycle < PORT_MAP_SIZE; cycle++) {
    const c1 = scheduleUop(tpl.uop1, ctx, cycle, false);
    const c2 = scheduleUop(tpl.uop2, ctx, cycle, false);
    if (c1 >= 0 && c1 === c2) {
      if (commit) {
        scheduleUop(tpl.uop1, ctx, cycle, true);
        scheduleUop(tpl.uop2, ctx, cycle, true);
      }
      return c1;
    }
  }
  return -1;
}

/** Generate the 512-instruction program, or null if the seed fails the constraints. */
function generateProgram(key) {
  const ctx = {
    cycle: 0,
    subCycle: 0,
    mulCount: 0,
    chainMul: false,
    latency: 0,
    rng: new SipRng(key),
    registers: [],
    ports: Array.from({ length: PORT_MAP_SIZE }, () => [0, 0, 0]),
  };
  for (let i = 0; i < 8; i++) {
    ctx.registers.push({ latency: 0, lastOp: -1, lastOpPar: -1 });
  }

  const program = [];
  let attempt = 0;
  let lastInstr = -1;

  while (program.length < REQUIREMENT_SIZE) {
    const tpl = selectTemplate(ctx, lastInstr, attempt);
    lastInstr = tpl.group;

    const instr = { op: 0, dst: -1, src: -1, imm: 0, opPar: 0xFFFFFFFF };
    instrFromTemplate(tpl, ctx.rng, instr);

    let scheduleCycle = scheduleInstr(tpl, ctx, false);
    if (scheduleCycle < 0) break;

    ctx.chainMul = attempt > 0;

    if (tpl.hasSrc && !selectSource(tpl, instr, ctx, scheduleCycle)) {
      if (attempt++ < MAX_RETRIES) continue;
      ctx.subCycle += 3;
      ctx.cycle = Math.floor(ctx.subCycle / 3);
      attempt = 0;
      continue;
    }
    if (tpl.hasDst && !selectDestination(tpl, instr, ctx, scheduleCycle)) {
      if (attempt++ < MAX_RETRIES) continue;
      ctx.subCycle += 3;
      ctx.cycle = Math.floor(ctx.subCycle / 3);
      attempt = 0;
      continue;
    }
    attempt = 0;

    scheduleCycle = scheduleInstr(tpl, ctx, true);
    if (scheduleCycle < 0) break;
    if (scheduleCycle >= TARGET_CYCLE) break;

    if (tpl.hasDst) {
      const r = ctx.registers[instr.dst];
      const retire = scheduleCycle + tpl.latency;
      r.latency = retire;
      r.lastOp = tpl.group;
      r.lastOpPar = instr.opPar;
      ctx.latency = Math.max(retire, ctx.latency);
    }

    program.push(instr);
    ctx.mulCount += isMul(instr.op) ? 1 : 0;

    ctx.subCycle++;
    if (tpl.uop2 !== PORT_NONE) ctx.subCycle++;
    ctx.cycle = Math.floor(ctx.subCycle / 3);
  }

  const ok = program.length === REQUIREMENT_SIZE &&
             ctx.mulCount === REQUIREMENT_MUL_COUNT &&
             ctx.latency === REQUIREMENT_LATENCY - 1;
  return ok ? program : null;
}

/**
 * Derive the program for a challenge, retrying with a little-endian counter
 * appended when the generator rejects the seed (Anubis's make_hashx does this).
 * Returns the register key, the program, and the seed actually used.
 */
function deriveProgram(challenge) {
  const base = challenge instanceof Uint8Array ? challenge : new Uint8Array(challenge);
  for (let counter = 0; ; counter++) {
    let seed;
    if (counter === 0) {
      seed = base;
    } else {
      // hashx_init's counter starts at 0 on the first retry, so it is counter-1
      const c = counter - 1;
      seed = new Uint8Array(base.length + 4);
      seed.set(base);
      seed[base.length] = c & 0xFF;
      seed[base.length + 1] = (c >>> 8) & 0xFF;
      seed[base.length + 2] = (c >>> 16) & 0xFF;
      seed[base.length + 3] = (c >>> 24) & 0xFF;
    }
    const { programKey, registerKey } = keyPairFromSeed(seed);
    const program = generateProgram(programKey);
    if (program) return { registerKey, program, seed, counter };
  }
}

/* ------------------------------------------------------- wasm binary writer */

function uleb(n, out) {
  let v = BigInt(n);
  do {
    let b = Number(v & 0x7Fn);
    v >>= 7n;
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
}

function sleb(n, out) {
  let v = BigInt.asIntN(64, BigInt(n));
  for (;;) {
    const b = Number(v & 0x7Fn);
    v >>= 7n;
    const sign = b & 0x40;
    if ((v === 0n && !sign) || (v === -1n && sign)) {
      out.push(b);
      return;
    }
    out.push(b | 0x80);
  }
}

class Code {
  constructor() {
    this.bytes = [];
  }
  op(...ops) {
    for (const o of ops) this.bytes.push(o);
  }
  uleb(n) {
    uleb(n, this.bytes);
  }
  sleb(n) {
    sleb(n, this.bytes);
  }
  localGet(i) { this.op(0x20); this.uleb(i); }
  localSet(i) { this.op(0x21); this.uleb(i); }
  i32Const(v) { this.op(0x41); this.sleb(v); }
  i64Const(v) { this.op(0x42); this.sleb(v); }
  call(f) { this.op(0x10); this.uleb(f); }
  br(depth) { this.op(0x0c); this.uleb(depth); }
  brIf(depth) { this.op(0x0d); this.uleb(depth); }
  block() { this.op(0x02, 0x40); }
  loop() { this.op(0x03, 0x40); }
  if_() { this.op(0x04, 0x40); }
  else_() { this.op(0x05); }
  end() { this.op(0x0b); }
  i64Store(offset) { this.op(0x37, 0x03); this.uleb(offset); }
}

function raw(bytes) {
  return Array.from(bytes);
}

function section(id, payload) {
  const out = [id];
  uleb(payload.length, out);
  return out.concat(payload);
}

function vec(items) {
  const out = [];
  uleb(items.length, out);
  for (const item of items) out.push(...item);
  return out;
}

// Wasm value types.
const I32 = 0x7F;
const I64 = 0x7E;

function functype(params, results) {
  return [0x60, ...vec(params.map((t) => [t])), ...vec(results.map((t) => [t]))];
}

function name(s) {
  const bytes = raw(new TextEncoder().encode(s));
  const out = [];
  uleb(bytes.length, out);
  return out.concat(bytes);
}

// Function indices and the hash body's local indices.
const F_HASH = 0;
const F_LZ = 1;
const F_SOLVE = 2;
const F_NINSTR = 3;
const F_DATA_PTR = 4;
const F_SET_LEN = 5;
const F_RESULT_PTR = 6;
const F_RESULT_SIZE = 7;
const F_ANUBIS_WORK = 8;

const H_NONCE = 0;
const H_R0 = 1;
const H_W0 = 9;
const H_V0 = 13;
const H_RESULT = 17;
const H_HI = 18;
const H_LO = 19;
const H_T0 = 20;
const H_BE = 24;

const hR = (i) => H_R0 + i;
const hW = (i) => H_W0 + i;
const hV = (i) => H_V0 + i;
const hT = (i) => H_T0 + i;

/** $hi = high 64 bits of x*y, clobbering t0..t3 and lo. */
function emitUmulhi(c, x, y) {
  // t0 = (x & 0xffffffff) * (y & 0xffffffff)
  c.localGet(x); c.i64Const(M32); c.op(0x83);
  c.localGet(y); c.i64Const(M32); c.op(0x83);
  c.op(0x7e); c.localSet(hT(0));
  // t1 = (x & 0xffffffff) * (y >> 32)
  c.localGet(x); c.i64Const(M32); c.op(0x83);
  c.localGet(y); c.i64Const(32); c.op(0x88);
  c.op(0x7e); c.localSet(hT(1));
  // t2 = (x >> 32) * (y & 0xffffffff)
  c.localGet(x); c.i64Const(32); c.op(0x88);
  c.localGet(y); c.i64Const(M32); c.op(0x83);
  c.op(0x7e); c.localSet(hT(2));
  // t3 = (x >> 32) * (y >> 32)
  c.localGet(x); c.i64Const(32); c.op(0x88);
  c.localGet(y); c.i64Const(32); c.op(0x88);
  c.op(0x7e); c.localSet(hT(3));
  // lo = carry word from the three low partial products
  c.localGet(hT(0)); c.i64Const(32); c.op(0x88);
  c.localGet(hT(1)); c.i64Const(M32); c.op(0x83);
  c.localGet(hT(2)); c.i64Const(M32); c.op(0x83);
  c.op(0x7c); c.op(0x7c); c.localSet(H_LO);
  // hi = t3 + carries out of the low half
  c.localGet(hT(3));
  c.localGet(hT(1)); c.i64Const(32); c.op(0x88);
  c.localGet(hT(2)); c.i64Const(32); c.op(0x88);
  c.op(0x7c);
  c.localGet(H_LO); c.i64Const(32); c.op(0x88);
  c.op(0x7c);
  c.op(0x7c); c.localSet(H_HI);
}

/** $hi = high 64 bits of the signed product. */
function emitSmulhi(c, x, y) {
  emitUmulhi(c, x, y);
  // hi -= (x < 0) ? y : 0; hi -= (y < 0) ? x : 0
  c.localGet(H_HI);
  c.localGet(y); c.i64Const(0n); c.localGet(x); c.i64Const(0n); c.op(0x53);
  c.op(0x1b); c.op(0x7d); c.localSet(H_HI);
  c.localGet(H_HI);
  c.localGet(x); c.i64Const(0n); c.localGet(y); c.i64Const(0n); c.op(0x53);
  c.op(0x1b); c.op(0x7d); c.localSet(H_HI);
}

function emitSipRound(c, a, b, cc, d) {
  // a += b; c += d; b = rotl(b,13); d = rotl(d,16); b ^= a; d ^= c
  c.localGet(a); c.localGet(b); c.op(0x7c); c.localSet(a);
  c.localGet(cc); c.localGet(d); c.op(0x7c); c.localSet(cc);
  c.localGet(b); c.i64Const(13); c.op(0x89); c.localSet(b);
  c.localGet(d); c.i64Const(16); c.op(0x89); c.localSet(d);
  c.localGet(b); c.localGet(a); c.op(0x85); c.localSet(b);
  c.localGet(d); c.localGet(cc); c.op(0x85); c.localSet(d);
  c.localGet(a); c.i64Const(32); c.op(0x89); c.localSet(a);
  // a = rotl(a,32); c += b; a += d; b = rotl(b,17); d = rotl(d,21);
  // b ^= c; d ^= a; c = rotl(c,32)
  c.localGet(cc); c.localGet(b); c.op(0x7c); c.localSet(cc);
  c.localGet(a); c.localGet(d); c.op(0x7c); c.localSet(a);
  c.localGet(b); c.i64Const(17); c.op(0x89); c.localSet(b);
  c.localGet(d); c.i64Const(21); c.op(0x89); c.localSet(d);
  c.localGet(b); c.localGet(cc); c.op(0x85); c.localSet(b);
  c.localGet(d); c.localGet(a); c.op(0x85); c.localSet(d);
  c.localGet(cc); c.i64Const(32); c.op(0x89); c.localSet(cc);
}

/** The counter-mode SipHash-2-4 that fills r0..r7, then the program, then finalise. */
function emitHashBody(c, key, program) {
  // ---- PRF: SipHash-2-4 in counter mode ----
  for (let i = 0; i < 4; i++) { c.i64Const(key[i]); c.localSet(hV(i)); }
  c.localGet(hV(1)); c.i64Const(238); c.op(0x85); c.localSet(hV(1));
  c.localGet(hV(3)); c.localGet(H_NONCE); c.op(0x85); c.localSet(hV(3));
  emitSipRound(c, hV(0), hV(1), hV(2), hV(3));
  emitSipRound(c, hV(0), hV(1), hV(2), hV(3));
  c.localGet(hV(0)); c.localGet(H_NONCE); c.op(0x85); c.localSet(hV(0));
  c.localGet(hV(2)); c.i64Const(238); c.op(0x85); c.localSet(hV(2));
  for (let i = 0; i < 4; i++) emitSipRound(c, hV(0), hV(1), hV(2), hV(3));
  for (let i = 0; i < 4; i++) { c.localGet(hV(i)); c.localSet(hR(i)); }
  c.localGet(hV(1)); c.i64Const(221); c.op(0x85); c.localSet(hV(1));
  for (let i = 0; i < 4; i++) emitSipRound(c, hV(0), hV(1), hV(2), hV(3));
  for (let i = 0; i < 4; i++) { c.localGet(hV(i)); c.localSet(hR(4 + i)); }

  // ---- the program, straight-line ----
  // A branch is the only control flow: be guards it and clears after one taken
  // branch, so at most one backward jump per hash. One loop per branch target.
  const targetOf = {};
  let lastTarget = null;
  for (let i = 0; i < program.length; i++) {
    if (program[i].op === OP_TARGET) lastTarget = i;
    else if (program[i].op === OP_BRANCH) {
      targetOf[i] = lastTarget === null ? 0 : lastTarget + 1;
    }
  }
  const heads = [...new Set(Object.values(targetOf))].filter((t) => t < program.length);
  const headSet = new Set(heads);

  const open = []; // { id: target index or -1 for an if }
  const branchDepth = (target) => {
    for (let i = open.length - 1; i >= 0; i--) {
      if (open[i].id === target) return open.length - 1 - i;
    }
    return -1;
  };

  c.i32Const(1); c.localSet(H_BE);
  for (let i = 0; i < program.length; i++) {
    const { op, dst, src, imm } = program[i];
    if (headSet.has(i)) {
      c.loop();
      open.push({ id: i });
    }
    const d = dst & 7;
    const s = src & 7;
    switch (op) {
      case OP_TARGET:
        break;
      case OP_BRANCH: {
        const tgt = targetOf[i];
        // if (be && (result & imm) == 0) { be = 0; br target }
        c.localGet(H_BE);
        c.localGet(H_RESULT); c.i64Const(BigInt(imm >>> 0)); c.op(0x83);
        c.i64Const(0n); c.op(0x51);
        c.op(0x71);
        c.if_();
        open.push({ id: -1 });
        c.i32Const(0); c.localSet(H_BE);
        if (headSet.has(tgt)) {
          const depth = branchDepth(tgt);
          if (depth < 0) throw new Error('branch target ' + tgt + ' has no loop');
          c.br(depth);
        }
        open.pop();
        c.end();
        break;
      }
      case OP_UMULH_R:
        emitUmulhi(c, hR(d), hR(s));
        c.localGet(H_HI); c.localSet(hR(d));
        c.localGet(H_HI); c.localSet(H_RESULT);
        break;
      case OP_SMULH_R:
        emitSmulhi(c, hR(d), hR(s));
        c.localGet(H_HI); c.localSet(hR(d));
        c.localGet(H_HI); c.localSet(H_RESULT);
        break;
      case OP_MUL_R:
        c.localGet(hR(d)); c.localGet(hR(s)); c.op(0x7e); c.localSet(hR(d));
        break;
      case OP_SUB_R:
        c.localGet(hR(d)); c.localGet(hR(s)); c.op(0x7d); c.localSet(hR(d));
        break;
      case OP_XOR_R:
        c.localGet(hR(d)); c.localGet(hR(s)); c.op(0x85); c.localSet(hR(d));
        break;
      case OP_ADD_RS:
        c.localGet(hR(d)); c.localGet(hR(s)); c.i64Const(imm & 63); c.op(0x86);
        c.op(0x7c); c.localSet(hR(d));
        break;
      case OP_ROR_C:
        c.localGet(hR(d)); c.i64Const(imm & 63); c.op(0x8a); c.localSet(hR(d));
        break;
      case OP_ADD_C:
        c.localGet(hR(d)); c.i64Const(BigInt(imm | 0)); c.op(0x7c); c.localSet(hR(d));
        break;
      case OP_XOR_C:
        c.localGet(hR(d)); c.i64Const(BigInt(imm | 0)); c.op(0x85); c.localSet(hR(d));
        break;
      default:
        throw new Error('unknown HashX opcode ' + op + ' at ' + i);
    }
  }
  for (let i = open.length - 1; i >= 0; i--) c.end();

  // ---- finalisation ----
  c.localGet(hR(0)); c.i64Const(key[0]); c.op(0x7c); c.localSet(hR(0));
  c.localGet(hR(1)); c.i64Const(key[1]); c.op(0x7c); c.localSet(hR(1));
  c.localGet(hR(6)); c.i64Const(key[2]); c.op(0x7c); c.localSet(hR(6));
  c.localGet(hR(7)); c.i64Const(key[3]); c.op(0x7c); c.localSet(hR(7));
  emitSipRound(c, hR(0), hR(1), hR(2), hR(3));
  emitSipRound(c, hR(4), hR(5), hR(6), hR(7));
  for (let i = 0; i < 4; i++) {
    c.i32Const(0);
    c.localGet(hR(i)); c.localGet(hR(4 + i)); c.op(0x85);
    c.op(0x37, 0x03); c.uleb(8 * i); // i64.store offset=8*i
  }
  c.call(F_LZ);
}

function emitLzBody(c) {
  // no params, so the three declared locals are indices 0,1,2
  const K = 0;
  const BITS = 1;
  const BYTE = 2;
  c.i32Const(0); c.localSet(K);
  c.i64Const(0n); c.localSet(BITS);
  c.block();
  c.loop();
  c.localGet(K); c.i32Const(32); c.op(0x4f); // i32.ge_u
  c.brIf(1); // exit the block
  c.localGet(K); c.op(0x2d, 0x00, 0x00); c.localSet(BYTE); // i32.load8_u
  c.localGet(BYTE); c.op(0x45); // i32.eqz
  c.if_();
  c.localGet(BITS); c.i64Const(8); c.op(0x7c); c.localSet(BITS);
  c.else_();
  c.localGet(BITS);
  c.localGet(BYTE); c.op(0x67); c.i32Const(24); c.op(0x6b); // clz - 24
  c.op(0xad); // i64.extend_i32_u
  c.op(0x7c); c.localSet(BITS);
  c.br(2); // exit the block
  c.end();
  c.localGet(K); c.i32Const(1); c.op(0x6a); c.localSet(K);
  c.br(0);
  c.end(); // loop
  c.end(); // block
  c.localGet(BITS);
}

function emitSolveBody(c) {
  const N = 3;
  const END = 4;
  const BITS = 5;
  c.localGet(0); c.localSet(N);
  c.localGet(0); c.localGet(2); c.op(0x7c); c.localSet(END);
  c.block();
  c.loop();
  c.localGet(N); c.localGet(END); c.op(0x59); // i64.ge_s
  c.brIf(1);
  c.localGet(N); c.call(F_HASH); c.localSet(BITS);
  c.localGet(BITS); c.localGet(1); c.op(0x59);
  c.if_();
  c.localGet(N); c.op(0x0f); // return n
  c.end();
  c.localGet(N); c.i64Const(1); c.op(0x7c); c.localSet(N);
  c.br(0);
  c.end(); // loop
  c.end(); // block
  c.i64Const(-1n);
}

function emitAnubisWorkBody(c) {
  const N = 3;
  const STEP = 4;
  const BITS = 5;
  // if (iterand == 0) iterand = 1
  c.localGet(2); c.op(0x45); c.if_();
  c.i32Const(1); c.localSet(STEP);
  c.else_();
  c.localGet(2); c.localSet(STEP);
  c.end();
  c.localGet(1); c.localSet(N);
  c.loop();
  c.localGet(N); c.op(0xad); c.call(F_HASH); c.localSet(BITS);
  c.localGet(BITS); c.localGet(0); c.op(0xad); c.op(0x59); // bits >= difficulty
  c.if_();
  c.localGet(N); c.op(0x0f);
  c.end();
  c.localGet(N); c.localGet(STEP); c.op(0x6a); c.localSet(N);
  c.br(0);
  c.end();
  c.op(0x00); // unreachable: the scan loop has no normal exit
}

function emitBody(localGroups, emit) {
  const c = new Code();
  c.uleb(localGroups.length);
  for (const [count, type] of localGroups) {
    c.uleb(count);
    c.op(type);
  }
  emit(c);
  c.end();
  return c.bytes;
}

function codeEntry(body) {
  const out = [];
  uleb(body.length, out);
  return out.concat(body);
}

/**
 * Build a wasm module specialized to one HashX program.
 * @param {{registerKey: bigint[], program: object[]}} derived from deriveProgram()
 * @returns {Uint8Array}
 */
function buildModuleForProgram(registerKey, program) {
  const hashBody = emitBody(
    [[8, I64], [4, I64], [4, I64], [3, I64], [4, I64], [1, I32]],
    (c) => emitHashBody(c, registerKey, program),
  );

  const types = vec([
    functype([I64], [I64]),        // hash / digest
    functype([], [I64]),           // lz
    functype([I64, I64, I64], [I64]), // solve
    functype([], [I32]),           // ninstr, data_ptr, result_hash_ptr, result_hash_size
    functype([I32], []),           // set_data_length
    functype([I32, I32, I32], [I32]), // anubis_work
  ]);

  // One defined function per interface. Types are listed in the order used here.
  const funcs = vec([[0], [1], [2], [3], [3], [4], [3], [3], [5]]);

  const memory = vec([[0x00, 0x01]]); // one page, no maximum

  const exports = vec([
    [...name('memory'), 0x02, 0x00],
    [...name('hash'), 0x00, F_HASH],
    [...name('digest'), 0x00, F_HASH],
    [...name('solve'), 0x00, F_SOLVE],
    [...name('ninstr'), 0x00, F_NINSTR],
    [...name('data_ptr'), 0x00, F_DATA_PTR],
    [...name('set_data_length'), 0x00, F_SET_LEN],
    [...name('result_hash_ptr'), 0x00, F_RESULT_PTR],
    [...name('result_hash_size'), 0x00, F_RESULT_SIZE],
    [...name('anubis_work'), 0x00, F_ANUBIS_WORK],
  ]);

  const bodies = [
    hashBody,
    emitBody([[1, I32], [1, I64], [1, I32]], emitLzBody),
    emitBody([[3, I64]], emitSolveBody),
    emitBody([], (c) => { c.i32Const(program.length); }),
    emitBody([], (c) => { c.i32Const(64); }),
    emitBody([], () => {}),
    emitBody([], (c) => { c.i32Const(0); }),
    emitBody([], (c) => { c.i32Const(32); }),
    emitBody([[2, I32], [1, I64]], emitAnubisWorkBody),
  ];

  const code = vec(bodies.map(codeEntry));

  const out = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  out.push(...section(1, types));
  out.push(...section(3, funcs));
  out.push(...section(5, memory));
  out.push(...section(7, exports));
  out.push(...section(10, code));
  return new Uint8Array(out);
}

/** Derive and emit in one step. This is what a challenge page calls. */
function buildModule(challenge) {
  const { registerKey, program } = deriveProgram(challenge);
  return buildModuleForProgram(registerKey, program);
}
  return {keyPairFromSeed:keyPairFromSeed,deriveProgram:deriveProgram,buildModule:buildModule};
  })();
  /* HASHX-JIT-END */

  const algo=(rules.algorithm||"").toLowerCase(), diff=rules.difficulty|0;
  const pass=(response,nonce,ms)=>{
    const u=new URL("/.within.website/x/cmd/anubis/api/pass-challenge",location.origin);
    u.searchParams.set("id",ch.id); u.searchParams.set("response",response);
    u.searchParams.set("nonce",String(nonce)); u.searchParams.set("redir",location.pathname+location.search);
    u.searchParams.set("elapsedTime",String(Math.max(1,Math.round(ms))));
    location.replace(u.toString());
  };

  // A HashX search does not report how many candidates it has tried, but the
  // compiled module can be called in windows, so this counts nonces actually
  // hashed: both the fraction and the rate below are measured, not estimated.
  const workBox=document.getElementById("work"), workBar=document.getElementById("workbar"),
        workFill=document.getElementById("fill"), workPct=document.getElementById("pct"),
        workRate=document.getElementById("rate"), workEta=document.getElementById("eta"),
        workSub=document.getElementById("worksub");
  function workShow(sub){
    if(workBox) workBox.hidden=false;
    if(workBar) workBar.classList.add("busy");
    if(workSub&&sub) workSub.textContent=sub;
  }
  function workUpdate(frac,done,ms,expected){
    if(workFill) workFill.style.width=(Math.max(0,Math.min(1,frac))*100).toFixed(1)+"%";
    if(workPct) workPct.textContent=(frac*100).toFixed(1)+"%";
    const rate=ms>0?done/(ms/1000):0;
    if(workRate) workRate.textContent=rate>0?(rate/1e6).toFixed(2)+" MHash/s":"\u2014";
    if(workEta&&rate>0) workEta.textContent="~"+Math.max(0,expected/rate-ms/1000).toFixed(0)+" s left at this rate";
  }
  function workDone(){ if(workBar) workBar.classList.remove("busy"); }

  if(algo==="metarefresh"){
    // Anubis's metarefresh proof is time: wait difficulty * 800 ms, then echo the
    // random data back as ?challenge=. Nothing is hashed.
    const wait=diff*800;
    say("waiting "+(wait/1000).toFixed(1)+" s as the proof of patience");
    const t0=performance.now();
    setTimeout(()=>{
      const u=new URL("/.within.website/x/cmd/anubis/api/pass-challenge",location.origin);
      u.searchParams.set("challenge",ch.randomData);
      u.searchParams.set("id",ch.id);
      u.searchParams.set("redir",location.pathname+location.search);
      u.searchParams.set("elapsedTime",String(Math.round(performance.now()-t0)));
      location.replace(u.toString());
    }, wait+50);
    return;
  }
  // Our own kernels, served next to the page. Same ABI as the modules Anubis
  // ships: data_ptr / set_data_length / anubis_work / result_hash_*.
  const KERNELS={sha256:"sha256_pow_batch.wasm","wasm-sha256":"sha256_pow_batch.wasm",
                 argon2id:"argon2id_pow.wasm",hashx:"hashx_pow.wasm"};
  async function solveWithWasm(){
    const name=KERNELS[algo];
    if(!name) return null;
    const raw=hex2bytes(ch.randomData);

    function run(ex){
      new Uint8Array(ex.memory.buffer).set(raw,ex.data_ptr());
      ex.set_data_length(raw.length);
      const t0=performance.now();
      const nonce=ex.anubis_work(diff,0,1)>>>0;
      const ms=performance.now()-t0;
      const digest=new Uint8Array(ex.memory.buffer,ex.result_hash_ptr(),ex.result_hash_size());
      return {hash:tohex(digest),nonce,ms};
    }

    // A HashX program is fixed for the whole challenge, so compile a module with
    // this challenge's program baked in instead of paying interpreter dispatch
    // per nonce. If anything about that fails (derivation, compilation, the
    // call), hashx_pow.wasm below has the same ABI and is always correct.
    if(algo==="hashx"){
      try{
        say("compiling this challenge's HashX program into wasm");
        const mod=new WebAssembly.Module(HASHX_JIT.buildModule(raw));
        const jx=new WebAssembly.Instance(mod,{}).exports;
        // Windows of 2^18 nonces: long enough to measure a real rate (about a
        // tenth of a second here), short enough that the bar keeps moving.
        const win=1n<<18n, expected=Math.pow(2,diff);
        let base=0n, t0=performance.now();
        workShow("2^"+diff+" ("+expected.toLocaleString("en-US")+") hashes expected, "+
                 "compiled for this challenge, 262,144 nonces per window");
        for(;;){
          const hit=Number(jx.solve(base,BigInt(diff),win));
          base+=win;
          const ms=performance.now()-t0, done=Number(base);
          if(hit>=0){
            jx.hash(BigInt(hit));
            const digest=new Uint8Array(jx.memory.buffer,jx.result_hash_ptr(),jx.result_hash_size());
            workUpdate(1,done,ms,expected);
            workDone();
            say("solved with nonce "+hit+" in "+ms.toFixed(0)+" ms");
            return {hash:tohex(digest),nonce:hit,ms};
          }
          workUpdate(Math.min(0.99,done/expected),done,ms,expected);
          await new Promise(r=>setTimeout(r,0));
        }
      }catch(e){
        console.warn("HashX JIT failed, falling back to hashx_pow.wasm:",e);
      }
    }

    say("loading the "+algo+" kernel");
    const bytes=await (await fetch("/.within.website/x/cmd/anubis/api/static/anubis/"+name)).arrayBuffer();
    const {instance}=await WebAssembly.instantiate(bytes,{anubis:{anubis_update_nonce:()=>{}}});
    return run(instance.exports);
  }

  if(algo==="sha256"||algo==="wasm-sha256"||algo==="argon2id"||algo==="hashx"){
    solveWithWasm().then(r=>{
      if(r){ say("solved with nonce "+r.nonce+" in "+r.ms.toFixed(0)+" ms"); pass(r.hash,r.nonce,r.ms); }
      else if(algo==="sha256"||algo==="wasm-sha256"){ solveInJs(); }
      else { say(algo+" could not load its kernel, use the anubis_fetch CLI or the Firefox extension"); }
    }).catch(e=>{
      if(algo==="sha256"||algo==="wasm-sha256"){ solveInJs(); }
      else { say(algo+" kernel failed to load: "+e); }
    });
    return;
  }
  if(algo!=="fast"&&algo!=="slow"){
    say(algo+" needs a native or WebAssembly solver - use the anubis_fetch CLI or the Firefox extension");
    return;
  }
  solveInJs();

  function solveInJs(){
    const t0=performance.now();
    const enc=new TextEncoder();
    for(let nonce=0;;nonce++){
      const d=sha256bytes(enc.encode(ch.randomData+nonce));
      if(lz(d)>=diff*4){ say("solved with nonce "+nonce); pass(tohex(d),nonce,performance.now()-t0); return; }
      if((nonce&8191)===0) say("trying nonce "+nonce);
    }
  }
})();
)JS";

/* Rewrite the API paths in the page for --base-prefix. Every link the page
 * builds is rooted at API_PREFIX (the C format arguments and the JS literals
 * alike), so one pass over the finished body is enough and the JS needs no
 * template variable. Frees the input on success. */
static char *prefix_api_paths(char *body) {
    size_t plen = strlen(cfg.base_prefix);
    if (plen == 0 || !body) return body;
    size_t nlen = strlen(API_PREFIX);
    size_t count = 0;
    for (const char *p = body; (p = strstr(p, API_PREFIX)) != NULL; p += nlen) count++;
    if (!count) return body;
    size_t blen = strlen(body);
    char *out = malloc(blen + count * plen + 1);
    if (!out) return body;
    size_t o = 0;
    const char *p = body, *hit;
    while ((hit = strstr(p, API_PREFIX)) != NULL) {
        size_t seg = (size_t)(hit - p);
        memcpy(out + o, p, seg);
        o += seg;
        memcpy(out + o, cfg.base_prefix, plen);
        o += plen;
        memcpy(out + o, API_PREFIX, nlen);
        o += nlen;
        p = hit + nlen;
    }
    size_t rest = strlen(p);
    memcpy(out + o, p, rest);
    o += rest;
    out[o] = 0;
    free(body);
    return out;
}

static void challenge_page(conn *c, const char *id, const char *random_data,
                           const char *metadata_json, const char *test_cookie,
                           const char *algorithm, int difficulty) {
    char payload[2048];
    snprintf(payload, sizeof payload,
             "{\"rules\":{\"algorithm\":\"%s\",\"difficulty\":%d},"
             "\"challenge\":{\"issuedAt\":\"%lld\",\"metadata\":%s,\"id\":\"%s\","
             "\"method\":\"%s\",\"randomData\":\"%s\",\"policyRuleHash\":\"rule-0\","
             "\"difficulty\":%d,\"spent\":false,\"extensions\":null}}",
             algorithm, difficulty, (long long)time(NULL), metadata_json, id,
             algorithm, random_data, difficulty);

    size_t cap = strlen(payload) + strlen(CHALLENGE_JS) + 4096;
    char *body = malloc(cap);
    if (!body) { respond(c, 500, "Internal Server Error", NULL, NULL, "oom", 3); return; }

    snprintf(body, cap,
             "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
             "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
             "<title>Proving you are not a robot</title><style>"
             "body{font:16px/1.6 system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;"
             "background:#12141a;color:#e6e9f0}a{color:#4d6bfe}"
             "code{font-family:ui-monospace,monospace;font-size:.85em;color:#98a0b3;word-break:break-all}"
             "#work{margin:1.75rem 0 1rem}#work h2{font-size:1.7rem;line-height:1.1;"
             "margin:0 0 .3rem;color:#f78166;letter-spacing:-.02em}"
             "#work p{font-family:ui-monospace,monospace;font-size:.85rem;color:#98a0b3;margin:.5rem 0 0}"
             ".bar{height:16px;border:1px solid #2b3040;border-radius:8px;background:#1a1d26;"
             "overflow:hidden;margin-top:.9rem}#fill{height:100%%;width:0;"
             "background:linear-gradient(90deg,#1f6feb,#3fb950);transition:width .18s linear}"
             ".bar.busy #fill{background-image:repeating-linear-gradient(115deg,"
             "rgba(255,255,255,.16) 0 10px,transparent 10px 22px);background-size:22px 22px}"
             "</style></head><body>"
             "<h1>Proving you are not a robot</h1>"
             "<p id=\"status\">solving a %s challenge at difficulty %d&hellip;</p>"
             "<div id=\"work\" hidden><h2>slowing you down!</h2>"
             "<p id=\"worksub\"></p>"
             "<div class=\"bar\" id=\"workbar\"><div id=\"fill\"></div></div>"
             "<p><span id=\"pct\">0.0%%</span> &middot; <span id=\"rate\">&mdash;</span>"
             " &middot; <span id=\"eta\"></span></p></div>"
             "<p><a id=\"manual\" href=\"#\">or pass the challenge manually</a></p>"
             "<p><small>If nothing happens, solve it yourself: the challenge is the JSON below, "
             "and the answer goes to <code>%spass-challenge?id=%s&amp;response=&lt;digest&gt;&amp;nonce=&lt;n&gt;</code>.</small></p>"
             "<script id=\"anubis_challenge\" type=\"application/json\">%s</script>"
             "<script>%s</script>"
             "<script>(function(){var u=new URL(\"%spass-challenge\",location.origin);"
             "u.searchParams.set(\"id\",\"%s\");u.searchParams.set(\"response\",\"\");u.searchParams.set(\"nonce\",\"0\");"
             "u.searchParams.set(\"redir\",location.pathname);document.getElementById(\"manual\").href=u.toString();})();</script>"
             "</body></html>",
             algorithm, difficulty, API_PREFIX, id, payload, CHALLENGE_JS, API_PREFIX, id);

    /* the honeypot link: inside <script type="ignore">, so no browser renders it
     * but a crawler that parses HTML for hrefs finds it. Same markup Anubis uses,
     * including the wording. */
    if (cfg.honeypot) {
        uint8_t trapb[16];
        char trap[33];
        if (random_bytes(trapb, sizeof trapb) != 0) memset(trapb, 0, sizeof trapb);
        hex_encode(trapb, sizeof trapb, trap);
        size_t used = strlen(body);
        snprintf(body + used, cap > used ? cap - used : 0,
                 "<script type=\"ignore\"><a href=\"" API_PREFIX "honeypot/%s/init\">"
                 "Don't click me</a></script>", trap);
    }

    body = prefix_api_paths(body);

    char extra[512];
    snprintf(extra, sizeof extra,
             "Set-Cookie: %s-cookie-verification=%s; Path=/; SameSite=Lax\r\n",
             cfg.cookie_prefix, test_cookie ? test_cookie : id);
    respond(c, cfg.challenge_status, reason_for(cfg.challenge_status),
            "text/html; charset=utf-8", extra, body, strlen(body));
    free(body);
}

/* -------------------------------------------------------------- policy */

/* One rule per line, first match wins:
 *
 *   allow     ua contains Googlebot
 *   allow     path prefix /health
 *   allow     net 10.0.0.0/8
 *   deny      ua contains AhrefsBot
 *   challenge ua contains curl difficulty 12
 *   default   challenge difficulty 12
 *
 * Matching is literal: "contains", "prefix" or "is", on the user agent, the path,
 * a header, or an IPv4/IPv6 CIDR. No regular expressions - a policy language is
 * the thing this project is avoiding.
 */
static const char *const known_algorithms[] = {"fast", "slow", "sha256", "wasm-sha256",
                                              "argon2id", "hashx", "metarefresh", NULL};

static int algorithm_known(const char *name) {
    for (int i = 0; known_algorithms[i]; i++)
        if (!strcasecmp(name, known_algorithms[i])) return 1;
    return 0;
}

typedef enum { RULE_ALLOW, RULE_DENY, RULE_CHALLENGE } rule_action;
typedef enum { SEL_UA, SEL_PATH, SEL_HEADER, SEL_NET } rule_selector;

typedef struct {
    rule_action action;
    rule_selector selector;
    int match;                  /* 1 = contains, 2 = prefix, 3 = is, 4 = regex */
    char value[256];
    char algorithm[24];         /* "" = the global --algorithm */
    char header[64];
    int difficulty;             /* 0 = the global default */
    int v4;                     /* for SEL_NET: IPv4 CIDR */
    int v6;                     /* for SEL_NET: IPv6 CIDR */
    uint32_t net_v4, mask_v4;
    uint8_t net_v6[16], mask_v6[16];
    regex_t re;                 /* compiled when match == 4 */
    int has_re;
} rule;

/* ======================================================================== *
 * Anubis's own policy format
 *
 * botPolicies.yaml is a YAML document: a list of bot rules, a list of weight
 * thresholds, and a handful of global blocks. This section reads the subset of
 * YAML that the format actually uses (block maps and sequences, folded and
 * literal scalars, quoted and plain scalars, comments), resolves import: lines
 * including the (data)/ macro, translates the RE2-isms the shipped patterns use
 * into POSIX ERE, and evaluates the CEL subset the shipped expressions use.
 *
 * It is deliberately not a YAML library and not a CEL implementation. Anything
 * it cannot express is reported at load time, by name, instead of quietly
 * changing the meaning of a policy.
 * ======================================================================== */

#define MAX_YAML_RULES 4096
#define MAX_YAML_THRESHOLDS 64
#define MAX_IMPORT_DEPTH 16
#define MAX_RULE_HEADERS 4

typedef enum { Y_SCALAR, Y_MAP, Y_SEQ } y_type;

typedef struct y_node {
    y_type type;
    char *key;              /* set when this node is a map member */
    char *scalar;           /* for Y_SCALAR */
    struct y_node *child;   /* for Y_MAP / Y_SEQ: first child */
    struct y_node *next;    /* sibling */
} y_node;

typedef struct {
    char *text;             /* the line with the indent removed */
    int indent;
    int blank;
} y_line;

typedef struct {
    y_line *lines;
    int n, pos;
    const char *path;
} y_file;

static void *y_alloc(size_t n) {
    void *p = calloc(1, n);
    return p;
}

static char *y_dup(const char *s) {
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

static y_node *y_new(y_type t) {
    y_node *n = y_alloc(sizeof *n);
    if (n) n->type = t;
    return n;
}

static void y_free(y_node *n) {
    while (n) {
        y_node *next = n->next;
        y_free(n->child);
        free(n->key);
        free(n->scalar);
        free(n);
        n = next;
    }
}

/* ---- reading the file -------------------------------------------------- */

static void y_strip_comment(char *s) {
    int q = 0;
    for (char *p = s; *p; p++) {
        if (q) {
            if (*p == q) q = 0;
            continue;
        }
        if (*p == '"' || *p == '\'') {
            q = *p;
            continue;
        }
        /* YAML needs whitespace before an inline comment; that keeps # inside a
         * pattern such as [#] from being eaten */
        if (*p == '#' && (p == s || p[-1] == ' ' || p[-1] == '\t')) {
            *p = 0;
            return;
        }
    }
}

static int y_open(const char *path, y_file *f) {
    memset(f, 0, sizeof *f);
    f->path = path;
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char *buf = NULL;
    size_t used = 0, cap = 0;
    for (;;) {
        if (used + 4096 > cap) {
            cap = cap ? cap * 2 : 65536;
            char *bigger = realloc(buf, cap);
            if (!bigger) {
                free(buf);
                fclose(fp);
                return -1;
            }
            buf = bigger;
        }
        size_t got = fread(buf + used, 1, cap - used - 1, fp);
        used += got;
        if (got == 0) break;
    }
    fclose(fp);
    if (!buf) return -1;
    buf[used] = 0;

    /* split into lines, strip comments, keep blanks (block scalars need them) */
    int cap_lines = 256;
    f->lines = y_alloc((size_t)cap_lines * sizeof *f->lines);
    if (!f->lines) {
        free(buf);
        return -1;
    }
    char *p = buf;
    while (*p) {
        char *eol = strchr(p, '\n');
        if (eol) *eol = 0;
        size_t len = strlen(p);
        if (len && p[len - 1] == '\r') p[--len] = 0;
        y_strip_comment(p);
        len = strlen(p);
        while (len && (p[len - 1] == ' ' || p[len - 1] == '\t')) p[--len] = 0;

        if (f->n == cap_lines) {
            cap_lines *= 2;
            y_line *bigger = realloc(f->lines, (size_t)cap_lines * sizeof *f->lines);
            if (!bigger) {
                free(buf);
                return -1;
            }
            f->lines = bigger;
        }
        int indent = 0;
        while (p[indent] == ' ' || p[indent] == '\t') indent++;
        f->lines[f->n].indent = indent;
        f->lines[f->n].blank = (p[indent] == 0);
        f->lines[f->n].text = y_dup(p + indent);
        f->n++;
        if (!eol) break;
        p = eol + 1;
    }
    free(buf);
    return 0;
}

static void y_close(y_file *f) {
    for (int i = 0; i < f->n; i++) free(f->lines[i].text);
    free(f->lines);
    f->lines = NULL;
    f->n = f->pos = 0;
}

static int y_next_indent(const y_file *f) {
    for (int i = f->pos; i < f->n; i++) {
        if (f->lines[i].blank) continue;
        return f->lines[i].indent;
    }
    return -1;
}

/* ---- block scalars ----------------------------------------------------- */

static char *y_block_scalar(y_file *f, int parent_indent, int literal) {
    int start = f->pos, end = f->pos;
    while (end < f->n) {
        if (f->lines[end].blank) {
            end++;
            continue;
        }
        if (f->lines[end].indent <= parent_indent) break;
        end++;
    }
    int base = -1;
    for (int i = start; i < end; i++) {
        if (f->lines[i].blank) continue;
        if (base < 0 || f->lines[i].indent < base) base = f->lines[i].indent;
    }
    if (base < 0) base = parent_indent + 1;

    size_t cap = 64, len = 0;
    char *out = malloc(cap);
    if (!out) return NULL;
    out[0] = 0;
    for (int i = start; i < end; i++) {
        y_line *ln = &f->lines[i];
        size_t need = len + (ln->blank ? 1 : strlen(ln->text) + 8);
        if (need + 2 > cap) {
            while (need + 2 > cap) cap *= 2;
            char *bigger = realloc(out, cap);
            if (!bigger) {
                free(out);
                return NULL;
            }
            out = bigger;
        }
        if (ln->blank) {
            out[len++] = '\n';
            out[len] = 0;
            continue;
        }
        int extra = ln->indent - base;
        if (extra < 0) extra = 0;
        int need_space = !literal && len > 0 && out[len - 1] != '\n';
        if (need_space) out[len++] = ' ';
        for (int k = 0; k < extra; k++) out[len++] = ' ';
        size_t tl = strlen(ln->text);
        memcpy(out + len, ln->text, tl);
        len += tl;
        out[len] = 0;
        if (literal) {
            out[len++] = '\n';
            out[len] = 0;
        }
    }
    f->pos = end;
    while (len && (out[len - 1] == '\n' || out[len - 1] == ' ')) out[--len] = 0;
    return out;
}

/* ---- scalars and the block parser -------------------------------------- */

static char *y_unquote(const char *v) {
    size_t n = strlen(v);
    if (n >= 2 && ((v[0] == '"' && v[n - 1] == '"') || (v[0] == '\'' && v[n - 1] == '\''))) {
        char *out = y_dup(v + 1);
        if (!out) return NULL;
        out[n - 2] = 0;
        /* a doubled quote is one quote, in both YAML styles */
        char *w = out;
        for (char *r = out; *r; r++) {
            *w++ = *r;
            if (*r == v[0] && r[1] == v[0]) r++;
        }
        *w = 0;
        return out;
    }
    return y_dup(v);
}

static int y_is_block_marker(const char *v) {
    return !strcmp(v, ">") || !strcmp(v, ">-") || !strcmp(v, ">+") ||
           !strcmp(v, "|") || !strcmp(v, "|-") || !strcmp(v, "|+");
}

static int y_is_literal(const char *v) { return v[0] == '|'; }

/* A sequence item is a map only when it has a YAML mapping colon, which needs a
 * space or end of line after it. Without that rule, "2001:db8::/32" looks like a
 * key called 2001 and every IPv6 CIDR in the tree is dropped. */
static int y_looks_like_pair(const char *s) {
    int q = 0;
    for (const char *p = s; *p; p++) {
        if (q) {
            if (*p == q) q = 0;
            continue;
        }
        if (*p == '"' || *p == '\'') {
            q = *p;
            continue;
        }
        if (*p == ':' && (p[1] == ' ' || p[1] == '\t' || p[1] == 0)) return 1;
    }
    return 0;
}

static y_node *y_parse_block(y_file *f, int indent);

/* One `key: value` pair. f->pos already points past the line it came from. */
static void y_take_pair(y_file *f, y_node *map, const char *text, int indent) {
    int q = 0;
    const char *colon = NULL;
    for (const char *p = text; *p; p++) {
        if (q) {
            if (*p == q) q = 0;
            continue;
        }
        if (*p == '"' || *p == '\'') {
            q = *p;
            continue;
        }
        if (*p == ':') {
            colon = p;
            break;
        }
    }
    if (!colon) return;

    size_t kl = (size_t)(colon - text);
    while (kl && text[kl - 1] == ' ') kl--;
    char key[160];
    if (kl >= sizeof key) kl = sizeof key - 1;
    memcpy(key, text, kl);
    key[kl] = 0;

    const char *val = colon + 1;
    while (*val == ' ') val++;

    y_node *member = y_new(Y_SCALAR);
    if (!member) return;
    member->key = y_dup(key);
    if (*val == 0) {
        int ni = y_next_indent(f);
        if (ni > indent) {
            y_node *child = y_parse_block(f, ni);
            if (child) {
                member->type = child->type;
                member->child = child->child;
                free(child->key);
                free(child);
            }
        } else {
            member->scalar = y_dup("");
        }
    } else if (y_is_block_marker(val)) {
        member->scalar = y_block_scalar(f, indent, y_is_literal(val));
    } else {
        member->scalar = y_unquote(val);
    }
    /* append */
    if (!map->child) {
        map->child = member;
    } else {
        y_node *t = map->child;
        while (t->next) t = t->next;
        t->next = member;
    }
}

static y_node *y_parse_map_body(y_file *f, int indent, const char *seed) {
    y_node *map = y_new(Y_MAP);
    if (!map) return NULL;
    if (seed && *seed) y_take_pair(f, map, seed, indent);
    while (f->pos < f->n) {
        y_line *ln = &f->lines[f->pos];
        if (ln->blank) {
            f->pos++;
            continue;
        }
        if (ln->indent != indent) break;
        if (ln->text[0] == '-') break;
        char *text = ln->text;
        f->pos++;
        y_take_pair(f, map, text, indent);
    }
    return map;
}

static y_node *y_parse_seq_body(y_file *f, int indent) {
    y_node *seq = y_new(Y_SEQ);
    if (!seq) return NULL;
    while (f->pos < f->n) {
        y_line *ln = &f->lines[f->pos];
        if (ln->blank) {
            f->pos++;
            continue;
        }
        if (ln->indent != indent || ln->text[0] != '-') break;
        const char *rest = ln->text + 1;
        while (*rest == ' ') rest++;
        int item_indent = ln->indent;
        int content_indent = item_indent + 2;
        f->pos++;

        y_node *item;
        if (*rest == 0) {
            int ni = y_next_indent(f);
            item = (ni > item_indent) ? y_parse_block(f, ni) : y_new(Y_SCALAR);
        } else if (y_looks_like_pair(rest) && rest[0] != '"' && rest[0] != '\'') {
            item = y_parse_map_body(f, content_indent, rest);
        } else if (rest[0] == '"' || rest[0] == '\'') {
            /* a quoted scalar may still be a key, but only if a colon follows
             * the closing quote */
            item = y_new(Y_SCALAR);
            item->scalar = y_unquote(rest);
        } else {
            item = y_new(Y_SCALAR);
            item->scalar = y_unquote(rest);
        }
        if (!item) break;
        if (!seq->child) {
            seq->child = item;
        } else {
            y_node *t = seq->child;
            while (t->next) t = t->next;
            t->next = item;
        }
    }
    return seq;
}

static y_node *y_parse_block(y_file *f, int indent) {
    if (f->pos >= f->n) return NULL;
    if (f->lines[f->pos].blank) {
        f->pos++;
        return y_parse_block(f, indent);
    }
    if (f->lines[f->pos].text[0] == '-') return y_parse_seq_body(f, indent);
    return y_parse_map_body(f, indent, NULL);
}

/* ---- accessors --------------------------------------------------------- */

static const y_node *y_get(const y_node *map, const char *key) {
    if (!map || map->type != Y_MAP) return NULL;
    for (const y_node *c = map->child; c; c = c->next)
        if (c->key && !strcmp(c->key, key)) return c;
    return NULL;
}

static const char *y_str(const y_node *n, const char *def) {
    if (!n) return def;
    if (n->type == Y_SCALAR && n->scalar) return n->scalar;
    return def;
}

static int y_bool(const y_node *n, int def) {
    const char *s = y_str(n, NULL);
    if (!s) return def;
    if (!strcasecmp(s, "true") || !strcmp(s, "yes") || !strcmp(s, "on")) return 1;
    if (!strcasecmp(s, "false") || !strcmp(s, "no") || !strcmp(s, "off")) return 0;
    return def;
}

/* ---- CIDR arena -------------------------------------------------------- */

typedef struct {
    int v4;
    uint32_t net4, mask4;
    uint8_t net6[16], mask6[16];
} cidr;

static cidr *cidr_pool;
static size_t cidr_count, cidr_cap;

static int cidr_parse(const char *spec, cidr *out) {
    memset(out, 0, sizeof *out);
    char tmp[128];
    snprintf(tmp, sizeof tmp, "%s", spec);
    char *slash = strchr(tmp, '/');
    int bits = slash ? atoi(slash + 1) : -1;
    if (slash) *slash = 0;
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, tmp, &a4) == 1) {
        if (bits < 0) bits = 32;
        if (bits > 32) bits = 32;
        out->v4 = 1;
        out->mask4 = bits == 0 ? 0 : 0xFFFFFFFFu << (32 - bits);
        out->net4 = ntohl(a4.s_addr) & out->mask4;
        return 0;
    }
    if (inet_pton(AF_INET6, tmp, &a6) == 1) {
        if (bits < 0) bits = 128;
        if (bits > 128) bits = 128;
        for (int i = 0; i < 16; i++) {
            int keep = bits - i * 8;
            uint8_t m = keep >= 8 ? 0xff : keep <= 0 ? 0 : (uint8_t)(0xffu << (8 - keep));
            out->mask6[i] = m;
            out->net6[i] = a6.s6_addr[i] & m;
        }
        return 0;
    }
    return -1;
}

static int cidr_contains(const cidr *c, const char *ip) {
    struct in6_addr a6;
    struct in_addr a4;
    if (c->v4) {
        if (strchr(ip, ':')) {
            /* a mapped v4 client still has to match a v4 rule */
            struct in6_addr v6;
            static const uint8_t mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
            if (inet_pton(AF_INET6, ip, &v6) != 1) return 0;
            if (memcmp(v6.s6_addr, mapped, 12) != 0) return 0;
            char v4s[32];
            snprintf(v4s, sizeof v4s, "%u.%u.%u.%u", v6.s6_addr[12], v6.s6_addr[13],
                     v6.s6_addr[14], v6.s6_addr[15]);
            return cidr_contains(c, v4s);
        }
        if (inet_pton(AF_INET, ip, &a4) != 1) return 0;
        return (ntohl(a4.s_addr) & c->mask4) == c->net4;
    }
    if (!strchr(ip, ':')) {
        if (inet_pton(AF_INET, ip, &a4) != 1) return 0;
        memset(&a6, 0, sizeof a6);
        a6.s6_addr[10] = a6.s6_addr[11] = 0xff;
        memcpy(a6.s6_addr + 12, &a4, 4);
    } else if (inet_pton(AF_INET6, ip, &a6) != 1) {
        return 0;
    }
    for (int i = 0; i < 16; i++)
        if ((a6.s6_addr[i] & c->mask6[i]) != c->net6[i]) return 0;
    return 1;
}

static int cidr_add(const char *spec) {
    cidr c;
    if (cidr_parse(spec, &c) != 0) return -1;
    if (cidr_count == cidr_cap) {
        size_t bigger = cidr_cap ? cidr_cap * 2 : 256;
        cidr *p = realloc(cidr_pool, bigger * sizeof *p);
        if (!p) return -1;
        cidr_pool = p;
        cidr_cap = bigger;
    }
    cidr_pool[cidr_count++] = c;
    return 0;
}

/* ---- the CEL subset ---------------------------------------------------- */

/* defined with the policy table below; the expression engine needs it for
 * .matches() */
static char *re2_to_posix(const char *pat, int *case_insensitive);

typedef struct {
    const request *rq;
    const char *ip;
    double weight;
    int ok;                  /* 0 once anything unsupported is seen */
} exctx;

static void ex_trim(const char **p) {
    while (**p == ' ' || **p == '\t') (*p)++;
}

static void ex_rtrim(char *s) {
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
}

/* .matches("regex") is used by two shipped rules. Compile on demand and keep a
 * few patterns; a policy has a handful, not thousands. */
#define EX_RE_CACHE 8
static struct {
    char pat[256];
    regex_t re;
    int set;
} ex_re_cache[EX_RE_CACHE];
static int ex_re_next;

static int ex_regex(const char *pat, const char *hay) {
    for (int i = 0; i < EX_RE_CACHE; i++)
        if (ex_re_cache[i].set && !strcmp(ex_re_cache[i].pat, pat))
            return regexec(&ex_re_cache[i].re, hay, 0, NULL, 0) == 0;
    int slot = ex_re_next++ % EX_RE_CACHE;
    if (ex_re_cache[slot].set) {
        regfree(&ex_re_cache[slot].re);
        ex_re_cache[slot].set = 0;
    }
    int icase = 0;
    char *posix = re2_to_posix(pat, &icase);
    if (!posix) return 0;
    int rc = regcomp(&ex_re_cache[slot].re, posix, REG_EXTENDED | REG_NOSUB |
                     (icase ? REG_ICASE : 0));
    free(posix);
    if (rc != 0) return 0;
    snprintf(ex_re_cache[slot].pat, sizeof ex_re_cache[slot].pat, "%s", pat);
    ex_re_cache[slot].set = 1;
    return regexec(&ex_re_cache[slot].re, hay, 0, NULL, 0) == 0;
}

static int ex_match_parens(const char *s) {
    /* s starts with '('; is its match the final character? */
    int depth = 0, q = 0;
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (q) {
            if (c == q) q = 0;
            continue;
        }
        if (c == '"' || c == '\'') q = c;
        else if (c == '(') depth++;
        else if (c == ')') {
            depth--;
            if (depth == 0) return s[i + 1] == 0;
        }
    }
    return 0;
}

static int ex_find_top(const char *s, const char *op, size_t *at) {
    int depth = 0, q = 0;
    size_t n = strlen(op);
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (q) {
            if (c == q) q = 0;
            continue;
        }
        if (c == '"' || c == '\'') { q = c; continue; }
        if (c == '(') { depth++; continue; }
        if (c == ')') { if (depth) depth--; continue; }
        if (!depth && !strncmp(s + i, op, n)) {
            *at = i;
            return 1;
        }
    }
    return 0;
}

/* Reads a quoted string at *p into buf. Returns 1 on success and advances *p. */
static int ex_quoted(const char **p, char *buf, size_t cap) {
    ex_trim(p);
    char q = **p;
    if (q != '"' && q != '\'') return 0;
    (*p)++;
    size_t n = 0;
    while (**p && **p != q) {
        if (n + 1 < cap) buf[n++] = **p;
        (*p)++;
    }
    if (**p != q) return 0;
    (*p)++;
    buf[n] = 0;
    return 1;
}

static int ex_cmp_num(double a, const char *op, double b) {
    if (!strcmp(op, ">=")) return a >= b;
    if (!strcmp(op, "<=")) return a <= b;
    if (!strcmp(op, "==")) return a == b;
    if (!strcmp(op, "!=")) return a != b;
    if (!strcmp(op, ">")) return a > b;
    if (!strcmp(op, "<")) return a < b;
    return 0;
}

static int ex_str_pred(const char *hay, const char *op, const char *needle) {
    if (!strcmp(op, "==")) return !strcmp(hay, needle);
    if (!strcmp(op, "!=")) return strcmp(hay, needle) != 0;
    if (!strcmp(op, "contains")) return strstr(hay, needle) != NULL;
    if (!strcmp(op, "startsWith")) return !strncmp(hay, needle, strlen(needle));
    if (!strcmp(op, "endsWith")) {
        size_t h = strlen(hay), n = strlen(needle);
        return h >= n && !strcmp(hay + h - n, needle);
    }
    return 0;
}

static int ex_eval(exctx *cx, const char *raw);

static int ex_leaf(exctx *cx, const char *s) {
    /* "NAME" in headers */
    const char *p = s;
    if (*p == '"' || *p == '\'') {
        char name[128];
        if (ex_quoted(&p, name, sizeof name)) {
            ex_trim(&p);
            if (!strcmp(p, "in headers")) {
                return cx->rq ? header_value(cx->rq, name) != NULL : 0;
            }
        }
        cx->ok = 0;
        return 0;
    }

    /* weight OP number, load_1m OP number, load_15m OP number */
    struct {
        const char *name;
        int which;          /* 0 weight, 1 load_1m, 2 load_15m */
    } subjects[] = {{"weight", 0}, {"load_1m", 1}, {"load_15m", 2}};
    for (size_t i = 0; i < sizeof subjects / sizeof subjects[0]; i++) {
        size_t n = strlen(subjects[i].name);
        if (strncmp(s, subjects[i].name, n) != 0) continue;
        const char *r = s + n;
        ex_trim(&r);
        char op[3] = "";
        if (r[0] == '>' || r[0] == '<' || r[0] == '=' || r[0] == '!') {
            size_t ol = (r[1] == '=') ? 2 : 1;
            memcpy(op, r, ol);
            op[ol] = 0;
            r += ol;
        } else {
            cx->ok = 0;
            return 0;
        }
        ex_trim(&r);
        char *end = NULL;
        double num = strtod(r, &end);
        if (end == r) {
            cx->ok = 0;
            return 0;
        }
        while (*end == ' ') end++;
        if (*end) {
            cx->ok = 0;
            return 0;
        }
        double value = subjects[i].which == 0 ? cx->weight : 0;
        if (subjects[i].which == 1 || subjects[i].which == 2) {
            FILE *lf = fopen("/proc/loadavg", "r");
            if (lf) {
                double l1 = 0, l5 = 0;
                if (fscanf(lf, "%lf %lf", &l1, &l5) == 2)
                    value = subjects[i].which == 1 ? l1 : l5;
                fclose(lf);
            }
        }
        return ex_cmp_num(value, op, num);
    }

    /* userAgent / path / headers["N"], then a predicate */
    const char *subject = NULL;
    char hdrname[128] = "";
    if (!strncmp(s, "userAgent", 9)) {
        subject = s + 9;
    } else if (!strncmp(s, "host", 4)) {
        subject = s + 4;
    } else if (!strncmp(s, "path", 4)) {
        subject = s + 4;
    } else if (!strncmp(s, "headers[", 8)) {
        p = s + 8;
        if (!ex_quoted(&p, hdrname, sizeof hdrname)) return (cx->ok = 0), 0;
        ex_trim(&p);
        if (*p != ']') return (cx->ok = 0), 0;
        subject = p + 1;
    } else if (!strcmp(s, "true")) {
        return 1;
    } else if (!strcmp(s, "false")) {
        return 0;
    } else {
        cx->ok = 0;
        return 0;
    }

    const char *q = subject;
    ex_trim(&q);
    char op[24] = "";
    if (q[0] == '.') {
        q++;
        const char *open = strchr(q, '(');
        if (!open) return (cx->ok = 0), 0;
        size_t ol = (size_t)(open - q);
        if (ol >= sizeof op) return (cx->ok = 0), 0;
        memcpy(op, q, ol);
        op[ol] = 0;
        q = open;
    } else if (q[0] == '=' || q[0] == '!') {
        size_t ol = (q[1] == '=') ? 2 : 1;
        memcpy(op, q, ol);
        op[ol] = 0;
        q += ol;
    } else {
        cx->ok = 0;
        return 0;
    }
    char needle[256];
    if (op[0] == '=' || op[0] == '!') {
        if (!ex_quoted(&q, needle, sizeof needle)) return (cx->ok = 0), 0;
    } else {
        if (*q != '(') return (cx->ok = 0), 0;
        q++;
        if (!ex_quoted(&q, needle, sizeof needle)) return (cx->ok = 0), 0;
        ex_trim(&q);
        if (*q != ')') return (cx->ok = 0), 0;
    }

    const char *have = "";
    if (!strncmp(s, "userAgent", 9)) {
        have = cx->rq ? header_value(cx->rq, "User-Agent") : "";
    } else if (!strncmp(s, "host", 4)) {
        have = cx->rq ? header_value(cx->rq, "Host") : "";
    } else if (!strncmp(s, "path", 4)) {
        have = cx->rq ? cx->rq->path : "";
    } else {
        have = cx->rq ? header_value(cx->rq, hdrname) : "";
    }
    if (!strcmp(op, "matches")) return ex_regex(needle, have ? have : "");
    return ex_str_pred(have ? have : "", op, needle);
}

static int ex_eval(exctx *cx, const char *raw) {
    char buf[1024];
    snprintf(buf, sizeof buf, "%s", raw);
    ex_rtrim(buf);
    char *s = buf;
    ex_trim((const char **)&s);
    /* strip redundant outer parentheses */
    int guard = 0;
    while (s[0] == '(' && ex_match_parens(s) && guard++ < 8) {
        s[strlen(s) - 1] = 0;
        s++;
        ex_trim((const char **)&s);
    }
    if (!*s) return (cx->ok = 0), 0;

    size_t at;
    if (ex_find_top(s, "||", &at) || ex_find_top(s, "&&", &at)) {
        int is_or = s[at] == '|';
        char left[1024];
        snprintf(left, sizeof left, "%.*s", (int)at, s);
        ex_rtrim(left);
        /* both sides, always: short-circuiting here would hide an unsupported
         * sub-expression from the load-time check and leave a rule inert */
        int a = ex_eval(cx, left);
        int b = ex_eval(cx, s + at + 2);
        return is_or ? (a || b) : (a && b);
    }
    if (s[0] == '!' && s[1] != '=') return !ex_eval(cx, s + 1);
    return ex_leaf(cx, s);
}

/* ---- the rule and threshold tables ------------------------------------ */

typedef struct {
    char name[96];
    int action;                 /* 0 ALLOW, 1 DENY, 2 CHALLENGE, 3 WEIGH */
    regex_t ua_re, path_re;
    int has_ua, has_path;
    struct {
        char name[64];
        regex_t re;
        int exists_only;        /* the value was ".*": present and non-empty */
    } hdr[MAX_RULE_HEADERS];
    int nhdr;
    char expr[1024];
    int has_expr;
    size_t cidr_start, cidr_len;
    int difficulty;
    char algorithm[24];
    int weight_adjust;
    const char *from;
} yrule;

typedef struct {
    char name[96];
    int action;
    int difficulty;
    char algorithm[24];
    char expr[1024];
    int has_expr;
    const char *from;
} ythreshold;

static yrule *yml_rules;
static int yml_rule_count, yml_rule_cap;
static ythreshold yml_thresholds[MAX_YAML_THRESHOLDS];
static int yml_threshold_count;
static int yml_loaded;
static const char *yml_data_dir = "data";
static int yml_unsupported_reported;

/* The shipped patterns are written for RE2. These substitutions cover the
 * syntax that appears in the tree; anything else fails to compile and the rule
 * is reported and skipped, rather than silently matching nothing. */
static char *re2_to_posix(const char *pat, int *case_insensitive) {
    size_t cap = strlen(pat) * 8 + 16;
    char *out = malloc(cap);
    if (!out) return NULL;
    size_t o = 0;
    *case_insensitive = 0;
    for (size_t i = 0; pat[i]; i++) {
        if (!strncmp(pat + i, "(?:", 3)) {
            out[o++] = '(';                 /* POSIX groups do not capture */
            i += 2;
            continue;
        }
        if (!strncmp(pat + i, "(?i:", 4)) {
            /* POSIX has no partial case folding, so the whole pattern is
             * compiled case-insensitively. Every such pattern in the tree wraps
             * the whole expression, so this is what it meant. */
            *case_insensitive = 1;
            out[o++] = '(';
            i += 3;
            continue;
        }
        if (pat[i] == '\\' && pat[i + 1] == 'd') {
            memcpy(out + o, "[0-9]", 5);
            o += 5;
            i++;
            continue;
        }
        if (pat[i] == '\\' && pat[i + 1] == 'w') {
            memcpy(out + o, "[[:alnum:]_]", 12);
            o += 12;
            i++;
            continue;
        }
        if (pat[i] == '\\' && pat[i + 1] == 's') {
            memcpy(out + o, "[[:space:]]", 11);
            o += 11;
            i++;
            continue;
        }
        out[o++] = pat[i];
    }
    out[o] = 0;
    return out;
}

static int yml_compile(regex_t *re, const char *pat, int *icase_out) {
    int icase = 0;
    char *posix = re2_to_posix(pat, &icase);
    if (!posix) return -1;
    int flags = REG_EXTENDED | REG_NOSUB | (icase ? REG_ICASE : 0);
    int rc = regcomp(re, posix, flags);
    if (rc != 0) {
        char why[256];
        regerror(rc, re, why, sizeof why);
        logmsg("policy: /%s/ does not compile as a POSIX regex (%s)", posix, why);
        free(posix);
        return -1;
    }
    free(posix);
    if (icase_out) *icase_out = icase;
    return 0;
}

static int yml_action_of(const char *s) {
    if (!s) return -1;
    if (!strcasecmp(s, "ALLOW")) return 0;
    if (!strcasecmp(s, "DENY")) return 1;
    if (!strcasecmp(s, "CHALLENGE")) return 2;
    if (!strcasecmp(s, "WEIGH")) return 3;
    return -1;
}

/* ---- interpreting one rule -------------------------------------------- */

static void yml_load_rule(const y_node *n, const char *from) {
    if (yml_rule_count >= MAX_YAML_RULES) {
        static int warned;
        if (!warned) {
            logmsg("policy: more than %d rules, the rest are ignored", MAX_YAML_RULES);
            warned = 1;
        }
        return;
    }
    const char *name = y_str(y_get(n, "name"), "");
    int action = yml_action_of(y_str(y_get(n, "action"), NULL));
    if (action < 0) {
        logmsg("policy: rule '%s' (%s) has no known action, skipped", name, from);
        return;
    }
    const y_node *geo = y_get(n, "geoip");
    const y_node *asns = y_get(n, "asns");
    if (geo || asns) {
        logmsg("policy: rule '%s' matches on GeoIP or ASN, which this gate does not "
               "have; the rule is ignored", name);
        return;
    }

    yrule r;
    memset(&r, 0, sizeof r);
    snprintf(r.name, sizeof r.name, "%s", name);
    r.action = action;
    r.from = from;

    const char *ua = y_str(y_get(n, "user_agent_regex"), NULL);
    if (ua) {
        if (yml_compile(&r.ua_re, ua, NULL) == 0) r.has_ua = 1;
        else logmsg("policy: rule '%s' has a user_agent_regex that cannot be used, rule skipped", name);
        if (!r.has_ua) {
            if (r.has_path) regfree(&r.path_re);
            for (int i = 0; i < r.nhdr; i++) regfree(&r.hdr[i].re);
            return;
        }
    }
    const char *path = y_str(y_get(n, "path_regex"), NULL);
    if (path) {
        if (yml_compile(&r.path_re, path, NULL) == 0) r.has_path = 1;
        else {
            logmsg("policy: rule '%s' has a path_regex that cannot be used, rule skipped", name);
            if (r.has_ua) regfree(&r.ua_re);
            return;
        }
    }

    const y_node *hdr = y_get(n, "headers_regex");
    if (hdr && hdr->type == Y_MAP) {
        for (const y_node *h = hdr->child; h && r.nhdr < MAX_RULE_HEADERS; h = h->next) {
            if (!h->key) continue;
            snprintf(r.hdr[r.nhdr].name, sizeof r.hdr[r.nhdr].name, "%s", h->key);
            const char *hpat = y_str(h, "");
            if (!strcmp(hpat, ".*")) {
                /* lib/policy/checker.go:171-174 treats .* this way */
                r.hdr[r.nhdr].exists_only = 1;
                r.nhdr++;
                continue;
            }
            if (yml_compile(&r.hdr[r.nhdr].re, hpat, NULL) != 0) {
                logmsg("policy: rule '%s' has a headers_regex that cannot be used, rule skipped", name);
                goto fail;
            }
            r.nhdr++;
        }
    }

    const y_node *expr = y_get(n, "expression");
    if (expr) {
        if (expr->type == Y_SCALAR) {
            snprintf(r.expr, sizeof r.expr, "%s", y_str(expr, ""));
            r.has_expr = 1;
        } else if (expr->type == Y_MAP) {
            const y_node *all = y_get(expr, "all");
            const y_node *any = y_get(expr, "any");
            const y_node *list = all ? all : any;
            if (!list || list->type != Y_SEQ) {
                logmsg("policy: rule '%s' has an expression that is neither a string "
                       "nor all/any, rule skipped", name);
                goto fail;
            }
            /* Fold the list into one expression: all() and any() have the same
             * meaning as the operators, and the evaluator already has both. */
            size_t off = 0;
            for (const y_node *it = list->child; it; it = it->next) {
                const char *item = y_str(it, NULL);
                if (!item) continue;
                off += (size_t)snprintf(r.expr + off, sizeof r.expr - off, "(%s)%s", item,
                                        it->next ? (all ? " && " : " || ") : "");
                if (off >= sizeof r.expr) {
                    logmsg("policy: rule '%s' has an expression that is too long, rule skipped", name);
                    goto fail;
                }
            }
            r.has_expr = 1;
        }
        if (r.has_expr) {
            exctx probe = {0};
            probe.ok = 1;
            ex_eval(&probe, r.expr);
            if (!probe.ok) {
                logmsg("policy: rule '%s' expresses something this gate does not "
                       "evaluate: %s. The rule will never match", name, r.expr);
            }
        }
    }

    const y_node *ch = y_get(n, "challenge");
    if (ch) {
        r.difficulty = atoi(y_str(y_get(ch, "difficulty"), "0"));
        const char *alg = y_str(y_get(ch, "algorithm"), NULL);
        if (alg) {
            if (algorithm_known(alg)) snprintf(r.algorithm, sizeof r.algorithm, "%s", alg);
            else logmsg("policy: rule '%s' names algorithm %s, which this gate does not "
                        "implement; the global algorithm is used", name, alg);
        }
    }

    const y_node *w = y_get(n, "weight");
    if (w) r.weight_adjust = atoi(y_str(y_get(w, "adjust"), "0"));

    const y_node *remote = y_get(n, "remote_addresses");
    if (remote && remote->type == Y_SEQ) {
        r.cidr_start = cidr_count;
        for (const y_node *it = remote->child; it; it = it->next) {
            const char *spec = y_str(it, NULL);
            if (!spec) continue;
            if (cidr_add(spec) != 0)
                logmsg("policy: rule '%s' lists %s, which is not a CIDR", name, spec);
        }
        r.cidr_len = cidr_count - r.cidr_start;
    }

    if (yml_rule_count == yml_rule_cap) {
        int bigger = yml_rule_cap ? yml_rule_cap * 2 : 128;
        yrule *p = realloc(yml_rules, (size_t)bigger * sizeof *p);
        if (!p) return;
        yml_rules = p;
        yml_rule_cap = bigger;
    }
    yml_rules[yml_rule_count++] = r;
    return;

fail:
    if (r.has_ua) regfree(&r.ua_re);
    if (r.has_path) regfree(&r.path_re);
    for (int i = 0; i < r.nhdr; i++) regfree(&r.hdr[i].re);
}

/* ---- imports ----------------------------------------------------------- */

static void yml_import(const char *ref, const char *base_dir, int depth);

static void yml_load_document(const y_node *root, const char *from, int depth,
                              const char *base_dir);

static void yml_import(const char *ref, const char *base_dir, int depth) {
    if (depth > MAX_IMPORT_DEPTH) {
        logmsg("policy: imports nested deeper than %d at %s, stopped", MAX_IMPORT_DEPTH, ref);
        return;
    }
    char path[2048];
    if (!strncmp(ref, "(data)/", 7)) {
        if (!yml_data_dir || !*yml_data_dir) {
            logmsg("policy: %s needs a data directory; pass --data-dir", ref);
            return;
        }
        snprintf(path, sizeof path, "%s/%s", yml_data_dir, ref + 7);
    } else if (ref[0] == '/') {
        snprintf(path, sizeof path, "%s", ref);
    } else {
        snprintf(path, sizeof path, "%s/%s", base_dir && *base_dir ? base_dir : ".", ref);
    }

    y_file f;
    if (y_open(path, &f) != 0) {
        logmsg("policy: cannot read the import %s (%s)", ref, path);
        return;
    }
    y_node *root = y_parse_block(&f, f.lines[0].blank ? f.lines[1].indent : f.lines[0].indent);
    y_close(&f);
    if (!root) {
        logmsg("policy: %s parsed as empty", path);
        return;
    }
    char dir[1024];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) *slash = 0;
    else snprintf(dir, sizeof dir, ".");
    yml_load_document(root, path, depth, dir);
    y_free(root);
}

/* ---- interpreting a document ------------------------------------------ */

static void yml_load_document(const y_node *root, const char *from, int depth,
                              const char *base_dir) {
    if (!root) return;

    /* A bare list is a list of bot rules, which is what the imported files are. */
    if (root->type == Y_SEQ) {
        for (const y_node *it = root->child; it; it = it->next) {
            if (!it) continue;
            const char *imp = y_str(y_get(it, "import"), NULL);
            if (imp) {
                yml_import(imp, base_dir, depth + 1);
                continue;
            }
            if (it->type == Y_MAP) yml_load_rule(it, from);
        }
        return;
    }
    if (root->type != Y_MAP) return;

    const y_node *bots = y_get(root, "bots");
    if (bots && bots->type == Y_SEQ) {
        for (const y_node *it = bots->child; it; it = it->next) {
            const char *imp = y_str(y_get(it, "import"), NULL);
            if (imp) {
                yml_import(imp, base_dir, depth + 1);
                continue;
            }
            if (it->type == Y_MAP) yml_load_rule(it, from);
        }
    }

    const y_node *th = y_get(root, "thresholds");
    if (th && th->type == Y_SEQ) {
        for (const y_node *it = th->child; it; it = it->next) {
            if (yml_threshold_count >= MAX_YAML_THRESHOLDS) {
                logmsg("policy: more than %d thresholds, the rest are ignored",
                       MAX_YAML_THRESHOLDS);
                break;
            }
            ythreshold t;
            memset(&t, 0, sizeof t);
            snprintf(t.name, sizeof t.name, "%s", y_str(y_get(it, "name"), ""));
            int action = yml_action_of(y_str(y_get(it, "action"), NULL));
            if (action < 0) {
                logmsg("policy: threshold '%s' has no known action, skipped", t.name);
                continue;
            }
            t.action = action;
            t.from = from;
            const y_node *expr = y_get(it, "expression");
            if (expr) {
                if (expr->type == Y_SCALAR) {
                    snprintf(t.expr, sizeof t.expr, "%s", y_str(expr, ""));
                    t.has_expr = 1;
                } else if (expr->type == Y_MAP) {
                    const y_node *all = y_get(expr, "all");
                    const y_node *any = y_get(expr, "any");
                    const y_node *list = all ? all : any;
                    size_t off = 0;
                    if (!list || list->type != Y_SEQ) {
                        logmsg("policy: threshold '%s' has an expression this gate cannot "
                               "read, skipped", t.name);
                        continue;
                    }
                    for (const y_node *x = list->child; x; x = x->next) {
                        const char *item = y_str(x, NULL);
                        if (!item) continue;
                        off += (size_t)snprintf(t.expr + off, sizeof t.expr - off, "(%s)%s",
                                                item, x->next ? (all ? " && " : " || ") : "");
                        if (off >= sizeof t.expr) break;
                    }
                    t.has_expr = 1;
                }
            }
            const y_node *ch = y_get(it, "challenge");
            if (ch) {
                t.difficulty = atoi(y_str(y_get(ch, "difficulty"), "0"));
                const char *alg = y_str(y_get(ch, "algorithm"), NULL);
                if (alg && algorithm_known(alg)) snprintf(t.algorithm, sizeof t.algorithm, "%s", alg);
            }
            if (!t.has_expr) {
                logmsg("policy: threshold '%s' has no expression this gate can read, skipped",
                       t.name);
                continue;
            }
            yml_thresholds[yml_threshold_count++] = t;
        }
    }

    const y_node *sc = y_get(root, "status_codes");
    if (sc) {
        int c = atoi(y_str(y_get(sc, "CHALLENGE"), "0"));
        int d = atoi(y_str(y_get(sc, "DENY"), "0"));
        if (c >= 100 && c <= 599) cfg.challenge_status = c;
        if (d >= 100 && d <= 599) cfg.deny_status = d;
    }

    const y_node *hp = y_get(root, "honeypot");
    if (hp) {
        if (y_get(hp, "enabled")) cfg.honeypot = y_bool(y_get(hp, "enabled"), 1);
        const char *logf = y_str(y_get(hp, "ip_log_file"), NULL);
        if (logf && *logf) cfg.honeypot_log = y_dup(logf);
    }

    const y_node *dnsbl = y_get(root, "dnsbl");
    if (dnsbl && y_bool(dnsbl, 0))
        logmsg("policy: dnsbl is enabled in the policy, but this gate has no DNSBL "
               "lookup; that check is not applied");

    /* blocks we knowingly do not implement */
    static const char *const ignored[] = {
        "openGraph", "impressum", "store", "metrics", "geoip", "logging", NULL
    };
    for (int i = 0; ignored[i]; i++)
        if (y_get(root, ignored[i]))
            logmsg("policy: the '%s' block is ignored by betterAnusbis", ignored[i]);
}

/* ---- matching ---------------------------------------------------------- */

static int yml_rule_matches(const yrule *r, const request *rq, const char *ip,
                            double weight) {
    if (!r->has_ua && !r->has_path && r->nhdr == 0 && !r->has_expr && r->cidr_len == 0)
        return 0;               /* a rule with no condition would match everything */
    if (r->has_ua) {
        const char *ua = header_value(rq, "User-Agent");
        if (!ua || regexec(&r->ua_re, ua, 0, NULL, 0) != 0) return 0;
    }
    if (r->has_path) {
        if (regexec(&r->path_re, rq->path, 0, NULL, 0) != 0) return 0;
    }
    for (int i = 0; i < r->nhdr; i++) {
        const char *v = header_value(rq, r->hdr[i].name);
        if (r->hdr[i].exists_only) {
            if (!v || !*v) return 0;          /* present and non-empty */
        } else if (!v || regexec(&r->hdr[i].re, v, 0, NULL, 0) != 0) {
            return 0;
        }
    }
    if (r->cidr_len) {
        int hit = 0;
        for (size_t i = 0; i < r->cidr_len; i++)
            if (cidr_contains(&cidr_pool[r->cidr_start + i], ip)) { hit = 1; break; }
        if (!hit) return 0;
    }
    if (r->has_expr) {
        exctx cx = {.rq = rq, .ip = ip, .weight = weight, .ok = 1};
        if (!ex_eval(&cx, r->expr)) return 0;
    }
    return 1;
}

static int yml_decide(const request *rq, const char *ip, int *difficulty,
                      const char **algorithm) {
    double weight = 0;
    for (int i = 0; i < yml_rule_count; i++) {
        const yrule *r = &yml_rules[i];
        if (!yml_rule_matches(r, rq, ip, weight)) continue;
        if (r->action == 3) {          /* WEIGH */
            weight += r->weight_adjust;
            continue;
        }
        __atomic_fetch_add(&m_policy[i < MAX_RULES ? i : MAX_RULES][r->action], 1,
                           __ATOMIC_RELAXED);
        if (r->difficulty > 0) *difficulty = r->difficulty;
        if (r->algorithm[0]) *algorithm = r->algorithm;
        return r->action;
    }
    for (int i = 0; i < yml_threshold_count; i++) {
        const ythreshold *t = &yml_thresholds[i];
        if (!t->has_expr) continue;
        exctx cx = {.rq = rq, .ip = ip, .weight = weight, .ok = 1};
        if (!ex_eval(&cx, t->expr)) continue;
        if (t->difficulty > 0) *difficulty = t->difficulty;
        if (t->algorithm[0]) *algorithm = t->algorithm;
        return t->action;
    }
    /* Anubis allows a request that matches no rule and no threshold. */
    return 0;
}

static void policy_load_yaml(const char *path) {
    y_file f;
    if (y_open(path, &f) != 0) {
        logmsg("cannot read the policy %s, challenging everything", path);
        return;
    }
    int first = 0;
    while (first < f.n && f.lines[first].blank) first++;
    y_node *root = first < f.n ? y_parse_block(&f, f.lines[first].indent) : NULL;
    y_close(&f);
    if (!root) {
        logmsg("policy: %s parsed as empty; challenging everything", path);
        return;
    }
    char dir[1024];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) *slash = 0;
    else snprintf(dir, sizeof dir, ".");

    yml_load_document(root, path, 0, dir);
    y_free(root);
    yml_loaded = 1;

    int weighed = 0, with_cidr = 0;
    for (int i = 0; i < yml_rule_count; i++) {
        if (yml_rules[i].action == 3) weighed++;
        if (yml_rules[i].cidr_len) with_cidr++;
    }
    logmsg("policy: %d rule(s) and %d threshold(s) read from the Anubis format, "
           "%d conditional, %d range-restricted, %zu CIDR(s). A request that matches "
           "nothing is allowed, as Anubis does",
           yml_rule_count, yml_threshold_count, weighed, with_cidr, cidr_count);
}

static rule rules[MAX_RULES];
static int rule_count;
static int default_action = RULE_CHALLENGE;
static int default_difficulty;
static char default_algorithm[24];

static uint64_t network_key(const char *ip);

static int rule_matches(const rule *r, const request *req, const char *client_ip) {
    const char *subject = NULL;
    if (r->selector == SEL_UA) subject = header_value(req, "User-Agent");
    else if (r->selector == SEL_PATH) subject = req->path;
    else if (r->selector == SEL_HEADER) subject = header_value(req, r->header);

    if (r->selector == SEL_NET) {
        if (r->v4) {
            uint64_t key = network_key(client_ip);
            return ((uint32_t)key & r->mask_v4) == r->net_v4;
        }
        if (r->v6) {
            struct in6_addr addr;
            struct in_addr v4a;
            if (!strchr(client_ip, ':')) {
                if (inet_pton(AF_INET, client_ip, &v4a) != 1) return 0;
                memset(&addr, 0, sizeof addr);
                addr.s6_addr[10] = addr.s6_addr[11] = 0xff;   /* ::ffff:a.b.c.d */
                memcpy(addr.s6_addr + 12, &v4a, 4);
            } else if (inet_pton(AF_INET6, client_ip, &addr) != 1) {
                return 0;
            }
            for (int i = 0; i < 16; i++)
                if ((addr.s6_addr[i] & r->mask_v6[i]) != r->net_v6[i]) return 0;
            return 1;
        }
        return 0;
    }
    if (!subject) return 0;
    if (r->match == 4) return r->has_re && regexec(&r->re, subject, 0, NULL, 0) == 0;
    if (r->match == 1) return strstr(subject, r->value) != NULL;
    if (r->match == 2) return strncmp(subject, r->value, strlen(r->value)) == 0;
    return strcmp(subject, r->value) == 0;
}

/* Where the per-rule options start: the token after the match value. Searching
 * the whole line for "algorithm" would find it inside a regex. */
static const char *policy_tail(const char *line) {
    const char *p = line;
    for (int t = 0; t < 4; t++) {
        while (*p == ' ' || *p == '\t') p++;
        while (*p && *p != ' ' && *p != '\t') p++;
    }
    return p;
}

/* Returns the action to take, and sets *difficulty to the rule's own or the global. */
static rule_action policy_decide(const request *req, const char *client_ip, int *difficulty,
                                 const char **algorithm) {
    if (yml_loaded) return (rule_action)yml_decide(req, client_ip, difficulty, algorithm);
    *difficulty = default_difficulty ? default_difficulty : cfg.difficulty;
    *algorithm = default_algorithm[0] ? default_algorithm : cfg.algorithm;
    for (int i = 0; i < rule_count; i++) {
        if (!rule_matches(&rules[i], req, client_ip)) continue;
        __atomic_fetch_add(&m_policy[i][(int)rules[i].action], 1, __ATOMIC_RELAXED);
        if (rules[i].difficulty > 0) *difficulty = rules[i].difficulty;
        if (rules[i].algorithm[0]) *algorithm = rules[i].algorithm;
        return rules[i].action;
    }
    __atomic_fetch_add(&m_policy[rule_count][(int)default_action], 1, __ATOMIC_RELAXED);
    return (rule_action)default_action;
}

/* Which policy format is this? Anubis's schema starts with a top-level key or a
 * bare rule list; ours starts with allow/deny/challenge/default. */
static int policy_looks_like_anubis(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    int answer = 0;
    while (fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == 0 || *p == '\n' || *p == '\r' || *p == '#') continue;
        if (!strncmp(p, "bots:", 5) || !strncmp(p, "thresholds:", 11) ||
            !strncmp(p, "status_codes:", 13) || !strncmp(p, "openGraph:", 10) ||
            !strncmp(p, "honeypot:", 9) || !strncmp(p, "store:", 6) ||
            !strncmp(p, "dnsbl:", 6) || !strncmp(p, "impressum:", 10) ||
            !strncmp(p, "metrics:", 8) || !strncmp(p, "geoip:", 6) ||
            !strncmp(p, "logging:", 8) || *p == '-' || *p == '{')
            answer = 1;
        break;
    }
    fclose(f);
    return answer;
}

static void policy_load(const char *path) {
    if (policy_looks_like_anubis(path)) {
        yml_data_dir = cfg.data_dir && *cfg.data_dir ? cfg.data_dir : "data";
        policy_load_yaml(path);
        return;
    }
    FILE *f = fopen(path, "r");
    if (!f) { logmsg("cannot read the policy %s, challenging everything", path); return; }
    char line[512];
    while (fgets(line, sizeof line, f)) {
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;
        char action[32] = "", sel[64] = "", how[32] = "", value[128] = "";
        int difficulty = 0;
        int n = sscanf(line, "%31s %63s %31s %255s", action, sel, how, value);
        if (n < 2) continue;
        if (!strcmp(action, "default")) {
            default_action = (!strcmp(sel, "allow")) ? RULE_ALLOW
                             : (!strcmp(sel, "deny")) ? RULE_DENY : RULE_CHALLENGE;
            char *d = strstr(line, "difficulty");
            if (d && sscanf(d, "difficulty %d", &difficulty) == 1) default_difficulty = difficulty;
            char *a = strstr(line, "algorithm");
            if (a && sscanf(a, "algorithm %23s", default_algorithm) == 1 &&
                !algorithm_known(default_algorithm)) {
                logmsg("policy: %s is not a known algorithm; the default stays %s",
                       default_algorithm, cfg.algorithm);
                default_algorithm[0] = 0;
            }
            continue;
        }
        if (rule_count >= MAX_RULES) { logmsg("policy: more than %d rules, ignoring the rest", MAX_RULES); break; }
        rule r = {0};
        if (!strcmp(action, "allow")) r.action = RULE_ALLOW;
        else if (!strcmp(action, "deny")) r.action = RULE_DENY;
        else if (!strcmp(action, "challenge")) r.action = RULE_CHALLENGE;
        else continue;

        if (!strcmp(sel, "ua")) r.selector = SEL_UA;
        else if (!strcmp(sel, "path")) r.selector = SEL_PATH;
        else if (!strcmp(sel, "net")) { r.selector = SEL_NET; }
        else if (!strncmp(sel, "header:", 7)) {
            r.selector = SEL_HEADER;
            snprintf(r.header, sizeof r.header, "%s", sel + 7);
        } else continue;

        if (r.selector == SEL_NET) {
            char netstr[128];
            snprintf(netstr, sizeof netstr, "%s", how);
            char *slash = strchr(netstr, '/');
            int bits = slash ? atoi(slash + 1) : -1;
            if (slash) *slash = 0;
            struct in_addr b4;
            struct in6_addr b6;
            if (inet_pton(AF_INET, netstr, &b4) == 1) {
                if (bits < 0) bits = 32;
                if (bits > 32) bits = 32;
                r.v4 = 1;
                r.mask_v4 = bits == 0 ? 0 : 0xFFFFFFFFu << (32 - bits);
                r.net_v4 = ntohl(b4.s_addr) & r.mask_v4;
                rules[rule_count++] = r;
            } else if (inet_pton(AF_INET6, netstr, &b6) == 1) {
                if (bits < 0) bits = 128;
                if (bits > 128) bits = 128;
                r.v6 = 1;
                for (int i = 0; i < 16; i++) {
                    int keep = bits - i * 8;
                    uint8_t m = keep >= 8 ? 0xff : keep <= 0 ? 0 : (uint8_t)(0xffu << (8 - keep));
                    r.mask_v6[i] = m;
                    r.net_v6[i] = b6.s6_addr[i] & m;
                }
                rules[rule_count++] = r;
            } else {
                logmsg("policy: %s is not an IPv4 or IPv6 address with an optional /prefix, "
                       "that rule is ignored", how);
            }
            continue;
        }

        if (!strcmp(how, "contains")) r.match = 1;
        else if (!strcmp(how, "prefix")) r.match = 2;
        else if (!strcmp(how, "is")) r.match = 3;
        else if (!strcmp(how, "matches")) r.match = 4;
        else {
            logmsg("policy: %s is not contains, prefix, is or matches; that rule is ignored", how);
            continue;
        }
        snprintf(r.value, sizeof r.value, "%s", value);
        if (r.match == 4) {
            int rc = regcomp(&r.re, r.value, REG_EXTENDED);
            if (rc != 0) {
                char why[256];
                regerror(rc, &r.re, why, sizeof why);
                logmsg("policy: /%s/ does not compile (%s); that rule is ignored", r.value, why);
                continue;
            }
            r.has_re = 1;
        }
        const char *tail = policy_tail(line);
        const char *d = strstr(tail, "difficulty");
        if (d && sscanf(d, "difficulty %d", &r.difficulty) == 1) { /* per-rule */ }
        const char *a = strstr(tail, "algorithm");
        if (a && sscanf(a, "algorithm %23s", r.algorithm) == 1) {
            if (!algorithm_known(r.algorithm)) {
                logmsg("policy: %s is not a known algorithm; rule %d keeps the global one",
                       r.algorithm, rule_count);
                r.algorithm[0] = 0;
            }
        }
        rules[rule_count++] = r;
    }
    fclose(f);
    logmsg("policy: %d rule(s) from %s, default %s", rule_count, path,
           default_action == RULE_ALLOW ? "allow" : default_action == RULE_DENY ? "deny" : "challenge");
}

/* ------------------------------------------------------------ the routes */

static void handle_connection(conn *c, const char *peer_ip) {
    char *raw = malloc(MAX_HEADER + 1);
    if (!raw) { close(c->fd); return; }
    int n = read_headers(c, raw, MAX_HEADER + 1);
    if (n <= 0) { free(raw); close(c->fd); return; }
    raw[n] = 0;

    request req;
    if (parse_request(raw, &req) != 0) {
        respond(c, 400, "Bad Request", NULL, NULL, "bad request\n", 12);
        free(raw);
        close(c->fd);
        return;
    }

    /* Who is really asking: the socket peer, or whatever the proxy in front of
     * us recorded. Computed before anything else looks at the address. */
    char client_ip[64];
    client_address(&req, peer_ip, client_ip, sizeof client_ip);

    /* --jwt-restriction-header names a header; if the proxy set it, that value
     * is what the token is bound to, because that is what upstream binds to. It
     * is sanitised first: it ends up inside a JSON string. */
    char bind_buf[128];
    const char *bind_to = client_ip;
    if (cfg.jwt_restrict_hdr && *cfg.jwt_restrict_hdr) {
        const char *hv = header_value(&req, cfg.jwt_restrict_hdr);
        if (hv && *hv) {
            size_t o = 0;
            for (const char *q = hv; *q && o + 1 < sizeof bind_buf; q++) {
                unsigned char ch = (unsigned char)*q;
                if (isalnum(ch) || ch == ':' || ch == '.' || ch == '-' ||
                    ch == '[' || ch == ']' || ch == '_')
                    bind_buf[o++] = (char)ch;
            }
            bind_buf[o] = 0;
            if (o) bind_to = bind_buf;
        }
    }

    /* body, if the client sent one */
    char *hdr_end = strstr(raw, "\r\n\r\n");
    size_t already = hdr_end ? (size_t)(raw + n - (hdr_end + 4)) : 0;
    const char *cl = header_value(&req, "Content-Length");
    size_t content_length = cl ? (size_t)strtoull(cl, NULL, 10) : 0;
    if (content_length && content_length <= MAX_BODY) {
        req.body = calloc(1, content_length);
        if (req.body) {
            size_t got = already < content_length ? already : content_length;
            if (got) memcpy(req.body, hdr_end + 4, got);
            while (got < content_length) {
                ssize_t r = conn_read(c, req.body + got, content_length - got);
                if (r <= 0) break;
                got += (size_t)r;
            }
            req.body_len = got;
        }
    }

    /* --base-prefix: route as if the gate were mounted at the root. The request
     * keeps its own path for the policy and for the log; what goes upstream is
     * the stripped path only when --strip-base-prefix asks for it. */
    char route_buf[4096];
    const char *route = req.path;
    size_t prelen = strlen(cfg.base_prefix);
    if (prelen && !strncmp(route, cfg.base_prefix, prelen) &&
        (route[prelen] == '/' || route[prelen] == 0)) {
        snprintf(route_buf, sizeof route_buf, "%s", route + prelen);
        if (!route_buf[0]) snprintf(route_buf, sizeof route_buf, "/");
        route = route_buf;
    }
    const char *upstream_path = (cfg.strip_base_prefix && route != req.path) ? route : req.path;

    if (cfg.verbose) logmsg("%s %s%s%s from %s%s%s", req.method, req.path,
                            req.query[0] ? "?" : "", req.query[0] ? req.query : "",
                            client_ip, client_ip[0] && strcmp(client_ip, peer_ip) ? " via " : "",
                            client_ip[0] && strcmp(client_ip, peer_ip) ? peer_ip : "");

    char cookie_value[2048];
    int authenticated = 0;
    if (find_cookie(req.headers, cfg.cookie_name, cookie_value, sizeof cookie_value))
        authenticated = verify_token(cookie_value, bind_to);
    if (cfg.debug_benchmark_js) authenticated = 0;   /* --debug-benchmark-js: always challenge */

    if (cfg.serve_robots_txt && !strcmp(route, "/robots.txt")) {
        const char *robots = "User-agent: *\nDisallow: /\n";
        respond(c, 200, "OK", "text/plain; charset=utf-8", NULL, robots, strlen(robots));
    } else if (!strcmp(route, API_PREFIX "ping")) {
        __atomic_fetch_add(&m_requests[M_API], 1, __ATOMIC_RELAXED);
        respond(c, 200, "OK", NULL, NULL, "pong\n", 5);
    } else if (!strcmp(route, API_PREFIX "check")) {
        __atomic_fetch_add(&m_requests[M_API], 1, __ATOMIC_RELAXED);
        if (authenticated) respond(c, 200, "OK", NULL, NULL, "ok\n", 3);
        else respond(c, 401, "Unauthorized", NULL, NULL, "challenge required\n", 19);
    } else if (!strncmp(route, API_PREFIX "static/anubis/", strlen(API_PREFIX) + 14)) {
        __atomic_fetch_add(&m_requests[M_STATIC], 1, __ATOMIC_RELAXED);
        /* the browser's kernels: our own builds, dropped in --web */
        const char *name = route + strlen(API_PREFIX) + 14;
        if (strchr(name, '/') || strstr(name, "..")) {
            respond(c, 404, "Not Found", NULL, NULL, "no\n", 3);
        } else {
            char path[1024];
            snprintf(path, sizeof path, "%s/%s", cfg.web_dir ? cfg.web_dir : "web", name);
            FILE *f = fopen(path, "rb");
            if (!f) {
                respond(c, 404, "Not Found", NULL, NULL, "no such kernel\n", 15);
            } else {
                fseek(f, 0, SEEK_END);
                long len = ftell(f);
                fseek(f, 0, SEEK_SET);
                char *blob = len > 0 && len < (8 << 20) ? malloc((size_t)len) : NULL;
                if (!blob || fread(blob, 1, (size_t)len, f) != (size_t)len) {
                    free(blob);
                    fclose(f);
                    respond(c, 500, "Internal Server Error", NULL, NULL, "read\n", 5);
                } else {
                    fclose(f);
                    respond(c, 200, "OK", "application/wasm", "Cache-Control: max-age=86400\r\n",
                            blob, (size_t)len);
                    free(blob);
                }
            }
        }
    } else if (!strcmp(route, API_PREFIX "state")) {
        __atomic_fetch_add(&m_requests[M_API], 1, __ATOMIC_RELAXED);
        char body[512];
        int n = snprintf(body, sizeof body,
                         "{\"stateful\":%s,\"issued\":%lld,\"accepted\":%lld,"
                         "\"replayed\":%lld,\"expired\":%lld}\n",
                         cfg.stateful ? "true" : "false", ch_issued, ch_accepted,
                         ch_replayed, ch_expired);
        respond(c, 200, "OK", "application/json", NULL, body, (size_t)n);
    } else if (!strcmp(route, API_PREFIX "pass-challenge")) {
        __atomic_fetch_add(&m_requests[M_API], 1, __ATOMIC_RELAXED);
        char id_buf[1024], response_buf[1024], nonce_buf[64], redir_buf[2048], elapsed_buf[64];
        const char *id = query_param(req.query, "id", id_buf, sizeof id_buf);
        const char *response = query_param(req.query, "response", response_buf, sizeof response_buf);
        const char *nonce_s = query_param(req.query, "nonce", nonce_buf, sizeof nonce_buf);
        const char *redir = query_param(req.query, "redir", redir_buf, sizeof redir_buf);
        (void)query_param(req.query, "elapsedTime", elapsed_buf, sizeof elapsed_buf);
        char redir_safe[2048];
        const char *go = safe_redirect(&req, redir, redir_safe, sizeof redir_safe);

        /* The id carries the challenge, so the server keeps no state:
         *   id = <hex randomData>.<unix time it was issued>
         * That makes verification a pure function and bounds nothing in memory.
         * A client can present any randomData it likes - it still has to solve
         * the proof for it, which is the whole point. What we give up is a
         * spent-challenge ledger; replaying a *solved* challenge is possible
         * within the window, and the window is the check below. */
        char rd_hex[128] = "";
        long long issued_at = 0;
        int have_challenge = 0;
        if (id) {
            char *dot = strrchr(id, '.');
            if (dot) {
                size_t n = (size_t)(dot - id);
                if (n > 0 && n < sizeof rd_hex) {
                    memcpy(rd_hex, id, n);
                    rd_hex[n] = 0;
                    issued_at = atoll(dot + 1);
                    have_challenge = strlen(rd_hex) % 2 == 0 && strlen(rd_hex) >= 2;
                }
            }
        }
        unsigned long long nonce = nonce_s ? strtoull(nonce_s, NULL, 10) : 0;
        char digest[65];
        int valid = 0;
        /* Which algorithm this id was issued for. Peeked, not taken, because the
         * metarefresh path answers before it would consume anything. */
        char peeked_algo[24];
        const char *algorithm = cfg.algorithm;
        if (ch_peek_algorithm(id, peeked_algo, sizeof peeked_algo) && peeked_algo[0])
            algorithm = peeked_algo;
        int used_difficulty = cfg.difficulty;
        int need_work = strcasecmp(algorithm, "metarefresh") != 0;

        if (!id || (need_work && (!response || !nonce_s))) {
            const char *msg = "betterAnusbis: pass-challenge needs id, response and nonce\n";
            respond(c, 400, "Bad Request", NULL, NULL, msg, strlen(msg));
        } else {

            /* metarefresh: no hashing, just elapsed time and the challenge echoed
             * back, exactly as lib/challenge/metarefresh/metarefresh.go checks */
            if (!strcasecmp(algorithm, "metarefresh")) {
                char gbuf[512];
                const char *got = query_param(req.query, "challenge", gbuf, sizeof gbuf);
                long long wait_ms = (long long)cfg.difficulty * 800;
                long long waited = issued_at ? (long long)time(NULL) * 1000 - issued_at * 1000
                                             : wait_ms;
                int time_ok = waited >= wait_ms;
                int data_ok = have_challenge && got && strlen(got) == strlen(rd_hex) &&
                              memcmp(got, rd_hex, strlen(rd_hex)) == 0;
                valid = time_ok && data_ok;
                if (!valid) {
                    logmsg("metarefresh rejected: waited %lld of %lld ms, challenge %s",
                           waited, wait_ms, data_ok ? "matched" : "did not match");
                }
                if (valid) {
                    char token[2048];
                    if (sign_token(token, sizeof token, id, bind_to, algorithm) == 0) {
                        char attrs[512];
                        cookie_attrs(attrs, sizeof attrs, cfg.cookie_ttl > 0 ? cfg.cookie_ttl : -1);
                        char extra[4096];
                        snprintf(extra, sizeof extra, "Set-Cookie: %s=%s%s\r\n",
                                 cfg.cookie_name, token, attrs);
                        respond_redirect(c, go, extra);
                        __atomic_fetch_add(&m_validated, 1, __ATOMIC_RELAXED);
                        logmsg("metarefresh passed (waited %lld ms)", waited);
                    } else {
                        respond(c, 500, "Internal Server Error", NULL, NULL, "cannot sign\n", 13);
                    }
                } else {
                    __atomic_fetch_add(&m_failed, 1, __ATOMIC_RELAXED);
                    char msg[512];
                    snprintf(msg, sizeof msg,
                             "betterAnusbis: metarefresh wants a %lld ms wait and the challenge "
                             "echoed as ?challenge=<randomData>\n", wait_ms);
                    respond(c, 403, "Forbidden", NULL, NULL, msg, strlen(msg));
                }
                goto done;
            }

            if (cfg.stateful) {
                char stored[65], taken_algo[24] = "";
                int stored_difficulty = 0;
                int rc = ch_take(id, stored, sizeof stored, &stored_difficulty,
                                 taken_algo, sizeof taken_algo);
                if (rc == 1) {
                    if (taken_algo[0]) algorithm = taken_algo;
                    used_difficulty = stored_difficulty;
                    valid = verify_answer(algorithm, stored, nonce, stored_difficulty,
                                          digest, sizeof digest);
                    if (valid && strcasecmp(response, digest) != 0) {
                        logmsg("rejecting: response %s is not the digest %s for nonce %llu",
                               response, digest, nonce);
                        valid = 0;
                    }
                } else if (rc == -2) {
                    logmsg("rejecting: challenge %s was already spent", id);
                    const char *msg = "betterAnusbis: that challenge was already used\n";
                    respond(c, 403, "Forbidden", NULL, NULL, msg, strlen(msg));
                    goto done;
                } else if (rc == -1) {
                    logmsg("rejecting: challenge %s expired", id);
                } else {
                    logmsg("rejecting: id %s is not a challenge we issued", id);
                }
            } else if (!have_challenge) {
                logmsg("rejecting: id %s is not a challenge we issued", id);
            } else if (issued_at && time(NULL) - issued_at > COOKIE_TTL) {
                logmsg("rejecting: challenge %s expired", id);
            } else {
                valid = verify_answer(algorithm, rd_hex, nonce, cfg.difficulty,
                                      digest, sizeof digest);
                if (valid && strcasecmp(response, digest) != 0) {
                    logmsg("rejecting: response %s is not the digest %s for nonce %llu",
                           response, digest, nonce);
                    valid = 0;
                }
            }

            if (!valid) {
                __atomic_fetch_add(&m_failed, 1, __ATOMIC_RELAXED);
                const char *msg =
                    "betterAnusbis: that answer did not verify\n"
                    "  the challenge id, the response and the nonce have to match\n";
                respond(c, 403, "Forbidden", NULL, NULL, msg, strlen(msg));
            } else {
                char token[2048];
                if (sign_token(token, sizeof token, id, bind_to, algorithm) != 0) {
                    respond(c, 500, "Internal Server Error", NULL, NULL, "cannot sign\n", 13);
                } else {
                    char attrs[512];
                    cookie_attrs(attrs, sizeof attrs, cfg.cookie_ttl > 0 ? cfg.cookie_ttl : -1);
                    char extra[4096];
                    snprintf(extra, sizeof extra,
                             "Set-Cookie: %s=%s%s\r\n"
                             "Set-Cookie: %s-cookie-verification=; Path=/; Max-Age=0\r\n",
                             cfg.cookie_name, token, attrs, cfg.cookie_prefix);
                    respond_redirect(c, go, extra);
                    __atomic_fetch_add(&m_validated, 1, __ATOMIC_RELAXED);
                    logmsg("challenge passed (nonce %llu, %s, difficulty %d)", nonce,
                           algorithm, used_difficulty);
                }
            }
        }
    } else if (!strncmp(route, API_PREFIX "honeypot/",
                        strlen(API_PREFIX) + strlen("honeypot/"))) {
        /* a request to a path only the trap link points at. Count it, make the
         * crawler wait, and hand it a page full of more trap links. */
        const char *rest = route + strlen(API_PREFIX) + strlen("honeypot/");
        char idbuf[64] = "trap";
        const char *slash = strchr(rest, '/');
        if (slash) {
            size_t n = (size_t)(slash - rest);
            if (n >= sizeof idbuf) n = sizeof idbuf - 1;
            memcpy(idbuf, rest, n);
            idbuf[n] = 0;
        }
        __atomic_fetch_add(&m_requests[M_HONEYPOT], 1, __ATOMIC_RELAXED);
        hp_record(client_ip);
        int count = hp_count(client_ip);
        if (cfg.verbose) logmsg("honeypot: maze for %s (hit %d in the window)", client_ip, count);
        hp_tarpit(count);
        honeypot_maze(c, idbuf, slash ? slash + 1 : "init", client_ip, count);
    } else {
        /* The policy is asked before the cookie is looked at, which is Anubis's
         * order: ALLOW forwards, DENY denies even a client that solved a
         * challenge earlier, and a CHALLENGE result is the only one a valid
         * cookie satisfies. */
        int difficulty = cfg.difficulty;
        int policy_difficulty = 0;
        const char *algorithm = cfg.algorithm;
        rule_action action = policy_decide(&req, client_ip, &policy_difficulty, &algorithm);
        if (action == RULE_ALLOW) {
            __atomic_fetch_add(&m_requests[M_ALLOWED], 1, __ATOMIC_RELAXED);
            __atomic_fetch_add(&m_proxied, 1, __ATOMIC_RELAXED);
            proxy_request(c, &req, client_ip, upstream_path);
            goto done;
        }
        if (action == RULE_DENY) {
            /* Anubis DENYs with a 200 on purpose, so the scraper thinks it got
             * the page; --deny-status 403 is the honest answer. */
            const char *msg = "betterAnusbis: denied by policy\n";
            __atomic_fetch_add(&m_requests[M_DENIED], 1, __ATOMIC_RELAXED);
            respond(c, cfg.deny_status, reason_for(cfg.deny_status), NULL, NULL,
                    msg, strlen(msg));
            goto done;
        }
        if (authenticated) {
            __atomic_fetch_add(&m_requests[M_PROXIED], 1, __ATOMIC_RELAXED);
            __atomic_fetch_add(&m_proxied, 1, __ATOMIC_RELAXED);
            proxy_request(c, &req, client_ip, upstream_path);
            goto done;
        }
        if (policy_difficulty > 0) difficulty = policy_difficulty;
        if (!cfg.stateful && strcmp(algorithm, cfg.algorithm) != 0) {
            /* The id has no room for an algorithm, so a per-rule algorithm needs
             * the ledger. Say so rather than hand out a challenge nobody can
             * verify. */
            logmsg("policy: rule wanted %s but --stateless cannot remember that; "
                   "issuing %s", algorithm, cfg.algorithm);
            algorithm = cfg.algorithm;
        }
        /* A network the honeypot has caught gets a harder challenge. Anubis adds
         * weight 30 to its policy rule and lets the thresholds decide; with one
         * rule here, +8 bits is the equivalent wall. */
        int trap_hits = hp_count(client_ip);
        if (trap_hits >= cfg.flag_threshold) {
            difficulty = cfg.difficulty + 8 > 64 ? 64 : cfg.difficulty + 8;
            if (cfg.verbose)
                logmsg("honeypot: %s has %d trap hits, difficulty raised %d -> %d",
                       client_ip, trap_hits, cfg.difficulty, difficulty);
        }
        uint8_t rd[32];
        char rd_hex[65];
        if (random_bytes(rd, sizeof rd) != 0) { respond(c, 500, "Internal Server Error", NULL, NULL, "entropy", 7); }
        else {
            hex_encode(rd, sizeof rd, rd_hex);
            char id[128];
            snprintf(id, sizeof id, "%s.%lld", rd_hex, (long long)time(NULL));
            const char *ua = header_value(&req, "User-Agent");
            char metadata[512];
            snprintf(metadata, sizeof metadata,
                     "{\"Referer\":\"\",\"User-Agent\":\"%.200s\",\"X-Real-IP\":\"%s\"}",
                     ua ? ua : "", client_ip);

            ch_issue(id, rd_hex, difficulty, algorithm);
            __atomic_fetch_add(&m_requests[M_CHALLENGED], 1, __ATOMIC_RELAXED);
            __atomic_fetch_add(&m_issued, 1, __ATOMIC_RELAXED);
            challenge_page(c, id, rd_hex, metadata, id, algorithm, difficulty);
        }
    }

done:
    free(req.headers);
    free(req.body);
    free(raw);
    close(c->fd);
}

/* ------------------------------------------------------------- main loop */

typedef struct {
    int fd;
    int tls;
} accepted;

static void *thread_main(void *arg) {
    accepted a = *(accepted *)arg;
    free(arg);
    int fd = a.fd;
    conn c = {.fd = fd, .ssl = NULL};
    if (a.tls && server_ctx) {
        SSL *ssl = SSL_new(server_ctx);
        SSL_set_fd(ssl, fd);
        if (SSL_accept(ssl) != 1) {
            if (cfg.verbose) logmsg("TLS handshake failed from fd %d", fd);
            SSL_free(ssl);
            close(fd);
            return NULL;
        }
        c.ssl = ssl;
    }
    struct sockaddr_storage peer;
    socklen_t plen = sizeof peer;
    char ip[64] = "0.0.0.0";
    if (getpeername(fd, (struct sockaddr *)&peer, &plen) == 0) {
        if (peer.ss_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)&peer)->sin_addr, ip, sizeof ip);
        else if (peer.ss_family == AF_INET6)
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&peer)->sin6_addr, ip, sizeof ip);
    }
    handle_connection(&c, ip);
    if (c.ssl) {
        SSL_shutdown((SSL *)c.ssl);
        SSL_free((SSL *)c.ssl);
    }
    return NULL;
}

static int parse_listen(const char *spec, struct sockaddr_in6 *out) {
    memset(out, 0, sizeof *out);
    out->sin6_family = AF_INET6;
    out->sin6_addr = in6addr_any;
    const char *colon = strrchr(spec, ':');
    if (!colon) return -1;
    out->sin6_port = htons((uint16_t)atoi(colon + 1));

    /* ":8080" keeps meaning every interface. "127.0.0.1:8080" has to mean that
     * address: a gate that says it listens on the loopback should not be
     * answering the whole network. */
    size_t hostlen = (size_t)(colon - spec);
    if (hostlen == 0) return 0;
    while (hostlen >= 2 && spec[0] == '[' && spec[hostlen - 1] == ']') {
        spec++;
        hostlen -= 2;
    }
    char host[64];
    if (hostlen >= sizeof host) return -1;
    memcpy(host, spec, hostlen);
    host[hostlen] = 0;

    struct in6_addr v6;
    struct in_addr v4;
    if (inet_pton(AF_INET6, host, &v6) == 1) {
        out->sin6_addr = v6;
        return 0;
    }
    if (inet_pton(AF_INET, host, &v4) == 1) {
        /* an IPv4 literal on an AF_INET6 socket is written as the mapped form */
        static const unsigned char mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        memcpy(out->sin6_addr.s6_addr, mapped, 12);
        memcpy(out->sin6_addr.s6_addr + 12, &v4, 4);
        return 0;
    }
    return -1;                  /* a bind address, not a hostname to resolve */
}

static void parse_target(const char *url) {
    const char *p = url;
    cfg.target_tls = 0;
    if (!strncmp(p, "https://", 8)) { cfg.target_tls = 1; p += 8; }
    else if (!strncmp(p, "http://", 7)) { p += 7; }
    const char *slash = strchr(p, '/');
    size_t n = slash ? (size_t)(slash - p) : strlen(p);
    char hostport[256];
    if (n >= sizeof hostport) n = sizeof hostport - 1;
    memcpy(hostport, p, n);
    hostport[n] = 0;
    char *colon = strchr(hostport, ':');
    if (colon) {
        *colon = 0;
        cfg.target_port = atoi(colon + 1);
    } else {
        cfg.target_port = cfg.target_tls ? 443 : 80;
    }
    snprintf(cfg.target_host, sizeof cfg.target_host, "%s", hostport);
}

static void usage(FILE *out) {
    fprintf(out,
        "betterAnusbis " VERSION " - an Anubis-compatible proof-of-work gate, in one C file\n"
        "\n"
        "usage: betterAnusbis --target http://127.0.0.1:3000 [options]\n"
        "\n"
        "where to listen, what to protect\n"
        "  --listen ADDR:PORT     where to listen; omit the address for every\n"
        "                         interface (default :8080)\n"
        "  --target URL           the backend to protect (required)\n"
        "  --target-sni NAME      TLS name to send to the target; \"auto\" reuses the\n"
        "                         Host header (default: the host we dialled)\n"
        "  --target-host NAME     Host header to send to the target\n"
        "  --target-insecure      do not verify the backend certificate (testing only)\n"
        "  --base-prefix PATH     serve under this path, e.g. /anubis\n"
        "  --strip-base-prefix    strip it again before the target sees the request\n"
        "\n"
        "the challenge\n"
        "  --algorithm NAME       fast, slow, sha256, argon2id, hashx or metarefresh\n"
        "                         (default sha256)\n"
        "  --difficulty N         difficulty; bits for sha256/argon2id/hashx,\n"
        "                         nibbles for fast/slow (default 4)\n"
        "  --challenge-status N   status for the challenge page (default 200)\n"
        "  --deny-status N        status for a policy deny (default 200, as Anubis\n"
        "                         ships it; 403 is what a human would choose)\n"
        "  --serve-robots-txt     answer /robots.txt with a disallow-all file\n"
        "  --debug-benchmark-js   challenge every request, for measuring a client\n"
        "\n"
        "cookies\n"
        "  --cookie-prefix NAME   cookie prefix (default " DEFAULT_COOKIE_PREFIX ")\n"
        "  --cookie-domain DNS    Domain= on the auth cookie\n"
        "  --cookie-expiration-time SECONDS\n"
        "                         Max-Age and JWT exp; 0 makes it a session cookie\n"
        "                         (default 604800)\n"
        "  --cookie-secure[=B]    Secure flag; default is on exactly when we serve TLS\n"
        "  --cookie-http-only[=B] HttpOnly on the auth cookie (default on)\n"
        "  --cookie-same-site S   default, lax, strict or none (default lax; none falls\n"
        "                         back to lax without Secure, like Anubis)\n"
        "  --cookie-partitioned[=B]\n"
        "                         CHIPS Partitioned, only emitted with Secure (default on)\n"
        "\n"
        "who the client is\n"
        "  --custom-real-ip-header NAME\n"
        "                         read the client address from this header, e.g.\n"
        "                         CF-Connecting-IP (Anubis: --custom-real-ip-header)\n"
        "  --use-remote-address   ignore X-Forwarded-For and the custom header\n"
        "  --no-xff-strip-private keep RFC1918 hops from X-Forwarded-For\n"
        "\n"
        "where a solved client may be sent\n"
        "  --redirect-domains LIST\n"
        "                         comma list of hosts the post-challenge redirect may\n"
        "                         use, glob supported (*.example.org), four stars max.\n"
        "                         Default: this host only, which is stricter than\n"
        "                         Anubis, whose default is any domain at all\n"
        "\n"
        "policy, honeypot, assets\n"
        "  --policy FILE          rule file: Anubis's botPolicies.yaml, or this\n"
        "                         gate's own allow/deny/challenge lines (see README)\n"
        "  --data-dir DIR         where (data)/... imports resolve for an Anubis\n"
        "                         policy (default data)\n"
        "  --no-honeypot          disable the trap link and the tarpit\n"
        "  --honeypot-log FILE    append one line per trap hit\n"
        "  --stateless            do not keep issued challenges (they can be replayed)\n"
        "  --web DIR              serve the wasm kernels from here\n"
        "\n"
        "TLS, metrics, noise\n"
        "  --tls-cert FILE        serve HTTPS with this PEM certificate chain\n"
        "  --tls-key FILE         ...and this PEM private key\n"
        "  --secret-file PATH     keep the signing key here, creating it 0600 if it\n"
        "                         is missing; without this the key is random per run\n"
        "                         and every restart logs everyone out\n"
        "  --secret-hex HEX       the same key, given inline (64 hex characters)\n"
        "  --jwt-restriction-header NAME\n"
        "                         bind the auth cookie to the client address, the way\n"
        "                         Anubis does by default; pass \"\" to turn it off\n"
        "  --metrics-bind ADDR:PORT\n"
        "                         Prometheus /metrics and /healthz on a listener of\n"
        "                         their own (default: off. Anubis binds :9090 for\n"
        "                         you, which hands your traffic numbers to anyone)\n"
        "  -v, --verbose          log every request\n"
        "  -h, --help             this text\n"
        "  -V, --version          version\n"
        "\n"
        "send SIGHUP to print the current settings.\n");
}

/* The option table. Values are parsed once, so --flag=value and --flag value both
 * work, and every boolean can be inverted with --no-<flag> or set with
 * --flag=false. --stateless is the inverse of a field, so it gets its own slot. */
static int stateless_arg = -1;

typedef enum { ARG_STR, ARG_INT, ARG_LONG, ARG_BOOL } arg_kind;

typedef struct {
    const char *name;
    arg_kind kind;
    void *dst;
} arg_spec;

static const arg_spec args[] = {
    {"listen", ARG_STR, &cfg.listen},
    {"target", ARG_STR, &cfg.target},
    {"algorithm", ARG_STR, &cfg.algorithm},
    {"difficulty", ARG_INT, &cfg.difficulty},
    {"challenge-status", ARG_INT, &cfg.challenge_status},
    {"deny-status", ARG_INT, &cfg.deny_status},
    {"cookie-prefix", ARG_STR, &cfg.cookie_prefix},
    {"cookie-domain", ARG_STR, &cfg.cookie_domain},
    {"cookie-expiration-time", ARG_LONG, &cfg.cookie_ttl},
    {"cookie-secure", ARG_BOOL, &cfg.cookie_secure},
    {"cookie-http-only", ARG_BOOL, &cfg.cookie_http_only},
    {"cookie-same-site", ARG_STR, &cfg.cookie_same_site},
    {"cookie-partitioned", ARG_BOOL, &cfg.cookie_partitioned},
    {"base-prefix", ARG_STR, &cfg.base_prefix},
    {"strip-base-prefix", ARG_BOOL, &cfg.strip_base_prefix},
    {"custom-real-ip-header", ARG_STR, &cfg.real_ip_header},
    {"use-remote-address", ARG_BOOL, &cfg.use_remote_address},
    {"xff-strip-private", ARG_BOOL, &cfg.xff_strip_private},
    {"redirect-domains", ARG_STR, &cfg.redirect_domains},
    {"serve-robots-txt", ARG_BOOL, &cfg.serve_robots_txt},
    {"debug-benchmark-js", ARG_BOOL, &cfg.debug_benchmark_js},
    {"target-sni", ARG_STR, &cfg.target_sni},
    {"target-host", ARG_STR, &cfg.target_host_hdr},
    {"target-insecure", ARG_BOOL, &cfg.target_insecure},
    {"honeypot", ARG_BOOL, &cfg.honeypot},
    {"honeypot-log", ARG_STR, &cfg.honeypot_log},
    {"stateless", ARG_BOOL, &stateless_arg},
    {"web", ARG_STR, &cfg.web_dir},
    {"policy", ARG_STR, &cfg.policy_file},
    {"tls-cert", ARG_STR, &cfg.tls_cert},
    {"tls-key", ARG_STR, &cfg.tls_key},
    {"metrics-bind", ARG_STR, &cfg.metrics_bind},
    {"jwt-restriction-header", ARG_STR, &cfg.jwt_restrict_hdr},
    {"secret-hex", ARG_STR, &cfg.secret_hex},
    {"secret-file", ARG_STR, &cfg.secret_file},
    {"data-dir", ARG_STR, &cfg.data_dir},
};

static int parse_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout); exit(0); }
        if (!strcmp(a, "-V") || !strcmp(a, "--version")) { puts(VERSION); exit(0); }
        if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) { cfg.verbose = 1; continue; }
        if (strncmp(a, "--", 2) != 0) {
            fprintf(stderr, "betterAnusbis: unknown option %s (try --help)\n", a);
            return -1;
        }

        char name[64];
        const char *inline_val = NULL;
        const char *eq = strchr(a + 2, '=');
        size_t nlen = eq ? (size_t)(eq - (a + 2)) : strlen(a + 2);
        if (nlen >= sizeof name) nlen = sizeof name - 1;
        memcpy(name, a + 2, nlen);
        name[nlen] = 0;
        if (eq) inline_val = eq + 1;

        int negated = 0;
        if (!strncmp(name, "no-", 3)) {
            negated = 1;
            memmove(name, name + 3, strlen(name + 3) + 1);
        }

        const arg_spec *spec = NULL;
        for (size_t k = 0; k < sizeof args / sizeof args[0]; k++)
            if (!strcmp(args[k].name, name)) { spec = &args[k]; break; }
        if (!spec) {
            fprintf(stderr, "betterAnusbis: unknown option %s (try --help)\n", a);
            return -1;
        }
        if (negated && spec->kind != ARG_BOOL) {
            fprintf(stderr, "betterAnusbis: --no-%s makes no sense, it wants a value\n", name);
            return -1;
        }

        const char *val = inline_val;
        if (!val && spec->kind != ARG_BOOL) {
            if (i + 1 >= argc) {
                fprintf(stderr, "betterAnusbis: --%s wants a value\n", name);
                return -1;
            }
            val = argv[++i];
        }
        switch (spec->kind) {
        case ARG_STR:
            *(const char **)spec->dst = val;
            break;
        case ARG_INT:
            *(int *)spec->dst = atoi(val);
            break;
        case ARG_LONG:
            *(long *)spec->dst = strtol(val, NULL, 10);
            break;
        case ARG_BOOL: {
            int b = 1;
            if (val) {
                if (!strcasecmp(val, "false") || !strcmp(val, "0") ||
                    !strcasecmp(val, "no") || !strcasecmp(val, "off")) b = 0;
                else if (!strcasecmp(val, "true") || !strcmp(val, "1") ||
                         !strcasecmp(val, "yes") || !strcasecmp(val, "on")) b = 1;
                else {
                    fprintf(stderr, "betterAnusbis: --%s wants true or false, got %s\n", name, val);
                    return -1;
                }
            }
            if (negated) b = !b;
            *(int *)spec->dst = b;
            break;
        }
        }
    }
    if (stateless_arg >= 0) cfg.stateful = !stateless_arg;
    return 0;
}

/* The signing key. A fresh random key per process is the one thing an operator
 * notices immediately: every restart logs every client out. So a key can be
 * given on the command line, or read from a file that is created on first start. */
static int load_secret(const char *path, uint8_t out[32]) {
    char buf[128];
    FILE *f = fopen(path, "r");
    if (f) {
        size_t n = fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
        buf[n] = 0;
        while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' '))
            buf[--n] = 0;
        if (hex_decode(buf, out, 32) != 32) {
            fprintf(stderr, "betterAnusbis: %s does not hold 32 bytes of hex. Refusing to "
                            "replace a key that may already be in use\n", path);
            return -1;
        }
        return 0;
    }
    if (errno != ENOENT) {
        fprintf(stderr, "betterAnusbis: cannot read %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (random_bytes(out, 32) != 0) {
        fprintf(stderr, "betterAnusbis: cannot read /dev/urandom\n");
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        fprintf(stderr, "betterAnusbis: cannot create %s: %s\n", path, strerror(errno));
        return -1;
    }
    char hex[65];
    hex_encode(out, 32, hex);
    ssize_t w = write(fd, hex, 64);
    close(fd);
    if (w != 64) {
        fprintf(stderr, "betterAnusbis: short write to %s\n", path);
        return -1;
    }
    logmsg("wrote a new signing key to %s (0600); keep that file, or every restart "
           "logs everyone out", path);
    return 0;
}

static volatile sig_atomic_t hup_pending;

static void on_reload(int sig) {
    (void)sig;
    hup_pending = 1;
}

/* What SIGHUP prints: the settings as they actually ended up, after defaults and
 * validation, not as they were typed. */
static void print_settings(void) {
    logmsg("settings: listen=%s target=%s algorithm=%s difficulty=%d",
           cfg.listen, cfg.target, cfg.algorithm, cfg.difficulty);
    logmsg("settings: cookie name=%s domain=%s secure=%s http_only=%s same_site=%s "
           "partitioned=%s ttl=%ld",
           cfg.cookie_name, *cfg.cookie_domain ? cfg.cookie_domain : "(host only)",
           cookie_use_secure() ? "yes" : "no", cfg.cookie_http_only ? "yes" : "no",
           cfg.cookie_same_site, cfg.cookie_partitioned ? "yes" : "no", cfg.cookie_ttl);
    logmsg("settings: base_prefix=%s strip_base_prefix=%s redirect_domains=%s",
           *cfg.base_prefix ? cfg.base_prefix : "/", cfg.strip_base_prefix ? "yes" : "no",
           cfg.redirect_domains ? cfg.redirect_domains : "(this host only)");
    logmsg("settings: real_ip_header=%s use_remote_address=%s xff_strip_private=%s",
           cfg.real_ip_header ? cfg.real_ip_header : "(none)",
           cfg.use_remote_address ? "yes" : "no", cfg.xff_strip_private ? "yes" : "no");
    logmsg("settings: statuses challenge=%d deny=%d robots_txt=%s benchmark_js=%s",
           cfg.challenge_status, cfg.deny_status, cfg.serve_robots_txt ? "yes" : "no",
           cfg.debug_benchmark_js ? "yes" : "no");
    logmsg("settings: signing key=%s", cfg.secret_hex && *cfg.secret_hex ? "--secret-hex"
           : cfg.secret_file && *cfg.secret_file ? cfg.secret_file : "(random per process)");
    logmsg("settings: honeypot=%s threshold=%d log=%s stateful=%s policy=%s web=%s tls=%s",
           cfg.honeypot ? "yes" : "no", cfg.flag_threshold,
           cfg.honeypot_log ? cfg.honeypot_log : "(none)", cfg.stateful ? "yes" : "no",
           cfg.policy_file ? cfg.policy_file : "(none)",
           cfg.web_dir ? cfg.web_dir : "web", cfg.tls_cert ? "yes" : "no");
    logmsg("settings: issued=%lld accepted=%lld replayed=%lld expired=%lld "
           "trap_hits=%lld networks_flagged=%lld",
           ch_issued, ch_accepted, ch_replayed, ch_expired, hp_hits_total,
           hp_networks_flagged);
}

int main(int argc, char **argv) {
    if (parse_args(argc, argv) != 0) return 2;
    if (!cfg.target) {
        fprintf(stderr, "betterAnusbis: --target is required. Try --help.\n");
        return 2;
    }
    if (cfg.difficulty < 0 || cfg.difficulty > 64) {
        fprintf(stderr, "betterAnusbis: --difficulty must be 0..64\n");
        return 2;
    }
    int ok = algorithm_known(cfg.algorithm);
    if (!ok) {
        fprintf(stderr, "betterAnusbis: unknown algorithm %s\n  known:", cfg.algorithm);
        for (int i = 0; known_algorithms[i]; i++) fprintf(stderr, " %s", known_algorithms[i]);
        fputc('\n', stderr);
        return 2;
    }

    if (cfg.challenge_status < 100 || cfg.challenge_status > 599) {
        fprintf(stderr, "betterAnusbis: --challenge-status must be 100..599\n");
        return 2;
    }
    if (cfg.deny_status < 100 || cfg.deny_status > 599) {
        fprintf(stderr, "betterAnusbis: --deny-status must be 100..599\n");
        return 2;
    }
    static const char *samesite_ok[] = {"default", "lax", "strict", "none", NULL};
    ok = 0;
    for (int i = 0; samesite_ok[i]; i++)
        if (!strcasecmp(cfg.cookie_same_site, samesite_ok[i])) ok = 1;
    if (!ok) {
        fprintf(stderr, "betterAnusbis: --cookie-same-site must be default, lax, strict or none\n");
        return 2;
    }
    if (cfg.cookie_ttl < 0) cfg.cookie_ttl = 0;      /* 0: a session cookie */
    /* the base prefix has to look like a path, and must not end in a slash */
    if (cfg.base_prefix && *cfg.base_prefix) {
        static char prefix_buf[256];
        if (cfg.base_prefix[0] != '/') {
            fprintf(stderr, "betterAnusbis: --base-prefix must start with /\n");
            return 2;
        }
        snprintf(prefix_buf, sizeof prefix_buf, "%s", cfg.base_prefix);
        size_t pn = strlen(prefix_buf);
        while (pn > 1 && prefix_buf[pn - 1] == '/') prefix_buf[--pn] = 0;
        if (!strcmp(prefix_buf, "/")) prefix_buf[0] = 0;   /* "/" is the root */
        cfg.base_prefix = prefix_buf;
    }
    /* A pattern with more than four stars is one nobody meant to write; say so
     * rather than let it silently never match. */
    if (cfg.redirect_domains && *cfg.redirect_domains) {
        char copy[1024];
        snprintf(copy, sizeof copy, "%s", cfg.redirect_domains);
        int patterns = 0;
        for (char *q = copy; q && *q; ) {
            char *comma = strchr(q, ',');
            if (comma) *comma = 0;
            while (*q == ' ' || *q == '\t') q++;
            int stars = 0;
            for (const char *r = q; *r; r++) if (*r == '*') stars++;
            if (*q) {
                patterns++;
                if (stars > MAX_GLOB_STARS)
                    logmsg("--redirect-domains: %s has %d stars, the limit is %d; "
                           "that pattern will never match", q, stars, MAX_GLOB_STARS);
            }
            q = comma ? comma + 1 : NULL;
        }
        if (patterns > MAX_REDIRECT_PATTERNS)
            logmsg("--redirect-domains: %d patterns, only the first %d are read",
                   patterns, MAX_REDIRECT_PATTERNS);
    }

    if (cfg.policy_file) policy_load(cfg.policy_file);
    parse_target(cfg.target);
    snprintf(cfg.cookie_name, sizeof cfg.cookie_name, "%s-auth", cfg.cookie_prefix);
    if (cfg.secret_hex && *cfg.secret_hex) {
        if (hex_decode(cfg.secret_hex, cfg.secret, sizeof cfg.secret) != (int)sizeof cfg.secret) {
            fprintf(stderr, "betterAnusbis: --secret-hex wants exactly 64 hex characters\n");
            return 2;
        }
    } else if (cfg.secret_file && *cfg.secret_file) {
        if (load_secret(cfg.secret_file, cfg.secret) != 0) return 1;
    } else if (random_bytes(cfg.secret, sizeof cfg.secret) != 0) {
        fprintf(stderr, "betterAnusbis: cannot read /dev/urandom\n");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    /* no SA_RESTART: accept() has to come back so the dump can happen */
    struct sigaction hup = {0};
    hup.sa_handler = on_reload;
    sigemptyset(&hup.sa_mask);
    sigaction(SIGHUP, &hup, NULL);

    struct sockaddr_in6 addr;
    if (parse_listen(cfg.listen, &addr) != 0) {
        fprintf(stderr, "betterAnusbis: --listen wants ADDR:PORT\n");
        return 2;
    }
    if ((cfg.tls_cert && !cfg.tls_key) || (!cfg.tls_cert && cfg.tls_key)) {
        fprintf(stderr, "betterAnusbis: --tls-cert and --tls-key go together\n");
        return 2;
    }
    int use_tls = cfg.tls_cert != NULL;
    if (use_tls) {
        OPENSSL_init_ssl(0, NULL);
        server_ctx = SSL_CTX_new(TLS_server_method());
        if (!server_ctx) { fprintf(stderr, "betterAnusbis: SSL_CTX_new failed\n"); return 1; }
        SSL_CTX_set_min_proto_version(server_ctx, TLS1_2_VERSION);
        if (SSL_CTX_use_certificate_chain_file(server_ctx, cfg.tls_cert) != 1) {
            fprintf(stderr, "betterAnusbis: cannot load the certificate %s\n", cfg.tls_cert);
            ERR_print_errors_fp(stderr);
            return 1;
        }
        if (SSL_CTX_use_PrivateKey_file(server_ctx, cfg.tls_key, SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "betterAnusbis: cannot load the key %s\n", cfg.tls_key);
            ERR_print_errors_fp(stderr);
            return 1;
        }
        if (SSL_CTX_check_private_key(server_ctx) != 1) {
            fprintf(stderr, "betterAnusbis: certificate and key do not match\n");
            return 1;
        }
    }

    int srv = socket(AF_INET6, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(srv, IPPROTO_IPV6, IPV6_V6ONLY, &(int){0}, sizeof(int));
    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) != 0) { perror("bind"); return 1; }
    if (listen(srv, 128) != 0) { perror("listen"); return 1; }

    logmsg("betterAnusbis " VERSION " listening on %s (%s) -> %s (%s, difficulty %d)",
           cfg.listen, use_tls ? "https" : "http", cfg.target, cfg.algorithm, cfg.difficulty);
    logmsg("open %s://127.0.0.1:%d/ and the challenge page solves it for you",
           use_tls ? "https" : "http", ntohs(addr.sin6_port));

    if (cfg.metrics_bind && *cfg.metrics_bind) {
        struct sockaddr_in6 maddr;
        if (parse_listen(cfg.metrics_bind, &maddr) != 0) {
            fprintf(stderr, "betterAnusbis: --metrics-bind wants ADDR:PORT\n");
            return 2;
        }
        int mfd = socket(AF_INET6, SOCK_STREAM, 0);
        if (mfd < 0) { perror("socket"); return 1; }
        setsockopt(mfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        setsockopt(mfd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){0}, sizeof(int));
        if (bind(mfd, (struct sockaddr *)&maddr, sizeof maddr) != 0) {
            fprintf(stderr, "betterAnusbis: cannot bind metrics to %s: %s\n",
                    cfg.metrics_bind, strerror(errno));
            return 1;
        }
        if (listen(mfd, 64) != 0) { perror("listen"); return 1; }
        int *mp = malloc(sizeof *mp);
        if (!mp) return 1;
        *mp = mfd;
        pthread_t mt;
        if (pthread_create(&mt, NULL, metrics_thread, mp) != 0) {
            fprintf(stderr, "betterAnusbis: cannot start the metrics thread\n");
            return 1;
        }
        pthread_detach(mt);
        logmsg("metrics on %s (GET /metrics, GET /healthz)", cfg.metrics_bind);
    }

    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) {
                if (hup_pending) {
                    hup_pending = 0;
                    print_settings();
                }
                continue;
            }
            perror("accept");
            break;
        }
        accepted *a = malloc(sizeof *a);
        if (!a) { close(fd); continue; }
        a->fd = fd;
        a->tls = use_tls;
        pthread_t t;
        if (pthread_create(&t, NULL, thread_main, a) == 0) {
            pthread_detach(t);
        } else {
            free(a);
            close(fd);
        }
    }
    close(srv);
    return 0;
}
