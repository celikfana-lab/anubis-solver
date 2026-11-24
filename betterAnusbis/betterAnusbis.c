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
 * HTTP/2 (nghttp2) and HTTP/3 (OpenSSL QUIC + nghttp3) are optional at build
 * time, on the listener and on the backend hop. A request in any of them is
 * decoded into the same `request` struct and answered through the same
 * handle_parsed(), so the gate did not grow a second implementation.
 *
 * Build:  make            (or: cc -O2 -pthread -o betterAnusbis betterAnusbis.c -L.. -lanubis_solver)
 */
#define _GNU_SOURCE
#if defined(_WIN32)
/* winsock, winpthreads and the POSIX names Win32 does not have. Included
 * first so the shims are visible to everything below; see win32-compat.h. */
#include "win32-compat.h"
#include <bcrypt.h>
/* PCRE2 ships a POSIX regcomp()/regexec() wrapper, so the policy code below
 * is the same on every platform. The gate only asks "does it match". */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2posix.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
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
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <ctype.h>
#include <regex.h>
#endif
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#ifdef HAVE_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif
#ifdef HAVE_NGHTTP3
#include <nghttp3/nghttp3.h>
#include <openssl/quic.h>
#endif

#include "anubis-solver.h"

/* ----------------------------------------------------------------- config */

#define VERSION "2.50"
#define CODENAME "mule"
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
    const char *meatrider_usd;   /* --meatrider-usd: a price, not a difficulty */
    int meatrider_ladder;        /* --meatrider-ladder: print and exit */
    int meatrider_escalate;      /* --meatrider-escalate: suspicion buys a rung */
    const char *meatrider_pay;   /* --meatrider-pay: a bitcoin address to pay */
    const char *meatrider_btc_usd; /* --meatrider-btc-usd: USD per BTC */
    const char *meatrider_receipt; /* --meatrider-receipt: mint one for this id */
    double btc_usd;              /* derived: 100000 when not given */
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
    int healthcheck;             /* GET /healthz on the metrics listener and exit */
    const char *bind_network;    /* tcp or unix, for the listener */
    const char *socket_mode;     /* unix socket permissions, octal */
    const char *metrics_network; /* tcp or unix, for the metrics listener */
    const char *log_level;       /* DEBUG, INFO, WARN or ERROR */
    int difficulty_in_jwt;       /* add the difficulty claim to the token */
    int dynamic_cookie_suffix;   /* hash the cookie settings into its name */
    const char *webmaster_email; /* shown on a deny page */
    int preserve_referer_qp;     /* utm_source/utm_medium from the Referer */
    int target_disable_keepalive;/* accepted; this gate always closes */
    const char *hs512_secret;    /* sign with HS512 and this key */
    const char *ed25519_hex;     /* sign with EdDSA and this seed */
    const char *ed25519_file;    /* ...read from this file */
    const char *forced_language; /* override Accept-Language */
    const char *impressum_footer;/* HTML shown on every page */
    const char *impressum_title; /* the imprint page's title */
    const char *impressum_body;  /* the imprint page's body */
    const char *public_url;      /* where this gate is reachable, for forwardAuth */
    int dnsbl;                   /* ask DroneBL about the client */
    const char *geoip_lookup;     /* diagnostic: print what the databases say */
    int ext_css_load;             /* require the css-load extension */
    int og_passthrough;           /* copy the protected page's og: tags */
    long og_ttl;                  /* how long a page's tags are cached */
    int og_consider_host;         /* include the Host in the cache key */
    long dns_ttl;                 /* how long a DroneBL answer is kept */
    const char *og_override;      /* key=value;... replaces the tags entirely */
    const char *challenge_extension; /* "css-load", and only for now */
    const char *store;            /* file:PATH keeps the ledger across restarts */
    const char *geoip_country_path;
    const char *geoip_asn_path;
    int subrequest;              /* no target: answer auth checks only */
    int jwt_alg;                 /* 0 HS256, 1 HS512, 2 EdDSA */
    EVP_PKEY *jwt_pkey;
    char verify_name[256];       /* the -cookie-verification name, suffix and all */
    /* HTTP/2 and HTTP/3. The listener and the target hop each get their own
     * switch: an environment that terminates h3 at the edge and speaks h1 to a
     * legacy backend is the normal one, and so is the reverse. */
    int http2;                   /* ALPN h2 and h2c prior knowledge (default on) */
    int http3;                   /* QUIC listener on the same port (needs TLS) */
    int target_http2;            /* use h2 to the backend when ALPN offers it */
    int target_http3;            /* use h3/QUIC to the backend */
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
    .healthcheck = 0,
    .og_passthrough = 0,
    .og_ttl = 86400,
    .og_consider_host = 0,
    .dns_ttl = 86400,
    .og_override = NULL,
    .bind_network = "tcp",
    .socket_mode = "0770",
    .metrics_network = "tcp",
    .log_level = "INFO",
    .difficulty_in_jwt = 0,
    .dynamic_cookie_suffix = 1,  /* upstream's default */
    .webmaster_email = NULL,
    .preserve_referer_qp = 0,
    .http2 = 1,
    .http3 = 0,
    .target_http2 = 1,
    .target_http3 = 0,
};

static int log_quiet;            /* WARN and ERROR: keep the startup lines, drop info */
static void store_mark_dirty(void);   /* defined with the store, used by the ledger */

static void logmsg(const char *fmt, ...) {
    if (log_quiet) return;
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
#if defined(_WIN32)
    /* There is no /dev/urandom on Windows; BCryptGenRandom is the documented
     * system RNG and needs no seeding of our own. */
    while (n > 0) {
        ULONG chunk = n > 0x10000000u ? 0x10000000u : (ULONG)n;
        if (BCryptGenRandom(NULL, out, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            return -1;
        out += chunk;
        n = n > chunk ? n - chunk : 0;
    }
    return 0;
#else
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
#endif
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
static int hmac_sha512(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen,
                       uint8_t out[64]) {
    unsigned int len = 0;
    if (!HMAC(EVP_sha512(), key, (int)keylen, msg, msglen, out, &len) || len != 64) return -1;
    return 0;
}

/* The JWT is signed one of three ways, chosen the way upstream chooses it:
 * --hs512-secret, else an Ed25519 key, else the shared secret this gate manages
 * itself (HS256). The header says which, so a token minted under one scheme
 * does not verify under another. */
static const char *jwt_header_json(void) {
    switch (cfg.jwt_alg) {
    case 1: return "{\"alg\":\"HS512\",\"typ\":\"JWT\"}";
    case 2: return "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}";
    default: return "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    }
}

static const char *policy_digest(void);   /* defined with the policy engine */

static int sign_token(char *out, size_t cap, const char *challenge_id,
                      const char *restrict_to, const char *algorithm, int difficulty) {
    char payload[768];
    time_t now = time(NULL);
    /* policyRule is Anubis's rule hash: a hash of the policy that produced the
     * challenge, compared on every request, so tightening a rule takes effect
     * for clients that already have a cookie. Ours is one digest over the whole
     * loaded policy, which means any edit logs everyone out. That is the blunt
     * direction and it is the one an incident wants.
     * Anubis binds the token to the client by default (--jwt-restriction-header,
     * X-Real-IP); so do we, because a cookie that works from any address is a
     * cookie that works from whoever steals it. */
    char difficulty_part[48] = "";
    if (cfg.difficulty_in_jwt)
        snprintf(difficulty_part, sizeof difficulty_part, ",\"difficulty\":%d", difficulty);
    char restrict_part[128] = "";
    if (restrict_to && *restrict_to && cfg.jwt_restrict_hdr && *cfg.jwt_restrict_hdr)
        snprintf(restrict_part, sizeof restrict_part, ",\"restrict\":\"%s\"", restrict_to);
    snprintf(payload, sizeof payload,
             "{\"challenge\":\"%s\",\"method\":\"%s\",\"policyRule\":\"%s\","
             "\"action\":\"CHALLENGE\",\"iat\":%lld,\"exp\":%lld%s%s}",
             challenge_id ? challenge_id : "issued",
             algorithm && *algorithm ? algorithm : cfg.algorithm,
             policy_digest(),
             (long long)now,
             (long long)(now + (cfg.cookie_ttl > 0 ? cfg.cookie_ttl : COOKIE_TTL)),
             difficulty_part, restrict_part);

    const char *header = jwt_header_json();
    char h64[256], p64[768];
    if (!b64url_encode((const uint8_t *)header, strlen(header), h64, sizeof h64)) return -1;
    if (!b64url_encode((const uint8_t *)payload, strlen(payload), p64, sizeof p64)) return -1;

    char signing[1024];
    snprintf(signing, sizeof signing, "%s.%s", h64, p64);
    uint8_t mac[64];
    size_t mac_len = 32;
    if (cfg.jwt_alg == 2) {
        if (!cfg.jwt_pkey) return -1;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) return -1;
        size_t siglen = sizeof mac;
        int ok = EVP_DigestSignInit(ctx, NULL, NULL, NULL, cfg.jwt_pkey) == 1 &&
                 EVP_DigestSign(ctx, mac, &siglen, (const uint8_t *)signing,
                                strlen(signing)) == 1;
        EVP_MD_CTX_free(ctx);
        if (!ok) return -1;
        mac_len = siglen;
    } else if (cfg.jwt_alg == 1) {
        if (hmac_sha512((const uint8_t *)cfg.hs512_secret, strlen(cfg.hs512_secret),
                        (const uint8_t *)signing, strlen(signing), mac) != 0)
            return -1;
        mac_len = 64;
    } else if (hmac_sha256(cfg.secret, sizeof cfg.secret, (const uint8_t *)signing,
                           strlen(signing), mac) != 0) {
        return -1;
    }
    char m64[128];
    if (!b64url_encode(mac, mac_len, m64, sizeof m64)) return -1;
    snprintf(out, cap, "%s.%s", signing, m64);
    return 0;
}

/* Comparing a MAC with strcmp leaks where the first differing byte is, which is
 * the one comparison in this program that must not do that (upstream uses
 * hmac.Equal for the same reason). */
static int ct_equal(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return 0;
    unsigned char diff = 0;
    for (size_t i = 0; i < la; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
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

    if (cfg.jwt_alg == 2) {
        uint8_t sig[128];
        int n = b64url_decode(dot2 + 1, sig, sizeof sig);
        if (n != 64 || !cfg.jwt_pkey) return 0;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) return 0;
        int ok = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, cfg.jwt_pkey) == 1 &&
                 EVP_DigestVerify(ctx, sig, 64, (const uint8_t *)signing, slen) == 1;
        EVP_MD_CTX_free(ctx);
        if (!ok) return 0;
    } else {
        uint8_t mac[64];
        size_t mac_len = cfg.jwt_alg == 1 ? 64 : 32;
        int rc = cfg.jwt_alg == 1
                     ? hmac_sha512((const uint8_t *)cfg.hs512_secret,
                                   strlen(cfg.hs512_secret), (const uint8_t *)signing,
                                   slen, mac)
                     : hmac_sha256(cfg.secret, sizeof cfg.secret,
                                   (const uint8_t *)signing, slen, mac);
        if (rc != 0) return 0;
        char want[128];
        if (!b64url_encode(mac, mac_len, want, sizeof want)) return 0;
        if (!ct_equal(want, dot2 + 1)) return 0;     /* signature */
    }

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
    char *policy_claim = strstr((char *)raw, "\"policyRule\":\"");
    if (policy_claim) {
        const char *want = policy_claim + strlen("\"policyRule\":\"");
        const char *end = strchr(want, '"');
        if (!end) return 0;
        char had[32];
        size_t hn = (size_t)(end - want);
        if (hn >= sizeof had) return 0;
        memcpy(had, want, hn);
        had[hn] = 0;
        if (!ct_equal(had, policy_digest())) {
            if (cfg.verbose)
                logmsg("rejecting a token minted under policy %s (now %s)", had,
                       policy_digest());
            return 0;
        }
    }

    char *restrict_claim = strstr((char *)raw, "\"restrict\":\"");
    if (restrict_claim && cfg.jwt_restrict_hdr && *cfg.jwt_restrict_hdr) {
        const char *want = restrict_claim + strlen("\"restrict\":\"");
        const char *end = strchr(want, '"');
        if (!end) return 0;
        size_t n = (size_t)(end - want);
        if (!client_ip || strlen(client_ip) != n) return 0;
        {
            char have[128];
            snprintf(have, sizeof have, "%.*s", (int)n, want);
            if (!ct_equal(have, client_ip)) return 0;
        }
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

/* `tensor-v`: the server never recomputes the GEMM. It samples this many
 * blocks of the committed output (and one element inside each); a client that
 * computed a fraction f of the elements passes with probability f^k. 96 is
 * 4e-5 at f=0.9, and costs the gate ~96*N multiply-adds instead of N^3. */
#define TENSOR_V_K 96

/* The sampler's key, separated from the cookie-signing key: the two uses must
 * not share raw key material, even though both are HMAC/SHA-256. */
static void tensor_v_secret(char out[65]) {
    unsigned char k[32];
    unsigned int klen = sizeof k;
    static const unsigned char label[] = "ANUBIS-TENSOR-V-KEY";
    if (!HMAC(EVP_sha256(), cfg.secret, (int)sizeof cfg.secret, label,
              sizeof label - 1, k, &klen) || klen != sizeof k) {
        memset(k, 0, sizeof k);
    }
    hex_encode(k, sizeof k, out);
}

/* A tensor response is a SHA-256 digest and nothing else, so a request that
 * cannot be one is refused before the GEMM runs. This is not a security
 * boundary - a determined client can still make the server compute one GEMM
 * per request - but it keeps a fuzzer or a bored scanner from costing a
 * 130 ms verification each time. */
static int looks_like_digest(const char *s) {
    size_t i;
    if (s == NULL || strlen(s) != 64) return 0;
    for (i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

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
    } else if (!strcasecmp(algorithm, "meatrider")) {
        rc = anubis_verify_meatrider(random_data, (uint32_t)nonce, difficulty, out);
    } else if (!strcasecmp(algorithm, "tensor")) {
        /* No nonce search: the digest is the proof. The nonce is still part
         * of the wire format (Anubis always sends one), and it is always 0. */
        rc = anubis_verify_tensor(random_data, (uint32_t)nonce, difficulty, out);
    } else if (!strcasecmp(algorithm, "metarefresh") || !strcasecmp(algorithm, "preact")) {
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

/* An option string is unset until the flag or its environment variable fills
 * it; every read has to go through this rather than [0] on a NULL pointer. */
#define OPT(s) ((s) != NULL && *(s) != '\0')

/* ------------------------------------------------- meatrider receipts
 *
 * The top of the ladder is priced for hardware, so there has to be a way to
 * buy your way past it. There is no node here: this is the preimage model with
 * an operator-issued receipt. The gate derives one secret per challenge,
 *
 *     receipt(id) = HMAC-SHA256(signing key, "meatrider-receipt:" || id)
 *
 * and only hands it out when the payment has been confirmed by whatever means
 * the operator likes (a lightning invoice, an on-chain tx, a bank transfer).
 * The page submits it as `response` with nonce 0; the gate recomputes it and
 * accepts. It is single-use because the challenge is, it cannot be transferred
 * to another id, and it needs --secret-hex/--secret-file so a restart (or the
 * --meatrider-receipt CLI, which is a second process) derives the same value.
 * This is reconciliation, not verification: the gate never talks to Bitcoin. */

static void mr_receipt(const char *id, char out[65]) {
    unsigned char mac[32];
    unsigned int mlen = sizeof mac;
    char msg[256];

    snprintf(msg, sizeof msg, "meatrider-receipt:%s", id ? id : "");
    if (!HMAC(EVP_sha256(), cfg.secret, (int)sizeof cfg.secret,
              (const unsigned char *)msg, strlen(msg), mac, &mlen) ||
        mlen != sizeof mac) {
        memset(mac, 0, sizeof mac);
    }
    hex_encode(mac, sizeof mac, out);
}

static int mr_receipt_matches(const char *id, const char *response) {
    char want[65];
    unsigned char diff = 0;
    int i;

    if (!OPT(cfg.meatrider_pay) || !id || !response) return 0;
    /* stateless has no ledger, so a receipt could be replayed forever */
    if (!cfg.stateful) return 0;
    if (strlen(response) != 64) return 0;
    mr_receipt(id, want);
    for (i = 0; i < 64; i++) {
        unsigned char c = (unsigned char)response[i];
        if (c >= 'A' && c <= 'F') c = (unsigned char)(c - 'A' + 'a');
        diff |= (unsigned char)(c ^ (unsigned char)want[i]);
    }
    return diff == 0;
}

/* Suspicion wears a price tag: each doubling of the trap count moves the
 * network one wall up the browser ladder — a second, a minute, an hour, three
 * days, an ASIC's second — and every step is also ten times the money. */
static int meatrider_suspicion_bits(int threshold, int hits) {
    static const int wall[] = {20, 26, 32, 38, 48};
    int step = 0;

    if (threshold < 1) threshold = 1;
    while (step < 4 && hits >= (threshold << (step + 1))) step++;
    return wall[step];
}

/* One connection: a socket, and an OpenSSL session when the listener is HTTPS. */
typedef struct {
    int fd;
    void *ssl;                    /* SSL *, or NULL for plain HTTP */
} conn;

static SSL_CTX *server_ctx;       /* the listener's context, once TLS is on */
static int h3_port;               /* the UDP port QUIC is on, 0 when HTTP/3 is off */

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
/* The Valkey client type lives further down with the store code; the ledger
 * hooks above it need the forward declaration and the shared handle. */
typedef struct vk_client vk_client;
typedef struct s3_client s3_client;
static int store_valkey;
static int store_s3;
static int s3_path_style;
static vk_client *vk;
static s3_client *s3;

#define CH_BUCKETS 4096
typedef struct {
    char id[80];
    char rd[65];
    char algorithm[24];
    char referer[256];
    long long issued_ms;
    int css_seen;
    int difficulty;
    time_t issued;
    int spent;
    int used;
} ch_entry;

/* defined with the remote stores below; the ledger calls them in place */
static int remote_available(void);
static int remote_get_challenge(const char *id, ch_entry *out);
static void remote_put_challenge(const ch_entry *e, long long ttl);
static void ch_cache_put(const ch_entry *src);
static int remote_get_honeypot(uint64_t key, int *count, time_t *last);
static void remote_put_honeypot(uint64_t key, int count, time_t last);
static void hp_cache_put(uint64_t key, int count, time_t last);
static int vk_miss_seen(uint64_t key);
static void vk_miss_mark(uint64_t key);
static int s3_available(void);
static int s3_get_challenge(const char *id, ch_entry *out);
static void s3_put_challenge(const ch_entry *e, long long ttl);
static int s3_get_honeypot(uint64_t key, int *count, time_t *last);
static void s3_put_honeypot(uint64_t key, int count, time_t last);
static int s3_store_start(const char *bucket);

static ch_entry ch_table[CH_BUCKETS];
static pthread_mutex_t ch_lock = PTHREAD_MUTEX_INITIALIZER;
static long long ch_issued, ch_accepted, ch_replayed, ch_expired;

static void ch_issue(const char *id, const char *rd, int difficulty, const char *algorithm,
                     const char *referer) {
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
            snprintf(e->referer, sizeof e->referer, "%s", referer ? referer : "");
            e->difficulty = difficulty;
            e->issued = now;
            {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                e->issued_ms = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
            }
            e->spent = 0;
            e->used = 1;
            store_mark_dirty();
            ch_issued++;
            ch_entry snap = *e;
            pthread_mutex_unlock(&ch_lock);
            if (store_valkey || store_s3) remote_put_challenge(&snap, COOKIE_TTL);
            return;
        }
        if (!strcmp(e->id, id)) {          /* re-issued: refresh it */
            snprintf(e->rd, sizeof e->rd, "%s", rd);
            snprintf(e->algorithm, sizeof e->algorithm, "%s", algorithm);
            snprintf(e->referer, sizeof e->referer, "%s", referer ? referer : "");
            e->difficulty = difficulty;
            e->issued = now;
            {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                e->issued_ms = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
            }
            e->spent = 0;
            ch_entry snap = *e;
            pthread_mutex_unlock(&ch_lock);
            if (store_valkey || store_s3) remote_put_challenge(&snap, COOKIE_TTL);
            return;
        }
    }
    pthread_mutex_unlock(&ch_lock);        /* table full: the stateless path covers us */
}

/* 1 accepted (and retired), 0 unknown, -1 expired, -2 already spent */
static int ch_take(const char *id, char *rd_out, size_t rd_cap, int *difficulty_out,
                   char *algo_out, size_t algo_cap) {
    time_t now = time(NULL);
    if (store_valkey || store_s3) {
        ch_entry remote;
        int got = remote_get_challenge(id, &remote);
        if (got == 1) {
            if (now - remote.issued > COOKIE_TTL) { ch_expired++; return -1; }
            if (remote.spent) { ch_replayed++; return -2; }
            remote.spent = 1;
            long long ttl = (long long)COOKIE_TTL - (long long)(now - remote.issued);
            if (ttl > 0) remote_put_challenge(&remote, ttl);
            ch_cache_put(&remote);
            snprintf(rd_out, rd_cap, "%s", remote.rd);
            if (difficulty_out) *difficulty_out = remote.difficulty;
            if (algo_out) snprintf(algo_out, algo_cap, "%s", remote.algorithm);
            ch_accepted++;
            return 1;
        }
        /* got == 0: a challenge issued before this store was configured, or a
         * remote error; the local table is still worth checking. */
    }
    uint32_t h = 2166136261u;
    for (const char *q = id; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
    int rc = 0;
    ch_entry snap;
    memset(&snap, 0, sizeof snap);
    pthread_mutex_lock(&ch_lock);
    for (int probe = 0; probe < 32; probe++) {
        ch_entry *e = &ch_table[(h + (uint32_t)probe) % CH_BUCKETS];
        if (!e->used) break;
        if (strcmp(e->id, id) != 0) continue;
        if (now - e->issued > COOKIE_TTL) { rc = -1; ch_expired++; break; }
        if (e->spent) { rc = -2; ch_replayed++; break; }
        e->spent = 1;
        store_mark_dirty();
        snprintf(rd_out, rd_cap, "%s", e->rd);
        if (difficulty_out) *difficulty_out = e->difficulty;
        if (algo_out) snprintf(algo_out, algo_cap, "%s", e->algorithm);
        snap = *e;
        ch_accepted++;
        rc = 1;
        break;
    }
    pthread_mutex_unlock(&ch_lock);
    if (rc == 1 && (store_valkey || store_s3)) {
        long long ttl = (long long)COOKIE_TTL - (long long)(now - snap.issued);
        if (ttl > 0) remote_put_challenge(&snap, ttl);
    }
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
    if (!found && (store_valkey || store_s3)) {
        ch_entry remote;
        if (remote_get_challenge(id, &remote) == 1) {
            ch_cache_put(&remote);
            snprintf(out, cap, "%s", remote.algorithm);
            found = 1;
        }
    }
    return found;
}

/* Same, for the fields tensor-v needs before it spends the challenge: the
 * random data and difficulty a step-1 sample has to be derived from. */
static int ch_peek_entry(const char *id, ch_entry *out) {
    if (!cfg.stateful || !id || !out) return 0;
    uint32_t h = 2166136261u;
    for (const char *q = id; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
    int found = 0;
    pthread_mutex_lock(&ch_lock);
    for (int probe = 0; probe < 32; probe++) {
        ch_entry *e = &ch_table[(h + (uint32_t)probe) % CH_BUCKETS];
        if (!e->used) break;
        if (strcmp(e->id, id) != 0) continue;
        *out = *e;
        found = 1;
        break;
    }
    pthread_mutex_unlock(&ch_lock);
    if (!found && (store_valkey || store_s3)) {
        ch_entry remote;
        if (remote_get_challenge(id, &remote) == 1) {
            ch_cache_put(&remote);
            *out = remote;
            found = 1;
        }
    }
    return found;
}

/* The css-load extension: the challenge page carries a stylesheet link, a
 * browser fetches it without being asked, and the pass-challenge request is
 * only accepted if that fetch happened (lib/challenge/extension/css-load). */
static int ch_mark_css(const char *id) {
    if (!cfg.stateful || !id) return 0;
    if (store_valkey || store_s3) {
        ch_entry remote;
        if (remote_get_challenge(id, &remote) == 1) {
            remote.css_seen = 1;
            long long ttl = (long long)COOKIE_TTL -
                            ((long long)time(NULL) - (long long)remote.issued);
            if (ttl > 0) remote_put_challenge(&remote, ttl);
            ch_cache_put(&remote);
            return 1;
        }
    }
    uint32_t h = 2166136261u;
    for (const char *q = id; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
    int found = 0;
    pthread_mutex_lock(&ch_lock);
    for (int probe = 0; probe < 32; probe++) {
        ch_entry *e = &ch_table[(h + (uint32_t)probe) % CH_BUCKETS];
        if (!e->used) break;
        if (strcmp(e->id, id) != 0) continue;
        e->css_seen = 1;
        store_mark_dirty();
        found = 1;
        break;
    }
    pthread_mutex_unlock(&ch_lock);
    return found;
}

/* 1 seen, 0 the challenge exists but the stylesheet was never fetched,
 * -1 no such challenge (or no ledger). */
static int ch_css_seen(const char *id) {
    if (!id || !cfg.stateful) return -1;
    uint32_t h = 2166136261u;
    for (const char *q = id; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
    int seen = -1;
    pthread_mutex_lock(&ch_lock);
    for (int probe = 0; probe < 32; probe++) {
        ch_entry *e = &ch_table[(h + (uint32_t)probe) % CH_BUCKETS];
        if (!e->used) break;
        if (strcmp(e->id, id) != 0) continue;
        seen = e->css_seen ? 1 : 0;
        break;
    }
    pthread_mutex_unlock(&ch_lock);
    if (seen < 0 && (store_valkey || store_s3)) {
        ch_entry remote;
        if (remote_get_challenge(id, &remote) == 1) {
            ch_cache_put(&remote);
            seen = remote.css_seen ? 1 : 0;
        }
    }
    return seen;
}

/* When it was issued, in milliseconds, so a preact wait of a few hundred is not
 * rounded to a whole second. */
static int ch_peek_issued_ms(const char *id, long long *out) {
    if (!cfg.stateful || !id) return 0;
    uint32_t h = 2166136261u;
    for (const char *q = id; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
    int found = 0;
    pthread_mutex_lock(&ch_lock);
    for (int probe = 0; probe < 32; probe++) {
        ch_entry *e = &ch_table[(h + (uint32_t)probe) % CH_BUCKETS];
        if (!e->used) break;
        if (strcmp(e->id, id) != 0) continue;
        *out = e->issued_ms;
        found = 1;
        break;
    }
    pthread_mutex_unlock(&ch_lock);
    if (!found && (store_valkey || store_s3)) {
        ch_entry remote;
        if (remote_get_challenge(id, &remote) == 1) {
            ch_cache_put(&remote);
            *out = remote.issued_ms;
            found = 1;
        }
    }
    return found;
}

/* The Referer recorded when the challenge was issued, which is what the
 * attribution query is derived from (lib/anubis.go:812-853). */
static int ch_peek_referer(const char *id, char *out, size_t cap) {
    if (!cfg.stateful || !id) return 0;
    uint32_t h = 2166136261u;
    for (const char *q = id; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
    int found = 0;
    pthread_mutex_lock(&ch_lock);
    for (int probe = 0; probe < 32; probe++) {
        ch_entry *e = &ch_table[(h + (uint32_t)probe) % CH_BUCKETS];
        if (!e->used) break;
        if (strcmp(e->id, id) != 0) continue;
        snprintf(out, cap, "%s", e->referer);
        found = 1;
        break;
    }
    pthread_mutex_unlock(&ch_lock);
    if (!found && (store_valkey || store_s3)) {
        ch_entry remote;
        if (remote_get_challenge(id, &remote) == 1) {
            ch_cache_put(&remote);
            snprintf(out, cap, "%s", remote.referer);
            found = 1;
        }
    }
    return found;
}

/* utm_source/utm_medium for analytics that cannot read document.referrer,
 * because the browser's history is the challenge page. Only for an external
 * referer, and only when the redirect carries no attribution of its own. */
static void with_referer_attribution(const char *redir, const char *referer,
                                     const char *host, char *out, size_t cap) {
    static const char *const already[] = {
        "ref", "source", "utm_source", "utm_medium", "utm_campaign", "utm_content",
        "utm_term", "gclid", "msclkid", NULL
    };
    if (!cfg.preserve_referer_qp || !referer || !*referer) {
        snprintf(out, cap, "%s", redir);
        return;
    }
    const char *h = strstr(referer, "://");
    h = h ? h + 3 : referer;
    size_t hn = strcspn(h, "/?#");
    if (!hn || (host && hn == strlen(host) && !strncasecmp(h, host, hn))) {
        snprintf(out, cap, "%s", redir);
        return;
    }
    char refhost[128];
    if (hn >= sizeof refhost) hn = sizeof refhost - 1;
    memcpy(refhost, h, hn);
    refhost[hn] = 0;
    for (int i = 0; already[i]; i++) {
        char probe[64];
        snprintf(probe, sizeof probe, "%s=", already[i]);
        if (strstr(redir, probe)) {
            snprintf(out, cap, "%s", redir);
            return;
        }
    }
    const char *sep = strchr(redir, '?') ? "&" : "?";
    snprintf(out, cap, "%s%sutm_source=%s&utm_medium=referral", redir, sep, refhost);
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
    int hcount = 0;
    time_t hlast = 0;
    pthread_mutex_lock(&hp_lock);
    uint64_t slot = key % HP_BUCKETS;
    for (int probe = 0; probe < 32; probe++) {
        hp_entry *e = &hp_table[(slot + probe) % HP_BUCKETS];
        if (e->used && e->key == key) {
            if (now - e->last > HP_WINDOW) e->count = 0;
            e->count++;
            e->last = now;
            hcount = e->count;
            hlast = e->last;
            hp_hits_total++;
            pthread_mutex_unlock(&hp_lock);
            goto report;
        }
        if (!e->used || now - e->last > HP_WINDOW) {
            e->used = 1;
            e->key = key;
            e->count = 1;
            e->last = now;
            hcount = e->count;
            hlast = e->last;
            hp_hits_total++;
            pthread_mutex_unlock(&hp_lock);
            goto report;
        }
    }
    pthread_mutex_unlock(&hp_lock);
    return;

report:
    if (store_valkey || store_s3) remote_put_honeypot(key, hcount, hlast);
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
    if (count == 0 && remote_available() && !vk_miss_seen(key)) {
        int c2 = 0;
        time_t l2 = 0;
        int got = remote_get_honeypot(key, &c2, &l2);
        if (got == 1 && c2 > 0 && now - l2 <= HP_WINDOW) {
            count = c2;
            hp_cache_put(key, c2, l2);
        } else if (got == 0) {
            vk_miss_mark(key);
        }
    }
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
    char ppath[4096];       /* repeated slashes collapsed, for rule matching */
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

/* Header lookups into a caller buffer. The pointer version below hands back one
 * shared buffer per thread, which is a trap: keeping two values from it leaves
 * both pointing at the second. Keep using it only where the value is consumed
 * immediately; anything else calls this. */
static int header_value_into(const request *req, const char *name, char *out, size_t cap) {
    size_t namelen = strlen(name);
    const char *p = req->headers;
    while (p && *p) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        if (!strncasecmp(p, name, namelen) && p[namelen] == ':') {
            const char *v = p + namelen + 1;
            while (*v == ' ') v++;
            size_t n = (size_t)(eol - v);
            if (n >= cap) n = cap - 1;
            memcpy(out, v, n);
            out[n] = 0;
            return 1;
        }
        p = eol + 2;
    }
    if (cap) out[0] = 0;
    return 0;
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

/* Anubis refuses a path with a "." or ".." segment outright
 * (lib/policy/checker.go:192-215) and collapses repeated slashes before rules
 * see it (:219-231). The first is a proxy hazard, the second is why a rule for
 * /health should also match //health. */
static int path_is_sane(const char *p) {
    const char *seg = p;
    for (;;) {
        const char *slash = strchr(seg, '/');
        size_t n = slash ? (size_t)(slash - seg) : strlen(seg);
        if ((n == 1 && seg[0] == '.') || (n == 2 && seg[0] == '.' && seg[1] == '.'))
            return 0;
        if (!slash) break;
        seg = slash + 1;
    }
    return 1;
}

static void collapse_slashes(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 1 < cap; i++) {
        if (in[i] == '/' && i > 0 && in[i - 1] == '/') continue;
        out[o++] = in[i];
    }
    out[o] = 0;
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
    char head[2176];
    char alt[96] = "";
    if (cfg.http3 && h3_port)
        snprintf(alt, sizeof alt, "Alt-Svc: h3=\":%d\"; ma=86400\r\n", h3_port);
    int n = snprintf(head, sizeof head,
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "Cache-Control: no-store\r\n"
                     "X-Powered-By: betterAnusbis/" VERSION "\r\n"
                     "%s%s"
                     "\r\n",
                     status, reason, content_type ? content_type : "text/plain; charset=utf-8",
                     body_len, extra_headers ? extra_headers : "", alt);
    if (n > 0) send_all(c, head, (size_t)n);
    if (body && body_len) send_all(c, body, body_len);
}

static void respond_redirect_with(conn *c, int status, const char *location,
                                  const char *extra_headers) {
    char head[4192];
    char alt[96] = "";
    if (cfg.http3 && h3_port)
        snprintf(alt, sizeof alt, "Alt-Svc: h3=\":%d\"; ma=86400\r\n", h3_port);
    int n = snprintf(head, sizeof head,
                     "HTTP/1.1 %d %s\r\n"
                     "Location: %s\r\n"
                     "Content-Length: 0\r\n"
                     "Connection: close\r\n"
                     "%s%s"
                     "\r\n",
                     status, reason_for(status), location,
                     extra_headers ? extra_headers : "", alt);
    if (n > 0) send_all(c, head, (size_t)n);
}

static void respond_redirect(conn *c, const char *location, const char *extra_headers) {
    respond_redirect_with(c, 302, location, extra_headers);
}

/* ---------------------------------------------------------------- metrics */

/* -------------------------------------------------------------- MaxMind DB
 *
 * Reading a .mmdb is four things: a search tree of fixed-width records, a
 * 16-byte separator, a data section of tagged values, and a metadata map behind
 * a marker near the end of the file. The record types Anubis asks for are
 * country.iso_code (with registered_country as a fallback) and
 * autonomous_system_number plus autonomous_system_organization
 * (lib/geoip/geoip.go:65-77). That is all this reads.
 *
 * Nothing here is guessed: the test databases from the MaxMind-DB repository
 * are checked into tools/geoip-testdata with the answers the C reader has to
 * reproduce.
 */
#define MMDB_MARKER "\xab\xcd\xefMaxMind.com"
#define MMDB_MARKER_LEN 14

typedef struct {
    unsigned char *buf;
    size_t len;
    uint32_t node_count;
    uint16_t record_size;
    uint16_t ip_version;
    size_t tree_size;            /* node_count * record_size * 2 / 8 */
    size_t ptr_base;             /* what a pointer's offset 0 refers to */
    char db_type[48];
    int ok;
} mmdb;

static mmdb mm_country, mm_asn;

typedef struct {
    int type;                    /* the type number from the spec, 1..15 */
    uint64_t num;                /* uint16/uint32/uint64/int32/bool */
    const char *str;             /* string bytes, not terminated */
    size_t str_len;
    size_t count;                /* map pairs or array elements */
    size_t body;                 /* absolute offset of the first child */
    int via_ptr;                 /* the value was reached through a pointer */
} mval;

static int mm_read_n(const mmdb *db, size_t *pos, int nbytes, uint64_t *out) {
    if (*pos + (size_t)nbytes > db->len) return -1;
    uint64_t v = 0;
    for (int i = 0; i < nbytes; i++) v = (v << 8) | db->buf[(*pos)++];
    *out = v;
    return 0;
}

/* Decode one value. Maps and arrays are reported with a count and the caller
 * walks them; a pointer is followed transparently. Returns the position just
 * past the value's *header*, which for a map is the first key. */
static int mm_decode(const mmdb *db, size_t *pos, mval *v) {
    if (*pos >= db->len) return -1;
    memset(v, 0, sizeof *v);
    uint8_t ctrl = db->buf[(*pos)++];
    int type = ctrl >> 5;
    uint64_t size = ctrl & 0x1f;
    if (type == 0) {
        if (*pos >= db->len) return -1;
        type = 7 + db->buf[(*pos)++];
    }
    if (size == 29) {
        uint64_t extra;
        if (mm_read_n(db, pos, 1, &extra) != 0) return -1;
        size = 29 + extra;
    } else if (size == 30) {
        uint64_t extra;
        if (mm_read_n(db, pos, 2, &extra) != 0) return -1;
        size = 285 + extra;
    } else if (size == 31) {
        uint64_t extra;
        if (mm_read_n(db, pos, 3, &extra) != 0) return -1;
        size = 65821 + extra;
    }
    v->type = type;

    switch (type) {
    case 1: {                    /* pointer: follow it, the target's type wins */
        /* the size field selects 1 to 4 bytes via size >> 3, and its low three
         * bits are the pointer's high bits (maxminddb decoder.py does the same) */
        int psize = (int)(size >> 3) + 1;
        static const uint64_t bias[5] = {0, 0, 2048, 526336, 0};
        uint64_t b = 0;
        if (mm_read_n(db, pos, psize, &b) != 0) return -1;
        uint64_t ptr = b | ((uint64_t)(size & 0x7) << (psize * 8));
        ptr += bias[psize];
        size_t target = db->ptr_base + (size_t)ptr;
        if (target >= db->len) return -1;
        int rc = mm_decode(db, &target, v);
        if (rc == 0) v->via_ptr = 1;
        return rc;
    }
    case 2:                      /* utf8 string */
        if (*pos + (size_t)size > db->len) return -1;
        v->str = (const char *)(db->buf + *pos);
        v->str_len = (size_t)size;
        *pos += (size_t)size;
        return 0;
    case 3:                      /* double */
    case 4:                      /* bytes */
    case 8:                      /* int32 */
    case 10:                     /* uint128 */
    case 15:                     /* float */
        if (*pos + (size_t)size > db->len) return -1;
        *pos += (size_t)size;
        return 0;
    case 5:                      /* uint16 */
    case 6:                      /* uint32 */
    case 9:                      /* uint64 */
        if (mm_read_n(db, pos, (int)size, &v->num) != 0) return -1;
        return 0;
    case 7:                      /* map */
    case 11:                     /* array */
        v->count = (size_t)size;
        v->body = *pos;
        return 0;
    case 14:                     /* boolean: the value is the size */
        v->num = size ? 1 : 0;
        return 0;
    default:
        return -1;
    }
}

/* Skip a whole value, including a map's or array's contents. */
static int mm_skip(const mmdb *db, size_t *pos, int depth) {
    if (depth > 24) return -1;
    mval v;
    if (mm_decode(db, pos, &v) != 0) return -1;
    if (v.type != 7 && v.type != 11) return 0;
    size_t resume = *pos;        /* right after the bytes stored here */
    size_t p = v.body;
    if (v.type == 7) {
        for (size_t i = 0; i < v.count; i++) {
            if (mm_skip(db, &p, depth + 1) != 0) return -1;   /* key */
            if (mm_skip(db, &p, depth + 1) != 0) return -1;   /* value */
        }
    } else {
        for (size_t i = 0; i < v.count; i++)
            if (mm_skip(db, &p, depth + 1) != 0) return -1;
    }
    /* a container reached through a pointer consumed only the pointer here;
     * its contents live somewhere else in the data section */
    *pos = v.via_ptr ? resume : p;
    return 0;
}

static int mm_key_is(const mval *k, const char *name) {
    size_t n = strlen(name);
    return k->type == 2 && k->str_len == n && !memcmp(k->str, name, n);
}

/* Walk a map looking for iso_code (one level down) and the ASN pair. */
static void mm_scan_map_body(const mmdb *db, size_t *pos, size_t pairs,
                        char *country, size_t ccap, char *reg_country, size_t rcap,
                        uint32_t *asn, char *org, size_t ocap, int depth) {
    if (depth > 6) return;
    for (size_t i = 0; i < pairs; i++) {
        mval key;
        if (mm_decode(db, pos, &key) != 0) return;
        size_t val_start = *pos;
        mval val;
        if (mm_decode(db, pos, &val) != 0) return;
        if (mm_key_is(&key, "country") || mm_key_is(&key, "registered_country")) {
            int is_reg = mm_key_is(&key, "registered_country");
            if (val.type == 7) {
                size_t walk = val.body;
                for (size_t k = 0; k < val.count; k++) {
                    mval ik, iv;
                    if (mm_decode(db, &walk, &ik) != 0) return;
                    size_t iv_start = walk;
                    if (mm_decode(db, &walk, &iv) != 0) return;
                    if (mm_key_is(&ik, "iso_code") && iv.type == 2 && iv.str_len >= 2) {
                        char *dst = is_reg ? reg_country : country;
                        size_t cap = is_reg ? rcap : ccap;
                        size_t n = iv.str_len < cap - 1 ? iv.str_len : cap - 1;
                        memcpy(dst, iv.str, n);
                        dst[n] = 0;
                        for (size_t q = 0; q < n; q++)
                            if (dst[q] >= 'a' && dst[q] <= 'z') dst[q] = (char)(dst[q] - 32);
                    } else if (iv.type == 7 || iv.type == 11) {
                        walk = iv_start;
                        if (mm_skip(db, &walk, depth + 1) != 0) return;
                    }
                }
            }
            *pos = val_start;
            if (mm_skip(db, pos, depth + 1) != 0) return;
            continue;
        }
        if (mm_key_is(&key, "autonomous_system_number")) {
            if (val.type == 5 || val.type == 6 || val.type == 9) *asn = (uint32_t)val.num;
        } else if (mm_key_is(&key, "autonomous_system_organization")) {
            if (val.type == 2) {
                size_t n = val.str_len < ocap - 1 ? val.str_len : ocap - 1;
                memcpy(org, val.str, n);
                org[n] = 0;
            }
        } else if (val.type == 7 || val.type == 11) {
            *pos = val_start;
            if (mm_skip(db, pos, depth + 1) != 0) return;
        }
    }
}

static int mmdb_open(mmdb *db, const char *path) {
    memset(db, 0, sizeof *db);
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "betterAnusbis: cannot read %s: %s\n", path, strerror(errno));
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0 || size > (64 << 20)) {
        fprintf(stderr, "betterAnusbis: %s is not a plausible database size\n", path);
        fclose(f);
        return -1;
    }
    db->buf = malloc((size_t)size);
    if (!db->buf || fread(db->buf, 1, (size_t)size, f) != (size_t)size) {
        fprintf(stderr, "betterAnusbis: cannot read %s\n", path);
        free(db->buf);
        db->buf = NULL;
        fclose(f);
        return -1;
    }
    fclose(f);
    db->len = (size_t)size;

    /* the marker sits in the last 128 KB */
    size_t search_from = db->len > (128u << 10) ? db->len - (128u << 10) : 0;
    size_t marker = SIZE_MAX;
    for (size_t i = db->len - MMDB_MARKER_LEN; i-- > search_from;)
        if (!memcmp(db->buf + i, MMDB_MARKER, MMDB_MARKER_LEN)) {
            marker = i;
            break;
        }
    if (marker == SIZE_MAX) {
        fprintf(stderr, "betterAnusbis: %s has no MaxMind metadata marker\n", path);
        free(db->buf);
        db->buf = NULL;
        return -1;
    }

    size_t pos = marker + MMDB_MARKER_LEN;
    db->ptr_base = marker;       /* metadata pointers are relative to the marker */
    mval meta;
    if (mm_decode(db, &pos, &meta) != 0 || meta.type != 7) {
        fprintf(stderr, "betterAnusbis: %s has unreadable metadata\n", path);
        free(db->buf);
        db->buf = NULL;
        return -1;
    }
    for (size_t i = 0; i < meta.count; i++) {
        mval key, val;
        size_t save = pos;
        if (mm_decode(db, &pos, &key) != 0) break;
        if (mm_decode(db, &pos, &val) != 0) break;
        if (mm_key_is(&key, "node_count")) db->node_count = (uint32_t)val.num;
        else if (mm_key_is(&key, "record_size")) db->record_size = (uint16_t)val.num;
        else if (mm_key_is(&key, "ip_version")) db->ip_version = (uint16_t)val.num;
        else if (mm_key_is(&key, "database_type") && val.type == 2) {
            size_t n = val.str_len < sizeof db->db_type - 1 ? val.str_len : sizeof db->db_type - 1;
            memcpy(db->db_type, val.str, n);
            db->db_type[n] = 0;
        } else if (val.type == 7 || val.type == 11) {
            pos = save;
            if (mm_skip(db, &pos, 0) != 0) break;
            if (mm_skip(db, &pos, 0) != 0) break;
        }
    }
    if (!db->node_count || !db->record_size || !db->ip_version) {
        fprintf(stderr, "betterAnusbis: %s metadata is missing node_count/record_size/ip_version\n",
                path);
        free(db->buf);
        db->buf = NULL;
        return -1;
    }
    db->tree_size = (size_t)db->node_count * (db->record_size * 2 / 8);
    db->ptr_base = db->tree_size + 16;   /* the data section starts after the separator */
    db->ok = 1;
    logmsg("geoip: %s is %s, %u nodes, %u-bit records, IPv%d", path, db->db_type,
           db->node_count, db->record_size, db->ip_version);
    return 0;
}

/* One tree walk. Returns the data-section offset, or 0 when the address is not
 * in the database. */
static size_t mmdb_find(const mmdb *db, const char *ipstr) {
    unsigned char addr[16];
    int v4 = 1;
    struct in_addr a4;
    struct in6_addr a6;
    if (!strchr(ipstr, ':')) {
        if (inet_pton(AF_INET, ipstr, &a4) != 1) return 0;
        memcpy(addr + 12, &a4, 4);
    } else {
        if (inet_pton(AF_INET6, ipstr, &a6) != 1) return 0;
        memcpy(addr, &a6, 16);
        v4 = 0;
    }
    int bits = db->ip_version == 6 ? 128 : 32;
    if (db->ip_version == 6 && v4) {
        /* the mapped form, ::ffff:a.b.c.d, is where an IPv4 address lives in an
         * IPv6 database (maxminddb's ip.To16 does the same before walking) */
        memset(addr, 0, 12);
        addr[10] = addr[11] = 0xff;
        memcpy(addr + 12, &a4, 4);
    }
    int start = 0;

    uint32_t node = 0;
    int bytes = db->record_size * 2 / 8;
    for (int i = start; i < bits; i++) {
        if (node >= db->node_count) break;
        int bit = (addr[i / 8] >> (7 - (i % 8))) & 1;
        size_t off = (size_t)node * (size_t)bytes;
        if (off + (size_t)bytes > db->len) return 0;
        uint32_t record;
        if (db->record_size == 24) {
            const unsigned char *p = db->buf + off + (bit ? 3 : 0);
            record = ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
        } else if (db->record_size == 28) {
            const unsigned char *p = db->buf + off;
            if (bit) {
                record = ((uint32_t)(p[3] & 0x0f) << 24) | ((uint32_t)p[4] << 16) |
                         ((uint32_t)p[5] << 8) | p[6];
            } else {
                record = ((uint32_t)(p[3] & 0xf0) << 20) | ((uint32_t)p[0] << 16) |
                         ((uint32_t)p[1] << 8) | p[2];
            }
        } else {                        /* 32 */
            const unsigned char *p = db->buf + off + (bit ? 4 : 0);
            record = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                     ((uint32_t)p[2] << 8) | p[3];
        }
        node = record;
    }
    if (node <= db->node_count) return 0;      /* == is "not found" */
    size_t offset = (size_t)(node - db->node_count) + db->tree_size;
    if (offset >= db->len) return 0;
    return offset;
}

/* Country code, uppercased. country.iso_code first, registered_country second,
 * which is what lib/geoip/geoip.go:203-236 prefers by default. */
static int geoip_country(const char *ip, char *out, size_t cap) {
    if (!mm_country.ok) return 0;
    mm_country.ptr_base = mm_country.tree_size + 16;
    size_t off = mmdb_find(&mm_country, ip);
    if (!off) return 0;
    char country[8] = "", registered[8] = "", org[8];
    size_t pos = off;
    mval root;
    if (mm_decode(&mm_country, &pos, &root) != 0 || root.type != 7) return 0;
    pos = root.body;
    mm_scan_map_body(&mm_country, &pos, root.count, country, sizeof country, registered,
                     sizeof registered, NULL, org, sizeof org, 0);
    const char *best = country[0] ? country : registered;
    if (!best[0]) return 0;
    snprintf(out, cap, "%s", best);
    return 1;
}

static int geoip_asn(const char *ip, uint32_t *out) {
    if (!mm_asn.ok) return 0;
    mm_asn.ptr_base = mm_asn.tree_size + 16;
    size_t off = mmdb_find(&mm_asn, ip);
    if (!off) return 0;
    char country[8], registered[8], org[128];
    uint32_t asn = 0;
    size_t pos = off;
    mval root;
    if (mm_decode(&mm_asn, &pos, &root) != 0 || root.type != 7) return 0;
    pos = root.body;
    memset(country, 0, sizeof country);
    memset(registered, 0, sizeof registered);
    memset(org, 0, sizeof org);
    mm_scan_map_body(&mm_asn, &pos, root.count, country, sizeof country, registered,
                     sizeof registered, &asn, org, sizeof org, 0);
    if (!asn) return 0;
    *out = asn;
    return 1;
}

/* the store backend is selected before the codec is defined, so these live here */
static char store_path[1024];
static volatile int store_dirty;

/*
 * bbolt_io.h -- self-contained generic reader/writer for bbolt (BoltDB) files.
 *
 * Format: bbolt meta page version 2, page size taken from the file (default
 * 4096 for new files). Only libc is used. Little-endian on-disk integers are
 * encoded/decoded explicitly, so the host byte order does not matter.
 *
 * Data model:
 *   bb_db.root        root bucket (the tree of top-level buckets)
 *   bb_bucket.items   items in bytewise-ascending key order
 *   bb_item.is_bucket bucket entries carry child != NULL and no value
 *
 * Keys are byte strings and must be non-empty. Values are binary-safe.
 * Buckets may be nested arbitrarily; the reader understands both inline
 * buckets (InBucket.root == 0, leaf page stored inside the item value) and
 * regular on-page buckets. The writer always emits regular (non-inline)
 * bucket pages, which is valid upstream bbolt.
 */
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bb_item {
    unsigned char *key;
    size_t keylen;
    unsigned char *value;
    size_t vallen;
    int is_bucket;
    struct bb_bucket *child;
} bb_item;

typedef struct bb_bucket {
    char *name;
    size_t namelen;
    bb_item *items;
    size_t nitems;
    size_t cap;
    unsigned long long sequence;
} bb_bucket;

typedef struct bb_db {
    bb_bucket root;
    unsigned int page_size;
    unsigned long long txid;
} bb_db;

/*
 * Read a bbolt file into *db.
 * Returns 0 on success, -1 on error (err receives a human-readable message).
 * On failure *db is left empty and all partially allocated memory is freed.
 * The caller must bb_db_free() a successfully initialized db.
 */
int bb_read_file(const char *path, bb_db *db, char *err, size_t errcap);

/*
 * Atomically write *db as a valid bbolt file.
 * The new file is created as a temporary file in the same directory, fully
 * written, fsynced, then renamed over path (mode 0600). page_size == 0 means
 * 4096. Returns 0 on success, -1 on error.
 */
int bb_write_file(const char *path, const bb_db *db, char *err, size_t errcap);

/* Free all memory owned by *db and zero it. Safe on a zeroed struct. */
void bb_db_free(bb_db *db);

/* Find a top-level bucket by NUL-terminated name; NULL if absent. */
bb_bucket *bb_find_bucket(bb_db *db, const char *name);

/*
 * Create (or return the existing) top-level bucket named name.
 * Returns NULL if the name is empty/too long, memory is exhausted, or the
 * name already exists as a plain value.
 */
bb_bucket *bb_add_bucket(bb_db *db, const char *name);

/*
 * Insert or replace key in b. Replaces the value if the key exists as a plain
 * value; fails (-1) if the key exists as a bucket entry.
 */
int bb_set(bb_bucket *b, const void *key, size_t keylen,
           const void *val, size_t vallen);

/*
 * Look up key. Returns a malloc'd copy of the value (non-NULL even for a
 * zero-length value) and stores its length in *vallen. Returns NULL if the
 * key is absent or names a bucket.
 */
void *bb_get(bb_bucket *b, const void *key, size_t keylen, size_t *vallen);

/*
 * Delete key. Returns 0 if the key was deleted or was already absent, -1 for
 * invalid arguments or if key names a bucket entry (bbolt behaviour).
 */
int bb_del(bb_bucket *b, const void *key, size_t keylen);

/*
 * Delete a bucket entry and free its whole subtree. Returns 0 if the bucket
 * was deleted or was already absent, -1 for invalid arguments or if the key
 * names a plain value. Works at any level (top-level or nested).
 */
int bb_del_bucket(bb_bucket *b, const void *key, size_t keylen);


/*
 * bbolt_io.c -- self-contained bbolt (BoltDB) file reader/writer.
 *
 * On-disk format (bbolt v1.4.x / v1.5.x, meta version 2):
 *
 *   page header (16 bytes): id u64, flags u16, count u16, overflow u32
 *   meta page body at +16:  magic u32 (0xED0CDAED), version u32 (2),
 *                           pageSize u32, flags u32, root.root u64,
 *                           root.sequence u64, freelist u64, pgid u64,
 *                           txid u64, checksum u64 (FNV-1a 64 over first 56
 *                           bytes of the meta, i.e. through txid)
 *   leaf element (16 bytes): flags u32, pos u32, ksize u32, vsize u32
 *   branch element (16):     pos u32, ksize u32, pgid u64
 *   pos is relative to the element address; data starts at 16 + 16*count and
 *   holds key (+ value for leaves) contiguously.
 *
 * Only libc is used. Multi-byte integers are encoded/decoded byte by byte so
 * the code is independent of host endianness.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BB_PAGE_HEADER   16u
#define BB_ELEM_SIZE     16u
#define BB_BUCKET_HEADER 16u

#define BB_FLAG_BRANCH   0x01u
#define BB_FLAG_LEAF     0x02u
#define BB_FLAG_META     0x04u
#define BB_FLAG_FREELIST 0x10u

#define BB_BUCKET_LEAF_FLAG 0x01u

#define BB_MAGIC   0xED0CDAEDu
#define BB_VERSION 2u

#define BB_MIN_PAGE_SIZE 1024u
#define BB_MAX_PAGE_SIZE (16u * 1024u * 1024u)
#define BB_MAX_DEPTH     64
#define BB_MAX_KEY_SIZE  32768u
#define BB_MAX_VALUE_SIZE 0x7FFFFFFEu
#define BB_NO_FREELIST   UINT64_MAX

/* ------------------------------------------------------------------ */
/* Little-endian load/store                                            */
/* ------------------------------------------------------------------ */

static uint16_t bb_rd16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t bb_rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t bb_rd64(const unsigned char *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static void bb_wr16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char)(v & 0xFFu);
    p[1] = (unsigned char)((v >> 8) & 0xFFu);
}

static void bb_wr32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v & 0xFFu);
    p[1] = (unsigned char)((v >> 8) & 0xFFu);
    p[2] = (unsigned char)((v >> 16) & 0xFFu);
    p[3] = (unsigned char)((v >> 24) & 0xFFu);
}

static void bb_wr64(unsigned char *p, uint64_t v)
{
    p[0] = (unsigned char)(v & 0xFFu);
    p[1] = (unsigned char)((v >> 8) & 0xFFu);
    p[2] = (unsigned char)((v >> 16) & 0xFFu);
    p[3] = (unsigned char)((v >> 24) & 0xFFu);
    p[4] = (unsigned char)((v >> 32) & 0xFFu);
    p[5] = (unsigned char)((v >> 40) & 0xFFu);
    p[6] = (unsigned char)((v >> 48) & 0xFFu);
    p[7] = (unsigned char)((v >> 56) & 0xFFu);
}

static uint64_t bb_fnv1a64(const unsigned char *p, size_t n)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= (uint64_t)p[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static int bb_err(char *err, size_t errcap, const char *fmt, ...)
{
    if (err != NULL && errcap > 0) {
        va_list ap;
        va_start(ap, fmt);
        (void)vsnprintf(err, errcap, fmt, ap);
        va_end(ap);
    }
    return -1;
}

static int bb_keycmp(const unsigned char *a, size_t alen,
                     const unsigned char *b, size_t blen)
{
    size_t n = (alen < blen) ? alen : blen;
    int c = 0;
    if (n > 0) {
        c = memcmp(a, b, n);
    }
    if (c != 0) {
        return (c < 0) ? -1 : 1;
    }
    if (alen < blen) {
        return -1;
    }
    if (alen > blen) {
        return 1;
    }
    return 0;
}

static unsigned char *bb_dup(const void *p, size_t n)
{
    unsigned char *q;
    if (n == 0) {
        n = 1; /* keep zero-length values distinguishable from NULL */
    }
    q = (unsigned char *)malloc(n);
    if (q == NULL) {
        return NULL;
    }
    if (p != NULL) {
        memcpy(q, p, n);
    }
    return q;
}

/* ------------------------------------------------------------------ */
/* Bucket memory management (used by reader and public helpers)        */
/* ------------------------------------------------------------------ */

static void bb_bucket_clear(bb_bucket *b)
{
    size_t i;
    if (b == NULL) {
        return;
    }
    for (i = 0; i < b->nitems; i++) {
        bb_item *it = &b->items[i];
        free(it->key);
        it->key = NULL;
        if (it->is_bucket) {
            if (it->child != NULL) {
                bb_bucket_clear(it->child);
                free(it->child);
            }
        } else {
            free(it->value);
        }
        it->value = NULL;
        it->child = NULL;
    }
    free(b->items);
    free(b->name);
    memset(b, 0, sizeof(*b));
}

void bb_db_free(bb_db *db)
{
    if (db == NULL) {
        return;
    }
    bb_bucket_clear(&db->root);
    memset(db, 0, sizeof(*db));
}

/* Append an item; takes ownership of key/val/child only on success. */
static int bb_bucket_append(bb_bucket *b, unsigned char *key, size_t keylen,
                            unsigned char *val, size_t vallen, int is_bucket,
                            bb_bucket *child)
{
    bb_item *it;
    if (b->nitems == b->cap) {
        size_t ncap = (b->cap == 0) ? 8 : b->cap * 2;
        bb_item *ni;
        if (ncap < b->cap || ncap > (SIZE_MAX / sizeof(bb_item))) {
            return -1;
        }
        ni = (bb_item *)realloc(b->items, ncap * sizeof(bb_item));
        if (ni == NULL) {
            return -1;
        }
        b->items = ni;
        b->cap = ncap;
    }
    it = &b->items[b->nitems];
    memset(it, 0, sizeof(*it));
    it->key = key;
    it->keylen = keylen;
    it->value = val;
    it->vallen = vallen;
    it->is_bucket = is_bucket;
    it->child = child;
    b->nitems++;
    return 0;
}

/* Binary search; returns index of key or the insertion point (as -(i+1)). */
static long bb_bucket_search(const bb_bucket *b, const unsigned char *key,
                             size_t keylen)
{
    size_t lo = 0;
    size_t hi = b->nitems;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = bb_keycmp(b->items[mid].key, b->items[mid].keylen, key, keylen);
        if (c == 0) {
            return (long)mid;
        }
        if (c < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return -(long)lo - 1;
}

/* ------------------------------------------------------------------ */
/* Public helpers                                                      */
/* ------------------------------------------------------------------ */

bb_bucket *bb_find_bucket(bb_db *db, const char *name)
{
    size_t nlen;
    long idx;

    if (db == NULL || name == NULL) {
        return NULL;
    }
    nlen = strlen(name);
    if (nlen == 0 || nlen > BB_MAX_KEY_SIZE) {
        return NULL;
    }
    idx = bb_bucket_search(&db->root, (const unsigned char *)name, nlen);
    if (idx < 0) {
        return NULL;
    }
    if (!db->root.items[idx].is_bucket) {
        return NULL;
    }
    return db->root.items[idx].child;
}

bb_bucket *bb_add_bucket(bb_db *db, const char *name)
{
    size_t nlen;
    long idx;
    bb_bucket *child;
    unsigned char *key;
    unsigned char *nm;

    if (db == NULL || name == NULL) {
        return NULL;
    }
    nlen = strlen(name);
    if (nlen == 0 || nlen > BB_MAX_KEY_SIZE) {
        return NULL;
    }
    idx = bb_bucket_search(&db->root, (const unsigned char *)name, nlen);
    if (idx >= 0) {
        if (db->root.items[idx].is_bucket) {
            return db->root.items[idx].child;
        }
        return NULL;
    }
    idx = -(idx + 1);
    child = (bb_bucket *)calloc(1, sizeof(*child));
    nm = bb_dup(name, nlen);
    key = bb_dup(name, nlen);
    if (child == NULL || nm == NULL || key == NULL) {
        free(child);
        free(nm);
        free(key);
        return NULL;
    }
    child->name = (char *)nm;
    child->namelen = nlen;
    child->sequence = 0;
    if (bb_bucket_append(&db->root, key, nlen, NULL, 0, 1, child) != 0) {
        free(child);
        free(nm);
        free(key);
        return NULL;
    }
    /* Keep items strictly sorted. */
    if ((size_t)idx + 1 < db->root.nitems) {
        bb_item tmp = db->root.items[db->root.nitems - 1];
        memmove(&db->root.items[(size_t)idx + 1], &db->root.items[idx],
                (db->root.nitems - 1 - (size_t)idx) * sizeof(bb_item));
        db->root.items[idx] = tmp;
    }
    return child;
}

int bb_set(bb_bucket *b, const void *key, size_t keylen,
           const void *val, size_t vallen)
{
    long idx;
    unsigned char *copy;

    if (b == NULL || key == NULL || keylen == 0 || keylen > BB_MAX_KEY_SIZE) {
        return -1;
    }
    if (vallen > 0 && val == NULL) {
        return -1;
    }
    if (vallen > BB_MAX_VALUE_SIZE) {
        return -1;
    }
    idx = bb_bucket_search(b, (const unsigned char *)key, keylen);
    if (idx >= 0) {
        bb_item *it = &b->items[idx];
        if (it->is_bucket) {
            return -1;
        }
        copy = bb_dup(val, vallen);
        if (copy == NULL) {
            return -1;
        }
        free(it->value);
        it->value = copy;
        it->vallen = vallen;
        return 0;
    }
    idx = -(idx + 1);
    copy = bb_dup(val, vallen);
    if (copy == NULL) {
        return -1;
    }
    if (bb_bucket_append(b, NULL, 0, NULL, 0, 0, NULL) != 0) {
        free(copy);
        return -1;
    }
    b->items[b->nitems - 1].key = bb_dup(key, keylen);
    if (b->items[b->nitems - 1].key == NULL) {
        b->nitems--;
        free(copy);
        return -1;
    }
    b->items[b->nitems - 1].keylen = keylen;
    b->items[b->nitems - 1].value = copy;
    b->items[b->nitems - 1].vallen = vallen;
    b->items[b->nitems - 1].is_bucket = 0;
    b->items[b->nitems - 1].child = NULL;
    /* Move into sorted position (append put it last). */
    if ((size_t)idx + 1 < b->nitems) {
        bb_item tmp = b->items[b->nitems - 1];
        memmove(&b->items[(size_t)idx + 1], &b->items[idx],
                (b->nitems - 1 - (size_t)idx) * sizeof(bb_item));
        b->items[idx] = tmp;
    }
    return 0;
}

void *bb_get(bb_bucket *b, const void *key, size_t keylen, size_t *vallen)
{
    long idx;
    unsigned char *copy;
    bb_item *it;

    if (vallen != NULL) {
        *vallen = 0;
    }
    if (b == NULL || key == NULL || keylen == 0) {
        return NULL;
    }
    idx = bb_bucket_search(b, (const unsigned char *)key, keylen);
    if (idx < 0) {
        return NULL;
    }
    it = &b->items[idx];
    if (it->is_bucket) {
        return NULL;
    }
    copy = bb_dup(it->value, it->vallen);
    if (copy == NULL) {
        return NULL;
    }
    if (vallen != NULL) {
        *vallen = it->vallen;
    }
    return copy;
}

int bb_del(bb_bucket *b, const void *key, size_t keylen)
{
    long idx;

    if (b == NULL || key == NULL || keylen == 0) {
        return -1;
    }
    idx = bb_bucket_search(b, (const unsigned char *)key, keylen);
    if (idx < 0) {
        return 0; /* bbolt: deleting an absent key is a no-op success */
    }
    if (b->items[idx].is_bucket) {
        return -1;
    }
    free(b->items[idx].key);
    free(b->items[idx].value);
    if ((size_t)idx + 1 < b->nitems) {
        memmove(&b->items[idx], &b->items[idx + 1],
                (b->nitems - (size_t)idx - 1) * sizeof(bb_item));
    }
    b->nitems--;
    return 0;
}

int bb_del_bucket(bb_bucket *b, const void *key, size_t keylen)
{
    long idx;

    if (b == NULL || key == NULL || keylen == 0) {
        return -1;
    }
    idx = bb_bucket_search(b, (const unsigned char *)key, keylen);
    if (idx < 0) {
        return 0; /* deleting an absent bucket is a no-op success */
    }
    if (!b->items[idx].is_bucket) {
        return -1;
    }
    free(b->items[idx].key);
    if (b->items[idx].child != NULL) {
        bb_bucket_clear(b->items[idx].child);
        free(b->items[idx].child);
    }
    if ((size_t)idx + 1 < b->nitems) {
        memmove(&b->items[idx], &b->items[idx + 1],
                (b->nitems - (size_t)idx - 1) * sizeof(bb_item));
    }
    b->nitems--;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Reader                                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t page_size;
    uint64_t root_root;
    uint64_t root_seq;
    uint64_t freelist;
    uint64_t pgid;
    uint64_t txid;
    uint64_t checksum;
} bb_meta;

typedef struct {
    const unsigned char *data;
    size_t size;
    unsigned int page_size;
    uint64_t pgid;
    uint64_t txid;
    unsigned char *visited;
} bb_reader;

typedef struct {
    const unsigned char *base;
    size_t phys;      /* bytes available from base (1+overflow pages) */
    uint16_t flags;
    uint16_t count;
    uint32_t overflow;
    uint64_t id;
} bb_page;

static int bb_meta_parse(const unsigned char *page, size_t avail,
                         int expect_page, bb_meta *m)
{
    const unsigned char *q;
    if (avail < BB_PAGE_HEADER + 64) {
        return 0;
    }
    /* bbolt's Tx.page() asserts meta pages carry exactly this header. */
    if (bb_rd16(page + 8) != BB_FLAG_META || bb_rd16(page + 10) != 0 ||
        bb_rd32(page + 12) != 0) {
        return 0;
    }
    if (expect_page >= 0 && bb_rd64(page) != (uint64_t)expect_page) {
        return 0;
    }
    q = page + BB_PAGE_HEADER;
    m->page_size = bb_rd32(q + 8);
    m->root_root = bb_rd64(q + 16);
    m->root_seq = bb_rd64(q + 24);
    m->freelist = bb_rd64(q + 32);
    m->pgid = bb_rd64(q + 40);
    m->txid = bb_rd64(q + 48);
    m->checksum = bb_rd64(q + 56);
    if (bb_rd32(q) != BB_MAGIC || bb_rd32(q + 4) != BB_VERSION) {
        return 0;
    }
    if (m->page_size < BB_MIN_PAGE_SIZE || m->page_size > BB_MAX_PAGE_SIZE ||
        (m->page_size % 1024u) != 0) {
        return 0;
    }
    if (bb_fnv1a64(q, 56) != m->checksum) {
        return 0;
    }
    return 1;
}

static int bb_load_file(const char *path, unsigned char **out, size_t *outlen,
                        char *err, size_t errcap)
{
    int fd;
    struct stat st;
    unsigned char *buf;
    size_t got = 0;
    size_t want;
    ssize_t n;

    *out = NULL;
    *outlen = 0;
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return bb_err(err, errcap, "cannot open '%s': %s", path, strerror(errno));
    }
    if (fstat(fd, &st) != 0) {
        int e = errno;
        (void)close(fd);
        return bb_err(err, errcap, "cannot stat '%s': %s", path, strerror(e));
    }
    if (st.st_size <= 0) {
        (void)close(fd);
        return bb_err(err, errcap, "'%s': empty file", path);
    }
    if ((uintmax_t)st.st_size > (uintmax_t)SIZE_MAX) {
        (void)close(fd);
        return bb_err(err, errcap, "'%s': file too large", path);
    }
    want = (size_t)st.st_size;
    buf = (unsigned char *)malloc(want);
    if (buf == NULL) {
        (void)close(fd);
        return bb_err(err, errcap, "'%s': out of memory", path);
    }
    while (got < want) {
        n = read(fd, buf + got, want - got);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            {
                int e = errno;
                free(buf);
                (void)close(fd);
                return bb_err(err, errcap, "'%s': read failed: %s", path,
                              strerror(e));
            }
        }
        if (n == 0) {
            free(buf);
            (void)close(fd);
            return bb_err(err, errcap, "'%s': unexpected EOF", path);
        }
        got += (size_t)n;
    }
    (void)close(fd);
    *out = buf;
    *outlen = want;
    return 0;
}

static int bb_page_mark(bb_reader *r, uint64_t pgid, uint32_t overflow,
                        char *err, size_t errcap)
{
    uint64_t i;
    for (i = 0; i <= (uint64_t)overflow; i++) {
        uint64_t id = pgid + i;
        size_t bit;
        if (id >= r->pgid) {
            return bb_err(err, errcap,
                          "page %llu overflow exceeds high water mark %llu",
                          (unsigned long long)pgid,
                          (unsigned long long)r->pgid);
        }
        if (r->visited == NULL) {
            continue;
        }
        bit = (size_t)id;
        if ((r->visited[bit >> 3] & (unsigned char)(1u << (bit & 7u))) != 0) {
            return bb_err(err, errcap,
                          "page %llu referenced more than once (cycle?)",
                          (unsigned long long)id);
        }
        r->visited[bit >> 3] |= (unsigned char)(1u << (bit & 7u));
    }
    return 0;
}

static int bb_page_load(bb_reader *r, uint64_t pgid, bb_page *p,
                        char *err, size_t errcap)
{
    uint64_t off;
    uint64_t phys;
    uint32_t overflow;
    uint16_t flags;
    uint16_t count;

    if (pgid < 2) {
        return bb_err(err, errcap, "invalid page id %llu",
                      (unsigned long long)pgid);
    }
    if (pgid >= r->pgid) {
        return bb_err(err, errcap,
                      "page id %llu out of range (high water mark %llu)",
                      (unsigned long long)pgid,
                      (unsigned long long)r->pgid);
    }
    off = pgid * (uint64_t)r->page_size;
    if (off > (uint64_t)r->size || (uint64_t)r->size - off < BB_PAGE_HEADER) {
        return bb_err(err, errcap, "page %llu: truncated header",
                      (unsigned long long)pgid);
    }
    p->base = r->data + (size_t)off;
    p->id = bb_rd64(p->base);
    flags = bb_rd16(p->base + 8);
    count = bb_rd16(p->base + 10);
    overflow = bb_rd32(p->base + 12);
    if (p->id != pgid) {
        return bb_err(err, errcap,
                      "page at offset %llu claims id %llu (expected %llu)",
                      (unsigned long long)off,
                      (unsigned long long)p->id,
                      (unsigned long long)pgid);
    }
    if (flags != BB_FLAG_BRANCH && flags != BB_FLAG_LEAF) {
        return bb_err(err, errcap,
                      "page %llu: unexpected flags 0x%x in bucket tree",
                      (unsigned long long)pgid, (unsigned int)flags);
    }
    if ((uint64_t)overflow + 1u > (uint64_t)SIZE_MAX / r->page_size) {
        return bb_err(err, errcap, "page %llu: overflow too large",
                      (unsigned long long)pgid);
    }
    phys = ((uint64_t)overflow + 1u) * (uint64_t)r->page_size;
    if (phys > (uint64_t)r->size - off) {
        return bb_err(err, errcap,
                      "page %llu: overflow pages run past end of file",
                      (unsigned long long)pgid);
    }
    if (BB_PAGE_HEADER + (size_t)count * BB_ELEM_SIZE > (size_t)phys) {
        return bb_err(err, errcap, "page %llu: element table overflows page",
                      (unsigned long long)pgid);
    }
    if (bb_page_mark(r, pgid, overflow, err, errcap) != 0) {
        return -1;
    }
    p->phys = (size_t)phys;
    p->flags = flags;
    p->count = count;
    p->overflow = overflow;
    return 0;
}

static int bb_tree_parse(bb_reader *r, uint64_t pgid, bb_bucket *b, int depth,
                         char *err, size_t errcap);

static int bb_leaf_parse(bb_reader *r, const unsigned char *base, size_t phys,
                         uint16_t count, bb_bucket *b, int depth,
                         char *err, size_t errcap)
{
    size_t i;
    size_t data_start = BB_PAGE_HEADER + (size_t)count * BB_ELEM_SIZE;

    for (i = 0; i < count; i++) {
        size_t elem_off = BB_PAGE_HEADER + i * BB_ELEM_SIZE;
        uint32_t flags = bb_rd32(base + elem_off);
        uint32_t pos = bb_rd32(base + elem_off + 4);
        uint32_t ksize = bb_rd32(base + elem_off + 8);
        uint32_t vsize = bb_rd32(base + elem_off + 12);
        uint64_t data_off = (uint64_t)elem_off + (uint64_t)pos;
        const unsigned char *key;
        const unsigned char *val;
        unsigned char *key_copy;

        if (ksize == 0) {
            return bb_err(err, errcap, "leaf page: empty key");
        }
        if (data_off < (uint64_t)data_start) {
            return bb_err(err, errcap,
                          "leaf page: element %zu data offset before data area",
                          i);
        }
        if (data_off > (uint64_t)phys ||
            (uint64_t)ksize > (uint64_t)phys - data_off ||
            (uint64_t)vsize > (uint64_t)phys - data_off - (uint64_t)ksize) {
            return bb_err(err, errcap,
                          "leaf page: element %zu data out of bounds "
                          "(pos=%u ksize=%u vsize=%u)",
                          i, (unsigned int)pos, (unsigned int)ksize,
                          (unsigned int)vsize);
        }
        key = base + (size_t)data_off;
        val = key + ksize;
        if (flags != 0 && flags != BB_BUCKET_LEAF_FLAG) {
            return bb_err(err, errcap,
                          "leaf page: element %zu has unknown flags 0x%x",
                          i, (unsigned int)flags);
        }
        if (b->nitems > 0) {
            const bb_item *prev = &b->items[b->nitems - 1];
            if (bb_keycmp(prev->key, prev->keylen, key, ksize) >= 0) {
                return bb_err(err, errcap,
                              "leaf page: keys are not strictly ascending");
            }
        }
        key_copy = bb_dup(key, ksize);
        if (key_copy == NULL) {
            return bb_err(err, errcap, "out of memory");
        }
        if (flags == BB_BUCKET_LEAF_FLAG) {
            uint64_t root;
            uint64_t seq;
            bb_bucket *child;

            if (vsize < BB_BUCKET_HEADER) {
                free(key_copy);
                return bb_err(err, errcap,
                              "bucket item: truncated bucket header");
            }
            root = bb_rd64(val);
            seq = bb_rd64(val + 8);
            child = (bb_bucket *)calloc(1, sizeof(*child));
            if (child == NULL) {
                free(key_copy);
                return bb_err(err, errcap, "out of memory");
            }
            child->name = (char *)bb_dup(key, ksize);
            child->namelen = ksize;
            child->sequence = (unsigned long long)seq;
            if (child->name == NULL) {
                free(child);
                free(key_copy);
                return bb_err(err, errcap, "out of memory");
            }
            if (root == 0) {
                size_t inline_len;
                uint16_t inline_flags;
                uint16_t inline_count;
                uint32_t inline_overflow;

                if (depth + 1 > BB_MAX_DEPTH) {
                    bb_bucket_clear(child);
                    free(child);
                    free(key_copy);
                    return bb_err(err, errcap, "bucket nesting too deep");
                }
                inline_len = (size_t)vsize - BB_BUCKET_HEADER;
                if (inline_len < BB_PAGE_HEADER) {
                    bb_bucket_clear(child);
                    free(child);
                    free(key_copy);
                    return bb_err(err, errcap, "inline bucket page truncated");
                }
                inline_flags = bb_rd16(val + BB_BUCKET_HEADER + 8);
                inline_count = bb_rd16(val + BB_BUCKET_HEADER + 10);
                inline_overflow = bb_rd32(val + BB_BUCKET_HEADER + 12);
                if (inline_flags != BB_FLAG_LEAF || inline_overflow != 0) {
                    bb_bucket_clear(child);
                    free(child);
                    free(key_copy);
                    return bb_err(err, errcap,
                                  "inline bucket page has invalid header");
                }
                if (BB_PAGE_HEADER + (size_t)inline_count * BB_ELEM_SIZE >
                    inline_len) {
                    bb_bucket_clear(child);
                    free(child);
                    free(key_copy);
                    return bb_err(err, errcap,
                                  "inline bucket element table overflows");
                }
                if (bb_leaf_parse(r, val + BB_BUCKET_HEADER, inline_len,
                                  inline_count, child, depth + 1,
                                  err, errcap) != 0) {
                    bb_bucket_clear(child);
                    free(child);
                    free(key_copy);
                    return -1;
                }
            } else {
                if (bb_tree_parse(r, root, child, depth + 1, err, errcap) != 0) {
                    bb_bucket_clear(child);
                    free(child);
                    free(key_copy);
                    return -1;
                }
            }
            if (bb_bucket_append(b, key_copy, ksize, NULL, 0, 1, child) != 0) {
                bb_bucket_clear(child);
                free(child);
                free(key_copy);
                return bb_err(err, errcap, "out of memory");
            }
        } else {
            unsigned char *val_copy = bb_dup(val, vsize);
            if (val_copy == NULL) {
                free(key_copy);
                return bb_err(err, errcap, "out of memory");
            }
            if (bb_bucket_append(b, key_copy, ksize, val_copy, vsize, 0,
                                 NULL) != 0) {
                free(key_copy);
                free(val_copy);
                return bb_err(err, errcap, "out of memory");
            }
        }
    }
    return 0;
}

static int bb_tree_parse(bb_reader *r, uint64_t pgid, bb_bucket *b, int depth,
                         char *err, size_t errcap)
{
    bb_page p;
    size_t i;

    if (depth > BB_MAX_DEPTH) {
        return bb_err(err, errcap, "bucket nesting too deep");
    }
    if (bb_page_load(r, pgid, &p, err, errcap) != 0) {
        return -1;
    }
    if (p.flags == BB_FLAG_LEAF) {
        return bb_leaf_parse(r, p.base, p.phys, p.count, b, depth,
                             err, errcap);
    }
    /* branch page */
    {
        size_t data_start = BB_PAGE_HEADER + (size_t)p.count * BB_ELEM_SIZE;
        const unsigned char *prev_key = NULL;
        size_t prev_klen = 0;

        for (i = 0; i < p.count; i++) {
            size_t elem_off = BB_PAGE_HEADER + i * BB_ELEM_SIZE;
            uint32_t pos = bb_rd32(p.base + elem_off);
            uint32_t ksize = bb_rd32(p.base + elem_off + 4);
            uint64_t child = bb_rd64(p.base + elem_off + 8);
            uint64_t data_off = (uint64_t)elem_off + (uint64_t)pos;
            const unsigned char *key;

            if (ksize == 0) {
                return bb_err(err, errcap, "branch page: empty key");
            }
            if (data_off < (uint64_t)data_start) {
                return bb_err(err, errcap,
                              "branch page: element %zu data offset invalid", i);
            }
            if (data_off > (uint64_t)p.phys ||
                (uint64_t)ksize > (uint64_t)p.phys - data_off) {
                return bb_err(err, errcap,
                              "branch page: element %zu key out of bounds", i);
            }
            key = p.base + (size_t)data_off;
            if (prev_key != NULL &&
                bb_keycmp(prev_key, prev_klen, key, ksize) >= 0) {
                return bb_err(err, errcap,
                              "branch page: keys are not strictly ascending");
            }
            prev_key = key;
            prev_klen = ksize;
            if (child < 2 || child >= r->pgid) {
                return bb_err(err, errcap,
                              "branch page: child page id %llu out of range",
                              (unsigned long long)child);
            }
            if (bb_tree_parse(r, child, b, depth + 1, err, errcap) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

int bb_read_file(const char *path, bb_db *db, char *err, size_t errcap)
{
    bb_reader r;
    bb_meta m0;
    bb_meta m1;
    bb_meta *use = NULL;
    int v0 = 0;
    int v1 = 0;
    unsigned char *buf = NULL;
    size_t size = 0;
    unsigned int ps;
    uint64_t total_bytes;

    if (db == NULL) {
        return bb_err(err, errcap, "bb_read_file: db is NULL");
    }
    memset(db, 0, sizeof(*db));
    if (path == NULL) {
        return bb_err(err, errcap, "bb_read_file: path is NULL");
    }
    if (bb_load_file(path, &buf, &size, err, errcap) != 0) {
        return -1;
    }
    if (size >= BB_PAGE_HEADER + 64) {
        v0 = bb_meta_parse(buf, size, 0, &m0);
    }
    ps = v0 ? m0.page_size : 0;
    if (ps == 0) {
        /* Meta page 0 is unreadable: find meta page 1 the way bbolt does. */
        unsigned int k;
        for (k = 0; k <= 14; k++) {
            uint64_t off = (uint64_t)1024u << k;
            bb_meta cand;
            if (off + BB_PAGE_HEADER + 64 > (uint64_t)size) {
                break;
            }
            if (bb_meta_parse(buf + (size_t)off, size - (size_t)off, -1,
                              &cand)) {
                ps = cand.page_size;
                break;
            }
        }
    }
    if (ps == 0) {
        free(buf);
        return bb_err(err, errcap, "not a bbolt file: no valid meta page");
    }
    if ((uint64_t)ps * 2u > (uint64_t)size) {
        free(buf);
        return bb_err(err, errcap,
                      "corrupt bbolt file: file smaller than two meta pages");
    }
    v0 = bb_meta_parse(buf, size, 0, &m0);
    v1 = bb_meta_parse(buf + ps, size - ps, 1, &m1);
    if (!v0 && !v1) {
        free(buf);
        return bb_err(err, errcap,
                      "corrupt bbolt file: both meta pages are invalid");
    }
    if (v0 && v1 && m0.page_size != m1.page_size) {
        free(buf);
        return bb_err(err, errcap,
                      "corrupt bbolt file: meta pages disagree on page size");
    }
    if (v0 && v1) {
        use = (m1.txid > m0.txid) ? &m1 : &m0;
    } else {
        use = v0 ? &m0 : &m1;
    }
    if (use->page_size != ps) {
        free(buf);
        return bb_err(err, errcap,
                      "corrupt bbolt file: inconsistent page size");
    }
    if (use->pgid < 3 || use->root_root < 2 || use->root_root >= use->pgid) {
        free(buf);
        return bb_err(err, errcap,
                      "corrupt bbolt file: invalid root page or high water mark");
    }
    if (use->pgid > (uint64_t)size / (uint64_t)ps) {
        free(buf);
        return bb_err(err, errcap,
                      "truncated bbolt file: high water mark %llu exceeds "
                      "file capacity (%zu bytes, page size %u)",
                      (unsigned long long)use->pgid, size, ps);
    }
    total_bytes = use->pgid * (uint64_t)ps;
    (void)total_bytes;
    memset(&r, 0, sizeof(r));
    r.data = buf;
    r.size = size;
    r.page_size = ps;
    r.pgid = use->pgid;
    r.txid = use->txid;
    r.visited = (unsigned char *)calloc((size_t)((use->pgid + 7) / 8), 1);
    if (r.visited == NULL) {
        free(buf);
        return bb_err(err, errcap, "out of memory");
    }
    /* Meta pages are not part of the bucket tree. */
    r.visited[0] |= 0x03u;

    db->page_size = ps;
    db->txid = use->txid;
    db->root.sequence = use->root_seq;
    db->root.name = NULL;
    db->root.namelen = 0;

    if (bb_tree_parse(&r, use->root_root, &db->root, 0, err, errcap) != 0) {
        free(r.visited);
        free(buf);
        bb_db_free(db);
        return -1;
    }
    free(r.visited);
    free(buf);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Writer                                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned char *data;
    size_t phys;
    uint64_t id;
} bb_out_page;

typedef struct {
    bb_out_page *pages;
    size_t npages;
    size_t cap;
    uint64_t next_pgid;
    unsigned int ps;
} bb_writer;

typedef struct {
    const unsigned char *key;
    size_t klen;
    const unsigned char *val;
    size_t vlen;
    uint64_t flags;
} bb_ent;

typedef struct {
    uint64_t id;
    const unsigned char *first;
    size_t firstlen;
} bb_child;

static void bb_writer_clear(bb_writer *w)
{
    size_t i;
    for (i = 0; i < w->npages; i++) {
        free(w->pages[i].data);
    }
    free(w->pages);
    memset(w, 0, sizeof(*w));
}

static unsigned char *bb_writer_new_page(bb_writer *w, uint32_t overflow,
                                         uint16_t flags, uint16_t count,
                                         uint64_t *id_out,
                                         char *err, size_t errcap)
{
    uint64_t nphys = (uint64_t)overflow + 1u;
    size_t phys;
    unsigned char *data;
    bb_out_page *np;

    if (nphys > (uint64_t)SIZE_MAX / (uint64_t)w->ps) {
        (void)bb_err(err, errcap, "page too large");
        return NULL;
    }
    phys = (size_t)nphys * w->ps;
    data = (unsigned char *)calloc(1, phys);
    if (data == NULL) {
        (void)bb_err(err, errcap, "out of memory");
        return NULL;
    }
    if (w->npages == w->cap) {
        size_t ncap = (w->cap == 0) ? 16 : w->cap * 2;
        np = (bb_out_page *)realloc(w->pages, ncap * sizeof(bb_out_page));
        if (np == NULL) {
            free(data);
            (void)bb_err(err, errcap, "out of memory");
            return NULL;
        }
        w->pages = np;
        w->cap = ncap;
    }
    w->pages[w->npages].data = data;
    w->pages[w->npages].phys = phys;
    w->pages[w->npages].id = w->next_pgid;
    w->npages++;
    if (id_out != NULL) {
        *id_out = w->next_pgid;
    }
    w->next_pgid += nphys;
    bb_wr64(data, w->next_pgid - nphys);
    bb_wr16(data + 8, flags);
    bb_wr16(data + 10, count);
    bb_wr32(data + 12, overflow);
    return data;
}

static int bb_overflow_for(size_t len, unsigned int ps, uint32_t *out)
{
    uint64_t pages;
    if (len == 0) {
        *out = 0;
        return 0;
    }
    pages = ((uint64_t)len + ps - 1u) / ps;
    if (pages == 0) {
        pages = 1;
    }
    if (pages - 1u > UINT32_MAX) {
        return -1;
    }
    *out = (uint32_t)(pages - 1u);
    return 0;
}

static int bb_pack(const bb_ent *ents, size_t n, size_t ps,
                   size_t **bounds_out, size_t *ngroups_out)
{
    size_t *bounds;
    size_t ng = 0;
    size_t start = 0;
    size_t len = BB_PAGE_HEADER;
    size_t i;

    bounds = (size_t *)malloc((n + 2) * sizeof(size_t));
    if (bounds == NULL) {
        return -1;
    }
    if (n == 0) {
        bounds[0] = 0;
        bounds[1] = 0;
        *bounds_out = bounds;
        *ngroups_out = 1;
        return 0;
    }
    bounds[0] = 0;
    for (i = 0; i < n; i++) {
        size_t esz = BB_ELEM_SIZE + ents[i].klen + ents[i].vlen;
        if (i > start && len + esz > ps) {
            ng++;
            bounds[ng] = i;
            start = i;
            len = BB_PAGE_HEADER;
        }
        len += esz;
    }
    ng++;
    bounds[ng] = n;
    /* Don't leave a lonely single element on the last page if we can move one
     * over without overflowing that page. */
    if (ng >= 2 && bounds[ng] - bounds[ng - 1] == 1 &&
        bounds[ng - 1] - bounds[ng - 2] >= 3) {
        size_t j = bounds[ng - 1] - 1;
        size_t szj = BB_ELEM_SIZE + ents[j].klen + ents[j].vlen;
        size_t szlast = BB_ELEM_SIZE + ents[bounds[ng - 1]].klen +
                        ents[bounds[ng - 1]].vlen;
        if (BB_PAGE_HEADER + 2 * BB_ELEM_SIZE + szj + szlast <= ps) {
            bounds[ng - 1] -= 1;
        }
    }
    *bounds_out = bounds;
    *ngroups_out = ng;
    return 0;
}

/*
 * Pack branch-level entries. Unlike leaves, a branch page may overflow, so a
 * page can always hold at least two child pointers. Requiring >=2 entries per
 * branch page guarantees that each level strictly reduces the page count
 * (otherwise, with huge keys, every page would hold one entry and the tree
 * build would never terminate). A lonely final entry is merged into the
 * previous page.
 */
static int bb_pack_children(const bb_ent *ents, size_t n, size_t ps,
                            size_t **bounds_out, size_t *ngroups_out)
{
    size_t *bounds;
    size_t ng = 0;
    size_t start = 0;
    size_t len = BB_PAGE_HEADER;
    size_t cnt = 0;
    size_t i;

    bounds = (size_t *)malloc((n + 2) * sizeof(size_t));
    if (bounds == NULL) {
        return -1;
    }
    if (n == 0) {
        bounds[0] = 0;
        bounds[1] = 0;
        *bounds_out = bounds;
        *ngroups_out = 1;
        return 0;
    }
    bounds[0] = 0;
    for (i = 0; i < n; i++) {
        size_t esz = BB_ELEM_SIZE + ents[i].klen + ents[i].vlen;
        if (cnt >= 2 && len + esz > ps) {
            ng++;
            bounds[ng] = i;
            start = i;
            len = BB_PAGE_HEADER;
            cnt = 0;
        }
        len += esz;
        cnt++;
    }
    ng++;
    bounds[ng] = n;
    if (ng >= 2 && bounds[ng] - bounds[ng - 1] == 1) {
        bounds[ng - 1] = bounds[ng];
        ng--;
    }
    /* Defensive: if the packing somehow made no progress, emit one (possibly
     * overflow) branch page holding every child. */
    if (n > 1 && ng >= n) {
        ng = 1;
        bounds[1] = n;
    }
    (void)start;
    *bounds_out = bounds;
    *ngroups_out = ng;
    return 0;
}

static int bb_emit_leaf(bb_writer *w, const bb_ent *ents, size_t a, size_t n,
                        uint64_t *id_out, char *err, size_t errcap)
{
    size_t len = BB_PAGE_HEADER + n * BB_ELEM_SIZE;
    size_t i;
    size_t data_off = len;
    unsigned char *page;
    uint32_t overflow;

    if (n > 0xFFFFu) {
        return bb_err(err, errcap, "too many leaf elements for one page");
    }
    for (i = 0; i < n; i++) {
        len += ents[a + i].klen + ents[a + i].vlen;
    }
    if (bb_overflow_for(len, w->ps, &overflow) != 0) {
        return bb_err(err, errcap, "bucket page too large");
    }
    page = bb_writer_new_page(w, overflow, BB_FLAG_LEAF, (uint16_t)n,
                              id_out, err, errcap);
    if (page == NULL) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        size_t elem_off = BB_PAGE_HEADER + i * BB_ELEM_SIZE;
        size_t klen = ents[a + i].klen;
        size_t vlen = ents[a + i].vlen;
        size_t rel = data_off - elem_off;
        if (rel > UINT32_MAX) {
            return bb_err(err, errcap, "leaf element offset overflow");
        }
        bb_wr32(page + elem_off, (uint32_t)ents[a + i].flags);
        bb_wr32(page + elem_off + 4, (uint32_t)rel);
        bb_wr32(page + elem_off + 8, (uint32_t)klen);
        bb_wr32(page + elem_off + 12, (uint32_t)vlen);
        if (klen > 0) {
            memcpy(page + data_off, ents[a + i].key, klen);
        }
        data_off += klen;
        if (vlen > 0) {
            memcpy(page + data_off, ents[a + i].val, vlen);
        }
        data_off += vlen;
    }
    return 0;
}

static int bb_emit_branch(bb_writer *w, const bb_ent *ents,
                          const bb_child *kids, size_t a, size_t n,
                          uint64_t *id_out, char *err, size_t errcap)
{
    size_t len = BB_PAGE_HEADER + n * BB_ELEM_SIZE;
    size_t i;
    size_t data_off = len;
    unsigned char *page;
    uint32_t overflow;

    if (n > 0xFFFFu) {
        return bb_err(err, errcap, "too many branch elements for one page");
    }
    for (i = 0; i < n; i++) {
        len += ents[a + i].klen;
    }
    if (bb_overflow_for(len, w->ps, &overflow) != 0) {
        return bb_err(err, errcap, "branch page too large");
    }
    page = bb_writer_new_page(w, overflow, BB_FLAG_BRANCH, (uint16_t)n,
                              id_out, err, errcap);
    if (page == NULL) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        size_t elem_off = BB_PAGE_HEADER + i * BB_ELEM_SIZE;
        size_t klen = ents[a + i].klen;
        size_t rel = data_off - elem_off;
        if (rel > UINT32_MAX) {
            return bb_err(err, errcap, "branch element offset overflow");
        }
        bb_wr32(page + elem_off, (uint32_t)rel);
        bb_wr32(page + elem_off + 4, (uint32_t)klen);
        bb_wr64(page + elem_off + 8, kids[a + i].id);
        if (klen > 0) {
            memcpy(page + data_off, ents[a + i].key, klen);
        }
        data_off += klen;
    }
    return 0;
}

static int bb_item_ptr_cmp(const void *pa, const void *pb)
{
    const bb_item *a = *(const bb_item *const *)pa;
    const bb_item *b = *(const bb_item *const *)pb;
    return bb_keycmp(a->key, a->keylen, b->key, b->keylen);
}

static int bb_build_bucket(bb_writer *w, const bb_bucket *b,
                           const bb_bucket **stack, int depth,
                           uint64_t *root_out, char *err, size_t errcap)
{
    const bb_item **sorted = NULL;
    uint64_t *child_roots = NULL;
    bb_ent *ents = NULL;
    unsigned char *bucket_hdrs = NULL;
    size_t *bounds = NULL;
    size_t ngroups = 0;
    bb_child *level = NULL;
    size_t nlevel = 0;
    size_t n;
    size_t i;
    int rc = -1;

    if (depth > BB_MAX_DEPTH) {
        return bb_err(err, errcap, "bucket nesting too deep");
    }
    for (i = 0; i < (size_t)depth; i++) {
        if (stack[i] == b) {
            return bb_err(err, errcap, "bucket tree contains a cycle");
        }
    }
    n = b->nitems;
    sorted = (const bb_item **)calloc(n ? n : 1, sizeof(*sorted));
    child_roots = (uint64_t *)calloc(n ? n : 1, sizeof(*child_roots));
    ents = (bb_ent *)calloc(n ? n : 1, sizeof(*ents));
    bucket_hdrs = (unsigned char *)calloc(n ? n : 1, BB_BUCKET_HEADER);
    if (sorted == NULL || child_roots == NULL ||
        ents == NULL || bucket_hdrs == NULL) {
        (void)bb_err(err, errcap, "out of memory");
        goto done;
    }
    for (i = 0; i < n; i++) {
        sorted[i] = &b->items[i];
    }
    if (n > 1) {
        qsort((void *)sorted, n, sizeof(*sorted), bb_item_ptr_cmp);
    }
    for (i = 0; i < n; i++) {
        const bb_item *it = sorted[i];
        if (i > 0 && bb_keycmp(sorted[i - 1]->key, sorted[i - 1]->keylen,
                               it->key, it->keylen) >= 0) {
            (void)bb_err(err, errcap,
                         "duplicate or unsorted key while writing bucket");
            goto done;
        }
        if (it->key == NULL || it->keylen == 0) {
            (void)bb_err(err, errcap, "cannot write an empty key");
            goto done;
        }
        if (it->keylen > BB_MAX_KEY_SIZE) {
            (void)bb_err(err, errcap, "key too large (%zu bytes)", it->keylen);
            goto done;
        }
        if (it->is_bucket) {
            const bb_bucket *child = it->child;
            if (child == NULL) {
                (void)bb_err(err, errcap, "bucket item without child bucket");
                goto done;
            }
            stack[depth] = b;
            if (bb_build_bucket(w, child, stack, depth + 1,
                                &child_roots[i], err, errcap) != 0) {
                goto done;
            }
            ents[i].key = it->key;
            ents[i].klen = it->keylen;
            ents[i].val = bucket_hdrs + i * BB_BUCKET_HEADER;
            ents[i].vlen = BB_BUCKET_HEADER;
            ents[i].flags = BB_BUCKET_LEAF_FLAG;
            bb_wr64(bucket_hdrs + i * BB_BUCKET_HEADER, child_roots[i]);
            bb_wr64(bucket_hdrs + i * BB_BUCKET_HEADER + 8, child->sequence);
        } else {
            if (it->vallen > BB_MAX_VALUE_SIZE) {
                (void)bb_err(err, errcap, "value too large (%zu bytes)",
                             it->vallen);
                goto done;
            }
            ents[i].key = it->key;
            ents[i].klen = it->keylen;
            ents[i].val = it->value;
            ents[i].vlen = it->vallen;
            ents[i].flags = 0;
        }
    }
    if (bb_pack(ents, n, w->ps, &bounds, &ngroups) != 0) {
        (void)bb_err(err, errcap, "out of memory");
        goto done;
    }
    level = (bb_child *)calloc(ngroups, sizeof(*level));
    if (level == NULL) {
        (void)bb_err(err, errcap, "out of memory");
        goto done;
    }
    for (i = 0; i < ngroups; i++) {
        size_t a = bounds[i];
        size_t cnt = bounds[i + 1] - a;
        if (bb_emit_leaf(w, ents, a, cnt, &level[i].id, err, errcap) != 0) {
            goto done;
        }
        if (cnt > 0) {
            level[i].first = ents[a].key;
            level[i].firstlen = ents[a].klen;
        } else {
            level[i].first = NULL;
            level[i].firstlen = 0;
        }
    }
    nlevel = ngroups;
    while (nlevel > 1) {
        bb_ent *bents;
        bb_child *next_level;
        size_t *bbounds = NULL;
        size_t nb = 0;
        size_t j;

        bents = (bb_ent *)calloc(nlevel, sizeof(*bents));
        if (bents == NULL) {
            (void)bb_err(err, errcap, "out of memory");
            goto done;
        }
        for (j = 0; j < nlevel; j++) {
            bents[j].key = level[j].first;
            bents[j].klen = level[j].firstlen;
            bents[j].val = NULL;
            bents[j].vlen = 0;
            bents[j].flags = 0;
        }
        if (bb_pack_children(bents, nlevel, w->ps, &bbounds, &nb) != 0) {
            free(bents);
            (void)bb_err(err, errcap, "out of memory");
            goto done;
        }
        if (nlevel > 1 && nb >= nlevel) {
            /* Defensive fallback: a single overflow branch page. */
            free(bbounds);
            bbounds = (size_t *)malloc(2 * sizeof(size_t));
            if (bbounds == NULL) {
                free(bents);
                (void)bb_err(err, errcap, "out of memory");
                goto done;
            }
            bbounds[0] = 0;
            bbounds[1] = nlevel;
            nb = 1;
        }
        next_level = (bb_child *)calloc(nb, sizeof(*next_level));
        if (next_level == NULL) {
            free(bents);
            free(bbounds);
            (void)bb_err(err, errcap, "out of memory");
            goto done;
        }
        for (j = 0; j < nb; j++) {
            size_t a = bbounds[j];
            size_t cnt = bbounds[j + 1] - a;
            if (bb_emit_branch(w, bents, level, a, cnt, &next_level[j].id,
                               err, errcap) != 0) {
                free(next_level);
                free(bents);
                free(bbounds);
                goto done;
            }
            next_level[j].first = level[a].first;
            next_level[j].firstlen = level[a].firstlen;
        }
        free(bents);
        free(bbounds);
        free(level);
        level = next_level;
        nlevel = nb;
    }
    *root_out = (nlevel > 0) ? level[0].id : 0;
    rc = 0;
done:
    free(sorted);
    free(child_roots);
    free(bucket_hdrs);
    free(ents);
    free(bounds);
    free(level);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Metadata + atomic file output                                       */
/* ------------------------------------------------------------------ */

static void bb_meta_write(unsigned char *page, unsigned int ps, uint64_t root,
                          uint64_t seq, uint64_t pgid, uint64_t txid)
{
    unsigned char *m = page + BB_PAGE_HEADER;
    memset(page, 0, ps);
    bb_wr64(page, txid % 2);
    bb_wr16(page + 8, BB_FLAG_META);
    bb_wr16(page + 10, 0);
    bb_wr32(page + 12, 0);
    bb_wr32(m, BB_MAGIC);
    bb_wr32(m + 4, BB_VERSION);
    bb_wr32(m + 8, ps);
    bb_wr32(m + 12, 0);
    bb_wr64(m + 16, root);
    bb_wr64(m + 24, seq);
    bb_wr64(m + 32, BB_NO_FREELIST);
    bb_wr64(m + 40, pgid);
    bb_wr64(m + 48, txid);
    bb_wr64(m + 56, bb_fnv1a64(m, 56));
}

static int bb_write_all(int fd, const unsigned char *data, size_t len,
                        char *err, size_t errcap)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, data + done, len - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return bb_err(err, errcap, "write failed: %s", strerror(errno));
        }
        if (n == 0) {
            return bb_err(err, errcap, "write returned 0");
        }
        done += (size_t)n;
    }
    return 0;
}

static int bb_write_atomic(const char *path, const unsigned char *data,
                           size_t len, char *err, size_t errcap)
{
    char *tmpl;
    const char *slash;
    size_t dirlen;
    int fd = -1;
    int rc = -1;

    slash = strrchr(path, '/');
    dirlen = (slash != NULL) ? (size_t)(slash - path) + 1 : 0;
    tmpl = (char *)malloc(dirlen + 32);
    if (tmpl == NULL) {
        return bb_err(err, errcap, "out of memory");
    }
    if (dirlen > 0) {
        memcpy(tmpl, path, dirlen);
    }
    memcpy(tmpl + dirlen, ".bbolt-tmp-XXXXXX", 18);
    fd = mkstemp(tmpl);
    if (fd < 0) {
        bb_err(err, errcap, "cannot create temporary file in '%s': %s",
               dirlen > 0 ? path : ".", strerror(errno));
        free(tmpl);
        return -1;
    }
    if (fchmod(fd, 0600) != 0) {
        bb_err(err, errcap, "cannot chmod temporary file: %s",
               strerror(errno));
        goto fail;
    }
    if (bb_write_all(fd, data, len, err, errcap) != 0) {
        goto fail;
    }
    if (fsync(fd) != 0) {
        bb_err(err, errcap, "fsync failed: %s", strerror(errno));
        goto fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        bb_err(err, errcap, "close failed: %s", strerror(errno));
        goto fail;
    }
    fd = -1;
    if (rename(tmpl, path) != 0) {
        bb_err(err, errcap, "rename failed: %s", strerror(errno));
        goto fail;
    }
    /* Best-effort durability of the directory entry. */
    {
        char *dir;
        size_t dl = dirlen;
        if (dl == 0) {
            dir = strdup(".");
        } else if (dl == 1) {
            dir = strdup("/");
        } else {
            dir = (char *)malloc(dl);
            if (dir != NULL) {
                memcpy(dir, path, dl - 1);
                dir[dl - 1] = '\0';
            }
        }
        if (dir != NULL) {
            int dfd = open(dir, O_RDONLY);
            if (dfd >= 0) {
                (void)fsync(dfd);
                (void)close(dfd);
            }
            free(dir);
        }
    }
    rc = 0;
    free(tmpl);
    return rc;

fail:
    if (fd >= 0) {
        (void)close(fd);
    }
    (void)unlink(tmpl);
    free(tmpl);
    return -1;
}

int bb_write_file(const char *path, const bb_db *db, char *err, size_t errcap)
{
    bb_writer w;
    unsigned int ps;
    uint64_t root_pgid = 0;
    uint64_t txid;
    uint64_t total;
    uint64_t total_bytes;
    unsigned char *buf = NULL;
    const bb_bucket *stack[BB_MAX_DEPTH + 1];
    size_t i;
    int rc = -1;

    if (path == NULL || db == NULL) {
        return bb_err(err, errcap, "bb_write_file: invalid arguments");
    }
    ps = (db->page_size != 0) ? db->page_size : 4096u;
    if (ps < BB_MIN_PAGE_SIZE || ps > BB_MAX_PAGE_SIZE ||
        (ps % 1024u) != 0) {
        return bb_err(err, errcap, "invalid page size %u", ps);
    }
    if (db->txid > UINT64_MAX - 2) {
        return bb_err(err, errcap, "transaction id overflow");
    }
    memset(&w, 0, sizeof(w));
    w.ps = ps;
    w.next_pgid = 2;
    /**
     * bbolt reserves page 0 and page 1 for the two meta pages, so the first
     * data page is page 2 (this also matches bolt's allocation).
     */
    if (bb_build_bucket(&w, &db->root, stack, 0, &root_pgid, err, errcap) != 0) {
        goto done;
    }
    if (root_pgid < 2) {
        (void)bb_err(err, errcap, "internal error: no root page");
        goto done;
    }
    txid = (db->txid == 0) ? 2u : db->txid + 2u;
    total = w.next_pgid;
    if (total > (uint64_t)SIZE_MAX / (uint64_t)ps) {
        (void)bb_err(err, errcap, "database too large");
        goto done;
    }
    total_bytes = total * (uint64_t)ps;
    buf = (unsigned char *)calloc(1, (size_t)total_bytes);
    if (buf == NULL) {
        (void)bb_err(err, errcap, "out of memory");
        goto done;
    }
    /* bbolt places the meta whose txid is T on physical page T%2, so page 0
     * always carries an even txid and page 1 an odd one (bbolt's Tx.page()
     * asserts this header id). */
    bb_meta_write(buf + (size_t)(txid % 2u) * ps, ps, root_pgid,
                  db->root.sequence, total, txid);
    bb_meta_write(buf + (size_t)((txid - 1u) % 2u) * ps, ps, root_pgid,
                  db->root.sequence, total, txid - 1u);
    for (i = 0; i < w.npages; i++) {
        uint64_t off = w.pages[i].id * (uint64_t)ps;
        if (off + (uint64_t)w.pages[i].phys > total_bytes) {
            (void)bb_err(err, errcap, "internal error: page beyond file size");
            goto done;
        }
        memcpy(buf + (size_t)off, w.pages[i].data, w.pages[i].phys);
    }
    if (bb_write_atomic(path, buf, (size_t)total_bytes, err, errcap) != 0) {
        goto done;
    }
    rc = 0;
done:
    free(buf);
    bb_writer_clear(&w);
    return rc;
}

/* ------------------------------------------------------------- bbolt store
 *
 * The optional --store bbolt:PATH backend, in the same on-disk format as
 * TecharoHQ/anubis's `lib/store/bbolt`: one top-level bucket per key, and that
 * bucket holds "data" and "expiry" (an RFC3339Nano timestamp). Anubis's own
 * records live under `challenge:<id>`; this gate writes
 * `betteranusbis:challenge:<id>` and `betteranusbis:honeypot:<key>` so a file
 * that has been used by both does not mix two incompatible challenge records.
 * Everything else in the file is preserved, and buckets whose expiry has passed
 * are dropped, which is what upstream's hourly cleanup does.
 *
 * The codec is a whole-file reader/rewriter rather than bbolt's copy-on-write
 * page engine: the gate is a single writer, a flush already costs a file
 * rewrite in the text backend, and a rewritten file has no stale pages to
 * reclaim. The catch is that a real bbolt process must not have the file open
 * while this gate flushes; the bbolt backend is a single-writer backend here.
 */
static int store_bbolt;
static bb_db store_db;
static int store_db_loaded;
static long long store_db_txid;

static void json_escape_into(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)(in ? in : ""); *p && o + 7 < cap; p++) {
        switch (*p) {
        case '"': out[o++] = '\\'; out[o++] = '"'; break;
        case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
        case '\n': out[o++] = '\\'; out[o++] = 'n'; break;
        case '\r': out[o++] = '\\'; out[o++] = 'r'; break;
        case '\t': out[o++] = '\\'; out[o++] = 't'; break;
        default:
            if (*p < 0x20) {
                static const char *hex = "0123456789abcdef";
                out[o++] = '\\'; out[o++] = 'u'; out[o++] = '0'; out[o++] = '0';
                out[o++] = hex[*p >> 4]; out[o++] = hex[*p & 15];
            } else {
                out[o++] = (char)*p;
            }
        }
    }
    out[o] = 0;
}

static const char *json_field(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char pat[128];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

/* A pointer into the JSON for a value that is large and known to contain no
 * escapes (the tensor-v witness is hex). Avoids copying 100 KB twice. */
static int json_raw_span(const char *json, const char *key, const char **out,
                         size_t *len) {
    const char *p = json_field(json, key);
    const char *e;
    if (!p || *p != '"') return 0;
    p++;
    e = strchr(p, '"');
    if (!e) return 0;
    *out = p;
    *len = (size_t)(e - p);
    return 1;
}

static int json_get_str(const char *json, const char *key, char *out, size_t cap) {
    const char *p = json_field(json, key);
    if (!p || *p != '"') return 0;
    p++;
    size_t o = 0;
    while (*p && *p != '"' && o + 1 < cap) {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
            case 'n': out[o++] = '\n'; break;
            case 'r': out[o++] = '\r'; break;
            case 't': out[o++] = '\t'; break;
            case 'b': out[o++] = '\b'; break;
            case 'f': out[o++] = '\f'; break;
            case 'u': {
                /* our own writer only emits \u00XX; accept that form */
                unsigned hi = 0, lo = 0;
                if (sscanf(p + 1, "%1x%1x", &hi, &lo) == 2) {
                    out[o++] = (char)((hi << 4) | lo);
                    p += 2;
                }
                break;
            }
            default: out[o++] = *p; break;
            }
            p++;
        } else {
            out[o++] = *p++;
        }
    }
    out[o] = 0;
    return 1;
}

static long long json_get_ll(const char *json, const char *key, long long dflt) {
    const char *p = json_field(json, key);
    if (!p) return dflt;
    char *end = NULL;
    long long v = strtoll(p, &end, 10);
    return end == p ? dflt : v;
}

static int json_get_bool(const char *json, const char *key, int dflt) {
    const char *p = json_field(json, key);
    if (!p) return dflt;
    if (!strncmp(p, "true", 4)) return 1;
    if (!strncmp(p, "false", 5)) return 0;
    return dflt;
}

/* A timestamp bbolt's time.RFC3339Nano parser accepts. Millisecond input is
 * the resolution the challenge id already carries. */
static void format_rfc3339nano(long long ms, char *out, size_t cap) {
    time_t sec = (time_t)(ms / 1000);
    long frac = (long)(ms % 1000);
    if (frac < 0) { frac += 1000; sec -= 1; }
    struct tm tm;
    if (!gmtime_r(&sec, &tm)) { snprintf(out, cap, "1970-01-01T00:00:00Z"); return; }
    snprintf(out, cap, "%04d-%02d-%02dT%02d:%02d:%02d.%03ld000Z",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, frac);
}

static long long parse_rfc3339(const char *s) {
    int y, mo, d, h, mi, se;
    if (!s || sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d", &y, &mo, &d, &h, &mi, &se) != 6)
        return -1;
    /* Go's time.RFC3339Nano writes "Z" or a numeric offset (+01:00). Ignoring
     * the offset would make an expiry look up to a day off, which is exactly
     * the kind of bug that keeps a dead bucket alive forever. */
    long offset = 0;
    const char *p = s;
    while (*p && *p != 'T') p++;
    while (*p && *p != 'Z' && *p != '+' && *p != '-') p++;
    if (*p == '+' || *p == '-') {
        int oh = 0, om = 0;
        if (sscanf(p + 1, "%2d:%2d", &oh, &om) >= 1)
            offset = (long)(oh * 3600 + om * 60) * (*p == '-' ? -1 : 1);
    }
    struct tm tm;
    memset(&tm, 0, sizeof tm);
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = se;
    time_t t = timegm(&tm);
    return (long long)(t - offset) * 1000;
}

static bb_item *bb_find_item(bb_bucket *b, const char *key) {
    if (!b || !key) return NULL;
    size_t n = strlen(key);
    for (size_t i = 0; i < b->nitems; i++) {
        if (b->items[i].keylen == n && !memcmp(b->items[i].key, key, n))
            return &b->items[i];
    }
    return NULL;
}

static int bbolt_bucket_data(bb_item *bucket, unsigned char **data, size_t *len,
                             long long *expires_ms) {
    if (!bucket || !bucket->is_bucket || !bucket->child) return 0;
    bb_item *d = bb_find_item(bucket->child, "data");
    bb_item *e = bb_find_item(bucket->child, "expiry");
    if (!d) return 0;
    *data = d->value;
    *len = d->vallen;
    *expires_ms = -1;
    if (e && e->vallen) {
        char buf[64];
        size_t n = e->vallen < sizeof buf - 1 ? e->vallen : sizeof buf - 1;
        memcpy(buf, e->value, n);
        buf[n] = 0;
        *expires_ms = parse_rfc3339(buf);
    }
    return 1;
}

static void bbolt_load_state(void) {
    time_t now = time(NULL);
    long long nch = 0, nhp = 0;
    for (size_t i = 0; i < store_db.root.nitems; i++) {
        bb_item *it = &store_db.root.items[i];
        if (!it->is_bucket || !it->keylen) continue;
        const char *name = (const char *)it->key;
        if (!strncmp(name, "betteranusbis:challenge:", 24)) {
            unsigned char *data = NULL;
            size_t len = 0;
            long long expires = -1;
            if (!bbolt_bucket_data(it, &data, &len, &expires)) continue;
            if (expires > 0 && expires / 1000 < (long long)now) continue;
            char json[8192];
            size_t n = len < sizeof json - 1 ? len : sizeof json - 1;
            memcpy(json, data, n);
            json[n] = 0;
            char id[80] = "", rd[65] = "", algo[24] = "sha256", ref[256] = "";
            json_get_str(json, "id", id, sizeof id);
            if (!id[0]) snprintf(id, sizeof id, "%s", name + 24);
            if (!json_get_str(json, "randomData", rd, sizeof rd)) continue;
            json_get_str(json, "algorithm", algo, sizeof algo);
            json_get_str(json, "referer", ref, sizeof ref);
            int difficulty = (int)json_get_ll(json, "difficulty", 0);
            int spent = json_get_bool(json, "spent", 0);
            int css = json_get_bool(json, "cssSeen", 0);
            long long issued_ms = json_get_ll(json, "issuedMs", (long long)now * 1000);
            uint32_t h = 2166136261u;
            for (const char *q = id; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
            for (int probe = 0; probe < 32; probe++) {
                ch_entry *e = &ch_table[(h + (uint32_t)probe) % CH_BUCKETS];
                if (e->used && strcmp(e->id, id) != 0) continue;
                snprintf(e->id, sizeof e->id, "%s", id);
                snprintf(e->rd, sizeof e->rd, "%s", rd);
                snprintf(e->algorithm, sizeof e->algorithm, "%s", algo);
                snprintf(e->referer, sizeof e->referer, "%s", ref);
                e->difficulty = difficulty;
                e->spent = spent;
                e->css_seen = css;
                e->issued_ms = issued_ms;
                e->issued = (time_t)(issued_ms / 1000);
                e->used = 1;
                nch++;
                break;
            }
        } else if (!strncmp(name, "betteranusbis:honeypot:", 23)) {
            unsigned char *data = NULL;
            size_t len = 0;
            long long expires = -1;
            if (!bbolt_bucket_data(it, &data, &len, &expires)) continue;
            if (expires > 0 && expires / 1000 < (long long)now) continue;
            char json[512];
            size_t n = len < sizeof json - 1 ? len : sizeof json - 1;
            memcpy(json, data, n);
            json[n] = 0;
            unsigned long long key = strtoull(name + 23, NULL, 10);
            int count = (int)json_get_ll(json, "count", 0);
            long long last = json_get_ll(json, "last", (long long)now);
            if (count <= 0) continue;
            for (int i = 0; i < HP_BUCKETS; i++) {
                hp_entry *e = &hp_table[i];
                if (!e->used) {
                    e->key = key;
                    e->count = count;
                    e->last = (time_t)last;
                    e->used = 1;
                    nhp++;
                    break;
                }
                if (e->key == key) {
                    e->count = count;
                    e->last = (time_t)last;
                    nhp++;
                    break;
                }
            }
        }
    }
    if (nch || nhp)
        logmsg("store: loaded %lld challenge(s) and %lld network(s) from %s",
               nch, nhp, store_path);
}

/* A path with no writable parent would only fail five seconds later, once per
 * flush, in the log. Upstream's factory checks the directory at startup too. */
static int bbolt_check_writable(void) {
    char dir[1024];
    snprintf(dir, sizeof dir, "%s", store_path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        if (slash == dir) slash[1] = 0;
        else *slash = 0;
    } else {
        snprintf(dir, sizeof dir, ".");
    }
    if (access(dir, W_OK) != 0) {
        fprintf(stderr, "betterAnusbis: the bbolt store directory %s is not "
                        "writable: %s\n", dir, strerror(errno));
        return -1;
    }
    return 0;
}

static int bbolt_load_or_create(void) {
    char err[256] = "";
    if (bbolt_check_writable() != 0) return -1;
    memset(&store_db, 0, sizeof store_db);
    if (access(store_path, F_OK) == 0) {
        if (bb_read_file(store_path, &store_db, err, sizeof err) != 0) {
            fprintf(stderr, "betterAnusbis: cannot read the bbolt store %s: %s\n",
                    store_path, err[0] ? err : "invalid database");
            return -1;
        }
        store_db_txid = (long long)store_db.txid;
        store_db_loaded = 1;
        bbolt_load_state();
    } else {
        if (errno != ENOENT) {
            fprintf(stderr, "betterAnusbis: cannot stat %s: %s\n", store_path,
                    strerror(errno));
            return -1;
        }
        store_db.page_size = 4096;
        store_db_loaded = 1;
    }
    return 0;
}

static int bbolt_store_write(void) {
    if (!store_db_loaded) return -1;

    /* Drop expired foreign buckets the way upstream's cleanup does; keep the
     * rest byte for byte. */
    long long now_ms = (long long)time(NULL) * 1000;
    for (size_t i = store_db.root.nitems; i-- > 0; ) {
        bb_item *it = &store_db.root.items[i];
        if (!it->is_bucket || !it->keylen) continue;
        const char *name = (const char *)it->key;
        if (!strncmp(name, "betteranusbis:challenge:", 24) ||
            !strncmp(name, "betteranusbis:honeypot:", 23))
            bb_del_bucket(&store_db.root, it->key, it->keylen);
    }
    for (size_t i = store_db.root.nitems; i-- > 0; ) {
        bb_item *it = &store_db.root.items[i];
        if (!it->is_bucket || !it->keylen) continue;
        bb_item *expiry = it->child ? bb_find_item(it->child, "expiry") : NULL;
        if (!expiry || !expiry->vallen) continue;
        char buf[64];
        size_t n = expiry->vallen < sizeof buf - 1 ? expiry->vallen : sizeof buf - 1;
        memcpy(buf, expiry->value, n);
        buf[n] = 0;
        long long e = parse_rfc3339(buf);
        if (e > 0 && e < now_ms)
            bb_del_bucket(&store_db.root, it->key, it->keylen);
    }

    long long nch = 0, nhp = 0;
    pthread_mutex_lock(&ch_lock);
    for (int i = 0; i < CH_BUCKETS; i++) {
        ch_entry *e = &ch_table[i];
        if (!e->used) continue;
        long long expires = e->issued_ms + (long long)COOKIE_TTL * 1000;
        if (expires < now_ms) continue;
        char name[128], json[4096], esc_ref[2048], esc_rd[256], esc_algo[128];
        snprintf(name, sizeof name, "betteranusbis:challenge:%s", e->id);
        json_escape_into(e->referer, esc_ref, sizeof esc_ref);
        json_escape_into(e->rd, esc_rd, sizeof esc_rd);
        json_escape_into(e->algorithm, esc_algo, sizeof esc_algo);
        snprintf(json, sizeof json,
                 "{\"id\":\"%s\",\"randomData\":\"%s\",\"algorithm\":\"%s\","
                 "\"difficulty\":%d,\"spent\":%s,\"issuedMs\":%lld,"
                 "\"cssSeen\":%s,\"referer\":\"%s\"}",
                 e->id, esc_rd, esc_algo, e->difficulty,
                 e->spent ? "true" : "false", e->issued_ms,
                 e->css_seen ? "true" : "false", esc_ref);
        bb_bucket *b = bb_find_bucket(&store_db, name);
        if (!b) b = bb_add_bucket(&store_db, name);
        if (!b) continue;
        char expiry[64];
        format_rfc3339nano(expires, expiry, sizeof expiry);
        bb_set(b, "data", 4, json, strlen(json));
        bb_set(b, "expiry", 6, expiry, strlen(expiry));
        nch++;
    }
    pthread_mutex_unlock(&ch_lock);

    pthread_mutex_lock(&hp_lock);
    for (int i = 0; i < HP_BUCKETS; i++) {
        hp_entry *e = &hp_table[i];
        if (!e->used) continue;
        if ((long long)e->last + HP_WINDOW < (long long)time(NULL)) continue;
        char name[64], json[160], expiry[64];
        snprintf(name, sizeof name, "betteranusbis:honeypot:%llu",
                 (unsigned long long)e->key);
        snprintf(json, sizeof json, "{\"count\":%d,\"last\":%lld}", e->count,
                 (long long)e->last);
        format_rfc3339nano(((long long)e->last + HP_WINDOW) * 1000, expiry,
                           sizeof expiry);
        bb_bucket *b = bb_find_bucket(&store_db, name);
        if (!b) b = bb_add_bucket(&store_db, name);
        if (!b) continue;
        bb_set(b, "data", 4, json, strlen(json));
        bb_set(b, "expiry", 6, expiry, strlen(expiry));
        nhp++;
    }
    pthread_mutex_unlock(&hp_lock);

    store_db.txid = (unsigned long long)(store_db_txid + 2);
    char err[256] = "";
    if (bb_write_file(store_path, &store_db, err, sizeof err) != 0) {
        logmsg("store: cannot write bbolt %s: %s", store_path,
               err[0] ? err : "unknown error");
        return -1;
    }
    store_db_txid += 2;
    if (cfg.verbose)
        logmsg("store: wrote %lld challenges and %lld networks to %s", nch, nhp,
               store_path);
    return 0;
}

/*
 * valkey_io.h - small standalone RESP2 client for Redis / Valkey.
 *
 * C17, libc + pthread + OpenSSL only.  One client owns one connection;
 * the connection is shared safely between threads by an internal mutex.
 *
 * Every function that can fail takes (char *err, size_t errcap) and writes
 * a human readable message there.  Return values: 0 success / -1 error,
 * except vk_get which returns 1 (found), 0 (nil) or -1 (error) and
 * vk_scan which returns 0 / -1.
 */
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Supported URLs:
 *   redis://[user][:pass@]host:port[/db][?db=N]
 *   rediss://[user][:pass@]host:port[/db][?db=N][&insecure=1]
 *   unix:///absolute/path/to.sock[?db=N]
 *   host:port            (bare, plain TCP)
 * Default port 6379, default db 0.  rediss: system CA store, hostname/IP
 * verification and SNI for names; ?insecure=1 disables verification.
 */
vk_client *vk_connect(const char *url, char *err, size_t errcap);
void vk_close(vk_client *c);

int vk_ping(vk_client *c, char *err, size_t errcap);

/* 1 = found (*val malloc'd, NUL terminated, non-NULL even for an empty
 * value), 0 = key does not exist (val untouched), -1 = error. */
int vk_get(vk_client *c, const char *key, unsigned char **val, size_t *vallen,
           char *err, size_t errcap);

/* SET key val EX ttl; ttl_sec <= 0 performs a plain SET. */
int vk_set_ex(vk_client *c, const char *key, const unsigned char *val,
              size_t vallen, long long ttl_sec, char *err, size_t errcap);

int vk_del(vk_client *c, const char *key, char *err, size_t errcap);

/* One SCAN call: SCAN cursor [MATCH match] [COUNT count].
 * cursor_out is malloc'd; keys is a malloc'd array of malloc'd NUL
 * terminated strings, release with vk_free_keys(keys, nkeys). */
int vk_scan(vk_client *c, const char *cursor_in, const char *match, long count,
            char **cursor_out, char ***keys, size_t *nkeys, char *err,
            size_t errcap);

void vk_free_keys(char **keys, size_t nkeys);


/*
 * valkey_io.c - small standalone RESP2 client for Redis / Valkey.
 *
 * Scope: one connection per client, mutex protected, AUTH/SELECT/PING on
 * connect, reconnect + one retry on I/O errors, RESP2 parser with bounds
 * checks, optional TLS (OpenSSL) and unix sockets.
 */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define VK_LINE_MAX 65536
#define VK_BULK_MAX (512ULL * 1024ULL * 1024ULL)
#define VK_ARRAY_MAX (8ULL * 1024ULL * 1024ULL)
#define VK_MAX_DEPTH 16
#define VK_CONNECT_TIMEOUT_MS 3000
#define VK_IO_TIMEOUT_MS 5000
#define VK_RBUF_SIZE 65536

struct vk_client {
    pthread_mutex_t lock;
    int fd;
    int tls;
    int insecure;
    int alive;
    int use_unix;
    int port;
    int db;
    int connect_timeout_ms;
    int io_timeout_ms;
    char *host; /* hostname or unix socket path */
    char *user; /* NULL when no userinfo was supplied */
    char *pass; /* NULL when no userinfo was supplied */
    SSL_CTX *ctx;
    SSL *ssl;
    unsigned char *rbuf;
    size_t rcap;
    size_t rlen;
    size_t rpos;
    int io_err;
    char io_msg[256];
};

static int vk__connect_internal(vk_client *c, char *err, size_t errcap);

/* ------------------------------------------------------------------ */
/* small helpers                                                      */
/* ------------------------------------------------------------------ */

static void set_err(char *err, size_t errcap, const char *fmt, ...)
{
    va_list ap;

    if (err == NULL || errcap == 0) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(err, errcap, fmt, ap);
    va_end(ap);
}

static long long now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (long long)ts.tv_sec * 1000LL + (long long)(ts.tv_nsec / 1000000L);
}

static int hex_value(int ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

/* Percent-decode a substring; unknown escapes are kept literally. */
static char *pct_decode(const char *s, size_t n)
{
    char *out;
    size_t i;
    size_t o = 0;

    out = (char *)malloc(n + 1);
    if (out == NULL) {
        return NULL;
    }
    for (i = 0; i < n; i++) {
        if (s[i] == '%' && i + 2 < n) {
            int hi = hex_value((unsigned char)s[i + 1]);
            int lo = hex_value((unsigned char)s[i + 2]);

            if (hi >= 0 && lo >= 0) {
                out[o++] = (char)(hi * 16 + lo);
                i += 2;
                continue;
            }
        }
        out[o++] = s[i];
    }
    out[o] = '\0';
    return out;
}

static char *dup_range(const char *s, size_t n)
{
    char *out = (char *)malloc(n + 1);

    if (out == NULL) {
        return NULL;
    }
    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

static int parse_u64(const char *s, size_t n, unsigned long long maxv,
                     unsigned long long *out)
{
    unsigned long long v = 0;
    size_t i;

    if (n == 0) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        unsigned int d;

        if (s[i] < '0' || s[i] > '9') {
            return -1;
        }
        d = (unsigned int)(s[i] - '0');
        if (v > (maxv - d) / 10ULL) {
            return -1;
        }
        v = v * 10ULL + d;
    }
    *out = v;
    return 0;
}

static int parse_i64(const char *s, size_t n, long long *out)
{
    int neg = 0;
    size_t i = 0;
    unsigned long long v = 0;
    unsigned long long limit;

    if (n == 0) {
        return -1;
    }
    if (s[0] == '-') {
        neg = 1;
        i = 1;
        if (n == 1) {
            return -1;
        }
    }
    limit = neg ? (unsigned long long)LLONG_MAX + 1ULL
                : (unsigned long long)LLONG_MAX;
    for (; i < n; i++) {
        unsigned int d;

        if (s[i] < '0' || s[i] > '9') {
            return -1;
        }
        d = (unsigned int)(s[i] - '0');
        if (v > (limit - d) / 10ULL) {
            return -1;
        }
        v = v * 10ULL + d;
    }
    if (neg) {
        *out = (v == (unsigned long long)LLONG_MAX + 1ULL)
                   ? LLONG_MIN
                   : -(long long)v;
    } else {
        *out = (long long)v;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* URL parsing                                                        */
/* ------------------------------------------------------------------ */

struct url_parts {
    int use_unix;
    int tls;
    int insecure;
    int port;
    int db;
    char *host;
    char *user;
    char *pass;
};

static void url_parts_free(struct url_parts *u)
{
    free(u->host);
    free(u->user);
    free(u->pass);
    u->host = NULL;
    u->user = NULL;
    u->pass = NULL;
}

static int query_lookup_db(const char *q, size_t qn, int *db)
{
    size_t i = 0;

    while (i < qn) {
        size_t start = i;
        size_t eq;
        size_t end;

        while (i < qn && q[i] != '&') {
            i++;
        }
        end = i;
        if (i < qn) {
            i++; /* skip '&' */
        }
        eq = start;
        while (eq < end && q[eq] != '=') {
            eq++;
        }
        if (eq == end) {
            continue;
        }
        if ((eq - start) == 2 && strncmp(q + start, "db", 2) == 0) {
            unsigned long long v;

            if (parse_u64(q + eq + 1, end - (eq + 1), 1000000ULL, &v) != 0) {
                return -1;
            }
            *db = (int)v;
        }
    }
    return 0;
}

static int query_insecure(const char *q, size_t qn)
{
    size_t i = 0;

    while (i < qn) {
        size_t start = i;
        size_t eq;
        size_t end;

        while (i < qn && q[i] != '&') {
            i++;
        }
        end = i;
        if (i < qn) {
            i++;
        }
        eq = start;
        while (eq < end && q[eq] != '=') {
            eq++;
        }
        if (eq == end || (eq - start) != 8) {
            continue;
        }
        if (strncasecmp(q + start, "insecure", 8) != 0) {
            continue;
        }
        if ((end - (eq + 1)) == 1 && q[eq + 1] == '1') {
            return 1;
        }
        if ((end - (eq + 1)) == 4 &&
            strncasecmp(q + eq + 1, "true", 4) == 0) {
            return 1;
        }
        if ((end - (eq + 1)) == 3 &&
            strncasecmp(q + eq + 1, "yes", 3) == 0) {
            return 1;
        }
    }
    return 0;
}

static int url_parse(const char *url, struct url_parts *u, char *err,
                     size_t errcap)
{
    const char *p = url;
    const char *qmark;
    const char *query = NULL;
    size_t query_len = 0;
    const char *authority;
    size_t authority_len;
    const char *path = NULL;
    size_t path_len = 0;
    const char *at;
    const char *hostport;
    size_t hostport_len;

    memset(u, 0, sizeof(*u));
    u->port = 6379;

    if (url == NULL || url[0] == '\0') {
        set_err(err, errcap, "empty URL");
        return -1;
    }

    if (strncasecmp(p, "unix://", 7) == 0) {
        u->use_unix = 1;
        p += 7;
    } else if (strncasecmp(p, "redis://", 8) == 0) {
        p += 8;
    } else if (strncasecmp(p, "rediss://", 9) == 0) {
        u->tls = 1;
        p += 9;
    } else if (strstr(p, "://") != NULL) {
        set_err(err, errcap, "unsupported URL scheme in \"%s\"", url);
        return -1;
    }

    qmark = strchr(p, '?');
    if (qmark != NULL) {
        query = qmark + 1;
        query_len = strlen(query);
    }

    if (u->use_unix) {
        size_t path_end = (qmark != NULL) ? (size_t)(qmark - p) : strlen(p);

        if (path_end == 0 || p[0] != '/') {
            set_err(err, errcap,
                    "unix URL needs an absolute socket path: %s", url);
            return -1;
        }
        u->host = dup_range(p, path_end);
        if (u->host == NULL) {
            set_err(err, errcap, "out of memory");
            return -1;
        }
        if (query != NULL && query_lookup_db(query, query_len, &u->db) != 0) {
            set_err(err, errcap, "invalid db in URL query: %s", url);
            url_parts_free(u);
            return -1;
        }
        return 0;
    }

    /* authority ends at the first '/' or at the query. */
    authority = p;
    {
        const char *slash = strchr(p, '/');

        if (slash != NULL && (qmark == NULL || slash < qmark)) {
            authority_len = (size_t)(slash - p);
            path = slash;
            path_len = (qmark != NULL) ? (size_t)(qmark - slash)
                                       : strlen(slash);
        } else if (qmark != NULL) {
            authority_len = (size_t)(qmark - p);
        } else {
            authority_len = strlen(p);
        }
    }

    at = NULL;
    {
        size_t i;

        for (i = 0; i < authority_len; i++) {
            if (authority[i] == '@') {
                at = authority + i;
            }
        }
    }
    if (at != NULL) {
        const char *ui = authority;
        size_t ui_len = (size_t)(at - authority);
        const char *colon = memchr(ui, ':', ui_len);

        if (colon != NULL) {
            u->user = pct_decode(ui, (size_t)(colon - ui));
            u->pass = pct_decode(colon + 1, ui_len - (size_t)(colon - ui) - 1);
        } else {
            u->pass = pct_decode(ui, ui_len);
        }
        if ((u->user != NULL && u->user[0] == '\0')) {
            free(u->user);
            u->user = NULL;
        }
        if (u->pass == NULL) {
            set_err(err, errcap, "out of memory");
            url_parts_free(u);
            return -1;
        }
        hostport = at + 1;
        hostport_len = authority_len - ui_len - 1;
    } else {
        hostport = authority;
        hostport_len = authority_len;
    }

    if (hostport_len == 0) {
        set_err(err, errcap, "missing host in URL: %s", url);
        url_parts_free(u);
        return -1;
    }

    if (hostport[0] == '[') {
        const char *close = memchr(hostport, ']', hostport_len);

        if (close == NULL) {
            set_err(err, errcap, "malformed IPv6 host in URL: %s", url);
            url_parts_free(u);
            return -1;
        }
        u->host = dup_range(hostport + 1, (size_t)(close - hostport) - 1);
        if (u->host == NULL) {
            set_err(err, errcap, "out of memory");
            url_parts_free(u);
            return -1;
        }
        if ((size_t)(close - hostport) + 1 < hostport_len) {
            const char *cport = close + 1;
            size_t clen = hostport_len - (size_t)(close - hostport) - 1;
            unsigned long long v;

            if (cport[0] != ':' ||
                parse_u64(cport + 1, clen - 1, 65535ULL, &v) != 0 ||
                v == 0) {
                set_err(err, errcap, "invalid port in URL: %s", url);
                url_parts_free(u);
                return -1;
            }
            u->port = (int)v;
        }
    } else {
        const char *colon = NULL;
        size_t i;

        for (i = 0; i < hostport_len; i++) {
            if (hostport[i] == ':') {
                colon = hostport + i;
            }
        }
        if (colon != NULL) {
            unsigned long long v;

            if (parse_u64(colon + 1,
                          hostport_len - (size_t)(colon - hostport) - 1,
                          65535ULL, &v) != 0 ||
                v == 0) {
                set_err(err, errcap, "invalid port in URL: %s", url);
                url_parts_free(u);
                return -1;
            }
            u->port = (int)v;
            u->host = dup_range(hostport, (size_t)(colon - hostport));
        } else {
            u->host = dup_range(hostport, hostport_len);
        }
        if (u->host == NULL) {
            set_err(err, errcap, "out of memory");
            url_parts_free(u);
            return -1;
        }
        if (u->host[0] == '\0') {
            set_err(err, errcap, "missing host in URL: %s", url);
            url_parts_free(u);
            return -1;
        }
    }

    /* path may be "/3" (db) and the query may override it. */
    if (path != NULL && path_len > 1) {
        unsigned long long v;

        if (parse_u64(path + 1, path_len - 1, 1000000ULL, &v) == 0) {
            u->db = (int)v;
        } else {
            set_err(err, errcap, "invalid db in URL path: %s", url);
            url_parts_free(u);
            return -1;
        }
    }
    if (query != NULL) {
        if (query_lookup_db(query, query_len, &u->db) != 0) {
            set_err(err, errcap, "invalid db in URL query: %s", url);
            url_parts_free(u);
            return -1;
        }
        if (query_insecure(query, query_len) != 0) {
            u->insecure = 1;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* growable command buffer                                            */
/* ------------------------------------------------------------------ */

struct sbuf {
    char *data;
    size_t len;
    size_t cap;
};

static void sbuf_free(struct sbuf *sb)
{
    free(sb->data);
    sb->data = NULL;
    sb->len = 0;
    sb->cap = 0;
}

static int sbuf_reserve(struct sbuf *sb, size_t extra)
{
    size_t need;
    size_t cap;
    char *p;

    if (extra > SIZE_MAX - sb->len) {
        return -1;
    }
    need = sb->len + extra;
    if (need <= sb->cap) {
        return 0;
    }
    cap = (sb->cap == 0) ? 256 : sb->cap;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) {
            cap = need;
            break;
        }
        cap *= 2;
    }
    p = (char *)realloc(sb->data, cap);
    if (p == NULL) {
        return -1;
    }
    sb->data = p;
    sb->cap = cap;
    return 0;
}

static int sbuf_append(struct sbuf *sb, const void *p, size_t n)
{
    if (n == 0) {
        return 0;
    }
    if (sbuf_reserve(sb, n) != 0) {
        return -1;
    }
    memcpy(sb->data + sb->len, p, n);
    sb->len += n;
    return 0;
}

typedef struct {
    const void *p;
    size_t len;
} vk_arg;

static int sbuf_bulk(struct sbuf *sb, const void *p, size_t n)
{
    char hdr[64];
    int hl;

    hl = snprintf(hdr, sizeof(hdr), "$%zu\r\n", n);
    if (hl < 0 || (size_t)hl >= sizeof(hdr)) {
        return -1;
    }
    if (sbuf_append(sb, hdr, (size_t)hl) != 0) {
        return -1;
    }
    if (sbuf_append(sb, p, n) != 0) {
        return -1;
    }
    return sbuf_append(sb, "\r\n", 2);
}

static int build_command(struct sbuf *sb, const vk_arg *args, size_t nargs,
                         char *err, size_t errcap)
{
    char hdr[64];
    int hl;
    size_t i;

    sb->data = NULL;
    sb->len = 0;
    sb->cap = 0;

    hl = snprintf(hdr, sizeof(hdr), "*%zu\r\n", nargs);
    if (hl < 0 || (size_t)hl >= sizeof(hdr) ||
        sbuf_append(sb, hdr, (size_t)hl) != 0) {
        set_err(err, errcap, "out of memory building command");
        sbuf_free(sb);
        return -1;
    }
    for (i = 0; i < nargs; i++) {
        if (sbuf_bulk(sb, args[i].p, args[i].len) != 0) {
            set_err(err, errcap, "out of memory building command");
            sbuf_free(sb);
            return -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* reply representation and parser                                    */
/* ------------------------------------------------------------------ */

enum vk_rkind {
    VK_R_STRING = 1,
    VK_R_ERROR,
    VK_R_INT,
    VK_R_NIL,
    VK_R_ARRAY
};

typedef struct vk_reply {
    int kind;
    char *str; /* STRING / ERROR payload */
    size_t len;
    long long ival;
    struct vk_reply **elems;
    size_t nelems;
} vk_reply;

static void reply_free(vk_reply *r)
{
    size_t i;

    if (r == NULL) {
        return;
    }
    if (r->elems != NULL) {
        for (i = 0; i < r->nelems; i++) {
            reply_free(r->elems[i]);
        }
        free(r->elems);
    }
    free(r->str);
    free(r);
}

/* ------------------------------------------------------------------ */
/* socket setup / TLS                                                 */
/* ------------------------------------------------------------------ */

static void close_socket(vk_client *c)
{
    if (c->ssl != NULL) {
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    c->alive = 0;
    c->rlen = 0;
    c->rpos = 0;
    c->io_err = 0;
}

static void set_fd_timeouts(int fd, int ms)
{
    struct timeval tv;

    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* 0 ok, -1 timeout (err set), -2 other failure (errno set, err set) */
static int wait_connect(int fd, int timeout_ms, const char *what, char *err,
                        size_t errcap)
{
    struct pollfd pfd;
    int soerr = 0;
    socklen_t slen = sizeof(soerr);

    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    for (;;) {
        int pr = poll(&pfd, 1, timeout_ms);

        if (pr > 0) {
            break;
        }
        if (pr == 0) {
            set_err(err, errcap, "%s timed out after %d ms", what, timeout_ms);
            return -1;
        }
        if (errno == EINTR) {
            continue;
        }
        set_err(err, errcap, "%s: poll failed: %s", what, strerror(errno));
        return -2;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0) {
        set_err(err, errcap, "%s: getsockopt(SO_ERROR) failed: %s", what,
                strerror(errno));
        return -2;
    }
    if (soerr != 0) {
        errno = soerr;
        set_err(err, errcap, "%s failed: %s", what, strerror(soerr));
        return -2;
    }
    return 0;
}

static int tcp_open(vk_client *c, char *err, size_t errcap)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    char portstr[16];
    int fd = -1;
    int last_errno = 0;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (snprintf(portstr, sizeof(portstr), "%d", c->port) >=
        (int)sizeof(portstr)) {
        set_err(err, errcap, "invalid port");
        return -1;
    }
    rc = getaddrinfo(c->host, portstr, &hints, &res);
    if (rc != 0) {
        set_err(err, errcap, "cannot resolve \"%s\": %s", c->host,
                gai_strerror(rc));
        return -1;
    }

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        int flags;
        int r;

        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }
        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            last_errno = errno;
            close(fd);
            fd = -1;
            continue;
        }
        r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r != 0 && errno != EINPROGRESS) {
            last_errno = errno;
            close(fd);
            fd = -1;
            continue;
        }
        if (r != 0) {
            int wr = wait_connect(fd, c->connect_timeout_ms, "connect", err,
                                  errcap);

            if (wr == -1) {
                close(fd);
                freeaddrinfo(res);
                return -1;
            }
            if (wr == -2) {
                last_errno = errno;
                close(fd);
                fd = -1;
                continue;
            }
        }
        break;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        if (last_errno == 0) {
            last_errno = EIO;
        }
        set_err(err, errcap, "cannot connect to %s:%d: %s", c->host, c->port,
                strerror(last_errno));
        return -1;
    }

    {
        int flags = fcntl(fd, F_GETFL, 0);

        if (flags >= 0) {
            (void)fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        }
    }
    set_fd_timeouts(fd, c->io_timeout_ms);
    {
        int one = 1;

        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    c->fd = fd;
    return 0;
}

static int unix_open(vk_client *c, char *err, size_t errcap)
{
    struct sockaddr_un sa;
    size_t plen;
    int fd;
    int flags;
    int r;

    plen = strlen(c->host);
    if (plen >= sizeof(sa.sun_path)) {
        set_err(err, errcap, "unix socket path is too long (%zu bytes)", plen);
        return -1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    memcpy(sa.sun_path, c->host, plen + 1);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        set_err(err, errcap, "socket(AF_UNIX) failed: %s", strerror(errno));
        return -1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        set_err(err, errcap, "fcntl failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (r != 0 && errno != EINPROGRESS) {
        set_err(err, errcap, "cannot connect to unix socket %s: %s", c->host,
                strerror(errno));
        close(fd);
        return -1;
    }
    if (r != 0) {
        int wr = wait_connect(fd, c->connect_timeout_ms, "unix connect", err,
                              errcap);

        if (wr != 0) {
            close(fd);
            return -1;
        }
    }
    {
        int fl = fcntl(fd, F_GETFL, 0);

        if (fl >= 0) {
            (void)fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
        }
    }
    set_fd_timeouts(fd, c->io_timeout_ms);
    c->fd = fd;
    return 0;
}

static void tls_last_error(vk_client *c, const char *what, char *err,
                           size_t errcap)
{
    unsigned long e = ERR_get_error();
    char ebuf[256];
    long vr;

    if (e != 0) {
        ERR_error_string_n(e, ebuf, sizeof(ebuf));
    } else {
        snprintf(ebuf, sizeof(ebuf), "no OpenSSL error queued");
    }
    while (ERR_get_error() != 0) {
        /* drain the rest of the queue */
    }
    vr = SSL_get_verify_result(c->ssl);
    if (vr != X509_V_OK) {
        set_err(err, errcap, "%s: %s (certificate verify: %s)", what, ebuf,
                X509_verify_cert_error_string(vr));
        snprintf(c->io_msg, sizeof(c->io_msg),
                 "TLS certificate verification failed: %s",
                 X509_verify_cert_error_string(vr));
    } else {
        set_err(err, errcap, "%s: %s", what, ebuf);
        snprintf(c->io_msg, sizeof(c->io_msg), "%.96s: %.120s", what,
                 ebuf);
    }
}

static int tls_start(vk_client *c, char *err, size_t errcap)
{
    int is_ip;
    unsigned char addr[16];
    long long deadline;

    if (c->ctx == NULL) {
        c->ctx = SSL_CTX_new(TLS_client_method());
        if (c->ctx == NULL) {
            set_err(err, errcap, "SSL_CTX_new failed");
            return -1;
        }
        if (SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION) != 1) {
            set_err(err, errcap, "cannot require TLS >= 1.2");
            return -1;
        }
        if (c->insecure) {
            SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, NULL);
        } else {
            SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
            if (SSL_CTX_set_default_verify_paths(c->ctx) != 1) {
                set_err(err, errcap, "cannot load system CA store");
                return -1;
            }
        }
    }

    c->ssl = SSL_new(c->ctx);
    if (c->ssl == NULL) {
        set_err(err, errcap, "SSL_new failed");
        return -1;
    }
    if (SSL_set_fd(c->ssl, c->fd) != 1) {
        tls_last_error(c, "SSL_set_fd failed", err, errcap);
        SSL_free(c->ssl);
        c->ssl = NULL;
        return -1;
    }

    is_ip = (inet_pton(AF_INET, c->host, addr) == 1) ||
            (inet_pton(AF_INET6, c->host, addr) == 1);
    if (!is_ip) {
        if (SSL_set_tlsext_host_name(c->ssl, c->host) != 1) {
            tls_last_error(c, "cannot set TLS SNI", err, errcap);
            SSL_free(c->ssl);
            c->ssl = NULL;
            return -1;
        }
        if (SSL_set1_host(c->ssl, c->host) != 1) {
            tls_last_error(c, "cannot set TLS hostname check", err, errcap);
            SSL_free(c->ssl);
            c->ssl = NULL;
            return -1;
        }
    } else {
        X509_VERIFY_PARAM *param = SSL_get0_param(c->ssl);

        if (param == NULL ||
            X509_VERIFY_PARAM_set1_ip_asc(param, c->host) != 1) {
            set_err(err, errcap, "cannot set TLS IP check for %s", c->host);
            SSL_free(c->ssl);
            c->ssl = NULL;
            return -1;
        }
    }

    SSL_set_connect_state(c->ssl);
    deadline = now_ms() + VK_IO_TIMEOUT_MS;
    for (;;) {
        int r;

        ERR_clear_error();
        r = SSL_connect(c->ssl);
        if (r == 1) {
            return 0;
        }
        {
            int e = SSL_get_error(c->ssl, r);

            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                if (now_ms() >= deadline) {
                    set_err(err, errcap,
                            "TLS handshake with %s timed out after %d ms",
                            c->host, VK_IO_TIMEOUT_MS);
                    SSL_free(c->ssl);
                    c->ssl = NULL;
                    return -1;
                }
                continue;
            }
            if (e == SSL_ERROR_SYSCALL && errno == EINTR) {
                continue;
            }
            if (e == SSL_ERROR_SYSCALL &&
                (errno == EAGAIN || errno == EWOULDBLOCK)) {
                set_err(err, errcap, "TLS handshake timed out");
                SSL_free(c->ssl);
                c->ssl = NULL;
                return -1;
            }
        }
        tls_last_error(c, "TLS handshake failed", err, errcap);
        SSL_free(c->ssl);
        c->ssl = NULL;
        return -1;
    }
}

static ssize_t tls_read_some(vk_client *c, char *err, size_t errcap)
{
    long long deadline = now_ms() + c->io_timeout_ms;

    for (;;) {
        int cap;
        int n;
        int e;

        ERR_clear_error();
        cap = (c->rcap > (size_t)INT_MAX) ? INT_MAX : (int)c->rcap;
        n = SSL_read(c->ssl, c->rbuf, cap);
        if (n > 0) {
            return (ssize_t)n;
        }
        e = SSL_get_error(c->ssl, n);
        if (e == SSL_ERROR_ZERO_RETURN) {
            return 0;
        }
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            if (now_ms() >= deadline) {
                set_err(err, errcap, "TLS read timed out after %d ms",
                        c->io_timeout_ms);
                snprintf(c->io_msg, sizeof(c->io_msg),
                         "TLS read timed out after %d ms", c->io_timeout_ms);
                return -1;
            }
            continue;
        }
        if (e == SSL_ERROR_SYSCALL && errno == EINTR) {
            continue;
        }
        if (e == SSL_ERROR_SYSCALL &&
            (errno == EAGAIN || errno == EWOULDBLOCK)) {
            set_err(err, errcap, "TLS read timed out after %d ms",
                    c->io_timeout_ms);
            snprintf(c->io_msg, sizeof(c->io_msg),
                     "TLS read timed out after %d ms", c->io_timeout_ms);
            return -1;
        }
        tls_last_error(c, "TLS read failed", err, errcap);
        return -1;
    }
}

static int io_send_all(vk_client *c, const void *buf, size_t len, char *err,
                       size_t errcap)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t off = 0;
    long long deadline = now_ms() + c->io_timeout_ms;

    if (c->ssl != NULL) {
        while (off < len) {
            int chunk = (len - off > (size_t)INT_MAX)
                            ? INT_MAX
                            : (int)(len - off);
            int n;
            int e;

            ERR_clear_error();
            n = SSL_write(c->ssl, p + off, chunk);
            if (n > 0) {
                off += (size_t)n;
                continue;
            }
            e = SSL_get_error(c->ssl, n);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                if (now_ms() >= deadline) {
                    set_err(err, errcap, "TLS write timed out after %d ms",
                            c->io_timeout_ms);
                    snprintf(c->io_msg, sizeof(c->io_msg),
                             "TLS write timed out after %d ms",
                             c->io_timeout_ms);
                    return -1;
                }
                continue;
            }
            if (e == SSL_ERROR_SYSCALL && errno == EINTR) {
                continue;
            }
            tls_last_error(c, "TLS write failed", err, errcap);
            return -1;
        }
        return 0;
    }

    while (off < len) {
        ssize_t n = send(c->fd, p + off, len - off, MSG_NOSIGNAL);

        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        set_err(err, errcap, "write failed: %s", strerror(errno));
        snprintf(c->io_msg, sizeof(c->io_msg), "write failed: %s",
                 strerror(errno));
        return -1;
    }
    return 0;
}

static int rb_fill(vk_client *c, char *err, size_t errcap)
{
    if (c->rpos < c->rlen) {
        return 0;
    }
    for (;;) {
        ssize_t n;

        if (c->ssl != NULL) {
            n = tls_read_some(c, err, errcap);
            if (n < 0) {
                c->io_err = 1;
                return -1;
            }
        } else {
            n = recv(c->fd, c->rbuf, c->rcap, 0);
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0) {
                set_err(err, errcap,
                        "read failed: %s (timeout %d ms)", strerror(errno),
                        c->io_timeout_ms);
                snprintf(c->io_msg, sizeof(c->io_msg), "read failed: %s",
                         strerror(errno));
                c->io_err = 1;
                return -1;
            }
        }
        if (n == 0) {
            set_err(err, errcap, "connection closed by server");
            snprintf(c->io_msg, sizeof(c->io_msg),
                     "connection closed by server");
            c->io_err = 1;
            return -1;
        }
        c->rlen = (size_t)n;
        c->rpos = 0;
        return 0;
    }
}

static int rb_read_line(vk_client *c, char *out, size_t outcap, size_t *outlen,
                        char *err, size_t errcap)
{
    size_t n = 0;

    for (;;) {
        unsigned char ch;

        if (c->rpos >= c->rlen) {
            if (rb_fill(c, err, errcap) != 0) {
                return -1;
            }
        }
        ch = c->rbuf[c->rpos++];
        if (ch == '\r') {
            unsigned char ch2;

            if (c->rpos >= c->rlen) {
                if (rb_fill(c, err, errcap) != 0) {
                    return -1;
                }
            }
            ch2 = c->rbuf[c->rpos++];
            if (ch2 != '\n') {
                set_err(err, errcap, "protocol error: expected LF after CR");
                return -1;
            }
            if (n >= outcap) {
                set_err(err, errcap, "protocol error: reply line too long");
                return -1;
            }
            out[n] = '\0';
            *outlen = n;
            return 0;
        }
        if (ch == '\n') {
            set_err(err, errcap, "protocol error: unexpected LF in reply");
            return -1;
        }
        if (n + 1 >= outcap) {
            set_err(err, errcap,
                    "protocol error: reply line exceeds %zu bytes", outcap);
            return -1;
        }
        out[n++] = (char)ch;
    }
}

static int rb_read_exact(vk_client *c, unsigned char *dst, size_t len,
                         char *err, size_t errcap)
{
    while (len > 0) {
        size_t avail;
        size_t take;

        if (c->rpos >= c->rlen) {
            if (rb_fill(c, err, errcap) != 0) {
                return -1;
            }
        }
        avail = c->rlen - c->rpos;
        take = (avail < len) ? avail : len;
        memcpy(dst, c->rbuf + c->rpos, take);
        c->rpos += take;
        dst += take;
        len -= take;
    }
    return 0;
}

static vk_reply *read_reply(vk_client *c, int depth, char *err, size_t errcap)
{
    char line[VK_LINE_MAX];
    size_t n = 0;
    vk_reply *r;

    if (depth > VK_MAX_DEPTH) {
        set_err(err, errcap,
                "protocol error: reply nesting deeper than %d levels",
                VK_MAX_DEPTH);
        return NULL;
    }
    if (rb_read_line(c, line, sizeof(line), &n, err, errcap) != 0) {
        return NULL;
    }
    if (n == 0) {
        set_err(err, errcap, "protocol error: empty reply line");
        return NULL;
    }

    r = (vk_reply *)calloc(1, sizeof(*r));
    if (r == NULL) {
        set_err(err, errcap, "out of memory");
        return NULL;
    }

    switch (line[0]) {
    case '+':
        r->kind = VK_R_STRING;
        r->str = dup_range(line + 1, n - 1);
        if (r->str == NULL) {
            set_err(err, errcap, "out of memory");
            reply_free(r);
            return NULL;
        }
        r->len = n - 1;
        break;
    case '-':
        r->kind = VK_R_ERROR;
        r->str = dup_range(line + 1, n - 1);
        if (r->str == NULL) {
            set_err(err, errcap, "out of memory");
            reply_free(r);
            return NULL;
        }
        r->len = n - 1;
        break;
    case ':':
        if (parse_i64(line + 1, n - 1, &r->ival) != 0) {
            set_err(err, errcap, "protocol error: invalid integer reply");
            reply_free(r);
            return NULL;
        }
        r->kind = VK_R_INT;
        break;
    case '$': {
        long long blen;

        if (parse_i64(line + 1, n - 1, &blen) != 0) {
            set_err(err, errcap, "protocol error: invalid bulk length");
            reply_free(r);
            return NULL;
        }
        if (blen == -1) {
            r->kind = VK_R_NIL;
            break;
        }
        if (blen < 0 || (unsigned long long)blen > VK_BULK_MAX) {
            set_err(err, errcap,
                    "protocol error: bulk length %lld out of range", blen);
            reply_free(r);
            return NULL;
        }
        r->str = (char *)malloc((size_t)blen + 1);
        if (r->str == NULL) {
            set_err(err, errcap, "out of memory for %lld byte bulk", blen);
            reply_free(r);
            return NULL;
        }
        if (rb_read_exact(c, (unsigned char *)r->str, (size_t)blen, err,
                          errcap) != 0) {
            reply_free(r);
            return NULL;
        }
        {
            unsigned char crlf[2];

            if (rb_read_exact(c, crlf, 2, err, errcap) != 0) {
                reply_free(r);
                return NULL;
            }
            if (crlf[0] != '\r' || crlf[1] != '\n') {
                set_err(err, errcap,
                        "protocol error: bulk payload not terminated by CRLF");
                reply_free(r);
                return NULL;
            }
        }
        r->str[blen] = '\0';
        r->len = (size_t)blen;
        r->kind = VK_R_STRING;
        break;
    }
    case '*': {
        long long count;
        size_t i;

        if (parse_i64(line + 1, n - 1, &count) != 0) {
            set_err(err, errcap, "protocol error: invalid array length");
            reply_free(r);
            return NULL;
        }
        if (count == -1) {
            r->kind = VK_R_NIL;
            break;
        }
        if (count < 0 || (unsigned long long)count > VK_ARRAY_MAX) {
            set_err(err, errcap,
                    "protocol error: array length %lld out of range", count);
            reply_free(r);
            return NULL;
        }
        if ((size_t)count > SIZE_MAX / sizeof(vk_reply *)) {
            set_err(err, errcap, "protocol error: array too large");
            reply_free(r);
            return NULL;
        }
        r->kind = VK_R_ARRAY;
        r->elems = (vk_reply **)calloc((size_t)count, sizeof(vk_reply *));
        if (r->elems == NULL) {
            set_err(err, errcap, "out of memory for array of %lld", count);
            reply_free(r);
            return NULL;
        }
        r->nelems = (size_t)count;
        for (i = 0; i < (size_t)count; i++) {
            r->elems[i] = read_reply(c, depth + 1, err, errcap);
            if (r->elems[i] == NULL) {
                reply_free(r);
                return NULL;
            }
        }
        break;
    }
    default:
        set_err(err, errcap,
                "protocol error: unexpected reply type byte 0x%02x",
                (unsigned)(unsigned char)line[0]);
        reply_free(r);
        return NULL;
    }
    return r;
}

/* ------------------------------------------------------------------ */
/* execution                                                          */
/* ------------------------------------------------------------------ */

static vk_reply *exec_once(vk_client *c, const struct sbuf *sb, char *err,
                           size_t errcap)
{
    c->io_err = 0;
    if (io_send_all(c, sb->data, sb->len, err, errcap) != 0) {
        c->io_err = 1;
        return NULL;
    }
    return read_reply(c, 0, err, errcap);
}

static vk_reply *exec_locked(vk_client *c, const struct sbuf *sb, char *err,
                             size_t errcap)
{
    int attempt;

    for (attempt = 0; attempt < 2; attempt++) {
        vk_reply *r;
        int was_io;

        if (!c->alive) {
            /* reconnect using the stored credentials (lock already held) */
            if (vk__connect_internal(c, err, errcap) != 0) {
                return NULL;
            }
        }
        r = exec_once(c, sb, err, errcap);
        if (r != NULL) {
            return r;
        }
        was_io = c->io_err;
        close_socket(c);
        if (!was_io) {
            return NULL;
        }
    }
    return NULL;
}

static vk_reply *vk_command(vk_client *c, const vk_arg *args, size_t nargs,
                            char *err, size_t errcap)
{
    struct sbuf sb;
    vk_reply *r;

    if (c == NULL) {
        set_err(err, errcap, "valkey client is NULL");
        return NULL;
    }
    if (build_command(&sb, args, nargs, err, errcap) != 0) {
        return NULL;
    }
    pthread_mutex_lock(&c->lock);
    r = exec_locked(c, &sb, err, errcap);
    pthread_mutex_unlock(&c->lock);
    sbuf_free(&sb);
    return r;
}

/* Check a handshake reply; returns 0 if the expected +string arrived. */
static int handshake_expect(vk_client *c, vk_reply *r, const char *what,
                            char *err, size_t errcap)
{
    int rc = 0;

    (void)c;
    if (r == NULL) {
        return -1;
    }
    if (r->kind == VK_R_ERROR) {
        set_err(err, errcap, "%s failed: %s", what, r->str);
        rc = -1;
    } else if (r->kind != VK_R_STRING) {
        set_err(err, errcap, "%s failed: unexpected reply type", what);
        rc = -1;
    }
    reply_free(r);
    return rc;
}

/* Connect + TLS + AUTH + SELECT + PING.  Must be called with the lock held
 * (or before the client is shared between threads). */
static int vk__connect_internal(vk_client *c, char *err, size_t errcap)
{
    struct sbuf sb;
    vk_reply *r;
    char dbstr[32];
    int rc = -1;

    close_socket(c);
    c->io_err = 0;

    if (c->use_unix) {
        if (unix_open(c, err, errcap) != 0) {
            return -1;
        }
    } else if (tcp_open(c, err, errcap) != 0) {
        return -1;
    }
    if (c->tls) {
        if (tls_start(c, err, errcap) != 0) {
            close_socket(c);
            return -1;
        }
    }

    if (c->pass != NULL) {
        vk_arg args[3];
        size_t nargs;

        args[0].p = "AUTH";
        args[0].len = 4;
        if (c->user != NULL) {
            args[1].p = c->user;
            args[1].len = strlen(c->user);
            args[2].p = c->pass;
            args[2].len = strlen(c->pass);
            nargs = 3;
        } else {
            args[1].p = c->pass;
            args[1].len = strlen(c->pass);
            nargs = 2;
        }
        if (build_command(&sb, args, nargs, err, errcap) != 0) {
            close_socket(c);
            return -1;
        }
        r = exec_once(c, &sb, err, errcap);
        sbuf_free(&sb);
        if (handshake_expect(c, r, "AUTH", err, errcap) != 0) {
            close_socket(c);
            return -1;
        }
    }

    if (c->db > 0) {
        vk_arg args[2];

        snprintf(dbstr, sizeof(dbstr), "%d", c->db);
        args[0].p = "SELECT";
        args[0].len = 6;
        args[1].p = dbstr;
        args[1].len = strlen(dbstr);
        if (build_command(&sb, args, 2, err, errcap) != 0) {
            close_socket(c);
            return -1;
        }
        r = exec_once(c, &sb, err, errcap);
        sbuf_free(&sb);
        if (handshake_expect(c, r, "SELECT", err, errcap) != 0) {
            close_socket(c);
            return -1;
        }
    }

    {
        vk_arg args[1];

        args[0].p = "PING";
        args[0].len = 4;
        if (build_command(&sb, args, 1, err, errcap) != 0) {
            close_socket(c);
            return -1;
        }
        r = exec_once(c, &sb, err, errcap);
        sbuf_free(&sb);
        if (r == NULL) {
            close_socket(c);
            return -1;
        }
        if (r->kind == VK_R_ERROR) {
            set_err(err, errcap, "PING failed: %s", r->str);
            reply_free(r);
            close_socket(c);
            return -1;
        }
        if (r->kind != VK_R_STRING) {
            set_err(err, errcap, "PING failed: unexpected reply type");
            reply_free(r);
            close_socket(c);
            return -1;
        }
        reply_free(r);
    }

    c->alive = 1;
    rc = 0;
    return rc;
}

/* ------------------------------------------------------------------ */
/* public API                                                         */
/* ------------------------------------------------------------------ */

vk_client *vk_connect(const char *url, char *err, size_t errcap)
{
    struct url_parts up;
    vk_client *c;

    if (err != NULL && errcap > 0) {
        err[0] = '\0';
    }
    if (url == NULL || url[0] == '\0') {
        set_err(err, errcap, "vk_connect: empty URL");
        return NULL;
    }
    if (url_parse(url, &up, err, errcap) != 0) {
        return NULL;
    }

    c = (vk_client *)calloc(1, sizeof(*c));
    if (c == NULL) {
        url_parts_free(&up);
        set_err(err, errcap, "out of memory");
        return NULL;
    }
    c->fd = -1;
    c->tls = up.tls;
    c->insecure = up.insecure;
    c->use_unix = up.use_unix;
    c->port = up.port;
    c->db = up.db;
    c->host = up.host;
    c->user = up.user;
    c->pass = up.pass;
    c->connect_timeout_ms = VK_CONNECT_TIMEOUT_MS;
    c->io_timeout_ms = VK_IO_TIMEOUT_MS;

    if (pthread_mutex_init(&c->lock, NULL) != 0) {
        free(c->host);
        free(c->user);
        free(c->pass);
        free(c);
        set_err(err, errcap, "cannot initialise client mutex");
        return NULL;
    }
    c->rbuf = (unsigned char *)malloc(VK_RBUF_SIZE);
    if (c->rbuf == NULL) {
        pthread_mutex_destroy(&c->lock);
        free(c->host);
        free(c->user);
        free(c->pass);
        free(c);
        set_err(err, errcap, "out of memory");
        return NULL;
    }
    c->rcap = VK_RBUF_SIZE;

    if (vk__connect_internal(c, err, errcap) != 0) {
        vk_close(c);
        return NULL;
    }
    return c;
}

void vk_close(vk_client *c)
{
    if (c == NULL) {
        return;
    }
    pthread_mutex_lock(&c->lock);
    close_socket(c);
    if (c->ctx != NULL) {
        SSL_CTX_free(c->ctx);
        c->ctx = NULL;
    }
    free(c->rbuf);
    c->rbuf = NULL;
    free(c->host);
    free(c->user);
    free(c->pass);
    pthread_mutex_unlock(&c->lock);
    pthread_mutex_destroy(&c->lock);
    free(c);
}

int vk_ping(vk_client *c, char *err, size_t errcap)
{
    vk_arg args[1];
    vk_reply *r;
    int rc = 0;

    if (c == NULL) {
        set_err(err, errcap, "vk_ping: NULL client");
        return -1;
    }
    args[0].p = "PING";
    args[0].len = 4;
    r = vk_command(c, args, 1, err, errcap);
    if (r == NULL) {
        return -1;
    }
    if (r->kind == VK_R_ERROR) {
        set_err(err, errcap, "%s", r->str);
        rc = -1;
    } else if (r->kind != VK_R_STRING) {
        set_err(err, errcap, "PING: unexpected reply type");
        rc = -1;
    }
    reply_free(r);
    return rc;
}

int vk_get(vk_client *c, const char *key, unsigned char **val, size_t *vallen,
           char *err, size_t errcap)
{
    vk_arg args[2];
    vk_reply *r;
    int rc = -1;

    if (c == NULL || key == NULL || val == NULL || vallen == NULL) {
        set_err(err, errcap, "vk_get: invalid argument");
        return -1;
    }
    args[0].p = "GET";
    args[0].len = 3;
    args[1].p = key;
    args[1].len = strlen(key);

    r = vk_command(c, args, 2, err, errcap);
    if (r == NULL) {
        return -1;
    }
    if (r->kind == VK_R_ERROR) {
        set_err(err, errcap, "%s", r->str);
    } else if (r->kind == VK_R_NIL) {
        rc = 0;
    } else if (r->kind == VK_R_STRING) {
        unsigned char *copy = (unsigned char *)malloc(r->len + 1);

        if (copy == NULL) {
            set_err(err, errcap, "out of memory");
        } else {
            memcpy(copy, r->str, r->len);
            copy[r->len] = '\0';
            *val = copy;
            *vallen = r->len;
            rc = 1;
        }
    } else {
        set_err(err, errcap, "GET: unexpected reply type");
    }
    reply_free(r);
    return rc;
}

int vk_set_ex(vk_client *c, const char *key, const unsigned char *val,
              size_t vallen, long long ttl_sec, char *err, size_t errcap)
{
    vk_arg args[5];
    vk_reply *r;
    char ttlstr[32];
    size_t nargs;
    int rc = 0;

    if (c == NULL || key == NULL || (val == NULL && vallen > 0)) {
        set_err(err, errcap, "vk_set_ex: invalid argument");
        return -1;
    }
    args[0].p = "SET";
    args[0].len = 3;
    args[1].p = key;
    args[1].len = strlen(key);
    args[2].p = (val != NULL) ? val : (const unsigned char *)"";
    args[2].len = vallen;
    nargs = 3;
    if (ttl_sec > 0) {
        int l = snprintf(ttlstr, sizeof(ttlstr), "%lld", ttl_sec);

        if (l < 0 || (size_t)l >= sizeof(ttlstr)) {
            set_err(err, errcap, "vk_set_ex: TTL out of range");
            return -1;
        }
        args[3].p = "EX";
        args[3].len = 2;
        args[4].p = ttlstr;
        args[4].len = strlen(ttlstr);
        nargs = 5;
    }

    r = vk_command(c, args, nargs, err, errcap);
    if (r == NULL) {
        return -1;
    }
    if (r->kind == VK_R_ERROR) {
        set_err(err, errcap, "%s", r->str);
        rc = -1;
    } else if (r->kind != VK_R_STRING) {
        set_err(err, errcap, "SET: unexpected reply type");
        rc = -1;
    }
    reply_free(r);
    return rc;
}

int vk_del(vk_client *c, const char *key, char *err, size_t errcap)
{
    vk_arg args[2];
    vk_reply *r;
    int rc = 0;

    if (c == NULL || key == NULL) {
        set_err(err, errcap, "vk_del: invalid argument");
        return -1;
    }
    args[0].p = "DEL";
    args[0].len = 3;
    args[1].p = key;
    args[1].len = strlen(key);

    r = vk_command(c, args, 2, err, errcap);
    if (r == NULL) {
        return -1;
    }
    if (r->kind == VK_R_ERROR) {
        set_err(err, errcap, "%s", r->str);
        rc = -1;
    } else if (r->kind != VK_R_INT) {
        set_err(err, errcap, "DEL: unexpected reply type");
        rc = -1;
    }
    reply_free(r);
    return rc;
}

void vk_free_keys(char **keys, size_t nkeys)
{
    size_t i;

    if (keys == NULL) {
        return;
    }
    for (i = 0; i < nkeys; i++) {
        free(keys[i]);
    }
    free(keys);
}

int vk_scan(vk_client *c, const char *cursor_in, const char *match, long count,
            char **cursor_out, char ***keys, size_t *nkeys, char *err,
            size_t errcap)
{
    vk_arg args[6];
    vk_reply *r;
    char countstr[32];
    size_t nargs = 2;
    size_t i;
    char **out_keys = NULL;
    char *out_cursor = NULL;
    size_t produced = 0;
    int rc = -1;

    if (c == NULL || cursor_in == NULL || cursor_out == NULL || keys == NULL ||
        nkeys == NULL) {
        set_err(err, errcap, "vk_scan: invalid argument");
        return -1;
    }
    *cursor_out = NULL;
    *keys = NULL;
    *nkeys = 0;

    args[0].p = "SCAN";
    args[0].len = 4;
    args[1].p = cursor_in;
    args[1].len = strlen(cursor_in);
    if (match != NULL) {
        args[nargs].p = "MATCH";
        args[nargs].len = 5;
        nargs++;
        args[nargs].p = match;
        args[nargs].len = strlen(match);
        nargs++;
    }
    if (count > 0) {
        int l = snprintf(countstr, sizeof(countstr), "%ld", count);

        if (l < 0 || (size_t)l >= sizeof(countstr)) {
            set_err(err, errcap, "vk_scan: COUNT out of range");
            return -1;
        }
        args[nargs].p = "COUNT";
        args[nargs].len = 5;
        nargs++;
        args[nargs].p = countstr;
        args[nargs].len = strlen(countstr);
        nargs++;
    }

    r = vk_command(c, args, nargs, err, errcap);
    if (r == NULL) {
        return -1;
    }
    if (r->kind == VK_R_ERROR) {
        set_err(err, errcap, "%s", r->str);
        goto done;
    }
    if (r->kind != VK_R_ARRAY || r->nelems != 2 ||
        r->elems[0]->kind != VK_R_STRING ||
        r->elems[1]->kind != VK_R_ARRAY) {
        set_err(err, errcap, "SCAN: malformed reply");
        goto done;
    }
    out_cursor = dup_range(r->elems[0]->str, r->elems[0]->len);
    if (out_cursor == NULL) {
        set_err(err, errcap, "out of memory");
        goto done;
    }
    if (r->elems[1]->nelems > 0) {
        out_keys = (char **)calloc(r->elems[1]->nelems, sizeof(char *));
        if (out_keys == NULL) {
            set_err(err, errcap, "out of memory");
            goto done;
        }
        for (i = 0; i < r->elems[1]->nelems; i++) {
            vk_reply *e = r->elems[1]->elems[i];

            if (e->kind != VK_R_STRING) {
                set_err(err, errcap, "SCAN: non-string key in reply");
                goto done;
            }
            out_keys[i] = dup_range(e->str, e->len);
            if (out_keys[i] == NULL) {
                set_err(err, errcap, "out of memory");
                goto done;
            }
            produced++;
        }
    }
    *cursor_out = out_cursor;
    *keys = out_keys;
    *nkeys = r->elems[1]->nelems;
    out_cursor = NULL;
    out_keys = NULL;
    rc = 0;

done:
    if (out_keys != NULL) {
        vk_free_keys(out_keys, produced);
    }
    free(out_cursor);
    reply_free(r);
    return rc;
}


/* ------------------------------------------------------------- valkey store
 *
 * --store valkey:redis://... is the shared backend: challenges and honeypot
 * counters live in Valkey (or any RESP-compatible server), not in this
 * process. Records use the same JSON as the bbolt store and native TTLs:
 *
 *   betteranusbis:challenge:<id>  {"id":...,"randomData":...,...}  EX 604800
 *   betteranusbis:honeypot:<key>  {"count":N,"last":unix}          EX 3600
 *
 * Reads are remote-first for the mutable state (spent, cssSeen) and local-first
 * for the immutable peeks (algorithm, referer, issued time), so a challenge
 * issued by one instance verifies on another. Startup walks SCAN over our two
 * prefixes and fills the in-memory tables, which keeps the normal path fast.
 *
 * If Valkey goes away the gate keeps serving from memory: remote failures log
 * once and back off, and the local table is the fallback. That is deliberate —
 * a cache outage should not take the site down — but it also means two
 * instances can disagree until the store returns.
 */
#define VK_CH_PREFIX "betteranusbis:challenge:"
#define VK_HP_PREFIX "betteranusbis:honeypot:"
#define VK_MISS_SLOTS 256

static time_t vk_backoff_until;

typedef struct {
    uint64_t key;
    time_t when;
    int used;
} vk_miss_entry;

static vk_miss_entry vk_misses[VK_MISS_SLOTS];

static void vk_warn(const char *what, const char *err) {
    static time_t last;
    time_t now = time(NULL);
    if (now - last >= 5) {
        logmsg("store: valkey %s: %s", what, err && *err ? err : "error");
        last = now;
    }
    vk_backoff_until = now + 5;
}

static int vk_available(void) {
    return store_valkey && vk != NULL && time(NULL) >= vk_backoff_until;
}

static void challenge_json(const ch_entry *e, char *buf, size_t cap) {
    char esc_ref[2048], esc_rd[256], esc_algo[128];
    json_escape_into(e->referer, esc_ref, sizeof esc_ref);
    json_escape_into(e->rd, esc_rd, sizeof esc_rd);
    json_escape_into(e->algorithm, esc_algo, sizeof esc_algo);
    snprintf(buf, cap,
             "{\"id\":\"%s\",\"randomData\":\"%s\",\"algorithm\":\"%s\","
             "\"difficulty\":%d,\"spent\":%s,\"issuedMs\":%lld,"
             "\"cssSeen\":%s,\"referer\":\"%s\"}",
             e->id, esc_rd, esc_algo, e->difficulty, e->spent ? "true" : "false",
             e->issued_ms, e->css_seen ? "true" : "false", esc_ref);
}

static int challenge_from_json(const char *json, ch_entry *e) {
    memset(e, 0, sizeof *e);
    if (!json_get_str(json, "randomData", e->rd, sizeof e->rd)) return 0;
    if (!json_get_str(json, "id", e->id, sizeof e->id) || !e->id[0]) {
        /* the bucket/key name carries one; the caller fills it if absent */
    }
    if (!json_get_str(json, "algorithm", e->algorithm, sizeof e->algorithm) ||
        !e->algorithm[0])
        snprintf(e->algorithm, sizeof e->algorithm, "%s", cfg.algorithm);
    json_get_str(json, "referer", e->referer, sizeof e->referer);
    e->difficulty = (int)json_get_ll(json, "difficulty", cfg.difficulty);
    e->spent = json_get_bool(json, "spent", 0);
    e->css_seen = json_get_bool(json, "cssSeen", 0);
    e->issued_ms = json_get_ll(json, "issuedMs", (long long)time(NULL) * 1000);
    e->issued = (time_t)(e->issued_ms / 1000);
    e->used = 1;
    return 1;
}

/* Insert or refresh the local cache without creating a second copy. */
static void ch_cache_put(const ch_entry *src) {
    uint32_t h = 2166136261u;
    for (const char *q = src->id; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
    pthread_mutex_lock(&ch_lock);
    for (int probe = 0; probe < 32; probe++) {
        ch_entry *e = &ch_table[(h + (uint32_t)probe) % CH_BUCKETS];
        if (!e->used || !strcmp(e->id, src->id)) {
            *e = *src;
            e->used = 1;
            pthread_mutex_unlock(&ch_lock);
            return;
        }
    }
    pthread_mutex_unlock(&ch_lock);
}

static int vk_get_challenge(const char *id, ch_entry *out) {
    if (!vk_available() || !id || !*id) return 0;
    char key[160], err[256] = "";
    unsigned char *val = NULL;
    size_t len = 0;
    snprintf(key, sizeof key, VK_CH_PREFIX "%s", id);
    int rc = vk_get(vk, key, &val, &len, err, sizeof err);
    if (rc < 0) { vk_warn("GET challenge", err); return -1; }
    if (rc == 0) return 0;
    char *json = malloc(len + 1);
    if (!json) { free(val); return -1; }
    memcpy(json, val, len);
    json[len] = 0;
    free(val);
    int ok = challenge_from_json(json, out);
    free(json);
    if (!ok) return 0;
    if (!out->id[0]) snprintf(out->id, sizeof out->id, "%s", id);
    return 1;
}

static void vk_put_challenge(const ch_entry *e, long long ttl) {
    if (!vk_available() || !e || !e->id[0]) return;
    char key[160], json[4096], err[256] = "";
    challenge_json(e, json, sizeof json);
    snprintf(key, sizeof key, VK_CH_PREFIX "%s", e->id);
    if (vk_set_ex(vk, key, (const unsigned char *)json, strlen(json), ttl, err,
                  sizeof err) != 0)
        vk_warn("SET challenge", err);
}

static int vk_get_honeypot(uint64_t key, int *count, time_t *last) {
    if (!vk_available()) return 0;
    char name[96], err[256] = "";
    unsigned char *val = NULL;
    size_t len = 0;
    snprintf(name, sizeof name, VK_HP_PREFIX "%llu", (unsigned long long)key);
    int rc = vk_get(vk, name, &val, &len, err, sizeof err);
    if (rc < 0) { vk_warn("GET honeypot", err); return -1; }
    if (rc == 0) return 0;
    char json[512];
    size_t n = len < sizeof json - 1 ? len : sizeof json - 1;
    memcpy(json, val, n);
    json[n] = 0;
    free(val);
    int c = (int)json_get_ll(json, "count", 0);
    long long l = json_get_ll(json, "last", 0);
    if (c <= 0 || l <= 0) return 0;
    *count = c;
    *last = (time_t)l;
    return 1;
}

static void vk_put_honeypot(uint64_t key, int count, time_t last) {
    if (!vk_available()) return;
    char name[96], json[160], err[256] = "";
    snprintf(name, sizeof name, VK_HP_PREFIX "%llu", (unsigned long long)key);
    snprintf(json, sizeof json, "{\"count\":%d,\"last\":%lld}", count, (long long)last);
    if (vk_set_ex(vk, name, (const unsigned char *)json, strlen(json), HP_WINDOW,
                  err, sizeof err) != 0)
        vk_warn("SET honeypot", err);
}

/* The ledger talks to one remote interface; Valkey and S3 both implement it. */
static int remote_available(void) {
    if (store_valkey) return vk_available();
    if (store_s3) return s3_available();
    return 0;
}

static int remote_get_challenge(const char *id, ch_entry *out) {
    if (store_valkey) return vk_get_challenge(id, out);
    if (store_s3) return s3_get_challenge(id, out);
    return 0;
}

static void remote_put_challenge(const ch_entry *e, long long ttl) {
    if (store_valkey) vk_put_challenge(e, ttl);
    else if (store_s3) s3_put_challenge(e, ttl);
}

static int remote_get_honeypot(uint64_t key, int *count, time_t *last) {
    if (store_valkey) return vk_get_honeypot(key, count, last);
    if (store_s3) return s3_get_honeypot(key, count, last);
    return 0;
}

static void remote_put_honeypot(uint64_t key, int count, time_t last) {
    if (store_valkey) vk_put_honeypot(key, count, last);
    else if (store_s3) s3_put_honeypot(key, count, last);
}

/* A negative cache: a network with no honeypot hits would otherwise cost a
 * Valkey round trip on every single request. */
static int vk_miss_seen(uint64_t key) {
    time_t now = time(NULL);
    int seen = 0;
    pthread_mutex_lock(&hp_lock);
    for (int probe = 0; probe < 16; probe++) {
        vk_miss_entry *m = &vk_misses[(key + (uint64_t)probe) % VK_MISS_SLOTS];
        if (!m->used) break;
        if (m->key != key) continue;
        seen = now - m->when < 5;
        if (!seen) m->when = now;
        break;
    }
    pthread_mutex_unlock(&hp_lock);
    return seen;
}

static void vk_miss_mark(uint64_t key) {
    pthread_mutex_lock(&hp_lock);
    for (int probe = 0; probe < 16; probe++) {
        vk_miss_entry *m = &vk_misses[(key + (uint64_t)probe) % VK_MISS_SLOTS];
        if (!m->used || m->key == key) {
            m->used = 1;
            m->key = key;
            m->when = time(NULL);
            break;
        }
    }
    pthread_mutex_unlock(&hp_lock);
}

static void hp_cache_put(uint64_t key, int count, time_t last) {
    pthread_mutex_lock(&hp_lock);
    for (int probe = 0; probe < 32; probe++) {
        hp_entry *e = &hp_table[(key + (uint64_t)probe) % HP_BUCKETS];
        if (!e->used || e->key == key) {
            e->used = 1;
            e->key = key;
            e->count = count;
            e->last = last;
            break;
        }
    }
    pthread_mutex_unlock(&hp_lock);
}

static void valkey_load_state(void) {
    char *cursor = strdup("0");
    long long nch = 0, nhp = 0;
    if (!cursor) return;
    for (;;) {
        char *next = NULL, err[256] = "";
        char **keys = NULL;
        size_t nkeys = 0;
        if (vk_scan(vk, cursor, "betteranusbis:*", 500, &next, &keys, &nkeys,
                    err, sizeof err) != 0) {
            vk_warn("SCAN", err);
            free(cursor);
            return;
        }
        for (size_t i = 0; i < nkeys; i++) {
            unsigned char *val = NULL;
            size_t len = 0;
            char gerr[256] = "";
            if (vk_get(vk, keys[i], &val, &len, gerr, sizeof gerr) != 1) continue;
            char *json = malloc(len + 1);
            if (!json) { free(val); continue; }
            memcpy(json, val, len);
            json[len] = 0;
            free(val);
            if (!strncmp(keys[i], VK_CH_PREFIX, strlen(VK_CH_PREFIX))) {
                ch_entry e;
                if (challenge_from_json(json, &e)) {
                    const char *id = keys[i] + strlen(VK_CH_PREFIX);
                    snprintf(e.id, sizeof e.id, "%s", id);
                    if ((long long)time(NULL) - (long long)e.issued <= COOKIE_TTL) {
                        ch_cache_put(&e);
                        nch++;
                    }
                }
            } else if (!strncmp(keys[i], VK_HP_PREFIX, strlen(VK_HP_PREFIX))) {
                unsigned long long key = strtoull(keys[i] + strlen(VK_HP_PREFIX), NULL, 10);
                int c = (int)json_get_ll(json, "count", 0);
                long long l = json_get_ll(json, "last", 0);
                if (c > 0 && key && (long long)time(NULL) - l <= HP_WINDOW) {
                    pthread_mutex_lock(&hp_lock);
                    for (int k = 0; k < HP_BUCKETS; k++) {
                        hp_entry *e = &hp_table[k];
                        if (!e->used || e->key == key) {
                            e->used = 1;
                            e->key = key;
                            e->count = c;
                            e->last = (time_t)l;
                            nhp++;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&hp_lock);
                }
            }
            free(json);
        }
        if (keys) vk_free_keys(keys, nkeys);
        int stuck = next && cursor && !strcmp(next, cursor);
        free(cursor);
        if (stuck) {
            /* a server that does not advance the cursor must not hang us */
            free(next);
            next = strdup("0");
        }
        cursor = next;
        if (!cursor || !strcmp(cursor, "0")) {
            free(cursor);
            cursor = NULL;
            break;
        }
    }
    free(cursor);
    logmsg("store: valkey %s, loaded %lld challenge(s) and %lld network(s)",
           store_path, nch, nhp);
}

/* Never put the password from redis://user:pass@host into a log or an error. */
static void vk_redact_url(const char *url, char *out, size_t cap) {
    const char *scheme = strstr(url, "://");
    const char *at = strrchr(url, '@');
    if (scheme && at && at > scheme + 3) {
        size_t keep = (size_t)(scheme - url) + 3;
        snprintf(out, cap, "%.*s***%s", (int)keep, url, at);
    } else {
        snprintf(out, cap, "%s", url);
    }
}

static int valkey_store_start(const char *url) {
    char err[512] = "";
    char safe[1024];
    vk_redact_url(url, safe, sizeof safe);
    vk = vk_connect(url, err, sizeof err);
    if (!vk) {
        fprintf(stderr, "betterAnusbis: cannot connect to valkey (%s): %s\n", safe,
                err[0] ? err : "connection failed");
        return -1;
    }
    if (vk_ping(vk, err, sizeof err) != 0) {
        fprintf(stderr, "betterAnusbis: valkey PING failed: %s\n",
                err[0] ? err : "no response");
        vk_close(vk);
        vk = NULL;
        return -1;
    }
    store_valkey = 1;
    logmsg("store: valkey %s, TTLs carry the expiry", safe);
    valkey_load_state();
    return 0;
}

/*
 * s3_io.h -- minimal standalone Amazon S3 client (HTTP/1.1 + TLS + SigV4).
 *
 * The implementation is single-file friendly: paste s3_io.h and s3_io.c into
 * a project and link with -lssl -lcrypto -lpthread.
 *
 * Public API (all return 0 on success and -1 on error unless noted):
 *   s3_client *s3_connect(bucket, path_style, err, errcap);
 *   void       s3_close(c);
 *   int        s3_ping(c, err, errcap);
 *   int        s3_get(c, key, &val, &vallen, &expiry_ms, err, errcap);
 *   int        s3_put(c, key, val, vallen, expiry_ms, err, errcap);
 *   int        s3_delete(c, key, err, errcap);
 *
 * Configuration comes from the environment in s3_connect():
 *   AWS_REGION or AWS_DEFAULT_REGION   (required)
 *   AWS_ACCESS_KEY_ID                  (required)
 *   AWS_SECRET_ACCESS_KEY              (required)
 *   AWS_SESSION_TOKEN                  (optional)
 *   AWS_ENDPOINT_URL_S3 / AWS_ENDPOINT_URL (optional; http:// or https://)
 *
 * path_style:  >0 forces path style, 0 forces virtual-host style, <0 selects
 *              automatically (virtual-host for the AWS default s3_endpoint,
 *              path style for any custom s3_endpoint).
 *
 * Secrets are never logged. See REPORT.md for the full contract and caveats.
 */
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct s3_client s3_client;

/* Connect (parse env config, validate addressing, build TLS context).
 * Returns NULL and fills err on failure. Never logs secret material. */
s3_client *s3_connect(const char *bucket, int path_style,
                      char *err, size_t errcap);

/* Release all resources owned by the client (safe with NULL). */
void s3_close(s3_client *c);

/* Probe the bucket: GET a sentinel key. 404 / NoSuchKey means the bucket and
 * the credentials/signature work. 0 = ok, -1 = error (err has details). */
int s3_ping(s3_client *c, char *err, size_t errcap);

/* Fetch an object.
 *   1  found: *val is a malloc'd, NUL-terminated buffer (non-NULL even for an
 *      empty object), *vallen the byte length, *expiry_ms the upstream
 *      x-amz-meta-x-anubis-expiry-ms value (0 when absent).
 *   0  not found, or the stored expiry has passed (a best-effort DELETE is
 *      attempted in that case).
 *  -1  error (err has details; S3 XML Code/Message are surfaced). */
int s3_get(s3_client *c, const char *key, unsigned char **val, size_t *vallen,
           long long *expiry_ms, char *err, size_t errcap);

/* Store an object. expiry_ms > 0 adds x-amz-meta-x-anubis-expiry-ms. */
int s3_put(s3_client *c, const char *key, const unsigned char *val,
           size_t vallen, long long expiry_ms, char *err, size_t errcap);

/* Delete an object. 2xx and 404 are both treated as success. */
int s3_delete(s3_client *c, const char *key, char *err, size_t errcap);

/* ------------------------------------------------------------------------ */
/* Test-only helpers (compiled unconditionally; unused by the S3 code paths) */
/* ------------------------------------------------------------------------ */

/*
 * Generic SigV4 signer used by the official AWS test suite harness.
 * It signs an arbitrary method / path / query / header set with an arbitrary
 * service name, and can apply the botocore-style URI path normalization that
 * the official suite expects. The production S3 path never normalizes the
 * URI (S3 keys are canonical already) and passes path_pre_encoded = 1.
 */
typedef struct {
    const char *method;        /* "GET", "POST", ...                      */
    const char *raw_path;      /* path as it appears before encoding      */
    int normalize_path;        /* 1: remove dot segments / extra slashes  */
    const char *raw_query;     /* query string without '?', or NULL/""    */
    const char *const *headers;/* "Name: value" lines, duplicates allowed */
    size_t nheaders;
    const unsigned char *body;
    size_t bodylen;
    const char *access_key;
    const char *secret_key;
    const char *region;
    const char *service;
    const char *amzdate;       /* "YYYYMMDDTHHMMSSZ"                      */
    int path_pre_encoded;      /* 1: raw_path already RFC3986 encoded     */
} s3_sigv4_test_req;

typedef struct {
    char *canonical_request;   /* <method>\n<uri>\n<query>\n...           */
    char *string_to_sign;
    char *authorization;
} s3_sigv4_test_out;

int s3_sigv4_test(const s3_sigv4_test_req *req, s3_sigv4_test_out *out,
                  char *err, size_t errcap);
void s3_sigv4_test_free(s3_sigv4_test_out *out);


/*
 * s3_io.c -- minimal standalone Amazon S3 client with SigV4 signing.
 *
 * Design notes:
 *  - No global mutable state. Each s3_client owns its configuration and its
 *    TLS_CTX, so distinct clients may be used concurrently from threads.
 *  - Stdlib/POSIX only + OpenSSL. No GNU extensions (clean with -Wpedantic).
 *  - Secrets live in the client struct and are never printed or logged.
 */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------------- */
/* Tunables                                                                  */
/* ------------------------------------------------------------------------- */

#define S3_MAX_HEADER_BYTES (64u * 1024u)
#define S3_MAX_BODY_BYTES   (8u * 1024u * 1024u)
#define S3_CONNECT_TIMEOUT_MS 5000
#define S3_IO_TIMEOUT_SEC 10
#define S3_READ_CHUNK 16384u
#define S3_STREAM_CAP (S3_MAX_BODY_BYTES + S3_MAX_HEADER_BYTES + 65536u)

#define S3_META_EXPIRY "x-amz-meta-x-anubis-expiry-ms"
#define S3_PROBE_KEY ".s3_io_probe"

/* ------------------------------------------------------------------------- */
/* Small growable byte buffer                                                */
/* ------------------------------------------------------------------------- */

typedef struct {
    char *p;
    size_t len;
    size_t cap;
} s3_sbuf;

static void sb_init(s3_sbuf *b)
{
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
}

static void sb_free(s3_sbuf *b)
{
    free(b->p);
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
}

static int sb_reserve(s3_sbuf *b, size_t extra)
{
    size_t need, cap;
    char *np;

    if (extra > SIZE_MAX - b->len - 1u) {
        return -1;
    }
    need = b->len + extra + 1u;
    if (need <= b->cap) {
        return 0;
    }
    cap = b->cap ? b->cap : 128u;
    while (cap < need) {
        if (cap > SIZE_MAX / 2u) {
            cap = need;
            break;
        }
        cap *= 2u;
    }
    np = (char *)realloc(b->p, cap);
    if (np == NULL) {
        return -1;
    }
    b->p = np;
    b->cap = cap;
    return 0;
}

static int sb_append(s3_sbuf *b, const void *data, size_t n)
{
    if (n == 0) {
        return 0;
    }
    if (sb_reserve(b, n) != 0) {
        return -1;
    }
    memcpy(b->p + b->len, data, n);
    b->len += n;
    b->p[b->len] = '\0';
    return 0;
}

static int sb_puts(s3_sbuf *b, const char *s)
{
    return sb_append(b, s, strlen(s));
}

static int sb_putc(s3_sbuf *b, char ch)
{
    return sb_append(b, &ch, 1u);
}

static int sb_printf(s3_sbuf *b, const char *fmt, ...)
{
    va_list ap;
    va_list ap2;
    int n;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        va_end(ap2);
        return -1;
    }
    if (sb_reserve(b, (size_t)n) != 0) {
        va_end(ap2);
        return -1;
    }
    (void)vsnprintf(b->p + b->len, (size_t)n + 1u, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)n;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Errors, allocation helpers                                                */
/* ------------------------------------------------------------------------- */

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 3, 4)))
#endif
static void s3_set_err(char *err, size_t cap, const char *fmt, ...)
{
    va_list ap;

    if (err == NULL || cap == 0) {
        return;
    }
    va_start(ap, fmt);
    (void)vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

static char *xstrdup(const char *s)
{
    size_t n;
    char *p;

    if (s == NULL) {
        return NULL;
    }
    n = strlen(s);
    p = (char *)malloc(n + 1u);
    if (p == NULL) {
        return NULL;
    }
    memcpy(p, s, n + 1u);
    return p;
}

static char *xstrndup(const char *s, size_t n)
{
    char *p;

    p = (char *)malloc(n + 1u);
    if (p == NULL) {
        return NULL;
    }
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

/* ------------------------------------------------------------------------- */
/* Crypto helpers (OpenSSL EVP/HMAC)                                         */
/* ------------------------------------------------------------------------- */

static int s3_sha256_hex(const void *data, size_t len, char out[65])
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    static const char hx[] = "0123456789abcdef";
    int i;

    if (len > 0 && data == NULL) {
        return -1;
    }
    if (EVP_Digest(data, len, md, &mdlen, EVP_sha256(), NULL) != 1) {
        return -1;
    }
    if (mdlen != 32u) {
        return -1;
    }
    for (i = 0; i < 32; i++) {
        out[i * 2] = hx[(md[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hx[md[i] & 0x0f];
    }
    out[64] = '\0';
    return 0;
}

static int s3_hmac_sha256(const void *key, size_t keylen,
                       const void *data, size_t datalen,
                       unsigned char out[32])
{
    unsigned int outlen = 0;

    if (keylen > (size_t)INT_MAX || datalen > (size_t)INT_MAX) {
        return -1;
    }
    if (key == NULL || (datalen > 0 && data == NULL)) {
        return -1;
    }
    if (HMAC(EVP_sha256(), key, (int)keylen,
             (const unsigned char *)data, datalen, out, &outlen) == NULL) {
        return -1;
    }
    if (outlen != 32u) {
        return -1;
    }
    return 0;
}

static void bin_to_hex(const unsigned char *in, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[i * 2] = hx[(in[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hx[in[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

/* ------------------------------------------------------------------------- */
/* RFC 3986 percent encoding / decoding                                      */
/* ------------------------------------------------------------------------- */

static int is_unreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
           c == '~';
}

static int pct_encode(const unsigned char *in, size_t n, int keep_slash,
                      s3_sbuf *out)
{
    static const char hx[] = "0123456789ABCDEF";
    size_t i;

    for (i = 0; i < n; i++) {
        unsigned char ch = in[i];

        if (is_unreserved(ch) || (keep_slash && ch == '/')) {
            if (sb_putc(out, (char)ch) != 0) {
                return -1;
            }
        } else {
            char enc[3];

            enc[0] = '%';
            enc[1] = hx[(ch >> 4) & 0x0f];
            enc[2] = hx[ch & 0x0f];
            if (sb_append(out, enc, 3u) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

static int hex_digit(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* Decode %XX escapes; malformed escapes are kept verbatim. */
static int s3_pct_decode(const char *in, size_t n, s3_sbuf *out)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (in[i] == '%' && i + 2u < n) {
            int hi = hex_digit((unsigned char)in[i + 1]);
            int lo = hex_digit((unsigned char)in[i + 2]);

            if (hi >= 0 && lo >= 0) {
                unsigned char byte = (unsigned char)((hi << 4) | lo);

                if (sb_putc(out, (char)byte) != 0) {
                    return -1;
                }
                i += 2u;
                continue;
            }
        }
        if (sb_putc(out, in[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Canonical URI path (botocore-compatible normalization for the test suite)  */
/* ------------------------------------------------------------------------- */

/*
 * RFC 3986 section 5.2.4 dot-segment removal, matching botocore's
 * remove_dot_segments (which also collapses empty segments). Used only by the
 * generic test signer: the S3 data path must never normalize keys.
 */
static int normalize_uri_path(const char *raw, s3_sbuf *out)
{
    size_t n = strlen(raw);
    size_t i = 0;
    size_t *starts = NULL;
    size_t *lens = NULL;
    size_t count = 0;
    size_t alloc = 0;
    size_t k;

    while (i <= n) {
        size_t seg_start = i;
        size_t seg_len;

        while (i < n && raw[i] != '/') {
            i++;
        }
        seg_len = i - seg_start;
        if (seg_len == 1u && raw[seg_start] == '.') {
            /* skip */
        } else if (seg_len == 2u && raw[seg_start] == '.' &&
                   raw[seg_start + 1u] == '.') {
            if (count > 0) {
                count--;
            }
        } else if (seg_len > 0) {
            if (count == alloc) {
                size_t nalloc = alloc ? alloc * 2u : 8u;
                size_t *ns = (size_t *)realloc(starts, nalloc * sizeof(*ns));
                size_t *nl;

                if (ns == NULL) {
                    free(starts);
                    free(lens);
                    return -1;
                }
                starts = ns;
                nl = (size_t *)realloc(lens, nalloc * sizeof(*nl));
                if (nl == NULL) {
                    free(starts);
                    free(lens);
                    return -1;
                }
                lens = nl;
                alloc = nalloc;
            }
            starts[count] = seg_start;
            lens[count] = seg_len;
            count++;
        }
        if (i == n) {
            break;
        }
        i++; /* skip '/' */
        if (i == n) {
            break; /* trailing slash handled below */
        }
    }

    if (n > 0 && raw[0] == '/') {
        if (sb_putc(out, '/') != 0) {
            goto oom;
        }
    }
    for (k = 0; k < count; k++) {
        if (k > 0 && sb_putc(out, '/') != 0) {
            goto oom;
        }
        if (sb_append(out, raw + starts[k], lens[k]) != 0) {
            goto oom;
        }
    }
    if (n > 0 && raw[n - 1] == '/' && count > 0) {
        if (sb_putc(out, '/') != 0) {
            goto oom;
        }
    }
    free(starts);
    free(lens);
    return 0;

oom:
    free(starts);
    free(lens);
    return -1;
}

/* ------------------------------------------------------------------------- */
/* Canonical query string                                                    */
/* ------------------------------------------------------------------------- */

typedef struct {
    s3_sbuf key;
    s3_sbuf val;
} s3_qpair;

static int qpair_cmp(const void *a, const void *b)
{
    const s3_qpair *x = (const s3_qpair *)a;
    const s3_qpair *y = (const s3_qpair *)b;
    int r = strcmp(x->key.p ? x->key.p : "", y->key.p ? y->key.p : "");

    if (r != 0) {
        return r;
    }
    return strcmp(x->val.p ? x->val.p : "", y->val.p ? y->val.p : "");
}

static void qpair_free(s3_qpair *v, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        sb_free(&v[i].key);
        sb_free(&v[i].val);
    }
    free(v);
}

static int canonical_query(const char *raw, s3_sbuf *out)
{
    const char *p;
    const char *end;
    s3_qpair *pairs = NULL;
    size_t count = 0;
    size_t alloc = 0;
    size_t i;

    if (raw == NULL || raw[0] == '\0') {
        return 0;
    }
    p = raw;
    end = raw + strlen(raw);
    while (p < end) {
        const char *amp = p;
        const char *eq;
        const char *seg_end;
        s3_sbuf dk, dv;

        while (amp < end && *amp != '&') {
            amp++;
        }
        seg_end = amp;
        if (seg_end > p) {
            eq = p;
            while (eq < seg_end && *eq != '=') {
                eq++;
            }
            sb_init(&dk);
            sb_init(&dv);
            if (s3_pct_decode(p, (size_t)(eq - p), &dk) != 0 ||
                s3_pct_decode(eq < seg_end ? eq + 1 : seg_end,
                           eq < seg_end ? (size_t)(seg_end - eq - 1) : 0u,
                           &dv) != 0) {
                sb_free(&dk);
                sb_free(&dv);
                qpair_free(pairs, count);
                return -1;
            }
            if (count == alloc) {
                size_t nalloc = alloc ? alloc * 2u : 8u;
                s3_qpair *np = (s3_qpair *)realloc(pairs, nalloc * sizeof(*np));

                if (np == NULL) {
                    sb_free(&dk);
                    sb_free(&dv);
                    qpair_free(pairs, count);
                    return -1;
                }
                pairs = np;
                alloc = nalloc;
            }
            sb_init(&pairs[count].key);
            sb_init(&pairs[count].val);
            if (pct_encode((const unsigned char *)dk.p, dk.len, 0,
                           &pairs[count].key) != 0 ||
                pct_encode((const unsigned char *)dv.p, dv.len, 0,
                           &pairs[count].val) != 0) {
                sb_free(&dk);
                sb_free(&dv);
                qpair_free(pairs, count + 1u);
                return -1;
            }
            sb_free(&dk);
            sb_free(&dv);
            count++;
        }
        p = (amp < end) ? amp + 1 : end;
    }
    if (count > 1) {
        qsort(pairs, count, sizeof(*pairs), qpair_cmp);
    }
    for (i = 0; i < count; i++) {
        if (i > 0 && sb_putc(out, '&') != 0) {
            qpair_free(pairs, count);
            return -1;
        }
        if (sb_append(out, pairs[i].key.p, pairs[i].key.len) != 0 ||
            sb_putc(out, '=') != 0 ||
            sb_append(out, pairs[i].val.p, pairs[i].val.len) != 0) {
            qpair_free(pairs, count);
            return -1;
        }
    }
    qpair_free(pairs, count);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Header canonicalization and SigV4 signing                                 */
/* ------------------------------------------------------------------------- */

typedef struct {
    char *name;   /* lowercase, trimmed */
    char *value;  /* trimmed, internal runs of SP/HTAB collapsed */
    size_t order; /* original position, keeps duplicate values in order */
} s3_shdr;

static void shdr_free_all(s3_shdr *v, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        free(v[i].name);
        free(v[i].value);
    }
    free(v);
}

static char *trim_ows_dup(const char *s, size_t n)
{
    size_t b = 0;
    size_t e = n;
    size_t i;
    size_t w = 0;
    char *out;
    int pending_space = 0;

    while (b < e && (s[b] == ' ' || s[b] == '\t')) {
        b++;
    }
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) {
        e--;
    }
    out = (char *)malloc(e - b + 1u);
    if (out == NULL) {
        return NULL;
    }
    for (i = b; i < e; i++) {
        char ch = s[i];

        if (ch == ' ' || ch == '\t') {
            pending_space = 1;
            continue;
        }
        if (pending_space && w > 0) {
            out[w++] = ' ';
        }
        pending_space = 0;
        out[w++] = ch;
    }
    out[w] = '\0';
    return out;
}

static int shdr_cmp(const void *a, const void *b)
{
    const s3_shdr *x = (const s3_shdr *)a;
    const s3_shdr *y = (const s3_shdr *)b;
    int r = strcmp(x->name, y->name);

    if (r != 0) {
        return r;
    }
    if (x->order < y->order) {
        return -1;
    }
    if (x->order > y->order) {
        return 1;
    }
    return 0;
}

static int parse_header_line(const char *line, size_t order, s3_shdr *out,
                             char *err, size_t errcap)
{
    const char *colon = strchr(line, ':');
    size_t i;
    size_t name_len;
    char *name;

    if (colon == NULL) {
        s3_set_err(err, errcap, "malformed header line (missing colon)");
        return -1;
    }
    name_len = (size_t)(colon - line);
    name = (char *)malloc(name_len + 1u);
    if (name == NULL) {
        s3_set_err(err, errcap, "out of memory");
        return -1;
    }
    for (i = 0; i < name_len; i++) {
        unsigned char ch = (unsigned char)line[i];

        if (ch <= 0x20 || ch >= 0x7f) {
            free(name);
            s3_set_err(err, errcap, "invalid character in header name");
            return -1;
        }
        name[i] = (char)tolower(ch);
    }
    name[name_len] = '\0';
    if (name_len == 0) {
        free(name);
        s3_set_err(err, errcap, "empty header name");
        return -1;
    }
    out->name = name;
    out->value = trim_ows_dup(colon + 1, strlen(colon + 1));
    out->order = order;
    if (out->value == NULL) {
        free(name);
        out->name = NULL;
        s3_set_err(err, errcap, "out of memory");
        return -1;
    }
    if (strpbrk(out->value, "\r\n") != NULL) {
        free(out->name);
        free(out->value);
        out->name = NULL;
        out->value = NULL;
        s3_set_err(err, errcap, "header value contains CR/LF");
        return -1;
    }
    return 0;
}

/*
 * Core SigV4 signer. Canonical URI and query are passed already encoded (the
 * production caller encodes the key exactly once). Header values are
 * normalized here, and the normalized values are what the caller must place
 * on the wire (production values are already canonical by construction).
 */
static int sigv4_sign(const char *method, const char *canon_uri,
                      const char *canon_query,
                      const char *const *hdr_lines, size_t nhdrs,
                      const char *payload_hash_hex,
                      const char *access_key, const char *secret_key,
                      const char *region, const char *service,
                      const char *amzdate,
                      s3_sbuf *out_authz, s3_sbuf *out_signed,
                      s3_sbuf *out_creq, s3_sbuf *out_sts,
                      char *err, size_t errcap)
{
    s3_shdr *hdrs = NULL;
    s3_sbuf canon_headers, signed_headers, creq, sts, scope, keybuf;
    unsigned char kdate[32], kregion[32], kservice[32], ksigning[32];
    unsigned char sig[32];
    char sig_hex[65];
    char creq_hash[65];
    size_t i;
    size_t groups = 0;
    int rc = -1;

    sb_init(&canon_headers);
    sb_init(&signed_headers);
    sb_init(&creq);
    sb_init(&sts);
    sb_init(&scope);
    sb_init(&keybuf);

    if (method == NULL || canon_uri == NULL || access_key == NULL ||
        secret_key == NULL || region == NULL || service == NULL ||
        amzdate == NULL || payload_hash_hex == NULL) {
        s3_set_err(err, errcap, "internal: missing signing input");
        goto done;
    }
    if (strlen(amzdate) != 16u || amzdate[8] != 'T' || amzdate[15] != 'Z') {
        s3_set_err(err, errcap, "internal: bad x-amz-date");
        goto done;
    }
    if (nhdrs > 0 && hdr_lines == NULL) {
        s3_set_err(err, errcap, "internal: missing headers");
        goto done;
    }

    if (nhdrs > 0) {
        hdrs = (s3_shdr *)calloc(nhdrs, sizeof(*hdrs));
        if (hdrs == NULL) {
            s3_set_err(err, errcap, "out of memory");
            goto done;
        }
        for (i = 0; i < nhdrs; i++) {
            if (parse_header_line(hdr_lines[i], i, &hdrs[i], err, errcap) != 0) {
                shdr_free_all(hdrs, nhdrs);
                hdrs = NULL;
                goto done;
            }
        }
        qsort(hdrs, nhdrs, sizeof(*hdrs), shdr_cmp);
    }

    /* Merge duplicate header names, preserving value order. */
    for (i = 0; i < nhdrs;) {
        size_t j = i + 1u;
        s3_sbuf merged;

        sb_init(&merged);
        if (sb_puts(&merged, hdrs[i].value) != 0) {
            sb_free(&merged);
            shdr_free_all(hdrs, nhdrs);
            hdrs = NULL;
            goto done;
        }
        while (j < nhdrs && strcmp(hdrs[j].name, hdrs[i].name) == 0) {
            if (sb_putc(&merged, ',') != 0 ||
                sb_puts(&merged, hdrs[j].value) != 0) {
                sb_free(&merged);
                shdr_free_all(hdrs, nhdrs);
                hdrs = NULL;
                goto done;
            }
            j++;
        }
        if (groups > 0 && sb_putc(&signed_headers, ';') != 0) {
            sb_free(&merged);
            shdr_free_all(hdrs, nhdrs);
            hdrs = NULL;
            goto done;
        }
        if (sb_puts(&signed_headers, hdrs[i].name) != 0 ||
            sb_puts(&canon_headers, hdrs[i].name) != 0 ||
            sb_putc(&canon_headers, ':') != 0 ||
            sb_append(&canon_headers, merged.p, merged.len) != 0 ||
            sb_putc(&canon_headers, '\n') != 0) {
            sb_free(&merged);
            shdr_free_all(hdrs, nhdrs);
            hdrs = NULL;
            goto done;
        }
        sb_free(&merged);
        groups++;
        i = j;
    }
    shdr_free_all(hdrs, nhdrs);
    hdrs = NULL;

    if (sb_printf(&creq, "%s\n%s\n%s\n", method, canon_uri,
                  canon_query ? canon_query : "") != 0 ||
        sb_append(&creq, canon_headers.p, canon_headers.len) != 0 ||
        sb_putc(&creq, '\n') != 0 ||
        sb_append(&creq, signed_headers.p, signed_headers.len) != 0 ||
        sb_putc(&creq, '\n') != 0 ||
        sb_puts(&creq, payload_hash_hex) != 0) {
        s3_set_err(err, errcap, "out of memory");
        goto done;
    }
    if (s3_sha256_hex(creq.p, creq.len, creq_hash) != 0) {
        s3_set_err(err, errcap, "SHA-256 failed");
        goto done;
    }
    if (sb_printf(&scope, "%.8s/%s/%s/aws4_request", amzdate, region,
                  service) != 0 ||
        sb_printf(&sts, "AWS4-HMAC-SHA256\n%s\n%s\n%s", amzdate, scope.p,
                  creq_hash) != 0) {
        s3_set_err(err, errcap, "out of memory");
        goto done;
    }

    if (sb_puts(&keybuf, "AWS4") != 0 || sb_puts(&keybuf, secret_key) != 0) {
        s3_set_err(err, errcap, "out of memory");
        goto done;
    }
    if (s3_hmac_sha256(keybuf.p, keybuf.len, amzdate, 8u, kdate) != 0 ||
        s3_hmac_sha256(kdate, 32u, region, strlen(region), kregion) != 0 ||
        s3_hmac_sha256(kregion, 32u, service, strlen(service), kservice) != 0 ||
        s3_hmac_sha256(kservice, 32u, "aws4_request", 12u, ksigning) != 0 ||
        s3_hmac_sha256(ksigning, 32u, sts.p, sts.len, sig) != 0) {
        s3_set_err(err, errcap, "HMAC-SHA256 failed");
        goto done;
    }
    bin_to_hex(sig, 32u, sig_hex);

    if (sb_printf(out_authz,
                  "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, "
                  "Signature=%s",
                  access_key, scope.p, signed_headers.p, sig_hex) != 0) {
        s3_set_err(err, errcap, "out of memory");
        goto done;
    }
    if (out_signed != NULL &&
        sb_append(out_signed, signed_headers.p, signed_headers.len) != 0) {
        s3_set_err(err, errcap, "out of memory");
        goto done;
    }
    if (out_creq != NULL &&
        sb_append(out_creq, creq.p, creq.len) != 0) {
        s3_set_err(err, errcap, "out of memory");
        goto done;
    }
    if (out_sts != NULL && sb_append(out_sts, sts.p, sts.len) != 0) {
        s3_set_err(err, errcap, "out of memory");
        goto done;
    }
    rc = 0;

done:
    if (hdrs != NULL) {
        shdr_free_all(hdrs, nhdrs);
    }
    sb_free(&canon_headers);
    sb_free(&signed_headers);
    sb_free(&creq);
    sb_free(&sts);
    sb_free(&scope);
    sb_free(&keybuf);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Test-only public signer entry point                                       */
/* ------------------------------------------------------------------------- */

static char *sbuf_take(s3_sbuf *b)
{
    char *p;

    if (b->p == NULL) {
        p = xstrdup("");
        return p;
    }
    p = b->p;
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
    return p;
}

int s3_sigv4_test(const s3_sigv4_test_req *req, s3_sigv4_test_out *out,
                  char *err, size_t errcap)
{
    s3_sbuf encpath, normpath, query, creq, sts, authz;
    char payload[65];
    int rc = -1;

    if (out != NULL) {
        out->canonical_request = NULL;
        out->string_to_sign = NULL;
        out->authorization = NULL;
    }
    if (req == NULL || out == NULL) {
        s3_set_err(err, errcap, "internal: null request");
        return -1;
    }
    sb_init(&encpath);
    sb_init(&normpath);
    sb_init(&query);
    sb_init(&creq);
    sb_init(&sts);
    sb_init(&authz);

    if (req->method == NULL || req->raw_path == NULL) {
        s3_set_err(err, errcap, "internal: missing method or path");
        goto done;
    }
    if (req->path_pre_encoded) {
        if (sb_puts(&encpath, req->raw_path) != 0) {
            s3_set_err(err, errcap, "out of memory");
            goto done;
        }
    } else {
        if (req->normalize_path) {
            if (normalize_uri_path(req->raw_path, &normpath) != 0) {
                s3_set_err(err, errcap, "out of memory");
                goto done;
            }
            if (pct_encode((const unsigned char *)normpath.p, normpath.len, 1,
                           &encpath) != 0) {
                s3_set_err(err, errcap, "out of memory");
                goto done;
            }
        } else {
            if (pct_encode((const unsigned char *)req->raw_path,
                           strlen(req->raw_path), 1, &encpath) != 0) {
                s3_set_err(err, errcap, "out of memory");
                goto done;
            }
        }
    }
    if (canonical_query(req->raw_query, &query) != 0) {
        s3_set_err(err, errcap, "out of memory");
        goto done;
    }
    if (s3_sha256_hex(req->body ? req->body : (const unsigned char *)"",
                   req->bodylen, payload) != 0) {
        s3_set_err(err, errcap, "SHA-256 failed");
        goto done;
    }
    if (sigv4_sign(req->method, encpath.p ? encpath.p : "/",
                   query.p ? query.p : "",
                   req->headers, req->nheaders, payload,
                   req->access_key, req->secret_key, req->region,
                   req->service, req->amzdate,
                   &authz, NULL, &creq, &sts, err, errcap) != 0) {
        goto done;
    }
    out->canonical_request = sbuf_take(&creq);
    out->string_to_sign = sbuf_take(&sts);
    out->authorization = sbuf_take(&authz);
    if (out->canonical_request == NULL || out->string_to_sign == NULL ||
        out->authorization == NULL) {
        s3_sigv4_test_free(out);
        s3_set_err(err, errcap, "out of memory");
        goto done;
    }
    rc = 0;

done:
    sb_free(&encpath);
    sb_free(&normpath);
    sb_free(&query);
    sb_free(&creq);
    sb_free(&sts);
    sb_free(&authz);
    return rc;
}

void s3_sigv4_test_free(s3_sigv4_test_out *out)
{
    if (out == NULL) {
        return;
    }
    free(out->canonical_request);
    free(out->string_to_sign);
    free(out->authorization);
    out->canonical_request = NULL;
    out->string_to_sign = NULL;
    out->authorization = NULL;
}

/* ------------------------------------------------------------------------- */
/* Environment / s3_endpoint configuration                                      */
/* ------------------------------------------------------------------------- */

static char *env_dup_nonempty(const char *name)
{
    const char *v = getenv(name);

    if (v == NULL) {
        return NULL;
    }
    while (*v == ' ' || *v == '\t') {
        v++;
    }
    if (*v == '\0') {
        return NULL;
    }
    {
        size_t n = strlen(v);
        char *out;

        while (n > 0 && (v[n - 1] == ' ' || v[n - 1] == '\t')) {
            n--;
        }
        out = xstrndup(v, n);
        if (out == NULL) {
            return NULL;
        }
        if (out[0] == '\0') {
            free(out);
            return NULL;
        }
        return out;
    }
}

static int ci_equal_n(const char *a, const char *b, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) {
            return 0;
        }
    }
    return 1;
}

typedef struct {
    char *scheme;
    char *host;
    int port;
    char *base_path;
} s3_endpoint;

static void endpoint_free(s3_endpoint *ep)
{
    if (ep == NULL) {
        return;
    }
    free(ep->scheme);
    free(ep->host);
    free(ep->base_path);
    ep->scheme = NULL;
    ep->host = NULL;
    ep->base_path = NULL;
}

static int parse_port(const char *s, size_t n, int *out)
{
    long v = 0;
    size_t i;

    if (n == 0 || n > 5u) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return -1;
        }
        v = v * 10 + (s[i] - '0');
        if (v > 65535) {
            return -1;
        }
    }
    if (v <= 0) {
        return -1;
    }
    *out = (int)v;
    return 0;
}

static int parse_endpoint(const char *url, s3_endpoint *ep,
                          char *err, size_t errcap)
{
    const char *sep;
    const char *authority;
    const char *auth_end;
    const char *host_start;
    const char *host_end;
    const char *port_start = NULL;
    const char *slash;
    size_t auth_len;

    memset(ep, 0, sizeof(*ep));
    sep = strstr(url, "://");
    if (sep == NULL) {
        s3_set_err(err, errcap, "s3_endpoint URL must start with http:// or https://");
        return -1;
    }
    ep->scheme = xstrndup(url, (size_t)(sep - url));
    if (ep->scheme == NULL) {
        s3_set_err(err, errcap, "out of memory");
        return -1;
    }
    if (strcmp(ep->scheme, "http") == 0) {
        ep->port = 80;
    } else if (strcmp(ep->scheme, "https") == 0) {
        ep->port = 443;
    } else {
        s3_set_err(err, errcap, "unsupported s3_endpoint scheme \"%s\" "
                "(only http and https)", ep->scheme);
        endpoint_free(ep);
        return -1;
    }

    authority = sep + 3;
    slash = strchr(authority, '/');
    auth_end = slash ? slash : authority + strlen(authority);
    auth_len = (size_t)(auth_end - authority);
    if (auth_len == 0) {
        s3_set_err(err, errcap, "s3_endpoint URL has an empty host");
        endpoint_free(ep);
        return -1;
    }
    if (memchr(authority, '@', auth_len) != NULL) {
        s3_set_err(err, errcap, "s3_endpoint URL must not contain userinfo");
        endpoint_free(ep);
        return -1;
    }

    host_start = authority;
    host_end = auth_end;
    if (*host_start == '[') {
        const char *rb = memchr(host_start, ']', auth_len);

        if (rb == NULL) {
            s3_set_err(err, errcap, "malformed IPv6 s3_endpoint host");
            endpoint_free(ep);
            return -1;
        }
        host_start++;
        host_end = rb;
        if (rb + 1 < auth_end) {
            if (rb[1] != ':') {
                s3_set_err(err, errcap, "malformed s3_endpoint host/port");
                endpoint_free(ep);
                return -1;
            }
            port_start = rb + 2;
        }
    } else {
        const char *colon = NULL;
        const char *q;

        for (q = authority; q < auth_end; q++) {
            if (*q == ':') {
                colon = q;
            }
        }
        if (colon != NULL) {
            host_end = colon;
            port_start = colon + 1;
        }
    }
    if (host_end <= host_start) {
        s3_set_err(err, errcap, "s3_endpoint URL has an empty host");
        endpoint_free(ep);
        return -1;
    }
    ep->host = xstrndup(host_start, (size_t)(host_end - host_start));
    if (ep->host == NULL) {
        s3_set_err(err, errcap, "out of memory");
        endpoint_free(ep);
        return -1;
    }
    if (port_start != NULL) {
        if (parse_port(port_start, (size_t)(auth_end - port_start),
                       &ep->port) != 0) {
            s3_set_err(err, errcap, "invalid port in s3_endpoint URL");
            endpoint_free(ep);
            return -1;
        }
    }

    /* Base path: normalize away a trailing slash; keep a leading one. */
    if (slash != NULL) {
        size_t blen = strlen(slash);

        while (blen > 0 && slash[blen - 1] == '/') {
            blen--;
        }
        if (blen > 0) {
            ep->base_path = xstrndup(slash, blen);
            if (ep->base_path == NULL) {
                s3_set_err(err, errcap, "out of memory");
                endpoint_free(ep);
                return -1;
            }
        }
    }
    if (ep->base_path != NULL && ep->base_path[0] != '/') {
        s3_set_err(err, errcap, "internal: base path must start with '/'");
        endpoint_free(ep);
        return -1;
    }
    return 0;
}

static int bucket_common_ok(const char *bucket, char *err, size_t errcap)
{
    size_t n;
    size_t i;

    if (bucket == NULL || bucket[0] == '\0') {
        s3_set_err(err, errcap, "bucket name is empty");
        return -1;
    }
    n = strlen(bucket);
    if (n > 255u) {
        s3_set_err(err, errcap, "bucket name is too long");
        return -1;
    }
    for (i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)bucket[i];

        if (ch <= 0x20 || ch == 0x7f) {
            s3_set_err(err, errcap, "bucket name contains whitespace/control "
                    "characters");
            return -1;
        }
        if (ch == '/' || ch == '#' || ch == '?' || ch == '\\') {
            s3_set_err(err, errcap, "bucket name contains an invalid character "
                    "('%c')", (char)ch);
            return -1;
        }
    }
    return 0;
}

static int bucket_dns_ok(const char *bucket, char *err, size_t errcap)
{
    size_t n = strlen(bucket);
    size_t i;
    int all_numeric_dots = 1;

    if (bucket_common_ok(bucket, err, errcap) != 0) {
        return -1;
    }
    if (n < 3u || n > 63u) {
        s3_set_err(err, errcap, "bucket name \"%s\" cannot be used in a DNS host "
                "(virtual-host style requires 3-63 characters); use path-style "
                "addressing", bucket);
        return -1;
    }
    for (i = 0; i < n; i++) {
        char ch = bucket[i];

        if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
              ch == '-' || ch == '.')) {
            if (ch >= 'A' && ch <= 'Z') {
                s3_set_err(err, errcap, "bucket name \"%s\" contains uppercase "
                        "letters, which is invalid for virtual-host style; use "
                        "path-style addressing", bucket);
            } else {
                s3_set_err(err, errcap, "bucket name \"%s\" contains a character "
                        "that is not DNS-safe for virtual-host style; use "
                        "path-style addressing", bucket);
            }
            return -1;
        }
        if (ch != '.' && ch != '-') {
            all_numeric_dots = 0;
        }
    }
    if (bucket[0] == '.' || bucket[0] == '-' || bucket[n - 1] == '.' ||
        bucket[n - 1] == '-') {
        s3_set_err(err, errcap, "bucket name \"%s\" must start and end with a "
                "letter or digit for virtual-host style; use path-style "
                "addressing", bucket);
        return -1;
    }
    if (strstr(bucket, "..") != NULL) {
        s3_set_err(err, errcap, "bucket name \"%s\" contains consecutive dots and "
                "is not DNS-safe; use path-style addressing", bucket);
        return -1;
    }
    if (all_numeric_dots) {
        s3_set_err(err, errcap, "bucket name \"%s\" looks like an IP address; "
                "use path-style addressing", bucket);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Client state                                                              */
/* ------------------------------------------------------------------------- */

struct s3_client {
    char *bucket;
    int path_style;
    char *s3_connect_host; /* DNS name actually resolved (bucket-prefixed) */
    char *host_header;  /* Host: value (may include :port)                */
    int port;
    int tls;
    char *base_path;
    char *region;
    char *access_key;
    char *secret_key;
    char *session_token; /* NULL when not configured */
    SSL_CTX *ssl_ctx;    /* NULL for plain HTTP */
};

static pthread_once_t sigpipe_once = PTHREAD_ONCE_INIT;

static void ignore_sigpipe_once(void)
{
    (void)signal(SIGPIPE, SIG_IGN);
}

static SSL_CTX *make_ssl_ctx(char *err, size_t errcap)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (ctx == NULL) {
        s3_set_err(err, errcap, "cannot create TLS context");
        return NULL;
    }
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        s3_set_err(err, errcap, "cannot require TLS 1.2");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        s3_set_err(err, errcap, "cannot load system CA certificates");
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    return ctx;
}

s3_client *s3_connect(const char *bucket, int path_style,
                      char *err, size_t errcap)
{
    s3_client *c;
    char *region = NULL;
    char *ak = NULL;
    char *sk = NULL;
    char *token = NULL;
    char *endpoint_url = NULL;
    char *custom_env = NULL;
    s3_endpoint ep;
    int resolved_path_style;
    int is_custom;
    size_t need;
    char *hh;

    memset(&ep, 0, sizeof(ep));
    if (err != NULL && errcap > 0) {
        err[0] = '\0';
    }
    if (bucket_common_ok(bucket, err, errcap) != 0) {
        return NULL;
    }

    region = env_dup_nonempty("AWS_REGION");
    if (region == NULL) {
        region = env_dup_nonempty("AWS_DEFAULT_REGION");
    }
    if (region == NULL) {
        s3_set_err(err, errcap, "AWS_REGION (or AWS_DEFAULT_REGION) is not set");
        goto fail;
    }
    ak = env_dup_nonempty("AWS_ACCESS_KEY_ID");
    if (ak == NULL) {
        s3_set_err(err, errcap, "AWS_ACCESS_KEY_ID is not set");
        goto fail;
    }
    sk = env_dup_nonempty("AWS_SECRET_ACCESS_KEY");
    if (sk == NULL) {
        s3_set_err(err, errcap, "AWS_SECRET_ACCESS_KEY is not set");
        goto fail;
    }
    token = env_dup_nonempty("AWS_SESSION_TOKEN");

    custom_env = env_dup_nonempty("AWS_ENDPOINT_URL_S3");
    if (custom_env == NULL) {
        custom_env = env_dup_nonempty("AWS_ENDPOINT_URL");
    }
    is_custom = (custom_env != NULL);
    if (custom_env != NULL) {
        endpoint_url = xstrdup(custom_env);
    } else {
        need = strlen(region) + 64u;
        endpoint_url = (char *)malloc(need);
        if (endpoint_url != NULL) {
            (void)snprintf(endpoint_url, need, "https://s3.%s.amazonaws.com",
                           region);
        }
    }
    if (endpoint_url == NULL) {
        s3_set_err(err, errcap, "out of memory");
        goto fail;
    }
    if (parse_endpoint(endpoint_url, &ep, err, errcap) != 0) {
        goto fail;
    }

    if (path_style < 0) {
        resolved_path_style = is_custom ? 1 : 0;
    } else {
        resolved_path_style = path_style ? 1 : 0;
    }
    if (!resolved_path_style && bucket_dns_ok(bucket, err, errcap) != 0) {
        goto fail;
    }

    c = (s3_client *)calloc(1u, sizeof(*c));
    if (c == NULL) {
        s3_set_err(err, errcap, "out of memory");
        goto fail;
    }
    c->port = ep.port;
    c->tls = (strcmp(ep.scheme, "https") == 0);
    c->path_style = resolved_path_style;

    if (!c->path_style) {
        need = strlen(bucket) + 1u + strlen(ep.host) + 1u;
        c->s3_connect_host = (char *)malloc(need);
        if (c->s3_connect_host != NULL) {
            (void)snprintf(c->s3_connect_host, need, "%s.%s", bucket, ep.host);
        }
    } else {
        c->s3_connect_host = xstrdup(ep.host);
    }
    if (c->s3_connect_host == NULL) {
        s3_set_err(err, errcap, "out of memory");
        free(c);
        goto fail;
    }

    need = strlen(c->s3_connect_host) + 16u;
    hh = (char *)malloc(need);
    if (hh == NULL) {
        s3_set_err(err, errcap, "out of memory");
        free(c->s3_connect_host);
        free(c);
        goto fail;
    }
    if (c->port == (c->tls ? 443 : 80)) {
        (void)snprintf(hh, need, "%s", c->s3_connect_host);
    } else {
        (void)snprintf(hh, need, "%s:%d", c->s3_connect_host, c->port);
    }
    c->host_header = hh;

    c->bucket = xstrdup(bucket);
    c->region = region;
    c->access_key = ak;
    c->secret_key = sk;
    c->session_token = token;
    c->base_path = ep.base_path ? xstrdup(ep.base_path) : xstrdup("");
    region = NULL;
    ak = NULL;
    sk = NULL;
    token = NULL;
    ep.base_path = NULL;

    if (c->bucket == NULL || c->base_path == NULL) {
        s3_set_err(err, errcap, "out of memory");
        s3_close(c);
        goto fail;
    }
    if (c->tls) {
        c->ssl_ctx = make_ssl_ctx(err, errcap);
        if (c->ssl_ctx == NULL) {
            s3_close(c);
            goto fail;
        }
    }
    (void)pthread_once(&sigpipe_once, ignore_sigpipe_once);

    free(region);
    free(ak);
    free(sk);
    free(token);
    free(custom_env);
    free(endpoint_url);
    endpoint_free(&ep);
    return c;

fail:
    free(region);
    free(ak);
    free(sk);
    free(token);
    free(custom_env);
    free(endpoint_url);
    endpoint_free(&ep);
    return NULL;
}

void s3_close(s3_client *c)
{
    if (c == NULL) {
        return;
    }
    if (c->ssl_ctx != NULL) {
        SSL_CTX_free(c->ssl_ctx);
    }
    free(c->bucket);
    free(c->s3_connect_host);
    free(c->host_header);
    free(c->base_path);
    if (c->region != NULL) {
        memset(c->region, 0, strlen(c->region));
    }
    free(c->region);
    if (c->access_key != NULL) {
        memset(c->access_key, 0, strlen(c->access_key));
    }
    free(c->access_key);
    if (c->secret_key != NULL) {
        memset(c->secret_key, 0, strlen(c->secret_key));
    }
    free(c->secret_key);
    if (c->session_token != NULL) {
        memset(c->session_token, 0, strlen(c->session_token));
    }
    free(c->session_token);
    memset(c, 0, sizeof(*c));
    free(c);
}

/* ------------------------------------------------------------------------- */
/* TCP / TLS transport                                                       */
/* ------------------------------------------------------------------------- */

typedef struct {
    int fd;
    SSL *ssl;
    int tls;
} s3_conn;

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int set_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static void set_io_timeouts(int fd)
{
    struct timeval tv;

    tv.tv_sec = S3_IO_TIMEOUT_SEC;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int s3_connect_tcp(const char *host, int port, char *err, size_t errcap)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    char portstr[16];
    int rc;
    int fd = -1;
    int last_errno = 0;

    (void)snprintf(portstr, sizeof(portstr), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) {
        s3_set_err(err, errcap, "DNS lookup failed for \"%s\": %s", host,
                gai_strerror(rc));
        return -1;
    }
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        struct pollfd pfd;
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        int cr;

        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }
        (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
        if (set_nonblocking(fd) != 0) {
            last_errno = errno;
            close(fd);
            fd = -1;
            continue;
        }
        cr = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (cr != 0 && errno != EINPROGRESS) {
            last_errno = errno;
            close(fd);
            fd = -1;
            continue;
        }
        if (cr != 0) {
            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            cr = poll(&pfd, 1, S3_CONNECT_TIMEOUT_MS);
            if (cr <= 0) {
                last_errno = (cr == 0) ? ETIMEDOUT : errno;
                close(fd);
                fd = -1;
                continue;
            }
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0 ||
                soerr != 0) {
                last_errno = (soerr != 0) ? soerr : errno;
                close(fd);
                fd = -1;
                continue;
            }
        }
        if (set_blocking(fd) != 0) {
            last_errno = errno;
            close(fd);
            fd = -1;
            continue;
        }
        set_io_timeouts(fd);
        break;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        s3_set_err(err, errcap, "cannot connect to %s:%d: %s", host, port,
                strerror(last_errno ? last_errno : ECONNREFUSED));
        return -1;
    }
    return fd;
}

static int is_ip_literal(const char *host)
{
    struct in_addr a4;
    struct in6_addr a6;

    return inet_pton(AF_INET, host, &a4) == 1 ||
           inet_pton(AF_INET6, host, &a6) == 1;
}

static void s3_conn_close(s3_conn *cn)
{
    if (cn->ssl != NULL) {
        (void)SSL_shutdown(cn->ssl);
        SSL_free(cn->ssl);
        cn->ssl = NULL;
    }
    if (cn->fd >= 0) {
        close(cn->fd);
        cn->fd = -1;
    }
}

static int s3_conn_open(s3_client *c, s3_conn *cn, char *err, size_t errcap)
{
    int fd;
    SSL *ssl;

    memset(cn, 0, sizeof(*cn));
    cn->fd = -1;
    cn->tls = c->tls;
    fd = s3_connect_tcp(c->s3_connect_host, c->port, err, errcap);
    if (fd < 0) {
        return -1;
    }
    cn->fd = fd;
    if (!c->tls) {
        return 0;
    }
    ssl = SSL_new(c->ssl_ctx);
    if (ssl == NULL) {
        s3_set_err(err, errcap, "SSL_new failed");
        s3_conn_close(cn);
        return -1;
    }
    cn->ssl = ssl;
    if (SSL_set_fd(ssl, fd) != 1) {
        s3_set_err(err, errcap, "SSL_set_fd failed");
        s3_conn_close(cn);
        return -1;
    }
    if (!is_ip_literal(c->s3_connect_host)) {
        if (SSL_set_tlsext_host_name(ssl, c->s3_connect_host) != 1) {
            s3_set_err(err, errcap, "cannot set TLS SNI host");
            s3_conn_close(cn);
            return -1;
        }
    }
    {
        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);

        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (is_ip_literal(c->s3_connect_host)) {
            if (X509_VERIFY_PARAM_set1_ip_asc(param, c->s3_connect_host) != 1) {
                s3_set_err(err, errcap, "cannot set TLS IP verification");
                s3_conn_close(cn);
                return -1;
            }
        } else if (X509_VERIFY_PARAM_set1_host(param, c->s3_connect_host, 0) != 1) {
            s3_set_err(err, errcap, "cannot set TLS hostname verification");
            s3_conn_close(cn);
            return -1;
        }
    }
    ERR_clear_error();
    if (SSL_connect(ssl) != 1) {
        unsigned long e = ERR_get_error();
        char ebuf[256];

        if (e != 0) {
            ERR_error_string_n(e, ebuf, sizeof(ebuf));
            s3_set_err(err, errcap, "TLS handshake failed: %s", ebuf);
        } else {
            long vr = SSL_get_verify_result(ssl);

            if (vr != X509_V_OK) {
                s3_set_err(err, errcap, "TLS certificate verification failed: %s",
                        X509_verify_cert_error_string(vr));
            } else {
                s3_set_err(err, errcap, "TLS handshake failed");
            }
        }
        s3_conn_close(cn);
        return -1;
    }
    return 0;
}

static int s3_conn_write_all(s3_conn *cn, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;

    while (len > 0) {
        size_t chunk = (len > (1024u * 1024u)) ? (1024u * 1024u) : len;
        int n;

        if (cn->tls) {
            n = SSL_write(cn->ssl, p, (int)chunk);
            if (n <= 0) {
                return -1;
            }
        } else {
            ssize_t r = send(cn->fd, p, chunk, MSG_NOSIGNAL);

            if (r < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            n = (int)r;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static ssize_t s3_conn_read(s3_conn *cn, void *buf, size_t cap)
{
    for (;;) {
        if (cn->tls) {
            int n = SSL_read(cn->ssl, buf, (int)cap);
            int e;

            if (n > 0) {
                return n;
            }
            e = SSL_get_error(cn->ssl, n);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            if (e == SSL_ERROR_ZERO_RETURN) {
                return 0;
            }
            return -1;
        } else {
            ssize_t r = recv(cn->fd, buf, cap, 0);

            if (r >= 0) {
                return r;
            }
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Response stream + HTTP exchange                                           */
/* ------------------------------------------------------------------------- */

typedef struct {
    s3_conn *cn;
    unsigned char *buf;
    size_t len;
    size_t cap;
    size_t pos;
    int eof;
} s3_rstream;

static void rs_init(s3_rstream *rs, s3_conn *cn)
{
    rs->cn = cn;
    rs->buf = NULL;
    rs->len = 0;
    rs->cap = 0;
    rs->pos = 0;
    rs->eof = 0;
}

static void rs_free(s3_rstream *rs)
{
    free(rs->buf);
    rs->buf = NULL;
    rs->len = 0;
    rs->cap = 0;
    rs->pos = 0;
}

static int rs_fill(s3_rstream *rs)
{
    size_t avail = rs->len - rs->pos;
    ssize_t n;

    if (rs->eof) {
        return 0;
    }
    if (rs->pos > 0 && (rs->pos > rs->cap / 2u || rs->len == rs->cap)) {
        if (avail > 0) {
            memmove(rs->buf, rs->buf + rs->pos, avail);
        }
        rs->len = avail;
        rs->pos = 0;
    }
    if (rs->len + S3_READ_CHUNK > rs->cap) {
        size_t ncap = rs->cap ? rs->cap * 2u : (S3_READ_CHUNK * 2u);
        unsigned char *nb;

        while (ncap < rs->len + S3_READ_CHUNK) {
            ncap *= 2u;
        }
        if (ncap > S3_STREAM_CAP) {
            ncap = S3_STREAM_CAP;
        }
        if (ncap <= rs->len) {
            return -1;
        }
        nb = (unsigned char *)realloc(rs->buf, ncap);
        if (nb == NULL) {
            return -1;
        }
        rs->buf = nb;
        rs->cap = ncap;
    }
    n = s3_conn_read(rs->cn, rs->buf + rs->len, rs->cap - rs->len);
    if (n < 0) {
        return -1;
    }
    if (n == 0) {
        rs->eof = 1;
        return 0;
    }
    rs->len += (size_t)n;
    return 1;
}

static int rs_ensure(s3_rstream *rs, size_t need)
{
    while (rs->len - rs->pos < need) {
        int r = rs_fill(rs);

        if (r <= 0) {
            return -1;
        }
    }
    return 0;
}

/* Find needle in [from, len); returns index or (size_t)-1. */
static size_t find_bytes(const unsigned char *hay, size_t haylen,
                         const char *needle, size_t nlen)
{
    size_t i;

    if (nlen == 0 || haylen < nlen) {
        return (size_t)-1;
    }
    for (i = 0; i + nlen <= haylen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) {
            return i;
        }
    }
    return (size_t)-1;
}

static char *header_value_dup(const unsigned char *block, size_t blocklen,
                              const char *name)
{
    size_t pos = 0;
    size_t namelen = strlen(name);

    while (pos < blocklen) {
        size_t eol = pos;
        size_t colon;
        size_t vstart;
        size_t vend;

        while (eol < blocklen && block[eol] != '\r') {
            eol++;
        }
        if (eol == pos) {
            break;
        }
        colon = pos;
        while (colon < eol && block[colon] != ':') {
            colon++;
        }
        if (colon < eol &&
            (colon - pos) == namelen &&
            ci_equal_n((const char *)block + pos, name, namelen)) {
            vstart = colon + 1u;
            while (vstart < eol &&
                   (block[vstart] == ' ' || block[vstart] == '\t')) {
                vstart++;
            }
            vend = eol;
            while (vend > vstart &&
                   (block[vend - 1] == ' ' || block[vend - 1] == '\t')) {
                vend--;
            }
            return xstrndup((const char *)block + vstart, vend - vstart);
        }
        pos = (eol + 2u <= blocklen) ? eol + 2u : blocklen;
    }
    return NULL;
}

static int header_contains_token(const unsigned char *block, size_t blocklen,
                                 const char *name, const char *token)
{
    char *v = header_value_dup(block, blocklen, name);
    int found = 0;

    if (v != NULL) {
        const char *p = v;
        size_t tlen = strlen(token);

        while (*p != '\0') {
            const char *st = p;
            size_t n;

            while (*p != '\0' && *p != ',' && *p != ' ' && *p != '\t') {
                p++;
            }
            n = (size_t)(p - st);
            if (n == tlen && ci_equal_n(st, token, n)) {
                found = 1;
                break;
            }
            if (*p != '\0') {
                p++;
            }
        }
        free(v);
    }
    return found;
}

static int parse_status_line(const unsigned char *buf, size_t len, int *status)
{
    size_t i = 0;

    if (len < 12u) {
        return -1;
    }
    if (memcmp(buf, "HTTP/1.", 7u) != 0) {
        return -1;
    }
    while (i < len && buf[i] != ' ') {
        i++;
    }
    if (i + 3u >= len) {
        return -1;
    }
    i++;
    if (buf[i] < '0' || buf[i] > '9' || buf[i + 1] < '0' || buf[i + 1] > '9' ||
        buf[i + 2] < '0' || buf[i + 2] > '9') {
        return -1;
    }
    *status = (buf[i] - '0') * 100 + (buf[i + 1] - '0') * 10 +
              (buf[i + 2] - '0');
    if (*status < 100 || *status > 599) {
        return -1;
    }
    return 0;
}

typedef struct {
    int status;
    unsigned char *body;
    size_t body_len;
    long long expiry_ms;
    int has_expiry;
} s3_http_response;

static void http_response_free(s3_http_response *r)
{
    free(r->body);
    r->body = NULL;
    r->body_len = 0;
}

static int parse_content_length(const char *v, long long *out)
{
    char *end = NULL;
    long long n;

    if (v == NULL || v[0] == '\0') {
        return -1;
    }
    errno = 0;
    n = strtoll(v, &end, 10);
    if (errno != 0 || end == v || *end != '\0' || n < 0) {
        return -1;
    }
    *out = n;
    return 0;
}

static int s3_read_chunked_body(s3_rstream *rs, unsigned char **out,
                             size_t *outlen, char *err, size_t errcap)
{
    s3_sbuf body;

    sb_init(&body);
    for (;;) {
        size_t line_end = (size_t)-1;
        size_t size = 0;
        size_t i;
        int digits = 0;

        /* Read the chunk-size line. */
        for (;;) {
            size_t start = rs->pos;

            while (start < rs->len) {
                size_t idx = find_bytes(rs->buf + start, rs->len - start,
                                        "\r\n", 2u);

                if (idx != (size_t)-1) {
                    line_end = start + idx;
                    break;
                }
                break; /* need more data */
            }
            if (line_end != (size_t)-1) {
                break;
            }
            if (rs->len - rs->pos > 1024u) {
                s3_set_err(err, errcap, "chunked response: chunk header too long");
                sb_free(&body);
                return -1;
            }
            if (rs_fill(rs) <= 0) {
                s3_set_err(err, errcap, "chunked response: truncated chunk header");
                sb_free(&body);
                return -1;
            }
        }
        i = rs->pos;
        while (i < line_end) {
            int hd;
            char ch = (char)rs->buf[i];

            if (ch == ';' || ch == ' ' || ch == '\t') {
                break;
            }
            hd = hex_digit((unsigned char)ch);
            if (hd < 0) {
                s3_set_err(err, errcap, "chunked response: invalid chunk size");
                sb_free(&body);
                return -1;
            }
            if (size > (SIZE_MAX - (size_t)hd) / 16u) {
                s3_set_err(err, errcap, "chunked response: chunk size overflow");
                sb_free(&body);
                return -1;
            }
            size = size * 16u + (size_t)hd;
            digits++;
            i++;
        }
        if (digits == 0) {
            s3_set_err(err, errcap, "chunked response: missing chunk size");
            sb_free(&body);
            return -1;
        }
        rs->pos = line_end + 2u;
        if (size == 0) {
            /* Consume optional trailers up to the terminating empty line. */
            for (;;) {
                size_t idx;
                size_t tstart = rs->pos;

                while (tstart < rs->len) {
                    idx = find_bytes(rs->buf + tstart, rs->len - tstart,
                                     "\r\n", 2u);
                    if (idx == (size_t)-1) {
                        break;
                    }
                    if (idx == 0) {
                        rs->pos = tstart + 2u;
                        goto chunk_done;
                    }
                    tstart += idx + 2u;
                }
                if (rs->len - rs->pos > 4096u) {
                    s3_set_err(err, errcap, "chunked response: trailers too long");
                    sb_free(&body);
                    return -1;
                }
                if (rs_fill(rs) <= 0) {
                    s3_set_err(err, errcap, "chunked response: truncated trailers");
                    sb_free(&body);
                    return -1;
                }
            }
        } else {
            if (size > S3_MAX_BODY_BYTES - body.len) {
                s3_set_err(err, errcap, "chunked response body exceeds %u bytes",
                        (unsigned)S3_MAX_BODY_BYTES);
                sb_free(&body);
                return -1;
            }
            if (rs_ensure(rs, size + 2u) != 0) {
                s3_set_err(err, errcap, "chunked response: truncated chunk data");
                sb_free(&body);
                return -1;
            }
            if (rs->buf[rs->pos + size] != '\r' ||
                rs->buf[rs->pos + size + 1u] != '\n') {
                s3_set_err(err, errcap, "chunked response: missing chunk CRLF");
                sb_free(&body);
                return -1;
            }
            if (sb_append(&body, rs->buf + rs->pos, size) != 0) {
                s3_set_err(err, errcap, "out of memory");
                sb_free(&body);
                return -1;
            }
            rs->pos += size + 2u;
        }
    }
chunk_done:
    *out = (unsigned char *)body.p;
    *outlen = body.len;
    if (*out == NULL) {
        *out = (unsigned char *)malloc(1u);
        if (*out == NULL) {
            s3_set_err(err, errcap, "out of memory");
            return -1;
        }
        *outlen = 0;
    }
    return 0;
}

/*
 * Returns 0 on success, 1 on a retryable transport error, -1 on a
 * non-retryable/protocol error.
 */
static int http_exchange(s3_client *c, const char *method, const char *path,
                         const char *const *hdr_lines, size_t nhdrs,
                         const char *authorization,
                         const unsigned char *body, size_t bodylen,
                         s3_http_response *resp, char *err, size_t errcap)
{
    s3_conn cn;
    s3_rstream rs;
    s3_sbuf req;
    size_t i;
    size_t hdr_end = (size_t)-1;
    size_t blocklen;
    int chunked = 0;
    long long content_length = 0;
    int has_cl = 0;
    int rc = 1;

    memset(resp, 0, sizeof(*resp));
    sb_init(&req);
    memset(&cn, 0, sizeof(cn));
    cn.fd = -1;

    if (s3_conn_open(c, &cn, err, errcap) != 0) {
        return 1;
    }
    rs_init(&rs, &cn);
    if (sb_printf(&req, "%s %s HTTP/1.1\r\n", method, path) != 0) {
        s3_set_err(err, errcap, "out of memory");
        rc = -1;
        goto out;
    }
    for (i = 0; i < nhdrs; i++) {
        if (sb_puts(&req, hdr_lines[i]) != 0 || sb_puts(&req, "\r\n") != 0) {
            s3_set_err(err, errcap, "out of memory");
            rc = -1;
            goto out;
        }
    }
    if (sb_puts(&req, "Authorization: ") != 0 ||
        sb_puts(&req, authorization) != 0 ||
        sb_puts(&req, "\r\n") != 0) {
        s3_set_err(err, errcap, "out of memory");
        rc = -1;
        goto out;
    }
    if ((body != NULL || strcmp(method, "PUT") == 0)) {
        if (sb_printf(&req, "Content-Length: %zu\r\n", bodylen) != 0) {
            s3_set_err(err, errcap, "out of memory");
            rc = -1;
            goto out;
        }
    }
    if (sb_puts(&req, "Connection: close\r\n\r\n") != 0) {
        s3_set_err(err, errcap, "out of memory");
        rc = -1;
        goto out;
    }
    if (bodylen > 0) {
        if (sb_reserve(&req, bodylen) != 0) {
            s3_set_err(err, errcap, "out of memory");
            rc = -1;
            goto out;
        }
        memcpy(req.p + req.len, body, bodylen);
        req.len += bodylen;
        req.p[req.len] = '\0';
    }
    if (s3_conn_write_all(&cn, req.p, req.len) != 0) {
        s3_set_err(err, errcap, "network error: failed to send request");
        rc = 1;
        goto out;
    }

    /* Read the response header block. */
    for (;;) {
        size_t avail = rs.len - rs.pos;
        size_t idx = find_bytes(rs.buf + rs.pos, avail, "\r\n\r\n", 4u);

        if (idx != (size_t)-1) {
            hdr_end = rs.pos + idx;
            break;
        }
        if (avail > S3_MAX_HEADER_BYTES) {
            s3_set_err(err, errcap, "response header block exceeds %u bytes",
                    (unsigned)S3_MAX_HEADER_BYTES);
            rc = -1;
            goto out;
        }
        {
            int f = rs_fill(&rs);

            if (f < 0) {
                s3_set_err(err, errcap, "network error: failed to read response");
                rc = 1;
                goto out;
            }
            if (f == 0) {
                s3_set_err(err, errcap, "network error: connection closed before "
                        "response headers");
                rc = 1;
                goto out;
            }
        }
    }
    blocklen = hdr_end - rs.pos;
    if (blocklen > S3_MAX_HEADER_BYTES) {
        s3_set_err(err, errcap, "response header block exceeds %u bytes",
                (unsigned)S3_MAX_HEADER_BYTES);
        rc = -1;
        goto out;
    }
    if (parse_status_line(rs.buf + rs.pos, blocklen, &resp->status) != 0) {
        s3_set_err(err, errcap, "malformed HTTP status line");
        rc = -1;
        goto out;
    }

    chunked = header_contains_token(rs.buf + rs.pos, blocklen,
                                    "transfer-encoding", "chunked");
    {
        char *cl = header_value_dup(rs.buf + rs.pos, blocklen,
                                    "content-length");

        if (cl != NULL) {
            has_cl = 1;
            if (parse_content_length(cl, &content_length) != 0) {
                free(cl);
                s3_set_err(err, errcap, "invalid Content-Length in response");
                rc = -1;
                goto out;
            }
            free(cl);
        }
    }
    {
        char *ex = header_value_dup(rs.buf + rs.pos, blocklen,
                                    S3_META_EXPIRY);

        if (ex != NULL) {
            char *end = NULL;
            long long v;

            errno = 0;
            v = strtoll(ex, &end, 10);
            if (errno == 0 && end != ex && *end == '\0' && v > 0) {
                resp->expiry_ms = v;
                resp->has_expiry = 1;
            }
            free(ex);
        }
    }
    rs.pos = hdr_end + 4u;

    if (resp->status == 204 || resp->status == 304 ||
        strcmp(method, "HEAD") == 0) {
        rc = 0;
        goto out;
    }
    if (chunked) {
        if (s3_read_chunked_body(&rs, &resp->body, &resp->body_len,
                              err, errcap) != 0) {
            rc = -1;
            goto out;
        }
        rc = 0;
        goto out;
    }
    if (has_cl) {
        if ((unsigned long long)content_length > S3_MAX_BODY_BYTES) {
            s3_set_err(err, errcap, "response body exceeds %u bytes",
                    (unsigned)S3_MAX_BODY_BYTES);
            rc = -1;
            goto out;
        }
        if (rs_ensure(&rs, (size_t)content_length) != 0) {
            s3_set_err(err, errcap, "network error: truncated response body");
            rc = 1;
            goto out;
        }
        resp->body = (unsigned char *)malloc((size_t)content_length + 1u);
        if (resp->body == NULL) {
            s3_set_err(err, errcap, "out of memory");
            rc = -1;
            goto out;
        }
        if (content_length > 0) {
            memcpy(resp->body, rs.buf + rs.pos, (size_t)content_length);
        }
        resp->body[content_length] = '\0';
        resp->body_len = (size_t)content_length;
        rs.pos += (size_t)content_length;
        rc = 0;
        goto out;
    }

    /* No framing headers: read until EOF (Connection: close). */
    {
        s3_sbuf acc;

        sb_init(&acc);
        for (;;) {
            size_t avail = rs.len - rs.pos;
            int f;

            if (avail > 0) {
                if (acc.len + avail > S3_MAX_BODY_BYTES) {
                    s3_set_err(err, errcap, "response body exceeds %u bytes",
                            (unsigned)S3_MAX_BODY_BYTES);
                    sb_free(&acc);
                    rc = -1;
                    goto out;
                }
                if (sb_append(&acc, rs.buf + rs.pos, avail) != 0) {
                    s3_set_err(err, errcap, "out of memory");
                    sb_free(&acc);
                    rc = -1;
                    goto out;
                }
                rs.pos = rs.len;
            }
            f = rs_fill(&rs);
            if (f < 0) {
                s3_set_err(err, errcap, "network error: failed to read body");
                sb_free(&acc);
                rc = 1;
                goto out;
            }
            if (f == 0) {
                break;
            }
        }
        resp->body = (unsigned char *)acc.p;
        resp->body_len = acc.len;
        if (resp->body == NULL) {
            resp->body = (unsigned char *)malloc(1u);
            if (resp->body == NULL) {
                s3_set_err(err, errcap, "out of memory");
                rc = -1;
                goto out;
            }
        }
        rc = 0;
    }

out:
    sb_free(&req);
    rs_free(&rs);
    s3_conn_close(&cn);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* S3 XML error parsing                                                      */
/* ------------------------------------------------------------------------- */

static char *xml_extract(const unsigned char *body, size_t len,
                         const char *tag)
{
    char open[64];
    char close[64];
    const char *p;
    size_t openlen;
    size_t closelen;
    size_t start;
    size_t end;

    (void)snprintf(open, sizeof(open), "<%s>", tag);
    (void)snprintf(close, sizeof(close), "</%s>", tag);
    openlen = strlen(open);
    closelen = strlen(close);
    if (len < openlen + closelen) {
        return NULL;
    }
    p = (const char *)body;
    {
        size_t i;
        size_t idx = (size_t)-1;

        for (i = 0; i + openlen <= len; i++) {
            if (memcmp(p + i, open, openlen) == 0) {
                idx = i;
                break;
            }
        }
        if (idx == (size_t)-1) {
            return NULL;
        }
        start = idx + openlen;
    }
    {
        size_t i = start;
        size_t idx = (size_t)-1;

        for (; i + closelen <= len; i++) {
            if (memcmp(p + i, close, closelen) == 0) {
                idx = i;
                break;
            }
        }
        if (idx == (size_t)-1) {
            return NULL;
        }
        end = idx;
    }
    while (start < end && (p[start] == ' ' || p[start] == '\t' ||
                           p[start] == '\r' || p[start] == '\n')) {
        start++;
    }
    while (end > start && (p[end - 1] == ' ' || p[end - 1] == '\t' ||
                           p[end - 1] == '\r' || p[end - 1] == '\n')) {
        end--;
    }
    return xstrndup(p + start, end - start);
}

static void xml_unescape_inplace(char *s)
{
    char *src = s;
    char *dst = s;

    while (*src != '\0') {
        if (*src == '&') {
            if (strncmp(src, "&amp;", 5u) == 0) {
                *dst++ = '&';
                src += 5;
                continue;
            }
            if (strncmp(src, "&lt;", 4u) == 0) {
                *dst++ = '<';
                src += 4;
                continue;
            }
            if (strncmp(src, "&gt;", 4u) == 0) {
                *dst++ = '>';
                src += 4;
                continue;
            }
            if (strncmp(src, "&quot;", 6u) == 0) {
                *dst++ = '"';
                src += 6;
                continue;
            }
            if (strncmp(src, "&apos;", 6u) == 0) {
                *dst++ = '\'';
                src += 6;
                continue;
            }
        }
        *dst++ = *src++;
    }
    *dst = '\0';
}

static void set_s3_error(s3_http_response *r, char *err, size_t errcap)
{
    char *code = xml_extract(r->body, r->body_len, "Code");
    char *msg = xml_extract(r->body, r->body_len, "Message");

    if (code != NULL) {
        xml_unescape_inplace(code);
    }
    if (msg != NULL) {
        xml_unescape_inplace(msg);
    }
    if (code != NULL && msg != NULL && msg[0] != '\0') {
        s3_set_err(err, errcap, "S3 HTTP %d %s: %s", r->status, code, msg);
    } else if (code != NULL) {
        s3_set_err(err, errcap, "S3 HTTP %d %s", r->status, code);
    } else {
        s3_set_err(err, errcap, "S3 HTTP %d", r->status);
    }
    free(code);
    free(msg);
}

/* ------------------------------------------------------------------------- */
/* Time + request construction                                               */
/* ------------------------------------------------------------------------- */

static long long s3_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (long long)ts.tv_sec * 1000LL + (long long)(ts.tv_nsec / 1000000L);
}

static void s3_amzdate_now(char out[17])
{
    time_t t = time(NULL);
    struct tm tmv;

    if (t == (time_t)-1 || gmtime_r(&t, &tmv) == NULL) {
        (void)snprintf(out, 17u, "19700101T000000Z");
        return;
    }
    (void)strftime(out, 17u, "%Y%m%dT%H%M%SZ", &tmv);
}

static int build_object_path(const s3_client *c, const char *key, s3_sbuf *out)
{
    if (c->base_path[0] != '\0') {
        if (sb_puts(out, c->base_path) != 0) {
            return -1;
        }
    }
    if (sb_putc(out, '/') != 0) {
        return -1;
    }
    if (c->path_style) {
        if (pct_encode((const unsigned char *)c->bucket,
                       strlen(c->bucket), 0, out) != 0) {
            return -1;
        }
        if (sb_putc(out, '/') != 0) {
            return -1;
        }
    }
    if (pct_encode((const unsigned char *)key, strlen(key), 1, out) != 0) {
        return -1;
    }
    return 0;
}

/*
 * Perform one signed S3 request. Retries exactly once on transport errors
 * (never on a received 4xx/5xx reply).
 */
static int s3_request(s3_client *c, const char *method, const char *key,
                      const unsigned char *body, size_t bodylen,
                      long long expiry_ms, s3_http_response *resp,
                      char *err, size_t errcap)
{
    s3_sbuf path, authz;
    char payload[65];
    char amzdate[17];
    char host_line[1200];
    char hash_line[96];
    char date_line[64];
    char meta_line[96];
    char token_line[8192];
    const char *hdr_lines[5];
    size_t nhdrs = 0;
    int attempt;
    int rc = -1;

    sb_init(&path);
    sb_init(&authz);
    memset(resp, 0, sizeof(*resp));

    if (build_object_path(c, key, &path) != 0) {
        s3_set_err(err, errcap, "out of memory");
        goto out;
    }
    if (s3_sha256_hex(body != NULL ? body : (const unsigned char *)"",
                   bodylen, payload) != 0) {
        s3_set_err(err, errcap, "SHA-256 failed");
        goto out;
    }
    s3_amzdate_now(amzdate);

    if (snprintf(host_line, sizeof(host_line), "Host: %s",
                 c->host_header) >= (int)sizeof(host_line)) {
        s3_set_err(err, errcap, "Host header too long");
        goto out;
    }
    if (snprintf(hash_line, sizeof(hash_line),
                 "x-amz-content-sha256: %s", payload) >=
        (int)sizeof(hash_line)) {
        s3_set_err(err, errcap, "internal: hash header too long");
        goto out;
    }
    if (snprintf(date_line, sizeof(date_line), "x-amz-date: %s",
                 amzdate) >= (int)sizeof(date_line)) {
        s3_set_err(err, errcap, "internal: date header too long");
        goto out;
    }
    hdr_lines[nhdrs++] = host_line;
    hdr_lines[nhdrs++] = hash_line;
    hdr_lines[nhdrs++] = date_line;
    if (expiry_ms > 0) {
        if (snprintf(meta_line, sizeof(meta_line), "%s: %lld",
                     S3_META_EXPIRY, expiry_ms) >=
            (int)sizeof(meta_line)) {
            s3_set_err(err, errcap, "internal: metadata header too long");
            goto out;
        }
        hdr_lines[nhdrs++] = meta_line;
    }
    if (c->session_token != NULL) {
        if (snprintf(token_line, sizeof(token_line),
                     "x-amz-security-token: %s", c->session_token) >=
            (int)sizeof(token_line)) {
            s3_set_err(err, errcap, "AWS_SESSION_TOKEN is too long");
            goto out;
        }
        hdr_lines[nhdrs++] = token_line;
    }

    if (sigv4_sign(method, path.p, "",
                   hdr_lines, nhdrs, payload,
                   c->access_key, c->secret_key, c->region, "s3", amzdate,
                   &authz, NULL, NULL, NULL, err, errcap) != 0) {
        goto out;
    }

    for (attempt = 0; attempt < 2; attempt++) {
        int hr = http_exchange(c, method, path.p, hdr_lines, nhdrs, authz.p,
                               body, bodylen, resp, err, errcap);

        if (hr == 0) {
            rc = 0;
            break;
        }
        http_response_free(resp);
        memset(resp, 0, sizeof(*resp));
        if (hr != 1 || attempt == 1) {
            rc = -1;
            break;
        }
        /* Transport failure: retry once with a fresh connection. */
    }

out:
    sb_free(&path);
    sb_free(&authz);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Public S3 operations                                                      */
/* ------------------------------------------------------------------------- */

int s3_ping(s3_client *c, char *err, size_t errcap)
{
    s3_http_response r;
    int rc;

    if (c == NULL) {
        s3_set_err(err, errcap, "s3_ping: null client");
        return -1;
    }
    if (s3_request(c, "GET", S3_PROBE_KEY, NULL, 0, 0, &r,
                   err, errcap) != 0) {
        return -1;
    }
    if (r.status == 404) {
        http_response_free(&r);
        return 0;
    }
    if (r.status >= 200 && r.status < 300) {
        http_response_free(&r);
        return 0;
    }
    {
        char *code = xml_extract(r.body, r.body_len, "Code");

        if (code != NULL) {
            xml_unescape_inplace(code);
            if (strcmp(code, "NoSuchKey") == 0) {
                free(code);
                http_response_free(&r);
                return 0;
            }
            free(code);
        }
    }
    set_s3_error(&r, err, errcap);
    http_response_free(&r);
    rc = -1;
    return rc;
}

int s3_get(s3_client *c, const char *key, unsigned char **val, size_t *vallen,
           long long *expiry_ms, char *err, size_t errcap)
{
    s3_http_response r;
    char *code;

    if (c == NULL || key == NULL || val == NULL || vallen == NULL ||
        expiry_ms == NULL) {
        s3_set_err(err, errcap, "s3_get: invalid arguments");
        return -1;
    }
    *val = NULL;
    *vallen = 0;
    *expiry_ms = 0;

    if (s3_request(c, "GET", key, NULL, 0, 0, &r, err, errcap) != 0) {
        return -1;
    }
    if (r.status == 404) {
        http_response_free(&r);
        return 0;
    }
    if (r.status >= 200 && r.status < 300) {
        if (r.has_expiry && r.expiry_ms > 0 && r.expiry_ms <= s3_now_ms()) {
            char ignore[1];

            ignore[0] = '\0';
            http_response_free(&r);
            (void)s3_delete(c, key, ignore, 0);
            return 0;
        }
        *val = r.body;
        *vallen = r.body_len;
        *expiry_ms = r.has_expiry ? r.expiry_ms : 0;
        r.body = NULL;
        r.body_len = 0;
        http_response_free(&r);
        return 1;
    }
    code = xml_extract(r.body, r.body_len, "Code");
    if (code != NULL) {
        xml_unescape_inplace(code);
        if (strcmp(code, "NoSuchKey") == 0) {
            free(code);
            http_response_free(&r);
            return 0;
        }
        free(code);
    }
    set_s3_error(&r, err, errcap);
    http_response_free(&r);
    return -1;
}

int s3_put(s3_client *c, const char *key, const unsigned char *val,
           size_t vallen, long long expiry_ms, char *err, size_t errcap)
{
    s3_http_response r;
    int rc;

    if (c == NULL || key == NULL || (val == NULL && vallen > 0)) {
        s3_set_err(err, errcap, "s3_put: invalid arguments");
        return -1;
    }
    if (vallen > S3_MAX_BODY_BYTES) {
        s3_set_err(err, errcap, "s3_put: value exceeds %u bytes",
                (unsigned)S3_MAX_BODY_BYTES);
        return -1;
    }
    if (s3_request(c, "PUT", key, val, vallen, expiry_ms, &r,
                   err, errcap) != 0) {
        return -1;
    }
    if (r.status >= 200 && r.status < 300) {
        http_response_free(&r);
        rc = 0;
    } else {
        set_s3_error(&r, err, errcap);
        http_response_free(&r);
        rc = -1;
    }
    return rc;
}

int s3_delete(s3_client *c, const char *key, char *err, size_t errcap)
{
    s3_http_response r;
    int rc;

    if (c == NULL || key == NULL) {
        s3_set_err(err, errcap, "s3_delete: invalid arguments");
        return -1;
    }
    if (s3_request(c, "DELETE", key, NULL, 0, 0, &r, err, errcap) != 0) {
        return -1;
    }
    if ((r.status >= 200 && r.status < 300) || r.status == 404) {
        http_response_free(&r);
        rc = 0;
    } else {
        set_s3_error(&r, err, errcap);
        http_response_free(&r);
        rc = -1;
    }
    return rc;
}

/* --------------------------------------------------------------- S3 store
 *
 * --store s3api:BUCKET is the object-storage backend: the same JSON records as
 * bbolt and Valkey, under
 *
 *   betteranusbis/challenge/<id>
 *   betteranusbis/honeypot/<network>
 *
 * with Anubis's x-amz-meta-x-anubis-expiry-ms metadata carrying the absolute
 * expiry (S3 has no native TTL, and GetObject checks the metadata before using
 * the body). Credentials and region come from the environment, as they do for
 * upstream's AWS SDK client: AWS_REGION/AWS_DEFAULT_REGION, AWS_ACCESS_KEY_ID,
 * AWS_SECRET_ACCESS_KEY, optional AWS_SESSION_TOKEN, and AWS_ENDPOINT_URL_S3 /
 * AWS_ENDPOINT_URL for S3-compatible services. AWS_S3_PATH_STYLE=1 (or the
 * policy's pathStyle) selects path-style addressing.
 *
 * Like Valkey, this is a shared backend: reads are remote-first for mutable
 * state, so an instance can verify a challenge another instance issued. S3 is
 * not atomic, so two instances racing on one challenge can both accept it once;
 * the spent write is last-writer-wins. There is no startup list/scan (the keys
 * are looked up on demand), which keeps startup independent of bucket size.
 */
#define S3_CH_PREFIX "betteranusbis/challenge/"
#define S3_HP_PREFIX "betteranusbis/honeypot/"

static time_t s3_backoff_until;

static void s3_warn(const char *what, const char *err) {
    static time_t last;
    time_t now = time(NULL);
    if (now - last >= 5) {
        logmsg("store: s3 %s: %s", what, err && *err ? err : "error");
        last = now;
    }
    s3_backoff_until = now + 5;
}

static int s3_available(void) {
    return store_s3 && s3 != NULL && time(NULL) >= s3_backoff_until;
}

static int s3_get_challenge(const char *id, ch_entry *out) {
    if (!s3_available() || !id || !*id) return 0;
    char key[200], err[512] = "";
    unsigned char *val = NULL;
    size_t len = 0;
    long long expiry = 0;
    snprintf(key, sizeof key, S3_CH_PREFIX "%s", id);
    int rc = s3_get(s3, key, &val, &len, &expiry, err, sizeof err);
    if (rc < 0) { s3_warn("GET challenge", err); return -1; }
    if (rc == 0) return 0;
    char *json = malloc(len + 1);
    if (!json) { free(val); return -1; }
    memcpy(json, val, len);
    json[len] = 0;
    free(val);
    int ok = challenge_from_json(json, out);
    free(json);
    if (!ok) return 0;
    if (!out->id[0]) snprintf(out->id, sizeof out->id, "%s", id);
    return 1;
}

static void s3_put_challenge(const ch_entry *e, long long ttl) {
    if (!s3_available() || !e || !e->id[0]) return;
    char key[200], json[4096], err[512] = "";
    challenge_json(e, json, sizeof json);
    snprintf(key, sizeof key, S3_CH_PREFIX "%s", e->id);
    long long expiry = 0;
    if (ttl > 0) expiry = (long long)time(NULL) * 1000 + ttl * 1000;
    if (s3_put(s3, key, (const unsigned char *)json, strlen(json), expiry, err,
               sizeof err) != 0)
        s3_warn("PUT challenge", err);
}

static int s3_get_honeypot(uint64_t key, int *count, time_t *last) {
    if (!s3_available()) return 0;
    char name[200], err[512] = "";
    unsigned char *val = NULL;
    size_t len = 0;
    long long expiry = 0;
    snprintf(name, sizeof name, S3_HP_PREFIX "%llu", (unsigned long long)key);
    int rc = s3_get(s3, name, &val, &len, &expiry, err, sizeof err);
    if (rc < 0) { s3_warn("GET honeypot", err); return -1; }
    if (rc == 0) return 0;
    char json[512];
    size_t n = len < sizeof json - 1 ? len : sizeof json - 1;
    memcpy(json, val, n);
    json[n] = 0;
    free(val);
    int c = (int)json_get_ll(json, "count", 0);
    long long l = json_get_ll(json, "last", 0);
    if (c <= 0 || l <= 0) return 0;
    *count = c;
    *last = (time_t)l;
    return 1;
}

static void s3_put_honeypot(uint64_t key, int count, time_t last) {
    if (!s3_available()) return;
    char name[200], json[160], err[512] = "";
    snprintf(name, sizeof name, S3_HP_PREFIX "%llu", (unsigned long long)key);
    snprintf(json, sizeof json, "{\"count\":%d,\"last\":%lld}", count, (long long)last);
    if (s3_put(s3, name, (const unsigned char *)json, strlen(json),
               ((long long)last + HP_WINDOW) * 1000, err, sizeof err) != 0)
        s3_warn("PUT honeypot", err);
}

static int s3_store_start(const char *bucket) {
    char err[512] = "";
    const char *ps = getenv("AWS_S3_PATH_STYLE");
    if (ps && *ps && strcmp(ps, "0") && strcasecmp(ps, "false"))
        s3_path_style = 1;
    s3 = s3_connect(bucket, s3_path_style ? 1 : -1, err, sizeof err);
    if (!s3) {
        fprintf(stderr, "betterAnusbis: cannot configure the S3 store: %s\n",
                err[0] ? err : "invalid configuration");
        return -1;
    }
    if (s3_ping(s3, err, sizeof err) != 0) {
        fprintf(stderr, "betterAnusbis: S3 bucket %s is not usable: %s\n", bucket,
                err[0] ? err : "request failed");
        s3_close(s3);
        s3 = NULL;
        return -1;
    }
    store_s3 = 1;
    logmsg("store: s3api bucket %s%s, object metadata carries the expiry", bucket,
           s3_path_style ? " (path style)" : "");
    return 0;
}

/* ---------------------------------------------------------------- the store
 *
 * The challenge ledger and the honeypot counters live in memory, so a restart
 * forgets which challenges were issued and how much a network has been annoying.
 * --store file:PATH snapshots both to a text file every few seconds and loads
 * them back at startup; --store bbolt:PATH does the same in a real bbolt
 * database with Anubis's bucket layout (data + expiry, RFC3339Nano).
 *
 * Both are snapshots, not journals: a crash loses up to five seconds. Neither
 * is a multi-writer store, and bbolt is explicitly single-writer here because a
 * flush rewrites the whole file atomically. Upstream's valkey and S3 backends
 * exist to share state between replicas, which this does not do.
 */
static pthread_t store_thread_id;
static volatile sig_atomic_t shutdown_requested;

static void on_shutdown(int sig) {
    (void)sig;
    shutdown_requested = 1;
}

static void store_mark_dirty(void) { store_dirty = 1; }

static void store_write(void) {
    if (store_valkey || store_s3) return;  /* writes happen with the event */
    if (store_bbolt) {
        if (bbolt_store_write() == 0) store_dirty = 0;
        return;
    }
    if (!store_path[0]) return;
    char tmp[1040];
    snprintf(tmp, sizeof tmp, "%s.tmp", store_path);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        logmsg("store: cannot write %s: %s", tmp, strerror(errno));
        return;
    }
    time_t now = time(NULL);
    long long ch_written = 0, hp_written = 0;
    pthread_mutex_lock(&ch_lock);
    for (int i = 0; i < CH_BUCKETS; i++) {
        ch_entry *e = &ch_table[i];
        if (!e->used) continue;
        /* expired entries are not worth carrying across a restart either */
        if (now - e->issued > COOKIE_TTL) continue;
        fprintf(f, "c %s %s %s %d %d %lld %d\n", e->id, e->rd, e->algorithm,
                e->difficulty, e->spent, e->issued_ms, e->css_seen);
        ch_written++;
    }
    pthread_mutex_unlock(&ch_lock);
    pthread_mutex_lock(&hp_lock);
    for (int i = 0; i < HP_BUCKETS; i++) {
        hp_entry *e = &hp_table[i];
        if (!e->used) continue;
        if (now - e->last > HP_WINDOW) continue;
        fprintf(f, "h %llu %d %lld\n", (unsigned long long)e->key, e->count,
                (long long)e->last);
        hp_written++;
    }
    pthread_mutex_unlock(&hp_lock);
    if (fclose(f) != 0) {
        logmsg("store: cannot close %s: %s", tmp, strerror(errno));
        return;
    }
    if (rename(tmp, store_path) != 0) {
        logmsg("store: cannot move %s into place: %s", tmp, strerror(errno));
        return;
    }
    store_dirty = 0;
    if (cfg.verbose) logmsg("store: wrote %lld challenges and %lld networks", ch_written, hp_written);
}

static int store_load(void) {
    if (store_valkey) return valkey_store_start(store_path);
    if (store_s3) return s3_store_start(store_path);
    if (store_bbolt) return bbolt_load_or_create();
    FILE *f = fopen(store_path, "r");
    if (!f) {
        if (errno != ENOENT)
            logmsg("store: cannot read %s: %s", store_path, strerror(errno));
        return 0;
    }
    char line[1024];
    long long nch = 0, nhp = 0;
    time_t now = time(NULL);
    while (fgets(line, sizeof line, f)) {
        if (line[0] == 'c') {
            char id[80], rd[65], algo[24];
            int difficulty = 0, spent = 0, css = 0;
            long long issued_ms = 0;
            if (sscanf(line, "c %79s %64s %23s %d %d %lld %d", id, rd, algo, &difficulty,
                       &spent, &issued_ms, &css) != 7)
                continue;
            uint32_t h = 2166136261u;
            for (const char *q = id; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
            for (int probe = 0; probe < 32; probe++) {
                ch_entry *e = &ch_table[(h + (uint32_t)probe) % CH_BUCKETS];
                if (e->used && strcmp(e->id, id) != 0) continue;
                snprintf(e->id, sizeof e->id, "%s", id);
                snprintf(e->rd, sizeof e->rd, "%s", rd);
                snprintf(e->algorithm, sizeof e->algorithm, "%s", algo);
                e->difficulty = difficulty;
                e->spent = spent;
                e->css_seen = css;
                e->issued = now;
                e->issued_ms = issued_ms ? issued_ms : (long long)now * 1000;
                e->used = 1;
                nch++;
                break;
            }
        } else if (line[0] == 'h') {
            unsigned long long key = 0;
            int count = 0;
            long long last = 0;
            if (sscanf(line, "h %llu %d %lld", &key, &count, &last) != 3) continue;
            for (int i = 0; i < HP_BUCKETS; i++) {
                hp_entry *e = &hp_table[i];
                if (!e->used) {
                    e->key = key;
                    e->count = count;
                    e->last = (time_t)last;
                    e->used = 1;
                    nhp++;
                    break;
                }
                if (e->key == key) {
                    e->count = count;
                    e->last = (time_t)last;
                    nhp++;
                    break;
                }
            }
        }
    }
    fclose(f);
    logmsg("store: loaded %lld challenge(s) and %lld network(s) from %s", nch, nhp,
           store_path);
    return 0;
}

static void *store_thread(void *arg) {
    (void)arg;
    store_write();                 /* an empty store is still a store */
    for (;;) {
        for (int i = 0; i < 25; i++) {
            if (shutdown_requested) break;
            usleep(200000);
        }
        if (shutdown_requested) {
            /* a supervisor's SIGTERM should not throw away the last few seconds */
            store_write();
            _exit(0);
        }
        if (store_dirty) store_write();
    }
    return NULL;
}

/* ------------------------------------------------------------ DNS lookups
 *
 * Two features need DNS and neither needs a hand-written resolver: the system
 * one is fine. A DNSBL query is an A lookup of a reversed address, and
 * forward-confirmed reverse DNS is a PTR lookup followed by an A lookup of the
 * name it returned.
 */
#define DNSBL_ZONE "dnsbl.dronebl.org"
#define DNSBL_TTL 86400
#define DNSBL_SLOTS 512

typedef struct {
    char ip[64];
    int verdict;             /* 0 clean, >0 class, -1 lookup failed */
    time_t when;
    int used;
} dnsbl_entry;
static dnsbl_entry dnsbl_cache[DNSBL_SLOTS];
static pthread_mutex_t dnsbl_lock = PTHREAD_MUTEX_INITIALIZER;

static void reverse_ip(const char *ip, char *out, size_t cap) {
    out[0] = 0;
    struct in_addr v4;
    struct in6_addr v6;
    if (!strchr(ip, ':')) {
        if (inet_pton(AF_INET, ip, &v4) != 1) return;
        unsigned char *b = (unsigned char *)&v4.s_addr;
        snprintf(out, cap, "%u.%u.%u.%u", b[3], b[2], b[1], b[0]);
        return;
    }
    if (inet_pton(AF_INET6, ip, &v6) != 1) return;
    size_t o = 0;
    for (int i = 15; i >= 0; i--) {
        o += (size_t)snprintf(out + o, cap - o, "%x.%x.", v6.s6_addr[i] & 0xf,
                              v6.s6_addr[i] >> 4);
        if (o >= cap) return;
    }
    out[o] = 0;
    if (o && out[o - 1] == '.') out[o - 1] = 0;
}

static int dnsbl_lookup(const char *ip) {
    char rev[256], name[320];
    reverse_ip(ip, rev, sizeof rev);
    if (!rev[0]) return 0;
    snprintf(name, sizeof name, "%s." DNSBL_ZONE, rev);
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(name, NULL, &hints, &res);
    if (rc == EAI_NONAME
#ifdef EAI_NODATA
        || rc == EAI_NODATA
#endif
    ) {
        if (res) freeaddrinfo(res);
        return 0;                       /* not listed */
    }
    if (rc != 0) {
        if (res) freeaddrinfo(res);
        return -1;
    }
    int cls = 0;
    if (res) {
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        cls = (int)(ntohl(sin->sin_addr.s_addr) & 0xff);
        freeaddrinfo(res);
    }
    return cls;                         /* 0 means all good */
}

static int dnsbl_verdict(const char *ip) {
    time_t now = time(NULL);
    uint32_t h = 2166136261u;
    for (const char *q = ip; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
    int slot = (int)(h % DNSBL_SLOTS);
    int result;
    pthread_mutex_lock(&dnsbl_lock);
    dnsbl_entry *e = &dnsbl_cache[slot];
    if (e->used && !strcmp(e->ip, ip) && now - e->when < cfg.dns_ttl) {
        result = e->verdict;
        pthread_mutex_unlock(&dnsbl_lock);
        return result;
    }
    pthread_mutex_unlock(&dnsbl_lock);

    result = dnsbl_lookup(ip);

    pthread_mutex_lock(&dnsbl_lock);
    e = &dnsbl_cache[slot];
    snprintf(e->ip, sizeof e->ip, "%s", ip);
    e->verdict = result;
    e->when = now;
    e->used = 1;
    pthread_mutex_unlock(&dnsbl_lock);
    return result;
}

/* verifyFCrDNS(ip, "^.*example$"): the PTR name must exist, and one of its
 * forward addresses must be the address we asked about
 * (internal/dns/dns.go:90-148). Returns the verified name, or 0. */
static int fcrdns_name(const char *ip, char *out, size_t cap) {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    struct sockaddr *sa;
    socklen_t salen;
    memset(&v4, 0, sizeof v4);
    memset(&v6, 0, sizeof v6);
    if (!strchr(ip, ':')) {
        if (inet_pton(AF_INET, ip, &v4.sin_addr) != 1) return 0;
        v4.sin_family = AF_INET;
        sa = (struct sockaddr *)&v4;
        salen = sizeof v4;
    } else {
        if (inet_pton(AF_INET6, ip, &v6.sin6_addr) != 1) return 0;
        v6.sin6_family = AF_INET6;
        sa = (struct sockaddr *)&v6;
        salen = sizeof v6;
    }
    char name[NI_MAXHOST];
    if (getnameinfo(sa, salen, name, sizeof name, NULL, 0, NI_NAMEREQD) != 0) return 0;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(name, NULL, &hints, &res) != 0) return 0;
    int confirmed = 0;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        if (a->ai_family == AF_INET &&
            !memcmp(&((struct sockaddr_in *)a->ai_addr)->sin_addr, &v4.sin_addr, 4)) {
            confirmed = 1;
            break;
        }
        if (a->ai_family == AF_INET6 &&
            !memcmp(&((struct sockaddr_in6 *)a->ai_addr)->sin6_addr, &v6.sin6_addr, 16)) {
            confirmed = 1;
            break;
        }
    }
    freeaddrinfo(res);
    if (!confirmed) return 0;
    snprintf(out, cap, "%s", name);
    return 1;
}

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

/* An upgrade is a request whose response never ends: after the 101 the two
 * sockets are one pipe. Anubis gets this from httputil.ReverseProxy, which has
 * handled upgrades since Go 1.12; here it is explicit, because the whole point
 * is to stop being an HTTP client and start being a splice.
 *
 * Grafana, Jupyter, the MinIO console and every live-reload dev server need it,
 * and a gate that answers 101 with a challenge page is worse than no gate. */

static int upgrade_requested(const request *req) {
    char upgrade[64], conn[128];
    if (!header_value_into(req, "Upgrade", upgrade, sizeof upgrade) || !upgrade[0]) return 0;
    if (!header_value_into(req, "Connection", conn, sizeof conn) || !conn[0]) return 0;
    return strcasestr(conn, "upgrade") != NULL && (!strcasecmp(upgrade, "websocket") ||
                                                   !strcasecmp(upgrade, "h2c") ||
                                                   !strcasecmp(upgrade, "HTTP/2.0"));
}

/* Read once from a conn, draining whatever the TLS layer already holds, and
 * tell the caller whether the peer is done. */
static ssize_t relay_read(conn *c, char *buf, size_t cap) {
    for (;;) {
        ssize_t n = conn_read(c, buf, cap);
        if (n > 0) return n;
        if (c->ssl && SSL_pending((SSL *)c->ssl) > 0) continue;
        return n;
    }
}

static void proxy_upgrade(conn *c, const request *req, const char *client_ip, const char *path) {
    conn up_c = {.fd = -1, .ssl = NULL};
    if (target_connect(&up_c) < 0) {
        const char *msg = "betterAnusbis: cannot reach the target\n";
        respond(c, 502, "Bad Gateway", NULL, NULL, msg, strlen(msg));
        return;
    }

    /* Forward the request as written, except the two headers we own. Unlike the
     * ordinary path, Connection and Upgrade must survive: they are the request. */
    char head[16384];
    size_t off = 0;
    const char *host_hdr = cfg.target_host_hdr && *cfg.target_host_hdr
                               ? cfg.target_host_hdr : cfg.target_host;
    sb_app(head, sizeof head, &off, "%s %s HTTP/1.1\r\nHost: %s\r\n",
           req->method, path, host_hdr);
    const char *p = req->headers;
    while (p && *p) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        size_t n = (size_t)(eol - p);
        if (n > 0 && n < 1024 &&
            strncasecmp(p, "Host:", 5) && strncasecmp(p, "X-Real-IP:", 10) &&
            strncasecmp(p, "X-Forwarded-For:", 16) && strncasecmp(p, "Proxy-", 6) &&
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
    sb_app(head, sizeof head, &off, "X-Real-IP: %s\r\nX-Forwarded-For: %s\r\n\r\n",
           client_ip, client_ip);
    if (send_all(&up_c, head, off) < 0) goto done;

    /* The answer head, then whatever of the tunnel arrived with it. */
    char resp[16384];
    size_t used = 0;
    while (used < sizeof resp - 1) {
        ssize_t r = conn_read(&up_c, resp + used, sizeof resp - 1 - used);
        if (r <= 0) break;
        used += (size_t)r;
        resp[used] = 0;
        if (strstr(resp, "\r\n\r\n")) break;
    }
    if (!used) {
        const char *msg = "betterAnusbis: the target closed during the upgrade\n";
        respond(c, 502, "Bad Gateway", NULL, NULL, msg, strlen(msg));
        goto done;
    }
    if (send_all(c, resp, used) < 0) goto done;

    const char *sp = strchr(resp, ' ');
    int status = sp ? atoi(sp + 1) : 0;
    if (status != 101) {
        /* Not an upgrade after all: hand back what the target said and stop. */
        char buf[8192];
        for (;;) {
            ssize_t r = conn_read(&up_c, buf, sizeof buf);
            if (r <= 0) break;
            if (send_all(c, buf, (size_t)r) < 0) break;
        }
        goto done;
    }
    if (cfg.verbose)
        logmsg("upgrade to %s accepted, splicing (client %s)", cfg.target_host, client_ip);

    /* Splice. Idle for five minutes and both ends go: a live socket that has
     * said nothing for five minutes is not live. */
    for (;;) {
        struct pollfd pfd[2] = {{c->fd, POLLIN, 0}, {up_c.fd, POLLIN, 0}};
        int ready = poll(pfd, 2, 300000);
        if (ready <= 0) break;
        char buf[32768];
        if (pfd[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t r = relay_read(c, buf, sizeof buf);
            if (r <= 0) break;
            if (send_all(&up_c, buf, (size_t)r) < 0) break;
        }
        if (pfd[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t r = relay_read(&up_c, buf, sizeof buf);
            if (r <= 0) break;
            if (send_all(c, buf, (size_t)r) < 0) break;
        }
    }

done:
    if (up_c.ssl) {
        SSL_shutdown((SSL *)up_c.ssl);
        SSL_free((SSL *)up_c.ssl);
        up_c.ssl = NULL;
    }
    if (up_c.fd >= 0) close(up_c.fd);
}

/* ------------------------------------------------------- upstream keep-alive
 *
 * The origin pays for a TCP handshake, and a TLS one, on every request unless
 * something keeps the connection. This does, for a small pool, and only when
 * the response was framed well enough to know where it ended: Content-Length,
 * chunked, or a status with no body. A reused connection that turns out to be
 * dead is retried once on a fresh one, because that is what every HTTP client
 * has to do.
 *
 * The client side is unchanged: it is told Connection: close, so this saves the
 * origin's handshakes without making the gate's own life complicated.
 */
#define UP_POOL 8
#define UP_IDLE_MAX 60

typedef struct {
    int fd;
    void *ssl;
    time_t when;
    int used;
} upslot;

static upslot up_pool[UP_POOL];
static pthread_mutex_t up_lock = PTHREAD_MUTEX_INITIALIZER;

static void up_close(conn *up) {
    if (up->ssl) {
        SSL_shutdown((SSL *)up->ssl);
        SSL_free((SSL *)up->ssl);
        up->ssl = NULL;
    }
    if (up->fd >= 0) close(up->fd);
    up->fd = -1;
}

static int pool_take(conn *up) {
    if (cfg.target_disable_keepalive) return 0;
    time_t now = time(NULL);
    for (int i = 0; i < UP_POOL; i++) {
        conn stale = {.fd = -1, .ssl = NULL};
        pthread_mutex_lock(&up_lock);
        if (!up_pool[i].used) {
            pthread_mutex_unlock(&up_lock);
            continue;
        }
        if (now - up_pool[i].when > UP_IDLE_MAX) {
            stale.fd = up_pool[i].fd;
            stale.ssl = up_pool[i].ssl;
            memset(&up_pool[i], 0, sizeof up_pool[i]);
            pthread_mutex_unlock(&up_lock);
            up_close(&stale);
            continue;
        }
        up->fd = up_pool[i].fd;
        up->ssl = up_pool[i].ssl;
        memset(&up_pool[i], 0, sizeof up_pool[i]);
        pthread_mutex_unlock(&up_lock);
        return 1;
    }
    return 0;
}

static void pool_put(conn *up) {
    if (up->fd < 0) return;
    if (cfg.target_disable_keepalive) {
        up_close(up);
        return;
    }
    time_t now = time(NULL);
    pthread_mutex_lock(&up_lock);
    for (int i = 0; i < UP_POOL; i++) {
        if (up_pool[i].used) continue;
        up_pool[i].fd = up->fd;
        up_pool[i].ssl = up->ssl;
        up_pool[i].when = now;
        up_pool[i].used = 1;
        pthread_mutex_unlock(&up_lock);
        up->fd = -1;
        up->ssl = NULL;
        return;
    }
    pthread_mutex_unlock(&up_lock);
    up_close(up);                /* the pool is full; the origin loses nothing */
}

/* A reader over the upstream connection with its own leftover buffer, so the
 * body bytes that arrived with the headers are not lost. */
typedef struct {
    conn *up;
    /* at least as large as relay_response()'s head buffer: the first read can
     * carry the whole head and a chunk of body, and that leftover is memcpy'd
     * here verbatim. 8 KiB was smaller than the 32 KiB head, which is a buffer
     * overflow the moment the origin answers quickly. */
    char buf[32768];
    size_t pos, len;
} rd_t;

static ssize_t rd_fill(rd_t *r) {
    if (r->pos < r->len) return (ssize_t)(r->len - r->pos);
    r->pos = r->len = 0;
    ssize_t n = relay_read(r->up, r->buf, sizeof r->buf);
    if (n <= 0) return n;
    r->len = (size_t)n;
    return n;
}

/* One raw line *with* its CRLF, copied out so it can be relayed unchanged. */
static int rd_line_raw(rd_t *r, char *out, size_t cap) {
    size_t o = 0;
    for (;;) {
        if (rd_fill(r) <= 0) return 0;
        char ch = r->buf[r->pos++];
        if (o + 1 < cap) out[o++] = ch;
        if (ch == '\n') break;
    }
    out[o] = 0;
    return 1;
}

static int rd_pump(conn *c, rd_t *r, size_t n) {
    while (n) {
        if (rd_fill(r) <= 0) return 0;
        size_t have = r->len - r->pos;
        size_t take = have < n ? have : n;
        if (send_all(c, r->buf + r->pos, take) < 0) return 0;
        r->pos += take;
        n -= take;
    }
    return 1;
}

static int rd_pump_to_end(conn *c, rd_t *r) {
    for (;;) {
        if (rd_fill(r) <= 0) return 0;
        size_t have = r->len - r->pos;
        if (send_all(c, r->buf + r->pos, have) < 0) return 0;
        r->pos = r->len;
    }
}

/* Relay one response. Returns 1 when the upstream connection can be reused. */
static int relay_response(conn *up_c, conn *c, const char *method) {
    char head[32768];
    size_t used = 0;
    while (1) {
        if (used >= sizeof head - 1) return -1;
        ssize_t n = conn_read(up_c, head + used, sizeof head - 1 - used);
        if (n <= 0) return -1;
        used += (size_t)n;
        head[used] = 0;
        if (strstr(head, "\r\n\r\n")) break;
    }
    char *body = strstr(head, "\r\n\r\n") + 4;
    size_t leftover = used - (size_t)(body - head);
    const char *sp = strchr(head, ' ');
    int status = sp ? atoi(sp + 1) : 0;

    char *cl = strcasestr(head, "\r\ncontent-length:");
    char *te = strcasestr(head, "\r\ntransfer-encoding:");
    char *ce = strcasestr(head, "\r\nconnection:");
    int chunked = te && te < body && strcasestr(te, "chunked");
    long long length = -1;
    if (cl && cl < body) length = atoll(cl + strlen("\r\ncontent-length:"));
    int conn_close = ce && ce < body && strcasestr(ce, "close") != NULL;
    int head_only = method && !strcasecmp(method, "HEAD");

    /* the head only; the leftover bytes are the start of the body. When HTTP/3
     * is on, every response is the place a browser learns the QUIC endpoint. */
    if (cfg.http3 && h3_port) {
        size_t hlen = (size_t)(body - head);
        char alt[96];
        int an = snprintf(alt, sizeof alt, "Alt-Svc: h3=\":%d\"; ma=86400\r\n",
                          h3_port);
        if (send_all(c, head, hlen - 2) < 0) return 0;
        if (send_all(c, alt, (size_t)an) < 0) return 0;
        if (send_all(c, "\r\n", 2) < 0) return 0;
    } else if (send_all(c, head, (size_t)(body - head)) < 0) {
        return 0;
    }

    rd_t r;
    memset(&r, 0, sizeof r);
    r.up = up_c;
    memcpy(r.buf, body, leftover);
    r.pos = 0;
    r.len = leftover;

    int reusable = !conn_close && !cfg.target_disable_keepalive && status != 101;

    if (head_only || status == 204 || status == 304) return reusable;

    if (chunked) {
        for (;;) {
            char raw[128];
            if (!rd_line_raw(&r, raw, sizeof raw)) return 0;
            if (send_all(c, raw, strlen(raw)) < 0) return 0;
            char num[128];
            snprintf(num, sizeof num, "%s", raw);
            char *semi = strchr(num, ';');
            if (semi) *semi = 0;
            long long sz = strtoll(num, NULL, 16);
            if (sz < 0) return 0;
            if (sz == 0) {
                /* trailers until an empty line, relayed as they came */
                for (;;) {
                    char t[512];
                    if (!rd_line_raw(&r, t, sizeof t)) return 0;
                    if (send_all(c, t, strlen(t)) < 0) return 0;
                    if (!strcmp(t, "\r\n")) return reusable;
                }
            }
            if (!rd_pump(c, &r, (size_t)sz)) return 0;
            if (!rd_pump(c, &r, 2)) return 0;
        }
    }

    if (length >= 0) {
        if (!rd_pump(c, &r, (size_t)length)) return 0;
        return reusable;
    }

    /* no framing: the close is the delimiter, so the connection cannot be reused */
    rd_pump_to_end(c, &r);
    return 0;
}

#ifdef HAVE_NGHTTP2
static int proxy_request_h2(conn *c, const request *req, const char *client_ip,
                            const char *path);
#endif
#ifdef HAVE_NGHTTP3
static int proxy_request_h3(conn *c, const request *req, const char *client_ip,
                            const char *path);
#endif

static void proxy_request(conn *c, const request *req, const char *client_ip, const char *path) {
    if (upgrade_requested(req)) {
        proxy_upgrade(c, req, client_ip, path);
        return;
    }
#ifdef HAVE_NGHTTP3
    /* --target-http3 asks for QUIC first; a 0 means the handshake did not
     * happen and the ordinary path below is the fallback. */
    if (cfg.target_http3 && cfg.target_tls &&
        proxy_request_h3(c, req, client_ip, path))
        return;
#endif
#ifdef HAVE_NGHTTP2
    /* --target-http2: when the origin's TLS offers h2, use it. A 0 means the
     * origin selected HTTP/1.1 and the ordinary path below dials again. */
    if (cfg.target_http2 && cfg.target_tls &&
        proxy_request_h2(c, req, client_ip, path))
        return;
#endif

    char head[8192];
    const char *host_hdr = cfg.target_host_hdr && *cfg.target_host_hdr
                               ? cfg.target_host_hdr : cfg.target_host;
    size_t off = (size_t)snprintf(head, sizeof head, "%s %s HTTP/1.1\r\nHost: %s\r\n",
                                 req->method, path, host_hdr);
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
                            "X-Real-IP: %s\r\nX-Forwarded-For: %s\r\nConnection: %s\r\n\r\n",
                            client_ip, client_ip,
                            cfg.target_disable_keepalive ? "close" : "keep-alive");

    /* Two attempts: the first may be a pooled connection the origin has since
     * closed, which is normal and undetectable until the read comes back empty. */
    for (int attempt = 0; attempt < 2; attempt++) {
        conn up_c = {.fd = -1, .ssl = NULL};
        int pooled = pool_take(&up_c);
        if (!pooled && target_connect(&up_c) < 0) {
            const char *msg = "betterAnusbis: cannot reach the target\n";
            respond(c, 502, "Bad Gateway", NULL, NULL, msg, strlen(msg));
            return;
        }
        int failed = send_all(&up_c, head, off) < 0;
        if (!failed && req->body_len && send_all(&up_c, req->body, req->body_len) < 0) failed = 1;
        if (failed) {
            up_close(&up_c);
            if (pooled) continue;       /* stale connection: retry on a fresh one */
            const char *msg = "betterAnusbis: cannot reach the target\n";
            respond(c, 502, "Bad Gateway", NULL, NULL, msg, strlen(msg));
            return;
        }
        int rc = relay_response(&up_c, c, req->method);
        if (rc > 0) pool_put(&up_c);
        else up_close(&up_c);
        if (rc < 0 && pooled) continue; /* the pooled one died before we wrote */
        if (rc < 0) {
            const char *msg = "betterAnusbis: the target closed without answering\n";
            respond(c, 502, "Bad Gateway", NULL, NULL, msg, strlen(msg));
        }
        return;
    }
    const char *msg = "betterAnusbis: cannot reach the target\n";
    respond(c, 502, "Bad Gateway", NULL, NULL, msg, strlen(msg));
}

static void url_encode(const char *in, char *out, size_t cap) {
    static const char *hex = "0123456789ABCDEF";
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p && o + 4 < cap; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || *p == '-' || *p == '.' || *p == '_' || *p == '~') {
            out[o++] = (char)*p;
        } else {
            out[o++] = '%';
            out[o++] = hex[*p >> 4];
            out[o++] = hex[*p & 15];
        }
    }
    out[o] = 0;
}

/* --------------------------------------------------------------- OpenGraph
 *
 * A link preview of a protected page would otherwise show the challenge page's
 * own title, which is not what the page is about. With --og-passthrough the
 * gate fetches the protected page once, keeps its og: and description tags, and
 * puts them in the challenge page's head. --og-override skips the fetch
 * entirely, which is what a site with no og tags or a fetch it cannot afford
 * wants (upstream's `override` is the same idea: a complete replacement, never
 * a per-tag overlay).
 */
#define OG_SLOTS 128
#define OG_FETCH_MAX (256u << 10)

typedef struct {
    char path[192];
    time_t when;
    char snippet[1536];
    int used;
} og_entry;

static og_entry og_cache[OG_SLOTS];
static pthread_mutex_t og_lock = PTHREAD_MUTEX_INITIALIZER;

static void og_escape(const char *in, size_t n, char *out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; i < n && o + 6 < cap; i++) {
        unsigned char ch = (unsigned char)in[i];
        if (ch == '"') { out[o++] = '&'; out[o++] = 'q'; out[o++] = 'u'; out[o++] = 'o'; out[o++] = 't'; out[o++] = ';'; }
        else if (ch == '<') { out[o++] = '&'; out[o++] = 'l'; out[o++] = 't'; out[o++] = ';'; }
        else if (ch == '>') { out[o++] = '&'; out[o++] = 'g'; out[o++] = 't'; out[o++] = ';'; }
        else if (ch == '\n' || ch == '\r') continue;
        else out[o++] = (char)ch;
    }
    out[o] = 0;
}

/* Pull one attribute's value out of a tag: name="value" or name='value'. */
static int og_attr(const char *tag, size_t len, const char *name, char *out, size_t cap) {
    size_t nl = strlen(name);
    for (size_t i = 0; i + nl < len; i++) {
        if (strncasecmp(tag + i, name, nl)) continue;
        size_t j = i + nl;
        while (j < len && (tag[j] == ' ' || tag[j] == '=')) j++;
        if (j >= len) return 0;
        char q = tag[j];
        if (q != '"' && q != '\'') return 0;
        j++;
        size_t o = 0;
        while (j < len && tag[j] != q && o + 1 < cap) out[o++] = tag[j++];
        out[o] = 0;
        return (int)o;
    }
    return 0;
}

static void og_extract(const char *html, size_t len, char *out, size_t cap) {
    size_t o = 0;
    out[0] = 0;
    const char *p = html;
    size_t left = len;
    int emitted = 0;
    while (left > 6 && emitted < 6) {
        const char *m = strcasestr(p, "<meta");
        if (!m || m >= p + left) break;
        left -= (size_t)(m - p);
        p = m;
        const char *gt = memchr(p, '>', left);
        if (!gt) break;
        size_t taglen = (size_t)(gt - p) + 1;
        char prop[128] = "", nameattr[128] = "", content[512] = "";
        og_attr(p, taglen, "property=", prop, sizeof prop);
        og_attr(p, taglen, "name=", nameattr, sizeof nameattr);
        og_attr(p, taglen, "content=", content, sizeof content);
        const char *key = NULL;
        if (prop[0] && !strncasecmp(prop, "og:", 3)) key = prop;
        else if (!strcasecmp(nameattr, "description")) key = "description";
        else if (!strcasecmp(nameattr, "twitter:card")) key = "twitter:card";
        if (key && content[0]) {
            char safe[600];
            og_escape(content, strlen(content), safe, sizeof safe);
            int n = snprintf(out + o, cap - o, "<meta property=\"%s\" content=\"%s\">",
                             key, safe);
            if (n > 0) o += (size_t)n;
            emitted++;
        }
        left -= taglen;
        p = gt + 1;
        if (o + 700 >= cap) break;
    }
}

/* Fetch the protected page and keep its tags. Returns 1 when it got anything. */
static int og_fetch(const char *path, char *out, size_t cap) {
    conn up_c = {.fd = -1, .ssl = NULL};
    if (target_connect(&up_c) < 0) return 0;
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(up_c.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    const char *host_hdr = cfg.target_host_hdr && *cfg.target_host_hdr
                               ? cfg.target_host_hdr : cfg.target_host;
    char req[1024];
    int n = snprintf(req, sizeof req,
                     "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: betterAnusbis-og/1\r\n"
                     "Connection: close\r\n\r\n", path, host_hdr);
    if (send_all(&up_c, req, (size_t)n) < 0) {
        up_close(&up_c);
        return 0;
    }
    char *page = malloc(OG_FETCH_MAX);
    size_t used = 0;
    if (page) {
        while (used < OG_FETCH_MAX - 1) {
            ssize_t r = conn_read(&up_c, page + used, OG_FETCH_MAX - 1 - used);
            if (r <= 0) break;
            used += (size_t)r;
        }
        page[used] = 0;
    }
    up_close(&up_c);
    if (!page) return 0;
    char *body = strstr(page, "\r\n\r\n");
    if (body) og_extract(body + 4, used - (size_t)(body + 4 - page), out, cap);
    free(page);
    return out[0] != 0;
}

/* The snippet for one path: override, else cache, else fetch. */
static void og_snippet(const char *path, char *out, size_t cap) {
    out[0] = 0;
    if (!cfg.og_passthrough && !(cfg.og_override && *cfg.og_override)) return;
    if (cfg.og_override && *cfg.og_override) {
        char copy[1024];
        snprintf(copy, sizeof copy, "%s", cfg.og_override);
        size_t o = 0;
        for (char *pair = copy; pair && *pair && o + 80 < cap;) {
            char *semi = strchr(pair, ';');
            if (semi) *semi = 0;
            char *eq = strchr(pair, '=');
            if (eq) {
                *eq = 0;
                char safe[512];
                og_escape(eq + 1, strlen(eq + 1), safe, sizeof safe);
                o += (size_t)snprintf(out + o, cap - o,
                                      "<meta property=\"%s\" content=\"%s\">", pair, safe);
            }
            pair = semi ? semi + 1 : NULL;
        }
        return;
    }

    time_t now = time(NULL);
    uint32_t h = 2166136261u;
    /* considerHost: two paths can be different pages on different vhosts */
    char key[320];
    if (cfg.og_consider_host) snprintf(key, sizeof key, "%s%s", cfg.target, path);
    else snprintf(key, sizeof key, "%s", path ? path : "/");
    for (const char *q = key; *q; q++) h = (h ^ (uint8_t)*q) * 16777619u;
    int slot = (int)(h % OG_SLOTS);
    pthread_mutex_lock(&og_lock);
    og_entry *e = &og_cache[slot];
    if (e->used && !strcmp(e->path, key) && now - e->when < cfg.og_ttl) {
        snprintf(out, cap, "%s", e->snippet);
        pthread_mutex_unlock(&og_lock);
        return;
    }
    pthread_mutex_unlock(&og_lock);

    char fetched[1536];
    if (!og_fetch(path, fetched, sizeof fetched)) return;

    pthread_mutex_lock(&og_lock);
    e = &og_cache[slot];
    snprintf(e->path, sizeof e->path, "%s", key);
    snprintf(e->snippet, sizeof e->snippet, "%s", fetched);
    e->when = now;
    e->used = 1;
    pthread_mutex_unlock(&og_lock);
    snprintf(out, cap, "%s", fetched);
}

/* ---------------------------------------------------------------- strings
 *
 * Our page has its own five strings, so they are translated here rather than
 * read out of Anubis's locale files, whose keys describe a different page. Six
 * locales by hand; upstream ships 31 through its JSON files.
 */
typedef struct {
    const char *code;
    const char *title;      /* Proving you are not a robot */
    const char *solving;    /* solving a %s challenge at difficulty %d... */
    const char *slowing;    /* slowing you down! */
    const char *manual;     /* or pass the challenge manually */
    const char *explain;    /* If nothing happens, solve it yourself... */
    const char *denied;     /* denied by policy */
} locale;

static const locale locales[] = {
    {"en", "Proving you are not a robot", "solving a %s challenge at difficulty %d&hellip;",
     "slowing you down!", "or pass the challenge manually",
     "If nothing happens, solve it yourself: the challenge is the JSON below, and the answer goes to",
     "denied by policy"},
    {"nl", "Bewijzen dat je geen robot bent", "een %s-uitdaging oplossen op moeilijkheid %d&hellip;",
     "we vertragen je!", "of los de uitdaging zelf op",
     "Als er niets gebeurt, los het dan zelf op: de uitdaging is de JSON hieronder, en het antwoord gaat naar",
     "geweigerd door het beleid"},
    {"de", "Nachweis, dass du kein Roboter bist", "eine %s-Aufgabe der Schwierigkeit %d wird gel&ouml;st&hellip;",
     "wir bremsen dich aus!", "oder l&ouml;se die Aufgabe selbst",
     "Wenn nichts passiert, l&ouml;se sie selbst: die Aufgabe ist das JSON unten, die Antwort geht an",
     "durch die Richtlinie abgelehnt"},
    {"fr", "Prouver que vous n'&ecirc;tes pas un robot", "r&eacute;solution d'un d&eacute;fi %s de difficult&eacute; %d&hellip;",
     "on vous ralentit !", "ou r&eacute;solvez le d&eacute;fi vous-m&ecirc;me",
     "Si rien ne se passe, r&eacute;solvez-le vous-m&ecirc;me : le d&eacute;fi est le JSON ci-dessous, la r&eacute;ponse va &agrave;",
     "refus&eacute; par la politique"},
    {"es", "Demostrando que no eres un robot", "resolviendo un desaf&iacute;o %s de dificultad %d&hellip;",
     "te estamos frenando!", "o resuelve el desaf&iacute;o t&uacute; mismo",
     "Si no pasa nada, resu&eacute;lvelo t&uacute; mismo: el desaf&iacute;o es el JSON de abajo, y la respuesta va a",
     "denegado por la pol&iacute;tica"},
    {"it", "Dimostra di non essere un robot", "risoluzione di una sfida %s a difficolt&agrave; %d&hellip;",
     "ti stiamo rallentando!", "oppure risolvi la sfida da solo",
     "Se non succede nulla, risolvila da solo: la sfida &egrave; il JSON qui sotto, la risposta va a",
     "negato dalla policy"},
};
#define LOCALE_COUNT ((int)(sizeof locales / sizeof locales[0]))

/* Accept-Language, or --forced-language when the operator insists. */
static const locale *pick_locale(const request *req) {
    if (cfg.forced_language && *cfg.forced_language) {
        for (int i = 0; i < LOCALE_COUNT; i++)
            if (!strncasecmp(locales[i].code, cfg.forced_language, 2)) return &locales[i];
        return &locales[0];
    }
    const char *al = req ? header_value(req, "Accept-Language") : NULL;
    /* walk the header in the order it was sent, not the order of our table:
     * "de-DE,en;q=0.5" means German, even though en is first in the table */
    for (const char *p = al; p && *p; ) {
        while (*p == ' ' || *p == ',' || *p == '\t') p++;
        char tag[3] = {0, 0, 0};
        size_t n = strcspn(p, ",;");
        if (n >= 2) {
            tag[0] = p[0];
            tag[1] = p[1];
        }
        for (int i = 0; i < LOCALE_COUNT; i++)
            if (tag[0] && !strncasecmp(locales[i].code, tag, 2)) return &locales[i];
        const char *comma = strchr(p, ',');
        p = comma ? comma + 1 : NULL;
    }
    return &locales[0];
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

  // compact SHA-256: the fast/slow challenges hash a text message, the sha256
  // challenge hashes raw bytes plus the nonce (sha256padded is shared by both)
  const K=new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  const rotr=(x,n)=>(x>>>n)|(x<<(32-n));
  // The compressor works on an already-padded message: the caller fills in the
  // 0x80 byte and the 64-bit length. The pure-JS sha256 solver reuses one
  // padded buffer and only rewrites the four nonce bytes per attempt.
  function sha256padded(padded){
    const H=new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
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
  function sha256bytes(data){
    const len=data.length;
    const padded=new Uint8Array(((len+9+63)/64|0)*64); padded.set(data); padded[len]=0x80;
    sha256length(padded,len*8);
    return sha256padded(padded);
  }
  // Write the 64-bit message length into the padding as two 32-bit halves.
  // `bits>>>(8*i)` alone is wrong for i>=4: JavaScript masks shift counts to 5
  // bits, so the high half would repeat the low word and every digest breaks.
  function sha256length(padded,bits){
    const hi=Math.floor(bits/4294967296)>>>0, lo=bits>>>0;
    for(let i=0;i<4;i++){
      padded[padded.length-1-i]=(lo>>>(8*i))&0xff;
      padded[padded.length-5-i]=(hi>>>(8*i))&0xff;
    }
  }
  const lz=(b)=>{let n=0;for(const x of b){if(x===0){n+=8;continue;}n+=Math.clz32(x)-24;break;}return n;};
  // leading zero bits of the Bitcoin-order hash, i.e. trailing zero bits of the
  // raw SHA-256d digest: the tier's digest is already reversed before it is shown
  const lzr=(b)=>{let n=0;for(let i=b.length-1;i>=0;i--){const x=b[i];if(x===0){n+=8;continue;}n+=Math.clz32(x)-24;break;}return n;};
  // nBits for the exact target 2^(256-difficulty): Bitcoin's GetCompact() for a
  // power of two, which always round-trips exactly. Same arithmetic as
  // meatrider_bits() in src/meatrider/meatrider.c.
  function mrBits(d){
    const k=256-d, blen=k+1, size=Math.ceil(blen/8);
    let c=size<=3?(1<<k)<<(8*(3-size)):(1<<(k-8*(size-3)));
    let sz=size;
    if(c&0x800000){c>>>=8;sz++;}
    return ((c>>>0)|(sz<<24))>>>0;
  }
  function mrTime(s){
    if(!isFinite(s)) return "longer than the universe";
    if(s<1e-6) return (s*1e9).toFixed(0)+" ns";
    if(s<1e-3) return (s*1e6).toFixed(0)+" us";
    if(s<1) return (s*1e3).toFixed(0)+" ms";
    if(s<90) return s.toFixed(0)+" s";
    if(s<5400) return (s/60).toFixed(0)+" min";
    if(s<172800) return (s/3600).toFixed(1)+" h";
    if(s<3.16e7) return (s/86400).toFixed(0)+" days";
    const y=s/3.156e7;
    return y<1e6 ? y.toFixed(0)+" years" : y.toExponential(1)+" years";
  }
  // The ladder is money: 2^difficulty hashes at the default hash price. These are
  // the same numbers as tools/meatrider_ref.py --ladder and anubis_meatrider_price_usd().
  const MR_TIERS=[[1e-15,"spark"],[1e-14,"grain"],[1e-13,"speck"],[1e-12,"mote"],
    [1e-11,"crumb"],[1e-10,"atom"],[1e-9,"nano"],[1e-8,"microbit"],[1e-7,"dust"],
    [1e-6,"suspicious"],[1e-5,"very-suspicious"],[1e-4,"bot-shaped"],[1e-3,"farm"],
    [1e-2,"datacenter"],[1e-1,"asic"],[1e0,"meatrider"]];
  function mrPriceUsd(d){ return Math.pow(2,d)*0.05/(1e12*86400); }
  function mrTierName(d){
    const price=mrPriceUsd(d);
    let name=MR_TIERS[0][1];
    for(const t of MR_TIERS) if(price>=t[0]) name=t[1];
    return name;
  }
  // Cents, with enough digits after the leading zeros to see something. The
  // whole ladder lives between 1e-16 and 1e-2 dollars, so "0.000000015 cents"
  // is not a formatting accident: it is the price.
  function mrCents(x){
    if(!(x>0)) return "0";
    const d=Math.min(18,Math.max(0,Math.ceil(-Math.log10(x))+3));
    return x.toFixed(d);
  }
  function mrMiningSay(d,totalCents,frac){
    const f=Math.max(0,Math.min(1,frac));
    say("meatrider "+mrTierName(d)+" - mining "+(f*100).toFixed(1)+"%: "+
        mrCents(totalCents*f)+" cents mined, "+mrCents(totalCents*(1-f))+" cents left");
  }
  // The Tenor clip, transcoded to a 150px animated WebP and served by the gate
  // itself: no third-party script, no request to tenor.com from a challenged
  // browser, 194 KB instead of 3.8 MB. Only meatrider mining ever loads it.
  function mrMiningBox(){
    try{
      const img=document.createElement("img");
      img.src="/.within.website/x/cmd/anubis/api/static/anubis/meatrider-mining.webp";
      img.alt="a man mining coal"; img.width=150;
      img.style.cssText="display:block;margin:.6rem auto 0;border-radius:.5rem";
      const cap=document.createElement("div");
      cap.style.cssText="font-size:.75rem;opacity:.7;text-align:center;margin-top:.2rem";
      const a=document.createElement("a");
      a.href="https://tenor.com/view/mining-pakistani-pakistani-miner-pakistani-mining-coal-gif-16305674345809141538";
      a.textContent="via Tenor"; a.rel="noopener";
      cap.appendChild(a);
      const box=document.createElement("div");
      box.appendChild(img); box.appendChild(cap);
      const st=document.getElementById("status");
      if(st&&st.parentNode) st.parentNode.insertBefore(box,st.nextSibling);
      else if(document.body) document.body.appendChild(box);
      return box;
    }catch(_){ return null; }
  }
  // Every tier but meatrider shows the same clip while it mines: a cat clapping,
  // transcoded from 833 KB of Tenor GIF to 142 KB of animated WebP and served by
  // the gate itself, so a challenged browser makes no third-party request.
  // meatrider has its own clip (mrMiningBox above) and this one stays out of it.
  let catBox=null;
  function showMiningClip(){
    if(catBox||algo==="meatrider") return catBox;
    try{
      const img=document.createElement("img");
      img.src="/.within.website/x/cmd/anubis/api/static/anubis/cat-clapping.webp";
      img.alt="a cat clapping"; img.width=150;
      img.style.cssText="display:block;margin:.6rem auto 0;border-radius:.5rem";
      const cap=document.createElement("div");
      cap.style.cssText="font-size:.75rem;opacity:.7;text-align:center;margin-top:.2rem";
      const a=document.createElement("a");
      a.href="https://tenor.com/view/cat-clapping-tweenslop-gif-4721454909525108914";
      a.textContent="via Tenor"; a.rel="noopener";
      cap.appendChild(a);
      const box=document.createElement("div");
      box.appendChild(img); box.appendChild(cap);
      const st=document.getElementById("status");
      if(st&&st.parentNode) st.parentNode.insertBefore(box,st.nextSibling);
      else if(document.body) document.body.appendChild(box);
      catBox=box;
      return box;
    }catch(_){ return null; }
  }

  function meatriderBlurb(d){
    const hashes=Math.pow(2,d);
    const price=mrPriceUsd(d), name=mrTierName(d);
    return name+": 2^"+d+" hashes, $"+(price<0.01?price.toExponential(1):price.toFixed(2))+
      " of bitcoin at $0.05/TH-day, "+mrTime(hashes/2.34e14)+" of an Antminer S21 Pro, "+
      mrTime(hashes/1e6)+" of this browser's wasm kernel";
  }
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
    showMiningClip();
  }
  function workUpdate(frac,done,ms,expected,unit){
    if(workFill) workFill.style.width=(Math.max(0,Math.min(1,frac))*100).toFixed(1)+"%";
    if(workPct) workPct.textContent=(frac*100).toFixed(1)+"%";
    const rate=ms>0?done/(ms/1000):0;
    if(workRate) workRate.textContent=rate>0?(rate/1e6).toFixed(2)+" M"+(unit||"Hash")+"/s":"\u2014";
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
  if(algo==="preact"){
    // preact's proof is patience plus the digest of the random data, and the
    // server also wants the verification cookie from this page
    // (lib/challenge/preact/preact.go:74-85). Anubis's own client waits 125 ms
    // per point; the server only insists on 80.
    const wait=diff*125;
    say("waiting "+(wait/1000).toFixed(1)+" s");
    const t0=performance.now();
    setTimeout(async ()=>{
      const bytes=new TextEncoder().encode(ch.randomData);
      const h=await crypto.subtle.digest("SHA-256",bytes);
      const result=Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,"0")).join("");
      const u=new URL("/.within.website/x/cmd/anubis/api/pass-challenge",location.origin);
      u.searchParams.set("id",ch.id);
      u.searchParams.set("result",result);
      u.searchParams.set("redir",location.pathname+location.search);
      u.searchParams.set("elapsedTime",String(Math.round(performance.now()-t0)));
      location.replace(u.toString());
    }, wait+50);
    return;
  }
  // Our own kernels, served next to the page. Same ABI as the modules Anubis
  // ships: data_ptr / set_data_length / anubis_work / result_hash_*.
  const KERNELS={sha256:"sha256_pow_batch.wasm","wasm-sha256":"sha256_pow_batch.wasm",
                 argon2id:"argon2id_pow.wasm",hashx:"hashx_pow.wasm",
                 tensor:"tensor_pow.wasm",meatrider:"meatrider_pow.wasm"};
  // Wasm SIMD128 probe: a two-instruction module that only validates on an
  // engine with the v128 types. meatrider has a 4-lane kernel (~2.3x the
  // scalar one on the same bytes); everything else stays on its single module.
  const WASM_SIMD=(()=>{try{
    return WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,123,
      3,2,1,0,10,10,1,8,0,65,0,253,15,253,98,11]));
  }catch(_){return false;}})();
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

    // ----------------------------------------------------------- meatrider
    // The tier's WebGPU kernel, served next to the page as meatrider.wgsl
    // (webgpu/meatrider.wgsl). It mines the same 80-byte header as the wasm
    // fallback: the first 64 bytes are folded into a midstate here, the kernel
    // tries four nonces per invocation, and a hit is re-hashed by mrDigest()
    // before it is believed -- a driver that returns a wrong digest costs a
    // dispatch, not a wrong answer.
    const MR_IV=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const MR_K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    const MR_LANES=4, MR_THREADS=64, MR_PER_GROUP=MR_LANES*MR_THREADS, MR_RESULTS_U32=76;
    const mrBe32=(a,o)=>((a[o]<<24)|(a[o+1]<<16)|(a[o+2]<<8)|a[o+3])>>>0;
    const mrPutLE=(a,o,v)=>{a[o]=v&255;a[o+1]=(v>>>8)&255;a[o+2]=(v>>>16)&255;a[o+3]=(v>>>24)&255;};
    const mrRotr=(x,n)=>((x>>>n)|(x<<(32-n)))>>>0;

    function mrCompress(h,w){
      const ww=new Uint32Array(64); ww.set(w);
      for(let i=16;i<64;i++){
        const x=ww[i-15], y=ww[i-2];
        const s0=(mrRotr(x,7)^mrRotr(x,18)^(x>>>3))>>>0;
        const s1=(mrRotr(y,17)^mrRotr(y,19)^(y>>>10))>>>0;
        ww[i]=(ww[i-16]+s0+ww[i-7]+s1)>>>0;
      }
      let a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
      for(let i=0;i<64;i++){
        const S1=(mrRotr(e,6)^mrRotr(e,11)^mrRotr(e,25))>>>0;
        const ch=((e&f)^((~e)&g))>>>0;
        const t1=(hh+S1+ch+MR_K[i]+ww[i])>>>0;
        const S0=(mrRotr(a,2)^mrRotr(a,13)^mrRotr(a,22))>>>0;
        const maj=((a&b)^(a&c)^(b&c))>>>0;
        const t2=(S0+maj)>>>0;
        hh=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
      }
      h[0]=(h[0]+a)>>>0;h[1]=(h[1]+b)>>>0;h[2]=(h[2]+c)>>>0;h[3]=(h[3]+d)>>>0;
      h[4]=(h[4]+e)>>>0;h[5]=(h[5]+f)>>>0;h[6]=(h[6]+g)>>>0;h[7]=(h[7]+hh)>>>0;
    }

    // SHA-256 of a message under 56 bytes: one padded block.
    function mrShaShort(msg){
      const h=Uint32Array.from(MR_IV), blk=new Uint8Array(64), bits=msg.length*8;
      blk.set(msg); blk[msg.length]=0x80;
      blk[62]=(bits>>>8)&255; blk[63]=bits&255;
      const w=new Uint32Array(16);
      for(let i=0;i<16;i++) w[i]=mrBe32(blk,4*i);
      mrCompress(h,w);
      return h;
    }

    // Bitcoin's nBits for the exact target 2^(256-difficulty).
    function mrBitsFor(diff){
      const blen=257-diff, size=Math.ceil(blen/8);
      let compact = size<=3 ? ((1<<(blen-1))<<(8*(3-size)))>>>0
                            : (1<<((blen-1)-8*(size-3)))>>>0;
      let sz=size;
      if(compact&0x00800000){compact=(compact>>>8)>>>0;sz++;}
      return (compact|(sz<<24))>>>0;
    }

    // The host half of meatrider_ctx_init(): midstate[8] plus the tail words.
    function mrCtx(rd,diff){
      const label=new Uint8Array(9+32);
      label.set([109,101,97,116,114,105,100,101,114]);   // "meatrider"
      label.set(rd,9);
      const mw=mrShaShort(label), merkle=new Uint8Array(32);
      for(let i=0;i<8;i++){
        merkle[4*i]=mw[i]>>>24;merkle[4*i+1]=(mw[i]>>>16)&255;
        merkle[4*i+2]=(mw[i]>>>8)&255;merkle[4*i+3]=mw[i]&255;
      }
      const first=new Uint8Array(64);
      mrPutLE(first,0,1); first.set(rd,4); first.set(merkle.subarray(0,28),36);
      const mid=Uint32Array.from(MR_IV), w=new Uint32Array(16);
      for(let i=0;i<16;i++) w[i]=mrBe32(first,4*i);
      mrCompress(mid,w);
      const tail=new Uint8Array(12);
      tail.set(merkle.subarray(28,32),0);
      mrPutLE(tail,4,1231006505);                // the genesis timestamp
      mrPutLE(tail,8,mrBitsFor(diff));
      return {mid, tailWords:[mrBe32(tail,0),mrBe32(tail,4),mrBe32(tail,8)], first};
    }

    // The reference digest for one nonce, in display order, in JavaScript.
    function mrDigest(ctx,nonce){
      const blk=new Uint8Array(64), w=new Uint32Array(16);
      const h=Uint32Array.from(ctx.mid);
      const tw=(o,v)=>{blk[o]=v>>>24;blk[o+1]=(v>>>16)&255;blk[o+2]=(v>>>8)&255;blk[o+3]=v&255;};
      tw(0,ctx.tailWords[0]); tw(4,ctx.tailWords[1]); tw(8,ctx.tailWords[2]);
      mrPutLE(blk,12,nonce>>>0); blk[16]=0x80; blk[62]=0x02; blk[63]=0x80;
      for(let i=0;i<16;i++) w[i]=mrBe32(blk,4*i);
      mrCompress(h,w);
      blk.fill(0);
      for(let i=0;i<8;i++) tw(4*i,h[i]);
      blk[32]=0x80; blk[62]=0x01; blk[63]=0x00;
      for(let i=0;i<16;i++) w[i]=mrBe32(blk,4*i);
      const h2=Uint32Array.from(MR_IV);
      mrCompress(h2,w);
      const out=new Uint8Array(32);
      for(let i=0;i<8;i++) mrPutLE(out,4*i,h2[7-i]);
      return tohex(out);
    }

    // Mine the challenge on WebGPU. Throws when there is no adapter, the shader
    // does not compile, or nothing is found in a bounded number of dispatches;
    // the caller falls through to wasm in every one of those cases.
    async function mrWebGPU(rd,diff,totalCents){
      if(!navigator.gpu) throw new Error("this browser has no navigator.gpu");
      const adapter=await navigator.gpu.requestAdapter();
      if(!adapter) throw new Error("no WebGPU adapter");
      const device=await adapter.requestDevice();
      const code=await (await fetch("/.within.website/x/cmd/anubis/api/static/anubis/meatrider.wgsl")).text();
      const module=device.createShaderModule({code,label:"meatrider"});
      const info=await module.getCompilationInfo();
      if(info.messages.some(m=>m.type==="error")) throw new Error("the WGSL kernel did not compile");
      const pipeline=device.createComputePipeline({layout:"auto",compute:{module,entryPoint:"main"}});
      const paramsBuf=device.createBuffer({size:64,usage:GPUBufferUsage.UNIFORM|GPUBufferUsage.COPY_DST});
      const resultsBuf=device.createBuffer({size:MR_RESULTS_U32*4,usage:GPUBufferUsage.STORAGE|GPUBufferUsage.COPY_SRC|GPUBufferUsage.COPY_DST});
      const readBuf=device.createBuffer({size:MR_RESULTS_U32*4,usage:GPUBufferUsage.MAP_READ|GPUBufferUsage.COPY_DST});
      const bind=device.createBindGroup({layout:pipeline.getBindGroupLayout(0),entries:[
        {binding:0,resource:{buffer:paramsBuf}},{binding:1,resource:{buffer:resultsBuf}}]});
      const ctx=mrCtx(rd,diff), CHUNK=1<<22, expected=Math.pow(2,diff);
      let base=0, scanned=0;
      const t0=performance.now();
      for(let c=0;c<1024;c++){
        const params=new Uint32Array(16);
        params.set(ctx.mid,0); params.set(ctx.tailWords,8);
        params[11]=diff>>>0; params[12]=base>>>0; params[13]=CHUNK;
        device.queue.writeBuffer(paramsBuf,0,params);
        device.queue.writeBuffer(resultsBuf,0,new Uint32Array(MR_RESULTS_U32));
        const enc=device.createCommandEncoder();
        const pass=enc.beginComputePass();
        pass.setPipeline(pipeline); pass.setBindGroup(0,bind);
        pass.dispatchWorkgroups(Math.ceil(CHUNK/MR_PER_GROUP));
        pass.end();
        enc.copyBufferToBuffer(resultsBuf,0,readBuf,0,MR_RESULTS_U32*4);
        device.queue.submit([enc.finish()]);
        await device.queue.onSubmittedWorkDone();
        await readBuf.mapAsync(GPUMapMode.READ);
        const u32=new Uint32Array(readBuf.getMappedRange()).slice(0);
        readBuf.unmap();
        base=(base+CHUNK)>>>0; scanned+=CHUNK;
        const ms=performance.now()-t0;
        if(u32[0]>0){
          let best=null;
          for(let s=0;s<Math.min(8,u32[0]);s++){
            const nonce=u32[4+s], words=u32.slice(12+s*8,12+s*8+8);
            let hexd=""; for(const w of words) hexd+=w.toString(16).padStart(8,"0");
            if(!best||nonce<best.nonce) best={nonce,hash:hexd};
          }
          if(best&&mrDigest(ctx,best.nonce)===best.hash){
            return {nonce:best.nonce,hash:best.hash,ms,scanned};
          }
          console.warn("meatrider: a WebGPU hit did not survive the JavaScript check");
        }
        const frac=Math.min(0.99,scanned/expected);
        workUpdate(frac,scanned,ms,expected);
        mrMiningSay(diff,totalCents,frac);
        await new Promise(r=>setTimeout(r,0));
      }
      throw new Error("no hit after "+scanned.toLocaleString("en-US")+" nonces");
    }

    // meatrider: the nonce is the last field of an 80-byte Bitcoin header, so
    // there is nothing to batch and no JIT to build. What the windowed export
    // buys is a progress bar and a tab that can be closed; the per-hash work is
    // two compressions after the challenge's fixed midstate.
    if(algo==="meatrider"){
      say("meatrider: "+meatriderBlurb(diff));
      if(diff>32){
        // The rung is priced for hardware. If the operator published a bitcoin
        // address, offer the other way past it: pay, and submit the receipt the
        // gate derives for this challenge id once the payment is confirmed.
        const pay=rules.pay;
        if(pay&&pay.address){
          const uri="bitcoin:"+pay.address+"?amount="+pay.btc+
                    "&label=meatrider&message="+encodeURIComponent("meatrider "+pay.sats+" sats");
          say("meatrider: this rung is priced at $"+(pay.usd<0.01?pay.usd.toExponential(2):pay.usd.toFixed(2))+
              " ("+pay.sats+" sats). Pay "+pay.btc+" BTC to "+pay.address+
              ", then paste the receipt the operator gave you.");
          try{
            const a=document.createElement("a");
            a.href=uri;
            a.textContent="open in a bitcoin wallet";
            a.style.cssText="display:inline-block;margin-left:.5rem;color:#f7931a";
            document.body.appendChild(a);
          }catch(_){}
          const r=prompt("This rung is priced for an ASIC.\n\nPay "+pay.btc+" BTC ("+
                         pay.sats+" sats) to:\n"+pay.address+"\n\n"+uri+
                         "\n\nThen paste the receipt the operator gave you:", "");
          if(r&&/^[0-9a-fA-F]{64}$/.test(r.trim())){
            pass(r.trim().toLowerCase(),0,0);
            return null;
          }
        }
        const refused=new Error("this rung is priced for an ASIC: "+meatriderBlurb(diff)+
          ". A browser cannot mine past 32 bits of difficulty, because one full "+
          "32-bit nonce sweep would already be 2^32 hashes -- that is the point of the rung");
        refused.meatriderRefused=true;
        throw refused;
      }
      const totalCents=mrPriceUsd(diff)*100;
      const box=mrMiningBox();
      mrMiningSay(diff,totalCents,0);
      // The site-wide progress bar, which the other tiers show and meatrider
      // never did: the number of hashes this rung needs is known exactly, so the
      // bar is real progress, not a spinner. It is fed by workUpdate() in both
      // the WebGPU loop (4M nonces per dispatch) and the wasm loop (262,144).
      workShow("2^"+diff+" ("+Math.pow(2,diff).toLocaleString("en-US")+") hashes expected: "+
               "WebGPU mines 4 nonces per invocation in 4,194,304-nonce dispatches, "+
               "the wasm fallback in 262,144-nonce windows");
      workUpdate(0,0,1,Math.pow(2,diff));
      // WebGPU first: the same kernel the tier ships for its GPU rows, and the
      // fastest thing a browser can bring. A hit is re-hashed in JavaScript
      // above, and any failure (no adapter, a shader that will not compile, no
      // hit) falls through to the wasm module below.
      if(navigator.gpu){
        try{
          say("meatrider: asking WebGPU for the kernel (4 nonces per invocation)");
          const g=await mrWebGPU(raw,diff,totalCents);
          const rate=g.scanned/(g.ms/1000);
          if(box) box.remove();
          workUpdate(1,g.scanned,g.ms,Math.pow(2,diff));
          workDone();
          say("solved with nonce "+g.nonce+" in "+g.ms.toFixed(0)+" ms on WebGPU ("+
              (rate/1e6).toFixed(1)+" MHash/s over "+g.scanned.toLocaleString("en-US")+
              " nonces, 4 per invocation)");
          console.log("meatrider-webgpu "+JSON.stringify({nonce:g.nonce,ms:Math.round(g.ms),
            nonces:g.scanned,mhs:+(rate/1e6).toFixed(1),difficulty:diff}));
          return {hash:g.hash,nonce:g.nonce,ms:g.ms};
        }catch(e){
          console.warn("meatrider: WebGPU path failed, using wasm:",e);
          say("WebGPU unavailable here ("+e.message+"), using the wasm kernel");
          workShow("2^"+diff+" ("+Math.pow(2,diff).toLocaleString("en-US")+
                   ") hashes expected: wasm kernel, 262,144-nonce windows");
        }
      }
      // Four nonces per SIMD vector where the browser can do it; the scalar
      // module computes the same digests, one at a time.
      const file=(WASM_SIMD?"meatrider_simd.wasm":name);
      say("loading the meatrider kernel (SHA-256d over an 80-byte Bitcoin header, "+
          (WASM_SIMD?"4-lane wasm SIMD":"scalar wasm")+")");
      const bytes=await (await fetch("/.within.website/x/cmd/anubis/api/static/anubis/"+file)).arrayBuffer();
      const {instance}=await WebAssembly.instantiate(bytes,{});
      const ex=instance.exports;
      new Uint8Array(ex.memory.buffer).set(raw,ex.data_ptr());
      ex.set_data_length(raw.length);
      const win=1<<18, expected=Math.pow(2,diff);
      let base=0, t0=performance.now();
      for(;;){
        const hit=ex.anubis_work_limited(diff>>>0,base>>>0,1,win);
        base=(base+win)>>>0;
        const ms=performance.now()-t0, done=base;
        if(hit>=0){
          const digest=new Uint8Array(ex.memory.buffer,ex.result_hash_ptr(),ex.result_hash_size());
          if(box) box.remove();
          workUpdate(1,done,ms,expected);
          workDone();
          return {hash:tohex(digest),nonce:hit,ms};
        }
        const frac=Math.min(0.99,done/expected);
        workUpdate(frac,done,ms,expected);
        mrMiningSay(diff,totalCents,frac);
        await new Promise(r=>setTimeout(r,0));
      }
    }

    say("loading the "+algo+" kernel");
    const bytes=await (await fetch("/.within.website/x/cmd/anubis/api/static/anubis/"+name)).arrayBuffer();
    const {instance}=await WebAssembly.instantiate(bytes,{anubis:{anubis_update_nonce:()=>{}}});
    return run(instance.exports);
  }

  // ---------------------------------------------------------------- Argon2id
  // Pure-JavaScript Argon2id, for browsers where WebAssembly is disabled,
  // missing, or refused. The host side (BLAKE2b, H0, B0/B1, the final tag) is
  // the same code the WebGPU demo uses; the fill phase is a straight port of
  // third_party/argon2/ref.c with the parameters Anubis fixes: Argon2id v1.3,
  // m=19456 KiB, t=2, p=1, 32-byte tag. 64-bit words are (lo, hi) u32 pairs;
  // 38,912 block fills per hash, one hash at a time.
// argon2id-blake2b.js — BLAKE2b-512, blake2b_long and Argon2id's host-side
// derivation (H0, B0, B1, the final tag), ported from the vendored reference:
//
//   third_party/argon2/blake2/blake2b.c      blake2b_init/update/final, blake2b_long
//   third_party/argon2/core.c                initial_hash(), fill_first_blocks(), finalize()
//   wasm/argon2id_pow.c                      the password/salt encoding Anubis uses
//
// The state is BigInt because this runs ~67 BLAKE2b compressions per Argon2id
// hash against 38,912 block fills on the GPU — it is noise either way, and
// BigInt is the version that is obviously right. See the comment in
// argon2id.html for the split of work between host and device.

const MASK64 = (1n << 64n) - 1n;

const IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

const SIGMA = [
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

const rotr64 = (x, n) => {
  const k = BigInt(n);
  return ((x >> k) | (x << (64n - k))) & MASK64;
};

class Blake2b {
  constructor(outlen) {
    this.outlen = outlen;
    this.h = IV.slice();
    // blake2b_param: digest_length, key_length, fanout=1, depth=1, the rest 0
    this.h[0] ^= BigInt(outlen) | (1n << 16n) | (1n << 24n);
    this.t = [0n, 0n];
    this.f = [0n, 0n];
    this.buf = new Uint8Array(128);
    this.buflen = 0;
  }

  increment(inc) {
    const before = this.t[0];
    this.t[0] = (before + BigInt(inc)) & MASK64;
    if (this.t[0] < before) this.t[1] = (this.t[1] + 1n) & MASK64;
  }

  update(bytes) {
    const inlen = bytes.length;
    if (inlen === 0) return;
    let pin = 0;
    if (this.buflen + inlen > 128) {
      const fill = 128 - this.buflen;
      this.buf.set(bytes.subarray(0, fill), this.buflen);
      this.increment(128);
      this.compress(this.buf);
      this.buflen = 0;
      pin = fill;
      while (inlen - pin > 128) {
        this.increment(128);
        this.compress(bytes.subarray(pin, pin + 128));
        pin += 128;
      }
    }
    this.buf.set(bytes.subarray(pin), this.buflen);
    this.buflen += inlen - pin;
  }

  compress(block) {
    const dv = new DataView(block.buffer, block.byteOffset, 128);
    const m = new Array(16);
    for (let i = 0; i < 16; i++) m[i] = dv.getBigUint64(8 * i, true);
    const v = new Array(16);
    for (let i = 0; i < 8; i++) v[i] = this.h[i];
    v[8] = IV[0]; v[9] = IV[1]; v[10] = IV[2]; v[11] = IV[3];
    v[12] = IV[4] ^ this.t[0];
    v[13] = IV[5] ^ this.t[1];
    v[14] = IV[6] ^ this.f[0];
    v[15] = IV[7] ^ this.f[1];

    const G = (a, b, c, d, x, y) => {
      v[a] = (v[a] + v[b] + m[x]) & MASK64;
      v[d] = rotr64(v[d] ^ v[a], 32);
      v[c] = (v[c] + v[d]) & MASK64;
      v[b] = rotr64(v[b] ^ v[c], 24);
      v[a] = (v[a] + v[b] + m[y]) & MASK64;
      v[d] = rotr64(v[d] ^ v[a], 16);
      v[c] = (v[c] + v[d]) & MASK64;
      v[b] = rotr64(v[b] ^ v[c], 63);
    };

    for (let r = 0; r < 12; r++) {
      const s = SIGMA[r];
      G(0, 4, 8, 12, s[0], s[1]);
      G(1, 5, 9, 13, s[2], s[3]);
      G(2, 6, 10, 14, s[4], s[5]);
      G(3, 7, 11, 15, s[6], s[7]);
      G(0, 5, 10, 15, s[8], s[9]);
      G(1, 6, 11, 12, s[10], s[11]);
      G(2, 7, 8, 13, s[12], s[13]);
      G(3, 4, 9, 14, s[14], s[15]);
    }

    for (let i = 0; i < 8; i++) this.h[i] = this.h[i] ^ v[i] ^ v[i + 8];
  }

  final() {
    this.increment(this.buflen);
    this.f[0] = MASK64;                       // last block
    this.buf.fill(0, this.buflen, 128);
    this.compress(this.buf);
    const out = new Uint8Array(64);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) dv.setBigUint64(8 * i, this.h[i], true);
    return out.slice(0, this.outlen);
  }
}

function blake2b(outlen, input) {
  const s = new Blake2b(outlen);
  s.update(input);
  return s.final();
}

const u32le = (x) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, x >>> 0, true);
  return b;
};

const concat = (...parts) => {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

/** blake2b_long() from blake2b.c: expand a digest to an arbitrary length. */
function blake2bLong(outlen, input) {
  const prefix = u32le(outlen);
  if (outlen <= 64) return blake2b(outlen, concat(prefix, input));

  const out = new Uint8Array(outlen);
  let buf = blake2b(64, concat(prefix, input));
  out.set(buf.subarray(0, 32), 0);
  let pos = 32;
  let toproduce = outlen - 32;
  while (toproduce > 64) {
    buf = blake2b(64, buf);
    out.set(buf.subarray(0, 32), pos);
    pos += 32;
    toproduce -= 32;
  }
  buf = blake2b(toproduce, buf);
  out.set(buf.subarray(0, toproduce), pos);
  return out;
}

/* ---------------------------- Argon2id host side ---------------------------- */

const ARGON2 = {
  lanes: 1, outlen: 32, mCost: 19456, tCost: 2, version: 0x13, type: 2, /* Argon2_id */
};

/** H0 = blake2b_512(LE32 params || LE32 pwdlen || pwd || LE32 saltlen || salt ||
 *                  LE32 secretlen || LE32 adlen) — initial_hash() in core.c. */
function h0(password, salt, p = ARGON2) {
  const s = new Blake2b(64);
  s.update(u32le(p.lanes));
  s.update(u32le(p.outlen));
  s.update(u32le(p.mCost));
  s.update(u32le(p.tCost));
  s.update(u32le(p.version));
  s.update(u32le(p.type));
  s.update(u32le(password.length));
  s.update(password);
  s.update(u32le(salt.length));
  s.update(salt);
  s.update(u32le(0));                        // secretlen, no secret
  s.update(u32le(0));                        // adlen, no associated data
  return s.final();
}

/** B0 = H'(H0 || LE32(0) || LE32(lane)), B1 = H'(H0 || LE32(1) || LE32(lane)). */
function firstBlocks(h0bytes, lane = 0) {
  const seed = new Uint8Array(72);
  seed.set(h0bytes, 0);
  const dv = new DataView(seed.buffer);
  dv.setUint32(64, 0, true);
  dv.setUint32(68, lane, true);
  const b0 = blake2bLong(1024, seed);
  dv.setUint32(64, 1, true);
  const b1 = blake2bLong(1024, seed);
  return { b0, b1 };
}

/** The tag: H'(C, outlen) over the final 1 KiB block (one lane, so no XOR). */
function tagFromFinalBlock(finalBlock, outlen = 32) {
  return blake2bLong(outlen, finalBlock);
}

/**
 * Anubis's salt: 8 bytes, the u32 nonce in bytes 0..3 little-endian if the last
 * challenge byte is >= 0x80 (bytes 4..7 zero), otherwise the nonce in bytes
 * 4..7 big-endian (bytes 0..3 zero). Copied from wasm/argon2id_pow.c.
 */
function anubisSalt(challenge, nonce) {
  const salt = new Uint8Array(8);
  const le = challenge.length > 0 && challenge[challenge.length - 1] >= 0x80;
  const n = nonce >>> 0;
  if (le) {
    salt[0] = n & 255; salt[1] = (n >>> 8) & 255;
    salt[2] = (n >>> 16) & 255; salt[3] = (n >>> 24) & 255;
  } else {
    salt[7] = n & 255; salt[6] = (n >>> 8) & 255;
    salt[5] = (n >>> 16) & 255; salt[4] = (n >>> 24) & 255;
  }
  return salt;
}



const A2_BLOCKS = 19456, A2_WORDS = 256, A2_SEGMENT = 4864, A2_ADDRESSES = 128;

let mem = null, R = null, T = null, V = null, ADDR = null, INPUT = null, ZERO = null;
function scratch() {
    if (!mem) {
        mem = new Uint32Array(A2_BLOCKS * A2_WORDS);
        R = new Uint32Array(A2_WORDS); T = new Uint32Array(A2_WORDS);
        V = new Uint32Array(32);
        ADDR = new Uint32Array(A2_WORDS); INPUT = new Uint32Array(A2_WORDS);
        ZERO = new Uint32Array(A2_WORDS);
    }
}

function mulhi32(a, b) {
    a >>>= 0; b >>>= 0;
    const al = a & 0xffff, ah = a >>> 16, bl = b & 0xffff, bh = b >>> 16;
    const t0 = al * bl, t1 = al * bh, t2 = ah * bl, t3 = ah * bh;
    const mid = (t0 >>> 16) + (t1 & 0xffff) + (t2 & 0xffff);
    return (t3 + (t1 >>> 16) + (t2 >>> 16) + (mid >>> 16)) >>> 0;
}

// v[a] = fBlaMka(v[a], v[b]); 32-bit pair layout, v is Uint32Array of u32 words
function blamka(v, a, b) {
    const ai = 2 * a, bi = 2 * b;
    const xl = v[ai], xh = v[ai + 1], yl = v[bi], yh = v[bi + 1];
    const lo = Math.imul(xl, yl) >>> 0;
    const hi = mulhi32(xl, yl);
    const dl = (lo << 1) >>> 0, dh = ((hi << 1) | (lo >>> 31)) >>> 0;
    const sl = (xl + yl) >>> 0, sh = (xh + yh + (sl < xl ? 1 : 0)) >>> 0;
    const rl = (sl + dl) >>> 0, rh = (sh + dh + (rl < sl ? 1 : 0)) >>> 0;
    v[ai] = rl; v[ai + 1] = rh;
}
function xorRotr(v, d, s, n) {
    const di = 2 * d, si = 2 * s;
    let lo = (v[di] ^ v[si]) >>> 0, hi = (v[di + 1] ^ v[si + 1]) >>> 0;
    let l, h;
    if (n === 32) { l = hi; h = lo; }
    else if (n < 32) { l = ((lo >>> n) | (hi << (32 - n))) >>> 0; h = ((hi >>> n) | (lo << (32 - n))) >>> 0; }
    else { const m = 64 - n; l = ((lo << m) | (hi >>> (32 - m))) >>> 0; h = ((hi << m) | (lo >>> (32 - m))) >>> 0; }
    v[di] = l; v[di + 1] = h;
}
// g/round over a 16-u64 window starting at u64 index `base`; lets the
// contiguous groups run in R directly instead of being copied to V.
function gAt(v, base, a, b, c, d) {
    blamka(v, base + a, base + b); xorRotr(v, base + d, base + a, 32);
    blamka(v, base + c, base + d); xorRotr(v, base + b, base + c, 24);
    blamka(v, base + a, base + b); xorRotr(v, base + d, base + a, 16);
    blamka(v, base + c, base + d); xorRotr(v, base + b, base + c, 63);
}
function roundAt(v, base) {
    gAt(v, base, 0, 4, 8, 12); gAt(v, base, 1, 5, 9, 13);
    gAt(v, base, 2, 6, 10, 14); gAt(v, base, 3, 7, 11, 15);
    gAt(v, base, 0, 5, 10, 15); gAt(v, base, 1, 6, 11, 12);
    gAt(v, base, 2, 7, 8, 13); gAt(v, base, 3, 4, 9, 14);
}

function fill(prevBuf, prevOff, refBuf, refOff, dstBuf, dstOff, withXor) {
    for (let j = 0; j < A2_WORDS; j++) {
        const x = (refBuf[refOff + j] ^ prevBuf[prevOff + j]) >>> 0;
        R[j] = x;
        T[j] = withXor ? (x ^ dstBuf[dstOff + j]) >>> 0 : x;
    }
    // contiguous 16-u64 groups (ref.c's first loop), in place
    for (let i = 0; i < 8; i++) roundAt(R, 16 * i);
    // strided groups (ref.c's second loop)
    for (let i = 0; i < 8; i++) {
        for (let m = 0; m < 16; m++) {
            const src = 2 * i + (m >> 1) * 16 + (m & 1);
            V[2 * m] = R[2 * src]; V[2 * m + 1] = R[2 * src + 1];
        }
        roundAt(V, 0);
        for (let m = 0; m < 16; m++) {
            const src = 2 * i + (m >> 1) * 16 + (m & 1);
            R[2 * src] = V[2 * m]; R[2 * src + 1] = V[2 * m + 1];
        }
    }
    for (let j = 0; j < A2_WORDS; j++) dstBuf[dstOff + j] = (T[j] ^ R[j]) >>> 0;
}

function nextAddresses() {
    const lo = (INPUT[12] + 1) >>> 0;
    INPUT[12] = lo;
    if (lo === 0) INPUT[13] = (INPUT[13] + 1) >>> 0;
    fill(ZERO, 0, INPUT, 0, ADDR, 0, false);
    fill(ZERO, 0, ADDR, 0, ADDR, 0, false);
}

function indexAlpha(pass, slice, idx, pseudoRand) {
    let area;
    if (pass === 0) area = slice === 0 ? idx - 1 : slice * A2_SEGMENT + idx - 1;
    else area = A2_BLOCKS - A2_SEGMENT + idx - 1;
    const rp = mulhi32(pseudoRand >>> 0, pseudoRand >>> 0);
    const rel = (area - 1 - mulhi32(area >>> 0, rp)) >>> 0;
    let start = 0;
    if (pass !== 0 && slice !== 3) start = (slice + 1) * A2_SEGMENT;
    return (start + rel) % A2_BLOCKS;
}

function resetInput(pass, slice) {
    INPUT.fill(0);
    INPUT[0] = pass; INPUT[2] = 0; INPUT[4] = slice;
    INPUT[6] = A2_BLOCKS; INPUT[8] = 2; INPUT[10] = 2;
}

function storeBlock(off, bytes) {
    for (let i = 0; i < A2_WORDS; i++) {
        const p = 4 * i;
        mem[off + i] = (bytes[p] | (bytes[p + 1] << 8) | (bytes[p + 2] << 16) | (bytes[p + 3] << 24)) >>> 0;
    }
}
function blockBytes(off) {
    const out = new Uint8Array(1024);
    for (let i = 0; i < A2_WORDS; i++) {
        const w = mem[off + i];
        out[4 * i] = w & 255; out[4 * i + 1] = (w >>> 8) & 255;
        out[4 * i + 2] = (w >>> 16) & 255; out[4 * i + 3] = (w >>> 24) & 255;
    }
    return out;
}

function argon2idTag(password, nonce) {
    scratch();
    const salt = anubisSalt(password, nonce);
    const h0bytes = h0(password, salt);
    const { b0, b1 } = firstBlocks(h0bytes);
    storeBlock(0, b0); storeBlock(A2_WORDS, b1);

    for (let pass = 0; pass < 2; pass++) {
        for (let slice = 0; slice < 4; slice++) {
            const independent = pass === 0 && slice < 2;
            if (independent) resetInput(pass, slice);
            let i = (pass === 0 && slice === 0) ? 2 : 0;
            if (pass === 0 && slice === 0 && independent) nextAddresses();
            let curr = slice * A2_SEGMENT + i;
            let prev = curr === 0 ? A2_BLOCKS - 1 : curr - 1;
            for (; i < A2_SEGMENT; i++, curr++, prev++) {
                if (curr === 1) prev = 0;
                let pseudo;
                if (independent) {
                    if (i % A2_ADDRESSES === 0) nextAddresses();
                    pseudo = ADDR[2 * (i % A2_ADDRESSES)];
                } else {
                    pseudo = mem[prev * A2_WORDS];
                }
                const refIndex = indexAlpha(pass, slice, i, pseudo);
                fill(mem, prev * A2_WORDS, mem, refIndex * A2_WORDS, mem, curr * A2_WORDS, pass !== 0);
            }
        }
    }
    return tagFromFinalBlock(blockBytes((A2_BLOCKS - 1) * A2_WORDS), 32);
}

  // --------------------------------------------------------------- tensor
  // One integer GEMM: A (N x N, uint8 masked to 0..127) times B (N x N,
  // int8), accumulated exactly in int32, digest = SHA-256 of C written as
  // N*N little-endian int32. There is no nonce to search: the digest is the
  // whole proof, and the server recomputes one GEMM to check it.
  //
  // Three paths produce the same bytes. WebNN (navigator.ml) is the point of
  // the tier: an int8 gemm on a GPU or an NPU, which is far more than a CPU
  // can do and is the reason a browser without WebAssembly can still work.
  // The wasm kernel is the portable accelerated floor, and the plain
  // JavaScript GEMM below is the last resort, at roughly a tenth of the wasm
  // rate. Unlike the hash tiers, none of this is optimisable away: the
  // digest covers every output element, so the work has to happen.
  const tenN=()=>64*Math.max(2,Math.min(16,diff));
  function tensorExpand(rd,n){
    const raw=hex2bytes(rd);
    const cells=n*n, seed=sha256bytes(raw);
    const a=new Uint8Array(cells), b=new Int8Array(cells);
    const msg=new Uint8Array(36), ctr=msg.subarray(32,36);
    msg.set(seed,0);
    let pos=0, counter=0;
    while(pos<2*cells){
      ctr[0]=counter&255; ctr[1]=(counter>>>8)&255;
      ctr[2]=(counter>>>16)&255; ctr[3]=(counter>>>24)&255;
      const block=sha256bytes(msg);
      for(let i=0;i<32&&pos<2*cells;i++,pos++){
        if(pos<cells) a[pos]=block[i]&0x7f;
        else b[pos-cells]=(block[i]<<24)>>24;
      }
      counter++;
    }
    return {a:a,b:b};
  }
  // i-k-j: one row of B and one row of C walked sequentially, which is the
  // order V8 keeps in cache. Skipping a zero in A is safe: 0*anything is 0.
  function tensorRows(a,b,c,n,from,to){
    for(let i=from;i<to;i++){
      const row=i*n;
      for(let k=0;k<n;k++){
        const av=a[row+k]; if(av===0) continue;
        const brow=k*n;
        for(let j=0;j<n;j++) c[row+j]+=av*b[brow+j];
      }
    }
  }
  function tensorDigest(c,n){
    const bytes=new Uint8Array(n*n*4), v=new DataView(bytes.buffer);
    for(let i=0;i<c.length;i++) v.setInt32(4*i,c[i],true);
    return tohex(sha256bytes(bytes));
  }
  async function tensorInJs(n){
    say("solving tensor in pure JavaScript (no WebAssembly)");
    const {a,b}=tensorExpand(ch.randomData,n);
    const c=new Int32Array(n*n);
    const t0=performance.now(), blocks=Math.max(1,n>>4), macs=2*n*n*n;
    workShow("pure-JavaScript int8 GEMM, "+n+"x"+n+"x"+n+" ("+
             (macs/1e9).toFixed(1)+" GMAC, "+blocks+" row blocks)");
    for(let s=0;s<blocks;s++){
      tensorRows(a,b,c,n,Math.floor(n*s/blocks),Math.floor(n*(s+1)/blocks));
      workUpdate((s+1)/blocks,macs*(s+1)/blocks,performance.now()-t0,macs,"MAC");
      await new Promise(r=>setTimeout(r,0));
    }
    workDone();
    return {hash:tensorDigest(c,n),nonce:0,ms:performance.now()-t0};
  }
  // WebNN: the graph is a single gemm. Support varies by browser and by
  // backend, so nothing here is trusted: the result of two rows is recomputed
  // in JavaScript and compared before the digest is accepted. A backend that
  // cannot do the gemm throws at build() and the wasm kernel takes over.
  //
  // The spec's gemm() is float32/float16 only, so the integer matrices are
  // widened to float32. That is exact here: every partial sum is an integer
  // bounded by 1024*127*128 < 2^24, and float32 represents every integer up
  // to 2^24. The output is narrowed back to int32 after the read.
  async function tensorWebNN(n){
    const ml=navigator.ml;
    if(!ml||typeof ml.createContext!=="function") return null;
    say("asking WebNN for a GEMM");
    const ctx=await ml.createContext({deviceType:"gpu"});
    const builder=new MLGraphBuilder(ctx);
    const A=builder.input("A",{dataType:"float32",shape:[n,n]});
    const B=builder.input("B",{dataType:"float32",shape:[n,n]});
    const C=builder.gemm(A,B);
    const graph=await builder.build({C});
    const {a,b}=tensorExpand(ch.randomData,n);
    const af=Float32Array.from(a), bf=Float32Array.from(b);
    const tA=ctx.createTensor({dataType:"float32",shape:[n,n],writable:true,readable:false});
    const tB=ctx.createTensor({dataType:"float32",shape:[n,n],writable:true,readable:false});
    const tC=ctx.createTensor({dataType:"float32",shape:[n,n],writable:false,readable:true});
    const t0=performance.now();
    ctx.writeTensor(tA,af); ctx.writeTensor(tB,bf);
    ctx.dispatch(graph,{A:tA,B:tB},{C:tC});
    const out=await ctx.readTensor(tC);
    const raw=new Float32Array(out.buffer?out.buffer.slice(out.byteOffset,out.byteOffset+out.byteLength):out);
    const c=new Int32Array(raw.length);
    for(let i=0;i<raw.length;i++) c[i]=Math.round(raw[i]);
    // two rows of independent JavaScript GEMM: cheap (0.4% of the work) and
    // the difference between "WebNN worked" and "WebNN returned rubbish"
    for(const row of [0,n>>1]){
      const want=new Int32Array(n);
      tensorRows(a,b,want,n,row,row+1);
      for(let j=0;j<n;j++){
        if(c[row*n+j]!==want[j]) throw new Error("WebNN row "+row+" column "+j+
          ": "+c[row*n+j]+" != "+want[j]);
      }
    }
    workDone();
    return {hash:tensorDigest(c,n),nonce:0,ms:performance.now()-t0};
  }
  async function solveTensor(){
    const n=tenN();
    if(forcedJs){ say("tensor: pure JavaScript requested"); return tensorInJs(n); }
    if(typeof WebAssembly==="object"){
      if(typeof navigator!=="undefined"&&navigator.ml){
        try{ const r=await tensorWebNN(n); if(r){ say("solved with WebNN in "+r.ms.toFixed(0)+" ms"); return r; } }
        catch(e){ console.warn("WebNN path failed, trying wasm:",e); }
      }
      try{ const r=await solveWithWasm(); if(r) return r; }
      catch(e){ console.warn("tensor wasm kernel failed, using JavaScript:",e); }
    }
    return tensorInJs(n);
  }

  // ------------------------------------------------------------- tensor-v
  // The sampled-proof variant. The client computes the same stream as `tensor`
  // but reads the second matrix as its transpose, so C[i][j] is the dot product
  // of two contiguous rows. It commits to C in 32-int32 blocks; the server then
  // picks 96 blocks and one element inside each from a secret, and the client
  // opens exactly those. The wasm module builds the tree and the witness; the
  // JavaScript tree below is the no-WebAssembly fallback.
  const TV_LEAF=new TextEncoder().encode("ANUBIS-TENSOR-VL");
  const TV_NODE=new TextEncoder().encode("ANUBIS-TENSOR-VN");
  const TV_CHAL=new TextEncoder().encode("ANUBIS-TENSOR-VC");
  function tvCat(parts){
    let n=0; for(const p of parts) n+=p.length;
    const out=new Uint8Array(n); let at=0;
    for(const p of parts){ out.set(p,at); at+=p.length; }
    return out;
  }
  function tvChal(rd){ return sha256bytes(tvCat([TV_CHAL,hex2bytes(rd)])); }
  function tvLeaf(chal,b,bytes){
    const idx=new Uint8Array(4);
    new DataView(idx.buffer).setUint32(0,b,true);
    return sha256bytes(tvCat([TV_LEAF,chal,idx,bytes]));
  }
  function tvNode(left,right){ return sha256bytes(tvCat([TV_NODE,left,right])); }
  function tvTree(c,n){
    const leaves=n*n/32, chal=tvChal(ch.randomData), levels=[];
    let cur=[];
    for(let b=0;b<leaves;b++){
      const bytes=new Uint8Array(128), v=new DataView(bytes.buffer);
      for(let j=0;j<32;j++) v.setInt32(4*j,c[b*32+j],true);
      cur.push(tvLeaf(chal,b,bytes));
    }
    levels.push(cur);
    while(cur.length>1){
      const next=[];
      for(let i=0;i<cur.length;i+=2) next.push(tvNode(cur[i],cur[i+1]||cur[i]));
      levels.push(next); cur=next;
    }
    return {levels:levels,root:cur[0],leaves:leaves};
  }
  function tvWitnessJS(tree,c,n,blocks,positions){
    const levels=tree.levels, depth=levels.length-1;
    const total=16+blocks.length*12+blocks.length*depth*32+blocks.length*128;
    const out=new Uint8Array(total), dv=new DataView(out.buffer);
    dv.setUint32(0,0x31565654,true); dv.setUint32(4,n,true);
    dv.setUint32(8,blocks.length,true); dv.setUint32(12,tree.leaves,true);
    let at=16;
    for(let i=0;i<blocks.length;i++){
      dv.setUint32(at,blocks[i],true); dv.setUint32(at+4,positions[i],true);
      dv.setUint32(at+8,depth,true); at+=12;
    }
    for(let i=0;i<blocks.length;i++){
      let idx=blocks[i];
      for(let l=0;l<depth;l++){
        let sib=idx^1; if(sib>=levels[l].length) sib=idx;
        out.set(levels[l][sib],at); at+=32; idx>>>=1;
      }
    }
    for(let i=0;i<blocks.length;i++){
      const bd=new DataView(out.buffer,at,128);
      for(let j=0;j<32;j++) bd.setInt32(4*j,c[blocks[i]*32+j],true);
      at+=128;
    }
    return tohex(out);
  }
  // C[i][j] = sum_k A[i][k] * BT[j][k]: both rows are contiguous, unlike the
  // i-k-j loop the `tensor` tier uses on B[k][j].
  function tensorVRows(a,b,c,n,from,to){
    for(let i=from;i<to;i++){
      const row=i*n;
      for(let j=0;j<n;j++){
        const brow=j*n; let sum=0;
        for(let k=0;k<n;k++) sum+=a[row+k]*b[brow+k];
        c[row+j]=sum;
      }
    }
  }
  // Load the tensor-v wasm kernel and put the challenge where it expects it.
  // The same instance computes the GEMM and serialises the witness, but it
  // also exposes tv_solve_from_c(), so a matrix computed by WebNN can reuse
  // its tree instead of paying for a second GEMM.
  async function tvWasmLoad(){
    const bytes=await (await fetch("/.within.website/x/cmd/anubis/api/static/anubis/tensor_pow.wasm?v=tv1")).arrayBuffer();
    const {instance}=await WebAssembly.instantiate(bytes,{});
    const ex=instance.exports;
    const raw=hex2bytes(ch.randomData);
    new Uint8Array(ex.memory.buffer).set(raw,ex.data_ptr());
    ex.set_data_length(raw.length);
    return ex;
  }
  function tvWasmWitness(ex){
    return (blocks,positions)=>{
      const inp=new Uint8Array(ex.memory.buffer,ex.tv_in_ptr(),blocks.length*8);
      const dv=new DataView(inp.buffer,inp.byteOffset,inp.byteLength);
      for(let i=0;i<blocks.length;i++){
        dv.setUint32(i*8,blocks[i]>>>0,true);
        dv.setUint32(i*8+4,positions[i]>>>0,true);
      }
      const len=ex.tv_make_witness(diff,blocks.length)>>>0;
      if(!len) throw new Error("tv_make_witness failed");
      return tohex(new Uint8Array(ex.memory.buffer,ex.tv_wit_ptr(),len));
    };
  }
  // WebNN: a single gemm, C = A * BT. The stream already stores the second
  // matrix transposed, so gemm(A, B, {bTranspose:true}) is exactly what we
  // need; backends without bTranspose get an explicit transpose. The spec's
  // gemm() is float32/float16 only, so the int8 matrices are widened; every
  // partial sum is an integer below 2^24, which float32 represents exactly.
  // Support varies by browser, and the result is not trusted: two rows are
  // recomputed in JavaScript and compared before the matrix is handed to the
  // tree.
  async function tensorVWebNN(n){
    const ml=navigator.ml;
    if(!ml||typeof ml.createContext!=="function") return null;
    say("asking WebNN for a tensor-v GEMM");
    const ctx=await ml.createContext({deviceType:"gpu"});
    const {a,b}=tensorExpand(ch.randomData,n);
    const af=Float32Array.from(a);
    let data=Float32Array.from(b), graph;
    const build=(operand,opts)=>{
      const builder=new MLGraphBuilder(ctx);
      const A=builder.input("A",{dataType:"float32",shape:[n,n]});
      const B=builder.input("B",{dataType:"float32",shape:[n,n]});
      const C=builder.gemm(A,B,opts);
      return builder.build({C});
    };
    try{
      graph=await build(data,{bTranspose:true});
    }catch(e){
      console.warn("WebNN bTranspose unavailable, transposing B:",e);
      const bt=new Float32Array(n*n);
      for(let j=0;j<n;j++) for(let k=0;k<n;k++) bt[k*n+j]=data[j*n+k];
      data=bt;
      graph=await build(data);
    }
    const tA=ctx.createTensor({dataType:"float32",shape:[n,n],writable:true,readable:false});
    const tB=ctx.createTensor({dataType:"float32",shape:[n,n],writable:true,readable:false});
    const tC=ctx.createTensor({dataType:"float32",shape:[n,n],writable:false,readable:true});
    const t0=performance.now();
    ctx.writeTensor(tA,af); ctx.writeTensor(tB,data);
    await ctx.dispatch(graph,{A:tA,B:tB},{C:tC});
    const out=await ctx.readTensor(tC);
    const raw=new Float32Array(out.buffer?out.buffer.slice(out.byteOffset,out.byteOffset+out.byteLength):out);
    const c=new Int32Array(raw.length);
    for(let i=0;i<raw.length;i++) c[i]=Math.round(raw[i]);
    // Two rows of independent JavaScript GEMM: cheap (0.4% of the work) and
    // the difference between "WebNN worked" and "WebNN returned rubbish".
    for(const row of [0,n>>1]){
      const want=new Int32Array(n);
      tensorVRows(a,b,want,n,row,row+1);
      for(let j=0;j<n;j++){
        if(c[row*n+j]!==want[j]) throw new Error("WebNN row "+row+" column "+j+
          ": "+c[row*n+j]+" != "+want[j]);
      }
    }
    return {c:c,ms:performance.now()-t0};
  }
  async function solveTensorV(){
    const n=tenN();
    let root=null, makeWit=null, ms=0;
    let ex=null, cnn=null, nnMs=0;
    // WebNN first: the point of the tier is the GEMM on a GPU or an NPU.
    if(!forcedJs && typeof navigator!=="undefined" && navigator.ml){
      try{
        const r=await tensorVWebNN(n);
        if(r){ cnn=r.c; nnMs=r.ms; }
      }catch(e){ console.warn("tensor-v WebNN path failed, trying wasm:",e); }
    }
    if(!forcedJs && typeof WebAssembly==="object"){
      try{ ex=await tvWasmLoad(); }
      catch(e){ console.warn("tensor-v wasm kernel unavailable:",e); }
    }
    if(cnn && ex){
      try{
        say("building the tensor-v tree from the WebNN matrix (wasm)");
        new Int32Array(ex.memory.buffer,ex.c_ptr(),n*n).set(cnn);
        const t0=performance.now();
        if((ex.tv_solve_from_c(n)>>>0)!==0) throw new Error("tv_solve_from_c rejected the matrix");
        ms=nnMs+performance.now()-t0;
        root=tohex(new Uint8Array(ex.memory.buffer,ex.tv_root_ptr(),32));
        makeWit=tvWasmWitness(ex);
        say("tensor-v: WebNN GEMM + wasm tree in "+ms.toFixed(0)+" ms");
      }catch(e){ console.warn("tensor-v wasm tree failed, using the JS tree:",e); root=null; }
    }
    if(!root && cnn){
      say("building the tensor-v tree in JavaScript");
      const t0=performance.now();
      const tree=tvTree(cnn,n);
      ms=nnMs+performance.now()-t0;
      root=tohex(tree.root);
      makeWit=(blocks,positions)=>tvWitnessJS(tree,cnn,n,blocks,positions);
      say("tensor-v: WebNN GEMM + JavaScript tree in "+ms.toFixed(0)+" ms");
    }
    if(!root && ex){
      try{
        say("computing the tensor-v commitment (wasm)");
        const t0=performance.now();
        if((ex.tv_solve(diff)>>>0)!==0) throw new Error("tv_solve rejected the challenge");
        ms=performance.now()-t0;
        root=tohex(new Uint8Array(ex.memory.buffer,ex.tv_root_ptr(),32));
        makeWit=tvWasmWitness(ex);
        say("tensor-v commitment in "+ms.toFixed(0)+" ms (wasm)");
      }catch(e){ console.warn("tensor-v wasm path failed, using JavaScript:",e); root=null; }
    }
    if(!root){
      const {a,b}=tensorExpand(ch.randomData,n);
      const c=new Int32Array(n*n);
      const t0=performance.now(), rows=Math.max(1,n>>4), macs=n*n*n;
      workShow("tensor-v: "+n+"x"+n+"x"+n+" int8 GEMM ("+
               (macs/1e9).toFixed(1)+" GMAC, "+rows+" row blocks)");
      for(let s=0;s<rows;s++){
        tensorVRows(a,b,c,n,Math.floor(n*s/rows),Math.floor(n*(s+1)/rows));
        workUpdate((s+1)/rows,macs*(s+1)/rows,performance.now()-t0,macs,"MAC");
        await new Promise(r=>setTimeout(r,0));
      }
      say("building the commitment tree");
      const tree=tvTree(c,n);
      workDone();
      ms=performance.now()-t0;
      root=tohex(tree.root);
      makeWit=(blocks,positions)=>tvWitnessJS(tree,c,n,blocks,positions);
    }
    const su=new URL("/.within.website/x/cmd/anubis/api/pass-challenge",location.origin);
    su.searchParams.set("id",ch.id);
    su.searchParams.set("response",root);
    su.searchParams.set("nonce","0");
    const sr=await fetch(su.toString(),{credentials:"include"});
    if(!sr.ok) throw new Error("commit response "+sr.status+": "+await sr.text());
    const sample=await sr.json();
    if(!sample||!sample.audit||!sample.audit.blocks) throw new Error("no audit in the response");
    const audit=makeWit(sample.audit.blocks,sample.audit.positions);
    const body=JSON.stringify({id:ch.id,root:root,audit:audit,
                               redir:location.pathname+location.search});
    const ar=await fetch("/.within.website/x/cmd/anubis/api/audit-tensor",{
      method:"POST",headers:{"Content-Type":"application/json"},
      credentials:"include",body:body});
    const j=await ar.json().catch(()=>({}));
    if(!ar.ok||!j.ok) throw new Error("audit rejected: "+(j.error||ar.status));
    say("tensor-v passed in "+ms.toFixed(0)+" ms");
    location.replace(j.redir||location.pathname);
  }

  const shaAlgo=algo==="sha256"||algo==="wasm-sha256";
  const mrAlgo=algo==="meatrider";
  // A URL ending in #pure-js asks for the JavaScript solvers explicitly; they
  // are also the automatic fallback when WebAssembly is not available at all.
  const forcedJs=location.hash.toLowerCase().replace(/^#\/?/,"")==="pure-js";
  const noWasm=forcedJs || typeof WebAssembly!=="object";
  if(algo==="tensor-v"){
    solveTensorV().catch(e=>say("tensor-v solver failed: "+e));
    return;
  }
  if(algo==="tensor"){
    solveTensor().then(r=>{ if(r) pass(r.hash,0,r.ms); })
                 .catch(e=>say("tensor solver failed: "+e));
    return;
  }
  if(shaAlgo && noWasm){ solveSha256InJs(); return; }
  if(algo==="hashx" && noWasm){ solveHashxInJs(); return; }
  if(mrAlgo && noWasm){ solveMeatriderInJs(); return; }
  if(algo==="argon2id" && noWasm){ solveArgon2idInJs(); return; }
  if(algo==="sha256"||algo==="wasm-sha256"||algo==="argon2id"||algo==="hashx"||mrAlgo){
    solveWithWasm().then(r=>{
      if(r){ say("solved with nonce "+r.nonce+" in "+r.ms.toFixed(0)+" ms"); pass(r.hash,r.nonce,r.ms); }
      else if(shaAlgo){ solveSha256InJs(); }
      else if(algo==="hashx"){ solveHashxInJs(); }
      else if(mrAlgo){ solveMeatriderInJs(); }
      else if(algo==="argon2id"){ solveArgon2idInJs(); }
      else { say(algo+" could not load its kernel, use the anubis_fetch CLI or the Firefox extension"); }
    }).catch(e=>{
      if(shaAlgo){ solveSha256InJs(); }
      else if(algo==="hashx"){ solveHashxInJs(); }
      else if(mrAlgo){ if(e.meatriderRefused) say(e.message); else solveMeatriderInJs(); }
      else if(algo==="argon2id"){ solveArgon2idInJs(); }
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

  // Pure-JavaScript solver for the wasm sha256 challenge, for browsers where
  // WebAssembly is disabled, missing, or refused. It is the same proof the
  // wasm kernel computes: the raw challenge bytes followed by a 32-bit nonce,
  // little-endian when the last challenge byte has its high bit set and
  // big-endian otherwise, accepted on `difficulty` leading zero *bits* of the
  // raw digest. The message is fixed apart from the nonce, so the padded block
  // is built once and its four nonce bytes are rewritten per attempt; the loop
  // yields every 8192 tries so a high difficulty cannot freeze the tab.
  async function solveSha256InJs(){
    const t0=performance.now();
    const data=hex2bytes(ch.randomData);
    const little=data.length!==0 && (data[data.length-1]&0x80)!==0;
    const total=data.length+4;
    const padded=new Uint8Array(((total+9+63)/64|0)*64);
    padded.set(data,0);
    padded[total]=0x80;
    sha256length(padded,total*8);
    const p=data.length;
    say("solving sha256 in pure JavaScript (no WebAssembly)");
    for(let nonce=0;;nonce++){
      const v=nonce>>>0;
      if(little){
        padded[p]=v&255; padded[p+1]=(v>>>8)&255;
        padded[p+2]=(v>>>16)&255; padded[p+3]=(v>>>24)&255;
      }else{
        padded[p]=(v>>>24)&255; padded[p+1]=(v>>>16)&255;
        padded[p+2]=(v>>>8)&255; padded[p+3]=v&255;
      }
      const d=sha256padded(padded);
      if(lz(d)>=diff){
        say("solved with nonce "+nonce+" in JavaScript");
        pass(tohex(d),nonce,performance.now()-t0);
        return;
      }
      if((nonce&8191)===8191) await new Promise(r=>setTimeout(r,0));
    }
  }

  // Pure-JavaScript HashX, for browsers where WebAssembly is disabled, missing,
  // or refused. The program generator is the same one the wasm path uses
  // (HASHX_JIT.deriveProgram, above); this interprets its 512 instructions
  // instead of emitting a module. The semantics are hashx_hash() in
  // src/hashx/hashx.c: SipHash-2-4 counter-mode register fill, the program with
  // its single guarded backward branch, the finalising SipRounds, then
  // r[i] ^ r[4+i] as little-endian 64-bit words (32 bytes).
  // Function declarations, not const arrows: the dispatch above can start
  // solving before this block has executed, and only hoisted functions are
  // usable at that point. Keep the 64-bit mask inline for the same reason.
  function hxU64(x){ return x & ((1n<<64n)-1n); }
  function hxRotl(x,n){ n&=63; if(n===0) return hxU64(x);
    return hxU64((x<<BigInt(n))|(x>>BigInt(64-n))); }
  function hxRotr(x,n){ n&=63; if(n===0) return hxU64(x);
    return hxU64((x>>BigInt(n))|(x<<BigInt(64-n))); }
  function hxSipRound(v,a,b,c,d){
    v[a]=hxU64(v[a]+v[b]); v[c]=hxU64(v[c]+v[d]);
    v[b]=hxRotl(v[b],13); v[d]=hxRotl(v[d],16);
    v[b]^=v[a]; v[d]^=v[c];
    v[a]=hxRotl(v[a],32); v[c]=hxU64(v[c]+v[b]); v[a]=hxU64(v[a]+v[d]);
    v[b]=hxRotl(v[b],17); v[d]=hxRotl(v[d],21);
    v[b]^=v[c]; v[d]^=v[a]; v[c]=hxRotl(v[c],32);
  }
  function hashxInit(raw){
    const derived=HASHX_JIT.deriveProgram(raw);
    return {key:derived.registerKey,code:derived.program};
  }
  function hashxHash(init,nonce,out){
    const k=init.key, n=BigInt(nonce>>>0), v=[k[0],k[1],k[2],k[3]];
    v[1]^=238n; v[3]^=n;
    hxSipRound(v,0,1,2,3); hxSipRound(v,0,1,2,3);
    v[0]^=n; v[2]^=238n;
    for(let i=0;i<4;i++) hxSipRound(v,0,1,2,3);
    const r=[v[0],v[1],v[2],v[3],0n,0n,0n,0n];
    v[1]^=221n;
    for(let i=0;i<4;i++) hxSipRound(v,0,1,2,3);
    r[4]=v[0]; r[5]=v[1]; r[6]=v[2]; r[7]=v[3];

    const code=init.code;
    let target=0, be=true, result=0n;
    for(let i=0;i<code.length;i++){
      const ins=code[i], d=ins.dst&7, s=ins.src&7;
      switch(ins.op){
        case 0: r[d]=hxU64((hxU64(r[d])*hxU64(r[s]))>>64n); result=r[d]; break;
        case 1: { const a=BigInt.asIntN(64,r[d]), b=BigInt.asIntN(64,r[s]);
                  r[d]=hxU64((a*b)>>64n); result=r[d]; break; }
        case 2: r[d]=hxU64(r[d]*r[s]); break;
        case 3: r[d]=hxU64(r[d]-r[s]); break;
        case 4: r[d]=hxU64(r[d]^r[s]); break;
        case 5: r[d]=hxU64(r[d]+hxU64(r[s]<<BigInt(ins.imm&63))); break;
        case 6: r[d]=hxRotr(r[d],ins.imm&63); break;
        case 7: r[d]=hxU64(r[d]+BigInt(ins.imm|0)); break;
        case 8: r[d]=hxU64(r[d]^BigInt(ins.imm|0)); break;
        case 9: target=i; break;
        case 10:
          if(be && (result & BigInt(ins.imm>>>0))===0n){ i=target; be=false; }
          break;
        default: throw new Error("unknown HashX opcode "+ins.op);
      }
    }

    r[0]=hxU64(r[0]+k[0]); r[1]=hxU64(r[1]+k[1]);
    r[6]=hxU64(r[6]+k[2]); r[7]=hxU64(r[7]+k[3]);
    hxSipRound(r,0,1,2,3); hxSipRound(r,4,5,6,7);
    for(let i=0;i<4;i++){
      let w=hxU64(r[i]^r[4+i]);
      for(let b=0;b<8;b++){ out[i*8+b]=Number(w&255n); w>>=8n; }
    }
  }
  async function solveArgon2idInJs(){
    const raw=hex2bytes(ch.randomData);
    const t0=performance.now();
    say("solving argon2id in pure JavaScript (about a second per attempt)");
    for(let nonce=0;;nonce++){
      const tag=argon2idTag(raw,nonce);
      if(lz(tag)>=diff){
        say("solved with nonce "+nonce+" in JavaScript");
        pass(tohex(tag),nonce,performance.now()-t0);
        return;
      }
      await new Promise(r=>setTimeout(r,0));
    }
  }
  async function solveHashxInJs(){
    const raw=hex2bytes(ch.randomData);
    say("deriving the HashX program in JavaScript");
    const init=hashxInit(raw);
    const out=new Uint8Array(32);
    const t0=performance.now();
    say("solving hashx in pure JavaScript (no WebAssembly)");
    for(let nonce=0;;nonce++){
      hashxHash(init,nonce,out);
      if(lz(out)>=diff){
        say("solved with nonce "+nonce+" in JavaScript");
        pass(tohex(out),nonce,performance.now()-t0);
        return;
      }
      if((nonce&255)===255) await new Promise(r=>setTimeout(r,0));
    }
  }

  // Pure-JavaScript meatrider, for browsers where WebAssembly is disabled,
  // missing, or refused. This is the specification from
  // src/meatrider/meatrider.c in JS: version 1, prev block = randomData,
  // merkle = SHA256("meatrider" || randomData), the genesis timestamp, nBits for
  // 2^(256-difficulty), then the nonce; the digest is SHA-256d in Bitcoin's
  // display order. The 80-byte header is padded once and only four bytes move.
  async function solveMeatriderInJs(){
    const rd=hex2bytes(ch.randomData);
    if(rd.length!==32){ say("meatrider needs a 32-byte randomData"); return; }
    if(diff<1||diff>255){ say("meatrider difficulty must be 1..255"); return; }
    say("meatrider: "+meatriderBlurb(diff));
    const lab=new Uint8Array(41);
    lab.set([109,101,97,116,114,105,100,101,114],0);   // "meatrider"
    lab.set(rd,9);
    const merkle=sha256bytes(lab);
    const pad1=new Uint8Array(128);
    pad1[0]=1;                       // version 1, little-endian
    pad1.set(rd,4);
    pad1.set(merkle.subarray(0,28),36);
    pad1.set(merkle.subarray(28,32),64);
    pad1[68]=0x29; pad1[69]=0xab; pad1[70]=0x5f; pad1[71]=0x49;  // 1231006505
    const bits=mrBits(diff);
    for(let i=0;i<4;i++) pad1[72+i]=(bits>>>(8*i))&255;
    pad1[80]=0x80;
    sha256length(pad1,640);
    const pad2=new Uint8Array(64);
    pad2[32]=0x80;
    sha256length(pad2,256);
    const rev=new Uint8Array(32);
    const totalCents=mrPriceUsd(diff)*100;
    const expected=Math.pow(2,diff);
    const box=mrMiningBox();
    const t0=performance.now();
    mrMiningSay(diff,totalCents,0);
    for(let nonce=0;;nonce++){
      const v=nonce>>>0;
      pad1[76]=v&255; pad1[77]=(v>>>8)&255; pad1[78]=(v>>>16)&255; pad1[79]=(v>>>24)&255;
      pad2.set(sha256padded(pad1));
      const h2=sha256padded(pad2);
      if(lzr(h2)>=diff){
        for(let i=0;i<32;i++) rev[i]=h2[31-i];
        if(box) box.remove();
        say("solved with nonce "+nonce+" in JavaScript");
        pass(tohex(rev),nonce,performance.now()-t0);
        return;
      }
      if((nonce&8191)===8191){
        mrMiningSay(diff,totalCents,Math.min(0.99,nonce/expected));
        await new Promise(r=>setTimeout(r,0));
      }
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
                           const char *algorithm, int difficulty, const locale *loc,
                           const char *og) {
    char pay_json[512] = "null";
    if (OPT(cfg.meatrider_pay) && !strcasecmp(algorithm, "meatrider")) {
        double usd = anubis_meatrider_price_usd(difficulty, 0.0);
        double btc = cfg.btc_usd > 0.0 ? usd / cfg.btc_usd : 0.0;
        long long sats = (long long)(btc * 1e8 + 0.5);
        /* below one satoshi there is nothing to pay: the rungs that matter are
         * the top of the ladder, where the amount is thousands of sats */
        if (sats >= 1) {
            snprintf(pay_json, sizeof pay_json,
                     "{\"address\":\"%s\",\"usd\":%.6g,\"btc\":\"%.8f\",\"sats\":%lld}",
                     cfg.meatrider_pay, usd, btc, sats);
        }
    }
    char payload[2560];
    snprintf(payload, sizeof payload,
             "{\"rules\":{\"algorithm\":\"%s\",\"difficulty\":%d,\"pay\":%s},"
             "\"challenge\":{\"issuedAt\":\"%lld\",\"metadata\":%s,\"id\":\"%s\","
             "\"method\":\"%s\",\"randomData\":\"%s\",\"policyRuleHash\":\"%s\","
             "\"difficulty\":%d,\"spent\":false,\"extensions\":null}}",
             algorithm, difficulty, pay_json, (long long)time(NULL), metadata_json, id,
             algorithm, random_data, policy_digest(), difficulty);

    char status_line[512];
    snprintf(status_line, sizeof status_line, loc->solving, algorithm, difficulty);

    size_t cap = strlen(payload) + strlen(CHALLENGE_JS) + strlen(status_line) +
                 (cfg.impressum_footer ? strlen(cfg.impressum_footer) : 0) + 8192;
    char *body = malloc(cap);
    if (!body) { respond(c, 500, "Internal Server Error", NULL, NULL, "oom", 3); return; }

    snprintf(body, cap,
             "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
             "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
             "<title>%s</title>%s<style>"
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
             "<h1>%s</h1>"
             "<p id=\"status\">%s</p>"
             "<div id=\"work\" hidden><h2>%s</h2>"
             "<p id=\"worksub\"></p>"
             "<div class=\"bar\" id=\"workbar\"><div id=\"fill\"></div></div>"
             "<p><span id=\"pct\">0.0%%</span> &middot; <span id=\"rate\">&mdash;</span>"
             " &middot; <span id=\"eta\"></span></p></div>"
             "<p><a id=\"manual\" href=\"#\">%s</a></p>"
             "<p><small>%s <code>%spass-challenge?id=%s&amp;response=&lt;digest&gt;&amp;nonce=&lt;n&gt;</code>.</small></p>"
             "<script id=\"anubis_challenge\" type=\"application/json\">%s</script>"
             "<script>%s</script>"
             "<script>(function(){var u=new URL(\"%spass-challenge\",location.origin);"
             "u.searchParams.set(\"id\",\"%s\");u.searchParams.set(\"response\",\"\");u.searchParams.set(\"nonce\",\"0\");"
             "u.searchParams.set(\"redir\",location.pathname);document.getElementById(\"manual\").href=u.toString();})();</script>"
             "%s</body></html>",
             loc->title, og && *og ? og : "", loc->title, status_line, loc->slowing,
             loc->manual, loc->explain,
             API_PREFIX, id, payload, CHALLENGE_JS, API_PREFIX, id,
             cfg.impressum_footer && *cfg.impressum_footer ? cfg.impressum_footer : "");

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
             "Set-Cookie: %s=%s; Path=/; SameSite=Lax\r\n",
             cfg.verify_name, test_cookie ? test_cookie : id);
    respond(c, cfg.challenge_status, reason_for(cfg.challenge_status),
            "text/html; charset=utf-8", extra, body, strlen(body));
    free(body);
}

/* ---------------------------------------------------------- policy digest
 *
 * One SHA-256 over the loaded policy, as text, in load order: the rules, the
 * default action, everything that changes a decision. It goes into the token as
 * policyRule and is compared on every request, so editing a policy invalidates
 * the cookies minted under the old one.
 */
static char policy_text[16384];
static size_t policy_text_len;
static char policy_digest_value[17];

static void policy_text_add(const char *fmt, ...) {
    if (policy_text_len + 2 >= sizeof policy_text) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(policy_text + policy_text_len, sizeof policy_text - policy_text_len,
                      fmt, ap);
    va_end(ap);
    if (n > 0) {
        policy_text_len += (size_t)n;
        if (policy_text_len >= sizeof policy_text) policy_text_len = sizeof policy_text - 1;
    }
}

static void policy_digest_finish(void) {
    uint8_t d[32];
    char hex[65];
    if (sha256_raw((const uint8_t *)policy_text, policy_text_len, d) != 0) {
        snprintf(policy_digest_value, sizeof policy_digest_value, "0000000000000000");
        return;
    }
    hex_encode(d, 8, hex);
    snprintf(policy_digest_value, sizeof policy_digest_value, "%s", hex);
}

static const char *policy_digest(void) { return policy_digest_value; }

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
                                              "argon2id", "hashx", "meatrider", "tensor",
                                              "tensor-v", "metarefresh", "preact", NULL};

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
/* Flow collections: [a, b] and {k: v, k2: v2}. Anubis's own policies are
 * block style, but configs in the wild use both, and "the file loads" has to
 * mean the file. */
static void y_take_flow(y_node *member, const char *val) {
    char close_ch = val[0] == '[' ? ']' : '}';
    const char *close = strrchr(val, close_ch);
    if (!close || close <= val) return;
    y_node **tail = &member->child;
    const char *p = val + 1;
    int pairs = val[0] == '{';
    while (p < close) {
        while (p < close && (*p == ' ' || *p == ',')) p++;
        if (p >= close) break;
        char item[512];
        size_t o = 0;
        if (*p == '"' || *p == '\'') {
            char q = *p++;
            while (p < close && *p != q && o + 1 < sizeof item) item[o++] = *p++;
            if (p < close) p++;
        } else {
            while (p < close && *p != ',' && !(pairs && *p == ':') && o + 1 < sizeof item)
                item[o++] = *p++;
        }
        while (o && item[o - 1] == ' ') o--;
        item[o] = 0;
        y_node *c = y_new(Y_SCALAR);
        if (!c) break;
        if (pairs && *p == ':') {
            p++;
            while (p < close && *p == ' ') p++;
            char v[512];
            size_t vo = 0;
            if (p < close && (*p == '"' || *p == '\'')) {
                char q = *p++;
                while (p < close && *p != q && vo + 1 < sizeof v) v[vo++] = *p++;
                if (p < close) p++;
            } else {
                while (p < close && *p != ',' && vo + 1 < sizeof v) v[vo++] = *p++;
            }
            while (vo && v[vo - 1] == ' ') vo--;
            v[vo] = 0;
            c->key = y_dup(item);
            c->scalar = y_dup(v);
        } else {
            if (!item[0]) break;
            c->scalar = y_dup(item);
        }
        *tail = c;
        tail = &c->next;
    }
    member->type = pairs ? Y_MAP : Y_SEQ;
}

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
    } else if (*val == '[' || *val == '{') {
        y_take_flow(member, val);
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
    } else if (!strncmp(s, "verifyFCrDNS(", 13)) {
        const char *q = s + 13;
        while (*q == ' ') q++;
        if (strncmp(q, "remoteAddress", 13)) return (cx->ok = 0), 0;
        q += 13;
        while (*q == ' ') q++;
        if (*q != ',') return (cx->ok = 0), 0;
        q++;
        char pat[256];
        if (!ex_quoted(&q, pat, sizeof pat)) return (cx->ok = 0), 0;
        while (*q == ' ') q++;
        if (*q != ')') return (cx->ok = 0), 0;
        if (!cx->rq) return 0;          /* understood; nothing to check yet */
        char name[NI_MAXHOST];
        if (!fcrdns_name(cx->ip, name, sizeof name)) return 0;
        return ex_regex(pat, name);
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
    int needle_var = 0;         /* 1 host, 2 userAgent, 3 path */
    if (op[0] == '=' || op[0] == '!') {
        if (!ex_quoted(&q, needle, sizeof needle)) {
            /* the right-hand side may be a variable, e.g. != host */
            ex_trim(&q);
            size_t idlen = strcspn(q, " )");
            if (idlen == 4 && !strncmp(q, "host", 4)) needle_var = 1;
            else if (idlen == 9 && !strncmp(q, "userAgent", 9)) needle_var = 2;
            else if (idlen == 4 && !strncmp(q, "path", 4)) needle_var = 3;
            else return (cx->ok = 0), 0;
            q += idlen;
        }
    } else {
        if (*q != '(') return (cx->ok = 0), 0;
        q++;
        if (!ex_quoted(&q, needle, sizeof needle)) return (cx->ok = 0), 0;
        ex_trim(&q);
        if (*q != ')') return (cx->ok = 0), 0;
    }

    if (needle_var && cx->rq) {
        const char *v = needle_var == 1 ? header_value(cx->rq, "Host")
                       : needle_var == 2 ? header_value(cx->rq, "User-Agent")
                                         : cx->rq->ppath;
        snprintf(needle, sizeof needle, "%s", v ? v : "");
    } else if (needle_var) {
        needle[0] = 0;
    }

    const char *have = "";
    if (!strncmp(s, "userAgent", 9)) {
        have = cx->rq ? header_value(cx->rq, "User-Agent") : "";
    } else if (!strncmp(s, "host", 4)) {
        have = cx->rq ? header_value(cx->rq, "Host") : "";
    } else if (!strncmp(s, "path", 4)) {
        have = cx->rq ? cx->rq->ppath : "";
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
    char countries[8][4];
    int ncountries;
    uint32_t asns[16];
    int nasns;
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
    if (!strcasecmp(s, "DEBUG_BENCHMARK")) return 4;   /* lib/config/config.go:43 */
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

    if (geo) {
        const y_node *list = y_get(geo, "countries");
        if (!mm_country.ok) {
            logmsg("policy: rule '%s' matches on countries but no --geoip-country is loaded; "
                   "the rule is ignored", name);
            goto fail;
        }
        if (list && list->type == Y_SEQ)
            for (const y_node *it = list->child; it && r.ncountries < 8; it = it->next) {
                const char *cc = y_str(it, NULL);
                if (!cc || strlen(cc) != 2) continue;
                snprintf(r.countries[r.ncountries], sizeof r.countries[0], "%s", cc);
                for (char *q = r.countries[r.ncountries]; *q; q++)
                    if (*q >= 'a' && *q <= 'z') *q = (char)(*q - 32);
                r.ncountries++;
            }
    }
    if (asns) {
        const y_node *list = y_get(asns, "match");
        if (!mm_asn.ok) {
            logmsg("policy: rule '%s' matches on ASN but no --geoip-asn is loaded; "
                   "the rule is ignored", name);
            goto fail;
        }
        if (list && list->type == Y_SEQ)
            for (const y_node *it = list->child; it && r.nasns < 16; it = it->next) {
                const char *num = y_str(it, NULL);
                if (!num) continue;
                r.asns[r.nasns++] = (uint32_t)strtoul(num, NULL, 10);
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
    policy_text_add("%s|%d|%d|%s|%d|%zu|%s|%s|", r.name, r.action, r.difficulty,
                    r.algorithm, r.weight_adjust, r.cidr_len, r.expr, r.from);
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
    if (dnsbl && y_bool(dnsbl, 0)) {
        cfg.dnsbl = 1;
        logmsg("policy: dnsbl is enabled, so every client address is checked against "
               "DroneBL once a day");
    }

    /* what is left of the blocks this gate still has no equivalent for */
    if (y_get(root, "botstopper"))
        logmsg("policy: the 'botstopper' block is an enterprise feature; it is ignored");
}

/* ---- matching ---------------------------------------------------------- */

static int yml_rule_matches(const yrule *r, const request *rq, const char *ip,
                            double weight) {
    if (!r->has_ua && !r->has_path && r->nhdr == 0 && !r->has_expr && r->cidr_len == 0 &&
        r->ncountries == 0 && r->nasns == 0)
        return 0;               /* a rule with no condition would match everything */
    if (r->has_ua) {
        const char *ua = header_value(rq, "User-Agent");
        if (!ua || regexec(&r->ua_re, ua, 0, NULL, 0) != 0) return 0;
    }
    if (r->has_path) {
        if (regexec(&r->path_re, rq->ppath, 0, NULL, 0) != 0) return 0;
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
    if (r->ncountries) {
        char cc[8];
        if (!geoip_country(ip, cc, sizeof cc)) return 0;
        int hit = 0;
        for (int i = 0; i < r->ncountries; i++)
            if (!strcasecmp(cc, r->countries[i])) hit = 1;
        if (!hit) return 0;
    }
    if (r->nasns) {
        uint32_t a = 0;
        if (!geoip_asn(ip, &a)) return 0;
        int hit = 0;
        for (int i = 0; i < r->nasns; i++)
            if (r->asns[i] == a) hit = 1;
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
        int metric_action = r->action == 4 ? 2 : r->action;   /* DEBUG_BENCHMARK */
        __atomic_fetch_add(&m_policy[i < MAX_RULES ? i : MAX_RULES][metric_action], 1,
                           __ATOMIC_RELAXED);
        if (r->difficulty > 0) *difficulty = r->difficulty;
        if (r->algorithm[0]) *algorithm = r->algorithm;
        return r->action == 4 ? 2 : r->action;   /* a benchmark always challenges */
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

/* ---------------------------------------------------- the policy's own config
 *
 * The blocks that configure the gate rather than describe a bot: store,
 * metrics, geoip, openGraph, impressum, logging, dns_ttl. An Anubis deployment
 * carries these in the same file as the rules, and a config that only works
 * half-way is not a drop-in.
 *
 * Flags win. The file fills in what the command line left alone, so an operator
 * can always override a policy file without editing it.
 */
static int geoip_open_databases(void) {
    if (cfg.geoip_country_path && *cfg.geoip_country_path && !mm_country.ok &&
        mmdb_open(&mm_country, cfg.geoip_country_path) != 0)
        return -1;
    if (cfg.geoip_asn_path && *cfg.geoip_asn_path && !mm_asn.ok &&
        mmdb_open(&mm_asn, cfg.geoip_asn_path) != 0)
        return -1;
    return 0;
}

/* "24h", "90m", "3600" and "3600s" are the shapes Anubis accepts. */
static long parse_seconds(const char *s, long def) {
    if (!s || !*s) return def;
    char *end = NULL;
    double v = strtod(s, &end);
    if (v <= 0) return def;
    if (end && *end) {
        if (*end == 'h') v *= 3600;
        else if (*end == 'm') v *= 60;
        else if (*end == 's') v *= 1;
        else if (*end == 'd') v *= 86400;
        else return def;
    }
    return (long)v;
}

static void policy_apply_blocks(const y_node *root) {
    const y_node *store = y_get(root, "store");
    if (store) {
        const char *backend = y_str(y_get(store, "backend"), "memory");
        const y_node *params = y_get(store, "parameters");
        const char *path = y_str(y_get(params, "path"), NULL);
        const char *url = y_str(y_get(params, "url"), NULL);
        const char *bucket = y_str(y_get(params, "bucketName"), NULL);
        if (!strcasecmp(backend, "memory")) {
            logmsg("policy: store backend memory");
        } else if (!strcasecmp(backend, "file") && path && *path) {
            if (!cfg.store) {
                char spec[600];
                snprintf(spec, sizeof spec, "file:%s", path);
                cfg.store = y_dup(spec);
            }
            logmsg("policy: store backend file, %s", path);
        } else if (!strcasecmp(backend, "bbolt") && path && *path) {
            if (!cfg.store) {
                char spec[600];
                snprintf(spec, sizeof spec, "bbolt:%s", path);
                cfg.store = y_dup(spec);
            }
            logmsg("policy: store backend bbolt, %s", path);
        } else if (!strcasecmp(backend, "valkey") && url && *url) {
            if (!cfg.store) {
                char spec[1024];
                snprintf(spec, sizeof spec, "valkey:%s", url);
                cfg.store = y_dup(spec);
            }
            logmsg("policy: store backend valkey configured");
        } else if (!strcasecmp(backend, "valkey")) {
            logmsg("policy: store backend valkey needs parameters.url; using memory");
        } else if (!strcasecmp(backend, "s3api") && bucket && *bucket) {
            if (!cfg.store) {
                char spec[1024];
                snprintf(spec, sizeof spec, "s3api:%s", bucket);
                cfg.store = y_dup(spec);
            }
            s3_path_style = y_bool(y_get(params, "pathStyle"), 0);
            logmsg("policy: store backend s3api, bucket %s%s", bucket,
                   s3_path_style ? " (path style)" : "");
        } else if (!strcasecmp(backend, "s3api")) {
            logmsg("policy: store backend s3api needs parameters.bucketName; using memory");
        } else {
            logmsg("policy: store backend %s is unknown here, using memory", backend);
        }
    }

    const y_node *metrics = y_get(root, "metrics");
    if (metrics) {
        int enabled = y_bool(y_get(metrics, "enabled"), 1);
        const char *bind = y_str(y_get(metrics, "bind"), NULL);
        if (!enabled) logmsg("policy: metrics are disabled");
        else if (bind && *bind && !cfg.metrics_bind) {
            cfg.metrics_bind = y_dup(bind);
            logmsg("policy: metrics on %s", bind);
        } else if (!bind) {
            logmsg("policy: metrics enabled with no bind address; use --metrics-bind");
        }
        if (y_get(metrics, "tls") || y_get(metrics, "basic_auth"))
            logmsg("policy: the metrics listener's tls/basic_auth are not implemented here");
        if (y_get(metrics, "pprof"))
            logmsg("policy: metrics.pprof has no equivalent here (it is a Go runtime view)");
    }

    const y_node *geo = y_get(root, "geoip");
    if (geo) {
        const char *c = y_str(y_get(y_get(geo, "country"), "path"), NULL);
        const char *a = y_str(y_get(y_get(geo, "asn"), "path"), NULL);
        if (c && *c && !cfg.geoip_country_path) cfg.geoip_country_path = y_dup(c);
        if (a && *a && !cfg.geoip_asn_path) cfg.geoip_asn_path = y_dup(a);
        geoip_open_databases();     /* rules that match on geography need it now */
    }

    const y_node *og = y_get(root, "openGraph");
    if (og) {
        if (!cfg.og_passthrough) cfg.og_passthrough = y_bool(y_get(og, "enabled"), 0);
        const y_node *ch = y_get(og, "considerHost");
        if (ch) cfg.og_consider_host = y_bool(ch, cfg.og_consider_host);
        const char *exp = y_str(y_get(og, "expiryTime"), NULL);
        if (exp) cfg.og_ttl = parse_seconds(exp, cfg.og_ttl);
        const y_node *ov = y_get(og, "override");
        if (ov && ov->type == Y_MAP && !cfg.og_override) {
            char joined[1024] = "";
            size_t used = 0;
            for (const y_node *c = ov->child; c; c = c->next) {
                if (!c->key) continue;
                const char *v = y_str(c, NULL);
                if (!v) continue;
                used += (size_t)snprintf(joined + used, sizeof joined - used, "%s%s=%s",
                                         used ? ";" : "", c->key, v);
            }
            if (joined[0]) cfg.og_override = y_dup(joined);
        }
        logmsg("policy: openGraph %s, cache %lds%s", cfg.og_passthrough ? "on" : "off",
               cfg.og_ttl, cfg.og_consider_host ? ", keyed on host" : "");
    }

    const y_node *imp = y_get(root, "impressum");
    if (imp && y_bool(y_get(imp, "enabled"), 0)) {
        if (!cfg.impressum_title) cfg.impressum_title = "Impressum";
        const char *footer = y_str(y_get(imp, "footer"), NULL);
        if (footer && *footer && !cfg.impressum_body) cfg.impressum_body = y_dup(footer);
        logmsg("policy: the imprint page is on");
    }

    const y_node *logging = y_get(root, "logging");
    if (logging) {
        const char *lvl = y_str(y_get(logging, "level"), NULL);
        if (lvl && !strcasecmp(lvl, "debug")) cfg.verbose = 1;
        else if (lvl && (!strcasecmp(lvl, "warn") || !strcasecmp(lvl, "error"))) log_quiet = 1;
    }

    const char *ttl = y_str(y_get(root, "dns_ttl"), NULL);
    if (ttl) cfg.dns_ttl = parse_seconds(ttl, cfg.dns_ttl);
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
    policy_apply_blocks(root);
    char dir[1024];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) *slash = 0;
    else snprintf(dir, sizeof dir, ".");

    yml_load_document(root, path, 0, dir);
    y_free(root);
    yml_loaded = 1;
    for (int i = 0; i < yml_threshold_count; i++)
        policy_text_add("threshold|%s|%d|%d|%s|%s|", yml_thresholds[i].name,
                        yml_thresholds[i].action, yml_thresholds[i].difficulty,
                        yml_thresholds[i].algorithm, yml_thresholds[i].expr);
    policy_digest_finish();

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
    else if (r->selector == SEL_PATH) subject = req->ppath;
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
        char action[32] = "", sel[64] = "", how[32] = "", value[256] = "";
        int difficulty = 0;
        int n = sscanf(line, "%31s %63s %31s %255s", action, sel, how, value);
        if (n < 2) continue;
        policy_text_add("%s %s %s %s|", action, sel, how, value);
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
    policy_text_add("default|%d|%d|%s", default_action, default_difficulty, default_algorithm);
    policy_digest_finish();
    logmsg("policy: %d rule(s) from %s, policy %s, default %s", rule_count, path,
           policy_digest(),
           default_action == RULE_ALLOW ? "allow" : default_action == RULE_DENY ? "deny" : "challenge");
}

/* ------------------------------------------------------------ the routes */

/* The part of request handling that runs after bytes have become a `request`.
 *
 * This used to be the second half of handle_connection(). It is separate so the
 * HTTP/2 and HTTP/3 frontends can hand a decoded request straight to it: those
 * protocols do not have an HTTP/1.1 header block to parse, and using a socketpair
 * per stream means this function needs no knowledge of the framing at all.
 * It owns req->headers/req->body and the connection's fd. */
static void handle_parsed(conn *c, request *req_in, const char *peer_ip) {
    request req = *req_in;
    req_in->headers = NULL;
    req_in->body = NULL;

    if (!path_is_sane(req.path)) {
        const char *msg = "betterAnusbis: that path has a . or .. segment\n";
        respond(c, 400, "Bad Request", NULL, NULL, msg, strlen(msg));
        free(req.headers);
        free(req.body);
        close(c->fd);
        return;
    }
    collapse_slashes(req.path, req.ppath, sizeof req.ppath);

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

    /* body, if the client sent one, is already in req.body: the HTTP/1.1
     * reader below filled it, and the HTTP/2 and HTTP/3 frontends collect it
     * from DATA frames before they get here. */

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
    } else if (!strcmp(route, API_PREFIX "imprint") && cfg.impressum_title &&
               *cfg.impressum_title) {
        size_t cap = strlen(cfg.impressum_title) + strlen(cfg.impressum_body ? cfg.impressum_body : "")
                   + (cfg.impressum_footer ? strlen(cfg.impressum_footer) : 0) + 2048;
        char *page = malloc(cap);
        if (!page) {
            respond(c, 500, "Internal Server Error", NULL, NULL, "oom\n", 4);
        } else {
            snprintf(page, cap,
                     "<!doctype html><html lang=\"%s\"><head><meta charset=\"utf-8\">"
                     "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                     "<title>%s</title><style>body{font:16px/1.6 system-ui,sans-serif;"
                     "max-width:40rem;margin:4rem auto;padding:0 1rem;background:#12141a;"
                     "color:#e6e9f0}a{color:#4d6bfe}</style></head><body><h1>%s</h1>%s"
                     "<p><a href=\"/\">%s</a></p><footer>%s</footer></body></html>",
                     pick_locale(&req)->code, cfg.impressum_title, cfg.impressum_title,
                     cfg.impressum_body ? cfg.impressum_body : "", pick_locale(&req)->manual,
                     cfg.impressum_footer && *cfg.impressum_footer ? cfg.impressum_footer : "");
            respond(c, 200, "OK", "text/html; charset=utf-8", NULL, page, strlen(page));
            free(page);
        }
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
                    const char *ctype = "application/octet-stream";
                    if (strstr(name, ".wasm")) ctype = "application/wasm";
                    else if (strstr(name, ".wgsl")) ctype = "text/plain; charset=utf-8";
                    else if (strstr(name, ".webp")) ctype = "image/webp";
                    else if (strstr(name, ".gif")) ctype = "image/gif";
                    else if (strstr(name, ".png")) ctype = "image/png";
                    else if (strstr(name, ".jpg") || strstr(name, ".jpeg"))
                        ctype = "image/jpeg";
                    respond(c, 200, "OK", ctype, "Cache-Control: max-age=86400\r\n",
                            blob, (size_t)len);
                    free(blob);
                }
            }
        }
    } else if (!strncmp(route, API_PREFIX "ext/css-load/", strlen(API_PREFIX) + 13)) {
        const char *id = route + strlen(API_PREFIX) + 13;
        const char *css = "/* ok */\n";
        if (ch_mark_css(id))
            respond(c, 200, "OK", "text/css", "Cache-Control: no-store\r\n", css, strlen(css));
        else
            respond(c, 404, "Not Found", NULL, NULL, "no\n", 3);
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
        char attributed[3072], ref[256] = "";
        ch_peek_referer(id, ref, sizeof ref);
        with_referer_attribution(go, ref, header_value(&req, "Host"), attributed,
                                 sizeof attributed);
        go = attributed;

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
        int need_work = strcasecmp(algorithm, "metarefresh") != 0 &&
                        strcasecmp(algorithm, "preact") != 0;

        if (!id || (need_work && (!response || !nonce_s))) {
            const char *msg = "betterAnusbis: pass-challenge needs id, response and nonce\n";
            respond(c, 400, "Bad Request", NULL, NULL, msg, strlen(msg));
        } else {

            /* metarefresh: no hashing, just elapsed time and the challenge echoed
             * back, exactly as lib/challenge/metarefresh/metarefresh.go checks */
            if (!strcasecmp(algorithm, "metarefresh") || !strcasecmp(algorithm, "preact")) {
                int is_preact = !strcasecmp(algorithm, "preact");
                char gbuf[512];
                const char *got = query_param(req.query, is_preact ? "result" : "challenge",
                                              gbuf, sizeof gbuf);
                /* preact: 80 ms per point (lib/challenge/preact/preact.go:74);
                 * metarefresh: 800 ms per point */
                long long wait_ms = (long long)cfg.difficulty * (is_preact ? 80 : 800);
                long long issued_ms = 0, now_ms;
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                now_ms = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
                long long waited = ch_peek_issued_ms(id, &issued_ms) && issued_ms
                                       ? now_ms - issued_ms
                                       : (issued_at ? now_ms - issued_at * 1000 : wait_ms);
                int time_ok = waited >= wait_ms;
                int data_ok = 0;
                if (is_preact) {
                    /* result is the hex digest of the hex random data, not the
                     * random data itself (:80-85) */
                    char expect[65], cookie_id[128];
                    if (have_challenge &&
                        anubis_sha256_hex(rd_hex, strlen(rd_hex), expect) == ANUBIS_OK &&
                        got && strlen(got) == 64 && !strcasecmp(got, expect) &&
                        find_cookie(req.headers, cfg.verify_name, cookie_id, sizeof cookie_id) &&
                        !strcmp(cookie_id, id))
                        data_ok = 1;
                } else {
                    data_ok = have_challenge && got && strlen(got) == strlen(rd_hex) &&
                              memcmp(got, rd_hex, strlen(rd_hex)) == 0;
                }
                valid = time_ok && data_ok;
                if (!valid) {
                    logmsg("metarefresh rejected: waited %lld of %lld ms, challenge %s",
                           waited, wait_ms, data_ok ? "matched" : "did not match");
                }
                if (valid) {
                    char token[2048];
                    if (sign_token(token, sizeof token, id, bind_to, algorithm, used_difficulty) == 0) {
                        char attrs[512];
                        cookie_attrs(attrs, sizeof attrs, cfg.cookie_ttl > 0 ? cfg.cookie_ttl : -1);
                        char extra[4096];
                        snprintf(extra, sizeof extra, "Set-Cookie: %s=%s%s\r\n",
                                 cfg.cookie_name, token, attrs);
                        respond_redirect(c, go, extra);
                        __atomic_fetch_add(&m_validated, 1, __ATOMIC_RELAXED);
                        logmsg("%s passed (waited %lld ms)", algorithm, waited);
                    } else {
                        respond(c, 500, "Internal Server Error", NULL, NULL, "cannot sign\n", 13);
                    }
                } else {
                    __atomic_fetch_add(&m_failed, 1, __ATOMIC_RELAXED);
                    char msg[512];
                    snprintf(msg, sizeof msg,
                             "betterAnusbis: %s wants a %lld ms wait and %s\n", algorithm,
                             wait_ms,
                             is_preact ? "?result=<sha256 of the random data plus a cookie>"
                                       : "the challenge echoed as ?challenge=<randomData>");
                    respond(c, 403, "Forbidden", NULL, NULL, msg, strlen(msg));
                }
                goto done;
            }

            if (cfg.ext_css_load && ch_css_seen(id) == 0) {
                logmsg("rejecting: the css-load extension was not exercised for %s", id);
                __atomic_fetch_add(&m_failed, 1, __ATOMIC_RELAXED);
                const char *msg = "betterAnusbis: the challenge page's stylesheet was "
                                  "never fetched, so the challenge is not accepted yet\n";
                respond(c, 403, "Forbidden", NULL, NULL, msg, strlen(msg));
                goto done;
            }

            /* tensor-v step 1: the client has committed to C and asks which
             * blocks to open. Nothing is consumed here; the audit endpoint
             * spends the challenge. The sample depends on a server secret, so
             * the client cannot know it before it commits the root. */
            if (!strcasecmp(algorithm, "tensor-v")) {
                char tv_rd[65] = "";
                int tv_d = cfg.difficulty;
                int tv_have = 0;
                if (cfg.stateful) {
                    ch_entry pe;
                    if (ch_peek_entry(id, &pe) == 1) {
                        snprintf(tv_rd, sizeof tv_rd, "%s", pe.rd);
                        tv_d = pe.difficulty;
                        tv_have = pe.algorithm[0] &&
                                  !strcasecmp(pe.algorithm, "tensor-v");
                    }
                } else if (have_challenge) {
                    snprintf(tv_rd, sizeof tv_rd, "%s", rd_hex);
                    tv_have = 1;
                }
                if (!tv_have) {
                    logmsg("rejecting: tensor-v id %s is not a challenge we issued", id);
                    __atomic_fetch_add(&m_failed, 1, __ATOMIC_RELAXED);
                    const char *msg = "betterAnusbis: that is not a tensor-v challenge\n";
                    respond(c, 403, "Forbidden", NULL, NULL, msg, strlen(msg));
                } else if (!looks_like_digest(response)) {
                    __atomic_fetch_add(&m_failed, 1, __ATOMIC_RELAXED);
                    const char *msg = "betterAnusbis: tensor-v wants a 64-hex root\n";
                    respond(c, 400, "Bad Request", NULL, NULL, msg, strlen(msg));
                } else {
                    uint32_t blocks[TENSOR_V_K], positions[TENSOR_V_K];
                    char secret[65];
                    char body[4096];
                    size_t off = 0;
                    int i;

                    tensor_v_secret(secret);
                    if (anubis_tensor_v_sample(tv_rd, tv_d, response, secret, TENSOR_V_K,
                                               blocks, positions) != ANUBIS_OK) {
                        respond(c, 500, "Internal Server Error", NULL, NULL, "sample\n", 7);
                        goto done;
                    }
                    off += (size_t)snprintf(body + off, sizeof body - off,
                                            "{\"audit\":{\"count\":%d,\"blocks\":[",
                                            TENSOR_V_K);
                    for (i = 0; i < TENSOR_V_K; i++) {
                        off += (size_t)snprintf(body + off, sizeof body - off,
                                                "%s%u", i ? "," : "", blocks[i]);
                    }
                    off += (size_t)snprintf(body + off, sizeof body - off,
                                            "],\"positions\":[");
                    for (i = 0; i < TENSOR_V_K; i++) {
                        off += (size_t)snprintf(body + off, sizeof body - off,
                                                "%s%u", i ? "," : "", positions[i]);
                    }
                    off += (size_t)snprintf(body + off, sizeof body - off, "]}}\n");
                    respond(c, 200, "OK", "application/json", NULL, body, off);
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
                    if (!strcasecmp(algorithm, "tensor") && !looks_like_digest(response)) {
                        logmsg("rejecting: tensor response is not a 64-hex digest");
                        valid = 0;
                    } else if (mr_receipt_matches(id, response)) {
                        /* paid, not mined: the operator handed this id's secret
                         * out after the payment arrived */
                        valid = 1;
                        snprintf(digest, sizeof digest, "%s", response);
                        logmsg("meatrider: receipt accepted for %s", id);
                    } else {
                        valid = verify_answer(algorithm, stored, nonce, stored_difficulty,
                                              digest, sizeof digest);
                    }
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
            } else if (!strcasecmp(algorithm, "tensor") && !looks_like_digest(response)) {
                logmsg("rejecting: tensor response is not a 64-hex digest");
            } else if (mr_receipt_matches(id, response)) {
                valid = 1;
                snprintf(digest, sizeof digest, "%s", response);
                logmsg("meatrider: receipt accepted for %s", id);
            } else {
                valid = verify_answer(algorithm, rd_hex, nonce, cfg.difficulty,
                                      digest, sizeof digest);
                if (valid && strcasecmp(response, digest) != 0) {
                    logmsg("rejecting: response %s is not the digest %s for nonce %llu",
                           response, digest, nonce);
                    valid = 0;
                }
            }

            if (valid && cfg.ext_css_load && !ch_css_seen(id)) {
                logmsg("rejecting: challenge %s passed but the css-load extension was "
                       "never exercised", id ? id : "?");
                valid = 0;
            }
            if (!valid) {
                __atomic_fetch_add(&m_failed, 1, __ATOMIC_RELAXED);
                const char *msg =
                    "betterAnusbis: that answer did not verify\n"
                    "  the challenge id, the response and the nonce have to match\n";
                respond(c, 403, "Forbidden", NULL, NULL, msg, strlen(msg));
            } else {
                char token[2048];
                if (sign_token(token, sizeof token, id, bind_to, algorithm, used_difficulty) != 0) {
                    respond(c, 500, "Internal Server Error", NULL, NULL, "cannot sign\n", 13);
                } else {
                    char attrs[512];
                    cookie_attrs(attrs, sizeof attrs, cfg.cookie_ttl > 0 ? cfg.cookie_ttl : -1);
                    char extra[4096];
                    snprintf(extra, sizeof extra,
                             "Set-Cookie: %s=%s%s\r\n"
                             "Set-Cookie: %s=; Path=/; Max-Age=0\r\n",
                             cfg.cookie_name, token, attrs, cfg.verify_name);
                    respond_redirect(c, go, extra);
                    __atomic_fetch_add(&m_validated, 1, __ATOMIC_RELAXED);
                    logmsg("challenge passed (nonce %llu, %s, difficulty %d)", nonce,
                           algorithm, used_difficulty);
                }
            }
        }
    } else if (!strcmp(route, API_PREFIX "audit-tensor")) {
        /* tensor-v step 2: the client opens the blocks the step-1 sample
         * asked for. The sample is re-derived from the root, so this endpoint
         * is stateless; the witness is checked against it before any dot
         * product runs, which is what stops a client from choosing its own
         * blocks. */
        __atomic_fetch_add(&m_requests[M_API], 1, __ATOMIC_RELAXED);
        char id[1024], root[128], redir[2048];
        const char *audit = NULL;
        size_t audit_len = 0;
        if (strcmp(req.method, "POST") != 0 || req.body == NULL ||
            req.body_len == 0) {
            const char *msg = "betterAnusbis: audit-tensor wants a JSON POST\n";
            respond(c, 405, "Method Not Allowed", NULL, NULL, msg, strlen(msg));
            goto done;
        }
        if (!json_get_str(req.body, "id", id, sizeof id) ||
            !json_get_str(req.body, "root", root, sizeof root) ||
            !json_raw_span(req.body, "audit", &audit, &audit_len) ||
            audit_len == 0 || (audit_len & 1) || audit_len > (1u << 20)) {
            const char *msg = "betterAnusbis: audit-tensor needs id, root and audit\n";
            respond(c, 400, "Bad Request", NULL, NULL, msg, strlen(msg));
            goto done;
        }
        if (!json_get_str(req.body, "redir", redir, sizeof redir)) redir[0] = 0;

        char rd[65] = "";
        char algo[24] = "";
        int tv_d = cfg.difficulty;
        int tv_ok = 0;
        if (cfg.stateful) {
            int rc = ch_take(id, rd, sizeof rd, &tv_d, algo, sizeof algo);
            if (rc == 1) {
                tv_ok = 1;
            } else if (rc == -2) {
                logmsg("rejecting: tensor-v challenge %s was already spent", id);
            } else if (rc == -1) {
                logmsg("rejecting: tensor-v challenge %s expired", id);
            } else {
                logmsg("rejecting: tensor-v id %s is not a challenge we issued", id);
            }
        } else {
            char *dot = strrchr(id, '.');
            if (dot) {
                size_t n = (size_t)(dot - id);
                if (n > 0 && n < sizeof rd) {
                    memcpy(rd, id, n);
                    rd[n] = 0;
                    long long issued_at = atoll(dot + 1);
                    if (strlen(rd) % 2 == 0 && strlen(rd) >= 2 &&
                        issued_at && time(NULL) - issued_at <= COOKIE_TTL) {
                        tv_ok = 1;
                    }
                }
            }
            snprintf(algo, sizeof algo, "%s", cfg.algorithm);
        }

        if (!tv_ok || strcasecmp(algo, "tensor-v") != 0) {
            __atomic_fetch_add(&m_failed, 1, __ATOMIC_RELAXED);
            const char *msg = "betterAnusbis: that is not a live tensor-v challenge\n";
            respond(c, 403, "Forbidden", NULL, NULL, msg, strlen(msg));
            goto done;
        }

        {
            uint32_t blocks[TENSOR_V_K], positions[TENSOR_V_K];
            char secret[65];
            char err[256] = "";
            char *audit_hex = malloc(audit_len + 1);

            if (audit_hex == NULL) {
                respond(c, 500, "Internal Server Error", NULL, NULL, "oom\n", 4);
                goto done;
            }
            memcpy(audit_hex, audit, audit_len);
            audit_hex[audit_len] = 0;

            tensor_v_secret(secret);
            if (anubis_tensor_v_sample(rd, tv_d, root, secret, TENSOR_V_K, blocks,
                                       positions) != ANUBIS_OK) {
                free(audit_hex);
                const char *msg = "betterAnusbis: cannot derive the tensor-v sample\n";
                respond(c, 500, "Internal Server Error", NULL, NULL, msg, strlen(msg));
                goto done;
            }
            if (anubis_tensor_v_check_sample(audit_hex, blocks, positions,
                                             TENSOR_V_K) != ANUBIS_OK) {
                free(audit_hex);
                logmsg("rejecting: tensor-v witness is not for this sample");
                __atomic_fetch_add(&m_failed, 1, __ATOMIC_RELAXED);
                const char *msg = "betterAnusbis: the witness does not answer this sample\n";
                respond(c, 403, "Forbidden", NULL, NULL, msg, strlen(msg));
                goto done;
            }
            if (anubis_tensor_v_verify(rd, tv_d, root, audit_hex, err,
                                       sizeof err) != ANUBIS_OK) {
                free(audit_hex);
                logmsg("rejecting: tensor-v witness failed: %s", err);
                __atomic_fetch_add(&m_failed, 1, __ATOMIC_RELAXED);
                const char *msg = "betterAnusbis: that tensor-v witness did not verify\n";
                respond(c, 403, "Forbidden", NULL, NULL, msg, strlen(msg));
                goto done;
            }
            free(audit_hex);

            {
                char token[2048];
                char redir_safe[2048];
                const char *go = safe_redirect(&req, redir, redir_safe,
                                               sizeof redir_safe);
                char esc[4096];
                char jbody[4352];
                char attrs[512];
                char extra[4096];
                if (sign_token(token, sizeof token, id, bind_to, "tensor-v", tv_d) != 0) {
                    respond(c, 500, "Internal Server Error", NULL, NULL, "cannot sign\n", 13);
                    goto done;
                }
                cookie_attrs(attrs, sizeof attrs,
                             cfg.cookie_ttl > 0 ? cfg.cookie_ttl : -1);
                snprintf(extra, sizeof extra,
                         "Set-Cookie: %s=%s%s\r\n"
                         "Set-Cookie: %s=; Path=/; Max-Age=0\r\n",
                         cfg.cookie_name, token, attrs, cfg.verify_name);
                json_escape_into(go, esc, sizeof esc);
                snprintf(jbody, sizeof jbody, "{\"ok\":true,\"redir\":\"%s\"}\n", esc);
                respond(c, 200, "OK", "application/json", extra, jbody, strlen(jbody));
                __atomic_fetch_add(&m_validated, 1, __ATOMIC_RELAXED);
                logmsg("tensor-v passed (%d samples, difficulty %d)", TENSOR_V_K, tv_d);
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
    } else if (cfg.subrequest) {
        /* forwardAuth: nginx asks "may this request through". The policy sees
         * the original URI when the proxy passes one along
         * (lib/policy/checker.go:117-131). */
        /* each value goes into its own buffer: the pointer version of this
         * lookup returns one shared string */
        char orig_buf[2048] = "";
        if (!header_value_into(&req, "X-Original-Uri", orig_buf, sizeof orig_buf) ||
            !orig_buf[0])
            header_value_into(&req, "X-Forwarded-Uri", orig_buf, sizeof orig_buf);
        const char *orig = orig_buf;
        if (orig && *orig) {
            snprintf(route_buf, sizeof route_buf, "%s", orig);
            collapse_slashes(route_buf, req.ppath, sizeof req.ppath);
            route = route_buf;
        }
        if (cfg.dnsbl) {
            int verdict = dnsbl_verdict(client_ip);
            if (verdict < 0) {
                const char *msg = "betterAnusbis: the DNSBL lookup failed\n";
                respond(c, 503, "Service Unavailable", NULL, NULL, msg, strlen(msg));
                goto done;
            }
            if (verdict > 0) {
                char msg[256];
                snprintf(msg, sizeof msg,
                         "betterAnusbis: %s\nlisted by DroneBL in class %d\n",
                         pick_locale(&req)->denied, verdict);
                __atomic_fetch_add(&m_requests[M_DENIED], 1, __ATOMIC_RELAXED);
                respond(c, cfg.deny_status, reason_for(cfg.deny_status), NULL, NULL,
                        msg, strlen(msg));
                goto done;
            }
        }
        int difficulty = cfg.difficulty;
        int policy_difficulty = 0;
        const char *algorithm = cfg.algorithm;
        const locale *loc = pick_locale(&req);
        rule_action action = policy_decide(&req, client_ip, &policy_difficulty, &algorithm);
        if (policy_difficulty > 0) difficulty = policy_difficulty;
        if (action == RULE_DENY) {
            char msg[512];
            snprintf(msg, sizeof msg, "betterAnusbis: %s\n%s%s\n", loc->denied,
                     cfg.webmaster_email && *cfg.webmaster_email ? "contact: " : "",
                     cfg.webmaster_email && *cfg.webmaster_email ? cfg.webmaster_email : "");
            __atomic_fetch_add(&m_requests[M_DENIED], 1, __ATOMIC_RELAXED);
            respond(c, cfg.deny_status, reason_for(cfg.deny_status), NULL, NULL,
                    msg, strlen(msg));
        } else if (authenticated || action == RULE_ALLOW) {
            const char *ok = "ok\n";
            respond(c, 200, "OK", NULL, NULL, ok, strlen(ok));
        } else if (cfg.public_url && *cfg.public_url) {
            /* send the browser to the challenge page on the public URL,
             * carrying where it wanted to go */
            char proto_buf[32] = "", host_buf[256] = "";
            header_value_into(&req, "X-Forwarded-Proto", proto_buf, sizeof proto_buf);
            header_value_into(&req, "X-Forwarded-Host", host_buf, sizeof host_buf);
            const char *proto = proto_buf;
            const char *host = host_buf;
            char target[1024];
            if (!proto || !*proto || !host || !*host) {
                const char *bad = "Missing required X-Forwarded-Proto and X-Forwarded-Host\n";
                respond(c, 400, "Bad Request", NULL, NULL, bad, strlen(bad));
            } else {
                snprintf(target, sizeof target, "%s://%s%s", proto, host,
                         orig && *orig ? orig : req.path);
                char encoded[2048], location[3072];
                url_encode(target, encoded, sizeof encoded);
                snprintf(location, sizeof location, "%s/.within.website/?redir=%s",
                         cfg.public_url, encoded);
                respond_redirect_with(c, 307, location, NULL);
            }
        } else {
            const char *msg = "Authorization required\n";
            respond(c, 401, "Unauthorized", NULL, NULL, msg, strlen(msg));
        }
    } else {
        /* The policy is asked before the cookie is looked at, which is Anubis's
         * order: ALLOW forwards, DENY denies even a client that solved a
         * challenge earlier, and a CHALLENGE result is the only one a valid
         * cookie satisfies. */
        const locale *loc = pick_locale(&req);
        int difficulty = cfg.difficulty;
        int policy_difficulty = 0;
        const char *algorithm = cfg.algorithm;
        rule_action action = policy_decide(&req, client_ip, &policy_difficulty, &algorithm);
        if (cfg.dnsbl) {
            int verdict = dnsbl_verdict(client_ip);
            if (verdict < 0) {
                const char *msg = "betterAnusbis: the DNSBL lookup failed\n";
                respond(c, 503, "Service Unavailable", NULL, NULL, msg, strlen(msg));
                goto done;
            }
            if (verdict > 0) {
                char msg[256];
                snprintf(msg, sizeof msg,
                         "betterAnusbis: %s\nlisted by DroneBL in class %d\n",
                         pick_locale(&req)->denied, verdict);
                __atomic_fetch_add(&m_requests[M_DENIED], 1, __ATOMIC_RELAXED);
                respond(c, cfg.deny_status, reason_for(cfg.deny_status), NULL, NULL,
                        msg, strlen(msg));
                goto done;
            }
        }
        if (action == RULE_ALLOW) {
            __atomic_fetch_add(&m_requests[M_ALLOWED], 1, __ATOMIC_RELAXED);
            __atomic_fetch_add(&m_proxied, 1, __ATOMIC_RELAXED);
            proxy_request(c, &req, client_ip, upstream_path);
            goto done;
        }
        if (action == RULE_DENY) {
            /* Anubis DENYs with a 200 on purpose, so the scraper thinks it got
             * the page; --deny-status 403 is the honest answer. */
            char msg[512];
            snprintf(msg, sizeof msg, "betterAnusbis: %s\n%s%s\n", loc->denied,
                     cfg.webmaster_email && *cfg.webmaster_email ? "contact: " : "",
                     cfg.webmaster_email && *cfg.webmaster_email ? cfg.webmaster_email : "");
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
            const char *why = "difficulty+8";
            if (cfg.meatrider_escalate && cfg.stateful) {
                /* The rung is chosen by the hit count, not by the operator's
                 * mood: threshold hits is a second of browser, twice that is a
                 * minute, then an hour, then three days, then an ASIC's second. */
                algorithm = "meatrider";
                difficulty = meatrider_suspicion_bits(cfg.flag_threshold, trap_hits);
                why = "meatrider";
            } else {
                difficulty = cfg.difficulty + 8 > 64 ? 64 : cfg.difficulty + 8;
                if (cfg.meatrider_escalate)
                    why = "difficulty+8 (--meatrider-escalate needs stateful)";
            }
            if (cfg.verbose)
                logmsg("honeypot: %s has %d trap hits, %s, tier %s, difficulty %d",
                       client_ip, trap_hits, why,
                       anubis_meatrider_tier(difficulty) ? anubis_meatrider_tier(difficulty) : "n/a",
                       difficulty);
        }
        uint8_t rd[32];
        char rd_hex[65];
        if (random_bytes(rd, sizeof rd) != 0) { respond(c, 500, "Internal Server Error", NULL, NULL, "entropy", 7); }
        else {
            hex_encode(rd, sizeof rd, rd_hex);
            char id[128];
            snprintf(id, sizeof id, "%s.%lld", rd_hex, (long long)time(NULL));
            char referer[256] = "", ua_buf[256] = "";
            {
                char raw_ref[512];
                header_value_into(&req, "Referer", raw_ref, sizeof raw_ref);
                size_t rn = 0;
                for (const char *q = raw_ref; *q && rn + 1 < sizeof referer; q++)
                    if (*q != '"' && *q != '\\') referer[rn++] = *q;
                referer[rn] = 0;
            }
            header_value_into(&req, "User-Agent", ua_buf, sizeof ua_buf);
            const char *ua = ua_buf;
            char metadata[1024];
            snprintf(metadata, sizeof metadata,
                     "{\"Referer\":\"%s\",\"User-Agent\":\"%.200s\",\"X-Real-IP\":\"%s\"}",
                     referer, ua ? ua : "", client_ip);

            ch_issue(id, rd_hex, difficulty, algorithm, referer);
            __atomic_fetch_add(&m_requests[M_CHALLENGED], 1, __ATOMIC_RELAXED);
            __atomic_fetch_add(&m_issued, 1, __ATOMIC_RELAXED);
            char og[2048] = "";
            og_snippet(route, og, sizeof og - 512);
            if (cfg.ext_css_load) {
                size_t used = strlen(og);
                snprintf(og + used, sizeof og - used,
                         "<link rel=\"stylesheet\" href=\"%sext/css-load/%s\">",
                         API_PREFIX, id);
            }
            challenge_page(c, id, rd_hex, metadata, id, algorithm, difficulty,
                           pick_locale(&req), og);
        }
    }

done:
    free(req.headers);
    free(req.body);
    close(c->fd);
}

/* HTTP/1.1 and HTTP/1.0: read one request off the connection, then hand the
 * decoded request to handle_parsed(). The whole connection is one request and
 * the answer says Connection: close, which is what the rest of this file has
 * always done. */
static void handle_connection(conn *c, const char *peer_ip) {
    char *raw = malloc(MAX_HEADER + 1);
    if (!raw) { close(c->fd); return; }
    int n = read_headers(c, raw, MAX_HEADER + 1);
    if (n <= 0) { free(raw); close(c->fd); return; }
    raw[n] = 0;

    request req;
    memset(&req, 0, sizeof req);
    if (parse_request(raw, &req) != 0) {
        respond(c, 400, "Bad Request", NULL, NULL, "bad request\n", 12);
        free(raw);
        close(c->fd);
        return;
    }

    if (!path_is_sane(req.path)) {
        const char *msg = "betterAnusbis: that path has a . or .. segment\n";
        respond(c, 400, "Bad Request", NULL, NULL, msg, strlen(msg));
        free(req.headers);
        free(raw);
        close(c->fd);
        return;
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
    free(raw);
    handle_parsed(c, &req, peer_ip);
}

/* --------------------------------------------------------------- HTTP/2
 *
 * The listener side of HTTP/2. The design is deliberately boring: the HTTP/1.1
 * request handler stays exactly as it is, and each HTTP/2 stream gets a
 * socketpair. A worker thread runs handle_parsed() on one end with a request
 * decoded from HEADERS/DATA; this thread reads the ordinary HTTP/1.1 response
 * from the other end, parses it once, and turns it into HEADERS plus DATA.
 *
 * That means the challenge page, the cookie, the pass route, the proxy, the
 * honeypot, the policy engine and the OpenGraph cache did not have to learn a
 * second protocol. Multiplexing is real: the socket is owned by this thread,
 * every stream is a separate worker, and a stream that is still being written
 * never blocks another one. Only one thread ever touches nghttp2.
 */
#ifdef HAVE_NGHTTP2

#define H2_MAX_STREAMS      128
#define H2_RESP_HEAD_MAX    (64u << 10)   /* a response head we are willing to read */
#define H2_RESP_BUFFER_MAX  (1u << 20)    /* how far a handler may run ahead of the socket */

typedef struct h2_stream h2_stream;

struct h2_stream {
    int32_t id;
    char *hdrs;                 /* raw "name: value\r\n" lines from HEADERS */
    size_t hdrs_len, hdrs_cap;
    char *body;
    size_t body_len, body_cap;
    int body_too_big;
    int req_done;
    int dispatched;
    int closed;
    char method[16];
    char path[4096];
    char query[4096];
    char authority[512];
    int rfd;                    /* socketpair read end, -1 once gone */
    int rfd_eof;
    /* response, parsed from the handler's HTTP/1.1 bytes */
    int headers_sent;
    char *head;
    size_t head_len, head_cap;
    char *out;                  /* body bytes not yet handed to nghttp2 */
    size_t out_len, out_off, out_cap;
    int out_eof;
    int framing;                /* 0 until close, 1 Content-Length, 2 chunked */
    long long remaining;        /* framing 1 */
    int ch_state;               /* framing 2: 0 size line, 1 data, 2 CRLF, 3 trailers */
    long long ch_rem;
    int ch_skip;
    char ch_line[256];
    size_t ch_line_len;
    int no_body;
    int is_head;
};

typedef struct {
    conn *c;
    nghttp2_session *sess;
    h2_stream *streams[H2_MAX_STREAMS];
    size_t nstreams;
    char peer[64];
    int dead;
} h2_conn;

typedef struct {
    int fd;
    request *req;
    char *ip;
} h2_job;

static ssize_t h2_data_read(nghttp2_session *sess, int32_t id, uint8_t *buf, size_t length,
                            uint32_t *flags, nghttp2_data_source *source, void *user_data);
static void h2_stream_feed(h2_conn *h, h2_stream *st, const unsigned char *data, size_t len);

static h2_stream *h2_get(h2_conn *h, int32_t id) {
    for (size_t i = 0; i < h->nstreams; i++)
        if (h->streams[i]->id == id) return h->streams[i];
    return NULL;
}

static h2_stream *h2_add(h2_conn *h, int32_t id) {
    h2_stream *st = h2_get(h, id);
    if (st) return st;
    if (h->nstreams >= H2_MAX_STREAMS) return NULL;
    st = calloc(1, sizeof *st);
    if (!st) return NULL;
    st->id = id;
    st->rfd = -1;
    h->streams[h->nstreams++] = st;
    return st;
}

static void h2_stream_free(h2_stream *st) {
    if (!st) return;
    if (st->rfd >= 0) close(st->rfd);
    free(st->hdrs);
    free(st->body);
    free(st->head);
    free(st->out);
    free(st);
}

/* Append to the small header block or the body queue. Both are bounded; a
 * handler that produces more than H2_RESP_BUFFER_MAX is simply not read from
 * until nghttp2 has drained what it already has, which is the backpressure a
 * socketpair would have given us anyway. */
static int h2_append(char **buf, size_t *len, size_t *cap, const void *data, size_t n) {
    /* +1 because the caller (and strstr) expects a NUL after the bytes */
    if (*len + n + 1 > *cap) {
        size_t want = *cap ? *cap : 256;
        while (want < *len + n + 1) want *= 2;
        char *nb = realloc(*buf, want);
        if (!nb) return -1;
        *buf = nb;
        *cap = want;
    }
    memcpy(*buf + *len, data, n);
    *len += n;
    (*buf)[*len] = 0;
    return 0;
}

static char *h2_lower(char *s) {
    for (char *p = s; *p; p++) *p = (char)tolower((unsigned char)*p);
    return s;
}

static void h2_stream_parse_head(h2_conn *h, h2_stream *st) {
    char statusbuf[8];
    nghttp2_nv nva[64];
    /* These must outlive the loop: nghttp2_nv holds pointers, and nghttp2 copies
     * at submit time, which is after the loop. A per-iteration stack buffer left
     * every entry pointing at the last header, which is how the first version
     * sent a set-cookie whose value was the tail of another header. */
    char names[64][96];
    char values[64][1024];
    size_t nv = 0;
    char *end = strstr(st->head, "\r\n\r\n");
    int status = 0;

    if (!end) return;
    if (!strncmp(st->head, "HTTP/1.", 7)) status = atoi(st->head + 9);
    if (status < 100 || status > 599) status = 502;
    snprintf(statusbuf, sizeof statusbuf, "%d", status);
    nva[nv++] = (nghttp2_nv){(uint8_t *)":status", (uint8_t *)statusbuf,
                             sizeof(":status") - 1, strlen(statusbuf),
                             NGHTTP2_NV_FLAG_NONE};

    int chunked = 0;
    long long clen = -1;
    char *p = strstr(st->head, "\r\n");
    p = p ? p + 2 : st->head;
    while (p < end) {
        char *eol = strstr(p, "\r\n");
        if (!eol || eol > end) break;
        char *colon = memchr(p, ':', (size_t)(eol - p));
        if (colon && colon > p && nv < sizeof nva / sizeof nva[0]) {
            char *name = names[nv];
            char *value = values[nv];
            size_t nl = (size_t)(colon - p);
            size_t vl;
            if (nl >= sizeof names[0]) nl = sizeof names[0] - 1;
            memcpy(name, p, nl);
            name[nl] = 0;
            h2_lower(name);
            const char *v = colon + 1;
            while (v < eol && (*v == ' ' || *v == '\t')) v++;
            vl = (size_t)(eol - v);
            if (vl >= sizeof values[0]) vl = sizeof values[0] - 1;
            memcpy(value, v, vl);
            value[vl] = 0;

            if (!strcmp(name, "content-length")) {
                clen = atoll(value);
            } else if (!strcmp(name, "transfer-encoding")) {
                if (strcasestr(value, "chunked")) chunked = 1;
            } else if (!strcmp(name, "connection") || !strcmp(name, "keep-alive") ||
                       !strcmp(name, "proxy-connection") || !strcmp(name, "upgrade") ||
                       !strcmp(name, "te") || !strcmp(name, "trailer") ||
                       !strcmp(name, "transfer-encoding") || !strcmp(name, "content-length")) {
                /* connection-specific: HTTP/2 has its own framing */
            } else {
                nva[nv] = (nghttp2_nv){(uint8_t *)name, (uint8_t *)value, strlen(name),
                                       strlen(value), NGHTTP2_NV_FLAG_NONE};
                nv++;
            }
        }
        p = eol + 2;
    }

    st->is_head = !strcasecmp(st->method, "HEAD");
    st->no_body = st->is_head || status == 204 || status == 304 || status < 200;

    size_t after = (size_t)(st->head + st->head_len - (end + 4));
    char *rest = end + 4;
    if (st->no_body) {
        st->out_eof = 1;
        after = 0;
    } else if (chunked) {
        st->framing = 2;
        st->ch_state = 0;
    } else if (clen >= 0) {
        st->framing = 1;
        st->remaining = clen;
        if (clen == 0) st->out_eof = 1;
    } else {
        st->framing = 0;             /* the handler's close is the delimiter */
    }

    nghttp2_data_provider dp;
    memset(&dp, 0, sizeof dp);
    dp.source.ptr = st;
    dp.read_callback = h2_data_read;
    if (st->no_body || (st->framing == 1 && st->remaining == 0))
        nghttp2_submit_response(h->sess, st->id, nva, nv, NULL);
    else
        nghttp2_submit_response(h->sess, st->id, nva, nv, &dp);
    st->headers_sent = 1;
    st->head_len = 0;

    if (after) {
        /* the read that finished the head usually started the body too */
        h2_stream_feed(h, st, (const unsigned char *)rest, after);
    }
}

/* Decode the body half of one handler response. Chunked is de-framed here
 * because HTTP/2 has no Transfer-Encoding: the relay in this file writes
 * chunked to a plain socket, and a browser speaking h2 must not see it. */
static void h2_body_append(h2_conn *h, h2_stream *st, const unsigned char *data, size_t len) {
    (void)h;
    if (!st->out_eof && h2_append(&st->out, &st->out_len, &st->out_cap, data, len) != 0)
        st->out_eof = 1;
}

static void h2_stream_feed_body(h2_conn *h, h2_stream *st, const unsigned char *data, size_t len) {
    while (len && !st->out_eof) {
        if (st->framing == 0) {
            h2_body_append(h, st, data, len);
            len = 0;
        } else if (st->framing == 1) {
            size_t take = (size_t)st->remaining < len ? (size_t)st->remaining : len;
            h2_body_append(h, st, data, take);
            st->remaining -= (long long)take;
            data += take;
            len -= take;
            if (st->remaining == 0) st->out_eof = 1;
        } else {
            switch (st->ch_state) {
            case 0: /* chunk-size line */
                while (len) {
                    char ch = (char)*data++;
                    len--;
                    if (st->ch_line_len + 1 < sizeof st->ch_line)
                        st->ch_line[st->ch_line_len++] = ch;
                    if (ch == '\n') {
                        char num[64];
                        size_t n = st->ch_line_len;
                        st->ch_line[n] = 0;
                        while (n && (st->ch_line[n - 1] == '\r' || st->ch_line[n - 1] == '\n'))
                            st->ch_line[--n] = 0;
                        char *semi = strchr(st->ch_line, ';');
                        if (semi) *semi = 0;
                        snprintf(num, sizeof num, "%s", st->ch_line);
                        long long sz = strtoll(num, NULL, 16);
                        st->ch_line_len = 0;
                        if (sz < 0) { st->out_eof = 1; len = 0; break; }
                        if (sz == 0) {
                            st->ch_state = 3;
                        } else {
                            st->ch_rem = sz;
                            st->ch_state = 1;
                        }
                        break;
                    }
                }
                break;
            case 1: /* chunk payload */
                if (st->ch_rem > 0) {
                    size_t take = (size_t)st->ch_rem < len ? (size_t)st->ch_rem : len;
                    h2_body_append(h, st, data, take);
                    st->ch_rem -= (long long)take;
                    data += take;
                    len -= take;
                }
                if (st->ch_rem == 0) {
                    st->ch_skip = 2;
                    st->ch_state = 2;
                }
                break;
            case 2: /* CRLF after a chunk */
                while (len && st->ch_skip > 0) { data++; len--; st->ch_skip--; }
                if (st->ch_skip == 0) st->ch_state = 0;
                break;
            default: /* trailers, then the empty line */
                while (len) {
                    char ch = (char)*data++;
                    len--;
                    if (st->ch_line_len + 1 < sizeof st->ch_line)
                        st->ch_line[st->ch_line_len++] = ch;
                    if (ch == '\n') {
                        size_t n = st->ch_line_len;
                        st->ch_line[n] = 0;
                        if (n == 2 && st->ch_line[0] == '\r') { st->out_eof = 1; len = 0; }
                        st->ch_line_len = 0;
                    }
                }
                break;
            }
        }
    }
    if (st->out_eof) nghttp2_session_resume_data(h->sess, st->id);
    else if (st->out_len > st->out_off) nghttp2_session_resume_data(h->sess, st->id);
}

static void h2_stream_feed(h2_conn *h, h2_stream *st, const unsigned char *data, size_t len) {
    if (!st || st->closed) return;
    if (!st->headers_sent) {
        if (h2_append(&st->head, &st->head_len, &st->head_cap, data, len) != 0) {
            st->out_eof = 1;
            return;
        }
        char *end = strstr(st->head, "\r\n\r\n");
        if (end) {
            h2_stream_parse_head(h, st);
        } else if (st->head_len > H2_RESP_HEAD_MAX) {
            /* a handler that never ends its headers: give the client a 502 */
            st->head_len = 0;
            const char *bad = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                              "Connection: close\r\n\r\n";
            h2_stream_feed(h, st, (const unsigned char *)bad, strlen(bad));
        }
    } else {
        h2_stream_feed_body(h, st, data, len);
    }
}

static void h2_inject(h2_conn *h, h2_stream *st, int status, const char *ctype,
                      const char *body) {
    if (!st || st->closed || st->headers_sent) return;
    char head[768];
    size_t blen = body ? strlen(body) : 0;
    int n = snprintf(head, sizeof head,
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                     "Connection: close\r\n\r\n",
                     status, reason_for(status), ctype ? ctype : "text/plain; charset=utf-8",
                     blen);
    if (n <= 0) return;
    h2_stream_feed(h, st, (const unsigned char *)head, (size_t)n);
    if (blen) h2_stream_feed(h, st, (const unsigned char *)body, blen);
}

static ssize_t h2_data_read(nghttp2_session *sess, int32_t id, uint8_t *buf, size_t length,
                            uint32_t *flags, nghttp2_data_source *source, void *user_data) {
    (void)sess; (void)source;
    h2_conn *h = user_data;
    h2_stream *st = h2_get(h, id);
    if (!st) { *flags |= NGHTTP2_DATA_FLAG_EOF; return 0; }
    size_t have = st->out_len - st->out_off;
    if (have == 0) {
        if (st->out_eof) { *flags |= NGHTTP2_DATA_FLAG_EOF; return 0; }
        return NGHTTP2_ERR_DEFERRED;
    }
    size_t take = have < length ? have : length;
    memcpy(buf, st->out + st->out_off, take);
    st->out_off += take;
    if (st->out_off == st->out_len) {
        st->out_len = st->out_off = 0;
        if (st->out_eof) *flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return (ssize_t)take;
}

static ssize_t h2_send_cb(nghttp2_session *sess, const uint8_t *data, size_t length,
                          int flags, void *user_data) {
    (void)sess; (void)flags;
    h2_conn *h = user_data;
    ssize_t w = conn_write(h->c, data, length);
    if (w < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return NGHTTP2_ERR_WOULDBLOCK;
        h->dead = 1;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return w;
}

static int h2_on_begin_headers(nghttp2_session *sess, const nghttp2_frame *frame,
                               void *user_data) {
    (void)sess;
    h2_conn *h = user_data;
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST)
        h2_add(h, frame->hd.stream_id);
    return 0;
}

static int h2_on_header(nghttp2_session *sess, const nghttp2_frame *frame,
                        const uint8_t *name, size_t namelen, const uint8_t *value,
                        size_t valuelen, uint8_t flags, void *user_data) {
    (void)sess; (void)frame; (void)flags;
    h2_conn *h = user_data;
    h2_stream *st = h2_get(h, frame->hd.stream_id);
    if (!st) return 0;
    if (namelen && name[0] == ':') {
        if (namelen == 7 && !memcmp(name, ":method", 7)) {
            size_t n = valuelen < sizeof st->method - 1 ? valuelen : sizeof st->method - 1;
            memcpy(st->method, value, n);
            st->method[n] = 0;
        } else if (namelen == 5 && !memcmp(name, ":path", 5)) {
            size_t n = valuelen < sizeof st->path - 1 ? valuelen : sizeof st->path - 1;
            memcpy(st->path, value, n);
            st->path[n] = 0;
        } else if (namelen == 10 && !memcmp(name, ":authority", 10)) {
            size_t n = valuelen < sizeof st->authority - 1 ? valuelen
                                                           : sizeof st->authority - 1;
            memcpy(st->authority, value, n);
            st->authority[n] = 0;
        }
        return 0;
    }
    if (h2_append(&st->hdrs, &st->hdrs_len, &st->hdrs_cap, name, namelen) != 0 ||
        h2_append(&st->hdrs, &st->hdrs_len, &st->hdrs_cap, ": ", 2) != 0 ||
        h2_append(&st->hdrs, &st->hdrs_len, &st->hdrs_cap, value, valuelen) != 0 ||
        h2_append(&st->hdrs, &st->hdrs_len, &st->hdrs_cap, "\r\n", 2) != 0) {
        st->body_too_big = 1;       /* header memory: treat as unservable */
    }
    return 0;
}

static int h2_on_data(nghttp2_session *sess, uint8_t flags, int32_t stream_id,
                      const uint8_t *data, size_t length, void *user_data) {
    (void)sess; (void)flags;
    h2_conn *h = user_data;
    h2_stream *st = h2_get(h, stream_id);
    if (!st) return 0;
    if (st->body_len + length > MAX_BODY) {
        st->body_too_big = 1;
        return 0;
    }
    if (h2_append(&st->body, &st->body_len, &st->body_cap, data, length) != 0)
        st->body_too_big = 1;
    return 0;
}

static void *h2_job_main(void *arg) {
    h2_job *j = arg;
    conn cc = {.fd = j->fd, .ssl = NULL};
    handle_parsed(&cc, j->req, j->ip);
    free(j->req);
    free(j->ip);
    free(j);
    return NULL;
}

static void h2_dispatch(h2_conn *h, h2_stream *st) {
    if (!st || st->req_done || st->closed) return;
    st->req_done = 1;
    if (st->body_too_big) {
        h2_inject(h, st, 413, NULL, "betterAnusbis: request too large\n");
        return;
    }
    if (!st->method[0]) {
        h2_inject(h, st, 400, NULL, "bad request\n");
        return;
    }
    if (!strcasecmp(st->method, "CONNECT")) {
        /* WebSocket over HTTP/2 (RFC 8441) is not implemented; an Upgrade
         * cannot be carried by an ordinary request. */
        h2_inject(h, st, 400, NULL, "betterAnusbis: extended CONNECT is not supported\n");
        return;
    }

    request *rq = calloc(1, sizeof *rq);
    if (!rq) { h2_inject(h, st, 500, NULL, "oom\n"); return; }
    snprintf(rq->method, sizeof rq->method, "%s", st->method);
    snprintf(rq->version, sizeof rq->version, "HTTP/2.0");
    const char *path = st->path[0] ? st->path : "/";
    const char *q = strchr(path, '?');
    if (q) {
        size_t n = (size_t)(q - path);
        if (n >= sizeof rq->path) n = sizeof rq->path - 1;
        memcpy(rq->path, path, n);
        rq->path[n] = 0;
        snprintf(rq->query, sizeof rq->query, "%s", q + 1);
    } else {
        snprintf(rq->path, sizeof rq->path, "%s", path);
    }

    /* Host is spelled :authority in HTTP/2 and the handler wants a header.
     * If the client also sent host, keep it; otherwise synthesize one. */
    int have_host = 0;
    for (const char *p = st->hdrs; p && *p; ) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        if ((size_t)(eol - p) >= 5 && !strncasecmp(p, "host:", 5)) { have_host = 1; break; }
        p = eol + 2;
    }
    size_t need = st->hdrs_len + strlen(st->authority) + 64;
    rq->headers = malloc(need);
    if (!rq->headers) {
        free(rq);
        h2_inject(h, st, 500, NULL, "oom\n");
        return;
    }
    size_t o = 0;
    if (!have_host && st->authority[0])
        o += (size_t)snprintf(rq->headers + o, need - o, "Host: %s\r\n", st->authority);
    if (st->hdrs_len) {
        memcpy(rq->headers + o, st->hdrs, st->hdrs_len);
        o += st->hdrs_len;
    }
    rq->headers[o] = 0;
    rq->body = st->body;
    rq->body_len = st->body_len;
    st->body = NULL;
    st->body_len = 0;

    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
        free(rq->headers);
        free(rq);
        h2_inject(h, st, 500, NULL, "socketpair\n");
        return;
    }
    h2_job *job = calloc(1, sizeof *job);
    if (!job) {
        close(sp[0]); close(sp[1]);
        free(rq->headers);
        free(rq);
        h2_inject(h, st, 500, NULL, "oom\n");
        return;
    }
    job->fd = sp[1];
    job->req = rq;
    job->ip = strdup(h->peer);
    st->rfd = sp[0];
    st->dispatched = 1;
    pthread_t t;
    if (pthread_create(&t, NULL, h2_job_main, job) == 0) {
        pthread_detach(t);
    } else {
        close(sp[0]); close(sp[1]);
        st->rfd = -1;
        free(job->ip);
        free(rq->headers);
        free(rq);
        free(job);
        h2_inject(h, st, 500, NULL, "thread\n");
    }
}

static int h2_on_frame(nghttp2_session *sess, const nghttp2_frame *frame, void *user_data) {
    h2_conn *h = user_data;
    h2_stream *st = h2_get(h, frame->hd.stream_id);
    if (!st) return 0;
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
        (void)sess;
        h2_dispatch(h, st);
    }
    return 0;
}

static int h2_on_close(nghttp2_session *sess, int32_t stream_id, uint32_t error_code,
                       void *user_data) {
    (void)sess; (void)error_code;
    h2_conn *h = user_data;
    h2_stream *st = h2_get(h, stream_id);
    if (st) {
        st->closed = 1;
        st->req_done = 1;
        if (st->rfd >= 0) { close(st->rfd); st->rfd = -1; }
    }
    return 0;
}

static int h2_is_prior_knowledge(int fd) {
    char pre[24];
    ssize_t n = recv(fd, pre, sizeof pre, MSG_PEEK);
    return n == (ssize_t)sizeof pre && !memcmp(pre, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
}

/* One HTTP/2 connection. Only this thread touches the nghttp2 session and the
 * socket; workers only write to their own socketpair. */
static void h2_serve(conn *c, const char *peer_ip) {
    h2_conn *h = calloc(1, sizeof *h);
    if (!h) { close(c->fd); return; }
    h->c = c;
    snprintf(h->peer, sizeof h->peer, "%s", peer_ip ? peer_ip : "0.0.0.0");

    nghttp2_session_callbacks *cbs = NULL;
    if (nghttp2_session_callbacks_new(&cbs) != 0) {
        free(h);
        close(c->fd);
        return;
    }
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, h2_on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(cbs, h2_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, h2_on_data);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, h2_on_frame);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, h2_on_close);
    nghttp2_session_callbacks_set_send_callback(cbs, h2_send_cb);
    /* nghttp2 copies what it needs, so the callbacks object can go right away */
    int srv_rc = nghttp2_session_server_new(&h->sess, cbs, h);
    nghttp2_session_callbacks_del(cbs);
    if (srv_rc != 0) {
        free(h);
        close(c->fd);
        return;
    }

    nghttp2_settings_entry iv[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, H2_MAX_STREAMS},
        {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
    };
    nghttp2_submit_settings(h->sess, NGHTTP2_FLAG_NONE, iv, sizeof iv / sizeof iv[0]);
    nghttp2_session_send(h->sess);

    unsigned char buf[16384];
    while (!h->dead) {
        struct pollfd pfds[1 + H2_MAX_STREAMS];
        h2_stream *watch[H2_MAX_STREAMS];
        int n = 0, nw = 0;
        pfds[n].fd = c->fd;
        pfds[n].events = POLLIN;
        pfds[n].revents = 0;
        n++;
        for (size_t i = 0; i < h->nstreams; i++) {
            h2_stream *st = h->streams[i];
            if (st->rfd < 0 || st->closed) continue;
            if (st->out_len - st->out_off >= H2_RESP_BUFFER_MAX) continue;
            watch[nw] = st;
            pfds[n].fd = st->rfd;
            pfds[n].events = POLLIN;
            pfds[n].revents = 0;
            n++, nw++;
        }
        int pr = poll(pfds, (nfds_t)n, 60000);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) break;          /* idle HTTP/2 connection */

        if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t r = conn_read(c, buf, sizeof buf);
            if (r <= 0) break;
            ssize_t used = nghttp2_session_mem_recv(h->sess, buf, (size_t)r);
            if (used < 0) break;
        }
        for (int i = 0; i < nw; i++) {
            h2_stream *st = watch[i];
            if (st->rfd < 0 || st->closed) continue;
            if (!(pfds[i + 1].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            unsigned char rbuf[16384];
            ssize_t r = read(st->rfd, rbuf, sizeof rbuf);
            if (r > 0) {
                h2_stream_feed(h, st, rbuf, (size_t)r);
            } else if (r == 0) {
                st->rfd_eof = 1;
                if (!st->headers_sent)
                    h2_inject(h, st, 500, NULL, "betterAnusbis: no response\n");
                if (st->framing == 0 || st->framing == 2) st->out_eof = 1;
                else if (st->remaining > 0) st->out_eof = 1;
                nghttp2_session_resume_data(h->sess, st->id);
                close(st->rfd);
                st->rfd = -1;
            }
        }
        if (nghttp2_session_send(h->sess) != 0) break;

        /* retire streams the session has finished with */
        for (size_t i = 0; i < h->nstreams; ) {
            if (h->streams[i]->closed) {
                h2_stream_free(h->streams[i]);
                h->streams[i] = h->streams[--h->nstreams];
            } else {
                i++;
            }
        }
        int live = 0;
        for (size_t i = 0; i < h->nstreams; i++)
            if (h->streams[i]->rfd >= 0 || !h->streams[i]->out_eof) live = 1;
        if (!nghttp2_session_want_read(h->sess) && !nghttp2_session_want_write(h->sess) && !live)
            break;
    }

    for (size_t i = 0; i < h->nstreams; i++) h2_stream_free(h->streams[i]);
    nghttp2_session_del(h->sess);
    free(h);
    close(c->fd);
}


/* --------------------------------------------------- HTTP/2 to the backend
 *
 * The origin hop is a synchronous h2 client: one request, one stream, the
 * response streamed back into the ordinary HTTP/1.1 relay format (chunked),
 * which the frontend (HTTP/1.1, HTTP/2 or HTTP/3) already knows how to carry.
 * No multiplexing and no pooling here yet; the gate's own clients are the ones
 * that benefit from multiplexing, and a pooled h2 connection is a much larger
 * piece of state to own than a pooled h1 one.
 */
typedef struct {
    conn *out;                  /* where the synthesized HTTP/1.1 response goes */
    conn *up;                   /* the h2 origin connection */
    request *req;
    int32_t stream_id;
    int status;
    int head_emitted;
    int done;
    int failed;
    int no_body;
    int chunked_out;
    int head_only;
    char *hdrs;
    size_t hdrs_len, hdrs_cap;
} h2_up_ctx;

typedef struct {
    const char *data;
    size_t len, off;
} h2_up_body;

static ssize_t h2_up_data_read(nghttp2_session *sess, int32_t stream_id, uint8_t *buf,
                               size_t length, uint32_t *flags, nghttp2_data_source *source,
                               void *user_data) {
    (void)sess; (void)stream_id; (void)user_data;
    h2_up_body *b = source->ptr;
    size_t left = b->len - b->off;
    if (left == 0) { *flags |= NGHTTP2_DATA_FLAG_EOF; return 0; }
    size_t take = left < length ? left : length;
    memcpy(buf, b->data + b->off, take);
    b->off += take;
    if (b->off == b->len) *flags |= NGHTTP2_DATA_FLAG_EOF;
    return (ssize_t)take;
}

static void h2_up_write_out(h2_up_ctx *u, const void *data, size_t len) {
    if (!u->failed && len && send_all(u->out, data, len) < 0) u->failed = 1;
}

static void h2_up_emit_head(h2_up_ctx *u) {
    if (u->head_emitted || u->failed) return;
    char head[512];
    int n = snprintf(head, sizeof head, "HTTP/1.1 %d %s\r\n", u->status,
                     reason_for(u->status));
    h2_up_write_out(u, head, (size_t)n);
    if (u->chunked_out) h2_up_write_out(u, "Transfer-Encoding: chunked\r\n", 28);
    h2_up_write_out(u, "Connection: close\r\n", 19);
    /* content-length and chunked cannot both be present */
    const char *p = u->hdrs;
    while (p && *p) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        size_t len = (size_t)(eol - p);
        int skip = u->chunked_out && len >= 15 && !strncasecmp(p, "content-length:", 15);
        if (!skip) h2_up_write_out(u, p, len + 2);
        p = eol + 2;
    }
    h2_up_write_out(u, "\r\n", 2);
    u->head_emitted = 1;
}

static int h2_up_on_header(nghttp2_session *sess, const nghttp2_frame *frame,
                           const uint8_t *name, size_t namelen, const uint8_t *value,
                           size_t valuelen, uint8_t flags, void *user_data) {
    (void)sess; (void)flags;
    h2_up_ctx *u = user_data;
    if (frame->hd.type != NGHTTP2_HEADERS || frame->hd.stream_id != u->stream_id) return 0;
    if (namelen && name[0] == ':') {
        if (namelen == 7 && !memcmp(name, ":status", 7)) {
            char s[8];
            size_t n = valuelen < sizeof s - 1 ? valuelen : sizeof s - 1;
            memcpy(s, value, n);
            s[n] = 0;
            u->status = atoi(s);
        }
        return 0;
    }
    /* Hop-by-hop fields do not survive the tunnel. content-length is dropped
     * when we re-frame as chunked, kept when the body is empty. */
    if ((namelen == 10 && !strncasecmp((const char *)name, "connection", 10)) ||
        (namelen == 10 && !strncasecmp((const char *)name, "keep-alive", 10)) ||
        (namelen == 17 && !strncasecmp((const char *)name, "transfer-encoding", 17)) ||
        (namelen == 16 && !strncasecmp((const char *)name, "proxy-connection", 16)) ||
        (namelen == 7 && !strncasecmp((const char *)name, "upgrade", 7)) ||
        (namelen == 2 && !strncasecmp((const char *)name, "te", 2)) ||
        (namelen == 7 && !strncasecmp((const char *)name, "trailer", 7)))
        return 0;
    if (h2_append(&u->hdrs, &u->hdrs_len, &u->hdrs_cap, name, namelen) != 0 ||
        h2_append(&u->hdrs, &u->hdrs_len, &u->hdrs_cap, ": ", 2) != 0 ||
        h2_append(&u->hdrs, &u->hdrs_len, &u->hdrs_cap, value, valuelen) != 0 ||
        h2_append(&u->hdrs, &u->hdrs_len, &u->hdrs_cap, "\r\n", 2) != 0)
        u->failed = 1;
    return 0;
}

static int h2_up_on_data(nghttp2_session *sess, uint8_t flags, int32_t stream_id,
                         const uint8_t *data, size_t length, void *user_data) {
    (void)sess; (void)flags;
    h2_up_ctx *u = user_data;
    if (stream_id != u->stream_id || u->failed) return 0;
    if (u->no_body) return 0;
    char ch[40];
    int n = snprintf(ch, sizeof ch, "%zx\r\n", length);
    h2_up_write_out(u, ch, (size_t)n);
    h2_up_write_out(u, data, length);
    h2_up_write_out(u, "\r\n", 2);
    return 0;
}

static int h2_up_on_frame(nghttp2_session *sess, const nghttp2_frame *frame, void *user_data) {
    (void)sess;
    h2_up_ctx *u = user_data;
    if (frame->hd.stream_id != u->stream_id) return 0;
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
        u->no_body = !strcasecmp(u->req->method, "HEAD") || u->status == 204 ||
                     u->status == 304 || u->status < 200;
        u->chunked_out = !u->no_body;
        if (!u->head_emitted) h2_up_emit_head(u);
    }
    if (frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) {
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) u->done = 1;
    }
    return 0;
}

static int h2_up_on_close(nghttp2_session *sess, int32_t stream_id, uint32_t error_code,
                          void *user_data) {
    (void)sess;
    h2_up_ctx *u = user_data;
    if (stream_id == u->stream_id) {
        if (error_code != 0 || !u->head_emitted) u->failed = 1;
        u->done = 1;
    }
    return 0;
}

static ssize_t h2_up_send(nghttp2_session *sess, const uint8_t *data, size_t length,
                          int flags, void *user_data) {
    (void)sess; (void)flags;
    h2_up_ctx *u = user_data;
    ssize_t w = send_all(u->up, data, length);
    return w < 0 ? NGHTTP2_ERR_CALLBACK_FAILURE : w;
}

/* Connect with h2 offered. Returns 1 when the origin selected h2, 0 when it
 * selected something else (the caller then does a fresh HTTP/1.1 connection),
 * and -1 after writing a 502 itself. */
static int target_connect_h2(conn *up) {
    if (!cfg.target_tls) return 0;
    int fd = connect_target();
    if (fd < 0) return 0;
    static SSL_CTX *h2_client_ctx;
    if (!h2_client_ctx) {
        h2_client_ctx = SSL_CTX_new(TLS_client_method());
        if (!h2_client_ctx) { close(fd); return 0; }
        SSL_CTX_set_min_proto_version(h2_client_ctx, TLS1_2_VERSION);
        if (cfg.target_insecure) SSL_CTX_set_verify(h2_client_ctx, SSL_VERIFY_NONE, NULL);
        else {
            SSL_CTX_set_verify(h2_client_ctx, SSL_VERIFY_PEER, NULL);
            SSL_CTX_set_default_verify_paths(h2_client_ctx);
        }
    }
    SSL *ssl = SSL_new(h2_client_ctx);
    if (!ssl) { close(fd); return 0; }
    SSL_set_fd(ssl, fd);
    static const unsigned char protos[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    SSL_set_alpn_protos(ssl, protos, sizeof protos);
    const char *sni = cfg.target_sni && *cfg.target_sni ? cfg.target_sni : cfg.target_host;
    if (!strcasecmp(sni, "auto")) sni = cfg.target_host;
    if (strcmp(sni, "0.0.0.0") != 0) SSL_set_tlsext_host_name(ssl, sni);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        close(fd);
        return 0;
    }
    if (!cfg.target_insecure && SSL_get_verify_result(ssl) != X509_V_OK) {
        logmsg("target certificate did not verify: %s",
               X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        SSL_free(ssl);
        close(fd);
        return 0;
    }
    const unsigned char *proto = NULL;
    unsigned int plen = 0;
    SSL_get0_alpn_selected(ssl, &proto, &plen);
    if (plen != 2 || !proto || memcmp(proto, "h2", 2) != 0) {
        SSL_free(ssl);
        close(fd);
        return 0;
    }
    up->fd = fd;
    up->ssl = ssl;
    return 1;
}

/* Returns 1 when it handled the request, 0 when the backend did not select h2
 * and the ordinary HTTP/1.1 path should run. */
static int proxy_request_h2(conn *c, const request *req, const char *client_ip,
                            const char *path) {
    conn up_c = {.fd = -1, .ssl = NULL};
    int rc = target_connect_h2(&up_c);
    if (rc == 0) return 0;
    if (rc < 0) return 1;

    h2_up_ctx u;
    memset(&u, 0, sizeof u);
    u.out = c;
    u.up = &up_c;
    u.req = (request *)req;
    u.status = 0;
    u.head_only = !strcasecmp(req->method, "HEAD");

    nghttp2_session_callbacks *cbs = NULL;
    nghttp2_session *sess = NULL;
    if (nghttp2_session_callbacks_new(&cbs) != 0) {
        up_close(&up_c);
        return 0;
    }
    nghttp2_session_callbacks_set_on_header_callback(cbs, h2_up_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, h2_up_on_data);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, h2_up_on_frame);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, h2_up_on_close);
    nghttp2_session_callbacks_set_send_callback(cbs, h2_up_send);
    int sr = nghttp2_session_client_new(&sess, cbs, &u);
    nghttp2_session_callbacks_del(cbs);
    if (sr != 0) {
        up_close(&up_c);
        return 0;
    }

    nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_ENABLE_PUSH, 0}};
    nghttp2_submit_settings(sess, NGHTTP2_FLAG_NONE, iv, sizeof iv / sizeof iv[0]);

    /* request headers: same forwarding rules as the HTTP/1.1 path */
    const char *host_hdr = cfg.target_host_hdr && *cfg.target_host_hdr
                               ? cfg.target_host_hdr : cfg.target_host;
    char pathbuf[8192];
    if (req->query[0])
        snprintf(pathbuf, sizeof pathbuf, "%s?%s", path, req->query);
    else
        snprintf(pathbuf, sizeof pathbuf, "%s", path);
    char methodbuf[16];
    snprintf(methodbuf, sizeof methodbuf, "%s", req->method);

    nghttp2_nv nva[96];
    char names[96][96];
    char values[96][1024];
    size_t nv = 0;
#define H2UP_NV(N, V) do { \
        snprintf(names[nv], sizeof names[nv], "%s", (N)); \
        snprintf(values[nv], sizeof values[nv], "%s", (V)); \
        nva[nv] = (nghttp2_nv){(uint8_t *)names[nv], (uint8_t *)values[nv], \
                               strlen(names[nv]), strlen(values[nv]), NGHTTP2_NV_FLAG_NONE}; \
        nv++; \
    } while (0)
    H2UP_NV(":method", methodbuf);
    H2UP_NV(":path", pathbuf);
    H2UP_NV(":scheme", "https");
    H2UP_NV(":authority", host_hdr);
    const char *p = req->headers;
    while (p && *p && nv < sizeof nva / sizeof nva[0]) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        size_t n = (size_t)(eol - p);
        char line[1200];
        if (n > 0 && n < sizeof line) {
            memcpy(line, p, n);
            line[n] = 0;
            char *colon = strchr(line, ':');
            if (colon && colon > line) {
                *colon = 0;
                char *val = colon + 1;
                while (*val == ' ' || *val == '\t') val++;
                if (strcasecmp(line, "host") && strcasecmp(line, "connection") &&
                    strcasecmp(line, "keep-alive") && strcasecmp(line, "proxy-connection") &&
                    strcasecmp(line, "upgrade") && strcasecmp(line, "te") &&
                    strcasecmp(line, "trailer") && strcasecmp(line, "transfer-encoding") &&
                    strcasecmp(line, "content-length"))
                    H2UP_NV(line, val);
            }
        }
        p = eol + 2;
    }
    H2UP_NV("x-real-ip", client_ip);
    H2UP_NV("x-forwarded-for", client_ip);
    if (req->body_len) {
        char clbuf[32];
        snprintf(clbuf, sizeof clbuf, "%zu", req->body_len);
        H2UP_NV("content-length", clbuf);
    }
#undef H2UP_NV

    h2_up_body body = {.data = req->body, .len = req->body_len, .off = 0};
    nghttp2_data_provider dp;
    memset(&dp, 0, sizeof dp);
    dp.source.ptr = &body;
    dp.read_callback = h2_up_data_read;
    int32_t id = nghttp2_submit_request(sess, NULL, nva, nv,
                                        req->body_len ? &dp : NULL, NULL);
    if (id < 0) {
        nghttp2_session_del(sess);
        up_close(&up_c);
        return 0;
    }
    u.stream_id = id;

    struct timeval tv = {.tv_sec = 60, .tv_usec = 0};
    setsockopt(up_c.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    unsigned char buf[16384];
    while (!u.done && !u.failed) {
        if (nghttp2_session_send(sess) != 0) { u.failed = 1; break; }
        ssize_t n = conn_read(&up_c, buf, sizeof buf);
        if (n <= 0) { u.failed = 1; break; }
        ssize_t used = nghttp2_session_mem_recv(sess, buf, (size_t)n);
        if (used < 0) { u.failed = 1; break; }
    }
    nghttp2_session_send(sess);
    if (!u.head_emitted) {
        u.failed = 1;
    }
    if (u.chunked_out && !u.failed) h2_up_write_out(&u, "0\r\n\r\n", 5);
    nghttp2_session_del(sess);
    up_close(&up_c);
    free(u.hdrs);
    if (u.failed && !u.head_emitted) {
        const char *msg = "betterAnusbis: the target closed without answering\n";
        respond(c, 502, "Bad Gateway", NULL, NULL, msg, strlen(msg));
    }
    return 1;
}

#endif /* HAVE_NGHTTP2 */



/* --------------------------------------------------------------- HTTP/3
 *
 * QUIC from OpenSSL 3.5, HTTP/3 framing and QPACK from nghttp3. The structure
 * mirrors the HTTP/2 frontend: the QUIC event loop owns every nghttp3 object
 * and the UDP socket, and a completed request is handed to an ordinary worker
 * thread over a socketpair. The worker writes HTTP/1.1; this loop parses it and
 * turns it into HEADERS plus DATA. Nothing in the gate below this comment
 * knows which protocol it is answering.
 *
 * Deliberate limits, all visible in this file: one thread for all QUIC
 * connections, 64 connections and 64 streams per connection, a 20 ms tick
 * (QUIC needs SSL_handle_events anyway, and the handler's socketpair is read on
 * that tick), QPACK with a zero-sized dynamic table for maximum interop, and no
 * 0-RTT. HTTP/3 is opt-in with --http3 and never touches a plain listener.
 */
#ifdef HAVE_NGHTTP3

#define H3_MAX_CONNS        64
#define H3_MAX_STREAMS      64
#define H3_RBUF_SIZE        (64u << 10)
#define H3_RESP_HEAD_MAX    (64u << 10)
#define H3_RESP_BUFFER_MAX  (1u << 20)
#define H3_TICK_US          20000

typedef struct h3_stream h3_stream;
typedef struct h3_conn h3_conn;

struct h3_stream {
    h3_conn *c;
    SSL *ssl;                   /* the QUIC stream SSL object */
    int64_t id;
    int is_uni;
    int dead;                   /* free at reap time */
    int closed_by_h3;
    int fin_sent;
    int blocked;

    /* request */
    int headers_done;
    int req_fin;
    int got_fin;
    int too_large;
    int dispatched;
    char method[16];
    char path[4096];
    char query[4096];
    char authority[512];
    char *hdrs;
    size_t hdrs_len, hdrs_cap;
    char *body;
    size_t body_len, body_cap;

    /* response, parsed from the worker's HTTP/1.1 */
    int rfd;
    int headers_sent;
    char *head;
    size_t head_len, head_cap;
    char *out;
    size_t out_len, out_off, out_cap;
    int out_eof;
    int want_resume;
    int framing;
    long long remaining;
    int ch_state;
    long long ch_rem;
    int ch_skip;
    char ch_line[256];
    size_t ch_line_len;
    int no_body;
    int is_head;
};

struct h3_conn {
    SSL *ssl;
    nghttp3_conn *h3;
    int uni_created;
    SSL *uni_ctl, *uni_enc, *uni_dec;
    int closing;
    int dead;
    h3_stream *streams[H3_MAX_STREAMS];
    size_t app_bytes;
    char peer[64];
};

typedef struct {
    int fd;
    request *req;
    char *ip;
} h3_job;

static SSL_CTX *h3_ctx;
static SSL *h3_listener;
static int h3_udp_fd = -1;
static h3_conn *h3_conns[H3_MAX_CONNS];
static size_t h3_nconns;

static h3_stream *h3_get(h3_conn *c, int64_t id) {
    for (size_t i = 0; i < H3_MAX_STREAMS; i++)
        if (c->streams[i] && !c->streams[i]->dead && c->streams[i]->id == id)
            return c->streams[i];
    return NULL;
}

static h3_stream *h3_add(h3_conn *c, SSL *ssl, int64_t id, int is_uni) {
    for (size_t i = 0; i < H3_MAX_STREAMS; i++) {
        if (!c->streams[i]) {
            h3_stream *st = calloc(1, sizeof *st);
            if (!st) return NULL;
            st->c = c;
            st->ssl = ssl;
            st->id = id;
            st->is_uni = is_uni;
            st->rfd = -1;
            c->streams[i] = st;
            return st;
        }
    }
    return NULL;
}

static void h3_stream_free(h3_stream *st) {
    if (!st) return;
    if (st->rfd >= 0) close(st->rfd);
    if (st->ssl) SSL_free(st->ssl);
    free(st->hdrs);
    free(st->body);
    free(st->head);
    free(st->out);
    free(st);
}

static void h3_conn_close(h3_conn *c, const char *why) {
    if (c->dead) return;
    if (cfg.verbose && why) logmsg("http3: closing a connection: %s", why);
    c->dead = 1;
}

/* Best effort client address for a QUIC connection. OpenSSL 3.5 does not
 * expose a peer-address getter for a connection SSL, so this asks the
 * connection BIO; when that is unavailable the address is left unspecified
 * rather than invented. */
static void h3_peer_ip(const h3_conn *c, char *out, size_t cap) {
    snprintf(out, cap, "0.0.0.0");
    if (!c->ssl) return;
    BIO *b = SSL_get_rbio(c->ssl);
    if (!b) return;
    const BIO_ADDR *pa = BIO_get_conn_address(b);
    BIO_ADDR *made = NULL;
    if (!pa) {
        made = BIO_ADDR_new();
        if (!made) return;
        if (BIO_dgram_get_peer(b, made) <= 0) { BIO_ADDR_free(made); return; }
        pa = made;
    }
    char *s = BIO_ADDR_hostname_string(pa, 1);
    if (s) {
        snprintf(out, cap, "%s", s);
        OPENSSL_free(s);
    }
    if (made) BIO_ADDR_free(made);
}

/* Reuse the HTTP/2 response parser's rules; the bytes are the same HTTP/1.1
 * a worker writes, only the sink differs (nghttp3 vectors instead of a
 * nghttp2 data provider). */
static void h3_append_bytes(char **buf, size_t *len, size_t *cap, const void *data,
                            size_t n) {
    if (*len + n + 1 > *cap) {
        size_t want = *cap ? *cap : 256;
        while (want < *len + n + 1) want *= 2;
        char *nb = realloc(*buf, want);
        if (!nb) return;
        *buf = nb;
        *cap = want;
    }
    memcpy(*buf + *len, data, n);
    *len += n;
    (*buf)[*len] = 0;
}

static char *h3_lower(char *s) {
    for (char *p = s; *p; p++) *p = (char)tolower((unsigned char)*p);
    return s;
}

static void h3_feed_body(h3_stream *st, const unsigned char *data, size_t len);

static void h3_result_append(h3_stream *st, const unsigned char *data, size_t len) {
    h3_append_bytes(&st->out, &st->out_len, &st->out_cap, data, len);
}

static nghttp3_ssize h3_read_data(nghttp3_conn *h3, int64_t sid, nghttp3_vec *vec,
                                  size_t veccnt, uint32_t *pflags, void *cud, void *sud) {
    (void)h3; (void)sud;
    h3_conn *c = cud;
    h3_stream *st = h3_get(c, sid);
    if (!st || veccnt == 0) return NGHTTP3_ERR_WOULDBLOCK;
    size_t have = st->out_len - st->out_off;
    if (have == 0) {
        if (st->out_eof) { *pflags |= NGHTTP3_DATA_FLAG_EOF; return 0; }
        st->want_resume = 1;
        return NGHTTP3_ERR_WOULDBLOCK;
    }
    size_t take = have < H3_RESP_BUFFER_MAX ? have : H3_RESP_BUFFER_MAX;
    vec[0].base = (uint8_t *)st->out + st->out_off;
    vec[0].len = take;
    st->out_off += take;
    if (st->out_off == st->out_len) {
        st->out_len = st->out_off = 0;
        if (st->out_eof) *pflags |= NGHTTP3_DATA_FLAG_EOF;
    }
    return 1;
}

static void h3_submit_head(h3_stream *st) {
    char statusbuf[8];
    nghttp3_nv nva[64];
    char names[64][96];
    char values[64][1024];
    size_t nv = 0;
    char *end = strstr(st->head, "\r\n\r\n");
    int status = 0;

    if (!end) return;
    if (!strncmp(st->head, "HTTP/1.", 7)) status = atoi(st->head + 9);
    if (status < 100 || status > 599) status = 502;
    snprintf(statusbuf, sizeof statusbuf, "%d", status);
    nva[nv++] = (nghttp3_nv){(uint8_t *)":status", (uint8_t *)statusbuf,
                             sizeof(":status") - 1, strlen(statusbuf),
                             NGHTTP3_NV_FLAG_NONE};

    int chunked = 0;
    long long clen = -1;
    char *p = strstr(st->head, "\r\n");
    p = p ? p + 2 : st->head;
    while (p < end) {
        char *eol = strstr(p, "\r\n");
        if (!eol || eol > end) break;
        char *colon = memchr(p, ':', (size_t)(eol - p));
        if (colon && colon > p && nv < sizeof nva / sizeof nva[0]) {
            char *name = names[nv];
            char *value = values[nv];
            size_t nl = (size_t)(colon - p);
            size_t vl;
            if (nl >= sizeof names[0]) nl = sizeof names[0] - 1;
            memcpy(name, p, nl);
            name[nl] = 0;
            h3_lower(name);
            const char *v = colon + 1;
            while (v < eol && (*v == ' ' || *v == '\t')) v++;
            vl = (size_t)(eol - v);
            if (vl >= sizeof values[0]) vl = sizeof values[0] - 1;
            memcpy(value, v, vl);
            value[vl] = 0;

            if (!strcmp(name, "content-length")) {
                clen = atoll(value);
            } else if (!strcmp(name, "transfer-encoding")) {
                if (strcasestr(value, "chunked")) chunked = 1;
            } else if (!strcmp(name, "connection") || !strcmp(name, "keep-alive") ||
                       !strcmp(name, "proxy-connection") || !strcmp(name, "upgrade") ||
                       !strcmp(name, "te") || !strcmp(name, "trailer") ||
                       !strcmp(name, "transfer-encoding") || !strcmp(name, "content-length")) {
                /* HTTP/2 and HTTP/3 have their own framing */
            } else {
                nva[nv] = (nghttp3_nv){(uint8_t *)name, (uint8_t *)value, strlen(name),
                                       strlen(value), NGHTTP3_NV_FLAG_NONE};
                nv++;
            }
        }
        p = eol + 2;
    }

    st->is_head = !strcasecmp(st->method, "HEAD");
    st->no_body = st->is_head || status == 204 || status == 304 || status < 200;
    size_t after = (size_t)(st->head + st->head_len - (end + 4));
    char *rest = end + 4;
    if (st->no_body) {
        st->out_eof = 1;
        after = 0;
    } else if (chunked) {
        st->framing = 2;
        st->ch_state = 0;
    } else if (clen >= 0) {
        st->framing = 1;
        st->remaining = clen;
        if (clen == 0) st->out_eof = 1;
    } else {
        st->framing = 0;
    }

    nghttp3_data_reader dr;
    memset(&dr, 0, sizeof dr);
    dr.read_data = h3_read_data;
    int body = !st->no_body && !(st->framing == 1 && st->remaining == 0);
    int rc = nghttp3_conn_submit_response(st->c->h3, st->id, nva, nv, body ? &dr : NULL);
    if (rc < 0) h3_conn_close(st->c, "nghttp3_conn_submit_response");
    st->headers_sent = 1;
    st->head_len = 0;
    if (after) h3_feed_body(st, (const unsigned char *)rest, after);
}

static void h3_feed_body(h3_stream *st, const unsigned char *data, size_t len) {
    while (len && !st->out_eof) {
        if (st->framing == 0) {
            h3_result_append(st, data, len);
            len = 0;
        } else if (st->framing == 1) {
            size_t take = (size_t)st->remaining < len ? (size_t)st->remaining : len;
            h3_result_append(st, data, take);
            st->remaining -= (long long)take;
            data += take;
            len -= take;
            if (st->remaining == 0) st->out_eof = 1;
        } else {
            switch (st->ch_state) {
            case 0:
                while (len) {
                    char ch = (char)*data++;
                    len--;
                    if (st->ch_line_len + 1 < sizeof st->ch_line)
                        st->ch_line[st->ch_line_len++] = ch;
                    if (ch == '\n') {
                        size_t n = st->ch_line_len;
                        st->ch_line[n] = 0;
                        while (n && (st->ch_line[n - 1] == '\r' || st->ch_line[n - 1] == '\n'))
                            st->ch_line[--n] = 0;
                        char *semi = strchr(st->ch_line, ';');
                        if (semi) *semi = 0;
                        long long sz = strtoll(st->ch_line, NULL, 16);
                        st->ch_line_len = 0;
                        if (sz < 0) { st->out_eof = 1; len = 0; break; }
                        if (sz == 0) st->ch_state = 3;
                        else { st->ch_rem = sz; st->ch_state = 1; }
                        break;
                    }
                }
                break;
            case 1:
                if (st->ch_rem > 0) {
                    size_t take = (size_t)st->ch_rem < len ? (size_t)st->ch_rem : len;
                    h3_result_append(st, data, take);
                    st->ch_rem -= (long long)take;
                    data += take;
                    len -= take;
                }
                if (st->ch_rem == 0) { st->ch_skip = 2; st->ch_state = 2; }
                break;
            case 2:
                while (len && st->ch_skip > 0) { data++; len--; st->ch_skip--; }
                if (st->ch_skip == 0) st->ch_state = 0;
                break;
            default:
                while (len) {
                    char ch = (char)*data++;
                    len--;
                    if (st->ch_line_len + 1 < sizeof st->ch_line)
                        st->ch_line[st->ch_line_len++] = ch;
                    if (ch == '\n') {
                        size_t n = st->ch_line_len;
                        st->ch_line[n] = 0;
                        if (n == 2 && st->ch_line[0] == '\r') { st->out_eof = 1; len = 0; }
                        st->ch_line_len = 0;
                    }
                }
                break;
            }
        }
    }
    if (st->want_resume && (st->out_eof || st->out_len > st->out_off)) {
        st->want_resume = 0;
        nghttp3_conn_resume_stream(st->c->h3, st->id);
    }
}

static void h3_feed(h3_stream *st, const unsigned char *data, size_t len) {
    if (!st || st->dead) return;
    if (!st->headers_sent) {
        h3_append_bytes(&st->head, &st->head_len, &st->head_cap, data, len);
        char *end = strstr(st->head, "\r\n\r\n");
        if (end) {
            h3_submit_head(st);
        } else if (st->head_len > H3_RESP_HEAD_MAX) {
            const char *bad = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                              "Connection: close\r\n\r\n";
            st->head_len = 0;
            h3_feed(st, (const unsigned char *)bad, strlen(bad));
        }
    } else {
        h3_feed_body(st, data, len);
    }
}

static void h3_inject(h3_stream *st, int status, const char *ctype, const char *body) {
    if (!st || st->dead || st->headers_sent) return;
    char head[768];
    size_t blen = body ? strlen(body) : 0;
    int n = snprintf(head, sizeof head,
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                     "Connection: close\r\n\r\n",
                     status, reason_for(status),
                     ctype ? ctype : "text/plain; charset=utf-8", blen);
    if (n > 0) h3_feed(st, (const unsigned char *)head, (size_t)n);
    if (blen) h3_feed(st, (const unsigned char *)body, blen);
}

static void *h3_job_main(void *arg) {
    h3_job *j = arg;
    conn cc = {.fd = j->fd, .ssl = NULL};
    handle_parsed(&cc, j->req, j->ip);
    free(j->req);
    free(j->ip);
    free(j);
    return NULL;
}

static void h3_dispatch(h3_stream *st) {
    if (!st || st->req_fin == 0 || st->dispatched || st->dead) return;
    st->dispatched = 1;
    if (st->too_large) {
        h3_inject(st, 413, NULL, "betterAnusbis: request too large\n");
        return;
    }
    if (!st->method[0] || !strcasecmp(st->method, "CONNECT")) {
        h3_inject(st, 400, NULL, "betterAnusbis: extended CONNECT is not supported\n");
        return;
    }
    request *rq = calloc(1, sizeof *rq);
    if (!rq) { h3_inject(st, 500, NULL, "oom\n"); return; }
    snprintf(rq->method, sizeof rq->method, "%s", st->method);
    snprintf(rq->version, sizeof rq->version, "HTTP/3.0");
    const char *path = st->path[0] ? st->path : "/";
    const char *q = strchr(path, '?');
    if (q) {
        size_t n = (size_t)(q - path);
        if (n >= sizeof rq->path) n = sizeof rq->path - 1;
        memcpy(rq->path, path, n);
        rq->path[n] = 0;
        snprintf(rq->query, sizeof rq->query, "%s", q + 1);
    } else {
        snprintf(rq->path, sizeof rq->path, "%s", path);
    }

    int have_host = 0;
    for (const char *p = st->hdrs; p && *p; ) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        if ((size_t)(eol - p) >= 5 && !strncasecmp(p, "host:", 5)) { have_host = 1; break; }
        p = eol + 2;
    }
    size_t need = st->hdrs_len + strlen(st->authority) + 64;
    rq->headers = malloc(need);
    if (!rq->headers) { free(rq); h3_inject(st, 500, NULL, "oom\n"); return; }
    size_t o = 0;
    if (!have_host && st->authority[0])
        o += (size_t)snprintf(rq->headers + o, need - o, "Host: %s\r\n", st->authority);
    if (st->hdrs_len) {
        memcpy(rq->headers + o, st->hdrs, st->hdrs_len);
        o += st->hdrs_len;
    }
    rq->headers[o] = 0;
    rq->body = st->body;
    rq->body_len = st->body_len;
    st->body = NULL;
    st->body_len = 0;

    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
        free(rq->headers);
        free(rq);
        h3_inject(st, 500, NULL, "socketpair\n");
        return;
    }
    h3_job *job = calloc(1, sizeof *job);
    char ip[64];
    h3_peer_ip(st->c, ip, sizeof ip);
    if (!job) {
        close(sp[0]); close(sp[1]);
        free(rq->headers);
        free(rq);
        h3_inject(st, 500, NULL, "oom\n");
        return;
    }
    job->fd = sp[1];
    job->req = rq;
    job->ip = strdup(ip);
    st->rfd = sp[0];
    int fl = fcntl(st->rfd, F_GETFL, 0);
    if (fl >= 0) fcntl(st->rfd, F_SETFL, fl | O_NONBLOCK);
    pthread_t t;
    if (pthread_create(&t, NULL, h3_job_main, job) == 0) {
        pthread_detach(t);
    } else {
        close(sp[0]); close(sp[1]);
        st->rfd = -1;
        free(job->ip);
        free(rq->headers);
        free(rq);
        free(job);
        h3_inject(st, 500, NULL, "thread\n");
    }
}

static int h3_cb_header(nghttp3_conn *h3, int64_t sid, int32_t token,
                        nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                        void *cud, void *sud) {
    (void)h3; (void)token; (void)flags; (void)sud;
    h3_conn *c = cud;
    h3_stream *st = h3_get(c, sid);
    if (!st) return 0;
    nghttp3_vec n = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
    if (n.len && n.base[0] == ':') {
        if (n.len == 7 && !memcmp(n.base, ":method", 7)) {
            size_t k = v.len < sizeof st->method - 1 ? v.len : sizeof st->method - 1;
            memcpy(st->method, v.base, k);
            st->method[k] = 0;
        } else if (n.len == 5 && !memcmp(n.base, ":path", 5)) {
            size_t k = v.len < sizeof st->path - 1 ? v.len : sizeof st->path - 1;
            memcpy(st->path, v.base, k);
            st->path[k] = 0;
        } else if (n.len == 10 && !memcmp(n.base, ":authority", 10)) {
            size_t k = v.len < sizeof st->authority - 1 ? v.len : sizeof st->authority - 1;
            memcpy(st->authority, v.base, k);
            st->authority[k] = 0;
        }
        return 0;
    }
    h3_append_bytes(&st->hdrs, &st->hdrs_len, &st->hdrs_cap, n.base, n.len);
    h3_append_bytes(&st->hdrs, &st->hdrs_len, &st->hdrs_cap, ": ", 2);
    h3_append_bytes(&st->hdrs, &st->hdrs_len, &st->hdrs_cap, v.base, v.len);
    h3_append_bytes(&st->hdrs, &st->hdrs_len, &st->hdrs_cap, "\r\n", 2);
    return 0;
}

static int h3_cb_end_headers(nghttp3_conn *h3, int64_t sid, int fin,
                             void *cud, void *sud) {
    (void)h3; (void)sud;
    h3_conn *c = cud;
    h3_stream *st = h3_get(c, sid);
    if (!st) return 0;
    st->headers_done = 1;
    if (fin) st->req_fin = 1;
    if (fin) h3_dispatch(st);
    return 0;
}

static int h3_cb_data(nghttp3_conn *h3, int64_t sid, const uint8_t *data, size_t datalen,
                      void *cud, void *sud) {
    (void)h3; (void)sud;
    h3_conn *c = cud;
    h3_stream *st = h3_get(c, sid);
    c->app_bytes += datalen;
    if (!st) return 0;
    if (st->too_large) return 0;
    if (st->body_len + datalen > MAX_BODY) {
        st->too_large = 1;
        return 0;
    }
    h3_append_bytes(&st->body, &st->body_len, &st->body_cap, data, datalen);
    return 0;
}

static int h3_cb_end_stream(nghttp3_conn *h3, int64_t sid, void *cud, void *sud) {
    (void)h3; (void)sud;
    h3_conn *c = cud;
    h3_stream *st = h3_get(c, sid);
    if (!st) return 0;
    st->req_fin = 1;
    h3_dispatch(st);
    return 0;
}

static int h3_cb_close(nghttp3_conn *h3, int64_t sid, uint64_t aec, void *cud, void *sud) {
    (void)h3; (void)aec; (void)sud;
    h3_conn *c = cud;
    h3_stream *st = h3_get(c, sid);
    if (!st) return 0;
    st->dead = 1;
    st->req_fin = 1;
    if (st->rfd >= 0) { close(st->rfd); st->rfd = -1; }
    return 0;
}

static int h3_cb_reset(nghttp3_conn *h3, int64_t sid, uint64_t aec, void *cud, void *sud) {
    (void)h3; (void)sud;
    h3_conn *c = cud;
    h3_stream *st = h3_get(c, sid);
    if (!st || !st->ssl) return 0;
    SSL_STREAM_RESET_ARGS args;
    memset(&args, 0, sizeof args);
    args.quic_error_code = aec;
    SSL_stream_reset(st->ssl, &args, sizeof args);
    return 0;
}

static int h3_create_uni(h3_conn *c) {
    if (c->uni_created) return 0;
    if (!SSL_is_init_finished(c->ssl)) return 0;
    c->uni_ctl = SSL_new_stream(c->ssl, SSL_STREAM_FLAG_UNI);
    c->uni_enc = SSL_new_stream(c->ssl, SSL_STREAM_FLAG_UNI);
    c->uni_dec = SSL_new_stream(c->ssl, SSL_STREAM_FLAG_UNI);
    if (!c->uni_ctl || !c->uni_enc || !c->uni_dec) return -1;
    if (nghttp3_conn_bind_control_stream(c->h3,
            (int64_t)SSL_get_stream_id(c->uni_ctl)) < 0) return -1;
    if (nghttp3_conn_bind_qpack_streams(c->h3,
            (int64_t)SSL_get_stream_id(c->uni_enc),
            (int64_t)SSL_get_stream_id(c->uni_dec)) < 0) return -1;
    if (!h3_add(c, c->uni_ctl, (int64_t)SSL_get_stream_id(c->uni_ctl), 1) ||
        !h3_add(c, c->uni_enc, (int64_t)SSL_get_stream_id(c->uni_enc), 1) ||
        !h3_add(c, c->uni_dec, (int64_t)SSL_get_stream_id(c->uni_dec), 1))
        return -1;
    c->uni_created = 1;
    return 0;
}

static void h3_pump_read(h3_stream *st) {
    if (!st || st->dead || !st->ssl) return;
    h3_conn *c = st->c;
    for (int guard = 0; guard < 1024; guard++) {
        size_t nread = 0;
        unsigned char buf[H3_RBUF_SIZE];

        if (SSL_get_stream_read_state(st->ssl) == SSL_STREAM_STATE_RESET_REMOTE) {
            uint64_t aec = 0;
            SSL_get_stream_read_error_code(st->ssl, &aec);
            /* one stream reset is not a connection error */
            nghttp3_conn_close_stream(c->h3, st->id, aec);
            return;
        }
        if (!SSL_read_ex(st->ssl, buf, sizeof buf, &nread)) {
            int err = SSL_get_error(st->ssl, 0);
            if (err == SSL_ERROR_WANT_READ) return;
            if (err == SSL_ERROR_ZERO_RETURN) {
                if (st->got_fin) return;
                st->got_fin = 1;
                c->app_bytes = 0;
                if (nghttp3_conn_read_stream(c->h3, st->id, NULL, 0, 1) < 0)
                    h3_conn_close(c, "nghttp3 fin error");
                return;
            }
            h3_conn_close(c, "SSL_read");
            return;
        }
        if (nread == 0) return;
        c->app_bytes = 0;
        nghttp3_ssize used = nghttp3_conn_read_stream(c->h3, st->id, buf, nread, 0);
        size_t app = c->app_bytes;
        c->app_bytes = 0;
        if (used < 0) { h3_conn_close(c, "nghttp3 read"); return; }
        if ((size_t)used + app < nread) return;
        if (st->dead) return;
    }
}

static void h3_pump_write(h3_conn *c) {
    if (c->dead) return;
    for (int round = 0; round < 1024; round++) {
        nghttp3_vec vec[16];
        int64_t sid = -1;
        int fin = 0;
        nghttp3_ssize nv = nghttp3_conn_writev_stream(c->h3, &sid, &fin, vec, 16);
        if (nv < 0) { h3_conn_close(c, "nghttp3 writev"); return; }
        if (nv == 0) {
            if (sid >= 0 && fin) {
                h3_stream *st = h3_get(c, sid);
                nghttp3_conn_add_write_offset(c->h3, sid, 0);
                if (st && st->ssl && !st->fin_sent) {
                    st->fin_sent = 1;
                    SSL_stream_conclude(st->ssl, 0);
                }
                continue;
            }
            break;
        }
        h3_stream *st = h3_get(c, sid);
        size_t total = 0, wanted = 0;
        int stop = 0;
        for (size_t i = 0; i < (size_t)nv; i++) wanted += vec[i].len;
        for (size_t i = 0; i < (size_t)nv; i++) {
            size_t written = 0;
            if (vec[i].len == 0) continue;
            if (!st || !st->ssl) { written = vec[i].len; }
            else if (!SSL_write_ex2(st->ssl, vec[i].base, vec[i].len, 0, &written)) {
                if (SSL_get_error(st->ssl, 0) == SSL_ERROR_WANT_WRITE) {
                    if (!st->blocked) {
                        nghttp3_conn_block_stream(c->h3, sid);
                        st->blocked = 1;
                    }
                    written = 0;
                    stop = 1;
                } else {
                    h3_conn_close(c, "SSL_write");
                    return;
                }
            } else if (st->blocked) {
                st->blocked = 0;
                nghttp3_conn_unblock_stream(c->h3, sid);
            }
            total += written;
            if (stop || written < vec[i].len) break;
        }
        if (total > 0) {
            nghttp3_conn_add_write_offset(c->h3, sid, total);
            nghttp3_conn_add_ack_offset(c->h3, sid, total);
        }
        if (fin && !stop && total == wanted) {
            if (st && st->ssl && !st->fin_sent) {
                st->fin_sent = 1;
                SSL_stream_conclude(st->ssl, 0);
            }
        }
        if (stop || total < wanted || total == 0) break;
    }
}

/* Read whatever a worker has produced and push it towards QUIC. */
static int h3_service_bridges(h3_conn *c, int *need_write) {
    int progressed = 0;
    for (size_t i = 0; i < H3_MAX_STREAMS; i++) {
        h3_stream *st = c->streams[i];
        if (!st || st->dead || st->rfd < 0) continue;
        for (;;) {
            unsigned char buf[16384];
            ssize_t r = read(st->rfd, buf, sizeof buf);
            if (r > 0) {
                h3_feed(st, buf, (size_t)r);
                progressed = 1;
                if (st->out_len - st->out_off >= H3_RESP_BUFFER_MAX) break;
            } else if (r == 0) {
                if (!st->headers_sent)
                    h3_inject(st, 500, NULL, "betterAnusbis: no response\n");
                if (st->framing == 0 || st->framing == 2) st->out_eof = 1;
                else if (st->framing == 1 && st->remaining > 0) st->out_eof = 1;
                if (st->want_resume) {
                    st->want_resume = 0;
                    nghttp3_conn_resume_stream(c->h3, st->id);
                }
                close(st->rfd);
                st->rfd = -1;
                break;
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) continue;
                close(st->rfd);
                st->rfd = -1;
                break;
            }
        }
    }
    if (progressed) *need_write = 1;
    return 0;
}

static void h3_accept_streams(h3_conn *c) {
    for (;;) {
        SSL *s = SSL_accept_stream(c->ssl, SSL_ACCEPT_STREAM_NO_BLOCK);
        if (!s) break;
        int64_t id = (int64_t)SSL_get_stream_id(s);
        int type = SSL_get_stream_type(s);
        if (h3_create_uni(c) < 0) { SSL_free(s); h3_conn_close(c, "uni streams"); return; }
        h3_stream *st = h3_add(c, s, id, type != SSL_STREAM_TYPE_BIDI);
        if (!st) { SSL_free(s); h3_conn_close(c, "stream slots"); return; }
        h3_pump_read(st);
        if (c->dead) return;
    }
}

static h3_conn *h3_accept_conns(void) {
    h3_conn *first = NULL;
    for (;;) {
        SSL *s = SSL_accept_connection(h3_listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
        if (!s) break;
        if (h3_nconns >= H3_MAX_CONNS) { SSL_free(s); break; }
        h3_conn *c = calloc(1, sizeof *c);
        if (!c) { SSL_free(s); break; }
        c->ssl = s;
        SSL_set_default_stream_mode(s, SSL_DEFAULT_STREAM_MODE_NONE);
        SSL_set_incoming_stream_policy(s, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);

        nghttp3_callbacks cbs;
        nghttp3_settings settings;
        memset(&cbs, 0, sizeof cbs);
        cbs.recv_header = h3_cb_header;
        cbs.end_headers = h3_cb_end_headers;
        cbs.recv_data = h3_cb_data;
        cbs.end_stream = h3_cb_end_stream;
        cbs.stream_close = h3_cb_close;
        cbs.reset_stream = h3_cb_reset;
        nghttp3_settings_default(&settings);
        settings.qpack_max_dtable_capacity = 0;
        settings.qpack_encoder_max_dtable_capacity = 0;
        settings.qpack_blocked_streams = 0;
        if (nghttp3_conn_server_new(&c->h3, &cbs, &settings, NULL, c) < 0) {
            SSL_free(s);
            free(c);
            break;
        }
        h3_peer_ip(c, c->peer, sizeof c->peer);
        h3_conns[h3_nconns++] = c;
        if (h3_create_uni(c) < 0) h3_conn_close(c, "uni at accept");
        if (!first) first = c;
    }
    return first;
}

static void h3_maybe_close(h3_conn *c) {
    for (size_t i = 0; i < H3_MAX_STREAMS; i++) {
        h3_stream *st = c->streams[i];
        if (!st || st->dead || !st->ssl || st->is_uni) continue;
        if (st->closed_by_h3 || !st->fin_sent || !st->req_fin) continue;
        int ws = SSL_get_stream_write_state(st->ssl);
        int rs = SSL_get_stream_read_state(st->ssl);
        if (ws != SSL_STREAM_STATE_FINISHED) continue;
        if (rs != SSL_STREAM_STATE_FINISHED && rs != SSL_STREAM_STATE_RESET_REMOTE &&
            rs != SSL_STREAM_STATE_CONN_CLOSED)
            continue;
        st->closed_by_h3 = 1;
        nghttp3_conn_close_stream(c->h3, st->id, NGHTTP3_H3_NO_ERROR);
    }
}

static void h3_reap(void) {
    for (size_t i = 0; i < h3_nconns; ) {
        h3_conn *c = h3_conns[i];
        for (size_t j = 0; j < H3_MAX_STREAMS; j++)
            if (c->streams[j] && c->streams[j]->dead) {
                h3_stream_free(c->streams[j]);
                c->streams[j] = NULL;
            }
        if (c->dead) {
            for (size_t j = 0; j < H3_MAX_STREAMS; j++)
                if (c->streams[j]) { h3_stream_free(c->streams[j]); c->streams[j] = NULL; }
            nghttp3_conn_del(c->h3);
            if (c->ssl) SSL_free(c->ssl);
            free(c);
            h3_conns[i] = h3_conns[--h3_nconns];
        } else {
            i++;
        }
    }
}

static int h3_alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                      const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl; (void)arg;
    static const unsigned char h3[] = {2, 'h', '3'};
    if (SSL_select_next_proto((unsigned char **)out, outlen, h3, sizeof h3, in, inlen) ==
        OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_NOACK;
}

static void *h3_server_main(void *arg) {
    (void)arg;
    for (;;) {
        SSL_POLL_ITEM items[1 + H3_MAX_CONNS * (1 + H3_MAX_STREAMS)];
        size_t nitems = 0, result_count = 0;
        int bridge_live = 0;
        for (size_t k = 0; k < h3_nconns; k++) {
            h3_conn *ck = h3_conns[k];
            if (!ck || ck->dead) continue;
            for (size_t j = 0; j < H3_MAX_STREAMS; j++)
                if (ck->streams[j] && ck->streams[j]->rfd >= 0) bridge_live = 1;
        }
        /* A worker's socketpair has no SSL to poll, so it is drained on the
         * tick. 10 ms while one is live is invisible; 100 ms when none is keeps
         * an idle gate asleep. */
        struct timeval tv = {.tv_sec = 0, .tv_usec = bridge_live ? 10000 : 100000};

        items[nitems].desc = SSL_as_poll_descriptor(h3_listener);
        items[nitems].events = SSL_POLL_EVENT_IC | SSL_POLL_EVENT_EL;
        nitems++;
        for (size_t i = 0; i < h3_nconns; i++) {
            h3_conn *c = h3_conns[i];
            if (!c || c->dead) continue;
            items[nitems].desc = SSL_as_poll_descriptor(c->ssl);
            items[nitems].events = c->closing ? SSL_POLL_EVENT_ECD
                : (SSL_POLL_EVENT_ISB | SSL_POLL_EVENT_ISU | SSL_POLL_EVENT_EC |
                   SSL_POLL_EVENT_ECD);
            nitems++;
            if (c->closing) continue;
            for (size_t j = 0; j < H3_MAX_STREAMS; j++) {
                h3_stream *st = c->streams[j];
                if (!st || st->dead || !st->ssl) continue;
                items[nitems].desc = SSL_as_poll_descriptor(st->ssl);
                items[nitems].events = SSL_POLL_EVENT_R | SSL_POLL_EVENT_ER |
                                       SSL_POLL_EVENT_W | SSL_POLL_EVENT_EW;
                nitems++;
            }
        }
        if (!SSL_poll(items, nitems, sizeof(SSL_POLL_ITEM), &tv, 0, &result_count))
            break;

        if (items[0].revents & SSL_POLL_EVENT_IC) h3_accept_conns();

        for (size_t i = 0; i < h3_nconns; i++) {
            h3_conn *c = h3_conns[i];
            if (!c || c->dead) continue;
            uint64_t crev = 0;
            for (size_t k = 1; k < nitems; k++)
                if (items[k].desc.value.ssl == c->ssl) { crev = items[k].revents; break; }

            if (crev & (SSL_POLL_EVENT_ISB | SSL_POLL_EVENT_ISU)) h3_accept_streams(c);
            if (crev & SSL_POLL_EVENT_EC) { c->closing = 1; }
            if (crev & SSL_POLL_EVENT_ECD) {
                h3_conn_close(c, "QUIC close complete");
                continue;
            }
            if (c->dead) continue;

            int need_write = 0;
            if (crev & (SSL_POLL_EVENT_R | SSL_POLL_EVENT_W | SSL_POLL_EVENT_ER |
                        SSL_POLL_EVENT_EW))
                need_write = 1;
            for (size_t j = 0; j < H3_MAX_STREAMS; j++) {
                h3_stream *st = c->streams[j];
                if (!st || st->dead || !st->ssl) continue;
                uint64_t rev = 0;
                for (size_t k = 1; k < nitems; k++)
                    if (items[k].desc.value.ssl == st->ssl) { rev = items[k].revents; break; }
                if (rev & SSL_POLL_EVENT_R) { h3_pump_read(st); need_write = 1; }
                if (rev & SSL_POLL_EVENT_W) {
                    if (st->blocked) { st->blocked = 0; nghttp3_conn_unblock_stream(c->h3, st->id); }
                    need_write = 1;
                }
                if (rev & SSL_POLL_EVENT_ER) {
                    uint64_t aec = 0;
                    SSL_get_stream_read_error_code(st->ssl, &aec);
                    nghttp3_conn_close_stream(c->h3, st->id, aec);
                }
                if (rev & SSL_POLL_EVENT_EW) {
                    uint64_t aec = 0;
                    SSL_get_stream_write_error_code(st->ssl, &aec);
                    nghttp3_conn_close_stream(c->h3, st->id, aec);
                }
                if (c->dead) break;
            }
            if (c->dead) continue;
            h3_service_bridges(c, &need_write);
            if (need_write) h3_pump_write(c);
            h3_maybe_close(c);
        }
        h3_reap();
    }
    return NULL;
}

/* Bind the UDP socket and start the QUIC listener thread. Called from main
 * after the TCP listener is up; returns 0 when HTTP/3 is now being served. */
static int h3_start(const struct sockaddr_in6 *addr) {
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (!ctx) return -1;
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_alpn_select_cb(ctx, h3_alpn_cb, NULL);
    if (SSL_CTX_use_certificate_chain_file(ctx, cfg.tls_cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, cfg.tls_key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }
    int fd = socket(addr->sin6_family, SOCK_DGRAM, 0);
    if (fd < 0) { SSL_CTX_free(ctx); return -1; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(fd, (const struct sockaddr *)addr, sizeof *addr) != 0) {
        close(fd);
        SSL_CTX_free(ctx);
        return -1;
    }
    h3_listener = SSL_new_listener(ctx, 0);
    if (!h3_listener || !SSL_set_fd(h3_listener, fd) || !SSL_listen(h3_listener) ||
        !SSL_set_blocking_mode(h3_listener, 0)) {
        if (h3_listener) SSL_free(h3_listener);
        close(fd);
        SSL_CTX_free(ctx);
        return -1;
    }
    h3_ctx = ctx;
    h3_udp_fd = fd;
    h3_port = ntohs(addr->sin6_port);
    pthread_t t;
    if (pthread_create(&t, NULL, h3_server_main, NULL) != 0) {
        SSL_free(h3_listener);
        h3_listener = NULL;
        close(fd);
        SSL_CTX_free(ctx);
        return -1;
    }
    pthread_detach(t);
    return 0;
}


/* --------------------------------------------------- HTTP/3 to the backend
 *
 * A synchronous one-request h3 client, the QUIC twin of proxy_request_h2().
 * It writes the same ordinary HTTP/1.1 response (chunked) into the client
 * connection, so the relay above does not care which protocol the origin
 * spoke. --target-http3 is off by default; h3 to the edge is common, h3 to the
 * origin is not.
 */
#define H3U_MAX_STREAMS 16

typedef struct {
    SSL *ssl;
    int64_t id;
    int is_uni;
    int dead;
    int fin_sent;
    int blocked;
    int got_fin;
} h3u_stream;

typedef struct {
    conn *out;
    request *req;
    SSL *conn;
    nghttp3_conn *h3;
    int64_t req_id;
    h3u_stream streams[H3U_MAX_STREAMS];
    size_t app_bytes;
    int status;
    int head_emitted;
    int no_body;
    int is_head;
    int done;
    int failed;
    char *hdrs;
    size_t hdrs_len, hdrs_cap;
    const unsigned char *body;
    size_t body_len, body_off;
    nghttp3_data_reader dr;
} h3u_ctx;

static h3u_stream *h3u_get(h3u_ctx *u, int64_t id) {
    for (size_t i = 0; i < H3U_MAX_STREAMS; i++)
        if (u->streams[i].ssl && !u->streams[i].dead && u->streams[i].id == id)
            return &u->streams[i];
    return NULL;
}

static h3u_stream *h3u_add(h3u_ctx *u, SSL *ssl, int64_t id, int is_uni) {
    for (size_t i = 0; i < H3U_MAX_STREAMS; i++)
        if (!u->streams[i].ssl) {
            u->streams[i].ssl = ssl;
            u->streams[i].id = id;
            u->streams[i].is_uni = is_uni;
            return &u->streams[i];
        }
    return NULL;
}

static void h3u_write_out(h3u_ctx *u, const void *data, size_t len) {
    if (!u->failed && len && send_all(u->out, data, len) < 0) u->failed = 1;
}

static void h3u_emit_head(h3u_ctx *u) {
    if (u->head_emitted || u->failed) return;
    char head[512];
    int n = snprintf(head, sizeof head, "HTTP/1.1 %d %s\r\n", u->status,
                     reason_for(u->status));
    h3u_write_out(u, head, (size_t)n);
    if (!u->no_body) h3u_write_out(u, "Transfer-Encoding: chunked\r\n", 28);
    h3u_write_out(u, "Connection: close\r\n", 19);
    const char *p = u->hdrs;
    while (p && *p) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        size_t len = (size_t)(eol - p);
        int skip = !u->no_body && len >= 15 && !strncasecmp(p, "content-length:", 15);
        if (!skip) h3u_write_out(u, p, len + 2);
        p = eol + 2;
    }
    h3u_write_out(u, "\r\n", 2);
    u->head_emitted = 1;
}

static nghttp3_ssize h3u_read_body(nghttp3_conn *h3, int64_t sid, nghttp3_vec *vec,
                                   size_t veccnt, uint32_t *pflags, void *cud, void *sud) {
    (void)h3; (void)sid; (void)sud;
    h3u_ctx *u = cud;
    if (veccnt == 0) return NGHTTP3_ERR_WOULDBLOCK;
    size_t left = u->body_len - u->body_off;
    if (left == 0) { *pflags = NGHTTP3_DATA_FLAG_EOF; return 0; }
    size_t take = left < (64u << 10) ? left : (64u << 10);
    vec[0].base = (uint8_t *)u->body + u->body_off;
    vec[0].len = take;
    u->body_off += take;
    if (u->body_off == u->body_len) *pflags = NGHTTP3_DATA_FLAG_EOF;
    return 1;
}

static int h3u_cb_header(nghttp3_conn *h3, int64_t sid, int32_t token,
                         nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                         void *cud, void *sud) {
    (void)h3; (void)token; (void)flags; (void)sud;
    h3u_ctx *u = cud;
    if (sid != u->req_id) return 0;
    nghttp3_vec n = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
    if (n.len && n.base[0] == ':') {
        if (n.len == 7 && !memcmp(n.base, ":status", 7)) {
            char s[8];
            size_t k = v.len < sizeof s - 1 ? v.len : sizeof s - 1;
            memcpy(s, v.base, k);
            s[k] = 0;
            u->status = atoi(s);
        }
        return 0;
    }
    if ((n.len == 10 && !strncasecmp((const char *)n.base, "connection", 10)) ||
        (n.len == 10 && !strncasecmp((const char *)n.base, "keep-alive", 10)) ||
        (n.len == 17 && !strncasecmp((const char *)n.base, "transfer-encoding", 17)) ||
        (n.len == 16 && !strncasecmp((const char *)n.base, "proxy-connection", 16)) ||
        (n.len == 7 && !strncasecmp((const char *)n.base, "upgrade", 7)) ||
        (n.len == 2 && !strncasecmp((const char *)n.base, "te", 2)) ||
        (n.len == 7 && !strncasecmp((const char *)n.base, "trailer", 7)))
        return 0;
    h3u_ctx *c = u;
    if (c->hdrs_len + n.len + v.len + 4 > c->hdrs_cap) {
        size_t want = c->hdrs_cap ? c->hdrs_cap : 1024;
        while (want < c->hdrs_len + n.len + v.len + 5) want *= 2;
        char *nb = realloc(c->hdrs, want);
        if (!nb) { c->failed = 1; return 0; }
        c->hdrs = nb;
        c->hdrs_cap = want;
    }
    memcpy(c->hdrs + c->hdrs_len, n.base, n.len);
    c->hdrs_len += n.len;
    memcpy(c->hdrs + c->hdrs_len, ": ", 2);
    c->hdrs_len += 2;
    memcpy(c->hdrs + c->hdrs_len, v.base, v.len);
    c->hdrs_len += v.len;
    memcpy(c->hdrs + c->hdrs_len, "\r\n", 2);
    c->hdrs_len += 2;
    c->hdrs[c->hdrs_len] = 0;
    return 0;
}

static int h3u_cb_end_headers(nghttp3_conn *h3, int64_t sid, int fin, void *cud, void *sud) {
    (void)h3; (void)fin; (void)sud;
    h3u_ctx *u = cud;
    if (sid != u->req_id) return 0;
    u->is_head = !strcasecmp(u->req->method, "HEAD");
    u->no_body = u->is_head || u->status == 204 || u->status == 304 || u->status < 200;
    h3u_emit_head(u);
    return 0;
}

static int h3u_cb_data(nghttp3_conn *h3, int64_t sid, const uint8_t *data, size_t datalen,
                       void *cud, void *sud) {
    (void)h3; (void)sud;
    h3u_ctx *u = cud;
    u->app_bytes += datalen;
    if (sid != u->req_id || u->no_body || u->failed) return 0;
    char ch[40];
    int n = snprintf(ch, sizeof ch, "%zx\r\n", datalen);
    h3u_write_out(u, ch, (size_t)n);
    h3u_write_out(u, data, datalen);
    h3u_write_out(u, "\r\n", 2);
    return 0;
}

static int h3u_cb_end_stream(nghttp3_conn *h3, int64_t sid, void *cud, void *sud) {
    (void)h3; (void)sud;
    h3u_ctx *u = cud;
    if (sid == u->req_id) u->done = 1;
    return 0;
}

static int h3u_cb_close(nghttp3_conn *h3, int64_t sid, uint64_t aec, void *cud, void *sud) {
    (void)h3; (void)aec; (void)sud;
    h3u_ctx *u = cud;
    h3u_stream *st = h3u_get(u, sid);
    if (st) st->dead = 1;
    if (sid == u->req_id) {
        if (!u->head_emitted) u->failed = 1;
        u->done = 1;
    }
    return 0;
}

static void h3u_pump_read(h3u_ctx *u, h3u_stream *st) {
    if (!u->h3 || !st || st->dead || !st->ssl) return;
    for (int guard = 0; guard < 256; guard++) {
        unsigned char buf[H3_RBUF_SIZE];
        size_t nread = 0;
        if (SSL_get_stream_read_state(st->ssl) == SSL_STREAM_STATE_RESET_REMOTE) {
            uint64_t aec = 0;
            SSL_get_stream_read_error_code(st->ssl, &aec);
            nghttp3_conn_close_stream(u->h3, st->id, aec);
            return;
        }
        if (!SSL_read_ex(st->ssl, buf, sizeof buf, &nread)) {
            int err = SSL_get_error(st->ssl, 0);
            if (err == SSL_ERROR_WANT_READ) return;
            if (err == SSL_ERROR_ZERO_RETURN) {
                if (st->got_fin) return;
                st->got_fin = 1;
                u->app_bytes = 0;
                nghttp3_conn_read_stream(u->h3, st->id, NULL, 0, 1);
                return;
            }
            u->failed = 1;
            return;
        }
        if (nread == 0) return;
        u->app_bytes = 0;
        nghttp3_ssize used = nghttp3_conn_read_stream(u->h3, st->id, buf, nread, 0);
        size_t app = u->app_bytes;
        u->app_bytes = 0;
        if (used < 0) { u->failed = 1; return; }
        if ((size_t)used + app < nread) return;   /* nghttp3 left bytes for later */
        if (st->dead) return;
    }
}

static void h3u_pump_write(h3u_ctx *u) {
    if (!u->h3) return;
    for (int round = 0; round < 512; round++) {
        nghttp3_vec vec[16];
        int64_t sid = -1;
        int fin = 0;
        nghttp3_ssize nv = nghttp3_conn_writev_stream(u->h3, &sid, &fin, vec, 16);
        if (nv < 0) { u->failed = 1; return; }
        if (nv == 0) {
            if (sid >= 0 && fin) {
                h3u_stream *st = h3u_get(u, sid);
                nghttp3_conn_add_write_offset(u->h3, sid, 0);
                if (st && st->ssl && !st->fin_sent) {
                    st->fin_sent = 1;
                    SSL_stream_conclude(st->ssl, 0);
                }
                continue;
            }
            break;
        }
        h3u_stream *st = h3u_get(u, sid);
        size_t total = 0, wanted = 0;
        int stop = 0;
        for (size_t i = 0; i < (size_t)nv; i++) wanted += vec[i].len;
        for (size_t i = 0; i < (size_t)nv; i++) {
            size_t written = 0;
            if (vec[i].len == 0) continue;
            if (!st || !st->ssl) written = vec[i].len;
            else if (!SSL_write_ex2(st->ssl, vec[i].base, vec[i].len, 0, &written)) {
                if (SSL_get_error(st->ssl, 0) == SSL_ERROR_WANT_WRITE) {
                    if (!st->blocked) {
                        nghttp3_conn_block_stream(u->h3, sid);
                        st->blocked = 1;
                    }
                    written = 0;
                    stop = 1;
                } else {
                    u->failed = 1;
                    return;
                }
            } else if (st->blocked) {
                st->blocked = 0;
                nghttp3_conn_unblock_stream(u->h3, sid);
            }
            total += written;
            if (stop || written < vec[i].len) break;
        }
        if (total > 0) {
            nghttp3_conn_add_write_offset(u->h3, sid, total);
            nghttp3_conn_add_ack_offset(u->h3, sid, total);
        }
        if (fin && !stop && total == wanted) {
            if (st && st->ssl && !st->fin_sent) {
                st->fin_sent = 1;
                SSL_stream_conclude(st->ssl, 0);
            }
        }
        if (stop || total < wanted || total == 0) break;
    }
}

static int h3u_poll(h3u_ctx *u, int timeout_ms) {
    SSL_POLL_ITEM items[1 + H3U_MAX_STREAMS];
    struct timeval tv = {.tv_sec = timeout_ms / 1000,
                         .tv_usec = (timeout_ms % 1000) * 1000};
    size_t nitems = 0, result_count = 0;
    items[nitems].desc = SSL_as_poll_descriptor(u->conn);
    items[nitems].events = SSL_POLL_EVENT_ISB | SSL_POLL_EVENT_ISU |
                           SSL_POLL_EVENT_EC | SSL_POLL_EVENT_ECD;
    nitems++;
    for (size_t i = 0; i < H3U_MAX_STREAMS; i++) {
        h3u_stream *st = &u->streams[i];
        if (!st->ssl || st->dead) continue;
        items[nitems].desc = SSL_as_poll_descriptor(st->ssl);
        items[nitems].events = SSL_POLL_EVENT_R | SSL_POLL_EVENT_ER |
                               SSL_POLL_EVENT_W | SSL_POLL_EVENT_EW;
        nitems++;
    }
    if (!SSL_poll(items, nitems, sizeof(SSL_POLL_ITEM), &tv, 0, &result_count))
        return -1;
    if ((items[0].revents & (SSL_POLL_EVENT_ISB | SSL_POLL_EVENT_ISU)) && u->h3) {
        for (;;) {
            SSL *s = SSL_accept_stream(u->conn, SSL_ACCEPT_STREAM_NO_BLOCK);
            if (!s) break;
            int64_t id = (int64_t)SSL_get_stream_id(s);
            h3u_stream *st = h3u_add(u, s, id, SSL_get_stream_type(s) != SSL_STREAM_TYPE_BIDI);
            if (!st) { SSL_free(s); break; }
            h3u_pump_read(u, st);
        }
    }
    if (items[0].revents & SSL_POLL_EVENT_ECD) return -1;
    for (size_t i = 0; i < H3U_MAX_STREAMS; i++) {
        h3u_stream *st = &u->streams[i];
        uint64_t rev = 0;
        if (!st->ssl || st->dead) continue;
        for (size_t k = 1; k < nitems; k++)
            if (items[k].desc.value.ssl == st->ssl) { rev = items[k].revents; break; }
        if (rev & SSL_POLL_EVENT_R) h3u_pump_read(u, st);
        if (rev & SSL_POLL_EVENT_W) {
            if (st->blocked) { st->blocked = 0; nghttp3_conn_unblock_stream(u->h3, st->id); }
        }
        if (rev & (SSL_POLL_EVENT_ER | SSL_POLL_EVENT_EW)) {
            uint64_t aec = 0;
            if (SSL_get_stream_read_state(st->ssl) == SSL_STREAM_STATE_RESET_REMOTE)
                SSL_get_stream_read_error_code(st->ssl, &aec);
            nghttp3_conn_close_stream(u->h3, st->id, aec);
        }
    }
    h3u_pump_write(u);
    return u->failed ? -1 : 0;
}

static int h3u_create_uni(h3u_ctx *u) {
    SSL *ctl = SSL_new_stream(u->conn, SSL_STREAM_FLAG_UNI);
    SSL *enc = SSL_new_stream(u->conn, SSL_STREAM_FLAG_UNI);
    SSL *dec = SSL_new_stream(u->conn, SSL_STREAM_FLAG_UNI);
    if (!ctl || !enc || !dec) return -1;
    if (nghttp3_conn_bind_control_stream(u->h3, (int64_t)SSL_get_stream_id(ctl)) < 0 ||
        nghttp3_conn_bind_qpack_streams(u->h3, (int64_t)SSL_get_stream_id(enc),
                                        (int64_t)SSL_get_stream_id(dec)) < 0)
        return -1;
    if (!h3u_add(u, ctl, (int64_t)SSL_get_stream_id(ctl), 1) ||
        !h3u_add(u, enc, (int64_t)SSL_get_stream_id(enc), 1) ||
        !h3u_add(u, dec, (int64_t)SSL_get_stream_id(dec), 1))
        return -1;
    return 0;
}

/* Returns 1 when it handled the request and 0 when the caller should fall back
 * to HTTP/1.1 (the usual reason: this build cannot connect over QUIC). */
static int proxy_request_h3(conn *c, const request *req, const char *client_ip,
                            const char *path) {
    if (!cfg.target_http3 || !cfg.target_tls) return 0;

    h3u_ctx u;
    memset(&u, 0, sizeof u);
    u.out = c;
    u.req = (request *)req;
    u.status = 0;
    u.body = (const unsigned char *)req->body;
    u.body_len = req->body_len;

    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    BIO *bio = NULL;
    if (!ctx) return 0;
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    if (cfg.target_insecure) SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_default_verify_paths(ctx);
    }
    bio = BIO_new_ssl_connect(ctx);
    if (!bio) { SSL_CTX_free(ctx); return 0; }
    char hostport[320];
    if (strchr(cfg.target_host, ':'))
        snprintf(hostport, sizeof hostport, "[%s]:%d", cfg.target_host, cfg.target_port);
    else
        snprintf(hostport, sizeof hostport, "%s:%d", cfg.target_host, cfg.target_port);
    if (!BIO_set_conn_hostname(bio, hostport) || !BIO_get_ssl(bio, &u.conn)) {
        BIO_free_all(bio); SSL_CTX_free(ctx); return 0;
    }
    BIO_set_nbio(bio, 1);
    SSL_set_blocking_mode(u.conn, 0);
    SSL_set_default_stream_mode(u.conn, SSL_DEFAULT_STREAM_MODE_NONE);
    static const unsigned char alpn_h3[] = {2, 'h', '3'};
    SSL_set_alpn_protos(u.conn, alpn_h3, sizeof alpn_h3);
    SSL_set_tlsext_host_name(u.conn, cfg.target_host);
    ERR_clear_error();
    if (!cfg.target_insecure) {
        X509_VERIFY_PARAM *param = SSL_get0_param(u.conn);
        struct in_addr a4;
        struct in6_addr a6;
        if (param && inet_pton(AF_INET, cfg.target_host, &a4) == 1)
            X509_VERIFY_PARAM_set1_ip_asc(param, cfg.target_host);
        else if (param && inet_pton(AF_INET6, cfg.target_host, &a6) == 1)
            X509_VERIFY_PARAM_set1_ip_asc(param, cfg.target_host);
        else
            SSL_set1_host(u.conn, cfg.target_host);
    }

    /* handshake */
    int ok = 0;
    for (int tries = 0; tries < 600; tries++) {
        int r = SSL_connect(u.conn);
        if (r == 1) { ok = 1; break; }
        int e = SSL_get_error(u.conn, r);
        if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) break;
        if (h3u_poll(&u, 50) < 0) break;
    }
    if (!ok) {
        if (cfg.verbose) logmsg("HTTP/3 handshake to %s failed", cfg.target_host);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }

    nghttp3_callbacks cbs;
    nghttp3_settings settings;
    memset(&cbs, 0, sizeof cbs);
    cbs.recv_header = h3u_cb_header;
    cbs.end_headers = h3u_cb_end_headers;
    cbs.recv_data = h3u_cb_data;
    cbs.end_stream = h3u_cb_end_stream;
    cbs.stream_close = h3u_cb_close;
    nghttp3_settings_default(&settings);
    settings.qpack_max_dtable_capacity = 0;
    settings.qpack_encoder_max_dtable_capacity = 0;
    settings.qpack_blocked_streams = 0;
    if (nghttp3_conn_client_new(&u.h3, &cbs, &settings, NULL, &u) < 0) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }
    if (h3u_create_uni(&u) < 0) {
        nghttp3_conn_del(u.h3);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }

    SSL *rq = SSL_new_stream(u.conn, 0);
    if (!rq) {
        nghttp3_conn_del(u.h3);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }
    h3u_stream *rst = h3u_add(&u, rq, (int64_t)SSL_get_stream_id(rq), 0);
    if (!rst) {
        SSL_free(rq);
        nghttp3_conn_del(u.h3);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }
    u.req_id = rst->id;

    const char *host_hdr = cfg.target_host_hdr && *cfg.target_host_hdr
                               ? cfg.target_host_hdr : cfg.target_host;
    char pathbuf[8192];
    if (req->query[0]) snprintf(pathbuf, sizeof pathbuf, "%s?%s", path, req->query);
    else snprintf(pathbuf, sizeof pathbuf, "%s", path);

    nghttp3_nv nva[96];
    char names[96][96];
    char values[96][1024];
    size_t nv = 0;
#define H3U_NV(N, V) do { \
        snprintf(names[nv], sizeof names[nv], "%s", (N)); \
        snprintf(values[nv], sizeof values[nv], "%s", (V)); \
        nva[nv].name = (uint8_t *)names[nv]; nva[nv].value = (uint8_t *)values[nv]; \
        nva[nv].namelen = strlen(names[nv]); nva[nv].valuelen = strlen(values[nv]); \
        nva[nv].flags = NGHTTP3_NV_FLAG_NONE; nv++; \
    } while (0)
    H3U_NV(":method", req->method);
    H3U_NV(":path", pathbuf);
    H3U_NV(":scheme", "https");
    H3U_NV(":authority", host_hdr);
    const char *p = req->headers;
    while (p && *p && nv < sizeof nva / sizeof nva[0]) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        size_t n = (size_t)(eol - p);
        char line[1200];
        if (n > 0 && n < sizeof line) {
            memcpy(line, p, n);
            line[n] = 0;
            char *colon = strchr(line, ':');
            if (colon && colon > line) {
                *colon = 0;
                char *val = colon + 1;
                while (*val == ' ' || *val == '\t') val++;
                if (strcasecmp(line, "host") && strcasecmp(line, "connection") &&
                    strcasecmp(line, "keep-alive") && strcasecmp(line, "proxy-connection") &&
                    strcasecmp(line, "upgrade") && strcasecmp(line, "te") &&
                    strcasecmp(line, "trailer") && strcasecmp(line, "transfer-encoding") &&
                    strcasecmp(line, "content-length"))
                    H3U_NV(line, val);
            }
        }
        p = eol + 2;
    }
    H3U_NV("x-real-ip", client_ip);
    H3U_NV("x-forwarded-for", client_ip);
    if (req->body_len) {
        char clbuf[32];
        snprintf(clbuf, sizeof clbuf, "%zu", req->body_len);
        H3U_NV("content-length", clbuf);
    }
#undef H3U_NV

    memset(&u.dr, 0, sizeof u.dr);
    u.dr.read_data = h3u_read_body;
    if (nghttp3_conn_submit_request(u.h3, u.req_id, nva, nv,
                                    req->body_len ? &u.dr : NULL, NULL) < 0) {
        nghttp3_conn_del(u.h3);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }

    for (int guard = 0; guard < 12000 && !u.done && !u.failed; guard++)
        if (h3u_poll(&u, 10) < 0) break;
    if (u.done && u.head_emitted && !u.no_body && !u.failed)
        h3u_write_out(&u, "0\r\n\r\n", 5);

    /* free streams before the connection */
    for (size_t i = 0; i < H3U_MAX_STREAMS; i++)
        if (u.streams[i].ssl) SSL_free(u.streams[i].ssl);
    nghttp3_conn_del(u.h3);
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    free(u.hdrs);
    if (!u.head_emitted) {
        const char *msg = "betterAnusbis: the HTTP/3 target closed without answering\n";
        respond(c, 502, "Bad Gateway", NULL, NULL, msg, strlen(msg));
    }
    return 1;
}

#endif /* HAVE_NGHTTP3 */

/* ------------------------------------------------------------- main loop */

typedef struct {
    int fd;
    int tls;
} accepted;

/* ALPN on the TLS listener. h2 first, HTTP/1.1 second: that ordering is what
 * tells every browser and curl that this gate can multiplex. When --no-http2 is
 * given the list still offers http/1.1 so clients that require ALPN work. */
static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl; (void)arg;
#ifdef HAVE_NGHTTP2
    static const unsigned char protos[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    if (cfg.http2 &&
        SSL_select_next_proto((unsigned char **)out, outlen, protos, sizeof protos, in, inlen) ==
            OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
#endif
    static const unsigned char h1[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    if (SSL_select_next_proto((unsigned char **)out, outlen, h1, sizeof h1, in, inlen) ==
        OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_NOACK;
}

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
        else if (peer.ss_family == AF_UNIX)
            /* a unix socket only ever has same-host peers, and loopback is the
             * truth here; it also makes X-Forwarded-For from that proxy trusted,
             * which is what the deployment wants */
            snprintf(ip, sizeof ip, "127.0.0.1");
    }
    int use_h2 = 0;
#ifdef HAVE_NGHTTP2
    if (cfg.http2) {
        if (c.ssl) {
            const unsigned char *proto = NULL;
            unsigned int plen2 = 0;
            SSL_get0_alpn_selected((SSL *)c.ssl, &proto, &plen2);
            use_h2 = plen2 == 2 && proto && !memcmp(proto, "h2", 2);
        } else {
            use_h2 = h2_is_prior_knowledge(fd);
        }
    }
    if (use_h2) {
        h2_serve(&c, ip);
        if (c.ssl) {
            SSL_shutdown((SSL *)c.ssl);
            SSL_free((SSL *)c.ssl);
        }
        return NULL;
    }
#endif
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

/* Both listeners can be a unix socket, which is how nginx and Traefik prefer to
 * talk to a gate on the same host: no port, no firewall question, and a socket
 * a non-root process can own. A stale socket file from a crashed run is removed
 * first, because bind() will not reuse it. */
static int make_listener(const char *spec, const char *network, const char *mode,
                         int *is_unix) {
    *is_unix = 0;
    if (network && !strcasecmp(network, "unix")) {
        struct sockaddr_un un;
        memset(&un, 0, sizeof un);
        un.sun_family = AF_UNIX;
        if (strlen(spec) >= sizeof un.sun_path) {
            fprintf(stderr, "betterAnusbis: the socket path %s is too long\n", spec);
            return -1;
        }
        snprintf(un.sun_path, sizeof un.sun_path, "%s", spec);
        unlink(spec);
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            perror("socket");
            return -1;
        }
        if (bind(fd, (struct sockaddr *)&un, sizeof un) != 0) {
            fprintf(stderr, "betterAnusbis: cannot bind %s: %s\n", spec, strerror(errno));
            close(fd);
            return -1;
        }
        mode_t m = (mode_t)strtol(mode ? mode : "0770", NULL, 8);
        chmod(spec, m);
        if (listen(fd, 128) != 0) {
            perror("listen");
            close(fd);
            return -1;
        }
        *is_unix = 1;
        return fd;
    }

    struct sockaddr_in6 addr;
    if (parse_listen(spec, &addr) != 0) {
        fprintf(stderr, "betterAnusbis: --listen wants ADDR:PORT\n");
        return -1;
    }
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &(int){0}, sizeof(int));
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        fprintf(stderr, "betterAnusbis: cannot bind %s: %s\n", spec, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 128) != 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
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
        "betterAnusbis " VERSION " \"" CODENAME "\" - an Anubis-compatible proof-of-work gate,\n"
        "in one C file\n"
        "\n"
        "usage: betterAnusbis --target http://127.0.0.1:3000 [options]\n"
        "\n"
        "where to listen, what to protect\n"
        "  --listen ADDR:PORT     where to listen; omit the address for every\n"
        "                         interface (default :8080). With\n"
        "                         --bind-network unix this is a socket path\n"
        "  --bind-network NAME    tcp (default) or unix\n"
        "  --socket-mode OCTAL    permissions for a unix socket (default 0770)\n"
        "  --metrics-bind-network NAME  tcp (default) or unix, for the metrics listener\n"
        "  --target URL           the backend to protect. Leave it empty for\n"
        "                         forwardAuth mode, where this only answers\n"
        "                         /api/check and the challenge\n"
        "  --public-url URL       where this gate is reachable, used to build the\n"
        "                         forwardAuth redirect\n"
        "  --store file:PATH|bbolt:PATH|valkey:URL|s3api:BUCKET\n"
        "                         keep the challenge ledger and the honeypot counters\n"
        "                         here: a snapshot text file, an Anubis-style bbolt DB\n"
        "                         (single writer), Valkey/Redis (redis://, rediss://,\n"
        "                         unix:///path?db=N), or S3 (AWS_REGION,\n"
        "                         AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,\n"
        "                         AWS_ENDPOINT_URL_S3, AWS_S3_PATH_STYLE=1)\n"
        "  --challenge-extension NAME\n"
        "                         css-load: the page's stylesheet must be fetched\n"
        "                         before pass-challenge is accepted\n"
        "  --og-passthrough       copy the protected page's og: tags onto the\n"
        "                         challenge page, cached for --og-expiry-time\n"
        "  --og-expiry-time SECS  how long those tags are cached (default 86400)\n"
        "  --og-override LIST     key=value pairs separated by ; to use instead of\n"
        "                         fetching anything\n"
        "  --geoip-country PATH   MaxMind country database, for geoip: rule matching\n"
        "  --geoip-asn PATH       MaxMind ASN database, for asns: rule matching\n"
        "  --dnsbl                check every client address against DroneBL, cached\n"
        "                         for a day; a lookup failure answers 503\n"
        "  --target-sni NAME      TLS name to send to the target; \"auto\" reuses the\n"
        "                         Host header (default: the host we dialled)\n"
        "  --target-host NAME     Host header to send to the target\n"
        "  --target-insecure      do not verify the backend certificate (testing only)\n"
        "  --base-prefix PATH     serve under this path, e.g. /anubis\n"
        "  --strip-base-prefix    strip it again before the target sees the request\n"
        "\n"
        "the challenge\n"
        "  --algorithm NAME       fast, slow, sha256, argon2id, hashx, meatrider, tensor,\n"
        "                         tensor-v, metarefresh or preact\n"
        "                         (default sha256)\n"
        "  --meatrider-usd USD    pick the meatrider rung by its price instead of by\n"
        "                         bits, e.g. 1e-10 for the atom-of-a-cent rung; sets\n"
        "                         --algorithm meatrider\n"
        "  --meatrider-ladder     print the meatrider rungs and exit\n"
        "  --meatrider-escalate   networks caught by the honeypot get a meatrider\n"
        "                         rung instead of difficulty+8: one wall up the\n"
        "                         browser ladder per doubling of the hit count\n"
        "  --meatrider-pay ADDR   publish a bitcoin: link for the ASIC rungs and\n"
        "                         accept an operator-issued receipt as the response\n"
        "  --meatrider-btc-usd N  USD per BTC for that amount (default 100000)\n"
        "  --meatrider-receipt ID mint the receipt for one challenge id and exit\n"
        "                         (needs --secret-hex or --secret-file)\n"
        "  --difficulty N         difficulty; bits for sha256/argon2id/hashx/meatrider,\n"
        "                         nibbles for fast/slow, and the matrix size for\n"
        "                         tensor: N = 64*clamp(N,2,16), so 8 is 512x512\n"
        "                         (default 4)\n"
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
        "  --http2[=B]            HTTP/2 on the listener: ALPN h2 over TLS, and\n"
        "                         h2c prior knowledge on a plain listener (default on)\n"
        "  --http3[=B]            HTTP/3 over QUIC on the same port; needs --tls-cert\n"
        "                         and --tls-key, and advertises Alt-Svc (default off)\n"
        "  --target-http2[=B]     use HTTP/2 to the backend when its TLS offers h2\n"
        "                         (default on; HTTP/1.1 is used when it does not)\n"
        "  --target-http3[=B]     use HTTP/3 over QUIC to the backend (default off)\n"
        "  --hs512-secret KEY     sign tokens with HS512 and this key\n"
        "  --ed25519-private-key-hex HEX\n"
        "                         sign tokens with EdDSA (32 or 64 bytes of hex)\n"
        "  --ed25519-private-key-hex-file FILE  the same, read from a file\n"
        "  --slog-level LEVEL     DEBUG, INFO (default), WARN or ERROR\n"
        "  --difficulty-in-jwt    add the difficulty claim to the token\n"
        "  --dynamic-cookie-suffix[=B]\n"
        "                         hash the cookie settings into the cookie name,\n"
        "                         so stale cookies under old settings are ignored\n"
        "                         (default on, as Anubis ships it)\n"
        "  --webmaster-email ADDR printed on a deny page, for appeals\n"
        "  --preserve-referer-query-param\n"
        "                         add utm_source/utm_medium from an external Referer\n"
        "  --target-disable-keepalive\n"
        "                         send Connection: close to the target instead of\n"
        "                         reusing a pooled connection\n"
        "  --secret-file PATH     keep the signing key here, creating it 0600 if it\n"
        "                         is missing; without this the key is random per run\n"
        "                         and every restart logs everyone out\n"
        "  --secret-hex HEX       the same key, given inline (64 hex characters)\n"
        "  --jwt-restriction-header NAME\n"
        "                         bind the auth cookie to the client address, the way\n"
        "                         Anubis does by default; pass \"\" to turn it off\n"
        "  --flag-threshold N     honeypot hits in the hour before a network is\n"
        "                         flagged (default 25)\n"
        "  --healthcheck          GET /healthz on --metrics-bind and exit 0 or 1\n"
        "  --metrics-bind ADDR:PORT\n"
        "                         Prometheus /metrics and /healthz on a listener of\n"
        "                         their own (default: off. Anubis binds :9090 for\n"
        "                         you, which hands your traffic numbers to anyone)\n"
        "  -v, --verbose          log every request\n"
        "  -h, --help             this text\n"
        "  -V, --version          version\n"
        "\n"
        "send SIGHUP to print the current settings.\n"
        "\n"
        "every flag is also an environment variable: --cookie-same-site is\n"
        "COOKIE_SAME_SITE, and a flag on the command line wins.\n");
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
    {"meatrider-usd", ARG_STR, &cfg.meatrider_usd},
    {"meatrider-ladder", ARG_BOOL, &cfg.meatrider_ladder},
    {"meatrider-escalate", ARG_BOOL, &cfg.meatrider_escalate},
    {"meatrider-pay", ARG_STR, &cfg.meatrider_pay},
    {"meatrider-btc-usd", ARG_STR, &cfg.meatrider_btc_usd},
    {"meatrider-receipt", ARG_STR, &cfg.meatrider_receipt},
    {"flag-threshold", ARG_INT, &cfg.flag_threshold},
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
    {"healthcheck", ARG_BOOL, &cfg.healthcheck},
    {"bind-network", ARG_STR, &cfg.bind_network},
    {"socket-mode", ARG_STR, &cfg.socket_mode},
    {"metrics-bind-network", ARG_STR, &cfg.metrics_network},
    {"public-url", ARG_STR, &cfg.public_url},
    {"dnsbl", ARG_BOOL, &cfg.dnsbl},
    {"bind", ARG_STR, &cfg.listen},                          /* upstream's name */
    {"policy-fname", ARG_STR, &cfg.policy_file},              /* upstream's name */
    {"target-insecure-skip-verify", ARG_BOOL, &cfg.target_insecure},
    {"geoip-lookup", ARG_STR, &cfg.geoip_lookup},
    {"challenge-extension", ARG_STR, &cfg.challenge_extension},
    {"store", ARG_STR, &cfg.store},
    {"og-passthrough", ARG_BOOL, &cfg.og_passthrough},
    {"og-expiry-time", ARG_LONG, &cfg.og_ttl},
    {"og-cache-consider-host", ARG_BOOL, &cfg.og_consider_host},
    {"og-override", ARG_STR, &cfg.og_override},
    {"geoip-country", ARG_STR, &cfg.geoip_country_path},
    {"geoip-asn", ARG_STR, &cfg.geoip_asn_path},
    {"forced-language", ARG_STR, &cfg.forced_language},
    {"impressum-footer", ARG_STR, &cfg.impressum_footer},
    {"impressum-page-title", ARG_STR, &cfg.impressum_title},
    {"impressum-page-body", ARG_STR, &cfg.impressum_body},
    {"hs512-secret", ARG_STR, &cfg.hs512_secret},
    {"ed25519-private-key-hex", ARG_STR, &cfg.ed25519_hex},
    {"ed25519-private-key-hex-file", ARG_STR, &cfg.ed25519_file},
    {"slog-level", ARG_STR, &cfg.log_level},
    {"difficulty-in-jwt", ARG_BOOL, &cfg.difficulty_in_jwt},
    {"dynamic-cookie-suffix", ARG_BOOL, &cfg.dynamic_cookie_suffix},
    {"webmaster-email", ARG_STR, &cfg.webmaster_email},
    {"preserve-referer-query-param", ARG_BOOL, &cfg.preserve_referer_qp},
    {"target-disable-keepalive", ARG_BOOL, &cfg.target_disable_keepalive},
    {"http2", ARG_BOOL, &cfg.http2},
    {"http3", ARG_BOOL, &cfg.http3},
    {"target-http2", ARG_BOOL, &cfg.target_http2},
    {"target-http3", ARG_BOOL, &cfg.target_http3},
};

static int arg_apply(const arg_spec *spec, const char *val, int negated) {
    switch (spec->kind) {
    case ARG_STR:
        if (!val) return -1;
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
                fprintf(stderr, "betterAnusbis: --%s wants true or false, got %s\n",
                        spec->name, val);
                return -1;
            }
        }
        if (negated) b = !b;
        *(int *)spec->dst = b;
        break;
    }
    }
    return 0;
}

/* Every flag is also an environment variable, upper case with dashes as
 * underscores, exactly the mapping upstream's flagenv gives it. A flag on the
 * command line wins over the environment, which is what lets docker-compose
 * carry a whole deployment in `environment:` while still being debuggable on
 * the command line. */
static void apply_environment(char *const seen, size_t nseen) {
    for (size_t k = 0; k < nseen; k++) {
        if (seen[k]) continue;
        char name[96];
        size_t o = 0;
        for (const char *q = args[k].name; *q && o + 1 < sizeof name; q++)
            name[o++] = (*q == '-') ? '_' : (char)toupper((unsigned char)*q);
        name[o] = 0;
        const char *v = getenv(name);
        if (!v || !*v) continue;
        arg_apply(&args[k], args[k].kind == ARG_BOOL && !*v ? NULL : v, 0);
    }
}

static int parse_args(int argc, char **argv) {
    char seen[sizeof args / sizeof args[0]] = {0};
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout); exit(0); }
        if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s \"%s\"\n", VERSION, CODENAME);
            exit(0);
        }
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
        if (arg_apply(spec, val, negated) != 0) return -1;
        seen[spec - args] = 1;
    }
    apply_environment(seen, sizeof seen / sizeof seen[0]);
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
        fprintf(stderr, "betterAnusbis: cannot read the system random source\n");
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

/* --healthcheck: GET /healthz on the metrics listener and exit 0 or 1. It has
 * to be a separate process because that is how a supervisor asks "are you
 * alive" without knowing anything about this program. */
static int do_healthcheck(const char *addr) {
    struct sockaddr_in6 sa;
    if (parse_listen(addr, &sa) != 0) {
        fprintf(stderr, "betterAnusbis: --healthcheck wants ADDR:PORT\n");
        return 2;
    }
    if (IN6_IS_ADDR_UNSPECIFIED(&sa.sin6_addr)) sa.sin6_addr = in6addr_loopback;
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        fprintf(stderr, "betterAnusbis: healthcheck cannot reach %s: %s\n", addr, strerror(errno));
        close(fd);
        return 1;
    }
    const char *req = "GET /healthz HTTP/1.1\r\nHost: healthcheck\r\nConnection: close\r\n\r\n";
    if (write(fd, req, strlen(req)) < 0) { close(fd); return 1; }
    char buf[256];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 1;
    buf[n] = 0;
    const char *sp = strchr(buf, ' ');
    int status = sp ? atoi(sp + 1) : 0;
    return status == 200 ? 0 : 1;
}

/* Anubis hashes the cookie settings into the cookie name, so a browser cannot
 * keep presenting a cookie that was minted under different settings
 * (lib/http.go:118-127). Same seven fields, same 4-byte digest, same 8 hex. */
static void build_cookie_names(void) {
    const char *ss = cfg.cookie_same_site && *cfg.cookie_same_site ? cfg.cookie_same_site : "lax";
    int ss_mode = !strcasecmp(ss, "default") ? 0 : !strcasecmp(ss, "lax") ? 1
                : !strcasecmp(ss, "strict") ? 2 : 3;
    char material[512];
    snprintf(material, sizeof material, "%d|%d|%d|%d|%s|%d|%s",
             cfg.cookie_http_only, cookie_use_secure(), cfg.cookie_partitioned, ss_mode,
             cfg.cookie_domain ? cfg.cookie_domain : "", 0,
             cfg.base_prefix ? cfg.base_prefix : "");
    char suffix[16] = "";
    if (cfg.dynamic_cookie_suffix) {
        uint8_t digest[32];
        char hex[16];
        if (sha256_raw((const uint8_t *)material, strlen(material), digest) == 0) {
            hex_encode(digest, 4, hex);
            snprintf(suffix, sizeof suffix, "-%s", hex);
        }
    }
    snprintf(cfg.cookie_name, sizeof cfg.cookie_name, "%s-auth%s", cfg.cookie_prefix, suffix);
    snprintf(cfg.verify_name, sizeof cfg.verify_name, "%s-cookie-verification%s",
             cfg.cookie_prefix, suffix);
}

/* --ed25519-private-key-hex(-file): 32 or 64 bytes of hex. Go stores the seed
 * followed by the public half, so the first 32 bytes are what OpenSSL wants. */
static int setup_ed25519(void) {
    char hex[512] = "";
    if (cfg.ed25519_file && *cfg.ed25519_file) {
        FILE *f = fopen(cfg.ed25519_file, "r");
        if (!f) {
            fprintf(stderr, "betterAnusbis: cannot read %s: %s\n", cfg.ed25519_file,
                    strerror(errno));
            return -1;
        }
        size_t n = fread(hex, 1, sizeof hex - 1, f);
        fclose(f);
        hex[n] = 0;
        char *p = hex;
        while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;
        size_t len = strlen(p);
        while (len && (p[len - 1] == ' ' || p[len - 1] == '\n' || p[len - 1] == '\r' ||
                       p[len - 1] == '\t'))
            p[--len] = 0;
        memmove(hex, p, len + 1);
    } else if (cfg.ed25519_hex && *cfg.ed25519_hex) {
        snprintf(hex, sizeof hex, "%s", cfg.ed25519_hex);
    } else {
        return 0;
    }
    uint8_t key[64];
    int n = hex_decode(hex, key, sizeof key);
    if (n != 32 && n != 64) {
        fprintf(stderr, "betterAnusbis: the Ed25519 key must be 32 or 64 bytes of hex, "
                        "32 or 128 hex characters; got %d\n", n);
        return -1;
    }
    cfg.jwt_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, key, 32);
    if (!cfg.jwt_pkey) {
        fprintf(stderr, "betterAnusbis: cannot load the Ed25519 key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    cfg.jwt_alg = 2;
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
    logmsg("settings: listen=%s (%s) target=%s algorithm=%s difficulty=%d",
           cfg.listen, cfg.bind_network, cfg.target, cfg.algorithm, cfg.difficulty);
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
    logmsg("settings: signing scheme=%s",
           cfg.jwt_alg == 1 ? "HS512" : cfg.jwt_alg == 2 ? "EdDSA" : "HS256");
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

static void human_seconds(double s, char *out, size_t cap) {
    if (!(s > 0.0)) { snprintf(out, cap, "0"); return; }
    if (s < 1e-6) snprintf(out, cap, "%.0f ns", s * 1e9);
    else if (s < 1e-3) snprintf(out, cap, "%.0f us", s * 1e6);
    else if (s < 1.0) snprintf(out, cap, "%.0f ms", s * 1e3);
    else if (s < 90.0) snprintf(out, cap, "%.0f s", s);
    else if (s < 5400.0) snprintf(out, cap, "%.0f min", s / 60.0);
    else if (s < 172800.0) snprintf(out, cap, "%.1f h", s / 3600.0);
    else if (s < 3.156e7) snprintf(out, cap, "%.0f days", s / 86400.0);
    else if (s / 3.156e7 < 1e6) snprintf(out, cap, "%.0f years", s / 3.156e7);
    else snprintf(out, cap, "%.1e years", s / 3.156e7);
}

/* The ladder, generated from the library's own price function rather than a
 * second table: a rung is printed where the price crosses into a new name, so
 * the two cannot drift. */
static void print_meatrider_ladder(FILE *out) {
    char asic[32], browser[32];
    const char *prev = NULL;
    int d;

    fprintf(out,
            "meatrider rungs. The money is what an Antminer S21 Pro earns doing\n"
            "2^difficulty hashes at $%.2f per TH-day; the times are that same work\n"
            "on one S21 Pro (234 TH/s) and on a browser at 1,000,000 H/s (this\n"
            "repo's wasm kernel, measured in node; the pure-JS fallback is ~10x slower).\n\n"
            "%-16s %4s %13s %12s %12s %16s\n",
            0.05, /* the library's default: MEATRIDER_DEFAULT_USD_PER_TH_DAY */
            "rung", "bits", "expected", "of bitcoin",
            "S21 Pro", "browser");

    for (d = 1; d <= 255; d++) {
        const char *name = anubis_meatrider_tier(d);
        double hashes = 1.0;
        int i;
        if (!name) continue;
        /* the ladder starts at a femtocent (1e-15 USD); below it the name
         * function clamps to the first rung, which would print a fake row */
        if (anubis_meatrider_price_usd(d, 0.0) < 1e-15) continue;
        if (prev && !strcmp(prev, name)) continue;
        for (i = 0; i < d; i++) hashes *= 2.0;
        human_seconds(anubis_meatrider_asic_seconds(d, 0.0), asic, sizeof asic);
        human_seconds(hashes / 1e6, browser, sizeof browser);
        fprintf(out, "%-16s %4d %13.1e %12.2e %12s %16s\n", name, d, hashes,
                anubis_meatrider_price_usd(d, 0.0), asic, browser);
        prev = name;
    }
    fprintf(out,
            "\nThe last rung is the joke with a straight face: $1 of bitcoin is about\n"
            "2.7 hours of an S21 Pro and 73 thousand years of one browser tab.\n"
            "No money changes hands: the tier prices work, it does not take payment.\n");
}

int main(int argc, char **argv) {
#if defined(_WIN32)
    ba_wsa_init();
#endif
    if (parse_args(argc, argv) != 0) return 2;

    if (cfg.meatrider_ladder) {
        print_meatrider_ladder(stdout);
        return 0;
    }
    cfg.btc_usd = OPT(cfg.meatrider_btc_usd) ? atof(cfg.meatrider_btc_usd) : 100000.0;
    if (!(cfg.btc_usd > 0.0)) {
        fprintf(stderr, "betterAnusbis: --meatrider-btc-usd wants a positive price\n");
        return 2;
    }
    if (OPT(cfg.meatrider_pay) && !cfg.stateful)
        logmsg("meatrider: --meatrider-pay needs the challenge ledger; "
               "receipts are refused on a stateless gate");
    if (cfg.meatrider_escalate && !cfg.stateful)
        logmsg("meatrider: --meatrider-escalate needs the challenge ledger; "
               "a stateless gate will only raise the difficulty by 8");
    if (OPT(cfg.meatrider_usd)) {
        double usd = atof(cfg.meatrider_usd);
        if (!(usd > 0.0)) {
            fprintf(stderr, "betterAnusbis: --meatrider-usd wants a positive amount\n");
            return 2;
        }
        cfg.algorithm = "meatrider";
        cfg.difficulty = anubis_meatrider_difficulty_for_usd(usd, 0.0);
        logmsg("meatrider: asking for $%.2e, so difficulty %d (%s)", usd,
               cfg.difficulty, anubis_meatrider_tier(cfg.difficulty));
    }

    if (cfg.healthcheck) {
        const char *addr = cfg.metrics_bind && *cfg.metrics_bind ? cfg.metrics_bind
                                                                 : "127.0.0.1:9090";
        int rc = do_healthcheck(addr);
        fprintf(stderr, "betterAnusbis: healthcheck %s %s\n", addr, rc == 0 ? "ok" : "failed");
        return rc;
    }

    if (OPT(cfg.meatrider_receipt)) {
        /* A receipt must come out of the same key the gate verifies with, and
         * this is a second process, so a random per-run key cannot work. */
        char receipt[65];
        if (OPT(cfg.secret_hex)) {
            if (hex_decode(cfg.secret_hex, cfg.secret, sizeof cfg.secret) != (int)sizeof cfg.secret) {
                fprintf(stderr, "betterAnusbis: --secret-hex wants exactly 64 hex characters\n");
                return 2;
            }
        } else if (OPT(cfg.secret_file)) {
            if (load_secret(cfg.secret_file, cfg.secret) != 0) return 1;
        } else {
            fprintf(stderr, "betterAnusbis: --meatrider-receipt needs --secret-hex "
                            "or --secret-file, so the gate and this command agree\n");
            return 2;
        }
        mr_receipt(cfg.meatrider_receipt, receipt);
        printf("%s\n", receipt);
        return 0;
    }

    if (!cfg.target || !*cfg.target) {
        /* Anubis switches to forwardAuth mode when TARGET is empty
         * (cmd/anubis/main.go:292,309): there is nothing to proxy to, so the
         * gate only answers auth checks. */
        cfg.subrequest = 1;
        cfg.target = "";
        logmsg("no target: forwardAuth mode, answering /api/check and the challenge only");
    }
    {
        int md = !strcmp(cfg.algorithm, "meatrider") ? 255 : 64;
        if (cfg.difficulty < 0 || cfg.difficulty > md) {
            fprintf(stderr, "betterAnusbis: --difficulty must be 0..%d for %s\n",
                    md, cfg.algorithm);
            return 2;
        }
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
    if (!strcasecmp(cfg.log_level, "DEBUG")) {
        cfg.verbose = 1;
    } else if (!strcasecmp(cfg.log_level, "WARN") || !strcasecmp(cfg.log_level, "WARNING") ||
               !strcasecmp(cfg.log_level, "ERROR")) {
        log_quiet = 1;
    } else if (strcasecmp(cfg.log_level, "INFO")) {
        fprintf(stderr, "betterAnusbis: --slog-level wants DEBUG, INFO, WARN or ERROR\n");
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

    if (cfg.geoip_lookup && *cfg.geoip_lookup) {
        char cc[8] = "";
        uint32_t asn = 0;
        int have_c = geoip_country(cfg.geoip_lookup, cc, sizeof cc);
        int have_a = geoip_asn(cfg.geoip_lookup, &asn);
        printf("%s: country %s%s%s\n", cfg.geoip_lookup, have_c ? cc : "(not found)",
               have_a ? ", ASN " : "", have_a ? "" : "");
        if (have_a) printf("%s: ASN %u\n", cfg.geoip_lookup, asn);
        return 0;
    }

    if (cfg.challenge_extension && *cfg.challenge_extension) {
        if (!strcasecmp(cfg.challenge_extension, "css-load")) {
            if (!cfg.stateful) {
                fprintf(stderr, "betterAnusbis: --challenge-extension css-load needs the "
                                "challenge ledger; it cannot work with --stateless\n");
                return 2;
            }
            cfg.ext_css_load = 1;
        } else if (!strcasecmp(cfg.challenge_extension, "headless")) {
            logmsg("--challenge-extension headless: this tree has no implementation of it "
                   "(it exists only in the enterprise build), so nothing is checked");
        } else {
            fprintf(stderr, "betterAnusbis: --challenge-extension wants css-load or "
                            "headless\n");
            return 2;
        }
    }

    if (geoip_open_databases() != 0) {
        fprintf(stderr, "betterAnusbis: the GeoIP database did not load\n");
        return 1;
    }

    if (cfg.policy_file) policy_load(cfg.policy_file);
    else policy_digest_finish();

    if (cfg.store && *cfg.store) {
        if (!strncmp(cfg.store, "file:", 5)) {
            snprintf(store_path, sizeof store_path, "%s", cfg.store + 5);
            if (!store_path[0]) {
                fprintf(stderr, "betterAnusbis: --store file: wants a path\n");
                return 2;
            }
            if (store_load() != 0) return 1;
            struct sigaction sd = {0};
            sd.sa_handler = on_shutdown;
            sigemptyset(&sd.sa_mask);
            sigaction(SIGTERM, &sd, NULL);
            sigaction(SIGINT, &sd, NULL);
            if (pthread_create(&store_thread_id, NULL, store_thread, NULL) == 0)
                pthread_detach(store_thread_id);
            logmsg("store: %s, snapshotted every five seconds", store_path);
        } else if (!strncmp(cfg.store, "bbolt:", 6)) {
            snprintf(store_path, sizeof store_path, "%s", cfg.store + 6);
            if (!store_path[0]) {
                fprintf(stderr, "betterAnusbis: --store bbolt: wants a path\n");
                return 2;
            }
            store_bbolt = 1;
            if (store_load() != 0) return 1;
            struct sigaction sd = {0};
            sd.sa_handler = on_shutdown;
            sigemptyset(&sd.sa_mask);
            sigaction(SIGTERM, &sd, NULL);
            sigaction(SIGINT, &sd, NULL);
            if (pthread_create(&store_thread_id, NULL, store_thread, NULL) == 0)
                pthread_detach(store_thread_id);
            logmsg("store: bbolt %s, flushed every five seconds (single writer)",
                   store_path);
        } else if (!strncmp(cfg.store, "valkey:", 7)) {
            snprintf(store_path, sizeof store_path, "%s", cfg.store + 7);
            if (!store_path[0]) {
                fprintf(stderr, "betterAnusbis: --store valkey: wants a URL, e.g. "
                                "redis://127.0.0.1:6379/0\n");
                return 2;
            }
            store_valkey = 1;
            if (store_load() != 0) return 1;
        } else if (!strncmp(cfg.store, "s3api:", 6)) {
            snprintf(store_path, sizeof store_path, "%s", cfg.store + 6);
            if (!store_path[0]) {
                fprintf(stderr, "betterAnusbis: --store s3api: wants a bucket name\n");
                return 2;
            }
            store_s3 = 1;
            if (store_load() != 0) return 1;
        } else if (!strcmp(cfg.store, "memory") || !strcmp(cfg.store, "none")) {
            logmsg("store: memory only, as before");
        } else {
            fprintf(stderr, "betterAnusbis: --store wants file:PATH, bbolt:PATH, "
                            "valkey:URL, s3api:BUCKET or memory\n");
            return 2;
        }
    }

    if (cfg.subrequest) {
        snprintf(cfg.target_host, sizeof cfg.target_host, "%s", "unix");
        cfg.target_port = 0;
        cfg.target_tls = 0;
    } else {
        parse_target(cfg.target);
    }
    build_cookie_names();
    if (cfg.hs512_secret && *cfg.hs512_secret) {
        cfg.jwt_alg = 1;
        logmsg("signing tokens with HS512 (--hs512-secret)");
    } else if ((cfg.ed25519_hex && *cfg.ed25519_hex) ||
               (cfg.ed25519_file && *cfg.ed25519_file)) {
        if (setup_ed25519() != 0) return 1;
        logmsg("signing tokens with EdDSA, Ed25519");
    } else if (cfg.secret_hex && *cfg.secret_hex) {
        if (hex_decode(cfg.secret_hex, cfg.secret, sizeof cfg.secret) != (int)sizeof cfg.secret) {
            fprintf(stderr, "betterAnusbis: --secret-hex wants exactly 64 hex characters\n");
            return 2;
        }
    } else if (cfg.secret_file && *cfg.secret_file) {
        if (load_secret(cfg.secret_file, cfg.secret) != 0) return 1;
    } else if (random_bytes(cfg.secret, sizeof cfg.secret) != 0) {
        fprintf(stderr, "betterAnusbis: cannot read the system random source\n");
        return 1;
    }


    signal(SIGPIPE, SIG_IGN);
    /* no SA_RESTART: accept() has to come back so the dump can happen */
    struct sigaction hup = {0};
    hup.sa_handler = on_reload;
    sigemptyset(&hup.sa_mask);
    sigaction(SIGHUP, &hup, NULL);

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof addr);
    if (strcasecmp(cfg.bind_network, "unix") && parse_listen(cfg.listen, &addr) != 0) {
        fprintf(stderr, "betterAnusbis: --listen wants ADDR:PORT (or a socket path "
                        "with --bind-network unix)\n");
        return 2;
    }
    if (strcasecmp(cfg.bind_network, "tcp") && strcasecmp(cfg.bind_network, "unix")) {
        fprintf(stderr, "betterAnusbis: --bind-network wants tcp or unix\n");
        return 2;
    }
    if (cfg.http3 && strcasecmp(cfg.bind_network, "unix")) {
        /* fine: UDP can share the port number with the TCP listener */
    } else if (cfg.http3) {
        fprintf(stderr, "betterAnusbis: --http3 needs --bind-network tcp\n");
        return 2;
    }
    if (strcasecmp(cfg.metrics_network, "tcp") && strcasecmp(cfg.metrics_network, "unix")) {
        fprintf(stderr, "betterAnusbis: --metrics-bind-network wants tcp or unix\n");
        return 2;
    }
    if ((cfg.tls_cert && !cfg.tls_key) || (!cfg.tls_cert && cfg.tls_key)) {
        fprintf(stderr, "betterAnusbis: --tls-cert and --tls-key go together\n");
        return 2;
    }
    if (cfg.http3 && !cfg.tls_cert) {
        fprintf(stderr, "betterAnusbis: --http3 needs --tls-cert and --tls-key; QUIC is "
                        "always TLS 1.3\n");
        return 2;
    }
#ifndef HAVE_NGHTTP3
    if (cfg.http3) {
        fprintf(stderr, "betterAnusbis: this build has no HTTP/3 support (nghttp3 was not "
                        "found at build time)\n");
        return 2;
    }
#endif
#ifndef HAVE_NGHTTP2
    if (cfg.http2) {
        /* Not an error: saying so once is better than silently downgrading. */
        logmsg("this build has no HTTP/2 support; --http2 has no effect");
    }
#endif
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
        SSL_CTX_set_alpn_select_cb(server_ctx, alpn_select_cb, NULL);
    }

    int srv_unix = 0;
    int srv = make_listener(cfg.listen, cfg.bind_network, cfg.socket_mode, &srv_unix);
    if (srv < 0) return 1;

    logmsg("betterAnusbis " VERSION " listening on %s (%s%s) -> %s (%s, difficulty %d)",
           cfg.listen, use_tls ? "https" : "http",
           srv_unix ? " unix socket" : "", cfg.target, cfg.algorithm, cfg.difficulty);
    if (!srv_unix)
        logmsg("open %s://127.0.0.1:%d/ and the challenge page solves it for you",
               use_tls ? "https" : "http", ntohs(addr.sin6_port));

#ifdef HAVE_NGHTTP3
    if (cfg.http3) {
        if (h3_start(&addr) != 0) {
            fprintf(stderr, "betterAnusbis: cannot start HTTP/3 on UDP %s\n", cfg.listen);
            return 1;
        }
        logmsg("HTTP/3 over QUIC on the same port (%s), Alt-Svc advertised", cfg.listen);
    }
#endif
    if (cfg.metrics_bind && *cfg.metrics_bind) {
        int munix = 0;
        int mfd = make_listener(cfg.metrics_bind, cfg.metrics_network, cfg.socket_mode, &munix);
        if (mfd < 0) return 1;
        int *mp = malloc(sizeof *mp);
        if (!mp) return 1;
        *mp = mfd;
        pthread_t mt;
        if (pthread_create(&mt, NULL, metrics_thread, mp) != 0) {
            fprintf(stderr, "betterAnusbis: cannot start the metrics thread\n");
            return 1;
        }
        pthread_detach(mt);
        logmsg("metrics on %s%s (GET /metrics, GET /healthz)", cfg.metrics_bind,
               munix ? " (unix socket)" : "");
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
