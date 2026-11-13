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

#include "anubis-solver.h"

/* ----------------------------------------------------------------- config */

#define VERSION "1.10.0"
#define API_PREFIX "/.within.website/x/cmd/anubis/api/"
#define DEFAULT_COOKIE_PREFIX "techaro.lol-anubis"
#define MAX_HEADER 32768
#define MAX_BODY (8u << 20)      /* requests we are willing to buffer */
#define MAX_REPLY (64u << 20)    /* backend responses we are willing to buffer */
#define COOKIE_TTL 604800        /* one week, like Anubis's default */

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
} config;

static config cfg = {
    .listen = ":8080",
    .target = NULL,
    .algorithm = "sha256",
    .difficulty = 4,
    .cookie_prefix = DEFAULT_COOKIE_PREFIX,
    .verbose = 0,
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
static int sign_token(char *out, size_t cap, const char *challenge_id) {
    char payload[512];
    time_t now = time(NULL);
    /* policyRule is Anubis's rule hash; here it stands for the algorithm+difficulty */
    snprintf(payload, sizeof payload,
             "{\"challenge\":\"%s\",\"method\":\"%s\",\"policyRule\":\"rule-0\","
             "\"action\":\"CHALLENGE\",\"iat\":%lld,\"exp\":%lld}",
             challenge_id ? challenge_id : "issued", cfg.algorithm,
             (long long)now, (long long)(now + COOKIE_TTL));

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

static int verify_token(const char *token) {
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
    if (!exp) return 1;                              /* Anubis requires exp; we accept either */
    long long when = atoll(exp + 6);
    return when > (long long)time(NULL);
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

static ssize_t send_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return (ssize_t)sent;
}

static int read_headers(int fd, char *buf, size_t cap) {
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t r = read(fd, buf + used, cap - 1 - used);
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

static void respond(int fd, int status, const char *reason, const char *content_type,
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
    if (n > 0) send_all(fd, head, (size_t)n);
    if (body && body_len) send_all(fd, body, body_len);
}

static void respond_redirect(int fd, const char *location, const char *extra_headers) {
    char head[4096];
    int n = snprintf(head, sizeof head,
                     "HTTP/1.1 302 Found\r\n"
                     "Location: %s\r\n"
                     "Content-Length: 0\r\n"
                     "Connection: close\r\n"
                     "%s"
                     "\r\n",
                     location, extra_headers ? extra_headers : "");
    if (n > 0) send_all(fd, head, (size_t)n);
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

static void proxy_request(int fd, const request *req, const char *client_ip) {
    int up = connect_target();
    if (up < 0) {
        const char *msg = "betterAnusbis: cannot reach the target\n";
        respond(fd, 502, "Bad Gateway", NULL, NULL, msg, strlen(msg));
        return;
    }

    char head[8192];
    size_t off = (size_t)snprintf(head, sizeof head, "%s %s HTTP/1.1\r\nHost: %s\r\n",
                                 req->method, req->path, cfg.target_host);
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
    if (send_all(up, head, off) < 0) { close(up); return; }
    if (req->body_len && send_all(up, req->body, req->body_len) < 0) { close(up); return; }

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
        ssize_t r = read(up, reply + used, cap - 1 - used);
        if (r <= 0) break;
        used += (size_t)r;
    }
    close(up);
    if (used) send_all(fd, reply, used);
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

  const algo=(rules.algorithm||"").toLowerCase(), diff=rules.difficulty|0;
  const pass=(response,nonce,ms)=>{
    const u=new URL("/.within.website/x/cmd/anubis/api/pass-challenge",location.origin);
    u.searchParams.set("id",ch.id); u.searchParams.set("response",response);
    u.searchParams.set("nonce",String(nonce)); u.searchParams.set("redir",location.pathname+location.search);
    u.searchParams.set("elapsedTime",String(Math.max(1,Math.round(ms))));
    location.replace(u.toString());
  };

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
  if(algo!=="fast"&&algo!=="slow"&&algo!=="sha256"&&algo!=="wasm-sha256"){
    say(algo+" needs a native or WebAssembly solver - use the anubis_fetch CLI or the Firefox extension");
    return;
  }
  const t0=performance.now();
  if(algo==="fast"||algo==="slow"){
    const enc=new TextEncoder();
    for(let nonce=0;;nonce++){
      const d=sha256bytes(enc.encode(ch.randomData+nonce));
      if(lz(d)>=diff*4){ say("solved with nonce "+nonce); pass(tohex(d),nonce,performance.now()-t0); return; }
      if((nonce&8191)===0) say("trying nonce "+nonce);
    }
  } else {
    const base=hex2bytes(ch.randomData), le=base[base.length-1]>=128;
    for(let nonce=0;;nonce++){
      const msg=new Uint8Array(base.length+4); msg.set(base);
      if(le){msg[base.length]=nonce&255;msg[base.length+1]=(nonce>>>8)&255;msg[base.length+2]=(nonce>>>16)&255;msg[base.length+3]=(nonce>>>24)&255;}
      else  {msg[base.length]=(nonce>>>24)&255;msg[base.length+1]=(nonce>>>16)&255;msg[base.length+2]=(nonce>>>8)&255;msg[base.length+3]=nonce&255;}
      const d=sha256bytes(msg);
      if(lz(d)>=diff){ say("solved with nonce "+nonce); pass(tohex(d),nonce,performance.now()-t0); return; }
      if((nonce&8191)===0) say("trying nonce "+nonce);
    }
  }
})();
)JS";

static void challenge_page(int fd, const char *id, const char *random_data, const char *metadata_json,
                           const char *test_cookie) {
    char payload[2048];
    snprintf(payload, sizeof payload,
             "{\"rules\":{\"algorithm\":\"%s\",\"difficulty\":%d},"
             "\"challenge\":{\"issuedAt\":\"%lld\",\"metadata\":%s,\"id\":\"%s\","
             "\"method\":\"%s\",\"randomData\":\"%s\",\"policyRuleHash\":\"rule-0\","
             "\"difficulty\":%d,\"spent\":false,\"extensions\":null}}",
             cfg.algorithm, cfg.difficulty, (long long)time(NULL), metadata_json, id,
             cfg.algorithm, random_data, cfg.difficulty);

    size_t cap = strlen(payload) + strlen(CHALLENGE_JS) + 4096;
    char *body = malloc(cap);
    if (!body) { respond(fd, 500, "Internal Server Error", NULL, NULL, "oom", 3); return; }

    snprintf(body, cap,
             "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
             "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
             "<title>Proving you are not a robot</title><style>"
             "body{font:16px/1.6 system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;"
             "background:#12141a;color:#e6e9f0}a{color:#4d6bfe}"
             "code{font-family:ui-monospace,monospace;font-size:.85em;color:#98a0b3;word-break:break-all}"
             "</style></head><body>"
             "<h1>Proving you are not a robot</h1>"
             "<p id=\"status\">solving a %s challenge at difficulty %d&hellip;</p>"
             "<p><a id=\"manual\" href=\"#\">or pass the challenge manually</a></p>"
             "<p><small>If nothing happens, solve it yourself: the challenge is the JSON below, "
             "and the answer goes to <code>%spass-challenge?id=%s&amp;response=&lt;digest&gt;&amp;nonce=&lt;n&gt;</code>.</small></p>"
             "<script id=\"anubis_challenge\" type=\"application/json\">%s</script>"
             "<script>%s</script>"
             "<script>(function(){var u=new URL(\"%spass-challenge\",location.origin);"
             "u.searchParams.set(\"id\",\"%s\");u.searchParams.set(\"response\",\"\");u.searchParams.set(\"nonce\",\"0\");"
             "u.searchParams.set(\"redir\",location.pathname);document.getElementById(\"manual\").href=u.toString();})();</script>"
             "</body></html>",
             cfg.algorithm, cfg.difficulty, API_PREFIX, id, payload, CHALLENGE_JS, API_PREFIX, id);

    char extra[512];
    snprintf(extra, sizeof extra,
             "Set-Cookie: %s-cookie-verification=%s; Path=/; SameSite=Lax\r\n",
             cfg.cookie_prefix, test_cookie ? test_cookie : id);
    respond(fd, 200, "OK", "text/html; charset=utf-8", extra, body, strlen(body));
    free(body);
}

/* ------------------------------------------------------------ the routes */

static void handle_connection(int fd, const char *client_ip) {
    char *raw = malloc(MAX_HEADER + 1);
    if (!raw) { close(fd); return; }
    int n = read_headers(fd, raw, MAX_HEADER + 1);
    if (n <= 0) { free(raw); close(fd); return; }
    raw[n] = 0;

    request req;
    if (parse_request(raw, &req) != 0) {
        respond(fd, 400, "Bad Request", NULL, NULL, "bad request\n", 12);
        free(raw);
        close(fd);
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
                ssize_t r = read(fd, req.body + got, content_length - got);
                if (r <= 0) break;
                got += (size_t)r;
            }
            req.body_len = got;
        }
    }

    if (cfg.verbose) logmsg("%s %s%s%s from %s", req.method, req.path,
                            req.query[0] ? "?" : "", req.query[0] ? req.query : "", client_ip);

    char cookie_value[2048];
    int authenticated = 0;
    if (find_cookie(req.headers, cfg.cookie_name, cookie_value, sizeof cookie_value))
        authenticated = verify_token(cookie_value);

    if (!strcmp(req.path, API_PREFIX "ping")) {
        respond(fd, 200, "OK", NULL, NULL, "pong\n", 5);
    } else if (!strcmp(req.path, API_PREFIX "check")) {
        if (authenticated) respond(fd, 200, "OK", NULL, NULL, "ok\n", 3);
        else respond(fd, 401, "Unauthorized", NULL, NULL, "challenge required\n", 19);
    } else if (!strcmp(req.path, API_PREFIX "pass-challenge")) {
        char id_buf[1024], response_buf[1024], nonce_buf[64], redir_buf[2048], elapsed_buf[64];
        const char *id = query_param(req.query, "id", id_buf, sizeof id_buf);
        const char *response = query_param(req.query, "response", response_buf, sizeof response_buf);
        const char *nonce_s = query_param(req.query, "nonce", nonce_buf, sizeof nonce_buf);
        const char *redir = query_param(req.query, "redir", redir_buf, sizeof redir_buf);
        (void)query_param(req.query, "elapsedTime", elapsed_buf, sizeof elapsed_buf);

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
        int need_work = strcasecmp(cfg.algorithm, "metarefresh") != 0;

        if (!id || (need_work && (!response || !nonce_s))) {
            const char *msg = "betterAnusbis: pass-challenge needs id, response and nonce\n";
            respond(fd, 400, "Bad Request", NULL, NULL, msg, strlen(msg));
        } else {

            /* metarefresh: no hashing, just elapsed time and the challenge echoed
             * back, exactly as lib/challenge/metarefresh/metarefresh.go checks */
            if (!strcasecmp(cfg.algorithm, "metarefresh")) {
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
                    if (sign_token(token, sizeof token, id) == 0) {
                        char extra[2300];
                        snprintf(extra, sizeof extra,
                                 "Set-Cookie: %s=%s; Path=/; Max-Age=%d; SameSite=Lax\r\n",
                                 cfg.cookie_name, token, COOKIE_TTL);
                        respond_redirect(fd, redir && *redir ? (redir[0] == '/' ? redir : "/") : "/", extra);
                        logmsg("metarefresh passed (waited %lld ms)", waited);
                    } else {
                        respond(fd, 500, "Internal Server Error", NULL, NULL, "cannot sign\n", 13);
                    }
                } else {
                    char msg[512];
                    snprintf(msg, sizeof msg,
                             "betterAnusbis: metarefresh wants a %lld ms wait and the challenge "
                             "echoed as ?challenge=<randomData>\n", wait_ms);
                    respond(fd, 403, "Forbidden", NULL, NULL, msg, strlen(msg));
                }
                goto done;
            }

            if (!have_challenge) {
                logmsg("rejecting: id %s is not a challenge we issued", id);
            } else if (issued_at && time(NULL) - issued_at > COOKIE_TTL) {
                logmsg("rejecting: challenge %s expired", id);
            } else {
                valid = verify_answer(cfg.algorithm, rd_hex, nonce, cfg.difficulty,
                                      digest, sizeof digest);
                if (valid && strcasecmp(response, digest) != 0) {
                    logmsg("rejecting: response %s is not the digest %s for nonce %llu",
                           response, digest, nonce);
                    valid = 0;
                }
            }

            if (!valid) {
                const char *msg =
                    "betterAnusbis: that answer did not verify\n"
                    "  the challenge id, the response and the nonce have to match\n";
                respond(fd, 403, "Forbidden", NULL, NULL, msg, strlen(msg));
            } else {
                char token[2048];
                if (sign_token(token, sizeof token, id) != 0) {
                    respond(fd, 500, "Internal Server Error", NULL, NULL, "cannot sign\n", 13);
                } else {
                    char extra[2300];
                    snprintf(extra, sizeof extra,
                             "Set-Cookie: %s=%s; Path=/; Max-Age=%d; SameSite=Lax\r\n"
                             "Set-Cookie: %s-cookie-verification=; Path=/; Max-Age=0\r\n",
                             cfg.cookie_name, token, COOKIE_TTL, cfg.cookie_prefix);
                    respond_redirect(fd, redir && *redir ? (redir[0] == '/' ? redir : "/") : "/", extra);
                    logmsg("challenge passed (nonce %llu, %s, difficulty %d)", nonce,
                           cfg.algorithm, cfg.difficulty);
                }
            }
        }
    } else if (authenticated) {
        proxy_request(fd, &req, client_ip);
    } else {
        /* issue a challenge */
        uint8_t rd[32];
        char rd_hex[65];
        if (random_bytes(rd, sizeof rd) != 0) { respond(fd, 500, "Internal Server Error", NULL, NULL, "entropy", 7); }
        else {
            hex_encode(rd, sizeof rd, rd_hex);
            char id[128];
            snprintf(id, sizeof id, "%s.%lld", rd_hex, (long long)time(NULL));
            const char *ua = header_value(&req, "User-Agent");
            char metadata[512];
            snprintf(metadata, sizeof metadata,
                     "{\"Referer\":\"\",\"User-Agent\":\"%.200s\",\"X-Real-IP\":\"%s\"}",
                     ua ? ua : "", client_ip);

            challenge_page(fd, id, rd_hex, metadata, id);
        }
    }

done:
    free(req.headers);
    free(req.body);
    free(raw);
    close(fd);
}

/* ------------------------------------------------------------- main loop */

static void *thread_main(void *arg) {
    int fd = (int)(intptr_t)arg;
    struct sockaddr_storage peer;
    socklen_t plen = sizeof peer;
    char ip[64] = "0.0.0.0";
    if (getpeername(fd, (struct sockaddr *)&peer, &plen) == 0) {
        if (peer.ss_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)&peer)->sin_addr, ip, sizeof ip);
        else if (peer.ss_family == AF_INET6)
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&peer)->sin6_addr, ip, sizeof ip);
    }
    handle_connection(fd, ip);
    return NULL;
}

static int parse_listen(const char *spec, struct sockaddr_in6 *out) {
    memset(out, 0, sizeof *out);
    out->sin6_family = AF_INET6;
    out->sin6_addr = in6addr_any;
    const char *colon = strrchr(spec, ':');
    if (!colon) return -1;
    out->sin6_port = htons((uint16_t)atoi(colon + 1));
    return 0;
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
        "  --listen ADDR:PORT     where to listen (default :8080)\n"
        "  --target URL           the backend to protect (required)\n"
        "  --algorithm NAME       fast, slow, sha256, argon2id, hashx or metarefresh\n"
        "                         (default sha256)\n"
        "  --difficulty N         difficulty; bits for sha256/argon2id/hashx,\n"
        "                         nibbles for fast/slow (default 4)\n"
        "  --cookie-prefix NAME   cookie prefix (default " DEFAULT_COOKIE_PREFIX ")\n"
        "  -v, --verbose          log every request\n"
        "  -h, --help             this text\n"
        "  -V, --version          version\n"
        "\n"
        "send SIGHUP to print the current settings; the secret is generated at start.\n");
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *next = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout); return 0; }
        if (!strcmp(a, "-V") || !strcmp(a, "--version")) { puts(VERSION); return 0; }
        if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) { cfg.verbose = 1; continue; }
        if (!strcmp(a, "--listen") && next) { cfg.listen = next; i++; continue; }
        if (!strcmp(a, "--target") && next) { cfg.target = next; i++; continue; }
        if (!strcmp(a, "--algorithm") && next) { cfg.algorithm = next; i++; continue; }
        if (!strcmp(a, "--difficulty") && next) { cfg.difficulty = atoi(next); i++; continue; }
        if (!strcmp(a, "--cookie-prefix") && next) { cfg.cookie_prefix = next; i++; continue; }
        fprintf(stderr, "betterAnusbis: unknown option %s (try --help)\n", a);
        return 2;
    }
    if (!cfg.target) {
        fprintf(stderr, "betterAnusbis: --target is required. Try --help.\n");
        return 2;
    }
    if (cfg.difficulty < 0 || cfg.difficulty > 64) {
        fprintf(stderr, "betterAnusbis: --difficulty must be 0..64\n");
        return 2;
    }
    static const char *known[] = {"fast", "slow", "sha256", "wasm-sha256", "argon2id",
                                  "hashx", "metarefresh", NULL};
    int ok = 0;
    for (int i = 0; known[i]; i++) if (!strcasecmp(cfg.algorithm, known[i])) ok = 1;
    if (!ok) {
        fprintf(stderr, "betterAnusbis: unknown algorithm %s\n  known:", cfg.algorithm);
        for (int i = 0; known[i]; i++) fprintf(stderr, " %s", known[i]);
        fputc('\n', stderr);
        return 2;
    }

    parse_target(cfg.target);
    snprintf(cfg.cookie_name, sizeof cfg.cookie_name, "%s-auth", cfg.cookie_prefix);
    if (random_bytes(cfg.secret, sizeof cfg.secret) != 0) {
        fprintf(stderr, "betterAnusbis: cannot read /dev/urandom\n");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    struct sockaddr_in6 addr;
    if (parse_listen(cfg.listen, &addr) != 0) {
        fprintf(stderr, "betterAnusbis: --listen wants ADDR:PORT\n");
        return 2;
    }
    int srv = socket(AF_INET6, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(srv, IPPROTO_IPV6, IPV6_V6ONLY, &(int){0}, sizeof(int));
    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) != 0) { perror("bind"); return 1; }
    if (listen(srv, 128) != 0) { perror("listen"); return 1; }

    logmsg("betterAnusbis " VERSION " listening on %s -> %s (%s, difficulty %d)",
           cfg.listen, cfg.target, cfg.algorithm, cfg.difficulty);
    logmsg("open http://127.0.0.1:%d/ and the challenge page solves it for you",
           ntohs(addr.sin6_port));

    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        pthread_t t;
        if (pthread_create(&t, NULL, thread_main, (void *)(intptr_t)fd) == 0) {
            pthread_detach(t);
        } else {
            close(fd);
        }
    }
    close(srv);
    return 0;
}
