/*
 * anubis_api.c — a small HTTP/1.1 JSON service in front of
 * libanubis_solver and the C fetch layer.
 *
 * Endpoints:
 *   GET  /healthz
 *   GET  /v1/version
 *   POST /v1/solve
 *   POST /v1/solve_raw      raw Anubis challenge in, raw result out (no I/O)
 *   POST /v1/verify
 *   POST /v1/fetch          JSON envelope, body as a string
 *   POST /v1/fetch_raw      the body bytes verbatim, origin Content-Type
 *   POST /v1/dump_headers   the header blocks of every response on the way
 *
 * One thread per connection, no external web framework, and a tiny
 * hand-written JSON parser/emitter so the binary has no extra dependencies.
 *
 * Build (from the repository root):
 *   cc -O2 -Wall -Wextra -Isrc/fetch -Iinclude -o /tmp/anubis_api \
 *      src/api/anubis_api.c src/fetch/anubis_fetch.c \
 *      -L. -lanubis_solver -Wl,-rpath,$PWD -lssl -lcrypto -lpthread
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
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
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "anubis-solver.h"
#include "anubis_fetch.h"

#define API_MAX_HEADER 65536u
#define API_DEFAULT_MAX_BODY 1048576u
#define API_READ_TIMEOUT_S 30

static size_t g_max_body = API_DEFAULT_MAX_BODY;

/* ------------------------------------------------------------------ */
/* Growable string buffer                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} strbuf;

static void sb_reserve(strbuf *b, size_t extra) {
    size_t need = b->len + extra + 1;
    if (need <= b->cap) {
        return;
    }
    size_t cap = b->cap ? b->cap : 64;
    while (cap < need) {
        if (cap > (SIZE_MAX / 2)) {
            cap = need;
            break;
        }
        cap *= 2;
    }
    char *p = realloc(b->data, cap);
    if (p == NULL) {
        abort();
    }
    b->data = p;
    b->cap = cap;
}

static void sb_putc(strbuf *b, char c) {
    sb_reserve(b, 1);
    b->data[b->len++] = c;
    b->data[b->len] = '\0';
}

static void sb_append(strbuf *b, const char *s, size_t n) {
    if (n == 0) {
        return;
    }
    sb_reserve(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void sb_puts(strbuf *b, const char *s) {
    sb_append(b, s, strlen(s));
}

static void sb_printf(strbuf *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        va_end(ap2);
        return;
    }
    sb_reserve(b, (size_t)n);
    vsnprintf(b->data + b->len, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)n;
}

static void sb_free(strbuf *b) {
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

/* Emit a JSON string with the bytes in [s, s+n). Non-ASCII bytes pass
 * through untouched (the payload is assumed UTF-8 already). */
static void sb_json_string(strbuf *b, const char *s, size_t n) {
    sb_putc(b, '"');
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':
            sb_puts(b, "\\\"");
            break;
        case '\\':
            sb_puts(b, "\\\\");
            break;
        case '\b':
            sb_puts(b, "\\b");
            break;
        case '\f':
            sb_puts(b, "\\f");
            break;
        case '\n':
            sb_puts(b, "\\n");
            break;
        case '\r':
            sb_puts(b, "\\r");
            break;
        case '\t':
            sb_puts(b, "\\t");
            break;
        default:
            if (c < 0x20) {
                sb_printf(b, "\\u%04x", (unsigned)c);
            } else {
                sb_putc(b, (char)c);
            }
            break;
        }
    }
    sb_putc(b, '"');
}

/* ------------------------------------------------------------------ */
/* Tiny JSON reader (validation, lookups, string unescaping)           */
/* ------------------------------------------------------------------ */

static void jws(const char *s, size_t n, size_t *i) {
    while (*i < n && isspace((unsigned char)s[*i])) {
        (*i)++;
    }
}

static int jhex4(const char *s, size_t n, size_t i, unsigned *out) {
    if (i + 4 > n) {
        return 0;
    }
    unsigned v = 0;
    for (size_t k = 0; k < 4; k++) {
        unsigned char c = (unsigned char)s[i + k];
        v <<= 4;
        if (c >= '0' && c <= '9') {
            v |= (unsigned)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v |= (unsigned)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            v |= (unsigned)(c - 'A' + 10);
        } else {
            return 0;
        }
    }
    *out = v;
    return 1;
}

static int sb_utf8(strbuf *b, unsigned cp) {
    if (cp <= 0x7f) {
        sb_putc(b, (char)cp);
    } else if (cp <= 0x7ff) {
        sb_putc(b, (char)(0xc0 | (cp >> 6)));
        sb_putc(b, (char)(0x80 | (cp & 0x3f)));
    } else if (cp <= 0xffff) {
        sb_putc(b, (char)(0xe0 | (cp >> 12)));
        sb_putc(b, (char)(0x80 | ((cp >> 6) & 0x3f)));
        sb_putc(b, (char)(0x80 | (cp & 0x3f)));
    } else {
        sb_putc(b, (char)(0xf0 | (cp >> 18)));
        sb_putc(b, (char)(0x80 | ((cp >> 12) & 0x3f)));
        sb_putc(b, (char)(0x80 | ((cp >> 6) & 0x3f)));
        sb_putc(b, (char)(0x80 | (cp & 0x3f)));
    }
    return 0;
}

/* Parse one JSON string at *i. When out is non-NULL the unescaped bytes are
 * appended to it. */
static int jstring(const char *s, size_t n, size_t *i, strbuf *out) {
    if (*i >= n || s[*i] != '"') {
        return 0;
    }
    (*i)++;
    while (*i < n) {
        unsigned char c = (unsigned char)s[*i];
        if (c == '"') {
            (*i)++;
            return 1;
        }
        if (c < 0x20) {
            return 0;
        }
        if (c != '\\') {
            if (out != NULL) {
                sb_putc(out, (char)c);
            }
            (*i)++;
            continue;
        }
        (*i)++;
        if (*i >= n) {
            return 0;
        }
        char e = s[*i];
        (*i)++;
        switch (e) {
        case '"':
        case '\\':
        case '/':
            if (out != NULL) {
                sb_putc(out, e);
            }
            break;
        case 'b':
            if (out != NULL) {
                sb_putc(out, '\b');
            }
            break;
        case 'f':
            if (out != NULL) {
                sb_putc(out, '\f');
            }
            break;
        case 'n':
            if (out != NULL) {
                sb_putc(out, '\n');
            }
            break;
        case 'r':
            if (out != NULL) {
                sb_putc(out, '\r');
            }
            break;
        case 't':
            if (out != NULL) {
                sb_putc(out, '\t');
            }
            break;
        case 'u': {
            unsigned cp = 0;
            if (!jhex4(s, n, *i, &cp)) {
                return 0;
            }
            *i += 4;
            if (cp >= 0xd800 && cp <= 0xdbff) {
                unsigned lo = 0;
                if (*i + 6 <= n && s[*i] == '\\' && s[*i + 1] == 'u' &&
                    jhex4(s, n, *i + 2, &lo) && lo >= 0xdc00 && lo <= 0xdfff) {
                    *i += 6;
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                }
            }
            if (out != NULL) {
                sb_utf8(out, cp);
            }
            break;
        }
        default:
            return 0;
        }
    }
    return 0;
}

static int jskip_value(const char *s, size_t n, size_t *i, int depth);

static int jskip_span(const char *s, size_t n, size_t *i) {
    /* number grammar: -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)? */
    size_t p = *i;
    if (p < n && s[p] == '-') {
        p++;
    }
    if (p >= n || !isdigit((unsigned char)s[p])) {
        return 0;
    }
    if (s[p] == '0') {
        p++;
    } else {
        while (p < n && isdigit((unsigned char)s[p])) {
            p++;
        }
    }
    if (p < n && s[p] == '.') {
        p++;
        if (p >= n || !isdigit((unsigned char)s[p])) {
            return 0;
        }
        while (p < n && isdigit((unsigned char)s[p])) {
            p++;
        }
    }
    if (p < n && (s[p] == 'e' || s[p] == 'E')) {
        p++;
        if (p < n && (s[p] == '+' || s[p] == '-')) {
            p++;
        }
        if (p >= n || !isdigit((unsigned char)s[p])) {
            return 0;
        }
        while (p < n && isdigit((unsigned char)s[p])) {
            p++;
        }
    }
    *i = p;
    return 1;
}

static int jskip_value(const char *s, size_t n, size_t *i, int depth) {
    if (depth > 32) {
        return 0;
    }
    jws(s, n, i);
    if (*i >= n) {
        return 0;
    }
    char c = s[*i];
    if (c == '"') {
        return jstring(s, n, i, NULL);
    }
    if (c == '{' || c == '[') {
        char close = (c == '{') ? '}' : ']';
        (*i)++;
        jws(s, n, i);
        if (*i < n && s[*i] == close) {
            (*i)++;
            return 1;
        }
        for (;;) {
            jws(s, n, i);
            if (c == '{') {
                if (!jstring(s, n, i, NULL)) {
                    return 0;
                }
                jws(s, n, i);
                if (*i >= n || s[*i] != ':') {
                    return 0;
                }
                (*i)++;
            }
            if (!jskip_value(s, n, i, depth + 1)) {
                return 0;
            }
            jws(s, n, i);
            if (*i >= n) {
                return 0;
            }
            if (s[*i] == ',') {
                (*i)++;
                continue;
            }
            if (s[*i] == close) {
                (*i)++;
                return 1;
            }
            return 0;
        }
    }
    if (c == 't' && *i + 4 <= n && memcmp(s + *i, "true", 4) == 0) {
        *i += 4;
        return 1;
    }
    if (c == 'f' && *i + 5 <= n && memcmp(s + *i, "false", 5) == 0) {
        *i += 5;
        return 1;
    }
    if (c == 'n' && *i + 4 <= n && memcmp(s + *i, "null", 4) == 0) {
        *i += 4;
        return 1;
    }
    return jskip_span(s, n, i);
}

/* 1 when the body is exactly one JSON value with nothing but whitespace after */
static int json_validate(const char *s, size_t n) {
    size_t i = 0;
    if (!jskip_value(s, n, &i, 0)) {
        return 0;
    }
    jws(s, n, &i);
    return i == n;
}

/* Find a top-level object member; *vpos is left on its value. */
static int json_find(const char *s, size_t n, const char *key, size_t *vpos) {
    size_t i = 0;
    size_t klen = strlen(key);
    jws(s, n, &i);
    if (i >= n || s[i] != '{') {
        return 0;
    }
    i++;
    jws(s, n, &i);
    if (i < n && s[i] == '}') {
        return 0;
    }
    for (;;) {
        strbuf k = {0};
        jws(s, n, &i); /* a pretty-printed body has spaces after the comma */
        if (!jstring(s, n, &i, &k)) {
            sb_free(&k);
            return 0;
        }
        int match = (k.len == klen && memcmp(k.data, key, klen) == 0);
        sb_free(&k);
        jws(s, n, &i);
        if (i >= n || s[i] != ':') {
            return 0;
        }
        i++;
        jws(s, n, &i);
        if (match) {
            *vpos = i;
            return 1;
        }
        if (!jskip_value(s, n, &i, 0)) {
            return 0;
        }
        jws(s, n, &i);
        if (i < n && s[i] == ',') {
            i++;
            continue;
        }
        return 0;
    }
}

/* 1 found, 0 absent, -1 present but not a string / invalid */
static int json_get_string(const char *s, size_t n, const char *key,
                           char **out) {
    size_t v = 0;
    if (!json_find(s, n, key, &v)) {
        return 0;
    }
    strbuf b = {0};
    if (!jstring(s, n, &v, &b)) {
        sb_free(&b);
        return -1;
    }
    if (b.data == NULL) {
        sb_reserve(&b, 0);
        b.data[0] = '\0';
    }
    *out = b.data;
    return 1;
}

/* 1 found, 0 absent, -1 not a number / malformed */
static int json_get_num_slice(const char *s, size_t n, const char *key,
                              char *buf, size_t bufsz) {
    size_t v = 0;
    if (!json_find(s, n, key, &v)) {
        return 0;
    }
    size_t start = v;
    if (!jskip_span(s, n, &v) || v == start) {
        return -1;
    }
    size_t len = v - start;
    if (len + 1 > bufsz) {
        return -1;
    }
    memcpy(buf, s + start, len);
    buf[len] = '\0';
    return 1;
}

static int json_get_i64(const char *s, size_t n, const char *key,
                        long long *out) {
    char buf[64];
    int r = json_get_num_slice(s, n, key, buf, sizeof buf);
    if (r != 1) {
        return r;
    }
    char *end = NULL;
    errno = 0;
    long long v = strtoll(buf, &end, 10);
    if (errno != 0 || end == buf || *end != '\0') {
        return -1;
    }
    *out = v;
    return 1;
}

static int json_get_u64(const char *s, size_t n, const char *key,
                        unsigned long long *out) {
    char buf[64];
    int r = json_get_num_slice(s, n, key, buf, sizeof buf);
    if (r != 1) {
        return r;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(buf, &end, 10);
    if (errno != 0 || end == buf || *end != '\0') {
        return -1;
    }
    *out = v;
    return 1;
}

static int json_get_double(const char *s, size_t n, const char *key,
                           double *out) {
    char buf[64];
    int r = json_get_num_slice(s, n, key, buf, sizeof buf);
    if (r != 1) {
        return r;
    }
    char *end = NULL;
    errno = 0;
    double v = strtod(buf, &end);
    if (errno != 0 || end == buf || *end != '\0') {
        return -1;
    }
    *out = v;
    return 1;
}

/* ------------------------------------------------------------------ */
/* HTTP helpers                                                        */
/* ------------------------------------------------------------------ */

static int write_all(int fd, const char *p, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    return 0;
}

static const char *reason_phrase(int status) {
    switch (status) {
    case 200:
        return "OK";
    case 400:
        return "Bad Request";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 413:
        return "Payload Too Large";
    case 431:
        return "Request Header Fields Too Large";
    case 500:
        return "Internal Server Error";
    case 502:
        return "Bad Gateway";
    default:
        return "Error";
    }
}

static void http_reply(int fd, int status, const char *body) {
    if (body == NULL) {
        body = "";
    }
    char head[320];
    int n = snprintf(head, sizeof head,
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     status, reason_phrase(status), strlen(body));
    if (n < 0) {
        return;
    }
    if (write_all(fd, head, (size_t)n) != 0) {
        return;
    }
    (void)write_all(fd, body, strlen(body));
}

/* Like http_reply, but for a body that must not be JSON-escaped: /v1/fetch_raw
 * hands back the upstream bytes with the upstream Content-Type. `extra` is a
 * pre-formatted block of additional response headers (may be NULL). */
static void http_reply_raw(int fd, int status, const char *content_type,
                           const char *extra, const char *body, size_t len) {
    char head[1536];
    int n;
    if (content_type == NULL || *content_type == '\0') {
        content_type = "application/octet-stream";
    }
    n = snprintf(head, sizeof head,
                 "HTTP/1.1 %d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %zu\r\n"
                 "%s"
                 "Connection: close\r\n"
                 "\r\n",
                 status, reason_phrase(status), content_type, len,
                 extra != NULL ? extra : "");
    if (n < 0 || (size_t)n >= sizeof head) {
        return;
    }
    if (write_all(fd, head, (size_t)n) != 0) {
        return;
    }
    if (len > 0) {
        (void)write_all(fd, body, len);
    }
}

/* Copy CR/LF out of a value that goes into a response header line. */
static void header_safe(char *s) {
    for (; *s != '\0'; s++) {
        if (*s == '\r' || *s == '\n') {
            *s = ' ';
        }
    }
}

/* Case-insensitive lookup of the last `name` header in a raw block. Returns 0
 * and writes a NUL-terminated value (leading space trimmed) on success. */
static int header_value(const char *headers, size_t len, const char *name,
                        char *out, size_t cap) {
    size_t name_len = strlen(name);
    const char *p = headers;
    const char *end = headers + len;
    int found = 0;

    if (out == NULL || cap == 0) {
        return 0;
    }
    out[0] = '\0';
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        size_t line_len = eol ? (size_t)(eol - p) : (size_t)(end - p);
        if (line_len > name_len && line_len >= name_len + 1 &&
            strncasecmp(p, name, name_len) == 0 && p[name_len] == ':') {
            const char *v = p + name_len + 1;
            const char *v_end = p + line_len;
            size_t k;
            while (v < v_end && (*v == ' ' || *v == '\t')) {
                v++;
            }
            while (v_end > v && (v_end[-1] == '\r' || v_end[-1] == ' ' ||
                                 v_end[-1] == '\t')) {
                v_end--;
            }
            k = (size_t)(v_end - v);
            if (k >= cap) {
                k = cap - 1;
            }
            memcpy(out, v, k);
            out[k] = '\0';
            header_safe(out);
            found = 1;
        }
        if (eol == NULL) {
            break;
        }
        p = eol + 1;
    }
    return found;
}

static void reply_error(int fd, int status, const char *message) {
    strbuf b = {0};
    sb_puts(&b, "{\"error\":");
    sb_json_string(&b, message, strlen(message));
    sb_puts(&b, "}");
    http_reply(fd, status, b.data ? b.data : "{}");
    sb_free(&b);
}

/* ------------------------------------------------------------------ */
/* Endpoint handlers                                                   */
/* ------------------------------------------------------------------ */

static const int backend_bits[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20};

/* Append one JSON array of backend names. */
static void sb_backend_list(strbuf *b, int mask) {
    size_t i;
    int first = 1;
    sb_puts(b, "[");
    for (i = 0; i < sizeof backend_bits / sizeof backend_bits[0]; i++) {
        const char *name;
        if (!(mask & backend_bits[i])) {
            continue;
        }
        name = anubis_backend_name(backend_bits[i]);
        if (name == NULL) {
            continue;
        }
        if (!first) {
            sb_puts(b, ",");
        }
        sb_json_string(b, name, strlen(name));
        first = 0;
    }
    sb_puts(b, "]");
}

static void handle_healthz(int fd) {
    strbuf b = {0};
    sb_puts(&b, "{\"ok\":true,\"version\":");
    sb_json_string(&b, anubis_solver_version(),
                   strlen(anubis_solver_version()));
    sb_puts(&b, ",\"codename\":");
    sb_json_string(&b, anubis_solver_codename(),
                   strlen(anubis_solver_codename()));
    sb_puts(&b, "}");
    http_reply(fd, 200, b.data);
    sb_free(&b);
}

static void handle_version(int fd) {
    strbuf b = {0};
    sb_puts(&b, "{\"version\":");
    sb_json_string(&b, anubis_solver_version(),
                   strlen(anubis_solver_version()));
    sb_puts(&b, ",\"codename\":");
    sb_json_string(&b, anubis_solver_codename(),
                   strlen(anubis_solver_codename()));
    sb_puts(&b, ",\"algorithms\":[\"fast\",\"slow\",\"sha256\","
               "\"wasm-sha256\",\"argon2id\",\"hashx\",\"tensor\"],"
               "\"backends_compiled\":");
    sb_backend_list(&b, anubis_backends_compiled());
    sb_puts(&b, ",\"impersonate\":");
    sb_json_string(&b, anubis_fetch_impersonate(),
                   strlen(anubis_fetch_impersonate()));
    sb_printf(&b, ",\"impersonate_available\":%s}",
              anubis_fetch_impersonate_available() ? "true" : "false");
    http_reply(fd, 200, b.data);
    sb_free(&b);
}

/* /v1/backends probes the hardware, so it is separate from /v1/version: it can
 * take a second on a cold driver and the version endpoint must stay cheap. */
static void handle_backends(int fd) {
    strbuf b = {0};
    int compiled = anubis_backends_compiled();
    int available = anubis_backends_available();
    sb_puts(&b, "{\"compiled\":");
    sb_backend_list(&b, compiled);
    sb_puts(&b, ",\"available\":");
    sb_backend_list(&b, available);
    sb_puts(&b, "}");
    http_reply(fd, 200, b.data);
    sb_free(&b);
}

/* Parse the common fields and hand them to the solver. Returns 0 when a reply
 * was already sent. */
static void handle_solve(int fd, const char *body, size_t blen) {
    char *alg = NULL;
    char *challenge = NULL;
    long long difficulty = 0;
    long long threads = 0;
    double budget_ms = 0.0;

    int r = json_get_string(body, blen, "algorithm", &alg);
    if (r < 0) {
        reply_error(fd, 400, "bad json");
        return;
    }
    if (r == 0) {
        reply_error(fd, 400, "missing field");
        return;
    }
    r = json_get_string(body, blen, "challenge", &challenge);
    if (r <= 0) {
        free(alg);
        reply_error(fd, 400, r < 0 ? "bad json" : "missing field");
        return;
    }
    r = json_get_i64(body, blen, "difficulty", &difficulty);
    if (r < 0) {
        free(alg);
        free(challenge);
        reply_error(fd, 400, "bad json");
        return;
    }
    r = json_get_i64(body, blen, "threads", &threads);
    if (r < 0 || (r == 1 && (threads < 0 || threads > 4096))) {
        free(alg);
        free(challenge);
        reply_error(fd, 400, "bad json");
        return;
    }
    r = json_get_double(body, blen, "budget_ms", &budget_ms);
    if (r < 0) {
        free(alg);
        free(challenge);
        reply_error(fd, 400, "bad json");
        return;
    }
    if (difficulty < 0 || difficulty > 1 << 20) {
        free(alg);
        free(challenge);
        reply_error(fd, 400, "bad argument");
        return;
    }

    int difficulty_i = (int)difficulty;
    int threads_i = (int)threads;
    double ms = 0.0;
    char hex[65] = {0};
    unsigned long long nonce = 0;
    int rc;

    if (strcmp(alg, "fast") == 0 || strcmp(alg, "slow") == 0) {
        uint64_t n = 0;
        rc = anubis_solve_nibbles(challenge, difficulty_i, threads_i, 0,
                                  budget_ms, &n, hex, &ms);
        nonce = (unsigned long long)n;
    } else if (strcmp(alg, "sha256") == 0 ||
               strcmp(alg, "wasm-sha256") == 0) {
        uint32_t n = 0;
        rc = anubis_solve_bits(challenge, difficulty_i, threads_i, budget_ms,
                               &n, hex, &ms);
        nonce = n;
    } else if (strcmp(alg, "argon2id") == 0) {
        uint32_t n = 0;
        rc = anubis_solve_argon2id(challenge, difficulty_i, threads_i,
                                   budget_ms, &n, hex, &ms);
        nonce = n;
    } else if (strcmp(alg, "hashx") == 0) {
        uint32_t n = 0;
        rc = anubis_solve_hashx(challenge, difficulty_i, threads_i, budget_ms,
                                &n, hex, &ms);
        nonce = n;
    } else if (strcmp(alg, "meatrider") == 0) {
        uint32_t n = 0;
        rc = anubis_solve_meatrider(challenge, difficulty_i, threads_i,
                                    budget_ms, &n, hex, &ms);
        nonce = n;
    } else if (strcmp(alg, "tensor") == 0) {
        uint32_t n = 0;
        rc = anubis_solve_tensor(challenge, difficulty_i, threads_i,
                                 budget_ms, &n, hex, &ms);
        nonce = n;
    } else {
        free(alg);
        free(challenge);
        reply_error(fd, 400, "unknown algorithm");
        return;
    }

    free(alg);
    free(challenge);

    if (rc == ANUBIS_ERR_ARG) {
        reply_error(fd, 400, "bad argument");
        return;
    }
    if (rc != ANUBIS_OK) {
        reply_error(fd, 500, rc == ANUBIS_ERR_UNSOLVED ? "unsolved"
                                                       : "internal error");
        return;
    }

    if (!isfinite(ms) || ms < 0.0) {
        ms = 0.0;
    }
    strbuf b = {0};
    sb_printf(&b, "{\"nonce\":%llu,\"response\":", nonce);
    sb_json_string(&b, hex, strlen(hex));
    sb_printf(&b, ",\"elapsed_ms\":%.3f}", ms);
    http_reply(fd, 200, b.data);
    sb_free(&b);
}

/* Find key=value in a query string. Values are simple (numbers, "json"), so
 * no percent-decoding is needed here. Returns 1 and copies the value when the
 * key is present. */
static int query_value(const char *query, const char *key, char *out,
                       size_t cap) {
    size_t klen = strlen(key);
    const char *p = query;
    if (p == NULL) {
        return 0;
    }
    while (*p != '\0') {
        const char *end = strchr(p, '&');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len > klen && strncmp(p, key, klen) == 0 && p[klen] == '=') {
            size_t vlen = len - klen - 1;
            if (vlen >= cap) {
                vlen = cap - 1;
            }
            memcpy(out, p + klen + 1, vlen);
            out[vlen] = '\0';
            return 1;
        }
        if (end == NULL) {
            break;
        }
        p = end + 1;
    }
    return 0;
}

/* /v1/solve_raw takes the challenge itself, not a JSON envelope: the body is
 * the anubis_challenge JSON, its <script> element, or the whole page. It
 * solves locally and returns the raw pass-challenge query. No fetch, no
 * socket, no cookie jar. */
static void handle_solve_raw(int fd, const char *body, size_t blen,
                             const char *query) {
    anubis_raw_solution sol;
    char err[256] = "";
    char value[64];
    long threads = 0;
    double budget_ms = 0.0;
    int json_out = 0;

    if (blen == 0) {
        reply_error(fd, 400, "empty challenge input");
        return;
    }
    if (query_value(query, "threads", value, sizeof value)) {
        char *end = NULL;
        errno = 0;
        threads = strtol(value, &end, 10);
        if (errno != 0 || end == value || *end != '\0' || threads < 0 ||
            threads > 4096) {
            reply_error(fd, 400, "bad threads");
            return;
        }
    }
    if (query_value(query, "budget_ms", value, sizeof value)) {
        char *end = NULL;
        errno = 0;
        budget_ms = strtod(value, &end);
        if (errno != 0 || end == value || *end != '\0' || budget_ms < 0.0 ||
            !isfinite(budget_ms)) {
            reply_error(fd, 400, "bad budget_ms");
            return;
        }
    }
    if (query_value(query, "format", value, sizeof value) &&
        strcmp(value, "json") == 0) {
        json_out = 1;
    }

    if (anubis_solve_challenge_input(body, blen, (int)threads, budget_ms, &sol,
                                     err, sizeof err) != 0) {
        reply_error(fd, 400, err[0] ? err : "cannot solve challenge");
        return;
    }

    if (json_out) {
        strbuf b = {0};
        sb_puts(&b, "{\"algorithm\":");
        sb_json_string(&b, sol.challenge.algorithm,
                       strlen(sol.challenge.algorithm));
        sb_printf(&b, ",\"difficulty\":%d,\"id\":", sol.challenge.difficulty);
        sb_json_string(&b, sol.challenge.id, strlen(sol.challenge.id));
        sb_printf(&b, ",\"nonce\":%llu,\"response\":",
                  (unsigned long long)sol.nonce);
        sb_json_string(&b, sol.response, strlen(sol.response));
        sb_printf(&b,
                  ",\"elapsed_ms\":%.3f,\"wait_ms\":%d,\"raw\":",
                  sol.elapsed_ms, sol.wait_ms);
        sb_json_string(&b, sol.raw, strlen(sol.raw));
        sb_puts(&b, "}");
        http_reply(fd, 200, b.data);
        sb_free(&b);
        return;
    }

    {
        char extra[768];
        snprintf(extra, sizeof extra,
                 "X-Anubis-Algorithm: %s\r\n"
                 "X-Anubis-Difficulty: %d\r\n"
                 "X-Anubis-Nonce: %llu\r\n"
                 "X-Anubis-Response: %s\r\n"
                 "X-Anubis-Wait-Ms: %d\r\n",
                 sol.challenge.algorithm, sol.challenge.difficulty,
                 (unsigned long long)sol.nonce, sol.response, sol.wait_ms);
        http_reply_raw(fd, 200, "text/plain; charset=utf-8", extra, sol.raw,
                       strlen(sol.raw));
    }
}

static void handle_verify(int fd, const char *body, size_t blen) {
    char *alg = NULL;
    char *challenge = NULL;
    long long difficulty = 0;
    unsigned long long nonce = 0;

    int r = json_get_string(body, blen, "algorithm", &alg);
    if (r <= 0) {
        free(alg);
        reply_error(fd, 400, r < 0 ? "bad json" : "missing field");
        return;
    }
    r = json_get_string(body, blen, "challenge", &challenge);
    if (r <= 0) {
        free(alg);
        free(challenge);
        reply_error(fd, 400, r < 0 ? "bad json" : "missing field");
        return;
    }
    r = json_get_i64(body, blen, "difficulty", &difficulty);
    if (r < 0) {
        free(alg);
        free(challenge);
        reply_error(fd, 400, "bad json");
        return;
    }
    r = json_get_u64(body, blen, "nonce", &nonce);
    if (r < 0) {
        free(alg);
        free(challenge);
        reply_error(fd, 400, "bad json");
        return;
    }
    if (difficulty < 0 || difficulty > 1 << 20) {
        free(alg);
        free(challenge);
        reply_error(fd, 400, "bad argument");
        return;
    }
    int difficulty_i = (int)difficulty;
    char hex[65] = {0};
    int rc;

    if (strcmp(alg, "fast") == 0 || strcmp(alg, "slow") == 0) {
        rc = anubis_verify_nibbles(challenge, (uint64_t)nonce, difficulty_i,
                                   hex);
    } else if (strcmp(alg, "sha256") == 0 ||
               strcmp(alg, "wasm-sha256") == 0) {
        rc = anubis_verify_bits(challenge, (uint32_t)nonce, difficulty_i, hex);
    } else if (strcmp(alg, "argon2id") == 0) {
        rc = anubis_verify_argon2id(challenge, (uint32_t)nonce, difficulty_i,
                                    hex);
    } else if (strcmp(alg, "hashx") == 0) {
        rc = anubis_verify_hashx(challenge, (uint32_t)nonce, difficulty_i, hex);
    } else if (strcmp(alg, "meatrider") == 0) {
        rc = anubis_verify_meatrider(challenge, (uint32_t)nonce, difficulty_i,
                                     hex);
    } else if (strcmp(alg, "tensor") == 0) {
        rc = anubis_verify_tensor(challenge, (uint32_t)nonce, difficulty_i,
                                  hex);
    } else {
        free(alg);
        free(challenge);
        reply_error(fd, 400, "unknown algorithm");
        return;
    }

    free(alg);
    free(challenge);

    if (rc == ANUBIS_ERR_ARG) {
        reply_error(fd, 400, "bad argument");
        return;
    }
    strbuf b = {0};
    sb_puts(&b, rc == ANUBIS_OK ? "{\"ok\":true,\"digest\":" :
                                  "{\"ok\":false,\"digest\":");
    sb_json_string(&b, hex, strlen(hex));
    sb_puts(&b, "}");
    http_reply(fd, 200, b.data);
    sb_free(&b);
}

static int fetch_args(int fd, const char *body, size_t blen, char **url,
                      char **impersonate, char **cookies);

static void handle_fetch(int fd, const char *body, size_t blen) {
    char *url = NULL;
    char *impersonate = NULL;
    char *cookies = NULL;
    anubis_page_dump dump;
    strbuf b = {0};

    if (fetch_args(fd, body, blen, &url, &impersonate, &cookies) != 0) {
        return;
    }
    memset(&dump, 0, sizeof dump);
    if (anubis_fetch_get_dump_with(url, impersonate, cookies, &dump) != 0) {
        const char *msg = dump.page.error[0] ? dump.page.error : "fetch failed";
        reply_error(fd, 502, msg);
        anubis_page_dump_free(&dump);
        free(url);
        free(impersonate);
        free(cookies);
        return;
    }

    sb_printf(&b, "{\"status\":%d,\"final_url\":", dump.page.status);
    sb_json_string(&b, dump.page.final_url ? dump.page.final_url : "",
                   dump.page.final_url ? strlen(dump.page.final_url) : 0);
    sb_puts(&b, ",\"transport\":");
    sb_json_string(&b, anubis_fetch_transport(), strlen(anubis_fetch_transport()));
    sb_printf(&b, ",\"solved\":%s,\"expired\":%s,\"cookies\":",
              dump.solved ? "true" : "false", dump.expired ? "true" : "false");
    sb_json_string(&b, dump.cookies ? dump.cookies : "",
                   dump.cookies ? dump.cookies_len : 0);
    sb_puts(&b, ",\"content\":");
    sb_json_string(&b, dump.page.body ? dump.page.body : "",
                   dump.page.body ? dump.page.body_len : 0);
    sb_puts(&b, "}");
    http_reply(fd, 200, b.data);
    sb_free(&b);
    anubis_page_dump_free(&dump);
    free(url);
    free(impersonate);
    free(cookies);
}

/* Parse the fetch arguments every fetch endpoint takes: url is required,
 * impersonate and cookies are optional. All three come back owned by the
 * caller. Returns 0, or -1 after replying when the body was bad. */
static int fetch_args(int fd, const char *body, size_t blen, char **url,
                      char **impersonate, char **cookies) {
    int r;

    *url = NULL;
    *impersonate = NULL;
    *cookies = NULL;
    r = json_get_string(body, blen, "url", url);
    if (r <= 0) {
        reply_error(fd, 400, r < 0 ? "bad json" : "missing field");
        return -1;
    }
    if ((*url)[0] == '\0') {
        free(*url);
        *url = NULL;
        reply_error(fd, 400, "missing field");
        return -1;
    }
    if (json_get_string(body, blen, "impersonate", impersonate) < 0 ||
        json_get_string(body, blen, "cookies", cookies) < 0) {
        free(*url);
        *url = NULL;
        free(*impersonate);
        *impersonate = NULL;
        free(*cookies);
        *cookies = NULL;
        reply_error(fd, 400, "bad json");
        return -1;
    }
    return 0;
}

/* The body bytes exactly as the origin sent them, with the origin
 * Content-Type and the fetch metadata as X-Anubis-* headers. */
static void handle_fetch_raw(int fd, const char *body, size_t blen) {
    char *url = NULL;
    char *impersonate = NULL;
    char *cookies = NULL;
    anubis_page_dump dump;
    char content_type[160] = "";
    char final_url[1200];
    strbuf extra = {0};

    if (fetch_args(fd, body, blen, &url, &impersonate, &cookies) != 0) {
        return;
    }
    memset(&dump, 0, sizeof dump);
    if (anubis_fetch_get_dump_with(url, impersonate, cookies, &dump) != 0) {
        const char *msg = dump.page.error[0] ? dump.page.error : "fetch failed";
        reply_error(fd, 502, msg);
        anubis_page_dump_free(&dump);
        free(url);
        free(impersonate);
        free(cookies);
        return;
    }
    if (!header_value(dump.headers, dump.headers_len, "Content-Type",
                      content_type, sizeof content_type)) {
        snprintf(content_type, sizeof content_type, "application/octet-stream");
    }
    snprintf(final_url, sizeof final_url, "%s",
             dump.page.final_url ? dump.page.final_url : url);
    header_safe(final_url);
    sb_printf(&extra,
              "X-Anubis-Status: %d\r\n"
              "X-Anubis-Final-URL: %s\r\n"
              "X-Anubis-Transport: %s\r\n"
              "X-Anubis-Solved: %s\r\n"
              "X-Anubis-Expired: %s\r\n",
              dump.page.status, final_url, anubis_fetch_transport(),
              dump.solved ? "1" : "0", dump.expired ? "1" : "0");
    if (dump.cookies != NULL && dump.cookies_len > 0) {
        char *safe = strdup(dump.cookies);
        if (safe != NULL) {
            header_safe(safe);
            sb_puts(&extra, "X-Anubis-Cookies: ");
            sb_puts(&extra, safe);
            sb_puts(&extra, "\r\n");
            free(safe);
        }
    }
    http_reply_raw(fd, 200, content_type, extra.data,
                   dump.page.body ? dump.page.body : "", dump.page.body_len);
    sb_free(&extra);
    anubis_page_dump_free(&dump);
    free(url);
    free(impersonate);
    free(cookies);
}

/* Every response header block the fetch went through, as JSON. */
static void handle_dump_headers(int fd, const char *body, size_t blen) {
    char *url = NULL;
    char *impersonate = NULL;
    char *cookies = NULL;
    anubis_page_dump dump;
    strbuf b = {0};

    if (fetch_args(fd, body, blen, &url, &impersonate, &cookies) != 0) {
        return;
    }
    memset(&dump, 0, sizeof dump);
    if (anubis_fetch_get_dump_with(url, impersonate, cookies, &dump) != 0) {
        const char *msg = dump.page.error[0] ? dump.page.error : "fetch failed";
        reply_error(fd, 502, msg);
        anubis_page_dump_free(&dump);
        free(url);
        free(impersonate);
        free(cookies);
        return;
    }
    sb_printf(&b, "{\"status\":%d,\"final_url\":", dump.page.status);
    sb_json_string(&b, dump.page.final_url ? dump.page.final_url : url,
                   strlen(dump.page.final_url ? dump.page.final_url : url));
    sb_puts(&b, ",\"transport\":");
    sb_json_string(&b, anubis_fetch_transport(), strlen(anubis_fetch_transport()));
    sb_printf(&b, ",\"solved\":%s,\"expired\":%s",
              dump.solved ? "true" : "false", dump.expired ? "true" : "false");
    sb_puts(&b, ",\"cookies\":");
    sb_json_string(&b, dump.cookies ? dump.cookies : "",
                   dump.cookies ? dump.cookies_len : 0);
    sb_printf(&b, ",\"headers_len\":%zu,\"headers\":", dump.headers_len);
    sb_json_string(&b, dump.headers ? dump.headers : "",
                   dump.headers ? dump.headers_len : 0);
    sb_puts(&b, "}");
    http_reply(fd, 200, b.data);
    sb_free(&b);
    anubis_page_dump_free(&dump);
    free(url);
    free(impersonate);
    free(cookies);
}

/* ------------------------------------------------------------------ */
/* Connection handling                                                 */
/* ------------------------------------------------------------------ */

static ssize_t find_header_end(const char *buf, size_t n) {
    for (size_t i = 0; i + 3 < n; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
            buf[i + 3] == '\n') {
            return (ssize_t)(i + 4);
        }
    }
    return -1;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') {
        s++;
    }
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t')) {
        *--end = '\0';
    }
    return s;
}

static void handle_client(int fd) {
    size_t cap = 8192;
    size_t len = 0;
    char *buf = malloc(cap);
    if (buf == NULL) {
        return;
    }
    ssize_t hdr_end = -1;
    for (;;) {
        if (len == cap) {
            if (cap >= API_MAX_HEADER) {
                reply_error(fd, 431, "header too large");
                free(buf);
                return;
            }
            size_t ncap = cap * 2;
            char *p = realloc(buf, ncap);
            if (p == NULL) {
                free(buf);
                return;
            }
            buf = p;
            cap = ncap;
        }
        ssize_t r = recv(fd, buf + len, cap - len, 0);
        if (r <= 0) {
            free(buf);
            return;
        }
        len += (size_t)r;
        hdr_end = find_header_end(buf, len);
        if (hdr_end >= 0) {
            break;
        }
        if (len >= API_MAX_HEADER) {
            reply_error(fd, 431, "header too large");
            free(buf);
            return;
        }
    }

    char *hdr = malloc((size_t)hdr_end + 1);
    if (hdr == NULL) {
        free(buf);
        return;
    }
    memcpy(hdr, buf, (size_t)hdr_end);
    hdr[hdr_end] = '\0';

    char method[16] = {0};
    char target[8192] = {0};
    char version[16] = {0};
    if (sscanf(hdr, "%15s %8191s %15s", method, target, version) != 3) {
        reply_error(fd, 400, "bad request");
        free(hdr);
        free(buf);
        return;
    }

    size_t content_length = 0;
    int has_content_length = 0;
    int chunked = 0;
    char *save = NULL;
    char *line = strtok_r(hdr, "\r\n", &save);
    if (line != NULL) {
        line = strtok_r(NULL, "\r\n", &save);
    }
    while (line != NULL) {
        char *colon = strchr(line, ':');
        if (colon != NULL) {
            *colon = '\0';
            char *key = trim(line);
            char *val = trim(colon + 1);
            if (strcasecmp(key, "Content-Length") == 0) {
                char *end = NULL;
                errno = 0;
                unsigned long long v = strtoull(val, &end, 10);
                if (errno != 0 || end == val || *end != '\0') {
                    reply_error(fd, 400, "bad request");
                    free(hdr);
                    free(buf);
                    return;
                }
                content_length = (size_t)v;
                has_content_length = 1;
            } else if (strcasecmp(key, "Transfer-Encoding") == 0 &&
                       strcasestr(val, "chunked") != NULL) {
                chunked = 1;
            }
        }
        line = strtok_r(NULL, "\r\n", &save);
    }
    free(hdr);

    if (chunked) {
        reply_error(fd, 400, "chunked bodies unsupported");
        free(buf);
        return;
    }
    if (has_content_length && content_length > g_max_body) {
        reply_error(fd, 413, "payload too large");
        free(buf);
        return;
    }
    if (content_length > SIZE_MAX - 1) {
        reply_error(fd, 413, "payload too large");
        free(buf);
        return;
    }

    char *body = malloc(content_length + 1);
    if (body == NULL) {
        reply_error(fd, 500, "out of memory");
        free(buf);
        return;
    }
    size_t avail = len - (size_t)hdr_end;
    size_t got = avail < content_length ? avail : content_length;
    if (got > 0) {
        memcpy(body, buf + (size_t)hdr_end, got);
    }
    while (got < content_length) {
        ssize_t r = recv(fd, body + got, content_length - got, 0);
        if (r <= 0) {
            reply_error(fd, 400, "short body");
            free(body);
            free(buf);
            return;
        }
        got += (size_t)r;
    }
    body[content_length] = '\0';
    free(buf);

    char *path = target;
    char *q = strchr(path, '?');
    const char *query = "";
    if (q != NULL) {
        *q = '\0';
        query = q + 1;
    }

    int is_get = strcmp(method, "GET") == 0;
    int is_post = strcmp(method, "POST") == 0;

    if (is_post && strcmp(path, "/v1/solve_raw") == 0) {
        handle_solve_raw(fd, body, content_length, query);
    } else if (is_get && strcmp(path, "/healthz") == 0) {
        handle_healthz(fd);
    } else if (is_get && strcmp(path, "/v1/version") == 0) {
        handle_version(fd);
    } else if (is_get && strcmp(path, "/v1/backends") == 0) {
        handle_backends(fd);
    } else if (is_post &&
               (strcmp(path, "/v1/solve") == 0 ||
                strcmp(path, "/v1/verify") == 0 ||
                strcmp(path, "/v1/fetch") == 0 ||
                strcmp(path, "/v1/fetch_raw") == 0 ||
                strcmp(path, "/v1/dump_headers") == 0)) {
        if (!json_validate(body, content_length)) {
            reply_error(fd, 400, "bad json");
        } else if (strcmp(path, "/v1/solve") == 0) {
            handle_solve(fd, body, content_length);
        } else if (strcmp(path, "/v1/verify") == 0) {
            handle_verify(fd, body, content_length);
        } else if (strcmp(path, "/v1/fetch") == 0) {
            handle_fetch(fd, body, content_length);
        } else if (strcmp(path, "/v1/fetch_raw") == 0) {
            handle_fetch_raw(fd, body, content_length);
        } else {
            handle_dump_headers(fd, body, content_length);
        }
    } else {
        reply_error(fd, 404, "not found");
    }
    free(body);
}

typedef struct {
    int fd;
} conn_arg;

static void *client_thread(void *arg) {
    conn_arg *c = arg;
    int fd = c->fd;
    free(c);
    handle_client(fd);
    close(fd);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

static void usage(FILE *out, const char *argv0) {
    fprintf(out,
            "usage: %s --listen 127.0.0.1:8088 [--max-body 1048576]\n"
            "\n"
            "  --listen ADDR:PORT   address to bind (default 127.0.0.1:8088)\n"
            "  --max-body BYTES     maximum request body (default %u)\n"
            "  --help               show this help\n",
            argv0, (unsigned)API_DEFAULT_MAX_BODY);
}

static int create_listener(const char *spec) {
    if (spec == NULL || *spec == '\0') {
        return -1;
    }
    const char *colon = strrchr(spec, ':');
    if (colon == NULL || colon == spec + strlen(spec) - 1) {
        fprintf(stderr, "anubis_api: bad --listen address '%s'\n", spec);
        return -1;
    }
    char host[256] = {0};
    size_t hlen = (size_t)(colon - spec);
    if (hlen >= 2 && spec[0] == '[' && spec[hlen - 1] == ']') {
        hlen -= 2;
        if (hlen >= sizeof host) {
            return -1;
        }
        memcpy(host, spec + 1, hlen);
    } else {
        if (hlen >= sizeof host) {
            return -1;
        }
        memcpy(host, spec, hlen);
    }
    const char *port = colon + 1;

    char *end = NULL;
    errno = 0;
    unsigned long pnum = strtoul(port, &end, 10);
    if (errno != 0 || end == port || *end != '\0' || pnum == 0 ||
        pnum > 65535) {
        fprintf(stderr, "anubis_api: bad --listen port '%s'\n", port);
        return -1;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    struct addrinfo *res = NULL;
    int gai = getaddrinfo(host[0] ? host : NULL, port, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "anubis_api: cannot resolve %s: %s\n", spec,
                gai_strerror(gai));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        int s = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
                       ai->ai_protocol);
        if (s < 0) {
            continue;
        }
        int one = 1;
        (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef IPV6_V6ONLY
        if (ai->ai_family == AF_INET6) {
            int zero = 0;
            (void)setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &zero,
                             sizeof zero);
        }
#endif
        if (bind(s, ai->ai_addr, ai->ai_addrlen) == 0 &&
            listen(s, 128) == 0) {
            fd = s;
            break;
        }
        close(s);
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "anubis_api: cannot listen on %s: %s\n", spec,
                strerror(errno));
    }
    return fd;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    const char *listen_spec = "127.0.0.1:8088";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--listen") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "anubis_api: --listen needs an argument\n");
                return 2;
            }
            listen_spec = argv[++i];
        } else if (strcmp(argv[i], "--max-body") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "anubis_api: --max-body needs an argument\n");
                return 2;
            }
            char *end = NULL;
            errno = 0;
            unsigned long long v = strtoull(argv[++i], &end, 10);
            if (errno != 0 || end == argv[i] || *end != '\0' || v == 0) {
                fprintf(stderr, "anubis_api: bad --max-body\n");
                return 2;
            }
            g_max_body = (size_t)v;
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            usage(stdout, argv[0]);
            return 0;
        } else {
            fprintf(stderr, "anubis_api: unknown option '%s'\n", argv[i]);
            usage(stderr, argv[0]);
            return 2;
        }
    }

    int lfd = create_listener(listen_spec);
    if (lfd < 0) {
        return 1;
    }

    printf("anubis_api %s \"%s\" listening on %s\n",
           anubis_solver_version(), anubis_solver_codename(), listen_spec);
    fflush(stdout);

    for (;;) {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof ss;
        int cfd = accept(lfd, (struct sockaddr *)&ss, &slen);
        if (cfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            continue;
        }
        struct timeval tv;
        tv.tv_sec = API_READ_TIMEOUT_S;
        tv.tv_usec = 0;
        (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void)setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

        conn_arg *c = malloc(sizeof *c);
        if (c == NULL) {
            close(cfd);
            continue;
        }
        c->fd = cfd;
        pthread_t t;
        if (pthread_create(&t, NULL, client_thread, c) != 0) {
            close(cfd);
            free(c);
            continue;
        }
        pthread_detach(t);
    }
}
