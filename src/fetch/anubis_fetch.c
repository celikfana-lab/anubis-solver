/*
 * anubis_fetch.c — the C client behind the MCP server and the API service.
 *
 * One job: GET a URL that may be behind Anubis, solve whatever it asks for
 * with libanubis_solver, submit the answer with the cookies the server set,
 * and hand back the real page. The challenge protocol here is the one the gate
 * implements: a JSON payload in <script id="anubis_challenge">, a
 * pass-challenge GET with id/response/nonce, and a cookie that follows.
 *
 * The same parser is available without the GET: anubis_solve_challenge_input()
 * takes a challenge the caller already has and returns the raw pass-challenge
 * query, opening no socket.
 *
 * Two transports. The built-in one is deliberately small: HTTP/1.1,
 * Content-Length or chunked, one request per connection (Connection: close), a
 * cookie list, and redirects. The other is libcurl-impersonate, when it is
 * installed (see fetch_impersonate.c): HTTP/2 with a real browser TLS
 * fingerprint, its own cookie engine, and connection reuse. The built-in client
 * is the fallback and needs nothing but OpenSSL.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE  /* strcasestr, strdup, readlink */
#endif
#include "anubis_fetch.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "fetch_impersonate.h"
#include "anubis-solver.h"

#define MAX_HEADER 65536
#define MAX_BODY (32u << 20)
#define UA "anubis-c/2.50"

/* ------------------------------------------------------------------ util */

static char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

typedef struct {
    char *data;
    size_t len, cap;
} buf;

static int buf_add(buf *b, const void *p, size_t n) {
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (cap < b->len + n + 1) cap *= 2;
        char *d = realloc(b->data, cap);
        if (!d) return -1;
        b->data = d;
        b->cap = cap;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = '\0';
    return 0;
}

static void seterr(anubis_page *out, const char *msg) {
    snprintf(out->error, sizeof out->error, "%s", msg);
}

static char *url_encode(const char *s) {
    static const char hex[] = "0123456789ABCDEF";
    size_t n = strlen(s), o = 0;
    char *r = malloc(n * 3 + 1);
    if (!r) return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            r[o++] = (char)c;
        } else {
            r[o++] = '%';
            r[o++] = hex[c >> 4];
            r[o++] = hex[c & 15];
        }
    }
    r[o] = '\0';
    return r;
}

/* --------------------------------------------------------------- cookies */

typedef struct {
    char **items;
    size_t n, cap;
} jar;

static void jar_set(jar *j, const char *pair) {
    char name[128];
    const char *eq = strchr(pair, '=');
    size_t nl;
    if (!eq) return;
    nl = (size_t)(eq - pair);
    if (nl == 0 || nl >= sizeof name) return;
    memcpy(name, pair, nl);
    name[nl] = '\0';
    for (size_t i = 0; i < j->n; i++) {
        if (strncmp(j->items[i], name, nl) == 0 && j->items[i][nl] == '=') {
            free(j->items[i]);
            j->items[i] = xstrdup(pair);
            return;
        }
    }
    if (j->n == j->cap) {
        size_t cap = j->cap ? j->cap * 2 : 8;
        char **p = realloc(j->items, cap * sizeof *p);
        if (!p) return;
        j->items = p;
        j->cap = cap;
    }
    j->items[j->n++] = xstrdup(pair);
}

/* Seed a jar from a Cookie header value ("a=b; c=d"), the form a caller keeps
 * between fetches. Names already present are replaced, which is what makes the
 * response's own Set-Cookie win over a stale seed. */
static void jar_seed(jar *j, const char *cookies) {
    const char *p = cookies;
    while (p && *p) {
        const char *semi = strchr(p, ';');
        size_t len = semi ? (size_t)(semi - p) : strlen(p);
        while (len > 0 && (*p == ' ' || *p == '\t')) {
            p++;
            len--;
        }
        while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t')) {
            len--;
        }
        if (len > 0 && len < 1024) {
            char pair[1024];
            memcpy(pair, p, len);
            pair[len] = '\0';
            jar_set(j, pair);
        }
        if (!semi) break;
        p = semi + 1;
    }
}

static char *jar_header(jar *j) {
    size_t total = 1;
    for (size_t i = 0; i < j->n; i++) total += strlen(j->items[i]) + 2;
    char *h = malloc(total);
    if (!h) return NULL;
    h[0] = '\0';
    for (size_t i = 0; i < j->n; i++) {
        if (i) strcat(h, "; ");
        strcat(h, j->items[i]);
    }
    return h;
}

static void jar_free(jar *j) {
    for (size_t i = 0; i < j->n; i++) free(j->items[i]);
    free(j->items);
    j->items = NULL;
    j->n = j->cap = 0;
}

/* ------------------------------------------------------------------- URL */

typedef struct {
    char scheme[8];
    char host[256];
    int port;
    char path[4096];
} url_t;

static int parse_url(const char *url, url_t *u) {
    const char *p = strstr(url, "://");
    const char *rest, *slash;
    size_t sl;
    if (!p) return -1;
    sl = (size_t)(p - url);
    if (sl >= sizeof u->scheme) return -1;
    memcpy(u->scheme, url, sl);
    u->scheme[sl] = '\0';
    rest = p + 3;
    slash = strchr(rest, '/');
    {
        const char *host_end = slash ? slash : rest + strlen(rest);
        const char *colon = memchr(rest, ':', (size_t)(host_end - rest));
        size_t hl = (size_t)((colon ? colon : host_end) - rest);
        if (hl == 0 || hl >= sizeof u->host) return -1;
        memcpy(u->host, rest, hl);
        u->host[hl] = '\0';
        u->port = strcmp(u->scheme, "https") == 0 ? 443 : 80;
        if (colon) u->port = atoi(colon + 1);
        snprintf(u->path, sizeof u->path, "%s", slash ? slash : "/");
    }
    if (strcmp(u->scheme, "http") && strcmp(u->scheme, "https")) return -1;
    return 0;
}

/* --------------------------------------------------------- one HTTP GET */

static int tcp_connect(const char *host, int port) {
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[16];
    int fd = -1;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        {
            struct timeval tv = {20, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int ssl_read_all(SSL *ssl, buf *out) {
    char tmp[16384];
    for (;;) {
        int n = SSL_read(ssl, tmp, sizeof tmp);
        if (n <= 0) {
            int e = SSL_get_error(ssl, n);
            if (e == SSL_ERROR_ZERO_RETURN) return 0;
            if (e == SSL_ERROR_SYSCALL && ERR_peek_error() == 0) return 0;
            return -1;
        }
        if (buf_add(out, tmp, (size_t)n) != 0) return -1;
    }
}

static int read_all(int fd, buf *out) {
    char tmp[16384];
    for (;;) {
        ssize_t n = read(fd, tmp, sizeof tmp);
        if (n == 0) return 0;
        if (n < 0) return (errno == EINTR) ? 0 : -1;
        if (buf_add(out, tmp, (size_t)n) != 0) return -1;
    }
}

static int decode_chunked(const char *in, size_t inlen, buf *out) {
    size_t i = 0;
    for (;;) {
        char sz[32];
        size_t k = 0, n;
        while (i < inlen && k < sizeof sz - 1 && in[i] != '\r' && in[i] != '\n') sz[k++] = in[i++];
        sz[k] = '\0';
        if (k == 0) break;
        n = (size_t)strtoul(sz, NULL, 16);
        while (i < inlen && in[i] != '\n') i++;
        if (i < inlen) i++;
        if (n == 0) break;
        if (i + n > inlen) n = inlen - i;
        if (buf_add(out, in + i, n) != 0) return -1;
        i += n;
        while (i < inlen && (in[i] == '\r' || in[i] == '\n')) i++;
    }
    return 0;
}

static int http_get(const char *url, jar *j, const char *extra_headers,
                    anubis_page *out, char **headers, size_t *headers_len) {
    url_t u;
    int fd = -1, rc = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    buf raw = {0};
    char *cookie = NULL;
    char *req = NULL;

    if (parse_url(url, &u) != 0) {
        seterr(out, "bad url");
        return -1;
    }
    fd = tcp_connect(u.host, u.port);
    if (fd < 0) {
        seterr(out, "connect failed");
        return -1;
    }
    if (strcmp(u.scheme, "https") == 0) {
        const char *insecure = getenv("ANUBIS_INSECURE");
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            seterr(out, "tls init failed");
            goto done;
        }
        SSL_CTX_set_default_verify_paths(ctx);
        SSL_CTX_set_verify(ctx, (insecure && *insecure == '1') ? SSL_VERIFY_NONE
                                                               : SSL_VERIFY_PEER,
                           NULL);
        ssl = SSL_new(ctx);
        if (!ssl || SSL_set_fd(ssl, fd) != 1) {
            seterr(out, "tls setup failed");
            goto done;
        }
        SSL_set_tlsext_host_name(ssl, u.host);
        SSL_set1_host(ssl, u.host);
        if (SSL_connect(ssl) != 1) {
            seterr(out, "tls handshake failed");
            goto done;
        }
    }

    cookie = jar_header(j);
    {
        size_t cap = 2048 + strlen(u.path) + strlen(u.host) + (cookie ? strlen(cookie) : 0);
        req = malloc(cap);
        /* Each header owns its line: the cookie is formatted as a complete
         * "Cookie: ...\r\n" line, and extra_headers (currently unused) must be
         * supplied the same way. Concatenating a value straight into the next
         * header is what silently dropped the auth cookie once. */
        {
            char *cookie_line = NULL;
            size_t clen = 0;
            size_t cap = 2048 + strlen(u.path) + strlen(u.host) +
                         (cookie ? strlen(cookie) : 0) +
                         (extra_headers ? strlen(extra_headers) : 0);
            if (cookie != NULL && *cookie != '\0') {
                clen = strlen(cookie) + 16;
                cookie_line = malloc(clen);
                if (!cookie_line) {
                    seterr(out, "oom");
                    goto done;
                }
                snprintf(cookie_line, clen, "Cookie: %s\r\n", cookie);
            }
            cap += clen;
            req = malloc(cap);
            if (!req) {
                free(cookie_line);
                seterr(out, "oom");
                goto done;
            }
            snprintf(req, cap,
                     "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                     "Accept: text/html,application/json;q=0.9,*/*;q=0.8\r\n"
                     "Accept-Encoding: identity\r\n%s%s"
                     "Connection: close\r\n\r\n",
                     u.path, u.host, UA,
                     extra_headers ? extra_headers : "",
                     cookie_line ? cookie_line : "");
            free(cookie_line);
        }
    }
    if (ssl) {
        if (SSL_write(ssl, req, (int)strlen(req)) <= 0) {
            seterr(out, "tls write failed");
            goto done;
        }
        if (ssl_read_all(ssl, &raw) != 0) {
            seterr(out, "tls read failed");
            goto done;
        }
    } else {
        if (write(fd, req, strlen(req)) < 0) {
            seterr(out, "write failed");
            goto done;
        }
        if (read_all(fd, &raw) != 0) {
            seterr(out, "read failed");
            goto done;
        }
    }

    {
        char *hdr_end = strstr(raw.data, "\r\n\r\n");
        char *body = hdr_end ? hdr_end + 4 : raw.data;
        size_t body_len = hdr_end ? raw.len - (size_t)(body - raw.data) : raw.len;
        char *line = raw.data;
        int chunked = 0;
        long content_length = -1;

        /* The header block as it arrived, status line included. */
        if (headers != NULL) {
            *headers = NULL;
            if (headers_len != NULL) {
                *headers_len = 0;
            }
            if (hdr_end != NULL) {
                size_t hl = (size_t)(hdr_end - raw.data);
                char *copy = malloc(hl + 1);
                if (copy != NULL) {
                    memcpy(copy, raw.data, hl);
                    copy[hl] = '\0';
                    *headers = copy;
                    if (headers_len != NULL) {
                        *headers_len = hl;
                    }
                }
            }
        }

        out->status = 0;
        if (strncmp(line, "HTTP/", 5) == 0) {
            char *sp = strchr(line, ' ');
            if (sp) out->status = atoi(sp + 1);
        }
        /* headers */
        {
            char *p = strstr(raw.data, "\r\n");
            while (p && p < body) {
                char *next = strstr(p + 2, "\r\n");
                size_t len = next ? (size_t)(next - (p + 2)) : 0;
                if (strncasecmp(p + 2, "Set-Cookie:", 11) == 0) {
                    char v[1024];
                    size_t k = 0;
                    const char *s = p + 2 + 11;
                    while (*s == ' ') s++;
                    while (k < sizeof v - 1 && s + k < (next ? next : body) && s[k] != ';') {
                        v[k] = s[k];
                        k++;
                    }
                    v[k] = '\0';
                    if (k) jar_set(j, v);
                } else if (strncasecmp(p + 2, "Content-Length:", 15) == 0) {
                    content_length = atol(p + 2 + 15);
                } else if (strncasecmp(p + 2, "Transfer-Encoding:", 18) == 0 &&
                           strcasestr(p + 2, "chunked")) {
                    chunked = 1;
                } else if (strncasecmp(p + 2, "Location:", 9) == 0) {
                    char v[2048];
                    size_t k = 0;
                    const char *s = p + 2 + 9;
                    while (*s == ' ') s++;
                    while (k < sizeof v - 1 && s + k < (next ? next : body) && s[k] != '\r') {
                        v[k] = s[k];
                        k++;
                    }
                    v[k] = '\0';
                    free(out->final_url);
                    out->final_url = xstrdup(v);
                }
                if (!next) break;
                p = next;
                if (len > MAX_HEADER) break;
            }
        }
        if (chunked) {
            buf dec = {0};
            if (decode_chunked(body, body_len, &dec) == 0) {
                out->body = dec.data;
                out->body_len = dec.len;
            } else {
                seterr(out, "chunked decode failed");
                goto done;
            }
        } else {
            size_t take = body_len;
            if (content_length >= 0 && (size_t)content_length < take) take = (size_t)content_length;
            if (take > MAX_BODY) take = MAX_BODY;
            out->body = malloc(take + 1);
            if (!out->body) {
                seterr(out, "oom");
                goto done;
            }
            memcpy(out->body, body, take);
            out->body[take] = '\0';
            out->body_len = take;
        }
    }
    rc = 0;

done:
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
    if (fd >= 0) close(fd);
    free(raw.data);
    free(cookie);
    free(req);
    return rc;
}

/* --------------------------------------------------- transport dispatch */

/* One get, through whichever transport this session selected. The cookie jar
 * is only used by the built-in client; libcurl keeps its own. */
typedef struct {
    anubis_imp_handle *imp;
    jar j;
} xport;

static int xport_get(xport *x, const char *url, anubis_page *out,
                     char **headers, size_t *headers_len) {
    if (x->imp) {
        const char *insecure = getenv("ANUBIS_INSECURE");
        return anubis_imp_get(x->imp, url, insecure && *insecure == '1', out,
                              headers, headers_len);
    }
    return http_get(url, &x->j, NULL, out, headers, headers_len);
}

static void xport_seed_cookies(xport *x, const char *cookies) {
    if (cookies == NULL || *cookies == '\0') {
        return;
    }
    if (x->imp) {
        anubis_imp_set_cookies(x->imp, cookies);
    } else {
        jar_seed(&x->j, cookies);
    }
}

/* The jar as it stands after the exchange: the seed plus everything the site
 * set, with the site's values winning. The impersonating transport keeps its
 * own jar, so merge rather than replace. */
static char *xport_cookies(xport *x, const char *seed) {
    char *header;
    if (!x->imp) {
        return jar_header(&x->j);
    }
    {
        jar j = {0};
        char *list = NULL;
        if (seed != NULL) {
            jar_seed(&j, seed);
        }
        if (anubis_imp_cookies(x->imp, &list) == 0 && list != NULL) {
            jar_seed(&j, list);
            free(list);
        }
        header = jar_header(&j);
        jar_free(&j);
    }
    return header;
}

static void xport_close(xport *x) {
    if (x->imp) {
        anubis_imp_close(x->imp);
        x->imp = NULL;
    }
    jar_free(&x->j);
}

/* ------------------------------------------------------------------ JSON */

static int json_string(const char *json, const char *key, char *out, size_t cap) {
    char pat[64];
    const char *p;
    size_t k = 0;
    snprintf(pat, sizeof pat, "\"%s\"", key);
    p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == ':') p++;
    if (*p != '"') return 0;
    p++;
    while (*p && *p != '"' && k < cap - 1) {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
                case 'n': out[k++] = '\n'; break;
                case 't': out[k++] = '\t'; break;
                case '"': out[k++] = '"'; break;
                case '\\': out[k++] = '\\'; break;
                default: out[k++] = *p; break;
            }
            p++;
        } else {
            out[k++] = *p++;
        }
    }
    out[k] = '\0';
    return k > 0;
}

static int json_int(const char *json, const char *key, long *out) {
    char pat[64];
    const char *p;
    snprintf(pat, sizeof pat, "\"%s\"", key);
    p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == ':') p++;
    if (!isdigit((unsigned char)*p) && *p != '-') return 0;
    *out = strtol(p, NULL, 10);
    return 1;
}

/* ---------------------------------------------------------- raw challenge */

/* A challenge page is small; a caller handing us a whole page should still
 * fit, but anything past this is a mistake or an attack on memory. */
#define RAW_CHALLENGE_MAX_INPUT (4u << 20)

/* Bounded, case-insensitive substring search. strcasestr() would keep going
 * past the end of an extracted script body. */
static const char *find_ci(const char *hay, size_t haylen, const char *needle) {
    size_t n = strlen(needle);
    size_t i;
    if (n == 0 || haylen < n) {
        return NULL;
    }
    for (i = 0; i + n <= haylen; i++) {
        if (strncasecmp(hay + i, needle, n) == 0) {
            return hay + i;
        }
    }
    return NULL;
}

/* Decode the handful of HTML entities that can appear if a page escaped its
 * JSON script instead of emitting it raw. Hex random data and UUIDs are
 * unaffected; this only makes the JSON parseable again. */
static void raw_entity_decode(const char *in, size_t len, char *out) {
    static const struct {
        const char *entity;
        char value;
    } table[] = {
        {"&quot;", '"'}, {"&#34;", '"'}, {"&#x22;", '"'}, {"&apos;", '\''},
        {"&#39;", '\''}, {"&#x27;", '\''}, {"&lt;", '<'},   {"&gt;", '>'},
        {"&amp;", '&'},
    };
    size_t i = 0, o = 0;
    while (i < len) {
        size_t k;
        int matched = 0;
        if (in[i] == '&') {
            for (k = 0; k < sizeof table / sizeof table[0]; k++) {
                size_t n = strlen(table[k].entity);
                if (i + n <= len && strncasecmp(in + i, table[k].entity, n) == 0) {
                    out[o++] = table[k].value;
                    i += n;
                    matched = 1;
                    break;
                }
            }
        }
        if (!matched) {
            out[o++] = in[i++];
        }
    }
    out[o] = '\0';
}

/* Find the JSON body of the challenge: <script id="anubis_challenge"> first,
 * then any application/json script whose contents look like a challenge, then
 * the whole input when it is already just the JSON payload. Returns 0 and
 * allocates a NUL-terminated, entity-decoded copy in *out. */
static int raw_extract_json(const char *input, size_t len, char **out,
                            char *err, size_t errcap) {
    const char *end = input + len;
    const char *content = NULL;
    size_t content_len = 0;
    const char *p = input;

    while ((p = find_ci(p, (size_t)(end - p), "<script")) != NULL) {
        const char *gt = memchr(p, '>', (size_t)(end - p));
        const char *close;
        if (gt == NULL) {
            break;
        }
        close = find_ci(gt + 1, (size_t)(end - (gt + 1)), "</script");
        if (close == NULL) {
            break;
        }
        if (find_ci(p, (size_t)(gt - p), "anubis_challenge") != NULL ||
            (find_ci(p, (size_t)(gt - p), "application/json") != NULL &&
             find_ci(gt + 1, (size_t)(close - (gt + 1)), "\"rules\"") != NULL &&
             (find_ci(gt + 1, (size_t)(close - (gt + 1)), "\"challenge\"") != NULL ||
              find_ci(gt + 1, (size_t)(close - (gt + 1)), "\"randomData\"") != NULL))) {
            content = gt + 1;
            content_len = (size_t)(close - content);
            break;
        }
        p = close + 8;
    }

    if (content == NULL) {
        /* No script element: accept the bare payload. */
        if (find_ci(input, len, "\"rules\"") != NULL &&
            (find_ci(input, len, "\"challenge\"") != NULL ||
             find_ci(input, len, "\"randomData\"") != NULL)) {
            content = input;
            content_len = len;
        } else {
            snprintf(err, errcap,
                     "input is not an Anubis challenge (no anubis_challenge "
                     "script and no challenge/rules JSON)");
            return -1;
        }
    }

    *out = malloc(content_len + 1);
    if (*out == NULL) {
        snprintf(err, errcap, "out of memory");
        return -1;
    }
    raw_entity_decode(content, content_len, *out);
    return 0;
}

int anubis_parse_challenge_input(const char *input, size_t len,
                                 anubis_raw_challenge *out, char *err,
                                 size_t errcap) {
    char *json = NULL;
    const char *scope;
    char local_err[256];
    long difficulty = 0;
    size_t i;

    if (err == NULL) {
        err = local_err;
        errcap = sizeof local_err;
    }
    if (out == NULL || input == NULL) {
        snprintf(err, errcap, "no challenge input");
        return -1;
    }
    memset(out, 0, sizeof *out);

    if (len > RAW_CHALLENGE_MAX_INPUT) {
        snprintf(err, errcap, "challenge input is too large");
        return -1;
    }
    if (len == 0) {
        snprintf(err, errcap, "empty challenge input");
        return -1;
    }
    if (raw_extract_json(input, len, &json, err, errcap) != 0) {
        return -1;
    }

    scope = strstr(json, "\"rules\"");
    if (scope == NULL) {
        scope = json;
    }
    if (!json_string(scope, "algorithm", out->algorithm,
                     sizeof out->algorithm)) {
        snprintf(err, errcap, "challenge has no rules.algorithm");
        free(json);
        return -1;
    }
    if (!json_int(scope, "difficulty", &difficulty) || difficulty < 0 ||
        difficulty > (1 << 20)) {
        snprintf(err, errcap, "challenge has no valid rules.difficulty");
        free(json);
        return -1;
    }
    out->difficulty = (int)difficulty;

    /* v1.22+ nests the payload under "challenge"; older pages and the
     * make-challenge reply keep the string at the top level. */
    if (!json_string(json, "randomData", out->random_data,
                     sizeof out->random_data) &&
        !json_string(json, "challenge", out->random_data,
                     sizeof out->random_data)) {
        snprintf(err, errcap, "challenge has no randomData/challenge payload");
        free(json);
        return -1;
    }
    if (out->random_data[0] == '\0') {
        snprintf(err, errcap, "challenge payload is empty");
        free(json);
        return -1;
    }

    (void)json_string(json, "id", out->id, sizeof out->id);

    for (i = 0; out->algorithm[i] != '\0'; i++) {
        out->algorithm[i] =
            (char)tolower((unsigned char)out->algorithm[i]);
    }
    free(json);
    return 0;
}

/* Append "name=<url-encoded value>" (prefixed with & unless it is first) to
 * the fixed raw buffer. Returns the new offset, or (size_t)-1 when it does not
 * fit. */
static size_t raw_kv(char *raw, size_t cap, size_t off, int first,
                     const char *name, const char *value) {
    char *enc = url_encode(value);
    int n;
    if (enc == NULL) {
        return (size_t)-1;
    }
    n = snprintf(raw + off, cap - off, "%s%s=%s", first ? "" : "&", name, enc);
    free(enc);
    if (n < 0 || (size_t)n >= cap - off) {
        return (size_t)-1;
    }
    return off + (size_t)n;
}

int anubis_solve_challenge_input(const char *input, size_t len, int threads,
                                 double budget_ms, anubis_raw_solution *out,
                                 char *err, size_t errcap) {
    int rc = 0;
    double ms = 0.0;
    unsigned long long nonce = 0;
    size_t off = 0;
    char local_err[256];
    int is_pow = 1;

    if (err == NULL) {
        err = local_err;
        errcap = sizeof local_err;
    }
    if (out == NULL) {
        snprintf(err, errcap, "no output");
        return -1;
    }
    memset(out, 0, sizeof *out);
    if (threads < 0) {
        snprintf(err, errcap, "threads must be non-negative");
        return -1;
    }
    if (budget_ms < 0.0) {
        budget_ms = 0.0;
    }
    if (anubis_parse_challenge_input(input, len, &out->challenge, err,
                                     errcap) != 0) {
        return -1;
    }

    const char *alg = out->challenge.algorithm;
    if (!strcasecmp(alg, "fast") || !strcasecmp(alg, "slow")) {
        uint64_t n = 0;
        rc = anubis_solve_nibbles(out->challenge.random_data,
                                  out->challenge.difficulty, threads, 0,
                                  budget_ms, &n, out->response, &ms);
        nonce = (unsigned long long)n;
    } else if (!strcasecmp(alg, "sha256") || !strcasecmp(alg, "wasm-sha256")) {
        uint32_t n = 0;
        rc = anubis_solve_bits(out->challenge.random_data,
                               out->challenge.difficulty, threads, budget_ms,
                               &n, out->response, &ms);
        nonce = n;
    } else if (!strcasecmp(alg, "argon2id")) {
        uint32_t n = 0;
        rc = anubis_solve_argon2id(out->challenge.random_data,
                                   out->challenge.difficulty, threads,
                                   budget_ms, &n, out->response, &ms);
        nonce = n;
    } else if (!strcasecmp(alg, "hashx")) {
        uint32_t n = 0;
        rc = anubis_solve_hashx(out->challenge.random_data,
                                out->challenge.difficulty, threads, budget_ms,
                                &n, out->response, &ms);
        nonce = n;
    } else if (!strcasecmp(alg, "meatrider")) {
        uint32_t n = 0;
        rc = anubis_solve_meatrider(out->challenge.random_data,
                                    out->challenge.difficulty, threads,
                                    budget_ms, &n, out->response, &ms);
        nonce = n;
    } else if (!strcasecmp(alg, "tensor")) {
        uint32_t n = 0;
        rc = anubis_solve_tensor(out->challenge.random_data,
                                 out->challenge.difficulty, threads, budget_ms,
                                 &n, out->response, &ms);
        nonce = n;
    } else if (!strcasecmp(alg, "preact")) {
        /* preact is a hash echo plus a server-side delay, not a search. */
        if (anubis_sha256_hex(out->challenge.random_data,
                              strlen(out->challenge.random_data),
                              out->response) != 0) {
            snprintf(err, errcap, "preact hash failed");
            return -1;
        }
        out->wait_ms = out->challenge.difficulty * 100 + 100;
        is_pow = 0;
    } else if (!strcasecmp(alg, "metarefresh")) {
        /* Nothing to compute; the server only checks elapsed time. */
        out->wait_ms = out->challenge.difficulty * 800 + 200;
        is_pow = 0;
        rc = ANUBIS_OK;
        ms = 0.0;
    } else {
        snprintf(err, errcap, "unknown challenge algorithm '%s'", alg);
        return -1;
    }

    if (is_pow && rc != ANUBIS_OK) {
        if (rc == ANUBIS_ERR_ARG) {
            snprintf(err, errcap,
                     "invalid challenge for %s (hex required for every "
                     "algorithm except fast/slow)",
                     alg);
        } else if (rc == ANUBIS_ERR_UNSOLVED) {
            snprintf(err, errcap, "no solution found for %s at difficulty %d",
                     alg, out->challenge.difficulty);
        } else {
            snprintf(err, errcap, "solver error %d for %s", rc, alg);
        }
        return -1;
    }

    out->nonce = nonce;
    out->elapsed_ms = (ms >= 0.0) ? ms : 0.0;
    if (strlen(out->response) != 64 && is_pow) {
        snprintf(err, errcap, "solver returned a malformed digest");
        return -1;
    }

    if (out->challenge.id[0] != '\0') {
        off = raw_kv(out->raw, sizeof out->raw, off, 1, "id",
                     out->challenge.id);
        if (off == (size_t)-1) {
            snprintf(err, errcap, "raw result is too large");
            return -1;
        }
    }
    if (is_pow) {
        off = raw_kv(out->raw, sizeof out->raw, off, off == 0, "response",
                     out->response);
    } else if (!strcasecmp(alg, "preact")) {
        off = raw_kv(out->raw, sizeof out->raw, off, off == 0, "result",
                     out->response);
    } else {
        off = raw_kv(out->raw, sizeof out->raw, off, off == 0, "challenge",
                     out->challenge.random_data);
    }
    if (off == (size_t)-1 || off >= sizeof out->raw) {
        snprintf(err, errcap, "raw result is too large");
        return -1;
    }
    {
        int n;
        if (is_pow) {
            n = snprintf(out->raw + off, sizeof out->raw - off,
                         "&nonce=%llu&elapsedTime=1", nonce);
        } else {
            n = snprintf(out->raw + off, sizeof out->raw - off,
                         "&elapsedTime=%d", out->wait_ms);
        }
        if (n < 0 || (size_t)n >= sizeof out->raw - off) {
            snprintf(err, errcap, "raw result is too large");
            return -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ solve */

static int solve_algorithm(const char *algorithm, const char *challenge,
                           int difficulty, uint32_t *nonce, char *digest,
                           size_t digest_cap) {
    int rc;
    if (!strcasecmp(algorithm, "fast") || !strcasecmp(algorithm, "slow")) {
        uint64_t n64 = 0;
        rc = anubis_solve_nibbles(challenge, difficulty, 0, 0, 0.0, &n64, digest, NULL);
        *nonce = (uint32_t)n64;
    } else if (!strcasecmp(algorithm, "sha256") || !strcasecmp(algorithm, "wasm-sha256")) {
        rc = anubis_solve_bits(challenge, difficulty, 0, 0, nonce, digest, NULL);
    } else if (!strcasecmp(algorithm, "argon2id")) {
        rc = anubis_solve_argon2id(challenge, difficulty, 0, 0, nonce, digest, NULL);
    } else if (!strcasecmp(algorithm, "hashx")) {
        rc = anubis_solve_hashx(challenge, difficulty, 0, 0, nonce, digest, NULL);
    } else if (!strcasecmp(algorithm, "meatrider")) {
        rc = anubis_solve_meatrider(challenge, difficulty, 0, 0, nonce, digest, NULL);
    } else if (!strcasecmp(algorithm, "tensor")) {
        rc = anubis_solve_tensor(challenge, difficulty, 0, 0, nonce, digest, NULL);
    } else {
        return -1;
    }
    (void)digest_cap;
    return rc == ANUBIS_OK ? 0 : -1;
}

static int is_challenge_page(const char *body) {
    return body && (strstr(body, "anubis_challenge") != NULL ||
                    strstr(body, "Anubis") != NULL);
}

static char *origin_of(const char *url) {
    url_t u;
    char *o;
    if (parse_url(url, &u) != 0) return NULL;
    o = malloc(300);
    if (!o) return NULL;
    if ((strcmp(u.scheme, "https") == 0 && u.port == 443) ||
        (strcmp(u.scheme, "http") == 0 && u.port == 80)) {
        snprintf(o, 300, "%s://%s", u.scheme, u.host);
    } else {
        snprintf(o, 300, "%s://%s:%d", u.scheme, u.host, u.port);
    }
    return o;
}

static char *join_url(const char *base, const char *path) {
    size_t n;
    char *r;
    if (strstr(path, "://")) return xstrdup(path);
    if (path[0] == '/') {
        char *origin = origin_of(base);
        n = strlen(origin) + strlen(path) + 1;
        r = malloc(n);
        snprintf(r, n, "%s%s", origin, path);
        free(origin);
        return r;
    }
    n = strlen(base) + strlen(path) + 2;
    r = malloc(n);
    snprintf(r, n, "%s/%s", base, path);
    return r;
}

static void sleep_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* ------------------------------------------------------------------- API */

/* ---- impersonation configuration ------------------------------------- */

/* Empty string means "auto": impersonate when a library is installed.
 * "off" forces the built-in OpenSSL client. */
static char g_target[64];
static int g_off;

static int is_off_word(const char *s) {
    if (!s) return 0;
    return !strcasecmp(s, "off") || !strcmp(s, "0") || !strcasecmp(s, "none") ||
           !strcasecmp(s, "no") || !strcasecmp(s, "openssl") ||
           !strcasecmp(s, "false");
}

static int is_auto_word(const char *s) {
    return !s || !*s || !strcasecmp(s, "auto");
}

static __thread char t_transport[64] = "openssl";

const char *anubis_fetch_transport(void) {
    return t_transport;
}

int anubis_fetch_impersonate_available(void) {
    return anubis_imp_load(NULL, 0) == 0;
}

int anubis_fetch_set_impersonate(const char *target) {
    char resolved[64];
    char err[512] = "";

    if (is_auto_word(target)) {
        g_target[0] = '\0';
        g_off = 0;
        return 0;
    }
    if (is_off_word(target)) {
        g_target[0] = '\0';
        g_off = 1;
        return 0;
    }
    if (anubis_imp_load(err, sizeof err) != 0) return -1;
    if (anubis_imp_resolve_target(target, resolved, sizeof resolved) != 0) return -1;
    snprintf(g_target, sizeof g_target, "%s", resolved);
    g_off = 0;
    return 0;
}

const char *anubis_fetch_impersonate(void) {
    static __thread char buf[64];
    if (g_off) return "";
    if (g_target[0]) return g_target;
    if (anubis_imp_load(NULL, 0) != 0) return "";
    if (anubis_imp_resolve_target("chrome", buf, sizeof buf) != 0) return "";
    return buf;
}

/* Decide the transport for one fetch. Reads $ANUBIS_IMPERSONATE first (so a
 * deployment can pin a profile without recompiling or re-calling the setter),
 * then the per-call target, then the process default. */
static int open_transport(xport *x, const char *target, anubis_page *out) {
    const char *env = getenv("ANUBIS_IMPERSONATE");
    const char *want;
    int strict = 0;
    char err[512] = "";

    if (env && *env) {
        want = env;
        strict = 1;
    } else if (target && *target) {
        want = target;
        strict = 1;
    } else if (g_off) {
        want = "off";
    } else if (g_target[0]) {
        want = g_target;
        strict = 1;
    } else {
        want = "auto";
    }

    snprintf(t_transport, sizeof t_transport, "openssl");
    if (is_off_word(want)) return 0;

    if (is_auto_word(want)) {
        /* Best effort: no library, no impersonation, no error. */
        if (anubis_imp_load(NULL, 0) != 0) return 0;
    }
    x->imp = anubis_imp_open(is_auto_word(want) ? "chrome" : want, err, sizeof err);
    if (!x->imp) {
        if (strict) {
            snprintf(out->error, sizeof out->error,
                     "impersonation requested but unavailable: %s", err);
            return -1;
        }
        return 0;
    }
    snprintf(t_transport, sizeof t_transport, "curl-impersonate/%s",
             anubis_imp_handle_target(x->imp));
    return 0;
}

const char *anubis_fetch_version(void) {
    return "2.50 \"mule\"";
}

void anubis_page_free(anubis_page *page) {
    if (!page) return;
    free(page->body);
    free(page->final_url);
    memset(page, 0, sizeof *page);
}

/* Append one response's header block to the running dump. Blocks already end
 * with CRLF; the extra newline only keeps them apart when one does not. */
static int hdr_append(char **acc, size_t *acc_len, const char *block,
                      size_t len) {
    char *n;
    if (block == NULL || len == 0) {
        return 0;
    }
    n = realloc(*acc, *acc_len + len + 2);
    if (n == NULL) {
        return -1;
    }
    memcpy(n + *acc_len, block, len);
    *acc_len += len;
    if (n[*acc_len - 1] != '\n') {
        n[(*acc_len)++] = '\n';
    }
    n[*acc_len] = '\0';
    *acc = n;
    return 0;
}

/* Cookie state for one exchange. `cookies` is the caller's jar going in;
 * out_cookies comes back owned by the caller. */
typedef struct {
    const char *cookies;
    char *out_cookies;
    int solved;
    int expired;
} fetch_cookies;

static int fetch_impl(const char *url, const char *target, anubis_page *out,
                      char **headers, size_t *headers_len, fetch_cookies *ck) {
    xport x = {0};
    char *current = xstrdup(url);
    char *acc = NULL;
    size_t acc_len = 0;
    int attempt;
    int rc = -1;

    if (!out) return -1;
    memset(out, 0, sizeof *out);
    if (headers != NULL) {
        *headers = NULL;
    }
    if (headers_len != NULL) {
        *headers_len = 0;
    }
    if (!url || !current) {
        snprintf(out->error, sizeof out->error, "bad url");
        free(current);
        return -1;
    }
    if (open_transport(&x, target, out) != 0) {
        free(current);
        return -1;
    }
    if (ck != NULL) {
        ck->out_cookies = NULL;
        ck->solved = 0;
        ck->expired = 0;
        xport_seed_cookies(&x, ck->cookies);
    }

    for (attempt = 0; attempt < 8; attempt++) {
        anubis_page page = {0};
        char *page_hdr = NULL;
        size_t page_hdr_len = 0;

        if (xport_get(&x, current, &page, headers ? &page_hdr : NULL,
                      headers ? &page_hdr_len : NULL) != 0) {
            snprintf(out->error, sizeof out->error, "%s", page.error);
            free(page_hdr);
            anubis_page_free(&page);
            goto done;
        }
        /* Accumulate before any branch: the dump wants every response, not
         * just the one that finally carried the page. */
        if (headers != NULL &&
            hdr_append(&acc, &acc_len, page_hdr, page_hdr_len) != 0) {
            snprintf(out->error, sizeof out->error, "out of memory");
            free(page_hdr);
            anubis_page_free(&page);
            goto done;
        }
        free(page_hdr);
        if (page.final_url && (page.status == 301 || page.status == 302 ||
                               page.status == 303 || page.status == 307 ||
                               page.status == 308)) {
            char *next = join_url(current, page.final_url);
            anubis_page_free(&page);
            free(current);
            current = next;
            continue;
        }
        if (is_challenge_page(page.body) && strstr(page.body, "anubis_challenge")) {
            char algorithm[32] = "sha256", random_data[1024] = "", id[256] = "";
            if (ck != NULL) {
                ck->solved = 1;
                if (ck->cookies != NULL && *ck->cookies != '\0') {
                    ck->expired = 1; /* the site did not accept them */
                }
            }
            long difficulty = 0;
            uint32_t nonce = 0;
            char digest[65] = "";
            char *origin, *pass, *enc_id, *enc_rd, *enc_resp, *enc_redir;
            anubis_page solved = {0};

            json_string(page.body, "algorithm", algorithm, sizeof algorithm);
            json_string(page.body, "randomData", random_data, sizeof random_data);
            json_string(page.body, "id", id, sizeof id);
            json_int(page.body, "difficulty", &difficulty);

            if (random_data[0] == '\0') {
                snprintf(out->error, sizeof out->error, "challenge without randomData");
                anubis_page_free(&page);
                goto done;
            }
            origin = origin_of(current);
            if (!origin) {
                snprintf(out->error, sizeof out->error, "bad url");
                anubis_page_free(&page);
                goto done;
            }
            enc_id = url_encode(id);
            enc_rd = url_encode(random_data);
            enc_redir = url_encode(current);

            if (!strcasecmp(algorithm, "metarefresh")) {
                sleep_ms((long)difficulty * 800 + 200);
                pass = malloc(strlen(origin) + strlen(enc_rd) + strlen(enc_redir) +
                              strlen(enc_id) + 256);
                sprintf(pass,
                        "%s/.within.website/x/cmd/anubis/api/pass-challenge"
                        "?challenge=%s&id=%s&redir=%s&elapsedTime=%ld",
                        origin, enc_rd, enc_id, enc_redir, difficulty * 800 + 200);
            } else if (!strcasecmp(algorithm, "preact")) {
                char hash[65];
                anubis_sha256_hex(random_data, strlen(random_data), hash);
                sleep_ms((long)difficulty * 100 + 100);
                enc_resp = url_encode(hash);
                pass = malloc(strlen(origin) + strlen(enc_resp) + strlen(enc_redir) +
                              strlen(enc_id) + 256);
                sprintf(pass,
                        "%s/.within.website/x/cmd/anubis/api/pass-challenge"
                        "?result=%s&id=%s&redir=%s&elapsedTime=%ld",
                        origin, enc_resp, enc_id, enc_redir, difficulty * 100 + 100);
                free(enc_resp);
            } else {
                if (solve_algorithm(algorithm, random_data, (int)difficulty, &nonce,
                                    digest, sizeof digest) != 0) {
                    snprintf(out->error, sizeof out->error,
                             "cannot solve %s difficulty %ld", algorithm, difficulty);
                    free(origin); free(enc_id); free(enc_rd); free(enc_redir);
                    anubis_page_free(&page);
                    goto done;
                }
                enc_resp = url_encode(digest);
                pass = malloc(strlen(origin) + strlen(enc_resp) + strlen(enc_redir) +
                              strlen(enc_id) + 256);
                sprintf(pass,
                        "%s/.within.website/x/cmd/anubis/api/pass-challenge"
                        "?id=%s&response=%s&nonce=%u&redir=%s&elapsedTime=1",
                        origin, enc_id, enc_resp, nonce, enc_redir);
                free(enc_resp);
            }
            free(origin);
            free(enc_id);
            free(enc_rd);
            free(enc_redir);

            {
                char *solved_hdr = NULL;
                size_t solved_hdr_len = 0;

                if (xport_get(&x, pass, &solved,
                              headers ? &solved_hdr : NULL,
                              headers ? &solved_hdr_len : NULL) != 0) {
                    snprintf(out->error, sizeof out->error,
                             "pass-challenge failed: %.200s", solved.error);
                    free(solved_hdr);
                    free(pass);
                    anubis_page_free(&solved);
                    anubis_page_free(&page);
                    goto done;
                }
                free(pass);
                if (headers != NULL &&
                    hdr_append(&acc, &acc_len, solved_hdr, solved_hdr_len) != 0) {
                    snprintf(out->error, sizeof out->error, "out of memory");
                    free(solved_hdr);
                    anubis_page_free(&solved);
                    anubis_page_free(&page);
                    goto done;
                }
                free(solved_hdr);
                anubis_page_free(&solved);
            }
            anubis_page_free(&page);
            continue; /* re-fetch the original URL with the new cookie */
        }

        *out = page;
        if (!out->final_url) out->final_url = xstrdup(current);
        if (headers != NULL) {
            *headers = acc;
            acc = NULL;
        }
        if (headers_len != NULL) {
            *headers_len = acc_len;
        }
        if (ck != NULL) {
            ck->out_cookies = xport_cookies(&x, ck->cookies);
        }
        rc = 0;
        break;
    }
    if (rc != 0) {
        snprintf(out->error, sizeof out->error, "too many challenge rounds");
    }

done:
    free(acc);
    free(current);
    xport_close(&x);
    return rc;
}

int anubis_fetch_get_with(const char *url, const char *target, anubis_page *out) {
    return fetch_impl(url, target, out, NULL, NULL, NULL);
}

int anubis_fetch_get_dump_with(const char *url, const char *target,
                               const char *cookies, anubis_page_dump *out) {
    fetch_cookies ck = {0};

    if (out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof *out);
    ck.cookies = cookies;
    if (fetch_impl(url, target, &out->page, &out->headers, &out->headers_len,
                   &ck) != 0) {
        free(ck.out_cookies);
        return -1;
    }
    out->cookies = ck.out_cookies;
    out->cookies_len = ck.out_cookies ? strlen(ck.out_cookies) : 0;
    out->solved = ck.solved;
    out->expired = ck.expired;
    return 0;
}

int anubis_fetch_get_dump(const char *url, const char *target,
                          anubis_page_dump *out) {
    return anubis_fetch_get_dump_with(url, target, NULL, out);
}

void anubis_page_dump_free(anubis_page_dump *dump) {
    if (dump == NULL) {
        return;
    }
    anubis_page_free(&dump->page);
    free(dump->headers);
    dump->headers = NULL;
    dump->headers_len = 0;
    free(dump->cookies);
    dump->cookies = NULL;
    dump->cookies_len = 0;
}

int anubis_fetch_get(const char *url, anubis_page *out) {
    return anubis_fetch_get_with(url, NULL, out);
}
