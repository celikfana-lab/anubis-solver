/*
 * anubis_mcp.c — Model Context Protocol server for Anubis.
 *
 * Newline-delimited JSON-RPC 2.0 over stdio: one request object per line on
 * stdin, one response object per line on stdout, nothing else on stdout.
 * Notifications (no "id") get no response. The tools are anubis_fetch
 * (network fetch through the C fetch layer, which solves challenges while it
 * goes, returned as text), anubis_fetch_raw (the same fetch without the HTML
 * to text pass), anubis_dump_headers (the same fetch, reporting the header
 * blocks of every response it went through), anubis_solve (one local proof of
 * work from separate fields), anubis_solve_raw (the same, starting from the raw
 * challenge/page and returning the raw pass-challenge query), anubis_version
 * and anubis_backends (introspection).
 *
 * No JSON library: a small validating parser and a small escaper are right
 * here. No dynamic allocations survive a request. The solver is the same
 * libanubis_solver.so the rest of the project builds.
 */
#include <ctype.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "anubis-solver.h"
#include "anubis_fetch.h"

#define SERVER_NAME "anubis"
#define SERVER_VERSION "2.0.2"

/* ------------------------------------------------------------------ strings */

typedef struct {
    char *s;
    size_t len, cap;
} sb;

static void sb_init(sb *b) {
    b->s = NULL;
    b->len = b->cap = 0;
}

static void sb_free(sb *b) {
    free(b->s);
    b->s = NULL;
    b->len = b->cap = 0;
}

static int sb_reserve(sb *b, size_t extra) {
    size_t need = b->len + extra + 1;
    if (need <= b->cap) return 0;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < need) cap *= 2;
    char *p = realloc(b->s, cap);
    if (!p) return -1;
    b->s = p;
    b->cap = cap;
    return 0;
}

static int sb_putn(sb *b, const char *s, size_t n) {
    if (sb_reserve(b, n) != 0) return -1;
    if (n) memcpy(b->s + b->len, s, n);
    b->len += n;
    b->s[b->len] = '\0';
    return 0;
}

static int sb_puts(sb *b, const char *s) {
    return sb_putn(b, s, strlen(s));
}

static int sb_putc(sb *b, char c) {
    return sb_putn(b, &c, 1);
}

static int sb_printf(sb *b, const char *fmt, ...) {
    va_list ap, aq;
    int n;
    va_start(ap, fmt);
    va_copy(aq, ap);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        va_end(aq);
        return -1;
    }
    if (sb_reserve(b, (size_t)n) != 0) {
        va_end(aq);
        return -1;
    }
    vsnprintf(b->s + b->len, (size_t)n + 1, fmt, aq);
    va_end(aq);
    b->len += (size_t)n;
    return 0;
}

/* Append `s` as the contents of a JSON string (without the outer quotes). */
static void json_escape(sb *b, const char *s, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"': sb_puts(b, "\\\""); break;
            case '\\': sb_puts(b, "\\\\"); break;
            case '\b': sb_puts(b, "\\b"); break;
            case '\f': sb_puts(b, "\\f"); break;
            case '\n': sb_puts(b, "\\n"); break;
            case '\r': sb_puts(b, "\\r"); break;
            case '\t': sb_puts(b, "\\t"); break;
            default:
                if (c < 0x20) {
                    sb_printf(b, "\\u%04x", (unsigned)c);
                } else {
                    sb_putc(b, (char)c);
                }
                break;
        }
    }
}

/* --------------------------------------------------------------- JSON parse */

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type;

typedef struct json_value json_value;

struct json_value {
    json_type type;
    int boolean;
    char *text;      /* decoded string, or raw number spelling */
    size_t text_len;
    json_value **items; /* array elements or object values */
    char **keys;        /* object keys */
    size_t count;
};

typedef struct {
    const char *cur, *end;
    int depth;
    char err[160];
} jparse;

static void jv_free(json_value *v) {
    size_t i;
    if (!v) return;
    for (i = 0; i < v->count; i++) {
        if (v->items) jv_free(v->items[i]);
        if (v->keys) free(v->keys[i]);
    }
    free(v->items);
    free(v->keys);
    free(v->text);
    free(v);
}

static int jp_fail(jparse *p, const char *msg) {
    if (!p->err[0]) snprintf(p->err, sizeof p->err, "%s", msg);
    return -1;
}

static void jp_ws(jparse *p) {
    while (p->cur < p->end &&
           (*p->cur == ' ' || *p->cur == '\t' || *p->cur == '\n' || *p->cur == '\r'))
        p->cur++;
}

static int hexval(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void put_utf8(sb *b, unsigned cp) {
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
}

static int jp_string(jparse *p, char **out, size_t *out_len) {
    sb b;
    sb_init(&b);
    if (p->cur >= p->end || *p->cur != '"') {
        sb_free(&b);
        return jp_fail(p, "expected string");
    }
    p->cur++;
    while (p->cur < p->end) {
        unsigned char c = (unsigned char)*p->cur++;
        if (c == '"') {
            if (!b.s) {
                b.s = malloc(1);
                if (!b.s) return -1;
                b.s[0] = '\0';
                b.cap = 1;
            }
            *out = b.s;
            if (out_len) *out_len = b.len;
            return 0;
        }
        if (c == '\\') {
            unsigned char e;
            if (p->cur >= p->end) { sb_free(&b); return jp_fail(p, "bad escape"); }
            e = (unsigned char)*p->cur++;
            switch (e) {
                case '"': sb_putc(&b, '"'); break;
                case '\\': sb_putc(&b, '\\'); break;
                case '/': sb_putc(&b, '/'); break;
                case 'b': sb_putc(&b, '\b'); break;
                case 'f': sb_putc(&b, '\f'); break;
                case 'n': sb_putc(&b, '\n'); break;
                case 'r': sb_putc(&b, '\r'); break;
                case 't': sb_putc(&b, '\t'); break;
                case 'u': {
                    unsigned cp = 0;
                    int k;
                    for (k = 0; k < 4; k++) {
                        int hv;
                        if (p->cur >= p->end ||
                            (hv = hexval((unsigned char)*p->cur)) < 0) {
                            sb_free(&b);
                            return jp_fail(p, "bad \\u escape");
                        }
                        cp = (cp << 4) | (unsigned)hv;
                        p->cur++;
                    }
                    if (cp >= 0xd800 && cp <= 0xdbff && p->end - p->cur >= 6 &&
                        p->cur[0] == '\\' && p->cur[1] == 'u') {
                        unsigned lo = 0;
                        int ok = 1;
                        for (k = 0; k < 4; k++) {
                            int hv = hexval((unsigned char)p->cur[2 + k]);
                            if (hv < 0) { ok = 0; break; }
                            lo = (lo << 4) | (unsigned)hv;
                        }
                        if (ok && lo >= 0xdc00 && lo <= 0xdfff) {
                            cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                            p->cur += 6;
                        } else {
                            cp = 0xfffd;
                        }
                    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                        cp = 0xfffd;
                    }
                    put_utf8(&b, cp);
                    break;
                }
                default:
                    sb_free(&b);
                    return jp_fail(p, "bad escape");
            }
        } else if (c < 0x20) {
            sb_free(&b);
            return jp_fail(p, "control character in string");
        } else {
            sb_putc(&b, (char)c);
        }
    }
    sb_free(&b);
    return jp_fail(p, "unterminated string");
}

static int jp_number(jparse *p, json_value *v) {
    const char *start = p->cur;
    if (p->cur < p->end && *p->cur == '-') p->cur++;
    if (p->cur >= p->end) return jp_fail(p, "bad number");
    if (*p->cur == '0') {
        p->cur++;
    } else if (*p->cur >= '1' && *p->cur <= '9') {
        while (p->cur < p->end && isdigit((unsigned char)*p->cur)) p->cur++;
    } else {
        return jp_fail(p, "bad number");
    }
    if (p->cur < p->end && *p->cur == '.') {
        p->cur++;
        if (p->cur >= p->end || !isdigit((unsigned char)*p->cur))
            return jp_fail(p, "bad number");
        while (p->cur < p->end && isdigit((unsigned char)*p->cur)) p->cur++;
    }
    if (p->cur < p->end && (*p->cur == 'e' || *p->cur == 'E')) {
        p->cur++;
        if (p->cur < p->end && (*p->cur == '+' || *p->cur == '-')) p->cur++;
        if (p->cur >= p->end || !isdigit((unsigned char)*p->cur))
            return jp_fail(p, "bad number");
        while (p->cur < p->end && isdigit((unsigned char)*p->cur)) p->cur++;
    }
    v->text_len = (size_t)(p->cur - start);
    v->text = malloc(v->text_len + 1);
    if (!v->text) return jp_fail(p, "out of memory");
    memcpy(v->text, start, v->text_len);
    v->text[v->text_len] = '\0';
    v->type = JSON_NUMBER;
    return 0;
}

static int jp_value(jparse *p, json_value **out);

static int add_member(json_value *v, char *key, json_value *item) {
    json_value **items = realloc(v->items, (v->count + 1) * sizeof *items);
    if (!items) return -1;
    v->items = items;
    if (v->keys || v->type == JSON_OBJECT) {
        char **keys = realloc(v->keys, (v->count + 1) * sizeof *keys);
        if (!keys) return -1;
        v->keys = keys;
    }
    if (v->keys) v->keys[v->count] = key;
    v->items[v->count] = item;
    v->count++;
    return 0;
}

static int jp_object(jparse *p, json_value *v) {
    v->type = JSON_OBJECT;
    p->cur++; /* '{' */
    if (++p->depth > 64) { p->depth--; return jp_fail(p, "nesting too deep"); }
    jp_ws(p);
    if (p->cur < p->end && *p->cur == '}') {
        p->cur++;
        p->depth--;
        return 0;
    }
    for (;;) {
        char *key = NULL;
        size_t klen = 0;
        json_value *item = NULL;
        jp_ws(p);
        if (jp_string(p, &key, &klen) != 0) return -1;
        (void)klen;
        jp_ws(p);
        if (p->cur >= p->end || *p->cur != ':') {
            free(key);
            return jp_fail(p, "expected ':'");
        }
        p->cur++;
        jp_ws(p);
        if (jp_value(p, &item) != 0) {
            free(key);
            return -1;
        }
        if (add_member(v, key, item) != 0) {
            free(key);
            jv_free(item);
            return jp_fail(p, "out of memory");
        }
        jp_ws(p);
        if (p->cur < p->end && *p->cur == ',') {
            p->cur++;
            continue;
        }
        if (p->cur < p->end && *p->cur == '}') {
            p->cur++;
            p->depth--;
            return 0;
        }
        return jp_fail(p, "expected ',' or '}'");
    }
}

static int jp_array(jparse *p, json_value *v) {
    v->type = JSON_ARRAY;
    p->cur++; /* '[' */
    if (++p->depth > 64) { p->depth--; return jp_fail(p, "nesting too deep"); }
    jp_ws(p);
    if (p->cur < p->end && *p->cur == ']') {
        p->cur++;
        p->depth--;
        return 0;
    }
    for (;;) {
        json_value *item = NULL;
        jp_ws(p);
        if (jp_value(p, &item) != 0) return -1;
        if (add_member(v, NULL, item) != 0) {
            jv_free(item);
            return jp_fail(p, "out of memory");
        }
        jp_ws(p);
        if (p->cur < p->end && *p->cur == ',') {
            p->cur++;
            continue;
        }
        if (p->cur < p->end && *p->cur == ']') {
            p->cur++;
            p->depth--;
            return 0;
        }
        return jp_fail(p, "expected ',' or ']'");
    }
}

static int jp_value(jparse *p, json_value **out) {
    json_value *v;
    if (p->cur >= p->end) return jp_fail(p, "unexpected end of input");
    v = calloc(1, sizeof *v);
    if (!v) return jp_fail(p, "out of memory");
    switch (*p->cur) {
        case '{':
            if (jp_object(p, v) != 0) goto fail;
            break;
        case '[':
            if (jp_array(p, v) != 0) goto fail;
            break;
        case '"':
            v->type = JSON_STRING;
            if (jp_string(p, &v->text, &v->text_len) != 0) goto fail;
            break;
        case 't':
            if (p->end - p->cur < 4 || strncmp(p->cur, "true", 4) != 0) {
                jp_fail(p, "invalid literal");
                goto fail;
            }
            p->cur += 4;
            v->type = JSON_BOOL;
            v->boolean = 1;
            break;
        case 'f':
            if (p->end - p->cur < 5 || strncmp(p->cur, "false", 5) != 0) {
                jp_fail(p, "invalid literal");
                goto fail;
            }
            p->cur += 5;
            v->type = JSON_BOOL;
            v->boolean = 0;
            break;
        case 'n':
            if (p->end - p->cur < 4 || strncmp(p->cur, "null", 4) != 0) {
                jp_fail(p, "invalid literal");
                goto fail;
            }
            p->cur += 4;
            v->type = JSON_NULL;
            break;
        default:
            if (*p->cur == '-' || isdigit((unsigned char)*p->cur)) {
                if (jp_number(p, v) != 0) goto fail;
            } else {
                jp_fail(p, "unexpected character");
                goto fail;
            }
            break;
    }
    *out = v;
    return 0;
fail:
    jv_free(v);
    return -1;
}

static int json_parse(const char *s, size_t len, json_value **out, char *err,
                      size_t errcap) {
    jparse p;
    json_value *v = NULL;
    p.cur = s;
    p.end = s + len;
    p.depth = 0;
    p.err[0] = '\0';
    jp_ws(&p);
    if (jp_value(&p, &v) != 0) {
        if (err) snprintf(err, errcap, "%s", p.err[0] ? p.err : "invalid JSON");
        return -1;
    }
    jp_ws(&p);
    if (p.cur != p.end) {
        jv_free(v);
        if (err) snprintf(err, errcap, "trailing data after JSON value");
        return -1;
    }
    *out = v;
    return 0;
}

static json_value *jv_get(const json_value *v, const char *key) {
    size_t i;
    if (!v || v->type != JSON_OBJECT || !v->keys) return NULL;
    for (i = 0; i < v->count; i++)
        if (v->keys[i] && strcmp(v->keys[i], key) == 0) return v->items[i];
    return NULL;
}

static const char *jv_string(const json_value *v, const char *key) {
    json_value *item = jv_get(v, key);
    return (item && item->type == JSON_STRING) ? item->text : NULL;
}

static int jv_long(const json_value *v, const char *key, long *out) {
    json_value *item = jv_get(v, key);
    char *endp = NULL;
    long value;
    if (!item || item->type != JSON_NUMBER) return 0;
    value = strtol(item->text, &endp, 10);
    if (!endp || *endp != '\0') return 0;
    *out = value;
    return 1;
}

static int jv_double(const json_value *v, const char *key, double *out) {
    json_value *item = jv_get(v, key);
    char *endp = NULL;
    double value;
    if (!item || item->type != JSON_NUMBER) return 0;
    value = strtod(item->text, &endp);
    if (!endp || *endp != '\0') return 0;
    *out = value;
    return 1;
}

/* ------------------------------------------------------------- JSON replies */

static void put_id(sb *b, const json_value *id) {
    if (!id || id->type == JSON_NULL) {
        sb_puts(b, "null");
    } else if (id->type == JSON_STRING) {
        sb_putc(b, '"');
        json_escape(b, id->text, id->text_len);
        sb_putc(b, '"');
    } else if (id->type == JSON_NUMBER) {
        sb_putn(b, id->text, id->text_len);
    } else {
        sb_puts(b, "null");
    }
}

static void write_line(sb *b) {
    if (!b->s) return;
    fwrite(b->s, 1, b->len, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

static void send_error(const json_value *id, int code, const char *message) {
    sb b;
    sb_init(&b);
    sb_puts(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
    put_id(&b, id);
    sb_printf(&b, ",\"error\":{\"code\":%d,\"message\":\"", code);
    json_escape(&b, message, strlen(message));
    sb_puts(&b, "\"}}");
    write_line(&b);
    sb_free(&b);
}

/* Emit a tools/call result: text content plus the isError flag. */
static void send_tool_text(const json_value *id, const char *text, size_t len,
                           int is_error) {
    sb b;
    sb_init(&b);
    sb_puts(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
    put_id(&b, id);
    sb_puts(&b, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"");
    json_escape(&b, text, len);
    sb_puts(&b, "\"}],\"isError\":");
    sb_puts(&b, is_error ? "true" : "false");
    sb_puts(&b, "}}");
    write_line(&b);
    sb_free(&b);
}

static void send_tool_error(const json_value *id, const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    send_tool_text(id, msg, strlen(msg), 1);
}

static void send_result_raw(const json_value *id, const char *json) {
    sb b;
    sb_init(&b);
    sb_puts(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
    put_id(&b, id);
    sb_puts(&b, ",\"result\":");
    sb_puts(&b, json);
    sb_putc(&b, '}');
    write_line(&b);
    sb_free(&b);
}

/* -------------------------------------------------------------- HTML to text */

static int is_space_byte(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static int starts_ci(const char *s, size_t n, const char *lit) {
    size_t i, m = strlen(lit);
    if (n < m) return 0;
    for (i = 0; i < m; i++)
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)lit[i])) return 0;
    return 1;
}

static const char *find_ci(const char *hay, size_t hay_len, const char *needle) {
    size_t i, m = strlen(needle);
    if (m == 0 || hay_len < m) return NULL;
    for (i = 0; i + m <= hay_len; i++)
        if (starts_ci(hay + i, hay_len - i, needle)) return hay + i;
    return NULL;
}

/* Block-level elements break the line; inline tags just disappear. */
static int is_block_tag(const char *name, size_t len) {
    static const char *blocks[] = {
        "address", "article", "aside", "blockquote", "br", "dd", "div", "dl",
        "dt", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2",
        "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p",
        "pre", "section", "table", "tbody", "td", "tfoot", "th", "thead", "tr",
        "ul", NULL
    };
    size_t i;
    for (i = 0; blocks[i]; i++) {
        size_t m = strlen(blocks[i]);
        if (len == m && strncasecmp(name, blocks[i], m) == 0) return 1;
    }
    return 0;
}

static void block_break(sb *out) {
    if (out->len > 0 && out->s[out->len - 1] != '\n') sb_putc(out, '\n');
}

/* Decode one entity starting at html[i] == '&'. Returns bytes consumed, or 0
 * when it is not an entity we know (the '&' is then copied literally). */
static size_t decode_entity(const char *html, size_t len, size_t i, sb *out) {
    static const struct { const char *name; const char *value; } named[] = {
        {"&amp;", "&"}, {"&lt;", "<"}, {"&gt;", ">"}, {"&quot;", "\""},
        {"&apos;", "'"}, {"&#39;", "'"}, {"&nbsp;", " "}, {"&copy;", "\xC2\xA9"},
        {"&mdash;", "\xE2\x80\x94"}, {"&ndash;", "\xE2\x80\x93"},
        {"&hellip;", "\xE2\x80\xA6"}, {"&rsquo;", "\xE2\x80\x99"},
        {"&lsquo;", "\xE2\x80\x98"}, {"&ldquo;", "\xE2\x80\x9C"},
        {"&rdquo;", "\xE2\x80\x9D"}, {NULL, NULL}
    };
    size_t k;
    for (k = 0; named[k].name; k++) {
        size_t m = strlen(named[k].name);
        if (i + m <= len && starts_ci(html + i, len - i, named[k].name)) {
            sb_puts(out, named[k].value);
            return m;
        }
    }
    if (i + 2 < len && html[i + 1] == '#') {
        size_t j = i + 2;
        unsigned cp = 0;
        int base = 10, digits = 0;
        if (j < len && (html[j] == 'x' || html[j] == 'X')) {
            base = 16;
            j++;
        }
        while (j < len) {
            int hv;
            if (html[j] == ';') break;
            if (base == 16) {
                hv = hexval((unsigned char)html[j]);
            } else {
                hv = isdigit((unsigned char)html[j]) ? html[j] - '0' : -1;
            }
            if (hv < 0) break;
            if (cp > 0x10ffff) break;
            cp = cp * (unsigned)base + (unsigned)hv;
            digits++;
            j++;
        }
        if (digits > 0 && j < len && html[j] == ';' && cp > 0 && cp <= 0x10ffff &&
            !(cp >= 0xd800 && cp <= 0xdfff)) {
            put_utf8(out, cp);
            return j + 1 - i;
        }
    }
    (void)starts_ci;
    return 0;
}

/* Strip tags/scripts/styles, decode entities, collapse whitespace. */
static int html_to_text(const char *html, size_t len, sb *out) {
    size_t i = 0;
    sb raw;
    sb_init(&raw);
    while (i < len) {
        char c = html[i];
        if (c != '<') {
            if (c == '&') {
                size_t used = decode_entity(html, len, i, &raw);
                if (used) {
                    i += used;
                    continue;
                }
            }
            if (c == '\r' || c == '\n' || c == '\t' || c == '\f' || c == '\v') {
                sb_putc(&raw, ' ');
            } else {
                sb_putc(&raw, c);
            }
            i++;
            continue;
        }
        if (len - i >= 4 && strncmp(html + i, "<!--", 4) == 0) {
            const char *end = find_ci(html + i + 4, len - i - 4, "-->");
            if (!end) break;
            i = (size_t)(end - html) + 3;
            continue;
        }
        if (len - i >= 7 && starts_ci(html + i, len - i, "<script") &&
            (i + 7 >= len || html[i + 7] == '>' || isspace((unsigned char)html[i + 7]))) {
            const char *end = find_ci(html + i + 7, len - i - 7, "</script");
            if (!end) break;
            end = memchr(end, '>', len - (size_t)(end - html));
            if (!end) break;
            i = (size_t)(end - html) + 1;
            continue;
        }
        if (len - i >= 6 && starts_ci(html + i, len - i, "<style") &&
            (i + 6 >= len || html[i + 6] == '>' || isspace((unsigned char)html[i + 6]))) {
            const char *end = find_ci(html + i + 6, len - i - 6, "</style");
            if (!end) break;
            end = memchr(end, '>', len - (size_t)(end - html));
            if (!end) break;
            i = (size_t)(end - html) + 1;
            continue;
        }
        if (len - i >= 5 && starts_ci(html + i, len - i, "<head") &&
            (i + 5 >= len || html[i + 5] == '>' || isspace((unsigned char)html[i + 5]))) {
            const char *end = find_ci(html + i + 5, len - i - 5, "</head");
            if (!end) break;
            end = memchr(end, '>', len - (size_t)(end - html));
            if (!end) break;
            i = (size_t)(end - html) + 1;
            continue;
        }
        {
            const char *gt = memchr(html + i, '>', len - i);
            const char *name;
            size_t nlen = 0;
            size_t j;
            if (!gt) break;
            j = i + 1;
            if (j < (size_t)(gt - html) && html[j] == '/') j++;
            while (j < (size_t)(gt - html) &&
                   (isalnum((unsigned char)html[j]) || html[j] == '-' || html[j] == ':'))
                j++;
            name = html + i + 1 + (i + 1 < (size_t)(gt - html) && html[i + 1] == '/');
            nlen = j - (size_t)(name - html);
            if (nlen > 0 && is_block_tag(name, nlen)) block_break(&raw);
            i = (size_t)(gt - html) + 1;
        }
    }

    /* Collapse the whitespace, keeping at most one blank line. */
    {
        size_t k;
        int pending_space = 0;
        int trailing_newlines = 0;
        for (k = 0; k < raw.len; k++) {
            char ch = raw.s[k];
            if (ch == '\n') {
                pending_space = 0;
                if (trailing_newlines < 2 && out->len > 0) {
                    sb_putc(out, '\n');
                    trailing_newlines++;
                }
            } else if (is_space_byte((unsigned char)ch)) {
                pending_space = 1;
            } else {
                if (pending_space && out->len > 0 && out->s[out->len - 1] != '\n')
                    sb_putc(out, ' ');
                pending_space = 0;
                trailing_newlines = 0;
                sb_putc(out, ch);
            }
        }
        while (out->len > 0 &&
               (out->s[out->len - 1] == ' ' || out->s[out->len - 1] == '\n' ||
                out->s[out->len - 1] == '\t'))
            out->len--;
        if (out->s) out->s[out->len] = '\0';
    }
    sb_free(&raw);
    return 0;
}

/* Cut `len` at a UTF-8 character boundary so truncation cannot split one. */
static size_t utf8_truncate(const char *s, size_t len, size_t max) {
    if (max >= len) return len;
    while (max > 0 && ((unsigned char)s[max] & 0xc0) == 0x80) max--;
    return max;
}

/* ----------------------------------------------------------------- solving */

typedef enum {
    ALG_NIBBLES,
    ALG_BITS,
    ALG_ARGON2ID,
    ALG_HASHX,
    ALG_TENSOR,
    ALG_MEATRIDER
} alg_kind;

typedef struct {
    const char *name;
    alg_kind kind;
} alg_entry;

static const alg_entry ALGORITHMS[] = {
    {"fast", ALG_NIBBLES},
    {"slow", ALG_NIBBLES},
    {"sha256", ALG_BITS},
    {"wasm-sha256", ALG_BITS},
    {"argon2id", ALG_ARGON2ID},
    {"hashx", ALG_HASHX},
    {"tensor", ALG_TENSOR},
    {"meatrider", ALG_MEATRIDER},
    {NULL, ALG_NIBBLES}
};

static const alg_entry *find_algorithm(const char *name) {
    size_t i;
    for (i = 0; ALGORITHMS[i].name; i++)
        if (strcasecmp(ALGORITHMS[i].name, name) == 0) return &ALGORITHMS[i];
    return NULL;
}

static const char *algorithm_list(void) {
    return "fast, slow, sha256, wasm-sha256, argon2id, hashx, tensor, meatrider";
}

static int solve_one(const alg_entry *alg, const char *challenge, int difficulty,
                     int threads, uint64_t *out_nonce, char out_hex[65], char *err,
                     size_t errcap) {
    int rc;
    if (difficulty < 0) {
        snprintf(err, errcap, "difficulty must be non-negative");
        return -1;
    }
    if (threads < 0) {
        snprintf(err, errcap, "threads must be non-negative");
        return -1;
    }
    out_hex[0] = '\0';
    *out_nonce = 0;
    switch (alg->kind) {
        case ALG_NIBBLES: {
            uint64_t nonce = 0;
            rc = anubis_solve_nibbles(challenge, difficulty, threads, 0, 0.0, &nonce,
                                      out_hex, NULL);
            *out_nonce = nonce;
            break;
        }
        case ALG_BITS: {
            uint32_t nonce = 0;
            rc = anubis_solve_bits(challenge, difficulty, threads, 0.0, &nonce, out_hex,
                                   NULL);
            *out_nonce = nonce;
            break;
        }
        case ALG_ARGON2ID: {
            uint32_t nonce = 0;
            rc = anubis_solve_argon2id(challenge, difficulty, threads, 0.0, &nonce,
                                       out_hex, NULL);
            *out_nonce = nonce;
            break;
        }
        case ALG_HASHX: {
            uint32_t nonce = 0;
            rc = anubis_solve_hashx(challenge, difficulty, threads, 0.0, &nonce, out_hex,
                                    NULL);
            *out_nonce = nonce;
            break;
        }
        case ALG_TENSOR: {
            uint32_t nonce = 0;
            rc = anubis_solve_tensor(challenge, difficulty, threads, 0.0, &nonce, out_hex,
                                     NULL);
            *out_nonce = nonce;
            break;
        }
        case ALG_MEATRIDER: {
            uint32_t nonce = 0;
            rc = anubis_solve_meatrider(challenge, difficulty, threads, 0.0, &nonce,
                                        out_hex, NULL);
            *out_nonce = nonce;
            break;
        }
        default:
            snprintf(err, errcap, "unsupported algorithm");
            return -1;
    }
    if (rc == ANUBIS_OK) {
        if (strlen(out_hex) != 64) {
            snprintf(err, errcap, "solver returned a malformed digest");
            return -1;
        }
        return 0;
    }
    if (rc == ANUBIS_ERR_ARG) {
        snprintf(err, errcap,
                 "invalid argument for %s (challenge must be hex for every algorithm "
                 "except fast/slow)",
                 alg->name);
    } else if (rc == ANUBIS_ERR_UNSOLVED) {
        snprintf(err, errcap, "no solution found for %s at difficulty %d", alg->name,
                 difficulty);
    } else {
        snprintf(err, errcap, "solver error %d for %s", rc, alg->name);
    }
    return -1;
}

/* ------------------------------------------------------------------- tools */

static const char TOOLS_JSON[] =
    "{\"tools\":["
    "{\"name\":\"anubis_fetch\","
    "\"description\":\"Fetch an Anubis-protected URL, solving any challenge on the "
    "way, and return the page as readable text. The text begins with status: <code>, "
    "url: <final_url> and transport: <openssl|curl-impersonate/profile>.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{"
    "\"url\":{\"type\":\"string\",\"description\":\"Absolute http or https URL.\"},\"cookies\":{\"type\":\"string\",\"description\":\"The cookies: value from an earlier call. Pass it back to reuse the solved session instead of solving again; when the site stops accepting it the result says expired: yes and carries a fresh set.\"},"
    "\"max_chars\":{\"type\":\"integer\",\"description\":\"Maximum body characters "
    "to return (default 100000, 0 means unlimited).\"},"
    "\"impersonate\":{\"type\":\"string\",\"description\":\"TLS fingerprint to "
    "present: chrome (default when a curl-impersonate library is installed), a "
    "concrete profile such as chrome116, edge101 or safari15_5, \\\"auto\\\" or "
    "\\\"off\\\" for the built-in OpenSSL client.\"}},"
    "\"required\":[\"url\"]}},"
    "{\"name\":\"anubis_fetch_raw\",\"description\":\"Fetch an Anubis-protected URL, solving any challenge on the way, and return the body exactly as it arrived: raw HTML or bytes, not the readable text anubis_fetch produces. Begins with status: <code>, url: <final_url> and transport: <openssl|curl-impersonate/profile>.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"url\":{\"type\":\"string\",\"description\":\"Absolute http or https URL.\"},\"cookies\":{\"type\":\"string\",\"description\":\"The cookies: value from an earlier call. Pass it back to reuse the solved session instead of solving again; when the site stops accepting it the result says expired: yes and carries a fresh set.\"},\"max_chars\":{\"type\":\"integer\",\"description\":\"Maximum body characters to return (default 100000, 0 means unlimited).\"},\"impersonate\":{\"type\":\"string\",\"description\":\"TLS fingerprint to present: chrome (default when a curl-impersonate library is installed), a concrete profile such as chrome116, edge101 or safari15_5, \\\"auto\\\" or \\\"off\\\" for the built-in OpenSSL client.\"}},\"required\":[\"url\"]}},"
    "{\"name\":\"anubis_dump_headers\",\"description\":\"Fetch an Anubis-protected URL, solving any challenge on the way, and return the raw header blocks of every response it went through, in order: the challenge, the pass-challenge reply, any redirect and the final page. Each block starts with its own status line.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"url\":{\"type\":\"string\",\"description\":\"Absolute http or https URL.\"},\"cookies\":{\"type\":\"string\",\"description\":\"The cookies: value from an earlier call. Pass it back to reuse the solved session instead of solving again; when the site stops accepting it the result says expired: yes and carries a fresh set.\"},\"impersonate\":{\"type\":\"string\",\"description\":\"TLS fingerprint to present: chrome (default when a curl-impersonate library is installed), a concrete profile such as chrome116, edge101 or safari15_5, \\\"auto\\\" or \\\"off\\\" for the built-in OpenSSL client.\"}},\"required\":[\"url\"]}},"
    "{\"name\":\"anubis_solve\","
    "\"description\":\"Solve one Anubis proof-of-work challenge locally, without "
    "network access. Returns a JSON text with nonce, response digest and "
    "algorithm.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{"
    "\"algorithm\":{\"type\":\"string\",\"description\":\"fast, slow, sha256, "
    "wasm-sha256, argon2id, hashx or tensor.\"},"
    "\"challenge\":{\"type\":\"string\",\"description\":\"Challenge payload; hex "
    "for sha256, wasm-sha256, argon2id, hashx and tensor.\"},"
    "\"difficulty\":{\"type\":\"integer\",\"description\":\"Leading zero nibbles "
    "for fast/slow, leading zero bits otherwise.\"},"
    "\"threads\":{\"type\":\"integer\",\"description\":\"Worker threads; 0 or "
    "omitted means the library default.\"}},"
    "\"required\":[\"algorithm\",\"challenge\",\"difficulty\"]}},"
    "{\"name\":\"anubis_solve_raw\","
    "\"description\":\"Solve an Anubis challenge the caller already has, with no "
    "network I/O at all. The input may be the anubis_challenge JSON (both the "
    "{\\\"challenge\\\":\\\"<hex>\\\"} and nested "
    "{\\\"challenge\\\":{\\\"randomData\\\":...}} spellings), the "
    "<script id=\\\"anubis_challenge\\\"> element, or the whole challenge page. "
    "Returns the raw pass-challenge query parameters as plain text, for example "
    "id=<uuid>&response=<hex>&nonce=<n>&elapsedTime=1. No page is fetched.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{"
    "\"input\":{\"type\":\"string\",\"description\":\"Raw challenge: the JSON "
    "payload, the anubis_challenge script element, or the whole page.\"},"
    "\"threads\":{\"type\":\"integer\",\"description\":\"Worker threads; 0 or "
    "omitted means the library default.\"},"
    "\"budget_ms\":{\"type\":\"number\",\"description\":\"Optional solve budget "
    "in milliseconds; 0 or omitted means no limit.\"}},"
    "\"required\":[\"input\"]}},"
    "{\"name\":\"anubis_version\","
    "\"description\":\"Return the solver version, release codename and supported "
    "algorithms.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{},\"required\":[]}},"
    "{\"name\":\"anubis_backends\","
    "\"description\":\"List the compute backends compiled into the solver and "
    "which of them this machine can use right now (probes the hardware; can "
    "take a second on a cold driver).\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{},\"required\":[]}}"
    "]}";

/* Append the names of `mask` as a JSON array. */
static void backend_json(char *out, size_t cap, int mask) {
    static const int bits[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20};
    size_t i, used = 0;
    int first = 1;
    out[0] = '\0';
    for (i = 0; i < sizeof bits / sizeof bits[0] && used + 24 < cap; i++) {
        const char *name;
        if (!(mask & bits[i])) {
            continue;
        }
        name = anubis_backend_name(bits[i]);
        if (name == NULL) {
            continue;
        }
        used += (size_t)snprintf(out + used, cap - used, "%s\"%s\"",
                                 first ? "" : ",", name);
        first = 0;
    }
}

static void tool_version(const json_value *id) {
    const char *version = anubis_solver_version();
    const char *codename = anubis_solver_codename();
    char text[1024];
    char compiled[256];
    if (!version || !*version) version = SERVER_VERSION;
    if (!codename || !*codename) codename = "shaoogle";
    backend_json(compiled, sizeof compiled, anubis_backends_compiled());
    snprintf(text, sizeof text,
             "{\"version\":\"%s\",\"codename\":\"%s\",\"algorithms\":[\"fast\","
             "\"slow\",\"sha256\",\"wasm-sha256\",\"argon2id\",\"hashx\",\"tensor\"],"
             "\"backends_compiled\":[%s],"
             "\"impersonate\":\"%s\",\"impersonate_available\":%s}",
             version, codename, compiled, anubis_fetch_impersonate(),
             anubis_fetch_impersonate_available() ? "true" : "false");
    send_tool_text(id, text, strlen(text), 0);
}

static void tool_backends(const json_value *id) {
    char text[1024];
    char compiled[256];
    char available[256];
    backend_json(compiled, sizeof compiled, anubis_backends_compiled());
    backend_json(available, sizeof available, anubis_backends_available());
    snprintf(text, sizeof text, "{\"compiled\":[%s],\"available\":[%s]}",
             compiled, available);
    send_tool_text(id, text, strlen(text), 0);
}

static void tool_solve(const json_value *id, const json_value *args) {
    const char *algorithm = jv_string(args, "algorithm");
    const char *challenge = jv_string(args, "challenge");
    long difficulty, threads = 0;
    const alg_entry *alg;
    uint64_t nonce = 0;
    char digest[65] = "";
    char err[256] = "";
    sb text;
    int have_threads;

    if (!algorithm) {
        send_tool_error(id, "missing required argument: algorithm");
        return;
    }
    if (!challenge) {
        send_tool_error(id, "missing required argument: challenge");
        return;
    }
    if (!jv_long(args, "difficulty", &difficulty)) {
        send_tool_error(id, "missing required integer argument: difficulty");
        return;
    }
    have_threads = jv_long(args, "threads", &threads);
    (void)have_threads;
    alg = find_algorithm(algorithm);
    if (!alg) {
        send_tool_error(id, "unknown algorithm %s (supported: %s)", algorithm,
                        algorithm_list());
        return;
    }
    if (solve_one(alg, challenge, (int)difficulty, (int)threads, &nonce, digest, err,
                  sizeof err) != 0) {
        send_tool_error(id, "%s", err);
        return;
    }
    sb_init(&text);
    sb_printf(&text, "{\"nonce\":%llu,\"response\":\"%s\",\"algorithm\":\"",
              (unsigned long long)nonce, digest);
    json_escape(&text, alg->name, strlen(alg->name));
    sb_puts(&text, "\"}");
    send_tool_text(id, text.s, text.len, 0);
    sb_free(&text);
}

/* The challenge is already in hand: parse it, solve it, and hand back the raw
 * pass-challenge query. Nothing here touches the network. */
static void tool_solve_raw(const json_value *id, const json_value *args) {
    json_value *input = jv_get(args, "input");
    long threads = 0;
    double budget_ms = 0.0;
    anubis_raw_solution sol;
    char err[256] = "";

    if (!input || input->type != JSON_STRING) {
        send_tool_error(id, "missing required argument: input");
        return;
    }
    if (jv_get(args, "threads") && !jv_long(args, "threads", &threads)) {
        send_tool_error(id, "threads must be an integer");
        return;
    }
    if (threads < 0 || threads > 4096) {
        send_tool_error(id, "threads must be between 0 and 4096");
        return;
    }
    if (jv_get(args, "budget_ms") && !jv_double(args, "budget_ms", &budget_ms)) {
        send_tool_error(id, "budget_ms must be a number");
        return;
    }
    if (budget_ms < 0.0) {
        budget_ms = 0.0;
    }
    if (anubis_solve_challenge_input(input->text, input->text_len, (int)threads,
                                     budget_ms, &sol, err, sizeof err) != 0) {
        send_tool_error(id, "%s", err[0] ? err : "cannot solve challenge");
        return;
    }
    send_tool_text(id, sol.raw, strlen(sol.raw), 0);
}

/* status/url/transport plus the session state. A caller keeps the session by
 * passing the cookies line back on the next call; expired says the site no
 * longer accepted them and the line below it is the replacement. */
static void append_preamble(sb *text, const anubis_page_dump *dump,
                            const char *url) {
    sb_printf(text,
              "status: %d\nurl: %s\ntransport: %s\nsolved: %s\nexpired: %s\n",
              dump->page.status,
              dump->page.final_url ? dump->page.final_url : url,
              anubis_fetch_transport(), dump->solved ? "yes" : "no",
              dump->expired ? "yes" : "no");
    if (dump->cookies != NULL && dump->cookies_len > 0) {
        sb_puts(text, "cookies: ");
        sb_puts(text, dump->cookies);
        sb_puts(text, "\n");
    } else {
        sb_puts(text, "cookies: (none)\n");
    }
    sb_puts(text, "\n");
}

static void tool_fetch(const json_value *id, const json_value *args) {
    const char *url = jv_string(args, "url");
    const char *impersonate = jv_string(args, "impersonate");
    const char *cookies = jv_string(args, "cookies");
    long max_chars = 100000;
    anubis_page_dump dump;
    sb body, text;
    size_t keep;

    if (!url || !*url) {
        send_tool_error(id, "missing required argument: url");
        return;
    }
    if (jv_get(args, "max_chars")) {
        if (!jv_long(args, "max_chars", &max_chars)) {
            send_tool_error(id, "max_chars must be an integer");
            return;
        }
        if (max_chars < 0) {
            send_tool_error(id, "max_chars must be non-negative");
            return;
        }
    }
    memset(&dump, 0, sizeof dump);
    if (anubis_fetch_get_dump_with(url, impersonate, cookies, &dump) != 0) {
        send_tool_error(id, "fetch failed: %s",
                        dump.page.error[0] ? dump.page.error : "unknown error");
        anubis_page_dump_free(&dump);
        return;
    }
    sb_init(&body);
    html_to_text(dump.page.body ? dump.page.body : "", dump.page.body_len, &body);
    keep = body.len;
    if (max_chars > 0 && (size_t)max_chars < keep)
        keep = utf8_truncate(body.s, keep, (size_t)max_chars);

    sb_init(&text);
    append_preamble(&text, &dump, url);
    if (keep > 0) sb_putn(&text, body.s, keep);
    send_tool_text(id, text.s, text.len, 0);
    sb_free(&text);
    sb_free(&body);
    anubis_page_dump_free(&dump);
}

/* Same fetch as tool_fetch, without the HTML to text pass: the caller gets the
 * body as the server sent it. Bytes are still valid UTF-8 in practice, so the
 * same character cap applies. */
static void tool_fetch_raw(const json_value *id, const json_value *args) {
    const char *url = jv_string(args, "url");
    const char *impersonate = jv_string(args, "impersonate");
    const char *cookies = jv_string(args, "cookies");
    long max_chars = 100000;
    anubis_page_dump dump;
    sb text;
    size_t keep;

    if (!url || !*url) {
        send_tool_error(id, "missing required argument: url");
        return;
    }
    if (jv_get(args, "max_chars")) {
        if (!jv_long(args, "max_chars", &max_chars)) {
            send_tool_error(id, "max_chars must be an integer");
            return;
        }
        if (max_chars < 0) {
            send_tool_error(id, "max_chars must be non-negative");
            return;
        }
    }
    memset(&dump, 0, sizeof dump);
    if (anubis_fetch_get_dump_with(url, impersonate, cookies, &dump) != 0) {
        send_tool_error(id, "fetch failed: %s",
                        dump.page.error[0] ? dump.page.error : "unknown error");
        anubis_page_dump_free(&dump);
        return;
    }
    keep = dump.page.body_len;
    if (max_chars > 0 && (size_t)max_chars < keep)
        keep = utf8_truncate(dump.page.body ? dump.page.body : "", keep,
                             (size_t)max_chars);

    sb_init(&text);
    append_preamble(&text, &dump, url);
    if (keep > 0) sb_putn(&text, dump.page.body, keep);
    send_tool_text(id, text.s, text.len, 0);
    sb_free(&text);
    anubis_page_dump_free(&dump);
}

/* The same fetch, reporting the header blocks instead of the page: every
 * response the loop went through, challenge and pass-challenge included. */
static void tool_dump_headers(const json_value *id, const json_value *args) {
    const char *url = jv_string(args, "url");
    const char *impersonate = jv_string(args, "impersonate");
    const char *cookies = jv_string(args, "cookies");
    anubis_page_dump dump;
    sb text;

    if (!url || !*url) {
        send_tool_error(id, "missing required argument: url");
        return;
    }
    memset(&dump, 0, sizeof dump);
    if (anubis_fetch_get_dump_with(url, impersonate, cookies, &dump) != 0) {
        send_tool_error(id, "fetch failed: %s",
                        dump.page.error[0] ? dump.page.error : "unknown error");
        anubis_page_dump_free(&dump);
        return;
    }
    sb_init(&text);
    append_preamble(&text, &dump, url);
    sb_printf(&text, "headers: %zu bytes\n\n", dump.headers_len);
    if (dump.headers != NULL && dump.headers_len > 0)
        sb_putn(&text, dump.headers, dump.headers_len);
    send_tool_text(id, text.s, text.len, 0);
    sb_free(&text);
    anubis_page_dump_free(&dump);
}

static void tool_call(const json_value *id, const json_value *params) {
    const char *name;
    const json_value *args;
    if (!params || params->type != JSON_OBJECT) {
        send_tool_error(id, "tools/call requires a params object");
        return;
    }
    name = jv_string(params, "name");
    if (!name) {
        send_tool_error(id, "tools/call requires a tool name");
        return;
    }
    args = jv_get(params, "arguments");
    if (!args || args->type == JSON_NULL) {
        static const json_value empty = {JSON_OBJECT, 0, NULL, 0, NULL, NULL, 0};
        args = &empty;
    }
    if (args->type != JSON_OBJECT) {
        send_tool_error(id, "arguments must be an object");
        return;
    }
    if (strcmp(name, "anubis_fetch") == 0) {
        tool_fetch(id, args);
    } else if (strcmp(name, "anubis_fetch_raw") == 0) {
        tool_fetch_raw(id, args);
    } else if (strcmp(name, "anubis_dump_headers") == 0) {
        tool_dump_headers(id, args);
    } else if (strcmp(name, "anubis_solve") == 0) {
        tool_solve(id, args);
    } else if (strcmp(name, "anubis_solve_raw") == 0) {
        tool_solve_raw(id, args);
    } else if (strcmp(name, "anubis_version") == 0) {
        tool_version(id);
    } else if (strcmp(name, "anubis_backends") == 0) {
        tool_backends(id);
    } else {
        send_tool_error(id, "unknown tool: %s", name);
    }
}

/* -------------------------------------------------------------- dispatch */

static void handle_line(const char *line, size_t len) {
    json_value *req = NULL;
    char err[200] = "";
    const json_value *id;
    const char *method;

    if (json_parse(line, len, &req, err, sizeof err) != 0) {
        send_error(NULL, -32700, "Parse error");
        return;
    }
    if (req->type != JSON_OBJECT) {
        send_error(NULL, -32600, "Invalid Request");
        jv_free(req);
        return;
    }
    id = jv_get(req, "id"); /* NULL when absent: a notification */
    method = jv_string(req, "method");
    if (!id) {
        /* Notifications never get a reply, and neither does anything we do
         * not know how to answer without an id. */
        jv_free(req);
        return;
    }
    if (!method) {
        send_error(id, -32600, "Invalid Request: missing method");
        jv_free(req);
        return;
    }
    if (strcmp(method, "initialize") == 0) {
        send_result_raw(id,
                        "{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{"
                        "\"tools\":{}},\"serverInfo\":{\"name\":\"" SERVER_NAME
                        "\",\"version\":\"" SERVER_VERSION "\"}}");
    } else if (strcmp(method, "ping") == 0) {
        send_result_raw(id, "{}");
    } else if (strcmp(method, "tools/list") == 0) {
        send_result_raw(id, TOOLS_JSON);
    } else if (strcmp(method, "tools/call") == 0) {
        tool_call(id, jv_get(req, "params"));
    } else if (strcmp(method, "notifications/initialized") == 0) {
        /* A notification by protocol; if a client puts an id on it anyway we
         * still answer nothing useful, so stay silent. */
    } else {
        send_error(id, -32601, "Method not found");
    }
    jv_free(req);
}

int main(void) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;

    signal(SIGPIPE, SIG_IGN);
    fprintf(stderr, "anubis MCP server %s (solver %s)\n", SERVER_VERSION,
            anubis_solver_version() ? anubis_solver_version() : "unknown");

    while ((n = getline(&line, &cap, stdin)) != -1) {
        size_t len = (size_t)n;
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        {
            size_t i;
            int blank = 1;
            for (i = 0; i < len; i++) {
                if (!is_space_byte((unsigned char)line[i])) {
                    blank = 0;
                    break;
                }
            }
            if (blank) continue;
        }
        handle_line(line, len);
    }
    free(line);
    return 0;
}
