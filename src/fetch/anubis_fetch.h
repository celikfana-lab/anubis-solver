/*
 * anubis_fetch.h — fetch an Anubis-protected URL from C.
 *
 * The library behind the C MCP server and the C API service: one call that
 * follows a challenge page, solves it with libanubis_solver, submits the
 * answer with the cookies the server set, and returns the real page.
 *
 *   anubis_page page;
 *   if (anubis_fetch_get("https://example.com/", &page) == 0) { ... }
 *
 * TLS is OpenSSL, verification on by default (set ANUBIS_INSECURE=1 to skip,
 * for testing against a self-signed gate). The solver is the .so this project
 * already builds, so every algorithm it supports is supported here.
 *
 * When a curl-impersonate library is present — $ANUBIS_IMPERSONATE_LIB, or
 * 3rd_party/curl-impersonate/lib/ in this repository — the requests go through
 * it instead, with a real browser TLS fingerprint (Chrome by default). The
 * hand-written OpenSSL client stays as the fallback and is still what runs when
 * no such library exists.
 */
#ifndef ANUBIS_FETCH_H
#define ANUBIS_FETCH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int status;        /* final HTTP status */
    char *body;        /* NUL-terminated; may contain NULs, use body_len */
    size_t body_len;
    char *final_url;   /* after redirects */
    char error[256];   /* empty on success */
} anubis_page;

/* Fetch a URL, solving any Anubis challenge on the way.
 * Returns 0 on success (out->status is the final status), -1 on failure with
 * out->error set. Free with anubis_page_free(). */
int anubis_fetch_get(const char *url, anubis_page *out);
void anubis_page_free(anubis_page *page);

/* Headers seen along the way, next to the page. A separate struct because
 * anubis_page is allocated by the caller: growing it would write past the end
 * of every program compiled against an older release. */
typedef struct {
    anubis_page page;   /* status, body, final_url, error as usual */
    char *headers;      /* every response header block seen, in order, CRLF */
    size_t headers_len; /* NUL-terminated anyway, but may contain NULs */
    char *cookies;      /* "name=value; name2=value2" to send next time */
    size_t cookies_len;
    int solved;         /* a challenge was solved during this call */
    int expired;        /* cookies were supplied and the site rejected them */
} anubis_page_dump;

/* Same fetch as anubis_fetch_get_with(), plus the raw header blocks of every
 * response it went through: the challenge 401, the pass-challenge reply, any
 * redirect and the final page. Each block starts with its own status line, so
 * concatenation is self-describing. Free with anubis_page_dump_free(). */
int anubis_fetch_get_dump(const char *url, const char *target,
                          anubis_page_dump *out);

/* The same, with the cookie jar carried in and out by the caller.
 *
 * `cookies` is a Cookie header value ("name=value; name2=value2") from an
 * earlier call, or NULL for a cold start. Out->cookies always holds the jar as
 * the site left it, so a caller keeps a session by passing the same string
 * back; no server-side state is needed and it survives process restarts.
 *
 * out->solved says a challenge was answered in this call, out->expired says
 * the supplied cookies were no longer accepted (a challenge was served
 * anyway). A caller that passes cookies and gets expired=1 should replace them
 * with the new out->cookies and carry on. Thread-safe. */
int anubis_fetch_get_dump_with(const char *url, const char *target,
                               const char *cookies, anubis_page_dump *out);

void anubis_page_dump_free(anubis_page_dump *dump);

/* Same, but choose the impersonation profile for this call only, so a
 * multi-threaded caller (the API service) never races on global state.
 * `target` may be NULL for the default, "off" for the built-in OpenSSL
 * client, "auto" to impersonate when a library is present, or a profile name
 * such as "chrome", "chrome116", "edge101", "safari15_5". Thread-safe. */
int anubis_fetch_get_with(const char *url, const char *target, anubis_page *out);

/* Default profile for anubis_fetch_get(): NULL/"auto" (impersonate when
 * available), "off" (never), or a profile name. The default is also settable
 * through $ANUBIS_IMPERSONATE, which takes precedence over this setting.
 * Returns 0, or -1 when the profile is not in the loaded library. */
int anubis_fetch_set_impersonate(const char *target);

/* The configured profile, "" when impersonation is disabled. */
const char *anubis_fetch_impersonate(void);

/* 1 when a usable libcurl-impersonate is installed, 0 otherwise. */
int anubis_fetch_impersonate_available(void);

/* Transport used by the calling thread's most recent fetch:
 * "openssl", or "curl-impersonate/<profile>". Never NULL. */
const char *anubis_fetch_transport(void);

/* Version of this layer, for MCP serverInfo and API /version. */
const char *anubis_fetch_version(void);

/* ------------------------------------------------------------- raw challenge
 *
 * Solve an Anubis challenge that the caller already has, with no network I/O
 * at all. The input may be:
 *
 *   - the JSON payload Anubis serves ({"rules":{...},"challenge":"<hex>",
 *     "id":"<uuid>"}, both the string and the nested-challenge spellings),
 *   - the <script id="anubis_challenge">...</script> element, or
 *   - the entire challenge page that contains it.
 *
 * The output is the raw pass-challenge query parameters, e.g.
 * "id=<uuid>&response=<hex>&nonce=<n>&elapsedTime=1", plus the parsed fields.
 * No page is fetched and no HTTPS request is made.
 *
 * The algorithms are the ones the fetch layer understands: fast, slow, sha256,
 * wasm-sha256, argon2id, hashx and tensor (proof of work), plus preact and
 * metarefresh (which compute the value Anubis expects but have no search).
 */
typedef struct {
    char algorithm[32];
    char id[128];
    char random_data[1024];
    int difficulty;
} anubis_raw_challenge;

typedef struct {
    anubis_raw_challenge challenge;
    unsigned long long nonce;
    char response[129];   /* lowercase hex digest, "" when the method has none */
    double elapsed_ms;
    int wait_ms;          /* time-based methods only; 0 for proof of work */
    char raw[8192];       /* ready-to-send pass-challenge query parameters */
} anubis_raw_solution;

/* Parse only; returns 0 on success, -1 with `err` set on malformed input. */
int anubis_parse_challenge_input(const char *input, size_t len,
                                 anubis_raw_challenge *out,
                                 char *err, size_t errcap);

/* Parse, solve, and build out->raw. threads 0 means the library default;
 * budget_ms <= 0 means no time limit. Returns 0 on success, -1 with `err`
 * set. This function never opens a socket. */
int anubis_solve_challenge_input(const char *input, size_t len, int threads,
                                 double budget_ms, anubis_raw_solution *out,
                                 char *err, size_t errcap);

#ifdef __cplusplus
}
#endif

#endif /* ANUBIS_FETCH_H */
