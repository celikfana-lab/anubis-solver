/*
 * R shim for libanubis_solver.
 *
 * R's base .C() interface discards the C return value, and every function in
 * anubis-solver.h signals success through its return code, so a .Call shim is
 * the honest way to expose it: each entry point returns the code *and* the
 * outputs, and the R layer in anubis.R turns a non-zero code into a proper R
 * condition.
 *
 * Build (see bindings/r/README.md):
 *   R CMD SHLIB -o anubisR.so src/anubis_r.c -I../../include
 */
#include <stdint.h>
#include <string.h>

#include <R.h>
#include <Rinternals.h>

#include "anubis-solver.h"

/* UTF-8 bytes of a character scalar, as a raw vector */
static SEXP char_to_raw(SEXP s)
{
    SEXP r;
    const char *p;
    if (TYPEOF(s) != STRSXP || LENGTH(s) != 1) {
        Rf_error("expected a single character string");
    }
    p = CHAR(STRING_ELT(s, 0));
    r = PROTECT(allocVector(RAWSXP, (R_xlen_t)strlen(p)));
    memcpy(RAW(r), p, (size_t)strlen(p));
    UNPROTECT(1);
    return r;
}

/* bytes of a raw vector, or the UTF-8 bytes of a string */
static const unsigned char *as_bytes(SEXP s, size_t *len)
{
    if (TYPEOF(s) == RAWSXP) {
        *len = (size_t)LENGTH(s);
        return RAW(s);
    }
    if (TYPEOF(s) == STRSXP && LENGTH(s) == 1) {
        SEXP r = char_to_raw(s); /* becomes garbage after this returns... */
        *len = (size_t)LENGTH(r);
        return RAW(r);
    }
    Rf_error("expected a raw vector or a string");
    return NULL;
}

/* ---- introspection ---------------------------------------------------- */

SEXP anubis_r_version(void) { return Rf_mkString(anubis_solver_version()); }

SEXP anubis_r_gpu_info(void)
{
    const char *g = anubis_gpu_info();
    return g ? Rf_mkString(g) : R_NilValue;
}

SEXP anubis_r_default_threads(void) { return Rf_ScalarInteger(anubis_default_threads()); }

SEXP anubis_r_affinity_info(void)
{
    const char *a = anubis_cpu_affinity_info();
    return a ? Rf_mkString(a) : R_NilValue;
}

SEXP anubis_r_batch_width(void) { return Rf_ScalarInteger(anubis_batch_width()); }

SEXP anubis_r_set_gpu_verify(SEXP enable)
{
    anubis_set_gpu_verify(Rf_asLogical(enable) ? 1 : 0);
    return R_NilValue;
}

SEXP anubis_r_gpu_verify(void) { return Rf_ScalarLogical(anubis_gpu_verify() != 0); }

/* ---- sha256 helpers --------------------------------------------------- */

SEXP anubis_r_sha256_hex(SEXP data)
{
    char out[65];
    int rc;
    size_t len = 0;
    const unsigned char *p;

    if (TYPEOF(data) == RAWSXP) {
        p = RAW(data);
        len = (size_t)LENGTH(data);
    } else if (TYPEOF(data) == STRSXP && LENGTH(data) == 1) {
        p = (const unsigned char *)CHAR(STRING_ELT(data, 0));
        len = (size_t)strlen((const char *)p);
    } else {
        Rf_error("expected a raw vector or a string");
    }
    memset(out, 0, sizeof out);
    rc = anubis_sha256_hex((const char *)p, len, out);
    if (rc != ANUBIS_OK) Rf_error("anubis_sha256_hex failed (code %d)", rc);
    return Rf_mkString(out);
}

SEXP anubis_r_sha256_midstate(SEXP data)
{
    uint32_t words[8];
    SEXP out;
    int rc;
    size_t len = 0;
    const unsigned char *p;

    if (TYPEOF(data) == RAWSXP) {
        p = RAW(data);
        len = (size_t)LENGTH(data);
    } else if (TYPEOF(data) == STRSXP && LENGTH(data) == 1) {
        p = (const unsigned char *)CHAR(STRING_ELT(data, 0));
        len = (size_t)strlen((const char *)p);
    } else {
        Rf_error("expected a raw vector or a string");
    }
    if (len % 64 != 0) Rf_error("midstate needs a length that is a multiple of 64");
    rc = anubis_sha256_midstate((const char *)p, len, words);
    if (rc != ANUBIS_OK) Rf_error("anubis_sha256_midstate failed (code %d)", rc);

    out = PROTECT(allocVector(REALSXP, 8));
    for (int i = 0; i < 8; i++) REAL(out)[i] = (double)words[i];
    UNPROTECT(1);
    return out;
}

/* ---- solving ---------------------------------------------------------- */

static SEXP result_sexp(int rc, double nonce, const char *hex, double ms)
{
    SEXP out = PROTECT(allocVector(VECSXP, 4));
    SEXP nm = PROTECT(allocVector(STRSXP, 4));
    SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(rc));
    SET_VECTOR_ELT(out, 1, Rf_ScalarReal(nonce));
    SET_VECTOR_ELT(out, 2, Rf_mkString(hex));
    SET_VECTOR_ELT(out, 3, Rf_ScalarReal(ms));
    SET_STRING_ELT(nm, 0, Rf_mkChar("status"));
    SET_STRING_ELT(nm, 1, Rf_mkChar("nonce"));
    SET_STRING_ELT(nm, 2, Rf_mkChar("hash"));
    SET_STRING_ELT(nm, 3, Rf_mkChar("ms"));
    Rf_setAttrib(out, R_NamesSymbol, nm);
    UNPROTECT(2);
    return out;
}

SEXP anubis_r_solve_nibbles(SEXP challenge, SEXP difficulty, SEXP threads,
                            SEXP max_nonce, SEXP budget_ms)
{
    uint64_t nonce = 0;
    char hex[65];
    double ms = 0.0;
    int rc;

    if (TYPEOF(challenge) != STRSXP) Rf_error("challenge must be a string");
    memset(hex, 0, sizeof hex);
    rc = anubis_solve_nibbles(CHAR(STRING_ELT(challenge, 0)),
                              (int)Rf_asInteger(difficulty),
                              (int)Rf_asInteger(threads),
                              (int64_t)Rf_asReal(max_nonce),
                              (double)Rf_asReal(budget_ms),
                              &nonce, hex, &ms);
    return result_sexp(rc, (double)nonce, hex, ms);
}

static SEXP solve_bits(const char *which, SEXP challenge_hex, SEXP difficulty,
                       SEXP threads, SEXP budget_ms)
{
    uint32_t nonce = 0;
    char hex[65];
    double ms = 0.0;
    int rc;
    const char *ch;

    if (TYPEOF(challenge_hex) != STRSXP) Rf_error("challenge must be a hex string");
    ch = CHAR(STRING_ELT(challenge_hex, 0));
    memset(hex, 0, sizeof hex);

    if (strcmp(which, "sha256") == 0) {
        rc = anubis_solve_bits(ch, (int)Rf_asInteger(difficulty), (int)Rf_asInteger(threads),
                               (double)Rf_asReal(budget_ms), &nonce, hex, &ms);
    } else if (strcmp(which, "argon2id") == 0) {
        rc = anubis_solve_argon2id(ch, (int)Rf_asInteger(difficulty), (int)Rf_asInteger(threads),
                                   (double)Rf_asReal(budget_ms), &nonce, hex, &ms);
    } else {
        rc = anubis_solve_hashx(ch, (int)Rf_asInteger(difficulty), (int)Rf_asInteger(threads),
                                (double)Rf_asReal(budget_ms), &nonce, hex, &ms);
    }
    return result_sexp(rc, (double)nonce, hex, ms);
}

SEXP anubis_r_solve_bits(SEXP ch, SEXP d, SEXP t, SEXP b) { return solve_bits("sha256", ch, d, t, b); }
SEXP anubis_r_solve_argon2id(SEXP ch, SEXP d, SEXP t, SEXP b) { return solve_bits("argon2id", ch, d, t, b); }
SEXP anubis_r_solve_hashx(SEXP ch, SEXP d, SEXP t, SEXP b) { return solve_bits("hashx", ch, d, t, b); }

/* ---- verifying -------------------------------------------------------- */

static SEXP verify_sexp(int rc, const char *hex)
{
    SEXP out = PROTECT(allocVector(VECSXP, 3));
    SEXP nm = PROTECT(allocVector(STRSXP, 3));
    SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(rc));
    SET_VECTOR_ELT(out, 1, Rf_ScalarLogical(rc == ANUBIS_OK));
    SET_VECTOR_ELT(out, 2, Rf_mkString(hex));
    SET_STRING_ELT(nm, 0, Rf_mkChar("status"));
    SET_STRING_ELT(nm, 1, Rf_mkChar("ok"));
    SET_STRING_ELT(nm, 2, Rf_mkChar("hash"));
    Rf_setAttrib(out, R_NamesSymbol, nm);
    UNPROTECT(2);
    return out;
}

SEXP anubis_r_verify_nibbles(SEXP challenge, SEXP nonce, SEXP difficulty)
{
    char hex[65];
    int rc;
    memset(hex, 0, sizeof hex);
    if (TYPEOF(challenge) != STRSXP) Rf_error("challenge must be a string");
    rc = anubis_verify_nibbles(CHAR(STRING_ELT(challenge, 0)),
                               (uint64_t)Rf_asReal(nonce),
                               (int)Rf_asInteger(difficulty), hex);
    return verify_sexp(rc, hex);
}

SEXP anubis_r_verify_bits(SEXP ch, SEXP nonce, SEXP d)
{
    char hex[65];
    int rc;
    memset(hex, 0, sizeof hex);
    if (TYPEOF(ch) != STRSXP) Rf_error("challenge must be a hex string");
    rc = anubis_verify_bits(CHAR(STRING_ELT(ch, 0)), (uint32_t)Rf_asReal(nonce),
                            (int)Rf_asInteger(d), hex);
    return verify_sexp(rc, hex);
}

SEXP anubis_r_verify_argon2id(SEXP ch, SEXP nonce, SEXP d)
{
    char hex[65];
    int rc;
    memset(hex, 0, sizeof hex);
    if (TYPEOF(ch) != STRSXP) Rf_error("challenge must be a hex string");
    rc = anubis_verify_argon2id(CHAR(STRING_ELT(ch, 0)), (uint32_t)Rf_asReal(nonce),
                                (int)Rf_asInteger(d), hex);
    return verify_sexp(rc, hex);
}

SEXP anubis_r_verify_hashx(SEXP ch, SEXP nonce, SEXP d)
{
    char hex[65];
    int rc;
    memset(hex, 0, sizeof hex);
    if (TYPEOF(ch) != STRSXP) Rf_error("challenge must be a hex string");
    rc = anubis_verify_hashx(CHAR(STRING_ELT(ch, 0)), (uint32_t)Rf_asReal(nonce),
                             (int)Rf_asInteger(d), hex);
    return verify_sexp(rc, hex);
}

/* ---- registration ----------------------------------------------------- */

static const R_CallMethodDef call_methods[] = {
    {"anubis_r_version",           (DL_FUNC)&anubis_r_version,           0},
    {"anubis_r_gpu_info",          (DL_FUNC)&anubis_r_gpu_info,          0},
    {"anubis_r_default_threads",   (DL_FUNC)&anubis_r_default_threads,   0},
    {"anubis_r_affinity_info",     (DL_FUNC)&anubis_r_affinity_info,     0},
    {"anubis_r_batch_width",       (DL_FUNC)&anubis_r_batch_width,       0},
    {"anubis_r_set_gpu_verify",    (DL_FUNC)&anubis_r_set_gpu_verify,    1},
    {"anubis_r_gpu_verify",        (DL_FUNC)&anubis_r_gpu_verify,        0},
    {"anubis_r_sha256_hex",        (DL_FUNC)&anubis_r_sha256_hex,        1},
    {"anubis_r_sha256_midstate",   (DL_FUNC)&anubis_r_sha256_midstate,   1},
    {"anubis_r_solve_nibbles",     (DL_FUNC)&anubis_r_solve_nibbles,     5},
    {"anubis_r_solve_bits",        (DL_FUNC)&anubis_r_solve_bits,        4},
    {"anubis_r_solve_argon2id",    (DL_FUNC)&anubis_r_solve_argon2id,    4},
    {"anubis_r_solve_hashx",       (DL_FUNC)&anubis_r_solve_hashx,       4},
    {"anubis_r_verify_nibbles",    (DL_FUNC)&anubis_r_verify_nibbles,    3},
    {"anubis_r_verify_bits",       (DL_FUNC)&anubis_r_verify_bits,       3},
    {"anubis_r_verify_argon2id",   (DL_FUNC)&anubis_r_verify_argon2id,   3},
    {"anubis_r_verify_hashx",      (DL_FUNC)&anubis_r_verify_hashx,      3},
    {NULL, NULL, 0}
};

void R_init_anubisR(DllInfo *dll)
{
    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
}
