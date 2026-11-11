/*
 * anubis_solver.c — native proof-of-work engine for TecharoHQ/anubis challenges.
 *
 * This file is the C core of the Python library in anubis_solver.py. It is
 * built as a shared object and loaded with ctypes.
 *
 * It understands the two SHA-256 based challenge families shipped by Anubis:
 *
 *  1. JavaScript "fast"/"slow" challenges (lib/challenge/proofofwork):
 *       message  = challenge_hex_string || decimal_nonce
 *       digest   = sha256(message)
 *       accepted when the *hex encoding* of the digest starts with
 *       `difficulty` zero nibbles (i.e. difficulty/2 zero bytes, plus a
 *       zero high nibble when difficulty is odd).
 *
 *  2. WebAssembly "sha256" challenge (wasm/pow/sha256/src/lib.rs):
 *       data     = hex_decode(challenge_hex_string)      (random bytes)
 *       message  = data || uint32_nonce
 *       nonce encoding is little-endian when data[len-1] >= 0x80,
 *       big-endian otherwise (an anti-GPU measure in Anubis)
 *       digest   = sha256(message)
 *       accepted when the *raw digest* starts with `difficulty` zero bits.
 *
 *  3. WebAssembly "argon2id" challenge (wasm/pow/argon2id/src/lib.rs):
 *       password = hex_decode(challenge)
 *       salt     = uint64_nonce, encoded LE when data[len-1] >= 0x80 else BE
 *       hash     = Argon2id(password, salt, m=19456 KiB, t=2, p=1), 32 bytes
 *       accepted when the raw digest starts with `difficulty` zero bits.
 *
 *  4. WebAssembly "hashx" challenge (wasm/pow/hashx/src/lib.rs):
 *       program  = HashX(seed = challenge bytes, with the seed-retry loop)
 *       hash     = hashx_hash_to_bytes(uint64_nonce), 32 bytes
 *       accepted when the raw digest starts with `difficulty` zero bits.
 *
 * Bundled code:
 *   - argon2/  : the reference Argon2 implementation (CC0 / Apache-2.0),
 *                used for the argon2id challenge.
 *   - hashx.c  : C port of tevador/hashx (LGPL-3.0), used for the hashx
 *                challenge. See the header of that file for provenance.
 *
 * Every worker thread owns a copy of the SHA-256 midstate after consuming the
 * fixed challenge prefix, so each nonce candidate only has to hash its own
 * suffix (the decimal digits or the 4 nonce bytes).
 *
 * On x86-64 the hot loops are hand-written assembly:
 *   avx2.s  — sha256_compress8_avx2(), eight candidate messages in one
 *             SHA-256 compression (one __m256i = the same word of 8 messages)
 *   shani.s — sha256_block_shani(), one block via the Intel SHA extension
 * Runtime dispatch picks SHA-NI for single-block hashing and AVX2 for the
 * 8-way batch, falling back to portable C. ANUBIS_NO_AVX2=1 /
 * ANUBIS_NO_SHANI=1 force the lower paths for A/B measurements.
 *
 * Build:  make            (see Makefile)
 * Test:   make check
 */

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "argon2.h"
#include "hashx.h"

#ifdef __GNUC__
#define ANUBIS_EXPORT __attribute__((visibility("default")))
#else
#define ANUBIS_EXPORT
#endif

/* ------------------------------------------------------------------ */
/* Return codes                                                        */
/* ------------------------------------------------------------------ */

#define ANUBIS_OK 0          /* solved / verified                          */
#define ANUBIS_ERR_ARG 1     /* bad argument                               */
#define ANUBIS_ERR_UNSOLVED 2/* search space / time budget exhausted       */
#define ANUBIS_ERR_INTERNAL 3/* thread or allocation failure               */

/* ------------------------------------------------------------------ */
/* SHA-256                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t h[8];
    uint64_t total;   /* total bytes fed */
    uint8_t block[64];
    size_t used;      /* bytes currently buffered */
} sha256_ctx;

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void sha256_compress_scalar(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, hh;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = load_be32(block + 4 * i);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;

        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

/* SHA-NI single-block compression lives in shani.s. */
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define ANUBIS_HAVE_SHANI_ASM 1
extern void sha256_block_shani(uint32_t state[8], const uint8_t block[64]);

static int sha_ni_available(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *off = getenv("ANUBIS_NO_SHANI");
        if (off != NULL && off[0] != '\0' && off[0] != '0') {
            cached = 0;
        } else {
            __builtin_cpu_init();
            cached = __builtin_cpu_supports("sha") ? 1 : 0;
        }
    }
    return cached;
}
#endif

static void sha256_compress(uint32_t h[8], const uint8_t block[64]) {
#ifdef ANUBIS_HAVE_SHANI_ASM
    if (sha_ni_available()) {
        sha256_block_shani(h, block);
        return;
    }
#endif
    sha256_compress_scalar(h, block);
}

static void sha256_init(sha256_ctx *c) {
    static const uint32_t IV[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    memcpy(c->h, IV, sizeof(IV));
    c->total = 0;
    c->used = 0;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t n;

    c->total += (uint64_t)len;

    if (c->used) {
        n = 64 - c->used;
        if (n > len) {
            n = len;
        }
        memcpy(c->block + c->used, p, n);
        c->used += n;
        p += n;
        len -= n;
        if (c->used == 64) {
            sha256_compress(c->h, c->block);
            c->used = 0;
        }
    }

    while (len >= 64) {
        sha256_compress(c->h, p);
        p += 64;
        len -= 64;
    }

    if (len) {
        memcpy(c->block + c->used, p, len);
        c->used += len;
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    uint8_t pad[72];
    size_t padlen;
    int i;

    pad[0] = 0x80;
    memset(pad + 1, 0, sizeof(pad) - 1);

    /* 0x80 + zeroes, ending with the 8-byte big-endian bit count, so that
     * (used + padlen) % 64 == 0. */
    padlen = (c->used < 56) ? (56 - c->used) : (120 - c->used);

    sha256_update(c, pad, padlen);

    {
        uint8_t lenbuf[8];
        for (i = 7; i >= 0; i--) {
            lenbuf[i] = (uint8_t)(bits & 0xff);
            bits >>= 8;
        }
        sha256_update(c, lenbuf, 8);
    }

    for (i = 0; i < 8; i++) {
        store_be32(out + 4 * i, c->h[i]);
    }
}

static void to_hex(const uint8_t *in, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int hex_decode(const char *hex, uint8_t *out, size_t out_cap,
                      size_t *out_len) {
    size_t n = 0;
    int hi = -1;

    if (!hex) {
        return ANUBIS_ERR_ARG;
    }
    for (; *hex; hex++) {
        int v;
        char ch = *hex;
        if (ch >= '0' && ch <= '9') {
            v = ch - '0';
        } else if (ch >= 'a' && ch <= 'f') {
            v = ch - 'a' + 10;
        } else if (ch >= 'A' && ch <= 'F') {
            v = ch - 'A' + 10;
        } else {
            return ANUBIS_ERR_ARG; /* no whitespace tolerance on purpose */
        }
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= out_cap) {
                return ANUBIS_ERR_ARG;
            }
            out[n++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    if (hi >= 0) {
        return ANUBIS_ERR_ARG; /* odd number of hex digits */
    }
    *out_len = n;
    return ANUBIS_OK;
}

/* ------------------------------------------------------------------ */
/* Difficulty predicates                                               */
/* ------------------------------------------------------------------ */

/* `difficulty` leading zero nibbles of the hex digest. */
static inline int nibbles_ok(const uint8_t digest[32], int difficulty) {
    int full = difficulty / 2;
    int i;
    for (i = 0; i < full; i++) {
        if (digest[i] != 0) {
            return 0;
        }
    }
    if (difficulty & 1) {
        if ((digest[full] >> 4) != 0) {
            return 0;
        }
    }
    return 1;
}

/* `difficulty` leading zero bits of the raw digest. */
static inline int bits_ok(const uint8_t digest[32], int difficulty) {
    int full = difficulty / 8;
    int rem = difficulty % 8;
    int i;
    for (i = 0; i < full; i++) {
        if (digest[i] != 0) {
            return 0;
        }
    }
    if (rem && (digest[full] & (uint8_t)(0xffu << (8 - rem))) != 0) {
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static int u64_to_dec(uint64_t v, char out[24]) {
    char tmp[24];
    int n = 0;
    int i;
    if (v == 0) {
        out[0] = '0';
        return 1;
    }
    while (v) {
        tmp[n++] = (char)('0' + (int)(v % 10));
        v /= 10;
    }
    for (i = 0; i < n; i++) {
        out[i] = tmp[n - 1 - i];
    }
    return n;
}

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ------------------------------------------------------------------ */
/* Hash backends for the search loop                                   */
/* ------------------------------------------------------------------ */

typedef int (*anubis_hash_fn)(void *ctx, uint64_t nonce, uint8_t out[32]);

/* fast/slow: sha256(challenge_ascii || decimal_nonce). The challenge is
 * folded into the midstate once, so only the decimal suffix is hashed. */
typedef struct {
    sha256_ctx base;
} fast_ctx;

static int hash_fast(void *vctx, uint64_t nonce, uint8_t out[32]) {
    fast_ctx *c = (fast_ctx *)vctx;
    sha256_ctx ctx = c->base;
    char num[24];
    int n = u64_to_dec(nonce, num);

    sha256_update(&ctx, num, (size_t)n);
    sha256_final(&ctx, out);
    return 0;
}

/* wasm sha256: sha256(raw_challenge || uint32_nonce[le|be]). */
typedef struct {
    sha256_ctx base;
    int use_le;
} bits_ctx;

static int hash_bits(void *vctx, uint64_t nonce, uint8_t out[32]) {
    bits_ctx *c = (bits_ctx *)vctx;
    sha256_ctx ctx = c->base;
    uint8_t suffix[4];
    uint32_t n32 = (uint32_t)nonce;

    if (c->use_le) {
        suffix[0] = (uint8_t)n32;
        suffix[1] = (uint8_t)(n32 >> 8);
        suffix[2] = (uint8_t)(n32 >> 16);
        suffix[3] = (uint8_t)(n32 >> 24);
    } else {
        suffix[0] = (uint8_t)(n32 >> 24);
        suffix[1] = (uint8_t)(n32 >> 16);
        suffix[2] = (uint8_t)(n32 >> 8);
        suffix[3] = (uint8_t)n32;
    }

    sha256_update(&ctx, suffix, 4);
    sha256_final(&ctx, out);
    return 0;
}

/* argon2id: Argon2id(password=raw_challenge, salt=u64_nonce[le|be],
 * m=19456 KiB, t=2, p=1 - the parameters of argon2::Argon2::default()). */
typedef struct {
    const uint8_t *data;
    size_t len;
    int use_le;
} argon_ctx;

static int hash_argon2id(void *vctx, uint64_t nonce, uint8_t out[32]) {
    argon_ctx *c = (argon_ctx *)vctx;
    uint8_t salt[8];
    int i;

    for (i = 0; i < 8; i++) {
        salt[i] = c->use_le ? (uint8_t)(nonce >> (8 * i))
                            : (uint8_t)(nonce >> (8 * (7 - i)));
    }

    if (argon2id_hash_raw(2, 19456, 1, c->data, c->len, salt, sizeof(salt),
                          out, 32) != ARGON2_OK) {
        return -1;
    }
    return 0;
}

/* hashx: Tor's HashX interpreter over the challenge-derived program. */
typedef struct {
    const void *state;
    size_t size;
} hashx_ctx;

static int hash_hashx(void *vctx, uint64_t nonce, uint8_t out[32]) {
    hashx_ctx *c = (hashx_ctx *)vctx;
    hashx_hash(c->state, c->size, nonce, out);
    return 0;
}


/* ------------------------------------------------------------------ */
/* AVX2: eight SHA-256 messages in parallel                            */
/* ------------------------------------------------------------------ */
/* Proof-of-work walks the nonce, so eight candidates in a batch share
 * the same message length and therefore the same padding. That makes
 * them a natural fit for 8-lane AVX2: one __m256i holds the same word
 * of eight different messages.
 *
 * The compression kernel is hand-written assembly in avx2.s; only the
 * batch construction (padding, decimal formatting) lives here.
 */

typedef struct {
    const uint32_t *mid;   /* midstate after the shared prefix */
    size_t prefix_len;     /* bytes already folded into mid */
    int use_le;            /* WASM nonce byte order */
} batch_ctx;

enum {
    BATCH_NONE = 0,
    BATCH_DECIMALS = 1,    /* fast/slow: prefix + decimal nonce */
    BATCH_FIXED4 = 2       /* wasm sha256: prefix + 4-byte nonce */
};

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define ANUBIS_HAVE_AVX2 1
extern void sha256_compress8_avx2(const uint32_t mid[8],
                                  const uint8_t tails[8][64],
                                  uint8_t out[8][32]);

static int anubis_avx2_available(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *off = getenv("ANUBIS_NO_AVX2");
        if (off != NULL && off[0] != '\0' && off[0] != '0') {
            cached = 0;
        } else {
            __builtin_cpu_init();
            cached = __builtin_cpu_supports("avx2") ? 1 : 0;
        }
    }
    return cached;
}

static void store_length_be(uint8_t *tail, uint64_t bits) {
    int i;
    for (i = 0; i < 8; i++) {
        tail[56 + i] = (uint8_t)(bits >> (8 * (7 - i)));
    }
}

/* fast/slow: all eight lanes must have the same decimal digit count. */
static int batch_decimals(const batch_ctx *c, uint64_t nonce, uint32_t stride,
                          uint8_t out[8][32]) {
    char digits[8][24];
    int dlen[8];
    uint8_t tails[8][64];
    uint64_t bits;
    int lane;

    if (c->prefix_len % 64u != 0) {
        return 0;
    }
    for (lane = 0; lane < 8; lane++) {
        uint64_t n = nonce + (uint64_t)lane * (uint64_t)stride;
        dlen[lane] = u64_to_dec(n, digits[lane]);
        if (dlen[lane] != dlen[0]) {
            return 0; /* mixed lengths -> caller hashes one scalar */
        }
    }
    bits = ((uint64_t)c->prefix_len + (uint64_t)dlen[0]) * 8u;
    for (lane = 0; lane < 8; lane++) {
        memset(tails[lane], 0, 64);
        memcpy(tails[lane], digits[lane], (size_t)dlen[0]);
        tails[lane][dlen[0]] = 0x80;
        store_length_be(tails[lane], bits);
    }
    sha256_compress8_avx2(c->mid, (const uint8_t (*)[64])tails, out);
    return 1;
}

/* wasm sha256: prefix + uint32 nonce, one byte order for the whole run. */
static int batch_fixed4(const batch_ctx *c, uint64_t nonce, uint32_t stride,
                        uint8_t out[8][32]) {
    uint8_t tails[8][64];
    uint64_t bits = ((uint64_t)c->prefix_len + 4u) * 8u;
    int lane;

    if (c->prefix_len % 64u != 0) {
        return 0;
    }
    for (lane = 0; lane < 8; lane++) {
        uint64_t n64 = nonce + (uint64_t)lane * (uint64_t)stride;
        uint32_t n;
        if (n64 > 0xffffffffull) {
            return 0;
        }
        n = (uint32_t)n64;
        memset(tails[lane], 0, 64);
        if (c->use_le) {
            tails[lane][0] = (uint8_t)n;
            tails[lane][1] = (uint8_t)(n >> 8);
            tails[lane][2] = (uint8_t)(n >> 16);
            tails[lane][3] = (uint8_t)(n >> 24);
        } else {
            tails[lane][0] = (uint8_t)(n >> 24);
            tails[lane][1] = (uint8_t)(n >> 16);
            tails[lane][2] = (uint8_t)(n >> 8);
            tails[lane][3] = (uint8_t)n;
        }
        tails[lane][4] = 0x80;
        store_length_be(tails[lane], bits);
    }
    sha256_compress8_avx2(c->mid, (const uint8_t (*)[64])tails, out);
    return 1;
}

#else /* no AVX2 host */

static int anubis_avx2_available(void) { return 0; }

static int batch_decimals(const batch_ctx *c, uint64_t nonce, uint32_t stride,
                          uint8_t out[8][32]) {
    (void)c; (void)nonce; (void)stride; (void)out;
    return 0;
}

static int batch_fixed4(const batch_ctx *c, uint64_t nonce, uint32_t stride,
                        uint8_t out[8][32]) {
    (void)c; (void)nonce; (void)stride; (void)out;
    return 0;
}

#endif /* x86-64 */

/* ------------------------------------------------------------------ */
/* Threaded search                                                     */
/* ------------------------------------------------------------------ */

enum solve_mode {
    MODE_NIBBLES = 0,
    MODE_BITS = 1
};

typedef struct {
    anubis_hash_fn hash;    /* backend under test */
    void *hash_ctx;
    int mode;
    int difficulty;
    int threads;
    unsigned check_mask;    /* deadline check cadence: 0 = every iteration */
    int batch_kind;         /* BATCH_* fast path, 0 = scalar only */
    batch_ctx bctx;

    pthread_mutex_t mu;
    volatile int found;
    volatile int stop;
    volatile int error;
    uint64_t nonce;
    uint8_t digest[32];
    double deadline;        /* monotonic seconds; 0 = no deadline */
} solve_job;

typedef struct {
    solve_job *job;
    int tid;
} worker_arg;

static void worker_loop(solve_job *job, int tid) {
    uint8_t digest[32];
    uint64_t iters = 0;

    if (job->mode == MODE_NIBBLES) {
        uint64_t nonce = (uint64_t)tid;

        for (;;) {
            if (job->stop) {
                return;
            }

            if (job->batch_kind == BATCH_DECIMALS) {
                uint8_t outs[8][32];
                if (batch_decimals(&job->bctx, nonce, (uint32_t)job->threads,
                                   outs)) {
                    int k;
                    for (k = 0; k < 8; k++) {
                        if (nibbles_ok(outs[k], job->difficulty)) {
                            pthread_mutex_lock(&job->mu);
                            if (!job->found) {
                                job->found = 1;
                                job->nonce = nonce +
                                             (uint64_t)k * (uint64_t)job->threads;
                                memcpy(job->digest, outs[k], 32);
                            }
                            pthread_mutex_unlock(&job->mu);
                            return;
                        }
                    }
                    nonce += 8u * (uint64_t)job->threads;
                    if (job->deadline > 0.0 && now_seconds() > job->deadline) {
                        job->stop = 1;
                        return;
                    }
                    continue;
                }
                /* mixed digit counts: fall through and hash one scalar */
            }

            if (job->hash(job->hash_ctx, nonce, digest) != 0) {
                job->error = 1;
                job->stop = 1;
                return;
            }
            if (nibbles_ok(digest, job->difficulty)) {
                pthread_mutex_lock(&job->mu);
                if (!job->found) {
                    job->found = 1;
                    job->nonce = nonce;
                    memcpy(job->digest, digest, 32);
                }
                pthread_mutex_unlock(&job->mu);
                return;
            }

            nonce += (uint64_t)job->threads;

            if (job->deadline > 0.0 &&
                (job->check_mask == 0 || (++iters & job->check_mask) == 0) &&
                now_seconds() > job->deadline) {
                job->stop = 1;
                return;
            }
        }
    } else {
        uint64_t nonce = (uint64_t)tid;

        for (;;) {
            if (job->stop) {
                return;
            }

            if (job->batch_kind == BATCH_FIXED4 &&
                nonce + 7u * (uint64_t)job->threads <= 0xffffffffull) {
                uint8_t outs[8][32];
                if (batch_fixed4(&job->bctx, nonce, (uint32_t)job->threads,
                                 outs)) {
                    int k;
                    for (k = 0; k < 8; k++) {
                        if (bits_ok(outs[k], job->difficulty)) {
                            pthread_mutex_lock(&job->mu);
                            if (!job->found) {
                                job->found = 1;
                                job->nonce = nonce +
                                             (uint64_t)k * (uint64_t)job->threads;
                                memcpy(job->digest, outs[k], 32);
                            }
                            pthread_mutex_unlock(&job->mu);
                            return;
                        }
                    }
                    nonce += 8u * (uint64_t)job->threads;
                    if (job->deadline > 0.0 && now_seconds() > job->deadline) {
                        job->stop = 1;
                        return;
                    }
                    continue;
                }
            }

            if (nonce > 0xffffffffull) {
                return;
            }
            if (job->hash(job->hash_ctx, nonce, digest) != 0) {
                job->error = 1;
                job->stop = 1;
                return;
            }
            if (bits_ok(digest, job->difficulty)) {
                pthread_mutex_lock(&job->mu);
                if (!job->found) {
                    job->found = 1;
                    job->nonce = nonce;
                    memcpy(job->digest, digest, 32);
                }
                pthread_mutex_unlock(&job->mu);
                return;
            }

            nonce += (uint64_t)job->threads;
            if (nonce > 0xffffffffull) {
                return;
            }

            if (job->deadline > 0.0 &&
                (job->check_mask == 0 || (++iters & job->check_mask) == 0) &&
                now_seconds() > job->deadline) {
                job->stop = 1;
                return;
            }
        }
    }
}

static void *worker_entry(void *arg) {
    worker_arg *wa = (worker_arg *)arg;
    worker_loop(wa->job, wa->tid);
    return NULL;
}

/*
 * Run the threaded search. Returns ANUBIS_OK with *out_nonce / out_hex filled
 * in, ANUBIS_ERR_UNSOLVED on exhaustion/timeout, or an error code.
 */
static int run_search(solve_job *job, uint64_t *out_nonce, char out_hex[65],
                      double *out_ms) {
    pthread_t *tids = NULL;
    worker_arg *args = NULL;
    int i;
    int rc = ANUBIS_OK;
    double t0;

    pthread_mutex_init(&job->mu, NULL);

    tids = (pthread_t *)calloc((size_t)job->threads, sizeof(*tids));
    args = (worker_arg *)calloc((size_t)job->threads, sizeof(*args));
    if (!tids || !args) {
        rc = ANUBIS_ERR_INTERNAL;
        goto done;
    }

    t0 = now_seconds();
    for (i = 0; i < job->threads; i++) {
        args[i].job = job;
        args[i].tid = i;
        if (pthread_create(&tids[i], NULL, worker_entry, &args[i]) != 0) {
            /* Run with however many threads started; stop the rest. */
            job->threads = i;
            if (i == 0) {
                rc = ANUBIS_ERR_INTERNAL;
            }
            break;
        }
    }

    for (i = 0; i < job->threads; i++) {
        pthread_join(tids[i], NULL);
    }

    if (out_ms) {
        *out_ms = (now_seconds() - t0) * 1000.0;
    }

    if (job->found) {
        *out_nonce = job->nonce;
        to_hex(job->digest, 32, out_hex);
    } else if (job->error) {
        rc = ANUBIS_ERR_INTERNAL;
    } else if (rc == ANUBIS_OK) {
        rc = ANUBIS_ERR_UNSOLVED;
    }

done:
    free(tids);
    free(args);
    pthread_mutex_destroy(&job->mu);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Public API: JavaScript fast/slow challenges (leading zero nibbles)  */
/* ------------------------------------------------------------------ */

ANUBIS_EXPORT
int anubis_solve_nibbles(const char *challenge, int difficulty, int threads,
                         int64_t max_nonce, double budget_ms,
                         uint64_t *out_nonce, char *out_hex,
                         double *out_ms) {
    solve_job job;
    fast_ctx ctx;
    size_t clen;

    if (!challenge || !out_nonce || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 64) {
        return ANUBIS_ERR_ARG;
    }
    if (threads < 1) {
        threads = 1;
    }
    if (threads > 256) {
        threads = 256;
    }

    memset(&job, 0, sizeof(job));
    job.mode = MODE_NIBBLES;
    job.hash = hash_fast;
    job.hash_ctx = &ctx;
    job.check_mask = 0x3ffu;
    job.difficulty = difficulty;
    job.threads = threads;
    if (budget_ms > 0.0) {
        job.deadline = now_seconds() + budget_ms / 1000.0;
    }

    clen = strlen(challenge);
    sha256_init(&ctx.base);
    sha256_update(&ctx.base, challenge, clen);

    job.batch_kind = (anubis_avx2_available() && clen % 64u == 0)
                         ? BATCH_DECIMALS
                         : BATCH_NONE;
    job.bctx.mid = ctx.base.h;
    job.bctx.prefix_len = clen;
    job.bctx.use_le = 0;

    /* max_nonce is accepted for API symmetry; the search is unbounded like
     * the browser implementation (nonce is a JS Number, printed in decimal). */
    (void)max_nonce;

    return run_search(&job, out_nonce, out_hex, out_ms);
}

ANUBIS_EXPORT
int anubis_verify_nibbles(const char *challenge, uint64_t nonce, int difficulty,
                          char *out_hex) {
    sha256_ctx c;
    uint8_t digest[32];
    char num[24];
    int n;

    if (!challenge || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 64) {
        return ANUBIS_ERR_ARG;
    }

    sha256_init(&c);
    sha256_update(&c, challenge, strlen(challenge));
    n = u64_to_dec(nonce, num);
    sha256_update(&c, num, (size_t)n);
    sha256_final(&c, digest);
    to_hex(digest, 32, out_hex);

    return nibbles_ok(digest, difficulty) ? ANUBIS_OK : ANUBIS_ERR_UNSOLVED;
}

/* ------------------------------------------------------------------ */
/* Public API: WASM sha256 challenge (leading zero bits)               */
/* ------------------------------------------------------------------ */

ANUBIS_EXPORT
int anubis_solve_bits(const char *challenge_hex, int difficulty, int threads,
                      double budget_ms, uint32_t *out_nonce, char *out_hex,
                      double *out_ms) {
    solve_job job;
    bits_ctx ctx;
    uint8_t raw[4096];
    size_t raw_len = 0;
    uint64_t nonce64 = 0;
    int rc;

    if (!challenge_hex || !out_nonce || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 256) {
        return ANUBIS_ERR_ARG;
    }
    if (threads < 1) {
        threads = 1;
    }
    if (threads > 256) {
        threads = 256;
    }

    rc = hex_decode(challenge_hex, raw, sizeof(raw), &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }

    memset(&job, 0, sizeof(job));
    job.mode = MODE_BITS;
    job.hash = hash_bits;
    job.hash_ctx = &ctx;
    job.check_mask = 0x3ffu;
    job.difficulty = difficulty;
    job.threads = threads;
    if (budget_ms > 0.0) {
        job.deadline = now_seconds() + budget_ms / 1000.0;
    }

    ctx.use_le = raw_len > 0 && raw[raw_len - 1] >= 0x80;
    sha256_init(&ctx.base);
    sha256_update(&ctx.base, raw, raw_len);

    job.batch_kind = (anubis_avx2_available() && raw_len % 64u == 0)
                         ? BATCH_FIXED4
                         : BATCH_NONE;
    job.bctx.mid = ctx.base.h;
    job.bctx.prefix_len = raw_len;
    job.bctx.use_le = ctx.use_le;

    rc = run_search(&job, &nonce64, out_hex, out_ms);
    if (rc == ANUBIS_OK) {
        *out_nonce = (uint32_t)nonce64;
    }
    return rc;
}

ANUBIS_EXPORT
int anubis_verify_bits(const char *challenge_hex, uint32_t nonce, int difficulty,
                       char *out_hex) {
    sha256_ctx c;
    uint8_t raw[4096];
    size_t raw_len = 0;
    uint8_t digest[32];
    uint8_t suffix[4];
    int use_le;
    int rc;

    if (!challenge_hex || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 256) {
        return ANUBIS_ERR_ARG;
    }

    rc = hex_decode(challenge_hex, raw, sizeof(raw), &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }
    use_le = raw_len > 0 && raw[raw_len - 1] >= 0x80;

    if (use_le) {
        suffix[0] = (uint8_t)nonce;
        suffix[1] = (uint8_t)(nonce >> 8);
        suffix[2] = (uint8_t)(nonce >> 16);
        suffix[3] = (uint8_t)(nonce >> 24);
    } else {
        suffix[0] = (uint8_t)(nonce >> 24);
        suffix[1] = (uint8_t)(nonce >> 16);
        suffix[2] = (uint8_t)(nonce >> 8);
        suffix[3] = (uint8_t)nonce;
    }

    sha256_init(&c);
    sha256_update(&c, raw, raw_len);
    sha256_update(&c, suffix, 4);
    sha256_final(&c, digest);
    to_hex(digest, 32, out_hex);

    return bits_ok(digest, difficulty) ? ANUBIS_OK : ANUBIS_ERR_UNSOLVED;
}

/* ------------------------------------------------------------------ */
/* Public API: WASM argon2id challenge (leading zero bits)             */
/* ------------------------------------------------------------------ */

/* argon2::Argon2::default() uses m=19456 KiB, so each worker needs ~19 MiB. */
#define ANUBIS_ARGON2_THREADS_MAX 16

static int argon2id_digest(const uint8_t *raw, size_t raw_len, uint32_t nonce,
                           uint8_t out[32]) {
    uint8_t salt[8];
    int use_le = raw_len > 0 && raw[raw_len - 1] >= 0x80;
    uint64_t n = (uint64_t)nonce;
    int i;

    for (i = 0; i < 8; i++) {
        salt[i] = use_le ? (uint8_t)(n >> (8 * i))
                         : (uint8_t)(n >> (8 * (7 - i)));
    }

    return argon2id_hash_raw(2, 19456, 1, raw, raw_len, salt, sizeof(salt),
                             out, 32) == ARGON2_OK
               ? ANUBIS_OK
               : ANUBIS_ERR_INTERNAL;
}

ANUBIS_EXPORT
int anubis_solve_argon2id(const char *challenge_hex, int difficulty, int threads,
                          double budget_ms, uint32_t *out_nonce, char *out_hex,
                          double *out_ms) {
    solve_job job;
    argon_ctx ctx;
    uint8_t raw[4096];
    size_t raw_len = 0;
    uint64_t nonce64 = 0;
    int rc;

    if (!challenge_hex || !out_nonce || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 256) {
        return ANUBIS_ERR_ARG;
    }
    if (threads < 1) {
        threads = 1;
    }
    if (threads > ANUBIS_ARGON2_THREADS_MAX) {
        threads = ANUBIS_ARGON2_THREADS_MAX;
    }

    rc = hex_decode(challenge_hex, raw, sizeof(raw), &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }

    memset(&job, 0, sizeof(job));
    job.mode = MODE_BITS;
    job.hash = hash_argon2id;
    job.hash_ctx = &ctx;
    job.check_mask = 0; /* one Argon2 hash is milliseconds: check every loop */
    job.difficulty = difficulty;
    job.threads = threads;
    if (budget_ms > 0.0) {
        job.deadline = now_seconds() + budget_ms / 1000.0;
    }

    ctx.data = raw;
    ctx.len = raw_len;
    ctx.use_le = raw_len > 0 && raw[raw_len - 1] >= 0x80;

    rc = run_search(&job, &nonce64, out_hex, out_ms);
    if (rc == ANUBIS_OK) {
        *out_nonce = (uint32_t)nonce64;
    }
    return rc;
}

ANUBIS_EXPORT
int anubis_verify_argon2id(const char *challenge_hex, uint32_t nonce,
                           int difficulty, char *out_hex) {
    uint8_t raw[4096];
    size_t raw_len = 0;
    uint8_t digest[32];
    int rc;

    if (!challenge_hex || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 256) {
        return ANUBIS_ERR_ARG;
    }

    rc = hex_decode(challenge_hex, raw, sizeof(raw), &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }
    rc = argon2id_digest(raw, raw_len, nonce, digest);
    if (rc != ANUBIS_OK) {
        return rc;
    }
    to_hex(digest, 32, out_hex);

    return bits_ok(digest, difficulty) ? ANUBIS_OK : ANUBIS_ERR_UNSOLVED;
}

/* ------------------------------------------------------------------ */
/* Public API: WASM hashx challenge (leading zero bits)                */
/* ------------------------------------------------------------------ */

ANUBIS_EXPORT
int anubis_solve_hashx(const char *challenge_hex, int difficulty, int threads,
                       double budget_ms, uint32_t *out_nonce, char *out_hex,
                       double *out_ms) {
    solve_job job;
    hashx_ctx ctx;
    uint8_t raw[4096];
    size_t raw_len = 0;
    uint64_t nonce64 = 0;
    void *state = NULL;
    size_t state_size = 0;
    int rc;

    if (!challenge_hex || !out_nonce || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 256) {
        return ANUBIS_ERR_ARG;
    }
    if (threads < 1) {
        threads = 1;
    }
    if (threads > 256) {
        threads = 256;
    }

    rc = hex_decode(challenge_hex, raw, sizeof(raw), &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }

    rc = hashx_init(raw, raw_len, &state, &state_size);
    if (rc != 0) {
        return ANUBIS_ERR_INTERNAL;
    }

    memset(&job, 0, sizeof(job));
    job.mode = MODE_BITS;
    job.hash = hash_hashx;
    job.hash_ctx = &ctx;
    job.check_mask = 0x3ffu;
    job.difficulty = difficulty;
    job.threads = threads;
    if (budget_ms > 0.0) {
        job.deadline = now_seconds() + budget_ms / 1000.0;
    }

    ctx.state = state;
    ctx.size = state_size;

    rc = run_search(&job, &nonce64, out_hex, out_ms);
    hashx_free(state);

    if (rc == ANUBIS_OK) {
        *out_nonce = (uint32_t)nonce64;
    }
    return rc;
}

ANUBIS_EXPORT
int anubis_verify_hashx(const char *challenge_hex, uint32_t nonce, int difficulty,
                        char *out_hex) {
    uint8_t raw[4096];
    size_t raw_len = 0;
    uint8_t digest[32];
    void *state = NULL;
    size_t state_size = 0;
    int rc;

    if (!challenge_hex || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 256) {
        return ANUBIS_ERR_ARG;
    }

    rc = hex_decode(challenge_hex, raw, sizeof(raw), &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }
    rc = hashx_init(raw, raw_len, &state, &state_size);
    if (rc != 0) {
        return ANUBIS_ERR_INTERNAL;
    }
    hashx_hash(state, state_size, (uint64_t)nonce, digest);
    hashx_free(state);

    to_hex(digest, 32, out_hex);
    return bits_ok(digest, difficulty) ? ANUBIS_OK : ANUBIS_ERR_UNSOLVED;
}

/* ------------------------------------------------------------------ */
/* Public API: helpers                                                 */
/* ------------------------------------------------------------------ */

/* Plain SHA-256 for unit tests and diagnostics. */
ANUBIS_EXPORT
int anubis_sha256_hex(const char *data, size_t len, char *out_hex) {
    sha256_ctx c;
    uint8_t digest[32];

    if (!out_hex || (!data && len)) {
        return ANUBIS_ERR_ARG;
    }
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, digest);
    to_hex(digest, 32, out_hex);
    return ANUBIS_OK;
}

ANUBIS_EXPORT
const char *anubis_solver_version(void) {
    return "1.0.0";
}
