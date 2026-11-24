/*
 * tpu_backend.c — the Anubis `sha256` proof of work on a TPU, as library code.
 *
 * This is sha256_pjrt.c with the command line, the printing and the exit()
 * calls removed. It keeps the same bet: a sha256 challenge is many independent
 * one-block messages (one per nonce), which is the shape a TPU likes. The host
 * builds the 16 message words for nonce 0 with the padding already in place,
 * bakes them into the StableHLO module as constants, and uploads only the base
 * nonce for each window. The module computes `lanes` candidates at once, the
 * device decides "does this lane meet the target?", and the host re-derives
 * every reported digest before believing it.
 *
 * Library rules applied here, because this object is linked into
 * libanubis_solver.so and loaded into arbitrary host processes:
 *
 *   - not one write to stdout or stderr; no exit(), no abort(), no assert;
 *   - the plugin is probed once (pthread_once) and the result is cached, so a
 *     missing libtpu costs one failed dlopen for the process;
 *   - a client is created once; the compiled executable and the read-back
 *     buffer are cached for the last (challenge, difficulty, window) key, and
 *     executions are serialized with a mutex so concurrent callers cannot
 *     interleave PJRT calls;
 *   - everything the module builder allocates is released after compile. The
 *     standalone client could leak "because the process is about to end"; a
 *     library called for many challenges cannot.
 *
 * The nonce byte order comes from the caller: little-endian when the last
 * decoded challenge byte has its high bit set, big-endian otherwise.
 *
 * Build:  cc -O2 -fPIC -Wall -Wextra -std=gnu17 -I. -c tpu_backend.c
 */
#include <dlfcn.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "meatrider/meatrider.h"
#include "pjrt_c_api.h"
#include "pjrt_common.h"
#include "tpu_backend.h"

/* Lanes per PJRT execution. 131072 was the sweet spot for the stand-alone
 * client's 343 MHash/s on Colab; ANUBIS_TPU_WINDOW overrides it, clamped so a
 * typo cannot ask for a 16-lane or a 100M-lane module. */
#define TPU_DEFAULT_WINDOW 131072
#define TPU_MIN_WINDOW 1024
#define TPU_MAX_WINDOW 262144

/* ==================================================================== */
/* text buffer, name arena and HLO generation                           */
/* ==================================================================== */

typedef struct {
    char *s;
    size_t len, cap;
    int oom;
} buf_t;

typedef struct arena_chunk {
    struct arena_chunk *next;
    size_t used, cap;
    char data[];
} arena_chunk;

/*
 * The standalone builder handed every HLO name its own malloc and never freed
 * them, which is fine for one module in a one-shot process and not fine here.
 * Names do not need individual lifetimes: a bump arena owns them until the
 * module text is complete, then releases the whole arena at once.
 */
typedef struct {
    arena_chunk *head;
    int oom;
} arena_t;

typedef struct {
    buf_t b;
    arena_t arena;
    int id;
    int lanes;
} modbuilder;

#define ARENA_CHUNK ((size_t)65536)

static void *arena_alloc(arena_t *a, size_t n) {
    arena_chunk *c = a->head;
    void *p;

    n = (n + 15u) & ~(size_t)15u;
    if (c == NULL || c->used + n > c->cap) {
        size_t cap = n > ARENA_CHUNK ? n : ARENA_CHUNK;
        c = malloc(sizeof *c + cap);
        if (c == NULL) {
            a->oom = 1;
            return NULL;
        }
        c->next = a->head;
        c->used = 0;
        c->cap = cap;
        a->head = c;
    }
    p = c->data + c->used;
    c->used += n;
    return p;
}

static void arena_release(arena_t *a) {
    arena_chunk *c = a->head;

    while (c != NULL) {
        arena_chunk *next = c->next;
        free(c);
        c = next;
    }
    a->head = NULL;
}

/* "%<prefix><id>", the builder's only kind of name. "" on allocation failure;
 * the builder's oom flag makes the resulting module text irrelevant. */
static const char *mb_name(modbuilder *bd, const char *prefix) {
    char *s = arena_alloc(&bd->arena, 32);

    if (s == NULL) {
        return "";
    }
    snprintf(s, 32, "%%%s%d", prefix, bd->id++);
    return s;
}

static void bprintf(buf_t *b, const char *fmt, ...) {
    va_list ap;
    int need;

    if (b->oom) {
        return;
    }
    va_start(ap, fmt);
    need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) {
        b->oom = 1;
        return;
    }
    if (b->len + (size_t)need + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 65536;
        char *grown;
        while (cap < b->len + (size_t)need + 1) {
            if (cap > SIZE_MAX / 2) {
                b->oom = 1;
                return;
            }
            cap *= 2;
        }
        grown = realloc(b->s, cap);
        if (grown == NULL) {
            b->oom = 1;
            return;
        }
        b->s = grown;
        b->cap = cap;
    }
    va_start(ap, fmt);
    vsnprintf(b->s + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    b->len += (size_t)need;
}

/* A scalar i32 constant broadcast to one value per lane. The signed decimal
 * matters: MLIR reads these as signed i32, so 0xffffffff must be -1. */
static const char *mb_const(modbuilder *bd, uint32_t value) {
    const char *scalar = mb_name(bd, "c");
    const char *splat = mb_name(bd, "s");

    bprintf(&bd->b, "    %s = stablehlo.constant dense<%d> : tensor<i32>\n",
            scalar, (int32_t)value);
    bprintf(&bd->b, "    %s = stablehlo.broadcast_in_dim %s, dims = [] "
                    ": (tensor<i32>) -> tensor<%dxi32>\n",
            splat, scalar, bd->lanes);
    return splat;
}

static const char *mb_op2(modbuilder *bd, const char *op, const char *x,
                          const char *y) {
    const char *r = mb_name(bd, "v");

    bprintf(&bd->b, "    %s = stablehlo.%s %s, %s : tensor<%dxi32>\n",
            r, op, x, y, bd->lanes);
    return r;
}

static const char *mb_xor3(modbuilder *bd, const char *x, const char *y,
                           const char *z) {
    const char *t = mb_op2(bd, "xor", x, y);
    return mb_op2(bd, "xor", t, z);
}

static const char *mb_add3(modbuilder *bd, const char *x, const char *y,
                           const char *z) {
    const char *t = mb_op2(bd, "add", x, y);
    return mb_op2(bd, "add", t, z);
}

static const char *mb_add4(modbuilder *bd, const char *x, const char *y,
                           const char *z, const char *w) {
    const char *t = mb_add3(bd, x, y, z);
    return mb_op2(bd, "add", t, w);
}

static const char *mb_rotr(modbuilder *bd, const char *x, unsigned n) {
    const char *sr = mb_op2(bd, "shift_right_logical", x, mb_const(bd, n));
    const char *sl = mb_op2(bd, "shift_left", x, mb_const(bd, 32 - n));
    return mb_op2(bd, "or", sr, sl);
}

/* ------------------------------------------------------------------ */
/* meatrider: SHA-256d over a Bitcoin header                           */
/*                                                                     */
/* One hash is two compressions, the first from the challenge's        */
/* midstate and the second over the first digest -- so the builder      */
/* runs the same emission twice and the device decides "does this lane  */
/* meet the target?" exactly as the sha256 tier's module does.          */
/* ------------------------------------------------------------------ */

static uint32_t mr_bswap32(uint32_t v) {
    return (v >> 24) | ((v >> 8) & 0x0000ff00u) | ((v << 8) & 0x00ff0000u) |
           (v << 24);
}

/* A 32-bit byte swap as HLO. Bitcoin shows the digest reversed, so the words
 * the target test reads are byte-swapped and word-reversed. */
static const char *mr_bswap(modbuilder *bd, const char *x) {
    const char *a = mb_op2(bd, "shift_left", x, mb_const(bd, 24));
    const char *bl = mb_op2(bd, "shift_left", x, mb_const(bd, 8));
    const char *b = mb_op2(bd, "and", bl, mb_const(bd, 0x00ff0000u));
    const char *cl = mb_op2(bd, "shift_right_logical", x, mb_const(bd, 8));
    const char *c = mb_op2(bd, "and", cl, mb_const(bd, 0x0000ff00u));
    const char *d = mb_op2(bd, "shift_right_logical", x, mb_const(bd, 24));

    return mb_op2(bd, "or", mb_op2(bd, "or", a, b), mb_op2(bd, "or", c, d));
}

/* One compression: out = st + working, over the schedule expanded from `w`.
 * The sha256 builder inlines this; meatrider needs it twice, so it is a
 * function here and the sha256 path is left alone. */
static void mr_compress(modbuilder *bd, const char *st[8], const char *w[16],
                        const char *out[8]) {
    const char *s[64];
    const char *v[8];
    int i;

    for (i = 0; i < 16; i++) {
        s[i] = w[i];
    }
    for (i = 16; i < 64; i++) {
        const char *a1 = mb_rotr(bd, s[i - 15], 7);
        const char *a2 = mb_rotr(bd, s[i - 15], 18);
        const char *a3 = mb_op2(bd, "shift_right_logical", s[i - 15],
                                mb_const(bd, 3));
        const char *s0 = mb_xor3(bd, a1, a2, a3);
        const char *b1 = mb_rotr(bd, s[i - 2], 17);
        const char *b2 = mb_rotr(bd, s[i - 2], 19);
        const char *b3 = mb_op2(bd, "shift_right_logical", s[i - 2],
                                mb_const(bd, 10));
        const char *s1 = mb_xor3(bd, b1, b2, b3);
        const char *t = mb_add3(bd, s[i - 16], s0, s[i - 7]);
        s[i] = mb_op2(bd, "add", t, s1);
    }

    for (i = 0; i < 8; i++) {
        v[i] = st[i];
    }
    for (i = 0; i < 64; i++) {
        const char *S1 = mb_xor3(bd, mb_rotr(bd, v[4], 6), mb_rotr(bd, v[4], 11),
                                 mb_rotr(bd, v[4], 25));
        const char *en = mb_op2(bd, "xor", v[4], mb_const(bd, 0xffffffffu));
        const char *ch = mb_op2(bd, "xor", mb_op2(bd, "and", v[4], v[5]),
                                mb_op2(bd, "and", en, v[6]));
        const char *kw = mb_op2(bd, "add", mb_const(bd, pjrt_k256[i]), s[i]);
        const char *t1 = mb_add4(bd, v[7], S1, ch, kw);
        const char *S0 = mb_xor3(bd, mb_rotr(bd, v[0], 2), mb_rotr(bd, v[0], 13),
                                 mb_rotr(bd, v[0], 22));
        const char *maj = mb_xor3(bd, mb_op2(bd, "and", v[0], v[1]),
                                  mb_op2(bd, "and", v[0], v[2]),
                                  mb_op2(bd, "and", v[1], v[2]));
        const char *t2 = mb_op2(bd, "add", S0, maj);
        const char *e_new = mb_op2(bd, "add", v[3], t1);
        const char *a_new = mb_op2(bd, "add", t1, t2);

        v[7] = v[6];
        v[6] = v[5];
        v[5] = v[4];
        v[4] = e_new;
        v[3] = v[2];
        v[2] = v[1];
        v[1] = v[0];
        v[0] = a_new;
    }
    for (i = 0; i < 8; i++) {
        out[i] = mb_op2(bd, "add", v[i], st[i]);
    }
}

/* is `word` worth zero (or with its top `rem` bits zero)? */
static const char *mr_eq_zero(modbuilder *bd, const char *x, int rem) {
    const char *cmp = mb_name(bd, "eq");
    const char *z = mb_name(bd, "z");
    const char *zb = mb_name(bd, "zb");
    const char *val = x;

    if (rem > 0 && rem < 32) {
        val = mb_op2(bd, "shift_right_logical", x, mb_const(bd, (unsigned)(32 - rem)));
    }
    bprintf(&bd->b, "    %s = stablehlo.constant dense<0> : tensor<i32>\n", z);
    bprintf(&bd->b, "    %s = stablehlo.broadcast_in_dim %s, dims = [] "
                    ": (tensor<i32>) -> tensor<%dxi32>\n", zb, z, bd->lanes);
    bprintf(&bd->b, "    %s = \"stablehlo.compare\"(%s, %s) "
                    "{comparison_direction = #stablehlo<comparison_direction EQ>, "
                    "compare_type = #stablehlo<comparison_type SIGNED>} "
                    ": (tensor<%dxi32>, tensor<%dxi32>) -> tensor<%dxi1>\n",
            cmp, val, zb, bd->lanes, bd->lanes, bd->lanes);
    return cmp;
}

static const char *mr_and_bool(modbuilder *bd, const char *a, const char *b) {
    const char *r = mb_name(bd, "and");

    bprintf(&bd->b, "    %s = stablehlo.and %s, %s : tensor<%dxi1>\n",
            r, a, b, bd->lanes);
    return r;
}

static char *build_module_meatrider(int lanes, const uint32_t mid[8],
                                    const uint32_t tail[3], int difficulty) {
    static const uint32_t iv[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u,
                                   0xa54ff53au, 0x510e527fu, 0x9b05688cu,
                                   0x1f83d9abu, 0x5be0cd19u};
    modbuilder bd;
    const char *w[16];
    const char *st[8];
    const char *h1[8];
    const char *h2[8];
    const char *dg[8];
    const char *acc;
    char *module;
    int i, full, rem;

    memset(&bd, 0, sizeof bd);
    bd.lanes = lanes;

    bprintf(&bd.b,
            "module {\n"
            "  func.func @main(%%n: tensor<i32>) -> tensor<%dxi8> {\n"
            "    %%lane = stablehlo.iota dim = 0 : tensor<%dxi32>\n", lanes,
            lanes);
    {
        const char *base = mb_name(&bd, "nb");
        const char *nb;

        bprintf(&bd.b, "    %s = stablehlo.broadcast_in_dim %%n, dims = [] "
                       ": (tensor<i32>) -> tensor<%dxi32>\n", base, lanes);
        nb = mb_op2(&bd, "add", "%lane", base);

        /* block 1: nBits and the timestamp as big-endian words, the nonce
         * little-endian at byte 12 (word 3, byte-swapped), 0x80, the length. */
        w[0] = mb_const(&bd, mr_bswap32(tail[0]));
        w[1] = mb_const(&bd, mr_bswap32(tail[1]));
        w[2] = mb_const(&bd, mr_bswap32(tail[2]));
        w[3] = mr_bswap(&bd, nb);
    }
    w[4] = mb_const(&bd, 0x80000000u);
    for (i = 5; i < 15; i++) {
        w[i] = mb_const(&bd, 0u);
    }
    w[15] = mb_const(&bd, 0x00000280u);   /* 80 bytes, 640 bits */
    for (i = 0; i < 8; i++) {
        st[i] = mb_const(&bd, mid[i]);
    }
    mr_compress(&bd, st, w, h1);

    /* block 2: the first digest's words are its message words, because a
     * SHA-256 message word is the big-endian reading of its four bytes. */
    for (i = 0; i < 8; i++) {
        w[i] = h1[i];
    }
    w[8] = mb_const(&bd, 0x80000000u);
    for (i = 9; i < 15; i++) {
        w[i] = mb_const(&bd, 0u);
    }
    w[15] = mb_const(&bd, 0x00000100u);   /* 32 bytes, 256 bits */
    for (i = 0; i < 8; i++) {
        st[i] = mb_const(&bd, iv[i]);
    }
    mr_compress(&bd, st, w, h2);

    /* display order: reverse the words and byte-swap each one */
    for (i = 0; i < 8; i++) {
        dg[i] = mr_bswap(&bd, h2[7 - i]);
    }

    /* Leading zero bits, as equalities against zero. `difficulty` is baked in,
     * so the number of words to test is known at build time; the host checks
     * the full difficulty again before believing a lane. */
    full = difficulty / 32;
    rem = difficulty % 32;
    acc = NULL;
    for (i = 0; i < full && i < 8; i++) {
        const char *t = mr_eq_zero(&bd, dg[i], 0);
        acc = (acc == NULL) ? t : mr_and_bool(&bd, acc, t);
    }
    if (rem != 0 && full < 8) {
        const char *t = mr_eq_zero(&bd, dg[full], rem);
        acc = (acc == NULL) ? t : mr_and_bool(&bd, acc, t);
    }
    if (acc == NULL) {
        /* difficulty 0: every lane passes, spelled as an equality with itself */
        acc = mr_eq_zero(&bd, dg[0], 0);
    }
    {
        const char *fl = mb_name(&bd, "flag");

        bprintf(&bd.b, "    %s = \"stablehlo.convert\"(%s) "
                       ": (tensor<%dxi1>) -> tensor<%dxi8>\n",
                fl, acc, lanes, lanes);
        bprintf(&bd.b, "    return %s : tensor<%dxi8>\n", fl, lanes);
    }
    bprintf(&bd.b, "  }\n}\n");

    if (bd.b.oom || bd.arena.oom || bd.b.s == NULL) {
        free(bd.b.s);
        arena_release(&bd.arena);
        return NULL;
    }
    module = bd.b.s;
    arena_release(&bd.arena);
    return module;
}

/* The module text, for tests and for anyone who wants to read the program the
 * device is asked to run without owning a TPU. Returns its length, -1 when the
 * builder fails, -2 when `out` is too small. */
int anubis_tpu_meatrider_hlo(int lanes, const uint32_t mid[8],
                             const uint32_t tail[3], int difficulty, char *out,
                             size_t cap) {
    char *module;
    size_t len;

    if (mid == NULL || tail == NULL || out == NULL) {
        return -1;
    }
    if (lanes < 1) {
        lanes = 8;
    }
    module = build_module_meatrider(lanes, mid, tail, difficulty);
    if (module == NULL) {
        return -1;
    }
    len = strlen(module);
    if (cap <= len) {
        free(module);
        return -2;
    }
    memcpy(out, module, len + 1);
    free(module);
    return (int)len;
}

/*
 * Build the module. `words` are the 16 big-endian message words with the nonce
 * field zeroed; `nonce_off` is where the four nonce bytes go and `use_le`
 * selects their order. `difficulty` is the number of leading bits the device
 * tests (at most 32; the host checks the full difficulty afterwards).
 *
 * Returns malloc'd text, or NULL on allocation failure. The arena that held
 * the SSA names is released before returning.
 */
static char *build_module(int lanes, const uint32_t words[16], int nonce_off,
                          int use_le, int difficulty) {
    static const uint32_t iv[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u,
                                   0xa54ff53au, 0x510e527fu, 0x9b05688cu,
                                   0x1f83d9abu, 0x5be0cd19u};
    modbuilder bd;
    const char *nb;
    const char *vars[8];
    const char *w[64];
    char *module;
    int i, j;

    memset(&bd, 0, sizeof bd);
    bd.lanes = lanes;

    bprintf(&bd.b,
            "module {\n"
            "  func.func @main(%%n: tensor<i32>) -> tensor<%dxi8> {\n"
            "    %%lane = stablehlo.iota dim = 0 : tensor<%dxi32>\n",
            lanes, lanes);
    {
        const char *base = mb_name(&bd, "nb");
        bprintf(&bd.b, "    %s = stablehlo.broadcast_in_dim %%n, dims = [] "
                       ": (tensor<i32>) -> tensor<%dxi32>\n", base, lanes);
        nb = mb_op2(&bd, "add", "%lane", base);
    }

    /* 16 message words: constants with the four nonce bytes spliced in. */
    for (j = 0; j < 16; j++) {
        const char *cj = mb_name(&bd, "c");
        bprintf(&bd.b, "    %s = stablehlo.constant dense<%d> : tensor<i32>\n",
                cj, (int32_t)words[j]);
        w[j] = mb_name(&bd, "w");
        bprintf(&bd.b, "    %s = stablehlo.broadcast_in_dim %s, dims = [] "
                       ": (tensor<i32>) -> tensor<%dxi32>\n",
                w[j], cj, lanes);
    }
    for (i = 0; i < 4; i++) {
        int byte = nonce_off + i;
        int word = byte / 4;
        /* The block words are big-endian: byte 0 of a word is its MSB. */
        unsigned shift = (unsigned)(8 * (3 - (byte % 4)));
        unsigned nshift = use_le ? (unsigned)(8 * i) : (unsigned)(8 * (3 - i));
        const char *shr = mb_op2(&bd, "shift_right_logical", nb,
                                 mb_const(&bd, nshift));
        const char *m = mb_op2(&bd, "and", shr, mb_const(&bd, 0xffu));
        const char *shl = mb_op2(&bd, "shift_left", m, mb_const(&bd, shift));
        w[word] = mb_op2(&bd, "add", w[word], shl);
    }

    /* message schedule */
    for (i = 16; i < 64; i++) {
        const char *a1 = mb_rotr(&bd, w[i - 15], 7);
        const char *a2 = mb_rotr(&bd, w[i - 15], 18);
        const char *a3 = mb_op2(&bd, "shift_right_logical", w[i - 15],
                                mb_const(&bd, 3));
        const char *s0 = mb_xor3(&bd, a1, a2, a3);
        const char *b1 = mb_rotr(&bd, w[i - 2], 17);
        const char *b2 = mb_rotr(&bd, w[i - 2], 19);
        const char *b3 = mb_op2(&bd, "shift_right_logical", w[i - 2],
                                mb_const(&bd, 10));
        const char *s1 = mb_xor3(&bd, b1, b2, b3);
        const char *t = mb_add3(&bd, w[i - 16], s0, w[i - 7]);
        w[i] = mb_op2(&bd, "add", t, s1);
    }

    /* state: IV, then 64 rounds */
    for (i = 0; i < 8; i++) {
        vars[i] = mb_const(&bd, iv[i]);
    }
    for (i = 0; i < 64; i++) {
        const char *S1 = mb_xor3(&bd, mb_rotr(&bd, vars[4], 6),
                                 mb_rotr(&bd, vars[4], 11),
                                 mb_rotr(&bd, vars[4], 25));
        const char *en = mb_op2(&bd, "xor", vars[4], mb_const(&bd, 0xffffffffu));
        const char *ch = mb_op2(&bd, "xor",
                                mb_op2(&bd, "and", vars[4], vars[5]),
                                mb_op2(&bd, "and", en, vars[6]));
        const char *kw = mb_op2(&bd, "add", mb_const(&bd, pjrt_k256[i]), w[i]);
        const char *t1 = mb_add4(&bd, vars[7], S1, ch, kw);
        const char *S0 = mb_xor3(&bd, mb_rotr(&bd, vars[0], 2),
                                 mb_rotr(&bd, vars[0], 13),
                                 mb_rotr(&bd, vars[0], 22));
        const char *maj = mb_xor3(&bd, mb_op2(&bd, "and", vars[0], vars[1]),
                                  mb_op2(&bd, "and", vars[0], vars[2]),
                                  mb_op2(&bd, "and", vars[1], vars[2]));
        const char *t2 = mb_op2(&bd, "add", S0, maj);
        const char *e_new = mb_op2(&bd, "add", vars[3], t1);
        const char *a_new = mb_op2(&bd, "add", t1, t2);

        vars[7] = vars[6];
        vars[6] = vars[5];
        vars[5] = vars[4];
        vars[4] = e_new;
        vars[3] = vars[2];
        vars[2] = vars[1];
        vars[1] = vars[0];
        vars[0] = a_new;
    }

    /* The device decides "does this lane meet the target?" and the host gets
     * one byte per lane instead of 32. The digest is re-derived on the CPU for
     * the lanes that matter, so the copy back is B bytes, not B*32 - at these
     * window sizes the copy back was the whole cost. */
    {
        const char *h0 = mb_name(&bd, "h0");
        const char *shr = mb_name(&bd, "shr");
        const char *zero = mb_name(&bd, "z");
        const char *cmp = mb_name(&bd, "ok");
        const char *fl = mb_name(&bd, "flag");
        unsigned shift = (unsigned)(32 - difficulty);

        bprintf(&bd.b, "    %s = stablehlo.add %s, %s : tensor<%dxi32>\n",
                h0, vars[0], mb_const(&bd, iv[0]), lanes);
        /* "the top `difficulty` bits are zero" as an equality against zero:
         * shifting by 32-difficulty leaves the compared bits in place, and
         * equality carries no signed/unsigned ambiguity - an unsigned LT
         * against 2^(32-d) looked right but behaved signed on this plugin. */
        bprintf(&bd.b, "    %s = stablehlo.shift_right_logical %s, %s "
                       ": tensor<%dxi32>\n",
                shr, h0, mb_const(&bd, shift), lanes);
        bprintf(&bd.b, "    %s = stablehlo.constant dense<0> : tensor<i32>\n",
                zero);
        {
            const char *zb = mb_name(&bd, "zb");
            bprintf(&bd.b, "    %s = stablehlo.broadcast_in_dim %s, dims = [] "
                           ": (tensor<i32>) -> tensor<%dxi32>\n",
                    zb, zero, lanes);
            bprintf(&bd.b, "    %s = \"stablehlo.compare\"(%s, %s) "
                           "{comparison_direction = #stablehlo<comparison_direction EQ>, "
                           "compare_type = #stablehlo<comparison_type SIGNED>} "
                           ": (tensor<%dxi32>, tensor<%dxi32>) -> tensor<%dxi1>\n",
                    cmp, shr, zb, lanes, lanes, lanes);
            bprintf(&bd.b, "    %s = \"stablehlo.convert\"(%s) "
                           ": (tensor<%dxi1>) -> tensor<%dxi8>\n",
                    fl, cmp, lanes, lanes);
            bprintf(&bd.b, "    return %s : tensor<%dxi8>\n", fl, lanes);
        }
    }
    bprintf(&bd.b, "  }\n}\n");

    if (bd.b.oom || bd.arena.oom || bd.b.s == NULL) {
        free(bd.b.s);
        arena_release(&bd.arena);
        return NULL;
    }
    module = bd.b.s;
    arena_release(&bd.arena);
    return module;
}

/* ==================================================================== */
/* PJRT plumbing: the same lifecycle as sha256_pjrt.c, but every failure */
/* is a return value instead of a message and exit(1)                    */
/* ==================================================================== */

typedef PJRT_Api *(*get_pjrt_api_fn)(void);

typedef struct {
    PJRT_Api *api;
    PJRT_Client *client;
    PJRT_Device *device;
    size_t num_devices;
    int status; /* 1 = ready, 0 = unavailable; written once by pthread_once */
} tpu_state;

typedef struct {
    PJRT_LoadedExecutable *ex;
    uint8_t *flags; /* lanes flag bytes, the read-back destination */
    uint32_t words[16];
    uint32_t raw_len;
    int use_le;
    int dev_bits;
    int lanes;
    int valid;
} ex_cache;

static tpu_state g_tpu;
static ex_cache g_cache;
static pthread_once_t g_probe_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_info[128];
static int g_lanes;

/* A PJRT_Error* carries an owned message; destroy it and drop it. This backend
 * has no place to report it, and reporting is not allowed. */
static void clear_error(PJRT_Api *api, PJRT_Error *e) {
    PJRT_Error_Destroy_Args da = {0};

    if (e == NULL) {
        return;
    }
    da.struct_size = sizeof da;
    da.error = e;
    (void)api->PJRT_Error_Destroy(&da);
}

static void destroy_client(PJRT_Api *api, PJRT_Client *c) {
    PJRT_Client_Destroy_Args cd = {0};
    PJRT_Error *e;

    if (c == NULL) {
        return;
    }
    cd.struct_size = sizeof cd;
    cd.client = c;
    e = api->PJRT_Client_Destroy(&cd);
    if (e != NULL) {
        clear_error(api, e);
    }
}

static void destroy_executable(PJRT_Api *api, PJRT_LoadedExecutable *ex) {
    PJRT_LoadedExecutable_Destroy_Args ed = {0};
    PJRT_Error *e;

    if (ex == NULL) {
        return;
    }
    ed.struct_size = sizeof ed;
    ed.executable = ex;
    e = api->PJRT_LoadedExecutable_Destroy(&ed);
    if (e != NULL) {
        clear_error(api, e);
    }
}

static void destroy_buffer(PJRT_Api *api, PJRT_Buffer *b) {
    PJRT_Buffer_Destroy_Args da = {0};
    PJRT_Error *e;

    if (b == NULL) {
        return;
    }
    da.struct_size = sizeof da;
    da.buffer = b;
    e = api->PJRT_Buffer_Destroy(&da);
    if (e != NULL) {
        clear_error(api, e);
    }
}

static void destroy_event(PJRT_Api *api, PJRT_Event *ev) {
    PJRT_Event_Destroy_Args ed = {0};
    PJRT_Error *e;

    if (ev == NULL) {
        return;
    }
    ed.struct_size = sizeof ed;
    ed.event = ev;
    e = api->PJRT_Event_Destroy(&ed);
    if (e != NULL) {
        clear_error(api, e);
    }
}

/* ANUBIS_TPU_WINDOW, clamped to a sane range. Read once, while probing, so a
 * later setenv() cannot change the shape of a cached executable. */
static int env_window(void) {
    const char *s = getenv("ANUBIS_TPU_WINDOW");
    long v = TPU_DEFAULT_WINDOW;
    char *end = NULL;

    if (s != NULL && *s != '\0') {
        long n = strtol(s, &end, 10);
        if (end != s) {
            if (n < TPU_MIN_WINDOW) {
                n = TPU_MIN_WINDOW;
            }
            if (n > TPU_MAX_WINDOW) {
                n = TPU_MAX_WINDOW;
            }
            v = n;
        }
    }
    return (int)v;
}

/* One open attempt. Returns:
 *   1 = ready, 0 = not loadable (try the next spelling), 2 = loaded and
 *   initialized but unusable (stop: do not initialize a second plugin copy).
 *
 * The handle is deliberately not dlclose()d after PJRT_Plugin_Initialize():
 * libtpu may own threads and global state by then, and unloading it under a
 * process that keeps running is more dangerous than keeping the mapping. The
 * "do not leak" case that matters is the ordinary one - nothing to unload when
 * dlopen() itself fails. */
static int try_open(const char *path) {
    void *h;
    get_pjrt_api_fn get;
    PJRT_Api *api;
    PJRT_Plugin_Initialize_Args ia = {0};
    PJRT_Client_Create_Args ca = {0};
    PJRT_Client_AddressableDevices_Args da = {0};
    PJRT_Error *e;

    h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) {
        return 0;
    }
    get = (get_pjrt_api_fn)dlsym(h, "GetPjrtApi");
    if (get == NULL) {
        (void)dlclose(h);
        return 0;
    }
    api = get();
    if (api == NULL || api->pjrt_api_version.major_version != PJRT_API_MAJOR) {
        (void)dlclose(h);
        return 0;
    }

    ia.struct_size = sizeof ia;
    e = api->PJRT_Plugin_Initialize(&ia);
    if (e != NULL) {
        clear_error(api, e);
        return 2;
    }

    ca.struct_size = sizeof ca;
    e = api->PJRT_Client_Create(&ca);
    if (e != NULL || ca.client == NULL) {
        clear_error(api, e);
        return 2;
    }

    da.struct_size = sizeof da;
    da.client = ca.client;
    e = api->PJRT_Client_AddressableDevices(&da);
    if (e != NULL || da.num_addressable_devices < 1) {
        clear_error(api, e);
        destroy_client(api, ca.client);
        return 2;
    }

    g_tpu.api = api;
    g_tpu.client = ca.client;
    g_tpu.device = da.addressable_devices[0];
    g_tpu.num_devices = da.num_addressable_devices;
    g_tpu.status = 1;
    snprintf(g_info, sizeof g_info, "TPU: PJRT %d.%d, %zu devices",
             api->pjrt_api_version.major_version,
             api->pjrt_api_version.minor_version,
             da.num_addressable_devices);
    return 1;
}

static void probe_once(void) {
    const char *env = getenv("ANUBIS_TPU_LIB");
    const char *paths[2];
    int npaths = 0;
    int i;

    g_lanes = env_window();

    if (env != NULL && *env != '\0') {
        paths[npaths++] = env;
    } else {
        paths[npaths++] = "libtpu.so";
        paths[npaths++] = "libtpu.so.0";
    }
    for (i = 0; i < npaths; i++) {
        int r = try_open(paths[i]);
        if (r == 1) {
            return;
        }
        if (r == 2) {
            /* A plugin that loaded and initialized but has no usable device is
             * a terminal answer; trying "libtpu.so.0" could initialize a second
             * copy of the same plugin in this process. */
            break;
        }
    }
    g_tpu.status = 0;
    g_info[0] = '\0';
}

int anubis_tpu_available(void) {
    pthread_once(&g_probe_once, probe_once);
    return g_tpu.status;
}

const char *anubis_tpu_info(void) {
    pthread_once(&g_probe_once, probe_once);
    return g_tpu.status ? g_info : NULL;
}

/* CompileOptionsProto{ executable_build_options{ num_replicas=1,
 * num_partitions=1 } } - field 3 (message), inside it fields 4 and 5 as
 * varint 1. Without it libtpu asks for a device assignment of zero replicas
 * and refuses: "Requested total cores: 0". */
static const unsigned char compile_options[] = {0x1a, 0x04, 0x20, 0x01, 0x28, 0x01};

static PJRT_LoadedExecutable *compile_module(PJRT_Api *api, PJRT_Client *client,
                                             const char *code) {
    PJRT_Program prog = {0};
    PJRT_Client_Compile_Args cc = {0};
    PJRT_Error *e;

    prog.struct_size = sizeof prog;
    prog.code = (char *)code;
    prog.code_size = strlen(code);
    prog.format = "mlir";
    prog.format_size = 4;

    cc.struct_size = sizeof cc;
    cc.client = client;
    cc.program = &prog;
    cc.compile_options = (const char *)compile_options;
    cc.compile_options_size = sizeof compile_options;
    e = api->PJRT_Client_Compile(&cc);
    if (e != NULL) {
        clear_error(api, e);
        return NULL;
    }
    /* A successful call should always hand back an executable; treating a
     * NULL one as failure keeps execute() from dereferencing nothing. */
    return cc.executable;
}

/* Implementation-defined unsigned->signed conversion kept explicit so the
 * base nonce above INT32_MAX round-trips as the same 32 bits. */
static int32_t bits_i32(uint32_t v) {
    int32_t r;
    memcpy(&r, &v, sizeof r);
    return r;
}

static int upload_i32(PJRT_Api *api, PJRT_Client *client, PJRT_Device *device,
                      int32_t value, PJRT_Buffer **out) {
    PJRT_Client_BufferFromHostBuffer_Args ba = {0};
    PJRT_Error *e;

    *out = NULL;
    ba.struct_size = sizeof ba;
    ba.client = client;
    ba.data = &value;
    ba.type = PJRT_Buffer_Type_S32;
    ba.dims = NULL;
    ba.num_dims = 0;
    ba.byte_strides = NULL;
    ba.num_byte_strides = 0;
    ba.host_buffer_semantics =
        PJRT_HostBufferSemantics_kImmutableUntilTransferCompletes;
    ba.device = device;
    e = api->PJRT_Client_BufferFromHostBuffer(&ba);
    if (e != NULL) {
        clear_error(api, e);
        return -1;
    }
    if (ba.done_with_host_buffer != NULL) {
        PJRT_Event_Await_Args wa = {0};
        PJRT_Error *we;
        wa.struct_size = sizeof wa;
        wa.event = ba.done_with_host_buffer;
        we = api->PJRT_Event_Await(&wa);
        destroy_event(api, ba.done_with_host_buffer);
        if (we != NULL) {
            clear_error(api, we);
            destroy_buffer(api, ba.buffer);
            return -1;
        }
    }
    if (ba.buffer == NULL) {
        return -1;
    }
    *out = ba.buffer;
    return 0;
}

static int execute(PJRT_Api *api, PJRT_LoadedExecutable *ex, PJRT_Buffer *arg,
                   PJRT_Buffer **out) {
    PJRT_Buffer *args0[1] = {arg};
    PJRT_Buffer *const *arg_lists[1] = {args0};
    PJRT_Buffer *out0[1] = {NULL};
    PJRT_Buffer **out_lists[1] = {out0};
    PJRT_Event *events[1] = {NULL};
    PJRT_ExecuteOptions opts = {0};
    PJRT_LoadedExecutable_Execute_Args ea = {0};
    PJRT_Error *e;

    *out = NULL;
    opts.struct_size = sizeof opts;
    ea.struct_size = sizeof ea;
    ea.executable = ex;
    ea.options = &opts;
    ea.argument_lists = arg_lists;
    ea.num_devices = 1;
    ea.num_args = 1;
    ea.output_lists = out_lists;
    ea.device_complete_events = events;
    e = api->PJRT_LoadedExecutable_Execute(&ea);
    if (e != NULL) {
        clear_error(api, e);
        return -1;
    }
    if (events[0] != NULL) {
        PJRT_Event_Await_Args wa = {0};
        PJRT_Error *we;
        wa.struct_size = sizeof wa;
        wa.event = events[0];
        we = api->PJRT_Event_Await(&wa);
        destroy_event(api, events[0]);
        if (we != NULL) {
            clear_error(api, we);
            destroy_buffer(api, out0[0]);
            return -1;
        }
    }
    if (out0[0] == NULL) {
        return -1;
    }
    *out = out0[0];
    return 0;
}

static int read_back(PJRT_Api *api, PJRT_Buffer *buf, void *dst, size_t bytes) {
    PJRT_Buffer_ToHostBuffer_Args ta = {0};
    PJRT_Error *e;

    ta.struct_size = sizeof ta;
    ta.src = buf;
    ta.dst = dst;
    ta.dst_size = bytes;
    e = api->PJRT_Buffer_ToHostBuffer(&ta);
    if (e != NULL) {
        clear_error(api, e);
        return -1;
    }
    if (ta.event != NULL) {
        PJRT_Event_Await_Args wa = {0};
        PJRT_Error *we;
        wa.struct_size = sizeof wa;
        wa.event = ta.event;
        we = api->PJRT_Event_Await(&wa);
        destroy_event(api, ta.event);
        if (we != NULL) {
            clear_error(api, we);
            return -1;
        }
    }
    return 0;
}

/* ==================================================================== */
/* host side: block, scan, verify                                       */
/* ==================================================================== */

static void build_block(const uint8_t *raw, uint32_t raw_len, uint32_t words[16]) {
    uint8_t block[64] = {0};
    uint64_t bits = (uint64_t)(raw_len + 4u) * 8u;
    int i, j;

    memcpy(block, raw, raw_len);
    block[raw_len + 4u] = 0x80;
    for (i = 0; i < 8; i++) {
        block[56 + i] = (uint8_t)(bits >> (8 * (7 - i)));
    }
    for (j = 0; j < 16; j++) {
        words[j] = ((uint32_t)block[4 * j] << 24) |
                   ((uint32_t)block[4 * j + 1] << 16) |
                   ((uint32_t)block[4 * j + 2] << 8) |
                   (uint32_t)block[4 * j + 3];
    }
}

static int digest_bits(const uint8_t *d, int difficulty) {
    int n = 0;
    int i;

    for (i = 0; i < 32 && n < difficulty; i++) {
        if (d[i] == 0) {
            n += 8;
            continue;
        }
        n += __builtin_clz((unsigned)d[i]) - 24;
        break;
    }
    return n;
}

/* The reference: SHA-256(raw || nonce) in the engine's byte order. */
static void reference_digest(const uint8_t *raw, uint32_t raw_len,
                             uint32_t nonce, int use_le, uint8_t out[32]) {
    uint8_t msg[64];

    memcpy(msg, raw, raw_len);
    if (use_le) {
        msg[raw_len + 0] = (uint8_t)nonce;
        msg[raw_len + 1] = (uint8_t)(nonce >> 8);
        msg[raw_len + 2] = (uint8_t)(nonce >> 16);
        msg[raw_len + 3] = (uint8_t)(nonce >> 24);
    } else {
        msg[raw_len + 0] = (uint8_t)(nonce >> 24);
        msg[raw_len + 1] = (uint8_t)(nonce >> 16);
        msg[raw_len + 2] = (uint8_t)(nonce >> 8);
        msg[raw_len + 3] = (uint8_t)nonce;
    }
    pjrt_sha256_buf(msg, (size_t)raw_len + 4u, out);
}

/* Find (or build) the executable for this challenge key. Called with g_lock
 * held. The old executable stays cached if the new compile fails. */
static int cache_ready(const uint32_t words[16], uint32_t raw_len, int use_le,
                       int dev_bits) {
    int need = !g_cache.valid ||
               g_cache.raw_len != raw_len ||
               g_cache.use_le != use_le ||
               g_cache.dev_bits != dev_bits ||
               g_cache.lanes != g_lanes ||
               memcmp(g_cache.words, words, sizeof g_cache.words) != 0;
    PJRT_LoadedExecutable *ex;
    uint8_t *flags;
    char *module;

    if (!need) {
        return 0;
    }
    module = build_module(g_lanes, words, (int)raw_len, use_le, dev_bits);
    if (module == NULL) {
        return -1;
    }
    ex = compile_module(g_tpu.api, g_tpu.client, module);
    free(module);
    if (ex == NULL) {
        return -1;
    }
    flags = malloc((size_t)g_lanes);
    if (flags == NULL) {
        destroy_executable(g_tpu.api, ex);
        return -1;
    }
    if (g_cache.valid) {
        destroy_executable(g_tpu.api, g_cache.ex);
        free(g_cache.flags);
    }
    g_cache.ex = ex;
    g_cache.flags = flags;
    memcpy(g_cache.words, words, sizeof g_cache.words);
    g_cache.raw_len = raw_len;
    g_cache.use_le = use_le;
    g_cache.dev_bits = dev_bits;
    g_cache.lanes = g_lanes;
    g_cache.valid = 1;
    return 0;
}

int anubis_tpu_solve(const uint8_t *challenge, uint32_t challenge_len,
                     int difficulty, int use_le, uint64_t max_nonce,
                     double budget_ms, uint32_t *out_nonce, char *out_hex,
                     double *out_ms) {
    uint32_t words[16];
    uint64_t maxn;
    uint64_t base;
    double t0;
    int dev_bits;
    int le;
    int result;

    /* Argument checks happen before the probe: a malformed request must not
     * touch the TPU at all. */
    if (challenge == NULL || out_nonce == NULL) {
        return -1;
    }
    if (challenge_len == 0 || (uint64_t)challenge_len + 4u > 55u) {
        return -1;
    }
    if (difficulty < 1 || difficulty > 256) {
        return -1;
    }

    pthread_once(&g_probe_once, probe_once);
    if (g_tpu.status == 0) {
        return -1;
    }

    le = use_le != 0;
    /* The device test is an equality on the top 32 bits at most; the host
     * verifies the full difficulty, so a larger difficulty still works. */
    dev_bits = difficulty > 32 ? 32 : difficulty;
    build_block(challenge, challenge_len, words);

    pthread_mutex_lock(&g_lock);
    /* t0 is taken before the lock so the wait for another caller is part of
     * the reported time too. */
    t0 = pjrt_now_s();
    if (cache_ready(words, challenge_len, le, dev_bits) != 0) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    /* max_nonce is an inclusive nonce bound, like the GPU backends; 0 means
     * "no limit" and the full 32-bit nonce space. */
    maxn = (max_nonce == 0 || max_nonce > 0xFFFFFFFFull)
               ? 0xFFFFFFFFull
               : max_nonce;
    base = 0;
    result = 1;
    /* A new challenge is a new compile. That is time the caller is waiting
     * for, so it counts against both budget_ms and out_ms; the old code
     * excluded it and reported a solve time that could be a second short. */
    if (budget_ms > 0.0 && (pjrt_now_s() - t0) * 1000.0 >= budget_ms) {
        pthread_mutex_unlock(&g_lock);
        return 1;
    }

    while (base <= maxn) {
        uint64_t remaining = maxn - base + 1;
        uint32_t count = remaining < (uint64_t)g_lanes
                             ? (uint32_t)remaining
                             : (uint32_t)g_lanes;
        PJRT_Buffer *arg = NULL;
        PJRT_Buffer *res = NULL;
        uint32_t lane;
        int hit = 0;

        if (upload_i32(g_tpu.api, g_tpu.client, g_tpu.device,
                       bits_i32((uint32_t)base), &arg) != 0) {
            result = -1;
            break;
        }
        if (execute(g_tpu.api, g_cache.ex, arg, &res) != 0) {
            destroy_buffer(g_tpu.api, arg);
            result = -1;
            break;
        }
        destroy_buffer(g_tpu.api, arg);
        if (read_back(g_tpu.api, res, g_cache.flags, (size_t)g_lanes) != 0) {
            destroy_buffer(g_tpu.api, res);
            result = -1;
            break;
        }
        destroy_buffer(g_tpu.api, res);

        /* Lanes past `count` are outside the requested nonce range. */
        for (lane = 0; lane < count; lane++) {
            uint32_t nonce;
            uint8_t ref[32];

            if (g_cache.flags[lane] == 0) {
                continue;
            }
            nonce = (uint32_t)(base + lane);
            reference_digest(challenge, challenge_len, nonce, le, ref);
            if (digest_bits(ref, difficulty) < difficulty) {
                continue; /* the device miscomputed this lane - keep looking */
            }
            *out_nonce = nonce;
            if (out_hex != NULL) {
                pjrt_to_hex(ref, 32, out_hex);
            }
            if (out_ms != NULL) {
                *out_ms = (pjrt_now_s() - t0) * 1000.0;
            }
            result = 0;
            hit = 1;
            break;
        }
        if (hit) {
            break;
        }

        base += count;
        if (budget_ms > 0.0 && (pjrt_now_s() - t0) * 1000.0 >= budget_ms) {
            result = 1;
            break;
        }
    }

    pthread_mutex_unlock(&g_lock);
    return result;
}

/* ==================================================================== */
/* meatrider: the same PJRT lifecycle, a different module               */
/* ==================================================================== */

typedef struct {
    PJRT_LoadedExecutable *ex;
    uint8_t *flags;
    uint32_t mid[8];
    uint32_t tail[3];
    int difficulty;
    int lanes;
    int valid;
} mr_ex_cache;

static mr_ex_cache g_mr_cache;

int anubis_tpu_meatrider_available(void) {
    pthread_once(&g_probe_once, probe_once);
    return g_tpu.status == 1;
}

/* A new challenge or difficulty is a new compile: the midstate, nBits and the
 * timestamp are constants in the module, exactly like the sha256 tier's
 * message words. The old executable stays cached if the new compile fails. */
static int mr_cache_ready(const uint32_t mid[8], const uint32_t tail[3],
                          int difficulty) {
    int need = !g_mr_cache.valid || g_mr_cache.difficulty != difficulty ||
               g_mr_cache.lanes != g_lanes ||
               memcmp(g_mr_cache.mid, mid, sizeof g_mr_cache.mid) != 0 ||
               memcmp(g_mr_cache.tail, tail, sizeof g_mr_cache.tail) != 0;
    PJRT_LoadedExecutable *ex;
    uint8_t *flags;
    char *module;

    if (!need) {
        return 0;
    }
    module = build_module_meatrider(g_lanes, mid, tail, difficulty);
    if (module == NULL) {
        return -1;
    }
    ex = compile_module(g_tpu.api, g_tpu.client, module);
    free(module);
    if (ex == NULL) {
        return -1;
    }
    flags = malloc((size_t)g_lanes);
    if (flags == NULL) {
        destroy_executable(g_tpu.api, ex);
        return -1;
    }
    if (g_mr_cache.valid) {
        destroy_executable(g_tpu.api, g_mr_cache.ex);
        free(g_mr_cache.flags);
    }
    g_mr_cache.ex = ex;
    g_mr_cache.flags = flags;
    memcpy(g_mr_cache.mid, mid, sizeof g_mr_cache.mid);
    memcpy(g_mr_cache.tail, tail, sizeof g_mr_cache.tail);
    g_mr_cache.difficulty = difficulty;
    g_mr_cache.lanes = g_lanes;
    g_mr_cache.valid = 1;
    return 0;
}

int anubis_tpu_meatrider_solve(const meatrider_ctx *ctx, uint32_t start,
                               uint32_t count, double budget_ms,
                               uint32_t *out_nonce, uint8_t out_digest[32]) {
    uint32_t tail[3];
    uint64_t base, end;
    double t0;
    int result = 1;
    int i;

    if (ctx == NULL || out_nonce == NULL || out_digest == NULL) {
        return -1;
    }
    if (!anubis_tpu_meatrider_available()) {
        return -1;
    }
    for (i = 0; i < 3; i++) {
        tail[i] = (uint32_t)ctx->tail[4 * i] |
                  ((uint32_t)ctx->tail[4 * i + 1] << 8) |
                  ((uint32_t)ctx->tail[4 * i + 2] << 16) |
                  ((uint32_t)ctx->tail[4 * i + 3] << 24);
    }
    end = 0xFFFFFFFFull;
    if (count > 0) {
        uint64_t last = (uint64_t)start + (uint64_t)count - 1u;
        if (last < end) {
            end = last;
        }
    }

    pthread_mutex_lock(&g_lock);
    t0 = pjrt_now_s();
    if (mr_cache_ready(ctx->mid, tail, ctx->difficulty) != 0) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    if (budget_ms > 0.0 && (pjrt_now_s() - t0) * 1000.0 >= budget_ms) {
        pthread_mutex_unlock(&g_lock);
        return 1;
    }

    base = start;
    while (base <= end) {
        uint64_t remaining = end - base + 1u;
        uint32_t n = remaining < (uint64_t)g_lanes ? (uint32_t)remaining
                                                  : (uint32_t)g_lanes;
        PJRT_Buffer *arg = NULL;
        PJRT_Buffer *res = NULL;
        uint32_t lane;
        int hit = 0;

        if (upload_i32(g_tpu.api, g_tpu.client, g_tpu.device,
                       bits_i32((uint32_t)base), &arg) != 0) {
            result = -1;
            break;
        }
        if (execute(g_tpu.api, g_mr_cache.ex, arg, &res) != 0) {
            destroy_buffer(g_tpu.api, arg);
            result = -1;
            break;
        }
        destroy_buffer(g_tpu.api, arg);
        if (read_back(g_tpu.api, res, g_mr_cache.flags, (size_t)g_lanes) != 0) {
            destroy_buffer(g_tpu.api, res);
            result = -1;
            break;
        }
        destroy_buffer(g_tpu.api, res);

        for (lane = 0; lane < n; lane++) {
            uint32_t nonce;
            uint8_t digest[32];

            if (g_mr_cache.flags[lane] == 0) {
                continue;
            }
            nonce = (uint32_t)(base + lane);
            /* Re-derive in C: a lane flag is a claim, the digest is the proof. */
            meatrider_hash(ctx, nonce, digest);
            if (!meatrider_meets(digest, ctx->difficulty)) {
                continue;
            }
            *out_nonce = nonce;
            memcpy(out_digest, digest, 32);
            pthread_mutex_unlock(&g_lock);
            return 0;
        }
        if (hit) {
            break;
        }
        base += n;
        if (budget_ms > 0.0 && (pjrt_now_s() - t0) * 1000.0 >= budget_ms) {
            result = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return result;
}
