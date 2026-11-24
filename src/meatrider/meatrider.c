/* meatrider.c -- the Bitcoin-shaped tier: SHA-256d over an 80-byte header.
 *
 * Self-contained on purpose: this file is compiled into libanubis_solver.so
 * AND into wasm/meatrider_pow.wasm with no libc, so it uses no headers beyond
 * stdint.h and no functions beyond the ones below. The layout and the price
 * ladder are documented in meatrider.h.
 *
 * The two compressions per hash are not an accident: header bytes 0..63 are
 * fixed for a challenge, so their midstate is compressed once by
 * meatrider_ctx_init(), and only the 16-byte second block moves with the nonce.
 */

#include "meatrider.h"

static const uint32_t MEATRIDER_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint8_t MEATRIDER_LABEL[] = "meatrider";

static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t load_be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
           (uint32_t)p[3];
}

static inline void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void store_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* One SHA-256 compression of a whole 64-byte block into h.
 *
 * The schedule lives in a 16-word rolling window and the loop is fully
 * unrolled, which is what makes the window indices compile to immediates and
 * keeps w in registers. The first version of this file used a 64-word array
 * and a rolled loop; it measured 1.34 us per hash (two compressions), about
 * 4x slower than this shape. */
void meatrider_compress(uint32_t h[8], const uint8_t blk[64]) {
    uint32_t w[16];
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    int i;

    for (i = 0; i < 16; i++)
        w[i] = load_be32(blk + 4 * i);

#if defined(__clang__)
#pragma clang loop unroll(full)
#else
#pragma GCC unroll 64
#endif
    for (i = 0; i < 64; i++) {
        if (i >= 16) {
            uint32_t x = w[(i - 15) & 15];
            uint32_t y = w[(i - 2) & 15];
            uint32_t s0 = rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
            uint32_t s1 = rotr32(y, 17) ^ rotr32(y, 19) ^ (y >> 10);
            w[i & 15] += s0 + w[(i - 7) & 15] + s1;
        }
        {
            uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + MEATRIDER_K[i] + w[i & 15];
            uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void meatrider_iv(uint32_t h[8]) {
    h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
    h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
}

/* SHA-256 of a message shorter than 56 bytes: one block after padding. */
static void meatrider_sha256_short(const uint8_t *msg, uint32_t len, uint8_t out[32]) {
    uint8_t blk[64];
    uint32_t h[8];
    uint32_t i;

    for (i = 0; i < len; i++) blk[i] = msg[i];
    blk[len] = 0x80;
    for (i = len + 1; i < 56; i++) blk[i] = 0;
    for (i = 0; i < 8; i++) blk[63 - i] = (uint8_t)(((uint64_t)len * 8) >> (8 * i));
    meatrider_iv(h);
    meatrider_compress(h, blk);
    for (i = 0; i < 8; i++) store_be32(out + 4 * i, h[i]);
}

uint32_t meatrider_bits(int difficulty) {
    /* Bitcoin's GetCompact() for the exact target 2^(256-difficulty). Powers of
     * two always round-trip exactly: the mantissa is one bit plus zeros. The
     * low-target branch keeps the exponent at the byte count (>= 1) and shifts
     * the value up into the three-byte mantissa, which is what SetCompact()
     * undoes with `mantissa >> 8*(3-exponent)`. */
    uint32_t blen;          /* bit length of the target, 2^(256-d) */
    uint32_t size, compact;

    if (difficulty < 1) difficulty = 1;
    if (difficulty > 255) difficulty = 255;
    blen = (uint32_t)(257 - difficulty);
    size = (blen + 7) / 8;                 /* bytes needed */
    if (size <= 3) {
        compact = (1u << (blen - 1)) << (8 * (3 - size));
    } else {
        compact = 1u << ((blen - 1) - 8 * (size - 3));
    }
    if (compact & 0x00800000u) {           /* the sign bit is not free */
        compact >>= 8;
        size++;
    }
    return compact | (size << 24);
}

int meatrider_ctx_init(meatrider_ctx *ctx, const uint8_t rd[32], int difficulty) {
    uint8_t label[sizeof MEATRIDER_LABEL - 1 + 32];
    uint8_t merkle[32];
    uint32_t i;

    if (ctx == NULL || rd == NULL || difficulty < 1 || difficulty > 255)
        return -1;

    for (i = 0; i < sizeof MEATRIDER_LABEL - 1; i++)
        label[i] = MEATRIDER_LABEL[i];
    for (i = 0; i < 32; i++) label[sizeof MEATRIDER_LABEL - 1 + i] = rd[i];
    meatrider_sha256_short(label, (uint32_t)sizeof label, merkle);

    store_le32(ctx->first, MEATRIDER_VERSION);
    for (i = 0; i < 32; i++) ctx->first[4 + i] = rd[i];
    for (i = 0; i < 28; i++) ctx->first[36 + i] = merkle[i];

    ctx->bits = meatrider_bits(difficulty);
    ctx->difficulty = difficulty;
    for (i = 0; i < 4; i++) ctx->tail[i] = merkle[28 + i];
    store_le32(ctx->tail + 4, MEATRIDER_TIME);
    store_le32(ctx->tail + 8, ctx->bits);

    meatrider_iv(ctx->mid);
    meatrider_compress(ctx->mid, ctx->first);

    /* block 1 never changes except in its four nonce bytes */
    for (i = 0; i < 12; i++) ctx->tail_block[i] = ctx->tail[i];
    for (i = 12; i < 16; i++) ctx->tail_block[i] = 0;
    ctx->tail_block[16] = 0x80;
    for (i = 17; i < 62; i++) ctx->tail_block[i] = 0;
    ctx->tail_block[62] = 0x02;            /* 80 bytes * 8 = 640 */
    ctx->tail_block[63] = 0x80;
    return 0;
}

void meatrider_header(const meatrider_ctx *ctx, uint32_t nonce, uint8_t out[80]) {
    uint32_t i;
    for (i = 0; i < 64; i++) out[i] = ctx->first[i];
    for (i = 0; i < 12; i++) out[64 + i] = ctx->tail[i];
    store_le32(out + 76, nonce);
}

void meatrider_block1(const meatrider_ctx *ctx, uint32_t nonce, uint8_t blk[64]) {
    uint32_t i;

    /* header bytes 64..79 are the last 16 bytes of the 80-byte message; the
     * block's tail is the standard 0x80, zeros, and the 640-bit length, all of
     * which the context already holds. So this is one 64-byte copy and four
     * nonce bytes -- and the copy is four vector moves, not 45 stores. */
    for (i = 0; i < 64; i++) blk[i] = ctx->tail_block[i];
    store_le32(blk + 12, nonce);
}

/* The second block's constant half: 0x80, zeros, and the 256-bit length. */
static const uint8_t MEATRIDER_PAD2[32] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00,
};

void meatrider_block2(const uint32_t h1[8], uint8_t blk[64]) {
    uint32_t i;

    /* the second SHA-256: 32 bytes, one padded block, 256-bit length */
    for (i = 0; i < 8; i++) store_be32(blk + 4 * i, h1[i]);
    for (i = 0; i < 32; i++) blk[32 + i] = MEATRIDER_PAD2[i];
}

void meatrider_finish(const uint32_t h2[8], uint8_t out[32]) {
    uint32_t i;

    /* Bitcoin shows the digest reversed; that reversed order is also the
     * big-endian integer the target comparison uses, so reversing whole words
     * and storing them little-endian reverses all 32 bytes. */
    for (i = 0; i < 8; i++) store_le32(out + 4 * i, h2[7 - i]);
}

int meatrider_meets(const uint8_t digest[32], int difficulty) {
    int full, rem, i;

    if (difficulty <= 0) return 1;
    if (difficulty > 256) return 0;
    full = difficulty / 8;
    rem = difficulty % 8;
    for (i = 0; i < full && i < 32; i++)
        if (digest[i] != 0) return 0;
    if (rem != 0 && full < 32)
        return (digest[full] & (uint8_t)(0xFFu << (8 - rem))) == 0;
    return 1;
}

void meatrider_hash(const meatrider_ctx *ctx, uint32_t nonce, uint8_t out[32]) {
    uint8_t blk[64];
    uint32_t h[8];
    uint32_t i;

    meatrider_block1(ctx, nonce, blk);
    for (i = 0; i < 8; i++) h[i] = ctx->mid[i];
    meatrider_compress(h, blk);
    meatrider_block2(h, blk);
    meatrider_iv(h);
    meatrider_compress(h, blk);
    meatrider_finish(h, out);
}

int meatrider_digest(const uint8_t rd[32], int difficulty, uint32_t nonce,
                     uint8_t out[32]) {
    meatrider_ctx ctx;
    if (meatrider_ctx_init(&ctx, rd, difficulty) != 0) return -1;
    meatrider_hash(&ctx, nonce, out);
    return 0;
}

/* ------------------------------------------------------------------ */
/* The price ladder                                                    */
/* ------------------------------------------------------------------ */

static double usd_per_hash(double usd_per_th_day) {
    if (usd_per_th_day <= 0.0) usd_per_th_day = MEATRIDER_DEFAULT_USD_PER_TH_DAY;
    return usd_per_th_day / (1e12 * 86400.0);
}

double meatrider_price_usd(int difficulty, double usd_per_th_day) {
    double v = usd_per_hash(usd_per_th_day);
    int i;
    if (difficulty < 1) difficulty = 1;
    if (difficulty > 255) difficulty = 255;
    for (i = 0; i < difficulty; i++) v *= 2.0;   /* 2^d, no libm */
    return v;
}

double meatrider_asic_seconds(int difficulty, double hashrate) {
    double v = 1.0;
    int i;
    if (difficulty < 1) difficulty = 1;
    if (difficulty > 255) difficulty = 255;
    if (hashrate <= 0.0) hashrate = MEATRIDER_S21_PRO_HASHRATE;
    for (i = 0; i < difficulty; i++) v *= 2.0;
    return v / hashrate;
}

/* Rungs, in USD, as powers of ten. The name is the rung the price has reached;
 * the table is a joke with a straight face, so the amounts are real. */
static const struct {
    double usd;
    const char *name;
} MEATRIDER_TIERS[] = {
    {1e-15, "spark"},        {1e-14, "grain"},      {1e-13, "speck"},
    {1e-12, "mote"},         {1e-11, "crumb"},      {1e-10, "atom"},
    {1e-9, "nano"},          {1e-8, "microbit"},    {1e-7, "dust"},
    {1e-6, "suspicious"},    {1e-5, "very-suspicious"},
    {1e-4, "bot-shaped"},    {1e-3, "farm"},        {1e-2, "datacenter"},
    {1e-1, "asic"},          {1e0, "meatrider"},
};

const char *meatrider_tier_name(int difficulty) {
    double price;
    const char *name;
    unsigned i;

    if (difficulty < 1 || difficulty > 255) return NULL;
    price = meatrider_price_usd(difficulty, 0.0);
    name = MEATRIDER_TIERS[0].name;
    for (i = 0; i < sizeof MEATRIDER_TIERS / sizeof MEATRIDER_TIERS[0]; i++)
        if (price >= MEATRIDER_TIERS[i].usd) name = MEATRIDER_TIERS[i].name;
    return name;
}

int meatrider_difficulty_for_usd(double usd, double usd_per_th_day) {
    double hp = usd_per_hash(usd_per_th_day);
    double v = hp;
    int d = 0;

    if (usd <= 0.0) return 1;
    while (v < usd && d < 255) {
        v *= 2.0;
        d++;
    }
    return d < 1 ? 1 : d;
}
