#ifndef FB_MEATRIDER_H
#define FB_MEATRIDER_H

/* `meatrider`: Bitcoin-shaped proof of work.
 *
 * The tier is SHA-256, twice, over a real 80-byte Bitcoin block header that is
 * rebuilt from the challenge. Nothing about the wire protocol changes: the
 * 32-byte `randomData` seeds the header, `difficulty` is the leading-zero-bit
 * count every other tier uses, and the client's 32-bit nonce lands in the
 * header's nonce field. The returned digest is in Bitcoin's display order
 * (byte-reversed), so its leading zero bits are what a block explorer shows
 * and `hash < 2^(256-difficulty)` is exactly the leading-zero-bits test.
 *
 * Header layout, all little-endian where Bitcoin is:
 *
 *   0..3    version    = 1                     (the genesis version)
 *   4..35   prev block = randomData[0..32)
 *   36..67  merkle     = SHA256("meatrider" || randomData)
 *   68..71  time       = 1231006505             (the genesis timestamp)
 *   72..75  bits       = compact(2^(256-difficulty))
 *   76..79  nonce      = the client's nonce
 *
 * The `bits` field is Bitcoin's own nBits encoding of the target, so the header
 * is self-describing: a Bitcoin verifier reading it would apply the same
 * threshold the leading-zero-bits test applies here. Because nBits is part of
 * the hashed message, a proof is bound to its difficulty -- the same nonce
 * hashes to something else at another difficulty, exactly as in Bitcoin.
 *
 * The price, for the ladder, is what an Antminer S21 Pro would earn doing
 * 2^difficulty hashes: `2^difficulty * usd_per_th_day / (1e12 * 86400)`. It is
 * a label on the work, not a payment: see anubis_solve_meatrider(). */

#include <stddef.h>
#include <stdint.h>

#define MEATRIDER_HEADER_LEN 80
#define MEATRIDER_VERSION 1u
#define MEATRIDER_TIME 1231006505u        /* 2009-01-03 18:15:05 UTC, block 0 */
#define MEATRIDER_DEFAULT_USD_PER_TH_DAY 0.05
#define MEATRIDER_S21_PRO_HASHRATE 2.34e14 /* 234 TH/s, the S21 Pro's spec */

/* A challenge's fixed half of the header, with the block-1 SHA-256 midstate
 * already compressed, so one hash costs two compressions instead of three. */
typedef struct {
    uint8_t first[64];    /* header bytes 0..63, for meatrider_header() */
    uint32_t mid[8];      /* SHA-256 state after those bytes */
    uint32_t bits;        /* the nBits field, compact(2^(256-difficulty)) */
    int difficulty;       /* the leading zero bits the header asks for */
    uint8_t tail[12];     /* header bytes 64..75: merkle[28..32), time, bits */
    /* Block 1 with its four nonce bytes still zero, and the constant tail of
     * block 2. A hash is two compressions; without these the padding would be
     * rewritten for every candidate, which measured about 100 of the ~450
     * cycles a SHA-NI hash costs. */
    uint8_t tail_block[64];
} meatrider_ctx;

/* Build the context. `rd` is the 32-byte randomData; `difficulty` is 1..255.
 * Returns 0, or -1 when the arguments are out of range. */
int meatrider_ctx_init(meatrider_ctx *ctx, const uint8_t rd[32], int difficulty);

/* The full 80-byte header for one nonce. */
void meatrider_header(const meatrider_ctx *ctx, uint32_t nonce, uint8_t out[80]);

/* The digest for one nonce, in display order (reverse of the SHA-256d output). */
void meatrider_hash(const meatrider_ctx *ctx, uint32_t nonce, uint8_t out[32]);

/* The digest for one nonce, from scratch: no midstate, for verification paths
 * that see a challenge once. `out` is display order. Returns 0 or -1. */
int meatrider_digest(const uint8_t rd[32], int difficulty, uint32_t nonce,
                     uint8_t out[32]);

/* ------------------------------------------------------------------ *
 * The pieces of one hash
 *
 * Exposed because every backend of the tier -- the SHA-NI and AVX2/AVX-512
 * assembly, the WASM SIMD128 kernel, the OpenCL/Vulkan/Level Zero/CUDA/PTX/TPU
 * kernels -- keeps the two compressions in its own hands and has to agree with
 * this file on the byte layout. There is exactly one place where "real
 * Bitcoin" lives: these five functions.
 * ------------------------------------------------------------------ */

/* One SHA-256 compression of a whole 64-byte block into `h`. The portable
 * reference: ~940 cycles, against ~80 for the SHA-NI block in
 * meatrider_shani.s. */
void meatrider_compress(uint32_t h[8], const uint8_t blk[64]);

/* The SHA-256 initial state. */
void meatrider_iv(uint32_t h[8]);

/* Block 1 for one nonce: `tail[12]`, the nonce as four little-endian bytes,
 * 0x80, zeros, and the 640-bit length. That is the block a Bitcoin miner
 * builds: header bytes 64..79 are the last 16 bytes of an 80-byte message. */
void meatrider_block1(const meatrider_ctx *ctx, uint32_t nonce, uint8_t blk[64]);

/* Block 2 from the first compression's state words: the 32-byte first digest
 * big-endian, 0x80, zeros, and the 256-bit length. */
void meatrider_block2(const uint32_t h1[8], uint8_t blk[64]);

/* Display-order digest from the final state: the byte reverse of SHA-256's
 * output, which is the form a block explorer shows. */
void meatrider_finish(const uint32_t h2[8], uint8_t out[32]);

/* 1 when a display-order digest has `difficulty` leading zero bits, i.e.
 * Bitcoin's `hash < 2^(256-difficulty)` test. Difficulty 0 always passes; the
 * full 256 only passes for a digest of zeros. */
int meatrider_meets(const uint8_t digest[32], int difficulty);

/* Bitcoin's nBits for the exact target 2^(256-difficulty). */
uint32_t meatrider_bits(int difficulty);

/* What the work is worth, in USD, at `usd_per_th_day` (<= 0 = the default). */
double meatrider_price_usd(int difficulty, double usd_per_th_day);

/* Seconds an ASIC of `hashrate` H/s needs for the expected 2^difficulty hashes
 * (<= 0 = the S21 Pro). */
double meatrider_asic_seconds(int difficulty, double hashrate);

/* The rung's name, from the price at the default hash price: "atom",
 * "suspicious", "asic", "meatrider", ... NULL when difficulty is out of range. */
const char *meatrider_tier_name(int difficulty);

/* The difficulty whose price first reaches `usd`, i.e. the rung to ask for. */
int meatrider_difficulty_for_usd(double usd, double usd_per_th_day);

#endif /* FB_MEATRIDER_H */
