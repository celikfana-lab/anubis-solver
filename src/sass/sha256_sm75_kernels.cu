
/* Device code only: no host includes, so nvcc -cubin yields one cubin. */
#include <stdint.h>

#define CUDA_RESULT_SLOTS 8

typedef struct {
    uint32_t mid[8];
    uint32_t prefix_len;
    uint32_t mode;
    uint32_t use_le;
    uint32_t difficulty;
    uint32_t check_bits;
} cuda_params;

typedef struct {
    uint32_t count;
    uint32_t pad[3];
    uint32_t nonces[CUDA_RESULT_SLOTS];
    uint32_t hashes[CUDA_RESULT_SLOTS][8];
} cuda_results;

__constant__ uint32_t c_k[64] = {
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
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

__device__ __forceinline__ uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

__device__ __forceinline__ uint32_t load_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

__device__ int dec_u64(uint64_t v, unsigned char *out) {
    unsigned char tmp[24];
    int n = 0;
    if (v == 0) { out[0] = '0'; return 1; }
    while (v > 0 && n < 24) { tmp[n++] = (unsigned char)('0' + (v % 10u)); v /= 10u; }
    for (int i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    return n;
}

/* ===================== the shipped kernel, verbatim ===================== */
__global__ void sha256_pow_kernel(cuda_params p, uint32_t base, uint32_t count,
                                  cuda_results *res) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    uint64_t nonce64 = (uint64_t)base + (uint64_t)idx;
    unsigned char blk[64];
    uint32_t dlen;
    for (int i = 0; i < 64; i++) blk[i] = 0;
    if (p.mode == 0) {
        dlen = (uint32_t)dec_u64(nonce64, blk);
    } else {
        uint32_t v = (uint32_t)nonce64;
        if (p.use_le) {
            blk[0] = (unsigned char)v; blk[1] = (unsigned char)(v >> 8);
            blk[2] = (unsigned char)(v >> 16); blk[3] = (unsigned char)(v >> 24);
        } else {
            blk[0] = (unsigned char)(v >> 24); blk[1] = (unsigned char)(v >> 16);
            blk[2] = (unsigned char)(v >> 8); blk[3] = (unsigned char)v;
        }
        dlen = 4;
    }
    blk[dlen] = 0x80;
    uint64_t bits = ((uint64_t)p.prefix_len + (uint64_t)dlen) * 8u;
    for (int i = 0; i < 8; i++) blk[56 + i] = (unsigned char)(bits >> (8 * (7 - i)));

    uint32_t w[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) w[i] = load_be32(blk + 4 * i);

    uint32_t a = p.mid[0], b = p.mid[1], c = p.mid[2], d = p.mid[3];
    uint32_t e = p.mid[4], f = p.mid[5], g = p.mid[6], h = p.mid[7];
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (i >= 16) {
            int j = i & 15;
            uint32_t x = w[(i + 1) & 15], y = w[(i + 14) & 15];
            uint32_t s0 = rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
            uint32_t s1 = rotr32(y, 17) ^ rotr32(y, 19) ^ (y >> 10);
            w[j] = w[j] + s0 + w[(i + 9) & 15] + s1;
        }
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + s1 + ch + c_k[i] + w[i & 15];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    uint32_t out[8];
    out[0] = p.mid[0] + a; out[1] = p.mid[1] + b;
    out[2] = p.mid[2] + c; out[3] = p.mid[3] + d;
    out[4] = p.mid[4] + e; out[5] = p.mid[5] + f;
    out[6] = p.mid[6] + g; out[7] = p.mid[7] + h;

    unsigned char dg[32];
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        dg[4*i] = (unsigned char)(out[i] >> 24);
        dg[4*i+1] = (unsigned char)(out[i] >> 16);
        dg[4*i+2] = (unsigned char)(out[i] >> 8);
        dg[4*i+3] = (unsigned char)out[i];
    }
    int ok = 1;
    if (p.check_bits == 0) {
        uint32_t full = p.difficulty / 2;
        for (uint32_t i = 0; i < full && ok; i++) ok = dg[i] == 0;
        if (ok && (p.difficulty & 1u)) ok = (dg[full] >> 4) == 0;
    } else {
        uint32_t full = p.difficulty / 8, rem = p.difficulty % 8;
        for (uint32_t i = 0; i < full && ok; i++) ok = dg[i] == 0;
        if (ok && rem) ok = (dg[full] & (unsigned char)(0xFFu << (8u - rem))) == 0;
    }
    if (ok) {
        uint32_t slot = atomicAdd(&res->count, 1u);
        if (slot < CUDA_RESULT_SLOTS) {
            res->nonces[slot] = (uint32_t)nonce64;
            for (int i = 0; i < 8; i++) res->hashes[slot][i] = out[i];
        }
    }
}

/* ===================== the optimised variant ============================
 * Same algorithm, same hit test. Three changes, all for the sha256 family
 * (u32 nonce, one tail block):
 *   1. no byte array: the block's 16 words are built in registers. The shipped
 *      kernel zeroes 64 bytes, writes 4, patches the length and reads all 16
 *      back - about 90 instructions of local-memory traffic per hash.
 *   2. the words that are constant for a challenge (W2..W14 = 0, W15 = bit
 *      length, W1 = 0x80) are not rebuilt per nonce.
 *   3. ILP 2: two nonces per thread, so the round chain of one overlaps the
 *      other's. SHA-256 rounds are latency-bound, not throughput-bound.
 */
#ifndef OPT_ILP
#define OPT_ILP 2
#endif
#define ILP OPT_ILP

__device__ __forceinline__ int hit_ok(const uint32_t o[8], uint32_t diff) {
    /* exactly the shipped rule for check_bits == 0: diff/2 whole bytes must be
       zero, then the high nibble if diff is odd. Sharing the rule keeps the A/B
       honest - only the compression path differs. */
    uint32_t full = diff / 2u;
    for (uint32_t i = 0; i < full; i++) {
        uint32_t b = (o[i >> 2] >> (24u - 8u * (i & 3u))) & 0xFFu;
        if (b) return 0;
    }
    if (diff & 1u) {
        uint32_t i = full;
        uint32_t b = (o[i >> 2] >> (24u - 8u * (i & 3u))) & 0xFFu;
        if (b >> 4) return 0;
    }
    return 1;
}

__global__ void sha256_opt_kernel(cuda_params p, uint32_t base, uint32_t count,
                                  cuda_results *res) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t first = tid * ILP;
    if (first >= count) return;

    uint32_t a[ILP], b[ILP], c[ILP], d[ILP], e[ILP], f[ILP], g[ILP], h[ILP];
    uint32_t w[ILP][16];
    uint32_t nonce[ILP];
    const uint32_t blen = (uint32_t)((p.prefix_len + 4u) * 8u);

    #pragma unroll
    for (int u = 0; u < ILP; u++) {
        uint32_t n = base + first + u;
        nonce[u] = n;
        w[u][0]  = p.use_le ? __byte_perm(n, 0u, 0x0123) : n;
        w[u][1]  = 0x80000000u;
        #pragma unroll
        for (int i = 2; i < 15; i++) w[u][i] = 0u;
        w[u][15] = blen;
        a[u] = p.mid[0]; b[u] = p.mid[1]; c[u] = p.mid[2]; d[u] = p.mid[3];
        e[u] = p.mid[4]; f[u] = p.mid[5]; g[u] = p.mid[6]; h[u] = p.mid[7];
    }

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        #pragma unroll
        for (int u = 0; u < ILP; u++) {
            if (i >= 16) {
                int j = i & 15;
                uint32_t x = w[u][(i + 1) & 15], y = w[u][(i + 14) & 15];
                uint32_t s0 = __funnelshift_r(x, x, 7) ^ __funnelshift_r(x, x, 18) ^ (x >> 3);
                uint32_t s1 = __funnelshift_r(y, y, 17) ^ __funnelshift_r(y, y, 19) ^ (y >> 10);
                w[u][j] = w[u][j] + s0 + w[u][(i + 9) & 15] + s1;
            }
            uint32_t s1 = __funnelshift_r(e[u], e[u], 6) ^ __funnelshift_r(e[u], e[u], 11)
                        ^ __funnelshift_r(e[u], e[u], 25);
            uint32_t ch = (e[u] & f[u]) ^ ((~e[u]) & g[u]);
            uint32_t t1 = h[u] + s1 + ch + c_k[i] + w[u][i & 15];
            uint32_t s0 = __funnelshift_r(a[u], a[u], 2) ^ __funnelshift_r(a[u], a[u], 13)
                        ^ __funnelshift_r(a[u], a[u], 22);
            uint32_t maj = (a[u] & b[u]) ^ (a[u] & c[u]) ^ (b[u] & c[u]);
            uint32_t t2 = s0 + maj;
            h[u] = g[u]; g[u] = f[u]; f[u] = e[u]; e[u] = d[u] + t1;
            d[u] = c[u]; c[u] = b[u]; b[u] = a[u]; a[u] = t1 + t2;
        }
    }

    #pragma unroll
    for (int u = 0; u < ILP; u++) {
        uint32_t o[8];
        o[0] = p.mid[0] + a[u]; o[1] = p.mid[1] + b[u];
        o[2] = p.mid[2] + c[u]; o[3] = p.mid[3] + d[u];
        o[4] = p.mid[4] + e[u]; o[5] = p.mid[5] + f[u];
        o[6] = p.mid[6] + g[u]; o[7] = p.mid[7] + h[u];
        if (hit_ok(o, p.difficulty)) {
            uint32_t slot = atomicAdd(&res->count, 1u);
            if (slot < CUDA_RESULT_SLOTS) {
                res->nonces[slot] = nonce[u];
                for (int i = 0; i < 8; i++) res->hashes[slot][i] = o[i];
            }
        }
    }
}

