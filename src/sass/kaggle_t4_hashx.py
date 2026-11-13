# HashX on sm_75: shipped interpreter vs register-pinned interpreter vs the
# program compiled to straight-line code.
KERNELS = r'''
#include <stdint.h>

typedef struct { uint64_t k0, k1, k2, k3; } hx_keys;
typedef struct {
    uint32_t count; uint32_t pad[3];
    uint32_t nonces[8];
    uint32_t hashes[8][8];
} hx_results;

__device__ __forceinline__ uint64_t rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }
__device__ __forceinline__ uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

#define SIPROUND(v0, v1, v2, v3)                                              \
    do {                                                                      \
        v0 += v1; v2 += v3; v1 = rotl64(v1, 13);                              \
        v3 = rotl64(v3, 16); v1 ^= v0; v3 ^= v2;                              \
        v0 = rotl64(v0, 32); v2 += v1; v0 += v3;                              \
        v1 = rotl64(v1, 17); v3 = rotl64(v3, 21);                             \
        v1 ^= v2; v3 ^= v0; v2 = rotl64(v2, 32);                              \
    } while (0)

__device__ __forceinline__ int64_t smulhi64(int64_t a, int64_t b) {
    int64_t hi = (int64_t)__umul64hi((uint64_t)a, (uint64_t)b);
    if (a < 0) hi -= b;
    if (b < 0) hi -= a;
    return hi;
}

__device__ __forceinline__ void hx_prf(hx_keys keys, uint32_t nonce, uint64_t *r) {
    uint64_t v0 = keys.k0, v1 = keys.k1, v2 = keys.k2, v3 = keys.k3;
    v1 ^= 0xeeULL; v3 ^= (uint64_t)nonce;
    SIPROUND(v0, v1, v2, v3); SIPROUND(v0, v1, v2, v3);
    v0 ^= (uint64_t)nonce; v2 ^= 0xeeULL;
    SIPROUND(v0, v1, v2, v3); SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3); SIPROUND(v0, v1, v2, v3);
    r[0] = v0; r[1] = v1; r[2] = v2; r[3] = v3;
    v1 ^= 0xddULL;
    SIPROUND(v0, v1, v2, v3); SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3); SIPROUND(v0, v1, v2, v3);
    r[4] = v0; r[5] = v1; r[6] = v2; r[7] = v3;
}

__device__ __forceinline__ void hx_fin(hx_keys keys, uint64_t *r, uint32_t nonce,
                                       uint32_t difficulty, hx_results *res, int *okp) {
    uint64_t w[4], a, b, c, e;
    uint8_t dg[32];
    int ok = 1, i;
    r[0] += keys.k0; r[1] += keys.k1; r[6] += keys.k2; r[7] += keys.k3;
    a = r[0]; b = r[1]; c = r[2]; e = r[3];
    SIPROUND(a, b, c, e);
    r[0] = a; r[1] = b; r[2] = c; r[3] = e;
    a = r[4]; b = r[5]; c = r[6]; e = r[7];
    SIPROUND(a, b, c, e);
    r[4] = a; r[5] = b; r[6] = c; r[7] = e;
    w[0] = r[0] ^ r[4]; w[1] = r[1] ^ r[5];
    w[2] = r[2] ^ r[6]; w[3] = r[3] ^ r[7];
    for (i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++) dg[8*i+j] = (uint8_t)(w[i] >> (8*j));
    for (uint32_t bi = 0; bi < difficulty; bi++)
        if (((dg[bi >> 3] >> (7u - (bi & 7u))) & 1u) != 0u) { ok = 0; break; }
    if (ok) {
        uint32_t slot = atomicAdd(&res->count, 1u);
        if (slot < 8u) {
            res->nonces[slot] = nonce;
            for (i = 0; i < 8; i++)
                res->hashes[slot][i] = ((uint32_t)dg[4*i] << 24) | ((uint32_t)dg[4*i+1] << 16) |
                                       ((uint32_t)dg[4*i+2] << 8) | (uint32_t)dg[4*i+3];
        }
    }
    *okp = ok;
}

/* ===================== the shipped kernel, verbatim ===================== */
__global__ void hashx_kernel(hx_keys keys, const uint4 *prog,
                             uint32_t code_size, uint32_t difficulty,
                             uint32_t base, uint32_t count, hx_results *res) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    uint64_t r[8];
    uint64_t v0, v1, v2, v3;
    int target = 0, be = 1, i;
    uint32_t result = 0, nonce;
    uint64_t w[4];
    uint8_t dg[32];
    if (idx >= count) return;
    nonce = base + idx;
    hx_prf(keys, nonce, r);

    i = 0;
    while (i < (int)code_size) {
        uint4 in = prog[i];
        uint32_t op = in.x, dst = in.y, src = in.z, imm = in.w;
        switch (op) {
        case 0: result = (uint32_t)__umul64hi(r[dst], r[src]); r[dst] = __umul64hi(r[dst], r[src]); break;
        case 1: r[dst] = (uint64_t)smulhi64((int64_t)r[dst], (int64_t)r[src]); result = (uint32_t)r[dst]; break;
        case 2: r[dst] *= r[src]; break;
        case 3: r[dst] -= r[src]; break;
        case 4: r[dst] ^= r[src]; break;
        case 5: r[dst] += r[src] << (imm & 63u); break;
        case 6: r[dst] = rotr64(r[dst], (int)(imm & 63u)); break;
        case 7: r[dst] += (uint64_t)(int64_t)(int32_t)imm; break;
        case 8: r[dst] ^= (uint64_t)(int64_t)(int32_t)imm; break;
        case 9: target = i; break;
        case 10: if (be && (result & imm) == 0) { i = target; be = 0; } break;
        default: break;
        }
        i++;
    }
    int ok; hx_fin(keys, r, nonce, difficulty, res, &ok);
}

/* ============ variant 2: register file pinned by a switch ============ */
#ifndef OPT_ILP
#define OPT_ILP 1
#endif
#define HX_ILP OPT_ILP

__constant__ uint4 c_prog[512];
__constant__ uint32_t c_codesize;
__constant__ uint32_t c_difficulty;

__device__ __forceinline__ void wr8(uint64_t *r, int i, uint64_t v) {
    switch (i) {
    case 0: r[0] = v; break;  case 1: r[1] = v; break;
    case 2: r[2] = v; break;  case 3: r[3] = v; break;
    case 4: r[4] = v; break;  case 5: r[5] = v; break;
    case 6: r[6] = v; break;  case 7: r[7] = v; break;
    default: break;
    }
}

__global__ void hashx_opt_kernel(hx_keys keys, const uint4 *prog,
                                 uint32_t code_size, uint32_t difficulty,
                                 uint32_t base, uint32_t count, hx_results *res) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t first = tid * HX_ILP;
    if (first >= count) return;

    uint64_t r[HX_ILP][8];
    int target[HX_ILP], be[HX_ILP], tkn;
    uint32_t result[HX_ILP], nonce[HX_ILP];
    uint32_t cs = c_codesize;

    #pragma unroll
    for (int u = 0; u < HX_ILP; u++) {
        nonce[u] = base + first + u;
        hx_prf(keys, nonce[u], r[u]);
        target[u] = 0; be[u] = 1; result[u] = 0;
    }

    for (uint32_t pc = 0; pc < cs; ) {
        uint4 in = c_prog[pc];
        uint32_t op = in.x, dst = in.y, src = in.z, imm = in.w;
        tkn = -1;
        #pragma unroll
        for (int u = 0; u < HX_ILP; u++) {
            uint64_t d, s, v;
            switch (dst) {
            case 0: d = r[u][0]; break; case 1: d = r[u][1]; break;
            case 2: d = r[u][2]; break; case 3: d = r[u][3]; break;
            case 4: d = r[u][4]; break; case 5: d = r[u][5]; break;
            case 6: d = r[u][6]; break; default: d = r[u][7]; break;
            }
            switch (src & 7u) {
            case 0: s = r[u][0]; break; case 1: s = r[u][1]; break;
            case 2: s = r[u][2]; break; case 3: s = r[u][3]; break;
            case 4: s = r[u][4]; break; case 5: s = r[u][5]; break;
            case 6: s = r[u][6]; break; default: s = r[u][7]; break;
            }
            v = d;
            switch (op) {
            case 0: v = __umul64hi(d, s); result[u] = (uint32_t)v; break;
            case 1: v = (uint64_t)smulhi64((int64_t)d, (int64_t)s); result[u] = (uint32_t)v; break;
            case 2: v = d * s; break;
            case 3: v = d - s; break;
            case 4: v = d ^ s; break;
            case 5: v = d + (s << (imm & 63u)); break;
            case 6: v = rotr64(d, (int)(imm & 63u)); break;
            case 7: v = d + (uint64_t)(int64_t)(int32_t)imm; break;
            case 8: v = d ^ (uint64_t)(int64_t)(int32_t)imm; break;
            case 9: target[u] = (int)pc; break;
            case 10: if (be[u] && (result[u] & imm) == 0u) { be[u] = 0; tkn = u; } break;
            default: break;
            }
            wr8(r[u], (int)dst, v);
        }
        if (tkn >= 0) pc = (uint32_t)target[tkn];
        else pc++;
    }

    #pragma unroll
    for (int u = 0; u < HX_ILP; u++) {
        int ok; hx_fin(keys, r[u], nonce[u], difficulty, res, &ok);
    }
}

/* ============ variant 3: the program compiled to straight line ============
 * The HashX program is fixed for a whole challenge, so the interpreter is not
 * needed at all: this kernel is the 512 instructions emitted as straight-line
 * code with constant register names. No program memory, no dispatch, no array
 * indexing, nothing in local memory. It is per-challenge code, which is what a
 * JIT backend does host-side; the branch is the program's one taken branch.
 */
__global__ void hashx_jit_kernel(hx_keys keys, const uint4 *prog,
                                 uint32_t code_size, uint32_t difficulty,
                                 uint32_t base, uint32_t count, hx_results *res) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    uint32_t nonce = base + idx;

    uint64_t rr[8];
    hx_prf(keys, nonce, rr);
    uint64_t r0 = rr[0], r1 = rr[1], r2 = rr[2], r3 = rr[3];
    uint64_t r4 = rr[4], r5 = rr[5], r6 = rr[6], r7 = rr[7];
    uint32_t result = 0;
    int be = 1;

    /* ---- generated from the challenge program ---- */
    r5 *= r1;
L2:;
    r1 *= r0;
    r6 = rotr64(r6, 27);
    r4 ^= 0x0000000068626fbbull;
    r7 *= r2;
    r0 ^= 0xffffffff99d3252cull;
    r3 -= r4;
    r4 *= r3;
    r2 = rotr64(r2, 18);
    r0 ^= r3;
    r1 = __umul64hi(r1, r0); result = (uint32_t)r1;
    r5 ^= 0xfffffffffdd2bb58ull;
    r5 *= r3;
    r3 += 0xffffffffed6667d7ull;
    r0 -= r6;
    r3 *= r0;
    if (be && ((result & 0x01000414u) == 0u)) { be = 0; goto L2; }
    r2 *= r0;
    r6 += 0x000000006f0d1051ull;
    r0 ^= 0xffffffffde57daffull;
    r7 = __umul64hi(r7, r7); result = (uint32_t)r7;
    r4 += 0x000000002702d017ull;
    r1 *= r3;
    r0 -= r3;
    r3 += 0xffffffffa3bcc218ull;
    r3 *= r2;
    r4 += r0 << 0u;
    r5 += 0x000000003ee87f22ull;
    r4 *= r0;
    r2 ^= r6;
    r6 = rotr64(r6, 59);
    r2 *= r5;
L34:;
    r0 *= r6;
    r1 ^= r5;
    r6 += r7 << 2u;
    r5 *= r6;
    r1 += 0xffffffffec679461ull;
    r6 = rotr64(r6, 54);
    r7 *= r1;
    r1 -= r3;
    r2 += 0x000000000bcf6a43ull;
    r1 = (uint64_t)smulhi64((int64_t)r1, (int64_t)r2); result = (uint32_t)r1;
    r3 = rotr64(r3, 59);
    r2 *= r3;
    r3 += 0xffffffffae117c02ull;
    r6 ^= 0x000000005738663bull;
    r3 *= r0;
    if (be && ((result & 0x80400402u) == 0u)) { be = 0; goto L34; }
    r4 *= r7;
    r7 ^= r5;
    r6 -= r5;
    r1 = (uint64_t)smulhi64((int64_t)r1, (int64_t)r7); result = (uint32_t)r1;
    r2 -= r5;
    r6 *= r3;
    r7 += 0xffffffffedbd27dcull;
    r3 = rotr64(r3, 52);
    r3 *= r2;
    r7 ^= 0x000000007202ac2full;
    r4 ^= r5;
    r4 *= r0;
    r2 ^= 0xffffffffc9f7d1a3ull;
    r5 += 0x000000002e93307full;
    r7 *= r0;
L66:;
    r5 *= r6;
    r1 -= r2;
    r6 ^= r3;
    r6 *= r3;
    r3 = rotr64(r3, 21);
    r4 += r1 << 1u;
    r3 *= r4;
    r7 += 0x00000000525d7670ull;
    r4 ^= 0xffffffffedd36bd6ull;
    r0 = __umul64hi(r0, r0); result = (uint32_t)r0;
    r7 ^= 0xffffffff941c07b5ull;
    r7 *= r4;
    r4 += r1 << 0u;
    r6 ^= 0x000000006cee1f0bull;
    r4 *= r6;
    if (be && ((result & 0x04084002u) == 0u)) { be = 0; goto L66; }
    r2 *= r6;
    r5 ^= 0xfffffffffef9daffull;
    r3 += 0xffffffff89b9c9d5ull;
    r5 = (uint64_t)smulhi64((int64_t)r5, (int64_t)r5); result = (uint32_t)r5;
    r7 ^= 0x00000000295ebad7ull;
    r3 *= r0;
    r0 ^= r1;
    r1 ^= 0x0000000000c08631ull;
    r7 *= r0;
    r4 += r2 << 0u;
    r0 ^= 0x000000002a33629dull;
    r4 *= r6;
    r2 ^= 0xffffffffc816d41bull;
    r6 -= r1;
    r6 *= r5;
L98:;
    r0 *= r1;
    r2 ^= r5;
    r3 = rotr64(r3, 31);
    r3 *= r4;
    r1 = rotr64(r1, 38);
    r2 ^= 0xffffffffa8b2e396ull;
    r5 *= r7;
    r2 += 0x00000000502bfb2cull;
    r1 ^= 0x000000005f52abe8ull;
    r6 = __umul64hi(r6, r4); result = (uint32_t)r6;
    r7 = rotr64(r7, 32);
    r7 *= r2;
    r0 -= r1;
    r4 ^= 0x0000000025235ba5ull;
    r2 *= r4;
    if (be && ((result & 0x00280024u) == 0u)) { be = 0; goto L98; }
    r1 *= r4;
    r5 ^= 0xffffffffb0137048ull;
    r4 ^= r3;
    r3 = __umul64hi(r3, r6); result = (uint32_t)r3;
    r0 = rotr64(r0, 52);
    r4 *= r0;
    r2 += 0xffffffff8809152dull;
    r5 -= r6;
    r5 *= r0;
    r1 ^= 0x000000007ccbb551ull;
    r6 += 0x000000006c373745ull;
    r2 *= r1;
    r7 += r1 << 2u;
    r0 ^= 0xffffffffa14d4f05ull;
    r1 *= r0;
L130:;
    r7 *= r0;
    r5 += 0x000000006aee46ceull;
    r6 ^= 0xffffffff92c8bafcull;
    r0 *= r5;
    r3 += 0x0000000019e247cfull;
    r5 ^= r2;
    r3 *= r5;
    r1 ^= 0xffffffffd312ff41ull;
    r2 ^= r5;
    r7 = __umul64hi(r7, r6); result = (uint32_t)r7;
    r6 -= r4;
    r2 *= r1;
    r1 += r4 << 0u;
    r5 ^= 0x000000007af03146ull;
    r6 *= r3;
    if (be && ((result & 0x01002011u) == 0u)) { be = 0; goto L130; }
    r5 *= r1;
    r0 += 0xffffffff9b112c11ull;
    r3 += r4 << 1u;
    r3 = __umul64hi(r3, r4); result = (uint32_t)r3;
    r1 ^= r2;
    r0 *= r7;
    r1 ^= 0xffffffff877d9721ull;
    r4 = rotr64(r4, 38);
    r4 *= r7;
    r6 += r5 << 3u;
    r2 ^= 0x000000005f7f1eaaull;
    r1 *= r6;
    r5 = rotr64(r5, 42);
    r2 += r7 << 3u;
    r2 *= r5;
L162:;
    r6 *= r3;
    r7 ^= 0xfffffffffe6200b7ull;
    r0 = rotr64(r0, 25);
    r5 *= r4;
    r3 += 0x0000000052ddaa73ull;
    r0 ^= 0x00000000054a4389ull;
    r7 *= r1;
    r0 += r1 << 2u;
    r2 += 0xffffffffb3c76eddull;
    r0 = __umul64hi(r0, r0); result = (uint32_t)r0;
    r4 ^= r6;
    r3 *= r2;
    r2 ^= 0x000000007018e1a6ull;
    r6 += 0xffffffffaeae4131ull;
    r6 *= r2;
    if (be && ((result & 0x00b00400u) == 0u)) { be = 0; goto L162; }
    r4 *= r1;
    r2 += r1 << 0u;
    r7 ^= 0xffffffff9d7a7f1eull;
    r5 = __umul64hi(r5, r3); result = (uint32_t)r5;
    r1 ^= r3;
    r0 *= r3;
    r3 += r1 << 3u;
    r1 = rotr64(r1, 45);
    r2 *= r1;
    r7 ^= r1;
    r1 += 0x00000000441f23ebull;
    r3 *= r6;
    r6 = rotr64(r6, 14);
    r4 += 0x000000002e624daaull;
    r6 *= r5;
L194:;
    r1 *= r5;
    r4 ^= r2;
    r0 = rotr64(r0, 40);
    r7 *= r3;
    r2 ^= 0xffffffff9e870524ull;
    r3 -= r5;
    r2 *= r4;
    r6 += 0x0000000013c532aeull;
    r3 = rotr64(r3, 25);
    r0 = (uint64_t)smulhi64((int64_t)r0, (int64_t)r6); result = (uint32_t)r0;
    r5 ^= 0x000000007dadfe0bull;
    r3 *= r6;
    r1 += 0x0000000038d81514ull;
    r7 ^= 0xffffffffe83bd51cull;
    r6 *= r2;
    if (be && ((result & 0x00208084u) == 0u)) { be = 0; goto L194; }
    r1 *= r7;
    r2 ^= 0x0000000045678968ull;
    r4 = rotr64(r4, 32);
    r7 = __umul64hi(r7, r7); result = (uint32_t)r7;
    r3 = rotr64(r3, 22);
    r0 *= r4;
    r2 += 0x000000003dcdd4d5ull;
    r3 ^= r4;
    r2 *= r6;
    r4 += 0x0000000026bc153bull;
    r3 += r1 << 1u;
    r3 *= r1;
    r5 -= r1;
    r6 ^= r1;
    r5 *= r7;
L226:;
    r4 *= r7;
    r7 ^= 0x000000004c9ecd5full;
    r2 += 0xffffffffeddf7b4eull;
    r7 *= r3;
    r3 ^= 0xffffffffde18bba0ull;
    r2 = rotr64(r2, 42);
    r3 *= r0;
    r0 = rotr64(r0, 58);
    r5 -= r1;
    r5 = (uint64_t)smulhi64((int64_t)r5, (int64_t)r6); result = (uint32_t)r5;
    r6 ^= 0x000000003bc53f56ull;
    r6 *= r0;
    r4 = rotr64(r4, 55);
    r7 += 0x000000004c41f47bull;
    r0 *= r7;
    if (be && ((result & 0x00080c10u) == 0u)) { be = 0; goto L226; }
    r4 *= r7;
    r2 ^= r7;
    r7 = rotr64(r7, 59);
    r2 = __umul64hi(r2, r3); result = (uint32_t)r2;
    r1 = rotr64(r1, 52);
    r1 *= r5;
    r0 -= r6;
    r5 ^= r7;
    r0 *= r5;
    r7 ^= 0x000000004f091543ull;
    r3 += 0x000000000bd98a4dull;
    r3 *= r4;
    r5 -= r6;
    r6 += 0xffffffffa72c6265ull;
    r5 *= r6;
L258:;
    r2 *= r1;
    r0 ^= 0x0000000042271bb9ull;
    r4 ^= r1;
    r0 *= r6;
    r3 ^= 0xfffffffff83ea8ccull;
    r7 += 0xffffffffd2acdbbcull;
    r7 *= r6;
    r6 ^= r4;
    r5 += 0xffffffffd149f89eull;
    r5 = (uint64_t)smulhi64((int64_t)r5, (int64_t)r3); result = (uint32_t)r5;
    r2 ^= 0x000000007cae4eeaull;
    r3 *= r1;
    r2 ^= r1;
    r1 += 0xffffffffe22316c4ull;
    r4 *= r0;
    if (be && ((result & 0x08100440u) == 0u)) { be = 0; goto L258; }
    r2 *= r6;
    r1 = rotr64(r1, 12);
    r7 ^= r6;
    r6 = __umul64hi(r6, r6); result = (uint32_t)r6;
    r5 = rotr64(r5, 54);
    r1 *= r7;
    r7 += 0x000000006a50d025ull;
    r3 += r4 << 0u;
    r3 *= r5;
    r7 = rotr64(r7, 48);
    r4 += r2 << 1u;
    r5 *= r7;
    r7 ^= 0x0000000055a15746ull;
    r0 ^= r4;
    r0 *= r7;
L290:;
    r7 *= r1;
    r6 = rotr64(r6, 50);
    r2 ^= 0x000000003c921017ull;
    r2 *= r4;
    r1 ^= r5;
    r6 -= r5;
    r1 *= r0;
    r3 += 0xffffffffe1cc9ed2ull;
    r5 = rotr64(r5, 61);
    r0 = (uint64_t)smulhi64((int64_t)r0, (int64_t)r6); result = (uint32_t)r0;
    r6 ^= 0x000000006d2430f1ull;
    r5 *= r7;
    r3 -= r6;
    r4 ^= 0xffffffffc6af7393ull;
    r4 *= r7;
    if (be && ((result & 0x00008601u) == 0u)) { be = 0; goto L290; }
    r3 *= r2;
    r6 += 0xffffffffbed3dc26ull;
    r2 += r1 << 1u;
    r7 = __umul64hi(r7, r1); result = (uint32_t)r7;
    r1 += 0x00000000723f658bull;
    r1 *= r0;
    r6 ^= 0xffffffffc1791db9ull;
    r0 += 0x0000000064776817ull;
    r2 *= r0;
    r3 += 0xffffffffc79b0495ull;
    r4 = rotr64(r4, 25);
    r6 *= r4;
    r4 += 0xffffffff8732680eull;
    r3 -= r5;
    r0 *= r3;
L322:;
    r4 *= r2;
    r2 += 0xffffffff8ee6c282ull;
    r5 ^= 0x000000003d963d05ull;
    r5 *= r3;
    r1 ^= r2;
    r6 += 0xfffffffffc7d31a4ull;
    r7 *= r2;
    r2 ^= 0x0000000015d75797ull;
    r1 ^= r3;
    r2 = __umul64hi(r2, r0); result = (uint32_t)r2;
    r0 ^= 0x00000000037063c5ull;
    r3 *= r5;
    r5 ^= 0xffffffff86768ab3ull;
    r0 += 0x000000006bd1e586ull;
    r1 *= r6;
    if (be && ((result & 0x41001200u) == 0u)) { be = 0; goto L322; }
    r5 *= r7;
    r6 ^= 0xfffffffffaa6fa7eull;
    r4 += r7 << 2u;
    r6 = (uint64_t)smulhi64((int64_t)r6, (int64_t)r3); result = (uint32_t)r6;
    r0 -= r4;
    r2 *= r0;
    r0 -= r7;
    r3 ^= r7;
    r4 *= r3;
    r5 -= r7;
    r3 ^= 0xffffffff9a451864ull;
    r5 *= r3;
    r0 += 0x000000006cb7d53dull;
    r1 ^= r3;
    r1 *= r3;
L354:;
    r3 *= r6;
    r6 += 0x000000002178d319ull;
    r0 = rotr64(r0, 42);
    r6 *= r4;
    r0 += r2 << 3u;
    r5 += 0x00000000549a8cadull;
    r5 *= r7;
    r4 -= r1;
    r2 ^= r7;
    r4 = __umul64hi(r4, r4); result = (uint32_t)r4;
    r1 ^= 0x000000002566d705ull;
    r1 *= r7;
    r6 = rotr64(r6, 32);
    r7 ^= 0xffffffffea55cce7ull;
    r2 *= r3;
    if (be && ((result & 0x8000a400u) == 0u)) { be = 0; goto L354; }
    r0 *= r6;
    r5 = rotr64(r5, 44);
    r7 += r3 << 0u;
    r1 = __umul64hi(r1, r4); result = (uint32_t)r1;
    r6 ^= r5;
    r7 *= r2;
    r4 ^= 0xffffffff9f31e141ull;
    r3 += 0xffffffffcd7e60deull;
    r6 *= r2;
    r3 ^= 0xffffffff9d4ed1a5ull;
    r5 ^= r0;
    r4 *= r0;
    r3 -= r0;
    r2 = rotr64(r2, 15);
    r2 *= r1;
L386:;
    r5 *= r1;
    r6 ^= r0;
    r7 ^= 0x000000000576d138ull;
    r7 *= r1;
    r4 = rotr64(r4, 11);
    r1 -= r3;
    r4 *= r0;
    r0 -= r1;
    r6 += 0x000000007d465b7eull;
    r6 = (uint64_t)smulhi64((int64_t)r6, (int64_t)r1); result = (uint32_t)r6;
    r2 += r5 << 0u;
    r2 *= r7;
    r7 = rotr64(r7, 43);
    r5 ^= 0x000000001292921eull;
    r1 *= r7;
    if (be && ((result & 0x21400020u) == 0u)) { be = 0; goto L386; }
    r5 *= r0;
    r0 -= r4;
    r3 = rotr64(r3, 50);
    r2 = (uint64_t)smulhi64((int64_t)r2, (int64_t)r6); result = (uint32_t)r2;
    r6 ^= r7;
    r3 *= r7;
    r0 ^= r4;
    r7 += r6 << 0u;
    r0 *= r7;
    r1 = rotr64(r1, 42);
    r6 ^= 0x000000007f8c0ca4ull;
    r6 *= r7;
    r4 ^= 0xffffffffe9cecc9dull;
    r7 -= r1;
    r1 *= r4;
L418:;
    r2 *= r0;
    r5 = rotr64(r5, 19);
    r7 ^= r3;
    r5 *= r3;
    r6 = rotr64(r6, 2);
    r0 += 0xffffffff9099491full;
    r4 *= r0;
    r1 ^= r7;
    r3 += r7 << 0u;
    r0 = (uint64_t)smulhi64((int64_t)r0, (int64_t)r3); result = (uint32_t)r0;
    r6 += 0x000000002b004455ull;
    r3 *= r5;
    r1 ^= 0xffffffff973f2b4aull;
    r2 += 0xfffffffff84480b3ull;
    r1 *= r2;
    if (be && ((result & 0x48084000u) == 0u)) { be = 0; goto L418; }
    r6 *= r7;
    r7 ^= r4;
    r2 ^= 0x000000004be6e4c0ull;
    r0 = __umul64hi(r0, r2); result = (uint32_t)r0;
    r7 ^= 0x000000006892e471ull;
    r7 *= r4;
    r5 = rotr64(r5, 6);
    r2 += 0xffffffffe12d28b6ull;
    r2 *= r6;
    r4 += r1 << 2u;
    r6 ^= 0x00000000437440e2ull;
    r6 *= r1;
    r1 = rotr64(r1, 63);
    r4 += 0x000000003f36c1a6ull;
    r4 *= r3;
L450:;
    r0 *= r5;
    r1 ^= r3;
    r5 += 0xffffffff8c266526ull;
    r1 *= r2;
    r6 = rotr64(r6, 47);
    r5 ^= r3;
    r5 *= r3;
    r6 ^= 0xffffffff8a6ad7afull;
    r2 = rotr64(r2, 50);
    r6 = (uint64_t)smulhi64((int64_t)r6, (int64_t)r0); result = (uint32_t)r6;
    r2 += r0 << 3u;
    r2 *= r1;
    r1 += r3 << 0u;
    r0 += 0x000000000801bf6cull;
    r0 *= r4;
    if (be && ((result & 0x00003840u) == 0u)) { be = 0; goto L450; }
    r1 *= r3;
    r5 ^= 0x000000005dc48e78ull;
    r7 += 0x000000003bbd0895ull;
    r2 = __umul64hi(r2, r2); result = (uint32_t)r2;
    r7 += r3 << 0u;
    r5 *= r0;
    r6 += r7 << 1u;
    r7 += 0xffffffffb490b225ull;
    r6 *= r7;
    r0 -= r7;
    r1 = rotr64(r1, 43);
    r1 *= r3;
    r4 += 0x000000007e241d1full;
    r7 = rotr64(r7, 62);
    r7 *= r0;
L482:;
    r4 *= r0;
    r5 -= r0;
    r3 ^= r0;
    r5 *= r1;
    r1 += 0xffffffffdf9ab6d2ull;
    r2 ^= 0x0000000042d67d9eull;
    r2 *= r3;
    r6 += 0xffffffffee11679full;
    r7 = rotr64(r7, 8);
    r3 = __umul64hi(r3, r6); result = (uint32_t)r3;
    r7 ^= r6;
    r7 *= r1;
    r5 -= r4;
    r0 ^= r4;
    r1 *= r0;
    if (be && ((result & 0x00824020u) == 0u)) { be = 0; goto L482; }
    r0 *= r6;
    r4 += 0x000000007cf89a4cull;
    r2 += r6 << 3u;
    r3 = (uint64_t)smulhi64((int64_t)r3, (int64_t)r4); result = (uint32_t)r3;
    r5 += 0xffffffff8204be72ull;
    r5 *= r2;
    r1 -= r4;
    r7 ^= 0xffffffffb7a2616full;
    r7 *= r2;
    r0 += 0x00000000587d2808ull;
    r4 += r1 << 0u;
    r0 *= r4;
    r4 -= r6;
    r1 += 0xffffffffc2c70fdbull;

    /* ---- end of generated program ---- */

    uint64_t rf[8];
    rf[0] = r0; rf[1] = r1; rf[2] = r2; rf[3] = r3;
    rf[4] = r4; rf[5] = r5; rf[6] = r6; rf[7] = r7;
    int ok; hx_fin(keys, rf, nonce, difficulty, res, &ok);
}
'''

BENCH = r'''
#include "kernels.cu"
#include "hx_vectors.h"
#include <cstdio>
#include <cstring>
#include <cuda_runtime.h>

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
    printf("CUDA error %s at %d: %s\n", #x, __LINE__, cudaGetErrorString(e_)); \
    return 1; } } while (0)

static void to_dev_prog(const unsigned int src[512][4], uint4 *dst) {
    for (int i = 0; i < 512; i++)
        dst[i] = make_uint4(src[i][0], src[i][1], src[i][2], src[i][3]);
}

static int check(const hx_results *hr, const unsigned long long *exp, const char *who) {
    for (int k = 0; k < 4; k++) {
        unsigned lo = (unsigned)(exp[k] & 0xFFFFFFFFull);
        unsigned hi = (unsigned)(exp[k] >> 32);
        unsigned want0 = __builtin_bswap32(lo), want1 = __builtin_bswap32(hi);
        if (hr->hashes[0][2*k] != want0 || hr->hashes[0][2*k+1] != want1) {
            printf("  %s mismatch word %d: got %08x %08x want %08x %08x\n", who, k,
                   hr->hashes[0][2*k], hr->hashes[0][2*k+1], want0, want1);
            return 1;
        }
    }
    return 0;
}

/* a generic lambda keeps the kernel launch out of a macro: <<<grid, block>>>
   contains commas, which a two argument macro cannot survive */
template <typename F>
static double time_it(const char *name, F launch, uint32_t total, int reps) {
    launch();
    cudaDeviceSynchronize();
    cudaEvent_t a, b;
    cudaEventCreate(&a); cudaEventCreate(&b);
    cudaEventRecord(a);
    for (int r = 0; r < reps; r++) launch();
    cudaEventRecord(b);
    cudaDeviceSynchronize();
    float ms = 0;
    cudaEventElapsedTime(&ms, a, b);
    double rate = (double)total * reps / (ms * 1e3);
    printf("%-8s %8.2f MH/s   (%.1f ms for %.1f M x %d)\n", name, rate, ms,
           total / 1e6, reps);
    return rate;
}

int main() {
    cudaDeviceProp pr;
    CK(cudaGetDeviceProperties(&pr, 0));
    printf("device: %s  sm_%d%d  SMs=%d  ILP=%d\n", pr.name, pr.major, pr.minor,
           pr.multiProcessorCount, HX_ILP);

    hx_keys keys;
    keys.k0 = HX_KEYS[0]; keys.k1 = HX_KEYS[1];
    keys.k2 = HX_KEYS[2]; keys.k3 = HX_KEYS[3];

    uint4 *dprog; CK(cudaMalloc(&dprog, sizeof(uint4) * 512));
    uint4 hprog[512]; to_dev_prog(HX_PROG, hprog);
    CK(cudaMemcpy(dprog, hprog, sizeof hprog, cudaMemcpyHostToDevice));
    CK(cudaMemcpyToSymbol(c_prog, hprog, sizeof hprog));
    uint32_t cs = HX_NINSTR;
    CK(cudaMemcpyToSymbol(c_codesize, &cs, sizeof cs));
    uint32_t d0 = 0;
    CK(cudaMemcpyToSymbol(c_difficulty, &d0, sizeof d0));

    hx_results *dres; CK(cudaMalloc(&dres, sizeof(hx_results)));
    hx_results hr;

    CK(cudaMemset(dres, 0, sizeof(hx_results)));
    hashx_kernel<<<1, 1>>>(keys, dprog, cs, 0, HX_NONCE, 1, dres);
    CK(cudaDeviceSynchronize()); CK(cudaMemcpy(&hr, dres, sizeof hr, cudaMemcpyDeviceToHost));
    int b1 = check(&hr, HX_EXPECT, "shipped");

    CK(cudaMemset(dres, 0, sizeof(hx_results)));
    hashx_opt_kernel<<<1, 1>>>(keys, dprog, cs, 0, HX_NONCE, HX_ILP, dres);
    CK(cudaDeviceSynchronize()); CK(cudaMemcpy(&hr, dres, sizeof hr, cudaMemcpyDeviceToHost));
    int b2 = check(&hr, HX_EXPECT, "opt");

    CK(cudaMemset(dres, 0, sizeof(hx_results)));
    hashx_jit_kernel<<<1, 1>>>(keys, dprog, cs, 0, HX_NONCE, 1, dres);
    CK(cudaDeviceSynchronize()); CK(cudaMemcpy(&hr, dres, sizeof hr, cudaMemcpyDeviceToHost));
    int b3 = check(&hr, HX_EXPECT, "jit");

    printf("correctness vs repo vector nonce %u: shipped %s, opt %s, jit %s\n", HX_NONCE,
           b1 ? "MISMATCH" : "ok", b2 ? "MISMATCH" : "ok", b3 ? "MISMATCH" : "ok");
    if (b1 || b2 || b3) return 1;

    uint32_t diff = 40;
    CK(cudaMemcpyToSymbol(c_difficulty, &diff, sizeof diff));
    uint32_t total = 1u << 23;
    int reps = 3;
    double s, o, j, rate;
    const int block = 128;
    int grid1 = (int)((total + block - 1) / block);
    int gridILP = (int)((total + block * HX_ILP - 1) / (block * HX_ILP));

    printf("\n=== sm_75, %u nonces x %d reps ===\n", total, reps);
    double s_rate = time_it("shipped", [&]{
        hashx_kernel<<<grid1, block>>>(keys, dprog, cs, diff, 0, total, dres); }, total, reps);
    double o_rate = time_it("opt", [&]{
        hashx_opt_kernel<<<gridILP, block>>>(keys, dprog, cs, diff, 0, total, dres); }, total, reps);
    double j_rate = time_it("jit", [&]{
        hashx_jit_kernel<<<grid1, block>>>(keys, dprog, cs, diff, 0, total, dres); }, total, reps);
    printf("\nvs shipped: opt %.2fx   jit %.2fx\n", o_rate / s_rate, j_rate / s_rate);
    printf("\n{\"device\": \"%s\", \"ilp\": %d, \"shipped_mhps\": %.2f, \"opt_mhps\": %.2f, "
           "\"jit_mhps\": %.2f, \"opt_speedup\": %.2f, \"jit_speedup\": %.2f, \"correct\": true}\n",
           pr.name, HX_ILP, s_rate, o_rate, j_rate, o_rate / s_rate, j_rate / s_rate);
    return 0;
}
'''

VECTORS = r'''#define HX_NINSTR 512
#define HX_NONCE  0u
static const unsigned long long HX_KEYS[4] = {10447330192400380064ull,4205750205684054173ull,16401796433918044409ull,13433881464282511545ull};
static const unsigned long long HX_EXPECT[4] = {319452427573024566ull,10590817332978460974ull,10661166129852722012ull,16401444840753615679ull};
static const unsigned int HX_PROG[512][4] = {
{2,5,1,0},
{9,4294967295,4294967295,0},
{2,1,0,0},
{6,6,4294967295,27},
{8,4,4294967295,1751281595},
{2,7,2,0},
{8,0,4294967295,2580751660},
{3,3,4,0},
{2,4,3,0},
{6,2,4294967295,18},
{4,0,3,0},
{0,1,0,0},
{8,5,4294967295,4258446168},
{2,5,3,0},
{7,3,4294967295,3982911447},
{3,0,6,0},
{2,3,0,0},
{10,4294967295,4294967295,16778260},
{2,2,0,0},
{7,6,4294967295,1863127121},
{8,0,4294967295,3730299647},
{0,7,7,0},
{7,4,4294967295,654495767},
{2,1,3,0},
{3,0,3,0},
{7,3,4294967295,2747056664},
{2,3,2,0},
{5,4,0,0},
{7,5,4294967295,1055424290},
{2,4,0,0},
{4,2,6,0},
{6,6,4294967295,59},
{2,2,5,0},
{9,4294967295,4294967295,0},
{2,0,6,0},
{4,1,5,0},
{5,6,7,2},
{2,5,6,0},
{7,1,4294967295,3966211169},
{6,6,4294967295,54},
{2,7,1,0},
{3,1,3,0},
{7,2,4294967295,198142531},
{1,1,2,0},
{6,3,4294967295,59},
{2,2,3,0},
{7,3,4294967295,2920381442},
{8,6,4294967295,1463313979},
{2,3,0,0},
{10,4294967295,4294967295,2151678978},
{2,4,7,0},
{4,7,5,0},
{3,6,5,0},
{1,1,7,0},
{3,2,5,0},
{2,6,3,0},
{7,7,4294967295,3988596700},
{6,3,4294967295,52},
{2,3,2,0},
{8,7,4294967295,1912777775},
{4,4,5,0},
{2,4,0,0},
{8,2,4294967295,3388461475},
{7,5,4294967295,781398143},
{2,7,0,0},
{9,4294967295,4294967295,0},
{2,5,6,0},
{3,1,2,0},
{4,6,3,0},
{2,6,3,0},
{6,3,4294967295,21},
{5,4,1,1},
{2,3,4,0},
{7,7,4294967295,1381856880},
{8,4,4294967295,3990055894},
{0,0,0,0},
{8,7,4294967295,2484864949},
{2,7,4,0},
{5,4,1,0},
{8,6,4294967295,1827544843},
{2,4,6,0},
{10,4294967295,4294967295,67649538},
{2,2,6,0},
{8,5,4294967295,4277787391},
{7,3,4294967295,2310654421},
{1,5,5,0},
{8,7,4294967295,694074071},
{2,3,0,0},
{4,0,1,0},
{8,1,4294967295,12617265},
{2,7,0,0},
{5,4,2,0},
{8,0,4294967295,708010653},
{2,4,6,0},
{8,2,4294967295,3356939291},
{3,6,1,0},
{2,6,5,0},
{9,4294967295,4294967295,0},
{2,0,1,0},
{4,2,5,0},
{6,3,4294967295,31},
{2,3,4,0},
{6,1,4294967295,38},
{8,2,4294967295,2830295958},
{2,5,7,0},
{7,2,4294967295,1345059628},
{8,1,4294967295,1599253480},
{0,6,4,0},
{6,7,4294967295,32},
{2,7,2,0},
{3,0,1,0},
{8,4,4294967295,623074213},
{2,2,4,0},
{10,4294967295,4294967295,2621476},
{2,1,4,0},
{8,5,4294967295,2954063944},
{4,4,3,0},
{0,3,6,0},
{6,0,4294967295,52},
{2,4,0,0},
{7,2,4294967295,2282296621},
{3,5,6,0},
{2,5,0,0},
{8,1,4294967295,2093725009},
{7,6,4294967295,1815557957},
{2,2,1,0},
{5,7,1,2},
{8,0,4294967295,2706198277},
{2,1,0,0},
{9,4294967295,4294967295,0},
{2,7,0,0},
{7,5,4294967295,1794000590},
{8,6,4294967295,2462628604},
{2,0,5,0},
{7,3,4294967295,434259919},
{4,5,2,0},
{2,3,5,0},
{8,1,4294967295,3541237569},
{4,2,5,0},
{0,7,6,0},
{3,6,4,0},
{2,2,1,0},
{5,1,4,0},
{8,5,4294967295,2062561606},
{2,6,3,0},
{10,4294967295,4294967295,16785425},
{2,5,1,0},
{7,0,4294967295,2601593873},
{5,3,4,1},
{0,3,4,0},
{4,1,2,0},
{2,0,7,0},
{8,1,4294967295,2273154849},
{6,4,4294967295,38},
{2,4,7,0},
{5,6,5,3},
{8,2,4294967295,1602166442},
{2,1,6,0},
{6,5,4294967295,42},
{5,2,7,3},
{2,2,5,0},
{9,4294967295,4294967295,0},
{2,6,3,0},
{8,7,4294967295,4267835575},
{6,0,4294967295,25},
{2,5,4,0},
{7,3,4294967295,1390258803},
{8,0,4294967295,88753033},
{2,7,1,0},
{5,0,1,2},
{7,2,4294967295,3016191709},
{0,0,0,0},
{4,4,6,0},
{2,3,2,0},
{8,2,4294967295,1880678822},
{7,6,4294967295,2930655537},
{2,6,2,0},
{10,4294967295,4294967295,11535360},
{2,4,1,0},
{5,2,1,0},
{8,7,4294967295,2642050846},
{0,5,3,0},
{4,1,3,0},
{2,0,3,0},
{5,3,1,3},
{6,1,4294967295,45},
{2,2,1,0},
{4,7,1,0},
{7,1,4294967295,1142891499},
{2,3,6,0},
{6,6,4294967295,14},
{7,4,4294967295,778194346},
{2,6,5,0},
{9,4294967295,4294967295,0},
{2,1,5,0},
{4,4,2,0},
{6,0,4294967295,40},
{2,7,3,0},
{8,2,4294967295,2659648804},
{3,3,5,0},
{2,2,4,0},
{7,6,4294967295,331690670},
{6,3,4294967295,25},
{1,0,6,0},
{8,5,4294967295,2108554763},
{2,3,6,0},
{7,1,4294967295,953685268},
{8,7,4294967295,3896235292},
{2,6,2,0},
{10,4294967295,4294967295,2130052},
{2,1,7,0},
{8,2,4294967295,1164413288},
{6,4,4294967295,32},
{0,7,7,0},
{6,3,4294967295,22},
{2,0,4,0},
{7,2,4294967295,1036899541},
{4,3,4,0},
{2,2,6,0},
{7,4,4294967295,649860411},
{5,3,1,1},
{2,3,1,0},
{3,5,1,0},
{4,6,1,0},
{2,5,7,0},
{9,4294967295,4294967295,0},
{2,4,7,0},
{8,7,4294967295,1285475679},
{7,2,4294967295,3990846286},
{2,7,3,0},
{8,3,4294967295,3726162848},
{6,2,4294967295,42},
{2,3,0,0},
{6,0,4294967295,58},
{3,5,1,0},
{1,5,6,0},
{8,6,4294967295,1002782550},
{2,6,0,0},
{6,4,4294967295,55},
{7,7,4294967295,1279390843},
{2,0,7,0},
{10,4294967295,4294967295,527376},
{2,4,7,0},
{4,2,7,0},
{6,7,4294967295,59},
{0,2,3,0},
{6,1,4294967295,52},
{2,1,5,0},
{3,0,6,0},
{4,5,7,0},
{2,0,5,0},
{8,7,4294967295,1325995331},
{7,3,4294967295,198806093},
{2,3,4,0},
{3,5,6,0},
{7,6,4294967295,2804703845},
{2,5,6,0},
{9,4294967295,4294967295,0},
{2,2,1,0},
{8,0,4294967295,1109859257},
{4,4,1,0},
{2,0,6,0},
{8,3,4294967295,4164856012},
{7,7,4294967295,3534543804},
{2,7,6,0},
{4,6,4,0},
{7,5,4294967295,3511285918},
{1,5,3,0},
{8,2,4294967295,2091798250},
{2,3,1,0},
{4,2,1,0},
{7,1,4294967295,3793950404},
{2,4,0,0},
{10,4294967295,4294967295,135267392},
{2,2,6,0},
{6,1,4294967295,12},
{4,7,6,0},
{0,6,6,0},
{6,5,4294967295,54},
{2,1,7,0},
{7,7,4294967295,1783681061},
{5,3,4,0},
{2,3,5,0},
{6,7,4294967295,48},
{5,4,2,1},
{2,5,7,0},
{8,7,4294967295,1436636998},
{4,0,4,0},
{2,0,7,0},
{9,4294967295,4294967295,0},
{2,7,1,0},
{6,6,4294967295,50},
{8,2,4294967295,1016205335},
{2,2,4,0},
{4,1,5,0},
{3,6,5,0},
{2,1,0,0},
{7,3,4294967295,3788283602},
{6,5,4294967295,61},
{1,0,6,0},
{8,6,4294967295,1831088369},
{2,5,7,0},
{3,3,6,0},
{8,4,4294967295,3333387155},
{2,4,7,0},
{10,4294967295,4294967295,34305},
{2,3,2,0},
{7,6,4294967295,3201555494},
{5,2,1,1},
{0,7,1,0},
{7,1,4294967295,1916757387},
{2,1,0,0},
{8,6,4294967295,3245940153},
{7,0,4294967295,1685547031},
{2,2,0,0},
{7,3,4294967295,3348825237},
{6,4,4294967295,25},
{2,6,4,0},
{7,4,4294967295,2268227598},
{3,3,5,0},
{2,0,3,0},
{9,4294967295,4294967295,0},
{2,4,2,0},
{7,2,4294967295,2397487746},
{8,5,4294967295,1033256197},
{2,5,3,0},
{4,1,2,0},
{7,6,4294967295,4236063140},
{2,7,2,0},
{8,2,4294967295,366434199},
{4,1,3,0},
{0,2,0,0},
{8,0,4294967295,57697221},
{2,3,5,0},
{8,5,4294967295,2255915699},
{7,0,4294967295,1808917894},
{2,1,6,0},
{10,4294967295,4294967295,1090523648},
{2,5,7,0},
{8,6,4294967295,4205247102},
{5,4,7,2},
{1,6,3,0},
{3,0,4,0},
{2,2,0,0},
{3,0,7,0},
{4,3,7,0},
{2,4,3,0},
{3,5,7,0},
{8,3,4294967295,2588219492},
{2,5,3,0},
{7,0,4294967295,1823987005},
{4,1,3,0},
{2,1,3,0},
{9,4294967295,4294967295,0},
{2,3,6,0},
{7,6,4294967295,561566489},
{6,0,4294967295,42},
{2,6,4,0},
{5,0,2,3},
{7,5,4294967295,1419414701},
{2,5,7,0},
{3,4,1,0},
{4,2,7,0},
{0,4,4,0},
{8,1,4294967295,627496709},
{2,1,7,0},
{6,6,4294967295,32},
{8,7,4294967295,3931491559},
{2,2,3,0},
{10,4294967295,4294967295,2147525632},
{2,0,6,0},
{6,5,4294967295,44},
{5,7,3,0},
{0,1,4,0},
{4,6,5,0},
{2,7,2,0},
{8,4,4294967295,2670846273},
{7,3,4294967295,3447611614},
{2,6,2,0},
{8,3,4294967295,2639188389},
{4,5,0,0},
{2,4,0,0},
{3,3,0,0},
{6,2,4294967295,15},
{2,2,1,0},
{9,4294967295,4294967295,0},
{2,5,1,0},
{4,6,0,0},
{8,7,4294967295,91672888},
{2,7,1,0},
{6,4,4294967295,11},
{3,1,3,0},
{2,4,0,0},
{3,0,1,0},
{7,6,4294967295,2101762942},
{1,6,1,0},
{5,2,5,0},
{2,2,7,0},
{6,7,4294967295,43},
{8,5,4294967295,311595550},
{2,1,7,0},
{10,4294967295,4294967295,557842464},
{2,5,0,0},
{3,0,4,0},
{6,3,4294967295,50},
{1,2,6,0},
{4,6,7,0},
{2,3,7,0},
{4,0,4,0},
{5,7,6,0},
{2,0,7,0},
{6,1,4294967295,42},
{8,6,4294967295,2139884708},
{2,6,7,0},
{8,4,4294967295,3922644125},
{3,7,1,0},
{2,1,4,0},
{9,4294967295,4294967295,0},
{2,2,0,0},
{6,5,4294967295,19},
{4,7,3,0},
{2,5,3,0},
{6,6,4294967295,2},
{7,0,4294967295,2425964831},
{2,4,0,0},
{4,1,7,0},
{5,3,7,0},
{1,0,3,0},
{7,6,4294967295,721437781},
{2,3,5,0},
{8,1,4294967295,2537499466},
{7,2,4294967295,4165238963},
{2,1,2,0},
{10,4294967295,4294967295,1208500224},
{2,6,7,0},
{4,7,4,0},
{8,2,4294967295,1273423040},
{0,0,2,0},
{8,7,4294967295,1754457201},
{2,7,4,0},
{6,5,4294967295,6},
{7,2,4294967295,3777833142},
{2,2,6,0},
{5,4,1,2},
{8,6,4294967295,1131692258},
{2,6,1,0},
{6,1,4294967295,63},
{7,4,4294967295,1060553126},
{2,4,3,0},
{9,4294967295,4294967295,0},
{2,0,5,0},
{4,1,3,0},
{7,5,4294967295,2351326502},
{2,1,2,0},
{6,6,4294967295,47},
{4,5,3,0},
{2,5,3,0},
{8,6,4294967295,2322257839},
{6,2,4294967295,50},
{1,6,0,0},
{5,2,0,3},
{2,2,1,0},
{5,1,3,0},
{7,0,4294967295,134332268},
{2,0,4,0},
{10,4294967295,4294967295,14400},
{2,1,3,0},
{8,5,4294967295,1573162616},
{7,7,4294967295,1002244245},
{0,2,2,0},
{5,7,3,0},
{2,5,0,0},
{5,6,7,1},
{7,7,4294967295,3029381669},
{2,6,7,0},
{3,0,7,0},
{6,1,4294967295,43},
{2,1,3,0},
{7,4,4294967295,2116295967},
{6,7,4294967295,62},
{2,7,0,0},
{9,4294967295,4294967295,0},
{2,4,0,0},
{3,5,0,0},
{4,3,0,0},
{2,5,1,0},
{7,1,4294967295,3751458514},
{8,2,4294967295,1121353118},
{2,2,3,0},
{7,6,4294967295,3994118047},
{6,7,4294967295,8},
{0,3,6,0},
{4,7,6,0},
{2,7,1,0},
{3,5,4,0},
{4,0,4,0},
{2,1,0,0},
{10,4294967295,4294967295,8536096},
{2,0,6,0},
{7,4,4294967295,2096667212},
{5,2,6,3},
{1,3,4,0},
{7,5,4294967295,2181348978},
{2,5,2,0},
{3,1,4,0},
{8,7,4294967295,3080872303},
{2,7,2,0},
{7,0,4294967295,1484597256},
{5,4,1,0},
{2,0,4,0},
{3,4,6,0},
{7,1,4294967295,3267825627},
};
'''


import os, re, subprocess

def sh(cmd, cwd=None):
    r = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    return r.stdout + r.stderr

os.chdir("/kaggle/working")
os.makedirs("out", exist_ok=True)
open("kernels.cu", "w").write(KERNELS)
open("bench.cu", "w").write(BENCH)
open("hx_vectors.h", "w").write(VECTORS)

print("=== BUILD v2 ===")
print("=== host ===")
print(sh("nvidia-smi --query-gpu=name,compute_cap --format=csv,noheader"))
print(sh("nvcc --version | tail -2"))

print("=== compile sm_75: registers / local memory ===")
print(sh("nvcc -arch=sm_75 -O3 -cubin -Xptxas -v -o out/hx.cubin kernels.cu 2>&1"))

sass = sh("nvdisasm -c out/hx.cubin")
open("out/nvdisasm_all.sass", "w").write(sass)
parts = re.split(r"(?m)^\s*\.section\s+\.text\.", sass)
for part in parts[1:]:
    name = part.split(",")[0].strip()
    body = ".section .text." + part
    tag = "opt" if "opt" in name else ("jit" if "jit" in name else "")
    fn = "out/nvidiaT4_hashx%s.sass" % (("_" + tag) if tag else "")
    open(fn, "w").write("// sm_75 (Tesla T4) SASS for " + name + "\n" + body)
    print("wrote", fn, len(body.splitlines()), "lines,", name)
    for pat in ("LDL", "STL", "LDG"):
        print("   %s: %d" % (pat, len(re.findall(r"\b%s" % pat, body))))

for ilp in (1, 2, 4):
    print("--- build ILP", ilp, "---")
    print(sh("nvcc -arch=sm_75 -O3 -DOPT_ILP=%d -o out/bench%d bench.cu -Xptxas -v 2>&1 | "
             "grep -E 'Used|spill|stack' | head -6" % (ilp, ilp)))

runs = []
for ilp in (1, 2, 4):
    r = sh("out/bench%d" % ilp)
    runs.append(r)
    print("--- run ILP %d ---" % ilp)
    print(r)
open("out/bench.log", "w").write("\n".join(runs))
