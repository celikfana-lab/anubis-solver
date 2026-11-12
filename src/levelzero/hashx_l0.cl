/*
 * hashx_l0.cl — OpenCL C HashX kernel for the oneAPI Level Zero backend.
 *
 * One work-item per candidate nonce: expand the 512-bit register file from
 * the SipHash key + nonce, interpret the HashX program, finalize, check the
 * leading zero bits and append hits. Mirrors src/cuda_hashx.cu.
 */

#define HX_MAX_INSTR 512

typedef struct {
    uint count;
    uint pad[3];
    uint nonces[8];
    uint hashes[8][8];
} hx_results;

static inline ulong rotl64(ulong x, int n) {
    return (x << n) | (x >> (64 - n));
}

static inline ulong rotr64(ulong x, int n) {
    return (x >> n) | (x << (64 - n));
}

#define SIPROUND(v0, v1, v2, v3)                                              \
    do {                                                                      \
        v0 += v1; v2 += v3; v1 = rotl64(v1, 13);                              \
        v3 = rotl64(v3, 16); v1 ^= v0; v3 ^= v2;                              \
        v0 = rotl64(v0, 32); v2 += v1; v0 += v3;                              \
        v1 = rotl64(v1, 17); v3 = rotl64(v3, 21);                             \
        v1 ^= v2; v3 ^= v0; v2 = rotl64(v2, 32);                              \
    } while (0)

__kernel void hashx_pow(__global const uint4 *prog, uint code_size, ulong k0,
                        ulong k1, ulong k2, ulong k3, uint difficulty,
                        uint base, uint count, __global hx_results *res) {
    uint idx = get_global_id(0);
    ulong r[8];
    ulong v0, v1, v2, v3;
    int target = 0;
    int be = 1;
    uint result = 0;
    int i;
    ulong w[4];
    uchar dg[32];
    int ok = 1;
    uint nonce;

    if (idx >= count) {
        return;
    }
    nonce = base + idx;
    v0 = k0;
    v1 = k1;
    v2 = k2;
    v3 = k3;
    v1 ^= 0xeeUL;
    v3 ^= (ulong)nonce;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    v0 ^= (ulong)nonce;
    v2 ^= 0xeeUL;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    r[0] = v0;
    r[1] = v1;
    r[2] = v2;
    r[3] = v3;
    v1 ^= 0xddUL;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);
    r[4] = v0;
    r[5] = v1;
    r[6] = v2;
    r[7] = v3;

    i = 0;
    while (i < (int)code_size) {
        uint4 in = prog[i];
        uint op = in.x;
        uint dst = in.y;
        uint src = in.z;
        uint imm = in.w;
        switch (op) {
        case 0: /* UMULH_R */
            r[dst] = mul_hi(r[dst], r[src]);
            result = (uint)r[dst];
            break;
        case 1: /* SMULH_R */
            r[dst] = (ulong)mul_hi((long)r[dst], (long)r[src]);
            result = (uint)r[dst];
            break;
        case 2: r[dst] *= r[src]; break;
        case 3: r[dst] -= r[src]; break;
        case 4: r[dst] ^= r[src]; break;
        case 5: r[dst] += r[src] << (imm & 63u); break;
        case 6: r[dst] = rotr64(r[dst], (int)(imm & 63u)); break;
        case 7: r[dst] += (ulong)(long)(int)imm; break;
        case 8: r[dst] ^= (ulong)(long)(int)imm; break;
        case 9: target = i; break;
        case 10:
            if (be && (result & imm) == 0u) {
                i = target;
                be = 0;
            }
            break;
        default: break;
        }
        i++;
    }

    r[0] += k0;
    r[1] += k1;
    r[6] += k2;
    r[7] += k3;
    v0 = r[0];
    v1 = r[1];
    v2 = r[2];
    v3 = r[3];
    SIPROUND(v0, v1, v2, v3);
    r[0] = v0;
    r[1] = v1;
    r[2] = v2;
    r[3] = v3;
    v0 = r[4];
    v1 = r[5];
    v2 = r[6];
    v3 = r[7];
    SIPROUND(v0, v1, v2, v3);
    r[4] = v0;
    r[5] = v1;
    r[6] = v2;
    r[7] = v3;
    w[0] = r[0] ^ r[4];
    w[1] = r[1] ^ r[5];
    w[2] = r[2] ^ r[6];
    w[3] = r[3] ^ r[7];
    for (i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            dg[8 * i + j] = (uchar)(w[i] >> (8 * j));
        }
    }
    for (uint b = 0; b < difficulty; b++) {
        if (((dg[b >> 3] >> (7u - (b & 7u))) & 1u) != 0u) {
            ok = 0;
            break;
        }
    }
    if (ok) {
        uint slot = atomic_inc(&res->count);
        if (slot < 8u) {
            res->nonces[slot] = nonce;
            for (i = 0; i < 8; i++) {
                res->hashes[slot][i] = ((uint)dg[4 * i] << 24) |
                                       ((uint)dg[4 * i + 1] << 16) |
                                       ((uint)dg[4 * i + 2] << 8) |
                                       (uint)dg[4 * i + 3];
            }
        }
    }
}
