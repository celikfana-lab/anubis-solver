/*
 * sha256_pow.cl — OpenCL C kernel for the portable OpenCL backend.
 *
 * One work-item per candidate nonce, like the Level Zero kernel of the same
 * name, but the prefix no longer has to be a whole number of 64-byte blocks:
 * the state after the whole blocks comes in `mid`, and the leftover bytes
 * (Anubis's randomData is 32 bytes, so this is the normal case) come in
 * `pre[0..pre_len)`. The tail block is then
 *
 *   pre || nonce || 0x80 || bit length
 *
 * which is the same message the scalar verifier hashes.
 *
 *   mode 0 (fast/slow):  message = prefix || decimal(nonce)
 *   mode 1 (sha256):     message = prefix || u32 nonce [le|be]
 *
 * Embedded in src/opencl/opencl_kernels.h by tools/embed_opencl_kernels.py.
 * Keep it separate from the Level Zero kernel: that one ships as precompiled
 * SPIR-V, so changing its params layout would invalidate the blob.
 */

typedef struct {
    uint mid[8];
    uint prefix_len;
    uint mode;
    uint use_le;
    uint difficulty;
    uint check_bits;
    uint base_nonce;
    uint chunk;
    uint pre_len;          /* leftover prefix bytes, 0..63 */
    uchar pre[64];         /* ...and the bytes themselves */
} l0_params;

typedef struct {
    uint count;
    uint pad[3];
    uint nonces[8];
    uint hashes[8][8];
} l0_results;

__constant uint K[64] = {
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

inline uint rotr32(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

inline uint load_be32(__private const uchar *p) {
    return ((uint)p[0] << 24) | ((uint)p[1] << 16) | ((uint)p[2] << 8) |
           (uint)p[3];
}

inline int dec_u64(ulong v, __private uchar *out) {
    uchar tmp[24];
    int n = 0;
    if (v == 0) {
        out[0] = '0';
        return 1;
    }
    while (v > 0 && n < 24) {
        tmp[n++] = (uchar)('0' + (uint)(v % 10ul));
        v /= 10ul;
    }
    for (int i = 0; i < n; i++) {
        out[i] = tmp[n - 1 - i];
    }
    return n;
}

__kernel void sha256_pow(__global const l0_params *p, __global l0_results *res) {
    uint gid = get_global_id(0);
    if (gid >= p->chunk) {
        return;
    }
    ulong nonce = (ulong)p->base_nonce + (ulong)gid;
    uchar blk[64];
    uint dlen;

    uint off = p->pre_len;

    for (int i = 0; i < 64; i++) {
        blk[i] = 0;
    }
    for (uint i = 0; i < off; i++) {
        blk[i] = p->pre[i];
    }
    if (p->mode == 0) {
        dlen = (uint)dec_u64(nonce, blk + off);
    } else {
        uint v = (uint)nonce;
        if (p->use_le != 0) {
            blk[off + 0] = (uchar)v;
            blk[off + 1] = (uchar)(v >> 8);
            blk[off + 2] = (uchar)(v >> 16);
            blk[off + 3] = (uchar)(v >> 24);
        } else {
            blk[off + 0] = (uchar)(v >> 24);
            blk[off + 1] = (uchar)(v >> 16);
            blk[off + 2] = (uchar)(v >> 8);
            blk[off + 3] = (uchar)v;
        }
        dlen = 4;
    }
    blk[off + dlen] = 0x80;
    ulong bits = ((ulong)p->prefix_len + (ulong)dlen) * 8ul;
    for (int i = 0; i < 8; i++) {
        blk[56 + i] = (uchar)(bits >> (8 * (7 - i)));
    }

    uint w[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        w[i] = load_be32(blk + 4 * i);
    }

    uint a = p->mid[0], b = p->mid[1], c = p->mid[2], d = p->mid[3];
    uint e = p->mid[4], f = p->mid[5], g = p->mid[6], h = p->mid[7];

    #pragma unroll
    for (uint i = 0; i < 64; i++) {
        if (i >= 16) {
            uint j = i & 15u;
            uint x = w[(i + 1u) & 15u];
            uint y = w[(i + 14u) & 15u];
            uint s0 = rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
            uint s1 = rotr32(y, 17) ^ rotr32(y, 19) ^ (y >> 10);
            w[j] = w[j] + s0 + w[(i + 9u) & 15u] + s1;
        }
        uint s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint ch = (e & f) ^ ((~e) & g);
        uint t1 = h + s1 + ch + K[i] + w[i & 15u];
        uint s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    uint out[8];
    out[0] = p->mid[0] + a; out[1] = p->mid[1] + b;
    out[2] = p->mid[2] + c; out[3] = p->mid[3] + d;
    out[4] = p->mid[4] + e; out[5] = p->mid[5] + f;
    out[6] = p->mid[6] + g; out[7] = p->mid[7] + h;

    uchar dg[32];
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        dg[4 * i + 0] = (uchar)(out[i] >> 24);
        dg[4 * i + 1] = (uchar)(out[i] >> 16);
        dg[4 * i + 2] = (uchar)(out[i] >> 8);
        dg[4 * i + 3] = (uchar)out[i];
    }

    int ok = 1;
    if (p->check_bits == 0) {
        uint full = p->difficulty / 2u;
        for (uint i = 0; i < full && ok; i++) {
            ok = dg[i] == 0;
        }
        if (ok && ((p->difficulty & 1u) != 0)) {
            ok = (dg[full] >> 4) == 0;
        }
    } else {
        uint full = p->difficulty / 8u;
        uint rem = p->difficulty % 8u;
        for (uint i = 0; i < full && ok; i++) {
            ok = dg[i] == 0;
        }
        if (ok && rem != 0) {
            ok = (dg[full] & (uchar)(0xFFu << (8u - rem))) == 0;
        }
    }
    if (ok) {
        uint slot = atomic_inc(&res->count);
        if (slot < 8u) {
            res->nonces[slot] = (uint)nonce;
            for (int i = 0; i < 8; i++) {
                res->hashes[slot][i] = out[i];
            }
        }
    }
}
