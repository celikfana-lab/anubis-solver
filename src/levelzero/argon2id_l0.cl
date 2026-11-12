/*
 * argon2id_l0.cl — OpenCL C Argon2id kernel for the oneAPI Level Zero backend.
 *
 * One work-group per candidate nonce (64 work-items): the 1 KiB Argon2 block
 * lives in local memory and the work-items cooperate on the BlaMka
 * permutation, while the 19 MiB matrix stays in global memory. Thread 0 does
 * the BLAKE2b work (H0, H', final tag).
 *
 * Compiled to SPIR-V 1.2 by tools/build_l0_argon2.sh.
 */

#define A2_M 19456u
#define A2_T 2u
#define WG 32u

__constant ulong c_iv[8] = {
    0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL,
    0xa54ff53a5f1d36f1UL, 0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
    0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
};

__constant uchar c_sigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
};

__constant uchar c_perm[8][4] = {
    {0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15},
    {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}
};

static inline ulong rotr64(ulong x, int n) {
    return (x >> n) | (x << (64 - n));
}

static inline void b2g(ulong *a, ulong *b, ulong *c, ulong *d, ulong x,
                       ulong y) {
    *a = *a + *b + x;
    *d = rotr64(*d ^ *a, 32);
    *c = *c + *d;
    *b = rotr64(*b ^ *c, 24);
    *a = *a + *b + y;
    *d = rotr64(*d ^ *a, 16);
    *c = *c + *d;
    *b = rotr64(*b ^ *c, 63);
}

static inline void b2_compress(ulong h[8], const ulong m[16], ulong t,
                               int last) {
    ulong v[16];
    for (int i = 0; i < 8; i++) {
        v[i] = h[i];
    }
    for (int i = 0; i < 8; i++) {
        v[8 + i] = c_iv[i];
    }
    v[12] ^= t;
    if (last) {
        v[14] = ~v[14];
    }
    for (int r = 0; r < 12; r++) {
        const __constant uchar *s = c_sigma[r];
        b2g(&v[0], &v[4], &v[8], &v[12], m[s[0]], m[s[1]]);
        b2g(&v[1], &v[5], &v[9], &v[13], m[s[2]], m[s[3]]);
        b2g(&v[2], &v[6], &v[10], &v[14], m[s[4]], m[s[5]]);
        b2g(&v[3], &v[7], &v[11], &v[15], m[s[6]], m[s[7]]);
        b2g(&v[0], &v[5], &v[10], &v[15], m[s[8]], m[s[9]]);
        b2g(&v[1], &v[6], &v[11], &v[12], m[s[10]], m[s[11]]);
        b2g(&v[2], &v[7], &v[8], &v[13], m[s[12]], m[s[13]]);
        b2g(&v[3], &v[4], &v[9], &v[14], m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) {
        h[i] ^= v[i] ^ v[8 + i];
    }
}

/* BLAKE2b over a local-memory buffer. */
static inline void b2_hash(const __local uchar *data, uint len, uint outlen,
                           ulong h[8]) {
    ulong m[16];
    uint off = 0;
    int i;

    for (i = 0; i < 8; i++) {
        h[i] = c_iv[i];
    }
    h[0] ^= 0x01010000UL ^ outlen;

    while (len - off > 128u) {
        for (i = 0; i < 16; i++) {
            ulong w = 0;
            for (int j = 0; j < 8; j++) {
                w |= (ulong)data[off + 8 * i + j] << (8 * j);
            }
            m[i] = w;
        }
        off += 128u;
        b2_compress(h, m, off, 0);
    }
    {
        uchar blk[128];
        uint rem = len - off;
        for (i = 0; i < 128; i++) {
            blk[i] = (i < (int)rem) ? data[off + i] : (uchar)0;
        }
        for (i = 0; i < 16; i++) {
            ulong w = 0;
            for (int j = 0; j < 8; j++) {
                w |= (ulong)blk[8 * i + j] << (8 * j);
            }
            m[i] = w;
        }
        b2_compress(h, m, len, 1);
    }
}

static inline ulong blamka(ulong x, ulong y) {
    return x + y + 2UL * (x & 0xFFFFFFFFUL) * (y & 0xFFFFFFFFUL);
}

static inline void a2g(ulong *a, ulong *b, ulong *c, ulong *d) {
    *a = blamka(*a, *b);
    *d = rotr64(*d ^ *a, 32);
    *c = blamka(*c, *d);
    *b = rotr64(*b ^ *c, 24);
    *a = blamka(*a, *b);
    *d = rotr64(*d ^ *a, 16);
    *c = blamka(*c, *d);
    *b = rotr64(*b ^ *c, 63);
}

static inline void fill_block(__global ulong *mem, uint dst, uint prev,
                              uint ref, int with_xor, __local ulong *sR,
                              uint tid) {
    const uint g = tid >> 2;
    const uint gi = tid & 3u;
    __global ulong *p = mem + (ulong)prev * 128u;
    __global ulong *r = mem + (ulong)ref * 128u;
    __global ulong *d = mem + (ulong)dst * 128u;
    const uchar off[16] = {0, 1, 16, 17, 32, 33, 48, 49,
                           64, 65, 80, 81, 96, 97, 112, 113};

    for (int i = tid; i < 128; i += WG) {
        sR[i] = p[i] ^ r[i];
    }
    barrier(CLK_LOCAL_MEM_FENCE | CLK_GLOBAL_MEM_FENCE);

    for (int ph = 0; ph < 2; ph++) {
        {
            uint idx = gi + (uint)(ph ? 4 : 0);
            uint base = g * 16u;
            ulong a = sR[base + c_perm[idx][0]];
            ulong b = sR[base + c_perm[idx][1]];
            ulong c = sR[base + c_perm[idx][2]];
            ulong dd = sR[base + c_perm[idx][3]];
            a2g(&a, &b, &c, &dd);
            sR[base + c_perm[idx][0]] = a;
            sR[base + c_perm[idx][1]] = b;
            sR[base + c_perm[idx][2]] = c;
            sR[base + c_perm[idx][3]] = dd;
        }
        barrier(CLK_LOCAL_MEM_FENCE | CLK_GLOBAL_MEM_FENCE);
    }

    for (int ph = 0; ph < 2; ph++) {
        {
            uint idx = gi + (uint)(ph ? 4 : 0);
            uint base = 2u * g;
            ulong a = sR[base + off[c_perm[idx][0]]];
            ulong b = sR[base + off[c_perm[idx][1]]];
            ulong c = sR[base + off[c_perm[idx][2]]];
            ulong dd = sR[base + off[c_perm[idx][3]]];
            a2g(&a, &b, &c, &dd);
            sR[base + off[c_perm[idx][0]]] = a;
            sR[base + off[c_perm[idx][1]]] = b;
            sR[base + off[c_perm[idx][2]]] = c;
            sR[base + off[c_perm[idx][3]]] = dd;
        }
        barrier(CLK_LOCAL_MEM_FENCE | CLK_GLOBAL_MEM_FENCE);
    }

    for (int i = tid; i < 128; i += WG) {
        ulong v = sR[i] ^ p[i] ^ r[i];
        if (with_xor) {
            v ^= d[i];
        }
        d[i] = v;
    }
    barrier(CLK_LOCAL_MEM_FENCE | CLK_GLOBAL_MEM_FENCE);
}

static inline uint index_alpha(uint pass, uint slice, uint index, uint pseudo,
                               uint seg, uint mb) {
    uint ref_area;
    ulong hi;
    uint rp;
    uint start;
    if (pass == 0) {
        ref_area = (slice == 0) ? (index - 1u) : (slice * seg + index - 1u);
    } else {
        ref_area = mb - seg + index - 1u;
    }
    hi = ((ulong)pseudo * (ulong)pseudo) >> 32;
    rp = (uint)(((ulong)ref_area * hi) >> 32);
    rp = ref_area - 1u - rp;
    start = (pass == 0) ? 0u : ((slice == 3u) ? 0u : (slice + 1u) * seg);
    return (start + rp) % mb;
}

typedef struct {
    uint count;
    uint pad[3];
    uint nonces[8];
    uint hashes[8][8];
} a2_results;

__kernel void argon2id_pow(__global const uchar *challenge, uint clen,
                           uint use_le, uint difficulty, uint base,
                           uint count, __global ulong *mem_all,
                           __global a2_results *res) {
    __local ulong sR[128];
    __local uchar sbuf[4224];
    __local uchar sbuf2[256];

    uint idx = get_group_id(0);
    uint tid = get_local_id(0);
    uint nonce;
    __global ulong *mem;
    uint seg = A2_M / 4u;
    ulong h0[8];
    ulong V[8];

    if (idx >= count) {
        return;
    }
    nonce = base + idx;
    mem = mem_all + (ulong)idx * (ulong)(A2_M + 3u) * 128u;

    if (tid == 0) {
        uint pw[7];
        uint len = 0;
        int i, j;
        pw[0] = 1u;
        pw[1] = 32u;
        pw[2] = A2_M;
        pw[3] = A2_T;
        pw[4] = 0x13u;
        pw[5] = 2u;
        pw[6] = clen;
        for (i = 0; i < 7; i++) {
            for (j = 0; j < 4; j++) {
                sbuf[len++] = (uchar)(pw[i] >> (8 * j));
            }
        }
        for (i = 0; i < (int)clen; i++) {
            sbuf[len++] = challenge[i];
        }
        sbuf[len++] = 8;
        sbuf[len++] = 0;
        sbuf[len++] = 0;
        sbuf[len++] = 0;
        for (i = 0; i < 8; i++) {
            int sh = use_le ? (8 * i) : (8 * (7 - i));
            sbuf[len++] = (uchar)((ulong)nonce >> sh);
        }
        for (i = 0; i < 8; i++) {
            sbuf[len++] = 0;
        }
        b2_hash(sbuf, len, 64, h0);

        for (int b = 0; b < 2; b++) {
            uchar Vb[64];
            uint o = (uint)b * 128u;
            sbuf2[0] = 0;
            sbuf2[1] = 4;
            sbuf2[2] = 0;
            sbuf2[3] = 0;
            for (i = 0; i < 64; i++) {
                sbuf2[4 + i] = (uchar)(h0[i >> 3] >> (8 * (i & 7)));
            }
            sbuf2[68] = (uchar)b;
            sbuf2[69] = 0;
            sbuf2[70] = 0;
            sbuf2[71] = 0;
            sbuf2[72] = 0;
            sbuf2[73] = 0;
            sbuf2[74] = 0;
            sbuf2[75] = 0;
            b2_hash(sbuf2, 76, 64, V);
            for (i = 0; i < 4; i++) {
                mem[o + (uint)i] = V[i];
            }
            for (int it = 2; it <= 31; it++) {
                for (i = 0; i < 64; i++) {
                    sbuf2[i] = (uchar)(V[i >> 3] >> (8 * (i & 7)));
                }
                b2_hash(sbuf2, 64, 64, V);
                if (it < 31) {
                    for (i = 0; i < 4; i++) {
                        mem[o + (uint)(4 * (it - 1) + i)] = V[i];
                    }
                } else {
                    for (i = 0; i < 8; i++) {
                        mem[o + (uint)(4 * (it - 1) + i)] = V[i];
                    }
                }
            }
        }
        for (i = 0; i < 256; i++) {
            mem[(ulong)A2_M * 128u + (ulong)i] = 0;
        }
    }
    barrier(CLK_LOCAL_MEM_FENCE | CLK_GLOBAL_MEM_FENCE);

    for (uint pass = 0; pass < A2_T; pass++) {
        for (uint slice = 0; slice < 4; slice++) {
            int di = (pass == 0 && slice < 2);
            uint start = (pass == 0 && slice == 0) ? 2u : 0u;
            if (di) {
                if (tid == 0) {
                    __global ulong *inp = mem + (ulong)(A2_M + 1u) * 128u;
                    for (int i = 0; i < 256; i++) {
                        inp[i] = 0;
                    }
                    inp[0] = pass;
                    inp[1] = 0;
                    inp[2] = slice;
                    inp[3] = A2_M;
                    inp[4] = A2_T;
                    inp[5] = 2;
                }
                barrier(CLK_LOCAL_MEM_FENCE | CLK_GLOBAL_MEM_FENCE);
                if (start == 2u) {
                    if (tid == 0) {
                        mem[(ulong)(A2_M + 1u) * 128u + 6u] += 1;
                    }
                    barrier(CLK_LOCAL_MEM_FENCE | CLK_GLOBAL_MEM_FENCE);
                    fill_block(mem, A2_M + 2u, A2_M, A2_M + 1u, 0, sR, tid);
                    fill_block(mem, A2_M + 2u, A2_M, A2_M + 2u, 0, sR, tid);
                }
            }
            for (uint i = start; i < seg; i++) {
                uint curr = slice * seg + i;
                uint prev = (curr == 0) ? (A2_M - 1u) : (curr - 1u);
                uint pseudo;
                if (di) {
                    if ((i & 127u) == 0u) {
                        if (tid == 0) {
                            mem[(ulong)(A2_M + 1u) * 128u + 6u] += 1;
                        }
                        barrier(CLK_LOCAL_MEM_FENCE | CLK_GLOBAL_MEM_FENCE);
                        fill_block(mem, A2_M + 2u, A2_M, A2_M + 1u, 0, sR, tid);
                        fill_block(mem, A2_M + 2u, A2_M, A2_M + 2u, 0, sR, tid);
                    }
                    pseudo = (uint)mem[(ulong)(A2_M + 2u) * 128u +
                                       (ulong)(i & 127u)];
                } else {
                    pseudo = (uint)mem[(ulong)prev * 128u];
                }
                {
                    uint ref = index_alpha(pass, slice, i, pseudo, seg, A2_M);
                    fill_block(mem, curr, prev, ref, (pass == 0) ? 0 : 1, sR,
                               tid);
                }
            }
        }
    }

    if (difficulty == 0xFFFFFFFEu) {
        if (tid == 0) {
            const __global ulong *last =
                mem + (ulong)(A2_M - 1u) * 128u;
            for (uint i = 0; i < 32u; i++) {
                res->hashes[0][2u * i] = (uint)last[i];
                res->hashes[0][2u * i + 1u] = (uint)(last[i] >> 32);
            }
            res->nonces[0] = nonce;
            res->count = 1;
        }
        return;
    }

    if (tid == 0) {
        uchar tag[32];
        int ok = 1;
        uint i;
        const __global uchar *lb =
            (const __global uchar *)(mem + (ulong)(A2_M - 1u) * 128u);
        sbuf[0] = 32;
        sbuf[1] = 0;
        sbuf[2] = 0;
        sbuf[3] = 0;
        for (i = 0; i < 1024u; i++) {
            sbuf[4 + i] = lb[i];
        }
        b2_hash(sbuf, 1028, 32, h0);
        for (i = 0; i < 32u; i++) {
            tag[i] = (uchar)(h0[i >> 3] >> (8 * (i & 7)));
        }
        for (i = 0; i < difficulty; i++) {
            if (((tag[i >> 3] >> (7u - (i & 7u))) & 1u) != 0) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            uint slot = atomic_inc(&res->count);
            if (slot < 8u) {
                res->nonces[slot] = nonce;
                for (i = 0; i < 8; i++) {
                    ulong w = h0[i >> 1];
                    uint v = (uint)((i & 1) ? (w >> 32) : (w & 0xffffffffUL));
                    res->hashes[slot][i] = ((v & 0xffu) << 24) |
                                           ((v >> 8 & 0xffu) << 16) |
                                           ((v >> 16 & 0xffu) << 8) |
                                           (v >> 24 & 0xffu);
                }
            }
        }
    }
}

/* Testing helper: BLAKE2b of a short input (used to validate the port). */
__kernel void b2_test(__global const uchar *in, uint len, uint outlen,
                      __global uchar *out) {
    __local uchar buf[4224];
    ulong h[8];
    uint tid = get_local_id(0);
    if (tid == 0) {
        for (uint i = 0; i < len; i++) {
            buf[i] = in[i];
        }
        b2_hash(buf, len, outlen, h);
        for (uint i = 0; i < outlen; i++) {
            out[i] = (uchar)(h[i >> 3] >> (8 * (i & 7)));
        }
    }
}

/* Debug helper: H0 and the first 32 bytes of H'(H0||0||0, 1024). */
__kernel void a2_dbg(__global const uchar *challenge, uint clen, uint use_le,
                     uint nonce, __global uchar *out) {
    __local uchar buf[4224];
    __local uchar buf2[256];
    ulong h[8];
    uint tid = get_local_id(0);
    uint len = 0;
    int i, j;

    if (tid == 0) {
        uint pw[7] = {1u, 32u, 19456u, 2u, 0x13u, 2u, clen};
        for (i = 0; i < 7; i++) {
            for (j = 0; j < 4; j++) {
                buf[len++] = (uchar)(pw[i] >> (8 * j));
            }
        }
        for (i = 0; i < (int)clen; i++) {
            buf[len++] = challenge[i];
        }
        buf[len++] = 8;
        buf[len++] = 0;
        buf[len++] = 0;
        buf[len++] = 0;
        for (i = 0; i < 8; i++) {
            int sh = use_le ? (8 * i) : (8 * (7 - i));
            buf[len++] = (uchar)((ulong)nonce >> sh);
        }
        for (i = 0; i < 8; i++) {
            buf[len++] = 0;
        }
        b2_hash(buf, len, 64, h);
        for (i = 0; i < 64; i++) {
            out[i] = (uchar)(h[i >> 3] >> (8 * (i & 7)));
        }
        buf2[0] = 0;
        buf2[1] = 4;
        buf2[2] = 0;
        buf2[3] = 0;
        for (i = 0; i < 64; i++) {
            buf2[4 + i] = out[i];
        }
        for (i = 0; i < 8; i++) {
            buf2[68 + i] = 0;
        }
        b2_hash(buf2, 76, 64, h);
        for (i = 0; i < 32; i++) {
            out[64 + i] = (uchar)(h[i >> 3] >> (8 * (i & 7)));
        }
        out[96] = (uchar)get_local_size(0);
        out[97] = (uchar)get_num_groups(0);
        out[98] = (uchar)get_local_id(0);
    }
}

/* Debug helper: one fill_block on 3 blocks (prev, ref, dst). */
__kernel void fill_dbg(__global ulong *mem, __global const uint *args) {
    __local ulong sR[128];
    uint tid = get_local_id(0);
    fill_block(mem, args[0], args[1], args[2], (int)args[3], sR, tid);
}
