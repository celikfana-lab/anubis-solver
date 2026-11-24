/*
 * meatrider_opencl.cl — the `meatrider` tier on any OpenCL 1.2 device.
 *
 * The tier is SHA-256d over a real 80-byte Bitcoin block header. One hash is
 * two compressions:
 *
 *   h1 = compress(mid, block1(nonce))
 *   h2 = compress(IV,  block2(h1))
 *   digest = the 32 bytes of h2, reversed        <- Bitcoin display order
 *
 * `mid` is the state after header bytes 0..63, which the host compresses once
 * per challenge; only block 1's four nonce bytes move. The digest is compared
 * byte by byte, so `difficulty` means leading zero bits of the reversed digest
 * exactly as it does in the C reference (src/meatrider/meatrider.c).
 *
 * One work-item per candidate nonce. Hits are appended to a small results
 * buffer and the host re-derives every digest in C before believing it, so a
 * kernel bug costs a wasted dispatch, not a wrong answer.
 *
 * Embedded into src/opencl/opencl_kernels.h by tools/embed_opencl_kernels.py.
 */

typedef struct {
    uint mid[8];       /* SHA-256 state after header bytes 0..63 */
    uint tail[3];      /* header bytes 64..75, little-endian words */
    uint difficulty;   /* leading zero bits of the display-order digest */
    uint base_nonce;
    uint chunk;        /* invocations in this dispatch */
} mr_params;

typedef struct {
    uint count;
    uint pad[3];
    uint nonces[8];
    uint hashes[8][8];   /* display-order digest, as big-endian words */
} mr_results;

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

static inline uint rotr32(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint load_be32(__private const uchar *p) {
    return ((uint)p[0] << 24) | ((uint)p[1] << 16) | ((uint)p[2] << 8) |
           (uint)p[3];
}

static inline uint byteswap32(uint x) {
    return (x >> 24) | ((x >> 8) & 0x0000ff00u) |
           ((x << 8) & 0x00ff0000u) | (x << 24);
}

/* One SHA-256 compression of a whole 64-byte block into h (in place). */
static void sha256_block(__private uint h[8], __private const uchar blk[64]) {
    uint w[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        w[i] = load_be32(blk + 4 * i);
    }

    uint a = h[0], b = h[1], c = h[2], d = h[3];
    uint e = h[4], f = h[5], g = h[6], hh = h[7];

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
        uint t1 = hh + s1 + ch + K[i] + w[i & 15u];
        uint s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = s0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

__kernel void meatrider_pow(__global const mr_params *p,
                            __global mr_results *res) {
    uint gid = get_global_id(0);
    if (gid >= p->chunk) {
        return;
    }
    uint nonce = p->base_nonce + gid;
    uchar blk[64];

    /* block 1: header bytes 64..79, the 0x80, and the 640-bit length */
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        blk[i] = 0;
    }
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        blk[4 * i + 0] = (uchar)p->tail[i];
        blk[4 * i + 1] = (uchar)(p->tail[i] >> 8);
        blk[4 * i + 2] = (uchar)(p->tail[i] >> 16);
        blk[4 * i + 3] = (uchar)(p->tail[i] >> 24);
    }
    blk[12] = (uchar)nonce;
    blk[13] = (uchar)(nonce >> 8);
    blk[14] = (uchar)(nonce >> 16);
    blk[15] = (uchar)(nonce >> 24);
    blk[16] = 0x80;
    blk[62] = 0x02;
    blk[63] = 0x80;

    uint h[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        h[i] = p->mid[i];
    }
    sha256_block(h, blk);

    /* block 2: the 32-byte first digest big-endian, 0x80, 256-bit length */
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        blk[i] = 0;
    }
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        blk[4 * i + 0] = (uchar)(h[i] >> 24);
        blk[4 * i + 1] = (uchar)(h[i] >> 16);
        blk[4 * i + 2] = (uchar)(h[i] >> 8);
        blk[4 * i + 3] = (uchar)h[i];
    }
    blk[32] = 0x80;
    blk[62] = 0x01;
    blk[63] = 0x00;

    h[0] = 0x6a09e667u; h[1] = 0xbb67ae85u; h[2] = 0x3c6ef372u;
    h[3] = 0xa54ff53au; h[4] = 0x510e527fu; h[5] = 0x9b05688cu;
    h[6] = 0x1f83d9abu; h[7] = 0x5be0cd19u;
    sha256_block(h, blk);

    /* display order: the digest byte-reversed, which for whole words means
     * reversing the word order and byteswapping each word */
    uint dg[8];
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        dg[i] = byteswap32(h[7 - i]);
    }

    /* Leading zero bits of the display-order digest. dg[] is words, each
     * covering four of the digest's bytes, so the bit count has to be turned
     * into a word mask -- a whole zero word is 32 bits, not 8. */
    int ok = 1;
    uint need = p->difficulty;
    for (uint w = 0; w < 8u && need > 0u; w++) {
        uint bits = need >= 32u ? 32u : need;
        uint mask = bits == 32u ? 0xffffffffu : (0xffffffffu << (32u - bits));
        if ((dg[w] & mask) != 0u) {
            ok = 0;
            break;
        }
        need -= bits;
    }

    if (ok) {
        uint slot = atomic_inc(&res->count);
        if (slot < 8u) {
            res->nonces[slot] = nonce;
            for (int i = 0; i < 8; i++) {
                res->hashes[slot][i] = dg[i];
            }
        }
    }
}
