/* anubis_sha256.h — a small SHA-256 for the QEMU device model, so the card
 * produces a real, checkable digest. Test-only code, not shipped in the RTL.
 * Handles messages up to 256 bytes, which is the challenge window. */
#ifndef ANUBIS_SHA256_H
#define ANUBIS_SHA256_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const uint32_t anubis_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static inline uint32_t anubis_ror32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static inline void anubis_sha256_block(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2, s0, s1, ch, mj, S0, S1;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) |
               ((uint32_t)p[4*i+2] << 8) | (uint32_t)p[4*i+3];
    for (i = 16; i < 64; i++) {
        s0 = anubis_ror32(w[i-15], 7) ^ anubis_ror32(w[i-15], 18) ^ (w[i-15] >> 3);
        s1 = anubis_ror32(w[i-2], 17) ^ anubis_ror32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (i = 0; i < 64; i++) {
        S1 = anubis_ror32(e, 6) ^ anubis_ror32(e, 11) ^ anubis_ror32(e, 25);
        ch = (e & f) ^ (~e & g);
        t1 = hh + S1 + ch + anubis_K[i] + w[i];
        S0 = anubis_ror32(a, 2) ^ anubis_ror32(a, 13) ^ anubis_ror32(a, 22);
        mj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static inline void anubis_sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t pad[320];
    size_t total, off, i, j;
    uint64_t bits = (uint64_t)len * 8;

    if (len > 256) len = 256;
    total = ((len + 8) / 64 + 1) * 64;      /* always >= len + 9 */
    memset(pad, 0, sizeof(pad));
    memcpy(pad, msg, len);
    pad[len] = 0x80;
    for (i = 0; i < 8; i++)
        pad[total - 1 - i] = (uint8_t)(bits >> (8 * i));

    for (off = 0; off < total; off += 64)
        anubis_sha256_block(h, pad + off);

    for (i = 0; i < 8; i++)
        for (j = 0; j < 4; j++)
            out[4*i + j] = (uint8_t)(h[i] >> (24 - 8*j));
}

#endif
