/*
 * cuda_argon2.cu — CUDA Argon2id backend (Anubis "argon2id" challenges).
 *
 * One CUDA block per candidate nonce: the 1 KiB Argon2 block lives in shared
 * memory and the 64 threads cooperate on the BlaMka permutation, while the
 * 19 MiB memory matrix lives in global memory (one region per block). The
 * BLAKE2b work (H0, H', final tag) runs on thread 0.
 *
 * Opt in with ANUBIS_GPU_ARGON2=1; the C core re-verifies every digest with
 * the reference Argon2 implementation before accepting it.
 */

#include <cuda_runtime.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define A2_M 19456u
#define A2_T 2u
#define A2_LANES 32u          /* parallel hashes per launch per device */

typedef struct {
    uint32_t count;
    uint32_t pad[3];
    uint32_t nonces[8];
    uint32_t hashes[8][8];
} a2_results;

__constant__ uint64_t c_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

__constant__ uint8_t c_sigma[12][16] = {
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

__constant__ uint8_t c_perm[8][4] = {
    {0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15},
    {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}
};

__device__ __forceinline__ uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

__device__ __forceinline__ uint64_t ld64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

__device__ __forceinline__ void st64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

__device__ __forceinline__ void b2g(uint64_t *a, uint64_t *b, uint64_t *c,
                                    uint64_t *d, uint64_t x, uint64_t y) {
    *a = *a + *b + x;
    *d = rotr64(*d ^ *a, 32);
    *c = *c + *d;
    *b = rotr64(*b ^ *c, 24);
    *a = *a + *b + y;
    *d = rotr64(*d ^ *a, 16);
    *c = *c + *d;
    *b = rotr64(*b ^ *c, 63);
}

__device__ void b2_compress(uint64_t h[8], const uint64_t m[16], uint64_t t,
                            int last) {
    uint64_t v[16];
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
        const uint8_t *s = c_sigma[r];
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

__device__ void b2_hash(const uint8_t *data, uint32_t len, uint32_t outlen,
                        uint8_t out[64]) {
    uint64_t h[8];
    uint64_t m[16];
    uint32_t off = 0;
    int i;

    for (i = 0; i < 8; i++) {
        h[i] = c_iv[i];
    }
    h[0] ^= 0x01010000ULL ^ outlen;

    while (len - off > 128u) {
        for (i = 0; i < 16; i++) {
            m[i] = ld64(data + off + 8 * i);
        }
        off += 128u;
        b2_compress(h, m, off, 0);
    }
    {
        uint8_t blk[128];
        uint32_t rem = len - off;
        for (i = 0; i < 128; i++) {
            blk[i] = (i < (int)rem) ? data[off + i] : 0;
        }
        for (i = 0; i < 16; i++) {
            m[i] = ld64(blk + 8 * i);
        }
        b2_compress(h, m, len, 1);
    }
    for (i = 0; i < 8; i++) {
        if ((uint32_t)(8 * i) >= outlen) {
            break;
        }
        st64(out + 8 * i, h[i]);
    }
}

__device__ __forceinline__ uint64_t blamka(uint64_t x, uint64_t y) {
    return x + y + 2ULL * (x & 0xFFFFFFFFULL) * (y & 0xFFFFFFFFULL);
}

__device__ __forceinline__ void a2g(uint64_t *a, uint64_t *b, uint64_t *c,
                                    uint64_t *d) {
    *a = blamka(*a, *b);
    *d = rotr64(*d ^ *a, 32);
    *c = blamka(*c, *d);
    *b = rotr64(*b ^ *c, 24);
    *a = blamka(*a, *b);
    *d = rotr64(*d ^ *a, 16);
    *c = blamka(*c, *d);
    *b = rotr64(*b ^ *c, 63);
}

__shared__ uint64_t sR[128];
__shared__ uint8_t sbuf[4224];

/* Fill one Argon2 block cooperatively (one block per CUDA block). */
__device__ void fill_block(uint64_t *mem, uint32_t dst, uint32_t prev,
                           uint32_t ref, int with_xor, int tid) {
    const uint32_t g = (uint32_t)tid >> 3;
    const uint32_t gi = (uint32_t)tid & 7u;
    const uint64_t *p = mem + (size_t)prev * 128u;
    const uint64_t *r = mem + (size_t)ref * 128u;
    uint64_t *d = mem + (size_t)dst * 128u;
    const uint8_t off[16] = {0, 1, 16, 17, 32, 33, 48, 49,
                             64, 65, 80, 81, 96, 97, 112, 113};

    for (int i = tid; i < 128; i += 64) {
        sR[i] = p[i] ^ r[i];
    }
    __syncthreads();

    for (int half = 0; half < 2; half++) {
        if (gi < 4) {
            uint32_t idx = gi + (uint32_t)(half ? 4 : 0);
            uint32_t base = g * 16u;
            uint64_t a = sR[base + c_perm[idx][0]];
            uint64_t b = sR[base + c_perm[idx][1]];
            uint64_t c = sR[base + c_perm[idx][2]];
            uint64_t dd = sR[base + c_perm[idx][3]];
            a2g(&a, &b, &c, &dd);
            sR[base + c_perm[idx][0]] = a;
            sR[base + c_perm[idx][1]] = b;
            sR[base + c_perm[idx][2]] = c;
            sR[base + c_perm[idx][3]] = dd;
        }
        __syncthreads();
    }

    for (int half = 0; half < 2; half++) {
        if (gi < 4) {
            uint32_t idx = gi + (uint32_t)(half ? 4 : 0);
            uint32_t base = 2u * g;
            uint64_t a = sR[base + off[c_perm[idx][0]]];
            uint64_t b = sR[base + off[c_perm[idx][1]]];
            uint64_t c = sR[base + off[c_perm[idx][2]]];
            uint64_t dd = sR[base + off[c_perm[idx][3]]];
            a2g(&a, &b, &c, &dd);
            sR[base + off[c_perm[idx][0]]] = a;
            sR[base + off[c_perm[idx][1]]] = b;
            sR[base + off[c_perm[idx][2]]] = c;
            sR[base + off[c_perm[idx][3]]] = dd;
        }
        __syncthreads();
    }

    for (int i = tid; i < 128; i += 64) {
        uint64_t v = sR[i] ^ p[i] ^ r[i];
        if (with_xor) {
            v ^= d[i];
        }
        d[i] = v;
    }
    __syncthreads();
}

__device__ uint32_t index_alpha(uint32_t pass, uint32_t slice,
                                uint32_t index, uint32_t pseudo,
                                uint32_t seg, uint32_t mb) {
    uint32_t ref_area;
    uint64_t hi;
    uint32_t rp;
    uint32_t start;
    if (pass == 0) {
        ref_area = (slice == 0) ? (index - 1u) : (slice * seg + index - 1u);
    } else {
        ref_area = mb - seg + index - 1u;
    }
    hi = ((uint64_t)pseudo * (uint64_t)pseudo) >> 32;
    rp = (uint32_t)(((uint64_t)ref_area * hi) >> 32);
    rp = ref_area - 1u - rp;
    start = (pass == 0) ? 0u : ((slice == 3u) ? 0u : (slice + 1u) * seg);
    return (start + rp) % mb;
}

__global__ void argon2id_kernel(const uint8_t *challenge, uint32_t clen,
                                uint32_t use_le, uint32_t difficulty,
                                uint32_t base, uint32_t count,
                                uint64_t *mem_all, a2_results *res) {
    uint32_t idx = blockIdx.x;
    int tid = (int)threadIdx.x;
    uint32_t nonce;
    uint64_t *mem;
    uint32_t seg = A2_M / 4u;
    uint64_t h0[8];

    if (idx >= count) {
        return;
    }
    nonce = base + idx;
    mem = mem_all + (size_t)idx * (size_t)(A2_M + 3u) * 128u;

    if (tid == 0) {
        uint32_t pw[7];
        uint32_t len = 0;
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
                sbuf[len++] = (uint8_t)(pw[i] >> (8 * j));
            }
        }
        for (i = 0; i < (int)clen; i++) {
            sbuf[len++] = challenge[i];
        }
        for (i = 0; i < 8; i++) {
            int sh = use_le ? (8 * i) : (8 * (7 - i));
            sbuf[len++] = (uint8_t)((uint64_t)nonce >> sh);
        }
        b2_hash(sbuf, len, 64, (uint8_t *)h0);

        for (int b = 0; b < 2; b++) {
            uint8_t in[76];
            uint8_t V[64];
            uint8_t out[64];
            uint32_t o;
            in[0] = 0x00;
            in[1] = 0x04;
            in[2] = 0x00;
            in[3] = 0x00;
            for (i = 0; i < 64; i++) {
                in[4 + i] = ((uint8_t *)h0)[i];
            }
            for (i = 0; i < 4; i++) {
                in[68 + i] = (uint8_t)((uint32_t)b >> (8 * i));
                in[72 + i] = 0;
            }
            b2_hash(in, 76, 64, V);
            o = (uint32_t)b * 128u;
            for (i = 0; i < 4; i++) {
                mem[o + (uint32_t)i] = ld64(V + 8 * i);
            }
            for (int it = 2; it <= 31; it++) {
                b2_hash(V, 64, 64, out);
                for (i = 0; i < 64; i++) {
                    V[i] = out[i];
                }
                if (it < 31) {
                    for (i = 0; i < 4; i++) {
                        mem[o + (uint32_t)(4 * (it - 1) + i)] = ld64(V + 8 * i);
                    }
                } else {
                    for (i = 0; i < 8; i++) {
                        mem[o + (uint32_t)(4 * (it - 1) + i)] = ld64(V + 8 * i);
                    }
                }
            }
        }
        for (i = 0; i < 256; i++) {
            mem[(size_t)A2_M * 128u + (size_t)i] = 0;
        }
    }
    __syncthreads();

    for (uint32_t pass = 0; pass < A2_T; pass++) {
        for (uint32_t slice = 0; slice < 4; slice++) {
            int di = (pass == 0 && slice < 2);
            uint32_t start = (pass == 0 && slice == 0) ? 2u : 0u;
            if (di) {
                if (tid == 0) {
                    uint64_t *inp = mem + (size_t)(A2_M + 1u) * 128u;
                    for (int i = 0; i < 256; i++) {
                        inp[i] = 0;
                    }
                    inp[0] = pass;
                    inp[1] = 0;            /* lane */
                    inp[2] = slice;
                    inp[3] = A2_M;
                    inp[4] = A2_T;
                    inp[5] = 2;
                }
                __syncthreads();
                if (start == 2u) {
                    if (tid == 0) {
                        mem[(size_t)(A2_M + 1u) * 128u + 6u] += 1;
                    }
                    __syncthreads();
                    fill_block(mem, A2_M + 2u, A2_M, A2_M + 1u, 0, tid);
                    fill_block(mem, A2_M + 2u, A2_M, A2_M + 2u, 0, tid);
                }
            }
            for (uint32_t i = start; i < seg; i++) {
                uint32_t curr = slice * seg + i;
                uint32_t prev = (curr == 0) ? (A2_M - 1u) : (curr - 1u);
                uint32_t pseudo;
                if (di) {
                    if ((i & 127u) == 0u) {
                        if (tid == 0) {
                            mem[(size_t)(A2_M + 1u) * 128u + 6u] += 1;
                        }
                        __syncthreads();
                        fill_block(mem, A2_M + 2u, A2_M, A2_M + 1u, 0, tid);
                        fill_block(mem, A2_M + 2u, A2_M, A2_M + 2u, 0, tid);
                    }
                    pseudo = (uint32_t)mem[(size_t)(A2_M + 2u) * 128u +
                                           (size_t)(i & 127u)];
                } else {
                    pseudo = (uint32_t)mem[(size_t)prev * 128u];
                }
                {
                    uint32_t ref = index_alpha(pass, slice, i, pseudo, seg, A2_M);
                    fill_block(mem, curr, prev, ref, (pass == 0) ? 0 : 1, tid);
                }
            }
        }
    }

    if (tid == 0) {
        uint8_t tag[32];
        int ok = 1;
        uint32_t i;
        sbuf[0] = 32;
        sbuf[1] = 0;
        sbuf[2] = 0;
        sbuf[3] = 0;
        {
            const uint8_t *lb = (const uint8_t *)(mem + (size_t)(A2_M - 1u) * 128u);
            for (i = 0; i < 1024u; i++) {
                sbuf[4 + i] = lb[i];
            }
        }
        b2_hash(sbuf, 1028, 32, tag);
        for (i = 0; i < difficulty; i++) {
            if (((tag[i >> 3] >> (7u - (i & 7u))) & 1u) != 0) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            uint32_t slot = atomicAdd(&res->count, 1u);
            if (slot < 8u) {
                res->nonces[slot] = nonce;
                for (i = 0; i < 8; i++) {
                    res->hashes[slot][i] = ((uint32_t)tag[4 * i] << 24) |
                                           ((uint32_t)tag[4 * i + 1] << 16) |
                                           ((uint32_t)tag[4 * i + 2] << 8) |
                                           (uint32_t)tag[4 * i + 3];
                }
            }
        }
    }
}

/* ------------------------------ host side ------------------------------ */

static struct {
    int inited;
    int available;
    int ndev;
    pthread_mutex_t mu;
    uint8_t *d_challenge[8];
    a2_results *d_res[8];
    uint64_t *d_mem[8];
    a2_results h_res;
    char info[160];
} g_a2 = { 0, 0, 0, PTHREAD_MUTEX_INITIALIZER, {0}, {0}, {0}, {0}, {0} };

static double a2_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint32_t a2_env_u32(const char *name, uint32_t def) {
    const char *s = getenv(name);
    if (s != NULL && *s != '\0') {
        return (uint32_t)strtoul(s, NULL, 0);
    }
    return def;
}

static int a2_init(void) {
    int count = 0;
    size_t mem_bytes = (size_t)A2_LANES * (size_t)(A2_M + 3u) * 1024u;

    if (g_a2.inited) {
        return g_a2.available;
    }
    g_a2.inited = 1;
    {
        const char *off = getenv("ANUBIS_NO_CUDA");
        if (off != NULL && off[0] != '\0' && off[0] != '0') {
            return 0;
        }
    }
    if (cudaGetDeviceCount(&count) != cudaSuccess || count <= 0) {
        return 0;
    }
    if (count > 8) {
        count = 8;
    }
    for (int i = 0; i < count; i++) {
        cudaDeviceProp prop;
        if (cudaSetDevice(i) != cudaSuccess ||
            cudaGetDeviceProperties(&prop, i) != cudaSuccess) {
            return 0;
        }
        if (cudaMalloc((void **)&g_a2.d_challenge[i], 4096) != cudaSuccess ||
            cudaMalloc((void **)&g_a2.d_res[i], sizeof(a2_results)) !=
                cudaSuccess ||
            cudaMalloc((void **)&g_a2.d_mem[i], mem_bytes) != cudaSuccess) {
            return 0;
        }
        if (count == 1) {
            snprintf(g_a2.info, sizeof(g_a2.info), "CUDA Argon2id: %.90s",
                     prop.name);
        } else {
            snprintf(g_a2.info, sizeof(g_a2.info), "CUDA Argon2id: %.80s x%d",
                     prop.name, count);
        }
    }
    if (cudaSetDevice(0) != cudaSuccess) {
        return 0;
    }
    g_a2.ndev = count;
    g_a2.available = 1;
    return 1;
}

extern "C" {
int anubis_cuda_argon2_available(void) {
    return a2_init();
}

const char *anubis_cuda_argon2_info(void) {
    if (!a2_init()) {
        return NULL;
    }
    return g_a2.info;
}

static void a2_hex(const uint32_t w[8], char out[65]) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            unsigned v = (w[i] >> (8 * (3 - j))) & 0xFFu;
            out[(4 * i + j) * 2 + 0] = hexd[v >> 4];
            out[(4 * i + j) * 2 + 1] = hexd[v & 0xFu];
        }
    }
    out[64] = '\0';
}

/*
 * Returns 0 on a hit (caller verifies with the reference Argon2), 1 if the
 * range was exhausted, -1 on backend failure.
 */
int anubis_cuda_argon2_solve(const uint8_t *challenge, size_t clen, int use_le,
                             int difficulty, uint64_t max_nonce,
                             double budget_ms, uint32_t *out_nonce,
                             char out_hex[65], double *out_ms) {
    uint32_t lanes;
    uint64_t base = 0;
    uint64_t maxn;
    double t0;
    int rc = 1;

    if (challenge == NULL || out_nonce == NULL || out_hex == NULL ||
        clen > 4096) {
        return -1;
    }
    if (!a2_init()) {
        return -1;
    }
    pthread_mutex_lock(&g_a2.mu);
    t0 = a2_now();
    lanes = a2_env_u32("ANUBIS_CUDA_ARGON2_LANES", A2_LANES);
    if (lanes < 1u) {
        lanes = 1u;
    }
    if (lanes > A2_LANES) {
        lanes = A2_LANES;
    }
    for (int d = 0; d < g_a2.ndev; d++) {
        cudaSetDevice(d);
        if (cudaMemcpy(g_a2.d_challenge[d], challenge, clen,
                       cudaMemcpyHostToDevice) != cudaSuccess) {
            pthread_mutex_unlock(&g_a2.mu);
            return -1;
        }
    }

    maxn = max_nonce > 0xFFFFFFFFull ? 0xFFFFFFFFull : max_nonce;
    while (base <= maxn) {
        int launched = 0;
        int found = 0;
        uint32_t best = 0;
        uint32_t bh[8];
        for (int d = 0; d < g_a2.ndev; d++) {
            uint64_t b = base + (uint64_t)d * lanes;
            uint32_t cnt;
            if (b > maxn) {
                break;
            }
            cnt = (uint32_t)((maxn - b + 1) < (uint64_t)lanes
                                 ? (maxn - b + 1)
                                 : (uint64_t)lanes);
            cudaSetDevice(d);
            if (cudaMemset(g_a2.d_res[d], 0, sizeof(a2_results)) != cudaSuccess) {
                rc = -1;
                goto done;
            }
            argon2id_kernel<<<cnt, 64>>>(g_a2.d_challenge[d], (uint32_t)clen,
                                         (uint32_t)use_le,
                                         (uint32_t)difficulty, (uint32_t)b,
                                         cnt, g_a2.d_mem[d], g_a2.d_res[d]);
            if (cudaGetLastError() != cudaSuccess) {
                rc = -1;
                goto done;
            }
            launched++;
        }
        if (launched == 0) {
            break;
        }
        for (int d = 0; d < launched; d++) {
            cudaSetDevice(d);
            if (cudaDeviceSynchronize() != cudaSuccess ||
                cudaMemcpy(&g_a2.h_res, g_a2.d_res[d], sizeof(a2_results),
                           cudaMemcpyDeviceToHost) != cudaSuccess) {
                rc = -1;
                goto done;
            }
            if (g_a2.h_res.count > 0) {
                uint32_t n = g_a2.h_res.nonces[0];
                if (!found || n < best) {
                    found = 1;
                    best = n;
                    memcpy(bh, g_a2.h_res.hashes[0], sizeof(bh));
                }
            }
        }
        if (found) {
            a2_hex(bh, out_hex);
            *out_nonce = best;
            if (out_ms != NULL) {
                *out_ms = (a2_now() - t0) * 1000.0;
            }
            rc = 0;
            goto done;
        }
        base += (uint64_t)launched * lanes;
        if (budget_ms > 0.0 && (a2_now() - t0) * 1000.0 > budget_ms) {
            rc = 1;
            goto done;
        }
    }

done:
    for (int d = 0; d < g_a2.ndev; d++) {
        cudaSetDevice(d);
        (void)cudaGetLastError();
    }
    pthread_mutex_unlock(&g_a2.mu);
    return rc;
}

/* Compute the Argon2id digest for one nonce (testing/debug helper). */
int anubis_cuda_argon2_digest(const uint8_t *challenge, size_t clen,
                              int use_le, uint32_t nonce, uint8_t out[32]) {
    if (challenge == NULL || out == NULL || clen > 4096 || !a2_init()) {
        return -1;
    }
    pthread_mutex_lock(&g_a2.mu);
    cudaSetDevice(0);
    if (cudaMemcpy(g_a2.d_challenge[0], challenge, clen,
                   cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemset(g_a2.d_res[0], 0, sizeof(a2_results)) != cudaSuccess) {
        pthread_mutex_unlock(&g_a2.mu);
        return -1;
    }
    argon2id_kernel<<<1, 64>>>(g_a2.d_challenge[0], (uint32_t)clen,
                               (uint32_t)use_le, 0u, nonce, 1u,
                               g_a2.d_mem[0], g_a2.d_res[0]);
    if (cudaGetLastError() != cudaSuccess || cudaDeviceSynchronize() != cudaSuccess ||
        cudaMemcpy(&g_a2.h_res, g_a2.d_res[0], sizeof(a2_results),
                   cudaMemcpyDeviceToHost) != cudaSuccess) {
        pthread_mutex_unlock(&g_a2.mu);
        return -1;
    }
    if (g_a2.h_res.count == 0) {
        pthread_mutex_unlock(&g_a2.mu);
        return -1;
    }
    for (int i = 0; i < 8; i++) {
        uint32_t w = g_a2.h_res.hashes[0][i];
        out[4 * i + 0] = (uint8_t)(w >> 24);
        out[4 * i + 1] = (uint8_t)(w >> 16);
        out[4 * i + 2] = (uint8_t)(w >> 8);
        out[4 * i + 3] = (uint8_t)w;
    }
    pthread_mutex_unlock(&g_a2.mu);
    return 0;
}
} /* extern "C" */
