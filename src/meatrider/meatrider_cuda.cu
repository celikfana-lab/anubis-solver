/*
 * meatrider_cuda.cu — the `meatrider` tier on NVIDIA GPUs.
 *
 * Same two compressions as every other kernel of the tier (see
 * src/meatrider/meatrider.c, which is the reference):
 *
 *   h1 = compress(header midstate, block1(nonce))
 *   h2 = compress(SHA-256 IV,     block2(h1))
 *   digest = h2 byte-reversed                      <- Bitcoin display order
 *
 * Block 2 is free of byte shuffling: its message words ARE the eight words of
 * h1, because SHA-256 reads a block as big-endian words and block 2 is the
 * big-endian first digest.
 *
 * Every device on the box is used: the nonce space is split into one contiguous
 * range per device and each one scans its range in chunks. The first hit wins;
 * the host re-derives the digest in C before believing it (the core does that),
 * so a kernel bug costs a dispatch, not a wrong answer.
 *
 * This file is only compiled when nvcc is present (make CUDA=1). It carries its
 * own device state instead of sharing cuda_sha256.cu's, so the tier stays
 * self-contained the way the other meatrider kernels are.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <pthread.h>

#include <cuda_runtime.h>

#include "meatrider/meatrider.h"

#define MR_MAX_DEV 4
#define MR_BLOCK 256

typedef struct {
    uint32_t mid[8];     /* SHA-256 state after header bytes 0..63 */
    uint32_t tail[3];    /* header bytes 64..75, little-endian words */
    uint32_t difficulty; /* leading zero bits of the display-order digest */
} mr_params;

typedef struct {
    uint32_t count;
    uint32_t pad[3];
    uint32_t nonces[8];
    uint32_t hashes[8][8]; /* display-order digest, as big-endian words */
} mr_results;

__constant__ uint32_t K[64] = {
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

__device__ static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

__device__ static inline uint32_t load_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

__device__ static inline uint32_t byteswap32(uint32_t x) {
    return (x >> 24) | ((x >> 8) & 0x0000ff00u) |
           ((x << 8) & 0x00ff0000u) | (x << 24);
}

/* One SHA-256 compression of a whole 64-byte block into h (in place). */
__device__ static void sha256_block(uint32_t h[8], const unsigned char blk[64]) {
    uint32_t w[16];
#pragma unroll
    for (int i = 0; i < 16; i++) {
        w[i] = load_be32(blk + 4 * i);
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

#pragma unroll
    for (uint32_t i = 0; i < 64; i++) {
        if (i >= 16) {
            uint32_t j = i & 15u;
            uint32_t x = w[(i + 1u) & 15u];
            uint32_t y = w[(i + 14u) & 15u];
            uint32_t s0 = rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
            uint32_t s1 = rotr32(y, 17) ^ rotr32(y, 19) ^ (y >> 10);
            w[j] = w[j] + s0 + w[(i + 9u) & 15u] + s1;
        }
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + s1 + ch + K[i] + w[i & 15u];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

__global__ void meatrider_pow_kernel(mr_params p, uint32_t base, uint32_t count,
                                     mr_results *res) {
    uint32_t gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= count) {
        return;
    }
    uint32_t nonce = base + gid;
    unsigned char blk[64];

    /* block 1: header bytes 64..79, the 0x80, and the 640-bit length */
#pragma unroll
    for (int i = 0; i < 64; i++) {
        blk[i] = 0;
    }
#pragma unroll
    for (int i = 0; i < 3; i++) {
        blk[4 * i + 0] = (unsigned char)p.tail[i];
        blk[4 * i + 1] = (unsigned char)(p.tail[i] >> 8);
        blk[4 * i + 2] = (unsigned char)(p.tail[i] >> 16);
        blk[4 * i + 3] = (unsigned char)(p.tail[i] >> 24);
    }
    blk[12] = (unsigned char)nonce;
    blk[13] = (unsigned char)(nonce >> 8);
    blk[14] = (unsigned char)(nonce >> 16);
    blk[15] = (unsigned char)(nonce >> 24);
    blk[16] = 0x80;
    blk[62] = 0x02;
    blk[63] = 0x80;

    uint32_t h[8];
#pragma unroll
    for (int i = 0; i < 8; i++) {
        h[i] = p.mid[i];
    }
    sha256_block(h, blk);

    /* block 2: the first digest's words are its message words */
#pragma unroll
    for (int i = 0; i < 64; i++) {
        blk[i] = 0;
    }
#pragma unroll
    for (int i = 0; i < 8; i++) {
        blk[4 * i + 0] = (unsigned char)(h[i] >> 24);
        blk[4 * i + 1] = (unsigned char)(h[i] >> 16);
        blk[4 * i + 2] = (unsigned char)(h[i] >> 8);
        blk[4 * i + 3] = (unsigned char)h[i];
    }
    blk[32] = 0x80;
    blk[62] = 0x01;
    blk[63] = 0x00;

    h[0] = 0x6a09e667u; h[1] = 0xbb67ae85u; h[2] = 0x3c6ef372u;
    h[3] = 0xa54ff53au; h[4] = 0x510e527fu; h[5] = 0x9b05688cu;
    h[6] = 0x1f83d9abu; h[7] = 0x5be0cd19u;
    sha256_block(h, blk);

    /* display order: reverse the word order and byteswap each word */
    uint32_t dg[8];
#pragma unroll
    for (int i = 0; i < 8; i++) {
        dg[i] = byteswap32(h[7 - i]);
    }

    /* leading zero bits, over big-endian words: a whole zero word is 32 bits */
    uint32_t need = p.difficulty;
    bool ok = true;
#pragma unroll
    for (uint32_t wi = 0; wi < 8u && need > 0u; wi++) {
        uint32_t bits = need >= 32u ? 32u : need;
        uint32_t mask = bits == 32u ? 0xffffffffu
                                    : (0xffffffffu << (32u - bits));
        if ((dg[wi] & mask) != 0u) {
            ok = false;
            break;
        }
        need -= bits;
    }

    if (ok) {
        uint32_t slot = atomicAdd(&res->count, 1u);
        if (slot < 8u) {
            res->nonces[slot] = nonce;
#pragma unroll
            for (int i = 0; i < 8; i++) {
                res->hashes[slot][i] = dg[i];
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Host side                                                           */
/* ------------------------------------------------------------------ */

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static struct {
    int inited;
    int available;
    int ndev;
    mr_params hparams;
    mr_results hresults;
    mr_params *dparams[MR_MAX_DEV];
    mr_results *dresults[MR_MAX_DEV];
    char info[200];
    pthread_mutex_t mu;
} g_mr;

static void mr_init_once(void) {
    pthread_mutex_init(&g_mr.mu, NULL);
}

static int mr_cuda_init(void) {
    int count = 0;
    if (g_mr.inited) {
        return g_mr.available;
    }
    g_mr.inited = 1;
    mr_init_once();
    {
        const char *off = getenv("ANUBIS_NO_CUDA");
        if (off != NULL && off[0] != '\0' && off[0] != '0') {
            return 0;
        }
    }
    if (cudaGetDeviceCount(&count) != cudaSuccess || count <= 0) {
        return 0;
    }
    if (count > MR_MAX_DEV) {
        count = MR_MAX_DEV;
    }
    for (int i = 0; i < count; i++) {
        cudaDeviceProp prop;
        if (cudaSetDevice(i) != cudaSuccess ||
            cudaGetDeviceProperties(&prop, i) != cudaSuccess ||
            cudaMalloc((void **)&g_mr.dparams[i], sizeof(mr_params)) != cudaSuccess ||
            cudaMalloc((void **)&g_mr.dresults[i], sizeof(mr_results)) !=
                cudaSuccess) {
            return 0;
        }
        if (i == 0) {
            if (count == 1) {
                snprintf(g_mr.info, sizeof(g_mr.info), "CUDA: %.96s", prop.name);
            } else {
                snprintf(g_mr.info, sizeof(g_mr.info), "CUDA: %.80s x%d",
                         prop.name, count);
            }
        }
    }
    if (cudaSetDevice(0) != cudaSuccess) {
        return 0;
    }
    g_mr.ndev = count;
    g_mr.available = 1;
    return 1;
}

extern "C" {
int anubis_cuda_meatrider_available(void) {
    return mr_cuda_init();
}

const char *anubis_cuda_meatrider_info(void) {
    if (!mr_cuda_init()) {
        return NULL;
    }
    return g_mr.info;
}

typedef struct {
    int dev;
    uint32_t start;
    uint32_t end;
    uint32_t chunk;
    double deadline;     /* monotonic seconds, 0 = none */
    int rc;              /* 0 hit, 1 exhausted, -1 failure */
    uint32_t nonce;
    uint32_t hashes[8];
    volatile int *stop;
} mr_worker;

static void *mr_worker_main(void *arg) {
    mr_worker *w = (mr_worker *)arg;
    mr_params p = g_mr.hparams;
    mr_results host;
    uint64_t base = w->start;

    if (cudaSetDevice(w->dev) != cudaSuccess) {
        w->rc = -1;
        return NULL;
    }
    memset(&host, 0, sizeof host);
    if (cudaMemcpy(g_mr.dresults[w->dev], &host, sizeof host,
                   cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(g_mr.dparams[w->dev], &p, sizeof p,
                   cudaMemcpyHostToDevice) != cudaSuccess) {
        w->rc = -1;
        return NULL;
    }

    while (base <= (uint64_t)w->end && !*w->stop) {
        uint64_t remaining = (uint64_t)w->end - base + 1u;
        uint32_t n = (uint32_t)(remaining < (uint64_t)w->chunk ? remaining
                                                              : (uint64_t)w->chunk);
        uint32_t blocks = (n + MR_BLOCK - 1u) / MR_BLOCK;
        if (n == 0) {
            break;
        }
        meatrider_pow_kernel<<<blocks, MR_BLOCK>>>(p, (uint32_t)base, n,
                                                   g_mr.dresults[w->dev]);
        if (cudaGetLastError() != cudaSuccess ||
            cudaDeviceSynchronize() != cudaSuccess) {
            w->rc = -1;
            return NULL;
        }
        if (cudaMemcpy(&host, g_mr.dresults[w->dev], sizeof host,
                       cudaMemcpyDeviceToHost) != cudaSuccess) {
            w->rc = -1;
            return NULL;
        }
        if (host.count > 0) {
            w->nonce = host.nonces[0];
            memcpy(w->hashes, host.hashes[0], sizeof w->hashes);
            w->rc = 0;
            *w->stop = 1;
            return NULL;
        }
        base += n;
        if (w->deadline > 0.0 && now_s() > w->deadline) {
            w->rc = 1;
            return NULL;
        }
    }
    w->rc = 1;
    return NULL;
}

/*
 * 0 on a hit, 1 when the range or budget ran out, -1 on backend failure.
 * Every device gets a contiguous slice of [start, end].
 */
int anubis_cuda_meatrider_solve(const meatrider_ctx *ctx, uint32_t start,
                                uint32_t count, double budget_ms,
                                uint32_t *out_nonce, uint8_t out_digest[32]) {
    mr_worker workers[MR_MAX_DEV];
    pthread_t threads[MR_MAX_DEV];
    uint32_t chunk, env_chunk;
    uint64_t end, per;
    double deadline = 0.0;
    volatile int stop = 0;
    int i, spawned = 0, rc = 1;
    const char *env;

    if (ctx == NULL || out_nonce == NULL || out_digest == NULL) {
        return -1;
    }
    if (!mr_cuda_init()) {
        return -1;
    }

    pthread_mutex_lock(&g_mr.mu);
    for (i = 0; i < 8; i++) {
        g_mr.hparams.mid[i] = ctx->mid[i];
    }
    for (i = 0; i < 3; i++) {
        g_mr.hparams.tail[i] = (uint32_t)ctx->tail[4 * i] |
                               ((uint32_t)ctx->tail[4 * i + 1] << 8) |
                               ((uint32_t)ctx->tail[4 * i + 2] << 16) |
                               ((uint32_t)ctx->tail[4 * i + 3] << 24);
    }
    g_mr.hparams.difficulty = (uint32_t)ctx->difficulty;

    env_chunk = 1u << 22;
    env = getenv("ANUBIS_CUDA_CHUNK");
    if (env != NULL && env[0] != '\0') {
        env_chunk = (uint32_t)strtoul(env, NULL, 0);
    }
    chunk = env_chunk;
    if (chunk < 65536u) {
        chunk = 65536u;
    }
    if (chunk > (1u << 26)) {
        chunk = 1u << 26;
    }

    end = 0xffffffffull;
    if (count > 0) {
        uint64_t last = (uint64_t)start + (uint64_t)count - 1u;
        if (last < end) {
            end = last;
        }
    }
    if (budget_ms > 0.0) {
        deadline = now_s() + budget_ms / 1000.0;
    }

    per = (end - (uint64_t)start + 1u + (uint64_t)g_mr.ndev - 1u) /
          (uint64_t)g_mr.ndev;
    for (i = 0; i < g_mr.ndev; i++) {
        uint64_t lo = (uint64_t)start + (uint64_t)i * per;
        uint64_t hi = lo + per - 1u;
        workers[i].dev = i;
        workers[i].start = (uint32_t)(lo > end ? end : lo);
        workers[i].end = (uint32_t)(hi > end ? end : hi);
        workers[i].chunk = chunk;
        workers[i].deadline = deadline;
        workers[i].rc = 1;
        workers[i].nonce = 0;
        workers[i].stop = &stop;
        if (lo > end) {
            break;
        }
        if (pthread_create(&threads[i], NULL, mr_worker_main, &workers[i]) != 0) {
            workers[i].rc = -1;
            break;
        }
        spawned++;
    }

    for (i = 0; i < spawned; i++) {
        pthread_join(threads[i], NULL);
    }

    rc = 1;
    for (i = 0; i < spawned; i++) {
        if (workers[i].rc == 0) {
            *out_nonce = workers[i].nonce;
            for (int k = 0; k < 8; k++) {
                out_digest[4 * k + 0] = (uint8_t)(workers[i].hashes[k] >> 24);
                out_digest[4 * k + 1] = (uint8_t)(workers[i].hashes[k] >> 16);
                out_digest[4 * k + 2] = (uint8_t)(workers[i].hashes[k] >> 8);
                out_digest[4 * k + 3] = (uint8_t)workers[i].hashes[k];
            }
            rc = 0;
            break;
        }
        if (workers[i].rc < 0) {
            rc = -1;
        }
    }
    if (spawned == 0) {
        rc = -1;
    }
    pthread_mutex_unlock(&g_mr.mu);
    return rc;
}
} /* extern "C" */
