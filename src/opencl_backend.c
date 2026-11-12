/*
 * opencl_backend.c — portable OpenCL backend (SHA-256, Argon2id, HashX).
 *
 * Uses the same OpenCL C kernels as the Level Zero backend, but through the
 * standard OpenCL API so it runs on any ICD (Intel, AMD, NVIDIA, rusticl,
 * POCL, ...). Loaded with dlopen("libOpenCL.so.1").
 */

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "opencl_kernels.h"
#include "hashx.h"

#define A2_M 19456u
#define A2_LANES 32u
#define A2_CHUNK A2_LANES

typedef int32_t cl_int;
typedef uint32_t cl_uint;
typedef uint64_t cl_ulong;
typedef int64_t cl_long;
typedef void *cl_platform_id;
typedef void *cl_device_id;
typedef void *cl_context;
typedef void *cl_command_queue;
typedef void *cl_mem;
typedef void *cl_program;
typedef void *cl_kernel;
typedef void *cl_event;

#define CL_SUCCESS 0
#define CL_DEVICE_TYPE_GPU (1u << 2)
#define CL_DEVICE_TYPE_ALL 0xFFFFFFFFu
#define CL_MEM_READ_WRITE (1u << 0)
#define CL_MEM_COPY_HOST_PTR (1u << 5)
#define CL_TRUE 1
#define CL_PROGRAM_BUILD_LOG 0x1183
#define CL_DEVICE_NAME 0x102B

typedef struct {
    uint32_t mid[8];
    uint32_t prefix_len;
    uint32_t mode;
    uint32_t use_le;
    uint32_t difficulty;
    uint32_t check_bits;
    uint32_t base_nonce;
    uint32_t chunk;
} cl_sha_params;

typedef struct {
    uint32_t count;
    uint32_t pad[3];
    uint32_t nonces[8];
    uint32_t hashes[8][8];
} cl_sha_results;

typedef struct {
    uint32_t count;
    uint32_t pad[3];
    uint32_t nonces[8];
    uint32_t hashes[8][8];
} cl_a2_results;

typedef struct {
    uint32_t count;
    uint32_t pad[3];
    uint32_t nonces[8];
    uint32_t hashes[8][8];
} cl_hx_results;

static struct {
    int state;
    int dev_count;
    cl_context ctx;
    cl_command_queue queue;
    cl_program prog_sha, prog_a2, prog_hx;
    cl_kernel k_sha, k_a2, k_hx;
    cl_mem sha_params, sha_results;
    cl_mem a2_challenge, a2_mem, a2_results;
    cl_mem hx_prog, hx_results;
    cl_sha_params *sha_p;
    cl_sha_results *sha_r;
    cl_a2_results *a2_r;
    cl_hx_results *hx_r;
    pthread_mutex_t mu;
    char info[200];
} g_ocl = { 0 };

static cl_int (*p_clGetPlatformIDs)(cl_uint, cl_platform_id *, cl_uint *);
static cl_int (*p_clGetDeviceIDs)(cl_platform_id, cl_uint, cl_uint, cl_device_id *, cl_uint *);
static cl_int (*p_clGetDeviceInfo)(cl_device_id, cl_uint, size_t, void *, size_t *);
static cl_context (*p_clCreateContext)(void *, cl_uint, const cl_device_id *, void *, void *, cl_int *);
static cl_command_queue (*p_clCreateCommandQueue)(cl_context, cl_device_id, cl_ulong, cl_int *);
static cl_program (*p_clCreateProgramWithSource)(cl_context, cl_uint, const char **, const size_t *, cl_int *);
static cl_int (*p_clBuildProgram)(cl_program, cl_uint, const cl_device_id *, const char *, void *, void *);
static cl_int (*p_clGetProgramBuildInfo)(cl_program, cl_device_id, cl_uint, size_t, void *, size_t *);
static cl_kernel (*p_clCreateKernel)(cl_program, const char *, cl_int *);
static cl_mem (*p_clCreateBuffer)(cl_context, cl_ulong, cl_int, void *, cl_int *);
static cl_int (*p_clSetKernelArg)(cl_kernel, cl_uint, size_t, const void *);
static cl_int (*p_clEnqueueNDRangeKernel)(cl_command_queue, cl_kernel, cl_uint, const size_t *, const size_t *, const size_t *, cl_uint, const cl_event *, cl_event *);
static cl_int (*p_clFinish)(cl_command_queue);
static cl_int (*p_clEnqueueWriteBuffer)(cl_command_queue, cl_mem, cl_int, size_t, size_t, const void *, cl_uint, const cl_event *, cl_event *);
static cl_int (*p_clEnqueueReadBuffer)(cl_command_queue, cl_mem, cl_int, size_t, size_t, void *, cl_uint, const cl_event *, cl_event *);
static cl_int (*p_clReleaseMemObject)(cl_mem);

static double ocl_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint32_t ocl_env_u32(const char *n, uint32_t d) {
    const char *s = getenv(n);
    return (s && *s) ? (uint32_t)strtoul(s, NULL, 0) : d;
}

static int ocl_load(void) {
    void *h = dlopen("libOpenCL.so.1", RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) {
        return 0;
    }
#define SYM(f, n) do { f = (void *)dlsym(h, n); if (!f) return 0; } while (0)
    SYM(p_clGetPlatformIDs, "clGetPlatformIDs");
    SYM(p_clGetDeviceIDs, "clGetDeviceIDs");
    SYM(p_clGetDeviceInfo, "clGetDeviceInfo");
    SYM(p_clCreateContext, "clCreateContext");
    SYM(p_clCreateCommandQueue, "clCreateCommandQueue");
    SYM(p_clCreateProgramWithSource, "clCreateProgramWithSource");
    SYM(p_clBuildProgram, "clBuildProgram");
    SYM(p_clGetProgramBuildInfo, "clGetProgramBuildInfo");
    SYM(p_clCreateKernel, "clCreateKernel");
    SYM(p_clCreateBuffer, "clCreateBuffer");
    SYM(p_clSetKernelArg, "clSetKernelArg");
    SYM(p_clEnqueueNDRangeKernel, "clEnqueueNDRangeKernel");
    SYM(p_clFinish, "clFinish");
    SYM(p_clEnqueueWriteBuffer, "clEnqueueWriteBuffer");
    SYM(p_clEnqueueReadBuffer, "clEnqueueReadBuffer");
    SYM(p_clReleaseMemObject, "clReleaseMemObject");
#undef SYM
    return 1;
}

static cl_program ocl_build(const char *src, const char *name) {
    cl_int err = 0;
    size_t len = strlen(src);
    cl_program p = p_clCreateProgramWithSource(g_ocl.ctx, 1, &src, &len, &err);
    char log[8192];
    if (p == NULL || err != CL_SUCCESS) {
        return NULL;
    }
    err = p_clBuildProgram(p, 0, NULL, "-cl-std=CL2.0", NULL, NULL);
    if (err != CL_SUCCESS) {
        log[0] = 0;
        p_clGetProgramBuildInfo(p, NULL, CL_PROGRAM_BUILD_LOG, sizeof(log), log, NULL);
        fprintf(stderr, "opencl: %s build failed: %s\n", name, log);
        return NULL;
    }
    return p;
}

static int ocl_init(void) {
    cl_int err = 0;
    cl_platform_id plat[8];
    cl_device_id dev[8];
    cl_uint np = 0, nd = 0;
    size_t got = 0;

    if (g_ocl.state != 0) {
        return g_ocl.state == 1;
    }
    g_ocl.state = -1;
    if (getenv("ANUBIS_NO_OPENCL") != NULL && getenv("ANUBIS_NO_OPENCL")[0] != '0') {
        return 0;
    }
    if (!ocl_load()) {
        return 0;
    }
    if (p_clGetPlatformIDs(8, plat, &np) != CL_SUCCESS || np == 0) {
        return 0;
    }
    for (cl_uint i = 0; i < np; i++) {
        if (p_clGetDeviceIDs(plat[i], CL_DEVICE_TYPE_GPU, 8, dev, &nd) == CL_SUCCESS && nd > 0) {
            break;
        }
        if (p_clGetDeviceIDs(plat[i], CL_DEVICE_TYPE_ALL, 8, dev, &nd) == CL_SUCCESS && nd > 0) {
            break;
        }
    }
    if (nd == 0) {
        return 0;
    }
    g_ocl.dev_count = (int)nd;
    g_ocl.ctx = p_clCreateContext(NULL, 1, dev, NULL, NULL, &err);
    if (g_ocl.ctx == NULL || err != CL_SUCCESS) {
        return 0;
    }
    g_ocl.queue = p_clCreateCommandQueue(g_ocl.ctx, dev[0], 0, &err);
    if (g_ocl.queue == NULL || err != CL_SUCCESS) {
        return 0;
    }
    {
        char name[128];
        name[0] = 0;
        p_clGetDeviceInfo(dev[0], CL_DEVICE_NAME, sizeof(name), name, &got);
        snprintf(g_ocl.info, sizeof(g_ocl.info), "OpenCL: %s", name);
    }
    g_ocl.prog_sha = ocl_build(ocl_sha256_src, "sha256_pow");
    g_ocl.prog_a2 = ocl_build(ocl_argon2_src, "argon2id_pow");
    g_ocl.prog_hx = ocl_build(ocl_hashx_src, "hashx_pow");
    if (g_ocl.prog_sha) {
        g_ocl.k_sha = p_clCreateKernel(g_ocl.prog_sha, "sha256_pow", &err);
        if (g_ocl.k_sha == NULL) {
            g_ocl.prog_sha = NULL;
        }
    }
    if (g_ocl.prog_a2) {
        g_ocl.k_a2 = p_clCreateKernel(g_ocl.prog_a2, "argon2id_pow", &err);
        if (g_ocl.k_a2 == NULL) {
            g_ocl.prog_a2 = NULL;
        }
    }
    if (g_ocl.prog_hx) {
        g_ocl.k_hx = p_clCreateKernel(g_ocl.prog_hx, "hashx_pow", &err);
        if (g_ocl.k_hx == NULL) {
            g_ocl.prog_hx = NULL;
        }
    }
    g_ocl.sha_p = (cl_sha_params *)calloc(1, sizeof(cl_sha_params));
    g_ocl.sha_r = (cl_sha_results *)calloc(1, sizeof(cl_sha_results));
    g_ocl.a2_r = (cl_a2_results *)calloc(1, sizeof(cl_a2_results));
    g_ocl.hx_r = (cl_hx_results *)calloc(1, sizeof(cl_hx_results));
    g_ocl.sha_params = p_clCreateBuffer(g_ocl.ctx, sizeof(cl_sha_params), CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, g_ocl.sha_p, &err);
    g_ocl.sha_results = p_clCreateBuffer(g_ocl.ctx, sizeof(cl_sha_results), CL_MEM_READ_WRITE, NULL, &err);
    g_ocl.a2_challenge = p_clCreateBuffer(g_ocl.ctx, 4096, CL_MEM_READ_WRITE, NULL, &err);
    g_ocl.a2_results = p_clCreateBuffer(g_ocl.ctx, sizeof(cl_a2_results), CL_MEM_READ_WRITE, NULL, &err);
    g_ocl.hx_prog = p_clCreateBuffer(g_ocl.ctx, 512u * 16u, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, NULL, &err);
    g_ocl.hx_results = p_clCreateBuffer(g_ocl.ctx, sizeof(cl_hx_results), CL_MEM_READ_WRITE, NULL, &err);
    pthread_mutex_init(&g_ocl.mu, NULL);
    g_ocl.state = 1;
    return 1;
}

int anubis_opencl_available(void) {
    return ocl_init();
}

const char *anubis_opencl_info(void) {
    if (!ocl_init()) {
        return NULL;
    }
    return g_ocl.info;
}

static void ocl_hex(const uint32_t w[8], char out[65]) {
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

/* ------------------------------- SHA-256 ------------------------------- */

int anubis_opencl_solve(const uint32_t mid[8], uint32_t prefix_len, int mode,
                        int use_le, int difficulty, int check_bits,
                        uint64_t max_nonce, double budget_ms,
                        uint32_t *out_nonce, char out_hex[65],
                        double *out_ms) {
    double t0;
    uint32_t chunk;
    uint64_t base = 0, maxn;
    int rc = 1;

    if (!ocl_init() || g_ocl.k_sha == NULL) {
        return -1;
    }
    pthread_mutex_lock(&g_ocl.mu);
    t0 = ocl_now();
    memcpy(g_ocl.sha_p->mid, mid, 32);
    g_ocl.sha_p->prefix_len = prefix_len;
    g_ocl.sha_p->mode = (uint32_t)mode;
    g_ocl.sha_p->use_le = (uint32_t)use_le;
    g_ocl.sha_p->difficulty = (uint32_t)difficulty;
    g_ocl.sha_p->check_bits = (uint32_t)check_bits;
    chunk = ocl_env_u32("ANUBIS_OPENCL_CHUNK", 1u << 22);
    if (chunk < 4096u) chunk = 4096u;
    if (chunk > (1u << 24)) chunk = 1u << 24;
    maxn = max_nonce > 0xFFFFFFFFull ? 0xFFFFFFFFull : max_nonce;
    while (base <= maxn) {
        uint64_t rem = maxn - base + 1;
        uint32_t count = (uint32_t)(rem < (uint64_t)chunk ? rem : (uint64_t)chunk);
        size_t gsz = count, lsz = 1;
        cl_int err;
        if (count == 0) break;
        g_ocl.sha_p->base_nonce = (uint32_t)base;
        g_ocl.sha_p->chunk = count;
        memset(g_ocl.sha_r, 0, sizeof(*g_ocl.sha_r));
        p_clEnqueueWriteBuffer(g_ocl.queue, g_ocl.sha_params, CL_TRUE, 0, sizeof(*g_ocl.sha_p), g_ocl.sha_p, 0, NULL, NULL);
        p_clEnqueueWriteBuffer(g_ocl.queue, g_ocl.sha_results, CL_TRUE, 0, sizeof(*g_ocl.sha_r), g_ocl.sha_r, 0, NULL, NULL);
        err = p_clSetKernelArg(g_ocl.k_sha, 0, sizeof(cl_mem), &g_ocl.sha_params);
        err |= p_clSetKernelArg(g_ocl.k_sha, 1, sizeof(cl_mem), &g_ocl.sha_results);
        if (err != CL_SUCCESS) { rc = -1; break; }
        err = p_clEnqueueNDRangeKernel(g_ocl.queue, g_ocl.k_sha, 1, NULL, &gsz, &lsz, 0, NULL, NULL);
        if (err != CL_SUCCESS) { rc = -1; break; }
        p_clFinish(g_ocl.queue);
        p_clEnqueueReadBuffer(g_ocl.queue, g_ocl.sha_results, CL_TRUE, 0, sizeof(*g_ocl.sha_r), g_ocl.sha_r, 0, NULL, NULL);
        if (g_ocl.sha_r->count > 0) {
            ocl_hex(g_ocl.sha_r->hashes[0], out_hex);
            *out_nonce = g_ocl.sha_r->nonces[0];
            if (out_ms) *out_ms = (ocl_now() - t0) * 1000.0;
            rc = 0;
            break;
        }
        base += count;
        if (budget_ms > 0.0 && (ocl_now() - t0) * 1000.0 > budget_ms) { rc = 1; break; }
    }
    pthread_mutex_unlock(&g_ocl.mu);
    return rc;
}

/* ------------------------------ Argon2id ------------------------------- */

int anubis_opencl_argon2_available(void) {
    return ocl_init() && g_ocl.k_a2 != NULL;
}

const char *anubis_opencl_argon2_info(void) {
    return anubis_opencl_available() ? g_ocl.info : NULL;
}

static int a2_dispatch_cl(const uint8_t *challenge, uint32_t clen, int use_le,
                          int difficulty, uint32_t base, uint32_t count) {
    cl_int err;
    cl_uint u_clen = clen, u_le = (cl_uint)use_le, u_diff = (cl_uint)difficulty;
    cl_uint u_base = base, u_count = count;
    size_t gsz = count, lsz = 32;
    memset(g_ocl.a2_r, 0, sizeof(*g_ocl.a2_r));
    p_clEnqueueWriteBuffer(g_ocl.queue, g_ocl.a2_results, CL_TRUE, 0, sizeof(*g_ocl.a2_r), g_ocl.a2_r, 0, NULL, NULL);
    if (clen > 0) {
        p_clEnqueueWriteBuffer(g_ocl.queue, g_ocl.a2_challenge, CL_TRUE, 0, clen, challenge, 0, NULL, NULL);
    }
    err = p_clSetKernelArg(g_ocl.k_a2, 0, sizeof(cl_mem), &g_ocl.a2_challenge);
    err |= p_clSetKernelArg(g_ocl.k_a2, 1, sizeof(cl_uint), &u_clen);
    err |= p_clSetKernelArg(g_ocl.k_a2, 2, sizeof(cl_uint), &u_le);
    err |= p_clSetKernelArg(g_ocl.k_a2, 3, sizeof(cl_uint), &u_diff);
    err |= p_clSetKernelArg(g_ocl.k_a2, 4, sizeof(cl_uint), &u_base);
    err |= p_clSetKernelArg(g_ocl.k_a2, 5, sizeof(cl_uint), &u_count);
    err |= p_clSetKernelArg(g_ocl.k_a2, 6, sizeof(cl_mem), &g_ocl.a2_mem);
    err |= p_clSetKernelArg(g_ocl.k_a2, 7, sizeof(cl_mem), &g_ocl.a2_results);
    if (err != CL_SUCCESS) return -1;
    if (p_clEnqueueNDRangeKernel(g_ocl.queue, g_ocl.k_a2, 1, NULL, &gsz, &lsz, 0, NULL, NULL) != CL_SUCCESS) return -1;
    p_clFinish(g_ocl.queue);
    p_clEnqueueReadBuffer(g_ocl.queue, g_ocl.a2_results, CL_TRUE, 0, sizeof(*g_ocl.a2_r), g_ocl.a2_r, 0, NULL, NULL);
    return 0;
}

int anubis_opencl_argon2_solve(const uint8_t *challenge, size_t clen, int use_le,
                               int difficulty, uint64_t max_nonce,
                               double budget_ms, uint32_t *out_nonce,
                               char out_hex[65], double *out_ms) {
    double t0;
    uint64_t base = 0, maxn;
    int rc = 1;

    if (!anubis_opencl_argon2_available()) {
        return -1;
    }
    pthread_mutex_lock(&g_ocl.mu);
    if (g_ocl.a2_mem == NULL) {
        cl_int err;
        g_ocl.a2_mem = p_clCreateBuffer(g_ocl.ctx,
                                        (size_t)A2_LANES * (A2_M + 3u) * 1024u,
                                        CL_MEM_READ_WRITE, NULL, &err);
        if (g_ocl.a2_mem == NULL) {
            pthread_mutex_unlock(&g_ocl.mu);
            return -1;
        }
    }
    t0 = ocl_now();
    maxn = max_nonce > 0xFFFFFFFFull ? 0xFFFFFFFFull : max_nonce;
    while (base <= maxn) {
        uint64_t rem = maxn - base + 1;
        uint32_t count = (uint32_t)(rem < (uint64_t)A2_LANES ? rem : (uint64_t)A2_LANES);
        if (count == 0) break;
        if (a2_dispatch_cl(challenge, (uint32_t)clen, use_le, difficulty,
                           (uint32_t)base, count) != 0) {
            rc = -1;
            break;
        }
        if (g_ocl.a2_r->count > 0) {
            ocl_hex(g_ocl.a2_r->hashes[0], out_hex);
            *out_nonce = g_ocl.a2_r->nonces[0];
            if (out_ms) *out_ms = (ocl_now() - t0) * 1000.0;
            rc = 0;
            break;
        }
        base += count;
        if (budget_ms > 0.0 && (ocl_now() - t0) * 1000.0 > budget_ms) { rc = 1; break; }
    }
    pthread_mutex_unlock(&g_ocl.mu);
    return rc;
}

/* -------------------------------- HashX -------------------------------- */

int anubis_opencl_hashx_available(void) {
    return ocl_init() && g_ocl.k_hx != NULL;
}

const char *anubis_opencl_hashx_info(void) {
    return anubis_opencl_available() ? g_ocl.info : NULL;
}

static int hx_dispatch_cl(const uint32_t *prog, uint32_t code_size,
                          const uint64_t keys[4], uint32_t difficulty,
                          uint32_t base, uint32_t count) {
    cl_int err;
    cl_uint u_code = code_size, u_diff = difficulty, u_base = base, u_count = count;
    cl_ulong k0 = keys[0], k1 = keys[1], k2 = keys[2], k3 = keys[3];
    size_t gsz = ((size_t)count + 255u) & ~(size_t)255u, lsz = 256;
    memset(g_ocl.hx_r, 0, sizeof(*g_ocl.hx_r));
    p_clEnqueueWriteBuffer(g_ocl.queue, g_ocl.hx_prog, CL_TRUE, 0,
                           code_size * 16u, prog, 0, NULL, NULL);
    p_clEnqueueWriteBuffer(g_ocl.queue, g_ocl.hx_results, CL_TRUE, 0,
                           sizeof(*g_ocl.hx_r), g_ocl.hx_r, 0, NULL, NULL);
    err = p_clSetKernelArg(g_ocl.k_hx, 0, sizeof(cl_mem), &g_ocl.hx_prog);
    err |= p_clSetKernelArg(g_ocl.k_hx, 1, sizeof(cl_uint), &u_code);
    err |= p_clSetKernelArg(g_ocl.k_hx, 2, sizeof(cl_ulong), &k0);
    err |= p_clSetKernelArg(g_ocl.k_hx, 3, sizeof(cl_ulong), &k1);
    err |= p_clSetKernelArg(g_ocl.k_hx, 4, sizeof(cl_ulong), &k2);
    err |= p_clSetKernelArg(g_ocl.k_hx, 5, sizeof(cl_ulong), &k3);
    err |= p_clSetKernelArg(g_ocl.k_hx, 6, sizeof(cl_uint), &u_diff);
    err |= p_clSetKernelArg(g_ocl.k_hx, 7, sizeof(cl_uint), &u_base);
    err |= p_clSetKernelArg(g_ocl.k_hx, 8, sizeof(cl_uint), &u_count);
    err |= p_clSetKernelArg(g_ocl.k_hx, 9, sizeof(cl_mem), &g_ocl.hx_results);
    if (err != CL_SUCCESS) return -1;
    if (p_clEnqueueNDRangeKernel(g_ocl.queue, g_ocl.k_hx, 1, NULL, &gsz, &lsz, 0, NULL, NULL) != CL_SUCCESS) return -1;
    p_clFinish(g_ocl.queue);
    p_clEnqueueReadBuffer(g_ocl.queue, g_ocl.hx_results, CL_TRUE, 0,
                          sizeof(*g_ocl.hx_r), g_ocl.hx_r, 0, NULL, NULL);
    return 0;
}

int anubis_opencl_hashx_solve(const void *state, size_t state_size,
                              int difficulty, uint64_t max_nonce,
                              double budget_ms, uint32_t *out_nonce,
                              char out_hex[65], double *out_ms) {
    uint64_t keys[4];
    static uint32_t prog[512 * 4];
    size_t ninstr = 0;
    uint32_t chunk;
    uint64_t base = 0, maxn;
    double t0;
    int rc = 1;

    if (state == NULL || out_nonce == NULL || out_hex == NULL) {
        return -1;
    }
    if (hashx_export(state, state_size, keys, prog, &ninstr) != 0 ||
        !anubis_opencl_hashx_available()) {
        return -1;
    }
    pthread_mutex_lock(&g_ocl.mu);
    t0 = ocl_now();
    chunk = ocl_env_u32("ANUBIS_OPENCL_HASHX_CHUNK", 1u << 22);
    if (chunk < 1024u) chunk = 1024u;
    if (chunk > (1u << 24)) chunk = 1u << 24;
    maxn = max_nonce > 0xFFFFFFFFull ? 0xFFFFFFFFull : max_nonce;
    while (base <= maxn) {
        uint64_t rem = maxn - base + 1;
        uint32_t count = (uint32_t)(rem < (uint64_t)chunk ? rem : (uint64_t)chunk);
        if (count == 0) break;
        if (hx_dispatch_cl(prog, (uint32_t)ninstr, keys, (uint32_t)difficulty,
                           (uint32_t)base, count) != 0) {
            rc = -1;
            break;
        }
        if (g_ocl.hx_r->count > 0) {
            ocl_hex(g_ocl.hx_r->hashes[0], out_hex);
            *out_nonce = g_ocl.hx_r->nonces[0];
            if (out_ms) *out_ms = (ocl_now() - t0) * 1000.0;
            rc = 0;
            break;
        }
        base += count;
        if (budget_ms > 0.0 && (ocl_now() - t0) * 1000.0 > budget_ms) { rc = 1; break; }
    }
    pthread_mutex_unlock(&g_ocl.mu);
    return rc;
}
