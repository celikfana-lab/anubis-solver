/*
 * anubis_solver.c — native proof-of-work engine for TecharoHQ/anubis challenges.
 *
 * This file is the C core of the Python library in anubis_solver.py. It is
 * built as a shared object and loaded with ctypes.
 *
 * It understands the two SHA-256 based challenge families shipped by Anubis:
 *
 *  1. JavaScript "fast"/"slow" challenges (lib/challenge/proofofwork):
 *       message  = challenge_hex_string || decimal_nonce
 *       digest   = sha256(message)
 *       accepted when the *hex encoding* of the digest starts with
 *       `difficulty` zero nibbles (i.e. difficulty/2 zero bytes, plus a
 *       zero high nibble when difficulty is odd).
 *
 *  2. WebAssembly "sha256" challenge (wasm/pow/sha256/src/lib.rs):
 *       data     = hex_decode(challenge_hex_string)      (random bytes)
 *       message  = data || uint32_nonce
 *       nonce encoding is little-endian when data[len-1] >= 0x80,
 *       big-endian otherwise (an anti-GPU measure in Anubis)
 *       digest   = sha256(message)
 *       accepted when the *raw digest* starts with `difficulty` zero bits.
 *
 *  3. WebAssembly "argon2id" challenge (wasm/pow/argon2id/src/lib.rs):
 *       password = hex_decode(challenge)
 *       salt     = uint64_nonce, encoded LE when data[len-1] >= 0x80 else BE
 *       hash     = Argon2id(password, salt, m=19456 KiB, t=2, p=1), 32 bytes
 *       accepted when the raw digest starts with `difficulty` zero bits.
 *
 *  4. WebAssembly "hashx" challenge (wasm/pow/hashx/src/lib.rs):
 *       program  = HashX(seed = challenge bytes, with the seed-retry loop)
 *       hash     = hashx_hash_to_bytes(uint64_nonce), 32 bytes
 *       accepted when the raw digest starts with `difficulty` zero bits.
 *
 * Bundled code:
 *   - argon2/  : the reference Argon2 implementation (CC0 / Apache-2.0),
 *                used for the argon2id challenge.
 *   - hashx.c  : C port of tevador/hashx (LGPL-3.0), used for the hashx
 *                challenge. See the header of that file for provenance.
 *
 * Every worker thread owns a copy of the SHA-256 midstate after consuming the
 * fixed challenge prefix, so each nonce candidate only has to hash its own
 * suffix (the decimal digits or the 4 nonce bytes).
 *
 * On x86-64 the hot loops are hand-written assembly:
 *   avx2.s  — sha256_compress8_avx2(), eight candidate messages in one
 *             SHA-256 compression (one __m256i = the same word of 8 messages)
 *   shani.s — sha256_block_shani(), one block via the Intel SHA extension
 * Runtime dispatch picks SHA-NI for single-block hashing and AVX2 for the
 * 8-way batch, falling back to portable C. ANUBIS_NO_AVX2=1 /
 * ANUBIS_NO_SHANI=1 force the lower paths for A/B measurements.
 *
 * Build:  make            (see Makefile)
 * Test:   make check
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__linux__)
#include <sched.h>
#include <unistd.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

/* One CPU count for both platforms. On Windows sysconf(_SC_NPROCESSORS_ONLN)
 * does not exist, so ask the kernel for the processor groups instead; the
 * affinity helpers below already compile to no-ops off Linux. */
static int anubis_cpu_count(void) {
#if defined(_WIN32)
    DWORD n = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    return n > 0 ? (int)n : 1;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
#endif
}

#if defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
#if defined(__has_include)
#if __has_include(<asm/hwcap.h>)
#include <asm/hwcap.h>
#endif
#endif
#ifndef HWCAP_SHA2
#define HWCAP_SHA2 (1UL << 6)
#endif
#endif

#include "anubis-solver.h"
#include "argon2.h"
#include "hashx.h"
#include "meatrider/meatrider.h"
#include "meatrider/meatrider_backend.h"
#include "meatrider/meatrider_simd.h"

#if defined(ANUBIS_HAVE_VULKAN)
extern int anubis_vulkan_available(void);
extern const char *anubis_vulkan_info(void);
extern int anubis_vulkan_hashx_available(void);
extern int anubis_vulkan_hashx_solve(const void *state, size_t state_size,
                                     int difficulty, uint64_t max_nonce,
                                     double budget_ms, uint32_t *out_nonce,
                                     char out_hex[65], double *out_ms);

extern int anubis_vulkan_argon2_available(void);
extern int anubis_vulkan_argon2_solve(const uint8_t *challenge, size_t clen,
                                      int use_le, int difficulty,
                                      uint64_t max_nonce, double budget_ms,
                                      uint32_t *out_nonce, char out_hex[65],
                                      double *out_ms);

extern int anubis_vulkan_solve(const uint32_t mid[8], uint32_t prefix_len,
                               int mode, int use_le, int difficulty,
                               int check_bits, uint64_t max_nonce,
                               double budget_ms, uint32_t *out_nonce,
                               char out_hex[65], double *out_ms);

/* Break-even differs between the two shader modes: the fixed-nonce path is
 * cheaper per candidate, so it pays off at lower difficulty. */
static uint64_t vulkan_min_work(int bits_mode) {
    const char *s = getenv("ANUBIS_VULKAN_MIN_WORK");
    if (s != NULL && *s != '\0') {
        return strtoull(s, NULL, 0);
    }
    return bits_mode ? (1ull << 16) : (1ull << 20);
}
#endif

/* Google TPU through the PJRT C API. The plugin (libtpu.so) is dlopen()ed by
 * the backend itself; on a TPU VM there is no GPU, and on a GPU box there is
 * no libtpu, so the two never fight over a device. */
#if defined(ANUBIS_HAVE_TPU)
#include "tpu_backend.h"

/* Same escape hatch as ANUBIS_NO_CUDA and friends; a TPU VM is a shared
 * resource and one process may own the chip, so being able to say "cpu only"
 * matters more here than anywhere else. */
static int tpu_enabled(void) {
    const char *e = getenv("ANUBIS_NO_TPU");
    return e == NULL || e[0] == '\0' || e[0] == '0';
}

/*
 * The TPU has a cost the GPUs do not: the challenge bytes are baked into the
 * StableHLO module, so every *new* challenge is a fresh compile (~1.3 s on a
 * v5e, see results/sha256-tpu-2026-11-15.json) before the first nonce is
 * tested. At the 343 MHash/s that client measured, 2^28 nonces is ~0.8 s of
 * search on either side of that compile, which is the point where a TPU still
 * beats a CPU core that would take seconds. The GPU default (2^16) would make
 * every ordinary Anubis challenge pay a compile to do 0.2 ms of work.
 */
static uint64_t tpu_min_work(int bits_mode) {
    const char *s = getenv("ANUBIS_TPU_MIN_WORK");
    if (s != NULL && *s != '\0') {
        return strtoull(s, NULL, 0);
    }
    return bits_mode ? (1ull << 28) : (1ull << 20);
}
#endif

#if defined(ANUBIS_HAVE_LEVELZERO)
extern int anubis_l0_available(void);
extern const char *anubis_l0_info(void);
extern int anubis_l0_solve(const uint32_t mid[8], uint32_t prefix_len,
                           int mode, int use_le, int difficulty,
                           int check_bits, uint64_t max_nonce,
                           double budget_ms, uint32_t *out_nonce,
                           char out_hex[65], double *out_ms);

extern int anubis_l0_hashx_available(void);
extern int anubis_l0_hashx_solve(const void *state, size_t state_size,
                                 int difficulty, uint64_t max_nonce,
                                 double budget_ms, uint32_t *out_nonce,
                                 char out_hex[65], double *out_ms);

extern int anubis_l0_argon2_available(void);
extern int anubis_l0_argon2_solve(const uint8_t *challenge, size_t clen,
                                  int use_le, int difficulty,
                                  uint64_t max_nonce, double budget_ms,
                                  uint32_t *out_nonce, char out_hex[65],
                                  double *out_ms);

static uint64_t l0_min_work(int bits_mode) {
    const char *s = getenv("ANUBIS_L0_MIN_WORK");
    if (s != NULL && *s != '\0') {
        return strtoull(s, NULL, 0);
    }
    return bits_mode ? (1ull << 16) : (1ull << 20);
}
#endif

#if defined(ANUBIS_HAVE_OPENCL)
extern int anubis_opencl_available(void);
extern const char *anubis_opencl_info(void);
extern int anubis_opencl_solve(const uint32_t mid[8], const uint8_t *prefix,
                               uint32_t prefix_len, int mode, int use_le,
                               int difficulty, int check_bits, uint64_t max_nonce,
                               double budget_ms, uint32_t *out_nonce,
                               char out_hex[65], double *out_ms);

static uint64_t opencl_min_work(int bits_mode) {
    const char *s = getenv("ANUBIS_OPENCL_MIN_WORK");
    if (s != NULL && *s != '\0') {
        return strtoull(s, NULL, 0);
    }
    return bits_mode ? (1ull << 16) : (1ull << 20);
}

#if defined(ANUBIS_HAVE_CUDA)
extern int anubis_cuda_available(void);
#endif

/* OpenCL goes last in the chain: it is the portable path, not the fast one.
 * On this laptop (Intel Xe, IGC) it measures 195 M sha256/s against Vulkan's
 * 70 M, so ANUBIS_OPENCL=1 is worth knowing about, but the vendor backends
 * above keep their place by default. Unset means "only if nothing else". */
static int opencl_enabled(void) {
    const char *e = getenv("ANUBIS_OPENCL");
    if (e != NULL && e[0] != '\0') {
        return e[0] != '0';
    }
#if defined(ANUBIS_HAVE_CUDA)
    if (anubis_cuda_available()) {
        return 0;
    }
#endif
#if defined(ANUBIS_HAVE_LEVELZERO)
    if (anubis_l0_available()) {
        return 0;
    }
#endif
#if defined(ANUBIS_HAVE_VULKAN)
    if (anubis_vulkan_available()) {
        return 0;
    }
#endif
    return 1;
}
#endif

#if defined(ANUBIS_HAVE_CUDA)
extern int anubis_cuda_available(void);
extern const char *anubis_cuda_info(void);
extern int anubis_cuda_solve(const uint32_t mid[8], uint32_t prefix_len,
                             int mode, int use_le, int difficulty,
                             int check_bits, uint64_t max_nonce,
                             double budget_ms, uint32_t *out_nonce,
                             char out_hex[65], double *out_ms);

extern int anubis_cuda_argon2_available(void);
extern int anubis_cuda_hashx_available(void);
extern int anubis_cuda_tensor_available(void);
extern const char *anubis_cuda_tensor_info(void);
extern int anubis_cuda_tensor_c(const uint8_t seed[32], int n, int32_t *c_host,
                                double *out_ms);
extern int anubis_cuda_hashx_solve(const void *state, size_t state_size,
                                   int difficulty, uint64_t max_nonce,
                                   double budget_ms, uint32_t *out_nonce,
                                   char out_hex[65], double *out_ms);
extern int anubis_cuda_argon2_solve(const uint8_t *challenge, size_t clen,
                                    int use_le, int difficulty,
                                    uint64_t max_nonce, double budget_ms,
                                    uint32_t *out_nonce, char out_hex[65],
                                    double *out_ms);

static uint64_t cuda_min_work(int bits_mode) {
    const char *s = getenv("ANUBIS_CUDA_MIN_WORK");
    if (s != NULL && *s != '\0') {
        return strtoull(s, NULL, 0);
    }
    return bits_mode ? (1ull << 16) : (1ull << 20);
}
#endif

static int vulkan_hashx_enabled(void) {
    const char *e = getenv("ANUBIS_VULKAN_HASHX");
    return e != NULL && e[0] != '\0' && e[0] != '0';
}

static int l0_hashx_enabled(void) {
    const char *e = getenv("ANUBIS_L0_HASHX");
    return e != NULL && e[0] != '\0' && e[0] != '0';
}

static int gpu_hashx_enabled(void) {
    const char *e = getenv("ANUBIS_GPU_HASHX");
    return e != NULL && e[0] != '\0' && e[0] != '0';
}

#if defined(ANUBIS_HAVE_CUDA) || defined(ANUBIS_HAVE_LEVELZERO) || defined(ANUBIS_HAVE_VULKAN)
static int gpu_argon2_enabled(void) {
    const char *e = getenv("ANUBIS_GPU_ARGON2");
    return e != NULL && e[0] != '\0' && e[0] != '0';
}
#endif

/* defined later; used to re-verify GPU results */
int anubis_verify_nibbles(const char *challenge, uint64_t nonce,
                                        int difficulty, char *out_hex);
int anubis_verify_bits(const char *challenge_hex, uint32_t nonce,
                                     int difficulty, char *out_hex);
int anubis_verify_argon2id(const char *challenge_hex, uint32_t nonce,
                           int difficulty, char *out_hex);
int anubis_verify_hashx(const char *challenge_hex, uint32_t nonce,
                        int difficulty, char *out_hex);

#ifdef __GNUC__
#define ANUBIS_EXPORT __attribute__((visibility("default")))
#else
#define ANUBIS_EXPORT
#endif


/* ------------------------------------------------------------------ */
/* CPU affinity: prefer the P-cores on hybrid CPUs                     */
/* ------------------------------------------------------------------ */
/* Alder Lake and friends expose P-cores via /sys/devices/cpu_core.  The
 * E-cores are much slower for SHA-256, so the default is to pin worker
 * threads to the physical P-cores (one thread per core first, then SMT
 * siblings) and to size the default thread count accordingly.
 *
 * ANUBIS_CPU_AFFINITY:
 *   unset / "pcores"  pin to the P-core set (default)
 *   "off" / "all" / "0" do not pin
 *   "0,2,4,6" or "0-3" pin to that explicit CPU set
 */

#define ANUBIS_MAX_CPUS 1024

static int g_pcpus[ANUBIS_MAX_CPUS];
static int g_npcpu;          /* all CPUs in the chosen set */
static int g_npcpu_phys;     /* one CPU per physical core */
static int g_pin_enabled;
static pthread_once_t g_affinity_once = PTHREAD_ONCE_INIT;
static char g_affinity_info[160] = "off";

static int read_small_file(const char *path, char *buf, size_t cap) {
    FILE *f = fopen(path, "r");
    size_t n;
    if (f == NULL) {
        return -1;
    }
    n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = '\0';
    return 0;
}

static int parse_cpu_mask(const char *s, unsigned char *mask, int max) {
    int any = 0;
    const char *p = s;
    memset(mask, 0, (size_t)max);
    while (*p != '\0') {
        char *end = NULL;
        long a = strtol(p, &end, 10);
        long b = a;
        if (end == p) {
            break;
        }
        p = end;
        if (*p == '-') {
            p++;
            b = strtol(p, &end, 10);
            if (end == p) {
                break;
            }
            p = end;
        }
        if (a >= 0 && b >= a && b < max) {
            for (long i = a; i <= b; i++) {
                mask[i] = 1;
            }
            any = 1;
        }
        if (*p == ',') {
            p++;
        }
    }
    return any;
}

static int read_core_id(int cpu) {
    char path[128];
    char buf[64];
    long pkg = 0;
    long core;

    /* core_id is per package, so combine it with the package id; otherwise
     * the second socket's cores look like duplicates of the first one's. */
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
    if (read_small_file(path, buf, sizeof(buf)) == 0) {
        pkg = strtol(buf, NULL, 10);
    }
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/topology/core_id",
             cpu);
    if (read_small_file(path, buf, sizeof(buf)) != 0) {
        return -1;
    }
    core = strtol(buf, NULL, 10);
    if (pkg < 0 || pkg > 1023) {
        pkg = 0;
    }
    return (int)(pkg * 1024 + core);
}

static int read_max_freq(int cpu) {
    char path[128];
    char buf[64];
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
    if (read_small_file(path, buf, sizeof(buf)) != 0) {
        return -1;
    }
    return (int)strtol(buf, NULL, 10);
}

static void build_ordered_set(const unsigned char *mask, int ncpu) {
    int core_seen[ANUBIS_MAX_CPUS];
    unsigned char chosen[ANUBIS_MAX_CPUS];
    int ncores = 0;
    int i, pass;

    g_npcpu = 0;
    g_npcpu_phys = 0;
    for (i = 0; i < ncpu; i++) {
        core_seen[i] = -1;
        chosen[i] = 0;
    }
    /* first one CPU per physical core, then the SMT siblings */
    for (pass = 0; pass < 2; pass++) {
        for (i = 0; i < ncpu; i++) {
            int cid, j, seen = 0;
            if (!mask[i]) {
                continue;
            }
            cid = read_core_id(i);
            if (cid < 0) {
                cid = i; /* no topology info: treat as its own core */
            }
            for (j = 0; j < ncores; j++) {
                if (core_seen[j] == cid) {
                    seen = 1;
                    break;
                }
            }
            if (pass == 0 && !seen) {
                core_seen[ncores++] = cid;
                g_pcpus[g_npcpu++] = i;
                chosen[i] = 1;
                g_npcpu_phys++;
            } else if (pass == 1 && seen && !chosen[i]) {
                g_pcpus[g_npcpu++] = i;
            }
        }
    }
}

static void init_affinity_once(void) {
    const char *env = getenv("ANUBIS_CPU_AFFINITY");
    unsigned char mask[ANUBIS_MAX_CPUS];
    int ncpu = anubis_cpu_count();
    char buf[512];
    int i;

    if (ncpu > ANUBIS_MAX_CPUS) {
        ncpu = ANUBIS_MAX_CPUS;
    }
    g_pin_enabled = 0;
    g_npcpu = 0;
    g_npcpu_phys = 0;

    if (env != NULL && (strcmp(env, "off") == 0 || strcmp(env, "all") == 0 ||
                        strcmp(env, "0") == 0 || strcmp(env, "none") == 0)) {
        snprintf(g_affinity_info, sizeof(g_affinity_info), "off");
        return;
    }

    if (env != NULL && *env != '\0' && strcmp(env, "pcores") != 0 &&
        strcmp(env, "auto") != 0) {
        /* explicit CPU set */
        if (!parse_cpu_mask(env, mask, ncpu)) {
            snprintf(g_affinity_info, sizeof(g_affinity_info), "off (bad mask)");
            return;
        }
        build_ordered_set(mask, ncpu);
    } else {
        /* default: P-cores from the hybrid PMU, else by max frequency */
        memset(mask, 0, sizeof(mask));
        if (read_small_file("/sys/devices/cpu_core/cpus", buf, sizeof(buf)) == 0 &&
            parse_cpu_mask(buf, mask, ncpu)) {
            /* got the P-core set */
        } else {
            int best = 0;
            int freqs[ANUBIS_MAX_CPUS];
            for (i = 0; i < ncpu; i++) {
                freqs[i] = read_max_freq(i);
                if (freqs[i] > best) {
                    best = freqs[i];
                }
            }
            if (best <= 0) {
                snprintf(g_affinity_info, sizeof(g_affinity_info), "off");
                return;
            }
            for (i = 0; i < ncpu; i++) {
                if (freqs[i] > 0 && freqs[i] * 10 >= best * 8) {
                    mask[i] = 1;
                }
            }
        }
        build_ordered_set(mask, ncpu);
    }

    if (g_npcpu == 0) {
        snprintf(g_affinity_info, sizeof(g_affinity_info), "off (no cores)");
        return;
    }
    g_pin_enabled = 1;
    {
        size_t off = 0;
        off += (size_t)snprintf(g_affinity_info + off,
                                sizeof(g_affinity_info) - off, "pcores:");
        for (i = 0; i < g_npcpu_phys && off < sizeof(g_affinity_info); i++) {
            off += (size_t)snprintf(g_affinity_info + off,
                                    sizeof(g_affinity_info) - off, "%s%d",
                                    i ? "," : "", g_pcpus[i]);
        }
        if (g_npcpu > g_npcpu_phys) {
            off += (size_t)snprintf(g_affinity_info + off,
                                    sizeof(g_affinity_info) - off, " +%d SMT",
                                    g_npcpu - g_npcpu_phys);
        }
        snprintf(g_affinity_info + off, sizeof(g_affinity_info) - off,
                 " (%d physical)", g_npcpu_phys);
    }
}

static void pin_current_thread(int tid) {
    pthread_once(&g_affinity_once, init_affinity_once);
#if defined(__linux__)
    cpu_set_t set;
    if (!g_pin_enabled || g_npcpu == 0) {
        return;
    }
    CPU_ZERO(&set);
    CPU_SET(g_pcpus[tid % g_npcpu], &set);
    (void)sched_setaffinity(0, sizeof(set), &set);
#else
    (void)tid;
#endif
}

ANUBIS_EXPORT
int anubis_default_threads(void) {
    pthread_once(&g_affinity_once, init_affinity_once);
    if (g_pin_enabled && g_npcpu_phys > 0) {
        return g_npcpu_phys;
    }
    return anubis_cpu_count();
}

ANUBIS_EXPORT
const char *anubis_cpu_affinity_info(void) {
    pthread_once(&g_affinity_once, init_affinity_once);
    return g_affinity_info;
}

/* ------------------------------------------------------------------ */
/* Return codes                                                        */
/* ------------------------------------------------------------------ */

#define ANUBIS_OK 0          /* solved / verified                          */
#define ANUBIS_ERR_ARG 1     /* bad argument                               */
#define ANUBIS_ERR_UNSOLVED 2/* search space / time budget exhausted       */
#define ANUBIS_ERR_INTERNAL 3/* thread or allocation failure               */

/* GPU hit verification: one reference hash per accepted hit (not per
 * candidate). Disable with anubis_set_gpu_verify(0), ANUBIS_GPU_NO_VERIFY=1
 * or --no-verify-gpu; only useful for benchmarking. */
static int g_gpu_verify = -1;

ANUBIS_EXPORT
void anubis_set_gpu_verify(int enable) {
    g_gpu_verify = enable ? 1 : 0;
}

ANUBIS_EXPORT
int anubis_gpu_verify(void) {
    if (g_gpu_verify >= 0) {
        return g_gpu_verify;
    }
    {
        const char *e = getenv("ANUBIS_GPU_NO_VERIFY");
        return !(e != NULL && e[0] != '\0' && e[0] != '0');
    }
}

/* TPU hit verification. Independent knob so a TPU-only disable does not weaken
 * the other backends; inherits ANUBIS_GPU_NO_VERIFY and anubis_set_gpu_verify().
 * Defaults to -1 (unset) so the env / the inherited switch decides. */
static int g_tpu_verify = -1;

ANUBIS_EXPORT
void anubis_set_tpu_verify(int enable) {
    /* -1 resets to "unset", so the env var / inherited switch decides again. */
    g_tpu_verify = (enable < 0) ? -1 : (enable ? 1 : 0);
}

ANUBIS_EXPORT
int anubis_tpu_verify(void) {
    const char *e;
    if (g_tpu_verify >= 0) {
        return g_tpu_verify;
    }
    e = getenv("ANUBIS_TPU_NO_VERIFY");
    if (e != NULL && e[0] != '\0' && e[0] != '0') {
        return 0;
    }
    return anubis_gpu_verify();
}

#if !defined(ANUBIS_HAVE_TPU)
/* The public header declares the TPU entry points in every build; without the
 * backend they report "unavailable" instead of failing to link. Same shape as
 * the verify knobs above, which are unconditional too. */
ANUBIS_EXPORT
int anubis_tpu_available(void) {
    return 0;
}

ANUBIS_EXPORT
const char *anubis_tpu_info(void) {
    return NULL;
}

ANUBIS_EXPORT
int anubis_tpu_solve(const uint8_t *challenge, uint32_t challenge_len,
                     int difficulty, int use_le, uint64_t max_nonce,
                     double budget_ms, uint32_t *out_nonce, char *out_hex,
                     double *out_ms) {
    (void)challenge;
    (void)challenge_len;
    (void)difficulty;
    (void)use_le;
    (void)max_nonce;
    (void)budget_ms;
    (void)out_nonce;
    (void)out_hex;
    (void)out_ms;
    return -1;
}
#endif

#if defined(ANUBIS_HAVE_CUDA) || defined(ANUBIS_HAVE_LEVELZERO) || \
    defined(ANUBIS_HAVE_VULKAN) || defined(ANUBIS_HAVE_OPENCL)
static int gpu_hit_ok_nibbles(const char *ch, uint64_t nonce, int diff,
                              const char *hex) {
    char v[65];
    if (!anubis_gpu_verify()) return 1;
    return anubis_verify_nibbles(ch, nonce, diff, v) == ANUBIS_OK &&
           memcmp(v, hex, 65) == 0;
}
static int gpu_hit_ok_bits(const char *ch, uint32_t nonce, int diff,
                           const char *hex) {
    char v[65];
    if (!anubis_gpu_verify()) return 1;
    return anubis_verify_bits(ch, nonce, diff, v) == ANUBIS_OK &&
           memcmp(v, hex, 65) == 0;
}
static int gpu_hit_ok_argon2id(const char *ch, uint32_t nonce, int diff,
                               const char *hex) {
    char v[65];
    if (!anubis_gpu_verify()) return 1;
    return anubis_verify_argon2id(ch, nonce, diff, v) == ANUBIS_OK &&
           memcmp(v, hex, 65) == 0;
}
static int gpu_hit_ok_hashx(const char *ch, uint32_t nonce, int diff,
                            const char *hex) {
    char v[65];
    if (!anubis_gpu_verify()) return 1;
    return anubis_verify_hashx(ch, nonce, diff, v) == ANUBIS_OK &&
           memcmp(v, hex, 65) == 0;
}
#endif

#if defined(ANUBIS_HAVE_TPU)
static int tpu_hit_ok_bits(const char *ch, uint32_t nonce, int diff,
                           const char *hex) {
    char v[65];
    if (!anubis_tpu_verify()) return 1;
    return anubis_verify_bits(ch, nonce, diff, v) == ANUBIS_OK &&
           memcmp(v, hex, 65) == 0;
}
#endif

/* ------------------------------------------------------------------ */
/* SHA-256                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t h[8];
    uint64_t total;   /* total bytes fed */
    uint8_t block[64];
    size_t used;      /* bytes currently buffered */
} sha256_ctx;

static const uint32_t SHA256_K[64] = {
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
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void sha256_compress_scalar(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, hh;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = load_be32(block + 4 * i);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;

        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

/* SHA-NI single-block compression lives in shani.s. The .s files are ELF
 * assembly, so the Windows build links no hand-written kernels and takes the
 * portable C paths; -march and the CPU still pick the C code's own paths. */
#if defined(__x86_64__) && !defined(_WIN32) && (defined(__GNUC__) || defined(__clang__))
#define ANUBIS_HAVE_SHANI_ASM 1
extern void sha256_block_shani(uint32_t state[8], const uint8_t block[64]);

static int sha_ni_available(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *off = getenv("ANUBIS_NO_SHANI");
        if (off != NULL && off[0] != '\0' && off[0] != '0') {
            cached = 0;
        } else {
            __builtin_cpu_init();
            cached = __builtin_cpu_supports("sha") ? 1 : 0;
        }
    }
    return cached;
}
#endif

#if defined(__aarch64__) && defined(ANUBIS_HAVE_NEON_ASM)
extern void sha256_block_neon(uint32_t state[8], const uint8_t block[64]);

static int arm_sha2_available(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *off = getenv("ANUBIS_NO_NEON");
        if (off != NULL && off[0] != '\0' && off[0] != '0') {
            cached = 0;
        } else {
            cached = (getauxval(AT_HWCAP) & HWCAP_SHA2) ? 1 : 0;
        }
    }
    return cached;
}
#endif

static void sha256_compress(uint32_t h[8], const uint8_t block[64]) {
#ifdef ANUBIS_HAVE_SHANI_ASM
    if (sha_ni_available()) {
        sha256_block_shani(h, block);
        return;
    }
#endif
#if defined(__aarch64__) && defined(ANUBIS_HAVE_NEON_ASM)
    if (arm_sha2_available()) {
        sha256_block_neon(h, block);
        return;
    }
#endif
    sha256_compress_scalar(h, block);
}

static void sha256_init(sha256_ctx *c) {
    static const uint32_t IV[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    memcpy(c->h, IV, sizeof(IV));
    c->total = 0;
    c->used = 0;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t n;

    c->total += (uint64_t)len;

    if (c->used) {
        n = 64 - c->used;
        if (n > len) {
            n = len;
        }
        memcpy(c->block + c->used, p, n);
        c->used += n;
        p += n;
        len -= n;
        if (c->used == 64) {
            sha256_compress(c->h, c->block);
            c->used = 0;
        }
    }

    while (len >= 64) {
        sha256_compress(c->h, p);
        p += 64;
        len -= 64;
    }

    if (len) {
        memcpy(c->block + c->used, p, len);
        c->used += len;
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    uint8_t pad[72];
    size_t padlen;
    int i;

    pad[0] = 0x80;
    memset(pad + 1, 0, sizeof(pad) - 1);

    /* 0x80 + zeroes, ending with the 8-byte big-endian bit count, so that
     * (used + padlen) % 64 == 0. */
    padlen = (c->used < 56) ? (56 - c->used) : (120 - c->used);

    sha256_update(c, pad, padlen);

    {
        uint8_t lenbuf[8];
        for (i = 7; i >= 0; i--) {
            lenbuf[i] = (uint8_t)(bits & 0xff);
            bits >>= 8;
        }
        sha256_update(c, lenbuf, 8);
    }

    for (i = 0; i < 8; i++) {
        store_be32(out + 4 * i, c->h[i]);
    }
}

static void to_hex(const uint8_t *in, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int hex_decode(const char *hex, uint8_t *out, size_t out_cap,
                      size_t *out_len) {
    size_t n = 0;
    int hi = -1;

    if (!hex) {
        return ANUBIS_ERR_ARG;
    }
    for (; *hex; hex++) {
        int v;
        char ch = *hex;
        if (ch >= '0' && ch <= '9') {
            v = ch - '0';
        } else if (ch >= 'a' && ch <= 'f') {
            v = ch - 'a' + 10;
        } else if (ch >= 'A' && ch <= 'F') {
            v = ch - 'A' + 10;
        } else {
            return ANUBIS_ERR_ARG; /* no whitespace tolerance on purpose */
        }
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= out_cap) {
                return ANUBIS_ERR_ARG;
            }
            out[n++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    if (hi >= 0) {
        return ANUBIS_ERR_ARG; /* odd number of hex digits */
    }
    *out_len = n;
    return ANUBIS_OK;
}

/* ------------------------------------------------------------------ */
/* Difficulty predicates                                               */
/* ------------------------------------------------------------------ */

/* `difficulty` leading zero nibbles of the hex digest. */
static inline int nibbles_ok(const uint8_t digest[32], int difficulty) {
    int full = difficulty / 2;
    int i;
    for (i = 0; i < full; i++) {
        if (digest[i] != 0) {
            return 0;
        }
    }
    if (difficulty & 1) {
        if ((digest[full] >> 4) != 0) {
            return 0;
        }
    }
    return 1;
}

/* `difficulty` leading zero bits of the raw digest. */
static inline int bits_ok(const uint8_t digest[32], int difficulty) {
    int full = difficulty / 8;
    int rem = difficulty % 8;
    int i;
    for (i = 0; i < full; i++) {
        if (digest[i] != 0) {
            return 0;
        }
    }
    if (rem && (digest[full] & (uint8_t)(0xffu << (8 - rem))) != 0) {
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static int u64_to_dec(uint64_t v, char out[24]) {
    char tmp[24];
    int n = 0;
    int i;
    if (v == 0) {
        out[0] = '0';
        return 1;
    }
    while (v) {
        tmp[n++] = (char)('0' + (int)(v % 10));
        v /= 10;
    }
    for (i = 0; i < n; i++) {
        out[i] = tmp[n - 1 - i];
    }
    return n;
}

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ------------------------------------------------------------------ */
/* Hash backends for the search loop                                   */
/* ------------------------------------------------------------------ */

typedef int (*anubis_hash_fn)(void *ctx, uint64_t nonce, uint8_t out[32]);

/* fast/slow: sha256(challenge_ascii || decimal_nonce). The challenge is
 * folded into the midstate once, so only the decimal suffix is hashed. */
typedef struct {
    sha256_ctx base;
} fast_ctx;

static int hash_fast(void *vctx, uint64_t nonce, uint8_t out[32]) {
    fast_ctx *c = (fast_ctx *)vctx;
    sha256_ctx ctx = c->base;
    char num[24];
    int n = u64_to_dec(nonce, num);

    sha256_update(&ctx, num, (size_t)n);
    sha256_final(&ctx, out);
    return 0;
}

/* wasm sha256: sha256(raw_challenge || uint32_nonce[le|be]). */
typedef struct {
    sha256_ctx base;
    int use_le;
} bits_ctx;

static int hash_bits(void *vctx, uint64_t nonce, uint8_t out[32]) {
    bits_ctx *c = (bits_ctx *)vctx;
    sha256_ctx ctx = c->base;
    uint8_t suffix[4];
    uint32_t n32 = (uint32_t)nonce;

    if (c->use_le) {
        suffix[0] = (uint8_t)n32;
        suffix[1] = (uint8_t)(n32 >> 8);
        suffix[2] = (uint8_t)(n32 >> 16);
        suffix[3] = (uint8_t)(n32 >> 24);
    } else {
        suffix[0] = (uint8_t)(n32 >> 24);
        suffix[1] = (uint8_t)(n32 >> 16);
        suffix[2] = (uint8_t)(n32 >> 8);
        suffix[3] = (uint8_t)n32;
    }

    sha256_update(&ctx, suffix, 4);
    sha256_final(&ctx, out);
    return 0;
}

/* argon2id: Argon2id(password=raw_challenge, salt=u64_nonce[le|be],
 * m=19456 KiB, t=2, p=1 - the parameters of argon2::Argon2::default()). */
typedef struct {
    const uint8_t *data;
    size_t len;
    int use_le;
} argon_ctx;

static int hash_argon2id(void *vctx, uint64_t nonce, uint8_t out[32]) {
    argon_ctx *c = (argon_ctx *)vctx;
    uint8_t salt[8];
    int i;

    for (i = 0; i < 8; i++) {
        salt[i] = c->use_le ? (uint8_t)(nonce >> (8 * i))
                            : (uint8_t)(nonce >> (8 * (7 - i)));
    }

    if (argon2id_hash_raw(2, 19456, 1, c->data, c->len, salt, sizeof(salt),
                          out, 32) != ARGON2_OK) {
        return -1;
    }
    return 0;
}

/* hashx: Tor's HashX interpreter over the challenge-derived program. */
typedef struct {
    const void *state;
    size_t size;
} hashx_ctx;

static int hash_hashx(void *vctx, uint64_t nonce, uint8_t out[32]) {
    hashx_ctx *c = (hashx_ctx *)vctx;
    hashx_hash(c->state, c->size, nonce, out);
    return 0;
}


/* ------------------------------------------------------------------ */
/* AVX2: eight SHA-256 messages in parallel                            */
/* ------------------------------------------------------------------ */
/* Proof-of-work walks the nonce, so eight candidates in a batch share
 * the same message length and therefore the same padding. That makes
 * them a natural fit for 8-lane AVX2: one __m256i holds the same word
 * of eight different messages.
 *
 * The compression kernel is hand-written assembly in avx2.s; only the
 * batch construction (padding, decimal formatting) lives here.
 */

typedef struct {
    const uint32_t *mid;   /* midstate after the shared prefix */
    size_t prefix_len;     /* bytes already folded into mid */
    int use_le;            /* WASM nonce byte order */
    const meatrider_ctx *mr; /* BATCH_MEATRIDER: the tier's header half */
} batch_ctx;

enum {
    BATCH_NONE = 0,
    BATCH_DECIMALS = 1,    /* fast/slow: prefix + decimal nonce */
    BATCH_FIXED4 = 2,      /* wasm sha256: prefix + 4-byte nonce */
    BATCH_MEATRIDER = 3    /* meatrider: the nonce is in the header */
};

#if defined(__x86_64__) && !defined(_WIN32) && (defined(__GNUC__) || defined(__clang__))
#define ANUBIS_HAVE_AVX2 1
extern void sha256_compress8_avx2(const uint32_t mid[8],
                                  const uint8_t tails[8][64],
                                  uint8_t out[8][32]);
extern void sha256_compress16_avx512(const uint32_t mid[8],
                                     const uint8_t tails[16][64],
                                     uint8_t out[16][32]);

static int anubis_avx512_available(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *off = getenv("ANUBIS_NO_AVX512");
        if (off != NULL && off[0] != '\0' && off[0] != '0') {
            cached = 0;
        } else {
            __builtin_cpu_init();
            cached = __builtin_cpu_supports("avx512f") ? 1 : 0;
        }
    }
    return cached;
}

static int anubis_avx2_available(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *off = getenv("ANUBIS_NO_AVX2");
        if (off != NULL && off[0] != '\0' && off[0] != '0') {
            cached = 0;
        } else {
            __builtin_cpu_init();
            cached = __builtin_cpu_supports("avx2") ? 1 : 0;
        }
    }
    return cached;
}

static void store_length_be(uint8_t *tail, uint64_t bits) {
    int i;
    for (i = 0; i < 8; i++) {
        tail[56 + i] = (uint8_t)(bits >> (8 * (7 - i)));
    }
}

/* fast/slow: all eight lanes must have the same decimal digit count. */
static int batch_decimals(const batch_ctx *c, uint64_t nonce, uint32_t stride,
                          int lanes, uint8_t out[16][32]) {
    char digits[16][24];
    int dlen[16];
    uint8_t tails[16][64];
    uint64_t bits;
    int lane;

    if (c->prefix_len % 64u != 0) {
        return 0;
    }
    for (lane = 0; lane < lanes; lane++) {
        uint64_t n = nonce + (uint64_t)lane * (uint64_t)stride;
        dlen[lane] = u64_to_dec(n, digits[lane]);
        if (dlen[lane] != dlen[0]) {
            return 0; /* mixed lengths -> caller hashes one scalar */
        }
    }
    bits = ((uint64_t)c->prefix_len + (uint64_t)dlen[0]) * 8u;
    for (lane = 0; lane < lanes; lane++) {
        memset(tails[lane], 0, 64);
        memcpy(tails[lane], digits[lane], (size_t)dlen[0]);
        tails[lane][dlen[0]] = 0x80;
        store_length_be(tails[lane], bits);
    }
    if (lanes == 16) {
        sha256_compress16_avx512(c->mid, (const uint8_t (*)[64])tails, out);
    } else {
        sha256_compress8_avx2(c->mid, (const uint8_t (*)[64])tails, out);
    }
    return 1;
}

/* wasm sha256: prefix + uint32 nonce, one byte order for the whole run. */
static int batch_fixed4(const batch_ctx *c, uint64_t nonce, uint32_t stride,
                        int lanes, uint8_t out[16][32]) {
    uint8_t tails[16][64];
    uint64_t bits = ((uint64_t)c->prefix_len + 4u) * 8u;
    int lane;

    if (c->prefix_len % 64u != 0) {
        return 0;
    }
    for (lane = 0; lane < lanes; lane++) {
        uint64_t n64 = nonce + (uint64_t)lane * (uint64_t)stride;
        uint32_t n;
        if (n64 > 0xffffffffull) {
            return 0;
        }
        n = (uint32_t)n64;
        memset(tails[lane], 0, 64);
        if (c->use_le) {
            tails[lane][0] = (uint8_t)n;
            tails[lane][1] = (uint8_t)(n >> 8);
            tails[lane][2] = (uint8_t)(n >> 16);
            tails[lane][3] = (uint8_t)(n >> 24);
        } else {
            tails[lane][0] = (uint8_t)(n >> 24);
            tails[lane][1] = (uint8_t)(n >> 16);
            tails[lane][2] = (uint8_t)(n >> 8);
            tails[lane][3] = (uint8_t)n;
        }
        tails[lane][4] = 0x80;
        store_length_be(tails[lane], bits);
    }
    if (lanes == 16) {
        sha256_compress16_avx512(c->mid, (const uint8_t (*)[64])tails, out);
    } else {
        sha256_compress8_avx2(c->mid, (const uint8_t (*)[64])tails, out);
    }
    return 1;
}

#else /* no AVX2 host */

static int anubis_avx2_available(void) { return 0; }
static int anubis_avx512_available(void) { return 0; }

static int batch_decimals(const batch_ctx *c, uint64_t nonce, uint32_t stride,
                          int lanes, uint8_t out[16][32]) {
    (void)c; (void)nonce; (void)stride; (void)lanes; (void)out;
    return 0;
}

static int batch_fixed4(const batch_ctx *c, uint64_t nonce, uint32_t stride,
                        int lanes, uint8_t out[16][32]) {
    (void)c; (void)nonce; (void)stride; (void)lanes; (void)out;
    return 0;
}

#endif /* x86-64 */

/* meatrider: unlike the two above, nothing here is x86-64 specific. The nonce
 * sits inside the 80-byte header, so the lanes' block 1 and block 2 are built
 * by the tier's own layer (meatrider_simd.c), and the result comes back in
 * Bitcoin display order. Returns 0 when no batch kernel is available, which
 * sends the worker back to one nonce at a time. */
static int batch_meatrider(const batch_ctx *c, uint64_t nonce, uint32_t stride,
                           int lanes, uint8_t out[16][32]) {
    if (c->mr == NULL) {
        return 0;
    }
    if (nonce + (uint64_t)(lanes - 1) * (uint64_t)stride > 0xffffffffull) {
        return 0;
    }
    return meatrider_hash_batch(c->mr, (uint32_t)nonce, stride, lanes, out) == 0;
}

/* ------------------------------------------------------------------ */
/* Threaded search                                                     */
/* ------------------------------------------------------------------ */

enum solve_mode {
    MODE_NIBBLES = 0,
    MODE_BITS = 1
};

typedef struct {
    anubis_hash_fn hash;    /* backend under test */
    void *hash_ctx;
    int mode;
    int difficulty;
    int threads;
    unsigned check_mask;    /* deadline check cadence: 0 = every iteration */
    int batch_kind;         /* BATCH_* fast path, 0 = scalar only */
    int batch_lanes;        /* 8 (AVX2) or 16 (AVX-512) */
    batch_ctx bctx;

    pthread_mutex_t mu;
    volatile int found;
    volatile int stop;
    volatile int error;
    uint64_t nonce;
    uint8_t digest[32];
    double deadline;        /* monotonic seconds; 0 = no deadline */
} solve_job;

typedef struct {
    solve_job *job;
    int tid;
} worker_arg;

static void worker_loop(solve_job *job, int tid) {
    uint8_t digest[32];
    uint64_t iters = 0;

    if (job->mode == MODE_NIBBLES) {
        uint64_t nonce = (uint64_t)tid;

        for (;;) {
            if (job->stop) {
                return;
            }

            if (job->batch_kind == BATCH_DECIMALS) {
                uint8_t outs[16][32];
                if (batch_decimals(&job->bctx, nonce, (uint32_t)job->threads,
                                   job->batch_lanes, outs)) {
                    int k;
                    for (k = 0; k < job->batch_lanes; k++) {
                        if (nibbles_ok(outs[k], job->difficulty)) {
                            pthread_mutex_lock(&job->mu);
                            if (!job->found) {
                                job->found = 1; job->stop = 1;
                                job->nonce = nonce +
                                             (uint64_t)k * (uint64_t)job->threads;
                                memcpy(job->digest, outs[k], 32);
                            }
                            pthread_mutex_unlock(&job->mu);
                            return;
                        }
                    }
                    nonce += (uint64_t)job->batch_lanes *
                             (uint64_t)job->threads;
                    if (job->deadline > 0.0 && now_seconds() > job->deadline) {
                        job->stop = 1;
                        return;
                    }
                    continue;
                }
            }

            if (job->hash(job->hash_ctx, nonce, digest) != 0) {
                job->error = 1;
                job->stop = 1;
                return;
            }
            if (nibbles_ok(digest, job->difficulty)) {
                pthread_mutex_lock(&job->mu);
                if (!job->found) {
                    job->found = 1; job->stop = 1;
                    job->nonce = nonce;
                    memcpy(job->digest, digest, 32);
                }
                pthread_mutex_unlock(&job->mu);
                return;
            }

            nonce += (uint64_t)job->threads;

            if (job->deadline > 0.0 &&
                (job->check_mask == 0 || (++iters & job->check_mask) == 0) &&
                now_seconds() > job->deadline) {
                job->stop = 1;
                return;
            }
        }
    } else {
        uint64_t nonce = (uint64_t)tid;

        for (;;) {
            if (job->stop) {
                return;
            }

            if (job->batch_kind == BATCH_FIXED4 &&
                nonce + 7u * (uint64_t)job->threads <= 0xffffffffull) {
                uint8_t outs[16][32];
                if (batch_fixed4(&job->bctx, nonce, (uint32_t)job->threads,
                                 job->batch_lanes, outs)) {
                    int k;
                    for (k = 0; k < job->batch_lanes; k++) {
                        if (bits_ok(outs[k], job->difficulty)) {
                            pthread_mutex_lock(&job->mu);
                            if (!job->found) {
                                job->found = 1; job->stop = 1;
                                job->nonce = nonce +
                                             (uint64_t)k * (uint64_t)job->threads;
                                memcpy(job->digest, outs[k], 32);
                            }
                            pthread_mutex_unlock(&job->mu);
                            return;
                        }
                    }
                    nonce += (uint64_t)job->batch_lanes *
                             (uint64_t)job->threads;
                    if (job->deadline > 0.0 && now_seconds() > job->deadline) {
                        job->stop = 1;
                        return;
                    }
                    continue;
                }
            }

            if (job->batch_kind == BATCH_MEATRIDER) {
                uint8_t outs[16][32];
                if (batch_meatrider(&job->bctx, nonce, (uint32_t)job->threads,
                                    job->batch_lanes, outs)) {
                    int k;
                    for (k = 0; k < job->batch_lanes; k++) {
                        if (bits_ok(outs[k], job->difficulty)) {
                            pthread_mutex_lock(&job->mu);
                            if (!job->found) {
                                job->found = 1; job->stop = 1;
                                job->nonce = nonce +
                                             (uint64_t)k * (uint64_t)job->threads;
                                memcpy(job->digest, outs[k], 32);
                            }
                            pthread_mutex_unlock(&job->mu);
                            return;
                        }
                    }
                    nonce += (uint64_t)job->batch_lanes *
                             (uint64_t)job->threads;
                    if (job->deadline > 0.0 && now_seconds() > job->deadline) {
                        job->stop = 1;
                        return;
                    }
                    continue;
                }
            }

            if (nonce > 0xffffffffull) {
                return;
            }
            if (job->hash(job->hash_ctx, nonce, digest) != 0) {
                job->error = 1;
                job->stop = 1;
                return;
            }
            if (bits_ok(digest, job->difficulty)) {
                pthread_mutex_lock(&job->mu);
                if (!job->found) {
                    job->found = 1; job->stop = 1;
                    job->nonce = nonce;
                    memcpy(job->digest, digest, 32);
                }
                pthread_mutex_unlock(&job->mu);
                return;
            }

            nonce += (uint64_t)job->threads;
            if (nonce > 0xffffffffull) {
                return;
            }

            if (job->deadline > 0.0 &&
                (job->check_mask == 0 || (++iters & job->check_mask) == 0) &&
                now_seconds() > job->deadline) {
                job->stop = 1;
                return;
            }
        }
    }
}

static void *worker_entry(void *arg) {
    worker_arg *wa = (worker_arg *)arg;
    pin_current_thread(wa->tid);
    worker_loop(wa->job, wa->tid);
    return NULL;
}

/*
 * Run the threaded search. Returns ANUBIS_OK with *out_nonce / out_hex filled
 * in, ANUBIS_ERR_UNSOLVED on exhaustion/timeout, or an error code.
 */
static int run_search(solve_job *job, uint64_t *out_nonce, char out_hex[65],
                      double *out_ms) {
    pthread_t *tids = NULL;
    worker_arg *args = NULL;
    int i;
    int rc = ANUBIS_OK;
    double t0;

    pthread_mutex_init(&job->mu, NULL);

    tids = (pthread_t *)calloc((size_t)job->threads, sizeof(*tids));
    args = (worker_arg *)calloc((size_t)job->threads, sizeof(*args));
    if (!tids || !args) {
        rc = ANUBIS_ERR_INTERNAL;
        goto done;
    }

    t0 = now_seconds();
    for (i = 0; i < job->threads; i++) {
        args[i].job = job;
        args[i].tid = i;
        if (pthread_create(&tids[i], NULL, worker_entry, &args[i]) != 0) {
            /* Run with however many threads started; stop the rest. */
            job->threads = i;
            if (i == 0) {
                rc = ANUBIS_ERR_INTERNAL;
            }
            break;
        }
    }

    for (i = 0; i < job->threads; i++) {
        pthread_join(tids[i], NULL);
    }

    if (out_ms) {
        *out_ms = (now_seconds() - t0) * 1000.0;
    }

    if (job->found) {
        *out_nonce = job->nonce;
        to_hex(job->digest, 32, out_hex);
    } else if (job->error) {
        rc = ANUBIS_ERR_INTERNAL;
    } else if (rc == ANUBIS_OK) {
        rc = ANUBIS_ERR_UNSOLVED;
    }

done:
    free(tids);
    free(args);
    pthread_mutex_destroy(&job->mu);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Public API: JavaScript fast/slow challenges (leading zero nibbles)  */
/* ------------------------------------------------------------------ */

ANUBIS_EXPORT
int anubis_solve_nibbles(const char *challenge, int difficulty, int threads,
                         int64_t max_nonce, double budget_ms,
                         uint64_t *out_nonce, char *out_hex,
                         double *out_ms) {
    solve_job job;
    fast_ctx ctx;
    size_t clen;

    if (!challenge || !out_nonce || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 64) {
        return ANUBIS_ERR_ARG;
    }
    if (threads < 1) {
        threads = 1;
    }
    if (threads > 256) {
        threads = 256;
    }

    memset(&job, 0, sizeof(job));
    job.mode = MODE_NIBBLES;
    job.hash = hash_fast;
    job.hash_ctx = &ctx;
    job.check_mask = 0x3ffu;
    job.difficulty = difficulty;
    job.threads = threads;
    if (budget_ms > 0.0) {
        job.deadline = now_seconds() + budget_ms / 1000.0;
    }

    clen = strlen(challenge);
    sha256_init(&ctx.base);
    sha256_update(&ctx.base, challenge, clen);

    job.batch_lanes = 0;
    if (clen % 64u == 0) {
        if (anubis_avx512_available()) {
            job.batch_lanes = 16;
        } else if (anubis_avx2_available()) {
            job.batch_lanes = 8;
        }
    }
    job.batch_kind = job.batch_lanes ? BATCH_DECIMALS : BATCH_NONE;
    job.bctx.mid = ctx.base.h;
    job.bctx.prefix_len = clen;
    job.bctx.use_le = 0;

    /* max_nonce is accepted for API symmetry; the search is unbounded like
     * the browser implementation (nonce is a JS Number, printed in decimal). */
    (void)max_nonce;

#if defined(ANUBIS_HAVE_CUDA)
    if (clen % 64u == 0 && anubis_cuda_available()) {
        uint64_t expected = 1;
        int i;
        for (i = 0; i < difficulty && i < 40; i++) {
            expected *= 16;
        }
        if (expected >= cuda_min_work(0)) {
            uint32_t gnonce = 0;
            char ghex[65];
            double gms = 0.0;
            uint64_t cap = expected < (0xFFFFFFFFull / 8)
                               ? expected * 8
                               : 0xFFFFFFFFull;
            int grc = anubis_cuda_solve(ctx.base.h, (uint32_t)clen, 0, 0,
                                        difficulty, 0, cap, budget_ms,
                                        &gnonce, ghex, &gms);
            if (grc == 0 &&
                gpu_hit_ok_nibbles(challenge, gnonce, difficulty, ghex)) {
                *out_nonce = gnonce;
                memcpy(out_hex, ghex, 65);
                if (out_ms != NULL) {
                    *out_ms = gms;
                }
                return ANUBIS_OK;
            }
        }
    }
#endif

#if defined(ANUBIS_HAVE_LEVELZERO)
    if (clen % 64u == 0 && anubis_l0_available()) {
        uint64_t expected = 1;
        int i;
        for (i = 0; i < difficulty && i < 40; i++) {
            expected *= 16;
        }
        if (expected >= l0_min_work(0)) {
            uint32_t gnonce = 0;
            char ghex[65];
            double gms = 0.0;
            uint64_t cap = expected < (0xFFFFFFFFull / 8)
                               ? expected * 8
                               : 0xFFFFFFFFull;
            int grc = anubis_l0_solve(ctx.base.h, (uint32_t)clen, 0, 0,
                                      difficulty, 0, cap, budget_ms, &gnonce,
                                      ghex, &gms);
            if (grc == 0 &&
                gpu_hit_ok_nibbles(challenge, gnonce, difficulty, ghex)) {
                *out_nonce = gnonce;
                memcpy(out_hex, ghex, 65);
                if (out_ms != NULL) {
                    *out_ms = gms;
                }
                return ANUBIS_OK;
            }
        }
    }
#endif

#if defined(ANUBIS_HAVE_VULKAN)
    if (clen % 64u == 0 && anubis_vulkan_available()) {
        uint64_t expected = 1;
        int i;
        for (i = 0; i < difficulty && i < 40; i++) {
            expected *= 16;
        }
        if (expected >= vulkan_min_work(0)) {
            uint32_t gnonce = 0;
            char ghex[65];
            double gms = 0.0;
            uint64_t cap = expected < (0xFFFFFFFFull / 8)
                               ? expected * 8
                               : 0xFFFFFFFFull;
            int grc = anubis_vulkan_solve(ctx.base.h, (uint32_t)clen, 0, 0,
                                          difficulty, 0, cap, budget_ms,
                                          &gnonce, ghex, &gms);
            if (grc == 0 &&
                gpu_hit_ok_nibbles(challenge, gnonce, difficulty, ghex)) {
                *out_nonce = gnonce;
                memcpy(out_hex, ghex, 65);
                if (out_ms != NULL) {
                    *out_ms = gms;
                }
                return ANUBIS_OK;
            }
        }
    }
#endif

#if defined(ANUBIS_HAVE_OPENCL)
    if (clen % 64u <= 35u && opencl_enabled() && anubis_opencl_available()) {
        uint64_t expected = 1;
        int i;
        for (i = 0; i < difficulty && i < 40; i++) {
            expected *= 16;
        }
        if (expected >= opencl_min_work(0)) {
            uint32_t gnonce = 0;
            char ghex[65];
            double gms = 0.0;
            uint64_t cap = expected < (0xFFFFFFFFull / 8)
                               ? expected * 8
                               : 0xFFFFFFFFull;
            int grc = anubis_opencl_solve(ctx.base.h, (const uint8_t *)challenge,
                                          (uint32_t)clen, 0, 0, difficulty, 0,
                                          cap, budget_ms, &gnonce, ghex, &gms);
            if (grc == 0 &&
                gpu_hit_ok_nibbles(challenge, gnonce, difficulty, ghex)) {
                *out_nonce = gnonce;
                memcpy(out_hex, ghex, 65);
                if (out_ms != NULL) {
                    *out_ms = gms;
                }
                return ANUBIS_OK;
            }
        }
    }
#endif

    return run_search(&job, out_nonce, out_hex, out_ms);
}

ANUBIS_EXPORT
int anubis_verify_nibbles(const char *challenge, uint64_t nonce, int difficulty,
                          char *out_hex) {
    sha256_ctx c;
    uint8_t digest[32];
    char num[24];
    int n;

    if (!challenge || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 64) {
        return ANUBIS_ERR_ARG;
    }

    sha256_init(&c);
    sha256_update(&c, challenge, strlen(challenge));
    n = u64_to_dec(nonce, num);
    sha256_update(&c, num, (size_t)n);
    sha256_final(&c, digest);
    to_hex(digest, 32, out_hex);

    return nibbles_ok(digest, difficulty) ? ANUBIS_OK : ANUBIS_ERR_UNSOLVED;
}

/* ------------------------------------------------------------------ */
/* Public API: WASM sha256 challenge (leading zero bits)               */
/* ------------------------------------------------------------------ */

ANUBIS_EXPORT
int anubis_solve_bits(const char *challenge_hex, int difficulty, int threads,
                      double budget_ms, uint32_t *out_nonce, char *out_hex,
                      double *out_ms) {
    solve_job job;
    bits_ctx ctx;
    uint8_t raw[4096];
    size_t raw_len = 0;
    uint64_t nonce64 = 0;
    int rc;

    if (!challenge_hex || !out_nonce || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 256) {
        return ANUBIS_ERR_ARG;
    }
    if (threads < 1) {
        threads = 1;
    }
    if (threads > 256) {
        threads = 256;
    }

    rc = hex_decode(challenge_hex, raw, sizeof(raw), &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }

    memset(&job, 0, sizeof(job));
    job.mode = MODE_BITS;
    job.hash = hash_bits;
    job.hash_ctx = &ctx;
    job.check_mask = 0x3ffu;
    job.difficulty = difficulty;
    job.threads = threads;
    if (budget_ms > 0.0) {
        job.deadline = now_seconds() + budget_ms / 1000.0;
    }

    ctx.use_le = raw_len > 0 && raw[raw_len - 1] >= 0x80;
    sha256_init(&ctx.base);
    sha256_update(&ctx.base, raw, raw_len);

    job.batch_lanes = 0;
    if (raw_len % 64u == 0) {
        if (anubis_avx512_available()) {
            job.batch_lanes = 16;
        } else if (anubis_avx2_available()) {
            job.batch_lanes = 8;
        }
    }
    job.batch_kind = job.batch_lanes ? BATCH_FIXED4 : BATCH_NONE;
    job.bctx.mid = ctx.base.h;
    job.bctx.prefix_len = raw_len;
    job.bctx.use_le = ctx.use_le;

#if defined(ANUBIS_HAVE_CUDA)
    if (raw_len % 64u == 0 && anubis_cuda_available()) {
        uint64_t expected = 1;
        int i;
        for (i = 0; i < difficulty && i < 40; i++) {
            expected *= 2;
        }
        if (expected >= cuda_min_work(1)) {
            uint32_t gnonce = 0;
            char ghex[65];
            double gms = 0.0;
            uint64_t cap = expected < (0xFFFFFFFFull / 8)
                               ? expected * 8
                               : 0xFFFFFFFFull;
            int grc = anubis_cuda_solve(ctx.base.h, (uint32_t)raw_len, 1,
                                        ctx.use_le, difficulty, 1, cap,
                                        budget_ms, &gnonce, ghex, &gms);
            if (grc == 0 &&
                gpu_hit_ok_bits(challenge_hex, gnonce, difficulty, ghex)) {
                *out_nonce = gnonce;
                memcpy(out_hex, ghex, 65);
                if (out_ms != NULL) {
                    *out_ms = gms;
                }
                return ANUBIS_OK;
            }
        }
    }
#endif

#if defined(ANUBIS_HAVE_LEVELZERO)
    if (raw_len % 64u == 0 && anubis_l0_available()) {
        uint64_t expected = 1;
        int i;
        for (i = 0; i < difficulty && i < 40; i++) {
            expected *= 2;
        }
        if (expected >= l0_min_work(1)) {
            uint32_t gnonce = 0;
            char ghex[65];
            double gms = 0.0;
            uint64_t cap = expected < (0xFFFFFFFFull / 8)
                               ? expected * 8
                               : 0xFFFFFFFFull;
            int grc = anubis_l0_solve(ctx.base.h, (uint32_t)raw_len, 1,
                                      ctx.use_le, difficulty, 1, cap,
                                      budget_ms, &gnonce, ghex, &gms);
            if (grc == 0 &&
                gpu_hit_ok_bits(challenge_hex, gnonce, difficulty, ghex)) {
                *out_nonce = gnonce;
                memcpy(out_hex, ghex, 65);
                if (out_ms != NULL) {
                    *out_ms = gms;
                }
                return ANUBIS_OK;
            }
        }
    }
#endif

#if defined(ANUBIS_HAVE_VULKAN)
    if (raw_len % 64u == 0 && anubis_vulkan_available()) {
        uint64_t expected = 1;
        int i;
        for (i = 0; i < difficulty && i < 40; i++) {
            expected *= 2;
        }
        if (expected >= vulkan_min_work(0)) {
            uint32_t gnonce = 0;
            char ghex[65];
            double gms = 0.0;
            uint64_t cap = expected < (0xFFFFFFFFull / 8)
                               ? expected * 8
                               : 0xFFFFFFFFull;
            int grc = anubis_vulkan_solve(ctx.base.h, (uint32_t)raw_len, 1,
                                          ctx.use_le, difficulty, 1, cap,
                                          budget_ms, &gnonce, ghex, &gms);
            if (grc == 0 &&
                gpu_hit_ok_bits(challenge_hex, gnonce, difficulty, ghex)) {
                *out_nonce = gnonce;
                memcpy(out_hex, ghex, 65);
                if (out_ms != NULL) {
                    *out_ms = gms;
                }
                return ANUBIS_OK;
            }
        }
    }
#endif

#if defined(ANUBIS_HAVE_OPENCL)
    if (raw_len % 64u <= 51u && opencl_enabled() && anubis_opencl_available()) {
        uint64_t expected = 1;
        int i;
        for (i = 0; i < difficulty && i < 40; i++) {
            expected *= 2;
        }
        if (expected >= opencl_min_work(1)) {
            uint32_t gnonce = 0;
            char ghex[65];
            double gms = 0.0;
            uint64_t cap = expected < (0xFFFFFFFFull / 8)
                               ? expected * 8
                               : 0xFFFFFFFFull;
            int grc = anubis_opencl_solve(ctx.base.h, raw, (uint32_t)raw_len,
                                          1, ctx.use_le, difficulty, 1, cap,
                                          budget_ms, &gnonce, ghex, &gms);
            if (grc == 0 &&
                gpu_hit_ok_bits(challenge_hex, gnonce, difficulty, ghex)) {
                *out_nonce = gnonce;
                memcpy(out_hex, ghex, 65);
                if (out_ms != NULL) {
                    *out_ms = gms;
                }
                return ANUBIS_OK;
            }
        }
    }
#endif

#if defined(ANUBIS_HAVE_TPU)
    /* One 64-byte block per nonce is the shape the TPU is good at, so this
     * path takes the raw challenge and has the same 51-byte limit as OpenCL. */
    if (raw_len > 0 && raw_len + 4 <= 55 && tpu_enabled() &&
        anubis_tpu_available()) {
        uint64_t expected = 1;
        int i;
        for (i = 0; i < difficulty && i < 40; i++) {
            expected *= 2;
        }
        if (expected >= tpu_min_work(1)) {
            uint32_t gnonce = 0;
            char ghex[65];
            double gms = 0.0;
            uint64_t cap = expected < (0xFFFFFFFFull / 8)
                               ? expected * 8
                               : 0xFFFFFFFFull;
            int grc = anubis_tpu_solve(raw, (uint32_t)raw_len, difficulty,
                                       ctx.use_le, cap, budget_ms, &gnonce,
                                       ghex, &gms);
            if (grc == 0 &&
                tpu_hit_ok_bits(challenge_hex, gnonce, difficulty, ghex)) {
                *out_nonce = gnonce;
                memcpy(out_hex, ghex, 65);
                if (out_ms != NULL) {
                    *out_ms = gms;
                }
                return ANUBIS_OK;
            }
        }
    }
#endif

    rc = run_search(&job, &nonce64, out_hex, out_ms);
    if (rc == ANUBIS_OK) {
        *out_nonce = (uint32_t)nonce64;
    }
    return rc;
}

ANUBIS_EXPORT
int anubis_verify_bits(const char *challenge_hex, uint32_t nonce, int difficulty,
                       char *out_hex) {
    sha256_ctx c;
    uint8_t raw[4096];
    size_t raw_len = 0;
    uint8_t digest[32];
    uint8_t suffix[4];
    int use_le;
    int rc;

    if (!challenge_hex || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 256) {
        return ANUBIS_ERR_ARG;
    }

    rc = hex_decode(challenge_hex, raw, sizeof(raw), &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }
    use_le = raw_len > 0 && raw[raw_len - 1] >= 0x80;

    if (use_le) {
        suffix[0] = (uint8_t)nonce;
        suffix[1] = (uint8_t)(nonce >> 8);
        suffix[2] = (uint8_t)(nonce >> 16);
        suffix[3] = (uint8_t)(nonce >> 24);
    } else {
        suffix[0] = (uint8_t)(nonce >> 24);
        suffix[1] = (uint8_t)(nonce >> 16);
        suffix[2] = (uint8_t)(nonce >> 8);
        suffix[3] = (uint8_t)nonce;
    }

    sha256_init(&c);
    sha256_update(&c, raw, raw_len);
    sha256_update(&c, suffix, 4);
    sha256_final(&c, digest);
    to_hex(digest, 32, out_hex);

    return bits_ok(digest, difficulty) ? ANUBIS_OK : ANUBIS_ERR_UNSOLVED;
}

/* ------------------------------------------------------------------ */
/* Public API: WASM argon2id challenge (leading zero bits)             */
/* ------------------------------------------------------------------ */

/* argon2::Argon2::default() uses m=19456 KiB, so each worker needs ~19 MiB. */
#define ANUBIS_ARGON2_THREADS_MAX 64

static int argon2id_digest(const uint8_t *raw, size_t raw_len, uint32_t nonce,
                           uint8_t out[32]) {
    uint8_t salt[8];
    int use_le = raw_len > 0 && raw[raw_len - 1] >= 0x80;
    uint64_t n = (uint64_t)nonce;
    int i;

    for (i = 0; i < 8; i++) {
        salt[i] = use_le ? (uint8_t)(n >> (8 * i))
                         : (uint8_t)(n >> (8 * (7 - i)));
    }

    return argon2id_hash_raw(2, 19456, 1, raw, raw_len, salt, sizeof(salt),
                             out, 32) == ARGON2_OK
               ? ANUBIS_OK
               : ANUBIS_ERR_INTERNAL;
}

ANUBIS_EXPORT
int anubis_solve_argon2id(const char *challenge_hex, int difficulty, int threads,
                          double budget_ms, uint32_t *out_nonce, char *out_hex,
                          double *out_ms) {
    solve_job job;
    argon_ctx ctx;
    uint8_t raw[4096];
    size_t raw_len = 0;
    uint64_t nonce64 = 0;
    int rc;

    if (!challenge_hex || !out_nonce || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 256) {
        return ANUBIS_ERR_ARG;
    }
    if (threads < 1) {
        threads = 1;
    }
    if (threads > ANUBIS_ARGON2_THREADS_MAX) {
        threads = ANUBIS_ARGON2_THREADS_MAX;
    }

    rc = hex_decode(challenge_hex, raw, sizeof(raw), &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }

    memset(&job, 0, sizeof(job));
    job.mode = MODE_BITS;
    job.hash = hash_argon2id;
    job.hash_ctx = &ctx;
    job.check_mask = 0; /* one Argon2 hash is milliseconds: check every loop */
    job.difficulty = difficulty;
    job.threads = threads;
    if (budget_ms > 0.0) {
        job.deadline = now_seconds() + budget_ms / 1000.0;
    }

    ctx.data = raw;
    ctx.len = raw_len;
    ctx.use_le = raw_len > 0 && raw[raw_len - 1] >= 0x80;

#if defined(ANUBIS_HAVE_CUDA)
    if (gpu_argon2_enabled() && anubis_cuda_argon2_available()) {
        uint64_t expected = 1;
        uint64_t cap;
        uint32_t gnonce = 0;
        char ghex[65];
        double gms = 0.0;
        int i;
        for (i = 0; i < difficulty && i < 32; i++) {
            expected *= 2;
        }
        cap = expected < (0xFFFFFFFFull / 8) ? expected * 8 : 0xFFFFFFFFull;
        if (anubis_cuda_argon2_solve(raw, raw_len, ctx.use_le, difficulty, cap,
                                     budget_ms, &gnonce, ghex, &gms) == 0 &&
            gpu_hit_ok_argon2id(challenge_hex, gnonce, difficulty, ghex)) {
            *out_nonce = gnonce;
            memcpy(out_hex, ghex, 65);
            if (out_ms != NULL) {
                *out_ms = gms;
            }
            return ANUBIS_OK;
        }
    }
#endif

#if defined(ANUBIS_HAVE_LEVELZERO)
    if (gpu_argon2_enabled() && anubis_l0_argon2_available()) {
        uint64_t expected = 1;
        uint64_t cap;
        uint32_t gnonce = 0;
        char ghex[65];
        double gms = 0.0;
        int i;
        for (i = 0; i < difficulty && i < 32; i++) {
            expected *= 2;
        }
        cap = expected < (0xFFFFFFFFull / 8) ? expected * 8 : 0xFFFFFFFFull;
        if (anubis_l0_argon2_solve(raw, raw_len, ctx.use_le, difficulty, cap,
                                   budget_ms, &gnonce, ghex, &gms) == 0 &&
            gpu_hit_ok_argon2id(challenge_hex, gnonce, difficulty, ghex)) {
            *out_nonce = gnonce;
            memcpy(out_hex, ghex, 65);
            if (out_ms != NULL) {
                *out_ms = gms;
            }
            return ANUBIS_OK;
        }
    }
#endif

#if defined(ANUBIS_HAVE_VULKAN)
    if (gpu_argon2_enabled() && anubis_vulkan_argon2_available()) {
        uint64_t expected = 1;
        uint64_t cap;
        uint32_t gnonce = 0;
        char ghex[65];
        double gms = 0.0;
        int i;
        for (i = 0; i < difficulty && i < 32; i++) {
            expected *= 2;
        }
        cap = expected < (0xFFFFFFFFull / 8) ? expected * 8 : 0xFFFFFFFFull;
        if (anubis_vulkan_argon2_solve(raw, raw_len, ctx.use_le, difficulty, cap,
                                       budget_ms, &gnonce, ghex, &gms) == 0 &&
            gpu_hit_ok_argon2id(challenge_hex, gnonce, difficulty, ghex)) {
            *out_nonce = gnonce;
            memcpy(out_hex, ghex, 65);
            if (out_ms != NULL) {
                *out_ms = gms;
            }
            return ANUBIS_OK;
        }
    }
#endif

    rc = run_search(&job, &nonce64, out_hex, out_ms);
    if (rc == ANUBIS_OK) {
        *out_nonce = (uint32_t)nonce64;
    }
    return rc;
}

ANUBIS_EXPORT
int anubis_verify_argon2id(const char *challenge_hex, uint32_t nonce,
                           int difficulty, char *out_hex) {
    uint8_t raw[4096];
    size_t raw_len = 0;
    uint8_t digest[32];
    int rc;

    if (!challenge_hex || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 256) {
        return ANUBIS_ERR_ARG;
    }

    rc = hex_decode(challenge_hex, raw, sizeof(raw), &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }
    rc = argon2id_digest(raw, raw_len, nonce, digest);
    if (rc != ANUBIS_OK) {
        return rc;
    }
    to_hex(digest, 32, out_hex);

    return bits_ok(digest, difficulty) ? ANUBIS_OK : ANUBIS_ERR_UNSOLVED;
}

/* ------------------------------------------------------------------ */
/* Public API: WASM hashx challenge (leading zero bits)                */
/* ------------------------------------------------------------------ */

ANUBIS_EXPORT
int anubis_solve_hashx(const char *challenge_hex, int difficulty, int threads,
                       double budget_ms, uint32_t *out_nonce, char *out_hex,
                       double *out_ms) {
    solve_job job;
    hashx_ctx ctx;
    uint8_t raw[4096];
    size_t raw_len = 0;
    uint64_t nonce64 = 0;
    void *state = NULL;
    size_t state_size = 0;
    int rc;

    if (!challenge_hex || !out_nonce || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 256) {
        return ANUBIS_ERR_ARG;
    }
    if (threads < 1) {
        threads = 1;
    }
    if (threads > 256) {
        threads = 256;
    }

    rc = hex_decode(challenge_hex, raw, sizeof(raw), &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }

    rc = hashx_init(raw, raw_len, &state, &state_size);
    if (rc != 0) {
        return ANUBIS_ERR_INTERNAL;
    }

    memset(&job, 0, sizeof(job));
    job.mode = MODE_BITS;
    job.hash = hash_hashx;
    job.hash_ctx = &ctx;
    job.check_mask = 0x3ffu;
    job.difficulty = difficulty;
    job.threads = threads;
    if (budget_ms > 0.0) {
        job.deadline = now_seconds() + budget_ms / 1000.0;
    }

    ctx.state = state;
    ctx.size = state_size;

#if defined(ANUBIS_HAVE_CUDA)
    if (gpu_hashx_enabled() && anubis_cuda_hashx_available()) {
        uint64_t expected = 1;
        uint64_t cap;
        uint32_t gnonce = 0;
        char ghex[65];
        double gms = 0.0;
        int i;
        for (i = 0; i < difficulty && i < 32; i++) {
            expected *= 2;
        }
        cap = expected < (0xFFFFFFFFull / 8) ? expected * 8 : 0xFFFFFFFFull;
        if (anubis_cuda_hashx_solve(state, state_size, difficulty, cap,
                                    budget_ms, &gnonce, ghex, &gms) == 0 &&
            gpu_hit_ok_hashx(challenge_hex, gnonce, difficulty, ghex)) {
            hashx_free(state);
            *out_nonce = gnonce;
            memcpy(out_hex, ghex, 65);
            if (out_ms != NULL) {
                *out_ms = gms;
            }
            return ANUBIS_OK;
        }
    }
#endif

#if defined(ANUBIS_HAVE_LEVELZERO)
    if (l0_hashx_enabled() && anubis_l0_hashx_available()) {
        uint64_t expected = 1;
        uint64_t cap;
        uint32_t gnonce = 0;
        char ghex[65];
        double gms = 0.0;
        int i;
        for (i = 0; i < difficulty && i < 32; i++) {
            expected *= 2;
        }
        cap = expected < (0xFFFFFFFFull / 8) ? expected * 8 : 0xFFFFFFFFull;
        if (anubis_l0_hashx_solve(state, state_size, difficulty, cap, budget_ms,
                                  &gnonce, ghex, &gms) == 0 &&
            gpu_hit_ok_hashx(challenge_hex, gnonce, difficulty, ghex)) {
            hashx_free(state);
            *out_nonce = gnonce;
            memcpy(out_hex, ghex, 65);
            if (out_ms != NULL) {
                *out_ms = gms;
            }
            return ANUBIS_OK;
        }
    }
#endif

#if defined(ANUBIS_HAVE_VULKAN)
    if (vulkan_hashx_enabled() && anubis_vulkan_hashx_available()) {
        uint64_t expected = 1;
        uint64_t cap;
        uint32_t gnonce = 0;
        char ghex[65];
        double gms = 0.0;
        int i;
        for (i = 0; i < difficulty && i < 32; i++) {
            expected *= 2;
        }
        cap = expected < (0xFFFFFFFFull / 8) ? expected * 8 : 0xFFFFFFFFull;
        if (anubis_vulkan_hashx_solve(state, state_size, difficulty, cap,
                                      budget_ms, &gnonce, ghex, &gms) == 0 &&
            gpu_hit_ok_hashx(challenge_hex, gnonce, difficulty, ghex)) {
            hashx_free(state);
            *out_nonce = gnonce;
            memcpy(out_hex, ghex, 65);
            if (out_ms != NULL) {
                *out_ms = gms;
            }
            return ANUBIS_OK;
        }
    }
#endif

    rc = run_search(&job, &nonce64, out_hex, out_ms);
    hashx_free(state);

    if (rc == ANUBIS_OK) {
        *out_nonce = (uint32_t)nonce64;
    }
    return rc;
}

ANUBIS_EXPORT
int anubis_verify_hashx(const char *challenge_hex, uint32_t nonce, int difficulty,
                        char *out_hex) {
    uint8_t raw[4096];
    size_t raw_len = 0;
    uint8_t digest[32];
    void *state = NULL;
    size_t state_size = 0;
    int rc;

    if (!challenge_hex || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0 || difficulty > 256) {
        return ANUBIS_ERR_ARG;
    }

    rc = hex_decode(challenge_hex, raw, sizeof(raw), &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }
    rc = hashx_init(raw, raw_len, &state, &state_size);
    if (rc != 0) {
        return ANUBIS_ERR_INTERNAL;
    }
    hashx_hash(state, state_size, (uint64_t)nonce, digest);
    hashx_free(state);

    to_hex(digest, 32, out_hex);
    return bits_ok(digest, difficulty) ? ANUBIS_OK : ANUBIS_ERR_UNSOLVED;
}

/* ------------------------------------------------------------------ */
/* Public API: meatrider challenge (SHA-256d over a Bitcoin header)    */
/* ------------------------------------------------------------------ */

/* The header, the SHA-256d and the price ladder live in
 * src/meatrider/meatrider.c, which is also compiled into wasm/, so the browser
 * kernel and this library cannot drift. This file only carries the search and
 * the verification policy. */

typedef struct {
    meatrider_ctx ctx;
} meatrider_job_ctx;

static int hash_meatrider(void *vctx, uint64_t nonce, uint8_t out[32]) {
    meatrider_job_ctx *c = (meatrider_job_ctx *)vctx;
    if (nonce > 0xffffffffull) {
        return 1;
    }
    meatrider_hash(&c->ctx, (uint32_t)nonce, out);
    return 0;
}

#if defined(MEATRIDER_HAVE_SIMD)
/* The same search with SHA-NI doing the two compressions: ~80 cycles per block
 * instead of ~940. Chosen once per call, never branched on per hash. */
static int hash_meatrider_shani(void *vctx, uint64_t nonce, uint8_t out[32]) {
    meatrider_job_ctx *c = (meatrider_job_ctx *)vctx;
    if (nonce > 0xffffffffull) {
        return 1;
    }
    meatrider_hash_shani(&c->ctx, (uint32_t)nonce, out);
    return 0;
}
#endif

static int meatrider_random_data(const char *challenge_hex, uint8_t rd[32]) {
    uint8_t raw[64];
    size_t raw_len = 0;
    int rc;

    if (challenge_hex == NULL) {
        return ANUBIS_ERR_ARG;
    }
    rc = hex_decode(challenge_hex, raw, sizeof raw, &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }
    /* every Anubis tier is handed a 32-byte randomData; meatrider needs exactly
     * that because the header has a 32-byte prev-block field and no room for
     * an arbitrary-length message. */
    if (raw_len != 32) {
        return ANUBIS_ERR_ARG;
    }
    memcpy(rd, raw, 32);
    return ANUBIS_OK;
}

/* One search on a named backend, or on whatever this machine has when
 * `backend` is negative. The accelerators get first refusal and the CPU is
 * always the fallback, which is the library's rule everywhere else. */
static int meatrider_solve_on(int backend, const char *challenge_hex,
                              int difficulty, int threads, double budget_ms,
                              uint32_t *out_nonce, char *out_hex,
                              double *out_ms) {
    solve_job job;
    meatrider_job_ctx ctx;
    anubis_hash_fn hash = hash_meatrider;
    uint8_t rd[32];
    uint64_t nonce64 = 0;
    int lanes = 0;
    int rc;

    if (!challenge_hex || !out_nonce || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 1 || difficulty > 255) {
        return ANUBIS_ERR_ARG;
    }
    if (threads < 1) {
        threads = 1;
    }
    if (threads > 256) {
        threads = 256;
    }

    rc = meatrider_random_data(challenge_hex, rd);
    if (rc != ANUBIS_OK) {
        return rc;
    }
    if (meatrider_ctx_init(&ctx.ctx, rd, difficulty) != 0) {
        return ANUBIS_ERR_INTERNAL;
    }

    if (backend < 0) {
        backend = meatrider_backend_active();
    }

    /* An accelerator covers the whole 32-bit space in one dispatch, so it is
     * asked first and the thread pool is not started at all. */
    if (backend >= MR_BACKEND_OPENCL) {
        double started = now_seconds();
        uint32_t accel_nonce = 0;
        uint8_t accel_digest[32];
        uint8_t check[32];

        rc = meatrider_backend_gpu_solve(backend, &ctx.ctx, 0, 0, budget_ms,
                                         &accel_nonce, accel_digest);
        if (rc == 0) {
            /* Every GPU hit is re-derived here before it is believed: a kernel
             * bug costs a wasted dispatch, never a wrong answer. */
            meatrider_digest(rd, difficulty, accel_nonce, check);
            if (memcmp(check, accel_digest, 32) == 0 &&
                bits_ok(check, difficulty)) {
                *out_nonce = accel_nonce;
                to_hex(check, 32, out_hex);
                if (out_ms != NULL) {
                    *out_ms = (now_seconds() - started) * 1000.0;
                }
                return ANUBIS_OK;
            }
        } else if (rc > 0) {
            /* The kernel ran and the range or the budget ran out. */
            return ANUBIS_ERR_UNSOLVED;
        }
        /* -1: not compiled in, no device, or the dispatch failed. The CPU is
         * the fallback, as it is for every other tier. */
        backend = MR_BACKEND_SCALAR;
    }

#if defined(MEATRIDER_HAVE_SIMD)
    if (backend != MR_BACKEND_SCALAR && meatrider_shani_available()) {
        hash = hash_meatrider_shani;
    }
#endif
    switch (backend) {
    case MR_BACKEND_AVX512:
        lanes = 16;
        break;
    case MR_BACKEND_AVX2:
        lanes = 8;
        break;
    default:
        /* Not a CPU kernel we can name (a pinned accelerator that was not
         * usable, or "auto" with none): take the widest thing this CPU has. */
        if (backend != MR_BACKEND_SCALAR && backend != MR_BACKEND_SHANI) {
            lanes = meatrider_batch_width();
#if defined(MEATRIDER_HAVE_SIMD)
            if (lanes == 0 && meatrider_shani_available()) {
                hash = hash_meatrider_shani;
            }
#endif
        }
        break;
    }

    memset(&job, 0, sizeof(job));
    job.mode = MODE_BITS;
    job.hash = hash;
    job.hash_ctx = &ctx;
    job.check_mask = 0x3ffu;
    job.difficulty = difficulty;
    job.threads = threads;
    /* The tier's vector kernels hash 8 or 16 nonces per pair of compressions;
     * the nonce sits inside the header, so the lanes' block 1 and block 2 come
     * from meatrider_simd.c rather than from the sha256 tier's padding code. */
    job.batch_kind = lanes != 0 ? BATCH_MEATRIDER : BATCH_NONE;
    job.batch_lanes = lanes;
    job.bctx.mr = &ctx.ctx;
    if (budget_ms > 0.0) {
        job.deadline = now_seconds() + budget_ms / 1000.0;
    }

    rc = run_search(&job, &nonce64, out_hex, out_ms);
    if (rc == ANUBIS_OK) {
        *out_nonce = (uint32_t)nonce64;
    }
    return rc;
}

ANUBIS_EXPORT
int anubis_solve_meatrider(const char *challenge_hex, int difficulty, int threads,
                           double budget_ms, uint32_t *out_nonce, char *out_hex,
                           double *out_ms) {
    return meatrider_solve_on(-1, challenge_hex, difficulty, threads, budget_ms,
                              out_nonce, out_hex, out_ms);
}

ANUBIS_EXPORT
int anubis_meatrider_backend_count(void) {
    return MR_BACKEND_COUNT;
}

ANUBIS_EXPORT
const char *anubis_meatrider_backend_name(int backend) {
    return meatrider_backend_name(backend);
}

ANUBIS_EXPORT
int anubis_meatrider_backend_available(int backend) {
    return meatrider_backend_available(backend);
}

ANUBIS_EXPORT
int anubis_meatrider_backend_active(void) {
    return meatrider_backend_active();
}

ANUBIS_EXPORT
int anubis_meatrider_backend_solve(const char *challenge_hex, int difficulty,
                                   int backend, int threads, double budget_ms,
                                   uint32_t *out_nonce, char *out_hex,
                                   double *out_ms) {
    return meatrider_solve_on(backend, challenge_hex, difficulty, threads,
                              budget_ms, out_nonce, out_hex, out_ms);
}

ANUBIS_EXPORT
int anubis_meatrider_backend_digest(const char *challenge_hex, int difficulty,
                                    int backend, uint32_t nonce, char *out_hex) {
    meatrider_ctx ctx;
    uint8_t rd[32];
    uint8_t digest[32];
    int rc;

    if (challenge_hex == NULL || out_hex == NULL) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 1 || difficulty > 255) {
        return ANUBIS_ERR_ARG;
    }
    rc = meatrider_random_data(challenge_hex, rd);
    if (rc != ANUBIS_OK) {
        return rc;
    }
    if (meatrider_ctx_init(&ctx, rd, difficulty) != 0) {
        return ANUBIS_ERR_INTERNAL;
    }
    if (meatrider_backend_digest(backend, &ctx, nonce, digest) != 0) {
        return ANUBIS_ERR_INTERNAL;
    }
    to_hex(digest, 32, out_hex);
    return ANUBIS_OK;
}

ANUBIS_EXPORT
int anubis_verify_meatrider(const char *challenge_hex, uint32_t nonce,
                            int difficulty, char *out_hex) {
    uint8_t rd[32];
    uint8_t digest[32];
    int rc;

    if (!challenge_hex || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 1 || difficulty > 255) {
        return ANUBIS_ERR_ARG;
    }

    rc = meatrider_random_data(challenge_hex, rd);
    if (rc != ANUBIS_OK) {
        return rc;
    }
    if (meatrider_digest(rd, difficulty, nonce, digest) != 0) {
        return ANUBIS_ERR_INTERNAL;
    }
    to_hex(digest, 32, out_hex);

    return bits_ok(digest, difficulty) ? ANUBIS_OK : ANUBIS_ERR_UNSOLVED;
}

ANUBIS_EXPORT
int anubis_meatrider_header(const char *challenge_hex, int difficulty,
                            uint32_t nonce, char *out_hex) {
    meatrider_ctx ctx;
    uint8_t rd[32];
    uint8_t header[MEATRIDER_HEADER_LEN];
    int rc;

    if (!challenge_hex || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    rc = meatrider_random_data(challenge_hex, rd);
    if (rc != ANUBIS_OK) {
        return rc;
    }
    if (meatrider_ctx_init(&ctx, rd, difficulty) != 0) {
        return ANUBIS_ERR_ARG;
    }
    meatrider_header(&ctx, nonce, header);
    to_hex(header, MEATRIDER_HEADER_LEN, out_hex);
    return ANUBIS_OK;
}

ANUBIS_EXPORT
unsigned anubis_meatrider_bits(int difficulty) {
    return meatrider_bits(difficulty);
}

ANUBIS_EXPORT
double anubis_meatrider_price_usd(int difficulty, double usd_per_th_day) {
    return meatrider_price_usd(difficulty, usd_per_th_day);
}

ANUBIS_EXPORT
double anubis_meatrider_asic_seconds(int difficulty, double hashrate) {
    return meatrider_asic_seconds(difficulty, hashrate);
}

ANUBIS_EXPORT
const char *anubis_meatrider_tier(int difficulty) {
    return meatrider_tier_name(difficulty);
}

ANUBIS_EXPORT
int anubis_meatrider_difficulty_for_usd(double usd, double usd_per_th_day) {
    return meatrider_difficulty_for_usd(usd, usd_per_th_day);
}

/* ------------------------------------------------------------------ */
/* Public API: tensor challenge (one int8 GEMM, digest of the result)  */
/* ------------------------------------------------------------------ */

/* `tensor` is the tier where acceleration is the point rather than a
 * bonus: the work is a single integer GEMM and nothing else.
 *
 *   N      = 64 * clamp(difficulty, 2, 16)     (512 at difficulty 8)
 *   seed   = SHA256(raw challenge bytes)
 *   stream = SHA256(seed || u32le(counter)) for counter = 0, 1, ...
 *   A[i]   = stream[i] & 0x7f        uint8, row-major N x N
 *   B[i]   = (int8)stream[N*N + i]   int8,  row-major N x N
 *   C      = A * B, exact int32
 *   digest = SHA256(C as N*N little-endian int32)
 *
 * There is no nonce search. The proof is the digest, so the client pays one
 * GEMM per challenge and the server pays one GEMM per accepted pass instead
 * of 2^difficulty of them. A client cannot shortcut the work either: the
 * digest covers every output element, so producing it means producing C.
 *
 * A is masked to seven bits on purpose. A pair of products then always fits
 * an i16 (2 * 127 * 127 = 32258 < 32767), which is what lets the wasm and
 * x86 kernels use the widening multiply-add instructions without saturation.
 * The accumulation cannot overflow int32: |C| <= 127 * 128 * N <= 16.6M at
 * N = 1024.
 *
 * Everything here is integer, in a fixed order, so every implementation
 * (this one, the wasm kernel, WebNN, the pure-JavaScript fallback) produces
 * the same bytes. That is the whole reason the tier is verifiable at all: a
 * float GEMM would reassociate and stop matching after the first kernel.
 */

#define ANUBIS_TENSOR_MIN_DIFFICULTY 2
#define ANUBIS_TENSOR_MAX_DIFFICULTY 16

static int tensor_dim(int difficulty) {
    int d = difficulty;

    if (d < ANUBIS_TENSOR_MIN_DIFFICULTY) {
        d = ANUBIS_TENSOR_MIN_DIFFICULTY;
    }
    if (d > ANUBIS_TENSOR_MAX_DIFFICULTY) {
        d = ANUBIS_TENSOR_MAX_DIFFICULTY;
    }
    return 64 * d;
}

/* Fill A and B from SHA256(seed || u32le(counter)), consuming the stream in
 * order: the first N*N bytes are A, the next N*N are B. */
static void tensor_expand(const uint8_t seed[32], uint8_t *a, int8_t *b,
                          size_t count) {
    sha256_ctx base;
    size_t pos = 0;
    uint32_t counter = 0;

    sha256_init(&base);
    sha256_update(&base, seed, 32);

    while (pos < 2 * count) {
        sha256_ctx c = base;
        uint8_t ctr[4];
        uint8_t block[32];
        size_t i;

        ctr[0] = (uint8_t)counter;
        ctr[1] = (uint8_t)(counter >> 8);
        ctr[2] = (uint8_t)(counter >> 16);
        ctr[3] = (uint8_t)(counter >> 24);
        sha256_update(&c, ctr, sizeof ctr);
        sha256_final(&c, block);

        for (i = 0; i < sizeof block && pos < 2 * count; i++, pos++) {
            if (pos < count) {
                a[pos] = (uint8_t)(block[i] & 0x7f);
            } else {
                b[pos - count] = (int8_t)block[i];
            }
        }
        counter++;
    }
}

typedef struct {
    const uint8_t *a;
    const int8_t *b;
    int32_t *c;
    int n;
    int begin;
    int end;
} tensor_job;

/* i-k-j: the inner loop walks one row of B and one row of C, so the only
 * streams are sequential and the expression vectorises to widening
 * multiply-adds on every target that has them. */
static void tensor_gemm_rows(const tensor_job *job) {
    const int n = job->n;
    int i;

    for (i = job->begin; i < job->end; i++) {
        int32_t *row = job->c + (size_t)i * (size_t)n;
        const uint8_t *arow = job->a + (size_t)i * (size_t)n;
        int k;

        memset(row, 0, (size_t)n * sizeof *row);
        for (k = 0; k < n; k++) {
            const int32_t av = (int32_t)arow[k];
            const int8_t *brow = job->b + (size_t)k * (size_t)n;
            int j;

            for (j = 0; j < n; j++) {
                row[j] += av * (int32_t)brow[j];
            }
        }
    }
}

static void *tensor_gemm_thread(void *p) {
    tensor_gemm_rows((const tensor_job *)p);
    return NULL;
}

/* Rows are independent, so the Gemm splits cleanly. Verification is on the
 * request path: one thread makes a difficulty-16 pass (N = 1024) take about a
 * second, which is not acceptable for a gate. */
static void tensor_gemm(const uint8_t *a, const int8_t *b, int32_t *c, int n) {
    tensor_job jobs[16];
    pthread_t tids[16];
    int threads = anubis_default_threads();
    int started = 0;
    int t;

    if (threads > n / 32) {
        threads = n / 32;
    }
    if (threads > 16) {
        threads = 16;
    }
    if (threads < 1) {
        threads = 1;
    }

    for (t = 0; t < threads; t++) {
        jobs[t].a = a;
        jobs[t].b = b;
        jobs[t].c = c;
        jobs[t].n = n;
        jobs[t].begin = n * t / threads;
        jobs[t].end = n * (t + 1) / threads;
    }

    if (threads == 1) {
        tensor_gemm_rows(&jobs[0]);
        return;
    }

    for (t = 0; t < threads; t++) {
        if (pthread_create(&tids[t], NULL, tensor_gemm_thread, &jobs[t]) != 0) {
            break;
        }
        started++;
    }
    /* runs the slices whose thread never started, including after a failure */
    for (t = started; t < threads; t++) {
        tensor_gemm_rows(&jobs[t]);
    }
    for (t = 0; t < started; t++) {
        pthread_join(tids[t], NULL);
    }
}

ANUBIS_EXPORT
int anubis_tensor_digest(const char *challenge_hex, int difficulty, char *out_hex) {
    uint8_t seed[32];
    uint8_t *a = NULL;
    int8_t *b = NULL;
    int32_t *c = NULL;
    uint8_t *ser = NULL;
    uint8_t digest[32];
    sha256_ctx s;
    uint8_t raw[4096];
    size_t raw_len = 0;
    int n;
    int rc = ANUBIS_ERR_INTERNAL;
    size_t cells;
    size_t i;

    if (challenge_hex == NULL || out_hex == NULL) {
        return ANUBIS_ERR_ARG;
    }
    if (difficulty < 0) {
        return ANUBIS_ERR_ARG;
    }

    rc = hex_decode(challenge_hex, raw, sizeof raw, &raw_len);
    if (rc != ANUBIS_OK) {
        return rc;
    }

    n = tensor_dim(difficulty);
    cells = (size_t)n * (size_t)n;

    a = malloc(cells);
    b = malloc(cells);
    c = malloc(cells * sizeof *c);
    ser = malloc(cells * 4);
    if (a == NULL || b == NULL || c == NULL || ser == NULL) {
        goto out;
    }

    /* The seed is the *decoded* challenge bytes, not the hex text: the
     * browser hands the wasm kernel exactly those bytes, and the page hashes
     * the same array, so all three paths start from identical input. */
    sha256_init(&s);
    sha256_update(&s, raw, raw_len);
    sha256_final(&s, seed);

    tensor_expand(seed, a, b, cells);
    tensor_gemm(a, b, c, n);

    for (i = 0; i < cells; i++) {
        uint32_t v = (uint32_t)c[i];
        ser[4 * i + 0] = (uint8_t)v;
        ser[4 * i + 1] = (uint8_t)(v >> 8);
        ser[4 * i + 2] = (uint8_t)(v >> 16);
        ser[4 * i + 3] = (uint8_t)(v >> 24);
    }

    sha256_init(&s);
    sha256_update(&s, ser, cells * 4);
    sha256_final(&s, digest);
    to_hex(digest, 32, out_hex);
    rc = ANUBIS_OK;

out:
    free(a);
    free(b);
    free(c);
    free(ser);
    return rc;
}

ANUBIS_EXPORT
int anubis_verify_tensor(const char *challenge_hex, uint32_t nonce, int difficulty,
                         char *out_hex) {
    (void)nonce; /* the proof is deterministic: the nonce is always 0 */
    return anubis_tensor_digest(challenge_hex, difficulty, out_hex);
}

/* ------------------------------------------------------------------ */
/* Public API: tensor-v, the sampled-proof tensor tier                 */
/* ------------------------------------------------------------------ */
/*
 * `tensor` asks the server to recompute the whole GEMM, so the cost is 1:1.
 * `tensor-v` keeps the client's work at one GEMM but makes the server check
 * only a random sample of committed output elements:
 *
 *   N          = 64 * clamp(difficulty, 2, 16)          (same as tensor)
 *   seed       = SHA256(raw challenge bytes)
 *   stream     = SHA256(seed || u32le(counter)) for counter = 0, 1, ...
 *   A[i][k]    = stream[i*N + k] & 0x7f                 uint8,  row-major
 *   BT[j][k]   = int8(stream[N*N + j*N + k])            int8,   row-major
 *   C[i][j]    = sum_k A[i][k] * BT[j][k]               exact int32
 *
 * BT is the transpose of the `tensor` tier's B, which makes one column of B
 * one contiguous row here: a verifier that only needs C[i][j] hashes N/32
 * stream blocks, not the whole matrix.
 *
 * The client commits to C in blocks of 32 int32 values:
 *
 *   chal  = SHA256("ANUBIS-TENSOR-VC" || raw)
 *   leaf  = SHA256("ANUBIS-TENSOR-VL" || chal || u32le(block) || block bytes)
 *   node  = SHA256("ANUBIS-TENSOR-VN" || left || right)   (odd last duplicated)
 *   root  = the top node
 *
 * The server samples k block indices and one element inside each from
 * SHA256("ANUBIS-TENSOR-VS" || secret || challenge || root). The client sends
 * the sampled blocks with Merkle proofs; the server hashes them up to the
 * root and recomputes only those elements, O(k*N) work against the client's
 * N^3. A client that computed a fraction f of the elements passes with
 * probability f^k, so k is the security parameter.
 *
 * Nothing here changes the `tensor` tier: same challenge bytes, same A, and
 * the same deterministic integer arithmetic. Only the proof is different.
 */

#define TV_BLOCK 32
#define TV_MAGIC 0x31565654u   /* "TVV1" little-endian */
#define TV_MAX_DEPTH 32
#define TV_MAX_SAMPLES 1024

static const uint8_t tv_dom_leaf[16] = {
    'A', 'N', 'U', 'B', 'I', 'S', '-', 'T',
    'E', 'N', 'S', 'O', 'R', '-', 'V', 'L'};
static const uint8_t tv_dom_node[16] = {
    'A', 'N', 'U', 'B', 'I', 'S', '-', 'T',
    'E', 'N', 'S', 'O', 'R', '-', 'V', 'N'};
static const uint8_t tv_dom_chal[16] = {
    'A', 'N', 'U', 'B', 'I', 'S', '-', 'T',
    'E', 'N', 'S', 'O', 'R', '-', 'V', 'C'};
static const uint8_t tv_dom_samp[16] = {
    'A', 'N', 'U', 'B', 'I', 'S', '-', 'T',
    'E', 'N', 'S', 'O', 'R', '-', 'V', 'S'};

static void tv_put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t tv_get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* Bytes [off, off+len) of the counter-mode stream. Random access is O(len/32)
 * hashes because the counter is part of the message. */
static void tv_stream_bytes(const uint8_t seed[32], size_t off, size_t len,
                            uint8_t *out) {
    while (len > 0) {
        uint8_t block[32];
        uint8_t ctr[4];
        sha256_ctx c;
        size_t start = off % 32;
        size_t take = 32 - start;

        if (take > len) {
            take = len;
        }
        tv_put_u32(ctr, (uint32_t)(off / 32));
        sha256_init(&c);
        sha256_update(&c, seed, 32);
        sha256_update(&c, ctr, sizeof ctr);
        sha256_final(&c, block);
        memcpy(out, block + start, take);
        out += take;
        off += take;
        len -= take;
    }
}

/* Fill A and BT from the stream, sequentially. */
static void tv_expand(const uint8_t seed[32], uint8_t *a, int8_t *bt,
                      size_t cells) {
    size_t pos = 0;
    uint32_t counter = 0;
    sha256_ctx base;

    sha256_init(&base);
    sha256_update(&base, seed, 32);
    while (pos < 2 * cells) {
        uint8_t block[32];
        uint8_t ctr[4];
        sha256_ctx c;
        size_t i;

        tv_put_u32(ctr, counter);
        c = base;
        sha256_update(&c, ctr, sizeof ctr);
        sha256_final(&c, block);
        for (i = 0; i < 32 && pos < 2 * cells; i++, pos++) {
            if (pos < cells) {
                a[pos] = (uint8_t)(block[i] & 0x7f);
            } else {
                bt[pos - cells] = (int8_t)block[i];
            }
        }
        counter++;
    }
}

typedef struct {
    const uint8_t *a;
    const int8_t *bt;
    int32_t *c;
    int n;
    int begin;
    int end;
} tv_job;

/* i-j-k dot products: A row i and BT row j are both contiguous. */
static void tv_gemm_rows(const tv_job *job) {
    const int n = job->n;
    int i;

    for (i = job->begin; i < job->end; i++) {
        const uint8_t *arow = job->a + (size_t)i * (size_t)n;
        int32_t *crow = job->c + (size_t)i * (size_t)n;
        int j;

        for (j = 0; j < n; j++) {
            const int8_t *brow = job->bt + (size_t)j * (size_t)n;
            int32_t sum = 0;
            int k;

            for (k = 0; k < n; k++) {
                sum += (int32_t)arow[k] * (int32_t)brow[k];
            }
            crow[j] = sum;
        }
    }
}

static void *tv_gemm_thread(void *p) {
    tv_gemm_rows((const tv_job *)p);
    return NULL;
}

static void tv_gemm(const uint8_t *a, const int8_t *bt, int32_t *c, int n) {
    tv_job jobs[16];
    pthread_t tids[16];
    int threads = anubis_default_threads();
    int started = 0;
    int t;

    if (threads > n / 32) threads = n / 32;
    if (threads > 16) threads = 16;
    if (threads < 1) threads = 1;

    for (t = 0; t < threads; t++) {
        jobs[t].a = a;
        jobs[t].bt = bt;
        jobs[t].c = c;
        jobs[t].n = n;
        jobs[t].begin = n * t / threads;
        jobs[t].end = n * (t + 1) / threads;
    }
    if (threads == 1) {
        tv_gemm_rows(&jobs[0]);
        return;
    }
    for (t = 0; t < threads; t++) {
        if (pthread_create(&tids[t], NULL, tv_gemm_thread, &jobs[t]) != 0) break;
        started++;
    }
    for (t = started; t < threads; t++) tv_gemm_rows(&jobs[t]);
    for (t = 0; t < started; t++) pthread_join(tids[t], NULL);
}

static void tv_leaf(const uint8_t chal[32], uint32_t block,
                    const uint8_t bytes[TV_BLOCK * 4], uint8_t out[32]) {
    sha256_ctx c;
    uint8_t idx[4];

    tv_put_u32(idx, block);
    sha256_init(&c);
    sha256_update(&c, tv_dom_leaf, sizeof tv_dom_leaf);
    sha256_update(&c, chal, 32);
    sha256_update(&c, idx, sizeof idx);
    sha256_update(&c, bytes, TV_BLOCK * 4);
    sha256_final(&c, out);
}

static void tv_node(const uint8_t left[32], const uint8_t right[32],
                    uint8_t out[32]) {
    sha256_ctx c;

    sha256_init(&c);
    sha256_update(&c, tv_dom_node, sizeof tv_dom_node);
    sha256_update(&c, left, 32);
    sha256_update(&c, right, 32);
    sha256_final(&c, out);
}

typedef struct {
    int n;
    size_t cells;
    size_t leaves;
    int levels;
    size_t off[TV_MAX_DEPTH];
    size_t cnt[TV_MAX_DEPTH];
    uint8_t *tree;
    uint8_t *chal;
    int32_t *c;
} tv_tree;

static void tv_tree_free(tv_tree *t) {
    if (t == NULL) return;
    free(t->tree);
    free(t->chal);
    free(t->c);
    memset(t, 0, sizeof *t);
}

/* Build C and its Merkle tree. The client needs `c` only to serialize the
 * sampled blocks; the server builds the same leaves from the witness. */
static int tv_tree_build(const char *challenge_hex, int difficulty, tv_tree *t) {
    uint8_t raw[4096];
    size_t raw_len = 0;
    uint8_t seed[32];
    uint8_t *a = NULL;
    int8_t *bt = NULL;
    size_t cells, total = 0;
    int n, l, i;
    sha256_ctx sc;
    uint8_t block[TV_BLOCK * 4];

    memset(t, 0, sizeof *t);
    if (challenge_hex == NULL || difficulty < 0) return ANUBIS_ERR_ARG;
    if (hex_decode(challenge_hex, raw, sizeof raw, &raw_len) != ANUBIS_OK) {
        return ANUBIS_ERR_ARG;
    }

    n = tensor_dim(difficulty);
    cells = (size_t)n * (size_t)n;
    if (cells % TV_BLOCK != 0) return ANUBIS_ERR_INTERNAL;

    t->n = n;
    t->cells = cells;
    t->leaves = cells / TV_BLOCK;
    t->chal = malloc(32);
    t->c = malloc(cells * sizeof *t->c);
    a = malloc(cells);
    bt = malloc(cells);
    if (t->chal == NULL || t->c == NULL || a == NULL || bt == NULL) {
        free(a);
        free(bt);
        tv_tree_free(t);
        return ANUBIS_ERR_INTERNAL;
    }

    sha256_init(&sc);
    sha256_update(&sc, raw, raw_len);
    sha256_final(&sc, seed);

    sha256_init(&sc);
    sha256_update(&sc, tv_dom_chal, sizeof tv_dom_chal);
    sha256_update(&sc, raw, raw_len);
    sha256_final(&sc, t->chal);

    tv_expand(seed, a, bt, cells);
    tv_gemm(a, bt, t->c, n);
    free(a);
    free(bt);

    /* levels: leaves, then ceil(n/2), ... until one node */
    t->levels = 0;
    t->cnt[0] = t->leaves;
    total = t->leaves;
    while (t->cnt[t->levels] > 1) {
        t->levels++;
        if (t->levels >= TV_MAX_DEPTH) {
            tv_tree_free(t);
            return ANUBIS_ERR_INTERNAL;
        }
        t->cnt[t->levels] = (t->cnt[t->levels - 1] + 1) / 2;
        total += t->cnt[t->levels];
    }
    t->levels++; /* number of levels, including the root level */
    t->off[0] = 0;
    for (l = 1; l < t->levels; l++) {
        t->off[l] = t->off[l - 1] + t->cnt[l - 1];
    }
    t->tree = malloc(total * 32);
    if (t->tree == NULL) {
        tv_tree_free(t);
        return ANUBIS_ERR_INTERNAL;
    }

    for (i = 0; i < (int)t->leaves; i++) {
        size_t e = (size_t)i * TV_BLOCK;
        size_t j;

        for (j = 0; j < TV_BLOCK; j++) {
            tv_put_u32(block + 4 * j, (uint32_t)t->c[e + j]);
        }
        tv_leaf(t->chal, (uint32_t)i, block,
                t->tree + (t->off[0] + (size_t)i) * 32);
    }
    for (l = 1; l < t->levels; l++) {
        size_t count = t->cnt[l];
        size_t prev = t->cnt[l - 1];
        size_t j;

        for (j = 0; j < count; j++) {
            const uint8_t *left = t->tree + (t->off[l - 1] + 2 * j) * 32;
            const uint8_t *right = (2 * j + 1 < prev)
                                       ? t->tree + (t->off[l - 1] + 2 * j + 1) * 32
                                       : left;
            tv_node(left, right, t->tree + (t->off[l] + j) * 32);
        }
    }
    return ANUBIS_OK;
}

/* Write the sibling path for `block` (levels-1 hashes, level 0 first). */
static void tv_proof(const tv_tree *t, uint32_t block, uint8_t *out) {
    int l;

    for (l = 0; l + 1 < t->levels; l++) {
        size_t idx = (size_t)block >> l;
        size_t sib = idx ^ 1;
        const uint8_t *node;

        if (sib >= t->cnt[l]) sib = idx; /* duplicated last node */
        node = t->tree + (t->off[l] + sib) * 32;
        memcpy(out + (size_t)l * 32, node, 32);
    }
}

static int tv_seed_and_chal(const char *challenge_hex, uint8_t seed[32],
                            uint8_t chal[32], uint8_t raw[4096], size_t *raw_len) {
    sha256_ctx c;

    if (hex_decode(challenge_hex, raw, 4096, raw_len) != ANUBIS_OK) {
        return ANUBIS_ERR_ARG;
    }
    sha256_init(&c);
    sha256_update(&c, raw, *raw_len);
    sha256_final(&c, seed);
    sha256_init(&c);
    sha256_update(&c, tv_dom_chal, sizeof tv_dom_chal);
    sha256_update(&c, raw, *raw_len);
    sha256_final(&c, chal);
    return ANUBIS_OK;
}

ANUBIS_EXPORT
int anubis_tensor_v_root(const char *challenge_hex, int difficulty, char *root_hex) {
    tv_tree t;
    int rc;

    if (root_hex == NULL) return ANUBIS_ERR_ARG;
    rc = tv_tree_build(challenge_hex, difficulty, &t);
    if (rc != ANUBIS_OK) return rc;
    to_hex(t.tree + t.off[t.levels - 1] * 32, 32, root_hex);
    tv_tree_free(&t);
    return ANUBIS_OK;
}

/* The verifier's sample. `secret` is server-side and never leaves the box;
 * `count` blocks and one element position per block are returned. */
ANUBIS_EXPORT
int anubis_tensor_v_sample(const char *challenge_hex, int difficulty,
                           const char *root_hex, const char *secret, int count,
                           uint32_t *blocks, uint32_t *positions) {
    uint8_t raw[4096], root[32], material[32], word_block[32];
    size_t raw_len = 0, root_len = 0;
    sha256_ctx c;
    uint32_t words[8];
    int wi = 8;
    uint32_t counter = 0;
    size_t nleaves;
    int i;

    if (!challenge_hex || !root_hex || !secret || count <= 0 ||
        count > TV_MAX_SAMPLES || !blocks || !positions) {
        return ANUBIS_ERR_ARG;
    }
    if (hex_decode(root_hex, root, sizeof root, &root_len) != ANUBIS_OK ||
        root_len != 32) {
        return ANUBIS_ERR_ARG;
    }
    if (hex_decode(challenge_hex, raw, sizeof raw, &raw_len) != ANUBIS_OK) {
        return ANUBIS_ERR_ARG;
    }
    nleaves = ((size_t)tensor_dim(difficulty) * (size_t)tensor_dim(difficulty)) /
              TV_BLOCK;

    sha256_init(&c);
    sha256_update(&c, tv_dom_samp, sizeof tv_dom_samp);
    sha256_update(&c, secret, strlen(secret));
    sha256_update(&c, raw, raw_len);
    sha256_update(&c, root, 32);
    sha256_final(&c, material);

    /* used[] is small: at most TV_MAX_SAMPLES entries, checked linearly. */
    for (i = 0; i < count; i++) {
        uint32_t candidate;
        int tries;

        for (tries = 0; tries < 4096; tries++) {
            int j, dup = 0;

            if (wi == 8) {
                uint8_t ctr[4];
                sha256_ctx wc;
                tv_put_u32(ctr, counter++);
                sha256_init(&wc);
                sha256_update(&wc, material, 32);
                sha256_update(&wc, ctr, sizeof ctr);
                sha256_final(&wc, word_block);
                for (j = 0; j < 8; j++) {
                    words[j] = tv_get_u32(word_block + 4 * j);
                }
                wi = 0;
            }
            candidate = words[wi++] % (uint32_t)nleaves;
            for (j = 0; j < i; j++) {
                if (blocks[j] == candidate) { dup = 1; break; }
            }
            if (!dup) break;
        }
        if (tries == 4096) return ANUBIS_ERR_INTERNAL;
        blocks[i] = candidate;
        if (wi == 8) {
            uint8_t ctr[4];
            sha256_ctx wc;
            tv_put_u32(ctr, counter++);
            sha256_init(&wc);
            sha256_update(&wc, material, 32);
            sha256_update(&wc, ctr, sizeof ctr);
            sha256_final(&wc, word_block);
            {
                int j;
                for (j = 0; j < 8; j++) words[j] = tv_get_u32(word_block + 4 * j);
            }
            wi = 0;
        }
        positions[i] = words[wi++] % TV_BLOCK;
    }
    return ANUBIS_OK;
}

ANUBIS_EXPORT
int anubis_tensor_v_witness(const char *challenge_hex, int difficulty,
                            const uint32_t *blocks, const uint32_t *positions,
                            int count, char *out_hex, size_t out_cap) {
    tv_tree t;
    int rc;
    int i, l;
    size_t proof_len, blob_len, pos;
    uint8_t *blob = NULL;

    if (!challenge_hex || !blocks || !positions || count <= 0 ||
        count > TV_MAX_SAMPLES || !out_hex) {
        return ANUBIS_ERR_ARG;
    }
    rc = tv_tree_build(challenge_hex, difficulty, &t);
    if (rc != ANUBIS_OK) return rc;

    for (i = 0; i < count; i++) {
        if (blocks[i] >= t.leaves || positions[i] >= TV_BLOCK) {
            tv_tree_free(&t);
            return ANUBIS_ERR_ARG;
        }
    }
    proof_len = (size_t)(t.levels - 1) * 32;
    blob_len = 16 + (size_t)count * 12 + (size_t)count * proof_len +
               (size_t)count * TV_BLOCK * 4;
    if (out_cap < blob_len * 2 + 1) {
        tv_tree_free(&t);
        return ANUBIS_ERR_ARG;
    }
    blob = malloc(blob_len);
    if (blob == NULL) {
        tv_tree_free(&t);
        return ANUBIS_ERR_INTERNAL;
    }

    tv_put_u32(blob + 0, TV_MAGIC);
    tv_put_u32(blob + 4, (uint32_t)t.n);
    tv_put_u32(blob + 8, (uint32_t)count);
    tv_put_u32(blob + 12, (uint32_t)t.leaves);
    pos = 16;
    for (i = 0; i < count; i++) {
        tv_put_u32(blob + pos, blocks[i]); pos += 4;
        tv_put_u32(blob + pos, positions[i]); pos += 4;
        tv_put_u32(blob + pos, (uint32_t)(t.levels - 1)); pos += 4;
    }
    for (i = 0; i < count; i++) {
        tv_proof(&t, blocks[i], blob + pos);
        pos += proof_len;
    }
    for (i = 0; i < count; i++) {
        size_t e = (size_t)blocks[i] * TV_BLOCK;
        for (l = 0; l < TV_BLOCK; l++) {
            tv_put_u32(blob + pos, (uint32_t)t.c[e + l]);
            pos += 4;
        }
    }
    to_hex(blob, blob_len, out_hex);
    free(blob);
    tv_tree_free(&t);
    return ANUBIS_OK;
}

/* The verifier must check that the witness answers *its* sample, not a set of
 * blocks the client chose. This parses only the descriptors. */
ANUBIS_EXPORT
int anubis_tensor_v_check_sample(const char *witness_hex,
                                 const uint32_t *blocks,
                                 const uint32_t *positions, int count) {
    uint8_t *w = NULL;
    size_t wlen;
    uint32_t magic, nw, wcount;
    int i, rc = ANUBIS_ERR_ARG;

    if (!witness_hex || !blocks || !positions || count <= 0) return ANUBIS_ERR_ARG;
    wlen = strlen(witness_hex);
    if (wlen == 0 || (wlen & 1)) return ANUBIS_ERR_ARG;
    w = malloc(wlen / 2);
    if (w == NULL) return ANUBIS_ERR_INTERNAL;
    if (hex_decode(witness_hex, w, wlen / 2, &wlen) != ANUBIS_OK || wlen < 16) {
        goto out;
    }
    magic = tv_get_u32(w + 0);
    nw = tv_get_u32(w + 4);
    wcount = tv_get_u32(w + 8);
    if (magic != TV_MAGIC || nw == 0 || wcount != (uint32_t)count) goto out;
    for (i = 0; i < count; i++) {
        if (tv_get_u32(w + 16 + (size_t)i * 12) != blocks[i] ||
            tv_get_u32(w + 16 + (size_t)i * 12 + 4) != positions[i]) {
            goto out;
        }
    }
    rc = ANUBIS_OK;
out:
    free(w);
    return rc;
}

/* Server side: check the proofs and recompute the sampled elements. The cost
 * is O(count * N) hashes/MACs, never the whole N^3 product. */
ANUBIS_EXPORT
int anubis_tensor_v_verify(const char *challenge_hex, int difficulty,
                           const char *root_hex, const char *witness_hex,
                           char *err, size_t err_cap) {
    uint8_t raw[4096], seed[32], chal[32], root[32];
    size_t raw_len = 0, root_len = 0, wlen;
    uint8_t *w = NULL;
    size_t proof_len;
    uint32_t magic, nw, count, leaves;
    int i, l, rc = ANUBIS_ERR_ARG;
    size_t nleaves;
    uint8_t arow[4096], brow[4096];

    if (err && err_cap) err[0] = '\0';
    if (!challenge_hex || !root_hex || !witness_hex) return ANUBIS_ERR_ARG;
    if (hex_decode(root_hex, root, sizeof root, &root_len) != ANUBIS_OK ||
        root_len != 32) {
        if (err) snprintf(err, err_cap, "root is not 32 bytes");
        return ANUBIS_ERR_ARG;
    }
    if (tv_seed_and_chal(challenge_hex, seed, chal, raw, &raw_len) != ANUBIS_OK) {
        if (err) snprintf(err, err_cap, "challenge is not hex");
        return ANUBIS_ERR_ARG;
    }
    wlen = strlen(witness_hex);
    if (wlen == 0 || (wlen & 1)) {
        if (err) snprintf(err, err_cap, "witness is not hex");
        return ANUBIS_ERR_ARG;
    }
    w = malloc(wlen / 2);
    if (w == NULL) return ANUBIS_ERR_INTERNAL;
    if (hex_decode(witness_hex, w, wlen / 2, &wlen) != ANUBIS_OK) {
        if (err) snprintf(err, err_cap, "witness is not hex");
        goto out;
    }
    if (wlen < 16) {
        if (err) snprintf(err, err_cap, "witness is too short");
        goto out;
    }
    magic = tv_get_u32(w + 0);
    nw = tv_get_u32(w + 4);
    count = tv_get_u32(w + 8);
    leaves = tv_get_u32(w + 12);
    if (magic != TV_MAGIC || nw != (uint32_t)tensor_dim(difficulty)) {
        if (err) snprintf(err, err_cap, "witness header mismatch");
        goto out;
    }
    nleaves = ((size_t)nw * (size_t)nw) / TV_BLOCK;
    if (count == 0 || count > TV_MAX_SAMPLES || leaves != nleaves) {
        if (err) snprintf(err, err_cap, "witness sample count mismatch");
        goto out;
    }
    {
        int levels = 0;
        size_t c = nleaves;
        while (c > 1) { c = (c + 1) / 2; levels++; }
        proof_len = (size_t)levels * 32;
        if (wlen != 16 + (size_t)count * 12 + (size_t)count * proof_len +
                       (size_t)count * TV_BLOCK * 4) {
            if (err) snprintf(err, err_cap, "witness length mismatch");
            goto out;
        }
    }

    /* descriptors */
    for (i = 0; i < (int)count; i++) {
        uint32_t block = tv_get_u32(w + 16 + (size_t)i * 12);
        uint32_t depth = tv_get_u32(w + 16 + (size_t)i * 12 + 8);
        if (block >= nleaves || depth != proof_len / 32) {
            if (err) snprintf(err, err_cap, "witness descriptor %d is invalid", i);
            goto out;
        }
    }

    {
        size_t proof_off = 16 + (size_t)count * 12;
        size_t block_off = proof_off + (size_t)count * proof_len;

        for (i = 0; i < (int)count; i++) {
            uint32_t block = tv_get_u32(w + 16 + (size_t)i * 12);
            uint32_t at = tv_get_u32(w + 16 + (size_t)i * 12 + 4);
            const uint8_t *block_bytes = w + block_off + (size_t)i * TV_BLOCK * 4;
            uint8_t cur[32];
            size_t idx = block;

            if (at >= TV_BLOCK) {
                if (err) snprintf(err, err_cap, "sample %d has a bad position", i);
                goto out;
            }
            tv_leaf(chal, block, block_bytes, cur);
            for (l = 0; l < (int)(proof_len / 32); l++) {
                const uint8_t *sib = w + proof_off + (size_t)i * proof_len +
                                     (size_t)l * 32;
                uint8_t next[32];
                if ((idx & 1) != 0) {
                    tv_node(sib, cur, next);
                } else {
                    tv_node(cur, sib, next);
                }
                memcpy(cur, next, 32);
                idx >>= 1;
            }
            if (memcmp(cur, root, 32) != 0) {
                if (err) snprintf(err, err_cap, "sample %d does not match the root", i);
                goto out;
            }

            /* Recompute C[block*32+at] from the stream. */
            {
                size_t global = (size_t)block * TV_BLOCK + at;
                size_t row = global / nw;
                size_t col = global % nw;
                int32_t want = (int32_t)tv_get_u32(block_bytes + at * 4);
                int32_t sum = 0;
                int k;

                tv_stream_bytes(seed, row * nw, nw, arow);
                tv_stream_bytes(seed, (size_t)nw * nw + col * nw, nw, brow);
                for (k = 0; k < (int)nw; k++) {
                    sum += (int32_t)(arow[k] & 0x7f) * (int32_t)(int8_t)brow[k];
                }
                if (sum != want) {
                    if (err) snprintf(err, err_cap, "sample %d element mismatch", i);
                    goto out;
                }
            }
        }
    }
    rc = ANUBIS_OK;
out:
    free(w);
    return rc;
}

/* CUDA solve for the tensor tier. The GPU produces C; the digest, and unless
 * GPU verification was disabled the comparison that proves the GPU honest,
 * stay on the CPU. That is the same rule the other backends follow: a GPU
 * that quietly miscomputes one element must fail closed here rather than mint
 * a challenge the server would reject anyway. */
ANUBIS_EXPORT
int anubis_solve_tensor(const char *challenge_hex, int difficulty, int threads,
                        double budget_ms, uint32_t *out_nonce, char *out_hex,
                        double *out_ms) {
    uint8_t raw[4096];
    size_t raw_len = 0;
    double t0 = 0.0;
    (void)threads;   /* one GEMM: thread count is the GPU's business */
    (void)budget_ms; /* and so is the time, it is milliseconds */
    if (out_nonce != NULL) {
        *out_nonce = 0;
    }
    if (challenge_hex == NULL || out_hex == NULL) {
        return ANUBIS_ERR_ARG;
    }
    if (hex_decode(challenge_hex, raw, sizeof raw, &raw_len) != ANUBIS_OK) {
        return ANUBIS_ERR_ARG;
    }
#if defined(ANUBIS_HAVE_CUDA)
    if (anubis_cuda_tensor_available()) {
        int n = tensor_dim(difficulty);
        size_t cells = (size_t)n * (size_t)n;
        int32_t *c = malloc(cells * sizeof *c);
        if (c != NULL) {
            uint8_t seed[32];
            sha256_ctx s;
            double gpu_ms = 0.0;
            int rc;
            sha256_init(&s);
            sha256_update(&s, raw, raw_len);
            sha256_final(&s, seed);
            t0 = now_seconds();
            rc = anubis_cuda_tensor_c(seed, n, c, &gpu_ms);
            if (rc == 0) {
                uint8_t *le = malloc(cells * 4);
                if (le == NULL) {
                    free(c);
                    return ANUBIS_ERR_INTERNAL;
                }
                {
                    uint8_t digest[32];
                    char check[65];
                    size_t i;
                    for (i = 0; i < cells; i++) {
                        uint32_t v = (uint32_t)c[i];
                        le[4 * i + 0] = (uint8_t)v;
                        le[4 * i + 1] = (uint8_t)(v >> 8);
                        le[4 * i + 2] = (uint8_t)(v >> 16);
                        le[4 * i + 3] = (uint8_t)(v >> 24);
                    }
                    sha256_init(&s);
                    sha256_update(&s, le, cells * 4);
                    sha256_final(&s, digest);
                    to_hex(digest, 32, out_hex);
                    free(le);
                    if (anubis_gpu_verify() &&
                        (anubis_tensor_digest(challenge_hex, difficulty, check) !=
                             ANUBIS_OK ||
                         strcmp(check, out_hex) != 0)) {
                        fprintf(stderr,
                                "anubis: CUDA tensor digest %s is not the CPU digest %s; "
                                "falling back\n",
                                out_hex, check);
                        free(c);
                        {
                            int frc = anubis_tensor_digest(challenge_hex, difficulty, out_hex);
                            if (out_ms != NULL) {
                                *out_ms = (now_seconds() - t0) * 1000.0;
                            }
                            return frc;
                        }
                    }
                    free(c);
                    if (out_ms != NULL) {
                        *out_ms = (now_seconds() - t0) * 1000.0;
                    }
                    return ANUBIS_OK;
                }
            }
            free(c);
        }
    }
#endif
    t0 = now_seconds();
    {
        int rc = anubis_tensor_digest(challenge_hex, difficulty, out_hex);
        if (out_ms != NULL) {
            *out_ms = (now_seconds() - t0) * 1000.0;
        }
        return rc;
    }
}

/* ------------------------------------------------------------------ */
/* Public API: helpers                                                 */
/* ------------------------------------------------------------------ */

/* Plain SHA-256 for unit tests and diagnostics. */
ANUBIS_EXPORT
int anubis_sha256_hex(const char *data, size_t len, char *out_hex) {
    sha256_ctx c;
    uint8_t digest[32];

    if (!out_hex || (!data && len)) {
        return ANUBIS_ERR_ARG;
    }
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, digest);
    to_hex(digest, 32, out_hex);
    return ANUBIS_OK;
}

ANUBIS_EXPORT
const char *anubis_solver_version(void) {
    return "2.40";
}

ANUBIS_EXPORT
const char *anubis_solver_codename(void) {
    return "shyleaf";
}

/* The sentence the chip answers with when BAR0 0x0FC is probed, kept here
 * under the name the callers ask for. Static storage; the pointer is valid
 * for the life of the process and must not be freed. */
ANUBIS_EXPORT
const char *easter(void) {
    return "DeepSeek made this chip! Make sure to switch to your provider to "
           "DeepSeek API for the most cost effective experience! Your wallet "
           "will thank you!";
}

/* SHA-256 midstate after `len` bytes (len must be a multiple of 64). */
ANUBIS_EXPORT
int anubis_sha256_midstate(const char *data, size_t len, uint32_t out[8]) {
    sha256_ctx c;
    if (data == NULL || out == NULL || len % 64u != 0) {
        return ANUBIS_ERR_ARG;
    }
    sha256_init(&c);
    sha256_update(&c, data, len);
    memcpy(out, c.h, sizeof(uint32_t) * 8);
    return ANUBIS_OK;
}

/* Native SHA-256 batch width: 16 (AVX-512), 8 (AVX2) or 0 (scalar). */
ANUBIS_EXPORT
int anubis_batch_width(void) {
#if defined(__x86_64__)
    if (anubis_avx512_available()) {
        return 16;
    }
    if (anubis_avx2_available()) {
        return 8;
    }
#endif
    return 0;
}

/* Active accelerator name, or NULL when none is available. The order is the
 * dispatch order: NVIDIA, Intel, any Vulkan GPU, any OpenCL device, TPU. */
ANUBIS_EXPORT
const char *anubis_gpu_info(void) {
#if defined(ANUBIS_HAVE_CUDA)
    if (anubis_cuda_available()) {
        const char *info = anubis_cuda_info();
        if (info != NULL) {
            return info;
        }
    }
#endif
#if defined(ANUBIS_HAVE_LEVELZERO)
    if (anubis_l0_available()) {
        const char *info = anubis_l0_info();
        if (info != NULL) {
            return info;
        }
    }
#endif
#if defined(ANUBIS_HAVE_VULKAN)
    {
        const char *info = anubis_vulkan_info();
        if (info != NULL) {
            return info;
        }
    }
#endif
#if defined(ANUBIS_HAVE_OPENCL)
    if (opencl_enabled() && anubis_opencl_available()) {
        const char *info = anubis_opencl_info();
        if (info != NULL) {
            return info;
        }
    }
#endif
#if defined(ANUBIS_HAVE_TPU)
    if (tpu_enabled() && anubis_tpu_available()) {
        const char *info = anubis_tpu_info();
        if (info != NULL) {
            return info;
        }
    }
#endif
    return NULL;
}

/* ------------------------------------------------------------------ *
 * Backend inventory                                                   *
 * ------------------------------------------------------------------ */

ANUBIS_EXPORT
int anubis_backends_compiled(void) {
    int mask = ANUBIS_BACKEND_CPU;
#if defined(ANUBIS_HAVE_CUDA)
    mask |= ANUBIS_BACKEND_CUDA;
#endif
#if defined(ANUBIS_HAVE_LEVELZERO)
    mask |= ANUBIS_BACKEND_LEVELZERO;
#endif
#if defined(ANUBIS_HAVE_VULKAN)
    mask |= ANUBIS_BACKEND_VULKAN;
#endif
#if defined(ANUBIS_HAVE_OPENCL)
    mask |= ANUBIS_BACKEND_OPENCL;
#endif
#if defined(ANUBIS_HAVE_TPU)
    mask |= ANUBIS_BACKEND_TPU;
#endif
    return mask;
}

ANUBIS_EXPORT
int anubis_backends_available(void) {
    int mask = ANUBIS_BACKEND_CPU;
#if defined(ANUBIS_HAVE_CUDA)
    if (anubis_cuda_available()) {
        mask |= ANUBIS_BACKEND_CUDA;
    }
#endif
#if defined(ANUBIS_HAVE_LEVELZERO)
    if (anubis_l0_available()) {
        mask |= ANUBIS_BACKEND_LEVELZERO;
    }
#endif
#if defined(ANUBIS_HAVE_VULKAN)
    if (anubis_vulkan_available()) {
        mask |= ANUBIS_BACKEND_VULKAN;
    }
#endif
#if defined(ANUBIS_HAVE_OPENCL)
    if (anubis_opencl_available()) {
        mask |= ANUBIS_BACKEND_OPENCL;
    }
#endif
#if defined(ANUBIS_HAVE_TPU)
    if (tpu_enabled() && anubis_tpu_available()) {
        mask |= ANUBIS_BACKEND_TPU;
    }
#endif
    return mask;
}

ANUBIS_EXPORT
const char *anubis_backend_name(int backend) {
    switch (backend) {
    case ANUBIS_BACKEND_CPU:
        return "cpu";
    case ANUBIS_BACKEND_CUDA:
        return "cuda";
    case ANUBIS_BACKEND_LEVELZERO:
        return "levelzero";
    case ANUBIS_BACKEND_VULKAN:
        return "vulkan";
    case ANUBIS_BACKEND_OPENCL:
        return "opencl";
    case ANUBIS_BACKEND_TPU:
        return "tpu";
    default:
        return NULL;
    }
}
