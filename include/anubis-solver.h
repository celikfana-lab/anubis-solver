/*
 * anubis-solver.h — public C/C++ API for libanubis_solver.
 *
 * C:   #include <anubis-solver.h>
 * C++: #include <anubis-solver.h>   (functions are declared extern "C")
 *
 * Build:  cc  demo.c   -Iinclude -L. -lanubis_solver -Wl,-rpath,'$ORIGIN'
 *         c++ demo.cpp -Iinclude -L. -lanubis_solver -Wl,-rpath,'$ORIGIN'
 */

#ifndef ANUBIS_SOLVER_H
#define ANUBIS_SOLVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes. */
#define ANUBIS_OK 0
#define ANUBIS_ERR_ARG 1
#define ANUBIS_ERR_UNSOLVED 2
#define ANUBIS_ERR_INTERNAL 3

#if defined(_WIN32) && defined(ANUBIS_BUILD_SHARED)
#  define ANUBIS_API __declspec(dllexport)
#elif defined(_WIN32)
#  define ANUBIS_API __declspec(dllimport)
#else
#  define ANUBIS_API
#endif

/* ------------------------------------------------------------------ *
 * Introspection
 * ------------------------------------------------------------------ */

/* Library version, e.g. "2.50". */
ANUBIS_API const char *anubis_solver_version(void);

/* Release codename, e.g. "mule". */
ANUBIS_API const char *anubis_solver_codename(void);

/* ------------------------------------------------------------------ *
 * Backends
 *
 * One .so carries every backend that could be compiled in; at run time the
 * library probes the machine and solves on whatever it finds. Vendor APIs are
 * dlopen()ed, so a build with all of them loads on a machine with none.
 * ------------------------------------------------------------------ */

#define ANUBIS_BACKEND_CPU 0x01          /* always */
#define ANUBIS_BACKEND_CUDA 0x02         /* NVIDIA, needs nvcc at build time */
#define ANUBIS_BACKEND_LEVELZERO 0x04    /* Intel Xe */
#define ANUBIS_BACKEND_VULKAN 0x08       /* any Vulkan ICD */
#define ANUBIS_BACKEND_OPENCL 0x10       /* any OpenCL ICD */
#define ANUBIS_BACKEND_TPU 0x20          /* Google, PJRT / libtpu */

/* Bitmask of the backends compiled into this .so. */
ANUBIS_API int anubis_backends_compiled(void);

/* Bitmask of those that are usable right now. Probes the hardware once per
 * backend and caches; a missing driver or device is not an error here. */
ANUBIS_API int anubis_backends_available(void);

/* Name of one backend bit ("cpu", "cuda", "levelzero", "vulkan", "opencl",
 * "tpu"), or NULL when the argument is not a single backend bit. */
ANUBIS_API const char *anubis_backend_name(int backend);

/* Easter egg. Returns the same sentence the chip answers to a probe of BAR0
 * at 0x0FC in `beyond/` — a static string, no arguments, never NULL, never
 * freed. Symbol name is exactly `easter` (no anubis_ prefix) because that is
 * the name the callers look for. */
ANUBIS_API const char *easter(void);

/* Name of the active GPU backend (e.g. "CUDA: Tesla T4 x2"), or NULL. */
ANUBIS_API const char *anubis_gpu_info(void);

/* CUDA kernel selector: returns the name of the kernel that will be used for
 * the given mode (0 = fast/slow decimal nonce, 1 = sha256 u32 nonce).
 * Values: "original", "optimized (auto)", "optimized (ILP=N)",
 * "original (opt requires mode 1)", or "unavailable". */
ANUBIS_API const char *anubis_cuda_kernel_name(int mode);

/* Sensible default worker count (physical cores). */
ANUBIS_API int anubis_default_threads(void);

/* Human-readable CPU affinity, e.g. "P-cores (0,2,4,...)" or "off". */
ANUBIS_API const char *anubis_cpu_affinity_info(void);

/* SHA-256 batch width: 16 (AVX-512), 8 (AVX2), 0 (scalar). */
ANUBIS_API int anubis_batch_width(void);

/* GPU hit verification (default on). Disabling it trusts the GPU result as-is
 * and skips one reference hash per hit; useful for benchmarking only. */
ANUBIS_API void anubis_set_gpu_verify(int enable);
ANUBIS_API int anubis_gpu_verify(void);

/* Pin every NVIDIA GPU at its maximum SM clock through NVML.
 *
 * A Tesla T4 idles at 300 MHz and boosts to ~1.5 GHz only under sustained
 * load, so a short benchmark measures the ramp rather than the kernel. Call
 * this once before timing, and anubis_nvidia_clock_mhz() between rows.
 *
 * Clock control needs root (CAP_SYS_ADMIN). Returns 0 when at least one device
 * was locked, otherwise -1 (no libnvidia-ml.so), -2 (no devices), -3 (needs
 * root), -4 (driver older than R450 / unsupported GPU) or -5 (driver refused
 * the value: power or thermal policy). See anubis_nvidia_boost_info().
 *
 * The lock lasts until the process exits or the driver is reset. Only NVML is
 * touched -- no nvidia-smi, no external process, no writes outside the driver.
 */
ANUBIS_API int anubis_nvidia_force_boost_max(void);
ANUBIS_API int force_nvidia_boost_max(void);   /* same, for plain ctypes */
ANUBIS_API int anubis_nvidia_clock_mhz(void);  /* first device, or -1 */
ANUBIS_API const char *anubis_nvidia_boost_info(void);
/* TPU hit verification (default on). Resolves as: the value set here, then
 * ANUBIS_TPU_NO_VERIFY=1, then anubis_gpu_verify(). Pass -1 to clear the
 * override and fall back to the env / inherited switch. "Off" skips only the
 * second reference hash in the core: anubis_tpu_solve() always derives the
 * winning digest itself, since the device reports just a lane flag. */
ANUBIS_API void anubis_set_tpu_verify(int enable);
ANUBIS_API int anubis_tpu_verify(void);

/* ------------------------------------------------------------------ *
 * SHA-256 helpers
 * ------------------------------------------------------------------ */

/* Hex SHA-256 of `data`; `out_hex` must hold 65 bytes. */
ANUBIS_API int anubis_sha256_hex(const char *data, size_t len, char *out_hex);

/* SHA-256 midstate after `len` bytes (len must be a multiple of 64). */
ANUBIS_API int anubis_sha256_midstate(const char *data, size_t len,
                                      uint32_t out[8]);

/* ------------------------------------------------------------------ *
 * Solving
 *
 * Each returns ANUBIS_OK on a hit, ANUBIS_ERR_UNSOLVED when max_nonce or
 * budget_ms is exhausted, or another ANUBIS_* error code.
 *
 * threads:   0 = anubis_default_threads()
 * max_nonce: 0 = no nonce limit (nibbles family only)
 * budget_ms: <= 0 = no time limit
 * out_hex:   65-byte buffer, receives the hash as lowercase hex
 * out_ms:    optional, receives the elapsed time
 * ------------------------------------------------------------------ */

/* `fast` / `slow` (leading zero nibbles). */
ANUBIS_API int anubis_solve_nibbles(const char *challenge, int difficulty,
                                    int threads, int64_t max_nonce,
                                    double budget_ms, uint64_t *out_nonce,
                                    char *out_hex, double *out_ms);

/* `sha256` / `wasm-sha256` (leading zero bits). */
ANUBIS_API int anubis_solve_bits(const char *challenge_hex, int difficulty,
                                 int threads, double budget_ms,
                                 uint32_t *out_nonce, char *out_hex,
                                 double *out_ms);

/* `argon2id` (leading zero bits, Argon2id v1.3). */
ANUBIS_API int anubis_solve_argon2id(const char *challenge_hex, int difficulty,
                                     int threads, double budget_ms,
                                     uint32_t *out_nonce, char *out_hex,
                                     double *out_ms);

/* `hashx` (leading zero bits, HashX program). */
ANUBIS_API int anubis_solve_hashx(const char *challenge_hex, int difficulty,
                                  int threads, double budget_ms,
                                  uint32_t *out_nonce, char *out_hex,
                                  double *out_ms);

/* `meatrider` (leading zero bits, SHA-256d over a Bitcoin block header).
 *
 * The 32-byte `randomData` seeds a real 80-byte header:
 * version 1, prev block = randomData, merkle = SHA256("meatrider" || randomData),
 * time = the genesis timestamp, bits = compact(2^(256-difficulty)), and the
 * nonce in the last four bytes. The digest is reported in Bitcoin's display
 * order, so `difficulty` means exactly what it means for every other tier.
 *
 * `difficulty` is 1..255 here (a 256-bit target does not fit nBits), and a
 * 32-bit nonce space above 32 bits of difficulty means one full sweep is
 * unlikely to succeed: that is the "you are an ASIC now" end of the ladder.
 *
 * The target is a field of the header, as Bitcoin's nBits is, so a proof is
 * valid only at the difficulty it was mined for: the same nonce hashes to a
 * different digest at another difficulty. Verifiers should use the difficulty
 * the challenge was issued with, which is what the gate does.
 *
 * The price helpers are labels on the work, not payments: they answer what an
 * Antminer S21 Pro earns doing 2^difficulty hashes, at `usd_per_th_day` per
 * terahash-day (0 = the 0.05 default). No money changes hands anywhere in this
 * library. */
ANUBIS_API int anubis_solve_meatrider(const char *challenge_hex, int difficulty,
                                      int threads, double budget_ms,
                                      uint32_t *out_nonce, char *out_hex,
                                      double *out_ms);

/* The full 80-byte header as 160 hex characters plus a terminator: `out_hex`
 * must hold 161 bytes. Useful for showing that the proof really is Bitcoin's
 * header and not a hash of the challenge string. */
ANUBIS_API int anubis_meatrider_header(const char *challenge_hex, int difficulty,
                                       uint32_t nonce, char *out_hex);

/* nBits for the exact target 2^(256-difficulty). */
ANUBIS_API unsigned anubis_meatrider_bits(int difficulty);

/* What the work is worth in USD, how long an ASIC needs for it, and the rung's
 * name ("atom", "suspicious", "asic", "meatrider", ...). */
ANUBIS_API double anubis_meatrider_price_usd(int difficulty, double usd_per_th_day);
ANUBIS_API double anubis_meatrider_asic_seconds(int difficulty, double hashrate);
ANUBIS_API const char *anubis_meatrider_tier(int difficulty);

/* The difficulty whose price first reaches `usd`, i.e. which rung to ask for. */
ANUBIS_API int anubis_meatrider_difficulty_for_usd(double usd,
                                                   double usd_per_th_day);

/* ------------------------------------------------------------------ *
 * The meatrider backends
 *
 * Every one of them computes the same digest: the tier's promise is that a
 * proof does not care which kernel produced it. These exist so that promise is
 * checkable — ask a named kernel for the digest of one nonce, or search with
 * only that kernel, and compare against the portable reference. That is what
 * tools/meatrider_backends.py does.
 *
 * ANUBIS_MEATRIDER_BACKEND=cpu|shani|avx2|avx512|opencl|vulkan|levelzero|cuda|tpu
 * pins anubis_solve_meatrider() to one kernel; a name that is compiled out or
 * has no device falls back to the next available kernel, and
 * anubis_meatrider_backend_available() says which of those would happen.
 *
 * An accelerator is only asked when the rung is worth a dispatch: below
 * 2^ANUBIS_MEATRIDER_MIN_WORK hashes (default 2^20) the CPU kernel is faster,
 * because a dispatch costs ~60 ms where the CPU does a rung in a millisecond.
 * Set ANUBIS_MEATRIDER_MIN_WORK=0 to always dispatch, or a larger number to
 * keep small rungs on the CPU.
 *
 * The CPU kernels (cpu, shani, avx2, avx512) hash one nonce at a time here;
 * the search uses the widest of them. The accelerators report only hits, so
 * their digest is a hit digest: ask for one nonce and a miss means "this
 * kernel reports nothing for that nonce", not "the digest is unknown".
 * ------------------------------------------------------------------ */

#define ANUBIS_MR_SCALAR 0   /* portable C, always present */
#define ANUBIS_MR_SHANI 1    /* Intel SHA extensions */
#define ANUBIS_MR_AVX2 2     /* 8 nonces per pass */
#define ANUBIS_MR_AVX512 3   /* 16 nonces per pass */
#define ANUBIS_MR_OPENCL 4
#define ANUBIS_MR_VULKAN 5
#define ANUBIS_MR_L0 6       /* Intel Level Zero */
#define ANUBIS_MR_CUDA 7     /* CUDA C and the generated PTX */
#define ANUBIS_MR_TPU 8      /* Google PJRT */

ANUBIS_API int anubis_meatrider_backend_count(void);
ANUBIS_API const char *anubis_meatrider_backend_name(int backend);
/* 1 when the kernel is compiled in and this machine can run it now. */
ANUBIS_API int anubis_meatrider_backend_available(int backend);
/* What anubis_solve_meatrider() will pick: the ANUBIS_MEATRIDER_BACKEND pin,
 * else the first available accelerator (CUDA, Level Zero, Vulkan, OpenCL),
 * else the widest CPU kernel. */
ANUBIS_API int anubis_meatrider_backend_active(void);

/* anubis_solve_meatrider() on one named kernel. Same return codes and same
 * contract: threads and budget_ms as above. */
ANUBIS_API int anubis_meatrider_backend_solve(const char *challenge_hex,
                                              int difficulty, int backend,
                                              int threads, double budget_ms,
                                              uint32_t *out_nonce,
                                              char *out_hex, double *out_ms);

/* One nonce's digest (65-byte hex buffer) from one named kernel. Returns
 * ANUBIS_OK, ANUBIS_ERR_ARG for an unknown challenge, or ANUBIS_ERR_INTERNAL
 * when that kernel is unavailable or does not report a digest for that nonce. */
ANUBIS_API int anubis_meatrider_backend_digest(const char *challenge_hex,
                                               int difficulty, int backend,
                                               uint32_t nonce, char *out_hex);

/* ------------------------------------------------------------------ *
 * Verification (re-check a nonce; returns ANUBIS_OK when valid)
 * ------------------------------------------------------------------ */

ANUBIS_API int anubis_verify_nibbles(const char *challenge, uint64_t nonce,
                                     int difficulty, char *out_hex);
ANUBIS_API int anubis_verify_bits(const char *challenge_hex, uint32_t nonce,
                                  int difficulty, char *out_hex);
ANUBIS_API int anubis_verify_argon2id(const char *challenge_hex, uint32_t nonce,
                                      int difficulty, char *out_hex);
ANUBIS_API int anubis_verify_hashx(const char *challenge_hex, uint32_t nonce,
                                   int difficulty, char *out_hex);
ANUBIS_API int anubis_verify_meatrider(const char *challenge_hex, uint32_t nonce,
                                       int difficulty, char *out_hex);

/* `tensor`: one integer GEMM, digest of the result. Deterministic, so the
 * proof is the digest itself and the nonce is always 0; verification
 * recomputes one GEMM and costs no more than one solve. */
ANUBIS_API int anubis_verify_tensor(const char *challenge_hex, uint32_t nonce,
                                    int difficulty, char *out_hex);
ANUBIS_API int anubis_tensor_digest(const char *challenge_hex, int difficulty,
                                    char *out_hex);

/* `tensor` solve. The proof is deterministic (nonce 0), so this is the same
 * digest as anubis_tensor_digest; when a CUDA device is present the GEMM runs
 * there and the digest is still checked against the CPU reference unless
 * anubis_set_gpu_verify(0). threads and budget_ms do not apply. */
ANUBIS_API int anubis_solve_tensor(const char *challenge_hex, int difficulty,
                                   int threads, double budget_ms,
                                   uint32_t *out_nonce, char *out_hex,
                                   double *out_ms);

/* `tensor-v`: the sampled-proof tensor tier.
 *
 * The client computes the same integer GEMM as `tensor` (A row-major uint8,
 * BT row-major int8 -- BT is the transpose of the stream's second matrix) and
 * commits to C in 32-element blocks with a Merkle root. The server samples k
 * blocks from a secret and verifies those blocks and one element inside each,
 * O(k*N) instead of the whole N^3 product. A client that computed a fraction
 * f of the elements is accepted with probability f^k.
 *
 * anubis_tensor_v_root()       client: C's Merkle root, 64 hex characters.
 * anubis_tensor_v_sample()     server: derive k (block, element) samples.
 * anubis_tensor_v_witness()    client: hex(blocks + proofs), for one sample.
 * anubis_tensor_v_verify()     server: check the witness against the root.
 *                              Returns ANUBIS_OK or ANUBIS_ERR_ARG.
 */
ANUBIS_API int anubis_tensor_v_root(const char *challenge_hex, int difficulty,
                                    char *root_hex);
ANUBIS_API int anubis_tensor_v_sample(const char *challenge_hex, int difficulty,
                                      const char *root_hex, const char *secret,
                                      int count, uint32_t *blocks,
                                      uint32_t *positions);
ANUBIS_API int anubis_tensor_v_witness(const char *challenge_hex, int difficulty,
                                       const uint32_t *blocks,
                                       const uint32_t *positions, int count,
                                       char *out_hex, size_t out_cap);
ANUBIS_API int anubis_tensor_v_check_sample(const char *witness_hex,
                                            const uint32_t *blocks,
                                            const uint32_t *positions,
                                            int count);
ANUBIS_API int anubis_tensor_v_verify(const char *challenge_hex, int difficulty,
                                      const char *root_hex,
                                      const char *witness_hex, char *err,
                                      size_t err_cap);

/* ------------------------------------------------------------------ *
 * Google TPU (PJRT C API), the `sha256` tier
 *
 * libtpu.so is dlopen()ed, so these symbols exist in every build: without the
 * plugin anubis_tpu_available() is 0 and anubis_tpu_solve() returns -1.
 *
 * anubis_solve_bits() is still the recommended entry point: it applies the
 * ANUBIS_TPU_MIN_WORK threshold and falls back to the CPU. A direct caller
 * owns both decisions. This call always re-derives the winning digest on the
 * host, so anubis_tpu_verify() does not apply to it.
 *
 * challenge       raw bytes, 1..51 (one 64-byte block with the nonce)
 * use_le          non-zero: little-endian nonce, else big-endian
 * max_nonce       inclusive nonce bound, 0 = the whole 32-bit space
 * budget_ms       wall clock for the call, compile included; <= 0 = none
 * Returns 0 on a hit, 1 when the range/budget ran out, -1 on backend failure
 * (no plugin, no device, compile or execute error).
 * ------------------------------------------------------------------ */
ANUBIS_API int anubis_tpu_available(void);
ANUBIS_API const char *anubis_tpu_info(void);   /* NULL when unavailable */
ANUBIS_API int anubis_tpu_solve(const uint8_t *challenge, uint32_t challenge_len,
                                int difficulty, int use_le, uint64_t max_nonce,
                                double budget_ms, uint32_t *out_nonce,
                                char *out_hex, double *out_ms);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ANUBIS_SOLVER_H */
