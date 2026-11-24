# C API

The shared library is `libanubis_solver.so` (built by `make`), and the public
header is [`include/anubis-solver.h`](../include/anubis-solver.h). It is valid C
and C++ (`extern "C"` guards), so:

```c
#include <anubis-solver.h>
```

```cpp
#include <anubis-solver.h>   // same header from C++
```

## Link against it

```bash
cc  demo.c   -Iinclude -L. -lanubis_solver -Wl,-rpath,'$ORIGIN' -o demo
c++ demo.cpp -Iinclude -L. -lanubis_solver -Wl,-rpath,'$ORIGIN' -o demo
```

Complete samples: [`examples/c_demo.c`](../examples/c_demo.c) and
[`examples/cpp_demo.cpp`](../examples/cpp_demo.cpp).

## Load it at runtime

```c
#include <dlfcn.h>

void *h = dlopen("./libanubis_solver.so", RTLD_NOW);
int (*solve_nibbles)(const char *, int, int, int64_t, double,
                     uint64_t *, char *, double *) =
    dlsym(h, "anubis_solve_nibbles");
```

This is what `anubis_solver.py` does, so it works without headers.

## Prototypes

The header declares all of the following; the list below mirrors it.

```c
#include <stdint.h>

/* Run a search. `threads == 0` means "pick a sensible default".
 * `budget_ms <= 0` means no time limit. `out_hex` must hold 65 bytes. */
int anubis_solve_nibbles(const char *challenge, int difficulty, int threads,
                         int64_t max_nonce, double budget_ms,
                         uint64_t *out_nonce, char *out_hex, double *out_ms);

int anubis_solve_bits(const char *challenge_hex, int difficulty, int threads,
                      double budget_ms, uint32_t *out_nonce, char *out_hex,
                      double *out_ms);

int anubis_solve_argon2id(const char *challenge_hex, int difficulty,
                          int threads, double budget_ms, uint32_t *out_nonce,
                          char *out_hex, double *out_ms);

int anubis_solve_hashx(const char *challenge_hex, int difficulty, int threads,
                       double budget_ms, uint32_t *out_nonce, char *out_hex,
                       double *out_ms);

int anubis_solve_meatrider(const char *challenge_hex, int difficulty,
                           int threads, double budget_ms, uint32_t *out_nonce,
                           char *out_hex, double *out_ms);

/* Verify one nonce (returns ANUBIS_OK when it is valid). */
int anubis_verify_nibbles(const char *challenge, uint64_t nonce,
                          int difficulty, char *out_hex);
int anubis_verify_bits(const char *challenge_hex, uint32_t nonce,
                       int difficulty, char *out_hex);
int anubis_verify_argon2id(const char *challenge_hex, uint32_t nonce,
                           int difficulty, char *out_hex);
int anubis_verify_hashx(const char *challenge_hex, uint32_t nonce,
                        int difficulty, char *out_hex);
int anubis_verify_meatrider(const char *challenge_hex, uint32_t nonce,
                            int difficulty, char *out_hex);

/* meatrider: the header behind the proof, and what the work is worth.
 * anubis_meatrider_header() needs a 161-byte buffer (160 hex chars + NUL). */
int anubis_meatrider_header(const char *challenge_hex, int difficulty,
                            uint32_t nonce, char *out_hex);
unsigned anubis_meatrider_bits(int difficulty);
double anubis_meatrider_price_usd(int difficulty, double usd_per_th_day);
double anubis_meatrider_asic_seconds(int difficulty, double hashrate);
const char *anubis_meatrider_tier(int difficulty);
int anubis_meatrider_difficulty_for_usd(double usd, double usd_per_th_day);

/* Utility. */
const char *anubis_solver_version(void);
const char *anubis_gpu_info(void);            /* NULL when no GPU */
int anubis_default_threads(void);
const char *anubis_cpu_affinity_info(void);
int anubis_batch_width(void);
int anubis_sha256_hex(const char *data, size_t len, char *out_hex);
int anubis_sha256_midstate(const char *data, size_t len, uint32_t out[8]);
void anubis_set_gpu_verify(int enable);       /* default 1 */
int anubis_gpu_verify(void);
void anubis_set_tpu_verify(int enable);       /* default 1; -1 clears */
int anubis_tpu_verify(void);                  /* call > env > gpu switch */

/* NVIDIA clock control for benchmarking. A Tesla T4 parks at 300 MHz when
 * idle and boosts only under sustained load, so short runs measure the ramp.
 * anubis_nvidia_force_boost_max() locks every visible GPU at its max SM clock
 * through NVML (dlopen'd, so a CPU-only box still loads the .so) and needs
 * root. Returns 0 when at least one device was locked, else -1 (no NVML),
 * -2 (no device), -3 (needs root), -4 (unsupported: older than R450),
 * -5 (driver refused: power/thermal). anubis_nvidia_clock_mhz() reads the
 * current clock of device 0 (-1 if unknown); anubis_nvidia_boost_info()
 * describes the last attempt. force_nvidia_boost_max() is the same call
 * without the prefix, for plain ctypes. */
int anubis_nvidia_force_boost_max(void);
int force_nvidia_boost_max(void);
int anubis_nvidia_clock_mhz(void);
const char *anubis_nvidia_boost_info(void);

/* Easter egg: the sentence the hardware answers to a BAR0 probe.
 * Static storage, never NULL, do not free. Exported under this exact
 * name (no anubis_ prefix) for the callers that scan for `easter`. */
const char *easter(void);

/* Backend inventory. One .so can carry CUDA, Level Zero, Vulkan, OpenCL, TPU
 * and the CPU at once; these say which are in it and which work here. */
#define ANUBIS_BACKEND_CPU       0x01   /* always */
#define ANUBIS_BACKEND_CUDA      0x02
#define ANUBIS_BACKEND_LEVELZERO 0x04   /* Intel Xe */
#define ANUBIS_BACKEND_VULKAN    0x08
#define ANUBIS_BACKEND_OPENCL    0x10
#define ANUBIS_BACKEND_TPU       0x20
int anubis_backends_compiled(void);       /* bitmask, no probing */
int anubis_backends_available(void);      /* bitmask, probes once and caches */
const char *anubis_backend_name(int backend);  /* "cpu", "cuda", ... or NULL */
```

`anubis_backends_available()` touches the drivers, so call it once and keep the
mask; the first call can take a second on a cold Vulkan or OpenCL stack.
`anubis_backend_name()` takes a **single** bit and returns NULL for anything
else. `anubis_gpu_info()` is the one-line description of the backend that would
be used first.

Which family to call: `nibbles` for `fast`/`slow`, `bits` for
`sha256`/`wasm-sha256`, `argon2id`, `hashx` and `meatrider` respectively, plus
`anubis_verify_tensor` and `anubis_tensor_digest` for the deterministic
`tensor` tier (one int8 GEMM; the nonce is always 0).

`meatrider` is SHA-256d over an 80-byte Bitcoin block header rebuilt from the
challenge. It takes exactly **32 bytes** of `randomData` (the header's prev-block
field is 32 bytes) and `difficulty` 1..255, because the target is a field of the
header (Bitcoin's nBits) and a 256-bit target does not fit. One consequence is
worth knowing before you cache anything: the target is hashed, so a proof is
valid only at the difficulty it was mined for, exactly as in Bitcoin.

The price helpers are labels on the work, not payments. They answer what an
Antminer S21 Pro earns doing 2^difficulty hashes at `usd_per_th_day` per
terahash-day (`<= 0` means the $0.05 default), and how long that ASIC needs.
`anubis_meatrider_tier()` names the rung: `spark`, `atom`, `suspicious`, `asic`,
`meatrider`. No money changes hands anywhere in this library.

The sampled variant is a four-call protocol in the same header:

| call | side | what it does |
|---|---|---|
| `anubis_tensor_v_root(challenge_hex, d, root_hex)` | client | computes C and its Merkle root |
| `anubis_tensor_v_sample(challenge_hex, d, root_hex, secret, k, blocks, positions)` | server | derives the k sampled blocks from the secret |
| `anubis_tensor_v_witness(challenge_hex, d, blocks, positions, k, out, cap)` | client | serializes the blocks and proofs as hex |
| `anubis_tensor_v_check_sample(witness_hex, blocks, positions, k)` | server | rejects a witness that answers a different sample |
| `anubis_tensor_v_verify(challenge_hex, d, root_hex, witness_hex, err, cap)` | server | checks the proofs and the sampled elements |

The verifier never calls the GEMM: it recomputes `C[i][j]` for the sampled
elements only. `anubis_tensor_v_verify` returns `ANUBIS_OK` or
`ANUBIS_ERR_ARG`; `err` receives a short reason. `tensor-v` uses a transposed
second matrix (`BT[j][k] = stream[N*N + j*N + k]`) so one column of B is one
contiguous row; that is the only difference from the `tensor` bytes. See the
comment block in `include/anubis-solver.h`.

Argument encoding matters:

- `anubis_solve_nibbles` takes the **raw challenge string** (any bytes).
- the `bits`, `argon2id` and `hashx` families take the challenge **hex-encoded**
  (`challenge_hex`), because the site serves it as base64/hex and the solver
  decodes it first. Passing a non-hex string returns `ANUBIS_ERR_ARG`.

## Return codes

| value | constant | meaning |
|---|---|---|
| 0 | `ANUBIS_OK` | solved / verified |
| 1 | `ANUBIS_ERR_ARG` | bad argument (bad difficulty, bad hex, …) |
| 2 | `ANUBIS_ERR_UNSOLVED` | search exhausted / budget hit |
| 3 | `ANUBIS_ERR_INTERNAL` | allocation or backend failure |

## Example

```c
#include <stdio.h>
#include <stdint.h>

int anubis_solve_nibbles(const char *challenge, int difficulty, int threads,
                         int64_t max_nonce, double budget_ms,
                         uint64_t *out_nonce, char *out_hex, double *out_ms);

int main(void) {
    uint64_t nonce = 0;
    char hex[65] = {0};
    double ms = 0.0;
    int rc = anubis_solve_nibbles("challenge-string", 4, 0, 0, 0,
                                  &nonce, hex, &ms);
    if (rc != 0) {
        fprintf(stderr, "search failed: %d\n", rc);
        return 1;
    }
    printf("nonce %llu -> %s (%.1f ms)\n", (unsigned long long)nonce, hex, ms);
    return 0;
}
```

## GPU behaviour

GPU use is opt-in through the environment (see [gpu.md](gpu.md)); the C API
takes no GPU argument. Every GPU result is re-verified with the reference
implementation and the search falls back to the CPU on a mismatch. The one
exception is the TPU, whose own switch (`anubis_set_tpu_verify`) skips a second
redundant hash; `anubis_tpu_solve()` already derived the digest on the host.

## TPU entry points

The PJRT backend exports the same trio as the other accelerators, and the
symbols exist in every build (libtpu is `dlopen()`ed):

```c
int anubis_tpu_available(void);        /* 0 without libtpu or a device */
const char *anubis_tpu_info(void);     /* "TPU: PJRT 0.118, 8 devices", or NULL */
int anubis_tpu_solve(const uint8_t *challenge, uint32_t challenge_len,
                     int difficulty, int use_le, uint64_t max_nonce,
                     double budget_ms, uint32_t *out_nonce,
                     char *out_hex, double *out_ms);
```

`0` is a hit, `1` means the nonce range or the budget ran out, `-1` is a
backend failure (no plugin, no device, compile or execute error). Outputs are
untouched unless a hit is returned.

A direct call owns the policy that `anubis_solve_bits()` would otherwise
apply: the `ANUBIS_TPU_MIN_WORK` threshold (2^28 expected nonces by default,
because a new challenge pays a ~1.3 s StableHLO compile), the CPU fallback on
`-1`, and the nonce byte order. It also ignores `anubis_tpu_verify()` — that
knob only controls the core's second reference hash, and `anubis_tpu_solve()`
always derives the winning digest on the host (the device returns a lane flag,
not a digest).

## Fetching protected pages

Since 2.0.1 the library also exports the client that the C services use, so a C
program can fetch an Anubis-protected URL without spawning anything. The
prototypes are in [`src/fetch/anubis_fetch.h`](../src/fetch/anubis_fetch.h) —
that header is not part of `anubis-solver.h` because the layer is optional
(`make FETCH=0` builds a library without it, and without the OpenSSL
dependency).

```c
#include "anubis_fetch.h"

anubis_page page;
if (anubis_fetch_get_with("https://example.com/", "chrome", &page) == 0) {
    printf("%d %s (%s)\n", page.status, page.final_url,
           anubis_fetch_transport());          /* curl-impersonate/chrome116 */
    fwrite(page.body, 1, page.body_len, stdout);
    anubis_page_free(&page);
}
```

| function | purpose |
|---|---|
| `anubis_fetch_get(url, &page)` | fetch, solving any challenge; default transport |
| `anubis_fetch_get_with(url, target, &page)` | same, with a per-call TLS profile |
| `anubis_fetch_get_dump(url, target, &dump)` | same, plus `anubis_page_dump.headers`: every response header block seen, in order |
| `anubis_page_dump_free(&dump)` | free a dump (`anubis_page_free` for the embedded page) |
| `anubis_fetch_set_impersonate(target)` | process default: `auto`, `off`, `chrome`, `chrome116`, … |
| `anubis_fetch_impersonate()` | the configured profile, `""` when off |
| `anubis_fetch_impersonate_available()` | 1 when libcurl-impersonate is installed |
| `anubis_fetch_transport()` | transport of this thread's last fetch |
| `anubis_fetch_version()` | version of the layer |

`anubis_page` is unchanged from earlier releases: it is allocated by the caller,
so a new field would write past the end of programs compiled against an older
header. Headers live in a second struct instead.

```c
anubis_page_dump dump;
if (anubis_fetch_get_dump("https://example.com/", "chrome", &dump) == 0) {
    fwrite(dump.headers, 1, dump.headers_len, stdout);  /* every response */
    anubis_page_dump_free(&dump);
}
```

`dump.headers` concatenates the raw blocks of every response the fetch went
through — the challenge, the `pass-challenge` reply, redirects and the final
page — each starting with its own status line. It is a single allocation with
CRLF line endings and a trailing NUL; `headers_len` is the length without it.

Impersonation is a runtime `dlopen()` of a libcurl-impersonate, searched for in
`$ANUBIS_IMPERSONATE_LIB`, `3rd_party/curl-impersonate/lib/`, next to the
executable, then the system loader path. Without it the built-in OpenSSL client
runs, and asking for a profile explicitly is an error instead of a silent
downgrade.
