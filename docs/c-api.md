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

/* Verify one nonce (returns ANUBIS_OK when it is valid). */
int anubis_verify_nibbles(const char *challenge, uint64_t nonce,
                          int difficulty, char *out_hex);
int anubis_verify_bits(const char *challenge_hex, uint32_t nonce,
                       int difficulty, char *out_hex);
int anubis_verify_argon2id(const char *challenge_hex, uint32_t nonce,
                           int difficulty, char *out_hex);
int anubis_verify_hashx(const char *challenge_hex, uint32_t nonce,
                        int difficulty, char *out_hex);

/* Utility. */
const char *anubis_solver_version(void);
const char *anubis_gpu_info(void);            /* NULL when no GPU */
int anubis_default_threads(void);
const char *anubis_cpu_affinity_info(void);
int anubis_batch_width(void);
int anubis_sha256_hex(const char *data, size_t len, char *out_hex);
int anubis_sha256_midstate(const char *data, size_t len, uint32_t out[8]);
```

Which family to call: `nibbles` for `fast`/`slow`, `bits` for
`sha256`/`wasm-sha256`, `argon2id`, `hashx` respectively.

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
implementation and the search falls back to the CPU on a mismatch.
