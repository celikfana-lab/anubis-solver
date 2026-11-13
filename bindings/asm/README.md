# Assembly bindings

Macros and runnable demos for calling `libanubis_solver.so` from hand-written
assembly: x86-64 System V (`call`) and AArch64 AAPCS64 (`bl`).

```
x86_64/anubis.inc    macros + the register map, as comments
x86_64/demo.s        solve and verify a challenge, print the result
aarch64/anubis.inc   the same for AArch64
aarch64/demo.s
Makefile             builds both; runs the ARM one under qemu
```

## Build and run

```bash
cd bindings/asm
make run        # x86-64, native
make run-arm    # cross-builds an aarch64 library, then runs under qemu-aarch64
```

Both demos print the same thing:

```
libanubis_solver 1.1.0
gpu: Intel(R) Iris(R) Xe Graphics (ADL GT2) | threads 4 | batch 8
nonce 1248  hash 0004e24f5f5e1d089b2fefa534fd51b5e077fbfae1dfdce6246966f20e47149d  0.643 ms
verify: ok
```

and on AArch64, under qemu, the *same nonce and hash* — which is the point of
running both: the two bindings are checked against each other, not just against
themselves.

## Linking

Assembly has nothing to offer the linker, so a C linker driver is the least
painful route. The demo defines `main`, so:

```bash
cc -no-pie -Ix86_64 -o demo x86_64/demo.s \
   -L$REPO -lanubis_solver -Wl,-rpath,$REPO
```

`-no-pie` keeps the addressing simple (`lea sym(%rip)` still works, `@PLT` calls
still work); the rpath is what lets the binary find the library without
`LD_LIBRARY_PATH`. A freestanding `_start` build works too, but then the library's
own `pthread`/`dlopen` dependencies are yours to satisfy.

## The register map, which is where this goes wrong

### x86-64 System V

`int anubis_solve_nibbles(const char *challenge, int difficulty, int threads,
int64_t max_nonce, double budget_ms, uint64_t *out_nonce, char *out_hex,
double *out_ms)` — eight arguments, and the double splits the sequence:

| argument | goes in |
|---|---|
| challenge, difficulty, threads, max_nonce | `%rdi %rsi %rdx %rcx` |
| budget_ms (double) | `%xmm0` |
| **out_nonce** | **`%r8`** — not `%r9` |
| out_hex | `%r9` |
| out_ms | **the stack**, at `(%rsp)` before `call` |

Integer and floating arguments are assigned from separate sequences, so the double
consumes a slot in `%xmm0..7` and **none** of `%r8`/`%r9`. Pass `out_nonce` in
`%r9` and `out_hex` on the stack and it assembles fine, links fine, and writes
garbage — the single most likely first bug in an asm binding for this library.

Two more rules the macros handle for you:

- **16-byte stack alignment.** `%rsp` must be 16-byte aligned at the `call`. The
  solve macros `sub $16, %rsp` to make room for the eighth argument and `add $16`
  afterwards, which keeps the alignment if the caller was aligned.
- `%rax` is clobbered. The `%al`-counts-vector-registers rule matters for
  variadic calls *you* make (the demo sets `%eax = 1` before its `printf`).

### AArch64 AAPCS64

The same function: `x0, w1, w2, x3, d0, x4, x5, x6` — eight arguments, seven
integer slots, **nothing on the stack**. Again the double takes a `d` register
without consuming an `x` one, so `out_nonce` is `x4`, not `x5`.

One AArch64-specific comment trap: `#` is an immediate prefix there, not a
comment. A `# ...` comment inside a `.macro` body gets glued onto the previous
instruction (`fmov d0, xzr # budget_ms = 0.0` → "unexpected characters following
instruction"). Use `//`.

## Calling convention summary

| function | arguments | returns |
|---|---|---|
| `anubis_solver_version`, `anubis_gpu_info`, `anubis_cpu_affinity_info` | none | pointer in `%rax` / `x0`, NULL when absent |
| `anubis_default_threads`, `anubis_batch_width` | none | `%eax` / `w0` |
| `anubis_set_gpu_verify` | int | void |
| `anubis_solve_*` | 4 ints + 1 double + 3 pointers, see above | `%eax` / `w0` |
| `anubis_verify_*` | 4 args, no floats, nothing on the stack | `%eax` / `w0` |
| `anubis_sha256_hex`, `_midstate` | pointer, length, pointer | `%eax` / `w0` |

Status codes: `0` ok, `1` argument error, `2` unsolved / budget exhausted,
`3` internal error. Out-parameter sizes: `out_hex` must be **65 bytes**,
`out_nonce` 8 bytes for the nibbles family and 4 bytes for the bits families,
`out_ms` 8 bytes as a `double`.

## Cross-building the library for AArch64

The root `Makefile` picks its CPU kernel and its Argon2id implementation from
`uname -m`, i.e. from the **host**, so a cross build has to say so explicitly:

```bash
make -C $REPO CC=aarch64-linux-gnu-gcc BUILD=$REPO/build-arm64 \
     LIB=$REPO/build-arm64/libanubis_solver.so \
     NATIVE= ASM_SRC=src/cpu/neon.s CFLAGS="-O3 -fPIC -Wall -Wextra" \
     ARGON2_SRC="third_party/argon2/argon2.c third_party/argon2/core.c \
                 third_party/argon2/encoding.c third_party/argon2/ref.c \
                 third_party/argon2/thread.c third_party/argon2/blake2/blake2b.c" \
     CUDA=0 VULKAN=0
```

Without `ASM_SRC=src/cpu/neon.s` it tries to hand the x86 `.s` files to the
AArch64 assembler; without `ARGON2_SRC=...ref.c...` it picks argon2's SSE `opt.c`
and dies on `emmintrin.h`. `NATIVE=` removes `-march=native`, which a cross
compiler rejects. This is exactly what `make arm-lib` does.
