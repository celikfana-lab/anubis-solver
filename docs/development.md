# Development

## Layout

```
anubis_solver.py        Python API + CLI (ctypes around the shared library)
include/anubis-solver.h public C/C++ header (extern "C")
examples/               Python, C and C++ samples
src/core/anubis_solver.c   C core: hashing, search loop, dispatch
src/hashx/hashx.c/.h       HashX generator, interpreter, x86-64/AArch64 JITs
src/cpu/*.s             hand-written SHA-256 kernels

vendor-specific backends are grouped by vendor:
src/nvidia/cuda/*.cu    CUDA backends (SHA-256, Argon2id, HashX, tensor)
src/nvidia/sass/        hand-measured T4 SASS listings, the kernels that produced them,
                        and the Kaggle notebooks that ran them
src/intel/levelzero/    Level Zero backends (+ *.cl kernels, *.spv.h)
src/intel/levelzero/level_zero/  vendored ze_api.h, so no libze-dev is needed
src/google/tpu/         Google TPU (PJRT C API), the sha256 tier; plugin dlopen()ed
src/intel/xe/           Intel Xe (gen12lp) SASS for the SHA-256 kernel

portable backends:
src/vulkan/*.c          Vulkan backends (GLSL kernels in *.comp)
src/opencl/             portable OpenCL host + its own sha256 kernel
third_party/argon2      Argon2id reference implementation
tools/                  generators, kernel build scripts, benchmarks
tests/                  test suite
results/                raw benchmark JSON
```

## Building

```bash
make                 # ./libanubis_solver.so
make -j8
make CUDA=0          # force-skip CUDA
make L0_INC=/path    # where level_zero/ze_api.h lives
make clean
```

Backends are auto-detected: `nvcc` for CUDA, `level_zero/ze_api.h` for Level
Zero, `vulkan/vulkan.h` for Vulkan.

## Tests

```bash
python3 tests/test_core.py          # hashing, solve+verify for every algorithm
python3 tests/test_local.py         # against a local Anubis instance
python3 tests/test_versions.py      # every known Anubis git tag
python3 tests/test_cve_2026_62314.py
make test-universal                 # one .so: exports, DT_NEEDED, inventory, API
make test-tpu                       # graceful path without libtpu; solves with it
```

## Regenerating kernels

The SPIR-V blobs are committed; regenerate them only when the kernel source
changes.

| script | input → output |
|---|---|
| `tools/build_shader.sh` | `src/vulkan/sha256_comp.comp` → Vulkan SPIR-V |
| `tools/embed_spv.py` | SPIR-V → `src/vulkan/sha256_comp.spv.h` |
| `tools/build_l0_shader.sh` | `src/intel/levelzero/sha256_pow.cl` → `src/intel/levelzero/sha256_pow.spv` |
| `tools/embed_l0_spv.py` | → `src/intel/levelzero/sha256_pow.spv.h` |
| `tools/build_l0_argon2.sh` | `src/intel/levelzero/argon2id_l0.cl` → `src/intel/levelzero/argon2id_l0.spv(.h)` |
| `tools/build_argon2_vk.sh` | `src/vulkan/argon2id.comp` → `src/vulkan/argon2id.spv` (needs `glslangValidator`) |
| `tools/gen_avx2_s.py`, `tools/gen_avx512_s.py` | generate the x86-64 assembly kernels |
| `tools/gen_meatrider_s.py` | re-emit the `sha256` tier's kernels as `src/meatrider/meatrider_{avx2,avx512,shani}.s` (`--check` fails when stale) |
| `tools/build_meatrider_vk.sh` | `src/vulkan/meatrider_comp.comp` → `src/vulkan/meatrider_comp.spv(.h)` (needs `glslangValidator`) |
| `tools/gen_meatrider_ptx.py` | the `meatrider` PTX kernel, `src/meatrider/meatrider.ptx` |

`src/opencl/opencl_kernels.h` embeds the `.cl` sources for the portable OpenCL
backend; regenerate it with `python3 tools/embed_opencl_kernels.py` after
editing one (`--check` fails instead of writing if it is stale). The SHA-256
entry comes from `src/opencl/sha256_pow.cl`, the other two from
`src/intel/levelzero/`, and the `meatrider` one from
`src/meatrider/meatrider_opencl.cl`.

## The `meatrider` kernels

The tier is SHA-256d over an 80-byte Bitcoin header, so one hash is two
compressions and every kernel in the repository's inventory needs the same three
facts: block 1 is `tail[12] || nonce_le || 0x80 || zeros || 0x280`, block 2 is
the first digest big-endian plus `0x80` and `0x100`, and the digest is compared
byte-reversed. `src/meatrider/meatrider.c` is the reference for all three;
`meatrider_block1()`, `meatrider_block2()` and `meatrider_finish()` are the whole
of "real Bitcoin" in this codebase.

Adding a kernel means adding it to the inventory in
`src/meatrider/meatrider_backend.{h,c}` and making
`tests/test_meatrider_backends.py` pass: it asks every available kernel for the
same digest and then makes each one mine. `ANUBIS_MEATRIDER_BACKEND` pins one
kernel for benchmarks.

Two of the slots are deliberately empty and say so:

- **Level Zero.** The shader is verified on this machine's Intel GPU through
  Vulkan, but `libze_intel_gpu` is not installed here, so an L0 host could not be
  run once. This repository does not ship device code it has never executed.
- **TPU.** A PJRT SHA-256 program measures 9.38 MHash/s on a TPU; `meatrider`
  needs two compressions, so it would land near 4.7 MHash/s — slower than the
  AVX2 kernel on the same laptop. It is not worth a kernel that loses.


Level Zero rejects SPIR-V newer than 1.2, hence
`llvm-spirv --spirv-max-version=1.2` in the build scripts.

## Load testing your own Anubis

`tools/stress_test.py` drives the normal client flow (challenge, solve,
`pass-challenge`, fetch) and reports requests/s, solves/s, latency and status
codes. It refuses non-private targets, requires `--i-own-this-host`, and caps
duration (300 s) and concurrency (256).

```bash
python3 tools/stress_test.py --url http://192.168.1.15:8923 \
    --duration 60 --concurrency 64 --i-own-this-host
```

A C version with no Python in the loop is also included:

```bash
cc -O2 -o stress_test tools/stress_test.c -Iinclude -L. -lanubis_solver \
   -Wl,-rpath,'$ORIGIN' -pthread
./stress_test --host 192.168.1.15 --port 8923 --duration 30 \
   --concurrency 128 --i-own-this-host
```

Measured on a 56-core server running Anubis v1.28.3 (challenge-all policy,
`fast` d4): 70 req/s from a laptop over LAN (1.3% server CPU) with the Python
client, 116 req/s locally at 256 Python workers (5.6% CPU), and 168-178
challenge+verify cycles/s with the C client (3.1% server CPU, ~1.7 cores).
Throughput plateaus because each cycle costs three HTTP round trips; the
server never gets close to saturation. The C client's authenticated fetch
returns 4xx (incomplete `Set-Cookie` capture), so its rate counts the
challenge/verify cycles, not fully authenticated pages.
Raw data: [`results/stress-anubis-2026-11-12.json`](../results/stress-anubis-2026-11-12.json).

## Benchmarks

```bash
python3 tools/bench_tiers.py          # SHA-256 tiers, many versions
python3 tools/bench_gpu.py            # CUDA / Level Zero / Vulkan vs CPU
python3 tools/bench_argon2_gpu.py     # Argon2id CPU vs GPU (ANUBIS_GPU_ARGON2=1)
python3 tools/bench_hashx_gpu.py      # HashX CPU vs GPU (ANUBIS_GPU_HASHX=1)
python3 tools/bench_isa.py            # AVX-512 / AVX2 / SHA-NI / C
```

Results are recorded under `results/` and summarised in [SPEED.md](../SPEED.md).

## Adding a backend

1. Implement `anubis_<backend>_available()`, `..._info()` and a solve function
   returning `0` on a hit, `1` on exhaustion, `-1` on failure.
2. Re-verify the hit in the core with the `anubis_verify_*` reference before
   accepting it, then fall through to the CPU search on mismatch.
3. Gate it behind an env var if it is not a clear win on typical hardware.
4. Add a benchmark script entry and a results JSON.

## Style

Ruff is configured in `pyproject.toml` (`line-length = 100`, `E`, `F`, `I`,
`UP`, `B`). C follows the kernel style of the surrounding files (4 spaces,
`ANUBIS_EXPORT` on public symbols).
