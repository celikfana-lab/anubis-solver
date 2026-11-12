# Development

## Layout

```
anubis_solver.py        Python API + CLI (ctypes around the shared library)
include/anubis-solver.h public C/C++ header (extern "C")
examples/               Python, C and C++ samples
src/core/anubis_solver.c   C core: hashing, search loop, dispatch
src/hashx/hashx.c/.h       HashX generator, interpreter, x86-64/AArch64 JITs
src/cpu/*.s             hand-written SHA-256 kernels
src/cuda/*.cu           CUDA backends (SHA-256, Argon2id, HashX)
src/levelzero/*.c       Level Zero backends (+ *.cl kernels, *.spv.h)
src/vulkan/*.c          Vulkan backends (GLSL kernels in *.comp)
src/opencl/             portable OpenCL host (same kernels as Level Zero)
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
```

## Regenerating kernels

The SPIR-V blobs are committed; regenerate them only when the kernel source
changes.

| script | input → output |
|---|---|
| `tools/build_shader.sh` | `src/vulkan/sha256_comp.comp` → Vulkan SPIR-V |
| `tools/embed_spv.py` | SPIR-V → `src/vulkan/sha256_comp.spv.h` |
| `tools/build_l0_shader.sh` | `src/levelzero/sha256_pow.cl` → `src/levelzero/sha256_pow.spv` |
| `tools/embed_l0_spv.py` | → `src/levelzero/sha256_pow.spv.h` |
| `tools/build_l0_argon2.sh` | `src/levelzero/argon2id_l0.cl` → `src/levelzero/argon2id_l0.spv(.h)` |
| `tools/build_argon2_vk.sh` | `src/vulkan/argon2id.comp` → `src/vulkan/argon2id.spv` (needs `glslangValidator`) |
| `tools/gen_avx2_s.py`, `tools/gen_avx512_s.py` | generate the x86-64 assembly kernels |

`src/opencl/opencl_kernels.h` embeds the three `.cl` sources for the portable
OpenCL backend; regenerate it after editing a `.cl` file.

Level Zero rejects SPIR-V newer than 1.2, hence
`llvm-spirv --spirv-max-version=1.2` in the build scripts.

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
