# AGENTS.md

Notes for AI coding agents working in this repository. This project was written
entirely by **DeepSeek V4.1 Flash** in DeepSeek Harness (DSH); keep that in mind
when it comes to style consistency.

## What this is

A C proof-of-work engine (`libanubis_solver.so`) plus a Python library/CLI for
solving [TecharoHQ/anubis](https://github.com/TecharoHQ/anubis) challenges:
`fast`, `slow`, `sha256` (WASM), `argon2id` (WASM) and `hashx` (WASM).

## Commands

```bash
make                      # build ./libanubis_solver.so
make -j8
make test                 # C core tests (needs argon2-cffi for the Python part)
make clean
make CUDA=0               # skip CUDA
make VULKAN=0             # skip Vulkan
make L0_INC=/path         # where level_zero/ze_api.h lives

python3 tests/test_core.py
python3 tests/test_local.py        # needs a local Anubis checkout (ANUBIS_SRC)
python3 tests/test_versions.py
python3 tools/bench_tiers.py
python3 tools/bench_gpu.py
python3 tools/bench_argon2_gpu.py  # ANUBIS_GPU_ARGON2=1 for the GPU
python3 tools/bench_hashx_gpu.py   # ANUBIS_GPU_HASHX=1 for CUDA
```

## Layout

| path | contents |
|---|---|
| `src/anubis_solver.c` | core: hashing, search loop, backend dispatch, verification |
| `src/hashx.c/.h` | HashX generator, interpreter, x86-64/AArch64 JITs (LGPL-3.0) |
| `src/*.s` | hand-written SHA-256 kernels (AVX2, SHA-NI, AVX-512, NEON) |
| `src/cuda_*.cu` | CUDA backends (SHA-256, Argon2id, HashX) |
| `src/levelzero_*.c` | Level Zero backends; kernels in `src/*.cl` |
| `src/vulkan.c` | Vulkan backends; kernels in `src/*.comp` |
| `src/opencl_backend.c` | portable OpenCL host (not wired yet) |
| `include/anubis-solver.h` | public C/C++ header — keep in sync with exports |
| `anubis_solver.py` | Python library, requests client, CLI |
| `docs/` | user and developer documentation |
| `results/` | committed benchmark JSON |

## Conventions

- **C**: 4 spaces, `ANUBIS_EXPORT` from `src/anubis_solver.c` on public symbols,
  `ANUBIS_OK`/`ANUBIS_ERR_*` return codes, no new dependencies without a license
  note in `THIRD_PARTY_NOTICES.md`.
- **Python**: 3.9+, type hints, ruff (`pyproject.toml`, line length 100).
- **ASM/GLSL/OpenCL C**: generated files are checked in; regenerate with the
  `tools/` scripts rather than editing `.spv`/`.spv.h` by hand.
- **Docs**: when a feature changes, update `README.md`, the relevant
  `docs/*.md`, and `BEGINNER.md` if the quick start changes.

## Backend rules (important)

- GPU use is **opt-in** for Argon2id/HashX (`ANUBIS_GPU_ARGON2`,
  `ANUBIS_GPU_HASHX`, `ANUBIS_L0_HASHX`, `ANUBIS_VULKAN_HASHX`) and threshold
  gated for SHA-256. The CPU is always built and always the fallback.
- Dispatch order: **CUDA → Level Zero → Vulkan → OpenCL → CPU**.
- **Every GPU hit must be re-verified** with the `anubis_verify_*` reference in
  the core before being accepted; on mismatch fall through to the CPU search.
- A new solve function returns `0` hit, `1` exhausted, `-1` backend failure.

## Generated files

| file | regenerate with |
|---|---|
| `src/sha256_comp.spv(.h)` | `tools/build_shader.sh` + `tools/embed_spv.py` |
| `src/sha256_pow.spv(.h)` | `tools/build_l0_shader.sh` + `tools/embed_l0_spv.py` |
| `src/argon2id_l0.spv(.h)` | `tools/build_l0_argon2.sh` |
| `src/argon2id.spv(.h)` | `tools/build_argon2_vk.sh` |
| `src/hashx_l0.spv(.h)`, `src/hashx.spv(.h)` | clang/llvm-spirv and `glslangValidator` (see `docs/development.md`) |
| `src/opencl_kernels.h` | re-embed the three `.cl` files |
| `src/avx2.s`, `src/avx512.s` | `tools/gen_avx2_s.py`, `tools/gen_avx512_s.py` |

## Pitfalls we hit

- Level Zero rejects SPIR-V newer than 1.2: always
  `llvm-spirv --spirv-max-version=1.2`.
- GLSL has no 64-bit ints: use `uvec2` emulation; the vector type is `uvec4`,
  and `in` is a reserved keyword.
- CUDA host APIs in `.cu` files need `extern "C"` (otherwise C++ mangling makes
  the Python `ctypes` load fail).
- The Makefile uses `-MMD -MP`; header-only changes (e.g. a new `.spv.h`) must
  trigger a rebuild. If in doubt, `make clean`.
- Mesa `rusticl` needs `RUSTICL_ENABLE=iris` and is extremely slow to compile
  the Argon2id kernel; prefer vendor ICDs (Intel NEO, NVIDIA, AMD).
- Mesa `V3DV` (Raspberry Pi 5) loads but does not produce verified results with
  these kernels — everything falls back to the CPU there.

## Safety

Authorized use only. The CVE-2026-62314 fast path is opt-in and refuses
non-loopback targets unless explicitly allowed. Do not remove those guards.
