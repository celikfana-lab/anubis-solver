# GPU backends

GPU use is **opt-in** and every GPU result is re-verified with the reference
implementation; on a mismatch the search silently falls back to the CPU. The
CPU is always built.

Detection order for a given algorithm: **CUDA → Level Zero → Vulkan → OpenCL →
CPU** (only the backends compiled into the library and present at runtime).

## Which flag for which algorithm

| algorithm | env var | backends tried |
|---|---|---|
| Argon2id | `ANUBIS_GPU_ARGON2=1` | CUDA, Level Zero, Vulkan |
| HashX | `ANUBIS_GPU_HASHX=1` | CUDA |
| HashX (Intel iGPU) | `ANUBIS_L0_HASHX=1` | Level Zero |
| HashX (portable) | `ANUBIS_VULKAN_HASHX=1` | Vulkan |
| SHA-256 (`sha256`/`wasm-sha256`, `fast`/`slow`) | on by default | CUDA, Level Zero, Vulkan |

The Level Zero and Vulkan HashX kernels are correct but slower than the CPU on
an Iris Xe, hence their separate flags.

## Requirements

| backend | build time | runtime |
|---|---|---|
| CUDA | `nvcc` (CUDA toolkit) | NVIDIA driver + `libcudart` |
| Level Zero | `level_zero/ze_api.h` (`libze-dev`) | `libze_loader.so.1`, Intel GPU driver + IGC |
| Vulkan | `vulkan/vulkan.h` | `libvulkan.so.1` and an ICD (`mesa-vulkan-drivers`, vendor driver) |
| OpenCL | nothing extra | `libOpenCL.so.1` and an ICD |

If the headers are missing the backend is simply not compiled; see
[troubleshooting.md](troubleshooting.md).

## Useful environment variables

| variable | effect |
|---|---|
| `ANUBIS_NO_CUDA` | disable the CUDA backend |
| `ANUBIS_NO_LEVELZERO` | disable Level Zero |
| `ANUBIS_NO_VULKAN` | disable Vulkan |
| `ANUBIS_NO_OPENCL` | disable OpenCL |
| `ANUBIS_CPU_AFFINITY` | `pcores` (default), `off`, or a mask (`0,2,4,6`) |
| `ANUBIS_CUDA_MIN_WORK` | minimum nonces before a CUDA launch is worth it |
| `ANUBIS_L0_CHUNK`, `ANUBIS_VULKAN_CHUNK` | SHA-256 nonces per dispatch |
| `ANUBIS_L0_ARGON2_LANES` | concurrent Argon2id hashes on Level Zero (default 64) |
| `ANUBIS_VULKAN_ARGON2_LANES` | concurrent Argon2id hashes on Vulkan (default 64) |
| `ANUBIS_CUDA_HASHX_CHUNK`, `ANUBIS_L0_HASHX_CHUNK`, `ANUBIS_VULKAN_HASHX_CHUNK` | HashX nonces per dispatch |
| `ANUBIS_OPENCL_CHUNK`, `ANUBIS_OPENCL_HASHX_CHUNK` | OpenCL dispatch sizes |
| `ANUBIS_GPU_NO_VERIFY=1` | skip the CPU re-check of GPU hits (benchmarking only) |

Argon2id needs ~19 MiB of device memory per concurrent hash (64 lanes ≈ 1.3 GB).

Every accepted GPU hit is re-computed once on the CPU before it is returned.
That is a single hash per hit (not per candidate): 13.7 ms for Argon2id and
0.08 ms for HashX on a T4 host, so `--no-verify-gpu` only saves time when a hit
is found inside one GPU batch (about 10% at d6–d10 on 2× T4).

## What we measured

| backend | hardware | Argon2id | HashX |
|---|---|---|---|
| CUDA | 2× Tesla T4 | ~1750 h/s | ~70–110 MH/s |
| Vulkan | Intel Iris Xe | ~230–330 h/s | error |
| Level Zero | Intel Iris Xe | ~200–290 h/s | ~2–3 MH/s |
| CPU | 1 thread | ~40 h/s | ~4 MH/s |

Full tables, per-version numbers and raw JSON live in [SPEED.md](../SPEED.md)
and `results/`.

## Raspberry Pi 5

Mesa's V3DV driver is detected but the compute kernels do not produce verified
digests there yet, so everything falls back to the CPU (Argon2id ≈ 29 h/s on
one core, ≈ 46 h/s on two). See [SPEED.md](../SPEED.md).

## OpenCL

The OpenCL backend is wired for SHA-256 and is the last GPU link in the chain:
it is used when no vendor backend answers, or when `ANUBIS_OPENCL=1` asks for
it by name. `ANUBIS_NO_OPENCL=1` turns it off. Devices that report themselves
as CPUs (pocl) are refused, because the hand-written SIMD kernels are faster.

It carries its own kernel, `src/opencl/sha256_pow.cl`, rather than reusing the
Level Zero one: the Anubis `sha256` challenge uses 32 bytes of `randomData`, so
the message is a partial block plus nonce, while the Level Zero kernel only
takes whole 64-byte blocks (its params struct is baked into a precompiled
SPIR-V blob). The OpenCL kernel takes the leftover bytes in `pre[]`/`pre_len`.

Measured on the Iris Xe (gen12lp, 96 EUs) through Intel NEO + IGC 2.16, against
the same challenge served by `betterAnusbis --algorithm sha256 --difficulty 26`
(one work-item per nonce, 64 lanes per workgroup):

| backend | difficulty 26 solve | M hashes/s |
|---|---|---|
| OpenCL (Intel NEO) | 236-296 ms | 260-268 |
| Vulkan (same GPU) | ~4 s | ~70 |
| CPU, 4 threads (the CLI default) | 3.6-9.1 s | 19.5 |
| CPU, 1 thread (`bench_gpu.py`) | | 5.0-5.6 |

`ANUBIS_OPENCL_CHUNK` sets the dispatch size (default 4 Mi work-items) and
`ANUBIS_OPENCL_MIN_WORK` the work threshold below which the CPU wins anyway.
`ANUBIS_OPENCL_DEBUG=1` prints one line per dispatch, which is the honest way
to see whether the GPU actually did the work.

`python3 tools/bench_gpu.py` prints one row per backend. Read it with care on a
machine without the vendor backends: the row labelled `level zero` there is the
OpenCL fallback, because Level Zero is not compiled in when
`level_zero/ze_api.h` is absent, and a row whose env only disables CUDA and
Vulkan still ends up at the last GPU link, which is this one.

A caveat worth knowing: this backend had never been exercised before, and the
first run of it found `clCreateBuffer` called with its size and flags arguments
swapped, so no device buffer was ever created and every search returned
"exhausted". Results are now checked for `CL_SUCCESS` and the backend reports
itself unavailable instead of pretending to have searched.

Mesa's `rusticl` needs `RUSTICL_ENABLE=iris` and is very slow to compile the
Argon2id kernel; a vendor ICD (Intel NEO, NVIDIA, AMD) is the intended target.
