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

## OpenCL note

The OpenCL host is implemented (`libOpenCL.so.1`, same kernels as Level Zero)
but not wired into the solver yet. Mesa's `rusticl` needs
`RUSTICL_ENABLE=iris` and is very slow to compile the Argon2id kernel; a vendor
ICD (Intel NEO, NVIDIA, AMD) is the intended target.
