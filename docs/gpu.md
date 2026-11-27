# GPU backends

GPU use is **opt-in** and every GPU result is re-verified with the reference
implementation; on a mismatch the search silently falls back to the CPU. The
CPU is always built.

Detection order for a given algorithm: **CUDA → Level Zero → Vulkan → OpenCL →
TPU → CPU** (only the backends compiled into the library and present at
runtime).

## One file, every machine

`make universal` compiles every backend whose toolchain/headers exist into one
`libanubis_solver.so`, and the file loads anywhere because every vendor library
is `dlopen()`ed:

- CUDA is linked with `-cudart=static` (`CUDA_RUNTIME=static`, the default), so
  `libcudart` is not a `DT_NEEDED`; with no NVIDIA driver the backend reports
  "no device" instead of the loader failing.
- Level Zero, Vulkan, OpenCL and the PJRT TPU plugin are resolved with
  `dlopen()` at first use, each cached.
- The Level Zero API header is vendored
  (`src/intel/levelzero/level_zero/ze_api.h`), so no `libze-dev` is needed to
  build the Intel path.

`make universal` prints a row per backend (`yes`, or `no` with the reason);
`make universal STRICT=1` turns a skip into an error. `make report` prints what
the `.so` on disk contains, and `python3 anubis_solver.py --backends` prints the
same table including what this machine can use right now.

| backend | build time | runtime |
|---|---|---|
| CUDA | `nvcc` (CUDA toolkit) | NVIDIA driver; cudart is embedded |
| Level Zero | vendored `ze_api.h` (or `libze-dev`) | `libze_loader.so.1`, Intel GPU driver + IGC |
| Vulkan | `vulkan/vulkan.h` | `libvulkan.so.1` and an ICD (`mesa-vulkan-drivers`, vendor driver) |
| OpenCL | `CL/cl.h` | `libOpenCL.so.1` and an ICD |
| TPU | nothing | `libtpu.so`, found via `ANUBIS_TPU_LIB` or the loader path |

If the headers are missing the backend is simply not compiled; see
[troubleshooting.md](troubleshooting.md).

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

## Useful environment variables

| variable | effect |
|---|---|
| `ANUBIS_NO_CUDA` | disable the CUDA backend |
| `ANUBIS_NO_LEVELZERO` | disable Level Zero |
| `ANUBIS_NO_VULKAN` | disable Vulkan |
| `ANUBIS_NO_OPENCL` | disable OpenCL |
| `ANUBIS_NO_TPU` | disable the TPU backend |
| `ANUBIS_TPU_LIB` | path or soname of the PJRT plugin (`libtpu.so`) |
| `ANUBIS_TPU_WINDOW` | nonces per TPU window (default 131072, max 262144) |
| `ANUBIS_TPU_MIN_WORK` | minimum expected nonces before a TPU window is worth it (default 2^28: every new challenge pays a ~1.3 s StableHLO compile, so 2^16 would buy 0.2 ms of search with it) |
| `ANUBIS_CPU_AFFINITY` | `pcores` (default), `off`, or a mask (`0,2,4,6`) |
| `ANUBIS_CUDA_MIN_WORK` | minimum nonces before a CUDA launch is worth it |
| `ANUBIS_L0_CHUNK`, `ANUBIS_VULKAN_CHUNK` | SHA-256 nonces per dispatch |
| `ANUBIS_L0_ARGON2_LANES` | concurrent Argon2id hashes on Level Zero (default 64) |
| `ANUBIS_VULKAN_ARGON2_LANES` | concurrent Argon2id hashes on Vulkan (default 64) |
| `ANUBIS_CUDA_HASHX_CHUNK`, `ANUBIS_L0_HASHX_CHUNK`, `ANUBIS_VULKAN_HASHX_CHUNK` | HashX nonces per dispatch |
| `ANUBIS_OPENCL_CHUNK`, `ANUBIS_OPENCL_HASHX_CHUNK` | OpenCL dispatch sizes |
| `ANUBIS_GPU_NO_VERIFY=1` | skip the CPU re-check of GPU hits (benchmarking only) |
| `ANUBIS_TPU_NO_VERIFY=1` | skip the CPU re-check of TPU hits (benchmarking only); also via `anubis_set_tpu_verify(0)` |

Argon2id needs ~19 MiB of device memory per concurrent hash (64 lanes ≈ 1.3 GB).

Every accepted GPU hit is re-computed once on the CPU before it is returned.
That is a single hash per hit (not per candidate): 13.7 ms for Argon2id and
0.08 ms for HashX on a T4 host, so `--no-verify-gpu` only saves time when a hit
is found inside one GPU batch (about 10% at d6–d10 on 2× T4).

The TPU has its own switch, `anubis_set_tpu_verify(0)` or
`ANUBIS_TPU_NO_VERIFY=1`, which does **not** affect the other backends; it
inherits `ANUBIS_GPU_NO_VERIFY` when neither is set. Turning it off removes
only the core's second hash: `anubis_tpu_solve()` always derives the winning
digest on the host, because the StableHLO module returns a lane flag rather
than a digest.

## What we measured

| backend | hardware | Argon2id | HashX |
|---|---|---|---|
| CUDA | 2× Tesla T4 | ~1750 h/s | ~70–110 MH/s |
| Vulkan | Intel Iris Xe | ~230–330 h/s | error |
| Level Zero | Intel Iris Xe | ~200–290 h/s | ~2–3 MH/s |
| CPU | 1 thread | ~40 h/s | ~4 MH/s |

Full tables, per-version numbers and raw JSON live in [SPEED.md](../SPEED.md)
and `results/`.

## Boost, and what the clock actually does

An iGPU clocks itself. On the Iris Xe in this laptop the floor is 100 MHz, the
idle clock 300 MHz, and the boost clock 1400 MHz; the driver raises it under
load, on its own schedule. There is **no i915 ioctl for a frequency**, so a
library cannot request one — the only lever is the sysfs floor,
`/sys/class/drm/cardN/gt_min_freq_mhz`, which is root-only on a stock system.

The library still reports and, where permitted, uses it:

```c
int anubis_gpu_freq_mhz(void);          /* current clock, 0 if no Intel GPU */
int anubis_gpu_boost(int enable);       /* 1 pins the floor at boost, 0 restores */
const char *anubis_gpu_power_state(void); /* JSON: card, clocks, writable, profile */
```

```python
s = AnubisSolver()
s.gpu_power_state()   # {'card': 'card1', 'cur_mhz': 300, 'max_mhz': 1400, ...}
s.gpu_boost(True)     # 0 when it pinned, -1 with EACCES on a stock system
s.gpu_freq_mhz()      # 1400 while hashing, 300 when idle
```

`ANUBIS_GPU_BOOST=1` runs the pin at library load. On this laptop it returns
`EACCES`: the sysfs files are `root:root 0644`. A udev rule can grant it if you
want the pin without root:

```
SUBSYSTEM=="drm", KERNEL=="card[0-9]*", RUN+="/bin/chown miku6 /sys/class/drm/%k/gt_min_freq_mhz"
```

What the clock costs, measured with `python3 tools/bench_gpu_boost.py`
(OpenCL/IGC sha256, difficulty 24, performance platform profile active):

| | MH/s | clock |
|---|---:|---|
| first solve, cold GPU | 168.5 | 300 → 1400 MHz |
| steady state (median) | 245.6 | 1100–1150 MHz |

So the ramp is 1.46x on a 40 ms solve, and the sustained clock sits below the
1400 MHz ceiling (power/thermal, even in the performance profile). If you are
benchmarking a GPU, discard the first solve — it measures the governor, not the
kernel.

The raw i915 replay (`src/i915raw/`) times one dispatch fence to fence, which
shows the same thing without a runtime in the way:

| raw dispatch, 4 Mi nonces, difficulty 24 | ms | MH/s | clock |
|---|---:|---:|---|
| first, after 2 s idle | 45.9 | 91.4 | 300 → 1400 MHz |
| second | 16.1 | 260.7 | 1400 MHz |
| steady (dispatches 8–15) | 21.8 | ~192 | 950–1000 MHz |

`./build/i915-replay --dump /tmp/i915dump --upto 8 --solve 24 --bench 16 --idle 2 --boost`
reproduces it; `--boost` reads the clock and tries the same pin (EACCES here).

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

## VPU (Intel NPU): not a backend

Core Ultra's neural accelerator also speaks Level Zero (`ZE_INIT_FLAG_VPU_ONLY`,
`ZE_DEVICE_TYPE_VPU`), but as **graph blobs** (`zeGraphCreate`) compiled by
Intel's Driver Compiler, not as modules you can hand SPIR-V to. So unlike
`levelzero_sha256.c`, there is no kernel to dispatch, and no `vpu` backend
exists. `make vpu-probe` is the first-contact check — it reports whether the
machine has a VPU at all and whether its driver would accept our SPIR-V
sha256 kernel. Details and the measurement that decided this:
[vpu.md](vpu.md).
