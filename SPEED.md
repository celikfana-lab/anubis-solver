# Speed per challenge tier and per Anubis version

How long the solver needs for each Anubis difficulty tier, and what each
release can actually ask for.

All times below are **expected time on one core** of the test machine, not
best case. A single solve is geometric: with `E[t]` being the expectation, one
run is often faster than that (median ≈ 0.69 × E[t]) and occasionally several
times slower.

## Test setup

| | |
|---|---|
| CPU | Intel i7-1260P (Alder Lake), 16 threads |
| Build | `-O3 -march=native`, AVX2 8-way + SHA-NI assembly kernels |
| Threads | 1 (pinned with `taskset -c 0`) |
| Run | `python3 tools/bench_tiers.py --reps 7`, measured 2026-11-11 |
| GPU | Intel Iris Xe (Vulkan), used where noted |
| Raw data | [`results/speed-tiers.json`](results/speed-tiers.json) |

The host runs a `powersave` governor on a laptop, so its frequency is not
stable. Rates were estimated from the total number of nonce candidates tested
across repetitions, which is far less noisy than a single solve time. A
desktop/server CPU with a fixed governor will be faster; the relative ordering
between algorithms is what matters.

## Throughput per algorithm (one core)

| algorithm | hashes/second | notes |
|---|---:|---|
| `fast`, `slow` | ~8.3 M/s | AVX2 8-way, one SHA-256 compression per 8 candidates |
| `sha256` (WASM) | ~8.0 M/s | same kernel, fixed 4-byte nonce tail |
| `hashx` (WASM) | ~3.6 M/s | interpreted HashX program |
| `argon2id` (WASM) | ~34/s | ~19 MiB and ~30 ms per hash |

## Tier tables

Anubis' documented light/medium/hard tiers (see the
[WASM challenge docs](https://anubis.techaro.lol/docs/admin/configuration/challenges/wasm)):

### `fast` / `slow` — difficulty in leading zero nibbles

| tier | difficulty | expected hashes | expected time |
|---|---:|---:|---:|
| light | 2 | 256 | 0.1 ms |
| medium | 4 | 65,536 | 9.8 ms |
| hard | 6 | 16,777,216 | 2.01 s |

### `sha256` (WASM) — difficulty in leading zero bits

| tier | difficulty | expected hashes | expected time |
|---|---:|---:|---:|
| light | 8 | 256 | 0.1 ms |
| medium | 16 | 65,536 | 8.7 ms |
| hard | 24 | 16,777,216 | 2.10 s |

### `hashx` (WASM)

| tier | difficulty | expected hashes | expected time |
|---|---:|---:|---:|
| light | 7 | 128 | 0.2 ms |
| medium | 15 | 32,768 | 15 ms |
| hard | 20 | 1,048,576 | 294 ms |

### `argon2id` (WASM)

| tier | difficulty | expected hashes | expected time |
|---|---:|---:|---:|
| light | 2 | 4 | 148 ms |
| medium | 4 | 16 | 508 ms |
| hard | 6 | 64 | 1.85 s |

`argon2id` is deliberately expensive per attempt, so its observed hashrate is
~34/s per core — and each worker thread needs ~19 MiB, so 16 threads cost
~300 MiB.

## Per-version table

The solver's speed does not depend on the Anubis version — only on the
challenge algorithm and difficulty. The version determines *which* algorithms
exist and what the built-in default difficulty is. The last column is the
expected time for that release's default `fast` difficulty (the fallback used
when a policy rule does not set one).

| version | default difficulty | algorithms available | `fast` at default |
|---|---:|---|---:|
| v1.12.1 | 5 | fast | 126 ms |
| v1.13.0 | 5 | fast | 126 ms |
| v1.14.0 | 5 | fast | 126 ms |
| v1.14.1 | 5 | fast | 126 ms |
| v1.14.2 | 5 | fast | 126 ms |
| v1.15.0 | 4 | fast | 8 ms |
| v1.15.1 | 4 | fast | 8 ms |
| v1.15.2 | 4 | fast | 8 ms |
| v1.16.0 | 4 | fast | 8 ms |
| v1.17.0 | 4 | fast | 8 ms |
| v1.17.1 | 4 | fast | 8 ms |
| v1.18.0 | 4 | fast | 8 ms |
| v1.19.0 | 4 | fast | 8 ms |
| v1.19.1 | 4 | fast | 8 ms |
| v1.20.0 | 4 | fast, slow | 8 ms |
| v1.21.0 | 4 | fast, slow | 8 ms |
| v1.21.1 | 4 | fast, slow | 8 ms |
| v1.21.2 | 4 | fast, slow | 8 ms |
| v1.21.3 | 4 | fast, slow | 8 ms |
| v1.22.0 | 4 | fast, slow | 8 ms |
| v1.23.0 | 4 | fast, slow | 8 ms |
| v1.23.1 | 4 | fast, slow | 8 ms |
| v1.24.0 | 4 | fast, slow | 8 ms |
| v1.25.0 | 4 | fast, slow | 8 ms |
| v1.26.0 | 4 | fast, slow | 8 ms |
| v1.26.1 | 4 | fast, slow | 8 ms |
| v1.26.2 | 4 | fast, slow | 8 ms |
| v1.27.0 | 4 | fast, slow | 8 ms |
| v1.28.0 | 4 | fast, slow, sha256, hashx, argon2id | 8 ms |
| v1.28.1 | 4 | fast, slow, sha256, hashx, argon2id | 8 ms |
| v1.28.2 | 4 | fast, slow, sha256, hashx, argon2id | 8 ms |

Pre-release tags follow their era; see
[`results/version-matrix-prereleases.json`](results/version-matrix-prereleases.json).

## GPU (Vulkan)

SHA-256 challenges can run on a Vulkan compute device. The GPU is only used
when the expected work is large enough to cover dispatch overhead; below the
threshold the CPU path runs. Every GPU result is re-verified on the CPU.

Measured on an Intel Iris Xe (i7-1260P), median of 3 runs:

| tier | CPU | GPU | speedup | used by default? |
|---|---:|---:|---:|---|
| `fast` difficulty 4 | 19 ms | ~20 ms | ~1× | no |
| `fast` difficulty 5 | 108 ms | 29 ms | 3.7× | yes |
| `fast` difficulty 6 | 2.27 s | 77 ms | 29× | yes |
| `sha256` 16 bits | 6.7 ms | 3.3 ms | 2× | yes |
| `sha256` 20 bits | 396 ms | 26 ms | 15× | yes |
| `sha256` 24 bits | 1.75 s | 78 ms | 22× | yes |

Default thresholds: `fast`/`slow` difficulty ≥ 5 (16⁵ = 1,048,576 expected
hashes), `sha256` ≥ 16 bits (65,536). Override with
`ANUBIS_VULKAN_MIN_WORK`, disable with `ANUBIS_NO_VULKAN=1`, or force a device
with `ANUBIS_VULKAN_DEVICE=NAME` (`ANUBIS_VULKAN_ALLOW_CPU=1` permits Mesa
lavapipe). The first call in a process pays pipeline creation; the driver's
shader cache usually makes that a few tens of milliseconds.

`argon2id` and `hashx` have no GPU implementation and always run on the CPU.


## Dual-Xeon server benchmark

2× Intel Xeon E5-2680 v4 (Broadwell-EP), 28 cores / 56 threads, 64 GB RAM,
no SHA-NI and no GPU — AVX2 only. Measured 2026-11-12:

| threads | `fast` | `sha256` | `argon2id` |
|---:|---:|---:|---:|
| 1 | 11.6 MH/s | 14.4 MH/s | 75 h/s |
| 4 | 43.1 MH/s | 53.0 MH/s | 229 h/s |
| 14 | 133.9 MH/s | 176.8 MH/s | 403 h/s |
| 28 | 214.7 MH/s | 204.9 MH/s | **411 h/s** |
| 56 | **349.6 MH/s** | **407.8 MH/s** | 266 h/s |

Argon2id is memory-bound and peaks at one thread per physical core (28);
hyperthreading makes it slower. SHA-256 keeps scaling to 56 threads.
Single Argon2id hash on one core: 13.3 ms.

Raw data: [`results/server-2026-11-12.json`](results/server-2026-11-12.json).


## Raspberry Pi 5 (Cortex-A76)

ARMv8 SHA-2 hardware path (`src/neon.s`), 4 cores at 2.4 GHz, 2 GB RAM,
measured 2026-11-12:

| threads | `fast` d6 | `sha256` bits20 | `hashx` d15 | `argon2id` |
|---:|---:|---:|---:|---:|
| 1 | 10.1 MH/s | 12.8 MH/s | 1.63 MH/s | 29.3 h/s |
| 2 | 20.3 MH/s | 25.8 MH/s | 3.25 MH/s | 46.1 h/s |
| 4 | 40.4 MH/s | 43.2 MH/s | **6.35 MH/s** | 41.2 h/s |

**GPU on the Pi 5:** Mesa's V3DV driver (V3D 7.1.10.2) is detected and the
Vulkan backend loads, but neither the SHA-256 nor the Argon2id compute kernel
produces a verifiable digest there yet (the solver falls back to CPU, which is
why the Vulkan and CPU rows match). So Argon2id on the Pi 5 is CPU-only for
now: ~29 h/s on one core, ~46 h/s on two.

The NEON/SHA-2 kernel is ~5× faster than the portable C fallback
(`fast` d6: 1.09 s vs 5.22 s). `ANUBIS_NO_NEON=1` reproduces the fallback.

The HashX JIT is ~5.3× the interpreter: 0.30 / 0.60 / 1.20 MH/s for
1 / 2 / 4 threads with `FB_HASHX_NOJIT=1`. Argon2id is memory-bound and
peaks at two threads on this board.


## ISA comparison

Measured on one Kaggle Xeon core (2.00 GHz, `avx512f/bw/cd/dq/vl`, no SHA-NI),
one thread, Vulkan disabled, 2026-11-12:

| backend | batch width | `fast` d6 | `sha256` b24 |
|---|---:|---:|---:|
| AVX-512 16-way (register schedule) | 16 | **18.49 MH/s** | **25.13 MH/s** |
| AVX-512 16-way (first version) | 16 | 17.40 MH/s | 23.42 MH/s |
| AVX2 8-way | 8 | 11.65 MH/s | 14.23 MH/s |
| SHA-NI single block | — | not present on this host | — |
| portable C | 0 | 3.01 MH/s | 3.17 MH/s |

On a client CPU with SHA-NI but no AVX-512 (Alder Lake laptop), the same
comparison gives AVX2 ≈ 9.1 MH/s, SHA-NI ≈ 8.1 MH/s, portable C ≈ 2.4 MH/s —
so the dispatch order AVX-512 → AVX2 → SHA-NI → C matches the measurements.

`tools/bench_isa.py` reproduces the table; `tools/kaggle_avx512.py` compares
AVX2 vs AVX-512 and verifies every digest against hashlib.
Raw data: [`results/avx512-kaggle.json`](results/avx512-kaggle.json).

## CUDA (NVIDIA GPUs)

Built automatically when `nvcc` is on PATH (`make CUDA=0` disables it), and
preferred over Vulkan at runtime. `fast`/`slow` and `sha256` run on the GPU;
`argon2id`/`hashx` stay on the CPU.

Measured on Kaggle with 2× Tesla T4, one CPU thread for the CPU column
(2026-11-12):

| workload | CUDA (2× T4) | CPU (1 core) | speedup |
|---|---:|---:|---:|
| `fast` d6 | 922.4 MH/s | 17.6 MH/s | 52× |
| `fast` d7 | 2286.3 MH/s | 16.4 MH/s | 140× |
| `sha256` b24 | 1719.8 MH/s | 22.7 MH/s | 76× |
| `sha256` b26 | 2985.1 MH/s | 22.8 MH/s | 131× |

Both GPUs are used: each round launches a chunk on every visible device and
the earliest hit wins; the CPU re-verifies the digest before accepting it.
`tools/bench_gpu.py` reproduces the table and verifies every digest against
hashlib. Raw data: [`results/cuda-t4.json`](results/cuda-t4.json).

## Intel GPU: oneAPI Level Zero vs Vulkan

Iris Xe (ADL GT2), one thread driving the GPU, median of 5, 2026-11-12.
Level Zero is preferred over Vulkan when both are available.

| workload | Level Zero | Vulkan | speedup |
|---|---:|---:|---:|
| `fast` d6 | 137.4 MH/s | 104.8 MH/s | 1.31× |
| `sha256` b24 | 155.8 MH/s | 92.5 MH/s | 1.68× |
| CPU (1 core, d6) | — | — | 5.9 MH/s |

Building the backend needs the Level Zero headers (`level_zero/ze_api.h`,
package `libze-dev`); the loader is `dlopen`ed, so the library still loads on
machines without an Intel GPU. At runtime it needs the Intel Level Zero
driver (`libze_intel_gpu.so.1`) and IGC for SPIR-V compilation.

`tools/bench_gpu.py` compares auto / Level Zero / Vulkan / CPU and verifies
every digest against hashlib. Raw data:
[`results/levelzero-irisxe.json`](results/levelzero-irisxe.json).

## Argon2id on CUDA (opt-in)

Two Tesla T4s, one CUDA block per hash (64 threads cooperate on the BlaMka
permutation, the 1 KiB block lives in shared memory, the 19 MiB matrix in
global memory), 128 concurrent hashes per device. Enabled with
`ANUBIS_GPU_ARGON2=1`; digests are re-verified against the reference Argon2.

Measured on Kaggle (4 vCPU host), 2026-11-12:

| difficulty | CPU (4 vCPU) | 2x T4 | speedup |
|---|---:|---:|---:|
| d6 (64 hashes) | 718 ms | 204 ms | 3.5× |
| d8 (256 hashes) | 1752 ms | 146 ms | **20.7×** |

d8 works out to ~1750 h/s on the two T4s vs ~85 h/s on the 4-vCPU host, and
is ~4× the 28-thread Xeon (411 h/s) from the earlier benchmark.

Raw data: [`results/argon2id-cuda-t4.json`](results/argon2id-cuda-t4.json).
`tools/bench_argon2_gpu.py` reproduces it.

## Argon2id on Level Zero (Intel GPUs, opt-in)

One work-group (32 work-items) per hash, 1 KiB block in local memory, 19 MiB
matrix in device memory, 64 concurrent hashes. Enabled with
`ANUBIS_GPU_ARGON2=1`; digests are re-verified on the CPU.

Iris Xe (ADL GT2), 2026-11-12, CPU column is one laptop thread:

| difficulty | CPU (1 thread) | Iris Xe (L0) | speedup |
|---|---:|---:|---:|
| d6 (64 hashes) | 1498 ms | 319 ms | 4.7× |
| d8 (256 hashes) | 3934 ms | 1310 ms | 5.1× |

That is ~200 h/s on the iGPU vs ~43 h/s for one CPU thread. Raising the
concurrency to 128 hashes made it slower (2.55 GB working set thrashes the
shared memory), so 64 is the default.

Raw data: [`results/argon2id-levelzero-irisxe.json`](results/argon2id-levelzero-irisxe.json).

## Argon2id on Vulkan (opt-in)

Same cooperative design as the Level Zero/CUDA kernels, written in GLSL with
`uvec2` emulation of the 64-bit BlaMka arithmetic (GLSL has no 64-bit ints).
H0 and the first two blocks are computed on the host; the 19 MiB matrix lives
in an SSBO. 64 concurrent hashes, `ANUBIS_GPU_ARGON2=1`.

Iris Xe (ADL GT2), 2026-11-12, CPU column is one laptop thread:

| difficulty | CPU (1 thread) | Iris Xe (Vulkan) | speedup |
|---|---:|---:|---:|
| d6 (64 hashes) | 1498 ms | 279 ms | 5.4× |
| d8 (256 hashes) | 3934 ms | 784 ms | 8.6× |

On this GPU the Vulkan path is slightly ahead of Level Zero (229/326 h/s vs
207/288 h/s), because the BLAKE2b prefix work is offloaded to the host.

Raw data: [`results/argon2id-vulkan-irisxe.json`](results/argon2id-vulkan-irisxe.json).

## HashX on CUDA (opt-in)

The generated HashX program is uploaded once; each CUDA thread expands its
512-bit register file from the SipHash key + nonce, interprets the program and
checks the leading zero bits. Every hit is re-verified on the CPU. Enabled with
`ANUBIS_GPU_HASHX=1`.

2× Tesla T4, 2026-11-12 (CPU column is one host thread):

| difficulty | CPU (1 thread) | 2× T4 | speedup |
|---|---:|---:|---:|
| d24 | 795.6 ms | 98.9 ms | 8.0× |
| d26 | 8910.6 ms | 753.3 ms | 11.8× |
| d28 | 8879.4 ms | 724.8 ms | 12.2× |

That is ~70–110 MH/s on the pair of T4s versus ~8.8 MH/s for one CPU thread
(~35 MH/s on four server cores, so still ~3× faster than a 4-thread CPU).

Raw data: [`results/hashx-cuda-t4.json`](results/hashx-cuda-t4.json).

## Notes

- **Thread scaling.** On this 20 W laptop, four pinned P-core threads are
  *slower* than two: the package hits its power/thermal limit (~89 °C) and
  clocks collapse (1 thread 0.69 s, 2 threads 0.45 s, 4 threads 2.10 s at
  `fast` difficulty 6). Two threads is the sweet spot here; on a machine with
  a stable all-core clock, time scales roughly with thread count. `argon2id`
  is the exception because of its memory cost.
- **Light tiers are overhead-bound.** At 256 expected hashes the solve is
  sub-millisecond, so request latency dominates.
- **Version defaults** are the built-in fallbacks (`-difficulty` flag /
  `DefaultDifficulty` constant). Default bot policies usually set explicit
  difficulties per rule instead; the tier tables above are the right reference
  for those.
- **CVE-2026-62314 (v1.22.0 .. < v1.26.0-pre1).** On an affected deployment the
  opt-in `use_cve=True` path skips all of this: one HTTP request, ~5 ms,
  no CPU. Enabled only for authorized testing; see the README and `SECURITY.md`.
- To reproduce on another machine:
  ```bash
  make
  taskset -c 0 python3 tools/bench_tiers.py --reps 7
  ```
