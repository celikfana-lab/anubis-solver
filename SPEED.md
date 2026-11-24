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
| GPU | Intel Iris Xe (Vulkan, and OpenCL through Intel NEO where noted) |
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
| `hashx` (WASM, compiled) | ~3.2 M/s | the challenge's program compiled to wasm in the page |
| `hashx` (WASM, interpreted) | ~0.46 M/s | fallback when the compile cannot run |
| `argon2id` (WASM) | ~15/s | 19,456 KiB and ~65 ms per hash |
| `sha256` (pure JS, browser fallback) | ~0.89 M/s | one nonce per hash, reused padding; ~9x slower than the wasm kernel |
| `hashx` (pure JS, browser fallback) | ~13-15 k/s | BigInt interpreter of the challenge's program; no wasm/WebGPU |
| `argon2id` (pure JS, browser fallback) | ~0.7-1.4/s | ~0.7-1.5 s/hash, 19 MiB; ~9-16x the wasm module |
| `tensor` (WASM, browser) | ~4.2-8.1 GMAC/s | int8 GEMM, SIMD dot; not a hash rate, see below |
| `tensor` (pure JS, browser fallback) | ~0.4-0.7 GMAC/s | same GEMM in JavaScript; ~10-13x slower |
| `fast`, `slow` (pure JS, browser) | ~0.36 M/s |
| `sha256` (Scratch blocks, TurboWarp) | ~1.7 k/s | the same tier written in Scratch blocks; 410,000x below the TPU kernel — see [SHA-256 in Scratch blocks](#sha-256-in-scratch-blocks-the-slow-end) |
| `meatrider` (native, one core) | ~0.91 M/s | SHA-256d over an 80-byte Bitcoin header: two compressions per hash, no SHA-NI path |
| `meatrider` (WASM) | ~1.04 M/s | the same `src/meatrider/meatrider.c`, compiled for wasm32 |
| `meatrider` (pure JS, browser fallback) | ~0.12 M/s | three JS compressions per hash — see [`meatrider`: two compressions and a price tag](#meatrider-two-compressions-and-a-price-tag) |
 a fresh padded block per candidate; the nibble challenges have no wasm module |

Correcting an earlier row here: this table used to say `hashx` was 3.6 M/s
"interpreted". It is not. The interpreter measures 0.46 M/s and the 3.2-3.6 M/s
figure is the compiled program, so the row was crediting the interpreter with
the JIT's number. The interpreter is still 1.16x the module Anubis ships
(0.456 M/s against 0.394 M/s), and the compiled path is 8.1x it.

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

The pure-JavaScript fallback (no WebAssembly, or `#pure-js`) is ~9x slower at
the same tiers; the measured table is in
[Pure JavaScript: the sha256 fallback](#pure-javascript-the-sha256-fallback).

### `hashx` (WASM)

The browser now compiles the challenge's program to wasm before hashing it, so
these are the compiled numbers with the interpreter in brackets:

| tier | difficulty | expected hashes | expected time |
|---|---:|---:|---:|
| light | 7 | 128 | 40 µs (281 µs) |
| medium | 15 | 32,768 | 10.3 ms (72 ms) |
| hard | 20 | 1,048,576 | 330 ms (2.3 s) |

The pure-JavaScript fallback is ~13-15k hashes/s, or about 24 ms / 2.44 s /
78 s at these tiers; see [HashX in pure JavaScript](#hashx-in-pure-javascript).

### `argon2id` (WASM)

| tier | difficulty | expected hashes | expected time |
|---|---:|---:|---:|
| light | 2 | 4 | 260 ms |
| medium | 4 | 16 | 1.03 s |
| hard | 6 | 64 | 4.1 s |

`argon2id` is deliberately expensive per attempt, so its observed hashrate is
~15/s per core — and each worker thread needs ~19 MiB, so 16 threads cost
~300 MiB. The pure-JavaScript fallback is ~0.7-1.5 s/hash, or 2.8 s / 11 s /
45 s at these tiers; see
[Argon2id in pure JavaScript](#argon2id-in-pure-javascript). These numbers were 30% faster than reality before the module was
rebuilt; see [the wasm section](#argon2id-in-wasm-why-it-was-2x-slower-and-what-fixed-it).

### `tensor` (WASM, WebNN, pure JS) — difficulty selects the matrix

`tensor` is not a hash tier, so its difficulty is not a bit count. It is the
matrix size: `N = 64 * clamp(difficulty, 2, 16)`, so difficulty 8 is a
512x512x512 int8 product. One challenge is one GEMM and there is no nonce to
search: the digest of the result is the answer, and the server recomputes that
same GEMM to check it.

| difficulty | N | work | wasm kernel | pure JS | C verifier (16 threads) |
|---:|---:|---:|---:|---:|---:|
| 4 | 256 | 0.034 GMAC | 7.9 ms | 82 ms | 3.7 ms |
| 8 | 512 | 0.27 GMAC | 41 ms | 408 ms | 20 ms |
| 12 | 768 | 0.91 GMAC | 112 ms | 1.46 s | 54 ms |
| 16 | 1024 | 2.15 GMAC | 281 ms | 3.44 s | 130 ms |

The wasm kernel runs 4.2-8.1 GMAC/s depending on size (it is memory-bound at
N=256 and compute-bound above 512), the JavaScript GEMM 0.4-0.7 GMAC/s, and
the C verifier is one GEMM on the server, not `2^difficulty` of them. WebNN,
when the browser has it, is a single int8 `gemm` in a graph and is the reason
the tier exists; it is not in the table because this box has no browser that
exposes `navigator.ml`, so any number for it would be invented. See
[the section below](#tensor-one-integer-gemm-and-why-webnn-is-its-real-target).

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

## PTX: hand-written kernels, no nvcc

`src/nvidia/ptx/` holds the SHA-256 kernels written directly as PTX, so
`ptxas` assembles them and nothing else is needed on the build machine. They
are not part of `libanubis_solver.so`: `ptx_loader.c` is a small driver-API
loader with a flat ABI (`anubis_ptx_solve`, and `anubis_ptx_hashx_*` for the
HashX interpreter). Every digest is re-verified by the CPU before it counts.

Measured on Kaggle with 2× Tesla T4, `ptxas` 13.0, 2026-11-17. The range is
fixed and a hit is impossible, so MH/s is nonces ÷ wall time — launch and
copy-back included, nothing extrapolated:

| workload | 1× T4 | 2× T4 | scaling |
|---|---:|---:|---:|
| PTX `sha256`, ILP=1 | 2655 MH/s | 5280 MH/s | 1.99× |
| PTX `sha256`, ILP=2 | **2687 MH/s** | 5265 MH/s | 1.96× |
| PTX `sha256`, ILP=4 | 2673 MH/s | **5291 MH/s** | 1.98× |

A later run with kernel-only timing (CUDA events around each launch, so the
results memset, the sync and the copy-back are excluded) and with the grid-stride
loop, threads per block and a register cap all varied, put the same kernel at
**2750 MH/s kernel-only** on one T4 at 1470 MHz, and showed why every knob is
flat: 21 configurations sit inside 7 % of each other, and 32 registers
(full occupancy) is 5 % *slower* than the default 42. The integer pipe is the
wall — 40 SM × 1.47 GHz × 2 warp-instr/clk × 32 lanes ÷ 1440 SASS instructions
per hash = 2.6 GH/s, and 1440 is exactly the arithmetic floor for scalar
SHA-256 (64 rounds × 15 + 48 schedule words × 10) after `ptxas` fuses Ch and Maj
into one `LOP3` each. Per clock that is 1.87 MH/s per MHz, against 2.0–2.1 for
published hashcat 1400 numbers, so compare per clock and per session, never
across them: a T4 idles at 300 MHz and boosts to 1590.

Two devices split the range and scale to ~1.96×, i.e. the PCIe copies are not on
the critical path for a range this size (1–4 M nonces per launch).

These are scan rates from a standalone kernel, like the WASM and SASS tables;
the CUDA rows above are timings of a real search through the library, with
per-chunk dispatch and verification, so the two are not directly comparable —
read the PTX column as "what this kernel does on its own". Verification ran in
the same job: `test_ptx.py` executes every kernel in `ptxsim.py` and matches
every digest against `hashlib` (mode 1 little- and big-endian, decimal nonces
of 1–10 digits, nibble and bit difficulty, both ILP lanes, and the grid-stride
loop at depths 1–8 including ranges that are not a multiple of the block width).

Raw data: [`results/ptx-t4-2026-11-17.json`](results/ptx-t4-2026-11-17.json) and
[`results/ptx-t4-ab-2026-11-18.json`](results/ptx-t4-ab-2026-11-18.json).
Reproduce with `python3 src/nvidia/ptx/kaggle_ab.py` on any CUDA machine, or
`kaggle kernels push -p src/nvidia/ptx/kaggle_hashx` for the HashX job.

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

`tools/bench_gpu.py` compares auto / Level Zero / Vulkan / OpenCL / CPU and
verifies every digest against hashlib. Raw data:
[`results/levelzero-irisxe.json`](results/levelzero-irisxe.json).

## Intel GPU: OpenCL (NEO + IGC)

The portable OpenCL backend was wired for SHA-256 in 2026-11-13 and is the
**last** GPU link in the chain (CUDA, Level Zero, Vulkan, OpenCL, CPU): it is
used when no vendor backend answers, or when `ANUBIS_OPENCL=1` asks for it by
name. On this laptop Vulkan answers, so OpenCL only takes over with that
variable set, which is also the only way to see it in the tables below.

End-to-end, through the actual protocol rather than a harness: an
Anubis-compatible gate issued the challenge, the CLI solved it, the protected
page came back, and the digest was checked against hashlib.

| difficulty 26 `sha256`, 64-byte `randomData` | solve | hashes/s |
|---|---:|---:|
| OpenCL (Intel NEO, 96 EUs) | 236 ms | 268 M |
| OpenCL, run 2 | 296 ms | 260 M |
| Vulkan, same GPU | ~4 s | ~70 M |
| CPU, 4 threads (CLI default) | 3.6 s | 19.5 M |
| CPU, 4 threads, run 2 | 9.1 s | 19.6 M |
| CPU, 1 thread (`bench_gpu.py`) | | 5.0-5.6 M |

That is 13x the CLI's four threads and roughly 47x one thread. The gap to
Vulkan is the interesting one: same silicon, 3.7x the throughput. The likely
reason is that the OpenCL kernel is a plain 32-bit 64-round loop while the GLSL
one carries `uvec2` 64-bit emulation, but that has not been isolated by
measurement, so treat it as a hypothesis and not a finding.

Steady-state dispatch cost, `ANUBIS_OPENCL_DEBUG=1` and a 4 Mi work-item chunk:

| chunk | time | rate |
|---|---:|---:|
| 4,194,304 nonces, warm | 14.3-15.5 ms | 270-293 MH/s |
| first dispatch after idle | 50-190 ms | clock ramp, not the kernel |

Per-backend rows from `python3 tools/bench_gpu.py`, 2026-11-13, MH/s:

| workload | auto | vulkan | opencl | cpu (1 thread) |
|---|---:|---:|---:|---:|
| `fast` d6 | 84.0 | 93.9 | 77.4 | 5.8 |
| `fast` d7 | 104.0 | 73.0 | 149.0 | 5.3 |
| `sha256` b24 | 49.6 | 60.0 | 141.1 | 5.0 |
| `sha256` b26 | 59.2 | 78.1 | 179.9 | 5.6 |

Short workloads understate the GPU: each of those rows pays the cold first
dispatch. Read the `level zero` row from that same run with even more care,
because Level Zero is not compiled in here (no `level_zero/ze_api.h`), so that
row ends up at the OpenCL fallback and reports 76-178 MH/s.

Two things this backend needed before it could measure anything at all: its
`clCreateBuffer` was being called with the size and flags arguments swapped, so
no device buffer existed and every search returned "exhausted" without hashing;
and it dispatched one lane per workgroup with a blocking transfer per chunk
(14 MH/s). Devices that report themselves as CPUs (pocl) are refused, since the
AVX2 kernels beat them. Raw data:
[`results/intel-xe-opencl-2026-11-13.json`](results/intel-xe-opencl-2026-11-13.json).

## Argon2id on CUDA (opt-in)

Two Tesla T4s, one CUDA block per hash (64 threads cooperate on the BlaMka
permutation, the 1 KiB block lives in shared memory, the 19 MiB matrix in
global memory), 128 concurrent hashes per device. Enabled with
`ANUBIS_GPU_ARGON2=1`; digests are re-verified against the reference Argon2.

Measured on Kaggle (4 vCPU host), 2026-11-12:

| difficulty | CPU (4 vCPU) | 2x T4 | speedup |
|---|---:|---:|---:|
| d6 (64 hashes) | 718 ms | 204 ms | 3.5× |
| d8 (256 hashes) | 3012 ms | 146 ms | **20.7×** |

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
| d8 (256 hashes) | 6737 ms | 1310 ms | 5.1× |

That is ~200 h/s on the iGPU against 38-43 h/s for one CPU thread. Raising the
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
| d8 (256 hashes) | 6737 ms | 784 ms | 8.6× |

On this GPU the Vulkan path is slightly ahead of Level Zero (229/326 h/s vs
201/196 h/s), because the BLAKE2b prefix work is offloaded to the host.

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

The same interpreter written in PTX (`src/nvidia/ptx/hashx_interp.ptx`) lands
at **115.4 MH/s** on the same pair of T4s — 3 reps over a fixed 128 Mi nonce
range at a difficulty no digest can meet, so the denominator is the work done.
One CPU thread is 9.7 MH/s, so 11.9×. That it matches the CUDA interpreter
(~108 MH/s under the library's dispatch) is the expected result: same program,
same twelve operations per instruction, and `r[]` lives in local memory either
way because the register index is data. Every digest was checked against
`hashx_hash()` at nonces 0, 1, 7, 123456 and 2^32−1, and the 12- and 16-bit
searches returned the *first* real solution with the required zeros.

Raw data: [`results/hashx-ptx-t4-2026-11-17.json`](results/hashx-ptx-t4-2026-11-17.json).

### HashX on Level Zero (Intel GPUs)

The same interpreter ported to OpenCL C. It is **correct** (it finds the same
nonces as the CPU search) but on the Iris Xe it is *slower* than the CPU,
because HashX is a branchy scalar interpreter and the iGPU has weak
per-thread scalar throughput:

| difficulty | CPU (1 thread) | Iris Xe (L0) | ratio |
|---|---:|---:|---:|
| d24 | 1402 ms | 1841 ms | 0.76× |
| d26 | 20020 ms | 40491 ms | 0.49× |
| d28 | 21259 ms | 45607 ms | 0.47× |

It is therefore gated behind `ANUBIS_L0_HASHX=1`, not enabled by
`ANUBIS_GPU_HASHX` (which turns on the CUDA path). Raw data:
[`results/hashx-levelzero-irisxe.json`](results/hashx-levelzero-irisxe.json).

### HashX on Vulkan

Same interpreter in GLSL with `uvec2` emulation of the 64-bit registers. It is
correct (same nonces as the CPU) but slower than one CPU thread on the Iris Xe:

| difficulty | CPU (1 thread) | Iris Xe (Vulkan) | ratio |
|---|---:|---:|---:|
| d24 | 1402 ms | 2355 ms | 0.60× |
| d26 | 20020 ms | 26174 ms | 0.76× |

Gated behind `ANUBIS_VULKAN_HASHX=1`. Raw data:
[`results/hashx-vulkan-irisxe.json`](results/hashx-vulkan-irisxe.json).

### HashX on a TPU (Colab, PJRT)

One Colab TPU device, one StableHLO module generated from the challenge's
program ([`src/google/tpu/hashx_pjrt.c`](src/google/tpu/hashx_pjrt.c)), 32,768
nonces per window:

| | HashX |
|---|---:|
| 1 CPU thread | 9.7 MH/s |
| 4 CPU threads | ~35 MH/s |
| **TPU, 8.4M-lane window** | **284.6 MH/s** |
| 2x T4, PTX interpreter | 115.4 MH/s |

33,554,432 hashes per measurement; the module compiles in 18-20 s and the
window is the knob: 32,768 lanes gives 74.1 MH/s, 262,144 gives 198.3, 1,048,576
gives 252.3 and 8,388,608 gives 284.6 MH/s. That is 29x one CPU thread and 2.5x
the two-T4 PTX interpreter, on a single device and a single chip.

The 64-bit registers are emulated in i32 pairs and each of the 16 program blocks
runs its body twice for the branch, so HashX lands at ~41% of the TPU `sha256`
tier's 700 MHash/s. The serialized executable (`--serialize`) is a
`xla.TpuExecutableProto` carrying a `jellyfish.TpuCompilationEnvironment`.
Raw data: [`results/hashx-tpu-colab-2026-11-21.json`](results/hashx-tpu-colab-2026-11-21.json).

```bash
./hashx_pjrt --lib libtpu.so --data HEX --difficulty 32 --window 32768 \
    --bench-hashes 2097152 --json
```

## CUDA: the `tensor` tier on a Tesla T4

One Kaggle session, 2x Tesla T4 (15,360 MiB each), CUDA 13.0, built with
`CUDA_ARCH=sm_75` so the `__dp4a` path is the one that runs. The numbers are
wall-clock per solve through `anubis_solve_tensor`, which on one call does the
GPU expand + GEMM + copy back, then the host SHA-256 of C:

| difficulty | N | work | one T4 | +CPU verify | two T4 | CPU only |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 128 | 4.2 MMAC | 0.60 ms | 1.68 ms | 0.91 ms | 1.00 ms |
| 4 | 256 | 33.6 MMAC | 1.70 ms | 5.67 ms | 1.99 ms | 3.94 ms |
| 8 | 512 | 268 MMAC | 5.88 ms | 24.0 ms | 6.06 ms | 17.4 ms |
| 12 | 768 | 906 MMAC | 15.9 ms | 62.9 ms | 16.3 ms | 47.8 ms |
| 16 | 1024 | 2.15 GMAC | 29.6 ms | 127 ms | 29.1 ms | 100 ms |

Read the middle column as a floor, not a GEMM rate: at difficulty 16 the host
SHA-256 of the 4 MiB result is ~10 ms of the 29.6 ms, the per-call `cudaMalloc`
and copy add a few more, and the GEMM itself is a fraction of what is left. The
honest summary is that on this tier a T4 buys **3-3.4x over the CPU** end to
end, against **10-13x** for the wasm kernel versus the browser's JavaScript
(see [the tensor section](#tensor-one-integer-gemm-and-why-webnn-is-its-real-target)).
A second T4 changes nothing: the work per solve is small enough that launch,
allocation and the duplicated A/B expansion are the cost, not the multiply-adds.
That is the same conclusion the per-algorithm CUDA sections reach one tier down,
just with a smaller budget to amortise it over.

Correctness came first, and the GPU re-check earned its keep: the first T4 run
produced a digest the CPU refused for **every** difficulty, because the copy
back read each device's slice from `dC[0]` instead of its row offset, so only
device 0's rows were real. The fix and a test that reads the GPU digest with
verification *off* (the old one compared through the verifying path, where a
mismatch silently falls back and agrees with itself) then ran 36/36 checks on
the T4: GPU == CPU at difficulties 2, 5, 8, 12, 16 on three challenges, plus an
independent `hashlib` reference.

Raw data: [`results/cuda-tensor-t4-2026-11-15.json`](results/cuda-tensor-t4-2026-11-15.json).
Reproduce: `kaggle kernels push -p src/nvidia/cuda/kaggle_tensor` (the harness clones
this repo, builds with `CUDA_ARCH=sm_75`, runs the tests and both benchmarks).

## TPU: the `tensor` tier through PJRT, no Python

One Colab TPU v5e-1 (single chip), libtpu 0.0.50, PJRT API 0.116, driven by
`src/google/tpu/tensor_pjrt.c`: plain C, `dlopen` the plugin, `GetPjrtApi`,
`PJRT_Plugin_Initialize`, client, buffers, execute. No Python anywhere in the
measurement path.

The tier's dot is `stablehlo.dot_general` on `tensor<NxNxi8>` pairs producing
`tensor<NxNxi32>`. That combination is legal in practice even though StableHLO's
spec (C20) says the result element type must equal the operands': the TPU
backend accepts the widening dot and runs it on the MXU. Two details cost real
time to find and are worth writing down: the plugin must be initialized *before*
`Client_Create` (otherwise libtpu aborts with `InitGoogle() has not finished
yet`), and an empty `compile_options` means zero replicas, which the TPU backend
refuses (`Requested total cores: 0`). The fix is six bytes of
`CompileOptionsProto` with `num_replicas=1, num_partitions=1`.

| difficulty | N | execute | execute rate | end-to-end | e2e rate |
|---:|---:|---:|---:|---:|---:|
| 4 | 256 | 0.173 ms | 194 GMAC/s | 1.37 ms | 24 GMAC/s |
| 8 | 512 | 0.217 ms | 1.24 TMAC/s | 4.74 ms | 57 GMAC/s |
| 12 | 768 | 0.222 ms | 4.08 TMAC/s | 10.2 ms | 89 GMAC/s |
| 16 | 1024 | 0.239 ms | 8.99 TMAC/s | 17.8 ms | 121 GMAC/s |

Every one of those digests matched the plain-C i-k-j reference exactly, so the
TPU's int32 accumulation and the copy-back layout agree with the engine.

Execute is flat at ~0.2 ms while the work grows 64x across that table, which
means the tier's sizes are launch-bound and the "execute rate" above is a
ceiling implied by the overhead, not the chip. Two bigger dots, run separately
and honestly marked unverified (the C reference at N=4096 is ~1 minute
single-threaded), show the silicon:

| N | work | execute | rate |
|---:|---:|---:|---:|
| 2048 | 17.2 GMAC | 0.421 ms | 40.8 TMAC/s |
| 4096 | 137 GMAC | 0.763 ms | **180 TMAC/s** |

180 TMAC/s is ~91% of a v5e chip's int8 spec, so the multiply-adds are not the
constraint at any size the tier uses. What is, is the return path: at N=4096
`e2e` is 294 ms of which 293 ms is copy back plus the host SHA-256 of a 64 MiB
result (`io_ms` in the JSON). That is the same shape of result the T4 produced
one order of magnitude down: the accelerated GEMM is no longer the cost, and a
tier that wants to be proof-of-compute rather than proof-of-bandwidth has to
hash on the device too.

For scale, the same dot is 8.1 GMAC/s in the browser's wasm kernel, 72 GMAC/s
end-to-end on a T4 and ~21 GMAC/s on the CPU reference, so the TPU's executed
dot is about 22,000x the wasm kernel and about 8,500x the CPU.

Raw data: [`results/tensor-tpu-2026-11-15.json`](results/tensor-tpu-2026-11-15.json).
Reproduce: `cc -O2 -I. -o tensor_pjrt tensor_pjrt.c -ldl` then
`./tensor_pjrt --lib /path/libtpu.so --difficulty 4,8,12,16 --rounds 5`.

## TPU: `tensor-v`, the GEMM is free

The same client with `--tensor-v` (`src/google/tpu/tensor_pjrt.c`) runs the
sampled tier's dot as `dot_general` with `contracting_dims = [1] x [1]`
(`C[i][j] = sum_k A[i][k]*B[j][k]`) on the MXU, copies C back, and builds the
tensor-v commitment on the host.

| difficulty | N | execute | execute rate | e2e | e2e rate | copy back |
|---:|---:|---:|---:|---:|---:|---:|
| 8 | 512 | 0.212 ms | 1.27 TMAC/s | 0.436 ms | 616 GMAC/s | 0.224 ms |
| 12 | 768 | 0.202 ms | 4.49 TMAC/s | 0.604 ms | 1.50 TMAC/s | 0.402 ms |
| 16 | 1024 | 0.188 ms | 11.5 TMAC/s | 0.821 ms | 2.62 TMAC/s | 0.634 ms |

Every root matched `anubis_tensor_v_root()` byte for byte:
`36a0a638...` at d8, `83db3c0b...` at d12, `2478762e...` at d16. Compile is
232-294 ms, once per challenge.

One caveat before quoting the e2e column: it is execute + copy-back only. The
Merkle tree runs on the host after the timed loop and is not included; the
16-thread C client's `root + tree` line above is 69 ms at d16. What the TPU
removes is the GEMM: execute is flat at ~0.2 ms and the copy-back dominates even
at N=1024. Hashing the tree on the device is the step that would make `tensor-v`
a single-device tier.

The copy-back is the term to attack. libtpu on v5e keeps a premapped host
region (`libtpu::RequiresPremappedBuffers()` is true from v4 up) and a
destination outside it is bounced through that region: one DMA plus one host
memcpy. `--dmamap` registers our own 2 MiB-aligned buffer with
`PJRT_Client_DmaMap` - a first-class PJRT C call, so no C++ objects - and the
JSON carries `"dma_mapped"` so the two runs are distinguishable. 0.63 ms for
4 MiB is 6.6 GB/s, about half of what one Gen4 x16 descriptor should manage,
which is what a staging copy looks like. Same family, zero code:
`TPU_PREMAPPED_BUFFER_SIZE`, `TPU_PREMAPPED_BUFFER_TRANSFER_THRESHOLD_BYTES`
and `--tfrt_tpu_pjrt_client_host_transfer_prefer_zero_copy_over_premap`.

Raw data: [`results/tensor-v-tpu-2026-11-21.json`](results/tensor-v-tpu-2026-11-21.json).
Reproduce: `cc -O2 -I. -o tensor_pjrt tensor_pjrt.c -ldl` then
`./tensor_pjrt --lib /path/libtpu.so --tensor-v --difficulty 8,12,16 --rounds 5 --json`.

## SHA-256 in Scratch blocks (the slow end)

The same algorithm at the other end of every scale in this document. A Scratch 3
project ([`scratch/`](scratch/)) implements the `sha256` tier in blocks: no wasm,
no JavaScript, no extension, 30 KiB of `.sb3` that opens in TurboWarp and runs.

It is a solver, not a demo — it asks for a challenge, searches the nonce space, and
reports its own rate and ETA while it works.

| runtime | hashes/second | difficulty 20 (2^20) | difficulty 21 (2^21) |
|---|---:|---:|---:|
| `scratch-vm`, the reference interpreter (Node) | 25 | 11.7 h | 23.3 h |
| TurboWarp in Chrome, compiled | **1,708** | **~10 min** | ~20.5 min |
| the same blocks compiled to WebAssembly (a separate compiler) | 2,100-2,600 | 7-8 min | ~14 min |

Measured 2026-11-23 on the same i7-1260P, one browser tab, difficulty 20 (five
leading zero nibbles, 20 bits):

```
nonce 1016595 in 595.7 s at 1708 H/s, hash 0000059c88d0ba19...
```

Expected work is 2^20 = 1,048,576 hashes, so the solve landed at 97% of the
expectation — an ordinary draw, not a lucky one.

Two things this number is good for.

**It is the honest floor for this tier.** Anubis's own wasm module runs this tier
at 1.7-1.9 M hashes/s — a thousand times more — and the TPU kernel in this
repository does 700.2 MHash/s, 410,000x more. None of the
*algorithm* changed — SHA-256 is SHA-256 — and there is no dispatch loop in the
Scratch project either, since the blocks are the program. What changed is that
Scratch has no integers and no bitwise operators, so one 32-bit `xor` becomes eight
16x16 table lookups over doubles.

**It separates interpretation from the language.** The same blocks run 68x slower
in the reference interpreter than compiled to wasm — yet compiling to wasm buys
only ~1.0-1.6x over TurboWarp's JavaScript compiler. Dispatch was never the wall.
The wall is that the program is arithmetic on doubles pretending to be integers,
and no compiler can fix that without recovering the integer semantics: an `i64`
backend would replace the tables with `xor` outright, and that is the only
remaining order of magnitude on this end.

Reproduce the project side with:

```bash
cd scratch && make test     # 20 vectors against hashlib, and the rates
cd scratch && make bench    # per-statement cost of the interpreter (~1 us)
```

The browser figure is a TurboWarp tab running `scratch/build/sha256.sb3`; the
interpreter figure is `scratch/tools/verify_sha256.py` timing the same project
through `scratch-vm`. The wasm figure comes from a compiler that is not part of
this repository, hence the range.


## `meatrider`: two compressions and a price tag

The Bitcoin-shaped tier ([README](README.md#meatrider-proof-of-work-priced-in-bitcoin))
is SHA-256, twice, over an 80-byte header. Header bytes 0..63 are fixed for a
challenge, so their midstate is compressed once and a hash costs **two**
compressions afterwards: the 16-byte block holding `time`, `nBits` and the nonce,
then the second SHA-256 over the 32-byte digest.

That shape is the standard Bitcoin miner loop, so the tier carries one kernel per
optimisation the rest of this repository already has — and because every kernel
recomputes the same header, the table below is also the test:

| backend | hashes/second | vs portable C |
|---|---:|---:|
| portable C, one core (`src/meatrider/meatrider.c`) | **2.14 M** | 1x |
| SHA-NI, one core (`meatrider_shani.s`) | **6.27 M** | 2.9x |
| AVX2, 8 nonces per pass (`meatrider_avx2.s`) | **6.91 M** | 3.2x |
| AVX-512, 16 nonces per pass (`meatrider_avx512.s`) | not run here | this CPU has AVX-512 fused off; see the Colab table below |
| WebGPU (`webgpu/meatrider.wgsl`, Iris Xe) | **43-62 M** | 20-29x |
| Vulkan (`src/vulkan/meatrider_comp.comp`, Iris Xe) | **56-80 M** | 26-37x |
| OpenCL (`src/meatrider/meatrider_opencl.cl`, Iris Xe) | **154-168 M** | 72-78x |
| wasm32, 4-lane SIMD128 (`wasm/meatrider_simd.wasm`) | **4.0-4.5 M** | 1.9x |
| wasm32, scalar (`wasm/meatrider_pow.wasm`) | **1.75-1.93 M** | — |
| pure JavaScript (browser fallback) | **0.12 M** | 0.05x |
| PTX (`src/meatrider/meatrider.ptx`) | 51 checks in the simulator | no NVIDIA device on this machine; see the Colab table below |
| Antminer S21 Pro, for scale | 234 T | 1.0e8x |

```bash
python3 tools/meatrider_backends.py            # every kernel, on the same header
node wasm/verify-meatrider-simd.mjs            # the 4-lane browser kernel, 1,993 checks
node wasm/verify-meatrider.mjs                 # the scalar browser kernel, 426 checks
deno run --allow-all tools/meatrider-webgpu.mjs  # WebGPU, 203 digest comparisons
python3 src/meatrider/test_meatrider_ptx.py    # the PTX kernel, in ptxsim
python3 src/nvidia/ptx/...                     # see "PTX: hand-written kernels, no nvcc"
```

`tools/meatrider_backends.py` is the one to run: it asks every available kernel
for the digest of the same nonces and compares against an independent Python
implementation of the header (`tools/meatrider_ref.py`), then makes each kernel
mine a real rung and re-verifies the winning nonce in C. The rates above are one
run on an i7-1260P with an Iris Xe, one thread, and are recorded in
[`results/meatrider-backends.json`](results/meatrider-backends.json); the
accelerators are measured on whole 2^22-nonce dispatches, which is why their
column moves in steps, and the same laptop gives ±10% between runs (Vulkan's
spread is wider because ANV recompiles the pipeline on some dispatches).

Four things are worth being precise about:

- **The kernel is byte-identical across the tier, the *driver* is not.** The
  SHA-256 compression in `src/cpu/avx2.s` does not care which bytes it is
  compressing, so `tools/gen_meatrider_s.py` re-emits the `sha256` tier's
  assembly under `meatrider` symbols and `meatrider_simd.c` feeds it Bitcoin
  blocks. The two copies exist so the tiers can diverge — fusing both
  compressions of a Bitcoin hash into one kernel is a `meatrider` change.
- **Batching works here, and that used to be wrong.** The `sha256` tier appends
  the nonce to the message, which is why AVX2 can hash 8 candidates at once;
  `meatrider` puts the nonce *inside* the header, and an earlier version of this
  file claimed that made batching impossible. It does not: block 1 differs only
  in its fourth word and block 2 is built from the first digest, so the batch
  path runs the compression kernel twice per lane group. 8 lanes at 3.2x rather
  than 8x because the portable C reference keeps the whole message schedule in
  registers with a rolling window while the vector kernels spill it to a stack
  frame — the win is bounded by memory traffic, not by the rounds.
- **SHA-NI is now used, and the wasm module stays portable.** `2.9x` for the
  native path; `src/meatrider/meatrider.c` remains the single implementation the
  wasm module compiles, so the browser and the server still agree bit for bit.
  The native library picks the fastest kernel per call, `ANUBIS_MEATRIDER_BACKEND`
  overrides it, and `anubis_meatrider_backend_digest()` asks one kernel directly.
- **Small rungs stay on the CPU.** A dispatch costs ~60 ms; the AVX2 kernel does
  a 2^11 rung in a millisecond and 2^20 in 150 ms. The crossover at 6.9 MHash/s
  CPU against 154 MHash/s GPU is about 2^19, so `anubis_solve_meatrider()` keeps
  anything below 2^20 on the CPU unless `ANUBIS_MEATRIDER_MIN_WORK` says
  otherwise. On this machine's Intel GPU OpenCL measures about 2.5x Vulkan for
  this tier even though the dispatch order prefers Vulkan.
- **The ladder is priced for a browser, and a GPU laughs at it.** The `atom` rung
  is 2^28 hashes: 4 minutes for the browser column, 1.6 seconds for OpenCL on an
  integrated GPU. This was always true of SHA-256d — Bitcoin ASICs have done it in
  microseconds since 2013 — but the repository now contains the GPU path, so the
  number is measured rather than assumed. A gate that wants its rung to cost what
  it says has to price the client it is aimed at; a bot with a GPU pays 1/73rd of
  the browser column.

### On a Colab T4

A free Colab T4 is the NVIDIA hardware this project has run on, and its CPU turned
out to have the AVX-512 the Kaggle box did not:

| kernel | Colab T4 box | this laptop |
|---|---:|---:|
| portable C | 1.44 M | 2.14 M |
| AVX2 ×8 | 6.94 M | 6.91 M |
| AVX-512 ×16 | **8.7-10.8 M** | not run (fused off) |
| OpenCL (on the T4) | 654.6 M | 154-168 M (Iris Xe) |
| CUDA, the `.cu` kernel | **785.8 M** | — |
| PTX, driver-JITed | **994.7-1199.5 M** | — |

`python3 tools/meatrider_backends.py` after `make CUDA_ARCH=sm_75` gives the
first five rows; `python3 src/meatrider/test_meatrider_ptx_gpu.py` gives the last.
The whole run is [`colab/meatrider-colab.ipynb`](colab/meatrider-colab.ipynb), and
the digests were checked per kernel: 60/60 for cpu, avx2 and avx512, and a real
mine whose nonce the C reference re-derived for opencl, cuda and ptx.

Two things that run only there, and their numbers:

- **AVX-512 works.** The 16-lane kernel passes all 60 digest checks. Two runs on
  shared Colab CPUs read 8.69 and 10.82 MHash/s against 6.94 and 4.62 for AVX2 —
  1.25x and 2.3x — so the box is too noisy for a single ratio, but not for the
  conclusion: the lane count does not double the rate, because one hash is two
  compressions through a stack-spilled schedule.
- **The generated PTX is the fastest thing on a T4.** Both compressions are fully
  unrolled and the whole message schedule lives in registers, where nvcc keeps a
  loop. Two measurements, both correct, on the same box: the standalone script
  (`test_meatrider_ptx_gpu.py`, 5 solves at each of d=16/20/24) reads 994.7, and
  the rate harness at d=23 reads 1199.5 in the same kind of run where the `.cu`
  kernel reads 785.8 — so the apples-to-apples figure is **1.53x**, and 994.7 is
  what the same kernel does under a different difficulty mix. The driver JITs the
  checked-in `meatrider.ptx` directly (no nvcc, no ptxas, no cubin), and
  `ANUBIS_MEATRIDER_PTX=1` makes the library's CUDA slot use it.

**The Kaggle CPU that was supposed to have AVX-512 does not**: `Intel(R) Xeon(R)
CPU @ 2.20GHz`, `flags: avx2` — no `avx512f`, and no `sha_ni` either, so that box
ran the portable C and AVX2 kernels only (`src/meatrider/kaggle_meatrider_cpu/`,
14 checks passed, 68 digests correct).

The browser column in the README ladder is at 1.0 M/s (the original scalar wasm
kernel). With the 4-lane SIMD kernel the gate now serves, those times shrink by
2.3x; the pure-JS fallback is 8x worse. The money column does not move at all —
it is `2^difficulty` hashes at the ASIC's price, whatever device does them.

## TPU: Argon2id, the chain is the wall

The `argon2id` tier is m=19456 KiB, t=2, p=1: 38,912 one-kilobyte block
computations per nonce, each one depending on the block before it. Unlike
`sha256` (independent messages) and `tensor` (a GEMM), there is no parallelism
*inside* a nonce, so
[`src/google/tpu/argon2_pjrt.c`](src/google/tpu/argon2_pjrt.c) parallelises the
only thing it can - nonces. The whole matrix is one int32 tensor
(`lanes * m * 256`, u64 as lo/hi pairs), a `stablehlo.while` walks the 38,912
steps, and every lane advances one block per iteration; `index_alpha` is i32
pairs with `mulhi32`, no divides and no unsigned compares, and pass 0's
data-independent address words are uploaded once because they depend only on
`(m, t)`.

Correctness came first, because a wrong fill also "runs fast". The device's
fill was compared with the host reference at one column round, one row round,
2 rounds, 4 rounds and the full 8+8 rounds - bit-identical at every truncation
- and the selftest passes at m=8/t=1 and m=64/t=2 (4 lanes). One real bug was
found this way and it was in the graph, not the device: the loop XORed `q` back
into a result that already contained it, so the first fill was right and every
later block was `rounds(t)` alone.

| | Argon2id, m=19456, t=2 |
|---|---:|
| 1 CPU thread, this machine | 35.3 H/s (28.3 ms/hash) |
| 2x Xeon E5-2680 v4, 28 threads | 411 H/s |
| **TPU v5e-1, 32 lanes** | **9.38 H/s** |

Measured with the executable deserialized (`--load`), so no compile is in the
loop, and with the first window discarded: 192 nonces in 6 windows, 20.5 s wall,
9.376 H/s, steady state 9.379 H/s. The per-window device time is 3411.6-3411.8
ms across all six windows - flat to 0.006%, which is what a latency-bound chain
looks like. That is 106.6 ms per nonce chain, or 87.7 us per block fill for all
32 lanes at once. Host cost is 4.1 ms of input blocks and 0.5 ms of tags per
window, 0.13% of the wall, and the 20.7 MB serialized executable compiles in
11.9 s once per `(m, t, lanes)`.

Why the 819 GB/s does not help: a block fill touches the previous block, the
reference block, the block being replaced and the write - ~4 KiB, so a window
of 32 nonces moves 4.86 GiB in 3.41 s, **1.42 GiB/s, or 0.19% of HBM**. To
saturate the HBM at this chain length you would need ~17,000 lanes, which is
330 GiB of matrix - 21x the chip's memory. The body is also only ~20k i32 ops
per fill; 87.7 us is ~140k cycles at 1.6 GHz, about 7 cycles per vector op,
i.e. the dependency chain, not issue rate or bandwidth.

So `argon2id` stays on the CPU. The honest summary is that the TPU is 3.8x
slower than **one** CPU core here and ~44x slower than the 28-thread Xeon,
and that this is the tier where the device's advantages (bandwidth, MXUs) are
structurally irrelevant. The obvious follow-up is a lane sweep: 32 lanes cost
637 MB of the 16 GB HBM and the per-window time was already sub-linear at 1 vs
4 lanes (166 vs 112 ms at m=64/t=2), so 128-256 lanes may still be free in time
- 128 lanes would be ~37 H/s, 256 lanes ~75 H/s, both below the CPU tier.

Raw data: [`results/argon2id-tpu-2026-11-21.json`](results/argon2id-tpu-2026-11-21.json).
Reproduce: `cc -O2 -I. -o argon2_pjrt argon2_pjrt.c -ldl` in
`src/google/tpu`, then
`./argon2_pjrt --lib $LIBTPU --run-matrix --selftest` for correctness and
`./argon2_pjrt --lib $LIBTPU --lanes 32 --difficulty 32 --stress 20 --json`
for the rate (add `--serialize F` once, `--load F` afterwards).

### No boost button, but there is a flag table

Before believing that a hidden switch could rescue this tier, the library was
read instead of guessed at. `libtpu.so` (451,904,656 bytes) carries 751,967
defined symbols, but only 83 dynamic exports - `GetPjrtApi`,
`GetLibtpuSdkApi`, `TpuTopology_*`, `TpuProfiler_*`, `TpuEmbeddingEngine_*`,
`TpuStatus_*`, the TF kernels. Nothing resembling "execute faster".

What it does carry is a flag table: 2,797 `FLAGS_*` variables, of which 1,079
are `xla_tpu_*` and 142 are `xla_jf_*`. The ones that could matter for one long
dependent chain are `xla_jf_critical_path_scheduler`, `xla_jf_vliw_scheduler`,
`xla_optimization_level` ("Numerical optimization level for the XLA compiler
backend"), and the code emitters `xla_llvm_isa_emitter{,_force,_bundles}`;
`xla_jf_naive_bundle_packer` only changes compile time. The channel is
`LIBTPU_INIT_ARGS` (a string in the image); `XLA_FLAGS` does not reach these -
the `xla_jf_*` ones are rejected there. That is the closest thing to a boost
button in this library. It was measured on a Colab v5e1 at a 4,194,304-lane
window, three interleaved rounds per set, same binary, only `LIBTPU_INIT_ARGS`
changing:

| flag set | median | min-max | vs baseline |
|---|---:|---:|---:|
| baseline | 662.8 MHash/s | 640.0-664.4 | - |
| `xla_jf_critical_path_scheduler=true` | 665.7 | 620.7-670.4 | +0.4% |
| `xla_jf_vliw_scheduler=true` | 669.8 | 649.9-670.5 | +1.1% |
| `xla_llvm_isa_emitter=true --xla_llvm_isa_emitter_force=true` | 657.9 | 622.4-668.4 | -0.7% |
| `xla_optimization_level=EFFORT_O1/O2/O3` | 663.1 / 631.4 / 654.4 | one run each | within noise |

Run-to-run spread on this VM is ~3-4% and the baseline drifted 630-669 across
sessions, so every one of those is noise. There is nothing for a scheduler flag
to win here: the module is elementwise vector ops and the pipeline already runs
at 98.7% of its asymptote (1.41 ns per lane). Separately,
`xla_optimization_level` takes the enum `EFFORT_O0..O3`, not an integer - `=3`
is rejected with a list of the legal values, which is how that row was found.

The scripts remain for other workloads:
[`src/google/tpu/colab_argon2_flags.sh`](src/google/tpu/colab_argon2_flags.sh)
runs the serialized Argon2id executable under each flag, and
[`src/google/tpu/colab_tpu_flags_all.sh`](src/google/tpu/colab_tpu_flags_all.sh)
does all five tiers at once, with argon2id recompiled per set so a codegen flag
is not silently ignored by `--load`.

There is no clock, voltage or power-limit flag: 17 of the 2,797 names match
clock/freq/throttle/power at all, and they point the other way -
`tpu_throttle_when_idle`, `tpu_throttle_idle_timer_duration`,
`tpu_throttle_when_continuation_queue_empty`. The power manager limits itself
for thermal and droop reasons and only reports it as counters
(`PWRMGR_*_THROTTLE_CORE_DEBUG_STATS_CLOCKS_SKIPPED`,
`THERMAL_THROTTLE_CLOCKS_SKIPPED`, `LDIDT_BRAKE_EVENTS`); nothing in the image
lets software raise that limit.

The "no XLA" door exists too, just not in `.dynsym`:
`tpu::EncodeProgram<pufferfish::isa::EncoderPfBarnaCoreSequencer, ...>` turns an
ISA program proto into a `TpuTypedHostDmaBuffer<unsigned char, 32>`, and
`deepsea::executor::DeepseaExecutor::LoadProgram` / `RunProgram` execute it. Using
those means calling internal C++ by base+offset and redoing it for every libtpu
release, in order to skip an 11.9 s compile that `--serialize`/`--load` already
skips. Not worth it, and it cannot move a chain that costs ~7 cycles per vector
op because of dependency latency rather than issue rate.

### Adding chips is free, lanes are not

A slice with eight addressable devices (v3-8, v5e-8) needs no sharding for this
tier: lanes are independent nonces, so one process per device is eight
independent problems. `--device-index K` selects the device and
[`src/google/tpu/colab_argon2_multidev.sh`](src/google/tpu/colab_argon2_multidev.sh)
starts one process per chip, sums the per-device steady rate and prints the
per-chip chain time. One chip measures 9.376-9.381 H/s with flat windows, so
eight chips should read ~75 H/s - still below the 28-thread Xeon's 411 H/s, and
the only way this tier wins is many lanes per chip, which is exactly the axis
the chain punishes. That sweep is the open question, not this one.

## TPU: the `sha256` tier, 700 MHash/s

The same PJRT client (`src/google/tpu/sha256_pjrt.c`) also runs the `sha256`
tier, and this is the one it is genuinely good at. A `sha256` challenge is many
independent 64-byte messages - one per nonce - so there is no chaining: iota
gives each lane its nonce, four byte-splices patch it into the 16 message words,
64 rounds of add/xor/rotate run over `tensor<Nxi32>`, and the device answers one
question per lane: is `H0 >> (32-difficulty)` zero? The host gets one byte per
lane, and re-derives the digest of the winning nonce on the CPU.

Window size is the whole tuning story, because the fixed cost per execute is a
launch plus a copy:

| window (lanes/execute) | rate | per window |
|---:|---:|---:|
| 8,192 | 18.0 MHash/s | 0.455 ms |
| 262,144 | 375.9 MHash/s | 0.70 ms |
| 524,288 | 476.9 MHash/s | 1.10 ms |
| 1,048,576 | 560.5 MHash/s | 1.87 ms |
| 2,097,152 | 633.1 MHash/s | 3.31 ms |
| 4,194,304 | 668.5 MHash/s | 6.27 ms |
| 16,777,216 | **700.2 MHash/s** | 23.96 ms |

The 343 MHash/s this section used to report was not the device: the client
refused `--window` above 262,144 lanes, and the curve was still climbing when
that assertion tripped. Raising our own cap to 16.7M lanes doubles the rate,
and the per-window time stays honest - 16.7M lanes is 16.7M hashes per execute
in 24 ms. A verified run at 4.19M lanes and difficulty 24 found nonce 29258703
(`000000cc4fb432e4...`), so the wider window is not a faster wrong answer.

Every row was verified: the program prints the winning nonce's digest and the
CPU recomputes it, and the same nonce (`740876`, digest `00000328…`) came out at
every window size because the scan order is deterministic. The knee is not
reached at 262k - the rate kept climbing to 16.7M, where it flattens at 700 M/s
is a floor for this configuration, not a ceiling.

For scale: the browser's four-wide wasm kernel is ~8 MHash/s and the engine's
AVX2 path ~8.3 MHash/s per core, so a single v5e chip is **~84x** either of
them. Compile is ~1.5 s once per challenge, the same trade the page makes when it
compiles a HashX program.

**What that means for the tier.** At 700 MHash/s, difficulty 24 (16.7M expected
hashes) is ~0.05 s on one chip, and difficulty 32 is ~12.5 s. `sha256` is
therefore a speed bump, not a wall, against anyone with TPU time - and unlike
the memory-hard tiers, the work is embarrassingly parallel on exactly the
hardware clouds sell cheaply. This is the argument for raising `sha256`'s
default difficulty on exposed sites, or steering high-value deployments to
`argon2id` (19,456 KiB per hash, so the same axis does not apply) or `hashx`
(program generation per challenge, which a batch compressor does not amortise).
It is also a reason to treat "the browser takes 2 s" as a statement about honest
browsers, not about attackers.

Limits, stated plainly: the device-side test looks at `H0` only, so difficulty
is capped at 32 bits; the client handles single-block messages (decoded
challenge up to 51 bytes, which is what Anubis issues); and the compile is per
challenge, so a solver that meets a fresh challenge every request pays 1.5 s
before it can start hashing.

Raw data: [`results/sha256-tpu-2026-11-15.json`](results/sha256-tpu-2026-11-15.json).
Reproduce: `make sha256_pjrt` then
`./sha256_pjrt --lib /path/libtpu.so --bench-hashes 4000000 --window 262144 --json`.

## Cost of GPU hit verification

Every accepted GPU hit is re-computed once on the CPU. On 2× T4 that is
13.7 ms for Argon2id and 0.08 ms for HashX, so `--no-verify-gpu`
(`ANUBIS_GPU_NO_VERIFY=1`) removes exactly one hash per hit:

| workload | verify | no-verify | saved |
|---|---:|---:|---:|
| Argon2id d6 | 128.2 ms | 114.7 ms | 10.5% |
| Argon2id d8 | 128.7 ms | 115.5 ms | 10.3% |
| HashX d24 | 71.3 ms | 71.8 ms | ~0% |

The saving shrinks as difficulty grows beyond one GPU batch. Digests remain
correct with verification off (checked against argon2-cffi); it is a
benchmarking switch, not a production default. Raw data:
[`results/gpu-verify-t4.json`](results/gpu-verify-t4.json).

## Hardware (the Verilog reference in `beyond/`)

`beyond/` solves both challenge families in simulation — see
[`beyond/README.md`](beyond/README.md). Everything here is **cycle-accurate
simulation, not silicon**, so read it as architecture: the cycle counts are
measured, the clock is assumed. No static timing analysis has been run, so
"1 GHz" is a plausible target rather than a verified one.

### Test setup

| | |
|---|---|
| RTL | `beyond/rtl/` — SHA-256 PoW, full Argon2id, full HashX, eight-stack HBM3e, and the 365-engine card top in `rtl/top/` |
| Simulator | Icarus Verilog 12.0 (function), Verilator 5.020 (single-hash speed) |
| Machine | 56-core Xeon, Ubuntu 24.04 |
| Run | `make -C beyond remote-sim`, `make -C beyond remote-mpipe`, 2026-11-12 |
| Raw data | [`results/chip-throughput-2026-11-12.json`](results/chip-throughput-2026-11-12.json), [`results/chip-fill-writeback-2026-11-12.json`](results/chip-fill-writeback-2026-11-12.json), [`results/hbm3e-x8-2026-11-12.json`](results/hbm3e-x8-2026-11-12.json) |

### One engine

| algorithm | cycles per hash | hashes/s @ 200 MHz | @ 1 GHz |
|---|---:|---:|---:|
| `fast` / `slow` / `sha256` (2-block message) | 128 | 1.56 M | 7.8 M |
| `hashx` (512-instruction program) | 533 | 375 k | 1.88 M |
| `argon2id` (m=19456, t=2) | 5,165,657 | 38.7 | 193.6 |

The SHA-256 and HashX cores are small enough to replicate: 100 HashX engines
at 1 GHz would be ~188 M hashes/s, which is 1.7× the measured 2× T4 pair
without any memory pressure. Argon2id is the opposite — 5.2 million cycles and
139 MB of traffic per hash, so one engine is nearly irrelevant.

### Making a block cheaper: the one-cycle write-back

A block used to cost 260 cycles: 128 for the permutation, then 128 more to
walk the 128 output words out one per cycle. All 128 words are final at the
same instant, so they are now written in a single cycle.

| | before | after |
|---|---:|---:|
| cycles per block | 260.2 | **132.8** |
| cycles per hash (m=19456, t=2) | 10,126,531 | **5,165,657** |
| hashes/s per engine @ 1 GHz | 98.8 | **193.6** |
| yosys generic cells | 261,685 | **186,594** |

The area fell too, which is the part that surprised me: indexing
`out[64*f +: 64]` with the register `f` made yosys build a 128-way 8,192-bit
mux, while a constant index leaves an XOR tree per word. 1.96× the work in
72% of the cells. Measured with `make vlreal` at the real m=19456, which also
solved a challenge on the way — nonce 25, 5 leading zero bits. Raw data:
[`results/chip-fill-writeback-2026-11-12.json`](results/chip-fill-writeback-2026-11-12.json).

None of this moves the memory ceiling, so on one HBM3 stack the win is that the
link saturates at ~30 engines instead of 59: half the die for the same
5,870 hashes/s.

### Scaling Argon2id: engines vs HBM3

The question for Argon2id is never the datapath, it is whether memory keeps
the engines fed. `beyond/rtl/argon2/argon2_mpipe.v` carries N engines with K
hashes each against `beyond/rtl/mem/hbm3_model.v` (819 B/cycle, 350-cycle
latency, byte-credit admission). `fill_block` is a 133-cycle counter there, so
this measures arbitration, occupancy and latency hiding.

A block costs `max(133, 350 / K)` engine cycles, because each hash in flight has
exactly one outstanding request. Two contexts per engine therefore floor at 175
cycles and three reach the datapath's 133:

| engines | contexts | link | hashes/s @ 1 GHz | cycles/engine/block |
|---:|---:|---:|---:|---:|
| 40 | 2 | 809.5 / 819 GB/s | 5,813 | 176.8 |
| 59 | 2 | 819 / 819 GB/s | 5,888 | 257.5 |

40 engines is where one stack runs out: 819 B/cycle is 0.229 blocks/cycle at
3,584 B per block, times 175 cycles per block. 59 buys nothing more, it just
sits idle — the write-back did not raise this ceiling, it lowered the engine
count that reaches it.

One caveat moves the ceiling more than any other. A random 1 KiB Argon2 block
costs a DRAM row activate, so the link does not achieve its headline bandwidth:

| link efficiency | effective link | ceiling @ 1 GHz |
|---:|---:|---:|
| 100% (ideal) | 819 GB/s | 5,888 |
| 75% (realistic) | 614 GB/s | 4,406 |
| 50% (pessimistic) | 409 GB/s | 2,935 |

So the honest range for a 1 GHz, single-HBM3 design is **4.4–5.9 k Argon2id
hashes/s**, and it is the memory that decides it, not the engines.

### Eight HBM3e stacks

HBM3e is 9.6 Gb/s/pin on a 1024-bit bus: 1,228.8 GB/s per stack, so eight of
them are 9.82 TB/s. `beyond/rtl/mem/hbm3e_mem.v` is that subsystem — eight
instances of the same per-stack link model (byte-credit admission and the
350-cycle pipeline, unchanged) behind a router that sends
`stack = block % 8`. Only the *selected* stack can backpressure a request; a
shared ready would serialise eight independent links behind the slowest one.

| | measured |
|---|---|
| per stack | 1,228.0 B/cycle ×8 |
| aggregate | **9,824 B/cycle = 9.82 TB/s** at 1 GHz |
| balance | 12.50% per stack |
| integrity | 0 responses reordered, 0 lost, 0 overflow |

**The wall is the request port, not the DRAM.** One request per cycle at
Argon2's 3,584-byte average block is 3,584 B/cycle, so a single-port design
uses 36% of the memory it paid for. Measured, with everything else wide open:

| request lanes | offered | used | hashes/s @ 1 GHz |
|---:|---:|---:|---:|
| 1 | 3,584 B/cycle | 3,575 (36%) | 25,699 |
| **3** | 10,752 B/cycle | **9,801 (99.8%)** | **70,426** |

Three lanes are enough because 9,824 / 3,584 = 2.74 requests per cycle fill the
memory. Lanes are per-engine (`lane = engine % 3`), each with its own rotating
arbiter, and responses stay id-tagged through a compaction network: at most one
response per stack per cycle, so three lanes can never lose one and the design
needs no queue at all.

And contexts, not engines, are what hide the latency — `max(133, 350/K)`:

| contexts | cycles/engine/block | engines to fill 9.82 TB/s |
|---:|---:|---:|
| 1 | 387 | ~1,060 |
| 2 | 176.5 | 484 |
| **3** | **133** (the datapath) | **365** |

The last third of the engine count is bought with DRAM (19 MiB of extra hash in
flight) rather than silicon, which is the cheapest trade in this document.

**365 engines is the most this memory can feed.** Measured sweep, eight HBM3e
stacks, 3 request lanes, 1 GHz, 10,000-cycle window:

| engines | contexts | cycles/engine/block | memory used | hashes/s @ 1 GHz |
|---:|---:|---:|---:|---:|
| 177 | 2, one lane | 177.0 | 3,575 / 9,824 (36%) | 25,699 |
| 240 | 3 | 135.6 | 6,378 / 9,824 (65%) | 45,500 |
| **365** | **3** | **133.2** | **9,801 / 9,824 (99.8%)** | **70,426** |
| 550 | 3 | 200.4 | 9,799 / 9,824 (99.8%) | 70,518 |

Past 365 the extra engines have nothing to do: 550 of them — 50% more
silicon — add **0.13%**. The engines are no longer the limit at that point; at
133.2 cycles per block each engine is running at exactly the datapath's own
cost, and the link is at 99.8%.

Capacity is not a consideration at this scale: 365 engines x 3 contexts is
1,095 hashes in flight, 20.8 GiB of a 128 GiB memory. All 6,894 hashes that
would fit could be resident at once — the memory is bought for bandwidth, and
bandwidth is what runs out.

With a realistic DRAM derate the same design gives:

| link efficiency | memory used | hashes/s @ 1 GHz |
|---:|---:|---:|
| 100% (ideal) | 9,801 B/cycle | **70,426** |
| 75% (realistic) | 6,454 B/cycle | **46,582** |

So the honest range for a 1 GHz, 365-engine, eight-HBM3e design is
**46.6–70.4 k hashes/s** — 8–12× the single-HBM3 design and 26–40× the measured
2x T4 pair.

### The card: 365 engines

`beyond/rtl/top/anubis_argon2_card.v` is that design point as a single Verilog
top: the 365-engine array, the three request lanes, the eight HBM3e stacks, the
PCIe BAR0 register block and the UART console, wired together.
`make -C beyond card-argon2-max` builds it and drives it through BAR0 the way a
host would.

```
card: NENG=365 x KCTX=3 = 1095 hashes in flight, 8 HBM3e stacks, 3 lanes
  BAR0 ID=a0b15c01, busy=1 done=0, console started
  400 cycles: 773 blocks, 1094 requests (2.735/cycle), 9779.2 B/cycle of 9824
  throughput: 70122 hashes/s at 1 GHz, collisions=642 overflow=0
```

| | |
|---|---|
| engines | 365 x 3 contexts = 1,095 hashes in flight |
| memory | 8 x 1,228 B/cycle = **9.82 TB/s** |
| measured | **9,779 B/cycle (99.5%), 2.735 requests/cycle** |
| throughput | **70,122 hashes/s at 1 GHz**; 46,582 at a 75% DRAM derate |
| block cost | 133 cycles — the measured cost of `argon2_fill` |
| datapath area | 365 x 186,594 = **68.1 M generic yosys cells**, 6.0 M flops of block registers |
| die estimate | 12–25 mm² of logic at 12 nm, before the eight HBM PHYs |

One caveat, stated plainly: the engine array in that top is `argon2_mpipe`,
which charges each block the measured 133 cycles rather than instantiating 365
copies of `argon2_fill` — 68 M cells, which no simulator here will take. The
wiring and the cycle budget are therefore proven at 365 engines, while the
arithmetic is proven separately: per block against the reference, per hash
against argon2-cffi, and once end to end by `make vlreal` solving a real
challenge.

### One die, three machines

The three Anubis families want three different machines, so
`beyond/rtl/top/anubis_tri_chip.v` puts the right machine next to each other
instead of forcing one datapath to be three things. Only the host interface and
the board are shared.

| sub-chip | machine | why that shape | rate @ 1 GHz | cells |
|---|---|---|---:|---:|
| **A2I** | 365 engines x 3 contexts + 8 HBM3e stacks | the permutation is 133 cycles and the HBM link is the wall | **70,122 h/s** | 68.1 M |
| **HX** | `hashx_pool`, 128 lanes of `hashx_top` | a 533-cycle *serial* VM: latency-bound, so throughput is lanes | **240 M h/s** | 7.5 M+ |
| **SHA** | `sha256_pool`, 128 x `anubis_pow` | 128 cycles and ~8.5k cells: pure ALU, so throughput is lanes | **1.0 Ghash/s** | 1.1 M |

Roughly **77 M generic cells** (the HX figure counts only `hashx_exec` per lane, so it is a floor), and the Argon2 array is 88% of it — which is the
whole point: the two cheap algorithms cost almost nothing next to the memory
machine, so there is no reason to compromise any of the three.

Measured per lane (these are the numbers the pool sizes multiply):
1.88 M h/s for one HashX lane, 7.81 M h/s for one SHA-256 lane, and the Argon2id
array is the measured 70,122 h/s at 365 engines.

**Why not one universal core.** SHA-256's round is a wide combinational network:
on a general register ALU it is ~12 micro-operations, i.e. **6x slower** than the
hardwired 128-cycle core. HashX genuinely is a sequence of register ops, so it
runs natively on an ALU. Argon2id is a 128 x 64-bit permutation gated by DRAM.
Unifying the datapath would slow SHA-256 down to save at most 67 k cells against
a 68.1 M-cell array — a bad trade by three orders of magnitude.

**Where sharing *is* right:** the HashX program. It is up to 512 instructions
(8 KiB) and fixed for every nonce of a challenge, so all 128 HX lanes read one
copy. That is the only genuinely shareable resource in the design.

**And the honest note on the SHA-256 block:** replication is not the area-optimal
form of it. A fully unrolled, 64-stage pipelined SHA-256 reaches 1 hash/cycle for
~100 k cells, where 128 replicated scanners cost ~1.1 M for the same 1 Ghash/s.
PoW has no latency requirement, so the pipeline is the right answer — it just
isn't written yet, and the pooled version is built from a core that is already
verified against known vectors.

`make -C beyond tri-chip` runs all three on one die and checks each against its
reference: HashX must find nonce 228 (9 leading zero bits, the C reference's
first hit), SHA-256 must find nonce 83 with digest `008fa7f1...`, and the
Argon2id array's traffic must match its engine count and block cost.

### Talking to it, and asking it to check itself

A Raspberry Pi or an ESP32 reaches the chip over **SPI, QSPI or OSPI**: one
`spi_slave` block with `LANES = 1, 2, 4 or 8`, so the same RTL covers a Pi's
plain SPI, a Pi's QSPI and an ESP32-S3's OSPI. Measured: a byte in and a byte
out in 8, 2 or 1 SCLK cycles respectively, all three checked by `tb_spi`.

Writing the command byte **0x01** — over SPI or over UART, both decode into the
same signal — makes the chip test itself. It resets the Argon2 array first (it
loses its work, which is the point of a doctor request) and then runs:

| test | what it proves |
|---|---|
| **ARGON** | one real `argon2_fill` on a fixed block, XOR-folded over all 128 output words |
| **SHA** | one real `sha256_core` on a fixed block against a digest computed offline |
| **SIP** | one real `SipRound` on a fixed state, the HashX ALU's core operation |
| **MEM** | 64 requests spread over all 8 HBM3e stacks: every response must arrive exactly once with a valid id |
| **LIVE** | a counter the host polls — a dead clock cannot be detected by logic running on that clock |

The result comes back as a status byte on the SPI pads and on the status pins:
`{pass, done, busy, fail[3:0], 0}`.

**The checker is proven able to fail.** With `fault_inject` set the doctor
reports `fail_mask = 4'b0111`, and `tb_doctor` requires exactly that — a checker
that cannot fail proves nothing.

Two limits, so a PASS is not over-read: it tests one instance of each datapath
rather than all 365 Argon2 engines (they have identical layout, so a systematic
fault is caught but a single defective engine is not), and **MEM tests the
controller and id path, not DRAM cells** — the memory model here has no data
path, so a stuck bit inside a DRAM cell is outside what it can see.

### Benchmark: all three at once

`make -C beyond bench` runs the three sub-chips together with the difficulty set
impossible, so every lane hashes flat out and what is measured is the machine
rather than the size of a search:

```
bench: 24 A2I engines, 8 HX lanes, 8 SHA lanes, 8000-cycle window
  A2I : 1453 blocks, 649 B/cycle -> 4654 hashes/s at 24 engines
  HX  : 112 hashes of a 512-instruction program -> 571.43 cycles/hash,
        1.75 M h/s per lane, 224 M h/s at 128 lanes
  SHA : 968 hashes -> 66.12 cycles/hash, 15.12 M h/s per lane, 1936 M h/s at 128 lanes
```

| algorithm | measured per lane | design point @ 1 GHz |
|---|---|---|
| SHA-256 (1-block message) | 66.1 cycles/hash, 15.12 M h/s | 128 lanes -> **1.94 G h/s** |
| HashX (512 instructions) | 571.4 cycles/hash, 1.75 M h/s | 128 lanes -> **224 M h/s** |
| Argon2id | 649 B/cycle at 24 engines | 365 engines, 9,801 B/cycle -> **70,122 h/s** |

SHA-256 and HashX scale exactly with lane count, so a rate measured on 8 lanes
is the rate on 128. Argon2id does not: it is memory-bound, so the 24-engine
point above is compute-bound at 4,654 h/s and the design point is the 365-engine
measurement from `make card-argon2-max`.

Two footnotes so these numbers are not over-read. The HashX figure is 571.4
cycles per hash rather than the 533 that `tb_hashx` reports, because this counts
the search loop around each hash (scan, compare, next nonce) - that is what a
deployment actually pays. And the SHA-256 message here is one block; the
two-block case that `tb_pow` exercises costs 128 cycles.

Against the 2x Tesla T4 pair measured earlier: Argon2id **40x** (70,122 vs
1,759) and HashX **2.1x** (224 M vs 108.5 M). A Pi 5 reaches ~10.1 MH/s of
SHA-256 on its NEON/SHA-2 path, so 128 lanes are ~190x that.

### WebAssembly: HashX compiled to WAT

The HashX verifier is a 512-instruction VM, and its program is fixed for a whole
challenge — so it does not have to be interpreted. `tools/gen_hashx_wat.py` emits
the program as straight-line WAT (`wasm/hashx_jit.wat`, 1,171 lines, 10,232-byte
module) and `wat2wasm` assembles it. Same challenge, 2,000,000 hashes, Node 26:

| module | size | hashes/s | vs compiled WAT |
|---|---:|---:|---:|
| **hashx_jit.wasm** (compiled WAT) | **10,232 B** | **2,060,938** | — |
| baseline/hashx.wasm (official Anubis) | 35,983 B | 329,083 | 6.26x slower |
| simd128/hashx.wasm (official Anubis) | 35,863 B | 350,914 | 5.87x slower |

For scale, the C engine is ~571 cycles/hash: ~1.75 M hashes/s per core lane at
1 GHz. The compiled-WAT module lands in the same range as native C per lane,
which is the interesting result — hand-emitted WAT with no optimiser behind it,
against a Rust-compiled interpreter.

That was a build-time artifact for one challenge. The shipped version is the
same idea at run time: `wasm/hashx_jit.mjs` derives the program and emits the
module bytes in JavaScript, so `betterAnusbis`'s page and `tools/anubis_fetch.js`
compile whatever challenge they are handed, with no toolchain and no server round
trip. Same challenge, difficulty 20, 479,623 counted hashes, warm, one process:

| path | hashes/s | per hash | size |
|---|---:|---:|---:|
| **compiled in the page** | **2.90-3.18 M** | 0.31-0.34 us | 10,380 B |
| `hashx_pow.wasm` (our interpreter) | 0.43-0.46 M | 2.19-2.31 us | 15,237 B |
| official Anubis baseline | 0.37-0.39 M | 2.54-2.73 us | 35,983 B |
| official Anubis simd128 | 0.37-0.39 M | 2.54-2.72 us | 35,863 B |

So the runtime compiler is 6.7-7.0x the interpreter and 7.9-8.1x the module
Anubis ships, and all four agree on the nonce and the digest. The compile itself
costs ~6 ms per challenge, which is why the browser does it unconditionally and
why a threshold would be the refinement if very low difficulties ever mattered:
below about difficulty 12 the build is a larger cost than the search.

### Pure JavaScript: the sha256 fallback

The page can solve `sha256` with no WebAssembly at all: it happens
automatically when `WebAssembly` is missing or refuses the module, and
`#pure-js` on the challenge URL forces it. `fast` and `slow` have no wasm
module in the first place, so this JavaScript SHA-256 is their only browser
implementation.

This path was wrong until 2026-11-15: JavaScript masks shift counts to five
bits, so `bits>>>(8*i)` for `i>=4` repeated the low word, the 64-bit length was
written twice, and every digest was wrong. The numbers below are from the fixed
implementation, verified against `node:crypto` and the C engine's
`anubis_verify_bits` by `betterAnusbis/tests_js_sha256.mjs`.

Method: one fixed challenge (`9f2c1b4a...5c4b`), difficulty 20 (1,048,576
expected hashes), warm, best of three, Chrome 154 headless on the same
i7-1260P. The 4-wide wasm kernel ran in the same page and the JS rows never call
WebAssembly; both found nonce 5,133,809 with digest `00000dcaf513...79a7` — the
correctness cross-check, not an assumption. Node 26 on the same machine agrees
within ~15% (0.81-0.89 M/s reused, 7.59-8.31 M/s wasm) and the same two numbers
come out of `node betterAnusbis/bench-js-sha256.mjs --wasm`. The governor is
`powersave`, so
the ranges are run-to-run, not error bars; the first Chrome run was 2.5x slower
than the next two (cold start) and is kept in the raw data but not quoted here.

| path | hashes/s | per hash | note |
|---|---:|---:|---|
| **4-wide wasm kernel, same page** | **7.95-8.05 M** | 0.124-0.126 us | `sha256_pow_batch.wasm`, the fast path |
| **pure JS, reused padded block** | **0.87-0.91 M** | 1.10-1.15 us | the `sha256` fallback; ~9x slower |
| pure JS, fresh block per candidate | 0.34-0.38 M | 2.6-2.9 us | `fast`/`slow`; `sha256bytes()` |
| native C engine, one core | ~8.0 M | 0.125 us | for scale; the wasm kernel matches it |

Expected solve time at Anubis's tiers, from those rates:

| tier | difficulty | expected hashes | wasm | pure JS |
|---|---:|---:|---:|---:|
| light | 8 | 256 | 0.1 ms | 0.29 ms |
| medium | 16 | 65,536 | 8.7 ms | 74 ms |
| hard | 24 | 16,777,216 | 2.10 s | 18.8 s |

For `fast`/`slow` (nibbles, JavaScript only), the same one-shot rate gives
0.71 ms at light (d2), 0.18 s at medium (d4) and 47 s at hard (d6).

The fallback is enough for the light and medium tiers, which is what it exists
for. A hard `sha256` tier costs 19 seconds instead of 2, and a hard nibble tier
costs 47 seconds against 2 on the native path — that is the price of a browser
with WebAssembly disabled. The solver is single-threaded and a browser tab will
not use more cores, so the only lever is the wasm kernel (or WebGPU, which the
gate does not use).

Reproduce: `node betterAnusbis/bench-js-sha256.mjs --wasm` for the Node numbers;
the browser column is the challenge page loaded with `#pure-js`. Raw data:
[`results/js-sha256-2026-11-15.json`](results/js-sha256-2026-11-15.json).

### HashX in pure JavaScript

`hashx` has a JavaScript fallback too. When WebAssembly is unavailable, or
`#pure-js` is set, the page derives the challenge's program with the same
generator the wasm path uses and interprets its 512 instructions with 64-bit
BigInt arithmetic: the same opcodes, guarded backward branch and finalisation
as `hashx.c`. No wasm, no WebGPU.

Method: one fixed challenge, 500 hashes after one program derivation, warm,
best of three, Chrome 154 headless and Node 26 on the same i7-1260P. Derivation
is a per-challenge cost, so the tier table below adds it.

| path | hashes/s | per hash | note |
|---|---:|---:|---|
| program compiled to wasm in the page | ~3.2 M | 0.31 us | the fast path |
| `hashx_pow.wasm` interpreter | ~0.46 M | 2.2 us | the wasm fallback |
| **pure JS interpreter (BigInt)** | **12.8-15.3 k** | 65-78 us | no wasm; derivation 9-17 ms once |

At the tiers, derivation included:

| tier | difficulty | expected hashes | wasm (compiled) | pure JS |
|---|---:|---:|---:|---:|
| light | 7 | 128 | 0.04 ms | ~24 ms |
| medium | 15 | 32,768 | 10.3 ms | 2.44 s |
| hard | 20 | 1,048,576 | 330 ms | 78 s |

That is ~34x the wasm interpreter and ~240x the compiled program, which is what
512 instructions of 64-bit BigInt work per hash costs. The fallback is a
light-tier solution; medium is a couple of seconds and hard is over a minute.
Correctness is not assumed: `betterAnusbis/tests_js_hashx.mjs` runs solved
challenges through `hashx_pow.wasm` and the C engine's `anubis_verify_hashx`
and requires identical digests.

Reproduce: `node betterAnusbis/bench-js-hashx.mjs`; raw data:
[`results/js-hashx-2026-11-15.json`](results/js-hashx-2026-11-15.json).

### Argon2id in pure JavaScript

The last fallback. When WebAssembly is unavailable, or `#pure-js` is set, the
page runs Argon2id v1.3 with Anubis's parameters (m = 19456 KiB, t = 2, p = 1,
32-byte tag) in JavaScript: the reference fill from `third_party/argon2/ref.c`
ported to 32-bit `(lo, hi)` pairs, plus the WebGPU demo's BLAKE2b/H0/H'/tag
host code. It allocates one 19.9 MiB `Uint32Array` and reuses it for every
nonce, so a tab pays ~20 MiB while it solves.

Method: one hash (nonce 0) after warm-up, best of two or three, Chrome 154
headless and Node 26 on the same i7-1260P. This one is dominated by the
38,912 block fills, and the laptop's `powersave` drift is visible in it:

| path | ms/hash | hashes/s | note |
|---|---:|---:|---|
| wasm module (`argon2id_pow.wasm`) | 64.6-74.8 | 13-15 | the fast path |
| wasm module, same-session check | 85.9 | 12 | warm laptop |
| **pure JS, quiet run** | **620-735** | **1.4-1.6** | best measured |
| pure JS, warm laptop | 1050-1460 | 0.7-1.0 | later runs |

That is roughly **9-16x the wasm module** depending on which side of the drift
the runs land; the ratio within one warm session was 14.6x. At Anubis's tiers
(4/16/64 hashes expected), using the quiet 0.7 s/hash run:

| tier | difficulty | expected hashes | wasm | pure JS |
|---|---:|---:|---:|---:|
| light | 2 | 4 | 260 ms | 2.8 s |
| medium | 4 | 16 | 1.03 s | 11.2 s |
| hard | 6 | 64 | 4.1 s | 44.8 s |

A warm laptop roughly doubles those. This is the least practical of the three
JavaScript fallbacks — the wasm module is the right path whenever it loads —
but a browser with WebAssembly disabled can still clear a light Argon2id
challenge in a few seconds instead of being locked out. Correctness: the tag is
checked against `argon2id_pow.wasm` and the C engine's
`anubis_verify_argon2id` by `betterAnusbis/tests_js_argon2id.mjs`.

Reproduce: `node betterAnusbis/bench-js-argon2id.mjs`; the wasm comparison is
`node wasm/bench-a2i.mjs`. Raw data:
[`results/js-argon2id-2026-11-15.json`](results/js-argon2id-2026-11-15.json).

### `tensor`: one integer GEMM, and why WebNN is its real target

The three Anubis tiers all scale with integer/bit throughput, which is the axis
a CPU with wide SIMD is already good at and a GPU is often *worse* at. The
natural accelerated primitive is a matrix product, so `tensor` makes the work
exactly that:

```
raw    = hex_decode(randomData)
seed   = SHA256(raw)
stream = concat SHA256(seed || u32le(counter)) for counter = 0, 1, 2, ...
A[i]   = stream[i] & 0x7f                  uint8, N x N, row-major
B[i]   = int8(stream[N*N + i])             int8,  N x N, row-major
C      = A * B, exact int32
proof  = SHA256(C as N*N little-endian int32)
N      = 64 * clamp(difficulty, 2, 16)
```

Three details are load-bearing.

**It has to be integer.** Float addition reassociates, so a float GEMM gives a
different sum for every tiling, vector width and backend. The digest would then
depend on which kernel computed it and the server could not verify anything.
Integer accumulation in a fixed order is exact everywhere: the wasm kernel, the
JavaScript GEMM, WebNN and the C verifier produce identical bytes, and a digest
mismatch is a real failure, not rounding. WebNN is the one exception in form —
its `gemm()` is float-only — but the page widens to float32, where every
partial sum below 2^24 is still exact (see below).

**A is masked to seven bits.** A pair of products then always fits an i16
(2 x 127 x 127 = 32,258 < 32,767), which is what allows the wasm
`i16x8` dot and the x86 `maddubs`/`madd` kernels to use widening multiply-add
without saturation. Seven bits per byte is still 7/8 of the entropy, and the
stream is expanded from a SHA-256 seed, so nothing is lost.

**Verification costs one solve, not a search.** The digest covers every output
element, so a client cannot produce it without producing `C`, and the server
recomputes one GEMM per accepted pass: 20 ms at difficulty 8, 130 ms at 16.
That is a different cost model from the hash tiers, where verification is one
hash and the client pays `2^difficulty`; it is the price of making the tier a
real proof of compute rather than a lottery.

The page runs a **WebNN** `gemm` when `navigator.ml` exists, then the
wasm kernel, then the pure-JavaScript GEMM (also forced by `#pure-js`). WebNN
is the tier's real target: it is a JavaScript API that reaches NPUs and
integrated GPUs where a WebGPU dispatch is either slow or absent, and its
result is checked before it is trusted — the page recomputes two output rows in
JavaScript (0.4% of the work) and rejects the whole path if they disagree.
That check exists because backend `gemm` support is uneven; a backend that
returns nonsense, saturates, or silently drops to a wrong precision must not
be able to produce a digest the server would reject anyway.

The spec's `gemm()` only accepts float32/float16/bfloat16, so the page widens
the integer matrices to float32. That is still exact: every partial sum is an
integer bounded by `1024 * 127 * 128 < 2^24`, and float32 represents every
integer up to 2^24. The output is narrowed back to int32 after the read.

Correctness: the wasm kernel is checked in 48 cases against an independent
Node reference (`wasm/verify-tensor.mjs`, including all-127 and all--128
inputs), the page's JavaScript against `node:crypto` and an independent GEMM
(`betterAnusbis/tests_js_tensor.mjs`, including the WebNN reject path), and the
C verifier against a NumPy reference at every difficulty
(`anubis_tensor_digest`). The three implementations agree on the same
cross-check vectors.

Reproduce: `node betterAnusbis/bench-js-tensor.mjs --wasm` for the JS-vs-wasm
comparison on the same challenge, `node wasm/bench-tensor.mjs` for kernel-only
rates. Raw data:
[`results/js-tensor-2026-11-15.json`](results/js-tensor-2026-11-15.json).

### `tensor-v`: the same GEMM, a sampled server check

The 1:1 cost model above is the one thing about `tensor` that does not scale:
at difficulty 16 the gate spends 130 ms of CPU per accepted pass. `tensor-v`
keeps the client's work and makes the check proportional to the *output size*
rather than to the product:

```
BT[j][k] = int8(stream[N*N + j*N + k])   // B transposed: rows are contiguous
C[i][j]  = sum_k A[i][k] * BT[j][k]
leaf[b]  = SHA256("ANUBIS-TENSOR-VL" || chal || u32le(b) || C[b*32 .. b*32+31])
root     = binary Merkle root over the leaves, odd last duplicated
sample   = k blocks and one element per block, from SHA256(secret || challenge || root)
```

The client sends the root, receives the sample, and opens those blocks with
Merkle proofs. The server hashes each opened block to the root and recomputes
the one sampled element with a length-`N` dot product: `O(k*N)`, no GEMM.
Because the sample is chosen after the root and from a secret the client cannot
predict, a client that computed a fraction `f` of the elements passes with
probability `f^k` (`k = 96` → 4e-5 at `f = 0.9`).

Measured on the same machine (16-thread C client, single-thread verifier):

| difficulty | N | client root + tree | wasm client (`tv_solve`) | server audit | ratio |
|---|---|---|---|---|---|
| 8 | 512 | 18 ms | 82 ms | 2.4 ms | 1:34 |
| 12 | 768 | 32 ms | 269 ms | 3.0 ms | 1:90 |
| 16 | 1024 | 69 ms | 538 ms | 3.6 ms | 1:150 |

The transposed layout is what makes a sampled element check cheap: one column
of B is one contiguous row, so fetching `BT[j][*]` is `N/32` hashes instead of
`N` separate stream seeks. The server's ~3 ms at difficulty 16 is mostly those
stream hashes and the 15-level proofs; the dot products are noise.

Reproduce: `python3 tools/bench_tensor_v.py` (C client and verifier) and the
wasm timing in that section's `node` one-liner; the JSON is
[`results/tensor-v-2026-11-19.json`](results/tensor-v-2026-11-19.json).

The same benchmark on a Kaggle CPU kernel (2 Xeon cores at 2.20 GHz — a slower
box than the one above, so the client side stretches and the server side does
not) gives 2.6x at difficulty 2, 23x at 8 and **79.5x at 16**: 331 ms of client
work against 4.2 ms of server check. The ratio is the property that matters,
not the absolute number, and it moves with the client's machine because the
server's work is `O(k*N)` either way. That run is also the portability check for
this tier: it clones the `unstable` branch, builds, and passes
`test_tensor_v.py`, `test_tensor_v_gate.py`, the wasm cross-check and one real
challenge through the gate. Reproduce with
`kaggle kernels push -p src/core/kaggle_tensor_v`; the JSON is
[`results/tensor-v-kaggle-2026-11-20.json`](results/tensor-v-kaggle-2026-11-20.json).

The browser builds the tree in the wasm kernel (`tv_solve`, `tv_make_witness`);
the pure-JavaScript fallback (`tvTree`, `tvWitnessJS` in the page) is the same
tree written with the page's SHA-256, and `wasm/verify-tensor-v.mjs` +
`tests/test_tensor_v.py` pin that the two produce the same root and witness
bytes as the C core. The gate side is `tests/test_tensor_v_gate.py`: a real
backend, a real gate, an honest audit, a replay, a tampered block, and a
witness for a different sample.

The page's `tensor-v` path is: WebNN GEMM (when `navigator.ml` exists) into
the wasm `C` buffer, then `tv_solve_from_c` for the tree and `tv_make_witness`
for the sample. The same wasm module is the fallback GEMM. Without WebAssembly
the page builds the tree in JavaScript over whichever `C` it has (WebNN or its
own GEMM), so a browser with WebNN but no wasm still works. The WebNN result is
checked against two JavaScript rows before the tree sees it, and the tree/wasm
integration is exercised by `betterAnusbis/tests_js_tensor_v.mjs` with a fake
backend (bTranspose path, explicit-transpose retry, and a garbage matrix).

### WebGPU: three algorithms, three different verdicts

All three Anubis algorithms are now compiled to WGSL and run from the browser's
GPU (`webgpu/`). The point of putting them in one table is that "is WebGPU faster"
has three different answers:

| algorithm | WebGPU, Intel Iris Xe | WebAssembly, same browser | ratio | digests on the GPU | engine actually used |
|---|---:|---:|---:|---|---|
| **`sha256`** | **86.7 M hashes/s** | 2.53 M (4-wide) | **34x faster** | exact | **WebGPU** |
| `hashx` | 41.6 M hashes/s | 2.78 M | 15x faster | **wrong** | WebAssembly |
| `argon2id` | 3.6 hashes/s (278 ms/hash) | 13.2 (76 ms) | **0.27x, i.e. slower** | exact | WebGPU, against its own interest |

Measured back to back in one window on 2026-11-13 (load average 1.4-1.8, so the
desktop was idle), Chrome 145, Intel Iris Xe `gen-12lp` over Vulkan, each page
comparing itself against `wasm/*.wasm` in the same process. One window matters: the
same three figures move by 2-20x when the host is busy, and on this machine an iGPU
degrades far more than the CPU does because it shares memory bandwidth and needs the
CPU to submit work.

Two rows need their caveat attached rather than a footnote:

- **`hashx` is fastest-looking and unusable.** 41.6 M hashes/s against 2.78 M is a
  15x win, on digests that are wrong. The page's self-check refuses it and falls
  back to WebAssembly, so the number in the "GPU" column is the price of a
  backend that cannot be trusted, not a result.
- **`argon2id` works and loses.** 3.6 h/s against 13.2 is not a kernel bug: one
  hash needs 19,456 KiB, WebGPU caps a storage binding at 128 MiB, and six
  concurrent hashes cannot fill a GPU. The native Vulkan backend on the same
  hardware, with 64 concurrent hashes and 1.24 GB, gets 326 h/s. The limit, not the
  algorithm, is the story.

The rest of this section is the detail per algorithm.

#### HashX on WebGPU: the fastest wrong answer here

`tools/gen_hashx_wgsl.py` compiles the challenge's program to a WGSL compute shader
and the browser runs it on the GPU, one invocation per nonce. WGSL has no 64-bit
integers, so a `u64` is a `vec2<u32>` with the multiplies built from 16-bit limbs.
Hits are counted with an `atomicAdd` inside the shader, so a dispatch costs one
readback, not one per hash.

| engine | hashes/s | per hash | digests | |
|---|---:|---:|---|---|
| WebGPU, Intel Iris Xe (`gen-12lp`, Vulkan) | 41.6 M | 24 ns | **wrong** | 15x the wasm, and unusable |
| WebAssembly, this repo | 2.78 M | 360 ns | exact | the reference |
| WebGPU on SwiftShader, Xeon 56c box | 0.89 M | 1.1 µs | **exact** | a CPU emulator; wasm does 5.99 M there |

Same browser, same process, same program, 1,048,576 nonces per dispatch at
difficulty 255. Earlier runs of the same kernel measured 11.5-47.2 M depending on
load; the 41.6 M above is from the quiet window.

So the answer to "would WebGPU be faster for HashX" is **yes, by 15x on an
integrated GPU** — but from this machine that is a measurement of the same
instructions computing the wrong thing, so it does not go in the headline tables.
What it establishes is that the idea is worth the work, not that it works.

The wrong digest is identical across three different control-flow encodings
(nested loops with `continue`, a dispatch loop, and a build with all branch
handling removed), while the PRF, the u64 helpers and the first 113 VM
instructions are bit-exact on that GPU when dumped individually — so it is the
same wrong arithmetic, not a wrong jump. Two independent software backends
(SwiftShader on two machines) produce exact digests, which puts the burden of
proof on the Intel Vulkan compiler rather than on the WGSL.

**The page verifies before it trusts.** `webgpu/hashx.html` hashes eight known
nonces, compares them against the WebAssembly module, and only uses the GPU if
they all match; otherwise it says so and runs on WebAssembly. That is the same
rule the C engine applies to every GPU hit - a backend that cannot reproduce the
reference digest is not used, however fast it is - applied in the one place a
browser can apply it: up front.

| backend | self-check | engine used |
|---|---|---|
| Intel Iris Xe | fails: wrong digests | WebAssembly |
| SwiftShader (either machine) | passes | WebGPU |
| no WebGPU adapter at all | unavailable | WebAssembly |

`webgpu/README.md` has the backend matrix, the debug flags (`--dump-after`,
`--truncate`, `--no-branch`) and the four isolated probe pages used to reduce
this. `webgpu/run.sh` runs it; without
`--enable-features=Vulkan --use-angle=vulkan --use-vulkan=native` Chrome hands out
SwiftShader and every number measured is a CPU emulator's.

#### Argon2id on WebGPU: correct, and slower

`webgpu/argon2id.wgsl` does the same for Argon2id (m=19456 KiB, t=2, p=1,
32-byte tag) and the digest is bit-exact against `wasm/argon2id_pow.wasm` - nonce 0
of the committed challenge is `99d43e7d...` from both, and the self-check passes
4/4 on the Intel backend as well as on SwiftShader. It is also **3.7x slower than
the WebAssembly module** (0.27x), for a structural reason:

| engine | ms/hash | hashes/s | concurrency |
|---|---:|---:|---:|
| **WebGPU, Intel Iris Xe** | **278** | **3.6** | 6 |
| WebAssembly, same browser | 76 | 13.2 | 1 |
| native C, one core | 13 | 75 | 1 |

One hash needs 19,456 KiB and WebGPU caps a storage binding at 128 MiB here, so at
most **six** hashes fit. Six hashes cannot fill a GPU. The native Vulkan backend
on the same GPU reaches 326 h/s at d8 (8.6x the CPU) with **64** concurrent hashes
and 1.24 GB of working set - memory that WebGPU will not hand out. Binding several
storage buffers would raise the ceiling, but the per-hash cost is a serial chain of
38,912 block fills, so it would still trail the native path and would not beat the
wasm module.

The useful side effect is a diagnostic: Argon2id passes on Intel while HashX does
not. Argon2id uses add/sub/xor/rotate, `blamka` (32x32->64 `mulhi32`) and the whole
fill, but never a full 64x64 multiply - so the Intel miscompile is pinned to
`umulh64`/`mul64`, not to the u64 emulation as a whole.

#### SHA-256 on WebGPU: the one that wins

`webgpu/sha256.wgsl` is compute-bound, needs no memory, and SHA-256 is entirely
32-bit, so `vec4<u32>` gives four nonces per invocation with no u64 emulation. It
self-checks 8/8 on both backends (including nonzero nonces on both nonce byte
orders, which a nonce-0 check cannot distinguish) and it is the first WebGPU kernel
here that beats the wasm module by a wide margin:

| window | GPU | wasm 4-wide | ratio |
|---|---:|---:|---:|
| quiet machine | **86.7 MH/s** | 2.53 MH/s | **34x** |
| quiet, earlier window | 68.0 MH/s | 2.03 MH/s | 33x |
| moderate load | 23-39 MH/s | 0.79-1.15 MH/s | 29-39x |
| desktop busy (load 10-11) | 3.5 MH/s | 0.93 MH/s | 3.7x |
| SwiftShader (CPU backend) | 0.51 MH/s | 2.48 MH/s | 0.2x |

The ratio is the result and the absolute is the host: an iGPU shares memory
bandwidth and needs the CPU to submit, so a busy desktop hurts it far more than it
hurts wasm. 68 MH/s is about half the native Vulkan/Level Zero 137 MH/s on the same
iGPU, which is the expected gap for a shader with less scheduling freedom, and
17-23x wasm using this repo's 3.0-3.9 M/s baseline.

Measured kernel shapes, same load, same digests: the shipped 64-round loop with
`w[i & 15]` and K in a private array won; a 4x16 unrolled form with constant
indices - the obvious optimisation - was 2-3x slower (register pressure and lost
occupancy); fully unrolling killed SwiftShader's JIT outright with
`VK_ERROR_DEVICE_LOST`.

And the diagnostic is now closed from both sides: SHA-256 (pure 32-bit vector
arithmetic) **passes** on Intel, Argon2id passes, and only HashX fails. 32-bit
scalar and `vec4` arithmetic, rotates, shifts and the whole Argon2 fill are all
compiled correctly there; the wrongness is confined to the 64x64 multiply's high
half, `umulh64`/`mul64`.

Correctness is not assumed: `wasm/verify.mjs` makes both engines solve the same
difficulty-16 challenge, and they return the **same nonce (180078) and the same
digest** — the official module is 7-9x slower on the same work. Three
implementations (our C engine, our WAT, Anubis's Rust) agreeing is the evidence.

### WebAssembly: Argon2id, six implementations

The Argon2id fill core, ported six ways and checked bit-exact against vectors
compiled from the vendored C reference. Interleaved rounds, median of five:

| implementation | cache-resident | memory-bound | size |
|---|---:|---:|---:|
| WAT, scalar (generated) | 1.53 us | 1.70 us | 26,859 B |
| clang C, -O3 | 1.53 us | 1.76 us | 3,683 B |
| rustc, scalar | 1.55 us | 1.77 us | 3,742 B |
| WAT, v128 hand-written (rewritten, separate run) | 1.21 us | 1.53 us | 39,887 B |
| rustc, +simd128 | 1.97 us | 2.21 us | 5,784 B |
| clang C, -O3 -msimd128 | 2.02 us | 2.32 us | 6,173 B |
| official Anubis baseline | - | 1.81-1.97 us | 35,813 B |

Three conclusions, all measured rather than argued:

- **write C**: within 4% of hand-written WAT (inside the noise) and 7x smaller.
- **`-msimd128` hurts**, in clang and in rustc. Their auto-vectoriser loses to
  plain scalar on this kernel.
- **hand-written v128 loses too**: in its own interleaved run it is 1.53 us
  memory-bound against the scalar module's 1.59, a tie, which is why it is
  marked as a separate run above. The round costs 1.31-1.49x the scalar round
  because the
  unsigned 32x32->64 multiply fBlaMka needs is not `vpmuludq` in wasm SIMD - it
  multiplies adjacent i32 lanes, so each operand needs a shuffle to gather the
  two low halves first, and V8 then lowers the extmul with two more. Four
  shuffle-port uops per fBlaMka, 1,472 shuffle uops per block on a CPU with one
  shuffle port. `wasm/README.md` has the instruction counts.

The parallel lever is real and elsewhere: p=1 is fixed by the challenge, so
threads go across nonces - 2.11x on 2 workers, 3.75x on 4.

Hand-written WAT paid for HashX because a challenge-defined program must be
interpreted or code-generated, and removing the interpreter was the whole 7x.
Where there is no interpreter, use a compiler.

### Argon2id in wasm: why it was 2x slower, and what fixed it

The verdict flipped twice here, so the whole sequence is worth recording. Both
times the artifact under test changed, and both times I stated a result that was
true of one artifact and false of another.

**Final numbers**, one process, all modules interleaved over five rounds, warm,
median, hashes counted from the nonce the search returned rather than from the
number of calls (m=19456 KiB, t=2, p=1 is 38,912 block fills per hash):

| module | ms/hash | µs/block | note |
|---|---:|---:|---|
| **`argon2id_pow.wasm`** (now) | **64.6 - 74.8** | **1.66 - 1.92** | `argon2_fill_fast.c`, clang `-O3` |
| Anubis `baseline/argon2id.wasm` | 67.8 - 76.0 | 1.74 - 1.95 | their scalar build |
| Anubis `simd128/argon2id.wasm` | 69.9 - 78.8 | 1.80 - 2.02 | their shipped SIMD build |
| `argon2id_pow.wasm` (previous) | 131.5 - 162.6 | 3.38 - 4.18 | what v1.14.0 and v1.14.1 shipped |

The ranges are two runs on the same machine at different times, not error bars on
one measurement: this laptop drifts by 30% with load and governor. So the claim
is the ratio within a run, which is stable at **1.02-1.05x faster than Anubis's
module** and **2.03-2.17x faster than the binary we were shipping**. Two
independent causes, in this order of size:

**1. The build was miscompiled by one flag.** The old `argon2id_pow.wasm`
contains 73 `call $memcpy` sites and no `memory.copy`; the same sources built
without `-ffreestanding` contain `memory.copy` and none of those calls.
`-ffreestanding` (and `-mcpu=mvp`, which does the same thing for a different
reason) disables the compiler's builtin `memcpy`, so each 1 KiB `copy_block` and
`xor_block` inside `fill_block` became a call to the byte-at-a-time shim in
`wasm_string.c`. Reproduced from clean sources:

| build | ms/hash | `call $memcpy` |
|---|---:|---:|
| `-O3 -ffreestanding` | 161.8 | 73 |
| `-O3` (default `-mcpu`) | 86.6 | 0 |
| `-O3 -msimd128` | 99.2 | 0 |
| `-O2` | 81.3 | 0 |

That is a 1.9x loss from a flag that looks like it belongs in a `-nostdlib` build
and does nothing useful. This is why the previous version of this section blamed
the reference implementation: the 161 ms I measured was real, but it was 80 ms of
reference code and 80 ms of my flag.

**2. Half of the rest was the reference block function.** `ref.c` expands
`BLAKE2_ROUND_NOMSG` over a block-wide `uint64_t v[128]` inside a
`for (i = 0; i < 8; ++i)` loop, so the 16 words of a round are indexed by a loop
variable and never leave memory. `wasm/argon2_fill_fast.c` gathers each round
into a 16-word local with constant indices, rounds it in registers, and scatters
it back: 32 loads and 32 stores per round instead of 128 of each. The rest of the
driver (H0, H′, `index_alpha`, the passes) is still the reference package, which
is why the digests still match byte for byte.

**What did not work**, tested rather than assumed: `-msimd128` is 8-15% slower
here (LLVM's auto-vectorised BLAKE2 round beats scalar in instruction count and
loses in practice), and Anubis's own `simd128` module is also slower than its
`baseline` one, so this is a property of the toolchain and not of our code.
`-funroll-loops` was neutral to worse. A "skip the saved-XOR array on pass 0"
rewrite measured 1.02x better and was **wrong** — with `with_xor` clear the
saved value is `ref ^ prev`, not zero — so it is not in the tree; the module test
caught it before it shipped.

The claim to be careful about is the one about the *block function*. An earlier
version of this file said "parity" while the tables around it were talking about
the whole module. `argon2_fill_c.wasm` really is at parity with their block
function (1.73-1.90 µs against 1.81-1.97, and that number moved with the machine
every time I re-measured it). The module is where the money is, and the module is
now ahead.

Reproduce with `cd wasm && make verify-module`, which runs ten random challenges
through our module and then hands each digest to the official Anubis module's own
`anubis_validate`. Both speeds and both digests are in the same script:
`node wasm/bench-a2i.mjs` for the block, `node wasm/verify-a2i-module.mjs` for the
whole hash.

### What uses less RAM, and what uses less CPU

Same two servers, same three clients, read from `/proc` (the kernel's numbers, not
an estimate). Servers serving 300 challenge pages and 40 full pass-challenge
exchanges each:

| server | idle RSS | threads | CPU per challenge page | CPU per verification |
|---|---:|---:|---:|---:|
| Anubis v1.28.3 (Go) | **44-46 MB** | 17-19 | 870-900 µs | 2.3-2.8 ms |
| **betterAnusbis (C)** | **2.1 MB** | **1** | **470-500 µs** | **1.25 ms** |

**betterAnusbis uses ~21-22x less RAM and about half the CPU.** Neither grows under
load: RSS after 300 pages equals idle RSS, and peak RSS (`VmHWM`) never moved, so
neither server leaks per request. Anubis's 45.7 MB is its Go runtime and the
machinery around it — six wasm modules are only ~200 KB of that, so this is the cost
of the runtime, not the challenges. betterAnusbis's 2.1 MB is the process: 32-byte
secret, a 4096-entry honeypot table (~96 KB), and one thread per connection.

The verification row is where the engines differ: Anubis re-checks each answer
through its wasm module via wazero (2.75 ms), betterAnusbis calls
`libanubis_solver.so` (1.25 ms).

Clients, per hash of SHA-256 work:

| client | memory | CPU per hash | implied rate |
|---|---:|---:|---:|
| Anubis `sha256.wasm` | 1.06 MiB linear | 637 ns | 1.57 M/s |
| **our wasm, 4 nonces wide** | **0.13 MiB linear** | **364 ns** | 2.74 M/s |
| **native `.so`, 1 thread** | 36.3 MB process RSS | **194 ns** | 5.15 M/s |

The wasm numbers are the whole cost of the page's solver: linear memory is what the
wasm instance allocates, and it is single-threaded so CPU time and wall time are the
same. **Our kernel is 8x smaller in memory and 1.75x cheaper per hash** than the
module Anubis ships — the 4-wide batching keeps one 64-byte block and a hand-rolled
schedule, where the official module carries a general-purpose SHA-256 with more
working state.

The native row is a different shape of cost and is labelled as such: it is a separate
process the user opted into, its RSS is mostly CPython (~30 MB of the 36.3 MB), and
it uses the SHA-NI kernel. 194 ns is *one* thread; the default is four, which is
where the ~20 M hashes/s wall-clock figure comes from. A native host written in C
rather than Python would drop that RSS to a few MB — it is the one number in this
document that is clearly left on the table.

### The wall, end to end: two servers x three clients

The combinations asked for, both against a real backend on the same machine, all
six verified by the protected page coming back (`node tools/bench-endtoend.mjs`,
difficulty 20, 6 runs per cell):

| server | client | server + network (6 runs) | client throughput |
|---|---|---:|---:|
| Anubis v1.28.3 | Anubis's own wasm | 7.5 ms | 1.67 M hashes/s |
| Anubis v1.28.3 | our wasm, 4 nonces wide | 7.0 ms | 3.04 M hashes/s |
| Anubis v1.28.3 | **native `.so`** (Firefox) | 7.3 ms | **19.73 M hashes/s** |
| betterAnusbis (C) | Anubis's own wasm | 7.9 ms | 1.67 M hashes/s |
| betterAnusbis (C) | our wasm, 4 nonces wide | 7.2 ms | 3.04 M hashes/s |
| betterAnusbis (C) | **native `.so`** (Firefox) | 7.5 ms | **19.73 M hashes/s** |

**The server is not the differentiator.** Every cell pays 7.0-7.9 ms for one round
trip, the server's verification and the redirect — Anubis and a ~1,000-line C server
are indistinguishable. The 400 ms that separate the slowest combination from the
fastest belong entirely to the client.

Client throughput is measured in isolation (difficulty 21, warm, total hashes over
total time) because a *cell* measurement is luck: the nonce that satisfies a fixed
difficulty is exponentially distributed, so with six samples the median swings by
2-3x. That is not a shortcut — the first version of this table reported the same
client at 899 kH/s against one server and 1571 kH/s against the other, which is
impossible and was the measurement, not the server.

Put the two measured halves together and the expected time to the page is
`2^difficulty / rate + overhead`:

| difficulty | Anubis wasm | our wasm (4-wide) | native `.so` |
|---|---:|---:|---:|
| 12 (4 k hashes) | 10.5 ms | 9.3 ms | **8.2 ms** |
| 16 (65 k hashes) | 47 ms | 30 ms | **11 ms** |
| 20 (1.0 M hashes) | 636 ms | 353 ms | **61 ms** |

At difficulty 12 the wall is the HTTP round trip and nothing else: every client is
within 2 ms. The client only starts to matter around difficulty 16, and by
difficulty 20 the native path is **10x ahead** of Anubis's own wasm. That is the
whole argument for the Firefox extension and for using the library instead of the
browser.

Anubis's server-side verification is itself wasm (its Go server runs the same module
through wazero), which is why its overhead is not lower than a C server's; the two
are indistinguishable here.

### Tesla T4 (sm_75): the SHA-256 kernel and its SASS

`src/nvidia/sass/nvidiaT4_sha256.sass` is the shipped `src/nvidia/cuda/cuda_sha256.cu` kernel
compiled for `sm_75` and disassembled with `nvdisasm -c`;
`src/nvidia/sass/nvidiaT4_sha256_opt.sass` is the same algorithm with the block assembly moved
out of local memory. Built and run by `src/nvidia/sass/kaggle_t4_sass.py` on a Tesla
T4 (40 SMs, 1590 MHz, CUDA 13.0).

| kernel | instruction lines | stack frame | registers | MH/s |
|---|---:|---:|---:|---:|
| shipped | 2,024 | 96 B | 64 | 1,348 – 1,749 |
| **optimised** | 1,436 / hash | **0 B** | 40 | **2,390 – 2,412** |

Both kernels are verified word-for-word against a CPU compression before timing
(difficulty 0, so every nonce is a hit). 33.5 M nonces x 5 reps.

The shipped kernel builds the message block in an `unsigned char[64]`: zero 64
bytes, write the nonce, patch the length, then read all 16 words back through
`load_be32`. That is **96 bytes of local memory per thread**. The optimised one
builds `W[0..15]` in registers — for the `sha256` family (u32 nonce, one tail
block) `W1 = 0x80000000`, `W2..W14 = 0` and `W15` = bit length are constant per
challenge and are not rebuilt. Result: **1.4–1.8x**, and the run-to-run variance
goes away with the local traffic.

**ILP is a measured negative.** One, two and four nonces per thread measure
2,390 / 2,412 / 2,407 MH/s. The SM is issue-throughput-bound, not latency-bound,
so ILP buys nothing — and ILP=1 uses 40 registers instead of 64 or 128, i.e.
full occupancy. The right choice is no ILP at all.

Both kernels also ship fully annotated, one comment per instruction:
`nvidiaT4_sha256.annotated.sass` (2,024 instructions) and
`nvidiaT4_sha256_opt.annotated.sass` (2,872). The instruction stream in those is
byte-for-byte the SASS above - only trailing comments were added, and stripping
them restores the originals exactly. They name the operands, the SHA-256 term each
line implements, and the SASS modifiers that carry meaning (`.HI` funnel shifts,
`.X` carry chains, LOP3 truth tables - 0x96 is a three-way xor here, 0xE8 Maj,
0xB8 Ch).

Scope: the shipped kernel serves both the decimal-nonce (`fast`/`slow`) and
u32-nonce (`sha256`) families through a runtime branch; this optimisation is the
`sha256` family. The decimal path can be specialised the same way, but its digit
conversion still costs, so it is not claimed here.

### Tesla T4 (sm_75): HashX, and what an interpreter costs

Same treatment as SHA-256, and the answer is much bigger.
`src/nvidia/sass/nvidiaT4_hashx.sass` is the shipped `src/nvidia/cuda/cuda_hashx.cu` kernel for
`sm_75`; `_opt` pins the register file; `_jit` is the challenge program compiled
to straight-line code. All three reproduce the repo's own HashX vector
(`beyond/vectors/hx_vectors.hex` case 0, nonce 0) exactly.

| kernel | what it does | LDL/STL | regs | MH/s | vs shipped |
|---|---|---|---:|---:|---:|
| shipped | interpreter, program in global memory | 20 / 19 | 56 | 62.7 | 1.0x |
| `_opt` | register file pinned by a switch, program in `__constant__` | 1 / 2 | 50 | 87.3 | **1.39x** |
| `_jit` | **the program emitted as 512 straight-line statements** | 1 / 2 | 48 | **1,244** | **19.9x** |

At ILP 4 the JIT reaches **1,400 MH/s, 22.4x**.

The reason is arithmetic. An interpreter charges one constant fetch, one 11-way
dispatch and two local-memory accesses **per VM instruction**; the instruction
itself is one 64-bit op. Over 512 instructions that overhead is roughly 20x the
useful work — which is exactly the measured ratio. The HashX program is fixed for
a whole challenge, so there is no reason to interpret it at all: a real backend
generates this code host-side from `hashx_export`, and the only control flow that
survives is the program's single taken branch, which becomes one label and one
`goto`.

ILP is a measured negative in both variants, for opposite reasons: the
interpreter variant spills the register file (0.82x at 2, 0.36x at 4), and the
JIT is already issue-bound at 48 registers.

### Tesla T4 (sm_75): Argon2id, and the block copy

`src/nvidia/sass/nvidiaT4_argon2id.sass` is the shipped `src/nvidia/cuda/cuda_argon2.cu` kernel
for `sm_75`. The device source is sliced straight out of the shipped file, so the
baseline really is the baseline; only the block copy is swapped for `_opt`.

| variant | what changed | H/s on one T4 | vs shipped |
|---|---|---:|---:|
| shipped | 8-byte scalar copies, `prev`/`ref` read twice | 714.98 | 1.00x |
| **`_opt`** | 16-byte `uint4` copies, `prev^ref` kept in shared | **960.22** | **1.34x** |

m=19456, t=2, p=1 (the real parameters), 64 concurrent hashes (1.19 GiB
resident) x 8 reps. Both variants produce the **identical 32-byte tag**, checked
before timing.

The permutation is byte-identical in both — it is the algorithm, and it was
already cooperative (one block per CUDA block, 64 threads, shared `sR`). Only
the traffic around it changed:

1. **16-byte vectors instead of 8-byte scalars.** 64 threads cover a 1 KiB block
   in one iteration instead of two, and a warp request becomes 512 B instead of
   256 B.
2. **`prev^ref` is kept in a second shared array**, so the final xor does not
   re-read `prev` and `ref`. The shipped form reads 2 KiB and then re-reads the
   same 2 KiB; on a random-access workload that second read is L2 traffic, and it
   is now gone.

Where the time goes: 38,912 blocks per hash x 3 KiB of random traffic is 139 MB
per hash, so at 715 H/s the T4 is moving ~102 GB/s of random 1 KiB accesses on a
320 GB/s part. The copy was costing about a quarter of the run.

Two things this did **not** fix, both visible in the ptxas report: the kernel is
at the **255-register wall** and already spills 6 bytes, which caps occupancy on
a memory-latency-bound kernel; and only 32 of the 64 threads do G work in each
half-phase. The real remaining lever is the warp-cooperative `fill_block` — 32
threads, the whole block in registers, `__syncwarp` instead of `__syncthreads` —
which is a rewrite of that function rather than a copy-path change.

### Against the GPUs

| machine | argon2id hashes/s | hashx hashes/s |
|---|---:|---:|
| 1 CPU thread (i7-1260P) | 73 | 8.8 M |
| 2× Tesla T4 (measured) | 1,759 | 108.5 M |
| 59 chip engines @ 1 GHz + HBM3 | 5,888 | 188 M (100 engines) |
| 365 chip engines @ 1 GHz + 8× HBM3e | **46.6–70.4 k** | — |
| RTX 4090 (estimate, bandwidth-bound) | ~7,000 | — |
| H100 (estimate, bandwidth-bound) | ~20,000 | — |

Argon2id: one HBM3 stack beats the 2× T4 pair by **3.4×** and roughly matches a
4090 — it is a pure DRAM-bandwidth contest at that point, and 819 GB/s buys about
what a 4090's 1,008 GB/s buys. Eight HBM3e stacks change the character of the
argument: 70,426 hashes/s is 40× the T4 pair and 3.5× a (bandwidth-extrapolated)
H100, because 9.82 TB/s is more bandwidth than any single GPU has.
HashX: 100 engines beat the T4 pair by 1.7×, which is the one place custom
silicon genuinely wins, because the core has no memory to wait on.

### Caveats

- **The memory is the machine.** 40 engines are ~7.5 M generic yosys cells and
  already saturate one HBM3 stack; the stack and its PHY cost far more than the
  logic does. The eight-stack design needs 365 engines (68.1 M cells, and eight
  PHYs) to use its 9.82 TB/s. That is Argon2id working as designed.
- **The eight-stack number depends on K=3.** At two contexts per engine the
  floor is 175 cycles/block and the same 9.82 TB/s needs 484 engines instead of
  365, for the same 70,426 hashes/s. Nothing else in the design changes.
- **Area, not throughput, is where a core is big.** `argon2_fill` synthesises
  to 186,594 generic cells against `sha256_core`'s 8,477 and `hashx_exec`'s
  58,654 — roughly 10× a CUDA core, because it holds a 128 × 64-bit block and
  its 4-read/4-write port network. Those are generic cells, not standard
  cells; a real synthesis run would replace the mux network with a banked
  memory and cut it substantially.
- **Sweeps belong on the server.** Eight configurations, 8 × 12,000 blocks of
  simulation, take 97 s wall / 10 min CPU on 56 cores versus roughly a quarter
  of an hour on the 16-core laptop. `make -C beyond remote-mpipe` and friends
  rsync the tree and run there.

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
