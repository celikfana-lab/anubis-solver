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
| `hashx` (WASM, compiled) | ~3.2 M/s | the challenge's program compiled to wasm in the page |
| `hashx` (WASM, interpreted) | ~0.46 M/s | fallback when the compile cannot run |
| `argon2id` (WASM) | ~15/s | 19,456 KiB and ~65 ms per hash |

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

### `hashx` (WASM)

The browser now compiles the challenge's program to wasm before hashing it, so
these are the compiled numbers with the interpreter in brackets:

| tier | difficulty | expected hashes | expected time |
|---|---:|---:|---:|
| light | 7 | 128 | 40 µs (281 µs) |
| medium | 15 | 32,768 | 10.3 ms (72 ms) |
| hard | 20 | 1,048,576 | 330 ms (2.3 s) |

### `argon2id` (WASM)

| tier | difficulty | expected hashes | expected time |
|---|---:|---:|---:|
| light | 2 | 4 | 260 ms |
| medium | 4 | 16 | 1.03 s |
| hard | 6 | 64 | 4.1 s |

`argon2id` is deliberately expensive per attempt, so its observed hashrate is
~15/s per core — and each worker thread needs ~19 MiB, so 16 threads cost
~300 MiB. These numbers were 30% faster than reality before the module was
rebuilt; see [the wasm section](#argon2id-in-wasm-why-it-was-2x-slower-and-what-fixed-it).

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
| WAT, v128 hand-written (rewritten) | 1.21 us | 1.53 us | 39,887 B |
| rustc, +simd128 | 1.97 us | 2.21 us | 5,784 B |
| clang C, -O3 -msimd128 | 2.02 us | 2.32 us | 6,173 B |
| official Anubis baseline | - | 1.81-1.97 us | 35,813 B |

Three conclusions, all measured rather than argued:

- **write C**: within 4% of hand-written WAT (inside the noise) and 7x smaller.
- **`-msimd128` hurts**, in clang and in rustc. Their auto-vectoriser loses to
  plain scalar on this kernel.
- **hand-written v128 loses too**: 1.53 us memory-bound against the scalar
  module's 1.59, a tie. The round costs 1.31-1.49x the scalar round because the
  unsigned 32x32->64 multiply fBlaMka needs is not `vpmuludq` in wasm SIMD - it
  multiplies adjacent i32 lanes, so each operand needs a shuffle to gather the
  two low halves first, and V8 then lowers the extmul with two more. Four
  shuffle-port uops per fBlaMka, 1,472 shuffle uops per block on a CPU with one
  shuffle port. `wasm/README.md` has the instruction counts.

The parallel lever is real and elsewhere: p=1 is fixed by the challenge, so
threads go across nonces - 2.11x on 2 workers, 3.75x on 4.

Hand-written WAT paid for HashX because a challenge-defined program must be
interpreted or code-generated, and removing the interpreter was the whole 6x.
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
| `argon2id_pow.wasm` (previous) | 131.5 - 162.6 | 3.38 - 4.18 | what the last three releases shipped |

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

`src/sass/nvidiaT4_sha256.sass` is the shipped `src/cuda/cuda_sha256.cu` kernel
compiled for `sm_75` and disassembled with `nvdisasm -c`;
`src/sass/nvidiaT4_sha256_opt.sass` is the same algorithm with the block assembly moved
out of local memory. Built and run by `src/sass/kaggle_t4_sass.py` on a Tesla
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
`src/sass/nvidiaT4_hashx.sass` is the shipped `src/cuda/cuda_hashx.cu` kernel for
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

`src/sass/nvidiaT4_argon2id.sass` is the shipped `src/cuda/cuda_argon2.cu` kernel
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
