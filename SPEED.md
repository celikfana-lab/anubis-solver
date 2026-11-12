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
