# CUDA backends

Three kernels, no build system of their own: the top-level `Makefile` compiles
them when a CUDA toolkit is present and skips them entirely with `make CUDA=0`.
Nothing here is required for a correct solve.

| file | algorithms | what one thread does |
|---|---|---|
| `cuda_sha256.cu` | `fast`, `slow`, `sha256` | builds one 64-byte tail block, hashes one nonce, tests the leading zero bits, claims a result slot with `atomicAdd` |
| `cuda_argon2.cu` | `argon2id` | one 64-thread CUDA block per hash: 1 KiB per block in shared memory, the 19 MiB matrix in global memory |
| `cuda_hashx.cu` | `hashx` | interprets the challenge's 512-instruction program, one copy of the program per thread |

## Measured on 2x Tesla T4 (Kaggle, CUDA 13.0)

| workload | GPU | one CPU thread | ratio | receipt |
|---|---:|---:|---:|---|
| `fast`, difficulty 6 | 922.4 MH/s | 17.6 MH/s | 52.3x | [`cuda-t4.json`](../../results/cuda-t4.json) |
| `fast`, difficulty 7 | 2286.3 MH/s | 16.4 MH/s | 139.7x | same run |
| `sha256`, 24 bits | 1719.8 MH/s | 22.7 MH/s | 75.7x | same run |
| `sha256`, 26 bits | 2985.1 MH/s | 22.8 MH/s | 130.9x | same run |
| `argon2id`, difficulty 8 | 1758.6 h/s | 85.0 h/s | 20.7x | [`argon2id-cuda-t4.json`](../../results/argon2id-cuda-t4.json) |
| `hashx`, difficulty 28 | 108.5 MH/s | 8.87 MH/s | 12.2x | [`hashx-cuda-t4.json`](../../results/hashx-cuda-t4.json) |

Three of those rows are lower than a reader expects, and each for a real reason.
Argon2id is memory-bound, so 128 concurrent hashes per device (2,550 MB of a
15 GB T4) buy 20.7x rather than 130x. HashX interprets 512 instructions per hash
instead of running a straight line, so it lands at 12.2x, the worst of the three.
And the first row is the smallest only because difficulty 6 is cheap: the ratio
grows with difficulty, because the denominator is fixed work per attempt and the
numerator is fixed work per attempt on better hardware.

## The rules these files follow

- **Opt-in.** Argon2id and HashX need `ANUBIS_GPU_ARGON2=1` / `ANUBIS_GPU_HASHX=1`.
  SHA-256 is threshold-gated. A default build never touches a GPU.
- **Every hit is re-verified.** `src/core/anubis_solver.c` re-computes each
  candidate with the reference implementation before accepting it. A GPU backend
  that returns a wrong digest is discarded and the search falls back to the CPU,
  which is why the WebGPU Intel bug in `webgpu/` is an annoyance rather than a
  correctness bug.
- **The CPU is always built.** No configuration makes the GPU mandatory.
- **Say what you measured.** These numbers are kernel throughput on one nonce per
  thread, not end-to-end solves. `SPEED.md` is where the honest comparison lives.

---

## "Hey Claude vibeslop me a CUDA Anubis solver"

From [It took a year to ship WebAssembly in Anubis](https://xeiaso.net/blog/2026/anubis-wasm/)
by Xe Iaso, September 6 2026, announcing memory-hard challenges:

> This makes Anubis challenges use a memory-hard proof of work function (argon2id)
> instead of just a CPU hard one. It also means that the "hey Claude vibeslop me a
> CUDA Anubis solver" route is on its way to being fundamentally dead.

This directory is the thing that sentence describes. `cuda_argon2.cu` is the
"vibeslop me a CUDA Anubis solver" file. It is in `src/cuda/`, it was written by
an AI — DeepSeek V4.1 Flash, per `AGENTS.md` — and it computes 1,758.6 hashes per
second on two T4s, 20.7x a CPU thread, with every tag checked against
`argon2-cffi` before it is reported. The route is not dead. It has a toll booth,
and the toll is one repo and one afternoon.

`HALL_OF_SHAME.md` makes this argument at length, with the numbers, because it is
the funniest claim anyone has made about this project. What is worth adding here,
in the directory where it landed, is the part that is **not** funny-back:

### Three things in that sentence are true

Pretending the whole criticism is wrong would be its own kind of vibeslop.

1. **Most AI-written GPU code is exactly that bad**, and the failure mode is the
   one the phrase names: a kernel that compiles, runs, produces plausible numbers,
   and computes something slightly else. The reason this repository re-verifies
   every GPU hit against the CPU is that it does not trust its own kernels either.
   That is not modesty, it is the only reason to ship one.
2. **Memory-hardness does take something away.** On the Intel Iris Xe in this
   laptop, Argon2id in WebGPU is **0.26x** the WebAssembly module — slower than
   the CPU it is supposed to beat. The claim is wrong about a Tesla T4 and right
   about an integrated GPU, which is most of the hardware in the world.
3. **"Fundamentally dead" is doing a lot of work in a claim whose own measurement
   is 3.5x.** At difficulty 6 Argon2id on two T4s is 3.5x a CPU thread; at
   difficulty 8 it is 20.7x. Anubis picks the difficulty, so the honest statement
   is "this got less obviously free", not "this is dead". A 3.5x return on a bot
   farm is a bad business, which is the actual argument, and it is much better
   made with the number than with the adverb.

What survives the whole exchange is the economic point, and it is the one Anubis
always made for itself: memory-hardening does not make solving impossible, it
makes solving cost money. The measurement that supports it is
[`HALL_OF_SHAME.md` entry 8](../../HALL_OF_SHAME.md): a difficulty-4 challenge
costs one Xeon core 9.8 ms. This directory is the faster car in that argument, and
the argument is still correct.

### What "vibeslop" would have looked like here

The useful test is not whether an AI wrote it. It is whether anything checks it.

| the stereotype | what is in this directory instead |
|---|---|
| a kernel that computes almost the right digest | every hit re-verified by `anubis_verify_*`, wrong backend discarded |
| numbers from one run on a hot laptop | committed JSON in `results/`, A/B interleaved in one process, ratios from one run |
| no baseline, so every number looks like a win | a CPU thread measured in the same run, in every row |
| negative results quietly deleted | `results/` keeps the 3.5x at difficulty 6 and the 0.26x WebGPU number |
| "it's faster" | `SPEED.md` says which artefact was timed, on which host, at which load |

If you want the version of this argument in one sentence: **vibeslop is not "an AI
wrote it", vibeslop is "nobody checked it".** The two are correlated for obvious
reasons, and the correlation is not a law.

## Reproducing

```bash
make                              # CUDA is used if nvcc is found
python3 tools/bench_gpu.py        # SHA-256 / fast, prints the CPU baseline too
ANUBIS_GPU_ARGON2=1 python3 tools/bench_argon2_gpu.py
ANUBIS_GPU_HASHX=1 python3 tools/bench_hashx_gpu.py
```

The machine code these compile to is disassembled and annotated, one comment per
instruction, in [`src/sass/`](../sass/README.md) — which is the part of the story
that makes the vibeslop criticism age worse, not better.
