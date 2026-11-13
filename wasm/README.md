# HashX compiled to WAT — and what that is worth in a browser

A HashX program is **fixed for a whole challenge**: the 512-instruction VM is
derived from the challenge bytes and never changes while you search. So it does
not have to be interpreted.

`tools/gen_hashx_wat.py` takes that program and emits it as **straight-line WAT** —
one WebAssembly instruction per VM instruction, eight 64-bit registers as locals,
and one nested `loop` per branch target so the program's single taken backward
branch becomes a `br`. The result is assembled with `wat2wasm` and needs no
interpreter, no dispatch, and no program memory.

```
wasm/hashx_jit.wat    1,171 lines of generated WAT
wasm/hashx_jit.wasm   10,232 bytes
```

This is the same move that gave the 19.9× CUDA speedup (`SPEED.md`): stop
interpreting the challenge program, start executing it.

## Measured against the official Anubis modules

`node wasm/bench.mjs` — same challenge, same 2,000,000 hashes, Node 26:

| module | size | hashes/s | vs the compiled WAT |
|---|---:|---:|---:|
| **`hashx_jit.wasm`** (compiled WAT) | **10,232 B** | **2,060,938** | — |
| `baseline/hashx.wasm` (official) | 35,983 B | 329,083 | **6.26× slower** |
| `simd128/hashx.wasm` (official) | 35,863 B | 350,914 | **5.87× slower** |

For context, the C engine does ~571 cycles/hash — about 1.75 M hashes/s per core
lane at 1 GHz, and ~224 M across 128 lanes. **The compiled-WAT module is in the
same league as native C per lane**, which is the surprising part: hand-emitted
WAT with no optimiser behind it beats a Rust-compiled interpreter by 6×.

## The check that matters: they agree

Speed is worthless if the answer is wrong, so `node wasm/verify.mjs` compares the
two implementations on identical work. Both derive the program from the same
32-byte challenge and scan the same nonce sequence, so at a given difficulty they
must find the *same* nonce and produce the *same* digest:

```
  ok   compiled WAT: digest(nonce 0) matches the C engine
  ok   compiled WAT: solved difficulty 16  nonce 180078
  ok   official baseline: same nonce as ours  theirs 180078, ours 180078
  ok   official baseline: same digest as ours  14b6f9a31b6b0000|…
  ok   official simd128: same nonce as ours
  ok   official simd128: same digest as ours
       ours 68 ms, theirs 481 ms  -> 7.08x slower
```

Three independent implementations — our C engine, our compiled WAT and Anubis's
Rust module — produce the same digest for the same nonce. That is the strongest
verification available here, and it is the demo page's centrepiece.

## Argon2id: the same trick, corrected

An earlier version of this file claimed the WAT port was **3.5–4.5× slower** than
the module Anubis ships. That was wrong, and the way it was wrong is worth
recording: the WAT side was measured cold and cache-resident (three fixed 1 KiB
blocks, single pass, wasm still on its baseline compiler tier) against a warm,
memory-bound whole hash. Both errors push in opposite directions and neither was
checked. Re-measured properly — warm, best of three, references scattered across
the 19 MiB arena a real Argon2id run uses — the answer changes.

`tools/gen_argon2_wat.py` emits the reference `fill_block` (8 column + 8 row
rounds of BlaMka, unrolled). `wasm/ref_fill_vectors.c` compiles the vendored C
reference itself to produce vectors, and `wasm/verify-a2i.mjs` checks the WAT
against them — bit-exact on all three trials.

Then the question that matters: *who schedules the instructions*. Same block
function, warmed, both regimes, best of three:

| implementation | cache-resident | memory-bound (19 MiB) | module size |
|---|---:|---:|---:|
| hand-written WAT | 1.59 µs | **1.61 µs** | 26,859 B |
| **rustc → wasm (scalar)** | **1.49 µs** | 1.74 µs | **3,742 B** |
| rustc → wasm (`+simd128`) | 1.94 µs | 2.20 µs | 5,784 B |
| official Anubis baseline | — | 1.81–1.97 µs | 35,813 B |
| official Anubis simd128 | — | 1.82–2.00 µs | 35,593 B |

Three things fall out of that:

1. **Hand-written WAT buys nothing here.** It is within run-to-run noise of
   `rustc`'s output (repeat runs of the same binary vary 1.6–2.3 µs), and 7×
   larger for it.
2. **Auto-vectorisation made it slower.** `+simd128` is a clear pessimisation on
   this kernel — 2.20 µs against 1.74 µs scalar. Do not assume the vector path
   helps; measure it.
3. **We are already at parity with what ships.** Within noise of the official
   module, whose figure is a whole hash and ours is the mixing loop only.

## So: raw WAT or C? — all three levers, measured

Four implementations of the same block function, all bit-exact against the C
reference, warmed and measured twice: cache-resident, and memory-bound over the
19 MiB arena a real hash uses. Best of three passes each.

| implementation | cache-resident | memory-bound | module size |
|---|---:|---:|---:|
| WAT, scalar (generated) | 1.40 µs | 2.55 µs | 26,859 B |
| **WAT, v128 hand-written** | 2.21 µs | 2.45 µs | 35,292 B |
| **rustc, scalar** | 2.08 µs | **1.90 µs** | **3,742 B** |
| rustc, `+simd128` | 2.10 µs | 2.33 µs | 5,784 B |
| official Anubis baseline | — | 1.81–1.97 µs | 35,813 B |

### 1. Explicit `v128`: it works, and it is not worth it

`tools/gen_argon2_wat_simd.py` emits the round with two u64 per vector register.
The column G's pair exactly — `G(i,i+4,i+8,i+12)` for i=0,1 is one vector G over
`(q0,q2,q4,q6)` — and the diagonal G's need the same alignr-style shuffles the C
SSE2 path uses. It is bit-exact on all three trials (128/128 words).

**And it buys nothing**: 2.45 µs against 2.55 µs scalar in the memory-bound
regime, inside the run-to-run noise. Halving the multiply count does not help
because the kernel is not multiply-bound in the way the op count suggests — every
round also round-trips 16 words through memory, and the shuffles for `fBlaMka`'s
unsigned 32×32→64 multiply cost most of what the vector lanes save.

One thing it *did* need: `i64x2.extmul_low_i32x4_u`. Rust's stable
`core::arch::wasm32` exposes only the **signed** variant, so a Rust intrinsics
version cannot express fBlaMka without a correction sequence that erases the win.
In WAT the unsigned opcode is one instruction. That is the one place in this whole
exercise where hand-written WAT could do something Rust could not — and it still
was not faster.

### 2. The memory access pattern: no headroom

The same fill_block, 15,000 blocks, working set swept from 16 KiB to the real
19 MiB (`node bench-memory.mjs`):

```
16 KiB   1.72 µs/block      1 MiB   1.86     16 MiB  1.60
64 KiB   1.90 µs/block      4 MiB   1.89     19 MiB  1.62
```

**Flat.** Argon2id is called memory-hard, and it is — for the whole 19 MiB
hash — but a single 1 KiB block mixes three blocks (3 KiB of traffic in ~1.6 µs
= under 2 GB/s), so the arithmetic dominates and the cache does not matter.
There is nothing to prefetch your way out of, which is why no reordering was
written: the measurement said not to bother.

### 3. Threads across nonces: the real win

`p=1` inside a hash is fixed by the challenge, so parallelism goes *across*
nonces — which is why the official module takes an `iterand` parameter. Each
nonce is an independent 19 MiB hash, so this scales:

```
 1 worker    8.5 hashes/s
 2 workers  17.9 hashes/s    2.11x   (ideal 2x)
 4 workers  31.9 hashes/s    3.75x   (ideal 4x)
```

`node bench-threads.mjs` — near-linear, and the only lever with real headroom.
Worker startup is included, so this understates it slightly at these hash counts.
In a browser this is Web Workers; a tab gets one per core.

### The answer

**Write C or Rust, and spend the parallel budget on nonces.** Hand-written WAT is
worth it only where a compiler *cannot express* the optimisation — a
challenge-defined program that must be interpreted or code-generated, which is the
HashX case and where removing the interpreter was the whole 6×. For a fixed
numeric kernel: the compiler is 7× smaller for the same speed, its scheduling is
free, and here even a hand-written vector kernel did not beat it.

## The demo

```bash
cd wasm
make serve          # http://127.0.0.1:8933/demo/
```

Pick a difficulty and a throughput window, press **Run**, and the page solves the
challenge with:

1. the **compiled WAT** module (ours),
2. the **official baseline** module,
3. the **official SIMD** module,

then reports hashes/s and solve time for each, and a check table: the digest for
nonce 0 against the C engine, the found nonce satisfying the difficulty, and —
the interesting row — **whether the official module finds the same nonce and the
same digest as ours**.

It is a static page: `python3 -m http.server` is enough, `file://` will not work
because `fetch()` is used for the modules.

## Files

| path | what |
|---|---|
| `hashx_jit.wat` | generated, committed (it is the deliverable) |
| `hashx_jit.wasm` | assembled from it |
| `bench.mjs` | headless benchmark, `--hashes N`, `--official <dir>` |
| `verify.mjs` | cross-implementation correctness check (exit status is CI-usable) |
| `demo/index.html`, `demo/app.js` | the browser demo |
| `demo/official/` | the two official modules, copied verbatim (see its README) |
| `argon2_fill.wat`, `argon2_fill.wasm` | the Argon2id fill core, generated |
| `verify-a2i.mjs`, `bench-a2i.mjs` | its correctness check and benchmark |
| `ref_fill_vectors.c`, `fill_vectors.txt` | vectors from the vendored C reference |

`make` regenerates the WAT and the wasm; `make bench`, `make serve`, `make clean`.

## Limits, stated plainly

- **One challenge, one program.** The WAT is generated for the challenge in
  `beyond/vectors/hx_vectors.hex` case 0. A real deployment runs the generator
  at challenge time; the generator is the JIT, WAT is its output. Nothing here
  compiles arbitrary challenges *in the browser*.
- **The official numbers are this machine, one Node version** (26.13). Wasm
  engines differ a lot; wasmtime or V8 in a browser will not give identical
  numbers. The ratio is the interesting quantity, not the absolute rate.
- **A 512-instruction program is not 512 wasm instructions.** About 32 mulhi
  operations expand to a dozen instructions each, and the straight-line body is
  ~5,000 wasm instructions. The 10 KB module is what that costs.
- **This does not make Anubis solvable faster for a *server*.** Its value is on
  the client: less CPU for the same proof of work, which is exactly where a
  browser verifier spends its time.
