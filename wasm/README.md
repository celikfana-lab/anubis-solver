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

## So: raw WAT or C? — measured, with C

Six implementations of the same block function, all bit-exact against vectors
compiled from the vendored C reference. Interleaved rounds, median of five, both
regimes (a sequential sweep drifts with wasm tier-up and GC and flips the
ranking — that mistake is documented below).

| implementation | cache-resident | memory-bound | module size |
|---|---:|---:|---:|
| WAT, scalar (generated) | 1.53 µs | 1.70 µs | 26,859 B |
| **clang C, `-O3`** | 1.53 µs | **1.76 µs** | **3,683 B** |
| rustc, scalar | 1.55 µs | 1.77 µs | 3,742 B |
| WAT, v128 hand-written | 1.71 µs | 1.95 µs | 35,292 B |
| rustc, `+simd128` | 1.97 µs | 2.21 µs | 5,784 B |
| clang C, `-O3 -msimd128` | 2.02 µs | 2.32 µs | 6,173 B |
| official Anubis baseline | — | 1.81–1.97 µs | 35,813 B |

**Answer: write C.** Not because it is faster — it is within 4 % of the
hand-written WAT, inside the noise — but because it is **7× smaller** for that
same speed, and because it is the version a person can maintain:

```bash
cd wasm
make argon2_fill_c.wasm        # the chosen kernel
node bench-compiler.mjs        # the table above
```

`wasm/argon2_fill_c.wasm` is built from `compiler/fill.c` by clang at `-O3`.

### What the measurements actually rule out

**`-msimd128` is a pessimisation, twice.** clang 2.32 µs against 1.76 scalar;
rustc 2.21 against 1.77. Two independent compilers, the same conclusion: their
auto-vectoriser does not help this kernel, it hurts. Not enabling it is a measured
decision, not an oversight.

**Hand-written `v128` does not win either.** `tools/gen_argon2_wat_simd.py` pairs
two u64 per register — the column G's pair exactly, the diagonals need the same
alignr-style shuffles as the C SSE2 path — and it is bit-exact. It lands at
1.95 µs: slower than plain C. Halving the multiply count does not help because
every round round-trips 16 words through memory, and the `fBlaMka` shuffles cost
most of what the lanes save.

That exercise did surface one real thing: `fBlaMka` needs the **unsigned** 32×32→64
multiply, `i64x2.extmul_low_i32x4_u`. Rust's stable `core::arch::wasm32` exposes
only the signed form, so a Rust intrinsics kernel cannot express it without a
correction sequence that erases the win. clang's `wasm_simd128.h` has it; WAT has
it. Worth knowing before writing Argon2 SIMD in Rust.

**The memory access pattern has no headroom.** Sweeping the working set from
16 KiB to the real 19 MiB leaves the per-block time flat (1.60–1.90 µs):
one `fill_block` moves 3 KiB in ~1.6 µs, under 2 GB/s, so arithmetic dominates and
the cache does not matter. No reordering was written, because the measurement said
not to.

**Threads across nonces are the only real lever.** `p=1` inside a hash is fixed by
the challenge, so parallelism goes across nonces — which is why the official module
takes an `iterand`. 1 → 2 → 4 workers scales 2.11× / 3.75× (31.9 hashes/s at 4),
near-linear, worker startup included.

### The rule

Hand-written WAT pays only where a compiler **cannot express** the optimisation: a
challenge-defined program that must be interpreted or code-generated, which is the
HashX case, where removing the interpreter was the whole 6×. For a fixed numeric
kernel the compiler is at least as fast, 7× smaller, and maintainable — so use it,
and spend the parallel budget on nonces.

## The true test: a real Anubis server, four solvers

A benchmark proves nothing on its own — the server is the judge. `wasm/live-test.mjs`
requests a challenge from a running Anubis, solves it four different ways, and only
counts a solve as a solve if the `pass-challenge` call is accepted **and** the
follow-up request returns the protected page.

Server: **Anubis v1.28.3, built from source here**, one rule
(`user_agent_regex: ".+"`, `algorithm: sha256`, `difficulty: 12`) in front of a
static page containing the string `PAST THE WALL`. Public hosts serve
`metarefresh` at difficulty 1, which measures nothing; a controlled server pins the
algorithm and the difficulty so the four solvers face identical work.

```bash
make sha256_pow.wasm   # our kernel
make live              # 8 runs per solver, every one verified by the server
```

Measured, 8 runs each, all 32 solves accepted:

| solver | median | rate | accepted |
|---|---:|---:|---|
| **official Anubis `sha256.wasm`** | 5.8 ms | **710 kH/s** | 8/8 |
| **our `sha256_pow.wasm`** (C, clang -O3) | 6.8 ms | **471 kH/s** | 8/8 |
| `crypto.createHash` (native, sync) | 20.6 ms | 168 kH/s | 8/8 |
| `crypto.subtle.digest` (native, async) | 86.2 ms | 24.5 kH/s | 8/8 |

**The native JS API is the slow path here.** That is the opposite of the intuition,
so it is worth being precise about why: these hashes are 36 bytes. At that size the
per-call overhead of a native API dwarfs the hash itself — `createHash` costs ~6 µs
per call against a ~1.4 µs hash, and `subtle.digest` chains a promise per nonce and
costs ~40 µs. A wasm module keeps the whole scan loop inside wasm and pays neither.

The rates are what the server actually demanded: difficulty 12 means the nonce
found varies with luck, so ms alone would compare luck. `hashes/s` is computed from
the nonces actually scanned.

### Our kernel vs the official one: 0.66×

471 kH/s against 710 kH/s. The first version of `sha256_pow.c` was **200 kH/s**
(0.28×) because it built the 64-word message schedule in a stack array; the fix was
the classic one — a rolling 16-word schedule with the 64 rounds fully unrolled, so
`w` stays in registers and `K[i]` becomes an immediate. That took it to 471 kH/s
and the module from 3.1 KB to 17.5 KB, which is the trade the official build also
made.

Closing the last 1.5× would mean the 4-way interleaved schedule OpenSSL and the
official build use. It is a real gap, and it is stated rather than hidden: our
kernel is 0.66× the official one, not equal to it.

### What changed in the fetcher

`tools/anubis_fetch.js` now solves `sha256` with this kernel instead of
`crypto.createHash`, which is the measured 2.8× (168 → 471 kH/s) and the reason to
have written it. It falls back to `createHash` when the module is not built.

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
