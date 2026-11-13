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
| WAT, v128 hand-written (rewritten) | 1.21 µs | 1.53 µs | 39,887 B |
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
The kernel that actually ships is the same round in `wasm/argon2_fill_fast.c`,
which adds the rest of `fill_segment` around it so the whole Argon2id hash can be
built without the reference implementation's memory-based block function.

### What the measurements actually rule out

**`-msimd128` is a pessimisation, twice.** clang 2.32 µs against 1.76 scalar;
rustc 2.21 against 1.77. Two independent compilers, the same conclusion: their
auto-vectoriser does not help this kernel, it hurts. Not enabling it is a measured
decision, not an oversight.

**Hand-written `v128` does not win either, and now we know exactly why.** The
rewritten `tools/gen_argon2_wat_simd.py` is bit-exact and lands at 1.21 µs/block
resident against the scalar module's 1.32 (both measured inside wasm, 128/128
vectors). But that is *resident*: with the real 19 MiB working set the same pair
is 1.53 against 1.59, a tie. The round itself is the problem, and it is
instruction-level:

- `i64x2.extmul_low_i32x4_u` is **not** `vpmuludq`. It multiplies i32 lanes 0 and
  1, which in the natural u64 layout are the two halves of *the same word*, so
  each operand has to be gathered into lanes 0,1 first (`i8x16.shuffle`), and V8
  lowers the extmul itself as `vpunpckldq` + `vpunpckldq` + `vpmuludq`. Four
  shuffle-port uops per `fBlaMka`.
- `rot24` is a `pshufb` whose mask V8 rematerialises inline; `rot16` becomes
  `vpshuflw` + `vpshufhw`. 320 shuffle-port uops per block.

On a CPU with one shuffle port that is the whole story: V8's TurboFan listing for
the fill is 4,432 instructions of which 1,472 are shuffle-port uops, against 4,791
instructions and **zero** shuffles for the scalar form. Measured rounds-only, in
module, the v128 round is 1.31–1.49x the scalar round, and no restructuring
changes that — the packing is the price of the 2-wide multiply.

**What the v128 work did buy** is the plumbing: the copy and the final XOR
unrolled to 64 `v128` steps with the `with_xor` branch hoisted, instead of
128-iteration scalar loops. Scalar rounds on that plumbing measure 1.24 µs/block
scattered against the scalar module's 1.59, and that is the fastest correct fill
measured here. It is *not* shipped as the module because it does not transfer to
C: both an unrolled/hoisted C version (1.06x the current module) and explicit
`wasm_simd128.h` intrinsics under `-msimd128` (1.23x) came out slower, since
`-msimd128` pessimises the round more than the plumbing saves. The 1 KiB copies
that the shipped module uses are already `memory.copy`, which is the same idea by
another route. `wasm/bench-fill-inmodule.mjs` reproduces every row.

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

## Beating the official module: four nonces at a time

The official module and my first kernel hash **one nonce per pass**. SHA-256's 64
rounds are serial, so the only thing left to vectorise is the message schedule —
which is exactly what `sha2`'s `wasm32_simd128` backend does, and why it was ~16 %
ahead of a scalar kernel.

But this is a **search**, and the candidates are independent. So don't vectorise
the schedule: vectorise **across four nonces**. Every round becomes four hashes
wide, the schedule comes along for free, and the winner is still the smallest
nonce that satisfies the difficulty — the same answer a sequential scan gives.

`wasm/sha256_pow_batch.c` does that, in `i32x4` lanes, with the padded block built
once per challenge and only the four nonce bytes differing per lane.

Fixed work, warm, difficulty 23, best of two (`node bench-sha256.mjs`):

| module | rate | per hash | size |
|---|---:|---:|---:|
| **ours, 4 nonces wide** | **3936 kH/s** | **0.254 µs** | 38,643 B |
| official `simd128` (schedule-vectorised) | 1854 kH/s | 0.539 µs | 18,428 B |
| ours, scalar schedule | 1682 kH/s | 0.595 µs | 25,924 B |
| official `baseline` | 1517 kH/s | 0.659 µs | 25,326 B |

**2.13× the module Anubis ships**, from a 2.6× wider module. Not a compiler trick
and not a micro-optimisation: it attacks the part neither of us could vectorise
before, because we were both optimising a single hash instead of the search.

### Why it is still the same answer

Changing the batch width must not change *which* nonce wins. It cannot: the
candidates are scanned in increasing order, four per batch, and the first hit in a
batch is the smallest. `vbatch` checks this at three difficulties against a
sequential scan and against `node:crypto`, and the fetcher's end-to-end test puts
it through a real server:

```
  start          1 -> nonce          1  digest matches node
  start       1234 -> nonce       1234  digest matches node
  difficulty  8: batch nonce 49, sequential 49  identical
  difficulty 12: batch nonce 350, sequential 350  identical
  difficulty 16: batch nonce 79656, sequential 79656  identical
```

All five solvers — including this one — are accepted by the live Anubis server.

### What it costs to run

The 4-wide kernel is not just faster, it is smaller: **0.13 MiB of linear memory**
against **1.06 MiB** for the module Anubis ships, and 347 ns of CPU per hash against
597 ns. `node tools/bench-client-resources.mjs` measures both from the module's own
memory and the process's CPU time; the table is in
[`../SPEED.md`](../SPEED.md#what-uses-less-ram-and-what-uses-less-cpu).

## The true test: a real Anubis server, four solvers

`wasm/live-test.mjs` stands up against a running Anubis, solves each challenge
four ways, and counts a solve only if `pass-challenge` is accepted **and** the
follow-up request returns the protected page. Server: **Anubis v1.28.3 built from
source**, one rule (`user_agent_regex: ".+"`, `sha256`, difficulty 12) in front of
a page containing `PAST THE WALL`. Public hosts serve `metarefresh` at difficulty
1, which measures nothing.

6 runs each, all 24 accepted, warmed before timing:

| solver | median | rate | accepted |
|---|---:|---:|---|
| official Anubis `sha256.wasm` (simd128) | 5.1 ms | **689 kH/s** | 6/6 |
| **our `sha256_pow.wasm`** (C, clang `-O3`) | 16.8 ms | **589 kH/s** | 6/6 |
| `crypto.createHash` (native, sync) | 15.3 ms | 157 kH/s | 6/6 |
| `crypto.subtle.digest` (native, async) | 339 ms | 19 kH/s | 6/6 |

**The native JS API is the slow path.** These hashes are 36 bytes, so per-call
overhead dwarfs the hash: `createHash` ~6 µs per call, `subtle.digest` ~50 µs with
a promise per nonce, against a ~0.7 µs hash. A wasm module keeps the whole scan
loop inside wasm and pays neither.

## Why the official module is faster, from its source

Not a compiler trick. `sha2 0.11.1` ships a dedicated backend:

```
sha2-0.11.1/src/sha256/wasm32_simd128.rs     195 lines
    #[target_feature(enable = "simd128")]
    pub(super) fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]])
```

It is the Intel SHA-NI-style structure ported to v128: the message schedule lives
in **four vector registers** (`ms: [u64x2; 4]`), fifteen of the rounds are computed
four at a time in vector form, and four scalar `sha_round`s run per vector step.
`lib.rs` then just calls `Sha256::new()` / `update` / `finalize` — no cleverness at
the algorithm level at all, and no midstate reuse.

Anubis's `wasm/scripts/build_wasm.sh` builds both `baseline/` and `simd128/`
modules; the client uses the simd128 one. So the comparison is *my scalar schedule
against their vectorised schedule*, which is exactly the shape of the gap.

Fixed work, warm (`node bench-sha256.mjs`), three runs of increasing size:

| module | diff 22 | diff 21 | **diff 23, best of 3** |
|---|---:|---:|---:|
| official `simd128` | 1692 | 1623 | **1702 kH/s** |
| **ours (scalar schedule)** | 1530 | 1923 | **1434 kH/s** |
| official `baseline` | 1280 | 1308 | **1308 kH/s** |

The largest run is the trustworthy one: **ours 0.84× of their SIMD build**, and
**1.10× their baseline build**. The smaller runs scattered between 0.90× and
1.18×, which is the machine noise floor — but every run agrees on the ordering
that matters: the vectorised schedule beats a scalar one in *either* codebase
(their baseline is 0.77× their own simd128), and our scalar kernel sits between
the two.

So: **Anubis is faster by about 16 %, and the source says exactly why.** Not the
algorithm, not the compiler flags — `sha2` ships a v128 SHA-256 backend and
Anubis builds with `-C target-feature=+simd128`. Porting
`wasm32_simd128.rs` to C with `<wasm_simd128.h>` is the work that would close it,
and it is the documented next step rather than something claimed as done.

### A measurement correction

An earlier version of this file reported **0.66×** here, and that was wrong. The
live test timed each solve cold: at difficulty 12 a solve is a few thousand hashes,
which lands entirely inside the wasm tier-up window, so the number was mostly
measuring how much code each module has to compile. Warming both modules first
moved it to 0.85×, and measuring fixed work instead of one lucky solve put it at
0.90×. Same lesson as the Argon2 correction earlier: a tight, cold, short-burst
measurement is a measurement of the compiler, not the kernel.

### What changed in the fetcher

`tools/anubis_fetch.js` now solves `sha256` with this kernel instead of
`crypto.createHash`, which is the measured 3.7× (157 → 589 kH/s) and the reason to
have written it. It falls back to `createHash` when the module is not built.

### What is left in the SHA-256 kernel

Two things were worth checking, and both were checked rather than assumed:

**The difficulty test in vector form.** The first version unpacked all 32 digest
words (32 `extract_lane` + 128 byte stores) to test ~23 bits. For difficulty ≤ 32
the whole test is one unsigned compare and one bitmask — `h[0] < 2^(32 − d)` per
lane — and only a passing lane needs unpacking. Interleaved A/B, 4 rounds, median:

| build | rate |
|---|---:|
| vector difficulty test | 3367 kH/s |
| unpack every batch | 3258 kH/s |

**+3 %, which is inside the noise.** Kept because it is simpler in the common path
and never worse — not because it is a win.

**Batching wider than four.** Ours runs at 2.3× the scalar rate for 4× the width,
so ~40 % of the theoretical gain is lost to overhead. That is where the next
improvement would come from — eight lanes across two `i32x4` groups — but the
kernel already holds 8 state vectors plus a 16-vector schedule live, and wasm has
no register allocator to lean on: more lanes means more spills, not linearly more
throughput. Untested, and honestly a coin flip.

## Can the same trick make HashX faster? No — and here is why

The SHA-256 win came from batching four nonces in `i32x4` lanes. It is tempting to
do the same to HashX, and wabt's opcode table says the arithmetic is available:
`i64x2.mul` exists (I claimed otherwise earlier — that was wrong), and
`i64x2.extmul_low_i32x4_u` covers the 32×32 half of a 64-bit multiply, so the 160
`MUL_R` and the 32 mulhi instructions could take two lanes each.

It still cannot be batched, because **HashX's control flow is data-dependent**.
Unlike SHA-256's branch-free compression, the program takes a backward jump when
`(result & imm) == 0`, and `result` is the last `mulh` output — a different value
for every nonce. Two nonces would diverge at the first branch and need different
instruction streams.

From this program's 16 branch points:

```
branch 145: imm 0x01002011   0 trailing zeros   P(taken) ~ 1/1
branch 305: imm 0x00008601   0 trailing zeros   P(taken) ~ 1/1
branch  49: imm 0x80400402   1 trailing zero    P(taken) ~ 1/2
branch  81: imm 0x04084002   1 trailing zero    P(taken) ~ 1/2
branch 113: imm 0x00280024   2 trailing zeros  P(taken) ~ 1/4
...
expected branches taken per hash: 1.0  (capped: `be` clears after the first)
```

Two of them fire with probability 1/2 each, so a jump happens in most hashes. Lanes
would spend their time diverging, not hashing. A predicate-masked variant that
falls back to scalar per diverged lane is *possible*, but the fallback would fire
often enough to eat the gain — and it is the kind of complexity that produces a
wrong digest once in a million hashes.

### What does work: independent workers

Each nonce is a separate search, so the parallel budget goes to workers, exactly as
for Argon2id. `node bench-hashx-threads.mjs`:

| workers | aggregate | per worker |
|---|---:|---:|
| 1 | 2.73 M hashes/s | 2.73 M |
| 2 | 4.22 M hashes/s (1.54×) | 2.11 M |
| 4 | 6.45 M hashes/s (2.36×) | 1.61 M |

Sub-linear rather than the 3.75× Argon2 saw: HashX is pure integer compute, so
workers contend for the same cores instead of for memory. Still, 6.45 M hashes/s
against the official module's ~0.33 M is **~19× aggregate**, and 6–8× on one
thread.

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
| `argon2_fill_fast.c` | the fill loop that ships: each round kept in registers |
| `hashx_jit.mjs` | the runtime HashX compiler: derives the program, emits the wasm bytes |
| `verify-jit.mjs` | its cross-check against the interpreter and the committed module |
| `argon2id_pow.wasm` | the whole Argon2id hash in Anubis's ABI, 13.9 KB |
| `hashx_pow.wasm` | HashX interpreter in Anubis's ABI, 14.9 KB |
| `verify-a2i-module.mjs`, `verify-hashx-module.mjs` | whole-module checks against the official ones |

`make` regenerates the WAT and the wasm; `make bench`, `make serve`, `make clean`.
`make verify-module` is the one to run after touching a shipped kernel: it hands
ten random challenges to the official Anubis modules and requires them to accept
our answers, so a silently miscompiled build fails the test instead of shipping.
(That happened once: `-ffreestanding` on the Argon2id module made every 1 KiB
block copy a byte-at-a-time `memcpy` call and cost 2.0x. See
[../SPEED.md](../SPEED.md#argon2id-in-wasm-why-it-was-2x-slower-and-what-fixed-it).)

## Limits, stated plainly

- **`hashx_jit.wasm` is one challenge's program.** The committed module is
  generated for the challenge in `beyond/vectors/hx_vectors.hex` case 0, so it is
  a demo artifact and a reference point. The general path is `hashx_jit.mjs`,
  which does the same derivation and emission in JavaScript for whatever
  challenge the server sends, with no toolchain. That is what `betterAnusbis`
  runs, and it is 7x the interpreter; the committed wat/wasm pair is what a
  build-time generator produces for a fixed challenge.
- **The official numbers are this machine, one Node version** (26.13). Wasm
  engines differ a lot; wasmtime or V8 in a browser will not give identical
  numbers. The ratio is the interesting quantity, not the absolute rate.
- **A 512-instruction program is not 512 wasm instructions.** About 32 mulhi
  operations expand to a dozen instructions each, and the straight-line body is
  ~5,000 wasm instructions. The 10 KB module is what that costs.
- **This does not make Anubis solvable faster for a *server*.** Its value is on
  the client: less CPU for the same proof of work, which is exactly where a
  browser verifier spends its time.
