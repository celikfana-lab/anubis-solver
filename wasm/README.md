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

## Argon2id: the same trick, and why it does not work

HashX's win came from removing an **interpreter**. Argon2id has no interpreter to
remove — it is a tight numeric kernel over 38,912 blocks of memory — so the
question worth asking is whether hand-written WAT beats an optimising compiler at
a numeric kernel. It does not.

`tools/gen_argon2_wat.py` emits the reference `fill_block` (8 column rounds + 8
row rounds of BlaMka, fully unrolled, 16 words per round in wasm locals).
`wasm/verify-a2i.mjs` checks it against vectors produced by **compiling the
vendored C reference** — bit-exact on all three trials:

```
  ok   trial 0 (with_xor=0): 128/128 words identical to the C reference
  ok   trial 1 (with_xor=1): 128/128 words identical to the C reference
  ok   trial 2 (with_xor=1): 128/128 words identical to the C reference
```

`node wasm/bench-a2i.mjs` then measures it (m=19456 KiB, t=2 → 38,912 blocks per
hash; H0 and H' are under 0.1% of the work, so a per-block rate converts directly):

| | per block | whole hash | |
|---|---:|---:|---|
| WAT `fill_block` (scalar) | 7.99 µs | 3.2 hashes/s equivalent | |
| official baseline | 2.25 µs | ~11 hashes/s | **3.5× faster** |
| official simd128 | 1.79 µs | ~14 hashes/s | **4.5× faster** |

**So the answer is no.** A scalar hand-emitted port loses to LLVM by 3.5–4.5×: the
kernel is ~3,000 64-bit multiply-heavy instructions per block, and the Rust build
gets SIMD (`simd128`, two 64-bit lanes per operation), better scheduling and
fewer round trips to memory. Hand-written WAT has none of those.

That is worth stating plainly, because it is where the HashX result came from: the
19.9× and the 6× were **interpreter removal**, not hand-optimisation. Where there
is no interpreter, there is nothing to win — and a person writing wasm by hand is
not going to out-schedule a compiler.

What *would* help Argon2id in wasm is the same thing that helps it anywhere: use
the `simd128` module, keep the block in registers across all 16 rounds, and let a
vectorising compiler do it. That is exactly what the official module already does.

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
