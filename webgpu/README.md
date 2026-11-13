# webgpu/ — HashX on WebGPU

Can HashX run on the GPU from inside a browser, and is it faster than the
WebAssembly module? This directory is the experiment, and the answer so far is a
split verdict:

- **it compiles, runs and is bit-exact** — on SwiftShader (Chrome's CPU
  WebGPU backend) every digest matches `wasm/hashx_jit.wasm`;
- **it is much faster** — 11.5–47 M hashes/s on the Intel Iris Xe against
  2.6–3.2 M/s for the wasm module in the same browser, i.e. **4–15×**;
- **but the digests are wrong on that GPU**, so the speed number is not yet a
  HashX result. It is the *cost of the same instructions*, which is the number
  that decides whether this is worth finishing.

That is the honest state. Details, including what is ruled out, are below.

## Running it

```bash
./run.sh                # native Vulkan adapter (Intel Iris Xe here)
./run.sh swiftshader    # CPU backend: correct, and slow
```

`run.sh` serves the repository, starts headless Chrome with the flags that give a
**real** Vulkan adapter, and prints the harness's result object. Those flags are
not optional: without `--enable-features=Vulkan --use-angle=vulkan
--use-vulkan=native`, Chrome silently hands out SwiftShader, and a benchmark on a
CPU emulator is a benchmark of nothing. `run.sh` prints which adapter it got.

```
adapter: { vendor: 'intel', arch: 'gen-12lp' }        <- Iris Xe, real
adapter: { vendor: 'google', arch: 'swiftshader' }    <- CPU fallback
```

## How it works

`tools/gen_hashx_wgsl.py` compiles the challenge's 512-instruction program to a
WGSL compute shader, one invocation per nonce:

```
python3 tools/gen_hashx_wgsl.py --out webgpu/hashx.wgsl
```

WGSL has no 64-bit integers, so a `u64` is a `vec2<u32>` and the multiplies are
built from 16-bit limbs. The u64 helpers are transcribed from
`tools/gen_hashx_wat.py`, **not** from `src/vulkan/hashx.comp`: that kernel's
`umulh64` does not compute the high half of a 128-bit product (it drops `a1*b1`
and the high halves of the cross terms, then shifts the rest by 32). The WAT
generator is the one that is verified against the C engine and against Anubis's
own module, so its semantics are the ones used here.

The program is emitted as segments joined by a dispatch loop rather than as
nested `loop`s with `continue`; see the comment in `vm()` for why.

The digest is checked inside the shader: leading zero bits are counted, and hits
are recorded through an `atomicAdd` into a small results buffer, so a dispatch
costs one readback rather than one per hash.

## Tested backends

Three machines, four configurations, and the digests do not agree:

| backend | digests | hashes/s | note |
|---|---|---|---|
| Intel Iris Xe, Vulkan (`gen-12lp`) | **wrong** | 11.5 M – 47.2 M | the fast one, and the broken one |
| SwiftShader, this laptop | exact | — | CPU emulator |
| SwiftShader, Xeon 56c / 64 GB box | **exact 8/8** | 0.89 M | CPU emulator; wasm there does 5.99 M |
| AMD FirePro V3800 | exact | — | ran on SwiftShader: that card has no Vulkan to run on |

The fourth row is worth explaining, because it is the one people ask about. The
FirePro V3800 is a 2010 Terascale 2 part with 512 MB: Mesa drives it with the
legacy `r600` Gallium driver for OpenGL, `radv` starts at GCN so it never sees
Vulkan, and Mesa's OpenCL support skipped it too (`/etc/OpenCL/vendors` had no
AMD ICD at all). Chrome therefore hands WebGPU to SwiftShader there. So the
shader *works* on that machine and the GPU cannot be used by WebGPU at all — no
Vulkan, no OpenCL, OpenGL only.

Two independent software backends produce exact digests. That is the strongest
argument that the WGSL is right and the Intel Vulkan compiler is the outlier, not
the other way round.

## The correctness story, on the failing backend

| check | Intel gen-12lp | SwiftShader |
|---|---|---|
| shader compiles | yes | yes |
| PRF (r0..r7 after SipHash-2-4) | **exact** | exact |
| u64 helpers, 32 random operand pairs | **exact** | exact |
| first 113 VM instructions (dumped) | **exact** | exact |
| whole program, nonce 0 | **wrong** | **exact** |
| 8 nonces at difficulty 0 | wrong | **8/8 exact** |

The wrong digest on Intel is `17ca683d…` where the reference says `36572054…`, and
it is *identical* across three completely different control-flow encodings:

1. nested `loop` per branch target with `continue` to jump back,
2. the dispatch loop used now (`if (pc == k) { segment }`),
3. a build with **all branch handling removed** (`--no-branch`).

A numbers-only change of the control flow would not survive that; the wrong value
is stable, so it is the same wrong arithmetic, not a wrong jump. In isolation the
helpers are correct on this GPU, the PRF is correct, and the first 113
instructions are correct. Something further into the program is miscompiled, and
the divergence appears only in the **high halves of two registers** (`r2.hi`,
`r7.hi`), both of which are produced by the emulated 64x64 multiply.

I could not reduce it further. What that needs is either a disassembly from the
Intel Vulkan compiler (not accessible from here) or a second GPU to test on. The
`webgpu/probe-*.html` pages are the isolated tests I used — they are kept so the
next person does not have to rewrite them:

| page | shows |
|---|---|
| `probe-cmp.html` | `(result & imm) == 0` on chosen operands |
| `probe-mul.html` | `mul64`/`umulh64` against 32 random operand pairs (needs `probe-mul.wgsl`) |
| `digest.html` | the digest for nonce 0, one dispatch |
| `dump.html` | r0..r7 (+`result`) after a chosen instruction, via `--dump-after` |

Debug flags on the generator: `--dump-after K`, `--truncate K`, `--no-branch`.

## The numbers

Same browser, same process, same program, same 1,048,576 nonces per dispatch,
difficulty 255 (nothing qualifies, so this is pure hashing):

| engine | hashes/s | per hash | |
|---|---:|---:|---|
| WebGPU on Iris Xe | 11.5 M – 47.2 M | 85 – 22 ns | indicative only (wrong digests) |
| WebAssembly (this repo) | 2.6 – 3.2 M | 380 – 310 ns | verified |

The spread on the GPU side is two runs; this laptop's clocks move a long way
between runs, and GPU clocks less visibly still. The wasm figure agrees with
`wasm/verify-jit.mjs`.

Those two orders of magnitude of headroom are plausible: an integrated GPU has
~96 execution units and the compiled kernel has no interpreter, no per-hash call
and no tier-up in the measured window. It is also why the correctness bug is
worth fixing rather than shelving.

## What is not done

- **No validated GPU number.** The number above is real work, but the program it
  computes does not match HashX on this backend.
- **One GPU, one browser, one driver.** The failure is backend-specific: two
  software backends are exact, so it may well work on another vendor's Vulkan, on
  macOS via Metal, or on a newer Dawn. That is still the most useful experiment
  to run next — the FirePro V3800 turned out to be unable to run it at all
  (no Vulkan), so it settled correctness and not speed.
- **Not wired into anything.** No gate serves this; `betterAnusbis` and the
  extension still use wasm and native code.
- **The 6 ms compile is per challenge**, same as the wasm JIT, so a threshold
  applies here too.

## Why this is not in the main documentation yet

`README.md`, `SPEED.md` and `web/benchmarks.html` only carry numbers that survive
their tests. This one does not yet, so it is reported here and nowhere else.
