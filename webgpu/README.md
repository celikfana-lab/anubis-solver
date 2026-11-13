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

## The page checks before it trusts

`hashx.html` does not assume the GPU is right. Before using it, it hashes eight
known nonces, compares the digests against `wasm/hashx_jit.wasm`, and only uses
the GPU if all eight match:

| backend | self-check | engine used |
|---|---|---|
| Intel Iris Xe | **fails** (wrong digests) | WebAssembly |
| SwiftShader (either machine) | passes | WebGPU |
| no WebGPU adapter | unavailable | WebAssembly |

If the check fails the page says so in a banner, keeps the GPU's number in the
table marked *not used: wrong digests*, and does the latency runs on WebAssembly.
`?engine=wasm` and `?engine=webgpu` force either side, which is how the Intel bug
is reproduced on purpose.

This is the same rule the C engine applies to every GPU hit - "every GPU hit must
be re-verified with the reference before it is accepted" - applied where a browser
can apply it: up front, once, instead of never.

## Running it

```bash
./run.sh                # HashX, native Vulkan adapter (Intel Iris Xe here)
./run.sh swiftshader    # HashX, CPU backend: correct, and slow
./run.sh argon2id       # Argon2id instead of HashX
```

Both pages take `?quick=1` (self-check only), `?engine=wasm` / `?engine=webgpu`
(force a side, so the fallback can be seen on purpose) and both print a
`window.__result` object that `tools/webgpu-run.mjs` returns.

`run.sh` is a convenience wrapper; the canonical command is the direct one below,
which is what the numbers in this file were measured with. Give each run its own
page load — a headless Chrome left over from an interrupted run is the usual
reason a second run appears to hang:

```bash
python3 -m http.server 8092 --bind 127.0.0.1 &
node tools/webgpu-run.mjs "http://127.0.0.1:8092/webgpu/argon2id.html?quick=1" \
  "window.__result" --enable-features=Vulkan --use-angle=vulkan --use-vulkan=native \
  --enable-unsafe-webgpu
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

| backend | HashX digests | Argon2id digests | note |
|---|---|---|---|
| Intel Iris Xe, Vulkan (`gen-12lp`) | **wrong** | **exact (4/4)** | the fast one, and the broken one for HashX only |
| SwiftShader, this laptop | exact | **exact** | CPU emulator |
| SwiftShader, Xeon 56c / 64 GB box | **exact 8/8** | — | CPU emulator; wasm there does 5.99 M |
| SwiftShader, 2x Tesla T4 host (Kaggle) | **exact** | **exact** | Chromium 158, Python 3.13; wasm does 5.25 M there |
| AMD FirePro V3800 | exact | — | ran on SwiftShader: that card has no Vulkan to run on |

Two of those rows are machines whose GPU cannot be reached at all, and the reason
is the same in both cases: a Vulkan-capable driver. The Kaggle row is the clearest
example - two Tesla T4s with CUDA 13.0 work fine (`nvidia-smi` lists them), but the
container has no graphics userspace:

```
/usr/share/vulkan/icd.d/           does not exist
libGLX_nvidia.so*                  not present; only libGLX_mesa.so.0
vulkaninfo --summary               "Found no drivers!", ERROR_INCOMPATIBLE_DRIVER
```

The Vulkan ICD is part of NVIDIA's *graphics* driver, and CUDA-only images install
only the compute half; `nvidia-container-toolkit` mounts the graphics libraries
only when `NVIDIA_DRIVER_CAPABILITIES` includes them, which a Kaggle kernel cannot
change from inside. So a T4 on Kaggle is unreachable from a browser, and the tests
there run on SwiftShader. The same caveat applies to most hosted notebooks.

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

## Argon2id

`webgpu/argon2id.wgsl` is the same idea for Argon2id with Anubis's parameters
(m=19456 KiB, t=2, p=1, 32-byte tag) and it is **bit-exact**: nonce 0 of the
committed challenge produces

```
99d43e7d61c5c6ac76345d531cf754f1a86081c9bcce1c1a8ff7756b7a3425d2
```

which is what `wasm/argon2id_pow.wasm` produces, and the page's self-check passes
**4/4 on the Intel backend** as well as on SwiftShader.

It is also **3.9x slower than the WebAssembly module**, and the reason is
structural rather than a bug:

| engine | ms/hash | hashes/s | concurrency |
|---|---:|---:|---:|
| **WebGPU, Intel Iris Xe** | **277** | **3.6** | 6 |
| WebAssembly, same browser | 71 | 14.1 | 1 |
| native C, one core | 13 | 75 | 1 |

One Argon2id hash needs 19,456 KiB. WebGPU caps a storage binding at
**128 MiB** here (`maxBufferSize` 256 MiB), so at most **six** hashes fit in one
binding, and six hashes is not enough to fill a GPU. The repository's native
Vulkan backend on the *same* GPU reaches 326 h/s at d8 — **8.6x** the CPU — and it
uses **64** concurrent hashes, 1.24 GB of working set, which WebGPU will not give
it. That is the whole gap. Binding several storage buffers (each up to 128 MiB)
would raise the ceiling, but the per-hash cost is dominated by a serial chain of
38,912 block fills, so the honest expectation is that it would still trail the
native path — and it would not beat the wasm module, which needs no such
gymnastics.

Design notes: one workgroup of **8 invocations per hash**, because the block
function is 8 independent BLAKE2 rounds then a `workgroupBarrier()` then 8 more, so
the lanes split each 1 KiB fill. The block lives in `var<workgroup>` (2 KiB), and
the three scratch blocks Argon2id's data-independent addressing needs are appended
to each hash's storage region (19,459 KiB per hash, not 19,456). The host computes
H0, B0, B1 and the final tag in JavaScript — about **6 ms per hash** (4.8 ms init,
1.2 ms tag) against 38,912 GPU block fills, so it is noise but it is not zero and
it is reported separately.

Two things this cost that are worth recording:

- **A serial kernel gets killed by the driver.** One invocation per hash runs
  ~8 s of serial work and the Intel driver returns `VK_ERROR_DEVICE_LOST`. The
  8-invocation version completes.
- **The address input block must be re-initialised per segment.** Not doing so
  changes the first address block of the first segment and every digest after it —
  the classic Argon2id port break, and the one bug found here.

## SHA-256

`webgpu/sha256.wgsl` is the algorithm this was all for. It is compute-bound, needs
no memory, and SHA-256 is entirely 32-bit — so `vec4<u32>` gives four nonces per
invocation in one instruction stream, with none of the u64 emulation the other two
kernels need. It self-checks 8/8 on **both** backends, including nonces 0, 1, 12345
and 0xdeadbeef on a big-endian challenge *and* a little-endian one, because the
nonce's byte order depends on the challenge's last byte and nonce 0 is four zero
bytes either way — a nonce-0-only check cannot catch that bug.

It is also the first thing here that beats the wasm module by a wide margin:

| window | GPU | wasm 4-wide | ratio |
|---|---:|---:|---:|
| quiet machine | **68.0 MH/s** (median of 73.1, 68.0, 68.6, 66.2, 66.8) | 2.03 MH/s | **33x** |
| moderate load | 23-39 MH/s | 0.79-1.15 MH/s | 29-39x |
| desktop busy (load 10-11) | 3.5 MH/s | 0.93 MH/s | 3.7x |
| SwiftShader (CPU backend) | 0.51 MH/s | 2.48 MH/s | 0.2x, i.e. slower |

The spread is the host, not the kernel: an iGPU shares memory bandwidth with the
CPU and needs the CPU to submit work, so a busy desktop hurts it far more than it
hurts the wasm module. The ratio is the result; the absolute figure depends on
whether you are using the machine.

68 MH/s is about half the repository's native Vulkan/Level Zero SHA-256 on the same
iGPU (137 MH/s), which is the right ballpark for a shader compiler with less
freedom than a hand-written SPIR-V kernel, and 17-23x the wasm module using the
repo's own 3.0-3.9 M/s figure.

**Kernel shape matters, and the obvious optimisation loses.** Three shapes A/B'd
interleaved under the same load: the shipped 64-round loop with `w[i & 15]` plus the
K constants in a private array won (11.2/5.5 MH/s in that window); a 4x16 unrolled
form with constant schedule indices — the "obvious" optimisation — was **2-3x
slower** (4.9/3.2), presumably from register pressure and lost occupancy; and
unrolling all 64 rounds ran at 6.1 MH/s and, worse, **kills SwiftShader's JIT**
with `VK_ERROR_DEVICE_LOST`. All three produced the same digests, so this is purely
a performance choice.

Because difficulty 0 never exercises the leading-zero-bit test, the page also does a
real hit test: a 1M-nonce scan at difficulty 16 found 21 hits, and
`anubis_work(16, 5030, 1)` on the wasm module returns exactly nonce 5030 — a
genuine qualifying hit, not merely a matching digest.

## The Intel diagnostic this produced

Argon2id **passes** on the Intel backend, which narrows the HashX failure. Argon2id
exercises add/sub/xor/rotate, `blamka` (which uses the 32x32->64 `mulhi32`) and
the whole fill — but it never performs a full 64x64 multiply, so it never touches
`umulh64`/`mul64`. HashX's divergence was exactly in the high halves of registers
produced by those two functions. So the open Intel bug is now pinned to the 64x64
multiply path (or to HashX's control flow around it), not to the u64 emulation in
general. That is a much smaller haystack than before.

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
