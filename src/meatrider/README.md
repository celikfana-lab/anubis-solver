# `meatrider`: SHA-256d over a real Bitcoin header

The ninth Anubis tier, and the only one whose proof is a Bitcoin proof of work.
The challenge's 32-byte `randomData` seeds a genuine 80-byte block header, the
client's 32-bit nonce lands in the header's nonce field, and `difficulty` is the
leading-zero-bit count every other tier uses — which is exactly Bitcoin's
`hash < 2^(256-difficulty)`:

| header bytes | field | value |
|---|---|---|
| 0..3 | version | `1` |
| 4..35 | prev block | `randomData[0..32)` |
| 36..67 | merkle root | `SHA256("meatrider" \|\| randomData)` |
| 68..71 | time | `1231006505`, the genesis block's timestamp |
| 72..75 | nBits | `compact(2^(256-difficulty))` |
| 76..79 | nonce | the client's nonce, little-endian |

The digest is `reverse(SHA256(SHA256(header)))` — Bitcoin's display order — and
`nBits` is hashed, so a proof is bound to the difficulty it was mined for. The
price ladder turns that work into dollars (see [below](#the-price-ladder)); it is
a label on the hashes, never a payment.

## Where "Bitcoin" lives

Header bytes 0..63 are fixed for a challenge, so their midstate is compressed
once and a hash costs **two** compressions afterwards. Those two compressions are
the whole of a Bitcoin miner's inner loop, and `meatrider.c` owns the only copy
of what they mean:

| function | what it is |
|---|---|
| `meatrider_ctx_init()` | builds the header half, compresses bytes 0..63, caches `tail_block` (block 1 with the nonce bytes still zero) |
| `meatrider_block1()` | `tail[12] \|\| nonce_le \|\| 0x80 \|\| zeros \|\| 0x0280` — 80 bytes, 640 bits |
| `meatrider_block2()` | the first digest big-endian `\|\| 0x80 \|\| zeros \|\| 0x0100` — 32 bytes, 256 bits |
| `meatrider_finish()` | the final state as the byte-reversed digest, i.e. display order |
| `meatrider_meets()` | leading zero bits of a display-order digest, the target test |

Every kernel below agrees with those five functions or it is wrong. The file is
libc-free on purpose: it is also what `wasm/meatrider_pow.wasm` compiles, so the
browser and the server cannot drift.

## The kernels

One hash is two single-block compressions from a shared midstate, so the tier
carries one kernel per optimisation the rest of this repository already has. The
CPU ones are re-emitted from the `sha256` tier's hand-written assembly under
meatrider symbols (`tools/gen_meatrider_s.py`); the rest are written for the
header.

| backend | here / next to its tier | entry point | MHash/s |
|---|---|---|---:|
| portable C | `meatrider.c` | `meatrider_hash()` | 2.14 |
| SHA-NI | `meatrider_shani.s` | `meatrider_block_shani()` | 6.27 |
| AVX2 ×8 | `meatrider_avx2.s` | `meatrider_compress8_avx2()` | 6.91 |
| AVX-512 ×16 | `meatrider_avx512.s` | `meatrider_compress16_avx512()` | 8.69 (Colab Ice Lake; this CPU fuses it off) |
| OpenCL | `meatrider_opencl.cl` | `meatrider_pow()` | 154–168 |
| Vulkan | [`src/vulkan/meatrider_comp.comp`](../vulkan/meatrider_comp.comp) | `main()` | 56–80 |
| CUDA | `meatrider_cuda.cu` | `meatrider_pow_kernel()` | 785.8 (Colab T4) |
| WebGPU | [`webgpu/meatrider.wgsl`](../../webgpu/meatrider.wgsl) | `main()` | 43–62 |
| wasm SIMD128 ×4 | [`wasm/meatrider_simd.c`](../../wasm/meatrider_simd.c) | `anubis_work()` | 4.0–4.5 |
| wasm scalar | [`wasm/meatrider_pow.c`](../../wasm/meatrider_pow.c) | `anubis_work()` | 1.75–1.93 |
| PTX | `meatrider.ptx` | `meatrider_kernel` | 994.7-1199.5 (Colab T4, driver-JITed) |

Numbers are one run on an i7-1260P with an Iris Xe, one thread; the machine
readable copy is [`results/meatrider-backends.json`](../../results/meatrider-backends.json)
and the commands are in [`SPEED.md`](../../SPEED.md#meatrider-two-compressions-and-a-price-tag).
The three kernels that live outside this directory do so because they share a
host and a build with the other tiers' kernels: Vulkan with `vulkan.c`, wasm with
the module Makefile, WebGPU with the pages beside it.

`meatrider_simd.c` is the glue for the CPU kernels — it builds the lanes' block 1
and block 2, calls the compression twice, and reverses the result — and
`meatrider_backend.{c,h}` is the inventory.

## Choosing a kernel

`anubis_solve_meatrider()` asks `meatrider_backend_active()` for the kernel:

- `ANUBIS_MEATRIDER_BACKEND=cpu|shani|avx2|avx512|opencl|vulkan|levelzero|cuda|tpu`
  pins one; an unavailable name falls back instead of failing.
- otherwise the first available accelerator in the library's dispatch order
  (CUDA → Level Zero → Vulkan → OpenCL), else the widest CPU kernel.
- `ANUBIS_MEATRIDER_PTX=1` makes the CUDA slot run the generated PTX instead of
  the `.cu` kernel; the same harness reads 1199.5 against 785.8 MHash/s on a T4.
- an accelerator is only asked above **2^20 hashes** (`ANUBIS_MEATRIDER_MIN_WORK`):
  a dispatch costs about 60 ms, where the AVX2 kernel does a `grain` rung in a
  millisecond. Below the threshold the CPU wins.

`anubis_meatrider_backend_{count,name,available,digest,solve}()` reach a kernel
directly, which is what the tests and `tools/meatrider_backends.py` use.

## Proving they agree

```bash
python3 tests/test_meatrider.py            # the portable reference, 546 checks
python3 tests/test_meatrider_backends.py   # every available kernel vs Python
python3 tools/meatrider_backends.py        # the same, plus the rate table
python3 src/meatrider/test_meatrider_ptx_gpu.py  # the PTX kernel on a real GPU (needs libcuda)
```

`test_meatrider_ptx_gpu.py` builds `meatrider_ptx_loader.c` (driver API only, no
toolkit headers) and lets the driver JIT the checked-in PTX, so the generated
kernel runs on hardware without nvcc or ptxas. It checks a difficulty-0 dispatch
-- where every nonce is a hit, so every reported digest is compared -- then real
searches, and reports nonces dispatched per second.

On a machine with an NVIDIA GPU the same three commands run after `make CUDA=1`;
the [`colab/`](../../colab/meatrider-colab.ipynb) notebook does exactly that on a
Colab T4, because the machine this was written on has no NVIDIA device.

`tests/test_meatrider_backends.py` asks each kernel for the digest of the same
nonces and compares against [`tools/meatrider_ref.py`](../../tools/meatrider_ref.py),
an independent Python implementation of the header — not a second call into C —
and then makes each one mine a rung and re-derives the winning digest. A kernel
that disagrees fails the test; a kernel that agrees but is slow merely shows up
in the table.

## Adding a kernel

1. Implement the two compressions against `meatrider.h`, writing the digest in
   display order.
2. Add it to the inventory in `meatrider_backend.{h,c}` and to the build.
3. Make `tests/test_meatrider_backends.py` pass, and measure it with
   `tools/meatrider_backends.py`.

Nothing else needs changing: the core re-derives every accelerator hit in C
before accepting it, so a wrong kernel costs a dispatch, not a wrong answer.

## The price ladder

`meatrider_price_usd()` prices the work at what an Antminer S21 Pro earns doing
it (234 TH/s at $0.05 per TH-day): `2^difficulty × 0.05 / (1e12 × 86400)`.
`meatrider_asic_seconds()` says how long the ASIC needs, `meatrider_tier_name()`
names the rung the price reached, and `meatrider_difficulty_for_usd()` goes the
other way. The amounts are real and the columns are the same column — the dollar
rung is 2.7 ASIC-hours — but no money moves: the gate publishes an address and a
sum, and the operator confirms the payment by hand. The `pay` fixture the tests
use is [`tests/wallet/`](../../tests/wallet), a testnet key with its private half
published on purpose. **Do not send bitcoin to it.**

## Regenerating

| file | command |
|---|---|
| `meatrider_{avx2,avx512,shani}.s` | `python3 tools/gen_meatrider_s.py` (`--check` fails when stale) |
| `meatrider.ptx` | `python3 tools/gen_meatrider_ptx.py --ilp 1` |
| `src/vulkan/meatrider_comp.spv(.h)` | `GLSLANG=/path/to/glslangValidator tools/build_meatrider_vk.sh` |
| `src/opencl/opencl_kernels.h` (embeds `meatrider_opencl.cl`) | `python3 tools/embed_opencl_kernels.py` |
| `wasm/meatrider_simd.wasm` | `make -C wasm meatrider_simd.wasm` |

## What is deliberately not here

- **Level Zero.** No host, because `libze_intel_gpu` is not installed on the
  machine that wrote this, so the code could not be run once. The shader above is
  the same work that runs through Vulkan there; an L0 host would be
  `levelzero_sha256.c` with this kernel plugged in.
- **TPU.** A PJRT SHA-256 program measures 9.38 MHash/s, so a two-compression
  tier lands near 4.7 — slower than the AVX2 kernel on the same laptop. A kernel
  that loses to the CPU is not worth its maintenance.
- **NEON.** The `sha256` tier has one; this tier's AArch64 path is the portable C
  kernel, which is what a phone would run anyway.
