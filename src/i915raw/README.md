# Raw i915

Three programs that drive the Intel GPU through `/dev/dri/renderD128` and DRM
ioctls only — no Mesa, no libOpenCL, no Level Zero, no libdrm wrappers, not
even `drmIoctl()`. Every interaction with the driver is one `ioctl` in this
directory.

Why: on this laptop Mesa's ANV computes the wrong HashX digests
([`webgpu/ANV-BUG.md`](../../webgpu/ANV-BUG.md)), and any userspace stack can
carry bugs that are invisible from above. This is the bottom of the stack, so
there is nothing left under it to be wrong.

| file | what it is |
|---|---|
| `i915_probe.c` | device identity, engine list, GEM objects, submission benchmarks, and a store instruction executed by the GPU as proof |
| `i915_dump.c` | `LD_PRELOAD` shim that records what a real driver (NEO/IGC) submits: every execbuffer, every buffer, the batch bytes |
| `i915_replay.c` | recreates a recorded dispatch at the same virtual addresses and submits it through raw i915; verified digest, timed |
| `verify_solve.py` | recomputes every hit with `hashlib` and checks the difficulty |
| `capture.sh` | capture + replay + solve + verify, end to end |

## The number

Alder Lake-P GT2 (Iris Xe, 96 EU), kernel 6.17.0-41-generic, i915, 27 Nov 2026:

| measurement | result |
|---|---|
| sequential submit + wait | **~330 µs** per submission (launch, execute, fence wakeup) |
| pipelined (submit N, wait for all) | **~30 µs** per submission, ~30–38 k/s |
| command stream (262,142 `MI_NOOP`) | **~140–210 M commands/s**, best of 3 |
| **raw replay of the SHA-256 dispatch** | **16.0–17.4 ms per 4,194,304 nonces = 241–262 M hashes/s** |
| digest, computed by our own submission | `f2bf82167d41fe1701711273d69d05f17793d6adb5bc30d290b448d1f5585f71` (matches `hashlib`) |

For scale, on the same GPU and the same kernel:

| path | sha256 hashes/s |
|---|---|
| WebGPU (ANV compiles WGSL) | 70.6 M |
| Intel OpenCL (NEO + IGC) | 195–247 M |
| **raw i915 (this directory)** | **241–262 M** |

The raw path is not faster because we outsmarted IGC: it runs the same machine
code. It is at least as fast, and it is ours.

And it **solves**. Patching the dispatch's argument block (below) turns the
replay into a search: any nonce range, any difficulty, hits read back and
checked. Every digest below was recomputed with `hashlib` and verified to carry
at least `difficulty` leading zero bits:

```
dispatch 0: 71 hits in 16.235 ms (258.4 M hashes/s)
hits 71
hit 1969 00009a6e7e9ec626094375229f3b38b64822e2f49bc95ec73009d1720f9a42ec
...
8/8 hits verified (total reported: 71, difficulty 16)
```

| solve test | result |
|---|---|
| scan 0 .. 4,194,303 at difficulty 16 | **71 hits, 258–279 M hashes/s**, 8/8 verified |
| same, base 4,194,304 (a different range) | 74 hits, all in the new range, 8/8 verified |
| difficulty 22 | 1 hit per dispatch (4 Mi / 2^22), verified |
| difficulty 24 | ~0.25 hits per dispatch — no hit in 8 dispatches is expected |

The nonce is **little-endian** at the front of the block (`w[0] = bswap(nonce)`),
so verification is `sha256(nonce.to_bytes(4, "little") + tail)`. A big-endian
check calls every hit wrong; that cost an hour.

## What the uapi makes you learn the hard way

All of these return `EINVAL` with no explanation:

1. **`batch_len` must be a multiple of 8.** A 4-byte batch (one `MI_BATCH_BUFFER_END`)
   and a 12-byte batch are rejected; 8 and 16 are fine.
   (`i915_gem_check_execbuffer()`: `(batch_start_offset | batch_len) & 0x7`.)
2. **The batch must not be the only object.** One object in `buffers_ptr` is
   rejected for anything but a tiny batch. The list is `[data, batch]`; i915
   takes the batch from the last entry.
3. **Relocations are rejected** on this kernel (`relocation_count > 0` →
   `EINVAL`) even though the uapi documents them. Use `I915_EXEC_NO_RELOC` and
   write addresses yourself. The kernel tells you the address it gave an
   object in `exec_object2.offset`; that is enough.
4. **Pinning above 4 GiB needs `EXEC_OBJECT_SUPPORTS_48B_ADDRESS`.** Without
   it, `EXEC_OBJECT_PINNED | offset >= 4 GiB` is `EINVAL` — the code checks
   `(start + size + 4095) >> 32` and needs the flag set.
5. **`batch_start_offset` is also 8-byte aligned.**
6. **The completion fence is `exec.rsvd2 >> 32`** when `I915_EXEC_FENCE_OUT` is
   set; it is a `sync_file` fd, so `poll()` it. No `SET_DOMAIN` dance needed.
7. A private address space is `VM_CREATE` (256 TiB) then
   `CONTEXT_CREATE_EXT` with `I915_CONTEXT_CREATE_EXT_SETPARAM` /
   `I915_CONTEXT_PARAM_VM` and **`param.size = 0`** (a nonzero size is
   `EINVAL`), then `exec.rsvd1 = ctx_id`.

`i915_probe --pin 0x40000000` pins the data object at a chosen address and
stores to it; that is the smallest complete proof that the address you wrote
is the address the GPU used.

## What Intel's own dispatch looks like

A GPGPU dispatch is not an ioctl. It is a batch of commands, and i915 has no
API for any of them. `i915_dump.c` recorded one from the vendor stack
(`tools/xe-sha256-opencl.c` under `LD_PRELOAD`), and this is its shape.

One submission carries 11–12 objects; the last one is the batch. The first
submission writes the pipeline state and then jumps into the dispatch buffer:

```
dw 0  69049312   PIPELINE_SELECT, media bit set
dw 1  61050000   vendor prologue (not decoded)
dw 3  7a000004   PIPE_CONTROL (6 dwords)
dw 9  70000007   MEDIA_VFE_STATE (9 dwords), max threads 0x1033
dw18  11020001   MI_LOAD_REGISTER_IMM, register 0x2580 = 0x00060002
dw21  7a000204   PIPE_CONTROL (6 dwords)
dw27  61010014   STATE_BASE_ADDRESS (22 dwords): general/dynamic/instruction bases
dw49  7a000004   PIPE_CONTROL (6 dwords)
dw55  18800101   MI_BATCH_BUFFER_START | 48-bit address
dw56  0x...      -> the dispatch buffer (64 KiB, one 128-byte block per dispatch)
```

Each dispatch block (30 dwords used, 128-byte slot):

```
+0x00  70040000   GPGPU_OBJECT
+0x08  70020002   MEDIA_INTERFACE_DESCRIPTOR_LOAD (4 dwords), address 0, size 32
+0x10  7105000d   GPGPU_WALKER (15 dwords)
         +0x04  interface descriptor offset 0
         +0x08  indirect data length 0xc80 (bytes of payload)
         +0x0c  indirect data address, an offset from the indirect object base
         +0x10  thread width 16, SIMD32 (dw4 bits 5:0 and 31:30)
         +0x1c  thread group count X (8192 for the throughput dispatch)
+0x54  70040000   GPGPU_OBJECT
+0x5c  7a000004   PIPE_CONTROL with a post-sync store to the results buffer
+0x70  05000000   MI_BATCH_BUFFER_END
```

Object roles, inferred from their contents:

| VA | size | role |
|---|---|---|
| `0xffff8001fffea000` | 24 KiB | kernel text (decodes as gen12 SASS; "kernel end" at 20,544 bytes) |
| `0x7e31bc37b000` | 4 KiB | kernel argument block; contains the message words big-endian |
| `0x7e31bc379000` | 4 KiB | **results**: hit count, hit nonce, eight digest words |
| `0x7e31bc381000` | 4 KiB | a second status buffer (atomic hit counter) |
| `0x7e31bc368000` | 64 KiB | dispatch batch: one 128-byte block per dispatch |
| `0x7e31bc37f000` | 64 KiB | prologue batch |
| `0xffff8001fffd9000` | 64 KiB | heap holding the per-dispatch argument structures |
| `0x7e31bafef000` | 64 KiB | surface states (128-byte entries; buffer pointer at +0x60) |
| `0x7e31bb295000` | 64 KiB | a second state heap (points at the instruction base) |
| `0xffffd556aa7e0000` | 64 KiB | userptr scratch |
| `0x7e31a8200000` | 6 MiB | per-workgroup status array |
| `0xffff8001fffe9000` | 4 KiB | NEO's private/scratch state |

Addresses change per run; they are assigned by the driver to the context.

## The replay

`i915_replay.c` creates every object at the address the capture shows
(`EXEC_OBJECT_PINNED | EXEC_OBJECT_SUPPORTS_48B_ADDRESS`), fills it from the
dump, and submits the capture's submissions in order, in a private VM. Nothing
in the batch has to be patched: nothing moved.

That is why the digest comes out right — the GPU runs Intel's machine code with
Intel's state, but the submission path is this program. It is a **replay**, not
a dispatcher: the nonce range, work-group count, kernel and arguments are
whatever the capture contains. What it proves is that the whole compute path
runs on raw i915 from userspace.

```sh
make -C src/i915raw              # build into ../../build
bash src/i915raw/capture.sh      # needs intel-opencl-icd for the capture
```

`capture.sh` prints the per-dispatch time (16.0–17.4 ms for 4,194,304 nonces)
and the digest.

## What Mesa says (the reference we should have read first)

Mesa ships this whole path twice: `src/gallium/drivers/iris/` for the render
engine, and — much closer to what we need — **`src/intel/executor/`**, a
standalone compute executor that builds a dispatch by hand and submits it with
`DRM_IOCTL_I915_GEM_EXECBUFFER2`, no ANV, no Gallium. Its `emit_execute()`
writes exactly this:

```
PIPE_CONTROL, PIPELINE_SELECT(GPGPU, mask 3), PIPE_CONTROL,
STATE_BASE_ADDRESS (general/instruction base 0, surface/dynamic base = a state BO),
3DSTATE_BINDING_TABLE_POOL_ALLOC, 3DSTATE_STATE_INVALIDATE,
MEDIA_VFE_STATE (URB entries 2, max threads, CURBE allocation),
PIPE_CONTROL,
INTERFACE_DESCRIPTOR_DATA (32 bytes, in the state BO),
MEDIA_INTERFACE_DESCRIPTOR_LOAD (offset of that IDD),
MEDIA_CURBE_LOAD (one GRF per hardware thread, thread id in dword 0),
GPGPU_WALKER (SIMD size, thread width, X dimension, masks),
MEDIA_STATE_FLUSH, PIPE_CONTROL, MI_BATCH_BUFFER_END
```

and the field layouts are in `src/intel/genxml/` — exact, machine-readable, and
inherited across generations (`gen120.xml` imports `gen110.xml`, which imports
`gen90.xml`, which imports `gen80.xml`; the file that actually defines
`GPGPU_WALKER` for this part is **gen80.xml**, length 15).

`decode_capture.py` in this directory uses those XML files to decode a capture
with field names. It corrects three things the earlier dword-guessing got
wrong:

```
GPGPU_WALKER  (15 dwords: 7105000d 00000000 00000c80 fffdd080 8000000f ...)
   dw0  DWord Length                           13
   dw2  Indirect Data Length                   0xc80
   dw3  Indirect Data Start Address            0x3fff742   -> IndirectObjectBase + 0xfffdd080
   dw4  Thread Width Counter Maximum           15          (16 threads per group)
   dw4  SIMD Size                              2           (SIMD32)
   dw7  Thread Group ID X Dimension            0x2000      (8192)
```

8192 groups x 16 threads x 32 lanes = **4,194,304**, exactly the dispatch's
nonce count. The `0xc80` that looked like a thread count is the indirect-data
length; the X dimension is `dw7`.

```
STATE_BASE_ADDRESS (22 dwords: 61010014 ...)
   dw1  General State Base Address             0x7b6b6d7ff000
   dw4  Surface State Base Address             0x7b6b75075000
   dw6  Dynamic State Base Address             0x7b6b75086000
   dw8  Indirect Object Base Address           0xffff800100000000
   dw10 Instruction Base Address               0x800100000000
   dw16 Bindless Surface State Base Address    0x7b6b75075000

MEDIA_INTERFACE_DESCRIPTOR_LOAD (4 dwords: 70020002 00000000 00000020 00000180)
   dw3  Interface Descriptor Data Start Address 0x180       (offset from dynamic base)
```

The IDD lives at `DynamicStateBase + 0x180`, and its `Kernel Start Pointer`
(`0xfffea000`) is an offset from the **Indirect Object Base Address**, not an
absolute address: `0xffff800100000000 + 0xfffea000` is the kernel buffer. The
payload (the kernel's cross-thread constants, difficulty/count included) is at
`IndirectObjectBase + 0xfffdd080`, which is the walker's indirect-data address.

That is the same trick the `.so` would use: one address space (the indirect
object base), the kernel at one offset, the payload at another, and the
interface descriptor pointing at both.

### What this changes for the `.so`

The state builder no longer has to be reverse-engineered. `gen_pack_header.py`
from Mesa turns `gen120.xml` into C pack functions
(`GFX12_STATE_BASE_ADDRESS_pack`, `GFX12_GPGPU_WALKER_pack`,
`GFX12_INTERFACE_DESCRIPTOR_DATA_pack`, ...), and `make gen12-pack` here does
that into `build/gen12_pack.h`. With those, the library can emit the executor's
sequence itself — Mesa is a *reference at build time*, not a runtime
dependency, which is exactly the "talk to the kernel driver directly" shape.

The kernel is still the open piece: IGC's binary is message-length specific
(one 48-byte block), and our own listing still needs its `send.dc1` store.

## Solving: the argument block

The walker points at a payload, and the payload has the kernel arguments at
fixed offsets. There is one payload per dispatch; a 64 KiB heap object holds
them all, spaced `0xc80` bytes apart after the first two (0x0000, 0x0200 then
0x0e80, 0x1b00, ...).

```
payload + 0x30  message buffer pointer   (u64)
payload + 0x38  results buffer pointer   (u64)
payload + 0x40  base                     (u32)
payload + 0x44  difficulty               (u32)
payload + 0x48  count                    (u32)
```

`--solve` finds the chosen submission's walker, resolves its 32-bit payload
address against our objects (the high half comes from the state base), patches
base/difficulty/count, clears the results buffer and dispatches. `hits` and the
first eight `nonce digest` pairs are read straight out of the results buffer;
`verify_solve.py` recomputes them.

```sh
./build/i915-replay --dump /tmp/i915dump --upto 8 --solve 16 --bench 1 \
    | python3 src/i915raw/verify_solve.py --difficulty 16
```

Expected time to one hit at 265 M hashes/s: 4 ms at difficulty 20, 63 ms at 24,
1 s at 28, 16 s at 32. Anubis caps difficulty at 64.

What is still not ours: the kernel. The payload is Intel's IGC output; what we
own is the submission and the scan parameters. Replacing the kernel with
`src/intel/xe/intelXe_sha256.xe` needs a result store (`send.dc1` plus one
surface state) — that is the next commit, and then the comparison that
`src/intel/xe/README.md` could not make becomes possible.

## Reproducing

```sh
make -C src/i915raw all
./build/i915-probe --bench 300 --pipe 512 --storm 262142
#  -> identity, engines, submission costs, command-stream rate, store proof

# capture + replay
bash src/i915raw/capture.sh

# or step by step
LD_PRELOAD=./build/i915-dump.so /tmp/anubis-i915-clrun
./build/i915-replay --dump /tmp/i915dump --upto 8 --bench 12
./build/i915-replay --dump /tmp/i915dump --upto 8 --solve 16 --bench 1

# verify the hits the GPU reported
./build/i915-replay --dump /tmp/i915dump --upto 8 --solve 16 --bench 1 \
    | python3 src/i915raw/verify_solve.py --difficulty 16
```

Requirements: `drm/i915_drm.h` (libdrm-dev) to build; membership of the
`render` group to open the render node; `intel-opencl-icd` only for producing
a capture.

## Not implemented

- A parameterised dispatcher (see above).
- The compute-only engine (`CCS`): the probe lists it, but submissions go to
  the default (render) engine. `I915_CONTEXT_PARAM_ENGINES` is the way.
- GuC/HuC identity, power management and frequency reporting: `/sys` and
  debugfs need root, which this repository does not ask for.
