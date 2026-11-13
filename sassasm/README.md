# sassasm — a partial SASS assembler, derived rather than documented

NVIDIA does not document SASS. There is no official assembler, and `nvdisasm`
only goes one way. This directory starts one anyway, and the method matters
more than the current coverage:

> `ptxas` compiles PTX to a cubin. The cubin's `.text.<kernel>` section holds
> each instruction as **16 bytes**. `nvdisasm` decodes those same bytes back to
> text. Pairing them gives ground truth: for any instruction, the bytes a real
> compiler chose.

`sassasm/extract.py` builds those pairs; `sassasm/selftest.py` assembles the
same instruction with our encoder and compares byte for byte. A wrong guess
fails loudly instead of looking plausible.

## What works today

| form | coverage | check |
|---|---|---|
| `MOV Rd, imm32` | **16/16 bytes**, 8 immediates | `python3 sassasm/selftest.py` |
| `MOV Rd, c[bank][off]` | **12/12 bytes** (control word excluded) | same |

```
$ python3 sassasm/selftest.py
  ok    MOV R0, 0xdeadbeef                       MOV R0, 0xdeadbeef
  ok    MOV R1, c[0x0][0x28] (12/12 bytes)       MOV R1, c[0x0][0x28]
9 matched, 0 failed
```

```
$ python3 sassasm/sassasm.py 'MOV R0, 0x2a'
027800002a000000000f000000e20f00  // MOV R0, 0x2a
```

## The obstacle that makes this a project, not an afternoon

The last four bytes of every instruction are the **control word**: stall count,
yield, read/write barriers, reuse hint. They are chosen by ptxas's *scheduler*
from the dependency graph, not from the instruction text. Three samples of the
same logical instruction:

```
MOV R0, 0x5              ... 00 e2 0f 00   (dependency-free)
MOV R0, c[0x0][0x28]     ... 00 c6 0f 00   (in one kernel)
MOV R1, c[0x0][0x28]     ... 00 e4 0f 00   (in another)
```

So a byte-exact assembler needs a scheduler too — which is exactly why MaxAs
and its descendants ship one. Until then this emits a semantically valid
instruction with a conservative control word, and the selftest only demands
exactness where the scheduler is not free to choose.

## Field maps for the next families

Measured from real cubins, not yet implemented (see `FIELD_MAPS` in
`sassasm.py`):

| family | first bytes | layout observed |
|---|---|---|
| `IADD3` | `10 72` / `10 7a` | dst +2, src1 +4, src2 +6, src3 +8, flags +10 |
| `LOP3.LUT` | `12 72` / `12 7a` | dst +2, src1 +4, src2 +6, src3 +8, LUT +9, flags +10 |
| `SHF.L/R.U32` | `19 78` | dst +2, shift +4, src1 +8, flags +9 |
| `STG.E` | `86 79` | address from a uniform register pair |
| `EXIT` / `NOP` | `4d 79` / `18 79` | fixed |

`IADD3` is how `add` appears (`add.u32 %r9, %r1, %r2` becomes
`IADD3 R0, R0, R0, RZ`), `LOP3` is `and`/`or`/`xor` with the truth table in the
LUT byte (`0x3c` for xor, `0xfc` for or, `0xc0` for and), and rotations become
`SHF`.

## What reverse engineering the tools did and did not give

`nvdisasm` was opened with REA (Ghidra 12.1.4). Findings:

- the binary is **stripped**: no named procedures, so no `DecodeInstruction` to
  point at;
- **no plaintext mnemonics anywhere** in ~50 MB of loaded memory: `LOP3` does
  not appear as bytes, so mnemonic text is table-generated rather than stored;
- `.data` is a single ~49 MB table region, which is almost certainly where the
  instruction formats live.

That is a real answer and a dead end for the cheap approach: recovering the
format tables from a stripped 50 MB binary is hours of structure work, while
the ptxas/nvdisasm oracle answers the same question in seconds per instruction.
The honest conclusion is that the oracle is the productive route, with REA as
the tool to use when the oracle is ambiguous.

## Using it

```sh
# a toolkit with ptxas + nvdisasm is all it needs (no CUDA headers, no driver)
export SASS_TOOLKIT=/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/nvida
python3 sassasm/selftest.py
python3 sassasm/extract.py kernel.ptx --json
```

The toolkit in `nvida/bin` was taken out of Ubuntu's `nvidia-cuda-toolkit`
12.4.131 without installing it (the package wants a 2.5 GB dev tree and the
driver stack; `dpkg-deb -x` of the toolkit alone is enough for `ptxas`,
`nvdisasm` and `cuobjdump`).

## Status, plainly

Two instruction forms out of the dozens a real kernel needs. This is a working
oracle, a verified encoding method, and two encodings — the beginning of an
assembler, not an assembler. The plan that follows from here:

1. finish the ALU families (`IADD3`, `LOP3`, `SHF`, `IMAD`) with per-form
   selftests;
2. add `LDG`/`STG`/`BRA`, which need the uniform-register and address forms;
3. write a scheduler that assigns the control word, so output becomes
   byte-exact against ptxas;
4. only then is `src/sass/nvidiaT4_sha256.sass` round-trippable: read the
   listing, emit bytes, diff against the original cubin.

Step 4 is the test that would make this real, and it is the reason the work is
worth starting rather than the reason to claim it is done.
