# SHA-256, Argon2id and HashX, in pure Scratch

`scratch/Scratch 3 Emulator.sb3` is a Scratch VM written in Scratch: 15,277
blocks emulating the thing that is running it. This directory is the same genre
applied to the proof-of-work kernels: the hashes Anubis asks a browser to
compute, written the same way, as blocks, with no JavaScript anywhere.

"Pure" means: no `js` escaping, no extension, no compiled-mode-only trick. Every
line the interpreter runs is a Scratch block you can see in the editor.

SHA-256 is done and verified. Argon2id and HashX are next; they share the
builder and the two techniques below.

```
scratch/
├── gen_sha256.py            generator: SHA-256 -> .sb3
├── tools/
│   ├── sb3.py               minimal, dependency-free .sb3 writer
│   ├── run_sb3.mjs          headless run in the official scratch-vm
│   ├── profile_sb3.mjs      count every primitive the interpreter executes
│   ├── verify_sha256.py     test vectors against hashlib
│   └── bench_ops.py         per-statement cost of the interpreter
├── build/sha256.sb3         the project (23 KiB, open it in TurboWarp)
└── Makefile
```

## Open it

Load `build/sha256.sb3` in [TurboWarp](https://turbowarp.org) (or scratch.mit.edu),
press the green flag. It hashes the byte list `MSG`, which starts as `abc`, and
puts the hex digest in `OUT_HEX`. `DONE` flips to 1 when it finishes. Edit `MSG`
to hash something else; the flag can be pressed repeatedly.

## The two things Scratch does not have

### 1. Bitwise operators

Scratch gives you `+ - * / mod` and `floor`. That is all. There is no `xor`,
`and`, `<<`, `>>>`.

A 32-bit word fits in a double exactly (every integer below 2^53 does), so most
of SHA-256 is plain arithmetic, and every one of these is *exact* — no rounding,
because the divisors are powers of two:

| operation | in Scratch |
|---|---|
| `a + b mod 2^32` | `(a + b) mod 4294967296` |
| `rotr(x, n)` | `floor(x / 2^n) + (x mod 2^n) * 2^(32-n)` |
| `shr(x, n)` | `floor(x / 2^n)` |
| `not x` | `4294967295 - x` |

xor/and/or have no arithmetic closed form, so they become table lookups: split
the word into limbs, use the limb pair as an index into a 2^L x 2^L table, add
the results back with the right place value.

```
xor32(a,b) = sum over k of   XOR_T[((a >> Lk) mod 2^L) * 2^L + ((b >> Lk) mod 2^L)] * 2^(Lk)
```

L = 4 needs a 256-entry table and 8 lookups per word. L = 8 needs 65,536 entries
and 4 lookups. The tables are generated, so their size costs nothing but file
size: `AND_T` and `OR_T` exist because Ch is `(e and f) or ((not e) and g)` and
Maj is `(a and b) or (c and (a or b))`.

### 2. No return values

`procedures_call` is a *stack* block. Scratch custom blocks cannot return
anything, so putting one in an input slot runs it and yields `undefined`. This
was verified against the real VM before the generator was written: the callee
ran, its global held 42, the receiving variable was `undefined`.

So the port has no functions. A call is a statement that leaves its result in
the global `IRES`, and any expression containing a call is flattened into
statements with temporaries. That flattening is the whole reason this is a
generator (`Fn` in `gen_sha256.py`) instead of a hand-drawn project.

## What it measures

Run against the official `scratch-vm` (the interpreter under TurboWarp and
scratch.mit.edu), counted by `tools/profile_sb3.mjs`:

| | 4-bit limbs | 8-bit limbs |
|---|---|---|
| table entries | 3 x 256 | 3 x 65,536 |
| blocks in project | 1,343 | 1,175 |
| `project.json` | 277 KiB | 1,289 KiB |
| `.sb3` on disk | 24 KiB | 62 KiB |
| block executions / 64-byte block | 117,523 | 67,347 |
| cost per block execution | 0.66 us | 0.84 us |
| throughput, 4 KiB message | 3.0 KB/s | 5.1 KB/s |
| one 64-byte block, steady state | ~21 ms | ~12 ms |
| 3-byte message end to end | ~52 ms | ~41 ms |

Every statement costs about a microsecond (`tools/bench_ops.py`: 1.0-1.3 us for
a variable store or a list read, ~2 us extra for a custom block call). That is
the number that decides the design. Two consequences, both applied:

- **Bake the constants.** `rotr`, `shr` and `add32` are not procedures at all;
  they are nested reporters with the powers of two already folded in. A rotate
  costs no call and no temporary.
- **Unroll the limb loop.** Each limb is one `change IRES by item(...)*2^(Lk)`
  statement. Doing it with variables and a loop instead costs 25 statements per
  xor instead of 5, which is what the first version did.

The 3-byte case is slower than one block of steady-state work because V8 is
still warming up: 41 ms for `abc` versus 12 ms for each block of a 4 KiB run.

## Test it

The project is checked against `hashlib` on 20 vectors, including the lengths
that break padding (55, 56, 57, 63, 64, 65, 119, 120), a multi-block message,
all 256 byte values, and random data:

```bash
python3 gen_sha256.py                       # -> build/sha256.sb3
node tools/run_sb3.mjs build/sha256.sb3 '[97,98,99]'
python3 tools/verify_sha256.py              # 20 vectors vs hashlib
python3 tools/verify_sha256.py --sb3 build/sha256_b8.sb3
python3 tools/bench_ops.py                  # where the microseconds go
```

`run_sb3.mjs` needs `scratch-vm` and `jszip`:

```bash
cd /tmp && npm i scratch-vm jszip
NODE_PATH=/tmp/node_modules node scratch/tools/verify_sha256.py
```

## Honest limits

- Verified in **scratch-vm**, the reference interpreter, which also validates the
  project against its own `sb3_definitions.json` schema. It has **not** been
  opened in the TurboWarp or scratch.mit.edu GUI editors; the blocks are the same
  blocks either way, but that check is not done.
- TurboWarp's **compiled mode** (a JS transpiler for block stacks) will be much
  faster and is not what these numbers measure. These are interpreter numbers,
  the floor.
- The 65,536-entry lists make the editor's list monitor unusable. Functional,
  not pleasant. Use the 4-bit build if you want to read the project.
- Only SHA-256 so far. Argon2id needs a 32x32 -> 64-bit multiply, which Scratch's
  doubles cannot do directly (limbs, again); HashX is an interpreter, so that
  port is a different and larger problem.
