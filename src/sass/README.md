# Ask Claude to read the machine code

This is the part of the project that is supposed to need an expert. Reading a
disassembly, working out what each instruction does to which register, then
compiling a second kernel and beating the compiler's own output is the thing
people get paid for. It took one prompt, and the prompt was boring enough that no
safety filter had anything to object to.

`src/cuda/README.md` answers the "hey Claude vibeslop me a CUDA Anubis solver"
criticism. This directory is where that criticism gets worse rather than better:
writing a kernel is the objectionable-sounding part and the easy part. **Reading
the machine code that came out of it, annotating all 2,024 instructions, and then
finding a 1.38-1.77x win inside it** is the part that sounds impossible, and it
happened in the same session, by two agents that have never held a GPU.

## What is in here

| file | what it is |
|---|---|
| `nvidiaT4_sha256.sass` | shipped `cuda_sha256.cu`, `sm_75`, `nvdisasm -c`. 2,024 instructions, 64 registers, 96 B stack frame |
| `nvidiaT4_sha256.annotated.sass` | the same file with **one comment per instruction**, 2,126 lines |
| `nvidiaT4_sha256_opt.sass` | the optimised variant: block assembled in registers, no stack frame, 1,436 instructions per hash |
| `nvidiaT4_sha256_opt.annotated.sass` | the same, annotated line by line, 2,944 lines (ILP 2: 2,872 instructions for two nonces) |
| `nvidiaT4_hashx*.sass`, `nvidiaT4_argon2id*.sass` | the other two kernels, plain dumps, not annotated |
| `kaggle_t4_sass.py` | the job that compiles both kernels, dumps the SASS and A/Bs them on a real T4 |

About 60,500 lines of SASS in total. Toolchain: `nvcc 13.0.88`, `-arch=sm_75 -O3
-cubin`, `nvdisasm -c`.

The annotated files are safe to strip, and checking that is the whole verification
of the annotation's honesty. It is one command, but not the obvious one: a naive
`sed 's|//.*$||' | diff` fails because the annotations carry a comment-only header
and differ in trailing whitespace. Normalise both, and the instruction text is
byte for byte the original:

```bash
strip() { sed 's|//.*$||; s/[[:space:]]*$//' "$1" | sed '/^[[:space:]]*$/d'; }
diff <(strip src/sass/nvidiaT4_sha256.annotated.sass) \
     <(strip src/sass/nvidiaT4_sha256.sass)        # prints nothing
```

2,052 instruction lines, zero differences. The same holds for the `_opt` pair at
2,895 lines. If a future edit to an annotated file breaks that, the annotation has
started changing the machine code it claims to describe.

## The ladder, and what each rung is supposed to cost

| rung | what people assume it requires | what it took |
|---|---|---|
| write the kernel | a CUDA engineer, a month | one prompt, and it was the third attempt |
| notice the kernel is 30% slower than it should be | profiling intuition | nothing, it was in the compiler report |
| read 2,024 instructions of SASS | a week and a copy of the ISA guide | one prompt per file, two files, two agents |
| compile a better kernel | the same engineer, another month | the same prompt, continued |
| A/B them on a real GPU | a GPU, a harness, a weekend | a Kaggle session and `kaggle_t4_sass.py` |
| accept the result | judgement, which is the part that is still yours | see "what it did not do" below |

## The prompt

The entire method. There is nothing else in it.

```
Here is the SASS for one CUDA kernel, produced with nvdisasm -c. Add a comment to
every instruction explaining what it does and which values it reads and writes,
without changing any instruction text. Where a register's role is inferred from
the dataflow rather than stated, say so in the comment. Then tell me which parts
look expensive and how you would write the same kernel with fewer instructions.
```

Then, for the second half:

```
Now write that second version as a separate kernel in the same file, compile both
to cubin with the same flags, and run an A/B in one process on the same GPU with a
correctness check before timing. Report instructions per hash, registers, stack
frame, and throughput for both.
```

That is it. `src/sass/kaggle_t4_sass.py` is the answer to the second prompt,
written out.

## Why no safety filter stops this

Because there is nothing in it to stop. At no point does the request mention a
website, a challenge, a CAPTCHA, a bypass or a victim. It is a compiler course
exercise: explain this disassembly, then write a faster one. A model that refused
it would be refusing to teach compiler optimisation, and it would be right to be
embarrassed about that.

The uncomfortable part is the asymmetry, and it is worth stating plainly rather
than as a joke about filters:

- the defence asks a visitor to prove it can run JavaScript;
- the offence asks a model to explain 2,024 instructions.

Both requests are individually reasonable, and one of them is the *only* one that
looks like it could be misuse. The harm is in the composition, and composition is
not visible to a classifier looking at one message at a time. If you want a
prediction from this repository, it is that filters will keep getting better at
catching "help me bypass", and continue to have nothing to say about "help me
understand", which is where the work actually happens.

## What came out of it

From [`results/t4-sha256-sass-2026-11-13.json`](../../results/t4-sha256-sass-2026-11-13.json),
both kernels timed in one process on a Tesla T4, digests checked word-for-word
against a CPU compression before any timing:

| | shipped | optimised |
|---|---:|---:|
| throughput | 1,348-1,749 MH/s (varies) | **2,390-2,412 MH/s** (repeats) |
| ratio | 1.0x | **1.38-1.77x** |
| stack frame | 96 B of local memory per thread | **0 B** |
| instructions per hash | 2,024 | **1,436** |
| registers | 64 | 40 (ILP 1), 64 for two nonces (ILP 2) |

The win is not a clever algorithm. It is that the shipped kernel builds its
message block in a local `unsigned char[64]`, and 96 bytes of local memory per
thread is a traffic pattern whose cost depends on what else is in L1 and L2 — which
is exactly why the shipped number wanders between 1,348 and 1,749 while the
register-only kernel repeats at 2.4 GH/s. The optimisation is "put the block in
registers", which is the first thing anyone would tell you to do, and it had been
sitting there in a file with no GPU to check it on.

**The negative result is the part worth keeping.** ILP was tried at 1, 2 and 4
nonces per thread: 2,390 / 2,412 / 2,407 MH/s. It does nothing, because the SM is
issue-throughput-bound rather than latency-bound, so the right answer is ILP 1,
which is also the version that uses 40 registers and gets full occupancy. An
agent that only reported wins would have "found" ILP 2 as a 1% improvement and
been wrong about why.

## What it did not do

- **The optimised kernel is not wired into `src/cuda/cuda_sha256.cu`.** Wiring it
  needs a GPU to validate against the C engine, and that is a maintainer's call,
  not an agent's. The SASS is evidence, not a patch.
- **It is sha256-family only.** The shipped kernel branches at runtime between the
  decimal-nonce (`fast`/`slow`) and u32-nonce (`sha256`) families; the optimisation
  applies to the second. The decimal path can be specialised the same way, but the
  digit conversion still costs and it was not measured.
- **Only two files are annotated.** The HashX and Argon2id dumps are raw. Nobody
  has read those 22,000 lines of Argon2id yet, including the machines.

## Do it yourself

```bash
# on a machine with a GPU, or as a Kaggle kernel with a T4 attached:
python3 src/sass/kaggle_t4_sass.py     # compiles, dumps SASS, A/Bs both kernels
nvdisasm -c kernel.cubin               # what the job does for you
```

Then paste the dump into the prompt above. The interesting part is not that it
works, it is how long you spend afterwards checking that the comments are true —
which is the correct way round for a tool that is very good at writing things that
sound right.

---

The CUDA half of this argument is in [`src/cuda/README.md`](../cuda/README.md), and
the claim it is answering is entry 1 of [`HALL_OF_SHAME.md`](../../HALL_OF_SHAME.md).
