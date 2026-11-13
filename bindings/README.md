# Bindings for libanubis_solver

The C library is the one implementation; these are thin bindings to it.

| language | path | how it reaches the library |
|---|---|---|
| Python | `anubis_solver.py` (repo root) | `ctypes` |
| Node | `bindings/node/` | `koffi` FFI — no native addon, no build step |
| Go | `bindings/go/` | `cgo` — links libanubis_solver.so directly |
| C# | `bindings/csharp/` | `[LibraryImport]` P/Invoke — no NuGet, no shim |
| R | `bindings/r/` | a small `.Call` shim, because `.C()` cannot return a code |
| Java | `bindings/java/` | a JNI shim; no jars, no preview flags |
| Assembly | `bindings/asm/` | `.include` macros for x86-64 SysV and AArch64 |
| Rust | `bindings/rust/` | hand-written FFI, no bindgen, no dependencies |

All of them answer the same four questions and expose the same five algorithm
families. Build the library first, from the repository root:

```bash
make
```

That produces `./libanubis_solver.so` (and a `.dylib` on macOS). The bindings look
there by default.

## Node

```bash
cd bindings/node
npm install          # koffi, which ships prebuilt binaries
node test.js         # 11 checks against the real library
```

```js
const anubis = require('./anubis');

anubis.info();                                  // {version, gpu, threads, ...}

// fast / slow: leading zero nibbles
const r = anubis.solveNibbles('demo-challenge', 3);
console.log(r.nonce, r.hash, r.ms);

// sha256 / argon2id / hashx: leading zero bits, hex challenge
const h = anubis.solve('hashx', '00112233445566778899aabbccddeeff', 4);
console.log(anubis.verify('hashx', '00112233445566778899aabbccddeeff', h.nonce, 4).ok);
```

`ANUBIS_LIB=/path/to/libanubis_solver.so` overrides where the library is found.
Failures throw `SolverError` with `.code` set to one of `ERR_ARG`,
`ERR_UNSOLVED`, `ERR_INTERNAL`.

Two details that cost real debugging time and are worth knowing if you write more
FFI against this library:

- **Pass C strings as JS strings, not Buffers.** koffi NUL-terminates a string but
  not a Buffer, and every `const char *` here is a C string. A Buffer makes
  `hex_decode` in the core read past the end and return `ERR_ARG`. Buffers are
  only correct where a length is passed too (`sha256Hex`).
- **Out-parameters must be koffi allocations.** A plain JavaScript array or
  typed array is not written back through an `_Out_` pointer; koffi copies it.
  Everything in `anubis.js` that receives a value uses `koffi.alloc` and decodes
  afterwards.

## Go

```bash
cd bindings/go
go test ./...        # exercises every family against the real library
```

```go
import anubis "github.com/celikfana-lab/anubis-solver/bindings/go"

r, err := anubis.SolveNibbles("demo-challenge", 3, anubis.Opts{})
if err != nil {
    log.Fatal(err)
}
ok, hash, err := anubis.VerifyNibbles("demo-challenge", r.Nonce, 3)
```

The rpath is baked in as `${SRCDIR}/../..`, so a program built against this
package finds the library next to the repository with no `LD_LIBRARY_PATH`. For a
library somewhere else:

```bash
CGO_LDFLAGS="-L/path/to/lib -Wl,-rpath,/path/to/lib" go build
```

Errors are sentinel values, so `errors.Is(err, anubis.ErrUnsolved)` works.
`Opts{Threads, MaxNonce, BudgetMS}` is the zero-value-is-default knob block.

### One behaviour worth knowing

The `sha256`/`argon2id`/`hashx` families hash the raw challenge bytes followed by
a 4-byte nonce. The core chooses the nonce byte order **from the challenge's last
byte**: little-endian when it is `>= 0x80`, big-endian otherwise. The Go test
mirrors that rule to recompute a digest independently; if you are implementing a
verifier yourself, this is the part to get right.

## C#

```bash
cd bindings/csharp
dotnet build AnubisSolver.csproj     # the library, no NuGet packages
dotnet run --project tests/Tests.csproj   # 13 checks against the real library
```

```csharp
using AnubisSolver;

var r = Anubis.SolveNibbles("demo-challenge", 3);
Console.WriteLine($"{r.Nonce} {r.Hash} {r.Millis}ms");

var h = Anubis.Solve("hashx", hexChallenge, 4);
var (ok, hash) = Anubis.VerifyHashx(hexChallenge, (uint)h.Nonce, 4);
```

The library is found by an `AssemblyLoadContext` resolver that walks up from the
build output to the repository root; `ANUBIS_LIB` overrides it. Failures throw
`SolverException` with `.Code`, `.IsUnsolved` and `.IsArgument`.

Two things to know if you write your own C# against this library:

- **`[LibraryImport]` requires `partial` and unsafe blocks.** The containing class
  must be `partial` and the project needs `<AllowUnsafeBlocks>true</AllowUnsafeBlocks>`.
- **A `string` parameter means UTF-8.** `anubis_sha256_hex` takes a byte pointer
  plus a length, so a string-only binding cannot hash binary data at all - the
  digest cross-check in the tests failed until `Sha256Hex(byte[])` and
  `Sha256Midstate(byte[])` overloads existed.

## R

```bash
cd bindings/r
make                          # builds anubisR.so via `R CMD SHLIB`
R --vanilla -f test.R         # 14 checks against the real library
```

If R was unpacked without the `R CMD` wrapper, compile directly:
`make direct R_INCLUDE=.../R/include R_LIB=.../R/lib R_LIB_LDFLAGS="-L.../R/lib -lR"`.

```r
source("anubis.R")

anubis_info()                                   # version, gpu, threads, ...
anubis_solve_nibbles("demo-challenge", 3)       # list(nonce, hash, ms)
anubis_solve_hashx(hexChallenge, 4)
anubis_verify_hashx(hexChallenge, nonce, 4)$ok
```

Errors are real R conditions, so `tryCatch` can tell them apart: a nonce or time
budget running out is `anubis_unsolved`, a malformed hex challenge is
`anubis_argument_error`, and both inherit from `anubis_error`.

**Why a shim and not plain `.C()`:** R's base `.C()` interface discards the C
function's return value, and every function in `anubis-solver.h` reports success
through exactly that. `src/anubis_r.c` is therefore a ~300-line `.Call` shim that
returns the status alongside the outputs; `anubis.R` turns a non-zero status into
a condition. Without it there is no way to see a return code at all.

R has no native 64-bit integer, so nonces come back as doubles - exact to 2^53,
far beyond anything a search will reach.

## Java

```bash
cd bindings/java
make            # javac -h generates the JNI header, then cc builds libanubis_jni.so
make test       # 15 checks against the real library
```

```java
import io.github.celikfana.anubis.Anubis;

var r = Anubis.solveNibbles("demo-challenge", 3);
System.out.println(r.nonce() + " " + r.hash() + " " + r.millis() + "ms");

var h = Anubis.solve("hashx", hexChallenge, 4);
System.out.println(Anubis.verifyHashx(hexChallenge, h.nonce(), 4).ok());
```

Records for `Result`, `Verdict`, `Info` and `Options`; `SolverException` carries
`.code()`, `.isUnsolved()` and `.isArgument()`.

**Why JNI and not the FFM API:** `java.lang.foreign` is still a *preview* feature
on JDK 21, so using it would require `--enable-preview` on both `javac` and
`java`, and the classes would not run on another JDK. JNI has no flags, no
dependencies and works from Java 8 to 25. The shim is ~300 lines.

**The JNI trap:** a hand-declared native function whose signature does not match
the Java declaration does not fail to link - it crashes or silently corrupts
arguments at the call. `make` therefore runs `javac -h` to generate
`io_github_celikfana_anubis_Anubis.h` and the C file includes it, so every
signature is checked by the C compiler. Do not remove that include.

The Java classes need the shim on `java.library.path`
(`-Djava.library.path=bindings/java/build`); the shim itself finds
`libanubis_solver.so` through its rpath, so no `LD_LIBRARY_PATH` is needed.

## Assembly

```bash
cd bindings/asm
make run        # x86-64, native: solves, verifies, prints the digest
make run-arm    # cross-builds an aarch64 library, runs the aarch64 demo under qemu
```

```asm
    .include "anubis.inc"

    ANUBIS_SOLVE_NIBBLES challenge, 3, 0, -1, snonce, shex, sms
    // %eax = 0 for a hit; snonce/shex/sms now hold the result
    test %eax, %eax
    jnz  .Lsolve_failed
```

`anubis.inc` gives you a macro per call, and the file's comments are the register
map. The map is the whole difficulty:

- **x86-64:** `budget_ms` is a double, so it takes `%xmm0` and consumes *none* of
  `%r8`/`%r9`. `out_nonce` is therefore `%r8`, `out_hex` is `%r9`, and `out_ms` is
  the only stack argument. Writing `out_nonce` into `%r9` assembles, links, and
  writes garbage.
- **AArch64:** same split with `d0`, so `out_nonce` is `x4`, `out_hex` is `x5`,
  `out_ms` is `x6` — and nothing goes on the stack. Note also that `#` is an
  immediate prefix there, not a comment: `#`-comments inside a macro body get
  glued onto the instruction. Use `//`.

Both demos are verified: x86-64 natively, AArch64 under `qemu-aarch64` against a
cross-built library, and they return the *same nonce and hash*, so the two are
checked against each other. `bindings/asm/README.md` also documents how to
cross-build the library (the root Makefile keys its kernel choice off `uname -m`,
so a cross build must pass `ASM_SRC=src/cpu/neon.s` and argon2's `ref.c`).

## Rust

```bash
cd bindings/rust
cargo run --example solve      # the example
cargo test                     # 9 integration tests + the doctest
```

```rust
use anubis_solver as anubis;

let r = anubis::solve_nibbles("demo-challenge", 3, anubis::Options::default())?;
println!("nonce {} -> {} in {:.1} ms", r.nonce, r.hash, r.millis);

let (ok, digest) = anubis::verify_nibbles("demo-challenge", r.nonce, 3)?;
```

The crate is a thin, hand-written FFI layer over `include/anubis-solver.h`:
**no `bindgen`, no build-time code generation, no dependencies at all**. It wraps
introspection, both SHA-256 helpers, all five algorithm families, per-family
verification and a `solve(Algorithm, ..)` dispatcher.

Errors are a real enum — `Error::Unsolved`, `Error::Argument`, `Error::Internal`,
`Error::Unknown(i32)`, `Error::InteriorNul` — implementing `std::error::Error`, so
`?` works and an exhausted budget is a value rather than a panic.

`build.rs` points the linker at the repository root and bakes in an rpath, so
`cargo test` needs no `LD_LIBRARY_PATH`. To link a library elsewhere:

```bash
ANUBIS_LIB_DIR=/opt/anubis/lib cargo build
```

The crate uses `license-file = "../../LICENSE"` rather than a `license` field,
because an SPDX expression cannot express MIT + attribution.
