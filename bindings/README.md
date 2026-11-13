# Bindings for libanubis_solver

The C library is the one implementation; these are thin bindings to it.

| language | path | how it reaches the library |
|---|---|---|
| Python | `anubis_solver.py` (repo root) | `ctypes` |
| Node | `bindings/node/` | `koffi` FFI — no native addon, no build step |
| Go | `bindings/go/` | `cgo` — links libanubis_solver.so directly |
| C# | `bindings/csharp/` | `[LibraryImport]` P/Invoke — no NuGet, no shim |
| R | `bindings/r/` | a small `.Call` shim, because `.C()` cannot return a code |

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
