# Bindings for libanubis_solver

The C library is the one implementation; these are thin bindings to it.

| language | path | how it reaches the library |
|---|---|---|
| Python | `anubis_solver.py` (repo root) | `ctypes` |
| Node | `bindings/node/` | `koffi` FFI — no native addon, no build step |
| Go | `bindings/go/` | `cgo` — links libanubis_solver.so directly |

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
