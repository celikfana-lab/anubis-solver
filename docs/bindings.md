# Node and Go bindings

Both bindings are thin wrappers over `libanubis_solver.so`, the same library the
Python package and the C examples use. Nothing is reimplemented: they call
`anubis_solve_*`, `anubis_verify_*` and the introspection functions from
[anubis-solver.h](../include/anubis-solver.h).

| | Node | Go |
|---|---|---|
| directory | `bindings/node/` | `bindings/go/` |
| mechanism | koffi FFI (no native addon, no build step) | cgo |
| test | `npm install && node test.js` (11 checks) | `go test ./...` |
| errors | `SolverError` with `.code` | `errors.Is(err, ErrUnsolved)` and friends |
| library lookup | `ANUBIS_LIB`, else the repo root | rpath `${SRCDIR}/../..`, or `CGO_LDFLAGS` |

Full usage, the API table and the two FFI pitfalls are in
[bindings/README.md](../bindings/README.md).

## Surface

```js
// Node
const anubis = require('./anubis');
anubis.info();                                          // version, gpu, threads, affinity, batchWidth
anubis.sha256Hex('abc');                                // hex digest
anubis.solveNibbles('demo-challenge', 3);               // {nonce, hash, ms}
anubis.solve('hashx', hexChallenge, 4);                 // dispatch by algorithm name
anubis.verify('hashx', hexChallenge, nonce, 4);         // {ok, hash}
```

```go
// Go
i := anubis.GetInfo()                                   // Info{Version, GPU, Threads, ...}
sum, err := anubis.SHA256Hex([]byte("abc"))
r, err := anubis.SolveNibbles("demo-challenge", 3, anubis.Opts{})
ok, hash, err := anubis.VerifyNibbles("demo-challenge", r.Nonce, 3)
```

Every family is covered: `fast`/`slow` (nibbles), `sha256`, `argon2id`, `hashx`
(bits), including the generic `solve`/`Solve` dispatchers that take the algorithm
name Anubis puts in the challenge page.
