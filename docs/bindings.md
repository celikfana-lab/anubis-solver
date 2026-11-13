# Node and Go bindings

Both bindings are thin wrappers over `libanubis_solver.so`, the same library the
Python package and the C examples use. Nothing is reimplemented: they call
`anubis_solve_*`, `anubis_verify_*` and the introspection functions from
[anubis-solver.h](../include/anubis-solver.h).

| | Node | Go | C# | R | Java |
|---|---|---|---|---|---|
| directory | `node/` | `go/` | `csharp/` | `r/` | `java/` |
| mechanism | koffi FFI | cgo | `[LibraryImport]` | `.Call` shim | JNI shim |
| test | `node test.js` (11) | `go test ./...` (10) | `dotnet run` (13) | `R -f test.R` (14) | `make test` (15) |
| errors | `SolverError.code` | `errors.Is` | `SolverException.Code` | `anubis_*` conditions | `SolverException.code()` |
| lookup | `ANUBIS_LIB` | rpath | resolver + `ANUBIS_LIB` | `ANUBIS_LIB` | `java.library.path` |

All paths are under `bindings/`.

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
