# Examples

Small, runnable snippets for using `anubis_solver` from your own code. Each
file is standalone; run them from the repository root.

| file | what it shows |
|---|---|
| [`solver.py`](solver.py) | Python: parse a challenge, solve it directly, verify the digest |
| [`basic.py`](basic.py) | Python: solve a challenge and fetch a page with the high-level client |
| [`impersonate.py`](impersonate.py) | Python: browser TLS/JA3 impersonation for fingerprint checks |
| [`gpu.py`](gpu.py) | Python: report the Vulkan device and CPU affinity; solve on the GPU |
| [`c_demo.c`](c_demo.c) | C: call the ABI directly |
| [`cpp_demo.cpp`](cpp_demo.cpp) | C++: the same header, `extern "C"` |
| [`node_demo.js`](node_demo.js) | Node: solve, verify, print the digest |
| [`go_demo/`](go_demo/) | Go: same, through the cgo binding |
| [`csharp_demo.cs`](csharp_demo.cs) | C#: .NET 10 file-based app, no project file needed |
| [`r_demo.R`](r_demo.R) | R: same, and shows `anubis_unsolved` as a catchable condition |
| [`java_demo/`](java_demo/) | Java: same, and shows `SolverException.isUnsolved()` |
| [`asm_min.s`](asm_min.s) | Assembly: the smallest binding — no libc, no startup files |
| [`../bindings/rust/examples/solve.rs`](../bindings/rust/examples/solve.rs) | Rust: the crate's own example (`cargo run --example solve`) |

The four algorithm families all behave the same way in every language: `fast` /
`slow` take a plain challenge string and a nibble difficulty, while `sha256`,
`argon2id` and `hashx` take a hex challenge and a bit difficulty. Every example
solves `fast` and `sha256`, verifies both, and prints the library's own
`sha256("abc")` as an independent cross-check.

## Run everything

```bash
./examples/run_all.sh                 # every language that this machine can run
./examples/run_all.sh node java       # a subset
```

It prints each language's output and a summary, skipping (with a reason) any
language whose toolchain or build output is missing. On a machine with all of
them installed the tail looks like this - note that **every language produces
the same nonce and the same digest**, which is the point:

```
=== node ===
nibbles   nonce 1248  0004e24f5f5e1d089b2fefa534fd51b5e077fbfae1dfdce6246966f20e47149d  0.820 ms
verify    ok  same digest
...
7 passed, 0 failed, 0 skipped
```

## Per language

```bash
python3 examples/solver.py                  # offline, no server needed
python3 examples/basic.py http://127.0.0.1:8923   # needs a local Anubis instance

cd bindings/node && npm install             # once, for koffi
node examples/node_demo.js

cd examples/go_demo && go run .             # needs bindings/go, uses a replace

dotnet run examples/csharp_demo.cs          # .NET 10 file-based app, from the repo root

cd bindings/r && make                       # builds anubisR.so
R --vanilla -f examples/r_demo.R

cd bindings/java && make                    # classes + libanubis_jni.so
javac -cp bindings/java/build/classes -d /tmp/anubis-java examples/java_demo/AnubisDemo.java
java -Djava.library.path=bindings/java/build \
     -cp bindings/java/build/classes:/tmp/anubis-java AnubisDemo

cc -nostdlib -no-pie -o /tmp/asm_min examples/asm_min.s \
   -L. -lanubis_solver -Wl,-rpath,$PWD && /tmp/asm_min
```

Notes:

- `basic.py` and `impersonate.py` need a reachable Anubis-protected URL. Use your
  own instance or a target you are authorized to test.
- `solver.py` builds an in-memory challenge, so it runs offline - that is why it
  is the one the runner uses for Python.
- `gpu.py` only solves when you pass `--solve`, and only a challenge small
  enough to finish quickly.
- The full assembly macro set and a solving demo live in
  [`bindings/asm/`](../bindings/asm/); `asm_min.s` here is the bare minimum to
  prove the ABI.
