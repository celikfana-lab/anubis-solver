# Python library

```python
import anubis_solver as a
```

The module finds `libanubis_solver.so` next to itself, builds it with `make`
if it is missing, or uses `ANUBIS_SOLVER_LIB` / an explicit `lib_path`.

## Challenges

```python
challenge = a.parse_challenge(html)      # AnubisChallenge | None
challenge = a.AnubisChallenge.from_payload(payload)   # from the JSON dict
```

`AnubisChallenge` fields:

| field | meaning |
|---|---|
| `id` | challenge id (the `id` query parameter) |
| `random_data` | the challenge string that is hashed |
| `algorithm` | `fast`, `slow`, `sha256`, `wasm-sha256`, `argon2id`, `hashx`, `meatrider`, `tensor`, `tensor-v` |
| `difficulty` | leading zero nibbles (fast/slow) or bits (the rest) |
| `method` | HTTP method the site expects (`POST` by default) |
| `raw` | the original payload |

## Solving

```python
solver = a.AnubisSolver()                 # threads = all physical cores
solver = a.AnubisSolver(threads=8, budget_ms=500)
solution = solver.solve(challenge)
```

`AnubisSolver(lib_path=None, threads=None, budget_ms=0.0)`.

`Solution` fields: `nonce`, `response` (hex string), `elapsed_ms`,
`algorithm`, `difficulty`.

`budget_ms` is a soft time limit for the search; `0` means unlimited (the
solver keeps scanning until it finds a nonce or `max_nonce` is exhausted).

Introspection:

```python
solver.version        # "1.0.0"
solver.gpu            # "CUDA: Tesla T4 x2" | "Vulkan: ..." | None
solver.affinity       # human-readable CPU affinity ("P-cores", "off", ...)
solver.batch_width    # SHA-256 lanes per batch (16/8/4/1)
solver.supported("argon2id")   # True
solver.verify(challenge, nonce)  # re-check a nonce
solver.sha256_hex(b"abc")        # native SHA-256
solver.easter()       # the sentence the chip answers with; None on a .so
                      # older than 2.0.2, which has no `easter` symbol
solver.backends()             # ["cpu", "vulkan", "opencl"] - usable right now
solver.backends_compiled()    # everything built into the .so
print(solver.backend_report())  # the table the CLI prints with --backends
solver.force_nvidia_boost_max()  # lock NVIDIA GPUs at max clock (root); 0 = ok
solver.nvidia_clock_mhz()        # current SM clock, -1 when there is no GPU
solver.nvidia_boost_info()       # why the last attempt succeeded or failed
```

`solver.supported()` accepts the names in `AnubisSolver.ALGORITHMS`
(`fast`, `slow`, `sha256`, `wasm-sha256`, `argon2id`, `hashx`, `meatrider`, `tensor`,
`tensor-v`).

### `tensor-v`

`tensor-v` is the sampled-proof tensor tier: the solver commits to the GEMM
with a Merkle root, the gate returns the blocks it wants opened, and the client
sends those blocks and their proofs to `audit-tensor`. The HTTP client runs
both steps for you, so `AnubisClient.get()` and `pass_challenge()` work without
extra code; the cookie is set by the second response.

The solver-level API exposes the two halves for callers that drive the
protocol themselves:

```python
solution = solver.solve_tensor_v(challenge)      # nonce 0, response = root
witness  = solver.tensor_v_witness(challenge, blocks, positions)
```

The sample (`blocks`, `positions`) comes from the gate's JSON response to the
first request; it cannot be computed without the gate's signing secret, which
is why this algorithm is the one exception to `solve()` returning something
self-contained.

## Errors

- `SolverError` — library missing/failed to load, invalid arguments.
- `ChallengeError` — malformed challenge payload.
- `UnsupportedAlgorithm` — the page uses an algorithm this build does not know.

Return codes from the C layer: `ANUBIS_OK` (0), `ANUBIS_ERR_ARG` (1),
`ANUBIS_ERR_UNSOLVED` (2), `ANUBIS_ERR_INTERNAL` (3).

## Sessions and the HTTP client

`make_session(impersonate=None, **kwargs)` returns a `requests.Session`, or a
`curl_cffi` session that impersonates a browser when `impersonate="chrome"`
(also `"firefox"`, `"safari"`, …). Use it for sites that check TLS/HTTP2
fingerprints.

`AnubisClient` wraps a session and does the whole flow for you:

```python
with a.AnubisClient("http://127.0.0.1:8923", solver=solver) as client:
    r = client.get("/dashboard")
    print(r.status_code)

    solution = client.pass_challenge("/dashboard")   # solve only, no fetch
```

`AnubisClient(base_url, solver=None, session=None, max_attempts=...)`; methods
`get(path="/", **kwargs)`, `pass_challenge(page_url="/")`, `close()`, and the
context-manager protocol.

## Examples

- [`examples/basic.py`](../examples/basic.py) — fetch a page.
- [`examples/solver.py`](../examples/solver.py) — solve offline from HTML.
- [`examples/gpu.py`](../examples/gpu.py) — show the detected GPU backend.
- [`examples/impersonate.py`](../examples/impersonate.py) — browser
  impersonation with `curl_cffi`.
