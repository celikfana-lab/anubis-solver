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
| `algorithm` | `fast`, `slow`, `sha256`, `wasm-sha256`, `argon2id`, `hashx` |
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
```

`solver.supported()` accepts the names in `AnubisSolver.ALGORITHMS`
(`fast`, `slow`, `sha256`, `wasm-sha256`, `argon2id`, `hashx`).

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
