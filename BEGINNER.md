# Beginner's guide

Anubis is a proof-of-work gate that many sites put in front of their pages.
`anubis-solver` solves that proof of work for you: a small C core (SHA-256,
Argon2id and HashX, with optional GPU backends) and a Python library that
wraps it and handles the HTTP dance.

This page gets you from zero to a working request in a few minutes. Deeper
material lives in [`docs/`](docs/index.md).

---

## 1. Build it

You need a C compiler and `make`. Python 3.9+ for the library.

```bash
git clone https://github.com/celikfana-lab/anubis-solver.git
cd anubis-solver
make                 # builds ./libanubis_solver.so
python3 -c "import anubis_solver; print(anubis_solver.__version__)"
```

`make` detects what your machine offers:

| found | gets built |
|---|---|
| x86-64 | AVX2 + SHA-NI kernels (assembler) |
| AVX-512F/BW | AVX-512 kernel |
| AArch64 | NEON + SHA-2 kernel |
| `nvcc` | CUDA backends (SHA-256, Argon2id, HashX) |
| `level_zero/ze_api.h` | Level Zero backends |
| `vulkan/vulkan.h` | Vulkan backends |

Missing pieces are skipped silently — the library still builds and uses the
CPU.

Optional Python extras:

```bash
pip install requests            # plain HTTP client
pip install curl_cffi           # browser TLS/HTTP2 impersonation (optional)
pip install argon2-cffi         # only needed to run the test suite
```

---

## 2. Quick start: solve a challenge from HTML

If you already have the HTML of an Anubis-protected page:

```python
import anubis_solver as a

html = open("page.html").read()          # any saved Anubis challenge page
challenge = a.parse_challenge(html)
print(challenge.algorithm, challenge.difficulty)

solver = a.AnubisSolver()                # threads = all physical cores
solution = solver.solve(challenge)

print(solution.nonce, solution.response, solution.elapsed_ms, "ms")
print(solver.verify(challenge, solution.nonce))   # True
```

`Solution.response` is the hex string the site expects back.

---

## 3. Quick start: fetch a protected page

`AnubisClient` loads the page, spots the challenge, solves it, submits the
response and retries — all transparently:

```python
from anubis_solver import AnubisClient

with AnubisClient("http://127.0.0.1:8923") as client:
    r = client.get("/")
    print(r.status_code, len(r.text))
```

If the site also checks your TLS fingerprint, use `make_session("chrome")`
(installs `curl_cffi`) or pass `impersonate="chrome"` to the client.

There is a ready-made script:

```bash
python3 examples/basic.py http://127.0.0.1:8923
```

And a CLI:

```bash
python3 anubis_solver.py http://127.0.0.1:8923
python3 anubis_solver.py https://example.com --threads 8 --impersonate chrome
```

Run `python3 anubis_solver.py --help` for all flags
(`--threads`, `--lib`, `--timeout`, `--impersonate`, `--cve`,
`--allow-remote-cve`, `--affinity`). Full details: [`docs/cli.md`](docs/cli.md).

---

## 4. Enable the GPU (optional)

The CPU is the default. GPU backends are opt-in and always re-verify their
results on the CPU:

```bash
ANUBIS_GPU_ARGON2=1 python3 examples/basic.py https://site.example   # Argon2id: CUDA → L0 → Vulkan
ANUBIS_GPU_HASHX=1 python3 examples/basic.py https://site.example    # HashX: CUDA
```

Check what was detected:

```python
import anubis_solver as a
print(a.AnubisSolver().gpu)     # e.g. "CUDA: Tesla T4 x2", or None
```

The Level Zero and Vulkan HashX kernels are correct but slower than the CPU
on an Iris Xe, so they have their own flags (`ANUBIS_L0_HASHX=1`,
`ANUBIS_VULKAN_HASHX=1`). Everything about backends, env vars and measured
throughput is in [`docs/gpu.md`](docs/gpu.md) and [`SPEED.md`](SPEED.md).

---

## 5. Use it from C or C++

There is a public header: **`include/anubis-solver.h`**. It works for both
languages (`extern "C"` is included), so C++ users can `#include` it directly.

```c
#include <stdio.h>
#include <stdint.h>
#include <anubis-solver.h>

int main(void) {
    uint64_t nonce = 0;
    char hex[65] = {0};
    double ms = 0.0;

    int rc = anubis_solve_nibbles("your-challenge-string", 4, 0, 0, 0.0,
                                  &nonce, hex, &ms);
    if (rc != ANUBIS_OK) {
        fprintf(stderr, "search failed: %d\n", rc);
        return 1;
    }
    printf("nonce %llu -> %s (%.1f ms)\n", (unsigned long long)nonce, hex, ms);
    return 0;
}
```

```bash
cc  demo.c   -Iinclude -L. -lanubis_solver -Wl,-rpath,"$PWD" -o demo && ./demo
c++ demo.cpp -Iinclude -L. -lanubis_solver -Wl,-rpath,"$PWD" -o demo && ./demo
```

Runnable samples live in [`examples/c_demo.c`](examples/c_demo.c) and
[`examples/cpp_demo.cpp`](examples/cpp_demo.cpp). The full function reference,
return codes and the `dlopen` variant are in [`docs/c-api.md`](docs/c-api.md).

## 6. Where to go next

| I want to… | read |
|---|---|
| understand the Python API | [`docs/python.md`](docs/python.md) |
| call it from C | [`docs/c-api.md`](docs/c-api.md) |
| use the command line | [`docs/cli.md`](docs/cli.md) |
| use a GPU | [`docs/gpu.md`](docs/gpu.md) |
| fix a build/runtime problem | [`docs/troubleshooting.md`](docs/troubleshooting.md) |
| hack on the solver | [`docs/development.md`](docs/development.md) |
| see measured speeds | [`SPEED.md`](SPEED.md) |
| check the security policy | [`SECURITY.md`](SECURITY.md) |

---

## 7. A word of caution

This tool exists for testing your own deployments, research, and
interoperability. Only solve challenges for sites you are authorised to test,
and keep in mind that a proof-of-work gate is a resource-protection mechanism.
The CVE-2026-62314 fast path is opt-in and refuses non-loopback targets unless
you explicitly allow them (`--allow-remote-cve`).
