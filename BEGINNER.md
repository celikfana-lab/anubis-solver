# Beginner's guide

Anubis is a proof-of-work gate that many sites put in front of their pages.
`anubis-solver` solves that proof of work for you: a small C core (SHA-256,
Argon2id, HashX and the `tensor` GEMM proof, with optional GPU backends), a
Python library that wraps it and handles the HTTP dance, and — since 2.0.2
`"shaoogle"` — two C services over the same library: an MCP server and an HTTP
JSON API.

This page gets you from zero to a working request in a few minutes. Deeper
material lives in [`docs/`](docs/index.md).

---

## 1. Build it

You need a C compiler and `make`. Python 3.9+ for the library.

```bash
git clone https://github.com/celikfana-lab/anubis-solver.git
cd anubis-solver
make                 # builds ./libanubis_solver.so
python3 -c "import anubis_solver; print(anubis_solver.__version__)"   # 2.50
```

`libanubis_solver.so` is a library, not a program — running it directly just
prints that reminder (with the credit line) and exits 1. Use it from Python
or the C services below.

`make` detects what your machine offers:

| found | gets built |
|---|---|
| x86-64 | AVX2 + SHA-NI kernels (assembler) |
| AVX-512F/BW | AVX-512 kernel |
| AArch64 | NEON + SHA-2 kernel |
| `nvcc` | CUDA backends (SHA-256, Argon2id, HashX) |
| `level_zero/ze_api.h` | Level Zero backends |
| `vulkan/vulkan.h` | Vulkan backends |
| `CL/cl.h` | OpenCL backend |
| always | TPU backend (SHA-256 tier; `libtpu.so` is `dlopen`ed at run time) |

Missing pieces are skipped silently — the library still builds and uses the
CPU. `make universal` is the release build: it asks for every backend, prints
why any was skipped, and writes one `libanubis_solver.so` that uses whatever
the machine has.

Two optional binaries come from the same sources: `make services` builds
`anubis_api` and `anubis_mcp` (section 6).

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

The `tensor` proof works the same way — `parse_challenge` recognises it and
`solve` does one deterministic int8 GEMM — so nothing changes in your code. If
the challenge names an algorithm you did not expect, `challenge.algorithm`
shows it before you solve.

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

## 6. Use the C services (MCP and HTTP API)

Both are plain C on top of the library — no Python, no Node — so you can drop
them anywhere a small binary runs. They share one client
(`src/fetch/anubis_fetch.c`) that fetches the page, reads the `anubis_challenge`
JSON, solves it with the `.so`, submits `pass-challenge` with the cookies the
server set, and re-fetches.

```bash
make services        # ./anubis_api and ./anubis_mcp
```

They need OpenSSL headers on top of the compiler (`libssl-dev` on Debian and
Ubuntu, `openssl-devel` on Fedora).

Keep each binary in the same directory as `libanubis_solver.so`: they link it
with `$ORIGIN` in the runpath.

### The HTTP API

```bash
./anubis_api --listen 127.0.0.1:8088
curl -s localhost:8088/v1/solve -d '{
  "algorithm":"sha256",
  "challenge":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
  "difficulty":12}'
# {"nonce":3356,"response":"0003dcd734e4...d8720956507","elapsed_ms":1.658}
```

`/v1/solve`, `/v1/verify` and `/v1/fetch` all take and return JSON, and
`/healthz` / `/v1/version` tell you what is running:

```bash
curl -s localhost:8088/v1/version
# {"version":"2.50","codename":"mule","algorithms":[...]}
```

**There is no authentication.** Bind it to loopback, or put it behind auth you
control: anyone who can reach it can spend your CPU on proofs of work.

### The MCP server

`anubis_mcp` speaks JSON-RPC 2.0 over stdio, so an MCP client starts it as a
subprocess:

```json
{
  "mcpServers": {
    "anubis": { "command": "/absolute/path/to/anubis_mcp" }
  }
}
```

It exposes three tools: `anubis_fetch` (solve the challenge and return the page
as text), `anubis_solve` (solve a challenge you already have) and
`anubis_version`.

Any language with an HTTP client can use the API; anything that speaks MCP can
use the server. Details: [`docs/api-service.md`](docs/api-service.md) and
[`docs/mcp.md`](docs/mcp.md).

### Looking like a browser (optional)

A site that fingerprints TLS will still challenge you, because the built-in
client's handshake is OpenSSL's. Install a libcurl-impersonate and the fetch
layer sends Chrome's instead:

```bash
make impersonate-lib CURL_IMPERSONATE_LIB=/path/to/libcurl-impersonate-chrome.so.4
```

That is a runtime library the `.so` loads with `dlopen()` — it is never linked,
and everything in this guide works without it. Then:

```bash
curl -s localhost:8088/v1/fetch -d '{"url":"https://example.com/","impersonate":"chrome"}'
# {"status":200, ..., "transport":"curl-impersonate/chrome116","content":"..."}
```

`impersonate` also takes a concrete profile (`chrome110`, `edge101`,
`safari15_5`) or `off`, and `ANUBIS_IMPERSONATE` pins the default for a whole
process. `transport` in the answer tells you what was really used. To check it
works on your machine, `make test-impersonate` starts a local TLS server and
looks at the ClientHello it receives.

---

## 7. Where to go next

| I want to… | read |
|---|---|
| understand the Python API | [`docs/python.md`](docs/python.md) |
| call it from C | [`docs/c-api.md`](docs/c-api.md) |
| use the command line | [`docs/cli.md`](docs/cli.md) |
| use a GPU | [`docs/gpu.md`](docs/gpu.md) |
| call it from an MCP client | [`docs/mcp.md`](docs/mcp.md) |
| call it over HTTP from any language | [`docs/api-service.md`](docs/api-service.md) |
| fix a build/runtime problem | [`docs/troubleshooting.md`](docs/troubleshooting.md) |
| hack on the solver | [`docs/development.md`](docs/development.md) |
| see measured speeds | [`SPEED.md`](SPEED.md) |
| check the security policy | [`SECURITY.md`](SECURITY.md) |

---

## 8. A word of caution

This tool exists for testing your own deployments, research, and
interoperability. Only solve challenges for sites you are authorised to test,
and keep in mind that a proof-of-work gate is a resource-protection mechanism.
The CVE-2026-62314 fast path is opt-in and refuses non-loopback targets unless
you explicitly allow them (`--allow-remote-cve`).
