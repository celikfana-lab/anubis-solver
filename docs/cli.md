# Command line

```bash
python3 anubis_solver.py URL [options]
```

It fetches `URL`, solves whatever Anubis challenge is served, and prints the
page. Exit code is `0` on success and `1` on a failed request.

## Options

| flag | meaning |
|---|---|
| `--threads N` | worker threads (default: all physical cores) |
| `--lib PATH` | use a specific `libanubis_solver.so` |
| `--timeout S` | HTTP timeout in seconds (default 30) |
| `--impersonate NAME` | `curl_cffi` browser profile, e.g. `chrome`, `chrome120`, `firefox` |
| `--cve` | try the CVE-2026-62314 fast path (loopback targets only) |
| `--allow-remote-cve` | allow that fast path for non-loopback targets |
| `--affinity SPEC` | `pcores` (default), `off`, or a mask like `0,2,4,6` |

## Examples

```bash
# local test instance
python3 anubis_solver.py http://127.0.0.1:8923

# a site that checks TLS fingerprints
python3 anubis_solver.py https://example.com --impersonate chrome --threads 4

# pin to the P-cores and use a debug build
python3 anubis_solver.py https://example.com --lib ./libanubis_solver.so
```

GPU acceleration is controlled by environment variables, not flags:

```bash
ANUBIS_GPU_ARGON2=1 python3 anubis_solver.py https://example.com
ANUBIS_GPU_HASHX=1 python3 anubis_solver.py https://example.com
```

See [gpu.md](gpu.md).

## Scripts in `examples/`

| script | what it does |
|---|---|
| `basic.py URL` | fetch a protected page (same flow as the CLI) |
| `solver.py` | solve from a saved HTML file, print nonce/response |
| `gpu.py` | print the detected GPU backend and device |
| `impersonate.py` | browser impersonation with `curl_cffi` |
