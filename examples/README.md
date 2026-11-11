# Examples

Small, runnable snippets for using `anubis_solver` from your own code. Each
file is standalone; run them from the repository root.

| file | what it shows |
|---|---|
| [`basic.py`](basic.py) | solve a challenge and fetch a page with the high-level client |
| [`solver.py`](solver.py) | parse a challenge, solve it directly, verify the digest |
| [`impersonate.py`](impersonate.py) | browser TLS/JA3 impersonation for fingerprint checks |
| [`gpu.py`](gpu.py) | report the Vulkan device and CPU affinity; solve on the GPU |

```bash
python3 examples/solver.py                      # no server needed
python3 examples/basic.py http://127.0.0.1:8923 # local Anubis instance
python3 examples/gpu.py [--solve]
```

Notes:

- `basic.py` and `impersonate.py` need a reachable Anubis-protected URL. Use your
  own instance or a target you are authorized to test.
- `solver.py` builds an in-memory challenge, so it runs offline.
- `gpu.py` only solves when you pass `--solve`, and only a challenge small
  enough to finish quickly.
