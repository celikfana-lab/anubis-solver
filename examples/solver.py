#!/usr/bin/env python3
"""Low-level use: build a challenge, solve it, verify the result.

    python3 examples/solver.py

Runs offline — no Anubis server required.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

import hashlib

from anubis_solver import AnubisChallenge, AnubisSolver

# The same payload an Anubis challenge page embeds. A server normally sets
# `randomData` to fresh hex and `difficulty` per policy; v1.17–v1.21 used a
# plain string instead of the {"id", "randomData"} object.
payload = {
    "challenge": {"id": "example", "randomData": "ab" * 64},
    "rules": {"algorithm": "fast", "difficulty": 4},
}

challenge = AnubisChallenge.from_payload(payload)
solver = AnubisSolver()  # threads default to the P-core count on hybrid CPUs

print(f"library:  {solver.version}")
print(f"threads:  {solver.threads}  affinity: {solver.affinity}")
print(f"gpu:      {solver.gpu or 'none'}")
print(f"challenge: {challenge.algorithm}, difficulty {challenge.difficulty}")

solution = solver.solve(challenge)
print(f"nonce:    {solution.nonce}")
print(f"elapsed:  {solution.elapsed_ms:.1f} ms")
print(f"digest:   {solution.response}")

# The proof: sha256("<randomData><decimal nonce>") has `difficulty` leading
# zero hex digits for fast/slow; WASM algorithms use leading zero bits.
message = (challenge.random_data + str(solution.nonce)).encode()
check = hashlib.sha256(message).hexdigest()
print(f"verified: {check == solution.response}")

# Your own challenge source works the same way:
#   solution = AnubisSolver().solve({"challenge": "<hex>", "rules": {...}})
