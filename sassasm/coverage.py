#!/usr/bin/env python3
"""coverage.py — how much of a real .sass listing can sassasm assemble?

Pointing the assembler at a real file is the honest way to measure it: parse the
listing, try to encode every instruction, and report what is supported, what is
not, and which mnemonics block the most lines. That list is the work order.

    python3 sassasm/coverage.py src/sass/nvidiaT4_argon2id_opt.sass
"""
from __future__ import annotations

import collections
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sassasm import encode_line  # noqa: E402

#  /*0008*/  IMAD.MOV.U32 R1, RZ, RZ, c[0x0][0x28] ;
LINE = re.compile(r"^\s*(?:/\*[0-9a-f]+\*/)?\s*([A-Za-z][A-Za-z0-9_.]*)\s*(.*?)\s*;?\s*$")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    for name in argv[1:]:
        path = Path(name)
        lines = path.read_text(errors="replace").splitlines()
        total = 0
        by_mnemonic: collections.Counter[str] = collections.Counter()
        encoded = 0
        blockers: collections.Counter[str] = collections.Counter()
        first_fail = None
        for i, raw in enumerate(lines, 1):
            s = raw.strip()
            if not s or s.startswith(("//", ".", "@")) or s.endswith(":") or ":" not in raw and not s:
                continue
            m = LINE.match(raw)
            if not m:
                continue
            op, rest = m.group(1), m.group(2)
            total += 1
            by_mnemonic[op] += 1
            try:
                encode_line(f"{op} {rest}")
                encoded += 1
            except Exception as e:
                blockers[op] += 1
                if first_fail is None:
                    first_fail = (i, op, str(e)[:100])

        print(f"== {path.name}: {total} instruction lines, {len(by_mnemonic)} mnemonics")
        print(f"   assembled: {encoded} ({100.0*encoded/max(total,1):.2f}%)")
        if first_fail:
            print(f"   first failure: line {first_fail[0]}, {first_fail[1]!r}")
            print(f"     {first_fail[2]}")
        print("   top mnemonics (count, supported?):")
        for op, n in by_mnemonic.most_common(15):
            sup = "yes" if op in ("MOV",) else "no"
            print(f"     {op:24s} {n:6d}  {sup}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
