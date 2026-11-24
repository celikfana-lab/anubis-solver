# meatrider on a Kaggle CPU: does this box have AVX-512, and does the tier's
# 16-lane kernel agree with the reference when it does?
#
#   kaggle kernels push -p src/meatrider/kaggle_meatrider_cpu
#   kaggle kernels status monktelv31/anubis-meatrider-avx512
#   kaggle kernels output monktelv31/anubis-meatrider-avx512 -p /tmp/mravx
#
# No GPU here on purpose: the T4 kernel sits in its own queue for a long time,
# and the AVX-512 question does not need one. This runs the same tests the T4
# kernel runs, so the two results are comparable line for line.
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

OUT = Path("/kaggle/working")
REPO = OUT / "anubis-solver"
RESULT = {}


def sh(cmd, timeout=3600, env=None, cwd=None):
    print(f"\n$ {cmd}", flush=True)
    e = dict(os.environ)
    if env:
        e.update(env)
    workdir = cwd or (str(REPO) if REPO.exists() else str(OUT))
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, env=e, cwd=workdir)
    except subprocess.TimeoutExpired:
        print("(timed out)", flush=True)
        return -1, "(timed out)"
    out = (r.stdout or "") + (r.stderr or "")
    print(out[-5000:], flush=True)
    return r.returncode, out


def cpu_facts():
    model, flags = "", []
    try:
        text = Path("/proc/cpuinfo").read_text()
        m = re.search(r"^model name\s*:\s*(.+)$", text, re.M)
        model = m.group(1).strip() if m else ""
        f = re.search(r"^flags\s*:\s*(.+)$", text, re.M)
        if f:
            have = set(f.group(1).split())
            flags = sorted(x for x in ("avx2", "sha_ni", "avx512f", "avx512vl",
                                       "avx512bw", "avx512dq", "avx512vbmi")
                           if x in have)
    except OSError:
        pass
    return model, flags


TABLE_ROW = re.compile(r"^(\w+)\s+([\d,]+)\s+(\d+)\s+(\d+)$", re.M)


def parse_harness(text):
    rates = {name: {"hashes_per_second": int(h.replace(",", "")),
                    "solves": int(s), "difficulty": int(d)}
             for name, h, s, d in TABLE_ROW.findall(text)}
    m = re.search(r"available:\s*(.+)$", text, re.M)
    return rates, (m.group(1).strip() if m else "")


def main():
    RESULT["started"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    model, flags = cpu_facts()
    RESULT["cpu"] = {"model": model, "flags": flags, "cores": os.cpu_count(),
                     "avx512": any(f.startswith("avx512") for f in flags),
                     "sha_ni": "sha_ni" in flags}
    print(f"\ncpu: {model}\nflags: {' '.join(flags)}", flush=True)

    if not REPO.exists():
        rc, out = sh("git clone --depth 1 https://github.com/celikfana-lab/anubis-solver.git "
                     + str(REPO), cwd=str(OUT))
        RESULT["clone"] = {"rc": rc, "tail": out[-600:]}
    _, out = sh("git -C %s log --oneline -1" % REPO, cwd=str(OUT))
    RESULT["commit"] = out.strip()

    rc, out = sh("make -j4")
    RESULT["build"] = {"rc": rc, "tail": out[-2000:]}
    if rc != 0:
        return finish()

    rc, out = sh("python3 tests/test_meatrider.py")
    RESULT["test_meatrider"] = {"rc": rc, "tail": out[-700:]}

    rc, out = sh("python3 tests/test_meatrider_backends.py", timeout=1800)
    RESULT["test_backends"] = {"rc": rc, "tail": out[-3000:]}

    # The tier's own harness, once with everything the box has and once with the
    # AVX-512 kernel switched off, so the 16-lane row is measured against the
    # 8-lane one on the same machine rather than inferred.
    rc, out = sh("python3 tools/meatrider_backends.py --threads 1 --reps 7 "
                 "--difficulty 20 --json /tmp/native.json", timeout=2400)
    rates, avail = parse_harness(out)
    RESULT["native"] = {"rc": rc, "available": avail, "rates": rates,
                        "tail": out[-1200:] if rc else ""}
    if RESULT["cpu"]["avx512"]:
        rc, out = sh("ANUBIS_NO_AVX512=1 python3 tools/meatrider_backends.py --threads 1 "
                     "--reps 7 --difficulty 20 --json /tmp/avx2.json", timeout=2400)
        rates, avail = parse_harness(out)
        RESULT["avx2_forced"] = {"rc": rc, "available": avail, "rates": rates,
                                 "tail": out[-1200:] if rc else ""}
    return finish()


def finish():
    RESULT["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path = OUT / "result.json"
    path.write_text(json.dumps(RESULT, indent=2, default=str))
    print("\nresult.json written to", path, flush=True)
    print("\n=== summary ===", flush=True)
    print("cpu:", RESULT["cpu"]["model"], "| avx512:", RESULT["cpu"]["avx512"],
          "| flags:", " ".join(RESULT["cpu"]["flags"]))
    for label in ("native", "avx2_forced"):
        for name, row in sorted(RESULT.get(label, {}).get("rates", {}).items()):
            print(f"{label:12s} {name:8s} {row['hashes_per_second']:>15,} H/s "
                  f"(2^{row['difficulty']}, {row['solves']} solves)")
    for key in ("build", "test_meatrider", "test_backends"):
        if key in RESULT:
            print(f"{key}: rc={RESULT[key]['rc']}")
    sys.exit(0)


if __name__ == "__main__":
    main()
