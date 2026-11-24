# meatrider on Kaggle: the AVX-512 kernel and one or two Tesla T4s.
#
# Everything this script learns is written to /kaggle/working/result.json, so a
# failed build is still evidence, and the log says the same thing either way:
#
#   kaggle kernels push -p src/meatrider/kaggle_meatrider
#   kaggle kernels status monktelv31/anubis-meatrider-kernels
#   kaggle kernels output monktelv31/anubis-meatrider-kernels -p /tmp/mrk
#
# What it checks, in order:
#   1. the CPU really has AVX-512 (and SHA-NI, AVX2) before measuring it;
#   2. `make` builds every kernel that machine can carry, CUDA included;
#   3. tests/test_meatrider.py -- the portable reference, 546 checks;
#   4. tests/test_meatrider_backends.py -- every available kernel agrees with
#      tools/meatrider_ref.py and mines a rung for real (this is where the
#      AVX-512 and CUDA kernels earn their place);
#   5. tools/meatrider_backends.py with one T4 and then with both.
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
    e["PATH"] = "/usr/local/cuda/bin:" + e.get("PATH", "")
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
    """Model and the instruction-set flags this run can actually use."""
    model, flags = "", []
    try:
        text = Path("/proc/cpuinfo").read_text()
        m = re.search(r"^model name\s*:\s*(.+)$", text, re.M)
        model = m.group(1).strip() if m else ""
        f = re.search(r"^flags\s*:\s*(.+)$", text, re.M)
        if f:
            have = set(f.group(1).split())
            flags = sorted(x for x in ("avx2", "sha_ni", "avx512f", "avx512vl",
                                       "avx512bw", "avx512dq")
                           if x in have)
    except OSError:
        pass
    return model, flags


TABLE_ROW = re.compile(r"^(\w+)\s+([\d,]+)\s+(\d+)\s+(\d+)$", re.M)


def parse_harness(text):
    """The rate rows the harness prints at the end, plus its inventory lines."""
    rates = {}
    for name, hps, solves, diff in TABLE_ROW.findall(text):
        rates[name] = {"hashes_per_second": int(hps.replace(",", "")),
                       "solves": int(solves), "difficulty": int(diff)}
    avail = ""
    m = re.search(r"available:\s*(.+)$", text, re.M)
    if m:
        avail = m.group(1).strip()
    return rates, avail


def main():
    RESULT["started"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _, out = sh("nvidia-smi -L")
    RESULT["nvidia_smi"] = out.strip()
    _, out = sh("nvcc --version | tail -2")
    RESULT["nvcc"] = out.strip()

    model, flags = cpu_facts()
    RESULT["cpu"] = {"model": model, "flags": flags,
                     "avx512": any(f.startswith("avx512") for f in flags),
                     "sha_ni": "sha_ni" in flags,
                     "cores": os.cpu_count()}
    print(f"\ncpu: {model}\nflags: {' '.join(flags)}", flush=True)

    if not REPO.exists():
        rc, out = sh("git clone --depth 1 https://github.com/celikfana-lab/anubis-solver.git "
                     + str(REPO), cwd=str(OUT))
        RESULT["clone"] = {"rc": rc, "tail": out[-800:]}
    _, out = sh("git -C %s log --oneline -1" % REPO, cwd=str(OUT))
    RESULT["commit"] = out.strip()

    rc, out = sh("make -j4 CUDA_ARCH=sm_75")
    RESULT["build"] = {"rc": rc, "tail": out[-2500:]}
    if rc != 0:
        finish()

    # The library's own view of what it got: compiled in, then actually usable.
    rc, out = sh("""python3 - <<'EOF'
import anubis_solver as a
s = a.AnubisSolver()
print("compiled:", s.backends())
print("available:", s.backends_available() if hasattr(s, "backends_available") else "?")
print("gpu:", s.gpu_info())
EOF""")
    RESULT["inventory"] = {"rc": rc, "tail": out[-1200:]}

    rc, out = sh("python3 tests/test_meatrider.py")
    RESULT["test_meatrider"] = {"rc": rc, "tail": out[-800:]}

    rc, out = sh("python3 tests/test_meatrider_backends.py", timeout=1800)
    RESULT["test_backends"] = {"rc": rc, "tail": out[-3000:]}

    # One T4, then both. CUDA_VISIBLE_DEVICES is how the same binary is told to
    # use half the box, which is also the only way to compare the two honestly.
    for label, visible in (("one_t4", "0"), ("two_t4", "0,1")):
        path = f"/tmp/{label}.json"
        rc, out = sh(
            f"CUDA_VISIBLE_DEVICES={visible} python3 tools/meatrider_backends.py "
            f"--only cuda --threads 1 --reps 7 --difficulty 26 --json {path}",
            env={"CUDA_VISIBLE_DEVICES": visible}, timeout=2400)
        rates, avail = parse_harness(out)
        try:
            bench = json.load(open(path))
        except OSError:
            bench = {}
        RESULT[label] = {"rc": rc, "visible": visible, "available": avail,
                         "rates": rates, "json": bench.get("rows", []),
                         "tail": out[-1500:] if rc else ""}

    # The same two configurations with the generated PTX instead of the .cu
    # kernel: ANUBIS_MEATRIDER_PTX=1 routes the CUDA slot through the driver,
    # which JITs meatrider.ptx per visible device and gives each one a worker.
    for label, visible in (("ptx_one_t4", "0"), ("ptx_two_t4", "0,1")):
        path = f"/tmp/{label}.json"
        rc, out = sh(
            f"CUDA_VISIBLE_DEVICES={visible} ANUBIS_MEATRIDER_PTX=1 "
            f"python3 tools/meatrider_backends.py --only cuda --threads 1 --reps 7 "
            f"--difficulty 26 --json {path}",
            env={"CUDA_VISIBLE_DEVICES": visible, "ANUBIS_MEATRIDER_PTX": "1"},
            timeout=2400)
        rates, avail = parse_harness(out)
        try:
            bench = json.load(open(path))
        except OSError:
            bench = {}
        RESULT[label] = {"rc": rc, "visible": visible, "available": avail,
                         "rates": rates, "json": bench.get("rows", []),
                         "tail": out[-1500:] if rc else ""}

    # The decisive one-vs-two-device comparison: the same standalone test, the
    # same challenge and the same winning nonce, with one T4 visible and then
    # both. Two devices in parallel find that nonce in the same wall time as one
    # and count twice the hashes, so the ratio is the parallelism itself -- free
    # of the harness's per-slice arithmetic.
    for label, visible in (("ptx_standalone_one", "0"), ("ptx_standalone_two", "0,1")):
        rc, out = sh("python3 src/meatrider/test_meatrider_ptx_gpu.py --reps 5 "
                     "--difficulty 24 --budget 300000",
                     env={"CUDA_VISIBLE_DEVICES": visible}, timeout=1200)
        RESULT[label] = {"rc": rc, "visible": visible, "tail": out[-2500:]}

    rc, out = sh("python3 src/meatrider/test_meatrider_ptx_gpu.py --reps 3",
                 timeout=1200)
    RESULT["ptx_standalone"] = {"rc": rc, "tail": out[-2500:]}

    # Forced AVX2 against AVX-512 on the same rungs, so the speedup is measured
    # rather than inferred from two different configurations.
    if RESULT["cpu"]["avx512"]:
        rc, out = sh("ANUBIS_NO_AVX512=1 python3 tools/meatrider_backends.py "
                     "--threads 1 --reps 7 --difficulty 20",
                     timeout=1200)
        rates, _ = parse_harness(out)
        RESULT["avx2_forced"] = {"rc": rc, "rates": rates}

    finish()


def finish():
    RESULT["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path = OUT / "result.json"
    path.write_text(json.dumps(RESULT, indent=2, default=str))
    print("\nresult.json written to", path, flush=True)

    print("\n=== summary ===", flush=True)
    print("cpu:", RESULT["cpu"]["model"], "| flags:", " ".join(RESULT["cpu"]["flags"]))
    for label in ("one_t4", "two_t4", "ptx_one_t4", "ptx_two_t4", "avx2_forced"):
        if label not in RESULT:
            continue
        r = RESULT[label]["rates"]
        for name, row in sorted(r.items()):
            print(f"{label:11s} {name:8s} {row['hashes_per_second']:>15,} H/s "
                  f"(2^{row['difficulty']}, {row['solves']} solves)")
    for key in ("build", "test_meatrider", "test_backends", "ptx_standalone",
            "ptx_standalone_one", "ptx_standalone_two"):
        if key in RESULT:
            print(f"{key}: rc={RESULT[key]['rc']}")
    sys.exit(0)


if __name__ == "__main__":
    main()
