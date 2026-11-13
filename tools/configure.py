#!/usr/bin/env python3
"""configure.py — answer the three build questions and write config.mk.

    make config

  1. Which GPU architecture are you building for?  A T4 is sm_75, and this repo
     ships hand-measured SASS for sm_75 in src/sass/. For an architecture with no
     shipped SASS the CUDA backend still builds, from standard .cu sources - the
     SASS is an optimisation, not a requirement.
  2. Which CPU architecture?  x86-64 or AArch64/ARM.
  3. What does the CPU support?  AVX2, AVX-512 (+VL/BW/DQ), SHA-NI, BMI2, or on
     ARM NEON/ASIMD, SHA-2, SVE.

Run interactively (it shows the answers and asks before writing):

    make config CONFIG_ARGS=--ask

Overrides, without editing anything:

    make config CUDA_ARCH=sm_86 CPU_SIMD=avx2
"""
import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SASS_DIR = ROOT / "src" / "sass"

# shipped SASS: filename prefix -> the architecture it was built for
SASS_ARCH = {"sm_75": "nvidiaT4"}

# compute capability -> nvcc -arch, for GPUs people actually build on
CC_NAMES = {
    "7.0": ("sm_70", "V100"), "7.2": ("sm_72", "Xavier"), "7.5": ("sm_75", "T4 / RTX 20xx"),
    "8.0": ("sm_80", "A100"), "8.6": ("sm_86", "A10 / RTX 30xx / A6000"),
    "8.7": ("sm_87", "Jetson Orin"), "8.9": ("sm_89", "L4 / L40 / RTX 40xx"),
    "9.0": ("sm_90", "H100 / H200"), "10.0": ("sm_100", "B200"), "12.0": ("sm_120", "RTX 50xx"),
}


def run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
        return r.stdout.strip(), r.returncode
    except Exception:
        return "", 1


def detect_gpu():
    """Return (gpus, nvcc_path). gpus is a list of dicts."""
    gpus = []
    if shutil.which("nvidia-smi"):
        out, rc = run("nvidia-smi --query-gpu=name,compute_cap,memory.total "
                      "--format=csv,noheader")
        if rc == 0:
            for line in out.splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 2 and parts[1]:
                    cc = parts[1]
                    arch, family = CC_NAMES.get(cc, ("sm_" + cc.replace(".", ""), "unknown family"))
                    gpus.append({"name": parts[0], "cc": cc, "arch": arch,
                                 "family": family,
                                 "mem": parts[2] if len(parts) > 2 else ""})
    return gpus


def detect_cpu():
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("aarch64", "arm64"):
        arch = "aarch64"
    elif machine.startswith("arm"):
        arch = "arm"
    else:
        arch = machine

    feats = set()
    flags = ""
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith(("flags", "Features")):
                flags = line.split(":", 1)[1]
                break
    except OSError:
        pass
    if not flags and platform.system() == "Darwin":
        flags, _ = run("sysctl -n machdep.cpu.features machdep.cpu.leaf7_features")
    for f in flags.split():
        feats.add(f.lower())

    info = {"arch": arch, "flags": feats}
    if arch == "x86_64":
        info["avx2"] = "avx2" in feats
        info["avx512"] = "avx512f" in feats
        info["avx512vl"] = "avx512vl" in feats and "avx512bw" in feats
        info["sha_ni"] = bool({"sha_ni", "sha"} & feats)
        info["bmi2"] = "bmi2" in feats
        info["aes"] = "aes" in feats
        if info["avx512"]:
            simd = "avx512"
        elif info["avx2"]:
            simd = "avx2"
        else:
            simd = "portable"
    else:
        info["neon"] = bool({"asimd", "neon"} & feats)
        info["sha2"] = bool({"sha2", "sha1"} & feats)
        info["sve"] = "sve" in feats
        simd = "neon" if info["neon"] else "portable"
    info["simd"] = simd
    return info


def sass_for(arch):
    """Which shipped SASS files target this architecture, if any."""
    prefix = SASS_ARCH.get(arch)
    if not prefix or not SASS_DIR.is_dir():
        return []
    return sorted(p.name for p in SASS_DIR.glob(prefix + "_*.sass")
                  if "annotated" not in p.name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ask", action="store_true", help="show the answers and confirm before writing")
    ap.add_argument("--out", default=str(ROOT / "config.mk"))
    args = ap.parse_args()

    gpus = detect_gpu()
    nvcc = shutil.which("nvcc")
    cpu = detect_cpu()

    # ---- answers ---------------------------------------------------------
    if gpus:
        arch = gpus[0]["arch"]
        gpu_line = ", ".join("%s (%s -> %s)" % (g["name"], g["cc"], g["arch"]) for g in gpus)
    else:
        arch = ""
        gpu_line = "no NVIDIA GPU detected"

    sass = sass_for(arch) if arch else []
    cuda_backend = bool(gpus) or bool(nvcc)

    print()
    print("anubis-solver build configuration")
    print("=" * 66)
    print("1. GPU architecture")
    print("   detected : %s" % gpu_line)
    if arch:
        print("   target   : %s (%s)" % (arch, CC_NAMES.get(gpus[0]["cc"], ("", "?"))[1]))
        if sass:
            print("   SASS     : measured reference exists - %d file(s) for %s" % (len(sass), arch))
            print("              %s" % (", ".join(sass[:3]) + (" ..." if len(sass) > 3 else "")))
            print("              the build still compiles CUDA C for %s; the SASS is what" % arch)
            print("              that compilation was measured against (see SPEED.md)")
        else:
            print("   SASS     : none shipped for %s" % arch)
            print("              the CUDA backend compiles from the .cu sources with")
            print("              -arch=%s, which is the standard path, just not a measured one" % arch)
    else:
        print("   target   : none (CUDA backend will not be built)")
    if nvcc:
        print("   nvcc     : %s" % nvcc)
    else:
        print("   nvcc     : not found")

    print()
    print("2. CPU architecture")
    print("   detected : %s" % cpu["arch"])

    print()
    print("3. CPU features")
    if cpu["arch"] == "x86_64":
        keys = [("avx2", "AVX2"), ("avx512", "AVX-512F"), ("avx512vl", "AVX-512VL/BW"),
                ("sha_ni", "SHA-NI"), ("bmi2", "BMI2"), ("aes", "AES")]
        for k, label in keys:
            print("   %-10s %s" % (label, "yes" if cpu.get(k) else "no"))
        print("   best SHA-256 path: %s" % {
            "avx512": "src/cpu/avx512.s (16-way)",
            "avx2": ("src/cpu/shani.s (SHA-NI, 1 way) + src/cpu/avx2.s"
                     if cpu.get("sha_ni") else "src/cpu/avx2.s"),
            "portable": "portable C"}[cpu["simd"]])
    else:
        for k, label in [("neon", "NEON/ASIMD"), ("sha2", "SHA-2"), ("sve", "SVE")]:
            print("   %-10s %s" % (label, "yes" if cpu.get(k) else "no"))
        print("   best SHA-256 path: %s" % ("src/cpu/neon.s" if cpu.get("neon") else "portable C"))
    print("=" * 66)

    cfg = {
        "CUDA_ARCH": arch,
        "CUDA_SASS": "1" if sass else "0",
        "CUDA_BACKEND": "1" if cuda_backend else "0",
        "CPU_ARCH": cpu["arch"],
        "CPU_SIMD": cpu["simd"],
        "CPU_SHANI": "1" if cpu.get("sha_ni") or cpu.get("sha2") else "0",
        "SASS_FILES": " ".join(sass),
    }

    if args.ask:
        print()
        try:
            ok = input("write these to config.mk? [Y/n] ").strip().lower()
        except EOFError:
            ok = "y"
        if ok not in ("", "y", "yes"):
            print("not written")
            return 0

    lines = ["# generated by `make config` - safe to delete and regenerate",
             "# overrides: make config CUDA_ARCH=sm_86 CPU_SIMD=avx2"]
    for k, v in cfg.items():
        if k == "SASS_FILES":
            continue
        lines.append("%s ?= %s" % (k, v))
    lines.append("# shipped SASS for this target: %s" % (cfg["SASS_FILES"] or "none"))
    Path(args.out).write_text("\n".join(lines) + "\n")
    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
