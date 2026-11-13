# WebGPU on Kaggle's Tesla T4, attempt 2: the first run proved the container has
# no Vulkan ICD at all ("Found no drivers!", /usr/share/vulkan/icd.d missing), so
# Chrome fell back to SwiftShader. NVIDIA's Vulkan ICD ships with the *graphics*
# userspace, which a CUDA-only image does not install. This run tries to supply
# it, then reruns the two self-checking pages.
#
# Everything is printed and copied into result.json, so a failed attempt is still
# evidence rather than a blank.
# How this was run: `kaggle kernels push -p webgpu/kaggle` with the metadata below
# (2x Tesla T4, internet on). Result: the T4 cannot be used, see webgpu/README.md.
import json
import os
import subprocess
import sys
import time
from pathlib import Path

OUT = Path("/kaggle/working")
REPO = OUT / "anubis-solver"
PORT = 8092
RESULT = {}


def sh(cmd, timeout=1800):
    print(f"\n$ {cmd}", flush=True)
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        print(out[-3000:], flush=True)
        return out
    except subprocess.TimeoutExpired:
        print("(timed out)", flush=True)
        return "(timed out)"


def note(**kw):
    RESULT.update(kw)
    print("\n:: " + json.dumps(kw, default=str)[:1500], flush=True)


def write_result():
    (OUT / "result.json").write_text(json.dumps(RESULT, indent=2, default=str))
    print("\n===== RESULT =====", flush=True)
    print(json.dumps(RESULT, indent=2, default=str), flush=True)


try:
    note(step="environment")
    sh("nvidia-smi -L || true")
    # What graphics userspace is actually mounted? nvidia-container-toolkit mounts
    # the compute parts by default; the Vulkan ICD is part of the graphics parts.
    note(nvidia_libs=sh(
        "ls /usr/lib/x86_64-linux-gnu/ 2>/dev/null | grep -iE 'nvidia|GLX' | head -40 || true"))
    note(icd_before=sh("ls -R /usr/share/vulkan 2>/dev/null | head -20 || echo none"))

    note(step="try to install a Vulkan ICD for NVIDIA")
    sh("apt-get update -qq || true")
    # nvidia-vulkan-common drops /usr/share/vulkan/icd.d/nvidia_icd.json; libgl1
    # gives libGLX_nvidia.so.0 its GL shims. Neither touches the kernel module.
    sh("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
       "libvulkan1 vulkan-tools nvidia-vulkan-common libgl1 libegl1 mesa-vulkan-drivers "
       ">/dev/null 2>&1 || true")
    note(icd_after=sh("ls -l /usr/share/vulkan/icd.d/ 2>/dev/null || echo 'still no ICD dir'"))
    note(icd_contents=sh("cat /usr/share/vulkan/icd.d/*.json 2>/dev/null | head -40 || true"))
    note(vulkan=sh("vulkaninfo --summary 2>&1 | head -30 || true"))

    # If nvidia-vulkan-common dropped an ICD but it points at a library that is not
    # mounted, write our own pointing at whatever GLX library does exist.
    libs = sh("ls /usr/lib/x86_64-linux-gnu/libGLX_nvidia.so* 2>/dev/null || true")
    if libs.strip():
        os.makedirs("/usr/share/vulkan/icd.d", exist_ok=True)
        lib = sorted(libs.split())[0].split("/")[-1]
        icd = {
            "file_format_version": "1.0.1",
            "ICD": {"library_path": lib, "api_version": "1.3.0"},
        }
        Path("/usr/share/vulkan/icd.d/zz-nvidia-written.json").write_text(json.dumps(icd))
        note(wrote_icd=icd)
        note(vulkan_retry=sh("vulkaninfo --summary 2>&1 | head -30 || true"))

    note(step="browser")
    sh(f"{sys.executable} -m pip install -q playwright", timeout=900)
    sh(f"{sys.executable} -m playwright install --with-deps chromium", timeout=2400)

    if not REPO.exists():
        sh(f"git clone --depth 1 https://github.com/celikfana-lab/anubis-solver {REPO}")
    note(git_head=sh(f"git -C {REPO} rev-parse --short HEAD").strip())

    srv = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(PORT), "--bind", "127.0.0.1",
         "--directory", str(REPO)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    from playwright.sync_api import sync_playwright

    FLAGS = ["--headless=new", "--no-sandbox", "--disable-dev-shm-usage",
             "--disable-gpu-sandbox", "--use-angle=vulkan", "--use-vulkan=native",
             "--enable-features=Vulkan", "--enable-unsafe-webgpu"]

    def probe(page):
        return page.evaluate("""async () => {
          const out = { hasGpu: !!navigator.gpu };
          try {
            if (!navigator.gpu) return out;
            const a = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' });
            out.adapter = !!a;
            if (a) { out.info = a.info ? { vendor: a.info.vendor, architecture: a.info.architecture } : null;
                     const d = await a.requestDevice();
                     out.limits = { storageBinding: d.limits.maxStorageBufferBindingSize }; d.destroy(); }
          } catch (e) { out.error = String(e); }
          return out; }""")

    def run_page(page, name, query, timeout_ms=900_000):
        url = f"http://127.0.0.1:{PORT}/webgpu/{name}{query}"
        print(f"\n===== {url}", flush=True)
        page.goto(url, wait_until="domcontentloaded", timeout=90_000)
        try:
            page.wait_for_function("() => window.__result !== undefined", timeout=timeout_ms)
        except Exception as e:                                # noqa: BLE001
            return {"error": f"timed out: {e}"}
        return page.evaluate("() => window.__result")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=FLAGS)
        page = browser.new_page()
        page.on("console", lambda m: print(f"[page] {m.text}", flush=True))
        note(chromium=browser.version)
        note(webgpu_probe=probe(page))
        note(hashx_check=run_page(page, "hashx.html", "?quick=1"))
        note(hashx_bench=run_page(page, "hashx.html", ""))
        note(argon2id_check=run_page(page, "argon2id.html", "?quick=1"))
        browser.close()
    srv.terminate()

except BaseException as e:                                    # noqa: BLE001
    import traceback
    RESULT["fatal"] = traceback.format_exc()[-4000:]
    print(RESULT["fatal"], flush=True)

write_result()
