// content.js — take over Anubis's own progress bar, and drive it with whichever
// solver this machine actually has.
//
// Anubis renders:
//   <p id="status">Calculating… Difficulty: 26, Speed: 1103 kH/s</p>
//   <div id="progress"><div class="bar-inner"></div></div>
// and its own single-core wasm keeps updating both. This replaces the text and
// the bar with the real solver's numbers, and re-asserts them over Anubis's
// writes (an observer, because the page's solver would otherwise keep
// overwriting #status).
//
// The page's own solver is stopped before it starts: once a challenge is seen,
// the background script cancels the challenge page's .wasm module requests. If
// nothing of ours works, we ask the background to unblock, so the tab is never
// left with a dead solver and no replacement.
//
// Four modes, chosen in this order by what answers:
//   native   the Firefox native host: libanubis_solver.so, which picks the best
//            backend it has (CUDA, Level Zero, Vulkan, OpenCL, SHA-NI/AVX-512)
//            — the fast path on Windows/macOS/Linux when the host is installed
//   gpu      WebGPU, after a known-answer self-check against WebCrypto
//            (webgpu/gpu-solver.js + webgpu/sha256.wgsl) — the fast path when
//            the host is missing but the browser has a real GPU
//   wasm     this repository's 4-wide wasm kernel in a Worker, when neither of
//            the above is there
//   page     nothing of ours: the tab is unblocked and Anubis's solver resumes
// A GPU that fails the self-check is not used: wrong answers are not fast.
(async () => {
  "use strict";


  // Only where our kernel is actually faster than the page's: the 4-wide
  // SHA-256 does 5.1 MH/s against Anubis's ~1.9, while our hashx interpreter
  // does 0.48 MH/s against the page's compiled ~3.2, so hashx stays with the
  // page's solver rather than being taken over by something slower.
  const WASM_FOR = {
    sha256: "sha256_pow_batch.wasm",
    "wasm-sha256": "sha256_pow_batch.wasm",
  };

  const state = {
    mode: null,          // "native" | "gpu" | "wasm" | "page"
    challenge: null,
    kernel: "",
    rate: 0,
    estimateMs: 0,
    started: 0,
    ticker: 0,
    worker: null,
    gpu: null,
  };

  /** "Vulkan · Intel(R) Iris(R) Xe Graphics (ADL GT2)" or "AVX-512 · 4 threads". */
  function engineLabel() {
    if (state.mode === "gpu") return state.kernel ? `WebGPU · ${state.kernel}` : "WebGPU";
    if (state.mode === "wasm") return state.kernel || "wasm";
    if (state.mode !== "native") return "page solver";
    const kernel = state.kernel || "native";
    const label = KERNEL_LABEL[kernel] ?? kernel;
    if (CPU_KERNELS.has(kernel)) {
      return state.threads ? `${label} · ${state.threads} threads` : label;
    }
    return state.gpu ? `${label} · ${state.gpu}` : label;
  }

  // anubis_active_kernel() names: the GPU backends and the CPU SIMD kernels.
  const KERNEL_LABEL = {
    cuda: "CUDA",
    levelzero: "Level Zero",
    vulkan: "Vulkan",
    opencl: "OpenCL",
    avx512: "AVX-512",
    avx2: "AVX2",
    shani: "SHA-NI",
    cpu: "CPU",
    tpu: "TPU",
    hashx: "HashX",
  };
  const CPU_KERNELS = new Set(["avx512", "avx2", "shani", "cpu"]);

  // What the page shows while we work: our mascot and headline in place of the
  // page's own error state (its solver cannot start, we cancelled its wasm).
  // look.js owns the choice, including the one-page-in-a-thousand variant.
  const LOOK = AnubisLook.pickLook(location.search);

  const MODE_LABEL = {
    native: "Solving natively",
    gpu: "Solving on the GPU",
    wasm: "Solving with better wasm",
    page: "Solving",
  };

  function $(id) {
    return document.getElementById(id);
  }

  /**
   * The challenge JSON lives in <head>, but a document_start script can run
   * before the parser has inserted it, so wait for the node instead of reading
   * once. Resolves with null if the page turns out not to be Anubis.
   */
  function whenChallenge() {
    const now = challenge();
    if (now) return Promise.resolve(now);
    return new Promise((resolve) => {
      let done = false;
      const finish = (value) => {
        if (done) return;
        done = true;
        observer.disconnect();
        resolve(value);
      };
      const observer = new MutationObserver(() => {
        const found = challenge();
        if (found) finish(found);
      });
      observer.observe(document.documentElement ?? document, {
        childList: true, subtree: true,
      });
      addEventListener("load", () => finish(challenge()), { once: true });
    });
  }

  function challenge() {
    const el = $("anubis_challenge");
    if (!el) return null;
    try {
      const payload = JSON.parse(el.textContent);
      const rules = payload?.rules ?? {};
      const chal = payload?.challenge ?? {};
      const difficulty = rules.difficulty ?? chal.difficulty ?? null;
      const randomData = chal.randomData ?? rules.randomData ?? null;
      if (difficulty == null || !randomData) return null;
      return {
        algorithm: String(rules.algorithm ?? chal.method ?? "sha256"),
        difficulty: Number(difficulty),
        randomData: String(randomData),
        id: chal.id ?? "",
      };
    } catch {
      return null;
    }
  }

  function humanRate(hps) {
    if (!hps || !isFinite(hps)) return "";
    if (hps >= 1e9) return `${(hps / 1e9).toFixed(2)} GH/s`;
    if (hps >= 1e6) return `${(hps / 1e6).toFixed(2)} MH/s`;
    if (hps >= 1e3) return `${(hps / 1e3).toFixed(0)} kH/s`;
    return `${Math.round(hps)} H/s`;
  }

  // ---- painting Anubis's own elements ---------------------------------

  function wantStatus() {
    const pct = state.pct ?? 0;
    if (state.phase === "done") {
      const rate = state.rate ? ` at ${humanRate(state.rate)}` : "";
      return `Solved with ${state.kernel} in ${(state.elapsedMs / 1000).toFixed(2)} s${rate}`;
    }
    const label = MODE_LABEL[state.mode] ?? "Solving";
    const bits = [`${label} · ${state.challenge?.algorithm ?? ""} · difficulty ${state.challenge?.difficulty ?? "?"}`];
    bits.push(engineLabel());
    if (state.rate) bits.push(`~${humanRate(state.rate)}`);
    if (state.phase === "error") bits.push(String(state.error ?? "failed").slice(0, 48));
    else if (pct) bits.push(`${pct.toFixed(0)}%`);
    else if (state.phase !== "done") bits.push("searching");
    const elapsed = state.elapsedMs ?? (state.started ? performance.now() - state.started : 0);
    if (elapsed > 1000 && state.phase !== "done") bits.push(`${(elapsed / 1000).toFixed(0)} s`);
    return bits.join(" — ");
  }

  function paint(force) {
    ensureStyle();
    // The page's own solver cannot start (its wasm is cancelled), so it paints
    // "Calculation error!" and the reject mascot. Keep our headline and our
    // mascot there instead, on every repaint.
    const title = $("title");
    if (title && title.textContent !== LOOK.title) title.textContent = LOOK.title;
    const image = $("image");
    const mascot = browser.runtime.getURL(LOOK.mascot);
    if (image && image.getAttribute("src") !== mascot) image.setAttribute("src", mascot);
    const status = $("status");
    if (status) {
      const text = wantStatus();
      if (force || status.textContent !== text) status.textContent = text;
      status.style.display = "";
    }
    const progress = $("progress");
    const inner = progress?.querySelector?.(".bar-inner");
    const indeterminate = state.phase !== "done" && state.pct == null && state.mode === "native";
    const pct = state.phase === "done" ? 100 : Math.min(99, state.pct ?? 0);
    if (inner) inner.classList.toggle("anubis-indeterminate", indeterminate);
    if (progress) progress.style.display = "";   // the page hides it on error
    if (inner) inner.style.width = `${pct}%`;
    if (progress && progress.setAttribute) {
      progress.setAttribute("aria-valuenow", String(Math.round(pct)));
      progress.setAttribute("aria-valuemin", "0");
      progress.setAttribute("aria-valuemax", "100");
    }
    // if the page has no such elements (some Anubis versions), fall back to a panel
    if (!status && !progress) ensurePanel();
    if (panelRefs) {
      panelRefs.engine.textContent = engineLabel();
      panelRefs.fill.style.width = `${pct}%`;
      panelRefs.pct.textContent = `${pct.toFixed(0)}%`;
      panelRefs.rate.textContent = humanRate(state.rate);
    }
  }

  // A bar cannot show progress it does not know: while the host has no measured
  // rate for this challenge shape, pulse instead of filling a fake bar.
  function ensureStyle() {
    if (document.getElementById("anubis-solver-style")) return;
    const style = document.createElement("style");
    style.id = "anubis-solver-style";
    style.textContent = `
      @keyframes anubis-indeterminate {
        0%   { background-position: -120% 0; }
        100% { background-position: 220% 0; }
      }
      .bar-inner.anubis-indeterminate {
        width: 100% !important;
        background: linear-gradient(90deg, #1b1e24 0%, #58c8ff 40%, #8fe3a8 60%, #1b1e24 100%);
        background-size: 60% 100%;
        background-repeat: no-repeat;
        animation: anubis-indeterminate 1.4s linear infinite;
      }`;
    document.documentElement.appendChild(style);
  }

  let panelRefs = null;
  function ensurePanel() {
    if (panelRefs) return;
    const host = document.createElement("div");
    host.style.cssText = "position:fixed;right:18px;bottom:18px;z-index:2147483647";
    const root = host.attachShadow({ mode: "closed" });
    root.innerHTML = `
      <style>
        .p{width:280px;padding:10px 12px;border-radius:10px;background:#1c1f26;color:#e8eaf0;
           border:1px solid #3a4150;font:12px/1.4 system-ui,sans-serif}
        .b{display:flex;justify-content:space-between;margin-bottom:8px}
        .e{color:#8fe3a8;font-family:ui-monospace,monospace}
        .t{height:6px;border-radius:999px;background:#2a303c;overflow:hidden}
        .f{height:100%;width:0;background:linear-gradient(90deg,#58c8ff,#8fe3a8)}
        .m{display:flex;justify-content:space-between;color:#9aa3b2;margin-top:6px;
           font-family:ui-monospace,monospace}
      </style>
      <div class="p"><div class="b"><b>anubis-solver</b><span class="e">…</span></div>
      <div class="t"><div class="f"></div></div>
      <div class="m"><span class="pct">0%</span><span class="rate"></span></div></div>`;
    document.documentElement.appendChild(host);
    panelRefs = {
      engine: root.querySelector(".e"),
      fill: root.querySelector(".f"),
      pct: root.querySelector(".pct"),
      rate: root.querySelector(".rate"),
    };
  }

  // Anubis's solver keeps writing to #status; put ours back.
  const observer = new MutationObserver(() => paint(false));
  function watch() {
    const status = $("status");
    if (status) observer.observe(status, { childList: true, characterData: true, subtree: true });
    const progress = $("progress");
    if (progress) observer.observe(progress, { attributes: true, attributeFilter: ["aria-valuenow"] });
    for (const id of ["title", "image"]) {
      const el = $(id);
      if (el) observer.observe(el, { childList: true, characterData: true, subtree: true, attributes: true });
    }
  }

  // ---- native mode -----------------------------------------------------

  browser.runtime.onMessage.addListener((message) => {
    if (!message) return;
    if (message.type === "anubis-native-progress") {
      const frame = message.frame ?? {};
      if (frame.event === "start") {
        state.mode = "native";
        state.kernel = frame.kernel ?? "native";
        state.gpu = frame.gpu ?? state.gpu;
        state.rate = frame.rate ?? 0;
        state.estimateMs = frame.estimateMs ?? 0;
        state.threads = frame.threads ?? 0;
        state.started = performance.now();
        state.phase = "running";
      } else if (frame.event === "progress") {
        state.pct = frame.pct ?? 0;
        state.rate = frame.rate ?? state.rate;
        if (frame.kernel) state.kernel = frame.kernel;
        state.gpu = frame.gpu ?? state.gpu;
      } else if (frame.event === "done") {
        state.phase = frame.ok ? "done" : "error";
        state.error = frame.error;
        state.elapsedMs = frame.elapsedMs ?? performance.now() - state.started;
        state.rate = frame.rate ?? state.rate;
        state.kernel = frame.kernel ?? state.kernel;
      }
      paint(true);
    } else if (message.type === "anubis-native-mode") {
      // the host is not there: pick the in-page engine if we have one
      startFallback();
    }
  });

  // ---- wasm mode -------------------------------------------------------

  function baseUrl(path) {
    return browser.runtime.getURL(path);
  }

  /** The host is not there: WebGPU if it passes the self-check, else wasm. */
  async function startFallback() {
    if (state.mode === "gpu" || state.mode === "wasm" || state.mode === "page") return;
    const chal = state.challenge;
    if (!chal) return;

    // The probe ran in parallel with the native attempt, so this is usually
    // already settled. A GPU holds the whole card; the wasm worker uses one core.
    if (chal.algorithm === "sha256" || chal.algorithm === "wasm-sha256") {
      const gpu = await gpuProbe;
      if (gpu && gpu.ok) {
        startGPU(gpu);
        return;
      }
      state.gpuWhy = gpu ? gpu.why : "no WebGPU";
    }
    if (WASM_FOR[chal.algorithm]) startWasm(chal);
    else giveUp(state.gpuWhy ?? "no kernel of ours for this algorithm");
  }

  function startWasm(chal) {
    const wasmName = WASM_FOR[chal.algorithm];
    if (!wasmName) {
      giveUp("no kernel of ours for this algorithm");
      return;
    }
    state.mode = "wasm";
    state.kernel = wasmName.includes("batch") ? "wasm 4-wide" : "wasm";
    state.phase = "running";
    state.started = performance.now();
    paint(true);

    const wasmUrl = baseUrl(`wasm/${wasmName}`);
    const worker = new Worker(baseUrl("wasm/pow-worker.js"));
    state.worker = worker;
    let calibrated = false;

    worker.onmessage = (event) => {
      const msg = event.data ?? {};
      if (msg.kind === "calibrated") {
        calibrated = true;
        state.rate = msg.rate;
        state.estimateMs = (2 ** chal.difficulty) / Math.max(msg.rate, 1) * 1000;
        state.ticker = setInterval(() => {
          const elapsed = performance.now() - state.started;
          state.pct = Math.min(99, (elapsed / Math.max(state.estimateMs, 1)) * 100);
          paint(false);
        }, 120);
        worker.postMessage({ kind: "solve", wasmUrl, algorithm: chal.algorithm,
                             challengeHex: chal.randomData, difficulty: chal.difficulty });
        return;
      }
      clearInterval(state.ticker);
      if (!calibrated && !msg.ok) {
        giveUp(msg.error ?? "the wasm module would not load");
        return;
      }
      if (msg.ok) {
        state.phase = "done";
        state.elapsedMs = msg.elapsedMs;
        paint(true);
        noteSolve(chal, "wasm 4-wide", msg.elapsedMs, 0);
        passThrough(chal, msg);
      } else {
        state.phase = "error";
        state.error = msg.error;
        paint(true);
      }
    };

    const cal = Math.max(8, Math.min(chal.difficulty - 4, 18));
    worker.postMessage({ kind: "calibrate", wasmUrl, algorithm: chal.algorithm,
                         challengeHex: chal.randomData, difficulty: cal });
  }

  // ---- gpu mode --------------------------------------------------------

  function startGPU(gpu) {
    const chal = state.challenge;
    state.mode = "gpu";
    state.kernel = gpu.adapter || "webgpu";
    state.phase = "running";
    state.started = performance.now();
    paint(true);

    AnubisWebGPU.solve(chal.randomData, chal.difficulty, (p) => {
      state.pct = p.pct;
      state.rate = p.rate;
      paint(false);
    }).then((res) => {
      if (res && res.ok) {
        state.phase = "done";
        state.elapsedMs = res.elapsedMs;
        state.rate = res.rate ?? state.rate;
        paint(true);
        noteSolve(chal, `webgpu ${gpu.adapter || ""}`.trim(), res.elapsedMs, res.rate ?? 0);
        passThrough(chal, res);
        return;
      }
      state.gpuWhy = res?.error ?? "the GPU scan failed";
      if (WASM_FOR[chal.algorithm]) startWasm(chal);
      else giveUp(state.gpuWhy);
    }).catch((err) => {
      state.gpuWhy = String(err);
      if (WASM_FOR[chal.algorithm]) startWasm(chal);
      else giveUp(state.gpuWhy);
    });
  }

  /** Nothing of ours worked: put the page's own solver back in charge. */
  function giveUp(why) {
    state.mode = "page";
    state.kernel = "page wasm";
    state.phase = "running";
    state.error = why;
    paint(true);
    browser.runtime.sendMessage({ type: "anubis-unblock" }).catch(() => {});
  }

  /**
   * Anubis has its own page for "your browser is configured to disable
   * cookies", shown when /pass-challenge arrives without its verification
   * cookie. That is a server-side cookie problem, not something the extension
   * causes or can fix, but it is easy to misread as the extension failing:
   * Anubis's default cookie is Secure; SameSite=None; Partitioned, and a
   * Partitioned cookie without Secure is rejected by Firefox, so a local http
   * server that passes -cookie-secure=false but forgets
   * -cookie-partitioned=false silently drops its own cookie.
   */
  function noteCookiePage() {
    const text = (document.body?.innerText || "").toLowerCase();
    if (!text.includes("disable cookies") || !text.includes("anubis")) return;
    if (document.getElementById("anubis-solver-cookie-hint")) return;
    const host = document.createElement("div");
    host.id = "anubis-solver-cookie-hint";
    host.style.cssText =
      "position:fixed;right:16px;bottom:16px;z-index:2147483647;max-width:330px";
    const root = host.attachShadow({ mode: "closed" });
    root.innerHTML = `
      <style>
        .c{background:#1c1f26;color:#e8eaf0;border:1px solid #3a4150;border-radius:10px;
           padding:11px 13px;font:12px/1.45 system-ui,sans-serif}
        b{color:#ffcf7a} code{font-family:ui-monospace,monospace;color:#8fe3a8;font-size:11px}
        .x{float:right;cursor:pointer;color:#9aa3b2;margin-left:8px}
      </style>
      <div class="c">
        <span class="x" id="x">dismiss</span>
        <b>This is Anubis's own cookie page.</b>
        Its challenge cookie was dropped before <code>/pass-challenge</code>, so the
        server never saw it. If you run this gate yourself, add
        <code>-cookie-partitioned=false</code>: Anubis sends a Partitioned cookie,
        Firefox rejects those unless they are also Secure, and
        <code>-cookie-secure=false</code> (needed on plain http) removes Secure.
        The full local set is
        <code>-cookie-secure=false -cookie-partitioned=false -cookie-same-site=Lax -use-remote-address</code>.
      </div>`;
    document.documentElement.appendChild(host);
    root.getElementById("x").addEventListener("click", () => host.remove());
  }

  /** One row for the toolbar panel; the native path is recorded in background.js. */
  function noteSolve(chal, engine, ms, rate) {
    if (typeof AnubisStats === "undefined" || !(ms >= 0)) return;
    AnubisStats.record({
      algorithm: chal.algorithm,
      difficulty: chal.difficulty,
      engine,
      ms,
      rate: rate || 0,
      url: location.href,
    }).catch(() => {});
  }

  function passThrough(chal, solution) {
    const url = new URL("/.within.website/x/cmd/anubis/api/pass-challenge", location.href);
    url.searchParams.set("id", chal.id ?? "");
    url.searchParams.set("response", solution.response);
    url.searchParams.set("nonce", String(solution.nonce));
    url.searchParams.set("redir", location.href);
    url.searchParams.set("elapsedTime", String(Math.max(1, Math.round(solution.elapsedMs))));
    location.assign(url.toString());
  }

  // ---- start -----------------------------------------------------------

  const chal = await whenChallenge();
  if (!chal) {
    noteCookiePage();
    return;
  }
  state.challenge = chal;
  state.mode = "native";             // until the host says otherwise
  state.phase = "running";
  watch();
  paint(true);

  // Probe the GPU while the native host is being tried, so a missing host does
  // not cost a round trip before the GPU scan can start.
  const gpuProbe = (typeof AnubisWebGPU !== "undefined" && AnubisWebGPU.probe)
    ? AnubisWebGPU.probe().catch((e) => ({ ok: false, why: String(e) }))
    : Promise.resolve({ ok: false, why: "no WebGPU support compiled in" });

  browser.runtime
    .sendMessage({ type: "anubis-native-detected", challenge: chal })
    .catch(() => startFallback());
})();
