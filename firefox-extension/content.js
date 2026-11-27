// content.js — take over Anubis's own progress bar, and drive it with whichever
// solver this machine actually has.
//
// Anubis renders:
//   <p id="status">Calculating… Difficulty: 26, Speed: 1103 kH/s</p>
//   <div id="progress"><div class="bar-inner"></div></div>
// and its own single-core wasm keeps updating both. This replaces the text and
// the bar with the real solver's numbers, and re-asserts them over Anubis's
// writes (an observer, because the page's solver is still running and will keep
// overwriting #status until it is navigated away from).
//
// Three modes, chosen by what answers:
//   native   the Firefox native host (libanubis_solver.so: SHA-NI/AVX2/AVX-512,
//            every core, an accelerator when one exists) — "solving natively"
//   wasm     this repository's wasm kernel in a Worker, when the host is missing
//            (Windows/macOS without install.sh) — "solving with better wasm"
//   page     nothing of ours: Anubis's own solver keeps the bar
// WebGPU is not a mode yet: the repository has WGSL for meatrider, not for the
// hashx/sha256 challenges a website issues, and a label without a kernel behind
// it would be a lie.
(() => {
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
    mode: null,          // "native" | "wasm" | "page"
    challenge: null,
    kernel: "",
    rate: 0,
    estimateMs: 0,
    started: 0,
    ticker: 0,
    worker: null,
  };

  function $(id) {
    return document.getElementById(id);
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
      return `Solved with ${state.kernel} in ${(state.elapsedMs / 1000).toFixed(2)} s`;
    }
    const label = state.mode === "native" ? "Solving natively"
                : state.mode === "wasm" ? "Solving with better wasm"
                : "Solving";
    const bits = [`${label} · ${state.challenge?.algorithm ?? ""} · difficulty ${state.challenge?.difficulty ?? "?"}`];
    if (state.rate) bits.push(humanRate(state.rate));
    if (state.threads) bits.push(`${state.threads} threads`);
    if (state.phase === "error") bits.push(String(state.error ?? "failed").slice(0, 48));
    else if (pct) bits.push(`${pct.toFixed(0)}%`);
    return bits.join(" — ");
  }

  function paint(force) {
    const status = $("status");
    if (status) {
      const text = wantStatus();
      if (force || status.textContent !== text) status.textContent = text;
      status.style.display = "";
    }
    const progress = $("progress");
    const inner = progress?.querySelector?.(".bar-inner");
    const pct = state.phase === "done" ? 100 : Math.min(99, state.pct ?? 0);
    if (inner) inner.style.width = `${pct}%`;
    if (progress && progress.setAttribute) {
      progress.setAttribute("aria-valuenow", String(Math.round(pct)));
      progress.setAttribute("aria-valuemin", "0");
      progress.setAttribute("aria-valuemax", "100");
    }
    // if the page has no such elements (some Anubis versions), fall back to a panel
    if (!status && !progress) ensurePanel();
    if (panelRefs) {
      panelRefs.engine.textContent =
        state.mode === "native" ? `${state.kernel}`
        : state.mode === "wasm" ? `wasm · ${state.kernel}`
        : "page solver";
      panelRefs.fill.style.width = `${pct}%`;
      panelRefs.pct.textContent = `${pct.toFixed(0)}%`;
      panelRefs.rate.textContent = humanRate(state.rate);
    }
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
  }

  // ---- native mode -----------------------------------------------------

  browser.runtime.onMessage.addListener((message) => {
    if (!message) return;
    if (message.type === "anubis-native-progress") {
      const frame = message.frame ?? {};
      if (frame.event === "start") {
        state.mode = "native";
        state.kernel = frame.kernel ?? "native";
        state.rate = frame.rate ?? 0;
        state.estimateMs = frame.estimateMs ?? 0;
        state.threads = frame.threads ?? 0;
        state.started = performance.now();
        state.phase = "running";
      } else if (frame.event === "progress") {
        state.pct = frame.pct ?? 0;
        state.rate = frame.rate ?? state.rate;
      } else if (frame.event === "done") {
        state.phase = frame.ok ? "done" : "error";
        state.error = frame.error;
        state.elapsedMs = frame.elapsedMs ?? performance.now() - state.started;
        state.rate = frame.rate ?? state.rate;
        state.kernel = frame.kernel ?? state.kernel;
      }
      paint(true);
    } else if (message.type === "anubis-native-mode") {
      // the host is not there: pick the in-page kernel if we have one
      startFallback();
    }
  });

  // ---- wasm mode -------------------------------------------------------

  function baseUrl(path) {
    return browser.runtime.getURL(path);
  }

  function startFallback() {
    if (state.mode === "wasm" || state.mode === "page") return;
    const chal = state.challenge;
    if (!chal) return;
    const wasmName = WASM_FOR[chal.algorithm];
    if (!wasmName) {
      state.mode = "page";             // no kernel of ours for this algorithm
      state.kernel = "page wasm";
      state.phase = "running";
      paint(true);
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
        // the module would not load: leave Anubis's own solver to it
        state.mode = "page";
        state.kernel = "page wasm";
        state.phase = "running";
        paint(true);
        return;
      }
      if (msg.ok) {
        state.phase = "done";
        state.elapsedMs = msg.elapsedMs;
        paint(true);
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

  const chal = challenge();
  if (!chal) return;
  state.challenge = chal;
  state.mode = "native";             // until the host says otherwise
  state.phase = "running";
  watch();
  paint(true);
  browser.runtime
    .sendMessage({ type: "anubis-native-detected", challenge: chal })
    .catch(() => startFallback());
})();
