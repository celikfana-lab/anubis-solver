// content.js — find an Anubis challenge, show the native solver working.
//
// Runs at document_start on every page (the manifest asks for <all_urls>) and
// does nothing at all unless the page carries Anubis's challenge element, so an
// ordinary page pays one getElementById. When there is one, this:
//
//   1. parses it and asks the background script to solve it natively,
//   2. draws a panel with the engine that is actually working (avx512, avx2,
//      cpu, cuda, hashx, ...), the rate and a bar,
//   3. leaves the page alone; the background navigates to the pass URL when the
//      native host answers.
//
// The panel lives in a shadow root: Anubis ships its own styles and a nested
// shadow tree cannot be reached by them.
(() => {
  "use strict";

  const CHALLENGE_ID = "anubis_challenge";
  const PANEL_ID = "anubis-native-panel";
  let panel = null;

  function challenge() {
    const el = document.getElementById(CHALLENGE_ID);
    if (!el) return null;
    try {
      const payload = JSON.parse(el.textContent);
      const rules = payload?.rules ?? {};
      const chal = payload?.challenge ?? {};
      const difficulty = rules.difficulty ?? chal.difficulty ?? null;
      const randomData = chal.randomData ?? rules.randomData ?? null;
      if (difficulty == null || !randomData) return null;
      return {
        algorithm: rules.algorithm ?? chal.method ?? "sha256",
        difficulty: Number(difficulty),
        randomData: String(randomData),
        id: chal.id ?? "",
      };
    } catch {
      return null;
    }
  }

  const CSS = `
    :host { all: initial; }
    .panel {
      position: fixed; right: 18px; bottom: 18px; z-index: 2147483647;
      width: 300px; padding: 12px 14px; border-radius: 12px;
      background: #1c1f26; color: #e8eaf0; border: 1px solid #3a4150;
      font: 13px/1.4 ui-sans-serif, system-ui, sans-serif;
      box-shadow: 0 10px 30px rgba(0,0,0,.45);
    }
    .title { display: flex; justify-content: space-between; align-items: baseline; }
    .title b { font-size: 13px; letter-spacing: .2px; }
    .engine { color: #8fe3a8; font-family: ui-monospace, monospace; font-size: 12px; }
    .bar { height: 8px; margin: 10px 0 6px; border-radius: 999px; background: #2a303c; overflow: hidden; }
    .fill { height: 100%; width: 0%; border-radius: 999px;
            background: linear-gradient(90deg, #58c8ff, #8fe3a8); transition: width .15s linear; }
    .meta { display: flex; justify-content: space-between; color: #9aa3b2;
            font-family: ui-monospace, monospace; font-size: 11.5px; }
    .done .fill { background: linear-gradient(90deg, #8fe3a8, #b7ff99); }
    .done .engine { color: #b7ff99; }
    .err .fill { background: #ff7a7a; }
    .err .engine { color: #ff9a9a; }
  `;

  function ensurePanel() {
    if (panel) return panel;
    const host = document.createElement("div");
    host.id = PANEL_ID;
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = CSS;
    const box = document.createElement("div");
    box.className = "panel";
    box.innerHTML = `
      <div class="title"><b>anubis-solver</b><span class="engine">connecting…</span></div>
      <div class="bar"><div class="fill"></div></div>
      <div class="meta"><span class="pct">0%</span><span class="rate">—</span><span class="time">—</span></div>
    `;
    root.append(style, box);
    document.documentElement.appendChild(host);
    panel = {
      host,
      box,
      engine: box.querySelector(".engine"),
      fill: box.querySelector(".fill"),
      pct: box.querySelector(".pct"),
      rate: box.querySelector(".rate"),
      time: box.querySelector(".time"),
    };
    return panel;
  }

  function humanRate(hps) {
    if (!hps || !isFinite(hps)) return "—";
    if (hps >= 1e9) return `${(hps / 1e9).toFixed(2)} GH/s`;
    if (hps >= 1e6) return `${(hps / 1e6).toFixed(2)} MH/s`;
    if (hps >= 1e3) return `${(hps / 1e3).toFixed(1)} kH/s`;
    return `${Math.round(hps)} H/s`;
  }

  function showStart(frame) {
    const p = ensurePanel();
    p.engine.textContent = `${frame.kernel ?? "native"} · difficulty ${frame.difficulty ?? "?"}`;
    p.rate.textContent = `${humanRate(frame.rate)} · ${frame.threads ?? "?"} threads`;
    p.time.textContent = `~${((frame.estimateMs ?? 0) / 1000).toFixed(0)} s`;
  }

  function showProgress(frame) {
    const p = ensurePanel();
    const pct = Math.max(0, Math.min(99, Number(frame.pct) || 0));
    p.fill.style.width = `${pct}%`;
    p.pct.textContent = `${pct.toFixed(0)}%`;
    p.rate.textContent = humanRate(frame.rate);
    p.time.textContent = `${((frame.elapsedMs ?? 0) / 1000).toFixed(1)} s`;
  }

  function showDone(frame) {
    const p = ensurePanel();
    p.box.classList.add(frame.ok ? "done" : "err");
    p.fill.style.width = "100%";
    p.pct.textContent = frame.ok ? "solved" : "failed";
    p.engine.textContent = frame.ok
      ? `${frame.kernel} · ${frame.algorithm}`
      : String(frame.error ?? "error").slice(0, 40);
    p.rate.textContent = frame.ok ? humanRate(frame.rate) : "";
    p.time.textContent = frame.ok ? `${(frame.elapsedMs / 1000).toFixed(2)} s` : "";
  }

  browser.runtime.onMessage.addListener((message) => {
    if (!message || message.type !== "anubis-native-progress") return;
    const frame = message.frame ?? {};
    if (frame.event === "start") showStart(frame);
    else if (frame.event === "progress") showProgress(frame);
    else if (frame.event === "done") showDone(frame);
  });

  const chal = challenge();
  if (!chal) return;
  // The page's own solver starts immediately too; ours is orders of magnitude
  // faster, so it wins the race and the page then navigates to the pass URL.
  browser.runtime.sendMessage({ type: "anubis-native-detected", challenge: chal })
    .catch(() => {});
})();
