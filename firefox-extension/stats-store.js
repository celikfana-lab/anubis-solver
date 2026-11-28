// stats-store.js — the solve history the toolbar panel draws.
//
// One entry per accepted solution, wherever it came from: the native host
// (background.js), WebGPU or the wasm worker (content.js). Kept in
// browser.storage.local so it survives restarts, capped so it cannot grow
// without bound.
//
// "Time saved" is an estimate, and the panel says so: it compares our solve
// against the rate Anubis's own in-page solver gets for that algorithm. Those
// rates are measured, not assumed (SPEED.md):
//
//   sha256   1.9 M hashes/s   the simd128 module the challenge page ships
//   hashx    3.2 M hashes/s   the challenge compiled to wasm in the page
//   argon2id ~15 hashes/s     the page's own module
//
// A solve stops at the first qualifying nonce, so the comparison is noisy per
// solve; over a session the totals are the honest part.
(function (root) {
  "use strict";

  const KEY = "solves";
  const CAP = 500;

  // What the page's own solver does, per algorithm, in hashes/second.
  const PAGE_RATE = {
    sha256: 1.9e6,
    "wasm-sha256": 1.9e6,
    hashx: 3.2e6,
    argon2id: 15,
    fast: 0.36e6,
    slow: 0.36e6,
  };

  /** How long the page's own solver would have needed for this challenge. */
  function pageMs(algorithm, difficulty) {
    const rate = PAGE_RATE[algorithm];
    if (!rate || !(difficulty >= 0)) return null;
    return (Math.pow(2, difficulty) / rate) * 1000;
  }

  /** Pure: fold entries into what the panel shows. */
  function summarize(entries) {
    const list = Array.isArray(entries) ? entries.filter((e) => e && e.ms >= 0) : [];
    const out = {
      count: list.length,
      totalMs: 0,
      savedMs: 0,
      compared: 0,          // solves we could compare against the page
      engines: {},          // engine -> {n, totalMs, bestRate, rate}
      recent: [],
    };
    for (const e of list) {
      out.totalMs += e.ms;
      const expected = pageMs(e.algorithm, e.difficulty);
      if (expected != null && isFinite(expected)) {
        out.compared++;
        out.savedMs += Math.max(0, expected - e.ms);
      }
      const name = e.engine || "unknown";
      const slot = (out.engines[name] ||= { n: 0, totalMs: 0, bestRate: 0, rate: 0 });
      slot.n++;
      slot.totalMs += e.ms;
      if (e.rate > (slot.bestRate || 0)) slot.bestRate = e.rate;
      if (e.rate > 0) slot.rate = slot.rate ? (slot.rate + e.rate) / 2 : e.rate;
    }
    out.recent = list.slice(-24).reverse();
    return out;
  }

  function humanMs(ms) {
    if (!isFinite(ms) || ms <= 0) return "0 s";
    if (ms < 1000) return `${Math.round(ms)} ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(ms < 10000 ? 2 : 1)} s`;
    if (ms < 3600000) return `${(ms / 60000).toFixed(1)} min`;
    return `${(ms / 3600000).toFixed(2)} h`;
  }

  function humanRate(hps) {
    if (!hps || !isFinite(hps)) return "";
    if (hps >= 1e9) return `${(hps / 1e9).toFixed(2)} GH/s`;
    if (hps >= 1e6) return `${(hps / 1e6).toFixed(1)} MH/s`;
    if (hps >= 1e3) return `${(hps / 1e3).toFixed(0)} kH/s`;
    return `${Math.round(hps)} H/s`;
  }

  // ---- storage -------------------------------------------------------

  const api = (root.browser && root.browser.storage && root.browser.storage.local) || null;

  async function all() {
    if (!api) return [];
    try {
      const got = await api.get(KEY);
      return Array.isArray(got[KEY]) ? got[KEY] : [];
    } catch {
      return [];
    }
  }

  async function record(entry) {
    if (!entry || !(entry.ms >= 0)) return;
    const row = {
      at: entry.at || Date.now(),
      algorithm: String(entry.algorithm || "sha256"),
      difficulty: Number(entry.difficulty) || 0,
      engine: String(entry.engine || "unknown"),
      ms: Number(entry.ms) || 0,
      rate: Number(entry.rate) || 0,
      url: String(entry.url || "").slice(0, 300),
    };
    const rows = await all();
    rows.push(row);
    while (rows.length > CAP) rows.shift();
    try {
      await api.set({ [KEY]: rows });
    } catch {
      /* storage full or blocked: the panel is not worth failing a solve over */
    }
  }

  async function clear() {
    if (!api) return;
    try {
      await api.remove(KEY);
    } catch {
      /* ignore */
    }
  }

  root.AnubisStats = { record, all, clear, summarize, pageMs, humanMs, humanRate, PAGE_RATE };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = { pageMs, summarize, humanMs, humanRate, PAGE_RATE };
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
