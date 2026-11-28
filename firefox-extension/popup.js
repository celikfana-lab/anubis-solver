// popup.js — draw the panel: totals, a bar per engine, the recent solves.
//
// No chart library: two SVG blocks built from strings. Everything numeric comes
// from stats-store.js, which is also what the tests drive.
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const S = globalThis.AnubisStats;

  function esc(text) {
    return String(text).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }

  /** Horizontal bars: average rate per engine, MH/s. */
  function engineChart(engines) {
    const rows = Object.entries(engines)
      .map(([name, v]) => ({ name, rate: v.rate || v.bestRate || 0, n: v.n, best: v.bestRate || 0 }))
      .filter((r) => r.rate > 0)
      .sort((a, b) => b.rate - a.rate);
    if (!rows.length) return `<div class="empty">No speed recorded yet — solve once and this fills in.</div>`;

    const width = 356, labelW = 86, rowH = 20, pad = 4;
    const top = rows[0].rate;
    const height = rows.length * rowH + pad * 2;
    const parts = rows.map((r, i) => {
      const y = pad + i * rowH;
      const w = Math.max(2, ((width - labelW - 46) * r.rate) / top);
      return `
        <text class="lbl" x="0" y="${y + 12}">${esc(r.name)}</text>
        <rect x="${labelW}" y="${y + 2}" width="${w}" height="${rowH - 8}" rx="3" fill="#58c8ff" opacity="${0.55 + 0.45 * (r.rate / top)}"/>
        <text class="val" x="${labelW + w + 5}" y="${y + 12}">${S.humanRate(r.rate)}</text>`;
    }).join("");
    return `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="speed by engine">${parts}</svg>`;
  }

  /** Bars: the last solves, height = time, green = ours, grey = the page would have taken. */
  function recentChart(recent) {
    if (!recent.length) return `<div class="empty">Nothing yet.</div>`;
    const rows = recent.slice(0, 12).reverse();
    const width = 356, height = 74, gap = 4;
    const slot = (width - gap * (rows.length - 1)) / rows.length;
    const maxMs = Math.max(...rows.map((r) => Math.max(r.ms, S.pageMs(r.algorithm, r.difficulty) || 0)), 1);
    const bars = rows.map((r, i) => {
      const x = i * (slot + gap);
      const ours = Math.max(1, (height * r.ms) / maxMs);
      const page = S.pageMs(r.algorithm, r.difficulty);
      const pageH = page ? Math.max(1, (height * Math.min(page, maxMs)) / maxMs) : 0;
      const better = page ? r.ms < page : true;
      return `
        <rect x="${x}" y="${height - pageH}" width="${slot}" height="${pageH}" fill="#333b48"/>
        <rect x="${x}" y="${height - ours}" width="${slot}" height="${ours}" fill="${better ? "#8fe3a8" : "#e0a05a"}"/>
        <title>${esc(r.engine)} · ${esc(r.algorithm)} d${r.difficulty} · ${S.humanMs(r.ms)}${
          page ? ` (page ≈ ${S.humanMs(page)})` : ""}</title>`;
    }).join("");
    return `<svg viewBox="0 0 ${width} ${height + 12}" role="img" aria-label="recent solves">
      <line class="axis" x1="0" y1="${height}" x2="${width}" y2="${height}"/>
      ${bars}
      <text class="lbl" x="0" y="${height + 10}">last ${rows.length} solves — green beats the page, grey is what the page would have taken</text>
    </svg>`;
  }

  function recentList(recent) {
    if (!recent.length) return `<div class="empty">Nothing yet.</div>`;
    return `<ol>${recent.slice(0, 6).map((r) => `
      <li><span class="e">${esc(r.engine)}</span>
          <span class="m">${esc(r.algorithm)} d${r.difficulty} · ${S.humanMs(r.ms)}${
            r.rate ? ` · ${S.humanRate(r.rate)}` : ""}</span></li>`).join("")}</ol>`;
  }

  async function render() {
    const entries = await S.all();
    const sum = S.summarize(entries);

    $("version").textContent = browser.runtime.getManifest().version;
    $("count").textContent = String(sum.count);
    $("spent").textContent = S.humanMs(sum.totalMs);
    $("saved").textContent = sum.compared ? S.humanMs(sum.savedMs) : "—";

    const engines = Object.entries(sum.engines);
    if (engines.length) {
      const fastest = engines.sort((a, b) => (b[1].rate || 0) - (a[1].rate || 0))[0][0];
      $("fastest").textContent = fastest;
    } else {
      $("fastest").textContent = "—";
    }

    $("engines").innerHTML = engineChart(sum.engines);
    $("recent").innerHTML = recentChart(sum.recent) + recentList(sum.recent);
    $("note").textContent = sum.compared
      ? `"Saved" compares each solve with what Anubis's own in-page solver would have needed ` +
        `(${(S.PAGE_RATE.sha256 / 1e6).toFixed(1)} M hashes/s for sha256, ` +
        `${(S.PAGE_RATE.hashx / 1e6).toFixed(1)} M for hashx). One solve stops at its first hit, ` +
        `so the per-solve numbers are noisy; the totals are the useful part.`
      : `Nothing to compare against yet: solve a challenge and the panel fills in.`;
  }

  $("clear").addEventListener("click", async () => {
    await S.clear();
    await render();
  });

  $("resolve").addEventListener("click", async () => {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id != null) {
      try {
        await browser.tabs.executeScript(tab.id, { file: "content.js" });
      } catch (err) {
        console.warn("[anubis-solver] cannot inject here:", err);
      }
    }
    window.close();
  });

  render();
})();
