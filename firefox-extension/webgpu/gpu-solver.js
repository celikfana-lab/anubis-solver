// gpu-solver.js — the Anubis sha256 challenge on WebGPU, for the extension.
//
// This is the WebGPU side of content.js: probe once, self-check against a
// reference implementation, then scan nonces in batches and re-derive every
// hit with WebCrypto before it is sent anywhere. The shader is
// webgpu/sha256.wgsl, the same module the webgpu/ page measures; the layout of
// the message and the nonce byte order are the ones the C core and the wasm
// kernels use:
//
//   message  = challenge bytes || 4-byte nonce
//   order    = little-endian if the challenge's last byte is >= 0x80, else big
//   hit      = the digest has `difficulty` leading zero bits
//   response = the 32 digest bytes as hex (what pass-challenge wants)
//
// Loaded as a classic content script before content.js, so it only publishes
// one global. The pure helpers are exported for node when it is run there
// (test-webgpu.js checks the nonce placement against node's crypto).
(function (root) {
  "use strict";

  const LANES = 4;            // nonces per invocation, must match the shader
  const THREADS = 64;         // @workgroup_size
  const N_PER_GROUP = LANES * THREADS;
  const RESULTS_U32 = 76;     // 4 header + 8 nonces + 64 hash words
  const DEFAULT_CHUNK = 1 << 22;

  const bytes = (h) => new Uint8Array((h.match(/../g) ?? []).map((x) => parseInt(x, 16)));
  const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

  /**
   * Padded message words for a challenge, with the four nonce bytes left zero,
   * plus the shifts and masks the shader uses to drop the nonce in. Same math
   * as webgpu/sha256.html and wasm/sha256_pow.c, both nonce byte orders.
   */
  function template(challengeHex) {
    const ch = bytes(challengeHex);
    if (!ch.length) throw new Error("empty challenge");
    const len = ch.length;
    const total = len + 4;
    const blocks = Math.ceil((total + 9) / 64);
    const msg = new Uint8Array(blocks * 64);
    msg.set(ch, 0);
    msg[len + 4] = 0x80;
    const bits = BigInt(total) * 8n;
    for (let i = 0; i < 8; i++) msg[blocks * 64 - 1 - i] = Number((bits >> BigInt(8 * i)) & 255n);

    const words = new Uint32Array(blocks * 16);
    for (let i = 0; i < words.length; i++) {
      words[i] = ((msg[4 * i] << 24) | (msg[4 * i + 1] << 16) | (msg[4 * i + 2] << 8) | msg[4 * i + 3]) >>> 0;
    }

    const r = len & 3;
    const wpA = len >>> 2;
    let wpB = 0xffffffff, keepA = 0, shiftA = 0, keepB = 0, shiftB = 0;
    if (r > 0) {
      const b = 4 - r;
      keepA = (0xffffffff << (8 * b)) >>> 0;
      shiftA = 8 * r;
      wpB = wpA + 1;
      keepB = (1 << (8 * r)) - 1;
      shiftB = 8 * b;
    }
    const swap = ch[len - 1] >= 0x80 ? 1 : 0;
    return { challengeHex, len, blocks, words, wpA, wpB, keepA, shiftA, keepB, shiftB, swap };
  }

  /** Digest words -> hex, big-endian (SHA-256 state words in order). */
  const digestHex = (w) => Array.from(w, (x) => (x >>> 0).toString(16).padStart(8, "0")).join("");

  /** The message the shader hashes, for checking it against WebCrypto. */
  function message(challengeHex, nonce) {
    const ch = bytes(challengeHex);
    const n = (nonce >>> 0);
    const le = ch[ch.length - 1] >= 0x80;
    const out = new Uint8Array(ch.length + 4);
    out.set(ch, 0);
    const b = le ? [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]
                 : [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
    out.set(b, ch.length);
    return out;
  }

  async function referenceDigest(challengeHex, nonce) {
    const d = await crypto.subtle.digest("SHA-256", message(challengeHex, nonce));
    return new Uint8Array(d);
  }

  function hitsFrom(u32) {
    const total = u32[0];
    const hits = [];
    for (let s = 0; s < Math.min(8, total); s++) {
      hits.push({ nonce: u32[4 + s], words: Array.from(u32.slice(12 + s * 8, 12 + s * 8 + 8)) });
    }
    return { total, hits };
  }

  // ---- device ---------------------------------------------------------

  let device = null, pipeline = null, bind = null;
  let paramsBuf, resultsBuf, msgBuf, readBuf, limits = null, adapterInfo = "";

  async function probe(opts) {
    const want = (opts && opts.checks) || 4;
    if (!root.navigator?.gpu) return { ok: false, why: "navigator.gpu is missing" };
    let adapter;
    try {
      adapter = await root.navigator.gpu.requestAdapter({ powerPreference: "high-performance" });
    } catch (e) {
      return { ok: false, why: `requestAdapter threw: ${e}` };
    }
    if (!adapter) return { ok: false, why: "no adapter" };
    const info = adapter.info ?? {};
    adapterInfo = [info.vendor, info.architecture, info.description || info.device].filter(Boolean).join(" · ") || "gpu";

    try {
      device = await adapter.requestDevice();
    } catch (e) {
      return { ok: false, why: `requestDevice threw: ${e}` };
    }
    device.addEventListener("uncapturederror", (e) => console.warn("[anubis-gpu]", e.error?.message));
    limits = {
      maxComputeWorkgroupsPerDimension: device.limits.maxComputeWorkgroupsPerDimension,
      maxStorageBufferBindingSize: device.limits.maxStorageBufferBindingSize,
      maxPerDispatch: Math.min(device.limits.maxComputeWorkgroupsPerDimension * N_PER_GROUP, 1 << 26),
    };

    // The shader has to compile here; SwiftShader and some drivers reject it.
    const code = await (await fetch(chromeUrl("webgpu/sha256.wgsl"))).text();
    const module = device.createShaderModule({ code, label: "anubis-sha256" });
    const ci = module.getCompilationInfo ? await module.getCompilationInfo() : { messages: [] };
    const errs = (ci.messages ?? []).filter((m) => m.type === "error");
    if (errs.length) return { ok: false, why: `shader: ${errs[0].message}` };

    try {
      pipeline = device.createComputePipeline({ layout: "auto", compute: { module, entryPoint: "main" } });
      paramsBuf = device.createBuffer({ size: 48, usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST });
      resultsBuf = device.createBuffer({ size: RESULTS_U32 * 4, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST });
      msgBuf = device.createBuffer({ size: 4096, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
      readBuf = device.createBuffer({ size: RESULTS_U32 * 4, usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST });
      bind = device.createBindGroup({
        layout: pipeline.getBindGroupLayout(0),
        entries: [
          { binding: 0, resource: { buffer: paramsBuf } },
          { binding: 1, resource: { buffer: resultsBuf } },
          { binding: 2, resource: { buffer: msgBuf } },
        ],
      });
    } catch (e) {
      return { ok: false, why: `pipeline: ${e}` };
    }

    // Known-answer test against WebCrypto: both byte orders, nonzero nonces.
    // A backend that miscompiles the shader returns wrong digests, not slow
    // ones, so nothing is dispatched before this passes.
    const chal = "6a1f8c2e4d0b9a7f3c5e2d1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d";
    const chalLe = chal.slice(0, -2) + "fd";
    const checks = [[chal, 1], [chal, 0xdeadbeef], [chalLe, 1], [chalLe, 0xdeadbeef]].slice(0, want);
    let bad = 0;
    try {
      for (const [c, nonce] of checks) {
        const tpl = template(c);
        const { u32 } = await dispatch(tpl, nonce, 4, 0);
        const hit = hitsFrom(u32).hits.find((h) => h.nonce === (nonce >>> 0));
        const mine = hit ? digestHex(hit.words) : "(missing)";
        const theirs = hex(await referenceDigest(c, nonce));
        if (mine !== theirs) bad++;
      }
    } catch (e) {
      return { ok: false, why: `self-check threw: ${e}` };
    }
    if (bad) return { ok: false, why: `${bad}/${checks.length} digests differ from WebCrypto` };
    return { ok: true, adapter: adapterInfo, limits, why: `${checks.length} known answers match` };
  }

  async function dispatch(tpl, base, count, difficulty) {
    device.queue.writeBuffer(msgBuf, 0, tpl.words);
    device.queue.writeBuffer(paramsBuf, 0, new Uint32Array([
      base >>> 0, count >>> 0, difficulty >>> 0, tpl.blocks,
      tpl.wpA, tpl.wpB, tpl.keepA, tpl.shiftA, tpl.keepB, tpl.shiftB, tpl.swap, 0,
    ]));
    device.queue.writeBuffer(resultsBuf, 0, new Uint32Array(RESULTS_U32));
    const groups = Math.ceil(count / N_PER_GROUP);
    const t0 = performance.now();
    const enc = device.createCommandEncoder();
    const pass = enc.beginComputePass();
    pass.setPipeline(pipeline);
    pass.setBindGroup(0, bind);
    pass.dispatchWorkgroups(groups);
    pass.end();
    enc.copyBufferToBuffer(resultsBuf, 0, readBuf, 0, RESULTS_U32 * 4);
    device.queue.submit([enc.finish()]);
    await device.queue.onSubmittedWorkDone();
    const ms = performance.now() - t0;
    await readBuf.mapAsync(GPUMapMode.READ);
    const u32 = new Uint32Array(readBuf.getMappedRange()).slice(0);
    readBuf.unmap();
    return { u32, ms, groups };
  }

  /**
   * Scan nonces from 0 until one qualifies. Calls onProgress({nonces, ms,
   * rate, pct}) after every chunk. Returns {ok, nonce, response, elapsedMs,
   * nonces, rate} or {ok:false, error}.
   */
  async function solve(challengeHex, difficulty, onProgress) {
    if (!pipeline) return { ok: false, error: "probe() was not called or failed" };
    const tpl = template(challengeHex);
    const chunk = Math.min(DEFAULT_CHUNK, limits.maxPerDispatch);
    const t0 = performance.now();
    let base = 0, rate = 0;

    for (;;) {
      const n = Math.min(chunk, 0xffffffff - base);
      const { u32, ms } = await dispatch(tpl, base, n, difficulty);
      const got = hitsFrom(u32);
      const done = base + n;
      const chunkRate = n / Math.max(ms, 1) * 1000;
      rate = rate ? rate * 0.7 + chunkRate * 0.3 : chunkRate;

      if (got.total > 0) {
        // Never trust the GPU: re-derive every hit with WebCrypto.
        for (const h of got.hits) {
          const ref = await referenceDigest(challengeHex, h.nonce);
          if (digestHex(h.words) === hex(ref)) {
            if (onProgress) onProgress({ nonces: done, ms, rate, pct: 100 });
            return { ok: true, nonce: h.nonce, response: hex(ref), elapsedMs: performance.now() - t0, nonces: done, rate };
          }
        }
      }

      const expectedMs = Math.pow(2, difficulty) / Math.max(rate, 1) * 1000;
      const pct = Math.min(99, (performance.now() - t0) / Math.max(expectedMs, 1) * 100);
      if (onProgress) onProgress({ nonces: done, ms, rate, pct });
      base = done;
      if (base >= 0xffffffff) return { ok: false, error: "nonce space exhausted" };
    }
  }

  function chromeUrl(path) {
    if (root.browser?.runtime?.getURL) return root.browser.runtime.getURL(path);
    return new URL(path, root.location?.href ?? "http://localhost/").toString();
  }

  root.AnubisWebGPU = { probe, solve, template, message, digestHex, hitsFrom, referenceDigest };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { template, message, digestHex, hitsFrom };
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
