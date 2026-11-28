// block.js — what of Anubis's own solver we refuse to load.
//
// web/static/js/main.mjs does this, for sha256/hashx/argon2id:
//
//   fetch(`${basePrefix}/.within.website/x/cmd/anubis/static/wasm/${simd}/${alg}.wasm?cacheBuster=…`)
//   WebAssembly.compileStreaming(that response)
//   new Worker(`${basePrefix}/.within.website/x/cmd/anubis/static/js/worker/wasm.mjs`)
//   worker.postMessage({ …, module })
//
// so the module is fetched by the page, not by the worker: cancelling that one
// request stops the in-page miner before it compiles anything. For fast/slow
// the worker is sha256.mjs and there is no module to cancel — those tiers are
// left to the page, which is why the extension only takes over hashx/sha256.
//
// The path is absolute: Anubis's APIPrefix lives at the site root even when the
// protected site is served under a base prefix.
(function (root) {
  "use strict";

  // Anubis builds the URL from its base prefix, so the prefix may come first:
  // `/sub/.within.website/x/cmd/anubis/...` is a real shape when the site is
  // mounted under a prefix.
  const SOLVER_WASM =
    /(?:^|\/)\.within\.website\/x\/cmd\/anubis\/static\/wasm\/[^/]+\/[^/]+\.wasm$/i;

  /** True for the wasm module Anubis's challenge page would mine with. */
  function isAnubisSolver(url) {
    try {
      return SOLVER_WASM.test(new URL(url, "http://x/").pathname);
    } catch {
      return false;
    }
  }

  root.AnubisBlock = { isAnubisSolver };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { isAnubisSolver };
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
