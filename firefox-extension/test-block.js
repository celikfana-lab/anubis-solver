#!/usr/bin/env node
// test-block.js — does the block rule match what Anubis actually requests?
//
// Anubis's web/static/js/main.mjs builds its solver URLs from the page's own
// `anubis_base_prefix` and `anubis_version`, then fetches
//
//   ${basePrefix}/.within.website/x/cmd/anubis/static/wasm/${simd}/${alg}.wasm?cacheBuster=${version}
//
// with simd = simd128 when WebAssembly.validate() accepts the SIMD probe and
// baseline otherwise, and alg from the challenge. Those exact URL shapes are
// what firefox-extension/block.js has to recognise; a rule that misses them
// silently lets the page's miner run at full speed next to ours.
//
//   node firefox-extension/test-block.js
//   node firefox-extension/test-block.js --url http://127.0.0.1:8080/
//
// With --url it reads a live challenge page and rebuilds the URL the page is
// about to fetch, so the check is against the real server, not a guess.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { isAnubisSolver } = require(join(here, "block.js"));

let checks = 0;
let fails = 0;
function check(what, ok, detail) {
  checks++;
  if (!ok) fails++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${what}${ok || !detail ? "" : ` — ${detail}`}`);
}

const V = "v1.28.3-0.20261122190339-0a6c5d68e0cd";
const SHAPES = [
  ["simd128 sha256", `/ .within.website/x/cmd/anubis/static/wasm/simd128/sha256.wasm?cacheBuster=${V}`, true],
  ["baseline hashx", `/.within.website/x/cmd/anubis/static/wasm/baseline/hashx.wasm?cacheBuster=${V}`, true],
  ["baseline argon2id", `/.within.website/x/cmd/anubis/static/wasm/baseline/argon2id.wasm`, true],
  ["under a base prefix", `/sub/.within.website/x/cmd/anubis/static/wasm/simd128/sha256.wasm`, true],
  ["worker script (not the module)", `/.within.website/x/cmd/anubis/static/js/worker/wasm.mjs?cacheBuster=${V}`, false],
  ["fast/slow worker", `/.within.website/x/cmd/anubis/static/js/worker/sha256.mjs`, false],
  ["the wasm2js fallback worker", `/.within.website/x/cmd/anubis/static/js/worker/wasm2js.mjs`, false],
  ["css/image next to it", `/.within.website/x/cmd/anubis/static/img/reject.webp`, false],
  ["some other site's wasm", `/static/app.wasm`, false],
  ["a wasm dir listing", `/.within.website/x/cmd/anubis/static/wasm/simd128/`, false],
];

console.log("block rule against Anubis's solver URLs");
for (const [label, path, want] of SHAPES) {
  const got = isAnubisSolver(`https://example.com${path.replace(" ", "")}`);
  check(label, got === want, `expected ${want}, got ${got}`);
}

const urlFlag = process.argv.indexOf("--url");
if (urlFlag > 0 && process.argv[urlFlag + 1]) {
  const page = process.argv[urlFlag + 1];
  console.log(`\nlive check against ${page}`);
  let html;
  try {
    html = await (await fetch(page)).text();
  } catch (err) {
    check("page fetch", false, String(err));
    html = "";
  }
  const json = (id) => {
    const m = new RegExp(`id="${id}"[^>]*>\\s*(.*?)\\s*</script>`, "s").exec(html);
    return m ? JSON.parse(m[1]) : null;
  };
  const base = json("anubis_base_prefix");
  const version = json("anubis_version");
  const chal = json("anubis_challenge");
  check("page is an Anubis challenge", chal?.challenge?.randomData != null);
  if (chal?.challenge) {
    const alg = chal.rules?.algorithm ?? "sha256";
    for (const simd of ["simd128", "baseline"]) {
      const u = `${base ?? ""}/.within.website/x/cmd/anubis/static/wasm/${simd}/${alg}.wasm?cacheBuster=${version}`;
      const abs = new URL(u, page).toString();
      check(`the page's own ${simd}/${alg}.wasm URL is blocked`, isAnubisSolver(abs), abs);
    }
  }
}

console.log(`\n${checks - fails}/${checks} checks passed`);
process.exit(fails ? 1 : 0);
