#!/usr/bin/env node
// test-stats.js — the panel's arithmetic, without a browser.
//
// The numbers a user reads ("solves taken", "saved vs the page", "speed by
// engine") come from stats-store.js. That file is also loaded into the
// background and content scripts, so it has no DOM and its pure parts can be
// driven from node.
//
//   node firefox-extension/test-stats.js
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { pageMs, summarize, humanMs, humanRate, PAGE_RATE } = require(join(here, "stats-store.js"));

let checks = 0;
let fails = 0;
function check(what, ok, detail) {
  checks++;
  if (!ok) fails++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${what}${ok || !detail ? "" : ` — ${detail}`}`);
}
const near = (a, b, tol = 0.02) => Math.abs(a - b) <= Math.abs(b) * tol;

console.log("page-solver times");
check("sha256 d20 is ~552 ms at 1.9 MH/s", near(pageMs("sha256", 20), (2 ** 20 / 1.9e6) * 1000));
check("hashx d21 is ~656 ms at 3.2 MH/s", near(pageMs("hashx", 21), (2 ** 21 / 3.2e6) * 1000));
check("unknown algorithm has no comparison", pageMs("meatrider", 20) === null);
check("difficulty 0 is a valid comparison", pageMs("sha256", 0) > 0);

console.log("\nsummarize");
const rows = [
  { at: 1, algorithm: "sha256", difficulty: 20, engine: "vulkan", ms: 4, rate: 262e6 },
  { at: 2, algorithm: "sha256", difficulty: 20, engine: "vulkan", ms: 8, rate: 131e6 },
  { at: 3, algorithm: "sha256", difficulty: 20, engine: "wasm 4-wide", ms: 300, rate: 3.5e6 },
  { at: 4, algorithm: "sha256", difficulty: 20, engine: "webgpu Intel", ms: 12, rate: 87e6 },
  { at: 5, algorithm: "hashx", difficulty: 21, engine: "wasm 4-wide", ms: 4000, rate: 0 },
];
const sum = summarize(rows);
check("counts every solve", sum.count === 5, String(sum.count));
check("adds the time", sum.totalMs === 4 + 8 + 300 + 12 + 4000, String(sum.totalMs));
check("compares only known algorithms", sum.compared === 5, String(sum.compared));
check("groups by engine", Object.keys(sum.engines).length === 3);
check("vulkan took two", sum.engines.vulkan.n === 2);
check("vulkan keeps the best rate", sum.engines.vulkan.bestRate === 262e6);
check("recent is newest first", sum.recent[0].at === 5);
check("recent is capped at 24", summarize(Array.from({ length: 40 }, (_, i) => ({
  at: i, algorithm: "sha256", difficulty: 1, engine: "cpu", ms: 1, rate: 1e6 }))).recent.length === 24);

console.log("\nsavings");
const slow = summarize([{ at: 1, algorithm: "sha256", difficulty: 20, engine: "cpu", ms: 10_000, rate: 1e5 }]);
check("a slower solve saves nothing", slow.savedMs === 0, String(slow.savedMs));
const fast = summarize([{ at: 1, algorithm: "sha256", difficulty: 20, engine: "vulkan", ms: 4, rate: 262e6 }]);
check("a faster solve saves the difference", near(fast.savedMs, pageMs("sha256", 20) - 4, 0.001));
const unknown = summarize([{ at: 1, algorithm: "argon2id", difficulty: 4, engine: "wasm", ms: 50, rate: 0 }]);
check("argon2id uses its own page rate", near(unknown.savedMs, (2 ** 4 / PAGE_RATE.argon2id) * 1000 - 50, 0.001));
check("no comparison, no claim", summarize([{ at: 1, algorithm: "nope", difficulty: 9, engine: "x", ms: 5 }]).savedMs === 0);

console.log("\nformatting");
check("milliseconds", humanMs(250) === "250 ms", humanMs(250));
check("seconds", humanMs(2500) === "2.50 s", humanMs(2500));
check("minutes", humanMs(90000) === "1.5 min", humanMs(90000));
check("rates", humanRate(262e6) === "262.0 MH/s", humanRate(262e6));
check("empty rate", humanRate(0) === "");

console.log(`\n${checks - fails}/${checks} checks passed`);
process.exit(fails ? 1 : 0);
