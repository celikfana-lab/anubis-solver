#!/usr/bin/env node
// test-look.js — the takeover's mascot and headline choice.
//
// One page in a thousand is supposed to get the alternate look, and both look
// like the same bug when it happens: the page's own solver died (we cancelled
// its wasm) and the extension paints over the wreckage. So the odds, the forced
// variants and the assets themselves are worth checking.
//
//   node firefox-extension/test-look.js
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { pickLook, LOOKS, EASTER_ODDS } = require(join(here, "look.js"));

let checks = 0;
let fails = 0;
function check(what, ok, detail) {
  checks++;
  if (!ok) fails++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${what}${ok || !detail ? "" : ` — ${detail}`}`);
}

console.log("odds");
check("one in a thousand", Math.abs(EASTER_ODDS - 0.001) < 1e-12, String(EASTER_ODDS));
check("just below the line is the easter egg", pickLook("", () => 0.0009) === LOOKS[1]);
check("exactly at the line is the normal look", pickLook("", () => 0.001) === LOOKS[0]);
check("above the line is the normal look", pickLook("", () => 0.5) === LOOKS[0]);
check("zero is the easter egg", pickLook("", () => 0) === LOOKS[1]);

// Over many draws the mix has to land near 1/1000, not "never" or "always".
let egg = 0;
const N = 200000;
for (let i = 0; i < N; i++) if (pickLook("", Math.random) === LOOKS[1]) egg++;
const share = egg / N;
check(`about 1/1000 over ${N} draws`, Math.abs(share - 0.001) < 0.0004, `${(share * 100).toFixed(3)}%`);

console.log("\nforced variants");
check("?anubis-easter=1", pickLook("?anubis-easter=1", () => 0.9) === LOOKS[1]);
check("?anubis-easter=0", pickLook("?anubis-easter=0", () => 0.0) === LOOKS[0]);
check("other query params do not matter", pickLook("?x=1&anubis-easter=1", () => 0.9) === LOOKS[1]);

console.log("\nthe looks");
check("two looks", LOOKS.length === 2);
check("every look has a title and a mascot", LOOKS.every((l) => l.title && l.mascot));
check("every mascot ships with the add-on", LOOKS.every((l) => existsSync(join(here, l.mascot))),
  LOOKS.filter((l) => !existsSync(join(here, l.mascot))).map((l) => l.mascot).join(", "));
check("the easter egg says the line", LOOKS[1].title === "what is the point of life? to like and sub", LOOKS[1].title);

console.log(`\n${checks - fails}/${checks} checks passed`);
process.exit(fails ? 1 : 0);
