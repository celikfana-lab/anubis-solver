#!/usr/bin/env node
// test-copy.js -- the text the takeover puts over Anubis's own challenge page.
//
// Anubis's explanation and credits live in paragraphs with no id or class
// (lib/challenge/challengepage/explanation.templ, web/index.templ), so the
// takeover targets them by position. That means the targeting itself is worth
// checking: the last footer paragraph is the Anubis version line and must
// survive, and a page without <details> must not get half a rewrite.
//
//   node firefox-extension/test-copy.js
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { COPY, plan } = require("./copy.js");

let checks = 0;
let fails = 0;
function check(what, ok, detail) {
  checks++;
  if (!ok) fails++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${what}${ok || !detail ? "" : ` - ${detail}`}`);
}

// the real page, as Anubis v1.28.x renders it in English
const DETAILS = [
  "This is a measure against bots and malicious requests similar to a CAPTCHA. However, instead of having to do work yourself, your browser is given a calculation task that it has to solve to ensure that it is a valid client. This concept is called Proof of Work. The task is calculated in a few seconds and you are granted access to the website. Thank you for your understanding and patience.",
  "Please note that Anubis requires the use of modern JavaScript features that plugins like JShelter will disable. Please disable JShelter or other such plugins for this domain.",
];
const FOOTER = [
  "Protected by Anubis From Techaro. Made with \u2764\ufe0f in \ud83c\udde8\ud83c\udde6.",
  "Mascot design by CELPHASE.",
  "This website is running Anubis version v1.28.3-0.20261122190339-0a6c5d68e0cd.",
];

console.log("the copy");
check("four replacements", Object.keys(COPY).length === 4, Object.keys(COPY).join(","));
for (const [k, v] of Object.entries(COPY)) {
  check(`${k}: non-empty`, typeof v === "string" && v.trim().length > 20, String(v).slice(0, 40));
}
check("explanation talks about the solver", /solver/i.test(COPY.why));
check("plugins note points at the native solver", /outside the page/i.test(COPY.plugins));
check("credit names celikfana and DeepSeek", /celikfana/.test(COPY.credit) && /DeepSeek/.test(COPY.credit));
check("credit carries both flags", COPY.credit.includes("\ud83c\uddf3\ud83c\uddf1") && COPY.credit.includes("\ud83c\udde8\ud83c\uddf3"));
check("mascot credit is ChatGPT", COPY.mascot === "Mascot design by ChatGPT.");

console.log("targeting the real page");
const targets = plan(DETAILS, FOOTER);
check("four paragraphs replaced", targets.length === 4, JSON.stringify(targets.map((t) => [t.where, t.index])));
check("both explanation paragraphs", targets.filter((t) => t.where === "details").map((t) => t.index).join(",") === "0,1");
check("both credit paragraphs", targets.filter((t) => t.where === "footer").map((t) => t.index).join(",") === "0,1");
check("nothing targets the version line", !targets.some((t) => t.where === "footer" && t.index === 2));
check("version line is still the page's", /running Anubis version/.test(FOOTER[2]));

console.log("odd pages");
check("no details, no crash", plan([], FOOTER).length === 2);
check("no footer, no crash", plan(DETAILS, []).length === 2);
check("empty page does nothing", plan([], []).length === 0);
check("one footer paragraph", plan(DETAILS, [FOOTER[0]]).length === 3);
const moved = [FOOTER[0], "", "Mascot design by CELPHASE.", FOOTER[2]];
check("mascot credit found by name", plan(DETAILS, moved).some((t) => t.where === "footer" && t.index === 2));
check("missing CELPHASE falls back to the second line",
  plan(DETAILS, ["Protected by Anubis.", "Mascot design by nobody."]).some((t) => t.where === "footer" && t.index === 1));

if (fails) {
  console.log(`FAILED (${fails} of ${checks})`);
  process.exit(1);
}
console.log(`all ${checks} copy checks passed`);
