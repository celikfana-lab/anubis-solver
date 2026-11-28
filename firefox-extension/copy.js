// copy.js — the words the takeover puts on Anubis's own challenge page.
//
// Anubis renders "why am I seeing this" from its localization files
// (lib/challenge/challengepage/explanation.templ: a <details> with two <p>),
// and its credits in the main page's <footer> (web/index.templ: one <p> per
// line, the last one being the Anubis version). None of those paragraphs
// carry an id or a class, so this addresses them by position instead.
//
// The version line is deliberately left alone: "this website is running
// Anubis version X" is still true and useful when something goes wrong.
//
// Pure (no DOM) so test-copy.js can check the targeting without a browser.
(function (root) {
  "use strict";

  const COPY = {
    // Replaces simplified_explanation: Anubis's "a CAPTCHA, but your browser
    // does the work" paragraph.
    why:
      "This page is a Proof of Work check, and this time you did not have to " +
      "solve it: the Anubis Solver extension took the challenge and handed it " +
      "to a native solver on this machine, which returned the answer in " +
      "milliseconds instead of seconds.",
    // Replaces jshelter_note: the warning about plugins that break modern JS.
    plugins:
      "Because the work runs outside the page, extensions that block this " +
      "site's scripts (JShelter, NoScript and friends) do not get in the way: " +
      "the page's own JavaScript is cancelled on purpose and only the " +
      "challenge in the HTML is read.",
    // Replaces "Protected by Anubis From Techaro. Made with ❤️ in 🇨🇦."
    credit: "Project made by celikfana & DeepSeek. Made with ❤️ in 🇳🇱 & 🇨🇳.",
    // Replaces "Mascot design by CELPHASE."
    mascot: "Mascot design by ChatGPT.",
  };

  /**
   * What to overwrite, given the paragraphs the page actually has.
   *
   * @param {string[]} detailsTexts  textContent of each <p> in <details>
   * @param {string[]} footerTexts   textContent of each <p> in <footer>
   * @returns {{where: "details"|"footer", index: number, text: string}[]}
   */
  function plan(detailsTexts, footerTexts) {
    const d = detailsTexts || [];
    const f = footerTexts || [];
    const out = [];
    if (d.length >= 1) out.push({ where: "details", index: 0, text: COPY.why });
    if (d.length >= 2) out.push({ where: "details", index: 1, text: COPY.plugins });
    if (f.length >= 1) out.push({ where: "footer", index: 0, text: COPY.credit });
    if (f.length >= 2) {
      // the mascot credit is normally the second <p>; find it by its old name
      // so an imprint line or a moved paragraph does not get clobbered
      const i = f.findIndex((t) => /celphase/i.test(String(t)));
      out.push({ where: "footer", index: i >= 0 ? i : 1, text: COPY.mascot });
    }
    return out;
  }

  root.AnubisCopy = { COPY, plan };
  if (typeof module !== "undefined" && module.exports) module.exports = { COPY, plan };
})(typeof globalThis !== "undefined" ? globalThis : this);
