// look.js — which mascot and headline the takeover uses.
//
// The page's own solver cannot start (its wasm is cancelled), so it paints its
// "Calculation error!" state; the extension replaces that art and headline with
// its own. One page in a thousand gets the other look instead.
//
// Kept out of content.js so the choice can be tested without a DOM:
// ?anubis-easter=1 or =0 on the page URL forces either look.
(function (root) {
  "use strict";

  const LOOKS = [
    { mascot: "mascot/anti-anti-ai.webp", title: "Hijacked Anubis" },
    { mascot: "mascot/deepseek-chan.webp", title: "what is the point of life? to like and sub" },
  ];
  const EASTER_ODDS = 1 / 1000;

  /**
   * @param {string} search  location.search (may be missing the leading ?)
   * @param {() => number} [rand]  0..1 source, defaults to Math.random
   */
  function pickLook(search, rand) {
    const forced = new URLSearchParams(search || "").get("anubis-easter");
    if (forced === "0") return LOOKS[0];
    if (forced === "1") return LOOKS[1];
    const roll = (rand || Math.random)();
    return roll < EASTER_ODDS ? LOOKS[1] : LOOKS[0];
  }

  root.AnubisLook = { pickLook, LOOKS, EASTER_ODDS };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = { pickLook, LOOKS, EASTER_ODDS };
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
