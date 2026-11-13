// content.js — pull the Anubis challenge out of the page.
//
// Anubis renders it as <script id="anubis_challenge" type="application/json">.
// This runs inside the page (activeTab grant), returns the parsed payload, and
// touches nothing else.
(() => {
  const el = document.getElementById("anubis_challenge");
  if (!el) return null;
  try {
    const payload = JSON.parse(el.textContent);
    return {
      algorithm: payload?.rules?.algorithm ?? payload?.challenge?.method ?? null,
      difficulty: payload?.rules?.difficulty ?? null,
      randomData: payload?.challenge?.randomData ?? null,
      id: payload?.challenge?.id ?? null,
    };
  } catch (err) {
    return { error: String(err) };
  }
})();
