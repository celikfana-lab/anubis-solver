// background.js — the extension side of native messaging.
//
// Native messaging cannot be used from a content script, so the content script
// only extracts the challenge and everything else happens here.
//
// Flow: toolbar click -> read the challenge from the active tab -> ask the native
// host to solve it with libanubis_solver.so -> navigate the tab to the
// pass-challenge URL. The point is the engine: the in-page solver is single-core
// WebAssembly, while the native host uses the SHA-NI/AVX2 kernels and every core.

const HOST = "anubis_solver";
const PASS_PATH = "/.within.website/x/cmd/anubis/api/pass-challenge";

async function activeTab() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  return tab ?? null;
}

async function readChallenge(tabId) {
  const [result] = await browser.tabs.executeScript(tabId, { file: "content.js" });
  return result ?? null;
}

async function nativeInfo() {
  return browser.runtime.sendNativeMessage(HOST, { cmd: "info" });
}

async function nativeSolve(algorithm, randomData, difficulty) {
  const started = performance.now();
  const reply = await browser.runtime.sendNativeMessage(HOST, {
    cmd: "solve",
    algorithm,
    randomData,
    difficulty,
  });
  reply.wallMs = performance.now() - started;
  return reply;
}

function passUrl(tab, challenge, solution, elapsedMs) {
  const url = new URL(PASS_PATH, tab.url);
  url.searchParams.set("id", challenge.id);
  url.searchParams.set("response", solution.response);
  url.searchParams.set("nonce", String(solution.nonce));
  url.searchParams.set("redir", tab.url);
  url.searchParams.set("elapsedTime", String(Math.max(1, Math.round(elapsedMs))));
  return url.toString();
}

browser.browserAction.onClicked.addListener(async () => {
  const tab = await activeTab();
  if (!tab || !tab.id) return;

  let challenge;
  try {
    challenge = await readChallenge(tab.id);
  } catch (err) {
    // activeTab is not granted on privileged pages (about:, the add-on store…)
    return notify("cannot read this page", String(err));
  }

  if (!challenge) return notify("no challenge here", "This page is not showing an Anubis challenge.");
  if (challenge.error) return notify("challenge parse failed", challenge.error);
  if (!challenge.randomData || challenge.difficulty == null) {
    return notify("unsupported page", "The challenge has no randomData/difficulty.");
  }

  let info;
  try {
    info = await nativeInfo();
  } catch (err) {
    return notify("native host not reachable", withInstallHint(String(err)));
  }

  try {
    const solution = await nativeSolve(challenge.algorithm, challenge.randomData, challenge.difficulty);
    if (!solution.ok) return notify("solver error", solution.error ?? "unknown");

    // navigate to the pass URL: the server sets the cookie and redirects back
    await browser.tabs.update(tab.id, { url: passUrl(tab, challenge, solution, solution.wallMs) });
    notify(
      `solved with the native engine in ${solution.elapsedMs.toFixed(1)} ms`,
      `libanubis_solver ${info.version} · ${info.threads} threads · ${solution.algorithm} difficulty ${challenge.difficulty}\n` +
      `nonce ${solution.nonce} · ${solution.wallMs.toFixed(1)} ms end to end`,
    );
  } catch (err) {
    notify("solve failed", String(err));
  }
});

function withInstallHint(message) {
  if (!/No such native application|not found/i.test(message)) return message;
  return `${message}\n\nRun firefox-extension/install.sh, then restart Firefox.`;
}

function notify(title, message) {
  // notifications are best-effort: the call itself can fail on some desktops
  browser.notifications.create({
    type: "basic",
    title,
    message: message ?? "",
  }).catch(() => {});
  console.log(`[anubis-native] ${title} — ${message ?? ""}`);
}
