// background.js — the extension side of native messaging.
//
// Native messaging cannot be used from a content script, so the content script
// only finds the challenge and draws; everything else happens here.
//
// Flow: the content script sees <script id="anubis_challenge"> -> this asks the
// native host over a *port* (so the host can stream progress frames) -> each
// frame is relayed to the tab's panel -> the final frame carries the nonce and
// this navigates to the pass URL.
//
// A port is used instead of sendNativeMessage because the host writes a frame
// every ~120 ms: one-shot messaging would take only the first and drop the rest.
//
// The point is the engine: the in-page solver is single-core WebAssembly, while
// the native host uses the SHA-NI/AVX2 kernels, every core, and an accelerator
// when one is available.
//
// The page's own solver is stopped at the network layer: once a tab has shown a
// challenge, its .wasm requests under /.within.website/ are cancelled, so the
// single-core in-page miner never starts and the progress bar is ours. If the
// page asks us to stand down (nothing of ours worked), the tab is unblocked.

const HOST = "anubis_solver";
const PASS_PATH = "/.within.website/x/cmd/anubis/api/pass-challenge";

/** tabId -> true while a native solve is running for that tab */
const solving = new Map();

/** tabIds whose challenge we took over: their own wasm module is cancelled */
const challenged = new Set();

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0 || !challenged.has(details.tabId)) return {};
    const url = details.url;
    // only the proof-of-work module: the page still needs its own scripts and
    // the pass-challenge navigation, which is not a sub-resource request.
    if (/\/\.within\.website\//.test(url) && /\.wasm($|\?)/i.test(url)) {
      console.log(`[anubis-native] blocked the page's wasm: ${url}`);
      return { cancel: true };
    }
    return {};
  },
  { urls: ["*://*/*"], types: ["script", "xmlhttprequest", "other", "object_subrequest"] },
  ["blocking"]
);

browser.tabs.onRemoved.addListener((tabId) => {
  challenged.delete(tabId);
  solving.delete(tabId);
});
browser.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "loading" || info.url) challenged.delete(tabId);
});

async function activeTab() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  return tab ?? null;
}

function passUrl(tabUrl, challenge, solution) {
  const url = new URL(PASS_PATH, tabUrl);
  url.searchParams.set("id", challenge.id ?? "");
  url.searchParams.set("response", solution.response);
  url.searchParams.set("nonce", String(solution.nonce));
  url.searchParams.set("redir", tabUrl);
  url.searchParams.set("elapsedTime", String(Math.max(1, Math.round(solution.elapsedMs))));
  return url.toString();
}

function relay(tabId, frame) {
  browser.tabs
    .sendMessage(tabId, { type: "anubis-native-progress", frame })
    .catch(() => {}); // the tab may already be navigating away
}

/** Solve one challenge for one tab, streaming progress back to its panel. */
function solveForTab(tabId, tabUrl, challenge) {
  if (solving.has(tabId)) return;
  solving.set(tabId, true);

  let port;
  try {
    port = browser.runtime.connectNative(HOST);
  } catch (err) {
    solving.delete(tabId);
    notify("native host not reachable", withInstallHint(String(err)));
    return;
  }

  let finished = false;

  port.onMessage.addListener((frame) => {
    relay(tabId, frame);
    if (frame.event !== "done") return;
    finished = true;
    solving.delete(tabId);
    try {
      port.disconnect();
    } catch {
      /* already gone */
    }
    if (frame.ok) {
      browser.tabs.update(tabId, { url: passUrl(tabUrl, challenge, frame) });
    } else {
      notify("solve failed", frame.error ?? "unknown error");
    }
  });

  port.onDisconnect.addListener(() => {
    solving.delete(tabId);
    if (finished) return;
    // Nothing came back: no host on this machine (Windows/macOS without
    // install.sh). Tell the page so it can use the wasm kernel in a Worker.
    relay(tabId, { event: "unavailable" });
    browser.tabs
      .sendMessage(tabId, { type: "anubis-native-mode", platform: platform() })
      .catch(() => {});
    const err = browser.runtime.lastError?.message ?? "the native host exited";
    relay(tabId, { event: "done", ok: false, error: err });
    notify("native host stopped", withInstallHint(err));
  });

  try {
    port.postMessage({
      cmd: "solve_stream",
      algorithm: challenge.algorithm,
      randomData: challenge.randomData,
      difficulty: challenge.difficulty,
    });
  } catch (err) {
    solving.delete(tabId);
    notify("could not ask the host", String(err));
  }
}

// The content script's auto-detection.
browser.runtime.onMessage.addListener((message, sender) => {
  if (!message) return;
  if (message.type === "anubis-unblock") {
    if (sender.tab?.id != null) challenged.delete(sender.tab.id);
    return;
  }
  if (message.type !== "anubis-native-detected") return;
  if (!sender.tab?.id) return;
  challenged.add(sender.tab.id);
  solveForTab(sender.tab.id, sender.tab.url, message.challenge);
});

// The toolbar button: re-run detection on the active tab (useful when the
// content script ran before the challenge element existed, or for a retry).
browser.browserAction.onClicked.addListener(async () => {
  const tab = await activeTab();
  if (!tab || !tab.id) return;
  if (solving.has(tab.id)) {
    notify("already solving", "the native host is working on this tab");
    return;
  }
  try {
    await browser.tabs.executeScript(tab.id, { file: "content.js" });
  } catch (err) {
    notify("cannot read this page", String(err));
  }
});

/** Where this browser is running: the native host is a per-OS install. */
function platform() {
  const p = (navigator.userAgentData?.platform || navigator.platform || "").toLowerCase();
  if (p.includes("win")) return "windows";
  if (p.includes("mac")) return "macos";
  if (p.includes("linux")) return "linux";
  return p || "unknown";
}

function withInstallHint(message) {
  if (!/No such native application|not found/i.test(message)) return message;
  return `${message}\n\nRun firefox-extension/install.sh, then restart Firefox.`;
}

function notify(title, message) {
  // notifications are best-effort: the call itself can fail on some desktops
  browser.notifications.create({ type: "basic", title, message: message ?? "" }).catch(() => {});
  console.log(`[anubis-native] ${title} — ${message ?? ""}`);
}
