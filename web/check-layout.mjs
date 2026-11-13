#!/usr/bin/env node
/**
 * check-layout.mjs — does any page overflow horizontally at phone width?
 *
 * The bottom of index.html is the last thing anyone looks at, and a single
 * unbreakable code token in a table cell is enough to make the whole page slide
 * sideways on a phone. That is invisible in a screenshot of the top of the page
 * and invisible in an HTML lint, so it gets its own check.
 *
 * No dependencies: Chrome is driven over the DevTools protocol with Node's
 * built-in WebSocket. Chrome is started here and killed on exit.
 *
 *   node web/check-layout.mjs                 # 390 px (a phone)
 *   node web/check-layout.mjs --width 768     # a tablet
 *   node web/check-layout.mjs --chrome /usr/bin/google-chrome --port 9222
 *
 * Exit status is 1 if any page overflows its viewport or any element sticks out.
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const flag = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
};

const WIDTH = Number(flag('width', 390));
const HEIGHT = Number(flag('height', 900));
const PORT = Number(flag('port', 9231));
/**
 * Find a Chrome, in the order the machines we care about install one. GitHub's
 * ubuntu runners and Debian both use "google-chrome"; snap and chromium packages
 * use the others.
 */
function findChrome() {
  const explicit = flag('chrome', process.env.CHROME);
  if (explicit) return explicit;
  const path = process.env.PATH ?? '';
  for (const name of ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser']) {
    for (const dir of path.split(':')) {
      if (dir && existsSync(join(dir, name))) return join(dir, name);
    }
  }
  for (const p of ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable']) {
    if (existsSync(p)) return p;
  }
  return null;
}

const CHROME = findChrome();
if (!CHROME) {
  console.error('no Chrome found: set CHROME=/path/to/chrome');
  process.exit(2);
}
const ORIGIN = flag('origin', 'http://127.0.0.1:8090');

const pages = readdirSync(HERE).filter((f) => f.endsWith('.html')).sort();
if (pages.length === 0) {
  console.error(`no HTML files in ${HERE}`);
  process.exit(2);
}

// Chrome refuses to start with a profile it cannot own, which is exactly the
// situation in CI, so it gets a throwaway one. The spawn error is captured rather
// than swallowed: "Chrome did not expose a page target" is not a useful thing to
// read when the real answer is "that binary does not exist".
const profile = mkdtempSync(join(tmpdir(), 'anubis-web-'));
const chrome = spawn(CHROME, [
  '--headless=new',
  '--disable-gpu',
  '--no-sandbox',
  '--no-first-run',
  '--disable-extensions',
  '--disable-dev-shm-usage',
  `--user-data-dir=${profile}`,
  `--remote-debugging-port=${PORT}`,
  `--window-size=${WIDTH},${HEIGHT}`,
  'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });

let spawnError = null;
chrome.on('error', (err) => { spawnError = err; });
chrome.stderr.on('data', (buf) => {
  const text = String(buf);
  if (spawnError === null && /not found|No such file/i.test(text)) spawnError = new Error(text.trim());
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let crashed = false;

async function findTarget() {
  for (let i = 0; i < 60; i++) {
    if (spawnError) throw spawnError;
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/json/list`);
      const list = await res.json();
      const page = list.find((t) => t.type === 'page');
      if (page?.webSocketDebuggerUrl) return page.webSocketDebuggerUrl;
    } catch {
      /* chrome is still starting */
    }
    await sleep(100);
  }
  throw new Error(`Chrome did not expose a page target on port ${PORT}`);
}

class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    ws.addEventListener('message', (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  static async connect(url) {
    const ws = new WebSocket(url);
    await new Promise((res, rej) => {
      ws.addEventListener('open', res, { once: true });
      ws.addEventListener('error', () => rej(new Error('websocket failed')), { once: true });
    });
    return new Cdp(ws);
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  async eval(expression) {
    const r = await this.send('Runtime.evaluate', {
      expression, returnByValue: true, awaitPromise: true,
    });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text);
    return r.result.value;
  }
}

const PROBE = `(() => {
  const vw = window.innerWidth;
  const doc = document.documentElement;
  const out = [];
  for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    if (r.right > vw + 1 || r.left < -1) {
      // a child of a horizontally scrollable box is allowed to stick out
      const scroller = el.closest('.table-scroll, pre');
      if (scroller) continue;
      // the skip link is parked off-screen on purpose until it is focused
      if (el.classList.contains('skip')) continue;
      out.push((el.tagName.toLowerCase()) +
        (el.className && typeof el.className === 'string' ? '.' + el.className.split(' ')[0] : '') +
        ' right=' + Math.round(r.right));
    }
  }
  return {
    loaded: location.protocol === 'http:' && !!document.querySelector('main'),
    href: location.href,
    title: document.title,
    h1: (document.querySelector('h1') || {}).textContent || '',
    viewport: vw,
    scrollWidth: doc.scrollWidth,
    overflows: out.slice(0, 5),
    count: out.length,
  };
})()`;

let failures = 0;
let notLoaded = 0;
try {
  const wsUrl = await findTarget();
  const cdp = await Cdp.connect(wsUrl);
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');

  console.log(`viewport ${WIDTH}x${HEIGHT}, ${pages.length} pages from ${ORIGIN}\n`);
  for (const page of pages) {
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: WIDTH < 500,
    });
    const url = `${ORIGIN}/${page}`;
    await cdp.send('Page.navigate', { url });
    for (let i = 0; i < 50; i++) {
      try {
        if (await cdp.eval('document.readyState') === 'complete') break;
      } catch { /* still navigating */ }
      await sleep(60);
    }
    await sleep(80);
    const r = await cdp.eval(PROBE);
    // A page that did not load has no overflow either, so check that first:
    // running this against a server that is not up must not report success.
    if (!r.loaded) {
      failures++;
      notLoaded++;
      console.log(`FAIL ${page.padEnd(18)} did not load: at ${r.href} ` +
                  `(${r.title || 'no title'}) — is ${ORIGIN} serving the site directory?`);
      continue;
    }
    const bad = r.count > 0 || r.scrollWidth > r.viewport + 1;
    if (bad) failures++;
    const tag = bad ? 'FAIL' : 'ok  ';
    console.log(`${tag} ${page.padEnd(18)} scrollWidth=${r.scrollWidth} viewport=${r.viewport}` +
                (bad ? `  ${r.count} element(s) outside: ${r.overflows.join(', ')}` : ''));
  }
  if (notLoaded) {
    console.log(`\n${notLoaded} page(s) did not load at all; fix that before reading the rest`);
  } else {
    console.log(failures === 0
      ? '\nno horizontal overflow at this width'
      : `\n${failures} page(s) overflow`);
  }
} catch (err) {
  console.error(`layout check could not run: ${err.message}`);
  console.error(`is ${ORIGIN} serving? start it with: cd web && make serve`);
  failures = 2;
  crashed = true;
} finally {
  chrome.kill('SIGKILL');
}

process.exit(crashed ? 2 : (failures === 0 ? 0 : 1));
