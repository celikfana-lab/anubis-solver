/**
 * webgpu-run.mjs — load a page in headless Chrome and print a JS value it sets.
 *
 * WebGPU does not exist in Node, so anything WebGPU has to run in a browser.
 * Chrome is driven over the DevTools protocol with Node's built-in WebSocket, so
 * there are no dependencies. The page is expected to set `window.__result` (or
 * whatever global you name) and this waits for it.
 *
 *   node tools/webgpu-run.mjs URL EXPRESSION [chrome flags...]
 *
 * The flags matter: without --enable-features=Vulkan --use-angle=vulkan
 * --use-vulkan=native, Chrome falls back to SwiftShader, a CPU emulator, and
 * every number you measure is meaningless.
 */
import { spawn } from 'node:child_process';
const [url, expr, ...flags] = process.argv.slice(2);
if (!url || !expr) {
  console.error('usage: node tools/webgpu-run.mjs URL EXPRESSION [chrome flags...]');
  process.exit(2);
}
const PORT = 9261;
const chrome = spawn('/usr/bin/google-chrome', [
  '--headless=new', '--no-sandbox', '--no-first-run', '--disable-dev-shm-usage',
  `--user-data-dir=${process.env.TMPDIR ?? '/tmp'}/webgpu-${Date.now()}`, `--remote-debugging-port=${PORT}`,
  '--window-size=1280,900', ...flags, 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });
let err = '';
chrome.stderr.on('data', (b) => { err += String(b); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let wsUrl;
for (let i = 0; i < 80; i++) {
  try { const l = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
    const p = l.find((t) => t.type === 'page'); if (p?.webSocketDebuggerUrl) { wsUrl = p.webSocketDebuggerUrl; break; } } catch {}
  await sleep(100);
}
if (!wsUrl) { console.error('no chrome target\n' + err.slice(-500)); process.exit(2); }
const sock = new WebSocket(wsUrl);
await new Promise((r) => sock.addEventListener('open', r, { once: true }));
let id = 0; const pend = new Map();
sock.addEventListener('message', (ev) => { const m = JSON.parse(ev.data); const p = pend.get(m.id);
  if (p) { pend.delete(m.id); m.error ? p.rej(new Error(JSON.stringify(m.error))) : p.res(m.result); } });
const send = (method, params = {}) => new Promise((res, rej) => { const i = ++id; pend.set(i, { res, rej }); sock.send(JSON.stringify({ id: i, method, params })); });
await send('Page.enable'); await send('Runtime.enable'); await send('Log.enable');
sock.addEventListener('message', (ev) => { const m = JSON.parse(ev.data);
  if (m.method === 'Runtime.consoleAPICalled') console.error('[console]', m.params.args.map((a) => a.value ?? a.description).join(' '));
  if (m.method === 'Runtime.exceptionThrown') console.error('[exception]', m.params.exceptionDetails.text, m.params.exceptionDetails.exception?.description ?? ''); });
await send('Page.navigate', { url });
for (let i = 0; i < 200; i++) {
  const r = await send('Runtime.evaluate', { expression: `(typeof ${expr} !== 'undefined') ? ${expr} : undefined`, returnByValue: true, awaitPromise: true });
  if (r.result?.value !== undefined) { console.log(JSON.stringify(r.result.value, null, 2)); chrome.kill('SIGKILL'); process.exit(0); }
  await sleep(100);
}
console.error('timed out waiting for ' + expr + '\n' + err.slice(-800));
chrome.kill('SIGKILL'); process.exit(1);
