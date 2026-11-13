#!/usr/bin/env node
/**
 * bench-endtoend.mjs — the wall, end to end: two servers x three clients.
 *
 *   server   standard Anubis v1.28.3   |  betterAnusbis (this repo, C)
 *   client   Anubis's own wasm         |  our wasm (4 nonces wide)  |  native .so
 *
 * The number that matters is "milliseconds until the protected page appears": it
 * includes the client's proof of work, the network round trip, the server's
 * verification, the cookie, and the redirect. Hashing rate is derived from the
 * nonce actually found, because at a fixed difficulty the nonce varies with luck.
 *
 *   node tools/bench-endtoend.mjs --anubis http://127.0.0.1:8923/ \
 *        --better http://127.0.0.1:8096/ --runs 3
 */
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = dirname(HERE);
const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };

const SERVERS = {
  anubis: flag('anubis', 'http://127.0.0.1:8923/'),
  better: flag('better', 'http://127.0.0.1:8096/'),
};
const RUNS = Number(flag('runs', 3));
const OFFICIAL_WASM = join(REPO, 'wasm/demo/official/hashx-baseline.wasm'); // placeholder, replaced below
const ANUBIS_WASM_DIR = flag('official-wasm',
  '/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis/web/static/wasm/simd128');
const HOST = join(REPO, 'firefox-extension/native-host/anubis_native.py');

/* ---------------------------------------------------------------- clients */

const leadingZeroBits = (buf) => {
  let bits = 0;
  for (const b of buf) { if (b === 0) { bits += 8; continue; } bits += Math.clz32(b) - 24; break; }
  return bits;
};

async function loadWasm(path) {
  const { instance } = await WebAssembly.instantiate(readFileSync(path),
    { anubis: { anubis_update_nonce: () => {} } });
  const ex = instance.exports;
  return (challenge, difficulty) => {
    new Uint8Array(ex.memory.buffer).set(challenge, ex.data_ptr());
    ex.set_data_length(challenge.length);
    const nonce = ex.anubis_work(difficulty, 0, 1);
    const digest = Buffer.from(new Uint8Array(ex.memory.buffer, ex.result_hash_ptr(), ex.result_hash_size()));
    return { nonce: nonce >>> 0, response: digest.toString('hex') };
  };
}

/** The native messaging host, driven exactly as the Firefox extension drives it. */
async function nativeClient() {
  const proc = spawn('python3', ['-u', HOST], { stdio: ['pipe', 'pipe', 'inherit'] });
  const pending = [];
  let buf = Buffer.alloc(0);
  proc.stdout.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 4) {
      const len = buf.readUInt32LE(0);
      if (buf.length < 4 + len) break;
      const msg = JSON.parse(buf.subarray(4, 4 + len).toString());
      buf = buf.subarray(4 + len);
      pending.shift()?.(msg);
    }
  });
  const call = (payload) => new Promise((resolve) => {
    const body = Buffer.from(JSON.stringify(payload));
    const header = Buffer.alloc(4);
    header.writeUInt32LE(body.length, 0);
    pending.push(resolve);
    proc.stdin.write(Buffer.concat([header, body]));
  });
  await call({ cmd: 'info' });                       // warm the library
  return {
    solve: async (challenge, difficulty) => {
      const r = await call({
        cmd: 'solve', algorithm: 'sha256', difficulty,
        randomData: challenge.toString('hex'),
      });
      if (!r.ok) throw new Error(r.error);
      return { nonce: r.nonce, response: r.response, engineMs: r.elapsedMs };
    },
    close: () => { proc.stdin.end(); },
  };
}

/* ------------------------------------------------------------------- http */

let cookies = '';
async function http(url) {
  const res = await fetch(url, { redirect: 'manual', headers: {
    'user-agent': 'Mozilla/5.0 (end-to-end bench)',
    ...(cookies ? { cookie: cookies } : {}),
  }});
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const kv = c.split(';')[0];
    if (kv.includes('=') && !kv.startsWith('techaro.lol-anubis-cookie-verification=')) {
      cookies = cookies ? `${cookies}; ${kv}` : kv;
    }
  }
  return { status: res.status, text: await res.text(), location: res.headers.get('location') };
}

const parseChallenge = (html) => {
  const m = /id="anubis_challenge"[^>]*>\s*(\{.*?\})\s*<\/script>/s.exec(html);
  return m ? JSON.parse(m[1]) : null;
};

/* -------------------------------------------------------------------- run */

const officialSolve = await loadWasm(join(ANUBIS_WASM_DIR, 'sha256.wasm'));
const ourSolve = await loadWasm(join(REPO, 'wasm/sha256_pow_batch.wasm'));
const native = await nativeClient();

const CLIENTS = [
  ['Anubis wasm', (c, d) => officialSolve(c, d)],
  ['solver wasm (4-wide)', (c, d) => ourSolve(c, d)],
  ['native .so', (c, d) => native.solve(c, d)],
];

const median = (xs) => { const s = [...xs].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]; };

console.log('The wall, end to end: time until the protected page appears');
console.log(`${RUNS} runs per cell, interleaved, clients warmed first\n`);

/* Warm every client before anything is timed: wasm tier-up otherwise makes the
 * first cells look slow, which is exactly the bias that made an earlier version of
 * this table claim the server changed the client's speed. */
const WARM = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
for (const [, solve] of CLIENTS) {
  for (let i = 0; i < 3; i++) await solve(WARM, 8);
}

const cells = [];
for (const [serverName, base] of Object.entries(SERVERS)) {
  for (const [clientName, solve] of CLIENTS) {
    cells.push({ server: serverName, base, client: clientName, solve, rows: [] });
  }
}

async function runCell(cell) {
  cookies = '';
  try {
    const first = await http(cell.base);
    const chal = parseChallenge(first.text);
    if (!chal) { cell.rows.push({ failed: 'no challenge' }); return; }
    const difficulty = chal.rules.difficulty;
    const challenge = Buffer.from(chal.challenge.randomData, 'hex');

    const t0 = performance.now();
    const { nonce, response } = await cell.solve(challenge, difficulty);
    const solveMs = performance.now() - t0;

    const pass = new URL('/.within.website/x/cmd/anubis/api/pass-challenge', cell.base);
    pass.searchParams.set('id', chal.challenge.id);
    pass.searchParams.set('response', response);
    pass.searchParams.set('nonce', String(nonce));
    pass.searchParams.set('redir', '/');
    pass.searchParams.set('elapsedTime', String(Math.max(1, Math.round(solveMs))));
    await http(pass.toString());
    const after = await http(cell.base);
    const e2e = performance.now() - t0;
    const ok = after.status === 200 && /PAST THE WALL/.test(after.text);
    cell.rows.push({ difficulty, nonce, solveMs, e2e, ok, hashes: nonce + 1 });
    if (process.env.BENCH_VERBOSE)
      console.log(`      ${cell.server}/${cell.client}: difficulty ${difficulty}, nonce ${nonce}, ` +
                  `solve ${solveMs.toFixed(1)} ms, e2e ${e2e.toFixed(1)} ms, ok ${ok}`);
  } catch (err) {
    cell.rows.push({ failed: String(err.message ?? err) });
  }
}

/* interleaved rounds so warm-up and drift hit every cell equally */
for (let r = 0; r < RUNS; r++) for (const cell of cells) await runCell(cell);

const results = cells.map((cell) => {
  const good = cell.rows.filter((r) => r.ok);
  const totalHashes = good.reduce((a, r) => a + r.hashes, 0);
  const totalSeconds = good.reduce((a, r) => a + r.solveMs, 0) / 1000;
  return {
    server: cell.server, client: cell.client, ok: good.length, runs: cell.rows.length,
    difficulty: cell.rows[0]?.difficulty,
    solveMs: good.length ? median(good.map((r) => r.solveMs)) : NaN,
    e2eMs: good.length ? median(good.map((r) => r.e2e)) : NaN,
    overheadMs: good.length ? median(good.map((r) => r.e2e - r.solveMs)) : NaN,
    hashesPerSec: good.length ? totalHashes / totalSeconds : NaN,
    nonces: good.map((r) => r.nonce),
  };
});
native.close();

const label = (r) => `${r.server} + ${r.client}`;
const pad = (s, n) => String(s).padEnd(n);

console.log('  ' + pad('combination', 40) + pad('rate', 11) + pad('server+net', 12) +
            pad('median solve', 14) + 'verified');
for (const r of results) {
  const ok = r.ok === r.runs;
  console.log('  ' + pad(label(r), 40) +
    pad(Number.isFinite(r.hashesPerSec) ? `${(r.hashesPerSec / 1000).toFixed(0)} kH/s` : '—', 11) +
    pad(Number.isFinite(r.overheadMs) ? `${r.overheadMs.toFixed(1)} ms` : '—', 12) +
    pad(Number.isFinite(r.solveMs) ? `${r.solveMs.toFixed(0)} ms` : '—', 14) +
    (ok ? `${r.ok}/${r.runs}` : `FAILED ${r.ok}/${r.runs}`));
}

const bestRate = Math.max(...results.filter((r) => Number.isFinite(r.hashesPerSec)).map((r) => r.hashesPerSec));
console.log('\n  relative throughput against the best cell:');
for (const r of [...results].filter((r) => Number.isFinite(r.hashesPerSec))
  .sort((a, b) => b.hashesPerSec - a.hashesPerSec)) {
  console.log(`    ${pad(label(r), 40)} ${(r.hashesPerSec / bestRate).toFixed(2)}x   ` +
              `(${(bestRate / r.hashesPerSec).toFixed(2)}x slower)`);
}
console.log('\n  nonces found per cell (exponential, so they vary by a lot):');
for (const r of results) if (r.nonces) console.log(`    ${pad(label(r), 40)} ${r.nonces.join(', ')}`);
