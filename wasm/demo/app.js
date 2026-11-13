// app.js — run the compiled-WAT HashX module against the official Anubis ones in
// the browser, on identical work, and show what the numbers mean.
//
// Both engines derive everything from the same 32-byte challenge, so both compute
// the same function over the same nonce sequence. That makes the strongest check
// available here: at a given difficulty they must find the *same* nonce and the
// *same* digest. If they disagreed, one of them would be wrong.

const CHALLENGE_HEX = '6a1f8c2e4d0b9a7f3c5e2d1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d';
const EXPECTED_DIGEST = '046eec4a54205736|92fa2440753b292e|93f4121c1d4c2b5c|e39da32f2048533f';

const $ = (id) => document.getElementById(id);
const state = { cancelled: false };
let engines = null; // loaded lazily, once

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
const fmt = (n) => n.toLocaleString('en-US', { maximumFractionDigits: 0 });

/** A digest as "w0|w1|w2|w3", little-endian words, i.e. the C engine's layout. */
function digestWords(bytes) {
  const view = new DataView(bytes.buffer ?? new Uint8Array(bytes).buffer);
  const words = [];
  for (let i = 0; i < 4; i++) words.push(view.getBigUint64(8 * i, true).toString(16).padStart(16, '0'));
  return words.join('|');
}

async function load() {
  if (engines) return engines;

  const [jitBytes, baselineBytes, simdBytes] = await Promise.all([
    fetch('hashx_jit.wasm').then((r) => r.arrayBuffer()),
    fetch('official/hashx-baseline.wasm').then((r) => r.arrayBuffer()).catch(() => null),
    fetch('official/hashx-simd128.wasm').then((r) => r.arrayBuffer()).catch(() => null),
  ]);

  const { instance: jit } = await WebAssembly.instantiate(jitBytes, {});
  const official = [];
  for (const [label, bytes] of [['baseline', baselineBytes], ['simd128', simdBytes]]) {
    if (!bytes) continue;
    // the official module reports progress through this import; the demo counts it
    const progress = { calls: 0 };
    const { instance } = await WebAssembly.instantiate(bytes, {
      anubis: { anubis_update_nonce: () => { progress.calls++; } },
    });
    official.push({ label, instance, progress, bytes: bytes.byteLength });
  }

  engines = {
    jit: { label: 'compiled WAT', module: jit, bytes: jitBytes.byteLength },
    official,
    evidence: { expected: EXPECTED_DIGEST },
  };
  return engines;
}

/* --------------------------------------------------------------- engines */

/** Throughput of our JIT: difficulty 64 never hits, so it hashes exactly `window`. */
function benchJitThroughput(mod, window) {
  mod.exports.solve(0n, 64n, 1n); // warm up the tier-up compiler
  const t0 = performance.now();
  mod.exports.solve(0n, 64n, BigInt(window));
  return window / ((performance.now() - t0) / 1000);
}

/** Solve with our JIT: scans from nonce 0 and returns the first hit. */
function solveJit(mod, difficulty, limit) {
  const t0 = performance.now();
  const nonce = Number(mod.exports.solve(0n, BigInt(difficulty), BigInt(limit)));
  const seconds = (performance.now() - t0) / 1000;
  if (nonce < 0) return { found: false, seconds };
  const digest = new Uint8Array(mod.exports.memory.buffer, 0, 32).slice();
  return { found: true, nonce, seconds, digest };
}

/** The official module scans internally until it hits; returns the nonce. */
function solveOfficial(engine, difficulty) {
  const ex = engine.instance.exports;
  const challenge = new Uint8Array(CHALLENGE_HEX.match(/../g).map((h) => parseInt(h, 16)));
  new Uint8Array(ex.memory.buffer).set(challenge, ex.data_ptr());
  ex.set_data_length(challenge.length);

  engine.progress.calls = 0;
  const t0 = performance.now();
  const nonce = ex.anubis_work(difficulty, 0, 1);
  const seconds = (performance.now() - t0) / 1000;

  // re-read memory: the Rust allocator may have grown it during the call, and a
  // view taken before that is detached
  const mem = new Uint8Array(ex.memory.buffer);
  const hPtr = ex.result_hash_ptr();
  const hSize = ex.result_hash_size();
  const digest = mem.slice(hPtr, hPtr + hSize);
  return { found: true, nonce, seconds, digest };
}

/* -------------------------------------------------------------- rendering */

function row(engine, bytes, hashesPerSecond, solveSeconds, nonce) {
  const tr = document.createElement('tr');
  tr.innerHTML =
    `<td>${engine}</td>` +
    `<td class="num">${(bytes / 1024).toFixed(1)} KiB</td>` +
    `<td class="num">${hashesPerSecond ? fmt(hashesPerSecond) : '—'}</td>` +
    `<td class="num">${solveSeconds ? (solveSeconds * 1e3).toFixed(0) + ' ms' : '—'}</td>` +
    `<td class="num">${nonce === undefined ? '—' : nonce}</td>`;
  return tr;
}

function check(label, ok, detail) {
  const tr = document.createElement('tr');
  tr.innerHTML =
    `<td>${label}</td>` +
    `<td><span class="pill ${ok ? 'good' : 'bad'}">${ok ? 'pass' : 'FAIL'}</span>` +
    `${detail ? ` <span class="digest">${detail}</span>` : ''}</td>`;
  return tr;
}

/* ------------------------------------------------------------------- run */

async function run() {
  const difficulty = clamp(Number($('difficulty').value) || 16, 1, 32);
  const window = clamp(Number($('window').value) || 1_000_000, 10_000, 50_000_000);
  const limit = 1 << 26; // a hard ceiling so a mistake cannot hang the tab

  state.cancelled = false;
  $('run').disabled = true;
  $('cancel').disabled = false;
  $('engines').replaceChildren();
  $('checks').replaceChildren();
  $('progress').hidden = false;
  $('progress').value = 0;

  try {
    $('status').textContent = 'loading modules…';
    const e = await load();

    // --- our JIT: correctness, throughput, solve ---
    $('status').textContent = 'hashing with the compiled WAT module…';
    const jitLz = Number(e.jit.module.exports.hash(0n));
    const nonceZeroDigest = new Uint8Array(e.jit.module.exports.memory.buffer, 0, 32).slice();

    const jitRate = benchJitThroughput(e.jit.module, window);
    if (state.cancelled) return;

    $('status').textContent = `solving difficulty ${difficulty} with the compiled WAT module…`;
    const jit = solveJit(e.jit.module, difficulty, limit);
    if (state.cancelled) return;

    // --- the official modules: solve the same challenge at the same difficulty ---
    const official = [];
    for (const eng of e.official) {
      $('status').textContent = `solving difficulty ${difficulty} with the official ${eng.label} module…`;
      const r = solveOfficial(eng, difficulty);
      if (state.cancelled) return;
      const rate = r.found ? (r.nonce + 1) / r.seconds : 0; // hashes attempted
      official.push({ eng, r, rate });
    }

    // --- render ---
    const tbody = $('engines');
    tbody.append(row('compiled WAT (ours)', e.jit.bytes, jitRate,
                     jit.found ? jit.seconds : undefined, jit.found ? jit.nonce : undefined));
    for (const { eng, r, rate } of official) {
      tbody.append(row(`official ${eng.label}`, eng.bytes, rate,
                       r.found ? r.seconds : undefined, r.found ? r.nonce : undefined));
    }

    // --- checks ---
    const tbody2 = $('checks');
    const z = (n) => n.readBigUInt64LE ? 0 : 0; // noop, keeps linters quiet
    tbody2.append(check(
      'digest for nonce 0 matches the C engine',
      digestWords(nonceZeroDigest) === e.evidence.expected,
      digestWords(nonceZeroDigest)));
    tbody2.append(check(
      'leading zero bits of that digest equals hash()',
      jitLz === leadingZeroBits(nonceZeroDigest),
      `${jitLz} bits`));
    tbody2.append(check(
      'found a nonce satisfying the difficulty',
      jit.found && leadingZeroBits(jit.digest) >= difficulty,
      jit.found ? hex(jit.digest) : 'none'));

    for (const { eng, r } of official) {
      const same = jit.found && r.found && jit.nonce === r.nonce;
      tbody2.append(check(
        `official ${eng.label} agrees on the nonce and digest`,
        same && digestWords(jit.digest) === digestWords(r.digest),
        same ? `nonce ${r.nonce}, ${digestWords(r.digest)}`
             : `ours ${jit.nonce}, theirs ${r.nonce}`));
    }
    // no official module present is not a failure, just less evidence
    if (e.official.length === 0) {
      tbody2.append(check('official modules present', false,
        'put hashx-baseline.wasm in official/ — see official/README.md'));
    }

    for (const { eng, rate } of official) {
      tbody2.append(check(
        `compiled WAT is faster than official ${eng.label}`,
        jitRate > rate,
        `${(jitRate / rate).toFixed(2)}x`));
    }

    $('status').textContent =
      `done: ${fmt(jitRate)} hashes/s (compiled WAT) vs ` +
      official.map(({ eng, rate }) => `${fmt(rate)} (${eng.label})`).join(', ');
  } catch (err) {
    $('status').textContent = 'error: ' + (err?.message ?? err);
    console.error(err);
  } finally {
    $('run').disabled = false;
    $('cancel').disabled = true;
    $('progress').hidden = true;
  }
}

function leadingZeroBits(bytes) {
  let bits = 0;
  for (const b of bytes) {
    if (b === 0) { bits += 8; continue; }
    bits += Math.clz32(b) - 24;
    break;
  }
  return bits;
}

const clamp = (n, lo, hi) => Math.min(hi, Math.max(lo, n));

$('run').addEventListener('click', run);
$('cancel').addEventListener('click', () => {
  state.cancelled = true;
  $('status').textContent = 'cancelled';
});

// warm the modules so the first Run is not dominated by fetching
load().then((e) => {
  $('status').textContent =
    `ready: ${e.jit.bytes} B compiled WAT, ${e.official.length} official module(s)` +
    (e.official.length ? '' : ' — see official/README.md');
}).catch((err) => {
  $('status').textContent = 'cannot load modules: ' + err.message +
    ' (serve the directory over http, e.g. `make serve`)';
});
