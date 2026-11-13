#!/usr/bin/env node
/**
 * anubis_fetch.js — fetch a URL through Anubis with no dependencies at all.
 *
 * Pure Node: `node:crypto` for the proof of work, the built-in `fetch` for HTTP,
 * and a cookie jar of its own. No Python, no native library, no npm packages.
 *
 *   node tools/anubis_fetch.js https://anubis.techaro.lol/ --max-chars 400
 *
 * Algorithm coverage, honestly:
 *
 *   fast, slow   SHA-256(challenge || decimal nonce), leading zero NIBBLES
 *   sha256       SHA-256(raw challenge || u32 nonce), leading zero BITS
 *   metarefresh  follow the refresh, which is what proves a browser
 *   hashx        compiled to wasm for this challenge by ../wasm/hashx_jit.mjs,
 *                then searched in wasm - no interpreter, no toolchain
 *   argon2id     not implemented here - needs ~19 MiB of memory-hard work; the
 *                Python driver (tools/anubis_fetch.py) or the C engine does it
 *
 * For argon2id this module throws UnsupportedAlgorithmError; the DSH plugin falls
 * back to the Python driver when it is available, and says so when it is not.
 */

import { createHash } from 'node:crypto';

const UA_CHROME =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

const CHALLENGE_PATH = '/.within.website/x/cmd/anubis/api/pass-challenge';
const MAX_ATTEMPTS = 4;
const MAX_NONCE_SCAN = 1 << 22; // 4.2 M candidates before giving up

/** The deployment asked for an algorithm this module refuses to implement. */
export class UnsupportedAlgorithmError extends Error {
  constructor(algorithm) {
    super(
      `anubis: ${algorithm} challenges are not solved by the pure-JS engine ` +
        '(they need the C engine: `make` in the repository root, then use ' +
        'tools/anubis_fetch.py)',
    );
    this.name = 'UnsupportedAlgorithmError';
    this.algorithm = algorithm;
  }
}

/* ------------------------------------------------------------------ cookies */

/** A minimal RFC 6265-ish jar: host -> name -> value. Attributes are ignored. */
class CookieJar {
  constructor() {
    this.byHost = new Map();
  }

  #host(url) {
    return new URL(url).hostname;
  }

  /** "name=value; name2=value2" for this host. */
  header(url) {
    const jar = this.byHost.get(this.#host(url));
    if (!jar || jar.size === 0) return undefined;
    return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  /** Absorb every Set-Cookie on a response. */
  store(url, response) {
    const host = this.#host(url);
    const list =
      typeof response.headers.getSetCookie === 'function'
        ? response.headers.getSetCookie()
        : [response.headers.get('set-cookie')].filter(Boolean);
    if (list.length === 0) return;
    let jar = this.byHost.get(host);
    if (!jar) {
      jar = new Map();
      this.byHost.set(host, jar);
    }
    for (const line of list) {
      // "name=value; Path=/; Expires=..." - only the pair matters here
      const pair = line.split(';', 1)[0].trim();
      const eq = pair.indexOf('=');
      if (eq <= 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (/max-age=0/i.test(line)) jar.delete(name);
      else jar.set(name, value);
    }
  }
}

/* ------------------------------------------------------------------- http */

/** GET with manual redirects so the jar sees every Set-Cookie. */
async function httpGet(url, jar, opts = {}, redirects = 0) {
  const headers = {
    'user-agent': opts.userAgent ?? UA_CHROME,
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'accept-language': 'en-US,en;q=0.9',
  };
  const cookie = jar.header(url);
  if (cookie) headers.cookie = cookie;

  const response = await fetch(url, {
    method: 'GET',
    headers,
    redirect: 'manual',
    signal: opts.signal,
  });
  jar.store(url, response);

  if (response.status >= 300 && response.status < 400 && redirects < 8) {
    const location = response.headers.get('location');
    if (location) {
      const next = new URL(location, url).toString();
      return httpGet(next, jar, opts, redirects + 1);
    }
  }
  const text = await response.text();
  return { url: response.url || url, status: response.status, headers: response.headers, text };
}

/* --------------------------------------------------------------- challenge */

const CHALLENGE_RE =
  /<script[^>]*id=["']anubis_challenge["'][^>]*>([\s\S]*?)<\/script>/i;
const BASE_PREFIX_RE =
  /<script[^>]*id=["']anubis_base_prefix["'][^>]*>([\s\S]*?)<\/script>/i;
/** Find the meta refresh in a challenge page, whatever the attribute order. */
function findMetaRefresh(html) {
  for (const tag of html.match(/<meta\b[^>]*>/gi) ?? []) {
    if (!/http-equiv\s*=\s*["']?refresh/i.test(tag)) continue;
    const content = /content\s*=\s*["']([^"']*)["']/i.exec(tag);
    if (!content) continue;
    const parsed = /^\s*(\d+)\s*;\s*url\s*=\s*(.+)$/i.exec(content[1]);
    if (!parsed) continue;
    return { delay: Number(parsed[1]), url: parsed[2].trim().replace(/&amp;/g, '&') };
  }
  return null;
}

/** The challenge payload, or null when the response is real content. */
function parseChallenge(html) {
  const m = CHALLENGE_RE.exec(html);
  if (!m) return null;
  let payload;
  try {
    payload = JSON.parse(m[1]);
  } catch {
    return null;
  }
  const rules = payload.rules ?? {};
  const chall = payload.challenge;

  // v1.17 .. v1.21: {"challenge": "<hex>", "rules": {...}} - no server-side id
  if (typeof chall === 'string') {
    return {
      id: '',
      randomData: chall,
      algorithm: rules.algorithm ?? 'fast',
      difficulty: Number(rules.difficulty ?? 0),
      metaRefresh: null,
    };
  }
  if (!chall || typeof chall !== 'object') return null;

  return {
    id: chall.id ?? '',
    randomData: chall.randomData ?? chall.challenge ?? '',
    algorithm: rules.algorithm ?? chall.method ?? 'fast',
    difficulty: Number(rules.difficulty ?? chall.difficulty ?? 0),
    metaRefresh: findMetaRefresh(html),
  };
}

function basePrefixOf(html) {
  const m = BASE_PREFIX_RE.exec(html);
  if (!m) return '';
  try {
    return String(JSON.parse(m[1]) ?? '');
  } catch {
    return '';
  }
}

/* ----------------------------------------------------------- proof of work */

/** Leading zero nibbles of a hex digest (the `fast` / `slow` difficulty unit). */
function leadingZeroNibbles(digest) {
  const hex = digest.toString('hex');
  let n = 0;
  for (const ch of hex) {
    if (ch !== '0') break;
    n++;
  }
  return n;
}

/** Leading zero bits of a digest buffer (the `sha256` difficulty unit). */
function leadingZeroBits(digest) {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

/**
 * `fast` / `slow`: SHA-256 over the challenge text followed by the decimal
 * nonce, difficulty counted in leading zero hex digits.
 */
export function solveNibbles(challengeText, difficulty) {
  const started = process.hrtime.bigint();
  for (let nonce = 0; nonce < MAX_NONCE_SCAN; nonce++) {
    const digest = createHash('sha256').update(challengeText + String(nonce)).digest();
    if (leadingZeroNibbles(digest) >= difficulty) {
      return { nonce, response: digest.toString('hex'), elapsedMs: msSince(started) };
    }
  }
  throw new Error(`anubis: no nibble solution in ${MAX_NONCE_SCAN} nonces`);
}

/**
 * `sha256`: SHA-256 over the decoded challenge bytes followed by the nonce as a
 * 4-byte integer, difficulty counted in leading zero bits.
 *
 * Byte order: big-endian, except when the challenge ends in a byte >= 0x80, which
 * is the same rule the C engine applies (src/core/anubis_solver.c sets use_le
 * that way) so the two implementations agree on every deployment.
 *
 * The work is done by `../wasm/sha256_pow.wasm`: the same C kernel, compiled with
 * clang. Measured against a live Anubis server (wasm/live-test.mjs), it does
 * 471 kH/s where `crypto.createHash` per nonce does 168 kH/s and
 * `crypto.subtle.digest` per nonce does 24 kH/s. Per-call overhead dominates at
 * this input size (36 bytes), so a native API is the *slow* path here — verified,
 * not assumed. Falls back to createHash when the module is not built.
 */
let sha256Module = null;

/** Load the wasm SHA-256 kernel once, or return null if it is not built. */
async function loadSha256() {
  if (sha256Module !== null) return sha256Module;
  try {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    // the 4-wide kernel hashes four nonces at once; the scalar one is the
    // fallback, and createHash after that
    const { fileURLToPath: toPath } = await import('node:url');
    for (const name of ['sha256_pow_batch.wasm', 'sha256_pow.wasm']) {
      try {
        const path = toPath(new URL(`../wasm/${name}`, import.meta.url));
        const { instance } = await WebAssembly.instantiate(readFileSync(path), {
          anubis: { anubis_update_nonce: () => {} },
        });
        sha256Module = instance.exports;
        break;
      } catch { /* try the next one */ }
    }
    if (sha256Module === null) sha256Module = false;
  } catch {
    sha256Module = false;
  }
  return sha256Module;
}

export async function solveBits(challengeHex, difficulty) {
  const raw = Buffer.from(challengeHex, 'hex');
  const started = process.hrtime.bigint();
  const ex = await loadSha256();

  if (ex) {
    const buf = new Uint8Array(ex.memory.buffer);
    buf.set(raw, ex.data_ptr());
    ex.set_data_length(raw.length);
    const nonce = ex.anubis_work(difficulty, 0, 1);
    const digest = Buffer.from(new Uint8Array(ex.memory.buffer, ex.result_hash_ptr(), 32));
    return { nonce, response: digest.toString('hex'), elapsedMs: msSince(started) };
  }

  // fallback: the native API, ~3x slower per hash at this input size
  const littleEndian = raw.length > 0 && raw[raw.length - 1] >= 0x80;
  const nonceBuf = Buffer.alloc(4);
  for (let nonce = 0; nonce < MAX_NONCE_SCAN; nonce++) {
    if (littleEndian) nonceBuf.writeUInt32LE(nonce >>> 0, 0);
    else nonceBuf.writeUInt32BE(nonce >>> 0, 0);
    const digest = createHash('sha256').update(raw).update(nonceBuf).digest();
    if (leadingZeroBits(digest) >= difficulty) {
      return { nonce, response: digest.toString('hex'), elapsedMs: msSince(started) };
    }
  }
  throw new Error(`anubis: no bit solution in ${MAX_NONCE_SCAN} nonces`);
}

/**
 * Solve a `hashx` challenge by compiling it.
 *
 * A HashX challenge is a 512-instruction program derived from the challenge
 * bytes, so it can be compiled once and run as straight-line wasm instead of
 * interpreted. ../wasm/hashx_jit.mjs does the derivation and emits the module
 * bytes in pure JavaScript, which makes the compiled path the default one here
 * rather than a demo: it is 7x the interpreter, which is itself 1.2x the module
 * Anubis ships.
 *
 * The compile costs ~6 ms, which only pays from about difficulty 12 upwards
 * (12 bits is ~4096 hashes, 1.3 ms interpreted against 0.82 ms compiled here
 * after the build). It is done unconditionally because the alternative is
 * shipping a second code path for the cheap case, and a real deployment's hashx
 * difficulty is well above that line.
 */
async function solveHashX(randomData, difficulty) {
  const { buildModule } = await import('../wasm/hashx_jit.mjs');
  const challenge = Buffer.from(randomData, 'hex');
  const bytes = buildModule(challenge);
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const ex = instance.exports;
  new Uint8Array(ex.memory.buffer).set(challenge, ex.data_ptr());
  ex.set_data_length(challenge.length);
  const started = process.hrtime.bigint();
  const nonce = ex.anubis_work(difficulty, 0, 1) >>> 0;
  const digest = Buffer.from(
    new Uint8Array(ex.memory.buffer, ex.result_hash_ptr(), ex.result_hash_size()),
  );
  return { nonce, response: digest.toString('hex'), elapsedMs: msSince(started) };
}

/** Solve one parsed challenge with the algorithm it names. */
export async function solveChallenge(challenge) {
  const algorithm = String(challenge.algorithm ?? '').toLowerCase();
  const difficulty = Number(challenge.difficulty ?? 0);
  if (algorithm === 'fast' || algorithm === 'slow') {
    return { algorithm, difficulty, ...solveNibbles(challenge.randomData, difficulty) };
  }
  if (algorithm === 'sha256' || algorithm === 'wasm-sha256') {
    // solveBits may load the wasm kernel on first use
    return { algorithm, difficulty, ...(await solveBits(challenge.randomData, difficulty)) };
  }
  if (algorithm === 'hashx') {
    return { algorithm, difficulty, ...(await solveHashX(challenge.randomData, difficulty)) };
  }
  if (algorithm === 'metarefresh') {
    throw new Error(
      'anubis: metarefresh is a redirect proof, not a proof of work - it is handled by ' +
        'anubisFetch, not solveChallenge',
    );
  }
  throw new UnsupportedAlgorithmError(algorithm || '(unknown)');
}

function msSince(startedNs) {
  return Number(process.hrtime.bigint() - startedNs) / 1e6;
}

/* ------------------------------------------------------------------ format */

const TAG = /<[^>]+>/g;
const SCRIPT = /<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi;

/** Strip tags to readable text. Deliberately crude: no DOM, no dependencies. */
export function htmlToText(html) {
  let body = html.replace(SCRIPT, ' ');
  body = body.replace(/<br\s*\/?>|<\/p>|<\/div>|<\/li>|<\/h[1-6]>|<\/tr>/gi, '\n');
  body = body.replace(TAG, '');
  body = body
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;|&apos;/g, "'")
    .replace(/&#x27;/g, "'");
  body = body.replace(/[ \t\r\f\v]+/g, ' ');
  body = body
    .split('\n')
    .map((line) => line.trim())
    .join('\n');
  return body.replace(/\n{3,}/g, '\n\n').trim();
}

export function titleOf(html) {
  const m = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  return m ? m[1].replace(TAG, '').trim() : '';
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/* -------------------------------------------------------------------- fetch */

/**
 * GET a URL, solving any Anubis challenge on the way.
 *
 * @param {string} url
 * @param {object} [opts]
 * @param {number} [opts.maxChars] body cap, default 100000
 * @param {number} [opts.timeoutMs] per-request timeout, default 30000
 * @param {AbortSignal} [opts.signal]
 * @param {boolean} [opts.solve] set false to return the challenge page as-is
 * @returns {Promise<object>} { url, finalUrl, statusCode, title, challenge,
 *   stillChallenged, truncated, content }
 */
export async function anubisFetch(url, opts = {}) {
  const maxChars = Number.isInteger(opts.maxChars) && opts.maxChars > 0 ? opts.maxChars : 100_000;
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const jar = new CookieJar();
  const solve = opts.solve !== false;

  let target = url;
  let last = null;
  let solved = null;
  let rounds = 0;

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    last = await httpGet(target, jar, opts);
    const challenge = parseChallenge(last.text);
    if (!challenge) break; // real content
    if (!solve) break;
    rounds++;

    const base = basePrefixOf(last.text);

    // metarefresh: the server's proof is that a browser followed the redirect,
    // so there is nothing to compute - wait what it asks for, then follow it.
    if (String(challenge.algorithm).toLowerCase() === 'metarefresh') {
      const refresh = challenge.metaRefresh ?? findMetaRefresh(last.text);
      if (refresh) {
        await sleep(Math.max(refresh.delay, 1) * 1000 + 300);
        await httpGet(new URL(refresh.url, target).toString(), jar, opts);
      } else {
        // No meta tag: the page's own JS builds this call (main.mjs does
        // location.replace(pass-challenge?challenge=&id=&redir=&elapsedTime=)).
        // `challenge` is the randomData and it is required - omitting it is a
        // 403, which is how this was found.
        const pause = 1500;
        await sleep(pause);
        const params = new URLSearchParams({
          challenge: challenge.randomData,
          redir: target,
          elapsedTime: `${pause}.000`,
        });
        if (challenge.id) params.set('id', challenge.id);
        const passUrl = new URL(base + CHALLENGE_PATH, target);
        passUrl.search = params.toString();
        await httpGet(passUrl.toString(), jar, opts);
      }
      solved = { algorithm: 'metarefresh', difficulty: challenge.difficulty, nonce: null,
        response: '', elapsedMs: refresh ? refresh.delay * 1000 : 1500, rounds };
      continue; // re-GET the original URL with the cookie we just earned
    }

    const result = await solveChallenge(challenge);
    const params = new URLSearchParams({
      response: result.response,
      nonce: String(result.nonce),
      redir: target,
      elapsedTime: result.elapsedMs.toFixed(3),
    });
    if (challenge.id) params.set('id', challenge.id);
    const passUrl = new URL(base + CHALLENGE_PATH, target);
    passUrl.search = params.toString();

    // Do not follow the redirect here: the auth cookie is set on this response.
    await httpGet(passUrl.toString(), jar, opts);
    solved = { ...result, rounds };
  }

  const body = last.text;
  const contentType = last.headers.get('content-type') ?? '';
  const looksHtml = /html/i.test(contentType) || body.trimStart().startsWith('<');
  const text = looksHtml ? htmlToText(body) : body;
  const stillChallenged = parseChallenge(body) !== null;

  return {
    url,
    finalUrl: last.url,
    statusCode: last.status,
    contentType,
    title: looksHtml ? titleOf(body) : '',
    challenge: solved
      ? {
          algorithm: solved.algorithm,
          difficulty: solved.difficulty,
          nonce: solved.nonce,
          response: solved.response,
          elapsedMs: Math.round(solved.elapsedMs * 1000) / 1000,
          rounds: solved.rounds,
        }
      : null,
    stillChallenged,
    truncated: text.length > maxChars,
    content: text.length > maxChars ? text.slice(0, maxChars) : text,
  };
}

/* ---------------------------------------------------------------------- CLI */

async function main(argv) {
  const args = argv.slice(2);
  const url = args.find((a) => !a.startsWith('--'));
  const flag = (name, fallback) => {
    const i = args.indexOf(`--${name}`);
    return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : fallback;
  };
  if (!url) {
    console.error('usage: node tools/anubis_fetch.js <url> [--max-chars N] [--timeout MS]');
    return 2;
  }
  try {
    const result = await anubisFetch(url, {
      maxChars: Number(flag('max-chars', 100_000)),
      timeoutMs: Number(flag('timeout', 30_000)),
      solve: !args.includes('--no-solve'),
    });
    console.log(JSON.stringify(result));
    return 0;
  } catch (err) {
    console.log(JSON.stringify({ url, error: err.message, unsupported: err.name === 'UnsupportedAlgorithmError' }));
    return err.name === 'UnsupportedAlgorithmError' ? 2 : 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = await main(process.argv);
}
