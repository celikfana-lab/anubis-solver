/**
 * meatrider-webgpu.mjs — headless verifier for webgpu/meatrider.wgsl.
 *
 * Drives WebGPU directly from Deno (no npm dependencies), computes the
 * midstate/tail half of the Bitcoin block header on the host, dispatches the
 * kernel, reads the hits back, and compares every digest with the independent
 * Python reference tools/meatrider_ref.py. A digest is never hardcoded here:
 * every expected value comes from the reference process at run time.
 *
 *   deno run --allow-all tools/meatrider-webgpu.mjs
 *
 * Exits 0 only when every comparison passes and the shader compiled. Prints the
 * adapter string, the number of digest comparisons, and one reproducible
 * hashes/second line.
 *
 * Three phases:
 *   1. digest equality — several randomData values, several difficulties (the
 *      header's nBits field depends on difficulty), and several base nonces,
 *      four consecutive nonces per dispatch (the kernel's vec4 lanes);
 *   2. anubis_work behaviour — scan a nonce range, find the first qualifying
 *      nonce, and require the same nonce (and digest) the Python reference
 *      finds, i.e. the minimum hit over the range;
 *   3. throughput — a warm-up then five timed dispatches at difficulty 256
 *      (unreachable, so no atomic writes), median rate reported.
 *
 * The WGSL kernel lives in webgpu/meatrider.wgsl; the host half of the context
 * (SHA-256 midstate of header bytes 0..63, the 12-byte tail) is computed here
 * with a small SHA-256, and is validated indirectly by phase 1: if the host
 * midstate were wrong, every GPU digest would miss the Python reference.
 */
const REPO = new URL('..', import.meta.url).pathname;
const WGSL_PATH = REPO + 'webgpu/meatrider.wgsl';

/* ------------------------------------------------------------------ */
/* SHA-256 on the host: merkle label hash and the 64-byte midstate      */
/* ------------------------------------------------------------------ */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

/** One SHA-256 compression in place: h[8] <- h + compress(h, w[16]). */
function compress(h, w) {
  const W = new Uint32Array(64);
  W.set(w);
  for (let i = 16; i < 64; i++) {
    const x = W[i - 15];
    const y = W[i - 2];
    const s0 = (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0;
    const s1 = (rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10)) >>> 0;
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
  }
  let a = h[0], b = h[1], c = h[2], d = h[3];
  let e = h[4], f = h[5], g = h[6], hh = h[7];
  for (let i = 0; i < 64; i++) {
    const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
    const ch = ((e & f) ^ (~e & g)) >>> 0;
    const t1 = (hh + S1 + ch + K[i] + W[i]) >>> 0;
    const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
    const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
    const t2 = (S0 + maj) >>> 0;
    hh = g; g = f; f = e; e = (d + t1) >>> 0;
    d = c; c = b; b = a; a = (t1 + t2) >>> 0;
  }
  h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
  h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
  h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
  h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
}

const be32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const le32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const hexToBytes = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const bytesToHex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const wordsToHex = (ws) => ws.map((w) => (w >>> 0).toString(16).padStart(8, '0')).join('');

/** SHA-256 of a message shorter than 56 bytes: one padded block. */
function sha256Short(msg) {
  const blk = new Uint8Array(64);
  blk.set(msg);
  blk[msg.length] = 0x80;
  const bits = BigInt(msg.length) * 8n;
  for (let i = 0; i < 8; i++) blk[63 - i] = Number((bits >> BigInt(8 * i)) & 255n);
  const w = new Uint32Array(16);
  for (let i = 0; i < 16; i++) w[i] = be32(blk, 4 * i);
  const h = new Uint32Array(IV);
  compress(h, w);
  return h;
}

/** Bitcoin nBits for the exact target 2^(256-difficulty) (meatrider_bits). */
function bitsFor(difficulty) {
  const d = Math.min(255, Math.max(1, difficulty));
  const blen = 257 - d;
  let size = Math.ceil(blen / 8);
  let compact;
  if (size <= 3) compact = ((1 << (blen - 1)) << (8 * (3 - size))) >>> 0;
  else compact = (1 << ((blen - 1) - 8 * (size - 3))) >>> 0;
  if (compact & 0x00800000) { compact >>>= 8; size++; }
  return ((compact | (size << 24)) >>> 0);
}

const VERSION = 1;
const TIME = 1231006505;
const LABEL = new TextEncoder().encode('meatrider');

/** Host half of meatrider_ctx_init(): midstate[8] and tail words[3]. */
function buildCtx(rdHex, difficulty) {
  const rd = hexToBytes(rdHex);
  if (rd.length !== 32) throw new Error('randomData must be 32 bytes');
  const label = new Uint8Array(LABEL.length + 32);
  label.set(LABEL);
  label.set(rd, LABEL.length);
  const merkleW = sha256Short(label);
  const merkle = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    merkle[4 * i] = merkleW[i] >>> 24;
    merkle[4 * i + 1] = (merkleW[i] >>> 16) & 255;
    merkle[4 * i + 2] = (merkleW[i] >>> 8) & 255;
    merkle[4 * i + 3] = merkleW[i] & 255;
  }

  // header bytes 0..63: version LE, prev block, merkle[0..28)
  const first = new Uint8Array(64);
  first[0] = VERSION; first[1] = 0; first[2] = 0; first[3] = 0;
  first.set(rd, 4);
  first.set(merkle.subarray(0, 28), 36);

  const mid = new Uint32Array(IV);
  const w = new Uint32Array(16);
  for (let i = 0; i < 16; i++) w[i] = be32(first, 4 * i);
  compress(mid, w);

  // header bytes 64..75, read as the three big-endian block words
  const tail = new Uint8Array(12);
  tail.set(merkle.subarray(28, 32), 0);
  const t = new Uint8Array(4);
  const putLE = (v) => { t[0] = v & 255; t[1] = (v >>> 8) & 255; t[2] = (v >>> 16) & 255; t[3] = (v >>> 24) & 255; };
  putLE(TIME); tail.set(t, 4);
  const bits = bitsFor(difficulty);
  putLE(bits); tail.set(t, 8);

  return {
    mid,
    tailWords: [be32(tail, 0), be32(tail, 4), be32(tail, 8)],
    bits,
    first,
  };
}

/* ------------------------------------------------------------------ */
/* Python reference ground truth (never hardcoded)                     */
/* ------------------------------------------------------------------ */

const PY_HELPER = `
import sys, json
sys.path.insert(0, 'tools')
import meatrider_ref as m
rd = bytes.fromhex(sys.argv[1]); diff = int(sys.argv[2]); mode = sys.argv[3]
out = {}
if mode == 'digests':
    for n in sys.argv[4:]:
        n = int(n); out[str(n)] = m.digest(rd, diff, n).hex()
elif mode == 'scan':
    base = int(sys.argv[4]); count = int(sys.argv[5]); want = int(sys.argv[6])
    hits = []
    for n in range(base, base + count):
        dg = m.digest(rd, diff, n)
        if m.leading_zero_bits(dg) >= diff:
            hits.append([n, dg.hex()])
            if len(hits) >= want:
                break
    out['hits'] = hits
print(json.dumps(out))
`;

const repoRoot = new URL('.', import.meta.url).pathname.replace(/\/tools\/$/, '');
async function pyRef(...args) {
  const cmd = new Deno.Command('python3', {
    args: ['-c', PY_HELPER, ...args.map(String)],
    cwd: repoRoot,
    stdout: 'piped',
    stderr: 'piped',
  });
  const { code, stdout, stderr } = await cmd.output();
  if (code !== 0) {
    throw new Error(`python reference failed (exit ${code}): ${new TextDecoder().decode(stderr)}`);
  }
  return JSON.parse(new TextDecoder().decode(stdout));
}

/* ------------------------------------------------------------------ */
/* WebGPU                                                              */
/* ------------------------------------------------------------------ */

const WORKGROUP = 64;      // @workgroup_size in the shader
const LANES = 4;           // nonces per invocation
const PER_GROUP = WORKGROUP * LANES;
const RESULTS_U32 = 76;    // 4 header + 8 nonces + 64 digest words

const fail = (msg) => { console.error('FAIL: ' + msg); Deno.exit(1); };

if (!navigator.gpu) fail('navigator.gpu is missing (try --unstable-webgpu on older Deno)');
const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' });
if (!adapter) fail('no WebGPU adapter');
const info = adapter.info ?? {};
const adapterName = info.description || info.device || '(unnamed adapter)';
const adapterLine = [info.vendor, info.architecture, info.device, info.description]
  .filter(Boolean).join(' / ');

const device = await adapter.requestDevice();
device.addEventListener('uncapturederror', (e) => console.error('GPU error: ' + e.error.message));

const code = await Deno.readTextFile(WGSL_PATH);
const module = device.createShaderModule({ code, label: 'meatrider' });
const ci = await module.getCompilationInfo();
const errs = ci.messages.filter((m) => m.type === 'error');
for (const m of ci.messages) {
  if (m.type !== 'info') console.error(`shader ${m.type} line ${m.lineNum}: ${m.message}`);
}
if (errs.length) fail('the shader does not compile on this backend');

const pipeline = device.createComputePipeline({ layout: 'auto', compute: { module, entryPoint: 'main' } });

const PARAMS_U32 = 16;
const paramsBuf = device.createBuffer({
  size: PARAMS_U32 * 4,
  usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
});
const resultsBuf = device.createBuffer({
  size: RESULTS_U32 * 4,
  usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
});
const readBuf = device.createBuffer({
  size: RESULTS_U32 * 4,
  usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
});
const bind = device.createBindGroup({
  layout: pipeline.getBindGroupLayout(0),
  entries: [
    { binding: 0, resource: { buffer: paramsBuf } },
    { binding: 1, resource: { buffer: resultsBuf } },
  ],
});

/** Dispatch `count` nonces from `base`; returns results words and wall ms. */
async function run(ctx, base, count, difficulty) {
  const params = new Uint32Array(PARAMS_U32);
  params.set(ctx.mid, 0);
  params.set(ctx.tailWords, 8);
  params[11] = difficulty >>> 0;
  params[12] = base >>> 0;
  params[13] = count >>> 0;
  device.queue.writeBuffer(paramsBuf, 0, params);
  device.queue.writeBuffer(resultsBuf, 0, new Uint32Array(RESULTS_U32));
  const groups = Math.ceil(count / PER_GROUP);
  const t0 = performance.now();
  const enc = device.createCommandEncoder();
  const pass = enc.beginComputePass();
  pass.setPipeline(pipeline);
  pass.setBindGroup(0, bind);
  pass.dispatchWorkgroups(groups);
  pass.end();
  enc.copyBufferToBuffer(resultsBuf, 0, readBuf, 0, RESULTS_U32 * 4);
  device.queue.submit([enc.finish()]);
  await device.queue.onSubmittedWorkDone();
  const ms = performance.now() - t0;
  await readBuf.mapAsync(GPUMapMode.READ);
  const u32 = new Uint32Array(readBuf.getMappedRange()).slice(0);
  readBuf.unmap();
  return { u32, ms, groups };
}

function hitsFrom(u32) {
  const total = u32[0];
  const hits = [];
  for (let s = 0; s < Math.min(8, total); s++) {
    const words = Array.from(u32.slice(12 + s * 8, 12 + s * 8 + 8));
    hits.push({ nonce: u32[4 + s], words, digest: wordsToHex(words) });
  }
  return { total, hits, reported: u32[1] };
}

const leadingZeroBits = (hex) => {
  let n = 0;
  for (const byte of hexToBytes(hex)) {
    if (byte) return n + 8 - byte.toString(2).length;
    n += 8;
  }
  return n;
};

/* ------------------------------------------------------------------ */
/* Phase 1: digest equality across randomData, difficulty, base nonce  */
/* ------------------------------------------------------------------ */

let comparisons = 0;
let mismatches = 0;
const mismatchSamples = [];

const RANDOM_DATA = [
  '6a1f8c2e4d0b9a7f3c5e2d1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d',
  '00'.repeat(32),
  'ff'.repeat(32),
];
const DIFFICULTIES = [1, 16, 32, 255];
const BASES = [0, 1, 12345, 0xdeadbeef];

for (const rdHex of RANDOM_DATA) {
  for (const difficulty of DIFFICULTIES) {
    const ctx = buildCtx(rdHex, difficulty);
    // Every nonce in every dispatch; four consecutive nonces per dispatch.
    const wanted = [];
    for (const base of BASES) for (let i = 0; i < LANES; i++) wanted.push((base + i) >>> 0);
    const truth = await pyRef(rdHex, difficulty, 'digests', ...wanted);
    for (const base of BASES) {
      const { u32 } = await run(ctx, base, LANES, 0);   // difficulty 0: every nonce is a hit
      const got = hitsFrom(u32);
      for (let i = 0; i < LANES; i++) {
        const nonce = (base + i) >>> 0;
        const hit = got.hits.find((h) => h.nonce === nonce);
        const mine = hit ? hit.digest : '(missing)';
        const theirs = truth[String(nonce)];
        comparisons++;
        if (mine !== theirs) {
          mismatches++;
          if (mismatchSamples.length < 5) {
            mismatchSamples.push(`rd=${rdHex.slice(0, 8)}… d=${difficulty} nonce=${nonce}\n  gpu ${mine}\n  ref ${theirs}`);
          }
        }
      }
    }
  }
}

/* ------------------------------------------------------------------ */
/* Phase 2: anubis_work behaviour — minimum qualifying nonce in range  */
/* ------------------------------------------------------------------ */

const SCAN_RD = RANDOM_DATA[0];
// Low hit density on purpose: the shader keeps only eight hits, so "the first
// qualifying nonce in the range" is only recoverable when the range has at most
// eight. ~1 hit expected per 65536 nonces at difficulty 16.
const SCAN = [
  { difficulty: 16, base: 0, count: 1 << 16 },
  { difficulty: 16, base: 2000000, count: 1 << 16 },
  { difficulty: 16, base: 50000000, count: 1 << 16 },
  { difficulty: 14, base: 0, count: 1 << 14 },
];
let scanChecks = 0;
for (const c of SCAN) {
  const ctx = buildCtx(SCAN_RD, c.difficulty);
  const { u32, ms } = await run(ctx, c.base, c.count, c.difficulty);
  const got = hitsFrom(u32);
  const ref = await pyRef(SCAN_RD, c.difficulty, 'scan', c.base, c.count, 8);
  const refHits = ref.hits;
  scanChecks++;
  comparisons++;

  if (refHits.length < 8 && got.total <= 8) {
    // The whole hit set is observable on both sides: compare it exactly, both
    // the nonces (anubis_work returns the minimum) and each digest.
    const refNonces = refHits.map((h) => h[0]).sort((a, b) => a - b);
    const gpuNonces = got.hits.map((h) => h.nonce).sort((a, b) => a - b);
    const sameSet = refNonces.length === gpuNonces.length &&
      refNonces.every((n, i) => n === gpuNonces[i]);
    if (!sameSet) {
      mismatches++;
      mismatchSamples.push(`scan d=${c.difficulty} base=${c.base} count=${c.count}: ` +
        `hit set gpu=[${gpuNonces}] ref=[${refNonces}]`);
      continue;
    }
    for (const [nonce, refDigest] of refHits) {
      const kernelDigest = got.hits.find((h) => h.nonce === nonce)?.digest;
      comparisons++;
      if (kernelDigest !== refDigest) {
        mismatches++;
        if (mismatchSamples.length < 8) {
          mismatchSamples.push(`scan d=${c.difficulty} nonce=${nonce}: gpu ${kernelDigest} ref ${refDigest}`);
        }
      }
    }
    const first = refNonces.length ? refNonces[0] : null;
    console.log(`scan d=${c.difficulty} base=${c.base} count=${c.count}: hit set [${refNonces}] ` +
      `(anubis_work would return ${first}) in ${ms.toFixed(1)} ms`);
  } else {
    // Too many hits for the eight result slots: "first hit" is not observable,
    // so only re-verify the nonces the kernel did report.
    console.log(`scan d=${c.difficulty} base=${c.base} count=${c.count}: ${got.total} hits ` +
      `(only 8 slots; checking reported hits only) in ${ms.toFixed(1)} ms`);
    if (got.hits.length) {
      const truth = await pyRef(SCAN_RD, c.difficulty, 'digests', ...got.hits.map((h) => h.nonce));
      for (const h of got.hits) {
        comparisons++;
        if (h.digest !== truth[String(h.nonce)] || leadingZeroBits(h.digest) < c.difficulty) {
          mismatches++;
          if (mismatchSamples.length < 8) {
            mismatchSamples.push(`scan d=${c.difficulty} nonce=${h.nonce}: gpu ${h.digest} ` +
              `ref ${truth[String(h.nonce)]}`);
          }
        }
      }
    }
  }
}

/* ------------------------------------------------------------------ */
/* Phase 3: throughput                                                 */
/* ------------------------------------------------------------------ */

const maxGroups = Math.min(device.limits.maxComputeWorkgroupsPerDimension, 65535);
const COUNT = Math.min(1 << 22, maxGroups * PER_GROUP);
const benchCtx = buildCtx(SCAN_RD, 16);
await run(benchCtx, 0, COUNT, 256);            // warm-up: 256 leading zero bits can never hit
const runsMs = [];
for (let r = 0; r < 5; r++) {
  const { u32, ms } = await run(benchCtx, 0, COUNT, 256);
  if (u32[0] !== 0) fail(`kernel reported ${u32[0]} hits at difficulty 256`);
  runsMs.push(ms);
}
runsMs.sort((a, b) => a - b);
const medianS = runsMs[2] / 1000;
const rates = runsMs.map((ms) => COUNT / (ms / 1000));
const rate = COUNT / medianS;

/* ------------------------------------------------------------------ */
/* Report                                                              */
/* ------------------------------------------------------------------ */

console.log('');
console.log(`adapter: ${adapterName}${adapterLine ? ` [${adapterLine}]` : ''}`);
console.log(`digest comparisons: ${comparisons} (${mismatches} mismatch${mismatches === 1 ? '' : 'es'}); ` +
  `anubis_work-style scans: ${scanChecks}`);
if (mismatches) {
  for (const s of mismatchSamples) console.log('  ' + s);
}
console.log(`hashes/second: ${rate.toFixed(1)} (COUNT=${COUNT} nonces/dispatch, 5 timed runs, ` +
  `median ${medianS.toFixed(6)} s, min ${Math.min(...rates).toFixed(1)}, max ${Math.max(...rates).toFixed(1)}, ` +
  `${LANES} nonces/invocation, adapter="${adapterName}")`);
console.log(`command: deno run --allow-all tools/meatrider-webgpu.mjs`);
Deno.exit(mismatches === 0 ? 0 : 1);
