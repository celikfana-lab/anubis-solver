#!/usr/bin/env node
/**
 * bench-client-resources.mjs — memory and CPU per hash for the three clients:
 * Anubis's sha256.wasm, our 4-wide kernel, and the native library through the
 * Firefox extension's native messaging host.
 *
 *   node tools/bench-client-resources.mjs
 */
/** Client side: memory and CPU per solve, wasm vs native. */
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';

const CH = Buffer.from('9f2c1b4a7e5d3c0b8a1f6e2d4c7b0a9f5e3d1c8b7a6f4e2d1c0b9a8f7e6d5c4b', 'hex');
const DIFF = 20;
const MODULES = [
  ['Anubis sha256.wasm', `${process.env.ANUBIS_WASM_DIR ?? '/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis/web/static/wasm/simd128'}/sha256.wasm`],
  ['our wasm, 4-wide', new URL('../wasm/sha256_pow_batch.wasm', import.meta.url).pathname],
];

const cpuMs = () => { const u = process.cpuUsage(); return (u.user + u.system) / 1000; };

for (const [name, path] of MODULES) {
  const { instance } = await WebAssembly.instantiate(readFileSync(path), { anubis: { anubis_update_nonce: () => {} } });
  const ex = instance.exports;
  new Uint8Array(ex.memory.buffer).set(CH, ex.data_ptr());
  ex.set_data_length(CH.length);
  ex.anubis_work(8, 0, 1);                       // warm
  const mem = ex.memory.buffer.byteLength;
  const t0 = cpuMs();
  let hashes = 0;
  for (let i = 0; i < 3; i++) hashes += (ex.anubis_work(DIFF, 0, 1) >>> 0) + 1;
  const used = cpuMs() - t0;
  console.log(`  ${name.padEnd(22)} ${(mem / 1048576).toFixed(2).padStart(6)} MiB linear memory   ` +
              `${(used / hashes * 1e6).toFixed(2).padStart(6)} ns/hash   ${(hashes / (used / 1000) / 1e6).toFixed(2)} M/s`);
}

// native: the host process's own footprint, read from /proc
const host = spawn('python3', ['-u',
  new URL('../firefox-extension/native-host/anubis_native.py', import.meta.url).pathname],
  { stdio: ['pipe', 'pipe', 'ignore'] });
const pending = []; let buf = Buffer.alloc(0);
host.stdout.on('data', (c) => {
  buf = Buffer.concat([buf, c]);
  while (buf.length >= 4) {
    const n = buf.readUInt32LE(0);
    if (buf.length < 4 + n) break;
    pending.shift()(JSON.parse(buf.subarray(4, 4 + n).toString()));
    buf = buf.subarray(4 + n);
  }
});
const call = (o) => new Promise((res) => {
  const b = Buffer.from(JSON.stringify(o)); const h = Buffer.alloc(4); h.writeUInt32LE(b.length);
  pending.push(res); host.stdin.write(Buffer.concat([h, b]));
});
const stat = () => {
  const raw = readFileSync(`/proc/${host.pid}/stat`, 'utf8');
  const s = raw.slice(raw.lastIndexOf(')') + 2).split(' ');
  const cpu = (Number(s[11]) + Number(s[12])) * 1000 / 100;   // USER_HZ is 100
  const status = readFileSync(`/proc/${host.pid}/status`, 'utf8');
  const rss = Number(/VmRSS:\s+(\d+)/.exec(status)[1]);
  return { cpu, rss };
};
await call({ cmd: 'info' });                     // warm: loads the .so
await call({ cmd: 'solve', algorithm: 'sha256', randomData: CH.toString('hex'), difficulty: 8 });
const before = stat();
let hashes = 0;
for (let i = 0; i < 3; i++) {
  const r = await call({ cmd: 'solve', algorithm: 'sha256', randomData: CH.toString('hex'), difficulty: DIFF });
  hashes += r.nonce + 1;
}
const after = stat();
const used = after.cpu - before.cpu;
console.log(`  ${'native .so (Firefox)'.padEnd(22)} ${(after.rss / 1024).toFixed(2).padStart(6)} MiB process RSS     ` +
            `${(used / hashes * 1e6).toFixed(2).padStart(6)} ns/hash   ${(hashes / (used / 1000) / 1e6).toFixed(2)} M/s`);
host.stdin.end();
