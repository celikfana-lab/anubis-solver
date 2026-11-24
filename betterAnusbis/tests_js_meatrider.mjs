#!/usr/bin/env node
/*
 * tests_js_meatrider.mjs — the challenge page's `meatrider` paths.
 *
 * Three things are checked here, all without a gate:
 *
 *   1. the page's pure-JavaScript solver, forced with #pure-js, against an
 *      independent SHA-256d built on node:crypto and the header layout from
 *      src/meatrider/meatrider.h;
 *   2. the same solver when WebAssembly is absent altogether (the automatic
 *      fallback a browser with wasm disabled takes);
 *   3. the wasm driver: the page fetches meatrider_pow.wasm, drives the
 *      windowed `anubis_work_limited` export and reports the answer -- the
 *      code path a real browser takes. The fetch is stubbed from ./web/.
 *
 * and that the ASIC end of the ladder refuses to mine instead of spinning:
 * above 32 bits of difficulty one sweep of the nonce space is already 2^32
 * hashes, so the page says so and stops.
 *
 *   node tests_js_meatrider.mjs
 */
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const HERE = new URL('.', import.meta.url);
const source = readFileSync(new URL('./betterAnusbis.c', import.meta.url), 'utf8');
const start = source.indexOf('static const char *CHALLENGE_JS = R"JS(');
if (start < 0) throw new Error('CHALLENGE_JS not found in betterAnusbis.c');
const begin = source.indexOf('R"JS(', start) + 5;
const end = source.indexOf(')JS"', begin);
if (end < 0) throw new Error('CHALLENGE_JS terminator not found');
const pageJs = source.slice(begin, end);
const wasmBytes = readFileSync(new URL('./web/meatrider_pow.wasm', HERE));

const sha256 = (buf) => createHash('sha256').update(buf).digest();

/* The specification, in the test: 80-byte Bitcoin header, SHA-256d, display order. */
function compact(target) {
    let size = Math.ceil(target.toString(2).length / 8);
    let c = size <= 3 ? target << BigInt(8 * (3 - size)) : target >> BigInt(8 * (size - 3));
    if (c & 0x00800000n) { c >>= 8n; size += 1; }
    return Number(c | BigInt(size << 24));
}
function bitcoinHash(rd, difficulty, nonce) {
    const hdr = Buffer.alloc(80);
    hdr.writeUInt32LE(1, 0);
    rd.copy(hdr, 4);
    sha256(Buffer.concat([Buffer.from('meatrider'), rd])).copy(hdr, 36);
    hdr.writeUInt32LE(1231006505, 68);
    hdr.writeUInt32LE(compact(1n << BigInt(256 - difficulty)), 72);
    hdr.writeUInt32LE(nonce, 76);
    return Buffer.from(sha256(sha256(hdr))).reverse();
}
function leadingZeroBits(buf) {
    let n = 0;
    for (const x of buf) {
        if (x === 0) { n += 8; continue; }
        n += Math.clz32(x) - 24;
        break;
    }
    return n;
}
const hexToBytes = (hex) => Buffer.from(hex, 'hex');

/* Run the page's solver for one synthetic meatrider challenge. */
async function solve({ difficulty, randomData, hash = '', wasm = true, withKernel = false,
                       untilSaid = null }) {
    const algorithm = 'meatrider';
    const payload = JSON.stringify({
        rules: { algorithm, difficulty },
        challenge: {
            issuedAt: '1', metadata: {}, id: 'test.1', method: algorithm,
            randomData, policyRuleHash: '', difficulty, spent: false, extensions: null,
        },
    });
    const state = { answer: null, said: [] };
    const status = { set textContent(v) { state.said.push(String(v)); } };
    const sandbox = {
        console, TextEncoder, URL, setTimeout, clearTimeout,
        performance: { now: () => Number(process.hrtime.bigint() / 1000n) / 1000 },
        document: {
            getElementById: (id) => id === 'anubis_challenge' ? { textContent: payload }
                                    : id === 'status' ? status : null,
        },
        location: {
            hash, search: '', pathname: '/', origin: 'http://gate.test',
            replace: (u) => { state.answer = u; },
        },
    };
    if (withKernel) {
        sandbox.fetch = async (url) => {
            if (!String(url).includes('meatrider_pow.wasm')) throw new Error('unexpected fetch ' + url);
            return { arrayBuffer: async () => wasmBytes.buffer.slice(
                wasmBytes.byteOffset, wasmBytes.byteOffset + wasmBytes.byteLength) };
        };
    } else {
        sandbox.fetch = async () => { throw new Error('no kernels in this test'); };
    }
    if (wasm) sandbox.WebAssembly = WebAssembly;
    else delete sandbox.WebAssembly;
    const context = vm.createContext(sandbox);
    vm.runInContext(pageJs, context, { filename: 'challenge.js' });

    const deadline = Date.now() + 120000;
    const done = () => untilSaid ? state.said.some((s) => untilSaid.test(s))
                                 : state.answer !== null;
    while (!done() && Date.now() < deadline)
        await new Promise((r) => setTimeout(r, 20));
    if (!done()) throw new Error('solver did not finish; said: ' + state.said.join(' | '));
    if (untilSaid) return { said: state.said };
    const u = new URL(state.answer);
    return {
        nonce: Number(u.searchParams.get('nonce')),
        response: u.searchParams.get('response'),
        said: state.said,
    };
}

let passed = 0;
let failed = 0;
function check(name, ok, detail = '') {
    if (ok) { passed++; console.log(`  PASS  ${name}`); }
    else { failed++; console.log(`  FAIL  ${name}${detail ? ': ' + detail : ''}`); }
}

// 1. pure JavaScript, forced by #pure-js
for (const [difficulty, randomData] of [
    [4, '00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef'],
    [8, 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221117'],
]) {
    const { nonce, response, said } = await solve({ difficulty, randomData, hash: '#pure-js' });
    const want = bitcoinHash(hexToBytes(randomData), difficulty, nonce).toString('hex');
    check(`pure-js digest d=${difficulty}`, response === want, `${response} != ${want}`);
    check(`pure-js leading bits d=${difficulty}`, leadingZeroBits(hexToBytes(response)) >= difficulty);
    check(`pure-js mentions the rung d=${difficulty}`,
          said.some((s) => /meatrider: .* 2\^/.test(s)), said.join(' | '));
}

// 2. no WebAssembly at all: automatic fallback, same proof
{
    const difficulty = 6;
    const randomData = 'a0b1c2d3e4f5061728394556677889900a1b2c3d4e5f60718293a4b5c6d7e8f9';
    const { nonce, response } = await solve({ difficulty, randomData, wasm: false });
    const want = bitcoinHash(hexToBytes(randomData), difficulty, nonce).toString('hex');
    check('no-wasm digest', response === want, `${response} != ${want}`);
    check('no-wasm leading bits', leadingZeroBits(hexToBytes(response)) >= difficulty);
}

// 3. the wasm driver: the kernel from ./web/, windowed through the page
for (const difficulty of [4, 12]) {
    const randomData = createHash('sha256').update(`kernel-${difficulty}`).digest('hex');
    const { nonce, response } = await solve({ difficulty, randomData, withKernel: true });
    const want = bitcoinHash(hexToBytes(randomData), difficulty, nonce).toString('hex');
    check(`wasm digest d=${difficulty}`, response === want, `${response} != ${want}`);
    check(`wasm leading bits d=${difficulty}`, leadingZeroBits(hexToBytes(response)) >= difficulty);
}

// 4. the ASIC rung refuses to mine
{
    const randomData = createHash('sha256').update('asic').digest('hex');
    const { said } = await solve({ difficulty: 40, randomData, withKernel: true,
                                   untilSaid: /priced for an ASIC/ });
    check('asic rung says it is priced for an ASIC',
          said.some((s) => /priced for an ASIC/.test(s)), said.join(' | '));
    check('asic rung reports the work instead of solving',
          said.some((s) => /of this browser's wasm kernel/.test(s)), said.join(' | '));
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
