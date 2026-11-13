// hashx_jit.mjs - compile a HashX challenge into a specialized wasm module, in JS.
//
// A HashX program is fixed for a whole challenge: 512 instructions derived from
// the challenge bytes by a deterministic PRF. The interpreter in hashx_pow.wasm
// pays a dispatch per instruction for every nonce; a module that has the program
// baked in does not. tools/gen_hashx_wat.py proves the speedup, but its output is
// assembled by wat2wasm, which a browser does not have. So this file emits the
// wasm binary directly: same derivation as src/hashx/hashx.c (BLAKE2b-512 below
// is SipState::pair_from_seed, the program generator is hashx_program_generate),
// same straight-line body as the Python generator, no toolchain.
//
// The emitted module carries two interfaces on purpose:
//
//   hash(nonce) -> leading zero bits, digest at memory 0     (the demo's bench)
//   digest(nonce) -> same function, aliased for reading
//   solve(base, difficulty, count) -> hit or -1
//   ninstr() -> the program size
//   data_ptr / set_data_length / anubis_work(diff,nonce,step) / result_hash_* /
//   memory                                                   (Anubis's ABI)
//
// so the same bytes drop into the demo and into a challenge page. There are no
// imports, matching hashx_pow.wasm: the program is already in the code.
//
// Numbers are BigInt only where a 64-bit value crosses the JS boundary (keys,
// BLAKE2b, SipHash, wasm i64 constants). The generator itself is 32-bit.

const M32 = 0xFFFFFFFFn;
const M64 = (1n << 64n) - 1n;

const u64 = (x) => x & M64;

function rotl(x, n) {
  const k = BigInt(n);
  return u64((x << k) | (x >> (64n - k)));
}

function load64(bytes, off) {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(bytes[off + i]);
  return v;
}

function store64(out, off, v) {
  for (let i = 0; i < 8; i++) {
    out[off + i] = Number(v & 0xFFn);
    v >>= 8n;
  }
}

/* ------------------------------------------------------------- BLAKE2b-512 */

// HashX derives both SipHash states from BLAKE2b-512(seed, salt="HashX v1").
// The parameters must match hashx_blake2_params in src/hashx/hashx.c.
const BLAKE2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

// The C generator unrolls twelve rounds and names each sigma row explicitly;
// rows 10 and 11 are rows 0 and 1 again, which BLAKE2b's round % 10 also gives.
const BLAKE2B_SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

function blake2bParamBlock() {
  const p = new Uint8Array(64);
  p[0] = 64; // digest_length
  p[1] = 0;  // key_length
  p[2] = 1;  // fanout
  p[3] = 1;  // depth
  // leaf_length, node_offset, node_depth, inner_length, reserved stay zero
  const salt = [0x48, 0x61, 0x73, 0x68, 0x58, 0x20, 0x76, 0x31]; // "HashX v1"
  p.set(salt, 32);
  return p;
}

function blake2bG(v, m, r, i, j, a, b, c, d) {
  const s = BLAKE2B_SIGMA[r];
  v[a] = u64(v[a] + v[b] + m[s[i]]);
  v[d] = rotl(v[d] ^ v[a], 32);   // rotr 32
  v[c] = u64(v[c] + v[d]);
  v[b] = rotl(v[b] ^ v[c], 40);   // rotr 24
  v[a] = u64(v[a] + v[b] + m[s[j]]);
  v[d] = rotl(v[d] ^ v[a], 48);   // rotr 16
  v[c] = u64(v[c] + v[d]);
  v[b] = rotl(v[b] ^ v[c], 1);    // rotr 63
}

function blake2bCompress(st, block) {
  const m = new Array(16);
  for (let i = 0; i < 16; i++) m[i] = load64(block, i * 8);
  const v = new Array(16);
  for (let i = 0; i < 8; i++) v[i] = st.h[i];
  v[8] = BLAKE2B_IV[0];
  v[9] = BLAKE2B_IV[1];
  v[10] = BLAKE2B_IV[2];
  v[11] = BLAKE2B_IV[3];
  v[12] = BLAKE2B_IV[4] ^ st.t0;
  v[13] = BLAKE2B_IV[5] ^ st.t1;
  v[14] = BLAKE2B_IV[6] ^ st.f0;
  v[15] = BLAKE2B_IV[7] ^ st.f1;
  for (let r = 0; r < 12; r++) {
    blake2bG(v, m, r, 0, 1, 0, 4, 8, 12);
    blake2bG(v, m, r, 2, 3, 1, 5, 9, 13);
    blake2bG(v, m, r, 4, 5, 2, 6, 10, 14);
    blake2bG(v, m, r, 6, 7, 3, 7, 11, 15);
    blake2bG(v, m, r, 8, 9, 0, 5, 10, 15);
    blake2bG(v, m, r, 10, 11, 1, 6, 11, 12);
    blake2bG(v, m, r, 12, 13, 2, 7, 8, 13);
    blake2bG(v, m, r, 14, 15, 3, 4, 9, 14);
  }
  for (let i = 0; i < 8; i++) st.h[i] = st.h[i] ^ v[i] ^ v[i + 8];
}

function blake2bIncrement(st, inc) {
  st.t0 = u64(st.t0 + inc);
  st.t1 = u64(st.t1 + (st.t0 < inc ? 1n : 0n));
}

function blake2bUpdate(st, data) {
  let pin = 0;
  let inlen = data.length;
  if (inlen === 0) return;
  if (st.buflen + inlen > 128) {
    const fill = 128 - st.buflen;
    st.buf.set(data.subarray(0, fill), st.buflen);
    blake2bIncrement(st, 128n);
    blake2bCompress(st, st.buf);
    st.buflen = 0;
    pin = fill;
    inlen -= fill;
    while (inlen > 128) {
      blake2bIncrement(st, 128n);
      blake2bCompress(st, data.subarray(pin, pin + 128));
      pin += 128;
      inlen -= 128;
    }
  }
  st.buf.set(data.subarray(pin, pin + inlen), st.buflen);
  st.buflen += inlen;
}

function blake2b512(seed) {
  const h = BLAKE2B_IV.slice();
  const param = blake2bParamBlock();
  for (let i = 0; i < 8; i++) h[i] ^= load64(param, i * 8);
  const st = { h, buf: new Uint8Array(128), buflen: 0, t0: 0n, t1: 0n, f0: 0n, f1: 0n };
  blake2bUpdate(st, seed);
  const inc = BigInt(st.buflen);
  const t0 = u64(st.t0 + inc);
  st.t1 = u64(st.t1 + (t0 < inc ? 1n : 0n));
  st.t0 = t0;
  st.f0 = M64;
  st.buf.fill(0, st.buflen);
  blake2bCompress(st, st.buf);
  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i++) store64(out, i * 8, st.h[i]);
  return out;
}

/** The two SipHash states HashX builds from a seed, exactly as hashx_build() does.
 *  keys[0] seeds the program generator; keys[1] is the register key hashes use. */
export function keyPairFromSeed(seed) {
  const out = blake2b512(seed);
  const programKey = [];
  const registerKey = [];
  for (let i = 0; i < 4; i++) {
    programKey.push(load64(out, 8 * i));
    registerKey.push(load64(out, 32 + 8 * i));
  }
  return { programKey, registerKey };
}

/* --------------------------------------------------------------- SipHash */

function sipround(v) {
  v[0] = u64(v[0] + v[1]);
  v[2] = u64(v[2] + v[3]);
  v[1] = rotl(v[1], 13);
  v[3] = rotl(v[3], 16);
  v[1] ^= v[0];
  v[3] ^= v[2];
  v[0] = rotl(v[0], 32);
  v[2] = u64(v[2] + v[1]);
  v[0] = u64(v[0] + v[3]);
  v[1] = rotl(v[1], 17);
  v[3] = rotl(v[3], 21);
  v[1] ^= v[2];
  v[3] ^= v[0];
  v[2] = rotl(v[2], 32);
}

/** SipHash-1-3 in counter mode: one 64-bit output per (counter, key). */
function siphash13(input, key) {
  const v = [key[0], key[1], key[2], key[3]];
  v[3] ^= input;
  sipround(v);
  v[0] ^= input;
  v[2] ^= 0xffn;
  sipround(v);
  sipround(v);
  sipround(v);
  return (v[0] ^ v[1]) ^ (v[2] ^ v[3]);
}

/** The generator's byte/word source. Buffers are refilled big-endian per word. */
class SipRng {
  constructor(key) {
    this.key = key;
    this.counter = 0n;
    this.buffer8 = 0n;
    this.buffer32 = 0n;
    this.count8 = 0;
    this.count32 = 0;
  }

  u8() {
    if (this.count8 === 0) {
      this.buffer8 = siphash13(this.counter, this.key);
      this.counter = u64(this.counter + 1n);
      this.count8 = 8;
    }
    this.count8--;
    return Number((this.buffer8 >> BigInt(this.count8 * 8)) & 0xFFn);
  }

  u32() {
    if (this.count32 === 0) {
      this.buffer32 = siphash13(this.counter, this.key);
      this.counter = u64(this.counter + 1n);
      this.count32 = 2;
    }
    this.count32--;
    return Number((this.buffer32 >> BigInt(this.count32 * 32)) & 0xFFFFFFFFn);
  }
}

/* ------------------------------------------------- HashX program generator */

// Instruction types, in the enum order of src/hashx/hashx.c.
const OP_UMULH_R = 0;
const OP_SMULH_R = 1;
const OP_MUL_R = 2;
const OP_SUB_R = 3;
const OP_XOR_R = 4;
const OP_ADD_RS = 5;
const OP_ROR_C = 6;
const OP_ADD_C = 7;
const OP_XOR_C = 8;
const OP_TARGET = 9;
const OP_BRANCH = 10;

const TARGET_CYCLE = 192;
const REQUIREMENT_SIZE = 512;
const REQUIREMENT_MUL_COUNT = 192;
const REQUIREMENT_LATENCY = 195;
const REGISTER_NEEDS_DISPLACEMENT = 5;
const PORT_MAP_SIZE = TARGET_CYCLE + 4;
const MAX_RETRIES = 1;
const LOG2_BRANCH_PROB = 4;
const BRANCH_MASK = 0x80000000;

const PORT_NONE = 0;
const PORT_P0 = 1;
const PORT_P1 = 2;
const PORT_P5 = 4;
const PORT_P01 = PORT_P0 | PORT_P1;
const PORT_P05 = PORT_P0 | PORT_P5;
const PORT_P015 = PORT_P0 | PORT_P1 | PORT_P5;

// One template per instruction shape; the field names follow instr_template.
const TPL = {
  umulh: { type: OP_UMULH_R, latency: 4, uop1: PORT_P1, uop2: PORT_P5, immMask: 0,
           group: OP_UMULH_R, imm0: false, distinct: false, parSrc: false, hasSrc: true, hasDst: true },
  smulh: { type: OP_SMULH_R, latency: 4, uop1: PORT_P1, uop2: PORT_P5, immMask: 0,
           group: OP_SMULH_R, imm0: false, distinct: false, parSrc: false, hasSrc: true, hasDst: true },
  mul:   { type: OP_MUL_R, latency: 3, uop1: PORT_P1, uop2: PORT_NONE, immMask: 0,
           group: OP_MUL_R, imm0: false, distinct: true, parSrc: true, hasSrc: true, hasDst: true },
  sub:   { type: OP_SUB_R, latency: 1, uop1: PORT_P015, uop2: PORT_NONE, immMask: 0,
           group: OP_ADD_RS, imm0: false, distinct: true, parSrc: true, hasSrc: true, hasDst: true },
  xor:   { type: OP_XOR_R, latency: 1, uop1: PORT_P015, uop2: PORT_NONE, immMask: 0,
           group: OP_XOR_R, imm0: false, distinct: true, parSrc: true, hasSrc: true, hasDst: true },
  addrs: { type: OP_ADD_RS, latency: 1, uop1: PORT_P01, uop2: PORT_NONE, immMask: 3,
           group: OP_ADD_RS, imm0: true, distinct: true, parSrc: true, hasSrc: true, hasDst: true },
  ror:   { type: OP_ROR_C, latency: 1, uop1: PORT_P05, uop2: PORT_NONE, immMask: 63,
           group: OP_ROR_C, imm0: false, distinct: true, parSrc: false, hasSrc: false, hasDst: true },
  addc:  { type: OP_ADD_C, latency: 1, uop1: PORT_P015, uop2: PORT_NONE, immMask: 0xFFFFFFFF,
           group: OP_ADD_C, imm0: false, distinct: true, parSrc: false, hasSrc: false, hasDst: true },
  xorc:  { type: OP_XOR_C, latency: 1, uop1: PORT_P015, uop2: PORT_NONE, immMask: 0xFFFFFFFF,
           group: OP_XOR_C, imm0: false, distinct: true, parSrc: false, hasSrc: false, hasDst: true },
  target:{ type: OP_TARGET, latency: 1, uop1: PORT_P015, uop2: PORT_P015, immMask: 0,
           group: OP_TARGET, imm0: false, distinct: true, parSrc: false, hasSrc: false, hasDst: false },
  branch:{ type: OP_BRANCH, latency: 1, uop1: PORT_P015, uop2: PORT_P015, immMask: BRANCH_MASK,
           group: OP_BRANCH, imm0: false, distinct: true, parSrc: false, hasSrc: false, hasDst: false },
};

const INSTR_LOOKUP = [TPL.ror, TPL.xorc, TPL.addc, TPL.addc, TPL.sub, TPL.xor, TPL.xorc, TPL.addrs];
const WIDE_MUL_LOOKUP = [TPL.smulh, TPL.umulh];

const ITEM_MUL = { templates: [TPL.mul], mask0: 0, mask1: 0, duplicates: true };
const ITEM_TARGET = { templates: [TPL.target], mask0: 0, mask1: 0, duplicates: true };
const ITEM_BRANCH = { templates: [TPL.branch], mask0: 0, mask1: 0, duplicates: true };
const ITEM_WIDE_MUL = { templates: WIDE_MUL_LOOKUP, mask0: 1, mask1: 1, duplicates: true };
const ITEM_ANY = { templates: INSTR_LOOKUP, mask0: 7, mask1: 3, duplicates: false };

// The 36-slot schedule of instruction families. Every 36 instructions is one
// "sub_cycle"; the blend of families is what makes the program deterministic
// across implementations.
const PROGRAM_LAYOUT = [
  ITEM_MUL, ITEM_TARGET, ITEM_ANY, ITEM_MUL, ITEM_ANY, ITEM_ANY, ITEM_MUL, ITEM_ANY,
  ITEM_ANY, ITEM_MUL, ITEM_ANY, ITEM_ANY, ITEM_WIDE_MUL, ITEM_ANY, ITEM_ANY, ITEM_MUL,
  ITEM_ANY, ITEM_ANY, ITEM_MUL, ITEM_BRANCH, ITEM_ANY, ITEM_MUL, ITEM_ANY, ITEM_ANY,
  ITEM_WIDE_MUL, ITEM_ANY, ITEM_ANY, ITEM_MUL, ITEM_ANY, ITEM_ANY, ITEM_MUL, ITEM_ANY,
  ITEM_ANY, ITEM_MUL, ITEM_ANY, ITEM_ANY,
];

const isMul = (type) => type <= OP_MUL_R;

function selectTemplate(ctx, lastInstr, attempt) {
  const item = PROGRAM_LAYOUT[ctx.subCycle % 36];
  let tpl;
  do {
    const index = item.mask0
      ? ctx.rng.u8() & (attempt > 0 ? item.mask1 : item.mask0)
      : 0;
    tpl = item.templates[index];
  } while (!item.duplicates && tpl.group === lastInstr);
  return tpl;
}

function branchMask(rng) {
  let mask = 0;
  let popcnt = 0;
  while (popcnt < LOG2_BRANCH_PROB) {
    const bit = rng.u8() % 32;
    const bitmask = (1 << bit) >>> 0;
    if (!(mask & bitmask)) {
      mask = (mask | bitmask) >>> 0;
      popcnt++;
    }
  }
  return mask;
}

function instrFromTemplate(tpl, rng, instr) {
  instr.op = tpl.type;
  if (tpl.immMask) {
    if (tpl.immMask === BRANCH_MASK) {
      instr.imm = branchMask(rng);
    } else {
      do {
        instr.imm = (rng.u32() & tpl.immMask) >>> 0;
      } while (instr.imm === 0 && !tpl.imm0);
    }
  }
  if (!tpl.parSrc) {
    instr.opPar = tpl.distinct ? 0xFFFFFFFF : rng.u32();
  }
  if (!tpl.hasSrc) instr.src = -1;
  if (!tpl.hasDst) instr.dst = -1;
}

function selectRegister(available, gen, out) {
  if (out.count === 0) return false;
  const index = out.count > 1 ? gen.u32() % out.count : 0;
  out.value = available[index];
  return true;
}

function selectDestination(tpl, instr, ctx, cycle) {
  const available = [];
  for (let i = 0; i < 8; i++) {
    const r = ctx.registers[i];
    let ok = r.latency <= cycle;
    ok = ok && (!tpl.distinct || i !== instr.src);
    ok = ok && (ctx.chainMul || tpl.group !== OP_MUL_R || r.lastOp !== OP_MUL_R);
    ok = ok && (r.lastOp !== tpl.group || (r.lastOpPar >>> 0) !== (instr.opPar >>> 0));
    ok = ok && (instr.op !== OP_ADD_RS || i !== REGISTER_NEEDS_DISPLACEMENT);
    if (ok) available.push(i);
  }
  const out = { value: -1, count: available.length };
  if (!selectRegister(available, ctx.rng, out)) return false;
  instr.dst = out.value;
  return true;
}

function selectSource(tpl, instr, ctx, cycle) {
  const available = [];
  for (let i = 0; i < 8; i++) {
    if (ctx.registers[i].latency <= cycle) available.push(i);
  }
  if (available.length === 2 && instr.op === OP_ADD_RS &&
      (available[0] === REGISTER_NEEDS_DISPLACEMENT || available[1] === REGISTER_NEEDS_DISPLACEMENT)) {
    instr.opPar = instr.src = REGISTER_NEEDS_DISPLACEMENT;
    return true;
  }
  const out = { value: -1, count: available.length };
  if (selectRegister(available, ctx.rng, out)) {
    instr.src = out.value;
    if (tpl.parSrc) instr.opPar = instr.src;
    return true;
  }
  return false;
}

function scheduleUop(uop, ctx, cycle, commit) {
  for (; cycle < PORT_MAP_SIZE; cycle++) {
    if ((uop & PORT_P5) && !ctx.ports[cycle][2]) {
      if (commit) ctx.ports[cycle][2] = uop;
      return cycle;
    }
    if ((uop & PORT_P0) && !ctx.ports[cycle][0]) {
      if (commit) ctx.ports[cycle][0] = uop;
      return cycle;
    }
    if ((uop & PORT_P1) && !ctx.ports[cycle][1]) {
      if (commit) ctx.ports[cycle][1] = uop;
      return cycle;
    }
  }
  return -1;
}

function scheduleInstr(tpl, ctx, commit) {
  if (tpl.uop2 === PORT_NONE) return scheduleUop(tpl.uop1, ctx, ctx.cycle, commit);
  for (let cycle = ctx.cycle; cycle < PORT_MAP_SIZE; cycle++) {
    const c1 = scheduleUop(tpl.uop1, ctx, cycle, false);
    const c2 = scheduleUop(tpl.uop2, ctx, cycle, false);
    if (c1 >= 0 && c1 === c2) {
      if (commit) {
        scheduleUop(tpl.uop1, ctx, cycle, true);
        scheduleUop(tpl.uop2, ctx, cycle, true);
      }
      return c1;
    }
  }
  return -1;
}

/** Generate the 512-instruction program, or null if the seed fails the constraints. */
export function generateProgram(key) {
  const ctx = {
    cycle: 0,
    subCycle: 0,
    mulCount: 0,
    chainMul: false,
    latency: 0,
    rng: new SipRng(key),
    registers: [],
    ports: Array.from({ length: PORT_MAP_SIZE }, () => [0, 0, 0]),
  };
  for (let i = 0; i < 8; i++) {
    ctx.registers.push({ latency: 0, lastOp: -1, lastOpPar: -1 });
  }

  const program = [];
  let attempt = 0;
  let lastInstr = -1;

  while (program.length < REQUIREMENT_SIZE) {
    const tpl = selectTemplate(ctx, lastInstr, attempt);
    lastInstr = tpl.group;

    const instr = { op: 0, dst: -1, src: -1, imm: 0, opPar: 0xFFFFFFFF };
    instrFromTemplate(tpl, ctx.rng, instr);

    let scheduleCycle = scheduleInstr(tpl, ctx, false);
    if (scheduleCycle < 0) break;

    ctx.chainMul = attempt > 0;

    if (tpl.hasSrc && !selectSource(tpl, instr, ctx, scheduleCycle)) {
      if (attempt++ < MAX_RETRIES) continue;
      ctx.subCycle += 3;
      ctx.cycle = Math.floor(ctx.subCycle / 3);
      attempt = 0;
      continue;
    }
    if (tpl.hasDst && !selectDestination(tpl, instr, ctx, scheduleCycle)) {
      if (attempt++ < MAX_RETRIES) continue;
      ctx.subCycle += 3;
      ctx.cycle = Math.floor(ctx.subCycle / 3);
      attempt = 0;
      continue;
    }
    attempt = 0;

    scheduleCycle = scheduleInstr(tpl, ctx, true);
    if (scheduleCycle < 0) break;
    if (scheduleCycle >= TARGET_CYCLE) break;

    if (tpl.hasDst) {
      const r = ctx.registers[instr.dst];
      const retire = scheduleCycle + tpl.latency;
      r.latency = retire;
      r.lastOp = tpl.group;
      r.lastOpPar = instr.opPar;
      ctx.latency = Math.max(retire, ctx.latency);
    }

    program.push(instr);
    ctx.mulCount += isMul(instr.op) ? 1 : 0;

    ctx.subCycle++;
    if (tpl.uop2 !== PORT_NONE) ctx.subCycle++;
    ctx.cycle = Math.floor(ctx.subCycle / 3);
  }

  const ok = program.length === REQUIREMENT_SIZE &&
             ctx.mulCount === REQUIREMENT_MUL_COUNT &&
             ctx.latency === REQUIREMENT_LATENCY - 1;
  return ok ? program : null;
}

/**
 * Derive the program for a challenge, retrying with a little-endian counter
 * appended when the generator rejects the seed (Anubis's make_hashx does this).
 * Returns the register key, the program, and the seed actually used.
 */
export function deriveProgram(challenge) {
  const base = challenge instanceof Uint8Array ? challenge : new Uint8Array(challenge);
  for (let counter = 0; ; counter++) {
    let seed;
    if (counter === 0) {
      seed = base;
    } else {
      // hashx_init's counter starts at 0 on the first retry, so it is counter-1
      const c = counter - 1;
      seed = new Uint8Array(base.length + 4);
      seed.set(base);
      seed[base.length] = c & 0xFF;
      seed[base.length + 1] = (c >>> 8) & 0xFF;
      seed[base.length + 2] = (c >>> 16) & 0xFF;
      seed[base.length + 3] = (c >>> 24) & 0xFF;
    }
    const { programKey, registerKey } = keyPairFromSeed(seed);
    const program = generateProgram(programKey);
    if (program) return { registerKey, program, seed, counter };
  }
}

/* ------------------------------------------------------- wasm binary writer */

function uleb(n, out) {
  let v = BigInt(n);
  do {
    let b = Number(v & 0x7Fn);
    v >>= 7n;
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
}

function sleb(n, out) {
  let v = BigInt.asIntN(64, BigInt(n));
  for (;;) {
    const b = Number(v & 0x7Fn);
    v >>= 7n;
    const sign = b & 0x40;
    if ((v === 0n && !sign) || (v === -1n && sign)) {
      out.push(b);
      return;
    }
    out.push(b | 0x80);
  }
}

class Code {
  constructor() {
    this.bytes = [];
  }
  op(...ops) {
    for (const o of ops) this.bytes.push(o);
  }
  uleb(n) {
    uleb(n, this.bytes);
  }
  sleb(n) {
    sleb(n, this.bytes);
  }
  localGet(i) { this.op(0x20); this.uleb(i); }
  localSet(i) { this.op(0x21); this.uleb(i); }
  i32Const(v) { this.op(0x41); this.sleb(v); }
  i64Const(v) { this.op(0x42); this.sleb(v); }
  call(f) { this.op(0x10); this.uleb(f); }
  br(depth) { this.op(0x0c); this.uleb(depth); }
  brIf(depth) { this.op(0x0d); this.uleb(depth); }
  block() { this.op(0x02, 0x40); }
  loop() { this.op(0x03, 0x40); }
  if_() { this.op(0x04, 0x40); }
  else_() { this.op(0x05); }
  end() { this.op(0x0b); }
  i64Store(offset) { this.op(0x37, 0x03); this.uleb(offset); }
}

function raw(bytes) {
  return Array.from(bytes);
}

function section(id, payload) {
  const out = [id];
  uleb(payload.length, out);
  return out.concat(payload);
}

function vec(items) {
  const out = [];
  uleb(items.length, out);
  for (const item of items) out.push(...item);
  return out;
}

// Wasm value types.
const I32 = 0x7F;
const I64 = 0x7E;

function functype(params, results) {
  return [0x60, ...vec(params.map((t) => [t])), ...vec(results.map((t) => [t]))];
}

function name(s) {
  const bytes = raw(new TextEncoder().encode(s));
  const out = [];
  uleb(bytes.length, out);
  return out.concat(bytes);
}

// Function indices and the hash body's local indices.
const F_HASH = 0;
const F_LZ = 1;
const F_SOLVE = 2;
const F_NINSTR = 3;
const F_DATA_PTR = 4;
const F_SET_LEN = 5;
const F_RESULT_PTR = 6;
const F_RESULT_SIZE = 7;
const F_ANUBIS_WORK = 8;

const H_NONCE = 0;
const H_R0 = 1;
const H_W0 = 9;
const H_V0 = 13;
const H_RESULT = 17;
const H_HI = 18;
const H_LO = 19;
const H_T0 = 20;
const H_BE = 24;

const hR = (i) => H_R0 + i;
const hW = (i) => H_W0 + i;
const hV = (i) => H_V0 + i;
const hT = (i) => H_T0 + i;

/** $hi = high 64 bits of x*y, clobbering t0..t3 and lo. */
function emitUmulhi(c, x, y) {
  // t0 = (x & 0xffffffff) * (y & 0xffffffff)
  c.localGet(x); c.i64Const(M32); c.op(0x83);
  c.localGet(y); c.i64Const(M32); c.op(0x83);
  c.op(0x7e); c.localSet(hT(0));
  // t1 = (x & 0xffffffff) * (y >> 32)
  c.localGet(x); c.i64Const(M32); c.op(0x83);
  c.localGet(y); c.i64Const(32); c.op(0x88);
  c.op(0x7e); c.localSet(hT(1));
  // t2 = (x >> 32) * (y & 0xffffffff)
  c.localGet(x); c.i64Const(32); c.op(0x88);
  c.localGet(y); c.i64Const(M32); c.op(0x83);
  c.op(0x7e); c.localSet(hT(2));
  // t3 = (x >> 32) * (y >> 32)
  c.localGet(x); c.i64Const(32); c.op(0x88);
  c.localGet(y); c.i64Const(32); c.op(0x88);
  c.op(0x7e); c.localSet(hT(3));
  // lo = carry word from the three low partial products
  c.localGet(hT(0)); c.i64Const(32); c.op(0x88);
  c.localGet(hT(1)); c.i64Const(M32); c.op(0x83);
  c.localGet(hT(2)); c.i64Const(M32); c.op(0x83);
  c.op(0x7c); c.op(0x7c); c.localSet(H_LO);
  // hi = t3 + carries out of the low half
  c.localGet(hT(3));
  c.localGet(hT(1)); c.i64Const(32); c.op(0x88);
  c.localGet(hT(2)); c.i64Const(32); c.op(0x88);
  c.op(0x7c);
  c.localGet(H_LO); c.i64Const(32); c.op(0x88);
  c.op(0x7c);
  c.op(0x7c); c.localSet(H_HI);
}

/** $hi = high 64 bits of the signed product. */
function emitSmulhi(c, x, y) {
  emitUmulhi(c, x, y);
  // hi -= (x < 0) ? y : 0; hi -= (y < 0) ? x : 0
  c.localGet(H_HI);
  c.localGet(y); c.i64Const(0n); c.localGet(x); c.i64Const(0n); c.op(0x53);
  c.op(0x1b); c.op(0x7d); c.localSet(H_HI);
  c.localGet(H_HI);
  c.localGet(x); c.i64Const(0n); c.localGet(y); c.i64Const(0n); c.op(0x53);
  c.op(0x1b); c.op(0x7d); c.localSet(H_HI);
}

function emitSipRound(c, a, b, cc, d) {
  // a += b; c += d; b = rotl(b,13); d = rotl(d,16); b ^= a; d ^= c
  c.localGet(a); c.localGet(b); c.op(0x7c); c.localSet(a);
  c.localGet(cc); c.localGet(d); c.op(0x7c); c.localSet(cc);
  c.localGet(b); c.i64Const(13); c.op(0x89); c.localSet(b);
  c.localGet(d); c.i64Const(16); c.op(0x89); c.localSet(d);
  c.localGet(b); c.localGet(a); c.op(0x85); c.localSet(b);
  c.localGet(d); c.localGet(cc); c.op(0x85); c.localSet(d);
  c.localGet(a); c.i64Const(32); c.op(0x89); c.localSet(a);
  // a = rotl(a,32); c += b; a += d; b = rotl(b,17); d = rotl(d,21);
  // b ^= c; d ^= a; c = rotl(c,32)
  c.localGet(cc); c.localGet(b); c.op(0x7c); c.localSet(cc);
  c.localGet(a); c.localGet(d); c.op(0x7c); c.localSet(a);
  c.localGet(b); c.i64Const(17); c.op(0x89); c.localSet(b);
  c.localGet(d); c.i64Const(21); c.op(0x89); c.localSet(d);
  c.localGet(b); c.localGet(cc); c.op(0x85); c.localSet(b);
  c.localGet(d); c.localGet(a); c.op(0x85); c.localSet(d);
  c.localGet(cc); c.i64Const(32); c.op(0x89); c.localSet(cc);
}

/** The counter-mode SipHash-2-4 that fills r0..r7, then the program, then finalise. */
function emitHashBody(c, key, program) {
  // ---- PRF: SipHash-2-4 in counter mode ----
  for (let i = 0; i < 4; i++) { c.i64Const(key[i]); c.localSet(hV(i)); }
  c.localGet(hV(1)); c.i64Const(238); c.op(0x85); c.localSet(hV(1));
  c.localGet(hV(3)); c.localGet(H_NONCE); c.op(0x85); c.localSet(hV(3));
  emitSipRound(c, hV(0), hV(1), hV(2), hV(3));
  emitSipRound(c, hV(0), hV(1), hV(2), hV(3));
  c.localGet(hV(0)); c.localGet(H_NONCE); c.op(0x85); c.localSet(hV(0));
  c.localGet(hV(2)); c.i64Const(238); c.op(0x85); c.localSet(hV(2));
  for (let i = 0; i < 4; i++) emitSipRound(c, hV(0), hV(1), hV(2), hV(3));
  for (let i = 0; i < 4; i++) { c.localGet(hV(i)); c.localSet(hR(i)); }
  c.localGet(hV(1)); c.i64Const(221); c.op(0x85); c.localSet(hV(1));
  for (let i = 0; i < 4; i++) emitSipRound(c, hV(0), hV(1), hV(2), hV(3));
  for (let i = 0; i < 4; i++) { c.localGet(hV(i)); c.localSet(hR(4 + i)); }

  // ---- the program, straight-line ----
  // A branch is the only control flow: be guards it and clears after one taken
  // branch, so at most one backward jump per hash. One loop per branch target.
  const targetOf = {};
  let lastTarget = null;
  for (let i = 0; i < program.length; i++) {
    if (program[i].op === OP_TARGET) lastTarget = i;
    else if (program[i].op === OP_BRANCH) {
      targetOf[i] = lastTarget === null ? 0 : lastTarget + 1;
    }
  }
  const heads = [...new Set(Object.values(targetOf))].filter((t) => t < program.length);
  const headSet = new Set(heads);

  const open = []; // { id: target index or -1 for an if }
  const branchDepth = (target) => {
    for (let i = open.length - 1; i >= 0; i--) {
      if (open[i].id === target) return open.length - 1 - i;
    }
    return -1;
  };

  c.i32Const(1); c.localSet(H_BE);
  for (let i = 0; i < program.length; i++) {
    const { op, dst, src, imm } = program[i];
    if (headSet.has(i)) {
      c.loop();
      open.push({ id: i });
    }
    const d = dst & 7;
    const s = src & 7;
    switch (op) {
      case OP_TARGET:
        break;
      case OP_BRANCH: {
        const tgt = targetOf[i];
        // if (be && (result & imm) == 0) { be = 0; br target }
        c.localGet(H_BE);
        c.localGet(H_RESULT); c.i64Const(BigInt(imm >>> 0)); c.op(0x83);
        c.i64Const(0n); c.op(0x51);
        c.op(0x71);
        c.if_();
        open.push({ id: -1 });
        c.i32Const(0); c.localSet(H_BE);
        if (headSet.has(tgt)) {
          const depth = branchDepth(tgt);
          if (depth < 0) throw new Error('branch target ' + tgt + ' has no loop');
          c.br(depth);
        }
        open.pop();
        c.end();
        break;
      }
      case OP_UMULH_R:
        emitUmulhi(c, hR(d), hR(s));
        c.localGet(H_HI); c.localSet(hR(d));
        c.localGet(H_HI); c.localSet(H_RESULT);
        break;
      case OP_SMULH_R:
        emitSmulhi(c, hR(d), hR(s));
        c.localGet(H_HI); c.localSet(hR(d));
        c.localGet(H_HI); c.localSet(H_RESULT);
        break;
      case OP_MUL_R:
        c.localGet(hR(d)); c.localGet(hR(s)); c.op(0x7e); c.localSet(hR(d));
        break;
      case OP_SUB_R:
        c.localGet(hR(d)); c.localGet(hR(s)); c.op(0x7d); c.localSet(hR(d));
        break;
      case OP_XOR_R:
        c.localGet(hR(d)); c.localGet(hR(s)); c.op(0x85); c.localSet(hR(d));
        break;
      case OP_ADD_RS:
        c.localGet(hR(d)); c.localGet(hR(s)); c.i64Const(imm & 63); c.op(0x86);
        c.op(0x7c); c.localSet(hR(d));
        break;
      case OP_ROR_C:
        c.localGet(hR(d)); c.i64Const(imm & 63); c.op(0x8a); c.localSet(hR(d));
        break;
      case OP_ADD_C:
        c.localGet(hR(d)); c.i64Const(BigInt(imm | 0)); c.op(0x7c); c.localSet(hR(d));
        break;
      case OP_XOR_C:
        c.localGet(hR(d)); c.i64Const(BigInt(imm | 0)); c.op(0x85); c.localSet(hR(d));
        break;
      default:
        throw new Error('unknown HashX opcode ' + op + ' at ' + i);
    }
  }
  for (let i = open.length - 1; i >= 0; i--) c.end();

  // ---- finalisation ----
  c.localGet(hR(0)); c.i64Const(key[0]); c.op(0x7c); c.localSet(hR(0));
  c.localGet(hR(1)); c.i64Const(key[1]); c.op(0x7c); c.localSet(hR(1));
  c.localGet(hR(6)); c.i64Const(key[2]); c.op(0x7c); c.localSet(hR(6));
  c.localGet(hR(7)); c.i64Const(key[3]); c.op(0x7c); c.localSet(hR(7));
  emitSipRound(c, hR(0), hR(1), hR(2), hR(3));
  emitSipRound(c, hR(4), hR(5), hR(6), hR(7));
  for (let i = 0; i < 4; i++) {
    c.i32Const(0);
    c.localGet(hR(i)); c.localGet(hR(4 + i)); c.op(0x85);
    c.op(0x37, 0x03); c.uleb(8 * i); // i64.store offset=8*i
  }
  c.call(F_LZ);
}

function emitLzBody(c) {
  // no params, so the three declared locals are indices 0,1,2
  const K = 0;
  const BITS = 1;
  const BYTE = 2;
  c.i32Const(0); c.localSet(K);
  c.i64Const(0n); c.localSet(BITS);
  c.block();
  c.loop();
  c.localGet(K); c.i32Const(32); c.op(0x4f); // i32.ge_u
  c.brIf(1); // exit the block
  c.localGet(K); c.op(0x2d, 0x00, 0x00); c.localSet(BYTE); // i32.load8_u
  c.localGet(BYTE); c.op(0x45); // i32.eqz
  c.if_();
  c.localGet(BITS); c.i64Const(8); c.op(0x7c); c.localSet(BITS);
  c.else_();
  c.localGet(BITS);
  c.localGet(BYTE); c.op(0x67); c.i32Const(24); c.op(0x6b); // clz - 24
  c.op(0xad); // i64.extend_i32_u
  c.op(0x7c); c.localSet(BITS);
  c.br(2); // exit the block
  c.end();
  c.localGet(K); c.i32Const(1); c.op(0x6a); c.localSet(K);
  c.br(0);
  c.end(); // loop
  c.end(); // block
  c.localGet(BITS);
}

function emitSolveBody(c) {
  const N = 3;
  const END = 4;
  const BITS = 5;
  c.localGet(0); c.localSet(N);
  c.localGet(0); c.localGet(2); c.op(0x7c); c.localSet(END);
  c.block();
  c.loop();
  c.localGet(N); c.localGet(END); c.op(0x59); // i64.ge_s
  c.brIf(1);
  c.localGet(N); c.call(F_HASH); c.localSet(BITS);
  c.localGet(BITS); c.localGet(1); c.op(0x59);
  c.if_();
  c.localGet(N); c.op(0x0f); // return n
  c.end();
  c.localGet(N); c.i64Const(1); c.op(0x7c); c.localSet(N);
  c.br(0);
  c.end(); // loop
  c.end(); // block
  c.i64Const(-1n);
}

function emitAnubisWorkBody(c) {
  const N = 3;
  const STEP = 4;
  const BITS = 5;
  // if (iterand == 0) iterand = 1
  c.localGet(2); c.op(0x45); c.if_();
  c.i32Const(1); c.localSet(STEP);
  c.else_();
  c.localGet(2); c.localSet(STEP);
  c.end();
  c.localGet(1); c.localSet(N);
  c.loop();
  c.localGet(N); c.op(0xad); c.call(F_HASH); c.localSet(BITS);
  c.localGet(BITS); c.localGet(0); c.op(0xad); c.op(0x59); // bits >= difficulty
  c.if_();
  c.localGet(N); c.op(0x0f);
  c.end();
  c.localGet(N); c.localGet(STEP); c.op(0x6a); c.localSet(N);
  c.br(0);
  c.end();
  c.op(0x00); // unreachable: the scan loop has no normal exit
}

function emitBody(localGroups, emit) {
  const c = new Code();
  c.uleb(localGroups.length);
  for (const [count, type] of localGroups) {
    c.uleb(count);
    c.op(type);
  }
  emit(c);
  c.end();
  return c.bytes;
}

function codeEntry(body) {
  const out = [];
  uleb(body.length, out);
  return out.concat(body);
}

/**
 * Build a wasm module specialized to one HashX program.
 * @param {{registerKey: bigint[], program: object[]}} derived from deriveProgram()
 * @returns {Uint8Array}
 */
export function buildModuleForProgram(registerKey, program) {
  const hashBody = emitBody(
    [[8, I64], [4, I64], [4, I64], [3, I64], [4, I64], [1, I32]],
    (c) => emitHashBody(c, registerKey, program),
  );

  const types = vec([
    functype([I64], [I64]),        // hash / digest
    functype([], [I64]),           // lz
    functype([I64, I64, I64], [I64]), // solve
    functype([], [I32]),           // ninstr, data_ptr, result_hash_ptr, result_hash_size
    functype([I32], []),           // set_data_length
    functype([I32, I32, I32], [I32]), // anubis_work
  ]);

  // One defined function per interface. Types are listed in the order used here.
  const funcs = vec([[0], [1], [2], [3], [3], [4], [3], [3], [5]]);

  const memory = vec([[0x00, 0x01]]); // one page, no maximum

  const exports = vec([
    [...name('memory'), 0x02, 0x00],
    [...name('hash'), 0x00, F_HASH],
    [...name('digest'), 0x00, F_HASH],
    [...name('solve'), 0x00, F_SOLVE],
    [...name('ninstr'), 0x00, F_NINSTR],
    [...name('data_ptr'), 0x00, F_DATA_PTR],
    [...name('set_data_length'), 0x00, F_SET_LEN],
    [...name('result_hash_ptr'), 0x00, F_RESULT_PTR],
    [...name('result_hash_size'), 0x00, F_RESULT_SIZE],
    [...name('anubis_work'), 0x00, F_ANUBIS_WORK],
  ]);

  const bodies = [
    hashBody,
    emitBody([[1, I32], [1, I64], [1, I32]], emitLzBody),
    emitBody([[3, I64]], emitSolveBody),
    emitBody([], (c) => { c.i32Const(program.length); }),
    emitBody([], (c) => { c.i32Const(64); }),
    emitBody([], () => {}),
    emitBody([], (c) => { c.i32Const(0); }),
    emitBody([], (c) => { c.i32Const(32); }),
    emitBody([[2, I32], [1, I64]], emitAnubisWorkBody),
  ];

  const code = vec(bodies.map(codeEntry));

  const out = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  out.push(...section(1, types));
  out.push(...section(3, funcs));
  out.push(...section(5, memory));
  out.push(...section(7, exports));
  out.push(...section(10, code));
  return new Uint8Array(out);
}

/** Derive and emit in one step. This is what a challenge page calls. */
export function buildModule(challenge) {
  const { registerKey, program } = deriveProgram(challenge);
  return buildModuleForProgram(registerKey, program);
}
