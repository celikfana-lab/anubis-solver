#!/usr/bin/env node
/**
 * bench-fill-inmodule.mjs — every Argon2id fill_block formulation, timed from
 * inside wasm and checked against the C reference's vectors.
 *
 * Why inside wasm: one JS->wasm call per block costs ~0.1 us, and the whole
 * spread between these formulations is a few tenths of a microsecond, so a
 * harness that calls fill_block once per block measures the call as much as
 * the kernel. Every module here gets an appended `bench(base, m, n, scatter)`
 * export that loops n times in wasm; only the outer call is timed.
 *
 * Why the CPU pinning: this machine is hybrid (i7-1260P: four P-cores at
 * 4.7 GHz max, eight E-cores at 3.4). Node migrates between them, which moved
 * the same byte-identical module between 1.41 and 2.20 us/block. The script
 * re-executes itself under `taskset` on the fastest core it can find; set
 * A2I_NO_PIN=1 to skip that.
 *
 * Two regimes, both reported:
 *   resident   dst/prev/ref stay on three fixed blocks: the arithmetic only
 *   scattered  references are pseudo-random across a 19 MiB arena (m=19456
 *              blocks), which is what a real Argon2id pass mixes
 *
 * every module is warmed with an increasing block count first, because the
 * wasm tier-up compiler is 4x slower than the optimized tier (measured:
 * 5.86 -> 1.33 us/block for the scalar module under --liftoff-only vs
 * default), and the first readings of any cold module measure compilation.
 *
 *   node wasm/bench-fill-inmodule.mjs [--blocks 4000] [--rounds 7]
 */
import { readFileSync, writeFileSync, mkdtempSync, existsSync, readdirSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = dirname(HERE);

/* ------------------------------------------------------------------ pinning */

function fastestCore() {
  // Pick the highest-max-frequency CPU that has an SMT sibling (the P-cores).
  // Among equals prefer the highest index: cpu0/cpu1 take most of the box's
  // interrupts, and a busy SMT sibling of the chosen CPU is the one thing that
  // can halve this measurement. Falls back to null when /sys is not readable.
  let best = null;
  try {
    for (const d of readdirSync('/sys/devices/system/cpu')) {
      const m = /^cpu(\d+)$/.exec(d);
      if (!m) continue;
      const n = Number(m[1]);
      const freqPath = `/sys/devices/system/cpu/${d}/cpufreq/cpuinfo_max_freq`;
      if (!existsSync(freqPath)) continue;
      const freq = Number(readFileSync(freqPath, 'utf8').trim());
      const sib = readFileSync(`/sys/devices/system/cpu/${d}/topology/thread_siblings_list`, 'utf8').trim();
      const smt = sib.includes(',') || sib.includes('-') ? 1 : 0;
      const score = [freq, smt, n];
      if (!best || score[0] > best.score[0]
          || (score[0] === best.score[0] && score[1] > best.score[1])
          || (score[0] === best.score[0] && score[1] === best.score[1] && score[2] > best.score[2])) {
        best = { n, score, sib };
      }
    }
  } catch { return null; }
  return best ? { cpu: best.n, sibling: best.sib } : null;
}

if (!process.env.A2I_PINNED && !process.env.A2I_NO_PIN
    && existsSync('/usr/bin/taskset') && process.platform === 'linux') {
  const core = fastestCore();
  if (core !== null) {
    const r = spawnSync('/usr/bin/taskset', ['-c', String(core.cpu), process.execPath,
      fileURLToPath(import.meta.url), ...process.argv.slice(2)],
      { stdio: 'inherit',
        env: { ...process.env, A2I_PINNED: String(core.cpu), A2I_SIBLING: core.sibling } });
    process.exit(r.status ?? 1);
  }
}

const argv = process.argv.slice(2);
const flag = (name, dflt) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : dflt;
};
const BLOCKS = Number(flag('blocks', 4000));
const ROUNDS = Number(flag('rounds', 7));
const BLOCKS_M = 19456;              // m = 19456 KiB -> one 1 KiB block per KiB
const ARENA = 4096;                  // past this module's 3 KiB of scratch
const WARM = [50, 200, 800, 3000, 3000];

const WORK = mkdtempSync(join(tmpdir(), 'a2i-fill-bench-'));

/* -------------------------------------------------------- reference vectors */

const lines = readFileSync(join(HERE, 'fill_vectors.txt'), 'utf8').trim().split('\n');
const trials = [];
{
  let i = 0;
  while (i < lines.length) {
    const h = /^trial (\d+) xor (\d+)$/.exec(lines[i++].trim());
    if (!h) throw new Error(`bad vector header near line ${i}`);
    const read = (name) => {
      if (lines[i++].trim() !== name) throw new Error(`expected ${name} at line ${i}`);
      const words = [];
      while (words.length < 128) words.push(...lines[i++].trim().split(/\s+/));
      return words;
    };
    trials.push({
      withXor: Number(h[2]), prev: read('prev'), ref: read('ref'),
      next: read('next'), result: read('result'),
    });
  }
}

/* ------------------------------------------------- the in-module bench loop */

const BENCH = `
  (func (export "bench") (param $base i32) (param $m i32) (param $n i32) (param $scatter i32)
        (result i32)
    (local $i i32) (local $seed i32) (local $r1 i32) (local $r2 i32) (local $d i32)
    (local.set $seed (i32.const 2712847316))
    (local.set $i (i32.const 0))
    (block $done (loop $lp
      (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
      (if (local.get $scatter)
        (then
          (local.set $seed (i32.add (i32.mul (local.get $seed) (i32.const 1103515245))
                                     (i32.const 12345)))
          (local.set $r1 (i32.rem_u (i32.shr_u (local.get $seed) (i32.const 8)) (local.get $m)))
          (local.set $seed (i32.add (i32.mul (local.get $seed) (i32.const 1103515245))
                                     (i32.const 12345)))
          (local.set $r2 (i32.rem_u (i32.shr_u (local.get $seed) (i32.const 8)) (local.get $m)))
          (local.set $d (i32.add (i32.const 16)
                                 (i32.rem_u (local.get $i)
                                            (i32.sub (local.get $m) (i32.const 16))))))
        (else
          (local.set $r1 (i32.const 1))
          (local.set $r2 (i32.const 2))
          (local.set $d (i32.const 3))))
      (call $FILL
        (i32.add (local.get $base) (i32.shl (local.get $d) (i32.const 10)))
        (i32.add (local.get $base) (i32.shl (local.get $r1) (i32.const 10)))
        (i32.add (local.get $base) (i32.shl (local.get $r2) (i32.const 10)))
        (i32.and (local.get $i) (i32.const 1)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $lp)))
    (local.get $seed))
`;

function assemble(wat, name) {
  const watPath = join(WORK, `${name}.wat`);
  writeFileSync(watPath, wat);
  execFileSync('wat2wasm', [watPath, '-o', join(WORK, `${name}.wasm`)]);
  return join(WORK, `${name}.wasm`);
}

/* ---------------------------------------------------------------- variants */

const CASES = [];

// the formulations from the generator (the first one is the committed kernel)
for (const name of ['simd', 'legacy', 'legacy_unrolled', 'simd_loop_mem', 'simd_rot_alu',
                    'simd_sequential', 'core', 'core_legacy', 'mem_unrolled', 'mem_loop',
                    'empty']) {
  execFileSync('python3', [join(REPO, 'tools/gen_argon2_wat_simd.py'),
                           '--variant', name, '--bench', '--out', join(WORK, `${name}.gen.wat`)],
               { stdio: 'pipe' });
  CASES.push({ label: name, path: assemble(readFileSync(join(WORK, `${name}.gen.wat`), 'utf8'), name),
               full: !['core', 'core_legacy', 'mem_unrolled', 'mem_loop', 'empty'].includes(name) });
}

/* the scalar baseline is the committed module itself: its WAT gets the same
 * bench loop appended (fill_block is function 0) and is then assembled. The
 * committed file is only ever read. */
const scalarWat = readFileSync(join(HERE, 'argon2_fill.wat'), 'utf8');
const withBench = (wat) => {
  const cut = wat.lastIndexOf(')');
  return wat.slice(0, cut) + BENCH.replace('$FILL', '0') + ')';
};
CASES.push({ label: 'scalar', path: assemble(withBench(scalarWat), 'scalar'), full: true });

/* those two markers bracket the copy and the output XOR in the scalar module;
 * cutting them out gives the round core alone and the plumbing alone, on the
 * same generated code. */
{
  const lineOf = (wat, needle) => {
    const i = wat.indexOf(needle);
    if (i < 0) throw new Error(`bench: marker not found in argon2_fill.wat: ${needle}`);
    return wat.lastIndexOf('\n', i) + 1;
  };
  const cutCopy = (wat, keep) => {
    const a = lineOf(wat, ';; ---- blockR = ref ^ prev');
    const b = lineOf(wat, ';; ---- columns:');
    return wat.slice(0, a) + keep + wat.slice(b);
  };
  const cutOut = (wat, keep) => {
    const a = lineOf(wat, ';; ---- dst = block_tmp ^ blockR ----');
    const rest = wat.slice(a);
    const m = /\n[ \t]*\)[ \t]*\n/.exec(rest);
    if (!m) throw new Error('bench: scalar fill_block close not found');
    return wat.slice(0, a) + keep + rest.slice(m.index + 1);
  };
  const cutRounds = (wat) => {
    const a = lineOf(wat, ';; ---- columns:');
    const b = lineOf(wat, ';; ---- dst = block_tmp ^ blockR ----');
    return wat.slice(0, a) + wat.slice(b);
  };
  CASES.push({ label: 'scalar_core', path: assemble(withBench(cutCopy(cutOut(scalarWat, ''), '')), 'scalar_core'), full: false });
  CASES.push({ label: 'scalar_mem', path: assemble(withBench(cutRounds(scalarWat)), 'scalar_mem'), full: false });

  /* the actionable one: the scalar round core with the v128 unrolled plumbing
   * this generator uses. It is what the scalar module would cost if its copy
   * and output loops were not 128-iteration scalar loops. WAT surgery on the
   * committed text, for measurement only. */
  let fast = `${scalarWat}`;
  // one v128 scratch local for the plumbing
  fast = fast.replace('(local $a i64)', '(local $a i64) (local $tv v128)');
  const copySteps = [];
  copySteps.push(';; blockR = ref ^ prev ; block_tmp = blockR ^ (with_xor ? dst : 0)');
  copySteps.push('(if (local.get $xor) (then');
  for (let k = 0; k < 64; k++) {
    const o = 16 * k;
    copySteps.push(`  (v128.store offset=${o} (i32.const 1024) (v128.xor (v128.load offset=${o} (local.get $ref)) (v128.load offset=${o} (local.get $prev))))`);
    copySteps.push(`  (v128.store offset=${o} (i32.const 0) (v128.xor (v128.load offset=${o} (i32.const 1024)) (v128.load offset=${o} (local.get $dst))))`);
  }
  copySteps.push(') (else');
  for (let k = 0; k < 64; k++) {
    const o = 16 * k;
    copySteps.push(`  (v128.store offset=${o} (i32.const 1024) (v128.xor (v128.load offset=${o} (local.get $ref)) (v128.load offset=${o} (local.get $prev))))`);
    copySteps.push(`  (v128.store offset=${o} (i32.const 0) (v128.load offset=${o} (i32.const 1024)))`);
  }
  copySteps.push('))');
  const outSteps = [';; dst = block_tmp ^ blockR'];
  for (let k = 0; k < 64; k++) {
    const o = 16 * k;
    outSteps.push(`(v128.store offset=${o} (local.get $dst) (v128.xor (v128.load offset=${o} (i32.const 0)) (v128.load offset=${o} (i32.const 1024))))`);
  }
  fast = cutCopy(fast, copySteps.join('\n    '));
  fast = cutOut(fast, outSteps.join('\n    '));
  CASES.push({ label: 'scalar_mem_v128', path: assemble(withBench(fast), 'scalar_mem_v128'), full: true });
}

/* ------------------------------------------------------------- measurement */

const load = (path) => {
  const bytes = readFileSync(path);
  const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
  return { ex: instance.exports, bytes: bytes.length };
};

function verify(ex) {
  const dv = new DataView(ex.memory.buffer);
  const at = ARENA;
  const write = (addr, words) => words.forEach((w, k) =>
    dv.setBigUint64(addr + 8 * k, BigInt('0x' + w), true));
  for (const t of trials) {
    write(at, t.prev);
    write(at + 1024, t.ref);
    write(at + 2048, t.next);
    ex.fill_block(at + 2048, at, at + 1024, t.withXor);
    for (let k = 0; k < 128; k++) {
      if (dv.getBigUint64(at + 2048 + 8 * k, true).toString(16).padStart(16, '0') !== t.result[k]) {
        return false;
      }
    }
  }
  return true;
}

function seedArena(ex) {
  const dv = new DataView(ex.memory.buffer);
  for (let b = 0; b < BLOCKS_M; b++) {
    for (let i = 0; i < 128; i++) dv.setBigUint64(ARENA + b * 1024 + 8 * i, BigInt(b * 128 + i), true);
  }
}

const time = (ex, scatter, n) => {
  const t0 = process.hrtime.bigint();
  ex.bench(ARENA, BLOCKS_M, n, scatter);
  return Number(process.hrtime.bigint() - t0) / n;
};

const mods = CASES.map((c) => {
  const { ex, bytes } = load(c.path);
  const out = { ...c, ex, bytes, ok: c.full ? verify(ex) : null, resident: [], scattered: [] };
  if (out.ok === false) throw new Error(`WRONG: ${c.label} does not match fill_vectors.txt`);
  seedArena(ex);
  return out;
});

if (process.env.A2I_PINNED) {
  console.log(`pinned to cpu${process.env.A2I_PINNED} (smt sibling ${process.env.A2I_SIBLING}); ` +
              `${BLOCKS} blocks x ${ROUNDS} interleaved rounds, best`);
} else {
  console.log(`not pinned; ${BLOCKS} blocks x ${ROUNDS} interleaved rounds, best`);
}
console.log('');

// tier up every module before timing anything
for (const m of mods) for (const n of WARM) time(m.ex, 0, n);

for (let r = 0; r < ROUNDS; r++) {
  for (const m of mods) {
    m.resident.push(time(m.ex, 0, BLOCKS));
    m.scattered.push(time(m.ex, 1, BLOCKS));
  }
}

const best = (xs) => Math.min(...xs);
const us = (ns) => (ns / 1000).toFixed(3);

console.log('  formulation        resident    scattered      size  vectors');
console.log('  ------------------ ----------  -----------  ---------  -------');
for (const m of mods) {
  const ok = m.ok === null ? 'n/a' : m.ok ? '128/128' : 'WRONG';
  console.log(`  ${m.label.padEnd(18)} ${us(best(m.resident)).padStart(8)} us  ` +
              `${us(best(m.scattered)).padStart(9)} us  ${String(m.bytes).padStart(8)} B  ${ok}`);
}

const get = (label) => mods.find((m) => m.label === label);
const simd = get('simd');
const scalar = get('scalar');
const core = get('core');
const coreLegacy = get('core_legacy');
const scalarCore = get('scalar_core');
const scalarMemV128 = get('scalar_mem_v128');

console.log(`
  the round core on its own (no copy, no output)
  ----------------------------------------------
  v128, pair layout            ${us(best(core.resident))} us/block
  v128, legacy 12-shuffle      ${us(best(coreLegacy.resident))} us/block
  scalar i64                   ${us(best(scalarCore.resident))} us/block
  the vector round is ${(best(core.resident) / best(scalarCore.resident)).toFixed(2)}x the scalar round, and it is
  ${(100 * best(core.resident) / best(simd.resident)).toFixed(0)}% of the v128 kernel's resident time.

  Why: fBlaMka needs an unsigned 32x32->64 multiply of the low halves of both
  u64 lanes. i64x2.extmul_low_i32x4_u multiplies i32 lanes 0 and 1, which in
  the natural u64 layout are the low and high half of the *same* word, so each
  operand has to be gathered into i32 lanes 0 and 1 by an i8x16.shuffle first,
  and V8 lowers the extmul itself as two vpunpckldq plus vpmuludq. Four
  shuffle-port uops per fBlaMka, all on the single shuffle port, against a
  scalar form that needs no shuffles at all: its adds, xors and rotates spread
  over the integer ALU ports and its 512 imulq occupy only the multiplier.

  (The instruction counts behind that argument come from
   node --wasm-tiering-budget=0 --wasm-sync-tier-up --print-wasm-code
   --print-wasm-code-function-index=0 on a bench-wrapped module: 4432
   instructions for the v128 fill_block, of which 1472 are shuffle-port uops,
   versus 4791 for the scalar one with zero.)

  the whole fill_block
  --------------------
  v128 module                   ${us(best(simd.resident))} us resident / ${us(best(simd.scattered))} us scattered
  scalar module                 ${us(best(scalar.resident))} us resident / ${us(best(scalar.scattered))} us scattered
  scalar rounds + v128 plumbing ${us(best(scalarMemV128.resident))} us resident / ${us(best(scalarMemV128.scattered))} us scattered

  The v128 module costs ${(best(simd.resident) / best(scalar.resident)).toFixed(2)}x the scalar module's time resident and
  ${(best(simd.scattered) / best(scalar.scattered)).toFixed(2)}x its time scattered, because the v128 win is in the
  plumbing (unrolled v128 copies instead of 128-iteration scalar loops), and
  once the working set is memory-bound that plumbing no longer pays for the
  slower round. The module that gets both, scalar rounds with the unrolled
  plumbing, is ${(best(scalar.resident) / best(scalarMemV128.resident)).toFixed(2)}x / ${(best(scalar.scattered) / best(scalarMemV128.scattered)).toFixed(2)}x the scalar module.`);
