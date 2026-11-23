// Solve one Anubis sha256 challenge with the generated Scratch project.
//
// The whole proof of work runs in blocks: the project builds
// challenge_raw || nonce_be, hashes it, checks the leading DIFF bits, and bumps
// the nonce until it fits.  This script only feeds it the challenge and reports
// what came back.
//
//   node solve_challenge.mjs <project.sb3> --chal <hex> --diff 12 [--timeout 900000]

import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const VM = require("scratch-vm");
const JSZip = require("jszip");

const argv = process.argv.slice(2);
const opts = {};
const positional = [];
for (let i = 0; i < argv.length; i += 1) {
  if (argv[i].startsWith("--")) {
    opts[argv[i].slice(2)] = argv[i + 1];
    i += 1;
  } else positional.push(argv[i]);
}
const sb3Path = positional[0];
const difficulty = Number(opts.diff || 12);
const timeoutMs = Number(opts.timeout || 900000);
const chalHex = String(opts.chal || "").replace(/^0x/, "");
if (chalHex.length % 2) throw new Error("odd-length challenge hex");
const chal = [];
for (let i = 0; i < chalHex.length; i += 2) chal.push(parseInt(chalHex.slice(i, i + 2), 16));

const buf = fs.readFileSync(sb3Path);
const zip = await JSZip.loadAsync(buf);
const pj = JSON.parse(await zip.file("project.json").async("string"));
const stageJson = pj.targets.find((t) => t.isStage);
const fname = (v) => (Array.isArray(v) ? v[0] : v);
const pick = (table, name) => Object.keys(table).find((k) => fname(table[k][0]) === name);
const need = (name) => {
  const id = pick(stageJson.variables, name);
  if (!id) throw new Error("project has no variable " + name);
  return id;
};

const vm = new VM();
await vm.loadProject(buf);
vm.setTurboMode(true);

const st = vm.runtime.getTargetForStage();
const slot = (id) => (st.variables instanceof Map ? st.variables.get(id) : st.variables[id]);

const CHAL = pick(stageJson.lists, "CHAL");
slot(CHAL).value = chal;
slot(need("DIFF")).value = difficulty;
slot(need("NONCE")).value = 0;
slot(need("FOUND")).value = 0;
slot(need("DONE")).value = 0;
slot(need("OUT_HEX")).value = "";

const nonceSlot = slot(need("NONCE"));
const doneSlot = slot(need("DONE"));
const foundSlot = slot(need("FOUND"));

vm.runtime.currentStepTime = 1;
const realStep = vm.runtime._step.bind(vm.runtime);
let busy = 0;
vm.runtime._step = () => {
  const t = process.hrtime.bigint();
  realStep();
  busy += Number(process.hrtime.bigint() - t) / 1e6;
};

const t0 = Date.now();
vm.start();
vm.greenFlag();

let last = 0;
let lastReport = Date.now();
while (Number(doneSlot.value) !== 1) {
  if (Date.now() - t0 > timeoutMs) {
    console.error(JSON.stringify({ error: "timeout", hashes: Number(nonceSlot.value) }));
    process.exit(3);
  }
  await new Promise((r) => setTimeout(r, 5));
  const n = Number(nonceSlot.value);
  if (n !== last) last = n;
  if (Date.now() - lastReport > 2000) {
    const rate = n / ((Date.now() - t0) / 1000);
    console.error(`  nonce ${n}  ${rate.toFixed(1)} H/s`);
    lastReport = Date.now();
  }
}

const out = {
  found: Number(foundSlot.value) === 1,
  nonce: Number(nonceSlot.value),
  hashes: Number(nonceSlot.value) + 1,
  hash: String(slot(need("OUT_HEX")).value),
  ms: Number(busy.toFixed(0)),
  wall: Number(((Date.now() - t0) / 1000).toFixed(1)),
  hps: Number(((Number(nonceSlot.value) + 1) / (busy / 1000)).toFixed(2)),
};
console.log(JSON.stringify(out));
process.exit(out.found ? 0 : 1);
