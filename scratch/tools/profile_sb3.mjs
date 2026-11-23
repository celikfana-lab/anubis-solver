// Profile one generated .sb3 by counting every primitive the interpreter runs.
//
// Wraps vm.runtime._primitives so each block execution is counted, then prints
// the totals and the hottest opcodes.  This is where the "microseconds per
// statement" claim comes from, and it says exactly which primitive to attack.
//
//   node profile_sb3.mjs <project.sb3> [msg-json]

import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const VM = require("scratch-vm");
const JSZip = require("jszip");

const [sb3Path, msgJson] = process.argv.slice(2);
const bytes = JSON.parse(msgJson || "[97,98,99]");

const buf = fs.readFileSync(sb3Path);
const zip = await JSZip.loadAsync(buf);
const pj = JSON.parse(await zip.file("project.json").async("string"));
const stageJson = pj.targets.find((t) => t.isStage);
const fname = (v) => (Array.isArray(v) ? v[0] : v);
const idOf = (t, n) => Object.keys(t).find((k) => fname(t[k][0]) === n);

const MSG = idOf(stageJson.lists, "MSG");
const DONE = idOf(stageJson.variables, "DONE");
const OUT = idOf(stageJson.variables, "OUT_HEX");

const vm = new VM();
await vm.loadProject(buf);
vm.setTurboMode(true);

const st = vm.runtime.getTargetForStage();
const slot = (id) => (st.variables instanceof Map ? st.variables.get(id) : st.variables[id]);
slot(DONE).value = 0;
if (OUT) slot(OUT).value = "";
if (MSG) slot(MSG).value = bytes.map(Number);

const counts = {};
const prims = vm.runtime._primitives;
for (const name of Object.keys(prims)) {
  const fn = prims[name];
  prims[name] = function (...a) {
    counts[name] = (counts[name] || 0) + 1;
    return fn.apply(this, a);
  };
}

vm.runtime.currentStepTime = 1;
const realStep = vm.runtime._step.bind(vm.runtime);
let busy = 0;
vm.runtime._step = () => {
  const t = process.hrtime.bigint();
  realStep();
  busy += Number(process.hrtime.bigint() - t) / 1e6;
};

vm.start();
vm.greenFlag();
const deadline = Date.now() + 120000;
while (Number(slot(DONE).value) !== 1) {
  if (Date.now() > deadline) {
    console.error("timeout");
    process.exit(3);
  }
  await new Promise((r) => setTimeout(r, 0));
}

const total = Object.values(counts).reduce((a, b) => a + b, 0);
const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 14);
console.log(
  JSON.stringify(
    {
      hex: OUT ? String(slot(OUT).value) : "",
      ms: Number(busy.toFixed(1)),
      execs: total,
      us_per_exec: Number(((busy * 1000) / total).toFixed(3)),
      top,
    },
    null,
    1
  )
);
process.exit(0);
