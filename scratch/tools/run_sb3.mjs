// Run one generated .sb3 headlessly and report the digest it computes.
//
// This is the honest arbiter: the official scratch-vm -- the same interpreter
// TurboWarp and scratch.mit.edu run -- executing the generated blocks with no
// shortcuts, no compiled-JS path, and no help from the generator.
//
//   node run_sb3.mjs <project.sb3> <msg-json>
//
// prints { hex, ms, wall, targets } as JSON on stdout.  `ms` is the time spent
// inside the interpreter (sum of _step durations), so the VM's 1 kHz scheduler
// tick does not inflate it; `wall` is the same measurement including sleeping.

import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const VM = require("scratch-vm");
const JSZip = require("jszip");

const argv = process.argv.slice(2);
const flags = {};
for (let i = 0; i < argv.length; i += 1) {
  if (argv[i].startsWith("--")) {
    flags[argv[i].slice(2)] = argv[i + 1];
    i += 1;
  }
}
const positional = argv.filter((a, i) => !a.startsWith("--") && !(i > 0 && argv[i - 1].startsWith("--")));
const [sb3Path, msgJson] = positional;
const bytes = JSON.parse(msgJson || "[]");
const repeats = Number(flags.repeats || 1);
// Answers to `ask and wait`, in order.  The default -- pressing Enter -- runs
// the "just hash MSG" path, which is what the vector tests use.
const answers = JSON.parse(flags.answers || '[""]');

const buf = fs.readFileSync(sb3Path);
const zip = await JSZip.loadAsync(buf);
const pj = JSON.parse(await zip.file("project.json").async("string"));
const stageJson = pj.targets.find((t) => t.isStage);
const fieldName = (v) => (Array.isArray(v) ? v[0] : v);
const idOf = (table, name) =>
  Object.keys(table).find((k) => fieldName(table[k][0]) === name);

const MSG = idOf(stageJson.lists, "MSG");
const DONE = idOf(stageJson.variables, "DONE");
const OUT = idOf(stageJson.variables, "OUT_HEX");
if (!DONE) {
  console.error("project is missing DONE (the completion flag)");
  process.exit(2);
}

const vm = new VM();
await vm.loadProject(buf);
vm.setTurboMode(true);

const st = vm.runtime.getTargetForStage();
// scratch-vm keeps variables AND lists in one map; a list is a variable whose
// .type is "list" and whose .value is an Array.
const slot = (id) =>
  st.variables instanceof Map ? st.variables.get(id) : st.variables[id];
slot(DONE).value = 0;
if (OUT) slot(OUT).value = "";
if (MSG) slot(MSG).value = bytes.map(Number);

// Count only the time the interpreter is actually executing.  The default
// scheduler tick is 1/30 s, which would otherwise dominate a short hash.
vm.runtime.currentStepTime = 1;
const realStep = vm.runtime._step.bind(vm.runtime);
let busyMs = 0;
vm.runtime._step = () => {
  const t0 = process.hrtime.bigint();
  realStep();
  busyMs += Number(process.hrtime.bigint() - t0) / 1e6;
};

async function hashOnce() {
  slot(DONE).value = 0;
  if (OUT) slot(OUT).value = "";
  vm.greenFlag();
  const deadline = Date.now() + 120000;
  while (Number(slot(DONE).value) !== 1) {
    if (Date.now() > deadline) {
      console.error(JSON.stringify({ error: "timeout", busyMs }));
      process.exit(3);
    }
    await new Promise((r) => setTimeout(r, 0));
  }
  return OUT ? String(slot(OUT).value) : "";
}

const wall0 = process.hrtime.bigint();
// `ask and wait` queues a question and waits for an ANSWER event; a GUI
// provides it with a text box, headless it has to come from here.  Driven from
// the queue rather than the QUESTION event: the runtime also emits
// QUESTION(null) when it clears questions (on green flag), which would eat an
// answer.
// Answering drives through emit('QUESTION'): the real ask emits a non-null
// payload (the text, or '' when the asking sprite is visible), while clearing
// questions on green flag emits QUESTION(null) -- which must NOT eat an answer.
let nextAnswer = 0;
const realEmit = vm.runtime.emit.bind(vm.runtime);
vm.runtime.emit = (event, ...rest) => {
  if (event === "QUESTION" && rest[0] !== null && rest[0] !== undefined) {
    const text = nextAnswer < answers.length ? String(answers[nextAnswer]) : "";
    nextAnswer += 1;
    setTimeout(() => realEmit("ANSWER", text), 0);
  }
  return realEmit(event, ...rest);
};

vm.start();
const digests = [];
for (let i = 0; i < repeats; i += 1) digests.push(await hashOnce());
const wallMs = Number(process.hrtime.bigint() - wall0) / 1e6;
const hex = digests[digests.length - 1];
if (OUT && digests.some((d) => d !== hex)) {
  console.error(JSON.stringify({ error: "not re-entrant", digests }));
  process.exit(4);
}

console.log(
  JSON.stringify({
    hex,
    ms: Number(busyMs.toFixed(3)),
    digests,
    wall: Number(wallMs.toFixed(1)),
    targets: pj.targets.length,
  })
);
process.exit(0);
