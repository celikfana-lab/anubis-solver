// wasm/pow-worker.js — solve an Anubis challenge with this repository's kernels.
//
// Runs in a Worker so a multi-second `anubis_work` cannot freeze the page. The
// module ABI is the one Anubis's own modules use (see wasm/sha256_pow.c):
//
//   data_ptr(), set_data_length(n)
//   result_hash_ptr(), result_hash_size()
//   anubis_work(difficulty, nonce, iterand) -> nonce
//
// so one driver serves sha256 (scalar and 4-wide) and hashx.
//
// Messages in:  {kind:"calibrate"|"solve", wasmUrl, algorithm, challengeHex, difficulty}
// Messages out: {kind:"calibrated", rate} | {kind:"solved", ok, nonce, response, elapsedMs}
//               or {kind:"solved", ok:false, error}
async function solveWith(wasmUrl, challengeHex, difficulty) {
  const bytes = await (await fetch(wasmUrl)).arrayBuffer();
  const { instance } = await WebAssembly.instantiate(bytes, {
    anubis: { anubis_update_nonce: () => {} },
  });
  const ex = instance.exports;
  const challenge = new Uint8Array(
    (challengeHex.match(/.{2}/g) ?? []).map((b) => parseInt(b, 16)),
  );
  new Uint8Array(ex.memory.buffer).set(challenge, ex.data_ptr());
  ex.set_data_length(challenge.length);
  const started = performance.now();
  const nonce = ex.anubis_work(difficulty, 0, 1);
  const elapsedMs = performance.now() - started;
  const digest = new Uint8Array(ex.memory.buffer, ex.result_hash_ptr(), ex.result_hash_size());
  const response = Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
  return { nonce, response, elapsedMs };
}

self.onmessage = async (event) => {
  const { kind, wasmUrl, algorithm, challengeHex, difficulty } = event.data ?? {};
  try {
    const result = await solveWith(wasmUrl, challengeHex, difficulty);
    if (kind === "calibrate") {
      self.postMessage({ kind: "calibrated",
                         rate: (2 ** difficulty) / Math.max(result.elapsedMs / 1000, 1e-6) });
    } else {
      self.postMessage({ kind: "solved", ok: true, algorithm, ...result });
    }
  } catch (err) {
    self.postMessage({ kind: "solved", ok: false, error: String(err) });
  }
};
