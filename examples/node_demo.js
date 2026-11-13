// Node demo: solve an Anubis challenge through libanubis_solver.
//
//   cd bindings/node && npm install      # once, for koffi
//   node examples/node_demo.js           # from the repository root
//
// ANUBIS_LIB overrides where the .so is found.
'use strict';

const anubis = require('../bindings/node/anubis');

const info = anubis.info();
console.log(`libanubis_solver ${info.version}  gpu ${info.gpu ?? '(none)'}  ` +
            `threads ${info.threads}  batch ${info.batchWidth}`);

// fast / slow: SHA-256 over challenge || decimal nonce, leading zero nibbles
const nib = anubis.solveNibbles('demo-challenge', 3);
console.log(`nibbles   nonce ${nib.nonce}  ${nib.hash}  ${nib.ms.toFixed(3)} ms`);
const v1 = anubis.verifyNibbles('demo-challenge', nib.nonce, 3);
console.log(`verify    ${v1.ok ? 'ok' : 'FAILED'}  ` +
            `${v1.hash === nib.hash ? 'same digest' : 'DIFFERENT digest'}`);

// sha256 / argon2id / hashx: leading zero bits, hex challenge
const hex = '00112233445566778899aabbccddeeff';
const bits = anubis.solve('sha256', hex, 8);
console.log(`sha256    nonce ${bits.nonce}  ${bits.hash}`);
console.log(`verify    ${anubis.verify('sha256', hex, bits.nonce, 8).ok ? 'ok' : 'FAILED'}`);

// the library's own SHA-256, to cross-check a digest independently
console.log(`sha256("abc") = ${anubis.sha256Hex('abc')}`);
