// sha256.wgsl — the Anubis `sha256` proof of work on WebGPU.
//
// Message layout, nonce encoding and the difficulty test are taken from
// wasm/sha256_pow.c (and the four-wide shape from wasm/sha256_pow_batch.c):
//
//   message = challenge bytes || 4-byte nonce
//   nonce byte order = little-endian if the challenge's last byte is >= 0x80,
//                      big-endian otherwise
//   hit iff the digest has `difficulty` leading zero BITS (digest bytes are the
//   eight SHA-256 state words, big-endian)
//
// Four nonces per invocation, one per component of vec4<u32>: SHA-256 is pure
// 32-bit arithmetic, so the vector lanes are free SIMD and none of the u64
// emulation the HashX/Argon2id kernels need. The message is padded on the host
// (the challenge is fixed for a whole dispatch), so the only per-nonce work is
// inserting the four nonce bytes and running the compression.
//
// The 64 rounds are a rolling-window loop with K in a private table (see the
// ABI below). That keeps the shader small enough for SwiftShader to compile;
// fully unrolling the 64 rounds is faster on a real GPU but SwiftShader's JIT
// dies on the resulting module.
//
// ABI:
//   params (uniform, 48 B): baseNonce, count, difficulty, msgBlocks,
//     wpA, wpB, keepA, shiftA, keepB, shiftB, swap, reserved
//   results (storage, same layout as hashx.wgsl/hashx.html):
//     total: atomic<u32>, hits, pad0, pad1, nonces[8], hashes[8 x 8]
//     `hashes` holds the eight digest words in order (big-endian), not HashX's
//     u64 lo/hi pairs.
//   msg (storage, read): the padded message, big-endian u32 words, msgBlocks*16.

struct Params {
  baseNonce: u32,
  count: u32,
  difficulty: u32,
  msgBlocks: u32,
  wpA: u32,
  wpB: u32,
  keepA: u32,
  shiftA: u32,
  keepB: u32,
  shiftB: u32,
  swap: u32,
  reserved: u32,
};

struct Results {
  total: atomic<u32>,   // every hit, even past the slots below
  hits: u32,
  pad0: u32,
  pad1: u32,
  nonces: array<u32, 8>,
  hashes: array<u32, 64>,  // 8 hits x 8 big-endian digest words
};

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read_write> results: Results;
@group(0) @binding(2) var<storage, read> msg: array<u32>;

var<private> K: array<u32, 64> = array<u32, 64>(
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
);

// 32-bit rotates over the four lanes. The shift amount is splatted because a
// vec4 shifted by a scalar is not portable in every WGSL front end.
fn shr(x: vec4<u32>, n: u32) -> vec4<u32> {
  return x >> vec4<u32>(n);
}
fn shl(x: vec4<u32>, n: u32) -> vec4<u32> {
  return x << vec4<u32>(n);
}
fn rotr(x: vec4<u32>, n: u32) -> vec4<u32> {
  return shr(x, n) | shl(x, 32u - n);
}

fn bswap(v: vec4<u32>) -> vec4<u32> {
  return ((v & vec4<u32>(0x000000ffu)) << vec4<u32>(24u))
       | ((v & vec4<u32>(0x0000ff00u)) << vec4<u32>(8u))
       | ((v & vec4<u32>(0x00ff0000u)) >> vec4<u32>(8u))
       | ((v & vec4<u32>(0xff000000u)) >> vec4<u32>(24u));
}

// Insert this lane's four nonce bytes into one message word, if this is one of
// the one or two words the four bytes touch. `V` is the nonce in big-endian
// byte order (already byte-swapped for the little-endian encoding).
fn patched(word: vec4<u32>, g: u32, V: vec4<u32>) -> vec4<u32> {
  var r = word;
  if (g == params.wpA) {
    r = (r & vec4<u32>(params.keepA)) | shr(V, params.shiftA);
  }
  if (g == params.wpB) {
    r = shl(V, params.shiftB) | (r & vec4<u32>(params.keepB));
  }
  return r;
}

// countLeadingZeros, scalar; x == 0 gives 32.
fn clz32(x: u32) -> u32 {
  if (x == 0u) { return 32u; }
  var v = x;
  var n = 0u;
  if ((v & 0xffff0000u) == 0u) { n = 16u; v = v << 16u; }
  if ((v & 0xff000000u) == 0u) { n = n + 8u; v = v << 8u; }
  if ((v & 0xf0000000u) == 0u) { n = n + 4u; v = v << 4u; }
  if ((v & 0xc0000000u) == 0u) { n = n + 2u; v = v << 2u; }
  if ((v & 0x80000000u) == 0u) { n = n + 1u; }
  return n;
}

// Leading zero bits of the 32-byte digest, per lane. Word order matters: the
// digest bytes are H0 big-endian, H1 big-endian, ... so the MSB-first bit
// stream is exactly clz(H0), then clz(H1), and so on.
fn zero_bits(h0: vec4<u32>, h1: vec4<u32>, h2: vec4<u32>, h3: vec4<u32>,
             h4: vec4<u32>, h5: vec4<u32>, h6: vec4<u32>, h7: vec4<u32>) -> vec4<u32> {
  var bits = vec4<u32>(0u, 0u, 0u, 0u);
  var live = vec4<u32>(1u, 1u, 1u, 1u);
  var c: vec4<u32>;

  c = vec4<u32>(clz32(h0.x), clz32(h0.y), clz32(h0.z), clz32(h0.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(h1.x), clz32(h1.y), clz32(h1.z), clz32(h1.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(h2.x), clz32(h2.y), clz32(h2.z), clz32(h2.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(h3.x), clz32(h3.y), clz32(h3.z), clz32(h3.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(h4.x), clz32(h4.y), clz32(h4.z), clz32(h4.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(h5.x), clz32(h5.y), clz32(h5.z), clz32(h5.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(h6.x), clz32(h6.y), clz32(h6.z), clz32(h6.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(h7.x), clz32(h7.y), clz32(h7.z), clz32(h7.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  return bits;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  // Four consecutive nonces per invocation, one per vector lane.
  let first = params.baseNonce + gid.x * 4u;
  let end = params.baseNonce + params.count;
  if (first >= end) { return; }
  let nvec = vec4<u32>(first, first + 1u, first + 2u, first + 3u);

  // V is the nonce packed so that its big-endian bytes are the message bytes
  // at params.wpA..params.wpA+3, as wasm/sha256_pow.c writes them.
  var V = nvec;
  if (params.swap != 0u) { V = bswap(V); }

  var h0 = vec4<u32>(0x6a09e667u);
  var h1 = vec4<u32>(0xbb67ae85u);
  var h2 = vec4<u32>(0x3c6ef372u);
  var h3 = vec4<u32>(0xa54ff53au);
  var h4 = vec4<u32>(0x510e527fu);
  var h5 = vec4<u32>(0x9b05688cu);
  var h6 = vec4<u32>(0x1f83d9abu);
  var h7 = vec4<u32>(0x5be0cd19u);

  for (var b = 0u; b < params.msgBlocks; b++) {
    let base = b * 16u;
    var w: array<vec4<u32>, 16>;
    for (var i = 0u; i < 16u; i++) {
      w[i] = patched(vec4<u32>(msg[base + i]), base + i, V);
    }

    var A = h0; var B = h1; var C = h2; var D = h3;
    var E = h4; var F = h5; var G = h6; var H = h7;
    for (var i = 0u; i < 64u; i++) {
      if (i >= 16u) {
        let w15 = w[(i + 1u) & 15u];
        let w2 = w[(i + 14u) & 15u];
        let s0s = rotr(w15, 7u) ^ rotr(w15, 18u) ^ shr(w15, 3u);
        let s1s = rotr(w2, 17u) ^ rotr(w2, 19u) ^ shr(w2, 10u);
        w[i & 15u] = w[i & 15u] + s0s + w[(i + 9u) & 15u] + s1s;
      }
      let s1 = rotr(E, 6u) ^ rotr(E, 11u) ^ rotr(E, 25u);
      let ch = (E & F) ^ (~E & G);
      let t1 = H + s1 + ch + vec4<u32>(K[i]) + w[i & 15u];
      let s0 = rotr(A, 2u) ^ rotr(A, 13u) ^ rotr(A, 22u);
      let maj = (A & B) ^ (A & C) ^ (B & C);
      let t2 = s0 + maj;
      H = G; G = F; F = E; E = D + t1;
      D = C; C = B; B = A; A = t1 + t2;
    }

    h0 = h0 + A; h1 = h1 + B; h2 = h2 + C; h3 = h3 + D;
    h4 = h4 + E; h5 = h5 + F; h6 = h6 + G; h7 = h7 + H;
  }

  // Difficulty test: leading zero bits of the big-endian digest bytes.
  let bits = zero_bits(h0, h1, h2, h3, h4, h5, h6, h7);
  for (var lane = 0u; lane < 4u; lane++) {
    let nonce = nvec[lane];
    if (nonce < end && bits[lane] >= params.difficulty) {
      let slot = atomicAdd(&results.total, 1u);
      if (slot < 8u) {
        results.nonces[slot] = nonce;
        results.hashes[slot * 8u + 0u] = h0[lane];
        results.hashes[slot * 8u + 1u] = h1[lane];
        results.hashes[slot * 8u + 2u] = h2[lane];
        results.hashes[slot * 8u + 3u] = h3[lane];
        results.hashes[slot * 8u + 4u] = h4[lane];
        results.hashes[slot * 8u + 5u] = h5[lane];
        results.hashes[slot * 8u + 6u] = h6[lane];
        results.hashes[slot * 8u + 7u] = h7[lane];
      }
    }
  }
}
