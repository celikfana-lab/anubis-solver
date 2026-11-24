// meatrider.wgsl — the Bitcoin-shaped `meatrider` tier on WebGPU.
//
// The algorithm is src/meatrider/meatrider.c, exactly:
//
//   ctx.mid[8]  = SHA-256 state after header bytes 0..63
//   ctx.tail[12]= header bytes 64..75 (merkle[28..32), time, nBits)
//
//   block1 = tail[12] || nonce (little-endian u32) || 0x80 || zeros
//            || 0x02 0x80                      (80 bytes = 640 bits)
//   digest1 = SHA-256(mid, block1), eight big-endian words
//   block2 = digest1(32) || 0x80 || zeros || 0x01 0x00   (256 bits)
//   h = SHA-256(IV, block2)
//
// Bitcoin's display order reverses all 32 digest bytes. The SHA-256 output bytes
// are h0 big-endian, h1 big-endian, ...; reversing the whole stream gives
// [LE(h7), LE(h6), ...], so display word i is byte-reversed h[7 - i], and that
// is what `results.hashes` holds (meatrider.c does the same with store_le32).
// The leading-zero-bit test walks those display words in order, `zero_bits`
// below.
//
// Two SHA-256 compressions per hash, four hashes per invocation (one per
// vec4<u32> lane), same shape as sha256.wgsl. Header bytes 0..63 are compressed
// once on the host into mid[], so the shader only compresses the two blocks that
// change with the nonce.
//
// ABI:
//   params (uniform, 64 B):
//     mid0..mid7   the eight midstate words, big-endian SHA-256 state
//     tail0..tail2 header bytes 64..75 as three big-endian words
//     difficulty   leading zero bits required
//     baseNonce    first nonce of this dispatch
//     count        number of nonces in this dispatch
//     pad0, pad1   padding to 64 bytes
//   results (storage, same layout as sha256.wgsl / hashx.wgsl):
//     total: atomic<u32>, hits, pad0, pad1, nonces[8], hashes[8 x 8]
//     `hashes` holds the eight DISPLAY-order digest words (h7..h0), so the hex
//     the host builds from it is the reference digest string as-is.
//   `count` nonces; each invocation handles four consecutive ones.

struct Params {
  mid0: u32,
  mid1: u32,
  mid2: u32,
  mid3: u32,
  mid4: u32,
  mid5: u32,
  mid6: u32,
  mid7: u32,
  tail0: u32,
  tail1: u32,
  tail2: u32,
  difficulty: u32,
  baseNonce: u32,
  count: u32,
  pad0: u32,
  pad1: u32,
};

struct Results {
  total: atomic<u32>,      // every hit, even past the eight slots below
  hits: u32,
  pad0: u32,
  pad1: u32,
  nonces: array<u32, 8>,
  hashes: array<u32, 64>,  // 8 hits x 8 display-order digest words
};

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read_write> results: Results;

var<private> K: array<u32, 64> = array<u32, 64>(
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
);

// 32-bit rotates over four lanes. Shift amounts are splatted because a vec4
// shifted by a scalar is not portable across WGSL front ends.
fn shr(x: vec4<u32>, n: u32) -> vec4<u32> {
  return x >> vec4<u32>(n);
}
fn shl(x: vec4<u32>, n: u32) -> vec4<u32> {
  return x << vec4<u32>(n);
}
fn rotr(x: vec4<u32>, n: u32) -> vec4<u32> {
  return shr(x, n) | shl(x, 32u - n);
}

// Byte-reverse each lane. Used for the nonce word: the header stores the nonce
// little-endian, SHA-256 reads the block big-endian, so block word 3 is the
// byte-reversed nonce.
fn bswap(v: vec4<u32>) -> vec4<u32> {
  return ((v & vec4<u32>(0x000000ffu)) << vec4<u32>(24u))
       | ((v & vec4<u32>(0x0000ff00u)) << vec4<u32>(8u))
       | ((v & vec4<u32>(0x00ff0000u)) >> vec4<u32>(8u))
       | ((v & vec4<u32>(0xff000000u)) >> vec4<u32>(24u));
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

// The eight SHA-256 state words of one lane set.
struct State {
  a: vec4<u32>,
  b: vec4<u32>,
  c: vec4<u32>,
  d: vec4<u32>,
  e: vec4<u32>,
  f: vec4<u32>,
  g: vec4<u32>,
  h: vec4<u32>,
};

// One SHA-256 compression of a whole 64-byte block: State + block words ->
// State + block. This is meatrider_compress() with every scalar in a vec4 lane.
fn compress(st: State, w0: array<vec4<u32>, 16>) -> State {
  var w = w0;
  var A = st.a;
  var B = st.b;
  var C = st.c;
  var D = st.d;
  var E = st.e;
  var F = st.f;
  var G = st.g;
  var H = st.h;

  for (var i = 0u; i < 64u; i = i + 1u) {
    if (i >= 16u) {
      let x15 = w[(i + 1u) & 15u];
      let x2 = w[(i + 14u) & 15u];
      let s0s = rotr(x15, 7u) ^ rotr(x15, 18u) ^ shr(x15, 3u);
      let s1s = rotr(x2, 17u) ^ rotr(x2, 19u) ^ shr(x2, 10u);
      w[i & 15u] = w[i & 15u] + s0s + w[(i + 9u) & 15u] + s1s;
    }
    let S1 = rotr(E, 6u) ^ rotr(E, 11u) ^ rotr(E, 25u);
    let ch = (E & F) ^ (~E & G);
    let t1 = H + S1 + ch + vec4<u32>(K[i]) + w[i & 15u];
    let S0 = rotr(A, 2u) ^ rotr(A, 13u) ^ rotr(A, 22u);
    let maj = (A & B) ^ (A & C) ^ (B & C);
    let t2 = S0 + maj;
    H = G; G = F; F = E; E = D + t1;
    D = C; C = B; B = A; A = t1 + t2;
  }

  return State(st.a + A, st.b + B, st.c + C, st.d + D,
               st.e + E, st.f + F, st.g + G, st.h + H);
}

// Leading zero bits of the 32-byte display digest, per lane. The digest's
// big-endian byte stream is h7, h6, ..., h0 (Bitcoin display order), so the
// words are passed in that order.
fn zero_bits(d0: vec4<u32>, d1: vec4<u32>, d2: vec4<u32>, d3: vec4<u32>,
             d4: vec4<u32>, d5: vec4<u32>, d6: vec4<u32>, d7: vec4<u32>) -> vec4<u32> {
  var bits = vec4<u32>(0u, 0u, 0u, 0u);
  var live = vec4<u32>(1u, 1u, 1u, 1u);
  var c: vec4<u32>;

  c = vec4<u32>(clz32(d0.x), clz32(d0.y), clz32(d0.z), clz32(d0.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(d1.x), clz32(d1.y), clz32(d1.z), clz32(d1.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(d2.x), clz32(d2.y), clz32(d2.z), clz32(d2.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(d3.x), clz32(d3.y), clz32(d3.z), clz32(d3.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(d4.x), clz32(d4.y), clz32(d4.z), clz32(d4.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(d5.x), clz32(d5.y), clz32(d5.z), clz32(d5.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(d6.x), clz32(d6.y), clz32(d6.z), clz32(d6.w));
  bits = bits + c * live;
  live = live * vec4<u32>(select(0u, 1u, c.x == 32u), select(0u, 1u, c.y == 32u),
                          select(0u, 1u, c.z == 32u), select(0u, 1u, c.w == 32u));

  c = vec4<u32>(clz32(d7.x), clz32(d7.y), clz32(d7.z), clz32(d7.w));
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

  let mid = State(vec4<u32>(params.mid0), vec4<u32>(params.mid1),
                  vec4<u32>(params.mid2), vec4<u32>(params.mid3),
                  vec4<u32>(params.mid4), vec4<u32>(params.mid5),
                  vec4<u32>(params.mid6), vec4<u32>(params.mid7));
  let iv = State(vec4<u32>(0x6a09e667u), vec4<u32>(0xbb67ae85u),
                 vec4<u32>(0x3c6ef372u), vec4<u32>(0xa54ff53au),
                 vec4<u32>(0x510e527fu), vec4<u32>(0x9b05688cu),
                 vec4<u32>(0x1f83d9abu), vec4<u32>(0x5be0cd19u));

  // block1: header bytes 64..79, then the standard padding for an 80-byte
  // message (0x80 at byte 16, length 640 = 0x280 at bytes 62..63).
  var w1: array<vec4<u32>, 16>;
  w1[0] = vec4<u32>(params.tail0);
  w1[1] = vec4<u32>(params.tail1);
  w1[2] = vec4<u32>(params.tail2);
  w1[3] = bswap(nvec);
  w1[4] = vec4<u32>(0x80000000u);
  for (var i = 5u; i < 15u; i = i + 1u) { w1[i] = vec4<u32>(0u); }
  w1[15] = vec4<u32>(0x00000280u);
  let s1 = compress(mid, w1);

  // block2: digest1's eight big-endian words, 0x80 at byte 32, 256-bit length.
  var w2: array<vec4<u32>, 16>;
  w2[0] = s1.a;
  w2[1] = s1.b;
  w2[2] = s1.c;
  w2[3] = s1.d;
  w2[4] = s1.e;
  w2[5] = s1.f;
  w2[6] = s1.g;
  w2[7] = s1.h;
  w2[8] = vec4<u32>(0x80000000u);
  for (var i = 9u; i < 15u; i = i + 1u) { w2[i] = vec4<u32>(0u); }
  w2[15] = vec4<u32>(0x00000100u);
  let s2 = compress(iv, w2);

  // Display order: reverse the eight words, and those are stored little-endian
  // (meatrider.c's store_le32), i.e. each word is byte-reversed.
  let d0 = bswap(s2.h);
  let d1 = bswap(s2.g);
  let d2 = bswap(s2.f);
  let d3 = bswap(s2.e);
  let d4 = bswap(s2.d);
  let d5 = bswap(s2.c);
  let d6 = bswap(s2.b);
  let d7 = bswap(s2.a);

  let bits = zero_bits(d0, d1, d2, d3, d4, d5, d6, d7);
  for (var lane = 0u; lane < 4u; lane = lane + 1u) {
    let nonce = nvec[lane];
    if (nonce < end && bits[lane] >= params.difficulty) {
      let slot = atomicAdd(&results.total, 1u);
      if (slot < 8u) {
        results.nonces[slot] = nonce;
        results.hashes[slot * 8u + 0u] = d0[lane];
        results.hashes[slot * 8u + 1u] = d1[lane];
        results.hashes[slot * 8u + 2u] = d2[lane];
        results.hashes[slot * 8u + 3u] = d3[lane];
        results.hashes[slot * 8u + 4u] = d4[lane];
        results.hashes[slot * 8u + 5u] = d5[lane];
        results.hashes[slot * 8u + 6u] = d6[lane];
        results.hashes[slot * 8u + 7u] = d7[lane];
      }
    }
  }
}
