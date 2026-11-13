// argon2id.wgsl — Argon2id's fill phase on WebGPU.
//
// One workgroup of 8 invocations fills one hash: between them they take the two
// initial blocks (B0, B1) that the host derived from H0, run all 38,912 block
// fills of Argon2id v1.3 with Anubis's parameters, and leave the last block of
// the single lane where the host can pick it up and finish the tag with
// blake2b_long.
//
//   Argon2id v0x13, m_cost = 19456 KiB (19456 blocks of 1 KiB), t_cost = 2,
//   p_cost = 1, 32-byte tag.  One lane, 4 slices of 4864 blocks, 2 passes.
//
// Why 8 and not 1: the block function is 8 independent BLAKE2 rounds over 16
// words, then a barrier, then 8 independent rounds over strided words. That is
// exactly 8-way parallelism per 1 KiB block, so a workgroup of 8 splits one
// block fill across 8 execution lanes instead of leaving one lane to do all
// 38,912 fills serially. The working block lives in workgroup memory (2 KiB,
// the R and T arrays); the address/input/zero blocks of Argon2id's
// data-independent addressing live in three extra blocks appended to the
// per-hash region, so every block operation is the same uniform
// "copy from storage, round, store to storage" call.
//
// The u64 helpers below (add64, sub64, xor64, rotl64, rotr64, shl64, mulhi32,
// umulh64, mul64) are copied verbatim from webgpu/hashx.wgsl, which are
// transcribed from tools/gen_hashx_wat.py and verified against the C engine and
// against Anubis's own module on two backends. They are not rewritten here on
// purpose: the Argon2 fill needs the same emulated 64-bit arithmetic, and the
// only thing that would be gained by a "better" version is a silent bug.
//
// ABI (one workgroup of 8 invocations per hash; the host bounds `count` by
// maxStorageBufferBindingSize / 19459 KiB):
//   params      uniform   { base, count, difficulty, reserved }  (16 B)
//   memory      storage   array<u32>: count regions of 19459*256 u32
//                         (19456 blocks + address + input + zero + spare)
//   init        storage   array<u32>: count regions of 2*256 u32  (B0 then B1)
//   final_block storage   array<u32>: count regions of 256 u32    (last block)
// Region g of `memory` starts at g * 19459 * 256.  `base`/`difficulty` are not
// used by the fill — the host owns the nonce -> salt mapping and the tag test —
// but they are kept so the ABI does not change when this becomes a search loop.

const BLOCKS: u32 = 19456u;        // memory_blocks = lane_length (p = 1)
const SEGMENT: u32 = 4864u;        // BLOCKS / ARGON2_SYNC_POINTS (4)
const WORDS: u32 = 256u;           // u32 words per 1 KiB block, i.e. 128 u64
const ADDRESSES: u32 = 128u;       // ARGON2_ADDRESSES_IN_BLOCK
const ADDR_BLOCK: u32 = 19456u;    // scratch block indices appended per hash
const INPUT_BLOCK: u32 = 19457u;   // (the address block's result is copied into
const ZERO_BLOCK: u32 = 19458u;    //  workgroup memory, see next_addresses())
const REGION_BLOCKS: u32 = 19459u; // 19456 data blocks + 3 scratch blocks
const U64_PER_THREAD: u32 = 16u;   // u64 words per thread per 1 KiB block (128/8)
const BLOCK_U32_PER_THREAD: u32 = 32u;   // 256/8, same slice as u32
const INIT_U32_PER_THREAD: u32 = 64u;    // the two initial blocks are 512 u32

struct Params {
  base: u32,
  count: u32,
  difficulty: u32,
  reserved: u32,
};

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read_write> memory: array<u32>;
@group(0) @binding(2) var<storage, read> init: array<u32>;
@group(0) @binding(3) var<storage, read_write> final_block: array<u32>;

// The block being worked on, shared by the 8 invocations of the workgroup. R is
// the working block and T the value its result is XORed with, as in ref.c's
// fill_block. Both are 1 KiB.
var<workgroup> R: array<vec2<u32>, 128>;
var<workgroup> T: array<vec2<u32>, 128>;
// The current address block. It is filled through storage like any other block,
// then copied here by the threads that wrote it, so the per-block reads of
// memory[i % 128] are workgroup reads (ordered by workgroupBarrier) instead of
// cross-invocation storage reads.
var<workgroup> address_block: array<vec2<u32>, 128>;
var<workgroup> addrCounter: u32;   // next_addresses() calls in this segment

// ---- 64-bit arithmetic over vec2<u32>(lo, hi) — copied from hashx.wgsl ----

fn add64(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
  let lo = a.x + b.x;
  return vec2<u32>(lo, a.y + b.y + select(0u, 1u, lo < a.x));
}

fn sub64(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
  let lo = a.x - b.x;
  return vec2<u32>(lo, a.y - b.y - select(0u, 1u, a.x < b.x));
}

fn xor64(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
  return vec2<u32>(a.x ^ b.x, a.y ^ b.y);
}

fn rotl64(x: vec2<u32>, n: u32) -> vec2<u32> {
  if (n == 0u) { return x; }
  if (n == 32u) { return vec2<u32>(x.y, x.x); }
  if (n < 32u) {
    return vec2<u32>((x.x << n) | (x.y >> (32u - n)),
                      (x.y << n) | (x.x >> (32u - n)));
  }
  let s = 64u - n;
  return vec2<u32>((x.x >> s) | (x.y << (32u - s)),
                    (x.y >> s) | (x.x << (32u - s)));
}

fn rotr64(x: vec2<u32>, n: u32) -> vec2<u32> {
  return rotl64(x, (64u - n) & 63u);
}

fn shl64(x: vec2<u32>, n: u32) -> vec2<u32> {
  if (n == 0u) { return x; }
  if (n >= 64u) { return vec2<u32>(0u, 0u); }
  if (n >= 32u) { return vec2<u32>(0u, x.x << (n - 32u)); }
  return vec2<u32>(x.x << n, (x.y << n) | (x.x >> (32u - n)));
}

// high 32 bits of an unsigned 32x32->64 multiply, from 16-bit limbs
fn mulhi32(a: u32, b: u32) -> u32 {
  let al = a & 0xffffu; let ah = a >> 16u;
  let bl = b & 0xffffu; let bh = b >> 16u;
  let t0 = al * bl;
  let t1 = al * bh;
  let t2 = ah * bl;
  let t3 = ah * bh;
  let mid = (t0 >> 16u) + (t1 & 0xffffu) + (t2 & 0xffffu);
  return t3 + (t1 >> 16u) + (t2 >> 16u) + (mid >> 16u);
}

// high 64 bits of the 128-bit product, transcribed from the verified WAT:
//   HI = T3 + (T1>>32) + (T2>>32) + (LO>>32),  T1=a.lo*b.hi, T2=a.hi*b.lo
fn umulh64(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
  let hi0 = mulhi32(a.x, b.x);
  let lo1 = a.x * b.y; let hi1 = mulhi32(a.x, b.y);
  let lo2 = a.y * b.x; let hi2 = mulhi32(a.y, b.x);
  let lo3 = a.y * b.y; let hi3 = mulhi32(a.y, b.y);
  let s0 = hi0 + lo1; let c0 = select(0u, 1u, s0 < hi0);
  let s1 = s0 + lo2;  let c1 = select(0u, 1u, s1 < s0);
  let carry = c0 + c1;
  let w0 = lo3 + hi1;      let d0 = select(0u, 1u, w0 < lo3);
  let w1 = w0 + hi2;       let d1 = select(0u, 1u, w1 < w0);
  let w2 = w1 + carry;     let d2 = select(0u, 1u, w2 < w1);
  return vec2<u32>(w2, hi3 + d0 + d1 + d2);
}

// low 64 bits of the product
fn mul64(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
  return vec2<u32>(a.x * b.x,
                    a.x * b.y + a.y * b.x + mulhi32(a.x, b.x));
}

// ---- the Argon2 block function ----

// fBlaMka: x + y + 2*((x & 0xffffffff) * (y & 0xffffffff)), all mod 2^64, from
// argon2_fill_fast.c. The low 32 bits of the product are an exact 32x32->64
// multiply, so only its high half needs the limb emulation.
fn blamka(x: vec2<u32>, y: vec2<u32>) -> vec2<u32> {
  let lo = x.x * y.x;
  let hi = mulhi32(x.x, y.x);
  let d = vec2<u32>(lo << 1u, (hi << 1u) | (lo >> 31u));   // 2 * (hi:lo)
  return add64(add64(x, y), d);
}

// One BLAKE2 round's G, in place on four words of a function-local array. The
// four pointers are always &v[constant], which is what lets the compiler keep
// the 16-word window in registers instead of re-reading workgroup memory.
fn gv(v: ptr<function, array<vec2<u32>, 16>>, a: u32, b: u32, c: u32, d: u32) {
  (*v)[a] = blamka((*v)[a], (*v)[b]);
  (*v)[d] = rotr64(xor64((*v)[d], (*v)[a]), 32u);
  (*v)[c] = blamka((*v)[c], (*v)[d]);
  (*v)[b] = rotr64(xor64((*v)[b], (*v)[c]), 24u);
  (*v)[a] = blamka((*v)[a], (*v)[b]);
  (*v)[d] = rotr64(xor64((*v)[d], (*v)[a]), 16u);
  (*v)[c] = blamka((*v)[c], (*v)[d]);
  (*v)[b] = rotr64(xor64((*v)[b], (*v)[c]), 63u);
}

// BLAKE2_ROUND_NOMSG over the 16 contiguous words starting at `off` — the
// "rowwise" step of ref.c. Thread t of the workgroup runs the row 16*t.
fn round_row(off: u32) {
  var v: array<vec2<u32>, 16>;
  for (var j = 0u; j < 16u; j++) { v[j] = R[off + j]; }
  gv(&v, 0u, 4u, 8u, 12u);
  gv(&v, 1u, 5u, 9u, 13u);
  gv(&v, 2u, 6u, 10u, 14u);
  gv(&v, 3u, 7u, 11u, 15u);
  gv(&v, 0u, 5u, 10u, 15u);
  gv(&v, 1u, 6u, 11u, 12u);
  gv(&v, 2u, 7u, 8u, 13u);
  gv(&v, 3u, 4u, 9u, 14u);
  for (var j = 0u; j < 16u; j++) { R[off + j] = v[j]; }
}

// BLAKE2_ROUND_NOMSG over (2g, 2g+1), (2g+16, 2g+17), ... (2g+112, 2g+113) —
// the "columnwise" step of ref.c. Thread t runs the column 2*t.
fn round_col(off: u32) {
  var v: array<vec2<u32>, 16>;
  v[0] = R[off + 0u];   v[1] = R[off + 1u];
  v[2] = R[off + 16u];  v[3] = R[off + 17u];
  v[4] = R[off + 32u];  v[5] = R[off + 33u];
  v[6] = R[off + 48u];  v[7] = R[off + 49u];
  v[8] = R[off + 64u];  v[9] = R[off + 65u];
  v[10] = R[off + 80u]; v[11] = R[off + 81u];
  v[12] = R[off + 96u]; v[13] = R[off + 97u];
  v[14] = R[off + 112u]; v[15] = R[off + 113u];
  gv(&v, 0u, 4u, 8u, 12u);
  gv(&v, 1u, 5u, 9u, 13u);
  gv(&v, 2u, 6u, 10u, 14u);
  gv(&v, 3u, 7u, 11u, 15u);
  gv(&v, 0u, 5u, 10u, 15u);
  gv(&v, 1u, 6u, 11u, 12u);
  gv(&v, 2u, 7u, 8u, 13u);
  gv(&v, 3u, 4u, 9u, 14u);
  R[off + 0u] = v[0];   R[off + 1u] = v[1];
  R[off + 16u] = v[2];  R[off + 17u] = v[3];
  R[off + 32u] = v[4];  R[off + 33u] = v[5];
  R[off + 48u] = v[6];  R[off + 49u] = v[7];
  R[off + 64u] = v[8];  R[off + 65u] = v[9];
  R[off + 80u] = v[10]; R[off + 81u] = v[11];
  R[off + 96u] = v[12]; R[off + 97u] = v[13];
  R[off + 112u] = v[14]; R[off + 113u] = v[15];
}

// fill_block() from ref.c/argon2_fill_fast.c, writing into the memory region:
// R = ref ^ prev, T = R (^ next on later passes), 8 row + 8 column rounds,
// next = T ^ R. `tid` is this invocation's lane of the block: it loads/stores
// the u64 words [16*tid, 16*tid+16).
fn fill_block(region: u32, dst: u32, prev: u32, refIdx: u32, with_xor: bool, tid: u32) {
  let co = region + dst * WORDS;
  let po = region + prev * WORDS;
  let ro = region + refIdx * WORDS;
  for (var j = 0u; j < U64_PER_THREAD; j++) {
    let k = tid * U64_PER_THREAD + j;
    let lo = memory[ro + 2u * k] ^ memory[po + 2u * k];
    let hi = memory[ro + 2u * k + 1u] ^ memory[po + 2u * k + 1u];
    R[k] = vec2<u32>(lo, hi);
    if (with_xor) {
      T[k] = vec2<u32>(lo ^ memory[co + 2u * k], hi ^ memory[co + 2u * k + 1u]);
    } else {
      T[k] = vec2<u32>(lo, hi);
    }
  }
  workgroupBarrier();
  round_row(16u * tid);
  workgroupBarrier();
  round_col(2u * tid);
  workgroupBarrier();
  for (var j = 0u; j < U64_PER_THREAD; j++) {
    let k = tid * U64_PER_THREAD + j;
    memory[co + 2u * k] = T[k].x ^ R[k].x;
    memory[co + 2u * k + 1u] = T[k].y ^ R[k].y;
  }
  workgroupBarrier();
}

// next_addresses() from ref.c, with input/zero/address blocks in storage so the
// same fill_block runs for them. `inputBlock` has already been reset for this
// segment; the counter in v[6] is bumped before each call, as in ref.c.
fn next_addresses(region: u32, tid: u32) {
  // v[6] is bumped before the fills, as in ref.c. Only thread 0 owns u64 word 6
  // of the input block, so this write is never read by another invocation.
  if (tid == 0u) {
    addrCounter = addrCounter + 1u;
    let off = region + INPUT_BLOCK * WORDS + 12u;      // u64 word 6 = u32 12,13
    memory[off] = addrCounter;
    memory[off + 1u] = 0u;
  }
  fill_block(region, ADDR_BLOCK, ZERO_BLOCK, INPUT_BLOCK, false, tid);
  fill_block(region, ADDR_BLOCK, ZERO_BLOCK, ADDR_BLOCK, false, tid);
  for (var j = 0u; j < U64_PER_THREAD; j++) {
    let k = tid * U64_PER_THREAD + j;
    let w = region + ADDR_BLOCK * WORDS + 2u * k;
    address_block[k] = vec2<u32>(memory[w], memory[w + 1u]);
  }
  workgroupBarrier();
}

// index_alpha() from core.c, with the one-lane specialisations folded in:
// reference_area_size needs only the pass/slice/index cases below, and both
// 64-bit multiplies only ask for their high 32 bits, so mulhi32 is enough.
fn index_alpha(passNo: u32, sliceNo: u32, idx: u32, pseudo_rand: u32) -> u32 {
  var area: u32;
  if (passNo == 0u) {
    if (sliceNo == 0u) {
      area = idx - 1u;                                  // first slice: all but previous
    } else {
      area = sliceNo * SEGMENT + idx - 1u;              // same lane, adds this segment
    }
  } else {
    area = BLOCKS - SEGMENT + idx - 1u;                 // last 3 segments + this one
  }
  // relative_position = pr; rp = rp*rp >> 32; rel = area-1 - (area*rp >> 32)
  let rp = mulhi32(pseudo_rand, pseudo_rand);
  let rel = area - 1u - mulhi32(area, rp);
  var start = 0u;
  if (passNo != 0u) {
    if (sliceNo != 3u) { start = (sliceNo + 1u) * SEGMENT; }
  }
  return (start + rel) % BLOCKS;
}

// Re-initialise the address input block for a segment: init_block_value() in
// ref.c, then v[0..5] = pass, lane, slice, memory_blocks, passes, type.
fn reset_input_block(region: u32, passNo: u32, sliceNo: u32, tid: u32) {
  let off = region + INPUT_BLOCK * WORDS;
  for (var j = 0u; j < BLOCK_U32_PER_THREAD; j++) {
    memory[off + tid * BLOCK_U32_PER_THREAD + j] = 0u;
  }
  workgroupBarrier();
  if (tid == 0u) {
    memory[off + 0u] = passNo;   memory[off + 1u] = 0u;
    memory[off + 2u] = 0u;       memory[off + 3u] = 0u;      // lane
    memory[off + 4u] = sliceNo;  memory[off + 5u] = 0u;
    memory[off + 6u] = BLOCKS;   memory[off + 7u] = 0u;      // memory_blocks
    memory[off + 8u] = 2u;       memory[off + 9u] = 0u;      // passes
    memory[off + 10u] = 2u;      memory[off + 11u] = 0u;     // argon2_type = Argon2_id
    addrCounter = 0u;
  }
  workgroupBarrier();
}

@compute @workgroup_size(8)
fn main(@builtin(workgroup_id) wid: vec3<u32>, @builtin(local_invocation_index) tid: u32) {
  let hid = wid.x;                       // one workgroup per hash
  if (hid >= params.count) { return; }

  let region = hid * (REGION_BLOCKS * WORDS);
  let ibase = hid * 512u;
  let fbase = hid * WORDS;

  // The first two blocks of the lane already exist: H0 -> H' -> B0, B1.
  for (var j = 0u; j < INIT_U32_PER_THREAD; j++) {
    memory[region + tid * INIT_U32_PER_THREAD + j] = init[ibase + tid * INIT_U32_PER_THREAD + j];
    memory[region + WORDS + tid * INIT_U32_PER_THREAD + j] = init[ibase + WORDS + tid * INIT_U32_PER_THREAD + j];
  }
  workgroupBarrier();

  for (var passNo = 0u; passNo < 2u; passNo++) {
    for (var sliceNo = 0u; sliceNo < 4u; sliceNo++) {
      // Argon2id: data-independent addressing in pass 0, slices 0 and 1.
      let dataIndependent = (passNo == 0u) && (sliceNo < 2u);
      // fill_segment() re-initialises the address input block for *every*
      // segment (init_block_value in ref.c), not once per hash, and v[6] is a
      // counter that restarts at 0. Getting this reset wrong changes the first
      // address block of the very first segment, so it is the first thing to
      // check when a port disagrees.
      if (dataIndependent) { reset_input_block(region, passNo, sliceNo, tid); }

      var i = 0u;
      if (passNo == 0u && sliceNo == 0u) {
        i = 2u;                                       // B0/B1 already in place
        if (dataIndependent) { next_addresses(region, tid); }
      }
      var curr = sliceNo * SEGMENT + i;
      var prev = select(curr - 1u, BLOCKS - 1u, curr == 0u);
      loop {
        if (i >= SEGMENT) { break; }
        if (curr == 1u) { prev = 0u; }                 // ref.c's wrap guard; unreachable with p=1
        var pr: vec2<u32>;
        if (dataIndependent) {
          if (i % ADDRESSES == 0u) { next_addresses(region, tid); }
          pr = address_block[i % ADDRESSES];
        } else {
          let w = region + prev * WORDS;
          pr = vec2<u32>(memory[w], memory[w + 1u]);
        }
        let refIndex = index_alpha(passNo, sliceNo, i, pr.x);
        // One lane, so ref_lane is always 0 and same_lane is always true.
        fill_block(region, curr, prev, refIndex, passNo != 0u, tid);
        i = i + 1u;
        curr = curr + 1u;
        prev = prev + 1u;
      }
    }
  }

  // Hand the last block of the lane back; the host XORs nothing (p = 1) and
  // computes the tag = blake2b_long(block, 32).
  for (var j = 0u; j < BLOCK_U32_PER_THREAD; j++) {
    final_block[fbase + tid * BLOCK_U32_PER_THREAD + j] = memory[region + (BLOCKS - 1u) * WORDS + tid * BLOCK_U32_PER_THREAD + j];
  }
}
