@group(0) @binding(0) var<storage, read_write> o: array<u32, 64>;
// ---- 64-bit arithmetic over vec2<u32>(lo, hi) ----

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
    // carry out of the low 32 bits of (hi0 + lo1 + lo2)
    let s0 = hi0 + lo1; let c0 = select(0u, 1u, s0 < hi0);
    let s1 = s0 + lo2;  let c1 = select(0u, 1u, s1 < s0);
    let carry = c0 + c1;
    // low word of the high half = lo3 + hi1 + hi2 + carry, with its own carry
    let w0 = lo3 + hi1;      let d0 = select(0u, 1u, w0 < lo3);
    let w1 = w0 + hi2;       let d1 = select(0u, 1u, w1 < w0);
    let w2 = w1 + carry;     let d2 = select(0u, 1u, w2 < w1);
    return vec2<u32>(w2, hi3 + d0 + d1 + d2);
  }

  // high 64 of a signed product: unsigned high, then correct for negatives
  fn smulh64(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    var h = umulh64(a, b);
    if ((a.y & 0x80000000u) != 0u) { h = sub64(h, b); }
    if ((b.y & 0x80000000u) != 0u) { h = sub64(h, a); }
    return h;
  }

  // low 64 bits of the product
  fn mul64(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    return vec2<u32>(a.x * b.x,
                      a.x * b.y + a.y * b.x + mulhi32(a.x, b.x));
  }

  @compute @workgroup_size(1)
fn main() {
  o[0] = mul64(vec2<u32>(0x73cf256du, 0xdda1494cu), vec2<u32>(0x8f4d3e27u, 0xdb5b5fabu)).y;
  o[1] = umulh64(vec2<u32>(0x73cf256du, 0xdda1494cu), vec2<u32>(0x8f4d3e27u, 0xdb5b5fabu)).x;
  o[2] = mul64(vec2<u32>(0xec99108du, 0xc7fde805u), vec2<u32>(0x7734d7c1u, 0x73ab4876u)).y;
  o[3] = umulh64(vec2<u32>(0xec99108du, 0xc7fde805u), vec2<u32>(0x7734d7c1u, 0x73ab4876u)).x;
  o[4] = mul64(vec2<u32>(0x8201e2bdu, 0xdae44550u), vec2<u32>(0x965eda32u, 0x309d6b79u)).y;
  o[5] = umulh64(vec2<u32>(0x8201e2bdu, 0xdae44550u), vec2<u32>(0x965eda32u, 0x309d6b79u)).x;
  o[6] = mul64(vec2<u32>(0x2f45e678u, 0xcdcc6929u), vec2<u32>(0x830c71c2u, 0x79cb9e86u)).y;
  o[7] = umulh64(vec2<u32>(0x2f45e678u, 0xcdcc6929u), vec2<u32>(0x830c71c2u, 0x79cb9e86u)).x;
  o[8] = mul64(vec2<u32>(0xa13ffe79u, 0x9d2c67edu), vec2<u32>(0xcb008853u, 0x2fa91425u)).y;
  o[9] = umulh64(vec2<u32>(0xa13ffe79u, 0x9d2c67edu), vec2<u32>(0xcb008853u, 0x2fa91425u)).x;
  o[10] = mul64(vec2<u32>(0x18187993u, 0x7253edc6u), vec2<u32>(0x4dabb481u, 0x244caf9cu)).y;
  o[11] = umulh64(vec2<u32>(0x18187993u, 0x7253edc6u), vec2<u32>(0x4dabb481u, 0x244caf9cu)).x;
  o[12] = mul64(vec2<u32>(0x17362f25u, 0x89e7d15fu), vec2<u32>(0xcf44dd3fu, 0xe3eff9c0u)).y;
  o[13] = umulh64(vec2<u32>(0x17362f25u, 0x89e7d15fu), vec2<u32>(0xcf44dd3fu, 0xe3eff9c0u)).x;
  o[14] = mul64(vec2<u32>(0xb1852f27u, 0xa26b7f62u), vec2<u32>(0x0ab8ab67u, 0x986e86cbu)).y;
  o[15] = umulh64(vec2<u32>(0xb1852f27u, 0xa26b7f62u), vec2<u32>(0x0ab8ab67u, 0x986e86cbu)).x;
  o[16] = mul64(vec2<u32>(0xfb710734u, 0x656abd72u), vec2<u32>(0xf6fa5db8u, 0x73f778aau)).y;
  o[17] = umulh64(vec2<u32>(0xfb710734u, 0x656abd72u), vec2<u32>(0xf6fa5db8u, 0x73f778aau)).x;
  o[18] = mul64(vec2<u32>(0xa7677796u, 0xbd299753u), vec2<u32>(0x9d95847eu, 0xa66b0d38u)).y;
  o[19] = umulh64(vec2<u32>(0xa7677796u, 0xbd299753u), vec2<u32>(0x9d95847eu, 0xa66b0d38u)).x;
  o[20] = mul64(vec2<u32>(0x28518867u, 0x9f8558a6u), vec2<u32>(0x03d71684u, 0xd4ea65d0u)).y;
  o[21] = umulh64(vec2<u32>(0x28518867u, 0x9f8558a6u), vec2<u32>(0x03d71684u, 0xd4ea65d0u)).x;
  o[22] = mul64(vec2<u32>(0x8743feb6u, 0x102b938bu), vec2<u32>(0x0f3ebdd3u, 0x09208a65u)).y;
  o[23] = umulh64(vec2<u32>(0x8743feb6u, 0x102b938bu), vec2<u32>(0x0f3ebdd3u, 0x09208a65u)).x;
  o[24] = mul64(vec2<u32>(0x30b17d0bu, 0xe12b2b8fu), vec2<u32>(0x3deffa38u, 0x99809225u)).y;
  o[25] = umulh64(vec2<u32>(0x30b17d0bu, 0xe12b2b8fu), vec2<u32>(0x3deffa38u, 0x99809225u)).x;
  o[26] = mul64(vec2<u32>(0x07b37e14u, 0xc7321cc0u), vec2<u32>(0x76c468aeu, 0x5387f613u)).y;
  o[27] = umulh64(vec2<u32>(0x07b37e14u, 0xc7321cc0u), vec2<u32>(0x76c468aeu, 0x5387f613u)).x;
  o[28] = mul64(vec2<u32>(0x70c6a5b8u, 0x97491e23u), vec2<u32>(0xd7a94dedu, 0x320094eau)).y;
  o[29] = umulh64(vec2<u32>(0x70c6a5b8u, 0x97491e23u), vec2<u32>(0xd7a94dedu, 0x320094eau)).x;
  o[30] = mul64(vec2<u32>(0x84e55160u, 0x3bd03346u), vec2<u32>(0xa3ea284du, 0x4b4d8474u)).y;
  o[31] = umulh64(vec2<u32>(0x84e55160u, 0x3bd03346u), vec2<u32>(0xa3ea284du, 0x4b4d8474u)).x;
  o[32] = mul64(vec2<u32>(0x7ff12229u, 0x012d0ea6u), vec2<u32>(0xa9964aefu, 0x15c1d2dfu)).y;
  o[33] = umulh64(vec2<u32>(0x7ff12229u, 0x012d0ea6u), vec2<u32>(0xa9964aefu, 0x15c1d2dfu)).x;
  o[34] = mul64(vec2<u32>(0x75139237u, 0xa7a11490u), vec2<u32>(0x4735af1cu, 0x6822a6b2u)).y;
  o[35] = umulh64(vec2<u32>(0x75139237u, 0xa7a11490u), vec2<u32>(0x4735af1cu, 0x6822a6b2u)).x;
  o[36] = mul64(vec2<u32>(0xff666589u, 0x8d1fe1dau), vec2<u32>(0xfee5a5b2u, 0xee82ec3fu)).y;
  o[37] = umulh64(vec2<u32>(0xff666589u, 0x8d1fe1dau), vec2<u32>(0xfee5a5b2u, 0xee82ec3fu)).x;
  o[38] = mul64(vec2<u32>(0xd7185ddau, 0x154cd2aau), vec2<u32>(0xb53302fcu, 0x4105cca7u)).y;
  o[39] = umulh64(vec2<u32>(0xd7185ddau, 0x154cd2aau), vec2<u32>(0xb53302fcu, 0x4105cca7u)).x;
  o[40] = mul64(vec2<u32>(0x50b601fcu, 0xc20ba2c2u), vec2<u32>(0x3acb6266u, 0x834c687au)).y;
  o[41] = umulh64(vec2<u32>(0x50b601fcu, 0xc20ba2c2u), vec2<u32>(0x3acb6266u, 0x834c687au)).x;
  o[42] = mul64(vec2<u32>(0x49fe85b0u, 0x079dd25au), vec2<u32>(0x11fa2ac0u, 0x902a174fu)).y;
  o[43] = umulh64(vec2<u32>(0x49fe85b0u, 0x079dd25au), vec2<u32>(0x11fa2ac0u, 0x902a174fu)).x;
  o[44] = mul64(vec2<u32>(0xc42b7170u, 0x1ba1192eu), vec2<u32>(0x66809a11u, 0x1b98fbe4u)).y;
  o[45] = umulh64(vec2<u32>(0xc42b7170u, 0x1ba1192eu), vec2<u32>(0x66809a11u, 0x1b98fbe4u)).x;
  o[46] = mul64(vec2<u32>(0xd8b9b45cu, 0x4a789cb3u), vec2<u32>(0x62f28d1au, 0x111b8aaau)).y;
  o[47] = umulh64(vec2<u32>(0xd8b9b45cu, 0x4a789cb3u), vec2<u32>(0x62f28d1au, 0x111b8aaau)).x;
  o[48] = mul64(vec2<u32>(0xf542441du, 0x0452ef05u), vec2<u32>(0xd8e94b15u, 0xaf5570eeu)).y;
  o[49] = umulh64(vec2<u32>(0xf542441du, 0x0452ef05u), vec2<u32>(0xd8e94b15u, 0xaf5570eeu)).x;
  o[50] = mul64(vec2<u32>(0x0023b682u, 0x36a80bdfu), vec2<u32>(0x35b00a54u, 0xed52a241u)).y;
  o[51] = umulh64(vec2<u32>(0x0023b682u, 0x36a80bdfu), vec2<u32>(0x35b00a54u, 0xed52a241u)).x;
  o[52] = mul64(vec2<u32>(0xe90794dfu, 0x0d650372u), vec2<u32>(0x78511608u, 0x601e5b45u)).y;
  o[53] = umulh64(vec2<u32>(0xe90794dfu, 0x0d650372u), vec2<u32>(0x78511608u, 0x601e5b45u)).x;
  o[54] = mul64(vec2<u32>(0xfaf8cda9u, 0xb57a6a1du), vec2<u32>(0x65bd9acbu, 0x6b77730fu)).y;
  o[55] = umulh64(vec2<u32>(0xfaf8cda9u, 0xb57a6a1du), vec2<u32>(0x65bd9acbu, 0x6b77730fu)).x;
  o[56] = mul64(vec2<u32>(0x12b2a414u, 0x90f5380eu), vec2<u32>(0xa123f501u, 0x32d03fddu)).y;
  o[57] = umulh64(vec2<u32>(0x12b2a414u, 0x90f5380eu), vec2<u32>(0xa123f501u, 0x32d03fddu)).x;
  o[58] = mul64(vec2<u32>(0xc74c7ccfu, 0xacc6d8f2u), vec2<u32>(0x45100358u, 0x563e9bedu)).y;
  o[59] = umulh64(vec2<u32>(0xc74c7ccfu, 0xacc6d8f2u), vec2<u32>(0x45100358u, 0x563e9bedu)).x;
  o[60] = mul64(vec2<u32>(0x164f1513u, 0x4fab6f3eu), vec2<u32>(0x552454f1u, 0x03e0d681u)).y;
  o[61] = umulh64(vec2<u32>(0x164f1513u, 0x4fab6f3eu), vec2<u32>(0x552454f1u, 0x03e0d681u)).x;
  o[62] = mul64(vec2<u32>(0xf6cdb2f8u, 0x68f918d8u), vec2<u32>(0xc20ef164u, 0xec3fbf4du)).y;
  o[63] = umulh64(vec2<u32>(0xf6cdb2f8u, 0x68f918d8u), vec2<u32>(0xc20ef164u, 0xec3fbf4du)).x;
}
