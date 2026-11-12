// argon2_index.v — Argon2id index_alpha (single lane, p = 1).
//
// Maps a 32-bit pseudo-random to the index of the reference block inside the
// lane. With p = 1 the "same lane" branch of the reference implementation is
// always taken, so the reference-area size is:
//
//   pass 0, slice 0 :  index - 1
//   pass 0, slice >0:  slice*seg + index - 1
//   pass > 0        :  lane_len - seg + index - 1
//
//   rel = (pseudo_rand^2 >> 32)
//   rel = size - 1 - (size * rel >> 32)
//   start = (pass == 0) ? 0 : (slice == 3 ? 0 : (slice+1)*seg)
//   ref = (start + rel) mod lane_len
//
// start <= lane_len and rel < lane_len, so the modulo is one conditional
// subtract - no divider.

`timescale 1ns/1ps
module argon2_index (
    input  wire [31:0] pass_i,
    input  wire [31:0] slice_i,
    input  wire [31:0] index_i,
    input  wire [31:0] lane_len,
    input  wire [31:0] seg_len,
    input  wire [31:0] pseudo_rand,
    output wire [31:0] ref_index
);
    wire [31:0] size = (pass_i == 32'd0)
        ? ((slice_i == 32'd0) ? (index_i - 32'd1)
                              : (slice_i * seg_len + index_i - 32'd1))
        : (lane_len - seg_len + index_i - 32'd1);

    wire [63:0] sq   = pseudo_rand * pseudo_rand;
    wire [31:0] r1   = sq[63:32];
    wire [63:0] prod = size * r1;
    wire [31:0] rela = size - 32'd1 - prod[63:32];

    wire [31:0] start = (pass_i == 32'd0) ? 32'd0
                      : ((slice_i == 32'd3) ? 32'd0 : ((slice_i + 32'd1) * seg_len));
    wire [31:0] sum = start + rela;

    assign ref_index = (sum >= lane_len) ? (sum - lane_len) : sum;
endmodule
