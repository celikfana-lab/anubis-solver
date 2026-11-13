// sipround.v — one SipHash round on four 64-bit words (SipHash-2-4).
`timescale 1ns/1ps
module sipround (
    input  wire [255:0] s,      // {d, c, b, a}
    output wire [255:0] o
);
    wire [63:0] a0 = s[63:0],  b0 = s[127:64];
    wire [63:0] c0 = s[191:128], d0 = s[255:192];

    wire [63:0] a1 = a0 + b0,  c1 = c0 + d0;
    wire [63:0] b1 = {b0[50:0], b0[63:51]};    // rotl 13
    wire [63:0] d1 = {d0[47:0], d0[63:48]};    // rotl 16
    wire [63:0] b2 = b1 ^ a1,  d2 = d1 ^ c1;
    wire [63:0] a2 = {a1[31:0], a1[63:32]};    // rotl 32
    wire [63:0] c2 = c1 + b2,  a3 = a2 + d2;
    wire [63:0] b3 = {b2[46:0], b2[63:47]};    // rotl 17
    wire [63:0] d3 = {d2[42:0], d2[63:43]};    // rotl 21
    wire [63:0] b4 = b3 ^ c2,  d4 = d3 ^ a3;
    wire [63:0] c3 = {c2[31:0], c2[63:32]};    // rotl 32

    assign o = {d4, c3, b4, a3};
endmodule
