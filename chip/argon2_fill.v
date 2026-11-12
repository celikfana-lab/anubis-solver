// argon2_fill.v — Argon2id fill_block (BlaMka) accelerator.
//
// Computes Z = P(R) ^ prev ^ refb ^ (dst if xor_en), where R = prev ^ refb and
// P is the Argon2 permutation: 8 column rounds over 16-word groups, then 8
// row rounds over the 16-word diagonals. 128 x 64-bit block, one G per cycle.
//
// Blocks are passed as 8192-bit vectors: word i is bits [64*i +: 64].
`timescale 1ns/1ps
module argon2_fill (
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,
    input  wire [8191:0] prev,
    input  wire [8191:0] refb,
    input  wire [8191:0] dst,
    input  wire          xor_en,
    output reg  [8191:0] out,
    output reg           busy,
    output reg           done
);
    reg [63:0] r [0:127];
    reg [8:0]  gcnt;    // 0..127: permutation steps, 128..255: finalize
    integer i;

    function [63:0] rotr64(input [63:0] x, input integer n);
        rotr64 = (x >> n) | (x << (64 - n));
    endfunction

    // f(a,b) = a + b + 2 * (a[31:0] * b[31:0])
    function [63:0] blamka(input [63:0] a, input [63:0] b);
        reg [63:0] p;
        begin
            p = a[31:0] * b[31:0];
            blamka = a + b + (p << 1);
        end
    endfunction

    // Permutation row: which of the 4 words each of the 8 G's touches.
    // P/G: 8 G's per round, 4 words each.
    function [3:0] perm_idx(input [2:0] gg, input integer p);
        reg [3:0] v;
        begin
            case (p)
                0: case (gg)
                       0, 4: v = 0; 1, 5: v = 1; 2, 6: v = 2; default: v = 3;
                   endcase
                1: case (gg)
                       0, 7: v = 4; 1, 4: v = 5; 2, 5: v = 6; default: v = 7;
                   endcase
                2: case (gg)
                       0, 6: v = 8; 1, 7: v = 9; 2, 4: v = 10; default: v = 11;
                   endcase
                default: case (gg)
                       0, 5: v = 12; 1, 6: v = 13; 2, 7: v = 14; default: v = 15;
                   endcase
            endcase
            perm_idx = v;
        end
    endfunction

    function [6:0] rowoff(input [3:0] p);
        case (p)
            4'd0: rowoff = 7'd0;   4'd1: rowoff = 7'd1;
            4'd2: rowoff = 7'd16;  4'd3: rowoff = 7'd17;
            4'd4: rowoff = 7'd32;  4'd5: rowoff = 7'd33;
            4'd6: rowoff = 7'd48;  4'd7: rowoff = 7'd49;
            4'd8: rowoff = 7'd64;  4'd9: rowoff = 7'd65;
            4'd10: rowoff = 7'd80; 4'd11: rowoff = 7'd81;
            4'd12: rowoff = 7'd96; 4'd13: rowoff = 7'd97;
            4'd14: rowoff = 7'd112;
            default: rowoff = 7'd113;
        endcase
    endfunction

    wire [3:0] rnd  = gcnt[6:3];
    wire [2:0] gsel = gcnt[2:0];
    wire [6:0] i0_w, i1_w, i2_w, i3_w;
    wire [3:0] p0 = perm_idx(gsel, 0);
    wire [3:0] p1 = perm_idx(gsel, 1);
    wire [3:0] p2 = perm_idx(gsel, 2);
    wire [3:0] p3 = perm_idx(gsel, 3);

    // Column rounds use 16*rnd + p; row rounds use 2*(rnd-8) + off[p].
    assign i0_w = (rnd < 4'd8) ? (7'd16 * rnd + {3'd0, p0})
                               : (7'd2 * (rnd - 4'd8) + rowoff(p0));
    assign i1_w = (rnd < 4'd8) ? (7'd16 * rnd + {3'd0, p1})
                               : (7'd2 * (rnd - 4'd8) + rowoff(p1));
    assign i2_w = (rnd < 4'd8) ? (7'd16 * rnd + {3'd0, p2})
                               : (7'd2 * (rnd - 4'd8) + rowoff(p2));
    assign i3_w = (rnd < 4'd8) ? (7'd16 * rnd + {3'd0, p3})
                               : (7'd2 * (rnd - 4'd8) + rowoff(p3));

    wire [63:0] v0 = r[i0_w];
    wire [63:0] v1 = r[i1_w];
    wire [63:0] v2 = r[i2_w];
    wire [63:0] v3 = r[i3_w];

    wire [63:0] a1 = blamka(v0, v1);
    wire [63:0] d1 = rotr64(v3 ^ a1, 32);
    wire [63:0] c1 = blamka(v2, d1);
    wire [63:0] b1 = rotr64(v1 ^ c1, 24);
    wire [63:0] a2 = blamka(a1, b1);
    wire [63:0] d2 = rotr64(d1 ^ a2, 16);
    wire [63:0] c2 = blamka(c1, d2);
    wire [63:0] b2 = rotr64(b1 ^ c2, 63);

    wire [8:0] f = gcnt - 9'd128;

    always @(posedge clk) begin
        if (!rst_n) begin
            busy <= 1'b0;
            done <= 1'b0;
            gcnt <= 9'd0;
        end else if (start) begin
            for (i = 0; i < 128; i = i + 1) begin
                r[i] <= prev[64*i +: 64] ^ refb[64*i +: 64];
            end
            gcnt <= 9'd0;
            busy <= 1'b1;
            done <= 1'b0;
        end else if (busy) begin
            if (gcnt < 9'd128) begin
                r[i0_w] <= a2;
                r[i1_w] <= b2;
                r[i2_w] <= c2;
                r[i3_w] <= d2;
                gcnt <= gcnt + 9'd1;
            end else begin
                out[64*f +: 64] <= r[f] ^ prev[64*f +: 64] ^ refb[64*f +: 64] ^
                                    (xor_en ? dst[64*f +: 64] : 64'd0);
                if (f == 7'd127) begin
                    busy <= 1'b0;
                    done <= 1'b1;
                end else begin
                    gcnt <= gcnt + 9'd1;
                end
            end
        end else begin
            done <= 1'b0;
        end
    end
endmodule
