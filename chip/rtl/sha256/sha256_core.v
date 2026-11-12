// sha256_core.v — iterative SHA-256 compression core (1 round / cycle).
//
// Compresses one 512-bit block into a 256-bit chaining value. Start with
// `midstate`, pulse `start`; `done` rises one cycle after the 64th round with
// `digest` valid.
`timescale 1ns/1ps
module sha256_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] midstate,   // 8 x 32-bit words, word i = [32*i +: 32]
    input  wire [511:0] block,      // 16 x 32-bit words (big-endian bytes)
    output reg  [255:0] digest,
    output reg          done,
    output reg          busy
);
    localparam [31:0] K0  = 32'h428a2f98;

    reg [31:0] h0 [0:7];
    reg [31:0] a, b, c, d, e, f, g, hh;
    reg [31:0] w  [0:15];
    reg [5:0]  r;
    integer i;

    function [31:0] rotr(input [31:0] x, input integer n);
        rotr = (x >> n) | (x << (32 - n));
    endfunction

    function [31:0] kconst(input [5:0] idx);
        case (idx)
            6'd0:  kconst = 32'h428a2f98; 6'd1:  kconst = 32'h71374491;
            6'd2:  kconst = 32'hb5c0fbcf; 6'd3:  kconst = 32'he9b5dba5;
            6'd4:  kconst = 32'h3956c25b; 6'd5:  kconst = 32'h59f111f1;
            6'd6:  kconst = 32'h923f82a4; 6'd7:  kconst = 32'hab1c5ed5;
            6'd8:  kconst = 32'hd807aa98; 6'd9:  kconst = 32'h12835b01;
            6'd10: kconst = 32'h243185be; 6'd11: kconst = 32'h550c7dc3;
            6'd12: kconst = 32'h72be5d74; 6'd13: kconst = 32'h80deb1fe;
            6'd14: kconst = 32'h9bdc06a7; 6'd15: kconst = 32'hc19bf174;
            6'd16: kconst = 32'he49b69c1; 6'd17: kconst = 32'hefbe4786;
            6'd18: kconst = 32'h0fc19dc6; 6'd19: kconst = 32'h240ca1cc;
            6'd20: kconst = 32'h2de92c6f; 6'd21: kconst = 32'h4a7484aa;
            6'd22: kconst = 32'h5cb0a9dc; 6'd23: kconst = 32'h76f988da;
            6'd24: kconst = 32'h983e5152; 6'd25: kconst = 32'ha831c66d;
            6'd26: kconst = 32'hb00327c8; 6'd27: kconst = 32'hbf597fc7;
            6'd28: kconst = 32'hc6e00bf3; 6'd29: kconst = 32'hd5a79147;
            6'd30: kconst = 32'h06ca6351; 6'd31: kconst = 32'h14292967;
            6'd32: kconst = 32'h27b70a85; 6'd33: kconst = 32'h2e1b2138;
            6'd34: kconst = 32'h4d2c6dfc; 6'd35: kconst = 32'h53380d13;
            6'd36: kconst = 32'h650a7354; 6'd37: kconst = 32'h766a0abb;
            6'd38: kconst = 32'h81c2c92e; 6'd39: kconst = 32'h92722c85;
            6'd40: kconst = 32'ha2bfe8a1; 6'd41: kconst = 32'ha81a664b;
            6'd42: kconst = 32'hc24b8b70; 6'd43: kconst = 32'hc76c51a3;
            6'd44: kconst = 32'hd192e819; 6'd45: kconst = 32'hd6990624;
            6'd46: kconst = 32'hf40e3585; 6'd47: kconst = 32'h106aa070;
            6'd48: kconst = 32'h19a4c116; 6'd49: kconst = 32'h1e376c08;
            6'd50: kconst = 32'h2748774c; 6'd51: kconst = 32'h34b0bcb5;
            6'd52: kconst = 32'h391c0cb3; 6'd53: kconst = 32'h4ed8aa4a;
            6'd54: kconst = 32'h5b9cca4f; 6'd55: kconst = 32'h682e6ff3;
            6'd56: kconst = 32'h748f82ee; 6'd57: kconst = 32'h78a5636f;
            6'd58: kconst = 32'h84c87814; 6'd59: kconst = 32'h8cc70208;
            6'd60: kconst = 32'h90befffa; 6'd61: kconst = 32'ha4506ceb;
            6'd62: kconst = 32'hbef9a3f7; 6'd63: kconst = 32'hc67178f2;
            default: kconst = 32'h0;
        endcase
    endfunction

    // Message schedule: Wr is W[r] (computed on the fly for r >= 16).
    wire [3:0]  ri = r[3:0];
    wire [31:0] w_m2  = w[(r - 2)  & 4'hf];
    wire [31:0] w_m7  = w[(r - 7)  & 4'hf];
    wire [31:0] w_m15 = w[(r - 15) & 4'hf];
    wire [31:0] w_m16 = w[r        & 4'hf];
    wire [31:0] s1w = rotr(w_m2, 17) ^ rotr(w_m2, 19) ^ (w_m2 >> 10);
    wire [31:0] s0w = rotr(w_m15, 7) ^ rotr(w_m15, 18) ^ (w_m15 >> 3);
    wire [31:0] wnext = s1w + w_m7 + s0w + w_m16;
    wire [31:0] Wr = (r < 6'd16) ? w[ri] : wnext;

    wire [31:0] S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    wire [31:0] ch = (e & f) ^ ((~e) & g);
    wire [31:0] t1 = hh + S1 + ch + kconst(r) + Wr;
    wire [31:0] S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    wire [31:0] maj = (a & b) ^ (a & c) ^ (b & c);
    wire [31:0] t2 = S0 + maj;

    wire [31:0] a_n = t1 + t2;
    wire [31:0] e_n = d + t1;

    always @(posedge clk) begin
        if (!rst_n) begin
            busy   <= 1'b0;
            done   <= 1'b0;
            digest <= 256'b0;
            r      <= 6'd0;
            a <= 0; b <= 0; c <= 0; d <= 0; e <= 0; f <= 0; g <= 0; hh <= 0;
        end else if (start) begin
            h0[0] <= midstate[255 -: 32];
            h0[1] <= midstate[223 -: 32];
            h0[2] <= midstate[191 -: 32];
            h0[3] <= midstate[159 -: 32];
            h0[4] <= midstate[127 -: 32];
            h0[5] <= midstate[95 -: 32];
            h0[6] <= midstate[63 -: 32];
            h0[7] <= midstate[31 -: 32];
            a  <= midstate[255:224];
            b  <= midstate[223:192];
            c  <= midstate[191:160];
            d  <= midstate[159:128];
            e  <= midstate[127:96];
            f  <= midstate[95:64];
            g  <= midstate[63:32];
            hh <= midstate[31:0];
            w[0] <= block[511 -: 32];
            w[1] <= block[479 -: 32];
            w[2] <= block[447 -: 32];
            w[3] <= block[415 -: 32];
            w[4] <= block[383 -: 32];
            w[5] <= block[351 -: 32];
            w[6] <= block[319 -: 32];
            w[7] <= block[287 -: 32];
            w[8] <= block[255 -: 32];
            w[9] <= block[223 -: 32];
            w[10] <= block[191 -: 32];
            w[11] <= block[159 -: 32];
            w[12] <= block[127 -: 32];
            w[13] <= block[95 -: 32];
            w[14] <= block[63 -: 32];
            w[15] <= block[31 -: 32];
            r    <= 6'd0;
            busy <= 1'b1;
            done <= 1'b0;
        end else if (busy) begin
            if (r == 6'd63) begin
                digest[255:224] <= h0[0] + a_n;
                digest[223:192] <= h0[1] + a;
                digest[191:160] <= h0[2] + b;
                digest[159:128] <= h0[3] + c;
                digest[127:96]  <= h0[4] + e_n;
                digest[95:64]   <= h0[5] + e;
                digest[63:32]   <= h0[6] + f;
                digest[31:0]    <= h0[7] + g;
                busy <= 1'b0;
                done <= 1'b1;
            end else begin
                a  <= a_n;
                b  <= a;
                c  <= b;
                d  <= c;
                e  <= e_n;
                f  <= e;
                g  <= f;
                hh <= g;
                w[ri] <= Wr;
                r <= r + 6'd1;
            end
        end else begin
            done <= 1'b0;
        end
    end
endmodule
