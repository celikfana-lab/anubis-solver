// hashx_prf.v — HashX's nonce -> initial register file.
//
// SipHash-2-4 used as a 512-bit PRF (tevador/hashx siphash.c):
//
//   v = keys; v1 ^= 0xee; v3 ^= nonce
//   2 rounds;  v0 ^= nonce; v2 ^= 0xee
//   4 rounds;  out[0..3] = v; v1 ^= 0xdd
//   4 rounds;  out[4..7] = v
//
// One SIPROUND per cycle, so ten cycles per nonce. The same round unit serves
// the finalisation, which is two independent rounds on r[0..3] and r[4..7].

`timescale 1ns/1ps
module hashx_prf (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] keys,     // k0 in [63:0] ... k3 in [255:192]
    input  wire [63:0]  nonce,
    output reg  [511:0] r_out,    // r0 in [63:0] ... r7 in [511:448]
    output reg          done,
    output reg          busy
);
    localparam [1:0] S_IDLE = 2'd0, S_RUN = 2'd1, S_DONE = 2'd2;

    reg [1:0]   st;
    reg [255:0] v;         // {v3, v2, v1, v0}
    reg [1:0]   grp;
    reg [3:0]   cnt;       // rounds left in this group
    reg [63:0]  nonce_r;

    wire [255:0] nxt;
    sipround round_u (.s(v), .o(nxt));

    always @(posedge clk) begin
        if (!rst_n) begin
            st <= S_IDLE; busy <= 1'b0; done <= 1'b0;
            v <= 256'd0; grp <= 2'd0; cnt <= 4'd0; r_out <= 512'd0;
            nonce_r <= 64'd0;
        end else if (st == S_IDLE) begin
            done <= 1'b0;
            if (start) begin
                v <= {keys[255:192] ^ nonce,        // v3 ^= nonce
                      keys[191:128],                // v2
                      keys[127:64] ^ 64'h00000000000000ee,  // v1 ^= 0xee
                      keys[63:0]};                  // v0
                nonce_r <= nonce;
                grp <= 2'd0;
                cnt <= 4'd2;        // two rounds before the first xor
                busy <= 1'b1;
                st <= S_RUN;
            end
        end else if (st == S_RUN) begin
            if (cnt != 4'd0) begin
                v <= nxt;
                cnt <= cnt - 4'd1;
            end else begin
                case (grp)
                    2'd0: begin         // v0 ^= nonce; v2 ^= 0xee
                        v <= {v[255:192],
                              v[191:128] ^ 64'h00000000000000ee,
                              v[127:64],
                              v[63:0] ^ nonce_r};
                        grp <= 2'd1;
                        cnt <= 4'd4;
                    end
                    2'd1: begin         // out[0..3] = v; v1 ^= 0xdd
                        r_out[255:0] <= v;
                        // v1 ^= 0xdd  (v1 is the second word of {v3,v2,v1,v0})
                        v <= {v[255:192],
                              v[191:128],
                              v[127:64] ^ 64'h00000000000000dd,
                              v[63:0]};
                        grp <= 2'd2;
                        cnt <= 4'd4;
                    end
                    default: begin      // out[4..7] = v
                        r_out[511:256] <= v;
                        busy <= 1'b0;
                        st <= S_DONE;
                    end
                endcase
            end
        end else begin
            done <= 1'b1;
            st <= S_IDLE;
        end
    end
endmodule
