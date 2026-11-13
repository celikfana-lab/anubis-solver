// anubis_hashx_solve.v — HashX nonce scanner, in RTL.
//
// `hashx_top` hashes one nonce; this walks the nonce space until the digest has
// `difficulty` leading zero bits, which is the Anubis hashx-family rule. The
// search used to live in the testbench (tb_hashx_solve.v); a chip needs it in
// hardware, and lanes need it with a stride so the pool covers disjoint nonces.
//
// The leading-zero count matches the C reference exactly: MSB of byte 0 first,
// which is the order the tag is packed in ([8k +: 8] is byte k).

`timescale 1ns/1ps
module anubis_hashx_solve #(
    parameter [63:0] STRIDE = 64'd1     // lanes take disjoint nonce classes
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] keys,           // k0..k3, as hashx_top wants them
    input  wire [31:0]  ninstr,
    input  wire [7:0]   difficulty,     // leading zero bits required
    input  wire [63:0]  nonce_start,
    input  wire [31:0]  max_tries,
    // program read port (shared RAM lives in hashx_pool)
    output wire [8:0]   prog_addr,
    input  wire [127:0] prog_data,
    // result
    output reg          hit,
    output reg  [63:0]  hit_nonce,
    output reg  [255:0] hit_tag,
    output reg  [7:0]   hit_lz,
    output reg          busy,
    output reg          done,
    output reg  [31:0]  tries
);
    localparam [1:0] S_IDLE = 2'd0, S_RUN = 2'd1, S_WAIT = 2'd2, S_CHK = 2'd3;

    reg  [1:0]  st;
    reg  [63:0] nonce;
    reg         hx_start;
    wire [255:0] tag;
    wire         hx_done, hx_busy;

    hashx_top hx (.clk(clk), .rst_n(rst_n), .start(hx_start), .keys(keys),
                  .nonce(nonce), .ninstr(ninstr),
                  .prog_addr(prog_addr), .prog_data(prog_data),
                  .tag(tag), .done(hx_done), .busy(hx_busy));

    // Leading zero bits of the 256-bit digest, MSB first (bit 7 of byte 0).
    function [7:0] lz_of(input [255:0] t);
        integer a, b;
        reg     stop;
        begin
            lz_of = 8'd0;
            stop  = 1'b0;
            for (a = 0; a < 32; a = a + 1)
                for (b = 7; b >= 0; b = b - 1)
                    if (!stop) begin
                        if (!t[8*a + b]) lz_of = lz_of + 8'd1;
                        else             stop  = 1'b1;
                    end
        end
    endfunction

    wire [7:0] lz = lz_of(tag);

    always @(posedge clk) begin
        if (!rst_n) begin
            st        <= S_IDLE;
            nonce     <= 64'd0;
            hx_start  <= 1'b0;
            hit       <= 1'b0;
            hit_nonce <= 64'd0;
            hit_tag   <= 256'd0;
            hit_lz    <= 8'd0;
            busy      <= 1'b0;
            done      <= 1'b0;
            tries     <= 32'd0;
        end else begin
            hx_start <= 1'b0;
            case (st)
                S_IDLE: if (start) begin
                    busy      <= 1'b1;
                    done      <= 1'b0;
                    hit       <= 1'b0;
                    tries     <= 32'd0;
                    nonce     <= nonce_start;
                    hx_start  <= 1'b1;
                    st        <= S_RUN;
                end
                S_RUN: st <= S_WAIT;
                S_WAIT: if (hx_done) st <= S_CHK;
                S_CHK: begin
                    tries <= tries + 32'd1;
                    if (lz >= difficulty) begin
                        hit       <= 1'b1;
                        hit_nonce <= nonce;
                        hit_tag   <= tag;
                        hit_lz    <= lz;
                        done      <= 1'b1;
                        busy      <= 1'b0;
                        st        <= S_IDLE;
                    end else if (tries + 32'd1 >= max_tries) begin
                        done <= 1'b1;
                        busy <= 1'b0;
                        st   <= S_IDLE;
                    end else begin
                        nonce    <= nonce + STRIDE;
                        hx_start <= 1'b1;
                        st       <= S_RUN;
                    end
                end
                default: st <= S_IDLE;
            endcase
        end
    end
endmodule
