// sim_top.v — synthesizable wrapper around argon2_engine for Verilator.
//
// Drives the nonce search with a plain clocked FSM (no delays, no $finish), so
// the whole thing compiles to C++ and runs far faster than Icarus. The password
// comes from solve_challenge.hex via $readmemh, exactly like tb_anubis_solve.
`timescale 1ns/1ps
module sim_top #(
    parameter [31:0] M_COST = 32'd19456,
    parameter [31:0] DIFF   = 32'd1
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         go,
    input  wire [63:0]  nonce_start,
    input  wire [31:0]  max_tries,
    input  wire [31:0]  plen,
    input  wire         le,
    output reg          hit,
    output reg          done_all,
    output reg  [63:0]  hit_nonce,
    output reg  [31:0]  tries,
    output reg  [7:0]   lz_out,
    output wire [31:0]  tag_w0, tag_w1, tag_w2, tag_w3,
    output wire [31:0]  tag_w4, tag_w5, tag_w6, tag_w7,
    output wire         eng_busy
);
    reg [7:0] pw [0:255];
    initial $readmemh("vectors/solve_challenge.hex", pw);

    reg         eng_start;
    reg  [31:0] eng_plen;
    reg  [63:0] salt;
    reg  [63:0] nonce;
    wire [31:0] p_addr;
    wire [255:0] tag;
    wire        eng_done;

    assign tag_w0 = tag[31:0];
    assign tag_w1 = tag[63:32];
    assign tag_w2 = tag[95:64];
    assign tag_w3 = tag[127:96];
    assign tag_w4 = tag[159:128];
    assign tag_w5 = tag[191:160];
    assign tag_w6 = tag[223:192];
    assign tag_w7 = tag[255:224];

    argon2_engine #(.M_COST(M_COST), .T_COST(32'd2), .TAGLEN(32'd32),
                    .VERSION(32'h13), .TYPE_ID(32'd2))
    dut (.clk(clk), .rst_n(rst_n), .start(eng_start), .plen(eng_plen),
         .p_addr(p_addr), .p_byte(pw[p_addr[7:0]]), .salt(salt),
         .tag_out(tag), .done(eng_done), .busy(eng_busy));

    function [7:0] lz_bits(input [255:0] t);
        integer a, b;
        reg stop;
        begin
            lz_bits = 8'd0; stop = 1'b0;
            for (a = 0; a < 32; a = a + 1)
                for (b = 7; b >= 0; b = b - 1)
                    if (!stop) begin
                        if (!t[8*a + b]) lz_bits = lz_bits + 8'd1;
                        else stop = 1'b1;
                    end
        end
    endfunction

    function [63:0] bswap(input [63:0] v);
        integer a;
        begin
            for (a = 0; a < 8; a = a + 1) bswap[8*a +: 8] = v[8*(7-a) +: 8];
        end
    endfunction

    localparam [1:0] S_IDLE = 2'd0, S_RUN = 2'd1, S_CHECK = 2'd2;
    reg [1:0] st;
    reg [7:0] lz;
    integer   i;

    always @(posedge clk) begin
        if (!rst_n) begin
            st <= S_IDLE; eng_start <= 1'b0; hit <= 1'b0; done_all <= 1'b0;
            hit_nonce <= 64'd0; tries <= 32'd0; lz_out <= 8'd0;
            nonce <= 64'd0; salt <= 64'd0; eng_plen <= 32'd0;
        end else begin
            eng_start <= 1'b0;
            case (st)
                S_IDLE: if (go) begin
                    nonce     <= nonce_start;
                    salt      <= le ? nonce_start : bswap(nonce_start);
                    eng_plen  <= plen;
                    tries     <= 32'd0;
                    hit       <= 1'b0;
                    done_all  <= 1'b0;
                    lz_out    <= 8'd0;
                    eng_start <= 1'b1;
                    st        <= S_RUN;
                end
                S_RUN: if (eng_done) begin
                    lz <= lz_bits(tag);
                    st <= S_CHECK;
                end
                S_CHECK: begin
                    lz_out <= lz;
                    tries  <= tries + 32'd1;
                    if (lz >= DIFF[7:0]) begin
                        hit       <= 1'b1;
                        hit_nonce <= nonce;
                        done_all  <= 1'b1;
                        st        <= S_IDLE;
                    end else if (tries + 32'd1 >= max_tries) begin
                        done_all <= 1'b1;
                        st       <= S_IDLE;
                    end else begin
                        nonce     <= nonce + 64'd1;
                        salt      <= le ? (nonce + 64'd1) : bswap(nonce + 64'd1);
                        eng_start <= 1'b1;
                        st        <= S_RUN;
                    end
                end
                default: st <= S_IDLE;
            endcase
        end
    end
endmodule
