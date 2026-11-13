// hashx_pool.v — NLANE HashX scanners sharing one program.
//
// The program (up to 512 instructions, 8 KiB) is the same for every nonce of a
// challenge, so it is loaded once and read by every lane. Each lane still needs
// its own instruction fetch because the HashX VM's branch is data-dependent, so
// the array is read with NLANE ports; in silicon that is a banked ROM rather
// than one huge multiplexer, but the ports are what the lanes actually need.
//
// HashX is a 533-cycle serial chain per hash, so the only way to go faster is
// more lanes: throughput = NLANE / 533 per cycle at the clock.

`timescale 1ns/1ps
module hashx_pool #(
    parameter integer NLANE = 128,
    parameter integer MAXI  = 512,
    parameter integer DW    = 128
) (
    input  wire         clk,
    input  wire         rst_n,

    // program load (the host writes it once per challenge)
    input  wire         prog_we,
    input  wire [8:0]   prog_waddr,
    input  wire [DW-1:0] prog_wdata,

    // keys/program parameters, same for every lane
    input  wire         start,
    input  wire [255:0] keys,
    input  wire [31:0]  ninstr,
    input  wire [7:0]   difficulty,
    input  wire [63:0]  nonce_base,
    input  wire [31:0]  tries_per_lane,

    // result: first lane to find one wins
    output wire         hit,
    output wire [63:0]  hit_nonce,
    output wire [255:0] hit_tag,
    output wire [7:0]   hit_lz,
    output wire         busy,
    output wire         all_done,
    output wire [31:0]  hashes_done
);
    reg [DW-1:0] prog [0:MAXI-1];

    always @(posedge clk)
        if (prog_we) prog[prog_waddr] <= prog_wdata;

    wire [NLANE*9-1:0]   prog_addr;
    wire [NLANE*DW-1:0]  prog_data;
    wire [NLANE-1:0]     lane_hit, lane_done, lane_busy;
    wire [NLANE*64-1:0]  lane_nonce;
    wire [NLANE*256-1:0] lane_tag;
    wire [NLANE*8-1:0]   lane_lz;
    wire [NLANE*32-1:0]  lane_tries;

    genvar g;
    generate
        for (g = 0; g < NLANE; g = g + 1) begin : lane
            // explicit 64-bit lane offset: `nonce_base + g` made a 65-bit
            // expression because a genvar is a 32-bit integer
            localparam [63:0] LSTART = g;
            anubis_hashx_solve #(.STRIDE(NLANE)) u_lane (
                .clk(clk), .rst_n(rst_n), .start(start),
                .keys(keys), .ninstr(ninstr), .difficulty(difficulty),
                .nonce_start(nonce_base + LSTART), .max_tries(tries_per_lane),
                .prog_addr(prog_addr[g*9 +: 9]),
                .prog_data(prog_data[g*DW +: DW]),
                .hit(lane_hit[g]), .hit_nonce(lane_nonce[g*64 +: 64]),
                .hit_tag(lane_tag[g*256 +: 256]), .hit_lz(lane_lz[g*8 +: 8]),
                .busy(lane_busy[g]), .done(lane_done[g]),
                .tries(lane_tries[g*32 +: 32]));

            // one read port per lane: the branch makes the fetch addresses
            // diverge, so they cannot be broadcast
            assign prog_data[g*DW +: DW] = prog[prog_addr[g*9 +: 9]];
        end
    endgenerate

    assign hit      = |lane_hit;
    assign busy     = |lane_busy;
    assign all_done = &lane_done;

    // winner = lowest-numbered lane reporting a hit. Counting down leaves the
    // lowest index in place, which is what "first lane to find one" should mean.
    reg [31:0] win;
    integer k;
    always @(*) begin
        win = 32'd0;
        for (k = NLANE - 1; k >= 0; k = k - 1)
            if (lane_hit[k]) win = k[31:0];
    end

    assign hit_nonce = lane_nonce[win*64 +: 64];
    assign hit_tag   = lane_tag[win*256 +: 256];
    assign hit_lz    = lane_lz[win*8 +: 8];

    function [31:0] sum_tries;
        input [NLANE*32-1:0] v;
        integer i;
        begin
            sum_tries = 32'd0;
            for (i = 0; i < NLANE; i = i + 1) sum_tries = sum_tries + v[i*32 +: 32];
        end
    endfunction

    assign hashes_done = sum_tries(lane_tries);
endmodule
