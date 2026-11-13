// sha256_pool.v — NSHA SHA-256 nonce scanners in parallel.
//
// Each lane is the verified `anubis_pow` scanner (1 round/cycle, 128 cycles for
// a two-block message). Replication is the right shape for PoW because there is
// no latency requirement to preserve: NSHA lanes give NSHA/128 hashes per cycle.
//
// Lanes take disjoint nonce chunks (lane g starts at nonce_base + g*CHUNK and
// walks forward), so the pool never wastes work re-testing another lane's
// nonces.
//
// The area-optimal form of this block is the opposite of replication: a fully
// unrolled, 64-stage pipelined SHA-256 reaches 1 hash/cycle for ~100k cells,
// where 128 replicated scanners cost ~1.09M cells for the same 1 Ghash/s. That
// pipeline is not written yet; this pool is the version built from a core that
// is already verified against known vectors.

`timescale 1ns/1ps
module sha256_pool #(
    parameter integer NSHA  = 128,
    parameter integer CHUNK = 128        // nonces each lane owns before it wraps
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] midstate,
    input  wire [511:0] block0,
    input  wire [511:0] block1,
    input  wire [1:0]   nblocks,
    input  wire [3:0]   nonce_word,
    input  wire         nonce_le,
    input  wire [5:0]   difficulty,
    input  wire [31:0]  nonce_base,

    output wire         found,
    output wire [31:0]  found_nonce,
    output wire [255:0] found_digest,
    output wire         busy,
    output wire [31:0]  hashes_done
);
    wire [NSHA-1:0] lane_found, lane_busy;
    wire [NSHA*32-1:0]  lane_nonce;
    wire [NSHA*256-1:0] lane_digest;
    wire [NSHA*32-1:0]  lane_hashes;

    genvar g;
    generate
        for (g = 0; g < NSHA; g = g + 1) begin : lane
            localparam [31:0] LSTART = g * CHUNK;   // anubis_pow takes a 32-bit nonce
            anubis_pow u_lane (
                .clk(clk), .rst_n(rst_n), .start(start),
                .midstate(midstate), .block0(block0), .block1(block1),
                .nblocks(nblocks), .nonce_word(nonce_word), .nonce_le(nonce_le),
                .difficulty(difficulty),
                .nonce_start(nonce_base + LSTART),
                .busy(lane_busy[g]), .found(lane_found[g]),
                .found_nonce(lane_nonce[g*32 +: 32]),
                .found_digest(lane_digest[g*256 +: 256]),
                .hashes(lane_hashes[g*32 +: 32]));
        end
    endgenerate

    assign found = |lane_found;
    assign busy  = |lane_busy;

    // lowest-numbered lane that found something
    reg [31:0] win;
    integer k;
    always @(*) begin
        win = 32'd0;
        for (k = NSHA - 1; k >= 0; k = k - 1)
            if (lane_found[k]) win = k[31:0];
    end

    assign found_nonce  = lane_nonce[win*32 +: 32];
    assign found_digest = lane_digest[win*256 +: 256];

    function [31:0] sum_hashes;
        input [NSHA*32-1:0] v;
        integer i;
        begin
            sum_hashes = 32'd0;
            for (i = 0; i < NSHA; i = i + 1) sum_hashes = sum_hashes + v[i*32 +: 32];
        end
    endfunction

    assign hashes_done = sum_hashes(lane_hashes);
endmodule
