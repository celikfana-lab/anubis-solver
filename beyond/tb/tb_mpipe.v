`timescale 1ns/1ps
// tb_mpipe.v — sustained throughput of NENG engines with KCTX hashes each
// against an HBM3 link. Reports blocks/s and hashes/s at 1 GHz.
module tb_mpipe;
    parameter integer NENG  = 24;
    parameter integer KCTX  = 2;
    parameter integer CLOCK = 1_000_000_000;   // Hz
    // NCTX has to exist before IDW: argon2_mpipe keeps the request id in
    // gsel[IDW-1:0], so a fixed IDW=6 silently starved every context above 63
    // as soon as NENG*KCTX > 64 (i.e. above 32 engines). Deriving it from NCTX
    // keeps `-Ptb_mpipe.NENG=59` honest without a manual override, and the
    // parameter can still be overridden explicitly.
    localparam integer NCTX = NENG*KCTX;
    parameter integer IDW   = (NCTX < 2) ? 1 : $clog2(NCTX);
    parameter integer EFF   = 100;             // HBM3 link efficiency, %
    parameter integer WARMUP = 480;            // blocks before measuring
    parameter integer TARGET = 4800;           // blocks measured in steady state

    reg clk = 0, rst_n = 0, start = 0;
    wire [31:0] blocks_done;
    wire        req_valid;
    wire [15:0] req_bytes;
    wire [IDW-1:0] req_id;
    wire        req_ready;
    wire        resp_valid;
    wire [IDW-1:0] resp_id;
    wire [63:0] bytes_served, req_served;

    argon2_mpipe #(.NENG(NENG), .KCTX(KCTX), .IDW(IDW)) dut (
        .clk(clk), .rst_n(rst_n), .start(start),
        .blocks_done(blocks_done),
        .mem_req_valid(req_valid), .mem_req_bytes(req_bytes), .mem_req_id(req_id),
        .mem_req_ready(req_ready),
        .mem_resp_valid(resp_valid), .mem_resp_id(resp_id));

    hbm3_model #(.BW(819), .LAT(350), .EFF(EFF), .IDW(IDW)) mem (
        .clk(clk), .rst_n(rst_n),
        .req_valid(req_valid), .req_bytes(req_bytes), .req_id(req_id),
        .req_ready(req_ready),
        .resp_valid(resp_valid), .resp_id(resp_id),
        .bytes_served(bytes_served), .req_served(req_served));

    always #5 clk = ~clk;

    integer cycles, cyc0, blk0, dblk, dcyc;
    real blocks_per_s, hashes_per_s, bpc, demand_bps;

    initial begin
        repeat (3) @(negedge clk);
        rst_n = 1;
        @(negedge clk);
        start = 1;
        @(negedge clk);
        start = 0;
        cycles = 0;
        while (blocks_done < WARMUP && cycles < 500_000) begin
            @(negedge clk);
            cycles = cycles + 1;
        end
        cyc0 = cycles; blk0 = blocks_done;
        while (blocks_done < WARMUP + TARGET && cycles < 1_000_000) begin
            @(negedge clk);
            cycles = cycles + 1;
        end
        dblk = blocks_done - blk0;
        dcyc = cycles - cyc0;
        blocks_per_s = dblk * 1.0 * CLOCK / dcyc;
        hashes_per_s = blocks_per_s / 38912.0;
        bpc          = bytes_served * 1.0 / cycles;
        demand_bps   = bpc * CLOCK / 1e9;
        $display("engines %0d, contexts/engine %0d (%0d in flight), HBM3 819 B/cycle at %0d%% efficiency, 350 cyc latency",
                 NENG, KCTX, NCTX, EFF);
        $display("  steady state: %0d blocks in %0d cycles (%.2f cycles/block, %.2f per engine)",
                 dblk, dcyc, dcyc * 1.0 / dblk, dcyc * 1.0 / dblk * NENG);
        $display("  link: %0d requests, %0d bytes, %.1f B/cycle (%.0f GB/s) of 819",
                 req_served[31:0], bytes_served[31:0], bpc, demand_bps);
        $display("  throughput: %.0f blocks/s -> %.0f hashes/s at 1 GHz",
                 blocks_per_s, hashes_per_s);
        $display("  at 200 MHz: %.0f hashes/s", hashes_per_s / 5.0);
        $finish;
    end
endmodule
