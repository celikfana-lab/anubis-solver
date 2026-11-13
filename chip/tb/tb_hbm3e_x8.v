`timescale 1ns/1ps
// tb_hbm3e_x8.v — what eight HBM3e stacks actually do to Argon2id throughput.
//
// Two testbenches live in this file; build one at a time with `-s <top>`:
//
//   tb_hbm3e_capacity  The memory subsystem on its own. Measured evidence for
//                      (a) each of the eight HBM3e links sustaining 1228
//                      B/cycle and the eight together sustaining 9824 B/cycle
//                      when they are each given a request port, (b) the
//                      8-stack router's req_ready following the SELECTED
//                      stack only, (c) one request/cycle through that router
//                      spreading across the stacks 12.5% each, and (d) no
//                      response lost, reordered or double-merged.
//   tb_hbm3e_mpipe     N argon2_mpipe engines x K hashes each against the
//                      8-stack subsystem: the engine-count sweep. fill_block
//                      is the CYC_BLOCK counter there, so this measures
//                      arbitration / occupancy / latency hiding, not the
//                      Argon2 round function.
//
// HBM3e in both: 1228.8 B/cycle per stack at 1 GHz, modelled as BW=1228
// (0.07% conservative). 8 stacks => 9824 B/cycle.

// ===========================================================================
// (1) subsystem capacity, routing and load balance
// ===========================================================================
module tb_hbm3e_capacity;
    parameter integer BW     = 1228;    // B/cycle per HBM3e stack (1228.8 rounded down)
    parameter integer LAT    = 350;     // ~350 ns at 1 GHz
    parameter integer EFF    = 100;     // link efficiency, %
    parameter integer IDW    = 6;
    parameter integer NL     = 8;       // stacks
    // 1024 cycles is an exact measurement, not a sample: 1228 B/cycle x 1024 =
    // 307 x 4096, so every link accepts exactly 307 of its 4096 B requests and
    // the credit restores to the same value. Any multiple of 1024 is exact too.
    parameter integer WINDOW = 1024;    // cycles measured
    parameter integer SEGB   = 19456;   // Argon2 blocks in pass 0 (blk wraps here)

    reg clk = 0, rst_n = 0;
    always #5 clk = ~clk;

    function [63:0] sum64;
        input [NL*64-1:0] v;
        integer i;
        begin
            sum64 = 64'd0;
            for (i = 0; i < NL; i = i + 1) sum64 = sum64 + v[i*64 +: 64];
        end
    endfunction

    // ---- (a) eight links, one request port per stack ----------------------
    // The shipped 8-stack router has ONE request port, which accepts at most
    // one request per cycle: with 4 KiB requests that is a 4096 B/cycle
    // client-side cap no matter how much bandwidth sits behind it. To measure
    // the links themselves, each stack is given its own port here (hbm3e_mem
    // with NSTACK=1) and all eight run flat out simultaneously.
    wire [NL-1:0]     l_ready, l_rvalid;
    wire [NL*IDW-1:0] l_rid;
    wire [NL*64-1:0]  l_bytes, l_reqs;
    reg  [NL*32-1:0]  l_blk;
    reg  [NL*IDW-1:0] l_id;

    genvar g;
    generate
        for (g = 0; g < NL; g = g + 1) begin : g_lane
            hbm3e_mem #(.NSTACK(1), .BW(BW), .LAT(LAT), .EFF(EFF), .IDW(IDW)) u_lane (
                .clk(clk), .rst_n(rst_n),
                .req_valid(1'b1),                       // always ready to ask
                .req_blk(l_blk[g*32 +: 32]),
                .req_bytes(16'd4096),                   // 4 KiB request, max size
                .req_id(l_id[g*IDW +: IDW]),
                .req_ready(l_ready[g]),
                .resp_valid(l_rvalid[g]),
                .resp_id(l_rid[g*IDW +: IDW]),
                .bytes_served(l_bytes[g*64 +: 64]),
                .req_served(l_reqs[g*64 +: 64]),
                .st_bytes_served(), .st_req_served(),
                .resp_collision(), .resp_overflow());
        end
    endgenerate

    // Advance a lane's block index only on an accepted request. Sampling at
    // posedge reads exactly the values the DUT sampled on that edge, so the
    // accepted sequence is 0,1,2,... with no off-by-one.
    integer k;
    always @(posedge clk) begin
        if (!rst_n) begin
            l_blk <= {NL*32{1'b0}};
            l_id  <= {NL*IDW{1'b0}};
        end else begin
            for (k = 0; k < NL; k = k + 1)
                if (l_ready[k]) begin
                    if (l_blk[k*32 +: 32] == SEGB - 1)
                        l_blk[k*32 +: 32] <= 32'd0;
                    else
                        l_blk[k*32 +: 32] <= l_blk[k*32 +: 32] + 32'd1;
                    l_id[k*IDW +: IDW] <= l_id[k*IDW +: IDW] + {{(IDW-1){1'b0}}, 1'b1};
                end
        end
    end

    // Response monitor: every accepted request must come back exactly once,
    // in order, with its id intact (one wrapper per stack, so per-lane order
    // is the natural check).
    reg  [NL*IDW-1:0] exp_id;
    integer resp_cnt, id_err, m;        // lane response bookkeeping
    always @(posedge clk) begin
        if (!rst_n) begin
            exp_id   <= {NL*IDW{1'b0}};
            resp_cnt = 0;
            id_err   = 0;
        end else begin
            for (m = 0; m < NL; m = m + 1)
                if (l_rvalid[m]) begin
                    resp_cnt = resp_cnt + 1;
                    if (l_rid[m*IDW +: IDW] !== exp_id[m*IDW +: IDW]) id_err = id_err + 1;
                    exp_id[m*IDW +: IDW] <= exp_id[m*IDW +: IDW] + {{(IDW-1){1'b0}}, 1'b1};
                end
        end
    end

    // ---- (b)+(c) the real 8-stack router, one request port ----------------
    reg           r_valid, r_en;
    reg  [31:0]   r_blk;
    reg  [15:0]   r_bytes;
    reg  [IDW-1:0] r_id;
    wire          r_ready, r_rvalid;
    wire [IDW-1:0] r_rid;
    wire [63:0]   r_bagg, r_ragg;
    wire [NL*64-1:0] r_stb, r_str;
    wire [31:0]   r_coll, r_ovfl;

    hbm3e_mem #(.NSTACK(NL), .BW(BW), .LAT(LAT), .EFF(EFF), .IDW(IDW)) dut8 (
        .clk(clk), .rst_n(rst_n),
        .req_valid(r_valid), .req_blk(r_blk), .req_bytes(r_bytes), .req_id(r_id),
        .req_ready(r_ready),
        .resp_valid(r_rvalid), .resp_id(r_rid),
        .bytes_served(r_bagg), .req_served(r_ragg),
        .st_bytes_served(r_stb), .st_req_served(r_str),
        .resp_collision(r_coll), .resp_overflow(r_ovfl));

    // Automatic blk++ for the distribution phase (r_en gates it so the
    // routing phase can drive r_blk by hand).
    always @(posedge clk) begin
        if (!rst_n) begin
            r_blk <= 32'd0;
            r_id  <= {IDW{1'b0}};
        end else if (r_en && r_ready) begin
            if (r_blk == SEGB - 1) r_blk <= 32'd0;
            else                   r_blk <= r_blk + 32'd1;
            r_id <= r_id + {{(IDW-1){1'b0}}, 1'b1};
        end
    end

    // Response monitor for the merged port: ids must arrive in request order
    // and increment by exactly one, so a dropped or reordered response shows up
    // as a gap. r_mon arms it only for the measured window (the routing phase
    // deliberately reuses id 0).
    reg           r_mon, r_have;
    reg [IDW-1:0] r_prev;
    integer       r_resp_cnt, r_id_err;
    always @(posedge clk) begin
        if (!rst_n) begin
            r_have <= 1'b0; r_prev <= {IDW{1'b0}};
            r_resp_cnt = 0; r_id_err = 0;
        end else if (r_mon && r_rvalid) begin
            r_resp_cnt = r_resp_cnt + 1;
            if (!r_have) begin
                r_have <= 1'b1;
                r_prev <= r_rid;
            end else begin
                if (r_rid !== r_prev + {{(IDW-1){1'b0}}, 1'b1}) r_id_err = r_id_err + 1;
                r_prev <= r_rid;
            end
        end
    end

    // ---- measurement ------------------------------------------------------
    reg  [NL*64-1:0] sb, sr;
    reg  [NL*64-1:0] rb0, rr0;
    reg  [63:0]      agg0, agg1, rq0;
    integer resp_cnt0, rc0, dreq, dres, dcoll, derr, re0, rm0;
    integer n, busy0, other_ok, share_ok;
    real             bpc, lane_bpc, tgt;
    real             sh, sh_min, sh_max;

    initial begin
        r_valid = 1'b0; r_en = 1'b0; r_mon = 1'b0; r_blk = 32'd0;
        r_bytes = 16'd4096; r_id = 0;

        $display("== HBM3e x%0d capacity check: BW=%0d B/cycle/stack, LAT=%0d cycles, EFF=%0d%%",
                 NL, BW, LAT, EFF);
        $display("   analytic: %0d stacks x %0d B/cycle = %0d B/cycle = %0d GB/s at 1 GHz",
                 NL, BW, NL*BW, NL*BW);
        $display("   (1228.8 B/cycle/stack rounded down to 1228: 0.07%% conservative)");

        repeat (3) @(negedge clk);
        rst_n = 1;

        // ---- (a) aggregate link capacity, one port per stack --------------
        repeat (500) @(negedge clk);         // credit fill + latency pipeline
        sb = l_bytes; sr = l_reqs; rc0 = resp_cnt;
        repeat (WINDOW) @(negedge clk);
        agg0 = sum64(l_bytes) - sum64(sb);
        dreq = sum64(l_reqs) - sum64(sr);
        dres = resp_cnt - rc0;

        bpc = agg0 * 1.0 / WINDOW;
        $display("   eight independent links, always-ready 4096 B requests, %0d cycles:", WINDOW);
        $write("     per-stack B/cycle:");
        for (n = 0; n < NL; n = n + 1) begin
            lane_bpc = (l_bytes[n*64 +: 64] - sb[n*64 +: 64]) * 1.0 / WINDOW;
            $write(" %.1f", lane_bpc);
        end
        $write("\n");
        $display("     aggregate: %.1f B/cycle = %.0f GB/s at 1 GHz  (target %0d B/cycle)",
                 bpc, bpc, NL*BW);
        // Requests still in the LAT pipeline at the window edge are expected;
        // more missing than that would mean a dropped response.
        $display("     accepted: %0d requests (%0d bytes), responses in window: %0d (in flight %0d, LAT=%0d), id/order errors: %0d",
                 dreq, agg0, dres, dreq - dres, LAT, id_err);
        if ((bpc > (NL*BW) * 0.999) && (bpc < (NL*BW) * 1.001) && (id_err == 0)
            && (dreq - dres >= 0) && (dreq - dres <= LAT + 4))
            $display("     RESULT: PASS - all %0d links run at full rate independently", NL);
        else
            $display("     RESULT: FAIL - aggregate off target or responses wrong");

        // ---- (b) req_ready follows the selected stack only ----------------
        // Drain stack 0 until the router backpressures it, then point the very
        // next request at stack 3: a router that ORs the stack readies (a
        // common bug) would stall here, a correct one accepts immediately.
        r_valid = 1'b1; r_blk = 32'd0;
        @(negedge clk);
        while (r_ready) @(negedge clk);       // accept until stack 0 runs dry
        busy0 = !r_ready;                     // stack 0 is busy: 1, as required
        r_blk = 32'd3;                        // same request, different stack
        #1;
        other_ok = r_ready;                   // stack 3 never waited on stack 0
        r_valid = 1'b0;
        @(negedge clk);
        $display("   router, stack 0 drained: selected stack busy=%0d, stack 3 ready=%0d",
                 busy0, other_ok);
        if (busy0 && other_ok)
            $display("     RESULT: PASS - req_ready is the selected stack's ready only");
        else
            $display("     RESULT: FAIL - an unrelated busy stack stalled the request");

        // ---- (c) distribution through the one shared request port ---------
        // blk increments on every accept, so consecutive requests walk the
        // stacks round-robin. The port accepts 1 request/cycle here, so the
        // aggregate must sit exactly at 4096 B/cycle and every stack must get
        // 12.5% of the traffic.
        r_valid = 1'b0; r_blk = 32'd0; r_id = {IDW{1'b0}}; r_en = 1'b0;
        repeat (LAT + 50) @(negedge clk);     // drain the routing-phase responses
        r_valid = 1'b1; r_blk = 32'd0; r_id = {IDW{1'b0}}; r_en = 1'b1;
        repeat (600) @(negedge clk);          // fill the pipeline, ids in step
        rb0 = r_stb; rr0 = r_str; agg0 = r_bagg;
        rq0 = sum64(r_str); rc0 = r_resp_cnt; re0 = r_id_err; rm0 = r_coll;
        r_mon = 1'b1;
        repeat (WINDOW) @(negedge clk);
        r_mon = 1'b0;
        agg1 = r_bagg - agg0;
        bpc  = agg1 * 1.0 / WINDOW;
        dreq = sum64(r_str) - rq0;
        dres = r_resp_cnt - rc0;
        derr = r_id_err - re0;
        dcoll = r_coll - rm0;

        $display("   eight-stack router, ONE request port, blk++ on every accept, %0d cycles:",
                 WINDOW);
        $display("     aggregate: %.1f B/cycle = %.0f GB/s at 1 GHz  (port limit 4096)",
                 bpc, bpc);
        $display("     requests: %0d (%.3f req/cycle), responses in window: %0d (in flight %0d)",
                 dreq, dreq * 1.0 / WINDOW, dres, dreq - dres);
        $write("     per-stack share %%:");
        sh_min = 100.0; sh_max = 0.0;
        for (n = 0; n < NL; n = n + 1) begin
            sh = (r_stb[n*64 +: 64] - rb0[n*64 +: 64]) * 100.0 / agg1;
            $write(" %.2f", sh);
            if (sh < sh_min) sh_min = sh;
            if (sh > sh_max) sh_max = sh;
        end
        $write("\n");
        $display("     share spread: %.2f%% .. %.2f%% (ideal %.2f%%)",
                 sh_min, sh_max, 100.0 / NL);
        share_ok = (sh_min > (100.0/NL) - 0.5) && (sh_max < (100.0/NL) + 0.5);
        if ((bpc > 4095.9) && (bpc < 4096.1) && share_ok && (dcoll == 0)
            && (derr == 0) && (dreq - dres >= 0) && (dreq - dres <= LAT + 4))
            $display("     RESULT: PASS - merged responses intact (collisions=%0d, id gaps=%0d, in-flight=%0d <= LAT+4)",
                     dcoll, derr, dreq - dres);
        else
            $display("     RESULT: FAIL - bpc=%.1f coll=%0d id_gaps=%0d resp=%0d reqs=%0d",
                     bpc, dcoll, derr, dres, dreq);

        $display("   note: the 4096 B/cycle above is the CLIENT port, not the memory:");
        $display("         %0d B/cycle of stacks are available and only %.0f%% are used here.",
                 NL*BW, 100.0 * bpc / (NL*BW));
        $finish;
    end
endmodule

// ===========================================================================
// (2) the engine sweep: NENG engines x KCTX hashes against 8 HBM3e stacks
// ===========================================================================
module tb_hbm3e_mpipe;
    parameter integer NENG      = 236;
    parameter integer KCTX      = 2;
    parameter integer CYC_BLOCK = 260;
    parameter integer NSTACK    = 8;
    parameter integer BW        = 1228;
    parameter integer LAT       = 350;
    parameter integer EFF       = 100;
    parameter integer BPH       = 38912;     // blocks per hash, m=19456 t=2
    parameter integer WARMUP    = 500;       // blocks before measuring
    parameter integer TARGET    = 10000;     // CYCLES measured in steady state
    parameter integer MINCYC    = 3000;      // never measure before this
    parameter integer MAXCYC    = 4000000;
    parameter integer CLOCK     = 1_000_000_000;

    localparam integer NCTX = NENG*KCTX;
    // IDW must cover every context: argon2_mpipe stores the request id in
    // gsel[IDW-1:0], so NCTX > 2^IDW silently starves every context above the
    // truncation point (the checked-in tb_mpipe leaves IDW=6, which is only
    // correct up to 32 engines; the SPEED.md table reproduces with IDW=8).
    localparam integer IDW  = (NCTX < 2) ? 1 : $clog2(NCTX);
    parameter integer NPORT     = 1;       // request lanes
    parameter integer NRESP     = 1;       // response lanes

    reg clk = 0, rst_n = 0, start = 0;
    wire [31:0] blocks_done;
    wire [NPORT-1:0]     req_valid;
    wire [NPORT*16-1:0]  req_bytes;
    wire [NPORT*32-1:0]  req_blk;
    wire [NPORT*IDW-1:0] req_id;
    wire [NPORT-1:0]     req_ready;
    wire [NRESP-1:0]     resp_valid;
    wire [NRESP*IDW-1:0] resp_id;
    wire [63:0] bytes_served, req_served;
    wire [NSTACK*64-1:0] st_bytes, st_reqs;
    wire [31:0] collisions, overflow;

    argon2_mpipe #(.NENG(NENG), .KCTX(KCTX), .CYC_BLOCK(CYC_BLOCK), .BPH(BPH),
                   .IDW(IDW), .NPORT(NPORT), .NRESP(NRESP)) dut (
        .clk(clk), .rst_n(rst_n), .start(start),
        .blocks_done(blocks_done),
        .mem_req_valid(req_valid), .mem_req_bytes(req_bytes),
        .mem_req_blk(req_blk), .mem_req_id(req_id),
        .mem_req_ready(req_ready),
        .mem_resp_valid(resp_valid), .mem_resp_id(resp_id));

    // NPORT/NRESP must be passed through: leaving them at their defaults
    // silently gives the memory one request lane and one response lane, which
    // truncates the multi-lane buses instead of failing to elaborate.
    hbm3e_mem #(.NSTACK(NSTACK), .BW(BW), .LAT(LAT), .EFF(EFF), .IDW(IDW),
                .NPORT(NPORT), .NRESP(NRESP)) mem (
        .clk(clk), .rst_n(rst_n),
        .req_valid(req_valid), .req_blk(req_blk), .req_bytes(req_bytes), .req_id(req_id),
        .req_ready(req_ready),
        .resp_valid(resp_valid), .resp_id(resp_id),
        .bytes_served(bytes_served), .req_served(req_served),
        .st_bytes_served(st_bytes), .st_req_served(st_reqs),
        .resp_collision(collisions), .resp_overflow(overflow));

    always #5 clk = ~clk;

    // 8 lanes x 64 bits: fixed width so NSTACK<8 also works (zero-extended)
    reg [8*64-1:0] bsnap, rsnap;
    integer cycles, cyc0, blk0, dblk, dcyc, n;
    integer dreq;
    real    cpb, cpb_eng, bpc, gbs, hashes, reqport, share, total;
    real    bwtotal;

    initial begin
        repeat (3) @(negedge clk);
        rst_n = 1;
        @(negedge clk);
        start = 1;
        @(negedge clk);
        start = 0;

        cycles = 0;
        while (((blocks_done < WARMUP) || (cycles < MINCYC)) && cycles < MAXCYC) begin
            @(negedge clk);
            cycles = cycles + 1;
        end
        cyc0 = cycles;
        blk0 = blocks_done;
        bsnap = st_bytes;
        rsnap = st_reqs;

        repeat (TARGET) begin
            @(negedge clk);
            cycles = cycles + 1;
        end

        dblk = blocks_done - blk0;
        dcyc = cycles - cyc0;
        if (dcyc < 1) dcyc = 1;

        cpb      = dcyc * 1.0 / dblk;
        cpb_eng  = cpb * NENG;
        // sum the per-stack deltas: a direct 512-bit vector -> real conversion
        // is not something to trust across simulators, 64 bits at a time is
        total = 0.0;
        for (n = 0; n < NSTACK; n = n + 1)
            total = total + (st_bytes[n*64 +: 64] - bsnap[n*64 +: 64]);
        bpc      = total / dcyc;
        gbs      = bpc * CLOCK / 1e9;
        hashes   = dblk * 1.0 * CLOCK / dcyc / BPH;
        dreq     = req_served - sum_reqs(rsnap);
        if (dreq < 0) dreq = 0;
        reqport  = dreq * 1.0 / dcyc;
        bwtotal  = BW * 1.0 * NSTACK;

        $display("== mpipe: %0d engines x %0d contexts = %0d hashes in flight, CYC_BLOCK=%0d, %0d req lanes, %0d resp lanes",
                 NENG, KCTX, NCTX, CYC_BLOCK, NPORT, NRESP);
        $display("   %0d HBM3e stacks @ %0d B/cycle = %0d B/cycle aggregate, LAT=%0d, EFF=%0d%%",
                 NSTACK, BW, BW*NSTACK, LAT, EFF);
        $display("   steady state: %0d blocks in %0d cycles (%.3f cycles/block, %.1f per engine)",
                 dblk, dcyc, cpb, cpb_eng);
        $display("   memory: %0d requests, %0d bytes -> %.1f B/cycle (%.0f GB/s) of %0d (%.0f%% used)",
                 dreq, total, bpc, gbs, BW*NSTACK, 100.0 * bpc / bwtotal);
        $display("   request lanes: %.3f requests/cycle (%.0f lane(s) => max %.0f)",
                 reqport, NPORT, NPORT*1.0);
        $write("   per-stack B/cycle:");
        for (n = 0; n < NSTACK; n = n + 1)
            $write(" %.1f", (st_bytes[n*64 +: 64] - bsnap[n*64 +: 64]) * 1.0 / dcyc);
        $write("\n");
        $write("   per-stack share %%:");
        for (n = 0; n < NSTACK; n = n + 1) begin
            share = (st_bytes[n*64 +: 64] - bsnap[n*64 +: 64]) * 100.0 / total;
            $write(" %.2f", share);
        end
        $write("\n");
        // Analytic ceilings for this CYC_BLOCK
        $display("   analytic: %.2f blocks/cycle to fill %0d B/cycle at 3584 B/block, i.e. %.0f engines at %0d cycles/block",
                 bwtotal / 3584.0, BW*NSTACK, bwtotal / 3584.0 * CYC_BLOCK, CYC_BLOCK);
        $display("   throughput: %.0f blocks/s -> %.0f hashes/s at 1 GHz, collisions=%0d overflow=%0d",
                 dblk * 1.0 * CLOCK / dcyc, hashes, collisions, overflow);

        // one machine-readable line for the sweep collector
        $write("MPIPE NENG=%0d KCTX=%0d CYC=%0d NSTACK=%0d EFF=%0d BW=%0d NPORT=%0d NRESP=%0d ",
               NENG, KCTX, CYC_BLOCK, NSTACK, EFF, BW, NPORT, NRESP);
        $display("dblk=%0d dcyc=%0d cpb=%.3f cpb_eng=%.1f bpc=%.2f gbs=%.1f hashes=%.1f reqport=%.3f coll=%0d ovfl=%0d",
                 dblk, dcyc, cpb, cpb_eng, bpc, gbs, hashes, reqport, collisions, overflow);
        $finish;
    end

    // sum of a packed per-stack request counter snapshot
    function [63:0] sum_reqs;
        input [8*64-1:0] v;
        integer i;
        begin
            sum_reqs = 64'd0;
            for (i = 0; i < NSTACK; i = i + 1) sum_reqs = sum_reqs + v[i*64 +: 64];
        end
    endfunction
endmodule
