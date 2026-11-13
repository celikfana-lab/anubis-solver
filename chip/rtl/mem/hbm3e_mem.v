// hbm3e_mem.v — eight HBM3e stacks behind NPORT routed request lanes and
// NRESP merged response lanes.
//
// HBM3e is 9.6 Gb/s/pin on a 1024-bit bus: 9.6e9 * 1024 / 8 = 1228.8 GB/s per
// stack. At a 1 GHz core clock that is 1228.8 B/cycle, so BW=1228 here (0.07%
// conservative, i.e. every number in this file and its testbench is a floor,
// never a rounding-up). Eight stacks => 8 * 1228 = 9824 B/cycle = 9.824 TB/s
// aggregate at 1 GHz.
//
// The per-stack link is NOT re-derived: this is eight instances of the
// verified hbm3_model.v (byte-credit admission + the LAT-deep response
// pipeline), parameterised to HBM3e. That is the point of the wrapper.
//
// Routing: a request carries the Argon2 block index blk (0..19455) and
// stack = blk % NSTACK, evaluated per lane. A lane's req_ready is the ready of
// the stack it selected (and 0 if it lost that stack's same-cycle lane
// arbitration), never the ready of an unrelated stack.
//
// One transaction per cycle each way is only ~3.5 TB/s, which is why the ports
// are vectorised. NPORT request lanes can each name their own stack, so up to
// NPORT different stacks can accept in the same cycle; when two lanes pick the
// SAME stack, a round-robin per stack picks one and the other sees ready=0.
// Responses are id-tagged, so they need no lane address: they are queued and
// handed out on NRESP lanes. Simultaneous responses from different stacks are
// therefore absorbed rather than lost (see resp_collision / resp_overflow).
// NRESP=1 with NPORT>1 is legal and simply throttles the request lanes to the
// response drain rate, which is the honest way to measure a single response
// port.

`timescale 1ns/1ps
module hbm3e_mem #(
    parameter integer NSTACK = 8,     // HBM3e stacks
    parameter integer BW     = 1228,  // HBM3e: 1228.8 B/cycle at 1 GHz -> 1228
    parameter integer LAT    = 350,   // ~350 ns at 1 GHz
    parameter integer EFF    = 100,   // link efficiency, %, passed through
    parameter integer IDW    = 6,     // context id width
    parameter integer BLKW   = 32,    // block-index width
    parameter integer NPORT  = 1,     // independent request lanes
    parameter integer NRESP  = 1      // response lanes (id-tagged)
) (
    input  wire            clk,
    input  wire            rst_n,
    // NPORT routed request lanes: blk selects the stack, ready is that stack's
    input  wire [NPORT-1:0]       req_valid,
    input  wire [NPORT*BLKW-1:0]  req_blk,
    input  wire [NPORT*16-1:0]    req_bytes,
    input  wire [NPORT*IDW-1:0]   req_id,
    output wire [NPORT-1:0]       req_ready,
    // NRESP merged response lanes: id preserved
    output reg  [NRESP-1:0]       resp_valid,
    output reg  [NRESP*IDW-1:0]   resp_id,
    // observable load balance: aggregate plus per-stack counters
    output wire [63:0]           bytes_served,
    output wire [63:0]           req_served,
    output wire [NSTACK*64-1:0]  st_bytes_served,
    output wire [NSTACK*64-1:0]  st_req_served,
    // cycles on which more than one stack answered at once (absorbed by the
    // queue, so this is simultaneity, not loss)
    output wire [31:0]           resp_collision,
    // responses that had to be dropped because the queue was full (must be 0)
    output wire [31:0]           resp_overflow
);

    // ---- per-lane routing -------------------------------------------------
    wire [NPORT*BLKW-1:0] lane_sel;
    genvar gl;
    generate
        for (gl = 0; gl < NPORT; gl = gl + 1) begin : g_lane_sel
            assign lane_sel[gl*BLKW +: BLKW] = req_blk[gl*BLKW +: BLKW] % NSTACK;
        end
    endgenerate

    wire [NSTACK-1:0]     st_req_ready;
    wire [NSTACK-1:0]     st_resp_valid;
    wire [NSTACK*IDW-1:0] st_resp_id;
    wire [NSTACK*64-1:0]  st_bytes;
    wire [NSTACK*64-1:0]  st_reqs;

    // ---- one request per stack per cycle, picked from the lanes -----------
    reg [NSTACK-1:0]      s_valid;
    reg [NSTACK*16-1:0]   s_bytes;
    reg [NSTACK*BLKW-1:0] s_blk;
    reg [NSTACK*IDW-1:0]  s_id;
    reg [NSTACK*32-1:0]   s_lane;      // winning lane per stack
    reg [NSTACK*32-1:0]   lrr;         // per-stack lane round-robin pointer
    reg [NPORT-1:0]       lane_ready;

    integer kk, ll, cand;
    reg found;
    always @(*) begin
        s_valid = {NSTACK{1'b0}};
        s_bytes = {(NSTACK*16){1'b0}};
        s_blk   = {(NSTACK*BLKW){1'b0}};
        s_id    = {(NSTACK*IDW){1'b0}};
        s_lane  = {(NSTACK*32){1'b0}};
        for (kk = 0; kk < NSTACK; kk = kk + 1) begin
            found = 1'b0;
            for (ll = 0; ll < NPORT; ll = ll + 1) begin
                cand = (lrr[kk*32 +: 32] + ll) % NPORT;
                if (!found && req_valid[cand] && (lane_sel[cand*BLKW +: BLKW] == kk)) begin
                    found = 1'b1;
                    s_valid[kk] = 1'b1;
                    s_bytes[kk*16 +: 16]   = req_bytes[cand*16 +: 16];
                    s_blk[kk*BLKW +: BLKW] = req_blk[cand*BLKW +: BLKW];
                    s_id[kk*IDW +: IDW]    = req_id[cand*IDW +: IDW];
                    s_lane[kk*32 +: 32]    = cand;
                end
            end
        end
        // ready: selected stack's ready, only for the lane that won it, and
        // only while the response queue has room for a burst and the new
        // accepts (otherwise requests would run ahead of the drain and the
        // queue would drop id-tagged responses, hanging their contexts).
        // ready must NOT depend on req_valid: a master is allowed to wait for
        // ready before asserting valid, and gating it on valid deadlocks such a
        // master (the capacity testbench does exactly that). A spurious high
        // ready while valid is low is harmless.
        for (ll = 0; ll < NPORT; ll = ll + 1)
            lane_ready[ll] = (s_lane[lane_sel[ll*BLKW +: BLKW]*32 +: 32] == ll)
                          && st_req_ready[lane_sel[ll*BLKW +: BLKW]];
    end

    assign req_ready = lane_ready;

    // The per-stack lane round-robin pointer must be initialised: it was left
    // unreset, so `cand` was X, `s_valid` was X and no stack ever accepted - the
    // request lanes reported ready while serving zero bytes.
    always @(posedge clk) begin
        if (!rst_n) lrr <= {(NSTACK*32){1'b0}};
        else
            for (kk = 0; kk < NSTACK; kk = kk + 1)
                if (s_valid[kk])
                    lrr[kk*32 +: 32] <= (s_lane[kk*32 +: 32] + 32'd1) % NPORT;
    end

    genvar gs;
    generate
        for (gs = 0; gs < NSTACK; gs = gs + 1) begin : g_stack
            hbm3_model #(.BW(BW), .LAT(LAT), .EFF(EFF), .IDW(IDW)) u_stack (
                .clk(clk), .rst_n(rst_n),
                .req_valid(s_valid[gs]),
                .req_bytes(s_bytes[gs*16 +: 16]),
                .req_id(s_id[gs*IDW +: IDW]),
                .req_ready(st_req_ready[gs]),
                .resp_valid(st_resp_valid[gs]),
                .resp_id(st_resp_id[gs*IDW +: IDW]),
                .bytes_served(st_bytes[gs*64 +: 64]),
                .req_served(st_reqs[gs*64 +: 64]));
        end
    endgenerate

    // ---- response merge ----------------------------------------------------
    // At most one response per stack per cycle, so at most NSTACK can land in
    // the same cycle. Compact those onto the NRESP lanes: with NRESP >= NSTACK
    // nothing can ever be lost, which is why this needs no queue (an earlier
    // version had a 32-deep FIFO and a ready/valid handshake that deadlocked
    // and returned nothing at all). With NRESP < NSTACK the excess is counted
    // in resp_overflow rather than dropped silently.
    reg [NRESP-1:0]     rd_valid;
    reg [NRESP*IDW-1:0] rd_ids;
    reg [31:0]          n_sim;      // simultaneous stack responses this cycle
    integer fi, rj;
    always @(*) begin
        rd_valid = {NRESP{1'b0}};
        rd_ids   = {(NRESP*IDW){1'b0}};
        n_sim    = 32'd0;
        for (fi = 0; fi < NSTACK; fi = fi + 1)
            if (st_resp_valid[fi]) begin
                if (n_sim < NRESP) begin
                    rd_valid[n_sim] = 1'b1;
                    rd_ids[n_sim*IDW +: IDW] = st_resp_id[fi*IDW +: IDW];
                end
                n_sim = n_sim + 32'd1;
            end
    end

    reg [31:0] coll, ovfl;
    always @(posedge clk) begin
        if (!rst_n) begin
            resp_valid <= {NRESP{1'b0}};
            resp_id    <= {(NRESP*IDW){1'b0}};
            coll       <= 32'd0;
            ovfl       <= 32'd0;
        end else begin
            resp_valid <= rd_valid;
            resp_id    <= rd_ids;
            if (n_sim > 32'd1)    coll <= coll + 32'd1;
            if (n_sim > NRESP)    ovfl <= ovfl + 32'd1;
        end
    end

    assign resp_collision = coll;
    assign resp_overflow  = ovfl;

    // ---- bookkeeping ------------------------------------------------------
    function [63:0] sum64;
        input [NSTACK*64-1:0] v;
        integer i;
        begin
            sum64 = 64'd0;
            for (i = 0; i < NSTACK; i = i + 1) sum64 = sum64 + v[i*64 +: 64];
        end
    endfunction

    assign bytes_served    = sum64(st_bytes);
    assign req_served      = sum64(st_reqs);
    assign st_bytes_served = st_bytes;
    assign st_req_served   = st_reqs;
endmodule
