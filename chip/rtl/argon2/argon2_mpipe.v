// argon2_mpipe.v — the memory architecture of a scaled-up engine, cycle by cycle.
//
// NENG engines, each carrying KCTX hashes, all sharing one memory link. The
// fill_block work is a fixed CYC_BLOCK counter here: the question this model
// answers is whether the memory system keeps the engines busy, which is what
// decides the hashes/s of any engine count and clock.
//
// Per context, one block of work looks like:
//   REQ   ask the link for the next block (3072 B on pass 0, 4096 B on pass 1)
//   CMP   spend CYC_BLOCK/2 engine cycles on the block already in hand
//   WAIT  by now the prefetched block should have landed
// so the prefetch overlaps the compute of the current block - that is what
// makes 2 contexts per engine enough to hide ~350 ns of HBM latency.
//
// The compute unit is shared by the engine's contexts round-robin: two
// contexts each progress at half clock rate, which is exactly one block per
// CYC_BLOCK engine cycles in aggregate.

`timescale 1ns/1ps
module argon2_mpipe #(
    parameter integer NENG      = 24,
    parameter integer KCTX      = 2,
    parameter integer CYC_BLOCK = 260,
    parameter integer BPH       = 38912,   // blocks per hash, m=19456 t=2
    parameter integer SEG       = 19456,   // blocks in pass 0
    parameter integer IDW       = 6
) (
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,
    output reg  [31:0]   blocks_done,
    // shared memory link
    output wire          mem_req_valid,
    output wire [15:0]   mem_req_bytes,
    output wire [IDW-1:0] mem_req_id,
    input  wire          mem_req_ready,
    input  wire          mem_resp_valid,
    input  wire [IDW-1:0] mem_resp_id
);
    localparam integer NCTX = NENG * KCTX;

    localparam [2:0] S_IDLE = 3'd0, S_REQ0 = 3'd1, S_WAIT0 = 3'd2,
                     S_REQ  = 3'd3, S_CMP  = 3'd4, S_WAIT  = 3'd5;

    reg [2:0]        st  [0:NCTX-1];
    reg [31:0]       blk [0:NCTX-1];
    reg [31:0]       nxt [0:NCTX-1];
    reg [15:0]       cyc [0:NCTX-1];
    reg              got [0:NCTX-1];      // response landed while computing
    reg [IDW-1:0]    cur;                 // rotating request arbiter
    reg              rr  [0:NENG-1];      // compute round-robin per engine
    reg [NCTX-1:0]   cgrant;              // compute grant, one per engine max

    integer c, e, i, idx;
    reg [IDW-1:0] cid;

    // ---- request side: rotating round-robin, skipping idle contexts --------
    // Granting only to the context under `cur` costs up to NCTX cycles of
    // waiting per block; scanning the ring from `cur` for the first context
    // that wants the link removes that without a full crossbar.
    reg [IDW-1:0] gsel;
    always @(*) begin
        gsel = cur;
        for (i = NCTX - 1; i >= 0; i = i - 1) begin
            idx = cur + i;
            if (idx >= NCTX) idx = idx - NCTX;
            if ((st[idx] == S_REQ0) || (st[idx] == S_REQ)) gsel = idx[IDW-1:0];
        end
    end
    wire any_wants = (st[gsel] == S_REQ0) || (st[gsel] == S_REQ);
    assign mem_req_valid = any_wants;
    assign mem_req_id    = gsel;
    assign mem_req_bytes = (st[gsel] == S_REQ0) ? 16'd3072
                         : (nxt[gsel] < SEG)    ? 16'd3072 : 16'd4096;
    wire req_go = mem_req_valid && mem_req_ready;

    // ---- compute side: one grant per engine, round-robin -------------------
    always @(*) begin
        cgrant = {NCTX{1'b0}};
        for (e = 0; e < NENG; e = e + 1) begin
            cid = KCTX * e + rr[e];
            if (st[cid] == S_CMP) cgrant[cid] = 1'b1;
            else if (KCTX > 1) begin
                cid = KCTX * e + (KCTX - 1 - rr[e]);
                if (st[cid] == S_CMP) cgrant[cid] = 1'b1;
            end
        end
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            blocks_done <= 32'd0;
            cur <= {IDW{1'b0}};
            for (c = 0; c < NCTX; c = c + 1) begin
                st[c] <= S_IDLE; blk[c] <= 32'd0; nxt[c] <= 32'd0; cyc[c] <= 16'd0;
                got[c] <= 1'b0;
            end
            for (e = 0; e < NENG; e = e + 1) rr[e] <= 1'b0;
        end else begin
            // advance past whoever just won. Advancing while idle as well
            // de-synchronised the ring from the demand pattern and cost up to
            // 38% at some engine counts, so the pointer only moves on a grant.
            if (req_go) cur <= (gsel + 1 == NCTX) ? {IDW{1'b0}} : gsel + 1;

            for (e = 0; e < NENG; e = e + 1)
                if (|cgrant[KCTX*e +: KCTX]) rr[e] <= ~rr[e];

            for (c = 0; c < NCTX; c = c + 1)
                if (mem_resp_valid && (mem_resp_id == c)) got[c] <= 1'b1;

            for (c = 0; c < NCTX; c = c + 1) begin
                case (st[c])
                    S_IDLE: if (start) begin
                        // Start each context at a different block so the window
                        // spans both passes: pass 0 moves 3072 B per block and
                        // pass 1 moves 4096 B, and starting everybody at block 0
                        // measured only the cheap half.
                        st[c]  <= S_REQ0;
                        nxt[c] <= c * (BPH / NCTX);
                        blk[c] <= 32'd0;
                    end
                    S_REQ0: if (req_go && (gsel == c)) st[c] <= S_WAIT0;
                    S_WAIT0: if (got[c]) begin
                        got[c] <= 1'b0;
                        blk[c] <= nxt[c];
                        nxt[c] <= (nxt[c] + 32'd1 == BPH) ? 32'd0 : nxt[c] + 32'd1;
                        st[c]  <= S_REQ;
                    end
                    S_REQ: if (req_go && (gsel == c)) begin
                        cyc[c] <= CYC_BLOCK;
                        got[c] <= 1'b0;
                        st[c]  <= S_CMP;
                    end
                    S_CMP: if (cgrant[c]) begin
                        if (cyc[c] <= 16'd1) st[c] <= S_WAIT;
                        else cyc[c] <= cyc[c] - 16'd1;
                    end
                    S_WAIT: if (got[c]) begin
                        got[c] <= 1'b0;
                        blk[c] <= nxt[c];
                        nxt[c] <= (nxt[c] + 32'd1 == BPH) ? 32'd0 : nxt[c] + 32'd1;
                        blocks_done <= blocks_done + 32'd1;
                        st[c] <= S_REQ;
                    end
                    default: st[c] <= S_IDLE;
                endcase
            end
        end
    end
endmodule
