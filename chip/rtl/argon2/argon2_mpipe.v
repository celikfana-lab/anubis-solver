// argon2_mpipe.v — the memory architecture of a scaled-up engine, cycle by cycle.
//
// NENG engines, each carrying KCTX hashes, all sharing the memory. The
// fill_block work is a fixed CYC_BLOCK counter here: the question this model
// answers is whether the memory system keeps the engines busy, which is what
// decides the hashes/s of any engine count and clock.
//
// Per context, one block of work looks like:
//   REQ   ask the link for the next block (3072 B on pass 0, 4096 B on pass 1)
//   CMP   spend CYC_BLOCK/2 engine cycles on the block already in hand
//   WAIT  by now the prefetched block should have landed
// so the prefetch overlaps the compute of the current block - that is what
// hides HBM latency behind work instead of stalling on it.
//
// The compute unit is shared by the engine's contexts round-robin. The grant
// scans the KCTX contexts from rr[e] and grants the first one in CMP, one grant
// per engine per cycle; rr[e] advances on every grant. (The original 2-way
// `rr`/`KCTX-1-rr` arbiter was a 2-context special case and silently
// under-granted for KCTX > 2, which made 3 contexts look no better than 2.)
//
// Contexts are the cheap way to hide latency: with one outstanding block per
// context, one block costs max(CYC_BLOCK, LAT/KCTX) engine cycles, so KCTX=2
// floors at LAT/2 and KCTX=3 can reach CYC_BLOCK.
//
// Request lanes: one request per cycle is only ~3.5 TB/s, so the link can be
// split into NPORT lanes. Context c belongs to engine c/KCTX and lane
// (c/KCTX) % NPORT; each lane has its own rotating engine pointer and its own
// valid/bytes/blk/id/ready. Responses stay id-tagged (the id already names the
// context), so they need no lane address: NRESP response lanes can land in the
// same cycle when the memory side is widened to match. NRESP=1 is enough only
// if one block per cycle is all the memory can return.

`timescale 1ns/1ps
module argon2_mpipe #(
    parameter integer NENG      = 24,
    parameter integer KCTX      = 2,
    parameter integer CYC_BLOCK = 260,
    parameter integer BPH       = 38912,   // blocks per hash, m=19456 t=2
    parameter integer SEG       = 19456,   // blocks in pass 0
    parameter integer IDW       = 6,
    parameter integer NPORT     = 1,       // request lanes
    parameter integer NRESP     = 1        // response lanes (id-tagged)
) (
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,
    output reg  [31:0]   blocks_done,
    // shared memory link: NPORT independent request lanes
    output wire [NPORT-1:0]     mem_req_valid,
    output wire [NPORT*16-1:0]  mem_req_bytes,
    output wire [NPORT*32-1:0]  mem_req_blk,
    output wire [NPORT*IDW-1:0] mem_req_id,
    input  wire [NPORT-1:0]     mem_req_ready,
    // responses: id-tagged, no lane address needed
    input  wire [NRESP-1:0]     mem_resp_valid,
    input  wire [NRESP*IDW-1:0] mem_resp_id
);
    localparam integer NCTX = NENG * KCTX;

    localparam [2:0] S_IDLE = 3'd0, S_REQ0 = 3'd1, S_WAIT0 = 3'd2,
                     S_REQ  = 3'd3, S_CMP  = 3'd4, S_WAIT  = 3'd5;

    reg [2:0]        st  [0:NCTX-1];
    reg [31:0]       blk [0:NCTX-1];
    reg [31:0]       nxt [0:NCTX-1];
    reg [15:0]       cyc [0:NCTX-1];
    reg              got [0:NCTX-1];      // response landed while computing
    reg [NPORT*32-1:0] cur;               // per-lane rotating engine pointer
    integer          rr  [0:NENG-1];      // compute round-robin per engine
    reg [NCTX-1:0]   cgrant;              // compute grant, one per engine max

    integer c, ce, ck, r, si, sk, sidx, gi, gk, gidx, p, cp;
    reg [IDW-1:0] cid;

    // ---- request side: one rotated engine scan per lane --------------------
    // Each lane owns the engines whose index is congruent to it mod NPORT, so
    // the lanes are independent: a lane only ever waits on its own engines.
    // Granting only to the context under a rotating pointer costs a full ring
    // traversal per request; scanning from cur[p] for the first wanting
    // context of the first wanting eligible engine removes that.
    reg [NPORT*IDW-1:0] gsel;
    reg [NPORT-1:0]     wants;
    reg [31:0]          eng;
    reg                 found;
    always @(*) begin
        gsel  = {(NPORT*IDW){1'b0}};
        wants = {NPORT{1'b0}};
        for (p = 0; p < NPORT; p = p + 1) begin
            found = 1'b0;
            for (si = 0; si < NENG; si = si + 1) begin
                eng = cur[p*32 +: 32] + si;
                if (eng >= NENG) eng = eng - NENG;
                if (!found && ((eng % NPORT) == p)) begin
                    for (sk = 0; sk < KCTX; sk = sk + 1) begin
                        sidx = KCTX*eng + sk;
                        if (!found && ((st[sidx] == S_REQ0) || (st[sidx] == S_REQ))) begin
                            gsel[p*IDW +: IDW] = sidx[IDW-1:0];
                            wants[p]           = 1'b1;
                            found              = 1'b1;
                        end
                    end
                end
            end
        end
    end

    wire [NPORT-1:0] req_go = mem_req_valid & mem_req_ready;

    genvar gp;
    generate
        for (gp = 0; gp < NPORT; gp = gp + 1) begin : g_req_lane
            assign mem_req_valid[gp]         = wants[gp];
            assign mem_req_id[gp*IDW +: IDW] = gsel[gp*IDW +: IDW];
            assign mem_req_bytes[gp*16 +: 16] =
                  (st[gsel[gp*IDW +: IDW]] == S_REQ0) ? 16'd3072
                : (nxt[gsel[gp*IDW +: IDW]] < SEG)    ? 16'd3072 : 16'd4096;
            assign mem_req_blk[gp*32 +: 32]  = nxt[gsel[gp*IDW +: IDW]];
        end
    endgenerate

    // ---- compute side: one grant per engine, true K-way round-robin --------
    reg                 gfound;
    always @(*) begin
        cgrant = {NCTX{1'b0}};
        for (gi = 0; gi < NENG; gi = gi + 1) begin
            gfound = 1'b0;
            for (gk = 0; gk < KCTX; gk = gk + 1) begin
                gidx = KCTX*gi + ((rr[gi] + gk) % KCTX);
                if (!gfound && (st[gidx] == S_CMP)) begin
                    cgrant[gidx] = 1'b1;
                    gfound       = 1'b1;
                end
            end
        end
    end

    integer lanec;
    always @(posedge clk) begin
        if (!rst_n) begin
            blocks_done <= 32'd0;
            cur <= {(NPORT*32){1'b0}};
            for (c = 0; c < NCTX; c = c + 1) begin
                st[c] <= S_IDLE; blk[c] <= 32'd0; nxt[c] <= 32'd0; cyc[c] <= 16'd0;
                got[c] <= 1'b0;
            end
            for (ce = 0; ce < NENG; ce = ce + 1) rr[ce] <= 0;
        end else begin
            // a lane's pointer moves to just past the engine it just served
            for (cp = 0; cp < NPORT; cp = cp + 1)
                if (req_go[cp])
                    cur[cp*32 +: 32] <= ((gsel[cp*IDW +: IDW] / KCTX) + 1) % NENG;

            for (ce = 0; ce < NENG; ce = ce + 1)
                if (|cgrant[KCTX*ce +: KCTX]) rr[ce] <= (rr[ce] + 1) % KCTX;

            for (c = 0; c < NCTX; c = c + 1)
                for (r = 0; r < NRESP; r = r + 1)
                    if (mem_resp_valid[r] && (mem_resp_id[r*IDW +: IDW] == c))
                        got[c] <= 1'b1;

            for (ce = 0; ce < NENG; ce = ce + 1) begin
                lanec = ce % NPORT;
                for (ck = 0; ck < KCTX; ck = ck + 1) begin
                    c = KCTX*ce + ck;
                    case (st[c])
                        S_IDLE: if (start) begin
                            // Start each context at a different block so the
                            // window spans both passes: pass 0 moves 3072 B per
                            // block and pass 1 moves 4096 B, and starting
                            // everybody at block 0 measured only the cheap half.
                            st[c]  <= S_REQ0;
                            nxt[c] <= c * (BPH / NCTX);
                            blk[c] <= 32'd0;
                        end
                        S_REQ0: if (req_go[lanec] && (gsel[lanec*IDW +: IDW] == c))
                                    st[c] <= S_WAIT0;
                        S_WAIT0: if (got[c]) begin
                            got[c] <= 1'b0;
                            blk[c] <= nxt[c];
                            nxt[c] <= (nxt[c] + 32'd1 == BPH) ? 32'd0 : nxt[c] + 32'd1;
                            st[c]  <= S_REQ;
                        end
                        S_REQ: if (req_go[lanec] && (gsel[lanec*IDW +: IDW] == c)) begin
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
                            // NB: several contexts can finish on one edge, and
                            // nonblocking increments collapse into a single +1,
                            // so this counter under-reads above one block per
                            // cycle. Bytes are the trustworthy throughput number.
                            blocks_done <= blocks_done + 32'd1;
                            st[c] <= S_REQ;
                        end
                        default: st[c] <= S_IDLE;
                    endcase
                end
            end
        end
    end
endmodule
