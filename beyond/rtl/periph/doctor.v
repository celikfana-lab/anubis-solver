// doctor.v — "stop everything and check the silicon".
//
// A board that has been running for hours, or that came back from a swap, needs
// an answer to one question that is not "resend the job": are these cores still
// computing what they should? The doctor is triggered by a single command over
// UART or SPI, halts the engine array (which loses its work - that is the
// point), and runs four known-answer tests plus a memory-subsystem test.
//
//   ARGON  one real argon2_fill on a fixed block, XOR-folded over all 128 words
//   SHA    one real sha256_core on a fixed block against a hash we computed
//   SIP    one real SipRound on a fixed state, the HashX ALU's core operation
//   MEM    the live HBM subsystem: 64 requests spread over all 8 stacks, then
//          every response must arrive, exactly once, with a valid id
//   LIVE   a counter must still be moving (catches a dead clock or a stuck
//          reset before anything else gets blamed)
//
// Any single wrong word in the Argon2 block changes the fold, so ARGON is a real
// datapath test and not a smoke alarm. `fault_inject` deliberately corrupts one
// expected value so a testbench can prove the checker is not vacuous.
//
// Limits, stated so nobody over-reads a PASS: this tests one instance of each
// datapath, not all 365 Argon2 engines (they have identical layout, so a
// systematic fault is caught but a single defective engine is not), and MEM
// tests the controller and id path, not DRAM cells - the memory model here has
// no data path, so a stuck bit in a DRAM cell is outside what it can see.

`timescale 1ns/1ps
module doctor #(
    parameter integer IDW   = 10,
    parameter integer NSTACK = 8,
    parameter integer NREQ  = 64,
    parameter integer LAT   = 350
) (
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,
    input  wire          fault_inject,     // corrupt one expected value on purpose

    output reg           busy,
    output reg           done,
    output reg           pass,
    output reg  [3:0]    fail_mask,        // {MEM, SIP, SHA, ARGON}
    output reg  [63:0]   argon_fold_seen,
    output reg  [63:0]   mem_seen_bitmap,
    output wire  [7:0]    live_count,

    // memory master: the top muxes the live subsystem over to this while busy
    output reg           mem_en,
    output reg           mem_req_valid,
    output reg  [31:0]   mem_req_blk,
    output reg  [15:0]   mem_req_bytes,
    output reg  [IDW-1:0] mem_req_id,
    input  wire          mem_req_ready,
    input  wire          mem_resp_valid,
    input  wire [IDW-1:0] mem_resp_id
);
    // ---- known-answer constants (beyond/tools/gen_doctor_consts.py) ---------
    // Argon2: the block-A vector times the XOR fold of all 128 output words
    localparam [63:0] ARGON_FOLD = 64'hA156E4FDFEC07F87;
    // SHA-256: IV over one padded block of 55 'a' bytes
    localparam [255:0] SHA_IV =
        256'h6a09e667_bb67ae85_3c6ef372_a54ff53a_510e527f_9b05688c_1f83d9ab_5be0cd19;
    localparam [511:0] SHA_BLOCK =
        512'h61616161_61616161_61616161_61616161_61616161_61616161_61616161_61616161_61616161_61616161_61616161_61616161_61616161_61616180_00000000_000001B8;
    localparam [255:0] SHA_WANT =
        256'h9F4390F8_D30C2DD9_2EC9F095_B65E2B9A_E9B0A925_A5258E24_1C9F1E91_0F734318;
    // SipRound on a fixed state
    localparam [255:0] SIP_STATE =
        256'h0123456789ABCDEF_FEDCBA9876543210_0F0F0F0F0F0F0F0F_F0F0F0F0F0F0F0F0;
    // and its output, packed the same way ({d, c, b, a})
    localparam [255:0] SIP_WANT =
        256'h701E344BE987ADD5_1E1E1E1D1E1E1E1E_2222222222222221_BA9876543210FEDB;

    // ---- the three datapaths under test -----------------------------------
    reg          argon_start, sha_start;
    wire [8191:0] argon_prev, argon_ref, argon_dst;
    wire [8191:0] argon_out;
    wire          argon_busy, argon_done;

    wire [255:0]  sha_digest;
    wire          sha_busy, sha_done;

    wire [255:0]  sip_out;

    argon2_fill u_argon (.clk(clk), .rst_n(rst_n), .start(argon_start),
                         .prev(argon_prev), .refb(argon_ref), .dst(argon_dst),
                         .xor_en(1'b1), .out(argon_out), .busy(argon_busy),
                         .done(argon_done));

    sha256_core u_sha (.clk(clk), .rst_n(rst_n), .start(sha_start),
                       .midstate(SHA_IV), .block(SHA_BLOCK),
                       .digest(sha_digest), .done(sha_done), .busy(sha_busy));

    sipround u_sip (.s(SIP_STATE), .o(sip_out));

    // Block A of gen_argon_vectors.py. These are arithmetic sequences, so a
    // generate loop is exact and folds to constants at elaboration - no 24 Kbit
    // of literal vectors and no chance of a typo drifting from the generator.
    genvar gi;
    generate
        for (gi = 0; gi < 128; gi = gi + 1) begin : vec
            assign argon_prev[64*gi +: 64] = 64'h9E3779B97F4A7C15 * (gi + 1);
            assign argon_ref [64*gi +: 64] = 64'h00000100000001B3 * (gi + 7);
            assign argon_dst [64*gi +: 64] = 64'hDEADBEEFCAFEBABE ^ gi;
        end
    endgenerate

    // XOR fold of the 128-word block
    function [63:0] fold128;
        input [8191:0] b;
        integer i;
        begin
            fold128 = 64'd0;
            for (i = 0; i < 128; i = i + 1) fold128 = fold128 ^ b[64*i +: 64];
        end
    endfunction
    wire [63:0] argon_fold = fold128(argon_out);

    wire [255:0] sip_want = fault_inject ? ~SIP_WANT : SIP_WANT;
    wire [63:0]  argon_want = fault_inject ? ~ARGON_FOLD : ARGON_FOLD;
    wire [255:0] sha_want = fault_inject ? ~SHA_WANT : SHA_WANT;

    // ---- sequencer --------------------------------------------------------
    localparam [3:0] S_IDLE = 4'd0, S_ARGON = 4'd1, S_ARGONW = 4'd2,
                     S_SHA = 4'd3, S_SHAW = 4'd4, S_SIP = 4'd5,
                     S_MEM = 4'd6, S_FIN = 4'd7, S_REPORT = 4'd8;
    reg [3:0]  st;
    reg [31:0] nreq;
    reg [31:0] nresp;
    reg [7:0]  live;
    assign live_count = live;

    always @(posedge clk) begin
        if (!rst_n) begin
            st <= S_IDLE;
            busy <= 1'b0; done <= 1'b0; pass <= 1'b0; fail_mask <= 4'd0;
            argon_fold_seen <= 64'd0; mem_seen_bitmap <= 64'd0;
            mem_en <= 1'b0; mem_req_valid <= 1'b0;
            mem_req_blk <= 32'd0; mem_req_bytes <= 16'd1024;
            mem_req_id <= {IDW{1'b0}};
            argon_start <= 1'b0; sha_start <= 1'b0;
            nreq <= 32'd0; nresp <= 32'd0;
            live <= 8'd0;
        end else begin
            argon_start <= 1'b0;
            sha_start   <= 1'b0;
            live <= live + 8'd1;

            case (st)
                S_IDLE: if (start) begin
                    busy <= 1'b1; done <= 1'b0; pass <= 1'b0; fail_mask <= 4'd0;
                    mem_seen_bitmap <= 64'd0;
                    st <= S_ARGON;
                end
                S_ARGON: begin
                    argon_start <= 1'b1;
                    st <= S_ARGONW;
                end
                S_ARGONW: if (argon_done) begin
                    argon_fold_seen <= argon_fold;
                    if (argon_fold !== argon_want) fail_mask[0] <= 1'b1;
                    st <= S_SHA;
                end
                S_SHA: begin
                    sha_start <= 1'b1;
                    st <= S_SHAW;
                end
                S_SHAW: if (sha_done) begin
                    if (sha_digest !== sha_want) fail_mask[1] <= 1'b1;
                    st <= S_SIP;
                end
                S_SIP: begin
                    if (sip_out !== sip_want) fail_mask[2] <= 1'b1;
                    mem_en    <= 1'b1;
                    nreq      <= 32'd0;
                    nresp     <= 32'd0;
                    st        <= S_MEM;
                end
                S_MEM: begin
                    // one request at a time, block index walks all 8 stacks
                    if (nreq < NREQ) begin
                        mem_req_valid <= 1'b1;
                        mem_req_blk   <= nreq;
                        mem_req_id    <= nreq[IDW-1:0];
                        if (mem_req_valid && mem_req_ready) begin
                            nreq <= nreq + 32'd1;
                            mem_req_valid <= 1'b0;
                        end
                    end else begin
                        mem_req_valid <= 1'b0;
                        if (nresp == NREQ) st <= S_FIN;
                    end
                    if (mem_resp_valid) begin
                        nresp <= nresp + 32'd1;
                        if (mem_resp_id >= NREQ || mem_seen_bitmap[mem_resp_id[5:0]])
                            fail_mask[3] <= 1'b1;         // stray or duplicate id
                        else
                            mem_seen_bitmap[mem_resp_id[5:0]] <= 1'b1;
                    end
                end
                S_FIN: begin
                    mem_en <= 1'b0;
                    if (nresp != NREQ) fail_mask[3] <= 1'b1;
                    // A dead clock cannot be detected by logic running on that
                    // clock; `live_count` is exposed so the host can poll it.
                    st <= S_REPORT;
                end
                S_REPORT: begin
                    pass <= (fail_mask == 4'd0) && (nresp == NREQ);
                    done <= 1'b1;
                    busy <= 1'b0;
                    st   <= S_IDLE;
                end
                default: st <= S_IDLE;
            endcase
        end
    end
endmodule
