// anubis_argon2_card.v — the 365-engine Argon2id card, as one Verilog top.
// Built with DeepSeek V4.1 Flash running DeepSeek Harness (DSH).
// See ../../../LICENSE (MIT + attribution) and ../../../ATTRIBUTION.md.
//
// The scaling study (`SPEED.md`, `beyond/README.md`) says the design point is:
//
//   8 HBM3e stacks   9,824 B/cycle = 9.82 TB/s at 1 GHz
//   3 request lanes  9,824 / 3,584 B per block = 2.74 requests per cycle needed
//   365 engines      x 133 cycles per block = 2.74 blocks/cycle, i.e. the
//                    datapath and the link are both exactly saturated
//   3 contexts each  so a block costs the datapath's 133 cycles and not the
//                    350-cycle latency floor of a single context
//
// This module is that design as RTL: the engine array, the memory subsystem,
// the PCIe BAR0 register block and the console log, wired together. Nothing in
// here is a new algorithm — every block it instantiates is separately verified.
//
// What is real and what is not, because this matters for reading the numbers:
//
//   * `hbm3e_mem` is the verified eight-stack subsystem: 1,228 B/cycle per
//     stack, `blk % 8` routing, per-lane ready, id-tagged responses.
//   * `axil_regs` and `uart_log` are the verified PCIe/UART blocks.
//   * the engine array is `argon2_mpipe`, which models the datapath as a
//     CYC_BLOCK counter rather than instantiating 365 copies of `argon2_fill`.
//     The counter is the measured cost of the real unit (5,165,657 cycles per
//     real m=19456 t=2 hash = 132.76 cycles per block, checked against
//     argon2-cffi by `tb_argon2_engine`), so this top proves the wiring and the
//     cycle budget at 365 engines, not 365 paralleled permutations. 365 copies
//     of the real datapath is ~68 M generic cells and cannot be simulated.
//
// So: this is the machine, not a substitute for the arithmetic in it.

`timescale 1ns/1ps
module anubis_argon2_card #(
    parameter integer NENG      = 365,
    parameter integer KCTX      = 3,
    parameter integer NSTACK    = 8,
    parameter integer NPORT     = 3,
    parameter integer BW        = 1228,      // HBM3e bytes/cycle per stack
    parameter integer LAT       = 350,       // HBM3e latency, cycles
    parameter integer EFF       = 100,       // link efficiency, %
    parameter integer CYC_BLOCK = 133,       // measured argon2_fill cost
    parameter integer BPH       = 38912,     // blocks per hash, m=19456 t=2
    parameter integer SEG       = 19456,     // blocks in pass 0
    parameter integer CLK_HZ    = 1_000_000_000,
    parameter integer BAUD      = 115_200
) (
    input  wire        clk,
    input  wire        rst_n,

    // AXI4-Lite slave: PCIe BAR0 (the PHY/TLP layer is vendor hard IP)
    input  wire [31:0] s_axil_awaddr,
    input  wire        s_axil_awvalid,
    output wire        s_axil_awready,
    input  wire [31:0] s_axil_wdata,
    input  wire [3:0]  s_axil_wstrb,
    input  wire        s_axil_wvalid,
    output wire        s_axil_wready,
    output wire [1:0]  s_axil_bresp,
    output wire        s_axil_bvalid,
    input  wire        s_axil_bready,
    input  wire [31:0] s_axil_araddr,
    input  wire        s_axil_arvalid,
    output wire        s_axil_arready,
    output wire [31:0] s_axil_rdata,
    output wire [1:0]  s_axil_rresp,
    output wire        s_axil_rvalid,
    input  wire        s_axil_rready,

    // console
    output wire        uart_tx,

    // observability (what a host-side throughput counter would read)
    output wire [31:0] blocks_done,
    output wire [63:0] bytes_served,
    output wire [63:0] requests_served,
    output wire        busy,
    output wire        done,
    output wire [31:0] memory_collisions,
    output wire [31:0] memory_overflow
);
    localparam integer NCTX = NENG * KCTX;
    localparam integer IDW  = (NCTX < 2) ? 1 : $clog2(NCTX);
    localparam integer NRESP = NPORT;

    // ---- BAR0 -------------------------------------------------------------
    wire        start_pulse;
    wire [63:0] nonce;

    // ---- engine array <-> memory -----------------------------------------
    wire [NPORT-1:0]     req_valid, req_ready;
    wire [NPORT*16-1:0]  req_bytes;
    wire [NPORT*32-1:0]  req_blk;
    wire [NPORT*IDW-1:0] req_id;
    wire [NRESP-1:0]     resp_valid;
    wire [NRESP*IDW-1:0] resp_id;

    wire [NSTACK*64-1:0] st_bytes, st_reqs;

    argon2_mpipe #(.NENG(NENG), .KCTX(KCTX), .CYC_BLOCK(CYC_BLOCK),
                   .BPH(BPH), .SEG(SEG), .IDW(IDW),
                   .NPORT(NPORT), .NRESP(NRESP)) engines (
        .clk(clk), .rst_n(rst_n), .start(start_pulse),
        .blocks_done(blocks_done),
        .mem_req_valid(req_valid), .mem_req_bytes(req_bytes),
        .mem_req_blk(req_blk), .mem_req_id(req_id),
        .mem_req_ready(req_ready),
        .mem_resp_valid(resp_valid), .mem_resp_id(resp_id));

    hbm3e_mem #(.NSTACK(NSTACK), .BW(BW), .LAT(LAT), .EFF(EFF), .IDW(IDW),
                .NPORT(NPORT), .NRESP(NRESP)) memory (
        .clk(clk), .rst_n(rst_n),
        .req_valid(req_valid), .req_blk(req_blk), .req_bytes(req_bytes),
        .req_id(req_id), .req_ready(req_ready),
        .resp_valid(resp_valid), .resp_id(resp_id),
        .bytes_served(bytes_served), .req_served(requests_served),
        .st_bytes_served(st_bytes), .st_req_served(st_reqs),
        .resp_collision(memory_collisions), .resp_overflow(memory_overflow));

    // ---- status -----------------------------------------------------------
    // A hash is 38,912 blocks of work, so "done" means that much block work has
    // been retired. There is no digest here: the PoW comparison lives in
    // argon2_engine, which is verified end to end on its own.
    reg started;
    always @(posedge clk) begin
        if (!rst_n)      started <= 1'b0;
        else if (start_pulse) started <= 1'b1;
    end
    assign done = started && (blocks_done >= BPH);
    assign busy = started && !done;

    // ---- BAR0 + console ---------------------------------------------------
    axil_regs bar0 (
        .clk(clk), .rst_n(rst_n),
        .s_axil_awaddr(s_axil_awaddr), .s_axil_awvalid(s_axil_awvalid),
        .s_axil_awready(s_axil_awready),
        .s_axil_wdata(s_axil_wdata), .s_axil_wstrb(s_axil_wstrb),
        .s_axil_wvalid(s_axil_wvalid), .s_axil_wready(s_axil_wready),
        .s_axil_bresp(s_axil_bresp), .s_axil_bvalid(s_axil_bvalid),
        .s_axil_bready(s_axil_bready),
        .s_axil_araddr(s_axil_araddr), .s_axil_arvalid(s_axil_arvalid),
        .s_axil_arready(s_axil_arready),
        .s_axil_rdata(s_axil_rdata), .s_axil_rresp(s_axil_rresp),
        .s_axil_rvalid(s_axil_rvalid), .s_axil_rready(s_axil_rready),
        .start_pulse(start_pulse), .algo(), .nonce(nonce),
        .challenge_len(), .challenge_we(), .challenge_addr(),
        .challenge_wdata(),
        .busy(busy), .done(done), .hit(1'b0), .lz(8'd0), .tag(256'd0));

    uart_log #(.CLK_HZ(CLK_HZ), .BAUD(BAUD)) console (
        .clk(clk), .rst_n(rst_n),
        .ev_start(start_pulse), .ev_hit(1'b0), .nonce(nonce), .lz(8'd0),
        .tx(uart_tx));
endmodule
