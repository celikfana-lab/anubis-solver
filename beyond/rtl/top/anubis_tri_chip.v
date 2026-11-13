// anubis_tri_chip.v — one die, three sub-chips, each as fast as its algorithm allows.
// Built with DeepSeek V4.1 Flash running DeepSeek Harness (DSH).
// See ../../../LICENSE (MIT + attribution) and ../../../ATTRIBUTION.md.
//
// The three Anubis families want three different machines, so this top does not
// try to share a datapath between them. It puts the right machine next to each
// other and shares only the host interface and the board:
//
//   A2I  argon2_mpipe(365) + hbm3e_mem(8)    memory-bound: 365 engines saturate
//                                            9.82 TB/s, measured 70,122 h/s
//   HX   hashx_pool(NHX)                     latency-bound serial VM: 533 cycles
//                                            per hash, so throughput is lanes
//   SHA  sha256_pool(NSHA)                   ALU-bound and tiny: 128 cycles per
//                                            hash per lane, ~8.5k cells each
//
// Why not one universal core: SHA-256's round is a wide combinational network
// (~12 micro-ops on a general ALU, i.e. 6x slower), HashX really is a sequence
// of register-register ops, and Argon2id is a 128x64-bit permutation gated by
// DRAM. Sharing the datapath would slow SHA-256 and save at most 67k cells
// against a 68.1M-cell Argon2 array.
//
// Sizes are parameters so the ratio is a die-budget decision, not a fixed 1:1:
// HX and SHA scales are independent of the Argon2 engine count.

`timescale 1ns/1ps
module anubis_tri_chip #(
    // ---- Argon2id sub-chip ------------------------------------------------
    parameter integer NENG      = 365,
    parameter integer KCTX      = 3,
    parameter integer NPORT     = 3,
    parameter integer NSTACK    = 8,
    parameter integer BW        = 1228,
    parameter integer LAT       = 350,
    parameter integer EFF       = 100,
    parameter integer CYC_BLOCK = 133,
    parameter integer BPH       = 38912,
    parameter integer SEG       = 19456,
    // ---- HashX sub-chip ---------------------------------------------------
    parameter integer NHX       = 128,
    parameter integer MAXI      = 512,
    // ---- SHA-256 sub-chip -------------------------------------------------
    parameter integer NSHA      = 128,
    parameter integer CHUNK     = 128,
    // ---- serial host interface + doctor ----------------------------------
    parameter integer SPI_LANES = 8,        // 1 SPI, 4 QSPI, 8 OSPI
    parameter integer CLK_HZ    = 1_000_000_000,
    parameter integer BAUD      = 115_200
) (
    input  wire         clk,
    input  wire         rst_n,

    // ---- Argon2id: start, progress ----------------------------------------
    input  wire         a2i_start,
    output wire [31:0]  a2i_blocks_done,
    output wire [63:0]  a2i_bytes_served,
    output wire         a2i_busy,

    // ---- HashX: program load, challenge, result ---------------------------
    input  wire         hx_prog_we,
    input  wire [8:0]   hx_prog_waddr,
    input  wire [127:0] hx_prog_wdata,
    input  wire         hx_start,
    input  wire [255:0] hx_keys,
    input  wire [31:0]  hx_ninstr,
    input  wire [7:0]   hx_difficulty,
    input  wire [63:0]  hx_nonce_base,
    input  wire [31:0]  hx_tries_per_lane,
    output wire         hx_hit,
    output wire [63:0]  hx_hit_nonce,
    output wire [255:0] hx_hit_tag,
    output wire [7:0]   hx_hit_lz,
    output wire         hx_busy,
    output wire [31:0]  hx_hashes_done,

    // ---- SHA-256: challenge, result ---------------------------------------
    input  wire         sha_start,
    input  wire [255:0] sha_midstate,
    input  wire [511:0] sha_block0,
    input  wire [511:0] sha_block1,
    input  wire [1:0]   sha_nblocks,
    input  wire [3:0]   sha_nonce_word,
    input  wire         sha_nonce_le,
    input  wire [5:0]   sha_difficulty,
    input  wire [31:0]  sha_nonce_base,
    output wire         sha_found,
    output wire [31:0]  sha_found_nonce,
    output wire [255:0] sha_found_digest,
    output wire         sha_busy,
    output wire [31:0]  sha_hashes_done,

    // ---- serial host interface: a Pi (SPI/QSPI) or an ESP32 (OSPI) --------
    input  wire         spi_sclk,
    input  wire         spi_cs_n,
    input  wire [7:0]   spi_io_in,
    output wire [7:0]   spi_io_out,
    output wire [7:0]   spi_io_oe,
    input  wire         uart_rx_pad,
    output wire         uart_tx_pad,

    // ---- doctor: one command byte (0x01) over either interface ------------
    input  wire         doc_start_ext,
    output wire         doc_busy,
    output wire         doc_done,
    output wire         doc_pass,
    output wire [3:0]   doc_fail_mask
);
    localparam integer NCTX = NENG * KCTX;
    localparam integer IDW  = (NCTX < 2) ? 1 : $clog2(NCTX);
    localparam integer NRESP = NPORT;

    // ======================= A2I: engines + eight HBM3e stacks =============
    wire [NPORT-1:0]     eng_req_valid, eng_req_ready;
    wire [NPORT-1:0]     mem_req_valid, mem_req_ready;
    wire [NPORT*16-1:0]  eng_req_bytes, mem_req_bytes;
    wire [NPORT*32-1:0]  eng_req_blk,   mem_req_blk;
    wire [NPORT*IDW-1:0] eng_req_id,    mem_req_id;
    wire [NRESP-1:0]     resp_valid;
    wire [NRESP*IDW-1:0] resp_id;
    wire                 doc_mem_en, doc_req_valid, doc_req_ready;
    wire [31:0]          doc_req_blk;
    wire [15:0]          doc_req_bytes;
    wire [IDW-1:0]       doc_req_id;
    wire [NSTACK*64-1:0] st_bytes, st_reqs;
    wire [63:0]          req_served;
    wire [31:0]          collisions, overflow;

    // "stop what you are doing" is a hard reset of the array: it loses its
    // work, which is the point of a doctor request
    wire a2i_rst_n = rst_n && !doc_mem_en;

    argon2_mpipe #(.NENG(NENG), .KCTX(KCTX), .CYC_BLOCK(CYC_BLOCK),
                   .BPH(BPH), .SEG(SEG), .IDW(IDW),
                   .NPORT(NPORT), .NRESP(NRESP)) a2i (
        .clk(clk), .rst_n(a2i_rst_n), .start(a2i_start),
        .blocks_done(a2i_blocks_done),
        .mem_req_valid(eng_req_valid), .mem_req_bytes(eng_req_bytes),
        .mem_req_blk(eng_req_blk), .mem_req_id(eng_req_id),
        .mem_req_ready(eng_req_ready),
        .mem_resp_valid(resp_valid), .mem_resp_id(resp_id));

    hbm3e_mem #(.NSTACK(NSTACK), .BW(BW), .LAT(LAT), .EFF(EFF), .IDW(IDW),
                .NPORT(NPORT), .NRESP(NRESP)) a2i_mem (
        .clk(clk), .rst_n(rst_n),
        .req_valid(mem_req_valid), .req_blk(mem_req_blk),
        .req_bytes(mem_req_bytes), .req_id(mem_req_id),
        .req_ready(mem_req_ready),
        .resp_valid(resp_valid), .resp_id(resp_id),
        .bytes_served(a2i_bytes_served), .req_served(req_served),
        .st_bytes_served(st_bytes), .st_req_served(st_reqs),
        .resp_collision(collisions), .resp_overflow(overflow));

    // a hash is BPH blocks of work, so the sub-chip is done once that much has
    // retired (there is no digest here; the PoW compare lives in argon2_engine)
    reg a2i_done_r;
    always @(posedge clk) begin
        if (!rst_n)                      a2i_done_r <= 1'b0;
        else if (a2i_start)              a2i_done_r <= 1'b0;
        else if (a2i_blocks_done >= BPH) a2i_done_r <= 1'b1;
    end
    assign a2i_busy = (a2i_blocks_done != 32'd0) && !a2i_done_r;

    // The doctor gets lane 0 of the live memory while it runs; the array is
    // held in reset, so nothing else can drive it.
    genvar gl;
    generate
        for (gl = 0; gl < NPORT; gl = gl + 1) begin : mem_mux
            wire sel = doc_mem_en && (gl == 0);
            assign mem_req_valid[gl]         = sel ? doc_req_valid : eng_req_valid[gl];
            assign mem_req_bytes[gl*16 +: 16] = sel ? doc_req_bytes
                                                    : eng_req_bytes[gl*16 +: 16];
            assign mem_req_blk[gl*32 +: 32]   = sel ? doc_req_blk
                                                    : eng_req_blk[gl*32 +: 32];
            assign mem_req_id[gl*IDW +: IDW]  = sel ? doc_req_id
                                                    : eng_req_id[gl*IDW +: IDW];
            assign eng_req_ready[gl] = mem_req_ready[gl];
        end
    endgenerate
    assign doc_req_ready = mem_req_ready[0];

    // ======================= serial host interface =========================
    wire        spi_rx_valid, spi_rx_ready, uart_rx_valid;
    wire [7:0]  spi_rx_byte, uart_rx_byte;
    wire [7:0]  status_byte = {doc_pass, doc_done, doc_busy, doc_fail_mask, 1'b0};

    wire [SPI_LANES-1:0] spi_do, spi_oe;

    spi_slave #(.LANES(SPI_LANES)) spi (
        .clk(clk), .rst_n(rst_n),
        .sclk(spi_sclk), .cs_n(spi_cs_n),
        .io_in(spi_io_in[SPI_LANES-1:0]),
        .io_out(spi_do), .io_oe(spi_oe),
        .rx_valid(spi_rx_valid), .rx_byte(spi_rx_byte),
        .tx_valid(1'b1), .tx_byte(status_byte), .tx_ready(spi_rx_ready),
        .frame_done());
    assign spi_io_out = {{(8-SPI_LANES){1'b0}}, spi_do};
    assign spi_io_oe  = {{(8-SPI_LANES){1'b0}}, spi_oe};

    uart_rx #(.CLK_HZ(CLK_HZ), .BAUD(BAUD)) serial_in (
        .clk(clk), .rst_n(rst_n), .rx(uart_rx_pad),
        .rx_valid(uart_rx_valid), .rx_byte(uart_rx_byte), .frame_err());
    // command out goes over SPI and the status pins; the UART log transmitter
    // lives in anubis_argon2_card, so this pad idles high
    assign uart_tx_pad = 1'b1;

    // ---- command decode: 0x01 = DOCTOR ------------------------------------
    wire cmd_doctor = doc_start_ext
                   || (spi_rx_valid  && (spi_rx_byte  == 8'h01))
                   || (uart_rx_valid && (uart_rx_byte == 8'h01));

    wire [63:0] doc_argon_fold, doc_mem_seen;
    wire [7:0]  doc_live;

    doctor #(.IDW(IDW), .NSTACK(NSTACK), .LAT(LAT)) doc (
        .clk(clk), .rst_n(rst_n), .start(cmd_doctor), .fault_inject(1'b0),
        .busy(doc_busy), .done(doc_done), .pass(doc_pass),
        .fail_mask(doc_fail_mask),
        .argon_fold_seen(doc_argon_fold), .mem_seen_bitmap(doc_mem_seen),
        .live_count(doc_live), .mem_en(doc_mem_en),
        .mem_req_valid(doc_req_valid), .mem_req_blk(doc_req_blk),
        .mem_req_bytes(doc_req_bytes), .mem_req_id(doc_req_id),
        .mem_req_ready(doc_req_ready),
        .mem_resp_valid(resp_valid[0]), .mem_resp_id(resp_id[IDW-1:0]));

    // ======================= HX: lane pool over a shared program ===========
    hashx_pool #(.NLANE(NHX), .MAXI(MAXI)) hx (
        .clk(clk), .rst_n(rst_n),
        .prog_we(hx_prog_we), .prog_waddr(hx_prog_waddr),
        .prog_wdata(hx_prog_wdata),
        .start(hx_start), .keys(hx_keys), .ninstr(hx_ninstr),
        .difficulty(hx_difficulty), .nonce_base(hx_nonce_base),
        .tries_per_lane(hx_tries_per_lane),
        .hit(hx_hit), .hit_nonce(hx_hit_nonce), .hit_tag(hx_hit_tag),
        .hit_lz(hx_hit_lz), .busy(hx_busy),
        .all_done(), .hashes_done(hx_hashes_done));

    // ======================= SHA-256: scanner pool =========================
    sha256_pool #(.NSHA(NSHA), .CHUNK(CHUNK)) sha (
        .clk(clk), .rst_n(rst_n), .start(sha_start),
        .midstate(sha_midstate), .block0(sha_block0), .block1(sha_block1),
        .nblocks(sha_nblocks), .nonce_word(sha_nonce_word),
        .nonce_le(sha_nonce_le), .difficulty(sha_difficulty),
        .nonce_base(sha_nonce_base),
        .found(sha_found), .found_nonce(sha_found_nonce),
        .found_digest(sha_found_digest), .busy(sha_busy),
        .hashes_done(sha_hashes_done));
endmodule
