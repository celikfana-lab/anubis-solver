`timescale 1ns/1ps
// tb_bench.v — what the three sub-chips actually deliver, measured in RTL.
//
// Difficulty is set to an impossible value on purpose: every lane then hashes
// flat out instead of stopping at the first hit, so what is measured is the
// machine's rate and not the size of the search.
//
// The A2I array is memory-bound, so its rate depends on the engine count; this
// bench runs a small array and quotes the 365-engine number from
// `make card-argon2-max` separately. HashX and SHA-256 lanes are independent, so
// their per-lane rate here is what a 128-lane pool delivers.
module tb_bench;
    parameter integer NENG   = 24;
    parameter integer NHX    = 8;
    parameter integer NSHA   = 8;
    parameter integer LAT    = 350;
    parameter integer CYC    = 133;
    parameter integer WARMUP = 1200;      // let the A2I pipeline fill
    parameter integer WINDOW = 8000;      // cycles measured; a HashX hash is
                                          // ~533 cycles, so 3000 only sampled 5
    parameter integer CLK_HZ = 1_000_000_000;

    reg clk = 0, rst_n = 0;
    always #5 clk = ~clk;

    reg  a2i_start = 0, hx_start = 0, sha_start = 0;
    wire [31:0] a2i_blocks_done, hx_hashes_done, sha_hashes_done;
    wire [63:0] a2i_bytes_served;
    wire a2i_busy, hx_busy, sha_busy;
    wire hx_hit, sha_found;

    anubis_tri_chip #(.NENG(NENG), .KCTX(3), .NPORT(3), .NSTACK(8),
                      .LAT(LAT), .CYC_BLOCK(CYC),
                      .NHX(NHX), .NSHA(NSHA)) dut (
        .clk(clk), .rst_n(rst_n),
        .a2i_start(a2i_start), .a2i_blocks_done(a2i_blocks_done),
        .a2i_bytes_served(a2i_bytes_served), .a2i_busy(a2i_busy),
        .hx_prog_we(prog_we), .hx_prog_waddr(prog_waddr),
        .hx_prog_wdata(prog_wdata),
        .hx_start(hx_start), .hx_keys(hx_keys_r), .hx_ninstr(hx_ninstr_r),
        // impossible difficulty: the lanes must not stop on a hit
        .hx_difficulty(8'd255), .hx_nonce_base(64'd0),
        .hx_tries_per_lane(32'd1000000),
        .hx_hit(hx_hit), .hx_hit_nonce(), .hx_hit_tag(), .hx_hit_lz(),
        .hx_busy(hx_busy), .hx_hashes_done(hx_hashes_done),
        .sha_start(sha_start), .sha_midstate(256'd0), .sha_block0(512'd0),
        .sha_block1(512'd0), .sha_nblocks(2'd1), .sha_nonce_word(4'd0),
        .sha_nonce_le(1'b0), .sha_difficulty(6'd63),   // impossible too
        .sha_nonce_base(32'd0),
        .sha_found(sha_found), .sha_found_nonce(), .sha_found_digest(),
        .sha_busy(sha_busy), .sha_hashes_done(sha_hashes_done),
        .spi_sclk(1'b0), .spi_cs_n(1'b1), .spi_io_in(8'd0),
        .spi_io_out(), .spi_io_oe(),
        .uart_rx_pad(1'b1), .uart_tx_pad(),
        .doc_start_ext(1'b0), .doc_busy(), .doc_done(), .doc_pass(),
        .doc_fail_mask());

    // The HashX lanes need a real program: with an unloaded (X) program the VM
    // "finishes" in about twenty cycles and the rate is meaningless.
    reg [63:0] hxmem [0:10289];
    reg [255:0] hx_keys_r;
    reg [31:0]  hx_ninstr_r;
    integer j;

    task load_hx_program;
        begin
            $readmemh("vectors/hx_vectors.hex", hxmem);
            hx_keys_r   = {hxmem[3], hxmem[2], hxmem[1], hxmem[0]};
            hx_ninstr_r = hxmem[4][31:0];
            for (j = 0; j < 512; j = j + 1) begin
                @(negedge clk);
                prog_we    = 1'b1;
                prog_waddr = j[8:0];
                prog_wdata = {hxmem[6+4*j][31:0], hxmem[7+4*j][31:0],
                              hxmem[8+4*j][31:0], hxmem[9+4*j][31:0]};
            end
            @(negedge clk);
            prog_we = 1'b0;
        end
    endtask

    reg        prog_we = 0;
    reg [8:0]  prog_waddr = 0;
    reg [127:0] prog_wdata = 0;

    integer i, blk0, sh0, hx0;
    reg [63:0] by0;
    real sha_rate, hx_rate, a2i_rate, sha_cyc, hx_cyc;

    initial begin
        repeat (3) @(negedge clk);
        rst_n = 1;
        @(negedge clk);

        load_hx_program;
        a2i_start = 1; hx_start = 1; sha_start = 1;
        @(negedge clk);
        a2i_start = 0; hx_start = 0; sha_start = 0;

        for (i = 0; i < WARMUP; i = i + 1) @(negedge clk);

        blk0 = a2i_blocks_done; by0 = a2i_bytes_served;
        sh0  = sha_hashes_done;  hx0 = hx_hashes_done;

        for (i = 0; i < WINDOW; i = i + 1) @(negedge clk);

        // per-lane rates: both pools are replication, so this scales exactly
        sha_rate = (sha_hashes_done - sh0) * 1.0e9 / (WINDOW * NSHA);
        hx_rate  = (hx_hashes_done  - hx0) * 1.0e9 / (WINDOW * NHX);
        sha_cyc  = WINDOW * NSHA * 1.0 / (sha_hashes_done - sh0);
        hx_cyc   = WINDOW * NHX  * 1.0 / (hx_hashes_done  - hx0);
        a2i_rate = ((a2i_bytes_served - by0) / 3584.0) * 1.0e9 / (WINDOW * 38912.0);

        $display("bench: %0d A2I engines, %0d HX lanes, %0d SHA lanes, %0d-cycle window",
                 NENG, NHX, NSHA, WINDOW);
        $display("  A2I : %0d blocks, %.0f B/cycle -> %.0f hashes/s at %0d engines",
                 a2i_blocks_done - blk0,
                 (a2i_bytes_served - by0) * 1.0 / WINDOW, a2i_rate, NENG);
        $display("  HX  : %0d hashes of a %0d-instruction program -> %.2f cycles/hash,",
                 hx_hashes_done - hx0, hx_ninstr_r, hx_cyc);
        $display("        %.2f M h/s per lane, %.0f M h/s at 128 lanes",
                 hx_rate / 1.0e6, hx_rate * 128.0 / 1.0e6);
        $display("  SHA : %0d hashes -> %.2f cycles/hash, %.2f M h/s per lane, %.0f M h/s at 128 lanes",
                 sha_hashes_done - sh0, sha_cyc, sha_rate / 1.0e6, sha_rate * 128.0 / 1.0e6);
        $display("BENCH sha_cyc=%0.2f hx_cyc=%0.2f a2i_bpc=%0.1f",
                 sha_cyc, hx_cyc, (a2i_bytes_served - by0) * 1.0 / WINDOW);

        if ((a2i_blocks_done - blk0) < 1 || (sha_hashes_done - sh0) < 1 ||
            (hx_hashes_done - hx0) < 1) begin
            $display("FAIL: a sub-chip did not run");
            $fatal;
        end
        $finish;
    end
endmodule
