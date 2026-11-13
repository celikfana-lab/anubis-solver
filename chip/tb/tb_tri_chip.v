`timescale 1ns/1ps
// tb_tri_chip.v — one die, three algorithms, each on the machine that suits it.
//
//   HX   real HashX program from vectors/hx_vectors.hex, difficulty 8; the C
//        reference says the first hit is nonce 228
//   SHA  the tb_pow challenge (64 bytes of 'a', big-endian nonce), difficulty
//        8; the first hit is nonce 83
//   A2I  small engine array; checks that the memory traffic matches
//        engines/cycles-per-block
//
// The sizes are small so this is seconds of Icarus; the design-point sizes are
// the module defaults and are reported by make tri-chip-sizes.
module tb_tri_chip;
    parameter integer NENG   = 12;
    parameter integer KCTX   = 3;
    parameter integer NPORT  = 3;
    parameter integer NSTACK = 8;
    parameter integer LAT    = 40;
    parameter integer CYC    = 20;
    parameter integer NHX    = 4;
    parameter integer NSHA   = 4;
    parameter integer CHUNK  = 32;
    parameter integer MAXI   = 512;

    reg clk = 0, rst_n = 0;
    always #5 clk = ~clk;

    // HashX
    reg  [255:0] hx_keys = 0;
    reg  [31:0]  hx_ninstr = 0;
    reg  [7:0]   hx_diff = 8'd8;
    reg  [63:0]  hx_nbase = 0;
    reg  [31:0]  hx_tries = 32'd64;
    reg          hx_start = 0;
    reg          hx_prog_we = 0;
    reg  [8:0]   hx_prog_waddr = 0;
    reg  [127:0] hx_prog_wdata = 0;
    wire         hx_hit, hx_busy;
    wire [63:0]  hx_hit_nonce;
    wire [255:0] hx_hit_tag;
    wire [7:0]   hx_hit_lz;
    wire [31:0]  hx_hashes_done;

    // SHA-256
    reg          sha_start = 0;
    reg  [255:0] sha_midstate = 0;
    reg  [511:0] sha_block0 = 0, sha_block1 = 0;
    reg  [1:0]   sha_nblocks = 2'd1;
    reg  [3:0]   sha_nword = 0;
    reg          sha_le = 0;
    reg  [5:0]   sha_diff = 6'd8;
    reg  [31:0]  sha_nbase = 0;
    wire         sha_found, sha_busy;
    wire [31:0]  sha_found_nonce;
    wire [255:0] sha_found_digest;

    // A2I
    reg          a2i_start = 0;
    wire [31:0]  a2i_blocks_done;
    wire [63:0]  a2i_bytes_served;
    wire         a2i_busy;

    anubis_tri_chip #(.NENG(NENG), .KCTX(KCTX), .NPORT(NPORT), .NSTACK(NSTACK),
                      .LAT(LAT), .CYC_BLOCK(CYC), .NHX(NHX), .MAXI(MAXI),
                      .NSHA(NSHA), .CHUNK(CHUNK)) dut (
        .clk(clk), .rst_n(rst_n),
        .a2i_start(a2i_start), .a2i_blocks_done(a2i_blocks_done),
        .a2i_bytes_served(a2i_bytes_served), .a2i_busy(a2i_busy),
        .hx_prog_we(hx_prog_we), .hx_prog_waddr(hx_prog_waddr),
        .hx_prog_wdata(hx_prog_wdata), .hx_start(hx_start),
        .hx_keys(hx_keys), .hx_ninstr(hx_ninstr), .hx_difficulty(hx_diff),
        .hx_nonce_base(hx_nbase), .hx_tries_per_lane(hx_tries),
        .hx_hit(hx_hit), .hx_hit_nonce(hx_hit_nonce), .hx_hit_tag(hx_hit_tag),
        .hx_hit_lz(hx_hit_lz), .hx_busy(hx_busy),
        .hx_hashes_done(hx_hashes_done),
        .sha_start(sha_start), .sha_midstate(sha_midstate),
        .sha_block0(sha_block0), .sha_block1(sha_block1),
        .sha_nblocks(sha_nblocks), .sha_nonce_word(sha_nword),
        .sha_nonce_le(sha_le), .sha_difficulty(sha_diff),
        .sha_nonce_base(sha_nbase),
        .sha_found(sha_found), .sha_found_nonce(sha_found_nonce),
        .sha_found_digest(sha_found_digest), .sha_busy(sha_busy),
        // serial host + doctor unused here; tb_tri_chip_cmd drives those
        .spi_sclk(1'b0), .spi_cs_n(1'b1), .spi_io_in(8'd0),
        .spi_io_out(), .spi_io_oe(),
        .uart_rx_pad(1'b1), .uart_tx_pad(),
        .doc_start_ext(1'b0), .doc_busy(), .doc_done(), .doc_pass(),
        .doc_fail_mask());

    // ---- HashX program vectors -------------------------------------------
    reg [63:0] hxmem [0:10289];   // 5 cases x 2058 words, as tb_hashx sizes it
    integer k, guard;

    task load_hx_program;
        begin
            $readmemh("vectors/hx_vectors.hex", hxmem);
            hx_keys   = {hxmem[3], hxmem[2], hxmem[1], hxmem[0]};
            hx_ninstr = hxmem[4][31:0];
            for (k = 0; k < MAXI; k = k + 1) begin
                @(negedge clk);
                hx_prog_we    = 1'b1;
                hx_prog_waddr = k[8:0];
                hx_prog_wdata = {hxmem[6+4*k][31:0], hxmem[7+4*k][31:0],
                                 hxmem[8+4*k][31:0], hxmem[9+4*k][31:0]};
            end
            @(negedge clk);
            hx_prog_we = 1'b0;
        end
    endtask

    integer a2i_by0, blk0;
    real bpc, a2i_hps;

    initial begin
        sha_midstate = {32'hdf5bb81c, 32'he81e0626, 32'hfb45a894, 32'h4fd40f31,
                        32'hb25e6816, 32'hd6d499c1, 32'hab904929, 32'h00635e66};
        // exactly tb_pow's block0: 16 words. A 14-word concatenation still
        // compiles, zero-extends, and quietly hashes a different message.
        sha_block0 = {32'h00000000, 32'h80000000,
                      32'h0, 32'h0, 32'h0, 32'h0, 32'h0, 32'h0,
                      32'h0, 32'h0,
                      32'h0, 32'h0, 32'h0, 32'h0, 32'h0, 32'h00000220};
        sha_block1 = 512'h0;

        repeat (3) @(negedge clk);
        rst_n = 1;
        @(negedge clk);

        load_hx_program;
        $display("tri-chip: HX %0d lanes, SHA %0d lanes x %0d nonces, A2I %0d engines x %0d contexts",
                 NHX, NSHA, CHUNK, NENG, KCTX);

        // ---- start all three sub-chips at once ---------------------------
        hx_start  = 1;
        sha_start = 1;
        a2i_start = 1;
        @(negedge clk);
        hx_start = 0; sha_start = 0; a2i_start = 0;
        a2i_by0 = a2i_bytes_served;

        // ---- HashX: first hit must be nonce 228 --------------------------
        guard = 0;
        while (!hx_hit && guard < 400000) begin
            @(negedge clk);
            guard = guard + 1;
        end
        if (!hx_hit) begin
            $display("FAIL: HashX pool found nothing in %0d cycles", guard);
            $fatal;
        end
        if (hx_hit_nonce !== 64'd228) begin
            $display("FAIL: HashX hit nonce %0d, C reference says 228", hx_hit_nonce);
            $fatal;
        end
        if (hx_hit_lz < hx_diff) begin
            $display("FAIL: HashX hit reports %0d leading zero bits < %0d", hx_hit_lz, hx_diff);
            $fatal;
        end
        $display("  HX : hit nonce %0d, %0d leading zero bits, %0d hashes across %0d lanes",
                 hx_hit_nonce, hx_hit_lz, hx_hashes_done, NHX);

        // ---- SHA-256: first hit must be nonce 83 -------------------------
        guard = 0;
        while (!sha_found && guard < 400000) begin
            @(negedge clk);
            guard = guard + 1;
        end
        if (!sha_found) begin
            $display("FAIL: SHA-256 pool found nothing in %0d cycles", guard);
            $fatal;
        end
        if (sha_found_nonce !== 32'd83) begin
            $display("FAIL: SHA-256 hit nonce %0d, tb_pow says 83", sha_found_nonce);
            $fatal;
        end
        $display("  SHA: hit nonce %0d, digest %h", sha_found_nonce,
                 sha_found_digest[255:128]);

        // ---- A2I: traffic must be engines / cycles-per-block -------------
        // snapshot right before the window: the HashX/SHA waits above can be
        // millions of cycles, and the byte counter keeps running through them
        a2i_by0 = a2i_bytes_served;
        blk0    = a2i_blocks_done;
        for (k = 0; k < 400; k = k + 1) @(negedge clk);
        bpc     = (a2i_bytes_served - a2i_by0) * 1.0 / 400.0;
        a2i_hps = (bpc / 3584.0) * 1.0e9 / 38912.0;
        $display("  A2I: %0d blocks in 400 cycles, %.1f B/cycle of %0d, %.0f hashes/s at 1 GHz",
                 a2i_blocks_done - blk0, bpc, NSTACK * 1228, a2i_hps);
        if ((a2i_blocks_done - blk0) < 1 || (a2i_bytes_served - a2i_by0) == 0) begin
            $display("FAIL: the Argon2id sub-chip produced no traffic");
            $fatal;
        end

        $display("tb_tri_chip: PASS - three algorithms, three machines, one die");
        $finish;
    end
endmodule
