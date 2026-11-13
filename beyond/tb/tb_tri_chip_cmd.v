`timescale 1ns/1ps
// tb_tri_chip_cmd.v — ask the chip to test itself, once over QSPI and once over
// UART, exactly as a Raspberry Pi or an ESP32 would.
//
// The command byte is 0x01 = DOCTOR. The chip answers with the status byte on
// the SPI pads (and on the status output pins): {pass, done, busy, fail[3:0], 0}.
module tb_tri_chip_cmd;
    parameter integer LANES = 4;              // QSPI
    localparam integer CYCLES = 8 / LANES;
    localparam integer HALF   = 40;           // ns per SCLK half period
    localparam integer CLK_HZ = 100_000_000;  // matches the 10 ns clock below
    localparam integer BAUD   = 1_000_000;

    reg clk = 0, rst_n = 0;
    always #5 clk = ~clk;

    // SPI
    reg  sclk = 0, cs_n = 1;
    reg  [LANES-1:0] io_in = 0;
    wire [7:0] io_out, io_oe;

    // UART
    reg  uart_rx = 1;
    wire uart_tx;

    wire doc_busy, doc_done, doc_pass;
    wire [3:0] doc_fail_mask;

    anubis_tri_chip #(.NENG(1), .KCTX(1), .NPORT(3), .NSTACK(8),
                      .NHX(1), .NSHA(1), .SPI_LANES(LANES),
                      .CLK_HZ(CLK_HZ), .BAUD(BAUD)) dut (
        .clk(clk), .rst_n(rst_n),
        .a2i_start(1'b0), .a2i_blocks_done(), .a2i_bytes_served(), .a2i_busy(),
        .hx_prog_we(1'b0), .hx_prog_waddr(9'd0), .hx_prog_wdata(128'd0),
        .hx_start(1'b0), .hx_keys(256'd0), .hx_ninstr(32'd0),
        .hx_difficulty(8'd8), .hx_nonce_base(64'd0), .hx_tries_per_lane(32'd1),
        .hx_hit(), .hx_hit_nonce(), .hx_hit_tag(), .hx_hit_lz(), .hx_busy(),
        .hx_hashes_done(),
        .sha_start(1'b0), .sha_midstate(256'd0), .sha_block0(512'd0),
        .sha_block1(512'd0), .sha_nblocks(2'd1), .sha_nonce_word(4'd0),
        .sha_nonce_le(1'b0), .sha_difficulty(6'd8), .sha_nonce_base(32'd0),
        .sha_found(), .sha_found_nonce(), .sha_found_digest(), .sha_busy(),
        .spi_sclk(sclk), .spi_cs_n(cs_n),
        .spi_io_in({{(8-LANES){1'b0}}, io_in}),
        .spi_io_out(io_out), .spi_io_oe(io_oe),
        .uart_rx_pad(uart_rx), .uart_tx_pad(uart_tx),
        .doc_start_ext(1'b0), .doc_busy(doc_busy), .doc_done(doc_done),
        .doc_pass(doc_pass), .doc_fail_mask(doc_fail_mask));

    task spi_byte(input [7:0] mosi, output [7:0] miso);
        integer c, k;
        reg [7:0] got;
        begin
            got = 8'd0;
            for (c = 0; c < CYCLES; c = c + 1) begin
                for (k = 0; k < LANES; k = k + 1)
                    io_in[k] = mosi[c*LANES + k];
                #(HALF); sclk = 1'b1;
                #(HALF);
                for (k = 0; k < LANES; k = k + 1) got[c*LANES + k] = io_out[k];
                sclk = 1'b0;
                #(HALF);
            end
            miso = got;
        end
    endtask

    // 8N1 at BAUD, given the clock is 1/(2*5ns) = 100 MHz
    task uart_send(input [7:0] b);
        integer i;
        begin
            uart_rx = 1'b0;                       // start bit
            #(1_000_000_000/BAUD);
            for (i = 0; i < 8; i = i + 1) begin
                uart_rx = b[i];                   // LSB first
                #(1_000_000_000/BAUD);
            end
            uart_rx = 1'b1;                       // stop bit
            #(1_000_000_000/BAUD);
        end
    endtask

    task wait_doctor(output ok);
        integer guard;
        begin
            guard = 0;
            while (!doc_done && guard < 200000) begin
                @(negedge clk);
                guard = guard + 1;
            end
            if (!doc_done) begin
                $display("FAIL: doctor did not finish after the command");
                $fatal;
            end
            ok = doc_pass;
            @(negedge clk);
        end
    endtask

    reg [7:0] back;
    reg ok;

    initial begin
        repeat (3) @(negedge clk);
        rst_n = 1;
        repeat (4) @(negedge clk);
        #(HALF);

        // ---------------- 1. a Pi sends DOCTOR over QSPI -------------------
        cs_n = 1'b0; #(HALF);
        spi_byte(8'h01, back);
        #(HALF); cs_n = 1'b1; #(HALF);
        wait_doctor(ok);
        if (!ok) begin
            $display("FAIL: QSPI doctor request reported fail_mask=%b", doc_fail_mask);
            $fatal;
        end
        // `back` is the status byte the chip presented when the frame began,
        // i.e. before the command - the doctor's own result is on the pins
        $display("cmd: %0d-lane SPI sent 0x01 -> doctor ran, PASS (status byte before the command was %h)",
                 LANES, back);

        // ---------------- 2. an ESP32 sends DOCTOR over UART ---------------
        uart_send(8'h01);
        wait_doctor(ok);
        if (!ok) begin
            $display("FAIL: UART doctor request reported fail_mask=%b", doc_fail_mask);
            $fatal;
        end
        $display("cmd: UART sent 0x01 -> doctor ran, PASS");

        $display("tb_tri_chip_cmd: PASS - the chip tests itself on request, over SPI and UART");
        $finish;
    end
endmodule
