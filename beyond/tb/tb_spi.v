`timescale 1ns/1ps
// tb_spi.v — the same chip talking over 1, 4 or 8 data lines.
//
// A Raspberry Pi will use plain SPI or QSPI, an ESP32-S3 can use OSPI. The
// slave is one block parameterised by LANES, so this drives all three and
// checks that a byte survives both directions.
//
// The slave synchronises SCLK into `clk`, so the master here runs SCLK at
// clk/20 - far slower than the clk/4 the synchroniser needs.
module tb_spi;
    parameter integer LANES = 1;
    localparam integer CYCLES = 8 / LANES;
    localparam integer HALF = 100;      // ns per SCLK half-period

    reg clk = 0, rst_n = 0;
    always #5 clk = ~clk;

    reg             sclk = 0;
    reg             cs_n = 1;
    reg  [LANES-1:0] io_in = 0;
    wire [LANES-1:0] io_out, io_oe;

    wire        rx_valid;
    wire [7:0]  rx_byte;
    reg         tx_valid = 1;
    reg  [7:0]  tx_byte = 8'h5A;
    wire        tx_ready;
    wire        frame_done;

    spi_slave #(.LANES(LANES)) dut (
        .clk(clk), .rst_n(rst_n),
        .sclk(sclk), .cs_n(cs_n),
        .io_in(io_in), .io_out(io_out), .io_oe(io_oe),
        .rx_valid(rx_valid), .rx_byte(rx_byte),
        .tx_valid(tx_valid), .tx_byte(tx_byte), .tx_ready(tx_ready),
        .frame_done(frame_done));

    // ---- one byte in, one byte out, full duplex ---------------------------
    task spi_byte(input [7:0] mosi, output [7:0] miso);
        integer c, k;
        reg [7:0] got;
        begin
            got = 8'd0;
            for (c = 0; c < CYCLES; c = c + 1) begin
                for (k = 0; k < LANES; k = k + 1)
                    io_in[k] = mosi[c*LANES + k];
                #(HALF);
                sclk = 1'b1;            // slave samples MOSI here
                #(HALF);
                for (k = 0; k < LANES; k = k + 1)
                    got[c*LANES + k] = io_out[k];
                sclk = 1'b0;            // slave shifts out the next group
                #(HALF);
            end
            miso = got;
        end
    endtask

    reg [7:0] back, seen;
    integer n;

    initial begin
        repeat (3) @(negedge clk);
        rst_n = 1;
        repeat (4) @(negedge clk);
        #(HALF);

        // ---- one byte out, the slave's fixed byte back -------------------
        tx_byte = 8'hA5;
        @(negedge clk);
        cs_n = 1'b0;
        #(HALF);
        spi_byte(8'h3C, back);
        #(HALF);
        cs_n = 1'b1;
        #(HALF);

        if (rx_byte !== 8'h3C) begin
            $display("FAIL: LANES=%0d master sent 3C, slave saw %h", LANES, rx_byte);
            $fatal;
        end
        if (back !== 8'hA5) begin
            $display("FAIL: LANES=%0d master got %h, slave offered A5", LANES, back);
            $fatal;
        end
        $display("spi LANES=%0d: sent 3C, received A5, %0d SCLK cycles per byte - PASS",
                 LANES, CYCLES);
        $display("tb_spi: PASS (%0d data lines)", LANES);
        $finish;
    end
endmodule
