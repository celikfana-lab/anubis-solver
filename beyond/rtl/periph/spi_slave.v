// spi_slave.v — SPI / Dual / Quad (QSPI) / Octal (OSPI) slave.
//
// One block, LANES = 1, 2, 4 or 8 data lines, so a Raspberry Pi can talk to it
// over plain SPI or QSPI, and an ESP32-S3 can use OSPI. Mode 0 only (idle low,
// sample on the rising edge, shift out on the falling edge), which is what every
// host defaults to and what needs no CPOL/CPHA configuration to get wrong.
//
// Framing: CS asserts, then whole bytes move in both directions at once, LSB
// first, LANES bits per SCLK cycle. 8 bits therefore take 8/LANES SCLK cycles:
// one cycle per byte on OSPI, two on QSPI, eight on a plain SPI wire.
//
// Clocking: SCLK is asynchronous to `clk`, so it is synchronised and edge-
// detected here. That costs a few clk cycles of latency and means SCLK must stay
// below clk/4 - at a 1 GHz core that is 250 MHz of SCLK, far more than any Pi or
// ESP32 will drive.
//
// The data path out is a byte stream (tx_valid/tx_byte), so the caller decides
// what a read means; rx bytes come back as (rx_valid, rx_byte).

`timescale 1ns/1ps
module spi_slave #(
    parameter integer LANES = 1          // 1 SPI, 2 dual, 4 QSPI, 8 OSPI
) (
    input  wire             clk,
    input  wire             rst_n,

    // pads
    input  wire             sclk,
    input  wire             cs_n,
    input  wire [LANES-1:0] io_in,
    output reg  [LANES-1:0] io_out,
    output reg  [LANES-1:0] io_oe,       // 1 = the slave drives these pads

    // received bytes
    output reg              rx_valid,
    output reg  [7:0]       rx_byte,

    // bytes to send back
    input  wire             tx_valid,
    input  wire [7:0]       tx_byte,
    output reg              tx_ready,

    output reg              frame_done
);
    localparam integer CYCLES_PER_BYTE = 8 / LANES;   // SCLK cycles per byte
    localparam integer BITS_PER_CYCLE  = LANES;

    // ---- synchronise the pads into the clk domain -------------------------
    reg [2:0] sclk_sync, cs_sync;
    always @(posedge clk) begin
        if (!rst_n) begin
            sclk_sync <= 3'b000;
            cs_sync   <= 3'b111;
        end else begin
            sclk_sync <= {sclk_sync[1:0], sclk};
            cs_sync   <= {cs_sync[1:0], cs_n};
        end
    end
    wire sclk_q = sclk_sync[1];
    wire cs_q   = cs_sync[1];
    reg  sclk_d, cs_d;
    wire sclk_rise = sclk_q & ~sclk_d;
    wire sclk_fall = ~sclk_q & sclk_d;
    wire cs_rise   = cs_q & ~cs_d;       // deselected
    wire cs_fall   = ~cs_q & cs_d;       // selected

    // ---- frame state ------------------------------------------------------
    reg [7:0] rx_sh;                     // shifts in, LSB first
    reg [7:0] tx_sh;                     // shifts out, LSB first
    reg [2:0] bitcnt;                    // SCLK cycles done in this byte
    reg       selected;

    always @(posedge clk) begin
        if (!rst_n) begin
            sclk_d <= 1'b0; cs_d <= 1'b1;
            selected <= 1'b0; rx_sh <= 8'd0; tx_sh <= 8'd0; bitcnt <= 3'd0;
            rx_valid <= 1'b0; rx_byte <= 8'd0;
            io_out <= {LANES{1'b0}}; io_oe <= {LANES{1'b0}};
            tx_ready <= 1'b0; frame_done <= 1'b0;
        end else begin
            sclk_d <= sclk_q;
            cs_d   <= cs_q;
            rx_valid   <= 1'b0;
            frame_done <= 1'b0;

            if (cs_fall) begin
                // Selected: reset the byte framing and present the first byte.
                // Mode 0 wants it valid before the first rising edge.
                selected <= 1'b1;
                bitcnt   <= 3'd0;
                rx_sh    <= 8'd0;
                tx_sh    <= tx_byte;
                tx_ready <= 1'b1;
                io_oe    <= {LANES{1'b1}};
                io_out   <= tx_byte[LANES-1:0];
            end else if (cs_rise) begin
                selected   <= 1'b0;
                io_oe      <= {LANES{1'b0}};
                io_out     <= {LANES{1'b0}};
                frame_done <= 1'b1;
            end else if (selected) begin
                if (sclk_rise) begin
                    // sample LANES bits, LSB first
                    rx_sh <= (rx_sh >> BITS_PER_CYCLE) |
                             (io_in << (8 - BITS_PER_CYCLE));
                    if (bitcnt == CYCLES_PER_BYTE - 1) begin
                        rx_valid <= 1'b1;
                        rx_byte  <= (rx_sh >> BITS_PER_CYCLE) |
                                    (io_in << (8 - BITS_PER_CYCLE));
                        bitcnt   <= 3'd0;
                        // the next byte to send is offered here; the caller has
                        // the whole of the next byte time to produce it
                        tx_sh    <= tx_byte;
                        tx_ready <= tx_valid;
                    end else begin
                        bitcnt <= bitcnt + 3'd1;
                    end
                end
                if (sclk_fall) begin
                    // shift out the LANES bits for this position. One formula,
                    // not a special case for the last group: the special case
                    // re-sent the low bits of the byte on QSPI (A5 came back 55).
                    io_out <= tx_sh >> (BITS_PER_CYCLE * bitcnt);
                end
            end
        end
    end
endmodule
