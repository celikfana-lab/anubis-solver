// uart_rx.v — 8N1 receiver, the other half of uart_tx.
//
// Anubis cards get their commands over a serial console, so the host interface
// needs a receiver as well as the log transmitter. Mid-bit sampling, no
// oversampling loop: at CLK_HZ/BAUD cycles per bit this samples once in the
// middle of each bit and checks the stop bit.

`timescale 1ns/1ps
module uart_rx #(
    parameter integer CLK_HZ = 50_000_000,
    parameter integer BAUD   = 115_200
) (
    input  wire       clk,
    input  wire       rst_n,
    input  wire       rx,
    output reg        rx_valid,
    output reg  [7:0] rx_byte,
    output reg        frame_err
);
    localparam integer BIT_CYC = CLK_HZ / BAUD;
    localparam integer HALF    = BIT_CYC / 2;

    reg [2:0]  rx_sync;
    wire       rx_q = rx_sync[1];

    reg [15:0] cnt;
    reg [3:0]  bitpos;        // 0 = start bit, 1..8 = data, 9 = stop
    reg [7:0]  sh;
    reg        active;

    always @(posedge clk) begin
        if (!rst_n) begin
            rx_sync <= 3'b111;
            active  <= 1'b0;
            cnt     <= 16'd0;
            bitpos  <= 4'd0;
            sh      <= 8'd0;
            rx_valid <= 1'b0;
            rx_byte  <= 8'd0;
            frame_err <= 1'b0;
        end else begin
            rx_sync  <= {rx_sync[1:0], rx};
            rx_valid <= 1'b0;
            frame_err <= 1'b0;

            if (!active) begin
                // a falling edge is the start bit; sample it mid-bit to be sure
                if (!rx_q) begin
                    active <= 1'b1;
                    cnt    <= 16'd0;
                    bitpos <= 4'd0;
                end
            end else if (bitpos == 4'd0) begin
                if (cnt == HALF - 1) begin
                    cnt    <= 16'd0;
                    bitpos <= 4'd1;
                end else
                    cnt <= cnt + 16'd1;
            end else if (bitpos <= 4'd8) begin
                if (cnt == BIT_CYC - 1) begin
                    cnt <= 16'd0;
                    sh  <= {rx_q, sh[7:1]};        // LSB first
                    bitpos <= bitpos + 4'd1;
                end else
                    cnt <= cnt + 16'd1;
            end else begin                          // stop bit
                if (cnt == BIT_CYC - 1) begin
                    if (!rx_q) frame_err <= 1'b1;
                    else begin
                        rx_valid <= 1'b1;
                        rx_byte  <= sh;
                    end
                    active <= 1'b0;
                    cnt    <= 16'd0;
                end else
                    cnt <= cnt + 16'd1;
            end
        end
    end
endmodule
