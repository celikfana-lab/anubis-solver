// uart_tx.v — 8N1 serial transmitter.
//
// The clock divider is a parameter, so the same core works at 50 MHz/115200 on
// a dev board and at 1 GHz/1 Mbaud in a fast simulation.
`timescale 1ns/1ps
module uart_tx #(
    parameter integer CLK_HZ = 50_000_000,
    parameter integer BAUD   = 115_200
) (
    input  wire       clk,
    input  wire       rst_n,
    input  wire       tx_valid,
    input  wire [7:0] tx_data,
    output wire       tx_ready,
    output reg        tx
);
    localparam integer DIV = (CLK_HZ / BAUD > 1) ? (CLK_HZ / BAUD) : 2;

    reg [15:0] div;
    reg [3:0]  nbits;
    reg [9:0]  shreg;
    reg        busy;

    assign tx_ready = !busy;

    always @(posedge clk) begin
        if (!rst_n) begin
            busy <= 1'b0; tx <= 1'b1; div <= 16'd0; nbits <= 4'd0; shreg <= 10'h3FF;
        end else if (!busy) begin
            if (tx_valid) begin
                // bit 0 = start, bits 1..8 = data LSB first, bit 9 = stop
                shreg <= {1'b1, tx_data, 1'b0};
                div   <= DIV - 1;
                nbits <= 4'd10;
                tx    <= 1'b0;
                busy  <= 1'b1;
            end
        end else begin
            if (div == 16'd0) begin
                div   <= DIV - 1;
                shreg <= {1'b1, shreg[9:1]};
                nbits <= nbits - 4'd1;
                tx    <= (nbits == 4'd1) ? 1'b1 : shreg[1];
                if (nbits == 4'd1) busy <= 1'b0;
            end else begin
                div <= div - 16'd1;
            end
        end
    end
endmodule
