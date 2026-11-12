// lpddr6_if.v — 1 KiB block <-> LPDDR6 packet adaptor.
//
// An Argon2 block is 1 KiB; LPDDR6 moves 32-byte packets (BL24) or 64-byte
// accesses (two packets). This adaptor issues `npkt` consecutive packet
// reads/writes for a block and assembles the data words.
`timescale 1ns/1ps
module lpddr6_if #(
    parameter NPKT = 32            // 32 x 32 bytes = 1 KiB
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire         we,
    input  wire [31:0]  byte_addr, // block base address
    input  wire [NPKT*256-1:0] wdata,
    output reg  [NPKT*256-1:0] rdata,
    output reg          done,
    output reg          busy,
    output wire         req_valid,
    output wire         req_we,
    output wire [31:0]  req_addr,
    output wire [255:0] req_wdata,
    input  wire         req_ready,
    input  wire         rsp_valid,
    input  wire [255:0] rsp_rdata
);
    reg [5:0] idx;
    reg       outstanding;

    assign req_valid = busy && !outstanding && (idx < NPKT);
    assign req_we    = we;
    assign req_addr  = byte_addr + {idx, 5'b0};
    assign req_wdata = wdata[idx*256 +: 256];

    always @(posedge clk) begin
        if (!rst_n) begin
            busy <= 1'b0;
            done <= 1'b0;
            idx  <= 6'd0;
            outstanding <= 1'b0;
        end else if (start) begin
            busy <= 1'b1;
            done <= 1'b0;
            idx  <= 6'd0;
            outstanding <= 1'b0;
        end else if (busy) begin
            if (req_valid && req_ready) begin
                outstanding <= 1'b1;
            end
            if (rsp_valid || (we && outstanding)) begin
                if (!we) begin
                    rdata[idx*256 +: 256] <= rsp_rdata;
                end
                outstanding <= 1'b0;
                if (idx == NPKT - 1) begin
                    busy <= 1'b0;
                    done <= 1'b1;
                end else begin
                    idx <= idx + 6'd1;
                end
            end
        end else begin
            done <= 1'b0;
        end
    end
endmodule
