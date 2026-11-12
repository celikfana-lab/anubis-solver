// lpddr6_model.v — behavioural LPDDR6 memory model (simulation only).
//
// Models the JEDEC JESD209-6 access granularity: 32-byte data packets
// (BL24 = 256 data bits + 32 metadata bits) and 64-byte accesses built from
// two packets. Latency is configurable (tRCD + tCL + burst), bandwidth is
// measured from the bytes actually moved.
`timescale 1ns/1ps
module lpddr6_model #(
    parameter LAT   = 24,          // read latency in clock cycles (tRCD+tCL)
    parameter DEPTH = 32768        // 32-byte packets (= 1 MiB)
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         req_valid,
    input  wire         req_we,
    input  wire [31:0]  req_addr,  // byte address, 32-byte aligned
    input  wire [255:0] req_wdata,
    output wire         req_ready,
    output reg          rsp_valid,
    output reg  [255:0] rsp_rdata,
    output reg  [63:0]  bytes_moved,
    output reg  [63:0]  accesses
);
    reg [255:0] mem [0:DEPTH-1];
    reg [LAT:0] pipe;
    reg [255:0] rdata_pipe [0:LAT];
    integer i;
    wire [31:0] pkt = req_addr[31:5];

    assign req_ready = 1'b1;

    always @(posedge clk) begin
        if (!rst_n) begin
            rsp_valid   <= 1'b0;
            bytes_moved <= 64'd0;
            accesses    <= 64'd0;
            pipe        <= 0;
            for (i = 0; i <= LAT; i = i + 1) rdata_pipe[i] <= 256'd0;
        end else begin
            // shift latency pipeline
            for (i = 0; i <= LAT - 1; i = i + 1) rdata_pipe[i+1] <= rdata_pipe[i];
            pipe <= {pipe[LAT-1:0], req_valid && !req_we};
            rsp_valid <= pipe[LAT];
            rsp_rdata <= rdata_pipe[LAT];
            if (req_valid) begin
                accesses <= accesses + 64'd1;
                if (req_we) begin
                    mem[pkt % DEPTH] <= req_wdata;
                    bytes_moved <= bytes_moved + 64'd32;
                end else begin
                    rdata_pipe[0] <= mem[pkt % DEPTH];
                    bytes_moved <= bytes_moved + 64'd32;
                end
            end
        end
    end
endmodule
