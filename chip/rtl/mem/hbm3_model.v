// hbm3_model.v — cycle-accurate HBM3 link model for capacity planning.
//
// It models the two things that decide throughput, and nothing else:
//   * the link: BW bytes per cycle, served strictly in order, one request at a
//     time, each request costing ceil(bytes / BW) cycles;
//   * the latency: a response appears LAT cycles after the request starts.
//
// No data is stored - for an architecture study only the timing matters, which
// keeps a 912 MiB working set free.

`timescale 1ns/1ps
module hbm3_model #(
    parameter integer BW  = 819,     // HBM3: 819 GB/s at 1 GHz = 819 B/cycle
    parameter integer LAT = 350,     // ~350 ns at 1 GHz
    parameter integer IDW = 6
) (
    input  wire          clk,
    input  wire          rst_n,
    input  wire          req_valid,
    input  wire [15:0]   req_bytes,
    input  wire [IDW-1:0] req_id,
    output wire          req_ready,
    output reg           resp_valid,
    output reg  [IDW-1:0] resp_id,
    output reg  [63:0]   bytes_served,
    output reg  [63:0]   req_served
);
    reg        link_busy;
    reg [15:0] link_left;          // cycles left on the current request

    // latency pipeline: one request can start per cycle, so one slot per cycle
    reg              pv [0:LAT-1];
    reg [IDW-1:0]    pi [0:LAT-1];

    integer i;

    assign req_ready = !link_busy;

    always @(posedge clk) begin
        if (!rst_n) begin
            link_busy <= 1'b0; link_left <= 16'd0;
            resp_valid <= 1'b0; resp_id <= {IDW{1'b0}};
            bytes_served <= 64'd0; req_served <= 64'd0;
            for (i = 0; i < LAT; i = i + 1) begin pv[i] <= 1'b0; pi[i] <= {IDW{1'b0}}; end
        end else begin
            resp_valid <= 1'b0;

            // service the link
            if (link_busy) begin
                if (link_left <= 16'd1) link_busy <= 1'b0;
                else link_left <= link_left - 16'd1;
            end else if (req_valid) begin
                link_busy <= 1'b1;
                link_left <= (req_bytes + BW - 1) / BW;
                bytes_served <= bytes_served + {48'd0, req_bytes};
                req_served <= req_served + 64'd1;
            end

            // shift the latency pipeline and emit the oldest entry
            for (i = LAT - 1; i > 0; i = i - 1) begin
                pv[i] <= pv[i-1];
                pi[i] <= pi[i-1];
            end
            pv[0] <= (req_valid && !link_busy);
            pi[0] <= req_id;

            if (pv[LAT-1]) begin
                resp_valid <= 1'b1;
                resp_id    <= pi[LAT-1];
            end
        end
    end
endmodule
