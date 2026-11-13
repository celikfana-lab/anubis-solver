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
    parameter integer EFF = 100,     // link efficiency in %, random 1 KiB
                                     // blocks cost a row activate each
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
    // Byte-credit admission instead of a per-request busy period: charging
    // ceil(bytes / BW) cycles rounded a 3584-byte block up from 4.38 to 5 and
    // capped the link at 87% of its bandwidth.
    reg [31:0] credit;             // bytes of transfer the link can still take
    // the derate must apply on the accept path too, or a request is paid for
    // with full-rate bytes while the recharge only trickles in
    wire [31:0] credit_after = credit + (BW * EFF / 100);

    // latency pipeline: one request can start per cycle, so one slot per cycle
    reg              pv [0:LAT-1];
    reg [IDW-1:0]    pi [0:LAT-1];

    integer i;

    assign req_ready = (credit >= {16'd0, req_bytes});

    always @(posedge clk) begin
        if (!rst_n) begin
            credit <= 32'd0;
            resp_valid <= 1'b0; resp_id <= {IDW{1'b0}};
            bytes_served <= 64'd0; req_served <= 64'd0;
            for (i = 0; i < LAT; i = i + 1) begin pv[i] <= 1'b0; pi[i] <= {IDW{1'b0}}; end
        end else begin
            resp_valid <= 1'b0;

            // credit rises by the derated bandwidth every cycle
            credit <= (credit > (8*BW)) ? (8*BW) : credit + (BW * EFF / 100);
            if (req_valid && req_ready) begin
                credit <= credit_after - {16'd0, req_bytes};
                bytes_served <= bytes_served + {48'd0, req_bytes};
                req_served <= req_served + 64'd1;
            end

            // shift the latency pipeline and emit the oldest entry
            for (i = LAT - 1; i > 0; i = i - 1) begin
                pv[i] <= pv[i-1];
                pi[i] <= pi[i-1];
            end
            pv[0] <= (req_valid && req_ready);
            pi[0] <= req_id;

            if (pv[LAT-1]) begin
                resp_valid <= 1'b1;
                resp_id    <= pi[LAT-1];
            end
        end
    end
endmodule
