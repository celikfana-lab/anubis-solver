`timescale 1ns/1ps
module tb_b2_trace;
    reg clk = 0, rst_n = 0, start = 0, last = 1;
    reg [511:0] h_in;
    reg [1023:0] block;
    reg [63:0] t;
    wire [511:0] h_out;
    wire done, busy;
    integer k, cyc;

    localparam [511:0] IV =
        {64'h6a09e667f3bcc908, 64'hbb67ae8584caa73b,
         64'h3c6ef372fe94f82b, 64'ha54ff53a5f1d36f1,
         64'h510e527fade682d1, 64'h9b05688c2b3e6c1f,
         64'h1f83d9abfb41bd6b, 64'h5be0cd19137e2179};

    blake2b_core dut (.clk(clk), .rst_n(rst_n), .start(start), .h_in(h_in),
                      .block(block), .t(t), .last(last), .h_out(h_out),
                      .done(done), .busy(busy));
    always #5 clk = ~clk;

    initial begin
        repeat (3) @(negedge clk);
        rst_n = 1;
        @(negedge clk);
        h_in = IV; block = 1024'h0; t = 64'd0; last = 1; start = 1;
        @(negedge clk); start = 0;
        cyc = 0;
        while (!done && cyc < 200) begin
            @(negedge clk);
            if (busy) begin
                $display("cyc %0d rnd %0d stage %0d v %h %h %h %h %h %h %h %h %h %h %h %h %h %h %h %h",
                    cyc, dut.rnd, dut.stage,
                    dut.v[0], dut.v[1], dut.v[2],  dut.v[3],
                    dut.v[4], dut.v[5], dut.v[6],  dut.v[7],
                    dut.v[8], dut.v[9], dut.v[10], dut.v[11],
                    dut.v[12],dut.v[13],dut.v[14], dut.v[15]);
            end
            cyc = cyc + 1;
        end
        $display("FINAL %h", h_out);
        $finish;
    end
endmodule
