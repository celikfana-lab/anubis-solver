`timescale 1ns/1ps
module tb_blake2b;
    reg clk = 0, rst_n = 0, start = 0, last = 1;
    reg [31:0] param_xor = 32'h01010040;   // unkeyed, 64-byte digest
    reg [511:0] h_in;
    reg [1023:0] block;
    reg [63:0] t;
    wire [511:0] h_out;
    wire done, busy;
    integer guard;

    localparam [511:0] IV =
        {64'h6a09e667f3bcc908, 64'hbb67ae8584caa73b,
         64'h3c6ef372fe94f82b, 64'ha54ff53a5f1d36f1,
         64'h510e527fade682d1, 64'h9b05688c2b3e6c1f,
         64'h1f83d9abfb41bd6b, 64'h5be0cd19137e2179};

    blake2b_core dut (.clk(clk), .rst_n(rst_n), .start(start), .h_in(h_in),
                      .block(block), .t(t), .last(last), .param_xor(param_xor), .h_out(h_out),
                      .done(done), .busy(busy));
    always #5 clk = ~clk;

    task check(input [1023:0] b, input [63:0] tt, input [511:0] want);
        begin
            @(negedge clk);
            h_in = IV; block = b; t = tt; last = 1; start = 1;
            @(negedge clk); start = 0;
            guard = 0;
            while (!done && guard < 200) begin @(negedge clk); guard = guard + 1; end
            if (!done) begin $display("FAIL: timeout"); $fatal; end
            if (h_out !== want) begin
                $display("FAIL: got %h", h_out);
                $display("      want %h", want);
                $fatal;
            end
            @(negedge clk);
        end
    endtask

    initial begin
        repeat (3) @(negedge clk);
        rst_n = 1;
        // 128 bytes of 'a'
        check({16{64'h6161616161616161}}, 64'd128,
              {64'ha73ef488f6716cfc, 64'hcaf30888471708d6,
               64'h955c867115e653c7, 64'ha743c922912dbcad,
               64'h3fef4710cbc2926b, 64'ha9d0c16e436ebfe7,
               64'h7fbf8067215b9e9a, 64'h3b8f3a1da97c9ded});
        // empty message: one zero block, t = 0, final
        check(1024'h0, 64'd0,
              {64'h03590142f7026a78, 64'h72d2522585fdc6c6,
               64'h614758e140472f91, 64'h19541ff717e2868a,
               64'h5358eeaf31105ed2, 64'h4bb04e9344648913,
               64'h55b748145b683a90, 64'hcee29bfe1a706fd5});
        // non-uniform block: bytes 0x00..0x7f (catches message word-order bugs)
        check({64'h0706050403020100, 64'h0f0e0d0c0b0a0908,
               64'h1716151413121110, 64'h1f1e1d1c1b1a1918,
               64'h2726252423222120, 64'h2f2e2d2c2b2a2928,
               64'h3736353433323130, 64'h3f3e3d3c3b3a3938,
               64'h4746454443424140, 64'h4f4e4d4c4b4a4948,
               64'h5756555453525150, 64'h5f5e5d5c5b5a5958,
               64'h6766656463626160, 64'h6f6e6d6c6b6a6968,
               64'h7776757473727170, 64'h7f7e7d7c7b7a7978}, 64'd128,
              {64'hdae2479c78e31923, 64'ha1c2be617f80fea5,
               64'h32ff193fa07f53a6, 64'h0e7e4bd6bfec7ee8,
               64'h043b33ac39f4cf8c, 64'h611ad1ddc4b0190f,
               64'h39a0100ffec14ae2, 64'h15d1a30dcc5d6c80});
        $display("tb_blake2b: all 3 vectors passed");
        $finish;
    end
endmodule
