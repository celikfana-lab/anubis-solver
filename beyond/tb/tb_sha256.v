// tb_sha256.v — known-answer tests for the SHA-256 core.
`timescale 1ns/1ps
module tb_sha256;
    reg clk = 0, rst_n = 0, start = 0;
    reg [255:0] midstate;
    reg [511:0] block;
    wire [255:0] digest;
    wire done, busy;

    sha256_core dut (.clk(clk), .rst_n(rst_n), .start(start), .midstate(midstate),
                     .block(block), .digest(digest), .done(done), .busy(busy));

    always #5 clk = ~clk;

    localparam [255:0] IV =
        256'h6a09e667_bb67ae85_3c6ef372_a54ff53a_510e527f_9b05688c_1f83d9ab_5be0cd19;

    task check(input [511:0] b, input [255:0] want);
        integer guard;
        begin
            @(negedge clk);
            midstate = IV; block = b; start = 1;
            @(negedge clk); start = 0;
            guard = 0;
            while (!done && guard < 200) begin
                @(negedge clk); guard = guard + 1;
            end
            if (!done) begin
                $display("FAIL: timeout");
                $fatal;
            end
            if (digest !== want) begin
                $display("FAIL: got %h", digest);
                $display("      want %h", want);
                $fatal;
            end
            @(negedge clk);
        end
    endtask

    task check2(input [511:0] b0, input [511:0] b1, input [255:0] want);
        integer guard;
        reg [255:0] mid;
        begin
            @(negedge clk);
            midstate = IV; block = b0; start = 1;
            @(negedge clk); start = 0;
            guard = 0;
            while (!done && guard < 200) begin @(negedge clk); guard = guard + 1; end
            if (!done) begin $display("FAIL: timeout block0"); $fatal; end
            mid = digest;
            @(negedge clk);
            midstate = mid; block = b1; start = 1;
            @(negedge clk); start = 0;
            guard = 0;
            while (!done && guard < 200) begin @(negedge clk); guard = guard + 1; end
            if (!done) begin $display("FAIL: timeout block1"); $fatal; end
            if (digest !== want) begin
                $display("FAIL(2-block): got %h", digest);
                $display("               want %h", want);
                $fatal;
            end
            @(negedge clk);
        end
    endtask

    initial begin
        $dumpfile("build/tb_sha256.vcd");
        $dumpvars(0, tb_sha256);
        repeat (3) @(negedge clk);
        rst_n = 1;

        // "" (one block: 0x80, length 0)
        check({32'h80000000, {15{32'h0}}},
              256'he3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855);
        // "abc"
        check({32'h61626380, {14{32'h0}}, 32'h00000018},
              256'hba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad);
        // 56-byte vector, two blocks
        check2({32'h61626364,32'h62636465,32'h63646566,32'h64656667,
                32'h65666768,32'h66676869,32'h6768696a,32'h68696a6b,
                32'h696a6b6c,32'h6a6b6c6d,32'h6b6c6d6e,32'h6c6d6e6f,
                32'h6d6e6f70,32'h6e6f7071,32'h80000000,32'h00000000},
               {32'h00000000,{14{32'h00000000}},32'h000001c0},
               256'h248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1);
        $display("tb_sha256: all vectors passed");
        $finish;
    end
endmodule
