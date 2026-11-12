// tb_pow.v — end-to-end PoW test: 64 bytes of 'a', 4-byte big-endian nonce,
// difficulty 8 leading zero bits. The first matching nonce is 83 and its digest
// starts with 00 8f a7 f1 ...
`timescale 1ns/1ps
module tb_pow;
    reg clk = 0, rst_n = 0, start = 0;
    reg [255:0] midstate;
    reg [511:0] block0, block1;
    reg [1:0] nblocks = 2'd1;
    reg nonce_le = 0;
    reg [3:0] nonce_word = 0;
    reg [5:0] difficulty = 6'd8;
    reg [31:0] nonce_start = 0;
    wire busy, found;
    wire [31:0] found_nonce;
    wire [255:0] found_digest;
    integer guard;

    anubis_pow dut (.clk(clk), .rst_n(rst_n), .start(start), .midstate(midstate),
                    .block0(block0), .block1(block1), .nblocks(nblocks),
                    .nonce_word(nonce_word), .nonce_le(nonce_le),
                    .difficulty(difficulty), .nonce_start(nonce_start),
                    .busy(busy), .found(found), .found_nonce(found_nonce),
                    .found_digest(found_digest));

    always #5 clk = ~clk;

    initial begin
        $dumpfile("build/tb_pow.vcd");
        $dumpvars(0, tb_pow);
        midstate = {32'hdf5bb81c, 32'he81e0626, 32'hfb45a894, 32'h4fd40f31,
                    32'hb25e6816, 32'hd6d499c1, 32'hab904929, 32'h00635e66};
        // nonce || 0x80 || zeros || bit length 0x220
        block0 = {32'h00000000, 32'h80000000,
                  32'h0,32'h0,32'h0,32'h0,32'h0,32'h0,32'h0,32'h0,
                  32'h0,32'h0,32'h0,32'h0,32'h0,32'h00000220};
        block1 = 512'h0;
        repeat (3) @(negedge clk);
        rst_n = 1;
        @(negedge clk);
        start = 1;
        @(negedge clk); start = 0;

        guard = 0;
        while (!found && guard < 200000) begin
            @(negedge clk); guard = guard + 1;
        end
        if (!found) begin
            $display("FAIL: no nonce found");
            $fatal;
        end
        if (found_nonce !== 32'd83) begin
            $display("FAIL: nonce %0d (expected 83)", found_nonce);
            $fatal;
        end
        if (found_digest !== 256'h008fa7f19286d1464dc7523e3d126b8f85294a070693759f73b7ba258152a12f) begin
            $display("FAIL: digest %h", found_digest);
            $fatal;
        end
        $display("tb_pow: found nonce %0d, digest %h", found_nonce, found_digest);
        $display("tb_pow: passed");
        $finish;
    end
endmodule
