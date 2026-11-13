`timescale 1ns/1ps
// tb_hashx_solve.v — search nonces with the HashX core, Anubis hit rule.
//
// Uses case 0 of vectors/hx_vectors.hex, whose challenge is the same as
// vectors/solve_challenge.hex, so a hit can be rechecked with
// tools/gen_hashx_vectors.c or the Python model.
module tb_hashx_solve;
    parameter DIFF = 8;
    parameter MAXN = 256;

    localparam CASE = 2058, MAXI = 512;

    reg clk = 0, rst_n = 0, start = 0;
    reg [255:0] keys = 0;
    reg [63:0]  nonce = 0;
    reg [31:0]  ninstr = 0;
    wire [8:0]  prog_addr;
    wire [127:0] prog_data;
    wire [255:0] tag;
    wire done, busy;

    reg [63:0]  mem [0:CASE-1];
    reg [127:0] prog [0:MAXI-1];
    assign prog_data = prog[prog_addr];

    hashx_top dut (.clk(clk), .rst_n(rst_n), .start(start),
                   .keys(keys), .nonce(nonce), .ninstr(ninstr),
                   .prog_addr(prog_addr), .prog_data(prog_data),
                   .tag(tag), .done(done), .busy(busy));
    always #5 clk = ~clk;

    integer k, guard, tries, lz, hit, i, n;
    reg [7:0] x;
    reg stop;

    function integer leading_zero_bits(input [255:0] t);
        integer a, b, c;
        reg s;
        begin
            c = 0; s = 0;
            for (a = 0; a < 32; a = a + 1)
                for (b = 7; b >= 0; b = b - 1)
                    if (!s) begin
                        if (!t[8*a + b]) c = c + 1;
                        else s = 1;
                    end
            leading_zero_bits = c;
        end
    endfunction

    initial $readmemh("vectors/hx_vectors.hex", mem);

    initial begin
        keys = {mem[3], mem[2], mem[1], mem[0]};
        ninstr = mem[4][31:0];
        for (k = 0; k < MAXI; k = k + 1)
            prog[k] = {mem[6+4*k][31:0], mem[7+4*k][31:0],
                       mem[8+4*k][31:0], mem[9+4*k][31:0]};
        $display("tb_hashx_solve: %0d instructions, difficulty %0d", ninstr, DIFF);
        repeat (3) @(negedge clk);
        rst_n = 1;
        tries = 0; hit = 0; nonce = 0;
        while (tries < MAXN && !hit) begin
            @(negedge clk);
            start = 1;
            @(negedge clk);
            start = 0;
            guard = 0;
            while (!done && guard < 5000) begin @(negedge clk); guard = guard + 1; end
            if (!done) begin $display("FAIL: timeout"); $fatal; end
            lz = leading_zero_bits(tag);
            tries = tries + 1;
            if (lz >= DIFF) begin
                hit = 1;
                $display("HIT nonce=%0d (0x%016x) leading_zero_bits=%0d >= %0d after %0d tries",
                         nonce, nonce, lz, DIFF, tries);
                $write("TAG ");
                for (i = 0; i < 32; i = i + 1) $write("%02x", tag[8*i +: 8]);
                $write("\n");
            end
            nonce = nonce + 1;
            @(negedge clk);
        end
        if (!hit) $display("no hit in %0d tries", tries);
        $finish;
    end
endmodule
