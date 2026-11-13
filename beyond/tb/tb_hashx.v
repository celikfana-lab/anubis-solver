`timescale 1ns/1ps
// tb_hashx.v — a whole HashX hash against the C reference in src/hashx.
//
// The program is staged from vectors/hx_vectors.hex, which
// tools/gen_hashx_vectors.c produces with hashx_init + hashx_export +
// hashx_hash: the same split the GPU backends use.
module tb_hashx;
    localparam NC = 5, CASE = 2058, MAXI = 512;

    reg clk = 0, rst_n = 0, start = 0;
    reg [255:0] keys = 0;
    reg [63:0]  nonce = 0;
    reg [31:0]  ninstr = 0;
    wire [8:0]  prog_addr;
    wire [127:0] prog_data;
    wire [255:0] tag;
    wire done, busy;

    reg [63:0]  mem [0:NC*CASE-1];
    reg [127:0] prog [0:MAXI-1];
    assign prog_data = prog[prog_addr];

    hashx_top dut (.clk(clk), .rst_n(rst_n), .start(start),
                   .keys(keys), .nonce(nonce), .ninstr(ninstr),
                   .prog_addr(prog_addr), .prog_data(prog_data),
                   .tag(tag), .done(done), .busy(busy));
    always #5 clk = ~clk;

    integer c, k, guard, errs, base, bad;
    reg [63:0] want;

    initial $readmemh("vectors/hx_vectors.hex", mem);

    initial begin
        errs = 0;
        repeat (3) @(negedge clk);
        rst_n = 1;
        for (c = 0; c < NC; c = c + 1) begin
            base = c * CASE;
            keys   = {mem[base+3], mem[base+2], mem[base+1], mem[base+0]};
            ninstr = mem[base+4][31:0];
            nonce  = mem[base+5];
            for (k = 0; k < MAXI; k = k + 1)
                prog[k] = {mem[base+6+4*k+0][31:0], mem[base+6+4*k+1][31:0],
                           mem[base+6+4*k+2][31:0], mem[base+6+4*k+3][31:0]};
            @(negedge clk);
            start = 1;
            @(negedge clk);
            start = 0;
            guard = 0;
            while (!done && guard < 20000) begin @(negedge clk); guard = guard + 1; end
            if (!done) begin $display("FAIL case %0d: timeout", c); $fatal; end
            bad = 0;
            for (k = 0; k < 4; k = k + 1) begin
                want = mem[base+2054+k];
                if (tag[64*k +: 64] !== want) begin
                    if (bad < 2)
                        $display("FAIL case %0d word %0d: got %016x want %016x",
                                 c, k, tag[64*k +: 64], want);
                    bad = bad + 1;
                end
            end
            if (bad != 0) errs = errs + 1;
            else $display("  case %0d: %0d instr, %0d cycles OK", c, ninstr, guard);
            @(negedge clk);
        end
        if (errs != 0) begin $display("tb_hashx: %0d/%0d failed", errs, NC); $fatal; end
        $display("tb_hashx: all %0d hashes match the C reference", NC);
        $finish;
    end
endmodule
