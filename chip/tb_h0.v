`timescale 1ns/1ps
// tb_h0.v — H0 against hashlib.
module tb_h0;
    localparam NC = 3, CASE = 272;

    reg clk = 0, rst_n = 0, start = 0;
    reg [31:0] plen = 0, taglen = 32;
    reg [63:0] salt = 0;
    wire [31:0] p_addr;
    reg [7:0] mem [0:NC*CASE-1];
    wire [7:0] p_byte = mem[base + p_addr];
    wire [511:0] h_out;
    wire done, busy;

    integer c, k, guard, errs, base, bad;
    reg [31:0] want;
    reg [63:0] word;

    h0 dut (.clk(clk), .rst_n(rst_n), .start(start), .plen(plen), .taglen(taglen),
            .p_addr(p_addr), .p_byte(p_byte), .salt(salt), .h_out(h_out),
            .done(done), .busy(busy));
    always #5 clk = ~clk;

    initial $readmemh("h0_vectors.hex", mem);

    initial begin
        errs = 0;
        repeat (3) @(negedge clk);
        rst_n = 1;
        for (c = 0; c < NC; c = c + 1) begin
            base = c * CASE;
            plen   = {mem[base+195], mem[base+194], mem[base+193], mem[base+192]};
            taglen = {mem[base+199], mem[base+198], mem[base+197], mem[base+196]};
            salt   = 0;
            for (k = 0; k < 8; k = k + 1) salt = salt | ({{56{1'b0}}, mem[base+200+k]} << (8*k));
            @(negedge clk);
            start = 1;
            @(negedge clk);
            start = 0;
            guard = 0;
            while (!done && guard < 5000) begin @(negedge clk); guard = guard + 1; end
            if (!done) begin $display("FAIL case %0d: timeout", c); $fatal; end
            bad = 0;
            for (k = 0; k < 8; k = k + 1) begin
                word = 0;
                for (guard = 0; guard < 8; guard = guard + 1)
                    word = word | ({{56{1'b0}}, mem[base+208+8*k+guard]} << (8*guard));
                if (h_out[511 - 64*k -: 64] !== word) begin
                    if (bad < 2)
                        $display("FAIL case %0d word %0d: got %016x want %016x",
                                 c, k, h_out[511-64*k -: 64], word);
                    bad = bad + 1;
                end
            end
            if (bad != 0) begin errs = errs + 1; end
            else $display("  case %0d: plen %0d taglen %0d OK", c, plen, taglen);
            @(negedge clk);
        end
        if (errs != 0) begin $display("tb_h0: %0d cases failed", errs); $fatal; end
        $display("tb_h0: all %0d cases passed", NC);
        $finish;
    end
endmodule
