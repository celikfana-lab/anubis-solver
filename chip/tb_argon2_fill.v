// tb_argon2_fill.v — compares argon2_fill against gen_argon_vectors.py.
`timescale 1ns/1ps
module tb_argon2_fill;
    reg clk = 0, rst_n = 0, start = 0, xor_en = 1;
    reg [8191:0] prev, refb, dst;
    wire [8191:0] out;
    wire busy, done;
    integer guard, k;

    reg [63:0] m_prev [0:127];
    reg [63:0] m_ref  [0:127];
    reg [63:0] m_dst  [0:127];
    reg [63:0] m_exp  [0:127];

    argon2_fill dut (.clk(clk), .rst_n(rst_n), .start(start), .prev(prev),
                     .refb(refb), .dst(dst), .xor_en(xor_en), .out(out),
                     .busy(busy), .done(done));

    always #5 clk = ~clk;

    initial begin
        $readmemh("prev.hex", m_prev);
        $readmemh("ref.hex", m_ref);
        $readmemh("dst.hex", m_dst);
        $readmemh("expected.hex", m_exp);
        prev = 0; refb = 0; dst = 0;
        for (k = 0; k < 128; k = k + 1) begin
            prev = prev | ({8064'b0, m_prev[k]} << (64 * k));
            refb = refb | ({8064'b0, m_ref[k]} << (64 * k));
            dst  = dst  | ({8064'b0, m_dst[k]} << (64 * k));
        end
        repeat (3) @(negedge clk);
        rst_n = 1;
        @(negedge clk);
        start = 1;
        @(negedge clk);
        start = 0;
        guard = 0;
        while (!done && guard < 2000) begin
            @(negedge clk);
            guard = guard + 1;
        end
        if (!done) begin
            $display("FAIL: timeout");
            $fatal;
        end
        for (k = 0; k < 128; k = k + 1) begin
            if (((out >> (64 * k)) & 64'hFFFFFFFFFFFFFFFF) !== m_exp[k]) begin
                $display("FAIL: word %0d got %h want %h", k,
                         (out >> (64 * k)) & {64{1'b1}}, m_exp[k]);
                $fatal;
            end
        end
        $display("tb_argon2_fill: 128-word block matches the reference");
        $finish;
    end
endmodule
