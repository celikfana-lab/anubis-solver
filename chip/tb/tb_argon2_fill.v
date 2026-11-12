// tb_argon2_fill.v — compares argon2_fill against gen_argon_vectors.py.
//
// Two independent blocks are run back to back with no idle cycle between them:
// `start` rises on the very cycle `done` is observed, which is one cycle
// earlier than argon2_engine does it. The hand-off, not the permutation, is
// what breaks when the write-back path changes.
`timescale 1ns/1ps
module tb_argon2_fill;
    reg clk = 0, rst_n = 0, start = 0, xor_en = 1;
    reg [8191:0] prev, refb, dst;
    wire [8191:0] out;
    wire busy, done;
    integer guard, k, which;

    // entries 0..127 are block A, 128..255 are block B
    reg [63:0] m_prev [0:255];
    reg [63:0] m_ref  [0:255];
    reg [63:0] m_dst  [0:255];
    reg [63:0] m_exp  [0:255];

    argon2_fill dut (.clk(clk), .rst_n(rst_n), .start(start), .prev(prev),
                     .refb(refb), .dst(dst), .xor_en(xor_en), .out(out),
                     .busy(busy), .done(done));

    always #5 clk = ~clk;

    task automatic run_block(input integer off);
        integer j;
        reg [8191:0] e;
        begin
            prev = 0; refb = 0; dst = 0;
            for (j = 0; j < 128; j = j + 1) begin
                prev = prev | ({8064'b0, m_prev[off + j]} << (64 * j));
                refb = refb | ({8064'b0, m_ref [off + j]} << (64 * j));
                dst  = dst  | ({8064'b0, m_dst [off + j]} << (64 * j));
            end
            start = 1;
            @(negedge clk);
            start = 0;
            guard = 0;
            while (!done && guard < 2000) begin
                @(negedge clk);
                guard = guard + 1;
            end
            if (!done) begin
                $display("FAIL: timeout in block at %0d (busy=%b)", off, busy);
                $fatal;
            end
            for (j = 0; j < 128; j = j + 1) begin
                e = m_exp[off + j];
                if (((out >> (64 * j)) & 64'hFFFFFFFFFFFFFFFF) !== e) begin
                    $display("FAIL: block at %0d word %0d got %h want %h", off, j,
                             (out >> (64 * j)) & {64{1'b1}}, e);
                    $fatal;
                end
            end
        end
    endtask

    initial begin
        $readmemh("vectors/prev.hex", m_prev);
        $readmemh("vectors/ref.hex", m_ref);
        $readmemh("vectors/dst.hex", m_dst);
        $readmemh("vectors/expected.hex", m_exp);
        prev = 0; refb = 0; dst = 0;
        repeat (3) @(negedge clk);
        rst_n = 1;
        @(negedge clk);
        for (which = 0; which < 2; which = which + 1) run_block(128 * which);
        $display("tb_argon2_fill: 2 back-to-back 128-word blocks match the reference");
        $finish;
    end
endmodule
