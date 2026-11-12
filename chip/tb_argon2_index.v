`timescale 1ns/1ps
// tb_argon2_index.v — index_alpha against the Argon2 reference arithmetic.
module tb_argon2_index;
    localparam NC = 70, L = 4;
    reg [63:0] mem [0:NC*L-1];
    reg [31:0] p, s, idx, prand, lane_len, seg;
    wire [31:0] ref_index;
    integer c, k, guard, errs, bad;
    reg [63:0] w;
    reg [31:0] want;

    argon2_index dut (.pass_i(p), .slice_i(s), .index_i(idx), .lane_len(lane_len),
                      .seg_len(seg), .pseudo_rand(prand), .ref_index(ref_index));

    initial $readmemh("index_vectors.hex", mem);

    initial begin
        errs = 0; bad = 0;
        for (c = 0; c < NC; c = c + 1) begin
            w = mem[c*L+0]; p = w[63:32]; s = w[31:0];
            w = mem[c*L+1]; idx = w[63:32]; prand = w[31:0];
            w = mem[c*L+2]; lane_len = w[63:32]; seg = w[31:0];
            w = mem[c*L+3]; want = w[31:0];
            #1;
            if (ref_index !== want) begin
                if (bad < 6)
                    $display("FAIL p=%0d s=%0d i=%0d pr=%08x ll=%0d seg=%0d: got %0d want %0d",
                             p, s, idx, prand, lane_len, seg, ref_index, want);
                bad = bad + 1;
            end
        end
        if (bad != 0) begin $display("tb_argon2_index: %0d/%0d failed", bad, NC); $fatal; end
        $display("tb_argon2_index: all %0d cases passed", NC);
        $finish;
    end
endmodule
