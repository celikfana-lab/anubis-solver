`timescale 1ns/1ps
// tb_argon2_addr.v — Argon2id address blocks against the Python reference.
module tb_argon2_addr;
    localparam NC = 5, CASE = 136;   // 8 parameter lines + 128 words

    reg clk = 0, rst_n = 0, start = 0, next_blk = 0;
    reg [31:0] pass_i = 0, lane_i = 0, slice_i = 0, mprime = 0, tcost = 0, ytype = 0;
    wire [8191:0] blk;
    wire ready, busy;

    reg [63:0] mem [0:NC*CASE-1];
    integer c, k, guard, errs, base, bad;
    reg [63:0] ctr_target, want;

    argon2_addr dut (.clk(clk), .rst_n(rst_n), .start(start), .next_blk(next_blk),
                     .pass_i(pass_i), .lane_i(lane_i), .slice_i(slice_i),
                     .mprime(mprime), .tcost(tcost), .ytype(ytype),
                     .blk(blk), .ready(ready), .busy(busy));
    always #5 clk = ~clk;

    initial $readmemh("addr_vectors.hex", mem);

    task wait_ready;
        begin
            guard = 0;
            while (!ready && guard < 20000) begin @(negedge clk); guard = guard + 1; end
            if (!ready) begin $display("FAIL: timeout waiting for ready"); $fatal; end
        end
    endtask

    initial begin
        errs = 0;
        repeat (3) @(negedge clk);
        rst_n = 1;
        for (c = 0; c < NC; c = c + 1) begin
            base = c * CASE;
            pass_i  = mem[base+0]; lane_i   = mem[base+1];
            slice_i = mem[base+2]; mprime   = mem[base+3];
            tcost   = mem[base+4]; ytype    = mem[base+5];
            ctr_target = mem[base+6];
            @(negedge clk);
            start = 1;
            @(negedge clk);
            start = 0;
            wait_ready;
            // walk the counter up to the target so the increment path is covered
            while (dut.counter < ctr_target) begin
                @(negedge clk);
                next_blk = 1;
                @(negedge clk);
                next_blk = 0;
                wait_ready;
            end
            bad = 0;
            for (k = 0; k < 128; k = k + 1) begin
                want = mem[base + 8 + k];
                if (blk[64*k +: 64] !== want) begin
                    if (bad < 2)
                        $display("FAIL case %0d word %0d: got %016x want %016x",
                                 c, k, blk[64*k +: 64], want);
                    bad = bad + 1;
                end
            end
            if (bad != 0) errs = errs + 1;
            else $display("  case %0d: pass %0d slice %0d counter %0d OK",
                          c, pass_i, slice_i, ctr_target);
            @(negedge clk);
        end
        if (errs != 0) begin $display("tb_argon2_addr: %0d cases failed", errs); $fatal; end
        $display("tb_argon2_addr: all %0d cases passed", NC);
        $finish;
    end
endmodule
