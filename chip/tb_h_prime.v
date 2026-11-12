`timescale 1ns/1ps
// tb_h_prime.v — H' against hashlib, driven through the external byte port.
module tb_h_prime;
    localparam NC = 4, CASE = 2056;

    reg clk = 0, rst_n = 0, start = 0;
    reg [31:0] tau = 64, xlen = 0;
    wire [31:0] x_addr;
    reg [7:0] mem [0:NC*CASE-1];
    wire [7:0] x_byte = mem[base + x_addr];
    wire out_we;
    wire [31:0] out_addr;
    wire [7:0] out_data;
    wire done, busy;

    reg [7:0] got [0:1023];
    integer c, k, guard, errs, base, olen;
    reg [31:0] want_len;
    reg [7:0] want_byte;

    h_prime dut (.clk(clk), .rst_n(rst_n), .start(start), .tau(tau), .xlen(xlen),
                 .x_addr(x_addr), .x_byte(x_byte),
                 .out_we(out_we), .out_addr(out_addr), .out_data(out_data),
                 .done(done), .busy(busy));
    always #5 clk = ~clk;

    initial $readmemh("hp_vectors.hex", mem);

    always @(posedge clk) if (out_we) got[out_addr] <= out_data;

    function [31:0] le32(input integer off);
        le32 = {mem[base+off+3], mem[base+off+2], mem[base+off+1], mem[base+off]};
    endfunction

    initial begin
        errs = 0;
        repeat (3) @(negedge clk);
        rst_n = 1;
        for (c = 0; c < NC; c = c + 1) begin
            base = c * CASE;
            xlen = le32(1024);
            tau  = le32(1028);
            @(negedge clk);
            start = 1;
            @(negedge clk);
            start = 0;
            guard = 0;
            while (!done && guard < 200000) begin @(negedge clk); guard = guard + 1; end
            if (!done) begin $display("FAIL case %0d: timeout", c); $fatal; end
            olen = 0;
            for (k = 0; k < tau; k = k + 1)
                if (got[k] !== mem[base + 1032 + k]) begin
                    if (olen < 4)
                        $display("FAIL case %0d (tau %0d) byte %0d: got %02x want %02x",
                                 c, tau, k, got[k], mem[base+1032+k]);
                    olen = olen + 1;
                end
            if (olen != 0) begin errs = errs + 1; $display("  case %0d: %0d bad bytes", c, olen); end
            else $display("  case %0d: tau %0d xlen %0d OK", c, tau, xlen);
            @(negedge clk);
        end
        if (errs != 0) begin $display("tb_h_prime: %0d cases failed", errs); $fatal; end
        $display("tb_h_prime: all %0d cases passed", NC);
        $finish;
    end
endmodule
