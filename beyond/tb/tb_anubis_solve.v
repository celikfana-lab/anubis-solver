`timescale 1ns/1ps
// tb_anubis_solve.v — search nonces on the chip and check the Anubis rule.
//
//   password = hex_decoded(challenge)
//   salt     = uint64 nonce, LE when the last challenge byte >= 0x80 else BE
//   hit      = the 32-byte Argon2id tag starts with DIFF zero bits
module tb_anubis_solve;
    parameter M_COST  = 64;         // 19456 for the real Anubis parameters
    parameter DIFF    = 4;
    parameter NSTART  = 0;
    parameter MAXN    = 64;

    localparam NC = 1;
    reg clk = 0, rst_n = 0, start = 0;
    reg [31:0] plen = 0;
    reg [63:0] salt = 0, nonce = 0;
    wire [31:0] p_addr;
    reg [7:0] pw [0:255];
    wire [7:0] p_byte = pw[p_addr];
    wire [255:0] tag_out;
    wire done, busy;
    reg le;

    integer i, guard, tries, lz, hit;
    reg [7:0] x;

    argon2_engine #(.M_COST(M_COST), .T_COST(2), .TAGLEN(32),
                    .VERSION(32'h13), .TYPE_ID(2))
    dut (.clk(clk), .rst_n(rst_n), .start(start), .plen(plen),
         .p_addr(p_addr), .p_byte(p_byte), .salt(salt),
         .tag_out(tag_out), .done(done), .busy(busy));
    always #5 clk = ~clk;

    function integer leading_zero_bits(input [255:0] t);
        integer a, b, c;
        reg stop;
        begin
            c = 0; stop = 0;
            for (a = 0; a < 32; a = a + 1)
                for (b = 7; b >= 0; b = b - 1)
                    if (!stop) begin
                        if (!t[8*a + b]) c = c + 1;
                        else stop = 1;
                    end
            leading_zero_bits = c;
        end
    endfunction

    function [63:0] bswap(input [63:0] v);
        integer a;
        begin
            for (a = 0; a < 8; a = a + 1) bswap[8*a +: 8] = v[8*(7-a) +: 8];
        end
    endfunction

    initial begin
        for (i = 0; i < 256; i = i + 1) pw[i] = 8'h00;
        $readmemh("vectors/solve_challenge.hex", pw);
        plen = 64;                    // set below by counting the file
    end

    initial begin
        // count the challenge bytes loaded from the file
        #1;
        i = 255;
        while (i >= 0 && pw[i] === 8'h00) i = i - 1;
        plen = i + 1;
        le = (pw[i] >= 8'h80);
        $display("tb_anubis_solve: M_COST=%0d plen=%0d last=%02x %s nonce encoding",
                 M_COST, plen, pw[i], le ? "little-endian" : "big-endian");

        repeat (3) @(negedge clk);
        rst_n = 1;
        tries = 0;
        hit = 0;
        nonce = NSTART;
        while (tries < MAXN && !hit) begin
            salt = le ? nonce : bswap(nonce);
            @(negedge clk);
            start = 1;
            @(negedge clk);
            start = 0;
            guard = 0;
            while (!done && guard < 200000000) begin @(negedge clk); guard = guard + 1; end
            if (!done) begin $display("FAIL: timeout"); $fatal; end
            lz = leading_zero_bits(tag_out);
            tries = tries + 1;
            if (lz >= DIFF) begin
                hit = 1;
                $display("HIT nonce=%0d (0x%016x) leading_zero_bits=%0d >= %0d after %0d tries",
                         nonce, nonce, lz, DIFF, tries);
                $write("TAG ");
                for (i = 0; i < 32; i = i + 1) $write("%02x", tag_out[8*i +: 8]);
                $write("\n");
            end
            nonce = nonce + 1;
            @(negedge clk);
        end
        if (!hit) begin
            $display("no hit in %0d tries", tries);
            $finish;
        end
        $finish;
    end
endmodule
