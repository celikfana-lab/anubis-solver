`timescale 1ns/1ps
// tb_argon2_engine.v — one whole Argon2id hash against argon2-cffi, M_COST = 64.
module tb_argon2_engine;
    localparam NC = 3, M_COST = 64;

    reg clk = 0, rst_n = 0, start = 0;
    reg [31:0] plen = 0;
    reg [63:0] salt = 0;
    wire [31:0] p_addr;
    reg [7:0] pw [0:NC*192-1];
    wire [7:0] p_byte = pw[base + p_addr];
    wire [255:0] tag_out;
    wire done, busy;

    reg [255:0] v [0:NC*3-1];
    integer c, k, guard, errs, base, bad;
    reg [255:0] want;

    argon2_engine #(.M_COST(M_COST), .T_COST(2), .TAGLEN(32),
                    .VERSION(32'h13), .TYPE_ID(2))
    dut (.clk(clk), .rst_n(rst_n), .start(start), .plen(plen),
         .p_addr(p_addr), .p_byte(p_byte), .salt(salt),
         .tag_out(tag_out), .done(done), .busy(busy));
    always #5 clk = ~clk;

    initial begin
        $readmemh("engine_vectors.hex", v);
        $readmemh("engine_pw.hex", pw);
    end

    initial begin
        errs = 0;
        repeat (3) @(negedge clk);
        rst_n = 1;
        for (c = 0; c < NC; c = c + 1) begin
            base = c * 192;
            plen = v[c*3][63:32];   // the hex line occupies the low 64 bits
            salt = {v[c*3+1][31:0], v[c*3][31:0]};
            @(negedge clk);
            start = 1;
            @(negedge clk);
            start = 0;
            guard = 0;
            while (!done && guard < 4000000) begin @(negedge clk); guard = guard + 1; end
            if (!done) begin $display("FAIL case %0d: timeout after %0d cycles", c, guard); $fatal; end
            bad = 0;
            for (k = 0; k < 32; k = k + 1)
                if (tag_out[8*k +: 8] !== v[c*3+2][255-8*k -: 8]) begin
                    if (bad < 4)
                        $display("FAIL case %0d byte %0d: got %02x want %02x", c, k,
                                 tag_out[8*k +: 8], v[c*3+2][255-8*k -: 8]);
                    bad = bad + 1;
                end
            if (bad != 0) errs = errs + 1;
            else $display("  case %0d: plen %0d TAG OK (%0d cycles)", c, plen, guard);
            @(negedge clk);
        end
        if (errs != 0) begin $display("tb_argon2_engine: %0d cases failed", errs); $fatal; end
        $display("tb_argon2_engine: whole Argon2id hashes match argon2-cffi");
        $finish;
    end
endmodule
