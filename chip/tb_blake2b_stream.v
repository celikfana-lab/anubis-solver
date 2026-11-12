`timescale 1ns/1ps
// tb_blake2b_stream.v — byte-stream BLAKE2b against hashlib, incl. H0-length input.
module tb_blake2b_stream;
    localparam NC = 6;
    localparam BLOCK = 512;

    reg clk = 0, rst_n = 0, start = 0, wr_en = 0, flush = 0, finish = 0;
    reg [7:0] wr_byte = 0;
    reg [31:0] outlen = 64;
    wire [511:0] h_out;
    wire ready, full, done, busy;

    reg [7:0] mem [0:NC*BLOCK-1];
    integer c, k, guard, base, errs, caseerr;
    reg [63:0] len, want_word, got_word;
    reg [31:0] tau;

    blake2b_stream dut (.clk(clk), .rst_n(rst_n), .start(start), .outlen(outlen),
                        .wr_en(wr_en), .wr_byte(wr_byte), .flush(flush),
                        .finish(finish), .ready(ready), .full(full),
                        .h_out(h_out), .done(done), .busy(busy));
    always #5 clk = ~clk;

    initial begin
        for (k = 0; k < NC*BLOCK; k = k + 1) mem[k] = 8'h00;
        $readmemh("b2_vectors.hex", mem);
    end

    initial begin
        errs = 0;
        repeat (3) @(negedge clk);
        rst_n = 1;

        for (c = 0; c < NC; c = c + 1) begin
            base = c * BLOCK;
            len = 0; tau = 0;
            for (k = 0; k < 8; k = k + 1) len = len | ({{56{1'b0}}, mem[base+256+k]} << (8*k));
            for (k = 0; k < 4; k = k + 1) tau = tau | ({{24{1'b0}}, mem[base+264+k]} << (8*k));
            outlen = tau;

            @(negedge clk);
            start = 1;
            @(negedge clk);
            start = 0;

            // push the message; flush whenever a full block is buffered
            k = 0;
            guard = 0;
            while (k < len && guard < 20000) begin
                @(negedge clk);
                wr_en = 0; flush = 0;
                if (full) flush = 1;
                else if (ready) begin
                    wr_en = 1;
                    wr_byte = mem[base + k];
                    k = k + 1;
                end
                guard = guard + 1;
            end

            @(negedge clk);
            wr_en = 0; flush = 0; finish = 1;
            @(negedge clk);
            finish = 0;

            guard = 0;
            while (!done && guard < 5000) begin @(negedge clk); guard = guard + 1; end
            if (!done) begin
                $display("FAIL case %0d: timeout (len %0d)", c, len);
                $fatal;
            end

            caseerr = 0;
            for (k = 0; k < 8; k = k + 1) begin
                got_word = h_out[511 - 64*k -: 64];
                want_word = 0;
                for (guard = 0; guard < 8; guard = guard + 1)
                    want_word = want_word | ({{56{1'b0}}, mem[base+268+8*k+guard]} << (8*guard));
                if (64*k < 8*tau && got_word !== want_word) begin
                    $display("FAIL case %0d (len %0d, tau %0d) word %0d: got %016x want %016x",
                             c, len, tau, k, got_word, want_word);
                    errs = errs + 1; caseerr = caseerr + 1;
                end
            end
            if (caseerr == 0) $display("  case %0d: len %0d tau %0d OK", c, len, tau);
            @(negedge clk);
        end

        if (errs != 0) begin $display("tb_blake2b_stream: %0d mismatches", errs); $fatal; end
        $display("tb_blake2b_stream: all %0d vectors passed", NC);
        $finish;
    end
endmodule
