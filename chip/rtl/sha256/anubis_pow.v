// anubis_pow.v — nonce scanner for Anubis sha256-family challenges.
//
// The host precomputes the midstate after the full 64-byte prefix blocks and
// the padded block template with the nonce field zeroed. The core patches the
// nonce into `nonce_word` of block0, hashes 1-2 blocks and compares the
// digest against `difficulty` leading zero bits.
`timescale 1ns/1ps
module anubis_pow (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] midstate,
    input  wire [511:0] block0,
    input  wire [511:0] block1,
    input  wire [1:0]   nblocks,      // number of blocks after the midstate (1 or 2)
    input  wire [3:0]   nonce_word,   // which 32-bit word of block0
    input  wire         nonce_le,     // 0: big-endian nonce, 1: little-endian
    input  wire [5:0]   difficulty,   // leading zero bits
    input  wire [31:0]  nonce_start,
    output reg          busy,
    output reg          found,
    output reg  [31:0]  found_nonce,
    output reg  [255:0] found_digest
);
    reg [31:0] nonce;
    reg        phase;   // 0: block0, 1: block1
    reg        running;
    reg        waiting;
    wire [511:0] patched;
    wire [255:0] core_digest;
    wire         core_done, core_busy;
    reg          core_start;

    wire [31:0] nonce_be = nonce_le
        ? {nonce[7:0], nonce[15:8], nonce[23:16], nonce[31:24]}
        : nonce;

    genvar gi;
    generate
        for (gi = 0; gi < 16; gi = gi + 1) begin : patch
            assign patched[511 - 32*gi -: 32] =
                (gi == nonce_word) ? nonce_be : block0[511 - 32*gi -: 32];
        end
    endgenerate

    sha256_core core (
        .clk(clk), .rst_n(rst_n), .start(core_start),
        .midstate(phase ? core_digest : midstate),
        .block(phase ? block1 : patched),
        .digest(core_digest), .done(core_done), .busy(core_busy)
    );

    function automatic ok_bits;
        input [255:0] d;
        input [5:0]   diff;
        integer i;
        begin
            ok_bits = 1'b1;
            for (i = 0; i < 64; i = i + 1)
                if ((i < diff) && (d[255 - i] !== 1'b0)) ok_bits = 1'b0;
        end
    endfunction

    always @(posedge clk) begin
        if (!rst_n) begin
            busy         <= 1'b0;
            found        <= 1'b0;
            running      <= 1'b0;
            waiting      <= 1'b0;
            core_start   <= 1'b0;
            phase        <= 1'b0;
            nonce        <= 32'b0;
            found_nonce  <= 32'b0;
            found_digest <= 256'b0;
        end else begin
            core_start <= 1'b0;
            if (start && !found) begin
                nonce  <= nonce_start;
                phase  <= 1'b0;
                busy   <= 1'b1;
                running<= 1'b1;
                waiting<= 1'b1;
                core_start <= 1'b1;
            end else if (running && core_done && waiting) begin
                waiting <= 1'b0;
                if (phase == 1'b0 && nblocks == 2'd2) begin
                    phase <= 1'b1;
                    waiting <= 1'b1;
                    core_start <= 1'b1;
                end else if (ok_bits(core_digest, difficulty)) begin
                    found        <= 1'b1;
                    found_nonce  <= nonce;
                    found_digest <= core_digest;
                    running      <= 1'b0;
                    busy         <= 1'b0;
                end else begin
                    nonce <= nonce + 32'd1;
                    phase <= 1'b0;
                    waiting <= 1'b1;
                    core_start <= 1'b1;
                end
            end
        end
    end
endmodule
