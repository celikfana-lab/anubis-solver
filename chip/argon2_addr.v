// argon2_addr.v — Argon2id data-independent address generator (pass 0, slices 0-1).
//
// Argon2 builds the reference indices for the first half of the first pass from
// a pseudo-random stream rather than from the memory contents:
//
//   Z   = [pass, lane, slice, m', t, y, counter, 0, ... 0]   (128 x 64-bit)
//   A1  = G(0, Z)          G(prev, ref) = P(prev ^ ref) ^ prev ^ ref
//   A   = G(0, A1)
//
// so the block is produced by two fill_block passes with prev = 0 and no xor-in.
// A holds 128 pseudo-randoms; the caller uses index i%128 and asks for the next
// block (counter++) every 128 indices.
//
// Word order matches argon2_fill: word i is bits [64*i +: 64].

`timescale 1ns/1ps
module argon2_addr (
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,      // pulse: begin, counter = 0
    input  wire          next_blk,   // pulse: regenerate with counter + 1
    input  wire [31:0]   pass_i,
    input  wire [31:0]   lane_i,
    input  wire [31:0]   slice_i,
    input  wire [31:0]   mprime,     // m_cost in blocks
    input  wire [31:0]   tcost,
    input  wire [31:0]   ytype,
    output reg  [8191:0] blk,        // the 128 pseudo-randoms
    output reg           ready,      // blk is valid for this counter
    output reg           busy
);
    localparam [1:0] P_IDLE = 2'd0, P_GO1 = 2'd1, P_W1 = 2'd2, P_GO2 = 2'd3;

    reg [63:0]   counter;
    reg [8191:0] a1;
    reg          refsel;     // 0: Z, 1: A1
    reg          fill_start;
    wire [8191:0] fill_out;
    wire          fill_done, fill_busy;

    // Z: the six header words, then the counter, then zeros
    reg [8191:0] zblk;
    always @(*) begin
        zblk = 8192'd0;
        zblk[63:0]    = {32'd0, pass_i};
        zblk[127:64]  = {32'd0, lane_i};
        zblk[191:128] = {32'd0, slice_i};
        zblk[255:192] = {32'd0, mprime};
        zblk[319:256] = {32'd0, tcost};
        zblk[383:320] = {32'd0, ytype};
        zblk[447:384] = counter;
    end

    argon2_fill fill_u (
        .clk(clk), .rst_n(rst_n), .start(fill_start),
        .prev(8192'd0), .refb(refsel ? a1 : zblk), .dst(8192'd0), .xor_en(1'b0),
        .out(fill_out), .busy(fill_busy), .done(fill_done));

    always @(posedge clk) begin
        if (!rst_n) begin
            counter <= 64'd0; a1 <= 8192'd0; refsel <= 1'b0;
            fill_start <= 1'b0; blk <= 8192'd0;
            ready <= 1'b0; busy <= 1'b0;
        end else begin
            fill_start <= 1'b0;
            case (1'b1)
                (start): begin
                    counter <= 64'd1;   // Argon2 pre-increments before filling
                    ready   <= 1'b0;
                    busy    <= 1'b1;
                    refsel  <= 1'b0;
                    fill_start <= 1'b1;
                end
                (next_blk && !busy): begin
                    counter <= counter + 64'd1;
                    ready   <= 1'b0;
                    busy    <= 1'b1;
                    refsel  <= 1'b0;
                    fill_start <= 1'b1;
                end
                ((refsel == 1'b0) && fill_done): begin
                    a1     <= fill_out;      // A1 = G(0, Z)
                    refsel <= 1'b1;
                    fill_start <= 1'b1;      // A = G(0, A1)
                end
                (fill_done && (refsel == 1'b1)): begin
                    blk   <= fill_out;
                    ready <= 1'b1;
                    busy  <= 1'b0;
                end
                default: ;
            endcase
        end
    end
endmodule
