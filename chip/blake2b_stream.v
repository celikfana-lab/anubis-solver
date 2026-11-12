// blake2b_stream.v — byte-streaming BLAKE2b front end.
//
// Argon2 needs three kinds of BLAKE2b call, all unkeyed (fanout=1, depth=1):
//   * H0      — a fixed 40-byte prefix + password + salt + lengths, outlen 64
//   * H'      — a chained expansion producing 1024 bytes, outlen 64 (and 32 last)
//   * the tag — H'(64, last memory block), outlen 64
// All of them are byte-oriented and of arbitrary length, so this wrapper takes
// one byte per cycle and hands whole 128-byte blocks to blake2b_core.
//
// Handshake
//   ready      high while a byte may be accepted. It goes low while a block is
//              being compressed *and* once the 128-byte buffer is full.
//   flush      the buffered full block is not the last: compress it (last=0)
//              and keep accepting bytes. Only legal when full is high.
//   finish     the buffered block is the last: zero-pad, compress (last=1) and
//              emit the digest. finish wins over wr_en on the same cycle.
//   full       the buffer holds 128 bytes and needs a flush or finish.
//
// BLAKE2b has no length padding: the final block is just zero-padded and the
// byte counter t carries the length, so finish only has to clear the tail.

`timescale 1ns/1ps
module blake2b_stream (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,     // pulse: begin a new hash
    input  wire [31:0]  outlen,    // tau = digest length in bytes, 1..64
    input  wire         wr_en,
    input  wire [7:0]   wr_byte,
    input  wire         flush,
    input  wire         finish,
    output wire         ready,
    output wire         full,
    output reg  [511:0] h_out,     // word i in [511-64*i -: 64], digest bytes are LE
    output reg          done,
    output reg          busy
);
    localparam [63:0] IV0 = 64'h6a09e667f3bcc908, IV1 = 64'hbb67ae8584caa73b,
                      IV2 = 64'h3c6ef372fe94f82b, IV3 = 64'ha54ff53a5f1d36f1,
                      IV4 = 64'h510e527fade682d1, IV5 = 64'h9b05688c2b3e6c1f,
                      IV6 = 64'h1f83d9abfb41bd6b, IV7 = 64'h5be0cd19137e2179;

    localparam [1:0] S_IDLE = 2'd0, S_FILL = 2'd1, S_WAIT = 2'd2, S_DONE = 2'd3;

    reg [63:0] h    [0:7];
    reg [63:0] blk  [0:15];
    reg [3:0]  nw;          // word being filled
    reg [2:0]  nbyte;       // bytes already in blk[nw]
    reg        fullf;
    reg [63:0] total;       // bytes fed so far, including the block in flight
    reg [1:0]  state;
    reg        lastblk;     // the block under compression is the final one
    reg        firstblk;    // next block starts from IV, so it takes the parameter xor

    reg         core_start;
    reg  [511:0] core_hin;
    reg  [63:0]  core_t;
    reg          core_last;
    wire [511:0] core_hout;
    wire         core_done, core_busy;
    wire [1023:0] core_block = {blk[0], blk[1], blk[2],  blk[3],
                                blk[4], blk[5], blk[6],  blk[7],
                                blk[8], blk[9], blk[10], blk[11],
                                blk[12],blk[13],blk[14], blk[15]};
    wire [511:0] h_flat = {h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]};

    integer i;

    blake2b_core core (
        .clk(clk), .rst_n(rst_n), .start(core_start),
        .h_in(core_hin), .block(core_block), .t(core_t), .last(core_last),
        // the parameter block is xored into h[0] once per hash, not per block:
        // later blocks continue from a state that already carries it.
        .param_xor(firstblk ? (32'h01010000 | outlen) : 32'd0),
        .h_out(core_hout), .done(core_done), .busy(core_busy));

    assign ready = (state == S_FILL) && !fullf;
    assign full  = (state == S_FILL) && fullf;

    // low 8*nb bits set, used to clear the unused bytes of a partial word
    function [63:0] pad_mask(input [2:0] nb);
        case (nb)
            3'd0: pad_mask = 64'd0;
            3'd1: pad_mask = 64'h00000000000000ff;
            3'd2: pad_mask = 64'h000000000000ffff;
            3'd3: pad_mask = 64'h0000000000ffffff;
            3'd4: pad_mask = 64'h00000000ffffffff;
            3'd5: pad_mask = 64'h000000ffffffffff;
            3'd6: pad_mask = 64'h0000ffffffffffff;
            3'd7: pad_mask = 64'h00ffffffffffffff;
            default: pad_mask = 64'hffffffffffffffff;
        endcase
    endfunction

    always @(posedge clk) begin
        if (!rst_n) begin
            state      <= S_IDLE;
            busy       <= 1'b0;
            done       <= 1'b0;
            core_start <= 1'b0;
            nw         <= 4'd0;
            nbyte      <= 3'd0;
            fullf      <= 1'b0;
            total      <= 64'd0;
            lastblk    <= 1'b0;
            firstblk   <= 1'b0;
        end else begin
            core_start <= 1'b0;

            if (state == S_IDLE) begin
                done <= 1'b0;
                if (start) begin
                    h[0] <= IV0; h[1] <= IV1; h[2] <= IV2; h[3] <= IV3;
                    h[4] <= IV4; h[5] <= IV5; h[6] <= IV6; h[7] <= IV7;
                    nw <= 4'd0; nbyte <= 3'd0; fullf <= 1'b0;
                    total <= 64'd0; lastblk <= 1'b0; firstblk <= 1'b1;
                    busy <= 1'b1;
                    state <= S_FILL;
                end
            end else if (state == S_FILL) begin
                if (finish) begin
                    // zero-pad the tail, then compress as the final block
                    if (!fullf) begin
                        blk[nw] <= blk[nw] & pad_mask(nbyte);
                        for (i = 0; i < 16; i = i + 1)
                            if (i > nw) blk[i] = 64'd0;
                    end
                    core_hin <= h_flat;
                    core_t   <= total;
                    core_last<= 1'b1;
                    lastblk  <= 1'b1;
                    core_start <= 1'b1;
                    state <= S_WAIT;
                end else if (flush && fullf) begin
                    core_hin <= h_flat;
                    core_t   <= total;
                    core_last<= 1'b0;
                    lastblk  <= 1'b0;
                    core_start <= 1'b1;
                    state <= S_WAIT;
                end else if (wr_en) begin
                    // little-endian: byte k of a word goes to bits [8k+7:8k], so a
                    // partial word is right-aligned and pad_mask can trim the tail
                    if (nbyte == 3'd0) blk[nw] <= {56'd0, wr_byte};
                    else blk[nw] <= blk[nw] | ({56'd0, wr_byte} << {nbyte, 3'b000});
                    total   <= total + 64'd1;
                    if (nbyte == 3'd7) begin
                        nbyte <= 3'd0;
                        if (nw == 4'd15) fullf <= 1'b1;
                        else nw <= nw + 4'd1;
                    end else begin
                        nbyte <= nbyte + 3'd1;
                    end
                end
            end else if (state == S_WAIT) begin
                if (core_done) begin
                    firstblk <= 1'b0;   // later blocks continue from the xored state
                    for (i = 0; i < 8; i = i + 1) h[i] = core_hout[511 - 64*i -: 64];
                    if (lastblk) begin
                        h_out    <= core_hout;
                        done     <= 1'b1;
                        busy     <= 1'b0;
                        fullf    <= 1'b0;
                        nw       <= 4'd0;
                        nbyte    <= 3'd0;
                        state    <= S_DONE;
                    end else begin
                        fullf <= 1'b0;
                        nw    <= 4'd0;
                        nbyte <= 3'd0;
                        state <= S_FILL;
                    end
                end
            end else begin // S_DONE
                done  <= 1'b0;
                state <= S_IDLE;
            end
        end
    end
endmodule
