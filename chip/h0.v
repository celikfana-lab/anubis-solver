// h0.v — Argon2's H0, the initial 64-byte hash.
//
//   H0 = BLAKE2b-64(
//          LE32(p) || LE32(T) || LE32(m) || LE32(t) || LE32(v) || LE32(y)
//          || LE32(|P|) || P || LE32(|S|) || S || LE32(|K|) || K
//          || LE32(|X|) || X )
//
// Anubis runs Argon2id with p=1, T=32, m=19456, t=2, v=0x13, y=2, no secret
// key (K) and no associated data (X), password = the raw challenge bytes and
// salt = the 8-byte nonce. The fixed part of the message is generated here;
// the password streams in through p_addr / p_byte.

`timescale 1ns/1ps
module h0 #(
    parameter [31:0] P_LANES  = 32'd1,
    parameter [31:0] M_COST   = 32'd19456,
    parameter [31:0] T_COST   = 32'd2,
    parameter [31:0] VERSION  = 32'h00000013,
    parameter [31:0] TYPE_ID  = 32'd2
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [31:0]  plen,       // |P|
    input  wire [31:0]  taglen,     // T
    output wire [31:0]  p_addr,     // byte index into P
    input  wire [7:0]   p_byte,
    input  wire [63:0]  salt,       // the 8-byte nonce, little-endian
    output wire [511:0] h_out,
    output reg          done,
    output reg          busy
);
    // ---- blake2b_stream wiring -------------------------------------------
    reg         st_start, st_finish;
    reg         st_wr_en;
    reg  [7:0]  st_wr_byte;
    wire        st_ready, st_full, st_done;
    wire        st_flush = st_full;
    wire [511:0] st_hout;

    blake2b_stream stream (
        .clk(clk), .rst_n(rst_n), .start(st_start), .outlen(32'd64),
        .wr_en(st_wr_en), .wr_byte(st_wr_byte), .flush(st_flush),
        .finish(st_finish), .ready(st_ready), .full(st_full),
        .h_out(st_hout), .done(st_done), .busy());

    assign h_out = st_hout;

    // ---- message layout ---------------------------------------------------
    // 24 parameter bytes, 4 length bytes, |P| password bytes, LE32(8), the
    // 8 salt bytes, then LE32(0) and LE32(0) for the empty K and X.
    wire [191:0] hdr = {TYPE_ID, VERSION, T_COST, M_COST, taglen, P_LANES};
    wire [31:0]  saltlen = 32'd8;
    wire [31:0]  c_p   = 32'd24;              // |P| length field
    wire [31:0]  c_pw  = 32'd28;              // first password byte
    wire [31:0]  c_sl  = 32'd28 + plen;       // |S| length field
    wire [31:0]  c_s   = 32'd32 + plen;       // first salt byte
    wire [31:0]  c_k   = 32'd40 + plen;       // |K| = 0
    wire [31:0]  c_x   = 32'd44 + plen;       // |X| = 0
    wire [31:0]  total = 32'd48 + plen;

    localparam [2:0] S_IDLE = 3'd0, S_FEED = 3'd1, S_FIN = 3'd2, S_WAIT = 3'd3,
                     S_DONE = 3'd4;
    reg [2:0]  state;
    reg [31:0] k;                             // byte index in the message

    // one byte per cycle, chosen by where k sits in the layout
    reg [7:0] cur_byte;
    always @(*) begin
        if (k < c_p)              cur_byte = hdr[8*k[4:0] +: 8];
        else if (k < c_pw)        cur_byte = plen[8*(k - c_p) +: 8];
        else if (k < c_sl)        cur_byte = p_byte;
        else if (k < c_s)         cur_byte = saltlen[8*(k - c_sl) +: 8];
        else if (k < c_k)         cur_byte = salt[8*(k - c_s) +: 8];
        else                      cur_byte = 8'h00;   // LE32(0) for K and X
    end
    assign p_addr = (k >= c_pw && k < c_sl) ? (k - c_pw) : 32'd0;

    wire feeding = (state == S_FEED) && (k < total);
    always @(*) begin
        st_wr_en   = feeding && st_ready;
        st_wr_byte = cur_byte;
    end

    always @(posedge clk) begin
        if (!rst_n) begin
            state <= S_IDLE; busy <= 1'b0; done <= 1'b0;
            st_start <= 1'b0; st_finish <= 1'b0;
            k <= 32'd0;
        end else begin
            st_start  <= 1'b0;
            st_finish <= 1'b0;
            if (state == S_IDLE) begin
                done <= 1'b0;
                if (start) begin
                    k <= 32'd0;
                    st_start <= 1'b1;
                    busy <= 1'b1;
                    state <= S_FEED;
                end
            end else if (state == S_FEED) begin
                if (st_wr_en) begin
                    if (k + 32'd1 == total) state <= S_FIN;
                    k <= k + 32'd1;
                end
            end else if (state == S_FIN) begin
                st_finish <= 1'b1;
                state <= S_WAIT;
            end else if (state == S_WAIT) begin
                if (st_done) state <= S_DONE;   // the core has the digest now
            end else begin
                done  <= 1'b1;
                busy  <= 1'b0;
                state <= S_IDLE;
            end
        end
    end
endmodule
