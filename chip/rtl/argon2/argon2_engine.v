// argon2_engine.v — a complete Argon2id hash for one salt/nonce.
//
//   H0 = h0(P, salt)
//   B[0] = H'(1024, H0 || LE32(0) || LE32(0))
//   B[1] = H'(1024, H0 || LE32(1) || LE32(0))
//   for pass in 0..t-1, slice in 0..3, index in first..seg-1:
//       prev = cur-1 (or the last block of the lane when cur == 0)
//       jour = pass == 0 && slice < 2
//       prand = jour ? A[index % 128] : mem[prev].v[0]
//       ref = index_alpha(pass, slice, index, prand)
//       mem[cur] = G(mem[prev], mem[ref], mem[cur], xor = pass > 0)
//   tag = H'(taglen, mem[lane_len-1])
//
// One lane (p = 1), as Anubis uses. Memory is internal, M_COST blocks of 1 KiB.

`timescale 1ns/1ps
module argon2_engine #(
    parameter [31:0] M_COST  = 32'd64,
    parameter [31:0] T_COST  = 32'd2,
    parameter [31:0] TAGLEN  = 32'd32,
    parameter [31:0] VERSION = 32'h00000013,
    parameter [31:0] TYPE_ID = 32'd2
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [31:0]  plen,        // |P|
    output wire [31:0]  p_addr,
    input  wire [7:0]   p_byte,
    input  wire [63:0]  salt,
    output reg  [255:0] tag_out,     // TAGLEN bytes, byte k at [8k +: 8]
    output reg          done,
    output reg          busy
);
    localparam [31:0] LANE_LEN = M_COST;
    localparam [31:0] SEG_LEN  = M_COST / 4;

    reg [8191:0] mem [0:M_COST-1];

    // ---- submodules -------------------------------------------------------
    reg          h0_start;
    wire [511:0] h0_out;
    wire         h0_done, h0_busy;

    h0 #(.M_COST(M_COST), .T_COST(T_COST), .VERSION(VERSION), .TYPE_ID(TYPE_ID))
    h0_u (.clk(clk), .rst_n(rst_n), .start(h0_start), .plen(plen), .taglen(TAGLEN),
          .p_addr(p_addr), .p_byte(p_byte), .salt(salt),
          .h_out(h0_out), .done(h0_done), .busy(h0_busy));

    reg          hp_start;
    reg  [31:0]  hp_tau, hp_xlen;
    reg          xsrc;               // 0: seed header, 1: mem[lane_len-1]
    wire [31:0]  hp_xaddr;
    wire         hp_we;
    wire [31:0]  hp_oaddr;
    wire [7:0]   hp_odata;
    wire         hp_done, hp_busy;

    reg  [511:0]  h0_reg;
    reg  [8191:0] seed_reg;
    reg  [1023:0] tagbuf;
    reg           seed_j;
    reg  [8191:0] tagblk;

    // H0 bytes in digest order: byte k is byte (k%8) of word (k/8)
    function [7:0] h0byte(input [5:0] k);
        h0byte = h0_reg[448 - 64*(k[5:3]) + 8*(k[2:0]) +: 8];
    endfunction

    wire [7:0] xb = xsrc ? tagblk[8*hp_xaddr +: 8]
                        : (hp_xaddr < 32'd64) ? h0byte(hp_xaddr[5:0])
                        : (hp_xaddr == 32'd64) ? {7'd0, seed_j}
                        : 8'h00;

    h_prime hp_u (.clk(clk), .rst_n(rst_n), .start(hp_start), .tau(hp_tau),
                  .xlen(hp_xlen), .x_addr(hp_xaddr), .x_byte(xb),
                  .out_we(hp_we), .out_addr(hp_oaddr), .out_data(hp_odata),
                  .done(hp_done), .busy(hp_busy));

    reg          addr_start, addr_next;
    wire [8191:0] addr_blk;
    wire         addr_ready, addr_busy;

    argon2_addr addr_u (.clk(clk), .rst_n(rst_n), .start(addr_start),
                        .next_blk(addr_next), .pass_i(pass_c), .lane_i(32'd0),
                        .slice_i(slice_c), .mprime(M_COST), .tcost(T_COST),
                        .ytype(TYPE_ID), .blk(addr_blk), .ready(addr_ready),
                        .busy(addr_busy));

    // ---- fill control -----------------------------------------------------
    reg  [31:0] pass_c, slice_c, idx_c;
    reg  [1:0]  need_addr;           // 0 none, 1 slice start, 2 next block
    reg         addr_wait;           // skip the cycle where ready is still stale
    reg         fill_start;
    wire [8191:0] fill_out;
    wire         fill_done, fill_busy;

    wire [31:0] cur  = slice_c * SEG_LEN + idx_c;
    wire [31:0] prev = (cur == 32'd0) ? (LANE_LEN - 32'd1) : (cur - 32'd1);
    wire [31:0]   refi;
    wire [8191:0] prevblk = mem[prev];
    wire [8191:0] refblk  = mem[refi];
    wire [8191:0] dstblk  = mem[cur];

    wire data_indep = (pass_c == 32'd0) && (slice_c < 32'd2);
    wire [31:0] prand = data_indep ? addr_blk[64*idx_c[6:0] +: 32] : prevblk[31:0];

    argon2_index idx_u (.pass_i(pass_c), .slice_i(slice_c), .index_i(idx_c),
                        .lane_len(LANE_LEN), .seg_len(SEG_LEN),
                        .pseudo_rand(prand), .ref_index(refi));

    argon2_fill fill_u (.clk(clk), .rst_n(rst_n), .start(fill_start),
                        .prev(prevblk), .refb(refblk), .dst(dstblk),
                        .xor_en(pass_c != 32'd0),
                        .out(fill_out), .busy(fill_busy), .done(fill_done));

    // next-position bookkeeping, so the addressing decision is made once
    wire at_seg_end = (idx_c + 32'd1 == SEG_LEN);
    wire [31:0] n_idx   = at_seg_end ? 32'd0 : (idx_c + 32'd1);
    wire [31:0] ns_raw  = at_seg_end ? (slice_c + 32'd1) : slice_c;
    wire [31:0] n_slice = (ns_raw == 32'd4) ? 32'd0 : ns_raw;
    wire [31:0] n_pass  = (at_seg_end && slice_c == 32'd3) ? (pass_c + 32'd1) : pass_c;
    wire        n_di    = (n_pass == 32'd0) && (n_slice < 32'd2);
    wire [1:0]  n_need  = (!n_di)            ? 2'd0 :
                          (n_idx == 32'd0)   ? 2'd1 :   // slice entry
                          (n_idx[6:0] == 0)  ? 2'd2 :   // next address block
                                              2'd0;
    wire        last_block = (pass_c + 32'd1 == T_COST) && (slice_c == 32'd3) && at_seg_end;

    localparam [3:0] E_IDLE = 4'd0, E_H0 = 4'd1, E_H0W = 4'd2, E_SEED = 4'd3,
                     E_SEEDW = 4'd4, E_IDX = 4'd5, E_ADDRW = 4'd6,
                     E_FILLW = 4'd7, E_TAG = 4'd8, E_TAGW = 4'd9,
                     E_TAGW2 = 4'd10, E_DONE = 4'd11;
    reg [3:0] st;
    integer k;

    always @(posedge clk) begin
        if (!rst_n) begin
            st <= E_IDLE; busy <= 1'b0; done <= 1'b0; tag_out <= 256'd0;
            h0_start <= 1'b0; hp_start <= 1'b0; addr_start <= 1'b0;
            addr_next <= 1'b0; fill_start <= 1'b0;
            pass_c <= 32'd0; slice_c <= 32'd0; idx_c <= 32'd0;
            need_addr <= 2'd0; addr_wait <= 1'b0; seed_j <= 1'b0;
            hp_tau <= 32'd64; hp_xlen <= 32'd72; xsrc <= 1'b0;
        end else begin
            h0_start <= 1'b0; hp_start <= 1'b0;
            addr_start <= 1'b0; addr_next <= 1'b0; fill_start <= 1'b0;
            case (st)
                E_IDLE: if (start) begin
                    busy <= 1'b1; done <= 1'b0;
                    h0_start <= 1'b1;
                    st <= E_H0;
                end
                E_H0: st <= E_H0W;
                E_H0W: if (h0_done) begin
                    h0_reg <= h0_out;
                    seed_j <= 1'b0;
                    seed_reg <= 8192'd0;
                    hp_tau <= 32'd1024; hp_xlen <= 32'd72; xsrc <= 1'b0;
                    hp_start <= 1'b1;
                    st <= E_SEEDW;
                end
                E_SEEDW: begin
                    if (hp_we) seed_reg[8*hp_oaddr +: 8] <= hp_odata;
                    if (hp_done) begin
                        mem[{31'd0, seed_j}] <= seed_reg;
                        seed_reg <= 8192'd0;
                        if (!seed_j) begin
                            seed_j <= 1'b1;
                            hp_tau <= 32'd1024; hp_xlen <= 32'd72; xsrc <= 1'b0;
                            hp_start <= 1'b1;
                        end else begin
                            pass_c <= 32'd0; slice_c <= 32'd0; idx_c <= 32'd2;
                            need_addr <= 2'd1;          // first address block
                            st <= E_IDX;
                        end
                    end
                end
                E_IDX: begin
                    if (need_addr == 2'd1) begin
                        addr_start <= 1'b1;
                        addr_wait <= 1'b1;
                        st <= E_ADDRW;
                    end else if (need_addr == 2'd2) begin
                        addr_next <= 1'b1;
                        addr_wait <= 1'b1;
                        st <= E_ADDRW;
                    end else begin
                        fill_start <= 1'b1;
                        st <= E_FILLW;
                    end
                end
                E_ADDRW: begin
                    // ready is a level that stays high after the previous block,
                    // and this module only clears it once the new start is seen,
                    // so ignore it for one cycle before trusting it.
                    if (addr_wait) addr_wait <= 1'b0;
                    else if (addr_ready) begin
                        need_addr <= 2'd0;
                        st <= E_IDX;
                    end
                end
                E_FILLW: if (fill_done) begin
                    mem[cur] <= fill_out;
                    pass_c  <= n_pass;
                    slice_c <= n_slice;
                    idx_c   <= n_idx;
                    need_addr <= n_need;
                    if (last_block) begin
                        tagblk <= fill_out;         // last block of the lane
                        tagbuf <= 1024'd0;
                        st <= E_TAG;
                    end else begin
                        st <= E_IDX;
                    end
                end
                E_TAG: begin
                    hp_tau <= TAGLEN; hp_xlen <= 32'd1024; xsrc <= 1'b1;
                    hp_start <= 1'b1;
                    st <= E_TAGW;
                end
                E_TAGW: begin
                    if (hp_we) tagbuf[8*hp_oaddr +: 8] <= hp_odata;
                    if (hp_done) st <= E_TAGW2;
                end
                E_TAGW2: begin
                    for (k = 0; k < 32; k = k + 1)
                        tag_out[8*k +: 8] <= tagbuf[8*k +: 8];
                    st <= E_DONE;
                end
                E_DONE: begin
                    done <= 1'b1;
                    busy <= 1'b0;
                    st <= E_IDLE;
                end
                default: st <= E_IDLE;
            endcase
        end
    end
endmodule
