// hashx_top.v — one HashX hash: PRF, program, finalisation.
//
//   r[0..7] = siphash24_ctr_state512(keys, nonce)
//   execute the exported program on r[]
//   r0 += k0, r1 += k1, r6 += k2, r7 += k3
//   SIPROUND(r0..r3) and SIPROUND(r4..r7)      (independent, done in parallel)
//   out = {r0^r4, r1^r5, r2^r6, r3^r7}         (4 x 64-bit little-endian)
//
// The program is generated in software (hashx_init / hashx_export) from the
// challenge bytes and stays fixed for the whole nonce search, exactly as the
// CUDA and Level Zero backends consume it.

`timescale 1ns/1ps
module hashx_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] keys,        // k0 in [63:0] ... k3 in [255:192]
    input  wire [63:0]  nonce,
    input  wire [31:0]  ninstr,
    output wire [8:0]   prog_addr,
    input  wire [127:0] prog_data,
    output reg  [255:0] tag,         // byte k at [8k +: 8]
    output reg          done,
    output reg          busy
);
    localparam [2:0] S_IDLE = 3'd0, S_PRF = 3'd1, S_EXEC = 3'd2,
                     S_FIN = 3'd3, S_DONE = 3'd4;

    reg [2:0]    st;
    reg          prf_start, exe_start;
    wire [511:0] prf_r;
    wire         prf_done, prf_busy;
    wire [511:0] exe_r;
    wire         exe_done, exe_busy;
    reg  [511:0] r_in;
    reg  [255:0] lo, hi;             // {r3,r2,r1,r0} and {r7,r6,r5,r4} plus keys
    reg  [63:0]  nonce_r;
    reg  [255:0] keys_r;

    hashx_prf prf_u (
        .clk(clk), .rst_n(rst_n), .start(prf_start), .keys(keys_r),
        .nonce(nonce_r), .r_out(prf_r), .done(prf_done), .busy(prf_busy));

    hashx_exec exe_u (
        .clk(clk), .rst_n(rst_n), .start(exe_start), .r_init(r_in),
        .ninstr(ninstr), .prog_addr(prog_addr), .prog_data(prog_data),
        .r_out(exe_r), .done(exe_done), .busy(exe_busy));

    wire [255:0] lo_f, hi_f;
    sipround fin_lo (.s(lo), .o(lo_f));
    sipround fin_hi (.s(hi), .o(hi_f));

    always @(posedge clk) begin
        if (!rst_n) begin
            st <= S_IDLE; busy <= 1'b0; done <= 1'b0;
            prf_start <= 1'b0; exe_start <= 1'b0;
            tag <= 256'd0; r_in <= 512'd0; lo <= 256'd0; hi <= 256'd0;
            nonce_r <= 64'd0; keys_r <= 256'd0;
        end else begin
            prf_start <= 1'b0;
            exe_start <= 1'b0;
            case (st)
                S_IDLE: if (start) begin
                    keys_r    <= keys;
                    nonce_r   <= nonce;
                    busy      <= 1'b1;
                    done      <= 1'b0;
                    prf_start <= 1'b1;
                    st        <= S_PRF;
                end
                S_PRF: if (prf_done) begin
                    r_in      <= prf_r;
                    exe_start <= 1'b1;
                    st        <= S_EXEC;
                end
                S_EXEC: if (exe_done) begin
                    // r0 += k0, r1 += k1, r6 += k2, r7 += k3
                    // lo = {r3, r2, r1+k1, r0+k0}, r_i at [64i +: 64]
                    lo <= {exe_r[255:192],
                           exe_r[191:128],
                           exe_r[127:64] + keys_r[127:64],
                           exe_r[63:0]   + keys_r[63:0]};
                    // hi = {r7+k3, r6+k2, r5, r4}, r_i at [64i +: 64]
                    // hi = {r7+k3, r6+k2, r5, r4}
                    hi <= {exe_r[511:448] + keys_r[255:192],
                           exe_r[447:384] + keys_r[191:128],
                           exe_r[383:320],
                           exe_r[319:256]};
                    st <= S_FIN;
                end
                S_FIN: begin
                    // one SipRound on each half, then xor the halves
                    tag[63:0]    <= lo_f[63:0]    ^ hi_f[63:0];
                    tag[127:64]  <= lo_f[127:64]  ^ hi_f[127:64];
                    tag[191:128] <= lo_f[191:128] ^ hi_f[191:128];
                    tag[255:192] <= lo_f[255:192] ^ hi_f[255:192];
                    st <= S_DONE;
                end
                S_DONE: begin
                    done <= 1'b1;
                    busy <= 1'b0;
                    st   <= S_IDLE;
                end
            endcase
        end
    end
endmodule
