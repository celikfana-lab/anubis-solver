// h_prime.v — Argon2 H' variable-length hash, byte in / byte out.
//
//   tau <= 64 :  H'(X) = BLAKE2b-tau( LE32(tau) || X )
//   tau >  64 :  r = tau/32 - 2
//                V1 = BLAKE2b-64( LE32(tau) || X )
//                Vi = BLAKE2b-64( V(i-1) )            for i = 2..r
//                V(r+1) = BLAKE2b-(tau-32r)( Vr )
//                out = V1[0:32] || .. || Vr[0:32] || V(r+1)[0:tau-32r]
//
// Argon2 uses H'(1024, block) to seed the first two memory blocks of each lane
// and H'(64, last block) for the tag. X is streamed from an external byte port
// (x_addr / x_byte) so a 1 KiB memory block never has to be buffered here.

`timescale 1ns/1ps
module h_prime (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,      // pulse: begin
    input  wire [31:0] tau,        // output length in bytes
    input  wire [31:0] xlen,       // |X| in bytes
    output wire [31:0] x_addr,     // byte index into X
    input  wire [7:0]  x_byte,
    output reg         out_we,
    output reg  [31:0] out_addr,
    output reg  [7:0]  out_data,
    output reg         done,
    output reg         busy
);
    // ---- blake2b_stream wiring -------------------------------------------
    reg         st_start;
    reg  [31:0] st_outlen;
    reg         st_wr_en;
    reg  [7:0]  st_wr_byte;
    reg         st_finish;
    wire        st_flush;             // buffer full: compress and keep going

    wire        st_ready, st_full, st_done;
    assign st_flush = st_full;
    wire [511:0] st_hout;

    blake2b_stream stream (
        .clk(clk), .rst_n(rst_n), .start(st_start), .outlen(st_outlen),
        .wr_en(st_wr_en), .wr_byte(st_wr_byte), .flush(st_flush), .finish(st_finish),
        .ready(st_ready), .full(st_full), .h_out(st_hout), .done(st_done), .busy());

    // ---- FSM --------------------------------------------------------------
    localparam [3:0] P_IDLE = 4'd0, P_PREFIX = 4'd1, P_X = 4'd2, P_V = 4'd3,
                     P_FIN = 4'd4, P_WAITD = 4'd5, P_LATCH = 4'd6, P_EMIT = 4'd7,
                     P_DONE = 4'd8;

    reg [3:0]  phase;
    reg [31:0] r;            // tau/32 - 2  (tau > 64 only)
    reg [31:0] lastlen;      // tau - 32*r
    reg [31:0] ncall_total;
    reg [31:0] call;         // 1..ncall_total
    reg [31:0] this_outlen;
    reg [31:0] emit_count;
    reg [31:0] out_base;     // bytes emitted by previous calls
    reg [31:0] n;            // byte index inside the current phase
    reg [31:0] xlen_r;
    reg [7:0]  vb [0:63];    // the V being emitted / re-fed

    // tau-derived sizes, so the first call is set up without waiting a cycle
    wire [31:0] r_c    = (tau > 32'd64) ? ((tau >> 5) - 32'd2) : 32'd0;
    wire [31:0] last_c = (tau > 32'd64) ? (tau - (((tau >> 5) - 32'd2) << 5)) : tau;
    wire [31:0] ncl_c  = (tau > 32'd64) ? ((tau >> 5) - 32'd1) : 32'd1;
    wire [31:0] ol1_c  = (tau > 32'd64) ? 32'd64 : tau;
    wire [31:0] ec1_c  = (tau > 32'd64) ? 32'd32 : tau;

    wire [1:0] src_sel = (phase == P_PREFIX) ? 2'd1 :
                         (phase == P_X)      ? 2'd2 :
                         (phase == P_V)      ? 2'd3 : 2'd0;
    wire src_valid = (src_sel != 2'd0) && (phase != P_FIN);

    reg [7:0] src_byte;
    always @(*) begin
        case (src_sel)
            2'd1:    src_byte = tau[8*n[1:0] +: 8];   // little-endian prefix
            2'd2:    src_byte = x_byte;
            2'd3:    src_byte = vb[n[5:0]];
            default: src_byte = 8'h00;
        endcase
    end

    assign x_addr = n;

    // drive the stream combinationally so a byte moves every ready cycle
    always @(*) begin
        st_wr_en   = src_valid && st_ready;
        st_wr_byte = src_byte;
    end

    integer i, j;

    always @(posedge clk) begin
        if (!rst_n) begin
            phase <= P_IDLE; busy <= 1'b0; done <= 1'b0;
            st_start <= 1'b0; st_finish <= 1'b0; st_outlen <= 32'd64;
            out_we <= 1'b0; out_addr <= 32'd0; out_data <= 8'd0;
            n <= 32'd0; call <= 32'd1; r <= 32'd0; lastlen <= 32'd64;
            ncall_total <= 32'd1; this_outlen <= 32'd64; emit_count <= 32'd32;
            out_base <= 32'd0; xlen_r <= 32'd0;
        end else begin
            st_start  <= 1'b0;
            st_finish <= 1'b0;
            out_we    <= 1'b0;

            if (phase == P_IDLE) begin
                done <= 1'b0;
                if (start) begin
                    r           <= r_c;
                    lastlen     <= last_c;
                    ncall_total <= ncl_c;
                    this_outlen <= ol1_c;
                    emit_count  <= ec1_c;
                    out_base    <= 32'd0;
                    call        <= 32'd1;
                    xlen_r      <= xlen;
                    n           <= 32'd0;
                    st_outlen   <= ol1_c;
                    st_start    <= 1'b1;
                    busy        <= 1'b1;
                    phase       <= P_PREFIX;
                end
            end else if (phase == P_PREFIX) begin
                if (st_wr_en) begin
                    if (n == 32'd3) begin n <= 32'd0; phase <= P_X; end
                    else n <= n + 32'd1;
                end
            end else if (phase == P_X) begin
                if (st_wr_en) begin
                    if (n + 32'd1 == xlen_r) begin n <= 32'd0; phase <= P_FIN; end
                    else n <= n + 32'd1;
                end
            end else if (phase == P_V) begin
                if (st_wr_en) begin
                    if (n == 32'd63) begin n <= 32'd0; phase <= P_FIN; end
                    else n <= n + 32'd1;
                end
            end else if (phase == P_FIN) begin
                st_finish <= 1'b1;
                phase <= P_WAITD;
            end else if (phase == P_WAITD) begin
                if (st_done) phase <= P_LATCH;
            end else if (phase == P_LATCH) begin
                // digest byte k is byte (k%8) of word (k/8); word i lives at
                // [511-64i -: 64] and its byte j (little-endian) at bit 8j
                for (i = 0; i < 8; i = i + 1)
                    for (j = 0; j < 8; j = j + 1)
                        vb[i*8+j] <= st_hout[448 - 64*i + 8*j +: 8];
                n <= 32'd0;
                phase <= P_EMIT;
            end else if (phase == P_EMIT) begin
                out_we   <= 1'b1;
                out_addr <= out_base + n;
                out_data <= vb[n[5:0]];
                if (n + 32'd1 == emit_count) begin
                    out_base <= out_base + emit_count;
                    n <= 32'd0;
                    if (call == ncall_total) begin
                        phase <= P_DONE;   // byte is registered this cycle
                    end else begin
                        call        <= call + 32'd1;
                        this_outlen <= (call + 32'd1 <= r) ? 32'd64 : lastlen;
                        emit_count  <= (call + 32'd1 <= r) ? 32'd32 : lastlen;
                        st_outlen   <= (call + 32'd1 <= r) ? 32'd64 : lastlen;
                        st_start    <= 1'b1;
                        phase       <= P_V;   // no LE32(tau) prefix after V1
                    end
                end else begin
                    n <= n + 32'd1;
                end
            end else if (phase == P_DONE) begin
                done  <= 1'b1;
                busy  <= 1'b0;
                phase <= P_IDLE;
            end
        end
    end
endmodule
