// axil_regs.v — BAR0 register file on AXI4-Lite.
//
// This is the part of a PCIe card you actually write. The TLP/PHY layer is
// vendor hard IP (Xilinx XDMA, Intel HIP, ...): it presents an AXI4-Lite slave
// that the host reaches through its BAR, and this block is what that slave
// drives. Bulk loads (the HashX program) belong on the IP's DMA stream rather
// than here.
//
// Register map (32-bit, byte addresses):
//   0x000 R  ID            0xA0B15C01
//   0x004 RW CTRL          [0] start, [1] abort, [3:2] algo (0 sha256, 1 hashx, 2 argon2id)
//   0x008 R  STATUS        [0] busy, [1] done, [2] hit, [15:8] leading zeros
//   0x00C RW NONCE_LO
//   0x010 RW NONCE_HI
//   0x014 RW CHALLENGE_LEN
//   0x018 W  CHALLENGE_DATA  word written at CH_INDEX*4, index auto-increments
//   0x01C RW CH_INDEX
//   0x040..0x05C R RESULT0..7   the 32-byte digest, little-endian words
//
// A write to CTRL with start set raises a one-cycle start pulse; the card's
// engine uses that to begin a search.

`timescale 1ns/1ps
module axil_regs (
    input  wire        clk,
    input  wire        rst_n,

    // AXI4-Lite slave
    input  wire [31:0] s_axil_awaddr,
    input  wire        s_axil_awvalid,
    output reg         s_axil_awready,
    input  wire [31:0] s_axil_wdata,
    input  wire [3:0]  s_axil_wstrb,
    input  wire        s_axil_wvalid,
    output reg         s_axil_wready,
    output reg  [1:0]  s_axil_bresp,
    output reg         s_axil_bvalid,
    input  wire        s_axil_bready,
    input  wire [31:0] s_axil_araddr,
    input  wire        s_axil_arvalid,
    output reg         s_axil_arready,
    output reg  [31:0] s_axil_rdata,
    output reg  [1:0]  s_axil_rresp,
    output reg         s_axil_rvalid,
    input  wire        s_axil_rready,

    // to the engine
    output reg         start_pulse,
    output reg  [1:0]  algo,
    output wire [63:0] nonce,
    output reg  [31:0] challenge_len,
    output reg         challenge_we,
    output reg  [9:0]  challenge_addr,   // word index
    output reg  [31:0] challenge_wdata,
    input  wire        busy,
    input  wire        done,
    input  wire        hit,
    input  wire [7:0]  lz,
    input  wire [255:0] tag
);
    localparam [31:0] ID = 32'hA0B1_5C01;

    assign nonce = {nonce_hi, nonce_lo};   // live, so the engine sees it at start

    reg [31:0] ctrl;
    reg [31:0] ch_index;
    reg [31:0] nonce_lo, nonce_hi;
    reg        aw_have;
    reg [31:0] aw_addr;
    reg        w_have;
    reg [31:0] w_data;
    reg        b_pending;

    wire [31:0] addr  = aw_have ? aw_addr : s_axil_awaddr;
    wire [8:0]  wword = addr[8:2];
    wire [8:0]  rword = s_axil_araddr[8:2];

    // read mux (the read address, not the write one)
    wire [31:0] tag_word = tag[s_axil_araddr[4:2] * 32 +: 32];
    wire        is_result = (s_axil_araddr >= 32'h40) && (s_axil_araddr < 32'h60);

    reg [31:0] rdata;
    always @(*) begin
        case (rword)
            9'h00:   rdata = ID;
            9'h01:   rdata = ctrl;
            9'h02:   rdata = {16'd0, lz, 5'd0, hit, done, busy};
            9'h03:   rdata = nonce_lo;
            9'h04:   rdata = nonce_hi;
            9'h05:   rdata = challenge_len;
            9'h06:   rdata = 32'd0;
            9'h07:   rdata = ch_index;
            default: rdata = 32'hDEAD_0000;
        endcase
    end

    // ---- write channel ----------------------------------------------------
    always @(posedge clk) begin
        if (!rst_n) begin
            s_axil_awready <= 1'b0; s_axil_wready <= 1'b0;
            s_axil_bvalid <= 1'b0;  s_axil_bresp <= 2'b00;
            s_axil_arready <= 1'b0; s_axil_rvalid <= 1'b0;
            s_axil_rdata <= 32'd0;  s_axil_rresp <= 2'b00;
            aw_have <= 1'b0; w_have <= 1'b0; b_pending <= 1'b0;
            ctrl <= 32'd0; ch_index <= 32'd0;
            nonce_lo <= 32'd0; nonce_hi <= 32'd0; challenge_len <= 32'd0;
            start_pulse <= 1'b0; algo <= 2'd0;
            challenge_we <= 1'b0; challenge_addr <= 10'd0; challenge_wdata <= 32'd0;
        end else begin
            start_pulse  <= 1'b0;
            challenge_we <= 1'b0;

            // accept AW and W independently, then commit once both are in
            s_axil_awready <= !aw_have && !b_pending;
            s_axil_wready  <= !w_have  && !b_pending;
            if (s_axil_awvalid && s_axil_awready) begin
                aw_have <= 1'b1; aw_addr <= s_axil_awaddr;
            end
            if (s_axil_wvalid && s_axil_wready) begin
                w_have <= 1'b1; w_data <= s_axil_wdata;
            end

            if (aw_have && w_have && !b_pending) begin
                aw_have <= 1'b0; w_have <= 1'b0;
                b_pending <= 1'b1; s_axil_bvalid <= 1'b1;
                case (addr[8:2])
                    9'h01: begin
                        ctrl <= w_data;
                        if (w_data[0]) start_pulse <= 1'b1;
                        algo  <= w_data[3:2];
                    end
                    9'h03: nonce_lo  <= w_data;
                    9'h04: nonce_hi  <= w_data;
                    9'h05: challenge_len <= w_data;
                    9'h06: begin
                        challenge_we    <= 1'b1;
                        challenge_addr  <= ch_index[9:0];
                        challenge_wdata <= w_data;
                        ch_index        <= ch_index + 32'd1;
                    end
                    9'h07: ch_index <= w_data;
                    default: ;
                endcase
            end

            if (s_axil_bvalid && s_axil_bready) begin
                s_axil_bvalid <= 1'b0; b_pending <= 1'b0;
            end

            // ---- read channel ---------------------------------------------
            s_axil_arready <= !s_axil_rvalid;
            if (s_axil_arvalid && s_axil_arready) begin
                s_axil_rvalid <= 1'b1;
                s_axil_rresp  <= 2'b00;
                s_axil_rdata  <= is_result ? tag_word : rdata;
            end else if (s_axil_rvalid && s_axil_rready) begin
                s_axil_rvalid <= 1'b0;
            end
        end
    end
endmodule
