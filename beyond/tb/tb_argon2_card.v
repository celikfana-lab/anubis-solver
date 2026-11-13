`timescale 1ns/1ps
// tb_argon2_card.v — the whole 365-engine card: BAR0, console, engine array and
// eight HBM3e stacks, driven the way a host would drive it.
//
// The default configuration is a small one (NENG=24) so this stays a fast
// regression; `make card-argon2-max` runs the real design point at 365.
module tb_argon2_card;
    // Fast defaults: this test proves the wiring (BAR0 -> start pulse ->
    // engines -> 3 lanes -> 8 stacks -> id-tagged responses), so it uses a short
    // latency and block cost. `make card-argon2-max` runs the real design point
    // (LAT=350, CYC=133, NENG=365), which is the configuration SPEED.md quotes.
    parameter integer NENG   = 12;
    parameter integer KCTX   = 3;
    parameter integer NSTACK = 8;
    parameter integer NPORT  = 3;
    parameter integer BW     = 1228;
    parameter integer LAT    = 40;
    parameter integer EFF    = 100;
    parameter integer CYC    = 20;
    parameter integer WARMUP = 200;      // cycles before measuring
    parameter integer WINDOW = 200;      // cycles measured
    parameter integer CLK_HZ = 1_000_000_000;

    reg clk = 0, rst_n = 0;
    always #5 clk = ~clk;

    reg  [31:0] awaddr = 0;  reg awvalid = 0; wire awready;
    reg  [31:0] wdata = 0;   reg wvalid = 0;  wire wready;
    wire [1:0]  bresp;       wire bvalid;     reg bready = 0;
    reg  [31:0] araddr = 0;  reg arvalid = 0; wire arready;
    wire [31:0] rdata;       wire [1:0] rresp; wire rvalid; reg rready = 0;

    wire        uart_tx;
    wire [31:0] blocks_done;
    wire [63:0] bytes_served, requests_served;
    wire        busy, done;
    wire [31:0] collisions, overflow;

    anubis_argon2_card #(.NENG(NENG), .KCTX(KCTX), .NSTACK(NSTACK), .NPORT(NPORT),
                         .BW(BW), .LAT(LAT), .EFF(EFF), .CYC_BLOCK(CYC),
                         .CLK_HZ(CLK_HZ)) dut (
        .clk(clk), .rst_n(rst_n),
        .s_axil_awaddr(awaddr), .s_axil_awvalid(awvalid), .s_axil_awready(awready),
        .s_axil_wdata(wdata), .s_axil_wstrb(4'hF), .s_axil_wvalid(wvalid),
        .s_axil_wready(wready), .s_axil_bresp(bresp), .s_axil_bvalid(bvalid),
        .s_axil_bready(bready),
        .s_axil_araddr(araddr), .s_axil_arvalid(arvalid),
        .s_axil_arready(arready), .s_axil_rdata(rdata), .s_axil_rresp(rresp),
        .s_axil_rvalid(rvalid), .s_axil_rready(rready),
        .uart_tx(uart_tx),
        .blocks_done(blocks_done), .bytes_served(bytes_served),
        .requests_served(requests_served), .busy(busy), .done(done),
        .memory_collisions(collisions), .memory_overflow(overflow));

    // same handshake as tb_axil: the slave's ready is a one-cycle pulse, so
    // waiting for it after deasserting valid deadlocks the master.
    task write_reg(input [31:0] a, input [31:0] d);
        begin
            @(negedge clk);
            awaddr = a; awvalid = 1; wdata = d; wvalid = 1; bready = 1;
            @(negedge clk);
            awvalid = 0; wvalid = 0;
            while (!bvalid) @(negedge clk);
            @(negedge clk);
            bready = 0;
        end
    endtask

    task read_reg(input [31:0] a, output [31:0] d);
        begin
            @(negedge clk);
            araddr = a; arvalid = 1; rready = 1;
            @(negedge clk);
            arvalid = 0;
            while (!rvalid) @(negedge clk);
            d = rdata;
            @(negedge clk);
            rready = 0;
        end
    endtask

    reg [31:0] id_reg;
    integer i, blk0, req0;
    reg [63:0] by0;
    real bpc, hps, reqpc;
    reg uart_seen;

    initial begin
        uart_seen = 0;
        repeat (3) @(negedge clk);
        rst_n = 1;
        @(negedge clk);

        read_reg(32'h000, id_reg);
        if (id_reg !== 32'hA0B15C01) begin
            $display("FAIL: BAR0 ID reads %h, want A0B15C01", id_reg);
            $fatal;
        end

        write_reg(32'h004, 32'h1);              // CTRL.start -> one-cycle pulse

        // The first block needs a request round trip (LAT=350) plus the block's
        // 133 cycles of compute, and there are 3 contexts per engine competing
        // for the datapath, so measure after the pipeline has filled.
        for (i = 0; i < WARMUP; i = i + 1) @(negedge clk);
        blk0 = blocks_done;
        by0  = bytes_served;
        req0 = requests_served;

        for (i = 0; i < WINDOW; i = i + 1) begin
            @(negedge clk);
            if (uart_tx === 1'b0) uart_seen = 1;   // the banner is going out
        end

        bpc   = (bytes_served - by0) * 1.0 / WINDOW;
        reqpc = (requests_served - req0) * 1.0 / WINDOW;
        hps   = (bpc / 3584.0) * (CLK_HZ / 1.0) / 38912.0;

        $display("card: NENG=%0d x KCTX=%0d = %0d hashes in flight, %0d HBM3e stacks, %0d lanes",
                 NENG, KCTX, NENG*KCTX, NSTACK, NPORT);
        $display("  BAR0 ID=%h, busy=%b done=%b, console %0s",
                 id_reg, busy, done, uart_seen ? "started" : "silent");
        $display("  %0d cycles: %0d blocks, %0d requests (%.3f/cycle), %.1f B/cycle (%.0f GB/s) of %0d",
                 WINDOW, blocks_done - blk0, requests_served - req0, reqpc,
                 bpc, bpc, NSTACK * BW);
        $display("  throughput: %.0f hashes/s at 1 GHz, collisions=%0d overflow=%0d",
                 hps, collisions, overflow);

        if ((blocks_done - blk0) < 1) begin
            $display("FAIL: the engines never completed a block");
            $fatal;
        end
        if (overflow != 0) begin
            $display("FAIL: %0d responses were dropped by the memory", overflow);
            $fatal;
        end
        $display("tb_argon2_card: PASS");
        $finish;
    end
endmodule
