// tb_lpddr6.v — write then read back a 1 KiB block through the LPDDR6 adaptor,
// checks the data and reports the effective bandwidth at 1.6 GHz.
`timescale 1ns/1ps
module tb_lpddr6;
    localparam NPKT = 32;
    reg clk = 0, rst_n = 0, start = 0, we = 1;
    reg [31:0] addr = 32'h0000_1000;
    reg [NPKT*256-1:0] wdata;
    wire [NPKT*256-1:0] rdata;
    wire done, busy, req_valid, req_we, req_ready, rsp_valid;
    wire [31:0] req_addr;
    wire [255:0] req_wdata, rsp_rdata;
    wire [63:0] bytes_moved, accesses;
    integer k, cycles;
    reg [63:0] t0, t1;

    lpddr6_if #(.NPKT(NPKT)) u_if (
        .clk(clk), .rst_n(rst_n), .start(start), .we(we), .byte_addr(addr),
        .wdata(wdata), .rdata(rdata), .done(done), .busy(busy),
        .req_valid(req_valid), .req_we(req_we), .req_addr(req_addr),
        .req_wdata(req_wdata), .req_ready(req_ready),
        .rsp_valid(rsp_valid), .rsp_rdata(rsp_rdata));

    lpddr6_model #(.LAT(24), .DEPTH(32768)) u_mem (
        .clk(clk), .rst_n(rst_n), .req_valid(req_valid), .req_we(req_we),
        .req_addr(req_addr), .req_wdata(req_wdata), .req_ready(req_ready),
        .rsp_valid(rsp_valid), .rsp_rdata(rsp_rdata),
        .bytes_moved(bytes_moved), .accesses(accesses));

    always #5 clk = ~clk;

    task run(input wr);
        begin
            we = wr;
            @(negedge clk);
            start = 1;
            @(negedge clk);
            start = 0;
            cycles = 0;
            while (!done && cycles < 100000) begin
                @(negedge clk);
                cycles = cycles + 1;
            end
            if (!done) begin $display("FAIL: timeout"); $fatal; end
        end
    endtask

    initial begin
        for (k = 0; k < NPKT; k = k + 1) begin
            wdata[k*256 +: 256] <= 256'h0;
            wdata[k*256 +: 256] <= {4{64'h1122334455667788 ^ k}};
        end
        repeat (3) @(negedge clk);
        rst_n = 1;
        run(1'b1);
        t0 = 64'd0;
        $display("write: %0d cycles, %0d bytes", cycles, bytes_moved);
        run(1'b0);
        for (k = 0; k < NPKT; k = k + 1) begin
            if (rdata[k*256 +: 256] !== {4{64'h1122334455667788 ^ k}}) begin
                $display("FAIL: packet %0d = %h", k, rdata[k*256 +: 256]);
                $fatal;
            end
        end
        $display("read: %0d cycles, %0d bytes", cycles, bytes_moved);
        $display("tb_lpddr6: 1 KiB block round-trip OK through 32 x 32-byte packets");
        // effective bandwidth of the read burst at 1.6 GHz
        $display("read bandwidth @1.6GHz: %0.2f GB/s (1 packet / %0d cycles)",
                 (1024.0 * 1.6e9) / (cycles * 1.0e9), cycles / NPKT);
        $finish;
    end
endmodule
