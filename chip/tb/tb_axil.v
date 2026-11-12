`timescale 1ns/1ps
// tb_axil.v — drive BAR0 like a host would and check what the card sees.
module tb_axil;
    reg clk = 0, rst_n = 0;
    always #5 clk = ~clk;

    reg  [31:0] awaddr = 0; reg awvalid = 0; wire awready;
    reg  [31:0] wdata = 0;  reg wvalid = 0;  wire wready;
    wire [1:0]  bresp;      wire bvalid;     reg bready = 0;
    reg  [31:0] araddr = 0; reg arvalid = 0; wire arready;
    wire [31:0] rdata;      wire [1:0] rresp; wire rvalid; reg rready = 0;

    wire        start_pulse;
    wire [1:0]  algo;
    wire [63:0] nonce;
    wire [31:0] challenge_len;
    wire        challenge_we;
    wire [9:0]  challenge_addr;
    wire [31:0] challenge_wdata;

    reg         busy = 0, done = 0, hit = 0;
    reg  [7:0]  lz = 0;
    reg  [255:0] tag = 0;

    axil_regs dut (
        .clk(clk), .rst_n(rst_n),
        .s_axil_awaddr(awaddr), .s_axil_awvalid(awvalid), .s_axil_awready(awready),
        .s_axil_wdata(wdata), .s_axil_wstrb(4'hF), .s_axil_wvalid(wvalid),
        .s_axil_wready(wready), .s_axil_bresp(bresp), .s_axil_bvalid(bvalid),
        .s_axil_bready(bready),
        .s_axil_araddr(araddr), .s_axil_arvalid(arvalid), .s_axil_arready(arready),
        .s_axil_rdata(rdata), .s_axil_rresp(rresp), .s_axil_rvalid(rvalid),
        .s_axil_rready(rready),
        .start_pulse(start_pulse), .algo(algo), .nonce(nonce),
        .challenge_len(challenge_len), .challenge_we(challenge_we),
        .challenge_addr(challenge_addr), .challenge_wdata(challenge_wdata),
        .busy(busy), .done(done), .hit(hit), .lz(lz), .tag(tag));

    integer chip_writes = 0;
    reg [31:0] chip_mem [0:1023];
    always @(posedge clk)
        if (challenge_we) begin
            chip_mem[challenge_addr] = challenge_wdata;
            chip_writes = chip_writes + 1;
        end

    integer starts = 0;
    always @(posedge clk) if (start_pulse) starts = starts + 1;

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

    reg [31:0] rd;
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

    integer i;
    initial begin
        repeat (3) @(negedge clk);
        rst_n = 1;

        read_reg(32'h00, rd);
        if (rd !== 32'hA0B15C01) begin $display("FAIL: ID = %08x", rd); $finish; end
        $display("  ID reads %08x", rd);

        write_reg(32'h0C, 32'h89ABCDEF);      // nonce lo
        write_reg(32'h10, 32'h01234567);      // nonce hi
        write_reg(32'h14, 32'd32);            // challenge length
        if (nonce !== 64'h01234567_89ABCDEF) begin
            $display("FAIL: nonce = %016x", nonce); $finish;
        end
        if (challenge_len !== 32'd32) begin $display("FAIL: len = %0d", challenge_len); $finish; end
        $display("  nonce %016x, length %0d latched", nonce, challenge_len);

        // 32-byte challenge = 8 words through the auto-incrementing window
        for (i = 0; i < 8; i = i + 1)
            write_reg(32'h18, 32'hA0000000 + i);
        if (chip_writes != 8) begin $display("FAIL: %0d words written", chip_writes); $finish; end
        for (i = 0; i < 8; i = i + 1)
            if (chip_mem[i] !== 32'hA0000000 + i) begin
                $display("FAIL: word %0d = %08x", i, chip_mem[i]); $finish;
            end
        $display("  8 challenge words written through the window");

        // start pulse, algorithm, status
        write_reg(32'h04, 32'h0000_0009);     // algo=2 (argon2id), start=1
        if (starts != 1) begin $display("FAIL: %0d start pulses", starts); $finish; end
        if (algo !== 2'd2) begin $display("FAIL: algo = %0d", algo); $finish; end
        $display("  start pulse seen once, algo=%0d", algo);

        busy = 1; @(negedge clk);
        read_reg(32'h08, rd);
        if (rd[0] !== 1'b1) begin $display("FAIL: busy not set: %08x", rd); $finish; end
        busy = 0; done = 1; hit = 1; lz = 8'd13;
        read_reg(32'h08, rd);
        if (rd[1] !== 1'b1 || rd[2] !== 1'b1 || rd[15:8] !== 8'd13) begin
            $display("FAIL: status = %08x", rd); $finish;
        end
        $display("  status reads done=%0d hit=%0d lz=%0d", rd[1], rd[2], rd[15:8]);

        // digest words
        for (i = 0; i < 8; i = i + 1) tag[32*i +: 32] <= 32'h5A5A0000 + i;
        @(negedge clk);
        for (i = 0; i < 8; i = i + 1) begin
            read_reg(32'h40 + 4*i, rd);
            if (rd !== 32'h5A5A0000 + i) begin
                $display("FAIL: result %0d = %08x", i, rd); $finish;
            end
        end
        $display("  8 digest words read back");

        $display("tb_axil: BAR0 register block behaves");
        $finish;
    end
endmodule
