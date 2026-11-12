`timescale 1ns/1ps
// tb_uart.v — two independent checks:
//   1. uart_tx framing, decoded from the serial line by a cycle-counting RX
//   2. uart_log text, captured at the uart_tx handshake (no serial decode)
module tb_uart;
    parameter integer CLK_HZ = 1_000_000;
    parameter integer BAUD   = 100_000;
    localparam integer DIV = CLK_HZ / BAUD;

    reg clk = 0, rst_n = 0;
    always #5 clk = ~clk;

    // ---------------- part 1: framing ------------------------------------
    reg        f_valid = 0;
    reg [7:0]  f_data = 0;
    wire       f_ready, f_tx;
    uart_tx #(.CLK_HZ(CLK_HZ), .BAUD(BAUD)) fmt (
        .clk(clk), .rst_n(rst_n), .tx_valid(f_valid), .tx_data(f_data),
        .tx_ready(f_ready), .tx(f_tx));

    reg [7:0] rx_byte;
    integer   i;
    reg [7:0] rx_hist [0:15];
    integer   nrx = 0;

    always begin
        @(negedge f_tx);
        repeat (DIV/2) @(posedge clk);          // middle of the start bit
        for (i = 0; i < 8; i = i + 1) begin
            repeat (DIV) @(posedge clk);
            rx_byte[i] = f_tx;
        end
        repeat (DIV) @(posedge clk);            // stop bit
        rx_hist[nrx] = rx_byte;
        nrx = nrx + 1;
    end

    task send(input [7:0] b);
        begin
            @(negedge clk);
            while (!f_ready) @(negedge clk);
            f_valid = 1; f_data = b;
            @(negedge clk);
            f_valid = 0;
            repeat (DIV * 10 + 20) @(posedge clk);
        end
    endtask

    // ---------------- part 2: log text -----------------------------------
    reg        ev_start = 0, ev_hit = 0;
    reg [63:0] nonce = 0;
    reg [7:0]  lz = 0;
    wire       l_tx;
    uart_log #(.CLK_HZ(CLK_HZ), .BAUD(BAUD) ) lg (
        .clk(clk), .rst_n(rst_n), .ev_start(ev_start), .ev_hit(ev_hit),
        .nonce(nonce), .lz(lz), .tx(l_tx));

    reg [7:0] txt [0:255];
    integer   ntxt = 0;
    always @(posedge clk)
        if (lg.tx_valid && lg.tx_ready) begin
            txt[ntxt] = lg.tx_byte;
            ntxt = ntxt + 1;
        end

    integer k, bad;
    task check_text(input integer len, input [511:0] want);
        integer m;
        begin
            if (ntxt < len) begin
                $display("FAIL: %0d bytes of text, wanted %0d", ntxt, len);
                $finish;
            end
            bad = 0;
            for (m = 0; m < len; m = m + 1)
                if (txt[m] !== want[8*(len-1-m) +: 8]) bad = bad + 1;
            $write("  text: ");
            for (m = 0; m < len; m = m + 1) $write("%c", txt[m]);
            $write("\n");
            if (bad != 0) begin
                $display("FAIL: %0d of %0d text bytes wrong", bad, len);
                $finish;
            end
            ntxt = 0;
        end
    endtask

    initial begin
        repeat (3) @(negedge clk);
        rst_n = 1;

        // part 1
        send(8'h55); send(8'h41); send(8'h00); send(8'hFF);
        if (nrx != 4) begin $display("FAIL: framed %0d bytes, wanted 4", nrx); $finish; end
        if (rx_hist[0] !== 8'h55 || rx_hist[1] !== 8'h41 ||
            rx_hist[2] !== 8'h00 || rx_hist[3] !== 8'hFF) begin
            $display("FAIL: decoded %02x %02x %02x %02x", rx_hist[0], rx_hist[1],
                     rx_hist[2], rx_hist[3]);
            $finish;
        end
        $display("  framing: 55 41 00 FF round-tripped");

        // part 2
        @(negedge clk); ev_start = 1;   // anchor to a negedge: a pulse
        @(negedge clk); ev_start = 0;   // set at a posedge misses one
        repeat (DIV * 10 * 11 + 120) @(posedge clk);
        check_text(11, 88'h414E5542495320_7631_0D0A);

        nonce = 64'h0000_0012_3456_789A; lz = 8'd13;
        @(negedge clk); ev_hit = 1;
        @(negedge clk); ev_hit = 0;
        repeat (DIV * 10 * 36 + 160) @(posedge clk);
        check_text(36, 288'h484954204E4F4E4345203078_30303030303031323334353637383941_204C5A20_3044_0D0A);

        $display("tb_uart: framing and log text both correct");
        $finish;
    end
endmodule
