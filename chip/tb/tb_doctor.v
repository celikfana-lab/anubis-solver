`timescale 1ns/1ps
// tb_doctor.v — the self-test must PASS on a healthy chip and FAIL when a
// value is corrupted. The second half is the important one: a checker that
// cannot fail proves nothing.
module tb_doctor;
    parameter integer IDW = 10;

    reg clk = 0, rst_n = 0;
    always #5 clk = ~clk;

    reg  start = 0, fault = 0;
    wire busy, done, pass;
    wire [3:0] fail_mask;
    wire [63:0] argon_fold_seen, mem_seen_bitmap;
    wire [7:0] live_count;

    wire        mem_en, mem_req_valid;
    wire [31:0] mem_req_blk;
    wire [15:0] mem_req_bytes;
    wire [IDW-1:0] mem_req_id;
    reg         mem_req_ready = 1;
    reg         mem_resp_valid = 0;
    reg  [IDW-1:0] mem_resp_id = 0;

    doctor dut (.clk(clk), .rst_n(rst_n), .start(start), .fault_inject(fault),
                .busy(busy), .done(done), .pass(pass), .fail_mask(fail_mask),
                .argon_fold_seen(argon_fold_seen),
                .mem_seen_bitmap(mem_seen_bitmap), .live_count(live_count),
                .mem_en(mem_en), .mem_req_valid(mem_req_valid),
                .mem_req_blk(mem_req_blk), .mem_req_bytes(mem_req_bytes),
                .mem_req_id(mem_req_id), .mem_req_ready(mem_req_ready),
                .mem_resp_valid(mem_resp_valid), .mem_resp_id(mem_resp_id));

    // ---- stand-in for the HBM subsystem: answer every request once --------
    integer pend [0:255];
    integer wp = 0, rp = 0, k;
    always @(posedge clk) begin
        if (!rst_n) begin
            wp = 0; rp = 0;
            mem_resp_valid <= 0;
            mem_resp_id    <= 0;
        end else begin
            if (mem_req_valid && mem_req_ready) begin
                pend[wp % 256] = mem_req_id;
                wp = wp + 1;
            end
            if (wp > rp) begin
                mem_resp_valid <= 1;
                mem_resp_id    <= pend[rp % 256];
                rp = rp + 1;
            end else
                mem_resp_valid <= 0;
        end
    end

    integer guard, errors;
    task run_doctor(input inject, output failed);
        begin
            @(negedge clk);
            fault = inject;
            start = 1;
            @(negedge clk);
            start = 0;
            guard = 0;
            while (!done && guard < 200000) begin
                @(negedge clk);
                guard = guard + 1;
            end
            if (!done) begin
                $display("FAIL: doctor never finished (%0d cycles)", guard);
                $fatal;
            end
            failed = !pass;
            @(negedge clk);
        end
    endtask

    reg failed;

    initial begin
        repeat (3) @(negedge clk);
        rst_n = 1;
        @(negedge clk);

        // ---- healthy chip: must pass -------------------------------------
        run_doctor(0, failed);
        if (failed) begin
            $display("FAIL: doctor reported a fault on a healthy chip, fail_mask=%b", fail_mask);
            $fatal;
        end
        if (mem_seen_bitmap !== 64'hFFFFFFFFFFFFFFFF) begin
            $display("FAIL: memory test saw bitmap %h, wanted all 64", mem_seen_bitmap);
            $fatal;
        end
        $display("doctor: healthy -> PASS (argon fold %h, 64/64 memory responses, live=%0d)",
                 argon_fold_seen, live_count);

        // ---- corrupted expectation: must fail ----------------------------
        run_doctor(1, failed);
        if (!failed) begin
            $display("FAIL: doctor passed with fault_inject set - the checker is vacuous");
            $fatal;
        end
        if (fail_mask === 4'b0000) begin
            $display("FAIL: doctor failed but set no fail_mask bit");
            $fatal;
        end
        $display("doctor: injected fault -> FAIL, fail_mask=%b (ARGON,%0s SHA,%0s SIP,%0s MEM,%0s)",
                 fail_mask, fail_mask[0] ? "x" : "-", fail_mask[1] ? "x" : "-",
                 fail_mask[2] ? "x" : "-", fail_mask[3] ? "x" : "-");

        $display("tb_doctor: PASS - it detects a corrupted datapath and a clean one alike");
        $finish;
    end
endmodule
