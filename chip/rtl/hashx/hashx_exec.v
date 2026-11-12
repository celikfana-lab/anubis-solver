// hashx_exec.v — the HashX virtual machine.
//
// Eight 64-bit registers, one instruction per cycle, up to 512 instructions
// and at most one backward branch (the real programs take it once, then run
// off the end). This mirrors hashx_program_execute() in src/hashx/hashx.c
// line for line, including the quirk that `result` - the value BRANCH tests -
// is only written by the two high-multiply opcodes.
//
// The program lives outside (a ROM or a port), as it does for the GPU
// backends: hashx_export() hands over (opcode, dst, src, imm32).

`timescale 1ns/1ps
module hashx_exec (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [511:0] r_init,      // r0 in [63:0]
    input  wire [31:0]  ninstr,
    output wire [8:0]   prog_addr,
    input  wire [127:0] prog_data,   // {op, dst, src, imm32}
    output reg  [511:0] r_out,
    output reg          done,
    output reg          busy
);
    localparam [3:0] OP_UMULH_R  = 4'd0,  OP_SMULH_R = 4'd1,  OP_MUL_R  = 4'd2,
                     OP_SUB_R    = 4'd3,  OP_XOR_R   = 4'd4,  OP_ADD_RS = 4'd5,
                     OP_ROR_C    = 4'd6,  OP_ADD_C   = 4'd7,  OP_XOR_C  = 4'd8,
                     OP_TARGET   = 4'd9,  OP_BRANCH  = 4'd10;

    reg [63:0]  r [0:7];
    reg [9:0]   pc, target;
    reg         branch_enable;
    reg [31:0]  result;
    reg [511:0] regs;            // flattened copy for the output port
    reg         st_busy;

    assign prog_addr = pc[8:0];

    // hashx_export emits four consecutive u32 per instruction: op, dst, src,
    // imm32. Pack them in that order, most significant first.
    wire [3:0]  op  = prog_data[99:96];    // [127:96] is the opcode
    wire [2:0]  dst = prog_data[66:64];    // [95:64]  is dst
    wire [2:0]  src = prog_data[34:32];    // [63:32]  is src
    wire [31:0] imm = prog_data[31:0];

    wire [63:0] rd = r[dst];
    wire [63:0] rs = r[src];
    wire [127:0] prod  = rd * rs;                    // unsigned
    wire [127:0] sprod = $signed(rd) * $signed(rs);  // signed
    wire [63:0] sext  = {{32{imm[31]}}, imm};
    wire [63:0] ror   = (rd >> imm[5:0]) | (rd << (64 - imm[5:0]));

    integer i;

    always @(posedge clk) begin
        if (!rst_n) begin
            busy <= 1'b0; done <= 1'b0; st_busy <= 1'b0;
            pc <= 10'd0; target <= 10'd0; branch_enable <= 1'b1;
            result <= 32'd0; r_out <= 512'd0;
            for (i = 0; i < 8; i = i + 1) r[i] = 64'd0;
        end else if (start) begin
            for (i = 0; i < 8; i = i + 1) r[i] = r_init[64*i +: 64];
            pc <= 10'd0;
            target <= 10'd0;
            branch_enable <= 1'b1;
            result <= 32'd0;
            busy <= 1'b1;
            done <= 1'b0;
            st_busy <= 1'b1;
        end else if (st_busy) begin
            if (pc >= ninstr[9:0]) begin
                regs = {r[7], r[6], r[5], r[4], r[3], r[2], r[1], r[0]};
                r_out <= regs;
                busy <= 1'b0;
                done <= 1'b1;
                st_busy <= 1'b0;
            end else begin
                case (op)
                    OP_UMULH_R: begin r[dst] <= prod[127:64];  result <= prod[127:64];  pc <= pc + 10'd1; end
                    OP_SMULH_R: begin r[dst] <= sprod[127:64]; result <= sprod[127:64]; pc <= pc + 10'd1; end
                    OP_MUL_R:   begin r[dst] <= prod[63:0];    pc <= pc + 10'd1; end
                    OP_SUB_R:   begin r[dst] <= rd - rs;       pc <= pc + 10'd1; end
                    OP_XOR_R:   begin r[dst] <= rd ^ rs;       pc <= pc + 10'd1; end
                    OP_ADD_RS:  begin r[dst] <= rd + (rs << imm[5:0]); pc <= pc + 10'd1; end
                    OP_ROR_C:   begin r[dst] <= ror;           pc <= pc + 10'd1; end
                    OP_ADD_C:   begin r[dst] <= rd + sext;     pc <= pc + 10'd1; end
                    OP_XOR_C:   begin r[dst] <= rd ^ sext;     pc <= pc + 10'd1; end
                    OP_TARGET:  begin target <= pc;           pc <= pc + 10'd1; end
                    OP_BRANCH: begin
                        if (branch_enable && ((result & imm) == 32'd0)) begin
                            pc <= target + 10'd1;      // the C: i = target, then ++i
                            branch_enable <= 1'b0;
                        end else begin
                            pc <= pc + 10'd1;
                        end
                    end
                    default: begin pc <= pc + 10'd1; end
                endcase
            end
        end else begin
            done <= 1'b0;
        end
    end
endmodule
