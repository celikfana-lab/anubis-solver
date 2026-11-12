// blake2b_core.v — BLAKE2b-512 compression core, 2 cycles per round (24/block).
`timescale 1ns/1ps
module blake2b_core (
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,
    input  wire [511:0]  h_in,     // 8 x 64-bit, word i = [64*i +: 64]
    input  wire [1023:0] block,    // 16 x 64-bit message words
    input  wire [63:0]   t,        // bytes processed so far (incl. this block)
    input  wire          last,     // final block flag
    input  wire [31:0]   param_xor,// 0x01010000 ^ (kk<<8) ^ nn; Argon2 uses 0x01010040 or 0x01010020
    output reg  [511:0]  h_out,
    output reg           done,
    output reg           busy
);
    reg [63:0] v [0:15];
    reg [63:0] m [0:15];
    reg [63:0] hv [0:7];
    reg [3:0]  rnd;
    reg        stage;
    integer i;

    localparam [63:0] IV0 = 64'h6a09e667f3bcc908, IV1 = 64'hbb67ae8584caa73b,
                      IV2 = 64'h3c6ef372fe94f82b, IV3 = 64'ha54ff53a5f1d36f1,
                      IV4 = 64'h510e527fade682d1, IV5 = 64'h9b05688c2b3e6c1f,
                      IV6 = 64'h1f83d9abfb41bd6b, IV7 = 64'h5be0cd19137e2179;

    reg [3:0] SIG [0:191];
    initial begin
        SIG[0]=0; SIG[1]=1; SIG[2]=2; SIG[3]=3; SIG[4]=4; SIG[5]=5; SIG[6]=6; SIG[7]=7;
        SIG[8]=8; SIG[9]=9; SIG[10]=10; SIG[11]=11; SIG[12]=12; SIG[13]=13; SIG[14]=14; SIG[15]=15;
        SIG[16]=14; SIG[17]=10; SIG[18]=4; SIG[19]=8; SIG[20]=9; SIG[21]=15; SIG[22]=13; SIG[23]=6;
        SIG[24]=1; SIG[25]=12; SIG[26]=0; SIG[27]=2; SIG[28]=11; SIG[29]=7; SIG[30]=5; SIG[31]=3;
        SIG[32]=11; SIG[33]=8; SIG[34]=12; SIG[35]=0; SIG[36]=5; SIG[37]=2; SIG[38]=15; SIG[39]=13;
        SIG[40]=10; SIG[41]=14; SIG[42]=3; SIG[43]=6; SIG[44]=7; SIG[45]=1; SIG[46]=9; SIG[47]=4;
        SIG[48]=7; SIG[49]=9; SIG[50]=3; SIG[51]=1; SIG[52]=13; SIG[53]=12; SIG[54]=11; SIG[55]=14;
        SIG[56]=2; SIG[57]=6; SIG[58]=5; SIG[59]=10; SIG[60]=4; SIG[61]=0; SIG[62]=15; SIG[63]=8;
        SIG[64]=9; SIG[65]=0; SIG[66]=5; SIG[67]=7; SIG[68]=2; SIG[69]=4; SIG[70]=10; SIG[71]=15;
        SIG[72]=14; SIG[73]=1; SIG[74]=11; SIG[75]=12; SIG[76]=6; SIG[77]=8; SIG[78]=3; SIG[79]=13;
        SIG[80]=2; SIG[81]=12; SIG[82]=6; SIG[83]=10; SIG[84]=0; SIG[85]=11; SIG[86]=8; SIG[87]=3;
        SIG[88]=4; SIG[89]=13; SIG[90]=7; SIG[91]=5; SIG[92]=15; SIG[93]=14; SIG[94]=1; SIG[95]=9;
        SIG[96]=12; SIG[97]=5; SIG[98]=1; SIG[99]=15; SIG[100]=14; SIG[101]=13; SIG[102]=4; SIG[103]=10;
        SIG[104]=0; SIG[105]=7; SIG[106]=6; SIG[107]=3; SIG[108]=9; SIG[109]=2; SIG[110]=8; SIG[111]=11;
        SIG[112]=13; SIG[113]=11; SIG[114]=7; SIG[115]=14; SIG[116]=12; SIG[117]=1; SIG[118]=3; SIG[119]=9;
        SIG[120]=5; SIG[121]=0; SIG[122]=15; SIG[123]=4; SIG[124]=8; SIG[125]=6; SIG[126]=2; SIG[127]=10;
        SIG[128]=6; SIG[129]=15; SIG[130]=14; SIG[131]=9; SIG[132]=11; SIG[133]=3; SIG[134]=0; SIG[135]=8;
        SIG[136]=12; SIG[137]=2; SIG[138]=13; SIG[139]=7; SIG[140]=1; SIG[141]=4; SIG[142]=10; SIG[143]=5;
        SIG[144]=10; SIG[145]=2; SIG[146]=8; SIG[147]=4; SIG[148]=7; SIG[149]=6; SIG[150]=1; SIG[151]=5;
        SIG[152]=15; SIG[153]=11; SIG[154]=9; SIG[155]=14; SIG[156]=3; SIG[157]=12; SIG[158]=13; SIG[159]=0;
        SIG[160]=0; SIG[161]=1; SIG[162]=2; SIG[163]=3; SIG[164]=4; SIG[165]=5; SIG[166]=6; SIG[167]=7;
        SIG[168]=8; SIG[169]=9; SIG[170]=10; SIG[171]=11; SIG[172]=12; SIG[173]=13; SIG[174]=14; SIG[175]=15;
        SIG[176]=14; SIG[177]=10; SIG[178]=4; SIG[179]=8; SIG[180]=9; SIG[181]=15; SIG[182]=13; SIG[183]=6;
        SIG[184]=1; SIG[185]=12; SIG[186]=0; SIG[187]=2; SIG[188]=11; SIG[189]=7; SIG[190]=5; SIG[191]=3;
    end

    function [63:0] rotr(input [63:0] x, input integer n);
        rotr = (x >> n) | (x << (64 - n));
    endfunction

    task gtask(inout [63:0] va, inout [63:0] vb, inout [63:0] vc,
               inout [63:0] vd, input [63:0] x, input [63:0] y);
        reg [63:0] a, b, c, d;
        begin
            a = va; b = vb; c = vc; d = vd;
            a = a + b + x; d = rotr(d ^ a, 32);
            c = c + d;     b = rotr(b ^ c, 24);
            a = a + b + y; d = rotr(d ^ a, 16);
            c = c + d;     b = rotr(b ^ c, 63);
            va = a; vb = b; vc = c; vd = d;
        end
    endtask

    always @(posedge clk) begin
        if (!rst_n) begin
            busy <= 1'b0;
            done <= 1'b0;
            rnd  <= 4'd0;
            stage<= 1'b0;
        end else if (start) begin
            // h[0] is pre-xored with the BLAKE2b parameter block; the same value
            // must be used in the finalisation xor, so store it in hv[0].
            hv[0] <= h_in[511:448] ^ param_xor;
            for (i = 1; i < 8; i = i + 1) hv[i] <= h_in[511 - 64*i -: 64];
            v[0] <= h_in[511:448] ^ param_xor;
            v[1] <= h_in[447:384];
            v[2] <= h_in[383:320]; v[3] <= h_in[319:256];
            v[4] <= h_in[255:192]; v[5] <= h_in[191:128];
            v[6] <= h_in[127:64];  v[7] <= h_in[63:0];
            v[8]  <= IV0; v[9]  <= IV1; v[10] <= IV2; v[11] <= IV3;
            v[12] <= IV4 ^ t; v[13] <= IV5;
            v[14] <= last ? (IV6 ^ 64'hFFFFFFFFFFFFFFFF) : IV6; v[15] <= IV7;
            for (i = 0; i < 16; i = i + 1) m[i] <= block[1023 - 64*i -: 64];
            rnd <= 4'd0;
            stage <= 1'b0;
            busy <= 1'b1;
            done <= 1'b0;
        end else if (busy) begin
            if (stage == 1'b0) begin
                gtask(v[0], v[4], v[8],  v[12], m[SIG[rnd*16+0]],  m[SIG[rnd*16+1]]);
                gtask(v[1], v[5], v[9],  v[13], m[SIG[rnd*16+2]],  m[SIG[rnd*16+3]]);
                gtask(v[2], v[6], v[10], v[14], m[SIG[rnd*16+4]],  m[SIG[rnd*16+5]]);
                gtask(v[3], v[7], v[11], v[15], m[SIG[rnd*16+6]],  m[SIG[rnd*16+7]]);
                stage <= 1'b1;
            end else begin
                gtask(v[0], v[5], v[10], v[15], m[SIG[rnd*16+8]],  m[SIG[rnd*16+9]]);
                gtask(v[1], v[6], v[11], v[12], m[SIG[rnd*16+10]], m[SIG[rnd*16+11]]);
                gtask(v[2], v[7], v[8],  v[13], m[SIG[rnd*16+12]], m[SIG[rnd*16+13]]);
                gtask(v[3], v[4], v[9],  v[14], m[SIG[rnd*16+14]], m[SIG[rnd*16+15]]);
                stage <= 1'b0;
                if (rnd == 4'd11) begin
                    h_out[511:448] <= hv[0] ^ v[0] ^ v[8];
                    h_out[447:384] <= hv[1] ^ v[1] ^ v[9];
                    h_out[383:320] <= hv[2] ^ v[2] ^ v[10];
                    h_out[319:256] <= hv[3] ^ v[3] ^ v[11];
                    h_out[255:192] <= hv[4] ^ v[4] ^ v[12];
                    h_out[191:128] <= hv[5] ^ v[5] ^ v[13];
                    h_out[127:64]  <= hv[6] ^ v[6] ^ v[14];
                    h_out[63:0]    <= hv[7] ^ v[7] ^ v[15];
                    busy <= 1'b0;
                    done <= 1'b1;
                end else begin
                    rnd <= rnd + 4'd1;
                end
            end
        end else begin
            done <= 1'b0;
        end
    end
endmodule
