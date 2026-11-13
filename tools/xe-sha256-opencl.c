// clrun.c — run the SHA-256 PoW kernel on the real GPU through Intel's OpenCL
// driver (NEO + IGC), verify the digest, measure it, and hand back the compiled
// binary so it can be disassembled into Intel Xe assembly.
//
//   gcc -O2 -o clrun clrun.c -lOpenCL && ./clrun
//
// The kernel is the same algorithm as src/intel/xe/intelXe_sha256.xe: one
// work-item per nonce, the nonce in W[0], a 48-byte message padded into one
// 64-byte block, leading-zero test, atomic slot claim.
#define CL_TARGET_OPENCL_VERSION 300
#include <CL/cl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *SRC =
"__constant uint K[64]={"
"0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,"
"0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,"
"0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,"
"0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,"
"0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,"
"0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,"
"0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,"
"0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};\n"
"#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))\n"
"__kernel void sha256_pow(__global const uint *msg11,__global uint *res,"
"                         uint base,uint difficulty,uint count){"
"  uint gid=get_global_id(0); if(gid>=count) return;"
"  uint nonce=base+gid, w[64];"
"  w[0]=((nonce&0xffu)<<24)|((nonce&0xff00u)<<8)|((nonce>>8)&0xff00u)|((nonce>>24)&0xffu);"
"  for(int i=0;i<11;i++) w[i+1]=msg11[i];"
"  w[12]=0x80000000u; w[13]=0u; w[14]=0u; w[15]=384u;"
"  for(int i=16;i<64;i++){"
"    uint s0=ROTR(w[i-15],7)^ROTR(w[i-15],18)^(w[i-15]>>3);"
"    uint s1=ROTR(w[i-2],17)^ROTR(w[i-2],19)^(w[i-2]>>10);"
"    w[i]=w[i-16]+s0+w[i-7]+s1; }"
"  uint a=0x6a09e667u,b=0xbb67ae85u,c=0x3c6ef372u,d=0xa54ff53au,"
"       e=0x510e527fu,f=0x9b05688cu,g=0x1f83d9abu,h=0x5be0cd19u;"
"  for(int i=0;i<64;i++){"
"    uint S1=ROTR(e,6)^ROTR(e,11)^ROTR(e,25), ch=(e&f)^(~e&g);"
"    uint t1=h+S1+ch+K[i]+w[i];"
"    uint S0=ROTR(a,2)^ROTR(a,13)^ROTR(a,22), mj=(a&b)^(a&c)^(b&c);"
"    uint t2=S0+mj;"
"    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2; }"
"  a+=0x6a09e667u; b+=0xbb67ae85u; c+=0x3c6ef372u; d+=0xa54ff53au;"
"  e+=0x510e527fu; f+=0x9b05688cu; g+=0x1f83d9abu; h+=0x5be0cd19u;"
"  if(clz(a)>=difficulty){"
"    uint slot=atomic_inc(&res[0]);"
"    if(slot<8u){ res[1+slot]=nonce; __global uint *o=res+9+slot*8;"
"      o[0]=a;o[1]=b;o[2]=c;o[3]=d;o[4]=e;o[5]=f;o[6]=g;o[7]=h; } } }";

// the same 44-byte tail as src/intel/xe/intelXe_sha256.xe
static const char TAIL[] = "anubis-solver: one card in the binder, Intel Xe gen"; // 54, cut to 44 below

#define CHECK(x, what) do { cl_int _e = (x); if (_e != CL_SUCCESS) { \
    fprintf(stderr, "%s -> CL error %d\n", what, _e); exit(1);} } while (0)

static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return t.tv_sec + t.tv_nsec/1e9; }

int main(void) {
    cl_platform_id plat; cl_device_id dev; cl_uint n;
    CHECK(clGetPlatformIDs(1, &plat, NULL), "platform");
    if (clGetDeviceIDs(plat, CL_DEVICE_TYPE_ALL, 1, &dev, &n) != CL_SUCCESS) {
        fprintf(stderr, "no device on first platform\n"); return 1; }
    char dn[256] = {0};
    clGetDeviceInfo(dev, CL_DEVICE_NAME, sizeof dn, dn, NULL);
    printf("device: %s\n", dn);

    cl_context ctx = clCreateContext(NULL, 1, &dev, NULL, NULL, NULL);
    cl_int err;
    cl_command_queue q = clCreateCommandQueueWithProperties(ctx, dev, NULL, &err);
    if (!q) { fprintf(stderr, "queue failed %d\n", err); return 1; }

    cl_program prog = clCreateProgramWithSource(ctx, 1, &SRC, NULL, &err);
    CHECK(err, "create program");
    err = clBuildProgram(prog, 1, &dev, "-cl-std=CL2.0", NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t len = 0;
        clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
        char *log = malloc(len + 1);
        clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, len, log, NULL);
        fprintf(stderr, "build failed (%d):\n%s\n", err, log);
        return 1;
    }
    cl_kernel k = clCreateKernel(prog, "sha256_pow", &err);
    CHECK(err, "create kernel");

    // the 11 message words: bytes 4..47 of the block, big-endian
    unsigned char tail[44];
    memset(tail, '.', 44);
    memcpy(tail, TAIL, 44);
    cl_uint msg11[11];
    for (int i = 0; i < 11; i++)
        msg11[i] = ((cl_uint)tail[i*4] << 24) | ((cl_uint)tail[i*4+1] << 16) |
                   ((cl_uint)tail[i*4+2] << 8) | (cl_uint)tail[i*4+3];

    cl_mem mmsg = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                 sizeof msg11, msg11, &err);
    CHECK(err, "msg buffer");
    cl_mem mres = clCreateBuffer(ctx, CL_MEM_READ_WRITE, 73 * sizeof(cl_uint), NULL, &err);
    CHECK(err, "res buffer");

    // one nonce, difficulty 0: the digest comes back in res[9..16]
    cl_uint zero73[73] = {0};
    CHECK(clEnqueueWriteBuffer(q, mres, CL_TRUE, 0, sizeof zero73, zero73, 0, NULL, NULL), "clear");
    cl_uint base = 0, difficulty = 0, count = 1;
    CHECK(clSetKernelArg(k, 0, sizeof mmsg, &mmsg), "arg0");
    CHECK(clSetKernelArg(k, 1, sizeof mres, &mres), "arg1");
    CHECK(clSetKernelArg(k, 2, sizeof base, &base), "arg2");
    CHECK(clSetKernelArg(k, 3, sizeof difficulty, &difficulty), "arg3");
    CHECK(clSetKernelArg(k, 4, sizeof count, &count), "arg4");
    size_t gsz = 64;
    CHECK(clEnqueueNDRangeKernel(q, k, 1, NULL, &gsz, NULL, 0, NULL, NULL), "dispatch");
    CHECK(clFinish(q), "finish");

    cl_uint out[73];
    CHECK(clEnqueueReadBuffer(q, mres, CL_TRUE, 0, sizeof out, out, 0, NULL, NULL), "read");
    printf("total=%u nonce=%u digest=", out[0], out[1]);
    for (int i = 0; i < 8; i++) printf("%08x", out[9 + i]);
    printf("\n");

    // IGC's compiled binary for this program, kept for disassembly
    size_t bsz = 0;
    clGetProgramInfo(prog, CL_PROGRAM_BINARY_SIZES, sizeof(size_t), &bsz, NULL);
    if (bsz) {
        unsigned char *bin = malloc(bsz);
        clGetProgramInfo(prog, CL_PROGRAM_BINARIES, sizeof(unsigned char *), &bin, NULL);
        FILE *f = fopen("/tmp/igc-sha256.bin", "wb");
        fwrite(bin, 1, bsz, f);
        fclose(f);
        printf("igc binary: %zu bytes -> /tmp/igc-sha256.bin\n", bsz);
    }

    // throughput: difficulty 32 so nothing matches and the loop is pure hashing
    cl_uint big = 1u << 22;
    difficulty = 32; base = 0; count = big;
    CHECK(clEnqueueWriteBuffer(q, mres, CL_TRUE, 0, sizeof zero73, zero73, 0, NULL, NULL), "clear2");
    CHECK(clSetKernelArg(k, 2, sizeof base, &base), "a2");
    CHECK(clSetKernelArg(k, 3, sizeof difficulty, &difficulty), "a3");
    CHECK(clSetKernelArg(k, 4, sizeof count, &count), "a4");

    // warm up
    size_t g2 = big;
    CHECK(clEnqueueNDRangeKernel(q, k, 1, NULL, &g2, NULL, 0, NULL, NULL), "warm");
    CHECK(clFinish(q), "warm finish");

    double best = 1e9;
    for (int rep = 0; rep < 5; rep++) {
        double t0 = now();
        CHECK(clEnqueueNDRangeKernel(q, k, 1, NULL, &g2, NULL, 0, NULL, NULL), "bench");
        CHECK(clFinish(q), "bench finish");
        double dt = now() - t0;
        if (dt < best) best = dt;
    }
    printf("throughput: %.1f M hashes/s (%u nonces in %.3f s, best of 5)\n",
           big / best / 1e6, big, best);
    return 0;
}
