// xe_load.c — run a hand-written Intel Xe kernel through OpenCL.
//
// OpenCL is the only Intel runtime installed here that can load machine code for
// the GPU. It does not take a bare instruction stream: it takes a Zebin (ELF)
// whose .text.<kernel> section holds the code and whose ze_info section holds
// the arguments and dispatch metadata.
//
// So this tool does the obvious hostile thing: it compiles a reference kernel
// with IGC, keeps IGC's metadata, appends our IGA-assembled code at the end of
// the file, and points the section header at it. The driver then loads our
// instructions with arguments and a payload layout that IGC chose.
//
//   gcc -O2 -DCL_TARGET_OPENCL_VERSION=300 -o xe-loader xe_load.c -lOpenCL
//   iga64 -p 12p1 -a src/intel/xe/intelXe_sha256.xe -o /tmp/ours.krn
//   ./xe-loader --text /tmp/ours.krn --save-ref /tmp/ref.zebin
//
// What this proves and what it does not:
//   * if the dispatch completes, our instructions executed on the GPU;
//   * the listing has no result store of its own (its `send` is elided), so the
//     results buffer stays as it was. Correctness of the listing is established
//     by the IGA encode check and by the generator's interpreter, not here.
#define CL_TARGET_OPENCL_VERSION 300
#include <CL/cl.h>
#include <elf.h>
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
"  if(clz(a)>=difficulty){ uint slot=atomic_inc(&res[0]);"
"    if(slot<8u){ res[1+slot]=nonce; __global uint *o=res+9+slot*8;"
"      o[0]=a;o[1]=b;o[2]=c;o[3]=d;o[4]=e;o[5]=f;o[6]=g;o[7]=h; } } }";

static double now(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

// Replace the payload of .text.<kernel> with `text`: append it, repoint the
// section header, and fix up the symbol sizes so nothing claims the old extent.
static unsigned char *patch_zebin(unsigned char *buf, size_t len, size_t *out_len,
                                  const unsigned char *text, size_t text_len,
                                  const char *want_section) {
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    if (len < sizeof *eh || memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "patch: not an ELF\n"); return NULL;
    }
    Elf64_Shdr *sh = (Elf64_Shdr *)(buf + eh->e_shoff);
    Elf64_Shdr *strsh = &sh[eh->e_shstrndx];
    const char *names = (const char *)(buf + strsh->sh_offset);

    int target = -1;
    for (int i = 0; i < eh->e_shnum; i++)
        if (strcmp(names + sh[i].sh_name, want_section) == 0) { target = i; break; }
    if (target < 0) { fprintf(stderr, "patch: no %s section\n", want_section); return NULL; }

    size_t off = (len + 63) & ~(size_t)63;
    unsigned char *nb = realloc(buf, off + text_len);
    if (!nb) { fprintf(stderr, "patch: out of memory\n"); return NULL; }
    memset(nb + len, 0, off - len);
    memcpy(nb + off, text, text_len);

    sh = (Elf64_Shdr *)(nb + eh->e_shoff);          // realloc may have moved it
    size_t old_off = sh[target].sh_offset, old_size = sh[target].sh_size;
    sh[target].sh_offset = off;
    sh[target].sh_size = text_len;

    // symbols that lived in the replaced section now describe the new extent
    int symsec = -1;
    for (int i = 0; i < eh->e_shnum; i++) if (sh[i].sh_type == SHT_SYMTAB) { symsec = i; break; }
    if (symsec >= 0) {
        Elf64_Sym *syms = (Elf64_Sym *)(nb + sh[symsec].sh_offset);
        size_t n = sh[symsec].sh_size / sizeof(Elf64_Sym);
        for (size_t i = 0; i < n; i++)
            if (syms[i].st_shndx == target) { syms[i].st_value = 0; syms[i].st_size = text_len; }
    }
    *out_len = off + text_len;
    printf("patch: %s was %zu bytes at 0x%zx, now %zu bytes at 0x%zx\n",
           want_section, old_size, old_off, text_len, off);
    return nb;
}

int main(int argc, char **argv) {
    const char *text_path = NULL, *save_ref = NULL, *section = ".text.sha256_pow";
    unsigned count = 1u << 20, difficulty = 32;
    int reps = 3;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--text") && i + 1 < argc) text_path = argv[++i];
        else if (!strcmp(argv[i], "--save-ref") && i + 1 < argc) save_ref = argv[++i];
        else if (!strcmp(argv[i], "--section") && i + 1 < argc) section = argv[++i];
        else if (!strcmp(argv[i], "--count") && i + 1 < argc) count = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--difficulty") && i + 1 < argc) difficulty = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--reps") && i + 1 < argc) reps = atoi(argv[++i]);
        else { fprintf(stderr, "usage: %s --text FILE.krn [--section .text.sha256_pow] "
                               "[--save-ref FILE] [--count N] [--difficulty D] [--reps N]\n", argv[0]);
               return 2; }
    }
    if (!text_path) { fprintf(stderr, "need --text (IGA output)\n"); return 2; }

    FILE *tf = fopen(text_path, "rb");
    if (!tf) { perror(text_path); return 1; }
    fseek(tf, 0, SEEK_END); long tlen = ftell(tf); fseek(tf, 0, SEEK_SET);
    unsigned char *text = malloc((size_t)tlen);
    if (fread(text, 1, (size_t)tlen, tf) != (size_t)tlen) { perror("read text"); return 1; }
    fclose(tf);
    printf("hand-written kernel: %ld bytes, %ld instructions\n", tlen, tlen / 16);

    cl_platform_id plat; cl_device_id dev; cl_uint nd;
    if (clGetPlatformIDs(1, &plat, NULL) != CL_SUCCESS) { fprintf(stderr, "no platform\n"); return 1; }
    if (clGetDeviceIDs(plat, CL_DEVICE_TYPE_ALL, 1, &dev, &nd) != CL_SUCCESS) {
        fprintf(stderr, "no device\n"); return 1; }
    char dn[256] = {0};
    clGetDeviceInfo(dev, CL_DEVICE_NAME, sizeof dn, dn, NULL);
    printf("device: %s\n", dn);

    cl_int err;
    cl_context ctx = clCreateContext(NULL, 1, &dev, NULL, NULL, &err);
    cl_command_queue q = clCreateCommandQueueWithProperties(ctx, dev, NULL, &err);

    // reference program: IGC's code plus the metadata that describes it
    cl_program ref = clCreateProgramWithSource(ctx, 1, &SRC, NULL, &err);
    if ((err = clBuildProgram(ref, 1, &dev, "-cl-std=CL2.0", NULL, NULL)) != CL_SUCCESS) {
        fprintf(stderr, "reference build failed %d\n", err); return 1;
    }
    size_t blen = 0;
    clGetProgramInfo(ref, CL_PROGRAM_BINARY_SIZES, sizeof blen, &blen, NULL);
    unsigned char *zebin = malloc(blen);
    if (blen == 0 || !zebin) { fprintf(stderr, "no binary from the reference build\n"); return 1; }
    clGetProgramInfo(ref, CL_PROGRAM_BINARIES, sizeof(unsigned char *), &zebin, NULL);
    printf("reference zebin: %zu bytes\n", blen);
    if (save_ref) {
        FILE *f = fopen(save_ref, "wb"); fwrite(zebin, 1, blen, f); fclose(f);
        printf("wrote %s\n", save_ref);
    }

    size_t plen = 0;
    unsigned char *patched = patch_zebin(zebin, blen, &plen, text, (size_t)tlen, section);
    if (!patched) return 1;

    // load the patched image
    const unsigned char *imgs[1] = { patched };
    cl_int status = 0;
    cl_program prog = clCreateProgramWithBinary(ctx, 1, &dev, &plen, imgs, &status, &err);
    if (!prog || err != CL_SUCCESS) {
        fprintf(stderr, "clCreateProgramWithBinary failed: %d (binary status %d)\n", err, status);
        return 1;
    }
    err = clBuildProgram(prog, 1, &dev, "", NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t l = 0;
        clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &l);
        char *log = malloc(l + 1);
        clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, l, log, NULL);
        fprintf(stderr, "patched build failed: %d\n%s\n", err, log);
        return 1;
    }
    printf("patched image loaded and built\n");

    cl_kernel k = clCreateKernel(prog, "sha256_pow", &err);
    if (err != CL_SUCCESS) { fprintf(stderr, "clCreateKernel failed: %d\n", err); return 1; }

    unsigned char tail[44]; memset(tail, '.', sizeof tail);
    memcpy(tail, "anubis-solver: one card in the binder, Intel Xe gen", 44);
    cl_uint msg11[11];
    for (int i = 0; i < 11; i++)
        msg11[i] = ((cl_uint)tail[i*4] << 24) | ((cl_uint)tail[i*4+1] << 16) |
                   ((cl_uint)tail[i*4+2] << 8) | (cl_uint)tail[i*4+3];
    cl_mem mmsg = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof msg11, msg11, &err);
    cl_mem mres = clCreateBuffer(ctx, CL_MEM_READ_WRITE, 73 * sizeof(cl_uint), NULL, &err);
    cl_uint zero73[73] = {0};
    clEnqueueWriteBuffer(q, mres, CL_TRUE, 0, sizeof zero73, zero73, 0, NULL, NULL);

    cl_uint base = 0, cnt = count, diff = difficulty;
    clSetKernelArg(k, 0, sizeof mmsg, &mmsg);
    clSetKernelArg(k, 1, sizeof mres, &mres);
    clSetKernelArg(k, 2, sizeof base, &base);
    clSetKernelArg(k, 3, sizeof diff, &diff);
    clSetKernelArg(k, 4, sizeof cnt, &cnt);

    size_t g = count;
    // warm up, then time: if this completes without a fault, our instructions ran
    if ((err = clEnqueueNDRangeKernel(q, k, 1, NULL, &g, NULL, 0, NULL, NULL)) != CL_SUCCESS) {
        fprintf(stderr, "dispatch failed: %d\n", err); return 1; }
    if ((err = clFinish(q)) != CL_SUCCESS) {
        fprintf(stderr, "clFinish failed after our kernel: %d (a GPU fault looks like this)\n", err);
        return 1; }

    double best = 1e9;
    for (int r = 0; r < reps; r++) {
        double t0 = now();
        err = clEnqueueNDRangeKernel(q, k, 1, NULL, &g, NULL, 0, NULL, NULL);
        if (err == CL_SUCCESS) err = clFinish(q);
        double dt = now() - t0;
        if (err != CL_SUCCESS) { fprintf(stderr, "repeat dispatch failed: %d\n", err); return 1; }
        if (dt < best) best = dt;
    }
    printf("hand-written kernel ran: %.3f s for %u nonces = %.1f M hashes/s\n",
           best, count, count / best / 1e6);

    cl_uint out[73];
    clEnqueueReadBuffer(q, mres, CL_TRUE, 0, sizeof out, out, 0, NULL, NULL);
    printf("results buffer: total=%u nonce=%u (expected 0: this listing has no store)\n",
           out[0], out[1]);

    // same dispatch on IGC's own code, for the comparison
    cl_kernel kr = clCreateKernel(ref, "sha256_pow", &err);
    clSetKernelArg(kr, 0, sizeof mmsg, &mmsg);
    clSetKernelArg(kr, 1, sizeof mres, &mres);
    clSetKernelArg(kr, 2, sizeof base, &base);
    clSetKernelArg(kr, 3, sizeof diff, &diff);
    clSetKernelArg(kr, 4, sizeof cnt, &cnt);
    double bestr = 1e9;
    for (int r = 0; r < reps; r++) {
        double t0 = now();
        clEnqueueNDRangeKernel(q, kr, 1, NULL, &g, NULL, 0, NULL, NULL);
        clFinish(q);
        double dt = now() - t0;
        if (dt < bestr) bestr = dt;
    }
    printf("IGC's kernel, same dispatch: %.3f s = %.1f M hashes/s (%.2fx)\n",
           bestr, count / bestr / 1e6, best / bestr);
    return 0;
}
