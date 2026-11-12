#include "Vsim_top.h"
#include "verilated.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    auto* t = new Vsim_top;

    uint64_t nstart = argc > 1 ? strtoull(argv[1], nullptr, 0) : 0;
    uint32_t maxtry = argc > 2 ? (uint32_t)strtoul(argv[2], nullptr, 0) : 1;
    uint32_t plen   = argc > 3 ? (uint32_t)strtoul(argv[3], nullptr, 0) : 32;
    int      le     = argc > 4 ? atoi(argv[4]) : 0;

    t->clk = 0; t->rst_n = 0; t->go = 0;
    t->nonce_start = nstart; t->max_tries = maxtry;
    t->plen = plen; t->le = le;

    auto tick = [&] { t->clk = 1; t->eval(); t->clk = 0; t->eval(); };

    for (int i = 0; i < 8; i++) tick();
    t->rst_n = 1;
    tick();
    t->go = 1; tick(); t->go = 0;

    auto t0 = std::chrono::steady_clock::now();
    uint64_t cycles = 0;
    while (!t->done_all && cycles < 400000000ULL) { tick(); cycles++; }
    double ms = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0).count();

    printf("cycles=%llu wall=%.1f ms tries=%u hit=%d done=%d\n",
           (unsigned long long)cycles, ms, (unsigned)t->tries,
           (int)t->hit, (int)t->done_all);
    if (t->hit) {
        printf("HIT nonce=%llu leading_zero_bits=%u\n",
               (unsigned long long)t->hit_nonce, (unsigned)t->lz_out);
        const uint32_t w[8] = {t->tag_w0, t->tag_w1, t->tag_w2, t->tag_w3,
                               t->tag_w4, t->tag_w5, t->tag_w6, t->tag_w7};
        printf("TAG ");
        for (int i = 0; i < 8; i++)
            for (int b = 0; b < 4; b++) printf("%02x", (w[i] >> (8*b)) & 0xff);
        printf("\n");
    }
    delete t;
    return t ? 0 : 1;
}
