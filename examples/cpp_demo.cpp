// Same as c_demo.c but compiled as C++: the header is extern "C".
#include <anubis-solver.h>

#include <cstdio>

int main() {
    char hex[65] = {};
    uint32_t nonce = 0;
    double ms = 0.0;
    const char *challenge = "00112233445566778899aabbccddeeff";

    int rc = anubis_solve_bits(challenge, 8, 0, 0.0, &nonce, hex, &ms);
    if (rc != ANUBIS_OK) {
        std::fprintf(stderr, "solve failed: %d\n", rc);
        return 1;
    }
    std::printf("C++: nonce %u -> %s (%.1f ms)\n", nonce, hex, ms);
    return 0;
}
