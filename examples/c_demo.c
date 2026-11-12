/* Solve a challenge from plain C.
 *
 *   make
 *   cc examples/c_demo.c -Iinclude -L. -lanubis_solver \
 *      -Wl,-rpath,"$PWD" -o /tmp/c_demo && /tmp/c_demo
 */
#include <stdio.h>
#include <string.h>

#include <anubis-solver.h>

int main(void) {
    const char *challenge = "demo-challenge";
    uint64_t nonce = 0;
    char hex[65] = {0};
    double ms = 0.0;
    int rc;

    printf("libanubis_solver %s\n", anubis_solver_version());
    if (anubis_gpu_info() != NULL) {
        printf("gpu: %s\n", anubis_gpu_info());
    }

    rc = anubis_solve_nibbles(challenge, 3, 0, 0, 0.0, &nonce, hex, &ms);
    if (rc != ANUBIS_OK) {
        fprintf(stderr, "solve failed: %d\n", rc);
        return 1;
    }
    printf("nonce %llu -> %s (%.1f ms)\n", (unsigned long long)nonce, hex, ms);

    memset(hex, 0, sizeof(hex));
    rc = anubis_verify_nibbles(challenge, nonce, 3, hex);
    printf("verify: %s\n", rc == ANUBIS_OK ? "ok" : "FAILED");
    return rc == ANUBIS_OK ? 0 : 1;
}
