/* Rake :: selftest_main.c
 *
 * Tests DGB-Skein and YescryptR16 independently.
 * Exits 0 if at least one algorithm passes (prints READY list).
 * Exits 1 if both fail.
 *
 * Orchestrator reads stderr for:
 *   [selftest] ALGO_OK skein
 *   [selftest] ALGO_OK yescrypt
 *   [selftest] ALGO_FAIL skein
 *   [selftest] ALGO_FAIL yescrypt
 *   [selftest] READY skein,yescrypt
 *   [selftest] ALL_FAIL
 */

#include "skein_bridge.h"
#include "skein_dispatch.h"
#include "yescryptr16_bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    int skein_ok    = 0;
    int yescrypt_ok = 0;

    /* --- DGB-Skein ---------------------------------------------------- */
    if (rake_skein512_selftest() == 0) {
        skein_ok = 1;
        fprintf(stderr, "[selftest] ALGO_OK skein\n");
    } else {
        fprintf(stderr, "[selftest] ALGO_FAIL skein\n");
    }

    /* --- AVX2 dispatch (best-effort, scalar always available) ---------- */
    rake_dispatch_init();

    /* --- YescryptR16 --------------------------------------------------- */
    if (rake_yescryptr16_bridge_selftest_soft() == 0) {
        yescrypt_ok = 1;
        fprintf(stderr, "[selftest] ALGO_OK yescrypt\n");
    } else {
        fprintf(stderr, "[selftest] ALGO_FAIL yescrypt\n");
    }

    /* --- Summary ------------------------------------------------------- */
    if (!skein_ok && !yescrypt_ok) {
        fprintf(stderr, "[selftest] ALL_FAIL\n");
        return 1;
    }
    char ready[32] = "";
    if (skein_ok)                  strcat(ready, "skein");
    if (yescrypt_ok) { if (ready[0]) strcat(ready, ","); strcat(ready, "yescrypt"); }
    fprintf(stderr, "[selftest] READY %s\n", ready);
    return 0;
}
