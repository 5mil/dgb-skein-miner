/* Rake :: selftest_main.c
 *
 * Runs self-tests for every hash algorithm independently.
 * Exit codes:
 *   0  -- at least one algorithm passed; prints available algorithms
 *   1  -- all algorithms failed; mining cannot proceed
 *
 * Output lines consumed by the Python orchestrator:
 *   [selftest] ALGO_OK skein
 *   [selftest] ALGO_OK yescrypt
 *   [selftest] ALGO_FAIL skein
 *   [selftest] ALGO_FAIL yescrypt
 *   [selftest] READY skein,yescrypt      <- comma-separated list of passing algos
 *   [selftest] ALL_FAIL                  <- if nothing passes
 */

#include "skein_bridge.h"
#include "sha256d.h"
#include "skein_dispatch.h"
#include "yescryptr16_bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    int skein_ok    = 0;
    int yescrypt_ok = 0;

    /* ------------------------------------------------------------------ */
    /* Skein-512                                                            */
    /* ------------------------------------------------------------------ */
    {
        int r = rake_skein512_selftest();
        if (r == 0) {
            skein_ok = 1;
            fprintf(stderr, "[selftest] ALGO_OK skein\n");
        } else {
            fprintf(stderr, "[selftest] ALGO_FAIL skein (%d vector(s) wrong)\n", r);
        }
    }

    /* ------------------------------------------------------------------ */
    /* SHA-256d (dependency check, not a mined algo)                       */
    /* ------------------------------------------------------------------ */
    rake_sha256d_selftest();  /* aborts on failure — SHA-256d is a hard dep */

    /* ------------------------------------------------------------------ */
    /* AVX2 dispatch init (best-effort; scalar fallback always available)  */
    /* ------------------------------------------------------------------ */
    rake_dispatch_init();

    /* ------------------------------------------------------------------ */
    /* YescryptR16                                                          */
    /* ------------------------------------------------------------------ */
    {
        int r = rake_yescryptr16_bridge_selftest_soft();
        if (r == 0) {
            yescrypt_ok = 1;
            fprintf(stderr, "[selftest] ALGO_OK yescrypt\n");
        } else {
            fprintf(stderr, "[selftest] ALGO_FAIL yescrypt\n");
        }
    }

    /* ------------------------------------------------------------------ */
    /* Summary                                                              */
    /* ------------------------------------------------------------------ */
    if (!skein_ok && !yescrypt_ok) {
        fprintf(stderr, "[selftest] ALL_FAIL -- no algorithm passed; cannot mine\n");
        return 1;
    }

    /* Build comma-separated ready list */
    char ready[64] = "";
    if (skein_ok)    { strcat(ready, "skein");    }
    if (yescrypt_ok) {
        if (ready[0]) strcat(ready, ",");
        strcat(ready, "yescrypt");
    }
    fprintf(stderr, "[selftest] READY %s\n", ready);
    return 0;
}
