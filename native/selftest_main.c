/*
** Rake :: native/selftest_main.c
** Standalone test runner — build and run independently of the Unison binary.
** Useful for validating the C layer on a new platform before linking.
**
** Build:
**   cmake -DCMAKE_BUILD_TYPE=Release -S . -B build
**   cmake --build build
**   ./build/selftest
**
** Expected output: all vectors pass, exit code 0.
** Any failure: detailed mismatch output, non-zero exit code.
*/
#include <stdio.h>
#include <stdlib.h>
#include "skein_bridge.h"

int main(void) {
    rake_skein_version_assert();
    int result = rake_skein512_selftest();
    if (result == 0) {
        printf("[selftest] PASS — all Skein-1.3 vectors verified.\n");
        return EXIT_SUCCESS;
    } else {
        printf("[selftest] FAIL — %d vector(s) did not match.\n", result);
        return EXIT_FAILURE;
    }
}
