/* Rake :: selftest_main.c
 * Standalone C self-test: runs Skein-512 and SHA-256 vectors.
 * Build and run before linking with Unison to confirm the C layer is clean.
 *
 * Expected output:
 *   [rake] All 5 Skein-1.3 self-test vectors passed.
 *   [sha256d] All 3 SHA-256 vectors passed.
 *   [selftest] PASS
 */

#include "skein_bridge.h"
#include "sha256d.h"
#include <stdio.h>

int main(void) {
  rake_skein512_selftest();
  rake_sha256d_selftest();
  fprintf(stderr, "[selftest] PASS\n");
  return 0;
}
