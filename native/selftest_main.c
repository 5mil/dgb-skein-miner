/* Rake :: selftest_main.c
 * Standalone C self-test: Skein-512, SHA-256d, yescryptr16.
 *
 * Expected output:
 *   [rake] All 5 Skein-1.3 self-test vectors passed.
 *   [sha256d] All 3 SHA-256 vectors passed.
 *   [dispatch] AVX2 detected: using 4-way Threefish-512 path.   (or scalar)
 *   [avx2] 4-way self-test PASSED.                              (if AVX2)
 *   [yescrypt] Self-test PASSED.
 *   [selftest] PASS
 */

#include "skein_bridge.h"
#include "sha256d.h"
#include "skein_dispatch.h"
#include "yescryptr16_bridge.h"
#include <stdio.h>

int main(void) {
  rake_skein512_selftest();
  rake_sha256d_selftest();
  rake_dispatch_init();
  rake_yescryptr16_bridge_selftest();
  fprintf(stderr, "[selftest] PASS\n");
  return 0;
}
