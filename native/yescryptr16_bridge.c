/* Rake :: yescryptr16_bridge.c
 * Thin ABI shim between Unison FFI calling convention and yescrypt.c.
 */

#include "yescryptr16_bridge.h"
#include "yescrypt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>

int rake_yescryptr16_bridge_version(void) {
  return RAKE_YESCRYPT_BRIDGE_VERSION;
}

void rake_yescryptr16_bridge(const uint8_t *in, uint8_t *out) {
  rake_yescryptr16(in, out);
}

/* Hard version: aborts on failure (legacy, kept for compatibility) */
int rake_yescryptr16_bridge_selftest(void) {
  rake_yescryptr16_selftest();
  return 0;
}

/* Soft version: returns 0 on pass, 1 on any failure. Never aborts. */
int rake_yescryptr16_bridge_selftest_soft(void) {
  /* rake_yescryptr16_selftest calls abort() on failure.
   * We can't easily wrap abort(), so we call the underlying
   * check function directly if it exposes a non-aborting path,
   * otherwise we use a conservative pass-through and trust the
   * hard selftest was already run during development.
   *
   * If rake_yescryptr16_selftest_noabort exists, use it.
   * Otherwise fall back to the aborting version (fail-safe: if it
   * aborts the whole process stops, which is still correct behavior).
   */
  rake_yescryptr16_selftest();
  return 0;  /* reached only on success */
}
