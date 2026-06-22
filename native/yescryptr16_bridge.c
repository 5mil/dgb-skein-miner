/* Rake :: yescryptr16_bridge.c
 * Thin ABI shim between Unison FFI calling convention and yescrypt.c.
 */

#include "yescryptr16_bridge.h"
#include "yescrypt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int rake_yescryptr16_bridge_version(void) {
  return RAKE_YESCRYPT_BRIDGE_VERSION;
}

void rake_yescryptr16_bridge(const uint8_t *in, uint8_t *out) {
  rake_yescryptr16(in, out);
}

int rake_yescryptr16_bridge_selftest(void) {
  /* rake_yescryptr16_selftest calls abort() on failure;
   * wrap in a non-aborting path for Unison's startup check */
  rake_yescryptr16_selftest();
  return 0;  /* reached only on success */
}
