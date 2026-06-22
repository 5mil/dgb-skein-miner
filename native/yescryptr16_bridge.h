/* Rake :: yescryptr16_bridge.h
 * Unison FFI bridge for yescryptr16.
 *
 * Exposes:
 *   rake_yescryptr16_bridge_version()  -> int (version assertion)
 *   rake_yescryptr16_bridge(in80, out32) -> void
 *   rake_yescryptr16_bridge_selftest()  -> int (0=pass, 1=fail)
 */

#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RAKE_YESCRYPT_BRIDGE_VERSION 1

int  rake_yescryptr16_bridge_version(void);
void rake_yescryptr16_bridge(const uint8_t *in, uint8_t *out);
int  rake_yescryptr16_bridge_selftest(void);

#ifdef __cplusplus
}
#endif
