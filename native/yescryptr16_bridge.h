/* Rake :: yescryptr16_bridge.h */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define RAKE_YESCRYPT_BRIDGE_VERSION 1
#define RAKE_YESCRYPT_OUTPUT_BYTES   32

#ifdef __cplusplus
extern "C" {
#endif

int  rake_yescryptr16_bridge_version(void);
void rake_yescryptr16_bridge(const uint8_t *in, uint8_t *out);
int  rake_yescryptr16_bridge_selftest(void);       /* aborts on failure */
int  rake_yescryptr16_bridge_selftest_soft(void);  /* returns 1 on failure */

#ifdef __cplusplus
}
#endif
