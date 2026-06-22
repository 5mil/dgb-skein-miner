/* Rake :: sha256d.h
 * Double-SHA256 implementation for coinbase txid and merkle steps.
 *
 * Implements SHA-256 from first principles (FIPS 180-4).
 * No OpenSSL dependency — keeps the build self-contained.
 *
 * rake_sha256d(in, len, out32)
 *   Computes SHA256(SHA256(in, len)) into out32 (32 bytes).
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RAKE_SHA256D_VERSION 1

void rake_sha256d_version_assert(void);

/* Double-SHA256: out32 must point to at least 32 bytes */
void rake_sha256d(const uint8_t *in, size_t len, uint8_t out32[32]);

/* Single SHA-256 (used internally and exposed for testing) */
void rake_sha256(const uint8_t *in, size_t len, uint8_t out32[32]);

/* Self-test: runs FIPS 180-4 test vectors. Calls abort() on failure. */
void rake_sha256d_selftest(void);

#ifdef __cplusplus
}
#endif
