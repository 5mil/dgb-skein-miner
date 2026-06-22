/* Rake :: yescrypt.h
 * yescrypt core (yescrypt-1.0) from-scratch implementation.
 *
 * yescrypt is a password/PoW KDF built on top of scrypt's SMix.
 * DGB yescryptr16 uses the following parameters:
 *   N = 2048   (memory: N * 128 * r bytes = 2048 * 128 * 16 = 4 MB)
 *   r = 16     (block size factor — hence the "r16" name)
 *   p = 1      (parallelism)
 *   t = 0      (no extra time-hardening; standard scrypt-style)
 *   g = 0      (no global ROM)
 *   flags = YESCRYPT_RW  (RW mode for mining ASIC resistance)
 *   output: 32 bytes
 *
 * The input for mining is the 80-byte block header.
 * The salt is also the 80-byte block header (same as yescrypt reference usage).
 *
 * API:
 *   rake_yescryptr16(in80, out32)
 *     Hash 80-byte mining header, write 32-byte digest.
 *
 *   rake_yescryptr16_selftest()
 *     Known-answer test. abort() on failure.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RAKE_YESCRYPT_VERSION 1

/* DGB yescryptr16 parameters */
#define YESCRYPT_N     2048
#define YESCRYPT_R     16
#define YESCRYPT_P     1

/* yescrypt flags */
#define YESCRYPT_RW    0x002   /* RW mode: enables bitmask mixing */
#define YESCRYPT_WORM  0x004   /* WORM mode (not used for DGB) */

/* Hash 80-byte header -> 32-byte digest */
void rake_yescryptr16(const uint8_t in[80], uint8_t out[32]);

/* Self-test: known-answer vector. abort() on mismatch. */
void rake_yescryptr16_selftest(void);

/* Low-level entry point (used internally and for testing) */
void rake_yescrypt_hash(
  const uint8_t *passwd, size_t passwdlen,
  const uint8_t *salt,   size_t saltlen,
  uint64_t N, uint32_t r, uint32_t p,
  uint32_t t, uint32_t g, uint32_t flags,
  uint8_t *out, size_t outlen
);

#ifdef __cplusplus
}
#endif
