/* Rake :: skein_avx2.h
 * 4-way AVX2 Threefish-512 + Skein-512 batch implementation.
 *
 * Hashes 4 independent 80-byte mining headers in parallel using
 * 256-bit AVX2 SIMD registers (4 x uint64 per __m256i lane).
 *
 * API:
 *   rake_skein512_avx2_4way(in0,in1,in2,in3, out0,out1,out2,out3)
 *     - Each inN: pointer to 80-byte header
 *     - Each outN: pointer to 64-byte output buffer
 *     - All four hashes computed simultaneously
 *
 *   rake_skein512_avx2_selftest()
 *     - Verifies all 4 lanes produce the same output as the scalar
 *       reference for each of the 5 official Skein-1.3 vectors.
 *     - abort() on any mismatch.
 *
 * Requires: AVX2 (__AVX2__ defined at compile time).
 * Runtime guard: call rake_cpu_has_avx2() before using this path.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 4-way parallel Skein-512 for 80-byte inputs (mining headers).
 * All four inputs must be exactly 80 bytes.
 * All four outputs must be at least 64 bytes. */
void rake_skein512_avx2_4way(
  const uint8_t *in0, const uint8_t *in1,
  const uint8_t *in2, const uint8_t *in3,
  uint8_t *out0, uint8_t *out1,
  uint8_t *out2, uint8_t *out3
);

/* Self-test: cross-check AVX2 lanes against scalar reference.
 * Runs all 5 official Skein-1.3 512-bit vectors.
 * abort() on any failure. */
void rake_skein512_avx2_selftest(void);

#ifdef __cplusplus
}
#endif
