/* Rake :: skein_dispatch.h
 * Runtime CPUID dispatch: selects AVX2 or scalar Skein-512 path.
 *
 * API:
 *   rake_cpu_has_avx2()   -> 1 if AVX2 available, 0 otherwise
 *   rake_dispatch_init()  -> call once at startup; sets function pointers
 *
 *   rake_skein512_fast(in, inlen, out64)
 *     -> calls AVX2 path if available, scalar otherwise (single hash)
 *
 *   rake_skein512_batch4(in0,in1,in2,in3, out0,out1,out2,out3)
 *     -> calls 4-way AVX2 path if available, 4x scalar otherwise
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int  rake_cpu_has_avx2(void);
void rake_dispatch_init(void);

/* Single-hash fast path (dispatched) */
void rake_skein512_fast(const uint8_t *in, size_t inlen, uint8_t out[64]);

/* 4-way batch path (dispatched): all inputs must be 80 bytes for mining */
void rake_skein512_batch4(
  const uint8_t *in0, const uint8_t *in1,
  const uint8_t *in2, const uint8_t *in3,
  uint8_t *out0, uint8_t *out1,
  uint8_t *out2, uint8_t *out3
);

#ifdef __cplusplus
}
#endif
