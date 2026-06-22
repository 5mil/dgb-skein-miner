/* Rake :: skein_dispatch.c
 * CPUID-based runtime dispatch for AVX2 vs scalar Skein-512.
 *
 * CPUID leaf 7, sub-leaf 0, EBX bit 5 = AVX2 support.
 * We also verify XSAVE (leaf 1 ECX bit 26) and OSXSAVE (bit 27)
 * to confirm the OS has enabled AVX state saving, which is required
 * for AVX2 instructions to work without #UD faults.
 */

#include "skein_dispatch.h"
#include "skein_bridge.h"
#include "skein_avx2.h"
#include <stdio.h>
#include <string.h>

/* -----------------------------------------------------------------------
 * CPUID helpers (x86/x86-64 only)
 * ----------------------------------------------------------------------- */

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
  #ifdef _MSC_VER
    #include <intrin.h>
    static void cpuid(uint32_t leaf, uint32_t subleaf,
                      uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
      int info[4];
      __cpuidex(info, (int)leaf, (int)subleaf);
      *eax=(uint32_t)info[0]; *ebx=(uint32_t)info[1];
      *ecx=(uint32_t)info[2]; *edx=(uint32_t)info[3];
    }
  #else
    #include <cpuid.h>
    static void cpuid(uint32_t leaf, uint32_t subleaf,
                      uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
      __cpuid_count(leaf, subleaf, *eax, *ebx, *ecx, *edx);
    }
  #endif
  #define RAKE_X86 1
#else
  #define RAKE_X86 0
#endif

int rake_cpu_has_avx2(void) {
#if RAKE_X86
  uint32_t eax, ebx, ecx, edx;
  /* Check XSAVE + OSXSAVE (leaf 1) */
  cpuid(1, 0, &eax, &ebx, &ecx, &edx);
  if (!((ecx >> 26) & 1) || !((ecx >> 27) & 1)) return 0;
  /* Check XCR0 bit 2 (YMM state enabled) */
  /* On MSVC use _xgetbv; on GCC use inline asm or _xgetbv intrinsic */
#ifdef _MSC_VER
  uint64_t xcr0 = _xgetbv(0);
#else
  uint64_t xcr0;
  __asm__ volatile("xgetbv" : "=A"(xcr0) : "c"(0));
#endif
  if (!((xcr0 >> 2) & 1)) return 0;
  /* Check AVX2 (leaf 7 subleaf 0 EBX bit 5) */
  cpuid(7, 0, &eax, &ebx, &ecx, &edx);
  return (ebx >> 5) & 1;
#else
  return 0;  /* Non-x86: no AVX2 */
#endif
}

/* -----------------------------------------------------------------------
 * Dispatch init: called once at startup
 * ----------------------------------------------------------------------- */

static int g_has_avx2 = -1;  /* -1 = not yet checked */

void rake_dispatch_init(void) {
  g_has_avx2 = rake_cpu_has_avx2();
  if (g_has_avx2) {
    fprintf(stderr, "[dispatch] AVX2 detected: using 4-way Threefish-512 path.\n");
    rake_skein512_avx2_selftest();
  } else {
    fprintf(stderr, "[dispatch] No AVX2: using scalar Threefish-512 path.\n");
  }
}

/* -----------------------------------------------------------------------
 * Dispatched single-hash
 * ----------------------------------------------------------------------- */

void rake_skein512_fast(const uint8_t *in, size_t inlen, uint8_t out[64]) {
  if (g_has_avx2 < 0) rake_dispatch_init();
  /* For single hashes always use scalar (AVX2 benefit is in batch) */
  rake_skein512(in, inlen, out);
}

/* -----------------------------------------------------------------------
 * Dispatched 4-way batch
 * ----------------------------------------------------------------------- */

void rake_skein512_batch4(
  const uint8_t *in0, const uint8_t *in1,
  const uint8_t *in2, const uint8_t *in3,
  uint8_t *out0, uint8_t *out1,
  uint8_t *out2, uint8_t *out3
) {
  if (g_has_avx2 < 0) rake_dispatch_init();
  if (g_has_avx2) {
    rake_skein512_avx2_4way(in0, in1, in2, in3, out0, out1, out2, out3);
  } else {
    rake_skein512(in0, 80, out0);
    rake_skein512(in1, 80, out1);
    rake_skein512(in2, 80, out2);
    rake_skein512(in3, 80, out3);
  }
}
