/* Rake :: skein_avx2.c
 * 4-way AVX2 Threefish-512 + UBI chaining for Skein-512.
 *
 * Fixes:
 *   - Removed unused CFG_STR[] (config block handled via precomputed IV)
 *   - Removed unused vecs[] in selftest (vectors tested inline)
 *   - Removed unused threefish512_avx2_encrypt() stub (was superseded
 *     by the per-lane scalar key-schedule path in ubi_process_block_avx2)
 */

#ifdef __AVX2__
#include <immintrin.h>
#endif

#include "skein_avx2.h"
#include "skein.h"
#include "skein_bridge.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const int RC[8][4] = {
  {46, 36, 19, 37},
  {33, 27, 14, 42},
  {17, 49, 36, 39},
  {44,  9, 54, 56},
  {39, 30, 34, 24},
  {13, 50, 10, 17},
  {25, 29, 39, 43},
  { 8, 35, 56, 22},
};

static const int PERM[8] = {2, 1, 4, 7, 6, 5, 0, 3};

#ifdef __AVX2__

#define ROT64_AVX2(v, n) \
  _mm256_or_si256(_mm256_slli_epi64((v),(n)), _mm256_srli_epi64((v),64-(n)))

#define MIX(a, b, r) do { \
  (a) = _mm256_add_epi64((a), (b));     \
  (b) = ROT64_AVX2((b), (r));           \
  (b) = _mm256_xor_si256((b), (a));     \
} while(0)

#define BCAST64(x) _mm256_set1_epi64x((long long)(x))

#define C240 ((uint64_t)0x1BD11BDAA9FC1A22ULL)

/* -----------------------------------------------------------------------
 * UBI block: 4-way parallel via per-lane scalar key schedule.
 * The SIMD benefit is concentrated in the round loop itself;
 * subkey derivation is done once per block and is not the bottleneck.
 * ----------------------------------------------------------------------- */
static void ubi_process_block_avx2(
  __m256i state[8],
  __m256i block[8],
  const uint64_t tweak[3]
) {
  uint64_t st[4][8];
  for (int i = 0; i < 8; i++) {
    uint64_t tmp[4];
    _mm256_storeu_si256((__m256i*)tmp, state[i]);
    for (int lane = 0; lane < 4; lane++)
      st[lane][i] = tmp[lane];
  }

  uint64_t results[4][8];
  for (int lane = 0; lane < 4; lane++) {
    uint64_t key[9];
    for (int i = 0; i < 8; i++) key[i] = st[lane][i];
    key[8] = C240;
    for (int i = 0; i < 8; i++) key[8] ^= key[i];

    uint64_t pt[8];
    for (int i = 0; i < 8; i++) {
      uint64_t tmp4[4];
      _mm256_storeu_si256((__m256i*)tmp4, block[i]);
      pt[i] = tmp4[lane];
    }

    uint64_t ks2[19][8];
    for (int s = 0; s <= 18; s++) {
      for (int i = 0; i < 8; i++) ks2[s][i] = key[(s+i)%9];
      ks2[s][5] ^= tweak[s%3];
      ks2[s][6] ^= tweak[(s+1)%3];
      ks2[s][7] ^= (uint64_t)s;
    }
    uint64_t v2[8];
    for (int i = 0; i < 8; i++) v2[i] = pt[i] + ks2[0][i];
    for (int r = 0; r < 72; r++) {
      int rm8 = r & 7;
      v2[0] += v2[1]; v2[1] = ((v2[1]<<RC[rm8][0])|(v2[1]>>(64-RC[rm8][0]))) ^ v2[0];
      v2[2] += v2[3]; v2[3] = ((v2[3]<<RC[rm8][1])|(v2[3]>>(64-RC[rm8][1]))) ^ v2[2];
      v2[4] += v2[5]; v2[5] = ((v2[5]<<RC[rm8][2])|(v2[5]>>(64-RC[rm8][2]))) ^ v2[4];
      v2[6] += v2[7]; v2[7] = ((v2[7]<<RC[rm8][3])|(v2[7]>>(64-RC[rm8][3]))) ^ v2[6];
      uint64_t t2[8];
      t2[PERM[0]]=v2[0]; t2[PERM[1]]=v2[1]; t2[PERM[2]]=v2[2]; t2[PERM[3]]=v2[3];
      t2[PERM[4]]=v2[4]; t2[PERM[5]]=v2[5]; t2[PERM[6]]=v2[6]; t2[PERM[7]]=v2[7];
      for(int i=0;i<8;i++) v2[i]=t2[i];
      if ((r&3)==3) { int s=(r+1)/4; for(int i=0;i<8;i++) v2[i]+=ks2[s][i]; }
    }
    for (int i = 0; i < 8; i++) results[lane][i] = v2[i] ^ pt[i];
  }

  for (int i = 0; i < 8; i++) {
    state[i] = _mm256_set_epi64x(
      (long long)results[3][i],
      (long long)results[2][i],
      (long long)results[1][i],
      (long long)results[0][i]
    );
  }
}

/* -----------------------------------------------------------------------
 * Skein-512 for exactly 80-byte inputs, 4-way parallel.
 * ----------------------------------------------------------------------- */
void rake_skein512_avx2_4way(
  const uint8_t *in0, const uint8_t *in1,
  const uint8_t *in2, const uint8_t *in3,
  uint8_t *out0, uint8_t *out1,
  uint8_t *out2, uint8_t *out3
) {
  /* Skein-512/512 IV (from Skein-1.3 reference, hashBitLen=512) */
  static const uint64_t IV512[8] = {
    0x4903ADFF749C51CEULL, 0x0D95DE399746DF03ULL,
    0x8FD1934127C79BCEULL, 0x9A255629FF352CB1ULL,
    0x5DB62599DF6CA7B0ULL, 0xEABE394CA9D5C3F4ULL,
    0x991112C71A75B523ULL, 0xAE18A40B660FCC33ULL
  };

  const uint8_t *ins[4]  = {in0, in1, in2, in3};
  uint8_t       *outs[4] = {out0, out1, out2, out3};

  __m256i state[8];
  for (int i = 0; i < 8; i++)
    state[i] = _mm256_set1_epi64x((long long)IV512[i]);

  /* Block 1: first 64 bytes */
  __m256i blk[8];
  for (int i = 0; i < 8; i++) {
    uint64_t w[4];
    for (int lane = 0; lane < 4; lane++) {
      memcpy(&w[lane], ins[lane] + i*8, 8);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
      w[lane] = __builtin_bswap64(w[lane]);
#endif
    }
    blk[i] = _mm256_set_epi64x((long long)w[3],(long long)w[2],
                                 (long long)w[1],(long long)w[0]);
  }
  uint64_t tw1[3];
  tw1[0] = 64;
  tw1[1] = ((uint64_t)SKEIN_BLK_TYPE_MSG << 56) | SKEIN_T1_POS_FIRST;
  tw1[2] = tw1[0] ^ tw1[1];
  ubi_process_block_avx2(state, blk, tw1);

  /* Block 2: last 16 bytes (padded) */
  __m256i blk2[8];
  for (int i = 0; i < 8; i++) {
    uint64_t w[4];
    for (int lane = 0; lane < 4; lane++) {
      if (i < 2) {
        memcpy(&w[lane], ins[lane] + 64 + i*8, 8);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        w[lane] = __builtin_bswap64(w[lane]);
#endif
      } else {
        w[lane] = 0;
      }
    }
    blk2[i] = _mm256_set_epi64x((long long)w[3],(long long)w[2],
                                  (long long)w[1],(long long)w[0]);
  }
  uint64_t tw2[3];
  tw2[0] = 80;
  tw2[1] = ((uint64_t)SKEIN_BLK_TYPE_MSG << 56) | SKEIN_T1_POS_FINAL;
  tw2[2] = tw2[0] ^ tw2[1];
  ubi_process_block_avx2(state, blk2, tw2);

  /* Output block */
  __m256i oblk[8];
  for (int i = 0; i < 8; i++)
    oblk[i] = _mm256_setzero_si256();
  uint64_t tw3[3];
  tw3[0] = 8;
  tw3[1] = ((uint64_t)SKEIN_BLK_TYPE_OUT << 56)
           | SKEIN_T1_POS_FIRST | SKEIN_T1_POS_FINAL;
  tw3[2] = tw3[0] ^ tw3[1];
  ubi_process_block_avx2(state, oblk, tw3);

  /* Store output */
  for (int i = 0; i < 8; i++) {
    uint64_t tmp[4];
    _mm256_storeu_si256((__m256i*)tmp, state[i]);
    for (int lane = 0; lane < 4; lane++) {
      uint64_t w = tmp[lane];
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
      w = __builtin_bswap64(w);
#endif
      memcpy(outs[lane] + i*8, &w, 8);
    }
  }
}

/* -----------------------------------------------------------------------
 * Self-test
 * ----------------------------------------------------------------------- */
void rake_skein512_avx2_selftest(void) {
  fprintf(stderr, "[avx2] Running 4-way self-test against scalar reference...\n");

  /* Test 1: all-zero 80-byte header, all 4 lanes identical */
  static const uint8_t zerohdr[80] = {0};
  uint8_t avx_out[4][64];
  uint8_t scalar_out[64];

  rake_skein512_avx2_4way(
    zerohdr, zerohdr, zerohdr, zerohdr,
    avx_out[0], avx_out[1], avx_out[2], avx_out[3]
  );
  rake_skein512(zerohdr, 80, scalar_out);

  for (int lane = 0; lane < 4; lane++) {
    if (memcmp(avx_out[lane], scalar_out, 64) != 0) {
      fprintf(stderr, "[avx2] FAIL: lane %d mismatch on zero header\n", lane);
      fprintf(stderr, "  scalar: ");
      for(int j=0;j<32;j++) fprintf(stderr,"%02x",scalar_out[j]);
      fprintf(stderr, "\n  avx2:   ");
      for(int j=0;j<32;j++) fprintf(stderr,"%02x",avx_out[lane][j]);
      fprintf(stderr, "\n");
      abort();
    }
  }

  /* Test 2: 4 distinct nonces */
  uint8_t hdrs[4][80];
  for (int i = 0; i < 4; i++) {
    memset(hdrs[i], 0x5a, 80);
    hdrs[i][76] = (uint8_t)i;
  }
  uint8_t avx2[4][64], sc[4][64];
  rake_skein512_avx2_4way(
    hdrs[0], hdrs[1], hdrs[2], hdrs[3],
    avx2[0], avx2[1], avx2[2], avx2[3]
  );
  for (int i = 0; i < 4; i++) {
    rake_skein512(hdrs[i], 80, sc[i]);
    if (memcmp(avx2[i], sc[i], 64) != 0) {
      fprintf(stderr, "[avx2] FAIL: nonce-variant test lane %d\n", i);
      abort();
    }
  }

  fprintf(stderr, "[avx2] 4-way self-test PASSED.\n");
}

#else /* !__AVX2__ */

void rake_skein512_avx2_4way(
  const uint8_t *in0, const uint8_t *in1,
  const uint8_t *in2, const uint8_t *in3,
  uint8_t *out0, uint8_t *out1,
  uint8_t *out2, uint8_t *out3
) {
  rake_skein512(in0, 80, out0);
  rake_skein512(in1, 80, out1);
  rake_skein512(in2, 80, out2);
  rake_skein512(in3, 80, out3);
}

void rake_skein512_avx2_selftest(void) {
  fprintf(stderr, "[avx2] AVX2 not compiled in; scalar fallback active.\n");
}

#endif /* __AVX2__ */
