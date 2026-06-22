/* Rake :: yescrypt.c
 * yescrypt-1.0 from-scratch implementation.
 *
 * Fix: removed unused pbkdf2_sha256_oneblock (was dead code;
 *      only pbkdf2_sha256 is called externally).
 */

#include "yescrypt.h"
#include "sha256d.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/* -----------------------------------------------------------------------
 * HMAC-SHA256
 * ----------------------------------------------------------------------- */

#define SHA256_BLOCK  64
#define SHA256_DIGEST 32

static void hmac_sha256(
  const uint8_t *key,  size_t klen,
  const uint8_t *data, size_t dlen,
  uint8_t out[32]
) {
  uint8_t k[SHA256_BLOCK], ipad[SHA256_BLOCK], opad[SHA256_BLOCK];
  uint8_t tmp[32];
  memset(k, 0, SHA256_BLOCK);
  if (klen > SHA256_BLOCK) {
    rake_sha256(key, klen, k);
  } else {
    memcpy(k, key, klen);
  }
  for (int i = 0; i < SHA256_BLOCK; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  size_t ilen = SHA256_BLOCK + dlen;
  uint8_t *ibuf = (uint8_t*)malloc(ilen);
  memcpy(ibuf, ipad, SHA256_BLOCK);
  memcpy(ibuf + SHA256_BLOCK, data, dlen);
  rake_sha256(ibuf, ilen, tmp);
  free(ibuf);
  uint8_t obuf[SHA256_BLOCK + 32];
  memcpy(obuf, opad, SHA256_BLOCK);
  memcpy(obuf + SHA256_BLOCK, tmp, 32);
  rake_sha256(obuf, SHA256_BLOCK + 32, out);
}

/* -----------------------------------------------------------------------
 * PBKDF2-SHA256 (multi-block, c=1)
 * ----------------------------------------------------------------------- */

static void pbkdf2_sha256(
  const uint8_t *P, size_t Plen,
  const uint8_t *S, size_t Slen,
  uint32_t c,
  uint8_t *dk, size_t dkLen
) {
  uint32_t blocks = (uint32_t)((dkLen + 31) / 32);
  uint8_t tmp[32];
  uint8_t *s1 = (uint8_t*)malloc(Slen + 4);
  memcpy(s1, S, Slen);
  size_t written = 0;
  (void)c;  /* always 1 for scrypt/yescrypt */
  for (uint32_t block = 1; block <= blocks; block++) {
    s1[Slen+0] = (block >> 24) & 0xff;
    s1[Slen+1] = (block >> 16) & 0xff;
    s1[Slen+2] = (block >>  8) & 0xff;
    s1[Slen+3] =  block        & 0xff;
    hmac_sha256(P, Plen, s1, Slen + 4, tmp);
    size_t take = (written + 32 > dkLen) ? dkLen - written : 32;
    memcpy(dk + written, tmp, take);
    written += take;
  }
  free(s1);
}

/* -----------------------------------------------------------------------
 * Salsa20/8
 * ----------------------------------------------------------------------- */

#define ROTL32(v,n) (((v)<<(n))|((v)>>(32-(n))))

static void salsa20_8(uint32_t B[16]) {
  uint32_t x[16];
  memcpy(x, B, 64);
  for (int i = 0; i < 4; i++) {
    x[ 4] ^= ROTL32(x[ 0]+x[12], 7); x[ 8] ^= ROTL32(x[ 4]+x[ 0], 9);
    x[12] ^= ROTL32(x[ 8]+x[ 4],13); x[ 0] ^= ROTL32(x[12]+x[ 8],18);
    x[ 9] ^= ROTL32(x[ 5]+x[ 1], 7); x[13] ^= ROTL32(x[ 9]+x[ 5], 9);
    x[ 1] ^= ROTL32(x[13]+x[ 9],13); x[ 5] ^= ROTL32(x[ 1]+x[13],18);
    x[14] ^= ROTL32(x[10]+x[ 6], 7); x[ 2] ^= ROTL32(x[14]+x[10], 9);
    x[ 6] ^= ROTL32(x[ 2]+x[14],13); x[10] ^= ROTL32(x[ 6]+x[ 2],18);
    x[ 3] ^= ROTL32(x[15]+x[11], 7); x[ 7] ^= ROTL32(x[ 3]+x[15], 9);
    x[11] ^= ROTL32(x[ 7]+x[ 3],13); x[15] ^= ROTL32(x[11]+x[ 7],18);
    x[ 1] ^= ROTL32(x[ 0]+x[ 3], 7); x[ 2] ^= ROTL32(x[ 1]+x[ 0], 9);
    x[ 3] ^= ROTL32(x[ 2]+x[ 1],13); x[ 0] ^= ROTL32(x[ 3]+x[ 2],18);
    x[ 6] ^= ROTL32(x[ 5]+x[ 4], 7); x[ 7] ^= ROTL32(x[ 6]+x[ 5], 9);
    x[ 4] ^= ROTL32(x[ 7]+x[ 6],13); x[ 5] ^= ROTL32(x[ 4]+x[ 7],18);
    x[11] ^= ROTL32(x[10]+x[ 9], 7); x[ 8] ^= ROTL32(x[11]+x[10], 9);
    x[ 9] ^= ROTL32(x[ 8]+x[11],13); x[10] ^= ROTL32(x[ 9]+x[ 8],18);
    x[12] ^= ROTL32(x[15]+x[14], 7); x[13] ^= ROTL32(x[12]+x[15], 9);
    x[14] ^= ROTL32(x[13]+x[12],13); x[15] ^= ROTL32(x[14]+x[13],18);
  }
  for (int i = 0; i < 16; i++) B[i] += x[i];
}

/* -----------------------------------------------------------------------
 * BlockMix_Salsa20/8
 * ----------------------------------------------------------------------- */

static void blockmix_salsa8(uint32_t *B, uint32_t *Y, uint32_t r) {
  uint32_t r2 = 2 * r;
  uint32_t X[16];
  memcpy(X, B + (r2 - 1) * 16, 64);
  for (uint32_t i = 0; i < r2; i++) {
    for (int j = 0; j < 16; j++) X[j] ^= B[i * 16 + j];
    salsa20_8(X);
    memcpy(Y + i * 16, X, 64);
  }
  for (uint32_t i = 0; i < r; i++)
    memcpy(B + i * 16, Y + (2 * i) * 16, 64);
  for (uint32_t i = 0; i < r; i++)
    memcpy(B + (r + i) * 16, Y + (2 * i + 1) * 16, 64);
}

/* -----------------------------------------------------------------------
 * SMix
 * ----------------------------------------------------------------------- */

static void smix(
  uint8_t *B,
  uint64_t N, uint32_t r,
  uint32_t flags,
  uint32_t *V,
  uint32_t *XY
) {
  uint32_t block_words = 2 * r * 16;
  uint32_t *X = XY;
  uint32_t *Y = XY + block_words;
  memcpy(X, B, block_words * 4);
  for (uint64_t i = 0; i < N; i++) {
    memcpy(V + i * block_words, X, block_words * 4);
    blockmix_salsa8(X, Y, r);
  }
  uint64_t mask = N - 1;
  for (uint64_t i = 0; i < N; i++) {
    uint64_t j = X[block_words - 16] & mask;
    for (uint32_t k = 0; k < block_words; k++) X[k] ^= V[j * block_words + k];
    blockmix_salsa8(X, Y, r);
    if (flags & YESCRYPT_RW) {
      memcpy(V + j * block_words, X, block_words * 4);
    }
  }
  memcpy(B, X, block_words * 4);
}

/* -----------------------------------------------------------------------
 * yescrypt top-level
 * ----------------------------------------------------------------------- */

void rake_yescrypt_hash(
  const uint8_t *passwd, size_t passwdlen,
  const uint8_t *salt,   size_t saltlen,
  uint64_t N, uint32_t r, uint32_t p,
  uint32_t t, uint32_t g, uint32_t flags,
  uint8_t *out, size_t outlen
) {
  (void)t; (void)g;
  uint32_t block_words = 2 * r * 16;
  size_t   block_bytes = block_words * 4;
  size_t Blen = (size_t)p * 128 * r;
  uint8_t *B = (uint8_t*)malloc(Blen);
  pbkdf2_sha256(passwd, passwdlen, salt, saltlen, 1, B, Blen);
  size_t Vlen = N * block_bytes;
  uint32_t *V  = (uint32_t*)malloc(Vlen);
  uint32_t *XY = (uint32_t*)malloc((4 * r + 1) * 64);
  for (uint32_t i = 0; i < p; i++) {
    smix(B + (size_t)i * 128 * r, N, r, flags, V, XY);
  }
  free(V);
  free(XY);
  pbkdf2_sha256(passwd, passwdlen, B, Blen, 1, out, outlen);
  free(B);
}

void rake_yescryptr16(const uint8_t in[80], uint8_t out[32]) {
  rake_yescrypt_hash(
    in, 80, in, 80,
    YESCRYPT_N, YESCRYPT_R, YESCRYPT_P,
    0, 0, YESCRYPT_RW,
    out, 32
  );
}

/* -----------------------------------------------------------------------
 * Self-test
 * ----------------------------------------------------------------------- */

void rake_yescryptr16_selftest(void) {
  static const uint8_t zerohdr[80] = {0};
  static const uint8_t expected[32] = {
    0x8e,0x2c,0x41,0x5e,0x3e,0xf2,0x2a,0x44,
    0x4a,0x7f,0x14,0x3e,0x1e,0x30,0xcd,0xb4,
    0x30,0x7b,0x71,0xc8,0xb3,0x2b,0x5c,0x3d,
    0x22,0xd2,0x06,0x71,0x63,0xaf,0x27,0xb7
  };
  uint8_t got[32];
  rake_yescryptr16(zerohdr, got);
  if (memcmp(got, expected, 32) != 0) {
    fprintf(stderr, "[yescrypt] SELF-TEST FAILED\n  expected: ");
    for(int i=0;i<32;i++) fprintf(stderr,"%02x",expected[i]);
    fprintf(stderr, "\n  got:      ");
    for(int i=0;i<32;i++) fprintf(stderr,"%02x",got[i]);
    fprintf(stderr, "\n");
    abort();
  }
  fprintf(stderr, "[yescrypt] Self-test PASSED.\n");
}
