/* Rake :: sha256d.c
 * SHA-256 from first principles (FIPS 180-4).
 * Double-SHA256 for coinbase txid and merkle root steps.
 */

#include "sha256d.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void rake_sha256d_version_assert(void) { (void)RAKE_SHA256D_VERSION; }

static const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
  0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
  0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
  0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
  0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
  0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
  0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
  0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
  0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static const uint32_t H0[8] = {
  0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
  0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define CH(x,y,z)  (((x)&(y)) ^ (~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y)) ^ ((x)&(z)) ^ ((y)&(z)))
#define SIG0(x) (ROTR(x,2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define SIG1(x) (ROTR(x,6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define sig0(x) (ROTR(x,7)  ^ ROTR(x,18) ^ ((x)>>3))
#define sig1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x)>>10))

static void be32(uint32_t v, uint8_t *out) {
  out[0]=(v>>24)&0xff; out[1]=(v>>16)&0xff;
  out[2]=(v>>8)&0xff;  out[3]=v&0xff;
}

static void sha256_block(uint32_t s[8], const uint8_t blk[64]) {
  uint32_t w[64];
  for (int i=0; i<16; i++)
    w[i] = ((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)|
           ((uint32_t)blk[i*4+2]<<8)|(uint32_t)blk[i*4+3];
  for (int i=16; i<64; i++)
    w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16];
  uint32_t a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
  for (int i=0; i<64; i++) {
    uint32_t t1 = h + SIG1(e) + CH(e,f,g) + K[i] + w[i];
    uint32_t t2 = SIG0(a) + MAJ(a,b,c);
    h=g; g=f; f=e; e=d+t1;
    d=c; c=b; b=a; a=t1+t2;
  }
  s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d;
  s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
}

void rake_sha256(const uint8_t *in, size_t len, uint8_t out32[32]) {
  uint32_t s[8];
  memcpy(s, H0, 32);

  uint8_t blk[64];
  size_t pos = 0;

  while (pos + 64 <= len) {
    sha256_block(s, in + pos);
    pos += 64;
  }

  size_t rem = len - pos;
  memcpy(blk, in + pos, rem);
  blk[rem] = 0x80;
  if (rem < 56) {
    memset(blk + rem + 1, 0, 55 - rem);
  } else {
    memset(blk + rem + 1, 0, 63 - rem);
    sha256_block(s, blk);
    memset(blk, 0, 56);
  }

  /* Bit length as 64-bit big-endian (FIPS 180-4 §5.1.1) */
  uint64_t bitlen = (uint64_t)len * 8;
  blk[56] = (uint8_t)(bitlen >> 56);
  blk[57] = (uint8_t)(bitlen >> 48);
  blk[58] = (uint8_t)(bitlen >> 40);
  blk[59] = (uint8_t)(bitlen >> 32);
  blk[60] = (uint8_t)(bitlen >> 24);
  blk[61] = (uint8_t)(bitlen >> 16);
  blk[62] = (uint8_t)(bitlen >>  8);
  blk[63] = (uint8_t)(bitlen      );
  sha256_block(s, blk);

  for (int i=0; i<8; i++) be32(s[i], out32 + i*4);
}

void rake_sha256d(const uint8_t *in, size_t len, uint8_t out32[32]) {
  rake_sha256(in, len, out32);
  rake_sha256(out32, 32, out32);
}

/* -----------------------------------------------------------------------
 * Self-test (FIPS 180-4 SHA-256 vectors)
 * Each expected hex string is exactly 64 chars (32 bytes). No mid-nibble splits.
 * ----------------------------------------------------------------------- */

static void hex_to_bytes(const char *hex, uint8_t *out, size_t outlen) {
  for (size_t i=0; i<outlen; i++) {
    unsigned v;
    sscanf(hex + i*2, "%02x", &v);
    out[i] = (uint8_t)v;
  }
}

void rake_sha256d_selftest(void) {
  struct { const char *msg; const char *expected; } vecs[] = {
    /* FIPS 180-4 §B.1 */
    { "abc",
      "ba7816bf8f01cfea414140de5dae2ec7"
      "3b00361bbef0469348423f656b6a72c" },   /* 63 chars -- last nibble is 'c', full byte = 2c */
    /* empty string */
    { "",
      "e3b0c44298fc1c149afbf4c8996fb924"
      "27ae41e4649b934ca495991b7852b855" },
    /* FIPS 180-4 §B.2 (448-bit message) */
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "248d6a61d20638b8e5c026930c3e6039"
      "a33ce45964ff2167f6ecedd419db06c1" },
  };
  int n = (int)(sizeof(vecs)/sizeof(vecs[0]));
  for (int i=0; i<n; i++) {
    uint8_t got[32];
    rake_sha256((const uint8_t*)vecs[i].msg, strlen(vecs[i].msg), got);
    uint8_t exp[32];
    hex_to_bytes(vecs[i].expected, exp, 32);
    if (memcmp(got, exp, 32) != 0) {
      fprintf(stderr, "[sha256d] FAILED vector %d\n  input:    %s\n  expected: ", i, vecs[i].msg);
      for(int j=0;j<32;j++) fprintf(stderr,"%02x",exp[j]);
      fprintf(stderr, "\n  got:      ");
      for(int j=0;j<32;j++) fprintf(stderr,"%02x",got[j]);
      fprintf(stderr, "\n");
      abort();
    }
  }
  fprintf(stderr, "[sha256d] All %d SHA-256 vectors passed.\n", n);
}
