/* Rake :: skein.c
 * Skein-512 / Threefish-512.
 * Correct implementation matching all Skein-1.3 official test vectors.
 */

#include "skein.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Rotation constants, Skein-1.3 Table 4, Nw=8 */
static const int R512[8][4] = {
    {46, 36, 19, 37}, {33, 27, 14, 42},
    {17, 49, 36, 39}, {44,  9, 54, 56},
    {39, 30, 34, 24}, {13, 50, 10, 17},
    {25, 29, 39, 43}, { 8, 35, 56, 22}
};

/* Word permutation pi, Nw=8 */
static const int PI8[8] = {2, 1, 4, 7, 6, 5, 0, 3};

#define C240     UINT64_C(0x1BD11BDAA9FC1A22)
#define ROTL64(v,n) (((v) << (n)) | ((v) >> (64-(n))))

/* -----------------------------------------------------------------------
 * Threefish-512 encrypt.
 * key[0..8]: key words, key[8] = C240 ^ key[0..7] (pre-computed by caller)
 * tw[0..2]:  tweak, tw[2] = tw[0]^tw[1] (pre-computed by caller)
 * ----------------------------------------------------------------------- */
static void threefish512(
    const uint64_t key[9],
    const uint64_t tw[3],
    const uint64_t pt[8],
    uint64_t       ct[8]
) {
    uint64_t v[8];
    for (int i = 0; i < 8; i++) v[i] = pt[i];

    /* Subkey injection s=0 */
    v[0] += key[0]; v[1] += key[1]; v[2] += key[2]; v[3] += key[3];
    v[4] += key[4];
    v[5] += key[5] + tw[0];
    v[6] += key[6] + tw[1];
    v[7] += key[7]; /* + 0 (s=0) */

    for (int d = 0; d < 72; d++) {
        /* Mix */
        const int *rc = R512[d & 7];
        v[0] += v[1]; v[1] = ROTL64(v[1], rc[0]) ^ v[0];
        v[2] += v[3]; v[3] = ROTL64(v[3], rc[1]) ^ v[2];
        v[4] += v[5]; v[5] = ROTL64(v[5], rc[2]) ^ v[4];
        v[6] += v[7]; v[7] = ROTL64(v[7], rc[3]) ^ v[6];

        /* Permute */
        uint64_t t[8];
        for (int i = 0; i < 8; i++) t[i] = v[PI8[i]];
        for (int i = 0; i < 8; i++) v[i] = t[i];

        /* Subkey injection every 4 rounds: after rounds 3,7,11,...,71 */
        if ((d & 3) == 3) {
            unsigned s = (unsigned)(d + 1) >> 2;   /* 1..18 */
            v[0] += key[ s    % 9];
            v[1] += key[(s+1) % 9];
            v[2] += key[(s+2) % 9];
            v[3] += key[(s+3) % 9];
            v[4] += key[(s+4) % 9];
            v[5] += key[(s+5) % 9] + tw[s % 3];
            v[6] += key[(s+6) % 9] + tw[(s+1) % 3];
            v[7] += key[(s+7) % 9] + (uint64_t)s;
        }
    }
    for (int i = 0; i < 8; i++) ct[i] = v[i];
}

/* -----------------------------------------------------------------------
 * UBI block processing (one 64-byte block).
 * bytesThisBlock: actual message bytes in this block (for T[0] update).
 * The caller must have already set ctx->T[1] with type/flag bits.
 * ctx->T[0] is incremented here, then T[2] = T[0]^T[1] is derived.
 * ----------------------------------------------------------------------- */
static void ubi_block(
    Skein_512_Ctxt_t *ctx,
    const uint8_t    *blk,
    size_t            bytesThisBlock
) {
    /* 1. Update byte counter FIRST, then compute T[2] */
    ctx->T[0] += (uint64_t)bytesThisBlock;
    ctx->T[2]  = ctx->T[0] ^ ctx->T[1];

    /* 2. Load block as little-endian uint64 words */
    uint64_t pt[8];
    for (int i = 0; i < 8; i++) {
        const uint8_t *p = blk + i * 8;
        pt[i] = (uint64_t)p[0]        | ((uint64_t)p[1] <<  8)
              | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24)
              | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40)
              | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
    }

    /* 3. Build key schedule from current chaining value */
    uint64_t key[9];
    key[8] = C240;
    for (int i = 0; i < 8; i++) { key[i] = ctx->X[i]; key[8] ^= ctx->X[i]; }

    /* 4. Threefish-512 encrypt */
    uint64_t ct[8];
    threefish512(key, ctx->T, pt, ct);

    /* 5. Feed-forward XOR */
    for (int i = 0; i < 8; i++) ctx->X[i] = ct[i] ^ pt[i];

    /* 6. Clear FIRST flag */
    ctx->T[1] &= ~SKEIN_T1_POS_FIRST;
}

void Skein_512_Process_Block(
    Skein_512_Ctxt_t *ctx,
    const uint8_t    *blkPtr,
    size_t            blkCnt,
    size_t            byteCntAdd
) {
    while (blkCnt--) {
        ubi_block(ctx, blkPtr, byteCntAdd);
        blkPtr += SKEIN_512_BLOCK_BYTES;
    }
}

/* -----------------------------------------------------------------------
 * Skein_512_Init: derive IV by processing the configuration block.
 * ----------------------------------------------------------------------- */
int Skein_512_Init(Skein_512_Ctxt_t *ctx, size_t hashBitLen) {
    if (hashBitLen == 0 || hashBitLen > 512) return SKEIN_BAD_HASHLEN;
    ctx->hashBitLen = hashBitLen;
    ctx->bCnt       = 0;
    memset(ctx->X, 0, sizeof(ctx->X));

    /* Configuration string (32 bytes, zero-padded to 64) */
    uint8_t cfg[SKEIN_512_BLOCK_BYTES];
    memset(cfg, 0, sizeof(cfg));
    cfg[0]=0x53; cfg[1]=0x48; cfg[2]=0x41; cfg[3]=0x33; /* "SHA3" */
    cfg[4]=1;    cfg[5]=0;                               /* version 1 */
    uint64_t ob = (uint64_t)hashBitLen;
    for (int i = 0; i < 8; i++) cfg[8+i] = (uint8_t)(ob >> (8*i));

    ctx->T[0] = 0;
    ctx->T[1] = SKEIN_T1_BLK_TYPE(CFG) | SKEIN_T1_POS_FIRST | SKEIN_T1_POS_FINAL;
    ubi_block(ctx, cfg, SKEIN_CFG_STR_LEN);

    /* Ready for message */
    ctx->T[0] = 0;
    ctx->T[1] = SKEIN_T1_BLK_TYPE(MSG) | SKEIN_T1_POS_FIRST;
    return SKEIN_SUCCESS;
}

/* -----------------------------------------------------------------------
 * Skein_512_Update
 * ----------------------------------------------------------------------- */
int Skein_512_Update(Skein_512_Ctxt_t *ctx, const uint8_t *msg, size_t msgByteCnt) {
    if (msgByteCnt == 0) return SKEIN_SUCCESS;

    /* Fill partial buffer first */
    if (ctx->bCnt > 0) {
        size_t n = SKEIN_512_BLOCK_BYTES - ctx->bCnt;
        if (n > msgByteCnt) n = msgByteCnt;
        memcpy(ctx->b + ctx->bCnt, msg, n);
        ctx->bCnt  += n;
        msg        += n;
        msgByteCnt -= n;
        /* Only process buffered block if there is MORE data coming.
         * If msgByteCnt==0, this might be the last block; leave it for Final. */
        if (msgByteCnt == 0) return SKEIN_SUCCESS;
        ubi_block(ctx, ctx->b, SKEIN_512_BLOCK_BYTES);
        ctx->bCnt = 0;
    }

    /* Process full blocks, always keeping >= 1 byte for Final */
    while (msgByteCnt > SKEIN_512_BLOCK_BYTES) {
        ubi_block(ctx, msg, SKEIN_512_BLOCK_BYTES);
        msg        += SKEIN_512_BLOCK_BYTES;
        msgByteCnt -= SKEIN_512_BLOCK_BYTES;
    }

    /* Buffer the remainder (1..64 bytes) */
    memcpy(ctx->b, msg, msgByteCnt);
    ctx->bCnt = msgByteCnt;
    return SKEIN_SUCCESS;
}

/* -----------------------------------------------------------------------
 * Skein_512_Final
 * ----------------------------------------------------------------------- */
int Skein_512_Final(Skein_512_Ctxt_t *ctx, uint8_t *hashVal) {
    /* Zero-pad, set FINAL, process last message block */
    ctx->T[1] |= SKEIN_T1_POS_FINAL;
    if (ctx->bCnt < SKEIN_512_BLOCK_BYTES)
        memset(ctx->b + ctx->bCnt, 0, SKEIN_512_BLOCK_BYTES - ctx->bCnt);
    ubi_block(ctx, ctx->b, ctx->bCnt);

    /* Output transform: UBI with type=OUT, FIRST|FINAL, counter=0 */
    uint8_t outBlk[SKEIN_512_BLOCK_BYTES];
    memset(outBlk, 0, sizeof(outBlk));   /* 64-bit counter = 0, LE */
    ctx->T[0] = 0;
    ctx->T[1] = SKEIN_T1_BLK_TYPE(OUT) | SKEIN_T1_POS_FIRST | SKEIN_T1_POS_FINAL;
    ubi_block(ctx, outBlk, sizeof(uint64_t)); /* byteCntAdd = 8 */

    /* Serialize chaining value as little-endian bytes */
    size_t byteCnt = (ctx->hashBitLen + 7) >> 3;
    for (size_t i = 0; i < byteCnt; i++)
        hashVal[i] = (uint8_t)(ctx->X[i >> 3] >> ((i & 7) << 3));

    return SKEIN_SUCCESS;
}
