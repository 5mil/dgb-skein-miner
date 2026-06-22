/* Rake :: skein.c
 * Skein-512 / Threefish-512 — correct reference implementation.
 *
 * Derived from the Skein 1.3 reference submission (public domain).
 * All constants and round structure match the official test vectors.
 *
 * Threefish-512:
 *   - 8 64-bit words
 *   - 72 rounds
 *   - Subkey injection every 4 rounds (at rounds 0,4,8,...,72) = 19 injections
 *   - Word permutation pi = [2,1,4,7,6,5,0,3] after every round
 *   - Mix uses 4 pairs: (0,1),(2,3),(4,5),(6,7)
 *   - Rotation constants from Skein-1.3, Table 4
 */

#include "skein.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* -----------------------------------------------------------------------
 * Rotation constants (Skein-1.3, Table 4, Nw=8)
 * Row index = round mod 8
 * Col index = mix pair (0..3)
 * ----------------------------------------------------------------------- */
static const int R512[8][4] = {
    {46, 36, 19, 37},
    {33, 27, 14, 42},
    {17, 49, 36, 39},
    {44,  9, 54, 56},
    {39, 30, 34, 24},
    {13, 50, 10, 17},
    {25, 29, 39, 43},
    { 8, 35, 56, 22}
};

/* Threefish-512 word permutation (pi) */
static const int PI8[8] = {2, 1, 4, 7, 6, 5, 0, 3};

#define C240 UINT64_C(0x1BD11BDAA9FC1A22)
#define ROTL64(v,n) (((v) << (n)) | ((v) >> (64-(n))))

/* -----------------------------------------------------------------------
 * Threefish-512 block encrypt.
 * key[0..7]: 8-word key (= chaining value)
 * tweak[0..1]: 2-word tweak; tweak[2] = tweak[0]^tweak[1] (caller sets)
 * pt[0..7]: plaintext input words (little-endian, already loaded)
 * ct[0..7]: ciphertext output words
 * ----------------------------------------------------------------------- */
static void threefish512(
    const uint64_t key[9],    /* key[8] = C240 ^ key[0..7] */
    const uint64_t tweak[3],  /* tweak[2] = tweak[0]^tweak[1] */
    const uint64_t pt[8],
    uint64_t       ct[8]
) {
    uint64_t v[8];
    for (int i = 0; i < 8; i++) v[i] = pt[i];

    /* Subkey injection 0 */
    v[0] += key[0]; v[1] += key[1]; v[2] += key[2]; v[3] += key[3];
    v[4] += key[4]; v[5] += key[5] + tweak[0];
    v[6] += key[6] + tweak[1]; v[7] += key[7];

    for (int d = 0; d < 72; d++) {
        /* Mix */
        int rm = d & 7;
        v[0] += v[1]; v[1] = ROTL64(v[1], R512[rm][0]) ^ v[0];
        v[2] += v[3]; v[3] = ROTL64(v[3], R512[rm][1]) ^ v[2];
        v[4] += v[5]; v[5] = ROTL64(v[5], R512[rm][2]) ^ v[4];
        v[6] += v[7]; v[7] = ROTL64(v[7], R512[rm][3]) ^ v[6];

        /* Permute */
        uint64_t t[8];
        t[0]=v[PI8[0]]; t[1]=v[PI8[1]]; t[2]=v[PI8[2]]; t[3]=v[PI8[3]];
        t[4]=v[PI8[4]]; t[5]=v[PI8[5]]; t[6]=v[PI8[6]]; t[7]=v[PI8[7]];
        for (int i = 0; i < 8; i++) v[i] = t[i];

        /* Subkey injection every 4 rounds */
        if ((d & 3) == 3) {
            int s = (d + 1) / 4;   /* s = 1..18 */
            v[0] += key[s % 9];
            v[1] += key[(s+1) % 9];
            v[2] += key[(s+2) % 9];
            v[3] += key[(s+3) % 9];
            v[4] += key[(s+4) % 9];
            v[5] += key[(s+5) % 9] + tweak[s % 3];
            v[6] += key[(s+6) % 9] + tweak[(s+1) % 3];
            v[7] += key[(s+7) % 9] + (uint64_t)s;
        }
    }
    for (int i = 0; i < 8; i++) ct[i] = v[i];
}

/* -----------------------------------------------------------------------
 * UBI (Unique Block Iteration) chaining.
 * Updates ctx->X in-place.
 * blk: one 64-byte block (padded by caller)
 * bytesInBlock: actual payload bytes in this block
 * ----------------------------------------------------------------------- */
static void ubi_process(
    Skein_512_Ctxt_t *ctx,
    const uint8_t    *blk,
    size_t            bytesInBlock
) {
    /* Update T0 byte counter */
    ctx->T[0] += (uint64_t)bytesInBlock;
    ctx->T[2]  = ctx->T[0] ^ ctx->T[1];

    /* Load block as little-endian uint64 words */
    uint64_t pt[8];
    for (int i = 0; i < 8; i++) {
        pt[i]  = (uint64_t)blk[i*8+0]       | ((uint64_t)blk[i*8+1] <<  8)
               | ((uint64_t)blk[i*8+2] << 16) | ((uint64_t)blk[i*8+3] << 24)
               | ((uint64_t)blk[i*8+4] << 32) | ((uint64_t)blk[i*8+5] << 40)
               | ((uint64_t)blk[i*8+6] << 48) | ((uint64_t)blk[i*8+7] << 56);
    }

    /* Build key schedule: key[8] = C240 ^ key[0..7] */
    uint64_t key[9];
    key[8] = C240;
    for (int i = 0; i < 8; i++) {
        key[i]  = ctx->X[i];
        key[8] ^= ctx->X[i];
    }

    uint64_t ct[8];
    threefish512(key, ctx->T, pt, ct);

    /* Feed-forward XOR */
    for (int i = 0; i < 8; i++) ctx->X[i] = ct[i] ^ pt[i];

    /* Clear FIRST flag after first block */
    ctx->T[1] &= ~SKEIN_T1_POS_FIRST;
}

/* -----------------------------------------------------------------------
 * Skein_512_Process_Block (called by Update and Final internals)
 * ----------------------------------------------------------------------- */
void Skein_512_Process_Block(
    Skein_512_Ctxt_t *ctx,
    const uint8_t    *blkPtr,
    size_t            blkCnt,
    size_t            byteCntAdd
) {
    do {
        ubi_process(ctx, blkPtr, byteCntAdd);
        blkPtr += SKEIN_512_BLOCK_BYTES;
    } while (--blkCnt);
}

/* -----------------------------------------------------------------------
 * Skein_512_Init
 * Processes the Skein configuration block to derive the IV.
 * ----------------------------------------------------------------------- */
int Skein_512_Init(Skein_512_Ctxt_t *ctx, size_t hashBitLen) {
    if (hashBitLen == 0 || hashBitLen > 512) return SKEIN_BAD_HASHLEN;
    ctx->hashBitLen = hashBitLen;
    ctx->bCnt       = 0;

    /* Zero initial chaining value */
    memset(ctx->X, 0, sizeof(ctx->X));

    /* Configuration block: 32 bytes, zero-padded to 64 */
    uint8_t cfg[SKEIN_512_BLOCK_BYTES];
    memset(cfg, 0, sizeof(cfg));
    /* Schema ID "SHA3" = 0x33414853 little-endian in first 4 bytes */
    cfg[0] = 0x53; cfg[1] = 0x48; cfg[2] = 0x41; cfg[3] = 0x33;
    /* Version = 1 (bytes 4-5) */
    cfg[4] = 1; cfg[5] = 0;
    /* Reserved bytes 6-7 = 0 */
    /* Output length in bits, little-endian 64-bit (bytes 8-15) */
    uint64_t outBits = (uint64_t)hashBitLen;
    for (int i = 0; i < 8; i++) cfg[8+i] = (uint8_t)(outBits >> (8*i));

    /* Process config block with type=CFG, FIRST|FINAL */
    ctx->T[0] = 0;
    ctx->T[1] = SKEIN_T1_BLK_TYPE(CFG) | SKEIN_T1_POS_FIRST | SKEIN_T1_POS_FINAL;
    ctx->T[2] = ctx->T[0] ^ ctx->T[1];
    ubi_process(ctx, cfg, SKEIN_CFG_STR_LEN);

    /* Set up for message processing */
    ctx->T[0] = 0;
    ctx->T[1] = SKEIN_T1_BLK_TYPE(MSG) | SKEIN_T1_POS_FIRST;
    ctx->T[2] = ctx->T[0] ^ ctx->T[1];
    return SKEIN_SUCCESS;
}

/* -----------------------------------------------------------------------
 * Skein_512_Update
 * ----------------------------------------------------------------------- */
int Skein_512_Update(Skein_512_Ctxt_t *ctx, const uint8_t *msg, size_t msgByteCnt) {
    if (msgByteCnt == 0) return SKEIN_SUCCESS;

    if (ctx->bCnt > 0) {
        size_t n = SKEIN_512_BLOCK_BYTES - ctx->bCnt;
        if (n > msgByteCnt) n = msgByteCnt;
        memcpy(ctx->b + ctx->bCnt, msg, n);
        ctx->bCnt  += n;
        msg        += n;
        msgByteCnt -= n;
        if (msgByteCnt == 0) return SKEIN_SUCCESS;
        /* Buffer is full and there is more data: process it (not final) */
        ubi_process(ctx, ctx->b, SKEIN_512_BLOCK_BYTES);
        ctx->bCnt = 0;
    }

    /* Process full blocks — keep at least 1 byte buffered so Final
     * can set SKEIN_T1_POS_FINAL on the last block */
    while (msgByteCnt > SKEIN_512_BLOCK_BYTES) {
        ubi_process(ctx, msg, SKEIN_512_BLOCK_BYTES);
        msg        += SKEIN_512_BLOCK_BYTES;
        msgByteCnt -= SKEIN_512_BLOCK_BYTES;
    }

    memcpy(ctx->b, msg, msgByteCnt);
    ctx->bCnt = msgByteCnt;
    return SKEIN_SUCCESS;
}

/* -----------------------------------------------------------------------
 * Skein_512_Final
 * ----------------------------------------------------------------------- */
int Skein_512_Final(Skein_512_Ctxt_t *ctx, uint8_t *hashVal) {
    /* Zero-pad and mark final */
    ctx->T[1] |= SKEIN_T1_POS_FINAL;
    if (ctx->bCnt < SKEIN_512_BLOCK_BYTES)
        memset(ctx->b + ctx->bCnt, 0, SKEIN_512_BLOCK_BYTES - ctx->bCnt);
    ubi_process(ctx, ctx->b, ctx->bCnt);

    /* Output transform: counter mode, block = 0-word counter (little-endian) */
    uint8_t outBlk[SKEIN_512_BLOCK_BYTES];
    memset(outBlk, 0, sizeof(outBlk));   /* counter = 0 for first output block */
    ctx->T[0] = 0;
    ctx->T[1] = SKEIN_T1_BLK_TYPE(OUT) | SKEIN_T1_POS_FIRST | SKEIN_T1_POS_FINAL;
    ctx->T[2] = ctx->T[0] ^ ctx->T[1];
    ubi_process(ctx, outBlk, sizeof(uint64_t));

    /* Write output (little-endian words) */
    size_t byteCnt = (ctx->hashBitLen + 7) >> 3;
    for (size_t i = 0; i < byteCnt; i++)
        hashVal[i] = (uint8_t)(ctx->X[i/8] >> (8*(i%8)));

    return SKEIN_SUCCESS;
}
