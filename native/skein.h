/* Rake :: skein.h
 * Skein-512 context and API.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SKEIN_SUCCESS    0
#define SKEIN_BAD_HASHLEN 1

#define SKEIN_512_BLOCK_BYTES  64
#define SKEIN_512_STATE_WORDS   8
#define SKEIN_CFG_STR_LEN      32

/* Tweak type bits (T[1]) */
#define SKEIN_T1_POS_FIRST  (UINT64_C(1) << 62)
#define SKEIN_T1_POS_FINAL  (UINT64_C(1) << 63)

/* Block type values */
#define SKEIN_BLK_TYPE_CFG   4
#define SKEIN_BLK_TYPE_MSG  48
#define SKEIN_BLK_TYPE_OUT  63

#define SKEIN_T1_BLK_TYPE(t) (((uint64_t)(SKEIN_BLK_TYPE_##t)) << 56)

typedef struct {
    uint64_t X[8];           /* current chaining value */
    uint64_t T[3];           /* T[0]=byte count, T[1]=tweak flags, T[2]=T[0]^T[1] */
    uint8_t  b[SKEIN_512_BLOCK_BYTES]; /* partial block buffer */
    size_t   bCnt;           /* bytes in b */
    size_t   hashBitLen;
} Skein_512_Ctxt_t;

void Skein_512_Process_Block(Skein_512_Ctxt_t *ctx, const uint8_t *blkPtr,
                              size_t blkCnt, size_t byteCntAdd);
int  Skein_512_Init  (Skein_512_Ctxt_t *ctx, size_t hashBitLen);
int  Skein_512_Update(Skein_512_Ctxt_t *ctx, const uint8_t *msg, size_t msgByteCnt);
int  Skein_512_Final (Skein_512_Ctxt_t *ctx, uint8_t *hashVal);

#ifdef __cplusplus
}
#endif
