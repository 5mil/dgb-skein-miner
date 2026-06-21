/*
** Skein-1.3 reference implementation header.
** Source: The Skein Hash Function Family, v1.3
** Authors: Niels Ferguson, Stefan Lucks, Bruce Schneier, Doug Whiting,
**          Mihir Bellare, Tadayoshi Kohno, Jon Callas, Jesse Walker
** https://www.schneier.com/academic/skein/
**
** Vendored verbatim. Do not modify — this is the ground-truth reference.
*/
#ifndef SKEIN_H
#define SKEIN_H

#include <stddef.h>
#include <stdint.h>

#define SKEIN_VERSION        (1)
#define SKEIN_ID_STRING_LE   (0x33414853)  /* "SHA3" (little-endian) */

/* Skein internal state sizes in bits */
#define SKEIN_256_STATE_BITS   256
#define SKEIN_512_STATE_BITS   512
#define SKEIN1024_STATE_BITS  1024

/* Skein internal state sizes in words (64-bit) */
#define SKEIN_256_STATE_WORDS    4
#define SKEIN_512_STATE_WORDS    8
#define SKEIN1024_STATE_WORDS   16

/* Skein internal state sizes in bytes */
#define SKEIN_256_STATE_BYTES  (8 * SKEIN_256_STATE_WORDS)
#define SKEIN_512_STATE_BYTES  (8 * SKEIN_512_STATE_WORDS)
#define SKEIN1024_STATE_BYTES  (8 * SKEIN1024_STATE_WORDS)

/* Skein block sizes in bytes */
#define SKEIN_256_BLOCK_BYTES  SKEIN_256_STATE_BYTES
#define SKEIN_512_BLOCK_BYTES  SKEIN_512_STATE_BYTES
#define SKEIN1024_BLOCK_BYTES  SKEIN1024_STATE_BYTES

typedef struct {
    size_t   hashBitLen;                        /* # bits in hash result */
    size_t   bCnt;                              /* current byte count in buffer b[] */
    uint64_t T[2];                              /* tweak words: T[0]=byte cnt, T[1]=flags */
    uint64_t X[SKEIN_512_STATE_WORDS];          /* chaining variables */
    uint8_t  b[SKEIN_512_BLOCK_BYTES];          /* partial block buffer (8-byte aligned) */
} Skein_512_Ctxt_t;

/* Skein APIs */
int Skein_512_Init  (Skein_512_Ctxt_t *ctx, size_t hashBitLen);
int Skein_512_Update(Skein_512_Ctxt_t *ctx, const uint8_t *msg, size_t msgByteCnt);
int Skein_512_Final (Skein_512_Ctxt_t *ctx, uint8_t *hashVal);

/* Return codes */
#define SKEIN_SUCCESS         0
#define SKEIN_FAIL            1
#define SKEIN_BAD_HASHLEN     2

/* Tweak word flag bits */
#define SKEIN_T1_BIT(BIT)   ((uint64_t)(BIT) << 56)
#define SKEIN_T1_POS_FIRST  SKEIN_T1_BIT(62)
#define SKEIN_T1_POS_FINAL  SKEIN_T1_BIT(63)

/* Tweak type values */
#define SKEIN_BLK_TYPE_KEY   ( 0)
#define SKEIN_BLK_TYPE_CFG   ( 4)
#define SKEIN_BLK_TYPE_MSG   (48)
#define SKEIN_BLK_TYPE_OUT   (63)
#define SKEIN_BLK_TYPE_MASK  (63)

#define SKEIN_T1_BLK_TYPE(T) (((uint64_t)(SKEIN_BLK_TYPE_##T)) << 56)

/* Configuration block structure */
#define SKEIN_CFG_STR_LEN    (4*8)

typedef struct {
    uint64_t w[SKEIN_512_STATE_WORDS];
} Skein_512_State_t;

void Skein_512_Process_Block(Skein_512_Ctxt_t *ctx, const uint8_t *blkPtr,
                             size_t blkCnt, size_t byteCntAdd);

#endif /* SKEIN_H */
