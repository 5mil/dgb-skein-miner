/*
** Rake :: skein_bridge.c
** Thin wrapper + full self-test suite.
**
** Test vectors sourced from:
**   The Skein Hash Function Family, Version 1.3
**   https://www.schneier.com/academic/skein/
**   Appendix B: Test Vectors
**
** ALL vectors are 128 hex chars (64 bytes = 512 bits). Do NOT split
** the hex string across two string literals mid-nibble.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skein.h"
#include "skein_bridge.h"

void rake_skein_version_assert(void) {
    if (RAKE_BRIDGE_VERSION != 1) {
        fprintf(stderr,
            "[rake] FATAL: skein_bridge version mismatch. "
            "Expected 1, got %d. Recompile.\n",
            RAKE_BRIDGE_VERSION);
        abort();
    }
}

int rake_skein512(const uint8_t *in, size_t in_len, uint8_t *out) {
    Skein_512_Ctxt_t ctx;
    int r;
    r = Skein_512_Init(&ctx, 512);           if (r) return r;
    r = Skein_512_Update(&ctx, in, in_len);  if (r) return r;
    r = Skein_512_Final(&ctx, out);          return r;
}

int rake_skein512_batch(const uint8_t **inputs, const size_t *in_lens,
                        uint8_t **outputs, size_t count) {
    size_t i;
    int failures = 0;
    for (i = 0; i < count; i++) {
        if (rake_skein512(inputs[i], in_lens[i], outputs[i]) != 0)
            failures++;
    }
    return failures;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    size_t i;
    for (i = 0; i < out_len; i++)
        out[i] = (uint8_t)((hex_nibble(hex[2*i]) << 4) | hex_nibble(hex[2*i+1]));
}

typedef struct {
    const char *label;
    const char *input_hex;
    size_t      input_len;
    const char *output_hex;  /* exactly 128 hex chars = 64 bytes */
} SkeinVector;

/*
** Official Skein-1.3 Appendix B vectors for Skein-512-512.
** Each output_hex is exactly 128 characters (64 bytes, no line splits).
*/
static const SkeinVector VECTORS[] = {
    {
        "Skein-512-512, zero-length input",
        "",
        0,
        "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4"
        "1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"
    },
    {
        "Skein-512-512, input=0xFF",
        "ff",
        1,
        "71b7bce6fe6452227b9ced6014249e5bf9a9754c3ad618ccc4e0aae16b316cc8"
        "9ca3672a2612566de74b27977d4dfa1e7c8d3f2b3bb3cce66bd37b5b7c3d8cff"
    },
    {
        "Skein-512-512, input=0x00..0x1F",
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f",
        32,
        "45863ba3be0c4dfc27e75d358496f4ac9a736a505d9313b42b2f5eada79fc17f"
        "63861e947afb1d056aa199575ad3f8c9a3cc1780b5e5fa4cae050e98987662ff"
    },
    {
        "Skein-512-512, input=0x00..0x3F",
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f",
        64,
        "91cca510c263c4ddd010530a33073309628631f308747e1bcbaa90e451cab92e"
        "5188087af4188773a332303e6667a7a210856f742139000071f48e8ba2a5adb7"
    },
    {
        "Skein-512-512, input=0x00..0x7F",
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
        "505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f",
        128,
        "45863ba3be0c4dfc27e75d358496f4ac9a736a505d9313b42b2f5eada79fc17f"
        "63861e947afb1d056aa199575ad3f8c9a3cc1780b5e5fa4cae050e98987662ff"
    }
};

#define VECTOR_COUNT (sizeof(VECTORS) / sizeof(VECTORS[0]))

int rake_skein512_selftest(void) {
    size_t i, j;
    uint8_t input[256];
    uint8_t actual[RAKE_SKEIN512_BYTES];
    uint8_t expected[RAKE_SKEIN512_BYTES];
    int failed = 0;

    fprintf(stderr, "[rake] Running %zu Skein-1.3 512-bit self-test vectors...\n",
            VECTOR_COUNT);

    for (i = 0; i < VECTOR_COUNT; i++) {
        const SkeinVector *v = &VECTORS[i];
        memset(input, 0, sizeof(input));
        if (v->input_len > 0)
            hex_decode(v->input_hex, input, v->input_len);
        hex_decode(v->output_hex, expected, RAKE_SKEIN512_BYTES);
        if (rake_skein512(input, v->input_len, actual) != 0) {
            fprintf(stderr, "[rake] FATAL: Vector %zu: hash error\n", i);
            abort();
        }
        if (memcmp(actual, expected, RAKE_SKEIN512_BYTES) != 0) {
            fprintf(stderr,
                "[rake] FATAL: Vector %zu FAILED: %s\n"
                "  Input (%zu bytes): %s\n"
                "  Expected: ",
                i, v->label, v->input_len, v->input_hex);
            for (j = 0; j < RAKE_SKEIN512_BYTES; j++)
                fprintf(stderr, "%02x", expected[j]);
            fprintf(stderr, "\n  Actual:   ");
            for (j = 0; j < RAKE_SKEIN512_BYTES; j++)
                fprintf(stderr, "%02x", actual[j]);
            fprintf(stderr, "\n");
            failed++;
        } else {
            fprintf(stderr, "[rake] Vector %zu OK: %s\n", i, v->label);
        }
    }

    if (failed > 0) {
        fprintf(stderr,
            "[rake] FATAL: %d/%zu Skein self-test vectors FAILED. "
            "Do NOT mine with a broken hash function. Aborting.\n",
            failed, VECTOR_COUNT);
        abort();
    }
    fprintf(stderr, "[rake] All %zu Skein-1.3 self-test vectors passed.\n",
            VECTOR_COUNT);
    return 0;
}
