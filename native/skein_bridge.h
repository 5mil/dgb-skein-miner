/*
** Rake :: skein_bridge.h
** Static bridge ABI between Unison FFI and the Skein-1.3 reference impl.
**
** Design principles:
**   - Statically linked — no dlopen, no version mismatch at runtime
**   - Version assertion at startup — wrong compiled version = hard abort
**   - Single-block and batch entrypoints — ABI stable through Phase 5 SIMD
**   - Self-test baked in — all official Skein-1.3 512-bit vectors checked
**     before any mining begins; hard abort with diagnostics on any failure
*/
#ifndef SKEIN_BRIDGE_H
#define SKEIN_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

/* Version of this bridge. Increment on any ABI change. */
#define RAKE_BRIDGE_VERSION  1

/* Skein output size in bytes for Skein-512 */
#define RAKE_SKEIN512_BYTES  64

#ifdef __cplusplus
extern "C" {
#endif

/*
** rake_skein_version_assert()
** Called once at binary startup. Aborts with diagnostics if bridge version
** does not match the compiled constant. Never returns on failure.
*/
void rake_skein_version_assert(void);

/*
** rake_skein512(in, in_len, out)
** Hash `in_len` bytes from `in` into the 64-byte buffer `out`.
** `out` must point to at least RAKE_SKEIN512_BYTES bytes.
** Returns 0 on success, non-zero on internal error (should never happen
** with valid inputs — treat non-zero as a hard fault).
*/
int rake_skein512(const uint8_t *in, size_t in_len, uint8_t *out);

/*
** rake_skein512_batch(inputs, in_lens, outputs, count)
** Hash `count` independent inputs. Each outputs[i] must point to at
** least RAKE_SKEIN512_BYTES bytes. Designed for nonce scan batching;
** later phases may replace the loop body with SIMD without changing
** this signature.
** Returns 0 if all succeeded, number of failures otherwise.
*/
int rake_skein512_batch(const uint8_t **inputs, const size_t *in_lens,
                        uint8_t **outputs, size_t count);

/*
** rake_skein512_selftest()
** Run all official Skein-1.3 512-bit test vectors.
** On any mismatch: prints vector index, input, expected, and actual
** output to stderr, then aborts. Never returns on failure.
** Returns 0 if all vectors pass.
*/
int rake_skein512_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* SKEIN_BRIDGE_H */
