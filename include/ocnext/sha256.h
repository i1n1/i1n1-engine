#ifndef OCNEXT_SHA256_H
#define OCNEXT_SHA256_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define OCNEXT_SHA256_ABI_VERSION 1u
#define OCNEXT_SHA256_BYTES 32u
/* Caller-owned incremental SHA-256, no allocation/libc. This hashes bytes;
 * authenticity requires an independently trusted expected digest. */
struct ocnext_sha256 {
    uint32_t h[8];
    uint64_t total_bytes;
    uint8_t block[64];
    uint32_t used;
    uint8_t finalized, reserved[3];
};
int ocnext_sha256_init(struct ocnext_sha256 *);
/* NULL input permitted only for length0. Input must not alias ctx. Invalid
 * state/overflow returns -1 before changing ctx. Maximum length is 2^61-1. */
int ocnext_sha256_update(struct ocnext_sha256 *, const uint8_t *, size_t);
/* Exactly one finalization. Output must not alias ctx. Errors change neither.
 * Context contains public hash state and is not a secret-storage primitive. */
int ocnext_sha256_final(struct ocnext_sha256 *, uint8_t out[32]);
/* Whole-buffer output may alias input; output is committed after all reads. */
int ocnext_sha256_digest(const uint8_t *, size_t, uint8_t out[32]);
#ifdef __cplusplus
}
#endif
#endif
