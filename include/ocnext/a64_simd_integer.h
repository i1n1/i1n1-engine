#ifndef OCNEXT_A64_SIMD_INTEGER_H
#define OCNEXT_A64_SIMD_INTEGER_H
#include "ocnext/a64.h"
#ifdef __cplusplus
extern "C" {
#endif
#define OCNEXT_A64_SIMD_INTEGER_ABI_VERSION 2u
enum ocnext_a64_simd_integer_operation {
    OCNEXT_A64_SIMD_INTEGER_AND=1,OCNEXT_A64_SIMD_INTEGER_BIC=2,
    OCNEXT_A64_SIMD_INTEGER_ORR=3,OCNEXT_A64_SIMD_INTEGER_ORN=4,
    OCNEXT_A64_SIMD_INTEGER_EOR=5,OCNEXT_A64_SIMD_INTEGER_MOVI=6,
    OCNEXT_A64_SIMD_INTEGER_ADD=7,OCNEXT_A64_SIMD_INTEGER_SUB=8,
    OCNEXT_A64_SIMD_INTEGER_BSL=9,OCNEXT_A64_SIMD_INTEGER_BIT=10,
    OCNEXT_A64_SIMD_INTEGER_BIF=11
};
enum ocnext_a64_simd_integer_result {
    OCNEXT_A64_SIMD_INTEGER_OK=0,OCNEXT_A64_SIMD_INTEGER_ARGUMENT=1,
    OCNEXT_A64_SIMD_INTEGER_UNSUPPORTED=2,OCNEXT_A64_SIMD_INTEGER_NOT_ALLOCATED=3
};
struct ocnext_a64_simd_integer_request {
#ifdef __cplusplus
    alignas(16) uint32_t opcode;
#else
    _Alignas(16) uint32_t opcode;
#endif
    uint32_t reserved[3];
};
struct ocnext_a64_simd_integer_effect {
#ifdef __cplusplus
    alignas(16) uint8_t bytes[16];
#else
    _Alignas(16) uint8_t bytes[16];
#endif
    uint16_t known_bytes;
    uint8_t destination,reserved;
    uint32_t opcode,reserved_words[2];
};
/* Bank ABI1/592B is defined by a64.h, not duplicated here. Natural16 native
 * alignment, stable serialized lifetime, pairwise disjoint bank/request/out
 * and uintptr bounds are required before dereference. Unknown storage must0.
 * No FPEN/EL authorization, feature issuer, CPU/PC/flags, memory or OS effect.
 * Root must check access BEFORE source knowledge and commit only after OK. */
int ocnext_a64_simd_integer_valid(const struct ocnext_a64_vector_registers *);
int ocnext_a64_simd_integer_reset(struct ocnext_a64_vector_registers *);
/* Positive operation only for the whitelist; zero means outside that subset,
 * not a claim that every nonwhitelisted architectural encoding is invalid. */
unsigned ocnext_a64_simd_integer_decode(uint32_t opcode);
/* On OK every written active byte was independently derivable. Q0 writes
 * upper64 known0, so this whole-register subset publishes known_bytes=ffff.
 * ABI2 adds BSL/BIT/BIF using old Vd as an input. Request/effect bytes,
 * alignment and earlier operation values stay fixed. Select mask/data aliases
 * refer to the same architectural input, never coincident UNKNOWN storage.
 * Symbolic same-register EOR/BIC/ORN and known-byte annihilators are exact;
 * distinct unknown bytes never become equal because both stored values0.
 * Remaining unknown active byte/lane => UNSUPPORTED/out unchanged. Partial
 * UNKNOWN results are never published/retired. Reserved primary-proven forms
 * return NOT_ALLOCATED; valid excluded families return UNSUPPORTED. */
enum ocnext_a64_simd_integer_result ocnext_a64_simd_integer_prepare(
    const struct ocnext_a64_vector_registers *,const struct ocnext_a64_simd_integer_request *,
    struct ocnext_a64_simd_integer_effect *);
#if defined(__STDC_VERSION__) && __STDC_VERSION__>=201112L
_Static_assert(sizeof(struct ocnext_a64_simd_integer_request)==16,"SIMD request ABI2");
_Static_assert(sizeof(struct ocnext_a64_simd_integer_effect)==32,"SIMD effect ABI2");
_Static_assert(_Alignof(struct ocnext_a64_simd_integer_request)==16,"SIMD request align16");
_Static_assert(_Alignof(struct ocnext_a64_simd_integer_effect)==16,"SIMD effect align16");
_Static_assert(offsetof(struct ocnext_a64_simd_integer_effect,known_bytes)==16,"SIMD known mask offset");
_Static_assert(offsetof(struct ocnext_a64_simd_integer_effect,opcode)==20,"SIMD opcode offset");
#endif
#ifdef __cplusplus
}
#endif
#endif
