#ifndef OCNEXT_A64_DIVBIT_H
#define OCNEXT_A64_DIVBIT_H
#include <stdint.h>
#include <stddef.h>
#define OCNEXT_A64_DIVBIT_ABI 1u
#define OCNEXT_A64_DIVBIT_KNOWN_RN 1u
#define OCNEXT_A64_DIVBIT_KNOWN_RM 2u
enum ocnext_a64_divbit_operation {
 OCNEXT_A64_DIVBIT_UDIV=1,OCNEXT_A64_DIVBIT_SDIV=2,
 OCNEXT_A64_DIVBIT_RBIT=3,OCNEXT_A64_DIVBIT_REV16=4,
 OCNEXT_A64_DIVBIT_REV32=5,OCNEXT_A64_DIVBIT_REV=6,
 OCNEXT_A64_DIVBIT_CLZ=7,OCNEXT_A64_DIVBIT_CLS=8
};
enum ocnext_a64_divbit_result {
 OCNEXT_A64_DIVBIT_OK=0,OCNEXT_A64_DIVBIT_ARGUMENT=1,
 OCNEXT_A64_DIVBIT_UNSUPPORTED=2
};
/* Host-private native ABI1. Full32B spans, align8, allocated stable serialized
 * caller lifetime, pairwise disjoint; numeric bounds checked before typed read.
 * Unknown stored operands may be any value, never an architectural zero.
 * Encoded source31 derives ZR regardless of request value/knowledge. No SP.
 * Unary RM is inactive/ignored. Div requires both active non-ZR sources known.
 * Same encoded active source, both known: effective Wlow32/X64 snapshots agree.
 * Partial-known alias remains conservative UNSUPPORTED, not copied knowledge.
 * Even Rd31 discard requires active source knowledge; effect result0 inactive.
 * No CPU, flags, PC, memory/provider, feature identity or Apple state effect. */
struct ocnext_a64_divbit_request {
 uint32_t abi_version,opcode;
 uint64_t rn_value,rm_value;
 uint8_t operand_known,reserved[7];
};
struct ocnext_a64_divbit_effect {
 uint64_t result;
 uint32_t destination,abi_version;
 uint8_t width,write_gpr,reserved[14];
};
/* Positive operation for the exact15 allocated variants, otherwise0. It is a
 * coverage result, never a general architectural UNDEFINED classifier. */
unsigned ocnext_a64_divbit_decode(uint32_t opcode);
/* ARGUMENT/UNSUPPORTED preserve input+entire output bytes. No fallible work
 * after single infallible logical publication. This does not sandbox freed
 * memory/hostile caller mutations; no callbacks or OS access occur here. */
enum ocnext_a64_divbit_result ocnext_a64_divbit_prepare(
 const struct ocnext_a64_divbit_request *,struct ocnext_a64_divbit_effect *);
#if defined(__STDC_VERSION__) && __STDC_VERSION__>=201112L
_Static_assert(sizeof(struct ocnext_a64_divbit_request)==32,"request32");
_Static_assert(sizeof(struct ocnext_a64_divbit_effect)==32,"effect32");
_Static_assert(_Alignof(struct ocnext_a64_divbit_request)==8,"request align8");
_Static_assert(_Alignof(struct ocnext_a64_divbit_effect)==8,"effect align8");
_Static_assert(offsetof(struct ocnext_a64_divbit_request,rn_value)==8,"RN offset8");
_Static_assert(offsetof(struct ocnext_a64_divbit_request,rm_value)==16,"RM offset16");
_Static_assert(offsetof(struct ocnext_a64_divbit_request,operand_known)==24,"knowledge offset24");
_Static_assert(offsetof(struct ocnext_a64_divbit_effect,destination)==8,"destination offset8");
_Static_assert(offsetof(struct ocnext_a64_divbit_effect,abi_version)==12,"ABI offset12");
_Static_assert(offsetof(struct ocnext_a64_divbit_effect,width)==16,"width offset16");
_Static_assert(offsetof(struct ocnext_a64_divbit_effect,reserved)==18,"reserved offset18");
#endif
#endif
