#ifndef OCNEXT_A64_FP_CONTROL_H
#define OCNEXT_A64_FP_CONTROL_H
#include "ocnext/a64.h"
#ifdef __cplusplus
extern "C" {
#endif
#define OCNEXT_A64_FP_CONTROL_ABI_VERSION 1u
#define OCNEXT_A64_FP_ACCESS_ABI_VERSION 1u
#define OCNEXT_A64_FP_CPACR_MASK UINT64_C(0x00300000)
#define OCNEXT_A64_FP_FPCR_MASK UINT64_C(0x07c00000)
#define OCNEXT_A64_FP_FPSR_MASK UINT64_C(0x0800009f)
/* FPEN_NOTRAP = FPEN_ONLY on an implementation without trapped FP exceptions: the FPCR
 * exception-trap enable bits (IDE,IXE,UFE,OFE,DZE,IOE) are RAZ/WI, so a write that sets
 * them is accepted and the bits stay 0 (the way software probes for that capability). */
#define OCNEXT_A64_FPCR_TRAP_ENABLE_MASK UINT64_C(0x00009f00)
enum ocnext_a64_fp_control_profile { OCNEXT_A64_FP_CONTROL_NONE=0, OCNEXT_A64_FP_CONTROL_FPEN_ONLY=1,
    OCNEXT_A64_FP_CONTROL_FPEN_NOTRAP=2 };
enum ocnext_a64_fp_control_register { OCNEXT_A64_FP_CONTROL_CPACR=1, OCNEXT_A64_FP_CONTROL_FPCR=2, OCNEXT_A64_FP_CONTROL_FPSR=3 };
enum ocnext_a64_fp_control_action { OCNEXT_A64_FP_CONTROL_READ=1, OCNEXT_A64_FP_CONTROL_WRITE=2, OCNEXT_A64_FP_CONTROL_EXCEPTION=3 };
enum ocnext_a64_fp_control_result { OCNEXT_A64_FP_CONTROL_OK=0, OCNEXT_A64_FP_CONTROL_ARGUMENT=1, OCNEXT_A64_FP_CONTROL_UNSUPPORTED=2, OCNEXT_A64_FP_CONTROL_NOT_ALLOCATED=3 };
enum ocnext_a64_fp_access_action { OCNEXT_A64_FP_ACCESS_ALLOWED=1, OCNEXT_A64_FP_ACCESS_EXCEPTION=2 };
/* Separate native access ABI1: request16/effect16, natural alignment8.
 * The selected allocated instruction must already be in the caller's coverage.
 * This checks FPEN only, before vector operand or memory knowledge. Unknown
 * FPCR/FPSR does not prevent an integer SIMD access check. No CPU/ISA feature,
 * arithmetic, Apple initial state, or exception-entry authority is issued. */
struct ocnext_a64_fp_access_request { uint32_t current_el,profile; uint64_t reserved; };
struct ocnext_a64_fp_access_effect { uint32_t action,esr; uint64_t reserved; };
/* Native ABI1/16B; root selects FPEN_ONLY only in its explicit SYNC CPU
 * coverage. current_el0/1, source operand is old Rt (Rt31 means ZR), not SP.
 * No caller setting establishes arithmetic/vector/ID/Apple capability. */
struct ocnext_a64_fp_control_request {
    uint64_t operand;
    uint32_t opcode;
    uint8_t current_el,profile,reserved[2];
};
/* Native ABI1/56B. Whole staged after-bank, READ value, or a precise EC/IL/ISS
 * EXCEPTION candidate. No CPU/PC/NZCV/SP/retirement/memory/vector commit is
 * performed here; root must preflight prospective entry before publication. */
struct ocnext_a64_fp_control_effect {
    struct ocnext_a64_fp_registers bank_after;
    uint64_t value;
    uint32_t esr,action,rt,reserved;
};
/* Valid aligned stable native objects, serialized caller. Unknown fields
 * must be stored0. A nonzero unsupported/reserved input is coverage rejection,
 * not a claim that architectural RES0 writes necessarily fault. Arithmetic,
 * exception-enable FPCR fields, FZ16/AFP/SVE/SME/EL2/EL3 remain unsupported. */
int ocnext_a64_fp_control_valid(const struct ocnext_a64_fp_registers *);
int ocnext_a64_fp_control_reset(struct ocnext_a64_fp_registers *);
unsigned ocnext_a64_fp_control_decode(uint32_t opcode);
/* All three natural-alignment8 spans must be pairwise disjoint and uintptr
 * overflow-free before dereference. API/model failure preserves output/input.
 * OK may describe a staged exception, not successful instruction retirement.
 * CPACR EL0 UNDEFINED precedes profile/knowledge; FPCR/FPSR known-CPACR access
 * denial precedes unknown destination knowledge and operand-mask validation. */
enum ocnext_a64_fp_control_result ocnext_a64_fp_control_prepare(
    const struct ocnext_a64_fp_registers *,const struct ocnext_a64_fp_control_request *,
    struct ocnext_a64_fp_control_effect *);
/* Stable serialized, pairwise disjoint, aligned8 overflow-free objects.
 * Non-OK preserves all objects. EXCEPTION is a candidate only; the CPU must
 * validate the prospective EL1 entry before committing the exception. */
enum ocnext_a64_fp_control_result ocnext_a64_fp_access_prepare(
    const struct ocnext_a64_fp_registers *,const struct ocnext_a64_fp_access_request *,
    struct ocnext_a64_fp_access_effect *);
#if defined(__STDC_VERSION__) && __STDC_VERSION__>=201112L
_Static_assert(sizeof(struct ocnext_a64_fp_registers)==32,"FP bank ABI1");
_Static_assert(sizeof(struct ocnext_a64_fp_control_request)==16,"FP request ABI1");
_Static_assert(sizeof(struct ocnext_a64_fp_control_effect)==56,"FP effect ABI1");
_Static_assert(offsetof(struct ocnext_a64_fp_control_effect,value)==32,"FP effect value offset");
_Static_assert(sizeof(struct ocnext_a64_fp_access_request)==16,"FP access request ABI1");
_Static_assert(sizeof(struct ocnext_a64_fp_access_effect)==16,"FP access effect ABI1");
#endif
#ifdef __cplusplus
}
#endif
#endif
