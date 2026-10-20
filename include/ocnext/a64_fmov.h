#ifndef OCNEXT_A64_FMOV_H
#define OCNEXT_A64_FMOV_H
#include "ocnext/a64_fp_control.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Product ABI2 is distinct from the unintegrated Phase13 private ABI1.
 * Raw bits only: no conversion, FP arithmetic, NaN canonicalization, SVE,
 * FEAT_FP16/feature identity or native-host FP state access. */
#define OCNEXT_A64_FMOV_ABI_VERSION 2u
enum ocnext_a64_fmov_form {
    OCNEXT_A64_FMOV_W_FROM_S=1, OCNEXT_A64_FMOV_S_FROM_W=2,
    OCNEXT_A64_FMOV_X_FROM_D=3, OCNEXT_A64_FMOV_D_FROM_X=4,
    OCNEXT_A64_FMOV_X_FROM_HIGH_D=5, OCNEXT_A64_FMOV_HIGH_D_FROM_X=6
};
enum ocnext_a64_fmov_action {
    OCNEXT_A64_FMOV_RETIRE=1, OCNEXT_A64_FMOV_EXCEPTION=2
};
enum ocnext_a64_fmov_result {
    OCNEXT_A64_FMOV_OK=0, OCNEXT_A64_FMOV_ARGUMENT=1,
    OCNEXT_A64_FMOV_UNSUPPORTED=2, OCNEXT_A64_FMOV_NOT_ALLOCATED=3
};
/* Native ABI2/16B, align8. Even forms use the old Xn (Rn31 is ZR,
 * never SP; W reads low32). Odd forms require gpr_value=0. */
struct ocnext_a64_fmov_request {
    uint64_t gpr_value;
    uint32_t opcode;
    uint8_t current_el, profile, reserved[2];
};
/* Native ABI2/40B, align8. Whole Vd image plus exact byte knowledge:
 * HIGH_D_FROM_X preserves low64 and its knowledge, writes high64 known.
 * Unknown byte storage is always0. Other vector writes zero upper bytes
 * with known bits set. GPR writes are zero-extended; Rd31 is discarded.
 * EXCEPTION publishes only action/esr; every other field is0.
 * A permitted transfer to GPR Rd31 publishes a discard-only RETIRE without
 * reading/inventing an UNKNOWN source value. FPEN still resolves first.
 * No CPU/PC/memory state changes. Reserved output bytes always0. */
struct ocnext_a64_fmov_effect {
    uint8_t vector_after[16];
    uint64_t gpr_value;
    uint32_t action, esr;
    uint16_t known_after;
    uint8_t gpr_write, vector_write, rd, vd, reserved[2];
};
/* Positive only for six exact allocated forms;0 means outside the whitelist,
 * not an architectural allocation verdict. All half-precision/scalar/vector
 * FMOV variants and conversions remain separate unsupported dependencies. */
unsigned ocnext_a64_fmov_decode(uint32_t opcode);
/* Stable serialized native lifetime; bank align16, other objects align8;
 * all four spans pairwise disjoint and uintptr-safe before dereference.
 * Non-OK leaves out unchanged. Validate arguments, classify allocation,
 * resolve explicit FPEN access, then source knowledge. NOT_ALLOCATED is
 * permitted only for a specifically primary-proven reserved encoding;
 * excluded valid or unresolved encodings return UNSUPPORTED. */
enum ocnext_a64_fmov_result ocnext_a64_fmov_prepare(
    const struct ocnext_a64_vector_registers *,
    const struct ocnext_a64_fp_registers *,
    const struct ocnext_a64_fmov_request *,
    struct ocnext_a64_fmov_effect *);
#if defined(__STDC_VERSION__) && __STDC_VERSION__>=201112L
_Static_assert(sizeof(struct ocnext_a64_fmov_request)==16,"FMOV request ABI2");
_Static_assert(sizeof(struct ocnext_a64_fmov_effect)==40,"FMOV effect ABI2");
_Static_assert(_Alignof(struct ocnext_a64_fmov_request)==8,"FMOV request align8");
_Static_assert(_Alignof(struct ocnext_a64_fmov_effect)==8,"FMOV effect align8");
_Static_assert(offsetof(struct ocnext_a64_fmov_effect,gpr_value)==16,"FMOV GPR offset");
_Static_assert(offsetof(struct ocnext_a64_fmov_effect,known_after)==32,"FMOV knowledge offset");
#endif
#ifdef __cplusplus
}
#endif
#endif
