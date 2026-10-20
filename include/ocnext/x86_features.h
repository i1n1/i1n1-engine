#ifndef OCNEXT_X86_FEATURES_H
#define OCNEXT_X86_FEATURES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OCNEXT_X86_SNAPSHOT_VERSION 1u

enum ocnext_x86_result {
    OCNEXT_X86_OK = 0,
    OCNEXT_X86_UNAVAILABLE = 1,
    OCNEXT_X86_INCONSISTENT = 2,
    OCNEXT_X86_INCOMPLETE = 3,
    OCNEXT_X86_ARGUMENT = -1
};

enum ocnext_x86_sse_os_state {
    OCNEXT_X86_SSE_OS_UNKNOWN = 0,
    OCNEXT_X86_SSE_OS_DISABLED = 1,
    OCNEXT_X86_SSE_OS_ENABLED = 2
};

enum ocnext_x86_origin {
    OCNEXT_X86_ORIGIN_UNAVAILABLE = 0,
    OCNEXT_X86_ORIGIN_INJECTED = 1,
    OCNEXT_X86_ORIGIN_HOSTED_X86_64 = 2,
    OCNEXT_X86_ORIGIN_ROSETTA = 3,
    OCNEXT_X86_ORIGIN_FREESTANDING_X86_64 = 4
};

enum ocnext_x86_valid {
    OCNEXT_X86_VALID_LEAF0 = 1u << 0,
    OCNEXT_X86_VALID_LEAF1 = 1u << 1,
    OCNEXT_X86_VALID_LEAF7_0 = 1u << 2,
    OCNEXT_X86_VALID_LEAFD_0 = 1u << 3,
    OCNEXT_X86_VALID_XCR0 = 1u << 4,
    OCNEXT_X86_VALID_ALL = 31u
};

enum ocnext_x86_capability {
    OCNEXT_X86_CAP_FXSR = 1u << 0,
    OCNEXT_X86_CAP_SSE = 1u << 1,
    OCNEXT_X86_CAP_SSE2 = 1u << 2,
    OCNEXT_X86_CAP_SSE3 = 1u << 3,
    OCNEXT_X86_CAP_SSSE3 = 1u << 4,
    OCNEXT_X86_CAP_SSE41 = 1u << 5,
    OCNEXT_X86_CAP_SSE42 = 1u << 6,
    OCNEXT_X86_CAP_XSAVE = 1u << 7,
    OCNEXT_X86_CAP_AVX = 1u << 8,
    OCNEXT_X86_CAP_AVX2 = 1u << 9,
    OCNEXT_X86_CAP_FMA = 1u << 10,
    OCNEXT_X86_CAP_F16C = 1u << 11,
    OCNEXT_X86_CAP_BMI1 = 1u << 12,
    OCNEXT_X86_CAP_BMI2 = 1u << 13,
    OCNEXT_X86_CAP_POPCNT = 1u << 14
};

enum ocnext_x86_reason {
    OCNEXT_X86_REASON_LEAF1_MISSING = 1u << 0,
    OCNEXT_X86_REASON_LEAF7_MISSING = 1u << 1,
    OCNEXT_X86_REASON_OSXSAVE_WITHOUT_XSAVE = 1u << 2,
    OCNEXT_X86_REASON_XCR0_ILLEGAL = 1u << 3,
    OCNEXT_X86_REASON_XCR0_MISSING = 1u << 4,
    OCNEXT_X86_REASON_XCR0_X87_MISSING = 1u << 5,
    OCNEXT_X86_REASON_YMM_WITHOUT_XMM = 1u << 6,
    OCNEXT_X86_REASON_XCR0_UNSUPPORTED = 1u << 7,
    OCNEXT_X86_REASON_AVX2_WITHOUT_AVX = 1u << 8,
    OCNEXT_X86_REASON_XSTATE_BASE_INVALID = 1u << 9,
    OCNEXT_X86_REASON_XSAVE_LEAF_RANGE = 1u << 10,
    OCNEXT_X86_REASON_XSTATE_MASK_MISSING = 1u << 11,
    OCNEXT_X86_REASON_SSE_OS_UNKNOWN = 1u << 12,
    OCNEXT_X86_REASON_SSE_OS_DISABLED = 1u << 13,
    OCNEXT_X86_REASON_SSE2_WITHOUT_SSE = 1u << 14,
    OCNEXT_X86_REASON_AVX_WITHOUT_XSAVE = 1u << 15,
    OCNEXT_X86_REASON_AVX_STATE_DISABLED = 1u << 16,
    OCNEXT_X86_REASON_OSXSAVE_DISABLED = 1u << 17,
    OCNEXT_X86_REASON_LEAF_OUT_OF_RANGE = 1u << 18,
    OCNEXT_X86_REASON_AVX_STATE_UNSUPPORTED = 1u << 19,
    OCNEXT_X86_REASON_XSTATE_DEPENDENCY = 1u << 20,
    OCNEXT_X86_REASON_FMA_F16C_WITHOUT_AVX = 1u << 21,
    OCNEXT_X86_REASON_SSE_SUBSET_WITHOUT_SSE = 1u << 22
};

struct ocnext_x86_cpuid {
    uint32_t eax, ebx, ecx, edx;
};

/* Native C ABI, not a serialized bridge payload. All validity flags are explicit.
 * A substrate must supply real OS state evidence; CPUID alone cannot prove SSE
 * context ownership. origin describes observation, not hardware attestation. */
struct ocnext_x86_snapshot {
    uint32_t version, valid;
    enum ocnext_x86_sse_os_state legacy_sse_os;
    enum ocnext_x86_origin origin;
    struct ocnext_x86_cpuid leaf0, leaf1, leaf7_0, leafd_0;
    uint64_t xcr0;
};

struct ocnext_x86_features {
    char vendor[13];
    uint32_t max_basic_leaf, signature, family, model, stepping, processor_type;
    uint32_t cpu_capabilities, usable_capabilities, reasons, inconsistent_reasons;
    uint64_t supported_xstate, enabled_xstate;
    enum ocnext_x86_sse_os_state legacy_sse_os;
    enum ocnext_x86_origin origin;
    uint8_t cpuid_available, vendor_is_intel, vendor_is_amd, hypervisor_present;
    uint8_t cpuid_osxsave, xgetbv_permitted, xcr0_observed, supported_xstate_observed;
};

/* Providers return 0 on success. A collector invokes XGETBV(index=0) only after
 * successful CPUID.1 reports BOTH XSAVE and OSXSAVE. Provider faults/traps are
 * the provider's responsibility; no signal/exception recovery is installed. */
struct ocnext_x86_provider {
    void *context;
    int (*cpuid)(void *, uint32_t leaf, uint32_t subleaf, struct ocnext_x86_cpuid *);
    int (*xgetbv)(void *, uint32_t index, uint64_t *);
    enum ocnext_x86_origin origin;
};

int ocnext_x86_evaluate(const struct ocnext_x86_snapshot *, struct ocnext_x86_features *);
int ocnext_x86_collect(const struct ocnext_x86_provider *,
                      enum ocnext_x86_sse_os_state, struct ocnext_x86_snapshot *);
/* Hosted x86_64 assumes the OS's x86_64 ABI preserves legacy XMM state. In
 * OCNEXT_X86_FREESTANDING builds native probe leaves that evidence UNKNOWN.
 * ARM builds return UNAVAILABLE without running or inventing x86 instructions. */
int ocnext_x86_native_probe(struct ocnext_x86_snapshot *, struct ocnext_x86_features *);

#ifdef __cplusplus
}
#endif
#endif
