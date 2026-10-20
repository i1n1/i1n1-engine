#include "ocnext/x86_features.h"

#if defined(__APPLE__) && defined(__x86_64__) && !defined(OCNEXT_X86_FREESTANDING)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif
#if defined(_MSC_VER) && defined(_M_X64)
#include <intrin.h>
#endif

static void zero_bytes(void *pointer, unsigned long size)
{
    unsigned char *bytes = pointer;
    while (size--) *bytes++ = 0;
}

static int valid_os(enum ocnext_x86_sse_os_state state)
{
    return state >= OCNEXT_X86_SSE_OS_UNKNOWN && state <= OCNEXT_X86_SSE_OS_ENABLED;
}

static int valid_origin(enum ocnext_x86_origin origin)
{
    return origin >= OCNEXT_X86_ORIGIN_UNAVAILABLE && origin <= OCNEXT_X86_ORIGIN_FREESTANDING_X86_64;
}

static int vendor_equals(const char *value, const char *expected)
{
    unsigned i;
    for (i = 0; i < 12; ++i) if (value[i] != expected[i]) return 0;
    return 1;
}

static void vendor_word(char *out, uint32_t value)
{
    unsigned i;
    for (i = 0; i < 4; ++i) out[i] = (char)((value >> (8 * i)) & 255u);
}

static void add_feature(struct ocnext_x86_features *features, uint32_t register_value,
                        unsigned bit, uint32_t capability)
{
    if (register_value & (UINT32_C(1) << bit)) features->cpu_capabilities |= capability;
}

int ocnext_x86_evaluate(const struct ocnext_x86_snapshot *snapshot,
                       struct ocnext_x86_features *features)
{
    uint32_t cpu, sse_mask, hard = 0;
    int incomplete = 0;
    unsigned base_family, base_model;
    if (!features) return OCNEXT_X86_ARGUMENT;
    zero_bytes(features, sizeof(*features));
    if (!snapshot || snapshot->version != OCNEXT_X86_SNAPSHOT_VERSION ||
        (snapshot->valid & ~(uint32_t)OCNEXT_X86_VALID_ALL) ||
        !valid_os(snapshot->legacy_sse_os) || !valid_origin(snapshot->origin)) return OCNEXT_X86_ARGUMENT;
    features->legacy_sse_os = snapshot->legacy_sse_os;
    features->origin = snapshot->origin;
    if (!(snapshot->valid & OCNEXT_X86_VALID_LEAF0)) {
        if (snapshot->valid) return OCNEXT_X86_ARGUMENT;
        return OCNEXT_X86_UNAVAILABLE;
    }
    features->cpuid_available = 1;
    features->max_basic_leaf = snapshot->leaf0.eax;
    vendor_word(features->vendor, snapshot->leaf0.ebx);
    vendor_word(features->vendor + 4, snapshot->leaf0.edx);
    vendor_word(features->vendor + 8, snapshot->leaf0.ecx);
    features->vendor_is_intel = (uint8_t)vendor_equals(features->vendor, "GenuineIntel");
    features->vendor_is_amd = (uint8_t)vendor_equals(features->vendor, "AuthenticAMD");
    if (((snapshot->valid & OCNEXT_X86_VALID_LEAF1) && snapshot->leaf0.eax < 1) ||
        ((snapshot->valid & OCNEXT_X86_VALID_LEAF7_0) && snapshot->leaf0.eax < 7) ||
        ((snapshot->valid & OCNEXT_X86_VALID_LEAFD_0) && snapshot->leaf0.eax < 13)) {
        hard |= OCNEXT_X86_REASON_LEAF_OUT_OF_RANGE;
    }
    if (!(snapshot->valid & OCNEXT_X86_VALID_LEAF1)) {
        features->reasons = OCNEXT_X86_REASON_LEAF1_MISSING | hard;
        if (snapshot->valid & OCNEXT_X86_VALID_XCR0) hard |= OCNEXT_X86_REASON_XCR0_ILLEGAL;
        if (snapshot->valid & OCNEXT_X86_VALID_LEAFD_0) hard |= OCNEXT_X86_REASON_XSTATE_BASE_INVALID;
        features->reasons |= hard; features->inconsistent_reasons = hard;
        return hard ? OCNEXT_X86_INCONSISTENT : OCNEXT_X86_INCOMPLETE;
    }
    features->signature = snapshot->leaf1.eax;
    base_family = (snapshot->leaf1.eax >> 8) & 15u;
    base_model = (snapshot->leaf1.eax >> 4) & 15u;
    features->family = base_family == 15 ? base_family + ((snapshot->leaf1.eax >> 20) & 255u) : base_family;
    features->model = (base_family == 6 || base_family == 15) ?
                      base_model | (((snapshot->leaf1.eax >> 16) & 15u) << 4) : base_model;
    features->stepping = snapshot->leaf1.eax & 15u;
    features->processor_type = (snapshot->leaf1.eax >> 12) & 3u;
    features->hypervisor_present = (uint8_t)((snapshot->leaf1.ecx >> 31) & 1u);
    features->cpuid_osxsave = (uint8_t)((snapshot->leaf1.ecx >> 27) & 1u);
    add_feature(features, snapshot->leaf1.edx, 24, OCNEXT_X86_CAP_FXSR);
    add_feature(features, snapshot->leaf1.edx, 25, OCNEXT_X86_CAP_SSE);
    add_feature(features, snapshot->leaf1.edx, 26, OCNEXT_X86_CAP_SSE2);
    add_feature(features, snapshot->leaf1.ecx, 0, OCNEXT_X86_CAP_SSE3);
    add_feature(features, snapshot->leaf1.ecx, 9, OCNEXT_X86_CAP_SSSE3);
    add_feature(features, snapshot->leaf1.ecx, 19, OCNEXT_X86_CAP_SSE41);
    add_feature(features, snapshot->leaf1.ecx, 20, OCNEXT_X86_CAP_SSE42);
    add_feature(features, snapshot->leaf1.ecx, 26, OCNEXT_X86_CAP_XSAVE);
    add_feature(features, snapshot->leaf1.ecx, 28, OCNEXT_X86_CAP_AVX);
    add_feature(features, snapshot->leaf1.ecx, 12, OCNEXT_X86_CAP_FMA);
    add_feature(features, snapshot->leaf1.ecx, 29, OCNEXT_X86_CAP_F16C);
    add_feature(features, snapshot->leaf1.ecx, 23, OCNEXT_X86_CAP_POPCNT);
    if (snapshot->valid & OCNEXT_X86_VALID_LEAF7_0) {
        add_feature(features, snapshot->leaf7_0.ebx, 5, OCNEXT_X86_CAP_AVX2);
        add_feature(features, snapshot->leaf7_0.ebx, 3, OCNEXT_X86_CAP_BMI1);
        add_feature(features, snapshot->leaf7_0.ebx, 8, OCNEXT_X86_CAP_BMI2);
    } else if (snapshot->leaf0.eax >= 7) {
        features->reasons |= OCNEXT_X86_REASON_LEAF7_MISSING;
        incomplete = 1;
    }
    cpu = features->cpu_capabilities;
    features->xgetbv_permitted = (uint8_t)(!!(cpu & OCNEXT_X86_CAP_XSAVE) && features->cpuid_osxsave);
    if (features->cpuid_osxsave && !(cpu & OCNEXT_X86_CAP_XSAVE)) hard |= OCNEXT_X86_REASON_OSXSAVE_WITHOUT_XSAVE;
    if ((cpu & OCNEXT_X86_CAP_AVX2) && !(cpu & OCNEXT_X86_CAP_AVX)) hard |= OCNEXT_X86_REASON_AVX2_WITHOUT_AVX;
    if ((cpu & (OCNEXT_X86_CAP_FMA | OCNEXT_X86_CAP_F16C)) && !(cpu & OCNEXT_X86_CAP_AVX)) hard |= OCNEXT_X86_REASON_FMA_F16C_WITHOUT_AVX;
    if ((cpu & OCNEXT_X86_CAP_AVX) && !(cpu & OCNEXT_X86_CAP_XSAVE)) hard |= OCNEXT_X86_REASON_AVX_WITHOUT_XSAVE;
    if ((cpu & OCNEXT_X86_CAP_XSAVE) && snapshot->leaf0.eax < 13) hard |= OCNEXT_X86_REASON_XSAVE_LEAF_RANGE;
    if ((cpu & OCNEXT_X86_CAP_SSE2) && !(cpu & OCNEXT_X86_CAP_SSE)) hard |= OCNEXT_X86_REASON_SSE2_WITHOUT_SSE;
    sse_mask = OCNEXT_X86_CAP_SSE | OCNEXT_X86_CAP_SSE2 | OCNEXT_X86_CAP_SSE3 |
               OCNEXT_X86_CAP_SSSE3 | OCNEXT_X86_CAP_SSE41 | OCNEXT_X86_CAP_SSE42;
    if ((cpu & (sse_mask & ~(uint32_t)OCNEXT_X86_CAP_SSE)) && !(cpu & OCNEXT_X86_CAP_SSE)) hard |= OCNEXT_X86_REASON_SSE_SUBSET_WITHOUT_SSE;
    if (snapshot->valid & OCNEXT_X86_VALID_LEAFD_0) {
        features->supported_xstate_observed = 1;
        features->supported_xstate = ((uint64_t)snapshot->leafd_0.edx << 32) | snapshot->leafd_0.eax;
        if (!(cpu & OCNEXT_X86_CAP_XSAVE) || (features->supported_xstate & 3) != 3) hard |= OCNEXT_X86_REASON_XSTATE_BASE_INVALID;
        if ((cpu & OCNEXT_X86_CAP_AVX) && !(features->supported_xstate & 4)) hard |= OCNEXT_X86_REASON_AVX_STATE_UNSUPPORTED;
    } else if (cpu & OCNEXT_X86_CAP_XSAVE) {
        features->reasons |= OCNEXT_X86_REASON_XSTATE_MASK_MISSING; incomplete = 1;
    }
    if (snapshot->valid & OCNEXT_X86_VALID_XCR0) {
        features->xcr0_observed = 1; features->enabled_xstate = snapshot->xcr0;
        if (!features->xgetbv_permitted) hard |= OCNEXT_X86_REASON_XCR0_ILLEGAL;
        if (!(snapshot->xcr0 & 1)) hard |= OCNEXT_X86_REASON_XCR0_X87_MISSING;
        if ((snapshot->xcr0 & 4) && !(snapshot->xcr0 & 2)) hard |= OCNEXT_X86_REASON_YMM_WITHOUT_XMM;
        if (features->supported_xstate_observed && (snapshot->xcr0 & ~features->supported_xstate)) hard |= OCNEXT_X86_REASON_XCR0_UNSUPPORTED;
        if (((snapshot->xcr0 & 0x18) && (snapshot->xcr0 & 0x18) != 0x18) ||
            ((snapshot->xcr0 & 0xe0) && ((snapshot->xcr0 & 0xe0) != 0xe0 || (snapshot->xcr0 & 6) != 6)) ||
            ((snapshot->xcr0 & (UINT64_C(1) << 18)) && !(snapshot->xcr0 & (UINT64_C(1) << 17)))) hard |= OCNEXT_X86_REASON_XSTATE_DEPENDENCY;
    } else if (features->xgetbv_permitted) {
        features->reasons |= OCNEXT_X86_REASON_XCR0_MISSING; incomplete = 1;
    }
    if (snapshot->legacy_sse_os == OCNEXT_X86_SSE_OS_UNKNOWN) features->reasons |= OCNEXT_X86_REASON_SSE_OS_UNKNOWN;
    else if (snapshot->legacy_sse_os == OCNEXT_X86_SSE_OS_DISABLED) features->reasons |= OCNEXT_X86_REASON_SSE_OS_DISABLED;
    if ((cpu & OCNEXT_X86_CAP_AVX) && !features->cpuid_osxsave) features->reasons |= OCNEXT_X86_REASON_OSXSAVE_DISABLED;
    if ((cpu & OCNEXT_X86_CAP_AVX) && (!features->xcr0_observed || (features->enabled_xstate & 6) != 6)) features->reasons |= OCNEXT_X86_REASON_AVX_STATE_DISABLED;
    features->inconsistent_reasons = hard; features->reasons |= hard;
    if (hard) return OCNEXT_X86_INCONSISTENT; /* Raw facts preserved, every usable bit remains zero. */
    features->usable_capabilities = cpu & (OCNEXT_X86_CAP_BMI1 | OCNEXT_X86_CAP_BMI2 | OCNEXT_X86_CAP_POPCNT);
    if (snapshot->legacy_sse_os == OCNEXT_X86_SSE_OS_ENABLED) features->usable_capabilities |= cpu & (sse_mask | OCNEXT_X86_CAP_FXSR);
    if (features->xgetbv_permitted && features->xcr0_observed && features->supported_xstate_observed) {
        features->usable_capabilities |= cpu & OCNEXT_X86_CAP_XSAVE;
        if (snapshot->legacy_sse_os == OCNEXT_X86_SSE_OS_ENABLED &&
            (features->enabled_xstate & 6) == 6 && (cpu & OCNEXT_X86_CAP_AVX))
            features->usable_capabilities |= cpu & (OCNEXT_X86_CAP_AVX | OCNEXT_X86_CAP_AVX2 | OCNEXT_X86_CAP_FMA | OCNEXT_X86_CAP_F16C);
    }
    return incomplete ? OCNEXT_X86_INCOMPLETE : OCNEXT_X86_OK;
}

int ocnext_x86_collect(const struct ocnext_x86_provider *provider,
                      enum ocnext_x86_sse_os_state os, struct ocnext_x86_snapshot *snapshot)
{
    struct ocnext_x86_features features;
    if (!snapshot) return OCNEXT_X86_ARGUMENT;
    zero_bytes(snapshot, sizeof(*snapshot)); snapshot->version = OCNEXT_X86_SNAPSHOT_VERSION;
    if (!provider || !provider->cpuid || !valid_os(os) || !valid_origin(provider->origin)) return OCNEXT_X86_ARGUMENT;
    snapshot->legacy_sse_os = os; snapshot->origin = provider->origin;
    if (provider->cpuid(provider->context, 0, 0, &snapshot->leaf0)) return OCNEXT_X86_UNAVAILABLE;
    snapshot->valid |= OCNEXT_X86_VALID_LEAF0;
    if (snapshot->leaf0.eax >= 1 && !provider->cpuid(provider->context, 1, 0, &snapshot->leaf1)) {
        snapshot->valid |= OCNEXT_X86_VALID_LEAF1;
        if (snapshot->leaf0.eax >= 7 && !provider->cpuid(provider->context, 7, 0, &snapshot->leaf7_0)) snapshot->valid |= OCNEXT_X86_VALID_LEAF7_0;
        if ((snapshot->leaf1.ecx & (UINT32_C(1) << 26)) && snapshot->leaf0.eax >= 13 &&
            !provider->cpuid(provider->context, 13, 0, &snapshot->leafd_0)) snapshot->valid |= OCNEXT_X86_VALID_LEAFD_0;
        if ((snapshot->leaf1.ecx & (UINT32_C(3) << 26)) == (UINT32_C(3) << 26) &&
            provider->xgetbv && !provider->xgetbv(provider->context, 0, &snapshot->xcr0)) snapshot->valid |= OCNEXT_X86_VALID_XCR0;
    }
    return ocnext_x86_evaluate(snapshot, &features);
}

#if defined(__x86_64__) || defined(_M_X64)
static int native_cpuid(void *context, uint32_t leaf, uint32_t subleaf, struct ocnext_x86_cpuid *out)
{
    (void)context;
#if defined(_MSC_VER)
    int regs[4]; __cpuidex(regs, (int)leaf, (int)subleaf);
    out->eax = (uint32_t)regs[0]; out->ebx = (uint32_t)regs[1]; out->ecx = (uint32_t)regs[2]; out->edx = (uint32_t)regs[3];
#else
    __asm__ volatile("cpuid" : "=a"(out->eax), "=b"(out->ebx), "=c"(out->ecx), "=d"(out->edx) : "0"(leaf), "2"(subleaf));
#endif
    return 0;
}
static int native_xgetbv(void *context, uint32_t index, uint64_t *out)
{
    (void)context;
#if defined(_MSC_VER)
    *out = _xgetbv(index);
#else
    uint32_t low, high;
    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(low), "=d"(high) : "c"(index));
    *out = ((uint64_t)high << 32) | low;
#endif
    return 0;
}
#endif

int ocnext_x86_native_probe(struct ocnext_x86_snapshot *snapshot, struct ocnext_x86_features *features)
{
    if (!snapshot || !features) return OCNEXT_X86_ARGUMENT;
    zero_bytes(snapshot, sizeof(*snapshot)); snapshot->version = OCNEXT_X86_SNAPSHOT_VERSION;
#if defined(__x86_64__) || defined(_M_X64)
    struct ocnext_x86_provider provider = {0};
    enum ocnext_x86_sse_os_state os;
    provider.cpuid = native_cpuid; provider.xgetbv = native_xgetbv;
#if defined(OCNEXT_X86_FREESTANDING)
    provider.origin = OCNEXT_X86_ORIGIN_FREESTANDING_X86_64; os = OCNEXT_X86_SSE_OS_UNKNOWN;
#else
    provider.origin = OCNEXT_X86_ORIGIN_HOSTED_X86_64; os = OCNEXT_X86_SSE_OS_ENABLED;
#if defined(__APPLE__)
    int translated = 0; size_t size = sizeof(translated);
    if (sysctlbyname("sysctl.proc_translated", &translated, &size, 0, 0) == 0 && translated == 1) provider.origin = OCNEXT_X86_ORIGIN_ROSETTA;
#endif
#endif
    (void)ocnext_x86_collect(&provider, os, snapshot);
#endif
    return ocnext_x86_evaluate(snapshot, features);
}
