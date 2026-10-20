#ifndef OCNEXT_VMAPPLE_PAC_MODEL_H
#define OCNEXT_VMAPPLE_PAC_MODEL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A separately named, source-versioned transition model. It is not an Apple
 * key issuer, a CPU bank, an ONXT message or a qualified guest HVC provider.
 * Behavior source: utmapp/Hypervisor b2c910fb9f687929a50e5a7d62e59e43a006d47d,
 * hv.c deliver_pac_trap; that source describes macOS12.5.1, not target26A434.
 * No upstream implementation text is included in this library.
 */
#define OCNEXT_VMAPPLE_PAC_MODEL_ABI_VERSION 1u
#define OCNEXT_VMAPPLE_PAC_MODEL_PROFILE_NONE 0u
#define OCNEXT_VMAPPLE_PAC_MODEL_PROFILE_UTM_12_5_1 1u
#define OCNEXT_VMAPPLE_PAC_MODEL_GPR_ALL 0x1fu
#define OCNEXT_VMAPPLE_PAC_MODEL_KEYS_ALL 0x0fffu
#define OCNEXT_VMAPPLE_PAC_MODEL_STATE_ALL 0x1fffu
#define OCNEXT_VMAPPLE_PAC_MODEL_ESR_KNOWN 1u
#define OCNEXT_VMAPPLE_PAC_MODEL_BANK_PAC 1u
#define OCNEXT_VMAPPLE_PAC_MODEL_BANK_KERN 2u
#define OCNEXT_VMAPPLE_PAC_MODEL_BANK_ALL 3u
#define OCNEXT_VMAPPLE_PAC_MODEL_SYNC_PAC UINT64_C(0x2000000000000000)
#define OCNEXT_VMAPPLE_PAC_MODEL_SYNC_KERN UINT64_C(0x1000000000000000)

enum ocnext_vmapple_pac_model_code {
    OCNEXT_VMAPPLE_PAC_MODEL_PREPARED = 0,
    OCNEXT_VMAPPLE_PAC_MODEL_ARGUMENT = 1,
    OCNEXT_VMAPPLE_PAC_MODEL_UNSUPPORTED = 2
};

enum ocnext_vmapple_pac_model_hacr {
    OCNEXT_VMAPPLE_PAC_MODEL_HACR_UNKNOWN = 0,
    OCNEXT_VMAPPLE_PAC_MODEL_HACR_DISABLED = 1,
    OCNEXT_VMAPPLE_PAC_MODEL_HACR_ENABLED = 2
};

/* Native128B/alignment8. Slots are APIA lo/hi, APIB lo/hi, APDA lo/hi,
 * APDB lo/hi, APGA lo/hi, KERN lo/hi. Bit i says slot i is known. A clear
 * slot bit requires stored0, which does not mean an architectural known zero.
 * APCTL uses per-bit knowledge; unrecognized stored bits must be0. The private
 * effect of APCTL/KERN on Apple's PAC algorithm is deliberately not inferred.
 */
struct ocnext_vmapple_pac_model_state {
    uint32_t abi_version, bytes, profile, key_known_mask;
    uint64_t key_halves[12];
    uint64_t apctl_value, apctl_known_mask;
};

/* Native80B/alignment8. GPR bits describe entire X0..4, with stored0 for an
 * unknown input. ESR is the actual routed syndrome, not an HVC opcode. The
 * caller supplies explicit HACR.bit4 knowledge; it is never derived from CPU
 * identity. A serialized native caller certifies the selected software banks
 * are already materialized and stable. Missing certification is unsupported.
 * These integer fields cannot authorize hardware bank synchronization.
 */
struct ocnext_vmapple_pac_model_request {
    uint32_t abi_version, bytes, profile, known_gpr_mask;
    uint64_t gpr[5];
    uint64_t esr;
    uint32_t context_known_mask, hacr_bit4, materialized_bank_mask, reserved;
};

/* Native240B/alignment8. PREPARED is a model result, not HVC success. handled0
 * describes a source-declined call. handled1 may return either source status0
 * or zero-extended0xffffffff in X0. gpr_write_mask is distinct from knowledge.
 * state_write_mask bits0..11 select halves; bit12 selects APCTL. Unwritten
 * state/GPRs keep their exact values and knowledge. sync_intents[] records the
 * source call sequence only; it certifies no executed callback/fence/dirty bit.
 * The model does not advance PC/retirement, inject exceptions, access RAM,
 * perform PAC/AUT, alter CPU features or publish any live CPU/key authority.
 */
struct ocnext_vmapple_pac_model_effect {
    uint32_t abi_version, bytes, handled, selector;
    uint64_t gpr[5];
    uint32_t gpr_write_mask, known_gpr_mask;
    struct ocnext_vmapple_pac_model_state after;
    uint64_t sync_intents[4];
    uint32_t sync_count, state_write_mask;
    uint64_t reserved;
};

/* All native objects must be valid stable readable/writable caller-owned
 * storage, aligned as declared, with disjoint complete spans. Alias/overflow
 * is rejected before typed reads. This is not a native-pointer sandbox.
 * Success publishes one complete effect after all validation; every error
 * leaves inputs and output byte-identical. No concurrent mutation/retry.
 * Validation rejects unknown profiles or unequal state/request profiles as
 * ARGUMENT. Matching NONE is UNSUPPORTED after canonical-field validation.
 * A declined EC/immediate/namespace returns selector0. The selector is set
 * only after recognizing EC0x16, immediate0 and the X0 c1 namespace. Unknown
 * ESR is UNSUPPORTED; a known declined EC/immediate does not need known X0.
 */
enum ocnext_vmapple_pac_model_code ocnext_vmapple_pac_model_prepare(
    const struct ocnext_vmapple_pac_model_state *,
    const struct ocnext_vmapple_pac_model_request *,
    struct ocnext_vmapple_pac_model_effect *);

#ifdef __cplusplus
}
#endif
#endif
