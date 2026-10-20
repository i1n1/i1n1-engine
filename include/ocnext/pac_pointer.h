#ifndef OCNEXT_PAC_POINTER_H
#define OCNEXT_PAC_POINTER_H

#include <stdint.h>
#include "ocnext/pac_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OCNEXT_PAC_POINTER_ABI_VERSION 1u
enum ocnext_pac_pointer_profile {
    OCNEXT_PAC_POINTER_NONE=0,
    OCNEXT_PAC_POINTER_QARMA5_PAUTH2=1,
    OCNEXT_PAC_POINTER_QARMA5_FPAC=2,
    /* FEAT_PAuth only (no PAuth2): the PAC replaces the field, a failed AUT
     * returns the restored pointer with an error code in [top-2:top-3]. */
    OCNEXT_PAC_POINTER_QARMA5_PAUTH1=3
};
enum ocnext_pac_pointer_operation {
    OCNEXT_PAC_POINTER_SIGN=1,
    OCNEXT_PAC_POINTER_AUTH=2,
    OCNEXT_PAC_POINTER_STRIP=3
};
enum ocnext_pac_pointer_result {
    OCNEXT_PAC_POINTER_OK=0,
    OCNEXT_PAC_POINTER_ARGUMENT=1,
    OCNEXT_PAC_POINTER_UNSUPPORTED=2,
    OCNEXT_PAC_POINTER_KEY_UNKNOWN=3,
    OCNEXT_PAC_POINTER_STALE=4,
    OCNEXT_PAC_POINTER_INACTIVE=5
};
enum ocnext_pac_pointer_outcome {
    OCNEXT_PAC_POINTER_SIGNED=1,
    OCNEXT_PAC_POINTER_AUTH_SUCCESS=2,
    OCNEXT_PAC_POINTER_AUTH_CORRUPTED=3,
    OCNEXT_PAC_POINTER_AUTH_EXCEPTION=4,
    OCNEXT_PAC_POINTER_STRIPPED=5,
    OCNEXT_PAC_POINTER_DISABLED=6
};

/* Explicit resolved EL1&0 geometry, native ABI1/16B. Every field is supplied
 * by the trusted caller; UNKNOWN TCR is not resolved by assuming zeros.
 * Both VA widths are25..48. TBI selects bit55's range; TBID applies only to
 * instruction keys. M0/M1 does not change these PAC placement rules.
 * Profile1 is PAuth2 XOR reconstruction without synchronous FPAC; profile2
 * supports standalone AUT with FPAC. No combined branch/return, base/EPAC,
 * PACM, MTE, 52-bit, implementation-defined MAC or QARMA3 behavior is implied.
 * No CPU APA register is advertised or changed by selecting this profile.
 */
struct ocnext_pac_pointer_config {
    uint32_t abi_version,profile;
    uint8_t va_bits[2],tbi[2],tbid[2],reserved[2];
};

/* Native ABI1/48B. current_el is0or1; key_index IA/IB/DA/DB only. key_enabled
 * is the explicitly known instruction-key enable state, not an inferred
 * SCTLR default. This native authority boundary still needs an active known
 * bound bank for DISABLED/STRIP; a future ISA decoder must separately handle
 * architectural disabled-key/no-key-access ordering and keyless XPAC.
 * No input is a guest address to dereference; pointer is only a64-bit value.
 */
struct ocnext_pac_pointer_request {
    uint64_t pointer,modifier,owner_id,generation;
    uint32_t operation,key_index;
    uint8_t current_el,key_enabled,reserved[6];
};

/* Native ABI1/32B. AUTH_EXCEPTION preserves the input destination and reports
 * EC0x1c/IL1/ISS(data<<1|keyB). It does not deliver a CPU exception itself.
 * AUTH_CORRUPTED is a retired PAuth2 reconstruction with noncanonical PAC
 * extension bits; no immediate fault/branch/memory access is performed.
 */
struct ocnext_pac_pointer_output {
    uint64_t pointer,esr,generation;
    uint32_t outcome,reserved;
};

int ocnext_pac_pointer_config_valid(const struct ocnext_pac_pointer_config *);
/* All four objects must be valid aligned stable serialized native objects,
 * with pairwise disjoint overflow-checked spans. Forged native pointers are
 * outside the contract. API rejection leaves output and all inputs unchanged.
 * FPAC outcome is an OK staged exception result, not API failure/successful
 * authentication. There are no CPU/RAM/key/PC/retirement commits or OS calls.
 * SIGN with bit63!=bit55 and effective TBI off is explicitly UNSUPPORTED:
 * ConstPACField/range-selector implementation choice is not guessed. Other
 * noncanonical extension bits remain accepted. AUTH accepts signed PAC bits
 * that differ from bit55. STRIP is for explicit independent public testing,
 * never a fallback for failed AUTH or a bypass of original-kernel PAC.
 * Uses the existing non-constant-time synthetic QARMA5 primitive only.
 */
enum ocnext_pac_pointer_result ocnext_pac_pointer_execute(
    const struct ocnext_pac_key_bank *, const struct ocnext_pac_pointer_config *,
    const struct ocnext_pac_pointer_request *, struct ocnext_pac_pointer_output *);

#ifdef __cplusplus
}
#endif
#endif
