#ifndef OCNEXT_A64_LDRA_H
#define OCNEXT_A64_LDRA_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define OCNEXT_A64_LDRA_ABI 1u
#define OCNEXT_A64_LDRA_BASE_KNOWN 1u
#define OCNEXT_A64_LDRA_ADDRESS_NORMAL_BASE64_NO_MTE 1u
enum ocnext_a64_ldra_status {
    OCNEXT_A64_LDRA_OK=0,
    OCNEXT_A64_LDRA_ARGUMENT=1,
    OCNEXT_A64_LDRA_UNSUPPORTED=2
};
/* Native ABI1 request32/effect32/alignment8. The caller separately resolves
 * authentication and source-SP alignment BEFORE planning the address.
 * selected_base is an integer, not a capability, native pointer or RAM lease.
 * UNKNOWN base storage is never inferred known-zero. Native spans must be
 * allocated, stable, serialized, overflow-checked and pairwise disjoint.
 * This helper does not authenticate, dereference RAM, throw exceptions or
 * publish CPU state. No MTE/52-bit/PACM/DIT or hardware feature is implied.
 */
struct ocnext_a64_ldra_request {
    uint64_t selected_base;
    uint32_t opcode, abi_version, known_mask, address_add_profile;
    uint64_t reserved;
};
struct ocnext_a64_ldra_effect {
    uint64_t access_address, writeback_value;
    uint32_t abi_version;
    uint8_t target_register, base_register, writeback, access_bytes;
    uint32_t key_index, reserved;
};
/* Exact LDRAA/LDRAB offset/pre-index family. signed10(S:imm9)*8 bytes.
 * Rt31 discards a destination; the CPU must still perform the actual READ8.
 * Rn31 selects SP. Pre-index Rn==Rt!=31 is coverage-unsupported, not a
 * fabricated guest UNDEFINED choice. No post-index form is accepted.
 * prepare preserves every request/effect byte on failure and publishes once
 * on success. Inactive writeback_value is canonical0. No wire/CPU ABI change.
 */
int ocnext_a64_ldra_decode(uint32_t opcode);
enum ocnext_a64_ldra_status ocnext_a64_ldra_prepare(
    const struct ocnext_a64_ldra_request *,struct ocnext_a64_ldra_effect *);
#ifdef __cplusplus
}
#endif
#endif
