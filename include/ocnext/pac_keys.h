#ifndef OCNEXT_PAC_KEYS_H
#define OCNEXT_PAC_KEYS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OCNEXT_PAC_KEYS_ABI_VERSION 1u
#define OCNEXT_PAC_KEY_COUNT 5u
#define OCNEXT_PAC_KEYS_KNOWN_ALL 31u
enum ocnext_pac_key_index {
    OCNEXT_PAC_KEY_IA=0, OCNEXT_PAC_KEY_IB=1, OCNEXT_PAC_KEY_DA=2,
    OCNEXT_PAC_KEY_DB=3, OCNEXT_PAC_KEY_GA=4
};
enum ocnext_pac_key_profile {
    OCNEXT_PAC_KEYS_NONE=0, OCNEXT_PAC_KEYS_QARMA5_SYNTHETIC=1
};
struct ocnext_pac_key { uint64_t lo, hi; };
/* Native POD ABI1/112B; never a guest wire object or hardware register image.
 * Keys are explicitly synthetic. UNKNOWN slots have stored0/known-clear.
 * A known zero key is valid deliberately provisioned test data. Reset is ABI1
 * with all other fields0. Closed retains owner+advanced generation and clears
 * profile, knowledge and keys. Active has owner!=0, generation>=1, profile1
 * and at least one known key. Caller owns a stable serialized object.
 */
struct ocnext_pac_key_bank {
    struct ocnext_pac_key keys[OCNEXT_PAC_KEY_COUNT];
    uint64_t generation, owner_id;
    uint32_t profile, known_mask, abi_version, reserved;
};
enum ocnext_pac_key_result {
    OCNEXT_PAC_KEYS_OK=0, OCNEXT_PAC_KEYS_ARGUMENT=1,
    OCNEXT_PAC_KEYS_STALE=2, OCNEXT_PAC_KEYS_OVERFLOW=3,
    OCNEXT_PAC_KEYS_STATE=4
};

/* Only trusted native lifetime owners may call reset/provision/rotate/close.
 * Integer IDs do not authenticate an untrusted caller. Never reset a live
 * object to reuse an old authority; destroy its containing lifetime instead.
 * No host sysregisters, Apple service or guest memory access is performed.
 * reset initializes a new object; all other operations preflight everything
 * before an all-or-none commit. Invalid calls leave the bank byte-identical.
 * keys must point to five stable readable keys and be disjoint from bank.
 * All pointers must be valid aligned native objects; forged pointers are not
 * a supported input. These APIs do not promise constant-time secret handling.
 */
enum ocnext_pac_key_result ocnext_pac_keys_reset(struct ocnext_pac_key_bank *);
int ocnext_pac_keys_valid(const struct ocnext_pac_key_bank *);
enum ocnext_pac_key_result ocnext_pac_keys_provision(
    struct ocnext_pac_key_bank *, uint64_t owner_id, uint64_t expected_generation,
    uint32_t known_mask, const struct ocnext_pac_key keys[OCNEXT_PAC_KEY_COUNT]);
enum ocnext_pac_key_result ocnext_pac_keys_rotate(
    struct ocnext_pac_key_bank *, uint64_t owner_id, uint64_t expected_generation,
    uint32_t known_mask, const struct ocnext_pac_key keys[OCNEXT_PAC_KEY_COUNT]);
enum ocnext_pac_key_result ocnext_pac_keys_close(
    struct ocnext_pac_key_bank *, uint64_t owner_id, uint64_t expected_generation);

#ifdef __cplusplus
}
#endif
#endif
