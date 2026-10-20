#ifndef OCNEXT_PAC_SERVICE_H
#define OCNEXT_PAC_SERVICE_H

#include <stddef.h>
#include <stdint.h>
#include "ocnext/pac_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OCNEXT_PAC_SERVICE_ABI_VERSION 1u
#define OCNEXT_PAC_SERVICE_SYNTHETIC_MACGA UINT32_C(0x4f4e0001)
#define OCNEXT_PAC_SERVICE_MAX_CONTEXT 1024u
#define OCNEXT_PAC_SERVICE_CONTEXT_PC 1u
#define OCNEXT_PAC_SERVICE_CONTEXT_PSTATE 2u
#define OCNEXT_PAC_SERVICE_CONTEXT_EL 4u
#define OCNEXT_PAC_SERVICE_CONTEXT_ALL 7u

enum ocnext_pac_service_result_code {
    OCNEXT_PAC_SERVICE_COMPLETED=0, OCNEXT_PAC_SERVICE_UNSUPPORTED=1,
    OCNEXT_PAC_SERVICE_DENIED=2, OCNEXT_PAC_SERVICE_ARGUMENT=3,
    OCNEXT_PAC_SERVICE_PROVIDER_FAILED=4, OCNEXT_PAC_SERVICE_OVERFLOW=5
};

/* Native POD48B. A trusted serialized native issuer initializes a new all-zero
 * object; init rejects any nonzero/live storage without mutation. Never clear
 * a live object to reuse authority; destroy its native registry lifetime.
 * integer IDs themselves do not authenticate guest/wire requests. Epoch starts
 * at1 and increments only after a completely validated synthetic transaction.
 * This service never provisions/rotates/closes keys or writes CPU/guest RAM.
 */
struct ocnext_pac_service_state {
    uint32_t abi_version, bytes, profile, reserved;
    uint64_t owner_id, session_id, epoch, completed_events;
};

/* Native POD208B, not SMCCC/wire serialization. MACGA defines known_input_mask7:
 * X0=separate synthetic FID, X1=data, X2=modifier; X3..7 are captured incidental
 * registers, never key payloads. Unknown context fields must have stored0.
 * Only known EL1 and immediate0 are supported. MMU/TLS values are captured
 * context, not inferred capabilities or callbacks. Native owner/session/epoch
 * and key generation are issued out of band, never obtained from raw HVC data.
 */
struct ocnext_pac_service_request {
    uint32_t abi_version, bytes, function_id, known_input_mask;
    uint64_t x[8];
    uint64_t owner_id, session_id, expected_epoch, expected_key_generation;
    uint64_t pc, mmu[5], tls[3];
    uint32_t context_known_mask, pstate, mmu_known_mask, tls_known_mask;
    uint16_t hvc_immediate;
    uint8_t current_el, reserved_byte;
    uint32_t reserved;
};

/* Native POD136B. A successful candidate has masks1, X0=PACGA upper32bits with
 * low32zero, X1..7 unchanged, identical bindings and exact epoch+1. The service
 * independently verifies the synthetic algorithm result before publication.
 * No key after-image exists: the immutable bank must remain byte-identical.
 */
struct ocnext_pac_service_result {
    uint32_t abi_version, bytes, known_output_mask, clobber_mask;
    uint64_t x[8];
    uint64_t owner_id, session_id, before_epoch, after_epoch, key_generation;
    uint32_t profile, reserved[3];
};

struct ocnext_pac_service_snapshot {
    struct ocnext_pac_service_state state;
    struct ocnext_pac_key_bank bank;
};

typedef enum ocnext_pac_service_result_code (*ocnext_pac_service_prepare)(
    const void *context, size_t context_bytes,
    const struct ocnext_pac_service_snapshot *before,
    const struct ocnext_pac_service_request *request,
    struct ocnext_pac_service_result *candidate);

struct ocnext_pac_service_provider {
    uint32_t abi_version, bytes;
    ocnext_pac_service_prepare prepare;
    const void *context;
    size_t context_bytes;
};

/* Valid aligned native objects and stable readable provider context are required.
 * All input/output objects and the provider context must be pairwise disjoint;
 * context supports native alignment requirements at most alignof(max_align_t)
 * and is privately copied to that alignment; its maximum size is1024 bytes.
 * alias/uintptr overflow is rejected before callbacks or writes. prepare receives
 * bounded private copies, never live state/bank/request/context pointers; their
 * mutation is detected. Callback must not mutate external live objects, retain
 * borrowed pointers, call recursively, or perform hidden authority/RAM effects.
 * Arbitrary native code outside that contract cannot be sandboxed by C.
 * Single caller/serialized storage, no automatic retries and no concurrent
 * publication. Failure leaves state, bank, request, provider, context and result
 * unchanged. COMPLETED atomically publishes state epoch/event and result in this
 * serialized logical sense. All Apple FIDs remain UNSUPPORTED even with keys.
 */
enum ocnext_pac_service_result_code ocnext_pac_service_init(
    struct ocnext_pac_service_state *, uint64_t owner_id, uint64_t session_id);
enum ocnext_pac_service_result_code ocnext_pac_service_execute(
    struct ocnext_pac_service_state *, const struct ocnext_pac_key_bank *,
    const struct ocnext_pac_service_request *,
    const struct ocnext_pac_service_provider *, struct ocnext_pac_service_result *);

/* Explicit public synthetic provider; accepts no context. No Apple derivation,
 * default PID, random key generation, firmware fixups or host sysregs. Lookup
 * QARMA5 has no constant-time secret-key guarantee: use synthetic fixture keys.
 */
enum ocnext_pac_service_result_code ocnext_pac_service_prepare_synthetic(
    const void *, size_t, const struct ocnext_pac_service_snapshot *,
    const struct ocnext_pac_service_request *, struct ocnext_pac_service_result *);

#ifdef __cplusplus
}
#endif
#endif
