#ifndef OCNEXT_NATIVE_MMIO_H
#define OCNEXT_NATIVE_MMIO_H
#include "ocnext/pci_capture.h"
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define OCNEXT_NATIVE_MMIO_ABI 1u
#define OCNEXT_NATIVE_MMIO_APERTURE 4096u
#define OCNEXT_NATIVE_MMIO_HEADER 32u
#define OCNEXT_NATIVE_MMIO_MAX_OPERATIONS 64u
#define OCNEXT_NATIVE_MMIO_MAX_CALLBACKS 4096u
#define OCNEXT_NATIVE_MMIO_MAX_COUNT 16u
enum ocnext_native_mmio_profile { OCNEXT_MMIO_QEMU_TESTDEV = 1 };
enum ocnext_native_mmio_cache { OCNEXT_MMIO_CACHE_UC = 1 };
enum ocnext_native_mmio_rights { OCNEXT_MMIO_READ8 = 1, OCNEXT_MMIO_SELECT0 = 2,
    OCNEXT_MMIO_PULSE0 = 4, OCNEXT_MMIO_STOP = 8, OCNEXT_MMIO_ALL_RIGHTS = 15 };
enum ocnext_native_mmio_op { OCNEXT_MMIO_ARM = 1, OCNEXT_MMIO_OBSERVE = 2,
    OCNEXT_MMIO_MATCH = 3, OCNEXT_MMIO_NONMATCH = 4, OCNEXT_MMIO_CLOSE = 5 };
enum ocnext_native_mmio_phase { OCNEXT_MMIO_EMPTY = 0, OCNEXT_MMIO_READY = 1,
    OCNEXT_MMIO_ARMED = 2, OCNEXT_MMIO_CLOSED = 3, OCNEXT_MMIO_QUARANTINED = 4 };
enum ocnext_native_mmio_status { OCNEXT_MMIO_OK = 0, OCNEXT_MMIO_ARGUMENT = 1,
    OCNEXT_MMIO_ALIAS = 2, OCNEXT_MMIO_CAPTURE = 3, OCNEXT_MMIO_AUTHORITY = 4,
    OCNEXT_MMIO_STATE = 5, OCNEXT_MMIO_STALE = 6, OCNEXT_MMIO_SEQUENCE = 7,
    OCNEXT_MMIO_QUOTA = 8, OCNEXT_MMIO_PROVIDER = 9, OCNEXT_MMIO_BINDING = 10,
    OCNEXT_MMIO_DEVICE = 11 };
enum ocnext_native_mmio_flags { OCNEXT_MMIO_F_PRIVATE_QEMU = 1u,
    OCNEXT_MMIO_F_ACTUAL_READBACK = 2u, OCNEXT_MMIO_F_WRITE_ACKNOWLEDGED = 4u,
    OCNEXT_MMIO_F_LEASE_RETAINED = 8u, OCNEXT_MMIO_F_LOGICAL_CLOSED = 16u };
/* Native ABI1 only, NOT ONXT/proxy/CPU/domain wire. native_pa is the owned
 * x64 VM's machine physical BAR0 address, not guest ARM GPA, host Mac PA,
 * NativeVA or IOVA. Identity/digests alone do not issue ownership. The trusted
 * issuer verifies a fresh same-VM private manifest, QMP aperture and root's
 * certified UC mapping before granting this one profile. No physical PCI,
 * DMA, IRQ, bus-master, IOMMU, GPU or native-kernel authority is represented. */
struct ocnext_native_mmio_binding {
    struct ocnext_pci_identity identity;
    uint64_t channel_id, source_epoch, authority_epoch, native_pa, aperture_bytes, issuer_nonce;
    uint8_t capture_sha256[32], qemu_source_sha256[32], qemu_binary_sha256[32], manifest_sha256[32];
    uint32_t abi, profile, rights, cache_policy;
};
struct ocnext_native_mmio_claim {
    struct ocnext_native_mmio_binding binding;
    const struct ocnext_pci_capture_record *capture;
    uint32_t operation_limit, callback_limit, abi, reserved;
};
/* Exactly1 success. The private claim copy and output are bounded native
 * objects. Original capture remains immutable and is revalidated afterward.
 * Callback/global side effects cannot be sandboxed by C: trusted serialized
 * issuer keeps all original inputs stable and opaque backing disjoint. */
typedef int (*ocnext_native_mmio_authorize_fn)(void *,
    const struct ocnext_native_mmio_claim *, struct ocnext_native_mmio_binding *);
struct ocnext_native_mmio_issuer {
    void *context;
    ocnext_native_mmio_authorize_fn authorize;
    uint32_t abi, profile;
    uint64_t reserved;
};
/* Every callback succeeds ONLY on exactly1 and raw_status0. Unknown returns,
 * errors and changed bindings quarantine the lease, never imply rollback or
 * zero device effects. read8/write8 receive fixed checked offsets, never a
 * pointer/address from a guest. observe performs no device/firmware access.
 * Provider must execute actual byte accesses; copying predicted bytes does
 * not prove a device effect. No cancellation of blocking/native callbacks. */
typedef int (*ocnext_native_mmio_read8_fn)(void *, uint32_t, uint8_t *, uint64_t *);
typedef int (*ocnext_native_mmio_write8_fn)(void *, uint32_t, uint8_t, uint64_t *);
typedef int (*ocnext_native_mmio_observe_fn)(void *, struct ocnext_native_mmio_binding *, uint64_t *);
struct ocnext_native_mmio_provider {
    void *context;
    ocnext_native_mmio_read8_fn read8;
    ocnext_native_mmio_write8_fn write8;
    ocnext_native_mmio_observe_fn observe;
    uint32_t abi, profile;
};
struct ocnext_native_mmio_request {
    uint64_t owner_id, session_id, instance_id, authority_epoch, sequence;
    uint32_t generation, operation;
    uint64_t reserved[2];
};
/* Caller-owned, zero before first init; no reinitialization/recovery of a
 * closed/quarantined lease. Only the separately proven owned-VM teardown can
 * resolve a quarantined external effect. sequence is consumed before the
 * first provider call. committed_sequence records acknowledged WRITE only;
 * failures can still have unknown effects. Counts are observations, not
 * GPU completion/fences. STOP+zero readback releases logical permission only,
 * never frees/pins/unmaps physical pages or proves DMA stopped. */
struct ocnext_native_mmio_state {
    struct ocnext_native_mmio_binding binding;
    uint64_t next_sequence, committed_sequence, callback_attempts, read_attempts,
        write_attempts, successful_operations, last_status;
    uint32_t counter_known, counter, abi, phase, lease_retained,
        operation_limit, callback_limit, used_operations;
    uint64_t reserved;
};
struct ocnext_native_mmio_result {
    uint64_t owner_id, session_id, instance_id, authority_epoch, sequence;
    uint32_t generation, operation, phase, flags;
    uint64_t callback_attempts, read_attempts, write_attempts;
    uint32_t observed_counter, counter_known;
    uint64_t raw_status;
};
struct ocnext_native_mmio_workspace {
    struct ocnext_native_mmio_claim claim;
    struct ocnext_native_mmio_request request;
    struct ocnext_native_mmio_binding issued, observed;
    struct ocnext_native_mmio_state staged;
    struct ocnext_native_mmio_result result;
    struct ocnext_pci_snapshot snapshot;
    uint8_t header[32];
    uint64_t raw_status;
};
/* init known spans claim/issuer/work/state/capture, run known spans
 * state/request/provider/work/result: natural8, end-overflow-free, pairwise
 * disjoint before typed reads or callbacks. All objects accessible/stable
 * under one serialized native caller. Early ARGUMENT/ALIAS/STATE/QUOTA
 * failures preserve every object. Later init CAPTURE/AUTHORITY failure leaves
 * scratch unspecified, preserves inputs/state. Init failures never
 * publish state. Run validates whole request/quota before reserving sequence;
 * runtime failure mutates only state diagnostics to QUARANTINED with lease1,
 * leaves result/inputs unchanged, scratch unspecified. No fallible operation
 * after successful final result publication. No allocation/libc/MMIO cast. */
enum ocnext_native_mmio_status ocnext_native_mmio_init(
    const struct ocnext_native_mmio_claim *, const struct ocnext_native_mmio_issuer *,
    struct ocnext_native_mmio_workspace *, struct ocnext_native_mmio_state *);
enum ocnext_native_mmio_status ocnext_native_mmio_execute(
    struct ocnext_native_mmio_state *, const struct ocnext_native_mmio_request *,
    const struct ocnext_native_mmio_provider *, struct ocnext_native_mmio_workspace *,
    struct ocnext_native_mmio_result *);
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct ocnext_native_mmio_binding)==256,"MMIO binding ABI1");
_Static_assert(offsetof(struct ocnext_native_mmio_binding,capture_sha256)==112,"MMIO binding hash");
_Static_assert(offsetof(struct ocnext_native_mmio_binding,abi)==240,"MMIO binding fields");
_Static_assert(sizeof(struct ocnext_native_mmio_claim)==280,"MMIO claim ABI1");
_Static_assert(sizeof(struct ocnext_native_mmio_issuer)==32,"MMIO issuer ABI1");
_Static_assert(sizeof(struct ocnext_native_mmio_provider)==40,"MMIO provider ABI1");
_Static_assert(sizeof(struct ocnext_native_mmio_request)==64,"MMIO request ABI1");
_Static_assert(sizeof(struct ocnext_native_mmio_state)==352,"MMIO state ABI1");
_Static_assert(offsetof(struct ocnext_native_mmio_state,next_sequence)==256,"MMIO sequence");
_Static_assert(offsetof(struct ocnext_native_mmio_state,abi)==320,"MMIO state ABI");
_Static_assert(sizeof(struct ocnext_native_mmio_result)==96,"MMIO result ABI1");
_Static_assert(sizeof(struct ocnext_native_mmio_workspace)==1456,"MMIO workspace ABI1");
#endif
#ifdef __cplusplus
}
#endif
#endif
