#ifndef OCNEXT_PCI_CAPTURE_H
#define OCNEXT_PCI_CAPTURE_H
#include "ocnext/pci_inventory.h"
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define OCNEXT_PCI_CAPTURE_ABI 1u
#define OCNEXT_PCI_CAPTURE_CHUNK 64u
#define OCNEXT_PCI_CAPTURE_MAX_READ_CALLS 128u
#define OCNEXT_PCI_CAPTURE_MAX_READ_BYTES 8192u
#define OCNEXT_PCI_CAPTURE_COMPLETED_UNKNOWN UINT32_MAX
enum ocnext_pci_capture_profile { OCNEXT_PCI_CAPTURE_QEMU_READONLY = 1 };
enum ocnext_pci_capture_result {
    OCNEXT_PCI_CAPTURE_OK = 0, OCNEXT_PCI_CAPTURE_ARGUMENT = 1,
    OCNEXT_PCI_CAPTURE_ALIAS = 2, OCNEXT_PCI_CAPTURE_IDENTITY = 3,
    OCNEXT_PCI_CAPTURE_QUOTA = 4, OCNEXT_PCI_CAPTURE_PROVIDER_FAILED = 5,
    OCNEXT_PCI_CAPTURE_PROVIDER_PROTOCOL = 6, OCNEXT_PCI_CAPTURE_BINDING_CHANGED = 7,
    OCNEXT_PCI_CAPTURE_UNSTABLE = 8, OCNEXT_PCI_CAPTURE_NO_DEVICE = 9,
    OCNEXT_PCI_CAPTURE_UNSUPPORTED_HEADER = 10, OCNEXT_PCI_CAPTURE_BAD_RECORD = 11,
    OCNEXT_PCI_CAPTURE_DIGEST_MISMATCH = 12
};
enum ocnext_pci_capture_trace_flags {
    OCNEXT_PCI_CAPTURE_T_BINDING_BEFORE = 1u, OCNEXT_PCI_CAPTURE_T_READ_ATTEMPTED = 2u,
    OCNEXT_PCI_CAPTURE_T_STABLE = 4u, OCNEXT_PCI_CAPTURE_T_BINDING_AFTER = 8u,
    OCNEXT_PCI_CAPTURE_T_DIGEST = 16u, OCNEXT_PCI_CAPTURE_T_PARTIAL_UNKNOWN = 32u
};
/* Native trusted-caller provenance, not authenticated device/IOVA/DMA rights.
 * Identity source_kind must be QEMU3. Epoch/channel are nonzero opaque issuer
 * tags. No registry validates historical freshness or physical hardware. */
struct ocnext_pci_capture_binding {
    struct ocnext_pci_identity identity;
    uint64_t channel_id, source_epoch;
};
struct ocnext_pci_capture_request {
    struct ocnext_pci_capture_binding binding;
    uint32_t config_bytes, max_read_calls, max_read_bytes, abi;
};
/* Exactly1 + status0 + completed==requested is success. Other return values
 * fail closed. On failure completed<=requested is provider-observed count;
 * UINT32_MAX means UNKNOWN (UEFI Read returns no partial count). Raw status is
 * diagnostic, never authority. Provider serializes and owns its opaque context,
 * performs configuration READS ONLY, keeps inputs stable and does not mutate
 * request/provider/output/trace or unrelated memory. The core cannot prevent
 * arbitrary native callback/global writes or cancel a blocking callback.
 * Call budgets are bounded work, not a claimed wall-clock deadline. */
typedef int (*ocnext_pci_capture_read_fn)(void *, uint32_t offset, uint8_t *,
                                        uint32_t requested, uint32_t *completed,
                                        uint64_t *raw_status);
typedef int (*ocnext_pci_capture_observe_fn)(void *, struct ocnext_pci_capture_binding *,
                                           uint64_t *raw_status);
struct ocnext_pci_capture_provider {
    void *context;
    ocnext_pci_capture_read_fn read;
    ocnext_pci_capture_observe_fn observe;
    uint32_t abi, profile;
};
/* Header144 + owned raw4096. known_mask7 means captured bytes/stability/two
 * matching bindings only. Unused raw tail is zero; size/aperture/authority and
 * future hotplug freshness remain UNKNOWN. SHA binds exact config_bytes only.
 * read_calls are callback attempts; read_bytes are successful/reported bytes.
 * This record contains no EFI/native pointers and is NOT an ONXT wire frame. */
struct ocnext_pci_capture_record {
    struct ocnext_pci_identity identity;
    uint8_t sha256[32];
    uint32_t abi, config_bytes, profile, known_mask;
    uint32_t read_calls, read_bytes, binding_observations, stability_passes;
    uint64_t channel_id, source_epoch;
    uint8_t raw[4096];
};
struct ocnext_pci_capture_workspace {
    struct ocnext_pci_capture_record staged;
    uint8_t verify[4096];
};
struct ocnext_pci_capture_trace {
    uint32_t abi, result, profile, flags;
    uint32_t read_calls, read_bytes, observations, failed_pass;
    uint32_t failed_offset, requested_bytes, completed_bytes, reserved;
    uint64_t provider_status;
    uint32_t source_generation, reserved2;
};
/* Five external spans need natural alignment8, no native end overflow and
 * pairwise disjoint ranges before typed dereference/callback/scratch mutation.
 * Validation errors preserve all objects, including trace. Runtime/provider
 * failures publish only trace; output record and inputs stay byte-identical,
 * scratch unspecified. Success publishes a complete record then trace under
 * serialized caller control (not concurrent hardware-atomic publication).
 * Two complete passes, before/after exact binding and SHA; no fallback to256
 * after incomplete4096. No allocation/libc, no address->hardware pointer cast. */
enum ocnext_pci_capture_result ocnext_pci_capture_run(
    const struct ocnext_pci_capture_request *, const struct ocnext_pci_capture_provider *,
    struct ocnext_pci_capture_workspace *, struct ocnext_pci_capture_record *,
    struct ocnext_pci_capture_trace *);
/* No provider/BootServices calls. Revalidates record metadata/counts/raw SHA
 * before publishing borrowed snapshot112. Failure preserves input/output.
 * The record must remain immutable/alive until every parser consumer finishes.
 * Consistency does not authenticate a forged native record or device source. */
enum ocnext_pci_capture_result ocnext_pci_capture_snapshot(
    const struct ocnext_pci_capture_record *, struct ocnext_pci_snapshot *);
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct ocnext_pci_capture_binding)==80,"binding ABI1");
_Static_assert(sizeof(struct ocnext_pci_capture_request)==96,"request ABI1");
_Static_assert(offsetof(struct ocnext_pci_capture_request,config_bytes)==80,"request offset");
_Static_assert(sizeof(struct ocnext_pci_capture_provider)==32,"provider ABI1");
_Static_assert(sizeof(struct ocnext_pci_capture_record)==4240,"record ABI1");
_Static_assert(offsetof(struct ocnext_pci_capture_record,raw)==144,"record raw offset");
_Static_assert(sizeof(struct ocnext_pci_capture_workspace)==8336,"workspace ABI1");
_Static_assert(sizeof(struct ocnext_pci_capture_trace)==64,"trace ABI1");
_Static_assert(offsetof(struct ocnext_pci_capture_trace,provider_status)==48,"trace status");
#endif
#ifdef __cplusplus
}
#endif
#endif
