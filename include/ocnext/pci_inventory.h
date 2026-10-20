#ifndef OCNEXT_PCI_INVENTORY_H
#define OCNEXT_PCI_INVENTORY_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define OCNEXT_PCI_INVENTORY_ABI 1u
#define OCNEXT_PCI_STD_CAP_MAX 48u
#define OCNEXT_PCI_EXT_CAP_MAX 64u
#define OCNEXT_PCI_CAP_MAX 112u
#define OCNEXT_PCI_BAR_MAX 6u

enum ocnext_pci_result {
    OCNEXT_PCI_OK = 0, OCNEXT_PCI_INVALID_ARGUMENT = 1,
    OCNEXT_PCI_ALIAS = 2, OCNEXT_PCI_INVALID_IDENTITY = 3,
    OCNEXT_PCI_DIGEST_MISMATCH = 4, OCNEXT_PCI_NO_DEVICE = 5,
    OCNEXT_PCI_UNSUPPORTED_HEADER = 6, OCNEXT_PCI_INVALID_BAR = 7,
    OCNEXT_PCI_INVALID_CHAIN = 8, OCNEXT_PCI_CAP_LIMIT = 9,
    OCNEXT_PCI_INVALID_CAPABILITY = 10, OCNEXT_PCI_DUPLICATE_CAPABILITY = 11,
    OCNEXT_PCI_CAP_OVERLAP = 12
};
enum ocnext_pci_source_kind {
    OCNEXT_PCI_SOURCE_CAPTURED = 1, OCNEXT_PCI_SOURCE_SYNTHETIC = 2,
    OCNEXT_PCI_SOURCE_QEMU = 3
};
enum ocnext_pci_bar_kind {
    OCNEXT_PCI_BAR_MEMORY32 = 1, OCNEXT_PCI_BAR_MEMORY_BELOW_1M = 2,
    OCNEXT_PCI_BAR_MEMORY64 = 3, OCNEXT_PCI_BAR_IO = 4,
    OCNEXT_PCI_BAR_CONTINUATION = 5
};
enum ocnext_pci_known {
    OCNEXT_PCI_K_HEADER = 1u, OCNEXT_PCI_K_SUBSYSTEM = 2u,
    OCNEXT_PCI_K_STD_CHAIN = 4u, OCNEXT_PCI_K_EXT_CHAIN = 8u
};
enum ocnext_pci_flags { OCNEXT_PCI_F_EXT_UNAVAILABLE = 1u };
enum ocnext_pci_bar_known {
    OCNEXT_PCI_BAR_K_RAW = 1u, OCNEXT_PCI_BAR_K_BASE = 2u,
    OCNEXT_PCI_BAR_K_KIND = 4u
};
enum ocnext_pci_cap_known {
    OCNEXT_PCI_CAP_K_HEADER = 1u, OCNEXT_PCI_CAP_K_REGISTERS = 2u,
    OCNEXT_PCI_CAP_K_FULL_LENGTH = 4u, OCNEXT_PCI_CAP_K_DERIVED = 8u
};
enum ocnext_pci_cap_list { OCNEXT_PCI_CAP_CONVENTIONAL = 1, OCNEXT_PCI_CAP_EXTENDED = 2 };

/* Native, caller-provisioned provenance; these IDs and BDF are NOT
 * authenticated device/NativePA/IOVA authority. A snapshot's SHA binds only
 * its exact 256/4096 captured bytes, not these IDs or a capture mechanism.
 * device<=31/function<=7; ARI addressing and bridge routing are not decoded.
 * All identity IDs and generation must be nonzero; reserved must be zero. */
struct ocnext_pci_identity {
    uint64_t source_id, capture_id, domain_id, owner_id, session_id, instance_id;
    uint32_t generation;
    uint16_t segment;
    uint8_t bus, device, function, source_kind;
    uint16_t reserved;
    uint32_t abi;
};
struct ocnext_pci_snapshot {
    const uint8_t *bytes;
    size_t length;
    struct ocnext_pci_identity identity;
    uint8_t expected_sha256[32];
};
struct ocnext_pci_bar {
    uint64_t base, aperture_bytes; /* aperture always UNKNOWN (stored zero). */
    uint32_t raw_low, raw_high, known_mask;
    uint8_t index, slots, kind, prefetch;
};
/* values depend on id/list (documented in implementation-pci-inventory.md).
 * validated_bytes covers only a proven prefix or declared opaque length.
 * An unknown capability's body is not silently inferred from next-offset.
 * No field establishes IRQ, ACS isolation, ATS/PASID or DMA permission. */
struct ocnext_pci_capability {
    uint16_t offset, next, id;
    uint8_t version, list;
    uint16_t validated_bytes, reserved;
    uint32_t known_mask;
    uint64_t values[4];
};
struct ocnext_pci_inventory {
    struct ocnext_pci_identity identity;
    uint8_t sha256[32];
    uint32_t abi, config_bytes, known_mask, flags;
    uint32_t authority_known, qualification; /* Always zero. */
    uint16_t vendor, device, command, status, subsystem_vendor, subsystem_device;
    uint16_t standard_count, extended_count;
    uint8_t revision, programming_interface, subclass, class_code;
    uint8_t header_type, multifunction, bar_slots, reserved;
    struct ocnext_pci_bar bars[OCNEXT_PCI_BAR_MAX];
    struct ocnext_pci_capability capabilities[OCNEXT_PCI_CAP_MAX];
};
struct ocnext_pci_workspace {
    struct ocnext_pci_inventory staged;
    uint8_t occupied[512];
};

/* Pure, bounded, stateless parsing; no PCI/config/MMIO reads or writes,
 * allocation, BAR sizing, address mapping, native driver or GPU execution.
 * The native caller serializes and owns valid accessible objects. All four
 * known spans (snapshot, raw bytes, workspace, output) must be pairwise
 * disjoint and address-overflow-free; typed objects need natural alignment.
 * Raw bytes may be unaligned. Opaque/unrelated backing is caller-owned.
 * Errors leave output and every input byte-identical. Scratch is unspecified
 * on error. OK publishes the whole output once all validation has succeeded.
 * Expected SHA consistency does not certify capture authenticity or freshness.
 * Conventional/extended limits are 48/64 entries. Unknown bodies remain
 * UNKNOWN; overlap checks cover every validated prefix/declared body only.
 * Native ABI1 is separate from ONXT minor0/1 and domain-policy handle ABI1. */
enum ocnext_pci_result ocnext_pci_inventory_parse(
    const struct ocnext_pci_snapshot *, struct ocnext_pci_workspace *,
    struct ocnext_pci_inventory *);

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8, "PCI native ABI is 64-bit");
_Static_assert(sizeof(struct ocnext_pci_identity) == 64, "identity ABI");
_Static_assert(sizeof(struct ocnext_pci_snapshot) == 112, "snapshot ABI");
_Static_assert(sizeof(struct ocnext_pci_bar) == 32, "BAR ABI");
_Static_assert(sizeof(struct ocnext_pci_capability) == 48, "capability ABI");
_Static_assert(offsetof(struct ocnext_pci_inventory, bars) == 144, "header ABI");
_Static_assert(sizeof(struct ocnext_pci_inventory) == 5712, "inventory ABI");
_Static_assert(sizeof(struct ocnext_pci_workspace) == 6224, "workspace ABI");
#endif
#ifdef __cplusplus
}
#endif
#endif
