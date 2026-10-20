#ifndef OCNEXT_CHAINED_FIXUPS_H
#define OCNEXT_CHAINED_FIXUPS_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define OCNEXT_CHAINED_ABI_VERSION 1u
#define OCNEXT_CHAINED_MAX_IMAGE (96u * 1024u * 1024u)
#define OCNEXT_CHAINED_MAX_SEGMENTS 32u
#define OCNEXT_CHAINED_MAX_SLOTS 1000000u
#define OCNEXT_CHAINED_MAX_WINDOW 4096u
#define OCNEXT_CHAINED_CATALOG_ABI_VERSION 1u
#define OCNEXT_CHAINED_WORKSPACE_BYTES 2312u
/* Native PODs, not wire structures. This immutable import-free format8
 * inventory does not resolve/sign/apply pointers or establish Apple keys,
 * effective modifiers, basePointers, slide, device or boot authority.
 * Snapshot IDs are caller provenance, not authenticated identity.
 * Supported root filetype is MH_FILESET, segment file offsets aligned4,
 * page4096/16384, import-free version0. Inner filesets are not loaded.
 * Serialized caller-owned stable native spans are required. No callbacks,
 * allocations or libc. On error all inputs/outputs are unchanged; workspace
 * and scratch are unspecified. Every native object and raw image must be
 * pairwise disjoint; object alignment8, image alignment unrestricted.
 * Two terminal slot bytes may cross their declared page, but the whole8B
 * must be file-backed. NEXT uses positive stride4 and cannot leave the page.
 * Root load-command/fixup metadata may not overlap a slot. This does not
 * certify every inner Mach-O metadata/code/data classification for patching. */
struct ocnext_chained_snapshot {
    const uint8_t *bytes;
    uint64_t byte_count;
    uint8_t expected_sha256[32];
    uint64_t source_id, source_epoch;
    uint32_t abi_version, reserved;
}; /*72*/
struct ocnext_chained_segment {
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint8_t name[16];
}; /*48: raw name bytes, no string assumption*/
struct ocnext_chained_slot {
    uint64_t file_offset, image_vm_offset, encoded_word;
    uint32_t segment_index, page_index, page_size, target_offset;
    uint16_t diversity, next_units;
    uint8_t key_selector, cache_level, address_diversity, authenticated;
}; /*48: unused unauthenticated metadata remains raw facts*/
struct ocnext_chained_summary {
    uint64_t root_vm_base, payload_file_offset, payload_bytes, image_bytes;
    uint8_t image_sha256[32], payload_sha256[32];
    uint64_t total, authenticated, unauthenticated, address_diverse;
    uint64_t not_address_diverse, cross_page_terminal, unauth_unused_nonzero;
    uint64_t distinct_diversity;
    uint64_t key_counts[4], cache_counts[4], segment_counts[32];
    uint32_t abi_version, root_segments, fileset_entries, load_commands;
}; /*496*/
struct ocnext_chained_window {
    struct ocnext_chained_slot *slots;
    uint64_t first_index;
    uint32_t capacity, count, abi_version, reserved;
}; /*32: input count must0, first_index <= final total; all-or-none output*/
struct ocnext_chained_workspace {
    uint64_t alignment;
    uint8_t opaque[OCNEXT_CHAINED_WORKSPACE_BYTES - 8u];
};
/* Separate native collection ABI1/24B. This complete catalog has no pagination:
 * first index is implicitly0, capacity<=MAX_SLOTS and input count must0.
 * Full-chain total>capacity is BUDGET, with every output unchanged. slots may
 * be NULL only for capacity0. This publishes immutable metadata facts only;
 * it is not a validated loader index, patch authority or Apple signer.
 * The complete capacity span is preflighted even if fewer entries are used. */
struct ocnext_chained_catalog {
    struct ocnext_chained_slot *slots;
    uint32_t capacity, count, abi_version, reserved;
};
enum ocnext_chained_result {
    OCNEXT_CHAINED_OK=0, OCNEXT_CHAINED_ARGUMENT=1,
    OCNEXT_CHAINED_DIGEST=2, OCNEXT_CHAINED_MACHO=3,
    OCNEXT_CHAINED_SEGMENT=4, OCNEXT_CHAINED_METADATA=5,
    OCNEXT_CHAINED_SLOT=6, OCNEXT_CHAINED_OVERLAP=7,
    OCNEXT_CHAINED_BUDGET=8, OCNEXT_CHAINED_WINDOW=9
};
/* Zero means invalid size/capacity. Scratch needs align8 and exactly or more
 * this many bytes: rounded occupancy bitmap + diversity bitmap + staged
 * window. It is never an implicit guest memory mapping. */
size_t ocnext_chained_scratch_bytes(uint64_t image_bytes, uint32_t capacity);
int ocnext_chained_scan(const struct ocnext_chained_snapshot *,
    struct ocnext_chained_workspace *, void *scratch, size_t scratch_bytes,
    struct ocnext_chained_summary *,
    struct ocnext_chained_segment segments[OCNEXT_CHAINED_MAX_SEGMENTS],
    struct ocnext_chained_window *optional_window);
/* A separately bounded full collection API. The historical window API and
 * its4096 limit are unchanged. Scratch stages capacity*48 bytes privately;
 * no caller output is published until the complete walk succeeds. All native
 * spans retain the same stable, serialized, pairwise-disjoint contract. */
size_t ocnext_chained_catalog_scratch_bytes(uint64_t image_bytes,
    uint32_t capacity);
int ocnext_chained_collect(const struct ocnext_chained_snapshot *,
    struct ocnext_chained_workspace *, void *scratch, size_t scratch_bytes,
    struct ocnext_chained_summary *,
    struct ocnext_chained_segment segments[OCNEXT_CHAINED_MAX_SEGMENTS],
    struct ocnext_chained_catalog *);
#ifdef __cplusplus
}
#endif
#endif
