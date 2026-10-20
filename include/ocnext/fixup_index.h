#ifndef OCNEXT_FIXUP_INDEX_H
#define OCNEXT_FIXUP_INDEX_H
#include <stddef.h>
#include <stdint.h>
#include "ocnext/chained_fixups.h"
#include "ocnext/fixup_transaction.h"
#ifdef __cplusplus
extern "C" {
#endif
#define OCNEXT_FIXUP_INDEX_ABI 1u
#define OCNEXT_FIXUP_INDEX_WORKSPACE_BYTES 32768u
#define OCNEXT_FIXUP_INDEX_MAX_READ 128u
#define OCNEXT_FIXUP_INDEX_MAX_INNERS 1024u
#define OCNEXT_FIXUP_INDEX_MAX_COMMANDS 65536u
#define OCNEXT_FIXUP_INDEX_MAX_SECTIONS 8192u
#define OCNEXT_FIXUP_INDEX_MAX_CLASS_WORK UINT64_C(1000000000)
#define OCNEXT_FIXUP_INDEX_READONLY 1u
#define OCNEXT_FIXUP_INDEX_SYNTHETIC 2u
#define OCNEXT_FIXUP_INDEX_LIVE 1u
#define OCNEXT_FIXUP_INDEX_CLOSED 2u
#define OCNEXT_FIXUP_INDEX_METADATA 1u
#define OCNEXT_FIXUP_INDEX_EXECUTE 2u
#define OCNEXT_FIXUP_INDEX_DATA 4u
#define OCNEXT_FIXUP_INDEX_UNKNOWN 8u
#define OCNEXT_FIXUP_INDEX_READABLE 16u
#define OCNEXT_FIXUP_INDEX_WRITABLE 32u
#define OCNEXT_FIXUP_INDEX_INNER 64u
#define OCNEXT_FIXUP_INDEX_CROSS_PAGE 128u
/* Native caller-owned immutable source/index lifetimes, not wire, authenticated
 * authority, native pin/mprotect, Apple key/modifier/slide or guest mappings.
 * Index ordinals refer to strictly ascending file offsets. walk_ordinal retains
 * original complete scanner traversal order. Classification is conservative:
 * every root/inner header, complete load command, segment and section is checked;
 * metadata/execute/unknown/conflicting overlap never qualifies writable data.
 * A READONLY index cannot be adapted into a synthetic transaction. SYNTHETIC
 * provenance must be explicitly issued by a trusted native caller; bytes/SHA
 * alone cannot identify or authorize Apple software. All spans stay serialized,
 * stable and disjoint. Scratch/workspace may change on error, outputs do not. */
struct ocnext_fixup_index_entry {
    struct ocnext_chained_slot slot;
    uint32_t classification;
    uint8_t root_initprot, inner_initprot;
    uint16_t inner_owner; /*0=no inner,1..1024=entry+1,65535=conflict*/
    uint64_t walk_ordinal;
}; /*64*/
struct ocnext_fixup_index_segment {
    struct ocnext_chained_segment segment;
    uint32_t maxprot,initprot,page_bytes,pointer_format;
}; /*64*/
struct ocnext_fixup_index_storage {
    struct ocnext_fixup_index_entry *entries;
    uint64_t capacity;
    struct ocnext_fixup_index_segment *segments; /*exactly32 objects*/
    uint64_t reserved;
}; /*32*/
struct ocnext_fixup_index_request {
    uint64_t owner_id,source_id,source_epoch,class_work_quota;
    uint32_t slot_quota,abi_version,profile,reserved;
}; /*48*/
struct ocnext_fixup_index_state {
    const uint8_t *source;
    const struct ocnext_fixup_index_entry *entries;
    const struct ocnext_fixup_index_segment *segments;
    uint64_t image_bytes,count,capacity,source_id,source_epoch,owner_id,index_epoch;
    uint8_t source_sha256[32],entries_sha256[32],segments_sha256[32];
    uint32_t abi_version,profile,lifecycle,reserved;
    uint64_t classification_counts[8]; /*individual flag counts, not exclusive*/
}; /*256; trusted zero new lifetime only. CLOSED never reopens.*/
struct ocnext_fixup_index_read_request {
    uint64_t owner_id,source_id,source_epoch,index_epoch,first_ordinal;
    uint32_t count,abi_version;
}; /*48; count1..128, full requested slice must exist*/
struct ocnext_fixup_index_lease {
    const struct ocnext_fixup_index_state *state;
    const uint8_t *source;
    const struct ocnext_fixup_index_entry *entries;
    const struct ocnext_fixup_index_segment *segments;
    uint64_t owner_id,source_id,source_epoch,index_epoch;
    uint64_t image_bytes,count,capacity;
    uint32_t abi_version,lifecycle;
    uint64_t reserved[2];
}; /*112; open verifies whole source/index SHA, close is terminal.*/
struct ocnext_fixup_index_resolution {
    uint64_t owner_id,source_id,source_epoch,index_epoch,key_generation,ordinal;
    uint64_t resolved_pointer,modifier;
    struct ocnext_pac_pointer_config geometry;
    uint32_t abi_version,flags,key_index,reserved;
}; /*96; explicit flags use transaction AUTH/POINTER_KNOWN/MODIFIER_KNOWN.
       Encoded diversity/target/cache are never a resolution authority.*/
struct ocnext_fixup_index_adapter_result {
    uint64_t owner_id,index_epoch,key_generation;
    uint32_t count,abi_version;
}; /*32*/
union ocnext_fixup_index_workspace {
    max_align_t alignment;
    uint8_t bytes[OCNEXT_FIXUP_INDEX_WORKSPACE_BYTES];
};
enum ocnext_fixup_index_code {
    OCNEXT_FIXUP_INDEX_OK=0, OCNEXT_FIXUP_INDEX_ARGUMENT=1,
    OCNEXT_FIXUP_INDEX_STALE=2, OCNEXT_FIXUP_INDEX_DIGEST=3,
    OCNEXT_FIXUP_INDEX_STRUCTURE=4, OCNEXT_FIXUP_INDEX_QUOTA=5,
    OCNEXT_FIXUP_INDEX_UNSUPPORTED=6, OCNEXT_FIXUP_INDEX_RESOLUTION=7,
    OCNEXT_FIXUP_INDEX_OVERFLOW=8
};
size_t ocnext_fixup_index_scratch_bytes(uint64_t image_bytes,uint32_t slot_quota);
enum ocnext_fixup_index_code ocnext_fixup_index_build(
    const struct ocnext_chained_snapshot *,const struct ocnext_fixup_index_request *,
    const struct ocnext_fixup_index_storage *,struct ocnext_fixup_index_state *,
    union ocnext_fixup_index_workspace *,void *,size_t);
/* Whole source + occupied entries + all32 segment SHA are checked. Inputs are
 * unchanged on every failure; no repeated chain walk or implicit signing. */
enum ocnext_fixup_index_code ocnext_fixup_index_read(
    const struct ocnext_chained_snapshot *,const struct ocnext_fixup_index_state *,
    const struct ocnext_fixup_index_read_request *,
    struct ocnext_fixup_index_entry *output);
enum ocnext_fixup_index_code ocnext_fixup_index_invalidate(
    struct ocnext_fixup_index_state *,uint64_t owner_id,uint64_t expected_epoch);
enum ocnext_fixup_index_code ocnext_fixup_index_open(
    const struct ocnext_chained_snapshot *,const struct ocnext_fixup_index_state *,
    const struct ocnext_fixup_index_read_request *,struct ocnext_fixup_index_lease *);
/* Fast reads do not rehash full spans. Caller freezes source/index/state and
 * the native lease during its live lifetime and serializes every operation.
 * Bindings + selected original words/geometry are checked. Changed nonselected
 * bytes are outside this explicit immutable contract, not detected or claimed.
 * No concurrent writer, native faults/MMIO/DMA/adversarial callback allowed. */
enum ocnext_fixup_index_code ocnext_fixup_index_read_lease(
    const struct ocnext_fixup_index_lease *,const struct ocnext_fixup_index_read_request *,
    struct ocnext_fixup_index_entry *output);
enum ocnext_fixup_index_code ocnext_fixup_index_close(struct ocnext_fixup_index_lease *);
/* Strict read/full SHA then explicit field adaptation, no callback, keys from
 * encoded facts, image writes or signing. All resolution bindings and geometry
 * must equal separately supplied synthetic capability. Output candidate[count],
 * segment[32] and result are published only after every item passes. */
enum ocnext_fixup_index_code ocnext_fixup_index_adapt(
    const struct ocnext_chained_snapshot *,const struct ocnext_fixup_index_state *,
    const struct ocnext_fixup_index_read_request *,
    const struct ocnext_fixup_index_resolution *,const struct ocnext_fixup_capability *,
    union ocnext_fixup_index_workspace *,struct ocnext_fixup_candidate *,
    struct ocnext_fixup_segment *,struct ocnext_fixup_index_adapter_result *);
#ifdef __cplusplus
}
#endif
#endif
