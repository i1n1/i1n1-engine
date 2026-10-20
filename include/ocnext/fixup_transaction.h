#ifndef OCNEXT_FIXUP_TRANSACTION_H
#define OCNEXT_FIXUP_TRANSACTION_H

#include <stddef.h>
#include <stdint.h>
#include "ocnext/pac_pointer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OCNEXT_FIXUP_TRANSACTION_ABI 1u
#define OCNEXT_FIXUP_MAX_IMAGE_BYTES (128u*1024u*1024u)
#define OCNEXT_FIXUP_MAX_SEGMENTS 32u
#define OCNEXT_FIXUP_MAX_CANDIDATES 128u
#define OCNEXT_FIXUP_MAX_CONTEXT 1024u
#define OCNEXT_FIXUP_WORKSPACE_BYTES 16384u
#define OCNEXT_FIXUP_SYNTHETIC_FORMAT8 1u
#define OCNEXT_FIXUP_CAP_SYNTHETIC_SIGNER 1u
#define OCNEXT_FIXUP_CAP_GEOMETRY_KNOWN 2u
#define OCNEXT_FIXUP_AUTHENTICATED 1u
#define OCNEXT_FIXUP_POINTER_KNOWN 2u
#define OCNEXT_FIXUP_MODIFIER_KNOWN 4u

enum ocnext_fixup_code {
    OCNEXT_FIXUP_OK=0, OCNEXT_FIXUP_ARGUMENT=1, OCNEXT_FIXUP_UNSUPPORTED=2,
    OCNEXT_FIXUP_STALE=3, OCNEXT_FIXUP_DIGEST=4, OCNEXT_FIXUP_BOUNDS=5,
    OCNEXT_FIXUP_METADATA=6, OCNEXT_FIXUP_SIGNER_FAILED=7,
    OCNEXT_FIXUP_OVERFLOW=8
};

/* Native ABI1/40B, explicitly adapted from immutable scanner facts. Relative
 * VM coordinates are not native pointers or physical addresses. This module
 * does not parse Mach-O/start tables or prove chain membership. The caller
 * supplies scanner-validated metadata bound to the original image digest.
 * Both file and VM segments must be disjoint; BSS is never a patch destination.
 */
struct ocnext_fixup_segment {
    uint64_t file_offset,file_bytes,image_vm_offset,vm_bytes;
    uint32_t page_bytes,pointer_format;
};

/* Native ABI1/64B, strictly ascending nonoverlapping file offsets. original_word
 * is the exact LE64 format8 source value, not a signed pointer. Explicit known
 * resolved_pointer/modifier are supplied by the synthetic issuer; encoded target,
 * cache level, diversity and address-diversity are never used to infer them.
 * AUTH requires flags7 and key_index equal the encoded selector0..3. Unauthenticated
 * rebase requires flags2, key_index0 and modifier0. All reserved fields are zero.
 */
struct ocnext_fixup_candidate {
    uint64_t file_offset,original_word,resolved_pointer,modifier,image_vm_offset;
    uint32_t segment_index,flags,key_index,reserved;
    uint64_t reserved64;
};

/* Native ABI1/48B. original and working are complete, disjoint ordinary RAM
 * objects with the same declared file-image length; neither is MMIO/DMA. The
 * immutable metadata objects and all other API objects must be disjoint from
 * both image spans. Only SYNTHETIC_FORMAT8 is supported; no Apple loader profile.
 */
struct ocnext_fixup_image {
    const uint8_t *original;
    uint8_t *working;
    size_t bytes;
    const struct ocnext_fixup_segment *segments;
    uint32_t segment_count,abi_version,profile,reserved;
};

struct ocnext_fixup_request {
    uint32_t abi_version,candidate_count;
    uint64_t owner_id,expected_epoch,expected_key_generation;
};

/* Native ABI1/160B. Explicit native capability, not raw-wire authentication.
 * Owner/generation must equal the canonical bank and current request. Keys and
 * geometry remain immutable. Native bank ABI1 and CPU-owned bank are different
 * objects; no reinterpretation, key provisioning, host registers or Apple HVC.
 */
struct ocnext_fixup_capability {
    uint32_t abi_version,profile,flags,reserved;
    uint64_t owner_id,key_generation;
    struct ocnext_pac_key_bank bank;
    struct ocnext_pac_pointer_config geometry;
};

/* Native ABI1/112B. Trusted new all-zero lifetime only; init rejects nonzero
 * storage. Epoch starts1, commits0, and both images must initially match the
 * independently trusted expected SHA. Epoch increments once per logical commit.
 * IDs/digests do not authenticate an untrusted issuer. Do not clear live storage
 * to reuse authority. No implicit replay or re-signing of already modified slots.
 */
struct ocnext_fixup_state {
    uint64_t owner_id,epoch,commits,image_bytes;
    uint8_t original_sha256[32],working_sha256[32];
    uint32_t abi_version,profile,reserved[2];
};

struct ocnext_fixup_sign_snapshot {
    struct ocnext_fixup_capability capability;
    struct ocnext_fixup_candidate candidate;
    struct ocnext_fixup_request request;
    uint32_t candidate_index,reserved[3];
};

/* Native ABI1/48B. Success is exact completed1, reserved0, exact bindings and
 * an independently recomputed public-QARMA5 signed pointer. This result never
 * contains an image pointer, key after-image or provider-issued authority.
 */
struct ocnext_fixup_prepared {
    uint64_t pointer,owner_id,epoch,key_generation;
    uint32_t candidate_index,abi_version,completed,reserved;
};
typedef enum ocnext_fixup_code (*ocnext_fixup_prepare)(
    const void *context,size_t context_bytes,
    const struct ocnext_fixup_sign_snapshot *,struct ocnext_fixup_prepared *);
struct ocnext_fixup_provider {
    uint32_t abi_version,bytes;
    ocnext_fixup_prepare prepare;
    const void *context;
    size_t context_bytes;
};

/* Native ABI1/80B; no output is published on failure. */
struct ocnext_fixup_result {
    uint64_t owner_id,before_epoch,after_epoch,key_generation;
    uint8_t working_sha256[32];
    uint32_t abi_version,patch_count,committed_bytes,reserved;
};
union ocnext_fixup_workspace {
    max_align_t alignment;
    uint8_t bytes[OCNEXT_FIXUP_WORKSPACE_BYTES];
};

/* Stable valid aligned native objects are required; forged pointers are outside
 * the contract. Every whole span, alias, metadata value, bound, digest and epoch
 * is checked before callbacks or image publication. Workspace may change on
 * failure. State/image/result and all immutable inputs remain byte-identical.
 * Providers receive only bounded private snapshots/context and one result;
 * mutation of const borrowed copies or wrong results is rejected. Context must
 * require alignment <=alignof(max_align_t). Native callbacks are trusted not
 * to use exogenous aliases/global addresses, recurse, retain borrowed pointers
 * or mutate external objects; C cannot sandbox arbitrary native code. The
 * all-or-none guarantee applies to this serialized native contract, not MMIO,
 * concurrent mutation, memory faults, process crashes or hostile native code.
 * A prospective digest and every signed patch are complete before one logical
 * publication; no callback/hash/fallible operation follows the first image write.
 * Publication is not a hardware multiword atomic store. No Apple input is signed
 * by this profile and no production loader/macOS/Intel/GPU gate is issued.
 */
enum ocnext_fixup_code ocnext_fixup_init(
    struct ocnext_fixup_state *,uint64_t owner_id,
    const uint8_t *original,uint8_t *working,size_t bytes,
    const uint8_t expected_sha256[32]);
enum ocnext_fixup_code ocnext_fixup_execute(
    struct ocnext_fixup_state *,const struct ocnext_fixup_image *,
    const struct ocnext_fixup_candidate *,const struct ocnext_fixup_request *,
    const struct ocnext_fixup_capability *,const struct ocnext_fixup_provider *,
    union ocnext_fixup_workspace *,struct ocnext_fixup_result *);
enum ocnext_fixup_code ocnext_fixup_prepare_synthetic(
    const void *,size_t,const struct ocnext_fixup_sign_snapshot *,
    struct ocnext_fixup_prepared *);

#ifdef __cplusplus
}
#endif
#endif
