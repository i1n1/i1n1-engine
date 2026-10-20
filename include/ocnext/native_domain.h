#ifndef OCNEXT_NATIVE_DOMAIN_H
#define OCNEXT_NATIVE_DOMAIN_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define OCNEXT_NATIVE_DOMAIN_ABI_VERSION 1u
#define OCNEXT_ND_MAX_RESOURCES 32u
#define OCNEXT_ND_MAX_QUEUES 8u
#define OCNEXT_ND_MAX_SUBMISSIONS 32u
#define OCNEXT_ND_MAX_REFERENCES 8u
#define OCNEXT_ND_PAGE_BYTES UINT64_C(4096)
#define OCNEXT_ND_MAX_RESOURCE_BYTES UINT64_C(1099511627776)
#define OCNEXT_ND_READ 1u
#define OCNEXT_ND_WRITE 2u
enum ocnext_nd_namespace { OCNEXT_ND_GUEST_VA=1, OCNEXT_ND_GUEST_PA=2,
    OCNEXT_ND_NATIVE_VA=3, OCNEXT_ND_NATIVE_PA=4, OCNEXT_ND_IOVA=5,
    OCNEXT_ND_NATIVE_GUEST_PA=6, OCNEXT_ND_GPU_VA=7 };
enum ocnext_nd_kind { OCNEXT_ND_BUFFER=1, OCNEXT_ND_MAPPING=2,
    OCNEXT_ND_QUEUE=3, OCNEXT_ND_SUBMISSION=4 };
enum ocnext_nd_state { OCNEXT_ND_ACTIVE=1, OCNEXT_ND_QUIESCING=2,
    OCNEXT_ND_QUARANTINED=3, OCNEXT_ND_QUIESCED=4, OCNEXT_ND_CLOSED=5 };
enum ocnext_nd_resource_state { OCNEXT_ND_LIVE=1, OCNEXT_ND_REVOKED=2 };
enum ocnext_nd_submission_state { OCNEXT_ND_PENDING=1, OCNEXT_ND_FINISHED=2,
    OCNEXT_ND_FINISHED_FAILED=3, OCNEXT_ND_UNKNOWN=4, OCNEXT_ND_CANCELLED=5 };
enum ocnext_nd_evidence_scope { OCNEXT_ND_OFFLINE_POLICY_ONLY=1 };
enum ocnext_nd_outcome { OCNEXT_ND_PROVEN_FINISHED=1,
    OCNEXT_ND_PROVIDER_FAILED=2, OCNEXT_ND_PROVIDER_UNKNOWN=3 };
enum ocnext_nd_op { OCNEXT_ND_DECLARE_BUFFER=1, OCNEXT_ND_DECLARE_MAPPING=2,
    OCNEXT_ND_DECLARE_QUEUE=3, OCNEXT_ND_REVOKE=4, OCNEXT_ND_RELEASE=5,
    OCNEXT_ND_SUBMIT=6, OCNEXT_ND_COMPLETE=7, OCNEXT_ND_BEGIN_QUIESCE=8,
    OCNEXT_ND_QUIESCE_RESULT=9, OCNEXT_ND_RESET=10, OCNEXT_ND_CLOSE=11 };
enum ocnext_nd_result { OCNEXT_ND_OK=0, OCNEXT_ND_ARGUMENT=1,
    OCNEXT_ND_AUTHORITY=2, OCNEXT_ND_REPLAY=3, OCNEXT_ND_STALE=4,
    OCNEXT_ND_BAD_STATE=5, OCNEXT_ND_BAD_HANDLE=6, OCNEXT_ND_RANGE=7,
    OCNEXT_ND_PERMISSION=8, OCNEXT_ND_QUOTA=9, OCNEXT_ND_BUSY=10,
    OCNEXT_ND_EXHAUSTED=11, OCNEXT_ND_BAD_EVIDENCE=12,
    OCNEXT_ND_UNSUPPORTED=13, OCNEXT_ND_CORRUPT=14 };
/* Native metadata ABI only: NEVER memcpy these structures to ONXT or UART.
 * Every address is a typed integer. This policy does not dereference it. */
struct ocnext_nd_handle { uint64_t id,domain;uint32_t generation,kind;uint64_t reserved; };
struct ocnext_nd_ticket { uint64_t owner,session,sequence;uint32_t generation,abi_version;
    uint64_t reserved[2]; };
struct ocnext_nd_span { uint64_t base,bytes;uint32_t namespace_id,permissions; };
struct ocnext_nd_reference { struct ocnext_nd_handle handle;uint64_t offset,bytes;
    uint32_t permissions,reserved; };
/* Only a trusted native provider supplies this evidence. Identity, generation,
 * scope and exact submission ID+generation are checked; checksum/guest input
 * cannot establish provenance. OFFLINE scope never certifies DMA stop/unpin.
 * COMPLETE FAILED means a proven finished operation with a failed result.
 * QUIESCE FAILED means no safe-stop evidence, so references remain retained. */
struct ocnext_nd_evidence { uint64_t issuer,domain,owner,session,submission_id;
    uint32_t generation,scope,outcome,submission_generation;uint64_t reserved; };
struct ocnext_nd_config { uint64_t domain,owner,session,provider;
    uint64_t buffer_byte_quota,iova_byte_quota,initial_sequence,initial_handle_id;
    uint32_t generation,max_resources,max_queues,max_submissions;
    uint32_t address_bits,profile,abi_version,reserved; };
/* All inactive fields MUST be zero. A command and all native input/output/state
 * spans must be naturally aligned, stable, serialized and disjoint. Misaligned
 * typed native pointers are rejected before any typed access. No callbacks or allocation. */
struct ocnext_nd_command { uint32_t abi_version,op;struct ocnext_nd_handle target;
    struct ocnext_nd_span span;struct ocnext_nd_handle parent;uint64_t parent_offset;
    struct ocnext_nd_reference references[OCNEXT_ND_MAX_REFERENCES];
    struct ocnext_nd_evidence evidence;uint32_t reference_count,reserved; };
struct ocnext_nd_reply { uint32_t result,state,generation,reserved;
    struct ocnext_nd_handle handle;uint64_t next_sequence,events; };
struct ocnext_nd_stats { uint32_t generation,state,resources,queues;
    uint32_t submissions,pending,mappings,buffers;
    uint64_t buffer_bytes,iova_bytes,events,next_sequence; };
struct ocnext_nd_resource_info { struct ocnext_nd_handle handle;struct ocnext_nd_span span;
    struct ocnext_nd_handle parent;uint64_t parent_offset;
    uint32_t in_flight,children,state,reserved; };
struct ocnext_nd_submission_info { struct ocnext_nd_handle handle,queue;
    uint32_t reference_count,state;uint64_t reserved; };
struct ocnext_native_domain;
size_t ocnext_native_domain_storage_size(void);
size_t ocnext_native_domain_storage_alignment(void);
struct ocnext_nd_config ocnext_native_domain_default_config(void);
/* Storage must be caller-owned, aligned, exactly zero-initialized and new for
 * this externally unique domain identity. Active/closed instances cannot be
 * reinitialized. Config may not alias storage. Keep storage alive until CLOSED.
 * Declared PA/IOVA extents are only ledger leases; no pages are pinned/mapped.
 * Cross-instance physical partitioning is a separate trusted issuer obligation. */
struct ocnext_native_domain *ocnext_native_domain_init(void *,size_t,
    const struct ocnext_nd_config *);
enum ocnext_nd_result ocnext_native_domain_validate_span(const struct ocnext_nd_span *,unsigned address_bits);
/* Exact next ticket; error leaves storage and reply unchanged. Accepted events
 * consume one sequence. RESET needs QUIESCED, clears ledger, increments generation
 * and restarts sequence1; opaque IDs never repeat. Unknown evidence quarantines
 * and retains references. SAFE offline quiescence cancels policy references only.
 * No retry, backend call, native page free, GPU/DMA/fence or wire capability. */
enum ocnext_nd_result ocnext_native_domain_apply(struct ocnext_native_domain *,
    const struct ocnext_nd_ticket *,const struct ocnext_nd_command *,struct ocnext_nd_reply *);
/* Queries validate the same owner/session/generation/next sequence, without
 * consuming it. Failure leaves output unchanged. Outputs may not alias inputs
 * or any byte of policy storage. Returned handles remain opaque metadata. */
enum ocnext_nd_result ocnext_native_domain_stats(const struct ocnext_native_domain *,
    const struct ocnext_nd_ticket *,struct ocnext_nd_stats *);
enum ocnext_nd_result ocnext_native_domain_resource(const struct ocnext_native_domain *,
    const struct ocnext_nd_ticket *,const struct ocnext_nd_handle *,struct ocnext_nd_resource_info *);
enum ocnext_nd_result ocnext_native_domain_submission(const struct ocnext_native_domain *,
    const struct ocnext_nd_ticket *,const struct ocnext_nd_handle *,struct ocnext_nd_submission_info *);
_Static_assert(sizeof(struct ocnext_nd_handle)==32,"native handle ABI drift");
_Static_assert(sizeof(struct ocnext_nd_ticket)==48,"native ticket ABI drift");
_Static_assert(sizeof(struct ocnext_nd_span)==24,"native address ABI drift");
_Static_assert(sizeof(struct ocnext_nd_reference)==56,"native reference ABI drift");
_Static_assert(sizeof(struct ocnext_nd_evidence)==64,"native evidence ABI drift");
_Static_assert(sizeof(struct ocnext_nd_config)==96,"native config ABI drift");
_Static_assert(sizeof(struct ocnext_nd_command)==624,"native command ABI drift");
_Static_assert(offsetof(struct ocnext_nd_command,evidence)==552,"native evidence offset drift");
_Static_assert(sizeof(struct ocnext_nd_reply)==64,"native reply ABI drift");
_Static_assert(sizeof(struct ocnext_nd_stats)==64,"native stats ABI drift");
_Static_assert(sizeof(struct ocnext_nd_resource_info)==112,"native resource view ABI drift");
_Static_assert(sizeof(struct ocnext_nd_submission_info)==80,"native submission view ABI drift");
#ifdef __cplusplus
}
#endif
#endif
