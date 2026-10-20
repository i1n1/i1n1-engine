#ifndef OCNEXT_BACKEND_TCG_H
#define OCNEXT_BACKEND_TCG_H
/* Native direct-emission lifecycle ABI1. Independent of ARM CPU, ONXT/legacy proxy,
 * ELF, FX-bank and Apple contracts. This library never calls generated code.
 * Actual EFI authority belongs to the separately provisioned Root provider.
 */
#include "ocnext/backend_heap.h"
#define OCNEXT_BACKEND_TCG_ABI 1u
#define OCNEXT_BACKEND_TCG_STORAGE_BYTES 1024u
#define OCNEXT_BACKEND_TCG_STORAGE_ALIGNMENT 16u
#define OCNEXT_BACKEND_TCG_CODE_BYTES UINT64_C(4194304)
#define OCNEXT_BACKEND_TCG_MAX_METADATA_BYTES UINT64_C(4096)
#define OCNEXT_BACKEND_TCG_MAX_FRAMES 4u
#define OCNEXT_BACKEND_TCG_JUMP_BYTES UINT64_C(256)
#if defined(__x86_64__) || defined(_M_X64)
#define OCNEXT_TCG_MSABI __attribute__((ms_abi))
#else
#define OCNEXT_TCG_MSABI
#endif

enum ocnext_backend_tcg_code {
    OCNEXT_TCG_OK=0, OCNEXT_TCG_ARGUMENT=1, OCNEXT_TCG_STATE=2,
    OCNEXT_TCG_STALE=3, OCNEXT_TCG_BUSY=4, OCNEXT_TCG_QUOTA=5,
    OCNEXT_TCG_PROVIDER=6, OCNEXT_TCG_QUARANTINED=7,
    OCNEXT_TCG_BOUNDS=8, OCNEXT_TCG_BINDING=9, OCNEXT_TCG_ALIAS=10
};
enum ocnext_backend_tcg_phase {
    OCNEXT_TCG_PREPARED=1, OCNEXT_TCG_IDLE=2, OCNEXT_TCG_WRITING=3,
    OCNEXT_TCG_PUBLISHED=4, OCNEXT_TCG_CLOSED=5,
    OCNEXT_TCG_TRANSITION=6, OCNEXT_TCG_QUARANTINE=7
};
enum ocnext_backend_tcg_permission {
    OCNEXT_TCG_RW_NX=1, OCNEXT_TCG_RO_NX=2,
    OCNEXT_TCG_RX_PREFIX=3 /* page-rounded prefix RX, remaining pages RO-NX */
};
/* Effectful provider callbacks:0 completed,1 certified no effect,2 UNKNOWN.
 * Any other value is UNKNOWN. verify/lookup instead use EXACT1 true/0 false.
 * A failed verification does not by itself establish a safe hardware state.
 */
enum ocnext_backend_tcg_provider_result {
    OCNEXT_TCG_PROVIDER_COMPLETED=0,
    OCNEXT_TCG_PROVIDER_NO_EFFECT=1,
    OCNEXT_TCG_PROVIDER_UNKNOWN=2
};
enum ocnext_backend_tcg_operation {
    OCNEXT_TCG_BIND=1, OCNEXT_TCG_BEGIN=2,
    OCNEXT_TCG_ALLOC_METADATA=3, OCNEXT_TCG_COMMIT=4,
    OCNEXT_TCG_FRAME_REGISTER=5, OCNEXT_TCG_ENTER=6,
    OCNEXT_TCG_LEAVE_NORMAL=7, OCNEXT_TCG_MARK_UNWIND=8,
    OCNEXT_TCG_LANDED=9, OCNEXT_TCG_METADATA_DONE=10,
    OCNEXT_TCG_DETACH=11, OCNEXT_TCG_RETIRE=12,
    OCNEXT_TCG_ABORT_WRITE=13, OCNEXT_TCG_FRAME_EXIT=14,
    OCNEXT_TCG_CLOSE=15
};
#define OCNEXT_TCG_FLAG_DIGEST_KNOWN UINT32_C(1)
#define OCNEXT_TCG_FLAG_WRITE_LEASE UINT32_C(2)
#define OCNEXT_TCG_FLAG_DIRECTORY UINT32_C(4)
#define OCNEXT_TCG_FLAG_METADATA_KNOWN UINT32_C(8)
#define OCNEXT_TCG_FLAG_DETACHED UINT32_C(16)
#define OCNEXT_TCG_FLAG_UNWIND_PENDING UINT32_C(32)
/* Result flags describe this library's last completed state, not fresh physical
 * authority. ENTER independently verifies current RX and digest. observe is a
 * diagnostic snapshot only and cannot issue an execution lease.
 */
struct ocnext_backend_tcg_config {
    uint32_t abi_version,bytes,flags,reserved0;
    uint64_t owner_id,session_id,generation;
    uint8_t *code_base;
    uint64_t code_bytes,reserved1;
}; /*64B; exact4MiB page-aligned caller-owned backing */
struct ocnext_backend_tcg_provider {
    uint32_t abi_version,bytes;
    void *context;
    int (OCNEXT_TCG_MSABI *verify)(void *,uint32_t,uint64_t);
    int (OCNEXT_TCG_MSABI *transition)(void *,uint32_t,uint64_t);
    int (OCNEXT_TCG_MSABI *lookup)(void *,const void *,struct ocnext_backend_heap_allocation *);
    int (OCNEXT_TCG_MSABI *allocate)(void *,uint64_t,uint64_t,struct ocnext_backend_heap_allocation *);
    int (OCNEXT_TCG_MSABI *release)(void *,const struct ocnext_backend_heap_allocation *);
    uint64_t context_bytes,reserved[4];
}; /*96B; stable trusted callbacks/context, separately Root-allowlisted */

/* Header64 + operation payload160 + reserved32. All unused payload/reserved
 * bytes must0. Every successful mutating operation consumes next_sequence;
 * prepare starts sequence1/epoch0. BIND is first, once, before UC_INIT.
 * BEGIN increments the nonwrapping code epoch; other operations bind current
 * epoch. FRAME cookies are independent of code epochs and survive LongJump.
 */
struct ocnext_backend_tcg_request {
    uint32_t abi_version,bytes,operation,flags;
    uint64_t owner_id,session_id,generation,code_epoch,sequence,reserved0;
    union {
        struct { uint64_t native_engine,native_engine_bytes,reserved[18]; } bind;
        struct { uint64_t requested_bytes,reserved[19]; } begin;
        struct { uint64_t bytes,alignment,reserved[18]; } allocation;
        struct {
            uint64_t prefix_bytes,prologue_offset,prologue_bytes,epilogue_offset;
            uint64_t tb_offset,tb_bytes,search_offset,search_bytes;
            uint64_t reserved[12];
        } commit;
        struct {
            uint64_t address,bytes,frame_cookie,dispatch_cookie,reason;
            uint64_t reserved[15];
        } frame;
        struct { uint64_t prologue_offset,tb_offset,frame_cookie,reserved[17]; } enter;
        struct { uint64_t frame_cookie,dispatch_cookie,raw_return,reserved[17]; } leave;
        struct { uint64_t frame_cookie,metadata_cookie,reserved[18]; } metadata;
        uint64_t zero[20];
    } payload;
    uint64_t reserved[4];
};
/* Payload selection (all other fields/bytes zero):
 * BIND bind; BEGIN begin.requested_bytes=4MiB; ALLOC_METADATA allocation;
 * COMMIT commit; FRAME_REGISTER frame.address/bytes; ENTER enter;
 * LEAVE_NORMAL leave; MARK_UNWIND frame.frame_cookie/dispatch_cookie/reason;
 * LANDED same three fields, reason is actual nonzero positive int32 jump return;
 * METADATA_DONE metadata; FRAME_EXIT frame.frame_cookie only;
 * DETACH/RETIRE/ABORT_WRITE/CLOSE entire payload zero.
 * MARK_UNWIND reason is the actual positive-int32 LongJump argument (1 in the
 * pinned source), not a guest exception/error. LANDED must equal this value.
 * Frame address is8B aligned and bytes exactly256 for this selected jump ABI.
 * LEAVE_NORMAL raw_return is exactly0 or (current metadata native address|3).
 * Reserved tag2, other tags/pointers mean post-call UNKNOWN/quarantine.
 */
struct ocnext_backend_tcg_result {
    uint32_t abi_version,bytes,phase,flags;
    uint64_t owner_id,session_id,generation,code_epoch,next_sequence;
    uint64_t code_base,code_bytes,prefix_bytes,prologue_offset,tb_offset;
    uint64_t metadata_native,metadata_bytes,metadata_serial;
    uint64_t frame_cookie,dispatch_cookie,metadata_cookie,frame_depth,native_inflight,metadata_pins;
    uint64_t pte_epoch,local_invalidations;
    uint64_t begins,allocations,commits,enters,normal_returns,landings,detaches,retires,aborts,closes,metadata_releases;
    uint8_t code_sha256[32];
    uint64_t reserved[2];
}; /*320B/alignment8; no raw FX, instruction stream or memory dump */

/* prepare is pure and requires zero1024B/alignment16 storage. Config/provider/
 * storage/code/context spans are complete, stable and pairwise disjoint. Provider
 * context_bytes is16..65536 and context is8B aligned. Config/provider original
 * spans remain retained and excluded from future client outputs. Provider
 * context backing/callees are caller-owned stable trusted objects. No callback
 * or physical authority is issued by prepare. Code is exactly4MiB/4KiB aligned.
 * execute requires request256/result320 disjoint from each other and all
 * service/config/provider/code/UC/metadata objects. The Root frontend validates
 * actual native accessibility and permits retained module RW client buffers.
 * Ordinary failures preserve result and pre-effect state. UNKNOWN effect makes
 * storage QUARANTINE, retains logical references and never authorizes replay.
 * After UNKNOWN release actual backing might already be freed: neither this
 * library nor diagnostics may dereference or retry that metadata reference.
 */
enum ocnext_backend_tcg_code ocnext_backend_tcg_prepare(void *,size_t,
    const struct ocnext_backend_tcg_config *,const struct ocnext_backend_tcg_provider *);
enum ocnext_backend_tcg_code ocnext_backend_tcg_execute(void *,
    const struct ocnext_backend_tcg_request *,struct ocnext_backend_tcg_result *);
enum ocnext_backend_tcg_code ocnext_backend_tcg_observe(const void *,
    struct ocnext_backend_tcg_result *);

_Static_assert(sizeof(struct ocnext_backend_tcg_config)==64,"TCG config64");
_Static_assert(sizeof(struct ocnext_backend_tcg_provider)==96,"TCG provider96");
_Static_assert(sizeof(struct ocnext_backend_tcg_request)==256,"TCG request256");
_Static_assert(offsetof(struct ocnext_backend_tcg_request,payload)==64,"TCG payload64");
_Static_assert(sizeof(struct ocnext_backend_tcg_result)==320,"TCG result320");
#endif
