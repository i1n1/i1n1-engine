#ifndef OCNEXT_ORDERING_H
#define OCNEXT_ORDERING_H
#include "ocnext/a64.h"
#ifdef __cplusplus
extern "C" {
#endif
#define OCNEXT_ORDERING_ABI_VERSION 1u
enum ocnext_ordering_profile {
    OCNEXT_ORDERING_SERIAL_RAM = 1
};
/* Caller certifies: one serialized guest CPU, synchronous coherent Normal RAM
 * reads/atomic writes, fresh translation and instruction fetch after each
 * dispatch, no JIT/prefetch cache. No other guest CPU, MMIO, DMA, devices,
 * asynchronous accesses or cache/TLB maintenance may use this capability.
 * Host seq_cst fences fulfill this restricted provider contract; event counts
 * are evidence of provider completion, not architectural SMP validation. */
struct ocnext_ordering {
    uint64_t events, host_fences, dmb, dsb, isb, instruction_epoch;
    struct ocnext_a64_sync_request last;
    uint32_t abi_version, profile;
};
int ocnext_ordering_init(struct ocnext_ordering *, enum ocnext_ordering_profile);
/* Exact request/opcode validation and overflow preflight before any fence or
 * publication. COMPLETED commits one actual host fence and an event. ISB also
 * commits an instruction-view epoch: subsequent dispatch must fetch afresh.
 * Request/state may alias; request is snapshotted before successful mutation.
 * No libc/allocation dependency, callback-compatible. */
enum ocnext_a64_sync_result ocnext_ordering_sync(void *,
                                const struct ocnext_a64_sync_request *);
#ifdef __cplusplus
}
#endif
#endif
