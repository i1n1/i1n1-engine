#ifndef OCNEXT_BACKEND_HEAP_H
#define OCNEXT_BACKEND_HEAP_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Native-only retained RAM allocator. No guest address, wire handle, DMA,
 * device ownership or executable-memory authority is issued here. */
#define OCNEXT_BACKEND_HEAP_ABI_VERSION 1u
#define OCNEXT_BACKEND_HEAP_STORAGE_BYTES 256u
#define OCNEXT_BACKEND_HEAP_STORAGE_ALIGNMENT 16u
#define OCNEXT_BACKEND_HEAP_ENTRY_BYTES 32u
#define OCNEXT_BACKEND_HEAP_MAX_ENTRIES 65536u
#define OCNEXT_BACKEND_HEAP_MIN_POOL UINT64_C(65536)
#define OCNEXT_BACKEND_HEAP_MAX_POOL UINT64_C(1073741824)
#define OCNEXT_BACKEND_HEAP_MIN_ALIGNMENT UINT64_C(16)
#define OCNEXT_BACKEND_HEAP_MAX_ALIGNMENT UINT64_C(1048576)

enum ocnext_backend_heap_code {
    OCNEXT_BACKEND_HEAP_OK=0, OCNEXT_BACKEND_HEAP_ARGUMENT=1,
    OCNEXT_BACKEND_HEAP_EXHAUSTED=2, OCNEXT_BACKEND_HEAP_QUOTA=3,
    OCNEXT_BACKEND_HEAP_BAD_HANDLE=4, OCNEXT_BACKEND_HEAP_BAD_STATE=5,
    OCNEXT_BACKEND_HEAP_CORRUPT=6
};
enum ocnext_backend_heap_phase {
    OCNEXT_BACKEND_HEAP_ACTIVE=1, OCNEXT_BACKEND_HEAP_CLOSED=2
};
struct ocnext_backend_heap;

/* Native40B/alignment8. owner/generation are nonzero caller identity labels,
 * not authentication. registry_capacity must match the complete registry. */
struct ocnext_backend_heap_config {
    uint32_t abi_version, bytes;
    uint64_t owner, generation, registry_capacity, reserved;
};
/* Native32B/alignment8. All four fields bind one live allocation. A stale
 * descriptor cannot free a new allocation at the same native address. A raw
 * C-pointer lookup deliberately has ordinary C lifetime/ABA limitations. */
struct ocnext_backend_heap_allocation {
    void *native;
    uint64_t requested_bytes, alignment, serial;
};
/* Native80B/alignment8. Serial numbers start at1 and are never reused by an
 * instance. close retains the caller's RAM; it frees/unmaps no native pages. */
struct ocnext_backend_heap_stats {
    uint32_t abi_version, bytes, phase, reserved;
    uint64_t owner, generation, pool_bytes, registry_capacity;
    uint64_t live_count, live_requested, peak_requested, next_serial;
};

/* All objects are stable serialized native caller storage. State256 is16B
 * aligned and exactly zero-initialized. Pool64KiB..1GiB is16B aligned.
 * Registry is8B aligned, exactly capacity*32B and initially all zero. Config,
 * state, pool and registry have disjoint complete nonoverflowing spans. The
 * caller also certifies disjointness from other instances/code/owned objects.
 * Invalid initialization performs no writes. This is no native-pointer or
 * corrupted-allocator-metadata sandbox. TLSF internal invariant failure traps
 * terminally; no successful diagnostic/fence/OS-call stub is substituted.
 */
enum ocnext_backend_heap_code ocnext_backend_heap_initialize(
    void *storage, size_t storage_bytes, void *pool, size_t pool_bytes,
    void *registry, size_t registry_bytes,
    const struct ocnext_backend_heap_config *config);

/* On initialize success, cast the storage address to the opaque heap pointer.
 * Requested bytes must be nonzero. Alignment is a power of2 in16..1MiB.
 * Out/old descriptor complete spans are disjoint from each other and all heap
 * storage/pool/registry. Failure preserves outputs, live allocation identities
 * and their payloads; no new serial is consumed. Allocator free-list byte
 * identity and rejection latency are not promised. C pointer payload lifetime
 * ends on successful release/reallocate. realloc always allocates/copies/frees
 * rather than invoking upstream's unchecked oversized realloc path.
 * Invalid native spans/aliases/config/size0/alignment return ARGUMENT. Requests
 * larger than the instance pool return EXHAUSTED; full registry or exhausted
 * serial/accounting quotas return QUOTA before allocator calls. A structurally
 * valid descriptor not matching a live entry (including nativeNULL) returns
 * BAD_HANDLE. A fresh/uninitialized or closed heap returns BAD_STATE except
 * for query on CLOSED. initialize on nonzero state is BAD_STATE. Nonzero fresh
 * registry is ARGUMENT. Pointer/span/config and independent size0/alignment
 * validation precedes those lifecycle
 * decisions. Unexpected trusted internal invariant failure is terminal, not a
 * recoverable successful operation.
 */
enum ocnext_backend_heap_code ocnext_backend_heap_allocate(
    struct ocnext_backend_heap *, uint64_t bytes, uint64_t alignment,
    struct ocnext_backend_heap_allocation *out);
enum ocnext_backend_heap_code ocnext_backend_heap_reallocate(
    struct ocnext_backend_heap *, const struct ocnext_backend_heap_allocation *old,
    uint64_t bytes, uint64_t alignment, struct ocnext_backend_heap_allocation *out);
enum ocnext_backend_heap_code ocnext_backend_heap_release(
    struct ocnext_backend_heap *, const struct ocnext_backend_heap_allocation *);
enum ocnext_backend_heap_code ocnext_backend_heap_lookup(
    const struct ocnext_backend_heap *, const void *native,
    struct ocnext_backend_heap_allocation *out);
enum ocnext_backend_heap_code ocnext_backend_heap_query(
    const struct ocnext_backend_heap *, struct ocnext_backend_heap_stats *out);
/* Active live allocations make close BAD_STATE. A closed instance may be
 * queried but cannot allocate/reallocate/release/lookup or be reinitialized. */
enum ocnext_backend_heap_code ocnext_backend_heap_close(struct ocnext_backend_heap *);

#ifdef __cplusplus
}
#endif
#endif
