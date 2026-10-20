#ifndef OCNEXT_BROKER_H
#define OCNEXT_BROKER_H

#include <stddef.h>
#include <stdint.h>

#include "ocnext/bridge.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OCNEXT_BROKER_PAYLOAD_VERSION UINT32_C(1)
#define OCNEXT_BROKER_CAP_SESSION UINT64_C(1)
#define OCNEXT_BROKER_CAP_CPU_BUFFER UINT64_C(2)
#define OCNEXT_BROKER_CAP_SESSION_RESET UINT64_C(4)
#define OCNEXT_BROKER_CAP_CPU_DATA_PLANE UINT64_C(8)
#define OCNEXT_BROKER_CAP_LEGACY UINT64_C(7)
#define OCNEXT_BROKER_CAP_IMPLEMENTED UINT64_C(15)
#define OCNEXT_BROKER_MAX_TRANSFER ((size_t)65536)
#define OCNEXT_BROKER_DATA_RESPONSE_CAPACITY ((size_t)64 + 16 + OCNEXT_BROKER_MAX_TRANSFER)
#define OCNEXT_BROKER_CPU_READ UINT32_C(1)
#define OCNEXT_BROKER_CPU_WRITE UINT32_C(2)
#define OCNEXT_BROKER_BUFFER_TYPE UINT32_C(1)
#define OCNEXT_BROKER_MAX_SESSIONS UINT32_C(8)
#define OCNEXT_BROKER_MAX_BUFFERS UINT32_C(64)
#define OCNEXT_BROKER_RESPONSE_CAPACITY ((size_t)96)

/* Semantic wire status. These are distinct from local bridge parser errors. */
enum ocnext_broker_status {
    OCNEXT_BROKER_OK = 0,
    OCNEXT_BROKER_BAD_PAYLOAD = -1001,
    OCNEXT_BROKER_NO_SESSION = -1002,
    OCNEXT_BROKER_WRONG_OWNER = -1003,
    OCNEXT_BROKER_REPLAY = -1004,
    OCNEXT_BROKER_STALE_GENERATION = -1005,
    OCNEXT_BROKER_CAPABILITY_DENIED = -1006,
    OCNEXT_BROKER_QUOTA = -1007,
    OCNEXT_BROKER_BAD_HANDLE = -1008,
    OCNEXT_BROKER_ALLOCATION_FAILED = -1009,
    OCNEXT_BROKER_UNSUPPORTED = -1010,
    OCNEXT_BROKER_ID_EXHAUSTED = -1011,
    OCNEXT_BROKER_BAD_REQUEST = -1012,
    OCNEXT_BROKER_VERSION_MISMATCH = -1013,
    OCNEXT_BROKER_PERMISSION_DENIED = -1014,
    OCNEXT_BROKER_BUFFER_RANGE = -1015
};

/* Dispatch failures return no response and do not change broker state. */
enum ocnext_broker_result {
    OCNEXT_BROKER_DISPATCH_OK = 0,
    OCNEXT_BROKER_INVALID_ARGUMENT = -1,
    OCNEXT_BROKER_RESPONSE_TOO_SMALL = -2,
    OCNEXT_BROKER_INVALID_WIRE = -3
};

struct ocnext_broker_limits {
    uint32_t max_sessions;
    uint32_t max_buffers_per_session;
    uint64_t max_session_bytes;
    uint64_t max_buffer_bytes;
    uint32_t max_alignment;
};

/* Allocator pointers are trusted native callbacks, never obtained from wire.
 * allocate must return non-overlapping, writable, suitably aligned memory.
 * deallocate must tolerate every allocation that allocate returned. */
struct ocnext_broker_allocator {
    void *context;
    void *(*allocate)(void *context, size_t bytes, size_t alignment);
    void (*deallocate)(void *context, void *memory, size_t bytes, size_t alignment);
};

struct ocnext_broker_stats {
    uint32_t active_sessions;
    uint32_t active_buffers;
    uint64_t allocated_bytes;
};

struct ocnext_broker;

size_t ocnext_broker_storage_size(void);
size_t ocnext_broker_storage_alignment(void);
struct ocnext_broker_limits ocnext_broker_default_limits(void);

/* Caller owns the aligned storage and must keep callbacks alive until destroy.
 * The portable engine has no OS calls, locks, or internal heap allocations.
 * Calls must be serialized. The native socket daemon provides serialization. */
struct ocnext_broker *ocnext_broker_init(
    void *storage, size_t storage_size, const struct ocnext_broker_limits *limits,
    const struct ocnext_broker_allocator *allocator);

/* owner_id is assigned by a trusted transport, not by a guest payload.
 * Output capacity must be >=96; valid READ additionally requires 80+length.
 * Too-small capacity is rejected before consuming a request ID or mutation.
 * Input/output/storage/native allocations must not overlap.
 * Requests remain immutable for the call. All semantic results become complete
 * ONXT responses. No GPU, DMA, device fence, or native-driver work is performed. */
enum ocnext_broker_result ocnext_broker_dispatch(
    struct ocnext_broker *broker, uint64_t owner_id,
    const void *request, size_t request_size,
    void *response, size_t response_capacity, size_t *response_size);

/* Disconnect cleanup closes every session of this transport owner. */
void ocnext_broker_disconnect(struct ocnext_broker *broker, uint64_t owner_id);
void ocnext_broker_destroy(struct ocnext_broker *broker);
struct ocnext_broker_stats ocnext_broker_get_stats(const struct ocnext_broker *broker);

#ifdef __cplusplus
}
#endif
#endif
