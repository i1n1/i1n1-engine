#ifndef OCNEXT_BRIDGE_H
#define OCNEXT_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
# if defined(OCNEXT_BRIDGE_BUILD)
#  define OCNEXT_API __declspec(dllexport)
# else
#  define OCNEXT_API __declspec(dllimport)
# endif
#elif defined(__GNUC__) || defined(__clang__)
# define OCNEXT_API __attribute__((visibility("default")))
#else
# define OCNEXT_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Wire versions 1.0 and 1.1 keep identical 64-byte headers.
 * Minor 0 accepts operations 1..7; minor 1 additionally accepts 8..10.
 * All multi-byte fields are little-endian.
 * Never send this host structure by memcpy: its layout is not the wire ABI.
 * Header offsets: magic 0, major 4, minor 6, op 8, flags 10, total 12,
 * request 16, session 24, generation 32, status 36, capability mask 40.
 * Bytes 48..63 are reserved and MUST be zero.
 */
#define OCNEXT_BRIDGE_HEADER_SIZE ((size_t)64)
#define OCNEXT_BRIDGE_MAX_MESSAGE ((size_t)1048576)
#define OCNEXT_BRIDGE_VERSION_MAJOR ((uint16_t)1)
#define OCNEXT_BRIDGE_VERSION_MINOR ((uint16_t)0)
#define OCNEXT_BRIDGE_DATA_MINOR ((uint16_t)1)

enum ocnext_bridge_operation {
    OCNEXT_OP_HELLO = 1,
    OCNEXT_OP_ENUMERATE = 2,
    OCNEXT_OP_BUFFER_REGISTER = 3,
    OCNEXT_OP_BUFFER_RELEASE = 4,
    OCNEXT_OP_GPU_SUBMIT = 5,
    OCNEXT_OP_FENCE_WAIT = 6,
    OCNEXT_OP_DEVICE_RESET = 7,
    OCNEXT_OP_BUFFER_READ = 8,
    OCNEXT_OP_BUFFER_WRITE = 9,
    OCNEXT_OP_BUFFER_COPY = 10
};

enum ocnext_bridge_flag {
    OCNEXT_FLAG_REQUEST = 1,
    OCNEXT_FLAG_RESPONSE = 2
};

/* Local parser results, independent of a response's signed wire status.
 * A transport must map these to its own failure path before dispatch.
 */
enum ocnext_bridge_result {
    OCNEXT_OK = 0,
    OCNEXT_ERR_ARGUMENT = -1,
    OCNEXT_ERR_TRUNCATED = -2,
    OCNEXT_ERR_MAGIC = -3,
    OCNEXT_ERR_VERSION = -4,
    OCNEXT_ERR_OPERATION = -5,
    OCNEXT_ERR_FLAGS = -6,
    OCNEXT_ERR_SIZE = -7,
    OCNEXT_ERR_RESERVED = -8,
    OCNEXT_ERR_REQUEST_STATUS = -9
};

struct ocnext_bridge_header {
    uint16_t version_major;
    uint16_t version_minor;
    uint16_t operation;
    uint16_t flags;
    uint32_t total_size;
    uint64_t request_id;
    uint64_t session_id;
    uint32_t generation;
    int32_t status;
    uint64_t capability_mask;
};

struct ocnext_bridge_view {
    struct ocnext_bridge_header header;
    const uint8_t *payload;
    size_t payload_size;
};

/* Parse exactly one complete message. Input must remain alive and unchanged
 * while the returned payload view is used. On failure, view is cleared.
 * Payload bytes are opaque. Session authorization, capability negotiation,
 * ownership, handles, dispatch, translation and GPU work are NOT implemented.
 */
OCNEXT_API enum ocnext_bridge_result ocnext_bridge_parse(
    const void *message, size_t message_size, struct ocnext_bridge_view *view);

/* Serialize only the 64-byte header. Capacity is destination buffer capacity,
 * not the declared total_size. Caller supplies payload bytes separately.
 * Reserved bytes are zeroed; the destination is unchanged on validation error.
 */
OCNEXT_API enum ocnext_bridge_result ocnext_bridge_encode_header(
    const struct ocnext_bridge_header *header, void *destination, size_t capacity);

OCNEXT_API const char *ocnext_bridge_result_string(enum ocnext_bridge_result result);

#ifdef __cplusplus
}
#endif
#endif
