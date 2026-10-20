#include "ocnext/bridge.h"

#include <limits.h>
#include <string.h>

_Static_assert(CHAR_BIT == 8, "The protocol requires 8-bit bytes");

static uint16_t read16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read64(const uint8_t *p)
{
    return (uint64_t)read32(p) | ((uint64_t)read32(p + 4) << 32);
}

static int32_t read_signed32(const uint8_t *p)
{
    uint32_t value = read32(p);
    if (value <= INT32_MAX) {
        return (int32_t)value;
    }
    /* Conversion stays within int32_t, including INT32_MIN. */
    return (int32_t)(-1 - (int64_t)(UINT32_MAX - value));
}

static void write16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void write32(uint8_t *p, uint32_t value)
{
    unsigned int i;
    for (i = 0; i < 4; ++i) {
        p[i] = (uint8_t)(value >> (8 * i));
    }
}

static void write64(uint8_t *p, uint64_t value)
{
    unsigned int i;
    for (i = 0; i < 8; ++i) {
        p[i] = (uint8_t)(value >> (8 * i));
    }
}

static enum ocnext_bridge_result validate(const struct ocnext_bridge_header *h)
{
    if (h->version_major != OCNEXT_BRIDGE_VERSION_MAJOR ||
        (h->version_minor != OCNEXT_BRIDGE_VERSION_MINOR &&
         h->version_minor != OCNEXT_BRIDGE_DATA_MINOR)) {
        return OCNEXT_ERR_VERSION;
    }
    if (h->operation < OCNEXT_OP_HELLO ||
        h->operation > (h->version_minor == OCNEXT_BRIDGE_DATA_MINOR
                        ? OCNEXT_OP_BUFFER_COPY : OCNEXT_OP_DEVICE_RESET)) {
        return OCNEXT_ERR_OPERATION;
    }
    if (h->flags != OCNEXT_FLAG_REQUEST && h->flags != OCNEXT_FLAG_RESPONSE) {
        return OCNEXT_ERR_FLAGS;
    }
    if (h->total_size < OCNEXT_BRIDGE_HEADER_SIZE ||
        h->total_size > OCNEXT_BRIDGE_MAX_MESSAGE) {
        return OCNEXT_ERR_SIZE;
    }
    if (h->flags == OCNEXT_FLAG_REQUEST && h->status != 0) {
        return OCNEXT_ERR_REQUEST_STATUS;
    }
    return OCNEXT_OK;
}

enum ocnext_bridge_result ocnext_bridge_parse(
    const void *message, size_t message_size, struct ocnext_bridge_view *view)
{
    const uint8_t *p = (const uint8_t *)message;
    struct ocnext_bridge_header h;
    enum ocnext_bridge_result result;
    size_t i;
    if (view == NULL) {
        return OCNEXT_ERR_ARGUMENT;
    }
    memset(view, 0, sizeof(*view));
    if (message == NULL) {
        return OCNEXT_ERR_ARGUMENT;
    }
    if (message_size < OCNEXT_BRIDGE_HEADER_SIZE) {
        return OCNEXT_ERR_TRUNCATED;
    }
    if (message_size > OCNEXT_BRIDGE_MAX_MESSAGE) {
        return OCNEXT_ERR_SIZE;
    }
    if (memcmp(p, "ONXT", 4) != 0) {
        return OCNEXT_ERR_MAGIC;
    }
    h.version_major = read16(p + 4);
    h.version_minor = read16(p + 6);
    h.operation = read16(p + 8);
    h.flags = read16(p + 10);
    h.total_size = read32(p + 12);
    h.request_id = read64(p + 16);
    h.session_id = read64(p + 24);
    h.generation = read32(p + 32);
    h.status = read_signed32(p + 36);
    h.capability_mask = read64(p + 40);
    result = validate(&h);
    if (result != OCNEXT_OK) {
        return result;
    }
    if (message_size < h.total_size) {
        return OCNEXT_ERR_TRUNCATED;
    }
    if (message_size != h.total_size) {
        return OCNEXT_ERR_SIZE;
    }
    for (i = 48; i < OCNEXT_BRIDGE_HEADER_SIZE; ++i) {
        if (p[i] != 0) {
            return OCNEXT_ERR_RESERVED;
        }
    }
    view->header = h;
    view->payload = p + OCNEXT_BRIDGE_HEADER_SIZE;
    view->payload_size = message_size - OCNEXT_BRIDGE_HEADER_SIZE;
    return OCNEXT_OK;
}

enum ocnext_bridge_result ocnext_bridge_encode_header(
    const struct ocnext_bridge_header *header, void *destination, size_t capacity)
{
    uint8_t encoded[64];
    enum ocnext_bridge_result result;
    if (header == NULL || destination == NULL) {
        return OCNEXT_ERR_ARGUMENT;
    }
    if (capacity < OCNEXT_BRIDGE_HEADER_SIZE) {
        return OCNEXT_ERR_TRUNCATED;
    }
    result = validate(header);
    if (result != OCNEXT_OK) {
        return result;
    }
    memset(encoded, 0, sizeof(encoded));
    memcpy(encoded, "ONXT", 4);
    write16(encoded + 4, header->version_major);
    write16(encoded + 6, header->version_minor);
    write16(encoded + 8, header->operation);
    write16(encoded + 10, header->flags);
    write32(encoded + 12, header->total_size);
    write64(encoded + 16, header->request_id);
    write64(encoded + 24, header->session_id);
    write32(encoded + 32, header->generation);
    write32(encoded + 36, (uint32_t)header->status);
    write64(encoded + 40, header->capability_mask);
    memcpy(destination, encoded, sizeof(encoded));
    return OCNEXT_OK;
}

const char *ocnext_bridge_result_string(enum ocnext_bridge_result result)
{
    switch (result) {
    case OCNEXT_OK: return "ok";
    case OCNEXT_ERR_ARGUMENT: return "invalid argument";
    case OCNEXT_ERR_TRUNCATED: return "truncated message or header buffer";
    case OCNEXT_ERR_MAGIC: return "bad magic";
    case OCNEXT_ERR_VERSION: return "unsupported wire version";
    case OCNEXT_ERR_OPERATION: return "unsupported operation";
    case OCNEXT_ERR_FLAGS: return "invalid request/response flags";
    case OCNEXT_ERR_SIZE: return "invalid or oversized message length";
    case OCNEXT_ERR_RESERVED: return "nonzero reserved bytes";
    case OCNEXT_ERR_REQUEST_STATUS: return "request status must be zero";
    default: return "unknown local parser result";
    }
}
