#include "ocnext/broker.h"

#include <limits.h>
#include <string.h>

struct session {
    uint64_t id, owner, capabilities, last_request, bytes;
    uint32_t generation, buffers;
    uint16_t wire_minor;
};

struct buffer {
    uint64_t id, session, bytes;
    uint32_t generation, usage;
    size_t alignment;
    void *memory;
};

struct ocnext_broker {
    struct ocnext_broker_limits limits;
    struct ocnext_broker_allocator allocator;
    uint64_t next_session, next_buffer;
    struct session sessions[OCNEXT_BROKER_MAX_SESSIONS];
    struct buffer buffers[OCNEXT_BROKER_MAX_BUFFERS];
};

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get64(const uint8_t *p)
{
    return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32);
}

static void put32(uint8_t *p, uint32_t value)
{
    unsigned int i;
    for (i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (8 * i));
}

static void put64(uint8_t *p, uint64_t value)
{
    put32(p, (uint32_t)value);
    put32(p + 4, (uint32_t)(value >> 32));
}

static int power_of_two(uint64_t n)
{
    return n != 0 && (n & (n - 1)) == 0;
}

size_t ocnext_broker_storage_size(void) { return sizeof(struct ocnext_broker); }
size_t ocnext_broker_storage_alignment(void) { return _Alignof(struct ocnext_broker); }

struct ocnext_broker_limits ocnext_broker_default_limits(void)
{
    struct ocnext_broker_limits limits = {
        8, 16, UINT64_C(16) * 1024 * 1024, UINT64_C(4) * 1024 * 1024,
        (uint32_t)_Alignof(max_align_t)
    };
    return limits;
}

struct ocnext_broker *ocnext_broker_init(
    void *storage, size_t storage_size, const struct ocnext_broker_limits *limits,
    const struct ocnext_broker_allocator *allocator)
{
    struct ocnext_broker *broker;
    if (storage == NULL || limits == NULL || allocator == NULL ||
        allocator->allocate == NULL || allocator->deallocate == NULL ||
        storage_size < sizeof(struct ocnext_broker) ||
        (uintptr_t)storage % _Alignof(struct ocnext_broker) != 0 ||
        limits->max_sessions == 0 || limits->max_sessions > OCNEXT_BROKER_MAX_SESSIONS ||
        limits->max_buffers_per_session == 0 ||
        limits->max_buffers_per_session > OCNEXT_BROKER_MAX_BUFFERS ||
        limits->max_buffer_bytes == 0 || limits->max_buffer_bytes > SIZE_MAX ||
        limits->max_session_bytes < limits->max_buffer_bytes ||
        limits->max_session_bytes > UINT64_MAX / limits->max_sessions ||
        !power_of_two(limits->max_alignment)) return NULL;
    broker = (struct ocnext_broker *)storage;
    memset(broker, 0, sizeof(*broker));
    broker->limits = *limits;
    broker->allocator = *allocator;
    broker->next_session = 1;
    broker->next_buffer = 1;
    return broker;
}

static struct session *find_session(struct ocnext_broker *broker, uint64_t id)
{
    size_t i;
    if (id == 0) return NULL;
    for (i = 0; i < OCNEXT_BROKER_MAX_SESSIONS; ++i)
        if (broker->sessions[i].id == id) return &broker->sessions[i];
    return NULL;
}

static void release_buffer(struct ocnext_broker *broker, struct session *s, struct buffer *b)
{
    broker->allocator.deallocate(broker->allocator.context, b->memory,
                                (size_t)b->bytes, b->alignment);
    s->bytes -= b->bytes;
    --s->buffers;
    memset(b, 0, sizeof(*b));
}

static void clear_session_buffers(struct ocnext_broker *broker, struct session *s)
{
    size_t i;
    for (i = 0; i < OCNEXT_BROKER_MAX_BUFFERS; ++i)
        if (broker->buffers[i].id != 0 && broker->buffers[i].session == s->id)
            release_buffer(broker, s, &broker->buffers[i]);
}

void ocnext_broker_disconnect(struct ocnext_broker *broker, uint64_t owner_id)
{
    size_t i;
    if (broker == NULL || owner_id == 0) return;
    for (i = 0; i < OCNEXT_BROKER_MAX_SESSIONS; ++i) {
        struct session *s = &broker->sessions[i];
        if (s->id != 0 && s->owner == owner_id) {
            clear_session_buffers(broker, s);
            memset(s, 0, sizeof(*s));
        }
    }
}

void ocnext_broker_destroy(struct ocnext_broker *broker)
{
    size_t i;
    if (broker == NULL) return;
    for (i = 0; i < OCNEXT_BROKER_MAX_SESSIONS; ++i) {
        struct session *s = &broker->sessions[i];
        if (s->id != 0) clear_session_buffers(broker, s);
    }
    memset(broker, 0, sizeof(*broker));
}

struct ocnext_broker_stats ocnext_broker_get_stats(const struct ocnext_broker *broker)
{
    struct ocnext_broker_stats stats = {0, 0, 0};
    size_t i;
    if (broker == NULL) return stats;
    for (i = 0; i < OCNEXT_BROKER_MAX_SESSIONS; ++i) {
        const struct session *s = &broker->sessions[i];
        if (s->id != 0) {
            ++stats.active_sessions;
            stats.active_buffers += s->buffers;
            stats.allocated_bytes += s->bytes;
        }
    }
    return stats;
}

static int valid_prefix(const struct ocnext_bridge_view *v, size_t expected)
{
    return v->payload_size == expected && get32(v->payload) == OCNEXT_BROKER_PAYLOAD_VERSION;
}

static int32_t hello(struct ocnext_broker *broker, uint64_t owner,
                     const struct ocnext_bridge_view *v, struct session **created,
                     uint8_t *payload, size_t *payload_size)
{
    uint32_t active = 0;
    struct session *empty = NULL;
    uint64_t caps = v->header.capability_mask & (v->header.version_minor == OCNEXT_BRIDGE_DATA_MINOR
                    ? OCNEXT_BROKER_CAP_IMPLEMENTED : OCNEXT_BROKER_CAP_LEGACY);
    size_t i;
    if (!valid_prefix(v, 8) || get32(v->payload + 4) != 0)
        return OCNEXT_BROKER_BAD_PAYLOAD;
    if (v->header.session_id != 0 || v->header.generation != 0)
        return OCNEXT_BROKER_BAD_REQUEST;
    if (!(caps & OCNEXT_BROKER_CAP_SESSION)) return OCNEXT_BROKER_CAPABILITY_DENIED;
    if (!(caps & OCNEXT_BROKER_CAP_CPU_BUFFER)) caps &= ~OCNEXT_BROKER_CAP_CPU_DATA_PLANE;
    for (i = 0; i < OCNEXT_BROKER_MAX_SESSIONS; ++i) {
        if (broker->sessions[i].id == 0) empty = &broker->sessions[i];
        else {
            ++active;
            if (broker->sessions[i].owner == owner &&
                v->header.request_id <= broker->sessions[i].last_request)
                return OCNEXT_BROKER_REPLAY;
        }
    }
    if (active >= broker->limits.max_sessions || empty == NULL) return OCNEXT_BROKER_QUOTA;
    if (broker->next_session == UINT64_MAX) return OCNEXT_BROKER_ID_EXHAUSTED;
    empty->id = broker->next_session++;
    empty->owner = owner;
    empty->capabilities = caps;
    empty->generation = 1;
    empty->last_request = v->header.request_id;
    empty->wire_minor = v->header.version_minor;
    *created = empty;
    put32(payload + 8, broker->limits.max_buffers_per_session);
    put32(payload + 12, 16); /* opaque handle byte length */
    put64(payload + 16, broker->limits.max_session_bytes);
    put64(payload + 24, broker->limits.max_buffer_bytes);
    *payload_size = 32;
    return OCNEXT_BROKER_OK;
}

static int32_t register_buffer(struct ocnext_broker *broker, struct session *s,
                              const struct ocnext_bridge_view *v,
                              uint8_t *payload, size_t *payload_size)
{
    uint32_t usage;
    uint64_t bytes, alignment;
    struct buffer *empty = NULL;
    void *memory;
    size_t i;
    if (!valid_prefix(v, 32)) return OCNEXT_BROKER_BAD_PAYLOAD;
    usage = get32(v->payload + 4);
    bytes = get64(v->payload + 8);
    alignment = get64(v->payload + 16);
    if (get64(v->payload + 24) != 0 || usage == 0 || (usage & ~UINT32_C(3)) != 0 ||
        bytes == 0 || bytes > SIZE_MAX || !power_of_two(alignment) ||
        alignment > broker->limits.max_alignment) return OCNEXT_BROKER_BAD_PAYLOAD;
    if (!(s->capabilities & OCNEXT_BROKER_CAP_CPU_BUFFER)) return OCNEXT_BROKER_CAPABILITY_DENIED;
    if (bytes > broker->limits.max_buffer_bytes ||
        bytes > broker->limits.max_session_bytes - s->bytes ||
        s->buffers >= broker->limits.max_buffers_per_session) return OCNEXT_BROKER_QUOTA;
    for (i = 0; i < OCNEXT_BROKER_MAX_BUFFERS; ++i)
        if (broker->buffers[i].id == 0) { empty = &broker->buffers[i]; break; }
    if (empty == NULL) return OCNEXT_BROKER_QUOTA;
    if (broker->next_buffer == UINT64_MAX) return OCNEXT_BROKER_ID_EXHAUSTED;
    memory = broker->allocator.allocate(broker->allocator.context, (size_t)bytes, (size_t)alignment);
    if (memory == NULL) return OCNEXT_BROKER_ALLOCATION_FAILED;
    if ((uintptr_t)memory % (size_t)alignment != 0) {
        broker->allocator.deallocate(broker->allocator.context, memory, (size_t)bytes, (size_t)alignment);
        return OCNEXT_BROKER_ALLOCATION_FAILED;
    }
    memset(memory, 0, (size_t)bytes);
    empty->id = broker->next_buffer++;
    empty->session = s->id;
    empty->generation = 1; /* IDs never reused in this context. */
    empty->usage = usage;
    empty->bytes = bytes;
    empty->alignment = (size_t)alignment;
    empty->memory = memory;
    s->bytes += bytes;
    ++s->buffers;
    put64(payload + 8, empty->id);
    put32(payload + 16, empty->generation);
    put32(payload + 20, OCNEXT_BROKER_BUFFER_TYPE);
    *payload_size = 24;
    return OCNEXT_BROKER_OK;
}

static int32_t release_request(struct ocnext_broker *broker, struct session *s,
                              const struct ocnext_bridge_view *v)
{
    uint64_t id;
    size_t i;
    if (!valid_prefix(v, 24) || get32(v->payload + 4) != 0)
        return OCNEXT_BROKER_BAD_PAYLOAD;
    if (!(s->capabilities & OCNEXT_BROKER_CAP_CPU_BUFFER)) return OCNEXT_BROKER_CAPABILITY_DENIED;
    id = get64(v->payload + 8);
    if (id == 0 || get32(v->payload + 20) != OCNEXT_BROKER_BUFFER_TYPE)
        return OCNEXT_BROKER_BAD_HANDLE;
    for (i = 0; i < OCNEXT_BROKER_MAX_BUFFERS; ++i) {
        struct buffer *b = &broker->buffers[i];
        if (b->id == id && b->session == s->id &&
            b->generation == get32(v->payload + 16)) {
            release_buffer(broker, s, b);
            return OCNEXT_BROKER_OK;
        }
    }
    return OCNEXT_BROKER_BAD_HANDLE;
}

static struct buffer *find_handle(struct ocnext_broker *broker, struct session *s, const uint8_t *handle)
{
    size_t i;
    uint64_t id = get64(handle);
    if (!id || get32(handle + 12) != OCNEXT_BROKER_BUFFER_TYPE) return NULL;
    for (i = 0; i < OCNEXT_BROKER_MAX_BUFFERS; ++i) {
        struct buffer *b = &broker->buffers[i];
        if (b->id == id && b->session == s->id && b->generation == get32(handle + 8)) return b;
    }
    return NULL;
}

static int buffer_range(const struct buffer *buffer, uint64_t offset, uint64_t length)
{
    return offset <= buffer->bytes && length <= buffer->bytes - offset;
}

static int32_t data_request(struct ocnext_broker *broker, struct session *s,
                           const struct ocnext_bridge_view *v, uint8_t *response,
                           uint8_t *payload, size_t *payload_size, size_t *data_size)
{
    const uint8_t *p = v->payload;
    struct buffer *source, *destination;
    uint64_t offset, destination_offset = 0, length;
    if (v->payload_size < 40 || get32(p) != OCNEXT_BROKER_PAYLOAD_VERSION || get32(p + 4)) return OCNEXT_BROKER_BAD_PAYLOAD;
    if (v->header.operation == OCNEXT_OP_BUFFER_COPY) {
        if (v->payload_size != 64) return OCNEXT_BROKER_BAD_PAYLOAD;
        offset = get64(p + 40); destination_offset = get64(p + 48); length = get64(p + 56);
    } else { offset = get64(p + 24); length = get64(p + 32); }
    if (!length || length > OCNEXT_BROKER_MAX_TRANSFER ||
        (v->header.operation == OCNEXT_OP_BUFFER_READ && v->payload_size != 40) ||
        (v->header.operation == OCNEXT_OP_BUFFER_WRITE && v->payload_size != 40 + (size_t)length)) return OCNEXT_BROKER_BAD_PAYLOAD;
    if ((s->capabilities & (OCNEXT_BROKER_CAP_CPU_BUFFER | OCNEXT_BROKER_CAP_CPU_DATA_PLANE)) !=
        (OCNEXT_BROKER_CAP_CPU_BUFFER | OCNEXT_BROKER_CAP_CPU_DATA_PLANE)) return OCNEXT_BROKER_CAPABILITY_DENIED;
    source = find_handle(broker, s, p + 8);
    if (!source) return OCNEXT_BROKER_BAD_HANDLE;
    if (v->header.operation == OCNEXT_OP_BUFFER_COPY) {
        destination = find_handle(broker, s, p + 24);
        if (!destination) return OCNEXT_BROKER_BAD_HANDLE;
        if (!(source->usage & OCNEXT_BROKER_CPU_READ) || !(destination->usage & OCNEXT_BROKER_CPU_WRITE)) return OCNEXT_BROKER_PERMISSION_DENIED;
        if (!buffer_range(source, offset, length) || !buffer_range(destination, destination_offset, length)) return OCNEXT_BROKER_BUFFER_RANGE;
        memmove((uint8_t *)destination->memory + (size_t)destination_offset,
                (uint8_t *)source->memory + (size_t)offset, (size_t)length);
    } else {
        uint32_t usage = v->header.operation == OCNEXT_OP_BUFFER_READ ? OCNEXT_BROKER_CPU_READ : OCNEXT_BROKER_CPU_WRITE;
        if (!(source->usage & usage)) return OCNEXT_BROKER_PERMISSION_DENIED;
        if (!buffer_range(source, offset, length)) return OCNEXT_BROKER_BUFFER_RANGE;
        if (v->header.operation == OCNEXT_OP_BUFFER_READ) {
            memcpy(response + 80, (uint8_t *)source->memory + (size_t)offset, (size_t)length);
            *data_size = (size_t)length;
        } else memcpy((uint8_t *)source->memory + (size_t)offset, p + 40, (size_t)length);
    }
    put64(payload + 8, length); *payload_size = 16;
    return OCNEXT_BROKER_OK;
}

enum ocnext_broker_result ocnext_broker_dispatch(
    struct ocnext_broker *broker, uint64_t owner_id,
    const void *request, size_t request_size,
    void *response, size_t response_capacity, size_t *response_size)
{
    struct ocnext_bridge_view v;
    struct ocnext_bridge_header reply;
    struct session *s = NULL;
    uint8_t payload[32] = {0};
    size_t payload_size = 8;
    size_t data_size = 0;
    int32_t status = OCNEXT_BROKER_OK;
    if (response_size == NULL) return OCNEXT_BROKER_INVALID_ARGUMENT;
    *response_size = 0;
    if (broker == NULL || owner_id == 0 || request == NULL || response == NULL)
        return OCNEXT_BROKER_INVALID_ARGUMENT;
    if (response_capacity < OCNEXT_BROKER_RESPONSE_CAPACITY)
        return OCNEXT_BROKER_RESPONSE_TOO_SMALL;
    if (ocnext_bridge_parse(request, request_size, &v) != OCNEXT_OK)
        return OCNEXT_BROKER_INVALID_WIRE;
    if (v.header.operation == OCNEXT_OP_BUFFER_READ && v.payload_size == 40 &&
        get32(v.payload) == OCNEXT_BROKER_PAYLOAD_VERSION && !get32(v.payload + 4)) {
        uint64_t length = get64(v.payload + 32);
        if (length && length <= OCNEXT_BROKER_MAX_TRANSFER && response_capacity < 80 + (size_t)length)
            return OCNEXT_BROKER_RESPONSE_TOO_SMALL;
    }
    put32(payload, OCNEXT_BROKER_PAYLOAD_VERSION);
    if (v.header.flags != OCNEXT_FLAG_REQUEST || v.header.request_id == 0)
        status = OCNEXT_BROKER_BAD_REQUEST;
    else if (v.header.operation == OCNEXT_OP_HELLO)
        status = hello(broker, owner_id, &v, &s, payload, &payload_size);
    else {
        s = find_session(broker, v.header.session_id);
        if (s == NULL) status = OCNEXT_BROKER_NO_SESSION;
        else if (s->owner != owner_id) { status = OCNEXT_BROKER_WRONG_OWNER; s = NULL; }
        else if (v.header.request_id <= s->last_request) status = OCNEXT_BROKER_REPLAY;
        else {
            s->last_request = v.header.request_id;
            if (v.header.generation != s->generation) status = OCNEXT_BROKER_STALE_GENERATION;
            else if (v.header.version_minor != s->wire_minor) status = OCNEXT_BROKER_VERSION_MISMATCH;
            else if ((v.header.capability_mask & ~s->capabilities) != 0)
                status = OCNEXT_BROKER_CAPABILITY_DENIED;
            else switch (v.header.operation) {
                case OCNEXT_OP_ENUMERATE:
                    if (!valid_prefix(&v, 8) || get32(v.payload + 4) != 0)
                        status = OCNEXT_BROKER_BAD_PAYLOAD;
                    else payload_size = 24; /* zero devices; CPU buffers are not a GPU */
                    break;
                case OCNEXT_OP_BUFFER_REGISTER:
                    status = register_buffer(broker, s, &v, payload, &payload_size);
                    break;
                case OCNEXT_OP_BUFFER_RELEASE:
                    status = release_request(broker, s, &v);
                    break;
                case OCNEXT_OP_BUFFER_READ:
                case OCNEXT_OP_BUFFER_WRITE:
                case OCNEXT_OP_BUFFER_COPY:
                    status = data_request(broker, s, &v, response, payload, &payload_size, &data_size);
                    break;
                case OCNEXT_OP_GPU_SUBMIT:
                case OCNEXT_OP_FENCE_WAIT:
                    status = (!valid_prefix(&v, 8) || get32(v.payload + 4) != 0)
                        ? OCNEXT_BROKER_BAD_PAYLOAD : OCNEXT_BROKER_UNSUPPORTED;
                    break;
                case OCNEXT_OP_DEVICE_RESET:
                    if (!valid_prefix(&v, 8) || get32(v.payload + 4) != 0)
                        status = OCNEXT_BROKER_BAD_PAYLOAD;
                    else if (!(s->capabilities & OCNEXT_BROKER_CAP_SESSION_RESET))
                        status = OCNEXT_BROKER_CAPABILITY_DENIED;
                    else if (s->generation == UINT32_MAX) status = OCNEXT_BROKER_ID_EXHAUSTED;
                    else { clear_session_buffers(broker, s); ++s->generation; }
                    break;
                default: status = OCNEXT_BROKER_UNSUPPORTED; break;
            }
        }
    }
    reply = v.header;
    reply.flags = OCNEXT_FLAG_RESPONSE;
    reply.status = status;
    reply.session_id = s == NULL ? v.header.session_id : s->id;
    reply.generation = s == NULL ? v.header.generation : s->generation;
    reply.capability_mask = s == NULL ? 0 : s->capabilities &
        (v.header.version_minor == OCNEXT_BRIDGE_DATA_MINOR ? OCNEXT_BROKER_CAP_IMPLEMENTED : OCNEXT_BROKER_CAP_LEGACY);
    reply.total_size = (uint32_t)(OCNEXT_BRIDGE_HEADER_SIZE + payload_size + data_size);
    if (ocnext_bridge_encode_header(&reply, response, response_capacity) != OCNEXT_OK)
        return OCNEXT_BROKER_INVALID_WIRE; /* unreachable with validated input */
    memcpy((uint8_t *)response + OCNEXT_BRIDGE_HEADER_SIZE, payload, payload_size);
    *response_size = reply.total_size;
    return OCNEXT_BROKER_DISPATCH_OK;
}
