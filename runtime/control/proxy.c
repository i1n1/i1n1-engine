#include "ocnext/proxy.h"

static void bytes_copy(uint8_t *out, const uint8_t *in, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) out[i] = in[i];
}
static void bytes_move(uint8_t *out, const uint8_t *in, size_t n)
{
    size_t i;
    if ((uintptr_t)out > (uintptr_t)in) {
        for (i = n; i; --i) out[i - 1] = in[i - 1];
    } else bytes_copy(out, in, n);
}
static void bytes_zero(uint8_t *out, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) out[i] = 0;
}
static uint32_t load32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t load64(const uint8_t *p)
{
    return (uint64_t)load32(p) | ((uint64_t)load32(p + 4) << 32);
}
static void store32(uint8_t *p, uint32_t v)
{
    unsigned i;
    for (i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (i * 8));
}
static void store64(uint8_t *p, uint64_t v)
{
    unsigned i;
    for (i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (i * 8));
}
static uint32_t checksum(const uint8_t *p, size_t n)
{
    uint32_t sum = UINT32_C(0xdeadbeef);
    size_t i;
    for (i = 0; i < n; ++i)
        sum = sum * UINT32_C(31337) + ((uint32_t)p[i] ^ UINT32_C(0x5a));
    return sum ^ UINT32_C(0xaddedbad);
}
static int type_valid(uint32_t type)
{
    return (type & UINT32_C(0x00ffffff)) == UINT32_C(0x00aa55ff);
}
static int zeros(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) if (p[i]) return 0;
    return 1;
}
static uint64_t saturating_add(uint64_t a, uint64_t b)
{
    return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}
static int span_valid(const void *p, size_t n)
{
    return (!n || p) && n <= UINTPTR_MAX - (uintptr_t)p;
}
static int spans_overlap(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (!an || !bn) return 0;
    if (!span_valid(a, an) || !span_valid(b, bn)) return 1;
    return x < y + bn && y < x + an;
}

enum ocnext_proxy_result ocnext_proxy_checksum(const uint8_t *p, size_t n,
                                               uint32_t *out)
{
    if (!out || !span_valid(p, n) || n > OCNEXT_PROXY_MAX_STREAM_INPUT)
        return OCNEXT_PROXY_ARGUMENT;
    *out = checksum(p, n);
    return OCNEXT_PROXY_OK;
}

enum ocnext_proxy_result ocnext_proxy_encode_request(uint32_t type,
    const uint8_t *payload, size_t payload_bytes, const uint8_t *data,
    size_t data_bytes, uint8_t *out, size_t capacity, size_t *written)
{
    uint8_t staged[OCNEXT_PROXY_REQUEST_BYTES];
    size_t total = OCNEXT_PROXY_REQUEST_BYTES;
    if (!out || !written || !type_valid(type) ||
        payload_bytes > OCNEXT_PROXY_PAYLOAD_BYTES || (payload_bytes && !payload) ||
        data_bytes > OCNEXT_PROXY_MAX_TRANSFER || !span_valid(payload, payload_bytes) ||
        !span_valid(data, data_bytes))
        return OCNEXT_PROXY_ARGUMENT;
    if (type == OCNEXT_PROXY_REQ_MEMWRITE) {
        if (payload_bytes < 20 || load64(payload + 8) != data_bytes)
            return OCNEXT_PROXY_ARGUMENT;
        total += data_bytes;
    } else if (data_bytes) return OCNEXT_PROXY_ARGUMENT;
    if (capacity < total) return OCNEXT_PROXY_OUTPUT_TOO_SMALL;
    if (!span_valid(out, total) || !span_valid(payload, payload_bytes) ||
        !span_valid(data, data_bytes) ||
        spans_overlap(written, sizeof(*written), out, total)) return OCNEXT_PROXY_ARGUMENT;
    bytes_zero(staged, OCNEXT_PROXY_REQUEST_BYTES);
    store32(staged, type);
    bytes_copy(staged + 4, payload, payload_bytes);
    store32(staged + 60, checksum(staged, 60));
    /* Header is completely staged; move the body first for native input alias. */
    if (data_bytes) bytes_move(out + 64, data, data_bytes);
    bytes_copy(out, staged, 64);
    *written = total;
    return OCNEXT_PROXY_OK;
}

enum ocnext_proxy_result ocnext_proxy_parse_request(const uint8_t *frame, size_t n,
    struct ocnext_proxy_request_view *out)
{
    struct ocnext_proxy_request_view staged;
    uint64_t declared;
    if (!frame || !out || !span_valid(frame, n) ||
        spans_overlap(frame, n, out, sizeof(*out))) return OCNEXT_PROXY_ARGUMENT;
    if (n < 64 || n > OCNEXT_PROXY_MAX_FRAME || !type_valid(load32(frame)) ||
        checksum(frame, 60) != load32(frame + 60))
        return OCNEXT_PROXY_INVALID_WIRE;
    bytes_zero((uint8_t *)&staged, sizeof(staged));
    staged.type = load32(frame);
    if (staged.type == OCNEXT_PROXY_REQ_MEMWRITE) {
        declared = load64(frame + 12);
        if (declared > OCNEXT_PROXY_MAX_TRANSFER || n != 64 + (size_t)declared)
            return OCNEXT_PROXY_INVALID_WIRE;
        staged.write_data = frame + 64;
        staged.write_bytes = (size_t)declared;
    } else if (n != 64) return OCNEXT_PROXY_INVALID_WIRE;
    bytes_copy(staged.payload, frame + 4, sizeof(staged.payload));
    bytes_copy((uint8_t *)out, (const uint8_t *)&staged, sizeof(staged));
    return OCNEXT_PROXY_OK;
}

enum ocnext_proxy_result ocnext_proxy_parse_reply(const uint8_t *frame, size_t n,
    uint32_t expected_type, size_t expected_read_bytes,
    struct ocnext_proxy_reply_view *out)
{
    struct ocnext_proxy_reply_view staged;
    uint32_t raw_status;
    size_t data_bytes = 0;
    if (!frame || !out || !span_valid(frame, n) ||
        spans_overlap(frame, n, out, sizeof(*out)) || !type_valid(expected_type) ||
        expected_read_bytes > OCNEXT_PROXY_MAX_TRANSFER)
        return OCNEXT_PROXY_ARGUMENT;
    if (n < 36 || n > OCNEXT_PROXY_MAX_REPLY || load32(frame) != expected_type ||
        checksum(frame, 32) != load32(frame + 32)) return OCNEXT_PROXY_INVALID_WIRE;
    raw_status = load32(frame + 4);
    if (raw_status != 0 && raw_status != UINT32_MAX &&
        raw_status != UINT32_MAX - 1 && raw_status != UINT32_MAX - 2 &&
        raw_status != UINT32_MAX - 3) return OCNEXT_PROXY_INVALID_WIRE;
    if (expected_type == OCNEXT_PROXY_REQ_MEMREAD && raw_status == 0)
        data_bytes = expected_read_bytes;
    if (n != 36 + data_bytes) return OCNEXT_PROXY_INVALID_WIRE;
    if (expected_type == OCNEXT_PROXY_REQ_MEMREAD && raw_status == 0 &&
        checksum(frame + 36, data_bytes) != load32(frame + 8))
        return OCNEXT_PROXY_INVALID_WIRE;
    bytes_zero((uint8_t *)&staged, sizeof(staged));
    staged.type = expected_type;
    /* Avoid implementation-defined unsigned-to-signed conversion. */
    staged.status = raw_status == 0 ? 0 : -(int32_t)(UINT32_MAX - raw_status + 1);
    bytes_copy(staged.payload, frame + 8, sizeof(staged.payload));
    if (data_bytes) staged.read_data = frame + 36;
    staged.read_bytes = data_bytes;
    bytes_copy((uint8_t *)out, (const uint8_t *)&staged, sizeof(staged));
    return OCNEXT_PROXY_OK;
}

static int session_valid(const struct ocnext_proxy_session *s)
{
    return s && s->bus.probe && s->bus.read && s->bus.writev && s->owner_id &&
           s->session_id && s->generation && s->ram_bytes &&
           s->ram_bytes <= OCNEXT_PROXY_MAX_RAM &&
           s->ram_base <= UINT64_MAX - s->ram_bytes &&
           (s->capabilities & OCNEXT_PROXY_CAP_CONTROL) &&
           !(s->capabilities & ~OCNEXT_PROXY_CAP_ALL) &&
           s->guard == OCNEXT_PROXY_GUARD_RETURN && s->open <= 1;
}
enum ocnext_proxy_result ocnext_proxy_session_init(struct ocnext_proxy_session *s,
    const struct ocnext_proxy_bus *bus, uint64_t owner, uint64_t id,
    uint32_t generation, uint32_t capabilities, uint64_t base, uint64_t bytes)
{
    struct ocnext_proxy_session staged;
    if (!s || !bus) return OCNEXT_PROXY_ARGUMENT;
    bytes_zero((uint8_t *)&staged, sizeof(staged));
    bytes_copy((uint8_t *)&staged.bus, (const uint8_t *)bus, sizeof(*bus));
    staged.owner_id = owner; staged.session_id = id;
    staged.generation = generation; staged.capabilities = capabilities;
    staged.ram_base = base; staged.ram_bytes = bytes;
    staged.guard = OCNEXT_PROXY_GUARD_RETURN; staged.open = 1;
    if (!session_valid(&staged)) return OCNEXT_PROXY_ARGUMENT;
    bytes_copy((uint8_t *)s, (const uint8_t *)&staged, sizeof(staged));
    return OCNEXT_PROXY_OK;
}
static enum ocnext_proxy_result ticket_valid(const struct ocnext_proxy_session *s,
    const struct ocnext_proxy_ticket *t, uint64_t previous)
{
    if (!t || t->reserved) return OCNEXT_PROXY_ARGUMENT;
    if (!s->open) return OCNEXT_PROXY_CLOSED;
    if (t->owner_id != s->owner_id) return OCNEXT_PROXY_WRONG_OWNER;
    if (t->session_id != s->session_id) return OCNEXT_PROXY_WRONG_SESSION;
    if (t->generation != s->generation) return OCNEXT_PROXY_STALE_GENERATION;
    if (!t->sequence || t->sequence <= previous) return OCNEXT_PROXY_REPLAY;
    return OCNEXT_PROXY_OK;
}
enum ocnext_proxy_result ocnext_proxy_session_reset(struct ocnext_proxy_session *s,
    const struct ocnext_proxy_ticket *t)
{
    enum ocnext_proxy_result r;
    if (!session_valid(s)) return OCNEXT_PROXY_ARGUMENT;
    r = ticket_valid(s, t, s->last_sequence);
    if (r != OCNEXT_PROXY_OK) return r;
    if (!(s->capabilities & OCNEXT_PROXY_CAP_RECOVERY)) return OCNEXT_PROXY_CAPABILITY;
    if (s->generation == UINT32_MAX) return OCNEXT_PROXY_EXHAUSTED;
    ++s->generation; s->last_sequence = 0; s->fault_count = 0;
    s->guard = OCNEXT_PROXY_GUARD_RETURN;
    return OCNEXT_PROXY_OK;
}
enum ocnext_proxy_result ocnext_proxy_session_close(struct ocnext_proxy_session *s,
    const struct ocnext_proxy_ticket *t)
{
    enum ocnext_proxy_result r;
    if (!session_valid(s)) return OCNEXT_PROXY_ARGUMENT;
    r = ticket_valid(s, t, s->last_sequence);
    if (r != OCNEXT_PROXY_OK) return r;
    if (!(s->capabilities & OCNEXT_PROXY_CAP_RECOVERY)) return OCNEXT_PROXY_CAPABILITY;
    s->last_sequence = t->sequence; s->open = 0;
    return OCNEXT_PROXY_OK;
}
static int in_ram(const struct ocnext_proxy_session *s, uint64_t address, size_t n)
{
    uint64_t offset;
    if (!n || n > OCNEXT_PROXY_MAX_TRANSFER || address < s->ram_base) return 0;
    offset = address - s->ram_base;
    return offset <= s->ram_bytes && n <= s->ram_bytes - offset;
}
static size_t scalar_width(uint64_t op)
{
    return (size_t)8 >> (unsigned)(op & 3);
}
static void reply_header(uint8_t *out, uint32_t type, int status)
{
    bytes_zero(out, 36); store32(out, type); store32(out + 4, (uint32_t)status);
}
static void reply_finish(uint8_t *out)
{
    store32(out + 32, checksum(out, 32));
}
static void inner_reply(uint8_t *out, uint64_t op, int status, uint64_t value)
{
    store64(out + 8, op); store64(out + 16, (uint64_t)(int64_t)status);
    store64(out + 24, value);
}
struct command {
    uint64_t op, address, value;
    size_t bytes;
    unsigned is_write, is_read, bulk;
    int error;
    unsigned memory_fault;
    uint32_t data_checksum;
};
static void classify(const struct ocnext_proxy_request_view *v, struct command *c)
{
    bytes_zero((uint8_t *)c, sizeof(*c));
    if (v->type == OCNEXT_PROXY_REQ_NOP) {
        /* Negotiation accepts any requested feature bits, grants none. */
        if (!zeros(v->payload + 8, 48)) c->error = OCNEXT_PROXY_ST_INVAL;
    } else if (v->type == OCNEXT_PROXY_REQ_MEMREAD || v->type == OCNEXT_PROXY_REQ_MEMWRITE) {
        uint64_t n = load64(v->payload + 8);
        c->address = load64(v->payload); c->bulk = 1;
        c->is_read = v->type == OCNEXT_PROXY_REQ_MEMREAD;
        c->is_write = !c->is_read;
        if (!n || n > OCNEXT_PROXY_MAX_TRANSFER ||
            !zeros(v->payload + (c->is_write ? 20 : 16), c->is_write ? 36 : 40))
            c->error = OCNEXT_PROXY_ST_INVAL;
        else c->bytes = (size_t)n;
        if (c->is_write) {
            c->data_checksum = checksum(v->write_data, v->write_bytes);
            if (!c->error && c->data_checksum != load32(v->payload + 16))
                c->error = OCNEXT_PROXY_ST_XFRERR;
        }
    } else if (v->type == OCNEXT_PROXY_REQ_PROXY) {
        c->op = load64(v->payload);
        if (c->op >= OCNEXT_PROXY_P_WRITE64 && c->op <= OCNEXT_PROXY_P_READ8) {
            c->address = load64(v->payload + 8); c->value = load64(v->payload + 16);
            c->bytes = scalar_width(c->op);
            c->is_write = c->op <= OCNEXT_PROXY_P_WRITE8; c->is_read = !c->is_write;
            if (!zeros(v->payload + (c->is_write ? 24 : 16), c->is_write ? 32 : 40) ||
                (c->address & (c->bytes - 1))) c->error = OCNEXT_PROXY_ST_INVAL;
        } else if (c->op == OCNEXT_PROXY_P_NOP || c->op == OCNEXT_PROXY_P_GET_EXC_COUNT) {
            if (!zeros(v->payload + 8, 48)) c->error = OCNEXT_PROXY_ST_INVAL;
        } else if (c->op == OCNEXT_PROXY_P_SET_EXC_GUARD) {
            c->value = load64(v->payload + 8);
            if (c->value != OCNEXT_PROXY_GUARD_RETURN || !zeros(v->payload + 16, 40))
                c->error = OCNEXT_PROXY_ST_INVAL;
        } else {
            /* The upstream inner protocol has S_BADCMD=-1, not outer BADCMD. */
            c->error = OCNEXT_PROXY_ST_BADCMD;
        }
    } else c->error = OCNEXT_PROXY_ST_BADCMD;
}
enum ocnext_proxy_result ocnext_proxy_dispatch_batch(struct ocnext_proxy_session *s,
    struct ocnext_proxy_item *items, size_t count, struct ocnext_proxy_workspace *w)
{
    struct command commands[OCNEXT_PROXY_MAX_BATCH];
    size_t lengths[OCNEXT_PROXY_MAX_BATCH];
    size_t i, j, writes = 0, failed = OCNEXT_PROXY_MAX_BATCH;
    uint64_t previous, faults = 0;
    enum ocnext_proxy_result r;
    if (!session_valid(s) || !items || !w || !count || count > OCNEXT_PROXY_MAX_BATCH)
        return OCNEXT_PROXY_ARGUMENT;
    if (spans_overlap(s, sizeof(*s), items, count * sizeof(*items)) ||
        spans_overlap(s, sizeof(*s), w, sizeof(*w)) ||
        spans_overlap(items, count * sizeof(*items), w, sizeof(*w)))
        return OCNEXT_PROXY_ARGUMENT;
    if (!s->open) return OCNEXT_PROXY_CLOSED;
    previous = s->last_sequence;
    /* Every native/framing/capacity/ticket check precedes any bus access. */
    for (i = 0; i < count; ++i) {
        if (!items[i].reply || !span_valid(items[i].reply, items[i].reply_capacity) ||
            !span_valid(items[i].request, items[i].request_bytes) ||
            spans_overlap(items[i].reply, items[i].reply_capacity, s, sizeof(*s)) ||
            spans_overlap(items[i].reply, items[i].reply_capacity, items, count * sizeof(*items)) ||
            spans_overlap(items[i].reply, items[i].reply_capacity, w, sizeof(*w)) ||
            spans_overlap(items[i].request, items[i].request_bytes, s, sizeof(*s)) ||
            spans_overlap(items[i].request, items[i].request_bytes, items, count * sizeof(*items)) ||
            spans_overlap(items[i].request, items[i].request_bytes, w, sizeof(*w)))
            return OCNEXT_PROXY_ARGUMENT;
        r = ticket_valid(s, &items[i].ticket, previous);
        if (r != OCNEXT_PROXY_OK) return r;
        previous = items[i].ticket.sequence;
        r = ocnext_proxy_parse_request(items[i].request, items[i].request_bytes, &w->views[i]);
        if (r != OCNEXT_PROXY_OK) return r;
        classify(&w->views[i], &commands[i]);
        lengths[i] = 36;
        if (commands[i].is_read && commands[i].bulk && !commands[i].error)
            lengths[i] += commands[i].bytes;
        if (items[i].reply_capacity < lengths[i]) return OCNEXT_PROXY_OUTPUT_TOO_SMALL;
        if (items[i].reply_capacity > OCNEXT_PROXY_MAX_REPLY) return OCNEXT_PROXY_ARGUMENT;
        for (j = 0; j < i; ++j)
            if (spans_overlap(items[i].reply, items[i].reply_capacity,
                              items[j].reply, items[j].reply_capacity)) return OCNEXT_PROXY_ARGUMENT;
    }
    for (i = 0; i < count; ++i)
        for (j = 0; j < count; ++j)
            if (spans_overlap(items[i].reply, items[i].reply_capacity,
                              items[j].request, items[j].request_bytes))
                return OCNEXT_PROXY_ARGUMENT;
    for (i = 0; i < count; ++i) {
        struct command *c = &commands[i];
        struct ocnext_proxy_request_view *v = &w->views[i];
        uint8_t *reply = w->replies[i];
        reply_header(reply, v->type, 0);
        if (c->bulk && c->is_write) store32(reply + 8, c->data_checksum);
        if (count > 1 && !c->is_write && !c->error) c->error = OCNEXT_PROXY_ST_INVAL;
        if (!c->error && (c->is_read || c->is_write)) {
            unsigned cap = c->is_write ? OCNEXT_PROXY_CAP_RAM_WRITE : OCNEXT_PROXY_CAP_RAM_READ;
            if (!(s->capabilities & cap)) c->error = OCNEXT_PROXY_ST_INVAL;
            else if (!in_ram(s, c->address, c->bytes) ||
                     s->bus.probe(s->bus.context, c->address, c->bytes, c->is_write) != 1) {
                c->error = OCNEXT_PROXY_ST_XFRERR; c->memory_fault = 1;
            }
        }
        if (!c->error && c->is_write) {
            if (c->bulk) bytes_copy(w->data[i], v->write_data, c->bytes);
            else {
                for (j = 0; j < c->bytes; ++j) w->data[i][j] = (uint8_t)(c->value >> (8 * j));
            }
            w->writes[writes].address = c->address;
            w->writes[writes].data = w->data[i];
            w->writes[writes].bytes = c->bytes; ++writes;
        }
        if (!c->error && c->is_read) {
            if (s->bus.read(s->bus.context, c->address, w->data[i], c->bytes) != 1) {
                c->error = OCNEXT_PROXY_ST_XFRERR; c->memory_fault = 1;
            } else if (c->bulk) {
                store32(reply + 8, checksum(w->data[i], c->bytes));
                bytes_copy(reply + 36, w->data[i], c->bytes);
            } else {
                c->value = 0;
                for (j = 0; j < c->bytes; ++j) c->value |= (uint64_t)w->data[i][j] << (8 * j);
            }
        }
        if (c->error && failed == OCNEXT_PROXY_MAX_BATCH) failed = i;
        if (c->memory_fault) ++faults;
    }
    if (failed == OCNEXT_PROXY_MAX_BATCH && writes &&
        s->bus.writev(s->bus.context, w->writes, writes) != 1) {
        failed = 0; commands[0].error = OCNEXT_PROXY_ST_XFRERR;
        ++faults;
    }
    s->last_sequence = previous;
    s->fault_count = saturating_add(s->fault_count, faults);
    for (i = 0; i < count; ++i) {
        struct command *c = &commands[i];
        struct ocnext_proxy_request_view *v = &w->views[i];
        uint8_t *reply = w->replies[i];
        int status = c->error;
        uint64_t value = 0;
        if (failed != OCNEXT_PROXY_MAX_BATCH && count > 1 && !status)
            status = OCNEXT_PROXY_ST_XFRERR;
        if (status) lengths[i] = 36;
        if (v->type == OCNEXT_PROXY_REQ_PROXY && status == OCNEXT_PROXY_ST_BADCMD)
            inner_reply(reply, c->op, -1, 0);
        else if (status) store32(reply + 4, (uint32_t)status);
        else if (v->type == OCNEXT_PROXY_REQ_PROXY) {
            if (c->is_read) value = c->value;
            else if (c->op == OCNEXT_PROXY_P_GET_EXC_COUNT) {
                value = s->fault_count; s->fault_count = 0;
            } else if (c->op == OCNEXT_PROXY_P_SET_EXC_GUARD) s->fault_count = 0;
            inner_reply(reply, c->op, 0, value);
        }
        reply_finish(reply);
    }
    for (i = 0; i < count; ++i) {
        bytes_copy(items[i].reply, w->replies[i], lengths[i]);
        items[i].reply_bytes = lengths[i];
    }
    return failed != OCNEXT_PROXY_MAX_BATCH && count > 1 ?
        OCNEXT_PROXY_BATCH_ABORTED : OCNEXT_PROXY_OK;
}

void ocnext_proxy_stream_init(struct ocnext_proxy_stream *s)
{
    if (s) bytes_zero((uint8_t *)s, sizeof(*s));
}
void ocnext_proxy_stream_reset(struct ocnext_proxy_stream *s)
{
    if (!s) return;
    s->discarded_bytes = saturating_add(s->discarded_bytes, (uint64_t)s->used);
    s->used = 0; s->expected = 0; s->ready = 0; s->poisoned = 0;
}
static void stream_drop(struct ocnext_proxy_stream *s)
{
    size_t i;
    for (i = 1; i < s->used; ++i) s->bytes[i - 1] = s->bytes[i];
    --s->used; s->discarded_bytes = saturating_add(s->discarded_bytes, 1);
}
enum ocnext_proxy_stream_result ocnext_proxy_stream_push(struct ocnext_proxy_stream *s,
    const uint8_t *input, size_t n, size_t *consumed)
{
    size_t i = 0;
    if (!s || !consumed || !span_valid(input, n) || n > OCNEXT_PROXY_MAX_STREAM_INPUT ||
        spans_overlap(input, n, s, sizeof(*s)) ||
        spans_overlap(consumed, sizeof(*consumed), s, sizeof(*s)) ||
        spans_overlap(consumed, sizeof(*consumed), input, n) ||
        s->used > OCNEXT_PROXY_MAX_FRAME || s->expected > OCNEXT_PROXY_MAX_FRAME ||
        s->ready > 1 || s->poisoned > 1)
        return OCNEXT_PROXY_STREAM_ARGUMENT;
    *consumed = 0;
    if (s->poisoned) return OCNEXT_PROXY_STREAM_LIMIT;
    if (s->ready) return OCNEXT_PROXY_STREAM_FRAME;
    for (;;) {
        if (!s->expected) {
            while (s->used >= 4 && !type_valid(load32(s->bytes))) stream_drop(s);
            if (s->used >= 64) {
                if (checksum(s->bytes, 60) != load32(s->bytes + 60)) {
                    s->checksum_errors = saturating_add(s->checksum_errors, 1);
                    stream_drop(s); continue;
                }
                s->expected = 64;
                if (load32(s->bytes) == OCNEXT_PROXY_REQ_MEMWRITE) {
                    uint64_t bytes = load64(s->bytes + 12);
                    if (bytes > OCNEXT_PROXY_MAX_TRANSFER) {
                        s->poisoned = 1; *consumed = i;
                        return OCNEXT_PROXY_STREAM_LIMIT;
                    }
                    s->expected += (size_t)bytes;
                }
            }
        }
        if (s->expected && s->used == s->expected) {
            s->ready = 1; *consumed = i; return OCNEXT_PROXY_STREAM_FRAME;
        }
        if (i == n) { *consumed = i; return OCNEXT_PROXY_STREAM_NEED_MORE; }
        /* Internal geometry checks also cover corrupted caller-owned state. */
        if (s->used >= OCNEXT_PROXY_MAX_FRAME || (s->expected && s->used > s->expected)) {
            s->poisoned = 1; *consumed = i; return OCNEXT_PROXY_STREAM_LIMIT;
        }
        s->bytes[s->used++] = input[i++];
    }
}
enum ocnext_proxy_result ocnext_proxy_stream_take(struct ocnext_proxy_stream *s,
    uint8_t *out, size_t capacity, size_t *written)
{
    size_t n;
    if (!s || !out || !written || s->poisoned || s->ready != 1 ||
        s->expected < 64 || s->expected > OCNEXT_PROXY_MAX_FRAME ||
        s->used != s->expected) return OCNEXT_PROXY_ARGUMENT;
    n = s->used;
    if (capacity < n) return OCNEXT_PROXY_OUTPUT_TOO_SMALL;
    if (!span_valid(out, n) || spans_overlap(out, n, s, sizeof(*s)) ||
        spans_overlap(written, sizeof(*written), s, sizeof(*s)) ||
        spans_overlap(out, n, written, sizeof(*written))) return OCNEXT_PROXY_ARGUMENT;
    bytes_copy(out, s->bytes, n); *written = n;
    s->used = 0; s->expected = 0; s->ready = 0;
    return OCNEXT_PROXY_OK;
}
