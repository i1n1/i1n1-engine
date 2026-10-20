#include "ocnext/proxy_monitor.h"

#define MONITOR_MARKER UINT64_C(0x4f4e58544d4f4e31)

static void copy_bytes(uint8_t *out, const uint8_t *in, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) out[i] = in[i];
}
static void zero_bytes(uint8_t *out, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) out[i] = 0;
}
static uint64_t sat_add(uint64_t a, uint64_t b)
{
    return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}
static int span_valid(const void *p, size_t n)
{
    return (!n || p) && n <= UINTPTR_MAX - (uintptr_t)p;
}
static int overlap(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (!an || !bn) return 0;
    if (!span_valid(a, an) || !span_valid(b, bn)) return 1;
    return x < y + bn && y < x + an;
}
static int transport_valid(const struct ocnext_proxy_monitor_transport *t)
{
    return t && t->read && t->write && t->authorize && t->recover;
}
static int monitor_valid(const struct ocnext_proxy_monitor *m)
{
    const struct ocnext_proxy_session *s;
    if (!m || !span_valid(m, sizeof(*m)) || m->marker != MONITOR_MARKER ||
        !transport_valid(&m->transport) || !m->workspace ||
        overlap(m, sizeof(*m), m->workspace, sizeof(*m->workspace)) ||
        m->timeout_ms < OCNEXT_PROXY_MONITOR_MIN_TIMEOUT_MS ||
        m->timeout_ms > OCNEXT_PROXY_MONITOR_MAX_TIMEOUT_MS || m->reserved ||
        m->deadline_active > 1 || m->pending_bytes > OCNEXT_PROXY_MONITOR_IO_BYTES ||
        m->pending_cursor > m->pending_bytes || m->request_bytes > OCNEXT_PROXY_MAX_FRAME ||
        m->reply_bytes > OCNEXT_PROXY_MAX_REPLY || m->reply_cursor > m->reply_bytes ||
        m->phase < OCNEXT_PROXY_MONITOR_RX || m->phase > OCNEXT_PROXY_MONITOR_CLOSED_PHASE)
        return 0;
    s = &m->session;
    if (!s->bus.probe || !s->bus.read || !s->bus.writev || !s->owner_id ||
        !s->session_id || !s->generation || !s->ram_bytes ||
        s->ram_bytes > OCNEXT_PROXY_MAX_RAM || s->ram_base > UINT64_MAX - s->ram_bytes ||
        !(s->capabilities & OCNEXT_PROXY_CAP_CONTROL) ||
        (s->capabilities & ~OCNEXT_PROXY_CAP_ALL) || s->guard != OCNEXT_PROXY_GUARD_RETURN ||
        s->open > 1) return 0;
    if (m->phase == OCNEXT_PROXY_MONITOR_CLOSED_PHASE) return !s->open;
    if (!s->open) return 0;
    if (m->phase == OCNEXT_PROXY_MONITOR_RX && (m->request_bytes || m->reply_bytes || m->reply_cursor))
        return 0;
    if (m->phase == OCNEXT_PROXY_MONITOR_TX &&
        (m->request_bytes < 64 || m->reply_bytes < 36)) return 0;
    return 1;
}
static enum ocnext_proxy_monitor_result fail(struct ocnext_proxy_monitor *m,
    uint32_t reason, enum ocnext_proxy_result proxy_error)
{
    m->phase = OCNEXT_PROXY_MONITOR_TERMINAL_PHASE;
    m->reason = reason; m->proxy_error = (int32_t)proxy_error;
    return OCNEXT_PROXY_MONITOR_TERMINAL;
}
static int clock_valid(const struct ocnext_proxy_monitor *m, uint64_t now)
{
    return now >= m->last_now_ms && now <= UINT64_MAX - m->timeout_ms;
}

enum ocnext_proxy_monitor_result ocnext_proxy_monitor_init(struct ocnext_proxy_monitor *m,
    const struct ocnext_proxy_monitor_provision *p,
    const struct ocnext_proxy_monitor_transport *transport,
    const struct ocnext_proxy_bus *bus, struct ocnext_proxy_workspace *workspace,
    uint64_t now_ms)
{
    struct ocnext_proxy_session session;
    enum ocnext_proxy_result result;
    unsigned i;
    if (!m || !p || !transport || !bus || !workspace ||
        !span_valid(m, sizeof(*m)) || !transport_valid(transport) ||
        overlap(m, sizeof(*m), p, sizeof(*p)) ||
        overlap(m, sizeof(*m), transport, sizeof(*transport)) ||
        overlap(m, sizeof(*m), bus, sizeof(*bus)) ||
        overlap(m, sizeof(*m), workspace, sizeof(*workspace)) ||
        overlap(workspace, sizeof(*workspace), p, sizeof(*p)) ||
        overlap(workspace, sizeof(*workspace), transport, sizeof(*transport)) ||
        overlap(workspace, sizeof(*workspace), bus, sizeof(*bus)) ||
        p->carrier != OCNEXT_PROXY_MONITOR_PRIVATE_RESEARCH_CARRIER ||
        p->timeout_ms < OCNEXT_PROXY_MONITOR_MIN_TIMEOUT_MS ||
        p->timeout_ms > OCNEXT_PROXY_MONITOR_MAX_TIMEOUT_MS ||
        now_ms > UINT64_MAX - p->timeout_ms)
        return OCNEXT_PROXY_MONITOR_ARGUMENT;
    for (i = 0; i < 4; ++i) if (p->reserved[i]) return OCNEXT_PROXY_MONITOR_ARGUMENT;
    result = ocnext_proxy_session_init(&session, bus, p->owner_id, p->session_id,
        p->generation, p->capabilities, p->ram_base, p->ram_bytes);
    if (result != OCNEXT_PROXY_OK) return OCNEXT_PROXY_MONITOR_ARGUMENT;
    zero_bytes((uint8_t *)m, sizeof(*m));
    copy_bytes((uint8_t *)&m->session, (const uint8_t *)&session, sizeof(session));
    copy_bytes((uint8_t *)&m->transport, (const uint8_t *)transport, sizeof(*transport));
    m->workspace = workspace; m->timeout_ms = p->timeout_ms;
    m->phase = OCNEXT_PROXY_MONITOR_RX; m->last_now_ms = now_ms; m->marker = MONITOR_MARKER;
    ocnext_proxy_stream_init(&m->stream);
    return OCNEXT_PROXY_MONITOR_PROGRESS;
}

static enum ocnext_proxy_monitor_result dispatch_frame(struct ocnext_proxy_monitor *m)
{
    struct ocnext_proxy_ticket expected, issued;
    struct ocnext_proxy_item item;
    enum ocnext_proxy_result result;
    uint64_t sequence;
    size_t bytes = 0, i;
    result = ocnext_proxy_stream_take(&m->stream, m->request, sizeof(m->request), &bytes);
    if (result != OCNEXT_PROXY_OK)
        return fail(m, OCNEXT_PROXY_MONITOR_STATE_INVALID, result);
    m->request_bytes = bytes;
    if (m->session.last_sequence == UINT64_MAX)
        return fail(m, OCNEXT_PROXY_MONITOR_SEQUENCE_EXHAUSTED, OCNEXT_PROXY_EXHAUSTED);
    sequence = m->session.last_sequence + 1;
    expected.owner_id = m->session.owner_id; expected.session_id = m->session.session_id;
    expected.sequence = sequence; expected.generation = m->session.generation; expected.reserved = 0;
    zero_bytes((uint8_t *)&issued, sizeof(issued));
    if (m->transport.authorize(m->transport.context, m->request, bytes, &expected, &issued) != 1)
        return fail(m, OCNEXT_PROXY_MONITOR_AUTHORITY_FAILED, OCNEXT_PROXY_CAPABILITY);
    /* take() preserves the original wire bytes in stream storage. Detect a
     * faulty provider mutating the borrowed const frame, without a large stack
     * copy or treating the protocol checksum as authentication. Native provider
     * code remains trusted; this is not a defense against arbitrary native code.
     */
    for (i = 0; i < bytes; ++i)
        if (m->request[i] != m->stream.bytes[i])
            return fail(m, OCNEXT_PROXY_MONITOR_AUTHORITY_FAILED, OCNEXT_PROXY_INVALID_WIRE);
    if (issued.owner_id != m->session.owner_id)
        return fail(m, OCNEXT_PROXY_MONITOR_AUTHORITY_FAILED, OCNEXT_PROXY_WRONG_OWNER);
    if (issued.session_id != m->session.session_id)
        return fail(m, OCNEXT_PROXY_MONITOR_AUTHORITY_FAILED, OCNEXT_PROXY_WRONG_SESSION);
    if (issued.generation != m->session.generation)
        return fail(m, OCNEXT_PROXY_MONITOR_AUTHORITY_FAILED, OCNEXT_PROXY_STALE_GENERATION);
    if (issued.sequence != sequence)
        return fail(m, OCNEXT_PROXY_MONITOR_AUTHORITY_FAILED, OCNEXT_PROXY_REPLAY);
    if (issued.reserved)
        return fail(m, OCNEXT_PROXY_MONITOR_AUTHORITY_FAILED, OCNEXT_PROXY_ARGUMENT);
    zero_bytes((uint8_t *)&item, sizeof(item));
    copy_bytes((uint8_t *)&item.ticket, (const uint8_t *)&issued, sizeof(issued));
    item.request = m->request; item.request_bytes = bytes;
    item.reply = m->reply; item.reply_capacity = sizeof(m->reply);
    result = ocnext_proxy_dispatch_batch(&m->session, &item, 1, m->workspace);
    if (result != OCNEXT_PROXY_OK)
        return fail(m, OCNEXT_PROXY_MONITOR_DISPATCH_FAILED, result);
    if (item.reply_bytes < 36 || item.reply_bytes > sizeof(m->reply))
        return fail(m, OCNEXT_PROXY_MONITOR_STATE_INVALID, OCNEXT_PROXY_INVALID_WIRE);
    m->reply_bytes = item.reply_bytes; m->reply_cursor = 0;
    m->dispatched_frames = sat_add(m->dispatched_frames, 1);
    m->phase = OCNEXT_PROXY_MONITOR_TX;
    return OCNEXT_PROXY_MONITOR_PROGRESS;
}

enum ocnext_proxy_monitor_result ocnext_proxy_monitor_pump(struct ocnext_proxy_monitor *m,
                                                        uint64_t now_ms)
{
    size_t transferred = 0, available, consumed = 0;
    enum ocnext_proxy_stream_result stream_result;
    if (!monitor_valid(m)) return OCNEXT_PROXY_MONITOR_ARGUMENT;
    if (m->phase == OCNEXT_PROXY_MONITOR_CLOSED_PHASE) return OCNEXT_PROXY_MONITOR_CLOSED;
    if (now_ms < m->last_now_ms)
        return fail(m, OCNEXT_PROXY_MONITOR_CLOCK_ROLLBACK, OCNEXT_PROXY_ARGUMENT);
    if (now_ms > UINT64_MAX - m->timeout_ms) {
        m->last_now_ms = now_ms;
        return fail(m, OCNEXT_PROXY_MONITOR_CLOCK_OVERFLOW, OCNEXT_PROXY_EXHAUSTED);
    }
    m->last_now_ms = now_ms;
    if (m->phase == OCNEXT_PROXY_MONITOR_TERMINAL_PHASE) return OCNEXT_PROXY_MONITOR_TERMINAL;
    if (m->deadline_active && now_ms >= m->deadline_ms)
        return fail(m, OCNEXT_PROXY_MONITOR_TIMEOUT, OCNEXT_PROXY_OK);
    if (m->phase == OCNEXT_PROXY_MONITOR_TX) {
        available = m->reply_bytes - m->reply_cursor;
        if (available > OCNEXT_PROXY_MONITOR_IO_BYTES) available = OCNEXT_PROXY_MONITOR_IO_BYTES;
        if (m->transport.write(m->transport.context, m->reply + m->reply_cursor,
                               available, &transferred) != 1 || transferred > available)
            return fail(m, OCNEXT_PROXY_MONITOR_WRITE_FAILED, OCNEXT_PROXY_OK);
        if (!transferred) return OCNEXT_PROXY_MONITOR_WOULD_BLOCK;
        m->reply_cursor += transferred;
        m->transmitted_bytes = sat_add(m->transmitted_bytes, (uint64_t)transferred);
        if (m->reply_cursor != m->reply_bytes) return OCNEXT_PROXY_MONITOR_PROGRESS;
        m->completed_replies = sat_add(m->completed_replies, 1);
        m->phase = OCNEXT_PROXY_MONITOR_RX;
        m->request_bytes = 0; m->reply_bytes = 0; m->reply_cursor = 0;
        m->deadline_active = 0; m->deadline_ms = 0;
        return OCNEXT_PROXY_MONITOR_REPLY_SENT;
    }
    if (m->pending_cursor == m->pending_bytes) {
        m->pending_cursor = 0; m->pending_bytes = 0;
        if (m->transport.read(m->transport.context, m->pending, sizeof(m->pending),
                              &transferred) != 1 || transferred > sizeof(m->pending))
            return fail(m, OCNEXT_PROXY_MONITOR_READ_FAILED, OCNEXT_PROXY_OK);
        if (!transferred) return OCNEXT_PROXY_MONITOR_WOULD_BLOCK;
        m->pending_bytes = transferred;
        m->received_bytes = sat_add(m->received_bytes, (uint64_t)transferred);
    }
    if (!m->deadline_active) {
        m->deadline_ms = now_ms + m->timeout_ms;
        m->deadline_active = 1;
    }
    available = m->pending_bytes - m->pending_cursor;
    stream_result = ocnext_proxy_stream_push(&m->stream, m->pending + m->pending_cursor,
                                            available, &consumed);
    if (consumed > available)
        return fail(m, OCNEXT_PROXY_MONITOR_STATE_INVALID, OCNEXT_PROXY_INVALID_WIRE);
    m->pending_cursor += consumed;
    if (stream_result == OCNEXT_PROXY_STREAM_FRAME) return dispatch_frame(m);
    if (stream_result == OCNEXT_PROXY_STREAM_LIMIT)
        return fail(m, OCNEXT_PROXY_MONITOR_FRAME_LIMIT, OCNEXT_PROXY_INVALID_WIRE);
    if (stream_result != OCNEXT_PROXY_STREAM_NEED_MORE)
        return fail(m, OCNEXT_PROXY_MONITOR_STATE_INVALID, OCNEXT_PROXY_ARGUMENT);
    return OCNEXT_PROXY_MONITOR_PROGRESS;
}

enum ocnext_proxy_monitor_result ocnext_proxy_monitor_recover(struct ocnext_proxy_monitor *m,
    const struct ocnext_proxy_ticket *ticket, uint64_t now_ms)
{
    struct ocnext_proxy_session staged;
    enum ocnext_proxy_result result;
    if (!monitor_valid(m) || !ticket ||
        overlap(ticket, sizeof(*ticket), m, sizeof(*m)) ||
        overlap(ticket, sizeof(*ticket), m->workspace, sizeof(*m->workspace)) ||
        m->phase != OCNEXT_PROXY_MONITOR_TERMINAL_PHASE || !clock_valid(m, now_ms))
        return OCNEXT_PROXY_MONITOR_ARGUMENT;
    copy_bytes((uint8_t *)&staged, (const uint8_t *)&m->session, sizeof(staged));
    result = ocnext_proxy_session_reset(&staged, ticket);
    if (result != OCNEXT_PROXY_OK) return OCNEXT_PROXY_MONITOR_ARGUMENT;
    if (m->transport.recover(m->transport.context, staged.generation) != 1) {
        m->last_now_ms = now_ms;
        return fail(m, OCNEXT_PROXY_MONITOR_RECOVERY_FAILED, OCNEXT_PROXY_OK);
    }
    copy_bytes((uint8_t *)&m->session, (const uint8_t *)&staged, sizeof(staged));
    ocnext_proxy_stream_reset(&m->stream);
    zero_bytes(m->request, sizeof(m->request)); zero_bytes(m->reply, sizeof(m->reply));
    zero_bytes(m->pending, sizeof(m->pending));
    m->pending_bytes = 0; m->pending_cursor = 0;
    m->request_bytes = 0; m->reply_bytes = 0; m->reply_cursor = 0;
    m->phase = OCNEXT_PROXY_MONITOR_RX; m->reason = OCNEXT_PROXY_MONITOR_REASON_NONE;
    m->proxy_error = OCNEXT_PROXY_OK; m->deadline_ms = 0; m->deadline_active = 0;
    m->last_now_ms = now_ms;
    return OCNEXT_PROXY_MONITOR_RECOVERED;
}

enum ocnext_proxy_monitor_result ocnext_proxy_monitor_close(struct ocnext_proxy_monitor *m,
    const struct ocnext_proxy_ticket *ticket)
{
    enum ocnext_proxy_result result;
    if (!monitor_valid(m) || !ticket ||
        overlap(ticket, sizeof(*ticket), m, sizeof(*m)) ||
        overlap(ticket, sizeof(*ticket), m->workspace, sizeof(*m->workspace)))
        return OCNEXT_PROXY_MONITOR_ARGUMENT;
    if (m->phase == OCNEXT_PROXY_MONITOR_CLOSED_PHASE) return OCNEXT_PROXY_MONITOR_CLOSED;
    result = ocnext_proxy_session_close(&m->session, ticket);
    if (result != OCNEXT_PROXY_OK) return OCNEXT_PROXY_MONITOR_ARGUMENT;
    m->phase = OCNEXT_PROXY_MONITOR_CLOSED_PHASE;
    m->deadline_ms = 0; m->deadline_active = 0;
    return OCNEXT_PROXY_MONITOR_CLOSED;
}

enum ocnext_proxy_monitor_result ocnext_proxy_monitor_get_status(const struct ocnext_proxy_monitor *m,
    struct ocnext_proxy_monitor_status *out)
{
    struct ocnext_proxy_monitor_status status;
    if (!monitor_valid(m) || !out ||
        overlap(out, sizeof(*out), m, sizeof(*m)) ||
        overlap(out, sizeof(*out), m->workspace, sizeof(*m->workspace)))
        return OCNEXT_PROXY_MONITOR_ARGUMENT;
    zero_bytes((uint8_t *)&status, sizeof(status));
    status.phase = m->phase; status.reason = m->reason; status.generation = m->session.generation;
    status.deadline_active = m->deadline_active; status.proxy_error = m->proxy_error;
    status.last_sequence = m->session.last_sequence;
    status.received_bytes = m->received_bytes; status.transmitted_bytes = m->transmitted_bytes;
    status.dispatched_frames = m->dispatched_frames; status.completed_replies = m->completed_replies;
    status.discarded_bytes = m->stream.discarded_bytes; status.checksum_errors = m->stream.checksum_errors;
    status.pending_bytes = (uint64_t)(m->pending_bytes - m->pending_cursor);
    status.reply_remaining = (uint64_t)(m->reply_bytes - m->reply_cursor);
    status.deadline_ms = m->deadline_ms;
    copy_bytes((uint8_t *)out, (const uint8_t *)&status, sizeof(status));
    return OCNEXT_PROXY_MONITOR_PROGRESS;
}
