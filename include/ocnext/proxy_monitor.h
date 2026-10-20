#ifndef OCNEXT_PROXY_MONITOR_H
#define OCNEXT_PROXY_MONITOR_H

#include "ocnext/proxy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OCNEXT_PROXY_MONITOR_ABI_VERSION 1u
#define OCNEXT_PROXY_MONITOR_IO_BYTES 256u
#define OCNEXT_PROXY_MONITOR_MIN_TIMEOUT_MS 1u
#define OCNEXT_PROXY_MONITOR_MAX_TIMEOUT_MS 60000u
#define OCNEXT_PROXY_MONITOR_PRIVATE_RESEARCH_CARRIER 1u

/* This provision is a trusted native assertion, not legacy proxy wire data or proof of
 * physical UART authentication. Only explicit private research carriers are
 * supported. A product authenticated transport remains unimplemented.
 * now_ms is supplied by an external monotonic clock; the engine never invents
 * elapsed time. Work-budget ticks must not be reported as real milliseconds.
 */
struct ocnext_proxy_monitor_provision {
    uint64_t owner_id, session_id, ram_base, ram_bytes;
    uint32_t generation, capabilities, timeout_ms, carrier, reserved[4];
};
/* Each callback returns exactly 1 on success; all other values are failures.
 * read/write transfer 0..capacity bytes; zero means would-block. Buffers are
 * valid borrowed monitor-owned RX/TX ranges. Transport backing must be distinct
 * from monitor/workspace/RAM. Count/ticket arguments are separately owned native
 * scratch; callbacks may not retain them. Callbacks may
 * not mutate monitor/session/workspace or unrelated frame bytes, must return
 * promptly, and never retain borrowed buffers. No MMIO callback is supplied.
 * authorize must supply an issuer ticket for this immutable frame; expected is
 * the only next admissible ticket. Raw UART bytes cannot prove that authority.
 * recover discards stale carrier input/output before accepting a new generation.
 */
struct ocnext_proxy_monitor_transport {
    void *context;
    int (*read)(void *, uint8_t *, size_t capacity, size_t *transferred);
    int (*write)(void *, const uint8_t *, size_t bytes, size_t *transferred);
    int (*authorize)(void *, const uint8_t *frame, size_t frame_bytes,
                     const struct ocnext_proxy_ticket *expected,
                     struct ocnext_proxy_ticket *issued);
    int (*recover)(void *, uint32_t new_generation);
};
enum ocnext_proxy_monitor_phase {
    OCNEXT_PROXY_MONITOR_RX = 1,
    OCNEXT_PROXY_MONITOR_TX = 2,
    OCNEXT_PROXY_MONITOR_TERMINAL_PHASE = 3,
    OCNEXT_PROXY_MONITOR_CLOSED_PHASE = 4
};
enum ocnext_proxy_monitor_reason {
    OCNEXT_PROXY_MONITOR_REASON_NONE = 0,
    OCNEXT_PROXY_MONITOR_READ_FAILED = 1,
    OCNEXT_PROXY_MONITOR_WRITE_FAILED = 2,
    OCNEXT_PROXY_MONITOR_CLOCK_ROLLBACK = 3,
    OCNEXT_PROXY_MONITOR_CLOCK_OVERFLOW = 4,
    OCNEXT_PROXY_MONITOR_TIMEOUT = 5,
    OCNEXT_PROXY_MONITOR_FRAME_LIMIT = 6,
    OCNEXT_PROXY_MONITOR_AUTHORITY_FAILED = 7,
    OCNEXT_PROXY_MONITOR_DISPATCH_FAILED = 8,
    OCNEXT_PROXY_MONITOR_SEQUENCE_EXHAUSTED = 9,
    OCNEXT_PROXY_MONITOR_RECOVERY_FAILED = 10,
    OCNEXT_PROXY_MONITOR_STATE_INVALID = 11
};
enum ocnext_proxy_monitor_result {
    OCNEXT_PROXY_MONITOR_PROGRESS = 0,
    OCNEXT_PROXY_MONITOR_WOULD_BLOCK = 1,
    OCNEXT_PROXY_MONITOR_REPLY_SENT = 2,
    OCNEXT_PROXY_MONITOR_TERMINAL = 3,
    OCNEXT_PROXY_MONITOR_CLOSED = 4,
    OCNEXT_PROXY_MONITOR_ARGUMENT = 5,
    OCNEXT_PROXY_MONITOR_RECOVERED = 6
};

/* Caller-owned stable state, no allocation. Keep disjoint from workspace, RAM,
 * transport backing, provision/transport/bus arguments and recovery tickets.
 * Initialize only through init; serialize all calls, and do not mutate fields.
 * Request/reply lifetime lasts through full TX or explicit terminal recovery.
 */
struct ocnext_proxy_monitor {
    uint64_t marker;
    struct ocnext_proxy_session session;
    struct ocnext_proxy_monitor_transport transport;
    struct ocnext_proxy_workspace *workspace;
    struct ocnext_proxy_stream stream;
    uint8_t request[OCNEXT_PROXY_MAX_FRAME];
    uint8_t reply[OCNEXT_PROXY_MAX_REPLY];
    uint8_t pending[OCNEXT_PROXY_MONITOR_IO_BYTES];
    size_t pending_bytes, pending_cursor, request_bytes, reply_bytes, reply_cursor;
    uint64_t last_now_ms, deadline_ms, received_bytes, transmitted_bytes;
    uint64_t dispatched_frames, completed_replies;
    uint32_t phase, reason, timeout_ms, deadline_active;
    int32_t proxy_error;
    uint32_t reserved;
};
struct ocnext_proxy_monitor_status {
    uint32_t phase, reason, generation, deadline_active;
    int32_t proxy_error;
    uint32_t reserved;
    uint64_t last_sequence, received_bytes, transmitted_bytes;
    uint64_t dispatched_frames, completed_replies, discarded_bytes, checksum_errors;
    uint64_t pending_bytes, reply_remaining, deadline_ms;
};

/* Rejection leaves monitor unchanged. A new init does not establish a hardware
 * session or clear RAM. Never reinitialize a committed session to replay traffic.
 */
enum ocnext_proxy_monitor_result ocnext_proxy_monitor_init(struct ocnext_proxy_monitor *,
    const struct ocnext_proxy_monitor_provision *, const struct ocnext_proxy_monitor_transport *,
    const struct ocnext_proxy_bus *, struct ocnext_proxy_workspace *, uint64_t now_ms);
/* At most 256 RX or TX bytes and one complete dispatch per call. A full reply
 * returns REPLY_SENT without consuming the next pending frame. Failed/timeout
 * state is terminal: no automatic callback, redispatch or retransmission follows.
 */
enum ocnext_proxy_monitor_result ocnext_proxy_monitor_pump(struct ocnext_proxy_monitor *,
                                                        uint64_t now_ms);
/* Recovery only from TERMINAL. Validates old authority and monotonic time before
 * carrier discard; on success increments generation, discards buffers and resets
 * sequence through proxy_session_reset. Committed RAM is preserved, not replayed.
 * A failing discard leaves authority unchanged and the engine terminal.
 */
enum ocnext_proxy_monitor_result ocnext_proxy_monitor_recover(struct ocnext_proxy_monitor *,
    const struct ocnext_proxy_ticket *, uint64_t now_ms);
/* Explicit authority close from any live/terminal phase. Does not send remaining
 * bytes, flush the device, clear RAM or revoke resources outside this session.
 */
enum ocnext_proxy_monitor_result ocnext_proxy_monitor_close(struct ocnext_proxy_monitor *,
                                                         const struct ocnext_proxy_ticket *);
enum ocnext_proxy_monitor_result ocnext_proxy_monitor_get_status(const struct ocnext_proxy_monitor *,
                                                               struct ocnext_proxy_monitor_status *);

#ifdef __cplusplus
}
#endif
#endif
